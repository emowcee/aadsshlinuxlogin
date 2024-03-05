#!/bin/bash


# This script must be run elevated. Adding a sudo wrapper if needed.
if [ "$UID" -ne 0 ]; then
    exec sudo "$0" "$@"
fi

set -o errexit

ERROR_MESSAGE='Unknown failure'

function report_status()
{
    local exitCode=$?

    if [ $exitCode -eq 0 ]; then
        echo 'Done.'
        status='success'
        ERROR_MESSAGE='Done'
    else
        if [ $exitCode -eq $ERROR_UNSUPPORTED_OS ]; then
            ERROR_MESSAGE='Unsupported Linux version. Learn more at https://aka.ms/AADSSHLogin'
        fi
        echo "$ERROR_MESSAGE" 1>&2;
        status='error'
    fi

    # Get the status file
    # normally we would need to find this config_dir by parsing the
    # HandlerEnvironment.json, but we are in a bash script here,
    # so assume it's at ../config/.
    SCRIPT_DIR=$(dirname "$0")
    config_dir=$(readlink -f "${SCRIPT_DIR}/config")
    status_dir=$(readlink -f "${SCRIPT_DIR}/status")
    config_file=$((ls $config_dir 2>/dev/null || :) | grep -E ^[0-9]+.settings$ | sort -n | tail -n 1)
    if [ -f "$config_dir/$config_file" ]; then
        status_file=$(echo $config_file | sed s/settings/status/)
        status_file=$(readlink -f "$status_dir/$status_file")
        timestamp="$(date --utc --iso-8601=seconds)"
        cat > "$status_file" <<- EOF
[
    {
        "version": 1,
        "timestampUTC": "$timestamp",
        "status": {
            "operation": "$OPERATION",
            "status": "$status",
            "formattedMessage": {
                "lang": "en",
                "message": "$ERROR_MESSAGE"
            }
        }
    }
]
EOF
    fi
}

function cleanup
{
    report_status || :

    for pkg in $INSTALLED_PACKAGES; do
        echo "Removing $pkg"
        $PKGUNINSTALL_CMD $pkg >/dev/null || echo "Failed to remove $pkg"
    done
    if [ -n "$TEMP_DIR" ]; then
        if [ -n "$MS_REPO_CONFIG" ]; then
            if [ -f "$TEMP_DIR/prod.backup" ]; then
                mv -f -T "$TEMP_DIR/prod.backup" "$MS_REPO_CONFIG" || echo "Failed to revert microsoft repo"
            else
                rm -f "$MS_REPO_CONFIG" || echo "Failed to remove microsoft repo"
            fi
        fi
        rm -rf "$TEMP_DIR" || echo "Could not delete $TEMP_DIR"
    fi
    for svc in $STOPPED_SERVICES; do
        echo "Starting $svc"
        systemctl start "$svc" || echo "Failed to start $svc"
    done
}
trap cleanup EXIT

ERROR_UNKNOWN_COMMAND=10003
ERROR_DOWNLOAD=10004
ERROR_POSTINST_FAILED=10005

EXTENSION_VERSION=1.0.2385.1
EXTENSION_VERSION_FILE='/var/log/AADSSHLoginForLinux.version'

# Errors that WA agent understands
ERROR_UNSUPPORTED_OS=51
ERROR_MISSING_DEPENDENCY=52
ERROR_CONFIGURATION=53

# Find the packaging system used by this machine. Set the correct commands for install/uninstall
if [ -f '/usr/bin/apt-get' ]; then
    PACKAGE_MANAGER=apt
    PACKAGE_TYPE=DEB
    PKGINSTALL_CMD='apt-get install -q -y -o Dpkg::Options::=--force-confold'
    PKGUPDATE_CMD='apt-get install -q -y -o Dpkg::Options::=--force-confold'
    PKGUNINSTALL_CMD='dpkg --purge'
    PKGEXISTS_CMD='dpkg -s'
    export DEBIAN_FRONTEND=noninteractive
elif [ -f '/usr/bin/yum' ]; then
    PACKAGE_MANAGER=yum
    PACKAGE_TYPE=RPM
    PKGINSTALL_CMD='yum -q -y install'
    PKGUPDATE_CMD='yum -q -y update'
    PKGUNINSTALL_CMD='yum -q -y erase'
    PKGEXISTS_CMD='rpm -q'
elif [ -f '/usr/bin/zypper' ]; then
    PACKAGE_MANAGER=zypper
    PACKAGE_TYPE=RPM
    PKGINSTALL_CMD='zypper -q -n install'
    PKGUPDATE_CMD='zypper -q -n update'
    PKGUNINSTALL_CMD='zypper -q -n remove'
    PKGEXISTS_CMD='rpm -q'
else
    echo "Unknown packaging system"
    exit $ERROR_UNSUPPORTED_OS
fi

# Check if sudo is needed to install packages
if [ "$EUID" -ne 0 ]; then
    SUDOCMD='sudo -E'
else
    SUDOCMD=''
fi

# Make sure sed and grep are installed (Mariner 2)
if [ ! -f /bin/sed ]; then
    $SUDOCMD $PKGINSTALL_CMD sed
fi
if [ ! -f /bin/grep ]; then
    $SUDOCMD $PKGINSTALL_CMD grep
fi

# Define the target Linux flavor
if [ -f "/etc/os-release" ]; then
    LINUX_FLAVOR=$(sed -r -n -e 's/^ID=\"?([^"-]+)-?.*\"?/\1/p' /etc/os-release)
    LINUX_VERSION=$(sed -r -n -e 's/^VERSION_ID=\"?([^"]+)\"?/\1/p' /etc/os-release)
elif [ -f "/etc/centos-release" ]; then
    LINUX_FLAVOR='centos'
    LINUX_VERSION=$(sed -r -n -e 's/.*([0-9]+\.[0-9]+).*/\1/p' /etc/centos-release)
elif [ -f "/etc/redhat-release" ]; then
    LINUX_FLAVOR='rhel'
    LINUX_VERSION=$(sed -r -n -e 's/.*([0-9]+\.[0-9]+).*/\1/p' /etc/redhat-release)
else
    echo "Unsupported Linux version"
    exit $ERROR_UNSUPPORTED_OS
fi
LINUX_ARCH=$(uname -m)
echo "Machine OS: $LINUX_FLAVOR v$LINUX_VERSION $LINUX_ARCH"

# Combine similar flavors in order to simplify scripts.
# Keep it a separate variable because sometimes we need the real flavor.
if [ $LINUX_FLAVOR == 'debian' ]; then
    LINUX_FLAVOR_LIKE='ubuntu'
elif [ $LINUX_FLAVOR == 'centos' ] || [ $LINUX_FLAVOR == 'ol' ] || [ $LINUX_FLAVOR == 'almalinux' ] || [ $LINUX_FLAVOR == 'rocky' ]; then
    LINUX_FLAVOR_LIKE='rhel'
elif [ $LINUX_FLAVOR == 'opensuse' ]; then
    LINUX_FLAVOR_LIKE='sles'
else
    LINUX_FLAVOR_LIKE="$LINUX_FLAVOR"
fi
if [ $LINUX_FLAVOR_LIKE != $LINUX_FLAVOR ]; then
    echo "OS similar to: $LINUX_FLAVOR_LIKE"
fi

# The architecture used by debian package differs from what is reported by uname -m
PACKAGE_ARCH=$LINUX_ARCH
if [ $PACKAGE_TYPE == 'DEB' ]; then
    if [ $LINUX_ARCH == 'x86_64' ]; then
        PACKAGE_ARCH='amd64'
    elif [ $LINUX_ARCH == 'aarch64' ]; then
        PACKAGE_ARCH='arm64'
    fi
fi

# Get the correct selinux policy to depend on
if [ $PACKAGE_MANAGER == 'apt' ]; then
    PKGSELINUX_POLICY='selinux-policy-default'
elif [ $PACKAGE_MANAGER == 'yum' ]; then
    PKGSELINUX_POLICY='selinux-policy-targeted'
elif [ $PACKAGE_MANAGER == 'zypper' ]; then
    if (( 10#${LINUX_VERSION%%.*} == 10#15 )); then
        PKGSELINUX_POLICY='selinux-policy-targeted'
    else
        PKGSELINUX_POLICY='selinux-policy-minimum'
    fi
fi

package_is_installed()
{
    if [ $PACKAGE_MANAGER == 'apt' ]; then
        $PKGEXISTS_CMD $1 2>/dev/null | grep -c "ok installed" >/dev/null 2>&1
    else
        $PKGEXISTS_CMD $1 >/dev/null 2>&1
    fi
}


stop_service()
{
    if systemctl --quiet is-active "$1" 2>/dev/null; then
        echo "Stopping $1"
        ERROR_MESSAGE="Failed to stop $1"
        systemctl stop "$1"
        STOPPED_SERVICES="$1 $STOPPED_SERVICES"
    fi
}

stop_unattended_upgrades()
{
    if [ $PACKAGE_MANAGER == 'apt' ]; then
        stop_service apt-daily.timer
        stop_service apt-daily-upgrade.timer
        stop_service apt-daily.service
        stop_service apt-daily-upgrade.service
        stop_service unattended-upgrades
    elif [ $PACKAGE_MANAGER == 'yum' ]; then
        stop_service yum-cron.service
        stop_service dnf-automatic.timer
    fi
}

wait_for_lock()
{
    local runtime="5 minute"
    local endtime=$(date -ud "$runtime" +%s)

    while true
    do
        local locked=$(lsof $@ 2>/dev/null || :)
        if [ -z "$locked" ]; then
            return 0
        fi
        if [[ $(date -u +%s) -le $endtime ]]; then
            echo "Waiting for locks: $locked"
            stop_unattended_upgrades
            sleep 10
        else
            echo "Timeout. Operation may fail. These are still locked: $locked"
            return 0
        fi
    done
}

wait_for_locks()
{
    if [ $PACKAGE_MANAGER == 'apt' ]; then
        wait_for_lock '/var/lib/apt/lists/lock' '/var/cache/apt/archives/lock' '/var/lib/dpkg/lock' '/var/lib/dpkg/lock-frontend'
    elif [ $PACKAGE_MANAGER == 'yum' ]; then
        wait_for_lock 'etc/selinux/targeted/semanage.trans.LOCK' '/var/run/yum.pid' '/var/lib/rpm/.rpm.lock'
    elif [ $PACKAGE_MANAGER == 'zypper' ]; then
        wait_for_lock '/var/run/zypp.pid' '/var/lib/rpm/.rpm.lock'
    fi
}

install_missing_package()
{
    echo "Installing $1"
    ERROR_MESSAGE="Failed to install $1. To get more info, try to run on the VM: sudo $PKGINSTALL_CMD $1"
    $PKGINSTALL_CMD $1
}

install_package()
{
    wait_for_locks
    if ! package_is_installed $1; then
        install_missing_package $1
        INSTALLED_PACKAGES="$1 $INSTALLED_PACKAGES"
    else
        INSTALLED_PACKAGES="$1 $INSTALLED_PACKAGES"
        echo "Updating $1"
        ERROR_MESSAGE="Failed to update $1. To get more info, try to run on the VM: sudo $PKGUPDATE_CMD $1"
        $PKGUPDATE_CMD $1
    fi
}

install_tool()
{
    if [ ! -f $1 ]; then
        wait_for_locks
        install_missing_package $2
    fi
}

uninstall_package()
{
    if $PKGEXISTS_CMD $1 >/dev/null 2>&1; then
        wait_for_locks
        echo "Removing $1"
        ERROR_MESSAGE="Failed to remove $1. To get more info, try to run on the VM: sudo $PKGUNINSTALL_CMD $1"
        $PKGUNINSTALL_CMD $1
    else
        echo "Skipping $1 removal (not found)"
    fi
}

download_file()
{
    if ! curl -f -sS -o "$TEMP_DIR/$2" "$REPO_ENDPOINT/$1/$2"; then
        return 1
    fi
    return 0
}

check_url_exists()
{
    local httpCode=$(curl -f -sL -w "%{http_code}\n" -I "$1" -o /dev/nul)
    if [ $httpCode == "200" ]; then
        return 0
    elif [ $httpCode == "404" ]; then
        return 1
    else
        ERROR_MESSAGE="Cannot access $1. HTTP Code: $httpCode"
        exit $ERROR_DOWNLOAD
    fi
}

refresh_repos()
{
    wait_for_locks
    if [ $PACKAGE_MANAGER == 'apt' ]; then
        apt-get update -qq -y -o APT::Update::Error-Mode=any
    elif [ $PACKAGE_MANAGER == 'yum' ]; then
        yum -q -y clean expire-cache
    elif [ $PACKAGE_MANAGER == 'zypper' ]; then
        zypper -q -n refresh --force-download
    fi
}

get_machine_type()
{
    if [[ -f '/opt/azcmagent/bin/himds' ]]; then
        echo "This is an Arc machine"
        isAzureMachine=0 #Arc
    else
        echo "This is an Azure machine"
        isAzureMachine=1 #Azure
    fi
}

check_for_msi()
{
    local runtime="2 minute"
    local endtime=$(date -ud "$runtime" +%s)

    # Note that if MSI was just added, the check may fail, so we are going to retry a few times.
    while true
    do
        ERROR_MESSAGE='Failed to call metadata service'
        local response=$(
            curl -H 'Metadata:true' 'http://169.254.169.254/metadata/identity/oauth2/token?resource=ce6ff14a-7fdc-4685-bbe0-f6afdfcfa8e0&api-version=latest_internal' \
            --write-out %{http_code} \
            --silent \
            --output /dev/null \
        )
        if [ "$response" == '200' ]; then
            return 0
        fi

        if [[ $(date -u +%s) -le $endtime ]]; then
            echo "No MSI found. Trying again..."
            sleep 10
        else
            ERROR_MESSAGE='Managed System Identity is required for Azure AD based SSH login to work. Enable it and try again.'
            return $ERROR_MISSING_DEPENDENCY
        fi
    done
}

common_install()
{
    # Remember the current version at the start. If something bad happens, the uninstall will know to remove everything as needed.
    echo $EXTENSION_VERSION >$EXTENSION_VERSION_FILE

    stop_unattended_upgrades
    refresh_repos || echo 'Failing to refresh repos; ignoring'

    #RHEL images frequently have expired certificate for their repos. Try to fix the issue here.
    if [ $LINUX_FLAVOR == 'rhel' ] && yum repolist 2>/dev/null | grep 'microsoft-azure' >/dev/null; then
        yum update -y -q --disablerepo='*' --enablerepo='*microsoft-azure*' || echo 'Failed to update the RHUI cert; ignoring the error'
    fi

    # Installation will fail if the V1 packages exist on the machine, so this check is not required.
    # However by doing it we can return a nicer message to the caller
    if package_is_installed aadlogin; then
        ERROR_MESSAGE='Detected obsolete packages. Please uninstall AADLoginForLinux first, then try again.'
        exit $ERROR_CONFIGURATION
    fi

    # Install curl if it is not already there. Needed to download repo config files.
    install_tool /usr/bin/curl curl

    # Get the machine type.
    get_machine_type

    REPO_ADD_PATH=''
    if [ "$isAzureMachine" -eq "1" ]; then
        # Find the Microsoft package repo endpoint
        cloudEnvironment=$(curl -H 'Metadata:true' 'http://169.254.169.254/metadata/instance/compute/azEnvironment?api-version=2019-08-01&format=text')
        if [ $cloudEnvironment == "USNat" ]
        then
            REPO_ENDPOINT="https://repodepot.azure.eaglex.ic.gov"
            REPO_ADD_PATH='/microsoft'
        elif [ $cloudEnvironment == "USSec" ]
        then
            REPO_ADD_PATH='/microsoft'
            REPO_ENDPOINT="https://repodepot.azure.microsoft.scloud"
        else
            REPO_ENDPOINT="https://packages.microsoft.com"
        fi
    else
        # TODO - add Arc support for airgapped clouds.
        REPO_ENDPOINT="https://packages.microsoft.com"
    fi

    # Register the Microsoft package repo
     echo "Configuring microsoft-prod repo"
    TEMP_DIR=$(mktemp -d -t tmp.XXXXXXXXXX)

    # First download the repo key. It is guaranteed to be there, so if this fails, we know that there are connectivity problems.
    if ! download_file 'keys' 'microsoft.asc'; then
        ERROR_MESSAGE="Cannot access $REPO_ENDPOINT. Make sure this URL is not blocked by a firewall"
        exit $ERROR_DOWNLOAD
    fi

    # Check if the Linux distro is supported. If not, try to use the alternative.
    if [ $LINUX_FLAVOR == 'fedora' ]; then
        # This is the only flavor that exists in packages.microsoft.com but is not supported for any version.
        exit $ERROR_UNSUPPORTED_OS
    elif [ $LINUX_FLAVOR == 'centos' ] && (( 10#${LINUX_VERSION%%.*} > 10#8 )); then
        # packages.microsoft.com stopped supporting a dedicated centos repo after version 8. Use the RHEL repo instead.
        LINUX_FLAVOR="$LINUX_FLAVOR_LIKE"
    elif [ $LINUX_FLAVOR != $LINUX_FLAVOR_LIKE ] && ! check_url_exists "$REPO_ENDPOINT$REPO_ADD_PATH/$LINUX_FLAVOR/"; then
        echo "There is no dedicated repo for $LINUX_FLAVOR; trying $LINUX_FLAVOR_LIKE instead"
        LINUX_FLAVOR="$LINUX_FLAVOR_LIKE"
    fi

    # Create the repo config.
    if [ $PACKAGE_TYPE == 'DEB' ]; then
        # Ubuntu and debian can access the repos either by version or by code name but the code name is the one replicated to sovereign clouds
        VERSION_CODENAME=$(sed -r -n -e 's/^VERSION_CODENAME=\"?([^"]+)\"?/\1/p' /etc/os-release)
        if [ -z "$VERSION_CODENAME" ]; then
            exit $ERROR_UNSUPPORTED_OS
        fi
        if [ $LINUX_FLAVOR == 'ubuntu' ] && [ $VERSION_CODENAME == 'bionic' ] && [ $LINUX_ARCH == 'aarch64' ]; then
            REPO_PATH="$REPO_ENDPOINT$REPO_ADD_PATH/repos/microsoft-$LINUX_FLAVOR-$VERSION_CODENAME-multiarch-prod"
        else
            REPO_PATH="$REPO_ENDPOINT$REPO_ADD_PATH/repos/microsoft-$LINUX_FLAVOR-$VERSION_CODENAME-prod"
        fi
        FILE_EXT=list
        echo "deb $REPO_PATH $VERSION_CODENAME main" >"$TEMP_DIR/prod.$FILE_EXT"
    else
        if [ $LINUX_FLAVOR == 'mariner' ]; then
            case $LINUX_VERSION in
                1.0)
                    REPO_PATH="$REPO_ENDPOINT$REPO_ADD_PATH/cbl-$LINUX_FLAVOR/$LINUX_VERSION/prod/extras/$LINUX_ARCH/rpms"
                    BASE_URL=$REPO_ENDPOINT$REPO_ADD_PATH/cbl-mariner/\$releasever/prod/extras/\$basearch/rpms
                    ;;
                2.0)
                    REPO_PATH="$REPO_ENDPOINT$REPO_ADD_PATH/cbl-$LINUX_FLAVOR/$LINUX_VERSION/prod/extras/$LINUX_ARCH"
                    # Note: Compared to Mariner-1.0 baseurl path does not have "rpms" at the end
                    BASE_URL=$REPO_ENDPOINT$REPO_ADD_PATH/cbl-mariner/\$releasever/prod/extras/\$basearch
                    ;;
                *)
                    exit $ERROR_UNSUPPORTED_OS
            esac
            FILE_EXT=repo
            cat > "$TEMP_DIR/prod.$FILE_EXT" <<- EOF
[mariner-official-extras]
name=CBL-Mariner Official Extras \$releasever \$basearch
baseurl=$BASE_URL
gpgkey=file:///etc/pki/rpm-gpg/MICROSOFT-RPM-GPG-KEY file:///etc/pki/rpm-gpg/MICROSOFT-METADATA-GPG-KEY
gpgcheck=1
repo_gpgcheck=1
enabled=1
skip_if_unavailable=True
sslverify=1
EOF
        else
            REPO_PATH="$REPO_ENDPOINT$REPO_ADD_PATH/$LINUX_FLAVOR/${LINUX_VERSION%%.*}/prod/"
            FILE_EXT=repo
            printf "[packages-microsoft-com-prod]\nname=packages-microsoft-com-prod\nbaseurl=$REPO_PATH\nenabled=1\ngpgcheck=1\ngpgkey=$REPO_ENDPOINT/keys/microsoft.asc" >"$TEMP_DIR/prod.$FILE_EXT"
            if [ $PACKAGE_MANAGER == 'zypper' ]; then
                printf "\nautorefresh=1" >>"$TEMP_DIR/prod.$FILE_EXT"
            fi
        fi
    fi

    # Check if the repo URL is valid
    if ! check_url_exists "$REPO_PATH"; then
        exit $ERROR_UNSUPPORTED_OS
    fi

    # Check if the VM has a MSI.
    # Arc machines always have MSI so no need to check.
    if [ "$isAzureMachine" -eq "1" ]; then
        check_for_msi
    fi

    # Install the key
    if [ $LINUX_FLAVOR != 'mariner' ]; then
        install_tool /usr/bin/gpg gnupg

        ERROR_MESSAGE='Failed to install Microsoft repo key'
        keyFile="$TEMP_DIR/microsoft.asc"
        if [ $PACKAGE_TYPE == 'DEB' ]; then
            rm -f /etc/apt/trusted.gpg.d/microsoft-prod.gpg
            gpg --dearmor < $keyFile > /etc/apt/trusted.gpg.d/microsoft-prod.gpg
        else
            rpm --import $keyFile
        fi
    fi

    # Install the repo.
    ERROR_MESSAGE='Failed to install Microsoft repo'
    if [ $PACKAGE_MANAGER == 'apt' ]; then
        FILE_FOLDER=/etc/apt/sources.list.d
    elif [ $PACKAGE_MANAGER == 'yum' ]; then
        FILE_FOLDER=/etc/yum.repos.d
    elif [ $PACKAGE_MANAGER == 'zypper' ]; then
        FILE_FOLDER=/etc/zypp/repos.d
    fi
    if [ $LINUX_FLAVOR == 'mariner' ]; then
        MS_REPO_CONFIG="$FILE_FOLDER/mariner-official-extras.$FILE_EXT"
    else
        MS_REPO_CONFIG="$FILE_FOLDER/microsoft-prod.$FILE_EXT"
    fi
    if [ -f "$MS_REPO_CONFIG" ]; then
        mv -f -T "$MS_REPO_CONFIG" "$TEMP_DIR/prod.backup"
    fi
    if [ ! -d "$FILE_FOLDER" ]; then
        mkdir -p "$FILE_FOLDER"
    fi
    cp "$TEMP_DIR/prod.$FILE_EXT" $MS_REPO_CONFIG
    chmod 644 $MS_REPO_CONFIG

    if [ $PACKAGE_MANAGER == 'apt' ]; then
        # Make sure apt-transport-https is installed (not needed for apt > v1.5)
        install_tool /usr/lib/apt/methods/https apt-transport-https
    fi

    # Update the repos and check if the packages are available for this distro.
    if refresh_repos; then
        if [ $PACKAGE_MANAGER == 'apt' ]; then
            if [ -z "$(apt-cache search aadsshlogin)" ]; then
                exit $ERROR_UNSUPPORTED_OS
            fi
        elif [ $PACKAGE_MANAGER == 'yum' ]; then
            if yum list aadsshlogin 2>&1 | grep 'No matching' >/dev/null; then
                exit $ERROR_UNSUPPORTED_OS
            fi
        elif [ $PACKAGE_MANAGER == 'zypper' ]; then
            if zypper search -s aadsshlogin 2>&1 | grep 'No matching' >/dev/null; then
                exit $ERROR_UNSUPPORTED_OS
            fi
        fi
    else
        echo 'Failing to refresh repos. Check for package existence will not be performed.'
    fi

    # Now we are ready to install all needed packages
    if package_is_installed $PKGSELINUX_POLICY; then
        install_package aadsshlogin-selinux
        # RPM ignores postinst failures. Do a sanity check here to verify it was sucessful.
        if ! semodule -l | grep aad_permissions >/dev/null; then
            ERROR_MESSAGE='SeLinux module aad_permissions failed to register'
            exit $ERROR_POSTINST_FAILED
        fi
    fi

    install_package aadsshlogin

    # RPM ignores postinst failures. Do a sanity check here to verify it was sucessful.
    grep -q 'aad' /etc/nsswitch.conf || { ERROR_MESSAGE="Missing registration in nsswitch.conf"; exit $ERROR_POSTINST_FAILED; }
    grep -q 'pam_aad' /etc/pam.d/* || { ERROR_MESSAGE="Missing auth registration in PAM"; exit $ERROR_POSTINST_FAILED; }
    grep -q 'aad_certhandler' /etc/ssh/sshd_config || { ERROR_MESSAGE="Missing AuthorizedKeysCommand registration"; exit $ERROR_POSTINST_FAILED; }

    # Clear the list of installed packages; we don't want the cleanup code to uninstall them.
    unset MS_REPO_CONFIG
    unset INSTALLED_PACKAGES
}

perform_install()
{
    OPERATION='Install'
    echo "Installing..."
    common_install
}

perform_uninstall()
{
    OPERATION='UnInstall'
    echo "Uninstalling..."

    # In the case of an update, do nothing. It is an update if the version file exists and it is not the same version as this extension.
    if [ -f "$EXTENSION_VERSION_FILE" ] && [ $(<$EXTENSION_VERSION_FILE) != $EXTENSION_VERSION ]; then
        echo "Version file does not match the current extension version; skipping uninstall."
        exit 0
    fi

    stop_unattended_upgrades

    uninstall_package aadsshlogin
    uninstall_package aadsshlogin-selinux

    #Delete the version file
    rm -f $EXTENSION_VERSION_FILE
}

perform_update()
{
    OPERATION='Update'
    echo "Updating..."
    common_install
}

perform_enable()
{
    OPERATION='Enable'
    echo "Enabling - nothing to do"
}

perform_disable()
{
    OPERATION='Disable'
    echo "Disabling - nothing to do"
}

case $1 in
    install) perform_install;;
    uninstall) perform_uninstall;;
    update) perform_update;;
    enable) perform_enable;;
    disable) perform_disable;;
    *)
        ERROR_MESSAGE="Unknown command"
        exit $ERROR_UNKNOWN_COMMAND;;
esac