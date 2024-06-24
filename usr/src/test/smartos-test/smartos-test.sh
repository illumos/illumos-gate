#! /usr/bin/bash
#
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2020 Joyent, Inc.
# Copyright 2024 MNX Cloud, Inc.
#

#
# This script is designed to run on an (effectively) disposable SmartOS
# install to configure the system, install a series of tests from the
# smartos-gate, and execute them.
# It exits 1 if any configuration, setup or test fails.
#

export PATH=/usr/bin:/usr/sbin:/opt/tools/sbin:/opt/tools/bin:$PATH

#
# Set $KEEP as a precaution in case we ever end up running the zfs-test suite
# by accident or design. This ensures it never attempts to destroy the 'zones'
# zpool. Note that the ZFS test suite also wants DISKS set to the disks which
# it can create/destroy pools on, but we're not computing that here.
#
if [[ -z "$KEEP" ]]; then
    export KEEP="zones"
fi

#
# Accumulate test suite exit codes and a list of failed tests
#
RESULT=0
FAILED_TESTS=""

function fatal {
    echo "ERROR: $@"
    exit 1
}

function warn {
    echo "WARNING: $@"
}

function log {
    echo "$@"
}

function log_must {
    echo "Running $@"
    $@ || fatal "Error running command."
}

function log_test {
    echo ""
    TEST_NAME=$1
    shift
    echo "Starting test for $TEST_NAME with $@"
    $@
    TEST_RESULT=$?
    if [[ $TEST_RESULT -ne 0 ]]; then
        FAILED_TESTS="$FAILED_TESTS $TEST_NAME"
    fi
    RESULT=$(( $RESULT + $TEST_RESULT ))
}

function log_testrunner {
    echo ""
    TEST_NAME=$1
    shift
    echo "Starting test-runner for $TEST_NAME with $@"
    /opt/test-runner/bin/run -c $@
    TEST_RESULT=$?
    if [[ $TEST_RESULT -ne 0 ]]; then
        FAILED_TESTS="$FAILED_TESTS $TEST_NAME"
    fi
    RESULT=$(( $RESULT + $TEST_RESULT ))
    # test-runner's default log dirs use a timestamp at per-second granularity.
    # Sleep here to ensure a unique timestamp per run if consecutive tests
    # bail out early.
    sleep 1
}

function guard_production_data {

    if [[ ! -f "/lib/sdc/.sdc-test-no-production-data" ]]; then
        cat <<EOF
To setup and run these tests you must create the file:
    /lib/sdc/.sdc-test-no-production-data
after ensuring you have no production data on this system.
EOF
        exit 1
    fi
}

function zone_check {
    if [[ $(zonename) != "global" ]]; then
        fatal "these tests must be run from the global zone."
    fi
}

#
# Check that the tests.buildstamp file in the test archive matches
# the current platform stamp. Running tests designed for a platform
# that we're not running is a bad idea.
#
function version_check {
    PLATFORM_VERSION=$(uname -v | sed -e 's/^joyent_//g')
    mkdir -p /tmp/version_check.$$
    tar xzf $1 -C /tmp/version_check.$$ ./tests.buildstamp
    TESTS_VERSION=$(cat /tmp/version_check.$$/tests.buildstamp)
    rm -rf /tmp/version_check.$$
    log "Platform version: $PLATFORM_VERSION"
    log "   Tests version: $TESTS_VERSION"
    if [[ "$PLATFORM_VERSION" != "$TESTS_VERSION" ]]; then
        fatal "mismatched platform version and tests version!"
    fi
}

function snapshot_rollback_opt {
    snapshot="system-test-smartos-test"
    has_snapshot=$(zfs list zones/opt@$snapshot 2> /dev/null)
    if [[ -n "$has_snapshot" ]]; then
        log_must zfs rollback zones/opt@$snapshot
    else
        log_must zfs snapshot zones/opt@$snapshot
    fi
}

#
# Since some tests want to deliver to /usr which is read-only on SmartOS,
# we make a temporary directory, dump the current /usr there, extract our
# content to it, then lofs-mount it over the real thing.
#
function add_loopback_mounts {
    test_archive=$1
    lofs_home=/var/tmp/smartos-test-loopback

    # If /usr is already lofs mounted, and pointing at $lofs_home, just
    # extract our new test bits on top. Ideally we'd just unmount it,
    # but while running this script, there's a good chance that the dataset
    # will be busy and the umount would fail.
    FS=$(/bin/df -n /usr | awk '{print $NF'})
    if [[ "$FS" == "lofs" ]]; then
        is_test_lofs=$(mount | grep ^/usr | grep "$lofs_home/usr ")
        if [[ -z "$is_test_lofs" ]]; then
            fatal "unsupported: existing lofs mount for /usr is not $lofs_home"
        else
            log "Extracting new test archive to lofs-mounted /usr"
            # extract the current test archive to it
            log_must tar -xzf $test_archive -C $lofs_home ./usr
        fi
    # Otherwise, setup a lofs mount for it.
    else
        log "Creating new lofs mount for /usr on $lofs_home"
        rm -rf $lofs_home
        mkdir -p $lofs_home
        find /usr | cpio -pdum $lofs_home
        log_must tar -xzf $test_archive -C $lofs_home ./usr
        # keep /usr read-only in an attempt to preserve smartos behaviour
        # unless specifically asked to
        if [[ "$mount_usr_rw" = "true" ]]; then
            mount_opts="-o rw"
        else
            mount_opts="-o ro"
        fi
        log_must mount -O -F lofs $mount_opts $lofs_home/usr /usr
    fi
}

#
# The ZFS test suite often will invoke user{add,del,mod}(8). Move /etc/shadow
# into /etc's normal ramdisk volume.  The link(2) calls the above utilities
# use will start working, unlocking a great deal of tests.
#
function shadow_fix {
    FS=$(/bin/df -n /etc/shadow | awk '{print $NF'})
    if [[ "$FS" == "lofs" ]]; then
	log_must umount /etc/shadow
	log_must cp -pf /usbkey/shadow /etc/shadow
    fi
    # Else leave it alone.
}

#
# Extract the non-/usr parts of the test archive
#
function extract_remaining_test_bits {
    log_must tar -xzf $1 -C / \
        ./opt ./kernel ./tests.manifest.gen ./tests.buildstamp
}

function setup_pkgsrc {

    if [[ -f /opt/tools/etc/pkgin/repositories.conf ]]; then
        log "Pkgsrc bootstrap already setup, continuing"
        return
    fi

    # We should always use the same pkgsrc version as we have installed
    # on the build machine in case any of our tests link against libraries
    # in /opt/tools
    PKGSRC_STEM="https://pkgsrc.smartos.org/packages/SmartOS/bootstrap"
    BOOTSTRAP_TAR="bootstrap-2021Q4-tools.tar.gz"
    BOOTSTRAP_SHA="c427cb1ed664fd161d8e12c5191adcae7aee68b4"

    # Ensure we are in a directory with enough space for the bootstrap
    # download, by default the SmartOS /root directory is limited to the size
    # of the ramdisk.
    cd /var/tmp

    # Download the bootstrap kit to the current directory.  Note that we
    # currently pass "-k" to skip SSL certificate checks as the GZ doesn't
    # install them.
    log_must curl -kO ${PKGSRC_STEM}/${BOOTSTRAP_TAR}

    # Verify the SHA1 checksum.
    [[ "${BOOTSTRAP_SHA}" = "$(/bin/digest -a sha1 ${BOOTSTRAP_TAR})" ]] || \
        fatal "checksum failure for ${BOOTSTRAP_TAR}, expected ${BOOTSTRAP_SHA}"

    # Install bootstrap kit to /opt/tools
    log_must tar -zxpf ${BOOTSTRAP_TAR} -C /
}

# The pkgsrc packages we will install are now a single metapackage.
# If updates in that metapackage (e.g. python change) cause tests to fail,
# consult with pkgsrc and/or maintainers of usr/src/test tests to update.

function install_required_pkgs {

    log_must pkgin -y in smartos-test-tools
}

function add_test_accounts {

    grep -q '^cyrus:' /etc/passwd
    if [[ $? -ne 0 ]]; then
        log "Adding cyrus user"
        echo "cyrus:x:977:1::/zones/global/cyrus:/bin/sh" >> /etc/passwd
        if ! grep -q '^cyrus:' /etc/shadow; then
            echo "cyrus:*LK*:::::::" >> /etc/shadow
        fi
        mkdir -p /zones/global/cyrus
        chown cyrus /zones/global/cyrus
    fi
    grep -q '^ztest:' /etc/passwd
    if [[ $? -ne 0 ]]; then
        log "Adding ztest user"
        echo "ztest:x:978:1::/zones/global/ztest:/bin/sh" >> /etc/passwd
        if ! grep -q '^ztest:' /etc/shadow; then
            # For sudo to work, the ztest account must not be locked
            echo "ztest:NP:::::::" >> /etc/shadow
        fi
        mkdir -p /zones/global/ztest
        chown ztest /zones/global/ztest
        zprofile=/zones/global/ztest/.profile
        if [[ ! -f $zprofile ]]; then
            cat > $zprofile <<-EOF
PATH=/bin:/usr/bin:/sbin:/usr/sbin:/opt/tools/bin:/opt/tools/sbin:/opt/zfs-tests/bin
export PATH

KEEP="zones"
export KEEP
EOF

            if [[ -n "$DISKS" ]]; then
		# NOTE: This will be enough to make this script's execute-tests
		# invocation run the ZFS test suite.
                echo "DISKS=\"$DISKS\"" >> $zprofile
		echo "export DISKS" >> $zprofile
            else
                msg='echo Please set \$DISKS appropriate before running zfstest'
                echo $msg >> $zprofile
            fi

            chown ztest $zprofile
        fi
    fi
    if [[ ! -f /opt/tools/etc/sudoers.d/ztest ]]; then
        mkdir -p /opt/tools/etc/sudoers.d
        echo "ztest ALL=(ALL) NOPASSWD: ALL" >> /opt/tools/etc/sudoers.d/ztest
    fi
}

function zfs_test_check {
    # DISKS is set either in our environment, or in the .profile of ~ztest.
    zprofile=/zones/global/ztest/.profile
    zdisksvar=$(su - ztest -c 'echo $DISKS' | tail -1)

    # Check for KEEP too.
    grep -q ^KEEP= $zprofile || \
	fatal "Cannot run ZFS test, you need KEEP set in your ztest's environment"

    # If neither are set DO NOT RUN the ztests.
    if [[ -z $DISKS && -z $zdisksvar ]]; then
	fatal "Cannot run ZFS test, you need DISKS set in your or ztest's environment"
    fi

    # Check if they are both non-zero and different.
    if [[ -n "$DISKS" && -n "$zdisksvar" && "$DISKS" != "$zdisksvar" ]]; then
	log "DISKS in current root environment: $DISKS"
	log "DISKS in user ztest's environment: $zdisksvar"
	fatal "Pleast reconcile these two before running the ZFS tests."
    fi

    if [[ -z "$zdisksvar" ]]; then
	# put DISKS into ztest's .profile.
        echo "DISKS=\"$DISKS\"" >> $zprofile
	echo "export DISKS" >> $zprofile
    fi

    # OKAY, now we can run it!
    log_test zfstest su - ztest -c /opt/zfs-tests/bin/zfstest
}

function nvme_test_check {
    # Execute the unit tests regardless...
    log_testrunner nvme-tests /opt/nvme-tests/runfiles/unit.run

    # If we specify NVME_TEST_DEVICE, then run the non-destructive NVMe tests.
    if [[ -n "$NVME_TEST_DEVICE" ]]; then
	log_testrunner nvme-tests /opt/nvme-tests/runfiles/non-destruct.run
    else
	log "Skipping NVMe non-destructive tests"
    fi
}

#
# By using log_test or log_testrunner, we accumulate the exit codes from each
# test run to $RESULT.
#
# We don't - yet - run net-tests, smbclient-tests, zfs-tests, or the dtrace
# suite.
#
function execute_tests {

    log "Starting test runs"
    log_test bhyvetest /opt/bhyve-tests/bin/bhyvetest
    log_testrunner crypto-tests /opt/crypto-tests/runfiles/default.run
    log_testrunner elf-tests /opt/elf-tests/runfiles/default.run
    log_testrunner libc-tests /opt/libc-tests/runfiles/default.run
    log_testrunner libsec-tests /opt/libsec-tests/runfiles/default.run
    log_test vndtest /opt/vndtest/bin/vndtest -a
    log_testrunner util-tests /opt/util-tests/runfiles/default.run
    log_testrunner os-tests /opt/os-tests/runfiles/default.run
    nvme_test_check
    zfs_test_check

    if [[ -n "$FAILED_TESTS" ]]; then
        echo ""
        log "Failures were seen in the following test suites: $FAILED_TESTS"
    fi

}

function usage {
    echo "Usage: smartos-test [-h] [-c] [-e] [-r] [-w] <path to tests.tgz>"
    echo ""
    echo "At least one of -c, -e, -r is required."
    echo ""
    echo "  -h       print usage"
    echo "  -c       configure the system for testing"
    echo "  -e       execute known tests"
    echo "  -f       skip the check to ensure platform version == test version"
    echo "  -r       snapshot or rollback to zones/opt@system-test-smartos-test"
    echo "           before doing any system configuration or test execution"
    echo "  -w       when mounting the lofs /usr, make it writable"
}

mount_usr_rw=false
skip_version_check=false
do_configure=false
do_execute=false
do_rollback=false

#
# Main
#
while getopts "cefrwh" opt; do
    case "${opt}" in
        c)
            do_configure=true
            ;;
        e)
            do_execute=true
            ;;
        f)
            skip_version_check=true
            ;;
        r)
            do_rollback=true
            ;;
        h)
            usage
            exit 2
            ;;
        w)
            mount_usr_rw=true
            ;;
        *)
            log "unknown argument ${opt}"
            usage
            exit 2
    esac
done
shift $((OPTIND - 1))

test_archive=$1

if [[ -z "$test_archive" ]]; then
    log "missing test archive argument."
    usage
    exit 1
fi

if [[ ! -f "$test_archive" ]]; then
    usage
    fatal "unable to access test archive at $test_archive"
fi

if [[ "$do_rollback" = false && \
        "$do_configure" = false && \
        "$do_execute" = false ]]; then
    log "nothing to do: use at least one of -r -e -c"
    usage
    exit 2
fi

if [[ "$skip_version_check" = false ]]; then
    version_check $1
fi

guard_production_data
zone_check

if [[ $do_rollback = true ]]; then
    snapshot_rollback_opt
fi

if [[ $do_configure = true ]]; then
    shadow_fix
    add_loopback_mounts $test_archive
    extract_remaining_test_bits $test_archive
    add_test_accounts
    setup_pkgsrc
    install_required_pkgs
    # Enable per-process coredumps, some tests assume they're pre-set.
    log_must coreadm -e process
    log "This system is now configured to run the SmartOS tests."
fi

if [[ "$do_execute" = true ]]; then
    execute_tests
fi

if [[ $RESULT -gt 0 ]]; then
    exit 1
else
    exit 0
fi
