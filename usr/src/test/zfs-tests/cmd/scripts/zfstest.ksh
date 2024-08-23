#!/usr/bin/ksh

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
# Copyright (c) 2012, 2016 by Delphix. All rights reserved.
# Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
# Copyright 2019 Joyent, Inc.
# Copyright 2021 Tintri by DDN, Inc. All rights reserved.
# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
# Copyright 2024 MNX Cloud, Inc.
#

export PATH="/usr/bin"
export NOINUSE_CHECK=1
export STF_SUITE="/opt/zfs-tests"
export COMMON="$STF_SUITE/runfiles/common.run"
export STF_TOOLS="/opt/test-runner/stf"
export PATHDIR=""
runner="/opt/test-runner/bin/run"
auto_detect=false

if [[ -z "$TESTFAIL_CALLBACKS" ]] ; then
	export TESTFAIL_CALLBACKS="$STF_SUITE/callbacks/zfs_dbgmsg"
fi

function fail
{
	echo $1
	exit ${2:-1}
}

function find_disks
{
	typeset all_disks=$(echo '' | sudo -k format | awk \
	    '/c[0-9]/ {print $2}')
	typeset used_disks=$(zpool status | awk \
	    '/c[0-9]+(t[0-9a-fA-F]+)?d[0-9]+/ {print $1}' | sed -E \
	    's/(s|p)[0-9]+//g')

	typeset disk used avail_disks
	for disk in $all_disks; do
		for used in $used_disks; do
			[[ "$disk" = "$used" ]] && continue 2
		done
		[[ -n $avail_disks ]] && avail_disks="$avail_disks $disk"
		[[ -z $avail_disks ]] && avail_disks="$disk"
	done

	echo $avail_disks
}

function find_rpool
{
	typeset ds=$(mount | awk '/^\/ / {print $3}')
	echo ${ds%%/*}
}

function find_runfile
{
	typeset distro=
	if [[ -d /opt/delphix && -h /etc/delphix/version ]]; then
		distro=delphix
	elif [[ 0 -ne $(grep -c OpenIndiana /etc/release 2>/dev/null) ]]; then
		distro=openindiana
	elif [[ 0 -ne $(grep -c OmniOS /etc/release 2>/dev/null) ]]; then
		distro=omnios
	elif [[ 0 -ne $(grep -c SmartOS /etc/release 2>/dev/null) ]]; then
		distro=smartos
	fi

	[[ -n $distro ]] && echo $COMMON,$STF_SUITE/runfiles/$distro.run
}

function verify_id
{
	[[ $(id -u) = "0" ]] && fail "This script must not be run as root."

	sudo -k -n id >/dev/null 2>&1
	[[ $? -eq 0 ]] || fail "User must be able to sudo without a password."
}

function verify_disks
{
	typeset disk
	typeset path
	typeset -lu expected_size
	typeset -lu size

	# Ensure disks are large enough for the tests: no less than 10GB
	# and large enough for a crash dump plus overheads: the disk partition
	# table (about 34k), zpool with 4.5MB for pool label and 128k for pool
	# data, so we round up pool data + labels to 5MB.
	expected_size=$(sudo -k -n dumpadm -epH)
	(( expected_size = expected_size + 5 * 1024 * 1024 ))

	if (( expected_size < 10 * 1024 * 1024 * 1024 )); then
		(( expected_size = 10 * 1024 * 1024 * 1024 ))
	fi

	for disk in $DISKS; do
		case $disk in
		/*) path=$disk;;
		*) path=/dev/rdsk/${disk}s0
		esac
		set -A disksize $(sudo -k prtvtoc $path 2>&1 |
			awk '$3 == "bytes/sector" ||
			    ($3 == "accessible" && $4 == "sectors") {print $2}')

		if [[ (-n "${disksize[0]}") && (-n "${disksize[1]}") ]]; then
			(( size = disksize[0] * disksize[1] ))
		else
			return 1
		fi
		if (( size <  expected_size )); then
			(( size = expected_size / 1024 / 1024 / 1024 ))
			fail "$disk is too small, need at least ${size}GB"
		fi
	done
	return 0
}

function create_links
{
	typeset dir=$1
	typeset file_list=$2

	[[ -n $PATHDIR ]] || fail "PATHDIR wasn't correctly set"

	for i in $file_list; do
		[[ ! -e $PATHDIR/$i ]] || fail "$i already exists"
		ln -s $dir/$i $PATHDIR/$i || fail "Couldn't link $i"
	done

}

function constrain_path
{
	. $STF_SUITE/include/commands.cfg

	PATHDIR=$(/usr/bin/mktemp -d /var/tmp/constrained_path.XXXX)
	chmod 755 $PATHDIR || fail "Couldn't chmod $PATHDIR"

	create_links "/usr/bin" "$USR_BIN_FILES"
	create_links "/usr/sbin" "$USR_SBIN_FILES"
	create_links "/sbin" "$SBIN_FILES"
	create_links "/opt/zfs-tests/bin" "$ZFSTEST_FILES"

	# Special case links
	ln -s /usr/gnu/bin/dd $PATHDIR/gnu_dd

	# SmartOS does not ship some required commands by default.
	# Link to them in the package manager's namespace.
	pkgsrc_bin=/opt/tools/bin
	pkgsrc_packages="fio uuidgen md5sum sudo truncate python base64 shuf sha256sum"
	for pkg in $pkgsrc_packages; do
		if [[ ! -x $PATHDIR/$pkg ]]; then
			rm -f $PATHDIR/$pkg &&
			    ln -s $pkgsrc_bin/$pkg $PATHDIR/$pkg ||
			    fail "Couldn't link $pkg"
		fi
	done
}

constrain_path
export PATH=$PATHDIR

verify_id
while getopts ac:l:qT: c; do
	case $c in
	'a')
		auto_detect=true
		;;
	'c')
		runfile=$OPTARG
		[[ -f $runfile ]] || fail "Cannot read file: $runfile"
		if [[ -z $runfiles ]]; then
			runfiles=$runfile
		else
			runfiles+=",$runfile"
		fi
		;;
	'l')
		logfile=$OPTARG
		[[ -f $logfile ]] || fail "Cannot read file: $logfile"
		xargs+=" -l $logfile"
		;;
	'q')
		xargs+=" -q"
		;;
	'T')
		xargs+=" -T $OPTARG"
		;;
	esac
done
shift $((OPTIND - 1))

# If the user specified -a, then use free disks, otherwise use those in $DISKS.
if $auto_detect; then
	export DISKS=$(find_disks)
elif [[ -z $DISKS ]]; then
	fail "\$DISKS not set in env, and -a not specified."
else
	verify_disks || fail "Couldn't verify all the disks in \$DISKS"
fi

# Add the root pool to $KEEP according to its contents.
# It's ok to list it twice.
if [[ -z $KEEP ]]; then
	KEEP="$(find_rpool)"
else
	KEEP+=" $(find_rpool)"
fi

export __ZFS_POOL_EXCLUDE="$KEEP"
export KEEP="^$(echo $KEEP | sed 's/ /$|^/g')\$"

[[ -z $runfiles ]] && runfiles=$(find_runfile)
[[ -z $runfiles ]] && fail "Couldn't determine distro"

. $STF_SUITE/include/default.cfg

num_disks=$(echo $DISKS | awk '{print NF}')
[[ $num_disks -lt 3 ]] && fail "Not enough disks to run ZFS Test Suite"

# Ensure user has only basic privileges.
ppriv -s EIP=basic -e $runner -c $runfiles $xargs
ret=$?

rm -rf $PATHDIR || fail "Couldn't remove $PATHDIR"

exit $ret
