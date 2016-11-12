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
# Copyright 2016 Nexenta Systems, Inc.
#

export PATH="/usr/bin"
export NOINUSE_CHECK=1
export STF_SUITE="/opt/zfs-tests"
export STF_TOOLS="/opt/test-runner/stf"
export PATHDIR=""
runner="/opt/test-runner/bin/run"
auto_detect=false

if [[ -z "$TESTFAIL_CALLBACKS" ]] ; then
	export TESTFAIL_CALLBACKS="$STF_SUITE/callbacks/zfs_dbgmsg.ksh"
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
	    '/c[0-9]*t[0-9a-f]*d[0-9]/ {print $1}' | sed 's/s[0-9]//g')

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
	fi

	[[ -n $distro ]] && echo $STF_SUITE/runfiles/$distro.run
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
	for disk in $DISKS; do
		sudo -k prtvtoc /dev/rdsk/${disk}s0 >/dev/null 2>&1
		[[ $? -eq 0 ]] || return 1
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
}

constrain_path
export PATH=$PATHDIR

verify_id
while getopts ac:q c; do
	case $c in
	'a')
		auto_detect=true
		;;
	'c')
		runfile=$OPTARG
		[[ -f $runfile ]] || fail "Cannot read file: $runfile"
		;;
	'q')
		quiet='-q'
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

[[ -z $runfile ]] && runfile=$(find_runfile)
[[ -z $runfile ]] && fail "Couldn't determine distro"

. $STF_SUITE/include/default.cfg

num_disks=$(echo $DISKS | awk '{print NF}')
[[ $num_disks -lt 3 ]] && fail "Not enough disks to run ZFS Test Suite"

# Ensure user has only basic privileges.
ppriv -s EIP=basic -e $runner $quiet -c $runfile
ret=$?

rm -rf $PATHDIR || fail "Couldn't remove $PATHDIR"

exit $ret
