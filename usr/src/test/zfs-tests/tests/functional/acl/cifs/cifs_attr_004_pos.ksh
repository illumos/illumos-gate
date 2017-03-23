#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
#

. $STF_SUITE/tests/functional/acl/acl_common.kshlib
. $STF_SUITE/tests/functional/acl/cifs/cifs.kshlib

#
# DESCRIPTION:
#	Verify the ability to continue writing to a file
#	after opening the file read/write, and setting
#	the DOS Readonly flag on that file.
#
# STRATEGY:
#	Run the special program "dos_ro"

verify_runnable "both"

function cleanup
{
	if [[ -n $gobject ]]; then
		destroy_object $gobject
	fi

	for fs in $TESTPOOL/$TESTFS $TESTPOOL ; do
		mtpt=$(get_prop mountpoint $fs)
		log_must rm -rf $mtpt/file.* $mtpt/dir.*
	done

	[[ -f $TESTFILE ]] && rm $TESTFILE
}

#
# Set the special attribute to the given node
#
# $1: The given node (file/dir)
# $2: The special attribute to be set
#
function set_attribute
{
	typeset object=$1
	typeset attr=$2

	if [[ -z $attr ]]; then
		attr="AHRSadimu"
		if [[ -f $object ]]; then
			attr="${attr}q"
		fi
	fi
	chmod S+c${attr} $object
	return $?
}

#
# Clear the special attribute to the given node
#
# $1: The given node (file/dir)
# $2: The special attribute to be cleared
#
function clear_attribute
{
	typeset object=$1
	typeset attr=$2

	if [[ -z $attr ]]; then
		if is_global_zone ; then
			attr="AHRSadimu"
			if [[ -f $object ]]; then
				attr="${attr}q"
			fi
		else
			attr="AHRS"
		fi
	fi

	chmod S-c${attr} $object
	return $?
}

FILES="file.0 file.1"
FS="$TESTPOOL $TESTPOOL/$TESTFS"
ATTRS="R"

TESTFILE=/tmp/tfile
TESTDIR=tdir
TESTATTR=tattr
TESTACL=user:$ZFS_ACL_OTHER1:write_data:allow
TESTMODE=777
TESTSTR="ZFS test suites"

log_assert "Verify writable open handle still works after " \
    "setting the DOS Readonly flag on a file."
log_onexit cleanup

echo "$TESTSTR" > $TESTFILE

typeset gobject
typeset gattr
for fs in $FS ; do
	mtpt=$(get_prop mountpoint $fs)
	chmod 777 $mtpt
	for user in root $ZFS_ACL_STAFF1; do
		log_must set_cur_usr $user
		for file in $FILES ; do
			gobject=$mtpt/$file
			create_object "file" $gobject $ZFS_ACL_CUR_USER
			log_must dos_ro $gobject
			destroy_object $gobject
		done
	done
done

log_pass "Writable handle OK after setting DOS R/O flag."
