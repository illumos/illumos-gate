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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
#

#
# NAME
#       smbmount_init
#
# DESCRIPTION
#       Create mount point for smbfs
#
# RETURN
#       0 - create successfully
#       1 - create failed
#
smbmount_init() {
	rm -rf $1
	cti_execute_cmd "mkdir $1"
	if [[ $? != 0 ]]; then
		cti_unresolved "UNRESOLVED: mkdir $1 failed"
		exit 1
	else
		cti_report "PASS: mkdir $1 successfully"
	fi
	return 0
}

#
# NAME
#       testdir_init
#
# DESCRIPTION
#       Create the test directory for smbfs testing
#
# RETURN
#       0 - create successfully
#       1 - create failed
#
testdir_init() {
	rm -rf $1
	cti_execute_cmd "mkdir $1"
	if [[ $? != 0 ]]; then
		cti_unresolved "UNRESOLVED: mkdir $1 failed"
		exit 1
	else
		cti_report "PASS: mkdir $1 successfully"
	fi
	return 0
}

#
# NAME
#       smbmount_getmntopts
#
# DESCRIPTION
#       Get the mount options string for the passed mount point,
#	(i.e. remote/read/write/setuid/devices/intr/xattr/dev=...)
#	which is copied to stdout for use by the caller.
#
# RETURN
#       0 - the mount is found, and is an smbfs mount
#       1 - any problem (no stdout in error cases)
#
smbmount_getmntopts() {
	typeset res on mp tp mtype opts rest
	/usr/sbin/mount -v |
	while read res on mp tp mtype opts rest
	do
		if [[ "$mp" == "$1" ]] ; then
			if [[ $mtype != smbfs ]] ; then
				echo "$1: not an smbfs mount" >&2
				return 1
			fi
			echo "$opts"
			return 0
		fi
	done
	echo "$1: no such mount point" >&2
	return 1
}

#
# NAME
#       smbmount_check
#
# DESCRIPTION
#       verify the passed dir is an smbfs mount
#
# RETURN
#       0 - it is an smbfs mount (successful)
#       1 - it is not... (fail)
#
smbmount_check() {
	cti_execute FAIL smbmount_getmntopts "$1"
	return $?
}

#
# NAME
#       smbmount_clean
#
# DESCRIPTION
#       umount the smbfs and cleanup the mount point
#
# RETURN
#       0 - umount and cleanup  successfully
#       1 - umount or cleanup failed
#
smbmount_clean() {

	# is it mounted?
	smbmount_getmntopts "$1" >/dev/null 2>&1
	if [[ $? == 0 ]]; then
		cti_execute_cmd sudo -n "umount -f $1"
		if [[ $? != 0 ]]; then
			cti_report "umount -f $1 failed"
			exit 1
		fi
	fi

	rm -rf $1
	if [[ $? != 0 ]]; then
		cti_report "rm -rf $1 failed"
		exit 1
	fi
	return 0
}
