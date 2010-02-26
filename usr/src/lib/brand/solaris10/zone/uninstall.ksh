#!/bin/ksh93 -p
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
# Use is subject to license terms.
#

#
# common shell script functions
#
. /usr/lib/brand/solaris10/common.ksh
. /usr/lib/brand/shared/uninstall.ksh

#
# options processing
#
# If we weren't passed at least two arguments, exit now.
(( $# < 2 )) && exit $ZONE_SUBPROC_USAGE

zonename=$1
zonepath=$2

shift 2

options="FhHnv"
options_repeat=""
options_seen=""

opt_F=""
opt_n=""
opt_v=""

# check for bad or duplicate options
OPTIND=1
while getopts $options OPT ; do
case $OPT in
	\? ) usage_err ;; # invalid argument
	: ) usage_err ;; # argument expected
	* )
		opt=`echo $OPT | sed 's/-\+//'`
		if [ -n "$options_repeat" ]; then
			echo $options_repeat | grep $opt >/dev/null
			[ $? = 0 ] && break
		fi
		( echo $options_seen | grep $opt >/dev/null ) &&
			usage_err
		options_seen="${options_seen}${opt}"
		;;
esac
done

# check for a help request
OPTIND=1
while getopts :$options OPT ; do
case $OPT in
	h|H ) usage
esac
done

# process options
OPTIND=1
while getopts :$options OPT ; do
case $OPT in
	F ) opt_F="-F" ;;
	n ) opt_n="-n" ;;
	v ) opt_v="-v" ;;
esac
done
shift `expr $OPTIND - 1`

[ $# -gt 0 ]  && usage_err

#
# main
#
zoneroot=$zonepath/root

nop=""
if [[ -n "$opt_n" ]]; then
	nop="echo"
	#
	# in '-n' mode we should never return success (since we haven't
	# actually done anything). so override ZONE_SUBPROC_OK here.
	#
	ZONE_SUBPROC_OK=$ZONE_SUBPROC_FATAL
fi

#
# We want uninstall to work in the face of various problems, such as a
# zone with no delegated root dataset or multiple active datasets, so we
# don't use the common functions.  Instead, we do our own work and
# are tolerant of errors.
#
uninstall_get_zonepath_ds
uninstall_get_zonepath_root_ds

# find all the zone BE datasets.
unset fs_all
(( fs_all_c = 0 ))
/sbin/zfs list -H -t filesystem -o name -r $ZONEPATH_RDS | while read fs; do
	# only look at filesystems directly below $ZONEPATH_RDS
	[[ "$fs" != ~()($ZONEPATH_RDS/+([^/])) ]] && continue

	fs_all[$fs_all_c]=$fs
	(( fs_all_c = $fs_all_c + 1 ))
done

destroy_zone_datasets

exit $ZONE_SUBPROC_OK
