#!/bin/ksh -p

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
# Copyright (c) 2017, Intel Corporation.
# Copyright (c) 2018 by Delphix. All rights reserved.
# Copyright 2019 Joyent, Inc.
#

. $STF_SUITE/tests/functional/alloc_class/alloc_class.kshlib

#
# DESCRIPTION:
#	Importing and exporting pool with special device succeeds.
#
claim="Import/export of pool with special device mirror succeeds."

verify_runnable "global"

log_assert $claim
log_onexit cleanup

log_must disk_setup

typeset stype=""
typeset sdisks=""

typeset imp_opt=""
case "$(uname)" in
	Linux)	imp_opt="-s"
		;;
esac

for type in "" "mirror" "raidz"
do
	if [ "$type" = "mirror" ]; then
		stype="mirror"
		sdisks="${CLASS_DISK0} ${CLASS_DISK1} ${CLASS_DISK2}"
	elif [ "$type" = "raidz" ]; then
		stype="mirror"
		sdisks="${CLASS_DISK0} ${CLASS_DISK1}"
	else
		stype=""
		special_args="${CLASS_DISK0}"
	fi

	log_must zpool create $TESTPOOL $type $ZPOOL_DISKS \
	    special $stype $sdisks
	log_must zpool export $TESTPOOL
	log_must zpool import -d $TEST_BASE_DIR $imp_opt $TESTPOOL
	log_must display_status $TESTPOOL
	log_must zpool destroy -f $TESTPOOL
done

log_pass $claim
