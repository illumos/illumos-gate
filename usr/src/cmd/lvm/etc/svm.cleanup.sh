#! /usr/bin/sh
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# SVM Flash cleanup
# Remove existing master SVM configuration on clone after full flash install.
# Restore existing clone SVM configuation after differential flash install.
#

IN_SYS=${FLASH_ROOT}/etc/system
IN_CONF=${FLASH_ROOT}/kernel/drv/md.conf
IN_CF=${FLASH_ROOT}/etc/lvm/mddb.cf

TMP_SYS=/var/tmp/system.1
TMP_CONF=/var/tmp/md.conf.1
TMP_CF=/var/tmp/mddb.cf.1

# Directory where original clone config is saved.
SAVE_DIR=${FLASH_DIR}/flash/svm

if [ "${FLASH_TYPE}" = "FULL" ]; then
	# Full flash install, remove master's SVM configuration from clone.

	# Remove any SVM root entry from /etc/system file.
	nawk '
	BEGIN {delroot=0}
	/^\* Begin MDD root info \(do not edit\)$/ {delroot=1}
	/^\* End MDD root info \(do not edit\)$/ {delroot=0; next}
	{if (delroot == 0) print $0}
	' ${IN_SYS} > ${TMP_SYS}
	cp ${TMP_SYS} ${IN_SYS}

	# Check if we are on the mini-root.  If we are, we need to clean up the
	# mddb configuration since this implies we are doing a full flash onto
	# a fresh system.
	#
	# If we are not on the mini-root that must mean we are installing
	# the full flash via live-upgrade.  In that case we share the
	# SVM configuration with the currently running system so we
	# need to copy the md.conf file from the current root onto the
	# newly installed root.  Note that the flash archive might not have
	# been created from the currently running system.
	if [ -h /kernel/drv/md.conf ]; then
		# Remove SVM mddb entries from /kernel/drv/md.conf.
		nawk '
		BEGIN {delmddb=0}
		/^# Begin MDD database info \(do not edit\)$/ {delmddb=1}
		/^# End MDD database info \(do not edit\)$/ {delmddb=0; next}
		{if (delmddb == 0) print $0}
		' ${IN_CONF} > ${TMP_CONF}
		cp ${TMP_CONF} ${IN_CONF}

		# Remove SVM mddb entries from /etc/lvm/mddb.cf.
		nawk '
		/^#/ {print $0}
		' ${IN_CF} > ${TMP_CF}
		cp ${TMP_CF} ${IN_CF}

	else
		# copy SVM config from current root to new root
		cp /kernel/drv/md.conf ${IN_CONF}
		cp /etc/lvm/mddb.cf ${IN_CF}
	fi

	# We may need to enable the SVM services in SMF.  This could happen
	# if we used jumpstart or live-upgrade to create SVM volumes as
	# part of the flash install.
	#
	# It doesn't matter if we are doing a flash install via a jumpstart
	# on the mini-root or via a live-upgrade.  In both cases we check
	# the md.conf on the currently running root to see if SVM is
	# configured.  For the jumpstart case it will have setup the
	# volumes already so the mini-root md.conf has the mddb info.  For
	# the live-upgade case both roots will be sharing the same md.conf
	# and have the same view of the SVM configuration.
	#
	# Check if there are mddb entries in md.conf to determine if SVM is
	# configured.
	sed -e 's/#.*$//' /kernel/drv/md.conf | \
	    egrep '^[    ]*mddb_bootlist' >/dev/null 2>&1
	MDDB_STATUS=$?

	if [ $MDDB_STATUS -eq 0 ]; then
		echo "/usr/sbin/svcadm enable system/metainit:default" >> \
		    ${FLASH_ROOT}/var/svc/profile/upgrade

		echo "/usr/sbin/svcadm enable system/mdmonitor:default" >> \
		    ${FLASH_ROOT}/var/svc/profile/upgrade

		echo "/usr/sbin/svcadm enable network/rpc/meta:default" >> \
		    ${FLASH_ROOT}/var/svc/profile/upgrade
	fi

else
	# Differential flash install, restore clone SVM configuration.
	# The matrix of master/clone SVM config w/ diff. flash looks like:
	#
	# master    clone    clone after differential flash
	# 
	# yes        yes     same as clone prior to diff. flash
	# yes        no      no
	# no         yes     same as clone prior to diff. flash
	# no         no      no
	#

	# restore saved config files
	cp ${SAVE_DIR}/md.conf ${FLASH_ROOT}/kernel/drv/md.conf
	cp ${SAVE_DIR}/devpath ${FLASH_ROOT}/etc/lvm/devpath
	cp ${SAVE_DIR}/md.cf ${FLASH_ROOT}/etc/lvm/md.cf
	cp ${SAVE_DIR}/md.ctlrmap ${FLASH_ROOT}/etc/lvm/md.ctlrmap
	cp ${SAVE_DIR}/md.tab ${FLASH_ROOT}/etc/lvm/md.tab
	cp ${SAVE_DIR}/mddb.cf ${FLASH_ROOT}/etc/lvm/mddb.cf
	cp ${SAVE_DIR}/runtime.cf ${FLASH_ROOT}/etc/lvm/runtime.cf

	# Now process the various permutations for the master and clone
	# /etc/system file SVM root entries.

	# First check if we need to do anything with /etc/system.
	if `cmp -s ${SAVE_DIR}/system ${IN_SYS} >/dev/null 2>&1`; then
	    # There is no difference so leave it alone.
	    exit 0;
	fi

	# Get any SVM root entry from master /etc/system file.
	MASTER_ROOT=`nawk '
	BEGIN {inroot=0}
	/^\* Begin MDD root info \(do not edit\)$/ {inroot=1; next}
	/^\* End MDD root info \(do not edit\)$/ {inroot=0}
	{if (inroot == 1) print $0}
	' ${IN_SYS}`

	# Get any SVM root entry from clone /etc/system file.
	CLONE_ROOT=`nawk '
	BEGIN {inroot=0}
	/^\* Begin MDD root info \(do not edit\)$/ {inroot=1; next}
	/^\* End MDD root info \(do not edit\)$/ {inroot=0}
	{if (inroot == 1) print $0}
	' ${SAVE_DIR}/system`

	# If there is an SVM root entry in the master /etc/system file.
	if [ "${MASTER_ROOT}" ]; then

	    # If there is an SVM root entry in the clone /etc/system file.
	    if [ "${CLONE_ROOT}" ]; then

		# Restore clone SVM root entry in /etc/system file.
		nawk -v clone_root="${CLONE_ROOT}" '
		BEGIN {newroot=0}
		/^\* Begin MDD root info \(do not edit\)$/ {
		    newroot=1
		    print $0
		    print clone_root
		}
		/^\* End MDD root info \(do not edit\)$/ {newroot=0}
		{if (newroot == 0) print $0}
		' ${IN_SYS} >${TMP_SYS}
		cp ${TMP_SYS} ${IN_SYS}

	    else

		# There is no SVM root entry in the clone so remove the entry
		# from the /etc/system file.
		nawk '
		BEGIN {delroot=0}
		/^\* Begin MDD root info \(do not edit\)$/ {delroot=1}
		/^\* End MDD root info \(do not edit\)$/ {delroot=0; next }
		{if (delroot == 0) print $0}
		' ${IN_SYS} >${TMP_SYS}
		cp ${TMP_SYS} ${IN_SYS}

	    fi

	else
	    # Master has no SVM root entry in the /etc/system file.
	    if [ "${CLONE_ROOT}" ]; then
		# But clone does have one so we need to add it back in.

		echo "* Begin MDD root info (do not edit)" >> ${IN_SYS}
		echo "${CLONE_ROOT}" >> ${IN_SYS}
		echo "* End MDD root info (do not edit)" >> ${IN_SYS}
	    fi

	    # If neither master nor clone has SVM root entry then
	    # we just leave the system file alone.
	fi
fi

exit 0
