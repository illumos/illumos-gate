#!/bin/ksh -p
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
# Copyright (c) 2014 Joyent, Inc.  All rights reserved.
#

#
# This file contains various hooks that are used by nore than a single
# brand. This file should be included by the brand-specific files.
#

jattach_kvm_final_setup()
{
	ZRAM=$(zonecfg -z ${ZONENAME} info attr name=ram | \
		grep "value: " | cut -d ':' -f2 | tr -d ' ')

	if [[ -z ${ZRAM} ]]; then
		echo "Unable to find RAM value for KVM VM"
		exit $ZONE_SUBPROC_FATAL
	fi

	# 100G unless the VM has 80G or more DRAM, in which case: DRAM + 20G.
	CORE_QUOTA=102400
	if [[ ${ZRAM} -gt 81920 ]]; then
		CORE_QUOTA=$((${ZRAM} + 20480))
	fi

	# The cores quota exists to control run-away zones. As such we make it
	# such that it will protect the system from a single run-away, but
	# still allow us to get most cores.
	rm -rf $ZONEPATH/cores
	zfs create -o quota=${CORE_QUOTA}m -o mountpoint=/${PDS_NAME}/$bname/cores \
	    ${PDS_NAME}/cores/$bname
}

jattach_zone_final_setup()
{
	if [[ -z ${REPROVISIONING} ]]; then
		# The cores quota exists to control run-away zones. As such we make it
		# such that it will protect the system from a single run-away, but
		# still allow us to get most cores. 100G seems good enough based on
		# samples from JPC.
		rm -rf $ZONEPATH/cores
		CORE_QUOTA=102400
		zfs create -o quota=${CORE_QUOTA}m -o mountpoint=/${PDS_NAME}/$bname/cores \
		    ${PDS_NAME}/cores/$bname

		chmod 700 $ZONEPATH
	fi

	egrep -s "netcfg:" $ZROOT/etc/passwd
	if (( $? != 0 )); then
		echo "netcfg:x:17:65:Network Configuration Admin:/:" \
		    >> $ZROOT/etc/passwd
		echo "netcfg:*LK*:::::::" >> $ZROOT/etc/shadow
	fi
	egrep -s "netadm:" $ZROOT/etc/group
	(( $? != 0 )) && echo "netadm::65:" >> $ZROOT/etc/group

	# /etc/svc/profile needs to be a directory with some contents which we
	# can get from the template.  The early manifest import svc
	# (lib/svc/method/manifest-import) copies some symlinks from the
	# template's var/svc/profile dir and we need to make sure those are
	# pointing at the right files and not left dangling.
	ZPROFILE=$ZROOT/etc/svc/profile
	if [ ! -d $ZPROFILE ]; then
		mkdir $ZPROFILE
		cp -p $ZROOT/var/svc/profile/generic_limited_net.xml $ZPROFILE
		cp -p $ZROOT/var/svc/profile/inetd_generic.xml $ZPROFILE
		cp -p $ZROOT/var/svc/profile/ns_dns.xml $ZPROFILE
		cp -p $ZROOT/var/svc/profile/platform_none.xml $ZPROFILE
	fi

	touch $ZROOT/var/log/courier.log
}

function juninstall_delegated_dataset
{
	# Now destroy any delegated datasets. Redirect to /dev/null in case they
	# were already destroyed when we removed the zonepath dataset.
	DD=`zonecfg -z $ZONENAME info dataset | nawk '{if ($1 == "name:") print $2}'`
	for i in $DD; do
		zfs destroy -rF $i >/dev/null 2>&1
	done
}
