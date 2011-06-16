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
# Copyright 2011 Joyent, Inc.  All rights reserved.
# Use is subject to license terms.
#

final_setup()
{
	# Convert quota to MB and use 10% of that value for the zone core dump
	# dataset.  The infrastructure zones can use 50%.
	if [ ! -d $ZONEPATH/cores ]; then
		case $ZONENAME in
			adminui|assets|atropos|ca|capi|dhcpd|mapi|portal| \
			pubapi|rabbitmq)
				CORE_QUOTA=$((($ZQUOTA * 1000) / 2));;
			*)
				CORE_QUOTA=$((($ZQUOTA * 1000) / 10));;
		esac
		zfs create -o quota=${CORE_QUOTA}m -o compression=gzip \
		   $PDS_NAME/$bname/cores
	fi

	chmod 700 $ZONEPATH

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
