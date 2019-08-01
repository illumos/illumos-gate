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
# Copyright 2015 Joyent, Inc.
#

# Does this brand support reprovisioning?
jst_reprovision="yes"

# Is a template image optional?
# jst_tmplopt="yes"

. /usr/lib/brand/jcommon/libhooks.ksh

function jcommon_attach_hook
{
	# lx-brand specific stuff is done here as final step of install

	#
	# Make sure the localhost has a hostname alias in the zone's
	# /etc/hosts file
	#
	zroot=$ZONEPATH/root
	hname=$ZONENAME
	hostnamef=$zroot/etc/hostname
	if [[ ! -h $hostnamef ]]; then
		echo $hname >$hostnamef
	fi

	hostfile=$zroot/etc/hosts
	if [[ -f $hostfile && ! -h $hostfile ]]; then
		# use awk to search and append to loopback in one command
		awk -v hname="$hname" '{
		    if ($1 ~ /^127\./ && index($0, hname) == 0) {
		        printf("%s %s\n", $0, hname);
		    } else {
		        print $0
		    }
		}' $hostfile >/tmp/tmp_${ZONENAME}_$$
		mv /tmp/tmp_${ZONENAME}_$$ $hostfile
		chmod 644 $hostfile
	fi

	rm -rf $ZONEPATH/cores
	CORE_QUOTA=102400
	zfs create -o quota=${CORE_QUOTA}m \
	    -o mountpoint=/${PDS_NAME}/$bname/cores ${PDS_NAME}/cores/$bname

	chmod 700 $ZONEPATH
}

. /usr/lib/brand/jcommon/cinstall
