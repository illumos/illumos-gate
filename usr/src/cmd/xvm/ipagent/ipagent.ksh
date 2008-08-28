#!/bin/ksh
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

# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.

#
# xVM PV domU IP address reporting agent. Reports IP address back to dom0.
#

interval=$1

xs_ipaddr_path="ipaddr/0"
xs_link_path="device-misc/vif/default-link"
link=""

#
# Look for a valid-seeming address for the given link. Return 0 on success.
#
link_to_addr()
{
	tmp=`netstat -I $1 -in | awk '{print $4}' | grep -v Address`;
	if [ -z "$tmp" ] || [ "$tmp" = "0.0.0.0" ];
	then
		addr="(none)";
		return 1;
	fi

	addr=$tmp;
	return 0;
}

default_link()
{
	#
	# Look in the store for a cached link name.
	#
	link=`/usr/lib/xen/bin/xenstore-read $xs_link_path 2>/dev/null`
	if [ -z "$link" ] || [ "$link" = "(none)" ]
	then
		#
		# If it's not there, try to determine what it is
		# and add it to the store.
		determine_default_link
	fi
}

#
# Determine the default link name and update xenstore with the details.
#
determine_default_link()
{
	link="(none)";
	#
	# Choose the first up, non-loopback interface with a valid-looking
	# IP address.
	#
	dladm show-link -p -o link,state | while IFS=: read LINKNAME STATE;
	do
		if [ "$STATE" = "up" ];
		then
			link_to_addr "$LINKNAME"
			if [ $? -eq 0 ]; then link=$LINKNAME; break; fi
		fi
	
	done

	/usr/lib/xen/bin/xenstore-write $xs_link_path $link
}

while true; do

	#
	# Determine the default link in use by this domU.
	#
	default_link;

	#
	# If the link still has a valid-looking IP address, notify dom0 of its
	# address.
	#
	link_to_addr $link
	if [ $? -ne 0 ]
	then
		#
		# An address could not be determined for the currently cached
		# default link so determine it again in case it has changed.
		# We'll still sleep this iteration to rate-limit dladm calls.
		#
		determine_default_link;
	fi

	/usr/lib/xen/bin/xenstore-write $xs_ipaddr_path $addr

	sleep $interval
done

