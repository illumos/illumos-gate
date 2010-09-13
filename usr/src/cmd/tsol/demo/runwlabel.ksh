#!/bin/sh
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
#
# Usage:
# runwlabel "my-label" my-program
#

[ ! -x /usr/sbin/zoneadm ] && exit 0    # SUNWzoneu not installed

PATH=/usr/sbin:/usr/bin; export PATH

# Get the zone path associated with the "my-label" zone
# Remove the trailing "/root"
zonepath=`getzonepath "$1" | sed -e 's/\/root$//'`
progname="$2"

# Find the zone name that is associated with this zone path
for zone in `zoneadm list -pi | nawk -F: -v zonepath=${zonepath} '{
	if ("$4" == "${zonepath}") {
		print $2
	}
}'`; do
	# Run the specified command in the matching zone
	zlogin ${zone} ${progname}
	done
exit
