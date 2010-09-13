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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# This preuninstall hook removes the service tag for the zone.
# We need this in a preuninstall hook since once the zone state is
# changed to 'incomplete' (which happens before we run the uninstall hook)
# then the zone gets a new UUID and we can no longer figure out which
# service tag instance to delete.
#

#
# common shell script functions
#
. /usr/lib/brand/solaris10/common.ksh

# If we weren't passed at least two arguments, exit now.
(( $# < 2 )) && exit $ZONE_SUBPROC_USAGE

ZONENAME=$1
ZONEPATH=$2

shift 2

#
# This hook will see the same options as the uninstall hook, so make sure
# we accept these even though all but -n are ignored.
#
options="FhHnv"
nop=""

# process options
OPTIND=1
while getopts :$options OPT ; do
case $OPT in
	F ) ;;
	h|H ) exit $ZONE_SUBPROC_OK ;;
	n ) nop="echo" ;;
	v ) ;;
esac
done
shift `expr $OPTIND - 1`

[ $# -gt 0 ] && exit $ZONE_SUBPROC_OK

# Remove the service tag for this zone.
$nop del_svc_tag "$ZONENAME"

exit $ZONE_SUBPROC_OK
