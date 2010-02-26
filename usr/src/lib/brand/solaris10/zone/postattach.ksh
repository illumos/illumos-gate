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
# This postattach hook adds the service tag for the zone.
# We need this in a postattach hook since the zone doesn't have
# a UUID when the attach hook is run.
#

. /usr/lib/brand/solaris10/common.ksh

install_media="-"

# If we weren't passed at least two arguments, exit now.
(( $# < 2 )) && exit $ZONE_SUBPROC_OK

ZONENAME="$1"
ZONEPATH="$2"

shift 2

noexecute=0
unset inst_type

#
# This hook will see the same options as the attach hook, so make sure
# we accept all of these.
#
while getopts "a:d:nr:" opt; do
	case $opt in
		a)
		 	inst_type="archive"
			install_media="$OPTARG"
			;;
		d)
		 	inst_type="directory"
			install_media="$OPTARG"
			;;
		n)	noexecute=1 ;;
		r)
		 	inst_type="stdin"
			install_media="$OPTARG"
			;;
		?)	exit $ZONE_SUBPROC_OK;;
		*)	exit $ZONE_SUBPROC_OK;;
	esac
done
shift $((OPTIND-1))

[ $noexecute -eq 1 ] && exit $ZONE_SUBPROC_OK
[[ -z "$inst_type" ]] && inst_type="directory"

# Add a service tag for this zone.
add_svc_tag "$ZONENAME" "attach $inst_type `basename $install_media`"

exit $ZONE_SUBPROC_OK
