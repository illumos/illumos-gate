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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

. /usr/lib/brand/solaris10/common.ksh

m_usage=$(gettext  "solaris10 brand usage: detach [-n].")

EXIT_CODE=$ZONE_SUBPROC_USAGE

# If we weren't passed at least two arguments, exit now.
(( $# < 2 )) && exit $ZONE_SUBPROC_USAGE

ZONENAME="$1"
ZONEPATH="$2"
# XXX shared/common script currently uses lower case zonename & zonepath
zonename="$ZONENAME"
zonepath="$ZONEPATH"

shift; shift	# remove ZONENAME and ZONEPATH from arguments array

noexecute=0

# Other brand attach options are invalid for this brand.
while getopts "n" opt; do
	case $opt in
		n)	noexecute=1 ;;
		?)	printf "$m_usage\n"
			exit $ZONE_SUBPROC_USAGE;;
		*)	printf "$m_usage\n"
			exit $ZONE_SUBPROC_USAGE;;
	esac
done
shift $((OPTIND-1))

if [[ $noexecute == 1 ]]; then
	cat /etc/zones/$ZONENAME.xml
	exit $ZONE_SUBPROC_OK
fi

cp /etc/zones/$ZONENAME.xml $ZONEPATH/SUNWdetached.xml

exit $ZONE_SUBPROC_OK
