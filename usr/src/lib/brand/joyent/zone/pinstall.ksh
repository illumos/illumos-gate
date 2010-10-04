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
# Copyright 2010 Joyent, Inc.  All rights reserved.
# Use is subject to license terms.
#

unset LD_LIBRARY_PATH
PATH=/usr/bin:/usr/sbin
export PATH

. /usr/lib/brand/shared/common.ksh

ZONENAME=""
ZONEPATH=""
# Default to 10GB diskset quota
ZQUOTA=10

while getopts "R:t:U:q:z:" opt
do
	case "$opt" in
		R)	ZONEPATH="$OPTARG";;
			# template is only used in the postinstall script
		t)	TMPLZONE="$OPTARG";;
		U)	UUID="$OPTARG";;
			# zquota is only used in the postinstall script
		q)	ZQUOTA="$OPTARG";;
		z)	ZONENAME="$OPTARG";;
		*)	printf "$m_usage\n"
			exit $ZONE_SUBPROC_USAGE;;
	esac
done
shift OPTIND-1

if [[ -z $ZONENAME ]]; then
	print -u2 "Brand error: No zone name"
	exit $ZONE_SUBPROC_USAGE
fi

# If no UUID provided, then nothing to do.
[[ -z $UUID ]] && exit $ZONE_SUBPROC_OK

nawk -F: -v zonename=$ZONENAME -v uuid=$UUID '{
	if ($1 != zonename) {
		print $0
		next
	}
	printf("%s:%s:%s:%s\n", $1, $2, $3, uuid);
}' /etc/zones/index >/etc/zones/index.new
cp /etc/zones/index.new /etc/zones/index
rm -f /etc/zones/index.new

exit $ZONE_SUBPROC_OK
