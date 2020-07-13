#!/usr/bin/ksh
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
# Copyright 2020 Oxide Computer Company
#

#
# Sit in a loop trying to unload the driver specified as an argument.
#

ksensor_id=
ksensor_drv=
ksensor_to=30
ksensor_skew=5

function get_id
{

	while [[ -z "$ksensor_id" ]]; do
		sleep 1
		ksensor_id=$(modinfo | awk "{
			if (\$6 == \"$1\") {
			    print \$1
			} }")
	done
}

function unload
{
	while :; do
		if ! modunload -i $ksensor_id 2>/dev/null; then
			echo "failed to unload $ksensor_drv" >&2
		else
			echo "unloaded $ksensor_drv"
		fi
		sleep $((($RANDOM % $ksensor_to) + $ksensor_skew))
	done
}

if [[ -z "$1" ]]; then
	echo "Missing required driver name" >&2
	exit 1
fi

ksensor_drv=$1
get_id $ksensor_drv
printf "Got module id for %s: %u\n" "$ksensor_drv" $ksensor_id
unload
