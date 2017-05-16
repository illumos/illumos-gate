#!/bin/bash

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
# Copyright (c) 2016 by Delphix. All rights reserved.
#

#
# This test attempts to stress the interaction between threads adding
# and deleting datalinks, and those reading kstats associated with
# those datalinks.
#

RUNFILE=$(mktemp)
linkname1=laverne0
linkname2=shirley0
duration=20 # seconds

#
# Delete any potential datalinks left behind by the etherstub function.
#
function cleanup
{
	rm -f $RUNFILE
}

function etherstub
{
	while [[ -e $RUNFILE ]]; do
		dladm create-etherstub -t $linkname1
		dladm rename-link $linkname1 $linkname2
		dladm delete-etherstub -t $linkname2
	done
}

function readkstat
{
	local linkname=$1
	while [[ -e $RUNFILE ]]; do
		kstat link:0:$linkname &>/dev/null
	done
}

trap "cleanup; exit" SIGHUP SIGINT SIGTERM

etherstub &
readkstat $linkname1 &
readkstat $linkname1 &
readkstat $linkname2 &
readkstat $linkname2 &

sleep $duration
cleanup

wait

exit 0
