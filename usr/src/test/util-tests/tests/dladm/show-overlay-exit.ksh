#!/bin/ksh
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
# Copyright (c) 2017, Joyent, Inc.
#

soe_arg0="$(basename $0)"

soe_overlay="soe_overlay$$"
soe_dummy_ip="169.254.0.0"

soe_port="2000"
soe_vnetid=20
soe_encap="vxlan"
soe_search="direct"

soe_etherstub="soe_teststub$$"

function fatal
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST_FAIL: $vt_arg0: $msg" >&2
	dladm delete-overlay $soe_overlay
	dladm delete-etherstub $soe_etherstub
	exit 1
}

function setup
{
	dladm create-overlay -v $soe_vnetid -e $soe_encap -s $soe_search \
	    -p vxlan/listen_ip=$soe_dummy_ip -p direct/dest_ip=$soe_dummy_ip \
	    -p direct/dest_port=$soe_port $soe_overlay || \
	    fatal "failed to create overlay"

	dladm create-etherstub $soe_etherstub || \
	    fatal "failed to create etherstub"
}

function cleanup
{
	dladm delete-overlay $soe_overlay || \
	    fatal "failed to remove overlay"
	dladm delete-etherstub $soe_etherstub || \
	    fatal "failed to remove etherstub"
}

function runtest
{
	dladm show-overlay $* > /dev/null 2>&1
}

function epass
{
	runtest $* || fatal "show-overlay=$* failed, expected success\n"
}

function efail
{
	runtest $* && fatal "show-overlay=$* succeeded, expected failure\n"
}

setup

epass $soe_overlay
efail $soe_etherstub
efail $soe_etherstub $soe_overlay
efail $soe_overlay $soe_etherstub

cleanup

printf "TEST PASS: $soe_arg0"
