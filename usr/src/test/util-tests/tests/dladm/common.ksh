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
# Copyright 2017 Joyent, Inc.
#

ai_arg0="$(basename $0)"
ai_stub="teststub$$"
ai_vnic="testvnic$$"

typeset property

function fatal
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST_FAIL: $ai_arg0: $msg" >&2
	exit 1
}

function setup
{
	dladm create-etherstub $ai_stub || fatal "failed to create etherstub"
	dladm create-vnic -l $ai_stub $ai_vnic || fatal "failed to create vnic"
}

function cleanup
{
	dladm delete-vnic $ai_vnic || fatal "failed to remove vnic"
	dladm delete-etherstub $ai_stub || fatal "failed to remove etherstub"
}

function runtest
{
	[[ -z "$property" ]] && fatal "missing property to set"
	dladm set-linkprop -p $property="$@" $ai_vnic 2>/dev/null
}

function epass
{
	runtest $* || fatal "$property=$* failed, expected success\n"
}

function efail
{
	runtest $* && fatal "$property=$* succeeded, expected failure\n"
}
