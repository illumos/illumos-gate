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
# Copyright (c) 2014, Joyent, Inc.
#

ai_arg0="$(basename $0)"
ai_stub="teststub$$"
ai_vnic="testvnic$$"

function fatal
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST_FAIL: $vt_arg0: $msg" >&2
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
	dladm set-linkprop -p allowed-ips="$@" $ai_vnic 2>/dev/null
}

function epass
{
	runtest $* || fatal "allowed-ips=$* failed, expected success\n"
}

function efail
{
	runtest $* && fatal "allowed-ips=$* succeeded, expected failure\n"
}

#
# Run through all IPv6 prefixes for validity with a token prefix
#
function allv6
{
	typeset i;
	for ((i = 1; i <= 128; i++)); do
		epass "8000::/$i"
	done
}

#
# Run through all of the v6 prefixes except /128 and ensure that they fail for
# a given IPv6 address because the other bits are set.
#
function v6specific
{
	typeset i;
	for ((i = 0; i < 128; i++)); do
		efail 2600:3c00::f03c:91ff:fe96:a267/$i
	done
}

setup

# Basic IPv4 single and multiple IPs
efail 0.0.0.0
epass 127.0.0.1
epass 127.0.0.1,127.0.0.2
efail 127.0.0.1,127.0.0.1
epass 10.167.169.23
epass 11.167.169.23
epass 12.167.169.23
epass 10.167.169.23,11.167.169.23,12.167.169.23
efail 256.1.1.1
efail 1.256.1.1
efail 1.1.256.1
efail 1.1.1.256
efail 300.300.300.300
efail 300.300.300.300,1.1.1.1
efail 1.1.1.1,300.300.300.300
efail 3.-3.3.-3

# Basic IPv4 prefixes
efail 0.0.0.0/0
epass 127.0.0.0/8
efail 127.0.0.1/8
epass 128.0.0.0/1
epass 128.0.0.0/2
epass 128.0.0.0/3
epass 128.0.0.0/4
epass 128.0.0.0/5
epass 128.0.0.0/6
epass 128.0.0.0/7
epass 128.0.0.0/8
epass 128.0.0.0/9
epass 128.0.0.0/10
epass 128.0.0.0/11
epass 128.0.0.0/12
epass 128.0.0.0/13
epass 128.0.0.0/14
epass 128.0.0.0/15
epass 128.0.0.0/16
epass 128.0.0.0/17
epass 128.0.0.0/18
epass 128.0.0.0/19
epass 128.0.0.0/20
epass 128.0.0.0/21
epass 128.0.0.0/22
epass 128.0.0.0/23
epass 128.0.0.0/24
epass 128.0.0.0/25
epass 128.0.0.0/26
epass 128.0.0.0/27
epass 128.0.0.0/28
epass 128.0.0.0/29
epass 128.0.0.0/30
epass 128.0.0.0/21
epass 128.0.0.0/32

efail 128.0.0.1/2
efail 128.0.0.1/4
efail 128.0.0.1/8
efail 128.0.0.1/10
efail 128.0.0.1/12
efail 128.0.0.1/14
efail 128.0.0.1/16
efail 128.0.0.1/18
efail 128.0.0.1/20
efail 128.0.0.1/22
efail 128.0.0.1/24
efail 128.0.0.1/28
efail 128.0.0.1/30
epass 128.0.0.1/32

epass 10.0.0.0/30
epass 10.0.0.4/30
epass 10.0.0.8/30
epass 10.0.0.12/30
epass 10.0.0.16/30
epass 10.0.0.20/30

efail 10.0.0.1/30
efail 10.0.0.5/30
efail 10.0.0.9/30
efail 10.0.0.13/30
efail 10.0.0.17/30
efail 10.0.0.21/30

epass 10.99.99.0/24,10.88.88.0/24,10.77.7.0/24
epass 10.99.99.7/32,10.168.0.0/16

efail 10.99.99.7/33
efail 10.99.99.7/-1
efail 10.99.99.7/
efail 10.99.99.7/0

# Basic IPv6 Addresss
efail ::
efail 1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1:1
efail dead:beef::gg
epass ::1
epass ::127.0.0.1
epass ::10.0.0.0
efail ::0.0.0.0
efail ::ffff:0.0.0.0
epass ::ffff:10.123.167.169
epass 2600:3c00::f03c:91ff:fe96:a264

# IPv6 Prefixes

efail ::/128
efail 2600:3c00::f03c:91ff:fe96:a264/129
efail 2600:3c00::f03c:91ff:fe96:a264/-1
efail 2600:3c00::f03c:91ff:fe96:a264/-
efail 2600:3c00::f03c:91ff:fe96:a264/
efail ::1/1
efail ::1/20

allv6
v6specific

epass 2600:3c00::f03c:91ff:fe96:a264/128
epass 2600:3c00::/64

efail fe80::8:20ff:fead:3361/10
efail fe80::1/10
epass fe80::/15
epass fe82::/15

cleanup
printf "TEST PASS: $ai_arg0"
