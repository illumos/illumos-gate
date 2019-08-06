#!/usr/bin/ksh
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
# Copyright 2019 Joyent, Inc.
#

#
# Run the IP forwarding test suite.
#
# Usage
#
#    ip_fwd_suite [-n <name>] [-a <args>]
#
#    To run all tests:
#
#	NET_TESTS=/opt/net-tests ip_fwd_suite
#
#    To run one test:
#
#	NET_TESTS=/opt/net-tests ip_fwd_suite -n 001
#
#    To run one test with additional arguments passed to 'ip_forwarding':
#
#	NET_TESTS=/opt/net-tests ip_fwd_suite -n 001 -a n
#

if [[ -z $NET_TESTS ]]; then
	echo "NET_TESTS not set" >&2
	exit 1
fi

. $NET_TESTS/tests/net_common
. $NET_TESTS/config/ip_forwarding.config

if [[ -z "$NT_CLIENT" ]]; then
	fail "NT_CLIENT must be set"
fi

if [[ -z "$NT_ROUTER" ]]; then
	fail "NT_ROUTER must be set"
fi

if [[ -z "$NT_SERVER" ]]; then
	fail "NT_SERVER must be set"
fi

while getopts "a:n:" opt; do
	case $opt in
	a)
		nt_args=$OPTARG
		;;
	n)
		nt_name=$OPTARG
		;;
	esac
done

shift $((OPTIND - 1))

nt_script=$NET_TESTS/tests/forwarding/ip_forwarding

#
# See the "Test Matrix" section of the README for a description of
# each test.
#
typeset -A nt_name_args
nt_name_args["001"]="uv"
nt_name_args["002"]="puv"
nt_name_args["003"]="lpuv"
nt_name_args["004"]="fuv"
nt_name_args["005"]="fluv"
nt_name_args["006"]="ruv"
nt_name_args["007"]="pruv"
nt_name_args["008"]="lpruv"
nt_name_args["009"]="fruv"
nt_name_args["010"]="flruv"

nt_name_args["011"]="buv"
nt_name_args["012"]="bpuv"
nt_name_args["013"]="blpuv"
nt_name_args["014"]="bfuv"
nt_name_args["015"]="bfluv"
nt_name_args["016"]="bruv"
nt_name_args["017"]="bpruv"
nt_name_args["018"]="blpruv"
nt_name_args["019"]="bfruv"
nt_name_args["020"]="bflruv"

if [[ -n $nt_name ]]; then
	if [[ -z ${nt_name_args[$nt_name]} ]]; then
		fail "invalid test name: $nt_name"
	fi

	export NT_TNAME="ip_fwd_$nt_name"
	nt_args="-${nt_name_args[$nt_name]}${nt_args}"
	$nt_script $nt_args $NT_CLIENT $NT_ROUTER $NT_SERVER
	exit $?
fi

for nt_name in ${!nt_name_args[@]}; do
	export NT_TNAME="ip_fwd_$nt_name"
	nt_args="-${nt_name_args[$nt_name]}${nt_args}"
	$nt_script $nt_args $NT_CLIENT $NT_ROUTER $NT_SERVER || exit $?
done

exit 0
