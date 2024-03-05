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
# Copyright 2024 Bill Sommerfeld
#

# This tests behavior around IP_BOUND_IF for ipv4 sockets as a check that
# other v6-focused work hasn't cause a regression.

# It does this with multiple vnics on multiple simnets created for this
# test.   No special system configuration is required.

typeset -a simnets=()
typeset -a vnics=()

typeset -i failures=0

scriptdir=$(dirname -- "$0")

function fatal {
	print "$*" >&2
	exit 1
}

function test_fail {
	print "$*" >&2
	(( failures++ ))
}

function cleanup {
	{
		for vnic in ${vnics[@]}; do
			ipadm delete-if ${vnic}
			dladm delete-vnic "$vnic"
		done

		for simnet in ${simnets[@]}; do
			dladm delete-simnet "$simnet"
		done
	} > /dev/null 2>&1
}

trap cleanup EXIT

function create_simnet {

	SIMNET="$1"
	simnets+=($SIMNET)
	dladm create-simnet -t "$SIMNET"
	shift
	while (( $# > 0 )); do
		IF="$1"
		vnics+=($IF)
		dladm create-vnic -t -l "$SIMNET" "$IF"
		shift
        done
	echo $simnets
	echo $vnics
}

function init_if {
	VNIC="$1"
	V4ADDR="$2"

	ipadm create-if -t $VNIC

	ipadm create-addr -T static -a local=$V4ADDR $VNIC/llt4
}

create_simnet llt_simnet0 llt_vnic0 llt_vnic1
create_simnet llt_simnet1 llt_vnic2 llt_vnic3

# RFC2544 assigns 198.18.0.0/15 for "benchmarking"; use in a unit test
# would be consistent with that assignment.

init_if llt_vnic0 198.18.1.1/25
init_if llt_vnic1 198.18.1.2/25
init_if llt_vnic2 198.18.2.1/25
init_if llt_vnic3 198.18.2.2/25

ipadm show-addr

c0=198.18.1.1
c1=198.18.1.2
c2=198.18.2.1
c3=198.18.2.2

# regression testing for IP_BOUND_IF

for proto in udp tcp; do
	c="--port 12345  --proto ${proto} --family 4 "

	${scriptdir}/dup_bind ${c} --addr ${c1} --addr ${c3} ${c1} ||
		test_fail "FAIL: v4 tcp connect 1 failed"
	${scriptdir}/dup_bind ${c} --addr ${c1} --addr ${c3} ${c3} ||
		test_fail "FAIL: v4 tcp connect 2 failed"
	${scriptdir}/dup_bind ${c} --addr ${c0} --addr ${c2} ${c0} ||
		test_fail "FAIL: v4 tcp connect 3 failed"
	${scriptdir}/dup_bind ${c} --addr ${c0} --addr ${c2} ${c2} ||
		test_fail "FAIL: v4 tcp connect 4 failed"

	a="--addr llt_vnic1,${c1} --addr llt_vnic3,${c3}"
	b="--addr llt_vnic0,${c0} --addr llt_vnic2,${c2}"
	${scriptdir}/dup_bind ${c} ${a} ${c1} ||
		test_fail "FAIL: v4 IP_BOUND_IF tcp connect 1 failed"
	${scriptdir}/dup_bind ${c} ${a} ${c3} ||
		test_fail "FAIL: v4 IP_BOUND_IF tcp connect 2 failed"
	${scriptdir}/dup_bind ${c} ${b} ${c0} ||
		test_fail "FAIL: v4 IP_BOUND_IF tcp connect 3 failed"
	${scriptdir}/dup_bind ${c} ${b} ${c2} ||
		test_fail "FAIL: v4 IP_BOUND_IF tcp connect 4 failed"

	${scriptdir}/dup_bind ${c} ${a} llt_vnic0,${c1} ||
		test_fail "FAIL: v4 2xIP_BOUND_IF tcp connect 1 failed"
	${scriptdir}/dup_bind ${c} ${a} llt_vnic2,${c3} ||
		test_fail "FAIL: v4 2xIP_BOUND_IF tcp connect 2 failed"
	${scriptdir}/dup_bind ${c} ${b} llt_vnic1,${c0} ||
		test_fail "FAIL: v4 2xIP_BOUND_IF tcp connect 3 failed"
	${scriptdir}/dup_bind ${c} ${b} llt_vnic3,${c2} ||
		test_fail "FAIL: v4 2xIP_BOUND_IF tcp connect 4 failed"

done

if (( failures > 0 )); then
	echo "${failures} failures detected."
	exit 1
fi


echo "all tests passed"
exit 0
