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

# This tests behavior around link local scopes, ensuring that traffic to
# link-local addresses is properly separated by scope id.

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
	IFID="$2"

	ipadm create-if -t $VNIC

	ipadm create-addr -T addrconf -i $IFID $VNIC/llt
}

create_simnet llt_simnet0 llt_vnic0 llt_vnic1
create_simnet llt_simnet1 llt_vnic2 llt_vnic3

# RFC2544 assigns 198.18.0.0/15 for "benchmarking"; use in a unit test
# would be consistent with that assignment.

init_if llt_vnic0 ::2112:1/64
init_if llt_vnic1 ::2112:2/64
init_if llt_vnic2 ::2112:1/64
init_if llt_vnic3 ::2112:2/64

# wait for DAD to complete
sleep 1
ipadm show-addr

a0=fe80::2112:1%llt_vnic0
a1=fe80::2112:1%llt_vnic1
a2=fe80::2112:1%llt_vnic2
a3=fe80::2112:1%llt_vnic3

b0=fe80::2112:2%llt_vnic0
b1=fe80::2112:2%llt_vnic1
b2=fe80::2112:2%llt_vnic2
b3=fe80::2112:2%llt_vnic3

# try with ifindex passed via IPV6_BOUND_IF instead of via sin6_scope_id
c0=llt_vnic0,fe80::2112:1
c1=llt_vnic1,fe80::2112:1
c2=llt_vnic2,fe80::2112:1
c3=llt_vnic3,fe80::2112:1


ping -i llt_vnic0 -s ${b0} 56 1 ||
	test_fail "FAIL: fe80::2112:2 unreachable through llt_vnic0"
ping -i llt_vnic1 -s ${a1} 56 1 ||
	test_fail "FAIL: fe80::2112:1 unreachable through llt_vnic1"
ping -i llt_vnic2 -s ${b2} 56 1 ||
	test_fail "FAIL: fe80::2112:2 unreachable through llt_vnic2"
ping -i llt_vnic3 -s ${a3} 56 1 ||
	test_fail "FAIL: fe80::2112:1 unreachable through llt_vnic3"

for proto in udp tcp; do
	c="--port 12345  --proto ${proto} --family 6"

	${scriptdir}/dup_bind ${c} --addr ${a0} --addr ${a2} ${a1} ||
		test_fail "FAIL: ${proto} connect 1 failed"
	${scriptdir}/dup_bind ${c} --addr ${a0} --addr ${a2} ${a3} ||
		test_fail "FAIL: ${proto} connect 2 failed"
	${scriptdir}/dup_bind ${c} --addr ${b1} --addr ${b3} ${b0} ||
		test_fail "FAIL: ${proto} connect 3 failed"
	${scriptdir}/dup_bind ${c} --addr ${b1} --addr ${b3} ${b2} ||
		test_fail "FAIL: ${proto} connect 4 failed"

	${scriptdir}/dup_bind ${c} --addr ${c0} --addr ${c2} ${a1} ||
		test_fail "FAIL: ${proto} connect 5 failed"
	${scriptdir}/dup_bind ${c} --addr ${c0} --addr ${c2} ${a3} ||
		test_fail "FAIL: ${proto} connect 6 failed"

	${scriptdir}/dup_bind ${c} --addr ${a2} ${a1} &&
		test_fail "FAIL: ${proto} neg 1 failed"
	${scriptdir}/dup_bind ${c} --addr ${a0} ${a3} &&
		test_fail "FAIL: ${proto} neg 2 failed"

done

if (( failures > 0 )); then
	echo "${failures} failures detected."
	exit 1
fi

echo "all tests passed"
exit 0
