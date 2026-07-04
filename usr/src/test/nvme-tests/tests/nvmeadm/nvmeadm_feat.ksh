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

#
# Copyright 2026 Oxide Computer Company
#

#
# Test various nvmeadm(8) driven set-feature related activity. This is run in
# the OCP destructive test set, meaning we can assume that we have certain OCP
# features present to try to set. The main goal is to test all our parsing.
#
# When we can get a feature and list specific fields from it in a
# machine-parsable way, we should come back and add a basic round-trip test for
# this.
#

export LC_ALL=C.UTF-8
export LD_PRELOAD=libumem.so
export UMEM_DEBUG=default
unalias -a
set -o pipefail

nt_prog=${NVMEADM:-"/usr/sbin/nvmeadm"}
nt_arg0=$(basename $0)
nt_exit=0
nt_fail=0
nt_dev="$NVME_TEST_DEVICE"

function warn
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST FAILED: $msg" >&2
	nt_exit=1
	((nt_fail++))
}

function fatal
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "$nt_arg0: $msg" >&2
        exit 1
}

function check_feat
{
	typeset feat="$1"
	typeset out=$($nt_prog list-features -po impl $nt_dev $feat)

	if [[ "$out" != "yes" ]]; then
		fatal "INTERNAL TEST FAILURE: missing required feature $feat"
	fi
}

function plp_fail
{
	typeset ret

	"$nt_prog" set-feature $@ "$nt_dev" ocp/plphealth 2>/dev/null \
	    1>/dev/null

	ret=$?
	if (( ret == 0 )); then
		warn "should have failed with args $@, but passed"
	elif (( ret != 255 )); then
		warn "$@ exited with $ret, but expected 255"
	else
		printf "TEST PASSED: program failed: set-feature %s %s %s\n" \
		    "$*" "$nt_dev" "ocp/plphealth"
	fi
}

function errinj_fail
{
	typeset ret

	"$nt_prog" set-feature $@ "$nt_dev" ocp/errinj 2>/dev/null \
	    1>/dev/null

	ret=$?
	if (( ret == 0 )); then
		warn "should have failed with args $@, but passed"
	elif (( ret != 255 )); then
		warn "$@ exited with $ret, but expected 255"
	else
		printf "TEST PASSED: program failed: set-feature %s %s %s\n" \
		    "$*" "$nt_dev" "ocp/errinj"
	fi

}

function nvmeadm_pass
{
	if ! "$nt_prog" $@ 2>/dev/null 1>/dev/null; then
		warn "should have passed with args $@, but failed"
		return;
	fi

	printf "TEST PASSED: %s %s exited successfully\n" "$nt_prog" "$*"
}

if [[ -n "$NVMEADM" ]]; then
	nt_prog="$NVMEADM"
fi

#
# Verify the wrappers set our device.
#
if [[ -z "$nt_dev" ]]; then
	fatal "missing disk definition for \$NVME_TEST_DEVICE"
fi

check_feat ocp/plphealth
check_feat ocp/errinj

#
# Verify a variety of parsing errors:
#
# - Invalid number formats
# - Fields that aren't allowed to be used with a given feature
# - Missing option combinations
#
plp_fail
plp_fail -v foo
plp_fail -v -3
plp_fail -v 0x7777world
plp_fail -v 123.456
plp_fail -v 0x12346789abcdef123456789abcdef
plp_fail -v 0xf --cdw12 foo
plp_fail -v 0xf --cdw12 -3
plp_fail -v 0xf --cdw12 0x7777world
plp_fail -v 0xf --cdw12 123.456
plp_fail -v 0xf --cdw12 0x23
plp_fail -v 0xf --cdw13 foo
plp_fail -v 0xf --cdw13 -3
plp_fail -v 0xf --cdw13 0x7777world
plp_fail -v 0xf --cdw13 123.456
plp_fail -v 0xf --cdw13 0x23
plp_fail -v 0xf --cdw15 foo
plp_fail -v 0xf --cdw15 -3
plp_fail -v 0xf --cdw15 0x7777world
plp_fail -v 0xf --cdw15 123.456
plp_fail -v 0xf --cdw15 0x23
plp_fail -v 0xf -I foobar
plp_fail -v 0xf -I 0,1,2
plp_fail -v 0xf -I 0x
plp_fail -v 0xf -I data,nonsense

#
# To test the offset / length errors we use the error injection which will treat
# a zeroed data payload as a means to clear this, meaning we can just use
# /dev/zero and vary the length. The expected length for the feature is 4k.
#
errinj_fail -v 1
errinj_fail -v 0 -i /dev/null
errinj_fail -v 0 -l 4096
errinj_fail -v 0 -i /dev/null -l foobar
errinj_fail -v 0 -i /dev/null -l 0x12.34
errinj_fail -v 0 -i /dev/null -l -23
errinj_fail -v 0 -i /dev/null -l 123abc
errinj_fail -v 0 -l 4096 -i /enoent

#
# Finally use the fact that this error injection is a set features and send the
# clear command via /dev/null.
#
nvmeadm_pass set-feature -v 0 -i /dev/null -l 0x1000 "$nt_dev" ocp/errinj
nvmeadm_pass set-feature --cdw11 0 --input /dev/null --length 0x1000 "$nt_dev" \
    ocp/errinj

if (( nt_exit == 0 )); then
	printf "All tests passed successfully!\n"
else
	printf "%u tests failed!\n" "$nt_fail"
fi

exit $nt_exit
