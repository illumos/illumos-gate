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
# Copyright 2024 Oxide Computer Company
#

unalias -a
set -o pipefail

pcidb_arg0="$(basename $0)"
pcidb_prog="${PCIDB:-/usr/lib/pci/pcidb}"
pcidb_exit=0

function warn
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST FAILED: $pcidb_arg0: $msg" >&2
}

#
# The following is intended to catch bad filters.
#
function pcidb_bad_filter
{
	typeset filt="$1"

	if $pcidb_prog $filt 2>/dev/null; then
		warn "invalid filter $filt erroneously worked"
		pcidb_exit=1
		return
	fi

	printf "TEST PASSED: invalid filter %s\n" "$filt"

}

function pcidb_bad_args
{
	if $pcidb_prog $@ 2>/dev/null 1>/dev/null; then
		warn "should have failed with args "$@", but passed"
		pcidb_exit=1
		return
	fi

	printf "TEST PASSED: invalid arguments %s\n" "$*"
}

function pcidb_no_match
{
	if $pcidb_prog $@ 2>/dev/null 1>/dev/null; then
		warn "should have failed with args "$@", but passed"
		pcidb_exit=1
		return
	fi

	printf "TEST PASSED: no match %s\n" "$*"
}

function pcidb_pass
{
	if ! $pcidb_prog $@ 2>/dev/null 1>/dev/null; then
		warn "should have passed with args "$@", but failed"
		pcidb_exit=1
		return
	fi

	printf "TEST PASSED: pcidb %s\n" "$*"
}

function pcidb_match
{
	typeset output
	typeset match="$1"
	shift

	output=$($pcidb_prog $@)
	if (( $? != 0)); then
		warn "failed to run pcidb with args: $@"
		pcidb_exit=1
		return
	fi

	if [[ "$output" != "$match" ]]; then
		warn "output mismatch with args: $@\n found:    $output\n" \
		    "expected: $match"
		pcidb_exit=1
		return
	fi

	printf "TEST PASSED: successfully matched against %s\n" "$*"
}

if [[ -n $PCIDB ]]; then
	pcidb_prog=$PCIDB
fi

#
# Before we begin execution, set up the environment such that we have a
# standard locale and that umem will help us catch mistakes.
#
export LC_ALL=C.UTF-8
export LD_PRELOAD=libumem.so
export UMEM_DEBUG=default

#
# Validate that filters match either exactly one or at least one line of
# output using parsable mode. When we match more than one entry, we
# don't try to assert the count because we expect that it will actually
# change over time.
#
exp="1de
8086"
pcidb_match "$exp" -v -p -o vid pci8086 pci1de
pcidb_match "Advanced Micro Devices, Inc. [AMD]" -v -p -o vendor pci1022
pcidb_match "1af4:1044:Virtio 1.0 RNG" -p -o vid,did,device pci1af4,1044
pcidb_match "Dell:HBA330 Adapter" -s -p -o subvendor,subsystem \
	pci1000,97.1028,1f45
pcidb_match "c:3:30:XHCI" -i -p -o bcc,scc,pi,interface pciclass,0c0330
pcidb_match "I2O" -S -p -o subclass pciexclass,0e
pcidb_match "Ethernet 1Gb 2-port 368i Adapter" -s -p -o subsystem pci1590,216,s

#
# Validate that multiple filters all match something. We don't look for
# the exact table output due to the breadth of these filters.
#
pcidb_pass "pci8086" "pci8086,10d3.8086,a01f"
pcidb_pass "pci8086,10d3.8086,a01f" "pci8086"
pcidb_pass "pci8086" "pci8086,10d3.8086,a01f" "pci8086"
pcidb_pass "pciclass,0c" "pciclass,0b"
pcidb_pass "pciclass,06" "pciclass,0604"

#
# Verify valid filters that don't match anything cause use to exit zero
#
pcidb_no_match "pci8086" "pci8086,10d3.8086,ffff"
pcidb_no_match "pci8086,10d3.8086,ffff"
pcidb_no_match "pciclass,fffefd"

#
# Run through filter parsing
#
pcidb_bad_filter "foo"
pcidb_bad_filter ";ffvi"
pcidb_bad_filter "12345"
pcidb_bad_filter "pc8086"
pcidb_bad_filter "pciqwer"
pcidb_bad_filter "pci12345"
pcidb_bad_filter "pci8086,"
pcidb_bad_filter "pci8086,locke"
pcidb_bad_filter "pci8086sigh"
pcidb_bad_filter "pci8086,p"
pcidb_bad_filter "pci8086,12345"
pcidb_bad_filter "pci8086,1234zz"
pcidb_bad_filter "pci8086,1234."
pcidb_bad_filter "pci8086,1234,"
pcidb_bad_filter "pci8086,1234,b"
pcidb_bad_filter "pci8086,1234,8"
pcidb_bad_filter "pci8086,1234,wat"
pcidb_bad_filter "pci8086,1234.terra"
pcidb_bad_filter "pci8086,1234.terra,celes"
pcidb_bad_filter "pci8086,1234.fffff"
pcidb_bad_filter "pci8086,1234.abcd,"
pcidb_bad_filter "pci8086,1234.abcd."
pcidb_bad_filter "pci8086,1234.abcdqr"
pcidb_bad_filter "pci8086,1234.abcd,2,p"
pcidb_bad_filter "pci8086,1234.abcd,2000000000"
pcidb_bad_filter "pci8086,1234.abcd,kefka"
pcidb_bad_filter "pci8086,1234.abcd,34ultros"
pcidb_bad_filter "pciexqwer"
pcidb_bad_filter "pciex12345"
pcidb_bad_filter "pciex8086,"
pcidb_bad_filter "pciex8086,locke"
pcidb_bad_filter "pciex8086sigh"
pcidb_bad_filter "pciex8086,p"
pcidb_bad_filter "pciex8086,12345"
pcidb_bad_filter "pciex8086,1234zz"
pcidb_bad_filter "pciex8086,1234."
pcidb_bad_filter "pciex8086,1234,"
pcidb_bad_filter "pciex8086,1234,b"
pcidb_bad_filter "pciex8086,1234,8"
pcidb_bad_filter "pciex8086,1234,wat"
pcidb_bad_filter "pciex8086,1234.terra"
pcidb_bad_filter "pciex8086,1234.terra,celes"
pcidb_bad_filter "pciex8086,1234.fffff"
pcidb_bad_filter "pciex8086,1234.abcd,"
pcidb_bad_filter "pciex8086,1234.abcd."
pcidb_bad_filter "pciex8086,1234.abcdqr"
pcidb_bad_filter "pciex8086,1234.abcd,2,p"
pcidb_bad_filter "pciex8086,1234.abcd,2000000000"
pcidb_bad_filter "pciex8086,1234.abcd,kefka"
pcidb_bad_filter "pciex8086,1234.abcd,34ultros"
pcidb_bad_filter "pciclas"
pcidb_bad_filter "pciclassedgar"
pcidb_bad_filter "pciclass,sabin"
pcidb_bad_filter "pciclass,0"
pcidb_bad_filter "pciclass,013"
pcidb_bad_filter "pciclass,01345"
pcidb_bad_filter "pciclass,0134567"
pcidb_bad_filter "pciclass,01,"
pcidb_bad_filter "pciclass,010,"
pcidb_bad_filter "pciclass,010aa,"
pcidb_bad_filter "pciclass,0102as"
pcidb_bad_filter "pciclass,0102.as"
pcidb_bad_filter "pciclass,0102@as"
pcidb_bad_filter "pciclass,010298aa"
pcidb_bad_filter "pciclass,010298,"
pcidb_bad_filter "pciclass,010298!"
pcidb_bad_filter "pciclass,010298!shadow"
pcidb_bad_filter "pciexclas"
pcidb_bad_filter "pciexclassedgar"
pcidb_bad_filter "pciexclass,sabin"
pcidb_bad_filter "pciexclass,0"
pcidb_bad_filter "pciexclass,013"
pcidb_bad_filter "pciexclass,01345"
pcidb_bad_filter "pciexclass,0134567"
pcidb_bad_filter "pciexclass,01,"
pcidb_bad_filter "pciexclass,010,"
pcidb_bad_filter "pciexclass,010aa,"
pcidb_bad_filter "pciexclass,0102as"
pcidb_bad_filter "pciexclass,0102.as"
pcidb_bad_filter "pciexclass,0102@as"
pcidb_bad_filter "pciexclass,010298aa"
pcidb_bad_filter "pciexclass,010298,"
pcidb_bad_filter "pciexclass,010298!"
pcidb_bad_filter "pciexclass,010298!shadow"

#
# Verify that if we ask for bad columns we error
#
pcidb_bad_args -p
pcidb_bad_args -o
pcidb_bad_args -o -p
pcidb_bad_args -p -o terra
pcidb_bad_args -p -o subclass -v
pcidb_bad_args -v -d -c

#
# Bad table / filter combinations. This covers filters that don't agree
# with one another, tables and filters that are opposite types, and
# filters and tables that aren't specific enough.
#
pcidb_bad_args "pci8086" "pciclass,0b"
pcidb_bad_args "pci8086,10d3" "pciclass,0b"
pcidb_bad_args "pci8086,10d3,p" "pciclass,0b"
pcidb_bad_args "pci8086,a01f,s" "pciclass,0b"
pcidb_bad_args "pci8086,10d3.8086" "pciclass,0b"
pcidb_bad_args "pci8086,10d3.8086.a01f" "pciclass,0b"
pcidb_bad_args "pci8086" "pciclass,0604"
pcidb_bad_args "pci8086,10d3" "pciclass,0604"
pcidb_bad_args "pci8086,10d3,p" "pciclass,0604"
pcidb_bad_args "pci8086,a01f,s" "pciclass,0604"
pcidb_bad_args "pci8086,10d3.8086" "pciclass,0604"
pcidb_bad_args "pci8086,10d3.8086.a01f" "pciclass,0604"
pcidb_bad_args "pci8086" "pciclass,0c0330"
pcidb_bad_args "pci8086,10d3" "pciclass,0c0330"
pcidb_bad_args "pci8086,10d3,p" "pciclass,0c0330"
pcidb_bad_args "pci8086,a01f,s" "pciclass,0c0330"
pcidb_bad_args "pci8086,10d3.8086" "pciclass,0c0330"
pcidb_bad_args "pci8086,10d3.8086.a01f" "pciclass,0c0330"

pcidb_bad_args -c "pci1022"
pcidb_bad_args -S "pci1022,1650"
pcidb_bad_args -i "pci1022,1483.01de,fff9"
pcidb_bad_args -v "pciclass02"

pcidb_bad_args -d pciclass,03
pcidb_bad_args -S pci1000
pcidb_bad_args -v pci8086,1234
pcidb_bad_args -c pciclass,010802


if (( pcidb_exit == 0 )); then
	printf "All tests passed successfully!\n"
fi

exit $pcidb_exit
