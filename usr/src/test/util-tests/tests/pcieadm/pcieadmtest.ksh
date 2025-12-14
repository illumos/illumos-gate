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
# Copyright 2026 Oxide Computer Company
#

unalias -a
set -o pipefail

pcieadm_arg0="$(basename $0)"
pcieadm_prog="/usr/lib/pci/pcieadm"
pcieadm_data="$(dirname $0)/pci"
pcieadm_exit=0
pcieadm_tmpfile="/tmp/pcieadmtest.$$"

warn()
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST FAILED: $pcieadm_arg0: $msg" >&2
	pcieadm_exit=1
}

pcieadm_bad_args()
{
	if $pcieadm_prog $@ 2>/dev/null 1>/dev/null; then
		warn "should have failed with args "$@", but passed"
		return
	fi

	printf "TEST PASSED: invalid arguments %s\n" "$*"
}

pcieadm_validate_output()
{
	typeset input="$pcieadm_data/$1"
	shift
	typeset outfile="$pcieadm_data/$1"
	shift
	typeset expexit=$1
	shift

	$pcieadm_prog $@ <$input >"$pcieadm_tmpfile" 2>&1
	if (( $? != expexit)); then
		warn "$@: mismatched exit status, found $?, expected $expexit"
	fi

	if ! diff $outfile $pcieadm_tmpfile; then
		warn "$@: output mismatched"
	else
		printf "TEST PASSED: %s\n" "$*"
	fi
}


if [[ -n $PCIEADM ]]; then
	pcieadm_prog=$PCIEADM
fi

#
# Before we begin execution, set up the environment such that we have a
# standard locale and that umem will help us catch mistakes.
#
export LC_ALL=C.UTF-8
export LD_PRELOAD=libumem.so
export UMEM_DEBUG=default

if [[ ! -d $pcieadm_data ]]; then
	printf "failed to find data directory %s\n" "$pcieadm_data" >&2
	exit 1
fi

#
# First work through bad options. The majority of the bar read and write bad
# options are in the privileged test.
#
pcieadm_bad_args
pcieadm_bad_args -d
pcieadm_bad_args foobar
pcieadm_bad_args save-cfgspace
pcieadm_bad_args save-cfgspace -a
pcieadm_bad_args save-cfgspace -d
pcieadm_bad_args save-cfgspace -d final
pcieadm_bad_args save-cfgspace -a -d fantasy
pcieadm_bad_args show-devs -h
pcieadm_bad_args show-devs -p
pcieadm_bad_args show-devs -s -o
pcieadm_bad_args show-cfgspace
pcieadm_bad_args show-cfgspace -d -H
pcieadm_bad_args show-cfgspace -d
pcieadm_bad_args show-cfgspace -f
pcieadm_bad_args show-cfgspace -h
pcieadm_bad_args show-cfgspace -L
pcieadm_bad_args show-cfgspace -L -n -f "$pcieadm_data/igb.pci"
pcieadm_bad_args show-cfgspace -L -p -f "$pcieadm_data/igb.pci"
pcieadm_bad_args show-cfgspace -p -f "$pcieadm_data/igb.pci"
pcieadm_bad_args show-cfgspace -o foo -f "$pcieadm_data/igb.pci"
pcieadm_bad_args show-cfgspace -L -o foo -f "$pcieadm_data/igb.pci"
pcieadm_bad_args bar
pcieadm_bad_args bar -h
pcieadm_bad_args bar asdf
pcieadm_bad_args bar list
pcieadm_bad_args bar list -p -d foobar
pcieadm_bad_args bar list -p -d foobar
pcieadm_bad_args bar list -p -d foobar -o nope
pcieadm_bad_args bar list -p -d foobar -o io,nope

#
# Test different output cases
#
pcieadm_validate_output igb.pci header0-basic.out 0 \
    show-cfgspace -f /dev/stdin header0.vendor header0.device
pcieadm_validate_output igb.pci header0-basic-L.out 0 \
    show-cfgspace -L -f /dev/stdin header0.vendor header0.device
pcieadm_validate_output igb.pci header0-basic-n.out 0 \
    show-cfgspace -n -f /dev/stdin header0.vendor header0.device
pcieadm_validate_output igb.pci header0-basic-LH.out 0 \
    show-cfgspace -L -H -f /dev/stdin header0.vendor header0.device

#
# Specific filter behavior. We want to validate the following:
#
#  o An inexact filter (e.g. a cap or subcap) matches in human mode,
#    but not parsable.
#  o An exact filter will show its contents in human mode, but not
#    parsable.
#  o A missing filter causes to exit non-zero, but still show what we
#    found with other filters or because of a prefix match.
#
pcieadm_validate_output igb.pci igb-ltr.out 0 \
    show-cfgspace -f /dev/stdin ltr
pcieadm_validate_output igb.pci igb-ltr-p.out 1 \
    show-cfgspace -p -o short,value -f /dev/stdin ltr
pcieadm_validate_output igb.pci header0-parse.out 0 \
    show-cfgspace -p -o short,value -f /dev/stdin header0.vendor header0.device
pcieadm_validate_output bridge.pci bridge-ht.out 0 \
    show-cfgspace -f /dev/stdin ht
pcieadm_validate_output bridge.pci bridge-ht.out 0 \
    show-cfgspace -f /dev/stdin ht.msi
pcieadm_validate_output bridge.pci bridge-ht.out 0 \
    show-cfgspace -f /dev/stdin ht.msi.command
pcieadm_validate_output bridge.pci bridge-ht-p.out 1 \
    show-cfgspace -p -o value,short -f /dev/stdin ht
pcieadm_validate_output bridge.pci bridge-ht.msi-p.out 1 \
    show-cfgspace -p -o value,short -f /dev/stdin ht.msi
pcieadm_validate_output bridge.pci bridge-ht.msi.command-p.out 0 \
    show-cfgspace -p -o value,short -f /dev/stdin ht.msi.command
pcieadm_validate_output bridge.pci bridge-efilt.out 1 \
    show-cfgspace -f /dev/stdin pcie.linksts atelier
pcieadm_validate_output bridge.pci bridge-efilt-p.out 1 \
    show-cfgspace -p -o short,value -f /dev/stdin pcie.linksts atelier

if (( pcieadm_exit == 0 )); then
	printf "All tests passed successfully!\n"
fi

rm -f "$pcieadm_tmpfile"
exit $pcieadm_exit
