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
# Copyright 2025 Oxide Computer Company
#

#
# This implements basic tests for nvmeadm(8). It expects to be passed a device
# to operate on the same as the other non-destructive tests. It is important
# that we only test non-destructive operations here. Even error paths for
# destructive operations should be done elsewhere.
#

#
# Set up the environment with a standard locale and debugging tools to help us
# catch failures.
#
export LC_ALL=C.UTF-8
export LD_PRELOAD=libumem.so
export UMEM_DEBUG=default
unalias -a
set -o pipefail

nt_prog=/usr/sbin/nvmeadm
nt_arg0=$(basename $0)
nt_exit=0
nt_fail=0
nt_dev="$NVME_TEST_DEVICE"
nt_maj=
nt_min=
nt_ns=

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

#
# Whether certain tests pass or fail depends on the version of the controller.
# Capture that information now.
#
function capture_version
{
	typeset vers
	typeset nsmgmt

	vers=$($nt_prog list -p -o version $nt_dev)
	if (( $? != 0 )); then
		fatal "failed to capture NVMe version from $nt_dev"
	fi

	IFS=. read -r nt_maj nt_min <<< "$vers"

	if [[ -z "$nt_maj" ]]; then
		fatal "failed to parse NVMe major version from $vers"
	fi

	if [[ -z "$nt_min" ]]; then
		fatal "failed to parse NVMe minor version from $vers"
	fi

	printf "Testing device %s: NVMe Version %u.%u\n" "$nt_dev" "$nt_maj" \
	    "$nt_min"

	nsmgmt=$(nvmeadm identify $nt_dev | awk \
	    '/Namespace Management:/{ print $3 }')

	if (( $? != 0 )); then
		fatal "failed to determine Namespace Management support from" \
	    "$nt_dev"
	fi

	if [[ -n "$nsmgmt" && "$nsmgmt" == "supported" ]]; then
		nt_ns="yes"
		printf "%s has namespace management\n" "$nt_dev"
	else
		printf "%s does not support namespace management\n" "$nt_dev"
	fi
}

#
# Run some program whose output we don't care about. Only whether it exits
# successfully or not.
#
function nvmeadm_fail
{
	if "$nt_prog" $@ 2>/dev/null 1>/dev/null; then
		warn "should have failed with args $@, but passed"
		return;
	fi

	printf "TEST PASSED: program failed: %s\n" "$*"
}

#
# Like the above, except we expect it to pass.
#
function nvmeadm_pass
{
	if ! "$nt_prog" $@ 2>/dev/null 1>/dev/null; then
		warn "should have passed with args $@, but failed"
		return;
	fi

	printf "TEST PASSED: %s %s exited successfully\n" "$nt_prog" "$*"
}

#
# This is a test that we expect to pass based upon the version of the controller.
#
function nvmeadm_pv
{
	typeset vers="$1"
	typeset maj min
	shift

	IFS=. read -r maj min <<< "$vers"
	if [[ -z "$maj" ]]; then
		fatal "failed to parse NVMe major version from test $vers"
	fi

	if [[ -z "$min" ]]; then
		fatal "failed to parse NVMe minor version from test $vers"
	fi

	if (( nt_maj > maj || (nt_maj == maj && nt_min >= min) )); then
		nvmeadm_pass $@
	else
		nvmeadm_fail $@
	fi
}

#
# Wrappers around nvmeadm_pv for the various versions we care about.
#
function nvmeadm_pv1v1
{
	nvmeadm_pv "1.1" $@
}

function nvmeadm_pv1v2
{
	nvmeadm_pv "1.2" $@
}

function nvmeadm_pv1v3
{
	nvmeadm_pv "1.3" $@
}

function nvmeadm_ns
{
	if [[ "$nt_ns" == "yes" ]]; then
		nvmeadm_pv "1.2" $@
	else
		nvmeadm_fail $@
	fi
}

if [[ -n "$NVMEADM" ]]; then
	nt_prog="$NVMEADM"
fi

#
# Note, we assume that the wrappers have already validated that this disk exists
# for us. This tells us that we can expect a basic and specific list to work.
#
if [[ -z "$nt_dev" ]]; then
	fatal "missing disk definition for \$NVME_TEST_DEVICE"
fi

capture_version

#
# Explicitly give bad arguments where our bad arguments aren't related to the
# device.
#
nvmeadm_fail
nvmeadm_fail foobar
nvmeadm_fail list nvme
nvmeadm_fail list nvmecloud
nvmeadm_fail list nvmeterra
nvmeadm_fail list nvme00
nvmeadm_fail list nvme01
nvmeadm_fail list nvme0x0
nvmeadm_fail list nvme000
nvmeadm_fail list nvme001
nvmeadm_fail list nvme/1
nvmeadm_fail list $nt_dev foobar
nvmeadm_fail list $nt_dev,foobar
nvmeadm_fail list $nt_dev/
nvmeadm_fail list $nt_dev//1
nvmeadm_fail list $nt_dev/terra
nvmeadm_fail list $nt_dev/0
nvmeadm_fail list $nt_dev/001
nvmeadm_fail list $nt_dev/0x1
nvmeadm_fail list $nt_dev/0o1
nvmeadm_fail list $nt_dev/000
nvmeadm_fail list $nt_dev/1asdf
nvmeadm_fail list -p
nvmeadm_fail list -o
nvmeadm_fail list -o foobar
nvmeadm_fail list -p -o foobar
nvmeadm_fail list -p -o model,foobar
nvmeadm_fail list -p -o model,foobar $nt_dev $nt_dev
nvmeadm_fail list -p -o model,serial $nt_dev/1 $nt_dev
nvmeadm_fail list -c $nt_dev foobar
nvmeadm_fail list -c $nt_dev,foobar
nvmeadm_fail list -c $nt_dev/
nvmeadm_fail list -c $nt_dev/terra
nvmeadm_fail list -c -p
nvmeadm_fail list -c -o
nvmeadm_fail list -c -o foobar
nvmeadm_fail list -c -p -o foobar
nvmeadm_fail list -c -p -o model,foobar
nvmeadm_fail list -c -p -o model,foobar $nt_dev $nt_dev
nvmeadm_fail list -c -p -o model,serial $nt_dev/1 $nt_dev
nvmeadm_fail identify
nvmeadm_fail identify -t
nvmeadm_fail identify -C
nvmeadm_fail identify -c
nvmeadm_fail identify -n
nvmeadm_fail identify -n -a
nvmeadm_fail identify -a
nvmeadm_fail identify -d
nvmeadm_fail identify -d $nt_dev
nvmeadm_fail identify -d $nt_dev/edgar
nvmeadm_fail identify -d $nt_dev/1,$nt_dev/sabin
nvmeadm_fail identify -C -a $nt_dev
nvmeadm_fail identify -C -n $nt_dev
nvmeadm_fail identify -c -a $nt_dev
nvmeadm_fail identify -c -n $nt_dev
nvmeadm_fail identify $nt_dev $nt_dev
nvmeadm_fail identify-controller $nt_dev/1
nvmeadm_fail identify-controller $nt_dev $nt_dev
nvmeadm_fail identify-controller -x
nvmeadm_fail identify-controller -C
nvmeadm_fail identify-controller -c
nvmeadm_fail identify-controller -n
nvmeadm_fail identify-controller -n -a
nvmeadm_fail identify-controller -a
nvmeadm_fail identify-controller -C -a $nt_dev
nvmeadm_fail identify-controller -C -n $nt_dev
nvmeadm_fail identify-controller -c -n $nt_dev
nvmeadm_fail identify-controller -c -a $nt_dev
nvmeadm_fail identify-controller -C $nt_dev/1
nvmeadm_fail identify-controller -c $nt_dev/1
nvmeadm_fail identify-controller -n $nt_dev/1
nvmeadm_fail identify-controller -n -a $nt_dev/1
nvmeadm_fail identify-namespace
nvmeadm_fail identify-namespace $nt_dev
nvmeadm_fail identify-namespace $nt_dev/1 $nt_dev/1
nvmeadm_fail identify-namespace -C
nvmeadm_fail identify-namespace -d
nvmeadm_fail identify-namespace -c
nvmeadm_fail identify-namespace -C $nt_dev
nvmeadm_fail identify-namespace -d $nt_dev
nvmeadm_fail identify-namespace -c $nt_dev

#
# Log page tests are constrained to NVMe 1.0 features to keep things simpler.
# See discussion in the pass section.
#
nvmeadm_fail list-logpages
nvmeadm_fail list-logpages -a
nvmeadm_fail list-logpages -H
nvmeadm_fail list-logpages -p
nvmeadm_fail list-logpages -p $nt_dev
nvmeadm_fail list-logpages -p -o locke $nt_dev
nvmeadm_fail list-logpages -o shadow $nt_dev
nvmeadm_fail list-logpages -o device,shadow $nt_dev
nvmeadm_fail list-logpages -s kefka $nt_dev
nvmeadm_fail list-logpages -s nvm,kefka $nt_dev
nvmeadm_fail list-logpages $nt_dev kefka
nvmeadm_fail list-logpages $nt_dev health umaro
nvmeadm_fail list-logpages $nt_dev/1 error
nvmeadm_fail list-logpages $nt_dev/mog
nvmeadm_fail list-logpages -s ns $nt_dev/1 firmware
nvmeadm_fail get-logpage
nvmeadm_fail get-logpage health
nvmeadm_fail get-logpage health health
nvmeadm_fail get-logpage $nt_dev
nvmeadm_fail get-logpage $nt_dev,$nt_dev/1
nvmeadm_fail get-logpage $nt_dev $nt_dev
nvmeadm_fail get-logpage $nt_dev sephiorth
nvmeadm_fail get-logpage $nt_dev health sephiorth
nvmeadm_fail get-logpage $nt_dev health,error
nvmeadm_fail list-features
nvmeadm_fail list-features -a
nvmeadm_fail list-features -o csi
nvmeadm_fail list-features -H
nvmeadm_fail list-features -p
nvmeadm_fail list-features -p $nt_dev
nvmeadm_fail list-features -o magicite $nt_dev
nvmeadm_fail list-features -o csi materia
nvmeadm_fail list-features $nt_dev $nt_dev
nvmeadm_fail list-features $nt_dev/1 $nt_dev/1
nvmeadm_fail list-features $nt_dev/1 aerith
nvmeadm_fail list-features $nt_dev aerith arb temp
nvmeadm_fail get-features
nvmeadm_fail get-features $nt_dev/cid
nvmeadm_fail get-features vincent
nvmeadm_fail get-features $nt_dev range
nvmeadm_fail get-features $nt_dev/1 temp
nvmeadm_fail get-features $nt_dev temp,tifa
nvmeadm_fail get-features $nt_dev temp cloud

nvmeadm_fail list-firmware
nvmeadm_fail list-firmware -t
nvmeadm_fail list-firmware $nt_dev/1
nvmeadm_fail list-firmware $nt_dev/squall
nvmeadm_fail list-firmware $nt_dev rinoa

#
# Tests that we expect to pass in some form.
#
nvmeadm_pass list
nvmeadm_pass list $nt_dev
nvmeadm_pass list $nt_dev/1
nvmeadm_pass list $nt_dev,$nt_dev/1
nvmeadm_pass list -p -o model,serial $nt_dev
nvmeadm_pass list -p -o model,serial $nt_dev/1
nvmeadm_pass list -p -o model,serial $nt_dev/1,$nt_dev
nvmeadm_pass list -p -o instance,ctrlpath $nt_dev
nvmeadm_pass list -p -o instance,ctrlpath $nt_dev/1
nvmeadm_pass list -p -o instance,ctrlpath $nt_dev/1,$nt_dev
nvmeadm_pass list -c
nvmeadm_pass list -c $nt_dev
nvmeadm_pass list -c $nt_dev/1
nvmeadm_pass list -c $nt_dev,$nt_dev/1
nvmeadm_pass list -c -p -o model,serial $nt_dev
nvmeadm_pass list -c -p -o model,serial $nt_dev/1
nvmeadm_pass list -c -p -o model,serial $nt_dev/1,$nt_dev
nvmeadm_pass list -c -p -o instance,ctrlpath $nt_dev
nvmeadm_pass list -c -p -o instance,ctrlpath $nt_dev/1
nvmeadm_pass list -c -p -o instance,ctrlpath $nt_dev/1,$nt_dev
nvmeadm_pass identify $nt_dev
nvmeadm_pass identify $nt_dev/1
nvmeadm_pass identify $nt_dev,$nt_dev/1
nvmeadm_pass identify $nt_dev,$nt_dev
nvmeadm_pass identify $nt_dev,$nt_dev/1,$nt_dev
nvmeadm_ns identify -C $nt_dev
nvmeadm_ns identify -c $nt_dev
nvmeadm_pv1v3 identify -d $nt_dev/1
nvmeadm_pv1v1 identify -n $nt_dev
nvmeadm_ns identify -n -a $nt_dev
nvmeadm_ns identify-controller -C $nt_dev
nvmeadm_ns identify-controller -c $nt_dev
nvmeadm_pv1v1 identify-controller -n $nt_dev
nvmeadm_ns identify-controller -n -a $nt_dev

#
# All of our list- and get-logpage tests strictly use the 3 NVMe 1.0 log pages:
# error, health, firmware. Note: NVMe 1.0 did not define any namespace-specific
# log pages, the health log page was changed later. Therefore there are no tests
# specific to solely namespace scope right now.
#
nvmeadm_pass list-logpages $nt_dev
nvmeadm_pass list-logpages -H $nt_dev
nvmeadm_pass list-logpages -o device $nt_dev
nvmeadm_pass list-logpages -H -o device $nt_dev
nvmeadm_pass list-logpages -o \
    device,name,desc,scope,fields,csi,lid,impl,size,minsize,sources,kind $nt_dev
nvmeadm_pass list-logpages -p -o lid $nt_dev
nvmeadm_pass list-logpages -H -p -o lid $nt_dev
nvmeadm_pass list-logpages -s controller $nt_dev
nvmeadm_pass list-logpages -s controller -H $nt_dev
nvmeadm_pass list-logpages -s controller -H -o device $nt_dev
nvmeadm_pass list-logpages -s controller -o \
    device,name,desc,scope,fields,csi,lid,impl,size,minsize,sources,kind $nt_dev
nvmeadm_pass list-logpages -s controller -p -o lid $nt_dev
nvmeadm_pass list-logpages -s controller,nvm $nt_dev
nvmeadm_pass list-logpages -s controller,nvm,ns $nt_dev
nvmeadm_pass list-logpages $nt_dev,$nt_dev
nvmeadm_pass list-logpages $nt_dev error
nvmeadm_pass list-logpages $nt_dev health
nvmeadm_pass list-logpages -a $nt_dev
nvmeadm_pass list-logpages -a $nt_dev health
nvmeadm_pass list-logpages -s controller $nt_dev health
nvmeadm_pass get-logpage $nt_dev health
nvmeadm_pass get-logpage $nt_dev firmware
nvmeadm_pass get-logpage $nt_dev,$nt_dev firmware
nvmeadm_pass list-features $nt_dev
nvmeadm_pass list-features -H $nt_dev
nvmeadm_pass list-features -o device $nt_dev
nvmeadm_pass list-features -p -o device,impl $nt_dev
nvmeadm_pass list-features -o \
    device,short,spec,fid,scope,kind,csi,flags,get-in,get-out,set-out,datalen \
    $nt_dev
nvmeadm_pass list-features -a $nt_dev
nvmeadm_pass list-features $nt_dev/1
nvmeadm_pass list-features -H $nt_dev/1
nvmeadm_pass list-features -o short,fid $nt_dev/1
nvmeadm_pass list-features -p -o device,impl $nt_dev/1
nvmeadm_pass list-features -o \
    device,short,spec,fid,scope,kind,csi,flags,get-in,get-out,set-out,datalen \
    $nt_dev/1
nvmeadm_pass list-features -a $nt_dev/1
nvmeadm_pass list-features $nt_dev,$nt_dev/1
nvmeadm_pass list-features $nt_dev,$nt_dev/1,$nt_dev
nvmeadm_pass list-features $nt_dev pm
nvmeadm_pass list-features $nt_dev arbitration
nvmeadm_pass list-features $nt_dev Arbitration
nvmeadm_pass list-features $nt_dev pm Arbitration temp
#
# If you find a get-features without arguments is causing issues, please feel
# free to remove this test.
#
nvmeadm_pass get-features $nt_dev
nvmeadm_pass get-features $nt_dev temp
nvmeadm_pass get-features $nt_dev temp,vector
nvmeadm_pass get-features $nt_dev,$nt_dev arb

nvmeadm_pass list-firmware $nt_dev

if (( nt_exit == 0 )); then
	printf "All tests passed successfully!\n"
else
	printf "%u tests failed!\n" "$nt_fail"
fi

exit $nt_exit
