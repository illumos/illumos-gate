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
# Copyright 2015 Joyent, Inc.
#

#
# The purpose of this is to test the MTU property on VNICs, using both
# temporary and persistent properties. To do this, we create an
# Etherstub and then create various VNICs on top of it.
#

vm_arg0="$(basename $0)"
vm_stub="teststub$$"
vm_vnic="testvnic$$"

VM_MTU_MIN=576
VM_MTU_MAX=9000

fatal()
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST_FAIL: $vm_arg0: $msg" >&2

	# Try to clean up just in case
	dladm delete-vnic $vm_vnic 2>/dev/null
	dladm delete-etherstub $vm_stub 2>/dev/null
	exit 1
}

#
# Validate that the MTU of the datalink dev has the MTU that we expect
#
validate_mtu()
{
	typeset dev=$1
	typeset mtu=$2
	typeset val

	[[ -z "$dev" ]] && fatal "missing required device"
	[[ -z "$mtu" ]] && fatal "missing required mtu"
	val=$(dladm show-linkprop -c -p mtu -o value $dev)
	[[ $? -eq 0 ]] || fatal "failed to get MTU for $dev"
	(( $val == $mtu )) || fatal \
	    "mtu mismatch on $dev: expected $mtu, got $val"
}

delete_stub()
{
	dladm delete-etherstub $vm_stub || fatal \
	    "failed to delete stub $vm_stub"
}

create_stub()
{
	dladm create-etherstub $vm_stub || fatal \
	    "failed to create stub"
	validate_mtu $vm_stub $VM_MTU_MAX
}

delete_vnic()
{
	dladm delete-vnic $vm_vnic || fatal "failed to delete vnic $vm_vnic"
}

test_vnic_pass()
{
	typeset mtu=$1
	typeset flags=$2

	[[ -z "$mtu" ]] && fatal "missing required mtu"
	dladm create-vnic $flags -l $vm_stub -p mtu=$mtu $vm_vnic || fatal \
	    "failed to create vnic: $vm_vnic"
	validate_mtu "$vm_vnic" "$mtu"
	delete_vnic
}

test_vnic_fail()
{
	typeset mtu=$1
	typeset flags=$2

	[[ -z "$mtu" ]] && fatal "missing required mtu"
	dladm create-vnic $flags -l $vm_stub -p mtu=$mtu \
	    $vm_vnic 2>/dev/null && fatal \
	    "created vnic with mtu $mtu, but failure expected"
}

test_pass()
{
	typeset flags=$1

	create_stub
	test_vnic_pass 1500 $flags
	test_vnic_pass 1400 $flags
	test_vnic_pass $VM_MTU_MIN $flags
	test_vnic_pass $VM_MTU_MAX $flags
	test_vnic_fail $((($VM_MTU_MIN - 1))) $flags
	test_vnic_fail $((($VM_MTU_MAX + 1))) $flags
	delete_stub
}

test_pass "-t"
test_pass
echo "TEST PASS: $vm_arg0"
