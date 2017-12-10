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

#
# The purpose of this test is to verify that set-linkprop performs as
# it should -- both on persistent and temporary links.
#

vm_arg0="$(basename $0)"
vm_stub="teststub$$"
vm_pvnic="test_pvnic$$"
vm_tvnic="test_tvnic$$"

DL_FILE=/etc/dladm/datalink.conf

fatal()
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST_FAIL: $vm_arg0: $msg" >&2

	# Try to clean up just in case
	dladm delete-vnic $vm_pvnic 2>/dev/null
	dladm delete-vnic $vm_tvnic 2>/dev/null
	dladm delete-etherstub $vm_stub 2>/dev/null
	exit 1
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
}

create_vnic()
{
	typeset dev=$1
	typeset flags=$2

	dladm create-vnic $flags -l $vm_stub $dev 2>/dev/null || fatal \
	    "failed to create vnic: $dev"
}

delete_vnic()
{
	typeset dev=$1

	dladm delete-vnic $dev || fatal "failed to delete vnic: $dev"
}

#
# Validate the property is reported by dladm.
#
validate_prop()
{
	typeset dev=$1
	typeset prop=$2
	typeset val=$3
	typeset oval

	[[ -z "$dev" ]] && fatal "missing required device"
	[[ -z "$prop" ]] && fatal "missing required prop"
	[[ -z "$val" ]] && fatal "missing required val"
	oval=$(dladm show-linkprop -c -o value -p $prop $dev | tr -d ' ')
	[[ $? -eq 0 ]] || fatal "failed to get $prop for $dev"
	[[ "$val" == "$oval" ]] || fatal \
	    "$prop mismatch on $dev: expected $val, got $oval"
}

#
# Validate the property is persistent.
#
validate_pprop()
{
	typeset dev=$1
	typeset prop=$2
	typeset val=$3
	typeset oval

	[[ -z "$dev" ]] && fatal "missing required device"
	[[ -z "$prop" ]] && fatal "missing required prop"
	[[ -z "$val" ]] && fatal "missing required val"

	oval=$(awk "/^$dev/ { print \$2 }" $DL_FILE | \
	    awk -F, "BEGIN { RS=\";\"; } /^$prop/ { print \$2; }")

	[[ $? -eq 0 ]] || fatal "failed to get persistent $prop for $dev"
	[[ "$val" == "$oval" ]] || fatal \
	    "persistent $prop mismatch on $dev: expected $val, got $oval"
}

#
# Validate the the property is not persistent.
#
validate_not_pprop()
{
	typeset dev=$1
	typeset prop=$2

	[[ -z "$dev" ]] && fatal "missing required device"
	[[ -z "$prop" ]] && fatal "missing required prop"

	oval=$(awk "/^$dev/ { print \$2 }" $DL_FILE | \
	    awk -F, "BEGIN { RS=\";\"; } /^$prop/ { print \$2; }")

	[[ $? -eq 0 ]] || fatal "failed to search $DL_FILE"

	[[ -z "$oval" ]] || fatal \
	    "found persistent $prop for $dev but didn't expect to"

}

set_prop_pass()
{
	typeset dev=$1
	typeset flags=$2
	typeset prop=$3
	typeset val=$4
	typeset msg="failed to set prop $prop on $dev"

	[[ "$#" -ne 4 ]] && fatal "set_prop_pass() requires 4 args"
	[[ -z "$dev" ]] && fatal "missing required device"
	[[ -z "$prop" ]] && fatal "missing required prop"
	[[ -z "$val" ]] && fatal "missing required val"

	if [ -n "$flags" ]; then
		typeset msg="failed to set temp prop $prop on $dev"
	fi

	dladm set-linkprop $flags -p $prop=$val $dev || fatal $msg
}

test_pass()
{
	[[ -f $DL_FILE ]] || fatal "datalink file does not exist: $DL_FILE"

	create_stub

	#
	# Test setting persistent and temp properties on a persistent
	# link.
	#
	create_vnic $vm_pvnic

	set_prop_pass $vm_pvnic "-t" maxbw 89
	validate_prop $vm_pvnic maxbw 89
	validate_not_pprop $vm_pvnic maxbw 89
	set_prop_pass $vm_pvnic "-t" priority medium
	validate_prop $vm_pvnic priority medium
	validate_not_pprop $vm_pvnic priority medium

	set_prop_pass $vm_pvnic "" maxbw 99
	validate_prop $vm_pvnic maxbw 99
	validate_pprop $vm_pvnic maxbw 99
	set_prop_pass $vm_pvnic "" priority low
	validate_prop $vm_pvnic priority low
	validate_pprop $vm_pvnic priority low

	delete_vnic $vm_pvnic

	#
	# Test setting persistent and temp properties on a temp link.
	# A "persistent" property on a temp link is really just a temp
	# property. But setting a property on a temp link, without
	# passing -t, should still work and report success to the
	# user.
	#
	create_vnic $vm_tvnic "-t"

	set_prop_pass $vm_tvnic "-t" maxbw 89
	validate_prop $vm_tvnic maxbw 89
	validate_not_pprop $vm_tvnic maxbw 89
	set_prop_pass $vm_tvnic "-t" priority medium
	validate_prop $vm_tvnic priority medium
	validate_not_pprop $vm_tvnic priority medium

	set_prop_pass $vm_tvnic "" maxbw 99
	validate_prop $vm_tvnic maxbw 99
	validate_not_pprop $vm_tvnic maxbw 99
	set_prop_pass $vm_tvnic "" priority low
	validate_prop $vm_tvnic priority low
	validate_not_pprop $vm_tvnic priority low

	delete_vnic $vm_tvnic

	delete_stub
}

test_pass
