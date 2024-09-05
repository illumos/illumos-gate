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
# Copyright 2024 Oxide Computer Company
#

#
# This is a regression test for illumos#16777. VNICs, VLANs, and Etherstubs are
# similar devices under the hood, but different classes. In this case, one could
# end up incidentally seeing information about one device when using the
# show-XXX interface of the other class. Other times, this would end up just
# outputting nothing.
#
# This test goes through and creates a device of each type that can done safely
# without interfering with actual system networking state and doesn't rely on
# existing hardware. We create everything as a temporary device other than the
# bridge because it does not currently support -t.
#

unalias -a
set -o pipefail
export LANG=C.UTF-8

dl_exit=0
dl_arg0=$(basename $0)
dl_stub="UTILtest_stub$$"
dl_vnic="UTILtest_vnic$$"
dl_vlan="UTILtest_vlan$$"
dl_sim="UTILtest_sim$$"
dl_iptun="UTILtest_iptun$$"
#
# Bridges can't end with a digit.
#
dl_bridge="UTILtest_bridge$$_"
dl_secobj="UTILtest_secobj$$"
dl_secobj_file="/tmp/UTILtest_secobj.pass"

typeset -A dl_classes
dl_classes["etherstub"]="show-etherstub"
dl_classes["vnic"]="show-vnic"
dl_classes["vlan"]="show-vlan"
dl_classes["simnet"]="show-simnet"
dl_classes["iptun"]="show-iptun"
dl_classes["bridge"]="show-bridge"
dl_classes["secobj"]="show-secobj"

fatal()
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	exit 1
}

warn()
{
	typeset msg="$*"
	echo "TEST FAILED: $msg" >&2
	dl_exit=1
}

cleanup()
{
	rm -f $dl_secobj_file
	dladm delete-secobj "$dl_secobj" 2>/dev/null
	dladm delete-bridge "$dl_bridge" 2>/dev/null
	dladm delete-iptun $dl_iptun 2>/dev/null
	dladm delete-vlan $dl_vlan 2>/dev/null
	dladm delete-simnet $dl_sim 2>/dev/null
	dladm delete-vnic $dl_vnic 2>/dev/null
	dladm delete-etherstub $dl_stub 2>/dev/null
}

setup()
{
	dladm create-etherstub -t $dl_stub || fatal "failed to create $dl_stub"
	dladm create-vnic -t -l $dl_stub $dl_vnic || fatal \
	    "failed to create $dl_vnic"
	dladm create-simnet -t -m Ethernet $dl_sim || fatal \
	    "failed to create $dl_sim"
	dladm create-vlan -t -v 23 -l $dl_sim $dl_vlan || fatal \
	    "failed to create $dl_vlan"
	dladm create-iptun -T ipv4 -t $dl_iptun || fatal \
	    "failed to create $dl_iptun"
	dladm create-bridge $dl_bridge || fatal "failed to create $dl_bridge"
	printf "A wonderful password" > $dl_secobj_file
	dladm create-secobj -c wpa -f $dl_secobj_file -t $dl_secobj || fatal \
	    "failed to create $dl_secobj"
}

#
# Given a specific device class and device, run through all of the different
# variants and make sure they pass and fail appropriately.
#
run_one()
{
	typeset dev="$1"
	typeset class="$2"
	typeset ex=
	typeset out=
	typeset ret=

	for c in "${!dl_classes[@]}"; do
		if [[ $class == $c ]]; then
			ex=0
		else
			ex=1
		fi

		out=$(dladm ${dl_classes[$c]} $dev 2>/dev/null)
		ret=$?
		if (( ret != ex )); then
			warn "dladm ${dl_classes[$c]} $dev returned $ret," \
			    "but expected $ex"
			continue
		fi

		printf "TEST PASSED: dladm %s %s correctly returned %d\n" \
		    "${dl_classes[$c]}" "$dev" $ex

		if (( ex != 0 )); then
			continue
		fi

		[[ -z "$out" ]] && warn "$dladm ${dl_classes[$c]} $dev output" \
		    "was empty"
	done
}

trap cleanup EXIT

setup
run_one "$dl_stub" "etherstub"
run_one "$dl_vnic" "vnic"
run_one "$dl_vlan" "vlan"
run_one "$dl_sim" "simnet"
run_one "$dl_iptun" "iptun"
run_one "$dl_bridge" "bridge"
run_one "$dl_secobj" "secobj"
cleanup

if (( dl_exit == 0 )); then
	printf "All tests passed successfully\n"
fi
exit $dl_exit
