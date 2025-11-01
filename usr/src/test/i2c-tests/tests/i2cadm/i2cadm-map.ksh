#! /usr/bin/ksh
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
# Various tests that the data we have for the i2c port map command is what we
# expect. This uses the full device profile and makes the following assumptions:
#
# 1. No one has snuck in and added or deleted devices.
# 2. We have to be careful about devices that are manually claimed as they may
#    be detached and therefore not listed in the port unless we have the device
#    actively open.
#
# We don't currently fake up the DDR4 RDIMMs which are the main user of the
# major-wide shared address binding, so there is no test for that here.
#

. $(dirname $0)/common.ksh

typeset -A port_count
typeset -A port_type
typeset port_path=

function read_map
{
	typeset path="$1"
	typeset map_ifs="$IFS"

	set -A port_count
	set -A port_type
	IFS=":"
	while read -A value; do
		port_count[${value[0]}]=${value[1]}
		port_type[${value[0]}]=${value[2]}
	done <<< $($I2CADM port map -Hpo addr,count,type $path)
	IFS="$scan ifs"
	port_path="$path"
}

function verify
{
	typeset addr="$1"
	typeset ptype="$2"
	typeset count="$3"
	typeset valid=

	if (( port_count[$addr] != count )); then
		valid=no
		warn "$addr on $port_path has count ${port_count[$addr]}, but" \
		    "expected $count"
	fi

	if [[ "${port_type[$addr]}" != $ptype ]]; then
		valid=no
		warn "$addr on $port_path has type ${port_type[$addr]}, but" \
		    "expected $ptype"
	fi

	if [[ -z "$valid" ]]; then
		printf "TEST PASSED: %s on %s has type (%s) and count (%u)\n" \
		    "$addr" "$port_path" "$ptype" "$count"
	fi
}

#
# We should find most things on the top-level port.
#
read_map i2csim0/0
verify 0x0 none 0
verify 0x10 local 1
verify 0x20 local 1
verify 0x33 none 0
verify 0x70 local 1
verify 0x71 downstream 4
verify 0x72 downstream 10
verify 0x7f none 0

#
# Moving onto the first port on the mux, we expect all of the older local
# devices to no longer be there.
#
read_map i2csim0/0/0x70/0
verify 0x10 none 0
verify 0x20 none 0
verify 0x30 none 0
verify 0x71 local 1
verify 0x72 downstream 8

#
# And even less if we go to one of the ports below it.
#
read_map i2csim0/0/0x70/0/0x71/0
for i in {0..127}; do
	(( i == 0x72 )) && continue
	verify $i none 0
done
verify 0x72 local 1

#
# This port should be empty.
#
read_map i2csim0/0/0x70/6
for i in {0..127}; do
	verify $i none 0
done


if (( i2c_exit == 0 )); then
	printf "All tests passed successfully!\n"
fi

exit $i2c_exit
