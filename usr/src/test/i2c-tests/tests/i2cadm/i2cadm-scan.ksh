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
# Test i2cadm scan behavior. This is generally designed for human output. First
# verify that we can run a few scans on i2csim0 error free. After that send
# parseable # output to files and check that specific entries have what we
# expect. This is definitely written in the max power way.
#

. $(dirname $0)/common.ksh

typeset -A scan_results

function read_scan
{
	typeset path="$1"
	typeset scan_ifs="$IFS"

	set -A scan_results
	IFS=":"
	while read -A value; do
		scan_results[${value[0]}]=${value[1]}
	done <<< $($I2CADM scan -Hpo addr,result $path)
	IFS="$scan_ifs"
}

function check_one
{
	typeset desc="$1"
	typeset addr="$2"
	typeset exp="$3"

	if [[ ${scan_results[$addr]} != "$exp" ]]; then
		warn "$desc: found $addr as ${scan_results[$addr]}, wanted $exp"
	else
		printf "TEST PASSED: %s 0x%x is %s\n" "$desc" "$addr" "$exp"
	fi
}

i2cadm_pass scan i2csim0/0
i2cadm_pass scan i2csim0/0/0x70/0
i2cadm_pass scan i2csim0/0/0x70/7
i2cadm_pass scan i2csim0/0/0x70/0/0x71/1
i2cadm_pass scan i2csim0/0/0x70/0/0x71/6

#
# Basic scan. Verify reserved addresses. Spot check missing and present. We
# explicitly hit the missing ones that'll be activated when we enable the mux.
#
read_scan i2csim0/0
check_one "i2csim0/0" 0x00 reserved
check_one "i2csim0/0" 0x01 reserved
check_one "i2csim0/0" 0x02 reserved
check_one "i2csim0/0" 0x03 reserved
check_one "i2csim0/0" 0x04 reserved
check_one "i2csim0/0" 0x05 reserved
check_one "i2csim0/0" 0x06 reserved
check_one "i2csim0/0" 0x07 reserved
check_one "i2csim0/0" 0x78 reserved
check_one "i2csim0/0" 0x79 reserved
check_one "i2csim0/0" 0x7a reserved
check_one "i2csim0/0" 0x7b reserved
check_one "i2csim0/0" 0x7c reserved
check_one "i2csim0/0" 0x7d reserved
check_one "i2csim0/0" 0x7e reserved
check_one "i2csim0/0" 0x7f reserved
check_one "i2csim0/0" 0x10 found
check_one "i2csim0/0" 0x20 found
check_one "i2csim0/0" 0x21 found
check_one "i2csim0/0" 0x22 found
check_one "i2csim0/0" 0x23 found
check_one "i2csim0/0" 0x70 found
check_one "i2csim0/0" 0x71 missing
check_one "i2csim0/0" 0x72 missing
check_one "i2csim0/0" 0x42 missing
check_one "i2csim0/0" 0x58 missing
check_one "i2csim0/0" 0x6f missing

read_scan i2csim0/0/0x70/0
check_one "i2csim0/0/0x70/0" 0x42 missing
check_one "i2csim0/0/0x70/0" 0x70 found
check_one "i2csim0/0/0x70/0" 0x71 found
check_one "i2csim0/0/0x70/0" 0x72 missing

read_scan i2csim0/0/0x70/1
check_one "i2csim0/0/0x70/1" 0x42 missing
check_one "i2csim0/0/0x70/1" 0x70 found
check_one "i2csim0/0/0x70/1" 0x71 found
check_one "i2csim0/0/0x70/1" 0x72 missing

read_scan i2csim0/0/0x70/2
check_one "i2csim0/0/0x70/2" 0x42 missing
check_one "i2csim0/0/0x70/2" 0x70 found
check_one "i2csim0/0/0x70/2" 0x71 found
check_one "i2csim0/0/0x70/2" 0x72 found

read_scan i2csim0/0/0x70/3
check_one "i2csim0/0/0x70/2" 0x42 missing
check_one "i2csim0/0/0x70/2" 0x70 found
check_one "i2csim0/0/0x70/2" 0x71 found
check_one "i2csim0/0/0x70/2" 0x72 found

read_scan i2csim0/0/0x70/7
check_one "i2csim0/0/0x70/7" 0x10 found
check_one "i2csim0/0/0x70/7" 0x20 found
check_one "i2csim0/0/0x70/7" 0x70 found
check_one "i2csim0/0/0x70/7" 0x71 missing
check_one "i2csim0/0/0x70/7" 0x72 missing

for port in {0..7}; do
	read_scan i2csim0/0/0x70/0/0x71/$port
	check_one "i2csim0/0/0x70/0/0x71/$port" 0x42 missing
	check_one "i2csim0/0/0x70/0/0x71/$port" 0x70 found
	check_one "i2csim0/0/0x70/0/0x71/$port" 0x71 found
	check_one "i2csim0/0/0x70/0/0x71/$port" 0x72 found
	check_one "i2csim0/0/0x70/0/0x71/$port" 0x73 missing
done

if (( i2c_exit == 0 )); then
	printf "All tests passed successfully!\n"
fi

exit $i2c_exit
