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

unalias -a

mac_test_dir="$(dirname $0)"
mac_data_dir="$mac_test_dir/data"
mac_cksum="$mac_test_dir/mac_cksum"
mac_exit=0

run_test()
{
	typeset input="$mac_data_dir/$1"
	shift

	echo "$mac_cksum $* $input"
	$mac_cksum $* $input
	if (( $? != 0 )); then
		mac_exit=1
	fi

	# And again with 2 bytes of padding to offset the data in memory
	echo "$mac_cksum $* -b 2 $input"
	$mac_cksum $* -b 2 $input
	if (( $? != 0 )); then
		mac_exit=1
	fi
}

# The bad-L4-proto case should only try getting a IPv4 checksum.
# It would fail to get an L4 checksum
run_test ipv4_bad_proto.snoop -4

ipv4_cases="ipv4_tcp.snoop ipv4_udp.snoop"
for c in $ipv4_cases; do
	run_test $c -4 -p
	run_test $c -4 -f
done

ipv6_cases="ipv6_icmp.snoop ipv6_tcp.snoop ipv6_udp.snoop ipv6_eh_udp.snoop"
for c in $ipv6_cases; do
	run_test $c -p
	if [[ $c == "ipv6_icmp.snoop" || $c == "ipv6_eh_udp.snoop" ]]; then
		# Full checksums on ICMPv6 or those bearing extension headers are not
		# presently supported.  Skip such testing for now.
		continue
	fi
	run_test $c -f
done

# Only full checksums are supported for SCTP
run_test "ipv4_sctp.snoop" -4 -f
run_test "ipv6_sctp.snoop" -f

exit $mac_exit
