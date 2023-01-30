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
mac_lso="$mac_test_dir/mac_lso"
mac_exit=0

run_one()
{
	typeset prog="$1"
	typeset input="$mac_data_dir/$2"
	shift 2

	typeset output=""
	if [[ $prog == $mac_lso ]]; then
		output="$mac_data_dir/$1"
		shift
	fi

	echo "$prog $* $input $output"
	if ! $prog $* $input $output; then
		mac_exit=1
	fi
}

run_test()
{
	# Run with and without 2-byte padding for offset reasons
	run_one $*
	run_one $* -b 2

	# Try some various mblk split combinations
	run_one $* -e
	run_one $* -s 20
	run_one $* -e -s 8
}

run_cso()
{
	run_test $mac_cksum $*
}

run_lso()
{
	run_test $mac_lso $*
}

# The bad-L4-proto case should only try getting a IPv4 checksum.
# It would fail to get an L4 checksum
run_cso ipv4_bad_proto.snoop -4

ipv4_cases="ipv4_icmp.snoop ipv4_tcp.snoop ipv4_udp.snoop"
for c in $ipv4_cases; do
	run_cso $c -4 -p
	run_cso $c -4 -f
done

ipv6_cases="ipv6_icmp.snoop ipv6_tcp.snoop ipv6_udp.snoop ipv6_eh_udp.snoop"
for c in $ipv6_cases; do
	run_cso $c -p
	run_cso $c -f
done

# Only full checksums are supported for SCTP
run_cso "ipv4_sctp.snoop" -4 -f
run_cso "ipv6_sctp.snoop" -f

# Only TCP is supported for LSO.
run_lso "ipv4_tcp_lso_in.snoop" "ipv4_tcp_lso_out.snoop" -4 -f -m 8948
run_lso "ipv4_tcp_lso_in.snoop" "ipv4_tcp_lso_out.snoop" -4 -p -m 8948
run_lso "ipv6_tcp_lso_in.snoop" "ipv6_tcp_lso_out.snoop" -f -m 8928
run_lso "ipv6_tcp_lso_in.snoop" "ipv6_tcp_lso_out.snoop" -p -m 8928

exit $mac_exit
