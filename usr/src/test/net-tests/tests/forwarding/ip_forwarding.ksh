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
# Copyright 2019 Joyent, Inc.
#

#
# Usage:
#
#     ip_forwarding.ksh -flnpvu <client> <router> <server>
#
#     Where client, router, and server are the UUIDs of three native
#     zones. The user must create and start these zones; but other
#     than that there is no special configuration required for them.
#
#     -c	Run cleanup only.
#
#     -f	Full ULP hardware checksum.
#
#     -l	Hardware TCP LSO.
#
#     -n	No cleanup: the various artifacts created by this script will
#               remain after execution.
#
#     -p	Partial ULP hardware checksum.
#
#     -u	Run UDP tests.
#
#     -v	Vebose mode.
#

if [[ -z $NET_TESTS ]]; then
	echo "NET_TESTS not set" >&2
	exit 1
fi

. $NET_TESTS/tests/net_common

function cleanup
{
	rm -rf ${nt_tdirprefix}*
	zlogin $nt_client rm -rf ${nt_tdirprefix}*
	zlogin $nt_server rm -rf ${nt_tdirprefix}*

	rm_route $nt_client $nt_server_ip $nt_server_subnet $nt_client_router_ip
	rm_route $nt_server $nt_client_ip $nt_client_subnet $nt_server_router_ip
	rm_route6 $nt_client $nt_server_ip6 $nt_server_subnet6 \
		  $nt_client_router_ip6
	rm_route6 $nt_server $nt_client_ip6 $nt_client_subnet6 \
		  $nt_server_router_ip6

	ip_fwd_disable $nt_router

	delete_addr $nt_client ipft_client0 v4
	delete_addr $nt_router ipft_client_r0 v4
	delete_addr $nt_router ipft_server_r0 v4
	delete_addr $nt_server ipft_server0 v4

	delete_addr $nt_client ipft_client0 v6
	delete_addr $nt_router ipft_client_r0 v6
	delete_addr $nt_router ipft_server_r0 v6
	delete_addr $nt_server ipft_server0 v6

	delete_if $nt_client ipft_client0
	delete_if $nt_router ipft_client_r0
	delete_if $nt_router ipft_server_r0
	delete_if $nt_server ipft_server0

	delete_vnic ipft_client0 ipft_nic0 0 $nt_client
	delete_vnic ipft_client_r0 ipft_nic1 0 $nt_router
	delete_vnic ipft_server_r0 ipft_nic1 5 $nt_router
	delete_vnic ipft_server0 ipft_nic1 5 $nt_server

	delete_simnet ipft_nic0
	delete_simnet ipft_nic1
}

function usage
{
	echo "$nt_tname -cflnpuv <client> <router> <server>" >&2
}

#
# Set test defaults.
#
nt_tname=${NT_TNAME:-$(basename $0)}
nt_ulp_full=0
nt_ulp_partial=0
nt_tcp_lso=0
nt_udp=0
nt_cleanup=1
nt_cleanup_only=0

nt_tdirprefix=/tmp/${nt_tname}
nt_tdir=${nt_tdirprefix}.$$
nt_dfile=${nt_tdir}/${nt_tname}.data
nt_efile=${nt_tdir}/${nt_tname}-expected-sha1
nt_rfile=${nt_tdir}/${nt_tname}-received-sha1
nt_ofile=${nt_tdir}/${nt_tname}-received
nt_client_subnet=192.168.77.0/24
nt_client_ip=192.168.77.2
nt_client_router_ip=192.168.77.1
nt_server_subnet=192.168.88.0/24
nt_server_ip=192.168.88.2
nt_server_router_ip=192.168.88.1
nt_port=7774
nt_client_subnet6=fd00:0:1:4d::2/64
nt_client_ip6=fd00:0:1:4d::2
nt_client_router_ip6=fd00:0:1:4d::1
nt_server_subnet6=fd00:0:1:58::/64
nt_server_router_ip6=fd00:0:1:58::1
nt_server_ip6=fd00:0:1:58::2
nt_port6=7776

while getopts "cflnpuv" opt; do
	case $opt in
	c)
		nt_cleanup_only=1
		;;
	f)
		nt_ulp_full=1
		;;
	l)
		nt_tcp_lso=1
		;;
	n)
		nt_cleanup=0
		;;
	p)
		nt_ulp_partial=1
		;;
	u)
		nt_udp=1
		;;
	v)
		DEBUG=1
		;;
	esac
done

shift $((OPTIND - 1))

if ((nt_ulp_partial == 1)) && ((nt_ulp_full == 1)); then
	fail "both partial and full checksum enabled"
fi

if (( $# != 3 )); then
	usage
	fail "wrong number of arguments"
fi

nt_client=$1
nt_router=$2
nt_server=$3

if [[ "$nt_client" == "$nt_router" || "$nt_router" == "$nt_server" ||
	      "$nt_client" == "$nt_server" ]]; then
	fail "all zones must be unique"
fi

dbg "client zone: $nt_client"
dbg "router zone: $nt_router"
dbg "server zone: $nt_server"

BAIL=1
zone_exists $nt_client || fail "zone $nt_client not found"
zone_exists $nt_router || fail "zone $nt_router not found"
zone_exists $nt_server || fail "zone $nt_server not found"

zone_running $nt_client
zone_running $nt_router
zone_running $nt_server

if ! zlogin $nt_client ls /usr/bin/socat > /dev/null; then
	fail "zone $nt_client missing socat"
fi

if ! zlogin $nt_server ls /usr/bin/socat > /dev/null; then
	fail "zone $nt_client missing socat"
fi

#
# Make a best effort to cleanup artifacts from a previous run.
#
if ((nt_cleanup_only == 1)); then
	dbg "performing cleanup only"
	BAIL=0
	cleanup
	BAIL=1
	exit 0
fi

mkdir $nt_tdir
zlogin $nt_client mkdir $nt_tdir
zlogin $nt_server mkdir $nt_tdir

create_simnet ipft_nic0
create_simnet ipft_nic1
link_simnets ipft_nic0 ipft_nic1

if ((nt_ulp_partial == 1)); then
	set_linkprop ipft_nic0 _tx_ulp_cksum partial
	set_linkprop ipft_nic1 _tx_ulp_cksum partial
fi

if ((nt_ulp_full == 1)); then
	set_linkprop ipft_nic0 _tx_ulp_cksum fullv4
	set_linkprop ipft_nic1 _tx_ulp_cksum fullv4
fi

if ((nt_ulp_full == 1)) || ((nt_ulp_partial == 1)); then
	set_linkprop ipft_nic0 _tx_ipv4_cksum on
	set_linkprop ipft_nic1 _tx_ipv4_cksum on
fi

if ((nt_tcp_lso == 1)); then
	set_linkprop ipft_nic0 _lso on
	set_linkprop ipft_nic1 _lso on
fi

create_vnic ipft_client0 ipft_nic0 0 $nt_client
create_vnic ipft_client_r0 ipft_nic1 0 $nt_router
create_vnic ipft_server_r0 ipft_nic1 5 $nt_router
create_vnic ipft_server0 ipft_nic1 5 $nt_server

ip_fwd_enable $nt_router

create_addr $nt_client ipft_client0 $nt_client_ip/24
create_addr $nt_router ipft_client_r0 $nt_client_router_ip/24
create_addr $nt_router ipft_server_r0 $nt_server_router_ip/24
create_addr $nt_server ipft_server0 $nt_server_ip/24

add_route $nt_client $nt_server_ip $nt_server_subnet $nt_client_router_ip
add_route $nt_server $nt_client_ip $nt_client_subnet $nt_server_router_ip

create_addr6 $nt_client ipft_client0 $nt_client_ip6
create_addr6 $nt_router ipft_client_r0 $nt_client_router_ip6
create_addr6 $nt_router ipft_server_r0 $nt_server_router_ip6
create_addr6 $nt_server ipft_server0 $nt_server_ip6

add_route6 $nt_client $nt_server_ip6 $nt_server_subnet6 $nt_client_router_ip6
add_route6 $nt_server $nt_client_ip6 $nt_client_subnet6 $nt_server_router_ip6

dd if=/dev/urandom of=$nt_dfile bs=1024 count=1024 > /dev/null 2>&1
if (($? != 0)); then
	fail "failed to create data file: $nt_dfile"
else
	dbg "created data file: $nt_dfile"
fi

digest -a sha1 $nt_dfile > $nt_efile

# ================================================================
# client -> server
# ================================================================
ping $nt_client $nt_client_ip $nt_server_ip
ping $nt_client $nt_client_ip6 $nt_server_ip6

start_server $nt_server TCP4 $nt_server_ip $nt_port $nt_ofile
nt_listener_ppid=$!

# Give the server time to start.
sleep 1

dbg "sending 1M $nt_client ($nt_client_ip) -> $nt_server ($nt_server_ip)"
zlogin $nt_client /usr/bin/socat -b 8192 STDIN \
       TCP4:$nt_server_ip:$nt_port,connect-timeout=5 < $nt_dfile

if (($? != 0)); then
	pkill -TERM -P $nt_listener_ppid
	fail "failed to run socat client"
else
	dbg "sent 1M $nt_client ($nt_client_ip) -> $nt_server ($nt_server_ip)"
fi

#
# The client may have exited but make sure to give the server time to
# exit and finish computing the SHA1.
#
dbg "waiting for listener $nt_listener_ppid"
wait_for_pid $nt_listener_ppid 5
dbg "listener $nt_listener_ppid exited"

digest -a sha1 /zones/$nt_server/root/$nt_ofile > $nt_rfile

if ! diff $nt_efile $nt_rfile; then
	fail "SHA1 comparison failed"
else
	dbg "SHA1 comparison passed"
fi

start_server $nt_server TCP6 $nt_server_ip6 $nt_port6 $nt_rfile
listener_ppid=$!

# Give the server time to start.
sleep 1

zlogin $nt_client /usr/bin/socat -b 8192 STDIN \
       TCP6:[${nt_server_ip6}]:$nt_port6,connect-timeout=5 < $nt_dfile

if (($? != 0)); then
	pkill -TERM -P $nt_listener_ppid
	fail "failed to run socat client IPv6"
else
	dbg "sent 1M $nt_client ($nt_client_ip6)" \
	    "-> $nt_server ($nt_server_ip6) IPv6"
fi

#
# The client may have exited but make sure to give the server time to
# exit and finish computing the SHA1.
#
dbg "waiting for listener $nt_listener_ppid"
wait_for_pid $nt_listener_ppid 5
dbg "listener $nt_listener_ppid exited"

digest -a sha1 /zones/$nt_server/root/$nt_ofile > $nt_rfile

if ! diff $nt_efile $nt_rfile; then
	fail "SHA1 comparison failed"
else
	dbg "SHA1 comparison passed"
fi

if ((nt_udp == 1)); then
	ping_udp $nt_client $nt_client_ip $nt_server_ip 256 3
	ping_udp $nt_client $nt_client_ip6 $nt_server_ip6 256 3

	#
	# Test IP fragmentation by sending a larger-than-MTU datagram.
	# You can verify fragmentation is happening by dtracing the
	# various "Frag" and "Reasm" mibs.
	#
	dbg "test IP fragmentation $nt_client_ip -> $nt_server_ip"
	ping_udp $nt_client $nt_client_ip $nt_server_ip $((1024 * 16)) 3

	dbg "test IPv6 fragmentation $nt_client_ip6 -> $nt_server_ip6"
	ping_udp $nt_client $nt_client_ip6 $nt_server_ip6 $((1024 * 16)) 3
fi

# ================================================================
# server -> client
# ================================================================
ping $nt_server $nt_server_ip $nt_client_ip
ping $nt_server $nt_server_ip6 $nt_client_ip6

start_server $nt_client TCP4 $nt_client_ip $nt_port $nt_ofile
nt_listener_ppid=$!

# Give the listener time to start.
sleep 1

zlogin $nt_server /usr/bin/socat -b 8192 STDIN \
       TCP4:$nt_client_ip:$nt_port,bind=$nt_server_ip,connect-timeout=5 \
       < $nt_dfile

if (($? != 0)); then
	pkill -TERM -P $nt_listener_ppid
	fail "failed to run socat client"
else
	dbg "sent 1M $nt_server ($nt_server_ip) -> $nt_client ($nt_client_ip)"
fi

#
# The client may have exited but make sure to give the server time to
# exit and finish computing the SHA1.
#
dbg "waiting for listener $nt_listener_ppid"
wait_for_pid $nt_listener_ppid 5
dbg "listener $nt_listener_ppid exited"

digest -a sha1 /zones/$nt_client/root/$nt_ofile > $nt_rfile

if ! diff $nt_efile $nt_rfile; then
	fail "SHA1 comparison failed"
else
	dbg "SHA1 comparison passed"
fi

start_server $nt_client TCP6 $nt_client_ip6 $nt_port6 $nt_ofile
nt_listener_ppid=$!

# Give the listener time to start.
sleep 1

zlogin $nt_server /usr/bin/socat -b 8192 STDIN \
       TCP6:[$nt_client_ip6]:$nt_port6,connect-timeout=5 < $nt_dfile

if (($? != 0)); then
	pkill -TERM -P $nt_listener_ppid
	fail "failed to run socat client IPv6"
else
	dbg "sent 1M $nt_server ($nt_server_ip6) -> $nt_client ($nt_client_ip6)"
fi

#
# The client may have exited but make sure to give the server time to
# exit and finish computing the SHA1.
#
dbg "waiting for listener $nt_listener_ppid"
wait_for_pid $nt_listener_ppid 5
dbg "server $nt_listener_ppid exited"

digest -a sha1 /zones/$nt_client/root/$nt_ofile > $nt_rfile

if ! diff $nt_efile $nt_rfile; then
	fail "SHA1 comparison failed"
else
	dbg "SHA1 comparison passed"
fi

if ((nt_udp == 1)); then
	ping_udp $nt_server $nt_server_ip $nt_client_ip 256 3
	ping_udp $nt_server $nt_server_ip6 $nt_client_ip6 256 3

	#
	# Test IP fragmentation by sending a larger-than-MTU datagram.
	# You can verify fragmentation is happening by dtracing the
	# various "Frag" and "Reasm" mibs.
	#
	dbg "test IP fragmentation $nt_server_ip -> $nt_client_ip"
	ping_udp $nt_server $nt_server_ip $nt_client_ip $((1024 * 16)) 3

	dbg "test IPv6 fragmentation $nt_server_ip6 -> $nt_client_ip6"
	ping_udp $nt_server $nt_server_ip6 $nt_client_ip6 $((1024 * 16)) 3
fi

if ((nt_cleanup == 0)); then
	dbg "skipping cleanup"
	echo "PASS [$nt_tname]"
	exit 0
fi

cleanup
echo "PASS [$nt_tname]"
