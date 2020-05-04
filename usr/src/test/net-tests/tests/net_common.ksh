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
# Functions shared across the network tests.
#

DEBUG=0

function dbg
{
	typeset msg="$*"
	if (($DEBUG == 1)); then
		echo "DBG [$nt_tname]: $msg"
	fi
}

function fail
{
	typeset msg="$*"
	echo "FAIL [$nt_tname]: $msg" >&2
	exit 1
}

function maybe_fail
{
	typeset msg=$1

	if ((BAIL == 1)); then
		fail "$msg"
	else
		dbg "$msg"
		return 1
	fi
}

function zone_exists
{
	typeset name=$1

	if (($# != 1)); then
		fail "$0: incorrect number of args provided"
	fi

	dbg "checking for existence of zone: $name"
	if zoneadm -z $name list > /dev/null 2>&1; then
		dbg "found zone: $name"
		return 0
	else
		dbg "zone not found: $name"
		return 1
	fi
}

function zone_running
{
	typeset name=$1
	typeset state=$(zoneadm -z $name list -p | awk -F: '{ print $3 }')
	typeset err="zone $name is not running"

	if (($# != 1)); then
		fail "$0: incorrect number of args provided"
	fi

	dbg "check if zone $name is running"
	dbg "state of zone $name: $state"
	if [[ "$state" == "running" ]]; then
		dbg "zone $name is running"
		return 0
	fi

	maybe_fail "$err"
}

function simnet_exists
{
	typeset name=$1

	if (($# != 1)); then
		fail "$0: incorrect number of args provided"
	fi

	if dladm show-simnet $name > /dev/null 2>&1; then
		dbg "simnet $name found"
		return 0
	else
		dbg "simnet $name not found"
		return 1
	fi
}

function create_simnet
{
	typeset name=$1
	typeset err="failed to create simnet $name"

	if (($# != 1)); then
		fail "$0: incorrect number of args provided"
	fi

	dbg "creating simnet $name"
	if simnet_exists $name; then
		dbg "simnet $name already exists"
		maybe_fail "$err"
		return 1
	fi

	if dladm create-simnet > /dev/null $name; then
		dbg "created simnet $name"
		return 0
	fi

	maybe_fail "$err"
}

function delete_simnet
{
	typeset name=$1
	typeset err="failed to delete simnet $name"

	if (($# != 1)); then
		fail "$0: incorrect number of args provided"
	fi

	dbg "deleting simnet $name"
	if ! simnet_exists $name; then
		dbg "simnet $name doesn't exist"
		return 1
	fi

	if dladm delete-simnet $name; then
		dbg "simnet $name deleted"
		return 0
	fi

	maybe_fail "$err"
}

function link_simnets
{
	typeset sim1=$1
	typeset sim2=$2
	typeset err="failed to link simnet $sim1 to $sim2"

	if (($# != 2)); then
		fail "$0: incorrect number of args provided"
	fi

	dbg "linking simnet $sim1 to $sim2"
	if dladm modify-simnet -p $sim2 $sim1 > /dev/null; then
		dbg "linked simnet $sim1 to $sim2"
		return 0
	fi

	maybe_fail "$err"
}

function vnic_exists
{
	typeset name=$1
	typeset vid=$2
	typeset over=$3
	typeset zone=$4

	if (($# != 4)); then
		fail "$0: incorrect number of args provided"
	fi

	if dladm show-vnic $name > /dev/null 2>&1; then
		typeset avid=$(dladm show-vnic -p -o vid $name)
		typeset aover=$(dladm show-vnic -p -o over $name)
		typeset azone=$(dladm show-linkprop -cp zone -o value $name)
		if (($avid == $vid)) && [ $aover == $over ] && \
			   [ $azone == $zone ]
		then
			return 0
		else
			return 1
		fi
	else
		return 1
	fi
}

function create_vnic
{
	typeset name=$1
	typeset over=$2
	typeset vid=$3
	typeset zone=$4
	typeset r=1
	typeset vid_opt=""
	typeset vnic_info="$name, vid: $vid, over: $over, zone: $zone"
	typeset err="failed to create VNIC: $vnic_info"

	if (($# != 4)); then
		fail "$0: incorrect number of args provided"
	fi

	if ((vid != 0)); then
		vid_opt="-v $vid"
	fi

	dbg "creating VNIC: $vnic_info"
	if ! dladm create-vnic -t -l $over $vid_opt $name > /dev/null 2>&1
	then
		maybe_fail "$err"
		return 1
	fi

	dbg "created VNIC: $vnic_info"
	if ! zonecfg -z $zone "add net; set physical=$name; end"; then
		maybe_fail "failed to assign $name to $zone"
		return 1
	fi

	dbg "assigned VNIC $name to $zone"
	if zoneadm -z $zone reboot; then
		dbg "rebooted $zone"
		#
		# Make sure the vnic is visible before returning. Without this
		# a create_addr command following immediately afterwards could
		# fail because the zone is up but the vnic isn't visible yet.
		#
		sleep 1
		return 0
	fi

	maybe_fail "failed to reboot $zone"
}

function delete_vnic
{
	typeset name=$1
	typeset vid=$2
	typeset zone=$3
	typeset vnic_info="$name, vid: $vid, zone: $zone"
	typeset err1="failed to assign VNIC $name from $zone to GZ"
	typeset err2="failed to delete VNIC: $vnic_info"

	if (($# != 3)); then
		fail "$0: incorrect number of args provided"
	fi

	dbg "assigning VNIC $name from $zone to GZ"

	if ! zonecfg -z $zone "remove net physical=$name"; then
		maybe_fail "failed to remove $name from $zone"
		return 1
	fi
	if ! zoneadm -z $zone reboot; then
		maybe_fail "failed to reboot $zone"
		return 1
	fi

	dbg "deleting VNIC: $vnic_info"
	if dladm delete-vnic $name > /dev/null; then
		dbg "deleted VNIC: $vnic_info"
		return 0
	fi

	maybe_fail "$err2"
}

function create_addr
{
	typeset zone=$1
	typeset vnic=$2
	typeset ip=$3
	typeset ipname=${vnic}/v4

	if (($# != 3)); then
		fail "$0: incorrect number of args provided"
	fi

	if zlogin $zone ipadm create-addr -t -T static -a $ip \
		  $ipname > /dev/null
	then
		dbg "created addr $ipname ($ip) in zone $zone"
		return 0
	fi

	maybe_fail "failed to create addr $ipname ($ip) in zone $zone"
}

function create_addr6
{
	typeset zone=$1
	typeset vnic=$2
	typeset ip=$3
	typeset ll_name=${vnic}/v6
	typeset uni_name=${vnic}/v6add
	typeset err1="failed to create link-local addr $ll_name in zone $zone"
	typeset err2="failed to create unicast addr $uni_name in zone $zone"

	if (($# != 3)); then
		fail "$0: incorrect number of args provided"
	fi

	if zlogin $zone ipadm create-addr -t -T addrconf $ll_name; then
		dbg "created link-local addr $ll_name in zone $zone"
	else
		maybe_fail "$err1"
		return 1
	fi

	if zlogin $zone ipadm create-addr -t -T static -a $ip/64 $uni_name; then
		dbg "created unicast addr $uni_name in zone $zone"
	else
		maybe_fail "$err2"
	fi
}

function delete_addr
{
	typeset zone=$1
	typeset ifname=$2
	typeset version=$3
	typeset ipname=$ifname/$version

	if (($# != 3)); then
		fail "$0: incorrect number of args provided"
	fi

	if zlogin $zone ipadm show-addr $ipname > /dev/null 2>&1; then
		if zlogin $zone ipadm delete-addr $ipname > /dev/null; then
			dbg "deleted addr $ipname in zone $zone"
		else
			maybe_fail "failed to delete addr $ipname in zone $zone"
			return 1
		fi
	else
		dbg "addr $ipname doesn't exist in zone $zone"
	fi

	if [[ "v6" == "$version" ]]; then
		typeset ipname=$ifname/v6add
		typeset err="failed to delete addr $ipname in zone $zone"

		if zlogin $zone ipadm show-addr $ipname > /dev/null 2>&1; then
			if zlogin $zone ipadm delete-addr $ipname > /dev/null
			then
				dbg "deleted addr $ipname in zone $zone"
			else
				maybe_fail "$err"
			fi
		else
			dbg "addr $ipname doesn't exist in zone $zone"
		fi
	fi
}

function delete_if
{
	typeset zone=$1
	typeset ifname=$2
	typeset err="failed to delete interface $ifname in zone $zone"

	if (($# != 2)); then
		fail "$0: incorrect number of args provided"
	fi

	if zlogin $zone ipadm show-if $ifname > /dev/null 2>&1; then
		if zlogin $zone ipadm delete-if $ifname > /dev/null; then
			dbg "deleted interface $ifname in zone $zone"
		else
			maybe_fail "$err"
		fi
	else
		dbg "interface $ifname doesn't exist in zone $zone"
	fi
}

function ip_fwd_enable
{
	typeset zone=$1

	if (($# != 1)); then
		fail "$0: incorrect number of args provided"
	fi

	if zlogin $zone routeadm -p ipv4-forwarding | \
			egrep 'current=enabled' > /dev/null
	then
		dbg "IPv4 forwarding already enabled for $zone"
	else
		if zlogin $zone routeadm -ue ipv4-forwarding; then
			dbg "enabled IPv4 forwarding for $zone"
		else
			maybe_fail "failed to enable IPv4 forwarding for $zone"
			return 1
		fi
	fi

	if zlogin $zone routeadm -p ipv6-forwarding | \
			egrep 'current=enabled' > /dev/null
	then
		dbg "IPv6 forwarding already enabled for $zone"
	else
		if zlogin $zone routeadm -ue ipv6-forwarding; then
			dbg "enabled IPv6 forwarding for $zone"
		else
			maybe_fail "failed to enable IPv6 forwarding for $zone"
		fi
	fi
}

function ip_fwd_disable
{
	typeset zone=$1

	if (($# != 1)); then
		fail "$0: incorrect number of args provided"
	fi

	if zlogin $zone routeadm -p ipv4-forwarding | \
			egrep 'current=disabled' > /dev/null
	then
		dbg "IPv4 forwarding already disabled for $zone"
	else
		if zlogin $zone routeadm -ud ipv4-forwarding; then
			dbg "disabled IPv4 forwarding in $zone"
		else
			maybe_fail "failed to disable IPv4 forwarding in $zone"
			return 1
		fi
	fi

	if zlogin $zone routeadm -p ipv6-forwarding | \
			egrep 'current=disabled' > /dev/null
	then
		dbg "IPv6 forwarding already disabled for $zone"
	else
		if zlogin $zone routeadm -ud ipv6-forwarding; then
			dbg "disabled IPv6 forwarding in $zone"
		else
			maybe_fail "failed to disable IPv6 forwarding in $zone"
		fi
	fi
}

function add_route
{
	typeset zone=$1
	typeset dest=$2
	typeset net=$3
	typeset gateway=$4

	if (($# != 4)); then
		fail "$0: incorrect number of args provided"
	fi

	if zlogin $zone route -n add $net $gateway > /dev/null; then
		dbg "added route $gateway => $net to $zone"
		return 0
	fi

	maybe_fail "failed to add route $gateway => $net to $zone"
}

function add_route6
{
	typeset zone=$1
	typeset dest=$2
	typeset net=$3
	typeset gateway=$4

	if (($# != 4)); then
		fail "$0: incorrect number of args provided"
	fi

	if zlogin $zone route -n add -inet6 $net $gateway > /dev/null
	then
		dbg "added route $gateway => $net to $zone"
		return 0
	fi

	maybe_fail "failed to add route $gateway => $net to $zone"
}

function rm_route
{
	typeset zone=$1
	typeset dest=$2
	typeset net=$3
	typeset gateway=$4
	typeset gw=$(zlogin $zone route -n get $dest | \
			     grep gateway | awk '{ print $2 }')
	typeset err="failed to remove route $gateway => $net from $zone"

	if (($# != 4)); then
		fail "$0: incorrect number of args provided"
	fi

	if [[ "$gw" == "$gateway" ]]; then
		if zlogin $zone route -n delete $net $gateway > /dev/null
		then
			dbg "removed route $gateway => $net from $zone"
		else
			maybe_fail "$err"
		fi
	else
		dbg "$zone already lacked route $gateway => $net"
	fi
}

function rm_route6
{
	typeset zone=$1
	typeset dest=$2
	typeset net=$3
	typeset gateway=$4
	typeset gw=$(zlogin $zone route -n get -inet6 $dest | \
			     grep gateway | awk '{ print $2 }')
	typeset err="failed to remove route $gateway => $net from $zone"

	if (($# != 4)); then
		fail "$0: incorrect number of args provided"
	fi

	if [[ "$gw" == "$gateway" ]]; then
		if zlogin $zone route -n delete -inet6 $net $gateway > /dev/null
		then
			dbg "removed route $gateway => $net from $zone"
		else
			maybe_fail "$err"
		fi
	else
		dbg "$zone already lacked route $gateway => $net"
	fi
}

function set_linkprop
{
	typeset link=$1
	typeset prop=$2
	typeset val=$3
	typeset err="failed to set $link prop: $prop=$val"

	if (($# != 3)); then
		fail "$0: incorrect number of args provided"
	fi

	dbg "attempt to set $link prop: $prop=$val"
	if dladm set-linkprop -p $prop=$val $link; then
		dbg "set $link prop: $prop=$val"
		return 0
	fi

	maybe_fail "$err"
}

function ping
{
	typeset zone=$1
	typeset src=$2
	typeset dst=$3
	typeset info="$src -> $dst"

	if (($# != 3)); then
		fail "$0: incorrect number of args provided"
	fi

	dbg "ping: $info"
	if zlogin $zone ping $dst > /dev/null 2>&1; then
		dbg "successful ping: $info"
		return 0
	fi

	maybe_fail "could not ping: $info"
}

function ping_udp
{
	typeset client=$1
	typeset client_ip=$2
	typeset server_ip=$3
	typeset size=$4
	typeset num=$5
	typeset info="$client_ip -> $server_ip (size: $size)"

	if (($# != 5)); then
		fail "$0: incorrect number of args provided"
	fi

	dbg "UDP ping: $info"
	if zlogin $client ping -ns -U $server_ip $size $num > /dev/null; then
		dbg "UDP ping passed: $info"
		return 0
	fi

	maybe_fail "UDP ping failed: $info"
}

function start_server
{
	typeset zone=$1
	typeset type=$2
	typeset ip=$3
	typeset port=$4
	typeset ofile=$5

	if (($# != 5)); then
		fail "$0: incorrect number of args provided"
	fi

	dbg "start server $rfile"
	zlogin $zone \
	       /usr/bin/socat -u ${type}-LISTEN:$port,bind=[$ip],reuseaddr \
	       CREATE:$ofile &
	listener_ppid=$!
	dbg "listener PPID: $listener_ppid, zone $zone"
}

function wait_for_pid
{
	typeset pid=$1
	typeset seconds=$2
	typeset s=0

	if (($# != 2)); then
		fail "$0: incorrect number of args provided"
	fi

	while true; do
		if kill -0 $pid > /dev/null 2>&1; then
			if ((seconds == s)); then
				maybe_fail "timed out waiting for pid $pid"
				return 1
			fi
			dbg "waiting for pid $pid"
			sleep 1
			((s++))
		else
			return 0
		fi
	done
}
