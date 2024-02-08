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
# Copyright 2024 Oxide Computer Company
#

# This tests the behaviour of in.ndpd in conjunction with the creation and
# deletion of IPv6 link local addresses in various combinations. It does this
# using a VNIC on a simnet created just for the purpose. No special system
# configuration is required, but the tests will restart the running in.ndpd
# several times.

SIMNET=ndpt_simnet0
IF=ndpt_vnic0

typeset -i comms=1
typeset -i failures=0
typeset -i zid=0

function fatal {
	print "$*" >&2
	exit 1
}

function cleanup {
	{
		dladm delete-vnic $IF
		dladm delete-simnet $SIMNET
	} >/dev/null 2>&1
}

trap cleanup EXIT

function init {
	zid=$(zoneadm list -p | awk -F: -vz=`zonename` '$2 == z { print $1 }')
	[[ -n "$zid" ]] || fatal "Cannot determine zone ID"
	print "+ zone ID $zid"
	print "+ creating simnet $SIMNET"
	dladm create-simnet "$SIMNET" || \
	    fatal "Could not create simnet $SIMNET"
	print "+ creating VNIC $IF"
	dladm create-vnic -l $SIMNET "$IF" || \
	    fatal "Could not create vnic $IF"
}

function ndpid {
	pgrep -x -z$zid in.ndpd || fatal "Could not find in.ndpd process"
}

function start {
	print
	print "************** $*"
	print
}

function clean {
	/usr/sbin/ipadm delete-if "$IF" 1>/dev/null 2>&1
	restart_ndp

	ifconfig "$IF" inet6 1>/dev/null 2>&1 && \
	    fatal "$IF IPv6 interface exists"
	mdb -p `ndpid` -e \
	    'phyints::list struct phyint pi_next|::print struct phyint pi_name'\
	    | egrep -s "$IF" && fatal "$IF exists in ndpd state after restart"

	# Check that in.ndpd is running
	ndpid >/dev/null
}

function ndpdump {
	typeset cmd=
	cmd+='phyints::list struct phyint pi_next '
	cmd+='| ::print struct phyint '
	cmd+='pi_name pi_ifaddr pi_autoconf pi_ipadm_aobjname'
	mdb -e "$cmd" -p `ndpid` | sed -n "
		/pi_name.*$IF/,/aobjname/ {
			/name = /s/, '\\0'.*/.../
			s/^/    /
			p
		}
	"
}

function ndpac {
	typeset cmd=
	cmd+='phyints::list struct phyint pi_next '
	cmd+='| ::printf "%s %s\n" struct phyint pi_name pi_autoconf'
	mdb -p `ndpid` -e "$cmd" | awk "/$IF/ {print \$NF}"
}

function check_ac {
	((comms)) || return

	typeset ac=`ndpac`

	[[ "$ac" == "$1" ]] && return
	[[ -z "$ac" ]] && ac="<entry missing>"
	print "FAIL: Expected autoconf $1, got $ac"
	ndpdump >&2
	((failures++))
}

function ipadm {
	print "+ ipadm $*"
	if ! /sbin/ipadm $*; then
		print "FAIL: ipadm command unexpectedly failed"
		((failures++))
	fi
}

function restart_ndp {
	disable_ndp
	enable_ndp
}

function disable_ndp {
	comms=0
	svcadm disable -s ndp
}

function enable_ndp {
	comms=1
	svcadm enable -s ndp
}

function create_if {
	ipadm create-if $IF
	check_ac B_FALSE
}

function delete_if {
	ipadm delete-if $IF
	check_ac B_TRUE
}

function create_addr {
	ipadm create-addr -T addrconf $IF/ll
	check_ac B_TRUE
}

function delete_addr {
	ipadm delete-addr $IF/ll
	check_ac B_FALSE
}

init

start "create-if, delete-if, repeat"
clean
for _ in {0..3}; do
	create_if
	delete_if
done

start "create/delete-addr with plumbed interface"
clean
create_if
create_addr
delete_addr
delete_if

start "create/delete_addr without plumbed interface"
clean
create_addr
delete_addr
delete_if

start "create_addr, delete-addr, repeat"
clean
for _ in {0..3}; do
	create_addr
	delete_addr
done

start "create_addr, delete-if, create-if, create-addr"
clean
create_addr
delete_if
create_if
create_addr

start "run without ndp"
clean
disable_ndp
create_addr
delete_addr
delete_if

start "start without ndp, enable after create-if"
clean
disable_ndp
create_if
enable_ndp
create_addr
delete_addr
delete_if
enable_ndp

start "start without ndp, enable after create-addr"
clean
disable_ndp
create_if
create_addr
enable_ndp
delete_addr
delete_if

start "start without ndp, enable after delete-addr"
clean
disable_ndp
create_addr
delete_addr
enable_ndp
delete_if

start "restart ndp after create-if"
clean
create_if
restart_ndp
create_addr
delete_addr
delete_if

start "restart ndp after create-addr"
clean
create_if
create_addr
restart_ndp
delete_addr
delete_if

print
if ((FAILURES)); then
	print "$FAILURES failure(s) detected"
	exit 1
fi
print "All tests passed"
exit 0
