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
# Copyright 2019 Joyent, Inc.
#

#
# This test sprays many concurrent ACQUIRE messages and checks the
# monitor.
#
# Note that it's not run by default, as the monitor is best-efforts and
# therefore not reliable under this kind of load.
#

if [ `id -u` -ne 0 ]; then
	echo "Need to be root or have effective UID of root."
	exit 255
fi

if [[ `zonename` != "global" ]]; then
	echo "Need to be the in the global zone for lock detection."
	exit 254
fi

PREFIX=10.21.12.0/24
MONITOR_LOG=/var/tmp/ipseckey-monitor.$$

# The program that sends an extended REGISTER to enable extended ACQUIREs.
EACQ_PROG=/opt/os-tests/tests/pf_key/eacq-enabler

$EACQ_PROG &
eapid=$!

# Tunnels will be preserved by using -f instead of -F.
ipsecconf -qf

# Simple one-type-of-ESP setup...
echo "{ raddr $PREFIX } ipsec { encr_algs aes encr_auth_algs sha512 }" | \
	ipsecconf -qa -
# ipsecconf -ln

echo "Starting monitor, logging to $MONITOR_LOG"

# Get monitoring PF_KEY for at least regular ACQUIREs.
ipseckey -n monitor > $MONITOR_LOG &
IPSECKEY_PID=$!

# Flush out the SADB to make damned sure we don't have straggler acquire
# records internally.
ipseckey flush

# wait for the monitor
sleep 5

echo "Starting pings"

# Launch 254 pings to different addresses (each requiring an ACQUIRE).
i=1
while [ $i -le 254 ]; do
	truss -Topen -o /dev/null ping -svn 10.21.12.$i 1024 1 2>&1 > /dev/null &
	i=$(($i + 1))
done

# Unleash the pings in 10 seconds, Smithers.
( sleep 10 ; prun `pgrep ping` ) &

echo "Waiting for pings to finish"

# wait for the pings; not so charming
while :; do
	pids="$(pgrep ping)"
	[[ -n "$pids" ]] || break
	pwait $pids
done

# wait for the monitor
sleep 10

kill $IPSECKEY_PID
kill $eapid
# Use SMF to restore anything that may have been there.  "restart" on
# a disabled service is a NOP, but an enabled one will get
# /etc/inet/ipsecinit.conf reloaded.
svcadm restart ipsec/policy

# See if we have decent results.

i=1
while [ $i -le 254 ]; do
	c=$(grep -c "^DST: AF_INET: port 0, 10\.21\.12\.$i\." $MONITOR_LOG)
	if [[ "$c" -ne 2 ]]; then
		echo "One or more log entries missing for 10.21.12.$i" >&2
		exit 1
	fi
	i=$(($i + 1))
done

rm -f $MONITOR_LOG
exit 0
