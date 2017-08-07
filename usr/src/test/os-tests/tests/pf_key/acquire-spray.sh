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
# Copyright (c) 2017 Joyent, Inc.
#

if [ `id -u` -ne 0 ]; then
	echo "Need to be root or have effective UID of root."
	exit 255
fi

if [[ `zonename` != "global" ]]; then
	echo "Need to be the in the global zone for lock detection."
	exit 254
fi

# This test sprays many concurrent ACQUIRE messages.  The idea originally
# was to view lock contention on the global netstack's IPsec algorithm lock.
# It is also useful for having multiple ACQUIRE records.

PREFIX=10.21.12.0/24
MONITOR_LOG=/var/run/ipseckey-monitor.$$

# The program that sends an extended REGISTER to enable extended ACQUIREs.
EACQ_PROG=/opt/os-tests/tests/pf_key/eacq-enabler

$EACQ_PROG &
eapid=$!

# Find the ipsec_alg_lock to monitor with lockstat (below).
GLOBAL_NETSTACK=`echo ::netstack | mdb -k | grep -w 0 | awk '{print $1}'`
GLOBAL_IPSEC=`echo $GLOBAL_NETSTACK::print netstack_t | mdb -k | grep -w nu_ipsec | awk '{print $3}'`
IPSEC_ALG_LOCK=`echo $GLOBAL_IPSEC::print -a ipsec_stack_t ipsec_alg_lock | mdb -k | head -1 | awk '{print $1}'`

#echo "WARNING -- this test flushes out IPsec policy..."
#echo "GLOBAL_NETSTACK = $GLOBAL_NETSTACK"
#echo "GLOBAL_IPSEC = $GLOBAL_IPSEC"
#echo "IPSEC_ALG_LOCK = $IPSEC_ALG_LOCK"

# Tunnels will be preserved by using -f instead of -F.
ipsecconf -qf

# Simple one-type-of-ESP setup...
echo "{ raddr $PREFIX } ipsec { encr_algs aes encr_auth_algs sha512 }" | \
	ipsecconf -qa -
# ipsecconf -ln

# Get monitoring PF_KEY for at least regular ACQUIREs.
ipseckey -n monitor > $MONITOR_LOG &
IPSECKEY_PID=$!

# Flush out the SADB to make damned sure we don't have straggler acquire
# records internally.
ipseckey flush

# Launch 254 pings to different addresses (each requiring an ACQUIRE).
i=1
while [ $i -le 254 ]; do
	truss -Topen -o /dev/null ping -svn 10.21.12.$i 1024 1 2>&1 > /dev/null &
	i=$(($i + 1))
done

# Unleash the pings in 10 seconds, Smithers.
( sleep 10 ; prun `pgrep ping` ) &

# Get the lockstats going now.
echo "Running:     lockstat -A -l 0x$IPSEC_ALG_LOCK,8 sleep 30"
lockstat -A -l 0x$IPSEC_ALG_LOCK,8 sleep 30
kill $IPSECKEY_PID
kill $eapid
# Use SMF to restore anything that may have been there.  "restart" on
# a disabled service is a NOP, but an enabled one will get
# /etc/inet/ipsecinit.conf reloaded.
svcadm restart ipsec/policy

# See if we have decent results.

numacq=`grep ACQUIRE $MONITOR_LOG | wc -l | awk '{print $1}`
#rm -f $MONITOR_LOG
# Pardon the hardcoding again.
if [[ $numacq != 508 ]]; then
    echo "Got $numacq ACQUIREs instead of 508"
    exit 1
else
    echo "Saw expected $numacq ACQUIREs."
fi

exit 0
