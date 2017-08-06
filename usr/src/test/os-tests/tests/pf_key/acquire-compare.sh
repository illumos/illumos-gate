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

# NOTE: If multihomed, this may fail in interesting ways...
MY_IP=`netstat -in -f inet | egrep -v "Name|lo0" | awk '{print $4}' | head -1`
TEST_REMOTE_DST1=10.90.1.25
TEST_REMOTE_DST2=10.19.84.2
TEST_REMOTE_DST3=10.19.84.3
TEST_REMOTE_DST4=10.19.84.4

T1_SRC=10.21.12.4
T1_DST=10.21.12.5
T1_PREFIX=10.21.12.0/24
T2_SRC=10.51.50.4
T2_DST=10.51.50.5
T2_PREFIX=10.51.50.0/24

MONITOR_LOG=/tmp/ipseckey-monitor.$$

EACQ_PROG=/opt/os-tests/tests/pf_key/eacq-enabler

$EACQ_PROG &
eapid=$!

echo "Warning, this trashes IPsec policy."
ipsecconf -Fq

# Setup the IPsec policy...
ipsecconf -qa - << EOF
# Global policy...
# Remote-port-based policy.  Use different algorithms...
{ raddr $TEST_REMOTE_DST3 rport 23 ulp tcp } ipsec { encr_algs aes encr_auth_algs sha512 }

# Unique policy...
{ raddr $TEST_REMOTE_DST4 rport 23 ulp tcp } ipsec { encr_algs aes encr_auth_algs sha256 sa unique }

# Simple IP address policy.  Use an AH + ESP for it.
{ raddr $TEST_REMOTE_DST1 } ipsec { auth_algs sha512 encr_algs aes(256) }
{ raddr $TEST_REMOTE_DST2 } ipsec { auth_algs sha384 encr_algs aes(256) }

# Tunnel policy...
{ tunnel rush0 raddr $T1_PREFIX negotiate tunnel } ipsec { encr_algs aes-gcm(256) }
# NULL-encryption...
{ tunnel vh0 raddr $T2_PREFIX negotiate tunnel } ipsec {encr_auth_algs hmac-sha384 }
EOF

# Plumb the tunnels
dladm create-iptun -t -T ipv4 -a local=$MY_IP -a remote=$TEST_REMOTE_DST1 rush0
dladm create-iptun -t -T ipv4 -a local=$MY_IP -a remote=$TEST_REMOTE_DST2 vh0
ipadm create-addr -t -T static -a local=$T1_SRC,remote=$T1_DST rush0/v4
ipadm create-addr -t -T static -a local=$T2_SRC,remote=$T2_DST vh0/v4
route add $T1_PREFIX $T1_DST
route add $T2_PREFIX $T2_DST

ipseckey flush
ipseckey -np monitor > $MONITOR_LOG &
IPSECKEY_PID=$!

# Launch pings and telnets to different addresses (each requiring an ACQUIRE).
ping -svn $TEST_REMOTE_DST1 1024 1 2>&1 > /dev/null &
p1=$!
ping -svn $TEST_REMOTE_DST2 1024 1 2>&1 > /dev/null &
p2=$!
ping -svn $T1_DST 1024 1 2>&1 > /dev/null &
p3=$!
ping -svn $T2_DST 1024 1 2>&1 > /dev/null &
p4=$!

echo "Waiting for pings..."
pwait $p1 $p2 $p3 $p4

# Now try some telnets to trigger port and unique policy.
# port-only for DST3
telnet $TEST_REMOTE_DST3 &
tpid=$!
t1port=`pfiles $tpid | grep sockname | awk '{print $5}'`
echo "First local port == $t1port"
sleep 10 ; kill $tpid
# unique for DST4
telnet $TEST_REMOTE_DST4 &
tpid=$!
t2port=`pfiles $tpid | grep sockname | awk '{print $5}'`
echo "Second local port == $t2port"
sleep 10 ; kill $tpid
# Nothing specced for DST1
telnet $TEST_REMOTE_DST1 &
tpid=$!
t3port=`pfiles $tpid | grep sockname | awk '{print $5}'`
echo "Third local port == $t3port"
sleep 10 ; kill $tpid

# Clean up.
kill $IPSECKEY_PID
kill $eapid
# Unplumb the tunnels
route delete $T2_PREFIX $T2_DST
route delete $T1_PREFIX $T1_DST
ipadm delete-addr vh0/v4
ipadm delete-addr rush0/v4
ipadm delete-if vh0
ipadm delete-if rush0
dladm delete-iptun vh0
dladm delete-iptun rush0
# Flush policy
ipsecconf -Fq
# Use SMF to restore anything that may have been there.  "restart" on
# a disabled service is a NOP, but an enabled one will get
# /etc/inet/ipsecinit.conf reloaded.
svcadm restart ipsec/policy

# Process MONITOR_LOG's output...
echo "Checking for unique local port only in one ACQUIRE case."
egrep "$t1port|$t2port|$t3port" $MONITOR_LOG > /tmp/egrep.$$
grep $t2port $MONITOR_LOG > /tmp/grep.$$
diff /tmp/grep.$$ /tmp/egrep.$$
if [[ $? != 0 ]]; then
    echo "More than just the one unique port, $tport2, found in monitor output."
    /bin/rm -f /tmp/grep.$$ /tmp/egrep.$$ $MONITOR_LOG
    exit 1
fi

# Split out extended (file.0) and regular (file.1) ACQUIREs.
# NOTE: "+7" is dependent on "ipseckey monitor"'s first output where it gets
# the "PROMISC" reply.

mkdir /tmp/raw.$$
savedir=$PWD
cd /tmp/raw.$$
tail +7 $MONITOR_LOG | \
    awk 'BEGIN { out=0; } /Read/ {out++;} { print >> (out % 2) }'
cd $savedir

# Pluck out the address extension from the two ACQUIRE types.
# NOTE: Add any new in-ACQUIRE address types here if more arrive.
egrep "DST:|SRC:|INS:|IND:" /tmp/raw.$$/0 > /tmp/extended-addresses.$$
egrep "DST:|SRC:|INS:|IND:" /tmp/raw.$$/1 > /tmp/regular-addresses.$$

# There should be NO differences between address fields from regular vs.
# extended ACQUIREs. If there are, it's a bug (or an older version of illumos).
diff /tmp/extended-addresses.$$ /tmp/regular-addresses.$$
if [[ $? != 0 ]]; then
    echo "Address fields in ACQUIRE differ."
    rc=1
else
    rc=0
fi

/bin/rm -rf /tmp/*-addresses.$$ /tmp/raw.$$
/bin/rm -f /tmp/grep.$$ /tmp/egrep.$$ /tmp/addrs.$$ $MONITOR_LOG

exit $rc
