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

# we can't presume /usr/bin/timeout is there
timeout_cmd() {
    $* &
    sleep 3
    kill $!
    # we want to pause a while to make sure the monitor log is
    # updated...
    sleep 2
}

if [[ `id -u` -ne 0 ]]; then
    echo "Error: need to be root or have effective UID of root." >&2
    exit 255
fi

if [[ ! -x "$(type -p curl)" ]]; then
    echo "Error: curl binary not found." >&2
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

CURL_DST3_LPORT=10001
CURL_DST4_LPORT=10002
CURL_DST1_LPORT=10003
CURL_PORT=80

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
{ raddr $TEST_REMOTE_DST3 rport $CURL_PORT ulp tcp } ipsec { encr_algs aes encr_auth_algs sha512 }

# Unique policy...
{ raddr $TEST_REMOTE_DST4 rport $CURL_PORT ulp tcp } ipsec { encr_algs aes encr_auth_algs sha256 sa unique }

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

# give the monitor some time to get set up
sleep 3

# Launch pings to various addresses (each requiring an ACQUIRE).

timeout_cmd ping -svn $TEST_REMOTE_DST1 1024 1
timeout_cmd ping -svn $TEST_REMOTE_DST2 1024 1
timeout_cmd ping -svn $T1_DST 1024 1
timeout_cmd ping -svn $T2_DST 1024 1

# Now try some curls to trigger local port and unique policy.

# port-only for DST3
timeout_cmd curl --local-port $CURL_DST3_LPORT \
    http://$TEST_REMOTE_DST3:$CURL_PORT
# unique for DST4
timeout_cmd curl --local-port $CURL_DST4_LPORT \
    http://$TEST_REMOTE_DST4:$CURL_PORT
# Nothing specced for DST1
timeout_cmd curl --local-port $CURL_DST1_LPORT \
    http://$TEST_REMOTE_DST1:$CURL_PORT

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

# give the monitor some time to finish up
sleep 5

# Process MONITOR_LOG's output...
echo "Checking for unique local port only in one ACQUIRE case."
egrep "$CURL_DST3_LPORT|$CURL_DST4_LPORT|$CURL_DST1_LPORT" \
    $MONITOR_LOG > /tmp/egrep.$$
grep $CURL_DST4_LPORT $MONITOR_LOG > /tmp/grep.$$ || {
    echo "unique port $CURL_DST4_LPORT missing from monitor log."
    exit 1
}
diff /tmp/grep.$$ /tmp/egrep.$$
if [[ $? != 0 ]]; then
    echo "More than just the one unique port $CURL_DST4_LPORT found."
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
