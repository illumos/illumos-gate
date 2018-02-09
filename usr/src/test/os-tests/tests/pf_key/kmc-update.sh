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
# Copyright (c) 2018, Joyent, Inc.
#

if [[ `id -u` -ne 0 ]]; then
	echo "Need to be root or have effective UID of root."
	exit 255
fi

#
# Two birds with one stone.
#
# 1.) Add some simple SAs.
# 2.) Run C programs that use SADB_UPDATE to alter the SAs' KM cookies.
#
# This tests both SADB_UPDATE of an SA's KM cookie, and the C programs can
# test (or not) cookie/cookie64 and the IKEv1 exception.
#

SADB_X_KMP_KINK=2
SADB_X_KMP_IKEV2=3
COOKIE_IKEV2="0x111770171170"
EINVAL=22

# Add three simple SAs.  Will delete them first, out of paranoia.

ipseckey 2>&1 >/dev/null <<EOF
delete ah spi 0x2112 dst 127.0.0.1
delete ah spi 0x5150 dst 127.0.0.1
delete ah spi 0x6768 dst 127.0.0.1
add ah spi 0x2112 dst 127.0.0.1 authalg md5 authkey \
	1234567890abcdeffedcba0987654321
add ah spi 0x5150 dst 127.0.0.1 authalg md5 authkey \
	abcdef01234567890123456789abcdef
add ah spi 0x6768 dst 127.0.0.1 authalg md5 authkey \
	fedcbafedcba01234567890123456789
EOF

# Run programs to see if UPDATE on their KM cookies works.  Both test
# programs take an SPI value, and assume dst=127.0.0.1.

TESTPATH=/opt/os-tests/tests/pf_key

# Test IKEv1, including masking of the reserved 32-bits.
$TESTPATH/kmc-updater 0x2112
if [[ $? != 0 ]]; then
    echo "IKEv1 32-bit KMC test failed."
    exit 1
fi
echo "Passed IKEv1 32-bit KMC test."

# Test that once set, an IKEv1 KMC cannot be changed
$TESTPATH/kmc-updater -e $EINVAL -k 0x12345 0x2112
if [[ $? != 0 ]]; then
    echo "IKEv1 32-bit KMC update test failed."
    exit 1
fi
echo "Passed IKEv1 32-bit KMC update test."

# Test that IKEv1 KMCs once set, cannot be changed to a different type
$TESTPATH/kmc-updater -e $EINVAL -p $SADB_X_KMP_IKEV2 0x2112
if [[ $? != 0 ]]; then
    echo "IKEv1 32-bit KMC protocol update test failed."
    exit 1
fi
echo "Passed IKEv1 32-bit KMC protocol update test."

# Test a different one, using all 64-bits.
$TESTPATH/kmc-updater 0x5150 64
if [[ $? != 0 ]]; then
    echo "64-bit KMC test failed."
    exit 1
fi
echo "Passed 64-bit KMC test."

# Test that non IKEv2 64-bit KMCs also cannot be changed once set
$TESTPATH/kmc-updater -e $EINVAL -k "0x12345678abcdef" 0x5150 64
if [[ $? != 0 ]]; then
    echo "64-bit KMC update test failed."
    exit 1
fi
echo "Passed 64-bit KMC update test."

# Test that non-IKEv2 KMCs cannot be changed to a different type
$TESTPATH/kmc-updater -e $EINVAL -p $SADB_X_KMP_IKEV2 0x5150 64
if [[ $? != 0 ]]; then
    echo "64-bit non-IKEv2 KMC protocol update test failed."
    exit 1
fi
echo "Passed 64-bit non-IKEv2 KMC protocol update test."

# Test allowing the update of IKEv2 KMCs
$TESTPATH/kmc-updater -p $SADB_X_KMP_IKEV2 0x6768 64
if [[ $? != 0 ]]; then
    echo "Failed to set KMC for IKEV2 test."
    exit 1
fi
$TESTPATH/kmc-updater -p $SADB_X_KMP_IKEV2 -k "$COOKIE_IKEV2" 0x6768 64
if [[ $? != 0 ]]; then
    echo "Failed to update IKEv2 KMC."
    exit 1
fi
echo "Passed IKEv2 KMC test."

# Test that IKEv2 KMCs cannot be changed to a different type
$TESTPATH/kmc-updater -e $EINVAL -p $SADB_X_KMP_KINK -k "$COOKIE_IKEV2" \
    0x6768 64
if [[ $? != 0 ]]; then
    echo "64-bit IKEv2 KMC protocol update test failed."
    exit 1
fi
echo "Passed 64-bit IKEv2 KMC protocol update test."

# Test that IKEv2 KMCs cannot be changed to a different type even w/ new KMC
$TESTPATH/kmc-updater -e $EINVAL -p $SADB_X_KMP_KINK 0x6768 64
if [[ $? != 0 ]]; then
    echo "64-bit IKEv2 KMC protocol + KMC update test failed."
    exit 1
fi
echo "Passed 64-bit IKEv2 KMC protocol + KMC update test."

ipseckey delete ah spi 0x2112 dst 127.0.0.1
ipseckey delete ah spi 0x5150 dst 127.0.0.1
ipseckey delete ah spi 0x6768 dst 127.0.0.1

exit 0
