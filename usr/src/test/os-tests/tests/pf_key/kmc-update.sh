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

#
# Two birds with one stone.
#
# 1.) Add some simple SAs.
# 2.) Run C programs that use SADB_UPDATE to alter the SAs' KM cookies.
#
# This tests both SADB_UPDATE of an SA's KM cookie, and the C programs can
# test (or not) cookie/cookie64 and the IKEv1 exception.
#

# Add two simple SAs.  Will delete them first, out of paranoia.

ipseckey 2>&1 >/dev/null <<EOF
delete ah spi 0x2112 dst 127.0.0.1
delete ah spi 0x5150 dst 127.0.0.1
add ah spi 0x2112 dst 127.0.0.1 authalg md5 authkey \
	1234567890abcdeffedcba0987654321
add ah spi 0x5150 dst 127.0.0.1 authalg md5 authkey \
	abcdef01234567890123456789abcdef
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

# Test a different one, using all 64-bits.
$TESTPATH/kmc-updater 0x5150 64
if [[ $? != 0 ]]; then
    echo "64-bit KMC test failed."
    exit 1
fi
echo "Passed 64-bit KMC test."

ipseckey delete ah spi 0x2112 dst 127.0.0.1
ipseckey delete ah spi 0x5150 dst 127.0.0.1

exit 0
