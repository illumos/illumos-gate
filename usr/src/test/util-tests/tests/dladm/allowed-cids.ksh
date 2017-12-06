#!/bin/ksh
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
# Copyright 2017 Joyent, Inc.
#

source ./common.ksh

property="allowed-dhcp-cids"

setup

# Valid hexadecimal strings
epass 0x1234
epass 0x123456789abcdef0
epass 0x123456789abcdef0

# Hex strings w/ an odd number of characters are not allowed
efail 0x0
efail 0x1
efail 0x1fa
efail 0xfba39e2

# Invalid hexadecimal strings
efail 0xz
efail 0x01234567q12
efail 0x=+
efail 0x-1
efail 0x1,2,3

# Valid RFC 3315 DUID strings

## DUID-LLT
epass 1.1.1234.90:b8:d0:81:91:30
epass 1.1.1512434853.90:b8:d0:81:91:30
epass 1.1.28530123.90:b8:d0:81:91:30
epass 1.6.1512434853.14:10:9f:d0:5b:d3

## DUID-EN
epass 2.9.0CC084D303000912
epass 2.9.0cc084d303000912
epass 2.32473.45ab
epass 2.38678.0123abcd

## DUID-LL
epass 3.1.90:b8:d0:81:91:30
epass 3.1.90:b8:d0:4b:c7:3b
epass 3.1.2:8:20:a4:4d:ee
epass 3.6.14:10:9f:d0:5b:d3

# Invalid RFC 3315 DUID strings

## DUID-LLT
efail 1.1.12a34.90:b8:d0:81:91:30
efail 1.1.15-33.90:b8:d0:81:91:30
efail 1.1.98+123.90:b8:d0:81:91:30
efail 3.z.1512434853.14:10:9f:d0:5b:d3
efail 3.6.1512434853.q4:10:9f:d0:5b:d3

## DUID-EN
efail 2.32473.45a
efail 2.9.Z
efail 2.9.-12
efail 2.QZ4.45a
efail 2.38d78.0123abcd

## DUID-LL
efail 3.wy.90:b8:d0:81:91:30
efail 3.1.90:z8:di:ob:c7:3b
efail 3.1.5.2:8:20:a4:4d:ee

## Uknown DUID forms
efail 4.1.45a
efail 9.1.45a
efail 23.1.45a

# Random strings of bytes are also accepted,
# if they don't have the above prefixes.
epass 1234
epass abcdef
epass qsxasdasdfgfdgkj123455
epass 0x

cleanup
printf "TEST PASS: $ai_arg0\n"
