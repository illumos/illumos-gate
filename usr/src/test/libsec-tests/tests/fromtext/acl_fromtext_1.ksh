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
# Copyright 2024 RackTop Systems, Inc.
#

scriptdir=$(dirname $0)
. $scriptdir/../acltext_common

# Reference output from: acl_totext -c
ref="owner@:rwxpdDaARWcCos:fd-----:allow
group@:-w-p---A-W----:fd-----:allow
everyone@:-w-p---A-W----:-------:allow
user:user501:rwxpdDaARWcCos:fd-----:allow
group:group502:-w-p---A-W----:fd-----:allow
user:user1001@test-domain-name:rwxpdDaARWcCos:fd-----:allow
group:group1002@test-domain-name:-w-p---A-W----:fd-----:allow
group:2147483651:r-----a-R-c---:fd-----:allow
group:group2002@test-domain-name-somewhat-longer:r-----a-R-c---:fd-----:allow
group:2147483653:r-----a-R-c---:fd-----:allow"

acl_fromtext "$ref" ||
{
    printf "TEST FAILED\n"
    exit 1
}
printf "TEST PASSED\n"
exit 0
