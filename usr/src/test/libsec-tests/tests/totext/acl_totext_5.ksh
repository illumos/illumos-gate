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

ref="owner@:rwxpdDaARWcCos:fd-----:allow
group@:-w-p---A-W----:fd-----:allow
everyone@:-w-p---A-W----:-------:allow
user:user501:rwxpdDaARWcCos:fd-----:allow
group:group502:-w-p---A-W----:fd-----:allow
usersid:user1001@test-domain-name:rwxpdDaARWcCos:fd-----:allow
groupsid:group1002@test-domain-name:-w-p---A-W----:fd-----:allow
groupsid:group1003-name-really-crazy-long-long-long-long-long-long-long-long-long@test-domain-name:r-----a-R-c---:fd-----:allow
groupsid:group2002@test-domain-name-somewhat-longer:r-----a-R-c---:fd-----:allow
groupsid:group3003@test-domain-name-really-crazy-long-long-long-long-long-long-long-long-long:r-----a-R-c---:fd-----:allow"

out="$(acl_totext -sc)"
if [ "$out" != "$ref" ] ; then
    printf "TEST FAILED: incorrect output ($out)\n"
    exit 1
fi
printf "TEST PASSED\n"
exit 0
