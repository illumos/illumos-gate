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

ref="owner@:read_data/write_data/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/delete/read_acl/write_acl/write_owner/synchronize:file_inherit/dir_inherit:allow
group@:write_data/append_data/write_xattr/write_attributes:file_inherit/dir_inherit:allow
everyone@:write_data/append_data/write_xattr/write_attributes:allow
user:user501:read_data/write_data/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/delete/read_acl/write_acl/write_owner/synchronize:file_inherit/dir_inherit:allow
group:group502:write_data/append_data/write_xattr/write_attributes:file_inherit/dir_inherit:allow
usersid:user1001@test-domain-name:read_data/write_data/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/delete/read_acl/write_acl/write_owner/synchronize:file_inherit/dir_inherit:allow
groupsid:group1002@test-domain-name:write_data/append_data/write_xattr/write_attributes:file_inherit/dir_inherit:allow
groupsid:group1003-name-really-crazy-long-long-long-long-long-long-long-long-long@test-domain-name:read_data/read_xattr/read_attributes/read_acl:file_inherit/dir_inherit:allow
groupsid:group2002@test-domain-name-somewhat-longer:read_data/read_xattr/read_attributes/read_acl:file_inherit/dir_inherit:allow
groupsid:group3003@test-domain-name-really-crazy-long-long-long-long-long-long-long-long-long:read_data/read_xattr/read_attributes/read_acl:file_inherit/dir_inherit:allow"

out="$(acl_totext -s)"
if [ "$out" != "$ref" ] ; then
    printf "TEST FAILED: incorrect output ($out)\n"
    exit 1
fi
printf "TEST PASSED\n"
exit 0
