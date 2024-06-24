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

# Reference output from: acl_totext -sn
ref="owner@:read_data/write_data/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/delete/read_acl/write_acl/write_owner/synchronize:file_inherit/dir_inherit:allow
group@:write_data/append_data/write_xattr/write_attributes:file_inherit/dir_inherit:allow
everyone@:write_data/append_data/write_xattr/write_attributes:allow
user:501:read_data/write_data/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/delete/read_acl/write_acl/write_owner/synchronize:file_inherit/dir_inherit:allow
group:502:write_data/append_data/write_xattr/write_attributes:file_inherit/dir_inherit:allow
usersid:S-1-5-21-1813420391-1960978090-3893453001-1001:read_data/write_data/append_data/read_xattr/write_xattr/execute/delete_child/read_attributes/write_attributes/delete/read_acl/write_acl/write_owner/synchronize:file_inherit/dir_inherit:allow
groupsid:S-1-5-21-1813420391-1960978090-3893453001-1002:write_data/append_data/write_xattr/write_attributes:file_inherit/dir_inherit:allow
groupsid:S-1-5-21-1813420391-1960978090-3893453001-1003:read_data/read_xattr/read_attributes/read_acl:file_inherit/dir_inherit:allow
groupsid:S-1-5-21-1813420391-1960978090-3893453002-2002:read_data/read_xattr/read_attributes/read_acl:file_inherit/dir_inherit:allow
groupsid:S-1-5-21-1813420391-1960978090-3893453003-3003:read_data/read_xattr/read_attributes/read_acl:file_inherit/dir_inherit:allow"

acl_fromtext "$ref" ||
{
    printf "TEST FAILED\n"
    exit 1
}
printf "TEST PASSED\n"
exit 0
