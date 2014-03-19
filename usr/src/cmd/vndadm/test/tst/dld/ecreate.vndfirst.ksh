#
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
# Copyright (c) 2014 Joyent, Inc.  All rights reserved.
#

#
# Make sure IP fails to come up when vnd is up
#

. ./dld.common.ksh

dld_nic=$1
[[ -z "$1" ]] && fatal "missing required vnic"

vndadm create $dld_nic || fatal "failed to bring up vnd"
ifconfig $dld_nic plumb up
