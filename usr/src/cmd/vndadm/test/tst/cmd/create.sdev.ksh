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
# Copyright (c) 2014 Joyent, Inc.  All rights reserved.
#

#
# Verify that our sdev links exist
#

. ./cmd.common.ksh

vndadm create $1 || fatal "failed to bring up vnd"
[[ -c /dev/vnd/$1 ]] || fatal "missing link"
[[ -c /dev/vnd/zone/$(zonename)/$1 ]] || fatal "missing per-zone link"
