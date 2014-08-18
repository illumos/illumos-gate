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
# Basic device listing
#

. ./cmd.common.ksh

#
# Use what we hope is a relatively unique name
#
cl_name="triforceofcourage0"
vndadm create -l $1 $cl_name || fatal "failed to create vnd device"
vndadm list -p -o name,zone $cl_name
vndadm list -p -d: -o zone,name $cl_name
vndadm destroy $cl_name || fatal "failed to destroy vnd device"
