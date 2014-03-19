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
# Set and validate the buffer size properties. Valiate that we can set
# the value using the various number analogues, eg. 1024K, etc.
#
set -o pipefail

. ./cmd.common.ksh

vndadm create $1 || fatal "failed to bring up vnd device"
vndadm set $1 rxbuf=1M
cur=$(vndadm get -p $1 rxbuf | nawk '{ print $4 }')
[[ $? -eq 0 ]] || fatal "failed to get rxbuf"
[[ $cur -eq 1048576 ]] || fatal "rxbuf is $cur, not 1M"

vndadm set $1 txbuf=1024K
cur=$(vndadm get -p $1 rxbuf | nawk '{ print $4 }')
[[ $? -eq 0 ]] || fatal "failed to get txbuf"
[[ $cur -eq 1048576 ]] || fatal "txbuf is $cur, not 1M"
