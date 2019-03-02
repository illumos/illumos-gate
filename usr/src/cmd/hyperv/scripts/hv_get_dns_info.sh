#!/bin/sh
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
# Copyright (c) 2017 by Delphix. All rights reserved.
#

#
# This script parses /etc/resolv.conf and prints the address of the first
# nameserver. It is primarily used by the kvp daemon.
#

awk '/^nameserver/ { print $2; exit }' /etc/resolv.conf || exit 1
