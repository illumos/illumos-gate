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

property="dynamic-methods"

setup

# All valid values on their own
epass slaac
epass dhcpv4
epass dhcpv6
epass addrconf

# Combinations of values
epass slaac,dhcpv4
epass slaac,dhcpv6
epass dhcpv4,dhcpv6
epass dhcpv4,addrconf
epass dhcpv4,dhcpv6,slaac

# Illegal values
efail dhcpv8
efail slaac,dhcpv8
efail slack
efail ipv6
efail dhcp
efail dhcpv

cleanup
printf "TEST PASS: $ai_arg0\n"
