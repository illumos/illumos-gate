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
# This script retrieves the DHCP state of a given interface. It is primarily
# used by the kvp daemon. It takes the name of the interface as input, and
# outputs either "Enabled" or "Disabled" to stdout depeneding on whether that
# interface has a DHCP address.
#

if [[ -n $1 ]]; then
	intf=$1
else
	intf=hv_netvsc0
fi

ipadm show-addr -p -o type $intf/ 2>/dev/null | grep dhcp >/dev/null
if [[ $? -eq 0 ]]; then
	echo "Enabled"
else
	echo "Disabled"
fi
