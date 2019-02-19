#!/usr/bin/bash

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
# Copyright 2019 Joyent, Inc.
#

grep ufmtest /etc/name_to_major &>/dev/null
if [[ $? -eq 0 ]]; then
	printf "ufmtest driver is already installed\n"
	exit 0
fi

printf "Installing ufmtest driver ... \n"
/usr/sbin/add_drv -v -f ufmtest

if [[ $? -ne 0 ]]; then
	printf "%s\n%s\n" "Failed to install the ufmtest driver." \
	    "Verify that the IPS package system/io/tests is installed." 1>&2
	exit 1
else
	exit 0
fi

