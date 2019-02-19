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

grep ufmtest /etc/name_to_major &> /dev/null
if [[ $? -eq 1 ]]; then
	printf "ufmtest driver is not currently installed\n"
	exit 0
fi

printf "Removing ufmtest driver ...\n"
/usr/sbin/rem_drv ufmtest
if [[ $? -ne 0 ]]; then
	printf "Failed to remove the ufmtest driver.\n" 1>&2
	exit 1
else
	exit 0
fi

