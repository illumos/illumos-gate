#!/usr/bin/ksh
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
# Copyright (c) 2019, Joyent, Inc.
#

unalias -a

check_env()
{
	if which "$1" 2>/dev/null >/dev/null; then
		return
	fi

	[[ -f "$1" ]] || {
		echo "failed to find $1" >&2
		exit 1
	}
}

check_env as
check_env ctfconvert
check_env ctfmerge
check_env elfdump
check_env gcc
check_env g++
check_env ld
check_env make
