#!/bin/ksh -p
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
# Copyright (c) 2016 by Delphix. All rights reserved.
# Copyright 2024 MNX Cloud, Inc.
#

. $STF_SUITE/tests/functional/channel_program/channel_common.kshlib

verify_runnable "global"

#
# DESCRIPTION:
#	run C program which tests passing different nvlists to lua
#

log_assert "nvlist arguments can be passed to LUA."

log_must $ZCP_ROOT/lua_core/nvlist_to_lua.exe $TESTPOOL

log_pass "nvlist arguments can be passed to LUA."
