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
#

verify_runnable "global"

. $STF_SUITE/tests/functional/channel_program/channel_common.kshlib

#
# DESCRIPTION:
#       Passing the instruction limit option to channel programs should work
#       correctly. Programs that exceed these instruction limits should fail
#       gracefully.
#

verify_runnable "both"

log_assert "Timeouts work correctly."

log_mustnot_checkerror_program "Channel program timed out" \
    $TESTPOOL $ZCP_ROOT/lua_core/tst.timeout.zcp

function test_instr_limit
{
	typeset lim=$1
	instrs_run=$(dtrace -q \
	    -n 'zfs_ioc_channel_program:entry{x=0}' \
	    -n 'zfs_ioc_channel_program:return{printf("%d", x)}' \
	    -n 'zcp_lua_counthook:entry{x+=100}' \
	    -c "zfs program -t $lim $TESTPOOL $ZCP_ROOT/lua_core/tst.timeout.zcp")
	if [[ $instrs_run -lt $(( $lim - 100 )) ]]; then
		log_fail "Runtime (${instrs_run} instr) < limit (${lim} - 100 instr)"
	elif [[ $instrs_run -gt $(( $lim + 100 )) ]]; then
		log_fail "Runtime (${instrs_run} instr) > limit (${lim} + 100 instr)"
	fi
}

test_instr_limit 1000
test_instr_limit 10000
test_instr_limit 100000
test_instr_limit 1000000
test_instr_limit 2000000

log_pass "Timeouts work correctly."
