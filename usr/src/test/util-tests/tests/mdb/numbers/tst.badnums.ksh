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
# Copyright 2021 Oxide Computer Company
#

ERR=0

function bad_num
{
	if $MDB -e $*; then
		print -u2 "TEST FAILED: $*"
		ERR=1
	else
		print "TEST PASSED: $*"
	fi
}

bad_num "0x_123=E"
bad_num "0xzasdf=K"
bad_num "0x1__p=K"
bad_num "0i_=K"
bad_num "0i__011=K"
bad_num "0i12345=K"
bad_num "0i0____3=K"
bad_num "0t34___asdf=K"
bad_num "0t_4=K"
bad_num "0tp=K"
bad_num "0tp__4=K"
bad_num "0t4______p=K"
bad_num "0o89=K"
bad_num "0o7____89=K"
bad_num "0o__324=K"
bad_num "0x123456789abcdef123456789abcdef=K"
bad_num "0x12___345678___9abcdef123456789_a_bcdef=K"

exit $ERR
