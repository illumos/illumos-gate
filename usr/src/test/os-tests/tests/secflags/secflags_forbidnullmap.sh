#! /usr/bin/ksh
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

# Copyright 2015, Richard Lowe.

/usr/bin/psecflags -s forbidnullmap $$

LD_PRELOAD=0@0.so.1 /usr/bin/sleep 100000 &
pid=$!

ret=0
(pmap $pid | grep -q '^00000000 ') && ret=1
kill -9 $pid

exit $ret
