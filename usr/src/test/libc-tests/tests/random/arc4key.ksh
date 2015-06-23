#!/usr/bin/ksh
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
# Copyright (c) 2015, Joyent, Inc. 
#

#
# The purpose of this test is to verify that we have actually gone
# through and called the rekey functions in the implementation of the
# arc4random code that we have. To do that, we look at the actual part
# of the code that does generation. In this case, the function
# arc4_rekey() which is a private function as part of libc.
#

set -o errexit

arc_pname=$(basename $0)
arc_root=$(dirname $0)/../..
arc_bin=$arc_root/tests/random/arc4random_rekey
arc_tmpfile=/tmp/$arc_pname.$$
arc_count=

rm -f $arc_tmpfile
dtrace -n 'pid$target::arc4_rekey:entry{ @ = count(); }' -c $arc_bin \
    -o $arc_tmpfile
arc_count=$(cat $arc_tmpfile)
[[ $arc_count -gt 1 ]]
