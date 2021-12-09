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

#
# Sanity check parts of bitfields.
#

set -o pipefail

tst_root="$(dirname $0)/.."
tst_prog="$tst_root/progs/bitfields"
tst_outfile="/tmp/mdb.bitfield.out.$$"
tst_exp="$0.out"

$MDB -e "first::print -t broken_t" $tst_prog > $ODIR/stdout
$MDB -e "second::print -t broken6491_t" $tst_prog >> $ODIR/stdout
