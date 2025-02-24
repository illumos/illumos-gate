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
# Copyright 2025 Oxide Computer Company
#

#
# Sanity check parts of bitfields.
#

set -o pipefail

tst_root="$(dirname $0)/.."
tst_prog="$tst_root/progs/bitfields"

#
# Top level ::print
#
$MDB -e "first::print -t broken_t" $tst_prog > $ODIR/stdout
$MDB -e "second::print -t broken6461_t" $tst_prog >> $ODIR/stdout

#
# ::print of specific members
#
$MDB -e "first::print broken_t brk_a" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_b" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_c" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_d" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_e" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_f" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_g" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_h" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_i" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_j" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_k" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_l" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_m" $tst_prog >> $ODIR/stdout
$MDB -e "second::print broken6461_t a" $tst_prog >> $ODIR/stdout
$MDB -e "second::print broken6461_t b" $tst_prog >> $ODIR/stdout
$MDB -e "second::print broken6461_t c" $tst_prog >> $ODIR/stdout
$MDB -e "second::print broken6461_t d" $tst_prog >> $ODIR/stdout
$MDB -e "second::print broken6461_t e" $tst_prog >> $ODIR/stdout
$MDB -e "second::print broken6461_t f" $tst_prog >> $ODIR/stdout

#
# ::printf of members. Note, if ::printf said '%x\n' below then we would
# include the string "\n" (not a newline) in the output. Instead we rely
# upon the implicit newline from mdb -e.
#
$MDB -e "first::printf '%x' broken_t brk_a" $tst_prog >> $ODIR/stdout
$MDB -e "first::printf '%x' broken_t brk_b" $tst_prog >> $ODIR/stdout
$MDB -e "first::printf '%x' broken_t brk_c" $tst_prog >> $ODIR/stdout
$MDB -e "first::printf '%x' broken_t brk_d" $tst_prog >> $ODIR/stdout
$MDB -e "first::printf '%x' broken_t brk_e" $tst_prog >> $ODIR/stdout
$MDB -e "first::printf '%x' broken_t brk_f" $tst_prog >> $ODIR/stdout
$MDB -e "first::printf '%x' broken_t brk_g" $tst_prog >> $ODIR/stdout
$MDB -e "first::printf '%x' broken_t brk_h" $tst_prog >> $ODIR/stdout
$MDB -e "first::printf '%x' broken_t brk_i" $tst_prog >> $ODIR/stdout
$MDB -e "first::printf '%x' broken_t brk_j" $tst_prog >> $ODIR/stdout
$MDB -e "first::printf '%x' broken_t brk_k" $tst_prog >> $ODIR/stdout
$MDB -e "first::printf '%x' broken_t brk_l" $tst_prog >> $ODIR/stdout
$MDB -e "first::printf '%x' broken_t brk_m" $tst_prog >> $ODIR/stdout
$MDB -e "second::printf '%x' broken6461_t a" $tst_prog >> $ODIR/stdout
$MDB -e "second::printf '%x' broken6461_t b" $tst_prog >> $ODIR/stdout
$MDB -e "second::printf '%x' broken6461_t c" $tst_prog >> $ODIR/stdout
$MDB -e "second::printf '%x' broken6461_t d" $tst_prog >> $ODIR/stdout
$MDB -e "second::printf '%x' broken6461_t e" $tst_prog >> $ODIR/stdout
$MDB -e "second::printf '%x' broken6461_t f" $tst_prog >> $ODIR/stdout

#
# If we pipe the output of ::print that is a different bitfield logic
# path. So we take that all to a `::eval '.=K'` as a basic way to get it
# out.
#
$MDB -e "first::print broken_t brk_a | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_b | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_c | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_d | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_e | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_f | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_g | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_h | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_i | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_j | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_k | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_l | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "first::print broken_t brk_m | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "second::print broken6461_t a | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "second::print broken6461_t b | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "second::print broken6461_t c | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "second::print broken6461_t d | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "second::print broken6461_t e | ::eval '.=K'" $tst_prog >> $ODIR/stdout
$MDB -e "second::print broken6461_t f | ::eval '.=K'" $tst_prog >> $ODIR/stdout
