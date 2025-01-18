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
# Copyright 2025 Oxide Computer Company
#

#
# Test our ability to recurse through and print information about anonymous
# structs and unions. Effectively, this is about the resolution capabilities of
# various dcmds. This is paired with the "anon" program. Note, we have to be
# very careful to avoid printing addresses into the output data we're comparing
# against. Make sure to use ::printf for strings rather than ::print or './s'
#

set -o pipefail

tst_root="$(dirname $0)/.."
tst_prog="$tst_root/progs/anon"

cat </dev/null > $ODIR/stdout

#
# Begin with basic offsetof logic on types. This ensures that embedded anonymous
# entities are at the correct offset.
#
$MDB -e "::offsetof struct foo foo" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct bar bar" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct bar bar_foo" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct bar bar_int" $tst_prog >> $ODIR/stdout

$MDB -e "::offsetof struct baz baz_str" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct baz baz_anon" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct baz baz_int" $tst_prog >> $ODIR/stdout

$MDB -e "::offsetof struct foobar foobar_int" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct foobar foo" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct foobar bar" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct foobar baz" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct foobar foobar_anon" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct foobar a" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct foobar b" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct foobar c" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct foobar d" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct foobar e" $tst_prog >> $ODIR/stdout
$MDB -e "::offsetof struct foobar f" $tst_prog >> $ODIR/stdout

#
# Print ::sizeof to make sure that this aligns with offsetof data.
#
$MDB -e "::sizeof struct foo" $tst_prog >> $ODIR/stdout
$MDB -e "::sizeof struct bar" $tst_prog >> $ODIR/stdout
$MDB -e "::sizeof struct baz" $tst_prog >> $ODIR/stdout
$MDB -e "::sizeof struct foobar" $tst_prog >> $ODIR/stdout

#
# Print the overall structure to make sure we get the <anon> entries we expect.
#
$MDB -e "foo::print" $tst_prog >> $ODIR/stdout
$MDB -e "foo::print foo" $tst_prog >> $ODIR/stdout
$MDB -e "bar::printf \"%s\\n\" struct bar bar" $tst_prog >> $ODIR/stdout
$MDB -e "bar::print bar_foo" $tst_prog >> $ODIR/stdout
$MDB -e "bar::print bar_foo.foo" $tst_prog >> $ODIR/stdout
$MDB -e "bar::print bar_foo.foo bar_int" $tst_prog >> $ODIR/stdout
$MDB -e "baz::printf \"%s\\n\" struct baz baz_str" $tst_prog >> $ODIR/stdout
$MDB -e "baz::printf \"0x%x 0x%x\\n\" struct baz baz_anon baz_int" \
    $tst_prog >> $ODIR/stdout
$MDB -e "foobar::printf \"0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\\n\" struct foobar \
    a b c d e f" $tst_prog >> $ODIR/stdout
$MDB -e "foobar::printf \"%s %s\\n\" struct foobar bar.bar baz.baz_str " \
    $tst_prog >> $ODIR/stdout
$MDB -e "foobar::print struct foobar foobar_int" $tst_prog >> $ODIR/stdout
$MDB -e "foobar::printf \"0x%x 0x%x 0x%x 0x%x\\n\" struct foobar bar.bar_foo.foo \
    bar.bar_int baz.baz_anon foobar_anon" $tst_prog >> $ODIR/stdout

#
# The stringless structure has no strings, so we can print it without worrying
# about addresses and make sure we get the appropriate anon names.
#
$MDB -e "stringless::print" $tst_prog >> $ODIR/stdout
$MDB -e "stringless::print -t" $tst_prog >> $ODIR/stdout

#
# Use the direct offset specification syntax to print a few things as
# well. This only works with ::print.
#
$MDB -e "bar::print \$[8]" $tst_prog >> $ODIR/stdout
$MDB -e "foobar::print \$[20] \$[2c]" $tst_prog >> $ODIR/stdout
