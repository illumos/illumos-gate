#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# test script for Sun::Solaris::Utils gmatch()
#

use strict;

BEGIN { $| = 1; print "1..49\n"; }
my $loaded;
END {print "not ok 1\n" unless $loaded;}
use Sun::Solaris::Utils qw(gmatch);
$loaded = 1;
print "ok 1\n";

my ($test);
$test = 2;

my @strs = ( 'a', 'aa', 'z', 'zz', '0', '0123456789' );
my @tests = (
    { pattern => 'a',       results => [ 1, 0, 0, 0, 0, 0 ] }, 
    { pattern => '*',       results => [ 1, 1, 1, 1, 1, 1 ] }, 
    { pattern => '?',       results => [ 1, 0, 1, 0, 1, 0 ] }, 
    { pattern => '??',      results => [ 0, 1, 0, 1, 0, 0 ] }, 
    { pattern => '[a-z]*',  results => [ 1, 1, 1, 1, 0, 0 ] }, 
    { pattern => '[!a-z]*', results => [ 0, 0, 0, 0, 1, 1 ] }, 
    { pattern => '[0-9]*',  results => [ 0, 0, 0, 0, 1, 1 ] }, 
    { pattern => '[!0-9]*', results => [ 1, 1, 1, 1, 0, 0 ] }, 
);

foreach my $t (@tests) {
	for (my $i = 0; $i < @strs; $i++) {
		if (gmatch($strs[$i], $t->{pattern}) == $t->{results}[$i]) {
			print("ok $test\n");
		} else {
			print("not ok $test\n");
		}
		$test++;
	}
}

exit(0);
