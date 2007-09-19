#!/usr/bin/perl

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
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
# Replacement for /usr/bin/nl in the sgs/messages piglatin tests.
#
#	usage: sgsmsg_piglatin_nl start_index
#
#	where start_index is the staring number
#
#
# The sgs/messages test target used to use /usr/bin/nl as part
# of the process of adding a piglatin translation to the file.
# The invocations looked like:
#
#	nl -v1 -i2
# or
#	nl -v2 -i2
#
# This adds line numbers to the beginning of each non-empty line
# from stdin, counting by 2, and starting at either 1 or 2, depending
# on whether the master file, or the piglatin file is being processed.
#
# The output format is "%6d\t%s". Empty lines are replaced with
# 7 space characters in the output, and the line number is not
# incremented.
#
# The problem with nl is that it has a 2K buffer for input lines,
# and our catalog files can have some very long lines, thanks to
# the elfedit module help strings. This perl script emulates nl
# to the extent required to replace it in the sgs piglatin tests,
# while not breaking lines longer than 2K characters.

use warnings;
use strict;

use vars qw($script $lineno);

$script = 'sgsmsg_piglatin_nl';

die "usage: $script start_index\n" if ($ARGV[0] eq '');
$lineno = int($ARGV[0]);


while (<STDIN>) {
	if (($_ ne "") && ($_ ne "\n")) {
		printf ("%6d\t%s", $lineno, $_);
		$lineno += 2;
	} else {
		print "       \n";
	}
}
