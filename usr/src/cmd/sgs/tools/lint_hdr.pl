#!/usr/bin/perl

#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
# Generate a header for lint output for subdirectories of
# usr/src/cmd/sgs, of the form:
#
#	lint_hdr [-s] target_file [elfclass]
#
# where:
#	target - Name of main target (library or program name)
#	elfclass - If present, 32 or 64, giving the ELFCLASS of
#		the code being linted.
#
# The resulting header looks like the following:
#
#	[elfclass - ]target [sgssubdir]
#       ----------------------------------------------------
#
# If the elfclass is omitted, then the header does not include
# it. If the target matches 'dirname sgssubdir', then sgssubdir
# is displayed without the target and without the square brackets.
#
# The -s option specifies that this is a sub-header, used when
# multiple lints are done within a single target. If -s is specified,
# the sgssubdir is not shown (presumably it was already shown in an earlier
# call to link_hdr), and a shorter dashed line is used:
#
#	[elfclass - ]target
#	========================
#	

use warnings;
use strict;
use Cwd;

use vars qw($script $usage $dir $argc $target $elfclass);
use vars qw($sub);

$script = 'lint_hdr';
$usage = "usage: $script target [elfclass]\n";

$sub = 0;
while ($_ = $ARGV[0],/^-/) {
	ARG: {
	    if (/^-s$/) {
		$sub = 1;
		last ARG;
	    }

	    # If it gets here, it's an unknown option
	    die $usage;
	}
	shift;
}

$argc = scalar(@ARGV);
die $usage if (($argc < 1) || ($argc > 2));
$target = $ARGV[0];
$elfclass = ($argc == 2) ? "Elf$ARGV[1] - " : '';

if ($sub) {
    print "\n$elfclass$target\n========================\n";
    exit 0;
}

# Clip the path up through ..sgs/, leaving the path from sgs to current dir
$dir = getcwd();
$dir = "$1" if $dir =~ /\/sgs\/(.*)$/;

# Normally, we format the target and directory like this:
#	target [dir]
# However, if this is the special case where $dir is equal to
#	prog/mach
# and prog matches our target name, then just show dir without brackets.
if (($dir =~ /^([^\/]+)\/[^\/]+$/) && ($1 eq $target)) {
    $target = '';
} else {
    $dir = " [$dir]";
}

print "\n$elfclass$target$dir\n";
print "------------------------------------------------------------\n";

exit 0;
