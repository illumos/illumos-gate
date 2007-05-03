#! /usr/bin/perl -w
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

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# Create THIRDPARTYLICENSE files using the index file in $CODEMGR_WS.
#

use Cwd;
use Env;
use strict;

my $usage = "mktpl license-list-file";

my $top = $ENV{"CODEMGR_WS"};
if (! $top) {
	die "CODEMGR_WS must be set.\n";
}

if (@ARGV != 1) {
	die "usage: $usage\n";
}

my $indexfile = $ARGV[0];

my $exitstatus = 0;

# create a THIRDPARTYLICENSE file from the given license list and suffix.
sub maketpl {
	my ($suffix, @tpllist) = @_;
	my $licnum = 1;
	my $tplname = "$top/THIRDPARTYLICENSE.$suffix";

	open(TPL, ">$tplname") or die "Can't create $tplname: $!\n";

	print TPL "DO NOT TRANSLATE OR LOCALIZE.\n\n";

	foreach my $licfile (@tpllist) {
		my $descrip = `cat "$licfile.descrip"`;
		if (! $descrip) {
			warn "Missing description for $licfile\n";
			$exitstatus = 1;
			$descrip = "(MISSING DESCRIPTION for $licfile)\n";
		}
		print TPL "$licnum)  The following software may be included ",
		    "in this product:\n\n";
		print TPL "\t$descrip\n";
		print TPL "    Use of this software is governed by the ",
		    "terms of the following license:\n";
		print TPL "\n";
		if (open(LIC, "<$licfile")) {
			while (<LIC>) {
				print TPL "    " . $_;
			}
			close LIC;
		} else {
			warn "Can't open $licfile: $!\n";
			$exitstatus = 1;
			print TPL "    (MISSING LICENSE: $licfile)\n";
		}
		print TPL "\n";
		$licnum++;
	}

	close TPL or die "I/O error on $tplname: $!\n";
}

#
# Make file list for each TPL file.
#

chdir($top) or die "Can't chdir to $top: $!\n";
$top = getcwd();

my $isclosed = qr"^usr/closed";
my $istools = qr"^usr/src/tools";

my @closedlist;
my @toolslist;
my @bfulist;

open(IX, "<$indexfile") or die "Can't open $indexfile: $!\n";
while (<IX>) {
	chomp;
	if (/$isclosed/) {
		push @closedlist, $_;
	}
	if (/$istools/) {
		push @toolslist, $_;
	} else {
		push @bfulist, $_;
	}
}
close IX;

#
# Generate each TPL file.
#

maketpl("ON-BINARIES", @closedlist) if (@closedlist);
maketpl("ON-BUILD-TOOLS", @toolslist) if (@toolslist);
maketpl("BFU-ARCHIVES", @bfulist) if (@bfulist);

exit $exitstatus;
