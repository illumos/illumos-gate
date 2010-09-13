#!/bin/perl -w
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
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ctfcvtptbl [-o outfile] patch-makeup-table
#
# Given a path to a patch makeup table, this script converts that table to
# machine-optimal format and deposits it in the file specified by the -o option
# or on stdout depending on whether or not -o is specified.
#
# The user-supplied patch makeup table is in the following format:
#
#   #
#   # comment
#   #
#
#   genunix_archive=/path/to/genunix/archive
#
#   patch 100001-01 kureq 100002-01
#     usr/src/uts/sparc/sd/debug32/sd
#     module2
#
#   patch 100003-08
#     module3
#
# The machine-optimal format for the above looks like this:
#
#   GENUNIX_ARCHIVE=/path/to/genunix/archive
#   module1 100001-01 100002-01
#   module2 100001-01 100002-01
#   module3 100003-08
#
#
# Macros and other time-savers:
#
#  * $RELEASE and $MACH in the genunix archive path will be replaced by the
#    values of the RELEASE and MACH environment variables, respectively, as
#    set by the program calling this one.
#
#  * BUILD, BUILD32, and BUILD64 will, when used in the path for the module,
#    will be match as follows:
#
#	BUILD	debug32, debug64, obj32, obj64
#	BUILD32	debug32, obj32
#	BUILD64	debug64, obj64
#
#  * The presence of `usr/src' at the beginning of each module path will be
#    assumed, and is not required to be specified.
#

use strict;
use Getopt::Std;
use File::Basename;

my $PROGNAME = basename($0);

my $genunix_archive;
my %moddata;
my %typehash = (
    BUILD	=> [ "debug32", "debug64", "obj32", "obj64" ],
    BUILD32	=> [ "debug32", "obj32" ],
    BUILD64	=> [ "debug64", "obj64" ]
);

my %opts;
my $err = 0;
$err = 1 unless getopts("ho:", \%opts);
if ($opts{"o"}) {
	close(STDOUT);
	open(STDOUT, ">" . $opts{"o"}) || do {
		print STDERR "Couldn't open " . $opts{"o"} . ": $!\n";
		exit(1);
	}
}
if ($opts{"h"}) {
	&usage;
	exit(2);
}

if (@ARGV != 1) {
	$err = 1;
}

if ($err) {
	&usage;
	exit(2);
}

$::table = $ARGV[0];

if (!open(TABLE, "<$::table")) {
	print STDERR "Couldn't open $::table: $!\n";
	exit(1);
}

if (!&read_table) {
	exit(1);
}

&sub_vars;

&dump_table;

exit(0);

sub usage {
	print STDERR "Usage: $PROGNAME [-o outfile] table\n";
}

sub read_table {
	my $patchid = "";
	my $kureq = "";
	my $kuprev = "";

	$genunix_archive = "";
	undef %moddata;

	while (<TABLE>) {
		chop;
		s/\#.*$//; # Strip comments
		s/^\s+//;

		if (!$patchid && /^genunix_archive=(\S+)\s*$/) {
			$genunix_archive = $1;
			next;
		}

		while ($_) {
			if (s/^patch\s+(\d{6}-\d{2})
			    (\s+ku(req|prev)\s+(\d{6}-\d{2}|fcs))?//x &&
			    (!$_ || /^\s/)) {
				$patchid = $1;
				$kureq = (defined $4 ? $4 : "fcs");
				$kuprev = (defined $3 && $3 eq "prev" ? 1 : 0);
			} elsif ($patchid && s/^(\S+)//) {
				my $module = $1;

				if (($module =~ m:/genunix/:) && !$kuprev) {
					&parseerror("No kuprev supplied " .
					    "for entry including genunix");
				}

				if (($module !~ m:^usr/src/:)) {
					$module = "usr/src/" . $module;
				}

				if (($module =~
				    m:^(.*)\$(BUILD|BUILD32|BUILD64)(/.*)$:)) {
					foreach my $type (@{$typehash{$2}}) {
						$moddata{$1 . $type . $3} =
						    [$patchid, $kureq];
					}
				} else {
					$moddata{$module} = [$patchid, $kureq];
				}
			} else {
				&parseerror("Cannot parse table");
			}

			s/^\s+//;
		}
	}

	if (!$genunix_archive) {
		print STDERR "No genunix_archive line in table\n";
		return (0);
	}

	if (!%moddata) {
		print STDERR "No module information read\n";
		return (0);
	}

	return (1);
}

sub parseerror {
	my $msg = $_[0];

	print STDERR "$msg at line $.\n";
	exit(1);
}

sub sub_vars {
	my $release = $ENV{"RELEASE"};
	my $mach = $ENV{"MACH"};

	$genunix_archive =~ s/\$RELEASE/$release/ if defined $release;
	$genunix_archive =~ s/\$MACH/$mach/ if defined $mach;
}

sub dump_table {
	print "GENUNIX_ARCHIVE=" . $genunix_archive . "\n";

	foreach my $mod (sort keys %moddata) {
		print join(" ", ($mod, @{$moddata{$mod}})) . "\n";
	}
}
