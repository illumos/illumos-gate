#!/bin/perl
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

#
# ctfstabs requires an object file with CTF data, and a file containing
# directives which indicate the types and members for which offsets are to
# be generated.  The developer provides a single input file containing both
# the #include directives used to generate the object file as well as the
# offset directives.  This script automates the splitting of the master file,
# the generation of the object file, the invocation of ctfstabs, and cleanup.
#

use strict;
use warnings;
use File::Basename;
use Getopt::Std;
use POSIX qw(:sys_wait_h);

# Globals.
our $PROGNAME = basename($0);
our ($CTmp, $OTmp, $GenTmp, $GenPPTmp, $Keep, $Verbose);

sub usage {
	print STDERR "Usage: $PROGNAME [-k] [-s ctfstabs] [-r ctfconvert] ",
	  "compiler [options]\n";
	print STDERR "  NOTE: compiler options must enable stabs or DWARF as ",
	  "appropriate\n";
	exit(2);
}

sub cleanup {
	return if ($Keep);

	unlink($CTmp) if (-f $CTmp);
	unlink($OTmp) if (-f $OTmp);
	unlink($GenTmp) if (-f $GenTmp);
	unlink($GenPPTmp) if (-f $GenPPTmp);
}

sub bail {
	print STDERR "$PROGNAME: ", join(" ", @_), "\n";
	cleanup();
	exit(1);
}


sub findprog {
	my ($arg, $name, $default) = @_;

	if (defined $arg) {
		return ($arg);
	} elsif (defined $ENV{$name}) {
		return ($ENV{$name});
	} else {
		return ($default);
	}
}

sub runit {
	my (@argv) = @_;
	my $rc;

	if ($Verbose) {
		print STDERR "+ @argv\n";
	}
	if ((my $rc = system(@argv)) == -1) {
		bail("Failed to execute $argv[0]: $!");
	} elsif (WIFEXITED($rc)) {
		$_ = WEXITSTATUS($rc);
		if ($_ == 0) {
			return;
		} else {
			bail("$argv[0] failed with status $_");
		}
	} elsif (WSIGNALLED($rc)) {
		$_ = WTERMSIG($rc);
		# WCOREDUMP isn't a POSIX macro, do it the non-portable way.
		if ($rc & 0x80) {
			bail("$argv[0] failed with signal $_ (core dumped)");
		} else {
			bail("$argv[0] failed with signal $_");
		}
	}
}

#
# Main.
#

my %opts;
getopts("kr:s:v", \%opts) || usage();
usage() if (@ARGV < 1);

my $ctfstabs = findprog($opts{"s"}, "CTFSTABS", "ctfstabs");
my $ctfconvert = findprog($opts{"r"}, "CTFCONVERT", "ctfconvert");

$Keep = $opts{k};
$Verbose = $opts{k} || $opts{v};
my ($cc, @cflags) = @ARGV;

$CTmp = "ctfstabs.tmp.$$.c";		# The C file used to generate CTF
$OTmp = "ctfstabs.tmp.$$.o";		# Object file with CTF
$GenTmp = "ctfstabs.tmp.$$.gen.c";	# genassym directives
$GenPPTmp = "ctfstabs.tmp.$$.genpp";	# Post-processed genassym directives

my ($cfile, $genfile);
open($cfile, '>', $CTmp) || bail("failed to create $CTmp: $!");
open($genfile, '>', $GenTmp) || bail("failed to create $GenTmp: $!");

if ($Verbose) {
	print STDERR "Splitting from stdin to $CTmp and $GenTmp\n";
}

while (<STDIN>) {
	# #includes go to the C file.  All other preprocessor directives
	# go to both the C file and the offsets input file.  Anything
	# that's not a preprocessor directive goes into the offsets input
	# file.  Also strip comments from the genfile, as they can confuse
	# the preprocessor.
	if (/^#include/) {
		print $cfile $_;
	} elsif (/^#/) {
		print $cfile $_;
		print $genfile $_;
	} elsif (/^\\#/) {
		print $genfile $_;
	} elsif (!/^\\/) {
		print $genfile $_;
	}
}
close($cfile) || bail("can't close $CTmp: $!");
close($genfile) || bail("can't close $GenTmp: $!");

# Compile the C file.
runit($cc, @cflags, '-c', '-o', $OTmp, $CTmp);

# Convert the debugging information to CTF.
runit($ctfconvert, '-l', 'ctfstabs', $OTmp);

# Run ctfstabs on the resulting mess.
runit($cc, @cflags, "-P", "-o", "$GenPPTmp", $GenTmp);
runit($ctfstabs, "-t", "genassym", "-i", $GenPPTmp, $OTmp);

cleanup();

exit (0);
