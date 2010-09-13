#!/usr/bin/perl
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Given either a list of files containing paths on the command line or
# a set of paths on standard input, validate that the paths actually
# exist, and complain if they do not.  This is invoked by nightly to
# verify the contents of various control files used by the ON build
# process.
#
# Command line options:
#
#	-m	Show the matches (for debug).
#
#	-r	Allow shell globs in the paths.  Unless otherwise
#		flagged by a keyword (see -k) or exclusion (see -e),
#		it is an error if no files match the expression at
#		all.
#
#	-s/from/to/
#		Perform a substitution on all of the paths in the
#		file.  This substitution is performed after stripping
#		any in-line comments but before any exclusion matching
#		is done.  The option may include any legal Perl
#		substitution expression and may be repeated to give
#		multiple expressions.
#
#	-e <pattern>
#		Exclude paths matching the given pattern from the
#		"must exist" rule.  These paths will not be checked.
#		Option may include any legal Perl regular expression,
#		and may be repeated to give multiple patterns.
#
#	-k <keyword>
#		Exclude paths if there is either an in-line comment
#		containing the given keyword, or the preceding line
#		consists of only a comment containing that keyword.
#		Option may be repeated to provide multiple keywords.
#
#	-b <base>
#		Base directory for relative paths tested.
#
#	-n <name>
#		String to use in place of file name when using stdin

use strict;

my ($opt_r, $opt_m, @opt_s, @opt_e, @opt_k, $opt_b, $opt_n);
my ($keywords, @exclude);

sub usage {
    die "usage: $0 [-r] [-m]\n",
    "\t[-s/from/to/] [-e <pattern>] [-k <keyword>] [-b <base>]\n",
    "\t[-n <name> ] [files...]\n";
}

# process the path list in a given file
sub process_paths {
    my ($FILE, $name) = @_;
    my ($ignore, $file, $line);
    $ignore = 0;
    $line = 0;
    while (<$FILE>) {
	chomp;
	$line++;
	# Ignore comment lines
	if (/^\s*#(.*)$/) {
	    $ignore = ($1 =~ /$keywords/) if defined $keywords;
	    next;
	}
	# Extract path as $1 from line
	if (/^\s*([^#]+)#(.*)$/) {
	    ($ignore = 0, next) if $ignore;
	    $ignore = ($2 =~ /$keywords/) if defined $keywords;
	    ($ignore = 0, next) if $ignore;
	} elsif (/^\s*([^#]+)$/) {
	    ($ignore = 0, next) if $ignore;
	} else {
	    # Ignore blank lines
	    $ignore = 0;
	    next;
	}
	# remove any trailing spaces from path
	($file = $1) =~ s/[	 ]*$//;
	# perform user-supplied substitutions
	foreach my $pat (@opt_s) {
	    eval '$file =~ s' . $pat;
	}
	# check if the given path is on the 'exclude' list
	$ignore = 0;
	foreach my $pat (@exclude) {
	    ($ignore = 1, last) if $file =~ /$pat/;
	}
	if ($ignore == 0) {
	    # construct the actual path to the file
	    my $path = $opt_b . $file;
	    # Expand any shell globs, if that feature is on.  Since
	    # Perl's glob() is stateful, we use an array assignment
	    # to get the first match and discard the others.
	    ($path) = glob($path) if $opt_r;
	    print "$name:$line: $file\n" unless !$opt_m && -e $path;
	    print "  $path\n" if $opt_m;
	}
	$ignore = 0;
    }
}

sub next_arg {
    my ($arg) = @_;
    if ($arg eq "") {
	die "$0: missing argument for $_\n" if $#ARGV == -1;
	$arg = shift @ARGV;
    }
    $arg;
}

# I'd like to use Perl's getopts here, but it doesn't handle repeated
# options, and using comma separators is just too ugly.
# This doesn't handle combined options (as in '-rm'), but I don't care.
my $arg, $opt_r, $opt_m, @opt_s, @opt_e, @opt_k, $opt_b, $opt_n;
while ($#ARGV >= 0) {
    $_ = $ARGV[0];
    last if /^[^-]/;
    shift @ARGV;
    $opt_n = "standard input";
    last if /^--$/;
    SWITCH: {
	  /^-r/ && do { $opt_r = 1; last SWITCH; };
	  /^-m/ && do { $opt_m = 1; last SWITCH; };
	  if (/^-s(.*)$/) {
	      $arg = next_arg($1);
	      push @opt_s, $arg;
	      last SWITCH;
	  }
	  if (/^-e(.*)$/) {
	      $arg = next_arg($1);
	      push @opt_e, $arg;
	      last SWITCH;
	  }
	  if (/^-k(.*)$/) {
	      $arg = next_arg($1);
	      push @opt_k, $arg;
	      last SWITCH;
	  }
	  if (/^-b(.*)$/) {
	      $opt_b = next_arg($1);
	      last SWITCH;
	  }
	  if (/^-n(.*)$/) {
	      $opt_n = next_arg($1);
	      last SWITCH;
	  }
	  print "$0: unknown option $_\n";
	  usage();
    }
}

# compile the 'exclude' regexps
@exclude = map qr/$_/x, @opt_e;
# if no keywords are given, then leave $keywords undefined
if (@opt_k) {
    # construct a regexp that matches the keywords specified
    my $opt_k = join("|", @opt_k);
    $keywords = qr/($opt_k)/xo;
}
$opt_b .= "/" if $opt_b =~ /[^\/]$/;

my $file;

if ($#ARGV < 0) {
    process_paths(\*STDIN, $opt_n);
} else {
    foreach $file (@ARGV) {
	if (! -e $file) {
	    warn "$0: $file doesn't exist\n";
	} elsif (! -f $file) {
	    warn "$0: $file isn't a regular file\n";
	} elsif (! -T $file) {
	    warn "$0: $file isn't a text file\n";
	} elsif (open FILE, "<$file") {
	    process_paths(\*FILE, $file);
	} else {
	    warn "$0: $file: $!\n";
	}
    }
}

exit 0
