#! /usr/perl5/bin/perl
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy is of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2016 Josef 'Jeff' Sipek <jeffpc@josefsipek.net>
#

#
# This extracts all the BSD copyrights (excluding the CDDL licenses)
# for use in a THIRDPARTYLICENSE file.  It tries hard to avoid duplicates.
#

use strict;
use warnings;
use File::Find;

my %LICENSE = ();

sub dofile
{
	my $file = shift;
	my $comment = 0;
	my @license = ();
	my @block = ();;
	my $copyr = 0;
	open(FILE, $file);
	while (<FILE>) {
		if (/^\/\*$/) {
			$comment = 1;
			$copyr = 0;
			@block = ();
			next;
		}
		if (!$comment) {
			next;
		}
		#
		# We don't want to know about CDDL files.  They don't
		# require an explicit THIRDPARTYLICENSE file.
		#
		if (/CDDL/) {
			#print "$file is CDDL.\n";
			close(FILE);
			return;
		}
		if (/Copyright/) {
			$copyr = 1;
		}
		if (!/^ \*\//) {
			push(@block, $_);
			next;
		}
		#
		# We have reached the end of the comment now.
		#
		$comment = 0;

		# Check to see if we saw a copyright.
		if (!$copyr) {
			next;
		}
		my $line;
		foreach $line (@block) {
			chomp $line;
			$line =~ s/^ \* //;
			$line =~ s/^ \*//;
			$line =~ s/^ \*$//;
			push(@license, $line);
		}
	}

	if ($#license > 0)  {
		my $lic = join "\n", @license;
		push (@{$LICENSE{$lic}}, $file);
	}

	close(FILE);
}

my @FILES;

sub wanted {
	my $path = $File::Find::name;

	if (!-f $path) {
		if ($path =~ /\.[chs]$/) {
			push(@FILES, $path);
		}
	}
	
}
foreach $a (@ARGV) {
    	if (-d $a) {
		find(\&wanted, $a);
	} elsif (-f $a) {
		push(@FILES, $a);
	}
}

# sort files to get a stable ordering to aid wsdiff(1onbld)
@FILES = sort @FILES;

foreach $a (@FILES) {
	dofile($a);
}

foreach my $lic (keys %LICENSE) {
	my @files = @{$LICENSE{$lic}};
	print "\nThe following files from the C library:\n";
	foreach my $f (@files) {
		print("    $f\n");
	}
	print "are provided under the following terms:\n\n";
	print "$lic\n";
}
