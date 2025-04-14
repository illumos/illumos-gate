#!/usr/perl5/bin/perl -w
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
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# This utility program reads the contents file to extract Solaris ELF
# libraries, and then runs pvs(1) on them to find the library versioning
# information (if any).  This info is printed to stdout in an index file
# format.
#

require 5.005;
use strict;
use locale;
use POSIX qw(locale_h);
use Sun::Solaris::Utils qw(textdomain gettext);
use File::Basename;

use vars qw(
	@liblist
	%symlink
	%inode_hash
	%fileoutput
	%didlib
);

setlocale(LC_ALL, "");
textdomain(TEXT_DOMAIN);

# parameters for what types of libraries to list out:
my $must_be_versioned = 0;
my $must_be_public = 0;

# paths to skip outright.
my @skip_list = qw(
	/etc
	/usr/perl5
);
my $path_skip = join('|', @skip_list);
$path_skip = qr/^($path_skip)/;

# find library names:
#
# We have to use pkgchk -l output (even though it is much slower than
# parsing /var/sadm/install/contents ourselves) because the contents
# file will go away or change incompatibly at some point.
#
my $old = $ENV{'LC_ALL'};
$ENV{'LC_ALL'} = 'C';
my $contents_fh = do { local *FH; *FH };
open($contents_fh, "/usr/sbin/pkgchk -l|") || die "$!\n";
if (defined($old)) {
	$ENV{'LC_ALL'} = $old;
} else {
	delete($ENV{'LC_ALL'});
}

my $pathname = '';
my $type = '';
my $link = '';
my $pkgs = '';
my $status = '';
my $inpkgs = 0;
while (<$contents_fh>) {
	next if (/^Ex/);
	chomp;
	if (/^Pathname:\s*/i) {
		$pathname = $';
		$type = '';
		$link = '';
		$status = '';
		$pkgs = '';
		$inpkgs = 0;
		next;
	} elsif (/^Type:\s*/i) {
		$type = $';
		next;
	} elsif (/^Source of link:\s*/i) {
		$link = $';
		next;
	} elsif (/^Referenced by/i) {
		$inpkgs = 1;
	} elsif (/^Current status:\s*/i) {
		$status = $';
		$inpkgs = 0;
		next;
	} elsif (/^\s*$/) {
		next unless ($pathname =~ m,\.so,);
		next unless ($pathname =~ m,/lib,);
		next unless ($pathname =~ m,/lib[^/]*\.so\b,);
		next unless ($type =~ /regular file|symbolic link/i);
		next unless ($status =~ /^\s*installed\s*$/);
		$pathname = trim($pathname);
		$link = trim($link);
		filter($pathname, $link, $pkgs);
	}
	if ($inpkgs) {
		$pkgs .= $_ . ' ';
	}
}
close($contents_fh);

# run pvs(1) on the libraries found:
my $batch = 30;	# batch size to use (running in batches is faster).

my @list = ();
for (my $i = 1; $i <= scalar(@liblist); $i++) {
	push(@list, $liblist[$i-1]);
	if ($i % $batch == 0) {
		do_pvs(@list) if (@list);
		@list = ();
	}
}
do_pvs(@list) if (@list);	# finish any remainder.

exit 0;

#
# Take a pkgchk -l entry and decide if it corresponds to a Solaris
# library. If so, save it in the list @liblist, and record info in
# %symlink & %inode_hash associative arrays as appropriate.
#
sub filter
{
	my ($path, $link, $pkgs) = @_;


	# consider only SUNW packages:
	return unless ($pkgs =~ /\bSUNW\S+/);

	my $basename;

	$basename = basename($path);

	if ($link ne '') {
		# include developer build-time symlinks:
		return unless ($basename =~ /^lib.*\.so[\.\d]*$/);
	} else {
		return unless ($basename =~ /^lib.*\.so\.[\.\d]+$/);
	}
	return if ($path =~ /$path_skip/);

	return unless (-f $path);

	# inode is used to identify what file a symlink point to:
	my $inode;
	$inode = (stat($path))[1];
	return unless (defined($inode));

	if ($link ne '') {
		# record info about symlinks:
		if (exists($symlink{$inode})) {
			$symlink{$inode} .= ":" . $path;
		} else {
			$symlink{$inode} = ":" . $path;
		}
	} else {
		# ordinary file case:
		$inode_hash{$path} = $inode;
		push(@liblist, $path);
	}
}

#
# Run pvs(1) on a list of libraries. More than one is done at a time to
# speed things up.
#
# Extracts the version information and passes it to the output() routine
# for final processing.
#
sub do_pvs
{
	my (@list) = @_;

	my (%list, $paths, $path, $cnt);

	#
	# record info about the library paths and construct the list of
	# files for the pvs command line.
	#
	$cnt = 0;
	$paths = '';
	foreach $path (@list) {
		$list{$path} = 1;
		$paths .= ' ' if ($paths ne '');
		#
		# $path should never have single quote in it in
		# all normal usage. Make sure this is so:
		#
		next if ($path =~ /'/);
		#
		# quote the filename in case it has meta-characters
		# (which should never happen in all normal usage)
		#
		$paths .= "'$path'";
		$cnt++;
	}

	return if ($cnt == 0);

	# set locale to C for running command, since we interpret the output:
	my $old = $ENV{'LC_ALL'};
	$ENV{'LC_ALL'} = 'C';

	# get the file(1) output for each item:
	my $file_fh = do { local *FH; *FH };
	open($file_fh, "/usr/has/bin/file $paths 2>&1 |") || die "$!\n";
	my ($file, $out);
	while (<$file_fh>) {
		($file, $out) = split(/:/, $_, 2);
		if ($list{$file} && $out =~ /\bELF\b/) {
			$fileoutput{$file} = $out;
		}
	}
	close($file_fh);

	#
	# in the case of only 1 item, we place it on the command line
	# twice to induce pvs(1) to indicate which file it is reporting
	# on.
	#
	if ($cnt == 1) {
		$paths .= " $paths";
	}

	#
	# $paths are entries from /var/sadm/install/contents and
	# so should not contain spaces or meta characters:
	#
	my $pvs_fh = do { local *FH; *FH };
	open($pvs_fh, "/usr/bin/pvs -dn $paths 2>&1 |") || die "$!\n";

	# reset LC_ALL, if there was any:
	if (defined($old)) {
		$ENV{'LC_ALL'} = $old;
	} else {
		delete($ENV{'LC_ALL'});
	}

	my ($pub, $pri, $obs, $evo, $vers, $new_path);

	undef($path);

	# initialize strings used below for appending info to:
	$pub = '';
	$pri = '';
	$obs = '';
	$evo = '';

	while (<$pvs_fh>) {
		$_ =~ s/\s*$//;
		if (m,^([^:]+):$,) {
		    # a new pvs file header, e.g. "/usr/lib/libc.so.1:"
		    if ($list{$1}) {
			$new_path = $1;

			# output the previous one and reset accumulators:
			if (defined($path)) {
				output($path, $pub, $pri, $obs, $evo);

				$pub = '';
				$pri = '';
				$obs = '';
				$evo = '';
			}
			$path = $new_path;
			next;	# done with pvs header case
		    }
		}

		# extract SUNW version head end:

		$vers = trim($_);
		$vers =~ s/;//g;

		# handle the various non-standard cases in Solaris libraries:
		if ($vers =~ /^(SUNW.*private|SUNW_XIL_GPI)/i) {
			$pri .= $vers . ":";
		} elsif ($vers =~ /^(SUNW_\d|SYSVABI|SISCD)/) {
			$pub .= $vers . ":";
		} elsif ($vers =~ /^(SUNW\.\d|SUNW_XIL)/) {
			$pub .= $vers . ":";
		} elsif ($vers =~ /^SUNWobsolete/) {
			$obs .= $vers . ":";
		} elsif ($vers =~ /^SUNWevolving/) {
			$evo .= $vers . ":";
		} else {
			next;
		}
	}
	close($pvs_fh);

	# output the last one (if any):
	if (defined($path)) {
		output($path, $pub, $pri, $obs, $evo);
	}
}

#
# Take the raw library versioning information and process it into index
# file format and then print it out.
#
sub output
{
	my ($path, $pub, $pri, $obs, $evo) = @_;

	return if ($didlib{$path});	# skip repeating a library

	# trim off any trailing separators:
	$pub =~ s/:$//;
	$pri =~ s/:$//;
	$obs =~ s/:$//;
	$evo =~ s/:$//;

	# work out the type of library:
	my $type;
	my $defn;
	my $n;
	if ($pri && ! $pub && ! $obs && ! $evo) {
		$type = 'INTERNAL';
		$defn = 'NO_PUBLIC_SYMS';
	} elsif ($obs) {
		$type = 'OBSOLETE';
		$defn = $obs;
	} elsif ($pub) {
		$type = 'PUBLIC';
		$defn = $pub;
		if ($defn =~ /:/) {
			$defn =~ s/:/,/g;
			$defn = "PUBLIC=$defn";
		}
	} elsif ($evo) {
		$type = 'EVOLVING';
		$defn = $evo;
	} elsif (! $pri && ! $pub && ! $obs && ! $evo) {
		$type = 'UNVERSIONED';
		$defn = '-';
	} else {
		return;
	}

	# return if instructed to skip either of these cases:
	if ($must_be_versioned && $type eq 'UNVERSIONED') {
		return;
	}
	if ($must_be_public && $type eq 'INTERNAL') {
		return;
	}


	# prepare the output line, including any symlink information:
	my $inode = $inode_hash{$path};
	my $links;
	if ($inode && exists($symlink{$inode})) {
		$links = "${path}$symlink{$inode}";
	} else {
		$links = "$path";
	}

	# count the total number of references:
	my (@n) = split(/:/, $links);
	$n = scalar(@n);

	# determine the abi to which the library file belongs:
	my ($fout, $abi);
	$abi = 'unknown';
	$fout = $fileoutput{$path};
	if ($fout =~ /\bSPARCV9\b/) {
		$abi = 'sparcv9';
	} elsif ($fout =~ /\bSPARC/) {
		$abi = 'sparc';
	} elsif ($fout =~ /\bAMD64\b/ || $fout =~ /\bELF\s+64-bit\s+LSB\b/) {
		$abi = 'amd64';
	} elsif ($fout =~ /\b80386\b/) {
		$abi = 'i386';
	}
	print STDOUT "$abi|$path|$defn|$n|$links\n";

	# record that we did this library so we do not process it a second time.
	$didlib{$path} = 1;
}

#
# Remove leading and trailing spaces.
#
sub trim
{
	my ($x) = @_;
	$x =~ s/^\s*//;
	$x =~ s/\s*$//;

	return $x;
}
