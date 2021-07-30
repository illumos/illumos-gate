#!/usr/bin/perl -w
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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
# Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
#

#
# Find ELF executables and sharable objects
#
# This script descends a directory hierarchy and reports the ELF
# objects found, one object per line of output.
#
#	find_elf [-frs] path
#
# Where path is a file or directory.
#
# Each line of output is of the form:
#
#	ELFCLASS  ELFTYPE VERDEF|NOVERDEF relpath
#
# where relpath is the path relative to the directory from which the
# search started.

use strict;

use vars  qw($Prog %Output @SaveArgv);
use vars  qw(%opt $HaveElfedit);

# Hashes used to detect aliases --- symlinks that reference a common file
#
#	id_hash - Maps the unique st_dev/st_ino pair to the real file
#	alias_hash - Maps symlinks to the real file they reference
#
use vars  qw(%id_hash %alias_hash);

use POSIX qw(getenv);
use Getopt::Std;
use File::Basename;
use IO::Dir;
use Config;

BEGIN {
	if ($Config{useithreads}) {
		require threads;
		require threads::shared;
		threads::shared->import(qw(share));
		require Thread::Queue;
	}
}

#
# We need to clamp the maximum number of threads that we use. Because
# this program is mostly an exercise in fork1, more threads doesn't
# actually help us after a certain point as we just spend more and more
# time trying to stop all of our LWPs than making forward progress.
# We've seen experimentally on both 2P systems with 128 cores and 1P
# systems with 16 cores that around 8 threads is a relative sweet spot.
#
chomp (my $NPROCESSORS_ONLN = `getconf NPROCESSORS_ONLN 2>/dev/null` || 1);
my $max_threads = $ENV{DMAKE_MAX_JOBS} || $NPROCESSORS_ONLN;
if ($max_threads > 8) {
	$max_threads = 8;
}

my $tq;

if ($Config{useithreads}) {
	share(%Output);
	share(%id_hash);
	share(%alias_hash);

	$tq = Thread::Queue->new;
}

## GetObjectInfo(path)
#
# Return a 3 element output array describing the object
# given by path. The elements of the array contain:
#
#	Index   Meaning
#	-----------------------------------------------
#	0	ELFCLASS of object (0 if not an ELF object)
#	1	Type of object (NONE if not an ELF object)
#	2	VERDEF if object defines versions, NOVERDEF otherwise
#
sub GetObjectInfo {
	my $path = $_[0];

	# If elfedit is available, we use it to obtain the desired information
	# by executing three commands in order, to produce a 0, 2, or 3
	# element output array.
	#
	#	Command                 Meaning
	#	-----------------------------------------------
	#	ehdr:ei_class		ELFCLASS of object
	#	ehdr:ei_e_type		Type of object
	#	dyn:tag verdef		Address of verdef items
	#
	# We discard stderr, and simply examine the resulting array to
	# determine the situation:
	#
	#	# Array Elements	Meaning
	#	-----------------------------------------------
	#	  0			File is not ELF object
	#	  2			Object with no versions (no VERDEF)
	#	  3			Object that has versions
	if ($HaveElfedit) {
		my $ecmd = "elfedit -r -o simple -e ehdr:ei_class " .
		    "-e ehdr:e_type -e 'dyn:tag verdef'";
		my @Elf = split(/\n/, `$ecmd $path 2>/dev/null`);

		my $ElfCnt = scalar @Elf;

		# Return ET_NONE array if not an ELF object
		return (0, 'NONE', 'NOVERDEF') if ($ElfCnt == 0);

		# Otherwise, convert the result to standard form
		$Elf[0] =~ s/^ELFCLASS//;
		$Elf[1] =~ s/^ET_//;
		$Elf[2] = ($ElfCnt == 3) ? 'VERDEF' : 'NOVERDEF';
		return @Elf;
	}

	# For older platforms, we use elfdump to get the desired information.
	my @Elf = split(/\n/, `elfdump -ed $path 2>&1`);
	my $Header = 'None';
	my $Verdef = 'NOVERDEF';
	my ($Class, $Type);

	foreach my $Line (@Elf) {
		# If we have an invalid file type (which we can tell from the
		# first line), or we're processing an archive, bail.
		if ($Header eq 'None') {
			if (($Line =~ /invalid file/) ||
			    ($Line =~ /$path(.*):/)) {
				return (0, 'NONE', 'NOVERDEF');
			}
		}

		if ($Line =~ /^ELF Header/) {
			$Header = 'Ehdr';
			next;
		}

		if ($Line =~ /^Dynamic Section/) {
			$Header = 'Dyn';
			next;
		}

		if ($Header eq 'Ehdr') {
			if ($Line =~ /e_type:\s*ET_([^\s]+)/) {
				$Type = $1;
				next;
			}
			if ($Line =~ /ei_class:\s+ELFCLASS(\d+)/) {
				$Class = $1;
				next;
			}
			next;
		}

		if (($Header eq 'Dyn') &&
		    ($Line =~ /^\s*\[\d+\]\s+VERDEF\s+/)) {
			$Verdef = 'VERDEF';
			next;
		}
	}
	return ($Class, $Type, $Verdef);
}


## ProcFile(FullPath, RelPath, AliasedPath, IsSymLink, dev, ino)
#
# Determine whether this a ELF dynamic object and if so, add a line
# of output for it to @Output describing it.
#
# entry:
#	FullPath - Fully qualified path
#	RelPath - Path relative to starting root directory
#	AliasedPath - True if RelPath contains a symlink directory component.
#		Such a path represents an alias to the same file found
#		completely via actual directories.
#	IsSymLink - True if basename (final component) of path is a symlink.
#
sub ProcFile {
	my($FullPath, $RelPath, $AliasedPath, $IsSymLink, $dev, $ino) = @_;
	my(@Elf, @Pvs, @Pvs_don, @Vers, %TopVer);
	my($Aud, $Max, $Priv, $Pub, $ElfCnt, $Val, $Ttl, $NotPlugin);

	my $uniqid = sprintf("%llx-%llx", $dev, $ino);

	# Remove ./ from front of relative path
	$RelPath =~ s/^\.\///;

	my $name = $opt{r} ? $RelPath : $FullPath;

	# If this is a symlink, or the path contains a symlink, put it in
	# the alias hash for later analysis. We do this before testing to
	# see if it is an ELF file, because that's a relatively expensive
	# test. The tradeoff is that the alias hash will contain some files
	# we don't care about. That is a small cost.
	if (($IsSymLink || $AliasedPath) && !$opt{a}) {
		$alias_hash{$name} = $uniqid;
		return;
	}

	# Obtain the ELF information for this object.
	@Elf = GetObjectInfo($FullPath);

        # Return quietly if:
	#	- Not an executable or sharable object
	#	- An executable, but the -s option was used.
	if ((($Elf[1] ne 'EXEC') && ($Elf[1] ne 'DYN')) ||
	    (($Elf[1] eq 'EXEC') && $opt{s})) {
		return;
	}

	$Output{$name} = sprintf("OBJECT %2s %-4s %-8s %s\n",
	    $Elf[0], $Elf[1], $Elf[2], $name);

	# Remember it for later alias analysis
	$id_hash{$uniqid} = $name;
}


## ProcDir(FullPath, RelPath, AliasedPath, SelfSymlink)
#
# Recursively search directory for dynamic ELF objects, calling
# ProcFile() on each one.
#
# entry:
#	FullPath - Fully qualified path
#	RelPath - Path relative to starting root directory
#	AliasedPath - True if RelPath contains a symlink directory component.
#		Such a path represents an alias to the same file found
#		completely via actual directories.
#	SelfSymlink - True (1) if the last segment in the path is a symlink
#		that points at the same directory (i.e. 32->.). If SelfSymlink
#		is True, ProcDir() examines the given directory for objects,
#		but does not recurse past it. This captures the aliases for
#		those objects, while avoiding entering a recursive loop,
#		or generating nonsensical paths (i.e., 32/amd64/...).
#
sub ProcDir {
	if ($Config{useithreads}) {
		threads->create(sub {
			while (my $q = $tq->dequeue) {
				ProcFile(@$q)
			}
		}) for (1 .. $max_threads);
	}

	_ProcDir(@_);

	if ($Config{useithreads}) {
		$tq->end;
		$_->join for threads->list;
	}
}

sub _ProcDir {
	my($FullDir, $RelDir, $AliasedPath, $SelfSymlink) = @_;
	my($NewFull, $NewRel, $Entry);

	# Open the directory and read each entry, omit files starting with "."
	my $Dir = IO::Dir->new($FullDir);
	if (defined($Dir)) {
		foreach $Entry ($Dir->read()) {

			# In fast mode, we skip any file name that starts
			# with a dot, which by side effect also skips the
			# '.' and '..' entries. In regular mode, we must
			# explicitly filter out those entries.
			if ($opt{f}) {
				next if ($Entry =~ /^\./);
			} else {
				next if ($Entry =~ /^\.\.?$/);
			}

			$NewFull = join('/', $FullDir, $Entry);

			# We need to follow symlinks in order to capture
			# all possible aliases for each object. However,
			# symlinks that point back at the same directory
			# (e.g. 32->.) must be flagged via the SelfSymlink
			# argument to our recursive self in order to avoid
			# taking it more than one level down.
			my $RecurseAliasedPath = $AliasedPath;
			my $RecurseSelfSymlink = 0;
			my $IsSymLink = -l $NewFull;
			if ($IsSymLink) {
				my $trans = readlink($NewFull);

				$trans =~ s/\/*$//;
				$RecurseSelfSymlink = 1 if $trans eq '.';
				$RecurseAliasedPath = 1;
			}

			if (!stat($NewFull)) {
				next;
			}
			$NewRel = join('/', $RelDir, $Entry);

			# Descend into and process any directories.
			if (-d _) {
				# If we have recursed here via a $SelfSymlink,
				# then do not persue directories. We only
				# want to find objects in the same directory
				# via that link.
				next if $SelfSymlink;

				_ProcDir($NewFull, $NewRel, $RecurseAliasedPath,
				    $RecurseSelfSymlink);
				next;
			}

			# In fast mode, we skip objects unless they end with
			# a .so extension, or are executable. We touch
			# considerably fewer files this way.
			if ($opt{f} && !($Entry =~ /\.so$/) &&
			    !($Entry =~ /\.so\./) &&
			    ($opt{s} || (! -x _))) {
			    next;
			}

			# Process any standard files.
			if (-f _) {
				my ($dev, $ino) = stat(_);
				if ($Config{useithreads}) {
					$tq->enqueue([ $NewFull, $NewRel,
					    $AliasedPath, $IsSymLink, $dev,
					    $ino ]);
				}
				else {
					ProcFile($NewFull, $NewRel,
					    $AliasedPath, $IsSymLink, $dev,
					    $ino);
				}
				next;
			}

		}
		$Dir->close();
	}
}


# -----------------------------------------------------------------------------

# Establish a program name for any error diagnostics.
chomp($Prog = `basename $0`);

# The onbld_elfmod package is maintained in the same directory as this
# script, and is installed in ../lib/perl. Use the local one if present,
# and the installed one otherwise.
my $moddir = dirname($0);
$moddir = "$moddir/../lib/perl" if ! -f "$moddir/onbld_elfmod.pm";
require "$moddir/onbld_elfmod.pm";

# Check that we have arguments.
@SaveArgv = @ARGV;
if ((getopts('afrs', \%opt) == 0) || (scalar(@ARGV) != 1)) {
	print "usage: $Prog [-frs] file | dir\n";
	print "\t[-a]\texpand symlink aliases\n";
	print "\t[-f]\tuse file name at mode to speed search\n";
	print "\t[-r]\treport relative paths\n";
	print "\t[-s]\tonly remote sharable (ET_DYN) objects\n";
	exit 1;
}

%Output = ();
%id_hash = ();
%alias_hash = ();
$HaveElfedit = -x '/usr/bin/elfedit';

my $Arg = $ARGV[0];
my $Error = 0;

ARG: {
	# Process simple files.
	if (-f $Arg) {
		my($RelPath) = $Arg;

		if ($opt{r}) {
			my $Prefix = $Arg;

			$Prefix =~ s/(^.*)\/.*$/$1/;
			$Prefix = '.' if ($Prefix eq $Arg);
			print "PREFIX $Prefix\n";
		}
		$RelPath =~ s/^.*\//.\//;
		my ($dev, $ino) = stat(_);
		my $IsSymLink = -l $Arg;
		ProcFile($Arg, $RelPath, 0, $IsSymLink, $dev, $ino);
		next;
	}

	# Process directories.
	if (-d $Arg) {
		$Arg =~ s/\/$//;
		print "PREFIX $Arg\n" if $opt{r};
		ProcDir($Arg, ".", 0, 0);
		next;
	}

	print STDERR "$Prog: not a file or directory: $Arg\n";
	$Error = 1;
}

# Build a hash, using the primary file name as the key, that has the
# strings for any aliases to that file.
my %alias_text = ();
foreach my $Alias (sort keys %alias_hash) {
	my $id = $alias_hash{$Alias};
	if (defined($id_hash{$id})) {
		my $obj = $id_hash{$id};
		my $str = "ALIAS                   $id_hash{$id}\t$Alias\n";

		if (defined($alias_text{$obj})) {
			$alias_text{$obj} .= $str;
		} else {
			$alias_text{$obj} = $str;
		}
	}
}

# Output the main files sorted by name. Place the alias lines immediately
# following each main file.
foreach my $Path (sort keys %Output) {
	print $Output{$Path};
	print $alias_text{$Path} if defined($alias_text{$Path});
}

exit $Error;
