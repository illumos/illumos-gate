#!/usr/perl5/bin/perl -w
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
# Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# Check ELF information.
#
# This script descends a directory hierarchy inspecting ELF dynamic executables
# and shared objects.  The general theme is to verify that common Makefile rules
# have been used to build these objects.  Typical failures occur when Makefile
# rules are re-invented rather than being inherited from "cmd/lib" Makefiles.
#
# As always, a number of components don't follow the rules, and these are
# excluded to reduce this scripts output.
#
# By default any file that has conditions that should be reported is first
# listed and then each condition follows.  The -o (one-line) option produces a
# more terse output which is better for sorting/diffing with "nightly".
#
# NOTE: missing dependencies, symbols or versions are reported by running the
# file through ldd(1).  As objects within a proto area are built to exist in a
# base system, standard use of ldd(1) will bind any objects to dependencies
# that exist in the base system.  It is frequently the case that newer objects
# exist in the proto area that are required to satisfy other objects
# dependencies, and without using these newer objects an ldd(1) will produce
# misleading error messages.  To compensate for this, the -D/-d options, or the
# existence of the CODEMSG_WS/ROOT environment variables, cause the creation of
# alternative dependency mappings via crle(1) configuration files that establish
# any proto shared objects as alternatives to their base system location.  Thus
# ldd(1) can be executed against these configuration files so that objects in a
# proto area bind to their dependencies in the same proto area.


# Define all global variables (required for strict)
use vars  qw($Prog $Env $Ena64 $Tmpdir);
use vars  qw($LddNoU $Conf32 $Conf64);
use vars  qw(%opt);
use vars  qw($ErrFH $ErrTtl $InfoFH $InfoTtl $OutCnt1 $OutCnt2);

# An exception file is used to specify regular expressions to match
# objects. These directives specify special attributes of the object.
# The regular expressions are read from the file and compiled into the
# regular expression variables.
#
# The name of each regular expression variable is of the form
#
#	$EXRE_xxx
#
# where xxx is the name of the exception in lower case. For example,
# the regular expression variable for EXEC_STACK is $EXRE_exec_stack.
#
# onbld_elfmod::LoadExceptionsToEXRE() depends on this naming convention
# to initialize the regular expression variables, and to detect invalid
# exception names.
#
# If a given exception is not used in the exception file, its regular
# expression variable will be undefined. Users of these variables must
# test the variable with defined() prior to use:
#
#	defined($EXRE_exec_stack) && ($foo =~ $EXRE_exec_stack)
#
# or if the test is to make sure the item is not specified:
#
#	!defined($EXRE_exec_stack) || ($foo !~ $EXRE_exec_stack)
#
# ----
#
# The exceptions are:
#
#   EXEC_DATA
#	Objects that are not required to have non-executable writable
#	data segments.
#
#   EXEC_STACK
#	Objects that are not required to have a non-executable stack
#
#   NOCRLEALT
#	Objects that should be skipped by AltObjectConfig() when building
#	the crle script that maps objects to the proto area.
#
#    NODIRECT
#	Objects that are not required to use direct bindings
#
#    NOSYMSORT
#	Objects we should not check for duplicate addresses in
#	the symbol sort sections.
#
#    OLDDEP
#	Objects that are no longer needed because their functionalty
#	has migrated elsewhere. These are usually pure filters that
#	point at libc.
#
#    SKIP
#	Files and directories that should be excluded from analysis.
#
#    STAB
#	Objects that are allowed to contain stab debugging sections
#
#    TEXTREL
#	Object for which relocations are allowed to the text segment
#
#    UNDEF_REF
#	Objects that are allowed undefined references
#
#    UNREF_OBJ
#	"unreferenced object=" ldd(1) diagnostics.
#
#    UNUSED_DEPS
#	Objects that are allowed to have unused dependencies
#
#    UNUSED_OBJ
#	Objects that are allowed to be unused dependencies
#
#    UNUSED_RPATH
#	Objects with unused runpaths
#

use vars  qw($EXRE_exec_data $EXRE_exec_stack $EXRE_nocrlealt);
use vars  qw($EXRE_nodirect $EXRE_nosymsort);
use vars  qw($EXRE_olddep $EXRE_skip $EXRE_stab $EXRE_textrel $EXRE_undef_ref);
use vars  qw($EXRE_unref_obj $EXRE_unused_deps $EXRE_unused_obj);
use vars  qw($EXRE_unused_rpath);

use strict;
use Getopt::Std;
use File::Basename;


# Reliably compare two OS revisions.  Arguments are <ver1> <op> <ver2>.
# <op> is the string form of a normal numeric comparison operator.
sub cmp_os_ver {
	my @ver1 = split(/\./, $_[0]);
	my $op = $_[1];
	my @ver2 = split(/\./, $_[2]);

	push @ver2, ("0") x $#ver1 - $#ver2;
	push @ver1, ("0") x $#ver2 - $#ver1;

	my $diff = 0;
	while (@ver1 || @ver2) {
		if (($diff = shift(@ver1) - shift(@ver2)) != 0) {
			last;
		}
	}
	return (eval "$diff $op 0" ? 1 : 0);
}

## ProcFile(FullPath, RelPath, File, Class, Type, Verdef)
#
# Determine whether this a ELF dynamic object and if so investigate its runtime
# attributes.
#
sub ProcFile {
	my($FullPath, $RelPath, $Class, $Type, $Verdef) = @_;
	my(@Elf, @Ldd, $Dyn, $Sym, $Stack);
	my($Sun, $Relsz, $Pltsz, $Tex, $Stab, $Strip, $Lddopt, $SymSort);
	my($Val, $Header, $IsX86, $RWX, $UnDep);
	my($HasDirectBinding);

	# Only look at executables and sharable objects
	return if ($Type ne 'EXEC') && ($Type ne 'DYN');

	# Ignore symbolic links
	return if -l $FullPath;

	# Is this an object or directory hierarchy we don't care about?
	return if (defined($EXRE_skip) && ($RelPath =~ $EXRE_skip));

	# Bail if we can't stat the file. Otherwise, note if it is SUID/SGID.
	return if !stat($FullPath);
	my $Secure = (-u _ || -g _) ? 1 : 0;

	# Reset output message counts for new input file
	$$ErrTtl = $$InfoTtl = 0;

	@Ldd = 0;

	# Determine whether we have access to inspect the file.
	if (!(-r $FullPath)) {
		onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
		    "unable to inspect file: permission denied");
		return;
	}

	# Determine whether we have a executable (static or dynamic) or a
	# shared object.
	@Elf = split(/\n/, `elfdump -epdcy $FullPath 2>&1`);

	$Dyn = $Stack = $IsX86 = $RWX = 0;
	$Header = 'None';
	foreach my $Line (@Elf) {
		# If we have an invalid file type (which we can tell from the
		# first line), or we're processing an archive, bail.
		if ($Header eq 'None') {
			if (($Line =~ /invalid file/) ||
			    ($Line =~ /\Q$FullPath\E(.*):/)) {
				return;
			}
		}

		if ($Line =~ /^ELF Header/) {
			$Header = 'Ehdr';
			next;
		}

		if ($Line =~ /^Program Header/) {
			$Header = 'Phdr';
			$RWX = 0;
			next;
		}

		if ($Line =~ /^Dynamic Section/) {
			# A dynamic section indicates we're a dynamic object
			# (this makes sure we don't check static executables).
			$Dyn = 1;
			next;
		}

		if (($Header eq 'Ehdr') && ($Line =~ /e_machine:/)) {
			# If it's a X86 object, we need to enforce RW- data.
			$IsX86 = 1 if $Line =~ /(EM_AMD64|EM_386)/;
			next;
		}

		if (($Header eq 'Phdr') &&
		    ($Line =~ /\[ PF_X\s+PF_W\s+PF_R \]/)) {
			# RWX segment seen.
			$RWX = 1;
			next;
		}

		if (($Header eq 'Phdr') &&
		    ($Line =~ /\[ PT_LOAD \]/ && $RWX && $IsX86)) {
			# Seen an RWX PT_LOAD segment.
			if (!defined($EXRE_exec_data) ||
			    ($RelPath !~ $EXRE_exec_data)) {
				onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
				    "application requires non-executable " .
				    "data\t<no -Mmapfile_noexdata?>");
			}
			next;
		}

		if (($Header eq 'Phdr') && ($Line =~ /\[ PT_SUNWSTACK \]/)) {
			# This object defines a non-executable stack.
			$Stack = 1;
			next;
		}
	}

	# Determine whether this ELF executable or shared object has a
	# conforming mcs(1) comment section.  If the correct $(POST_PROCESS)
	# macros are used, only a 3 or 4 line .comment section should exist
	# containing one or two "@(#)SunOS" identifying comments (one comment
	# for a non-debug build, and two for a debug build). The results of
	# the following split should be three or four lines, the last empty
	# line being discarded by the split.
	if ($opt{m}) {
		my(@Mcs, $Con, $Dev);

		@Mcs = split(/\n/, `mcs -p $FullPath 2>&1`);

		$Con = $Dev = $Val = 0;
		foreach my $Line (@Mcs) {
			$Val++;

			if (($Val == 3) && ($Line !~ /^@\(#\)SunOS/)) {
				$Con = 1;
				last;
			}
			if (($Val == 4) && ($Line =~ /^@\(#\)SunOS/)) {
				$Dev = 1;
				next;
			}
			if (($Dev == 0) && ($Val == 4)) {
				$Con = 1;
				last;
			}
			if (($Dev == 1) && ($Val == 5)) {
				$Con = 1;
				last;
			}
		}
		if ($opt{m} && ($Con == 1)) {
			onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
		    "non-conforming mcs(1) comment\t<no \$(POST_PROCESS)?>");
		}
	}

	# Applications should contain a non-executable stack definition.
	if (($Type eq 'EXEC') && ($Stack == 0) &&
	    (!defined($EXRE_exec_stack) || ($RelPath !~ $EXRE_exec_stack))) {
		onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
		    "non-executable stack required\t<no -Mmapfile_noexstk?>");
	}

	# Having caught any static executables in the mcs(1) check and non-
	# executable stack definition check, continue with dynamic objects
	# from now on.
	if ($Dyn eq 0) {
		return;
	}

	# Use ldd unless its a 64-bit object and we lack the hardware.
	if (($Class == 32) || $Ena64) {
		my $LDDFullPath = $FullPath;

		if ($Secure) {
			# The execution of a secure application over an nfs file
			# system mounted nosuid will result in warning messages
			# being sent to /var/adm/messages.  As this type of
			# environment can occur with root builds, move the file
			# being investigated to a safe place first.  In addition
			# remove its secure permission so that it can be
			# influenced by any alternative dependency mappings.
	
			my $File = $RelPath;
			$File =~ s!^.*/!!;      # basename

			my($TmpPath) = "$Tmpdir/$File";

			system('cp', $LDDFullPath, $TmpPath);
			chmod 0777, $TmpPath;
			$LDDFullPath = $TmpPath;
		}

		# Use ldd(1) to determine the objects relocatability and use.
		# By default look for all unreferenced dependencies.  However,
		# some objects have legitimate dependencies that they do not
		# reference.
		if ($LddNoU) {
			$Lddopt = "-ru";
		} else {
			$Lddopt = "-rU";
		}
		@Ldd = split(/\n/, `ldd $Lddopt $Env $LDDFullPath 2>&1`);
		if ($Secure) {
			unlink $LDDFullPath;
		}
	}

	$Val = 0;
	$Sym = 5;
	$UnDep = 1;

	foreach my $Line (@Ldd) {

		if ($Val == 0) {
			$Val = 1;
			# Make sure ldd(1) worked.  One possible failure is that
			# this is an old ldd(1) prior to -e addition (4390308).
			if ($Line =~ /usage:/) {
				$Line =~ s/$/\t<old ldd(1)?>/;
				onbld_elfmod::OutMsg($ErrFH, $ErrTtl,
				    $RelPath, $Line);
				last;
			} elsif ($Line =~ /execution failed/) {
				onbld_elfmod::OutMsg($ErrFH, $ErrTtl,
				    $RelPath, $Line);
				last;
			}

			# It's possible this binary can't be executed, ie. we've
			# found a sparc binary while running on an intel system,
			# or a sparcv9 binary on a sparcv7/8 system.
			if ($Line =~ /wrong class/) {
				onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
				    "has wrong class or data encoding");
				next;
			}

			# Historically, ldd(1) likes executable objects to have
			# their execute bit set.
			if ($Line =~ /not executable/) {
				onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
				    "is not executable");
				next;
			}
		}

		# Look for "file" or "versions" that aren't found.  Note that
		# these lines will occur before we find any symbol referencing
		# errors.
		if (($Sym == 5) && ($Line =~ /not found\)/)) {
			if ($Line =~ /file not found\)/) {
				$Line =~ s/$/\t<no -zdefs?>/;
			}
			onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath, $Line);
			next;
		}
		# Look for relocations whose symbols can't be found.  Note, we
		# only print out the first 5 relocations for any file as this
		# output can be excessive.
		if ($Sym && ($Line =~ /symbol not found/)) {
			# Determine if this file is allowed undefined
			# references.
			if (($Sym == 5) && defined($EXRE_undef_ref) &&
			    ($RelPath =~ $EXRE_undef_ref)) {
				$Sym = 0;
				next;
			}
			if ($Sym-- == 1) {
				onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
				    "continued ...") if !$opt{o};
				next;
			}
			# Just print the symbol name.
			$Line =~ s/$/\t<no -zdefs?>/;
			onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath, $Line);
			next;
		}
		# Look for any unused search paths.
		if ($Line =~ /unused search path=/) {
			next if defined($EXRE_unused_rpath) &&
			    ($Line =~ $EXRE_unused_rpath);

			if ($Secure) {
				$Line =~ s!$Tmpdir/!!;
			}
			$Line =~ s/^[ \t]*(.*)/\t$1\t<remove search path?>/;
			onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath, $Line);
			next;
		}
		# Look for unreferenced dependencies.  Note, if any unreferenced
		# objects are ignored, then set $UnDep so as to suppress any
		# associated unused-object messages.
		if ($Line =~ /unreferenced object=/) {
			if (defined($EXRE_unref_obj) &&
			    ($Line =~ $EXRE_unref_obj)) {
				$UnDep = 0;
				next;
			}
			if ($Secure) {
				$Line =~ s!$Tmpdir/!!;
			}
			$Line =~ s/^[ \t]*(.*)/$1\t<remove lib or -zignore?>/;
			onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath, $Line);
			next;
		}
		# Look for any unused dependencies.
		if ($UnDep && ($Line =~ /unused/)) {
			# Skip if object is allowed to have unused dependencies
			next if defined($EXRE_unused_deps) &&
			    ($RelPath =~ $EXRE_unused_deps);

			# Skip if dependency is always allowed to be unused
			next if defined($EXRE_unused_obj) &&
			    ($Line =~ $EXRE_unused_obj);

			$Line =~ s!$Tmpdir/!! if $Secure;
			$Line =~ s/^[ \t]*(.*)/$1\t<remove lib or -zignore?>/;
			onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath, $Line);
			next;
		}
	}

	# Reuse the elfdump(1) data to investigate additional dynamic linking
	# information.

	$Sun = $Relsz = $Pltsz = $Dyn = $Stab = $SymSort = 0;
	$Tex = $Strip = 1;
	$HasDirectBinding = 0;

	$Header = 'None';
ELF:	foreach my $Line (@Elf) {
		# We're only interested in the section headers and the dynamic
		# section.
		if ($Line =~ /^Section Header/) {
			$Header = 'Shdr';

			if (($Sun == 0) && ($Line =~ /\.SUNW_reloc/)) {
				# This object has a combined relocation section.
				$Sun = 1;

			} elsif (($Stab == 0) && ($Line =~ /\.stab/)) {
				# This object contain .stabs sections
				$Stab = 1;
			} elsif (($SymSort == 0) &&
				 ($Line =~ /\.SUNW_dyn(sym)|(tls)sort/)) {
				# This object contains a symbol sort section
				$SymSort = 1;
			}

			if (($Strip == 1) && ($Line =~ /\.symtab/)) {
				# This object contains a complete symbol table.
				$Strip = 0;
			}
			next;

		} elsif ($Line =~ /^Dynamic Section/) {
			$Header = 'Dyn';
			next;
		} elsif ($Line =~ /^Syminfo Section/) {
			$Header = 'Syminfo';
			next;
		} elsif (($Header ne 'Dyn') && ($Header ne 'Syminfo')) {
			next;
		}

		# Look into the Syminfo section.
		# Does this object have at least one Directly Bound symbol?
		if (($Header eq 'Syminfo')) {
			my(@Symword);

			if ($HasDirectBinding == 1) {
				next;
			}

			@Symword = split(' ', $Line);

			if (!defined($Symword[1])) {
				next;
			}
			if ($Symword[1] =~ /B/) {
				$HasDirectBinding = 1;
			}
			next;
		}

		# Does this object contain text relocations.
		if ($Tex && ($Line =~ /TEXTREL/)) {
			# Determine if this file is allowed text relocations.
			if (defined($EXRE_textrel) &&
			    ($RelPath =~ $EXRE_textrel)) {
				$Tex = 0;
				next ELF;
			}
			onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
			    "TEXTREL .dynamic tag\t\t\t<no -Kpic?>");
			$Tex = 0;
			next;
		}

		# Does this file have any relocation sections (there are a few
		# psr libraries with no relocations at all, thus a .SUNW_reloc
		# section won't exist either).
		if (($Relsz == 0) && ($Line =~ / RELA?SZ/)) {
			$Relsz = hex((split(' ', $Line))[2]);
			next;
		}

		# Does this file have any plt relocations.  If the plt size is
		# equivalent to the total relocation size then we don't have
		# any relocations suitable for combining into a .SUNW_reloc
		# section.
		if (($Pltsz == 0) && ($Line =~ / PLTRELSZ/)) {
			$Pltsz = hex((split(' ', $Line))[2]);
			next;
		}

		# Does this object have any dependencies.
		if ($Line =~ /NEEDED/) {
			my($Need) = (split(' ', $Line))[3];

			if (defined($EXRE_olddep) && ($Need =~ $EXRE_olddep)) {
				# Catch any old (unnecessary) dependencies.
				onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
			"NEEDED=$Need\t<dependency no longer necessary>");
			} elsif ($opt{i}) {
				# Under the -i (information) option print out
				# any useful dynamic entries.
				onbld_elfmod::OutMsg($InfoFH, $InfoTtl, $RelPath,
				    "NEEDED=$Need");
			}
			next;
		}

		# Is this object built with -B direct flag on?
		if ($Line =~ / DIRECT /) {
			$HasDirectBinding = 1;
		}

		# Does this object specify a runpath.
		if ($opt{i} && ($Line =~ /RPATH/)) {
			my($Rpath) = (split(' ', $Line))[3];
			onbld_elfmod::OutMsg($InfoFH, $InfoTtl,
			    $RelPath, "RPATH=$Rpath");
			next;
		}
	}

	# A shared object, that contains non-plt relocations, should have a
	# combined relocation section indicating it was built with -z combreloc.
	if (($Type eq 'DYN') && $Relsz && ($Relsz != $Pltsz) && ($Sun == 0)) {
		onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
		    ".SUNW_reloc section missing\t\t<no -zcombreloc?>");
	}

	# No objects released to a customer should have any .stabs sections
	# remaining, they should be stripped.
	if ($opt{s} && $Stab) {
		goto DONESTAB if defined($EXRE_stab) && ($RelPath =~ $EXRE_stab);

		onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
		    "debugging sections should be deleted\t<no strip -x?>");
	}

	# Identify an object that is not built with either -B direct or
	# -z direct.
	goto DONESTAB
	    if (defined($EXRE_nodirect) && ($RelPath =~ $EXRE_nodirect));

	if ($Relsz && ($HasDirectBinding == 0)) {
		onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
		 "object has no direct bindings\t<no -B direct or -z direct?>");
	}

DONESTAB:

	# All objects should have a full symbol table to provide complete
	# debugging stack traces.
	onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
	    "symbol table should not be stripped\t<remove -s?>") if $Strip;

	# If there are symbol sort sections in this object, report on
	# any that have duplicate addresses.
	ProcSymSort($FullPath, $RelPath) if $SymSort;

	# If -v was specified, and the object has a version definition
	# section, generate output showing each public symbol and the
	# version it belongs to.
	ProcVerdef($FullPath, $RelPath)
	    if ($Verdef eq 'VERDEF') && $opt{v};
}


## ProcSymSortOutMsg(RelPath, secname, addr, names...)
#
# Call onbld_elfmod::OutMsg for a duplicate address error in a symbol sort
# section
#
sub ProcSymSortOutMsg {
	my($RelPath, $secname, $addr, @names) = @_;

	onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
	    "$secname: duplicate $addr: ". join(', ', @names));
}


## ProcSymSort(FullPath, RelPath)
#
# Examine the symbol sort sections for the given object and report
# on any duplicate addresses found.  Ideally, mapfile directives
# should be used when building objects that have multiple symbols
# with the same address so that only one of them appears in the sort
# section. This saves space, reduces user confusion, and ensures that
# libproc and debuggers always display public names instead of symbols
# that are merely implementation details.
#
sub ProcSymSort {

	my($FullPath, $RelPath) = @_;

	# If this object is exempt from checking, return quietly
	return if defined($EXRE_nosymsort) && ($FullPath =~ $EXRE_nosymsort);


	open(SORT, "elfdump -S $FullPath|") ||
	    die "$Prog: Unable to execute elfdump (symbol sort sections)\n";

	my $line;
	my $last_addr;
	my @dups = ();
	my $secname;
	while ($line = <SORT>) {
		chomp $line;
		
		next if ($line eq '');

		# If this is a header line, pick up the section name
		if ($line =~ /^Symbol Sort Section:\s+([^\s]+)\s+/) {
			$secname = $1;

			# Every new section is followed by a column header line
			$line = <SORT>;		# Toss header line

			# Flush anything left from previous section
			ProcSymSortOutMsg($RelPath, $secname, $last_addr, @dups)
			    if (scalar(@dups) > 1);

			# Reset variables for new sort section
			$last_addr = '';
			@dups = ();

			next;
		}

		# Process symbol line
		my @fields = split /\s+/, $line;
		my $new_addr = $fields[2]; 
		my $new_type = $fields[8];
		my $new_name = $fields[9]; 

		if ($new_type eq 'UNDEF') {
			onbld_elfmod::OutMsg($ErrFH, $ErrTtl, $RelPath,
			    "$secname: unexpected UNDEF symbol " .
			    "(link-editor error): $new_name");
			next;
		}

		if ($new_addr eq $last_addr) {
			push @dups, $new_name;
		} else {
			ProcSymSortOutMsg($RelPath, $secname,
			    $last_addr, @dups) if (scalar(@dups) > 1);
			@dups = ( $new_name );
			$last_addr = $new_addr; 
		}
	}

	ProcSymSortOutMsg($RelPath, $secname, $last_addr, @dups)
		if (scalar(@dups) > 1);
	
	close SORT;
}


## ProcVerdef(FullPath, RelPath)
#
# Examine the version definition section for the given object and report
# each public symbol along with the version it belongs to.
#
sub ProcVerdef {

	my($FullPath, $RelPath) = @_;
	my $line;
	my $cur_ver = '';
	my $tab = $opt{o} ? '' : "\t";

	# pvs -dov provides information about the versioning hierarchy
	# in the file. Lines are of the format:
	#	path - version[XXX];
	# where [XXX] indicates optional information, such as flags
	# or inherited versions.
	#
	# Private versions are allowed to change freely, so ignore them.
	open(PVS, "pvs -dov $FullPath|") ||
	    die "$Prog: Unable to execute pvs (version definition section)\n";

	while ($line = <PVS>) {
		chomp $line;

		if ($line =~ /^[^\s]+\s+-\s+([^;]+)/) {
			my $ver = $1;

			next if $ver =~ /private/i;
			onbld_elfmod::OutMsg($InfoFH, $InfoTtl, $RelPath,
			    "${tab}VERDEF=$ver");
		}
	}
	close PVS;

	# pvs -dos lists the symbols assigned to each version definition.
	# Lines are of the format:
	#	path - version: symbol;
	#	path - version: symbol (size);
	# where the (size) is added to data items, but not for functions.
	# We strip off the size, if present.

	open(PVS, "pvs -dos $FullPath|") ||
	    die "$Prog: Unable to execute pvs (version definition section)\n";
	while ($line = <PVS>) {
		chomp $line;
		if ($line =~ /^[^\s]+\s+-\s+([^:]+):\s*([^\s;]+)/) {
		    my $ver = $1;
		    my $sym = $2;

		    next if $ver =~ /private/i;

		    if ($opt{o}) {
			onbld_elfmod::OutMsg($InfoFH, $InfoTtl, $RelPath,
			    "VERSION=$ver, SYMBOL=$sym");
		    } else {
			if ($cur_ver ne $ver) {
			    onbld_elfmod::OutMsg($InfoFH, $InfoTtl,
			        $RelPath, "VERSION=$ver");
			    $cur_ver = $ver;
			}			    
			onbld_elfmod::OutMsg($InfoFH, $InfoTtl,
			    $RelPath, "SYMBOL=$sym");
		    }
		}
	}
	
	close PVS;
}


## OpenFindElf(file, FileHandleRef, LineNumRef)
#
# Open file in 'find_elf -r' format, and return the value of
# the opening PREFIX line.
#
# entry:
#	file - file, or find_elf child process, to open
#	FileHandleRef - Reference to file handle to open
#	LineNumRef - Reference to integer to increment as lines are input
#
# exit:
#	This routine issues a fatal error and does not return on error.
#	Otherwise, the value of PREFIX is returned.
#
sub OpenFindElf {
	my ($file, $fh, $LineNum) = @_;
	my $line;
	my $prefix;

	open($fh, $file) || die "$Prog: Unable to open: $file";
	$$LineNum = 0;

	# This script requires relative paths as created by 'find_elf -r'.
	# When this is done, the first non-comment line will always
	# be PREFIX. Obtain that line, or issue a fatal error.
	while ($line = onbld_elfmod::GetLine($fh, $LineNum)) {
		if ($line =~ /^PREFIX\s+(.*)$/i) {
			$prefix = $1;
			last;
		}

		die "$Prog: No PREFIX line seen on line $$LineNum: $file";
	}

	$prefix;
}


## ProcFindElf(file)
#
# Open the specified file, which must be produced by "find_elf -r",
# and process the files it describes.
#
sub ProcFindElf {
	my $file = $_[0];
	my $line;
	my $LineNum;

	my $prefix = OpenFindElf($file, \*FIND_ELF, \$LineNum);

	while ($line = onbld_elfmod::GetLine(\*FIND_ELF, \$LineNum)) {
		next if !($line =~ /^OBJECT\s/i);

		my ($item, $class, $type, $verdef, $obj) =
		    split(/\s+/, $line, 5);

		ProcFile("$prefix/$obj", $obj, $class, $type, $verdef);
	}

	close FIND_ELF;
}


## AltObjectConfig(file)
#
# Recurse through a directory hierarchy looking for appropriate dependencies
# to map from their standard system locations to the proto area via a crle
# config file.
#
# entry:
#	file - File of ELF objects, in 'find_elf -r' format, to examine.
#
# exit:
#	Scripts are generated for the 32 and 64-bit cases to run crle
#	and create runtime configuration files that will establish
#	alternative dependency mappings for the objects identified.
#
#	$Env - Set to environment variable definitions that will cause
#		the config files generated by this routine to be used
#		by ldd.
#	$Conf32, $Conf64 - Undefined, or set to the config files generated
#		by this routine. If defined, the caller is responsible for
#		unlinking the files before exiting.
#
sub AltObjectConfig {
	my $file = $_[0];
	my ($Crle32, $Crle64);
	my $line;
	my $LineNum;
	my $obj_path;
	my $obj_active = 0;
	my $obj_class;

	my $prefix = OpenFindElf($file, \*FIND_ELF);

LINE:
	while ($line = onbld_elfmod::GetLine(\*FIND_ELF, \$LineNum)) {
	      ITEM: {

			if ($line =~ /^OBJECT\s/i) {
				my ($item, $class, $type, $verdef, $obj) =
				    split(/\s+/, $line, 5);

				if ($type eq 'DYN') {
					$obj_active = 1;
					$obj_path = $obj;
					$obj_class = $class;
				} else {
					# Only want sharable objects
					$obj_active = 0;
				}
				last ITEM;
			}

			# We need to follow links to sharable objects so
			# that any dependencies are expressed in all their
			# available forms. We depend on ALIAS lines directly
			# following the object they alias, so if we have
			# a current object, this alias belongs to it.
			if ($obj_active && ($line =~ /^ALIAS\s/i)) {
				my ($item, $real_obj, $obj) =
				    split(/\s+/, $line, 3);
				$obj_path = $obj;
				last ITEM;
			}

			# Skip unrecognized item
			next LINE;
		}

		next if !$obj_active;

		my $full = "$prefix/$obj_path";

		next if defined($EXRE_nocrlealt) &&
		    ($obj_path =~ $EXRE_nocrlealt);

		my $Dir = $full;
		$Dir =~ s/^(.*)\/.*$/$1/;

		# Create a crle(1) script for the dependency we've found.
		# We build separate scripts for the 32 and 64-bit cases.
		# We create and initialize each script when we encounter
		# the first object that needs it.
		if ($obj_class == 32) {
			if (!$Crle32) {
				$Crle32 = "$Tmpdir/$Prog.crle32.$$";
				open(CRLE32, "> $Crle32") ||
				    die "$Prog: open failed: $Crle32: $!";
				print CRLE32 "#!/bin/sh\ncrle \\\n";
			}
			print CRLE32 "\t-o $Dir -a /$obj_path \\\n";
		} elsif ($Ena64) {
			if (!$Crle64) {
				$Crle64 = "$Tmpdir/$Prog.crle64.$$";
				open(CRLE64, "> $Crle64") ||
				    die "$Prog: open failed: $Crle64: $!";
				print CRLE64 "#!/bin/sh\ncrle -64\\\n";
			}
			print CRLE64 "\t-o $Dir -a /$obj_path \\\n";
		}
	}

	close FIND_ELF;


	# Now that the config scripts are complete, use them to generate
	# runtime linker config files.
	if ($Crle64) {
		$Conf64 = "$Tmpdir/$Prog.conf64.$$";
		print CRLE64 "\t-c $Conf64\n";

		chmod 0755, $Crle64;
		close CRLE64;

		undef $Conf64 if system($Crle64);

		# Done with the script
		unlink $Crle64;
	}
	if ($Crle32) {
		$Conf32 = "$Tmpdir/$Prog.conf32.$$";
		print CRLE32 "\t-c $Conf32\n";

		chmod 0755, $Crle32;
		close CRLE32;

		undef $Conf32 if system($Crle32);

		# Done with the script
		unlink $Crle32;
	}

	# Set $Env so that we will use the config files generated above
	# when we run ldd.
	if ($Crle64 && $Conf64 && $Crle32 && $Conf32) {
		$Env = "-e LD_FLAGS=config_64=$Conf64,config_32=$Conf32";
	} elsif ($Crle64 && $Conf64) {
		$Env = "-e LD_FLAGS=config_64=$Conf64";
	} elsif ($Crle32 && $Conf32) {
		$Env = "-e LD_FLAGS=config_32=$Conf32";
	}
}

# -----------------------------------------------------------------------------

# This script relies on ldd returning output reflecting only the binary 
# contents.  But if LD_PRELOAD* environment variables are present, libraries
# named by them will also appear in the output, disrupting our analysis.
# So, before we get too far, scrub the environment.

delete($ENV{LD_PRELOAD});
delete($ENV{LD_PRELOAD_32});
delete($ENV{LD_PRELOAD_64});

# Establish a program name for any error diagnostics.
chomp($Prog = `basename $0`);

# The onbld_elfmod package is maintained in the same directory as this
# script, and is installed in ../lib/perl. Use the local one if present,
# and the installed one otherwise.
my $moddir = dirname($0);
$moddir = "$moddir/../lib/perl" if ! -f "$moddir/onbld_elfmod.pm";
require "$moddir/onbld_elfmod.pm";

# Determine what machinery is available.
my $Mach = `uname -p`;
my$Isalist = `isalist`;
if ($Mach =~ /sparc/) {
	if ($Isalist =~ /sparcv9/) {
		$Ena64 = "ok";
	}
} elsif ($Mach =~ /i386/) {
	if ($Isalist =~ /amd64/) {
		$Ena64 = "ok";
	}
}

# $Env is used with all calls to ldd. It is set by AltObjectConfig to
# cause an alternate object mapping runtime config file to be used.
$Env = '';

# Check that we have arguments.
if ((getopts('D:d:E:e:f:I:imosvw:', \%opt) == 0) ||
    (!$opt{f} && ($#ARGV == -1))) {
	print "usage: $Prog [-imosv] [-D depfile | -d depdir] [-E errfile]\n";
	print "\t\t[-e exfile] [-f listfile] [-I infofile] [-w outdir]\n";
	print "\t\t[file | dir]...\n";
	print "\n";
	print "\t[-D depfile]\testablish dependencies from 'find_elf -r' file list\n";
	print "\t[-d depdir]\testablish dependencies from under directory\n";
	print "\t[-E errfile]\tdirect error output to file\n";
	print "\t[-e exfile]\texceptions file\n";
	print "\t[-f listfile]\tuse file list produced by find_elf -r\n";
	print "\t[-I infofile]\tdirect informational output (-i, -v) to file\n";
	print "\t[-i]\t\tproduce dynamic table entry information\n";
	print "\t[-m]\t\tprocess mcs(1) comments\n";
	print "\t[-o]\t\tproduce one-liner output (prefixed with pathname)\n";
	print "\t[-s]\t\tprocess .stab and .symtab entries\n";
	print "\t[-v]\t\tprocess version definition entries\n";
	print "\t[-w outdir]\tinterpret all files relative to given directory\n";
	exit 1;
}

die "$Prog: -D and -d options are mutually exclusive\n" if ($opt{D} && $opt{d});

$Tmpdir = "/tmp" if (!($Tmpdir = $ENV{TMPDIR}) || (! -d $Tmpdir));

# If -w, change working directory to given location
!$opt{w} || chdir($opt{w}) || die "$Prog: can't cd to $opt{w}";

# Locate and process the exceptions file
onbld_elfmod::LoadExceptionsToEXRE('check_rtime');

# Is there a proto area available, either via the -d option, or because
# we are part of an activated workspace?
my $Proto;
if ($opt{d}) {
	# User specified dependency directory - make sure it exists.
	-d $opt{d} || die "$Prog: $opt{d} is not a directory\n";
	$Proto = $opt{d};
} elsif ($ENV{CODEMGR_WS}) {
	my $Root;

	# Without a user specified dependency directory see if we're
	# part of a codemanager workspace and if a proto area exists.
	$Proto = $Root if ($Root = $ENV{ROOT}) && (-d $Root);
}

# If we are basing this analysis off the sharable objects found in
# a proto area, then gather dependencies and construct an alternative
# dependency mapping via a crle(1) configuration file.
#
# To support alternative dependency mapping we'll need ldd(1)'s
# -e option.  This is relatively new (s81_30), so make sure
# ldd(1) is capable before gathering any dependency information.
if ($opt{D} || $Proto) {
	if (system('ldd -e /usr/lib/lddstub 2> /dev/null')) {
		print "ldd: does not support -e, unable to ";
		print "create alternative dependency mappingings.\n";
		print "ldd: option added under 4390308 (s81_30).\n\n";
	} else {
		# If -D was specified, it supplies a list of files in
		# 'find_elf -r' format, and can use it directly. Otherwise,
		# we will run find_elf as a child process to find the
		# sharable objects found under $Proto.
		AltObjectConfig($opt{D} ? $opt{D} : "find_elf -frs $Proto|");
	}
}

# To support unreferenced dependency detection we'll need ldd(1)'s -U
# option.  This is relatively new (4638070), and if not available we
# can still fall back to -u.  Even with this option, don't use -U with
# releases prior to 5.10 as the cleanup for -U use only got integrated
# into 5.10 under 4642023.  Note, that nightly doesn't typically set a
# RELEASE from the standard <env> files.  Users who wish to disable use
# of ldd(1)'s -U should set (or uncomment) RELEASE in their <env> file
# if using nightly, or otherwise establish it in their environment.
if (system('ldd -U /usr/lib/lddstub 2> /dev/null')) {
	$LddNoU = 1;
} else {
	my($Release);

	if (($Release = $ENV{RELEASE}) && (cmp_os_ver($Release, "<", "5.10"))) {
		$LddNoU = 1;
	} else {
		$LddNoU = 0;
	}
}

# Set up variables used to handle output files:
#
# Error messages go to stdout unless -E is specified. $ErrFH is a
# file handle reference that points at the file handle where error messages
# are sent, and $ErrTtl is a reference that points at an integer used
# to count how many lines have been sent there.
#
# Informational messages go to stdout unless -I is specified. $InfoFH is a
# file handle reference that points at the file handle where info messages
# are sent, and $InfoTtl is a reference that points at an integer used
# to count how many lines have been sent there.
#
if ($opt{E}) {
	open(ERROR, ">$opt{E}") || die "$Prog: open failed: $opt{E}";
	$ErrFH = \*ERROR;
} else {
	$ErrFH = \*STDOUT;
}

if ($opt{I}) {
	open(INFO, ">$opt{I}") || die "$Prog: open failed: $opt{I}";
	$InfoFH = \*INFO;
} else {
	$InfoFH = \*STDOUT;
}
my ($err_dev, $err_ino) = stat($ErrFH);
my ($info_dev, $info_ino) = stat($InfoFH);
$ErrTtl = \$OutCnt1;
$InfoTtl = (($err_dev == $info_dev) && ($err_ino == $info_ino)) ?
    \$OutCnt1 : \$OutCnt2;


# If we were given a list of objects in 'find_elf -r' format, then
# process it.
ProcFindElf($opt{f}) if $opt{f};

# Process each argument
foreach my $Arg (@ARGV) {
	# Run find_elf to find the files given by $Arg and process them
	ProcFindElf("find_elf -fr $Arg|");
}

# Cleanup output files
unlink $Conf64 if $Conf64;
unlink $Conf32 if $Conf32;
close ERROR if $opt{E};
close INFO if $opt{I};

exit 0;
