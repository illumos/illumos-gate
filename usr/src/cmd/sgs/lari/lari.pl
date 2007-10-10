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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Link Analysis of Runtime Interfaces.
#

# Define all global variables (required for strict)
use vars  qw($Prog $DestDir $ObjRef $ObjFlag $ObjSize $ObjVis $TmpDir);
use vars  qw($LddArgs $SymFlag);
use vars  qw($Glob $Intp $Dirc $Cpyr $Prot $Extn $Self $Gfte $Plta $User $Func);
use vars  qw($Sfte $Afte $Objt $Nodi $Osft $Oaft $Ssft $Saft $Msft);
use vars  qw($Rtld $GlobWeak $MultSyms $CrtSyms $Platform $DbgSeed %opt);

# Global arrays that must be cleared for multi input file use.
use vars  qw(%Symbols %Objects %Versioned %DemSyms %ObjFltrs %SymFltes);

use strict;

use Getopt::Std;
use File::Basename;

# Pattern match to skip the runtime linker.
$Rtld = qr{
	/lib/ld\.so\.1 |
	/usr/lib/ld\.so\.1 |
	/lib/sparcv9/ld\.so\.1 |
	/usr/lib/sparcv9/ld\.so\.1 |
	/lib/amd64/ld\.so\.1 |
	/usr/lib/amd64/ld\.so\.1
}x;

# Pattern matching required to determine a global symbol.
$GlobWeak = qr{ ^(?:
	GLOB |
	WEAK
	)$
}x;

# Pattern matching to determine link-editor specific symbols and those common
# to the compilation environment (ie. provided by all crt's).
$MultSyms = qr{ ^(?:
	 _DYNAMIC |
	 _GLOBAL_OFFSET_TABLE_ |
	 _PROCEDURE_LINKAGE_TABLE_ |
	 _etext |
	 _edata |
	 _end |
	 _init |
	 _fini |
	 _lib_version |			# Defined in values
	 __xpg4 |			# Defined in values
	 __xpg6				# Defined in values
	)$
}x;

$CrtSyms = qr{ ^(?:
	 ___Argv |			# Defined in crt
	 __environ_lock |		# Defined in crt
	 _environ |			# Defined in crt
	 environ			# Defined in crt
	 )$
}x;

# Symbol flags.
$Glob = 0x00001;	# symbol is global
$Sfte = 0x00002;	# symbol is a filtee backing a standard filter
$Afte = 0x00004;	# symbol is a filtee backing a auxiliary filter
$Gfte = 0x00008;	# symbol bound as a filtee
$Intp = 0x00010;	# symbol originates from explicit interposer
$Dirc = 0x00020;	# symbol bound to directly
$Cpyr = 0x00040;	# symbol bound to copy-relocation reference
$Prot = 0x00080;	# symbol is protected (symbolic)
$Extn = 0x00100;	# symbol has been bound to from an external reference
$Self = 0x00200;	# symbol has been bound to from the same object
$Plta = 0x00800;	# symbol bound to executables plt address
$User = 0x01000;	# symbol binding originates from user (dlsym) request
$Func = 0x02000;	# symbol is of type function
$Objt = 0x04000;	# symbol is of type object
$Nodi = 0x08000;	# symbol prohibits direct binding

$Osft = 0x10000;	# symbol is an standard object filter
$Oaft = 0x20000;	# symbol is an auxiliary object filter
$Ssft = 0x40000;	# symbol is a per-symbol standard filter
$Saft = 0x80000;	# symbol is a per-symbol auxiliary filter
$Msft = 0xf0000;	# filter mask

# Offsets into $Symbols{$SymName}{$Obj} array.
$ObjRef =	0;
$ObjFlag =	1;
$ObjSize =	2;
$ObjVis =	3;

# Offset into $SymFltr{$SymName}{$Filtee} array.
$SymFlag = 	0;

# Establish locale
use POSIX qw(locale_h);
use Sun::Solaris::Utils qw(textdomain gettext);

setlocale(LC_ALL, "");
textdomain("SUNW_OST_SGS");

# Establish a program name for any error diagnostics.
$Prog = basename($0);

sub inappropriate {
	my ($Opt1, $Opt2, $Flag) = @_;

	if ($Flag) {
	    printf STDERR
		gettext("%s: inappropriate use of %s with %s: %s ignored\n"),
		$Prog, $Opt1, $Opt2, $Opt1;
	} else {
	    printf STDERR
		gettext("%s: inappropriate use of %s without %s: %s ignored\n"),
		$Prog, $Opt1, $Opt2, $Opt1;
	}
}

# Cleanup any temporary files on interruption.
sub Cleanup {
	my ($Sig) = @_;

	$SIG{$Sig} = 'IGNORE';

	if ($DbgSeed ne "") {
		foreach my $File (<\Q${DbgSeed}\E.*>) {
			if ($File =~ /^\Q$DbgSeed\E\.\d+$/) {
				unlink($File);
			}
		}
	}
	exit 1;
}

# Check that we have arguments.
if ((getopts('abCDd:imosVv', \%opt) == 0) || ($#ARGV < 0)) {
	printf STDERR gettext("usage:\n");
	printf STDERR
	    gettext("    %s [-bCDsVv] [-a | -i | -o ] file | dir ...\n"), $Prog;
	printf STDERR
	    gettext("    %s [-CDosVv] [-m [-d mapdir]] file\n"), $Prog;
	print STDERR
	    gettext("\t[-a]     print diagnostics for all symbols\n");
	print STDERR
	    gettext("\t[-b]     limit diagnostics to bound symbols\n");
	print STDERR
	    gettext("\t[-C]     print demangled symbol names also\n");
	print STDERR
	    gettext("\t[-D]     read debugging information from \"file\"\n");
	print STDERR
	    gettext("\t[-d dir] create mapfiles in \"mapdir\"\n");
	print STDERR
	    gettext("\t[-i]     print interesting information (default)\n");
	print STDERR
	    gettext("\t[-m]     create mapfiles for interface requirements\n");
	print STDERR
	    gettext("\t[-o]     limit diagnostics to overhead information\n");
	print STDERR
	    gettext("\t[-s]     save bindings information created by ldd(1)\n");
	print STDERR
	    gettext("\t[-V]     append interesting symbol visibilities\n");
	print STDERR
	    gettext("\t[-v]     ignore versioned objects\n");
	exit 1;
} else {
	my ($Mult, $Error);

	# Catch any incompatible argument usage.
	if ($opt{m}) {
		if ($opt{a}) {
			inappropriate("-a", "-m", 1);
			$opt{a} = 0;
		}
		if ($opt{i}) {
			inappropriate("-i", "-m", 1);
			$opt{i} = 0;
		}
	} else {
		if ($opt{d}) {
			inappropriate("-d", "-m", 0);
			$opt{d} = 0;
		}
	}
	if ($opt{a}) {
		if ($opt{o}) {
			inappropriate("-a", "-o", 1);
			$opt{o} = 0;
		}
		if ($opt{i}) {
			inappropriate("-a", "-i", 1);
			$opt{i} = 0;
		}
	}
	if ($opt{o}) {
		if ($opt{i}) {
			inappropriate("-o", "-i", 1);
			$opt{i} = 0;
		}
		if ($opt{b}) {
			inappropriate("-o", "-b", 1);
			$opt{b} = 0;
		}
	}

	# If -m is used, only one input file is applicable.
	if ($opt{m} && ($#ARGV != 0)) {
		printf STDERR gettext("%s: only one input file is allowed " .
		    "with the -m option\n"), $Prog;
		exit 1;
	}

	# Insure any specified directory exists, or apply a default.
	if ($opt{d}) {
		# User specified directory - make sure it exists.
		if (! -d $opt{d}) {
			printf STDERR gettext("%s: %s is not a directory\n"),
			    $Prog, $opt{d};
			exit 1;
		}
		$DestDir = $opt{d};
	} else {
		$DestDir = ".";
	}

	# Establish a temporary directory if necessary.
	if (!$opt{D}) {
		if (!($TmpDir = $ENV{TMPDIR}) || (! -d $TmpDir)) {
			$TmpDir = "/tmp";
		}
	}

	# Establish any initial ldd(1) argument requirements.
	if ($LddArgs = $ENV{LARI_LDD_ARGS}) {
		$LddArgs = $LddArgs . ' -r -e LD_DEBUG=bindings,files,detail';
	} else {
		$LddArgs = '-r -e LD_DEBUG=bindings,files,detail';
	}

	# If we've been asked to demangle symbols, make sure we can find the
	# demangler.
	if ($opt{C}) {
		my ($DemName) = `dem XXXX 2> /dev/null`;
		if (!$DemName) {
			printf STDERR gettext("%s: can not locate demangler: " .
			    "-C ignored\n"), $Prog;
			$opt{C} = 0;
		}
	}

	# If -a or -o hasn't been specified, default to -i.
	if (!$opt{a} && !$opt{o}) {
		$opt{i} = 1;
	}

	# Determine whether we have multiple input files.
	if ($#ARGV == 0) {
		$Mult = 0;
	} else {
		$Mult = 1;
	}

	# Determine what platform we're running on - some inappropriate
	# platform specific dependencies are better skipped.
	chomp($Platform = `uname -i`);

	# Establish signal handlers
	$SIG{INT} = \&Cleanup;
	$SIG{QUIT} = \&Cleanup;

	$DbgSeed = "";

	# For each argument determine if we're dealing with a file or directory.
	$Error = 0;
	foreach my $Arg (@ARGV) {
		if (!stat($Arg)) {
			printf STDERR gettext("%s: %s: unable to stat file\n"),
			    $Prog, $Arg;
			$Error = 1;
			next;
		}

		# Process simple files.
		if (-f _) {
			if (!-r _) {
				printf STDERR gettext("%s: %s: unable to " .
				   "read file\n"), $Prog, $Arg;
				$Error = 1;
				next;
			}
			if (!$opt{D}) {
				if (ProcFile($Arg, $Mult, 1) == 0) {
					$Error = 1;
				}
			} else {
				# If the -D option is specified, read the
				# bindings debugging information from the
				# specified file.
				if ($Mult) {
					print STDOUT "$Arg:\n";
				}
				ProcBindings($Arg, $Mult, $Arg);
			}
			next;
		}

		# Process directories.
		if (-d _) {
			ProcDir($Arg);
			next;
		}

		printf STDERR gettext("%s: %s: is not a file or directory\n"),
		    $Prog, $Arg;
		$Error = 1;
	}
	exit $Error;
}

sub ProcDir {
	my ($Dir) = @_;
	my ($File);

	# Open the directory and read each entry, omit "." and "..".  Sorting
	# the directory listing makes analyzing different source hierarchies
	# easier.
	if (opendir(DIR, $Dir)) {
		foreach my $Entry (sort(readdir(DIR))) {
			if (($Entry eq '.') || ($Entry eq '..')) {
				next;
			}

			# If we're descending into a platform directory, ignore
			# any inappropriate platform specific files.  These
			# files can have dependencies that in turn bring in the
			# appropriate platform specific file, resulting in more
			# than one dependency offering the same interfaces.  In
			# practice, the non-appropriate platform specific file
			# wouldn't be loaded with a process.
			if (($Dir =~ /\/platform$/) &&
			    ($Entry !~ /^$Platform$/)) {
				next;
			}

			$File = "$Dir/$Entry";
			if (!lstat($File)) {
				next;
			}
			# Ignore symlinks.
			if (-l _) {
				next;
			}

			# Descend into, and process any directories.
			if (-d _) {
				ProcDir($File);
				next;
			}
			
			# Process any standard files.
			if (-f _ && -r _) {
				ProcFile($File, 1, 0);
				next;

			}
		}
		closedir(DIR);
	}
}

# Process a file.  If the file was explicitly defined on the command-line, and
# an error occurs, tell the user.  Otherwise, this file probably came about from
# scanning a directory, in which case just skip it and move on.
sub ProcFile {
	my ($File, $Mult, $CmdLine) = @_;
	my (@Ldd, $NoFound, $DbgFile, @DbgGlob, $Type);

	# If we're scanning a directory (ie. /lib) and have picked up ld.so.1,
	# ignore it.
	if (($CmdLine eq 0) && ($File =~ $Rtld)) {
		return 1;
	}

	$Type = `LC_ALL=C file '$File' 2>&1`;
	if (($Type !~ /dynamically linked/) || ($Type =~ /Sun demand paged/)) {
		if ($CmdLine) {
			printf STDERR gettext("%s: %s: is an invalid file " .
			    "type\n"), $Prog, $File;
		}
		return 0;
	}

	# Create a temporary filename for capturing binding information.
	$DbgSeed = basename($File);
	$DbgSeed = "$TmpDir/lari.dbg.$$.$DbgSeed";

	# Exercise the file under ldd(1), capturing all the bindings.
	@Ldd = split(/\n/,
	    `LC_ALL=C ldd $LddArgs -e LD_DEBUG_OUTPUT='$DbgSeed' '$File' 2>&1`);

	# If ldd isn't -e capable we'll get a usage message.  The -e option was
	# introduced in Solaris 9 and related patches.  Also, make sure the user
	# sees any ldd errors.
	$NoFound = 0;
	for my $Line (@Ldd) {
		if ($Line =~ /^usage: ldd/) {
			printf STDERR gettext("%s: ldd: does not support -e, " .
			    "unable to capture bindings output\n"), $Prog;
			exit 1;
		}
		if ($Line =~ /not found/) {
			$NoFound = 1;
			last;
		}
	}

	# The runtime linker will have appended a process id to the debug file.
	# As we have to intuit the name, make sure there is only one debug
	# file match, otherwise there must be some clutter in the output
	# directory that is going to mess up our analysis.
	foreach my $Match (<\Q${DbgSeed}\E.*>) {
		if ($Match =~ /^\Q$DbgSeed\E\.\d+$/) {
			push(@DbgGlob, $Match);
		}
	}
	if (@DbgGlob == 0) {
		# If there is no debug file, bail.  This can occur if the file
		# being processed is secure.
		if ($CmdLine) {
			printf STDERR gettext("%s: %s: unable to capture " .
			    "bindings output - possible secure application?\n"),
			    $Prog, $File; 
		}
		return 0;
	} elsif (@DbgGlob > 1) {
		# Too many debug files found.
		if ($CmdLine) {
			printf STDERR gettext("%s: %s: multiple bindings " .
			    "output files exist: %s: clean up temporary " .
			    "directory\n"), $Prog, $File, $DbgSeed;
		}
		return 0;
	} else {
		$DbgFile = $DbgGlob[0];
	}

	# Ok, we're ready to process the bindings information.  Print a header
	# if necessary, and if there were any ldd(1) errors push some of them
	# out before any bindings information.  Limit the output, as it can
	# sometimes be excessive.  If there are errors, the bindings information
	# is likely to be incomplete.
	if ($Mult) {
		print STDOUT "$File:\n";
	}
	if ($NoFound) {
		my ($Cnt) = 4;

		for my $Line (@Ldd) {
			if ($Line =~ /not found/) {
				print STDOUT "$Line\n";
				$Cnt--;
			}
			if ($Cnt == 0) {
				print STDOUT gettext("\tcontinued ...\n");
				last;
			}
		}
	}

	# If the user wants the original debugging file left behind, rename it
	# so that it doesn't get re-read by another instance of lari processing
	# this file.
	if ($opt{s}) {
		rename($DbgFile, $DbgSeed);
		$DbgFile = $DbgSeed;
		printf STDOUT gettext("%s: %s: bindings information " .
		    "saved as: %s\n"), $Prog, $File, $DbgFile;
	}

	ProcBindings($File, $Mult, $DbgFile);

	# Now that we've finished with the debugging file, nuke it if necessary.
	if (!$opt{s}) {
		unlink($DbgFile);
	}
	$DbgSeed = "";
	return 1;
}

sub ProcBindings {
	my ($File, $Mult, $DbgFile) = @_;
	my (%Filtees, $FileHandle);

	# Reinitialize our arrays when we're dealing with multiple files.
	if ($Mult) {
		%Symbols = ();
		%Objects = ();
		%Versioned = ();
		%DemSyms = ();
		%ObjFltrs = ();
		%SymFltes = ();
	}

	# As debugging output can be significant, read a line at a time.
	open($FileHandle, "<$DbgFile");
	while (defined(my $Line = <$FileHandle>)) {
		chomp($Line);

		# Collect the symbols from any file analyzed.
		if ($Line =~ /^.*: file=(.*);  analyzing .*/) {
			GetAllSymbols($1);
			next;
		}

		# Process any symbolic relocations that bind to a file.
		if ($Line =~ /: binding file=.* to file=/) {
			my ($RefFile, $DstFile, $SymName);
			my (@Syms, $Found, @Fields);
			my ($BndInfo) = 0;
			my ($Offset) = 1;
			my ($Dlsym) = 0;
			my ($Detail) = 0;

			# For greatest flexibility, split the line into fields
			# and walk each field until we find what we need.
			@Fields = split(' ', $Line);

			# The referencing file, "... binding file=".*".
			while ($Fields[$Offset]) {
				if ($Fields[$Offset] =~ /^file=(.*)/) {
					$RefFile = $1;
					$Offset++;
					last;
				}
				$Offset++;
			}
			# The referencing offset, typically this is the address
			# of the reference, "(0x1234...)", but in the case of a
			# user lookup it's the string "(dlsym)".  If we don't
			# find this offset information we've been given a debug
			# file that didn't use the "detail" token, in which case
			# we're not getting all the information we need.
			if ($Fields[$Offset] =~ /^\((.*)\)/) {
				if ($1 eq 'dlsym') {
					$Dlsym = 1;
				}
				$Detail = 1;
				$Offset++;
			}
			# The destination file, "... to file=".*".
			while ($Fields[$Offset]) {
				if ($Fields[$Offset] =~ /^file=(.*)/) {
					$DstFile = $1;
					$Offset++;
					last;
				}
				$Offset++;
			}
			# The symbol being bound, "... symbol `.*' ...".
			while ($Fields[$Offset]) {
				if ($Fields[$Offset] =~ /^\`(.*)\'$/) {
					$SymName = $1;
					$Offset++;
					last;
				}
				$Offset++;
			}
			# Possible trailing binding info, "... (direct,.*)$".
			while ($Fields[$Offset]) {
				if ($Fields[$Offset] =~ /^\((.*)\)$/) {
					$BndInfo = $1;
					$Offset++;
					last;
				}
				$Offset++;
			}

			if ($Detail == 0) {
				printf STDERR gettext("%s: %s: debug file " .
				    "does not contain `detail' information\n"),
				    $Prog, $DbgFile;
				return;
			}

			# Collect the symbols from each object.
			GetAllSymbols($RefFile);
			GetAllSymbols($DstFile);

			# Identify that this definition has been bound to.
			$Symbols{$SymName}{$DstFile}[$ObjRef]++;
			if ($RefFile eq $DstFile) {
				# If the reference binds to a definition within
				# the same file this symbol may be a candidate
				# for reducing to local.
				$Symbols{$SymName}{$DstFile}[$ObjFlag] |= $Self;
				$Objects{$DstFile}{$SymName} |= $Self;
			} else {
				# This symbol is required to satisfy an external
				# reference.
				$Symbols{$SymName}{$DstFile}[$ObjFlag] |= $Extn;
				$Objects{$DstFile}{$SymName} |= $Extn;
			}

			# Assign any other state indicated by the binding info
			# associated with the diagnostic output.
			if (!$BndInfo) {
				next;
			}

			if ($BndInfo =~ /direct/) {
				$Symbols{$SymName}{$DstFile}[$ObjFlag] |= $Dirc;
				$Objects{$DstFile}{$SymName} |= $Dirc;
			}
			if ($BndInfo =~ /copy-ref/) {
				$Symbols{$SymName}{$DstFile}[$ObjFlag] |= $Cpyr;
				$Objects{$DstFile}{$SymName} |= $Cpyr;
			}
			if ($BndInfo =~ /filtee/) {
				$Symbols{$SymName}{$DstFile}[$ObjFlag] |= $Gfte;
				$Objects{$DstFile}{$SymName} |= $Gfte;
			}
			if ($BndInfo =~ /interpose/) {
				$Symbols{$SymName}{$DstFile}[$ObjFlag] |= $Intp;
				$Objects{$DstFile}{$SymName} |= $Intp;
			}
			if ($BndInfo =~ /plt-addr/) {
				$Symbols{$SymName}{$DstFile}[$ObjFlag] |= $Plta;
				$Objects{$DstFile}{$SymName} |= $Plta;
			}
			if ($Dlsym) {
				$Symbols{$SymName}{$DstFile}[$ObjFlag] |= $User;
				$Objects{$DstFile}{$SymName} |= $User;
			}
		}
	}
	close($FileHandle);

	# Now that we've processed all objects, traverse the set of object
	# filters that have been captured from parsing any FILTER and AUXILIARY
	# dynamic tags.  For each filtee, determine which of the symbols it
	# exports are also defined in the filter.  If a filter is bound to, the
	# runtime linkers diagnostics will indicate a filtee binding.  However,
	# some of the filtee symbols may not be bound to, so here we mark them
	# all so as to remove them from any interesting output.
	for my $Filter (keys(%ObjFltrs)) {

		# Determine the filtees that are associated with this filter.
		for my $Filtee (keys(%{$ObjFltrs{$Filter}})) {
			my ($FileName);

			# Reduce the filtee to a simple file name.  Then, try
			# and associate this simple file name with the objects
			# that have been processed.  These objects are typically
			# recorded with a full path name.
			chomp($FileName = `basename $Filtee`);
			for my $Obj (keys(%Objects)) {
				if ($Obj =~ /\/$FileName$/) {
					$Filtee = $Obj;
					last;
				}
			}

			if (!exists($Objects{$Filtee})) {
				next;
			}

			# Traverse the symbols of the filtee (these are
			# typically a smaller set than the filter) and if the
			# symbol is defined by the filter tag the symbol as a
			# filtee.
			for my $SymName (keys(%{$Objects{$Filtee}})) {
				my ($OFlag, $FFlag);

				# Ignore the usual stuff.
				if (($SymName =~ $MultSyms) ||
				    ($SymName =~ $CrtSyms)) {
					next;
				}

				if (!$Symbols{$SymName}{$Filter}) {
					next;
				}

				# Determine the type of filter.
				$OFlag = $Symbols{$SymName}{$Filter}[$ObjFlag];

				# Specifically identify the type of filtee we
				# have and remove any generic filtee flag.
				if ($OFlag & ($Osft | $Ssft)) {
					$FFlag = $Sfte;
				} else {
					$FFlag = $Afte;
				}

				$Symbols{$SymName}{$Filtee}[$ObjFlag] |= $FFlag;
				$Symbols{$SymName}{$Filtee}[$ObjFlag] &= ~$Gfte;
			}
		}
	}

	# Traverse the set of per-symbol filters making sure we've tagged any
	# associated filtee symbols, as we did above for object filters.
	for my $Filtee (keys(%SymFltes)) {
		my ($FullPath) = $Filtee;
		my ($FileName);

		# Reduce the filtee to a simple file name.  Then, try and
		# associate this simple file name with the objects that have
		# been processed.  These objects are typically recorded with a
		# full path name.
		chomp($FileName = `basename $Filtee`);
		for my $Obj (keys(%Objects)) {
			if ($Obj =~ /\/$FileName$/) {
				$FullPath = $Obj;
				last;
			}
		}

		if (!exists($Objects{$FullPath})) {
			next;
		}

		for my $SymName (keys(%{$SymFltes{$Filtee}})) {
			my ($OFlag, $FFlag);

			# Determine the type of filter.
			$OFlag = $SymFltes{$Filtee}{$SymName}[$SymFlag];

			# Specifically identify the type of filtee we have and
			# remove any generic filtee flag.
			if ($OFlag & $Ssft) {
				$FFlag = $Sfte;
			} else {
				$FFlag = $Afte;
			}

			$Symbols{$SymName}{$FullPath}[$ObjFlag] |= $FFlag;
			$Symbols{$SymName}{$FullPath}[$ObjFlag] &= ~$Gfte;
		}
	}

	# Process objects and their symbols as required.
	if ($opt{m}) {
		# If we're creating a mapfile, traverse each object we've
		# collected.
		foreach my $Obj (keys(%Objects)) {
			my ($File, $Path);

			# Skip any objects that should be ignored.
			if ($Obj =~ $Rtld) {
				next;
			}

			# Skip any versioned objects if required.
			if ($opt{v} && $Versioned{$Obj}) {
				next;
			}

			# Open the mapfile if required.
			$File = basename($Obj);
			$Path = "$DestDir/mapfile-$File";
			if (!open(MAPOUT, "> $Path")) {
				printf STDERR gettext("%s: %s: open failed:" .
				    "%s\n"), $Prog, $Path, $!;
				exit 1;
			}

			# Establish the mapfile preamble.
			print MAPOUT "#\n# Interface Definition mapfile for:\n";
			print MAPOUT "#\tDynamic Object: $Obj\n";
			print MAPOUT "#\tProcess:        $File\n#\n\n";

			# Process each global symbol.
			print MAPOUT "$File {\n\tglobal:\n";

			foreach my $SymName (sort(keys(%{$Objects{$Obj}}))) {
				my ($Flag) = $Objects{$Obj}{$SymName};

				# For the first pass we're only interested in
				# symbols that have been bound to from an
				# external object, or must be global to enable
				# a binding to an interposing definition.
				# Skip bindings to ourself, as these are
				# candidates for demoting to local.
				if (!($Flag & ($Extn | $Intp))) {
					next;
				}
				if (($Flag & ($Extn | $Self)) == $Self) {
					next;
				}

				# Add the demangled name as a comment if
				# required.
				if ($opt{C}) {
					my ($DemName) = Demangle($SymName);

					if ($DemName ne "") {
						print MAPOUT "\t\t#$DemName\n";
					}
				}
				print MAPOUT "\t\t$SymName;\n";
			}

			# Process each local demotion.
			print MAPOUT "\tlocal:\n";

			if ($opt{o}) {
				foreach my $SymName
				    (sort(keys(%{$Objects{$Obj}}))) {
					my ($Flag) = $Objects{$Obj}{$SymName};

					# For this pass we're only interested
					# in symbol definitions that haven't
					# been bound to, or have only been
					# bound to from the same object.
					if ($Flag & $Extn) {
						next;
					}

					# Add the demangled name as a comment if
					# required.
					if ($opt{C}) {
						my ($DemName) =
						    Demangle($SymName);

						if ($DemName ne "") {
							print MAPOUT
							    "\t\t#$DemName\n";
						}
					}
					print MAPOUT "\t\t$SymName;\n";
				}
			}

			# Capture everything else as local.
			print MAPOUT "\t\t\*;\n};\n";
			close MAPOUT;
		}

	} else {
		# If we're gathering information regarding the symbols used by
		# the process, automatically sort any standard output using the
		# symbol name.
		if (!open(SORT, "| sort +1")) {
			printf STDERR gettext("%s: fork failed: %s\n"),
			    $Prog, $!;
			exit 1;
		}

		foreach my $SymName (keys(%Symbols)) {
			my ($Cnt);
			
			# If we're looking for interesting symbols, inspect
			# each definition of each symbol.  If one is found to
			# be interesting, the whole family are printed.
			if (($Cnt = Interesting($SymName)) == 0) {
				next;
			}

			# We've found something interesting, or all symbols
			# should be output.  List all objects that define this
			# symbol.
			foreach my $Obj (keys(%{$Symbols{$SymName}})) {
				my ($DemName, $Type);
				my ($Flag) = $Symbols{$SymName}{$Obj}[$ObjFlag];
				my ($Str) = "$Cnt:";
				my ($Vis);
				my ($DisVis) = "";

				# Do we just want overhead symbols.  Consider
				# copy-relocations, and plt address binding,
				# as overhead too.
				if ($opt{o} && (($Flag &
				    ($Extn | $Cpyr | $Plta)) == $Extn)) {
					next;
				}

				# Do we just want all symbols that have been
				# bound to.
				if (($opt{a} || $opt{o}) && $opt{b} &&
				    (($Flag & ($Extn | $Self | $Prot)) == 0)) {
					next;
				}

				# If we haven't been asked for all symbols, only
				# print those reserved symbols that have been
				# bound to, as the number of reserved symbols
				# can be quite excessive.  Also, remove any
				# standard filters, as nothing can bind to these
				# symbols anyway.
				if (!$opt{a} && ((($SymName =~ $MultSyms) &&
				    (($Flag & ($Extn | $Self)) == 0)) ||
				    (($SymName =~ $CrtSyms) && (($Flag &
				    ($Extn | $Self | $Prot)) == 0)) ||
				    ($Flag & ($Ssft | $Osft)))) {
					next;
				}

				# Skip any versioned objects if required.
				if ($opt{v} && $Versioned{$Obj}) {
					next;
				}

				# Display this symbol.
				if ($Symbols{$SymName}{$Obj}[$ObjRef]) {
					$Str = $Str . 
					    $Symbols{$SymName}{$Obj}[$ObjRef];
				} else {
					$Str = $Str . '0';
				}

				# Has the symbol been bound to externally
				if ($Flag & $Extn) {
					$Str = $Str . 'E';
				}
				# Has the symbol been bound to from the same
				# object.
				if ($Flag & $Self) {
					$Str = $Str . 'S';
				}
				# Has the symbol been bound to directly.
				if ($Flag & $Dirc) {
					$Str = $Str . 'D';
				}
				# Does this symbol originate for an explicit
				# interposer.
				if ($Flag & $Intp) {
					$Str = $Str . 'I';
				}
				# Is this symbol the reference data of a copy
				# relocation.
				if ($Flag & $Cpyr) {
					$Str = $Str . 'C';
				}
				# Is this symbol part of filtee.
				if ($Flag & ($Sfte | $Afte | $Gfte)) {
					$Str = $Str . 'F';
				}
				# Is this symbol protected (in which case there
				# may be a symbolic binding within the same
				# object to this symbol).
				if ($Flag & $Prot) {
					$Str = $Str . 'P';
				}
				# Is this symbol an executables .plt address.
				if ($Flag & $Plta) {
					$Str = $Str . 'A';
				}
				# Does this binding originate from a user
				# (dlsym) request.
				if ($Flag & $User) {
					$Str = $Str . 'U';
				}
				# Does this definition redirect the binding.
				if ($Flag & $Msft) {
					$Str = $Str . 'R';
				}
				# Does this definition explicitly define no
				# direct binding.
				if ($Flag & $Nodi) {
					$Str = $Str . 'N';
				}

				# Determine whether this is a function or a data
				# object.  For the latter, display the symbol
				# size.  Otherwise, the symbol is a reserved
				# label, and is left untyped.
				if ($Flag & $Func) {
					$Type = '()';
				} elsif ($Flag & $Objt) {
					$Type = '[' .
					    $Symbols{$SymName}{$Obj}[$ObjSize] .
					']';
				} else {
					$Type = "";
				}

				# Demangle the symbol name if desired.
				$DemName = Demangle($SymName);

				# If symbol visibility differences are
				# interesting, append the verbose representation
				# of any interesting visibilities.
				$Vis = $Symbols{$SymName}{$Obj}[$ObjVis];
				if ($opt{V} && $Vis) {
					if ($Vis =~ 'S') {
						$DisVis = "  (singleton)";
					} elsif ($Vis =~ 'P') {
						$DisVis = "  (protected)";
					}
				}
				if ($Mult) {
					print SORT "  [$Str]: " .
					    "$SymName$Type$DemName: " .
					    "$Obj$DisVis\n";
				} else {
					print SORT "[$Str]: " .
					    "$SymName$Type$DemName: " .
					    "$Obj$DisVis\n";
				}
			}
		}
		close SORT;
	}
}

# Heuristics to determine whether a symbol binding is interesting.  In most
# applications there can be a large amount of symbol binding information to
# wade through.  The most typical binding, to a single definition, probably
# isn't interesting or the cause of unexpected behavior.  Here, we try and
# determine those bindings that may can cause unexpected behavior.
#
# Note, this routine is actually called for all symbols so that their count
# can be calculated in one place.
sub Interesting
{
	my ($SymName) = @_;
	my ($ObjCnt, $GFlags, $BndCnt, $FltCnt, $NodiCnt, $RdirCnt, $ExRef);
	my ($TotCnt);

	# Scan all definitions of this symbol, thus determining the definition
	# count, the number of filters, redirections, executable references
	# (copy-relocations, or plt addresses), no-direct bindings, and the
	# number of definitions that have been bound to.
	$ObjCnt = $GFlags = $BndCnt = $FltCnt =
	    $NodiCnt = $RdirCnt = $ExRef = $TotCnt = 0;
	foreach my $Obj (keys(%{$Symbols{$SymName}})) {
		my ($Flag) = $Symbols{$SymName}{$Obj}[$ObjFlag];

		$TotCnt++;

		# Ignore standard filters when determining the symbol count, as
		# a standard filter can never be bound to.
		if (($Flag & ($Osft | $Ssft)) == 0) {
			$ObjCnt++;
		}

		# If we're only looking at interesting objects, then standard
		# filters are ignored, so suppress any standard filtee tagging.
		if (!$opt{a}) {
			$Flag = $Symbols{$SymName}{$Obj}[$ObjFlag] &= ~$Sfte;
		}

		$GFlags |= $Flag;
		if ($Flag & ($Sfte | $Afte | $Gfte)) {
			$FltCnt++;
		}
		if ($Flag & $Nodi) {
			$NodiCnt++;
		}
		if ($Flag & ($Cpyr | $Plta)) {
			$ExRef++;
		}
		if ($Flag & $Msft) {
			$RdirCnt++;
		}

		# Ignore bindings to undefined .plts, and copy-relocation
		# references.  These are implementation details, rather than
		# a truly interesting multiple-binding.  If a symbol is tagged
		# as protected, count it as having bound to itself, even though
		# we can't tell if it's really been used.
		if (($Flag & ($Self | $Extn | $Prot)) &&
		    (($Flag & ($Plta | $Cpyr)) == 0)) {
			$BndCnt++;
		}
	}

	# If we want all overhead symbols, return the count.
	if ($opt{o}) {
		return $ObjCnt;
	}

	# If we want all symbols, return the count.  If we want all bound
	# symbols, return the count provided it is non-zero.
	if ($opt{a} && (!$opt{b} || ($BndCnt > 0))) {
		return $TotCnt;
	}

	# Single instance symbol definitions aren't very interesting.
	if ($ObjCnt == 1) {
		return 0;
	}

	# Traverse each symbol definition looking for the following:
	#
	#   .	Multiple symbols are bound to externally.
	#   .	A symbol is bound to externally, and possibly symbolically.
	#
	# Two symbol bindings are acceptable in some cases, and thus aren't
	# interesting:
	#
	#   .	Copy relocations.  Here, the executable binds to a shared object
	#	to access the data definition, which is then copied to the
	#	executable.  All other references should then bind to the copied
	#	data.
	#   .	Non-plt relocations to functions that are referenced by the
	#	executable will bind to the .plt in the executable.  This
	#	provides for address comparison calculations (although plainly
	#	an overhead).
	#
	# Multiple symbol bindings are acceptable in some cases, and thus aren't
	# interesting:
	#
	#   .	Filtees.  Multiple filtees may exist for one filter.
	#
	if ((($ObjCnt == 2) && ($GFlags & ($Cpyr | $Plta))) ||
	    ($ObjCnt == ($FltCnt + 1))) {
		return 0;
	}

	# Only display any reserved symbols if more than one binding has
	# occurred.
	if ((($SymName =~ $MultSyms) || ($SymName =~ $CrtSyms)) &&
	    ($BndCnt < 2)) {
		return (0);
	}

	# For all other symbols, determine whether a binding has occurred.
	# Note: definitions within an executable are tagged as protected ("P")
	# as they may have been bound to from within the executable - we can't
	# tell.
	if ($opt{b} && ($BndCnt == 0)) {
		return (0);
	}

	# Multiple instances of a definition, where all but one are filter
	# references and/or copy relocations, are also uninteresting.
	# Effectively, only one symbol is providing the final binding.
	if (($FltCnt && $RdirCnt) &&
	    (($FltCnt + $RdirCnt + $ExRef) == $ObjCnt)) {
		return (0);
	}

	# Multiple instances of explicitly defined no-direct binding symbols
	# are known to occur, and their no-binding definition indicates they
	# are expected and accounted for.  Thus, these aren't interesting.
	if (($ExRef + $NodiCnt) == $ObjCnt) {
		return (0);
	}

	# We have an interesting symbol, returns its count.
	return $ObjCnt;
}

# Obtain the global symbol definitions of an object and determine whether the
# object has been versioned.
sub GetAllSymbols {
	my ($Obj) = @_;
	my ($Type, $FileHandle);
	my (%AddrToName, %NameToAddr);
	my ($Exec) = 0;
	my ($Vers) = 0;
	my ($Symb) = 0;
	my ($Copy) = 0;
	my ($Interpose) = 0;
	my ($Fltr) = 0;
	my ($Ehdr) = 0;
	my ($Dyn) = 0;
	my ($Rel) = 0;
	my ($Info) = 0;

	# Determine whether we've already retrieved this object's symbols.
	# Also, ignore the runtime linker, it's on a separate link-map, and
	# except for the filtee symbols that might be bound via libdl, is
	# uninteresting.  Tag the runtime linker as versioned to simplify
	# possible -v processing.
	if ($Objects{$Obj}) {
		return;
	}

	if ($Obj =~ $Rtld) {
		$Versioned{$Obj} = 1;
		return;
	}

	# Get as much ELF information as we can from elfdump(1).  A second
	# invocation of elfdump(1) is required to obtain the symbol table, whose
	# processing can be affected by states determined during this pass.
	#
	# The information required:
	#	-e	ELF header provides the file type
	#	-d	dynamic information provides filter names 
	#	-r	relocations provide for copy relocations
	#	-y	symbol information section provide pre-symbol filters
	#		and direct binding information
	#
	# As this information can be quite large, process the elfdump(1) output
	# through a pipe.
	open($FileHandle, "LC_ALL=C elfdump -edry '$Obj' 2> /dev/null |");

	while (defined(my $Line = <$FileHandle>)) {
		my (@Fields);

		chomp($Line);

		# Each collection of data is preceded with a title that
		# starts in column 0.  Items of data all have some form of
		# indentation.
		if ($Line =~ /^[A-Z]/) {
			if ($Line =~ /^ELF Header/) {
				$Ehdr = 1;
				$Dyn = $Rel = $Info = 0;
			} elsif ($Line =~ /^Dynamic Section:/) {
				$Dyn = 1;
				$Ehdr = $Rel = $Info = 0;
			} elsif ($Line =~ /^Relocation Section:/) {
				$Rel = 1;
				$Ehdr = $Dyn = $Info = 0;
			} elsif ($Line =~ /^Syminfo Section:/) {
				$Info = 1;
				$Ehdr = $Dyn = $Rel = 0;
			} else {
				$Ehdr = $Dyn = $Rel = $Info = 0;
			}
			next;
		}

		# Inspect the ELF header.
		if ($Ehdr eq 1) {
			# Determine the ELF file type from the e_type element.
			if ($Line =~ /e_type:/) {
				if ($Line =~ /ET_EXEC/) {
					$Exec = 1;
				}

				# There's nothing of interest left in the ELF
				# header, so skip processing other entries.
				$Ehdr = 0;
				next;
			}
		}

		# Inspect the .dynamic section.
		if ($Dyn eq 1) {
			@Fields = split(' ', $Line);

			# Determine if the FILTER or AUXILIARY tag is set.
			if ($#Fields == 3) {
				my ($Flte) = 0;

				if ($Fields[1] eq 'FILTER') {
					$Fltr |= $Osft;
					$Flte = 1;
				}
				elsif ($Fields[1] eq 'AUXILIARY') {
					$Fltr |= $Oaft;
					$Flte = 1;
				}
				if ($Flte eq 1) {
					my (@Filtees) = split(':', $Fields[3]);

					for my $Filtee (@Filtees) {
						if ($Filtee =~ $Rtld) {
							next;
						}
						$ObjFltrs{$Obj}{$Filtee} = 1;
					}
				}
				next;
			}

			# We're only interested in the FLAGS entry.
			if (($#Fields < 4) || ($Fields[1] !~ /^FLAGS/)) {
				next;
			}

			# Determine whether we've got a symbolicly bound object.
			# With newer link-editors, all symbols will be marked as
			# protected ("P"), but with older link-editors this
			# state could only be inferred from the symbolic dynamic
			# tag.
			if (($Fields[1] eq 'FLAGS') &&
			    ($Line =~ / SYMBOLIC /)) {
				$Symb = 1;
				next;
			}

			# Determine whether this object is an interposer.
			if (($Fields[1] eq 'FLAGS_1') &&
			    ($Line =~ / OBJECT-INTERPOSE /)) {
				$Interpose = 1;
				next;
			}
			next;
		}

		# Inspect the relocation information.  As we're only looking
		# for copy relocations, this processing is only necessary for
		# executables.
		if ($Rel eq 1) {
			my ($SymName);

			if ($Exec eq 0) {
				$Rel = 0;
				next;
			}

			# Obtain any copy relocations.
			if ($Line !~ / R_[A-Z0-9]+_COPY /) {
				next;
			}

			@Fields = split(' ', $Line);

			# Intel relocation records don't contain an addend,
			# where as every other supported platform does.
			if ($Fields[0] eq 'R_386_COPY') {
				$SymName = $Fields[3];
			} else {
				$SymName = $Fields[4];
			}

			$Symbols{$SymName}{$Obj}[$ObjFlag] |= $Cpyr;
			$Objects{$Obj}{$SymName} |= $Cpyr;
			$Copy = 1;
		}

		# Inspect the .SUNW_syminfo section.
		if ($Info eq 1) {
			my ($SymName);
			my ($Flags) = 0;

			@Fields = split(' ', $Line);

			# Binding attributes are in the second column.
			if ($#Fields < 1) {
				next;
			}
			if ($Fields[1] =~ /N/) {
				$Flags |= $Nodi;
			}
			if ($Fields[1] =~ /F/) {
				$Flags |= $Ssft;
			}
			if ($Fields[1] =~ /A/) {
				$Flags |= $Saft;
			}
			if ($Fields[1] =~ /I/) {
				$Flags |= $Intp;
			}

			# Determine the symbol name based upon the number of
			# fields.
			if ($Flags) {
				$SymName = $Fields[$#Fields];
				$Symbols{$SymName}{$Obj}[$ObjFlag] |= $Flags;
				$Objects{$Obj}{$SymName} |= $Flags;
			}

			# If this is a filter, we need to tag the associated
			# filtee symbol.  However, the filtee might not have
			# been processed yet, so save this information for later.
			$Flags &= ~($Nodi | $Intp);
			if ($Flags) {
				my ($Filtee) = $Fields[$#Fields - 1];

				if ($Filtee =~ $Rtld) {
					next;
				}
				$SymFltes{$Filtee}{$SymName}[$SymFlag] = $Flags;
			}
		}
	}

	close($FileHandle);

	# If there's no expected information, it's possible we've been given a
	# debug output file and are processing the file from a location from
	# which the dependencies specified in the debug file aren't accessible.
	if ($Dyn eq 0) {
		printf STDERR gettext("%s: %s: unable to process ELF file\n"),
		    $Prog, $Obj;

		# Add the file to our list, so that we don't create the same
		# message again.  Processing should continue so that we can
		# flush out as many error messages as possible.
		$Objects{$Obj}{"DoesNotExist"} = 0;
		return;
	}

	# Process elfdump(1) once more to obtain the .dynsym symbol table. We
	# are only interested in global symbols, so .SUNW_ldynsym is not needed.
	open($FileHandle, "LC_ALL=C elfdump -sN.dynsym '$Obj' 2> /dev/null |");

	while (defined(my $Line = <$FileHandle>)) {
		chomp($Line);

		my (@Fields) = split(' ', $Line);
		my ($Flags);

		# We're only interested in defined symbol entries.  Unless
		# we've been asked for all symbols, ignore any ABS or NOTY
		# symbols.  The former are typically reserved symbols or
		# versioning names.  The latter are labels that are not bound
		# to.  Note, ABS and NOTY symbols of non-zero size have been
		# known to occur, so capture them.
		if (($#Fields < 8) || ($Fields[4] !~ $GlobWeak) ||
		    ($Fields[7] eq 'UNDEF') ||
		    (!$opt{a} && (oct($Fields[2]) eq 0) &&
		    ((($Fields[7] eq 'ABS') && ($Fields[3] eq 'OBJT')) ||
		    ($Fields[3] eq 'NOTY')))) {
			next;
		}

		# If we're found copy relocations, save the address of all OBJT
		# definitions, together with the copy symbol.  These definitions
		# are used to determine whether the copy symbol has any aliases
		# (ie. __iob and _iob).
		if (($Copy eq 1) && ($Fields[3] eq 'OBJT')) {
			push(@{$AddrToName{$Fields[1]}}, $Fields[8]);

			if (($Symbols{$Fields[8]}{$Obj}) &&
			    ($Symbols{$Fields[8]}{$Obj}[$ObjFlag] & $Cpyr)) {
				$NameToAddr{$Fields[8]} = $Fields[1];
			}
		}

		# Identify this symbol as global, and associate it with any
		# object filtering.
		$Flags = $Glob | $Fltr;

		# If the symbol visibility is protected, this is an internal
		# symbolic binding.  Note, an INTERNAL visibility for a global
		# symbol is invalid, but for a while ld(1) was setting this
		# attribute mistakenly for protected.  If this is a dynamic
		# executable, mark its symbols as protected.  These symbols
		# can't be interposed on any more than symbols defined as
		# protected within shared objects).
		if (($Fields[5] =~ /^[IP]$/) || $Symb || $Exec) {
			$Flags |= $Prot;
		}

		# If this object is marked as an interposer, tag each symbol.
		if ($Interpose) {
			$Flags |= $Intp;
		}

		# Identify the symbol as a function or data type, and for the
		# latter, capture the symbol size.  Ignore the standard symbolic
		# labels, as we don't want to type them.
		if ($Fields[8] !~ $MultSyms) {
			if ($Fields[3] =~ /^FUNC$/) {
				$Flags |= $Func;
			} elsif ($Fields[3] =~ /^OBJT$/) {
				my ($Size) = $Fields[2];

				if (oct($Size) eq 0) {
					$Size = "0";
				} else {
					$Size =~ s/0x0*/0x/;
				}
				$Flags |= $Objt;
				$Symbols{$Fields[8]}{$Obj}[$ObjSize] = $Size;
			}
		}

		$Symbols{$Fields[8]}{$Obj}[$ObjFlag] |= $Flags;
		$Symbols{$Fields[8]}{$Obj}[$ObjVis] = $Fields[5];
		$Objects{$Obj}{$Fields[8]} |= $Flags;

		# If the version field is non-null this object has already been
		# versioned.
		if (($Vers == 0) && ($Fields[6] ne '0')) {
			$Versioned{$Obj} = 1;
			$Vers = 1;
		}
	}
	close($FileHandle);

	# Process any copy relocation symbols to see if the copy symbol has any
	# aliases, which should also be marked as copy relocations.
	if ($Copy) {
		foreach my $SymName (keys(%NameToAddr)) {
			my ($Addr) = $NameToAddr{$SymName};

			# Determine all symbols that have the same address.
			foreach my $AliasName (@{$AddrToName{$Addr}}) {
				if ($SymName eq $AliasName) {
					next;
				}
				$Symbols{$AliasName}{$Obj}[$ObjFlag] |= $Cpyr;
				$Objects{$Obj}{$AliasName} |= $Cpyr;
			}
		}
	}
}

# Demangle a symbol name if required.
sub Demangle
{
	my ($SymName) = @_;
	my ($DemName);

	if ($opt{C}) {
		my (@Dem);
		
		# Determine if we've already demangled this name.
		if (exists($DemSyms{$SymName})) {
			return $DemSyms{$SymName};
		}

		@Dem = split(/\n/, `dem '$SymName'`);
		foreach my $Line (@Dem) {
			my (@Fields) = split(' ', $Line);

			if (($#Fields < 2) || ($Fields[1] ne '==') ||
			    ($Fields[0] eq $Fields[2])) {
				next;
			}
			$DemName = $Line;
			$DemName =~ s/.*== (.*)$/ \[$1]/;
			$DemSyms{$SymName} = $DemName;
			return($DemName);
		}
	}
	$DemSyms{$SymName} = "";
	return("");
}
