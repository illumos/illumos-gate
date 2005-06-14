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
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#
# Check versioning information.
#
# This script descends a directory hierarchy inspecting ELF shared objects for
# version definitions.  The general theme is to verify that common versioning
# rules have been used to build these objects.
#
# As always, a number of components don't follow the rules, and these are
# excluded to reduce this scripts output.  Pathnames used for this exclusion
# assume this script is being run over a "proto" area.
#
# Besides the default operation of checking the files within a directory
# hierarchy, a detailed analysis of each files versions can be created with the
# -d option.  The database created is useful for auditing the difference between
# different builds, and for thus monitoring that versioning changes are made in
# a compatible manner.
#
# Shared objects containing public interfaces should have an associated .3lib
# man page.  The -m option generates a template sgml man file (under the
# directory specified by -d) for each public shared object found.


# Define all global variables (required for strict)

use vars  qw($SkipManFiles $SkipProfile);
use vars  qw($Mandir $Error $Pub32 $Pub64 $Auddir $Prog $Version);
use vars  qw($IntfDir);
use vars  qw(%opt);

# Vars needed for data handling and exceptions processing
use Env   qw(SRC);
use vars  qw($DbPath $Data_Dir $Log_File $Exceptions_File $Lib_Log_File);
use vars  qw(%RuleHash %LibHash %LibSym %Lib);

use strict;

# hash of error messages.  These RULES are interfaces used by the exception
# lists and documented in the manpage.  Only additions may be made
# to this RuleHash.
#
# (See RULES and OUTPUT MESSAGES sections of intf_check manpage for details)
%RuleHash = (
	'RULE E1'  => 'non-standard version name',
	'RULE E2'  => 'invalid inheritance',
	'RULE E3'  => 'was public .* unexported',
	'RULE E4'  => 'was public .* private',
	'RULE E5'  => 'invalid new version',
	'RULE E6'  => 'base version not maintained',
	'RULE E7'  => 'inconsistent increment of version',
	'RULE E8'  => 'no SONAME recorded',
	'RULE E9'  => 'SONAME recorded differs from the actual filename',
	'RULE E10' => 'invalid version name, should be .* major version',
	'RULE E11' => 'invalid library filename; should not use minor version
			number (.*) as part of filename',
	'RULE E12' => 'new public interface introduced to the obsolete library',
	'RULE W1'  => 'does not have a versioned name',
	'RULE W2'  => 'no compilation symlink \(\.so\) exists',
	'RULE W3'  => 'unnecessary compilation symlink \(\.so\) exists',
	'RULE W4'  => 'no versions found',
	'RULE W5'  => 'version offers no interfaces',
	'RULE W6'  => 'was private .* unexported',
	'RULE W7'  => 'new public interface introduced',
	'RULE W8'  => 'was private .* public',
	'RULE W9' => 'new private interface introduced to the obsolete library',
	'RULE W10' => 'library is not found',
);


# Define any files whose public interfaces we should skip.
$SkipProfile = qr{
	etc/lib/libdl.so.1 |		# Already accounted for with usr/lib.
	usr/lib/libp/ |			# Profiled versions of standard libs.
	/abi/ |				# skip all abi interceptor libraries.
	usr/perl5/
}x;

# Define any files whose man pages we should skip.
$SkipManFiles = qr{ ^(?:
	lib300.so.1 |			# Accounted for with libplot(3lib).
	lib300s.so.1 |			# Accounted for with libplot(3lib).
	lib4014.so.1 |			# Accounted for with libplot(3lib).
	lib450.so.1 |			# Accounted for with libplot(3lib).
	libvt0.so.1 |			# Accounted for with libplot(3lib).
	libcrypt_d.so.1			# Accounted for with libcrypt(3lib).
	)$
}x;

use POSIX qw(getenv);
use Getopt::Std;
use File::Basename;
use FileHandle;
autoflush STDOUT 1;
autoflush STDERR 1;

# --------------------- Main Program -----------------------------------------

# Establish a program name for any error diagnostics.
$Prog = basename($0);

# Define version of this tool
$Version = "VERSION 1.0";

$Error = 0;

GetOptions();

SetupIntfDir();

# once the intf-dir is setup, the Log_File is ready
open(LOG, "> $Log_File") || die "$Prog: open failed: $Log_File: $!";

FindDataDir();

SetupRefDb();

# set up a temporary profile of all the libraries found under the test
# directory.
$Lib_Log_File = "/tmp/abi_audit_lib_log";
if (-f "$Lib_Log_File") {
	unlink $Lib_Log_File;
}
open(LIBLOG, "> $Lib_Log_File") || die "$Prog: open failed: $Lib_Log_File: $!";

IntfCheck();

# Lib_Log_File needs to be closed for abi_audit program to read.
close(LIBLOG);

# Log_File needs to be closed for abi_audit program to append to this file.
close(LOG);

# Call to abi_audit program
AbiAudit();

# filter exceptions
LoadExceptions();

ProcessExceptions();

CleanUp();

exit $Error;

# --------------------- Subroutines start here --------------------------------
#
# Prints usage message to stdout
#
sub Usage
{
	print <<EOF;

usage:	$Prog [-ahimopstTV] [-d intf-dir] [-b ABI_DB_path | -A sparc | i386]
	[-g ABI_DB_filename] [-r release] file | dir, ...

	-a	Prints all releases associated with the Solaris ABI
		database file
	-b ABI_DB_path
		Directory containing ABI_*.db, exceptions files
	-d intf-dir
		Directory to deposit interface information
	-g ABI_DB_filename
		Generate an ABI database file ABI_DB_filename
	-h	Prints out the usage information
	-i	Perform Integrity Checking
	-m	Add manpage material to interface information
	-o	Check for omissions
	-p	Report new public interfaces introduced as WARNING
	-r release
		Provide the current build/release name
	-s	Silence all WARNING messages
	-t	Report symbol transitions from private to public as ERROR
	-T	Report symbol transitions from private to unexported as WARNING
	-A sparc | i386
		Perform checking against a platform specific ABI database
		Any name other than i386 and sparc is ignored as an usage error
	-V	Report version number of this tool

	Note, specifying the -V and -a options do not require file(s)/dir(s)
	operand(s).

EOF
	exit 1;
}

#
# Check that we have arguments.
#

sub GetOptions
{

	# options used in auditing portion include g:in:opr:st.  These args
	# are processed in AbiAudit() subroutine.
	# options used in intf_check profiling portion
	if (getopts('ab:d:mr:sopA:V?hg:in:tT', \%opt) == 0 || $opt{'?'} ||
	    $opt{h}) {
		Usage();
	}

	if (!@ARGV && !$opt{V} && !$opt{a}) {
		Usage();
	}

	# Ensure the argument passed into options are valid.
	# i.e., the argument may not be another option tag.
	if (($opt{d} && $opt{d} =~ /^-/) ||
	    ($opt{b} && $opt{b} =~ /^-/) ||
	    ($opt{n} && $opt{n} =~ /^-/) ||
	    ($opt{g} && $opt{g} =~ /^-/) ||
	    ($opt{r} && $opt{r} =~ /^-/)) {
		Usage();
	}

	if ($opt{V}) {
		# Version is printed to STDOUT
		print "$Version\n";

		# -V option is specified w/out any file(s)/dir(s)
		if (!@ARGV) {
			exit 0;
		}
	}

	if ($opt{m} && !$opt{d}) {
		print "-m option must be accompanied by -d\n";
		Usage();
	}

	if (($opt{r} && !$opt{g}) ||
	    ($opt{g} && !$opt{r})) {
		print "-r option must be accompanied by -g\n";
		Usage();
	}

	# -n, -b, -A are mutually exclusive.  Ensure at most
	# of the options is specified.
	my ($count) = 0;
	foreach my $option ($opt{n}, $opt{b}, $opt{A}) {
		if ($option) {
			$count ++;
		}
	}

	if ($count > 1) {
		print "-A and -b are mutually exclusive\n";
		Usage();
	}

}


#
# Setup all files and directories associated with the intf-dir.  By default,
# intf-dir is created under /tmp/abi_audit.$$.  Under intf-dir, the
# following files/dirs are created:
#
#		tmplog.$$   - temporary report of ERROR/WARNING messages
#		audit/	    - contains version databases
#		man/	    - if -m option is specified
#		$opt{r}.rel - empty release file.
#
sub SetupIntfDir
{
	my $release;

	# Create any interface output directories, or clean up any pre-existing
	# entries.
	if ($opt{d}) {
		$IntfDir = $opt{d};
	} else {
		$IntfDir = "/tmp/abi_audit.$$";
	}

	# Create intf-dir directory
	if (! -d "$IntfDir") {
		mkdir $IntfDir, 0755 or die "$Prog: mkdir failed: $IntfDir: $!";
	}

	# "tmplog.$$" file will contain all unprocessed ERRORS/WARNINGS.
	# It will be filtered by filter_errors() after call to the abi_audit
	# program
	$Log_File = "$IntfDir/tmplog.$$";
	if (-f "$Log_File") {
		unlink $Log_File;
	}

	# audit/ will contain all version databases generated by ProcFile()
	$Auddir = "$IntfDir/audit";
	if (! -d $Auddir) {
		mkdir $Auddir, 0755 or die "$Prog: mkdir failed: $Auddir: $!";
	} else {
		system("rm -fr $Auddir/*");
	}

	# man/ will contain all sgml man page templates.
	$Mandir = "$IntfDir/man";
	if ($opt{m}) {
		if (! -d $Mandir) {
			mkdir $Mandir, 0755 or
			    die "$Prog: mkdir failed: $Mandir: $!";
		} else {
			system("rm -fr $Mandir/*");
		}
	}

	# Create a release file (suffixed by ".rel").  This file is needed
	# when generating a new database.  It will be recognized as the release
	# file when abi_audit is processing the intf-dir.
	if ($opt{r}) {
		$release = $opt{r} . ".rel";
		system("touch $IntfDir/$release");
	}
}

#
# Find the directory containing all the ABI_*.db and exceptions files.
#
sub FindDataDir
{
	# directory containing data files
	my $etc_dir = "";

	if ($ENV{SRC}) {
		$etc_dir = $ENV{SRC};
	}
	$etc_dir .= "/tools/abi/etc";

	if ($opt{b} && -f "$opt{b}/exceptions" ) {

		# Path specified by -b contains the relevant datafiles
		$Data_Dir = $opt{b};

	} elsif (-d $etc_dir && -f "$etc_dir/exceptions") {

		# A workspace is defined
		$Data_Dir = $etc_dir;

	} else {
		# use the datafiles from the SUNWonbld package
		$Data_Dir = "/opt/onbld/etc/abi";
	}

	$Exceptions_File = "$Data_Dir/exceptions";
	# no exceptions file is present (either in the $opt{b} area,
	# $SRC/tools/abi/etc area, or under /opt/onbld/etc/abi)
	if (! -f "$Exceptions_File") {
		die "$Exceptions_File: No such file.";
	}

	if ($opt{b} && ! -f "$opt{b}/exceptions") {
		# path specified by -b does not contain all the relevant
		# datafiles
		ErrMsg("$opt{b}/exceptions", "No such file.  "
		    . "Using $Data_Dir/exceptions");
	}
}

#
# Options processing for the Reference database
#
sub SetupRefDb
{
	my $mach = "";
	my $arch = "";

	if ($ENV{MACH}) {
		$mach = $ENV{MACH};
	} else {
		$mach = `uname -p`;
	}

	# -A, specify the platform specific database to check against
	if ($opt{A}) {
		$arch = $opt{A};
		if ($arch =~ /i386/) {		# -Ai386, use intel database
			$DbPath = "$Data_Dir/ABI_i386.db";
		} elsif ($arch =~ /sparc/) {	# -Asparc, use sparc database
			$DbPath = "$Data_Dir/ABI_sparc.db";
		} else {
			print "Invalid option: -A $opt{A}\n";
			Usage();
		}

	# -n, specify alternate database
	} elsif ($opt{n}) {
		$DbPath = $opt{n};

	# by default, use the database correlated with the machine architecture
	# this script is run from.
	} else {
		if ($mach =~ /i386/) {
			$DbPath = "$Data_Dir/ABI_i386.db";
		} elsif ($mach =~ /sparc/) {
			$DbPath = "$Data_Dir/ABI_sparc.db";
		} else {
			$DbPath = "$Data_Dir/ABI_$mach\.db";
		}
	}

	if (! -f $DbPath) {
		die "$DbPath: $!";
	}

	# Functions requiring DbPath to be set
	if (!$opt{o}) {
		BuildLibHash();
	}

	if ($opt{a}) {
		# print releases associated with an ABI_DB_filename to STDOUT
		AbiDbRelease();

		# -a option is specified w/out any file(s)/dir(s)
		if (!@ARGV) {
			exit 0;
		}
	}
}

#
# Store all library names from reference database (e.g. ABI.db) into %LibHash.
# This will uniquify all the library names from the reference db.
#
sub BuildLibHash
{
	my ($line, $dir);

	open(LIBRARY, $DbPath) or die "$Prog: open failed: $DbPath: $!";

	# keys of hash are the library names
	foreach $line (<LIBRARY>) {
		my ($sym, $lib, $rest_of_line) = split(' ', $line);
		if (defined($lib)) {
			$LibHash{$lib} = 1;
		}
	}
	my $num_libs = scalar(keys %LibHash);

	close(LIBRARY);
}

#
# Collect all info from shared objects specified on the command line
#
sub IntfCheck
{
	# For each argument determine if we're dealing with a file or directory.
	foreach my $Arg (@ARGV) {

		if (-l $Arg) {
			next;
		}

		# Process simple files.
		if (-f $Arg) {
			my $RelPath = $Arg;

			# If $ROOT is set, for example;
			# $ROOT = /net/abi/export/xxx/./proto/root_sparc
			# $Arg =
			# /net/abi/export/xxx/./proto/root_sparc/lib/libc.so.1
			# $RelPath = ./lib/libc.so.1
			if ($ENV{ROOT}) {
				$RelPath =~ s/\Q$ENV{ROOT}\E//;
				$RelPath =~ s/^\.\///;
					
			}
			# For safety, eliminate "proto/root_sparc|i386/" path
			# if $ROOT is not set but user checks on file under
			# the proto area of any build workspace.
			if ($RelPath =~ /proto\/root_(sparc|i386)\/(.*)/) {
					$RelPath = $2;
			} else {
				if ($RelPath !~ /\//) {
					$RelPath = basename $Arg;
				}
			}

			ProcFile($Arg, $RelPath);
			next;
		}

		# Process directories.
		if (-d $Arg) {
			ProcDir($Arg, ".");
			next;
		}

		ErrMsg($Arg, "No such file or directory");
		$Error = 1;
	}
}


sub man
{
	my ($Len, $RelPath, $File, @Syms) = @_;
	my ($Man, $Col, $Cnt, $Num);

	if ($RelPath =~ $SkipProfile) {
		return;
	}
	if ($File =~ $SkipManFiles) {
		return;
	}

	# Establish the man page entry from the filename.  By maintaining the
	# directory structure in which the library is found multiple versions
	# of the same filename can be accommodated (ie. usr/lib/libcurses.so.1,
	# usr/ucblib/libcurses.so.1 and usr/xpg4/lib/libcurses.so.[12]).
	$RelPath =~ s/^\.\///;
	if ($RelPath =~ /\//) {
		$RelPath =~ s/(.*)\/.*/$Mandir\/$1/;
	} else {
		$RelPath = $Mandir;
	}

	if (! -d $RelPath) {
		system("mkdir -p $RelPath");
	}

	$Man = join('/', $RelPath, $File);
	open(MAN, "> $Man") || die "$Prog: open failed: $Man: $!";

	# Initialize the file with sufficient sgml to make it usable.
	print MAN "<!DOCTYPE REFENTRY PUBLIC \"-//Sun Microsystems//";
	print MAN "DTD DocBook V3.0-Based SolBook Subset V2.0//EN\">\n";
	print MAN "<refentry>\n";
	print MAN "<refmeta>\n";
	print MAN "<refentrytitle>$File</refentrytitle>";
	print MAN "<manvolnum>3LIB</manvolnum>\n";
	print MAN "</refmeta>\n";
	print MAN "<refsect1>\n";
	print MAN "<title>INTERFACES</title>\n";
	print MAN "<!-- OSNet - interface table begin -->\n";
	print MAN "<para>The shared object <filename>$File</filename>\n";
	print MAN "provides the public interfaces defined below.\nSee ";
	print MAN "<olink targetdocent=\"REFMAN3F\" localinfo=\"intro-3\">\n";
	print MAN "<citerefentry><refentrytitle>intro</refentrytitle>\n";
	print MAN "<manvolnum>3</manvolnum></citerefentry></olink>\n";
	print MAN "for additional information on shared object interfaces.\n";
	print MAN "</para>\n";

	# Determine the number of columns required based on the maximum length
	# of the interface names (note, we always create 2 columns at a minimum,
	# although the doc folks might still need to massage the output).
	if ($Len > 18) {
		$Col = 2;
	} elsif ($Len > 13) {
		$Col = 3;
	} elsif ($Len > 10) {
		$Col = 4;
	} elsif ($Len > 8) {
		$Col = 5;
	} elsif ($Len > 6) {
		$Col = 6;
	} elsif ($Len > 5) {
		$Col = 7;
	} else {
		$Col = 8;
	}

	# Compensate for man(1) inflexibility.
	if ($Col > 2) {
		--$Col;
	}

	print MAN "<informaltable frame=\"none\">\n";
	print MAN "<tgroup cols=\"$Col\" colsep=\"0\" rowsep=\"0\">\n";
	for ($Cnt = 0; $Cnt < $Col; ++$Cnt) {
		print MAN "<colspec colwidth=\"1*\" align=\"left\">\n";
	}
	print MAN "<tbody>\n";

	# Sort all our public interfaces and output the associated 3lib format.
	for ($Cnt = 1, $Num = 0; $Num <= $#Syms; ++$Cnt, ++$Num) {
		if ($Cnt == 1) {
			print MAN "<row>\n";
		}
		print MAN "<entry><literal>$Syms[$Num]</literal></entry>\n";
		if (($Cnt == $Col) && ($Num != $#Syms)) {
			print MAN "</row>\n";
			$Cnt = 0;
		}
	}

	# Finish off any sgml.
	print MAN "</row>\n</tbody>\n</tgroup>\n</informaltable>\n";
	print MAN "<!-- OSNet - interface table end -->\n";
	print MAN "</refsect1></refentry>\n";
	close MAN;
}


# Determine whether this a ELF dynamic object and if so investigate its runtime
# attributes.
sub ProcFile
{
	my ($FullPath, $RelPath) = @_;
	my (@Elf, @Pvs, @Vers, @Syms);
	my ($Aud, $Man, $Max, $Priv, $Pub, $Def, $Val, $Cls);
	my ($RelPath_File, $LibName, $Name, $File);

	if ($RelPath =~ $SkipProfile) {
		return;
	}

	# Way to recognize the difference between /usr/lib/libcurses.so.1 &
	# /usr/ucblib/libcurses.so.1
	# Translate $RelPath into a unique format $RelPath_File
	# i.e., /usr/lib/sparcv9/libc.so.1 to =usr=lib=sparcv9=libc.so.1
	$File = basename $FullPath;
	$RelPath_File = $RelPath;
	$RelPath_File =~ s/^\.\///;
	$Name = $RelPath_File;
	$RelPath_File =~ s/\//=/g;

	$LibName = GetLibraryName($FullPath, $RelPath, $File);
	$LibName =~ s/\//=/g;
	$Aud = "$Auddir/$LibName";

	# Determine whether we have a shared object, and whether version
	# definitions exist.
	@Elf = split(/\n/, `elfdump -ed '$FullPath' 2>&1`);

	$Val = $Def = 0;
	foreach my $Line (@Elf) {
		$Val++;

		# If we have an invalid file type, which we can tell from the
		# first line, bail.
		if (($Val == 1) && ($Line =~ /invalid file/)) {
			return;
		}

		# Look for the ei_class (line 4) for man page processing.
		if ($Val == 4) {
			if ($Line !~ /ei_class:/) {
				return;
			}
			if ($Line =~ /ELFCLASS32/) {
				$Cls = "-32";
			} else {
				$Cls = "-64";
			}
		}

		# Look for the e_type field (line 6) which indicates whether
		# this file is a shared object (ET_DYN).
		if ($Val == 6) {
			if ($Line !~ /e_type:/) {
				return;
			}
			if ($Line !~ /ET_DYN/) {
				return;
			}
			next;
		}

		# Look for the dynamic section (occurs after line 11) and
		# whether version definitions exist.
		if (($Val > 11) && ($Line =~ /VERDEF/)) {
			$Def = 1;
			last;
		}
	}

	# Does this object follow the runtime versioned name convention?
	# There are actually numerous instances of .so files, typically used
	# for dlopen() rather than linking against.  Although a versioned name
	# would be preferred, trying to change all these now won't happen.
	if ($File !~ /\.so\./ && !$opt{s} && !$opt{g}) {
		OutMsg($Name, "does not have a versioned name",
		    "WARNING");
	}

	# If there are no versions in the file we're done.
	if (($Def eq 0) && !$opt{s} && !$opt{g}) {
		OutMsg($Name, "no versions found", "WARNING");
		return;
	}

	# record library files under the test directory into LIBLOG to be
	# used by abi_audit program.
	print LIBLOG "$Name\n";

	# Check the version inheritance chain using "pvs -d" to ensure
	# that proper incrementing of the chain has occurred and that
	# the version string is named correctly.
	CheckVersInheritance($FullPath, $Name);

	# obtain the highest versions of the library so that abi_audit
	# can compare this version incrementing against the previous releases
	@Pvs = split(/\n/, `pvs -dn '$FullPath' 2>&1`);

	# This does not contain a match
	unlink $Aud;
	open(AUD, "> $Aud") || die "$Prog: open failed: $Aud: $!";

	# record all symbols inheriting the highest version of the library
	foreach my $Line (@Pvs) {
		my $Ver;
		# $Line equals to one line of output from pvs -dn , e.g.
		#  	SUNW_1.20.1;
		if ($Line =~ /^\s+(.*);$/) {
			$Ver = $1;
		}

		my @subpvs =
		    split(/\n/, `pvs -ds -N '$Ver' '$FullPath' 2>&1`);
		foreach my $Sym (@subpvs) {
			if ($Sym =~ /:$/) {
				next;
			}
			if ($Sym =~ /\s+(.*);$/) {
				$Sym = $1;
			}
			print AUD "$Ver: $Sym\n";
		}
	}

	# First determine what versions exist that offer interfaces.  pvs -dos
	# will list these.  Note that other versions may exist, ones that
	# don't offer interfaces ... we'll get to those next.
	@Pvs = split(/\n/, `pvs -dosl '$FullPath' 2>&1`);
	$Max = $Man = $Priv = $Pub = 0;
PVS1:	foreach my $Line (@Pvs) {
		my ($Ver) = $Line;
		my ($Sym) = $Line;
		my ($Siz);

		$Ver =~ s/.* -\t(.*): .*/$1/;	# isolate version
		$Sym =~ s/.* -\t.*: (.*);$/$1/;	# isolate symbol

		if ($Line =~ /no symbol table .* found/ ||
		    $Line =~ /pvs: warning.*unable to deduce reduced symbols/) {
			next PVS1;
		}

		print AUD "$Ver: $Sym\n";
		$Sym =~ s/ .*$//;			# remove any size
		$Siz = length($Sym);

		#  See if we've already caught this version name.
		foreach my $Vers (@Vers) {
			if ($Vers eq $Ver) {
				if ($opt{m} && $Man) {
					push(@Syms, $Sym);
					if ($Siz > $Max) {
						$Max = $Siz;
					}
				}
				next PVS1;
			}
		}
		$Vers[++$#Vers] = $Ver;

		# Capture any standard versions, and if necessary save the
		# interfaces they offer.
		if (PublicStr($Ver)) {
			$Pub = 1;
			if ($opt{m}) {
				$Man = 1;
				push(@Syms, $Sym);
				if ($Siz > $Max) {
					$Max = $Siz;
				}
			}
			next;
		}

		# Capture any private and "base" versions.  Each object exports
		# a "base" version which contains the linker generated symbols
		# _etext, _edata, etc., and is named using the objects SONAME.
		# This name should typically match the file name.  If it doesn't
		# we have a non-standard version name.  Be lenient with
		# SUNWprivate, they seem to have evolved into a world of
		# their own.

		if (PrivateStr($Ver) || (index($Ver, $File) == 0) ||
		    (index($File, $Ver) == 0)) {
			$Priv = 1;
			$Man = 0;
			next;
		}

		# Any versioned object contains a "base" version, this version
		# is defined with the files soname, which is typically pruned in
		# the above test against $File.  Continue to flag this as a non-
		# standard version name, but identify the symbols as private so
		# they don't get added to any interface definitions.

		if ($Sym eq "_etext" ||
		    $Sym eq "_edata" ||
		    $Sym eq "_end" ||
		    $Sym eq "_PROCEDURE_LINKAGE_TABLE_" ||
		    $Sym eq "_GLOBAL_OFFSET_TABLE_" ||
		    $Sym eq "_DYNAMIC") {
			$Priv = 1;
			$Man = 0;
			next;
		} else {
			# Any remaining interfaces are non-standard, but assume
			# they're public, so if necessary save the interfaces
			# they offer.
			$Pub = 1;
			if ($opt{m}) {
				$Man = 1;
				push(@Syms, $Sym);
				if ($Siz > $Max) {
					$Max = $Siz;
				}
			}
		}

		OutMsg($Name,
		    "$Ver: non-standard version name", "ERROR");
		next;
	}

	if ($File =~ /\.so\./) {
		my ($Link) = $FullPath;
		$Link =~ s/\.so\..*/\.so/;

		if (-l $Link) {
			my $is_shared_object =
			    `dump -Lv '$FullPath' | grep SONAME 2>&1`;
			if (defined($is_shared_object) && !$is_shared_object) {
				OutMsg($Name,
				    "no SONAME recorded", "ERROR");
			} else {
				if ($is_shared_object !~ /$File/) {
					OutMsg($Name,
					    "SONAME recorded differs " .
					    "from the actual filename",
					    "ERROR");
				}
			}
		}

		if ($Pub) {
			if ((! -l $Link) && !$opt{s} && !$opt{g}) {
				OutMsg($Name,
				    "no compilation symlink (.so) exists",
				    "WARNING");
			}
		} else {
			# On the other hand, if this file only contains private
			# interfaces and follows to .so.? naming convention then
			# there's no need for a compilation symlink to be
			# pointing at it.

			if ((-l $Link) && !$opt{s} && !$opt{g}) {
				OutMsg($Name,
				    "unnecessary compilation symlink (.so) " .
				    "exists", "WARNING");
			}
		}
		# If public interfaces have been found format any man page material
		if ($opt{d} && $opt{m} && $Pub) {
			# only format manpages corresponding to libraries on the
			# current system.
			my $linked_file = readlink($Link);
			if ((-l $Link) && ($linked_file =~ /$File/)) {
				man($Max, $RelPath, $File, sort @Syms);
			}
		}
	}

	@Pvs = split(/\n/, `pvs -d '$FullPath' 2>&1`);

PVS2:	foreach my $Line (@Pvs) {
		$Line =~ s/^\s*//;
		$Line =~ s/;.*$//;

		foreach my $Vers (@Vers) {
			if ($Vers eq $Line) {
				next PVS2;
			}
		}

		# If no symbols were found in a version set, then that version
		# set hasn't been tested for non-standard version names yet.
		# We test for them here.  e.g. SUNW.1.1 from libXm.so.1.2
		if (!CheckVerStr($Line)) {
			OutMsg($Name,
			    "$Line: non-standard version name", "ERROR");
		}

		if (!$opt{s} && !$opt{g} && $Line ne "SUNWobsolete") {
			OutMsg($Name,
			    "$Line: version offers no interfaces", "WARNING");
		}
	}

	close(AUD);

	# Having completed any verification, and if we've collecting interface
	# information, and this object contains public interfaces, generate a
	# normalized version control directive for this object.  This is
	# supposed to represent the versions that may be bound to be ld(1),
	# thus we fabricate a ".so" name.  Whether this compilation environment
	# name actually exists is another rats-nest of inconsistency.

	if ($opt{d} && $Pub) {

		@Pvs = split(/\n/, `pvs -don '$FullPath' 2>&1`);

		foreach my $Line (@Pvs) {
			if ($Line =~ /SUNWprivate/) {
				next;
			}
			$Line =~ s/$FullPath/$RelPath/;
			$Line =~ s/^\.//;
			$Line =~ s/\.so\.\d+/.so/;

			if ($Cls eq "-32") {
				if (!$Pub32) {
					$Pub32 = "$IntfDir/Public-32";
					open(PUB32, "> $Pub32") or die
					    "$Prog: open failed: $Pub32: $!";
				}
				print PUB32 "$Line\n";
			} else {
				if (!$Pub64) {
					$Pub64 = "$IntfDir/Public-64";
					open(PUB64, "> $Pub64") or die
					    "$Prog: open failed: $Pub64: $!";
				}
				print PUB64 "$Line\n";
			}
		}
	}
}

sub ProcDir
{
	my ($FullDir, $RelDir) = @_;
	my ($NewFull, $NewRel, $Entry);

	# Open the directory and read each entry, omit files starting with "."
	if (opendir(DIR, $FullDir)) {
		foreach $Entry (readdir(DIR)) {
			if ($Entry =~ /^\./) {
				next;
			}
			$NewFull = join('/', $FullDir, $Entry);

			# Ignore symlinks.
			if (-l $NewFull) {
				next;
			}
			if (!stat($NewFull)) {
				next;
			}
			$NewRel = "$RelDir/$Entry";

			# Descend into and process any directories.
			if (-d _) {
				ProcDir($NewFull, $NewRel);
				next;
			}

			# Typically dynamic objects are executable, so we can
			# reduce the overall cost of this script (a lot!) by
			# screening out non-executables here, rather than pass
			# them to elfdump(1) later.  However, it has been known
			# for shared objects to be mistakenly left non-
			# executable, so with -a let all files through so that
			# this requirement can be verified (see ProcFile()).
			if (! -x _) {
				next;
			}
			# Typically shared object dependencies end with
			# ".so" or ".so.?", hence we can reduce the cost
			# of this script (a lot!) by screening out files
			# that don't follow this pattern.
			if (!($Entry =~ /\.so$/) &&
			    !($Entry =~ /\.so\./)) {
				next;
			}

			# Process any standard files.
			if (-f _) {
				ProcFile($NewFull, $NewRel, $Entry);
				next;
			}

		}
		closedir(DIR);
	}
}

# Check that the proper inheritance chain is maintained.  i.e., the chain
# must consist of version sets whose names increment by at most ".1" per
# release.
sub CheckVersInheritance
{

	my ($FullPath, $RelPath) = @_;
	my (@Pvs) = split(/\n/, `pvs -d '$FullPath' 2>&1`);
	# old/new version naming correlate with chronological ordering of
	# the version numbers. i.e. since the pvs output displays the
	# inheritance chain in reverse chronological order (from highest to
	# lowest), the old_versions (omaj, omin, omic) all refer to the lower
	# version set being compared
	my ($omaj, $omin, $omic, $nmaj, $nmin, $nmic);
	my ($new_ver_name, $old_ver_name, $old_full_name, $new_full_name);
	my ($libver_major, $libver_minor);
	$omaj = $omin = $omic = $nmaj = $nmin = $nmic = 0;

	# To see if the shared object has a major, minor version
	if ($RelPath =~ /.so.(\d+)(\.\d+)?$/) {
		if (defined($1)) {
			$libver_major = $1;
		}
		if (defined($2)) {
			$libver_minor = $2;
		}
	}

	# The first line of the pvs -d output does not need to be checked
	# for version inheritance or string since it is the name of the library
	$Pvs[0] = "";

	foreach my $Line (@Pvs) {
		$Line =~ s/^\s+//;
		$Line =~ s/;$//;

		# Only check vers inheritance if it contains a major and minor
		# version number (with an optional micro number)
		# and they are only Public.

		if (!PublicStr($Line)) {
			next;
		}

		if ($Line =~ /(.*)_(\d+)\.(\d+)(\.\d+)?$/) {
			$old_full_name = $Line;
			$old_ver_name = $1;
			$omaj = $2;
			$omin = $3;
			$omic = $4;
			# ignore version perior to 1.1
			next if ($omaj < 1 || $omin < 1);
			if (!defined($omic)) {
				$omic = -1;
			} else {
				$omic =~ s/\.//;
			}

			# To ensure that Sun libraries not to have a minor
			# version number as part of the library filename
			# For example, it is a violation for a Sun library
			# with version name of SUNW_2.3 and the library is
			# named as libfoo.so.2.3
			if (defined($libver_major) && defined($libver_minor) &&
			    $old_ver_name eq "SUNW") {
				OutMsg($RelPath,
				    "invalid library filename; " .
				    "should not use minor version number " .
				    "($libver_minor) as part of filename",
				    "ERROR");
			}

			# To ensure that the major version number chosen for
			# the version name must be identical to the
			# major version number contained in its library
			# filename.  For example,
			# SUNW_5.1 w.r.t libldap.so.5
			# SUNW_2.1 w.r.t libresolv.so.2
			if (defined($libver_major) &&
			    $old_ver_name eq "SUNW" &&
			    $libver_major ne $omaj) {
				OutMsg($RelPath,
				    "$old_full_name: invalid version name, " .
				    "should be $old_ver_name" .
				    "_${libver_major}.${omin} " .
				    "to reflect major version",
				    "ERROR");
			}

			# Compare 2 versions of the same category (i.e., SUNW_)
			if (defined($new_ver_name) &&
			    $new_ver_name eq $old_ver_name) {

				# if omajor is less than nmajor; incompatible
				# changes within a library
				# i.e., SUNW_1.n.o	vs. SUNW_2.n.o
				# if omaj > nmaj; impossible within library
				if ($omaj < $nmaj || $omaj > $nmaj) {
					OutMsg($RelPath,
					    "$old_full_name" .
					    "->$new_full_name:" .
					    " invalid inheritance",
					    "ERROR");
				# if omaj equals nmaj
				# i.e., SUNW_1.n.o	vs. SUNW_1.n.o
				} elsif ($omaj == $nmaj) {

					# m stays, n is incremented with
					# optional o
					# i.e., SUNW_1.2	vs. SUNW_1.4
					# i.e., SUNW_1.2	vs. SUNW_1.3.1
					# i.e., SUNW_1.2.1	vs. SUNW_1.3.1
					if ($omin < $nmin &&
					    ($omin + 1 != $nmin ||
					    $nmic != -1)) {
						OutMsg($RelPath,
						    "$old_full_name" .
						    "->$new_full_name:" .
						    " invalid inheritance",
						    "ERROR");

					# m & n stay the same but o is
					# incremented
					# i.e., SUNW_1.20.1	vs. SUNW_1.20.3
					# i.e., SUNW_1.20	vs. SUNW_1.20.2
					} elsif ($omin == $nmin &&
						    (($omic != -1 &&
						    $omic + 1 != $nmic) ||
						    ($omic == -1 &&
						    $nmic != 1))) {
						OutMsg($RelPath,
						    "$old_full_name" .
						    "->$new_full_name:" .
						    " invalid inheritance",
						    "ERROR");

					# old minor > new minor version
					# i.e., SUNW_1.21	vs. SUNW_1.20
					} elsif ($omin > $nmin) {
						OutMsg($RelPath,
						    "$old_full_name" .
						    "->$new_full_name:" .
						    " invalid inheritance",
						    "ERROR");
					}
				} else {
					# It's impossible to reach here but
					# just in case, print out the error
					OutMsg("intf_check:",
					    "CheckVersInheritance():" .
					    "$omaj.$omin.$omic <-> " .
					    "$nmaj.$nmin.$nmic", "ERROR");
				}
			}
		} else {
			# Assertion check that it is ERROR for
			# SUNWobsolete->SUNW_m.n.o
			# and it is WARNING for
			# SUNWobsolete->SUNWprivate_m.n
			if ($Line =~ /SUNWobsolete/) {
				$old_full_name = $Line;
				if (defined($new_full_name) &&
				    ($new_full_name ne $old_full_name) &&
				    ($old_full_name eq "SUNWobsolete")) {
					if ($new_full_name =~ /private/) {
						OutMsg($RelPath,
						    "$old_full_name" .
						    "->$new_full_name: " .
						    "new private " .
						    "interface introduced " .
						    "to the obsolete library",
						    "WARNING");
					} else {
						OutMsg($RelPath,
						    "$old_full_name" .
						    "->$new_full_name: " .
						    "new public " .
						    "interface introduced " .
						    "to the obsolete library",
						    "ERROR");
					}
				}
			}
			next;
		}
		$new_ver_name = $old_ver_name;
		$new_full_name = $old_full_name;
		$nmaj = $omaj;
		$nmin = $omin;
		$nmic = $omic;
	}
}

# If the version string did not match one of the following
# patterns, then output Error message:
# Public - SUNW_m.n.o      Private - SUNWprivate
#          SYSVABI_1.[23]            SUNWprivate_m.n.o
#          SISCD_2.3[ab]	     SUNWabi_m.n.o
# where "m" is major version of library, "n" is minor version,
# "o" is an optional micro version representing update releases
sub CheckVerStr
{
	my ($vers_str) = @_;

	if (PublicStr($vers_str) || PrivateStr($vers_str)) {
		return 1;
	} else {
		return 0;
	}
}

#
# Returns 1 if $arg is classified as public
#
sub PublicStr
{
	my ($arg) = @_;

	if ($arg ne "" && ($arg =~ /^SUNW_\d+\.\d+(\.\d+)?$/ ||
	    $arg =~ /^SYSVABI_1\.[23]$/ || $arg =~ /^SISCD_2\.3[ab]?$/ ||
	    $arg =~ /^SUNWobsolete$/)) {
		return 1;
	} else {
		return 0;
	}
}

#
# Returns 1 if $arg is classified as private
#
sub PrivateStr
{
	my ($arg) = @_;
	if ($arg ne "" && ($arg =~ /^SUNWabi_\d+\.\d+(\.\d+)?$/ ||
	    $arg =~ /^SUNWprivate_\d+\.\d+(\.\d+)?$/ ||
	    $arg eq "SUNWprivate" ||
	    $arg eq "_LOCAL_")) {
		return 1;
	} else {
		return 0;
	}
}

#
# GetLibraryName() returns the matching library name from ABI.db.
#
# The heuristics we use for finding the matching is the following:
# We first search based on the full path name (i.e. /usr/lib/sparcv9/libc.so.1)
# if no matching library exists in the %LibHash obtained from BuildLibHash(),
# then we try generalizing the search by using the relative path name
# (i.e. ./sparcv9/libc.so.1).  Finally, if both these checks fails, then
# we'll search based on the filename (i.e. libc.so.1).
#
# Once we've found all matching libraries, we need to make sure only 1 match
# was made.  If more than one library matches the library, we'll
# need to prompt the developer for the correct match.
#
sub GetLibraryName
{
	my ($full_path, $rel_path, $file) = @_;

	my (@liblist, @tmp_liblist, @check_liblist);
	my ($count, $num_libs, $other_num, $number, $lib);
	my ($valid_flag, $file_type);


	# Takes out the leading "." character and escapes '/', for grepping
	# later.
	$rel_path =~ s/^\.\///;
	$full_path =~ s/^\.\///;

	# To be able to uniquely distinguish a particular library with its
	# path, we introduce a delimiter "^" inside grep for accuracy.
	# i.e., " ^usr/lib/libfoo.so.1" vs. " ^lib/libfoo.so.1"

	# Need to escape the '/' from the path, for grepping
	if ($full_path =~ /\//) {
		@liblist = grep /^\Q$full_path\E$/, (keys %LibHash);
	}

	# If no backslash is found, then this wasn't a full_path and
	# we'll need to perform further checking.  The '/' is used to
	# allow for searching of the $rel_path as a word beginning with
	# the rel_path.
	# library is relative, e.g usr/lib/libc.so.1
	if (!@liblist) {
		if ($rel_path =~ /\//) {
			@liblist = grep /^\Q$rel_path\E$/, (keys %LibHash);
		}
	}

	# library in relative path is not accurrate for final destination
	# Therefore, we can only use the filename: e.g., libc.so.1
	if (!@liblist) {
		@liblist = grep /\/\Q$file\E$/, (keys %LibHash);
	}

	$num_libs = scalar(@liblist);
	if ($num_libs == 0) {
		return $rel_path;
	}

	if ($num_libs == 1) {
		return $liblist[0];
	}

	# if not unique, we can check whether sparcv9 or amd64 will help
	# to resolve the name
	$file_type = `file $full_path`;
	if ($file_type =~ /64-bit\s+LSB/) {
		$file_type = "amd64";
	} elsif ($file_type =~ /64-bit\s+MSB/) {
		$file_type = "sparcv9";
	} elsif ($file_type =~ /Sun demand paged/) {
		return "";
	} else {
		$file_type = "";
	}

	# tmp_liblist array, so that we can delete elements from the @liblist
	# array later when looping through the elements.

	$count = 0;
	foreach my $lib (@liblist) {

		# if this shared object is 64-bit MSB, then make sure
		# pathname contains sparcv9 name
		if ($file_type eq "sparcv9") {
			if ($lib =~ /sparcv9/) {
				push(@tmp_liblist, $lib);
			}
		# if this shared object is 64-bit LSB, then make sure
		# pathname contains amd64 name
		} elsif ($file_type eq "amd64") {
			if ($lib =~ /amd64/) {
				push(@tmp_liblist, $lib);
			}
		# Otherwise, pathname should not contain sparcv9/amd64 in it.
		} else {
			push(@tmp_liblist, $lib);
		}
	}
	@liblist = @tmp_liblist;
	$num_libs = scalar(@liblist);

	# if library is unique, return match
	if ($num_libs == 1) {
		return $liblist[0];

	# in checking for omitted libraries, we always assume that anything
	# under $ROOT that is not recognized, is considered a new library.
	} elsif ($opt{o} || $num_libs == 0) {
		return $rel_path;

	# for multiple matches, try to resolve it based on its file type;
	# sparcv9 or amd64 or 32-bit.
	} else {
		my $cnt = 0;
		while (defined($liblist[$cnt])) {
			if (($file_type eq "sparcv9" &&
			    $liblist[$cnt] =~ /^lib\/sparcv9/) ||
			    ($file_type eq "amd64" &&
			    $liblist[$cnt] =~ /^lib\/amd64/) ||
			    ($file_type eq "" &&
			    $liblist[$cnt] =~ /^lib/)) {
				if (!$opt{s} && !$opt{g}) {
					ErrMsg($rel_path,
					    "found at multiple locations in "
					    . "the Solaris ABI database, "
					    . "comparing against "
					    . "$liblist[$cnt]");
				}
				return $liblist[$cnt];
			}
			$cnt ++;
		}
		# if it still cannot resolve, return the first match
		if (!$opt{s} && !$opt{g}) {
			ErrMsg($rel_path,
			    "found at multiple locations in the Solaris ABI "
			    . "database, comparing against $liblist[0]");
		}
		return $liblist[0];
	}
}

#
# analyze all the args that will need to be passed into abi_audit
# Create audit message and call to abi_audit program
#
sub AbiAudit
{

	my ($pflag, $tflag, $Tflag, $gflag, $iflag, $oflag, $sflag);
	my ($abi_audit);

	$pflag = $tflag = $Tflag = $gflag = "";
	$iflag = $oflag = $sflag = "";

	# append path to abi_audit program
	if ($opt{g}) {
		$gflag = "-g $opt{g} ";
	}
	if ($opt{i}) {
		$iflag = "-i ";
	}
	if ($opt{t}) {
		$tflag = "-t ";
	}
	if ($opt{T}) {
		$Tflag = "-T ";
	}
	if ($opt{o}) {
		$oflag = "-o ";
	}
	if ($opt{s}) {
		$sflag = "-s ";
	}
	if ($opt{p}) {
		$pflag = "-p ";
	}

	$abi_audit = "abi_audit ";
	$abi_audit .= "$oflag $sflag $gflag $iflag ";
	$abi_audit .= "$pflag $tflag $Tflag ";

	# Arguments were determined in GetOptions()
	$abi_audit .= "-n $DbPath -f $Log_File ";
	$abi_audit .= "$IntfDir";

	system("$abi_audit");
}

#
# Compare ERROR and WARNING messages with an exception list.  Historical errors 
# will be skipped
#
sub LoadExceptions
{
	my $line;
	my $line_count = 0;

	open(IN, "$Exceptions_File") ||
	    die "Cannot open: $Exceptions_File: $!";
	while ($line = <IN>) {
		chomp($line);
		$line_count ++;
		my ($bugid, $rule_no, $library, $name) = split(':', $line);

		# trim off leading and trailing whitespace
		foreach my $var ($bugid, $rule_no, $library, $name) {
			if (defined($var)) {
				$var =~ s/^\s*//;
				$var =~ s/\s*$//;
			}
		}

		# Skip commented lines
		if ($line =~ /^#/ || $line =~ /^\s*$/) {
			next;
		}

		# check line format in baseline
		CheckLineFormat($line_count, $line);

		if (!defined($name)) {
			# '|' are used to separate multiple entries
			if (defined($library)) {
				$library =~ s/\/$//;
				if (!defined($Lib{$library})) {
					$Lib{$library} = ""
				}
				$Lib{$library} .= "|$rule_no";
			}
		} else {
			if (!defined($LibSym{$library}{$name})) {
				$LibSym{$library}{$name} = "";
			}
			$LibSym{$library}{$name} .= "|$rule_no";
		}
	}
	close(IN);
}

#
# Check line format of the exceptions.  All lines should match one of
# the following patterns:
# <bugid or ARC #>: <RULE #>: <library_name>: <symbol_name>
# <bugid or ARC #>: <RULE #>: <library_name>: <version_name>
# <bugid or ARC #>: <RULE #>: <library_name>
# <bugid or ARC #>: <RULE #>: <directory_path_name>
# 
sub CheckLineFormat
{
	my $error = 0;
	my ($line_count, $line) = @_;
	my ($bugid, $rule_no, $library, $name) = split(':', $line);

	if (defined($rule_no)) {
		# trim off leading whitespace
		$rule_no =~ s/^\s*//;
	}

	# make sure all variables are initialized
	if (defined($bugid) && defined($rule_no) && defined($library)) {

		# Check bugid field for either ARC case number or bugid
		if ($bugid !~ /ARC \d{4}\/\d{3}$/ && $bugid !~ /^\d{7}$/) {
			$error = 1;
		}
		# Check rule_no field for RULE entry
		if (!defined($RuleHash{$rule_no})) {
			$error = 1;
		}
	} else {
		$error = 1;
	}

	if ($error) {
		ErrMsg("$Exceptions_File",
		    "line $line_count: Invalid entry");
	}
}

#
# Compare the output from an abi_audit run to the exceptions file
#
sub ProcessExceptions
{
	my ($line, $version) = "";

	# sort "inconsistent increment of version" messages
	system("sort -u -o $Log_File $Log_File");

	open(IN, "$Log_File") ||  die "Cannot open: $Log_File: $!";
	while ($line = <IN>) {
		chomp($line);
		my ($error_type, $library, $name, $error_msg) =
		    split(': ', $line, 4);

		# trim off leading whitespace
		foreach my $var ($error_type, $library, $name, $error_msg) {
			if (defined($var)) {
				$var =~ s/^\s*//;
			}
		}

		# covers format of RULES W1-W4, W10 where $name
		# is an error message
		if (!defined($error_msg)) {
			$error_msg = $name;
			if (!(defined($Lib{$library}) &&
			    MsgFound($error_msg, $Lib{$library}))) {
				my $path = '';
				my $skip = 0;
				foreach my $part (split(/\//, $library)) {
					# examine all the subpaths of $library
					# to see if any $path are to be skipped
					# from the paths in %Lib.
					if ($library =~ m,^/,
					    && $path eq '' && $part eq '') {
						$path = '/';
						next;
					}
					$path .= '/' unless $path =~ m,^/*$,;
					$path .= $part;
					if (exists($Lib{$path})) {
						$skip = 1;
					}
				}
				print "$line\n" if ! $skip;
			}
		} else {
			# Need to parse out new version name for E2, E12 and E7
			# errors
			    # E2 or E12 error
			if ($name =~ /(.*)->(.*)/ ||
			    # E7 error
			    $name =~ /was (.*) in .*, becomes (.*) in .*/) {
				$name = $2;
			}
			# find if error message, library/name matches
			# any of the entries in our exception database.
			# covers format of RULES E1, E3-E6, E8, E9, E10-11,
			# W5-W8
			if (!defined($Lib{$library})) {
				$library =~ s/^\///;
			}
			if (!(defined($Lib{$library}) &&
			    MsgFound($error_msg, $Lib{$library})) &&
			    !(defined($LibSym{$library}{$name}) &&
			    MsgFound($error_msg, $LibSym{$library}{$name}))) {
				print "$line\n";
			}
		}
	}
	close(IN);
}

#
# All entries in %Lib and %LibSym are of the following format:
#	<RULE #> | <RULE #> | ...
# If we find a match between the error message in the %RuleHash and the 
# error message from the output file, then 1 is returned.
# Otherwise, 0 is returned.
#
sub MsgFound
{
	my ($error_msg, $rules_list) = @_;
	my (@rules) = split('\|', $rules_list);

	foreach my $rule (@rules) {
		if (!defined($rule) || !defined($error_msg)) {
			next;
		}
		if ($rule ne "" && defined($RuleHash{$rule}) &&
		    $error_msg =~ /$RuleHash{$rule}/) {
			return 1;
		}
	}

	return 0;
}

#
# Close any working output files.
#
sub CleanUp
{
	if ($Pub32) {
		close PUB32;
	}
	if ($Pub64) {
		close PUB64;
	}

	# temporary file containing unprocessed ERRORS/WARNINGS messages:
	# $IntfDir/tmplog.$$
	unlink $Log_File;

	# remove Lib_Log_File = "/tmp/abi_audit_lib_log":
	unlink $Lib_Log_File;

	if (!$opt{d}) {
		# This directory was set in GetOptions to "/tmp/abi_audit.$$"
		system("rm -rf $IntfDir");
	}
}

#
# Create an output message.  Messages will be printed to $Log_File file
#
sub OutMsg
{
	my ($Path, $Msg, $Type) = @_;
	my ($Real_path);

	# Change Path back to '/'
	$Real_path = $Path;
	$Real_path =~ s/=/\//g;

	print LOG "$Type: $Real_path: $Msg\n";
}

#
# Create an error message.  Messages will be printed to STDERR
#
sub ErrMsg
{
	my ($Path, $Msg) = @_;
	print STDERR "$Path: $Msg\n";

	# Indicate an error has occurred.
	$Error = 1;
}

#
# Print out releases correlating with an ABI_*.db file
#
sub AbiDbRelease
{
	my $rel_cnt = 0;

	open(ABI_DB, $DbPath) or
	    die "$Prog: open failed: $DbPath: $!";

	# keys of hash are the library names
	foreach my $line (<ABI_DB>) {
		if ($line =~ /^#Releases:(.*)/) {
			my $releases = $1;
			print "$DbPath contains ABI information for the ";
			print "following releases: $releases\n";
			last;
		}
	}
	close(ABI_DB);
}
