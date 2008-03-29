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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
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
# excluded to reduce this scripts output.  Pathnames used for this exclusion
# assume this script is being run over a "proto" area.  The -a (all) option
# skips any exclusions.
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
# misleading error messages.  To compensate for this, the -d option (or the
# existence of the CODEMSG_WS/ROOT environment variables) cause the creation of
# alternative dependency mappings via crle(1) configuration files that establish
# any proto shared objects as alternatives to their base system location.  Thus
# ldd(1) can be executed against these configuration files so that objects in a
# proto area bind to their dependencies in the same proto area.


# Define all global variables (required for strict)
use vars  qw($SkipDirs $SkipFiles $SkipTextrelFiles $SkipDirectBindFiles);
use vars  qw($SkipUndefDirs $SkipUndefFiles $SkipUnusedDirs $SkipUnusedFiles);
use vars  qw($SkipStabFiles $SkipNoExStkFiles $SkipCrleConf);
use vars  qw($UnusedNoise $Prog $Mach $Isalist $Env $Ena64 $Tmpdir $Error);
use vars  qw($UnusedFiles $UnusedPaths $LddNoU $Crle32 $Crle64 $Conf32 $Conf64);
use vars  qw($SkipDirectBindDirs $SkipInterps $SkipSymSort $OldDeps %opt);

use strict;


# Define any directories we should skip completely.
$SkipDirs = qr{ 
	etc/lib |			# special - used for partial statics
	usr/lib/devfsadm |		# 4382889
	usr/lib/libc |			# optimized libc
	usr/lib/rcm |			# 4426119
	usr/perl5 |			# alan's taking care of these :-)
	usr/src				# no need to look at shipped source
}x;

# Define any files we should skip completely.
$SkipFiles = qr{ ^(?:
	ld\.so\.1 |			# confusing but correct dependencies
	lddstub |			# lddstub has no dependencies
	libmakestate\.so\.1 |		# temporary; delivered by compiler group
	libm\.so\.1 |			# temporary; delivered by compiler group
	libm\.so\.2 |			# temporary; delivered by compiler group
	geniconvtbl\.so |		# 4384329
	libssagent\.so\.1 |		# 4328854
	libpsvcplugin_psr\.so\.1 |	# 4385799
	libpsvcpolicy_psr\.so\.1 |	#  "  "
	libpsvcpolicy\.so\.1 |		#  "  "
	picl_slm\.so |			#  "  "
	libcrypto_extra\.so\.0\.9\.8 |	# OpenSSL SUNWcry filter lib
	libssl_extra\.so\.0\.9\.8 |	# OpenSSL SUNWcry filter lib
	fcpackage\.so |			# circular dependency on fcthread.so
	mod_ipp\.so |			# Apache loadable module
	grub
	)$
}x;

# Define any files that are allowed text relocations.
$SkipTextrelFiles = qr{ ^(?:
	unix |				# kernel models are non-pic
	mdb				# relocations against __RTC (dbx)
	)$
}x;

# Define any directories or files that are allowed to have no direct bound
# symbols
$SkipDirectBindDirs = qr{
	usr/ucb
}x;

$SkipDirectBindFiles = qr{ ^(?:
	unix |
	sbcp |
	libproc.so.1 |
	libnisdb.so.2
	)$
}x;

# Define any files that are allowed undefined references.
$SkipUndefDirs = qr{
	usr/lib/elfedit/ |		# elfedit modules have callbacks
	usr/lib/inet/ppp/ |		# pppd plugins have callbacks
	usr/lib/libp/ |			# libc.so.1 requires _mcount
	/lib/mdb/ |			# mdb modules have callbacks
	/lib/fm/fmd/plugins/ |		# fmd modules have callbacks
	/lib/fm/fmd/schemes/ |		# fmd schemes have callbacks
	/lib/scsi/plugins/ |		# scsi plugins have callbacks
	/i86pc/lib/mtst/		# mtst modules have callbacks
}x;

$SkipUndefFiles = qr{ ^(?:
	libthread_db\.so\.0 |		# callbacks to proc service interface
	libthread_db\.so\.1 |		#  "	"	"	"
	librtld_db\.so\.1 |		#  "	"	"	"
	libc_db\.so\.1 |		#  "	"	"	"
	libldstab\.so\.1 |		# link-edit support libraries have
	libld\.so\.[2-4] |			# callback to the link-editors
	liblddbg\.so\.4 |		#  "	"	"	"
	librtld\.so\.1 |		#  "	"	"	"
	libnisdb\.so\.2 |		# C++
	libsvm\.so\.1 |			# libspmicommon.so.1 lacking
	libwanboot\.so\.1 |		# libcrypto.a and libssl.a
	libwrap\.so\.1\.0 |		# uses symbols provided by application
	fcthread\.so |			# uses symbols provided by application
	fn\.so\.2 |			# callback to automount
	preen_md\.so\.1 |		# callback to driver
	libike\.so\.1 |			# callbacks to in.iked for IKE policy
	devfsadmd_mod\.so |		# sysevent module callback to syseventd
	sysevent_conf_mod\.so |		# sysevent module callback to syseventd
	sysevent_reg_mod\.so		# sysevent module callback to syseventd
	)$
}x;

# Define any files that have unused dependencies.
$SkipUnusedDirs = qr{
	lib/picl/plugins/ |		# require devtree dependencies
	/lib/libp			# profile libc makes libm an unused
}x;					#	dependency of standard libc

$SkipUnusedFiles = qr{ ^(?:
	devfsadm |			# 4382889
	disks |				#  "  "
	tapes |				#  "  "
	ports |				#  "  "
	audlinks |			#  "  "
	devlinks |			#  "  "
	drvconfig |			#  "  "
	ntptrace |			# on intel doesn't need libmd5
	ocfserv |			# libsched unreference by libjvm,
	poold |				#	see 4952319. 
	libc\.so\.1\.9 |		# 4lib/libc versions have private
	libc\.so\.2\.9			#	copies of stuff from libc.
	)$
}x;

# Define any files that should contain debugging information.
$SkipStabFiles = qr{ ^(?:
	abi_.* |
	interceptors\.so\.1 |
	unix
	)$
}x;

# Define any files that don't require a non-executable stack definition.
$SkipNoExStkFiles = qr{ ^(?:
	forth |
	unix |
	multiboot
	)$
}x;

# Identify any files that should be skipped when building a crle(1)
# configuration file.  As the hwcap libraries can be loop-back mounted onto
# libc, these can confuse crle(1) because of their identical dev/inode.
$SkipCrleConf = qr{
	lib/libc/libc_hwcap
}x;

# Define any files that should only have unused (ldd -u) processing.
$UnusedPaths = qr{
	ucb/shutdown			# libucb interposes on libc and makes
					# dependencies on libc seem unnecessary
}x;

$UnusedFiles = qr{ ^(?:
	rpc\.nisd			# CCNEEDED makes pthread unreferenced
	)$
}x;

# Define unused dependencies we should ignore.
# libCrun has a unnecessary dependency on libw, and libmapmalloc is often
# defined to interpose on libc but isn't used by the application itself.
# Threads dependencies look unused if libc is bound first.
$UnusedNoise = qr{
	libw\.so\.1;\ unused |
	unused\ object=.*libw\.so\.1 |
	libthread\.so\.1;\ unused |
	libpthread\.so\.1;\ unused |
	unused\ object=.*libpthread\.so\.1 |
	libnsl\.so\.1;\ unused\ dependency\ of\ .*libxslt\.so\.1 |
	libdl\.so\.1;\ unused\ dependency\ of\ .*libspmicommon\.so\.1 |
	libdl\.so\.1;\ unused\ dependency\ of\ .*libCrun\.so\.1 |
	libfru\.so\.1;\ unused\ object=.*libdl\.so\.1 |
	libfrupicl\.so\.1;\ unused\ object=.*libdl\.so\.1 |
	libmapmalloc\.so\.1;\ unused |
	unused\ dependency\ of\ .*libstdc\+\+\.so\.6 |
	unreferenced\ object=.*libstdc\+\+\.so\.6 |
	unused\ dependency\ of\ .*libnetsnmp\.so\.5 |
	unused\ dependency\ of\ .*libnetsnmphelpers\.so\.5 |
	unused\ dependency\ of\ .*libnetsnmpmibs\.so\.5 |
	unused\ dependency\ of\ .*libnetsnmpagent\.so\.5
}x;

# Define interpreters we should ignore.
$SkipInterps = qr{
	misc/krtld |
	misc/amd64/krtld |
	misc/sparcv9/krtld
}x;

# Catch libintl and libw, although ld(1) will bind to these and thus determine
# they're needed, their content was moved into libc as of on297 build 7.
# libthread and libpthread were completely moved into libc as of on10 build 53.
# Also, catch libdl, whose content was moved into libc as of on10 build 49.
$OldDeps = qr{ ^(?:
	libintl\.so\.1 |
	libw\.so\.1 |
	libthread\.so\.1 |
	libpthread\.so\.1 |
	libdl\.so\.1
	)$
}x;

# Files for which we skip checking of duplicate addresses in the
# symbol sort sections. Such exceptions should be rare --- most code will
# not have duplicate addresses, since it takes assember or a "#pragma weak"
# to do such aliasing in C. C++ is different: The compiler generates aliases
# for implementation reasons, and the mangled names used to encode argument
# and return value types are difficult to handle well in mapfiles.
# Furthermore, the Sun compiler and gcc use different and incompatible
# name mangling conventions. Since ON must be buildable by either, we
# would have to maintain two sets of mapfiles for each such object.
# C++ use is rare in ON, so this is not worth pursuing.
#
$SkipSymSort = qr{ ^.*(?:
	opt/SUNWdtrt/tst/common/pid/tst.weak2.exe |	# DTrace test
	lib/amd64/libnsl\.so\.1 |			# C++
	lib/sparcv9/libnsl\.so\.1 |			# C++
	lib/sparcv9/libfru\.so\.1 |			# C++
	usr/lib/sgml/nsgmls				# C++
	)$
}x;

use Getopt::Std;

# -----------------------------------------------------------------------------

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

# This script relies on ldd returning output reflecting only the binary 
# contents.  But if LD_PRELOAD* environment variables are present, libraries
# named by them will also appear in the output, disrupting our analysis.
# So, before we get too far, scrub the environment.

delete($ENV{LD_PRELOAD});
delete($ENV{LD_PRELOAD_32});
delete($ENV{LD_PRELOAD_64});

# Establish a program name for any error diagnostics.
chomp($Prog = `basename $0`);

# Determine what machinery is available.
$Mach = `uname -p`;
$Isalist = `isalist`;
$Env = "";
if ($Mach =~ /sparc/) {
	if ($Isalist =~ /sparcv9/) {
		$Ena64 = "ok";
	}
} elsif ($Mach =~ /i386/) {
	if ($Isalist =~ /amd64/) {
		$Ena64 = "ok";
	}
}

# Check that we have arguments.
if ((getopts('ad:imos', \%opt) == 0) || ($#ARGV == -1)) {
	print "usage: $Prog [-a] [-d depdir] [-m] [-o] [-s] file | dir, ...\n";
	print "\t[-a]\t\tprocess all files (ignore any exception lists)\n";
	print "\t[-d dir]\testablish dependencies from under directory\n";
	print "\t[-i]\t\tproduce dynamic table entry information\n";
	print "\t[-m]\t\tprocess mcs(1) comments\n";
	print "\t[-o]\t\tproduce one-liner output (prefixed with pathname)\n";
	print "\t[-s]\t\tprocess .stab and .symtab entries\n";
	exit 1;
} else {
	my($Proto);

	if ($opt{d}) {
		# User specified dependency directory - make sure it exists.
		if (! -d $opt{d}) {
			print "$Prog: $opt{d} is not a directory\n";
			exit 1;
		}
		$Proto = $opt{d};

	} elsif ($ENV{CODEMGR_WS}) {
		my($Root);

		# Without a user specified dependency directory see if we're
		# part of a codemanager workspace and if a proto area exists.
		if (($Root = $ENV{ROOT}) && (-d $Root)) {
			$Proto = $Root;
		}
	}

	if (!($Tmpdir = $ENV{TMPDIR}) || (! -d $Tmpdir)) {
		$Tmpdir = "/tmp";
	}

	# Look for dependencies under $Proto.
	if ($Proto) {
		# To support alternative dependency mapping we'll need ldd(1)'s
		# -e option.  This is relatively new (s81_30), so make sure
		# ldd(1) is capable before gathering any dependency information.
		if (system('ldd -e /usr/lib/lddstub 2> /dev/null')) {
			print "ldd: does not support -e, unable to ";
			print "create alternative dependency mappingings.\n";
			print "ldd: option added under 4390308 (s81_30).\n\n";
		} else {
			# Gather dependencies and construct a alternative
			# dependency mapping via a crle(1) configuration file.
			GetDeps($Proto, "/");
			GenConf();
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

		if (($Release = $ENV{RELEASE}) &&
		    (cmp_os_ver($Release, "<", "5.10"))) {
			$LddNoU = 1;
		} else {
			$LddNoU = 0;
		}
	}

	# For each argument determine if we're dealing with a file or directory.
	foreach my $Arg (@ARGV) {
		# Ignore symbolic links.
		if (-l $Arg) {
			next;
		}

		if (!stat($Arg)) {
			next;
		}

		# Process simple files.
		if (-f _) {
			my($RelPath) = $Arg;
			my($File) = $Arg;
			my($Secure) = 0;

			$RelPath =~ s!^.*/!./!;
			$File =~ s!^.*/!!;

			if (-u _ || -g _) {
				$Secure = 1;
			}

			ProcFile($Arg, $RelPath, $File, $Secure);
			next;
		}
		# Process directories.
		if (-d _) {
			ProcDir($Arg, ".");
			next;
		}

		print "$Arg is not a file or directory\n";
		$Error = 1;
	}

	# Cleanup
	CleanUp();
}

$Error = 0;

# Clean up any temporary files.
sub CleanUp {
	if ($Crle64) {
		unlink $Crle64;
	}
	if ($Conf64) {
		unlink $Conf64;
	}
	if ($Crle32) {
		unlink $Crle32;
	}
	if ($Conf32) {
		unlink $Conf32;
	}
}

# Create an output message, either a one-liner (under -o) or preceded by the
# files relative pathname as a title.
sub OutMsg {
	my($Ttl, $Path, $Msg) = @_;

	if ($opt{o}) {
		$Msg =~ s/^[ \t]*//;
		print "$Path: $Msg\n";
	} else {
		if ($Ttl eq 0) {
			print "==== $Path ====\n";
		}
		print "$Msg\n";
	}
}

# Determine whether this a ELF dynamic object and if so investigate its runtime
# attributes.
sub ProcFile {
	my($FullPath, $RelPath, $File, $Secure) = @_;
	my(@Elf, @Ldd, $Dyn, $Intp, $Dll, $Ttl, $Sym, $Interp, $Stack);
	my($Sun, $Relsz, $Pltsz, $Uns, $Tex, $Stab, $Strip, $Lddopt, $SymSort);
	my($Val, $Header, $SkipLdd, $IsX86, $RWX);
	my($HasDirectBinding);

	# Ignore symbolic links.
	if (-l $FullPath) {
		return;
	}

	$Ttl = 0;
	@Ldd = 0;

	# Determine whether we have access to inspect the file.
	if (!(-r $FullPath)) {
		OutMsg($Ttl++, $RelPath,
		    "\tunable to inspect file: permission denied");
		return;
	}

	# Determine if this is a file we don't care about.
	if (!$opt{a}) {
		if ($File =~ $SkipFiles) {
			return;
		}
	}

	# Determine whether we have a executable (static or dynamic) or a
	# shared object.
	@Elf = split(/\n/, `elfdump -epdicy $FullPath 2>&1`);

	$Dyn = $Intp = $Dll = $Stack = $IsX86 = $RWX = 0;
	$Interp = 1;
	$Header = 'None';
	foreach my $Line (@Elf) {
		# If we have an invalid file type (which we can tell from the
		# first line), or we're processing an archive, bail.
		if ($Header eq 'None') {
			if (($Line =~ /invalid file/) ||
			    ($Line =~ /$FullPath(.*):/)) {
				return;
			}
		}

		if ($Line =~ /^ELF Header/) {
			$Header = 'Ehdr';

		} elsif ($Line =~ /^Program Header/) {
			$Header = 'Phdr';
			$RWX = 0;

		} elsif ($Line =~ /^Interpreter/) {
			$Header = 'Intp';

		} elsif ($Line =~ /^Dynamic Section/) {
			# A dynamic section indicates we're a dynamic object
			# (this makes sure we don't check static executables).
			$Dyn = 1;

		} elsif (($Header eq 'Ehdr') && ($Line =~ /e_type:/)) {
			# The e_type field indicates whether this file is a
			# shared object (ET_DYN) or an executable (ET_EXEC).
			if ($Line =~ /ET_DYN/) {
				$Dll = 1;
			} elsif ($Line !~ /ET_EXEC/) {
				return;
			}
		} elsif (($Header eq 'Ehdr') && ($Line =~ /ei_class:/)) {
			# If we encounter a 64-bit object, but we're not running
			# on a 64-bit system, suppress calling ldd(1).
			if (($Line =~ /ELFCLASS64/) && !$Ena64) {
				$SkipLdd = 1;
			}
		} elsif (($Header eq 'Ehdr') && ($Line =~ /e_machine:/)) {
			# If it's a X86 object, we need to enforce RW- data.
			if (($Line =~ /(EM_AMD64|EM_386)/)) {
				$IsX86 = 1;
			}
		} elsif (($Header eq 'Phdr') &&
		    ($Line =~ /\[ PF_X  PF_W  PF_R \]/)) {
			# RWX segment seen.
			$RWX = 1;

		} elsif (($Header eq 'Phdr') &&
		    ($Line =~ /\[ PT_LOAD \]/ && $RWX && $IsX86)) {
			# Seen an RWX PT_LOAD segment.
			if ($File !~ $SkipNoExStkFiles) {
				OutMsg($Ttl++, $RelPath,
				    "\tapplication requires non-executable " .
				    "data\t<no -Mmapfile_noexdata?>");
			}

		} elsif (($Header eq 'Phdr') &&
		    ($Line =~ /\[ PT_SUNWSTACK \]/)) {
			# This object defines a non-executable stack.
			$Stack = 1;

		} elsif (($Header eq 'Intp') && !$opt{a} &&
		    ($Line =~ $SkipInterps)) {
			# This object defines an interpretor we should skip.
			$Interp = 0;
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
			OutMsg($Ttl++, $RelPath,
			    "\tnon-conforming mcs(1) comment\t<no \$(POST_PROCESS)?>");
		}
	}

	# Applications should contain a non-executable stack definition.
	if (($Dll == 0) && ($Stack == 0)) {
		if (!$opt{a}) {
			if ($File =~ $SkipNoExStkFiles) {
				goto DYN;
			}
		}
		OutMsg($Ttl++, $RelPath,
		    "\tapplication requires non-executable stack\t<no -Mmapfile_noexstk?>");
	}

DYN:
	# Having caught any static executables in the mcs(1) check and non-
	# executable stack definition check, continue with dynamic objects
	# from now on.
	if ($Dyn eq 0) {
		return;
	}

	# Only use ldd unless we've encountered an interpreter that should
	# be skipped.
	if (!$SkipLdd && $Interp) {
		my $LDDFullPath = $FullPath;

		if ($Secure) {
			# The execution of a secure application over an nfs file
			# system mounted nosuid will result in warning messages
			# being sent to /var/adm/messages.  As this type of
			# environment can occur with root builds, move the file
			# being investigated to a safe place first.  In addition
			# remove its secure permission so that it can be
			# influenced by any alternative dependency mappings.
	
			my($TmpPath) = "$Tmpdir/$File";

			system('cp', $LDDFullPath, $TmpPath);
			chmod 0777, $TmpPath;
			$LDDFullPath = $TmpPath;
		}

		# Use ldd(1) to determine the objects relocatability and use.
		# By default look for all unreferenced dependencies.  However,
		# some objects have legitimate dependencies that they do not
		# reference.
		if ($LddNoU || ($File =~ $UnusedFiles) ||
		    ($RelPath =~ $UnusedPaths)) {
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
	$Uns = 1;

LDD:	foreach my $Line (@Ldd) {

		if ($Val == 0) {
			$Val = 1;
			# Make sure ldd(1) worked.  One possible failure is that
			# this is an old ldd(1) prior to -e addition (4390308).
			if ($Line =~ /usage:/) {
				$Line =~ s/$/\t<old ldd(1)?>/;
				OutMsg($Ttl++, $RelPath, $Line);
				last;
			} elsif ($Line =~ /execution failed/) {
				OutMsg($Ttl++, $RelPath, $Line);
				last;
			}

			# It's possible this binary can't be executed, ie. we've
			# found a sparc binary while running on an intel system,
			# or a sparcv9 binary on a sparcv7/8 system.
			if ($Line =~ /wrong class/) {
				OutMsg($Ttl++, $RelPath,
				    "\thas wrong class or data encoding");
				next;
			}

			# Historically, ldd(1) likes executable objects to have
			# their execute bit set.  Note that this test isn't
			# applied unless the -a option is in effect, as any
			# non-executable files are skipped by default to reduce
			# the cost of running this script.
			if ($Line =~ /not executable/) {
				OutMsg($Ttl++, $RelPath,
				    "\tis not executable");
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
			OutMsg($Ttl++, $RelPath, $Line);
			next;
		}
		# Look for relocations whose symbols can't be found.  Note, we
		# only print out the first 5 relocations for any file as this
		# output can be excessive.
		if ($Sym && ($Line =~ /symbol not found/)) {
			# Determine if this file is allowed undefined
			# references.
			if ($Sym == 5) {
				if (!$opt{a}) {
					if ($RelPath =~ $SkipUndefDirs) {
						$Sym = 0;
						next LDD;
					}
					if ($File =~ $SkipUndefFiles) {
						$Sym = 0;
						next LDD;
					}
				}
			}
			if ($Sym-- == 1) {
				if (!$opt{o}) {
					OutMsg($Ttl++, $RelPath,
					    "\tcontinued ...");
				}
				next;
			}
			# Just print the symbol name.
			$Line =~ s/$/\t<no -zdefs?>/;
			OutMsg($Ttl++, $RelPath, $Line);
			next;
		}
		# Look for any unused dependencies.
		if ($Uns && ($Line =~ /unused/)) {
			if (!$opt{a}) {
				if ($RelPath =~ $SkipUnusedDirs) {
					$Uns = 0;
					next LDD;
				}
				if ($File =~ $SkipUnusedFiles) {
					$Uns = 0;
					next LDD;
				}

				# Remove any noise.
				if ($Line =~ $UnusedNoise) {
					$Uns = 0;
					next LDD;
				}
			}
			if ($Secure) {
				$Line =~ s!$Tmpdir/!!;
			}
			$Line =~ s/^[ \t]*(.*)/\t$1\t<remove lib or -zignore?>/;
			OutMsg($Ttl++, $RelPath, $Line);
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
			if (!$opt{a}) {
				if ($File =~ $SkipTextrelFiles) {
					$Tex = 0;
					next ELF;
				}
			}
			OutMsg($Ttl++, $RelPath,
			    "\tTEXTREL .dynamic tag\t\t\t<no -Kpic?>");
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

		# Under the -i (information) option print out any useful dynamic
		# entries.
		# Does this object have any dependencies.
		if ($opt{i} && ($Line =~ /NEEDED/)) {
			my($Need) = (split(' ', $Line))[3];

			# Catch any old (unnecessary) dependencies.
			if ($Need =~ $OldDeps) {
				OutMsg($Ttl++, $RelPath,
				    "\tNEEDED=$Need\t<dependency no longer necessary>");
			} else { 
				OutMsg($Ttl++, $RelPath, "\tNEEDED=$Need");
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
			OutMsg($Ttl++, $RelPath, "\tRPATH=$Rpath");
			next;
		}
	}

	# A shared object, that contains non-plt relocations, should have a
	# combined relocation section indicating it was built with -z combreloc.
	if ($Dll && $Relsz && ($Relsz != $Pltsz) && ($Sun == 0)) {
		OutMsg($Ttl++, $RelPath,
		    "\tSUNW_reloc section missing\t\t<no -zcombreloc?>");
	}

	# No objects released to a customer should have any .stabs sections
	# remaining, they should be stripped.
	if ($opt{s} && $Stab) {
		if (!$opt{a}) {
			if ($File =~ $SkipStabFiles) {
				goto DONESTAB;
			}
		}
		OutMsg($Ttl++, $RelPath,
		    "\tdebugging sections should be deleted\t<no strip -x?>");
	}

	# Identify an object that is not built with either -B direct or
	# -z direct.
	if (($RelPath =~ $SkipDirectBindDirs) ||
	    ($File =~ $SkipDirectBindFiles)) {
		goto DONESTAB;
	}
	if ($Relsz && ($HasDirectBinding == 0)) {
		OutMsg($Ttl++, $RelPath,
		    "\tobject has no direct bindings\t<no -B direct or -z direct?>");
	}

DONESTAB:

	# All objects should have a full symbol table to provide complete
	# debugging stack traces.
	if ($Strip) {
		OutMsg($Ttl++, $RelPath,
		    "\tsymbol table should not be stripped\t<remove -s?>");
	}

	# If there are symbol sort sections in this object, report on
	# any that have duplicate addresses.
	ProcSymSort($FullPath, $RelPath, \$Ttl) if $SymSort;
}


## ProcSymSortOutMsg(RefTtl, RelPath, secname, addr, names...)
#
# Call OutMsg for a duplicate address error in a symbol sort
# section
#
sub ProcSymSortOutMsg {
	my($RefTtl, $RelPath, $secname, $addr, @names) = @_;

	OutMsg($$RefTtl++, $RelPath,
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

	my($FullPath, $RelPath, $RefTtl) = @_;

	# If this object is exempt from checking, return quietly
	return if ($FullPath =~ $SkipSymSort);


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
			ProcSymSortOutMsg($RefTtl, $RelPath, $secname,
			    $last_addr, @dups) if (scalar(@dups) > 1);

			# Reset variables for new sort section
			$last_addr = '';
			@dups = ();

			next;
		}

		# Process symbol line
		my @fields = split /\s+/, $line;
		my $new_addr = $fields[2]; 
		my $new_name = $fields[9]; 

		if ($new_addr eq $last_addr) {
			push @dups, $new_name;
		} else {
			ProcSymSortOutMsg($RefTtl, $RelPath, $secname,
			    $last_addr, @dups) if (scalar(@dups) > 1);
			@dups = ( $new_name );
			$last_addr = $new_addr; 
		}
	}

	ProcSymSortOutMsg($RefTtl, $RelPath, $secname, $last_addr, @dups)
		if (scalar(@dups) > 1);
	
	close SORT;
}


sub ProcDir {
	my($FullDir, $RelDir) = @_;
	my($NewFull, $NewRel);

	# Determine if this is a directory we don't care about.
	if (!$opt{a}) {
		if ($RelDir =~ $SkipDirs) {
			return;
		}
	}

	# Open the directory and read each entry, omit files starting with "."
	if (opendir(DIR, $FullDir)) {
		foreach my $Entry (readdir(DIR)) {
			if ($Entry =~ /^\./) {
				next;
			}
			$NewFull = "$FullDir/$Entry";

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
			# them to file(1) later.  However, it has been known
			# for shared objects to be mistakenly left non-
			# executable, so with -a let all files through so that
			# this requirement can be verified (see ProcFile()).
			if (!$opt{a}) {
				if (! -x _) {
					next;
				}
			}

			# Process any standard files.
			if (-f _) {
				my($Secure) = 0;

				if (-u _ || -g _) {
					$Secure = 1;
				}

				ProcFile($NewFull, $NewRel, $Entry, $Secure);
				next;
			}

		}
		closedir(DIR);
	}
}

# Create a crle(1) script for any 64-bit dependencies we locate.  A runtime
# configuration file will be generated to establish alternative dependency
# mappings for all these dependencies.

sub Entercrle64 {
	my($FullDir, $RelDir, $Entry) = @_;

	if (!$Crle64) {
		# Create and initialize the script if is doesn't already exit.

		$Crle64 = "$Tmpdir/$Prog.crle64.$$";
		open(CRLE64, "> $Crle64") ||
			die "$Prog: open failed: $Crle64: $!";

		print CRLE64 "#!/bin/sh\ncrle -64\\\n";
	}
	print CRLE64 "\t-o $FullDir -a $RelDir/$Entry \\\n";
}

# Create a crle(1) script for any 32-bit dependencies we locate.  A runtime
# configuration file will be generated to establish alternative dependency
# mappings for all these dependencies.

sub Entercrle32 {
	my($FullDir, $RelDir, $Entry) = @_;

	if (!$Crle32) {
		# Create and initialize the script if is doesn't already exit.

		$Crle32 = "$Tmpdir/$Prog.crle32.$$";
		open(CRLE32, "> $Crle32") ||
			die "$Prog: open failed: $Crle32: $!";

		print CRLE32 "#!/bin/sh\ncrle \\\n";
	}
	print CRLE32 "\t-o $FullDir -a $RelDir/$Entry \\\n";
}

# Having finished gathering dependencies, complete any crle(1) scripts and
# execute them to generate the associated runtime configuration files.  In
# addition establish the environment variable required to pass the configuration
# files to ldd(1).

sub GenConf {
	if ($Crle64) {
		$Conf64 = "$Tmpdir/$Prog.conf64.$$";
		print CRLE64 "\t-c $Conf64\n";

		chmod 0755, $Crle64;
		close CRLE64;

		if (system($Crle64)) {
			undef $Conf64;
		}
	}
	if ($Crle32) {
		$Conf32 = "$Tmpdir/$Prog.conf32.$$";
		print CRLE32 "\t-c $Conf32\n";

		chmod 0755, $Crle32;
		close CRLE32;

		if (system($Crle32)) {
			undef $Conf32;
		}
	}

	if ($Crle64 && $Conf64 && $Crle32 && $Conf32) {
		$Env = "-e LD_FLAGS=config_64=$Conf64,config_32=$Conf32";
	} elsif ($Crle64 && $Conf64) {
		$Env = "-e LD_FLAGS=config_64=$Conf64";
	} elsif ($Crle32 && $Conf32) {
		$Env = "-e LD_FLAGS=config_32=$Conf32";
	}
}

# Recurse through a directory hierarchy looking for appropriate dependencies.

sub GetDeps {
	my($FullDir, $RelDir) = @_;
	my($NewFull);

	# Open the directory and read each entry, omit files starting with "."
	if (opendir(DIR, $FullDir)) {
		 foreach my $Entry (readdir(DIR)) {
			if ($Entry =~ /^\./) {
				next;
			}
			$NewFull = "$FullDir/$Entry";

			# We need to follow links so that any dependencies
			# are expressed in all their available forms.
			# Bail on symlinks like 32 -> .
			if (-l $NewFull) {
				if (readlink($NewFull) =~ /^\.$/) {
					next;
				}
			}
			if (!stat($NewFull)) {
				next;
			}

			if (!$opt{a}) {
				if ($NewFull =~ $SkipCrleConf) {
					next;
				}
			}
				
			# If this is a directory descend into it.
			if (-d _) {
				my($NewRel);
				
				if ($RelDir =~ /^\/$/) {
					$NewRel = "$RelDir$Entry";
				} else {
					$NewRel = "$RelDir/$Entry";
				}

				GetDeps($NewFull, $NewRel);
				next;
			}

			# If this is a regular file determine if its a
			# valid ELF dependency.
			if (-f _) {
				my($File);

				# Typically shared object dependencies end with
				# ".so" or ".so.?", hence we can reduce the cost
				# of this script (a lot!) by screening out files
				# that don't follow this pattern.
				if (!$opt{a}) {
					if ($Entry !~ /\.so(?:\.\d+)*$/) {
						next;
					}
				}

				$File = `file $NewFull`;
				if ($File !~ /dynamic lib/) {
					next;
				}

				if ($File =~ /32-bit/) {
					Entercrle32($FullDir, $RelDir, $Entry);
				} elsif ($Ena64) {
					Entercrle64($FullDir, $RelDir, $Entry);
				}
				next;
			}
		}
		closedir(DIR);
	}
}
exit $Error
