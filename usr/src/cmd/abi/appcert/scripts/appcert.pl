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

#
# This is the top level script for performing the appcert checks.  It
# reads the command line options, determines list of binaries to check,
# and then calls symprof (the raw symbol profiler), symcheck (that
# checks for unstable behavior), and symreport (that constructs and
# outputs a rollup report)
#

require 5.005;
use strict;
use locale;
use Getopt::Std;
use POSIX qw(locale_h);
use Sun::Solaris::Utils qw(textdomain gettext);
use File::Basename;
use File::Path;

use lib qw(/usr/lib/abi/appcert);
use AppcertUtil;

setlocale(LC_ALL, "");
textdomain(TEXT_DOMAIN);

use vars qw(
	@item_list
	$file_list
	$do_not_follow_symlinks
	$modify_ld_path
	$append_solaris_dirs_to_ld_path
	$skipped_count
);

my $caught_signal = 0;
my $record_binary_call_count = 0;

# The directory where the appcert specific scripts and data reside:
$appcert_lib_dir = "/usr/lib/abi/appcert";

set_clean_up_exit_routine(\&clean_up_exit);

signals('on', \&interrupted);

get_options();

@item_list = @ARGV;		# List of directories and/or objects to check.
check_item_list();

set_working_dir();

find_binaries();		# Records all of the binary objects to check.

supplement_ld_library_path();

export_vars_to_environment();	# Exports info for our child scripts to use.

run_profiler();			# Run the script symprof.

run_checker();			# Run script symcheck.

run_report_generator();		# Run the script symreport.

my $rc = overall_result_code();

clean_up();

exit $rc;


#
# This subroutine calls getopts() and sets up variables reflecting how
# we were called.
#
sub get_options
{
	my %opt;

	getopts('?hnLBSw:f:', \%opt) || (show_usage() && exiter(2));

	if (exists($opt{'?'}) || exists($opt{'h'})) {
		show_usage();
		exiter(2);
	}

	if (exists($opt{'f'})) {
		$file_list = $opt{'f'};
	} else {
		$file_list = '';
	}

	if (exists($opt{'w'})) {
		$working_dir = $opt{'w'};
	} else {
		$working_dir = '';
	}
	if ($working_dir =~ /'/) {
		#
		# This character will ultimately cause problems with
		# system() and pipelines so we exit now.
		#
		exiter(sprintf(gettext(
		    "directory contains the single-quote character ': %s\n"),
		    $working_dir));
	}

	if (defined($opt{'B'})) {
		$batch_report = 1;
	} else {
		$batch_report = 0;
	}

	if (defined($opt{'n'})) {
		$do_not_follow_symlinks = 1;
	} else {
		$do_not_follow_symlinks = 0;
	}

	if (defined($opt{'L'})) {
		$modify_ld_path = 0;
	} else {
		$modify_ld_path = 1;
	}

	if (defined($opt{'S'})) {
		$append_solaris_dirs_to_ld_path = 1;
	} else {
		$append_solaris_dirs_to_ld_path = 0;
	}
}

#
# Performs an initial check to see if the user supplied anything at all
# to check.  Also reads in the file list if the user supplied one via -f <file>
#
sub check_item_list
{
	# Add the items if the -f flag was used.
	if ($file_list) {
		my $file;
		my $list_fh = do { local *FH; *FH };
		if (-f $file_list && open($list_fh, "<$file_list")) {
			while (<$list_fh>) {
				chomp($file = $_);
				push(@item_list, $file);
			}
			close($list_fh);
		} else {
			exiter(nofile($file_list, $!));
		}
	}

	return if (@item_list);

	emsg("$command_name: " . gettext(
	    "at least one file or directory to check must be specified.") .
	    "\n\n");

	show_usage();
	exiter(3);
}

#
# This subroutine sets up the working directory, the default something
# like: /tmp/appcert.<PID>
#
sub set_working_dir
{
	if ($working_dir) {
		# working_dir has been set in get_options().
		if (! -d $working_dir) {
			if (! mkpath($working_dir) || ! -d $working_dir) {
				exiter(nocreatedir($working_dir, $!));
			}
		} else {
			if (! dir_is_empty($working_dir)) {
				# create a subdir of it for our use.
				$working_dir = create_tmp_dir($working_dir);
			}
		}
	} else {
		# Default case: will create, e.g., /tmp/appcert.12345
		$working_dir = create_tmp_dir();
	}

	if (! -d $working_dir) {
		# We have no working directory.
		exiter(nocreatedir($working_dir));
	}

	#
	# Create a subdirectory of working_dir that will contain all of
	# the object subdirs.
	#
	my $dir = "$working_dir/$object_dir";
	if (! mkpath($dir) || ! -d $dir) {
		exiter(nocreatedir($dir, $!));
	}
	#
	# Make a tmp subdirectory for small temporary work. It is
	# preferred to have it on tmpfs (especially not NFS) for
	# performance reasons.
	#
	$tmp_dir = "/tmp/${command_name}_tmp.$$";
	if (-d $tmp_dir) {
		exiter(nocreatedir("$tmp_dir", $!));
	}
	if (! mkpath($tmp_dir, 0, 0700) || ! -d $tmp_dir) {
		emsg("%s", nocreatedir($tmp_dir, $!));
		# fall back to our output dir (which could have slow access)
		$tmp_dir = "$working_dir/tmp";
		if (! mkpath($tmp_dir)) {
			exiter(nocreatedir($tmp_dir, $!));
		}
	}

	if (! -d $tmp_dir) {
		exiter(nocreatedir($tmp_dir, $!));
	}
}

#
# Top level function to find all the binaries to be checked.  Calls
# record_binary() to do the actual deciding and recording.
#
# The array @item_list contains all the items to find.
#
sub find_binaries
{
	$binary_count = 0;

	my $skipped_file = "$working_dir/Skipped";
	my $skipped_fh = do { local *FH; *FH };
	open($skipped_fh, ">$skipped_file") ||
	    exiter(nofile($skipped_file, $!));

	$skipped_count = 0;

	my ($item, $args, $file);
	emsg("\n" .  gettext(
	    "finding executables and shared libraries to check") . " ...\n");

	$args = '';
	$args .= '-follow ' unless ($do_not_follow_symlinks);
	$args .= '-type f -print';

	my $quote_fmt = gettext(
	    "skipping:  item contains the single-quote character ': %s\n");

	foreach $item (@item_list) {
		if (! -e $item) {
			emsg(gettext("skipping:  %s: %s\n"), $item, $!);
			print $skipped_fh "$item: no_exist\n";
			$skipped_count++;
			next;
		} elsif ($item =~ /'/)  {
			emsg($quote_fmt, $item);
			print $skipped_fh "$item: item_has_bad_char\n";
			$skipped_count++;
			next;
		}
		# note that $item does not contain a single-quote.
		my $find_fh = do { local *FH; *FH };
		open($find_fh, "$cmd_find '$item' $args|") ||
		    exiter(norunprog("$cmd_find '$item' $args", $!));

		while (<$find_fh>) {
			chomp($file = $_);
			#
			# We are free to remove leading "./". This will
			# minimize directory names we create that would
			# start with a dot.
			#
			$file =~ s,^\./,,;

			next if ($file eq '');

			record_binary($file, $skipped_fh);
		}
		close($find_fh);
	}

	if ($binary_count == 0) {
		exiter("$command_name: " . gettext(
		    "no checkable binary objects were found."), 3);
	}

	if ($skipped_count == 0) {
		print $skipped_fh "# NO_FILES_WERE_SKIPPED\n";
	}
	close($skipped_fh);
}

#
# This subroutine will determine if a binary is checkable.
#
# If so, it will reserve a directory for its output in the $working_dir
# location, and store the output of a number of commands there.
#
sub record_binary
{
	my ($file, $skipped_fh) = @_;

	if ((++$record_binary_call_count % 500) == 0) {
		#
		# This indicates are being called many times for a large
		# product.  Clear out our caches.
		#
		purge_caches();
	}

	#
	# Check if the object exists and is regular file.  Note that
	# this test also passes a symlink as long as that symlink
	# ultimately refers to a regular file.
	#
	if (! -f $file) {
		emsg(gettext("skipping:  not a file: %s\n"), $file);
		print $skipped_fh "$file: not_a_file\n";
		$skipped_count++;
		return 0;
	}

	# Check if it is readable:
	if (! -r $file) {
		emsg(gettext("skipping:  cannot read: %s\n"), $file);
		print $skipped_fh "$file: unreadable\n";
		$skipped_count++;
		return 0;
	}

	#
	# Since the filename will be used as operands passed to utility
	# commands via the shell, we exclude at the outset certain meta
	# characters in the filenames.
	#
	my $quote_fmt = gettext(
	    "skipping:  filename contains the single-quote character: ': %s\n");
	if ($file =~ /'/) {
		emsg($quote_fmt, $file);
		print $skipped_fh "$file: filename_has_bad_char\n";
		$skipped_count++;
		return 0;
	}

	my $newline_fmt = gettext(
	    "skipping:  filename contains the newline character: \\n: %s\n");
	if ($file =~ /\n/) {
		emsg($newline_fmt, $file);
		print $skipped_fh "$file: filename_has_bad_char\n";
		$skipped_count++;
		return 0;
	}

	my $pipe_fmt = gettext(
	    "skipping:  filename contains the pipe character: \|: %s\n");
	if ($file =~ /\|/) {
		emsg($pipe_fmt, $file);
		print $skipped_fh "$file: filename_has_bad_char\n";
		$skipped_count++;
		return 0;
	}

	my $file_output;

	# Run the file(1) command on it.

	c_locale(1);
	# note that $file does not contain a single-quote.
	$file_output = `$cmd_file '$file' 2>/dev/null`;
	c_locale(0);

	if ($file_output =~ /script$/) {
		$file_output =~ s/:\s+/: /;
		$file_output =~ s/: /: script /;
		print $skipped_fh "$file_output";

		#
		# again now without the c_locale() setting:
		# note that $file does not contain a single-quote.
		#
		$file_output = `$cmd_file '$file' 2>/dev/null`;
		$file_output =~ s/:\s+/: /;
		emsg(gettext("skipping:  %s"), $file_output);
		$skipped_count++;
		return 0;
	}

	# create ELF and a.out matching regex:
	my $object_match =
	    'ELF.*executable.*dynamically' . '|' .
	    'ELF.*dynamic lib' . '|' .
	    'ELF.*executable.*statically' . '|' .
	    'Sun demand paged SPARC.*dynamically linked' . '|' .
	    'Sun demand paged SPARC executable' . '|' .
	    'pure SPARC executable' . '|' .
	    'impure SPARC executable';

	#
	# Note that we let the "statically linked" binaries through
	# here, but will catch them later in the profiler and checker.
	#

	if ($file_output !~ /$object_match/io) {
		# it is not an ELF object file and so does not interest us.
		return 0;
	}

	my $exec_fmt = gettext(
	    "skipping:  must have exec permission to be checked: %s\n");
	if (! -x $file) {
		#
		# It interests us, but the execute bit not set.  Shared
		# objects will be let through here since ldd will still
		# work on them (since it uses lddstub).  Otherwise, we
		# cannot check it.
		#
		if (! is_shared_object($file)) {
			# warn the user exec bit should be set:
			emsg($exec_fmt, $file);
			print $skipped_fh "$file: no_exec_permission\n";
			$skipped_count++;
			return 0;
		}
	}

	#
	# Rather than let ldd fail later on in symprof, we check the
	# arch here to make sure it matches $uname_p.  If it does not
	# match, we anticipate a 64-bit application and so we
	# immediately test how ldd will handle it (kernel might be
	# 32-bit, etc).
	#
	my ($arch, $type, $wordsize, $endian, $e_machine) = bin_type($file);

	if ($arch !~ /^${uname_p}$/io) {
		my ($ldd_output, $ldd_output2);

		#
		# Now run ldd on it to see how things would go.  If it
		# fails we must skip it.
		#
		c_locale(1);
		# note that $file does not contain single-quote
		$ldd_output = `$cmd_ldd '$file' 2>&1 1>/dev/null`;
		c_locale(0);
		if ($? != 0) {
			# note that $file does not contain a single-quote
			$ldd_output2 = `$cmd_ldd '$file' 2>&1 1>/dev/null`;
			$ldd_output	=~ s/\n.*$//;
			$ldd_output2	=~ s/\n.*$//;
			if ($ldd_output !~ /wrong class/) {
				$ldd_output = "$file: " . sprintf(
				    gettext("ldd failed for arch: %s"), $arch);
				$ldd_output2 = $ldd_output;
			} else {
				$ldd_output	.= " ($arch)";
				$ldd_output2	.= " ($arch)";
			}
			$ldd_output	=~ s/:\s+/: /;
			$ldd_output2	=~ s/:\s+/: /;
			emsg(gettext("skipping:  %s\n"), $ldd_output2);
			$ldd_output =~ s/: /: ldd_failed /;
			print $skipped_fh "$ldd_output\n";
			$skipped_count++;
			return 0;
		}
	}

	# From this point on, object is one we decided to check.

	# Create the directory name for this object:
	my $dirname = object_to_dir_name($file);
	my $dirpath = "$working_dir/$dirname";
	my $early_fmt = gettext(
	    "skipping:  %s referenced earlier on the command line\n");
	if (-e $dirpath) {
		#
		# Directory already exists.  We assume this means the
		# user listed it twice (possibly indirectly via "find").
		#
		emsg($early_fmt, $file);
		return 0;
	}

	if (! mkdir($dirpath, 0777)) {
		exiter(nocreatedir($dirpath, $!));
	}

	$binary_count++;

	# Record binary object's location:
	my $path_fh = do { local *FH; *FH };
	open($path_fh, ">$dirpath/info.path") ||
	    exiter(nofile("$dirpath/info.path", $!));
	print $path_fh $file, "\n";
	close($path_fh);

	#
	# Record file(1) output.  Note that the programmatical way
	# to access this info is through the command cmd_output_file().
	#
	my $file_fh = do { local *FH; *FH };
	open($file_fh, ">$dirpath/info.file") ||
	    exiter(nofile("$dirpath/info.file", $!));
	print $file_fh $file_output;
	close($file_fh);

	#
	# Record dump -Lv output.  Note that the programmatical way to
	# access this info is through the command cmd_output_dump().
	#
	my $dump_fh = do { local *FH; *FH };
	open($dump_fh, ">$dirpath/info.dump") ||
	    exiter(nofile("$dirpath/info.dump", $!));

	my $dump_output;
	c_locale(1);
	# note that $file does not contain a single-quote
	$dump_output = `$cmd_dump -Lv '$file' 2>&1`;
	c_locale(0);
	print $dump_fh $dump_output;
	close($dump_fh);

	#
	# Record arch and etc binary type.
	#
	my $arch_fh = do { local *FH; *FH };
	open($arch_fh, ">$dirpath/info.arch") ||
	    exiter(nofile("$dirpath/info.arch", $!));

	if ($arch eq 'unknown') {
		my $tmp = $file_output;
		chomp($tmp);
		emsg(gettext("warning:   cannot determine arch: %s\n"), $tmp);
	}

	print $arch_fh "ARCH: $arch\n";
	print $arch_fh "TYPE: $type\n";
	print $arch_fh "WORDSIZE: $wordsize\n";
	print $arch_fh "BYTEORDER: $endian\n";
	print $arch_fh "E_MACHINE: $e_machine\n";
	close($arch_fh);

	# Record the file -> directory name mapping in the index file.
	my $index_file   = "$working_dir/Index";
	my $index_fh = do { local *FH; *FH };
	open($index_fh, ">>$index_file") ||
	    exiter(nofile($index_file, $!));
	print $index_fh "$file => $dirname\n";
	close($index_fh);

	return 1;
}

#
# Prints the usage statement to standard out.
#
sub show_usage
{
	emsg(gettext(
	"usage:	appcert [ -nBLS ] [ -f file ] [ -w dir ] { obj | dir } ...\n" .
	"	Examine binary object files for use of private Solaris\n" .
	"	interfaces, unstable use of static linking, and other\n" .
	"	unstable practices.\n")
	);
}

#
# Examines the set of binaries to be checked and notes which ones are
# shared libraries. Constructs a LD_LIBRARY_PATH that would find ALL of
# these shared objects. The new directories are placed at the END of the
# current LD_LIBRARY_PATH (if any).
#
sub supplement_ld_library_path
{
	my (@orig, @add_product, @add_solaris, %ldpath);

	# First, note the current LD_LIBRARY_PATH parts:

	my $dirname;
	if (defined($ENV{'LD_LIBRARY_PATH'})) {
		foreach $dirname (split(/:/, $ENV{'LD_LIBRARY_PATH'})) {
			if (! exists($ldpath{$dirname})) {
				push(@orig, $dirname);
				$ldpath{$dirname} = 1;
			}
		}
	}

	# Next, search for ELF shared objects.
	my ($dir, $path);

	if ($modify_ld_path) {
		while (defined($dir = next_dir_name())) {
			$path = dir_name_to_path($dir);

			$dirname = dirname($path);
			next if (exists($ldpath{$dirname}));

			#
			# A colon ":" in directory name is cannot be
			# accepted because that is the LD_LIBRARY_PATH
			# separator.
			#
			next if ($dirname =~ /:/);

			if (is_shared_object($path)) {
				if (! exists($ldpath{$dirname})) {
					push(@add_product, $dirname);
					$ldpath{$dirname} = 1;
				}
			}
		}
	}

	if ($append_solaris_dirs_to_ld_path) {
		foreach $dirname (split(/:/, $solaris_library_ld_path)) {
			if (! exists($ldpath{$dirname})) {
				push(@add_solaris, $dirname);
				$ldpath{$dirname} = 1;
			}
		}
	}

	# modify the LD_LIBRARY_PATH:
	if (@add_product || @add_solaris) {
		$ENV{'LD_LIBRARY_PATH'} =
		    join(':', (@orig, @add_product, @add_solaris));
	}

	emsg("\n");
	if (@add_product) {
		emsg(gettext(
		    "Shared libraries were found in the application and the\n" .
		    "following directories are appended to LD_LIBRARY_PATH:\n"
		    ) . "\n");

		foreach $dir (@add_product) {
			$dir = "./$dir" unless ($dir =~ m,^/,);
			emsg("   $dir\n");
		}
		emsg("\n");
	}

	if (@add_solaris) {
		emsg(gettext(
		    "These Solaris library directories are being appended\n" .
		    "to LD_LIBRARY_PATH:\n") . "\n");

		foreach $dir (@add_solaris) {
			emsg("   $dir\n");
		}
		emsg("\n");
	}
}

#
# Everything is correctly exported by now, and so we just run "symprof".
# It is run in batches of $block_size binaries to minimize the effect of
# memory usage caused by huge binaries in the product to be checked.
#
sub run_profiler
{
	my $block_size = 20;

	my $i = 0;

	# record old values of the blocks (if any)
	my $env_min = $ENV{'AC_BLOCK_MIN'};
	my $env_max = $ENV{'AC_BLOCK_MAX'};

	while ($i < $binary_count) { # do each block
		# export our symprof values of the block limits
		$ENV{'AC_BLOCK_MIN'} = $i;
		$ENV{'AC_BLOCK_MAX'} = $i + $block_size;

		run_symprof();

		$i += $block_size;
	}

	# restore old values of the blocks (if any)
	if (defined($env_min)) {
		$ENV{'AC_BLOCK_MIN'} = $env_min;
	} else {
		delete $ENV{'AC_BLOCK_MIN'};
	}
	if (defined($env_max)) {
		$ENV{'AC_BLOCK_MAX'} = $env_max;
	} else {
		delete $ENV{'AC_BLOCK_MAX'};
	}
}

#
# Sub that actually runs "symprof".
#
sub run_symprof
{
	system("$appcert_lib_dir/symprof");
	if ($? != 0) {
		emsg("%s", utilityfailed("symprof"));
		clean_up_exit(1);
	}
}

#
# Sub to run "symcheck".
#
sub run_checker
{
	system("$appcert_lib_dir/symcheck");
	if ($? != 0) {
		emsg("%s", utilityfailed("symcheck"));
		clean_up_exit(1);
	}
}

#
# Sub to run "symreport".
#
sub run_report_generator
{
	system("$appcert_lib_dir/symreport");
	if ($? != 0) {
		emsg("%s", utilityfailed("symreport"));
		clean_up_exit(1);
	}
}

#
# General routine to be called if one of our utility programs (symprof,
# symcheck, symreport) failed (that is, return != 0).  returns the
# formatted error message string to pass to the user.
#
sub utilityfailed
{
	my ($prog) = @_;
	my $fmt;
	$fmt = "\n *** " . gettext("utility program failed: %s\n");
	return sprintf($fmt, $prog);
}

#
# Does the cleanup and then exits with return code $rc.  The utility
# subroutine exiter() will call this subroutine.  No general cleanup is
# performed if exiting with error ($rc > 0) so that the user can examine
# at the output files, etc.
#
sub clean_up_exit
{
	my ($rc) = @_;

	if ($rc != 0) {
		working_dir_msg();
	} else {
		clean_up();
	}

	exit $rc;
}

#
# General cleanup routine.
#
sub clean_up
{
	if (-d $tmp_dir && ($tmp_dir !~ m,^/+$,)) {
		rmdir($tmp_dir);
	}
}

#
# Routine that is called when an error has occurred.  It indicates to
# user where the working and/or temporary directory is and that they are
# not being removed.
#
sub working_dir_msg
{

	my @dirlist;
	emsg("\n");
	if (defined($working_dir) && -d $working_dir) {
		push(@dirlist, $working_dir);
	}
	if (defined($tmp_dir) && -d $tmp_dir) {
		push(@dirlist, $tmp_dir);
	}

	return if (! @dirlist);

	emsg(gettext(
	    "Note that the temporary working directories still exist:") .
	    "\n\n");

	my $dir;
	# show the user explicitly which directories remains:
	foreach $dir (@dirlist) {
		system($cmd_ls, '-ld', $dir);
	}

	emsg("\n");
}

#
# Signal handler for interruptions (E.g. Ctrl-C SIGINT).
#
sub interrupted
{
	$SIG{$_[0]} = 'IGNORE';

	exit 1 if ($caught_signal);
	$caught_signal = 1;

	signals('off');
	emsg("\n** " . gettext("interrupted") . " **\n");

	clean_up_exit(1);
}
