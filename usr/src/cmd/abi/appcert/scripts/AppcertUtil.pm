#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
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
# This module contains utility routines and data for use by the appcert
# programs: appcert, symprof, symcheck, and symreport.
#

package AppcertUtil;

require 5.005;
use strict;
use locale;
use Getopt::Std;
use POSIX qw(locale_h);
use Sun::Solaris::Utils qw(textdomain gettext);
use File::Basename;
use File::Path;

BEGIN {
	use Exporter();
	use vars qw(@ISA @EXPORT @EXPORT_OK %EXPORT_TAGS);

	@ISA = qw(Exporter);
	@EXPORT = qw(
		$command_name
		$object_dir
		$solaris_library_ld_path
		$uname_p
		$working_dir
		$appcert_lib_dir
		$batch_report
		$binary_count
		$block_min
		$block_max
		$tmp_dir

		$cmd_dump
		$cmd_elfdump
		$cmd_file
		$cmd_find
		$cmd_ldd
		$cmd_ls
		$cmd_more
		$cmd_pvs
		$cmd_sort
		$cmd_uname
		$cmd_uniq

		@lib_index_loaded

		%lib_index_definition
		%text
		%model_tweak
		%skip_symbols
		%scoped_symbol
		%scoped_symbol_all
		%warnings_bind
		%warnings_desc
		%warnings_match

		&object_to_dir_name
		&dir_name_to_path
		&next_dir_name
		&cmd_output_file
		&cmd_output_dump
		&all_ldd_neededs
		&all_ldd_neededs_string
		&direct_syms
		&import_vars_from_environment
		&export_vars_to_environment
		&c_locale
		&overall_result_code
		&trim
		&sort_on_count
		&print_line
		&list_format
		&emsg
		&pmsg
		&nofile
		&nopathexist
		&norunprog
		&nocreatedir
		&exiter
		&set_clean_up_exit_routine
		&signals
		&create_tmp_dir
		&dir_is_empty
		&follow_symlink
		&is_statically_linked
		&is_elf
		&is_shared_object
		&is_aout
		&is_suid
		&bin_type
		&files_equal
		&purge_caches
		&filter_lib_type
		&load_model_index
		&load_misc_check_databases
	);

	@EXPORT_OK = ();

	%EXPORT_TAGS = ();
}

use vars @EXPORT;
use vars @EXPORT_OK;

use vars qw(
	$lib_match_initialized

	%lib_index
	%lib_index_loaded
	%shared_object_index

	%file_inode_cache
	%file_exists_cache
	%filter_lib_cache
	%lib_match_cache
	%cmd_output_file_cache
	%cmd_output_dump_cache
	%all_ldd_neededs_cache
);

my $clean_up_exit_routine;
my $tmp_dir_count = 0;
my $next_dir_name_dh;
my $LC_ALL = '';

# Get the name of the program:
$command_name = basename($0);

$cmd_dump	= '/usr/ccs/bin/dump';
$cmd_elfdump	= '/usr/ccs/bin/elfdump';
$cmd_file	= '/usr/has/bin/file';
$cmd_find	= '/usr/bin/find';
$cmd_ldd	= '/usr/bin/ldd';
$cmd_ls		= '/usr/bin/ls';
$cmd_more	= '/usr/bin/more';
$cmd_pvs	= '/usr/bin/pvs';
$cmd_sort	= '/usr/bin/sort';
$cmd_uname	= '/usr/bin/uname';
$cmd_uniq	= '/usr/bin/uniq';

chomp($uname_p	= `$cmd_uname -p`);


# Initialize constants:

$solaris_library_ld_path = "/usr/openwin/lib:/usr/dt/lib";

# Prefix for every object's profiling (etc) subdir in $working_dir.
$object_dir = 'objects/';

$text{'Summary_Result_None_Checked'} = gettext(
    "No binaries were checked.");
$text{'Summary_Result_Some_Failed'} = gettext(
    "Potential binary stability problem(s) detected.");
$text{'Summary_Result_Some_Incomplete'} = gettext(
    "No stability problems detected, but not all binaries were checked.");
$text{'Summary_Result_All_Passed'} = gettext(
    "No binary stability problems detected.");


$text{'Message_Private_Symbols_Check_Outfile'} = <<"END";
#
# <binary>|<abi>|<caller>|<callee>|private|<symbol>
#
END

$text{'Message_Public_Symbols_Check_Outfile'} =
	$text{'Message_Private_Symbols_Check_Outfile'};
$text{'Message_Public_Symbols_Check_Outfile'} =~ s/private/public/g;

#
# Maps a filesystem path of a binary object to a subdirectory name (in
# $working_dir).  $working_dir is NOT prepended.
#
# Maps, e.g., /home/auser/bin/netscape.sparc
#      ===> objects/:=home=auser=bin=netscape.sparc
#
sub object_to_dir_name
{
	my ($filename) = @_;

	my $dirname = $filename;

	# protect any percents there:
	$dirname =~ s,%,%%,g;

	# protect any equals there:
	$dirname =~ s,=,%=,g;

	# now change slashes to equals:
	$dirname =~ s,/,=,g;

	#
	# Prepend "objects/" and ":" tag to avoid dirname starting
	# with "=" or "."
	#
	$dirname = $object_dir . ':' . $dirname;

	return $dirname;
}

#
# Takes the application output data directory and returns the path to
# the actual binary.
#
sub dir_name_to_path
{
	my ($dirname) = @_;
	my $path = '';

	if (! -f "$dirname/info.path") {
		exiter(nofile("$dirname/info.path", $!));
	} else {
		my $info_path_fh = do { local *FH; *FH };
		open($info_path_fh, "<$dirname/info.path") ||
		    exiter(nofile("$dirname/info.path", $!));
		chomp($path = <$info_path_fh>);
		close($info_path_fh);
	}

	return $path;
}

#
# This subroutine repeatly returns the object dirnames in the
# working_dir.  The full path to the dirname is returned.  "undef" is
# returned when all have been cycled through.
#
sub next_dir_name
{
	# object directory:
	my $object_directory = $working_dir;
	$object_directory .= "/" . $object_dir if ($object_dir);

	# Check if we have the directory handle already open:
	if (! defined($next_dir_name_dh)) {
		# If not, then opendir it:
		$next_dir_name_dh = do { local *FH; *FH };
		if (! opendir($next_dir_name_dh, $object_directory)) {
			exiter(nodir($object_directory, $!));
		}
	}

	my $dirname;

	#
	# Loop over directory entries until one matches the magic tag
	# "object:" Return undef when done reading the directory.
	#
	while (1) {
		$dirname = readdir($next_dir_name_dh);

		if (! defined($dirname)) {
			# Done with dir. Clean up for next time:
			closedir($next_dir_name_dh);
			undef($next_dir_name_dh);
			return undef;
		} elsif ($dirname =~ m,^:,) {
			# Return the full path to object's directory:
			return "$object_directory/$dirname";
		}
	}
}

#
# When appcert started up, it stored the file(1) output in the
# app's output directory (appcert: record_binary()). This subroutine
# retrieves it.  If it cannot find it, it runs the file command
# instead.  The result is stored in memory in %cmd_output_file_cache
#
# Returns the single line of "file" output including the "\n".  It
# returns the null string if it had trouble, usually only if filename
# doesn't exist.
#
sub cmd_output_file
{
	my ($filename) = @_;

	# Check if we have it cached:
	if (exists($cmd_output_file_cache{$filename})) {
		return $cmd_output_file_cache{$filename};
	}

	# Otherwise, try to look it up in the $working_dir:
	my $outfile = object_to_dir_name($filename);
	$outfile = "$working_dir/$outfile/info.file";

	my $str;

	if (-f $outfile) {
		my $file_cmd_fh = do { local *FH; *FH };
		if (open($file_cmd_fh, "<$outfile")) {
			$str = <$file_cmd_fh>;
			close($file_cmd_fh);
		}
	}

	# Otherwise run file(1) on it:
	if (! defined($str) && -f $filename && $filename !~ /'/) {
		c_locale(1);
		$str = `$cmd_file '$filename' 2>/dev/null`;
		c_locale(0);
	}

	$cmd_output_file_cache{$filename} = $str;

	return $str;
}

#
# When appcert started up, it stored the /usr/ccs/bin/dump output in the
# app's output directory (appcert: record_binary()). This subroutine
# retrieves it.  If it cannot find it, it runs the dump -Lv command
# instead.  The result is stored in memory in %cmd_output_dump_cache
#
# Returns the "dump -Lv" output.  It returns the null string if it had
# trouble, usually only if filename doesn't exist.
#
sub cmd_output_dump
{
	my ($filename) = @_;

	# Check if we have it cached:
	if (exists($cmd_output_dump_cache{$filename})) {
		return $cmd_output_dump_cache{$filename};
	}

	# Otherwise, try to look it up in the $working_dir:
	my $outfile = object_to_dir_name($filename);
	$outfile = "$working_dir/$outfile/info.dump";

	my $str;

	if (-f $outfile) {
		my $dump_cmd_fh = do { local *FH; *FH };
		if (open($dump_cmd_fh, "<$outfile")) {
			while (<$dump_cmd_fh>) {
				$str .= $_;
			}
			close($dump_cmd_fh);
		}
	}

	# Otherwise run /usr/ccs/bin/dump -Lv on it:
	if (! defined($str) && -f $filename && $filename !~ /'/) {
		c_locale(1);
		$str = `$cmd_dump -Lv '$filename' 2>/dev/null`;
		c_locale(0);
	}

	$cmd_output_dump_cache{$filename} = $str;

	return $str;
}

#
# When symprof runs it stores the /usr/bin/ldd output in the app's
# output directory (symprof: dynamic_profile()). This subroutine
# retrieves it. If it cannot find it, it runs the ldd command instead.
# The result is stored in memory in %all_ldd_neededs_cache
#
# Returns a "neededs hash" as output. The keys being the things needed
# (left side of " => ") and the values are the resolution (right side of
# " => ").  It returns the null hash if it had trouble, usually only if
# filename doesn't even exist, or if the object is not dynamically
# linked.
#
sub all_ldd_neededs
{
	my ($filename) = @_;

	my (%all_neededs);

	my $output;

	# Check if we have it cached:
	if (exists($all_ldd_neededs_cache{$filename})) {
		$output = $all_ldd_neededs_cache{$filename};
	}

	if (! defined($output)) {
		# Otherwise, try to look it up in the $working_dir:
		my $outfile = object_to_dir_name($filename);
		$outfile = "$working_dir/$outfile/profile.dynamic.ldd";

		if (-f $outfile) {
			my $all_neededs_fh = do { local *FH; *FH };
			if (open($all_neededs_fh, "<$outfile")) {
				while (<$all_neededs_fh>) {
					next if (/^\s*#/);
					$output .= $_;
				}
			}
			close($all_neededs_fh);
		}
	}

	my ($str, $line, $l1, $l2);
	if (! defined($output) && -f $filename && $filename !~ /'/) {
		# Otherwise run /usr/bin/ldd on it:
		c_locale(1);
		$str = `$cmd_ldd '$filename' 2>/dev/null`;
		c_locale(0);
		foreach $line (split(/\n/, $str)) {
			$line = trim($line);
			$output .= "$line\n";
		}
	}

	if (! defined($output)) {
		#
		# Set the output to the null string so following loop
		# will do nothing and thus the empty hash will be
		# returned.
		#
		$output = '';
	}

	$all_ldd_neededs_cache{$filename} = $output;

	foreach $line (split(/\n/, $output)) {
		($l1, $l2) = split(/\s*=>\s*/, $line);
		$l1 = trim($l1);
		$l2 = trim($l2);
		$all_neededs{$l1} = $l2;
		if ($l2 !~ /file not found/) {
			$all_neededs{$l2} = $l2;
		}
	}

	return %all_neededs;
}

#
# Create a string with all of the needed objects (direct and indirect).
# This is intended for object name matching.  See the 'needed' MATCH
# entries in etc.warn.
#
sub all_ldd_neededs_string
{
	my ($filename) = @_;
	my (%hash, $key);
	my $str = '';
	%hash = all_ldd_neededs($filename);
	foreach $key (keys(%hash)) {
		$str .= "$key $hash{$key}\n";
	}
	return $str;
}

#
# Create a list with all of the directly bound symbols.  This is
# intended for symbol call matching.  See the 'syms' MATCH entries in
# etc.warn.
#
sub direct_syms
{
	my ($filename) = @_;
	#
	# We stored the dynamic profile output in the app's output
	# directory. This subroutine retrieves it, identifies the
	# direct bindings symbol names and places them in a newline
	# separated string returned to caller.
	#
	my $direct_syms = '';

	my $outfile = object_to_dir_name($filename);
	$outfile = "$working_dir/$outfile/profile.dynamic";

	my $prof_fh = do { local *FH; *FH };
	if (! open($prof_fh, "<$outfile")) {
		exiter(nofile($outfile, $!));
	}
	my ($app, $caller, $lib, $sym);
	while (<$prof_fh>) {
		next if (/^\s*#/);
		next if (/^\s*$/);
		chop;
		($app, $caller, $lib, $sym) = split(/\|/, $_, 4);
		next unless ($caller eq '*DIRECT*');
		$direct_syms .= "$sym\n";
	}
	close($prof_fh);

	return $direct_syms;
}

#
# Block to keep export_list private
#
{
	my %export_list = (
		'AC_LIB_DIR',		'appcert_lib_dir',
		'AC_WORKING_DIR',	'working_dir',
		'AC_TMP_DIR',		'tmp_dir',
		'AC_BINARY_COUNT',	'binary_count',
		'AC_BLOCK_MIN',		'block_min',
		'AC_BLOCK_MAX',		'block_max',
		'AC_BATCH_REPORT',	'batch_report',
	);


	#
	# Subroutine to read in possibly exported variables
	#
	sub import_vars_from_environment
	{
		no strict qw(refs);

		while (my ($evar, $pvar) = each(%export_list)) {
			$pvar = $export_list{$evar};
			if (exists($ENV{$evar})) {
				$$pvar = $ENV{$evar};
			} else {
				$$pvar = '';
			}
		}
	}

	#
	# Exports the variables in %export_list to the environment.
	#
	sub export_vars_to_environment
	{
		my $pval;
		no strict qw(refs);

		while (my ($evar, $pvar) = each(%export_list)) {
			$pvar = $export_list{$evar};
			$pval = $$pvar;
			if (defined($pval)) {
				$ENV{$evar} = $pval;
			}
		}
	}
}

#
# Routine for turning on or off LC_ALL environment variable 'C'.  When
# we want command output that we will parse we set LC_ALL=C.  On the
# other hand, when we want to pass command output to the user we retain
# their locale (if any).
#
sub c_locale
{
	my ($action) = @_;

	#
	# example usage:
	#	c_locale(1);
	#	$output = `some_cmd some_args 2>/dev/null`;
	#	c_locale(0);
	#

	if ($action) {
		if (defined($ENV{'LC_ALL'})) {
			$LC_ALL = $ENV{'LC_ALL'};
		} else {
			$LC_ALL = '__UNSET__';
		}
		$ENV{'LC_ALL'} = 'C';
	} else {
		if ($LC_ALL eq '__UNSET__') {
			delete $ENV{'LC_ALL'};
		} else {
			$ENV{'LC_ALL'} = $LC_ALL;
		}
	}
}

#
# Set or get the overall appcert result/return code.
#
sub overall_result_code
{
	my ($val) = @_;
	#
	# The code has significance (see below) and is the numerical
	# exit() code for the appcert script.
	#
	# Code can be number followed by 1-line description.
	#
	# 0	appcert completed OK and ZERO binaries had problems detected
	#                            and ZERO binaries had "warnings".
	# 1	appcert failed somehow
	# 2	appcert completed OK and SOME binaries had problems detected.
	# 3	appcert completed OK and ZERO binaries had problems detected.
	#                            and SOME binaries had "warnings".
	#
	# When called with a no arguments, only the number is returned.
	# When called with a non-null argument it is written to the rc file.
	#

	my ($return_code_file, $line);

	$return_code_file = "$working_dir/ResultCode";

	my $rc_file_fh = do { local *FH; *FH };
	if (! defined($val)) {
		if (! -f $return_code_file) {
			emsg("%s", nofile($return_code_file));
			return 1;
		}
		open($rc_file_fh, "<$return_code_file") ||
		    exiter(nofile($return_code_file, $!));
		chomp($line = <$rc_file_fh>);
		close($rc_file_fh);
		if ($line =~ /^(\d+)/) {
			return $1;
		} else {
			return $line;
		}
	} else {
		$val = trim($val);
		if ($val !~ /^\d+/) {
			$val = "1 $val";
		}
		open($rc_file_fh, ">$return_code_file") ||
		    exiter(nofile($return_code_file, $!));
		print $rc_file_fh $val, "\n";
		close($rc_file_fh);
		return;
	}
}

#
# Sorter for strings like: "something 14", sorts on count (number)
# first, then by string.
#
sub sort_on_count
{
	my $soc_cmp = sub {
		my($n1, $n2);
		if ($a =~ /(\d+)\s*$/) {
			$n1 = $1;
		} else {
			$n1 = 0;
		}
		if ($b =~ /(\d+)\s*$/) {
			$n2 = $1;
		} else {
			$n2 = 0;
		}

		if ($n1 == $n2) {
			# if the numbers are "tied", then compare the
			# string portion.
			$a cmp $b;
		} else {
			# otherwise compare numerically:
			$n2 <=> $n1;
		}
	};
	return sort $soc_cmp @_;
}

#
# Trims leading and trailing whitespace from a string.
#
sub trim
{
	my ($x) = @_;
	if (! defined($x)) {
		return '';
	}
	$x =~ s/^\s*//;
	$x =~ s/\s*$//;
	return $x;
}

#
# Prints a line to filehandle or STDOUT.
#
sub print_line
{
	my ($fh) = @_;
	if (defined($fh)) {
		print $fh '-' x 72, "\n";
	} else {
		print STDOUT '-' x 72, "\n";
	}
}

#
# Returns formatted output of list items that fit in 80 columns, e.g.
# Gelf_got_title 1            Gelf_reloc_entry 1
# Gelf_ver_def_print 1        Gelf_syminfo_entry_title 1
# Gelf_sym_table_title 1      Gelf_elf_header 1
#
sub list_format
{
	my ($indent, @list) = @_;

	# $indent is a string which shifts everything over to the right.

	my $width = 0;
	my ($item, $len, $space);

	foreach $item (@list) {		# find the widest list item.
		$len = length($item);
		$width = $len if ($len > $width);
	}
	$width += 2;			# pad 2 spaces for each column.

	if ($width > (80 - length($indent))) {
		$width = 80 - length($indent);
	}

	# compute number of columns:
	my $columns = int((80 - length($indent))/$width);

	# initialize:
	my $current_column = 0;
	my $text = $indent;

	# put the items into lined up columns:
	foreach $item (@list) {
		if ($current_column >= $columns) {
			$text .= "\n";
			$current_column = 0;
			$text .= $indent;
		}
		$space = $width - length($item);
		$text .= $item . ' ' x $space if ($space > 0);
		$current_column++;
	}
	$text .= "\n" if ($current_column);

	return $text;
}

#
# Wrapper for STDERR messages.
#
sub emsg
{
	printf STDERR @_;
}

#
# Wrapper for STDOUT messages.
#
sub pmsg
{
	printf STDOUT @_;
}

#
# Error message for a failed file open.
#
sub nofile
{
	my $msg = "$command_name: ";
	$msg .= gettext("cannot open file: %s\n");
	$msg = sprintf($msg, join(' ', @_));

	return $msg;
}

#
# Error message for an invalid file path.
#
sub nopathexist
{
	my $msg = "$command_name: ";
	$msg .= gettext("path does not exist: %s\n");
	$msg = sprintf($msg, join(' ', @_));

	return $msg;
}

#
# Error message for a failed running of a command.
#
sub norunprog
{
	my $msg = "$command_name: ";
	$msg .= gettext("cannot run program: %s\n");
	$msg = sprintf($msg, join(' ', @_));

	return $msg;
}

#
# Error message for a failed directory creation.
#
sub nocreatedir
{
	my $msg = "$command_name: ";
	$msg .= gettext("cannot create directory: %s\n");
	$msg = sprintf($msg, join(' ', @_));

	return $msg;
}

#
# Error message for a failed directory opendir.
#
sub nodir
{
	my $msg = "$command_name: ";
	$msg .= gettext("cannot open directory: %s\n");
	$msg = sprintf($msg, join(' ', @_));

	return $msg;
}

#
# exiter routine wrapper is used primarily to abort.  Calls
# clean_up_exit() routine if that routine is defined.  Prints $msg to
# STDERR and exits with exit code $status $status is 1 (aborted command)
# by default.
#
sub exiter
{
	my ($msg, $status) = @_;

	if (defined($msg) && ! defined($status) && $msg =~ /^\d+$/) {
		$status = $msg;
		undef($msg);
	}
	if (! defined($status)) {
		$status = 1;
	}

	if (defined($msg)) {
		#
		# append a newline unless one is already there or string
		# is empty:
		#
		$msg .= "\n" unless ($msg eq '' || $msg =~ /\n$/);
		emsg($msg);
	}
	if (defined($clean_up_exit_routine)) {
		&$clean_up_exit_routine($status);
	}

	exit $status;
}

sub set_clean_up_exit_routine
{
	my($code_ref) = @_;
	$clean_up_exit_routine = $code_ref;
}

#
# Generic routine for setting up signal handling.  (usually just a clean
# up and exit routine).
#
# Call with mode 'on' and the name of the handler subroutine.
# Call with mode 'off' to set signal handling back to defaults
# (e.g. a handler wants to call signals('off')).
# Call it with 'ignore' to set them to ignore.
#
sub signals
{
	my ($mode, $handler) = @_;

	# List of general signals to handle:
	my (@sigs) = qw(INT QUIT);

	my $sig;

	# Loop through signals and set the %SIG array accordingly.

	if ($mode eq 'on') {
		foreach $sig (@sigs) {
			$SIG{$sig} = $handler;
		}
	} elsif ($mode eq 'off') {
		foreach $sig (@sigs) {
			$SIG{$sig} = 'DEFAULT';
		}
	} elsif ($mode eq 'ignore') {
		foreach $sig (@sigs) {
			$SIG{$sig} = 'IGNORE';
		}
	}
}

#
# Creates a temporary directory with a unique name.  Directory is
# created and the directory name is return.  On failure to create it,
# null string is returned.
#
sub create_tmp_dir
{
	my ($basedir) = @_;
	#
	# If passed a prefix in $prefix, try to create a unique tmp dir
	# with that basedir. Otherwise, it will make a name in /tmp.
	#
	# If passed a directory that already exists, a subdir is created
	# with madeup basename "prefix.suffix"
	#

	my $cmd = $command_name;
	$cmd = 'tempdir' unless (defined($cmd) && $cmd ne '');

	if (! defined($basedir) || ! -d $basedir) {
		$basedir = "/tmp/$cmd";
	} else {
		$basedir = "$basedir/$cmd";
	}

	my $suffix = $$;
	if ($tmp_dir_count) {
		$suffix .= ".$tmp_dir_count";
	}
	my $dir = "$basedir.$suffix";
	$tmp_dir_count++;
	if ($dir =~ m,^/tmp/,) {
		if (! mkpath($dir, 0, 0700) || ! -d $dir) {
			emsg("%s", nocreatedir($dir, $!));
			return '';
		}
	} else {
		if (! mkpath($dir) || ! -d $dir) {
			emsg("%s", nocreatedir($dir, $!));
			return '';
		}
	}
	return $dir;
}

#
# Checks to see if a directory is empty.  Returns 1 if the directory is.
# returns 0 if it is not or if directory does not exist.
#
sub dir_is_empty
{
	my ($dir) = @_;

	return 0 if (! -d $dir);

	my $is_empty = 1;

	my $dir_is_empty_dh = do { local *FH; *FH };
	if (opendir($dir_is_empty_dh, $dir)) {
		my $subdir;
		foreach $subdir (readdir($dir_is_empty_dh)) {
			if ($subdir ne '.' && $subdir ne '..') {
				$is_empty = 0;
				last;
			}
		}
		close($dir_is_empty_dh);
	} else {
		return 0;
	}

	return $is_empty;
}

#
# Follows a symbolic link until it points to a non-symbolic link.  If
# $file is not a symlink but rather a file, returns $file.  Returns null
# if what is pointed to does not exist.
#
sub follow_symlink
{
	my ($file) = @_;

	if (! -e $file) {
		# We will never find anything:
		return '';
	}

	if (! -l $file) {
		# Not a symlink:
		return $file;
	}

	my ($tmp1, $tmp2);

	$tmp1 = $file;

	while ($tmp2 = readlink($tmp1)) {

		if ($tmp2 !~ m,^/,) {
			$tmp2 = dirname($tmp1) . "/" . $tmp2;
		}

		$tmp1 = $tmp2;			#
		$tmp1 =~ s,/+,/,g;		# get rid of ////
		$tmp1 =~ s,^\./,,g;		# remove leading ./
		$tmp1 =~ s,/\./,/,g;		# remove /./
		$tmp1 =~ s,/+,/,g;		# get rid of //// again
		$tmp1 =~ s,/[^/]+/\.\./,/,g;	# remove "abc/.."
						#

		if (! -e $tmp1) {
			$tmp1 = $tmp2;
		}
		if (! -e $tmp1) {
			return '';
		}
	}

	return $tmp1;
}

#
# Examines if the file is statically linked.  Can be called on any file,
# but it is preferable to run it on things known to be executables or
# libraries.
#
# Returns 0 if not statically linked. Otherwise, returns 1.
#
sub is_statically_linked
{
	my ($file) = @_;

	my $tmp;
	my $file_cmd_output;
	$file_cmd_output = cmd_output_file($file);

	if ($file_cmd_output eq '') {
		return 1;
	}

	if ($file_cmd_output =~ /[:\s](.*)$/) {
		$tmp = $1;
		if ($tmp =~ /ELF.*statically linked/) {
			return 1;
		} elsif ($tmp =~ /Sun demand paged/) {
			if ($tmp !~ /dynamically linked/) {
				return 1;
			}
		}
	}

	return 0;
}

#
# Examines first 4 bytes of file.  Returns 1 if they are "\x7fELF".
# Otherwise, returns 0.
#
sub is_elf
{
	my ($file) = @_;

	my ($buf, $n);
	my $cmp = "\x7fELF";
	if (! -r $file) {
		return 0;
	}

	my $is_elf_fh = do { local *FH; *FH };
	if (open($is_elf_fh, "<$file")) {
		$n = read($is_elf_fh, $buf, 4);
		close($is_elf_fh);
		if ($n != 4) {
			return 0;
		}
		if ($buf eq $cmp) {
			return 1;
		}
	}
	return 0;
}

#
# Returns 1 if $file is a shared object (i.e. ELF shared library)
# Returns 0 if it is not.
#
# Routine uses the dump -Lv output to determine this.  Failing that, it
# examines  the file(1) output.
#
sub is_shared_object
{
	my ($file) = @_;

	return 0 unless (-f $file);

	my ($on, $line, $is_shared_object);
	my ($n, $tag, $val);

	$on = 0;
	$is_shared_object = 0;

	foreach $line (split(/\n/, cmd_output_dump($file))) {

		if ($line =~ /^\[INDEX\]/) {
			$on = 1;
			next;
		}
		next unless ($on);
		($n, $tag, $val) = split(/\s+/, trim($line));
		if ($tag eq "SONAME") {
			$is_shared_object = 1;
			last;
		}
	}

	if (! $is_shared_object) {
		# If it is ELF, file output will say "dynamic lib":
		$line = cmd_output_file($file);
		if ($line =~ /ELF.* dynamic lib /) {
			$is_shared_object = 1;
		}
	}

	return $is_shared_object;
}

#
# Used for the a.out warning in etc.warn.  Examines first 4 bytes of
# file, and returns 1 if SunOS 4.x a.out binary 0 otherwise.
#
sub is_aout
{
	my ($file) = @_;

	my ($buf, $n);
	my $cmp1 = "\001\013";
	my $cmp2 = "\001\010";
	my $cmp3 = "\001\007";
	if (! -r $file) {
		return 0;
	}

	my $is_aout_fh = do { local *FH; *FH };
	if (open($is_aout_fh, "<$file")) {
		$n = read($is_aout_fh, $buf, 4);
		close($is_aout_fh);
		if ($n != 4) {
			return 0;
		}
		$buf = substr($buf, 2);
		if ($buf eq $cmp1) {
			return 1;
		}
		if ($buf eq $cmp2) {
			return 1;
		}
		if ($buf eq $cmp3) {
			return 1;
		}
	}
	return 0;
}

#
# is_suid
# Returns 1 if $file is a set user ID file.
# Returns 2 if $file otherwise is a set group ID (but not suid).
# Returns 0 if it is neither or file does not exist.
#
sub is_suid
{
	my ($file) = @_;

	return 0 unless (-f $file);

	my ($mask, $mode, $test);
	my @is_suid_masks = (04000, 02010, 02030, 02050, 02070);

	$mode = (stat($file))[2];

	foreach $mask (@is_suid_masks) {
		$test = $mode & $mask;
		if ($test == $mask) {
			if ($mask == $is_suid_masks[0]) {
				return 1;
			} else {
				return 2;
			}
		}
	}
	return 0;
}

#
# Returns a list of (abi, [ELF|a.out], wordsize, endianness)
#
sub bin_type
{
	my ($filename) = @_;

	my ($abi, $e_machine, $type, $wordsize, $endian, $rest);

	$abi		= 'unknown';
	$e_machine	= 'unknown';
	$type		= 'unknown';
	$wordsize	= 'unknown';
	$endian		= 'unknown';

	# Try to look it up in the $working_dir:
	my $outfile = object_to_dir_name($filename);
	$outfile = "$working_dir/$outfile/info.arch";

	if (-f $outfile) {
		my $arch_info_fh = do { local *FH; *FH };
		if (open($arch_info_fh, "<$outfile")) {
			while (<$arch_info_fh>) {
				chomp;
				if (/^ARCH:\s*(\S.*)$/) {
					$abi = $1;
				} elsif (/^TYPE:\s*(\S.*)$/) {
					$type = $1;
				} elsif (/^WORDSIZE:\s*(\S.*)$/) {
					$wordsize = $1;
				} elsif (/^BYTEORDER:\s*(\S.*)$/) {
					$endian = $1;
				}
			}
			close($arch_info_fh);
		}
		return ($abi, $type, $wordsize, $endian);
	}

	# Otherwise, process file(1) output:
	my $file_output;
	$file_output = cmd_output_file($filename);

	if ($file_output =~ /Sun demand paged SPARC|pure SPARC/) {
		$type = 'a.out';
		$abi = 'sparc';
		$e_machine = 'SPARC';
		$wordsize = '32';
		$endian = 'MSB';
	} elsif ($file_output =~ /ELF\s+/) {
		$type = 'ELF';
		$rest = $';
		if ($rest =~ /^(\d+)-bit\s+/) {
			$wordsize = $1;
			$rest = $';
		}
		if ($rest =~ /^(LSB|MSB)\s+/) {
			$endian = $1;
			$rest = $';
		}
		if ($rest =~ /SPARC/) {
			if ($rest =~ /\bSPARC\b/) {
				$abi = 'sparc';
				$e_machine = 'SPARC';
			} elsif ($rest =~ /\bSPARC32PLUS\b/) {
				$abi = 'sparc';
				$e_machine = 'SPARC32PLUS';
			} elsif ($rest =~ /\bSPARCV9\b/) {
				$abi = 'sparcv9';
				$e_machine = 'SPARCV9';
			}
		} else {
			if ($rest =~ /\bAMD64\b/ ||
			    $wordsize == 64 && $endian eq 'LSB') {
				$abi = 'amd64';
				$e_machine = 'AMD64';
			} elsif ($rest =~ /\b80386\b/) {
				$abi = 'i386';
				$e_machine = '80386';
			}
		}
	}
	return ($abi, $type, $wordsize, $endian, $e_machine);
}

#
# Compares two files to see if they are the same.  First tries some
# string comparisons. Then, if $fast is not true, attempts an inode
# comparison.
#
sub files_equal
{
	my ($file1, $file2, $fast) = @_;

	my ($f1, $f2);

	#
	# If they are the same string, we say they are equal without
	# checking if they do exist.
	#

	if ($file1 eq $file2) {
		return 1;
	}

	# Try trimming off any leading "./"
	$f1 = $file1;
	$f2 = $file2;

	$f1 =~ s,^\./+,,;
	$f2 =~ s,^\./+,,;

	if ($f1 eq $f2) {
		return 1;
	}

	# That is all we do if doing a fast compare.
	return 0 if ($fast);

	# Otherwise, resort to the file system:

	my ($inode1, $inode2);
	$inode1 = file_inode($file1);
	$inode2 = file_inode($file2);

	if (! defined($inode1) || ! defined($inode2) ||
	    $inode1 < 0 || $inode2 < 0) {
		return 0;
	} elsif ($inode1 eq $inode2) {
		return 1;
	}
	return 0;
}

#
# Utility to return the inode of a file.  Used to determine if two
# different paths or a path + symlink point to the same actual file.
#
sub file_inode
{
	my ($file) = @_;

	my $inode;
	if (exists($file_inode_cache{$file})) {
		return $file_inode_cache{$file};
	}

	if (! file_exists($file)) {
		$file_inode_cache{$file} = -1;
		return -1;
	}

	$inode = (stat($file))[1];

	if (! defined($inode) || $inode !~ /^\d+$/) {
		$inode = -1;
	}

	$file_inode_cache{$file} = $inode;
	return $inode;
}

#
# Existence test for files. Caches the results for speed.
#
sub file_exists
{
	my ($file) = @_;

	if (exists($file_exists_cache{$file})) {
		return $file_exists_cache{$file};
	}

	my $x;
	if (-e $file) {
		$x = 1;
	} else {
		$x = 0;
	}
	$file_exists_cache{$file} = $x;

	return $x;
}

#
# This routine deletes the caches we store information (e.g. cmd output)
# in to improve performance.  It is called when the caches are suspected
# to be too large.
#
sub purge_caches
{
	undef %file_exists_cache;
	undef %file_inode_cache;
	undef %filter_lib_cache;
	undef %cmd_output_file_cache;
	undef %cmd_output_dump_cache;
	undef %all_ldd_neededs_cache;
}

#
# Given a filter library, this routine tries to determine if it is a
# STANDARD filter or an AUXILIARY filter. This is done by running dump
# -Lv on the filter library. Results are cached in the global
# filter_lib_cache to avoid calling dump many times on the same library
# (e.g. libc.so.1).
#
sub filter_lib_type
{
	my ($filter) = @_;

	my $type = 'unknown';

	if (exists($filter_lib_cache{$filter})) {
		return $filter_lib_cache{$filter};
	}

	if (! -f $filter) {
		$filter_lib_cache{$filter} = 'unknown';
		return 'unknown';
	}

	my $dump_output;
	$dump_output = cmd_output_dump($filter);

	if (! $dump_output) {
		emsg(gettext("could not determine library filter type: %s\n"),
		    $filter);
		$filter_lib_cache{$filter} = 'unknown';

	} else {
		my ($line, $dump, $idx, $tag, $val);
		my ($saw_filter, $saw_aux);
		$saw_filter = 0;
		$saw_aux = 0;
		foreach $line (split(/\n/, $dump_output)) {
			next unless ($line =~ /^\[\d+\]/);
			$dump = trim($line);
			($idx, $tag, $val) = split(/\s+/, $dump);
			# detect both names used for each filter type:
			if ($tag eq 'FILTER' || $tag eq 'SUNW_FILTER') {
				$type = 'STD';
				$saw_filter = 1;
			} elsif ($tag eq 'AUXILIARY' || $tag eq
			    'SUNW_AUXILIARY') {
				$type = 'AUX';
				$saw_aux = 1;
			}
		}
		if ($saw_filter && $saw_aux) {
			$type = 'AUX';
		}
		$filter_lib_cache{$filter} = $type;
	}
	return $filter_lib_cache{$filter};
}

#
# Calls "abi_index" to dynamically create the list of Solaris libraries
# and their characteristics.
#
sub load_model_index
{
	my $dir = "auto";	# all model indexes are created automatically

	if (exists($lib_index_loaded{$dir})) {
		if ($lib_index_loaded{$dir} == -1) {
			return 0;
		} else {
			return 1;
		}
	}

	my ($lib, $lib2, $def, $cnt, $link_cnt, $all_links);
	my ($key, $base);

	my $reading_cache_file;

	$link_cnt = 0;
	my $cache_file = "$working_dir/AbiIndex";
	my $index_fh = do { local *FH; *FH };
	my $cache_fh = do { local *FH; *FH };
	if (-f $cache_file) {
		open($index_fh, "<$cache_file") ||
		    exiter(nofile($cache_file, $!));
		$reading_cache_file = 1;
	} else {
		if (! open($index_fh,
		    "$appcert_lib_dir/abi_index 2>/dev/null |")) {
			exiter(noprogrun("abi_index", $!));
		}
		if (! open($cache_fh, ">$cache_file")) {
			exiter(nofile($cache_file, $!));
		}
		$reading_cache_file = 0;
	}

	if (! $reading_cache_file) {
		emsg("\n");
		emsg(gettext("determining list of Solaris libraries"));
		emsg(" ...\n");
	}

	my $abi;
	while (<$index_fh>) {
		next if (/^\s*#/);
		next if (/^\s*$/);
		print $cache_fh $_ if (! $reading_cache_file);
		chomp;

		($abi, $lib, $def, $cnt, $all_links) = split(/\|/, $_, 5);

		next if (! -f $lib);

		$abi = 'any' if ($abi eq 'unknown');

		# note if $all_links is empty, we still get the base lib.
		foreach $lib2 ($lib, split(/:/, $all_links)) {
			$key = "$dir|$lib2|$abi";
			$lib_index_definition{$key} = $def;

			$base = basename($lib2);
			#
			# store an index of lib basenames to be used for
			# libfoo.so* matching.
			#
			$shared_object_index{$base}++;
			$lib_index{$base}++ if ($base =~ /^lib/);

			$link_cnt++;
		}
		#
		# record the device/inode too, used to avoid confusion due
		# to symlinks between *directories* instead of files. E.g.:
		#	/usr/lib/64 -> /usr/lib/sparcv9
		# under some crle(1) configurations this can be
		# particularly problematic.
		#
		if (-e $lib) {
			my ($device, $inode) = (stat($lib))[0,1];
			if (defined($device) && defined($inode)) {
				$key = "$dir|$device/$inode|$abi";
				$lib_index_definition{$key} = $def;
			}
		}
	}
	close($index_fh);
	close($cache_fh) if (! $reading_cache_file);

	# return 1 if library links were loaded. 0 indicates a failure.
	push(@lib_index_loaded, $dir);
	if ($link_cnt) {
		$lib_index_loaded{$dir} = $link_cnt;
		return 1;
	} else {
		$lib_index_loaded{$dir} = -1;
		return 0;
	}
}

#
# Returns a list of Solaris library basenames matching a pattern.  If a
# directory name is in $pattern, it will be prepended to each item.
#
sub lib_match
{
	my ($pattern, $return_something) = @_;

	if ($pattern eq '*') {
		# special case '*'
		return $pattern;
	}

	#
	# $return_something = 1 means if there was nothing matched,
	# return $pattern to the caller.
	#
	# This sub should only be called to initialize things since it
	# is very slow. (runs the regex over all libraries) Do not call
	# it in a loop over, say, application binaries.  Rather, call it
	# before the loop and make note of all the discrete cases.
	#

	# To handle libfoo.so* matching, we need the Index file loaded:
	if (! $lib_match_initialized) {
		load_model_index();
		$lib_match_initialized = 1;
	}

	my (@list, @libs, $lib, $id, $patt0, $dir0);

	# if empty, set it to "0" for the $id key.
	$return_something = 0 if ($return_something eq '');
	$id = "$pattern|$return_something";

	if (defined($lib_match_cache{$id})) {
		# If we have already found it, return the cached result.
		return split(/\|/, $lib_match_cache{$id});
	}

	$patt0 = $pattern;
	# extract dirname, if any.
	if ($pattern =~ m,/,) {
		$dir0 = dirname($pattern);
		$pattern = basename($pattern);
	} else {
		$dir0 = '';
	}

	# turn the matching pattern into a regex:
	$pattern =~ s/\./\\./g;	# protect .'s
	$pattern =~ s/\*/.*/g;	# * -> .*
	$pattern =~ s,/,\\/,g;	# protect /'s (see below)

	#
	# create a little code to check the match, since there will be a
	# big loop of checks:  note the anchoring /^...$/
	#
	my $regex = qr/^$pattern$/;

	if ($pattern =~ /^lib/) {
		# for a bit of speed, the lib* set is much smaller, so use it:
		@libs = keys(%lib_index);
	} else {
		# this is the full list:
		@libs = keys(%shared_object_index);
	}

	# now try all libs for a match, and store in @list.
	foreach $lib (@libs) {
		if ($lib =~ /$regex/) {
			if ($dir0 ne '') {
				# put back the dirname:
				$lib = "$dir0/$lib";
			}
			push(@list, $lib);
		}
	}

	# return list and cache result:
	if ($return_something && ! @list) {
		$lib_match_cache{$id} = $patt0;
		return $patt0;
	} else {
		$lib_match_cache{$id} = join('|', @list);
		return @list;
	}
}

#
# Expand the matches in a etc.warn MATCH expression.
# returns subroutine code for the comparison.
#
sub expand_expr
{
	my($expr) = @_;
	my $code = 'my($fn) = @_; ';
	$expr =~ s/\bfile\s*\=\~\s*/ cmd_output_file(\$fn) =~ /g;
	$expr =~ s/\bdump\s*\=\~\s*/ cmd_output_dump(\$fn) =~ /g;
	$expr =~ s/\bneeded\s*\=\~\s*/ all_ldd_neededs_string(\$fn) =~ /g;
	$expr =~ s/\bsyms\s*\=\~\s*/ direct_syms(\$fn) =~ /g;

	$code .= "if ($expr) {return 1;} else {return 0;}";
	return $code;
}

#
# Loads the binary stability information contained in the
# /usr/lib/abi/appcert/etc.* files.
#
sub load_misc_check_databases
{
	my $etc_dir = "$appcert_lib_dir";

	my ($etc_file, $line);

	my (@etcs) = <$etc_dir/etc.*>;

	#
	# Event(etc.) types to handle:
	#
	# SCOPED_SYMBOL|<release>|<lib>|<sym>
	# MODEL_TWEAK|<library>|<abi1,...>|<symbol>|<classification>
	# REMOVED_SYMBOL|<release>|<lib>|<sym>
	#

	my ($tag, $rel, $lib, $sym, $rest);
	my ($abis, $class, $tmp, $gather);

	# Read in and process all the etc files:
	my $count = 0;
	foreach $etc_file (@etcs) {
		my $etc_fh = do { local *FH; *FH };
		if (! open($etc_fh, "<$etc_file")) {
			exiter(nofile($etc_file, $!));
		}
		while (<$etc_fh>) {
			# read each line:
			chomp($line = $_);

			# gather lines continued  with "\" at end:
			while ($line =~ /\\$/) {
				chomp($line);
				last if (eof($etc_fh));
				chomp($tmp = <$etc_fh>);
				# handle "-" ... "-" style text blocks.
				if ($tmp eq '-') {
					#
					# gather everything until the
					# next '-' line.
					#
					$gather = '';
					while (1) {
						last if (eof($etc_fh));
						chomp($tmp = <$etc_fh>);
						last if ($tmp eq '-');
						$gather .= "|$tmp";
					}
					$line .= $gather;
				} else {
					$line .= " " . $tmp;
				}
			}

			#
			# skip blank lines or lines (including continued lines)
			# beginning with "#"
			#
			next if ($line =~ /^\s*#/);
			next if ($line =~ /^\s*$/);

			my $lib2;

			# Case statement for all the types:
			if ($line =~ /^SCOPED_SYMBOL/) {
				($tag, $rel, $lib, $sym, $rest) =
				    split(/\|/, $line, 5);
				#
				# current implementation uses library basename.
				#
				# We may also want to split this value
				# into a hash or two, e.g.
				# Scope_Symbol_Release, etc..
				#
				# No lib_match wild-carding done for this case.
				#
				$scoped_symbol{"$lib|$sym"} .=
				    "$rel|$lib|$sym,";
				$scoped_symbol_all{"$sym"} .=
				    "$rel|$lib|$sym,";
			} elsif ($line =~ /^SKIP_SYMBOL/) {
				#
				# These are low-level, e.g. C runtime
				# we always want to skip.
				#
				($tag, $sym) = split(/\|/, $line, 2);
				$skip_symbols{$sym} = 1;

			} elsif ($line =~ /^MODEL_TWEAK/) {
				#
				# These are direct edits of symbol
				# public/private database.
				#
				($tag, $lib, $abis, $sym, $class) =
				    split(/\|/, $line, 5);
				# change arch sep from "," to "%"
				$abis =~ s/,/%/g;

				my (@libs, $lib64, @tmp);
				if ($lib =~ /\*/) {
					@libs = lib_match($lib, 1);
				} else {
					push(@libs, $lib);
				}
				if ($abis eq '*') {
					#
					# '*' means all ABIs, so we modify
					# pathnames to reflect the 64 bit
					# versions.  If these exists on the
					# system, we append them to the list
					# for this tweak.
					#
					@tmp = @libs;
					foreach $lib2 (@tmp) {
						if ($lib2 !~ m,/lib/,) {
							next;
						}
						#
						# check for existence of sparc
						# and x86 64 bit versions.
						#
						$lib64 = $lib2;
						$lib64 =~
						    s,/lib/,/lib/sparcv9/,;
						if (-e $lib64) {
							push(@libs, $lib64);
						}
						$lib64 = $lib2;
						$lib64 =~ s,/lib/,/lib/amd64/,;
						if (-e $lib64) {
							push(@libs, $lib64);
						}
						$lib64 = $lib2;
						$lib64 =~ s,/lib/,/lib/64/,;
						if (-e $lib64) {
							push(@libs, $lib64);
						}
					}
				}

				@tmp = @libs;
				foreach $lib2 (@tmp) {
					if ($lib2 !~ m,/, || ! -e $lib2) {
						next;
					}
					#
					# if it exists on the system,
					# store info wrt inode as well:
					#
					my ($device, $inode);
					($device, $inode) = (stat($lib2))[0,1];
					if ($device ne '' && $inode ne '') {
						push(@libs, "$device/$inode");
					}
				}

				#
				# now store the tweak info for all associated
				# libraries.
				#
				foreach $lib2 (@libs) {
					$model_tweak{$lib2} .=
					    "$sym|$abis|$class,";
				}

			} elsif ($line =~ /^WARNING:/) {
				#
				# Extra warnings for miscellaneous problems.
				#
				my $cnt = 0;
				my ($warn, $tag, $desc, $bindings);
				my ($bind, $text);
				($warn, $tag, $desc, $bindings, $text) =
				    split(/:/, $line, 5);

				# trim any leading spaces:
				$tag =~ s/^\s*//;
				$desc =~ s/^\s*//;
				$bindings =~ s/^\s*//;
				$text =~ s/^\s*//;

				$tag =~ s,[\s/;]+,_,g;

				#
				# desc lists will be ";" delimited, so
				# replace any found in the text.
				#
				$desc =~ s/;/,/g;
				$desc = trim($desc);


				# Store info in %Warnings_* hashes:

				$warnings_desc{$tag} = $desc;

				$warnings_match{$tag} = '';

				if ($bindings =~ /^MATCH\s*(\S.*)$/) {
					#
					# Handle the pattern MATCH
					# case.  Note there there is no
					# libfoo.so.* matching here.
					#
					my $expr = $1;
					my $code;

					#
					# For efficiency we will create
					# a subroutine for each case.
					#

					# get subref code:
					$code = expand_expr($expr);

					# define the subroutine:

					my $subref;
					eval "\$subref = sub { $code };";
					if ("$@" eq "" && $subref) {
						$warnings_match{$tag} = $subref;
					}
				} else {
					#
					# Otherwise, it is a
					# lib|sym|caller type match
					#
					my ($lib, $sym, $rest);
					foreach $bind (split(/,/, $bindings)) {
						#
						# Create pseudo tag,
						# "tag|N", for each
						# binding.
						#
						$bind = trim($bind);
						($lib, $sym, $rest) =
						    split(/\|/, $bind, 3);
						foreach $lib2
						    (lib_match($lib, 1)) {
							$tmp = "$tag|$cnt";
							$warnings_bind{$tmp} =
							    "$lib2|$sym|$rest";
							$warnings_desc{$tmp} =
							    $desc;
							$cnt++;
						}
					}
				}
			}
		}
		$count++;
		close($etc_fh);
	}

	# Trim any trailing "," separators from the last append:

	my $key;
	foreach $key (keys(%scoped_symbol)) {
		$scoped_symbol{$key} =~ s/,+$//;
	}
	foreach $key (keys(%scoped_symbol_all)) {
		$scoped_symbol_all{$key} =~ s/,+$//;
	}
	foreach $key (keys(%model_tweak)) {
		$model_tweak{$key} =~ s/,+$//;
		#
		# make sure tweak is associated with device/inode to aid not
		# getting tricked by symlinks under crle, LD_LIBRARY_PATH, etc.
		#
		my ($device, $inode) = (stat($key))[0,1];
		if (defined($device) && defined($inode)) {
			$model_tweak{"$device/$inode"} = $model_tweak{$key};
		}
	}
	return $count;
}

1;
