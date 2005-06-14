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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# This utility program loads the unstable behavior databases, then reads
# the symprof output for each binary, and record any detected unstable
# behavior in the binary's output directory.
#

require 5.005;
use strict;
use locale;
use POSIX qw(locale_h);
use Sun::Solaris::Utils qw(textdomain gettext);
use File::Basename;
use File::Path;

use lib qw(/usr/lib/abi/appcert);
use AppcertUtil;

setlocale(LC_ALL, "");
textdomain(TEXT_DOMAIN);

use vars qw(
	$LIBC
	$tmp_check_dir
	$binaries_checked_count
	$misc_check_databases_loaded_ok
	%load_model_default
	%load_error
	%model_loaded
	%model
	%is_system_library_cache
);

set_clean_up_exit_routine(\&clean_up_exit);

initialize_variables();

import_vars_from_environment();

signals('on', \&interrupted);

set_working_dir();

load_model_index();

check_objects();

clean_up();

exit 0;

#
# Set up any variables.
#
sub initialize_variables
{
	# Here is what we call libc:
	$LIBC = '/usr/lib/libc.so.1';
}

#
# working_dir has been imported by import_vars_from_environment()
# A sanity check is performed here to make sure it exists.
#
sub set_working_dir
{
	if (! defined($working_dir) || ! -d $working_dir) {
		exiter("$command_name: " . sprintf(gettext(
		    "cannot locate working directory: %s\n"), $working_dir));
	}
}

#
# Called when interrupted by a signal.
#
sub interrupted
{
	$SIG{$_[0]} = 'DEFAULT';
	signals('off');
	clean_up_exit(1);
}

#
# Does the cleanup then exit with return code $rc.  Note: The utility
# routine exiter() will call this routine.
#
sub clean_up_exit
{
	my ($rc) = @_;
	$rc = 0 unless ($rc);

	clean_up();
	exit $rc;
}

#
# General cleanup activities are placed here.  There may not be an
# immediate exit after this cleanup.
#
sub clean_up
{
	if (defined($tmp_check_dir) && -d $tmp_check_dir) {
		rmtree($tmp_check_dir);
	}
}

#
# Top level routine to initialize databases and then loop over the
# objects and call the checking routines on each one.
#
sub check_objects
{
	# Make a tmp dir for the checking work.
	$tmp_check_dir = create_tmp_dir($tmp_dir);

	if (! -d $tmp_check_dir) {
		exiter(nocreatedir($tmp_check_dir, $!));
	}

	emsg("\n" . gettext(
	    "checking binary objects for unstable practices") . " ...\n\n");

	my ($dir, $path_to_object);

	#
	# Loop over each object item in the working_dir.
	#  - $dir will be each one of these object directories.
	#  - $path_to_object will be the corresponding actual path
	#    to the the binary to be checked.
	# Output will be placed down in $dir, e.g. "$dir/check.foo"
	#

	$binaries_checked_count = 0;

	#
	# We need to load the Misc Databases to get any modifications to
	# the symbol database. E.g. gethostname should be public.
	#
	$misc_check_databases_loaded_ok = load_misc_check_databases();

	while (defined($dir = next_dir_name())) {

		# Map object output dir to actual path of the object:
		$path_to_object = dir_name_to_path($dir);

		if (! -f $path_to_object) {
			exiter(nopathexist($path_to_object, $!));
		}

		# Check it:
		emsg(gettext("checking: %s\n"), $path_to_object);

		static_check_object($path_to_object, $dir);
		dynamic_check_object($path_to_object, $dir);
	}

	if ($binaries_checked_count == 0) {
		exiter("$command_name: " . gettext(
		    "no binary objects where checked."));
	}

	# Do additional heuristic checks of unstable behavior:
	perform_misc_checks();

	clean_up();	# Remove any tmp dirs and files.
}

#
# Reads in the static profile (i.e. the symbols exported by bin in
# .text section) and calls the static archive checking routine.
#
sub static_check_object
{
	my ($path_to_object, $dir) = @_;

	# The profile output file created by static_profile() in symprof.

	my $profile_file = "$dir/profile.static";

	my $err_fmt = gettext(
	    "binary object %s has no static profile: %s: %s\n");
	if (! -f $profile_file) {
		emsg("$command_name: " . $err_fmt, $path_to_object,
		    $profile_file, $!);
		return 0;
	}

	my $profile_fh = do { local *FH; *FH };
	if (! open($profile_fh, "<$profile_file")) {
		exiter(nofile($profile_file, $!));
	}

	my ($profile, $lib, $lib2, $base, %libs_needed);

	my $completely_statically_linked = 0;

	while (<$profile_fh>) {
		$profile .= $_;
		if (/^\s*#dtneeded:\s*(.*)$/) {
			#
			# record the bare name, e.g. "libc" of the
			# (direct) dtneededs.
			#
			foreach $lib (split(/\s+/, $1)) {
				next if ($lib eq '');
				$base = $lib;
				# record it as libc.so.1 -> libc
				$base =~ s/\.so\..*$//;
				$base =~ s/\.so$//;
				$libs_needed{$base} = $lib;
				$libs_needed{basename($base)} = $lib;
			}
		} elsif (/^\s*#SKIPPED_TEST:\s+STATICALLY_LINKED/) {
			#
			# Record statical linking if it takes place
			# since it indicates to skip the test.
			#
			$completely_statically_linked = 1;
		}
	}
	close($profile_fh);

	my $problems = "$dir/check.problems";

	my $problems_fh = do { local *FH; *FH };
	if (! open($problems_fh, ">>$problems")) {
		exiter(nofile($problems, $!));
	}

	if ($completely_statically_linked) {
		print $problems_fh "STATIC: COMPLETELY_STATIC"  . "\n";
	}

	my (%saw_lib);
	if (! defined($profile)) {
		close($problems_fh);
		return;
	}
	foreach $lib (lib_static_check($profile)) {
		#
		# lib_static_check returns a list of statically linked
		# libraries, however to be on the safe side we will skip
		# false positives our dtneeded's show they are really
		# dynamically linked in.
		#

		next if ($libs_needed{$lib});
		next if ($libs_needed{basename($lib)});
		next if ($saw_lib{basename($lib)}++);

		$lib2 = $lib;
		$lib2 =~ s/\.a$//;
		next if ($libs_needed{$lib2});
		next if ($libs_needed{basename($lib2)});

		# Otherwise, record in the problems file:
		print $problems_fh "STATIC: LINKED_ARCHIVE $lib" . "\n";
	}
	close($problems_fh);
}

#
# Takes as input the static profile (e.g. the .text symbols) and returns
# a list of suspected statically linked Solaris archive libraries.
#
sub lib_static_check
{
	my ($profile) = @_;

	my ($line, $area, $extent, $type, $sym, $obj);

	my (%symbols);

	#
	# Working on lines like:
	# /bin/ftp|TEXT|GLOB|FUNC|glob
	# /bin/ftp|TEXT|GLOB|FUNC|help
	#

	# First record all the symbols in the TEXT area:

	foreach $line (split(/\n/, $profile)) {
		next unless ($line =~ /\bTEXT\b/);
		($obj, $area, $extent, $type, $sym) = split(/\|/, $line);

		$symbols{$sym} = 1;
	}

	my (@static_libs);

	# Next, check against the library heuristics for static linking:

	# libc.a:

	if (exists($symbols{'_exit'})) {
		push(@static_libs, "/usr/lib/libc.a");
	}

	# libsocket.a:

	if (exists($symbols{'socket'}) && exists($symbols{'_socket'}) &&
	    exists($symbols{'bind'}) && exists($symbols{'_bind'}) &&
	    exists($symbols{'connect'}) && exists($symbols{'_connect'})) {
			push(@static_libs, "/usr/lib/libsocket.a");
	}

	# libnsl.a:

	if (exists($symbols{'_xti_bind'}) && exists($symbols{'_xti_connect'}) &&
	    exists($symbols{'_tx_bind'}) && exists($symbols{'_tx_connect'})) {
			push(@static_libs, "/usr/lib/libnsl.a");
	}

	return @static_libs;
}

#
# Reads in the dynamic profile from the object's output directory.
# Loads any needed public/private Solaris library symbol models.
# Records unstable use of any private Solaris symbols in the object's
# output directory.
#
sub dynamic_check_object
{
	my ($path_to_object, $dir) = @_;

	# Location of the dynamic profile output:
	my $profile_file = "$dir/profile.dynamic";

	my $err_fmt = gettext(
	    "binary object %s has no dynamic profile: %s: %s\n");
	if (! -f $profile_file) {
		emsg("$command_name: " . $err_fmt, $path_to_object,
		    $profile_file, $!);
		return 0;
	}

	my $profile_fh = do { local *FH; *FH };
	if (! open($profile_fh, "<$profile_file")) {
		exiter(nofile($profile_file, $!));
	}

	$binaries_checked_count++;

	#
	# Variables to hold temporary items:
	#
	# %library_list will be a hash of "to" libraries we need to load.
	# @symbol_list will be an array of the "lib|sym" pairs.
	#

	my (%library_list, @symbol_list, @unbound_list);
	my ($to, $sym, $from, $binary, $line);

	my ($to_is_sys_lib, $from_is_sys_lib);

	#
	# profile lines look like:
	# /bin/ftp|*DIRECT*|libsocket.so.1|socket
	# /bin/ftp|libnsl.so.1|libc.so.1|mutex_lock
	#
	# or:
	#
	# /bin/ftp|*DIRECT*|/usr/lib/libsocket.so.1|socket
	# /bin/ftp|/usr/lib/libnsl.so.1|/usr/lib/libc.so.1|mutex_lock
	#

	my ($abi, $type, $wordsize, $endian, $e_machine) =
	    bin_type($path_to_object);

	#
	# Setting abi to 'any' will allow continuation when
	# we encounter an abi we do not recognize.
	#
	if (! defined($abi) || $abi eq 'unknown') {
		$abi = 'any';
	} else {
		#
		# Always try to load libc.  This will be used for symbol
		# migration to libc checks.
		#
		if (! exists($load_model_default{$abi})) {
			load_model($LIBC, $abi);
		}
		$load_model_default{$abi} = 1;
	}

	my $dynamic_bindings_count = 0;
	my $no_bindings_msg;

	while (<$profile_fh>) {
		chomp;

		if (/^\s*#/) {
		    if (/NO_BINDINGS_FOUND\s*(.*)$/) {
			my $msg = $1;
			if ($msg =~ /^\s*$/) {
				$no_bindings_msg = 'NO_SYMBOL_BINDINGS_FOUND';
			} else {
				$no_bindings_msg = $msg;
			}
		    }
		    next;
		}

		($binary, $from, $to, $sym) = split(/\|/, $_, 4);

		$dynamic_bindings_count++;

		# Skip the checking of reverse calls:
		next if ($from eq "*REVERSE*");

		# Skip the checking of special symbols:
		next if (exists($skip_symbols{$sym}));

		# Accumulate unbounds, but otherwise skip them:
		if ($to eq "*UNBOUND*") {
			push(@unbound_list, "$from|$sym");
			next;
		}

		# Record if the "to" object is a system library:
		$to_is_sys_lib = is_system_library($to, $abi);

		if ($from eq "*DIRECT*") {
			$from_is_sys_lib = 0;
		} else {
			#
			# Otherwise we may check its calls. See if it is
			# a system lib:
			#
			$from_is_sys_lib = is_system_library($from, $abi);
		}

		#
		# We will pass judgement on *DIRECT* calls and indirect
		# calls from a library we do not recognize.
		#
		if ($from_is_sys_lib) {
			next;
		}
		if (! $to_is_sys_lib) {
			# Call to a middleware or supporting library.
			next;
		}

		$library_list{$to} = 1;
		push(@symbol_list, "$from|$to|$abi|$sym");
	}

	close($profile_fh);

	my $file;

	my $problems_fh = do { local *FH; *FH };
	if ($dynamic_bindings_count == 0 && defined($no_bindings_msg)) {
		$file = "$dir/check.problems";

		if (! open($problems_fh, ">>$file")) {
			exiter(nofile($file, $!));
		}

		print $problems_fh "DYNAMIC: NO_DYNAMIC_BINDINGS_FOUND" .
		    " $no_bindings_msg\n";
		close($problems_fh);
		return;
	}

	my ($lib, $str);

	$file = "$dir/check.dynamic.abi_models";
	my $model_info_fh = do { local *FH; *FH };
	if (! open($model_info_fh, ">$file")) {
		exiter(nofile($file, $!));
	}

	# Load all the needed library models:
	my ($s1, $s2);
	$s1 = ",NO_PUBLIC/PRIVATE_MODEL_FOUND-SKIPPING_CHECK_FOR_THIS_LIBRARY";
	$s2 = "ERROR_LOADING_PUBLIC/PRIVATE_MODEL";

	foreach $lib (keys %library_list) {
		if (! load_model($lib, $abi) && ! $load_error{"$lib|$abi"}) {
			$load_error{"$lib|$abi"} = 1;
		}
		$str = $model_loaded{"$lib|$abi"};
		if ($str eq '__FAILED__') {
			$str .= $s1;
		} elsif (! $str) {
			$str = $s2;
		}
		print $model_info_fh "$lib:$str\n";
	}
	close($model_info_fh);

	my ($lib_abi_sym, $class, %result_list);

	my ($l, $a, $s);
	foreach $lib_abi_sym (@symbol_list) {

		($from, $lib_abi_sym) = split(/\|/, $lib_abi_sym, 2);

		($l, $a, $s) = split(/\|/, $lib_abi_sym);

		if (! exists($model{$lib_abi_sym})) {
			#
			# Check the library.  If it is not in
			# model_loaded, then we claim it is not a
			# library we are interested in.
			#
			next if (! exists($model_loaded{"$l|$a"}));
			next if ($model_loaded{"$l|$a"} eq '__FAILED__');

			# it is an unrecognized symbol:
			$result_list{'unrecognized'} .=
			    "$from|$lib_abi_sym" . "\n";
			next;
		}

		# N.B. $lib_abi_sym and $l may have been altered above.
		$class = $model{$lib_abi_sym};
		$line = "$path_to_object|$a|$from|$l|$class|$s" . "\n";

		if ($class !~ /^(public|private|unclassified)$/) {
			exiter("$command_name" . sprintf(gettext(
			    "unrecognized symbol class: %s"), $class));
		}

		$result_list{$class} .= $line;
	}

	if (@unbound_list) {
		my $ldd_file = "$dir/profile.dynamic.ldd";
		my $tmp;
		if (-f $ldd_file) {
			my $ldd_info_fh = do { local *FH; *FH };
			if (! open($ldd_info_fh, "<$ldd_file")) {
				exiter(nofile($ldd_file, $!));
			}
			while (<$ldd_info_fh>) {
				$tmp .= '# ' . $_ if (/not\s+found/);
			}
			close($ldd_info_fh);
		}
		if (defined($tmp)) {
			$result_list{'unbound'} = $tmp;
		}
		$result_list{'unbound'} .= join("\n", @unbound_list) . "\n";
	}

	my $count;

	my @classes = qw(private public unbound unclassified unrecognized);

	foreach $class (@classes) {

		next if (! exists($result_list{$class}));

		$file = "$dir/check.dynamic.$class";

		my $outfile_fh = do { local *FH; *FH };
		if (! open($outfile_fh, ">$file")) {
			exiter(nofile($file, $!));
		}
		if ($class eq 'private') {
			print $outfile_fh
			    $text{'Message_Private_Symbols_Check_Outfile'};
		} elsif ($class eq 'public') {
			print $outfile_fh
			    $text{'Message_Public_Symbols_Check_Outfile'};
		}
		print $outfile_fh $result_list{$class};
		close($outfile_fh);
	}

	$file = "$dir/check.problems";

	if (! open($problems_fh, ">>$file")) {
		exiter(nofile($file, $!));
	}

	if (exists($result_list{'private'})) {
		$count = scalar(my @a = split(/\n/, $result_list{'private'}));
		print $problems_fh "DYNAMIC: PRIVATE_SYMBOL_USE $count\n";
	}
	if (exists($result_list{'unbound'})) {
		$count = scalar(@unbound_list);
		print $problems_fh "DYNAMIC: UNBOUND_SYMBOL_USE $count\n";
	}
	if (exists($result_list{'unrecognized'})) {
		$count =
		    scalar(my @a = split(/\n/, $result_list{'unrecognized'}));
		print $problems_fh "DYNAMIC: UNRECOGNIZED_SYMBOL_USE $count\n";
	}

	close($problems_fh);
}

#
# Loads a system model for a library on demand.
#
# Input is a library to load and the architecture ABI.
#
# On successful completion, 1 is returned and the associative array:
#
#	%model{"$library|$abi|$symbol"} = {public,private}
#
#	is set.
#
sub load_model
{
	#
	# Returns 1 if the model was successfully loaded, or returns 0
	# if it was not.
	#

	my ($library, $abi) = @_;

	#
	# This %model_loaded hash records the following states:
	#    <string>	Method by which successfully loaded.
	#    __FAILED__	Failed to loaded successfully.
	#    undef      Have not tried to load yet.
	#
	if (exists($model_loaded{"$library|$abi"})) {
		if ($model_loaded{"$library|$abi"} eq '__FAILED__') {
			return 0;
		} elsif ($model_loaded{"$library|$abi"}) {
			return 1;
		}
	}

	my ($loaded, $ok);

	$loaded = 1 if (load_model_versioned_lib($library, $abi));

	# Record the result so we do not have to repeat the above:

	if ($loaded) {
		$ok = "OK";
		my $tweaks = load_tweaks($library, $abi);
		$ok .= ",Model_Tweaks\[$tweaks\]" if ($tweaks);
		$model_loaded{"$library|$abi"} = $ok;
	} else {
		$model_loaded{"$library|$abi"} = '__FAILED__';
	}

	return $loaded;
}

#
# Routine to load into %model any special modifications to the Solaris
# symbol Models kept in the etc.* file.
#
sub load_tweaks
{
	my ($lib, $abi) = @_;

	my $key;
	if (exists($model_tweak{$lib}) && $model_tweak{$lib}) {
		$key = $lib;
	} else {
		#
		# check device/inode record so as to not get tricked by
		# symlinks.
		#
		my ($device, $inode) = (stat($lib))[0,1];
		if (! defined($device) || ! defined($inode)) {
			return 0;
		}
		$key = "$device/$inode";
		if (! exists($model_tweak{$key}) || ! $model_tweak{$key}) {
			return 0;
		}
		#
		# device/inode $key is recorded, so continue along
		# using it below in the model_tweak lookup.
		#
	}

	#
	# etc line looks like:
	# MODEL_TWEAK|/usr/lib/libnsl.so.1|sparc,i386|gethostname|public
	# value looks like:
	# gethostname|sparc,i386|public
	#

	my ($case, $abis, $sym, $class, $count);

	$count = 0;
	foreach $case (split(/,/, $model_tweak{$key})) {
		($sym, $abis, $class) = split(/\|/, $case);
		if ($abis eq '*' || ($abis =~ /\b${abi}\b/)) {
			$model{"$lib|$abi|$sym"} = $class;
			$count++;
		}
	}

	return $count;
}

#
# Determine the public/private symbol model for a versioned Solaris
# library. Returns 0 if no model could be extracted, otherwise returns a
# string detailing the model loading.
#
sub load_model_versioned_lib
{
	my ($library, $abi) = @_;

	#
	# This subroutine runs pvs -dos directly on the Solaris shared
	# object, and parses data that looks like this:
	#
	# % pvs -dos /usr/lib/libsocket.so.1
	# ...
	# /usr/lib/libsocket.so.1 -       SUNW_1.1: __xnet_sendmsg;
	# ...
	# /usr/lib/libsocket.so.1 -       SISCD_2.3: connect;
	# ...
	# /usr/lib/libsocket.so.1 -       SUNWprivate_1.2: getnetmaskbyaddr;
	#
	# Note that data types look like:
	# /usr/lib/libc.so.1 -    SUNWprivate_1.1: __environ_lock (24);
	#
	# we discard the size.
	#
	# On successful completion 1, is returned and the hash:
	#
	#	%model{"$library|$abi|$symbol"} = {public,private}
	#
	# is set.
	#

	# library must be a full path and exist:
	if (! -f $library) {
		return 0;
	}

	my ($rc, $output, $output_syslib);

	#
	# quote character should never happen in normal use, but if it
	# did it will foul up the pvs commands below, so we return
	# early.
	#
	if ($library =~ /'/) {
		return 0;
	}

	#
	# Get the entire list of symbols:
	# note that $library does not contain a single-quote.
	#
	c_locale(1);
	$output = `$cmd_pvs -dos '$library' 2>/dev/null`;
	$rc = $?;
	c_locale(0);

	if ($rc != 0 || ($output =~ /^[\s\n]*$/)) {
		# It is not versioned, so get out.
		return 0;
	}

	# Library is versioned with something from this point on.

	my ($line, $libtmp, $j1, $j2, $version, $symbol, $class);
	my ($count, $public_count, $private_count);
	my (%versions);
	my $libbase = basename($library);

	$count = 0;
	$public_count = 0;
	$private_count = 0;

	my $is_system_lib = is_system_library($library, $abi);

	my (@defs, $def);
	if (defined($is_system_lib)) {
		foreach $def (split(/:/, $is_system_lib)) {
			next if ($def =~ /^FILE=/);
			next if ($def =~ /^-$/);
			push(@defs, $def);
		}
		if (@defs == 1) {
			$is_system_lib = $defs[0];
		}
	}

	my (@version_heads, $vers, $default_class);
	if (defined($is_system_lib) && $is_system_lib ne 'NO_PUBLIC_SYMS') {
		#
		# It is a versioned system library.  Extract the public
		# symbols version head end(s)
		#
		if ($is_system_lib =~ /^PUBLIC=(.*)$/) {
			@version_heads = split(/,/, $1);
		} else {
			push(@version_heads, $is_system_lib);
		}

		#
		# Rerun pvs again to extract the symbols associated with
		# the *public* inheritance chain(s).
		#
		c_locale(1);
		foreach $vers (@version_heads) {
			# something is wrong if $vers has a quote
			$vers =~ s/'//g;

			# $library has been screened for single quotes earlier. 
			$output_syslib .=
			    `$cmd_pvs -dos -N '$vers' '$library' 2>/dev/null`;
		}
		c_locale(0);
	}


	if (defined($output_syslib) && ($output_syslib !~ /^[\s\n]*$/)) {
		#
		# If non-empty there are some public symbols sets.
		# First, mark everything private:
		#
		$output = "DEFAULT_CLASS=private\n" . $output;
		# then overwrite the public ones:
		$output .= "DEFAULT_CLASS=public\n"  . $output_syslib;
	} elsif (defined($is_system_lib) &&
	    $is_system_lib eq 'NO_PUBLIC_SYMS') {
		# Everything is private:
		$output = "DEFAULT_CLASS=private\n" . $output;
	} else {
		#
		# assume public, the override will occur when version
		# string matches /private/i. This is for 3rd party
		# libraries.
		#
		$output = "DEFAULT_CLASS=public\n" . $output;
	}

	foreach $line (split(/\n/, $output)) {
		$line = trim($line);
		if ($line =~ /^DEFAULT_CLASS=(.*)$/) {
			$default_class = $1;
			next;
		}
		($libtmp, $j1, $version, $symbol, $j2) = split(/\s+/, $line);

		$symbol  =~ s/;*$//;
		$version =~ s/:*$//;

		next if ($symbol =~ /^\s*$/);
		next if ($version eq $libbase);	# see example output above

		$versions{$version}++;

		$class = $default_class;

		if (! $output_syslib && ($version =~ /private/i)) {
			$class = 'private';
		}

		if ($class eq 'private') {
			$private_count++;
		} else {
			if ($output_syslib) {
				# remove the double counting of this version:
				$versions{$version}--;
				$private_count--;
				$count--;
			}
			$public_count++;
		}

		$model{"$library|$abi|$symbol"} = $class;
		$count++;
	}

	if (! $count) {
		return 0;
	}

	# Construct the info string:
	$libtmp = "load_model_versioned_lib,$library,$abi:";
	foreach $version (sort(keys(%versions))) {
		$libtmp .= "$version\[$versions{$version}\],";
	}
	$libtmp .=
	    "\[${count}symbols=${public_count}public+${private_count}private\]";
	return $libtmp;
}

#
# Returns a non-empty string if the $path_to_library is recognized as a
# System (i.e. Solaris) ABI library for given abi.  Returns undef
# otherwise.  The returned string will either be the public symbol version
# name(s), "NO_PUBLIC_SYMS" if all symbols are private, or "-" if there
# is no versioning at all.
#
sub is_system_library
{
	my ($path_to_library, $abi) = @_;

	if (exists($is_system_library_cache{"$path_to_library|$abi"})) {
		return $is_system_library_cache{"$path_to_library|$abi"};
	}

	my ($dir, $def, $key);

	my ($device, $inode) = (stat($path_to_library))[0,1];
	foreach $dir (@lib_index_loaded) {

		$key = "$dir|$path_to_library|$abi";
		$def = $lib_index_definition{$key};
		if (defined($device) && defined($inode) && ! defined($def)) {
			# try inode lookup (chases down unexpected symlinks)
			$key = "$dir|$device/$inode|$abi";
			$def = $lib_index_definition{$key};
		}
		last if (defined($def));
	}
	if (!defined($def) && $path_to_library !~ /'/) {
		#
		# we skip the case $path_to_library containing
		# a single quote, so the cmd argument is protected.
		#
		my $tmp = `$cmd_pvs -dn '$path_to_library' 2>/dev/null`;
		if ($tmp =~ /\b(SUNW[^;]*);/) {
			$def = $1;
		}
	}

	$is_system_library_cache{"$path_to_library|$abi"} = $def;

	return $def;
}

#
# Loop over each object item in the working_dir.
#  - $dir will be each one of these object directories.
#  - $path_to_object will be the corresponding actual path
#    to the the binary to be checked.
# Output will usually be placed down in $dir, e.g. "$dir/check.foo"
#
sub perform_misc_checks
{
	my ($dir, $path_to_object);

	if (! $misc_check_databases_loaded_ok) {
		#
		# The load was attempted in check_objects() There is no
		# point in continuing if that loading failed.
		#
		return;
	}

	emsg("\n" . gettext(
	    "performing miscellaneous checks") . " ...\n\n");

	while (defined($dir = next_dir_name())) {

		# Map object output dir to actual path of the object:
		$path_to_object = dir_name_to_path($dir);

		if (! -f $path_to_object) {
			exiter(nopathexist($path_to_object, $!));
		}

		# Check it:
		misc_check($path_to_object, $dir);
	}
}

#
# Routine to perform the misc. checks on a given binary object.  Records
# the findings in object's output directory.
#
sub misc_check
{
	my ($path_to_object, $dir) = @_;

	# Load the entire dynamic profile for this object:

	my (@profile, @profile_short, %direct_syms, $file);
	my $tmp;

	$file = "$dir/profile.dynamic";

	my ($app, $caller, $lib, $base, $sym);
	my ($libsymcaller, $cnt, %sawlib);
	if (-f $file) {
		my $prof_fh = do { local *FH; *FH };
		if (! open($prof_fh, "<$file")) {
			exiter(nofile($file, $!));
		}
		$cnt = 0;
		while (<$prof_fh>) {
			next if (/^\s*#/);
			next if (/^\s*$/);
			chomp;
			($app, $caller, $lib, $sym) = split(/\|/, $_, 4);

			# Skip the checking of special symbols:
			next if (exists($skip_symbols{$sym}));

			push(@profile, "$lib|$sym|$caller");

			#
			# We collect in @profile_short up to 10
			# lib-sym-caller triples where all the libs are
			# distinct.  This is used to speed up some
			# loops over the profile below: when we catch
			# the lib-matching checks early in the loop we
			# can exclude those checks from the remainder
			# of the loop.  Since a profile may involve
			# 1000's of symbols this can be a savings.
			#
			if ($cnt < 10 && ! exists($sawlib{$lib})) {
				push(@profile_short, "$lib|$sym|$caller");
				$sawlib{$lib} = 1;
				$cnt++;
			}
		}
		close($prof_fh);
	}
	#
	# Misc Check #1:
	# Go through dynamic profile looking for scoped local symbols:
	#

	my (%all_neededs, %lib_not_found);
	my ($scoped_list, $scoped_msg);
	my ($sc_rel, $sc_lib, $sc_sym, $sc_val);

	%all_neededs = all_ldd_neededs($path_to_object);
	my ($key, $key_trim);
	foreach $key (keys(%all_neededs)) {
		$key_trim = basename($key);
		$all_neededs{$key_trim} = $all_neededs{$key};
		if ($all_neededs{$key} =~ /file not found/) {
			# %lib_not_found will be used below in check #2
			$lib_not_found{$key}++;
			$lib_not_found{$key_trim}++;
		}
	}

	# We will need the abi of the object:
	my $abi;
	($abi) = bin_type($path_to_object);
	if ($abi eq '' || ($abi =~ /^(unknown|any)$/)) {
		if ($uname_p =~ /sparc/i) {
			$abi = 'sparc';
		} else {
			$abi = 'i386';
		}
	}

	foreach $libsymcaller (@profile) {
		next unless ($libsymcaller =~ /\*DIRECT\*$/);

		($lib, $sym, $caller) = split(/\|/, $libsymcaller, 3);

		#
		# Record direct symbols to improve our %wskip list used
		# to speed up loops over symbols.
		#
		$direct_syms{$sym} = 1;
		next unless (exists($scoped_symbol_all{$sym}));

		$base = basename($lib);

		#
		# We only worry if a scoped call is a direct one.  This
		# assumes the user's support shared objects are also
		# checked by appcert.
		#

		if (exists($scoped_symbol{"$lib|$sym"}) ||
		    exists($scoped_symbol{"$base|$sym"})) {
			#
			# This one is for checking on releases BEFORE
			# the scoping actually occurred.
			#
			$scoped_msg  .= "$base:$sym ";
			$scoped_list .= "$path_to_object|$caller|$lib|$sym\n";

		} elsif ($lib eq '*UNBOUND*' &&
		    exists($scoped_symbol_all{$sym})) {
			#
			# This one is for checking on releases AFTER the
			# scoping.
			#
			# Assume these type of unbounds are deprecated
			# if found in scoped_symbol_all. Double check it
			# is in the all-needed-libs though:
			#

			if (defined($sc_sym) &&
			    exists($model{"$LIBC|$abi|$sc_sym"})) {
				next;
			}

			foreach $sc_val (split(/,/, $scoped_symbol_all{$sym})) {
				($sc_rel, $sc_lib, $sc_sym) =
				    split(/\|/, $sc_val);

				#
				# The general scoping that occurred for
				# ld.so.1 makes the current heuristic
				# somewhat less accurate. Unboundedness
				# from other means has too good a chance
				# of overlapping with the ld.so.1
				# scoping. Note that the app likely does
				# NOT have ld.so.1 in its neededs, but
				# we still skip this case.
				#

				next if ($sc_lib eq 'ld.so.1');

				if ($all_neededs{$sc_lib}) {
					# note that $lib is '*UNBOUND*'
					$scoped_msg  .= "<unbound>:$sym ";
					$scoped_list .=
					"$path_to_object|$caller|$lib|$sym\n";
				}
			}
		}
	}

	if (defined($scoped_msg)) {
		my $problems = "$dir/check.problems";

		# problems will be appended to the file:
		my $problems_fh = do { local *FH; *FH };
		if (! open($problems_fh, ">>$problems")) {
			exiter(nofile($problems, $!));
		}
		print $problems_fh
		    "MISC: REMOVED_SCOPED_SYMBOLS: $scoped_msg\n";
		close($problems_fh);

		$problems = "$dir/check.demoted_symbols";

		# problems will be appended to the file:
		my $check_fh = do { local *FH; *FH };
		if (! open($check_fh, ">>$problems")) {
			exiter(nofile($problems, $!));
		}
		print $check_fh $scoped_list;
		close($check_fh);
	}

	#
	# Misc Check #2
	# Go through dynamic profile looking for special warnings.
	#

	my (%warnings, %wskip);
	my (%lib_star, %sym_star, %caller_star);
	my ($tag, $tag0, $sub, $res);

	while (($tag, $sub) = each(%warnings_match)) {
		next if (! $sub);

		$res = &{$sub}($path_to_object);
		$warnings{$tag} = 1 if ($res);
	}

	my $warnings_bind_has_non_direct = 0;

	while (($tag0, $tmp) =  each(%warnings_bind)) {
		($lib, $sym, $caller) = split(/\|/, $tmp, 3);
		$lib_star{$tag0}	= 1 if ($lib eq '*');
		$sym_star{$tag0}	= 1 if ($sym eq '*');
		$caller_star{$tag0}	= 1 if ($caller eq '*');
		if ($lib ne '*' && $lib !~ m,/, && ! $all_neededs{$lib}) {
			# it can never match:
			$wskip{$tag0} = 1;
		}
		if ($caller ne '*DIRECT*') {
			# this will be used to speed up the *DIRECT* only case:
			$warnings_bind_has_non_direct = 1;
		} elsif ($sym ne '*' && ! $direct_syms{$sym}) {
			# it can never match:
			$wskip{$tag0} = 1;
		}
	}

	foreach $lib (keys(%lib_not_found)) {
		#
		# add a placeholder symbol in %profile to indicate
		# $lib is on dtneeded, but wasn't found. This will
		# match a $sym = '*' warnings_bind misc check:
		#
		push(@profile,
		    "$lib|__ldd_indicated_file_not_found__|*DIRECT*");
	}

	my ($l_t, $s_t, $c_t, $match_t);

	my (@tag_list, @tag_list2, $new_tags);
	#
	# create a list of tags excluding the ones we know will be
	# skipped in the $libsymcaller loop below.
	#
	foreach $tag0 (keys(%warnings_bind)) {
		next if ($wskip{$tag0});
		push(@tag_list, $tag0);
	}

	#
	# we loop over @profile_short first, these will give us up to
	# 10 different libraries early to help us shrink @tag_list
	# as we go through the profile.
	#
	foreach $libsymcaller (@profile_short, @profile) {
		@tag_list = @tag_list2 if ($new_tags);
		last if (! @tag_list);

		($lib, $sym, $caller) = split(/\|/, $libsymcaller, 3);

		if (! $warnings_bind_has_non_direct && $caller ne '*DIRECT*') {
			next;
		}

		$base = basename($lib);
		$new_tags = 0;

		foreach $tag0 (@tag_list) {

			# try to get out early:
			next if ($wskip{$tag0});

			($tag, $tmp) = split(/\|/, $tag0, 2);
			# try to get out early:
			next if ($warnings{$tag});

			$match_t = $warnings_bind{$tag0};

			$l_t = $lib;
			$s_t = $sym;
			$c_t = $caller;

			$l_t = '*' if ($lib_star{$tag0});
			$s_t = '*' if ($sym_star{$tag0});
			$c_t = '*' if ($caller_star{$tag0});

			if ("$l_t|$s_t|$c_t" eq $match_t ||
			    "$base|$s_t|$c_t" eq $match_t) {
				$warnings{$tag} = 1;
				$wskip{$tag0} = 1;

				# shorten tag list:
				my (@t, $tg, $tg2, $tp);
				foreach $tg (@tag_list) {
					next if ($tg eq $tag0);
					($tg2, $tp) = split(/\|/, $tg, 2);
					next if ($tg2 eq $tag);
					push(@t, $tg);
				}
				@tag_list2 = @t;
				$new_tags = 1;
			}
		}
	}

	if (%warnings) {
		my $problems = "$dir/check.problems";

		# append problems to the file:
		my $problems_fh = do { local *FH; *FH };
		if (! open($problems_fh, ">>$problems")) {
			exiter(nofile($problems, $!));
		}

		my $tag;
		foreach $tag (keys(%warnings)) {
			print $problems_fh "MISC: WARNING: $tag\n";
		}
		close($problems_fh);
	}
}
