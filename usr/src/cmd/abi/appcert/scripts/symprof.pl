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
# This utility program creates the profiles of the binaries to be
# checked.
#
# The dynamic profiling is done by running ldd -r on the binary with
# LD_DEBUG=files,bindings and parsing the linker debug output.
#
# The static profiling (gathering of .text symbols) is done by calling
# the utility program static_prof.
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
	$tmp_prof_dir
);

set_clean_up_exit_routine(\&clean_up_exit);

import_vars_from_environment();

signals('on', \&interrupted);

set_working_dir();

profile_objects();

clean_up();

exit 0;

#
# working_dir has been imported by import_vars_from_environment() from
# appcert.  A sanity check is performed here to make sure it exists.
#
sub set_working_dir
{
	if (! defined($working_dir) || ! -d $working_dir) {
		exiter("$command_name: " . sprintf(gettext(
		    "cannot locate working directory: %s\n"), $working_dir));
	}
}

#
# Routine called when interrupted by user (e.g. SIGINT).
#
sub interrupted
{
	$SIG{$_[0]} = 'DEFAULT';
	signals('off');
	clean_up_exit(1);
}

#
# Does the cleanup then exits with return code $rc.  Note: The utility
# routine exiter() calls this routine.
#
sub clean_up_exit
{
	my ($rc) = @_;
	$rc = 0 unless ($rc);

	clean_up();
	exit $rc;
}

#
# General cleanup activities.
#
sub clean_up
{
	if (defined($tmp_prof_dir) && -d $tmp_prof_dir) {
		rmtree($tmp_prof_dir);
	}
}

#
# Top level routine to loop over the objects and call the profiling
# routines on each.
#
sub profile_objects
{
	# Make a tmp directory for the profiling work.
	$tmp_prof_dir = create_tmp_dir($tmp_dir);

	if (! -d $tmp_prof_dir) {
		exiter(nocreatedir($tmp_prof_dir, $!));
	}

	my ($dir, $path_to_object);

	#
	# Loop over each object item in the working_dir.
	#  - $dir will be each one of these object directories.
	#  - $path_to_object will be the corresponding actual path
	#    to the the binary to be profiled.
	# Output will usually be placed down in $dir, e.g. "$dir/profile.static"
	#

	my $cnt = -1;
	my $last_i;
	while (defined($dir = next_dir_name())) {
		$cnt++;
		if ($block_max ne '') {
			next if ($cnt < $block_min || $cnt >= $block_max);
		}

		$last_i = $cnt;

		# Map object output directory to actual path of the object:
		$path_to_object = dir_name_to_path($dir);

		if (! -f $path_to_object) {
			exiter(nopathexist($path_to_object, $!));
		}

		# Profile it:

		emsg(gettext("profiling: %s\n"), $path_to_object);

		static_profile($path_to_object, $dir);

		dynamic_profile($path_to_object, $dir);
	}

	# Only try this after everything has been initially profiled.
	if (! $block_max || $last_i >= $binary_count - 1) {
		redo_unbound_profile();
	}
	clean_up();	# Remove any tmp dirs and files.
}

#
# Runs utility program static_prof on the object and places results in
# output directory.
#
sub static_profile($$)
{
	my ($object, $output_dir) = @_;

	# This is the location of static_prof's output file:

	my $outfile = "$output_dir/profile.static";

	# It is consumed by static_check_object() in symcheck.

	#
	# Do not run on *completely* statically linked objects.  This
	# case will be caught and noted in the dynamic profiling and
	# checking.
	#
	my $skip_it;
	if (is_statically_linked($object)) {
		$skip_it = "STATICALLY_LINKED";
	} elsif (! is_elf($object)) {
		$skip_it = "NON_ELF";
	}

	my $static_prof_fh = do { local *FH; *FH };
	if (defined($skip_it)) {
		open($static_prof_fh, ">$outfile") ||
		    exiter(nofile($outfile, $!));

		print $static_prof_fh "#SKIPPED_TEST: $skip_it\n";
		close($static_prof_fh);

		return;
	}

	#
	# system() when run in the following manner will prevent the
	# shell from expanding any strange characters in $object. Quotes
	# around '$object' would be almost as safe.  since excluded
	# earlier the cases where it contains the ' character.
	#
	system("$appcert_lib_dir/static_prof", '-p', '-s', '-o', $outfile,
	    $object);

	if ($? != 0) {
		open($static_prof_fh, ">$outfile") ||
		    exiter(nofile($outfile, $!));

		#
		# For completeness, we'll use elfdump to record the
		# static profile for 64 bit binaries, although the
		# static linking problems only occur for 32-bit
		# applications.
		#
		my ($prof, $sym);
		$prof = '';
		my $elfdump_fh = do { local *FH; *FH };
		if (open($elfdump_fh, "$cmd_elfdump -s -N .dynsym '$object' " .
		    " 2>/dev/null |")) {
			while (<$elfdump_fh>) {
				chomp;
				if (/\s\.text\s+(\S+)$/) {
					$sym = $1;
					if (! /\bFUNC\b/) {
						next;
					}
					if (/\bGLOB\b/) {
						$prof .= "$object|TEXT|GLOB|" .
						    "FUNC|$sym\n";
					} else {
						$prof .= "$object|TEXT|WEAK|" .
						    "FUNC|$sym\n";
					}
				}
			}
			close($elfdump_fh);
		}
		if ($prof ne '') {
			my $line;
			print $static_prof_fh "#generated by symprof/elfdump\n";
			print $static_prof_fh "#dtneeded:";
			foreach $line (split(/\n/, cmd_output_dump($object))) {
				if ($line =~ /\bNEEDED\s+(\S+)/) {
					print $static_prof_fh " $1";
				}
			}
			print $static_prof_fh "\n";
			print $static_prof_fh $prof;
		} else {
			print $static_prof_fh "#SKIPPED_TEST: " .
			    "PROFILER_PROGRAM_static_prof_RETURNED:$?\n";
		}
		close($static_prof_fh);


		return;
	}

	# Also store the dtneededs from the static profile output.
	my $dtneeded = "$output_dir/info.dtneeded";

	my $dtneeded_fh = do { local *FH; *FH };
	open($dtneeded_fh, ">$dtneeded") ||
	    exiter(nofile($dtneeded, $!));

	open($static_prof_fh, "<$outfile") ||
	    exiter(nofile($outfile, $!));

	my $lib;
	while (<$static_prof_fh>) {

		next unless (/^\s*#/);

		if (/^\s*#\s*dtneeded:\s*(\S.*)$/) {
			foreach $lib (split(/\s+/, $1)) {
				next if ($lib eq '');
				print $dtneeded_fh "$lib\n";
			}
			last;
		}
	}
	close($dtneeded_fh);
	close($static_prof_fh);
}

#
# Top level subroutine for doing a dynamic profile of an object.  It
# calls get_dynamic_profile() which handles the details of the actual
# profiling and returns the newline separated "preprocessed format" to
# this subroutine.
#
# The records are then processed and placed in the output directory.
#
sub dynamic_profile
{
	my ($object, $output_dir) = @_;

	my ($profile, $line, $tmp);

	# This is the profile output file.
	my $outfile = "$output_dir/profile.dynamic";

	$profile = get_dynamic_profile($object);

	if ($profile =~ /^ERROR:\s*(.*)$/) {
		# There was some problem obtaining the dynamic profile
		my $msg = $1;
		my $errfile = "$output_dir/profile.dynamic.errors";

		my $profile_error_fh = do { local *FH; *FH };
		open($profile_error_fh, ">>$errfile") ||
		    exiter(nofile($errfile, $!));

		$msg =~ s/\n/ /g;
		$msg =~ s/;/,/g;
		print $profile_error_fh $msg, "\n";
		close($profile_error_fh);

		# Write a comment to the profile file as well:
		my $profile_fh = do { local *FH; *FH };
		open($profile_fh, ">$outfile") ||
		    exiter(nofile($outfile, $!));
		print $profile_fh "#NO_BINDINGS_FOUND $msg\n";
		close($profile_fh);

		return;
	}

	my ($filter, $filtee, $from, $to, $sym);
	my ($type, $saw_bindings, $all_needed);
	my (%filter_map, %symlink_map);

	# Resolve the symlink of the object, if any.
	$symlink_map{$object} = follow_symlink($object);

	#
	# Collect the filter or static linking info first.  Since the
	# filter info may be used to alias libraries, it is safest to do
	# it before any bindings processing.  that is why we iterate
	# through $profile twice.
	#
	my @dynamic_profile_array = split(/\n/, $profile);

	foreach $line (@dynamic_profile_array) {

		if ($line =~ /^FILTER_AUX:(.*)$/) {
			#
			# Here is the basic example of an auxiliary filter:
			#
			# FILTER: /usr/lib/libc.so.1
			# FILTEE: /usr/platform/sun4u/lib/libc_psr.so.1
			#
			# The app links against symbol memcpy() in
			# libc.so.1 at build time. Now, at run time IF
			# memcpy() is provided by libc_psr.so.1 then
			# that "code" is used, otherwise it backs off to
			# use the memcpy()in libc.so.1. The
			# libc_psr.so.1 doesn't even have to exist.
			#
			# The dynamic linker happily informs us that it
			# has found (and will bind to) memcpy() in
			# /usr/platform/sun4u/lib/libc_psr.so.1.  We
			# want to alias libc_psr.so.1 => libc.so.1.
			# Why?
			#	- less models to maintain. Note the symlink
			#	  situation in /usr/platform.
			#	- libc_psr.so.1 is versioned, but we would be
			#	  incorrect since it has memcpy() as SUNWprivate
			#
			# Therefore we record this aliasing in the hash
			# %filter_map.  This will be used below to
			# replace occurrences of the FILTEE string by
			# the FILTER string. Never the other way round.
			#

			($filter, $filtee) = split(/\|/, $1, 2);
			$filter_map{$filtee} = $filter;

			# Map the basenames too:
			$filter = basename($filter);
			$filtee = basename($filtee);
			$filter_map{$filtee} = $filter;

		} elsif ($line =~ /^FILTER_STD:(.*)$/) {

			#
			# Here is the basic example(s) of a standard filter:
			#
			# FILTER: /usr/lib/libsys.so.1
			# FILTEE: /usr/lib/libc.so.1
			#
			# Here is another:
			#
			# FILTER: /usr/lib/libw.so.1
			# FILTEE: /usr/lib/libc.so.1
			#
			# Here is a more perverse one, libxnet.so.1 has 3
			# filtees:
			#
			# FILTER: /usr/lib/libxnet.so.1
			# FILTEE: /usr/lib/{libsocket.so.1,libnsl.so.1,libc.so.1}
			#
			# The important point to note about standard
			# filters is that they contain NO CODE AT ALL.
			# All of the symbols in the filter MUST be found
			# in (and bound to) the filtee(s) or there is a
			# relocation error.
			#
			# The app links against symbol getwc() in
			# libw.so.1 at build time. Now, at run time
			# getwc() is actually provided by libc.so.1.
			#
			# The dynamic linker happily informs us that it
			# has found (and will bind to) getwc() in
			# libc.so.1. IT NEVER DIRECTLY TELLS US getwc was
			# actually referred to in libw.so.1
			#
			# So, unless we open a model file while
			# PROFILING, we cannot figure out which ones
			# come from libw.so.1 and which ones come from
			# libc.so.1. In one sense this is too bad: the
			# libw.so.1 structure is lost.
			#
			# The bottom line is we should not alias
			# libc.so.1 => libw.so.1 (FILTEE => FILTER) as
			# we did above with FILTER_AUX. That would be a
			# disaster. (would say EVERYTHING in libc came
			# from libw!)
			#
			# So we DO NOT store the alias in this case, this
			# leads to:
			#	- more models to maintain.
			#
			# Thus we basically skip this info.
			# EXCEPT for one case, libdl.so.1, see below.
			#

			($filter, $filtee) = split(/\|/, $1, 2);

			#
			# The dlopen(), ... family of functions in
			# libdl.so.1 is implemented as a filter for
			# ld.so.1.  We DO NOT want to consider a symbol
			# model for ld.so.1. So in this case alone we
			# want to alias ld.so.1 => libdl.so.1
			#
			#
			# We only need to substitute the standard filter
			# libdl.so.n. Record the alias in that case.
			#
			if ($filter =~ /\blibdl\.so\.\d+/) {
				$filter_map{$filtee} = $filter;

				# Map basenames too:
				$filter = basename($filter);
				$filtee = basename($filtee);
				$filter_map{$filtee} = $filter;
			}

		} elsif ($line =~ /^DYNAMIC_PROFILE_SKIPPED_NOT_ELF/ ||
		    $line =~ /^STATICALLY_LINKED:/) {
			#
			# This info will go as a COMMENT into the
			# output.  n.b.: there is no checking whether
			# this piece of info is consistent with the rest
			# of the profile output.
			#
			# The $message string will come right after the
			# header, and before the bindings (if any).  See
			# below where we write to the PROF filehandle.
			#

			my $profile_msg_fh = do { local *FH; *FH };
			open($profile_msg_fh, ">>$outfile") ||
			    exiter(nofile($outfile, $!));
			print $profile_msg_fh "#$line\n";
			close($profile_msg_fh);

		} elsif ($line =~ /^NEEDED_FOUND:(.*)$/) {
			#
			# These libraries are basically information
			# contained in the ldd "libfoo.so.1 =>
			# /usr/lib/libfoo.so.1" output lines.  It is the
			# closure of the neededs (not just the directly
			# needed ones).
			#

			$all_needed .= $1 . "\n";
		}
	}

	#
	# Now collect the bindings info:
	#
	# Each BINDING record refers to 1 symbol. After manipulation
	# here it will go into 1 record into the profile output.
	#
	# What sort of manipulations? Looking below reveals:
	#
	#  - we apply the library FILTER_AUX aliases in %filter_map
	#  - for shared objects we resolve symbolic links to the actual
	#    files they point to.
	#  - we may be in a mode where we do not store full paths of
	#    the shared objects, e.g. /usr/lib/libc.so.1, but rather
	#    just their basename "libc.so.1"
	#
	# There are exactly four(4) types of bindings that will be
	# returned to us by get_dynamic_profile().  See
	# get_dynamic_profile() and Get_ldd_Profile() for more details.
	#
	# Here are the 4 types:
	#
	# BINDING_DIRECT:from|to|sym
	#	The object being profiled is the "from" here!
	#	It directly calls "sym" in library "to".
	#
	# BINDING_INDIRECT:from|to|sym
	#	The object being profiled is NOT the "from"  here.
	#	"from" is a shared object, and "from" calls "sym" in
	#	library "to".
	#
	# BINDING_REVERSE:from|to|sym
	#	The shared object "from" makes a reverse binding
	#	all the way back to the object being profiled! We call
	#	this *REVERSE*. "to" is the object being profiled.
	#
	# BINDING_UNBOUND:from|sym
	#	object "from" wants to call "sym", but "sym" was
	#	not found! We didn't find the "to", and so no
	#	"to" is passed to us.
	#

	my $put_DIRECT_in_the_UNBOUND_record;

	$saw_bindings = 0;
	#
	# Start the sorting pipeline that appends to the output file.
	# It will be written to in the following loop.
	#
	# Tracing back $outfile to $outdir to $working_dir, one sees $outfile
	# should have no single-quote characters.  We double check it does not
	# before running the command.
	#
	if ($outfile =~ /'/) {
	    exiter(norunprog("|$cmd_sort -t'|' +1 | $cmd_uniq >> '$outfile'"));
	}

	my $prof_fh = do { local *FH; *FH };
	open($prof_fh, "|$cmd_sort -t'|' +1 | $cmd_uniq >> '$outfile'") ||
	    exiter(norunprog("|$cmd_sort -t'|' +1 | $cmd_uniq >> '$outfile'",
	    $!));
	local($SIG{'PIPE'}) = sub {
		exiter(norunprog(
		    "|$cmd_sort -t'|' +1 | $cmd_uniq >> '$outfile'", $!));
	};

	foreach $line (@dynamic_profile_array) {

		if ($line =~ /^BINDING_([^:]+):(.*)$/) {

			$type = $1;

			if ($type eq 'UNBOUND') {
				#
				# If the symbol was unbound, there is no
				# "to" library. We make an empty "to"
				# value so as to avoid special casing
				# "to" all through the code that
				# follows.  It is easy to verify no
				# matter what happens with the $to
				# variable, it will NOT be printed to the
				# profile output file in the UNBOUND
				# case.
				#

				($from, $sym) = split(/\|/, $2, 2);
				$to = '';

			} else {
				# Otherwise, we have the full triple:

				($from, $to, $sym) = split(/\|/, $2, 3);
			}

			#
			# We record here information to be used in
			# writing out UNBOUND records, namely if the
			# "from" happened to also be the object being
			# profiled. In that case The string "*DIRECT*"
			# will be placed in the "*UNBOUND*" record,
			# otherwise the "from" will stand as is in the
			# "*UNBOUND*" record. We do this check here
			# before the filter_map is applied. The chances
			# of it making a difference is small, but we had
			# best to do it here.
			#
			if (files_equal($from, $object)) {
				#
				# Switch to indicate placing *DIRECT* in
				# the *UNBOUND* line, etc.
				#
				$put_DIRECT_in_the_UNBOUND_record = 1;
			} else  {
				$put_DIRECT_in_the_UNBOUND_record = 0;
			}

			#
			# See if there is a filter name that "aliases"
			# either of the "from" or "to" libraries, if so
			# then rename it.
			#
			if ($to ne '' && $filter_map{$to}) {
				$to = $filter_map{$to};
			}
			if ($type ne 'DIRECT' && $filter_map{$from}) {
				$from = $filter_map{$from};
			}

			#
			# Record symlink information.
			#
			# Note that follow_symlink returns the file
			# name itself when the file is not a symlink.
			#
			# Work out if either "from" or "to" are
			# symlinks.  For efficiency we keep them in the
			# %symlink_map hash.  Recall that we are in a
			# loop here, so why do libc.so.1 200 times?
			#
			if ($from ne '') {
				if (! exists($symlink_map{$from})) {
					$symlink_map{$from} =
					    follow_symlink($from);
				}
			}
			if ($to ne '') {
				if (! exists($symlink_map{$to})) {
					$symlink_map{$to} =
					    follow_symlink($to);
				}
			}

			#
			# Now make the actual profile output line. Construct
			# it in $tmp and then append it to $prof_fh pipeline.
			#
			$tmp = '';

			if ($type eq "DIRECT") {
				$tmp = "$object|*DIRECT*|$to|$sym";
			} elsif ($type eq "INDIRECT") {
				$tmp = "$object|$from|$to|$sym";
			} elsif ($type eq "REVERSE") {
				$tmp = "$object|*REVERSE*|$from|$sym";
			} elsif ($type eq "UNBOUND") {
				if ($put_DIRECT_in_the_UNBOUND_record) {
					$tmp =
					    "$object|*DIRECT*|*UNBOUND*|$sym";
				} else {
					$tmp = "$object|$from|*UNBOUND*|$sym";
				}
			} else {
				exiter("$command_name: " . sprintf(gettext(
				    "unrecognized ldd(1) LD_DEBUG " .
				    "bindings line: %s\n"), $line));
			}

			# write it to the sorting pipeline:
			print $prof_fh $tmp, "\n";
			$saw_bindings = 1;
		} elsif ($line =~ /^DYNAMIC_PROFILE_SKIPPED_NOT_ELF/) {
			# ignore no bindings warning for non-ELF
			$saw_bindings = 1;
		}
	}

	if (! $saw_bindings) {
		print $prof_fh "#NO_BINDINGS_FOUND\n";
	}
	close($prof_fh);
	if ($? != 0) {
		exiter(norunprog(
		    "|$cmd_sort -t'|' +1 | $cmd_uniq >> '$outfile'", $!));
	}

	# Print out the library location and symlink info.
	$outfile = "$output_dir/profile.dynamic.objects";

	my $objects_fh = do { local *FH; *FH };
	open($objects_fh, ">$outfile") || exiter(nofile($outfile, $!));

	my ($var, $val);
	while (($var, $val) = each(%ENV)) {
		if ($var =~ /^LD_/) {
			print $objects_fh "#info: $var=$val\n";
		}
	}

	my $obj;
	foreach $obj (sort(keys(%symlink_map))) {
		next if ($obj eq '');
		print $objects_fh "$obj => $symlink_map{$obj}\n";
	}
	close($objects_fh);

	# Print out ldd shared object resolution.
	$outfile = "$output_dir/profile.dynamic.ldd";

	my $ldd_prof_fh = do { local *FH; *FH };
	open($ldd_prof_fh, ">$outfile") || exiter(nofile($outfile, $!));

	if (defined($all_needed)) {
		print $ldd_prof_fh $all_needed;
	}
	close($ldd_prof_fh);

}

#
# If the users environment is not the same when running symprof as when
# running their application, the dynamic linker cannot resolve all of
# the dynamic bindings and we get "unbound symbols".
# redo_unbound_profile attempts to alleviate this somewhat. In
# particular, for shared objects that do not have all of their
# dependencies recorded, it attempts to use binding information in the
# other *executables* under test to supplement the binding information
# for the shared object with unbound symbols.  This is not the whole
# story (e.g. dlopen(3L)), but it often helps considerably.
#
sub redo_unbound_profile
{
	my ($dir, $path_to_object);
	my ($profile, $total, $count);
	my (%unbound_bins);

	#
	# Find the objects with unbound symbols. Put them in the list
	# %unbound_bins.
	#
	$total = 0;
	while (defined($dir = next_dir_name())) {

		$profile = "$dir/profile.dynamic";
		my $profile_fh = do { local *FH; *FH };
		if (! -f $profile || ! open($profile_fh, "<$profile")) {
			next;
		}

		$count = 0;
		while (<$profile_fh>) {
			next if (/^\s*#/);
			$count++ if (/\|\*UNBOUND\*\|/);
		}
		close($profile_fh);

		$unbound_bins{$dir} = $count if ($count);
		$total += $count;
	}

	# we are done if no unbounds are detected.
	return unless (%unbound_bins);
	return if ($total == 0);

	my (%dtneededs_lookup_full, %dtneededs_lookup_base);

	# Read in *ALL* objects dt_neededs.

	my ($soname, $base, $full);
	while (defined($dir = next_dir_name())) {

		$profile = "$dir/profile.dynamic.ldd";
		my $all_neededs_fh = do { local *FH; *FH };
		if (! open($all_neededs_fh, "<$profile")) {
			# this is a heuristic, so we skip on to the next
			next;
		}

		while (<$all_neededs_fh>) {
			chop;
			next if (/^\s*#/);
			# save the dtneeded info:
			($soname, $full) = split(/\s+=>\s+/, $_);

			if ($full !~ /not found|\)/) {
				$dtneededs_lookup_full{$full}{$dir} = 1;
			}
			if ($soname !~ /not found|\)/) {
				$base = basename($soname);
				$dtneededs_lookup_base{$base}{$dir} = 1;
			}
		}
		close($all_neededs_fh);
	}

	emsg("\n" . gettext(
	    "re-profiling binary objects with unbound symbols") . " ...\n");

	# Now combine the above info with each object having unbounds:

	my $uref = \%unbound_bins;
	foreach $dir (keys(%unbound_bins)) {

		# Map object output directory to the actual path of the object:
		$path_to_object = dir_name_to_path($dir);

		#
		# Here is the algorithm:
		#
		# 1) binary with unbounds must be a shared object.
		#
		# 2) check if it is in the dtneeded of other product binaries.
		#	if so, use the dynamic profile of those binaries
		#	to augment the bindings of the binary with unbounds
		#

		if (! -f $path_to_object) {
			exiter(nopathexist($path_to_object, $!));
		}

		# only consider shared objects (e.g. with no DTNEEDED recorded)
		if (! is_shared_object($path_to_object)) {
			next;
		}

		$base = basename($path_to_object);

		my (@dirlist);

		my $result = 0;

		if (defined($dtneededs_lookup_base{$base})) {
			# the basename is on another's dtneededs:
			@dirlist = keys(%{$dtneededs_lookup_base{$base}});
			# try using the bindings of these executables:
			$result =
			    try_executables_bindings($dir, $uref, @dirlist);
		}
		if ($result) {
			# we achieved some improvements and so are done:
			next;
		}

		# Otherwise, try objects that have our full path in their
		# dtneededs:
		@dirlist = ();
		foreach $full (keys(%dtneededs_lookup_full)) {
			if (! files_equal($path_to_object, $full)) {
				next;
			}
			push(@dirlist, keys(%{$dtneededs_lookup_full{$full}}));
		}
		if (@dirlist) {
			$result =
			    try_executables_bindings($dir, $uref, @dirlist);
		}
	}
	emsg("\n");
}

#
# We are trying to reduce unbound symbols of shared objects/libraries
# under test that *have not* recorded their dependencies (i.e.
# DTNEEDED's). So we look for Executables being checked that have *this*
# binary ($path_to_object, a shared object) on *its* DTNEEDED. If we
# find one, we use those bindings.
#
sub try_executables_bindings
{
	my ($dir, $uref, @dirlist) = @_;

	my $path_to_object = dir_name_to_path($dir);

	#
	# N.B. The word "try" here means for a binary (a shared library,
	# actually) that had unbound symbols, "try" to use OTHER
	# executables binding info to resolve those unbound symbols.
	#
	# At least one executable needs this library; we select the one
	# with minimal number of its own unbounds.
	#
	my (%sorting_list);
	my (@executables_to_try);
	my ($dir2, $cnt);
	foreach $dir2 (@dirlist) {
		next if (! defined($dir2));
		next if ($dir2 eq $dir);
		if (exists($uref->{$dir2})) {
			$cnt = $uref->{$dir2};
		} else {
			#
			# This binary is not on the unbounds list, so
			# give it the highest priority.
			#
			$cnt = 0;
		}
		$sorting_list{"$dir2 $cnt"} = $dir2;
	}

	foreach my $key (reverse(sort_on_count(keys %sorting_list))) {
		push(@executables_to_try, $sorting_list{$key});
	}

	my ($my_new_count, $my_new_profile, %my_new_symbols);
	my ($object, $caller, $callee, $sym, $profile);
	my $reprofiled = 0;

	my ($line, $path2);

	foreach $dir2 (@executables_to_try) {
		$path2 = dir_name_to_path($dir2);
		emsg(gettext(
		    "re-profiling: %s\n" .
		    "using:        %s\n"), $path_to_object, $path2);

		# read the other binary's profile

		$profile = "$dir2/profile.dynamic";
		if (! -f $profile) {
			next;
		}

		my $prof_try_fh = do { local *FH; *FH };
		open($prof_try_fh, "<$profile") ||
		    exiter(nofile($profile, $!));

		# initialize for the next try:
		$my_new_profile = '';
		$my_new_count = 0;
		%my_new_symbols = ();

		# try to find bindings that involve us ($dir)
		while (<$prof_try_fh>) {
			chop($line = $_);
			next if (/^\s*#/);
			next if (/^\s*$/);
			($object, $caller, $callee, $sym) =
			    split(/\|/, $line, 4);

			if ($caller eq '*REVERSE*') {
				next if ($callee =~ /^\*.*\*$/);
				if (! files_equal($callee, $path_to_object)) {
					next;
				}

				$my_new_profile .=
				    "$callee|*DIRECT*|REVERSE_TO:" .
				    "$object|$sym\n";

				$my_new_symbols{$sym}++;
				$my_new_count++;

			} elsif (files_equal($caller, $path_to_object)) {
				$my_new_profile .=
				    "$caller|*DIRECT*|$callee|$sym\n";

				$my_new_symbols{$sym}++;
				$my_new_count++;
			}
		}
		close($prof_try_fh);

		next if (! $my_new_count);

		# modify our profile with the new information:
		$profile = "$dir/profile.dynamic";
		if (! rename($profile, "$profile.0") || ! -f "$profile.0") {
			return 0;
		}
		my $prof_orig_fh = do { local *FH; *FH };
		if (! open($prof_orig_fh, "<$profile.0")) {
			rename("$profile.0", $profile);
			return 0;
		}
		my $prof_fh = do { local *FH; *FH };
		if (! open($prof_fh, ">$profile")) {
			rename("$profile.0", $profile);
			return 0;
		}
		my $resolved_from = dir_name_to_path($dir2);
		print $prof_fh "# REDUCING_UNBOUNDS_VIA_PROFILE_FROM: " .
		    "$resolved_from\n";

		while (<$prof_orig_fh>) {
			if (/^\s*#/) {
				print $prof_fh $_;
				next;
			}
			chop($line = $_);
			($object, $caller, $callee, $sym) =
			    split(/\|/, $line, 4);
			if (! exists($my_new_symbols{$sym})) {
				print $prof_fh $_;
				next;
			}
			print $prof_fh "# RESOLVED_FROM=$resolved_from: $_";
		}
		close($prof_orig_fh);
		print $prof_fh "# NEW_PROFILE:\n" . $my_new_profile;
		close($prof_fh);

		$reprofiled = 1;
		last;
	}
	return $reprofiled;
}

#
# This routine calls get_ldd_output on the object and parses the
# LD_DEBUG output. Returns a string containing the information in
# standard form.
#
sub get_dynamic_profile
{
	my ($object) = @_;

	# Check if the object is statically linked:

	my $str;
	if (! is_elf($object)) {
		return "DYNAMIC_PROFILE_SKIPPED_NOT_ELF";
	} elsif (is_statically_linked($object)) {
		$str = cmd_output_file($object);
		return "STATICALLY_LINKED: $str";
	}

	# Get the raw ldd output:
	my $ldd_output = get_ldd_output($object);

	if ($ldd_output =~ /^ERROR:/) {
		# some problem occurred, pass the error upward:
		return $ldd_output;
	}

	# variables for manipulating the output:
	my ($line, $filters, $neededs, $rest);
	my ($tmp, $tmp2, @bindings);

	# Now parse it:

	foreach $line (split(/\n/, $ldd_output)) {

		if ($line =~ /^\d+:\s*(.*)$/) {
			# LD_DEBUG profile line, starts with "NNNNN:"
			$tmp = $1;
			next if ($tmp eq '');

			if ($tmp =~ /^binding (.*)$/) {
				#
				# First look for:
				# binding file=/bin/pagesize to \
				# file=/usr/lib/libc.so.1: symbol `exit'
				#
				$tmp = $1;
				push(@bindings, ldd_binding_line($1, $object));

			} elsif ($tmp =~ /^file=\S+\s+(.*)$/) {
				#
				# Next look for:
				# file=/usr/platform/SUNW,Ultra-1/\
				# lib/libc_psr.so.1;  filtered by /usr...
				# file=libdl.so.1;  needed by /usr/lib/libc.so.1
				#
				$rest =  trim($1);

				if ($rest =~ /^filtered by /) {
					$filters .=
					    ldd_filter_line($tmp);
				} elsif ($rest =~ /^needed by /) {
					$neededs .=
					    ldd_needed_line($tmp, $object);
				}

			}

		} elsif ($line =~ /^stdout:(.*)$/) {
			# LD_DEBUG stdout line:

			$tmp = trim($1);
			next if ($tmp eq '');

			if ($tmp =~ /\s+=>\s+/) {
				#
				# First look for standard dependency
				# resolution lines:
				#
				#      libsocket.so.1 => /usr/lib/libsocket.so.1
				#
				# Note that these are *all* of the
				# needed shared objects, not just the
				# directly needed ones.
				#
				$tmp =~ s/\s+/ /g;
				$neededs .= "NEEDED_FOUND:$tmp" . "\n";

			} elsif ($tmp =~ /symbol not found: (.*)$/) {
				#
				# Next look for unbound symbols:
				# symbol not found: gethz     (/usr/\
				# local/bin/gethz)
				#

				$tmp = trim($1);
				($tmp, $tmp2) = split(/\s+/, $tmp, 2);
				$tmp2 =~ s/[\(\)]//g;	# trim off ().

				# $tmp is the symbol, $tmp2 is the
				# calling object.

				push(@bindings,
				    "BINDING_UNBOUND:$tmp2|$tmp" . "\n"
				);
			}
		}
	}

	# Return the output:
	my $ret = '';
	$ret .= $filters if (defined($filters));
	$ret .= $neededs if (defined($neededs));
	$ret .= join('', @bindings);

	return $ret;
}

#
# Routine used to parse a LD_DEBUG "binding" line.
#
# Returns "preprocessed format line" if line is ok, or
# null string otherwise.
#
sub ldd_binding_line
{
	my ($line, $object) = @_;

	my ($from, $to, $sym);

	my ($t1, $t2, $t3);	# tmp vars for regex output

	#
	# Working on a line like:
	#
	# binding file=/bin/pagesize to file=/usr/lib/libc.so.1: symbol `exit'
	#
	# (with the leading "binding " removed).
	#

	if ($line =~ /^file=(\S+)\s+to file=(\S+)\s+symbol(.*)$/) {
		#
		# The following trim off spaces, ', `, ;, and :, from
		# the edges so if the filename had those there could
		# be a problem.
		#
		$from = $1;
		$to = $2;
		$sym = $3;
		#
		# guard against future changes to the LD_DEBUG output
		# (i.e. information appended to the end)
		#
		$sym =~ s/'\s+.*$//;

		$to =~ s/:$//;

		$sym =~ s/[\s:;`']*$//;
		$sym =~ s/^[\s:;`']*//;

	} elsif ($line =~ /^file=(.+) to file=(.+): symbol (.*)$/) {
		# This will catch spaces, but is less robust.
		$t1 = $1;
		$t2 = $2;
		$t3 = $3;
		#
		# guard against future changes to the LD_DEBUG output
		# (i.e. information appended to the end)
		#
		$t3 =~ s/'\s+.*$//;

		$from = wclean($t1, 1);
		$to   = wclean($t2, 1);
		$sym  = wclean($t3);

	} else {
		return '';
	}

	if ($from eq '' || $to eq '' || $sym eq '') {
		return '';
	}

	#
	# OK, we have 3 files: $from, $to, $object
	# Which, if any, are the same file?
	#
	# Note that we have not yet done the Filter library
	# substitutions yet. So one cannot be too trusting of the file
	# comparisons done here.
	#

	if (files_equal($from, $to, 0)) {
		#
		# We skip the "from" = "to" case
		# (could call this: BINDING_SELF).
		#
		return '';
	} elsif (files_equal($object, $from, 0)) {
		# DIRECT CASE (object calls library):
		return "BINDING_DIRECT:$from|$to|$sym"   . "\n";
	} elsif (files_equal($object, $to, 0)) {
		# REVERSE CASE (library calls object):
		return "BINDING_REVERSE:$from|$to|$sym"  . "\n";
	} else {
		#
		# INDIRECT CASE (needed library calls library):
		# (this will not be a library calling itself because
		# we skip $from eq $to above).
		#
		return "BINDING_INDIRECT:$from|$to|$sym" . "\n";
	}
}

#
# Routine used to parse a LD_DEBUG "filtered by" line.
#
# Returns "preprocessed format line" if line is ok, or null string
# otherwise.
#
sub ldd_filter_line
{
	my ($line) = @_;

	my ($filter, $filtee);

	#
	# Working on a line like:
	#
	# file=/usr/platform/SUNW,Ultra-1/lib/libc_psr.so.1;  \
	#					filtered by /usr/lib/libc.so.1
	#

	my ($t1, $t2);	# tmp vars for regex output

	if ($line =~ /file=(\S+)\s+filtered by\s+(\S.*)$/) {
		$t1 = $1;
		$t2 = $2;
		$filtee = wclean($t1);
		$filter = wclean($t2);
	} elsif ($line =~ /file=(.+);  filtered by (.*)$/) {
		$t1 = $1;
		$t2 = $2;
		$filtee = wclean($t1, 1);
		$filter = wclean($t2, 1);
	} else {
		return '';
	}

	if ($filtee eq '' || $filter eq '') {
		return '';
	}
	#
	# What kind of filter is $filter?
	#	STANDARD  (contains no "real code", e.g. libxnet.so.1), or
	#	AUXILIARY (provides "code" if needed, but
	#	           prefers to pass filtee's "code", e.g. libc.so.1)
	#
	# LD_DEBUG output does not indicate this, so dump -Lv is run on it
	# in filter_lib_type:
	#

	my $type = 'unknown';

	$type = filter_lib_type($filter);

	if ($type eq 'STD') {
		return "FILTER_STD:$filter|$filtee" . "\n";
	} elsif ($type eq 'AUX') {
		return "FILTER_AUX:$filter|$filtee" . "\n";
	} else {
		return '';
	}
}

#
# Routine used to parse a LD_DEBUG "needed by" line.
#
# Returns "preprocessed format line" if line is ok, or the null string
# otherwise.
#
sub ldd_needed_line
{
	my ($line, $object) = @_;

	my ($thing_needed, $file);

	my ($t1, $t2);	# tmp variables for regex output.

	#
	# Working on a line like:
	#
	# file=libdl.so.1;  needed by /usr/lib/libc.so.1
	#

	if ($line =~ /file=(\S+)\s+needed by\s+(\S.*)$/) {
		$t1 = $1;
		$t2 = $2;
		$thing_needed	= wclean($t1);
		$file		= wclean($t2);
	} elsif ($line =~ /file=(.+);  needed by (.*)$/) {
		$t1 = $1;
		$t2 = $2;
		$thing_needed	= wclean($t1, 1);
		$file		= wclean($t2, 1);
	} else {
		return '';
	}

	if ($thing_needed eq '' || $file eq '') {
		return '';
	}

	#
	# Note that $thing_needed is not a path to a file, just the
	# short name unresolved, e.g. "libc.so.1".  The next line of the
	# LD_DEBUG output would tell us where $thing_needed is resolved
	# to.
	#

	if (files_equal($object, $file)) {
		return "NEEDED_DIRECT:$thing_needed|$file"   . "\n";
	} else {
		return "NEEDED_INDIRECT:$thing_needed|$file" . "\n";
	}
}

#
# Routine to clean up a "word" string from ldd output.
#
# This is specialized for removing the stuff surrounding files and
# symbols in the LD_DEBUG output. It is usually a file name or symbol
# name.
#
sub wclean
{
	my ($w, $keep_space) = @_;

	if (! $keep_space) {
		# make sure leading/trailing spaces are gone.
		$w =~ s/[\s:;`']*$//;	# get rid of : ; ' and `
		$w =~ s/^[\s:;`']*//;
	} else {
		$w =~ s/[:;`']*$//;	# get rid of : ; ' and `
		$w =~ s/^[:;`']*//;
	}

	return $w;
}

#
# This routine runs ldd -r on the object file with LD_DEBUG flags turned
# on.  It collects the stdout and the LD_DEBUG profile data for the
# object (it must skip the LD_DEBUG profile data for /usr/bin/ldd
# /bin/sh, or any other extraneous processes).
#
# It returns the profile data as a single string with \n separated
# records. Records starting with "stdout: " are the stdout lines,
# Records starting with "NNNNN: " are the LD_DEBUG lines.  Our caller
# must split and parse those lines.
#
# If there is some non-fatal error, it returns a 1-line string like:
#	ERROR: <error-message>
#
sub get_ldd_output
{

	my ($object) = @_;

	my ($tmpdir, $outfile, $errfile);

	if (! -f $object) {
		exiter(nopathexist($object));
	}

	# We use the tmp_dir for our work:
	$tmpdir = $tmp_prof_dir;

	# Clean out the tmpdir.
	if ($tmpdir !~ m,^/*$,) {
		unlink(<$tmpdir/*>);
		#
		# The following puts xgettext(1) back on track. It is
		# confused and believes it is inside a C-style /* comment */
		#
		my $unused = "*/";
	}

	# Output files for collecting output of the ldd -r command:
	$errfile = "$tmpdir/stderr";
	$outfile = "$tmpdir/stdout";

	my ($rc, $msg, $child, $result);

	#
	# This forking method should have 2 LD_DEBUG bind.<PID> files
	# one for ldd and the other for $object. system() could have
	# another from the shell.
	#

	# Fork off a child:
	$child = fork();

	#
	# Note: the file "/tmp/.../bind.$child" should be the "ldd"
	# profile, but we do not want to depend upon that.
	#

	if (! defined($child)) {
		# Problem forking:
		exiter(sprintf(gettext(
		    "cannot fork for command: ldd -r %s: %s\n"), $object, $!));

	} elsif ($child == 0) {

		# Reopen std output to the desired output files:
		open(STDOUT, ">$outfile") ||
		    exiter(nofile($outfile, $!));

		open(STDERR, ">$errfile") ||
		    exiter(nofile($errfile, $!));

		#
		# Set the env to turn on debugging from the linker:
		#
		$ENV{'LD_DEBUG'} = "files,bindings";
		$ENV{'LD_DEBUG_OUTPUT'} = "$tmpdir/bind";

		#
		# Set LD_NOAUXFLTR to avoid auxiliary filters (e.g. libc_psr)
		# since they are not of interest to the public/private
		# symbol status and confuse things more than anything else.
		#
		$ENV{'LD_NOAUXFLTR'} = "1";

		# Run ldd -r:
		c_locale(1);
		exec($cmd_ldd, '-r', $object);
		exit 1;		# only reached if exec fails.
	} else {
		wait;		# Wait for children to finish.
		$rc = $?; 	# Record exit status.
		$msg = $!;
	}

	# Check the exit status:
	if ($rc != 0) {
		if (-s $errfile) {
			my $tmp;
			my $errfile_fh = do { local *FH; *FH };
			if (open($errfile_fh, "<$errfile")) {
				while (<$errfile_fh>) {
					if (/ldd:/) {
						$tmp = $_;
						last;
					}
				}
				close($errfile_fh);
			}
			if (defined($tmp))  {
				chomp($tmp);
				if ($tmp =~ /ldd:\s*(\S.*)$/) {
					$tmp = $1;
				}
				if ($tmp =~ /^[^:]+:\s*(\S.*)$/) {
					my $t = $1;
					if ($t !~ /^\s*$/) {
						$tmp = $t;
					}
				}
				$msg = $tmp if ($tmp !~ /^\s*$/);
			}
		}
		emsg("%s", norunprog("$cmd_ldd -r $object", "$msg\n"));
		$msg =~ s/\n/ /g;
		$msg =~ s/;/,/g;
		$msg = sprintf("ERROR: " . gettext(
		    "Error running: ldd -r LD_DEBUG: %s"), $msg);
		return $msg;
	}

	#
	# We now have all the output files created. We read them and
	# merge them into one long string to return to whoever called
	# us.  The caller will parse it, not us. Our goal here is to
	# just return the correct LD_DEBUG profile data.
	#

	if (-f "$tmpdir/stdout") {
		my $out_fh = do { local *FH; *FH };
		if (! open($out_fh, "<$tmpdir/stdout")) {
			exiter(nofile("$tmpdir/stdout", $!));
		}
		while (<$out_fh>) {
			# Add the special prefix for STDOUT:
			$result .= "stdout: $_";
		}
		close($out_fh);
	}

	my ($file, $count, $goodone, $ok, $aok, @file);

	$count = 0;

	my $prevline;

	# Loop over each "bind.NNNNN" file in the tmp directory:
	foreach $file (<$tmpdir/bind.*>) {

		# Open it for reading:
		my $ldd_file_fh = do { local *FH; *FH };
		if (! open($ldd_file_fh, "<$file")) {
			exiter(nofile($file, $!));
		}

		#
		# ok = 1 means this file we are reading the profile file
		# corresponding to $object. We set ok = 0 as soon as we
		# discover otherwise.
		#
		$ok = 1;

		#
		# $aok = 1 means always OK. I.e. we are definitely in the
		# correct profile.
		#
		$aok = 0;

		#
		# this variable will hold the previous line so that we
		# can skip adjacent duplicates.
		#
		$prevline = '';

		my $idx;

		while (<$ldd_file_fh>) {

			#
			# This check is done to perform a simple
			# uniq'ing of the output. Non-PIC objects have
			# lots of duplicates, many of them right after
			# each other.
			#

			next if ($_ eq $prevline);
			$prevline = $_;

			#
			# Check to see if this is the wrong profile
			# file:  The ones we know about are "ldd" and
			# "sh".  If the object under test is ever "ldd"
			# or "sh" this will fail.
			#
			if ($aok) {
				;
			} elsif ($ok) {
			#
			# checks line:
			# file=ldd;  analyzing  [ RTLD_GLOBAL  RTLD_LAZY ]
			#
				if (/\bfile=\S+\b(ldd|sh)\b/) {
					$ok = 0;
				} else {
					$idx =
					index($_, " file=$object;  analyzing");
					$aok = 1 if ($idx != -1);
				}
			}

			# We can skip this file as soon as we see $ok = 0.
			last unless ($ok);

			# Gather the profile output into a string:
			$file[$count] .= $_;
		}

		#
		# Note that this one is the desired profile
		# (i.e. if $ok is still true):
		#
		$goodone .= "$count," if ($ok);

		# On to the next $file:
		close($ldd_file_fh);
		$count++;
	}

	if (defined($goodone)) {
		$goodone =~ s/,$//;	# Trim the last comma off.
	}

	# If we have none or more than one "good one" we are in trouble:
	if (! defined($goodone) || ($goodone !~ /^\d+$/) || ($goodone =~ /,/)) {

		#
		# Note that this is the first point at which we would detect
		# a problem with the checking of SUID/SGID objects, although
		# in theory we could have skipped these objects earlier.
		# We prefer to let the linker, ld.so.1, indicate this failure
		# and then we catch it and diagnose it here.
		#
		my $suid = is_suid($object);

		if ($suid == 1) {
			$result = "ERROR: " . gettext(
			    "SUID - ldd(1) LD_DEBUG profile failed");
		} elsif ($suid == 2) {
			$result = "ERROR: " . gettext(
			    "SGID - ldd(1) LD_DEBUG profile failed");
		} else {
			$result = "ERROR: " . gettext(
			    "could not get ldd(1) LD_DEBUG profile output");
		}

	} else {
		# Append the correct profile to the result and return it:
		$result .= $file[$goodone];
	}

	# Tidy up our mess by cleaning out the tmpdir.
	unlink(<$tmpdir/*>) if ($tmpdir !~ m,^/*$,);

	return $result;
}
