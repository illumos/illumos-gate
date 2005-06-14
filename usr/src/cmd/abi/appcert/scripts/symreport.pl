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
# Copyright (c) 1996-2000 by Sun Microsystems, Inc.
# All rights reserved.
#
#ident	"%Z%%M%	%I%	%E% SMI"
#

#
# This utility program reads the symcheck output of each binary and
# creates additional output for then and an overall report.
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
	$tmp_report_dir
	$misc_check_databases_loaded_ok
	%result_list_hash
	%result_msg
	%warnings_found
);

set_clean_up_exit_routine(\&clean_up_exit);

import_vars_from_environment();

signals('on', \&interrupted);

set_working_dir();

generate_reports();

clean_up();

exit 0;

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
# Called when interrupted by user.
#
sub interrupted
{
	$SIG{$_[0]} = 'DEFAULT';
	signals('off');
	clean_up_exit(1);
}

#
# Does the cleanup and then exit with return code $rc.  Note: The
# utility routine exiter() will call this routine.
#
sub clean_up_exit
{
	my ($rc) = @_;
	$rc = 0 unless ($rc);

	clean_up();
	exit $rc;
}

#
# General cleanup activities are placed here. There may not be an
# immediate exit after this cleanup.
#
sub clean_up
{
	if (defined($tmp_report_dir) && -d $tmp_report_dir) {
		rmtree($tmp_report_dir);
	}
}

#
# Top level routine for generating the additional reports.
#
sub generate_reports
{
	# Make a tmp dir for the reporting work.
	$tmp_report_dir = create_tmp_dir($tmp_dir);

	if (! -d $tmp_report_dir) {
		exiter(nocreatedir($tmp_report_dir, $!));
	}

	pmsg("\n");
	print_line();

	my ($dir, $path_to_object);

	#
	# Loop over each object item in the working_dir.
	#  - $dir will be each one of these object directories.
	#  - $path_to_object will be the corresponding actual path
	#    to the the binary to be profiled.
	# Output will be placed down in $dir, e.g. "$dir/report"
	#

	while (defined($dir = next_dir_name())) {

		# Map object output dir to actual path of the object:
		$path_to_object = dir_name_to_path($dir);

		# Make a report for it:
		report_object($path_to_object, $dir);
	}

	my $type;
	foreach $type (keys(%result_list_hash)) {
		$result_list_hash{$type} =~ s/\|+$//;
	}

	print_report();
	my $tout;
	$tout = gettext(
	    "Additional output regarding private symbols usage and other\n" .
	    "data is in the directory:\n");

	$tout .= "\n   $working_dir\n\n";

	$tout .= gettext(
	    "see the appcert documentation for more information.\n");

	pmsg("%s", $tout);

	clean_up();	# Remove any tmp directories and files.
}

#
# Examines the symcheck output for a given binary object recording and
# reporting and problems found.  Generates additional reports and
# summaries.
#
sub report_object
{
	my ($object, $dir) = @_;

	my (%problems);

	my $problems_file = "$dir/check.problems";

	my $problems_fh = do { local *FH; *FH };
	open($problems_fh, "<$problems_file") ||
	    exiter(nofile($problems_file, $!));

	# We need the "warning" msgs and text from the Misc Checks loaded:
	if (! defined($misc_check_databases_loaded_ok)) {
		$misc_check_databases_loaded_ok = load_misc_check_databases();
	}

	my ($prob, $incomp, $c, $w);
	my $problem_count = 0;
	my $incomplete_count = 0;
	my $line_count = 0;

	while (<$problems_fh>) {
		chomp;
		$prob = 1;
		$incomp = 0;
		$line_count++;

		if (/^DYNAMIC: PRIVATE_SYMBOL_USE\s+(\d*)/) {
			$problems{'private_syms'} += $1;
		} elsif (/^DYNAMIC: UNBOUND_SYMBOL_USE\s+(\d*)/) {
			$problems{'unbound_syms'} += $1;
			$incomp = 1;
		} elsif (/^DYNAMIC: UNRECOGNIZED_SYMBOL_USE\s+(\d*)/) {
			$problems{'unrecognized_syms'} += $1;
			$incomp = 1;
		} elsif (/^DYNAMIC: NO_DYNAMIC_BINDINGS_FOUND\s*(.*)$/) {
			$problems{'no_dynamic_bindings'} .= "$1, ";
			$incomp = 1;
		} elsif (/^STATIC: LINKED_ARCHIVE\s+(.*)$/) {
			$problems{'static_linking'} .= "$1, ";
		} elsif (/^STATIC: COMPLETELY_STATIC/) {
			$problems{'completely_static'}++;
		} elsif (/^MISC: REMOVED_SCOPED_SYMBOLS:\s+(.*)$/) {
			$problems{'scoped_symbols'} .= "$1, ";
		} elsif (/^MISC: WARNING:\s+(INCOMPLETE\S+)/) {
			$problems{'warnings'} .= "$1|";
			$incomp = 1;
		} elsif (/^MISC: WARNING:\s+(.*)$/) {
			$problems{'warnings'} .= "$1|";
		} else {
			$prob = 0;
		}
		$problem_count += $prob;
		$incomplete_count += $incomp;
	}
	close($problems_fh);

	if ($line_count == 0) {
		# No problems at all, leave a comment message:
		open($problems_fh, ">$problems_file") ||
		    exiter(nofile($problems_file, $!));
		print $problems_fh "# NO_PROBLEMS_DETECTED\n";
		close($problems_fh);
	}

	if ($problem_count == 0) {
		$result_list_hash{'passed'} .= "$object|";
		return;
	}

	if ($incomplete_count == $problem_count) {
		$result_list_hash{'incomplete'} .= "$object|";
	} else {
		$result_list_hash{'failed'} .= "$object|";
	}

	my $m;

	if ($m = $problems{'private_syms'}) {
		$result_list_hash{'private_syms'} .= "$object|";
		$result_msg{$object} .= "$m " .
		    gettext("private symbols") . "; ";
	}

	if ($m = $problems{'unbound_syms'}) {
		$result_list_hash{'unbound_syms'} .= "$object|";
		$result_msg{$object} .= "$m " .
		    gettext("unbound symbols") . "; ";

		# add this case to the warnings output at end of report.
		my $tag  = 'unbound symbols';
		$warnings_found{$tag} .= "$object|";

		if (! exists($warnings_desc{$tag})) {
			my $desc = gettext("unbound symbols");
			$warnings_desc{$tag} = $desc;
		}
	}

	if ($m = $problems{'unrecognized_syms'}) {
		$result_list_hash{'unrecognized_syms'} .= "$object|";
		$result_msg{$object} .= "$m " .
		    gettext("unrecognized symbols") . "; ";

		# Add this case to the warnings output at end of report.
		my $tag  = 'unrecognized symbols';
		$warnings_found{$tag} .= "$object|";

		if (! exists($warnings_desc{$tag})) {
			my $desc = gettext("unrecognized symbols");
			$warnings_desc{$tag} = $desc;
		}
	}

	if ($m = $problems{'static_linking'}) {
		$result_list_hash{'static_linking'} .= "$object|";
		$m =~ s/,\s*$//;
		$result_msg{$object} .= sprintf(gettext(
		    "statically linked with %s"), $m) . "; ";

		# Add this case to the warnings output at end of report.
		my $tag  = 'statically linked';
		$warnings_found{$tag} .= "$object|";

		if (! exists($warnings_desc{$tag})) {
			my $desc =
			    gettext("static linking of Solaris libraries");
			$warnings_desc{$tag} = $desc;
		}
	}

	if ($problems{'completely_static'}) {
		$result_list_hash{'completely_static'} .= "$object|";
		$result_msg{$object} .=
		    gettext("completely statically linked") . "; ";

		# Add this case to the warnings output.
		my $tag  = gettext("completely statically linked");
		$warnings_found{$tag} .= "$object|";

		my $desc =
		    gettext("complete static linking of Solaris libraries");
		if (! exists($warnings_desc{$tag})) {
			$warnings_desc{$tag} = $desc;
		}

	} elsif ($m = $problems{'no_dynamic_bindings'}) {
		#
		# Note we skip this error if it is completely static.
		# The app could technically be SUID as well.
		#

		$result_list_hash{'no_dynamic_bindings'} .= "$object|";
		$m =~ s/,\s*$//;
		$m = " : $m";
		$m =~ s/ : NO_SYMBOL_BINDINGS_FOUND//;
		$m =~ s/^ :/:/;
		$result_msg{$object} .=
		    gettext("no bindings found") . "$m; ";
	}

	if ($m = $problems{'scoped_symbols'}) {
		$m =~ s/[,\s]*$//;
		$result_list_hash{'scoped_symbols'} .= "$object|";
		$c = scalar(my @a = split(' ', $m));

		$result_msg{$object} .= "$c " .
		    gettext("demoted (removed) private symbols") . ": $m; ";

		# Add this case to the warnings output.
		my $tag  = 'scoped symbols';
		$warnings_found{$tag} .= "$object|";

		my $desc = gettext(
		    "dependency on demoted (removed) private Solaris symbols");
		if (! exists($warnings_desc{$tag})) {
			$warnings_desc{$tag} = $desc;
		}
	}

	if ($m = $problems{'warnings'}) {
		foreach $w (split(/\|/, $m)) {
			next if ($w =~ /^\s*$/);

			$c = $w;
			if (defined($warnings_desc{$c})) {
				$c = $warnings_desc{$c};
				$c = gettext($c);
			}
			$c =~ s/;//g;
			$result_msg{$object} .= "$c; ";
			$warnings_found{$w} .= "$object|";
		}
	}

	$result_msg{$object} =~ s/;\s+$//;
}

#
# Create the top level roll-up report.
#
sub print_report
{
	# Count the number of passed, failed and total binary objects:
	my(@a);
	my($r_passed, $r_incomp, $r_failed);
	if (exists($result_list_hash{'passed'})) {
		$r_passed = $result_list_hash{'passed'};
	} else {
		$r_passed = '';
	}
	if (exists($result_list_hash{'incomplete'})) {
		$r_incomp = $result_list_hash{'incomplete'};
	} else {
		$r_incomp = '';
	}
	if (exists($result_list_hash{'failed'})) {
		$r_failed = $result_list_hash{'failed'};
	} else {
		$r_failed = '';
	}
	my $n_passed = scalar(@a = split(/\|/, $r_passed));
	my $n_incomp = scalar(@a = split(/\|/, $r_incomp));
	my $n_failed = scalar(@a = split(/\|/, $r_failed));
	my $n_checked = $n_passed + $n_incomp + $n_failed;

	my ($summary_result, $msg, $output, $object);


	if ($n_checked == 0) {
		$summary_result = $text{'Summary_Result_None_Checked'};
	} elsif ($n_failed > 0) {
		$summary_result = $text{'Summary_Result_Some_Failed'};
	} elsif ($n_incomp > 0) {
		$summary_result = $text{'Summary_Result_Some_Incomplete'};
	} else {
		$summary_result = $text{'Summary_Result_All_Passed'};
	}

	# place the info in problem count file:
	my $cnt_file = "$working_dir/ProblemCount";
	my $pcount_fh = do { local *FH; *FH };
	if (! open($pcount_fh, ">$cnt_file")) {
		exiter(nofile($cnt_file, $!));
	}

	print $pcount_fh "$n_failed / $n_checked binary_objects_had_problems\n";
	print $pcount_fh
	    "$n_incomp / $n_checked could_not_be_completely_checked\n";

	print $pcount_fh "NO_PROBLEMS_LIST: $r_passed\n";
	print $pcount_fh "INCOMPLETE_LIST: $r_incomp\n";
	print $pcount_fh "PROBLEMS_LIST: $r_failed\n";
	close($pcount_fh);

	#
	# Set the overall result code.
	# This is used to communicate back to the appcert script to
	# indicate how it should exit(). The string must start with the
	# exit number, after which a message may follow.
	#

	if ($n_checked == 0) {
		overall_result_code("3 => nothing_checked");
	} elsif ($n_failed > 0) {
		overall_result_code("2 => some_problems_detected($n_failed)");
	} elsif ($n_incomp > 0) {
		overall_result_code("1 => " .
		    "some_binaries_incompletely_checked($n_incomp)");
	} else {
		overall_result_code("0 => no_problems_detected");
	}

	my ($sp0, $sp, $sf, $si);	# PASS & FAIL spacing tags.
	$sp0 = '   ';
	if ($batch_report) {
		$sp = 'PASS ';
		$sf = 'FAIL ';
		$si = 'INC  ';
	} else {
		$sp = $sp0;
		$sf = $sp0;
		$si = $sp0;
	}


	$msg = sprintf(gettext("Summary: %s"), $summary_result) . "\n\n";
	my $format = gettext("A total of %d binary objects were examined.");
	$msg .= sprintf($format, $n_checked) . "\n\n\n";
	$output .= $msg;

	my $fmt1 = gettext(
	    "The following (%d of %d) components had no problems detected:");

	if ($n_passed > 0) {
		$output .= sprintf($fmt1, $n_passed, $n_checked);
		$output .= "\n\n";

		foreach $object (split(/\|/, $r_passed)) {
			$output .= "${sp}$object\n";
		}
		$output .= "\n";
	}

	my $fmt2 = gettext(
	    "The following (%d of %d) components had no problems detected,\n" .
	    "   but could not be completely checked:");

	if ($n_incomp > 0) {
		$output .= sprintf($fmt2, $n_incomp, $n_checked);
		$output .= "\n\n";

		foreach $object (split(/\|/, $r_incomp)) {
			$msg = $result_msg{$object};
			$output .= "${si}$object\t($msg)\n";
		}
		$output .= "\n";
	}

	my $fmt3 = gettext(
	    "The following (%d of %d) components have potential " .
	    "stability problems:");
	if ($n_failed > 0) {
		$output .= sprintf($fmt3, $n_failed, $n_checked);
		$output .= "\n\n";

		foreach $object (split(/\|/, $r_failed)) {
			$msg = $result_msg{$object};
			$output .= "${sf}$object\t($msg)\n";
		}
		$output .= "\n";
	}

	$output .= "\n" . get_summary();

	$output .= "\n" . get_warnings();

	my $report_file = "$working_dir/Report";
	my $report_fh = do { local *FH; *FH };
	open($report_fh, ">$report_file") ||
	    exiter(nofile($report_file, $!));

	print $report_fh $output;
	close($report_fh);
	system($cmd_more, $report_file);
}

#
# Collects all of the warnings issued for the binaries that were
# checked.  Returns the warning text that will go into the roll-up
# report.
#
sub get_warnings
{
	my ($w, $c, $output, $count);

	if (! %warnings_found) {
		return '';	# appends null string to output text
	}

	$output = gettext("Summary of various warnings:") . "\n\n";
	my(@a);
	foreach $w (keys(%warnings_found)) {
		$warnings_found{$w} =~ s/\|+$//;
		$count = scalar(@a = split(/\|/, $warnings_found{$w}));
		$c = $w;
		if (defined($warnings_desc{$c})) {
			$c = $warnings_desc{$c};
		}
		$c = gettext($c);
		$output .= " - $c  " . sprintf(gettext(
		    "(%d binaries)\n"), $count);
		$output .= "\n";

	}
	$output .= "\n";

	return $output;
}

#
# Computes the summary information for each binary object that was
# checked.  Returns the text that will go into the roll-up report.
#
sub get_summary
{
	my ($dir, $file);
	my (%lib_private, %libsym_private);
	my (%libapp, %libapp_private);

	my ($bin, $arch, $direct, $lib, $class, $sym);

	while (defined($dir = next_dir_name())) {

		# This is where the public symbol list is:
		$file = "$dir/check.dynamic.public";

		my %app_public;
		my %app_sym_public;
		my %app_private;
		my %app_sym_private;

		if (-s $file) {
			my $publics_fh = do { local *FH; *FH };
			open($publics_fh, "<$file") ||
			    exiter(nofile($file, $!));

			while (<$publics_fh>) {
				next if (/^\s*#/);
				chomp;
				($bin, $arch, $direct, $lib, $class, $sym) =
				    split(/\|/, $_);

				$libapp{"$lib|$bin"}++;

				$app_public{$lib}++;
				$app_sym_public{"$lib|$sym"}++;
			}
			close($publics_fh);
		}

		# This is where the private symbol list is:
		$file = "$dir/check.dynamic.private";

		if (-s $file) {
			my $privates_fh = do { local *FH; *FH };
			open($privates_fh, "<$file") ||
			    exiter(nofile($file, $!));

			while (<$privates_fh>) {
				next if (/^\s*#/);
				chomp;
				($bin, $arch, $direct, $lib, $class, $sym) =
				    split(/\|/, $_);

				$lib_private{$lib}++;
				$libsym_private{"$lib|$sym"}++;
				$libapp_private{"$lib|$bin"}++;
				$libapp{"$lib|$bin"}++;

				$app_private{$lib}++;
				$app_sym_private{"$lib|$sym"}++;
			}
			close($privates_fh);
		}

		write_app_summary($dir, \%app_public, \%app_sym_public,
		    \%app_private, \%app_sym_private);
	}

	my ($app_total, $app_private_total);
	my ($key, $lib2, $app2, $sym2);
	my $val;
	my $text;

	foreach $lib (sort(keys(%lib_private))) {

		$app_total = 0;
		foreach $key (keys(%libapp)) {
			($lib2, $app2) = split(/\|/, $key);
			$app_total++ if ($lib eq $lib2);
		}

		$app_private_total = 0;
		foreach $key (keys(%libapp_private)) {
			($lib2, $app2) = split(/\|/, $key);
			$app_private_total++ if ($lib eq $lib2);
		}

		my @list;
		while (($key, $val) =  each(%libsym_private)) {
			($lib2, $sym2) = split(/\|/, $key);
			next unless ($lib eq $lib2);
			push(@list, "$sym2 $val");

		}

		$text .= private_format($lib, $app_total,
		    $app_private_total, @list);
	}

	if (! defined($text)) {
		return '';	# appends null string to output report.
	}
	return $text;
}

#
# Given the symbols and counts of private symbols used by all binaries
# that were checked, returns a pretty-printed format table of the
# symbols. This text goes into the roll-up report and the summary.dynamic
# file.
#
sub private_format
{
	my ($lib, $tot, $priv, @list) = @_;

	my (@sorted) = sort_on_count(@list);
	my $formatted = list_format('  ', @sorted);

	my $text;
	my $libbase = basename($lib);

	$text = sprintf(gettext(
	    "Summary of Private symbol use in %s\n"), $lib);
	my $fmt =
	    gettext("%d binaries used %s, %d of these used private symbols");
	$text .= sprintf($fmt, $tot, $libbase, $priv);
	$text .= "\n\n$formatted\n";

	return $text;
}

#
# Given the public/private symbol and library usage information for a
# binary object, creates an output file with this information formatted
# in tables.
#
sub write_app_summary
{
	my ($dir, $public, $sym_public, $private, $sym_private) = @_;

	my $outfile = "$dir/summary.dynamic";

	my $summary_fh = do { local *FH; *FH };
	open($summary_fh, ">$outfile") ||
	    exiter(nofile($outfile, $!));

	my $path_to_object = dir_name_to_path($dir);


	my ($tmp1, $tmp2, $tmp3);

	$tmp1 = gettext("ABI SYMBOL USAGE SUMMARY REPORT");
	$tmp2 = '*' x length($tmp1);

	print $summary_fh "$tmp2\n$tmp1\n$tmp2\n\n";

	print $summary_fh "  ", sprintf(gettext(
	    "Binary Object: %s\n"), $path_to_object);

	my $uname_a = `$cmd_uname -a`;
	print $summary_fh "  ", sprintf(gettext("System: %s\n"), $uname_a);

	$tmp1 = gettext("References to shared objects in the Solaris ABI");
	$tmp2 = '*' x length($tmp1);

	print $summary_fh "$tmp2\n$tmp1\n$tmp2\n\n";


	my (%libs, $lib, $maxlen, $len);
	$maxlen = 0;

	foreach $lib (keys(%$public), keys(%$private)) {
		$len = length($lib);
		$maxlen = $len if ($len > $maxlen);
		$libs{$lib} = 1;
	}

	if (! %libs) {
		my $str = gettext(
		"  NONE FOUND. Possible explanations:\n" .
		"    - the dynamic profiling failed, see ldd(1), ld.so.1(1)\n" .
		"    - the object is SUID or SGID\n" .
		"    - the object is completely statically linked.\n"
		);
		print $summary_fh $str, "\n";
		close($summary_fh);
		return;
	}

	foreach $lib (sort(keys(%libs))) {
		print $summary_fh "  $lib\n";
	}
	print $summary_fh "\n";

	my ($len1, $len2, $len3);
	my $heading = '  ' . gettext("Library");
	$heading .= ' ' x ($maxlen + 6 - length($heading));
	$len1 = length($heading) - 2;
	my $public_str = gettext("Public");
	$len2 = length($public_str);
	my $private_str = gettext("Private");
	$len3 = length("  $private_str");
	$heading .= "$public_str  $private_str";
	$tmp3 = $heading;
	$tmp3 =~ s/\S/-/g;

	$tmp1 = gettext("Symbol usage statistics (summary by shared object)");
	$tmp2 = '*' x length($tmp1);

	print $summary_fh "$tmp2\n$tmp1\n$tmp2\n\n";
	print $summary_fh "$heading\n";
	print $summary_fh "$tmp3\n";

	my ($pub, $priv, $str);
	foreach $lib (sort(keys(%libs))) {
		$pub  = $public->{$lib};
		$priv = $private->{$lib};

		$pub = 0 if (! defined($pub));
		$priv = 0 if (! defined($priv));

		$str = '  ';
		$str .= sprintf("%-${len1}s", $lib);
		$str .= sprintf("%${len2}s", $pub);
		$str .= sprintf("%${len3}s", $priv);
		print $summary_fh $str, "\n";
	}
	print $summary_fh "\n";

	$tmp1 = gettext("Symbol usage (detailed inventory by shared object)");
	$tmp2 = '*' x length($tmp1);

	print $summary_fh "$tmp2\n$tmp1\n$tmp2\n\n";

	my (@pub, @priv, $lib2, $sym2, $text, $key);
	foreach $lib (sort(keys(%libs))) {
		@pub  = ();
		@priv = ();

		foreach $key (keys(%$sym_public)) {
			next unless (index($key, $lib) == 0);
			($lib2, $sym2) = split(/\|/, $key, 2);
			next unless ($lib2 eq $lib);
			push(@pub, $sym2);
		}
		foreach $key (keys(%$sym_private)) {
			next unless (index($key, $lib) == 0);
			($lib2, $sym2) = split(/\|/, $key, 2);
			next unless ($lib2 eq $lib);
			push(@priv, $sym2);
		}

		next if (! @pub && ! @priv);

		my $fmt = gettext("Symbols in %s Directly Referenced");
		$text = sprintf($fmt, $lib);

		if (@pub) {
			$lib2 = scalar(@pub);
			$text .= sprintf(gettext(
			    "  %d public symbols are used:\n"), $lib2);
			$text .= list_format('    ', sort(@pub));
			$text .= "\n";
		}
		if (@priv) {
			$lib2 = scalar(@priv);
			$text .= sprintf(gettext(
			    "  %d private symbols are used:\n"), $lib2);
			$text .= list_format('    ', sort(@priv));
			$text .= "\n";
		}

		print $summary_fh $text;
	}
	close($summary_fh);
}
