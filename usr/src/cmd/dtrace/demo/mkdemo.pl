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

require 5.005;

use strict;
use warnings;
use Time::localtime;
use File::Basename;

our ($cmd, $chapfile, $htmlfile, $dtrace_url, %chaps);

$cmd = "mkdemo";
$chapfile = "chapters";
$htmlfile = "index.html";
$dtrace_url = "http://www.sun.com/bigadmin/content/dtrace";

sub chaps_read {
	my $fatal;
	my %hash;

	open(CHAPS, "$chapfile");

	while (<CHAPS>) {
		my $field;
		my $value;

		chop;

		if (/^#/) {
			next;
		}

		if (!/:/) {
			if (exists $hash{'name'}) {
				if (exists $chaps{$hash{'name'}}) {
					print "$cmd: chapter $hash{'name'} ";
					print "has two entries.\n";
					$fatal = 1;
				}

				$chaps{$hash{'name'}} = { %hash };
				%hash = ();
				next;
			}

			%hash = ();
			next;
		}

		($field, $value) = split /:\s*/, $_, 2;

		if ($field eq "descr") {
			$value .= " ";
		}

		$hash{$field} .= $value;
	}

	if ($fatal) {
		print "$cmd: fatal errors; cannot proceed.\n";
		exit;
	}

	close (CHAPS);
}	

sub chaps_ascending {
	$chaps{$a}{index} <=> $chaps{$b}{index};
}

sub demo_process {
	my $chap = $_[0];
	my $demo = $_[1];
	my $year = localtime->year() + 1900;

	open DEMO, "<$chap/$demo" or die "Can't open demo $chap/$demo";
	open OUT, ">$demo" or die "Can't open $demo";

	while (<DEMO>) {
		print OUT $_;

		if (/Use is subject to license terms/) {
			print OUT <<EOF;
 *
 * This D script is used as an example in the Solaris Dynamic Tracing Guide
 * wiki in the \"$chaps{$chap}{title}\" Chapter.
 *
 * The full text of the this chapter may be found here:
 *
 *   $chaps{$chap}{url}
 *
 * On machines that have DTrace installed, this script is available as
 * $demo in /usr/demo/dtrace, a directory that contains all D scripts
 * used in the Solaris Dynamic Tracing Guide.  A table of the scripts and their
 * corresponding chapters may be found here:
 *
 *   file:///usr/demo/dtrace/index.html
EOF
		}
	}

	close (DEMO);
	close (OUT);
}

sub demo_find {
	my $demo = $_[0];
	my $chap;

	foreach $chap (keys %chaps) {
		if (!stat("$chap/$demo")) {
			next;
		}

		demo_process($chap, $demo);
		return;
	}

	die "Couldn't find $demo in any chapter";
}

sub chaps_process {
	my $outfile = $_[0];
	my $chap;

	open HTML, ">$outfile" or die "Can't open $outfile.";

	print HTML "<html>\n<head>\n";
	print HTML "<title>Example DTrace Scripts</title>\n";
	print HTML "</head>\n<body bgcolor=\"#ffffff\">\n";

	print HTML "<table width=\"85%\" border=0 align=\"center\"><tr><td>";
	print HTML "<h2>DTrace Examples</h2>\n";

	print HTML "<hr><p>\n";
	print HTML "Here are the <a href=\"$dtrace_url\">DTrace</a> scripts\n";
	print HTML "that are used as examples in the\n";
	print HTML "<a href=\"$chaps{book}{url}\">$chaps{book}{title}</a>. ";
	print HTML "For more information on any one script, follow the link\n";
	print HTML "to its corresponding chapter.\n";
	print HTML "<p>\n<hr><p>\n";

	print HTML "<left><table width=\"85%\" border=1 cellpadding=4 ";
	print HTML "cellspacing=0 align=\"center\" bgcolor=\"#ffffff\">\n";
	print HTML "<tr bgcolor=\"#5882a1\"><td width=\"50%\">";
	print HTML "<font color=\"#ffffff\"><b>Chapter</b></td></font>\n";
	print HTML "<td><font color=\"#ffffff\"><b>Script</b></td>\n";
	print HTML "</font></tr>\n";

	foreach $chap (sort chaps_ascending (keys %chaps)) {
		my @demos;
		my $demo;

		#
		# Open the directory associated with the chapter.
		#
		if ($chap =~ /^book$/) {
			next;
		}

		opendir(DEMOS, $chap) || die("Cannot open directory $chap");
		@demos = readdir(DEMOS);
		closedir(DEMOS);

		print HTML "<tr>\n";
		print HTML "<td align=left>";
		print HTML "<a href=\"$chaps{$chap}{url}\">";
		print HTML "$chaps{$chap}{title}</a></td>\n";

		print HTML "<td><table border=0>\n";

		foreach $demo (sort(@demos)) {
			if ($demo !~ /^[a-z].*\.d$/) {
				next;
			}

			print HTML "<tr><td><a href=\"$demo\">$demo</a>";
			print HTML "</td></tr>\n";

			demo_process($chap, $demo);
		}

		print HTML "</table></td></tr>\n";
	}

	print HTML "</table>\n</td>\n<p>\n\n";
	print HTML "</td></tr>\n";
	print HTML "<tr><td><hr><small>Copyright ";
	print HTML localtime->year() + 1900;
	print HTML " Sun Microsystems</small>\n";
	print HTML "</table>\n";
	print HTML "</body>\n</html>\n";
	close HTML;
}

chaps_read();

if (basename($ARGV[0]) ne "$htmlfile") {
	demo_find(basename($ARGV[0]));
} else {
	chaps_process($htmlfile);
}
