#!/usr/bin/perl -w
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
# Copyright 2015 Toomas Soome <tsoome@me.com>
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# jstyle - check for some common stylistic errors.
#

require 5.006;
use Getopt::Std;
use strict;

my $usage =
"usage: jstyle [-c] [-h] [-p] [-t] [-v] [-C] file ...
	-c	check continuation line indenting
	-h	perform heuristic checks that are sometimes wrong
	-p	perform some of the more picky checks
	-t	insist on indenting by tabs
	-v	verbose
	-C	don't check anything in header block comments
";

my %opts;

# Keep -s, as it's been around for a while.  It just doesn't do anything
# anymore.
if (!getopts("chpstvC", \%opts)) {
	print $usage;
	exit 2;
}

my $check_continuation = $opts{'c'};
my $heuristic = $opts{'h'};
my $picky = $opts{'p'};
my $tabs = $opts{'t'};
my $verbose = $opts{'v'};
my $ignore_hdr_comment = $opts{'C'};

my ($filename, $line, $prev);
my $err_stat = 0;		# Exit status

my $fmt;

if ($verbose) {
	$fmt = "%s: %d: %s\n%s\n";
} else {
	$fmt = "%s: %d: %s\n";
}

# Note, following must be in single quotes so that \s and \w work right.
my $typename = '(int|char|boolean|byte|short|long|float|double)';
my $keywords = '(for|if|while|switch|return|catch|synchronized|throw|assert)';
# See perlre(1) for the meaning of (??{ ... })
my $annotations = ""; $annotations = qr/@\w+\((?:(?>[^()]+)|(??{ $annotations }))*\)/;
my $generics = ""; $generics = qr/<(([\s\w,.?[\]]| & )+|(??{ $generics }))*>/;
my $relationalops = qr/>=|<=|<|>|!=|==/;
my $shiftops = qr/<<<|>>>|<<|>>/;
my $shiftassignmentops = qr/[<>]{2,3}=/;
my $assignmentops = qr/[-+\/*|&^%]?=/;
# These need to be in decreasing order of length
my $allops = qr/$shiftassignmentops|$shiftops|$relationalops|$assignmentops/;

if ($#ARGV >= 0) {
	foreach my $arg (@ARGV) {
		if (!open(STDIN, $arg)) {
			printf "%s: can not open\n", $arg;
		} else {
			&jstyle($arg);
			close STDIN;
		}
	}
} else {
	&jstyle("<stdin>");
}
exit $err_stat;

sub err($) {
	if ($verbose) {
		printf $fmt, $filename, $., $_[0], $line;
	} else {
		printf $fmt, $filename, $., $_[0];
	}
	$err_stat = 1;
}

sub jstyle($) {

my $in_comment = 0;
my $in_header_comment = 0;
my $in_continuation = 0;
my $in_class = 0;
my $in_declaration = 0;
my $nextok = 0;
my $nocheck = 0;
my $expect_continuation = 0;
my $continuation_indent;
my $okmsg;
my $comment_prefix;
my $comment_done;
my $cpp_comment;

$filename = $_[0];

line: while (<STDIN>) {
	s/\r?\n$//;	# strip return and newline

	# save the original line, then remove all text from within
	# double or single quotes, we do not want to check such text.

	$line = $_;
	s/"[^"]*"/\"\"/g;
	s/'.'/''/g;

	# an /* END JSTYLED */ comment ends a no-check block.
	if ($nocheck) {
		if (/\/\* *END *JSTYLED *\*\//) {
			$nocheck = 0;
		} else {
			next line;
		}
	}

	# a /*JSTYLED*/ comment indicates that the next line is ok.
	if ($nextok) {
		if ($okmsg) {
			err($okmsg);
		}
		$nextok = 0;
		$okmsg = 0;
		if (/\/\* *JSTYLED.*\*\//) {
			/^.*\/\* *JSTYLED *(.*) *\*\/.*$/;
			$okmsg = $1;
			$nextok = 1;
		}
		$prev = $line;
		next line;
	}

	# remember whether we expect to be inside a continuation line.
	$in_continuation = $expect_continuation;

	# check for proper continuation line.  blank lines
	# in the middle of the
	# continuation do not count.
	# XXX - only check within functions.
	if ($check_continuation && $expect_continuation && $in_class &&
	    !/^\s*$/) {
		# continuation line must start with whitespace of
		# previous line, plus either 4 spaces or a tab, but
		# do not check lines that start with a string constant
		# since they are often shifted to the left to make them
		# fit on the line.
		if (!/^$continuation_indent    \S/ &&
		    !/^$continuation_indent\t\S/ && !/^\s*"/) {
			err("continuation line improperly indented");
		}
		$expect_continuation = 0;
	}

	# a /* BEGIN JSTYLED */ comment starts a no-check block.
	if (/\/\* *BEGIN *JSTYLED *\*\//) {
		$nocheck = 1;
	}

	# a /*JSTYLED*/ comment indicates that the next line is ok.
	if (/\/\* *JSTYLED.*\*\//) {
		/^.*\/\* *JSTYLED *(.*) *\*\/.*$/;
		$okmsg = $1;
		$nextok = 1;
	}
	if (/\/\/ *JSTYLED/) {
		/^.*\/\/ *JSTYLED *(.*)$/;
		$okmsg = $1;
		$nextok = 1;
	}

	# is this the beginning or ending of a class?
	if (/^(public\s+)*\w(class|interface)\s/) {
		$in_class = 1;
		$in_declaration = 1;
		$prev = $line;
		next line;
	}
	if (/^}\s*(\/\*.*\*\/\s*)*$/) {
		$in_class = 0;
		$prev = $line;
		next line;
	}

	if ($comment_done) {
		$in_comment = 0;
		$in_header_comment = 0;
		$comment_done = 0;
	}
	# does this looks like the start of a block comment?
	if (/^\s*\/\*/ && !/^\s*\/\*.*\*\//) {
		if (/^\s*\/\*./ && !/^\s*\/\*\*$/) {
			err("improper first line of block comment");
		}
		if (!/^(\t|    )*\/\*/) {
			err("block comment not indented properly");
		}
		$in_comment = 1;
		/^(\s*)\//;
		$comment_prefix = $1;
		if ($comment_prefix eq "") {
			$in_header_comment = 1;
		}
		$prev = $line;
		next line;
	}
	# are we still in the block comment?
	if ($in_comment) {
		if (/^$comment_prefix \*\/$/) {
			$comment_done = 1;
		} elsif (/\*\//) {
			$comment_done = 1;
			err("improper block comment close")
			    unless ($ignore_hdr_comment && $in_header_comment);
		} elsif (!/^$comment_prefix \*[ \t]/ &&
		    !/^$comment_prefix \*$/) {
			err("improper block comment")
			    unless ($ignore_hdr_comment && $in_header_comment);
		}
	}

	if ($in_header_comment && $ignore_hdr_comment) {
		$prev = $line;
		next line;
	}

	# check for errors that might occur in comments and in code.

	# check length of line.
	# first, a quick check to see if there is any chance of being too long.
	if ($line =~ tr/\t/\t/ * 7 + length($line) > 80) {
		# yes, there is a chance.
		# replace tabs with spaces and check again.
		my $eline = $line;
		1 while $eline =~
		    s/\t+/' ' x (length($&) * 8 - length($`) % 8)/e;
		if (length($eline) > 80) {
			err("line > 80 characters");
		}
	}

	# Allow spaces to be used to draw pictures in header comments, but
	# disallow blocks of spaces almost everywhere else.  In particular,
	# five spaces are also allowed at the end of a line's indentation
	# if the rest of the line belongs to a block comment.
	if (!$in_header_comment &&
	    /[^ ]     / &&
	    !(/^\t*     \*/ && !/^\t*     \*.*     /)) {
		err("spaces instead of tabs");
	}
	if ($tabs && /^ / && !/^ \*[ \t\/]/ && !/^ \*$/ &&
	    (!/^    \w/ || $in_class != 0)) {
		err("indent by spaces instead of tabs");
	}
	if (!$in_comment && (/^(\t    )* {1,3}\S/ || /^(\t    )* {5,7}\S/) &&
	    !(/^\s*[-+|&\/?:=]/ || ($prev =~ /,\s*$/))) {
		err("indent not a multiple of 4");
	}
	if (/\s$/) {
		err("space or tab at end of line");
	}
if (0) {
	if (/^[\t]+ [^ \t\*]/ || /^[\t]+  \S/ || /^[\t]+   \S/) {
		err("continuation line not indented by 4 spaces");
	}
}
	if (/\/\//) {
		$cpp_comment = 1;
	}
	if (!$cpp_comment && /[^ \t(\/]\/\*/ && !/\w\(\/\*.*\*\/\);/) {
		err("comment preceded by non-blank");
	}
	if (/\t +\t/) {
		err("spaces between tabs");
	}
	if (/ \t+ /) {
		err("tabs between spaces");
	}

	if ($in_comment) {	# still in comment
		$prev = $line;
		next line;
	}

	if (!$cpp_comment && ((/\/\*\S/ && !/\/\*\*/) || /\/\*\*\S/)) {
		err("missing blank after open comment");
	}
	if (!$cpp_comment && /\S\*\//) {
		err("missing blank before close comment");
	}
	# check for unterminated single line comments.
	if (/\S.*\/\*/ && !/\S.*\/\*.*\*\//) {
		err("unterminated single line comment");
	}

	# delete any comments and check everything else.  Be sure to leave
	# //-style comments intact, and if there are multiple comments on a
	# line, preserve whatever's in between.
	s/(?<!\/)\/\*.*?\*\///g;
	# Check for //-style comments only outside of block comments
	if (m{(//(?!$))} && substr($_, $+[0], 1) !~ /[ \t]/) {
		err("missing blank after start comment");
	}
	s/\/\/.*$//;		# C++ comments
	$cpp_comment = 0;

	# delete any trailing whitespace; we have already checked for that.
	s/\s*$//;

	# We don't style (yet) what's inside annotations, so just delete them.
	s/$annotations//;

	# following checks do not apply to text in comments.

	# if it looks like an operator at the end of the line, and it is
	# not really the end of a comment (...*/), and it is not really
	# a label (done:), and it is not a case label (case FOO:),
	# or we are not in a function definition (ANSI C style) and the
	# operator is a "," (to avoid hitting "int\nfoo(\n\tint i,\n\tint j)"),
	# or we are in a function and the operator is a
	# "*" (to avoid hitting on "char*\nfunc()").
	if ((/[-+|&\/?:=]$/ && !/\*\/$/ && !/^\s*\w*:$/ &&
	    !/^\s\s*case\s\s*\w*:$/) ||
	    /,$/ ||
	    ($in_class && /\*$/)) {
		$expect_continuation = 1;
		if (!$in_continuation) {
			/^(\s*)\S/;
			$continuation_indent = $1;
		}
	}
	while (/($allops)/g) {
		my $z = substr($_, $-[1] - 1);
		if ($z !~ /\s\Q$1\E(?:\s|$)/) {
			my $m = $1;
			my $shift;
			# @+ is available only in the currently active
			# dynamic scope.  Assign it to a new variable
			# to pass it into the if block.
			if ($z =~ /($generics)/ &&
			    ($shift = $+[1])) {
				pos $_ += $shift;
				next;
			}

			# These need to be in decreasing order of length
			# (violable as long as there's no ambiguity)
			my $nospace = "missing space around";
			if ($m =~ $shiftassignmentops) {
				err("$nospace assignment operator");
			} elsif ($m =~ $shiftops) {
				err("$nospace shift operator");
			} elsif ($m =~ $relationalops) {
				err("$nospace relational operator");
			} elsif ($m =~ $assignmentops) {
				err("$nospace assignment operator");
			}
		}
	}
	if (/[,;]\S/ && !/\bfor \(;;\)/) {
		err("comma or semicolon followed by non-blank");
	}
	# allow "for" statements to have empty "while" clauses
	if (/\s[,;]/ && !/^[\t]+;$/ && !/^\s*for \([^;]*; ;[^;]*\)/) {
		err("comma or semicolon preceded by blank");
	}
if (0) {
	if (/^\s*(&&|\|\|)/) {
		err("improper boolean continuation");
	}
}
	if ($picky && /\S   *(&&|\|\|)/ || /(&&|\|\|)   *\S/) {
		err("more than one space around boolean operator");
	}
	if (/\b$keywords\(/) {
		err("missing space between keyword and paren");
	}
	if (/(\b$keywords\b.*){2,}/ && !/\bcase\b.*/) { # "case" excepted
		err("more than one keyword on line");
	}
	if (/\b$keywords\s\s+\(/ &&
	    !/^#if\s+\(/) {
		err("extra space between keyword and paren");
	}
	# try to detect "func (x)" but not "if (x)" or
	# "int (*func)();"
	if (/\w\s\(/) {
		my $save = $_;
		# strip off all keywords on the line
		s/\b$keywords\s\(/XXX(/g;
		#s/\b($typename|void)\s+\(+/XXX(/og;
		if (/\w\s\(/) {
			err("extra space between function name and left paren");
		}
		$_ = $save;
	}
	if (/\(\s/) {
		err("whitespace after left paren");
	}
	# allow "for" statements to have empty "continue" clauses
	if (/\s\)/ && !/^\s*for \([^;]*;[^;]*; \)/) {
		err("whitespace before right paren");
	}
	if (/^\s*\(void\)[^ ]/) {
		err("missing space after (void) cast");
	}
	if (/\S\{/ && !/\{\{/) {
		err("missing space before left brace");
	}
	if ($in_class && /^\s+{/ && ($prev =~ /\)\s*$/)) {
		err("left brace starting a line");
	}
	if (/}(else|while)/) {
		err("missing space after right brace");
	}
	if (/}\s\s+(else|while)/) {
		err("extra space after right brace");
	}
	if (/\b$typename\*/o) {
		err("missing space between type name and *");
	}
	if ($heuristic) {
		# cannot check this everywhere due to "struct {\n...\n} foo;"
		if ($in_class && !$in_declaration &&
		    /}./ && !/}\s+=/ && !/{.*}[;,]$/ && !/}(\s|)*$/ &&
		    !/} (else|while)/ && !/}}/) {
			err("possible bad text following right brace");
		}
		# cannot check this because sub-blocks in
		# the middle of code are ok
		if ($in_class && /^\s+{/) {
			err("possible left brace starting a line");
		}
	}
	if (/^\s*else\W/) {
		if ($prev =~ /^\s*}$/) {
			my $str = "else and right brace should be on same line";
			printf $fmt, $filename, $., $str, $prev;
			if ($verbose) {
				printf "%s\n", $line;
			}
		}
	}
	$prev = $line;
}

if ($picky && $prev eq "") {
	err("last line in file is blank");
}

}
