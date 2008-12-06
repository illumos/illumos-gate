#!/usr/perl5/bin/perl
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

# bsmrecord - display one or more audit records

require 5.8.4;		
use strict;
use warnings;

our (%opt, $parse, $callFilter, $debug,
    %attr, %event, %class, %skipClass, %token, %noteAlias,
    $title, $note, $name, $col1, $col2, $col3, $skip);

use Getopt::Std;
use locale;
use POSIX qw(locale_h);
use Sun::Solaris::Utils qw(gettext textdomain);
use Sun::Solaris::BSM::_BSMparse;

setlocale(LC_ALL, "");
textdomain(TEXT_DOMAIN);

if (!getopts('adhe:c:i:p:s:', \%opt) || @ARGV) {
	my $errString =
	    gettext("$0 takes no arguments other than switches.\n");
	print STDERR $errString if (@ARGV);
	usage();
	exit (1);
}

unless ($opt{a} || $opt{c} || $opt{e} || $opt{h} || $opt{i} ||
	$opt{p} || $opt{s}) {
	usage();
	exit (1);
}

my %options;
$options{'classFilter'} = $opt{c};   # filter on this class
$debug			= $opt{d};   # debug mode on
$options{'eventFilter'} = $opt{e};   # filter on this event
my $html		= $opt{h};   # output in html format
$options{'idFilter'}	= $opt{i};   # filter on this id
$callFilter		= $opt{p};   # filter on this program name
$callFilter		= $opt{s} if ($opt{s}); # filter on this system call

if (defined($callFilter)) {
	$callFilter = qr/\b$callFilter\b/;
} else {
	$callFilter = qr//;
}
$parse = new Sun::Solaris::BSM::_BSMparse($debug, \%options);

my ($attr, $token, $skipClass, $noteAlias) = $parse->readAttr();
%attr  = %$attr;
%token = %$token;
%noteAlias = %$noteAlias;
%skipClass = %$skipClass;

%class = %{$parse->readClass()};
%event = %{$parse->readEvent()};

# the calls to readControl and readUser are for debug; they are not
# needed for generation of record formats.  'ignore' means if there
# is no permission to read the file, don't die, just soldier on.

# $error is L10N'd by $parse

if ($debug) {
	my ($cnt, $error);

	# verify audit_control content
	($cnt, $error) = $parse->readControl('ignore');
	print STDERR $error if ($cnt);

	# verify audit_user content
	($cnt, $error) = $parse->readUser('ignore');
	print STDERR $error if ($cnt);

	# check audit_event, audit_display_attr
	($cnt, $error) = $parse->ckAttrEvent();
	print STDERR $error if ($cnt);
}

# check for invalid class to -c option if supplied
if (defined $options{'classFilter'}) {
	my $invalidClass = gettext('Invalid class %s supplied.');
	my $isInvalidClass = 0;
	foreach (split(/\s*,\s*/, $options{'classFilter'})) {
		unless (exists $class{$_}) {
			printf STDERR "$invalidClass\n", $_;
			$isInvalidClass = 1;
		}
	}
	exit (1) if $isInvalidClass;
}

if ($html) {
	writeHTML();
} else {
	writeASCII();
}

exit (0);

# writeASCII -- collect what's been read from various sources and
# output the formatted audit records

sub writeASCII {
	my $label;

	my $errString;

	foreach $label (sort(keys(%event))) {
		my $description;
		my @case;

		my ($id, $class, $eventDescription) = @{$event{$label}};

		our ($title, $note, $name, $col1, $col2, $col3);

		my ($skipThisClass, $mask) = classToMask($class, $label);

		next if ($skipThisClass);

		$mask = sprintf("0x%08X", $mask);

		($name, $description, $title, $skip, @case) =
			getAttributes($label, $eventDescription);

		next if ($name eq 'undefined');

		next unless $description =~ $callFilter;

		$~ = 'nameLine';
		write;

		$note = $skip;
		$~ = 'wrapped1';
		while ($note) {
			write;
		}
		next if ($skip);

		$~ = 'threeColumns';
		($col1, $col2, $col3) = getCallInfo($id, $name, $description);
		my @col1 = split(/\s*;\s*/, $col1);
		my @col2 = split(/\s*;\s*/, $col2);
		my @col3 = split(/\s*;\s*/, $col3);
		my $rows = $#col1;
		$rows = $#col2 if ($#col2 > $rows);
		$rows = $#col3 if ($#col3 > $rows);
		for (my $i = 0; $i <= $rows; $i++) {
			$col1 = defined ($col1[$i]) ? $col1[$i] : '';
			$col2 = defined ($col2[$i]) ? $col2[$i] : '';
			$col3 = defined ($col3[$i]) ? 'See ' . $col3[$i] : '';
			write;
		}
		$col1 = 'event ID';
		$col2 = $id;
		$col3 = $label;
		write;

		$col1 = 'class';
		$col2 = $class;
		$col3 = "($mask)";
		write;

		my $haveFormat = 0;
		my $caseElement;

		foreach $caseElement (@case) {
			# $note1 is the "case" description
			# $note2 is a "note"
			my ($note1, $format, $comment, $note2) = @$caseElement;

			$note = $note1;
			$~ = 'wrapped1';
			while ($note) {
				write;
			}
			unless (defined($format)) {
				$errString = gettext(
				    "missing format field: %s");
				printf STDERR ("$errString\n", $label);
				next;
			}
			unless ($format eq 'none') {
				$haveFormat = 1;

				my $list = getFormatList($format, $id);

				my @format  = split(/\s*:\s*/, $list);
				my @comment = split(/\s*:\s*/, $comment);

				my $item;

				foreach $item (@format) {
					$~ = 'twoColumns';
					($col1, $col2) =
					    getFormatLine($item, $label,
					    @comment);
					write;
					$~ = "col2Wrapped";
					while ($col2) {
						write;
					}
				}
			}
			$note2 = $noteAlias{$note2} if ($noteAlias{$note2});
			if ($note2) {
				$note = $note2;
				$~ = 'space';
				write;
				$~ = 'wrapped1';
				while ($note) {
					write;
				}
			}
		}
		unless ($haveFormat) {
			$~ = 'wrapped1';
			$note = gettext('No format information available');
			write;
		}
	}
}

# writeHTML -- collect what's been read from various sources
# and output the formatted audit records
#

sub writeHTML {
	my $label;

	my $description;
	my @case;

	my $docTitle = gettext("Audit Record Formats");

	print qq{
<!doctype html PUBLIC "-//IETF//DTD HTML//EN">
<html>
<head>
  <title>$docTitle</title>
  <META http-equiv="Content-Style-Type" content="text/css">
</head>

<body TEXT="#000000" BGCOLOR="#F0F0F0">
	};

	my $tableRows = 0;	# work around Netscape large table bug
	startTable();		# by generating multiple tables

	foreach $label (sort(keys(%event))) {
		my ($id, $class, $eventDescription) = @{$event{$label}};

		our ($title, $name, $note, $col1, $col2, $col3);

		my ($skipThisClass, $mask) = classToMask($class, $label);

		next if ($skipThisClass);

		$mask = sprintf("0x%08X", $mask);

		my $description;

		($name, $description, $title, $skip, @case) =
			getAttributes($label, $eventDescription);

		next if ($name eq 'undefined');

		next unless $description =~ $callFilter;

		$tableRows++;
		if ($tableRows > 50) {
			endTable();
			startTable();
			$tableRows = 0;
		}

		my ($callType, $callName);
		($callType, $callName, $description) =
			getCallInfo($id, $name, $description);
		$description =~ s/\s*;\s*/<br>/g;

		my $titleName = $title;
		if ($callName) {
			$titleName = $callName;
		}
		$titleName =~ s/\s*;\s*/<br>/g;
		$titleName = '&nbsp;' if ($titleName eq $title);

		print qq{
  <tr bgcolor="#C0C0C0">
    <td>$label</td>
    <td>$id</td>
    <td>$class</td>
    <td>$mask</td>
  </tr>
  <tr>
    <td colspan=2>$titleName</td>
    <td colspan=2>$description</td>
  </tr>
  <tr>
    <td colspan=4>
      <pre>
};

		$note = $skip;
		$~ = 'wrapped2';
		while ($note) {
			write;
		}
		next if ($skip);

		my $haveFormat = 0;
		my $caseElement;

		foreach $caseElement (@case) {
			my ($note1, $format, $comment, $note2) = @$caseElement;

			$note = $note1;
			$~ = 'wrapped2';
			while ($note) {
				write;
			}
			unless (defined($format)) {
				my $errString = gettext(
				    "Missing format field: %s\n");
				printf STDERR ($errString, $label);
				next;
			}
			unless ($format eq 'none') {
				$haveFormat = 1;

				my $list = getFormatList($format, $id);

				my @format  = split(/\s*:\s*/, $list);
				my @comment = split(/\s*:\s*/, $comment);
				my $item;

				$~ = 'twoColumns';
				foreach $item (@format) {
					($col1, $col2) =
					    getFormatLine($item, $label,
					    @comment);
					write;
				}
			}
			if ($note2) {
				$note2 = $noteAlias{$note2} if ($noteAlias{$note2});
				$note = $note2;
				$~ = 'space';
				write;
				$~ = 'wrapped2';
				while ($note) {
					write;
				}
			}
		}
		unless ($haveFormat) {
			$~ = 'wrapped2';
			$note = 'No format information available';
			write;
		}
		print q{
      </pre>
    </td/>
  </tr>
		};
	}
	endTable();
}

sub startTable {

	print q{
<table border=1>
  <tr bgcolor="#C0C0C0">
    <th>Event Name</th>
    <th>Event ID</th>
    <th>Event Class</th>
    <th>Mask</th>
  </tr>
  <tr>
    <th colspan=2>Call Name</th>
    <th colspan=2>Reference</th>
  <tr>
  <tr>
    <th colspan=4>Format</th>
  </tr>
	};
}

sub endTable {

	print q{
</table>
</body>
</html>
	};
}

# classToMask: One, given a class list, it calculates the mask; Two,
# it checks to see if every item on the class list is marked for
# skipping, and if so, sets a flag.

sub classToMask {
	my $classList = shift;
	my $label = shift;
	my $mask = 0;

	my @classes = split(/\s*,\s*/, $classList);
	my $skipThisClass = 0;

	my $thisClass;
	foreach $thisClass (@classes) {
		unless (defined($class{$thisClass})) {
			my $errString = gettext(
			    "%s not found in audit_class.  Omitting %s\n");
			$errString = sprintf($errString, $thisClass,
			    $label);
			print STDERR $errString if ($debug);
			next;
		}
		$skipThisClass = 1 if ($skipClass{$thisClass});
		$mask |=  $class{$thisClass};
	}
	return ($skipThisClass, $mask);
}

# getAttributes: Combine fields from %event and %attr; a description
# in the attribute file overrides a description from audit_event

sub getAttributes {
	my $label = shift;
	my $desc = shift;	# description from audit_event

	my ($description, $title, $skip, @case);

	my $errString = gettext("%s not found in attribute file.");
	my $name = gettext("undefined");

	if (defined($attr{$label})) {
		($name, $description, $title, $skip, @case) = @{$attr{$label}};
		if ($description eq 'none') {
			if ($desc eq 'blank') {
				$description = '';
			} else {
				$description = $desc;
			}
		}
		$name = '' if ($name eq 'none');
		$title = $name if (($title eq 'none') || (!defined($title)));
	} else {
		printf STDERR ("$errString\n", $label) if ($debug);
	}
	return ($name, $description, $title, $skip, @case);
}

# getCallInfo: the system call or program name for an audit record can
# usually be derived from the event name; %attr provides exceptions to
# this rule

sub getCallInfo {
	my $id = shift;
	my $name = shift;
	my $desc = shift;

	my $callType;
	my $callName;
	my $description;

	if ($name) {
		if ($id < 6000) {
			$callType = 'system call';
		} else {
			$callType = 'program';
		}
		($callName) = split(/\s*:\s*/, $name);
	} else {
		$callType = '';
		$callName = '';
	}
	$description = '';
	$description = "$desc" if ($desc);

	return ($callType, $callName, $description);
}

# getFormatList: determine the order and details of kernel vs user
# audit records.  If the first token is "head" then the token list
# is explicit, otherwise the header, subject and return are implied.

sub getFormatList {
	my $format = shift;
	my $id = shift;

	my $list;

	if ($format =~ /^head:/) {
		$list = $format;
	}
	elsif ($format eq 'kernel') {
		$list = $parse->{'kernelDefault'};
		$list =~ s/insert://;
	} elsif ($format eq 'user') {
		$list = $parse->{'userDefault'};
		$list =~ s/insert://;
	} elsif ($id < 6000) {
		$list = $parse->{'kernelDefault'};
		$list =~ s/insert/$format/;
	} else {
		$list = $parse->{'userDefault'};
		$list =~ s/insert/$format/;
	}
	return ($list);
}

# getFormatLine: the arguments from the attribute 'format' are
# expanded to their printable form and also paired with a comment if
# one exists

sub getFormatLine {
	my $arg = shift;
	my $label = shift;
	my @comment = @_;

	my $isOption = 0;

	my ($token, $comment);

	my $cmt = -1;
	if ($arg =~ s/(\D*)(\d+)$/$1/) {  # trailing digits select a comment
		$cmt = $2 - 1;
	}
	$isOption = 1 if ($arg =~ s/^\[(.+)\]$/$1/);

	if (defined($token{$arg})) {	# expand abbreviated name to token
		$token = $token{$arg};
	} else {
		$token = $arg;		# no abbreviation found
	}
	$token = '['.$token.']' if ($isOption);

	if ($cmt > -1) {
		unless(defined($comment[$cmt])) {
			my $errString = gettext(
			    "missing comment for %s %s token %d\n");
			printf STDERR ($errString, $label, $token,
			    $cmt);
			$comment = gettext('missing comment field');
		} else {
			$comment = $comment[$cmt];
			$comment =~ s/&colon;/:/g;	#':' is a delimiter
		}
	} else {
		$comment = '';
	}
	unless (defined($token) && defined($comment)) {
		my $errString = gettext("attribute format/comment error for %s\n");
		printf STDERR ($errString, $label);
	}
	return ($token, $comment);
}

sub usage {
	print "$0 [ -d ] [ -h ] {[ -a ] | [ -e event ] |\n";
	print "\t[ -c class ] | [-i id ] | [ -p program ] |\n";
	print "\t[ -s syscall ]}\n";
}

format nameLine =

@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$title
.

format threeColumns =
  @<<<<<<<<<< @<<<<<<<<<<<<<<<<<<< @<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$col1, $col2, $col3
.

format twoColumns =
      @<<<<<<<<<<<<<<<<<<<<<<<<<<< ^<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$col1, $col2
.
format col2Wrapped =
				   ^<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$col2
.

format space =

.

format wrapped1 =
    ^<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$note
.

format wrapped2 =
^<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
$note
.
