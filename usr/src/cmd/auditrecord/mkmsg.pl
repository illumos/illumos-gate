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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

# mkmsg.pl -- generate message file content for strings that
# originate in audit_record_attr and audit_event
#
# mkmsg.pl domain po_file_name

require 5.005;
use strict;

use vars qw(
    $parse %translateText
    $debug
    %attr %event %class %skipClass %token %noteAlias);

use locale;
use POSIX qw(locale_h);
use Sun::Solaris::Utils qw(gettext textdomain);
use Sun::Solaris::BSM::_BSMparse;

unless ($#ARGV == 1) {
	print STDERR "usage: $0 domain_name file_name\n";
	exit (1);
}
my $textDomain = $ARGV[0];
my $poFile = $ARGV[1];

# Set message locale
setlocale(LC_ALL, "");
textdomain($textDomain);

my %options;
$options{'classFilter'} = '';		# don''t filter
$debug			= 0;		# debug mode on
$options{'eventFilter'} = '';   	# don''t filter
$options{'idFilter'}	= '';		# don''t filter

$parse = new Sun::Solaris::BSM::_BSMparse($debug, \%options, './',
    '../../lib/libbsm', '.txt');

my ($attr, $token, $skipClass, $noteAlias) = $parse->readAttr();
%class = %{$parse->readClass()};
%event = %{$parse->readEvent()};

%attr  = %$attr;
%token = %$token;
%noteAlias = %$noteAlias;
%skipClass = %$skipClass;

my $label;

my $errString;

foreach $label (sort keys %event) {

	my ($id, $class, $eventDescription) = ('', '', '');
	if (defined($event{$label})) {
		($id, $class, $eventDescription) = @{$event{$label}};
		$eventDescription =~ s/\(\w+\)//;
	}

	my ($name, $description, $title, $skip, @case) = ('', '', '', '', ());
	if (defined($attr{$label})) {
		($name, $description, $title, $skip, @case) = @{$attr{$label}};
		$description = '' if ($description eq 'none');
		$name = '' if ($name eq 'none');
		$title = $name if (($title eq 'none') || (!defined($title)));
	}

# in auditrecord.pl, _either_ $description _or_ $eventDescription
# is used.  Both are put into the message file so that this script
# doesn't have logic dependent on auditrecord.pl

	addToMsgFile($title);
	addToMsgFile($eventDescription);
	addToMsgFile($description);

	my $case;

	foreach $case (@case) {
		addToMsgFile(${$case}[0]);	# description
		#		[1]		# token id (a name list)
		my @comment = split(/\s*:\s*/, ${$case}[2]);
		my $note = ${$case}[3];

		my $comment;
		foreach $comment (@comment) {
			addToMsgFile($comment);
		}
		if ($noteAlias{$note}) {
			addToMsgFile($noteAlias{$note});
		} else {
			addToMsgFile($note);
		}
	}
	
}
writeMsgFile($textDomain, $poFile);

exit (0);

sub addToMsgFile {
	my @text = @_;

	my $text;
	foreach $text (@text) {
		next if ($text =~ /^$/);
		$text =~ s/&colon;/:/g;
		$translateText{$text} = 1;
	}
}

# ids in the .po file must be quoted; since the messages themselves
# contain quotes, quotes must be escaped

sub writeMsgFile {
	my $domain = shift;
	my $file = shift;

	my $text;

	open(Message, ">$file") or
		die "Failed to open $file: $!\n";

	print Message "# File:audit_record_attr: textdomain(\"$domain\")\n";
	foreach $text (sort keys %translateText) {
		$text =~ s/"/\\"/g;
		print Message "msgid \"$text\"\nmsgstr\n";
	}
	close Message;
}
