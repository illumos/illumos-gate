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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
# dictck -- Sanity check a .dict file and optionally the corresponding .po file
#
# example: dickck FMD.dict FMD.po
#
# usage: dickck [-vp] [ -b buildcode ] dictfile [ pofile ]
#
#	-b	specify location of "buildcode" command
#
#	-p	print a .po file template to stdout, based on dictfile given
#
#	-v	verbose, show how code is assembled
#
# Note: this program requires the "buildcode" program in your search path.
#

use strict;

use Getopt::Std;

use vars qw($opt_b $opt_p $opt_v);

my $Myname = $0;	# save our name for error messages
$Myname =~ s,.*/,,;

$SIG{HUP} = $SIG{INT} = $SIG{TERM} = $SIG{__DIE__} = sub {
	# although fatal, we prepend "WARNING:" to make sure the
	# commonly-used "nightly" script flags this as lint on the .dict file
	die "$Myname: WARNING: @_";
};

#
# usage -- print a usage message and exit
#
sub usage {
	my $msg = shift;

	warn "$Myname: $msg\n" if defined($msg);
	warn "usage: $Myname [-pv] [ -b buildcode ] dictfile [ pofile ]\n";
	exit 1;
}

my %keys2val;
my %val2keys;
my %code2val;

my $buildcode = 'buildcode';

#
# the "main" for this script...
#
getopts('b:pv') or usage;

my $dictfile = shift;
my $pofile = shift;
usage unless defined($dictfile);
usage if @ARGV;
$buildcode = $opt_b if defined($opt_b);
dodict($dictfile);
dopo($pofile) if defined($pofile);
exit 0;

#
# dodict -- load up a .dict file, sanity checking it as we go
#
sub dodict {
	my $name = shift;
	my $dname;
	my $line = 0;
	my $lhs;
	my $rhs;
	my %props;
	my $maxkey = 1;

	if ($name =~ m,([^/]+)\.dict$,) {
		$dname = $1;
	} else {
		die "dictname \"$name\" not something.dict as expected\n";
	}

	open(F, $name) or die "$name: $!\n";
	print "parsing \"$name\"\n" if $opt_v;
	while (<F>) {
		$line++;
		next if /^\s*#/;
		chomp;
		next if /^\s*$/;
		die "$name:$line: first non-comment line must be FMDICT line\n"
		    unless /^FMDICT:/;
		print "FMDICT keyword found on line $line\n" if $opt_v;
		s/FMDICT:\s*//;
		my $s = $_;
		while ($s =~ /^\s*([^=\s]+)(.*)$/) {
			$lhs = $1;
			$rhs = "";
			$s = $+;
			if ($s =~ /^\s*=\s*(.*)$/) {
				$s = $+;
				die "$name:$line: property \"$lhs\" incomplete\n"
				    unless $s ne "";
			}
			if ($s =~ /^"((?:[^"]|\\")*)"(.*)$/) {
				$s = $+;
				$rhs = $1;
			} else {
				$s =~ /^([^\s]*)(.*)$/;
				$s = $+;
				$rhs = $1;
			}
			$rhs =~ s/\\(.)/dobs($1)/ge;
			$props{$lhs} = $rhs;
			print "property \"$lhs\" value \"$rhs\"\n" if $opt_v;
		}
		last;
	}
	# check for required headers
	die "$name: no version property in header\n"
	    unless defined($props{'version'});
	die "$name: no name property in header\n"
	    unless defined($props{'name'});
	die "$name: no maxkey property in header\n"
	    unless defined($props{'maxkey'});

	# check version
	die "$name:$line: unexpected version: \"$props{'version'}\"\n"
	    unless $props{'version'} eq "1";

	# check name
	die "$name:$line: name \"$props{'name'}\" doesn't match \"$dname\" from filename\n"
	    unless $props{'name'} eq $dname;

	# check format of maxkey (value checked later)
	die "$name:$line: maxkey property must be a number\n"
	    unless $props{'maxkey'} =~ /^\d+$/;

	# check for old bits property
	die "$name: obsolete \"bits\" property found in header\n"
	    if defined($props{'bits'});

	# parse entries
	while (<F>) {
		$line++;
		chomp;
		s/#.*//;
		next if /^\s*$/;
		die "$name:$line: malformed entry\n"
		    unless /^([^=]+)=(\d+)$/;
		$lhs = $1;
		$rhs = $2;

		# make sure keys are sorted
		my $elhs = join(' ', sort split(/\s/, $lhs));
		die "$name:$line: keys not in expected format of:\n" .
		    "    \"$elhs\"\n"
		    unless $elhs eq $lhs;

		# check for duplicate or unexpected keys
		my %keys;
		foreach my $e (split(/\s/, $lhs)) {
			die "$name:$line: unknown event type \"$e\"\n"
			    unless $e =~
			    /^(fault|defect|upset|ereport|list)\..*[^.]$/;
			die "$name:$line: key repeated: \"$e\"\n"
			    if defined($keys{$e});
			$keys{$e} = 1;
		}
		$maxkey = keys(%keys) if $maxkey < keys(%keys);

		die "$name:$line: duplicate entry for keys\n"
		    if defined($keys2val{$lhs});
		die "$name:$line: duplicate entry for value $rhs\n"
		    if defined($val2keys{$rhs});
		$keys2val{$lhs} = $rhs;
		$val2keys{$rhs} = $lhs;

		open(B, "$buildcode $dname $rhs|") or
		    die "can't run buildcode: $!\n";
		my $code = <B>;
		chomp $code;
		close(B);
		print "code: $code keys: $lhs\n" if $opt_v;
		$code2val{$code} = $rhs;

		if ($opt_p) {
			print <<EOF;
#
# code: $code
# keys: $lhs
#
msgid "$code.type"
msgstr "XXX"
msgid "$code.severity"
msgstr "XXX"
msgid "$code.description"
msgstr "XXX"
msgid "$code.response"
msgstr "XXX"
msgid "$code.impact"
msgstr "XXX"
msgid "$code.action"
msgstr "XXX"
EOF
		}
	}

	print "computed maxkey: $maxkey\n" if $opt_v;

	# check maxkey
	die "$name: maxkey too low, should be $maxkey\n"
	    if $props{'maxkey'} < $maxkey;

	close(F);
}

#
# dobs -- handle backslashed sequences
#
sub dobs {
	my $s = shift;

	return "\n" if $s eq 'n';
	return "\r" if $s eq 'r';
	return "\t" if $s eq 't';
	return $s;
}

#
# dopo -- sanity check a po file
#
sub dopo {
	my $name = shift;
	my $line = 0;
	my $id;
	my $code;
	my $suffix;
	my %ids;

	open(F, $name) or die "$name: $!\n";
	print "parsing \"$name\"\n" if $opt_v;
	while (<F>) {
		$line++;
		next if /^\s*#/;
		chomp;
		next if /^\s*$/;
		next unless /^msgid\s*"([^"]+)"$/;
		$id = $1;
		next unless $id =~
		   /^(.*)\.(type|severity|description|response|impact|action)$/;
		$code = $1;
		$suffix = $2;
		die "$name:$line: no dict entry for code \"$code\"\n"
		   unless defined($code2val{$code});
		$ids{$id} = $line;
	}
	close(F);

	# above checks while reading in file ensured that node code was
	# mentioned in .po file that didn't exist in .dict file.  now
	# check the other direction: make sure the full set of entries
	# exist for each code in the .dict file
	foreach $code (sort keys %code2val) {
		die "$name: missing entry for \"$code.type\"\n"
		    unless defined($ids{"$code.type"});
		die "$name: missing entry for \"$code.severity\"\n"
		    unless defined($ids{"$code.severity"});
		die "$name: missing entry for \"$code.description\"\n"
		    unless defined($ids{"$code.description"});
		die "$name: missing entry for \"$code.response\"\n"
		    unless defined($ids{"$code.response"});
		die "$name: missing entry for \"$code.impact\"\n"
		    unless defined($ids{"$code.impact"});
		die "$name: missing entry for \"$code.action\"\n"
		    unless defined($ids{"$code.action"});
	}
}
