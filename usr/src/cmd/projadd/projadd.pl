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
#ident	"%Z%%M%	%I%	%E% SMI"
#

require 5.005;
use strict;
use locale;
use Errno;
use Fcntl;
use File::Basename;
use Getopt::Std;
use Getopt::Long qw(:config no_ignore_case bundling);
use POSIX qw(locale_h getuid getgid);
use Sun::Solaris::Utils qw(textdomain gettext);
use Sun::Solaris::Project qw(:ALL :PRIVATE);

#
# Print a usage message and exit.
#
sub usage
{
	my (@msg) = @_;
	my $prog = basename($0);
	my $space = ' ' x length($prog);
	print(STDERR "$prog: @msg\n") if (@msg);
	printf(STDERR gettext(
	    "       %s [-n] [-f filename] [-p projid [-o]] [-c comment]\n".
            "       %s [-U user[,user...]] [-G group[,group...]]\n".
            "       %s [-K name[=value[,value...]]] project\n"),
	       $prog, $space, $space);
	exit(2);
}

#
# Print a list of error messages and exit.
#
sub error
{
	my $exit = $_[0][0];
	my $prog = basename($0) . ': ';
	foreach my $err (@_) {
		my ($e, $fmt, @args) = @$err;
		printf(STDERR $prog . $fmt . "\n", @args);
	}
	exit($exit);
}

#
# Main routine of script.
#
# Set the message locale.
#
setlocale(LC_ALL, '');
textdomain(TEXT_DOMAIN);


# Process command options and do some initial command-line validity checking.
my ($pname, $flags);

my $projfile = &PROJF_PATH;
my $opt_n;
my $opt_c;
my $opt_o;
my $opt_p;
my $opt_U;
my $opt_G;
my @opt_K;

GetOptions("f=s" => \$projfile,
	   "n"   => \$opt_n,
	   "c=s" => \$opt_c,
	   "o"	 => \$opt_o,
	   "p=s" => \$opt_p,
	   "U=s" => \$opt_U,
	   "G=s" => \$opt_G,
	   "K=s" => \@opt_K) || usage();

usage(gettext('Invalid command-line arguments')) if (@ARGV != 1);
usage(gettext('No project name specified')) if (! defined($ARGV[0]));
usage(gettext('-o requires -p projid to be specified'))
    if (defined($opt_o) && ! defined($opt_p));

$pname = $ARGV[0];
my $maxpjid = 99;
my $tmpprojf;


# Fabricate an unique temporary filename.
$tmpprojf = $projfile . ".tmp.$$";

my $pfh;

if (defined($opt_n)) {
	$flags->{'validate'} = 'false';
} else {
	$flags->{'validate'} = 'true';
}

$flags->{'res'} = 'true';
$flags->{'dup'} = 'true';

my $pf;
my ($mode, $uid, $gid);
my $tmperr;
my $ret;
my $err;

# Read the project file.  sysopen() is used so we can control the file mode.
if (! sysopen($pfh, $projfile, O_RDONLY)) {
	if ($! == Errno::ENOENT) {
		$pf = [];
		$mode = 0644;
		$uid = getuid();
		$gid = getgid();
	} else {
		error([10, gettext('Cannot open %s: %s'), $projfile, $!]);
	}
} else {
	($mode, $uid, $gid) = (stat($pfh))[2,4,5];

	($ret, $pf) = projf_read($pfh, $flags);
	if ($ret != 0) {
		error(@$pf);
	}
	close($pfh);
	foreach (@$pf) {
		$maxpjid = $_->{'projid'} if ($_->{'projid'} > $maxpjid);
	}
}


my $proj = {};
my ($value, $list);

$proj->{'name'} = '';
$proj->{'projid'} = $maxpjid + 1;;
$proj->{'comment'} = '';
$proj->{'userlist'} = [];
$proj->{'grouplist'} = [];
$proj->{'attributelist'} = [];
$proj->{'modified'} = 'true';
push(@$pf, $proj);

# Update the record as appropriate.
$err = [];

($ret, $value) = projent_parse_name($pname);
if ($ret != 0) {
	push(@$err, @$value);
} else {
	$proj->{'name'} = $value;
	if (!defined($opt_n)) {
		($ret, $tmperr) =
		    projent_validate_unique_name($proj, $pf);
		if ($ret != 0) {
			push(@$err, @$tmperr);
		}
	}
}

# Apply any changes due to options.
if (defined($opt_p)) {

	my ($ret, $value) = projent_parse_projid($opt_p);
	if ($ret != 0) {
		push(@$err, @$value);
	} else {
		$proj->{'projid'} = $value;
		if (!defined($opt_n)) {
			($ret, $tmperr) =
			    projent_validate_projid($value, {});
			if ($ret != 0) {
				push(@$err, @$tmperr);
			}
		}
		if ((!defined($opt_n)) && (!defined($opt_o))) {
			($ret, $tmperr) =
			    projent_validate_unique_id($proj, $pf);
			if ($ret != 0) {
				push(@$err, @$tmperr);
			}
		}
	}	
}
if (defined($opt_c)) {

	my ($ret, $value) = projent_parse_comment($opt_c);
	if ($ret != 0) {
		push(@$err, @$value);
	} else {
		$proj->{'comment'} = $value;
	}
}
if (defined($opt_U)) {

	my @sortlist;
	my ($ret, $list) = projent_parse_users($opt_U,
	    { 'allowspaces' => 1 });
	if ($ret != 0) {
		push(@$err, @$list);
	} else {
		@sortlist = sort(@$list);
		$proj->{'userlist'} = \@sortlist;
	}
}
if (defined($opt_G)) {

	my @sortlist;
	my ($ret, $list) = projent_parse_groups($opt_G,
	    { 'allowspaces' => 1 });
	if ($ret != 0) {
		push(@$err, @$list);
	} else {
		@sortlist = sort(@$list);
		$proj->{'grouplist'} = \@sortlist;
	}
}

my $attrib;
my @attriblist;
my @sortlist;

# Support multiple instances of -K.
foreach $attrib (@opt_K) {

	my ($ret, $list) = projent_parse_attributes($attrib,
	    {'allowunits' => 1});
	if ($ret != 0) {
		push(@$err, @$list);
	} else {
		push(@attriblist, @$list);
	}
}

if (@attriblist) {
	@sortlist = sort { $a->{'name'} cmp $b->{'name'} } @attriblist;
	$proj->{'attributelist'} = \@sortlist;
}

# Validate project entry changes.
if (!defined($opt_n)) {
	($ret, $tmperr) = projent_validate($proj, $flags);
	if ($ret != 0) {
		push(@$err, @$tmperr);
	}
}
if (@$err) {
	error(@$err);
}

# Write out the project file.
umask(0000);
sysopen($pfh, $tmpprojf, O_WRONLY | O_CREAT | O_EXCL, $mode) ||
    error([10, gettext('Cannot create %s: %s'), $tmpprojf, $!]);
projf_write($pfh, $pf);
close($pfh);
if (!chown($uid, $gid, $tmpprojf)) {
	unlink($tmpprojf);
	error([10, gettext('Cannot set ownership of %s: %s'),
	    $tmpprojf, $!]);
}
if (! rename($tmpprojf, $projfile)) {
	unlink($tmpprojf);
	error([10, gettext('cannot rename %s to %s: %s'),
	    $tmpprojf, $projfile, $!]);
}

exit(0);
