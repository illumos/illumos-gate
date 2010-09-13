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
use Getopt::Long qw(:config no_ignore_case bundling);
use POSIX qw(locale_h);
use Sun::Solaris::Utils qw(textdomain gettext);
use Sun::Solaris::Project qw(:ALL :PRIVATE);

#
# Print a usage message and exit.
#
sub usage
{
	my (@msg) = @_;
	my $prog = basename($0);
	print(STDERR "$prog: @msg\n") if (@msg);
	printf(STDERR gettext("Usage: %s [-f filename] project\n"), $prog);
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
my $opt_f;

GetOptions("f=s" => \$opt_f) || usage();
usage(gettext('Invalid command-line arguments')) if (@ARGV != 1);
usage(gettext('No project name specified')) if (! defined($ARGV[0]));

my $pname = $ARGV[0];

my $projfile;
my $tmpprojf;

if (defined($opt_f)) {
	$projfile = $opt_f;
} else {
	$projfile = &PROJF_PATH;
}

# Fabricate an unique temporary filename.
$tmpprojf = $projfile . ".tmp.$$";

my $pfh;

# Read the project file.  sysopen() is used so we can control the file mode.
if (! sysopen($pfh, $projfile, O_RDONLY)) {
	error([10, gettext('Cannot open %s: %s'), $projfile, $!]);
}
my ($mode, $uid, $gid) = (stat($pfh))[2,4,5];

my $flags = {};
$flags->{'validate'} = 'false';
$flags->{'res'} = 'true';
$flags->{'dup'} = 'true';

my ($ret, $pf) = projf_read($pfh, $flags);
if ($ret != 0) {
	error(@$pf);
}
close($pfh);

# Search for the project & remove it.
my $del = 0;
my @newpf = grep { $_->{'name'} eq $pname ? $del++ && 0 : 1 } @$pf;
error([6, gettext('Project "%s" does not exist'), $pname])
    if ($del == 0);
error([6, gettext('Duplicate project name "%s"'), $pname])
    if ($del > 1);   # Should be impossible due to projf_validate() check.

# Write out the project file.
umask(0000);
sysopen($pfh, $tmpprojf, O_WRONLY | O_CREAT | O_EXCL, $mode) ||
    error([10, gettext('Cannot create %s: %s'), $tmpprojf, $!]);
projf_write($pfh, \@newpf);
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
