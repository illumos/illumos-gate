#
# Copyright (c) 2004, Oracle and/or its affiliates. All rights reserved.
#

#
# test script for Sun::Solaris::Ucred
#

$^W = 1;
use strict;
use Data::Dumper;
use English;
$Data::Dumper::Terse = 1;
$Data::Dumper::Indent = 0;


use Sun::Solaris::Privilege qw(:ALL);
use Sun::Solaris::Project qw(:ALL);

#
# Status reporting utils
#

use vars qw($test);
$test = 1;

sub pass
{
	print("ok $test $@\n");
	$test++;
}

sub fail
{
	print("not ok $test $@\n");
	$test++;
}

sub fatal
{
	print("not ok $test $@\n");
	exit(1);
}

my $errs;

sub report
{
	if ($errs) {
		fail();
	} else {
		pass();
	}
	$errs = 0;
}

sub ucred_verify
{
	my ($ucred) = @_;

	my $pid = ucred_getpid($ucred);

	$errs++ unless (!defined $pid || $pid == $$);
	$errs++ unless (ucred_geteuid($ucred) == $EUID);
	$errs++ unless (ucred_getruid($ucred) == $UID);
	$errs++ unless (ucred_getegid($ucred) == $EGID);
	$errs++ unless (ucred_getrgid($ucred) == $GID);
	$errs++ unless (ucred_getprojid($ucred) == getprojid());
	foreach my $f (PRIV_AWARE, PRIV_DEBUG) {
		$errs++ unless (ucred_getpflags($ucred, $f) == getpflags($f));
	}

	# Get a sorted list of groups; the real gid is first and we need
	# to shift that one out of the way first.
	my @gr = split(/\s+/, $();
	shift @gr;
	@gr = sort {$a <=> $b} (@gr);
	my @ucgr = sort {$a <=> $b} ucred_getgroups($ucred);

	$errs++ unless ("@gr" eq "@ucgr");

	foreach my $s (keys %PRIVSETS) {
		my $set = ucred_getprivset($ucred, $s);
		$errs++ unless priv_isequalset($set, getppriv($s));
	}
}

#
# Main body of tests starts here
#

my ($loaded, $line) = (1, 0);
my $fh = do { local *FH; *FH; };

#
# 1. Check the module loads
#
BEGIN { $| = 1; print "1..5\n"; }
END   { print "not ok 1\n" unless $loaded; }
use Sun::Solaris::Ucred qw(:ALL);
$loaded = 1;
pass();

#
# 2. ucred_get works.
#

my $ucred = ucred_get($$);

$errs++ unless defined $ucred;

report();

#
# 3. Returned ucred matches perl's idea of the process' credentials.
#
if (defined $ucred) {
	ucred_verify($ucred);
}
report();

#
# 4. Create a socketpair; make sure that the ucred returned
# is mine.
#

use IO::Socket::UNIX;

my ($unix) = new IO::Socket::UNIX;
my ($s1, $s2) = $unix->socketpair(AF_UNIX, SOCK_STREAM, 0);

if ($ucred = getpeerucred(fileno($s1))) {
	ucred_verify($ucred);
} else {
	$errs++;
}
close($s1);
close($s2);

($s1, $s2) = $unix->socketpair(AF_UNIX, SOCK_SEQPACKET, 0);

if ($ucred = getpeerucred(fileno($s1))) {
	ucred_verify($ucred);
} else {
	$errs++;
}
close($s1);
close($s2);
report();

#
# 5. Create a AF_INET loopback connected socket and call getpeerucred().
#
use IO::Socket::INET;

my $inet = new IO::Socket::INET;

$s1 = $inet->socket(AF_INET, SOCK_STREAM, 0);
$inet = new IO::Socket::INET;
$s2 = $inet->socket(AF_INET, SOCK_STREAM, 0);

$s1->bind(0, inet_aton("localhost"));
$s1->listen(0);

$s2->connect($s1->sockname);
my $s3 = $s1->accept();

# getpeerucred on the accepter should fail
$errs++ if getpeerucred(fileno($s1));
# but on the other two it should succeed.

foreach my $s ($s2, $s3) {
	if ($ucred = getpeerucred(fileno($s))) {
		ucred_verify($ucred);
	} else {
		$errs++;
	}
}
report();
