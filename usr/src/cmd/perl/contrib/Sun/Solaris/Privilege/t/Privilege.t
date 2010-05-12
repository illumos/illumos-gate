#
# Copyright (c) 2004, Oracle and/or its affiliates. All rights reserved.
#

#
# test script for Sun::Solaris::Privilege
#

$^W = 1;
use strict;
use Data::Dumper;
$Data::Dumper::Terse = 1;
$Data::Dumper::Indent = 0;

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

#
# Main body of tests starts here
#

my ($loaded, $line) = (1, 0);
my $fh = do { local *FH; *FH; };

# 1. Check the module loads
BEGIN { $| = 1; print "1..15\n"; }
END   { print "not ok 1\n" unless $loaded; }
use Sun::Solaris::Privilege qw(:ALL :PRIVATE);
$loaded = 1;
pass();

#
# 2. ppriv -l works
#
my $privs = `ppriv -l`;
if ($privs eq "") {
	fail();
} else {
	pass();
}
my @privs = split(/\s+/, $privs);

#
# 3. Are all privileges according ppriv -l defined in the privileges hash?
#

my %sprivs;
foreach my $p (@privs)
{
	my $cn = $p;
	$cn =~ s/.*/PRIV_\U$&/;
	$sprivs{$cn} = $p;
	$errs++ if (!defined $PRIVILEGES{$cn} || $PRIVILEGES{$cn} ne $p);
}
report();

#
# 4. And are those all the privileges.
#
foreach my $p (keys %PRIVILEGES)
{
	$errs++ if (!defined $sprivs{$p});
}
report();

#
# 5. Verify that all privileges are part of the full set.
#
my $full = priv_fillset();

foreach my $p (keys %PRIVILEGES)
{
	$errs++ if (!priv_ismember($full, $p));
}
report();

#
# 6. Verify that no privilege is part of the empty set.
#
my $empty = priv_emptyset();

foreach my $p (keys %PRIVILEGES)
{
	$errs++ if (priv_ismember($empty, $p));
}
report();

#
# 7. Verify that priv_delset removes privileges.
#
foreach my $p (keys %PRIVILEGES)
{
	my $testset = priv_fillset();
	$errs++ unless priv_delset($testset, $p);
	$errs++ if priv_ismember($testset, $p);
	
}
report();

#
# 8. Verify getpflags/setpflags.
#
my $pflags;
$errs++ unless ($pflags = getpflags(PRIV_AWARE));

$errs++ unless setpflags(PRIV_AWARE, 0);
$errs++ unless setpflags(PRIV_DEBUG, 1);
$errs++ unless (getpflags(PRIV_DEBUG) == 1);
$errs++ unless setpflags(PRIV_DEBUG, 0);
$errs++ unless (getpflags(PRIV_DEBUG) == 0);

report();

#
# 9. Verify getppriv() works.
#
my %psets;
foreach my $s (keys %PRIVSETS)
{
	$errs++ unless ($psets{$s} = getppriv($s));
}
report();

#
# 10. Verify that we can reset those sets.
#
foreach my $s (keys %PRIVSETS)
{
	$errs++ unless (setppriv(PRIV_SET, $s, $psets{$s}));
}
report();

#
# 11. E/P/I manipulations.
#
$errs++ unless setppriv(PRIV_SET, PRIV_EFFECTIVE, priv_emptyset());
$errs++ unless setppriv(PRIV_SET, PRIV_EFFECTIVE, getppriv(PRIV_PERMITTED));
$errs++ unless setppriv(PRIV_SET, PRIV_INHERITABLE, priv_emptyset());
$errs++ unless setppriv(PRIV_SET, PRIV_INHERITABLE, getppriv(PRIV_PERMITTED));
report();
#
# 12. Fork()/exec() tests.  See if the setting the privileges actually
# has an effect.
#
my $p;
priv_delset($p = getppriv(PRIV_PERMITTED), PRIV_PROC_FORK);
$errs++ unless setppriv(PRIV_SET, PRIV_EFFECTIVE, $p);

my $fr = fork();

# Child of a sucessful fork().
exit if (defined($fr) && $fr == 0);

$errs++ unless !defined $fr;

# Exec test
priv_addset($p, PRIV_PROC_FORK);
priv_delset($p, PRIV_PROC_EXEC);
$errs++ unless setppriv(PRIV_SET, PRIV_EFFECTIVE, $p);
my $out = `echo foo 2>/dev/null`;
$errs++ unless (!defined $out || $out eq "");

# Restore E.
$errs++ unless setppriv(PRIV_SET, PRIV_EFFECTIVE, getppriv(PRIV_PERMITTED));

report();

#
# 13. Verify priv_str_to_set, priv_set_to_str
#
my $newset = priv_str_to_set(join(",", keys %PRIVILEGES), ",");
map { $errs++ if (!priv_ismember($newset, $_)); } keys %PRIVILEGES;

$newset = priv_str_to_set("all", ",");
map { $errs++ if (!priv_ismember($newset, $_)); } keys %PRIVILEGES;

$newset = priv_str_to_set("none", ",");
map { $errs++ if (priv_ismember($newset, $_)); } keys %PRIVILEGES;

foreach my $p (keys %PRIVILEGES)
{
	$newset = priv_str_to_set($PRIVILEGES{$p}, ",");
	$errs++ if (!priv_ismember($newset, $p));
	$errs++ if (priv_ismember(priv_inverse($newset), $p));
}

foreach my $p (keys %PRIVILEGES)
{
	$newset = priv_str_to_set("all,!" . $PRIVILEGES{$p}, ",");
	$errs++ if (priv_ismember($newset, $p));
	foreach my $p2 (keys %PRIVILEGES)
	{
		next if ($p eq $p2);
		$errs++ if (!priv_ismember($newset, $p2));
		$errs++ if (priv_ismember(priv_inverse($newset), $p2));
	}
}
report();

#
# 14. Check whether PRIV_SET, PRIV_ON, PRIV_OFF work.
#
my $perm;
my @ours = split(/,/,
    priv_set_to_str($perm = getppriv(PRIV_PERMITTED), ",", PRIV_STR_LIT));
my $set = priv_emptyset();


$errs++ unless (setppriv(PRIV_SET, PRIV_EFFECTIVE, $perm));
priv_addset($set, $ours[0]);
$errs++ unless (setppriv(PRIV_OFF, PRIV_EFFECTIVE, $set));
my $new = getppriv(PRIV_EFFECTIVE);

# The new set should be equal to the $perm minus the priv set in $set.
my $temp = priv_intersect($perm, priv_inverse($set));
$errs++ unless (priv_isequalset($temp, $new));

# Set the single bit back on.
$errs++ unless (setppriv(PRIV_ON, PRIV_EFFECTIVE, $set));
$new = getppriv(PRIV_EFFECTIVE);
$errs++ unless (priv_isequalset($perm, $new));

# Set the set
$errs++ unless (setppriv(PRIV_SET, PRIV_EFFECTIVE, $set));
$new = getppriv(PRIV_EFFECTIVE);
$errs++ unless (priv_isequalset($set, $new));

# Clear the set
$errs++ unless (setppriv(PRIV_OFF, PRIV_EFFECTIVE, $set));
$new = getppriv(PRIV_EFFECTIVE);
$errs++ unless (priv_isemptyset( $new));

# Set the single bit back on.
$errs++ unless (setppriv(PRIV_ON, PRIV_EFFECTIVE, $set));
$new = getppriv(PRIV_EFFECTIVE);
$errs++ unless (priv_isequalset($set, $new));

report();

#
# 15. We should be privilege aware by now.
#
$errs++ unless (getpflags(PRIV_AWARE) == 1);
report();
