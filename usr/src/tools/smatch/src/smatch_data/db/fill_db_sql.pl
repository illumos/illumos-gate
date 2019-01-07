#!/usr/bin/perl -w

use strict;
use DBI;

my $project = shift;
my $warns = shift;
my $db_file = shift;

if (!defined($warns)) {
    print "usage:  $0 <-p=project> <smatch_warns.txt> <db_file>\n";
    exit(1);
}

my $db = DBI->connect("dbi:SQLite:$db_file", "", "", {AutoCommit => 0});
$db->do("PRAGMA cache_size = 800000");
$db->do("PRAGMA journal_mode = OFF");
$db->do("PRAGMA count_changes = OFF");
$db->do("PRAGMA temp_store = MEMORY");
$db->do("PRAGMA locking = EXCLUSIVE");

my ($dummy, $sql);

open(WARNS, "<$warns");
while (<WARNS>) {

    if (!($_ =~ /^.*? [^ ]*\(\) SQL: /)) {
        next;
    }
    ($dummy, $dummy, $sql) = split(/:/, $_, 3);

    $db->do($sql);
}
close(WARNS);

open(WARNS, "<$warns");
while (<WARNS>) {

    if (!($_ =~ /^.*? [^ ]*\(\) SQL_late: /)) {
        next;
    }
    ($dummy, $dummy, $sql) = split(/:/, $_, 3);

    $db->do($sql);
}
close(WARNS);

$db->commit();
$db->disconnect();
