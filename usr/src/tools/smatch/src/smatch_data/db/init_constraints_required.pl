#!/usr/bin/perl -w

use strict;
use warnings;
use bigint;
use DBI;
use Data::Dumper;
use File::Basename;

my $project = shift;
$project =~ s/.*=(.*)/$1/;
my $warns = shift;
my $db_file = shift;

my $db;

sub connect_to_db($)
{
    my $name = shift;

    $db = DBI->connect("dbi:SQLite:$name", "", "", {AutoCommit => 0});

    $db->do("PRAGMA cache_size = 800000");
    $db->do("PRAGMA journal_mode = OFF");
    $db->do("PRAGMA count_changes = OFF");
    $db->do("PRAGMA temp_store = MEMORY");
    $db->do("PRAGMA locking = EXCLUSIVE");
}

sub load_manual_constraints($$)
{
    my $full_path = shift;
    my $project = shift;
    my $dir = dirname($full_path);
    my ($data, $op, $limit);

    if ($project =~ /^$/) {
        return;
    }

    open(FILE, "$dir/$project.constraints_required");
    while (<FILE>) {
        ($data, $op, $limit) = split(/,/);
        $op =~ s/ //g;
        $limit =~ s/^ +//;
        $limit =~ s/\n//;
        $db->do("insert into constraints_required values (?, ?, ?);", undef, $data, $op, $limit);
    }
    close(FILE);

    $db->commit();
}

connect_to_db($db_file);
load_manual_constraints($0, $project);

$db->commit();
$db->disconnect();
