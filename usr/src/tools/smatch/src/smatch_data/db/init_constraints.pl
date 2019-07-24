#!/usr/bin/perl -w

use strict;
use warnings;
use bigint;
use DBI;
use Data::Dumper;
use File::Basename;
use Try::Tiny;

my $project = shift;
$project =~ s/.*=(.*)/$1/;
my $warns = shift;
my $db_file = shift;

sub preserve_existing_constraints()
{
    if (! -e "smatch_db.sqlite") {
        return;
    }

    my $db = DBI->connect("dbi:SQLite:$db_file", "", "",);
    $db->do('attach "smatch_db.sqlite" as old_db');
    $db->do('insert into constraints select * from old_db.constraints');
    $db->disconnect();
}

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

    if ($project =~ /^$/) {
        return;
    }

    open(FILE, "$dir/$project.constraints");
    while (<FILE>) {
        s/\n//;
        $db->do("insert or ignore into constraints (str) values ('$_')");
    }
    close(FILE);

    open(FILE, "$dir/$project.constraints_required");
    while (<FILE>) {
        my $limit;
        my $dummy;

        ($dummy, $dummy, $limit) = split(/,/);
        $limit =~ s/^ +//;
        $limit =~ s/\n//;
        try {
            $db->do("insert or ignore into constraints (str) values ('$limit')");
        } catch {}
    }
    close(FILE);

    $db->commit();
}

preserve_existing_constraints();

connect_to_db($db_file);
load_manual_constraints($0, $project);

$db->commit();
$db->disconnect();
