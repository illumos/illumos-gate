#!/usr/bin/perl -w

use strict;
use warnings;
use File::Basename;
use DBI;

my $bin_dir = dirname($0);
my $project = shift;
my $db_file = shift;
if (!defined($db_file)) {
    print "usage:  $0 <project> <db_file>\n";
    exit(1);
}
my $insertions = "$bin_dir/$project.insert.return_states";

my $db = DBI->connect("dbi:SQLite:$db_file", "", "", {AutoCommit => 0});
$db->do("PRAGMA cache_size = 800000");
$db->do("PRAGMA journal_mode = OFF");
$db->do("PRAGMA count_changes = OFF");
$db->do("PRAGMA temp_store = MEMORY");
$db->do("PRAGMA locking = EXCLUSIVE");

sub insert_record($$$$$$$)
{
    my $file = shift;
    my $func = shift;
    my $ret = shift;
    my $type = shift;
    my $param = shift;
    my $key = shift;
    my $value = shift;

#    print "file = '$file' func = '$func' ret = $ret\n";
#    print "type = $type param = $param, key = $key, value = '$value'\n";
#    print "select file, return_id, return, static from return_states where function = '$func' and return = '$ret' and type = 0;'\n";

    my $sth;
    if ($file ne '') {
        $sth = $db->prepare("select file, return_id, static from return_states where file = ? and function = ? and return = ? and type = 0;");
        $sth->execute($file, $func, $ret);
    } else {
        $sth = $db->prepare("select file, return_id, static from return_states where function = ? and return = ? and type = 0;");
        $sth->execute($func, $ret);
    }

    my $insert = $db->prepare("insert into return_states values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");
    while (my @row = $sth->fetchrow_array()) {
        my $file = $row[0];
        my $return_id = $row[1];
        my $static = $row[2];

        $insert->execute($file, $func, 0, $return_id, $ret, $static, $type, $param, $key, $value);
    }
}

my ($ret, $insert, $file, $func, $type, $param, $key, $value);

open(FILE, "<$insertions");
while (<FILE>) {

    if ($_ =~ /^\s*#/) {
        next;
    }

    ($ret, $insert) = split(/\|/, $_);

    if ($ret =~ /(.+),\W*(.+),\W*"(.*)"/) {
        $file = $1;
        $func = $2;
        $ret = $3;
    } elsif ($ret =~ /(.+),\W*"(.*)"/) {
        $file = "";
        $func = $1;
        $ret = $2;
    } else {
        next;
    }

    ($type, $param, $key, $value) = split(/,/, $insert);

    $type = int($type);
    $param = int($param);
    $key =~ s/^["\s]+|["\s]+$//g;
    $value =~ s/^["\s]+|["\s]+$//g;
    chomp($value);

    insert_record($file, $func, $ret, $type, $param, $key, $value);
}
close(FILE);

$db->commit();
$db->disconnect();
