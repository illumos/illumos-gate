#!/usr/bin/perl -w

use strict;
use warnings;
use bigint;
use DBI;
use Data::Dumper;

my $db_file = shift;
my $db = DBI->connect("dbi:SQLite:$db_file", "", "", {AutoCommit => 0});

$db->do("PRAGMA cache_size = 800000");
$db->do("PRAGMA journal_mode = OFF");
$db->do("PRAGMA count_changes = OFF");
$db->do("PRAGMA temp_store = MEMORY");
$db->do("PRAGMA locking = EXCLUSIVE");

my ($select, $select_type, $remove, $file, $caller, $function, $param, $src_param, $value, $type);

$remove = $db->prepare_cached('DELETE FROM caller_info WHERE file = ? AND caller = ? AND function = ? AND parameter = ? AND type != 1014');
$select = $db->prepare('SELECT file, caller, function, parameter, value FROM caller_info WHERE function LIKE "% param %" AND type = 1014 AND value LIKE "p %"');
$select_type = $db->prepare_cached('SELECT value from function_type WHERE file = ? AND function = ? AND parameter = ? limit 1');
$select->execute();

while (($file, $caller, $function, $param, $value) = $select->fetchrow_array()) {

    if ($value =~ /p (.*)/) {
        $src_param = $1;
    } else {
        print "error:  unexpected source parameter $value\n";
        next;
    }

    $select_type->execute($file, $caller, $src_param);
    $type = $select_type->fetchrow_array();
    if (!$type) {
        next;
    }
    #FIXME: Why is this extra fetch() needed???
    $select_type->fetch();

    if (!($type =~ /^void\*$/) && !($type =~ /^ulong$/)) {
        next;
    }

    $remove->execute($file, $caller, $function, $param);
}

$db->commit();
$db->disconnect();
