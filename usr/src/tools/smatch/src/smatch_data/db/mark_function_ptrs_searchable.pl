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

my ($update, $sth, $fn_ptr, $ptr_to_ptr, $count);

$update = $db->prepare_cached('UPDATE function_ptr set searchable = 1 where ptr = ?');
$sth = $db->prepare('select distinct(ptr) from function_ptr;');
$sth->execute();

while ($fn_ptr = $sth->fetchrow_array()) {

    # following a pointer to pointer chain is too complicated for now
    $ptr_to_ptr = $db->selectrow_array("select function from function_ptr where ptr = '$fn_ptr' and function like '% %';");
    if ($ptr_to_ptr) {
        next;
    }
    $ptr_to_ptr = $db->selectrow_array("select function from function_ptr where ptr = '$fn_ptr' and function like '%[]';");
    if ($ptr_to_ptr) {
        next;
    }

    $count = $db->selectrow_array("select count(*) from return_states join function_ptr where return_states.function == function_ptr.function and ptr = '$fn_ptr';");
    # if there are too many states then bail
    if ($count > 1000) {
        next;
    }
    # if there are no states at all then don't bother recording
    if ($count == 0) {
        next;
    }

    $update->execute($fn_ptr);
}

$db->commit();
$db->disconnect();
