#!/usr/bin/perl -w

use strict;
use DBI;

my $db_file = shift;
if (!$db_file) {
    print "usage: copy_function_pointers.pl <db file>\n";
    exit(0);
}

my $db = DBI->connect("dbi:SQLite:$db_file", "", "", {AutoCommit => 0});

my ($select, $function, $ptr);

$select = $db->prepare('SELECT DISTINCT function, ptr FROM function_ptr WHERE function LIKE "% %";');

my %ptrs;

$select->execute();
while (($function, $ptr) = $select->fetchrow_array()) {
    $ptrs{"$function"}{'ptr'} = $ptr;
    $ptrs{"$function"}{'done'} = 0;
}

sub copy_functions($);
sub copy_functions($)
{
    my $src = shift;

    if ($ptrs{"$src"}{'done'}) {
        return;
    }
    $ptrs{"$src"}{'done'} = 1;

    my $select = $db->prepare('SELECT distinct file, function FROM function_ptr WHERE ptr = ?;');
    my $insert = $db->prepare('INSERT OR IGNORE INTO function_ptr VALUES (?, ?, ?, 1);');

    $select->execute($src);
    while (my ($file, $function) = $select->fetchrow_array()) {
        if ($function =~ / /) {
            copy_functions($function);
            next;
        }

        $insert->execute($file, $function, $ptrs{"$src"}{'ptr'});
    }
}

foreach my $key (keys(%ptrs)) {
    copy_functions($key);
}

$db->commit();
$db->disconnect();
