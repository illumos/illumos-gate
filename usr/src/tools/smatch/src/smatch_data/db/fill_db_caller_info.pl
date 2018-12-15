#!/usr/bin/perl -w

use strict;
use DBI;
use Scalar::Util qw(looks_like_number);

sub usage()
{
    print "usage:  $0 <project> <smatch_warns.txt> <db_file>\n";
    exit(1);
}

my %too_common_funcs;
sub get_too_common_functions($$$)
{
    my $path = shift;
    my $project = shift;
    my $warns = shift;

    open(FUNCS, "grep 'SQL_caller_info: ' $warns | grep '%call_marker%' | cut -d \"'\" -f 6 | sort | uniq -c | ");

    while (<FUNCS>) {
        if ($_ =~ /(\d+) (.*)/) {
            if (int($1) > 200) {
                $too_common_funcs{$2} = 1;
            }
        }
    }

    close(FUNCS);

    open(FILE, ">", "$path/../$project.common_functions");
    foreach my $func (keys %too_common_funcs) {
        if ($func =~ / /) {
            next;
        }
        print FILE "$func\n";
    }
    close(FILE);
}

my $exec_name = $0;
my $path = $exec_name;
$path =~ s/(.*)\/.*/$1/;
my $project = shift;
my $warns = shift;
my $db_file = shift;

if (!defined($db_file)) {
    usage();
}

get_too_common_functions($path, $project, $warns);

my $db = DBI->connect("dbi:SQLite:$db_file", "", "", {AutoCommit => 0});
$db->do("PRAGMA cache_size = 800000");
$db->do("PRAGMA journal_mode = OFF");
$db->do("PRAGMA count_changes = OFF");
$db->do("PRAGMA temp_store = MEMORY");
$db->do("PRAGMA locking = EXCLUSIVE");

foreach my $func (keys %too_common_funcs) {
    $db->do("insert into common_caller_info values ('unknown', 'too common', '$func', 0, 0, 0, -1, '', '');");
}

my $call_id = 0;
my ($fn, $dummy, $sql);

open(WARNS, "<$warns");
while (<WARNS>) {
    # test.c:11 frob() SQL_caller_info: insert into caller_info values ('test.c', 'frob', '__smatch_buf_size', %CALL_ID%, 1, 0, -1, '', ');

    if (!($_ =~ /^.*? \w+\(\) SQL_caller_info: /)) {
        next;
    }
    ($dummy, $dummy, $dummy, $dummy, $dummy, $fn, $dummy) = split(/'/);

    if ($fn =~ /__builtin_/) {
        next;
    }
    if ($fn =~ /^(printk|memset|memcpy|kfree|printf|dev_err|writel)$/) {
        next;
    }

    ($dummy, $dummy, $sql) = split(/:/, $_, 3);

    if ($sql =~ /%call_marker%/) {
        $sql =~ s/%call_marker%//; # don't need this taking space in the db.
        $call_id++;
    }
    $sql =~ s/%CALL_ID%/$call_id/;

    $db->do($sql);
}
$db->commit();
$db->disconnect();
