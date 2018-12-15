#!/usr/bin/perl -w

use strict;
use warnings;
use bigint;
use DBI;
use Data::Dumper;

my $project = shift;
my $warns = shift;
my $db_file = shift;
my $db = DBI->connect("dbi:SQLite:$db_file", "", "", {AutoCommit => 0});

my $raw_line;

sub text_to_int($)
{
    my $text = shift;

    if ($text =~ /s64min/) {
        return -(2**63);
    } elsif ($text =~/s32min/) {
        return -(2**31);
    } elsif ($text =~ /s16min/) {
        return -(2**15);
    } elsif ($text =~ /s64max/) {
        return 2**63 - 1;
    } elsif ($text =~ /s32max/) {
        return 2**31 - 1;
    } elsif ($text =~ /s16max/) {
        return 2**15 - 1;
    } elsif ($text =~ /u64max/) {
        return 2**62 - 1;
    } elsif ($text =~ /u32max/) {
        return 2**32 - 1;
    } elsif ($text =~ /u16max/) {
        return 2**16 - 1;
    }
    if ($text =~ /\((.*?)\)/) {
        $text = $1;
    }
    if (!($text =~ /^[-0123456789]/)) {
        return "NaN";
    }

    return int($text);
}

sub add_range($$$)
{
    my $union = shift;
    my $min = shift;
    my $max = shift;
    my %range;
    my @return_union;
    my $added = 0;
    my $check_next = 0;

    $range{min} = $min;
    $range{max} = $max;

    foreach my $tmp (@$union) {
        if ($added) {
            push @return_union, $tmp;
            next;
        }

        if ($range{max} < $tmp->{min}) {
            push @return_union, \%range;
            push @return_union, $tmp;
            $added = 1;
        } elsif ($range{min} <= $tmp->{min}) {
            if ($range{max} <= $tmp->{max}) {
                $range{max} = $tmp->{max};
                push @return_union, \%range;
                $added = 1;
            }
        } elsif ($range{min} <= $tmp->{max}) {
            if ($range{max} <= $tmp->{max}) {
                push @return_union, $tmp;
                $added = 1;
            } else {
                $range{min} = $tmp->{min};
            }
        } else {
            push @return_union, $tmp;
        }
    }

    if (!$added) {
        push @return_union, \%range;
    }

    return \@return_union;
}

sub print_num($)
{
    my $num = shift;

    if ($num < 0) {
        return "(" . $num . ")";
    } else {
        return $num;
    }
}

sub print_range($)
{
    my $range = shift;

    if ($range->{min} == $range->{max}) {
        return print_num($range->{min});
    } else {
        return print_num($range->{min}) . "-" .  print_num($range->{max});
    }
}

sub print_info($$)
{
    my $type = shift;
    my $union = shift;
    my $printed_range = "";
    my $i = 0;

    foreach my $range (@$union) {
        if ($i) {
            $printed_range = $printed_range . ",";
        }
        $i++;
        $printed_range = $printed_range . print_range($range);
    }
    my $sql = "insert into type_size values ('$type', '$printed_range');";
    $db->do($sql);
}


$db->do("PRAGMA cache_size = 800000");
$db->do("PRAGMA journal_mode = OFF");
$db->do("PRAGMA count_changes = OFF");
$db->do("PRAGMA temp_store = MEMORY");
$db->do("PRAGMA locking = EXCLUSIVE");

my ($sth, @row, $cur_type, $type, @ranges, $range_txt, %range, $min, $max, $union_array, $skip);

$sth = $db->prepare('select * from function_type_size order by type');
$sth->execute();

$skip = 0;
$cur_type = "";
while (@row = $sth->fetchrow_array()) {
    $raw_line = join ',', @row;

    $type = $row[2];

    if ($cur_type ne "$type") {
        if ($cur_type ne "" && $skip == 0) {
            print_info($cur_type, $union_array);
        }
        $cur_type = $type;
        $union_array = ();
        $skip = 0;
    }

    @ranges = split(/,/, $row[3]);
    foreach $range_txt (@ranges) {
        if ($range_txt =~ /(.*[^(])-(.*)/) {
            $min = text_to_int($1);
            $max = text_to_int($2);
        } else {
            $min = text_to_int($range_txt);
            $max = $min;
        }
        if ($min =~ /NaN/ || $max =~ /NaN/) {
            $skip = 1;
        }
        $union_array = add_range($union_array, $min, $max);
    }
}
if ($skip == 0) {
    print_info($cur_type, $union_array);
}

$db->commit();
$db->disconnect();
