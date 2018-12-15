#!/usr/bin/perl

use strict;

my $cur_struct = "";
my $printed = 0;

while (<>) {
    if ($_ =~ /^struct (\w+) {/) {
	$cur_struct = $1;
	$printed = 0;
	next;
    }
    if ($_ =~ /.* hole,.*/ && !$printed) {
	print "$cur_struct\n";
	$printed = 1;
    }
}
