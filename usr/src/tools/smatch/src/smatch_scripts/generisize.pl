#!/usr/bin/perl

use strict;

sub help()
{
    print "usage: $0 [-r]\n";
    print "Counts the number of errors of each type.\n";
    print "-r means down to the nearest 10.\n";
    exit 1;
}

my $round;
my $arg = shift;
if ($arg =~ /-h/) {
    help();
} elsif ($arg =~ /-r/) {
    $round = 1;
}

my %msgs;

sub add_msg($)
{
    my $msg = shift;

    if (defined $msgs{$msg}) {
	$msgs{$msg}++;
    } else {
	$msgs{$msg} = 1;
    }
}

while (<>) {
    s/^.*?:\d+(|:\d+:) .*? //;
    s/[us](16|32|64)(min|max)//g;
    s/0x\w+//g;
    s/[01234567890]//g;
    if ($_ =~ /can't/) {
        s/(.*can't.*').*?('.*)/$1 $2/;
        s/(.*?)'.*?'(.*can't.*)/$1 $2/;
    } elsif ($_ =~ /don't/) {
    	s/(.*don't.*').*?('.*)/$1 $2/;
    } else {
    	s/'.*?'/''/g;
    }
    s/,//g;
    s/\(\w+ returns null\)/(... returns null)/;
    s/dma on the stack \(.*?\)/dma on the stack (...)/;
    s/possible ERR_PTR '' to .*/possible ERR_PTR '' to .../;
    s/inconsistent returns ([^ ]+?) locked \(\)/inconsistent returns ... locked ()/;
    s/(.*) [^ ]* (too large for) [^ ]+ (.*)/$1 $2 $3/;

    add_msg($_);
}

foreach my $key (sort { $msgs{$b} <=> $msgs{$a} } keys %msgs) {
    my $count = $msgs{$key};

    if ($round) {
	$count = $msgs{$key} - $msgs{$key} % 10;
    }
    print "$count $key";
}
