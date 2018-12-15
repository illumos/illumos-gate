#!/usr/bin/perl

use strict;

sub usage()
{
    print "$0 <smatch output file> <function> <parameter>\n";
    print "Give this program a function and parameter and it follows to find\n";
    print "how the parameter gets passed down to lower levels.\n'";
    exit(1);
}

my %param_map;

my $UNUSED   = 0;
my $USED     = 1;

sub print_link($)
{
    my $link = shift;

    $link =~ s/%/ /;
    print "$link\n";
}

sub recurse($)
{
    my $link = shift;

    if ($param_map{$link}{used} == $USED) {
	return;
    }
    ${param_map}{$link}->{used} = $USED;

    print_link($link);

    foreach my $l (@{$param_map{$link}{links}}){
	recurse($l);
    }

}

sub follow($$)
{
    my $f = shift;
    my $p = shift;

    recurse("$f%$p");
}

sub add_link($$)
{
    my $one = shift;
    my $two = shift;

    if (!defined($param_map{$one})) {
	$param_map{$one} = {used => $UNUSED, links => []};
    }
    push @{$param_map{$one}{links}}, $two;
}

sub load_all($)
{
    my $file = shift;

    open(FILE, "<$file");
    while (<FILE>) {
	if (/.*?:\d+ (.*?)\(\) info: param_mapper (\d+) => (.*?) (\d+)/) {
	    add_link("$1%$2", "$3%$4");
	}
    }
}

sub set_all_unused()
{
    foreach my $func (keys %param_map){
	($param_map{$func}{used} = $UNUSED);
    }

}

my $file = shift();
my $func = shift();
my $param = shift();

if (!defined($file) or !defined($func) or !defined($param)) {
    usage();
}

if (! -e $file) {
    printf("Error:  $file does not exist.\n");
    exit(1);
}

load_all($file);

while (1) {
    follow($func, $param);

    $func = shift();
    $param = shift();
    if (!defined($func) || !defined($param)) {
	last;
    }
    set_all_unused();
}
