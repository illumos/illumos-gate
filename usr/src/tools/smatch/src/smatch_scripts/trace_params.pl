#!/usr/bin/perl

# This script is supposed to help use the param_mapper output.
# Give it a function and parameter and it lists the functions
# and parameters which are basically equivalent.

use strict;

sub usage()
{
    print ("trace_params.pl <smatch output file> <function> <parameter>\n");
    exit(1);
}

my %param_map;

my $UNKNOWN  = 1;
my $NOTFOUND = 2;
my $FOUND    = 3;

sub recurse($$)
{
    my $link = shift;
    my $target = shift;
    my $found = 0;

    if ($link =~ /$target/) {
        $param_map{$link}->{found} = $FOUND;
        return 1;
    }

    if ($param_map{$link}->{found} == $FOUND) {
        return 1;
    }
    if ($param_map{$link}->{found} == $NOTFOUND) {
        return 0;
    }

    $param_map{$link}->{found} = $NOTFOUND;
    foreach my $l (@{$param_map{$link}->{links}}){
        $found = recurse($l, $target);
        if ($found) {
            $param_map{$link}->{found} = $FOUND;
            return 1;
        }
    }

    return 0;
}

sub compress_all($$)
{
    my $f = shift;
    my $p = shift;
    my $target = "$f%$p";

    foreach my $link (keys %param_map){
        recurse($link, $target);
    }
}

sub add_link($$)
{
    my $one = shift;
    my $two = shift;

    if (!defined($param_map{$one})) {
        $param_map{$one} = {found => $UNKNOWN, links => []};
    }
    push @{$param_map{$one}->{links}}, $two;
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

sub print_found()
{
    foreach my $func (keys %param_map){
        my $tmp = $param_map{$func};

        if ($tmp->{found} == $FOUND) {
            my ($f, $p) = split(/%/, $func);
            print("$f $p\n");
        }
    }
}

my $file = shift();
my $func = shift();
my $param = shift();

if (!$file or !$func or !defined($param)) {
    usage();
}

if (! -e $file) {
    printf("Error:  $file does not exist.\n");
    exit(1);
}

load_all($file);
compress_all($func, $param);
print_found();
