#!/usr/bin/perl

# This script is supposed to help use the param_mapper output.
# Give it a function and parameter and it lists the functions
# and parameters which are basically equivalent.

use strict;

sub usage()
{
    print("call_tree.pl <smatch output file>\n");
    print("call_tree.pl finds paths between two functions\n"); 
    exit(1);
}

my %param_map;

my $UNKNOWN  = 1;
my $NOTFOUND = 2;
my $FOUND    = 3;

my $path;

sub print_path()
{
    my $i = 0;

    foreach my $func (@{$path}) {
	if ($i++) {
	    print(", ");
	}
	print("$func");
    }
    print("\n");
    print("\n");
}

sub recurse($$)
{
    my $link = shift;
    my $target = shift;
    my $found = 0;

    if ($link =~ /$target/) {
	print_path();
	return 1;
    }
    if (%{$param_map{$link}}->{found} == $NOTFOUND) {
	return 0;
    }

    %{$param_map{$link}}->{found} = $NOTFOUND;

    foreach my $l (@{%{$param_map{$link}}->{links}}){
	push(@{$path}, $l);
	$found = recurse($l, $target);
	if (!$found) {
	    pop(@{$path});
	} else {
	    last;
	}
    }

    return $found;
}

sub search($$)
{
    my $start_func = shift;
    my $end_func = shift;

    foreach my $link (@{%{$param_map{$start_func}}->{links}}){
	%{$param_map{$start_func}}->{found} = $NOTFOUND;
	foreach my $l (@{%{$param_map{$start_func}}->{links}}){
	    %{$param_map{$l}}->{found} = $NOTFOUND;
	}
	$path = [$start_func, $link];
	%{$param_map{$link}}->{found} = $UNKNOWN;
	recurse($link, $end_func);
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
	if (/.*?:\d+ (.*?)\(\) info: func_call (.*)/) {
	    add_link("$1", "$2");
	}
    }
}

sub set_all_unknown()
{
    my $i = 0;

    foreach my $func (keys %param_map){
	%{$param_map{$func}}->{found} = $UNKNOWN;
    }
}

my $file = shift();
if (!$file) {
    usage();
}

if (! -e $file) {
    printf("Error:  $file does not exist.\n");
    exit(1);
}

print("Loading functions...\n");
load_all($file);

while (1) {
    my $start_func;
    my $end_func;

    print("Enter the start function:  ");
    $start_func = <STDIN>;
    $start_func =~ s/^\s+|\s+$//g;
    print("Enter the target function:  ");
    $end_func = <STDIN>;
    $end_func =~ s/^\s+|\s+$//g;


    print("$start_func to $end_func\n");
    if ($start_func =~ /./ && $end_func =~ /./) {
	search($start_func, $end_func);
    }

    set_all_unknown();
}
