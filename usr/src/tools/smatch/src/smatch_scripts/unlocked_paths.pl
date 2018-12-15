#!/usr/bin/perl

use strict;

sub usage()
{
    print "Usage: unlocked_paths.pl <call tree file> <lock> <function>\n";
    print "Prints a list of paths to <function> which don't take the <lock>.\n";
    print "Generate the call tree file by running smatch with --call-tree.\n";
    exit(1);
}

my %f_map;

sub add_to_map($)
{
    my $callee = shift;

    if (!defined($f_map{$callee})) {
	$f_map{$callee} = {visited => 0, called_by => {}};
    }
}

sub add_called_by($$)
{
    my $caller = shift;
    my $callee = shift;
    my $tmp;

    %{$f_map{$callee}->{called_by}}->{$caller} = 1;
}

sub load_all($$)
{
    my $file = shift;
    my $lock = shift;

    open(FILE, "<$file");
    while (<FILE>) {
	if (/.*?:\d+ (.*?)\(\) info: func_call \((.*)\) (.*)/) {
	    my $caller = quotemeta $1;
	    my $locks = quotemeta $2;
	    my $callee = quotemeta $3;

	    add_to_map($callee);
	    if (!($locks =~ /$lock/)) {
		add_called_by($caller, $callee);
	    }
	}
    }
}

my @fstack;
sub print_fstack()
{
    foreach my $f (reverse @fstack) {
	printf "$f ";
    }
    printf "\n";
}

sub print_unlocked_paths($)
{
    my $function = shift;

    if (! defined %{$f_map{$function}}->{called_by}) {
	push @fstack, $function;
	print_fstack();
	pop @fstack;
	return;
    }

    push @fstack, $function;

    if (!%{$f_map{$function}}->{visited}) {
	%{$f_map{$function}}->{visited} = 1;
	foreach my $caller (keys %{%{$f_map{$function}}->{called_by}}){
	    print_unlocked_paths($caller);
	}
	%{$f_map{$function}}->{visited} = 0;

    }

    pop @fstack;
}

my $file = shift;
my $lock = shift;
my $target = shift;

if (!$file || !$lock || !$target) {
    usage();
}
if (! -e $file) {
    printf("Error:  $file does not exist.\n");
    exit(1);
}

load_all($file, $lock);
print_unlocked_paths($target);
