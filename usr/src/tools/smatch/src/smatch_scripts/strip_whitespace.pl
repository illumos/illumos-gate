#!/usr/bin/perl

use strict;

my $file = shift();
open FILE, "<$file";
my $txt = do { local $/;  <FILE> };

# strip C99 comments
$txt =~ s/\/\/.*//g;
# strip newlines
$txt =~ s/\n//g;
# strip remaining comments
$txt =~ s/\/\*.*?\*\///g;
# strip tabs
$txt =~ s/\t//g;
# strip spaces
$txt =~ s/ //g;
# add newlines
$txt =~ s/;/;\n/g;
$txt =~ s/{/{\n/g;
$txt =~ s/}/}\n/g;

print "$txt\n";
