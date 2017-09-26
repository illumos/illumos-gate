#!/usr/bin/perl -w
#
# COPYRIGHT 2013 Pluribus Networks Inc.
#
# All rights reserved. This copyright notice is Copyright Management
# Information under 17 USC 1202 and is included to protect this work and
# deter copyright infringement.  Removal or alteration of this Copyright
# Management Information without the express written permission from
# Pluribus Networks Inc is prohibited, and any such unauthorized removal
# or alteration will be a violation of federal law.

use strict;

my @Sections = split(/\n/, `elfedit -r -e \'shdr:sh_name -osimple\' $ARGV[0] 2>&1`);

foreach my $Section (@Sections) {
	if ($Section =~ "^set_") {
		print "\tfixing $Section\n";

		chomp(my $SectionAddr = `elfedit -r -e \'shdr:sh_addr -onum $Section\' $ARGV[0] 2>&1`);
		chomp(my $SectionSize = `elfedit -r -e \'shdr:sh_size -onum $Section\' $ARGV[0] 2>&1`);
		my $SectionEnd = hex($SectionAddr) + hex($SectionSize);

		`elfedit -e \'sym:st_bind __start_$Section global\' $ARGV[0] 2>&1`;
		`elfedit -e \'sym:st_value __start_$Section $SectionAddr\' $ARGV[0] 2>&1`;
		`elfedit -e \'sym:st_shndx __start_$Section $Section\' $ARGV[0] 2>&1`;
		`elfedit -e \'sym:st_bind __stop_$Section global\' $ARGV[0] 2>&1`;
		`elfedit -e \'sym:st_value __stop_$Section $SectionEnd\' $ARGV[0] 2>&1`;
		`elfedit -e \'sym:st_shndx __stop_$Section $Section\' $ARGV[0] 2>&1`;
	}
}
