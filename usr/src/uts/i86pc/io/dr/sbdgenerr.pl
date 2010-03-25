#!/usr/bin/perl
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright (c) 2000 by Sun Microsystems, Inc.
# All rights reserved.
#

sub trim {
	my ($line) = @_;
	$line =~ s#/\*|\*/##g;
	$line =~ s#^\s+|\s+$##g;
	return $line;
}

my $filter = 0;
my %prefix;
while ($#ARGV >= 0) {
	$prefix{$ARGV[0]} = 0;
	shift @ARGV;
	$filter = 1;
}

my $base;
my $bnd;
my @text;
my @sets;
while (<STDIN>) {
	my $n = m@^#define\s(E\w\w\w)\w+\s+(\d+)(.*)@;
	next unless ($n > 0);
	next unless ($filter == 0 || defined $prefix{$1});
	my $txt = trim($3);
	if (length($txt) == 0) {
		my $l = <STDIN>;
		$txt = trim($l);
	}

	$base = $2 if (!defined $base);
	if (defined $bnd && $2 != $bnd + 1) {
		push(@sets, { base => $base, bnd => $bnd });
		$base = $2;
	}
	$bnd = $2;
	push(@text, $txt);
}

push(@sets, { base => $base, bnd => $bnd });

printf "#include <sys/sbd_ioctl.h>\n";

my $i = 0;
my $s = 0;
do {
	my $set = $sets[$s];

	printf "static char *sbd_t%d[] = {\n", $set->{base};
	my $n = $set->{bnd} - $set->{base} + 1;
	while ($n--) {
		printf "\t\"%s\",\n", $text[$i++];
	}
	printf "};\n";
} while (++$s <= $#sets);

printf "sbd_etab_t sbd_etab[] = {\n";
$s = 0;
do {
	my $set = $sets[$s];
	printf "\t{ %d, %d, sbd_t%d },\n",
		$set->{base}, $set->{bnd}, $set->{base};
} while (++$s <= $#sets);
printf "};\n";
printf "int sbd_etab_len = %d;\n", $s;
