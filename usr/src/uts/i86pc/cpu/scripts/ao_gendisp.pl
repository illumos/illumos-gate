#!/bin/perl
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

use strict;
use File::Basename;

my $PROGNAME = basename($0);

my ($funcunit, $error);
my @funcunits = ();

my $state = "initial";

sub usage() {
	print STDERR "Usage: $PROGNAME inputfile\n";
	exit(2);
}

sub bail() {
	print STDERR "$PROGNAME: ", join(" ", @_), "\n";
	exit(1);
}

sub parsebail() {
	print STDERR "$PROGNAME: $::infile: $.: ", join(" ", @_), "\n";
	exit(1);
}

sub print_header() {
	print "#include \"ao_mca_disp.h\"\n\n";
}

sub print_footer() {
	print "const ao_error_disp_t *ao_error_disp[] = {\n";

	foreach my $name (@funcunits) {
		print "\t$name,\n";
	}

	print "};\n";
}

sub funcunit_begin() {
	my $arrnm = "ao_error_disp_" . $_[0];
	print "static const ao_error_disp_t " . $arrnm . "[] = {\n";

	@funcunits = (@funcunits, $arrnm);
}

sub funcunit_end() {
	print "\tNULL\n};\n\n";
}

sub error_begin() {
	my ($ereport_name) = @_;

	$ereport_name =~ tr/[a-z]./[A-Z]_/;
	my $flags_name = $ereport_name;
	$flags_name =~ s/EREPORT_/EREPORT_PAYLOAD_FLAGS_/;

	print "\tFM_$ereport_name,\n\tFM_$flags_name,\n";
}

sub error_end() {
	print "\t},\n\n";
}

sub print_bits() {
	my $name = $_[0];
	my @bits = @_[1..$#_];

	if (@bits == 0) {
		print "\t0,";
	} elsif (@bits == 1) {
		print "\t$bits[0],";
	} else {
		print "\t( ", join(" | ", @bits), " ),";
	}

	print " /* $name */\n";
}

sub field_burst() {
	my ($field, $valuesref, $name, $prefix) = @_;

	if ($field eq "-") {
		return ();
	}

	map {
		if (!defined ${$valuesref}{$_}) {
			&parsebail("unknown $name value `$_'");
		}
		$_ = ${$valuesref}{$_};
		tr/[a-z]/[A-Z]/;
		$prefix . "_" . $_;
	} split(/\//, $field);
}

sub bin2dec() {
	my $bin = $_[0];
	my $dec = 0;

	foreach my $bit (split(//, $bin)) {
		$dec = $dec * 2 + ($bit eq "1" ? 1 : 0);
	}

	$dec;
}

sub state_funcunit() {
	my $val = $_[0];

	if (defined $::funcunit) {
		&funcunit_end();
	}

	$::funcunit = $val;
	undef $::error;
	&funcunit_begin($::funcunit);
}

sub state_desc() {
	my $desc = $_[0];

	print "\t/* $desc */\n\t{\n";
}

sub state_error() {
	$::error = $_[0];
	&error_begin($::error);
}

sub state_mask_on() {
	@::mask_on = map { tr/[a-z]/[A-Z]/; $_; } split(/,\s*/, $_[0]);
}

sub state_mask_off() {
	my @mask_off = map { tr/[a-z]/[A-Z]/; $_; } split(/,\s*/, $_[0]);

	&print_bits("mask", @::mask_on, @mask_off);
	&print_bits("mask_res", @::mask_on);
}

sub state_code() {
	my ($ext, $type, $pp, $t, $r4, $ii, $ll, $tt) = split(/\s+/, $_[0]);

	my %tt_values = ( instr => 1, data => 1, gen => 1, '-' => 1 );
	my %ll_values = ( l0 => 1, l1 => 1, l2 => 1, lg => 1 );

	my %r4_values = (
		gen => 'gen',
		rd => 'rd',
		wr => 'wr',
		drd => 'drd',
		dwr => 'dwr',
		ird => 'ird',
		pf => 'prefetch',
		ev => 'evict',
		snp => 'snoop',
	        '-' => '-');

	my %pp_values = (
		src => 'src',
		rsp => 'rsp',
		obs => 'obs',
		gen => 'gen',
		'-' => '-' );

	my %t_values = ( 0 => 1, 1 => 1, '-' => 1 );

	my %ii_values = (
		mem => 'mem',
		io => 'io',
		gen => 'gen',
		'-' => '-' );

	if (!defined $tt_values{$tt}) {
		&parsebail("unknown tt value `$tt'");
	}

	if (!defined $ll_values{$ll}) {
		&parsebail("unknown ll value `$ll'");
	}

	my @r4 = &field_burst($r4, \%r4_values, "r4", "AO_MCA_R4_BIT");

	my @pp = ($pp eq '-') ? () :
	    &field_burst($pp, \%pp_values, "pp", "AO_MCA_PP_BIT");

	if (!defined $t_values{$t}) {
		&parsebail("unknown t value `$t'");
	}

	my @ii = ($ii eq '-') ? () :
	    &field_burst($ii, \%ii_values, "ii", "AO_MCA_II_BIT");

	map {
		tr/[a-z]/[A-Z]/;
	} ($ii, $ll, $tt);

	if ($type eq "bus") {
		if ($pp eq "-" || $t eq "-" || $r4 eq "-" || $ii eq "-" ||
		    $ll eq "-" ||
		    $tt ne "-") {
			&parsebail("invalid members for bus code type");
		}

		print "\tAMD_ERRCODE_MKBUS(" .
		    "0, " . # pp
		    "AMD_ERRCODE_T_" . ($t ? "TIMEOUT" : "NONE") . ", " .
		    "0, " . # r4
		    "0, " . # ii
		    "AMD_ERRCODE_LL_$ll),\n";

	} elsif ($type eq "mem") {
		if ($r4 eq "-" || $tt eq "-" || $ll eq "-" ||
		    $pp ne "-" || $t ne "-" || $ii ne "-") {
			&parsebail("invalid members for mem code type");
		}

		print "\tAMD_ERRCODE_MKMEM(" .
		    "0, " . # r4
		    "AMD_ERRCODE_TT_$tt, " .
		    "AMD_ERRCODE_LL_$ll),\n";

	} elsif ($type eq "tlb") {
		if ($tt eq "-" || $ll eq "-" ||
		    $r4 ne "-" || $pp ne "-" || $t ne "-" || $ii ne "-") {
			&parsebail("invalid members for tlb code type");
		}

		print "\tAMD_ERRCODE_MKTLB(" .
		    "AMD_ERRCODE_TT_$tt, " .
		    "AMD_ERRCODE_LL_$ll),\n";
	} else {
		&parsebail("unknown code type `$type'");
	}

	print "\t" . &bin2dec($ext) . ", /* ext code $ext */\n";

	&print_bits("pp_bits", @pp);
	&print_bits("ii_bits", @ii);
	&print_bits("r4_bits", @r4);
}

sub state_panic() {
	my $val = $_[0];

	if ($val eq "") {
		print "\t0, /* panic_when */\n";
	} else {
		$val =~ tr/[a-z]/[A-Z]/;
		print "\tAO_AED_PANIC_$val,\n";
	}
}

sub state_flags() {
	my @flags = split(/,\s*/, $_[0]);

	@flags = map { tr/[a-z]/[A-Z]/; "AO_AED_F_" . $_; } @flags;

	&print_bits("flags", @flags);
}

my %stateparse = (
	funcunit	=> [ \&state_funcunit, "desc" ],
	desc		=> [ \&state_desc, "error" ],
	error		=> [ \&state_error, "mask on" ],
	'mask on'	=> [ \&state_mask_on, "mask off" ],
	'mask off'	=> [ \&state_mask_off, "code" ],
	code		=> [ \&state_code, "panic" ],
	panic		=> [ \&state_panic, "flags" ],
	flags		=> [ \&state_flags, "initial" ]
);

usage unless (@ARGV == 1);

my $infile = $ARGV[0];
open(INFILE, "<$infile") || &bail("failed to open $infile: $!");

&print_header();

while (<INFILE>) {
	chop;

	/^#/ && next;
	/^$/ && next;

	if (!/^\s*(\S[^=]*\S)\s*=\s*(\S.*)?$/) {
		&parsebail("failed to parse");
	}

	my ($keyword, $val) = ($1, $2);

	if ($state eq "initial") {
		if ($keyword eq "funcunit") {
			$state = "funcunit";
		} elsif ($keyword eq "desc") {
			$state = "desc";
		} else {
			&parsebail("unexpected keyword $keyword between " .
			    "errors");
		}

	} elsif ($state eq "desc") {
		if ($keyword eq "funcunit") {
			$state = "funcunit";
		}
	}

	if ($keyword ne $state) {
		&parsebail("keyword `$keyword' invalid here; expected `$state'");
	}

	if (!defined $stateparse{$state}) {
		&parsebail("attempt to transition to invalid state `$state'");
	}

	my ($handler, $next) = @{$stateparse{$state}};

	&{$handler}($val);

	$state = $next;

	if ($state eq "initial") {
		&error_end();
	}
}

close(INFILE);

if ($state ne "initial" && $state ne "desc") {
	&bail("input file ended prematurely");
}

if (defined $::funcunit) {
	&funcunit_end();
} else {
	&bail("no functional units defined");
}

&print_footer;
