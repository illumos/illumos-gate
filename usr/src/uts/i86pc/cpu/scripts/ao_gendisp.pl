#!/bin/perl
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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# ident	"%Z%%M%	%I%	%E% SMI"
#

use strict;
use File::Basename;

my $PROGNAME = basename($0);

my ($funcunit, $error);
my @funcunits = ();
my @errorrefs = ();

my $codelinesin = 0;	# number of input 'code' lines for an ereport type
my $codeoutlen = 0;	# number of output lines from sub state_code

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

sub error_alloc() {
	my @a = ();

	push(@::errorrefs, \@a);
	return (\@a);
}

sub error_dup() {
	my ($drop) = @_;
	my $newref = &error_alloc();

	my $zeroref = $::errorrefs[0];

	my $n = $#$zeroref - $drop;

	@$newref = @$zeroref[0 .. $n];
}

sub code_lines() {
	return ($::codelinesin++);
}

sub error_init() {
	&error_alloc();
	$::codelinesin = 0;
}

sub error_reset() {
	@::errorrefs = ();
	$::codelinesin = 0;
	$::codeoutlen = 0;
}

sub errout() {
	my ($line) = @_;

	foreach my $ref (@::errorrefs) {
		push(@$ref, $line);
	}
}

sub errout_N() {
	my ($instance, $line) = @_;
	my $ref = @::errorrefs[$instance];
	push(@$ref, $line);
	return 1;
}

sub print_errout() {
	foreach my $ref (@::errorrefs) {
		print @$ref;
	}
}

sub print_header() {
	print "#include <sys/mca_x86.h>\n";
	print "#include \"ao_mca_disp.h\"\n\n";
}

sub print_footer() {
	print 'const ao_error_disp_t *ao_error_disp[] = {' . "\n";

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
	print "\t{ NULL }\n};\n\n";
}

sub error_begin() {
	my ($ereport_name) = @_;

	$ereport_name =~ tr/[a-z]./[A-Z]_/;
	my $flags_name = $ereport_name;
	$flags_name =~ s/EREPORT_/EREPORT_PAYLOAD_FLAGS_/;

	&errout("\tFM_$ereport_name,\n\tFM_$flags_name,\n");
}

sub error_end() {
	&errout("\t},\n\n");

	&print_errout();

	&error_reset();
}

sub print_bits() {
	my $name = $_[0];
	my @bits = @_[1..$#_];
	my $out = "";

	if (@bits == 0) {
		$out = "\t0,";
	} elsif (@bits == 1) {
		$out = "\t$bits[0],";
	} else {
		$out = "\t( " . join(" | ", @bits) . " ),";
	}

	$out .= " /* $name */" if (defined $name);
	$out .= "\n";

	return ($out);
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

	&error_init();

	&errout("\t/* $desc */\n\t{\n");
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

	&errout(&print_bits("mask", @::mask_on, @mask_off));
	&errout(&print_bits("mask_res", @::mask_on));
}

sub state_code() {
	my ($ext, $type, $pp, $t, $r4, $addr, $ii, $ll, $tt) =
	    split(/\s+/, $_[0]);

	my %tt_values = ( instr => 1, data => 1, gen => 1, '-' => 1 );
	my %ll_values = ( l0 => 1, l1 => 1, l2 => 1, lg => 1 );

	my %r4_values = (
		'err' => 'err',
		'rd' => 'rd',
		'wr' => 'wr',
		'drd' => 'drd',
		'dwr' => 'dwr',
		'ird' => 'ird',
		'pf' => 'prefetch',
		'ev' => 'evict',
		'snp' => 'snoop',
	        '-' => '-');

	my %pp_values = (
		'src' => 'src',
		'res' => 'res',
		'obs' => 'obs',
		'gen' => 'gen',
		'-' => '-' );

	my %t_values = ( 0 => 1, 1 => 1, '-' => 1 );

	my %ii_values = (
		'mem' => 'mem',
		'io' => 'io',
		'gen' => 'gen',
		'-' => '-' );

	my $instance = &code_lines();
	if ($instance > 0) {
		&error_dup($::codeoutlen);	# dup info thus far
	}

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

		$::codeoutlen += &errout_N($instance, "\tAMD_ERRCODE_MKBUS(" .
		    "0, " . # pp
		    "MCAX86_ERRCODE_T_" . ($t ? "TIMEOUT" : "NONE") . ", " .
		    "0, " . # r4
		    "0, " . # ii
		    "MCAX86_ERRCODE_LL_$ll),\n");

	} elsif ($type eq "mem") {
		if ($r4 eq "-" || $tt eq "-" || $ll eq "-" ||
		    $pp ne "-" || $t ne "-" || $ii ne "-") {
			&parsebail("invalid members for mem code type");
		}

		$::codeoutlen += &errout_N($instance, "\tAMD_ERRCODE_MKMEM(" .
		    "0, " . # r4
		    "MCAX86_ERRCODE_TT_$tt, " .
		    "MCAX86_ERRCODE_LL_$ll),\n");

	} elsif ($type eq "tlb") {
		if ($tt eq "-" || $ll eq "-" ||
		    $r4 ne "-" || $pp ne "-" || $t ne "-" || $ii ne "-") {
			&parsebail("invalid members for tlb code type");
		}

		$::codeoutlen += &errout_N($instance, "\tAMD_ERRCODE_MKTLB(" .
		    "MCAX86_ERRCODE_TT_$tt, " .
		    "MCAX86_ERRCODE_LL_$ll),\n");
	} else {
		&parsebail("unknown code type `$type'");
	}

	$::codeoutlen += &errout_N($instance, "\t" . &bin2dec($ext) .
	    ", /* ext code $ext */\n");

	$::codeoutlen += &errout_N($instance, &print_bits("pp_bits", @pp));
	$::codeoutlen += &errout_N($instance, &print_bits("ii_bits", @ii));
	$::codeoutlen += &errout_N($instance, &print_bits("r4_bits", @r4));

	my $valid_hi;
	my $valid_lo;

	if ($addr eq "none") {
		$valid_hi = $valid_lo = 0;
	} elsif ($addr =~ /<(\d+):(\d+)>/) {
		$valid_hi = $1;
		$valid_lo = $2;
	} else {
		&parsebail("invalid addr specification");
	}
	$::codeoutlen += &errout_N($instance, "\t" . $valid_hi .
	    ", /* addr valid hi */\n");
	$::codeoutlen += &errout_N($instance, "\t" . $valid_lo .
	    ", /* addr valid lo */\n");
}

sub state_panic() {
	my @vals = split(/,\s*/, $_[0]);

	if ($#vals < 0) {
		&errout("\t0, /* panic_when */\n");
	} else {
		@vals = map { tr/[a-z]/[A-Z]/; "AO_AED_PANIC_" . $_; } @vals;
		&errout(&print_bits("panic_when", @vals));
	}
}

sub state_flags() {
	my @flags = split(/,\s*/, $_[0]);

	@flags = map { tr/[a-z]/[A-Z]/; "AO_AED_F_" . $_; } @flags;

	&errout(&print_bits("flags", @flags));
}

sub state_errtype() {
	my @types = split(/,\s*/, $_[0]);

	@types = map { tr/[a-z]/[A-Z]/; "AO_AED_ET_" . $_; } @types;

	&errout(&print_bits("errtype", @types));
}

my %stateparse = (
	funcunit	=> [ \&state_funcunit, 'desc' ],
	desc		=> [ \&state_desc, 'error' ],
	error		=> [ \&state_error, 'mask on' ],
	'mask on'	=> [ \&state_mask_on, 'mask off' ],
	'mask off'	=> [ \&state_mask_off, 'code' ],
	code		=> [ \&state_code, 'code|panic' ],
	panic		=> [ \&state_panic, 'flags' ],
	flags		=> [ \&state_flags, 'errtype' ],
	errtype		=> [ \&state_errtype, 'initial' ]
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

	if (!($keyword =~ /$state/)) {
		&parsebail("keyword `$keyword' invalid here; expected " .
		    "`$state'");
	}
	$state = $keyword;	# disambiguate between multiple legal states

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
