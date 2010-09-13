#!/usr/bin/perl -w
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
# ident	"%Z%%M%	%I%	%E% SMI"
#
# Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#
# bustcode -- Given a Message ID, bust it up into fields and print them
#
# usage: bustcode [-cq] message-id
#
#	-c	trace checksumming process
#
#	-q	quiet mode, only output dictname and dictval
#
# This script is used for testing & debugging of libdiagcode
# (PSARC/2003/323).
#
# NOTE: This implementation may not support the full range of
# possible diagcodes (currently it only works up to 2^63-1 or
# 9223372036854775807 on most machines).
#
# XXX could probably fix the above limitation by using Math::BigInt.
#

use strict;
use integer;

use Getopt::Std;

use vars qw($opt_c $opt_q);

my $Myname = $0;	# save our name for error messages
$Myname =~ s,.*/,,;

$SIG{HUP} = $SIG{INT} = $SIG{TERM} = $SIG{__DIE__} = sub {
	die "$Myname: ERROR: @_";
};

# the alphabet used for diagcodes, indexed by 5-bit values
my $Alphabet = "0123456789ACDEFGHJKLMNPQRSTUVWXY";

# map codelen to the two-bit binary code size field in diagcode
my @Codesize = ( '00', '01', '10', '11' );

# map codelen to the sprintf format we use for dictval
my @Dictvalformat = ( '%021b', '%038b', '%055b', '%072b' );

# map codelen to number of data bits for dictval
my @Dictvalbits = ( 21, 38, 55, 72 );

# map codelen to the number of checksum bits used in diagcode
my @Csumbits = ( 5, 8, 11, 14 );

#
# bustcode -- bust up a Message ID into fields
#
sub bustcode {
	my $id = shift;
	my $dictname;
	my $xpart;
	my $dictval;
	my $csum = 0;
	my $csumfromcode;
	my $bits;
	my $codelen;
	my $x;
	my $i;

	die "\"$id\" malformed Message ID\n"
	    unless $id =~ /^(\w+)-(([a-zA-Z0-9]{4}-){1,4}[a-zA-Z0-9]{2})$/;

	$dictname = $1;
	$xpart = $2;

	if ($xpart =~ /(([a-zA-Z0-9]{4}-){4}[a-zA-Z0-9]{2})/) {
		$codelen = 3;
	} elsif ($xpart =~ /(([a-zA-Z0-9]{4}-){3}[a-zA-Z0-9]{2})/) {
		$codelen = 2;
	} elsif ($xpart =~ /(([a-zA-Z0-9]{4}-){2}[a-zA-Z0-9]{2})/) {
		$codelen = 1;
	} elsif ($xpart =~ /(([a-zA-Z0-9]{4}-){1}[a-zA-Z0-9]{2})/) {
		$codelen = 0;
	} else {
		die "internal error: code len patterns are wrong\n";
	}
	print "             Bust up code: \"$id\" (format $codelen)\n"
	    unless $opt_q;

	$dictname = uc($dictname);
	$xpart = uc($xpart);
	$xpart =~ s/B/8/g;
	$xpart =~ s/I/1/g;
	$xpart =~ s/O/0/g;
	$xpart =~ s/Z/2/g;

	unless ($opt_q) {
		print "After alphabet correction: \"$dictname-$xpart\"\n"
		    if $id ne "$dictname-$xpart";

		print "          Dictionary name: \"$dictname\"\n";
	}

	# first run dictname through checksum
	foreach $i (unpack('C*', $dictname)) {
		$csum = crc($csum, $i);
	}

	# convert xpart to binary number (really a string of [01])
	print "               Conversion:\n" unless $opt_q;
	while ($xpart =~ /(.)/) {
		$x = $1;
		$xpart =~ s/.//;
		next if $x eq '-';
		$i = 0;
		while (1) {
			
			die "illegal character in Message ID: \"$x\"\n"
			    unless $i < length($Alphabet);

			last if $x eq substr($Alphabet, $i, 1);
			$i++;
		}
		print "                           $x = " .
		    sprintf('%05b', $i) . "\n" unless $opt_q;
		$bits .= sprintf('%05b', $i);
	}

	die "no code type in bits \"$bits\"\n"
	    unless $bits =~ /^(..)/;
	print "         2 bits code type: $1\n" unless $opt_q;
	die "unrecognized code type (must be 01)\n" unless $1 eq '01';

	die "no code length in bits \"$bits\"\n"
	    unless $bits =~ /^..(..)/;
	print "              2 bits size: $1\n" unless $opt_q;
	die "size field doesn't match format\n"
	    unless oct('0b' . $1) == $codelen;

	# extract the dictval (skip 4 bits for code type & size fields)
	$dictval = substr($bits, 4, $Dictvalbits[$codelen]);
	die "no dictval in bits \"$bits\"\n"
	    unless length($dictval) == $Dictvalbits[$codelen];
	print "          " . sprintf('%2d', $Dictvalbits[$codelen]) .
	    " bits dictval: $dictval\n" unless $opt_q;
	$dictval = bintoi($dictval);
	print "          Decimal dictval: $dictval\n" unless $opt_q;

	# check for integer overflow
	warn "$Myname: ERROR: dictval is negative (integer overflow)\n"
		if $dictval < 0;

	if ($codelen == 1) {
		print "      Add format 1 offset: 2097152\n" unless $opt_q;
		$dictval += 2097152;
		print "         Adjusted dictval: $dictval\n" unless $opt_q;
	} elsif ($codelen == 2) {
		print "      Add format 2 offset: 274880004096\n" unless $opt_q;
		$dictval += 274880004096;
		print "         Adjusted dictval: $dictval\n" unless $opt_q;
	} elsif ($codelen == 3) {
		print "      Add format 3 offset: 36029071898968064\n"
		    unless $opt_q;
		$dictval += 36029071898968064;
		print "         Adjusted dictval: $dictval\n" unless $opt_q;
	}

	# check for integer overflow
	warn "$Myname: ERROR: dictval $dictval converts to " .
	    sprintf("%d", $dictval) . " (integer overflow?)\n"
	    if sprintf("%d", $dictval) ne $dictval;

	# save the checksum given to us in the code
	$csumfromcode =
	    substr($bits, - $Csumbits[$codelen],  $Csumbits[$codelen]);
	die "no checksum in bits \"$bits\"\n"
	    unless length($csumfromcode) == $Csumbits[$codelen];

	# zero the checksum for our calculation
	substr($bits, - $Csumbits[$codelen],  $Csumbits[$codelen]) =
	    '0' x $Csumbits[$codelen];

	# compute csum by taking 5 bits at a time from left to right
	my $bitscopy = $bits;
	while ($bitscopy =~ /(.....)/) {
		$csum = crc($csum, oct('0b' . $1));
		$bitscopy =~ s/.....//;
	}

	printf("CRC: 0x%x\n", $csum) if $opt_c;

	# changed the zeroed csum bits to the computed value, masking
	# the computed checksum down to the appropriate number of bits
	unless ($opt_q) {
		print "         " . sprintf('%2d', $Csumbits[$codelen]) .
		    " bits checksum: ";
		print "$csumfromcode ";
	}
	if ($csumfromcode eq substr(sprintf('%014b', $csum),
	    - $Csumbits[$codelen],  $Csumbits[$codelen])) {
		print "(correct)\n" unless $opt_q;
	} else {
		if ($opt_q) {
			warn "$Myname: ERROR: incorrect checksum " .
			    "($csumfromcode should be " .
			    substr(sprintf('%014b', $csum),
			    - $Csumbits[$codelen],
			    $Csumbits[$codelen]) . ")\n";
		} else {
			print "INCORRECT (should be " .
			    substr(sprintf('%014b', $csum),
			    - $Csumbits[$codelen],
			    $Csumbits[$codelen]) . ")\n";
		}
	}

	return "$dictname $dictval";
}

#
# bintoi -- convert string of binary digits to a number
#
# XXX there's got to be a better way to do this, but using oct()
# XXX causes a warning about non-portable binary numbers...
#
sub bintoi {
	my $bits = shift;
	my $mul = 1;
	my $retval = 0;

	while ($bits =~ /(.)$/) {
		$retval += $mul if $1 eq '1';
		$mul *= 2;
		$bits =~ s/.$//;
	}

	return $retval;
}

# table used by crc()
my @Crctab = (
0x00000000,
0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B,
0x1A864DB2, 0x1E475005, 0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6,
0x2B4BCB61, 0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD,
0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC,
0x5BD4B01B, 0x569796C2, 0x52568B75, 0x6A1936C8, 0x6ED82B7F,
0x639B0DA6, 0x675A1011, 0x791D4014, 0x7DDC5DA3, 0x709F7B7A,
0x745E66CD, 0x9823B6E0, 0x9CE2AB57, 0x91A18D8E, 0x95609039,
0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5, 0xBE2B5B58,
0xBAEA46EF, 0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033,
0xA4AD16EA, 0xA06C0B5D, 0xD4326D90, 0xD0F37027, 0xDDB056FE,
0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95,
0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4,
0xE5FFEB43, 0xE8BCCD9A, 0xEC7DD02D, 0x34867077, 0x30476DC0,
0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C, 0x2E003DC5,
0x2AC12072, 0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16,
0x018AEB13, 0x054BF6A4, 0x0808D07D, 0x0CC9CDCA, 0x7897AB07,
0x7C56B6B0, 0x71159069, 0x75D48DDE, 0x6B93DDDB, 0x6F52C06C,
0x6211E6B5, 0x66D0FB02, 0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1,
0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA,
0xACA5C697, 0xA864DB20, 0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B,
0xBB60ADFC, 0xB6238B25, 0xB2E29692, 0x8AAD2B2F, 0x8E6C3698,
0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D,
0x94EA7B2A, 0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E,
0xF3B06B3B, 0xF771768C, 0xFA325055, 0xFEF34DE2, 0xC6BCF05F,
0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34,
0xDC3ABDED, 0xD8FBA05A, 0x690CE0EE, 0x6DCDFD59, 0x608EDB80,
0x644FC637, 0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB,
0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F, 0x5C007B8A,
0x58C1663D, 0x558240E4, 0x51435D53, 0x251D3B9E, 0x21DC2629,
0x2C9F00F0, 0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C,
0x3B5A6B9B, 0x0315D626, 0x07D4CB91, 0x0A97ED48, 0x0E56F0FF,
0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623, 0xF12F560E,
0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65,
0xEBA91BBC, 0xEF68060B, 0xD727BBB6, 0xD3E6A601, 0xDEA580D8,
0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604, 0xC960EBB3,
0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2,
0xAAFBE615, 0xA7B8C0CC, 0xA379DD7B, 0x9B3660C6, 0x9FF77D71,
0x92B45BA8, 0x9675461F, 0x8832161A, 0x8CF30BAD, 0x81B02D74,
0x857130C3, 0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640,
0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C, 0x7B827D21,
0x7F436096, 0x7200464F, 0x76C15BF8, 0x68860BFD, 0x6C47164A,
0x61043093, 0x65C52D24, 0x119B4BE9, 0x155A565E, 0x18197087,
0x1CD86D30, 0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC,
0x3793A651, 0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D,
0x2056CD3A, 0x2D15EBE3, 0x29D4F654, 0xC5A92679, 0xC1683BCE,
0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB,
0xDBEE767C, 0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18,
0xF0A5BD1D, 0xF464A0AA, 0xF9278673, 0xFDE69BC4, 0x89B8FD09,
0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5, 0x9E7D9662,
0x933EB0BB, 0x97FFAD0C, 0xAFB010B1, 0xAB710D06, 0xA6322BDF,
0xA2F33668, 0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4
);

#
# crc -- calculate a CRC using passed-in starting value & additional data
#
sub crc {
	my $cval = shift;
	my $val = shift;

	printf("crc(0x%08x, 0x%x)\n", $cval, $val) if $opt_c;

	return (($cval<<8) ^ $Crctab[((($cval>>24) & 0xff) ^ $val) & 0xff]);
}

#
# usage -- print a usage message and exit
#
sub usage {
	my $msg = shift;

	warn "$Myname: $msg\n" if defined($msg);
	warn "usage: $Myname [-q] message-id\n";
	exit 1;
}

#
# the "main" for this script...
#
getopts('cq') or usage;

my $id = shift || usage;
usage if @ARGV;
if ($opt_q) {
	print bustcode($id) . "\n";
} else {
	bustcode($id);
}
exit 0;
