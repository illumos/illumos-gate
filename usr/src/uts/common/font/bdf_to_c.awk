#! /bin/awk -f
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
# Copyright (c) 1998-1999 by Sun Microsystems, Inc.
# All rights reserved.
#

BEGIN {
	pats["0"]="    ";
	pats["1"]="   X";
	pats["2"]="  X ";
	pats["3"]="  XX";
	pats["4"]=" X  ";
	pats["5"]=" X X";
	pats["6"]=" XX ";
	pats["7"]=" XXX";
	pats["8"]="X   ";
	pats["9"]="X  X";
	pats["a"]="X X "; pats["A"] = pats["a"];
	pats["b"]="X XX"; pats["B"] = pats["b"];
	pats["c"]="XX  "; pats["C"] = pats["c"];
	pats["d"]="XX X"; pats["D"] = pats["d"];
	pats["e"]="XXX "; pats["E"] = pats["e"];
	pats["f"]="XXXX"; pats["F"] = pats["f"];
}

$1=="ENDCHAR" {
	in_bitmap = 0;
	next;
}

in_bitmap != 0 {
	if (ignoring) next;

	for (c = 0; c < byteswide; c++)
	    printf "0x%s, ", substr($0,c*2+1,2);
	s="";
	for (c = 0; c < byteswide*2; c++)
	    s = s pats[substr($0,c+1,1)];
	s = substr(s, 1, bitswide);
	printf "/* %s */\n", s;

	offset += length($0)/2;
	next;
}

$1=="STARTFONT" {
	if ($2 != "2.1") {
	    printf "Unknown BDF version number %s!\n", $2;
	    exit 1;
	}
	in_bitmap = 0;
	ignoring = 1;
	first = 1;
	offset = 0;

	for (i = 0; i < 256; i++)
		encoding[i] = -1;
	
	next;
}

$1=="COMMENT" {
	if (NF > 1) {
		printf "/*";
		for (i = 2; i < NF; i++)
			printf " %s",$i;
		printf " */";
	}
	printf "\n";
	next;
}

$1=="FONT" {
	font = $2;
	printf "#include <sys/types.h>\n"
	printf "#include <sys/font.h>\n\n"
	printf "/* %s */\n", $0;
	next;
}

$1=="SIZE" {
	next;
}

$1=="FONTBOUNDINGBOX" {
	rows = $3;
	byteswide = int(($2 + 7)/8);
	bitswide = $2;
	next;
}

$1=="STARTPROPERTIES" {
	next;
}

$1=="FONTNAME_REGISTRY" {
	next;
}

$1=="FOUNDRY" {
	next;
}

$1=="FAMILY_NAME" {
	next;
}

$1=="WEIGHT_NAME" {
	next;
}

$1=="SLANT" {
	next;
}

$1=="SETWIDTH_NAME" {
	next;
}

$1=="ADD_STYLE_NAME" {
	next;
}

$1=="PIXEL_SIZE" {
	next;
}

$1=="POINT_SIZE" {
	next;
}

$1=="RESOLUTION_X" {
	next;
}

$1=="RESOLUTION_Y" {
	next;
}


$1=="SPACING" {
	if ($2 != "\"C\"") printf "Unsupported format %s!\n",$2;
	next;
}

$1=="AVERAGE_WIDTH" {
	next;
}

$1=="CHARSET_REGISTRY" {
	next;
}

$1=="CHARSET_ENCODING" {
	next;
}


$1=="DEFAULT_CHAR" {
	default_char = $2;
	next;
}

$1=="FONT_DESCENT" {
	next;
}

$1=="FONT_ASCENT" {
	next;
}


$1=="COPYRIGHT" {
	printf "/* Copyright notice from .bdf file: */\n";
	printf "/* %s */\n", $0;
	next;
}

$1=="ENDPROPERTIES" {
	next;
}

$1=="CHARS" {
	next;
}


$1=="STARTCHAR" {
	if (first) {
	    printf "static unsigned char FONTDATA_%s[] = {\n", font;
	    first = 0;
	}
	ignoring = 1;
	row = 0;
	next;
}

$1=="ENCODING" {
	encoding[$2] = offset;
	ignoring = 0;
	got[$2] = 1;
	printf "\n";
	if ($2 >= 32 && $2 < 127) printf "/* '%c' */\n", $2;
	else printf "/* 0x%2.2x */\n", $2;
	next;
}

$1=="SWIDTH" {
	next;
}

$1=="DWIDTH" {
	next;
}

$1=="BBX" {
	next;
}

$1=="BITMAP" {
	in_bitmap = 1;
	next;
}

$1=="ENDFONT" {
	printf "};\n";
	printf "\n";
	printf "static unsigned char *ENCODINGS_%s[256] = {\n", font;

	for (i = 0; i < 256; i++) {
	    if (encoding[i] == -1) encoding[i] = encoding[default_char];
	    printf "\tFONTDATA_%s+%d,\n", font, encoding[i];
	}
	printf "};\n\n";
	printf "bitmap_data_t font_data_%s = {\n", font;
	printf "\t%s, %s,\n", bitswide, rows;
	printf "\tFONTDATA_%s,\n", font;
	printf "\tENCODINGS_%s\n", font;
	printf "};\n";
	next;
}

{
	printf "?!? %s\n", $0;
}
