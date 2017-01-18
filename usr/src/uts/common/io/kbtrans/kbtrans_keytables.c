/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * This file contains generic keytable information across all
 * keyboard hardware.
 */

#include <sys/param.h>
#include <sys/kbd.h>

/*
 * Keyboard String Table
 *
 * This defines the strings sent by various keys (as selected in the
 * tables above).
 * The first byte of each string is its length, the rest is data.
 */

#ifdef	__STDC__
#define	kstescinit(c)	"\033[" #c
#else	/* __STDC__ */
#define	kstescinit(c)	{'\033', '[', 'c', '\0'}
#endif	/* __STDC__ */
char keystringtab[16][KTAB_STRLEN] = {
	kstescinit(H) /* home */,
	kstescinit(A) /* up */,
	kstescinit(B) /* down */,
	kstescinit(D) /* left */,
	kstescinit(C) /* right */,
};


/*
 * Compose Key Sequence Table
 *
 * Taken from Suncompose.h of openwindows.
 *
 * The idea here is to create a simple index into a table of
 * compose key sequences.  The purpose is to provide a fast
 * lookup mechanism using as little space as possible (while
 * still using a table of triplets).
 *
 * For reference, here is the set of all composable characters:
 * SP !\"\'*+,-./01234:<>?ACDEHILNOPRSTUXY\\^_`acdehilnoprstuxy|~
 *
 * if ascii_char[i] is not composable,
 *	kb_compose_map[i] is -1
 * else
 * 	if ascii_char[i] appears as a first char in compose_table,
 *		kb_compose_map[i] is the index of it's first appearance
 *	else
 *		kb_compose_map[i] is 112	(end of table)
 */

signed char kb_compose_map[ASCII_SET_SIZE] = {
	-1,	/* 000 (^@) */
	-1,	/* 001 (^A) */
	-1,	/* 002 (^B) */
	-1,	/* 003 (^C) */
	-1,	/* 004 (^D) */
	-1,	/* 005 (^E) */
	-1,	/* 006 (^F) */
	-1,	/* 007 (^G) */
	-1,	/* 008 (^H) */
	-1,	/* 009 (^I) */
	-1,	/* 010 (^J) */
	-1,	/* 011 (^K) */
	-1,	/* 012 (^L) */
	-1,	/* 013 (^M) */
	-1,	/* 014 (^N) */
	-1,	/* 015 (^O) */
	-1,	/* 016 (^P) */
	-1,	/* 017 (^Q) */
	-1,	/* 018 (^R) */
	-1,	/* 019 (^S) */
	-1,	/* 020 (^T) */
	-1,	/* 021 (^U) */
	-1,	/* 022 (^V) */
	-1,	/* 023 (^W) */
	-1,	/* 024 (^X) */
	-1,	/* 025 (^Y) */
	-1,	/* 026 (^Z) */
	-1,	/* 027 (^[) */
	-1,	/* 028 (^\) */
	-1,	/* 029 (^]) */
	-1,	/* 030 (^^) */
	-1,	/* 031 (^_) */
	0,	/* 032 (SP) */
	1,	/* 033 (!) */
	4,	/* 034 (") */
	-1,	/* 035 (#) */
	-1,	/* 036 ($) */
	-1,	/* 037 (%) */
	-1,	/* 038 (&) */
	16,	/* 039 (') */
	-1,	/* 040 (() */
	-1,	/* 041 ()) */
	28,	/* 042 (*) */
	31,	/* 043 (+) */
	32,	/* 044 (,) */
	36,	/* 045 (-) */
	48,	/* 046 (.) */
	49,	/* 047 (/) */
	54,	/* 048 (0) */
	57,	/* 049 (1) */
	60,	/* 050 (2) */
	61,	/* 051 (3) */
	112,	/* 052 (4) */
	-1,	/* 053 (5) */
	-1,	/* 054 (6) */
	-1,	/* 055 (7) */
	-1,	/* 056 (8) */
	-1,	/* 057 (9) */
	112,	/* 058 (:) */
	-1,	/* 059 (;) */
	63,	/* 060 (<) */
	-1,	/* 061 (=) */
	64,	/* 062 (>) */
	65,	/* 063 (?) */
	-1,	/* 064 (@) */
	66,	/* 065 (A) */
	-1,	/* 066 (B) */
	70,	/* 067 (C) */
	112,	/* 068 (D) */
	71,	/* 069 (E) */
	-1,	/* 070 (F) */
	-1,	/* 071 (G) */
	73,	/* 072 (H) */
	74,	/* 073 (I) */
	-1,	/* 074 (J) */
	-1,	/* 075 (K) */
	112,	/* 076 (L) */
	-1,	/* 077 (M) */
	76,	/* 078 (N) */
	77,	/* 079 (O) */
	84,	/* 080 (P) */
	-1,	/* 081 (Q) */
	112,	/* 082 (R) */
	112,	/* 083 (S) */
	112,	/* 084 (T) */
	85,	/* 085 (U) */
	-1,	/* 086 (V) */
	-1,	/* 087 (W) */
	112,	/* 088 (X) */
	112,	/* 089 (Y) */
	-1,	/* 090 (Z) */
	-1,	/* 091 ([) */
	87,	/* 092 (\) */
	-1,	/* 093 (]) */
	88,	/* 094 (^) */
	93,	/* 095 (_) */
	94,	/* 096 (`) */
	99,	/* 097 (a) */
	-1,	/* 098 (b) */
	101,	/* 099 (c) */
	112,	/* 100 (d) */
	112,	/* 101 (e) */
	-1,	/* 102 (f) */
	-1,	/* 103 (g) */
	102,	/* 104 (h) */
	112,	/* 105 (i) */
	-1,	/* 106 (j) */
	-1,	/* 107 (k) */
	112,	/* 108 (l) */
	-1,	/* 109 (m) */
	103,	/* 110 (n) */
	104,	/* 111 (o) */
	108,	/* 112 (p) */
	-1,	/* 113 (q) */
	112,	/* 114 (r) */
	109,	/* 115 (s) */
	112,	/* 116 (t) */
	112,	/* 117 (u) */
	-1,	/* 118 (v) */
	-1,	/* 119 (w) */
	110,	/* 120 (x) */
	112,	/* 121 (y) */
	-1,	/* 122 (z) */
	-1,	/* 123 ({) */
	111,	/* 124 (|) */
	-1,	/* 125 (}) */
	112,	/* 126 (~) */
	-1,	/* 127 (DEL) */
};

/*
 * IMPORTANT NOTE:  This table MUST be kept in proper sorted order:
 * 	The first and second characters in each entry must be in ASCII
 *	    collating sequence (left to right).
 *	The table must be in ASCII collating sequence by first character
 *	    (top to bottom).
 */

/* COMPOSE + first character + second character => UTF-8 character */

struct compose_sequence_t kb_compose_table[] = {

	{' ', ' ', 0xA0},	/* 000 */	/* NBSP (non-breaking space) */
	{'!', '!', 0xA1},	/* 001 */	/* inverted ! */
	{'!', 'P', 0xB6},	/* 002 */	/* paragraph mark */
	{'!', 'p', 0xB6},	/* 003 */	/* paragraph mark */
	{'"', '"', 0xA8},	/* 004 */	/* diaresis */
	{'"', 'A', 0xC4},	/* 005 */	/* A with diaresis */
	{'"', 'E', 0xCB},	/* 006 */	/* E with diaresis */
	{'"', 'I', 0xCF},	/* 007 */	/* I with diaresis */
	{'"', 'O', 0xD6},	/* 008 */	/* O with diaresis */
	{'"', 'U', 0xDC},	/* 009 */	/* U with diaresis */
	{'"', 'a', 0xE4},	/* 010 */	/* a with diaresis */
	{'"', 'e', 0xEB},	/* 011 */	/* e with diaresis */
	{'"', 'i', 0xEF},	/* 012 */	/* i with diaresis */
	{'"', 'o', 0xF6},	/* 013 */	/* o with diaresis */
	{'"', 'u', 0xFC},	/* 014 */	/* u with diaresis */
	{'"', 'y', 0xFF},	/* 015 */	/* y with diaresis */
	{'\'', 'A', 0xC1},	/* 016 */	/* A with acute accent */
	{'\'', 'E', 0xC9},	/* 017 */	/* E with acute accent */
	{'\'', 'I', 0xCD},	/* 018 */	/* I with acute accent */
	{'\'', 'O', 0xD3},	/* 019 */	/* O with acute accent */
	{'\'', 'U', 0xDA},	/* 020 */	/* U with acute accent */
	{'\'', 'Y', 0xDD},	/* 021 */	/* Y with acute accent */
	{'\'', 'a', 0xE1},	/* 022 */	/* a with acute accent */
	{'\'', 'e', 0xE9},	/* 023 */	/* e with acute accent */
	{'\'', 'i', 0xED},	/* 024 */	/* i with acute accent */
	{'\'', 'o', 0xF3},	/* 025 */	/* o with acute accent */
	{'\'', 'u', 0xFA},	/* 026 */	/* u with acute accent */
	{'\'', 'y', 0xFD},	/* 027 */	/* y with acute accent */
	{'*', 'A', 0xC5},	/* 028 */	/* A with ring */
	{'*', '^', 0xB0},	/* 029 */	/* degree */
	{'*', 'a', 0xE5},	/* 030 */	/* a with ring */
	{'+', '-', 0xB1},	/* 031 */	/* plus/minus */
	{',', ',', 0xB8},	/* 032 */	/* cedilla */
	{',', '-', 0xAC},	/* 033 */	/* not sign */
	{',', 'C', 0xC7},	/* 034 */	/* C with cedilla */
	{',', 'c', 0xE7},	/* 035 */	/* c with cedilla */
	{'-', '-', 0xAD},	/* 036 */	/* soft hyphen */
	{'-', ':', 0xF7},	/* 037 */	/* division sign */
	{'-', 'A', 0xAA},	/* 038 */	/* feminine superior numeral */
	{'-', 'D', 0xD0},	/* 039 */	/* Upper-case eth */
	{'-', 'L', 0xA3},	/* 040 */	/* pounds sterling */
	{'-', 'Y', 0xA5},	/* 041 */	/* yen */
	{'-', '^', 0xAF},	/* 042 */	/* macron */
	{'-', 'a', 0xAA},	/* 043 */	/* feminine superior numeral */
	{'-', 'd', 0xF0},	/* 044 */	/* Lower-case eth */
	{'-', 'l', 0xA3},	/* 045 */	/* pounds sterling */
	{'-', 'y', 0xA5},	/* 046 */	/* yen */
	{'-', '|', 0xAC},	/* 047 */	/* not sign */
	{'.', '^', 0xB7},	/* 048 */	/* centered dot */
	{'/', 'C', 0xA2},	/* 049 */	/* cent sign */
	{'/', 'O', 0xD8},	/* 050 */	/* O with slash */
	{'/', 'c', 0xA2},	/* 051 */	/* cent sign */
	{'/', 'o', 0xF8},	/* 052 */	/* o with slash */
	{'/', 'u', 0xB5},	/* 053 */	/* mu */
	{'0', 'X', 0xA4},	/* 054 */	/* currency symbol */
	{'0', '^', 0xB0},	/* 055 */	/* degree */
	{'0', 'x', 0xA4},	/* 056 */	/* currency symbol */
	{'1', '2', 0xBD},	/* 057 */	/* 1/2 */
	{'1', '4', 0xBC},	/* 058 */	/* 1/4 */
	{'1', '^', 0xB9},	/* 059 */	/* superior '1' */
	{'2', '^', 0xB2},	/* 060 */	/* superior '2' */
	{'3', '4', 0xBE},	/* 061 */	/* 3/4 */
	{'3', '^', 0xB3},	/* 062 */	/* superior '3' */
	{'<', '<', 0xAB},	/* 063 */	/* left guillemot */
	{'>', '>', 0xBB},	/* 064 */	/* right guillemot */
	{'?', '?', 0xBF},	/* 065 */	/* inverted ? */
	{'A', 'E', 0xC6},	/* 066 */	/* AE dipthong */
	{'A', '^', 0xC2},	/* 067 */	/* A with circumflex accent */
	{'A', '`', 0xC0},	/* 068 */	/* A with grave accent */
	{'A', '~', 0xC3},	/* 069 */	/* A with tilde */
	{'C', 'O', 0xA9},	/* 060 */	/* copyright */
	{'E', '^', 0xCA},	/* 071 */	/* E with circumflex accent */
	{'E', '`', 0xC8},	/* 072 */	/* E with grave accent */
	{'H', 'T', 0xDE},	/* 073 */	/* Upper-case thorn */
	{'I', '^', 0xCE},	/* 074 */	/* I with circumflex accent */
	{'I', '`', 0xCC},	/* 075 */	/* I with grave accent */
	{'N', '~', 0xD1},	/* 076 */	/* N with tilde */
	{'O', 'R', 0xAE},	/* 077 */	/* registered */
	{'O', 'S', 0xA7},	/* 078 */	/* section mark */
	{'O', 'X', 0xA4},	/* 079 */	/* currency symbol */
	{'O', '^', 0xD4},	/* 080 */	/* O with circumflex accent */
	{'O', '_', 0xBA},	/* 081 */	/* masculine superior numeral */
	{'O', '`', 0xD2},	/* 082 */	/* O with grave accent */
	{'O', '~', 0xD5},	/* 083 */	/* O with tilde */
	{'P', '|', 0xDE},	/* 084 */	/* Upper-case thorn */
	{'U', '^', 0xDB},	/* 085 */	/* U with circumflex accent */
	{'U', '`', 0xD9},	/* 086 */	/* U with grave accent */
	{'\\', '\\', 0xB4},	/* 087 */	/* acute accent */
	{'^', 'a', 0xE2},	/* 088 */	/* a with circumflex accent */
	{'^', 'e', 0xEA},	/* 089 */	/* e with circumflex accent */
	{'^', 'i', 0xEE},	/* 090 */	/* i with circumflex accent */
	{'^', 'o', 0xF4},	/* 091 */	/* o with circumflex accent */
	{'^', 'u', 0xFB},	/* 092 */	/* u with circumflex accent */
	{'_', 'o', 0xBA},	/* 093 */	/* masculine superior numeral */
	{'`', 'a', 0xE0},	/* 094 */	/* a with grave accent */
	{'`', 'e', 0xE8},	/* 095 */	/* e with grave accent */
	{'`', 'i', 0xEC},	/* 096 */	/* i with grave accent */
	{'`', 'o', 0xF2},	/* 097 */	/* o with grave accent */
	{'`', 'u', 0xF9},	/* 098 */	/* u with grave accent */
	{'a', 'e', 0xE6},	/* 099 */	/* ae dipthong */
	{'a', '~', 0xE3},	/* 100 */	/* a with tilde */
	{'c', 'o', 0xA9},	/* 101 */	/* copyright */
	{'h', 't', 0xFE},	/* 102 */	/* Lower-case thorn */
	{'n', '~', 0xF1},	/* 103 */	/* n with tilde */
	{'o', 'r', 0xAE},	/* 104 */	/* registered */
	{'o', 's', 0xA7},	/* 105 */	/* section mark */
	{'o', 'x', 0xA4},	/* 106 */	/* currency symbol */
	{'o', '~', 0xF5},	/* 107 */	/* o with tilde */
	{'p', '|', 0xFE},	/* 108 */	/* Lower-case thorn */
	{'s', 's', 0xDF},	/* 109 */	/* German double-s */
	{'x', 'x', 0xD7},	/* 110 */	/* multiplication sign */
	{'|', '|', 0xA6},	/* 111 */	/* broken bar */

	{0, 0, 0},			/* end of table */
};

/*
 * Floating Accent Sequence Table
 */

/* FA + ASCII character => UTF-8 character */
struct fltaccent_sequence_t kb_fltaccent_table[] = {

	{FA_UMLAUT, ' ', 0xA8},		/* umlaut/diaresis */
	{FA_UMLAUT, 'A', 0xC4},		/* A with umlaut */
	{FA_UMLAUT, 'E', 0xCB},		/* E with umlaut */
	{FA_UMLAUT, 'I', 0xCF},		/* I with umlaut */
	{FA_UMLAUT, 'O', 0xD6},		/* O with umlaut */
	{FA_UMLAUT, 'U', 0xDC},		/* U with umlaut */
	{FA_UMLAUT, 'a', 0xE4},		/* a with umlaut */
	{FA_UMLAUT, 'e', 0xEB},		/* e with umlaut */
	{FA_UMLAUT, 'i', 0xEF},		/* i with umlaut */
	{FA_UMLAUT, 'o', 0xF6},		/* o with umlaut */
	{FA_UMLAUT, 'u', 0xFC},		/* u with umlaut */
	{FA_UMLAUT, 'y', 0xFF},		/* y with umlaut */

	{FA_CFLEX, 'A', 0xC2},		/* A with circumflex */
	{FA_CFLEX, 'E', 0xCA},		/* E with circumflex */
	{FA_CFLEX, 'I', 0xCE},		/* I with circumflex */
	{FA_CFLEX, 'O', 0xD4},		/* O with circumflex */
	{FA_CFLEX, 'U', 0xDB},		/* U with circumflex */
	{FA_CFLEX, 'a', 0xE2},		/* a with circumflex */
	{FA_CFLEX, 'e', 0xEA},		/* e with circumflex */
	{FA_CFLEX, 'i', 0xEE},		/* i with circumflex */
	{FA_CFLEX, 'o', 0xF4},		/* o with circumflex */
	{FA_CFLEX, 'u', 0xFB},		/* u with circumflex */

	{FA_TILDE, ' ', '~'},		/* tilde */
	{FA_TILDE, 'A', 0xC3},		/* A with tilde */
	{FA_TILDE, 'N', 0xD1},		/* N with tilde */
	{FA_TILDE, 'O', 0xD5},		/* O with tilde */
	{FA_TILDE, 'a', 0xE3},		/* a with tilde */
	{FA_TILDE, 'n', 0xF1},		/* n with tilde */
	{FA_TILDE, 'o', 0xF5},		/* o with tilde */

	{FA_CEDILLA, ' ', 0xB8},	/* cedilla */
	{FA_CEDILLA, 'C', 0xC7},	/* C with cedilla */
	{FA_CEDILLA, 'c', 0xE7},	/* c with cedilla */

	{FA_ACUTE, ' ', '\''},		/* apostrophe */
	{FA_ACUTE, 'A', 0xC1},		/* A with acute accent */
	{FA_ACUTE, 'E', 0xC9},		/* E with acute accent */
	{FA_ACUTE, 'I', 0xCD},		/* I with acute accent */
	{FA_ACUTE, 'O', 0xD3},		/* O with acute accent */
	{FA_ACUTE, 'U', 0xDA},		/* U with acute accent */
	{FA_ACUTE, 'a', 0xE1},		/* a with acute accent */
	{FA_ACUTE, 'e', 0xE9},		/* e with acute accent */
	{FA_ACUTE, 'i', 0xED},		/* i with acute accent */
	{FA_ACUTE, 'o', 0xF3},		/* o with acute accent */
	{FA_ACUTE, 'u', 0xFA},		/* u with acute accent */
	{FA_ACUTE, 'y', 0xFD},		/* y with acute accent */

	{FA_GRAVE, ' ', '`'},		/* grave accent */
	{FA_GRAVE, 'A', 0xC0},		/* A with grave accent */
	{FA_GRAVE, 'E', 0xC8},		/* E with grave accent */
	{FA_GRAVE, 'I', 0xCC},		/* I with grave accent */
	{FA_GRAVE, 'O', 0xD2},		/* O with grave accent */
	{FA_GRAVE, 'U', 0xD9},		/* U with grave accent */
	{FA_GRAVE, 'a', 0xE0},		/* a with grave accent */
	{FA_GRAVE, 'e', 0xE8},		/* e with grave accent */
	{FA_GRAVE, 'i', 0xEC},		/* i with grave accent */
	{FA_GRAVE, 'o', 0xF2},		/* o with grave accent */
	{FA_GRAVE, 'u', 0xF9},		/* u with grave accent */

	{FA_MACRON, ' ', 0xAF},		/* macron */

	{FA_BREVE, ' ', 0x306},		/* combining breve */

	{FA_DOT, ' ', 0x307},		/* combining dot above */

	{FA_SLASH, 0, 0},		/* slash, invalid entry */

	{FA_RING, ' ', 0x30A},		/* combining ring above */

	{FA_APOSTROPHE, ' ', '\''},	/* apostrophe */

	{FA_DACUTE, ' ', 0x30B},	/* combining double acute */

	{FA_OGONEK, ' ', 0x328},	/* combining ogonek */

	{FA_CARON, ' ', 0x2C7},		/* caron */
	{FA_CARON, 'C', 0x10C},		/* C with caron */
	{FA_CARON, 'S', 0x160},		/* S with caron */
	{FA_CARON, 'Z', 0x17D},		/* Z with caron */
	{FA_CARON, 'c', 0x10D},		/* c with caron */
	{FA_CARON, 's', 0x161},		/* s with caron */
	{FA_CARON, 'z', 0x17E},		/* z with caron */

	{0, 0, 0},			/* end of table */
};

/*
 * Num Lock Table
 */

/* Num Lock:  pad key entry & 0x1F => ASCII character */
uchar_t kb_numlock_table[] = {
	'=',
	'/',
	'*',
	'-',
	',',

	'7',
	'8',
	'9',
	'+',

	'4',
	'5',
	'6',

	'1',
	'2',
	'3',

	'0',
	'.',
	'\n',	/* Enter */
};
