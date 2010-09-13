/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains the translation tables for PS/2 style keyboards.
 */
#define	KEYMAP_SIZE_VARIABLE

#include <sys/param.h>
#include <sys/kbd.h>

/* handy way to define control characters in the tables */
#define	c(ch)	(ch&0x1F)
#define	ESC 0x1B
#define	DEL 0x7F

#define	KEYMAP_SIZE_PC	160

/* ***************************** */
/*  PC-101 keyboard definitions  */
/* ***************************** */
/* Unshifted keyboard table for PC keyboard */

/* BEGIN CSTYLED */
static keymap_entry_t keytab_pc_lc[KEYMAP_SIZE_PC] = {
/*  0 */	HOLE,	'`',	'1',	'2',	'3',	'4',	'5',	'6',
/*  8 */	'7', 	'8',	'9',	'0',	'-',	'=',	HOLE,	'\b',
/* 16 */	'\t',	'q',	'w',	'e',	'r',	't',	'y',	'u',
/* 24 */	'i',	'o', 	'p', 	'[',	']',	'\\',
							SHIFTKEYS+CAPSLOCK,
									'a',
/* 32 */	's',	'd',	'f',	'g',	'h',	'j',	'k',	'l',
/* 40 */	';',	'\'',	'\\',	'\r',
					SHIFTKEYS+LEFTSHIFT,
							HOLE,	'z',	'x',
/* 48 */	'c',	'v',	'b',	'n',	'm',	',',	'.',	'/',
/* 56 */	NOP,	SHIFTKEYS+RIGHTSHIFT,
				SHIFTKEYS+LEFTCTRL,
					HOLE,	SHIFTKEYS+LEFTALT,
							' ',	SHIFTKEYS+
								RIGHTALT,
									HOLE,
/* 64 */        SHIFTKEYS+RIGHTCTRL,
			HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/* 72 */	HOLE,	HOLE,	HOLE,	BF(8),	DEL,
							NOP,	HOLE,
							    STRING+LEFTARROW,
/* 80 */	RF(7),	RF(13),	HOLE,
				    STRING+UPARROW,
					    STRING+DOWNARROW,
							RF(9),	RF(15),	HOLE,
/* 88 */	HOLE,
		STRING+RIGHTARROW,
			    SHIFTKEYS+NUMLOCK,
					RF(7),	STRING+LEFTARROW,
							RF(13),	HOLE,
								PADSLASH,
/* 96 */	STRING+UPARROW,
			RF(11),	STRING+DOWNARROW,
					BF(8),	PADSTAR,
							RF(9),
							  STRING+RIGHTARROW,
									RF(15),
/*104 */	DEL,	PADMINUS,
				PADPLUS,
					HOLE,	PADENTER,
							HOLE,	ESC,	HOLE,
/*112 */	TF(1),	TF(2),	TF(3),	TF(4),	TF(5),	TF(6),	TF(7),	TF(8),
/*120 */	TF(9),	TF(10),	TF(11),	TF(12),	NOP,	NOP,	NOP,	HOLE,
/*128 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*136 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*144 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*152 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*160 */
};

/* Shifted keyboard table for PC keyboard */

static keymap_entry_t keytab_pc_uc[KEYMAP_SIZE_PC] = {
/*  0 */	HOLE,	'~',	'!',	'@',	'#',	'$',	'%',	'^',
/*  8 */	'&', 	'*',	'(',	')',	'_',	'+',	HOLE,	'\b',
/* 16 */	'\t',	'Q',	'W',	'E',	'R',	'T',	'Y',	'U',
/* 24 */	'I',	'O', 	'P', 	'{',	'}',	'|',
							SHIFTKEYS+CAPSLOCK,
									'A',
/* 32 */	'S',	'D',	'F',	'G',	'H',	'J',	'K',	'L',
/* 40 */	':',	'"',	'|',	'\r',
					SHIFTKEYS+LEFTSHIFT,
							HOLE,	'Z',	'X',
/* 48 */	'C',	'V',	'B',	'N',	'M',	'<',	'>',	'?',
/* 56 */	NOP,	SHIFTKEYS+RIGHTSHIFT,
				SHIFTKEYS+LEFTCTRL,
					HOLE,
						SHIFTKEYS+LEFTALT,
							' ',	SHIFTKEYS+
								RIGHTALT,
									HOLE,
/* 64 */        SHIFTKEYS+RIGHTCTRL,
			HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/* 72 */	HOLE,	HOLE,	HOLE,	BF(8),	DEL,	NOP,	HOLE,
							    STRING+LEFTARROW,
/* 80 */	RF(7),	RF(13),	HOLE,	STRING+UPARROW,
						STRING+DOWNARROW,
							RF(9),	RF(15),	HOLE,
/* 88 */	HOLE,
		STRING+RIGHTARROW,
			    SHIFTKEYS+NUMLOCK,
					'7',	'4',	'1',	HOLE,	'/',
/* 96 */	'8',	'5',	'2',	'0',	'*',	'9',	'6',	'3',
/*104 */	'.',	'-',	'+',	HOLE,	'\n',	HOLE,	ESC,	HOLE,
/*112 */	TF(1),	TF(2),	TF(3),	TF(4),	TF(5),	TF(6),	TF(7),	TF(8),
/*120 */	TF(9),	TF(10),	TF(11),	TF(12),	NOP,	NOP,	NOP,	HOLE,
/*128 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*136 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*144 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*152 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*160 */
};

/* Caps Locked keyboard table for PC keyboard */

static keymap_entry_t keytab_pc_cl[KEYMAP_SIZE_PC] = {
/*  0 */	HOLE,	'`',	'1',	'2',	'3',	'4',	'5',	'6',
/*  8 */	'7', 	'8',	'9',	'0',	'-',	'=',	HOLE,	'\b',
/* 16 */	'\t',	'Q',	'W',	'E',	'R',	'T',	'Y',	'U',
/* 24 */	'I',	'O', 	'P', 	'[',	']',	'\\',
							SHIFTKEYS+CAPSLOCK,
									'A',
/* 32 */	'S',	'D',	'F',	'G',	'H',	'J',	'K',	'L',
/* 40 */	';',	'\'',	'\\',	'\r',
					SHIFTKEYS+LEFTSHIFT,
							HOLE,	'Z',	'X',
/* 48 */	'C',	'V',	'B',	'N',	'M',	',',	'.',	'/',
/* 56 */	NOP,	SHIFTKEYS+RIGHTSHIFT,
				SHIFTKEYS+LEFTCTRL,
					HOLE,
						SHIFTKEYS+LEFTALT,
							' ',	SHIFTKEYS+
								RIGHTALT,
									HOLE,
/* 64 */        SHIFTKEYS+RIGHTCTRL,
			HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/* 72 */	HOLE,	HOLE,	HOLE,	BF(8),	DEL,	NOP,	HOLE,
							    STRING+LEFTARROW,
/* 80 */	RF(7),
			RF(13),	HOLE,
				    STRING+UPARROW,
					    STRING+DOWNARROW,
							RF(9),	RF(15),	HOLE,
/* 88 */	HOLE,
		STRING+RIGHTARROW,
			    SHIFTKEYS+NUMLOCK,
					RF(7),	STRING+LEFTARROW,
							RF(13),	HOLE, PADSLASH,
/* 96 */	STRING+UPARROW,
			RF(11),	STRING+DOWNARROW,
					BF(8),	PADSTAR,
							RF(9),
							   STRING+RIGHTARROW,
									RF(15),
/*104 */	DEL,	PADMINUS,
				PADPLUS,
					HOLE,	PADENTER,
							HOLE,	ESC,	HOLE,
/*112 */	TF(1),	TF(2),	TF(3),	TF(4),	TF(5),	TF(6),	TF(7),	TF(8),
/*120 */	TF(9),	TF(10),	TF(11),	TF(12),	NOP,	NOP,	NOP,	HOLE,
/*128 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*136 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*144 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*152 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*160 */
};

/* Alt Graph keyboard table for PC keyboard */

static keymap_entry_t keytab_pc_ag[KEYMAP_SIZE_PC] = {
/*  0 */	HOLE,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/*  8 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	HOLE,	NOP,
/* 16 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/* 24 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
							SHIFTKEYS+CAPSLOCK,
									NOP,
/* 32 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/* 40 */	NOP,	NOP,	NOP,	NOP,
					SHIFTKEYS+LEFTSHIFT,
							HOLE,	NOP,	NOP,
/* 48 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/* 56 */	NOP,	SHIFTKEYS+RIGHTSHIFT,
				SHIFTKEYS+LEFTCTRL,
					HOLE,
						SHIFTKEYS+LEFTALT,
							' ',	SHIFTKEYS+
								RIGHTALT,
									HOLE,
/* 64 */        SHIFTKEYS+RIGHTCTRL,
			HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/* 72 */	HOLE,	HOLE,	HOLE,	BF(8),	DEL,	NOP,	HOLE,
									STRING+
								     LEFTARROW,
/* 80 */	RF(7),	RF(13),	HOLE,	STRING+
					UPARROW,STRING+
					      DOWNARROW,RF(9),	RF(15),	HOLE,
/* 88 */	HOLE,	STRING+
		    RIGHTARROW,
			SHIFTKEYS+NUMLOCK,
					NOP,	NOP,	NOP,	HOLE,	NOP,
/* 96 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/*104 */	NOP,	NOP,	NOP,	HOLE,	NOP,	HOLE,	ESC,	HOLE,
/*112 */	TF(1),	TF(2),	TF(3),	TF(4),	TF(5),	TF(6),	TF(7),	TF(8),
/*120 */	TF(9),	TF(10),	TF(11),	TF(12),	NOP,	NOP,	NOP,	HOLE,
/*128 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*136 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*144 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*152 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*160 */
};

/* Num Locked keyboard table for PC keyboard */

static keymap_entry_t keytab_pc_nl[KEYMAP_SIZE_PC] = {
/*  0 */	HOLE,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,
/*  8 */	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	HOLE,	NONL,
/* 16 */	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,
/* 24 */	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,
/* 32 */	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,
/* 40 */	NONL,	NONL,	NONL,	NONL,	NONL,	HOLE,	NONL,	NONL,
/* 48 */	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,
/* 56 */	NONL,	NONL,	NONL,	HOLE,	NONL,	NONL,	NONL,	HOLE,
/* 64 */	NONL,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/* 72 */	HOLE,	HOLE,	HOLE,	NONL,	NONL,	NONL,	HOLE,	NONL,
/* 80 */	NONL,	NONL,	HOLE,	NONL,	NONL,	NONL,	NONL,	HOLE,
/* 88 */	HOLE,	NONL,	NONL,	PAD7,	PAD4,	PAD1,	HOLE,	NONL,
/* 96 */	PAD8,	PAD5,	PAD2,	PAD0,	NONL,	PAD9,	PAD6,	PAD3,
/*104 */	PADDOT,	NONL,	NONL,	HOLE,	NONL,	HOLE,	NONL,	HOLE,
/*112 */	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,
/*120 */	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	NONL,	HOLE,
/*128 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*136 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*144 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*152 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*160 */
};

/* Controlled keyboard table for PC keyboard */

static keymap_entry_t keytab_pc_ct[KEYMAP_SIZE_PC] = {
/*  0 */	HOLE,	c('^'),	'1',	c('@'),	'3',	'4',	'5',	c('^'),
/*  8 */	'7', 	'8',	'9',	'0',	c('_'),	'=',	HOLE,	'\b',
/* 16 */	'\t',	c('q'),	c('w'),	c('e'),	c('r'),	c('t'),	c('y'),	c('u'),
/* 24 */	c('i'),	c('o'), c('p'), c('['),	c(']'),	c('\\'),
							SHIFTKEYS+CAPSLOCK,
									c('a'),
/* 32 */	c('s'),	c('d'),	c('f'),	c('g'),	c('h'),	c('j'),	c('k'),	c('l'),
/* 40 */	';',	'\'',	'\\',	'\r',
					SHIFTKEYS+LEFTSHIFT,
							HOLE,	c('z'),	c('x'),
/* 48 */	c('c'),	c('v'),	c('b'),	c('n'),	c('m'),	',',	'.',	c('_'),
/* 56 */	NOP,	SHIFTKEYS+RIGHTSHIFT,
				SHIFTKEYS+LEFTCTRL,
					HOLE,
						SHIFTKEYS+LEFTALT,
							' ',	SHIFTKEYS+
								RIGHTALT,
									HOLE,
/* 64 */        SHIFTKEYS+RIGHTCTRL,
			HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/* 72 */	HOLE,	HOLE,	HOLE,	BF(8),	DEL,	NOP,	HOLE,
							    STRING+LEFTARROW,
/* 80 */	RF(7),	RF(13),	HOLE,
				    STRING+UPARROW,
					    STRING+DOWNARROW,
							RF(9),	RF(15),	HOLE,
/* 88 */	HOLE,
		STRING+RIGHTARROW,
			    SHIFTKEYS+NUMLOCK,
					PAD7,	PAD4,	PAD1,	HOLE,
								PADSLASH,
/* 96 */	PAD8,	PAD5,	PAD2,	PAD0,	PADSTAR,
							PAD9,	PAD6,	PAD3,
/*104 */	PADDOT,	PADMINUS,
				PADPLUS,
					HOLE,	PADENTER,
							HOLE,	ESC,	HOLE,
/*112 */	TF(1),	TF(2),	TF(3),	TF(4),	TF(5),	TF(6),	TF(7),	TF(8),
/*120 */	TF(9),	TF(10),	TF(11),	TF(12),	NOP,	NOP,	NOP,	HOLE,
/*128 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*136 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*144 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*152 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*160 */
};

/* "Key Up" keyboard table for PC keyboard */


static keymap_entry_t keytab_pc_up[KEYMAP_SIZE_PC] = {
/*  0 */	HOLE,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/*  8 */	NOP, 	NOP,	NOP,	NOP,	NOP,	NOP,	HOLE,	NOP,
/* 16 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/* 24 */	NOP,	NOP, 	NOP, 	NOP,	NOP,	NOP,	NOP,	NOP,
/* 32 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/* 40 */	NOP,	NOP,	NOP,	NOP,
					SHIFTKEYS+LEFTSHIFT,
							HOLE,	NOP,	NOP,
/* 48 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/* 56 */	NOP,	SHIFTKEYS+RIGHTSHIFT,
				SHIFTKEYS+LEFTCTRL,
					HOLE,	SHIFTKEYS+LEFTALT,
							NOP,	SHIFTKEYS+
								RIGHTALT,
									HOLE,
/* 64 */        SHIFTKEYS+RIGHTCTRL,
			HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/* 72 */	HOLE,	HOLE,	HOLE,	NOP,	NOP,	NOP,	HOLE,	NOP,
/* 80 */	NOP,	NOP,	HOLE,	NOP,	NOP,	NOP,	NOP,	HOLE,
/* 88 */	HOLE,	NOP,	NOP,	NOP,	NOP,	NOP,	HOLE,	NOP,
/* 96 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/*104 */	NOP,	NOP,	NOP,	HOLE,	NOP,	HOLE,	NOP,	HOLE,
/*112 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/*120 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	HOLE,
/*128 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*136 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*144 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*152 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,
/*160 */
};

/* END CSTYLED */

#define	M(x)	(1 << (x))
#define	MASK_ALL	(M(LEFTSHIFT) |	\
			M(RIGHTSHIFT) |	\
			CTRLMASK |	\
			ALTMASK |	\
			ALTGRAPHMASK)

/*
 * Make Ctrl+Shift+F1 be Compose.  This is SOOOO hokey.
 */
static struct exception_map exceptions_pc[] = {
	{ MASK_ALL, M(LEFTSHIFT)|M(LEFTCTRL),   112, COMPOSE, },
	{ MASK_ALL, M(LEFTSHIFT)|M(RIGHTCTRL),  112, COMPOSE, },
	{ MASK_ALL, M(RIGHTSHIFT)|M(LEFTCTRL),  112, COMPOSE, },
	{ MASK_ALL, M(RIGHTSHIFT)|M(RIGHTCTRL), 112, COMPOSE, },
	{ 0, },
};

/* Index to keymaps for PC keyboard */
struct keyboard keyindex_pc = {
	KEYMAP_SIZE_PC,
	keytab_pc_lc,
	keytab_pc_uc,
	keytab_pc_cl,
	keytab_pc_ag,
	keytab_pc_nl,
	keytab_pc_ct,
	keytab_pc_up,
	0x0000,		/* Shift bits which stay on with idle keyboard */
	0x0000,		/* Bucky bits which stay on with idle keyboard */
	112, 0,	31,	/* abort keys: F1+A */
	CAPSMASK|NUMLOCKMASK,	/* Shift bits which toggle on down event */
	exceptions_pc,	/* Exceptions */
	44, 57, 126,	/* new abort keys: Shift+Pause */
};
