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
 * This module contains the translation tables for the up-down encoded
 * USB keyboards.
 */
#include <sys/usb/usba/usbai_version.h>

#define	KEYMAP_SIZE_VARIABLE

#include <sys/param.h>
#include <sys/kbd.h>
#include <sys/stream.h>
#include <sys/consdev.h>
#include <sys/note.h>
#include <sys/usb/clients/hid/hid.h>
#include <sys/usb/clients/hid/hid_polled.h>
#include <sys/usb/clients/hidparser/hidparser.h>
#include <sys/kbtrans.h>
#include <sys/usb/clients/usbkbm/usbkbm.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/sunddi.h>

/* handy way to define control characters in the tables */
#define	c(char)(char&0x1F)
#define	ESC 0x1B
#define	DEL 0x7F

/* Unshifted keyboard table for USB keyboard */

static keymap_entry_t keytab_usb_lc[KEYMAP_SIZE_USB] = {
/*   0 */	HOLE, HOLE, HOLE, ERROR, 'a', 'b', 'c', 'd',
/*   8 */	'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
/*  16 */	'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
/*  24 */	'u', 'v', 'w', 'x', 'y', 'z', '1', '2',
/*  32 */	'3', '4', '5', '6', '7', '8', '9', '0',
/*  40 */	'\r', ESC, '\b', '\t', ' ', '-', '=', '[',
/*  48  */	']',   '\\',   HOLE,    ';',   '\'',    '`',   ',',   '.',
/*  56 */	'/', SHIFTKEYS+CAPSLOCK, TF(1), TF(2), TF(3),
		TF(4), TF(5), TF(6),
/*  64 */	TF(7), TF(8), TF(9), TF(10), TF(11), TF(12),
		RF(2), RF(3),
/*  72 */	RF(1), BF(8), RF(7), RF(9), DEL, RF(13), RF(15),
					STRING+RIGHTARROW,
/*  80 */	STRING+LEFTARROW, STRING+DOWNARROW, STRING+UPARROW,
					SHIFTKEYS+NUMLOCK, RF(5),
		RF(6), BF(15), BF(14),
/*  88 */	BF(11), RF(13), STRING+DOWNARROW, RF(15), STRING+LEFTARROW, \
		RF(11), STRING+RIGHTARROW, RF(7),
/*  96 */	STRING+UPARROW, RF(9), BF(8), BF(10), HOLE, COMPOSE,
		BF(13), HOLE,
/* 104 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 112 */	HOLE, HOLE, HOLE, HOLE, LF(7), LF(16), LF(3), LF(5),
/* 120 */	BUCKYBITS+SYSTEMBIT, LF(2), LF(4), LF(10), LF(6), LF(8), \
		LF(9), RF(4),
/* 128 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 136 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 144 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 152 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, '\r', HOLE,
/* 160 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 168 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 176 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 184 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 192 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 200 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 208 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 216 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 224 */	SHIFTKEYS+LEFTCTRL, SHIFTKEYS+LEFTSHIFT, SHIFTKEYS+ALT,
		BUCKYBITS+METABIT, SHIFTKEYS+RIGHTCTRL, SHIFTKEYS+RIGHTSHIFT,
		SHIFTKEYS+ALTGRAPH, BUCKYBITS+METABIT,
/* 232 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 240 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 248 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
};


/* Shifted keyboard table for USB keyboard */

static keymap_entry_t keytab_usb_uc[KEYMAP_SIZE_USB] = {
/*   0 */	HOLE, HOLE, HOLE, ERROR, 'A', 'B', 'C', 'D',
/*   8 */	'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
/*  16 */	'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
/*  24 */	'U', 'V', 'W', 'X', 'Y', 'Z', '!', '@',
/*  32 */	'#', '$', '%', '^', '&', '*', '(', ')',
/*  40 */	'\r', ESC, '\b', '\t', ' ', '_', '+', '{',
/*  48  */	'}',   '|',   HOLE,    ':',   '"',  '~',   '<',   '>',
/*  56 */	'?', SHIFTKEYS+CAPSLOCK, TF(1), TF(2), TF(3),
		TF(4), TF(5), TF(6),
/*  64 */	TF(7), TF(8), TF(9), TF(10), TF(11), TF(12),
		RF(2), RF(3),
/*  72 */	RF(1), BF(8), RF(7), RF(9), DEL, RF(13), RF(15),
					STRING+RIGHTARROW,
/*  80 */	STRING+LEFTARROW, STRING+DOWNARROW, STRING+UPARROW,
					SHIFTKEYS+NUMLOCK, RF(5), RF(6), \
		BF(15), BF(14), \
/*  88 */	BF(11), RF(13), STRING+DOWNARROW, RF(15), \
		STRING+LEFTARROW, RF(11), STRING+RIGHTARROW, RF(7),
/*  96 */	STRING+UPARROW, RF(9), BF(8), BF(10), HOLE, COMPOSE,
		BF(13), HOLE,
/* 104 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 112 */	HOLE, HOLE, HOLE, HOLE, LF(7), LF(16), LF(3), LF(5),
/* 120 */	BUCKYBITS+SYSTEMBIT, LF(2), LF(4), LF(10), LF(6), \
		LF(8), LF(9), RF(4),
/* 128 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 136 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 144 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 152 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, '\r', HOLE,
/* 160 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 168 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 176 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 184 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 192 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 200 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 208 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 216 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 224 */	SHIFTKEYS+LEFTCTRL, SHIFTKEYS+LEFTSHIFT, SHIFTKEYS+ALT,
		BUCKYBITS+METABIT, SHIFTKEYS+RIGHTCTRL, SHIFTKEYS+RIGHTSHIFT,
		SHIFTKEYS+ALTGRAPH, BUCKYBITS+METABIT,
/* 232 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 240 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 248 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
	};


/* Caps Locked keyboard table for USB keyboard */

static keymap_entry_t keytab_usb_cl[KEYMAP_SIZE_USB] = {

/*   0 */	HOLE, HOLE, HOLE, ERROR, 'A', 'B', 'C', 'D',
/*   8 */	'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
/*  16 */	'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
/*  24 */	'U', 'V', 'W', 'X', 'Y', 'Z', '1', '2',
/*  32 */	'3', '4', '5', '6', '7', '8', '9', '0',
/*  40 */	'\r', ESC, '\b', '\t', ' ', '-', '=', '[',
/*  48  */	']',   '\\',   HOLE,    ';',   '\'',  '`',   ',',   '.',
/*  56 */	'/', SHIFTKEYS+CAPSLOCK, TF(1), TF(2), TF(3),
		TF(4), TF(5), TF(6),
/*  64 */	TF(7), TF(8), TF(9), TF(10), TF(11), TF(12),
		RF(2), RF(3),
/*  72 */	RF(1), BF(8), RF(7), RF(9), DEL, RF(13), RF(15),
						STRING+RIGHTARROW,
/*  80 */	STRING+LEFTARROW, STRING+DOWNARROW, STRING+UPARROW,
			SHIFTKEYS+NUMLOCK, RF(5), RF(6), BF(15), BF(14),
/*  88 */	BF(11), RF(13), STRING+DOWNARROW, RF(15),
		STRING+LEFTARROW, RF(11), STRING+RIGHTARROW, RF(7),
/*  96 */	STRING+UPARROW, RF(9), BF(8), BF(10), HOLE, COMPOSE,
		BF(13), HOLE,
/* 104 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 112 */	HOLE, HOLE, HOLE, HOLE, LF(7), LF(16), LF(3), LF(5),
/* 120 */	BUCKYBITS+SYSTEMBIT, LF(2), LF(4), LF(10), LF(6),
		LF(8), LF(9), RF(4),
/* 128 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 136 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 144 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 152 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, '\r', HOLE,
/* 160 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 168 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 176 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 184 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 192 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 200 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 208 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 216 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 224 */	SHIFTKEYS+LEFTCTRL, SHIFTKEYS+LEFTSHIFT,
		SHIFTKEYS+ALT, BUCKYBITS+METABIT, SHIFTKEYS+RIGHTCTRL,
		SHIFTKEYS+RIGHTSHIFT,
		SHIFTKEYS+ALTGRAPH, BUCKYBITS+METABIT,
/* 232 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 240 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 248 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
	};


/* Alt Graph keyboard table for USB keyboard */

static keymap_entry_t keytab_usb_ag[KEYMAP_SIZE_USB] = {
/*  0 */	HOLE,	HOLE, HOLE,	ERROR,	NOP,	NOP,	NOP,	NOP,
/*  8 */	NOP, 	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/* 16 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/* 24 */	NOP, 	NOP, 	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/* 32 */	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,	NOP,
/* 40 */	'\r',	ESC,	'\b',	'\t',	' ',	NOP,	NOP,	NOP,
/* 48 */	NOP,	NOP,	HOLE,	NOP,	NOP,	NOP,	NOP,	NOP,
/* 56 */	NOP,	SHIFTKEYS+CAPSLOCK,	TF(1), TF(2),
				TF(3),	TF(4),	TF(5),	TF(6),
/* 64 */	TF(7),	TF(8),	 TF(9),	TF(10),
					TF(11),	TF(12), RF(2),	RF(3),
/* 72 */	RF(1),	BF(8),	RF(7),	RF(9),	DEL, RF(13), RF(15),
					STRING+RIGHTARROW,
/* 80 */	STRING+LEFTARROW, STRING+DOWNARROW, STRING+UPARROW,
			SHIFTKEYS+NUMLOCK, RF(5), RF(6), BF(15), BF(14),
/* 88 */	BF(11),	RF(13),	STRING+DOWNARROW, RF(15),
			STRING+LEFTARROW, RF(11), STRING+RIGHTARROW, RF(7),
/* 96 */	STRING+UPARROW,	RF(9),	BF(8), BF(10),
					HOLE,	COMPOSE, BF(13), HOLE,
/* 104 */	HOLE,	HOLE,	HOLE,	HOLE,	HOLE,	HOLE, HOLE,	HOLE,
/* 112 */	HOLE,	HOLE, HOLE,	HOLE,	LF(7),	LF(16), LF(3), LF(5),
/* 120 */	BUCKYBITS+SYSTEMBIT, LF(2),	LF(4), LF(10), LF(6),
		LF(8),	LF(9),	RF(4),
/* 128 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 136 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 144 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 152 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, '\r', HOLE,
/* 160 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 168 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 176 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 184 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 192 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 200 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 208 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 216 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 224 */	SHIFTKEYS+LEFTCTRL, SHIFTKEYS+LEFTSHIFT, SHIFTKEYS+ALT,
		BUCKYBITS+METABIT, SHIFTKEYS+RIGHTCTRL, SHIFTKEYS+RIGHTSHIFT,
		SHIFTKEYS+ALTGRAPH, BUCKYBITS+METABIT,
/* 232 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 240 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 248 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
};

/* Num Locked keyboard table for USB keyboard */

static keymap_entry_t keytab_usb_nl[KEYMAP_SIZE_USB] = {

/*   0 */	HOLE, HOLE, HOLE, NONL, NONL, NONL, NONL, NONL,
/*   8 */	NONL, NONL, NONL, NONL, NONL, NONL, NONL, NONL,
/*  16 */	NONL, NONL, NONL, NONL, NONL, NONL, NONL, NONL,
/*  24 */	NONL, NONL, NONL, NONL, NONL, NONL, NONL, NONL,
/*  32 */	NONL, NONL, NONL, NONL, NONL, NONL, NONL, NONL,
/*  40 */	NONL, NONL, NONL, NONL, NONL, NONL, NONL, NONL,
/*  48 */	NONL, NONL, HOLE, NONL, NONL, NONL, NONL, NONL,
/*  56 */	NONL, NONL, NONL, NONL, NONL, NONL, NONL, NONL,
/*  64 */	NONL, NONL, NONL, NONL, NONL, NONL, NONL, NONL,
/*  72 */	NONL, NONL, NONL, NONL, NONL, NONL, NONL, NONL,
/*  80 */	NONL, NONL, NONL, NONL, PADSLASH, PADSTAR, PADMINUS, PADPLUS,
/*  88 */	PADENTER, PAD1, PAD2, PAD3, PAD4, PAD5, PAD6, PAD7,
/*  96 */	PAD8, PAD9, PAD0, PADDOT, HOLE, NONL, NONL, HOLE,
/* 104 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 112 */	HOLE, HOLE, HOLE, HOLE, NONL, NONL, NONL, NONL,
/* 120 */	NONL, NONL, NONL, NONL, NONL, NONL, NONL, PADEQUAL,
/* 128 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 136 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 144 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 152 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, NONL, HOLE,
/* 160 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 168 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 176 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 184 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 192 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 200 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 208 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 216 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 224 */	NONL, NONL, NONL, NONL, NONL, NONL, NONL, NONL,
/* 232 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 240 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 248 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
};

/* Controlled keyboard table for USB keyboard */

static keymap_entry_t keytab_usb_ct[KEYMAP_SIZE_USB] = {
/*   0 */	HOLE, HOLE, HOLE, ERROR, c('a'), c('b'), c('c'), c('d'),
/*   8 */	c('e'), c('f'), c('g'), c('h'), c('i'), c('j'), c('k'), c('l'),
/*  16 */	c('m'), c('n'), c('o'), c('p'), c('q'), c('r'), c('s'), c('t'),
/*  24 */	c('u'), c('v'), c('w'), c('x'), c('y'), c('z'), '1', c(' '),
/*  32 */	'3', '4', '5', c('^'), '7', '8', '9', '0',
/*  40 */	'\r', ESC, '\b', '\t', c(' '), c('_'), '=', ESC,
/*  48  */	c(']'),   c('\\'),   HOLE,    ';',   '\'',    c('^'),
		',',   '.',
/*  56 */	c('_'), SHIFTKEYS+CAPSLOCK, TF(1), TF(2), TF(3),
		TF(4), TF(5), TF(6),
/*  64 */	TF(7), TF(8), TF(9), TF(10), TF(11), TF(12),
		RF(2), RF(3),
/*  72 */	RF(1), BF(8), RF(7), RF(9), DEL, RF(13), RF(15),
						STRING+RIGHTARROW,
/*  80 */	STRING+LEFTARROW, STRING+DOWNARROW, STRING+UPARROW,
		SHIFTKEYS+NUMLOCK, RF(5), RF(6), BF(15), BF(14),
/*  88 */	BF(11), RF(13), STRING+DOWNARROW, RF(15),
		STRING+LEFTARROW, RF(11), STRING+RIGHTARROW, RF(7),
/*  96 */	STRING+UPARROW, RF(9), BF(8), BF(10), HOLE, COMPOSE,
		BF(13), HOLE,
/* 104 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 112 */	HOLE, HOLE, HOLE, HOLE, LF(7), LF(16), LF(3), LF(5),
/* 120 */	BUCKYBITS+SYSTEMBIT, LF(2), LF(4), LF(10), LF(6),
		LF(8), LF(9), RF(4),
/* 128 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 136 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 144 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 152 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, '\r', HOLE,
/* 160 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 168 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 176 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 184 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 192 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 200 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 208 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 216 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 224 */	SHIFTKEYS+LEFTCTRL, SHIFTKEYS+LEFTSHIFT, SHIFTKEYS+ALT,
		BUCKYBITS+METABIT, SHIFTKEYS+RIGHTCTRL, SHIFTKEYS+RIGHTSHIFT,
		SHIFTKEYS+ALTGRAPH, BUCKYBITS+METABIT,
/* 232 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 240 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 248 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,


};

/* "Key Up" keyboard table for USB keyboard */

static keymap_entry_t keytab_usb_up[KEYMAP_SIZE_USB] = {

/*   0 */	HOLE, HOLE, HOLE, NOP, NOP, NOP, NOP, NOP,
/*   8 */	NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
/*  16 */	NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
/*  24 */	NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
/*  32 */	NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
/*  40 */	NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
/*  48  */	NOP, NOP, HOLE, NOP, NOP, NOP, NOP, NOP,
/*  56 */	NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
/*  64 */	NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
/*  72 */	NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
/*  80 */	NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
/*  88 */	NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
/*  96 */	NOP, NOP, NOP, NOP, HOLE, NOP, NOP, HOLE,
/* 104 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 112 */	HOLE, HOLE, HOLE, HOLE, NOP, NOP, NOP, NOP,
/* 120 */	BUCKYBITS+SYSTEMBIT, NOP, NOP, NOP, NOP, NOP, NOP, NOP,
/* 128 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 136 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 144 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 152 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, NOP, HOLE,
/* 160 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 168 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 176 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 184 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 192 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 200 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 208 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 216 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 224 */	SHIFTKEYS+LEFTCTRL, SHIFTKEYS+LEFTSHIFT, SHIFTKEYS+ALT,
		BUCKYBITS+METABIT, SHIFTKEYS+RIGHTCTRL, SHIFTKEYS+RIGHTSHIFT,
		SHIFTKEYS+ALTGRAPH, BUCKYBITS+METABIT,
/* 232 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 240 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
/* 248 */	HOLE, HOLE, HOLE, HOLE, HOLE, HOLE, HOLE,
	};


/*
 * Index into keytab_pc_lc based on USB scancodes
 */
static keymap_entry_t keytab_usb2pc[KEYMAP_SIZE_USB] = {
/*   0 */	0,	0,	0,	0,	31,	50,	48,	33,
/*   8 */	19,	34,	35,	36,	24,	37,	38,	39,
/*  16 */	52,	51,	25,	26,	17,	20,	32,	21,
/*  24 */	23,	49,	18,	47,	22,	46,	2,	3,
/*  32 */	4,	5,	6,	7,	8,	9,	10,	11,
/*  40 */	43,	110,	15,	16,	61,	12,	13,	27,
/*  48 */	28,	29,	0,	40,	41,	1,	53,	54,
/*  56 */	55,	30,	112,	113,	114,	115,	116,	117,
/*  64 */	118,	119,	120,	121,	122,	123,	124,	125,
/*  72 */	126,	75,	80,	85,	76,	81,	86,	89,
/*  80 */	79,	84,	83,	90,	95,	100,	105,	106,
/*  88 */	108,	93,	98,	103,	92,	97,	102,	91,
/*  96 */	96,	101,	99,	104,	0,	0,	0,	0,
/* 104 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 112 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 120 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 128 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 136 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 144 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 152 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 160 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 168 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 176 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 184 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 192 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 200 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 208 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 216 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 224 */	58,	44,	60,	0,	64,	57,	62,	0,
/* 232 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 240 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 248 */	0,	0,	0,	0,	0,	0,	0
};

/* Index to keymaps for USB keyboard */
static struct keyboard kbtrans_usb_keyindex = {
	KEYMAP_SIZE_USB,
	keytab_usb_lc,
	keytab_usb_uc,
	keytab_usb_cl,
	keytab_usb_ag,
	keytab_usb_nl,
	keytab_usb_ct,
	keytab_usb_up,
	0x0000,		/* Shift bits which stay on with idle keyboard */
	0x0000,		/* Bucky bits which stay on with idle keyboard */
	120,
#if defined(__sparc)
	0,		/* no alternate abort key F1 on sparc */
#else
	58,		/* alternate abort key F1 */
#endif
	4,
	CAPSMASK|NUMLOCKMASK,	/* Shift bits which toggle on down event */
	NULL,		/* Exception table */
	225,		/* new abort key Left Shift */
	229,		/* alternate new abort key Right Shift */
	72,		/* new abort key Pause */
};

struct keyboard *
kbtrans_usbkb_maptab_init(void)
{
	struct keyboard *pkbd;

	pkbd = (struct keyboard *)
	    kmem_alloc(sizeof (struct keyboard), KM_SLEEP);

	bcopy(&kbtrans_usb_keyindex, pkbd, sizeof (*pkbd));

	return (pkbd);
}

void
kbtrans_usbkb_maptab_fini(struct keyboard **ppkbd)
{
	kmem_free(*ppkbd, sizeof (struct keyboard));
	*ppkbd = NULL;
}

/*
 * Translate USB scancodes to PC scancodes before sending it to 'kbtrans'
 */
keymap_entry_t
kbtrans_keycode_usb2pc(int key)
{
	ASSERT(key >= 0 && key <= 255);
	return (keytab_usb2pc[key]);
}
