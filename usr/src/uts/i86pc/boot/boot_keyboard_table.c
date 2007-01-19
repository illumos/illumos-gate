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
 * Keyboard table for bootstrap's simple keyboard driver.
 */

#include "boot_keyboard_table.h"

#define	A	| KBTYPE_ALPHA
#define	C	& 0x1f
#define	F	| KBTYPE_FUNC
#define	N	| KBTYPE_NUMPAD

#define	ALT	KBTYPE_SPEC_ALT
#define	CTRL	KBTYPE_SPEC_CTRL
#define	LSHIFT	KBTYPE_SPEC_LSHIFT
#define	NOP	KBTYPE_SPEC_NOP
#define	NUMLK	KBTYPE_SPEC_NUM_LOCK
#define	SCRLLK	KBTYPE_SPEC_SCROLL_LOCK
#define	CAPSLK	KBTYPE_SPEC_CAPS_LOCK
#define	RSHIFT	KBTYPE_SPEC_RSHIFT
#define	REBOOT	KBTYPE_SPEC_MAYBE_REBOOT
#define	UNDEF	KBTYPE_SPEC_UNDEF

struct keyboard_translate keyboard_translate[128] = {
	/*		Normal	Shifted	Ctrled	Alted */
	/* 00 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 01 */	'['C,	'['C,	NOP,	NOP,
	/* 02 */	'1',	'!',	NOP,	0x78 F,
	/* 03 */	'2',	'@',	NOP,	0x79 F,
	/* 04 */	'3',	'#',	NOP,	0x7a F,
	/* 05 */	'4',	'$',	NOP,	0x7b F,
	/* 06 */	'5',	'%',	NOP,	0x7c F,
	/* 07 */	'6',	'^',	'^'C,	0x7d F,
	/* 08 */	'7',	'&',	NOP,	0x7e F,
	/* 09 */	'8',	'*',	NOP,	0x7f F,
	/* 0a */	'9',	'(',	NOP,	0x80 F,
	/* 0b */	'0',	')',	NOP,	0x81 F,
	/* 0c */	'-',	'_',	NOP,	0x82 F,
	/* 0d */	'=',	'+',	NOP,	0x83 F,
	/* 0e */	'h'C,	0x0e F,	0x7f,	NOP,
	/* 0f */	'i'C,	0x0f F,	NOP,	NOP,
	/* 10 */	'q'A,	'Q',	'q'C,	0x10 F,
	/* 11 */	'w'A,	'W',	'w'C,	0x11 F,
	/* 12 */	'e'A,	'E',	'e'C,	0x12 F,
	/* 13 */	'r'A,	'R',	'r'C,	0x13 F,
	/* 14 */	't'A,	'T',	't'C,	0x14 F,
	/* 15 */	'y'A,	'Y',	'y'C,	0x15 F,
	/* 16 */	'u'A,	'U',	'u'C,	0x16 F,
	/* 17 */	'i'A,	'I',	'i'C,	0x17 F,
	/* 18 */	'o'A,	'O',	'o'C,	0x18 F,
	/* 19 */	'p'A,	'P',	'p'C,	0x19 F,
	/* 1a */	'[',	'{',	'['C,	NOP,
	/* 1b */	']',	'}',	']'C,	NOP,
	/* 1c */	'm'C,	'm'C,	NOP,	NOP,
	/* 1d */	CTRL,	CTRL,	CTRL,	CTRL,
	/* 1e */	'a'A,	'A',	'a'C,	0x1e F,
	/* 1f */	's'A,	'S',	's'C,	0x1f F,
	/* 20 */	'd'A,	'D',	'd'C,	0x20 F,
	/* 21 */	'f'A,	'F',	'f'C,	0x21 F,
	/* 22 */	'g'A,	'G',	'g'C,	0x22 F,
	/* 23 */	'h'A,	'H',	'h'C,	0x23 F,
	/* 24 */	'j'A,	'J',	'j'C,	0x24 F,
	/* 25 */	'k'A,	'K',	'k'C,	0x25 F,
	/* 26 */	'l'A,	'L',	'l'C,	0x26 F,
	/* 27 */	';',	':',	NOP,	NOP,
	/* 28 */	'\'',	'"',	NOP,	NOP,
	/* 29 */	'`',	'~',	NOP,	NOP,
	/* 2a */	LSHIFT,	LSHIFT,	LSHIFT,	LSHIFT,
	/* 2b */	'\\',	'|',	'\\'C,	NOP,
	/* 2c */	'z'A,	'Z',	'z'C,	0x2c F,
	/* 2d */	'x'A,	'X',	'x'C,	0x2d F,
	/* 2e */	'c'A,	'C',	'c'C,	0x2e F,
	/* 2f */	'v'A,	'V',	'v'C,	0x2f F,
	/* 30 */	'b'A,	'B',	'b'C,	0x30 F,
	/* 31 */	'n'A,	'N',	'n'C,	0x31 F,
	/* 32 */	'm'A,	'M',	'm'C,	0x32 F,
	/* 33 */	',',	'<',	NOP,	NOP,
	/* 34 */	'.',	'>',	NOP,	NOP,
	/* 35 */	'/',	'?',	NOP,	NOP,
	/* 36 */	RSHIFT,	RSHIFT,	RSHIFT,	RSHIFT,
	/* 37 */	'*',	NOP,	NOP,	NOP,	/* * PrtSc */
	/* 38 */	ALT,	ALT,	ALT,	ALT,
	/* 39 */	' ',	' ',	NOP,	NOP,
	/* 3a */	CAPSLK,	CAPSLK,	CAPSLK,	CAPSLK,
	/* 3b */	0x3b F,	0x54 F,	0x5e F,	0x68 F,
	/* 3c */	0x3c F,	0x55 F,	0x5f F,	0x69 F,
	/* 3d */	0x3d F,	0x56 F,	0x60 F,	0x6a F,
	/* 3e */	0x3e F,	0x57 F,	0x61 F,	0x6b F,
	/* 3f */	0x3f F,	0x58 F,	0x62 F,	0x6c F,
	/* 40 */	0x40 F,	0x59 F,	0x63 F,	0x6d F,
	/* 41 */	0x41 F,	0x5a F,	0x64 F,	0x6e F,
	/* 42 */	0x42 F,	0x5b F,	0x65 F,	0x6f F,
	/* 43 */	0x43 F,	0x5c F,	0x66 F,	0x70 F,
	/* 44 */	0x44 F,	0x5d F,	0x67 F,	0x71 F,
	/* 45 */	NUMLK,	NUMLK,	NUMLK,	NUMLK,
	/* 46 */	SCRLLK,	SCRLLK,	SCRLLK,	SCRLLK,
	/* 47 */	0x47 N,	'7',	NOP,	NOP,
	/* 48 */	0x48 N,	'8',	NOP,	NOP,
	/* 49 */	0x49 N,	'9',	NOP,	NOP,
	/* 4a */	'-',	'-',	NOP,	NOP,
	/* 4b */	0x4b N,	'4',	NOP,	NOP,
	/* 4c */	NOP,	'5',	NOP,	NOP,
	/* 4d */	0x4d N,	'6',	NOP,	NOP,
	/* 4e */	'+',	'+',	NOP,	NOP,
	/* 4f */	0x4f N,	'1',	NOP,	NOP,
	/* 50 */	0x50 N,	'2',	NOP,	NOP,
	/* 51 */	0x51 N,	'3',	NOP,	NOP,
	/* 52 */	0x52 N,	'0',	NOP,	NOP,
	/* 53 */	0x53 N,	'.',	REBOOT,	REBOOT,
	/* 54 */	NOP,	NOP,	NOP,	NOP,	/* SysReq */
	/* 55 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 56 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 57 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 58 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 59 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 5a */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 5b */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 5c */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 5d */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 5e */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 5f */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 60 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 61 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 62 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 63 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 64 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 65 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 66 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 67 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 68 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 69 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 6a */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 6b */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 6c */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 6d */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 6e */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 6f */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 70 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 71 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 72 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 73 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 74 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 75 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 76 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 77 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 78 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 79 */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 7a */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 7b */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 7c */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 7d */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 7e */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
	/* 7f */	UNDEF,	UNDEF,	UNDEF,	UNDEF,
};
