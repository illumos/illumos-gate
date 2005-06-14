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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *	All Rights Reserved
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.3 */

#define TOTAL_WINDOWS	20

/* types of screen definitions */
#define	NOTSET		3
#define	SMALL		0
#define FULL		1
#define LARGE		2

/*
 * Various display modes
 */
#define VT_VIDEO	0xff80
#define VT_CHAR		0x7f

/*
 *	CHAR attributes
 */
#define VT_NORMAL	0
#define VT_STANDOUT	0x80
#define VT_UNDER	0x100
#define VT_REVV		0x200
#define VT_BLINK	0x400
#define VT_HALF		0x800
#define VT_BOLD		0x1000
#define VT_INVISIBLE	0x2000
#define VT_ISGRAPH	0x4000
#define VT_PROTECT	0x8000

#define	CURS_TO_END	0
#define	BEG_TO_CURS	1
#define	BEG_TO_END	2

/*** #define CTL(x)		('x' & 037) unused abs 9/14/88 */

/* Returns for cursor pad and mouse */
#define	_NKEYS	27
#define K_HOME		0200
#define K_UP		0201
#define K_DOWN		0202
#define K_RIGHT		0203
#define K_LEFT		0204
#define K_F0		0205
#define K_F1		0206
#define K_F2		0207
#define K_F3		0210
#define K_F4		0211
#define K_F5		0212
#define K_F6		0213
#define K_F7		0214
#define K_F8		0215
#define K_F9		0216
#define K_FA		0217
#define K_BOTTOM	0220
#define K_BTAB		0221
#define K_MOUSE		0222
#define K_MOUSE2	0223
#define K_FTAB		0224
#define K_TAB		0225
#define K_NULL		0226
#define K_ESC		0227
#define K_HELP		0230
#define K_EOL		0231
#define K_EOF		0232

/*
 * returns from meta_getc()
 */

#define TS_KEYS	(K_HOME + _NKEYS)

/* Phone responses */
#define RET_OH		TS_KEYS
#define RET_BUSY	(TS_KEYS + 1)
#define RET_RING	(TS_KEYS + 2)
#define RET_NOTONE	(TS_KEYS + 3)

/* Function Keys */
#define RET_FL1		(TS_KEYS + 4)
#define RET_FL8		(TS_KEYS + 11)
#define RET_PAINT	(TS_KEYS + 11)
#define RET_FR1		(TS_KEYS + 12)
#define RET_FR8		(TS_KEYS + 19)
#define RET_MKEY	(TS_KEYS + 19)
#define RET_CMD		(TS_KEYS + 20)
#define NUMFUNCS	21

/* returns other than from termdeps */
#define RET_LEFT	(TS_KEYS + 21)
#define RET_RIGHT	(TS_KEYS + 22)
#define RET_UP		(TS_KEYS + 23)
#define RET_DOWN	(TS_KEYS + 24)
#define RET_INSERT	(TS_KEYS + 25)
#define RET_TAB		(TS_KEYS + 26)
#define RET_NEWLINE	(TS_KEYS + 27)
#define RET_RETURN	(TS_KEYS + 28)
#define RET_KILL	(TS_KEYS + 29)
#define RET_LINSERT	(TS_KEYS + 30)
#define RET_QUIT	(TS_KEYS + 31)
#define RET_XED		(TS_KEYS + 32)
#define RET_EXIT	(TS_KEYS + 33)
#define RET_ERASE	(TS_KEYS + 34)
#define RET_RLABS	(TS_KEYS + 35)
#define RET_LLABS	(TS_KEYS + 36)

/* returns from get_input() */
#define STRING	(TS_KEYS + TS_NKEYS + NUMFUNCS)
#define KWD	(STRING + 1)	/* return from command inside of objhandler */
