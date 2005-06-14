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
 * Copyright (c) 1997 by Sun Microsystems, Inc.
 * All rights reserved
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <termio.h>

/* gsi plotting output routines */
#define	DOWN 012
#define	UP 013
#define	LEFT 010
#define	RIGHT 040
#define	BEL 007
#define	ESC 033
#define	ACK 006
#define	CR 015
#define	FF 014
#define	VERTRESP 48
#define	HORZRESP 60.
#define	VERTRES 8.
#define	HORZRES 6.
/*
 * down is line feed, up is reverse line feed,
 * left is backspace, right is space.  48 points per inch
 * vertically, 60 horizontally
 */

extern struct termio ITTY, PTTY;
extern float botx, boty, obotx, oboty, scalex, scaley;
extern int xscale, xoffset, yscale;
extern int OUTF;
extern void movep(short, short);
extern void spew(char);
extern void inplot(void);
extern void outplot(void);
extern void reset(void);
extern float dist2(int, int, int, int);
extern int xsc(short);
extern int ysc(short);
extern short xconv(short);
extern short yconv(short);
extern short xnow, ynow;
