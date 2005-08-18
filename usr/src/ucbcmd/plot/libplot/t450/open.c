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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sgtty.h>

/* gsi plotting output routines */
#define DOWN 012
#define UP 013
#define LEFT 010
#define RIGHT 040
#define BEL 007
#define ACK 006
#define PLOTIN 063
#define PLOTOUT 064
#define CR 015
#define FF 014
#define VERTRESP 48
#define HORZRESP 60.
#define HORZRES 6.
#define VERTRES 8.
/* down is line feed, up is reverse oyne feed,
   left is bwckspace, right is space.  48 points per inch
   vertically, 60 horizontally */

int xnow, ynow;
int OUTF;
struct sgttyb ITTY, PTTY;
float HEIGHT = 6.0, WIDTH = 6.0, OFFSET = 0.0;
int xscale, xoffset, yscale;
float botx = 0., boty = 0., obotx = 0., oboty = 0.;
float scalex = 1., scaley = 1.;

void
openpl(void)
{
	int reset();
		xnow = ynow = 0;
		OUTF = 1;
		printf("\r");
		gtty(OUTF, &ITTY);
		signal (2, reset);
		PTTY = ITTY;
		PTTY.sg_flags &= ~CRMOD;	/* don't map lf */
		stty(OUTF,&PTTY);
		/* initialize constants */
		xscale  = 4096./(HORZRESP * WIDTH);
		yscale = 4096 /(VERTRESP * HEIGHT);
		xoffset = OFFSET * HORZRESP;
		return;
}

void
openvt(void)
{
	openpl();
}
