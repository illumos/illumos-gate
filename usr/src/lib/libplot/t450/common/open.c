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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.3	*/

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include "con.h"


float botx = 0.0, boty = 0.0, obotx = 0.0, oboty = 0.0;
float scalex = 1.0, scaley = 1.0;
static float HEIGHT = 6.0, WIDTH = 6.0, OFFSET = 0.0;
int xscale = 0, xoffset = 0, yscale = 0;
struct termio ITTY, PTTY;

void
openpl(void)
{
	int OUTF = 1;
	(void) printf("\r");
	(void) ioctl(OUTF, TCGETA, &ITTY);
	(void) signal(SIGINT, (void (*)(int))reset);
	PTTY = ITTY;
	PTTY.c_oflag &= ~(ONLCR|OCRNL|ONOCR|ONLRET);
	PTTY.c_cflag |= CSTOPB;
	(void) ioctl(OUTF, TCSETAW, &PTTY);
	/* set vert and horiz spacing to 6 and 10 */
	(void) putchar(ESC);	/* set vert spacing to 6 lpi */
	(void) putchar(RS);
	(void) putchar(HT);
	(void) putchar(ESC);	/* set horiz spacing to 10 cpi */
	(void) putchar(US);
	(void) putchar(CR);
	/* initialize constants */
	xscale  = (int)(4096./(HORZRESP * WIDTH));
	yscale = (int)(4096 /(VERTRESP * HEIGHT));
	xoffset = (int)(OFFSET * HORZRESP);
}

void
openvt(void)
{
	openpl();
}
