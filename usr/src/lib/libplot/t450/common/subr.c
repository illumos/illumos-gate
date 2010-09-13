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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*LINTLIBRARY*/

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <plot.h>
#include "con.h"

int xnow, ynow, OUTF;

int
xconv(int xp)
{
	/*
	 * x position input is -2047 to +2047,
	 * output must be 0 to PAGSIZ*HORZRES
	 */
	xp += 2048;
	/* the computation is newx = xp*(PAGSIZ*HORZRES)/4096 */
	return (xoffset + xp / xscale);
}

int
yconv(int yp)
{
	/* see description of xconv */
	yp += 2048;
	return (yp / yscale);
}

void
inplot(void)
{
	spew(ESC);
	spew(PLOTIN);
}

void
outplot(void)
{
	spew(ESC);
	spew(PLOTOUT);
	(void) fflush(stdout);
}

void
spew(char ch)
{
	if (ch == UP) {
		(void) putc(ESC, stdout);
		ch = DOWN;
	}
	(void) putc(ch, stdout);
}

void
tobotleft(void)
{
	move(-2048, -2048);
}

void
reset(void)
{
	(void) signal(SIGINT, SIG_IGN);
	outplot();
	(void) ioctl(OUTF, TCSETAW, &ITTY);
	_exit(0);
}

float
dist2(int x1, int y1, int x2, int y2)
{
	float t, v;
	t = x2 - x1;
	v = y1 - y2;
	return (t * t + v * v);
}

void
swap(int *pa, int *pb)
{
	int t;
	t = *pa;
	*pa = *pb;
	*pb = t;
}

void
movep(int xg, int yg)
{
	int i;
	char ch;
	if ((xg == xnow) && (yg == ynow))
		return;
	/* if we need to go to left margin, just CR */
	if (xg < xnow / 2) {
		spew(CR);
		xnow = 0;
	}
	i = (int)((xg - xnow) / HORZRES);
	if (xnow < xg)
		ch = RIGHT;
	else ch = LEFT;
	xnow += i * HORZRES;
	i = abs(i);
	while (i--)
		spew(ch);
	i = abs(xg - xnow);
	inplot();
	while (i--)
		spew(ch);
	outplot();
	i = (int)((yg - ynow) / VERTRES);
	if (ynow < yg)
		ch = UP;
	else ch = DOWN;
	ynow += i * VERTRES;
	i = abs(i);
	while (i--)
		spew(ch);
	i = abs(yg - ynow);
	inplot();
	while (i--)
		spew(ch);
	outplot();
	xnow = xg; ynow = yg;
}

int
xsc(int xi)
{
	int xa;
	xa = (int)((xi - obotx) * scalex + botx);
	return (xa);
}

int
ysc(int yi)
{
	int ya;
	ya = (int)((yi - oboty) *scaley +boty);
	return (ya);
}
