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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.4	*/
/*LINTLIBRARY*/

#include <stdlib.h>
#include <math.h>
#include <plot.h>
#include "con.h"

static int del = 20;

static void
step(int d)
{
	del = d;
}

/*
 * local definition of quad
 * legacy code
 */
static short
quad_l(short x, short y, short xp, short yp)
{
	if (x < xp)
		if (y <= yp)
			return (1);
		else return (4);
	else if (x > xp)
		if (y < yp)
			return (2);
		else return (3);
	else if (y < yp)
		return (2);
	else return (4);
}

void
arc(short x, short y, short x0, short y0, short x1, short y1)
{
	double pc;
	int flg, m, xc, yc, xs, ys, qs, qf, qt, qtctr = 0;
	int m0, m1;
	float dx, dy, r;
	char use;
	dx = x - x0;
	dy = y - y0;
	r = dx * dx + dy * dy;
	pc = r;
	pc = sqrt(pc);
	flg = (int)(pc / 4);
	if (flg == 0)
		step(1);
	else if (flg < del)
		step(flg);
	xc = xs = x0;
	yc = ys = y0;
	move((short)xs, (short)ys);
	if ((x0 == x1) && (y0 == y1))
		flg = 0;
	else flg = 1;
	qs = quad_l(x, y, x0, y0);
	qf = quad_l(x, y, x1, y1);
	if (abs(x - x1) < abs(y - y1)) {
		use = 'x';
		if ((qs == 2) || (qs == 3))
			m = -1;
		else m = 1;
	} else {
		use = 'y';
		if (qs > 2)
			m = -1;
		else m = 1;
	}
	if (qs == qf) {
		m0 = (y0 - y) / (x0 - x);
		m1 = (y1 - y) / (x1 - x);
		if (m0 >= m1)
			qt = 4;
		else qt = 0;
	} else if ((qt = qf - qs) < 0)
			qt += 4;
	/* LINTED */
	while (1) {
		switch (use) {
		case 'x':
			if ((qs == 2) || (qs == 3))
				yc -= del;
			else yc += del;
			dy = yc - y;
			pc = r - dy * dy;
			xc = (int)(m * sqrt(pc) + x);
			if (((x < xs) && (x >= xc)) ||
			    ((x > xs) && (x <= xc)) ||
			    ((y < ys) && (y >= yc)) ||
			    ((y > ys) && (y <= yc))) {
				if (++qtctr > qt)
					return;
				if (++qs > 4)
					qs = 1;
				if ((qs == 2) || (qs == 3))
					m = -1;
				else m = 1;
				flg = 1;
			}
			cont((short)xc, (short)yc);
			xs = xc;
			ys = yc;
			if ((qs == qf) && (flg == 1))
				switch (qf) {
				case 3:
				case 4:
					if (xs >= x1)
						return;
					continue;
				case 1:
				case 2:
					if (xs <= x1)
						return;
				}
			continue;
		case 'y':
			if (qs > 2)
				xc += del;
			else xc -= del;
			dx = xc - x;
			pc = r - dx * dx;
			yc = (int)(m * sqrt(pc) + y);
			if (((x < xs) && (x >= xc)) ||
			    ((x > xs) && (x <= xc)) ||
			    ((y < ys) && (y >= yc)) ||
			    ((y > ys) && (y <= yc))) {
				if (++qtctr > qt)
					return;
				if (++qs > 4)
					qs = 1;
				if (qs > 2)
					m = -1;
				else m = 1;
				flg = 1;
			}
			cont((short)xc, (short)yc);
			xs = xc;
			ys = yc;
			if ((qs == qf) && (flg == 1))
				switch (qs) {
				case 1:
				case 4:
					if (ys >= y1)
						return;
					continue;
				case 2:
				case 3:
					if (ys <= y1)
						return;
				}
		}
	}
}
