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

int del = 20;

void
step(int d)
{
	del = d;
}

void
arc(int x, int y, int x0, int y0, int x1, int y1)
{
	double pc;
	double sqrt();
	int flg,m,xc,yc,xs,ys,qs,qf;
	float dx,dy,r;
	char use;
	dx = x-x0;
	dy = y-y0;
	r = dx*dx+dy*dy;
	pc = r;
	pc = sqrt(pc);
	flg = pc/4;
	if(flg == 0)step(1);
	else if(flg < del)step(flg);
	xc = xs = x0;
	yc = ys = y0;
	move(xs,ys);
	if(x0 == x1 && y0 == y1)flg=0;
	else flg=1;
	qs = quad(x,y,x0,y0);
	qf = quad(x,y,x1,y1);
	if(abs(x-x1) < abs(y-y1)){
		use = 'x';
		if(qs == 2 || qs ==3)m = -1;
		else m=1;
	}
	else {
		use = 'y';
		if(qs > 2)m= -1;
		else m= 1;
	}
	while(1){
		switch(use){
		case 'x':	
			if(qs == 2 || qs == 3)yc -= del;
			else yc += del;
			dy = yc-y;
			pc = r-dy*dy;
			xc = m*sqrt(pc)+x;
			if((x < xs && x >= xc) || ( x > xs && x <= xc) ||
			    (y < ys && y >= yc) || ( y > ys && y <=  yc) )
			{
				if(++qs > 4)qs=1;
				if(qs == 2 || qs == 3)m= -1;
				else m=1;
				flg=1;
			}
			cont(xc,yc);
			xs = xc; 
			ys = yc;
			if(qs == qf && flg == 1)
				switch(qf){
				case 3:
				case 4:	
					if(xs >= x1)return;
					continue;
				case 1:
				case 2:
					if(xs <= x1)return;
				}
			continue;
		case 'y':	
			if(qs > 2)xc += del;
			else xc -= del;
			dx = xc-x;
			pc = r-dx*dx;
			yc = m*sqrt(pc)+y;
			if((x < xs && x >= xc) || ( x > xs && x <= xc ) ||
			    (y < ys && y >= yc) || (y > ys && y <= yc) )
			{
				if(++qs > 4)qs=1;
				if(qs > 2)m = -1;
				else m = 1;
				flg=1;
			}
			cont(xc,yc);
			xs = xc; 
			ys = yc;
			if(qs == qf && flg == 1)
				switch(qs){
				case 1:
				case 4:
					if(ys >= y1)return;
					continue;
				case 2:
				case 3:
					if(ys <= y1)return;
				}
		}
	}
}

int
quad(int x, int y, int xp, int yp)
{
	if(x < xp)
		if(y <= yp)return(1);
		else return(4);
	else if(x > xp)
		if(y < yp)return(2);
		else return(3);
	else if(y < yp)return(2);
	else return(4);
}

int
abs(int a)
{
	if(a < 0)return(-a);
	return(a);
}
