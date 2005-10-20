/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SORTS UP.
 * IF THERE ARE NO EXCHANGES (IEX=0) ON A SWEEP
 * THE COMPARISON GAP (IGAP) IS HALVED FOR THE NEXT SWEEP
 */
void
shell(int n, int (*comp)(), int (*exch)())
{
	int igap, iplusg, iex, i, imax;
	igap = n;
	while (igap > 1) {
		igap /= 2;
		imax = n-igap;
		do {
			iex = 0;
			for (i = 0; i < imax; i++) {
				iplusg = i + igap;
				if ((*comp)(i, iplusg)) continue;
				(*exch) (i, iplusg);
				iex = 1;
			}
		}
		while (iex > 0)
			;
	}
}
