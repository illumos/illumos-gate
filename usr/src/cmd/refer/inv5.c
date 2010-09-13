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

#include <stdio.h>
#include <locale.h>

extern void err();

int
recopy(FILE *ft, FILE *fb, FILE *fa, int nhash)
{
	/* copy fb (old hash items/pointers) to ft (new ones) */
	int n, i, iflong;
	long getl();
	int getw();
	int *hpt_s;
	int (*getfun)();
	long *hpt_l;
	long k, lp;
	if (fa == NULL) {
		err(gettext("No old pointers"), 0);
		return (0);
	}
	fread(&n, sizeof (n), 1, fa);
	fread(&iflong, sizeof (iflong), 1, fa);
	if (iflong) {
		hpt_l = (long *)calloc(sizeof (*hpt_l), n+1);
		n = fread(hpt_l, sizeof (*hpt_l), n, fa);
	} else {
		hpt_s = (int *)calloc(sizeof (*hpt_s), n+1);
		n = fread(hpt_s, sizeof (*hpt_s), n, fa);
	}
	if (n != nhash)
		fprintf(stderr, gettext("Changing hash value to old %d\n"), n);
	fclose(fa);
	if (iflong)
		getfun = (int(*)())getl;
	else
		getfun = getw;
	for (i = 0; i < n; i++) {
		if (iflong)
			lp = hpt_l[i];
		else
			lp = hpt_s[i];
		fseek(fb, lp, 0);
		while ((k = (*getfun)(fb)) != -1)
			fprintf(ft, "%04d %06ld\n", i, k);
	}
	fclose(fb);
	return (n);
}
