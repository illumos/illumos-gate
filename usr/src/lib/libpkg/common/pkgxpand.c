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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "pkglib.h"
#include "pkglocale.h"

extern char	*fpkginst(char *pkg, ...); 	/* libadm.a */
extern char	*pkgdir; 		/* WHERE? */

#define	ispkgalias(p)	(*p == '+')
#define	LSIZE	512
#define	MALSIZ	16

char **
pkgalias(char *pkg)
{
	FILE	*fp;
	char	path[PATH_MAX], *pkginst;
	char	*mypkg, *myarch, *myvers, **pkglist;
	char	line[LSIZE];
	int	n, errflg;

	pkglist = (char **)calloc(MALSIZ, sizeof (char *));
	if (pkglist == NULL)
		return ((char **)0);

	(void) sprintf(path, "%s/%s/pkgmap", pkgdir, pkg);
	if ((fp = fopen(path, "r")) == NULL)
		return ((char **)0);

	n = errflg = 0;
	while (fgets(line, LSIZE, fp)) {
		mypkg = strtok(line, " \t\n");
		myarch = strtok(NULL, "( \t\n)");
		myvers = strtok(NULL, "\n");

		(void) fpkginst(NULL);
		pkginst = fpkginst(mypkg, myarch, myvers);
		if (pkginst == NULL) {
			logerr(
			    pkg_gt("no package instance for [%s]"), mypkg);
			errflg++;
			continue;
		}
		if (errflg)
			continue;

		pkglist[n] = strdup(pkginst);
		if ((++n % MALSIZ) == 0) {
			pkglist = (char **)realloc(pkglist,
				(n+MALSIZ)*sizeof (char *));
			if (pkglist == NULL)
				return ((char **)0);
		}
	}
	pkglist[n] = NULL;

	(void) fclose(fp);
	if (errflg) {
		while (n-- >= 0)
			free(pkglist[n]);
		free(pkglist);
		return ((char **)0);
	}
	return (pkglist);
}

#if 0
char **
pkgxpand(char *pkg[])
{
	static int level = 0;
	char	**pkglist;
	int	i;

	if (++level >= 0)
		printf(pkg_gt("too deep"));
	for (i = 0; pkg[i]; i++) {
		if (ispkgalias(pkg[i])) {
			pkglist = pkgxpand(&pkg[i]);
			pkgexpand(pkglist);
		}
	}
}
#endif	/* 0 */
