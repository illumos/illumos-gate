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

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<string.h>
#include	"wish.h"
#include	"token.h"
#include	"slk.h"
#include	"actrec.h"
#include	"ctl.h"
#include	"moremacros.h"
#include	"sizes.h"

extern int Vflag;
extern char *Aliasfile;

#define MAX_ALIAS	32

static int	Num_alias = 0;
static struct	pathalias {
	char	*alias;
	char	*path;
} Alias[MAX_ALIAS];

static void get_one(char *path);
static void get_aliases(void);

char *
path_to_full(s)
char	*s;
{
	int	n;
	char	buf[PATHSIZ];
	register char	*p, *q;
	bool	b;
	struct actrec	*a;
	extern char	*Home, *Filecabinet;
	struct actrec	*wdw_to_ar();
	char	 *expand(), *alias_to_path();

	if (strcmp(s, "-i") == 0)	/* unfortunate kludge for inline objects */
		return(strsave(s));

	if (Num_alias == 0 && Aliasfile)
		get_aliases();

	/* check if a number, if so then path of an open folder */

	if ((n = atoi(s)) > 0 && strspn(s, "0123456789") == strlen(s) && 
			(a = wdw_to_ar(n)) != NULL)
		return(strsave(a->path));

	p = expand(s);
	if (*p == '/')	/* already a full path */
		return(p);

	/* check if an alias of another path */

	if (q = strchr(p, '/'))
		*q = '\0';
	if ((s = alias_to_path(p, q ? q + 1 : NULL)) != NULL)
		return(s);
	if (q)
		*q = '/'; 		/* restore p */

	if (Vflag) {
		/*
		 * relative to current folder if there is one, else FILECABINET
		 */

		if (ar_ctl(ar_get_current(), CTISDEST, &b, NULL, NULL, NULL, NULL, NULL) != FAIL && b == TRUE)
			sprintf(buf, "%s/%s", ar_get_current()->path, p);
		else
			sprintf(buf, "%s/%s", Filecabinet, p);
	}
	else 
		strcpy(buf, p); 
	free(p);
	return(strsave(buf));
}

static void
get_aliases(void)
{
	char	path[PATHSIZ];
	extern char	*Home;

	if (Vflag) {
		sprintf(path, "%s/pref/pathalias", Home);
		get_one(path);
	}
	strcpy(path, Aliasfile);
	get_one(path);
}

static void
get_one(char *path)
{
	FILE	*fp;
	char	buf[BUFSIZ];
	char	*p;
	char	 *expand();

	if ((fp = fopen(path, "r")) == NULL)
		return;

	while (Num_alias < MAX_ALIAS && fgets(buf, BUFSIZ, fp)) {
		if (p = strchr(buf, '=')) {
			buf[strlen(buf)-1] = '\0';	/* clip off the newline */
			*p = '\0';
			/* les 12/4
			if (Alias[Num_alias].alias)
				free(Alias[Num_alias].alias);
			*/
			Alias[Num_alias].alias = strsave(buf);
			Alias[Num_alias].path = expand(++p);
			Num_alias++;
		}
	}
	fclose(fp);
}

char *
alias_to_path(s, rest)
char	*s;
char	*rest;
{
	register int	i;
	
	for (i = 0; i < Num_alias; i++) {
		if (strCcmp(s, Alias[i].alias) == 0) {
			char *hold;
			register char *p;
			char path[PATHSIZ];

			if (!strchr(Alias[i].path, ':')) {
				strcpy(path, Alias[i].path);
				if (rest) {
					strcat(path, "/");
					strcat(path, rest);
				}
				return(strsave(path));
			}
			for (p = strtok(hold = strsave(Alias[i].path), ":"); p; p = strtok(NULL, ":")) {
				strcpy(path, p);
				if (rest) {
					strcat(path, "/");
					strcat(path, rest);
				}
				if (access(path, 0) == 0) {
					free(hold);
					return(strsave(path));
				}
			}
			break;
		}
	}
	return(NULL);
}
