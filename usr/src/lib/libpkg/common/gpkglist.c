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
#include <ctype.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <valtools.h>
#include "pkginfo.h"
#include "pkglib.h"
#include "pkglibmsgs.h"
#include "pkgstrct.h"
#include "pkglocale.h"

extern char	*pkgdir; 		/* WHERE? */

/* libadm.a */
extern CKMENU	*allocmenu(char *label, int attr);
extern int	ckitem(CKMENU *menup, char *item[], short max, char *defstr,
				char *error, char *help, char *prompt);
extern int	pkgnmchk(register char *pkg, register char *spec,
				int presvr4flg);
extern int	fpkginfo(struct pkginfo *info, char *pkginst);
extern char	*fpkginst(char *pkg, ...);
extern int	setinvis(CKMENU *menup, char *choice);
extern int	setitem(CKMENU *menup, char *choice);

#define	CMDSIZ			512
#define	LSIZE			256
#define	MAXSIZE			128
#define	MALLOCSIZ		128
#define	MAX_CAT_ARGS	64
#define	MAX_CAT_LEN		16

static int	cont_in_list = 0;	/* live continuation */
static char	cont_keyword[PKGSIZ+1];	/* the continuation keyword */

/*
 * Allocate memory for the next package name. This function attempts the
 * allocation and if that succeeds, returns a pointer to the new memory
 * location and increments "n". Otherwise, it returens NULL and n is
 * unchanged.
 */
static char **
next_n(int *n, char **nwpkg)
{
	int loc_n = *n;

	if ((++loc_n % MALLOCSIZ) == 0) {
		nwpkg = (char **)realloc(nwpkg,
			(loc_n+MALLOCSIZ) * sizeof (char **));
		if (nwpkg == NULL) {
			progerr(pkg_gt(ERR_MEMORY), errno);
			errno = ENOMEM;
			return (NULL);
		}
	}

	*n = loc_n;
	return (nwpkg);
}

/*
 * This informs gpkglist() to put a keyword at the head of the pkglist. This
 * was originally intended for live continue, but it may have other
 * applications as well.
 */
void
pkglist_cont(char *keyword)
{
	cont_in_list = 1;
	(void) strncpy(cont_keyword, keyword, PKGSIZ);
}

/*
 * This function constructs the list of packages that the user wants managed.
 * It may be a list on the command line, it may be some or all of the
 * packages in a directory or it may be a continuation from a previous
 * dryrun. It may also be a list of pkgs gathered from the CATEGORY parameter
 * in a spooled or installed pkginfo file.
 */
char **
gpkglist(char *dir, char **pkg, char **catg)
{
	struct _choice_ *chp;
	struct pkginfo info;
	char	*inst;
	CKMENU	*menup;
	char	temp[LSIZE];
	char	*savedir, **nwpkg;
	int	i, n;

	savedir = pkgdir;
	pkgdir = dir;

	info.pkginst = NULL; /* initialize for memory handling */
	if (pkginfo(&info, "all", NULL, NULL)) {
		errno = ENOPKG; /* contains no valid packages */
		pkgdir = savedir;
		return (NULL);
	}

	/*
	 * If no explicit list was provided and this is not a continuation
	 * (implying a certain level of direction on the caller's part)
	 * present a menu of available packages for installation.
	 */
	if (pkg[0] == NULL && !cont_in_list) {
		menup = allocmenu(pkg_gt(HEADER), CKALPHA);
		if (setinvis(menup, "all")) {
			errno = EFAULT;
			return (NULL);
		}
		do {
			/* bug id 1087404 */
			if (!info.pkginst || !info.name || !info.arch ||
			    !info.version)
				continue;
			(void) sprintf(temp, "%s %s\n(%s) %s", info.pkginst,
				info.name, info.arch, info.version);
			if (setitem(menup, temp)) {
				errno = EFAULT;
				return (NULL);
			}
		} while (pkginfo(&info, "all", NULL, NULL) == 0);
		/* clear memory usage by pkginfo */
		(void) pkginfo(&info, NULL, NULL, NULL);
		pkgdir = savedir; 	/* restore pkgdir to orig value */

		nwpkg = (char **)calloc(MALLOCSIZ, sizeof (char **));
		n = ckitem(menup, nwpkg, MALLOCSIZ, "all", NULL,
		    pkg_gt(HELP), pkg_gt(PROMPT));
		if (n) {
			free(nwpkg);
			errno = ((n == 3) ? EINTR : EFAULT);
			pkgdir = savedir;
			return (NULL);
		}
		if (strcmp(nwpkg[0], "all") == 0) {
			chp = menup->choice;
			for (n = 0; chp; /* void */) {
				nwpkg[n] = strdup(chp->token);
				nwpkg = next_n(&n, nwpkg);
				chp = chp->next;
				nwpkg[n] = NULL;
			}
		} else {
			for (n = 0; nwpkg[n]; n++)
				nwpkg[n] = strdup(nwpkg[n]);
		}
		(void) setitem(menup, NULL); /* free resources */
		free(menup);
		pkgdir = savedir;
		return (nwpkg);
	}

	/* clear memory usage by pkginfo */
	(void) pkginfo(&info, NULL, NULL, NULL);

	nwpkg = (char **)calloc(MALLOCSIZ, sizeof (char **));

	/*
	 * pkg array contains the instance identifiers to
	 * be selected, or possibly wildcard definitions
	 */
	i = n = 0;
	do {
		if (cont_in_list) {	/* This is a live continuation. */
			nwpkg[n] = strdup(cont_keyword);
			nwpkg = next_n(&n, nwpkg);
			nwpkg[n] = NULL;
			cont_in_list = 0;	/* handled */

			if (pkg[0] == NULL) {	/* It's just a continuation. */
				break;
			}
		} else if (pkgnmchk(pkg[i], "all", 1)) {
			/* wildcard specification */
			(void) fpkginst(NULL);
			inst = fpkginst(pkg[i], NULL, NULL);
			if (inst == NULL) {
				progerr(pkg_gt(ERR_NOPKG), pkg[i]);
				free(nwpkg);
				nwpkg = NULL;
				errno = ESRCH;
				break;
			}
			do {
				if (catg != NULL) {
					pkginfo(&info, inst, NULL, NULL);
					if (!is_same_CATEGORY(catg,
							info.catg))
						continue;
				}
				nwpkg[n] = strdup(inst);
				nwpkg = next_n(&n, nwpkg);
				nwpkg[n] = NULL;
			} while (inst = fpkginst(pkg[i], NULL, NULL));
		} else {
			if (fpkginfo(&info, pkg[i])) {
				progerr(pkg_gt(ERR_NOPKG), pkg[i]);
				free(nwpkg);
				nwpkg = NULL;
				errno = ESRCH;
				break;
			}
			nwpkg[n] = strdup(pkg[i]);
			nwpkg = next_n(&n, nwpkg);
			nwpkg[n] = NULL;
		}
	} while (pkg[++i]);

	(void) fpkginst(NULL);
	(void) fpkginfo(&info, NULL);
	pkgdir = savedir; 	/* restore pkgdir to orig value */

	if (catg != NULL) {
		if (nwpkg[0] == NULL) {

			/*
			 * No pkgs in the spooled directory matched the
			 * category specified by the user.
			 */

			free(nwpkg);
			return (NULL);
		}
	}
	return (nwpkg);
}

/*
 * Check category passed in on the command line to see if it is valid.
 *
 * returns 0 if the category is valid
 * returns 1 if the category is invalid
 */

int
is_not_valid_category(char **category, char *progname)
{
	if (strcasecmp(progname, "pkgrm") == 0) {
		if (is_same_CATEGORY(category, "system"))
			return (1);
	}

	return (0);
}

/*
 * Check category length
 *
 * returns 0 if the category length is valid
 * returns 1 if a category has length > 16 chars as defined by the SVr4 ABI
 */

int
is_not_valid_length(char **category)
{
	int i;

	for (i = 0; category[i] != NULL; i++) {
		if (strlen(category[i]) > MAX_CAT_LEN)
			return (1);
	}

	return (0);
}

/*
 * Check category passed in on the command line against the CATEGORY in the
 * spooled or installed packages pkginfo file.
 *
 * returns 0 if categories match
 * returns 1 if categories don't match
 */

int
is_same_CATEGORY(char **category, char *persistent_category)
{
	int i, j, n = 0;
	char *pers_catg, **pers_catgs;

	pers_catg = strdup(persistent_category);

	pers_catgs = (char **)calloc(MAX_CAT_LEN, sizeof (char **));

	pers_catgs[n++] = strtok(pers_catg, " \t\n, ");
	while (pers_catgs[n] = strtok(NULL, " \t\n, "))
		n++;

	for (i = 0; category[i] != NULL; i++) {
		for (j = 0; j < n; j++) {
			if (strcasecmp(category[i], pers_catgs[j]) == 0) {
				return (1);
			}
		}
	}

	return (0);
}

/*
 * Given a string of categories, construct a null-terminated array of
 * categories.
 *
 * returns the array of categories or NULL
 */

char **
get_categories(char *catg_arg)
{
	int n = 0;
	char *tmp_catg;
	char **catgs;

	tmp_catg = strdup(catg_arg);

	catgs = (char **)calloc(MAX_CAT_LEN, sizeof (char **));

	catgs[n++] = strtok(tmp_catg, " \t\n, ");
	while (catgs[n] = strtok(NULL, " \t\n, "))
		n++;

	if (*catgs == NULL)
		return (NULL);
	else
		return (catgs);
}
