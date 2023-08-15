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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"	/* from SVR4 bnu:expfile.c 2.10 */

#include "uucp.h"

/*
 * expand file name expansion is based on first characters
 *	/	-> fully qualified pathname. no
 *		   processing necessary
 *	~	-> prepended with login directory
 *	~/	-> prepended with Pubdir
 *	default	-> prepended with current directory
 *	file	-> filename to expand
 * returns:
 *	0	-> ok
 *      FAIL	-> no Wrkdir name available
 */
int
expfile(file)
register char *file;
{
	register char *fpart, *up;
	uid_t uid;
	char user[NAMESIZE], save[MAXFULLNAME];
	extern int gninfo(), canPath();

	if (strlcpy(save, file, sizeof (save)) >= sizeof (save))
		return(FAIL);
	if (*file != '/')
	    if (*file ==  '~') {
		/* find / and copy user part */
		for (fpart = save + 1, up = user; *fpart != '\0'
			&& *fpart != '/'; fpart++)
				*up++ = *fpart;
		*up = '\0';
		if ((user[0]=='\0') || (gninfo(user, &uid, file) != 0)){
			(void) strcpy(file, Pubdir);
		}
		if (strlen(file) + strlen(fpart) + 1 > (unsigned)MAXFULLNAME)
			return(FAIL);
		(void) strcat(file, fpart);
	    } else {
		if (strlen(Wrkdir) + strlen(save) + 2 > (unsigned)MAXFULLNAME)
			return(FAIL);
		(void) sprintf(file, "%s/%s", Wrkdir, save);
		if (Wrkdir[0] == '\0')
			return(FAIL);
	    }

	if (canPath(file) != 0) { /* I don't think this will ever fail */
	    (void) strcpy(file, CORRUPTDIR);
	    return(FAIL);
	} else
	    return(0);
}


/*
 * make all necessary directories
 *	name	-> directory to make
 *	mask	-> mask to use during directory creation
 * return:
 *	0	-> success
 * 	FAIL	-> failure
 */
int
mkdirs(name, mask)
mode_t mask;
register char *name;
{
	register char *p;
	mode_t omask;
	char dir[MAXFULLNAME];

	strcpy(dir, name);
	if (*LASTCHAR(dir) != '/')
	    	(void) strcat(dir, "/");
	p = dir + 1;
	for (;;) {
	    if ((p = strchr(p, '/')) == NULL)
		return(0);
	    *p = '\0';
	    if (DIRECTORY(dir)) {
		/* if directory exists and is owned by uucp, child's
		    permissions should be no more open than parent */
		if (__s_.st_uid == UUCPUID)
		    mask |= ((~__s_.st_mode) & PUB_DIRMODE);
	    } else {
		DEBUG(4, "mkdir - %s\n", dir);
		omask = umask(mask);
		if (mkdir(dir, PUB_DIRMODE) == FAIL) {
		    umask(omask);
		    return (FAIL);
		}
		umask(omask);
	    }
	    *p++ = '/';
	}
	/* NOTREACHED */
}

/*
 * expand file name and check return
 * print error if it failed.
 *	file	-> file name to check
 * returns:
 *      0	-> ok
 *      FAIL	-> if expfile failed
 */
int
ckexpf(file)
char *file;
{
	if (expfile(file) == 0)
		return(0);

	fprintf(stderr, gettext("Illegal filename (%s).\n"), file);
	return(FAIL);
}


/*
 * make canonical path out of path passed as argument.
 *
 * Eliminate redundant self-references like // or /./
 * (A single terminal / will be preserved, however.)
 * Dispose of references to .. in the path names.
 * In relative path names, this means that .. or a/../..
 * will be treated as an illegal reference.
 * In full paths, .. is always allowed, with /.. treated as /
 *
 * returns:
 *	0	-> path is now in canonical form
 *	FAIL	-> relative path contained illegal .. reference
 */

int
canPath(path)
register char *path;	/* path is modified in place */
{
    register char *to, *fr;

    to = fr = path;
    if (*fr == '/') *to++ = *fr++;
    for (;;) {
	/* skip past references to self and validate references to .. */
	for (;;) {
	    if (*fr == '/') {
		fr++;
		continue;
	    }
	    if ((strncmp(fr, "./", 2) == SAME) || EQUALS(fr, ".")) {
		fr++;
		continue;
	    }
	    if ((strncmp(fr, "../", 3) == SAME) || EQUALS(fr, "..")) {
		fr += 2;
		/*	/.. is /	*/
		if (((to - 1) == path) && (*path == '/')) continue;
		/* error if no previous component */
		if (to <= path) return (FAIL);
		/* back past previous component */
		while ((--to > path) && (to[-1] != '/'));
		continue;
	    }
	    break;
	}
	/*
	 * What follows is a legitimate component,
	 * terminated by a null or a /
	 */
	if (*fr == '\0') break;
	while (((*to++ = *fr) != '\0') && (*fr++ != '/'));
    }
    /* null path is . */
    if (to == path) *to++ = '.';
    *to = '\0';
    return (0);
}
