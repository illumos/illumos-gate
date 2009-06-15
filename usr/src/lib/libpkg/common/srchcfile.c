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
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <sys/types.h>
#include <libintl.h>
#include "pkglib.h"
#include "pkgstrct.h"
#include "pkglocale.h"
#include "pkglibmsgs.h"

/*
 * Forward declarations
 */

static int	getend(char **cp);
static int	getstr(char **cp, int n, char *str, int separator[]);

/* from gpkgmap.c */
int	getnumvfp(char **cp, int base, long *d, long bad);
int	getlnumvfp(char **cp, int base, fsblkcnt_t *d, long bad);

/*
 * Module globals
 */

static char	lpath[PATH_MAX];	/* for ept->path */
static char	mylocal[PATH_MAX];	/* for ept->ainfo.local */
static int	decisionTableInit = 0;

/*
 * These arrays must be indexable by an unsigned char.
 */

static int	ISWORDSEP[UCHAR_MAX+1];
static int	ISPKGNAMESEP[UCHAR_MAX+1];

/*
 * Name:	COPYPATH
 * Description:	copy path limiting size to destination capacity
 * Arguments:	DEST - (char []) - [RW]
 *		SRC - (char *) - [RO, *RO]
 *			Pointer to first byte of path to copy
 *		LEN - (int) - [RO]
 *			Number of bytes to copy
 */

#define	COPYPATH(DEST, SRC, LEN)					\
	{								\
		/* assure return path does not overflow */		\
		if ((LEN) > sizeof ((DEST))) {				\
			(LEN) = sizeof ((DEST))-1;			\
		}							\
		/* copy return path to local storage */			\
		(void) memcpy((DEST), (SRC), (LEN));			\
		(DEST)[(LEN)] = '\0';					\
	}

/*
 * Name:	srchcfile
 * Description:	search contents file looking for closest match to entry,
 *		creating a new contents file if output contents file specified
 * Arguments:	ept - (struct cfent *) - [RO, *RW]
 *			- contents file entry, describing last item found
 *		path - (char *) - [RO, *RO]
 *			- path to search for in contents file
 *			- If path is "*", then the next entry is returned;
 *				the next entry always matches this path
 *		PKGserver
 *			- our door to the database server.
 *
 * Returns:	int
 *		< 0 - error occurred
 *			- Use getErrstr to retrieve character-string describing
 *			  the reason for failure
 *		== 0 - no match found
 *			- specified path not in the contents file
 *		== 1 - exact match found
 *			- specified path found in contents file
 *			- this value is always returned if path is "*" and the
 *			  next entry is returned - 0 is returned when no more
 *			  entries are left to process
 * Side Effects:
 *		- The ept structure supplied is filled in with a description of
 *		  the item that caused the search to terminate, except in the
 *		  case of '0' in which case the contents of 'ept' is undefined.
 *		- NOTE: the ept->path item points to a path that is statically
 *		  allocated and will be overwritten on the next call.
 *		- NOTE: the ept->ainfo.local item points to a path that is
 *		  statically allocated and will be overwritten on the next call.
 */

int
srchcfile(struct cfent *ept, char *path, PKGserver server)
{
	char		*cpath_start = NULL;
	char		classname[CLSSIZ+1];
	char		pkgname[PKGSIZ+1];
	int		anypath = 0;
	int		c;
	int		cpath_len = 0;
	struct pinfo	*lastpinfo;
	struct pinfo	*pinfo;
	char		*p;
	char		*curbuf;
	int		linelen;	/* includes NUL */

	/*
	 * this code does not use nested subroutines because execution time
	 * of this routine is especially critical to installation and upgrade
	 */

	/* initialize local variables */

	setErrstr(NULL);	/* no error message currently cached */
	lpath[0] = '\0';
	lpath[sizeof (lpath)-1] = '\0';

	/* initialize ept structure values */

	(void) strlcpy(ept->ainfo.group, BADGROUP, sizeof (ept->ainfo.group));
	(void) strlcpy(ept->ainfo.owner, BADOWNER, sizeof (ept->ainfo.owner));
	(void) strlcpy(ept->pkg_class, BADCLASS,  sizeof (ept->pkg_class));
	ept->ainfo.local = (char *)NULL;
	ept->ainfo.mode = BADMODE;
	ept->cinfo.cksum = BADCONT;
	ept->cinfo.modtime = BADCONT;
	ept->cinfo.size = (fsblkcnt_t)BADCONT;
	ept->ftype = BADFTYPE;
	ept->npkgs = 0;
	ept->path = (char *)NULL;
	ept->pinfo = (struct pinfo *)NULL;
	ept->pkg_class_idx = -1;
	ept->volno = 0;

	/*
	 * populate decision tables that implement fast character checking;
	 * this is much faster than the equivalent strpbrk() call or a
	 * while() loop checking for the characters. It is only faster if
	 * there are at least 3 characters to scan for - when checking for
	 * one or two characters (such as '\n' or '\0') its faster to do
	 * a simple while() loop.
	 */

	if (decisionTableInit == 0) {
		/*
		 * any chars listed stop scan;
		 * scan stops on first byte found that is set to '1' below
		 */

		/*
		 * Separators for normal words
		 */
		bzero(ISWORDSEP, sizeof (ISWORDSEP));
		ISWORDSEP[' '] = 1;
		ISWORDSEP['\t'] = 1;
		ISWORDSEP['\n'] = 1;
		ISWORDSEP['\0'] = 1;

		/*
		 * Separators for list of packages, includes \\ for
		 * alternate ftype and : for classname
		 */
		bzero(ISPKGNAMESEP, sizeof (ISPKGNAMESEP));
		ISPKGNAMESEP[' '] = 1;
		ISPKGNAMESEP['\t'] = 1;
		ISPKGNAMESEP['\n'] = 1;
		ISPKGNAMESEP[':'] = 1;
		ISPKGNAMESEP['\\'] = 1;
		ISPKGNAMESEP['\0'] = 1;

		decisionTableInit = 1;
	}

	/* if the path to scan for is empty, act like no path was specified */

	if ((path != NULL) && (*path == '\0')) {
		path = NULL;
	}

	/*
	 * if path to search for is "*", then we will return the first path
	 * we encounter as a match, otherwise we return an error
	 */

	if ((path != NULL) && (path[0] != '/')) {
		if (strcmp(path, "*") != 0) {
			setErrstr(pkg_gt(ERR_ILLEGAL_SEARCH_PATH));
			return (-1);
		}
		anypath = 1;
	}

	/* attempt to narrow down the search for the specified path */

	if (anypath == 0 && path == NULL)
		return (0);

	/* determine first character of the next entry */
	if (anypath == 0)
		curbuf = pkggetentry_named(server, path, &linelen, &cpath_len);
	else
		curbuf = pkggetentry(server, &linelen, &cpath_len);

	if (curbuf == NULL)
		return (0);

	/*
	 * current entry DOES start with absolute path
	 * set ept->path to point to lpath
	 * set cpath_start/cpath_len to point to the file name
	 */

	/* copy first token into path element of passed structure */

	cpath_start = curbuf;

	p = cpath_start + cpath_len;

	ept->path = lpath;

	/* copy path found to 'lpath' */
	COPYPATH(lpath, cpath_start, cpath_len);

	/* get first character following the end of the path */

	c = *p++;

	/*
	 * we want to return information about this path in
	 * the structure provided, so parse any local path
	 * and jump to code which parses rest of the input line
	 */
	if (c == '=') {
		/* parse local path specification */
		if (getstr(&p, PATH_MAX, mylocal, ISWORDSEP)) {
			setErrstr(ERR_CANNOT_READ_LL_PATH);
			return (-1);
		}
		ept->ainfo.local = mylocal;
	}

	/*
	 * if an exact match and processing a new style entry, read the
	 * remaining information from the new style entry.
	 */

	while (isspace((c = *p++)))
		;

	switch (c) {
	case '?': case 'f': case 'v': case 'e': case 'l':
	case 's': case 'p': case 'c': case 'b': case 'd':
	case 'x':
		/* save ftype */
		ept->ftype = (char)c;

		/* save class */
		if (getstr(&p, CLSSIZ, ept->pkg_class, ISWORDSEP)) {
			setErrstr(ERR_CANNOT_READ_CLASS_TOKEN);
			return (-1);
		}
		break; /* we already read the pathname */

	case '\0':
		/* end of line before new-line seen */
		setErrstr(ERR_INCOMPLETE_ENTRY);
		return (-1);

	case '0': case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
		setErrstr(ERR_VOLUMENO_UNEXPECTED);
		return (-1);

	case 'i':
		setErrstr(ERR_FTYPE_I_UNEXPECTED);
		return (-1);

	default:
		/* unknown ftype */
		setErrstr(ERR_UNKNOWN_FTYPE);
		return (-1);
	}

	/* link/symbolic link must have link destination */

	if (((ept->ftype == 's') || (ept->ftype == 'l')) &&
	    (ept->ainfo.local == NULL)) {
		setErrstr(ERR_NO_LINK_SOURCE_SPECIFIED);
		return (-1);
	}

	/* character/block devices have major/minor device numbers */

	if (((ept->ftype == 'c') || (ept->ftype == 'b'))) {
		ept->ainfo.major = BADMAJOR;
		ept->ainfo.minor = BADMINOR;
		if (getnumvfp(&p, 10, (long *)&ept->ainfo.major, BADMAJOR) ||
		    getnumvfp(&p, 10, (long *)&ept->ainfo.minor, BADMINOR)) {
			setErrstr(pkg_gt(ERR_CANNOT_READ_MM_NUMS));
			return (-1);
		}
	}

	/* most types have mode, owner, group identification components */

	if ((ept->ftype == 'd') || (ept->ftype == 'x') || (ept->ftype == 'c') ||
	    (ept->ftype == 'b') || (ept->ftype == 'p') ||
	    (ept->ftype == 'f') || (ept->ftype == 'v') ||
	    (ept->ftype == 'e')) {
		/* mode, owner, group should be here */
		if (getnumvfp(&p, 8, (long *)&ept->ainfo.mode, BADMODE) ||
		    getstr(&p, sizeof (ept->ainfo.owner), ept->ainfo.owner,
		    ISWORDSEP) ||
		    getstr(&p, sizeof (ept->ainfo.group), ept->ainfo.group,
		    ISWORDSEP)) {
			setErrstr(ERR_CANNOT_READ_MOG);
			return (-1);
		}
	}

	/* i/f/v/e have size, checksum, modification time components */

	if ((ept->ftype == 'i') || (ept->ftype == 'f') ||
	    (ept->ftype == 'v') || (ept->ftype == 'e')) {
		/* look for content description */
		if (getlnumvfp(&p, 10, (fsblkcnt_t *)&ept->cinfo.size,
		    BADCONT) ||
		    getnumvfp(&p, 10, (long *)&ept->cinfo.cksum, BADCONT) ||
		    getnumvfp(&p, 10, (long *)&ept->cinfo.modtime, BADCONT)) {
			setErrstr(ERR_CANNOT_READ_CONTENT_INFO);
			return (-1);
		}
	}

	/* i files processing is completed - return 'exact match found' */

	if (ept->ftype == 'i') {
		return (1);
	}

	/*
	 * determine list of packages which reference this entry
	 */

	lastpinfo = (struct pinfo *)NULL;
	while ((c = getstr(&p, sizeof (pkgname), pkgname, ISPKGNAMESEP)) <= 0) {
		/* if c < 0 the string was too long to fix in the buffer */

		if (c < 0) {
			setErrstr(ERR_PACKAGE_NAME_TOO_LONG);
			return (-1);
		}

		/* a package is present - create and populate pinfo structure */

		pinfo = (struct pinfo *)calloc(1, sizeof (struct pinfo));
		if (!pinfo) {
			setErrstr(ERR_NO_MEMORY);
			return (-1);
		}
		if (!lastpinfo) {
			ept->pinfo = pinfo; /* first one */
		} else {
			lastpinfo->next = pinfo; /* link list */
		}
		lastpinfo = pinfo;

		if ((pkgname[0] == '-') || (pkgname[0] == '+') ||
		    (pkgname[0] == '*') || (pkgname[0] == '~') ||
		    (pkgname[0] == '!') || (pkgname[0] == '%')) {
			pinfo->status = pkgname[0];
			(void) strlcpy(pinfo->pkg, pkgname+1,
			    sizeof (pinfo->pkg));
		} else {
			(void) strlcpy(pinfo->pkg, pkgname,
			    sizeof (pinfo->pkg));
		}

		/* pkg/[:[ftype][:class] */
		c = *p++;
		if (c == '\\') {
			/* get alternate ftype */
			pinfo->editflag++;
			c = *p++;
		}

		if (c == ':') {
			/* get special classname */
			(void) getstr(&p, sizeof (classname), classname,
			    ISWORDSEP);
			(void) strlcpy(pinfo->aclass, classname,
			    sizeof (pinfo->aclass));
			c = *p++;
		}
		ept->npkgs++;

		/* break out of while if at end of entry */

		if ((c == '\n') || (c == '\0')) {
			break;
		}

		/* if package not separated by a space return an error */

		if (!isspace(c)) {
			setErrstr(ERR_BAD_ENTRY_END);
			return (-1);
		}
	}

	/*
	 * parsing of the entry is complete
	 */

	/* if not at the end of the entry, make it so */

	if ((c != '\n') && (c != '\0')) {
		if (getend(&p) && ept->pinfo) {
			setErrstr(ERR_EXTRA_TOKENS);
			return (-1);
		}
	}

	return (1);
}

static int
getstr(char **cp, int n, char *str, int separator[])
{
	int	c;
	char	*p = *cp;
	char	*p1;
	size_t	len;

	if (*p == '\0') {
		return (1);
	}

	/* leading white space ignored */

	while (((c = *p) != '\0') && (isspace(*p++)))
		;
	if ((c == '\0') || (c == '\n')) {
		p--;
		*cp = p;
		return (1); /* nothing there */
	}

	p--;

	/* compute length based on delimiter found or not */

	p1 = p;
	while (separator[(int)(*(unsigned char *)p1)] == 0) {
		p1++;
	}

	len = (ptrdiff_t)p1 - (ptrdiff_t)p;

	/* if string will fit in result buffer copy string and return success */

	if (len < n) {
		(void) memcpy(str, p, len);
		str[len] = '\0';
		p += len;
		*cp = p;
		return (0);
	}

	/* result buffer too small; copy partial string, return error */
	(void) memcpy(str, p, n-1);
	str[n-1] = '\0';
	p += n;
	*cp = p;
	return (-1);
}

static int
getend(char **cp)
{
	int	n;
	char	*p = *cp;

	n = 0;

	/* if at end of buffer return no more characters left */

	if (*p == '\0') {
		return (0);
	}

	while ((*p != '\0') && (*p != '\n')) {
		if (n == 0) {
			if (!isspace(*p)) {
				n++;
			}
		}
		p++;
	}

	*cp = ++p;
	return (n);
}
