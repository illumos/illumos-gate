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

static void	findend(char **cp);
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

static int	ISPKGPATHSEP[UCHAR_MAX+1];
static int	ISWORDSEP[UCHAR_MAX+1];
static int	ISPKGNAMESEP[UCHAR_MAX+1];

/*
 * Name:	WRITEDATA
 * Description:	write out data to VFP_T given start and end pointers
 * Arguments:	VFP - (VFP_T *) - [RO, *RW]
 *			Contents file VFP to narrow search on
 *		FIRSTPOS - (char *) - [RO, *RO]
 *			Pointer to first byte to write out
 *		LASTPOS - (char *) - [RO, *RO]
 *			Pointer to last byte to write out
 */

#define	WRITEDATA(VFP, FIRSTPOS, LASTPOS)				\
	{								\
		ssize_t XXlenXX;					\
		/* compute number of bytes skipped */			\
		XXlenXX = (ptrdiff_t)(LASTPOS) - (ptrdiff_t)(FIRSTPOS);	\
		/* write the bytes out */				\
		vfpPutBytes((VFP), (FIRSTPOS), XXlenXX);		\
	}

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
 * Name:	narrowSearch
 * Description:	narrow the search location for a specified path
 *		The contents and package map files are always sorted by path.
 *		This function is given a target path to search for given the
 *		current location in a contents file. It is assured that the
 *		target path has not been searched for yet in the contents file
 *		so the current location in the contents file is guaranteed to
 *		be less than the location of the target path (if present).
 *		Given this employ a binary search to speed up the search for
 *		the path nearest to a specified target path.
 * Arguments:	a_vfp - (VFP_T *) - [RO, *RW]
 *			Contents file VFP to narrow search on
 *		a_path - (char *) - [RO, *RO]
 *			Pointer to path to search for
 *		a_pathLen - (size_t) - [RO]
 *			Length of string (a_path)
 * Returns:	char *	- pointer to first byte of entry in contents file that
 *			is guaranteed to be the closest match to the specified
 *			a_path without being "greater than" the path.
 *			== (char *)NULL if no entry found
 */

static char *
narrowSearch(VFP_T *a_vfp, char *a_path, size_t a_pathLen)
{
	char	*phigh;
	char	*plow;
	char	*pmid;
	int	n;
	size_t	plen;

	/* if no path to compare, start at beginning */

	if ((a_path == (char *)NULL) || (*a_path == '\0')) {
		return ((char *)NULL);
	}

	/* if the contents file is empty, resort to sequential search */

	if (vfpGetBytesRemaining(a_vfp) <= 1) {
		return ((char *)NULL);
	}

	/*
	 * test against first path - if the path specified is less than the
	 * first path in the contents file, then the path can be inserted
	 * before the first entry in the contents file.
	 */

	/* locate start of first line */

	plow = vfpGetCurrCharPtr(a_vfp);
	pmid = plow;

	/* if first path not absolute, resort to sequential search */

	if (*pmid != '/') {
		return ((char *)NULL);
	}

	/* find end of path */

	while (ISPKGPATHSEP[(int)*pmid] == 0) {
		pmid++;
	}

	/* determine length of path */

	plen = (ptrdiff_t)pmid - (ptrdiff_t)plow;

	/* compare target path with current path */

	n = strncmp(a_path, plow, plen);
	if (n == 0) {
		/* if lengths same exact match return position found */
		if (a_pathLen == plen) {
			return (plow);
		}
		/* not exact match - a_path > pm */
		n = a_pathLen;
	}

	/* return if target is less than or equal to first entry */

	if (n <= 0) {
		return (plow);
	}

	/*
	 * test against last path - if the path specified is greater than the
	 * last path in the contents file, then the path can be appended after
	 * the last entry in the contents file.
	 */

	/* locate start of last line */

	plow = vfpGetCurrCharPtr(a_vfp);
	pmid = vfpGetLastCharPtr(a_vfp);

	while ((pmid > plow) && (!((pmid[0] == '/') && (pmid[-1] == '\n')))) {
		pmid--;
	}

	/* if absolute path, do comparison */

	if ((pmid > plow) && (*pmid == '/')) {
		plow = pmid;

		/* find end of path */

		while (ISPKGPATHSEP[(int)*pmid] == 0) {
			pmid++;
		}

		/* determine length of path */

		plen = (ptrdiff_t)pmid - (ptrdiff_t)plow;

		/* compare target path with current path */

		n = strncmp(a_path, plow, plen);
		if (n == 0) {
			/* if lengths same exact match return position found */
			if (a_pathLen == plen) {
				return (plow);
			}
			/* not exact match - a_path > pm */
			n = a_pathLen;
		}

		/* return if target is greater than or equal to entry */

		if (n >= 0) {
			return (plow);
		}
	}
	/*
	 * firstPath < targetpath < lastPath:
	 * binary search looking for closest "less than" match
	 */

	plow = vfpGetCurrCharPtr(a_vfp);
	phigh = vfpGetLastCharPtr(a_vfp);

	for (;;) {
		char	*pm;

		/* determine number of bytes left in search area */

		plen = (ptrdiff_t)phigh - (ptrdiff_t)plow;

		/* calculate mid point between current low and high points */

		pmid = plow + (plen >> 1);

		/* backup and find first "\n/" -or- start of buffer */

		while ((pmid > plow) &&
				(!((pmid[0] == '/') && (pmid[-1] == '\n')))) {
			pmid--;
		}

		/* return lowest line found if current line not past that */

		if (pmid <= plow) {
			return (plow);
		}

		/* remember start of this line */

		pm = pmid;

		/* find end of path */

		while (ISPKGPATHSEP[(int)*pmid] == 0) {
			pmid++;
		}

		/* determine length of path */

		plen = (ptrdiff_t)pmid - (ptrdiff_t)pm;

		/* compare target path with current path */

		n = strncmp(a_path, pm, plen);

		if (n == 0) {
			/* if lengths same exact match return position found */
			if (a_pathLen == plen) {
				return (pm);
			}
			/* not exact match - a_path > pm */
			n = a_pathLen;
		}


		/* not exact match - determine which watermark to split */

		if (n > 0) {	/* a_path > pm */
			plow = pm;
		} else {	/* a_path < pm */
			phigh = pm;
		}
	}
	/*NOTREACHED*/
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
 *			- If the path is (char *)NULL or "", then all remaining
 *				entries are processed and copied out to the
 *				file specified by cfTmpVFp
 *		cfVfp - (VFP_T *) - [RO, *RW]
 *			- VFP_T open on contents file to search
 *		cfTmpVfp - (VFP_T *) - [RO, *RW]
 *			- VFP_T open on temporary contents file to populate
 * Returns:	int
 *		< 0 - error occurred
 *			- Use getErrstr to retrieve character-string describing
 *			  the reason for failure
 *		== 0 - no match found
 *			- specified path not in the contents file
 *			- all contents of cfVfp copied to cfTmpVfp
 *			- current character of cfVfp is at end of file
 *		== 1 - exact match found
 *			- specified path found in contents file
 *			- contents of cfVfp up to entry found copied to cfTmpVfp
 *			- current character of cfVfp is first character of
 *				entry found
 *			- this value is always returned if path is "*" and the
 *			  next entry is returned - -1 is returned when no more
 *			  entries are left to process
 *		== 2 - entry found which is GREATER than path specified
 *			- specified path would fit BEFORE entry found
 *			- contents of cfVfp up to entry found copied to cfTmpVfp
 *			- current character of cfVfp is first character of
 *				entry found
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
srchcfile(struct cfent *ept, char *path, VFP_T *cfVfp, VFP_T *cfTmpVfp)
{
	char		*cpath_start = (char *)NULL;
	char		*firstPos = vfpGetCurrCharPtr(cfVfp);
	char		*lastPos = NULL;
	char		*pos;
	char		classname[CLSSIZ+1];
	char		pkgname[PKGSIZ+1];
	int		anypath = 0;
	int		c;
	int		dataSkipped = 0;
	int		n;
	int		rdpath;
	size_t		cpath_len = 0;
	size_t		pathLength;
	struct pinfo	*lastpinfo;
	struct pinfo	*pinfo;

	/*
	 * this code does not use nested subroutines because execution time
	 * of this routine is especially critical to installation and upgrade
	 */

	/* initialize local variables */

	setErrstr(NULL);	/* no error message currently cached */
	pathLength = (path == (char *)NULL ? 0 : strlen(path));
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
		 * Separators for path names, normal space and =
		 * for linked filenames
		 */
		bzero(ISPKGPATHSEP, sizeof (ISPKGPATHSEP));
		ISPKGPATHSEP['='] = 1;		/* = */
		ISPKGPATHSEP[' '] = 1;		/* space */
		ISPKGPATHSEP['\t'] = 1;		/* horizontal-tab */
		ISPKGPATHSEP['\n'] = 1;		/* new-line */
		ISPKGPATHSEP['\0'] = 1;		/* NULL character */

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

	/* if no bytes in contents file, return 0 */

	if (vfpGetBytesRemaining(cfVfp) <= 1) {
		return (0);
	}

	/* if the path to scan for is empty, act like no path was specified */

	if ((path != (char *)NULL) && (*path == '\0')) {
		path = (char *)NULL;
	}

	/*
	 * if path to search for is "*", then we will return the first path
	 * we encounter as a match, otherwise we return an error
	 */

	if ((path != (char *)NULL) && (path[0] != '/')) {
		if (strcmp(path, "*") != 0) {
			setErrstr(pkg_gt(ERR_ILLEGAL_SEARCH_PATH));
			return (-1);
		}
		anypath = 1;
	}

	/* attempt to narrow down the search for the specified path */

	if (anypath == 0) {
		char	*np;

		np = narrowSearch(cfVfp, path, pathLength);
		if (np != (char *)NULL) {
			dataSkipped = 1;
			lastPos = np;
			vfpSetCurrCharPtr(cfVfp, np);
		}
	}

	/*
	 * If the path to search for in the source contents file is NULL, then
	 * this is a request to scan to the end of the source contents file. If
	 * there is a temporary contents file to copy entries to, all that needs
	 * to be done is to copy the data remaining from the current location in
	 * the source contents file to the end of the temporary contents file.
	 * if there is no temporary contents file to copy to, then all that
	 * needs to be done is to seek to the end of the source contents file.
	 */

	if ((anypath == 0) && (path == (char *)NULL)) {
		if (cfTmpVfp != (VFP_T *)NULL) {
			if (vfpGetBytesRemaining(cfVfp) > 0) {
				WRITEDATA(cfTmpVfp, firstPos,
					vfpGetLastCharPtr(cfVfp)+1);
			}
			*vfpGetLastCharPtr(cfTmpVfp) = '\0';
		}
		vfpSeekToEnd(cfVfp);
		return (0);
	}

	/*
	 * *********************************************************************
	 * main loop processing entries from the contents file looking for
	 * the specified path
	 * *********************************************************************
	 */

	for (;;) {
		char	*p;

		/* not reading old style entry */

		rdpath = 0;

		/* determine first character of the next entry */

		if (vfpGetBytesRemaining(cfVfp) <= 0) {
			/* no bytes in contents file current char is NULL */

			c = '\0';
		} else {
			/* grab path from first entry */

			c = vfpGetcNoInc(cfVfp);
		}

		/* save current position in file */

		pos = vfpGetCurrCharPtr(cfVfp);

		/*
		 * =============================================================
		 * at the first character of the next entry in the contents file
		 * if not absolute path check for exceptions and old style entry
		 * --> if end of contents file write out skipped data and return
		 * --> if comment character skip to end of line and restart loop
		 * --> else process "old style entry: ftype class path"
		 * =============================================================
		 */

		if (c != '/') {
			/* if NULL character then end of contents file found */

			if (c == '\0') {
				/* write out skipped data before returning */
				if (dataSkipped &&
						(cfTmpVfp != (VFP_T *)NULL)) {
					WRITEDATA(cfTmpVfp, firstPos, lastPos);
					*vfpGetLastCharPtr(cfTmpVfp) = '\0';
				}

				return (0); /* no more entries */
			}

			/* ignore lines that begin with #, : or a "space" */

			if ((isspace(c) != 0) || (c == '#') || (c == ':')) {
				/* line is a comment */
				findend(&vfpGetCurrCharPtr(cfVfp));
				continue;
			}

			/*
			 * old style entry - format is:
			 *	ftype class path
			 * set ept->ftype to the type
			 * set ept->class to the class
			 * set ept->path to point to lpath
			 * set cpath_start/cpath_len to point to the file name
			 * set rdpath to '1' to indicate old style entry parsed
			 */

			while (isspace((c = vfpGetc(cfVfp))))
				;

			switch (c) {
			case '?': case 'f': case 'v': case 'e': case 'l':
			case 's': case 'p': case 'c': case 'b': case 'd':
			case 'x':
				/* save ftype */
				ept->ftype = (char)c;

				/* save class */
				if (getstr(&vfpGetCurrCharPtr(cfVfp), CLSSIZ,
						ept->pkg_class, ISWORDSEP)) {
					setErrstr(ERR_CANNOT_READ_CLASS_TOKEN);
					findend(&vfpGetCurrCharPtr(cfVfp));
					return (-1);
				}

				/*
				 * locate file name up to "=", set cpath_start
				 * and cpath_len to point to the file name
				 */
				cpath_start = vfpGetCurrCharPtr(cfVfp);
				p = vfpGetCurrCharPtr(cfVfp);

				/*
				 * skip past all bytes until first '= \t\n\0':
				 */
				while (ISPKGPATHSEP[(int)*p] == 0) {
					p++;
				}

				cpath_len = vfpGetCurrPtrDelta(cfVfp, p);

				/*
				 * if the path is zero bytes, line is corrupted
				 */

				if (cpath_len < 1) {
					setErrstr(ERR_CANNOT_READ_PATHNAME_FLD);
					findend(&vfpGetCurrCharPtr(cfVfp));
					return (-1);
				}

				vfpIncCurrPtrBy(cfVfp, cpath_len);

				/* set path to point to local path cache */
				ept->path = lpath;

				/* set flag indicating path already parsed */
				rdpath = 1;
				break;

			case '\0':
				/* end of line before new-line seen */
				vfpDecCurrPtr(cfVfp);
				setErrstr(ERR_INCOMPLETE_ENTRY);
				return (-1);

			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				/* volume number seen */
				setErrstr(ERR_VOLUMENO_UNEXPECTED);
				findend(&vfpGetCurrCharPtr(cfVfp));
				return (-1);

			case 'i':
				/* type i files are not cataloged */
				setErrstr(ERR_FTYPE_I_UNEXPECTED);
				findend(&vfpGetCurrCharPtr(cfVfp));
				return (-1);

			default:
				/* unknown ftype */
				setErrstr(ERR_UNKNOWN_FTYPE);
				findend(&vfpGetCurrCharPtr(cfVfp));
				return (-1);
			}
		} else {
			/*
			 * current entry DOES start with absolute path
			 * set ept->path to point to lpath
			 * set cpath_start/cpath_len to point to the file name
			 */
		/* copy first token into path element of passed structure */

			cpath_start = vfpGetCurrCharPtr(cfVfp);

			p = cpath_start;

			/*
			 * skip past all bytes until first from '= \t\n\0':
			 */

			while (ISPKGPATHSEP[(int)*p] == 0) {
				p++;
			}

			cpath_len = vfpGetCurrPtrDelta(cfVfp, p);

			vfpIncCurrPtrBy(cfVfp, cpath_len);

			if (vfpGetcNoInc(cfVfp) == '\0') {
				setErrstr(ERR_INCOMPLETE_ENTRY);
				findend(&vfpGetCurrCharPtr(cfVfp));
				return (-1);
			}

			ept->path = lpath;
		}

		/*
		 * =============================================================
		 * if absolute path then the path is collected and we are at the
		 * first byte following the absolute path name;
		 * if not an absolute path then an old style entry, ept has been
		 * filled with the type and class and path name.
		 * determine if we have read the pathname which identifies
		 * the entry we are searching for
		 * =============================================================
		 */

		if (anypath != 0) {
			n = 0;	/* next entry is "equal to" */
		} else if (path == (char *)NULL) {
			n = 1;	/* next entry is "greater than" */
		} else {
			n = strncmp(path, cpath_start, cpath_len);
			if ((n == 0) && (cpath_len != pathLength)) {
				n = cpath_len;
			}
		}

		/* get first character following the end of the path */

		c = vfpGetc(cfVfp);

		/*
		 * if an exact match, always parse out the local path
		 */

		if (n == 0) {
			/*
			 * we want to return information about this path in
			 * the structure provided, so parse any local path
			 * and jump to code which parses rest of the input line
			 */
			if (c == '=') {
				/* parse local path specification */
				if (getstr(&vfpGetCurrCharPtr(cfVfp), PATH_MAX,
						mylocal, ISWORDSEP)) {

					/* copy path found to 'lpath' */
					COPYPATH(lpath, cpath_start, cpath_len);

					setErrstr(ERR_CANNOT_READ_LL_PATH);
					findend(&vfpGetCurrCharPtr(cfVfp));
					return (-1);
				}
				ept->ainfo.local = mylocal;
			}
		}

		/*
		 * if an exact match and processing a new style entry, read the
		 * remaining information from the new style entry - if this is
		 * an old style entry (rdpath != 0) then the existing info has
		 * already been processed as it exists before the pathname and
		 * not after like a new style entry
		 */

		if (n == 0 && rdpath == 0) {
			while (isspace((c = vfpGetc(cfVfp))))
				;

			switch (c) {
			case '?': case 'f': case 'v': case 'e': case 'l':
			case 's': case 'p': case 'c': case 'b': case 'd':
			case 'x':
				/* save ftype */
				ept->ftype = (char)c;

				/* save class */
				if (getstr(&vfpGetCurrCharPtr(cfVfp), CLSSIZ,
						ept->pkg_class, ISWORDSEP)) {

					/* copy path found to 'lpath' */
					COPYPATH(lpath, cpath_start, cpath_len);

					setErrstr(ERR_CANNOT_READ_CLASS_TOKEN);
					findend(&vfpGetCurrCharPtr(cfVfp));
					return (-1);
				}
				break; /* we already read the pathname */

			case '\0':
				/* end of line before new-line seen */
				vfpDecCurrPtr(cfVfp);

				/* copy path found to 'lpath' */
				COPYPATH(lpath, cpath_start, cpath_len);

				setErrstr(ERR_INCOMPLETE_ENTRY);
				return (-1);

			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':

				/* copy path found to 'lpath' */
				COPYPATH(lpath, cpath_start, cpath_len);

				setErrstr(ERR_VOLUMENO_UNEXPECTED);
				findend(&vfpGetCurrCharPtr(cfVfp));
				return (-1);

			case 'i':

				/* copy path found to 'lpath' */
				COPYPATH(lpath, cpath_start, cpath_len);

				setErrstr(ERR_FTYPE_I_UNEXPECTED);
				findend(&vfpGetCurrCharPtr(cfVfp));
				return (-1);

			default:
				/* unknown ftype */

				/* copy path found to 'lpath' */
				COPYPATH(lpath, cpath_start, cpath_len);

				setErrstr(ERR_UNKNOWN_FTYPE);
				findend(&vfpGetCurrCharPtr(cfVfp));
				return (-1);
			}
		}

		/*
		 * if an exact match all processing is completed; break out of
		 * the main processing loop and finish processing this entry
		 * prior to returning to the caller.
		 */

		if (n == 0) {
			break;
		}

		/*
		 * this entry is not an exact match for the path being searched
		 * for - if this entry is GREATER THAN the path being searched
		 * for then finish processing and return GREATER THAN result
		 * to the caller so the entry for the path being searched for
		 * can be added to the contents file.
		 */

		if (n < 0) {
			/*
			 * the entry we want would fit BEFORE the one we just
			 * read, so we need to unread what we've read by
			 * seeking back to the start of this entry
			 */

			vfpSetCurrCharPtr(cfVfp, pos);

			/* copy path found to 'lpath' */
			COPYPATH(lpath, cpath_start, cpath_len);

			/* write out any skipped data before returning */
			if (dataSkipped && (cfTmpVfp != (VFP_T *)NULL)) {
				WRITEDATA(cfTmpVfp, firstPos, lastPos);
			}

			return (2); /* path would insert here */
		}

		/*
		 * This entry is "LESS THAN" the specified path to search for
		 * need to process the next entry from the contents file. First,
		 * if writing to new contents file, update new contents file if
		 * processing old style entry; otherwise, update skipped data
		 * information to remember current last byte of skipped data.
		 */

		if (cfTmpVfp != (VFP_T *)NULL) {
			char	*px;
			ssize_t	len;

			if (rdpath != 0) {
				/* modify record: write out any skipped data */
				if (dataSkipped) {
					WRITEDATA(cfTmpVfp, firstPos, lastPos);
				}

				/*
				 * copy what we've read and the rest of this
				 * line onto the specified output stream
				 */
				vfpPutBytes(cfTmpVfp, cpath_start, cpath_len);
				vfpPutc(cfTmpVfp, c);
				vfpPutc(cfTmpVfp, ept->ftype);
				vfpPutc(cfTmpVfp, ' ');
				vfpPuts(cfTmpVfp, ept->pkg_class);

				px = strchr(vfpGetCurrCharPtr(cfVfp), '\n');

				if (px == (char *)NULL) {
					len = vfpGetBytesRemaining(cfVfp);
					vfpPutBytes(cfTmpVfp,
						vfpGetCurrCharPtr(cfVfp), len);
					vfpPutc(cfTmpVfp, '\n');
					vfpSeekToEnd(cfVfp);
				} else {
					len = vfpGetCurrPtrDelta(cfVfp, px);
					vfpPutBytes(cfTmpVfp,
						vfpGetCurrCharPtr(cfVfp), len);
					vfpIncCurrPtrBy(cfVfp, len);
				}

				/* reset skiped bytes if any data skipped */
				if (dataSkipped) {
					dataSkipped = 0;
					lastPos = (char *)NULL;
					firstPos = vfpGetCurrCharPtr(cfVfp);
				}
			} else {
				/* skip data */
				dataSkipped = 1;

				px = strchr(vfpGetCurrCharPtr(cfVfp), '\n');

				if (px == (char *)NULL) {
					vfpSeekToEnd(cfVfp);
				} else {
					len = vfpGetCurrPtrDelta(cfVfp, px)+1;
					vfpIncCurrPtrBy(cfVfp, len);
				}
				lastPos = vfpGetCurrCharPtr(cfVfp);
			}
		} else {
			/*
			 * since this isn't the entry we want, just read the
			 * stream until we find the end of this entry and
			 * then start this search loop again
			 */
			char	*px;

			px = strchr(vfpGetCurrCharPtr(cfVfp), '\n');

			if (px == (char *)NULL) {
				vfpSeekToEnd(cfVfp);

				/* copy path found to 'lpath' */
				COPYPATH(lpath, cpath_start, cpath_len);

				setErrstr(pkg_gt(ERR_MISSING_NEWLINE));
				findend(&vfpGetCurrCharPtr(cfVfp));
				return (-1);
			} else {
				ssize_t	len;

				len = vfpGetCurrPtrDelta(cfVfp, px)+1;
				vfpIncCurrPtrBy(cfVfp, len);
			}
		}
	}

	/*
	 * *********************************************************************
	 * end of main loop processing entries from contents file
	 * the loop is broken out of when an exact match for the
	 * path being searched for has been found and the type is one of:
	 *   - ?fvelspcbdx
	 * at this point parsing is at the first character past the full path
	 * name on an exact match for the path being looked for - parse the
	 * remainder of the entries information into the ept structure.
	 * *********************************************************************
	 */

	/* link/symbolic link must have link destination */

	if (((ept->ftype == 's') || (ept->ftype == 'l')) &&
					(ept->ainfo.local == NULL)) {
		/* copy path found to 'lpath' */
		COPYPATH(lpath, cpath_start, cpath_len);

		setErrstr(ERR_NO_LINK_SOURCE_SPECIFIED);
		findend(&vfpGetCurrCharPtr(cfVfp));
		return (-1);
	}

	/* character/block devices have major/minor device numbers */

	if (((ept->ftype == 'c') || (ept->ftype == 'b'))) {
		ept->ainfo.major = BADMAJOR;
		ept->ainfo.minor = BADMINOR;
		if (getnumvfp(&vfpGetCurrCharPtr(cfVfp), 10,
				(long *)&ept->ainfo.major, BADMAJOR) ||
		    getnumvfp(&vfpGetCurrCharPtr(cfVfp), 10,
				(long *)&ept->ainfo.minor, BADMINOR)) {
			/* copy path found to 'lpath' */
			COPYPATH(lpath, cpath_start, cpath_len);

			setErrstr(pkg_gt(ERR_CANNOT_READ_MM_NUMS));
			findend(&vfpGetCurrCharPtr(cfVfp));
			return (-1);
		}
	}

	/* most types have mode, owner, group identification components */

	if ((ept->ftype == 'd') || (ept->ftype == 'x') || (ept->ftype == 'c') ||
		(ept->ftype == 'b') || (ept->ftype == 'p') ||
		(ept->ftype == 'f') || (ept->ftype == 'v') ||
		(ept->ftype == 'e')) {
		/* mode, owner, group should be here */
		if (getnumvfp(&vfpGetCurrCharPtr(cfVfp), 8,
				(long *)&ept->ainfo.mode, BADMODE) ||
		    getstr(&vfpGetCurrCharPtr(cfVfp), sizeof (ept->ainfo.owner),
				ept->ainfo.owner, ISWORDSEP) ||
		    getstr(&vfpGetCurrCharPtr(cfVfp), sizeof (ept->ainfo.group),
				ept->ainfo.group, ISWORDSEP)) {
			/* copy path found to 'lpath' */
			COPYPATH(lpath, cpath_start, cpath_len);

			setErrstr(ERR_CANNOT_READ_MOG);
			findend(&vfpGetCurrCharPtr(cfVfp));
			return (-1);
		}
	}

	/* i/f/v/e have size, checksum, modification time components */

	if ((ept->ftype == 'i') || (ept->ftype == 'f') ||
			(ept->ftype == 'v') || (ept->ftype == 'e')) {
		/* look for content description */
		if (getlnumvfp(&vfpGetCurrCharPtr(cfVfp), 10,
				(fsblkcnt_t *)&ept->cinfo.size, BADCONT) ||
		    getnumvfp(&vfpGetCurrCharPtr(cfVfp), 10,
				(long *)&ept->cinfo.cksum, BADCONT) ||
		    getnumvfp(&vfpGetCurrCharPtr(cfVfp), 10,
				(long *)&ept->cinfo.modtime, BADCONT)) {
			/* copy path found to 'lpath' */
			COPYPATH(lpath, cpath_start, cpath_len);

			setErrstr(ERR_CANNOT_READ_CONTENT_INFO);
			findend(&vfpGetCurrCharPtr(cfVfp));
			return (-1);
		}
	}

	/* i files processing is completed - return 'exact match found' */

	if (ept->ftype == 'i') {
		/* copy path found to 'lpath' */
		COPYPATH(lpath, cpath_start, cpath_len);

		if (getend(&vfpGetCurrCharPtr(cfVfp))) {
			/* copy path found to 'lpath' */
			COPYPATH(lpath, cpath_start, cpath_len);

			setErrstr(ERR_EXTRA_TOKENS);
			return (-1);
		}

		/* write out any skipped data before returning */
		if (dataSkipped && (cfTmpVfp != (VFP_T *)NULL)) {
			WRITEDATA(cfTmpVfp, firstPos, lastPos);
		}

		return (1);
	}

	/*
	 * determine list of packages which reference this entry
	 */

	lastpinfo = (struct pinfo *)NULL;
	while ((c = getstr(&vfpGetCurrCharPtr(cfVfp), sizeof (pkgname),
						pkgname, ISPKGNAMESEP)) <= 0) {
		/* if c < 0 the string was too long to fix in the buffer */

		if (c < 0) {
			/* copy path found to 'lpath' */
			COPYPATH(lpath, cpath_start, cpath_len);

			setErrstr(ERR_PACKAGE_NAME_TOO_LONG);
			findend(&vfpGetCurrCharPtr(cfVfp));
			return (-1);
		}

		/* a package is present - create and populate pinfo structure */

		pinfo = (struct pinfo *)calloc(1, sizeof (struct pinfo));
		if (!pinfo) {
			/* copy path found to 'lpath' */
			COPYPATH(lpath, cpath_start, cpath_len);

			setErrstr(ERR_NO_MEMORY);
			findend(&vfpGetCurrCharPtr(cfVfp));
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
		c = (vfpGetc(cfVfp));
		if (c == '\\') {
			/* get alternate ftype */
			pinfo->editflag++;
			c = (vfpGetc(cfVfp));
		}

		if (c == ':') {
			/* get special classname */
			(void) getstr(&vfpGetCurrCharPtr(cfVfp),
				sizeof (classname), classname, ISWORDSEP);
			(void) strlcpy(pinfo->aclass, classname,
							sizeof (pinfo->aclass));
			c = (vfpGetc(cfVfp));
		}
		ept->npkgs++;

		/* break out of while if at end of entry */

		if ((c == '\n') || (c == '\0')) {
			break;
		}

		/* if package not separated by a space return an error */

		if (!isspace(c)) {
			/* copy path found to 'lpath' */
			COPYPATH(lpath, cpath_start, cpath_len);

			setErrstr(ERR_BAD_ENTRY_END);
			findend(&vfpGetCurrCharPtr(cfVfp));
			return (-1);
		}
	}

	/*
	 * parsing of the entry is complete
	 */

	/* copy path found to 'lpath' */
	COPYPATH(lpath, cpath_start, cpath_len);

	/* write out any skipped data before returning */
	if (dataSkipped && (cfTmpVfp != (VFP_T *)NULL)) {
		WRITEDATA(cfTmpVfp, firstPos, lastPos);
	}

	/* if not at the end of the entry, make it so */

	if ((c != '\n') && (c != '\0')) {
		if (getend(&vfpGetCurrCharPtr(cfVfp)) && ept->pinfo) {
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
	while (separator[(int)*p1] == 0) {
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

static void
findend(char **cp)
{
	char	*p1;
	char	*p = *cp;

	/* if at end of buffer return no more characters left */

	if (*p == '\0') {
		return;
	}

	/* find the end of the line */

	p1 = strchr(p, '\n');

	if (p1 != (char *)NULL) {
		*cp = ++p1;
		return;
	}

	*cp = strchr(p, '\0');
}
