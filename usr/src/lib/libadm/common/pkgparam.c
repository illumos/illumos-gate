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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

/*LINTLIBRARY*/

/*   5-20-92   newroot support added  */

#include <stdio.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <pkgstrct.h>
#include <pkginfo.h>
#include <pkglocs.h>
#include <stdlib.h>
#include <unistd.h>
#include "libadm.h"

#define	VALSIZ	128
#define	NEWLINE	'\n'
#define	ESCAPE	'\\'

static char sepset[] =	":=\n";
static char qset[] =	"'\"";
static char *pkg_inst_root = NULL;

char *pkgdir = NULL;
char *pkgfile = NULL;

static char Adm_pkgloc[PATH_MAX] = { 0 }; /* added for newroot */
static char Adm_pkgadm[PATH_MAX] = { 0 }; /* added for newroot */

/*
 * This looks in a directory that might be the top level directory of a
 * package. It tests a temporary install directory first and then for a
 * standard directory. This looks a little confusing, so here's what's
 * happening. If this pkginfo is being openned in a script during a pkgadd
 * which is updating an existing package, the original pkginfo file is in a
 * directory that has been renamed from <pkginst> to .save.<pkginst>. If the
 * pkgadd fails it will be renamed back to <pkginst>. We are always interested
 * in the OLD pkginfo data because the new pkginfo data is already in our
 * environment. For that reason, we try to open the backup first - that has
 * the old data. This returns the first accessible path in "path" and a "1"
 * if an appropriate pkginfo file was found. It returns a 0 if no type of
 * pkginfo was located.
 */
int
pkginfofind(char *path, char *pkg_dir, char *pkginst)
{
	int len = 0;

	/* Construct the temporary pkginfo file name. */
	len =  snprintf(path, PATH_MAX, "%s/.save.%s/pkginfo", pkg_dir,
	    pkginst);
	if (len > PATH_MAX)
		return (0);
	if (access(path, 0)) {
		/*
		 * This isn't a temporary directory, so we look for a
		 * regular one.
		 */
		len =  snprintf(path, PATH_MAX, "%s/%s/pkginfo", pkg_dir,
		    pkginst);
		if (len > PATH_MAX)
			return (0);
		if (access(path, 0))
			return (0); /* doesn't appear to be a package */
	}

	return (1);
}

/*
 * This opens the appropriate pkginfo file for a particular package.
 */
FILE *
pkginfopen(char *pkg_dir, char *pkginst)
{
	FILE *fp = NULL;
	char temp[PATH_MAX];

	if (pkginfofind(temp, pkg_dir, pkginst))
		fp = fopen(temp, "r");

	return (fp);
}


char *
fpkgparam(FILE *fp, char *param)
{
	char	ch, buffer[VALSIZ];
	char	*mempt, *copy;
	int	c, n;
	boolean_t check_end_quote = B_FALSE;
	boolean_t begline, quoted, escape;
	int idx = 0;

	if (param == NULL) {
		errno = ENOENT;
		return (NULL);
	}

	mempt = NULL;

	for (;;) {		/* For each entry in the file fp */
		copy = buffer;
		n = 0;

		/* Get the next token. */
		while ((c = getc(fp)) != EOF) {
			ch = (char)c;
			if (strchr(sepset, ch))
				break;
			if (++n < VALSIZ)
				*copy++ = ch;
		}

		/* If it's the end of the file, exit the for() loop */
		if (c == EOF) {
			errno = EINVAL;
			return (NULL); /* No more entries left */

		/* If it's end of line, look for the next parameter. */
		} else if (c == NEWLINE)
			continue;

		/* At this point copy points to the end of a valid parameter. */
		*copy = '\0';		/* Terminate the string. */
		if (buffer[0] == '#')	/* If it's a comment, drop thru. */
			copy = NULL;	/* Comments don't get buffered. */
		else {
			/* If parameter is NULL, we return whatever we got. */
			if (param[0] == '\0') {
				(void) strcpy(param, buffer);
				copy = buffer;

			/* If this doesn't match the parameter, drop thru. */
			} else if (strcmp(param, buffer))
				copy = NULL;

			/* Otherwise, this is our boy. */
			else
				copy = buffer;
		}

		n = 0;
		quoted = escape = B_FALSE;
		begline = B_TRUE; /* Value's line begins */

		/* Now read the parameter value. */
		while ((c = getc(fp)) != EOF) {
			ch = (char)c;

			if (begline && ((ch == ' ') || (ch == '\t')))
				continue; /* Ignore leading white space */

			/*
			 * Take last end quote 'verbatim' if anything
			 * other than space, newline and escape.
			 * Example:
			 * PARAM1="zonename="test-zone""
			 *	Here in this example the letter 't' inside
			 *	the value is followed by '"', this makes
			 *	the previous end quote candidate '"',
			 *	a part of value and the end quote
			 *	disqualfies. Reset check_end_quote.
			 * PARAM2="value"<== newline here
			 * PARAM3="value"\
			 * "continued"<== newline here.
			 *	Check for end quote continues.
			 */
			if (ch != NEWLINE && ch != ' ' && ch != ESCAPE &&
			    ch != '\t' && check_end_quote)
				check_end_quote = B_FALSE;

			if (ch == NEWLINE) {
				if (!escape) {
					/*
					 * The end quote candidate qualifies.
					 * Eat any trailing spaces.
					 */
					if (check_end_quote) {
						copy -= n - idx;
						n = idx;
						check_end_quote = B_FALSE;
						quoted = B_FALSE;
					}
					break; /* End of entry */
				}
				/*
				 * The end quote if exists, doesn't qualify.
				 * Eat end quote and trailing spaces if any.
				 * Value spans to next line.
				 */
				if (check_end_quote) {
					copy -= n - idx;
					n = idx;
					check_end_quote = B_FALSE;
				} else if (copy) {
					copy--; /* Eat previous esc */
					n--;
				}
				escape = B_FALSE;
				begline = B_TRUE; /* New input line */
				continue;
			} else {
				if (!escape && strchr(qset, ch)) {
					/* Handle quotes */
					if (begline) {
						/* Starting quote */
						quoted = B_TRUE;
						begline = B_FALSE;
						continue;
					} else if (quoted) {
						/*
						 * This is the candidate
						 * for end quote. Check
						 * to see it qualifies.
						 */
						check_end_quote = B_TRUE;
						idx = n;
					}
				}
				if (ch == ESCAPE)
					escape = B_TRUE;
				else if (escape)
					escape = B_FALSE;
				if (copy) *copy++ = ch;
				begline = B_FALSE;
			}

			if (copy && ((++n % VALSIZ) == 0)) {
				if (mempt) {
					mempt = realloc(mempt,
					    (n+VALSIZ)*sizeof (char));
					if (!mempt)
						return (NULL);
				} else {
					mempt = calloc((size_t)(2*VALSIZ),
					    sizeof (char));
					if (!mempt)
						return (NULL);
					(void) strncpy(mempt, buffer, n);
				}
				copy = &mempt[n];
			}
		}

		/*
		 * Don't allow trailing white space.
		 * NOTE : White space in the middle is OK, since this may
		 * be a list. At some point it would be a good idea to let
		 * this function know how to validate such a list. -- JST
		 *
		 * Now while there's a parametric value and it ends in a
		 * space and the actual remaining string length is still
		 * greater than 0, back over the space.
		 */
		while (copy && isspace((unsigned char)*(copy - 1)) && n-- > 0)
			copy--;

		if (quoted) {
			if (mempt)
				(void) free(mempt);
			errno = EFAULT; /* missing closing quote */
			return (NULL);
		}
		if (copy) {
			*copy = '\0';
			break;
		}
		if (c == EOF) {
			errno = EINVAL; /* parameter not found */
			return (NULL);
		}
	}

	if (!mempt)
		mempt = strdup(buffer);
	else
		mempt = realloc(mempt, (strlen(mempt)+1)*sizeof (char));
	return (mempt);
}

char *
pkgparam(char *pkg, char *param)
{
	static char lastfname[PATH_MAX];
	static FILE *fp = NULL;
	char *pt, *copy, *value, line[PATH_MAX];

	if (!pkgdir)
		pkgdir = get_PKGLOC();

	if (!pkg) {
		/* request to close file */
		if (fp) {
			(void) fclose(fp);
			fp = NULL;
		}
		return (NULL);
	}

	if (!param) {
		errno = ENOENT;
		return (NULL);
	}

	if (pkgfile)
		(void) strcpy(line, pkgfile); /* filename was passed */
	else
		(void) pkginfofind(line, pkgdir, pkg);

	if (fp && strcmp(line, lastfname)) {
		/* different filename implies need for different fp */
		(void) fclose(fp);
		fp = NULL;
	}
	if (!fp) {
		(void) strcpy(lastfname, line);
		if ((fp = fopen(lastfname, "r")) == NULL)
			return (NULL);
	}

	/*
	 * if parameter is a null string, then the user is requesting us
	 * to find the value of the next available parameter for this
	 * package and to copy the parameter name into the provided string;
	 * if it is not, then it is a request for a specified parameter, in
	 * which case we rewind the file to start search from beginning
	 */
	if (param[0]) {
		/* new parameter request, so reset file position */
		if (fseek(fp, 0L, 0))
			return (NULL);
	}

	if (pt = fpkgparam(fp, param)) {
		if (strcmp(param, "ARCH") == 0 ||
		    strcmp(param, "CATEGORY") == 0) {
			/* remove all whitespace from value */
			value = copy = pt;
			while (*value) {
				if (!isspace((unsigned char)*value))
					*copy++ = *value;
				value++;
			}
			*copy = '\0';
		}
		return (pt);
	}
	return (NULL);
}
/*
 * This routine sets adm_pkgloc and adm_pkgadm which are the
 * replacement location for PKGLOC and PKGADM.
 */

static void canonize_name(char *);

void
set_PKGpaths(char *path)
{
	if (path && *path) {
		(void) snprintf(Adm_pkgloc, sizeof (Adm_pkgloc),
		    "%s%s", path, PKGLOC);
		(void) snprintf(Adm_pkgadm, sizeof (Adm_pkgadm),
		    "%s%s", path, PKGADM);
		set_install_root(path);
	} else {
		(void) snprintf(Adm_pkgloc, sizeof (Adm_pkgloc), "%s", PKGLOC);
		(void) snprintf(Adm_pkgadm, sizeof (Adm_pkgadm), "%s", PKGADM);
	}
	canonize_name(Adm_pkgloc);
	canonize_name(Adm_pkgadm);
	pkgdir = Adm_pkgloc;
}

char *
get_PKGLOC(void)
{
	if (Adm_pkgloc[0] == '\0')
		return (PKGLOC);
	else
		return (Adm_pkgloc);
}

char *
get_PKGADM(void)
{
	if (Adm_pkgadm[0] == '\0')
		return (PKGADM);
	else
		return (Adm_pkgadm);
}

void
set_PKGADM(char *newpath)
{
	(void) strcpy(Adm_pkgadm, newpath);
}

void
set_PKGLOC(char *newpath)
{
	(void) strcpy(Adm_pkgloc, newpath);
}

#define	isdot(x)	((x[0] == '.')&&(!x[1]||(x[1] == '/')))
#define	isdotdot(x)	((x[0] == '.')&&(x[1] == '.')&&(!x[2]||(x[2] == '/')))

static void
canonize_name(char *file)
{
	char *pt, *last;
	int level;

	/* Remove references such as "./" and "../" and "//" */

	for (pt = file; *pt; ) {
		if (isdot(pt))
			(void) strcpy(pt, pt[1] ? pt+2 : pt+1);
		else if (isdotdot(pt)) {
			level = 0;
			last = pt;
			do {
				level++;
				last += 2;
				if (*last)
					last++;
			} while (isdotdot(last));
			--pt; /* point to previous '/' */
			while (level--) {
				if (pt <= file)
					return;
				while ((*--pt != '/') && (pt > file))
					;
			}
			if (*pt == '/')
				pt++;
			(void) strcpy(pt, last);
		} else {
			while (*pt && (*pt != '/'))
				pt++;
			if (*pt == '/') {
				while (pt[1] == '/')
					(void) strcpy(pt, pt+1);
				pt++;
			}
		}
	}
	if ((--pt > file) && (*pt == '/'))
		*pt = '\0';
}

void
set_install_root(char *path)
{
	pkg_inst_root = strdup(path);
}

char *
get_install_root()
{
	return (pkg_inst_root);
}
