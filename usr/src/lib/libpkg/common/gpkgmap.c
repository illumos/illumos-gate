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
 * Copyright (c) 2017 Peter Tribble.
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
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include "pkgstrct.h"
#include "pkglib.h"
#include "pkglibmsgs.h"
#include "pkglocale.h"

#define	ERR_CANT_READ_LCLPATH		"unable to read local pathname"
#define	ERR_BAD_VOLUME_NUMBER		"bad volume number"
#define	ERR_CANNOT_READ_PATHNAME_FIELD	"unable to read pathname field"
#define	ERR_CANNOT_READ_CONTENT_INFO	"unable to read content info"
#define	ERR_EXTRA_TOKENS_PRESENT	"extra tokens on input line"
#define	ERR_CANNOT_READ_CLASS_TOKEN	"unable to read class token"
#define	ERR_BAD_LINK_SPEC		"missing or invalid link specification"
#define	ERR_UNKNOWN_FTYPE		"unknown ftype"
#define	ERR_NO_LINKSOURCE		"no link source specified"
#define	ERR_CANNOT_READ_MM_DEVNUMS	"unable to read major/minor "\
					"device numbers"
static int	eatwhite(FILE *fp);
static int	getend(FILE *fp);
static int	getstr(FILE *fp, char *sep, int n, char *str);
static int	getnum(FILE *fp, int base, long *d, long bad);
static int	getlnum(FILE *fp, int base, fsblkcnt_t *d, long bad);
static int	getvalmode(FILE *fp, mode_t *d, long bad, int map);

static int	getendvfp(char **cp);
static void	findendvfp(char **cp);
static int	getstrvfp(char **cp, char *sep, int n, char *str);
static int	getvalmodevfp(char **cp, mode_t *d, long bad, int map);
int		getnumvfp(char **cp, int base, long *d, long bad);
int		getlnumvfp(char **cp, int base, fsblkcnt_t *d, long bad);

static char	mypath[PATH_MAX];
static char	mylocal[PATH_MAX];
static int	mapmode = MAPNONE;
static char	*maptype = "";
static mode_t	d_mode = BADMODE;
static char 	*d_owner = BADOWNER;
static char	*d_group = BADGROUP;

/*
 * These determine how gpkgmap() deals with mode, owner and group defaults.
 * It is assumed that the owner and group arguments represent static fields
 * which will persist until attrdefault() is called.
 */
void
attrpreset(int mode, char *owner, char *group)
{
	d_mode = mode;
	d_owner = owner;
	d_group = group;
}

void
attrdefault()
{
	d_mode = NOMODE;
	d_owner = NOOWNER;
	d_group = NOGROUP;
}

/*
 * This determines how gpkgmap() deals with environment variables in the
 * mode, owner and group. Path is evaluated at a higher level based upon
 * other circumstances.
 */
void
setmapmode(int mode)
{
	if (mode >= 0 || mode <= 3) {
		mapmode = mode;
		if (mode == MAPBUILD)
			maptype = " build";
		else if (mode == MAPINSTALL)
			maptype = " install";
		else
			maptype = "";
	}
}

/* This is the external query interface for mapmode. */
int
getmapmode(void)
{
	return (mapmode);
}

/*
 * Unpack the pkgmap or the contents file or whatever file is in that format.
 * Based upon mapmode, environment parameters will be resolved for mode,
 * owner and group.
 */

int
gpkgmap(struct cfent *ept, FILE *fp)
{
	int		c;
	boolean_t	first_char = B_TRUE;

	setErrstr(NULL);
	ept->volno = 0;
	ept->ftype = BADFTYPE;
	(void) strcpy(ept->pkg_class, BADCLASS);
	ept->pkg_class_idx = -1;
	ept->path = NULL;
	ept->ainfo.local = NULL;
	/* default attributes were supplied, so don't reset */
	ept->ainfo.mode = d_mode;
	(void) strcpy(ept->ainfo.owner, d_owner);
	(void) strcpy(ept->ainfo.group, d_group);
	ept->ainfo.major = BADMAJOR;
	ept->ainfo.minor = BADMINOR;
	ept->cinfo.cksum = ept->cinfo.modtime = ept->cinfo.size = (-1L);

	ept->npkgs = 0;

	if (!fp)
		return (-1);
readline:
	c = eatwhite(fp);

	/*
	 * If the first character is not a digit, we assume that the
	 * volume number is 1.
	 */
	if (first_char && !isdigit(c)) {
		ept->volno = 1;
	}
	first_char = B_FALSE;

	switch (c) {
	    case EOF:
		return (0);

	    case '0':
	    case '1':
	    case '2':
	    case '3':
	    case '4':
	    case '5':
	    case '6':
	    case '7':
	    case '8':
	    case '9':
		if (ept->volno) {
			setErrstr(pkg_gt(ERR_BAD_VOLUME_NUMBER));
			goto error;
		}
		do {
			ept->volno = (ept->volno*10)+c-'0';
			c = getc(fp);
		} while (isdigit(c));
		if (ept->volno == 0)
			ept->volno = 1;

		goto readline;

	    case ':':
	    case '#':
		(void) getend(fp);
		/*FALLTHRU*/
	    case '\n':
		/*
		 * Since we are going to scan the next line,
		 * we need to reset volume number and first_char.
		 */
		ept->volno = 0;
		first_char = B_TRUE;
		goto readline;

	    case 'i':
		ept->ftype = (char)c;
		c = eatwhite(fp);
		/*FALLTHRU*/
	    case '.':
	    case '/':
		(void) ungetc(c, fp);

		if (getstr(fp, "=", PATH_MAX, mypath)) {
			setErrstr(pkg_gt(ERR_CANNOT_READ_PATHNAME_FIELD));
			goto error;
		}
		ept->path = mypath;
		c = getc(fp);
		if (c == '=') {
			if (getstr(fp, NULL, PATH_MAX, mylocal)) {
				setErrstr(pkg_gt(ERR_CANT_READ_LCLPATH));
				goto error;
			}
			ept->ainfo.local = mylocal;
		} else
			(void) ungetc(c, fp);

		if (ept->ftype == 'i') {
			/* content info might exist */
			if (!getlnum(fp, 10, (fsblkcnt_t *)&ept->cinfo.size,
			    BADCONT) &&
			    (getnum(fp, 10, (long *)&ept->cinfo.cksum,
			    BADCONT) ||
			    getnum(fp, 10, (long *)&ept->cinfo.modtime,
			    BADCONT))) {
				setErrstr(pkg_gt(ERR_CANNOT_READ_CONTENT_INFO));
				goto error;
			}
		}
		if (getend(fp)) {
			setErrstr(pkg_gt(ERR_EXTRA_TOKENS_PRESENT));
			return (-1);
		}
		return (1);

	    case '?':
	    case 'f':
	    case 'v':
	    case 'e':
	    case 'l':
	    case 's':
	    case 'p':
	    case 'c':
	    case 'b':
	    case 'd':
	    case 'x':
		ept->ftype = (char)c;
		if (getstr(fp, NULL, CLSSIZ, ept->pkg_class)) {
			setErrstr(pkg_gt(ERR_CANNOT_READ_CLASS_TOKEN));
			goto error;
		}
		if (getstr(fp, "=", PATH_MAX, mypath)) {
			setErrstr(pkg_gt(ERR_CANNOT_READ_PATHNAME_FIELD));
			goto error;
		}
		ept->path = mypath;

		c = getc(fp);
		if (c == '=') {
			/* local path */
			if (getstr(fp, NULL, PATH_MAX, mylocal)) {
				if (ept->ftype == 's' || ept->ftype == 'l') {
					setErrstr(pkg_gt(ERR_READLINK));
				} else {
					setErrstr(
						pkg_gt(ERR_CANT_READ_LCLPATH));
				}
				goto error;
			}
			ept->ainfo.local = mylocal;
		} else if (strchr("sl", ept->ftype)) {
			if ((c != EOF) && (c != '\n'))
				(void) getend(fp);
			setErrstr(pkg_gt(ERR_BAD_LINK_SPEC));
			return (-1);
		} else
			(void) ungetc(c, fp);
		break;

	    default:
		setErrstr(pkg_gt(ERR_UNKNOWN_FTYPE));
error:
		(void) getend(fp);
		return (-1);
	}

	if (strchr("sl", ept->ftype) && (ept->ainfo.local == NULL)) {
		setErrstr(pkg_gt(ERR_NO_LINKSOURCE));
		goto error;
	}

	if (strchr("cb", ept->ftype)) {
		ept->ainfo.major = BADMAJOR;
		ept->ainfo.minor = BADMINOR;
		if (getnum(fp, 10, (long *)&ept->ainfo.major, BADMAJOR) ||
		    getnum(fp, 10, (long *)&ept->ainfo.minor, BADMINOR)) {
			setErrstr(pkg_gt(ERR_CANNOT_READ_MM_DEVNUMS));
			goto error;
		}
	}

	/*
	 * Links and information files don't have attributes associated with
	 * them. The following either resolves potential variables or passes
	 * them through. Mode is tested for validity to some degree. BAD???
	 * is returned to indicate that no meaningful mode was provided. A
	 * higher authority will decide if that's OK or not. CUR??? means that
	 * the prototype file specifically requires a wildcard ('?') for
	 * that entry. We issue an error if attributes were entered wrong.
	 * We just return BAD??? if there was no entry at all.
	 */
	if (strchr("cbdxpfve", ept->ftype)) {
		int retval;

		if ((retval = getvalmode(fp, &(ept->ainfo.mode), CURMODE,
		    (mapmode != MAPNONE))) == 1)
			goto end;	/* nothing else on the line */
		else if (retval == 2)
			goto error;	/* mode is too no good */

		/* owner & group should be here */
		if ((retval = getstr(fp, NULL, ATRSIZ,
		    ept->ainfo.owner)) == 1)
			goto end;	/* no owner or group - warning */
		if (retval == -1) {
			setErrstr(pkg_gt(ERR_OWNTOOLONG));
			goto error;
		}

		if ((retval = getstr(fp, NULL, ATRSIZ,
		    ept->ainfo.group)) == 1)
			goto end;	/* no group - warning */
		if (retval == -1) {
			setErrstr(pkg_gt(ERR_GRPTOOLONG));
			goto error;
		}

		/* Resolve the parameters if required. */
		if (mapmode != MAPNONE) {
			if (mapvar(mapmode, ept->ainfo.owner)) {
				(void) snprintf(getErrbufAddr(),
					getErrbufSize(),
					pkg_gt(ERR_NOVAR),
					maptype, ept->ainfo.owner);
				setErrstr(getErrbufAddr());
				goto error;
			}
			if (mapvar(mapmode, ept->ainfo.group)) {
				(void) snprintf(getErrbufAddr(),
					getErrbufSize(), pkg_gt(ERR_NOVAR),
					maptype, ept->ainfo.group);
				setErrstr(getErrbufAddr());
				goto error;
			}
		}
	}

	if (strchr("ifve", ept->ftype)) {
		/* look for content description */
		if (!getlnum(fp, 10, (fsblkcnt_t *)&ept->cinfo.size, BADCONT) &&
		(getnum(fp, 10, (long *)&ept->cinfo.cksum, BADCONT) ||
		getnum(fp, 10, (long *)&ept->cinfo.modtime, BADCONT))) {
			setErrstr(pkg_gt(ERR_CANNOT_READ_CONTENT_INFO));
			goto error;
		}
	}

	if (ept->ftype == 'i')
		goto end;

end:
	if (getend(fp) && ept->pinfo) {
		setErrstr(pkg_gt(ERR_EXTRA_TOKENS_PRESENT));
		return (-1);
	}

	return (1);
}

/*
 * Get and validate the mode attribute. This returns an error if
 *	1. the mode string is too long
 *	2. the mode string includes alpha characters
 *	3. the mode string is not octal
 *	4. mode string is an install parameter
 *	5. mode is an unresolved build parameter and MAPBUILD is
 *	   in effect.
 * If the mode is a build parameter, it is
 *	1. returned as is if MAPNONE is in effect
 *	2. evaluated if MAPBUILD is in effect
 *
 * NOTE : We use "mapmode!=MAPBUILD" to gather that it is install
 * time. At install time we just fix a mode with bad bits set by
 * setting it to CURMODE. This should be an error in a few releases
 * (2.8 maybe) but faulty modes are so common in existing packages
 * that this is a reasonable exception. -- JST 1994-11-9
 *
 * RETURNS
 *	0 if mode is being returned as a valid value
 *	1 if no attributes are present on the line
 *	2 if there was a fundamental error
 */
static int
getvalmode(FILE *fp, mode_t *d, long bad, int map)
{
	char tempmode[20];
	mode_t tempmode_t;
	int retval;

	if ((retval = getstr(fp, NULL, ATRSIZ, tempmode)) == 1)
		return (1);
	else if (retval == -1) {
		setErrstr(pkg_gt(ERR_MODELONG));
		return (2);
	} else {
		/*
		 * If it isn't a '?' (meaning go with whatever mode is
		 * there), validate the mode and convert it to a mode_t. The
		 * "bad" variable here is a misnomer. It doesn't necessarily
		 * mean bad.
		 */
		if (tempmode[0] == '?') {
			*d = WILDCARD;
		} else {
			/*
			 * Mode may not be an install parameter or a
			 * non-build parameter.
			 */
			if (tempmode[0] == '$' &&
			    (isupper(tempmode[1]) || !islower(tempmode[1]))) {
				setErrstr(pkg_gt(ERR_IMODE));
				return (2);
			}

			if ((map) && (mapvar(mapmode, tempmode))) {
				(void) snprintf(getErrbufAddr(),
						getErrbufSize(),
						pkg_gt(ERR_NOVAR),
						maptype, tempmode);
				setErrstr(getErrbufAddr());
				return (2);
			}


			if (tempmode[0] == '$') {
				*d = BADMODE;	/* may be a problem */
			} else {
				/*
				 * At this point it's supposed to be
				 * something we can convert to a number.
				 */
				int n = 0;

				/*
				 * We reject it if it contains nonnumbers or
				 * it's not octal.
				 */
				while (tempmode[n] && !isspace(tempmode[n])) {
					if (!isdigit(tempmode[n])) {
						setErrstr(
							pkg_gt(ERR_MODEALPHA));
						return (2);
					}

					if (strchr("89abcdefABCDEF",
					    tempmode[n])) {
						setErrstr(
							pkg_gt(ERR_BASEINVAL));
						return (2);
					}
					n++;
				}

				tempmode_t = strtol(tempmode, NULL, 8);

				/*
				 * We reject it if it contains inappropriate
				 * bits.
				 */
				if (tempmode_t & ~(S_IAMB |
				    S_ISUID | S_ISGID | S_ISVTX)) {
					if (mapmode != MAPBUILD) {
						tempmode_t = bad;
					} else {
						setErrstr(pkg_gt(ERR_MODEBITS));
						return (2);
					}
				}
				*d = tempmode_t;
			}
		}
		return (0);
	}
}

static int
getnum(FILE *fp, int base, long *d, long bad)
{
	int c, b;

	/* leading white space ignored */
	c = eatwhite(fp);
	if (c == '?') {
		*d = bad;
		return (0);
	}

	if ((c == EOF) || (c == '\n') || !isdigit(c)) {
		(void) ungetc(c, fp);
		return (1);
	}

	*d = 0;
	while (isdigit(c)) {
		b = (c & 017);
		if (b >= base)
			return (2);
		*d = (*d * base) + b;
		c = getc(fp);
	}
	(void) ungetc(c, fp);
	return (0);
}

static int
getlnum(FILE *fp, int base, fsblkcnt_t *d, long bad)
{
	int c, b;

	/* leading white space ignored */
	c = eatwhite(fp);
	if (c == '?') {
		*d = bad;
		return (0);
	}

	if ((c == EOF) || (c == '\n') || !isdigit(c)) {
		(void) ungetc(c, fp);
		return (1);
	}

	*d = 0;
	while (isdigit(c)) {
		b = (c & 017);
		if (b >= base)
			return (2);
		*d = (*d * base) + b;
		c = getc(fp);
	}
	(void) ungetc(c, fp);
	return (0);
}

/*
 *  Get a string from the file. Returns
 *	0 if all OK
 *	1 if nothing there
 *	-1 if string is too long
 */
static int
getstr(FILE *fp, char *sep, int n, char *str)
{
	int c;

	/* leading white space ignored */
	c = eatwhite(fp);
	if ((c == EOF) || (c == '\n')) {
		(void) ungetc(c, fp);
		return (1); /* nothing there */
	}

	/* fill up string until space, tab, or separator */
	while (!strchr(" \t", c) && (!sep || !strchr(sep, c))) {
		if (n-- < 1) {
			*str = '\0';
			return (-1); /* too long */
		}
		*str++ = (char)c;
		c = getc(fp);
		if ((c == EOF) || (c == '\n'))
			break; /* no more on this line */
	}
	*str = '\0';
	(void) ungetc(c, fp);

	return (0);
}

static int
getend(FILE *fp)
{
	int c;
	int n;

	n = 0;
	do {
		if ((c = getc(fp)) == EOF)
			return (n);
		if (!isspace(c))
			n++;
	} while (c != '\n');
	return (n);
}

static int
eatwhite(FILE *fp)
{
	int c;

	/* this test works around a side effect of getc() */
	if (feof(fp))
		return (EOF);
	do
		c = getc(fp);
	while ((c == ' ') || (c == '\t'));
	return (c);
}

int
gpkgmapvfp(struct cfent *ept, VFP_T *vfp)
{
	int		c;
	boolean_t	first_char = B_TRUE;
	(void) strlcpy(ept->pkg_class, BADCLASS, sizeof (ept->pkg_class));
	(void) strlcpy(ept->ainfo.owner, d_owner, sizeof (ept->ainfo.owner));
	(void) strlcpy(ept->ainfo.group, d_group, sizeof (ept->ainfo.group));

	setErrstr(NULL);
	ept->volno = 0;
	ept->ftype = BADFTYPE;
	ept->pkg_class_idx = -1;
	ept->path = NULL;
	ept->ainfo.local = NULL;
	ept->ainfo.mode = d_mode;
	ept->ainfo.major = BADMAJOR;
	ept->ainfo.minor = BADMINOR;
	ept->cinfo.cksum = (-1L);
	ept->cinfo.modtime = (-1L);
	ept->cinfo.size = (-1L);

	ept->npkgs = 0;

	/* return error if no vfp specified */

	if (vfp == (VFP_T *)NULL) {
		return (-1);
	}

readline:
	while (((c = vfpGetcNoInc(vfp)) != '\0') && (isspace(vfpGetc(vfp))))
		;

	/*
	 * If the first character is not a digit, we assume that the
	 * volume number is 1.
	 */
	if (first_char && !isdigit(c)) {
		ept->volno = 1;
	}
	first_char = B_FALSE;

	/*
	 * In case of hsfs the zero-padding of partial pages
	 * returned by mmap is not done properly. A separate bug has been filed
	 * on this.
	 */

	if (vfp->_vfpCurr && (vfp->_vfpCurr > vfp->_vfpEnd)) {
		return (0);
	}

	switch (c) {
	    case '\0':
		return (0);

	    case '0':
	    case '1':
	    case '2':
	    case '3':
	    case '4':
	    case '5':
	    case '6':
	    case '7':
	    case '8':
	    case '9':
		if (ept->volno) {
			setErrstr(pkg_gt(ERR_BAD_VOLUME_NUMBER));
			goto error;
		}
		do {
			ept->volno = (ept->volno*10)+c-'0';
			c = vfpGetc(vfp);
		} while (isdigit(c));
		if (ept->volno == 0) {
			ept->volno = 1;
		}

		goto readline;

	    case ':':
	    case '#':
		(void) findendvfp(&vfpGetCurrCharPtr(vfp));
		/*FALLTHRU*/
	    case '\n':
		/*
		 * Since we are going to scan the next line,
		 * we need to reset volume number and first_char.
		 */
		ept->volno = 0;
		first_char = B_TRUE;
		goto readline;

	    case 'i':
		ept->ftype = (char)c;
		while (((c = vfpGetcNoInc(vfp)) != '\0') &&
						(isspace(vfpGetc(vfp))))
			;
		/*FALLTHRU*/
	    case '.':
	    case '/':
		vfpDecCurrPtr(vfp);

		if (getstrvfp(&vfpGetCurrCharPtr(vfp), "=", PATH_MAX, mypath)) {
			setErrstr(pkg_gt(ERR_CANNOT_READ_PATHNAME_FIELD));
			goto error;
		}
		ept->path = mypath;
		c = vfpGetc(vfp);
		if (c == '=') {
			if (getstrvfp(&vfpGetCurrCharPtr(vfp), NULL, PATH_MAX,
							mylocal)) {
				setErrstr(pkg_gt(ERR_CANT_READ_LCLPATH));
				goto error;
			}
			ept->ainfo.local = mylocal;
		} else {
			vfpDecCurrPtr(vfp);
		}

		if (ept->ftype == 'i') {
			/* content info might exist */
			if (!getlnumvfp(&vfpGetCurrCharPtr(vfp), 10,
				(fsblkcnt_t *)&ept->cinfo.size, BADCONT) &&
			    (getnumvfp(&vfpGetCurrCharPtr(vfp), 10,
				(long *)&ept->cinfo.cksum, BADCONT) ||
			    getnumvfp(&vfpGetCurrCharPtr(vfp), 10,
				(long *)&ept->cinfo.modtime, BADCONT))) {
				setErrstr(pkg_gt(ERR_CANNOT_READ_CONTENT_INFO));
				goto error;
			}
		}

		if (getendvfp(&vfpGetCurrCharPtr(vfp))) {
			setErrstr(pkg_gt(ERR_EXTRA_TOKENS_PRESENT));
			return (-1);
		}
		return (1);

	    case '?':
	    case 'f':
	    case 'v':
	    case 'e':
	    case 'l':
	    case 's':
	    case 'p':
	    case 'c':
	    case 'b':
	    case 'd':
	    case 'x':
		ept->ftype = (char)c;
		if (getstrvfp(&vfpGetCurrCharPtr(vfp), NULL,
						CLSSIZ, ept->pkg_class)) {
			setErrstr(pkg_gt(ERR_CANNOT_READ_CLASS_TOKEN));
			goto error;
		}
		if (getstrvfp(&vfpGetCurrCharPtr(vfp), "=", PATH_MAX, mypath)) {
			setErrstr(pkg_gt(ERR_CANNOT_READ_PATHNAME_FIELD));
			goto error;
		}
		ept->path = mypath;

		c = vfpGetc(vfp);
		if (c == '=') {
			/* local path */
			if (getstrvfp(&vfpGetCurrCharPtr(vfp), NULL,
							PATH_MAX, mylocal)) {
				if (ept->ftype == 's' || ept->ftype == 'l') {
					setErrstr(pkg_gt(ERR_READLINK));
				} else {
					setErrstr(
						pkg_gt(ERR_CANT_READ_LCLPATH));
				}
				goto error;
			}
			ept->ainfo.local = mylocal;
		} else if ((ept->ftype == 's') || (ept->ftype == 'l')) {
			if ((c != '\0') && (c != '\n'))
				(void) findendvfp(&vfpGetCurrCharPtr(vfp));
			setErrstr(pkg_gt(ERR_BAD_LINK_SPEC));
			return (-1);
		} else {
			vfpDecCurrPtr(vfp);
		}
		break;

	    default:
		setErrstr(pkg_gt(ERR_UNKNOWN_FTYPE));
error:
		(void) findendvfp(&vfpGetCurrCharPtr(vfp));
		return (-1);
	}

	if (((ept->ftype == 's') || (ept->ftype == 'l')) &&
					(ept->ainfo.local == NULL)) {
		setErrstr(pkg_gt(ERR_NO_LINKSOURCE));
		goto error;
	}

	if (((ept->ftype == 'c') || (ept->ftype == 'b'))) {
		ept->ainfo.major = BADMAJOR;
		ept->ainfo.minor = BADMINOR;

		if (getnumvfp(&vfpGetCurrCharPtr(vfp), 10,
				(long *)&ept->ainfo.major, BADMAJOR) ||
		    getnumvfp(&vfpGetCurrCharPtr(vfp), 10,
				(long *)&ept->ainfo.minor, BADMINOR)) {
			setErrstr(pkg_gt(ERR_CANNOT_READ_MM_DEVNUMS));
			goto error;
		}
	}

	/*
	 * Links and information files don't have attributes associated with
	 * them. The following either resolves potential variables or passes
	 * them through. Mode is tested for validity to some degree. BAD???
	 * is returned to indicate that no meaningful mode was provided. A
	 * higher authority will decide if that's OK or not. CUR??? means that
	 * the prototype file specifically requires a wildcard ('?') for
	 * that entry. We issue an error if attributes were entered wrong.
	 * We just return BAD??? if there was no entry at all.
	 */
	if ((ept->ftype == 'd') || (ept->ftype == 'x') || (ept->ftype == 'c') ||
		(ept->ftype == 'b') || (ept->ftype == 'p') ||
		(ept->ftype == 'f') || (ept->ftype == 'v') ||
		(ept->ftype == 'e')) {
		int retval;

		retval = getvalmodevfp(&vfpGetCurrCharPtr(vfp),
				&(ept->ainfo.mode),
				CURMODE, (mapmode != MAPNONE));

		if (retval == 1) {
			goto end;	/* nothing else on the line */
		} else if (retval == 2) {
			goto error;	/* mode is too no good */
		}

		/* owner & group should be here */
		if ((retval = getstrvfp(&vfpGetCurrCharPtr(vfp), NULL, ATRSIZ,
		    ept->ainfo.owner)) == 1)
			goto end;	/* no owner or group - warning */
		if (retval == -1) {
			setErrstr(pkg_gt(ERR_OWNTOOLONG));
			goto error;
		}

		if ((retval = getstrvfp(&vfpGetCurrCharPtr(vfp), NULL, ATRSIZ,
		    ept->ainfo.group)) == 1)
			goto end;	/* no group - warning */
		if (retval == -1) {
			setErrstr(pkg_gt(ERR_GRPTOOLONG));
			goto error;
		}

		/* Resolve the parameters if required. */
		if (mapmode != MAPNONE) {
			if (mapvar(mapmode, ept->ainfo.owner)) {
				(void) snprintf(getErrbufAddr(),
					getErrbufSize(), pkg_gt(ERR_NOVAR),
					maptype, ept->ainfo.owner);
				setErrstr(getErrbufAddr());
				goto error;
			}
			if (mapvar(mapmode, ept->ainfo.group)) {
				(void) snprintf(getErrbufAddr(),
					getErrbufSize(), pkg_gt(ERR_NOVAR),
					maptype, ept->ainfo.group);
				setErrstr(getErrbufAddr());
				goto error;
			}
		}
	}

	if ((ept->ftype == 'i') || (ept->ftype == 'f') ||
			(ept->ftype == 'v') || (ept->ftype == 'e')) {
		/* look for content description */
		if (!getlnumvfp(&vfpGetCurrCharPtr(vfp), 10,
				(fsblkcnt_t *)&ept->cinfo.size, BADCONT) &&
		(getnumvfp(&vfpGetCurrCharPtr(vfp), 10,
				(long *)&ept->cinfo.cksum, BADCONT) ||
		getnumvfp(&vfpGetCurrCharPtr(vfp), 10,
				(long *)&ept->cinfo.modtime, BADCONT))) {
			setErrstr(pkg_gt(ERR_CANNOT_READ_CONTENT_INFO));
			goto error;
		}
	}

	if (ept->ftype == 'i')
		goto end;

end:
	if (getendvfp(&vfpGetCurrCharPtr(vfp)) && ept->pinfo) {
		setErrstr(pkg_gt(ERR_EXTRA_TOKENS_PRESENT));
		return (-1);
	}

	return (1);
}

/*
 * Get and validate the mode attribute. This returns an error if
 *	1. the mode string is too long
 *	2. the mode string includes alpha characters
 *	3. the mode string is not octal
 *	4. mode string is an install parameter
 *	5. mode is an unresolved build parameter and MAPBUILD is
 *	   in effect.
 * If the mode is a build parameter, it is
 *	1. returned as is if MAPNONE is in effect
 *	2. evaluated if MAPBUILD is in effect
 *
 * NOTE : We use "mapmode!=MAPBUILD" to gather that it is install
 * time. At install time we just fix a mode with bad bits set by
 * setting it to CURMODE. This should be an error in a few releases
 * (2.8 maybe) but faulty modes are so common in existing packages
 * that this is a reasonable exception. -- JST 1994-11-9
 *
 * RETURNS
 *	0 if mode is being returned as a valid value
 *	1 if no attributes are present on the line
 *	2 if there was a fundamental error
 */
static int
getvalmodevfp(char **cp, mode_t *d, long bad, int map)
{
	char	tempmode[ATRSIZ+1];
	mode_t	tempmode_t;
	int	retval;
	int	n;

	if ((retval = getstrvfp(cp, NULL, sizeof (tempmode), tempmode)) == 1) {
		return (1);
	} else if (retval == -1) {
		setErrstr(pkg_gt(ERR_MODELONG));
		return (2);
	}

	/*
	 * If it isn't a '?' (meaning go with whatever mode is
	 * there), validate the mode and convert it to a mode_t. The
	 * "bad" variable here is a misnomer. It doesn't necessarily
	 * mean bad.
	 */
	if (tempmode[0] == '?') {
		*d = WILDCARD;
		return (0);
	}

	/*
	 * Mode may not be an install parameter or a
	 * non-build parameter.
	 */

	if (tempmode[0] == '$' &&
	    (isupper(tempmode[1]) || !islower(tempmode[1]))) {
		setErrstr(pkg_gt(ERR_IMODE));
		return (2);
	}

	if ((map) && (mapvar(mapmode, tempmode))) {
		(void) snprintf(getErrbufAddr(), getErrbufSize(),
				pkg_gt(ERR_NOVAR), maptype, tempmode);
		setErrstr(getErrbufAddr());
		return (2);
	}

	if (tempmode[0] == '$') {
		*d = BADMODE;	/* may be a problem */
		return (0);
	}

	/* it's supposed to be something we can convert to a number */

	n = 0;

	/* reject it if it contains nonnumbers or it's not octal */

	while (tempmode[n] && !isspace(tempmode[n])) {
		if (!isdigit(tempmode[n])) {
			setErrstr(pkg_gt(ERR_MODEALPHA));
			return (2);
		}

		if (strchr("89abcdefABCDEF", tempmode[n])) {
			setErrstr(pkg_gt(ERR_BASEINVAL));
			return (2);
		}
		n++;
	}

	tempmode_t = strtol(tempmode, NULL, 8);

	/*
	 * We reject it if it contains inappropriate
	 * bits.
	 */
	if (tempmode_t & (~(S_IAMB | S_ISUID | S_ISGID | S_ISVTX))) {
		if (mapmode == MAPBUILD) {
			setErrstr(pkg_gt(ERR_MODEBITS));
			return (2);
		}
		tempmode_t = bad;
	}

	*d = tempmode_t;

	return (0);
}

int
getnumvfp(char **cp, int base, long *d, long bad)
{
	int c;
	char	*p = *cp;

	if (*p == '\0') {
		return (0);
	}

	/* leading white space ignored */
	while (((c = *p) != '\0') && (isspace(*p++)))
		;
	if (c == '?') {
		*d = bad;
		*cp = p;
		return (0);
	}

	if ((c == '\0') || (c == '\n') || !isdigit(c)) {
		p--;
		*cp = p;
		return (1);
	}

	*d = 0;
	while (isdigit(c)) {
		*d = (*d * base) + (c & 017);
		c = *p++;
	}
	p--;
	*cp = p;
	return (0);
}

int
getlnumvfp(char **cp, int base, fsblkcnt_t *d, long bad)
{
	int c;
	char	*p = *cp;

	if (*p == '\0') {
		return (0);
	}

	/* leading white space ignored */
	while (((c = *p) != '\0') && (isspace(*p++)))
		;
	if (c == '?') {
		*d = bad;
		*cp = p;
		return (0);
	}

	if ((c == '\0') || (c == '\n') || !isdigit(c)) {
		p--;
		*cp = p;
		return (1);
	}

	*d = 0;
	while (isdigit(c)) {
		*d = (*d * base) + (c & 017);
		c = *p++;
	}
	p--;
	*cp = p;
	return (0);
}

static int
getstrvfp(char **cp, char *sep, int n, char *str)
{
	char	delims[256];
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

	/* generate complete list of delimiters to scan for */

	(void) strlcpy(delims, " \t\n", sizeof (delims));
	if ((sep != (char *)NULL) && (*sep != '\0')) {
		(void) strlcat(delims, sep, sizeof (delims));
	}

	/* compute length based on delimiter found or not */

	p1 = strpbrk(p, delims);
	if (p1 == (char *)NULL) {
		len = strlen(p);
	} else {
		len = (ptrdiff_t)p1 - (ptrdiff_t)p;
	}

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

/*
 * Name:	getendvfp
 * Description:	Locate the end of the current line given a pointer into a buffer
 *		containing characters that is null terminated.
 * Arguments:	char **cp - pointer to pointer to null-terminated string buffer
 * Returns:	int == 0 -- no non-space characters preceeded the newline
 *		    != 0 -- one or more non-space characters preceeded newline
 * Effects:	cp is updated to point to the first character PAST the first new
 *		line character found. If no newline character is found, cp is
 *		updated to point to the '\0' at the end of the buffer.
 */

static int
getendvfp(char **cp)
{
	int	n;
	char	*p = *cp;

	n = 0;

	/* if at end of buffer return no more characters left */

	if (*p == '\0') {
		return (0);
	}

	/* find the first null or end of line character */

	while ((*p != '\0') && (*p != '\n')) {
		if (n == 0) {
			if (!isspace(*p)) {
				n++;
			}
		}
		p++;
	}

	/* if at newline, increment pointer to first character past newline */

	if (*p == '\n') {
		p++;
	}

	/* set return pointer to null or first character past newline */

	*cp = p;

	/* return space/nospace indicator */

	return (n);
}

/*
 * Name:	findendvfp
 * Description:	Locate the end of the current line given a pointer into a buffer
 *		containing characters that is null terminated.
 * Arguments:	char **cp - pointer to pointer to null-terminated string buffer
 * Returns:	none
 * Effects:	cp is updated to point to the first character PAST the first new
 *		line character found. If no newline character is found, cp is
 *		updated to point to the '\0' at the end of the buffer.
 */

static void
findendvfp(char **cp)
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

	/* no newline found - point to null terminator */

	*cp = strchr(p, '\0');
}
