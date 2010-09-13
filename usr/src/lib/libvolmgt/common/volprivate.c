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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * routines in this module are meant to be called by other libvolmgt
 * routines only
 */

#include	<stdio.h>
#include	<string.h>
#include	<dirent.h>
#include	<string.h>
#include	<libintl.h>
#include	<limits.h>
#include	<unistd.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<sys/varargs.h>
#include	"volmgt_private.h"


/*
 * fix the getfull{raw,blk}name problem for the fd and diskette case
 *
 * return value is malloc'ed, and must be free'd
 *
 * no match gets a malloc'ed null string
 */

char *
volmgt_getfullblkname(char *n)
{
	extern char	*getfullblkname(char *);
	char		*rval;
	char		namebuf[MAXPATHLEN+1];
	char		*s;
	char		c;
	char		*res;



	/* try to get full block-spcl device name */
	rval = getfullblkname(n);
	if ((rval != NULL) && (*rval != NULLC)) {
		/* found it */
		res = rval;
		goto dun;
	}

	/* we have a null-string result */
	if (rval != NULL) {
		/* free null string */
		free(rval);
	}

	/* ok, so we either have a bad device or a floppy */

	/* try the rfd# or rdiskette forms */
	if (((s = strstr(n, "/rfd")) != NULL) ||
	    ((s = strstr(n, "/rdiskette")) != NULL) ||
	    ((s = strstr(n, "/rdsk/")) != NULL)) {
		/*
		 * we do not have to check for room here, since we will
		 * be making the string one shorter
		 */
		c = *++s;			/* save the first char */
		*s = NULLC;			/* replace it with a null */
		(void) strcpy(namebuf, n);	/* save first part of it */
		*s++ = c;			/* give the first char back */
		(void) strcat(namebuf, s);	/* copy the rest */
		res = strdup(namebuf);
		goto dun;
	}

	/* no match found */
	res = strdup("");

dun:
	return (res);
}


char *
volmgt_getfullrawname(char *n)
{
	extern char	*getfullrawname(char *);
	char		*rval;
	char		namebuf[MAXPATHLEN+1];
	char		*s;
	char		c;
	char		*res;


#ifdef	DEBUG
	denter("volmgt_getfullrawname(%s): entering\n", n);
#endif
	/* try to get full char-spcl device name */
	rval = getfullrawname(n);
	if ((rval != NULL) && (*rval != NULLC)) {
		/* found it */
		res = rval;
		goto dun;
	}

	/* we have a null-string result */
	if (rval != NULL) {
		/* free null string */
		free(rval);
	}

	/* ok, so we either have a bad device or a floppy */

	/* try the "fd", "diskette", and the "dsk" form */
	if (((s = strstr(n, "/fd")) != NULL) ||
	    ((s = strstr(n, "/diskette")) != NULL) ||
	    ((s = strstr(n, "/dsk/")) != NULL)) {
		/*
		 * ensure we have room to add one more char
		 */
		if (strlen(n) < (MAXPATHLEN - 1)) {
			c = *++s;		/* save the first char */
			*s = NULLC;		/* replace it with a null */
			(void) strcpy(namebuf, n); /* save first part of str */
			*s = c;			/* put first charback */
			(void) strcat(namebuf, "r"); /* insert an 'r' */
			(void) strcat(namebuf, s); /* copy rest of str */
			res = strdup(namebuf);
			goto dun;
		}
	}

	/* no match found */
	res = strdup("");
dun:
#ifdef	DEBUG
	dexit("volmgt_getfullrawname: returning %s\n",
	    res ? res : "<null ptr>");
#endif
	return (res);
}


#ifdef	DEBUG

/*
 * debug print routines -- private to libvolmgt
 */

#define	DEBUG_INDENT_SPACES	"  "

int	debug_level = 0;


static void
derrprint(char *fmt, va_list ap)
{
	int		i;
	int		j;
	char		date_buf[256];
	time_t		t;
	struct tm	*tm;


	(void) time(&t);
	tm = localtime(&t);
	(void) fprintf(stderr, "%02d/%02d/%02d %02d:%02d:%02d ",
	    tm->tm_mon+1, tm->tm_mday, tm->tm_year % 100,
	    tm->tm_hour, tm->tm_min, tm->tm_sec);
	for (i = 0; i < debug_level; i++) {
		(void) fprintf(stderr, DEBUG_INDENT_SPACES);
	}
	(void) vfprintf(stderr, fmt, ap);
}

/*
 * denter -- do a derrprint(), then increment debug level
 */
void
denter(char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	derrprint(fmt, ap);
	va_end(ap);
	debug_level++;
}

/*
 * dexit -- decrement debug level then do a derrprint()
 */
void
dexit(char *fmt, ...)
{
	va_list		ap;

	if (--debug_level < 0) {
		debug_level = 0;
	}
	va_start(ap, fmt);
	derrprint(fmt, ap);
	va_end(ap);
}

/*
 * dprintf -- print debug info, indenting based on debug level
 */
void
dprintf(char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	derrprint(fmt, ap);
	va_end(ap);
}

#endif	/* DEBUG */
