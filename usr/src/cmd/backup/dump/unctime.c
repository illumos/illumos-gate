/*
 * Copyright (c) 1998,2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
/*
 * Convert a ctime(3) format string into a system format date.
 * Return the date thus calculated.
 *
 * Return -1 if the string is not in ctime format.
 */

/*
 * Offsets into the ctime string to various parts.
 */

#define	E_MONTH		4
#define	E_DAY		8
#define	E_HOUR		11
#define	E_MINUTE	14
#define	E_SECOND	17
#define	E_YEAR		20

#ifdef __STDC__
static int lookup(char *);
static time_t emitl(struct tm *);
#else
static int lookup();
static time_t emitl();
#endif

time_t
unctime(str)
	char *str;
{
	struct tm then;
	char dbuf[30];

	/* Definition of ctime(3) is 24 characters + newline + NUL */
	(void) strncpy(dbuf, str, 24);
	dbuf[24] = '\0';
	dbuf[E_MONTH+3] = '\0';
	then.tm_mon = lookup(&dbuf[E_MONTH]);
	if (then.tm_mon < 0) {
		return (-1);
	}
	then.tm_mday = atoi(&dbuf[E_DAY]);
	then.tm_hour = atoi(&dbuf[E_HOUR]);
	then.tm_min = atoi(&dbuf[E_MINUTE]);
	then.tm_sec = atoi(&dbuf[E_SECOND]);
	then.tm_year = atoi(&dbuf[E_YEAR]) - 1900;
	return (emitl(&then));
}

static char months[] =
	"JanFebMarAprMayJunJulAugSepOctNovDec";

static int
lookup(str)
	char *str;
{
	char *cp, *cp2;

	for (cp = months, cp2 = str; *cp != 0; cp += 3)
		if (strncmp(cp, cp2, 3) == 0)
			/* LINTED ptr arith will give < INT_MAX result */
			return (((int)(cp-months)) / 3);
	return (-1);
}
/*
 * Routine to convert a localtime(3) format date back into
 * a system format date.
 */
static time_t
emitl(dp)
	struct tm *dp;
{
	dp->tm_isdst = -1;
	return (mktime(dp));
}
