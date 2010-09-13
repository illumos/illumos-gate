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
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	LOCK_EX		1

#include <stdio.h>
#include <ctype.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>

static	struct mnttab *mntp = 0;

int getmntent(FILE *mnttabp, struct mnttab *mp);
static int mntdigit(char **p);
extern	char	*calloc();

struct mnttab *
_mnt()
{

	if (mntp == 0)
		mntp = (struct mnttab *)calloc(1, sizeof (struct mnttab));
	return (mntp);
}

static char *
mntstr(p)
	register char **p;
{
	char *cp = *p;
	char *retstr;

	while (*cp && isspace(*cp))
		cp++;
	retstr = cp;
	while (*cp && !isspace(*cp))
		cp++;
	if (*cp)
	{
		*cp = '\0';
		cp++;
	}
	*p = cp;
	return (retstr);
}

static int
mntdigit(p)
	register char **p;
{
	register int value = 0;
	char *cp = *p;

	while (*cp && isspace(*cp))
		cp++;
	for (; *cp && isdigit(*cp); cp++)
	{
		value *= 10;
		value += *cp - '0';
	}
	while (*cp && !isspace(*cp))
		cp++;
	if (*cp)
	{
		*cp = '\0';
		cp++;
	}
	*p = cp;
	return (value);
}

static int
mnttabscan(FILE *mnttabp, struct mnttab *mnt)
{
	static	char *line = NULL;
	char *cp;

	if (line == NULL)
		line = (char *)malloc(BUFSIZ+1);
	do
	{
		cp = fgets(line, 256, mnttabp);
		if (cp == NULL)
		{
			return (EOF);
		}
	} while (*cp == '#');
	mnt->mnt_special = mntstr(&cp);
	if (*cp == '\0')
		return (1);
	mnt->mnt_mountp = mntstr(&cp);
	if (*cp == '\0')
		return (2);
	mnt->mnt_fstype = mntstr(&cp);
	if (*cp == '\0')
		return (3);
	mnt->mnt_mntopts = mntstr(&cp);
	if (*cp == '\0')
		return (4);
	mnt->mnt_time = mntstr(&cp);
	return (5);
}
	
FILE *
setmntent(fname, flag)
	char *fname;
	char *flag;
{
	FILE *mnttabp;

	if ((mnttabp = fopen(fname, flag)) == NULL)
	{
		return (NULL);
	}
	for (; *flag ; flag++)
	{
		if (*flag == 'w' || *flag == 'a' || *flag == '+')
		{
			if (lockf(fileno(mnttabp), LOCK_EX, 0) < 0)
			{
				fclose(mnttabp);
				return (NULL);
			}
			break;
		}
	}
	return (mnttabp);
}

int
endmntent(mnttabp)
	FILE *mnttabp;
{

	if (mnttabp)
	{
		fclose(mnttabp);
	}
	return (1);
}

/*
 * #ifdef	NOWAY
 * int getmntent (mnttabp, mp)
 * 	FILE *mnttabp;
 * 	struct mnttab *mp;
 * {
 * 	int nfields;
 * 
 * 	if (mnttabp == 0)
 * 		return (-1);
 * 
 * 	if (_mnt() == 0)
 * 		return (-1);
 * 
 * 	nfields = mnttabscan(mnttabp, mntp);
 * 
 * 	if (nfields == EOF || nfields != 5)
 * 		return (-1);
 * 
 * 	mp = mntp;
 * 
 * 	return ( 0 );
 * }
 * #endif
 *
 *
 * #ifdef	NOWAY
 * struct mnttab *
 * getmntent(mnttabp)
 * 	FILE *mnttabp;
 * {
 * 	int nfields;
 * 
 * 	if (mnttabp == 0)
 * 		return ((struct mnttab *)0);
 * 	if (_mnt() == 0)
 * 		return ((struct mnttab *)0);
 * 	nfields = mnttabscan(mnttabp, mntp);
 * 	if (nfields == EOF || nfields != 5)
 * 		return ((struct mnttab *)0);
 * 	return (mntp);
 * }
 * #endif
 */

/*
 * addmntent(mnttabp, mnt)
 * 	FILE *mnttabp;
 * 	register struct mnttab *mnt;
 * 
 * 	if (fseek(mnttabp, 0L, 2) < 0)
 * 		return (1);
 * 	if (mnt == (struct mnttab *)0)
 * 		return (1);
 * 	if (mnt->mnt_special == NULL || mnt->mnt_mountp  == NULL ||
 * 	    mnt->mnt_fstype   == NULL || mnt->mnt_mntopts == NULL)
 * 		return (1);
 * 
 * 	mntprtent(mnttabp, mnt);
 * 	return (0);
 * }
 */

static int
mntprtent(FILE *mnttabp, struct mnttab *mnt)
{
	fprintf(mnttabp, "%s\t%s\t%s\t%s\t%s\n",
	    mnt->mnt_special,
	    mnt->mnt_mountp,
	    mnt->mnt_fstype,
	    mnt->mnt_mntopts,
	    mnt->mnt_time);
	return(0);
}
