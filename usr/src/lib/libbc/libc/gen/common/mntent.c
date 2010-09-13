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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <mntent.h>
#include <sys/file.h>
#include <malloc.h>

static int	mntprtent(FILE *, struct mntent *);

static	struct mntent *mntp;

struct mntent *
_mnt(void)
{

	if (mntp == 0)
		mntp = (struct mntent *)calloc(1, sizeof (struct mntent));
	return (mntp);
}

static char *
mntstr(char **p)
{
	unsigned char *cp = (unsigned char *) *p;
	unsigned char *retstr;

	while (*cp && isspace(*cp))
		cp++;
	retstr = cp;
	while (*cp && !isspace(*cp))
		cp++;
	if (*cp) {
		*cp = '\0';
		cp++;
	}
	*p = (char *) cp;
	return ((char *)retstr);
}

static int
mntdigit(char **p)
{
	int value = 0;
	unsigned char *cp = (unsigned char *) *p;

	while (*cp && isspace(*cp))
		cp++;
	for (; *cp && isdigit(*cp); cp++) {
		value *= 10;
		value += *cp - '0';
	}
	while (*cp && !isspace(*cp))
		cp++;
	if (*cp) {
		*cp = '\0';
		cp++;
	}
	*p =  (char *) cp;
	return (value);
}

static int
mnttabscan(FILE *mnttabp, struct mntent *mnt)
{
	static	char *line = NULL;
	char *cp;

	if (line == NULL)
		line = (char *)malloc(BUFSIZ+1);
	do {
		cp = fgets(line, BUFSIZ, mnttabp);
		if (cp == NULL) {
			return (EOF);
		}
	} while (*cp == '#');
	mnt->mnt_fsname = mntstr(&cp);
	if (*cp == '\0')
		return (1);
	mnt->mnt_dir = mntstr(&cp);
	if (*cp == '\0')
		return (2);
	mnt->mnt_type = mntstr(&cp);
	if (*cp == '\0')
		return (3);
	mnt->mnt_opts = mntstr(&cp);
	if (*cp == '\0')
		return (4);
	mnt->mnt_freq = mntdigit(&cp);
	if (*cp == '\0')
		return (5);
	mnt->mnt_passno = mntdigit(&cp);
	return (6);
}
	
FILE *
setmntent(char *fname, char *flag)
{
	FILE *mnttabp;

	if ((mnttabp = fopen(fname, flag)) == NULL) {
		return (NULL);
	}
	for (; *flag ; flag++) {
		if (*flag == 'w' || *flag == 'a' || *flag == '+') {
			if (flock(fileno(mnttabp), LOCK_EX) < 0) {
				fclose(mnttabp);
				return (NULL);
			}
			break;
		}
	}
	return (mnttabp);
}

int
endmntent(FILE *mnttabp)
{

	if (mnttabp) {
		fclose(mnttabp);
	}
	return (1);
}

struct mntent *
getmntent(FILE *mnttabp)
{
	int nfields;

	if (mnttabp == 0)
		return ((struct mntent *)0);
	if (_mnt() == 0)
		return ((struct mntent *)0);
	nfields = mnttabscan(mnttabp, mntp);
	if (nfields == EOF || nfields != 6)
		return ((struct mntent *)0);
	return (mntp);
}

int
addmntent(FILE *mnttabp, struct mntent *mnt)
{
	if (fseek(mnttabp, 0L, 2) < 0)
		return (1);
	if (mnt == (struct mntent *)0)
		return (1);
	if (mnt->mnt_fsname == NULL || mnt->mnt_dir  == NULL ||
	    mnt->mnt_type   == NULL || mnt->mnt_opts == NULL)
		return (1);

	mntprtent(mnttabp, mnt);
	return (0);
}

static char *
mntopt(char **p)
{
	unsigned char *cp = (unsigned char *) *p;
	unsigned char *retstr;

	while (*cp && isspace(*cp))
		cp++;
	retstr = cp;
	while (*cp && *cp != ',')
		cp++;
	if (*cp) {
		*cp = '\0';
		cp++;
	}
	*p =  (char *) cp;
	return ((char *)retstr);
}

char *
hasmntopt(struct mntent *mnt, char *opt)
{
	char *f, *opts;
	static char *tmpopts;

	if (tmpopts == 0) {
		tmpopts = (char *)calloc(256, sizeof (char));
		if (tmpopts == 0)
			return (0);
	}
	strcpy(tmpopts, mnt->mnt_opts);
	opts = tmpopts;
	f = mntopt(&opts);
	for (; *f; f = mntopt(&opts)) {
		if (strncmp(opt, f, strlen(opt)) == 0)
			return (f - tmpopts + mnt->mnt_opts);
	} 
	return (NULL);
}

static int
mntprtent(FILE *mnttabp, struct mntent *mnt)
{
	fprintf(mnttabp, "%s %s %s %s %d %d\n",
	    mnt->mnt_fsname,
	    mnt->mnt_dir,
	    mnt->mnt_type,
	    mnt->mnt_opts,
	    mnt->mnt_freq,
	    mnt->mnt_passno);
	return (0);
}
