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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include <mtlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mnttab.h>
#include <sys/mntio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <libc.h>
#include <unistd.h>
#include "tsd.h"

static int getmntent_compat(FILE *fp, struct mnttab *mp);
static int convert_mntent(struct extmnttab *, struct extmnttab *, int);

#define	GETTOK_R(xx, ll, tmp)\
	if ((mp->xx = (char *)strtok_r(ll, sepstr, tmp)) == NULL)\
		return (MNT_TOOFEW);\
	if (strcmp(mp->xx, dash) == 0)\
		mp->xx = NULL

#define	DIFF(xx)\
	(mrefp->xx != NULL && (mgetp->xx == NULL ||\
	    strcmp(mrefp->xx, mgetp->xx) != 0))

#define	SDIFF(xx, typem, typer)\
	((mgetp->xx == NULL) || (stat64(mgetp->xx, &statb) == -1) ||\
	((statb.st_mode & S_IFMT) != typem) ||\
	    (statb.st_rdev != typer))

static const char	sepstr[] = " \t\n";
static const char	dash[] = "-";

typedef struct {
	size_t	buflen;
	char	*buf;
} thread_data_t;

static void
destroy_thread_data(void *arg)
{
	thread_data_t *thread_data = arg;

	if (thread_data->buf != NULL) {
		free(thread_data->buf);
		thread_data->buf = NULL;
	}
	thread_data->buflen = 0;
}

static char *
getmntbuf(size_t size)
{
	thread_data_t *thread_data;

	if (size < MNT_LINE_MAX)
		size = MNT_LINE_MAX;

	thread_data = tsdalloc(_T_GETMNTENT,
	    sizeof (thread_data_t), destroy_thread_data);
	if (thread_data == NULL)
		return (NULL);
	if (thread_data->buf == NULL ||
	    thread_data->buflen < size) {
		if (thread_data->buf != NULL)
			free(thread_data->buf);
		thread_data->buflen = 0;
		if ((thread_data->buf = malloc(size)) == NULL)
			return (NULL);
		thread_data->buflen = size;
	}
	return (thread_data->buf);
}

int
getmntany(FILE *fp, struct mnttab *mgetp, struct mnttab *mrefp)
{
	int	ret, bstat;
	mode_t	bmode;
	dev_t	brdev;
	struct stat64	statb;

	/*
	 * Ignore specials that don't correspond to real devices to avoid doing
	 * unnecessary lookups in stat64().
	 */
	if (mrefp->mnt_special && mrefp->mnt_special[0] == '/' &&
	    stat64(mrefp->mnt_special, &statb) == 0 &&
	    ((bmode = (statb.st_mode & S_IFMT)) == S_IFBLK ||
	    bmode == S_IFCHR)) {
		bstat = 1;
		brdev = statb.st_rdev;
	} else {
		bstat = 0;
	}

	while ((ret = getmntent(fp, mgetp)) == 0 &&
	    ((bstat == 0 && DIFF(mnt_special)) ||
	    (bstat == 1 && SDIFF(mnt_special, bmode, brdev)) ||
	    DIFF(mnt_mountp) ||
	    DIFF(mnt_fstype) ||
	    DIFF(mnt_mntopts) ||
	    DIFF(mnt_time)))
		;

	return (ret);
}

int
getmntent(FILE *fp, struct mnttab *mp)
{
	int	ret;
	struct	extmnttab *emp;

	ret = ioctl(fileno(fp), MNTIOC_GETMNTENT, &emp);

	switch (ret) {
		case 0:
			return (convert_mntent(emp, (struct extmnttab *)mp, 0));
		case 1:
			return (-1);
		default:
			return (getmntent_compat(fp, mp));
	}
}

char *
mntopt(char **p)
{
	char *cp = *p;
	char *retstr;

	while (*cp && isspace(*cp))
		cp++;

	retstr = cp;
	while (*cp && *cp != ',')
		cp++;

	if (*cp) {
		*cp = '\0';
		cp++;
	}

	*p = cp;
	return (retstr);
}

char *
hasmntopt(struct mnttab *mnt, char *opt)
{
	char tmpopts[MNT_LINE_MAX];
	char *f, *opts = tmpopts;
	size_t	len;

	if (mnt->mnt_mntopts == NULL)
		return (NULL);
	(void) strcpy(opts, mnt->mnt_mntopts);
	len = strlen(opt);
	f = mntopt(&opts);
	for (; *f; f = mntopt(&opts)) {
		/*
		 * Match only complete substrings. For options
		 * which use a delimiter (such as 'retry=3'),
		 * treat the delimiter as the end of the substring.
		 */
		if (strncmp(opt, f, len) == 0 &&
		    (f[len] == '\0' || !isalnum(f[len])))
			return (f - tmpopts + mnt->mnt_mntopts);
	}
	return (NULL);
}

/*ARGSUSED*/
int
getextmntent(FILE *fp, struct extmnttab *mp, size_t len)
{
	int	ret;
	struct	extmnttab *emp;

	ret = ioctl(fileno(fp), MNTIOC_GETMNTENT, &emp);

	switch (ret) {
		case 0:
			return (convert_mntent(emp, mp, 1));
		case 1:
			return (-1);
		default:
			return (ret);
	}
}

void
resetmnttab(FILE *fp)
{
	rewind(fp);
}

/*
 * This is a horrible function, necessary to support this broken interface.
 * Some callers of get(ext)mntent assume that the memory is valid even after the
 * file is closed.  Since we switched to a direct ioctl() interface, this is no
 * longer true.  In order to support these apps, we have to put the data into a
 * thread specific buffer.
 */
static int
convert_mntent(struct extmnttab *src, struct extmnttab *dst, int isext)
{
	size_t len;
	char *buf;

	len = src->mnt_time - src->mnt_special + strlen(src->mnt_time) + 1;

	buf = getmntbuf(len);
	if (buf == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	memcpy(buf, src->mnt_special, len);
	dst->mnt_special = buf;
	dst->mnt_mountp = buf + (src->mnt_mountp - src->mnt_special);
	dst->mnt_fstype = buf + (src->mnt_fstype - src->mnt_special);
	dst->mnt_mntopts = buf + (src->mnt_mntopts - src->mnt_special);
	dst->mnt_time = buf + (src->mnt_time - src->mnt_special);
	if (isext) {
		dst->mnt_major = src->mnt_major;
		dst->mnt_minor = src->mnt_minor;
	}

	return (0);
}

/*
 * Compatibility for non-mntfs files.  For backwards compatibility, we continue
 * to have to support this broken interface.  Note that getextmntent() has
 * always failed when using a file other than /etc/mnttab, because it relies on
 * an ioctl() call.
 */
static int
getline(char *lp, FILE *fp)
{
	char	*cp;

	while ((lp = fgets(lp, MNT_LINE_MAX, fp)) != NULL) {
		if (strlen(lp) == MNT_LINE_MAX-1 && lp[MNT_LINE_MAX-2] != '\n')
			return (MNT_TOOLONG);

		for (cp = lp; *cp == ' ' || *cp == '\t'; cp++)
			;

		if (*cp != '#' && *cp != '\n')
			return (0);
	}
	return (-1);
}

static int
getmntent_compat(FILE *fp, struct mnttab *mp)
{
	int	ret;
	char	*tmp;
	char	*line = getmntbuf(MNT_LINE_MAX);

	if (line == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	/* skip leading spaces and comments */
	if ((ret = getline(line, fp)) != 0)
		return (ret);

	/* split up each field */
	GETTOK_R(mnt_special, line, &tmp);
	GETTOK_R(mnt_mountp, NULL, &tmp);
	GETTOK_R(mnt_fstype, NULL, &tmp);
	GETTOK_R(mnt_mntopts, NULL, &tmp);
	GETTOK_R(mnt_time, NULL, &tmp);

	/* check for too many fields */
	if (strtok_r(NULL, sepstr, &tmp) != NULL)
		return (MNT_TOOMANY);

	return (0);
}
