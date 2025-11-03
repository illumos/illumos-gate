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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2025 Edgecast Cloud LLC.
 */

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
#include <atomic.h>
#include <strings.h>

static int getmntent_compat(FILE *fp, struct mnttab *mp);

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

static int
getmntany_compat(FILE *fp, struct mnttab *mgetp, struct mnttab *mrefp)
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

	while ((ret = getmntent_compat(fp, mgetp)) == 0 &&
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
getmntany(FILE *fp, struct mnttab *mgetp, struct mnttab *mrefp)
{
	struct mntentbuf embuf;
	char *copyp, *bufp;
	int ret;


	/*
	 * We collect all of the text strings pointed to by members of the
	 * user's preferences struct into a single buffer. At the same time
	 * populate the members of the results struct to point to the
	 * corresponding words. We then ask the kernel to figure out the
	 * rest; if this is a non-mntfs file then we handover to
	 * getmntany_compat().
	 */
	if ((copyp = bufp = getmntbuf(MNT_LINE_MAX)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}
	bzero(mgetp, sizeof (struct mnttab));
	if (mrefp->mnt_special) {
		mgetp->mnt_special = copyp;
		copyp += snprintf(mgetp->mnt_special, MNT_LINE_MAX, "%s",
		    mrefp->mnt_special) + 1;
	}
	if (mrefp->mnt_mountp) {
		mgetp->mnt_mountp = copyp;
		copyp += snprintf(mgetp->mnt_mountp,
		    bufp + MNT_LINE_MAX - copyp, "%s", mrefp->mnt_mountp) + 1;
	}
	if (mrefp->mnt_fstype) {
		mgetp->mnt_fstype = copyp;
		copyp += snprintf(mgetp->mnt_fstype,
		    bufp + MNT_LINE_MAX - copyp, "%s", mrefp->mnt_fstype) + 1;
	}
	if (mrefp->mnt_mntopts) {
		mgetp->mnt_mntopts = copyp;
		copyp += snprintf(mgetp->mnt_mntopts,
		    bufp + MNT_LINE_MAX - copyp, "%s", mrefp->mnt_mntopts) + 1;
	}
	if (mrefp->mnt_time) {
		mgetp->mnt_time = copyp;
		(void) snprintf(mgetp->mnt_time, bufp + MNT_LINE_MAX - copyp,
		    "%s", mrefp->mnt_time);
	}

	embuf.mbuf_emp = (struct extmnttab *)mgetp;
	embuf.mbuf_bufsize = MNT_LINE_MAX;
	embuf.mbuf_buf = bufp;

	switch (ret = ioctl(fileno(fp), MNTIOC_GETMNTANY, &embuf)) {
	case 0:
		/* Success. */
		return (0);
	case MNTFS_EOF:
		return (-1);
	case MNTFS_TOOLONG:
		return (MNT_TOOLONG);
	default:
		/* A failure of some kind. */
		if (errno == ENOTTY)
			return (getmntany_compat(fp, mgetp, mrefp));
		else
			return (ret);
	}
}

/*
 * Common code for getmntent() and getextmntent().
 *
 * These functions serve to populate a structure supplied by the user. Common
 * to both struct mnttab and struct extmnttab is a set of pointers to the
 * individual text fields that form an entry in /etc/mnttab. We arrange for the
 * text itself to be stored in some thread-local storage, and for the kernel to
 * populate both this buffer and the structure directly.
 *
 * If getmntent() passes a file that isn't provided by mntfs then we assume that
 * it is a simple text file and give it to getmntent_compat() to parse. For
 * getextmntent() we give up; it requires major and minor numbers that only the
 * kernel can provide.
 */
static int
getmntent_common(FILE *fp, struct extmnttab *emp, int command)
{
	struct mntentbuf embuf;
	static size_t bufsize = MNT_LINE_MAX;
	int ret;

	embuf.mbuf_emp = emp;
	embuf.mbuf_bufsize = bufsize;
	if ((embuf.mbuf_buf = getmntbuf(embuf.mbuf_bufsize)) == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	while ((ret = ioctl(fileno(fp), command, &embuf)) == MNTFS_TOOLONG) {
		/* The buffer wasn't large enough. */
		(void) atomic_swap_ulong((unsigned long *)&bufsize,
		    2 * embuf.mbuf_bufsize);
		embuf.mbuf_bufsize = bufsize;
		if ((embuf.mbuf_buf = getmntbuf(embuf.mbuf_bufsize)) == NULL) {
			errno = ENOMEM;
			return (-1);
		}
	}

	switch (ret) {
	case 0:
		/*
		 * We were successful, but we may have to enforce getmntent()'s
		 * documented limit on the line length.
		 */
		if (command == MNTIOC_GETMNTENT &&
		    (emp->mnt_time + strlen(emp->mnt_time) + 1 -
		    emp->mnt_special > MNT_LINE_MAX))
			return (MNT_TOOLONG);
		else
			return (0);
	case MNTFS_EOF:
		/* EOF. */
		return (-1);
	default:
		/* A non-mntfs file. */
		if (command == MNTIOC_GETMNTENT)
			return (getmntent_compat(fp, (struct mnttab *)emp));
		else
			return (ret);
	}
}

int
getmntent(FILE *fp, struct mnttab *mp)
{
	return (getmntent_common(fp, (struct extmnttab *)mp, MNTIOC_GETMNTENT));
}

int
getextmntent(FILE *fp, struct extmnttab *emp, size_t len __unused)
{
	return (getmntent_common(fp, emp, MNTIOC_GETEXTMNTENT));
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
hasmntopt(const struct mnttab *mnt, const char *opt)
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

void
resetmnttab(FILE *fp)
{
	rewind(fp);
}

/*
 * Compatibility for non-mntfs files.  For backwards compatibility, we continue
 * to have to support this broken interface.  Note that getextmntent() has
 * always failed when using a file other than /etc/mnttab, because it relies on
 * an ioctl() call.
 */
static int
getaline(char *lp, FILE *fp)
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
	if ((ret = getaline(line, fp)) != 0)
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
