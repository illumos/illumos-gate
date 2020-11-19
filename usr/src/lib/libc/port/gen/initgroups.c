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
 * Copyright 2020 Joyent, Inc.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma weak _initgroups = initgroups

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <grp.h>
#include <limits.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/param.h>
#include <unistd.h>

/* Private interface to the groups code in getgrnam.c */
extern int _getgroupsbymember(const char *, gid_t[], int, int);

int
initgroups(const char *uname, gid_t agroup)
{
	gid_t *groups;
	long ngroups_max;
	int ngroups;
	int errsave, retsave;

	if ((ngroups_max = sysconf(_SC_NGROUPS_MAX)) < 0) {
		/* ==== Hope sysconf() set errno to something sensible */
		return (-1);
	}
	/*
	 * ngroups_max is the maximum number of supplemental groups per
	 * process. if no supplemental groups are allowed, we're done.
	 */
	if (ngroups_max == 0)
		return (0);

	if ((groups = (gid_t *)calloc(ngroups_max, sizeof (gid_t))) == 0) {
		errno = ENOMEM;
		return (-1);
	}
	groups[0] = agroup;

	ngroups = _getgroupsbymember(uname, groups, (int)ngroups_max,
	    (agroup <= MAXUID) ? 1 : 0);
	if (ngroups < 0) {
		/* XXX -- man page does not define a value for errno in */
		/* this case.  Should be looked into sometime.	*/
		free(groups);
		return (-1);
	}

	retsave = setgroups(ngroups, groups);
	errsave = errno;

	free(groups);

	errno = errsave;
	return (retsave);
}

int
getgrouplist(const char *uname, gid_t agroup, gid_t *groups, int *ngroups)
{
	gid_t *grouplist = NULL;
	gid_t *grpptr;
	long ngroups_max;
	int sz, ret;

	/*
	 * We require sysconf(_SC_NGROUPS_MAX) either returns a sane value (>0)
	 * or fails. If it returns 0, something has gone horribly, horribly
	 * wrong.
	 */
	ngroups_max = sysconf(_SC_NGROUPS_MAX);
	if (ngroups_max > INT_MAX)
		ngroups_max = INT_MAX;
	else if (ngroups_max < 0)
		return (-1);
	VERIFY3S(ngroups_max, >, 0);

	/*
	 * The documented behavior of getgrouplist(3C) on other platforms
	 * (e.g. Linux and FreeBSD) do not list any failures other than
	 * 'groups is too small'. However, examination of some popular
	 * implementations of getgrouplist on those platforms (e.g. glibc and
	 * musl -- both appear to share the same man page for getgrouplist(3))
	 * show that they can in fact fail for other reasons (e.g. ENOMEM,
	 * EIO).
	 *
	 * As such, we don't attempt to catch and deal with any underlying
	 * errors here. Instead, any underlying errors cause getgrouplist(3C)
	 * to fail, and any errno value set is left unmodified for examination
	 * by the caller.
	 *
	 * One small complication is that the internal _getgroupsbymember()
	 * itself doesn't provide any way to report back if the buffer supplied
	 * to _getgroupsbymember() is too small. Instead, we always supply
	 * a buffer large enough to hold _SC_NGROUPS_MAX entries -- either
	 * by allocating one ourselves or using the user supplied buffer if
	 * sufficiently large.
	 *
	 * The system behavior is undefined for any user in more groups than
	 * _SC_NGROUPS_MAX -- initgroups(3C) for example just ignores any
	 * excess groups (and which _SC_NGROUPS_MAX sized subset of groups end
	 * up being set as the secondary groups is non-deterministic), so this
	 * seems reasonable. Modifying _getgroupsbymember() would require
	 * modification of the NSS code (due to the pervasive special handling
	 * of _getgroupsbymember() in the NSS code) as well as modification of
	 * all NSS backends that implement it. As there are at least a few
	 * known third party NSS backends, we've opted to avoid doing this
	 * for now.
	 */

	if ((ngroups == NULL) || (*ngroups <= 0) || (groups == NULL)) {
		*ngroups = ngroups_max;
		errno = EINVAL;
		return (-1);
	}

	if (*ngroups < ngroups_max) {
		/*
		 * The caller's buffer might be too small, try to use our own
		 * buffer instead.
		 */
		grouplist = calloc(ngroups_max, sizeof (gid_t));
		if (grouplist == NULL)
			return (-1);

		grpptr = grouplist;
		sz = ngroups_max;
	} else {
		/* The caller's buffer is large enough, so use it */
		grpptr = groups;
		sz = *ngroups;
	}

	/*
	 * Always add agroup as the first member -- it should always appear
	 * in the resulting list of groups, and this allows the backends to
	 * skip adding it.
	 */
	grpptr[0] = agroup;

	ret = _getgroupsbymember(uname, grpptr, sz, 1);

	/*
	 * We passed in 1 group entry. We should at minimum get 1 entry back
	 * from _getgroupsbymember(). If we don't, there is a bug in the NSS
	 * code or a backend. Since the return value is used to size a copy
	 * further below, we hard fail (abort) here if we get back an
	 * impossible value so we're not traipsing all over memory (which would
	 * just make debugging any such problem all the more difficult).
	 */
	VERIFY3S(ret, >, 0);

	/*
	 * If we used the caller's buffer, it means its size was >= ngroups_max
	 * entries, and we're done.
	 */
	if (grpptr == groups) {
		/* Set *ngroups to the number of entries in groups */
		*ngroups = ret;
		return (ret);
	}

	/* We verified earlier *ngroups > 0 */
	if (ret < *ngroups) {
		/* Copy as many gids that will fit */
		(void) memcpy(groups, grpptr, *ngroups * sizeof (gid_t));

		*ngroups = ret;
		ret = -1;
		errno = ERANGE;
	} else {
		(void) memcpy(groups, grpptr, ret * sizeof (gid_t));
		*ngroups = ret;
	}

	free(grouplist);
	return (ret);
}
