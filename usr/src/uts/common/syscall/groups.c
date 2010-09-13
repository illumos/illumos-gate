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
 * Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/sid.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/policy.h>

int
setgroups(int gidsetsize, gid_t *gidset)
{
	proc_t	*p;
	cred_t	*cr, *newcr;
	int	i;
	int	n = gidsetsize;
	int	error;
	int	scnt = 0;
	ksidlist_t *ksl = NULL;
	zone_t	*zone;
	struct credgrp *grps = NULL;

	/* Perform the cheapest tests before grabbing p_crlock  */
	if (n > ngroups_max || n < 0)
		return (set_errno(EINVAL));

	zone = crgetzone(CRED());
	if (n != 0) {
		const gid_t *groups;

		grps = crgrpcopyin(n, gidset);

		if (grps == NULL)
			return (set_errno(EFAULT));

		groups = crgetggroups(grps);

		for (i = 0; i < n; i++) {
			if (!VALID_GID(groups[i], zone)) {
				crgrprele(grps);
				return (set_errno(EINVAL));
			}
			if (groups[i] > MAXUID)
				scnt++;
		}
		if (scnt > 0) {
			ksl = kcrsid_gidstosids(zone, n, (gid_t *)groups);
			if (ksl == NULL) {
				crgrprele(grps);
				return (set_errno(EINVAL));
			}
		}
	}


	/*
	 * Need to pre-allocate the new cred structure before acquiring
	 * the p_crlock mutex.
	 */
	newcr = cralloc_ksid();
	p = ttoproc(curthread);
	mutex_enter(&p->p_crlock);
retry:
	cr = p->p_cred;
	crhold(cr);
	mutex_exit(&p->p_crlock);

	if ((error = secpolicy_allow_setid(cr, -1, B_FALSE)) != 0) {
		if (grps != NULL)
			crgrprele(grps);
		if (ksl != NULL)
			ksidlist_rele(ksl);
		crfree(newcr);
		crfree(cr);
		return (set_errno(error));
	}
	mutex_enter(&p->p_crlock);
	crfree(cr);
	if (cr != p->p_cred)
		goto retry;

	crdup_to(cr, newcr);
	crsetsidlist(newcr, ksl);
	crsetcredgrp(newcr, grps);

	p->p_cred = newcr;
	crhold(newcr);			/* hold for the current thread */
	crfree(cr);			/* free the old one */
	mutex_exit(&p->p_crlock);

	/*
	 * Broadcast new cred to process threads (including the current one).
	 */
	crset(p, newcr);

	return (0);
}

int
getgroups(int gidsetsize, gid_t *gidset)
{
	struct cred *cr;
	int n;

	cr = curthread->t_cred;
	n = crgetngroups(cr);

	if (gidsetsize != 0) {
		if (gidsetsize < n)
			return (set_errno(EINVAL));
		if (copyout(crgetgroups(cr), gidset, n * sizeof (gid_t)))
			return (set_errno(EFAULT));
	}

	return (n);
}
