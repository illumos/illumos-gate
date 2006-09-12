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

#include <errno.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/resource.h>
#include <sys/sysconfig.h>
#include <sys/lx_types.h>
#include <sys/lx_misc.h>

#define	LX_RLIMIT_RSS		5
#define	LX_RLIMIT_NPROC		6
#define	LX_RLIMIT_MEMLOCK	8
#define	LX_RLIMIT_LOCKS		10
#define	LX_RLIMIT_NLIMITS	11

/*
 * Linux supports many of the same resources that we do, but the numbering
 * is slightly different.  This table is used to translate Linux resource
 * limit keys into their Solaris equivalents.
 */
static int ltos_resource[LX_RLIMIT_NLIMITS] = {
	RLIMIT_CPU,
	RLIMIT_FSIZE,
	RLIMIT_DATA,
	RLIMIT_STACK,
	RLIMIT_CORE,
	-1,			/* RSS */
	-1,			/* NPROC */
	RLIMIT_NOFILE,
	-1,			/* MEMLOCK */
	RLIMIT_AS,
	-1			/* LOCKS */
};

#define	NLIMITS	(sizeof (ltos_resource) / sizeof (int))

/*
 * Magic values Linux uses to indicate infinity
 */
#define	LX_RLIM_INFINITY_O	(0x7fffffffUL)
#define	LX_RLIM_INFINITY_N	(0xffffffffUL)

/*
 * Array to store the rlimits that we track but do not enforce.
 */
static struct rlimit fake_limits[NLIMITS] = {
	0, 0,
	0, 0,
	0, 0,
	0, 0,
	0, 0,
	RLIM_INFINITY, RLIM_INFINITY,	/* LX_RLIM_RSS */
	RLIM_INFINITY, RLIM_INFINITY,	/* LX_RLIM_NPROC */
	0, 0,
	RLIM_INFINITY, RLIM_INFINITY,	/* LX_RLIM_MEMLOCK */
	0, 0,
	RLIM_INFINITY, RLIM_INFINITY	/* LX_RLIM_LOCKS */
};

static int
lx_getrlimit_common(int resource, struct rlimit *rlp, int inf)
{
	int rv;
	int sresource;
	struct rlimit rl;

	if (resource < 0 || resource >= LX_RLIMIT_NLIMITS)
		return (-EINVAL);

	sresource = ltos_resource[resource];

	if (sresource == -1) {
		switch (resource) {
		case LX_RLIMIT_MEMLOCK:
		case LX_RLIMIT_RSS:
		case LX_RLIMIT_LOCKS:
		case LX_RLIMIT_NPROC:
			rl.rlim_max = fake_limits[resource].rlim_max;
			rl.rlim_cur = fake_limits[resource].rlim_cur;
			if (rl.rlim_cur == RLIM_INFINITY)
				rl.rlim_cur = inf;
			if (rl.rlim_max == RLIM_INFINITY)
				rl.rlim_max = inf;
			if ((uucopy(&rl, rlp, sizeof (rl))) != 0)
				return (-errno);
			return (0);
		default:
			lx_unsupported("Unsupported resource type %d\n",
			    resource);
			return (-ENOTSUP);
		}
	} else {
		rv = getrlimit(sresource, rlp);
	}

	if (rv < 0)
		return (-errno);

	if (rlp->rlim_cur == RLIM_INFINITY)
		rlp->rlim_cur = inf;

	if (rlp->rlim_max == RLIM_INFINITY)
		rlp->rlim_max = inf;

	return (0);
}

/*
 * This is the 'new' getrlimit, variously called getrlimit or ugetrlimit
 * in Linux headers and code.  The only difference between this and the old
 * getrlimit (variously called getrlimit or old_getrlimit) is the value of
 * RLIM_INFINITY, which is smaller for the older version.  Modern code will
 * use this version by default.
 */
int
lx_getrlimit(uintptr_t p1, uintptr_t p2)
{
	int resource = (int)p1;
	struct rlimit *rlp = (struct rlimit *)p2;

	return (lx_getrlimit_common(resource, rlp, LX_RLIM_INFINITY_N));
}

/*
 * This is the 'old' getrlimit, variously called getrlimit or old_getrlimit
 * in Linux headers and code.  The only difference between this and the new
 * getrlimit (variously called getrlimit or ugetrlimit) is the value of
 * RLIM_INFINITY, which is smaller for the older version.
 */
int
lx_oldgetrlimit(uintptr_t p1, uintptr_t p2)
{
	int resource = (int)p1;
	struct rlimit *rlp = (struct rlimit *)p2;

	return (lx_getrlimit_common(resource, rlp, LX_RLIM_INFINITY_O));
}

int
lx_setrlimit(uintptr_t p1, uintptr_t p2)
{
	int resource = (int)p1;
	struct rlimit *rlp = (struct rlimit *)p2;
	struct rlimit rl;
	int rv, sresource;

	if (resource < 0 || resource >= LX_RLIMIT_NLIMITS)
		return (-EINVAL);

	sresource = ltos_resource[resource];

	if (sresource == -1) {
		if (uucopy((void *)p2, &rl, sizeof (rl)) != 0)
			return (-errno);

		switch (resource) {
		case LX_RLIMIT_MEMLOCK:
		case LX_RLIMIT_RSS:
		case LX_RLIMIT_LOCKS:
		case LX_RLIMIT_NPROC:
			if (rl.rlim_max != LX_RLIM_INFINITY_N &&
			    (rl.rlim_cur == LX_RLIM_INFINITY_N ||
			    rl.rlim_cur > rl.rlim_max))
				return (-EINVAL);
			if (rl.rlim_max == LX_RLIM_INFINITY_N)
				fake_limits[resource].rlim_max = RLIM_INFINITY;
			else
				fake_limits[resource].rlim_max = rl.rlim_max;
			if (rl.rlim_cur == LX_RLIM_INFINITY_N)
				fake_limits[resource].rlim_cur = RLIM_INFINITY;
			else
				fake_limits[resource].rlim_cur = rl.rlim_cur;
			return (0);
		}

		lx_unsupported("Unsupported resource type %d\n", resource);
		return (-ENOTSUP);
	}

	rv = setrlimit(sresource, rlp);

	return (rv < 0 ? -errno : 0);
}

/*
 * We lucked out here.  Linux and Solaris have exactly the same
 * rusage structures.
 */
int
lx_getrusage(uintptr_t p1, uintptr_t p2)
{
	int who = (int)p1;
	struct rusage *rup = (struct rusage *)p2;
	int rv, swho;

	if (who == LX_RUSAGE_SELF)
		swho = _RUSAGESYS_GETRUSAGE;
	else if (who == LX_RUSAGE_CHILDREN)
		swho = _RUSAGESYS_GETRUSAGE_CHLD;
	else
		return (-EINVAL);

	rv = getrusage(swho, rup);

	return (rv < 0 ? -errno : 0);
}
