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
 * Copyright (c) 1992, 1993, 1994, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Caching stat function
 */

#include <meta.h>

#define	MD_NUM_STAT_HEAD	16

struct statcache {
	struct statcache	*sc_next;
	struct stat		sc_stat;
	char			*sc_filename;
};

static struct statcache	*statcache_head[MD_NUM_STAT_HEAD] =
	{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

int
meta_stat(const char *filename, struct stat *sbp)
{
	struct statcache	*scp;
	int			 hash;
	char			*cp;

	hash = 0;
	for (cp = (char *)filename; *cp != 0; cp++)
		hash += *cp;

	hash &= 0xf;

	for (scp = statcache_head[hash]; scp != NULL; scp = scp->sc_next)
		if (strcmp(filename, scp->sc_filename) == 0)
			break;
	if (scp) {
		(void) memcpy((caddr_t)sbp, (caddr_t)&scp->sc_stat,
		    sizeof (*sbp));
		return (0);
	}
	if (stat(filename, sbp) != 0)
		return (-1);

	if (!S_ISBLK(sbp->st_mode) && !S_ISCHR(sbp->st_mode))
		return (-1);

	scp = (struct statcache *)malloc(sizeof (*scp));
	if (scp != NULL) {
		(void) memcpy((caddr_t)&scp->sc_stat, (caddr_t)sbp,
		    sizeof (*sbp));
		scp->sc_filename = strdup(filename);
		if (scp->sc_filename == NULL) {
			free((char *)scp);
			return (0);
		}
		scp->sc_next = statcache_head[hash];
		statcache_head[hash] = scp;
	}
	return (0);
}

void
metaflushstatcache(void)
{
	struct statcache	*p, *n;
	int			i;

	for (i = 0; i < MD_NUM_STAT_HEAD; i++) {
		for (p = statcache_head[i], n = NULL; p != NULL; p = n) {
			n = p->sc_next;
			Free(p->sc_filename);
			Free(p);
		}
		statcache_head[i] = NULL;
	}
}
