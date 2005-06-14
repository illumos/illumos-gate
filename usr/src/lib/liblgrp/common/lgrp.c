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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * lgroup interface
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/bitmap.h>
#include <sys/pset.h>
#include <sys/types.h>

#include <sys/lgrp_user.h>


/*
 * Fast trap for getting home lgroup of current thread
 */
extern lgrp_id_t	_lgrp_home_fast(void);

/*
 * lgroup system call
 */
extern int		_lgrpsys(int subcode, long arg, void *ap);

static int lgrp_cpus_hier(lgrp_snapshot_header_t *snap, lgrp_id_t lgrp,
    processorid_t **cpuids, uint_t *count);


/*
 * Get generation ID of lgroup hierarchy given view
 * which changes whenever the hierarchy changes (eg. DR or pset contents
 * change for caller's view)
 */
static lgrp_gen_t
lgrp_generation(lgrp_view_t view)
{
	return (_lgrpsys(LGRP_SYS_GENERATION, view, NULL));
}


/*
 * Get supported revision number of lgroup interface
 */
int
lgrp_version(int version)
{
	return (_lgrpsys(LGRP_SYS_VERSION, version, NULL));
}


/*
 * Get affinity for given lgroup
 */
lgrp_affinity_t
lgrp_affinity_get(idtype_t idtype, id_t id, lgrp_id_t lgrp)
{
	lgrp_affinity_args_t	args;

	args.idtype = idtype;
	args.id = id;
	args.lgrp = lgrp;
	return (_lgrpsys(LGRP_SYS_AFFINITY_GET, 0, (void *)&args));
}


/*
 * Set affinity for given lgroup
 */
int
lgrp_affinity_set(idtype_t idtype, id_t id, lgrp_id_t lgrp,
    lgrp_affinity_t aff)
{
	lgrp_affinity_args_t	args;

	args.idtype = idtype;
	args.id = id;
	args.lgrp = lgrp;
	args.aff = aff;
	return (_lgrpsys(LGRP_SYS_AFFINITY_SET, 0, (void *)&args));
}


/*
 * Get home lgroup for given process or thread
 */
lgrp_id_t
lgrp_home(idtype_t idtype, id_t id)
{
	/*
	 * Use fast trap to get home lgroup of current thread or process
	 * Otherwise, use system call for other process or thread
	 */
	if (id == P_MYID && (idtype == P_LWPID || idtype == P_PID))
		return (_lgrp_home_fast());
	else
		return (_lgrpsys(LGRP_SYS_HOME, idtype, (void *)(intptr_t)id));
}


/*
 * Get a snapshot of the lgroup hierarchy
 */
static int
lgrp_snapshot(void *buf, size_t bufsize)
{
	return (_lgrpsys(LGRP_SYS_SNAPSHOT, bufsize, buf));
}


/*
 * Find any orphan lgroups without parents and make them be children of
 * root lgroup
 */
static int
parent_orphans(lgrp_snapshot_header_t *snap)
{
	int		i;
	lgrp_info_t	*lgrp_info;
	int		nlgrpsmax;
	int		orphan;
	lgrp_info_t	*root;
	ulong_t		*parents;

	if (snap == NULL || snap->ss_info == NULL ||
	    snap->ss_parents == NULL || snap->ss_root < 0 ||
	    snap->ss_root >= snap->ss_nlgrps_max)
		return (-1);

	nlgrpsmax = snap->ss_nlgrps_max;
	root = &snap->ss_info[snap->ss_root];

	for (i = 0; i < nlgrpsmax; i++) {
		int	j;

		/*
		 * Skip root lgroup
		 */
		if (i == snap->ss_root)
			continue;

		lgrp_info = &snap->ss_info[i];
		if (lgrp_info == NULL || lgrp_info->info_lgrpid == LGRP_NONE)
			continue;

		/*
		 * Make sure parents bitmap is setup
		 */
		if (lgrp_info->info_parents == NULL)
			lgrp_info->info_parents =
			    (ulong_t *)((uintptr_t)snap->ss_parents +
			    (i * BT_SIZEOFMAP(nlgrpsmax)));

		/*
		 * Look for orphans (lgroups with no parents)
		 */
		orphan = 1;
		parents = lgrp_info->info_parents;
		for (j = 0; j < BT_BITOUL(nlgrpsmax); j++)
			if (parents[j] != 0) {
				orphan = 0;
				break;
			}

		/*
		 * Make root be parent of any orphans
		 */
		if (orphan) {
			BT_SET(parents, root->info_lgrpid);
			if (root->info_children) {
				BT_SET(root->info_children, i);
			}
		}
	}

	return (0);
}


/*
 * Remove given lgroup from parent lgroup(s)
 */
static void
prune_child(lgrp_snapshot_header_t *snap, lgrp_id_t lgrp)
{
	int		i;
	lgrp_info_t	*lgrp_info;
	ulong_t		*parents;

	if (snap == NULL || lgrp < 0 || lgrp > snap->ss_nlgrps_max)
		return;

	lgrp_info = &snap->ss_info[lgrp];

	parents = lgrp_info->info_parents;
	if (parents == NULL)
		return;

	/*
	 * Update children of parents not to include given lgroup
	 */
	for (i = 0; i < snap->ss_nlgrps_max; i++) {
		if (BT_TEST(parents, i)) {
			lgrp_info = &snap->ss_info[i];
			BT_CLEAR(lgrp_info->info_children, lgrp);
		}
	}
}

/*
 * Prune any CPUs not in given array from specified lgroup
 */
static void
prune_cpus(lgrp_snapshot_header_t *snap, lgrp_id_t lgrp, processorid_t *cpus,
    int ncpus)
{
	int		count;
	int		i;
	int		j;
	int		k;
	lgrp_info_t	*lgrp_info;
	uint_t		lgrp_ncpus;
	processorid_t	*lgrp_cpus;

	if (snap == NULL || lgrp < 0 || lgrp > snap->ss_nlgrps_max)
		return;

	lgrp_info = &snap->ss_info[lgrp];

	/*
	 * No CPUs to remove
	 */
	if (ncpus == 0 || lgrp_info->info_ncpus == 0)
		return;

	/*
	 * Remove all CPUs from lgroup
	 */
	if (cpus == NULL && ncpus == -1) {
		lgrp_info->info_ncpus = 0;
		return;
	}

	/*
	 * Remove any CPUs from lgroup not in given list of CPUs
	 */
	lgrp_cpus = lgrp_info->info_cpuids;
	lgrp_ncpus = lgrp_info->info_ncpus;
	i = 0;
	for (count = 0; count < lgrp_ncpus; count++) {
		/*
		 * Look for CPU in list
		 */
		for (j = 0; j < ncpus; j++)
			if (lgrp_cpus[i] == cpus[j])
				break;

		/*
		 * Go to next CPU if found this one in list
		 */
		if (j < ncpus) {
			i++;
			continue;
		}

		/*
		 * Remove this CPU and shift others into its place
		 * and decrement number of CPUs
		 */
		for (k = i + 1; k < lgrp_info->info_ncpus; k++)
			lgrp_cpus[k - 1] = lgrp_cpus[k];
		lgrp_cpus[k - 1] = -1;
		lgrp_info->info_ncpus--;
	}
}


/*
 * Prune lgroup hierarchy for caller's view
 */
static int
prune_tree(lgrp_snapshot_header_t *snap)
{
	processorid_t	*cpus;
	int		i;
	lgrp_info_t	*lgrp_info;
	lgrp_mem_size_t	nbytes;
	uint_t		ncpus;
	int		nlgrps_max;

	if (snap == NULL || snap->ss_info == NULL)
		return (-1);

	/*
	 * Get CPUs in caller's pset
	 */
	if (pset_info(PS_MYID, NULL, &ncpus, NULL) == -1)
		return (-1);

	cpus = NULL;
	if (ncpus > 0) {
		cpus = malloc(ncpus * sizeof (processorid_t));
		if (pset_info(PS_MYID, NULL, &ncpus, cpus) == -1) {
			free(cpus);
			return (-1);
		}
	}

	/*
	 * Remove any CPUs not in caller's pset from lgroup hierarchy
	 */
	nlgrps_max = snap->ss_nlgrps_max;
	for (i = 0; i < nlgrps_max; i++) {
		lgrp_info = &snap->ss_info[i];
		if (BT_TEST(snap->ss_lgrpset, i))
			prune_cpus(snap, i, cpus, ncpus);
		else if (lgrp_info->info_lgrpid != LGRP_NONE)
			prune_cpus(snap, i, NULL, -1);
	}

	if (ncpus > 0)
		free(cpus);

	/*
	 * Change lgroup bitmask from just reflecting lgroups overlapping
	 * caller's pset to all lgroups available to caller, starting by
	 * filling in all lgroups and then removing any empty ones below
	 */
	for (i = 0; i < nlgrps_max; i++) {
		lgrp_info = &snap->ss_info[i];
		if (lgrp_info->info_lgrpid == LGRP_NONE)
			continue;

		BT_SET(snap->ss_lgrpset, i);
	}

	/*
	 * Remove empty lgroups from lgroup hierarchy, removing it from its
	 * parents and decrementing nlgrps
	 */
	for (i = 0; i < nlgrps_max; i++) {
		lgrp_info = &snap->ss_info[i];
		if (lgrp_info->info_lgrpid == LGRP_NONE)
			continue;

		ncpus = lgrp_cpus_hier(snap, i, NULL, NULL);
		nbytes = lgrp_mem_size((lgrp_cookie_t)snap, i,
		    LGRP_MEM_SZ_INSTALLED, LGRP_CONTENT_HIERARCHY);
		if (ncpus == 0 && nbytes == 0) {
			BT_CLEAR(snap->ss_lgrpset, i);
			prune_child(snap, i);
			snap->ss_nlgrps--;
		}
	}

	return (0);
}


/*
 * Initialize lgroup interface
 */
lgrp_cookie_t
lgrp_init(lgrp_view_t view)
{
	ssize_t			bufsize;
	uint_t			gen;
	int			i;
	lgrp_snapshot_header_t	*snap;

	/*
	 * Check for legal view
	 */
	if (view != LGRP_VIEW_OS && view != LGRP_VIEW_CALLER) {
		errno = EINVAL;
		return (LGRP_COOKIE_NONE);
	}

	/*
	 * Try to take a consistent snapshot of lgroup hierarchy
	 */
	snap = NULL;
	while (snap == NULL) {
		/*
		 * Get lgroup generation number before taking snapshot
		 */
		gen = lgrp_generation(view);

		/*
		 * Get size of buffer needed for snapshot
		 */
		bufsize = lgrp_snapshot(NULL, 0);
		if (bufsize <= 0) {
			if (errno == ENOMEM)
				return (LGRP_COOKIE_NONE);

			snap = NULL;
			continue;
		}

		/*
		 * Allocate buffer
		 */
		snap = malloc(bufsize);
		if (snap == NULL)
			return (LGRP_COOKIE_NONE);
		bzero(snap, bufsize);

		/*
		 * Take snapshot of lgroup hierarchy
		 */
		bufsize = lgrp_snapshot(snap, bufsize);
		if (bufsize <= 0) {
			free(snap);
			if (errno == ENOMEM)
				return (LGRP_COOKIE_NONE);

			snap = NULL;
			continue;
		}

		/*
		 * See whether lgroup generation number changed
		 */
		if (gen == lgrp_generation(view))
			break;

		free(snap);
		snap = NULL;
	}

	/*
	 * Remember generation number and view of this snapshot
	 */
	snap->ss_gen = gen;
	snap->ss_view = view;

	/*
	 * Keep caller's pset ID for caller's view
	 */
	snap->ss_pset = 0;
	if (view == LGRP_VIEW_CALLER) {
		psetid_t	pset;

		if (pset_bind(PS_QUERY, P_LWPID, P_MYID, &pset) == -1)
			return ((uintptr_t)-1);

		snap->ss_pset = pset;
	}

	/*
	 * Find any orphan lgroups without parents and make them be children
	 * of the root lgroup
	 */
	if (snap->ss_levels > 1)
		(void) parent_orphans(snap);

	/*
	 * Prune snapshot of lgroup hierarchy for caller's view
	 */
	if (view == LGRP_VIEW_CALLER)
		(void) prune_tree(snap);
	else {
		/*
		 * Change lgroup bitmask from just reflecting lgroups
		 * overlapping caller's pset to all lgroups available
		 */
		for (i = 0; i < snap->ss_nlgrps_max; i++) {
			lgrp_info_t	*lgrp_info;

			lgrp_info = &snap->ss_info[i];
			if (lgrp_info->info_lgrpid == LGRP_NONE)
				continue;

			BT_SET(snap->ss_lgrpset, i);
		}
	}

	return ((uintptr_t)snap);
}


/*
 * Return whether given cookie is out-of-date (stale) or not
 */
int
lgrp_cookie_stale(lgrp_cookie_t cookie)
{
	psetid_t		pset;
	lgrp_snapshot_header_t	*snap;

	/*
	 * Check for bad cookie
	 */
	snap = (lgrp_snapshot_header_t *)cookie;
	if (snap == NULL || snap->ss_magic != cookie) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Check generation number which changes when lgroup hierarchy changes
	 * or pset contents change for caller's view
	 */
	if (snap->ss_gen != lgrp_generation(snap->ss_view))
		return (1);

	/*
	 * See whether pset binding has changed for caller's view
	 */
	if (snap->ss_view == LGRP_VIEW_CALLER) {
		if (pset_bind(PS_QUERY, P_LWPID, P_MYID, &pset) == -1)
			return (-1);
		if (snap->ss_pset != pset)
			return (1);
	}

	return (0);	/* cookie isn't stale */
}


/*
 * Get view of lgroup hierarchy from snapshot represented by given cookie
 */
lgrp_view_t
lgrp_view(lgrp_cookie_t cookie)
{
	lgrp_snapshot_header_t	*snap;

	snap = (lgrp_snapshot_header_t *)cookie;
	if (snap == NULL || snap->ss_magic != cookie) {
		errno = EINVAL;
		return (-1);
	}

	return (snap->ss_view);
}


/*
 * Get number of lgroups
 */
int
lgrp_nlgrps(lgrp_cookie_t cookie)
{
	lgrp_snapshot_header_t	*snap;

	snap = (lgrp_snapshot_header_t *)cookie;

	if (snap == NULL || snap->ss_magic != cookie) {
		errno = EINVAL;
		return (-1);
	}

	return (snap->ss_nlgrps);
}


/*
 * Return root lgroup ID
 */
lgrp_id_t
lgrp_root(lgrp_cookie_t cookie)
{
	lgrp_snapshot_header_t	*snap;

	snap = (lgrp_snapshot_header_t *)cookie;

	if (snap == NULL || snap->ss_magic != cookie) {
		errno = EINVAL;
		return (-1);
	}

	return (snap->ss_root);
}


/*
 * Get parent lgroups of given lgroup
 */
int
lgrp_parents(lgrp_cookie_t cookie, lgrp_id_t lgrp, lgrp_id_t *parents,
    uint_t count)
{
	int			i;
	ulong_t			*lgrp_parents;
	lgrp_snapshot_header_t	*snap;
	int			nlgrps_max;
	int			nparents;

	snap = (lgrp_snapshot_header_t *)cookie;

	/*
	 * Check for valid arguments
	 */
	if (snap == NULL || snap->ss_magic != cookie ||
	    lgrp < 0 || lgrp == LGRP_NONE) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * See whether given lgroup exists
	 */
	nlgrps_max = snap->ss_nlgrps_max;
	if (lgrp >= nlgrps_max || !BT_TEST(snap->ss_lgrpset, lgrp)) {
		errno = ESRCH;
		return (-1);
	}

	/*
	 * No parents, since given lgroup is root lgroup or
	 * only one level in lgroup hierarchy (ie. SMP)
	 */
	if (lgrp == snap->ss_root || snap->ss_levels == 1) {
		if (parents == NULL || count < 1)
			return (0);
		return (0);
	}

	/*
	 * Make sure that parents exist
	 */
	if (snap->ss_parents == NULL) {
		errno = ESRCH;
		return (-1);
	}

	/*
	 * Given lgroup should have a parent
	 */
	lgrp_parents = &snap->ss_parents[lgrp * BT_BITOUL(nlgrps_max)];
	if (lgrp_parents == NULL) {
		errno = ESRCH;
		return (-1);
	}

	/*
	 * Check lgroup parents bitmask, fill in parents array, and return
	 * number of parents
	 */
	nparents = 0;
	for (i = 0; i < nlgrps_max; i++) {
		if (BT_TEST(lgrp_parents, i)) {
			if (parents != NULL && nparents < count) {
				parents[nparents] = i;
			}
			nparents++;
		}
	}
	return (nparents);
}


/*
 * Get children lgroups of given lgroup
 */
int
lgrp_children(lgrp_cookie_t cookie, lgrp_id_t lgrp, lgrp_id_t *children,
    uint_t count)
{
	int			i;
	ulong_t			*lgrp_children;
	int			nlgrps_max;
	int			nchildren;
	lgrp_snapshot_header_t	*snap;

	snap = (lgrp_snapshot_header_t *)cookie;

	/*
	 * Check for valid arguments
	 */
	if (snap == NULL || snap->ss_magic != cookie ||
	    lgrp < 0 || lgrp == LGRP_NONE) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * See whether given lgroup exists
	 */
	nlgrps_max = snap->ss_nlgrps_max;
	if (lgrp >= nlgrps_max || !BT_TEST(snap->ss_lgrpset, lgrp)) {
		errno = ESRCH;
		return (-1);
	}

	/*
	 * No children, since only one level in lgroup hierarchy (ie. SMP)
	 */
	if (snap->ss_levels == 1) {
		if (children == NULL || count < 1)
			return (0);
		return (0);
	}

	/*
	 * Make sure that children exist
	 */
	if (snap->ss_children == NULL) {
		errno = ESRCH;
		return (-1);
	}

	/*
	 * Given lgroup may not have any children
	 */
	lgrp_children = &snap->ss_children[lgrp * BT_BITOUL(nlgrps_max)];

	if (lgrp_children == NULL)
		return (0);

	/*
	 * Check lgroup children bitmask, fill in children array, and return
	 * number of children
	 */
	nchildren = 0;
	for (i = 0; i < nlgrps_max; i++) {
		if (BT_TEST(lgrp_children, i)) {
			if (children != NULL && nchildren < count)
				children[nchildren] = i;
			nchildren++;
		}
	}
	return (nchildren);
}


/*
 * Get all CPUs within given lgroup (hierarchy)
 */
static int
lgrp_cpus_hier(lgrp_snapshot_header_t *snap, lgrp_id_t lgrp,
    processorid_t **cpuids, uint_t *count)
{
	processorid_t	*cpus;
	int		i;
	int		j;
	lgrp_info_t	*lgrp_info;
	int		ncpus;
	int		nlgrps_max;
	ulong_t		*rset;
	int		total;

	/*
	 * Get lgroup info
	 */
	lgrp_info = &snap->ss_info[lgrp];

	if (lgrp_info == NULL) {
		errno = ESRCH;
		return (-1);
	}

	/*
	 * Check whether given lgroup contains any lgroups with CPU resources
	 */
	if (lgrp_info->info_rset == NULL)
		return (0);

	nlgrps_max = snap->ss_nlgrps_max;
	rset = &lgrp_info->info_rset[LGRP_RSRC_CPU * BT_BITOUL(nlgrps_max)];

	/*
	 * Get all CPUs within this lgroup
	 */
	total = 0;
	for (i = 0; i < nlgrps_max; i++) {
		if (!BT_TEST(rset, i))
			continue;

		lgrp_info = &snap->ss_info[i];

		/*
		 * Get all CPUs within lgroup
		 */
		cpus = lgrp_info->info_cpuids;
		ncpus = lgrp_info->info_ncpus;
		total += ncpus;

		/*
		 * Copy as many CPU IDs into array that will fit
		 * and decrement count and increment array pointer
		 * as we go
		 */
		if (cpuids && *cpuids && count) {
			for (j = 0; j < ncpus; j++) {
				if (*count) {
					**cpuids = cpus[j];
					(*cpuids)++;
					(*count)--;
				}
			}
		}
	}

	return (total);
}


/*
 * Get CPUs in given lgroup
 */
int
lgrp_cpus(lgrp_cookie_t cookie, lgrp_id_t lgrp, processorid_t *cpuids,
    uint_t count, lgrp_content_t content)
{
	int			i;
	processorid_t		*cpus;
	lgrp_info_t		*lgrp_info;
	int			ncpus;
	lgrp_snapshot_header_t	*snap;

	snap = (lgrp_snapshot_header_t *)cookie;

	/*
	 * Check for valid arguments
	 */
	if (snap == NULL || snap->ss_magic != cookie ||
	    lgrp < 0 || lgrp == LGRP_NONE ||
	    (content != LGRP_CONTENT_DIRECT &&
	    content != LGRP_CONTENT_HIERARCHY)) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * See whether given lgroup exists
	 */
	if (lgrp >= snap->ss_nlgrps_max || snap->ss_info == NULL ||
	    !BT_TEST(snap->ss_lgrpset, lgrp)) {
		errno = ESRCH;
		return (-1);
	}

	/*
	 * Get lgroup info
	 */
	lgrp_info = &snap->ss_info[lgrp];

	/*
	 * Get contents of lgroup
	 */
	switch (content) {
	case LGRP_CONTENT_DIRECT:
		/*
		 * Get CPUs contained directly within given lgroup
		 */
		cpus = lgrp_info->info_cpuids;
		ncpus = lgrp_info->info_ncpus;

		/*
		 * No array to copy CPU IDs into,
		 * so just return number of CPUs.
		 */
		if (cpuids == NULL)
			return (ncpus);

		/*
		 * Copy as many CPU IDs into array that will fit
		 */
		for (i = 0; i < ncpus; i++)
			if (i < count)
				cpuids[i] = cpus[i];

		return (ncpus);

	case LGRP_CONTENT_ALL:
		return (lgrp_cpus_hier(snap, lgrp, &cpuids, &count));

	default:
		errno = EINVAL;
		return (-1);
	}
}


/*
 * Return physical memory size in pages for given lgroup
 */
lgrp_mem_size_t
lgrp_mem_size(lgrp_cookie_t cookie, lgrp_id_t lgrp, lgrp_mem_size_flag_t type,
    lgrp_content_t content)
{
	int			i;
	lgrp_info_t		*lgrp_info;
	int			nlgrps_max;
	int			pgsz;
	ulong_t			*rset;
	lgrp_mem_size_t		size;
	lgrp_snapshot_header_t	*snap;

	snap = (lgrp_snapshot_header_t *)cookie;

	/*
	 * Check for valid arguments
	 */
	if (snap == NULL || snap->ss_magic != cookie ||
	    lgrp < 0 || lgrp == LGRP_NONE) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * See whether given lgroup exists
	 */
	nlgrps_max = snap->ss_nlgrps_max;
	if (lgrp >= nlgrps_max || snap->ss_info == NULL ||
	    !BT_TEST(snap->ss_lgrpset, lgrp)) {
		errno = ESRCH;
		return (-1);
	}

	pgsz = getpagesize();

	/*
	 * Get lgroup info
	 */
	lgrp_info = &snap->ss_info[lgrp];

	switch (content) {
	case LGRP_CONTENT_DIRECT:
		/*
		 * Get memory contained directly in this lgroup
		 */
		switch (type) {
		case LGRP_MEM_SZ_FREE:
			size = (lgrp_mem_size_t)pgsz *
			    lgrp_info->info_mem_free;
			return (size);
		case LGRP_MEM_SZ_INSTALLED:
			size = (lgrp_mem_size_t)pgsz *
			    lgrp_info->info_mem_install;
			return (size);
		default:
			errno = EINVAL;
			return (-1);
		}

	case LGRP_CONTENT_ALL:
		/*
		 * Get memory contained within this lgroup (and its children)
		 */
		/*
		 * Check whether given lgroup contains any lgroups with CPU
		 * resources
		 */
		if (lgrp_info->info_rset == NULL)
			return (0);

		rset = &lgrp_info->info_rset[LGRP_RSRC_MEM *
		    BT_BITOUL(nlgrps_max)];

		/*
		 * Add up memory in lgroup resources
		 */
		size = 0;
		for (i = 0; i < nlgrps_max; i++) {
			if (!BT_TEST(rset, i))
				continue;

			lgrp_info = &snap->ss_info[i];
			switch (type) {
			case LGRP_MEM_SZ_FREE:
				size += (lgrp_mem_size_t)pgsz *
				    lgrp_info->info_mem_free;
				break;
			case LGRP_MEM_SZ_INSTALLED:
				size += (lgrp_mem_size_t)pgsz *
				    lgrp_info->info_mem_install;
				break;
			default:
				errno = EINVAL;
				return (-1);
			}

		}

		return (size);

	default:
		errno = EINVAL;
		return (-1);
	}
}


/*
 * Get resources for a particuliar lgroup
 */
int
lgrp_resources(lgrp_cookie_t cookie, lgrp_id_t lgrp, lgrp_id_t *lgrps,
    uint_t count, lgrp_rsrc_t type)
{
	int			i;
	lgrp_info_t		*lgrp_info;
	int			nlgrps;
	int			nlgrps_max;
	ulong_t			*rset;
	lgrp_snapshot_header_t	*snap;

	snap = (lgrp_snapshot_header_t *)cookie;

	/*
	 * Check for valid arguments
	 */
	if (snap == NULL || snap->ss_magic != cookie ||
	    lgrp < 0 || lgrp == LGRP_NONE ||
	    (type != LGRP_RSRC_CPU && type != LGRP_RSRC_MEM)) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * See whether given lgroup exists
	 */
	nlgrps_max = snap->ss_nlgrps_max;
	if (lgrp >= nlgrps_max || snap->ss_info == NULL ||
	    !BT_TEST(snap->ss_lgrpset, lgrp)) {
		errno = ESRCH;
		return (-1);
	}

	/*
	 * Get lgroup info
	 */
	lgrp_info = &snap->ss_info[lgrp];

	/*
	 * Count number lgroups contained within this lgroup and
	 * copy as many lgroup IDs into array that will fit
	 */
	rset = &lgrp_info->info_rset[type * BT_BITOUL(nlgrps_max)];
	nlgrps = 0;
	for (i = 0; i < snap->ss_nlgrps_max; i++)
		if (BT_TEST(rset, i)) {
			if (lgrps != NULL && nlgrps < count)
				lgrps[nlgrps] = i;
			nlgrps++;
		}

	return (nlgrps);
}


/*
 * Finish using lgroup interface
 */
int
lgrp_fini(lgrp_cookie_t cookie)
{
	lgrp_snapshot_header_t	*snap;

	snap = (lgrp_snapshot_header_t *)cookie;

	if (snap == NULL || snap->ss_magic != cookie) {
		errno = EINVAL;
		return (-1);
	}

	bzero(snap, snap->ss_size);
	free(snap);
	snap = NULL;

	return (0);
}


/*
 * Return latency between "from" and "to" lgroups
 *
 * This latency number can only be used for relative comparison
 * between lgroups on the running system, cannot be used across platforms,
 * and may not reflect the actual latency.  It is platform and implementation
 * specific, so platform gets to decide its value.  It would be nice if the
 * number was at least proportional to make comparisons more meaningful though.
 */
int
lgrp_latency(lgrp_id_t from, lgrp_id_t to)
{
	lgrp_cookie_t		cookie;
	int			latency;

	cookie = lgrp_init(LGRP_VIEW_OS);
	latency = lgrp_latency_cookie(cookie, from, to, LGRP_LAT_CPU_TO_MEM);
	(void) lgrp_fini(cookie);

	return (latency);
}


/*
 * Return latency between "from" and "to" lgroups
 *
 * This latency number can only be used for relative comparison
 * between lgroups on the running system, cannot be used across platforms,
 * and may not reflect the actual latency.  It is platform and implementation
 * specific, so platform gets to decide its value.  It would be nice if the
 * number was at least proportional to make comparisons more meaningful though.
 */
int
lgrp_latency_cookie(lgrp_cookie_t cookie, lgrp_id_t from, lgrp_id_t to,
    lgrp_lat_between_t between)
{
	lgrp_info_t		*lgrp_info;
	lgrp_mem_size_t		nbytes;
	int			ncpus;
	int			nlgrps_max;
	lgrp_snapshot_header_t	*snap;

	snap = (lgrp_snapshot_header_t *)cookie;

	/*
	 * Check for valid snapshot, lgroup, and between flag
	 */
	if (snap == NULL || snap->ss_magic != cookie || from < 0 || to < 0 ||
	    between != LGRP_LAT_CPU_TO_MEM) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Check whether lgroups exist
	 */
	nlgrps_max = snap->ss_nlgrps_max;
	if (from >= nlgrps_max || to >= nlgrps_max) {
		errno = ESRCH;
		return (-1);
	}

	/*
	 * Check whether "from" lgroup has any CPUs
	 */
	ncpus = lgrp_cpus(cookie, from, NULL, 0, LGRP_CONTENT_HIERARCHY);
	if (ncpus <= 0) {
		if (ncpus == 0)
			errno = ESRCH;
		return (-1);
	}

	/*
	 * Check whether "to" lgroup has any memory
	 */
	nbytes = lgrp_mem_size(cookie, to, LGRP_MEM_SZ_INSTALLED,
	    LGRP_CONTENT_HIERARCHY);
	if (nbytes <= 0) {
		if (nbytes == 0)
			errno = ESRCH;
		return (-1);
	}

	if (from == to) {
		lgrp_info = &snap->ss_info[from];
		return (lgrp_info->info_latency);
	}

	return (snap->ss_latencies[from][to]);
}
