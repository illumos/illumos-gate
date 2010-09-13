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

#ifndef	_SYS_VM_USAGE_H
#define	_SYS_VM_USAGE_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The flags passed to getvmusage() request how to aggregate rss/swap results.
 * Results can be aggregated by zone, project, task, ruser, and/or euser.
 *
 * If VMUSAGE_ALL_* or VMUSAGE_COL_* are passed from a non-global-zone, the
 * flag is treated as VMUSAGE_*.  For example, VMUSAGE_ALL_ZONES would be
 * treated as VMUSAGE_ZONE.
 *
 * If VMUSAGE_SYSTEM is passed from a non-global zone, a result of type
 * VMUSAGE_SYSTEM will be returned, but it will only reflect the usage
 * of the calling zone.
 *
 * VMUSAGE_*	 requests results for the calling zone.
 * VMUSAGE_ALL_* requests results for all zones.
 * VMUSAGE_COL_* requests results for all zones, but collapses out the zoneid.
 *		 For example, VMUSAGE_COL_PROJECTS requests results for all
 *		 projects in all zones, and project N in ANY zone is treated
 *		 as the same project.
 */
#define	VMUSAGE_SYSTEM		0x1	/* rss/swap for ALL processes */
#define	VMUSAGE_ZONE		0x2	/* rss/swap for caller's zone */
#define	VMUSAGE_PROJECTS	0x4	/* rss/swap for all projects in */
					/* caller's zone */
#define	VMUSAGE_TASKS		0x8	/* rss/swap for all tasks in */
					/* caller's zones */
#define	VMUSAGE_RUSERS		0x10	/* rss/swap for all users (by process */
					/* ruser) in the caller's zone */
#define	VMUSAGE_EUSERS		0x20	/* same as VMUSAGE_RUSERS, but by */
					/* euser */

#define	VMUSAGE_ALL_ZONES	0x40	/* rss/swap for all zones */
#define	VMUSAGE_ALL_PROJECTS	0x80	/* rss/swap for all projects in */
					/* all zones */
#define	VMUSAGE_ALL_TASKS	0x100	/* rss/swap for all tasks in all */
					/* zones */
#define	VMUSAGE_ALL_RUSERS	0x200	/* rss/swap for all users (by process */
					/* ruser) in all zones */
#define	VMUSAGE_ALL_EUSERS	0x400	/* same as VMUSAGE_ALL_RUSERS, but by */
					/* euser */

#define	VMUSAGE_COL_PROJECTS	0x800	/* rss/swap for all projects in */
					/* all zones.  Collapse zoneid. */
#define	VMUSAGE_COL_RUSERS	0x1000	/* rss/swap for all users (by process */
					/* ruser), in all zones.  Collapse */
					/* zoneid */
#define	VMUSAGE_COL_EUSERS	0x2000	/* same as VMUSAGE_COL_RUSERS, but by */
					/* euser */

#define	VMUSAGE_MASK		0x3fff  /* all valid flags for getvmusage() */

typedef struct vmusage {
	id_t	vmu_zoneid;		/* zoneid, or ALL_ZONES for */
					/* VMUSAGE_COL_* results */
					/* ALL_ZONES means that the result */
					/* reflects swap and rss usage for */
					/* a projid/uid across all zones */
	uint_t	vmu_type;		/* Entity type of result.  One of:  */
					/* VMUSAGE_(SYSTEM|ZONE|PROJECTS| */
					/* TASKS|RUSERS|EUSERS) */
	id_t	vmu_id;			/* zoneid, projid, taskid, ... */
	size_t	vmu_rss_all;		/* total resident memory of entity */
					/* in bytes */
	size_t	vmu_rss_private;	/* total resident private memory */
	size_t	vmu_rss_shared;		/* total resident shared memory */
	size_t	vmu_swap_all;		/* total swap reserved, in bytes */
	size_t	vmu_swap_private;	/* swap reserved for private mappings */
	size_t	vmu_swap_shared;	/* swap reserved for shared mappings */

} vmusage_t;

extern int getvmusage(uint_t flags, time_t age, vmusage_t *buf, size_t *nres);

#ifdef	_KERNEL

int vm_getusage(uint_t, time_t, vmusage_t *, size_t *, int);
void vm_usage_init();

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VM_USAGE_H */
