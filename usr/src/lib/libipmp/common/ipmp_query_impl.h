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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPMP_QUERY_IMPL_H
#define	_IPMP_QUERY_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ipmp_query.h>

/*
 * Private IPMP query interfaces and structures.
 *
 * These are *only* for use by in.mpathd and libipmp itself.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * List of ipmp_groupinfo_t structures.
 */
typedef struct ipmp_groupinfolist {
	struct ipmp_groupinfolist *grl_next;
	ipmp_groupinfo_t	*grl_grinfop;
} ipmp_groupinfolist_t;

/*
 * List of ipmp_ifinfo_t structures.
 */
typedef struct ipmp_ifinfolist {
	struct ipmp_ifinfolist	*ifl_next;
	ipmp_ifinfo_t		*ifl_ifinfop;
} ipmp_ifinfolist_t;

/*
 * Snapshot of IPMP state.
 */
typedef struct ipmp_snap {
	ipmp_grouplist_t	*sn_grlistp;
	ipmp_groupinfolist_t	*sn_grinfolistp;
	ipmp_ifinfolist_t	*sn_ifinfolistp;
	unsigned int		sn_ngroup;
	unsigned int		sn_nif;
} ipmp_snap_t;

/*
 * Snapshot-related routines.
 */
extern ipmp_snap_t *ipmp_snap_create(void);
extern void ipmp_snap_free(ipmp_snap_t *);
extern int ipmp_snap_addifinfo(ipmp_snap_t *, ipmp_ifinfo_t *);
extern int ipmp_snap_addgroupinfo(ipmp_snap_t *, ipmp_groupinfo_t *);

/*
 * IPMP structure creation routines.
 */
extern ipmp_ifinfo_t *ipmp_ifinfo_create(const char *, const char *,
    ipmp_if_state_t, ipmp_if_type_t);
extern ipmp_groupinfo_t *ipmp_groupinfo_create(const char *, uint64_t,
    ipmp_group_state_t, unsigned int, char (*)[LIFNAMSIZ]);
extern ipmp_grouplist_t *ipmp_grouplist_create(uint64_t, unsigned int,
    char (*)[LIFGRNAMSIZ]);

#ifdef __cplusplus
}
#endif

#endif /* _IPMP_QUERY_IMPL_H */
