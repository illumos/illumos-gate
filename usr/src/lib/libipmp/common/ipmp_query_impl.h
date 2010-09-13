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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPMP_QUERY_IMPL_H
#define	_IPMP_QUERY_IMPL_H

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
 * List of ipmp_addrinfo_t structures.
 */
typedef struct ipmp_addrinfolist {
	struct ipmp_addrinfolist *adl_next;
	ipmp_addrinfo_t		*adl_adinfop;
} ipmp_addrinfolist_t;

/*
 * Snapshot of IPMP state.
 */
typedef struct ipmp_snap {
	ipmp_grouplist_t	*sn_grlistp;
	ipmp_groupinfolist_t	*sn_grinfolistp;
	ipmp_ifinfolist_t	*sn_ifinfolistp;
	ipmp_addrinfolist_t	*sn_adinfolistp;
	unsigned int		sn_ngroup;
	unsigned int		sn_nif;
	unsigned int		sn_naddr;
} ipmp_snap_t;

/*
 * Snapshot-related routines.
 */
extern ipmp_snap_t *ipmp_snap_create(void);
extern void ipmp_snap_free(ipmp_snap_t *);
extern int ipmp_snap_addifinfo(ipmp_snap_t *, ipmp_ifinfo_t *);
extern int ipmp_snap_addaddrinfo(ipmp_snap_t *, ipmp_addrinfo_t *);
extern int ipmp_snap_addgroupinfo(ipmp_snap_t *, ipmp_groupinfo_t *);

/*
 * IPMP structure creation/destruction routines.
 */
extern ipmp_ifinfo_t *ipmp_ifinfo_create(const char *, const char *,
    ipmp_if_state_t, ipmp_if_type_t, ipmp_if_linkstate_t, ipmp_if_probestate_t,
    ipmp_if_flags_t, ipmp_targinfo_t *, ipmp_targinfo_t *);
extern ipmp_groupinfo_t *ipmp_groupinfo_create(const char *, uint64_t, uint_t,
    ipmp_group_state_t, uint_t, char (*)[LIFNAMSIZ], const char *,
    const char *, const char *, const char *, uint_t,
    struct sockaddr_storage *);
extern ipmp_grouplist_t *ipmp_grouplist_create(uint64_t, unsigned int,
    char (*)[LIFGRNAMSIZ]);
extern ipmp_addrinfo_t *ipmp_addrinfo_create(struct sockaddr_storage *,
    ipmp_addr_state_t, const char *, const char *);
extern ipmp_targinfo_t *ipmp_targinfo_create(const char *,
    struct sockaddr_storage *, ipmp_if_targmode_t, uint_t,
    struct sockaddr_storage *);
extern void ipmp_freetarginfo(ipmp_targinfo_t *);


#ifdef __cplusplus
}
#endif

#endif /* _IPMP_QUERY_IMPL_H */
