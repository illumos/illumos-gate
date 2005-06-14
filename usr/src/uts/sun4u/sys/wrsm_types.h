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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _WRSM_TYPES_H
#define	_WRSM_TYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>

#ifdef _KERNEL
#include <sys/rsm/rsmpi.h>
#endif
#include <sys/wci_offsets.h>


#ifdef	__cplusplus
extern "C" {
#endif

#define	WRSM_NAME "wrsm"
#define	WRSM_MAX_RAG_INSTANCE 32
#define	WRSM_MAX_CNODES	256
#define	WRSM_MAX_NCSLICES 256
#define	WRSM_MAX_WNODES 16
#define	WRSM_LINKS_PER_WCI ENTRIES_WCI_SW_LINK_STATUS
#define	WRSM_MAX_LINKS_PER_WCI 3
#define	WRSM_MAX_WCIS_PER_STRIPE 4
#define	WRSM_MAX_DNIDS 4
#define	WRSM_NODE_NCSLICES	8

/*
 * macros for manipulating bitmask sets that use arrays of 32-bit ints
 * (lifted from cpuvar.h)
 */
#define	WRSMBPM		(sizeof (uint32_t) * NBBY) /* Number of bits in mask */
#define	WRSMSHIFT	5			/* divide by 32 */
#define	WRSMBPM		(sizeof (uint32_t) * NBBY) /* Number of bits in mask */
#define	WRSMBIT(bit)		((uint32_t)1 << (((uint32_t)bit) & 0x1f))
#define	WRSMMASKS(x, y)	(((x)+((y)-1))/(y))	/* Number of masks in set */
#define	WRSMMASKSIZE(set) (sizeof (set) / sizeof (uint32_t))

/*
 * bit mask manipulation macros
 */
#define	WRSM_IN_SET(set, bit)	(((set).b[(bit)>>WRSMSHIFT]) & WRSMBIT(bit))
#define	WRSMSET_ADD(set, bit)	(((set).b[(bit)>>WRSMSHIFT]) |= WRSMBIT(bit))
#define	WRSMSET_DEL(set, bit)	(((set).b[(bit)>>WRSMSHIFT]) &= ~WRSMBIT(bit))
#define	WRSMSET_ZERO(set)	bzero(&(set), sizeof (set))


#define	NCSLICE_MASKS	WRSMMASKS(WRSM_MAX_NCSLICES, WRSMBPM)
typedef struct wrsm_ncslice_bitmask {
	uint32_t	b[NCSLICE_MASKS];
} wrsm_ncslice_bitmask_t;

#define	CNODE_MASKS	WRSMMASKS(WRSM_MAX_CNODES, WRSMBPM)
typedef struct wrsm_cnode_bitmask {
	uint32_t	b[CNODE_MASKS];
} wrsm_cnode_bitmask_t;

#define	WNODE_MASKS	WRSMMASKS(WRSM_MAX_WNODES, WRSMBPM)
typedef struct wrsm_wnode_bitmask {
	uint32_t	b[WNODE_MASKS];
} wrsm_wnode_bitmask_t;


typedef int64_t		wrsm_fmnodeid_t;
typedef unsigned char	wrsm_cnodeid_t;
typedef unsigned char	wrsm_wnodeid_t;
typedef uint16_t	wrsm_gnid_t;
typedef unsigned char	wrsm_ncslice_t;
typedef unsigned char	wrsm_linkid_t;
typedef uint32_t 	wrsm_safari_port_t;


/*
 * This is an ordered list.  The first entry (entry 0) is the small page
 * ncslice.  The remaining 7 entries are large page slices; each entry maps
 * to a well defined range of CMMU entries, as described in the WCI PRM.
 * The ncslice for entry 1 must end with b'001', the ncslice for entry 2
 * must end with b'010', entry 3 with b'011' and so on.  An ncslice value
 * of 0 indicates that the entry is invalid.
 */
typedef struct node_ncslice_array {
	wrsm_ncslice_t id[WRSM_NODE_NCSLICES];
} wrsm_node_ncslice_array_t;


/*
 * typedefs for opaque structure definitions (for structures private to
 * particular wrsm modules, declared in module specific header files)
 */
typedef struct wrsm_net_member wrsm_net_member_t;
typedef struct wrsm_wci_data wrsm_wci_data_t;
typedef struct wrsm_ncslice_info wrsm_ncslice_info_t;

#ifdef	__cplusplus
}
#endif

#endif /* _WRSM_TYPES_H */
