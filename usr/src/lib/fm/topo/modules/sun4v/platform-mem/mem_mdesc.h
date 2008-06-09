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

#ifndef _MEM_MDESC_H
#define	_MEM_MDESC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/topo_mod.h>
#include <sys/fm/ldom.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MEM_DIMM_MAX	8		/* max FB DIMM depth */
#define	MAX_DIMMS_PER_BANK	4	/* would allow sun4u */

#ifndef	MIN
#define	MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef	MAX
#define	MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

typedef struct mem_dimm_map {
	struct mem_dimm_map *dm_next;	/* The next DIMM map */
	char *dm_label;			/* The UNUM for this DIMM */
	char *dm_serid; 		/* Cached serial number */
	char *dm_part;			/* DIMM part number */
	uint64_t dm_drgen;		/* DR gen count for cached S/N */
} mem_dimm_map_t;

typedef struct mem_bank_map {
	struct mem_bank_map *bm_next;	/* the next bank map overall */
	struct mem_bank_map *bm_grp;	/* next bank map in group */
	uint64_t	bm_mask;
	uint64_t	bm_match;
	uint16_t	bm_shift;	/* dimms-per-reference shift */
	mem_dimm_map_t *bm_dimm[MAX_DIMMS_PER_BANK];
} mem_bank_map_t;

typedef struct mem_grp {
	struct mem_grp *mg_next;
	size_t		mg_size;
	mem_bank_map_t *mg_bank;
} mem_grp_t;

typedef struct mem_seg_map {
	struct mem_seg_map *sm_next;	/* the next segment map */
	uint64_t	sm_base;	/* base address for this segment */
	uint64_t	sm_size;	/* size for this segment */
	mem_grp_t	*sm_grp;
} mem_seg_map_t;

typedef struct md_mem_info {
	mem_dimm_map_t *mem_dm;		/* List supported DIMMs */
/*	uint64_t mem_memconfig;		   HV memory-configuration-id# */
	mem_seg_map_t *mem_seg;		/* list of defined segments */
	mem_bank_map_t *mem_bank;
	mem_grp_t *mem_group;		/* groups of banks for a segment */
} md_mem_info_t;

extern int mem_mdesc_init(topo_mod_t *, md_mem_info_t *);
extern void mem_mdesc_fini(topo_mod_t *, md_mem_info_t *);
extern mem_dimm_map_t *mem_get_dimm_by_sn(char *, md_mem_info_t *);
extern void *mem_alloc(size_t);
extern void mem_free(void *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _MEM_MDESC_H */
