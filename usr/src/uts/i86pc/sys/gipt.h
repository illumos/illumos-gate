/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#ifndef _GIPT_H_
#define	_GIPT_H_

#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/param.h>
#include <sys/list.h>

struct gipt {
	list_node_t	gipt_node;
	uint64_t	gipt_vaddr;
	uint64_t	gipt_pfn;
	uint16_t	gipt_level;
	uint16_t	gipt_valid_cnt;
	uint32_t	_gipt_pad;
	struct gipt	*gipt_parent;
	uint64_t	*gipt_kva;
	uint64_t	_gipt_pad2;
};
typedef struct gipt gipt_t;

typedef enum {
	PTET_EMPTY	= 0,
	PTET_PAGE	= 1,
	PTET_LINK	= 2,
} gipt_pte_type_t;

/* Given a PTE and its level, determine the type of that PTE */
typedef gipt_pte_type_t (*gipt_pte_type_cb_t)(uint64_t, uint_t);
/* Given the PFN of a child table, emit a PTE that references it */
typedef uint64_t (*gipt_pte_map_cb_t)(uint64_t);

struct gipt_cbs {
	gipt_pte_type_cb_t	giptc_pte_type;
	gipt_pte_map_cb_t	giptc_pte_map;
};

struct gipt_map {
	kmutex_t	giptm_lock;
	gipt_t		*giptm_root;
	list_t		*giptm_hash;
	struct gipt_cbs	giptm_cbs;
	size_t		giptm_table_cnt;
	uint_t		giptm_levels;
};
typedef struct gipt_map gipt_map_t;

#define	GIPT_HASH_SIZE_DEFAULT	0x2000
#define	GIPT_MAX_LEVELS	4

#define	GIPT_VA2IDX(pt, va)			\
	(((va) - (pt)->gipt_vaddr) >>		\
	gipt_level_shift[(pt)->gipt_level])

#define	GIPT_VA2PTE(pt, va)	((pt)->gipt_kva[GIPT_VA2IDX(pt, va)])
#define	GIPT_VA2PTEP(pt, va)	(&(pt)->gipt_kva[GIPT_VA2IDX(pt, va)])

extern const uint_t gipt_level_shift[GIPT_MAX_LEVELS+1];
extern const uint64_t gipt_level_mask[GIPT_MAX_LEVELS+1];
extern const uint64_t gipt_level_size[GIPT_MAX_LEVELS+1];
extern const uint64_t gipt_level_count[GIPT_MAX_LEVELS+1];

extern gipt_t *gipt_alloc(void);
extern void gipt_free(gipt_t *);
extern void gipt_map_init(gipt_map_t *, uint_t, uint_t,
    const struct gipt_cbs *, gipt_t *);
extern void gipt_map_fini(gipt_map_t *);
extern gipt_t *gipt_map_lookup(gipt_map_t *, uint64_t, uint_t);
extern gipt_t *gipt_map_lookup_deepest(gipt_map_t *, uint64_t);
extern uint64_t gipt_map_next_page(gipt_map_t *, uint64_t, uint64_t,
    gipt_t **);
extern void gipt_map_insert(gipt_map_t *, gipt_t *);
extern void gipt_map_remove(gipt_map_t *, gipt_t *);
extern gipt_t *gipt_map_create_parents(gipt_map_t *, uint64_t, uint_t);
extern void gipt_map_clean_parents(gipt_map_t *, gipt_t *);

#endif /* _GIPT_H_ */
