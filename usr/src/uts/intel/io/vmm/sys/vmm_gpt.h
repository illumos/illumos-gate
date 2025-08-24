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
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _VMM_GPT_H
#define	_VMM_GPT_H

#include <sys/types.h>

/*
 * Constants for the nodes in the GPT radix tree.  Note
 * that, in accordance with hardware page table descriptions,
 * the root of the tree is referred to as "LEVEL4" while the
 * leaf level is "LEVEL1".
 */
typedef enum vmm_gpt_node_level {
	LEVEL4 = 0,
	LEVEL3,
	LEVEL2,
	LEVEL1,
	MAX_GPT_LEVEL,
} vmm_gpt_node_level_t;

struct vmm_gpt;
typedef struct vmm_gpt vmm_gpt_t;

/* PTEs get a defined type to distinguish them from other uint64_t variables */
typedef uint64_t vmm_gpt_entry_t;

typedef struct vmm_gpt_iter {
	vmm_gpt_t *vgi_gpt;
	uint64_t vgi_addr;
	uint64_t vgi_end;
	uint64_t vgi_current;
	vmm_gpt_entry_t *vgi_entries[MAX_GPT_LEVEL];
} vmm_gpt_iter_t;

typedef struct vmm_gpt_iter_entry {
	uint64_t vgie_gpa;
	vmm_gpt_entry_t *vgie_ptep;
} vmm_gpt_iter_entry_t;

struct vmm_pte_impl;
bool vmm_gpt_init(const struct vmm_pte_impl *);
void vmm_gpt_fini(void);

vmm_gpt_t *vmm_gpt_alloc(void);
void vmm_gpt_free(vmm_gpt_t *);

uint64_t vmm_gpt_walk(vmm_gpt_t *, uint64_t, vmm_gpt_entry_t **,
    vmm_gpt_node_level_t);
void vmm_gpt_iter_init(vmm_gpt_iter_t *, vmm_gpt_t *, uint64_t, uint64_t);
bool vmm_gpt_iter_next(vmm_gpt_iter_t *, vmm_gpt_iter_entry_t *);
void vmm_gpt_populate_region(vmm_gpt_t *, uint64_t, uint64_t);
bool vmm_gpt_map_at(vmm_gpt_t *, vmm_gpt_entry_t *, pfn_t, uint_t, uint8_t);
void vmm_gpt_vacate_region(vmm_gpt_t *, uint64_t, uint64_t);
bool vmm_gpt_unmap(vmm_gpt_t *, uint64_t);
size_t vmm_gpt_unmap_region(vmm_gpt_t *, uint64_t, uint64_t);
uint64_t vmm_gpt_get_pmtp(vmm_gpt_t *, bool);

bool vmm_gpte_is_mapped(const vmm_gpt_entry_t *, pfn_t *, uint_t *);
bool vmm_gpte_reset_accessed(vmm_gpt_entry_t *, bool);
bool vmm_gpte_reset_dirty(vmm_gpt_entry_t *, bool);
bool vmm_gpte_query_accessed(const vmm_gpt_entry_t *);
bool vmm_gpte_query_dirty(const vmm_gpt_entry_t *);

bool vmm_gpt_can_track_dirty(vmm_gpt_t *);

#endif /* _VMM_GPT_H */
