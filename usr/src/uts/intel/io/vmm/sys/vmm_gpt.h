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

typedef enum vmm_gpt_query {
	VGQ_ACCESSED,
	VGQ_DIRTY,
} vmm_gpt_query_t;

/*
 * The vmm_pte_ops structure contains function pointers for format-specific
 * operations on page table entries.  The operations are as follows:
 *
 * vpeo_map_table: Creates a PTE that maps an inner node in the page table.
 * vpeo_map_page: Creates a leaf entry PTE that maps a page of physical memory.
 * vpeo_pte_pfn: Returns the PFN contained in the given PTE.
 * vpeo_pte_is_present: Returns true IFF the PTE maps a present page.
 * vpeo_pte_prot: Returns a bitmask of protection bits for the PTE.
 *   The bits correspond to the standard mmap(2) bits: PROT_READ, PROT_WRITE,
 *   PROT_EXEC.
 * vpeo_reset_dirty: Resets the dirty bit on the given PTE.  If the second
 *   argument is `true`, the bit will be set, otherwise it will be cleared.
 *   Returns non-zero if the previous value of the bit was set.
 * vpeo_reset_accessed: Resets the accessed bit on the given PTE.  If the
 *   second argument is `true`, the bit will be set, otherwise it will be
 *   cleared.  Returns non-zero if the previous value of the bit was set.
 * vpeo_get_pmtp: Generate a properly formatted PML4 (EPTP/nCR3), given the root
 *   PFN for the GPT.
 * vpeo_hw_ad_supported: Returns true IFF hardware A/D tracking is supported.
 */
typedef struct vmm_pte_ops vmm_pte_ops_t;
struct vmm_pte_ops {
	uint64_t	(*vpeo_map_table)(pfn_t);
	uint64_t	(*vpeo_map_page)(pfn_t, uint_t, uint8_t);
	pfn_t		(*vpeo_pte_pfn)(uint64_t);
	bool		(*vpeo_pte_is_present)(uint64_t);
	uint_t		(*vpeo_pte_prot)(uint64_t);
	uint_t		(*vpeo_reset_dirty)(uint64_t *, bool);
	uint_t		(*vpeo_reset_accessed)(uint64_t *, bool);
	uint64_t	(*vpeo_get_pmtp)(pfn_t, bool);
	bool		(*vpeo_hw_ad_supported)(void);
	bool		(*vpeo_query)(uint64_t *, vmm_gpt_query_t);
};

extern vmm_pte_ops_t ept_pte_ops;
extern vmm_pte_ops_t rvi_pte_ops;

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

vmm_gpt_t *vmm_gpt_alloc(vmm_pte_ops_t *);
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

bool vmm_gpt_is_mapped(vmm_gpt_t *, vmm_gpt_entry_t *, pfn_t *, uint_t *);
uint_t vmm_gpt_reset_accessed(vmm_gpt_t *, vmm_gpt_entry_t *, bool);
uint_t vmm_gpt_reset_dirty(vmm_gpt_t *, vmm_gpt_entry_t *, bool);
bool vmm_gpt_query(vmm_gpt_t *, vmm_gpt_entry_t *, vmm_gpt_query_t);
bool vmm_gpt_can_track_dirty(vmm_gpt_t *);

#endif /* _VMM_GPT_H */
