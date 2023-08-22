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
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/panic.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/hat_i86.h>

#include <sys/vmm_gpt.h>

/*
 * VMM Generic Page Tables
 *
 * Bhyve runs on AMD and Intel hosts and both support nested page tables
 * describing the guest's physical address space.  But the two use different and
 * mutually incompatible page table formats: Intel uses the EPT, which is based
 * on the Itanium page table format, while AMD uses the nPT, which is based on
 * the x86_64 page table format.
 *
 * The GPT abstracts these format differences, and provides a single interface
 * for interacting with either kind of table structure.
 *
 * At a high-level, the GPT is a tree that mirrors the paging table radix tree.
 * It is parameterized with operations on PTEs that are specific to the table
 * type (EPT or nPT) and also keeps track of how many pages the table maps, as
 * well as a pointer to the root node in the tree.
 *
 * A node in the GPT keep pointers to its parent (NULL for the root), its
 * left-most child, and its siblings.  The node understands its position in the
 * tree in terms of the level it appears at and the index it occupies at its
 * parent's level, as well as how many children it has.  It also owns the
 * physical memory page for the hardware page table entries that map its
 * children.  Thus, for a node at any given level in the tree, the nested PTE
 * for that node's child at index $i$ is the i'th uint64_t in that node's entry
 * page and the entry page is part of the paging structure consumed by hardware.
 *
 * The GPT interface provides functions for populating and vacating the tree for
 * regions in the guest physical address space, and for mapping and unmapping
 * pages in populated regions.  Users must populate a region before mapping
 * pages into it, and must unmap pages before vacating the region.
 *
 * The interface also exposes a function for walking the table from the root to
 * a leaf entry, populating an array of pointers to PTEs.  This walk uses the
 * hardware page structure itself, and is thus fast, though as a result it
 * potentially aliases entries; caveat emptor.  The walk primitive is used for
 * mapping, unmapping, and lookups.
 *
 * Format-specific differences are abstracted by parameterizing the GPT with a
 * set of PTE operations specific to the platform.  The GPT code makes use of
 * these when mapping or populating entries, resetting accessed and dirty bits
 * on entries, and similar operations.
 */

/*
 * A GPT node.
 *
 * Each node contains pointers to its parent, its left-most child, and its
 * siblings.  Interior nodes also maintain a reference count, and each node
 * contains its level and index in its parent's table.  Finally, each node
 * contains the host PFN of the page that it links into the page table, as well
 * as a kernel pointer to table.
 *
 * On leaf nodes, the reference count tracks how many entries in the table are
 * covered by mapping from the containing vmspace.  This is maintained during
 * calls to vmm_populate_region() and vmm_gpt_vacate_region() as part of vmspace
 * map/unmap operations, rather than in the data path of faults populating the
 * PTEs themselves.
 *
 * Note, this is carefully sized to fit exactly into a 64-byte cache line.
 */
typedef struct vmm_gpt_node vmm_gpt_node_t;
struct vmm_gpt_node {
	uint64_t	vgn_host_pfn;
	uint16_t	vgn_level;
	uint16_t	vgn_index;
	uint32_t	vgn_ref_cnt;
	vmm_gpt_node_t	*vgn_parent;
	vmm_gpt_node_t	*vgn_children;
	vmm_gpt_node_t	*vgn_sib_next;
	vmm_gpt_node_t	*vgn_sib_prev;
	uint64_t	*vgn_entries;
	uint64_t	vgn_gpa;
};

/* Maximum node index determined by number of entries in page table (512) */
#define	PTE_PER_TABLE	512
#define	MAX_NODE_IDX	(PTE_PER_TABLE - 1)

/*
 * A VMM Generic Page Table.
 *
 * The generic page table is a format-agnostic, 4-level paging structure
 * modeling a second-level page table (EPT on Intel, nPT on AMD).  It
 * contains a counter of pages the table maps, a pointer to the root node
 * in the table, and is parameterized with a set of PTE operations specific
 * to the table type.
 */
struct vmm_gpt {
	vmm_gpt_node_t	*vgpt_root;
	vmm_pte_ops_t	*vgpt_pte_ops;
};

/*
 * Allocates a vmm_gpt_node_t structure with corresponding page of memory to
 * hold the PTEs it contains.
 */
static vmm_gpt_node_t *
vmm_gpt_node_alloc(void)
{
	vmm_gpt_node_t *node;
	caddr_t page;

	node = kmem_zalloc(sizeof (*node), KM_SLEEP);
	/*
	 * Note: despite the man page, allocating PAGESIZE bytes is
	 * guaranteed to be page-aligned.
	 */
	page = kmem_zalloc(PAGESIZE, KM_SLEEP);
	node->vgn_entries = (uint64_t *)page;
	node->vgn_host_pfn = hat_getpfnum(kas.a_hat, page);

	return (node);
}

/*
 * Allocates and initializes a vmm_gpt_t.
 */
vmm_gpt_t *
vmm_gpt_alloc(vmm_pte_ops_t *pte_ops)
{
	vmm_gpt_t *gpt;

	VERIFY(pte_ops != NULL);
	gpt = kmem_zalloc(sizeof (*gpt), KM_SLEEP);
	gpt->vgpt_pte_ops = pte_ops;
	gpt->vgpt_root = vmm_gpt_node_alloc();

	return (gpt);
}

/*
 * Frees a given node.  The node is expected to have no familial (parent,
 * children, siblings) associations at this point.  Accordingly, its reference
 * count should be zero.
 */
static void
vmm_gpt_node_free(vmm_gpt_node_t *node)
{
	ASSERT(node != NULL);
	ASSERT3U(node->vgn_ref_cnt, ==, 0);
	ASSERT(node->vgn_host_pfn != PFN_INVALID);
	ASSERT(node->vgn_entries != NULL);
	ASSERT(node->vgn_parent == NULL);

	kmem_free(node->vgn_entries, PAGESIZE);
	kmem_free(node, sizeof (*node));
}

/*
 * Frees a vmm_gpt_t.  Any lingering nodes in the GPT will be freed too.
 */
void
vmm_gpt_free(vmm_gpt_t *gpt)
{
	/* Empty anything remaining in the tree */
	vmm_gpt_vacate_region(gpt, 0, UINT64_MAX & PAGEMASK);

	VERIFY(gpt->vgpt_root != NULL);
	VERIFY3U(gpt->vgpt_root->vgn_ref_cnt, ==, 0);

	vmm_gpt_node_free(gpt->vgpt_root);
	kmem_free(gpt, sizeof (*gpt));
}

/*
 * Given a GPA, return its corresponding index in a paging structure at the
 * provided level.
 */
static inline uint16_t
vmm_gpt_lvl_index(vmm_gpt_node_level_t level, uint64_t gpa)
{
	ASSERT(level < MAX_GPT_LEVEL);

	const uint_t shifts[] = {
		[LEVEL4] = 39,
		[LEVEL3] = 30,
		[LEVEL2] = 21,
		[LEVEL1] = 12,
	};
	const uint16_t mask = (1U << 9) - 1;
	return ((gpa >> shifts[level]) & mask);
}

/* Get mask for addresses of entries at a given table level. */
static inline uint64_t
vmm_gpt_lvl_mask(vmm_gpt_node_level_t level)
{
	ASSERT(level < MAX_GPT_LEVEL);

	const uint64_t gpa_mask[] = {
		[LEVEL4] = 0xffffff8000000000ul, /* entries cover 512G */
		[LEVEL3] = 0xffffffffc0000000ul, /* entries cover 1G */
		[LEVEL2] = 0xffffffffffe00000ul, /* entries cover 2M */
		[LEVEL1] = 0xfffffffffffff000ul, /* entries cover 4K */
	};
	return (gpa_mask[level]);
}

/* Get length of GPA covered by entries at a given table level. */
static inline uint64_t
vmm_gpt_lvl_len(vmm_gpt_node_level_t level)
{
	ASSERT(level < MAX_GPT_LEVEL);

	const uint64_t gpa_len[] = {
		[LEVEL4] = 0x8000000000ul,	/* entries cover 512G */
		[LEVEL3] = 0x40000000ul,	/* entries cover 1G */
		[LEVEL2] = 0x200000ul,		/* entries cover 2M */
		[LEVEL1] = 0x1000ul,		/* entries cover 4K */
	};
	return (gpa_len[level]);
}

/*
 * Get the ending GPA which this node could possibly cover given its base
 * address and level.
 */
static inline uint64_t
vmm_gpt_node_end(vmm_gpt_node_t *node)
{
	ASSERT(node->vgn_level > LEVEL4);
	return (node->vgn_gpa + vmm_gpt_lvl_len(node->vgn_level - 1));
}

/*
 * Is this node the last entry in its parent node, based solely by its GPA?
 */
static inline bool
vmm_gpt_node_is_last(vmm_gpt_node_t *node)
{
	return (node->vgn_index == MAX_NODE_IDX);
}

/*
 * How many table entries (if any) in this node are covered by the range of
 * [start, end).
 */
static uint16_t
vmm_gpt_node_entries_covered(vmm_gpt_node_t *node, uint64_t start, uint64_t end)
{
	const uint64_t node_end = vmm_gpt_node_end(node);

	/* Is this node covered at all by the region? */
	if (start >= node_end || end <= node->vgn_gpa) {
		return (0);
	}

	const uint64_t mask = vmm_gpt_lvl_mask(node->vgn_level);
	const uint64_t covered_start = MAX(node->vgn_gpa, start & mask);
	const uint64_t covered_end = MIN(node_end, end & mask);
	const uint64_t per_entry = vmm_gpt_lvl_len(node->vgn_level);

	return ((covered_end - covered_start) / per_entry);
}

/*
 * Find the next node (by address) in the tree at the same level.
 *
 * Returns NULL if this is the last node in the tree or if `only_seq` was true
 * and there is an address gap between this node and the next.
 */
static vmm_gpt_node_t *
vmm_gpt_node_next(vmm_gpt_node_t *node, bool only_seq)
{
	ASSERT3P(node->vgn_parent, !=, NULL);
	ASSERT3U(node->vgn_level, >, LEVEL4);

	/*
	 * Next node sequentially would be the one at the address starting at
	 * the end of what is covered by this node.
	 */
	const uint64_t gpa_match = vmm_gpt_node_end(node);

	/* Try our next sibling */
	vmm_gpt_node_t *next = node->vgn_sib_next;
	if (next != NULL) {
		if (next->vgn_gpa == gpa_match || !only_seq) {
			return (next);
		}
	} else {
		/*
		 * If the next-sibling pointer is NULL on the node, it can mean
		 * one of two things:
		 *
		 * 1. This entry represents the space leading up to the trailing
		 *    boundary of what this node covers.
		 *
		 * 2. The node is not entirely populated, and there is a gap
		 *    between the last populated entry, and the trailing
		 *    boundary of the node.
		 *
		 * Either way, the proper course of action is to check the first
		 * child of our parent's next sibling.
		 */
		vmm_gpt_node_t *pibling = node->vgn_parent->vgn_sib_next;
		if (pibling != NULL) {
			next = pibling->vgn_children;
			if (next != NULL) {
				if (next->vgn_gpa == gpa_match || !only_seq) {
					return (next);
				}
			}
		}
	}

	return (NULL);
}


/*
 * Finds the child for the given GPA in the given parent node.
 * Returns a pointer to node, or NULL if it is not found.
 */
static vmm_gpt_node_t *
vmm_gpt_node_find_child(vmm_gpt_node_t *parent, uint64_t gpa)
{
	const uint16_t index = vmm_gpt_lvl_index(parent->vgn_level, gpa);
	for (vmm_gpt_node_t *child = parent->vgn_children;
	    child != NULL && child->vgn_index <= index;
	    child = child->vgn_sib_next) {
		if (child->vgn_index == index)
			return (child);
	}

	return (NULL);
}

/*
 * Add a child node to the GPT at a position determined by GPA, parent, and (if
 * present) preceding sibling.
 *
 * If `parent` node contains any children, `prev_sibling` must be populated with
 * a pointer to the node preceding (by GPA) the to-be-added child node.
 */
static void
vmm_gpt_node_add(vmm_gpt_t *gpt, vmm_gpt_node_t *parent,
    vmm_gpt_node_t *child, uint64_t gpa, vmm_gpt_node_t *prev_sibling)
{
	ASSERT3U(parent->vgn_level, <, LEVEL1);
	ASSERT3U(child->vgn_parent, ==, NULL);

	const uint16_t idx = vmm_gpt_lvl_index(parent->vgn_level, gpa);
	child->vgn_index = idx;
	child->vgn_level = parent->vgn_level + 1;
	child->vgn_gpa = gpa & vmm_gpt_lvl_mask(parent->vgn_level);

	/* Establish familial connections */
	child->vgn_parent = parent;
	if (prev_sibling != NULL) {
		ASSERT3U(prev_sibling->vgn_gpa, <, child->vgn_gpa);

		child->vgn_sib_next = prev_sibling->vgn_sib_next;
		if (child->vgn_sib_next != NULL) {
			child->vgn_sib_next->vgn_sib_prev = child;
		}
		child->vgn_sib_prev = prev_sibling;
		prev_sibling->vgn_sib_next = child;
	} else if (parent->vgn_children != NULL) {
		vmm_gpt_node_t *next_sibling = parent->vgn_children;

		ASSERT3U(next_sibling->vgn_gpa, >, child->vgn_gpa);
		ASSERT3U(next_sibling->vgn_sib_prev, ==, NULL);

		child->vgn_sib_next = next_sibling;
		child->vgn_sib_prev = NULL;
		next_sibling->vgn_sib_prev = child;
		parent->vgn_children = child;
	} else {
		parent->vgn_children = child;
		child->vgn_sib_next = NULL;
		child->vgn_sib_prev = NULL;
	}

	/* Configure PTE for child table */
	parent->vgn_entries[idx] =
	    gpt->vgpt_pte_ops->vpeo_map_table(child->vgn_host_pfn);
	parent->vgn_ref_cnt++;
}

/*
 * Remove a child node from its relatives (parent, siblings) and free it.
 */
static void
vmm_gpt_node_remove(vmm_gpt_node_t *child)
{
	ASSERT3P(child->vgn_children, ==, NULL);
	ASSERT3U(child->vgn_ref_cnt, ==, 0);
	ASSERT3P(child->vgn_parent, !=, NULL);

	/* Unlink child from its siblings and parent */
	vmm_gpt_node_t *parent = child->vgn_parent;
	vmm_gpt_node_t *prev = child->vgn_sib_prev;
	vmm_gpt_node_t *next = child->vgn_sib_next;
	if (prev != NULL) {
		ASSERT3P(prev->vgn_sib_next, ==, child);
		prev->vgn_sib_next = next;
	}
	if (next != NULL) {
		ASSERT3P(next->vgn_sib_prev, ==, child);
		next->vgn_sib_prev = prev;
	}
	if (prev == NULL) {
		ASSERT3P(parent->vgn_children, ==, child);
		parent->vgn_children = next;
	}
	child->vgn_parent = NULL;
	child->vgn_sib_next = NULL;
	child->vgn_sib_prev = NULL;
	parent->vgn_entries[child->vgn_index] = 0;
	parent->vgn_ref_cnt--;

	vmm_gpt_node_free(child);
}

/*
 * Walks the GPT for the given GPA, accumulating entries to the given depth.  If
 * the walk terminates before the depth is reached, the remaining entries are
 * written with NULLs.
 */
void
vmm_gpt_walk(vmm_gpt_t *gpt, uint64_t gpa, uint64_t **entries,
    vmm_gpt_node_level_t depth)
{
	uint64_t *current_entries, entry;
	pfn_t pfn;

	ASSERT(gpt != NULL);
	current_entries = gpt->vgpt_root->vgn_entries;
	for (uint_t i = 0; i < depth; i++) {
		if (current_entries == NULL) {
			entries[i] = NULL;
			continue;
		}
		entries[i] = &current_entries[vmm_gpt_lvl_index(i, gpa)];
		entry = *entries[i];
		if (!gpt->vgpt_pte_ops->vpeo_pte_is_present(entry)) {
			current_entries = NULL;
			continue;
		}
		pfn = gpt->vgpt_pte_ops->vpeo_pte_pfn(entry);
		current_entries = (uint64_t *)hat_kpm_pfn2va(pfn);
	}
}

/*
 * Looks up an entry given GPA.
 */
uint64_t *
vmm_gpt_lookup(vmm_gpt_t *gpt, uint64_t gpa)
{
	uint64_t *entries[MAX_GPT_LEVEL];

	vmm_gpt_walk(gpt, gpa, entries, MAX_GPT_LEVEL);

	return (entries[LEVEL1]);
}

/*
 * Populate child table nodes for a given level between the provided interval
 * of [addr, addr + len).  Caller is expected to provide a pointer to the parent
 * node which would contain the child node for GPA at `addr`.  A pointer to said
 * child node will be returned when the operation is complete.
 */
static vmm_gpt_node_t *
vmm_gpt_populate_region_lvl(vmm_gpt_t *gpt, uint64_t addr, uint64_t len,
    vmm_gpt_node_t *node_start)
{
	const vmm_gpt_node_level_t lvl = node_start->vgn_level;
	const uint64_t end = addr + len;
	const uint64_t incr = vmm_gpt_lvl_len(lvl);
	uint64_t gpa = addr & vmm_gpt_lvl_mask(lvl);
	vmm_gpt_node_t *parent = node_start;

	/* Try to locate node at starting address */
	vmm_gpt_node_t *prev = NULL, *node = parent->vgn_children;
	while (node != NULL && node->vgn_gpa < gpa) {
		prev = node;
		node = node->vgn_sib_next;
	}

	/*
	 * If no node exists at the starting address, create one and link it
	 * into the parent.
	 */
	if (node == NULL || node->vgn_gpa > gpa) {
		/* Need to insert node for starting GPA */
		node = vmm_gpt_node_alloc();
		vmm_gpt_node_add(gpt, parent, node, gpa, prev);
	}

	vmm_gpt_node_t *front_node = node;
	prev = node;
	gpa += incr;

	/*
	 * With a node at the starting address, walk forward creating nodes in
	 * any of the gaps.
	 */
	for (; gpa < end; gpa += incr, prev = node) {
		node = vmm_gpt_node_next(prev, true);
		if (node != NULL) {
			ASSERT3U(node->vgn_gpa, ==, gpa);

			/* We may have crossed into a new parent */
			parent = node->vgn_parent;
			continue;
		}

		if (vmm_gpt_node_is_last(prev)) {
			/*
			 * The node preceding this was the last one in its
			 * containing parent, so move on to that parent's
			 * sibling.  We expect (demand) that it exist already.
			 */
			parent = vmm_gpt_node_next(parent, true);
			ASSERT(parent != NULL);

			/*
			 * Forget our previous sibling, since it is of no use
			 * for assigning the new node to the a now-different
			 * parent.
			 */
			prev = NULL;

		}
		node = vmm_gpt_node_alloc();
		vmm_gpt_node_add(gpt, parent, node, gpa, prev);
	}

	return (front_node);
}

/*
 * Ensures that PTEs for the region of address space bounded by
 * [addr, addr + len) exist in the tree.
 */
void
vmm_gpt_populate_region(vmm_gpt_t *gpt, uint64_t addr, uint64_t len)
{
	ASSERT0(addr & PAGEOFFSET);
	ASSERT0(len & PAGEOFFSET);

	/*
	 * Starting at the top of the tree, ensure that tables covering the
	 * requested region exist at each level.
	 */
	vmm_gpt_node_t *node = gpt->vgpt_root;
	for (uint_t lvl = LEVEL4; lvl < LEVEL1; lvl++) {
		ASSERT3U(node->vgn_level, ==, lvl);

		node = vmm_gpt_populate_region_lvl(gpt, addr, len, node);
	}


	/*
	 * Establish reference counts for the soon-to-be memory PTEs which will
	 * be filling these LEVEL1 tables.
	 */
	uint64_t gpa = addr;
	const uint64_t end = addr + len;
	while (gpa < end) {
		ASSERT(node != NULL);
		ASSERT3U(node->vgn_level, ==, LEVEL1);

		const uint16_t covered =
		    vmm_gpt_node_entries_covered(node, addr, end);

		ASSERT(covered != 0);
		ASSERT3U(node->vgn_ref_cnt, <, PTE_PER_TABLE);
		ASSERT3U(node->vgn_ref_cnt + covered, <=, PTE_PER_TABLE);

		node->vgn_ref_cnt += covered;

		vmm_gpt_node_t *next = vmm_gpt_node_next(node, true);
		if (next != NULL) {
			gpa = next->vgn_gpa;
			node = next;
		} else {
			/*
			 * We do not expect to find a subsequent node after
			 * filling the last node in the table, completing PTE
			 * accounting for the specified range.
			 */
			VERIFY3U(end, <=, vmm_gpt_node_end(node));
			break;
		}
	}
}

/*
 * Format a PTE and install it in the provided PTE-pointer.
 */
bool
vmm_gpt_map_at(vmm_gpt_t *gpt, uint64_t *ptep, pfn_t pfn, uint_t prot,
    uint8_t attr)
{
	uint64_t entry, old_entry;

	entry = gpt->vgpt_pte_ops->vpeo_map_page(pfn, prot, attr);
	old_entry = atomic_cas_64(ptep, 0, entry);
	if (old_entry != 0) {
		ASSERT3U(gpt->vgpt_pte_ops->vpeo_pte_pfn(entry), ==,
		    gpt->vgpt_pte_ops->vpeo_pte_pfn(old_entry));
		return (false);
	}

	return (true);
}

/*
 * Inserts an entry for a given GPA into the table.  The caller must
 * ensure that a conflicting PFN is not mapped at the requested location.
 * Racing operations to map the same PFN at one location is acceptable and
 * properly handled.
 */
bool
vmm_gpt_map(vmm_gpt_t *gpt, uint64_t gpa, pfn_t pfn, uint_t prot, uint8_t attr)
{
	uint64_t *entries[MAX_GPT_LEVEL];

	ASSERT(gpt != NULL);
	vmm_gpt_walk(gpt, gpa, entries, MAX_GPT_LEVEL);
	ASSERT(entries[LEVEL1] != NULL);

	return (vmm_gpt_map_at(gpt, entries[LEVEL1], pfn, prot, attr));
}

/*
 * Cleans up the unused inner nodes in the GPT for a region of guest physical
 * address space of [addr, addr + len).  The region must map no pages.
 */
void
vmm_gpt_vacate_region(vmm_gpt_t *gpt, uint64_t addr, uint64_t len)
{
	ASSERT0(addr & PAGEOFFSET);
	ASSERT0(len & PAGEOFFSET);

	const uint64_t end = addr + len;
	vmm_gpt_node_t *node, *starts[MAX_GPT_LEVEL] = {
		[LEVEL4] = gpt->vgpt_root,
	};

	for (vmm_gpt_node_level_t lvl = LEVEL4; lvl < LEVEL1; lvl++) {
		node = vmm_gpt_node_find_child(starts[lvl], addr);
		if (node == NULL) {
			break;
		}
		starts[lvl + 1] = node;
	}

	/*
	 * Starting at the bottom of the tree, ensure that PTEs for pages have
	 * been cleared for the region, and remove the corresponding reference
	 * counts from the containing LEVEL1 tables.
	 */
	uint64_t gpa = addr;
	node = starts[LEVEL1];
	while (gpa < end && node != NULL) {
		const uint16_t covered =
		    vmm_gpt_node_entries_covered(node, addr, end);

		ASSERT3U(node->vgn_ref_cnt, >=, covered);
		node->vgn_ref_cnt -= covered;

		node = vmm_gpt_node_next(node, false);
		if (node != NULL) {
			gpa = node->vgn_gpa;
		}
	}

	/*
	 * With the page PTE references eliminated, work up from the bottom of
	 * the table, removing nodes which have no remaining references.
	 *
	 * This stops short of LEVEL4, which is the root table of the GPT.  It
	 * is left standing to be cleaned up when the vmm_gpt_t is destroyed.
	 */
	for (vmm_gpt_node_level_t lvl = LEVEL1; lvl > LEVEL4; lvl--) {
		gpa = addr;
		node = starts[lvl];

		while (gpa < end && node != NULL) {
			vmm_gpt_node_t *next = vmm_gpt_node_next(node, false);

			if (node->vgn_ref_cnt == 0) {
				vmm_gpt_node_remove(node);
			}
			if (next != NULL) {
				gpa = next->vgn_gpa;
			}
			node = next;
		}
	}
}

/*
 * Remove a mapping from the table.  Returns false if the page was not mapped,
 * otherwise returns true.
 */
bool
vmm_gpt_unmap(vmm_gpt_t *gpt, uint64_t gpa)
{
	uint64_t *entries[MAX_GPT_LEVEL], entry;

	ASSERT(gpt != NULL);
	vmm_gpt_walk(gpt, gpa, entries, MAX_GPT_LEVEL);
	if (entries[LEVEL1] == NULL)
		return (false);

	entry = *entries[LEVEL1];
	*entries[LEVEL1] = 0;
	return (gpt->vgpt_pte_ops->vpeo_pte_is_present(entry));
}

/*
 * Un-maps the region of guest physical address space bounded by [start..end).
 * Returns the number of pages that are unmapped.
 */
size_t
vmm_gpt_unmap_region(vmm_gpt_t *gpt, uint64_t addr, uint64_t len)
{
	ASSERT0(addr & PAGEOFFSET);
	ASSERT0(len & PAGEOFFSET);

	const uint64_t end = addr + len;
	size_t num_unmapped = 0;
	for (uint64_t gpa = addr; gpa < end; gpa += PAGESIZE) {
		if (vmm_gpt_unmap(gpt, gpa) != 0) {
			num_unmapped++;
		}
	}

	return (num_unmapped);
}

/*
 * Returns a value indicating whether or not this GPT maps the given
 * GPA.  If the GPA is mapped, *protp will be filled with the protection
 * bits of the entry.  Otherwise, it will be ignored.
 */
bool
vmm_gpt_is_mapped(vmm_gpt_t *gpt, uint64_t *ptep, pfn_t *pfnp, uint_t *protp)
{
	uint64_t entry;

	if (ptep == NULL) {
		return (false);
	}
	entry = *ptep;
	if (!gpt->vgpt_pte_ops->vpeo_pte_is_present(entry)) {
		return (false);
	}
	*pfnp = gpt->vgpt_pte_ops->vpeo_pte_pfn(entry);
	*protp = gpt->vgpt_pte_ops->vpeo_pte_prot(entry);
	return (true);
}

/*
 * Resets the accessed bit on the page table entry pointed to be `entry`.
 * If `on` is true, the bit will be set, otherwise it will be cleared.
 * The old value of the bit is returned.
 */
uint_t
vmm_gpt_reset_accessed(vmm_gpt_t *gpt, uint64_t *entry, bool on)
{
	ASSERT(entry != NULL);
	return (gpt->vgpt_pte_ops->vpeo_reset_accessed(entry, on));
}

/*
 * Resets the dirty bit on the page table entry pointed to be `entry`.
 * If `on` is true, the bit will be set, otherwise it will be cleared.
 * The old value of the bit is returned.
 */
uint_t
vmm_gpt_reset_dirty(vmm_gpt_t *gpt, uint64_t *entry, bool on)
{
	ASSERT(entry != NULL);
	return (gpt->vgpt_pte_ops->vpeo_reset_dirty(entry, on));
}

/*
 * Get properly formatted PML4 (EPTP/nCR3) for GPT.
 */
uint64_t
vmm_gpt_get_pmtp(vmm_gpt_t *gpt, bool track_dirty)
{
	const pfn_t root_pfn = gpt->vgpt_root->vgn_host_pfn;
	return (gpt->vgpt_pte_ops->vpeo_get_pmtp(root_pfn, track_dirty));
}
