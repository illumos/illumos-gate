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
 * Copyright 2021 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/malloc.h>
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
 * left-most child, and its rightward siblings.  The node understands its
 * position in the tree in terms of its level it appears at and the index it
 * occupies at its parent's level, as well as how many children it has.  It also
 * owns the physical memory page for the hardware page table entries that map
 * its children.  Thus, for a node at any given level in the tree, the nested
 * PTE for that node's child at index $i$ is the i'th uint64_t in that node's
 * entry page and the entry page is part of the paging structure consumed by
 * hardware.
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
 * rightward siblings.  Interior nodes also maintain a reference count, and
 * each node contains its level and index in its parent's table.  Finally,
 * each node contains the host PFN of the page that it links into the page
 * table, as well as a kernel pointer to table.
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
	vmm_gpt_node_t	*vgn_siblings;
	uint64_t	*vgn_entries;
	uint64_t	_vgn_pad[2];
};

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
	uint64_t	vgpt_mapped_page_count;
};

/*
 * VMM Guest Page Tables
 */

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
 * Retrieves the host kernel address of the GPT root.
 */
void *
vmm_gpt_root_kaddr(vmm_gpt_t *gpt)
{
	return (gpt->vgpt_root->vgn_entries);
}

/*
 * Retrieves the host PFN of the GPT root.
 */
uint64_t
vmm_gpt_root_pfn(vmm_gpt_t *gpt)
{
	return (gpt->vgpt_root->vgn_host_pfn);
}

/*
 * Frees the given node, first nulling out all of its links to other nodes in
 * the tree, adjusting its parents reference count, and unlinking itself from
 * its parents page table.
 */
static void
vmm_gpt_node_free(vmm_gpt_node_t *node)
{
	ASSERT(node != NULL);
	ASSERT3U(node->vgn_ref_cnt, ==, 0);
	ASSERT(node->vgn_host_pfn != PFN_INVALID);
	ASSERT(node->vgn_entries != NULL);
	if (node->vgn_parent != NULL) {
		uint64_t *parent_entries = node->vgn_parent->vgn_entries;
		parent_entries[node->vgn_index] = 0;
		node->vgn_parent->vgn_ref_cnt--;
	}
	kmem_free(node->vgn_entries, PAGESIZE);
	kmem_free(node, sizeof (*node));
}

/*
 * Frees the portion of the radix tree rooted at the given node.
 */
static void
vmm_gpt_node_tree_free(vmm_gpt_node_t *node)
{
	ASSERT(node != NULL);

	for (vmm_gpt_node_t *child = node->vgn_children, *next = NULL;
	    child != NULL;
	    child = next) {
		next = child->vgn_siblings;
		vmm_gpt_node_tree_free(child);
	}
	vmm_gpt_node_free(node);
}

/*
 * Cleans up a vmm_gpt_t by removing any lingering vmm_gpt_node_t entries
 * it refers to.
 */
void
vmm_gpt_free(vmm_gpt_t *gpt)
{
	vmm_gpt_node_tree_free(gpt->vgpt_root);
	kmem_free(gpt, sizeof (*gpt));
}

/*
 * Return the index in the paging structure for the given level.
 */
static inline uint16_t
vmm_gpt_node_index(uint64_t gpa, enum vmm_gpt_node_level level)
{
	const int SHIFTS[MAX_GPT_LEVEL] = { 39, 30, 21, 12 };
	const uint_t MASK = (1U << 9) - 1;
	ASSERT(level < MAX_GPT_LEVEL);
	return ((gpa >> SHIFTS[level]) & MASK);
}

/*
 * Finds the child for the given GPA in the given parent node.
 * Returns a pointer to node, or NULL if it is not found.
 */
static vmm_gpt_node_t *
vmm_gpt_node_find_child(vmm_gpt_node_t *parent, uint64_t gpa)
{
	if (parent == NULL)
		return (NULL);

	const uint16_t index = vmm_gpt_node_index(gpa, parent->vgn_level);
	for (vmm_gpt_node_t *child = parent->vgn_children;
	    child != NULL && child->vgn_index <= index;
	    child = child->vgn_siblings) {
		if (child->vgn_index == index)
			return (child);
	}

	return (NULL);
}

/*
 * Walks the GPT for the given GPA, accumulating entries to the given depth.  If
 * the walk terminates before the depth is reached, the remaining entries are
 * written with NULLs.
 */
void
vmm_gpt_walk(vmm_gpt_t *gpt, uint64_t gpa, uint64_t **entries,
    enum vmm_gpt_node_level depth)
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
		entries[i] = &current_entries[vmm_gpt_node_index(gpa, i)];
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
 * Adds a node for the given GPA to the GPT as a child of the given parent.
 */
static void
vmm_gpt_add_child(vmm_gpt_t *gpt, vmm_gpt_node_t *parent, vmm_gpt_node_t *child,
    uint64_t gpa)
{
	vmm_gpt_node_t **prevp;
	vmm_gpt_node_t *node;
	uint64_t *parent_entries, entry;

	ASSERT(gpt != NULL);
	ASSERT(gpt->vgpt_pte_ops != NULL);
	ASSERT(parent != NULL);
	ASSERT(child != NULL);

	const int index = vmm_gpt_node_index(gpa, parent->vgn_level);
	child->vgn_index = index;
	child->vgn_level = parent->vgn_level + 1;
	child->vgn_parent = parent;
	parent_entries = parent->vgn_entries;
	entry = gpt->vgpt_pte_ops->vpeo_map_table(child->vgn_host_pfn);
	parent_entries[index] = entry;

	for (prevp = &parent->vgn_children, node = parent->vgn_children;
	    node != NULL;
	    prevp = &node->vgn_siblings, node = node->vgn_siblings) {
		if (node->vgn_index > child->vgn_index) {
			break;
		}
	}
	if (node != NULL)
		ASSERT3U(node->vgn_index, !=, child->vgn_index);
	child->vgn_siblings = node;
	*prevp = child;
	parent->vgn_ref_cnt++;
}

/*
 * Populate the GPT with nodes so that a entries for the given GPA exist.  Note
 * that this does not actually map the entry, but simply ensures that the
 * entries exist.
 */
void
vmm_gpt_populate_entry(vmm_gpt_t *gpt, uint64_t gpa)
{
	vmm_gpt_node_t *node, *child;

	ASSERT(gpt != NULL);
	node = gpt->vgpt_root;
	for (uint_t i = 0; i < LEVEL1; i++) {
		ASSERT(node != NULL);
		child = vmm_gpt_node_find_child(node, gpa);
		if (child == NULL) {
			child = vmm_gpt_node_alloc();
			ASSERT(child != NULL);
			vmm_gpt_add_child(gpt, node, child, gpa);
		}
		node = child;
	}
}

/*
 * Ensures that PTEs for the region of address space bounded by
 * [start, end) exist in the tree.
 */
void
vmm_gpt_populate_region(vmm_gpt_t *gpt, uint64_t start, uint64_t end)
{
	for (uint64_t page = start; page < end; page += PAGESIZE) {
		vmm_gpt_populate_entry(gpt, page);
	}
}

/*
 * Inserts an entry for a given GPA into the table.  The caller must
 * ensure that the entry is not currently mapped, though note that this
 * can race with another thread inserting the same page into the tree.
 * If we lose the race, we ensure that the page we thought we were
 * inserting is the page that was inserted.
 */
bool
vmm_gpt_map(vmm_gpt_t *gpt, uint64_t gpa, pfn_t pfn, uint_t prot, uint8_t attr)
{
	uint64_t *entries[MAX_GPT_LEVEL], entry, old_entry;

	ASSERT(gpt != NULL);
	vmm_gpt_walk(gpt, gpa, entries, MAX_GPT_LEVEL);
	ASSERT(entries[LEVEL1] != NULL);

	entry = gpt->vgpt_pte_ops->vpeo_map_page(pfn, prot, attr);
	old_entry = atomic_cas_64(entries[LEVEL1], 0, entry);
	if (old_entry != 0) {
		ASSERT3U(gpt->vgpt_pte_ops->vpeo_pte_pfn(entry),
		    ==,
		    gpt->vgpt_pte_ops->vpeo_pte_pfn(old_entry));
		return (false);
	}
	gpt->vgpt_mapped_page_count++;

	return (true);
}

/*
 * Removes a child node from its parent's list of children, and then frees
 * the now-orphaned child.
 */
static void
vmm_gpt_node_remove_child(vmm_gpt_node_t *parent, vmm_gpt_node_t *child)
{
	ASSERT(parent != NULL);

	ASSERT3P(child->vgn_children, ==, NULL);
	vmm_gpt_node_t **prevp = &parent->vgn_children;
	for (vmm_gpt_node_t *node = parent->vgn_children;
	    node != NULL;
	    prevp = &node->vgn_siblings, node = node->vgn_siblings) {
		if (node == child) {
			*prevp = node->vgn_siblings;
			vmm_gpt_node_free(node);
			break;
		}
	}
}

/*
 * Cleans up unused inner nodes in the GPT.  Asserts that the
 * leaf corresponding to the entry does not map any additional
 * pages.
 */
static void
vmm_gpt_vacate_entry(vmm_gpt_t *gpt, uint64_t gpa)
{
	vmm_gpt_node_t *nodes[MAX_GPT_LEVEL], *node;

	node = gpt->vgpt_root;
	for (uint_t i = 0; i < MAX_GPT_LEVEL; i++) {
		nodes[i] = node;
		node = vmm_gpt_node_find_child(node, gpa);
	}
	if (nodes[LEVEL1] != NULL) {
		uint64_t *ptes = nodes[LEVEL1]->vgn_entries;
		for (uint_t i = 0; i < (PAGESIZE / sizeof (uint64_t)); i++)
			ASSERT3U(ptes[i], ==, 0);
	}
	for (uint_t i = LEVEL1; i > 0; i--) {
		if (nodes[i] == NULL)
			continue;
		if (nodes[i]->vgn_ref_cnt != 0)
			break;
		vmm_gpt_node_remove_child(nodes[i - 1], nodes[i]);
	}
}

/*
 * Cleans up the unused inner nodes in the GPT for a region of guest
 * physical address space bounded by [start..end).  The region must
 * map no pages.
 */
void
vmm_gpt_vacate_region(vmm_gpt_t *gpt, uint64_t start, uint64_t end)
{
	for (uint64_t page = start; page < end; page += PAGESIZE) {
		vmm_gpt_vacate_entry(gpt, page);
	}
}

/*
 * Remove a mapping from the table.  Returns false if the page was not
 * mapped, otherwise returns true.
 */
bool
vmm_gpt_unmap(vmm_gpt_t *gpt, uint64_t gpa)
{
	uint64_t *entries[MAX_GPT_LEVEL], entry;
	bool was_mapped;

	ASSERT(gpt != NULL);
	vmm_gpt_walk(gpt, gpa, entries, MAX_GPT_LEVEL);
	if (entries[LEVEL1] == NULL)
		return (false);

	entry = *entries[LEVEL1];
	*entries[LEVEL1] = 0;
	was_mapped = gpt->vgpt_pte_ops->vpeo_pte_is_present(entry);
	if (was_mapped)
		gpt->vgpt_mapped_page_count--;

	return (was_mapped);
}

/*
 * Un-maps the region of guest physical address space bounded by
 * [start..end).  Returns the number of pages that are unmapped.
 */
size_t
vmm_gpt_unmap_region(vmm_gpt_t *gpt, uint64_t start, uint64_t end)
{
	size_t n = 0;

	for (uint64_t page = start; page < end; page += PAGESIZE) {
		if (vmm_gpt_unmap(gpt, page) != 0)
			n++;
	}

	return (n);
}

/*
 * Returns a value indicating whether or not this GPT maps the given
 * GPA.  If the GPA is mapped, *protp will be filled with the protection
 * bits of the entry.  Otherwise, it will be ignored.
 */
bool
vmm_gpt_is_mapped(vmm_gpt_t *gpt, uint64_t gpa, uint_t *protp)
{
	uint64_t *entries[MAX_GPT_LEVEL], entry;

	vmm_gpt_walk(gpt, gpa, entries, MAX_GPT_LEVEL);
	if (entries[LEVEL1] == NULL)
		return (false);
	entry = *entries[LEVEL1];
	if (!gpt->vgpt_pte_ops->vpeo_pte_is_present(entry))
		return (false);
	*protp = gpt->vgpt_pte_ops->vpeo_pte_prot(entry);

	return (true);
}

/*
 * Returns the number of pages that are mapped in by this GPT.
 */
size_t
vmm_gpt_mapped_count(vmm_gpt_t *gpt)
{
	return (gpt->vgpt_mapped_page_count);
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
