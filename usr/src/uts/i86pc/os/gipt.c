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

#include <sys/gipt.h>
#include <sys/malloc.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/panic.h>
#include <vm/hat.h>
#include <vm/as.h>

/*
 * Generic Indexed Page Table
 *
 * There are several applications, such as hardware virtualization or IOMMU
 * control, which require construction of a page table tree to represent a
 * virtual address space.  Many features of the existing htable system would be
 * convenient for this, but its tight coupling to the VM system make it
 * undesirable for independent consumers.  The GIPT interface exists to provide
 * page table allocation and indexing on top of which a table hierarchy
 * (EPT, VT-d, etc) can be built by upstack logic.
 *
 * Types:
 *
 * gipt_t - Represents a single page table with a physical backing page and
 *     associated metadata.
 * gipt_map_t - The workhorse of this facility, it contains an hash table to
 *     index all of the gipt_t entries which make up the page table tree.
 * struct gipt_cbs - Callbacks used by the gipt_map_t:
 *     gipt_pte_type_cb_t - Given a PTE, emit the type (empty/page/table)
 *     gipt_pte_map_cb_t - Given a PFN, emit a (child) table mapping
 */

/*
 * For now, the level shifts are hard-coded to match with standard 4-level
 * 64-bit paging structures.
 */

#define	GIPT_HASH(map, va, lvl)			\
	((((va) >> 12) + ((va) >> 28) + (lvl)) & ((map)->giptm_table_cnt - 1))

const uint_t gipt_level_shift[GIPT_MAX_LEVELS+1] = {
	12,	/* 4K */
	21,	/* 2M */
	30,	/* 1G */
	39,	/* 512G */
	48	/* MAX */
};
const uint64_t gipt_level_mask[GIPT_MAX_LEVELS+1] = {
	0xfffffffffffff000ull,	/* 4K */
	0xffffffffffe00000ull,	/* 2M */
	0xffffffffc0000000ull,	/* 1G */
	0xffffff8000000000ull,	/* 512G */
	0xffff000000000000ull	/* MAX */
};
const uint64_t gipt_level_size[GIPT_MAX_LEVELS+1] = {
	0x0000000000001000ull,	/* 4K */
	0x0000000000200000ull,	/* 2M */
	0x0000000040000000ull,	/* 1G */
	0x0000008000000000ull,	/* 512G */
	0x0001000000000000ull	/* MAX */
};
const uint64_t gipt_level_count[GIPT_MAX_LEVELS+1] = {
	0x0000000000000001ull,	/* 4K */
	0x0000000000000200ull,	/* 2M */
	0x0000000000040000ull,	/* 1G */
	0x0000000008000000ull,	/* 512G */
	0x0000001000000000ull	/* MAX */
};

/*
 * Allocate a gipt_t structure with corresponding page of memory to hold the
 * PTEs which it contains.
 */
gipt_t *
gipt_alloc(void)
{
	gipt_t *pt;
	void *page;

	pt = kmem_zalloc(sizeof (*pt), KM_SLEEP);
	page = kmem_zalloc(PAGESIZE, KM_SLEEP);
	pt->gipt_kva = page;
	pt->gipt_pfn = hat_getpfnum(kas.a_hat, page);

	return (pt);
}

/*
 * Free a gipt_t structure along with its page of PTE storage.
 */
void
gipt_free(gipt_t *pt)
{
	void *page = pt->gipt_kva;

	ASSERT(pt->gipt_pfn != PFN_INVALID);
	ASSERT(pt->gipt_kva != NULL);

	pt->gipt_pfn = PFN_INVALID;
	pt->gipt_kva = NULL;

	kmem_free(page, PAGESIZE);
	kmem_free(pt, sizeof (*pt));
}

/*
 * Initialize a gipt_map_t with a max level (must be >= 1) and allocating its
 * hash table based on a provided size (must be a power of 2).
 */
void
gipt_map_init(gipt_map_t *map, uint_t levels, uint_t hash_table_size,
    const struct gipt_cbs *cbs, gipt_t *root)
{
	VERIFY(map->giptm_root == NULL);
	VERIFY(map->giptm_hash == NULL);
	VERIFY3U(levels, >, 0);
	VERIFY3U(levels, <=, GIPT_MAX_LEVELS);
	VERIFY(ISP2(hash_table_size));
	VERIFY(root != NULL);

	mutex_init(&map->giptm_lock, NULL, MUTEX_DEFAULT, NULL);
	map->giptm_table_cnt = hash_table_size;
	bcopy(cbs, &map->giptm_cbs, sizeof (*cbs));
	map->giptm_hash = kmem_alloc(sizeof (list_t) * map->giptm_table_cnt,
	    KM_SLEEP);
	for (uint_t i = 0; i < hash_table_size; i++) {
		list_create(&map->giptm_hash[i], sizeof (gipt_t),
		    offsetof(gipt_t, gipt_node));
	}
	map->giptm_levels = levels;

	/*
	 * Insert the table root into the hash.  It will be held in existence
	 * with an extra "valid" reference.  This will prevent its clean-up
	 * during gipt_map_clean_parents() calls, even if it has no children.
	 */
	mutex_enter(&map->giptm_lock);
	gipt_map_insert(map, root);
	map->giptm_root = root;
	root->gipt_valid_cnt++;
	mutex_exit(&map->giptm_lock);
}

/*
 * Clean up a gipt_map_t by removing any lingering gipt_t entries referenced by
 * it, and freeing its hash table.
 */
void
gipt_map_fini(gipt_map_t *map)
{
	const uint_t cnt = map->giptm_table_cnt;
	const size_t sz = sizeof (list_t) * cnt;

	mutex_enter(&map->giptm_lock);
	/* Clean up any lingering tables */
	for (uint_t i = 0; i < cnt; i++) {
		list_t *list = &map->giptm_hash[i];
		gipt_t *pt;

		while ((pt = list_remove_head(list)) != NULL) {
			gipt_free(pt);
		}
		ASSERT(list_is_empty(list));
	}

	kmem_free(map->giptm_hash, sz);
	map->giptm_hash = NULL;
	map->giptm_root = NULL;
	map->giptm_levels = 0;
	mutex_exit(&map->giptm_lock);
	mutex_destroy(&map->giptm_lock);
}

/*
 * Look in the map for a gipt_t containing a given VA which is located at a
 * specified level.
 */
gipt_t *
gipt_map_lookup(gipt_map_t *map, uint64_t va, uint_t lvl)
{
	gipt_t *pt;

	ASSERT(MUTEX_HELD(&map->giptm_lock));
	ASSERT3U(lvl, <=, GIPT_MAX_LEVELS);

	/*
	 * Lookup gipt_t at the VA aligned to the next level up.  For example,
	 * level 0 corresponds to a page table containing 512 PTEs which cover
	 * 4k each, spanning a total 2MB. As such, the base VA of that table
	 * must be aligned to the same 2MB.
	 */
	const uint64_t masked_va = va & gipt_level_mask[lvl + 1];
	const uint_t hash = GIPT_HASH(map, masked_va, lvl);

	/* Only the root is expected to be at the top level. */
	if (lvl == (map->giptm_levels - 1) && map->giptm_root != NULL) {
		pt = map->giptm_root;

		ASSERT3U(pt->gipt_level, ==, lvl);

		/*
		 * It may be so that the VA in question is not covered by the
		 * range of the table root.
		 */
		if (pt->gipt_vaddr != masked_va) {
			return (NULL);
		}

		return (pt);
	}

	list_t *list = &map->giptm_hash[hash];
	for (pt = list_head(list); pt != NULL; pt = list_next(list, pt)) {
		if (pt->gipt_vaddr == masked_va && pt->gipt_level == lvl)
			break;
	}
	return (pt);
}

/*
 * Look in the map for the deepest (lowest level) gipt_t which contains a given
 * VA.  This could still fail if the VA is outside the range of the table root.
 */
gipt_t *
gipt_map_lookup_deepest(gipt_map_t *map, uint64_t va)
{
	gipt_t *pt = NULL;
	uint_t lvl;

	ASSERT(MUTEX_HELD(&map->giptm_lock));

	for (lvl = 0; lvl < map->giptm_levels; lvl++) {
		pt = gipt_map_lookup(map, va, lvl);
		if (pt != NULL) {
			break;
		}
	}
	return (pt);
}

/*
 * Given a VA inside a gipt_t, calculate (based on the level of that PT) the VA
 * corresponding to the next entry in the table.  It returns 0 if that VA would
 * fall beyond the bounds of the table.
 */
static __inline__ uint64_t
gipt_next_va(gipt_t *pt, uint64_t va)
{
	const uint_t lvl = pt->gipt_level;
	const uint64_t masked = va & gipt_level_mask[lvl];
	const uint64_t max = pt->gipt_vaddr + gipt_level_size[lvl+1];
	const uint64_t next = masked + gipt_level_size[lvl];

	ASSERT3U(masked, >=, pt->gipt_vaddr);
	ASSERT3U(masked, <, max);

	/*
	 * If the "next" VA would be outside this table, including cases where
	 * it overflowed, indicate an error result.
	 */
	if (next >= max || next <= masked) {
		return (0);
	}
	return (next);
}

/*
 * For a given VA, find the next VA which corresponds to a valid page mapping.
 * The gipt_t containing that VA will be indicated via 'ptp'.  (The gipt_t of
 * the starting VA can be passed in via 'ptp' for a minor optimization).  If
 * there is no valid mapping higher than 'va' but contained within 'max_va',
 * then this will indicate failure with 0 returned.
 */
uint64_t
gipt_map_next_page(gipt_map_t *map, uint64_t va, uint64_t max_va, gipt_t **ptp)
{
	gipt_t *pt = *ptp;
	uint64_t cur_va = va;
	gipt_pte_type_cb_t pte_type = map->giptm_cbs.giptc_pte_type;

	ASSERT(MUTEX_HELD(&map->giptm_lock));
	ASSERT3U(max_va, !=, 0);
	ASSERT3U(ptp, !=, NULL);

	/*
	 * If a starting table is not provided, search the map for the deepest
	 * table which contains the VA.  If for some reason that VA is beyond
	 * coverage of the map root, indicate failure.
	 */
	if (pt == NULL) {
		pt = gipt_map_lookup_deepest(map, cur_va);
		if (pt == NULL) {
			goto fail;
		}
	}

	/*
	 * From the starting table (at whatever level that may reside), walk
	 * forward through the PTEs looking for a valid page mapping.
	 */
	while (cur_va < max_va) {
		const uint64_t next_va = gipt_next_va(pt, cur_va);
		if (next_va == 0) {
			/*
			 * The end of this table has been reached.  Ascend one
			 * level to continue the walk if possible.  If already
			 * at the root, the end of the table means failure.
			 */
			if (pt->gipt_level >= map->giptm_levels) {
				goto fail;
			}
			pt = gipt_map_lookup(map, cur_va, pt->gipt_level + 1);
			if (pt == NULL) {
				goto fail;
			}
			continue;
		} else if (next_va >= max_va) {
			/*
			 * Terminate the walk with a failure if the VA
			 * corresponding to the next PTE is beyond the max.
			 */
			goto fail;
		}
		cur_va = next_va;

		const uint64_t pte = GIPT_VA2PTE(pt, cur_va);
		const gipt_pte_type_t ptet = pte_type(pte, pt->gipt_level);
		if (ptet == PTET_EMPTY) {
			continue;
		} else if (ptet == PTET_PAGE) {
			/* A valid page mapping: success. */
			*ptp = pt;
			return (cur_va);
		} else if (ptet == PTET_LINK) {
			/*
			 * A child page table is present at this PTE.  Look it
			 * up from the map.
			 */
			ASSERT3U(pt->gipt_level, >, 0);
			pt = gipt_map_lookup(map, cur_va, pt->gipt_level - 1);
			ASSERT3P(pt, !=, NULL);
			break;
		} else {
			panic("unexpected PTE type %x @ va %p", ptet, cur_va);
		}
	}

	/*
	 * By this point, the above loop has located a table structure to
	 * descend into in order to find the next page.
	 */
	while (cur_va < max_va) {
		const uint64_t pte = GIPT_VA2PTE(pt, cur_va);
		const gipt_pte_type_t ptet = pte_type(pte, pt->gipt_level);

		if (ptet == PTET_EMPTY) {
			const uint64_t next_va = gipt_next_va(pt, cur_va);
			if (next_va == 0 || next_va >= max_va) {
				goto fail;
			}
			cur_va = next_va;
			continue;
		} else if (ptet == PTET_PAGE) {
			/* A valid page mapping: success. */
			*ptp = pt;
			return (cur_va);
		} else if (ptet == PTET_LINK) {
			/*
			 * A child page table is present at this PTE.  Look it
			 * up from the map.
			 */
			ASSERT3U(pt->gipt_level, >, 0);
			pt = gipt_map_lookup(map, cur_va, pt->gipt_level - 1);
			ASSERT3P(pt, !=, NULL);
		} else {
			panic("unexpected PTE type %x @ va %p", ptet, cur_va);
		}
	}

fail:
	*ptp = NULL;
	return (0);
}

/*
 * Insert a gipt_t into the map based on its VA and level.  It is up to the
 * caller to ensure that a duplicate entry does not already exist in the map.
 */
void
gipt_map_insert(gipt_map_t *map, gipt_t *pt)
{
	const uint_t hash = GIPT_HASH(map, pt->gipt_vaddr, pt->gipt_level);

	ASSERT(MUTEX_HELD(&map->giptm_lock));
	ASSERT(gipt_map_lookup(map, pt->gipt_vaddr, pt->gipt_level) == NULL);
	VERIFY3U(pt->gipt_level, <, map->giptm_levels);

	list_insert_head(&map->giptm_hash[hash], pt);
}

/*
 * Remove a gipt_t from the map.
 */
void
gipt_map_remove(gipt_map_t *map, gipt_t *pt)
{
	const uint_t hash = GIPT_HASH(map, pt->gipt_vaddr, pt->gipt_level);

	ASSERT(MUTEX_HELD(&map->giptm_lock));

	list_remove(&map->giptm_hash[hash], pt);
}

/*
 * Given a VA, create any missing gipt_t entries from the specified level all
 * the way up to (but not including) the root.  This is done from lowest level
 * to highest, and stops when an existing table covering that VA is found.
 * References to any created gipt_t tables, plus the final "found" gipt_t are
 * stored in 'pts'.  The number of gipt_t pointers stored to 'pts' serves as
 * the return value (1 <= val <= root level).  It is up to the caller to
 * populate linking PTEs to the newly created empty tables.
 */
static uint_t
gipt_map_ensure_chain(gipt_map_t *map, uint64_t va, uint_t lvl, gipt_t **pts)
{
	const uint_t root_lvl = map->giptm_root->gipt_level;
	uint_t clvl = lvl, count = 0;
	gipt_t *child_pt = NULL;

	ASSERT(MUTEX_HELD(&map->giptm_lock));
	ASSERT3U(lvl, <, root_lvl);
	ASSERT3P(map->giptm_root, !=, NULL);

	do {
		const uint64_t pva = (va & gipt_level_mask[clvl + 1]);
		gipt_t *pt;

		pt = gipt_map_lookup(map, pva, clvl);
		if (pt != NULL) {
			ASSERT3U(pva, ==, pt->gipt_vaddr);

			if (child_pt != NULL) {
				child_pt->gipt_parent = pt;
			}
			pts[count++] = pt;
			return (count);
		}

		pt = gipt_alloc();
		pt->gipt_vaddr = pva;
		pt->gipt_level = clvl;
		if (child_pt != NULL) {
			child_pt->gipt_parent = pt;
		}

		gipt_map_insert(map, pt);
		child_pt = pt;
		pts[count++] = pt;
		clvl++;
	} while (clvl <= root_lvl);

	return (count);
}

/*
 * Ensure that a page table covering a VA at a specified level exists.  This
 * will create any necessary tables chaining up to the root as well.
 */
gipt_t *
gipt_map_create_parents(gipt_map_t *map, uint64_t va, uint_t lvl)
{
	gipt_t *pt, *pts[GIPT_MAX_LEVELS] = { 0 };
	gipt_pte_type_cb_t pte_type = map->giptm_cbs.giptc_pte_type;
	gipt_pte_map_cb_t pte_map = map->giptm_cbs.giptc_pte_map;
	uint64_t *ptep;
	uint_t i, count;

	ASSERT(MUTEX_HELD(&map->giptm_lock));

	count = gipt_map_ensure_chain(map, va, lvl, pts);
	if (count == 1) {
		/* Table already exists in the hierarchy */
		return (pts[0]);
	}
	ASSERT3U(count, >, 1);

	/* Make sure there is not already a large page mapping at the top */
	pt = pts[count - 1];
	if (pte_type(GIPT_VA2PTE(pt, va), pt->gipt_level) == PTET_PAGE) {
		const uint_t end = count - 1;

		/*
		 * Nuke those gipt_t entries which were optimistically created
		 * for what was found to be a conflicted mapping.
		 */
		for (i = 0; i < end; i++) {
			gipt_map_remove(map, pts[i]);
			gipt_free(pts[i]);
		}
		return (NULL);
	}

	/* Initialize the appropriate tables from bottom to top */
	for (i = 1; i < count; i++) {
		pt = pts[i];
		ptep = GIPT_VA2PTEP(pt, va);

		/*
		 * Since gipt_map_ensure_chain() creates missing tables until
		 * it find a valid one, and that existing table has been
		 * checked for the existence of a large page, nothing should
		 * occupy this PTE.
		 */
		ASSERT3U(pte_type(*ptep, pt->gipt_level), ==, PTET_EMPTY);

		*ptep = pte_map(pts[i - 1]->gipt_pfn);
		pt->gipt_valid_cnt++;
	}

	return (pts[0]);
}

/*
 * If a page table is empty, free it from the map, as well as any parent tables
 * that would subsequently become empty as part of the clean-up.  As noted in
 * gipt_map_init(), the table root is a special case and will remain in the
 * map, even when empty.
 */
void
gipt_map_clean_parents(gipt_map_t *map, gipt_t *pt)
{
	ASSERT(MUTEX_HELD(&map->giptm_lock));

	while (pt->gipt_valid_cnt == 0) {
		gipt_t *parent = pt->gipt_parent;
		uint64_t *ptep = GIPT_VA2PTEP(parent, pt->gipt_vaddr);

		ASSERT3S(map->giptm_cbs.giptc_pte_type(*ptep,
		    parent->gipt_level), ==, PTET_LINK);

		/*
		 * For now, it is assumed that all gipt consumers consider PTE
		 * zeroing as an adequate action for table unmap.
		 */
		*ptep = 0;

		parent->gipt_valid_cnt--;
		gipt_map_remove(map, pt);
		gipt_free(pt);
		pt = parent;
	}
}
