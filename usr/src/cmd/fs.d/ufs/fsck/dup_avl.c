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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Keep track of duplicate fragment references (elsewhere called
 * blocks for ancient historical reasons).
 *
 * The duplicates are kept in a binary tree to attempt to minimize
 * search times when checking the block lists of all active inodes
 * for multiple uses.  This is opposed to using a simple linear list
 * that is traversed for every block, as is used in the traditional
 * fsck.  It can be very time-expensive if there's more than just a
 * very few duplicates, and typically there are either none or lots.
 *
 * For each multiply-claimed fragment, we note all of the claiming
 * inodes and their corresponding logical block numbers.  This allows
 * reporting exactly which parts of which files were damaged, which
 * provides at least a chance of recovering the bulk of the data on
 * a seriously-corrupted filesystem.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/avl.h>
#define	_KERNEL
#include <sys/fs/ufs_fsdir.h>	/* for struct direct */
#undef _KERNEL
#include <sys/debug.h>
#include "fsck.h"

#define	OFFSETOF(type, elt) ((size_t)(&((type *)NULL)->elt))

/*
 * For each physical fragment with multiple claimants, the specifics
 * of each claim are recorded. This means there are N+1 AVL trees in
 * use: one for each fragment's claimant table, plus one that orders
 * the fragments themselves.
 *
 * The table of fragments simply has the physical fragment number
 * (pfn) and has the root of the tree of the associated claimants.  It
 * is keyed by the pfn and called dup_frags.
 *
 * The subsidiary trees list inodes and logical fragment number (lfn)
 * for each claimant.  They are keyed first by inode number and then
 * by lfn.  Both are needed, as it is possible for one inode to have
 * multiple claims on the same fragment.
 */

typedef struct claimant {
	fsck_ino_t cl_inode;
	daddr32_t cl_lfn;
	avl_node_t cl_avl;
} claimant_t;

typedef struct fragment {
	daddr32_t fr_pfn;
	avl_tree_t fr_claimants;
	avl_node_t fr_avl;
} fragment_t;

typedef struct reference {
	daddr32_t ref_lfn;
	daddr32_t ref_pfn;
	avl_node_t ref_avl;
} reference_t;

typedef struct inode_dup {
	fsck_ino_t id_ino;
	avl_tree_t id_fragments;
	avl_node_t id_avl;
} inode_dup_t;

static avl_tree_t dup_frags;

static void free_invert_frags(avl_tree_t *);
static void report_dup_lfn_pfn(daddr32_t, daddr32_t, daddr32_t, daddr32_t);
static inode_dup_t *new_inode_dup(fsck_ino_t);
static void invert_frags(avl_tree_t *, avl_tree_t *);
static void report_inode_dups(inode_dup_t *);
static int by_ino_cmp(const void *, const void *);
static int by_lfn_cmp(const void *, const void *);
static claimant_t *alloc_claimant(fsck_ino_t, daddr32_t);
static fragment_t *alloc_dup(daddr32_t);
static int claimant_cmp(const void *, const void *);
static int fragment_cmp(const void *, const void *);
static int decrement_claimant(fragment_t *, fsck_ino_t, daddr32_t);
static int increment_claimant(fragment_t *, fsck_ino_t, daddr32_t);

/*
 * Simple accessor function for the outside world so only we need to
 * see and interpret our data structures.
 */
int
have_dups(void)
{
	return (avl_numnodes(&dup_frags) > 0);
}

/*
 * Locates, creates, and deletes a record of a duplicate reference.
 *
 * For DB_INCR, returns true if the dup was added to the tree.
 * For DB_DECR, returns true if the dup was in the tree.
 */
int
find_dup_ref(daddr32_t fragno, fsck_ino_t ino, daddr32_t lfn, int flags)
{
	fragment_t key;
	fragment_t *dup;
	avl_index_t where;
	int added = 0;
	int removed = 0;

	if (avl_first(&dup_frags) == NULL) {
		if (flags & DB_CREATE)
			avl_create(&dup_frags, fragment_cmp,
			    sizeof (fragment_t),
			    OFFSETOF(fragment_t, fr_avl));
		else
			return (0);
	}

	key.fr_pfn = fragno;
	dup = avl_find(&dup_frags, (void *)&key, &where);
	if ((dup == NULL) & (flags & DB_CREATE)) {
		dup = alloc_dup(fragno);
		avl_insert(&dup_frags, (void *)dup, where);
	}

	if (dup != NULL) {
		if (flags & DB_INCR) {
			if (debug)
				(void) printf(
				    "adding claim by ino %d as lfn %d\n",
				    ino, lfn);
			added = increment_claimant(dup, ino, lfn);
		} else if (flags & DB_DECR) {
			/*
			 * Note that dup may be invalidated by this call.
			 */
			removed = decrement_claimant(dup, ino, lfn);
			if (debug)
				(void) printf(
		    "check for claimant ino %d lfn %d returned %d\n",
				    ino, lfn, removed);
		}
	}

	return (added || removed || (dup != NULL));
}

/*
 * Dump the duplicates table in a relatively user-friendly form.
 * The idea is that the output can be useful when trying to manually
 * work out which block belongs to which of the claiming inodes.
 *
 * What we have is a tree of duplicates indexed by physical
 * fragment number.  What we want to report is:
 *
 *    Inode %d:
 *        Logical Offset 0x%08llx,             Physical Fragment  %d
 *        Logical Offsets 0x%08llx - 0x%08llx, Physical Fragments %d - %d
 *        ...
 *    Inode %d:
 *        Logical Offsets 0x%08llx - 0x%08llx, Physical Fragments %d - %d
 *    ...
 */
int
report_dups(int quiet)
{
	int overlaps;
	inode_dup_t *inode;
	fragment_t *dup;
	avl_tree_t inode_frags;

	overlaps = 0;
	ASSERT(have_dups());
	/*
	 * Figure out how many actual dups are still around.
	 * This tells us whether or not we can mark the
	 * filesystem clean.
	 */
	dup = avl_first(&dup_frags);
	while (dup != NULL) {
		if (avl_numnodes(&dup->fr_claimants) > 1) {
			overlaps++;
			break;
		}
		dup = AVL_NEXT(&dup_frags, dup);
	}

	/*
	 * Now report on every object that still exists that
	 * had *any* dups associated with it.
	 */
	if (!quiet) {
		(void) puts("\nSome blocks that were found to be in "
		    "multiple files are still\nassigned to "
		    "file(s).\nFragments sorted by inode and "
		    "logical offsets:");

		invert_frags(&dup_frags, &inode_frags);
		inode = avl_first(&inode_frags);
		while (inode != NULL) {
			report_inode_dups(inode);
			inode = AVL_NEXT(&inode_frags, inode);
		}
		(void) printf("\n");

		free_invert_frags(&inode_frags);
	}

	return (overlaps);
}

static void
report_inode_dups(inode_dup_t *inode)
{
	reference_t *dup;
	daddr32_t first_lfn, last_lfn, first_pfn, last_pfn;

	(void) printf("Inode %d:\n", inode->id_ino);
	dup = avl_first(&inode->id_fragments);
	first_lfn = last_lfn = dup->ref_lfn;
	first_pfn = last_pfn = dup->ref_pfn;
	while ((dup = AVL_NEXT(&inode->id_fragments, dup)) != NULL) {
		if (((last_lfn + 1) != dup->ref_lfn) ||
		    ((last_pfn + 1) != dup->ref_pfn)) {
			report_dup_lfn_pfn(first_lfn, last_lfn,
			    first_pfn, last_pfn);
			first_lfn = last_lfn = dup->ref_lfn;
			first_pfn = last_pfn = dup->ref_pfn;
		}
	}
	report_dup_lfn_pfn(first_lfn, last_lfn, first_pfn, last_pfn);
}

static void
report_dup_lfn_pfn(daddr32_t first_lfn, daddr32_t last_lfn,
	daddr32_t first_pfn, daddr32_t last_pfn)
{
	if ((first_lfn == last_lfn) && (first_pfn == last_pfn)) {
		(void) printf(
	    "  Logical Offset  0x%08llx               Physical Fragment  %d\n",
		    (longlong_t)first_lfn * sblock.fs_fsize, first_pfn);
	} else {
		(void) printf(
		    "  Logical Offsets 0x%08llx - 0x%08llx, "
		    "Physical Fragments %d - %d\n",
		    (longlong_t)first_lfn * sblock.fs_fsize,
		    (longlong_t)last_lfn * sblock.fs_fsize,
		    first_pfn, last_pfn);
	}
}

/*
 * Given a tree of fragment_ts, each element of which has an integral
 * sub-tree of claimant_ts, produce a tree of inode_dup_ts, each element
 * of which has an integral sub-tree of reference_ts.
 */
static void
invert_frags(avl_tree_t *source, avl_tree_t *target)
{
	fragment_t *src_frag;
	claimant_t *src_claim;
	inode_dup_t *tgt_inode;
	inode_dup_t tgt_inode_key;
	reference_t *tgt_ref;
	reference_t tgt_ref_key;
	avl_index_t where;

	avl_create(target, by_ino_cmp, sizeof (inode_dup_t),
	    OFFSETOF(inode_dup_t, id_avl));

	src_frag = avl_first(source);
	while (src_frag != NULL) {
		src_claim = avl_first(&src_frag->fr_claimants);
		while (src_claim != NULL) {
			/*
			 * Have we seen this inode before?
			 */
			tgt_inode_key.id_ino = src_claim->cl_inode;
			tgt_inode = avl_find(target, (void *)&tgt_inode_key,
			    &where);
			if (tgt_inode == NULL) {
				/*
				 * No, so set up a record for it.
				 */
				tgt_inode = new_inode_dup(src_claim->cl_inode);
				avl_insert(target, (void *)tgt_inode, where);
			}
			/*
			 * Now, how about this logical fragment?  In
			 * theory, we should never see a duplicate, since
			 * a given lfn only exists once for a given inode.
			 * As such, we ignore duplicate hits.
			 */
			tgt_ref_key.ref_lfn = src_claim->cl_lfn;
			tgt_ref = avl_find(&tgt_inode->id_fragments,
			    (void *)&tgt_ref_key, &where);
			if (tgt_ref == NULL) {
				/*
				 * Haven't seen it, add it.
				 */
				tgt_ref = (reference_t *)malloc(
				    sizeof (reference_t));
				if (tgt_ref == NULL)
					errexit("Out of memory in "
					    "invert_frags\n");
				tgt_ref->ref_lfn = src_claim->cl_lfn;
				tgt_ref->ref_pfn = src_frag->fr_pfn;
				avl_insert(&tgt_inode->id_fragments,
				    (void *)tgt_ref, where);
			}
			src_claim = AVL_NEXT(&src_frag->fr_claimants,
			    src_claim);
		}
		src_frag = AVL_NEXT(source, src_frag);
	}
}

/*
 * Discard memory associated with the inverted fragments tree created
 * by report_dups() via invert_frags().
 */
static void
free_invert_frags(avl_tree_t *tree)
{
	void *outer = NULL;	/* traversal cookie */
	void *inner;		/* traversal cookie */
	inode_dup_t *inode_dup;
	reference_t *ref_dup;

	while ((inode_dup = avl_destroy_nodes(tree, &outer)) != NULL) {
		inner = NULL;
		while ((ref_dup = avl_destroy_nodes(&inode_dup->id_fragments,
		    &inner)) != NULL) {
			free((void *)ref_dup);
		}
		avl_destroy(&inode_dup->id_fragments);
		free((void *)inode_dup);
	}
	avl_destroy(tree);
}

/*
 * Discard all memory allocations associated with the current duplicates
 * table.
 */
void
free_dup_state(void)
{
	void *dup_cookie = NULL;
	void *claim_cookie;
	fragment_t *fragv;
	claimant_t *claimv;

	while ((fragv = avl_destroy_nodes(&dup_frags, &dup_cookie)) != NULL) {
		claim_cookie = NULL;
		while ((claimv = avl_destroy_nodes(&fragv->fr_claimants,
		    &claim_cookie)) != NULL) {
			free((void *)claimv);
		}
		avl_destroy(&fragv->fr_claimants);
		free((void *)fragv);
	}
	avl_destroy(&dup_frags);
}

/*
 * If the given claimant has not been seen before, add it to DUP's
 * list of them.  It's not fatal for the same PFN/INODE/LFN to get
 * added twice, because pass1b() will add the same dups that pass1()
 * did, plus one.
 */
static int
increment_claimant(fragment_t *dup, fsck_ino_t ino, daddr32_t lfn)
{
	avl_index_t where;
	claimant_t *claimant;
	claimant_t key;
	int added = 0;

	key.cl_inode = ino;
	key.cl_lfn = lfn;
	claimant = avl_find(&dup->fr_claimants, &key, &where);
	if (claimant == NULL) {
		if (debug)
			(void) printf("inserting claimant\n");
		claimant = alloc_claimant(ino, lfn);
		avl_insert(&dup->fr_claimants, (void *)claimant, where);
		statemap[ino] |= INCLEAR;
		/*
		 * If the inode is to be cleared and has zero links then remove
		 * the zero link bit as it will be cleared anyway. If INZLINK
		 * is being removed and it's a directory inode then add the
		 * inode to the orphan directory list.
		 */
		if (statemap[ino] & INZLINK) {
			statemap[ino] &= ~INZLINK;
			if (statemap[ino] & DSTATE) {
				add_orphan_dir(ino);
			}
		}
		added = 1;
	}

	return (added);
}

/*
 * If the given claimant is on DUP's list, remove it.  It is not
 * an error for the claimant to not be on the list.
 */
static int
decrement_claimant(fragment_t *dup, fsck_ino_t ino, daddr32_t lfn)
{
	avl_index_t where;
	claimant_t *claimant;
	claimant_t key;
	int busy = 0;

	key.cl_inode = ino;
	key.cl_lfn = lfn;
	claimant = avl_find(&dup->fr_claimants, &key, &where);
	if (claimant != NULL) {
		avl_remove(&dup->fr_claimants, claimant);
		if (avl_numnodes(&dup->fr_claimants) == 0) {
			avl_destroy(&dup->fr_claimants);
			avl_remove(&dup_frags, (void *)dup);
			free((void *)dup);
		} else {
			busy = 1;
		}
	}

	return (busy);
}

static claimant_t *
alloc_claimant(fsck_ino_t inode, daddr32_t lfn)
{
	claimant_t *new = (claimant_t *)malloc(sizeof (claimant_t));

	if (new == NULL)
		errexit("Out of memory in alloc_claimant()\n");

	new->cl_inode = inode;
	new->cl_lfn = lfn;

	return (new);
}

static fragment_t *
alloc_dup(daddr32_t pfn)
{
	fragment_t *new = (fragment_t *)malloc(sizeof (fragment_t));

	if (new == NULL)
		errexit("Out of memory in alloc_dup()\n");

	new->fr_pfn = pfn;
	avl_create(&new->fr_claimants, claimant_cmp, sizeof (fragment_t),
	    OFFSETOF(claimant_t, cl_avl));

	return (new);
}

/*
 * Compare two fragment_t instances for avl_find().  It requires a
 * return value of -1/0/1, so we can't just hand back left - right.
 */
static int
fragment_cmp(const void *vlp, const void *vrp)
{
	const fragment_t *lp = (const fragment_t *)vlp;
	const fragment_t *rp = (const fragment_t *)vrp;
	int cmp = lp->fr_pfn - rp->fr_pfn;

	if (cmp < 0)
		cmp = -1;
	else if (cmp > 0)
		cmp = 1;

	return (cmp);
}

/*
 * Compare two claimant_t instances for avl_find().  It requires a
 * return value of -1/0/1, so we can't just hand back left - right.
 */
static int
claimant_cmp(const void *vlp, const void *vrp)
{
	const claimant_t *lp = (const claimant_t *)vlp;
	const claimant_t *rp = (const claimant_t *)vrp;
	int cmp;

	cmp = lp->cl_inode - rp->cl_inode;
	if (cmp == 0) {
		/*
		 * lfn < 0 is a wildcard lfn match.
		 */
		if ((lp->cl_lfn >= 0) && (rp->cl_lfn >= 0))
			cmp = lp->cl_lfn - rp->cl_lfn;
	}

	if (cmp < 0)
		cmp = -1;
	else if (cmp > 0)
		cmp = 1;

	return (cmp);
}

static int
by_ino_cmp(const void *vlp, const void *vrp)
{
	const inode_dup_t *lp = (const inode_dup_t *)vlp;
	const inode_dup_t *rp = (const inode_dup_t *)vrp;
	int cmp;

	cmp = lp->id_ino - rp->id_ino;

	if (cmp < 0)
		cmp = -1;
	else if (cmp > 0)
		cmp = 1;

	return (cmp);
}

static int
by_lfn_cmp(const void *vlp, const void *vrp)
{
	const reference_t *lp = (const reference_t *)vlp;
	const reference_t *rp = (const reference_t *)vrp;
	int cmp;

	cmp = lp->ref_lfn - rp->ref_lfn;

	if (cmp < 0)
		cmp = -1;
	else if (cmp > 0)
		cmp = 1;

	return (cmp);
}

static inode_dup_t *
new_inode_dup(fsck_ino_t inode)
{
	inode_dup_t *new;

	new = (inode_dup_t *)malloc(sizeof (inode_dup_t));
	if (new == NULL)
		errexit("Out of memory in new_inode_dup\n");
	new->id_ino = inode;
	avl_create(&new->id_fragments, by_lfn_cmp, sizeof (reference_t),
	    OFFSETOF(reference_t, ref_avl));

	return (new);
}
