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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * DDI nodeid management ...
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/debug.h>

/*
 * Keep a sorted free list of available nodeids.
 * Allocating a nodeid won't cause memory allocation.
 * Freeing a nodeid does cause memory allocation.
 */

struct available {
	uint32_t nodeid;
	uint32_t count;
	struct available *next;
	struct available *prev;
};

/*
 * The initial seed of available nodeids: 1 .. 0x10000000
 * 0, -1 (DEVI_PSEUDO_NODEID) and -2 (DEVI_SID_NODEID) are illegal values
 * and may not be used.  Although this code is fully capable of dealing
 * with a full 32-bit range of nodeids, we use a low numeric range of
 * nodeids as an optimization to avoid overlap with promif nodeids.
 */
#define	OUR_NODEID_MIN		((uint32_t)1)
#define	OUR_NODEID_MAX		((uint32_t)0x10000000)
#define	OUR_NODEID_COUNT	((uint32_t)(OUR_NODEID_MAX - OUR_NODEID_MIN))

static struct available seed = {
	OUR_NODEID_MIN, OUR_NODEID_COUNT, NULL, NULL
};

/*
 * head of the available list ...
 */
static struct available *nhead;

/*
 * A single lock for the list ...
 */
static kmutex_t nodeid_lock;

/*
 * Helper functions to manage the list ...
 */
static struct available *
np_alloc(int kmflag)
{
	return (kmem_zalloc(sizeof (struct available), kmflag));
}

static void
np_free(struct available *np)
{
	kmem_free(np, sizeof (struct available));
}

/*
 * Unlink a node from the list ... the lock must be held.
 */
static void
np_unlink(struct available *np)
{
	if (np->prev)
		np->prev->next = np->next;
	else
		nhead = np->next;

	if (np->next)
		np->next->prev = np->prev;
}

/*
 * Insert fp before np ... the lock must be held.
 */
static void
np_insert(struct available *fp, struct available *np)
{
	fp->prev = np->prev;
	fp->next = np;

	if (np->prev)
		np->prev->next = fp;
	else
		nhead = fp;
	np->prev = fp;
}

/*
 * Add fp to the end of the list ... the lock must be held.
 */
static void
np_add(struct available *fp)
{
	struct available *np;

	if (nhead == NULL) {
		nhead = fp;
		return;
	}

	for (np = nhead; np->next != NULL; np = np->next)
		/* empty */;

	np->next = fp;
	fp->prev = np;
}

/*
 * If this entry and the next entry are consecutive, coalesce the
 * two entries into a single entry ... the lock must be held.
 * If the entry can be coalesced, the extra entry is freed.
 */
static void
np_coalesce(struct available *np)
{
	struct available *xp;

	xp = np->next;
	if (xp == NULL)
		return;

	if ((np->nodeid + np->count) == xp->nodeid) {
		np->count += xp->count;
		np_unlink(xp);
		np_free(xp);
	}
}

void
impl_ddi_init_nodeid(void)
{
	struct available *np;

	mutex_init(&nodeid_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Copy the seed into kmem_alloc-ed memory so we don't have to
	 * worry about not freeing it later.
	 */
	np = np_alloc(KM_SLEEP);
	*np = seed;
	nhead = np;
}

int
impl_ddi_alloc_nodeid(int *nodeid)
{
	struct available *np;
	int x;
	int unlinked = 0;

	mutex_enter(&nodeid_lock);

	if (nhead == NULL) {
		mutex_exit(&nodeid_lock);
		*nodeid = 0;
		return (DDI_FAILURE);
	}

	np = nhead;
	x = (int)((unsigned int)np->nodeid);
	++np->nodeid;
	--np->count;
	if (np->count == 0) {
		np_unlink(np);
		unlinked = 1;
	}
	mutex_exit(&nodeid_lock);

	if (unlinked)
		np_free(np);

	ASSERT(x != 0);
	ASSERT(x != DEVI_PSEUDO_NODEID);
	ASSERT(x != DEVI_SID_NODEID);

	*nodeid = x;
	return (DDI_SUCCESS);
}

void
impl_ddi_free_nodeid(int n)
{
	uint32_t nodeid = (uint32_t)n;
	struct available *np, *fp;

	ASSERT(n != 0);
	ASSERT(n != DEVI_PSEUDO_NODEID);
	ASSERT(n != DEVI_SID_NODEID);

	/*
	 * Allocate memory wihout holding the lock in case we need it.
	 * If we don't use it, we'll free it.
	 */
	fp = np_alloc(KM_SLEEP);

	mutex_enter(&nodeid_lock);

	/*
	 * Insert nodeid in the appropriate place in our sorted available
	 * list. Maintain the list as we do it.
	 */
	for (np = nhead; np != NULL; np = np->next) {
		/*
		 * Add to the beginning of this entry?
		 */
		if ((nodeid + 1) == np->nodeid) {
			np->nodeid = nodeid;
			++np->count;
			mutex_exit(&nodeid_lock);
			np_free(fp);
			return;
		}
		/*
		 * Add to end of this entry? (If yes, try to coalesce
		 * this entry with the next entry.)
		 */
		if (nodeid == (np->nodeid + np->count)) {
			++np->count;
			np_coalesce(np);
			mutex_exit(&nodeid_lock);
			np_free(fp);
			return;
		}
		/*
		 * Does it belong before this entry? (new entry)
		 */
		if (nodeid < np->nodeid)  {
			fp->nodeid = nodeid;
			fp->count = 1;
			np_insert(fp, np);
			mutex_exit(&nodeid_lock);
			return;
		}
		if (nodeid < (np->nodeid + np->count))
			cmn_err(CE_PANIC, "impl_ddi_free_nodeid: "
			    "nodeid %x already free", n);
	}

	/*
	 * Add a new list item to the end of the list ...
	 */
	fp->nodeid = nodeid;
	fp->count = 1;
	np_add(fp);
	mutex_exit(&nodeid_lock);
}

/*
 * Remove (take) nodeid n off of the available list.
 * Returns 0 if successful or -1 if it fails.
 *
 * A failure indicates we were called with KM_NOSLEEP and we
 * couldn't allocate memory when we needed to.
 */
int
impl_ddi_take_nodeid(int n, int kmflag)
{
	uint32_t nodeid = (uint32_t)n;
	struct available *np, *fp;
	int unlinked = 0;

	ASSERT(n != 0);
	ASSERT(n != DEVI_PSEUDO_NODEID);
	ASSERT(n != DEVI_SID_NODEID);

	/*
	 * If this nodeid is not within the range of nodeids we
	 * manage, we simply succeed.  The initial seed may be
	 * setup so that promif nodeids fall outside our range.
	 */
	if ((nodeid < OUR_NODEID_MIN) || (nodeid > OUR_NODEID_MAX))
		return (0);

	/*
	 * Allocate memory wihout holding the lock in case we need it.
	 * If we don't use it, we'll free it.
	 */
	fp = np_alloc(kmflag);		/* if KM_NOSLEEP, fp may be NULL */

	mutex_enter(&nodeid_lock);

	/*
	 * Find nodeid in our list, if it exists, 'take' it.
	 */
	for (np = nhead; np != NULL; np = np->next) {

		/*
		 * If it's less than this entry, it's not available...
		 */
		if (nodeid < np->nodeid)
			break;

		/*
		 * If it's the first entry in this list item, take it ...
		 */
		if ((nodeid) == np->nodeid) {
			++np->nodeid;
			--np->count;
			if (np->count == 0) {
				np_unlink(np);
				++unlinked;
			}
			mutex_exit(&nodeid_lock);
			if (fp)
				np_free(fp);
			if (unlinked)
				np_free(np);
			return (0);
		}

		/*
		 * If it's the last entry in this list item, take it ...
		 * The count can't be 1 otherwise it would have matched
		 * the beginning of list case, above.
		 */
		if (nodeid == (np->nodeid + np->count - 1)) {
			--np->count;
			ASSERT(np->count != 0);
			mutex_exit(&nodeid_lock);
			if (fp)
				np_free(fp);
			return (0);
		}

		/*
		 * Is it in the middle of this entry? If it is, we'll
		 * have to split np into two items, removing nodeid
		 * from the middle of the list item.
		 */
		if (nodeid < (np->nodeid + np->count - 1)) {
			if (fp == NULL) {
				/*
				 * We were called with KM_NOSLEEP and
				 * were unable to allocate memory.
				 */
				mutex_exit(&nodeid_lock);
				return (-1);
			}
			/*
			 * Split np, removing nodeid from the middle of
			 * this entry. We already know it isn't on either
			 * end of of this entry, so we know we have to split it.
			 */
			fp->nodeid = np->nodeid;
			fp->count = nodeid - np->nodeid;
			np->nodeid = nodeid + 1;
			np->count = np->count - fp->count - 1;
			ASSERT((fp->count != 0) && (np->count != 0));
			ASSERT(np->nodeid == (fp->nodeid + fp->count + 1));
			np_insert(fp, np);
			mutex_exit(&nodeid_lock);
			return (0);
		}
	}

	/*
	 * Apparently the nodeid is not available ...
	 */
	mutex_exit(&nodeid_lock);

	if (fp)
		np_free(fp);
	cmn_err(CE_CONT, "?impl_ddi_take_nodeid: nodeid %x may not "
	    "be unique\n", nodeid);
	return (0);
}
