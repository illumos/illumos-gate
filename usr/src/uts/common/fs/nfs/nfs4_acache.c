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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/rnode4.h>
#include <nfs/nfs4_clnt.h>
#include <sys/bitmap.h>

/*
 * Access cache
 */
static acache4_hash_t *acache4;
static long nacache;    /* used strictly to size the number of hash queues */

static int acache4size;
static int acache4mask;
static struct kmem_cache *acache4_cache;
static int acache4_hashlen = 4;

/*
 * This probably needs to be larger than or equal to
 * log2(sizeof (struct rnode)) due to the way that rnodes are
 * allocated.
 */
#define	ACACHE4_SHIFT_BITS	9

static int
acache4hash(rnode4_t *rp, cred_t *cred)
{
	return ((((intptr_t)rp >> ACACHE4_SHIFT_BITS) + crgetuid(cred)) &
	    acache4mask);
}

#ifdef DEBUG
static long nfs4_access_cache_hits = 0;
static long nfs4_access_cache_misses = 0;
#endif

nfs4_access_type_t
nfs4_access_check(rnode4_t *rp, uint32_t acc, cred_t *cr)
{
	acache4_t *ap;
	acache4_hash_t *hp;
	nfs4_access_type_t all;
	vnode_t *vp;

	vp = RTOV4(rp);
	if (!ATTRCACHE4_VALID(vp) || nfs4_waitfor_purge_complete(vp))
		return (NFS4_ACCESS_UNKNOWN);

	if (rp->r_acache != NULL) {
		hp = &acache4[acache4hash(rp, cr)];
		rw_enter(&hp->lock, RW_READER);
		ap = hp->next;
		while (ap != (acache4_t *)hp) {
			if (crcmp(ap->cred, cr) == 0 && ap->rnode == rp) {
				if ((ap->known & acc) == acc) {
#ifdef DEBUG
					nfs4_access_cache_hits++;
#endif
					if ((ap->allowed & acc) == acc)
						all = NFS4_ACCESS_ALLOWED;
					else
						all = NFS4_ACCESS_DENIED;
				} else {
#ifdef DEBUG
					nfs4_access_cache_misses++;
#endif
					all = NFS4_ACCESS_UNKNOWN;
				}
				rw_exit(&hp->lock);
				return (all);
			}
			ap = ap->next;
		}
		rw_exit(&hp->lock);
	}

#ifdef DEBUG
	nfs4_access_cache_misses++;
#endif
	return (NFS4_ACCESS_UNKNOWN);
}

void
nfs4_access_cache(rnode4_t *rp, uint32_t acc, uint32_t resacc, cred_t *cr)
{
	acache4_t *ap;
	acache4_t *nap;
	acache4_hash_t *hp;

	hp = &acache4[acache4hash(rp, cr)];

	/*
	 * Allocate now assuming that mostly an allocation will be
	 * required.  This allows the allocation to happen without
	 * holding the hash bucket locked.
	 */
	nap = kmem_cache_alloc(acache4_cache, KM_NOSLEEP);
	if (nap != NULL) {
		nap->known = acc;
		nap->allowed = resacc;
		nap->rnode = rp;
		crhold(cr);
		nap->cred = cr;
		nap->hashq = hp;
	}

	rw_enter(&hp->lock, RW_WRITER);

	if (rp->r_acache != NULL) {
		ap = hp->next;
		while (ap != (acache4_t *)hp) {
			if (crcmp(ap->cred, cr) == 0 && ap->rnode == rp) {
				ap->known |= acc;
				ap->allowed &= ~acc;
				ap->allowed |= resacc;
				rw_exit(&hp->lock);
				if (nap != NULL) {
					crfree(nap->cred);
					kmem_cache_free(acache4_cache, nap);
				}
				return;
			}
			ap = ap->next;
		}
	}

	if (nap != NULL) {
#ifdef DEBUG
		clstat4_debug.access.value.ui64++;
#endif
		nap->next = hp->next;
		hp->next = nap;
		nap->next->prev = nap;
		nap->prev = (acache4_t *)hp;

		mutex_enter(&rp->r_statelock);
		nap->list = rp->r_acache;
		rp->r_acache = nap;
		mutex_exit(&rp->r_statelock);
	}

	rw_exit(&hp->lock);
}

int
nfs4_access_purge_rp(rnode4_t *rp)
{
	acache4_t *ap, *tmpap, *rplist;

	/*
	 * If there aren't any cached entries, then there is nothing
	 * to free.
	 */
	if (rp->r_acache == NULL)
		return (0);

	mutex_enter(&rp->r_statelock);
	rplist = rp->r_acache;
	rp->r_acache = NULL;
	mutex_exit(&rp->r_statelock);

	/*
	 * Loop through each entry in the list pointed to in the
	 * rnode.  Remove each of these entries from the hash
	 * queue that it is on and remove it from the list in
	 * the rnode.
	 */
	for (ap = rplist; ap != NULL; ap = tmpap) {
		rw_enter(&ap->hashq->lock, RW_WRITER);
		ap->prev->next = ap->next;
		ap->next->prev = ap->prev;
		rw_exit(&ap->hashq->lock);

		tmpap = ap->list;
		crfree(ap->cred);
		kmem_cache_free(acache4_cache, ap);
#ifdef DEBUG
		clstat4_debug.access.value.ui64--;
#endif
	}

	return (1);
}

int
nfs4_acache_init(void)
{
	extern int rtable4size;
	int i;

	/*
	 * Initial guess is one access cache entry per rnode unless
	 * nacache is set to a non-zero value and then it is used to
	 * indicate a guess at the number of access cache entries.
	 */
	if (nacache > 0)
		acache4size = 1 << highbit(nacache / acache4_hashlen);
	else
		acache4size = rtable4size;
	acache4mask = acache4size - 1;
	acache4 = kmem_alloc(acache4size * sizeof (*acache4), KM_SLEEP);
	for (i = 0; i < acache4size; i++) {
		acache4[i].next = (acache4_t *)&acache4[i];
		acache4[i].prev = (acache4_t *)&acache4[i];
		rw_init(&acache4[i].lock, NULL, RW_DEFAULT, NULL);
	}
	acache4_cache = kmem_cache_create("nfs4_access_cache",
	    sizeof (acache4_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	return (0);
}

int
nfs4_acache_fini(void)
{
	int i;

	/*
	 * Deallocated the access cache
	 */
	kmem_cache_destroy(acache4_cache);

	for (i = 0; i < acache4size; i++)
		rw_destroy(&acache4[i].lock);
	kmem_free(acache4, acache4size * sizeof (*acache4));

	return (0);
}
