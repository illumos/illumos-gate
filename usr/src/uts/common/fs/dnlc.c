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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/systm.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/dnlc.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/vtrace.h>
#include <sys/bitmap.h>
#include <sys/var.h>
#include <sys/sysmacros.h>
#include <sys/kstat.h>
#include <sys/atomic.h>
#include <sys/taskq.h>

/*
 * Directory name lookup cache.
 * Based on code originally done by Robert Elz at Melbourne.
 *
 * Names found by directory scans are retained in a cache
 * for future reference.  Each hash chain is ordered by LRU
 * Cache is indexed by hash value obtained from (vp, name)
 * where the vp refers to the directory containing the name.
 */

/*
 * We want to be able to identify files that are referenced only by the DNLC.
 * When adding a reference from the DNLC, call VN_HOLD_DNLC instead of VN_HOLD,
 * since multiple DNLC references should only be counted once in v_count. This
 * file contains only two(2) calls to VN_HOLD, renamed VN_HOLD_CALLER in the
 * hope that no one will mistakenly add a VN_HOLD to this file. (Unfortunately
 * it is not possible to #undef VN_HOLD and retain VN_HOLD_CALLER. Ideally a
 * Makefile rule would grep uncommented C tokens to check that VN_HOLD is
 * referenced only once in this file, to define VN_HOLD_CALLER.)
 */
#define	VN_HOLD_CALLER	VN_HOLD
#define	VN_HOLD_DNLC(vp)	{	\
	mutex_enter(&(vp)->v_lock);	\
	if ((vp)->v_count_dnlc == 0) {	\
		VN_HOLD_LOCKED(vp);	\
	}				\
	(vp)->v_count_dnlc++;		\
	mutex_exit(&(vp)->v_lock);	\
}
#define	VN_RELE_DNLC(vp)	{	\
	vn_rele_dnlc(vp);		\
}

/*
 * Tunable nc_hashavelen is the average length desired for this chain, from
 * which the size of the nc_hash table is derived at create time.
 */
#define	NC_HASHAVELEN_DEFAULT	4
int nc_hashavelen = NC_HASHAVELEN_DEFAULT;

/*
 * NC_MOVETOFRONT is the move-to-front threshold: if the hash lookup
 * depth exceeds this value, we move the looked-up entry to the front of
 * its hash chain.  The idea is to make sure that the most frequently
 * accessed entries are found most quickly (by keeping them near the
 * front of their hash chains).
 */
#define	NC_MOVETOFRONT	2

/*
 *
 * DNLC_MAX_RELE is used to size an array on the stack when releasing
 * vnodes. This array is used rather than calling VN_RELE() inline because
 * all dnlc locks must be dropped by that time in order to avoid a
 * possible deadlock. This deadlock occurs when the dnlc holds the last
 * reference to the vnode and so the VOP_INACTIVE vector is called which
 * can in turn call back into the dnlc. A global array was used but had
 * many problems:
 *	1) Actually doesn't have an upper bound on the array size as
 *	   entries can be added after starting the purge.
 *	2) The locking scheme causes a hang.
 *	3) Caused serialisation on the global lock.
 *	4) The array was often unnecessarily huge.
 *
 * Note the current value 8 allows up to 4 cache entries (to be purged
 * from each hash chain), before having to cycle around and retry.
 * This ought to be ample given that nc_hashavelen is typically very small.
 */
#define	DNLC_MAX_RELE	8 /* must be even */

/*
 * Hash table of name cache entries for fast lookup, dynamically
 * allocated at startup.
 */
nc_hash_t *nc_hash;

/*
 * Rotors. Used to select entries on a round-robin basis.
 */
static nc_hash_t *dnlc_purge_fs1_rotor;
static nc_hash_t *dnlc_free_rotor;

/*
 * # of dnlc entries (uninitialized)
 *
 * the initial value was chosen as being
 * a random string of bits, probably not
 * normally chosen by a systems administrator
 */
int ncsize = -1;
volatile uint32_t dnlc_nentries = 0;	/* current num of name cache entries */
static int nc_hashsz;			/* size of hash table */
static int nc_hashmask;			/* size of hash table minus 1 */

/*
 * The dnlc_reduce_cache() taskq queue is activated when there are
 * ncsize name cache entries and if no parameter is provided, it reduces
 * the size down to dnlc_nentries_low_water, which is by default one
 * hundreth less (or 99%) of ncsize.
 *
 * If a parameter is provided to dnlc_reduce_cache(), then we reduce
 * the size down based on ncsize_onepercent - where ncsize_onepercent
 * is 1% of ncsize; however, we never let dnlc_reduce_cache() reduce
 * the size below 3% of ncsize (ncsize_min_percent).
 */
#define	DNLC_LOW_WATER_DIVISOR_DEFAULT 100
uint_t dnlc_low_water_divisor = DNLC_LOW_WATER_DIVISOR_DEFAULT;
uint_t dnlc_nentries_low_water;
int dnlc_reduce_idle = 1; /* no locking needed */
uint_t ncsize_onepercent;
uint_t ncsize_min_percent;

/*
 * If dnlc_nentries hits dnlc_max_nentries (twice ncsize)
 * then this means the dnlc_reduce_cache() taskq is failing to
 * keep up. In this case we refuse to add new entries to the dnlc
 * until the taskq catches up.
 */
uint_t dnlc_max_nentries; /* twice ncsize */
uint64_t dnlc_max_nentries_cnt = 0; /* statistic on times we failed */

/*
 * Tunable to define when we should just remove items from
 * the end of the chain.
 */
#define	DNLC_LONG_CHAIN 8
uint_t dnlc_long_chain = DNLC_LONG_CHAIN;

/*
 * ncstats has been deprecated, due to the integer size of the counters
 * which can easily overflow in the dnlc.
 * It is maintained (at some expense) for compatability.
 * The preferred interface is the kstat accessible nc_stats below.
 */
struct ncstats ncstats;

struct nc_stats ncs = {
	{ "hits",			KSTAT_DATA_UINT64 },
	{ "misses",			KSTAT_DATA_UINT64 },
	{ "negative_cache_hits",	KSTAT_DATA_UINT64 },
	{ "enters",			KSTAT_DATA_UINT64 },
	{ "double_enters",		KSTAT_DATA_UINT64 },
	{ "purge_total_entries",	KSTAT_DATA_UINT64 },
	{ "purge_all",			KSTAT_DATA_UINT64 },
	{ "purge_vp",			KSTAT_DATA_UINT64 },
	{ "purge_vfs",			KSTAT_DATA_UINT64 },
	{ "purge_fs1",			KSTAT_DATA_UINT64 },
	{ "pick_free",			KSTAT_DATA_UINT64 },
	{ "pick_heuristic",		KSTAT_DATA_UINT64 },
	{ "pick_last",			KSTAT_DATA_UINT64 },

	/* directory caching stats */

	{ "dir_hits",			KSTAT_DATA_UINT64 },
	{ "dir_misses",			KSTAT_DATA_UINT64 },
	{ "dir_cached_current",		KSTAT_DATA_UINT64 },
	{ "dir_entries_cached_current",	KSTAT_DATA_UINT64 },
	{ "dir_cached_total",		KSTAT_DATA_UINT64 },
	{ "dir_start_no_memory",	KSTAT_DATA_UINT64 },
	{ "dir_add_no_memory",		KSTAT_DATA_UINT64 },
	{ "dir_add_abort",		KSTAT_DATA_UINT64 },
	{ "dir_add_max",		KSTAT_DATA_UINT64 },
	{ "dir_remove_entry_fail",	KSTAT_DATA_UINT64 },
	{ "dir_remove_space_fail",	KSTAT_DATA_UINT64 },
	{ "dir_update_fail",		KSTAT_DATA_UINT64 },
	{ "dir_fini_purge",		KSTAT_DATA_UINT64 },
	{ "dir_reclaim_last",		KSTAT_DATA_UINT64 },
	{ "dir_reclaim_any",		KSTAT_DATA_UINT64 },
};

static int doingcache = 1;

vnode_t negative_cache_vnode;

/*
 * Insert entry at the front of the queue
 */
#define	nc_inshash(ncp, hp) \
{ \
	(ncp)->hash_next = (hp)->hash_next; \
	(ncp)->hash_prev = (ncache_t *)(hp); \
	(hp)->hash_next->hash_prev = (ncp); \
	(hp)->hash_next = (ncp); \
}

/*
 * Remove entry from hash queue
 */
#define	nc_rmhash(ncp) \
{ \
	(ncp)->hash_prev->hash_next = (ncp)->hash_next; \
	(ncp)->hash_next->hash_prev = (ncp)->hash_prev; \
	(ncp)->hash_prev = NULL; \
	(ncp)->hash_next = NULL; \
}

/*
 * Free an entry.
 */
#define	dnlc_free(ncp) \
{ \
	kmem_free((ncp), sizeof (ncache_t) + (ncp)->namlen); \
	atomic_dec_32(&dnlc_nentries); \
}


/*
 * Cached directory info.
 * ======================
 */

/*
 * Cached directory free space hash function.
 * Needs the free space handle and the dcp to get the hash table size
 * Returns the hash index.
 */
#define	DDFHASH(handle, dcp) ((handle >> 2) & (dcp)->dc_fhash_mask)

/*
 * Cached directory name entry hash function.
 * Uses the name and returns in the input arguments the hash and the name
 * length.
 */
#define	DNLC_DIR_HASH(name, hash, namelen)			\
	{							\
		char Xc;					\
		const char *Xcp;				\
		hash = *name;					\
		for (Xcp = (name + 1); (Xc = *Xcp) != 0; Xcp++)	\
			hash = (hash << 4) + hash + Xc;		\
		ASSERT((Xcp - (name)) <= ((1 << NBBY) - 1));	\
		namelen = Xcp - (name);				\
	}

/* special dircache_t pointer to indicate error should be returned */
/*
 * The anchor directory cache pointer can contain 3 types of values,
 * 1) NULL: No directory cache
 * 2) DC_RET_LOW_MEM (-1): There was a directory cache that found to be
 *    too big or a memory shortage occurred. This value remains in the
 *    pointer until a dnlc_dir_start() which returns the a DNOMEM error.
 *    This is kludgy but efficient and only visible in this source file.
 * 3) A valid cache pointer.
 */
#define	DC_RET_LOW_MEM (dircache_t *)1
#define	VALID_DIR_CACHE(dcp) ((dircache_t *)(dcp) > DC_RET_LOW_MEM)

/* Tunables */
uint_t dnlc_dir_enable = 1; /* disable caching directories by setting to 0 */
uint_t dnlc_dir_min_size = 40; /* min no of directory entries before caching */
uint_t dnlc_dir_max_size = UINT_MAX; /* ditto maximum */
uint_t dnlc_dir_hash_size_shift = 3; /* 8 entries per hash bucket */
uint_t dnlc_dir_min_reclaim =  350000; /* approx 1MB of dcentrys */
/*
 * dnlc_dir_hash_resize_shift determines when the hash tables
 * get re-adjusted due to growth or shrinkage
 * - currently 2 indicating that there can be at most 4
 * times or at least one quarter the number of entries
 * before hash table readjustment. Note that with
 * dnlc_dir_hash_size_shift above set at 3 this would
 * mean readjustment would occur if the average number
 * of entries went above 32 or below 2
 */
uint_t dnlc_dir_hash_resize_shift = 2; /* readjust rate */

static kmem_cache_t *dnlc_dir_space_cache; /* free space entry cache */
static dchead_t dc_head; /* anchor of cached directories */

/* Prototypes */
static ncache_t *dnlc_get(uchar_t namlen);
static ncache_t *dnlc_search(vnode_t *dp, const char *name, uchar_t namlen,
    int hash);
static void dnlc_dir_reclaim(void *unused);
static void dnlc_dir_abort(dircache_t *dcp);
static void dnlc_dir_adjust_fhash(dircache_t *dcp);
static void dnlc_dir_adjust_nhash(dircache_t *dcp);
static void do_dnlc_reduce_cache(void *);


/*
 * Initialize the directory cache.
 */
void
dnlc_init()
{
	nc_hash_t *hp;
	kstat_t *ksp;
	int i;

	/*
	 * Set up the size of the dnlc (ncsize) and its low water mark.
	 */
	if (ncsize == -1) {
		/* calculate a reasonable size for the low water */
		dnlc_nentries_low_water = 4 * (v.v_proc + maxusers) + 320;
		ncsize = dnlc_nentries_low_water +
		    (dnlc_nentries_low_water / dnlc_low_water_divisor);
	} else {
		/* don't change the user specified ncsize */
		dnlc_nentries_low_water =
		    ncsize - (ncsize / dnlc_low_water_divisor);
	}
	if (ncsize <= 0) {
		doingcache = 0;
		dnlc_dir_enable = 0; /* also disable directory caching */
		ncsize = 0;
		cmn_err(CE_NOTE, "name cache (dnlc) disabled");
		return;
	}
	dnlc_max_nentries = ncsize * 2;
	ncsize_onepercent = ncsize / 100;
	ncsize_min_percent = ncsize_onepercent * 3;

	/*
	 * Initialise the hash table.
	 * Compute hash size rounding to the next power of two.
	 */
	nc_hashsz = ncsize / nc_hashavelen;
	nc_hashsz = 1 << highbit(nc_hashsz);
	nc_hashmask = nc_hashsz - 1;
	nc_hash = kmem_zalloc(nc_hashsz * sizeof (*nc_hash), KM_SLEEP);
	for (i = 0; i < nc_hashsz; i++) {
		hp = (nc_hash_t *)&nc_hash[i];
		mutex_init(&hp->hash_lock, NULL, MUTEX_DEFAULT, NULL);
		hp->hash_next = (ncache_t *)hp;
		hp->hash_prev = (ncache_t *)hp;
	}

	/*
	 * Initialize rotors
	 */
	dnlc_free_rotor = dnlc_purge_fs1_rotor = &nc_hash[0];

	/*
	 * Set up the directory caching to use kmem_cache_alloc
	 * for its free space entries so that we can get a callback
	 * when the system is short on memory, to allow us to free
	 * up some memory. we don't use the constructor/deconstructor
	 * functions.
	 */
	dnlc_dir_space_cache = kmem_cache_create("dnlc_space_cache",
	    sizeof (dcfree_t), 0, NULL, NULL, dnlc_dir_reclaim, NULL,
	    NULL, 0);

	/*
	 * Initialise the head of the cached directory structures
	 */
	mutex_init(&dc_head.dch_lock, NULL, MUTEX_DEFAULT, NULL);
	dc_head.dch_next = (dircache_t *)&dc_head;
	dc_head.dch_prev = (dircache_t *)&dc_head;

	/*
	 * Put a hold on the negative cache vnode so that it never goes away
	 * (VOP_INACTIVE isn't called on it). The mutex_enter() isn't necessary
	 * for correctness, but VN_HOLD_LOCKED() asserts that it's held, so
	 * we oblige.
	 */
	mutex_enter(&negative_cache_vnode.v_lock);
	negative_cache_vnode.v_count = 0;
	VN_HOLD_LOCKED(&negative_cache_vnode);
	negative_cache_vnode.v_count_dnlc = 0;
	mutex_exit(&negative_cache_vnode.v_lock);

	/*
	 * Initialise kstats - both the old compatability raw kind and
	 * the more extensive named stats.
	 */
	ksp = kstat_create("unix", 0, "ncstats", "misc", KSTAT_TYPE_RAW,
	    sizeof (struct ncstats), KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) &ncstats;
		kstat_install(ksp);
	}
	ksp = kstat_create("unix", 0, "dnlcstats", "misc", KSTAT_TYPE_NAMED,
	    sizeof (ncs) / sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) &ncs;
		kstat_install(ksp);
	}
}

/*
 * Add a name to the directory cache.
 */
void
dnlc_enter(vnode_t *dp, const char *name, vnode_t *vp)
{
	ncache_t *ncp;
	nc_hash_t *hp;
	uchar_t namlen;
	int hash;

	TRACE_0(TR_FAC_NFS, TR_DNLC_ENTER_START, "dnlc_enter_start:");

	if (!doingcache) {
		TRACE_2(TR_FAC_NFS, TR_DNLC_ENTER_END,
		    "dnlc_enter_end:(%S) %d", "not caching", 0);
		return;
	}

	/*
	 * Get a new dnlc entry. Assume the entry won't be in the cache
	 * and initialize it now
	 */
	DNLCHASH(name, dp, hash, namlen);
	if ((ncp = dnlc_get(namlen)) == NULL)
		return;
	ncp->dp = dp;
	VN_HOLD_DNLC(dp);
	ncp->vp = vp;
	VN_HOLD_DNLC(vp);
	bcopy(name, ncp->name, namlen + 1); /* name and null */
	ncp->hash = hash;
	hp = &nc_hash[hash & nc_hashmask];

	mutex_enter(&hp->hash_lock);
	if (dnlc_search(dp, name, namlen, hash) != NULL) {
		mutex_exit(&hp->hash_lock);
		ncstats.dbl_enters++;
		ncs.ncs_dbl_enters.value.ui64++;
		VN_RELE_DNLC(dp);
		VN_RELE_DNLC(vp);
		dnlc_free(ncp);		/* crfree done here */
		TRACE_2(TR_FAC_NFS, TR_DNLC_ENTER_END,
		    "dnlc_enter_end:(%S) %d", "dbl enter", ncstats.dbl_enters);
		return;
	}
	/*
	 * Insert back into the hash chain.
	 */
	nc_inshash(ncp, hp);
	mutex_exit(&hp->hash_lock);
	ncstats.enters++;
	ncs.ncs_enters.value.ui64++;
	TRACE_2(TR_FAC_NFS, TR_DNLC_ENTER_END,
	    "dnlc_enter_end:(%S) %d", "done", ncstats.enters);
}

/*
 * Add a name to the directory cache.
 *
 * This function is basically identical with
 * dnlc_enter().  The difference is that when the
 * desired dnlc entry is found, the vnode in the
 * ncache is compared with the vnode passed in.
 *
 * If they are not equal then the ncache is
 * updated with the passed in vnode.  Otherwise
 * it just frees up the newly allocated dnlc entry.
 */
void
dnlc_update(vnode_t *dp, const char *name, vnode_t *vp)
{
	ncache_t *ncp;
	ncache_t *tcp;
	vnode_t *tvp;
	nc_hash_t *hp;
	int hash;
	uchar_t namlen;

	TRACE_0(TR_FAC_NFS, TR_DNLC_ENTER_START, "dnlc_update_start:");

	if (!doingcache) {
		TRACE_2(TR_FAC_NFS, TR_DNLC_ENTER_END,
		    "dnlc_update_end:(%S) %d", "not caching", 0);
		return;
	}

	/*
	 * Get a new dnlc entry and initialize it now.
	 * If we fail to get a new entry, call dnlc_remove() to purge
	 * any existing dnlc entry including negative cache (DNLC_NO_VNODE)
	 * entry.
	 * Failure to clear an existing entry could result in false dnlc
	 * lookup (negative/stale entry).
	 */
	DNLCHASH(name, dp, hash, namlen);
	if ((ncp = dnlc_get(namlen)) == NULL) {
		dnlc_remove(dp, name);
		return;
	}
	ncp->dp = dp;
	VN_HOLD_DNLC(dp);
	ncp->vp = vp;
	VN_HOLD_DNLC(vp);
	bcopy(name, ncp->name, namlen + 1); /* name and null */
	ncp->hash = hash;
	hp = &nc_hash[hash & nc_hashmask];

	mutex_enter(&hp->hash_lock);
	if ((tcp = dnlc_search(dp, name, namlen, hash)) != NULL) {
		if (tcp->vp != vp) {
			tvp = tcp->vp;
			tcp->vp = vp;
			mutex_exit(&hp->hash_lock);
			VN_RELE_DNLC(tvp);
			ncstats.enters++;
			ncs.ncs_enters.value.ui64++;
			TRACE_2(TR_FAC_NFS, TR_DNLC_ENTER_END,
			    "dnlc_update_end:(%S) %d", "done", ncstats.enters);
		} else {
			mutex_exit(&hp->hash_lock);
			VN_RELE_DNLC(vp);
			ncstats.dbl_enters++;
			ncs.ncs_dbl_enters.value.ui64++;
			TRACE_2(TR_FAC_NFS, TR_DNLC_ENTER_END,
			    "dnlc_update_end:(%S) %d",
			    "dbl enter", ncstats.dbl_enters);
		}
		VN_RELE_DNLC(dp);
		dnlc_free(ncp);		/* crfree done here */
		return;
	}
	/*
	 * insert the new entry, since it is not in dnlc yet
	 */
	nc_inshash(ncp, hp);
	mutex_exit(&hp->hash_lock);
	ncstats.enters++;
	ncs.ncs_enters.value.ui64++;
	TRACE_2(TR_FAC_NFS, TR_DNLC_ENTER_END,
	    "dnlc_update_end:(%S) %d", "done", ncstats.enters);
}

/*
 * Look up a name in the directory name cache.
 *
 * Return a doubly-held vnode if found: one hold so that it may
 * remain in the cache for other users, the other hold so that
 * the cache is not re-cycled and the identity of the vnode is
 * lost before the caller can use the vnode.
 */
vnode_t *
dnlc_lookup(vnode_t *dp, const char *name)
{
	ncache_t *ncp;
	nc_hash_t *hp;
	vnode_t *vp;
	int hash, depth;
	uchar_t namlen;

	TRACE_2(TR_FAC_NFS, TR_DNLC_LOOKUP_START,
	    "dnlc_lookup_start:dp %x name %s", dp, name);

	if (!doingcache) {
		TRACE_4(TR_FAC_NFS, TR_DNLC_LOOKUP_END,
		    "dnlc_lookup_end:%S %d vp %x name %s",
		    "not_caching", 0, NULL, name);
		return (NULL);
	}

	DNLCHASH(name, dp, hash, namlen);
	depth = 1;
	hp = &nc_hash[hash & nc_hashmask];
	mutex_enter(&hp->hash_lock);

	for (ncp = hp->hash_next; ncp != (ncache_t *)hp;
	    ncp = ncp->hash_next) {
		if (ncp->hash == hash &&	/* fast signature check */
		    ncp->dp == dp &&
		    ncp->namlen == namlen &&
		    bcmp(ncp->name, name, namlen) == 0) {
			/*
			 * Move this entry to the head of its hash chain
			 * if it's not already close.
			 */
			if (depth > NC_MOVETOFRONT) {
				ncache_t *next = ncp->hash_next;
				ncache_t *prev = ncp->hash_prev;

				prev->hash_next = next;
				next->hash_prev = prev;
				ncp->hash_next = next = hp->hash_next;
				ncp->hash_prev = (ncache_t *)hp;
				next->hash_prev = ncp;
				hp->hash_next = ncp;

				ncstats.move_to_front++;
			}

			/*
			 * Put a hold on the vnode now so its identity
			 * can't change before the caller has a chance to
			 * put a hold on it.
			 */
			vp = ncp->vp;
			VN_HOLD_CALLER(vp); /* VN_HOLD 1 of 2 in this file */
			mutex_exit(&hp->hash_lock);
			ncstats.hits++;
			ncs.ncs_hits.value.ui64++;
			if (vp == DNLC_NO_VNODE) {
				ncs.ncs_neg_hits.value.ui64++;
			}
			TRACE_4(TR_FAC_NFS, TR_DNLC_LOOKUP_END,
			    "dnlc_lookup_end:%S %d vp %x name %s", "hit",
			    ncstats.hits, vp, name);
			return (vp);
		}
		depth++;
	}

	mutex_exit(&hp->hash_lock);
	ncstats.misses++;
	ncs.ncs_misses.value.ui64++;
	TRACE_4(TR_FAC_NFS, TR_DNLC_LOOKUP_END,
	    "dnlc_lookup_end:%S %d vp %x name %s", "miss", ncstats.misses,
	    NULL, name);
	return (NULL);
}

/*
 * Remove an entry in the directory name cache.
 */
void
dnlc_remove(vnode_t *dp, const char *name)
{
	ncache_t *ncp;
	nc_hash_t *hp;
	uchar_t namlen;
	int hash;

	if (!doingcache)
		return;
	DNLCHASH(name, dp, hash, namlen);
	hp = &nc_hash[hash & nc_hashmask];

	mutex_enter(&hp->hash_lock);
	if (ncp = dnlc_search(dp, name, namlen, hash)) {
		/*
		 * Free up the entry
		 */
		nc_rmhash(ncp);
		mutex_exit(&hp->hash_lock);
		VN_RELE_DNLC(ncp->vp);
		VN_RELE_DNLC(ncp->dp);
		dnlc_free(ncp);
		return;
	}
	mutex_exit(&hp->hash_lock);
}

/*
 * Purge the entire cache.
 */
void
dnlc_purge()
{
	nc_hash_t *nch;
	ncache_t *ncp;
	int index;
	int i;
	vnode_t *nc_rele[DNLC_MAX_RELE];

	if (!doingcache)
		return;

	ncstats.purges++;
	ncs.ncs_purge_all.value.ui64++;

	for (nch = nc_hash; nch < &nc_hash[nc_hashsz]; nch++) {
		index = 0;
		mutex_enter(&nch->hash_lock);
		ncp = nch->hash_next;
		while (ncp != (ncache_t *)nch) {
			ncache_t *np;

			np = ncp->hash_next;
			nc_rele[index++] = ncp->vp;
			nc_rele[index++] = ncp->dp;

			nc_rmhash(ncp);
			dnlc_free(ncp);
			ncp = np;
			ncs.ncs_purge_total.value.ui64++;
			if (index == DNLC_MAX_RELE)
				break;
		}
		mutex_exit(&nch->hash_lock);

		/* Release holds on all the vnodes now that we have no locks */
		for (i = 0; i < index; i++) {
			VN_RELE_DNLC(nc_rele[i]);
		}
		if (ncp != (ncache_t *)nch) {
			nch--; /* Do current hash chain again */
		}
	}
}

/*
 * Purge any cache entries referencing a vnode. Exit as soon as the dnlc
 * reference count goes to zero (the caller still holds a reference).
 */
void
dnlc_purge_vp(vnode_t *vp)
{
	nc_hash_t *nch;
	ncache_t *ncp;
	int index;
	vnode_t *nc_rele[DNLC_MAX_RELE];

	ASSERT(vp->v_count > 0);
	if (vp->v_count_dnlc == 0) {
		return;
	}

	if (!doingcache)
		return;

	ncstats.purges++;
	ncs.ncs_purge_vp.value.ui64++;

	for (nch = nc_hash; nch < &nc_hash[nc_hashsz]; nch++) {
		index = 0;
		mutex_enter(&nch->hash_lock);
		ncp = nch->hash_next;
		while (ncp != (ncache_t *)nch) {
			ncache_t *np;

			np = ncp->hash_next;
			if (ncp->dp == vp || ncp->vp == vp) {
				nc_rele[index++] = ncp->vp;
				nc_rele[index++] = ncp->dp;
				nc_rmhash(ncp);
				dnlc_free(ncp);
				ncs.ncs_purge_total.value.ui64++;
				if (index == DNLC_MAX_RELE) {
					ncp = np;
					break;
				}
			}
			ncp = np;
		}
		mutex_exit(&nch->hash_lock);

		/* Release holds on all the vnodes now that we have no locks */
		while (index) {
			VN_RELE_DNLC(nc_rele[--index]);
		}

		if (vp->v_count_dnlc == 0) {
			return;
		}

		if (ncp != (ncache_t *)nch) {
			nch--; /* Do current hash chain again */
		}
	}
}

/*
 * Purge cache entries referencing a vfsp.  Caller supplies a count
 * of entries to purge; up to that many will be freed.  A count of
 * zero indicates that all such entries should be purged.  Returns
 * the number of entries that were purged.
 */
int
dnlc_purge_vfsp(vfs_t *vfsp, int count)
{
	nc_hash_t *nch;
	ncache_t *ncp;
	int n = 0;
	int index;
	int i;
	vnode_t *nc_rele[DNLC_MAX_RELE];

	if (!doingcache)
		return (0);

	ncstats.purges++;
	ncs.ncs_purge_vfs.value.ui64++;

	for (nch = nc_hash; nch < &nc_hash[nc_hashsz]; nch++) {
		index = 0;
		mutex_enter(&nch->hash_lock);
		ncp = nch->hash_next;
		while (ncp != (ncache_t *)nch) {
			ncache_t *np;

			np = ncp->hash_next;
			ASSERT(ncp->dp != NULL);
			ASSERT(ncp->vp != NULL);
			if ((ncp->dp->v_vfsp == vfsp) ||
			    (ncp->vp->v_vfsp == vfsp)) {
				n++;
				nc_rele[index++] = ncp->vp;
				nc_rele[index++] = ncp->dp;
				nc_rmhash(ncp);
				dnlc_free(ncp);
				ncs.ncs_purge_total.value.ui64++;
				if (index == DNLC_MAX_RELE) {
					ncp = np;
					break;
				}
				if (count != 0 && n >= count) {
					break;
				}
			}
			ncp = np;
		}
		mutex_exit(&nch->hash_lock);
		/* Release holds on all the vnodes now that we have no locks */
		for (i = 0; i < index; i++) {
			VN_RELE_DNLC(nc_rele[i]);
		}
		if (count != 0 && n >= count) {
			return (n);
		}
		if (ncp != (ncache_t *)nch) {
			nch--; /* Do current hash chain again */
		}
	}
	return (n);
}

/*
 * Purge 1 entry from the dnlc that is part of the filesystem(s)
 * represented by 'vop'. The purpose of this routine is to allow
 * users of the dnlc to free a vnode that is being held by the dnlc.
 *
 * If we find a vnode that we release which will result in
 * freeing the underlying vnode (count was 1), return 1, 0
 * if no appropriate vnodes found.
 *
 * Note, vop is not the 'right' identifier for a filesystem.
 */
int
dnlc_fs_purge1(vnodeops_t *vop)
{
	nc_hash_t *end;
	nc_hash_t *hp;
	ncache_t *ncp;
	vnode_t *vp;

	if (!doingcache)
		return (0);

	ncs.ncs_purge_fs1.value.ui64++;

	/*
	 * Scan the dnlc entries looking for a likely candidate.
	 */
	hp = end = dnlc_purge_fs1_rotor;

	do {
		if (++hp == &nc_hash[nc_hashsz])
			hp = nc_hash;
		dnlc_purge_fs1_rotor = hp;
		if (hp->hash_next == (ncache_t *)hp)
			continue;
		mutex_enter(&hp->hash_lock);
		for (ncp = hp->hash_prev;
		    ncp != (ncache_t *)hp;
		    ncp = ncp->hash_prev) {
			vp = ncp->vp;
			if (!vn_has_cached_data(vp) && (vp->v_count == 1) &&
			    vn_matchops(vp, vop))
				break;
		}
		if (ncp != (ncache_t *)hp) {
			nc_rmhash(ncp);
			mutex_exit(&hp->hash_lock);
			VN_RELE_DNLC(ncp->dp);
			VN_RELE_DNLC(vp)
			dnlc_free(ncp);
			ncs.ncs_purge_total.value.ui64++;
			return (1);
		}
		mutex_exit(&hp->hash_lock);
	} while (hp != end);
	return (0);
}

/*
 * Perform a reverse lookup in the DNLC.  This will find the first occurrence of
 * the vnode.  If successful, it will return the vnode of the parent, and the
 * name of the entry in the given buffer.  If it cannot be found, or the buffer
 * is too small, then it will return NULL.  Note that this is a highly
 * inefficient function, since the DNLC is constructed solely for forward
 * lookups.
 */
vnode_t *
dnlc_reverse_lookup(vnode_t *vp, char *buf, size_t buflen)
{
	nc_hash_t *nch;
	ncache_t *ncp;
	vnode_t *pvp;

	if (!doingcache)
		return (NULL);

	for (nch = nc_hash; nch < &nc_hash[nc_hashsz]; nch++) {
		mutex_enter(&nch->hash_lock);
		ncp = nch->hash_next;
		while (ncp != (ncache_t *)nch) {
			/*
			 * We ignore '..' entries since it can create
			 * confusion and infinite loops.
			 */
			if (ncp->vp == vp && !(ncp->namlen == 2 &&
			    0 == bcmp(ncp->name, "..", 2)) &&
			    ncp->namlen < buflen) {
				bcopy(ncp->name, buf, ncp->namlen);
				buf[ncp->namlen] = '\0';
				pvp = ncp->dp;
				/* VN_HOLD 2 of 2 in this file */
				VN_HOLD_CALLER(pvp);
				mutex_exit(&nch->hash_lock);
				return (pvp);
			}
			ncp = ncp->hash_next;
		}
		mutex_exit(&nch->hash_lock);
	}

	return (NULL);
}
/*
 * Utility routine to search for a cache entry. Return the
 * ncache entry if found, NULL otherwise.
 */
static ncache_t *
dnlc_search(vnode_t *dp, const char *name, uchar_t namlen, int hash)
{
	nc_hash_t *hp;
	ncache_t *ncp;

	hp = &nc_hash[hash & nc_hashmask];

	for (ncp = hp->hash_next; ncp != (ncache_t *)hp; ncp = ncp->hash_next) {
		if (ncp->hash == hash &&
		    ncp->dp == dp &&
		    ncp->namlen == namlen &&
		    bcmp(ncp->name, name, namlen) == 0)
			return (ncp);
	}
	return (NULL);
}

#if ((1 << NBBY) - 1) < (MAXNAMELEN - 1)
#error ncache_t name length representation is too small
#endif

void
dnlc_reduce_cache(void *reduce_percent)
{
	if (dnlc_reduce_idle && (dnlc_nentries >= ncsize || reduce_percent)) {
		dnlc_reduce_idle = 0;
		if ((taskq_dispatch(system_taskq, do_dnlc_reduce_cache,
		    reduce_percent, TQ_NOSLEEP)) == NULL)
			dnlc_reduce_idle = 1;
	}
}

/*
 * Get a new name cache entry.
 * If the dnlc_reduce_cache() taskq isn't keeping up with demand, or memory
 * is short then just return NULL. If we're over ncsize then kick off a
 * thread to free some in use entries down to dnlc_nentries_low_water.
 * Caller must initialise all fields except namlen.
 * Component names are defined to be less than MAXNAMELEN
 * which includes a null.
 */
static ncache_t *
dnlc_get(uchar_t namlen)
{
	ncache_t *ncp;

	if (dnlc_nentries > dnlc_max_nentries) {
		dnlc_max_nentries_cnt++; /* keep a statistic */
		return (NULL);
	}
	ncp = kmem_alloc(sizeof (ncache_t) + namlen, KM_NOSLEEP);
	if (ncp == NULL) {
		return (NULL);
	}
	ncp->namlen = namlen;
	atomic_inc_32(&dnlc_nentries);
	dnlc_reduce_cache(NULL);
	return (ncp);
}

/*
 * Taskq routine to free up name cache entries to reduce the
 * cache size to the low water mark if "reduce_percent" is not provided.
 * If "reduce_percent" is provided, reduce cache size by
 * (ncsize_onepercent * reduce_percent).
 */
/*ARGSUSED*/
static void
do_dnlc_reduce_cache(void *reduce_percent)
{
	nc_hash_t *hp = dnlc_free_rotor, *start_hp = hp;
	vnode_t *vp;
	ncache_t *ncp;
	int cnt;
	uint_t low_water = dnlc_nentries_low_water;

	if (reduce_percent) {
		uint_t reduce_cnt;

		/*
		 * Never try to reduce the current number
		 * of cache entries below 3% of ncsize.
		 */
		if (dnlc_nentries <= ncsize_min_percent) {
			dnlc_reduce_idle = 1;
			return;
		}
		reduce_cnt = ncsize_onepercent *
		    (uint_t)(uintptr_t)reduce_percent;

		if (reduce_cnt > dnlc_nentries ||
		    dnlc_nentries - reduce_cnt < ncsize_min_percent)
			low_water = ncsize_min_percent;
		else
			low_water = dnlc_nentries - reduce_cnt;
	}

	do {
		/*
		 * Find the first non empty hash queue without locking.
		 * Only look at each hash queue once to avoid an infinite loop.
		 */
		do {
			if (++hp == &nc_hash[nc_hashsz])
				hp = nc_hash;
		} while (hp->hash_next == (ncache_t *)hp && hp != start_hp);

		/* return if all hash queues are empty. */
		if (hp->hash_next == (ncache_t *)hp) {
			dnlc_reduce_idle = 1;
			return;
		}

		mutex_enter(&hp->hash_lock);
		for (cnt = 0, ncp = hp->hash_prev; ncp != (ncache_t *)hp;
		    ncp = ncp->hash_prev, cnt++) {
			vp = ncp->vp;
			/*
			 * A name cache entry with a reference count
			 * of one is only referenced by the dnlc.
			 * Also negative cache entries are purged first.
			 */
			if (!vn_has_cached_data(vp) &&
			    ((vp->v_count == 1) || (vp == DNLC_NO_VNODE))) {
				ncs.ncs_pick_heur.value.ui64++;
				goto found;
			}
			/*
			 * Remove from the end of the chain if the
			 * chain is too long
			 */
			if (cnt > dnlc_long_chain) {
				ncp = hp->hash_prev;
				ncs.ncs_pick_last.value.ui64++;
				vp = ncp->vp;
				goto found;
			}
		}
		/* check for race and continue */
		if (hp->hash_next == (ncache_t *)hp) {
			mutex_exit(&hp->hash_lock);
			continue;
		}

		ncp = hp->hash_prev; /* pick the last one in the hash queue */
		ncs.ncs_pick_last.value.ui64++;
		vp = ncp->vp;
found:
		/*
		 * Remove from hash chain.
		 */
		nc_rmhash(ncp);
		mutex_exit(&hp->hash_lock);
		VN_RELE_DNLC(vp);
		VN_RELE_DNLC(ncp->dp);
		dnlc_free(ncp);
	} while (dnlc_nentries > low_water);

	dnlc_free_rotor = hp;
	dnlc_reduce_idle = 1;
}

/*
 * Directory caching routines
 * ==========================
 *
 * See dnlc.h for details of the interfaces below.
 */

/*
 * Lookup up an entry in a complete or partial directory cache.
 */
dcret_t
dnlc_dir_lookup(dcanchor_t *dcap, const char *name, uint64_t *handle)
{
	dircache_t *dcp;
	dcentry_t *dep;
	int hash;
	int ret;
	uchar_t namlen;

	/*
	 * can test without lock as we are only a cache
	 */
	if (!VALID_DIR_CACHE(dcap->dca_dircache)) {
		ncs.ncs_dir_misses.value.ui64++;
		return (DNOCACHE);
	}

	if (!dnlc_dir_enable) {
		return (DNOCACHE);
	}

	mutex_enter(&dcap->dca_lock);
	dcp = (dircache_t *)dcap->dca_dircache;
	if (VALID_DIR_CACHE(dcp)) {
		dcp->dc_actime = ddi_get_lbolt64();
		DNLC_DIR_HASH(name, hash, namlen);
		dep = dcp->dc_namehash[hash & dcp->dc_nhash_mask];
		while (dep != NULL) {
			if ((dep->de_hash == hash) &&
			    (namlen == dep->de_namelen) &&
			    bcmp(dep->de_name, name, namlen) == 0) {
				*handle = dep->de_handle;
				mutex_exit(&dcap->dca_lock);
				ncs.ncs_dir_hits.value.ui64++;
				return (DFOUND);
			}
			dep = dep->de_next;
		}
		if (dcp->dc_complete) {
			ret = DNOENT;
		} else {
			ret = DNOCACHE;
		}
		mutex_exit(&dcap->dca_lock);
		return (ret);
	} else {
		mutex_exit(&dcap->dca_lock);
		ncs.ncs_dir_misses.value.ui64++;
		return (DNOCACHE);
	}
}

/*
 * Start a new directory cache. An estimate of the number of
 * entries is provided to as a quick check to ensure the directory
 * is cacheable.
 */
dcret_t
dnlc_dir_start(dcanchor_t *dcap, uint_t num_entries)
{
	dircache_t *dcp;

	if (!dnlc_dir_enable ||
	    (num_entries < dnlc_dir_min_size)) {
		return (DNOCACHE);
	}

	if (num_entries > dnlc_dir_max_size) {
		return (DTOOBIG);
	}

	mutex_enter(&dc_head.dch_lock);
	mutex_enter(&dcap->dca_lock);

	if (dcap->dca_dircache == DC_RET_LOW_MEM) {
		dcap->dca_dircache = NULL;
		mutex_exit(&dcap->dca_lock);
		mutex_exit(&dc_head.dch_lock);
		return (DNOMEM);
	}

	/*
	 * Check if there's currently a cache.
	 * This probably only occurs on a race.
	 */
	if (dcap->dca_dircache != NULL) {
		mutex_exit(&dcap->dca_lock);
		mutex_exit(&dc_head.dch_lock);
		return (DNOCACHE);
	}

	/*
	 * Allocate the dircache struct, entry and free space hash tables.
	 * These tables are initially just one entry but dynamically resize
	 * when entries and free space are added or removed.
	 */
	if ((dcp = kmem_zalloc(sizeof (dircache_t), KM_NOSLEEP)) == NULL) {
		goto error;
	}
	if ((dcp->dc_namehash = kmem_zalloc(sizeof (dcentry_t *),
	    KM_NOSLEEP)) == NULL) {
		goto error;
	}
	if ((dcp->dc_freehash = kmem_zalloc(sizeof (dcfree_t *),
	    KM_NOSLEEP)) == NULL) {
		goto error;
	}

	dcp->dc_anchor = dcap; /* set back pointer to anchor */
	dcap->dca_dircache = dcp;

	/* add into head of global chain */
	dcp->dc_next = dc_head.dch_next;
	dcp->dc_prev = (dircache_t *)&dc_head;
	dcp->dc_next->dc_prev = dcp;
	dc_head.dch_next = dcp;

	mutex_exit(&dcap->dca_lock);
	mutex_exit(&dc_head.dch_lock);
	ncs.ncs_cur_dirs.value.ui64++;
	ncs.ncs_dirs_cached.value.ui64++;
	return (DOK);
error:
	if (dcp != NULL) {
		if (dcp->dc_namehash) {
			kmem_free(dcp->dc_namehash, sizeof (dcentry_t *));
		}
		kmem_free(dcp, sizeof (dircache_t));
	}
	/*
	 * Must also kmem_free dcp->dc_freehash if more error cases are added
	 */
	mutex_exit(&dcap->dca_lock);
	mutex_exit(&dc_head.dch_lock);
	ncs.ncs_dir_start_nm.value.ui64++;
	return (DNOCACHE);
}

/*
 * Add a directopry entry to a partial or complete directory cache.
 */
dcret_t
dnlc_dir_add_entry(dcanchor_t *dcap, const char *name, uint64_t handle)
{
	dircache_t *dcp;
	dcentry_t **hp, *dep;
	int hash;
	uint_t capacity;
	uchar_t namlen;

	/*
	 * Allocate the dcentry struct, including the variable
	 * size name. Note, the null terminator is not copied.
	 *
	 * We do this outside the lock to avoid possible deadlock if
	 * dnlc_dir_reclaim() is called as a result of memory shortage.
	 */
	DNLC_DIR_HASH(name, hash, namlen);
	dep = kmem_alloc(sizeof (dcentry_t) - 1 + namlen, KM_NOSLEEP);
	if (dep == NULL) {
#ifdef DEBUG
		/*
		 * The kmem allocator generates random failures for
		 * KM_NOSLEEP calls (see KMEM_RANDOM_ALLOCATION_FAILURE)
		 * So try again before we blow away a perfectly good cache.
		 * This is done not to cover an error but purely for
		 * performance running a debug kernel.
		 * This random error only occurs in debug mode.
		 */
		dep = kmem_alloc(sizeof (dcentry_t) - 1 + namlen, KM_NOSLEEP);
		if (dep != NULL)
			goto ok;
#endif
		ncs.ncs_dir_add_nm.value.ui64++;
		/*
		 * Free a directory cache. This may be the one we are
		 * called with.
		 */
		dnlc_dir_reclaim(NULL);
		dep = kmem_alloc(sizeof (dcentry_t) - 1 + namlen, KM_NOSLEEP);
		if (dep == NULL) {
			/*
			 * still no memory, better delete this cache
			 */
			mutex_enter(&dcap->dca_lock);
			dcp = (dircache_t *)dcap->dca_dircache;
			if (VALID_DIR_CACHE(dcp)) {
				dnlc_dir_abort(dcp);
				dcap->dca_dircache = DC_RET_LOW_MEM;
			}
			mutex_exit(&dcap->dca_lock);
			ncs.ncs_dir_addabort.value.ui64++;
			return (DNOCACHE);
		}
		/*
		 * fall through as if the 1st kmem_alloc had worked
		 */
	}
#ifdef DEBUG
ok:
#endif
	mutex_enter(&dcap->dca_lock);
	dcp = (dircache_t *)dcap->dca_dircache;
	if (VALID_DIR_CACHE(dcp)) {
		/*
		 * If the total number of entries goes above the max
		 * then free this cache
		 */
		if ((dcp->dc_num_entries + dcp->dc_num_free) >
		    dnlc_dir_max_size) {
			mutex_exit(&dcap->dca_lock);
			dnlc_dir_purge(dcap);
			kmem_free(dep, sizeof (dcentry_t) - 1 + namlen);
			ncs.ncs_dir_add_max.value.ui64++;
			return (DTOOBIG);
		}
		dcp->dc_num_entries++;
		capacity = (dcp->dc_nhash_mask + 1) << dnlc_dir_hash_size_shift;
		if (dcp->dc_num_entries >=
		    (capacity << dnlc_dir_hash_resize_shift)) {
			dnlc_dir_adjust_nhash(dcp);
		}
		hp = &dcp->dc_namehash[hash & dcp->dc_nhash_mask];

		/*
		 * Initialise and chain in new entry
		 */
		dep->de_handle = handle;
		dep->de_hash = hash;
		/*
		 * Note de_namelen is a uchar_t to conserve space
		 * and alignment padding. The max length of any
		 * pathname component is defined as MAXNAMELEN
		 * which is 256 (including the terminating null).
		 * So provided this doesn't change, we don't include the null,
		 * we always use bcmp to compare strings, and we don't
		 * start storing full names, then we are ok.
		 * The space savings is worth it.
		 */
		dep->de_namelen = namlen;
		bcopy(name, dep->de_name, namlen);
		dep->de_next = *hp;
		*hp = dep;
		dcp->dc_actime = ddi_get_lbolt64();
		mutex_exit(&dcap->dca_lock);
		ncs.ncs_dir_num_ents.value.ui64++;
		return (DOK);
	} else {
		mutex_exit(&dcap->dca_lock);
		kmem_free(dep, sizeof (dcentry_t) - 1 + namlen);
		return (DNOCACHE);
	}
}

/*
 * Add free space to a partial or complete directory cache.
 */
dcret_t
dnlc_dir_add_space(dcanchor_t *dcap, uint_t len, uint64_t handle)
{
	dircache_t *dcp;
	dcfree_t *dfp, **hp;
	uint_t capacity;

	/*
	 * We kmem_alloc outside the lock to avoid possible deadlock if
	 * dnlc_dir_reclaim() is called as a result of memory shortage.
	 */
	dfp = kmem_cache_alloc(dnlc_dir_space_cache, KM_NOSLEEP);
	if (dfp == NULL) {
#ifdef DEBUG
		/*
		 * The kmem allocator generates random failures for
		 * KM_NOSLEEP calls (see KMEM_RANDOM_ALLOCATION_FAILURE)
		 * So try again before we blow away a perfectly good cache.
		 * This random error only occurs in debug mode
		 */
		dfp = kmem_cache_alloc(dnlc_dir_space_cache, KM_NOSLEEP);
		if (dfp != NULL)
			goto ok;
#endif
		ncs.ncs_dir_add_nm.value.ui64++;
		/*
		 * Free a directory cache. This may be the one we are
		 * called with.
		 */
		dnlc_dir_reclaim(NULL);
		dfp = kmem_cache_alloc(dnlc_dir_space_cache, KM_NOSLEEP);
		if (dfp == NULL) {
			/*
			 * still no memory, better delete this cache
			 */
			mutex_enter(&dcap->dca_lock);
			dcp = (dircache_t *)dcap->dca_dircache;
			if (VALID_DIR_CACHE(dcp)) {
				dnlc_dir_abort(dcp);
				dcap->dca_dircache = DC_RET_LOW_MEM;
			}
			mutex_exit(&dcap->dca_lock);
			ncs.ncs_dir_addabort.value.ui64++;
			return (DNOCACHE);
		}
		/*
		 * fall through as if the 1st kmem_alloc had worked
		 */
	}

#ifdef DEBUG
ok:
#endif
	mutex_enter(&dcap->dca_lock);
	dcp = (dircache_t *)dcap->dca_dircache;
	if (VALID_DIR_CACHE(dcp)) {
		if ((dcp->dc_num_entries + dcp->dc_num_free) >
		    dnlc_dir_max_size) {
			mutex_exit(&dcap->dca_lock);
			dnlc_dir_purge(dcap);
			kmem_cache_free(dnlc_dir_space_cache, dfp);
			ncs.ncs_dir_add_max.value.ui64++;
			return (DTOOBIG);
		}
		dcp->dc_num_free++;
		capacity = (dcp->dc_fhash_mask + 1) << dnlc_dir_hash_size_shift;
		if (dcp->dc_num_free >=
		    (capacity << dnlc_dir_hash_resize_shift)) {
			dnlc_dir_adjust_fhash(dcp);
		}
		/*
		 * Initialise and chain a new entry
		 */
		dfp->df_handle = handle;
		dfp->df_len = len;
		dcp->dc_actime = ddi_get_lbolt64();
		hp = &(dcp->dc_freehash[DDFHASH(handle, dcp)]);
		dfp->df_next = *hp;
		*hp = dfp;
		mutex_exit(&dcap->dca_lock);
		ncs.ncs_dir_num_ents.value.ui64++;
		return (DOK);
	} else {
		mutex_exit(&dcap->dca_lock);
		kmem_cache_free(dnlc_dir_space_cache, dfp);
		return (DNOCACHE);
	}
}

/*
 * Mark a directory cache as complete.
 */
void
dnlc_dir_complete(dcanchor_t *dcap)
{
	dircache_t *dcp;

	mutex_enter(&dcap->dca_lock);
	dcp = (dircache_t *)dcap->dca_dircache;
	if (VALID_DIR_CACHE(dcp)) {
		dcp->dc_complete = B_TRUE;
	}
	mutex_exit(&dcap->dca_lock);
}

/*
 * Internal routine to delete a partial or full directory cache.
 * No additional locking needed.
 */
static void
dnlc_dir_abort(dircache_t *dcp)
{
	dcentry_t *dep, *nhp;
	dcfree_t *fep, *fhp;
	uint_t nhtsize = dcp->dc_nhash_mask + 1; /* name hash table size */
	uint_t fhtsize = dcp->dc_fhash_mask + 1; /* free hash table size */
	uint_t i;

	/*
	 * Free up the cached name entries and hash table
	 */
	for (i = 0; i < nhtsize; i++) { /* for each hash bucket */
		nhp = dcp->dc_namehash[i];
		while (nhp != NULL) { /* for each chained entry */
			dep = nhp->de_next;
			kmem_free(nhp, sizeof (dcentry_t) - 1 +
			    nhp->de_namelen);
			nhp = dep;
		}
	}
	kmem_free(dcp->dc_namehash, sizeof (dcentry_t *) * nhtsize);

	/*
	 * Free up the free space entries and hash table
	 */
	for (i = 0; i < fhtsize; i++) { /* for each hash bucket */
		fhp = dcp->dc_freehash[i];
		while (fhp != NULL) { /* for each chained entry */
			fep = fhp->df_next;
			kmem_cache_free(dnlc_dir_space_cache, fhp);
			fhp = fep;
		}
	}
	kmem_free(dcp->dc_freehash, sizeof (dcfree_t *) * fhtsize);

	/*
	 * Finally free the directory cache structure itself
	 */
	ncs.ncs_dir_num_ents.value.ui64 -= (dcp->dc_num_entries +
	    dcp->dc_num_free);
	kmem_free(dcp, sizeof (dircache_t));
	ncs.ncs_cur_dirs.value.ui64--;
}

/*
 * Remove a partial or complete directory cache
 */
void
dnlc_dir_purge(dcanchor_t *dcap)
{
	dircache_t *dcp;

	mutex_enter(&dc_head.dch_lock);
	mutex_enter(&dcap->dca_lock);
	dcp = (dircache_t *)dcap->dca_dircache;
	if (!VALID_DIR_CACHE(dcp)) {
		mutex_exit(&dcap->dca_lock);
		mutex_exit(&dc_head.dch_lock);
		return;
	}
	dcap->dca_dircache = NULL;
	/*
	 * Unchain from global list
	 */
	dcp->dc_prev->dc_next = dcp->dc_next;
	dcp->dc_next->dc_prev = dcp->dc_prev;
	mutex_exit(&dcap->dca_lock);
	mutex_exit(&dc_head.dch_lock);
	dnlc_dir_abort(dcp);
}

/*
 * Remove an entry from a complete or partial directory cache.
 * Return the handle if it's non null.
 */
dcret_t
dnlc_dir_rem_entry(dcanchor_t *dcap, const char *name, uint64_t *handlep)
{
	dircache_t *dcp;
	dcentry_t **prevpp, *te;
	uint_t capacity;
	int hash;
	int ret;
	uchar_t namlen;

	if (!dnlc_dir_enable) {
		return (DNOCACHE);
	}

	mutex_enter(&dcap->dca_lock);
	dcp = (dircache_t *)dcap->dca_dircache;
	if (VALID_DIR_CACHE(dcp)) {
		dcp->dc_actime = ddi_get_lbolt64();
		if (dcp->dc_nhash_mask > 0) { /* ie not minimum */
			capacity = (dcp->dc_nhash_mask + 1) <<
			    dnlc_dir_hash_size_shift;
			if (dcp->dc_num_entries <=
			    (capacity >> dnlc_dir_hash_resize_shift)) {
				dnlc_dir_adjust_nhash(dcp);
			}
		}
		DNLC_DIR_HASH(name, hash, namlen);
		prevpp = &dcp->dc_namehash[hash & dcp->dc_nhash_mask];
		while (*prevpp != NULL) {
			if (((*prevpp)->de_hash == hash) &&
			    (namlen == (*prevpp)->de_namelen) &&
			    bcmp((*prevpp)->de_name, name, namlen) == 0) {
				if (handlep != NULL) {
					*handlep = (*prevpp)->de_handle;
				}
				te = *prevpp;
				*prevpp = (*prevpp)->de_next;
				kmem_free(te, sizeof (dcentry_t) - 1 +
				    te->de_namelen);

				/*
				 * If the total number of entries
				 * falls below half the minimum number
				 * of entries then free this cache.
				 */
				if (--dcp->dc_num_entries <
				    (dnlc_dir_min_size >> 1)) {
					mutex_exit(&dcap->dca_lock);
					dnlc_dir_purge(dcap);
				} else {
					mutex_exit(&dcap->dca_lock);
				}
				ncs.ncs_dir_num_ents.value.ui64--;
				return (DFOUND);
			}
			prevpp = &((*prevpp)->de_next);
		}
		if (dcp->dc_complete) {
			ncs.ncs_dir_reme_fai.value.ui64++;
			ret = DNOENT;
		} else {
			ret = DNOCACHE;
		}
		mutex_exit(&dcap->dca_lock);
		return (ret);
	} else {
		mutex_exit(&dcap->dca_lock);
		return (DNOCACHE);
	}
}


/*
 * Remove free space of at least the given length from a complete
 * or partial directory cache.
 */
dcret_t
dnlc_dir_rem_space_by_len(dcanchor_t *dcap, uint_t len, uint64_t *handlep)
{
	dircache_t *dcp;
	dcfree_t **prevpp, *tfp;
	uint_t fhtsize; /* free hash table size */
	uint_t i;
	uint_t capacity;
	int ret;

	if (!dnlc_dir_enable) {
		return (DNOCACHE);
	}

	mutex_enter(&dcap->dca_lock);
	dcp = (dircache_t *)dcap->dca_dircache;
	if (VALID_DIR_CACHE(dcp)) {
		dcp->dc_actime = ddi_get_lbolt64();
		if (dcp->dc_fhash_mask > 0) { /* ie not minimum */
			capacity = (dcp->dc_fhash_mask + 1) <<
			    dnlc_dir_hash_size_shift;
			if (dcp->dc_num_free <=
			    (capacity >> dnlc_dir_hash_resize_shift)) {
				dnlc_dir_adjust_fhash(dcp);
			}
		}
		/*
		 * Search for an entry of the appropriate size
		 * on a first fit basis.
		 */
		fhtsize = dcp->dc_fhash_mask + 1;
		for (i = 0; i < fhtsize; i++) { /* for each hash bucket */
			prevpp = &(dcp->dc_freehash[i]);
			while (*prevpp != NULL) {
				if ((*prevpp)->df_len >= len) {
					*handlep = (*prevpp)->df_handle;
					tfp = *prevpp;
					*prevpp = (*prevpp)->df_next;
					dcp->dc_num_free--;
					mutex_exit(&dcap->dca_lock);
					kmem_cache_free(dnlc_dir_space_cache,
					    tfp);
					ncs.ncs_dir_num_ents.value.ui64--;
					return (DFOUND);
				}
				prevpp = &((*prevpp)->df_next);
			}
		}
		if (dcp->dc_complete) {
			ret = DNOENT;
		} else {
			ret = DNOCACHE;
		}
		mutex_exit(&dcap->dca_lock);
		return (ret);
	} else {
		mutex_exit(&dcap->dca_lock);
		return (DNOCACHE);
	}
}

/*
 * Remove free space with the given handle from a complete or partial
 * directory cache.
 */
dcret_t
dnlc_dir_rem_space_by_handle(dcanchor_t *dcap, uint64_t handle)
{
	dircache_t *dcp;
	dcfree_t **prevpp, *tfp;
	uint_t capacity;
	int ret;

	if (!dnlc_dir_enable) {
		return (DNOCACHE);
	}

	mutex_enter(&dcap->dca_lock);
	dcp = (dircache_t *)dcap->dca_dircache;
	if (VALID_DIR_CACHE(dcp)) {
		dcp->dc_actime = ddi_get_lbolt64();
		if (dcp->dc_fhash_mask > 0) { /* ie not minimum */
			capacity = (dcp->dc_fhash_mask + 1) <<
			    dnlc_dir_hash_size_shift;
			if (dcp->dc_num_free <=
			    (capacity >> dnlc_dir_hash_resize_shift)) {
				dnlc_dir_adjust_fhash(dcp);
			}
		}

		/*
		 * search for the exact entry
		 */
		prevpp = &(dcp->dc_freehash[DDFHASH(handle, dcp)]);
		while (*prevpp != NULL) {
			if ((*prevpp)->df_handle == handle) {
				tfp = *prevpp;
				*prevpp = (*prevpp)->df_next;
				dcp->dc_num_free--;
				mutex_exit(&dcap->dca_lock);
				kmem_cache_free(dnlc_dir_space_cache, tfp);
				ncs.ncs_dir_num_ents.value.ui64--;
				return (DFOUND);
			}
			prevpp = &((*prevpp)->df_next);
		}
		if (dcp->dc_complete) {
			ncs.ncs_dir_rems_fai.value.ui64++;
			ret = DNOENT;
		} else {
			ret = DNOCACHE;
		}
		mutex_exit(&dcap->dca_lock);
		return (ret);
	} else {
		mutex_exit(&dcap->dca_lock);
		return (DNOCACHE);
	}
}

/*
 * Update the handle of an directory cache entry.
 */
dcret_t
dnlc_dir_update(dcanchor_t *dcap, const char *name, uint64_t handle)
{
	dircache_t *dcp;
	dcentry_t *dep;
	int hash;
	int ret;
	uchar_t namlen;

	if (!dnlc_dir_enable) {
		return (DNOCACHE);
	}

	mutex_enter(&dcap->dca_lock);
	dcp = (dircache_t *)dcap->dca_dircache;
	if (VALID_DIR_CACHE(dcp)) {
		dcp->dc_actime = ddi_get_lbolt64();
		DNLC_DIR_HASH(name, hash, namlen);
		dep = dcp->dc_namehash[hash & dcp->dc_nhash_mask];
		while (dep != NULL) {
			if ((dep->de_hash == hash) &&
			    (namlen == dep->de_namelen) &&
			    bcmp(dep->de_name, name, namlen) == 0) {
				dep->de_handle = handle;
				mutex_exit(&dcap->dca_lock);
				return (DFOUND);
			}
			dep = dep->de_next;
		}
		if (dcp->dc_complete) {
			ncs.ncs_dir_upd_fail.value.ui64++;
			ret = DNOENT;
		} else {
			ret = DNOCACHE;
		}
		mutex_exit(&dcap->dca_lock);
		return (ret);
	} else {
		mutex_exit(&dcap->dca_lock);
		return (DNOCACHE);
	}
}

void
dnlc_dir_fini(dcanchor_t *dcap)
{
	dircache_t *dcp;

	mutex_enter(&dc_head.dch_lock);
	mutex_enter(&dcap->dca_lock);
	dcp = (dircache_t *)dcap->dca_dircache;
	if (VALID_DIR_CACHE(dcp)) {
		/*
		 * Unchain from global list
		 */
		ncs.ncs_dir_finipurg.value.ui64++;
		dcp->dc_prev->dc_next = dcp->dc_next;
		dcp->dc_next->dc_prev = dcp->dc_prev;
	} else {
		dcp = NULL;
	}
	dcap->dca_dircache = NULL;
	mutex_exit(&dcap->dca_lock);
	mutex_exit(&dc_head.dch_lock);
	mutex_destroy(&dcap->dca_lock);
	if (dcp) {
		dnlc_dir_abort(dcp);
	}
}

/*
 * Reclaim callback for dnlc directory caching.
 * Invoked by the kernel memory allocator when memory gets tight.
 * This is a pretty serious condition and can lead easily lead to system
 * hangs if not enough space is returned.
 *
 * Deciding which directory (or directories) to purge is tricky.
 * Purging everything is an overkill, but purging just the oldest used
 * was found to lead to hangs. The largest cached directories use the
 * most memory, but take the most effort to rebuild, whereas the smaller
 * ones have little value and give back little space. So what to do?
 *
 * The current policy is to continue purging the oldest used directories
 * until at least dnlc_dir_min_reclaim directory entries have been purged.
 */
/*ARGSUSED*/
static void
dnlc_dir_reclaim(void *unused)
{
	dircache_t *dcp, *oldest;
	uint_t dirent_cnt = 0;

	mutex_enter(&dc_head.dch_lock);
	while (dirent_cnt < dnlc_dir_min_reclaim) {
		dcp = dc_head.dch_next;
		oldest = NULL;
		while (dcp != (dircache_t *)&dc_head) {
			if (oldest == NULL) {
				oldest = dcp;
			} else {
				if (dcp->dc_actime < oldest->dc_actime) {
					oldest = dcp;
				}
			}
			dcp = dcp->dc_next;
		}
		if (oldest == NULL) {
			/* nothing to delete */
			mutex_exit(&dc_head.dch_lock);
			return;
		}
		/*
		 * remove from directory chain and purge
		 */
		oldest->dc_prev->dc_next = oldest->dc_next;
		oldest->dc_next->dc_prev = oldest->dc_prev;
		mutex_enter(&oldest->dc_anchor->dca_lock);
		/*
		 * If this was the last entry then it must be too large.
		 * Mark it as such by saving a special dircache_t
		 * pointer (DC_RET_LOW_MEM) in the anchor. The error DNOMEM
		 * will be presented to the caller of dnlc_dir_start()
		 */
		if (oldest->dc_next == oldest->dc_prev) {
			oldest->dc_anchor->dca_dircache = DC_RET_LOW_MEM;
			ncs.ncs_dir_rec_last.value.ui64++;
		} else {
			oldest->dc_anchor->dca_dircache = NULL;
			ncs.ncs_dir_recl_any.value.ui64++;
		}
		mutex_exit(&oldest->dc_anchor->dca_lock);
		dirent_cnt += oldest->dc_num_entries;
		dnlc_dir_abort(oldest);
	}
	mutex_exit(&dc_head.dch_lock);
}

/*
 * Dynamically grow or shrink the size of the name hash table
 */
static void
dnlc_dir_adjust_nhash(dircache_t *dcp)
{
	dcentry_t **newhash, *dep, **nhp, *tep;
	uint_t newsize;
	uint_t oldsize;
	uint_t newsizemask;
	int i;

	/*
	 * Allocate new hash table
	 */
	newsize = dcp->dc_num_entries >> dnlc_dir_hash_size_shift;
	newhash = kmem_zalloc(sizeof (dcentry_t *) * newsize, KM_NOSLEEP);
	if (newhash == NULL) {
		/*
		 * System is short on memory just return
		 * Note, the old hash table is still usable.
		 * This return is unlikely to repeatedy occur, because
		 * either some other directory caches will be reclaimed
		 * due to memory shortage, thus freeing memory, or this
		 * directory cahe will be reclaimed.
		 */
		return;
	}
	oldsize = dcp->dc_nhash_mask + 1;
	dcp->dc_nhash_mask = newsizemask = newsize - 1;

	/*
	 * Move entries from the old table to the new
	 */
	for (i = 0; i < oldsize; i++) { /* for each hash bucket */
		dep = dcp->dc_namehash[i];
		while (dep != NULL) { /* for each chained entry */
			tep = dep;
			dep = dep->de_next;
			nhp = &newhash[tep->de_hash & newsizemask];
			tep->de_next = *nhp;
			*nhp = tep;
		}
	}

	/*
	 * delete old hash table and set new one in place
	 */
	kmem_free(dcp->dc_namehash, sizeof (dcentry_t *) * oldsize);
	dcp->dc_namehash = newhash;
}

/*
 * Dynamically grow or shrink the size of the free space hash table
 */
static void
dnlc_dir_adjust_fhash(dircache_t *dcp)
{
	dcfree_t **newhash, *dfp, **nhp, *tfp;
	uint_t newsize;
	uint_t oldsize;
	int i;

	/*
	 * Allocate new hash table
	 */
	newsize = dcp->dc_num_free >> dnlc_dir_hash_size_shift;
	newhash = kmem_zalloc(sizeof (dcfree_t *) * newsize, KM_NOSLEEP);
	if (newhash == NULL) {
		/*
		 * System is short on memory just return
		 * Note, the old hash table is still usable.
		 * This return is unlikely to repeatedy occur, because
		 * either some other directory caches will be reclaimed
		 * due to memory shortage, thus freeing memory, or this
		 * directory cahe will be reclaimed.
		 */
		return;
	}
	oldsize = dcp->dc_fhash_mask + 1;
	dcp->dc_fhash_mask = newsize - 1;

	/*
	 * Move entries from the old table to the new
	 */
	for (i = 0; i < oldsize; i++) { /* for each hash bucket */
		dfp = dcp->dc_freehash[i];
		while (dfp != NULL) { /* for each chained entry */
			tfp = dfp;
			dfp = dfp->df_next;
			nhp = &newhash[DDFHASH(tfp->df_handle, dcp)];
			tfp->df_next = *nhp;
			*nhp = tfp;
		}
	}

	/*
	 * delete old hash table and set new one in place
	 */
	kmem_free(dcp->dc_freehash, sizeof (dcfree_t *) * oldsize);
	dcp->dc_freehash = newhash;
}
