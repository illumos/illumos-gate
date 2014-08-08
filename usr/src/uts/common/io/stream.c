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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/thread.h>
#include <sys/sysmacros.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/errno.h>
#include <sys/vtrace.h>
#include <sys/ftrace.h>
#include <sys/ontrap.h>
#include <sys/multidata.h>
#include <sys/multidata_impl.h>
#include <sys/sdt.h>
#include <sys/strft.h>

#ifdef DEBUG
#include <sys/kmem_impl.h>
#endif

/*
 * This file contains all the STREAMS utility routines that may
 * be used by modules and drivers.
 */

/*
 * STREAMS message allocator: principles of operation
 *
 * The streams message allocator consists of all the routines that
 * allocate, dup and free streams messages: allocb(), [d]esballoc[a],
 * dupb(), freeb() and freemsg().  What follows is a high-level view
 * of how the allocator works.
 *
 * Every streams message consists of one or more mblks, a dblk, and data.
 * All mblks for all types of messages come from a common mblk_cache.
 * The dblk and data come in several flavors, depending on how the
 * message is allocated:
 *
 * (1) mblks up to DBLK_MAX_CACHE size are allocated from a collection of
 *     fixed-size dblk/data caches. For message sizes that are multiples of
 *     PAGESIZE, dblks are allocated separately from the buffer.
 *     The associated buffer is allocated by the constructor using kmem_alloc().
 *     For all other message sizes, dblk and its associated data is allocated
 *     as a single contiguous chunk of memory.
 *     Objects in these caches consist of a dblk plus its associated data.
 *     allocb() determines the nearest-size cache by table lookup:
 *     the dblk_cache[] array provides the mapping from size to dblk cache.
 *
 * (2) Large messages (size > DBLK_MAX_CACHE) are constructed by
 *     kmem_alloc()'ing a buffer for the data and supplying that
 *     buffer to gesballoc(), described below.
 *
 * (3) The four flavors of [d]esballoc[a] are all implemented by a
 *     common routine, gesballoc() ("generic esballoc").  gesballoc()
 *     allocates a dblk from the global dblk_esb_cache and sets db_base,
 *     db_lim and db_frtnp to describe the caller-supplied buffer.
 *
 * While there are several routines to allocate messages, there is only
 * one routine to free messages: freeb().  freeb() simply invokes the
 * dblk's free method, dbp->db_free(), which is set at allocation time.
 *
 * dupb() creates a new reference to a message by allocating a new mblk,
 * incrementing the dblk reference count and setting the dblk's free
 * method to dblk_decref().  The dblk's original free method is retained
 * in db_lastfree.  dblk_decref() decrements the reference count on each
 * freeb().  If this is not the last reference it just frees the mblk;
 * if this *is* the last reference, it restores db_free to db_lastfree,
 * sets db_mblk to the current mblk (see below), and invokes db_lastfree.
 *
 * The implementation makes aggressive use of kmem object caching for
 * maximum performance.  This makes the code simple and compact, but
 * also a bit abstruse in some places.  The invariants that constitute a
 * message's constructed state, described below, are more subtle than usual.
 *
 * Every dblk has an "attached mblk" as part of its constructed state.
 * The mblk is allocated by the dblk's constructor and remains attached
 * until the message is either dup'ed or pulled up.  In the dupb() case
 * the mblk association doesn't matter until the last free, at which time
 * dblk_decref() attaches the last mblk to the dblk.  pullupmsg() affects
 * the mblk association because it swaps the leading mblks of two messages,
 * so it is responsible for swapping their db_mblk pointers accordingly.
 * From a constructed-state viewpoint it doesn't matter that a dblk's
 * attached mblk can change while the message is allocated; all that
 * matters is that the dblk has *some* attached mblk when it's freed.
 *
 * The sizes of the allocb() small-message caches are not magical.
 * They represent a good trade-off between internal and external
 * fragmentation for current workloads.  They should be reevaluated
 * periodically, especially if allocations larger than DBLK_MAX_CACHE
 * become common.  We use 64-byte alignment so that dblks don't
 * straddle cache lines unnecessarily.
 */
#define	DBLK_MAX_CACHE		73728
#define	DBLK_CACHE_ALIGN	64
#define	DBLK_MIN_SIZE		8
#define	DBLK_SIZE_SHIFT		3

#ifdef _BIG_ENDIAN
#define	DBLK_RTFU_SHIFT(field)	\
	(8 * (&((dblk_t *)0)->db_struioflag - &((dblk_t *)0)->field))
#else
#define	DBLK_RTFU_SHIFT(field)	\
	(8 * (&((dblk_t *)0)->field - &((dblk_t *)0)->db_ref))
#endif

#define	DBLK_RTFU(ref, type, flags, uioflag)	\
	(((ref) << DBLK_RTFU_SHIFT(db_ref)) | \
	((type) << DBLK_RTFU_SHIFT(db_type)) | \
	(((flags) | (ref - 1)) << DBLK_RTFU_SHIFT(db_flags)) | \
	((uioflag) << DBLK_RTFU_SHIFT(db_struioflag)))
#define	DBLK_RTFU_REF_MASK	(DBLK_REFMAX << DBLK_RTFU_SHIFT(db_ref))
#define	DBLK_RTFU_WORD(dbp)	(*((uint32_t *)&(dbp)->db_ref))
#define	MBLK_BAND_FLAG_WORD(mp)	(*((uint32_t *)&(mp)->b_band))

static size_t dblk_sizes[] = {
#ifdef _LP64
	16, 80, 144, 208, 272, 336, 528, 1040, 1488, 1936, 2576, 3856,
	8192, 12048, 16384, 20240, 24576, 28432, 32768, 36624,
	40960, 44816, 49152, 53008, 57344, 61200, 65536, 69392,
#else
	64, 128, 320, 576, 1088, 1536, 1984, 2624, 3904,
	8192, 12096, 16384, 20288, 24576, 28480, 32768, 36672,
	40960, 44864, 49152, 53056, 57344, 61248, 65536, 69440,
#endif
	DBLK_MAX_CACHE, 0
};

static struct kmem_cache *dblk_cache[DBLK_MAX_CACHE / DBLK_MIN_SIZE];
static struct kmem_cache *mblk_cache;
static struct kmem_cache *dblk_esb_cache;
static struct kmem_cache *fthdr_cache;
static struct kmem_cache *ftblk_cache;

static void dblk_lastfree(mblk_t *mp, dblk_t *dbp);
static mblk_t *allocb_oversize(size_t size, int flags);
static int allocb_tryhard_fails;
static void frnop_func(void *arg);
frtn_t frnop = { frnop_func };
static void bcache_dblk_lastfree(mblk_t *mp, dblk_t *dbp);

static boolean_t rwnext_enter(queue_t *qp);
static void rwnext_exit(queue_t *qp);

/*
 * Patchable mblk/dblk kmem_cache flags.
 */
int dblk_kmem_flags = 0;
int mblk_kmem_flags = 0;

static int
dblk_constructor(void *buf, void *cdrarg, int kmflags)
{
	dblk_t *dbp = buf;
	ssize_t msg_size = (ssize_t)cdrarg;
	size_t index;

	ASSERT(msg_size != 0);

	index = (msg_size - 1) >> DBLK_SIZE_SHIFT;

	ASSERT(index < (DBLK_MAX_CACHE >> DBLK_SIZE_SHIFT));

	if ((dbp->db_mblk = kmem_cache_alloc(mblk_cache, kmflags)) == NULL)
		return (-1);
	if ((msg_size & PAGEOFFSET) == 0) {
		dbp->db_base = kmem_alloc(msg_size, kmflags);
		if (dbp->db_base == NULL) {
			kmem_cache_free(mblk_cache, dbp->db_mblk);
			return (-1);
		}
	} else {
		dbp->db_base = (unsigned char *)&dbp[1];
	}

	dbp->db_mblk->b_datap = dbp;
	dbp->db_cache = dblk_cache[index];
	dbp->db_lim = dbp->db_base + msg_size;
	dbp->db_free = dbp->db_lastfree = dblk_lastfree;
	dbp->db_frtnp = NULL;
	dbp->db_fthdr = NULL;
	dbp->db_credp = NULL;
	dbp->db_cpid = -1;
	dbp->db_struioflag = 0;
	dbp->db_struioun.cksum.flags = 0;
	return (0);
}

/*ARGSUSED*/
static int
dblk_esb_constructor(void *buf, void *cdrarg, int kmflags)
{
	dblk_t *dbp = buf;

	if ((dbp->db_mblk = kmem_cache_alloc(mblk_cache, kmflags)) == NULL)
		return (-1);
	dbp->db_mblk->b_datap = dbp;
	dbp->db_cache = dblk_esb_cache;
	dbp->db_fthdr = NULL;
	dbp->db_credp = NULL;
	dbp->db_cpid = -1;
	dbp->db_struioflag = 0;
	dbp->db_struioun.cksum.flags = 0;
	return (0);
}

static int
bcache_dblk_constructor(void *buf, void *cdrarg, int kmflags)
{
	dblk_t *dbp = buf;
	bcache_t *bcp = cdrarg;

	if ((dbp->db_mblk = kmem_cache_alloc(mblk_cache, kmflags)) == NULL)
		return (-1);

	dbp->db_base = kmem_cache_alloc(bcp->buffer_cache, kmflags);
	if (dbp->db_base == NULL) {
		kmem_cache_free(mblk_cache, dbp->db_mblk);
		return (-1);
	}

	dbp->db_mblk->b_datap = dbp;
	dbp->db_cache = (void *)bcp;
	dbp->db_lim = dbp->db_base + bcp->size;
	dbp->db_free = dbp->db_lastfree = bcache_dblk_lastfree;
	dbp->db_frtnp = NULL;
	dbp->db_fthdr = NULL;
	dbp->db_credp = NULL;
	dbp->db_cpid = -1;
	dbp->db_struioflag = 0;
	dbp->db_struioun.cksum.flags = 0;
	return (0);
}

/*ARGSUSED*/
static void
dblk_destructor(void *buf, void *cdrarg)
{
	dblk_t *dbp = buf;
	ssize_t msg_size = (ssize_t)cdrarg;

	ASSERT(dbp->db_mblk->b_datap == dbp);
	ASSERT(msg_size != 0);
	ASSERT(dbp->db_struioflag == 0);
	ASSERT(dbp->db_struioun.cksum.flags == 0);

	if ((msg_size & PAGEOFFSET) == 0) {
		kmem_free(dbp->db_base, msg_size);
	}

	kmem_cache_free(mblk_cache, dbp->db_mblk);
}

static void
bcache_dblk_destructor(void *buf, void *cdrarg)
{
	dblk_t *dbp = buf;
	bcache_t *bcp = cdrarg;

	kmem_cache_free(bcp->buffer_cache, dbp->db_base);

	ASSERT(dbp->db_mblk->b_datap == dbp);
	ASSERT(dbp->db_struioflag == 0);
	ASSERT(dbp->db_struioun.cksum.flags == 0);

	kmem_cache_free(mblk_cache, dbp->db_mblk);
}

/* ARGSUSED */
static int
ftblk_constructor(void *buf, void *cdrarg, int kmflags)
{
	ftblk_t *fbp = buf;
	int i;

	bzero(fbp, sizeof (ftblk_t));
	if (str_ftstack != 0) {
		for (i = 0; i < FTBLK_EVNTS; i++)
			fbp->ev[i].stk = kmem_alloc(sizeof (ftstk_t), kmflags);
	}

	return (0);
}

/* ARGSUSED */
static void
ftblk_destructor(void *buf, void *cdrarg)
{
	ftblk_t *fbp = buf;
	int i;

	if (str_ftstack != 0) {
		for (i = 0; i < FTBLK_EVNTS; i++) {
			if (fbp->ev[i].stk != NULL) {
				kmem_free(fbp->ev[i].stk, sizeof (ftstk_t));
				fbp->ev[i].stk = NULL;
			}
		}
	}
}

static int
fthdr_constructor(void *buf, void *cdrarg, int kmflags)
{
	fthdr_t *fhp = buf;

	return (ftblk_constructor(&fhp->first, cdrarg, kmflags));
}

static void
fthdr_destructor(void *buf, void *cdrarg)
{
	fthdr_t *fhp = buf;

	ftblk_destructor(&fhp->first, cdrarg);
}

void
streams_msg_init(void)
{
	char name[40];
	size_t size;
	size_t lastsize = DBLK_MIN_SIZE;
	size_t *sizep;
	struct kmem_cache *cp;
	size_t tot_size;
	int offset;

	mblk_cache = kmem_cache_create("streams_mblk", sizeof (mblk_t), 32,
	    NULL, NULL, NULL, NULL, NULL, mblk_kmem_flags);

	for (sizep = dblk_sizes; (size = *sizep) != 0; sizep++) {

		if ((offset = (size & PAGEOFFSET)) != 0) {
			/*
			 * We are in the middle of a page, dblk should
			 * be allocated on the same page
			 */
			tot_size = size + sizeof (dblk_t);
			ASSERT((offset + sizeof (dblk_t) + sizeof (kmem_slab_t))
			    < PAGESIZE);
			ASSERT((tot_size & (DBLK_CACHE_ALIGN - 1)) == 0);

		} else {

			/*
			 * buf size is multiple of page size, dblk and
			 * buffer are allocated separately.
			 */

			ASSERT((size & (DBLK_CACHE_ALIGN - 1)) == 0);
			tot_size = sizeof (dblk_t);
		}

		(void) sprintf(name, "streams_dblk_%ld", size);
		cp = kmem_cache_create(name, tot_size, DBLK_CACHE_ALIGN,
		    dblk_constructor, dblk_destructor, NULL, (void *)(size),
		    NULL, dblk_kmem_flags);

		while (lastsize <= size) {
			dblk_cache[(lastsize - 1) >> DBLK_SIZE_SHIFT] = cp;
			lastsize += DBLK_MIN_SIZE;
		}
	}

	dblk_esb_cache = kmem_cache_create("streams_dblk_esb", sizeof (dblk_t),
	    DBLK_CACHE_ALIGN, dblk_esb_constructor, dblk_destructor, NULL,
	    (void *)sizeof (dblk_t), NULL, dblk_kmem_flags);
	fthdr_cache = kmem_cache_create("streams_fthdr", sizeof (fthdr_t), 32,
	    fthdr_constructor, fthdr_destructor, NULL, NULL, NULL, 0);
	ftblk_cache = kmem_cache_create("streams_ftblk", sizeof (ftblk_t), 32,
	    ftblk_constructor, ftblk_destructor, NULL, NULL, NULL, 0);

	/* Initialize Multidata caches */
	mmd_init();

	/* initialize throttling queue for esballoc */
	esballoc_queue_init();
}

/*ARGSUSED*/
mblk_t *
allocb(size_t size, uint_t pri)
{
	dblk_t *dbp;
	mblk_t *mp;
	size_t index;

	index =  (size - 1)  >> DBLK_SIZE_SHIFT;

	if (index >= (DBLK_MAX_CACHE >> DBLK_SIZE_SHIFT)) {
		if (size != 0) {
			mp = allocb_oversize(size, KM_NOSLEEP);
			goto out;
		}
		index = 0;
	}

	if ((dbp = kmem_cache_alloc(dblk_cache[index], KM_NOSLEEP)) == NULL) {
		mp = NULL;
		goto out;
	}

	mp = dbp->db_mblk;
	DBLK_RTFU_WORD(dbp) = DBLK_RTFU(1, M_DATA, 0, 0);
	mp->b_next = mp->b_prev = mp->b_cont = NULL;
	mp->b_rptr = mp->b_wptr = dbp->db_base;
	mp->b_queue = NULL;
	MBLK_BAND_FLAG_WORD(mp) = 0;
	STR_FTALLOC(&dbp->db_fthdr, FTEV_ALLOCB, size);
out:
	FTRACE_1("allocb(): mp=0x%p", (uintptr_t)mp);

	return (mp);
}

/*
 * Allocate an mblk taking db_credp and db_cpid from the template.
 * Allow the cred to be NULL.
 */
mblk_t *
allocb_tmpl(size_t size, const mblk_t *tmpl)
{
	mblk_t *mp = allocb(size, 0);

	if (mp != NULL) {
		dblk_t *src = tmpl->b_datap;
		dblk_t *dst = mp->b_datap;
		cred_t *cr;
		pid_t cpid;

		cr = msg_getcred(tmpl, &cpid);
		if (cr != NULL)
			crhold(dst->db_credp = cr);
		dst->db_cpid = cpid;
		dst->db_type = src->db_type;
	}
	return (mp);
}

mblk_t *
allocb_cred(size_t size, cred_t *cr, pid_t cpid)
{
	mblk_t *mp = allocb(size, 0);

	ASSERT(cr != NULL);
	if (mp != NULL) {
		dblk_t *dbp = mp->b_datap;

		crhold(dbp->db_credp = cr);
		dbp->db_cpid = cpid;
	}
	return (mp);
}

mblk_t *
allocb_cred_wait(size_t size, uint_t flags, int *error, cred_t *cr, pid_t cpid)
{
	mblk_t *mp = allocb_wait(size, 0, flags, error);

	ASSERT(cr != NULL);
	if (mp != NULL) {
		dblk_t *dbp = mp->b_datap;

		crhold(dbp->db_credp = cr);
		dbp->db_cpid = cpid;
	}

	return (mp);
}

/*
 * Extract the db_cred (and optionally db_cpid) from a message.
 * We find the first mblk which has a non-NULL db_cred and use that.
 * If none found we return NULL.
 * Does NOT get a hold on the cred.
 */
cred_t *
msg_getcred(const mblk_t *mp, pid_t *cpidp)
{
	cred_t *cr = NULL;
	cred_t *cr2;
	mblk_t *mp2;

	while (mp != NULL) {
		dblk_t *dbp = mp->b_datap;

		cr = dbp->db_credp;
		if (cr == NULL) {
			mp = mp->b_cont;
			continue;
		}
		if (cpidp != NULL)
			*cpidp = dbp->db_cpid;

#ifdef DEBUG
		/*
		 * Normally there should at most one db_credp in a message.
		 * But if there are multiple (as in the case of some M_IOC*
		 * and some internal messages in TCP/IP bind logic) then
		 * they must be identical in the normal case.
		 * However, a socket can be shared between different uids
		 * in which case data queued in TCP would be from different
		 * creds. Thus we can only assert for the zoneid being the
		 * same. Due to Multi-level Level Ports for TX, some
		 * cred_t can have a NULL cr_zone, and we skip the comparison
		 * in that case.
		 */
		mp2 = mp->b_cont;
		while (mp2 != NULL) {
			cr2 = DB_CRED(mp2);
			if (cr2 != NULL) {
				DTRACE_PROBE2(msg__getcred,
				    cred_t *, cr, cred_t *, cr2);
				ASSERT(crgetzoneid(cr) == crgetzoneid(cr2) ||
				    crgetzone(cr) == NULL ||
				    crgetzone(cr2) == NULL);
			}
			mp2 = mp2->b_cont;
		}
#endif
		return (cr);
	}
	if (cpidp != NULL)
		*cpidp = NOPID;
	return (NULL);
}

/*
 * Variant of msg_getcred which, when a cred is found
 * 1. Returns with a hold on the cred
 * 2. Clears the first cred in the mblk.
 * This is more efficient to use than a msg_getcred() + crhold() when
 * the message is freed after the cred has been extracted.
 *
 * The caller is responsible for ensuring that there is no other reference
 * on the message since db_credp can not be cleared when there are other
 * references.
 */
cred_t *
msg_extractcred(mblk_t *mp, pid_t *cpidp)
{
	cred_t *cr = NULL;
	cred_t *cr2;
	mblk_t *mp2;

	while (mp != NULL) {
		dblk_t *dbp = mp->b_datap;

		cr = dbp->db_credp;
		if (cr == NULL) {
			mp = mp->b_cont;
			continue;
		}
		ASSERT(dbp->db_ref == 1);
		dbp->db_credp = NULL;
		if (cpidp != NULL)
			*cpidp = dbp->db_cpid;
#ifdef DEBUG
		/*
		 * Normally there should at most one db_credp in a message.
		 * But if there are multiple (as in the case of some M_IOC*
		 * and some internal messages in TCP/IP bind logic) then
		 * they must be identical in the normal case.
		 * However, a socket can be shared between different uids
		 * in which case data queued in TCP would be from different
		 * creds. Thus we can only assert for the zoneid being the
		 * same. Due to Multi-level Level Ports for TX, some
		 * cred_t can have a NULL cr_zone, and we skip the comparison
		 * in that case.
		 */
		mp2 = mp->b_cont;
		while (mp2 != NULL) {
			cr2 = DB_CRED(mp2);
			if (cr2 != NULL) {
				DTRACE_PROBE2(msg__extractcred,
				    cred_t *, cr, cred_t *, cr2);
				ASSERT(crgetzoneid(cr) == crgetzoneid(cr2) ||
				    crgetzone(cr) == NULL ||
				    crgetzone(cr2) == NULL);
			}
			mp2 = mp2->b_cont;
		}
#endif
		return (cr);
	}
	return (NULL);
}
/*
 * Get the label for a message. Uses the first mblk in the message
 * which has a non-NULL db_credp.
 * Returns NULL if there is no credp.
 */
extern struct ts_label_s *
msg_getlabel(const mblk_t *mp)
{
	cred_t *cr = msg_getcred(mp, NULL);

	if (cr == NULL)
		return (NULL);

	return (crgetlabel(cr));
}

void
freeb(mblk_t *mp)
{
	dblk_t *dbp = mp->b_datap;

	ASSERT(dbp->db_ref > 0);
	ASSERT(mp->b_next == NULL && mp->b_prev == NULL);
	FTRACE_1("freeb(): mp=0x%lx", (uintptr_t)mp);

	STR_FTEVENT_MBLK(mp, caller(), FTEV_FREEB, dbp->db_ref);

	dbp->db_free(mp, dbp);
}

void
freemsg(mblk_t *mp)
{
	FTRACE_1("freemsg(): mp=0x%lx", (uintptr_t)mp);
	while (mp) {
		dblk_t *dbp = mp->b_datap;
		mblk_t *mp_cont = mp->b_cont;

		ASSERT(dbp->db_ref > 0);
		ASSERT(mp->b_next == NULL && mp->b_prev == NULL);

		STR_FTEVENT_MBLK(mp, caller(), FTEV_FREEB, dbp->db_ref);

		dbp->db_free(mp, dbp);
		mp = mp_cont;
	}
}

/*
 * Reallocate a block for another use.  Try hard to use the old block.
 * If the old data is wanted (copy), leave b_wptr at the end of the data,
 * otherwise return b_wptr = b_rptr.
 *
 * This routine is private and unstable.
 */
mblk_t	*
reallocb(mblk_t *mp, size_t size, uint_t copy)
{
	mblk_t		*mp1;
	unsigned char	*old_rptr;
	ptrdiff_t	cur_size;

	if (mp == NULL)
		return (allocb(size, BPRI_HI));

	cur_size = mp->b_wptr - mp->b_rptr;
	old_rptr = mp->b_rptr;

	ASSERT(mp->b_datap->db_ref != 0);

	if (mp->b_datap->db_ref == 1 && MBLKSIZE(mp) >= size) {
		/*
		 * If the data is wanted and it will fit where it is, no
		 * work is required.
		 */
		if (copy && mp->b_datap->db_lim - mp->b_rptr >= size)
			return (mp);

		mp->b_wptr = mp->b_rptr = mp->b_datap->db_base;
		mp1 = mp;
	} else if ((mp1 = allocb_tmpl(size, mp)) != NULL) {
		/* XXX other mp state could be copied too, db_flags ... ? */
		mp1->b_cont = mp->b_cont;
	} else {
		return (NULL);
	}

	if (copy) {
		bcopy(old_rptr, mp1->b_rptr, cur_size);
		mp1->b_wptr = mp1->b_rptr + cur_size;
	}

	if (mp != mp1)
		freeb(mp);

	return (mp1);
}

static void
dblk_lastfree(mblk_t *mp, dblk_t *dbp)
{
	ASSERT(dbp->db_mblk == mp);
	if (dbp->db_fthdr != NULL)
		str_ftfree(dbp);

	/* set credp and projid to be 'unspecified' before returning to cache */
	if (dbp->db_credp != NULL) {
		crfree(dbp->db_credp);
		dbp->db_credp = NULL;
	}
	dbp->db_cpid = -1;

	/* Reset the struioflag and the checksum flag fields */
	dbp->db_struioflag = 0;
	dbp->db_struioun.cksum.flags = 0;

	/* and the COOKED and/or UIOA flag(s) */
	dbp->db_flags &= ~(DBLK_COOKED | DBLK_UIOA);

	kmem_cache_free(dbp->db_cache, dbp);
}

static void
dblk_decref(mblk_t *mp, dblk_t *dbp)
{
	if (dbp->db_ref != 1) {
		uint32_t rtfu = atomic_add_32_nv(&DBLK_RTFU_WORD(dbp),
		    -(1 << DBLK_RTFU_SHIFT(db_ref)));
		/*
		 * atomic_add_32_nv() just decremented db_ref, so we no longer
		 * have a reference to the dblk, which means another thread
		 * could free it.  Therefore we cannot examine the dblk to
		 * determine whether ours was the last reference.  Instead,
		 * we extract the new and minimum reference counts from rtfu.
		 * Note that all we're really saying is "if (ref != refmin)".
		 */
		if (((rtfu >> DBLK_RTFU_SHIFT(db_ref)) & DBLK_REFMAX) !=
		    ((rtfu >> DBLK_RTFU_SHIFT(db_flags)) & DBLK_REFMIN)) {
			kmem_cache_free(mblk_cache, mp);
			return;
		}
	}
	dbp->db_mblk = mp;
	dbp->db_free = dbp->db_lastfree;
	dbp->db_lastfree(mp, dbp);
}

mblk_t *
dupb(mblk_t *mp)
{
	dblk_t *dbp = mp->b_datap;
	mblk_t *new_mp;
	uint32_t oldrtfu, newrtfu;

	if ((new_mp = kmem_cache_alloc(mblk_cache, KM_NOSLEEP)) == NULL)
		goto out;

	new_mp->b_next = new_mp->b_prev = new_mp->b_cont = NULL;
	new_mp->b_rptr = mp->b_rptr;
	new_mp->b_wptr = mp->b_wptr;
	new_mp->b_datap = dbp;
	new_mp->b_queue = NULL;
	MBLK_BAND_FLAG_WORD(new_mp) = MBLK_BAND_FLAG_WORD(mp);

	STR_FTEVENT_MBLK(mp, caller(), FTEV_DUPB, dbp->db_ref);

	dbp->db_free = dblk_decref;
	do {
		ASSERT(dbp->db_ref > 0);
		oldrtfu = DBLK_RTFU_WORD(dbp);
		newrtfu = oldrtfu + (1 << DBLK_RTFU_SHIFT(db_ref));
		/*
		 * If db_ref is maxed out we can't dup this message anymore.
		 */
		if ((oldrtfu & DBLK_RTFU_REF_MASK) == DBLK_RTFU_REF_MASK) {
			kmem_cache_free(mblk_cache, new_mp);
			new_mp = NULL;
			goto out;
		}
	} while (atomic_cas_32(&DBLK_RTFU_WORD(dbp), oldrtfu, newrtfu) !=
	    oldrtfu);

out:
	FTRACE_1("dupb(): new_mp=0x%lx", (uintptr_t)new_mp);
	return (new_mp);
}

static void
dblk_lastfree_desb(mblk_t *mp, dblk_t *dbp)
{
	frtn_t *frp = dbp->db_frtnp;

	ASSERT(dbp->db_mblk == mp);
	frp->free_func(frp->free_arg);
	if (dbp->db_fthdr != NULL)
		str_ftfree(dbp);

	/* set credp and projid to be 'unspecified' before returning to cache */
	if (dbp->db_credp != NULL) {
		crfree(dbp->db_credp);
		dbp->db_credp = NULL;
	}
	dbp->db_cpid = -1;
	dbp->db_struioflag = 0;
	dbp->db_struioun.cksum.flags = 0;

	kmem_cache_free(dbp->db_cache, dbp);
}

/*ARGSUSED*/
static void
frnop_func(void *arg)
{
}

/*
 * Generic esballoc used to implement the four flavors: [d]esballoc[a].
 */
static mblk_t *
gesballoc(unsigned char *base, size_t size, uint32_t db_rtfu, frtn_t *frp,
	void (*lastfree)(mblk_t *, dblk_t *), int kmflags)
{
	dblk_t *dbp;
	mblk_t *mp;

	ASSERT(base != NULL && frp != NULL);

	if ((dbp = kmem_cache_alloc(dblk_esb_cache, kmflags)) == NULL) {
		mp = NULL;
		goto out;
	}

	mp = dbp->db_mblk;
	dbp->db_base = base;
	dbp->db_lim = base + size;
	dbp->db_free = dbp->db_lastfree = lastfree;
	dbp->db_frtnp = frp;
	DBLK_RTFU_WORD(dbp) = db_rtfu;
	mp->b_next = mp->b_prev = mp->b_cont = NULL;
	mp->b_rptr = mp->b_wptr = base;
	mp->b_queue = NULL;
	MBLK_BAND_FLAG_WORD(mp) = 0;

out:
	FTRACE_1("gesballoc(): mp=0x%lx", (uintptr_t)mp);
	return (mp);
}

/*ARGSUSED*/
mblk_t *
esballoc(unsigned char *base, size_t size, uint_t pri, frtn_t *frp)
{
	mblk_t *mp;

	/*
	 * Note that this is structured to allow the common case (i.e.
	 * STREAMS flowtracing disabled) to call gesballoc() with tail
	 * call optimization.
	 */
	if (!str_ftnever) {
		mp = gesballoc(base, size, DBLK_RTFU(1, M_DATA, 0, 0),
		    frp, freebs_enqueue, KM_NOSLEEP);

		if (mp != NULL)
			STR_FTALLOC(&DB_FTHDR(mp), FTEV_ESBALLOC, size);
		return (mp);
	}

	return (gesballoc(base, size, DBLK_RTFU(1, M_DATA, 0, 0),
	    frp, freebs_enqueue, KM_NOSLEEP));
}

/*
 * Same as esballoc() but sleeps waiting for memory.
 */
/*ARGSUSED*/
mblk_t *
esballoc_wait(unsigned char *base, size_t size, uint_t pri, frtn_t *frp)
{
	mblk_t *mp;

	/*
	 * Note that this is structured to allow the common case (i.e.
	 * STREAMS flowtracing disabled) to call gesballoc() with tail
	 * call optimization.
	 */
	if (!str_ftnever) {
		mp = gesballoc(base, size, DBLK_RTFU(1, M_DATA, 0, 0),
		    frp, freebs_enqueue, KM_SLEEP);

		STR_FTALLOC(&DB_FTHDR(mp), FTEV_ESBALLOC, size);
		return (mp);
	}

	return (gesballoc(base, size, DBLK_RTFU(1, M_DATA, 0, 0),
	    frp, freebs_enqueue, KM_SLEEP));
}

/*ARGSUSED*/
mblk_t *
desballoc(unsigned char *base, size_t size, uint_t pri, frtn_t *frp)
{
	mblk_t *mp;

	/*
	 * Note that this is structured to allow the common case (i.e.
	 * STREAMS flowtracing disabled) to call gesballoc() with tail
	 * call optimization.
	 */
	if (!str_ftnever) {
		mp = gesballoc(base, size, DBLK_RTFU(1, M_DATA, 0, 0),
		    frp, dblk_lastfree_desb, KM_NOSLEEP);

		if (mp != NULL)
			STR_FTALLOC(&DB_FTHDR(mp), FTEV_DESBALLOC, size);
		return (mp);
	}

	return (gesballoc(base, size, DBLK_RTFU(1, M_DATA, 0, 0),
	    frp, dblk_lastfree_desb, KM_NOSLEEP));
}

/*ARGSUSED*/
mblk_t *
esballoca(unsigned char *base, size_t size, uint_t pri, frtn_t *frp)
{
	mblk_t *mp;

	/*
	 * Note that this is structured to allow the common case (i.e.
	 * STREAMS flowtracing disabled) to call gesballoc() with tail
	 * call optimization.
	 */
	if (!str_ftnever) {
		mp = gesballoc(base, size, DBLK_RTFU(2, M_DATA, 0, 0),
		    frp, freebs_enqueue, KM_NOSLEEP);

		if (mp != NULL)
			STR_FTALLOC(&DB_FTHDR(mp), FTEV_ESBALLOCA, size);
		return (mp);
	}

	return (gesballoc(base, size, DBLK_RTFU(2, M_DATA, 0, 0),
	    frp, freebs_enqueue, KM_NOSLEEP));
}

/*ARGSUSED*/
mblk_t *
desballoca(unsigned char *base, size_t size, uint_t pri, frtn_t *frp)
{
	mblk_t *mp;

	/*
	 * Note that this is structured to allow the common case (i.e.
	 * STREAMS flowtracing disabled) to call gesballoc() with tail
	 * call optimization.
	 */
	if (!str_ftnever) {
		mp = gesballoc(base, size, DBLK_RTFU(2, M_DATA, 0, 0),
		    frp, dblk_lastfree_desb, KM_NOSLEEP);

		if (mp != NULL)
			STR_FTALLOC(&DB_FTHDR(mp), FTEV_DESBALLOCA, size);
		return (mp);
	}

	return (gesballoc(base, size, DBLK_RTFU(2, M_DATA, 0, 0),
	    frp, dblk_lastfree_desb, KM_NOSLEEP));
}

static void
bcache_dblk_lastfree(mblk_t *mp, dblk_t *dbp)
{
	bcache_t *bcp = dbp->db_cache;

	ASSERT(dbp->db_mblk == mp);
	if (dbp->db_fthdr != NULL)
		str_ftfree(dbp);

	/* set credp and projid to be 'unspecified' before returning to cache */
	if (dbp->db_credp != NULL) {
		crfree(dbp->db_credp);
		dbp->db_credp = NULL;
	}
	dbp->db_cpid = -1;
	dbp->db_struioflag = 0;
	dbp->db_struioun.cksum.flags = 0;

	mutex_enter(&bcp->mutex);
	kmem_cache_free(bcp->dblk_cache, dbp);
	bcp->alloc--;

	if (bcp->alloc == 0 && bcp->destroy != 0) {
		kmem_cache_destroy(bcp->dblk_cache);
		kmem_cache_destroy(bcp->buffer_cache);
		mutex_exit(&bcp->mutex);
		mutex_destroy(&bcp->mutex);
		kmem_free(bcp, sizeof (bcache_t));
	} else {
		mutex_exit(&bcp->mutex);
	}
}

bcache_t *
bcache_create(char *name, size_t size, uint_t align)
{
	bcache_t *bcp;
	char buffer[255];

	ASSERT((align & (align - 1)) == 0);

	if ((bcp = kmem_alloc(sizeof (bcache_t), KM_NOSLEEP)) == NULL)
		return (NULL);

	bcp->size = size;
	bcp->align = align;
	bcp->alloc = 0;
	bcp->destroy = 0;

	mutex_init(&bcp->mutex, NULL, MUTEX_DRIVER, NULL);

	(void) sprintf(buffer, "%s_buffer_cache", name);
	bcp->buffer_cache = kmem_cache_create(buffer, size, align, NULL, NULL,
	    NULL, NULL, NULL, 0);
	(void) sprintf(buffer, "%s_dblk_cache", name);
	bcp->dblk_cache = kmem_cache_create(buffer, sizeof (dblk_t),
	    DBLK_CACHE_ALIGN, bcache_dblk_constructor, bcache_dblk_destructor,
	    NULL, (void *)bcp, NULL, 0);

	return (bcp);
}

void
bcache_destroy(bcache_t *bcp)
{
	ASSERT(bcp != NULL);

	mutex_enter(&bcp->mutex);
	if (bcp->alloc == 0) {
		kmem_cache_destroy(bcp->dblk_cache);
		kmem_cache_destroy(bcp->buffer_cache);
		mutex_exit(&bcp->mutex);
		mutex_destroy(&bcp->mutex);
		kmem_free(bcp, sizeof (bcache_t));
	} else {
		bcp->destroy++;
		mutex_exit(&bcp->mutex);
	}
}

/*ARGSUSED*/
mblk_t *
bcache_allocb(bcache_t *bcp, uint_t pri)
{
	dblk_t *dbp;
	mblk_t *mp = NULL;

	ASSERT(bcp != NULL);

	mutex_enter(&bcp->mutex);
	if (bcp->destroy != 0) {
		mutex_exit(&bcp->mutex);
		goto out;
	}

	if ((dbp = kmem_cache_alloc(bcp->dblk_cache, KM_NOSLEEP)) == NULL) {
		mutex_exit(&bcp->mutex);
		goto out;
	}
	bcp->alloc++;
	mutex_exit(&bcp->mutex);

	ASSERT(((uintptr_t)(dbp->db_base) & (bcp->align - 1)) == 0);

	mp = dbp->db_mblk;
	DBLK_RTFU_WORD(dbp) = DBLK_RTFU(1, M_DATA, 0, 0);
	mp->b_next = mp->b_prev = mp->b_cont = NULL;
	mp->b_rptr = mp->b_wptr = dbp->db_base;
	mp->b_queue = NULL;
	MBLK_BAND_FLAG_WORD(mp) = 0;
	STR_FTALLOC(&dbp->db_fthdr, FTEV_BCALLOCB, bcp->size);
out:
	FTRACE_1("bcache_allocb(): mp=0x%p", (uintptr_t)mp);

	return (mp);
}

static void
dblk_lastfree_oversize(mblk_t *mp, dblk_t *dbp)
{
	ASSERT(dbp->db_mblk == mp);
	if (dbp->db_fthdr != NULL)
		str_ftfree(dbp);

	/* set credp and projid to be 'unspecified' before returning to cache */
	if (dbp->db_credp != NULL) {
		crfree(dbp->db_credp);
		dbp->db_credp = NULL;
	}
	dbp->db_cpid = -1;
	dbp->db_struioflag = 0;
	dbp->db_struioun.cksum.flags = 0;

	kmem_free(dbp->db_base, dbp->db_lim - dbp->db_base);
	kmem_cache_free(dbp->db_cache, dbp);
}

static mblk_t *
allocb_oversize(size_t size, int kmflags)
{
	mblk_t *mp;
	void *buf;

	size = P2ROUNDUP(size, DBLK_CACHE_ALIGN);
	if ((buf = kmem_alloc(size, kmflags)) == NULL)
		return (NULL);
	if ((mp = gesballoc(buf, size, DBLK_RTFU(1, M_DATA, 0, 0),
	    &frnop, dblk_lastfree_oversize, kmflags)) == NULL)
		kmem_free(buf, size);

	if (mp != NULL)
		STR_FTALLOC(&DB_FTHDR(mp), FTEV_ALLOCBIG, size);

	return (mp);
}

mblk_t *
allocb_tryhard(size_t target_size)
{
	size_t size;
	mblk_t *bp;

	for (size = target_size; size < target_size + 512;
	    size += DBLK_CACHE_ALIGN)
		if ((bp = allocb(size, BPRI_HI)) != NULL)
			return (bp);
	allocb_tryhard_fails++;
	return (NULL);
}

/*
 * This routine is consolidation private for STREAMS internal use
 * This routine may only be called from sync routines (i.e., not
 * from put or service procedures).  It is located here (rather
 * than strsubr.c) so that we don't have to expose all of the
 * allocb() implementation details in header files.
 */
mblk_t *
allocb_wait(size_t size, uint_t pri, uint_t flags, int *error)
{
	dblk_t *dbp;
	mblk_t *mp;
	size_t index;

	index = (size -1) >> DBLK_SIZE_SHIFT;

	if (flags & STR_NOSIG) {
		if (index >= (DBLK_MAX_CACHE >> DBLK_SIZE_SHIFT)) {
			if (size != 0) {
				mp = allocb_oversize(size, KM_SLEEP);
				FTRACE_1("allocb_wait (NOSIG): mp=0x%lx",
				    (uintptr_t)mp);
				return (mp);
			}
			index = 0;
		}

		dbp = kmem_cache_alloc(dblk_cache[index], KM_SLEEP);
		mp = dbp->db_mblk;
		DBLK_RTFU_WORD(dbp) = DBLK_RTFU(1, M_DATA, 0, 0);
		mp->b_next = mp->b_prev = mp->b_cont = NULL;
		mp->b_rptr = mp->b_wptr = dbp->db_base;
		mp->b_queue = NULL;
		MBLK_BAND_FLAG_WORD(mp) = 0;
		STR_FTALLOC(&DB_FTHDR(mp), FTEV_ALLOCBW, size);

		FTRACE_1("allocb_wait (NOSIG): mp=0x%lx", (uintptr_t)mp);

	} else {
		while ((mp = allocb(size, pri)) == NULL) {
			if ((*error = strwaitbuf(size, BPRI_HI)) != 0)
				return (NULL);
		}
	}

	return (mp);
}

/*
 * Call function 'func' with 'arg' when a class zero block can
 * be allocated with priority 'pri'.
 */
bufcall_id_t
esbbcall(uint_t pri, void (*func)(void *), void *arg)
{
	return (bufcall(1, pri, func, arg));
}

/*
 * Allocates an iocblk (M_IOCTL) block. Properly sets the credentials
 * ioc_id, rval and error of the struct ioctl to set up an ioctl call.
 * This provides consistency for all internal allocators of ioctl.
 */
mblk_t *
mkiocb(uint_t cmd)
{
	struct iocblk	*ioc;
	mblk_t		*mp;

	/*
	 * Allocate enough space for any of the ioctl related messages.
	 */
	if ((mp = allocb(sizeof (union ioctypes), BPRI_MED)) == NULL)
		return (NULL);

	bzero(mp->b_rptr, sizeof (union ioctypes));

	/*
	 * Set the mblk_t information and ptrs correctly.
	 */
	mp->b_wptr += sizeof (struct iocblk);
	mp->b_datap->db_type = M_IOCTL;

	/*
	 * Fill in the fields.
	 */
	ioc		= (struct iocblk *)mp->b_rptr;
	ioc->ioc_cmd	= cmd;
	ioc->ioc_cr	= kcred;
	ioc->ioc_id	= getiocseqno();
	ioc->ioc_flag	= IOC_NATIVE;
	return (mp);
}

/*
 * test if block of given size can be allocated with a request of
 * the given priority.
 * 'pri' is no longer used, but is retained for compatibility.
 */
/* ARGSUSED */
int
testb(size_t size, uint_t pri)
{
	return ((size + sizeof (dblk_t)) <= kmem_avail());
}

/*
 * Call function 'func' with argument 'arg' when there is a reasonably
 * good chance that a block of size 'size' can be allocated.
 * 'pri' is no longer used, but is retained for compatibility.
 */
/* ARGSUSED */
bufcall_id_t
bufcall(size_t size, uint_t pri, void (*func)(void *), void *arg)
{
	static long bid = 1;	/* always odd to save checking for zero */
	bufcall_id_t bc_id;
	struct strbufcall *bcp;

	if ((bcp = kmem_alloc(sizeof (strbufcall_t), KM_NOSLEEP)) == NULL)
		return (0);

	bcp->bc_func = func;
	bcp->bc_arg = arg;
	bcp->bc_size = size;
	bcp->bc_next = NULL;
	bcp->bc_executor = NULL;

	mutex_enter(&strbcall_lock);
	/*
	 * After bcp is linked into strbcalls and strbcall_lock is dropped there
	 * should be no references to bcp since it may be freed by
	 * runbufcalls(). Since bcp_id field is returned, we save its value in
	 * the local var.
	 */
	bc_id = bcp->bc_id = (bufcall_id_t)(bid += 2);	/* keep it odd */

	/*
	 * add newly allocated stream event to existing
	 * linked list of events.
	 */
	if (strbcalls.bc_head == NULL) {
		strbcalls.bc_head = strbcalls.bc_tail = bcp;
	} else {
		strbcalls.bc_tail->bc_next = bcp;
		strbcalls.bc_tail = bcp;
	}

	cv_signal(&strbcall_cv);
	mutex_exit(&strbcall_lock);
	return (bc_id);
}

/*
 * Cancel a bufcall request.
 */
void
unbufcall(bufcall_id_t id)
{
	strbufcall_t *bcp, *pbcp;

	mutex_enter(&strbcall_lock);
again:
	pbcp = NULL;
	for (bcp = strbcalls.bc_head; bcp; bcp = bcp->bc_next) {
		if (id == bcp->bc_id)
			break;
		pbcp = bcp;
	}
	if (bcp) {
		if (bcp->bc_executor != NULL) {
			if (bcp->bc_executor != curthread) {
				cv_wait(&bcall_cv, &strbcall_lock);
				goto again;
			}
		} else {
			if (pbcp)
				pbcp->bc_next = bcp->bc_next;
			else
				strbcalls.bc_head = bcp->bc_next;
			if (bcp == strbcalls.bc_tail)
				strbcalls.bc_tail = pbcp;
			kmem_free(bcp, sizeof (strbufcall_t));
		}
	}
	mutex_exit(&strbcall_lock);
}

/*
 * Duplicate a message block by block (uses dupb), returning
 * a pointer to the duplicate message.
 * Returns a non-NULL value only if the entire message
 * was dup'd.
 */
mblk_t *
dupmsg(mblk_t *bp)
{
	mblk_t *head, *nbp;

	if (!bp || !(nbp = head = dupb(bp)))
		return (NULL);

	while (bp->b_cont) {
		if (!(nbp->b_cont = dupb(bp->b_cont))) {
			freemsg(head);
			return (NULL);
		}
		nbp = nbp->b_cont;
		bp = bp->b_cont;
	}
	return (head);
}

#define	DUPB_NOLOAN(bp) \
	((((bp)->b_datap->db_struioflag & STRUIO_ZC) != 0) ? \
	copyb((bp)) : dupb((bp)))

mblk_t *
dupmsg_noloan(mblk_t *bp)
{
	mblk_t *head, *nbp;

	if (bp == NULL || DB_TYPE(bp) != M_DATA ||
	    ((nbp = head = DUPB_NOLOAN(bp)) == NULL))
		return (NULL);

	while (bp->b_cont) {
		if ((nbp->b_cont = DUPB_NOLOAN(bp->b_cont)) == NULL) {
			freemsg(head);
			return (NULL);
		}
		nbp = nbp->b_cont;
		bp = bp->b_cont;
	}
	return (head);
}

/*
 * Copy data from message and data block to newly allocated message and
 * data block. Returns new message block pointer, or NULL if error.
 * The alignment of rptr (w.r.t. word alignment) will be the same in the copy
 * as in the original even when db_base is not word aligned. (bug 1052877)
 */
mblk_t *
copyb(mblk_t *bp)
{
	mblk_t	*nbp;
	dblk_t	*dp, *ndp;
	uchar_t *base;
	size_t	size;
	size_t	unaligned;

	ASSERT(bp->b_wptr >= bp->b_rptr);

	dp = bp->b_datap;
	if (dp->db_fthdr != NULL)
		STR_FTEVENT_MBLK(bp, caller(), FTEV_COPYB, 0);

	/*
	 * Special handling for Multidata message; this should be
	 * removed once a copy-callback routine is made available.
	 */
	if (dp->db_type == M_MULTIDATA) {
		cred_t *cr;

		if ((nbp = mmd_copy(bp, KM_NOSLEEP)) == NULL)
			return (NULL);

		nbp->b_flag = bp->b_flag;
		nbp->b_band = bp->b_band;
		ndp = nbp->b_datap;

		/* See comments below on potential issues. */
		STR_FTEVENT_MBLK(nbp, caller(), FTEV_COPYB, 1);

		ASSERT(ndp->db_type == dp->db_type);
		cr = dp->db_credp;
		if (cr != NULL)
			crhold(ndp->db_credp = cr);
		ndp->db_cpid = dp->db_cpid;
		return (nbp);
	}

	size = dp->db_lim - dp->db_base;
	unaligned = P2PHASE((uintptr_t)dp->db_base, sizeof (uint_t));
	if ((nbp = allocb_tmpl(size + unaligned, bp)) == NULL)
		return (NULL);
	nbp->b_flag = bp->b_flag;
	nbp->b_band = bp->b_band;
	ndp = nbp->b_datap;

	/*
	 * Well, here is a potential issue.  If we are trying to
	 * trace a flow, and we copy the message, we might lose
	 * information about where this message might have been.
	 * So we should inherit the FT data.  On the other hand,
	 * a user might be interested only in alloc to free data.
	 * So I guess the real answer is to provide a tunable.
	 */
	STR_FTEVENT_MBLK(nbp, caller(), FTEV_COPYB, 1);

	base = ndp->db_base + unaligned;
	bcopy(dp->db_base, ndp->db_base + unaligned, size);

	nbp->b_rptr = base + (bp->b_rptr - dp->db_base);
	nbp->b_wptr = nbp->b_rptr + MBLKL(bp);

	return (nbp);
}

/*
 * Copy data from message to newly allocated message using new
 * data blocks.  Returns a pointer to the new message, or NULL if error.
 */
mblk_t *
copymsg(mblk_t *bp)
{
	mblk_t *head, *nbp;

	if (!bp || !(nbp = head = copyb(bp)))
		return (NULL);

	while (bp->b_cont) {
		if (!(nbp->b_cont = copyb(bp->b_cont))) {
			freemsg(head);
			return (NULL);
		}
		nbp = nbp->b_cont;
		bp = bp->b_cont;
	}
	return (head);
}

/*
 * link a message block to tail of message
 */
void
linkb(mblk_t *mp, mblk_t *bp)
{
	ASSERT(mp && bp);

	for (; mp->b_cont; mp = mp->b_cont)
		;
	mp->b_cont = bp;
}

/*
 * unlink a message block from head of message
 * return pointer to new message.
 * NULL if message becomes empty.
 */
mblk_t *
unlinkb(mblk_t *bp)
{
	mblk_t *bp1;

	bp1 = bp->b_cont;
	bp->b_cont = NULL;
	return (bp1);
}

/*
 * remove a message block "bp" from message "mp"
 *
 * Return pointer to new message or NULL if no message remains.
 * Return -1 if bp is not found in message.
 */
mblk_t *
rmvb(mblk_t *mp, mblk_t *bp)
{
	mblk_t *tmp;
	mblk_t *lastp = NULL;

	ASSERT(mp && bp);
	for (tmp = mp; tmp; tmp = tmp->b_cont) {
		if (tmp == bp) {
			if (lastp)
				lastp->b_cont = tmp->b_cont;
			else
				mp = tmp->b_cont;
			tmp->b_cont = NULL;
			return (mp);
		}
		lastp = tmp;
	}
	return ((mblk_t *)-1);
}

/*
 * Concatenate and align first len bytes of common
 * message type.  Len == -1, means concat everything.
 * Returns 1 on success, 0 on failure
 * After the pullup, mp points to the pulled up data.
 */
int
pullupmsg(mblk_t *mp, ssize_t len)
{
	mblk_t *bp, *b_cont;
	dblk_t *dbp;
	ssize_t n;

	ASSERT(mp->b_datap->db_ref > 0);
	ASSERT(mp->b_next == NULL && mp->b_prev == NULL);

	/*
	 * We won't handle Multidata message, since it contains
	 * metadata which this function has no knowledge of; we
	 * assert on DEBUG, and return failure otherwise.
	 */
	ASSERT(mp->b_datap->db_type != M_MULTIDATA);
	if (mp->b_datap->db_type == M_MULTIDATA)
		return (0);

	if (len == -1) {
		if (mp->b_cont == NULL && str_aligned(mp->b_rptr))
			return (1);
		len = xmsgsize(mp);
	} else {
		ssize_t first_mblk_len = mp->b_wptr - mp->b_rptr;
		ASSERT(first_mblk_len >= 0);
		/*
		 * If the length is less than that of the first mblk,
		 * we want to pull up the message into an aligned mblk.
		 * Though not part of the spec, some callers assume it.
		 */
		if (len <= first_mblk_len) {
			if (str_aligned(mp->b_rptr))
				return (1);
			len = first_mblk_len;
		} else if (xmsgsize(mp) < len)
			return (0);
	}

	if ((bp = allocb_tmpl(len, mp)) == NULL)
		return (0);

	dbp = bp->b_datap;
	*bp = *mp;		/* swap mblks so bp heads the old msg... */
	mp->b_datap = dbp;	/* ... and mp heads the new message */
	mp->b_datap->db_mblk = mp;
	bp->b_datap->db_mblk = bp;
	mp->b_rptr = mp->b_wptr = dbp->db_base;

	do {
		ASSERT(bp->b_datap->db_ref > 0);
		ASSERT(bp->b_wptr >= bp->b_rptr);
		n = MIN(bp->b_wptr - bp->b_rptr, len);
		ASSERT(n >= 0);		/* allow zero-length mblk_t's */
		if (n > 0)
			bcopy(bp->b_rptr, mp->b_wptr, (size_t)n);
		mp->b_wptr += n;
		bp->b_rptr += n;
		len -= n;
		if (bp->b_rptr != bp->b_wptr)
			break;
		b_cont = bp->b_cont;
		freeb(bp);
		bp = b_cont;
	} while (len && bp);

	mp->b_cont = bp;	/* tack on whatever wasn't pulled up */

	return (1);
}

/*
 * Concatenate and align at least the first len bytes of common message
 * type.  Len == -1 means concatenate everything.  The original message is
 * unaltered.  Returns a pointer to a new message on success, otherwise
 * returns NULL.
 */
mblk_t *
msgpullup(mblk_t *mp, ssize_t len)
{
	mblk_t	*newmp;
	ssize_t	totlen;
	ssize_t	n;

	/*
	 * We won't handle Multidata message, since it contains
	 * metadata which this function has no knowledge of; we
	 * assert on DEBUG, and return failure otherwise.
	 */
	ASSERT(mp->b_datap->db_type != M_MULTIDATA);
	if (mp->b_datap->db_type == M_MULTIDATA)
		return (NULL);

	totlen = xmsgsize(mp);

	if ((len > 0) && (len > totlen))
		return (NULL);

	/*
	 * Copy all of the first msg type into one new mblk, then dupmsg
	 * and link the rest onto this.
	 */

	len = totlen;

	if ((newmp = allocb_tmpl(len, mp)) == NULL)
		return (NULL);

	newmp->b_flag = mp->b_flag;
	newmp->b_band = mp->b_band;

	while (len > 0) {
		n = mp->b_wptr - mp->b_rptr;
		ASSERT(n >= 0);		/* allow zero-length mblk_t's */
		if (n > 0)
			bcopy(mp->b_rptr, newmp->b_wptr, n);
		newmp->b_wptr += n;
		len -= n;
		mp = mp->b_cont;
	}

	if (mp != NULL) {
		newmp->b_cont = dupmsg(mp);
		if (newmp->b_cont == NULL) {
			freemsg(newmp);
			return (NULL);
		}
	}

	return (newmp);
}

/*
 * Trim bytes from message
 *  len > 0, trim from head
 *  len < 0, trim from tail
 * Returns 1 on success, 0 on failure.
 */
int
adjmsg(mblk_t *mp, ssize_t len)
{
	mblk_t *bp;
	mblk_t *save_bp = NULL;
	mblk_t *prev_bp;
	mblk_t *bcont;
	unsigned char type;
	ssize_t n;
	int fromhead;
	int first;

	ASSERT(mp != NULL);
	/*
	 * We won't handle Multidata message, since it contains
	 * metadata which this function has no knowledge of; we
	 * assert on DEBUG, and return failure otherwise.
	 */
	ASSERT(mp->b_datap->db_type != M_MULTIDATA);
	if (mp->b_datap->db_type == M_MULTIDATA)
		return (0);

	if (len < 0) {
		fromhead = 0;
		len = -len;
	} else {
		fromhead = 1;
	}

	if (xmsgsize(mp) < len)
		return (0);

	if (fromhead) {
		first = 1;
		while (len) {
			ASSERT(mp->b_wptr >= mp->b_rptr);
			n = MIN(mp->b_wptr - mp->b_rptr, len);
			mp->b_rptr += n;
			len -= n;

			/*
			 * If this is not the first zero length
			 * message remove it
			 */
			if (!first && (mp->b_wptr == mp->b_rptr)) {
				bcont = mp->b_cont;
				freeb(mp);
				mp = save_bp->b_cont = bcont;
			} else {
				save_bp = mp;
				mp = mp->b_cont;
			}
			first = 0;
		}
	} else {
		type = mp->b_datap->db_type;
		while (len) {
			bp = mp;
			save_bp = NULL;

			/*
			 * Find the last message of same type
			 */
			while (bp && bp->b_datap->db_type == type) {
				ASSERT(bp->b_wptr >= bp->b_rptr);
				prev_bp = save_bp;
				save_bp = bp;
				bp = bp->b_cont;
			}
			if (save_bp == NULL)
				break;
			n = MIN(save_bp->b_wptr - save_bp->b_rptr, len);
			save_bp->b_wptr -= n;
			len -= n;

			/*
			 * If this is not the first message
			 * and we have taken away everything
			 * from this message, remove it
			 */

			if ((save_bp != mp) &&
			    (save_bp->b_wptr == save_bp->b_rptr)) {
				bcont = save_bp->b_cont;
				freeb(save_bp);
				prev_bp->b_cont = bcont;
			}
		}
	}
	return (1);
}

/*
 * get number of data bytes in message
 */
size_t
msgdsize(mblk_t *bp)
{
	size_t count = 0;

	for (; bp; bp = bp->b_cont)
		if (bp->b_datap->db_type == M_DATA) {
			ASSERT(bp->b_wptr >= bp->b_rptr);
			count += bp->b_wptr - bp->b_rptr;
		}
	return (count);
}

/*
 * Get a message off head of queue
 *
 * If queue has no buffers then mark queue
 * with QWANTR. (queue wants to be read by
 * someone when data becomes available)
 *
 * If there is something to take off then do so.
 * If queue falls below hi water mark turn off QFULL
 * flag.  Decrement weighted count of queue.
 * Also turn off QWANTR because queue is being read.
 *
 * The queue count is maintained on a per-band basis.
 * Priority band 0 (normal messages) uses q_count,
 * q_lowat, etc.  Non-zero priority bands use the
 * fields in their respective qband structures
 * (qb_count, qb_lowat, etc.)  All messages appear
 * on the same list, linked via their b_next pointers.
 * q_first is the head of the list.  q_count does
 * not reflect the size of all the messages on the
 * queue.  It only reflects those messages in the
 * normal band of flow.  The one exception to this
 * deals with high priority messages.  They are in
 * their own conceptual "band", but are accounted
 * against q_count.
 *
 * If queue count is below the lo water mark and QWANTW
 * is set, enable the closest backq which has a service
 * procedure and turn off the QWANTW flag.
 *
 * getq could be built on top of rmvq, but isn't because
 * of performance considerations.
 *
 * A note on the use of q_count and q_mblkcnt:
 *   q_count is the traditional byte count for messages that
 *   have been put on a queue.  Documentation tells us that
 *   we shouldn't rely on that count, but some drivers/modules
 *   do.  What was needed, however, is a mechanism to prevent
 *   runaway streams from consuming all of the resources,
 *   and particularly be able to flow control zero-length
 *   messages.  q_mblkcnt is used for this purpose.  It
 *   counts the number of mblk's that are being put on
 *   the queue.  The intention here, is that each mblk should
 *   contain one byte of data and, for the purpose of
 *   flow-control, logically does.  A queue will become
 *   full when EITHER of these values (q_count and q_mblkcnt)
 *   reach the highwater mark.  It will clear when BOTH
 *   of them drop below the highwater mark.  And it will
 *   backenable when BOTH of them drop below the lowwater
 *   mark.
 *   With this algorithm, a driver/module might be able
 *   to find a reasonably accurate q_count, and the
 *   framework can still try and limit resource usage.
 */
mblk_t *
getq(queue_t *q)
{
	mblk_t *bp;
	uchar_t band = 0;

	bp = getq_noenab(q, 0);
	if (bp != NULL)
		band = bp->b_band;

	/*
	 * Inlined from qbackenable().
	 * Quick check without holding the lock.
	 */
	if (band == 0 && (q->q_flag & (QWANTW|QWANTWSYNC)) == 0)
		return (bp);

	qbackenable(q, band);
	return (bp);
}

/*
 * Calculate number of data bytes in a single data message block taking
 * multidata messages into account.
 */

#define	ADD_MBLK_SIZE(mp, size) 					\
	if (DB_TYPE(mp) != M_MULTIDATA) {				\
		(size) += MBLKL(mp);					\
	} else {							\
		uint_t	pinuse;						\
									\
		mmd_getsize(mmd_getmultidata(mp), NULL, &pinuse);	\
		(size) += pinuse;					\
	}

/*
 * Returns the number of bytes in a message (a message is defined as a
 * chain of mblks linked by b_cont). If a non-NULL mblkcnt is supplied we
 * also return the number of distinct mblks in the message.
 */
int
mp_cont_len(mblk_t *bp, int *mblkcnt)
{
	mblk_t	*mp;
	int	mblks = 0;
	int	bytes = 0;

	for (mp = bp; mp != NULL; mp = mp->b_cont) {
		ADD_MBLK_SIZE(mp, bytes);
		mblks++;
	}

	if (mblkcnt != NULL)
		*mblkcnt = mblks;

	return (bytes);
}

/*
 * Like getq() but does not backenable.  This is used by the stream
 * head when a putback() is likely.  The caller must call qbackenable()
 * after it is done with accessing the queue.
 * The rbytes arguments to getq_noneab() allows callers to specify a
 * the maximum number of bytes to return. If the current amount on the
 * queue is less than this then the entire message will be returned.
 * A value of 0 returns the entire message and is equivalent to the old
 * default behaviour prior to the addition of the rbytes argument.
 */
mblk_t *
getq_noenab(queue_t *q, ssize_t rbytes)
{
	mblk_t *bp, *mp1;
	mblk_t *mp2 = NULL;
	qband_t *qbp;
	kthread_id_t freezer;
	int	bytecnt = 0, mblkcnt = 0;

	/* freezestr should allow its caller to call getq/putq */
	freezer = STREAM(q)->sd_freezer;
	if (freezer == curthread) {
		ASSERT(frozenstr(q));
		ASSERT(MUTEX_HELD(QLOCK(q)));
	} else
		mutex_enter(QLOCK(q));

	if ((bp = q->q_first) == 0) {
		q->q_flag |= QWANTR;
	} else {
		/*
		 * If the caller supplied a byte threshold and there is
		 * more than this amount on the queue then break up the
		 * the message appropriately.  We can only safely do
		 * this for M_DATA messages.
		 */
		if ((DB_TYPE(bp) == M_DATA) && (rbytes > 0) &&
		    (q->q_count > rbytes)) {
			/*
			 * Inline version of mp_cont_len() which terminates
			 * when we meet or exceed rbytes.
			 */
			for (mp1 = bp; mp1 != NULL; mp1 = mp1->b_cont) {
				mblkcnt++;
				ADD_MBLK_SIZE(mp1, bytecnt);
				if (bytecnt  >= rbytes)
					break;
			}
			/*
			 * We need to account for the following scenarios:
			 *
			 * 1) Too much data in the first message:
			 *	mp1 will be the mblk which puts us over our
			 *	byte limit.
			 * 2) Not enough data in the first message:
			 *	mp1 will be NULL.
			 * 3) Exactly the right amount of data contained within
			 *    whole mblks:
			 *	mp1->b_cont will be where we break the message.
			 */
			if (bytecnt > rbytes) {
				/*
				 * Dup/copy mp1 and put what we don't need
				 * back onto the queue. Adjust the read/write
				 * and continuation pointers appropriately
				 * and decrement the current mblk count to
				 * reflect we are putting an mblk back onto
				 * the queue.
				 * When adjusting the message pointers, it's
				 * OK to use the existing bytecnt and the
				 * requested amount (rbytes) to calculate the
				 * the new write offset (b_wptr) of what we
				 * are taking. However, we  cannot use these
				 * values when calculating the read offset of
				 * the mblk we are putting back on the queue.
				 * This is because the begining (b_rptr) of the
				 * mblk represents some arbitrary point within
				 * the message.
				 * It's simplest to do this by advancing b_rptr
				 * by the new length of mp1 as we don't have to
				 * remember any intermediate state.
				 */
				ASSERT(mp1 != NULL);
				mblkcnt--;
				if ((mp2 = dupb(mp1)) == NULL &&
				    (mp2 = copyb(mp1)) == NULL) {
					bytecnt = mblkcnt = 0;
					goto dup_failed;
				}
				mp2->b_cont = mp1->b_cont;
				mp1->b_wptr -= bytecnt - rbytes;
				mp2->b_rptr += mp1->b_wptr - mp1->b_rptr;
				mp1->b_cont = NULL;
				bytecnt = rbytes;
			} else {
				/*
				 * Either there is not enough data in the first
				 * message or there is no excess data to deal
				 * with. If mp1 is NULL, we are taking the
				 * whole message. No need to do anything.
				 * Otherwise we assign mp1->b_cont to mp2 as
				 * we will be putting this back onto the head of
				 * the queue.
				 */
				if (mp1 != NULL) {
					mp2 = mp1->b_cont;
					mp1->b_cont = NULL;
				}
			}
			/*
			 * If mp2 is not NULL then we have part of the message
			 * to put back onto the queue.
			 */
			if (mp2 != NULL) {
				if ((mp2->b_next = bp->b_next) == NULL)
					q->q_last = mp2;
				else
					bp->b_next->b_prev = mp2;
				q->q_first = mp2;
			} else {
				if ((q->q_first = bp->b_next) == NULL)
					q->q_last = NULL;
				else
					q->q_first->b_prev = NULL;
			}
		} else {
			/*
			 * Either no byte threshold was supplied, there is
			 * not enough on the queue or we failed to
			 * duplicate/copy a data block. In these cases we
			 * just take the entire first message.
			 */
dup_failed:
			bytecnt = mp_cont_len(bp, &mblkcnt);
			if ((q->q_first = bp->b_next) == NULL)
				q->q_last = NULL;
			else
				q->q_first->b_prev = NULL;
		}
		if (bp->b_band == 0) {
			q->q_count -= bytecnt;
			q->q_mblkcnt -= mblkcnt;
			if (q->q_mblkcnt == 0 || ((q->q_count < q->q_hiwat) &&
			    (q->q_mblkcnt < q->q_hiwat))) {
				q->q_flag &= ~QFULL;
			}
		} else {
			int i;

			ASSERT(bp->b_band <= q->q_nband);
			ASSERT(q->q_bandp != NULL);
			ASSERT(MUTEX_HELD(QLOCK(q)));
			qbp = q->q_bandp;
			i = bp->b_band;
			while (--i > 0)
				qbp = qbp->qb_next;
			if (qbp->qb_first == qbp->qb_last) {
				qbp->qb_first = NULL;
				qbp->qb_last = NULL;
			} else {
				qbp->qb_first = bp->b_next;
			}
			qbp->qb_count -= bytecnt;
			qbp->qb_mblkcnt -= mblkcnt;
			if (qbp->qb_mblkcnt == 0 ||
			    ((qbp->qb_count < qbp->qb_hiwat) &&
			    (qbp->qb_mblkcnt < qbp->qb_hiwat))) {
				qbp->qb_flag &= ~QB_FULL;
			}
		}
		q->q_flag &= ~QWANTR;
		bp->b_next = NULL;
		bp->b_prev = NULL;
	}
	if (freezer != curthread)
		mutex_exit(QLOCK(q));

	STR_FTEVENT_MSG(bp, q, FTEV_GETQ, NULL);

	return (bp);
}

/*
 * Determine if a backenable is needed after removing a message in the
 * specified band.
 * NOTE: This routine assumes that something like getq_noenab() has been
 * already called.
 *
 * For the read side it is ok to hold sd_lock across calling this (and the
 * stream head often does).
 * But for the write side strwakeq might be invoked and it acquires sd_lock.
 */
void
qbackenable(queue_t *q, uchar_t band)
{
	int backenab = 0;
	qband_t *qbp;
	kthread_id_t freezer;

	ASSERT(q);
	ASSERT((q->q_flag & QREADR) || MUTEX_NOT_HELD(&STREAM(q)->sd_lock));

	/*
	 * Quick check without holding the lock.
	 * OK since after getq() has lowered the q_count these flags
	 * would not change unless either the qbackenable() is done by
	 * another thread (which is ok) or the queue has gotten QFULL
	 * in which case another backenable will take place when the queue
	 * drops below q_lowat.
	 */
	if (band == 0 && (q->q_flag & (QWANTW|QWANTWSYNC)) == 0)
		return;

	/* freezestr should allow its caller to call getq/putq */
	freezer = STREAM(q)->sd_freezer;
	if (freezer == curthread) {
		ASSERT(frozenstr(q));
		ASSERT(MUTEX_HELD(QLOCK(q)));
	} else
		mutex_enter(QLOCK(q));

	if (band == 0) {
		if (q->q_lowat == 0 || (q->q_count < q->q_lowat &&
		    q->q_mblkcnt < q->q_lowat)) {
			backenab = q->q_flag & (QWANTW|QWANTWSYNC);
		}
	} else {
		int i;

		ASSERT((unsigned)band <= q->q_nband);
		ASSERT(q->q_bandp != NULL);

		qbp = q->q_bandp;
		i = band;
		while (--i > 0)
			qbp = qbp->qb_next;

		if (qbp->qb_lowat == 0 || (qbp->qb_count < qbp->qb_lowat &&
		    qbp->qb_mblkcnt < qbp->qb_lowat)) {
			backenab = qbp->qb_flag & QB_WANTW;
		}
	}

	if (backenab == 0) {
		if (freezer != curthread)
			mutex_exit(QLOCK(q));
		return;
	}

	/* Have to drop the lock across strwakeq and backenable */
	if (backenab & QWANTWSYNC)
		q->q_flag &= ~QWANTWSYNC;
	if (backenab & (QWANTW|QB_WANTW)) {
		if (band != 0)
			qbp->qb_flag &= ~QB_WANTW;
		else {
			q->q_flag &= ~QWANTW;
		}
	}

	if (freezer != curthread)
		mutex_exit(QLOCK(q));

	if (backenab & QWANTWSYNC)
		strwakeq(q, QWANTWSYNC);
	if (backenab & (QWANTW|QB_WANTW))
		backenable(q, band);
}

/*
 * Remove a message from a queue.  The queue count and other
 * flow control parameters are adjusted and the back queue
 * enabled if necessary.
 *
 * rmvq can be called with the stream frozen, but other utility functions
 * holding QLOCK, and by streams modules without any locks/frozen.
 */
void
rmvq(queue_t *q, mblk_t *mp)
{
	ASSERT(mp != NULL);

	rmvq_noenab(q, mp);
	if (curthread != STREAM(q)->sd_freezer && MUTEX_HELD(QLOCK(q))) {
		/*
		 * qbackenable can handle a frozen stream but not a "random"
		 * qlock being held. Drop lock across qbackenable.
		 */
		mutex_exit(QLOCK(q));
		qbackenable(q, mp->b_band);
		mutex_enter(QLOCK(q));
	} else {
		qbackenable(q, mp->b_band);
	}
}

/*
 * Like rmvq() but without any backenabling.
 * This exists to handle SR_CONSOL_DATA in strrput().
 */
void
rmvq_noenab(queue_t *q, mblk_t *mp)
{
	int i;
	qband_t *qbp = NULL;
	kthread_id_t freezer;
	int	bytecnt = 0, mblkcnt = 0;

	freezer = STREAM(q)->sd_freezer;
	if (freezer == curthread) {
		ASSERT(frozenstr(q));
		ASSERT(MUTEX_HELD(QLOCK(q)));
	} else if (MUTEX_HELD(QLOCK(q))) {
		/* Don't drop lock on exit */
		freezer = curthread;
	} else
		mutex_enter(QLOCK(q));

	ASSERT(mp->b_band <= q->q_nband);
	if (mp->b_band != 0) {		/* Adjust band pointers */
		ASSERT(q->q_bandp != NULL);
		qbp = q->q_bandp;
		i = mp->b_band;
		while (--i > 0)
			qbp = qbp->qb_next;
		if (mp == qbp->qb_first) {
			if (mp->b_next && mp->b_band == mp->b_next->b_band)
				qbp->qb_first = mp->b_next;
			else
				qbp->qb_first = NULL;
		}
		if (mp == qbp->qb_last) {
			if (mp->b_prev && mp->b_band == mp->b_prev->b_band)
				qbp->qb_last = mp->b_prev;
			else
				qbp->qb_last = NULL;
		}
	}

	/*
	 * Remove the message from the list.
	 */
	if (mp->b_prev)
		mp->b_prev->b_next = mp->b_next;
	else
		q->q_first = mp->b_next;
	if (mp->b_next)
		mp->b_next->b_prev = mp->b_prev;
	else
		q->q_last = mp->b_prev;
	mp->b_next = NULL;
	mp->b_prev = NULL;

	/* Get the size of the message for q_count accounting */
	bytecnt = mp_cont_len(mp, &mblkcnt);

	if (mp->b_band == 0) {		/* Perform q_count accounting */
		q->q_count -= bytecnt;
		q->q_mblkcnt -= mblkcnt;
		if (q->q_mblkcnt == 0 || ((q->q_count < q->q_hiwat) &&
		    (q->q_mblkcnt < q->q_hiwat))) {
			q->q_flag &= ~QFULL;
		}
	} else {			/* Perform qb_count accounting */
		qbp->qb_count -= bytecnt;
		qbp->qb_mblkcnt -= mblkcnt;
		if (qbp->qb_mblkcnt == 0 || ((qbp->qb_count < qbp->qb_hiwat) &&
		    (qbp->qb_mblkcnt < qbp->qb_hiwat))) {
			qbp->qb_flag &= ~QB_FULL;
		}
	}
	if (freezer != curthread)
		mutex_exit(QLOCK(q));

	STR_FTEVENT_MSG(mp, q, FTEV_RMVQ, NULL);
}

/*
 * Empty a queue.
 * If flag is set, remove all messages.  Otherwise, remove
 * only non-control messages.  If queue falls below its low
 * water mark, and QWANTW is set, enable the nearest upstream
 * service procedure.
 *
 * Historical note: when merging the M_FLUSH code in strrput with this
 * code one difference was discovered. flushq did not have a check
 * for q_lowat == 0 in the backenabling test.
 *
 * pcproto_flag specifies whether or not a M_PCPROTO message should be flushed
 * if one exists on the queue.
 */
void
flushq_common(queue_t *q, int flag, int pcproto_flag)
{
	mblk_t *mp, *nmp;
	qband_t *qbp;
	int backenab = 0;
	unsigned char bpri;
	unsigned char	qbf[NBAND];	/* band flushing backenable flags */

	if (q->q_first == NULL)
		return;

	mutex_enter(QLOCK(q));
	mp = q->q_first;
	q->q_first = NULL;
	q->q_last = NULL;
	q->q_count = 0;
	q->q_mblkcnt = 0;
	for (qbp = q->q_bandp; qbp; qbp = qbp->qb_next) {
		qbp->qb_first = NULL;
		qbp->qb_last = NULL;
		qbp->qb_count = 0;
		qbp->qb_mblkcnt = 0;
		qbp->qb_flag &= ~QB_FULL;
	}
	q->q_flag &= ~QFULL;
	mutex_exit(QLOCK(q));
	while (mp) {
		nmp = mp->b_next;
		mp->b_next = mp->b_prev = NULL;

		STR_FTEVENT_MBLK(mp, q, FTEV_FLUSHQ, NULL);

		if (pcproto_flag && (mp->b_datap->db_type == M_PCPROTO))
			(void) putq(q, mp);
		else if (flag || datamsg(mp->b_datap->db_type))
			freemsg(mp);
		else
			(void) putq(q, mp);
		mp = nmp;
	}
	bpri = 1;
	mutex_enter(QLOCK(q));
	for (qbp = q->q_bandp; qbp; qbp = qbp->qb_next) {
		if ((qbp->qb_flag & QB_WANTW) &&
		    (((qbp->qb_count < qbp->qb_lowat) &&
		    (qbp->qb_mblkcnt < qbp->qb_lowat)) ||
		    qbp->qb_lowat == 0)) {
			qbp->qb_flag &= ~QB_WANTW;
			backenab = 1;
			qbf[bpri] = 1;
		} else
			qbf[bpri] = 0;
		bpri++;
	}
	ASSERT(bpri == (unsigned char)(q->q_nband + 1));
	if ((q->q_flag & QWANTW) &&
	    (((q->q_count < q->q_lowat) &&
	    (q->q_mblkcnt < q->q_lowat)) || q->q_lowat == 0)) {
		q->q_flag &= ~QWANTW;
		backenab = 1;
		qbf[0] = 1;
	} else
		qbf[0] = 0;

	/*
	 * If any band can now be written to, and there is a writer
	 * for that band, then backenable the closest service procedure.
	 */
	if (backenab) {
		mutex_exit(QLOCK(q));
		for (bpri = q->q_nband; bpri != 0; bpri--)
			if (qbf[bpri])
				backenable(q, bpri);
		if (qbf[0])
			backenable(q, 0);
	} else
		mutex_exit(QLOCK(q));
}

/*
 * The real flushing takes place in flushq_common. This is done so that
 * a flag which specifies whether or not M_PCPROTO messages should be flushed
 * or not. Currently the only place that uses this flag is the stream head.
 */
void
flushq(queue_t *q, int flag)
{
	flushq_common(q, flag, 0);
}

/*
 * Flush the queue of messages of the given priority band.
 * There is some duplication of code between flushq and flushband.
 * This is because we want to optimize the code as much as possible.
 * The assumption is that there will be more messages in the normal
 * (priority 0) band than in any other.
 *
 * Historical note: when merging the M_FLUSH code in strrput with this
 * code one difference was discovered. flushband had an extra check for
 * did not have a check for (mp->b_datap->db_type < QPCTL) in the band 0
 * case. That check does not match the man page for flushband and was not
 * in the strrput flush code hence it was removed.
 */
void
flushband(queue_t *q, unsigned char pri, int flag)
{
	mblk_t *mp;
	mblk_t *nmp;
	mblk_t *last;
	qband_t *qbp;
	int band;

	ASSERT((flag == FLUSHDATA) || (flag == FLUSHALL));
	if (pri > q->q_nband) {
		return;
	}
	mutex_enter(QLOCK(q));
	if (pri == 0) {
		mp = q->q_first;
		q->q_first = NULL;
		q->q_last = NULL;
		q->q_count = 0;
		q->q_mblkcnt = 0;
		for (qbp = q->q_bandp; qbp; qbp = qbp->qb_next) {
			qbp->qb_first = NULL;
			qbp->qb_last = NULL;
			qbp->qb_count = 0;
			qbp->qb_mblkcnt = 0;
			qbp->qb_flag &= ~QB_FULL;
		}
		q->q_flag &= ~QFULL;
		mutex_exit(QLOCK(q));
		while (mp) {
			nmp = mp->b_next;
			mp->b_next = mp->b_prev = NULL;
			if ((mp->b_band == 0) &&
			    ((flag == FLUSHALL) ||
			    datamsg(mp->b_datap->db_type)))
				freemsg(mp);
			else
				(void) putq(q, mp);
			mp = nmp;
		}
		mutex_enter(QLOCK(q));
		if ((q->q_flag & QWANTW) &&
		    (((q->q_count < q->q_lowat) &&
		    (q->q_mblkcnt < q->q_lowat)) || q->q_lowat == 0)) {
			q->q_flag &= ~QWANTW;
			mutex_exit(QLOCK(q));

			backenable(q, pri);
		} else
			mutex_exit(QLOCK(q));
	} else {	/* pri != 0 */
		boolean_t flushed = B_FALSE;
		band = pri;

		ASSERT(MUTEX_HELD(QLOCK(q)));
		qbp = q->q_bandp;
		while (--band > 0)
			qbp = qbp->qb_next;
		mp = qbp->qb_first;
		if (mp == NULL) {
			mutex_exit(QLOCK(q));
			return;
		}
		last = qbp->qb_last->b_next;
		/*
		 * rmvq_noenab() and freemsg() are called for each mblk that
		 * meets the criteria.  The loop is executed until the last
		 * mblk has been processed.
		 */
		while (mp != last) {
			ASSERT(mp->b_band == pri);
			nmp = mp->b_next;
			if (flag == FLUSHALL || datamsg(mp->b_datap->db_type)) {
				rmvq_noenab(q, mp);
				freemsg(mp);
				flushed = B_TRUE;
			}
			mp = nmp;
		}
		mutex_exit(QLOCK(q));

		/*
		 * If any mblk(s) has been freed, we know that qbackenable()
		 * will need to be called.
		 */
		if (flushed)
			qbackenable(q, pri);
	}
}

/*
 * Return 1 if the queue is not full.  If the queue is full, return
 * 0 (may not put message) and set QWANTW flag (caller wants to write
 * to the queue).
 */
int
canput(queue_t *q)
{
	TRACE_1(TR_FAC_STREAMS_FR, TR_CANPUT_IN, "canput:%p", q);

	/* this is for loopback transports, they should not do a canput */
	ASSERT(STRMATED(q->q_stream) || STREAM(q) == STREAM(q->q_nfsrv));

	/* Find next forward module that has a service procedure */
	q = q->q_nfsrv;

	if (!(q->q_flag & QFULL)) {
		TRACE_2(TR_FAC_STREAMS_FR, TR_CANPUT_OUT, "canput:%p %d", q, 1);
		return (1);
	}
	mutex_enter(QLOCK(q));
	if (q->q_flag & QFULL) {
		q->q_flag |= QWANTW;
		mutex_exit(QLOCK(q));
		TRACE_2(TR_FAC_STREAMS_FR, TR_CANPUT_OUT, "canput:%p %d", q, 0);
		return (0);
	}
	mutex_exit(QLOCK(q));
	TRACE_2(TR_FAC_STREAMS_FR, TR_CANPUT_OUT, "canput:%p %d", q, 1);
	return (1);
}

/*
 * This is the new canput for use with priority bands.  Return 1 if the
 * band is not full.  If the band is full, return 0 (may not put message)
 * and set QWANTW(QB_WANTW) flag for zero(non-zero) band (caller wants to
 * write to the queue).
 */
int
bcanput(queue_t *q, unsigned char pri)
{
	qband_t *qbp;

	TRACE_2(TR_FAC_STREAMS_FR, TR_BCANPUT_IN, "bcanput:%p %p", q, pri);
	if (!q)
		return (0);

	/* Find next forward module that has a service procedure */
	q = q->q_nfsrv;

	mutex_enter(QLOCK(q));
	if (pri == 0) {
		if (q->q_flag & QFULL) {
			q->q_flag |= QWANTW;
			mutex_exit(QLOCK(q));
			TRACE_3(TR_FAC_STREAMS_FR, TR_BCANPUT_OUT,
			    "bcanput:%p %X %d", q, pri, 0);
			return (0);
		}
	} else {	/* pri != 0 */
		if (pri > q->q_nband) {
			/*
			 * No band exists yet, so return success.
			 */
			mutex_exit(QLOCK(q));
			TRACE_3(TR_FAC_STREAMS_FR, TR_BCANPUT_OUT,
			    "bcanput:%p %X %d", q, pri, 1);
			return (1);
		}
		qbp = q->q_bandp;
		while (--pri)
			qbp = qbp->qb_next;
		if (qbp->qb_flag & QB_FULL) {
			qbp->qb_flag |= QB_WANTW;
			mutex_exit(QLOCK(q));
			TRACE_3(TR_FAC_STREAMS_FR, TR_BCANPUT_OUT,
			    "bcanput:%p %X %d", q, pri, 0);
			return (0);
		}
	}
	mutex_exit(QLOCK(q));
	TRACE_3(TR_FAC_STREAMS_FR, TR_BCANPUT_OUT,
	    "bcanput:%p %X %d", q, pri, 1);
	return (1);
}

/*
 * Put a message on a queue.
 *
 * Messages are enqueued on a priority basis.  The priority classes
 * are HIGH PRIORITY (type >= QPCTL), PRIORITY (type < QPCTL && band > 0),
 * and B_NORMAL (type < QPCTL && band == 0).
 *
 * Add appropriate weighted data block sizes to queue count.
 * If queue hits high water mark then set QFULL flag.
 *
 * If QNOENAB is not set (putq is allowed to enable the queue),
 * enable the queue only if the message is PRIORITY,
 * or the QWANTR flag is set (indicating that the service procedure
 * is ready to read the queue.  This implies that a service
 * procedure must NEVER put a high priority message back on its own
 * queue, as this would result in an infinite loop (!).
 */
int
putq(queue_t *q, mblk_t *bp)
{
	mblk_t *tmp;
	qband_t *qbp = NULL;
	int mcls = (int)queclass(bp);
	kthread_id_t freezer;
	int	bytecnt = 0, mblkcnt = 0;

	freezer = STREAM(q)->sd_freezer;
	if (freezer == curthread) {
		ASSERT(frozenstr(q));
		ASSERT(MUTEX_HELD(QLOCK(q)));
	} else
		mutex_enter(QLOCK(q));

	/*
	 * Make sanity checks and if qband structure is not yet
	 * allocated, do so.
	 */
	if (mcls == QPCTL) {
		if (bp->b_band != 0)
			bp->b_band = 0;		/* force to be correct */
	} else if (bp->b_band != 0) {
		int i;
		qband_t **qbpp;

		if (bp->b_band > q->q_nband) {

			/*
			 * The qband structure for this priority band is
			 * not on the queue yet, so we have to allocate
			 * one on the fly.  It would be wasteful to
			 * associate the qband structures with every
			 * queue when the queues are allocated.  This is
			 * because most queues will only need the normal
			 * band of flow which can be described entirely
			 * by the queue itself.
			 */
			qbpp = &q->q_bandp;
			while (*qbpp)
				qbpp = &(*qbpp)->qb_next;
			while (bp->b_band > q->q_nband) {
				if ((*qbpp = allocband()) == NULL) {
					if (freezer != curthread)
						mutex_exit(QLOCK(q));
					return (0);
				}
				(*qbpp)->qb_hiwat = q->q_hiwat;
				(*qbpp)->qb_lowat = q->q_lowat;
				q->q_nband++;
				qbpp = &(*qbpp)->qb_next;
			}
		}
		ASSERT(MUTEX_HELD(QLOCK(q)));
		qbp = q->q_bandp;
		i = bp->b_band;
		while (--i)
			qbp = qbp->qb_next;
	}

	/*
	 * If queue is empty, add the message and initialize the pointers.
	 * Otherwise, adjust message pointers and queue pointers based on
	 * the type of the message and where it belongs on the queue.  Some
	 * code is duplicated to minimize the number of conditionals and
	 * hopefully minimize the amount of time this routine takes.
	 */
	if (!q->q_first) {
		bp->b_next = NULL;
		bp->b_prev = NULL;
		q->q_first = bp;
		q->q_last = bp;
		if (qbp) {
			qbp->qb_first = bp;
			qbp->qb_last = bp;
		}
	} else if (!qbp) {	/* bp->b_band == 0 */

		/*
		 * If queue class of message is less than or equal to
		 * that of the last one on the queue, tack on to the end.
		 */
		tmp = q->q_last;
		if (mcls <= (int)queclass(tmp)) {
			bp->b_next = NULL;
			bp->b_prev = tmp;
			tmp->b_next = bp;
			q->q_last = bp;
		} else {
			tmp = q->q_first;
			while ((int)queclass(tmp) >= mcls)
				tmp = tmp->b_next;

			/*
			 * Insert bp before tmp.
			 */
			bp->b_next = tmp;
			bp->b_prev = tmp->b_prev;
			if (tmp->b_prev)
				tmp->b_prev->b_next = bp;
			else
				q->q_first = bp;
			tmp->b_prev = bp;
		}
	} else {		/* bp->b_band != 0 */
		if (qbp->qb_first) {
			tmp = qbp->qb_last;

			/*
			 * Insert bp after the last message in this band.
			 */
			bp->b_next = tmp->b_next;
			if (tmp->b_next)
				tmp->b_next->b_prev = bp;
			else
				q->q_last = bp;
			bp->b_prev = tmp;
			tmp->b_next = bp;
		} else {
			tmp = q->q_last;
			if ((mcls < (int)queclass(tmp)) ||
			    (bp->b_band <= tmp->b_band)) {

				/*
				 * Tack bp on end of queue.
				 */
				bp->b_next = NULL;
				bp->b_prev = tmp;
				tmp->b_next = bp;
				q->q_last = bp;
			} else {
				tmp = q->q_first;
				while (tmp->b_datap->db_type >= QPCTL)
					tmp = tmp->b_next;
				while (tmp->b_band >= bp->b_band)
					tmp = tmp->b_next;

				/*
				 * Insert bp before tmp.
				 */
				bp->b_next = tmp;
				bp->b_prev = tmp->b_prev;
				if (tmp->b_prev)
					tmp->b_prev->b_next = bp;
				else
					q->q_first = bp;
				tmp->b_prev = bp;
			}
			qbp->qb_first = bp;
		}
		qbp->qb_last = bp;
	}

	/* Get message byte count for q_count accounting */
	bytecnt = mp_cont_len(bp, &mblkcnt);

	if (qbp) {
		qbp->qb_count += bytecnt;
		qbp->qb_mblkcnt += mblkcnt;
		if ((qbp->qb_count >= qbp->qb_hiwat) ||
		    (qbp->qb_mblkcnt >= qbp->qb_hiwat)) {
			qbp->qb_flag |= QB_FULL;
		}
	} else {
		q->q_count += bytecnt;
		q->q_mblkcnt += mblkcnt;
		if ((q->q_count >= q->q_hiwat) ||
		    (q->q_mblkcnt >= q->q_hiwat)) {
			q->q_flag |= QFULL;
		}
	}

	STR_FTEVENT_MSG(bp, q, FTEV_PUTQ, NULL);

	if ((mcls > QNORM) ||
	    (canenable(q) && (q->q_flag & QWANTR || bp->b_band)))
		qenable_locked(q);
	ASSERT(MUTEX_HELD(QLOCK(q)));
	if (freezer != curthread)
		mutex_exit(QLOCK(q));

	return (1);
}

/*
 * Put stuff back at beginning of Q according to priority order.
 * See comment on putq above for details.
 */
int
putbq(queue_t *q, mblk_t *bp)
{
	mblk_t *tmp;
	qband_t *qbp = NULL;
	int mcls = (int)queclass(bp);
	kthread_id_t freezer;
	int	bytecnt = 0, mblkcnt = 0;

	ASSERT(q && bp);
	ASSERT(bp->b_next == NULL);
	freezer = STREAM(q)->sd_freezer;
	if (freezer == curthread) {
		ASSERT(frozenstr(q));
		ASSERT(MUTEX_HELD(QLOCK(q)));
	} else
		mutex_enter(QLOCK(q));

	/*
	 * Make sanity checks and if qband structure is not yet
	 * allocated, do so.
	 */
	if (mcls == QPCTL) {
		if (bp->b_band != 0)
			bp->b_band = 0;		/* force to be correct */
	} else if (bp->b_band != 0) {
		int i;
		qband_t **qbpp;

		if (bp->b_band > q->q_nband) {
			qbpp = &q->q_bandp;
			while (*qbpp)
				qbpp = &(*qbpp)->qb_next;
			while (bp->b_band > q->q_nband) {
				if ((*qbpp = allocband()) == NULL) {
					if (freezer != curthread)
						mutex_exit(QLOCK(q));
					return (0);
				}
				(*qbpp)->qb_hiwat = q->q_hiwat;
				(*qbpp)->qb_lowat = q->q_lowat;
				q->q_nband++;
				qbpp = &(*qbpp)->qb_next;
			}
		}
		qbp = q->q_bandp;
		i = bp->b_band;
		while (--i)
			qbp = qbp->qb_next;
	}

	/*
	 * If queue is empty or if message is high priority,
	 * place on the front of the queue.
	 */
	tmp = q->q_first;
	if ((!tmp) || (mcls == QPCTL)) {
		bp->b_next = tmp;
		if (tmp)
			tmp->b_prev = bp;
		else
			q->q_last = bp;
		q->q_first = bp;
		bp->b_prev = NULL;
		if (qbp) {
			qbp->qb_first = bp;
			qbp->qb_last = bp;
		}
	} else if (qbp) {	/* bp->b_band != 0 */
		tmp = qbp->qb_first;
		if (tmp) {

			/*
			 * Insert bp before the first message in this band.
			 */
			bp->b_next = tmp;
			bp->b_prev = tmp->b_prev;
			if (tmp->b_prev)
				tmp->b_prev->b_next = bp;
			else
				q->q_first = bp;
			tmp->b_prev = bp;
		} else {
			tmp = q->q_last;
			if ((mcls < (int)queclass(tmp)) ||
			    (bp->b_band < tmp->b_band)) {

				/*
				 * Tack bp on end of queue.
				 */
				bp->b_next = NULL;
				bp->b_prev = tmp;
				tmp->b_next = bp;
				q->q_last = bp;
			} else {
				tmp = q->q_first;
				while (tmp->b_datap->db_type >= QPCTL)
					tmp = tmp->b_next;
				while (tmp->b_band > bp->b_band)
					tmp = tmp->b_next;

				/*
				 * Insert bp before tmp.
				 */
				bp->b_next = tmp;
				bp->b_prev = tmp->b_prev;
				if (tmp->b_prev)
					tmp->b_prev->b_next = bp;
				else
					q->q_first = bp;
				tmp->b_prev = bp;
			}
			qbp->qb_last = bp;
		}
		qbp->qb_first = bp;
	} else {		/* bp->b_band == 0 && !QPCTL */

		/*
		 * If the queue class or band is less than that of the last
		 * message on the queue, tack bp on the end of the queue.
		 */
		tmp = q->q_last;
		if ((mcls < (int)queclass(tmp)) || (bp->b_band < tmp->b_band)) {
			bp->b_next = NULL;
			bp->b_prev = tmp;
			tmp->b_next = bp;
			q->q_last = bp;
		} else {
			tmp = q->q_first;
			while (tmp->b_datap->db_type >= QPCTL)
				tmp = tmp->b_next;
			while (tmp->b_band > bp->b_band)
				tmp = tmp->b_next;

			/*
			 * Insert bp before tmp.
			 */
			bp->b_next = tmp;
			bp->b_prev = tmp->b_prev;
			if (tmp->b_prev)
				tmp->b_prev->b_next = bp;
			else
				q->q_first = bp;
			tmp->b_prev = bp;
		}
	}

	/* Get message byte count for q_count accounting */
	bytecnt = mp_cont_len(bp, &mblkcnt);

	if (qbp) {
		qbp->qb_count += bytecnt;
		qbp->qb_mblkcnt += mblkcnt;
		if ((qbp->qb_count >= qbp->qb_hiwat) ||
		    (qbp->qb_mblkcnt >= qbp->qb_hiwat)) {
			qbp->qb_flag |= QB_FULL;
		}
	} else {
		q->q_count += bytecnt;
		q->q_mblkcnt += mblkcnt;
		if ((q->q_count >= q->q_hiwat) ||
		    (q->q_mblkcnt >= q->q_hiwat)) {
			q->q_flag |= QFULL;
		}
	}

	STR_FTEVENT_MSG(bp, q, FTEV_PUTBQ, NULL);

	if ((mcls > QNORM) || (canenable(q) && (q->q_flag & QWANTR)))
		qenable_locked(q);
	ASSERT(MUTEX_HELD(QLOCK(q)));
	if (freezer != curthread)
		mutex_exit(QLOCK(q));

	return (1);
}

/*
 * Insert a message before an existing message on the queue.  If the
 * existing message is NULL, the new messages is placed on the end of
 * the queue.  The queue class of the new message is ignored.  However,
 * the priority band of the new message must adhere to the following
 * ordering:
 *
 *	emp->b_prev->b_band >= mp->b_band >= emp->b_band.
 *
 * All flow control parameters are updated.
 *
 * insq can be called with the stream frozen, but other utility functions
 * holding QLOCK, and by streams modules without any locks/frozen.
 */
int
insq(queue_t *q, mblk_t *emp, mblk_t *mp)
{
	mblk_t *tmp;
	qband_t *qbp = NULL;
	int mcls = (int)queclass(mp);
	kthread_id_t freezer;
	int	bytecnt = 0, mblkcnt = 0;

	freezer = STREAM(q)->sd_freezer;
	if (freezer == curthread) {
		ASSERT(frozenstr(q));
		ASSERT(MUTEX_HELD(QLOCK(q)));
	} else if (MUTEX_HELD(QLOCK(q))) {
		/* Don't drop lock on exit */
		freezer = curthread;
	} else
		mutex_enter(QLOCK(q));

	if (mcls == QPCTL) {
		if (mp->b_band != 0)
			mp->b_band = 0;		/* force to be correct */
		if (emp && emp->b_prev &&
		    (emp->b_prev->b_datap->db_type < QPCTL))
			goto badord;
	}
	if (emp) {
		if (((mcls == QNORM) && (mp->b_band < emp->b_band)) ||
		    (emp->b_prev && (emp->b_prev->b_datap->db_type < QPCTL) &&
		    (emp->b_prev->b_band < mp->b_band))) {
			goto badord;
		}
	} else {
		tmp = q->q_last;
		if (tmp && (mcls == QNORM) && (mp->b_band > tmp->b_band)) {
badord:
			cmn_err(CE_WARN,
			    "insq: attempt to insert message out of order "
			    "on q %p", (void *)q);
			if (freezer != curthread)
				mutex_exit(QLOCK(q));
			return (0);
		}
	}

	if (mp->b_band != 0) {
		int i;
		qband_t **qbpp;

		if (mp->b_band > q->q_nband) {
			qbpp = &q->q_bandp;
			while (*qbpp)
				qbpp = &(*qbpp)->qb_next;
			while (mp->b_band > q->q_nband) {
				if ((*qbpp = allocband()) == NULL) {
					if (freezer != curthread)
						mutex_exit(QLOCK(q));
					return (0);
				}
				(*qbpp)->qb_hiwat = q->q_hiwat;
				(*qbpp)->qb_lowat = q->q_lowat;
				q->q_nband++;
				qbpp = &(*qbpp)->qb_next;
			}
		}
		qbp = q->q_bandp;
		i = mp->b_band;
		while (--i)
			qbp = qbp->qb_next;
	}

	if ((mp->b_next = emp) != NULL) {
		if ((mp->b_prev = emp->b_prev) != NULL)
			emp->b_prev->b_next = mp;
		else
			q->q_first = mp;
		emp->b_prev = mp;
	} else {
		if ((mp->b_prev = q->q_last) != NULL)
			q->q_last->b_next = mp;
		else
			q->q_first = mp;
		q->q_last = mp;
	}

	/* Get mblk and byte count for q_count accounting */
	bytecnt = mp_cont_len(mp, &mblkcnt);

	if (qbp) {	/* adjust qband pointers and count */
		if (!qbp->qb_first) {
			qbp->qb_first = mp;
			qbp->qb_last = mp;
		} else {
			if (mp->b_prev == NULL || (mp->b_prev != NULL &&
			    (mp->b_prev->b_band != mp->b_band)))
				qbp->qb_first = mp;
			else if (mp->b_next == NULL || (mp->b_next != NULL &&
			    (mp->b_next->b_band != mp->b_band)))
				qbp->qb_last = mp;
		}
		qbp->qb_count += bytecnt;
		qbp->qb_mblkcnt += mblkcnt;
		if ((qbp->qb_count >= qbp->qb_hiwat) ||
		    (qbp->qb_mblkcnt >= qbp->qb_hiwat)) {
			qbp->qb_flag |= QB_FULL;
		}
	} else {
		q->q_count += bytecnt;
		q->q_mblkcnt += mblkcnt;
		if ((q->q_count >= q->q_hiwat) ||
		    (q->q_mblkcnt >= q->q_hiwat)) {
			q->q_flag |= QFULL;
		}
	}

	STR_FTEVENT_MSG(mp, q, FTEV_INSQ, NULL);

	if (canenable(q) && (q->q_flag & QWANTR))
		qenable_locked(q);

	ASSERT(MUTEX_HELD(QLOCK(q)));
	if (freezer != curthread)
		mutex_exit(QLOCK(q));

	return (1);
}

/*
 * Create and put a control message on queue.
 */
int
putctl(queue_t *q, int type)
{
	mblk_t *bp;

	if ((datamsg(type) && (type != M_DELAY)) ||
	    (bp = allocb_tryhard(0)) == NULL)
		return (0);
	bp->b_datap->db_type = (unsigned char) type;

	put(q, bp);

	return (1);
}

/*
 * Control message with a single-byte parameter
 */
int
putctl1(queue_t *q, int type, int param)
{
	mblk_t *bp;

	if ((datamsg(type) && (type != M_DELAY)) ||
	    (bp = allocb_tryhard(1)) == NULL)
		return (0);
	bp->b_datap->db_type = (unsigned char)type;
	*bp->b_wptr++ = (unsigned char)param;

	put(q, bp);

	return (1);
}

int
putnextctl1(queue_t *q, int type, int param)
{
	mblk_t *bp;

	if ((datamsg(type) && (type != M_DELAY)) ||
	    ((bp = allocb_tryhard(1)) == NULL))
		return (0);

	bp->b_datap->db_type = (unsigned char)type;
	*bp->b_wptr++ = (unsigned char)param;

	putnext(q, bp);

	return (1);
}

int
putnextctl(queue_t *q, int type)
{
	mblk_t *bp;

	if ((datamsg(type) && (type != M_DELAY)) ||
	    ((bp = allocb_tryhard(0)) == NULL))
		return (0);
	bp->b_datap->db_type = (unsigned char)type;

	putnext(q, bp);

	return (1);
}

/*
 * Return the queue upstream from this one
 */
queue_t *
backq(queue_t *q)
{
	q = _OTHERQ(q);
	if (q->q_next) {
		q = q->q_next;
		return (_OTHERQ(q));
	}
	return (NULL);
}

/*
 * Send a block back up the queue in reverse from this
 * one (e.g. to respond to ioctls)
 */
void
qreply(queue_t *q, mblk_t *bp)
{
	ASSERT(q && bp);

	putnext(_OTHERQ(q), bp);
}

/*
 * Streams Queue Scheduling
 *
 * Queues are enabled through qenable() when they have messages to
 * process.  They are serviced by queuerun(), which runs each enabled
 * queue's service procedure.  The call to queuerun() is processor
 * dependent - the general principle is that it be run whenever a queue
 * is enabled but before returning to user level.  For system calls,
 * the function runqueues() is called if their action causes a queue
 * to be enabled.  For device interrupts, queuerun() should be
 * called before returning from the last level of interrupt.  Beyond
 * this, no timing assumptions should be made about queue scheduling.
 */

/*
 * Enable a queue: put it on list of those whose service procedures are
 * ready to run and set up the scheduling mechanism.
 * The broadcast is done outside the mutex -> to avoid the woken thread
 * from contending with the mutex. This is OK 'cos the queue has been
 * enqueued on the runlist and flagged safely at this point.
 */
void
qenable(queue_t *q)
{
	mutex_enter(QLOCK(q));
	qenable_locked(q);
	mutex_exit(QLOCK(q));
}
/*
 * Return number of messages on queue
 */
int
qsize(queue_t *qp)
{
	int count = 0;
	mblk_t *mp;

	mutex_enter(QLOCK(qp));
	for (mp = qp->q_first; mp; mp = mp->b_next)
		count++;
	mutex_exit(QLOCK(qp));
	return (count);
}

/*
 * noenable - set queue so that putq() will not enable it.
 * enableok - set queue so that putq() can enable it.
 */
void
noenable(queue_t *q)
{
	mutex_enter(QLOCK(q));
	q->q_flag |= QNOENB;
	mutex_exit(QLOCK(q));
}

void
enableok(queue_t *q)
{
	mutex_enter(QLOCK(q));
	q->q_flag &= ~QNOENB;
	mutex_exit(QLOCK(q));
}

/*
 * Set queue fields.
 */
int
strqset(queue_t *q, qfields_t what, unsigned char pri, intptr_t val)
{
	qband_t *qbp = NULL;
	queue_t	*wrq;
	int error = 0;
	kthread_id_t freezer;

	freezer = STREAM(q)->sd_freezer;
	if (freezer == curthread) {
		ASSERT(frozenstr(q));
		ASSERT(MUTEX_HELD(QLOCK(q)));
	} else
		mutex_enter(QLOCK(q));

	if (what >= QBAD) {
		error = EINVAL;
		goto done;
	}
	if (pri != 0) {
		int i;
		qband_t **qbpp;

		if (pri > q->q_nband) {
			qbpp = &q->q_bandp;
			while (*qbpp)
				qbpp = &(*qbpp)->qb_next;
			while (pri > q->q_nband) {
				if ((*qbpp = allocband()) == NULL) {
					error = EAGAIN;
					goto done;
				}
				(*qbpp)->qb_hiwat = q->q_hiwat;
				(*qbpp)->qb_lowat = q->q_lowat;
				q->q_nband++;
				qbpp = &(*qbpp)->qb_next;
			}
		}
		qbp = q->q_bandp;
		i = pri;
		while (--i)
			qbp = qbp->qb_next;
	}
	switch (what) {

	case QHIWAT:
		if (qbp)
			qbp->qb_hiwat = (size_t)val;
		else
			q->q_hiwat = (size_t)val;
		break;

	case QLOWAT:
		if (qbp)
			qbp->qb_lowat = (size_t)val;
		else
			q->q_lowat = (size_t)val;
		break;

	case QMAXPSZ:
		if (qbp)
			error = EINVAL;
		else
			q->q_maxpsz = (ssize_t)val;

		/*
		 * Performance concern, strwrite looks at the module below
		 * the stream head for the maxpsz each time it does a write
		 * we now cache it at the stream head.  Check to see if this
		 * queue is sitting directly below the stream head.
		 */
		wrq = STREAM(q)->sd_wrq;
		if (q != wrq->q_next)
			break;

		/*
		 * If the stream is not frozen drop the current QLOCK and
		 * acquire the sd_wrq QLOCK which protects sd_qn_*
		 */
		if (freezer != curthread) {
			mutex_exit(QLOCK(q));
			mutex_enter(QLOCK(wrq));
		}
		ASSERT(MUTEX_HELD(QLOCK(wrq)));

		if (strmsgsz != 0) {
			if (val == INFPSZ)
				val = strmsgsz;
			else  {
				if (STREAM(q)->sd_vnode->v_type == VFIFO)
					val = MIN(PIPE_BUF, val);
				else
					val = MIN(strmsgsz, val);
			}
		}
		STREAM(q)->sd_qn_maxpsz = val;
		if (freezer != curthread) {
			mutex_exit(QLOCK(wrq));
			mutex_enter(QLOCK(q));
		}
		break;

	case QMINPSZ:
		if (qbp)
			error = EINVAL;
		else
			q->q_minpsz = (ssize_t)val;

		/*
		 * Performance concern, strwrite looks at the module below
		 * the stream head for the maxpsz each time it does a write
		 * we now cache it at the stream head.  Check to see if this
		 * queue is sitting directly below the stream head.
		 */
		wrq = STREAM(q)->sd_wrq;
		if (q != wrq->q_next)
			break;

		/*
		 * If the stream is not frozen drop the current QLOCK and
		 * acquire the sd_wrq QLOCK which protects sd_qn_*
		 */
		if (freezer != curthread) {
			mutex_exit(QLOCK(q));
			mutex_enter(QLOCK(wrq));
		}
		STREAM(q)->sd_qn_minpsz = (ssize_t)val;

		if (freezer != curthread) {
			mutex_exit(QLOCK(wrq));
			mutex_enter(QLOCK(q));
		}
		break;

	case QSTRUIOT:
		if (qbp)
			error = EINVAL;
		else
			q->q_struiot = (ushort_t)val;
		break;

	case QCOUNT:
	case QFIRST:
	case QLAST:
	case QFLAG:
		error = EPERM;
		break;

	default:
		error = EINVAL;
		break;
	}
done:
	if (freezer != curthread)
		mutex_exit(QLOCK(q));
	return (error);
}

/*
 * Get queue fields.
 */
int
strqget(queue_t *q, qfields_t what, unsigned char pri, void *valp)
{
	qband_t 	*qbp = NULL;
	int 		error = 0;
	kthread_id_t 	freezer;

	freezer = STREAM(q)->sd_freezer;
	if (freezer == curthread) {
		ASSERT(frozenstr(q));
		ASSERT(MUTEX_HELD(QLOCK(q)));
	} else
		mutex_enter(QLOCK(q));
	if (what >= QBAD) {
		error = EINVAL;
		goto done;
	}
	if (pri != 0) {
		int i;
		qband_t **qbpp;

		if (pri > q->q_nband) {
			qbpp = &q->q_bandp;
			while (*qbpp)
				qbpp = &(*qbpp)->qb_next;
			while (pri > q->q_nband) {
				if ((*qbpp = allocband()) == NULL) {
					error = EAGAIN;
					goto done;
				}
				(*qbpp)->qb_hiwat = q->q_hiwat;
				(*qbpp)->qb_lowat = q->q_lowat;
				q->q_nband++;
				qbpp = &(*qbpp)->qb_next;
			}
		}
		qbp = q->q_bandp;
		i = pri;
		while (--i)
			qbp = qbp->qb_next;
	}
	switch (what) {
	case QHIWAT:
		if (qbp)
			*(size_t *)valp = qbp->qb_hiwat;
		else
			*(size_t *)valp = q->q_hiwat;
		break;

	case QLOWAT:
		if (qbp)
			*(size_t *)valp = qbp->qb_lowat;
		else
			*(size_t *)valp = q->q_lowat;
		break;

	case QMAXPSZ:
		if (qbp)
			error = EINVAL;
		else
			*(ssize_t *)valp = q->q_maxpsz;
		break;

	case QMINPSZ:
		if (qbp)
			error = EINVAL;
		else
			*(ssize_t *)valp = q->q_minpsz;
		break;

	case QCOUNT:
		if (qbp)
			*(size_t *)valp = qbp->qb_count;
		else
			*(size_t *)valp = q->q_count;
		break;

	case QFIRST:
		if (qbp)
			*(mblk_t **)valp = qbp->qb_first;
		else
			*(mblk_t **)valp = q->q_first;
		break;

	case QLAST:
		if (qbp)
			*(mblk_t **)valp = qbp->qb_last;
		else
			*(mblk_t **)valp = q->q_last;
		break;

	case QFLAG:
		if (qbp)
			*(uint_t *)valp = qbp->qb_flag;
		else
			*(uint_t *)valp = q->q_flag;
		break;

	case QSTRUIOT:
		if (qbp)
			error = EINVAL;
		else
			*(short *)valp = q->q_struiot;
		break;

	default:
		error = EINVAL;
		break;
	}
done:
	if (freezer != curthread)
		mutex_exit(QLOCK(q));
	return (error);
}

/*
 * Function awakes all in cvwait/sigwait/pollwait, on one of:
 *	QWANTWSYNC or QWANTR or QWANTW,
 *
 * Note: for QWANTWSYNC/QWANTW and QWANTR, if no WSLEEPer or RSLEEPer then a
 *	 deferred wakeup will be done. Also if strpoll() in progress then a
 *	 deferred pollwakeup will be done.
 */
void
strwakeq(queue_t *q, int flag)
{
	stdata_t 	*stp = STREAM(q);
	pollhead_t 	*pl;

	mutex_enter(&stp->sd_lock);
	pl = &stp->sd_pollist;
	if (flag & QWANTWSYNC) {
		ASSERT(!(q->q_flag & QREADR));
		if (stp->sd_flag & WSLEEP) {
			stp->sd_flag &= ~WSLEEP;
			cv_broadcast(&stp->sd_wrq->q_wait);
		} else {
			stp->sd_wakeq |= WSLEEP;
		}

		mutex_exit(&stp->sd_lock);
		pollwakeup(pl, POLLWRNORM);
		mutex_enter(&stp->sd_lock);

		if (stp->sd_sigflags & S_WRNORM)
			strsendsig(stp->sd_siglist, S_WRNORM, 0, 0);
	} else if (flag & QWANTR) {
		if (stp->sd_flag & RSLEEP) {
			stp->sd_flag &= ~RSLEEP;
			cv_broadcast(&_RD(stp->sd_wrq)->q_wait);
		} else {
			stp->sd_wakeq |= RSLEEP;
		}

		mutex_exit(&stp->sd_lock);
		pollwakeup(pl, POLLIN | POLLRDNORM);
		mutex_enter(&stp->sd_lock);

		{
			int events = stp->sd_sigflags & (S_INPUT | S_RDNORM);

			if (events)
				strsendsig(stp->sd_siglist, events, 0, 0);
		}
	} else {
		if (stp->sd_flag & WSLEEP) {
			stp->sd_flag &= ~WSLEEP;
			cv_broadcast(&stp->sd_wrq->q_wait);
		}

		mutex_exit(&stp->sd_lock);
		pollwakeup(pl, POLLWRNORM);
		mutex_enter(&stp->sd_lock);

		if (stp->sd_sigflags & S_WRNORM)
			strsendsig(stp->sd_siglist, S_WRNORM, 0, 0);
	}
	mutex_exit(&stp->sd_lock);
}

int
struioget(queue_t *q, mblk_t *mp, struiod_t *dp, int noblock)
{
	stdata_t *stp = STREAM(q);
	int typ  = STRUIOT_STANDARD;
	uio_t	 *uiop = &dp->d_uio;
	dblk_t	 *dbp;
	ssize_t	 uiocnt;
	ssize_t	 cnt;
	unsigned char *ptr;
	ssize_t	 resid;
	int	 error = 0;
	on_trap_data_t otd;
	queue_t	*stwrq;

	/*
	 * Plumbing may change while taking the type so store the
	 * queue in a temporary variable. It doesn't matter even
	 * if the we take the type from the previous plumbing,
	 * that's because if the plumbing has changed when we were
	 * holding the queue in a temporary variable, we can continue
	 * processing the message the way it would have been processed
	 * in the old plumbing, without any side effects but a bit
	 * extra processing for partial ip header checksum.
	 *
	 * This has been done to avoid holding the sd_lock which is
	 * very hot.
	 */

	stwrq = stp->sd_struiowrq;
	if (stwrq)
		typ = stwrq->q_struiot;

	for (; (resid = uiop->uio_resid) > 0 && mp; mp = mp->b_cont) {
		dbp = mp->b_datap;
		ptr = (uchar_t *)(mp->b_rptr + dbp->db_cksumstuff);
		uiocnt = dbp->db_cksumend - dbp->db_cksumstuff;
		cnt = MIN(uiocnt, uiop->uio_resid);
		if (!(dbp->db_struioflag & STRUIO_SPEC) ||
		    (dbp->db_struioflag & STRUIO_DONE) || cnt == 0) {
			/*
			 * Either this mblk has already been processed
			 * or there is no more room in this mblk (?).
			 */
			continue;
		}
		switch (typ) {
		case STRUIOT_STANDARD:
			if (noblock) {
				if (on_trap(&otd, OT_DATA_ACCESS)) {
					no_trap();
					error = EWOULDBLOCK;
					goto out;
				}
			}
			if (error = uiomove(ptr, cnt, UIO_WRITE, uiop)) {
				if (noblock)
					no_trap();
				goto out;
			}
			if (noblock)
				no_trap();
			break;

		default:
			error = EIO;
			goto out;
		}
		dbp->db_struioflag |= STRUIO_DONE;
		dbp->db_cksumstuff += cnt;
	}
out:
	if (error == EWOULDBLOCK && (resid -= uiop->uio_resid) > 0) {
		/*
		 * A fault has occured and some bytes were moved to the
		 * current mblk, the uio_t has already been updated by
		 * the appropriate uio routine, so also update the mblk
		 * to reflect this in case this same mblk chain is used
		 * again (after the fault has been handled).
		 */
		uiocnt = dbp->db_cksumend - dbp->db_cksumstuff;
		if (uiocnt >= resid)
			dbp->db_cksumstuff += resid;
	}
	return (error);
}

/*
 * Try to enter queue synchronously. Any attempt to enter a closing queue will
 * fails. The qp->q_rwcnt keeps track of the number of successful entries so
 * that removeq() will not try to close the queue while a thread is inside the
 * queue.
 */
static boolean_t
rwnext_enter(queue_t *qp)
{
	mutex_enter(QLOCK(qp));
	if (qp->q_flag & QWCLOSE) {
		mutex_exit(QLOCK(qp));
		return (B_FALSE);
	}
	qp->q_rwcnt++;
	ASSERT(qp->q_rwcnt != 0);
	mutex_exit(QLOCK(qp));
	return (B_TRUE);
}

/*
 * Decrease the count of threads running in sync stream queue and wake up any
 * threads blocked in removeq().
 */
static void
rwnext_exit(queue_t *qp)
{
	mutex_enter(QLOCK(qp));
	qp->q_rwcnt--;
	if (qp->q_flag & QWANTRMQSYNC) {
		qp->q_flag &= ~QWANTRMQSYNC;
		cv_broadcast(&qp->q_wait);
	}
	mutex_exit(QLOCK(qp));
}

/*
 * The purpose of rwnext() is to call the rw procedure of the next
 * (downstream) modules queue.
 *
 * treated as put entrypoint for perimeter syncronization.
 *
 * There's no need to grab sq_putlocks here (which only exist for CIPUT
 * sync queues). If it is CIPUT sync queue sq_count is incremented and it does
 * not matter if any regular put entrypoints have been already entered. We
 * can't increment one of the sq_putcounts (instead of sq_count) because
 * qwait_rw won't know which counter to decrement.
 *
 * It would be reasonable to add the lockless FASTPUT logic.
 */
int
rwnext(queue_t *qp, struiod_t *dp)
{
	queue_t		*nqp;
	syncq_t		*sq;
	uint16_t	count;
	uint16_t	flags;
	struct qinit	*qi;
	int		(*proc)();
	struct stdata	*stp;
	int		isread;
	int		rval;

	stp = STREAM(qp);
	/*
	 * Prevent q_next from changing by holding sd_lock until acquiring
	 * SQLOCK. Note that a read-side rwnext from the streamhead will
	 * already have sd_lock acquired. In either case sd_lock is always
	 * released after acquiring SQLOCK.
	 *
	 * The streamhead read-side holding sd_lock when calling rwnext is
	 * required to prevent a race condition were M_DATA mblks flowing
	 * up the read-side of the stream could be bypassed by a rwnext()
	 * down-call. In this case sd_lock acts as the streamhead perimeter.
	 */
	if ((nqp = _WR(qp)) == qp) {
		isread = 0;
		mutex_enter(&stp->sd_lock);
		qp = nqp->q_next;
	} else {
		isread = 1;
		if (nqp != stp->sd_wrq)
			/* Not streamhead */
			mutex_enter(&stp->sd_lock);
		qp = _RD(nqp->q_next);
	}
	qi = qp->q_qinfo;
	if (qp->q_struiot == STRUIOT_NONE || ! (proc = qi->qi_rwp)) {
		/*
		 * Not a synchronous module or no r/w procedure for this
		 * queue, so just return EINVAL and let the caller handle it.
		 */
		mutex_exit(&stp->sd_lock);
		return (EINVAL);
	}

	if (rwnext_enter(qp) == B_FALSE) {
		mutex_exit(&stp->sd_lock);
		return (EINVAL);
	}

	sq = qp->q_syncq;
	mutex_enter(SQLOCK(sq));
	mutex_exit(&stp->sd_lock);
	count = sq->sq_count;
	flags = sq->sq_flags;
	ASSERT(sq->sq_ciputctrl == NULL || (flags & SQ_CIPUT));

	while ((flags & SQ_GOAWAY) || (!(flags & SQ_CIPUT) && count != 0)) {
		/*
		 * if this queue is being closed, return.
		 */
		if (qp->q_flag & QWCLOSE) {
			mutex_exit(SQLOCK(sq));
			rwnext_exit(qp);
			return (EINVAL);
		}

		/*
		 * Wait until we can enter the inner perimeter.
		 */
		sq->sq_flags = flags | SQ_WANTWAKEUP;
		cv_wait(&sq->sq_wait, SQLOCK(sq));
		count = sq->sq_count;
		flags = sq->sq_flags;
	}

	if (isread == 0 && stp->sd_struiowrq == NULL ||
	    isread == 1 && stp->sd_struiordq == NULL) {
		/*
		 * Stream plumbing changed while waiting for inner perimeter
		 * so just return EINVAL and let the caller handle it.
		 */
		mutex_exit(SQLOCK(sq));
		rwnext_exit(qp);
		return (EINVAL);
	}
	if (!(flags & SQ_CIPUT))
		sq->sq_flags = flags | SQ_EXCL;
	sq->sq_count = count + 1;
	ASSERT(sq->sq_count != 0);		/* Wraparound */
	/*
	 * Note: The only message ordering guarantee that rwnext() makes is
	 *	 for the write queue flow-control case. All others (r/w queue
	 *	 with q_count > 0 (or q_first != 0)) are the resposibilty of
	 *	 the queue's rw procedure. This could be genralized here buy
	 *	 running the queue's service procedure, but that wouldn't be
	 *	 the most efficent for all cases.
	 */
	mutex_exit(SQLOCK(sq));
	if (! isread && (qp->q_flag & QFULL)) {
		/*
		 * Write queue may be flow controlled. If so,
		 * mark the queue for wakeup when it's not.
		 */
		mutex_enter(QLOCK(qp));
		if (qp->q_flag & QFULL) {
			qp->q_flag |= QWANTWSYNC;
			mutex_exit(QLOCK(qp));
			rval = EWOULDBLOCK;
			goto out;
		}
		mutex_exit(QLOCK(qp));
	}

	if (! isread && dp->d_mp)
		STR_FTEVENT_MSG(dp->d_mp, nqp, FTEV_RWNEXT, dp->d_mp->b_rptr -
		    dp->d_mp->b_datap->db_base);

	rval = (*proc)(qp, dp);

	if (isread && dp->d_mp)
		STR_FTEVENT_MSG(dp->d_mp, _RD(nqp), FTEV_RWNEXT,
		    dp->d_mp->b_rptr - dp->d_mp->b_datap->db_base);
out:
	/*
	 * The queue is protected from being freed by sq_count, so it is
	 * safe to call rwnext_exit and reacquire SQLOCK(sq).
	 */
	rwnext_exit(qp);

	mutex_enter(SQLOCK(sq));
	flags = sq->sq_flags;
	ASSERT(sq->sq_count != 0);
	sq->sq_count--;
	if (flags & SQ_TAIL) {
		putnext_tail(sq, qp, flags);
		/*
		 * The only purpose of this ASSERT is to preserve calling stack
		 * in DEBUG kernel.
		 */
		ASSERT(flags & SQ_TAIL);
		return (rval);
	}
	ASSERT(flags & (SQ_EXCL|SQ_CIPUT));
	/*
	 * Safe to always drop SQ_EXCL:
	 *	Not SQ_CIPUT means we set SQ_EXCL above
	 *	For SQ_CIPUT SQ_EXCL will only be set if the put procedure
	 *	did a qwriter(INNER) in which case nobody else
	 *	is in the inner perimeter and we are exiting.
	 *
	 * I would like to make the following assertion:
	 *
	 * ASSERT((flags & (SQ_EXCL|SQ_CIPUT)) != (SQ_EXCL|SQ_CIPUT) ||
	 * 	sq->sq_count == 0);
	 *
	 * which indicates that if we are both putshared and exclusive,
	 * we became exclusive while executing the putproc, and the only
	 * claim on the syncq was the one we dropped a few lines above.
	 * But other threads that enter putnext while the syncq is exclusive
	 * need to make a claim as they may need to drop SQLOCK in the
	 * has_writers case to avoid deadlocks.  If these threads are
	 * delayed or preempted, it is possible that the writer thread can
	 * find out that there are other claims making the (sq_count == 0)
	 * test invalid.
	 */

	sq->sq_flags = flags & ~SQ_EXCL;
	if (sq->sq_flags & SQ_WANTWAKEUP) {
		sq->sq_flags &= ~SQ_WANTWAKEUP;
		cv_broadcast(&sq->sq_wait);
	}
	mutex_exit(SQLOCK(sq));
	return (rval);
}

/*
 * The purpose of infonext() is to call the info procedure of the next
 * (downstream) modules queue.
 *
 * treated as put entrypoint for perimeter syncronization.
 *
 * There's no need to grab sq_putlocks here (which only exist for CIPUT
 * sync queues). If it is CIPUT sync queue regular sq_count is incremented and
 * it does not matter if any regular put entrypoints have been already
 * entered.
 */
int
infonext(queue_t *qp, infod_t *idp)
{
	queue_t		*nqp;
	syncq_t		*sq;
	uint16_t	count;
	uint16_t 	flags;
	struct qinit	*qi;
	int		(*proc)();
	struct stdata	*stp;
	int		rval;

	stp = STREAM(qp);
	/*
	 * Prevent q_next from changing by holding sd_lock until
	 * acquiring SQLOCK.
	 */
	mutex_enter(&stp->sd_lock);
	if ((nqp = _WR(qp)) == qp) {
		qp = nqp->q_next;
	} else {
		qp = _RD(nqp->q_next);
	}
	qi = qp->q_qinfo;
	if (qp->q_struiot == STRUIOT_NONE || ! (proc = qi->qi_infop)) {
		mutex_exit(&stp->sd_lock);
		return (EINVAL);
	}
	sq = qp->q_syncq;
	mutex_enter(SQLOCK(sq));
	mutex_exit(&stp->sd_lock);
	count = sq->sq_count;
	flags = sq->sq_flags;
	ASSERT(sq->sq_ciputctrl == NULL || (flags & SQ_CIPUT));

	while ((flags & SQ_GOAWAY) || (!(flags & SQ_CIPUT) && count != 0)) {
		/*
		 * Wait until we can enter the inner perimeter.
		 */
		sq->sq_flags = flags | SQ_WANTWAKEUP;
		cv_wait(&sq->sq_wait, SQLOCK(sq));
		count = sq->sq_count;
		flags = sq->sq_flags;
	}

	if (! (flags & SQ_CIPUT))
		sq->sq_flags = flags | SQ_EXCL;
	sq->sq_count = count + 1;
	ASSERT(sq->sq_count != 0);		/* Wraparound */
	mutex_exit(SQLOCK(sq));

	rval = (*proc)(qp, idp);

	mutex_enter(SQLOCK(sq));
	flags = sq->sq_flags;
	ASSERT(sq->sq_count != 0);
	sq->sq_count--;
	if (flags & SQ_TAIL) {
		putnext_tail(sq, qp, flags);
		/*
		 * The only purpose of this ASSERT is to preserve calling stack
		 * in DEBUG kernel.
		 */
		ASSERT(flags & SQ_TAIL);
		return (rval);
	}
	ASSERT(flags & (SQ_EXCL|SQ_CIPUT));
/*
 * XXXX
 * I am not certain the next comment is correct here.  I need to consider
 * why the infonext is called, and if dropping SQ_EXCL unless non-CIPUT
 * might cause other problems.  It just might be safer to drop it if
 * !SQ_CIPUT because that is when we set it.
 */
	/*
	 * Safe to always drop SQ_EXCL:
	 *	Not SQ_CIPUT means we set SQ_EXCL above
	 *	For SQ_CIPUT SQ_EXCL will only be set if the put procedure
	 *	did a qwriter(INNER) in which case nobody else
	 *	is in the inner perimeter and we are exiting.
	 *
	 * I would like to make the following assertion:
	 *
	 * ASSERT((flags & (SQ_EXCL|SQ_CIPUT)) != (SQ_EXCL|SQ_CIPUT) ||
	 *	sq->sq_count == 0);
	 *
	 * which indicates that if we are both putshared and exclusive,
	 * we became exclusive while executing the putproc, and the only
	 * claim on the syncq was the one we dropped a few lines above.
	 * But other threads that enter putnext while the syncq is exclusive
	 * need to make a claim as they may need to drop SQLOCK in the
	 * has_writers case to avoid deadlocks.  If these threads are
	 * delayed or preempted, it is possible that the writer thread can
	 * find out that there are other claims making the (sq_count == 0)
	 * test invalid.
	 */

	sq->sq_flags = flags & ~SQ_EXCL;
	mutex_exit(SQLOCK(sq));
	return (rval);
}

/*
 * Return nonzero if the queue is responsible for struio(), else return 0.
 */
int
isuioq(queue_t *q)
{
	if (q->q_flag & QREADR)
		return (STREAM(q)->sd_struiordq == q);
	else
		return (STREAM(q)->sd_struiowrq == q);
}

#if defined(__sparc)
int disable_putlocks = 0;
#else
int disable_putlocks = 1;
#endif

/*
 * called by create_putlock.
 */
static void
create_syncq_putlocks(queue_t *q)
{
	syncq_t	*sq = q->q_syncq;
	ciputctrl_t *cip;
	int i;

	ASSERT(sq != NULL);

	ASSERT(disable_putlocks == 0);
	ASSERT(n_ciputctrl >= min_n_ciputctrl);
	ASSERT(ciputctrl_cache != NULL);

	if (!(sq->sq_type & SQ_CIPUT))
		return;

	for (i = 0; i <= 1; i++) {
		if (sq->sq_ciputctrl == NULL) {
			cip = kmem_cache_alloc(ciputctrl_cache, KM_SLEEP);
			SUMCHECK_CIPUTCTRL_COUNTS(cip, n_ciputctrl - 1, 0);
			mutex_enter(SQLOCK(sq));
			if (sq->sq_ciputctrl != NULL) {
				mutex_exit(SQLOCK(sq));
				kmem_cache_free(ciputctrl_cache, cip);
			} else {
				ASSERT(sq->sq_nciputctrl == 0);
				sq->sq_nciputctrl = n_ciputctrl - 1;
				/*
				 * putnext checks sq_ciputctrl without holding
				 * SQLOCK. if it is not NULL putnext assumes
				 * sq_nciputctrl is initialized. membar below
				 * insures that.
				 */
				membar_producer();
				sq->sq_ciputctrl = cip;
				mutex_exit(SQLOCK(sq));
			}
		}
		ASSERT(sq->sq_nciputctrl == n_ciputctrl - 1);
		if (i == 1)
			break;
		q = _OTHERQ(q);
		if (!(q->q_flag & QPERQ)) {
			ASSERT(sq == q->q_syncq);
			break;
		}
		ASSERT(q->q_syncq != NULL);
		ASSERT(sq != q->q_syncq);
		sq = q->q_syncq;
		ASSERT(sq->sq_type & SQ_CIPUT);
	}
}

/*
 * If stream argument is 0 only create per cpu sq_putlocks/sq_putcounts for
 * syncq of q. If stream argument is not 0 create per cpu stream_putlocks for
 * the stream of q and per cpu sq_putlocks/sq_putcounts for all syncq's
 * starting from q and down to the driver.
 *
 * This should be called after the affected queues are part of stream
 * geometry. It should be called from driver/module open routine after
 * qprocson() call. It is also called from nfs syscall where it is known that
 * stream is configured and won't change its geometry during create_putlock
 * call.
 *
 * caller normally uses 0 value for the stream argument to speed up MT putnext
 * into the perimeter of q for example because its perimeter is per module
 * (e.g. IP).
 *
 * caller normally uses non 0 value for the stream argument to hint the system
 * that the stream of q is a very contended global system stream
 * (e.g. NFS/UDP) and the part of the stream from q to the driver is
 * particularly MT hot.
 *
 * Caller insures stream plumbing won't happen while we are here and therefore
 * q_next can be safely used.
 */

void
create_putlocks(queue_t *q, int stream)
{
	ciputctrl_t	*cip;
	struct stdata	*stp = STREAM(q);

	q = _WR(q);
	ASSERT(stp != NULL);

	if (disable_putlocks != 0)
		return;

	if (n_ciputctrl < min_n_ciputctrl)
		return;

	ASSERT(ciputctrl_cache != NULL);

	if (stream != 0 && stp->sd_ciputctrl == NULL) {
		cip = kmem_cache_alloc(ciputctrl_cache, KM_SLEEP);
		SUMCHECK_CIPUTCTRL_COUNTS(cip, n_ciputctrl - 1, 0);
		mutex_enter(&stp->sd_lock);
		if (stp->sd_ciputctrl != NULL) {
			mutex_exit(&stp->sd_lock);
			kmem_cache_free(ciputctrl_cache, cip);
		} else {
			ASSERT(stp->sd_nciputctrl == 0);
			stp->sd_nciputctrl = n_ciputctrl - 1;
			/*
			 * putnext checks sd_ciputctrl without holding
			 * sd_lock. if it is not NULL putnext assumes
			 * sd_nciputctrl is initialized. membar below
			 * insures that.
			 */
			membar_producer();
			stp->sd_ciputctrl = cip;
			mutex_exit(&stp->sd_lock);
		}
	}

	ASSERT(stream == 0 || stp->sd_nciputctrl == n_ciputctrl - 1);

	while (_SAMESTR(q)) {
		create_syncq_putlocks(q);
		if (stream == 0)
			return;
		q = q->q_next;
	}
	ASSERT(q != NULL);
	create_syncq_putlocks(q);
}

/*
 * STREAMS Flow Trace - record STREAMS Flow Trace events as an mblk flows
 * through a stream.
 *
 * Data currently record per-event is a timestamp, module/driver name,
 * downstream module/driver name, optional callstack, event type and a per
 * type datum.  Much of the STREAMS framework is instrumented for automatic
 * flow tracing (when enabled).  Events can be defined and used by STREAMS
 * modules and drivers.
 *
 * Global objects:
 *
 *	str_ftevent() - Add a flow-trace event to a dblk.
 *	str_ftfree() - Free flow-trace data
 *
 * Local objects:
 *
 *	fthdr_cache - pointer to the kmem cache for trace header.
 *	ftblk_cache - pointer to the kmem cache for trace data blocks.
 */

int str_ftnever = 1;	/* Don't do STREAMS flow tracing */
int str_ftstack = 0;	/* Don't record event call stacks */

void
str_ftevent(fthdr_t *hp, void *p, ushort_t evnt, ushort_t data)
{
	ftblk_t *bp = hp->tail;
	ftblk_t *nbp;
	ftevnt_t *ep;
	int ix, nix;

	ASSERT(hp != NULL);

	for (;;) {
		if ((ix = bp->ix) == FTBLK_EVNTS) {
			/*
			 * Tail doesn't have room, so need a new tail.
			 *
			 * To make this MT safe, first, allocate a new
			 * ftblk, and initialize it.  To make life a
			 * little easier, reserve the first slot (mostly
			 * by making ix = 1).  When we are finished with
			 * the initialization, CAS this pointer to the
			 * tail.  If this succeeds, this is the new
			 * "next" block.  Otherwise, another thread
			 * got here first, so free the block and start
			 * again.
			 */
			nbp = kmem_cache_alloc(ftblk_cache, KM_NOSLEEP);
			if (nbp == NULL) {
				/* no mem, so punt */
				str_ftnever++;
				/* free up all flow data? */
				return;
			}
			nbp->nxt = NULL;
			nbp->ix = 1;
			/*
			 * Just in case there is another thread about
			 * to get the next index, we need to make sure
			 * the value is there for it.
			 */
			membar_producer();
			if (atomic_cas_ptr(&hp->tail, bp, nbp) == bp) {
				/* CAS was successful */
				bp->nxt = nbp;
				membar_producer();
				bp = nbp;
				ix = 0;
				goto cas_good;
			} else {
				kmem_cache_free(ftblk_cache, nbp);
				bp = hp->tail;
				continue;
			}
		}
		nix = ix + 1;
		if (atomic_cas_32((uint32_t *)&bp->ix, ix, nix) == ix) {
		cas_good:
			if (curthread != hp->thread) {
				hp->thread = curthread;
				evnt |= FTEV_CS;
			}
			if (CPU->cpu_seqid != hp->cpu_seqid) {
				hp->cpu_seqid = CPU->cpu_seqid;
				evnt |= FTEV_PS;
			}
			ep = &bp->ev[ix];
			break;
		}
	}

	if (evnt & FTEV_QMASK) {
		queue_t *qp = p;

		if (!(qp->q_flag & QREADR))
			evnt |= FTEV_ISWR;

		ep->mid = Q2NAME(qp);

		/*
		 * We only record the next queue name for FTEV_PUTNEXT since
		 * that's the only time we *really* need it, and the putnext()
		 * code ensures that qp->q_next won't vanish.  (We could use
		 * claimstr()/releasestr() but at a performance cost.)
		 */
		if ((evnt & FTEV_MASK) == FTEV_PUTNEXT && qp->q_next != NULL)
			ep->midnext = Q2NAME(qp->q_next);
		else
			ep->midnext = NULL;
	} else {
		ep->mid = p;
		ep->midnext = NULL;
	}

	if (ep->stk != NULL)
		ep->stk->fs_depth = getpcstack(ep->stk->fs_stk, FTSTK_DEPTH);

	ep->ts = gethrtime();
	ep->evnt = evnt;
	ep->data = data;
	hp->hash = (hp->hash << 9) + hp->hash;
	hp->hash += (evnt << 16) | data;
	hp->hash += (uintptr_t)ep->mid;
}

/*
 * Free flow-trace data.
 */
void
str_ftfree(dblk_t *dbp)
{
	fthdr_t *hp = dbp->db_fthdr;
	ftblk_t *bp = &hp->first;
	ftblk_t *nbp;

	if (bp != hp->tail || bp->ix != 0) {
		/*
		 * Clear out the hash, have the tail point to itself, and free
		 * any continuation blocks.
		 */
		bp = hp->first.nxt;
		hp->tail = &hp->first;
		hp->hash = 0;
		hp->first.nxt = NULL;
		hp->first.ix = 0;
		while (bp != NULL) {
			nbp = bp->nxt;
			kmem_cache_free(ftblk_cache, bp);
			bp = nbp;
		}
	}
	kmem_cache_free(fthdr_cache, hp);
	dbp->db_fthdr = NULL;
}
