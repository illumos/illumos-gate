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
/*	  All Rights Reserved	*/

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
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
#include <sys/sdt.h>
#include <sys/strft.h>

/*
 * This file contains selected functions from io/stream.c
 * needed by this library, mostly unmodified.
 */

/*
 * STREAMS message allocator: principles of operation
 * (See usr/src/uts/common/io/stream.c)
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

static void dblk_lastfree(mblk_t *mp, dblk_t *dbp);
static mblk_t *allocb_oversize(size_t size, int flags);
static int allocb_tryhard_fails;
static void frnop_func(void *arg);
frtn_t frnop = { frnop_func };
static void bcache_dblk_lastfree(mblk_t *mp, dblk_t *dbp);

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

/* Needed in the ASSERT below */
#ifdef	DEBUG
#ifdef	_KERNEL
#define	KMEM_SLAB_T_SZ	sizeof (kmem_slab_t)
#else	/* _KERNEL */
#define	KMEM_SLAB_T_SZ	64	/* fakekernel */
#endif	/* _KERNEL */
#endif	/* DEBUG */

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
			ASSERT((offset + sizeof (dblk_t) + KMEM_SLAB_T_SZ)
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

		(void) sprintf(name, "streams_dblk_%ld", (long)size);
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

	/* fthdr_cache, ftblk_cache, mmd_init... */
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

	while (mp != NULL) {
		dblk_t *dbp = mp->b_datap;

		cr = dbp->db_credp;
		if (cr == NULL) {
			mp = mp->b_cont;
			continue;
		}
		if (cpidp != NULL)
			*cpidp = dbp->db_cpid;

		/* DEBUG check for only one db_credp */
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

		/* DEBUG check for only one db_credp */
		return (cr);
	}
	return (NULL);
}

/* _KERNEL msg_getlabel() */

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

/*ARGSUSED*/
static void
frnop_func(void *arg)
{
}

/*
 * Generic esballoc used to implement the four flavors: [d]esballoc[a].
 * and allocb_oversize
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

/* _KERNEL: bufcall, unbufcall */

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
		/* _KERNEL mmd_copy stuff */
		return (NULL);
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

/* getq() etc to EOF removed */
