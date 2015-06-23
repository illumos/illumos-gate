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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Multidata, as described in the following papers:
 *
 * Adi Masputra,
 * Multidata V.2: VA-Disjoint Packet Extents Framework Interface
 * Design Specification.  August 2004.
 * Available as http://sac.sfbay/PSARC/2004/594/materials/mmd2.pdf.
 *
 * Adi Masputra,
 * Multidata Interface Design Specification.  Sep 2002.
 * Available as http://sac.sfbay/PSARC/2002/276/materials/mmd.pdf.
 *
 * Adi Masputra, Frank DiMambro, Kacheong Poon,
 * An Efficient Networking Transmit Mechanism for Solaris:
 * Multidata Transmit (MDT).  May 2002.
 * Available as http://sac.sfbay/PSARC/2002/276/materials/mdt.pdf.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/strlog.h>
#include <sys/strsubr.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/atomic.h>

#include <sys/multidata.h>
#include <sys/multidata_impl.h>

static int mmd_constructor(void *, void *, int);
static void mmd_destructor(void *, void *);
static int pdslab_constructor(void *, void *, int);
static void pdslab_destructor(void *, void *);
static int pattbl_constructor(void *, void *, int);
static void pattbl_destructor(void *, void *);
static void mmd_esballoc_free(caddr_t);
static int mmd_copy_pattbl(patbkt_t *, multidata_t *, pdesc_t *, int);

static boolean_t pbuf_ref_valid(multidata_t *, pdescinfo_t *);
#pragma inline(pbuf_ref_valid)

static boolean_t pdi_in_range(pdescinfo_t *, pdescinfo_t *);
#pragma inline(pdi_in_range)

static pdesc_t *mmd_addpdesc_int(multidata_t *, pdescinfo_t *, int *, int);
#pragma inline(mmd_addpdesc_int)

static void mmd_destroy_pattbl(patbkt_t **);
#pragma inline(mmd_destroy_pattbl)

static pattr_t *mmd_find_pattr(patbkt_t *, uint_t);
#pragma inline(mmd_find_pattr)

static pdesc_t *mmd_destroy_pdesc(multidata_t *, pdesc_t *);
#pragma inline(mmd_destroy_pdesc)

static pdesc_t *mmd_getpdesc(multidata_t *, pdesc_t *, pdescinfo_t *, uint_t,
    boolean_t);
#pragma inline(mmd_getpdesc)

static struct kmem_cache *mmd_cache;
static struct kmem_cache *pd_slab_cache;
static struct kmem_cache *pattbl_cache;

int mmd_debug = 1;
#define	MMD_DEBUG(s)	if (mmd_debug > 0) cmn_err s

/*
 * Set to this to true to bypass pdesc bounds checking.
 */
boolean_t mmd_speed_over_safety = B_FALSE;

/*
 * Patchable kmem_cache flags.
 */
int mmd_kmem_flags = 0;
int pdslab_kmem_flags = 0;
int pattbl_kmem_flags = 0;

/*
 * Alignment (in bytes) of our kmem caches.
 */
#define	MULTIDATA_CACHE_ALIGN	64

/*
 * Default number of packet descriptors per descriptor slab.  Making
 * this too small will trigger more descriptor slab allocation; making
 * it too large will create too many unclaimed descriptors.
 */
#define	PDSLAB_SZ	15
uint_t pdslab_sz = PDSLAB_SZ;

/*
 * Default attribute hash table size.  It's okay to set this to a small
 * value (even to 1) because there aren't that many attributes currently
 * defined, and because we assume there won't be many attributes associated
 * with a Multidata at a given time.  Increasing the size will reduce
 * attribute search time (given a large number of attributes in a Multidata),
 * and decreasing it will reduce the memory footprints and the overhead
 * associated with managing the table.
 */
#define	PATTBL_SZ	1
uint_t pattbl_sz = PATTBL_SZ;

/*
 * Attribute hash key.
 */
#define	PATTBL_HASH(x, sz)	((x) % (sz))

/*
 * Structure that precedes each Multidata metadata.
 */
struct mmd_buf_info {
	frtn_t	frp;		/* free routine */
	uint_t	buf_len;	/* length of kmem buffer */
};

/*
 * The size of each metadata buffer.
 */
#define	MMD_CACHE_SIZE	\
	(sizeof (struct mmd_buf_info) + sizeof (multidata_t))

/*
 * Called during startup in order to create the Multidata kmem caches.
 */
void
mmd_init(void)
{
	pdslab_sz = MAX(1, pdslab_sz);	/* at least 1 descriptor */
	pattbl_sz = MAX(1, pattbl_sz);	/* at least 1 bucket */

	mmd_cache = kmem_cache_create("multidata", MMD_CACHE_SIZE,
	    MULTIDATA_CACHE_ALIGN, mmd_constructor, mmd_destructor,
	    NULL, NULL, NULL, mmd_kmem_flags);

	pd_slab_cache = kmem_cache_create("multidata_pdslab",
	    PDESC_SLAB_SIZE(pdslab_sz), MULTIDATA_CACHE_ALIGN,
	    pdslab_constructor, pdslab_destructor, NULL,
	    (void *)(uintptr_t)pdslab_sz, NULL, pdslab_kmem_flags);

	pattbl_cache = kmem_cache_create("multidata_pattbl",
	    sizeof (patbkt_t) * pattbl_sz, MULTIDATA_CACHE_ALIGN,
	    pattbl_constructor, pattbl_destructor, NULL,
	    (void *)(uintptr_t)pattbl_sz, NULL, pattbl_kmem_flags);
}

/*
 * Create a Multidata message block.
 */
multidata_t *
mmd_alloc(mblk_t *hdr_mp, mblk_t **mmd_mp, int kmflags)
{
	uchar_t *buf;
	multidata_t *mmd;
	uint_t mmd_mplen;
	struct mmd_buf_info *buf_info;

	ASSERT(hdr_mp != NULL);
	ASSERT(mmd_mp != NULL);

	/*
	 * Caller should never pass in a chain of mblks since we
	 * only care about the first one, hence the assertions.
	 */
	ASSERT(hdr_mp->b_cont == NULL);

	if ((buf = kmem_cache_alloc(mmd_cache, kmflags)) == NULL)
		return (NULL);

	buf_info = (struct mmd_buf_info *)buf;
	buf_info->frp.free_arg = (caddr_t)buf;

	mmd = (multidata_t *)(buf_info + 1);
	mmd_mplen = sizeof (*mmd);

	if ((*mmd_mp = desballoc((uchar_t *)mmd, mmd_mplen, BPRI_HI,
	    &(buf_info->frp))) == NULL) {
		kmem_cache_free(mmd_cache, buf);
		return (NULL);
	}

	DB_TYPE(*mmd_mp) = M_MULTIDATA;
	(*mmd_mp)->b_wptr += mmd_mplen;
	mmd->mmd_dp = (*mmd_mp)->b_datap;
	mmd->mmd_hbuf = hdr_mp;

	return (mmd);
}

/*
 * Associate additional payload buffer to the Multidata.
 */
int
mmd_addpldbuf(multidata_t *mmd, mblk_t *pld_mp)
{
	int i;

	ASSERT(mmd != NULL);
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);
	ASSERT(pld_mp != NULL);

	mutex_enter(&mmd->mmd_pd_slab_lock);
	for (i = 0; i < MULTIDATA_MAX_PBUFS &&
	    mmd->mmd_pbuf_cnt < MULTIDATA_MAX_PBUFS; i++) {
		if (mmd->mmd_pbuf[i] == pld_mp) {
			/* duplicate entry */
			MMD_DEBUG((CE_WARN, "mmd_addpldbuf: error adding "
			    "pld 0x%p to mmd 0x%p since it has been "
			    "previously added into slot %d (total %d)\n",
			    (void *)pld_mp, (void *)mmd, i, mmd->mmd_pbuf_cnt));
			mutex_exit(&mmd->mmd_pd_slab_lock);
			return (-1);
		} else if (mmd->mmd_pbuf[i] == NULL) {
			mmd->mmd_pbuf[i] = pld_mp;
			mmd->mmd_pbuf_cnt++;
			mutex_exit(&mmd->mmd_pd_slab_lock);
			return (i);
		}
	}

	/* all slots are taken */
	MMD_DEBUG((CE_WARN, "mmd_addpldbuf: error adding pld 0x%p to mmd 0x%p "
	    "since no slot space is left (total %d max %d)\n", (void *)pld_mp,
	    (void *)mmd, mmd->mmd_pbuf_cnt, MULTIDATA_MAX_PBUFS));
	mutex_exit(&mmd->mmd_pd_slab_lock);

	return (-1);
}

/*
 * Multidata metadata kmem cache constructor routine.
 */
/* ARGSUSED */
static int
mmd_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct mmd_buf_info *buf_info;
	multidata_t *mmd;

	bzero((void *)buf, MMD_CACHE_SIZE);

	buf_info = (struct mmd_buf_info *)buf;
	buf_info->frp.free_func = mmd_esballoc_free;
	buf_info->buf_len = MMD_CACHE_SIZE;

	mmd = (multidata_t *)(buf_info + 1);
	mmd->mmd_magic = MULTIDATA_MAGIC;

	mutex_init(&(mmd->mmd_pd_slab_lock), NULL, MUTEX_DRIVER, NULL);
	QL_INIT(&(mmd->mmd_pd_slab_q));
	QL_INIT(&(mmd->mmd_pd_q));

	return (0);
}

/*
 * Multidata metadata kmem cache destructor routine.
 */
/* ARGSUSED */
static void
mmd_destructor(void *buf, void *cdrarg)
{
	multidata_t *mmd;
#ifdef DEBUG
	int i;
#endif

	mmd = (multidata_t *)((uchar_t *)buf + sizeof (struct mmd_buf_info));

	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);
	ASSERT(mmd->mmd_dp == NULL);
	ASSERT(mmd->mmd_hbuf == NULL);
	ASSERT(mmd->mmd_pbuf_cnt == 0);
#ifdef DEBUG
	for (i = 0; i < MULTIDATA_MAX_PBUFS; i++)
		ASSERT(mmd->mmd_pbuf[i] == NULL);
#endif
	ASSERT(mmd->mmd_pattbl == NULL);

	mutex_destroy(&(mmd->mmd_pd_slab_lock));
	ASSERT(mmd->mmd_pd_slab_q.ql_next == &(mmd->mmd_pd_slab_q));
	ASSERT(mmd->mmd_slab_cnt == 0);
	ASSERT(mmd->mmd_pd_q.ql_next == &(mmd->mmd_pd_q));
	ASSERT(mmd->mmd_pd_cnt == 0);
	ASSERT(mmd->mmd_hbuf_ref == 0);
	ASSERT(mmd->mmd_pbuf_ref == 0);
}

/*
 * Multidata message block free callback routine.
 */
static void
mmd_esballoc_free(caddr_t buf)
{
	multidata_t *mmd;
	pdesc_t *pd;
	pdesc_slab_t *slab;
	int i;

	ASSERT(buf != NULL);
	ASSERT(((struct mmd_buf_info *)buf)->buf_len == MMD_CACHE_SIZE);

	mmd = (multidata_t *)(buf + sizeof (struct mmd_buf_info));
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);

	ASSERT(mmd->mmd_dp != NULL);
	ASSERT(mmd->mmd_dp->db_ref == 1);

	/* remove all packet descriptors and private attributes */
	pd = Q2PD(mmd->mmd_pd_q.ql_next);
	while (pd != Q2PD(&(mmd->mmd_pd_q)))
		pd = mmd_destroy_pdesc(mmd, pd);

	ASSERT(mmd->mmd_pd_q.ql_next == &(mmd->mmd_pd_q));
	ASSERT(mmd->mmd_pd_cnt == 0);
	ASSERT(mmd->mmd_hbuf_ref == 0);
	ASSERT(mmd->mmd_pbuf_ref == 0);

	/* remove all global attributes */
	if (mmd->mmd_pattbl != NULL)
		mmd_destroy_pattbl(&(mmd->mmd_pattbl));

	/* remove all descriptor slabs */
	slab = Q2PDSLAB(mmd->mmd_pd_slab_q.ql_next);
	while (slab != Q2PDSLAB(&(mmd->mmd_pd_slab_q))) {
		pdesc_slab_t *slab_next = Q2PDSLAB(slab->pds_next);

		remque(&(slab->pds_next));
		slab->pds_next = NULL;
		slab->pds_prev = NULL;
		slab->pds_mmd = NULL;
		slab->pds_used = 0;
		kmem_cache_free(pd_slab_cache, slab);

		ASSERT(mmd->mmd_slab_cnt > 0);
		mmd->mmd_slab_cnt--;
		slab = slab_next;
	}
	ASSERT(mmd->mmd_pd_slab_q.ql_next == &(mmd->mmd_pd_slab_q));
	ASSERT(mmd->mmd_slab_cnt == 0);

	mmd->mmd_dp = NULL;

	/* finally, free all associated message blocks */
	if (mmd->mmd_hbuf != NULL) {
		freeb(mmd->mmd_hbuf);
		mmd->mmd_hbuf = NULL;
	}

	for (i = 0; i < MULTIDATA_MAX_PBUFS; i++) {
		if (mmd->mmd_pbuf[i] != NULL) {
			freeb(mmd->mmd_pbuf[i]);
			mmd->mmd_pbuf[i] = NULL;
			ASSERT(mmd->mmd_pbuf_cnt > 0);
			mmd->mmd_pbuf_cnt--;
		}
	}

	ASSERT(mmd->mmd_pbuf_cnt == 0);
	ASSERT(MUTEX_NOT_HELD(&(mmd->mmd_pd_slab_lock)));
	kmem_cache_free(mmd_cache, buf);
}

/*
 * Multidata message block copy routine, called by copyb() when it
 * encounters a M_MULTIDATA data block type.  This routine should
 * not be called by anyone other than copyb(), since it may go away
 * (read: become static to this module) once some sort of copy callback
 * routine is made available.
 */
mblk_t *
mmd_copy(mblk_t *bp, int kmflags)
{
	multidata_t *mmd, *n_mmd;
	mblk_t *n_hbuf = NULL, *n_pbuf[MULTIDATA_MAX_PBUFS];
	mblk_t **pmp_last = &n_pbuf[MULTIDATA_MAX_PBUFS - 1];
	mblk_t **pmp;
	mblk_t *n_bp = NULL;
	pdesc_t *pd;
	uint_t n_pbuf_cnt = 0;
	int idx, i;

#define	FREE_PBUFS() {					\
	for (pmp = &n_pbuf[0]; pmp <= pmp_last; pmp++)	\
		if (*pmp != NULL) freeb(*pmp);		\
}

#define	REL_OFF(p, base, n_base)			\
	((uchar_t *)(n_base) + ((uchar_t *)(p) - (uchar_t *)base))

	ASSERT(bp != NULL && DB_TYPE(bp) == M_MULTIDATA);
	mmd = mmd_getmultidata(bp);

	/* copy the header buffer */
	if (mmd->mmd_hbuf != NULL && (n_hbuf = copyb(mmd->mmd_hbuf)) == NULL)
		return (NULL);

	/* copy the payload buffer(s) */
	mutex_enter(&mmd->mmd_pd_slab_lock);
	bzero((void *)&n_pbuf[0], sizeof (mblk_t *) * MULTIDATA_MAX_PBUFS);
	n_pbuf_cnt = mmd->mmd_pbuf_cnt;
	for (i = 0; i < n_pbuf_cnt; i++) {
		ASSERT(mmd->mmd_pbuf[i] != NULL);
		n_pbuf[i] = copyb(mmd->mmd_pbuf[i]);
		if (n_pbuf[i] == NULL) {
			FREE_PBUFS();
			mutex_exit(&mmd->mmd_pd_slab_lock);
			return (NULL);
		}
	}

	/* allocate new Multidata */
	n_mmd = mmd_alloc(n_hbuf, &n_bp, kmflags);
	if (n_mmd == NULL) {
		if (n_hbuf != NULL)
			freeb(n_hbuf);
		if (n_pbuf_cnt != 0)
			FREE_PBUFS();
		mutex_exit(&mmd->mmd_pd_slab_lock);
		return (NULL);
	}

	/*
	 * Add payload buffer(s); upon success, leave n_pbuf array
	 * alone, as the newly-created Multidata had already contained
	 * the mblk pointers stored in the array.  These will be freed
	 * along with the Multidata itself.
	 */
	for (i = 0, pmp = &n_pbuf[0]; i < n_pbuf_cnt; i++, pmp++) {
		idx = mmd_addpldbuf(n_mmd, *pmp);
		if (idx < 0) {
			FREE_PBUFS();
			freeb(n_bp);
			mutex_exit(&mmd->mmd_pd_slab_lock);
			return (NULL);
		}
	}

	/* copy over global attributes */
	if (mmd->mmd_pattbl != NULL &&
	    mmd_copy_pattbl(mmd->mmd_pattbl, n_mmd, NULL, kmflags) < 0) {
		freeb(n_bp);
		mutex_exit(&mmd->mmd_pd_slab_lock);
		return (NULL);
	}

	/* copy over packet descriptors and their atttributes */
	pd = mmd_getpdesc(mmd, NULL, NULL, 1, B_TRUE);	/* first pdesc */
	while (pd != NULL) {
		pdesc_t *n_pd;
		pdescinfo_t *pdi, n_pdi;
		uchar_t *n_base, *base;
		pdesc_t *pd_next;

		/* next pdesc */
		pd_next = mmd_getpdesc(pd->pd_slab->pds_mmd, pd, NULL,
		    1, B_TRUE);

		/* skip if already removed */
		if (pd->pd_flags & PDESC_REM_DEFER) {
			pd = pd_next;
			continue;
		}

		pdi = &(pd->pd_pdi);
		bzero(&n_pdi, sizeof (n_pdi));

		/*
		 * Calculate new descriptor values based on the offset of
		 * each pointer relative to the associated buffer(s).
		 */
		ASSERT(pdi->flags & PDESC_HAS_REF);
		if (pdi->flags & PDESC_HBUF_REF) {
			n_base = n_mmd->mmd_hbuf->b_rptr;
			base = mmd->mmd_hbuf->b_rptr;

			n_pdi.flags |= PDESC_HBUF_REF;
			n_pdi.hdr_base = REL_OFF(pdi->hdr_base, base, n_base);
			n_pdi.hdr_rptr = REL_OFF(pdi->hdr_rptr, base, n_base);
			n_pdi.hdr_wptr = REL_OFF(pdi->hdr_wptr, base, n_base);
			n_pdi.hdr_lim = REL_OFF(pdi->hdr_lim, base, n_base);
		}

		if (pdi->flags & PDESC_PBUF_REF) {
			n_pdi.flags |= PDESC_PBUF_REF;
			n_pdi.pld_cnt = pdi->pld_cnt;

			for (i = 0; i < pdi->pld_cnt; i++) {
				idx = pdi->pld_ary[i].pld_pbuf_idx;
				ASSERT(idx < MULTIDATA_MAX_PBUFS);
				ASSERT(n_mmd->mmd_pbuf[idx] != NULL);
				ASSERT(mmd->mmd_pbuf[idx] != NULL);

				n_base = n_mmd->mmd_pbuf[idx]->b_rptr;
				base = mmd->mmd_pbuf[idx]->b_rptr;

				n_pdi.pld_ary[i].pld_pbuf_idx = idx;

				/*
				 * We can't copy the pointers just like that,
				 * so calculate the relative offset.
				 */
				n_pdi.pld_ary[i].pld_rptr =
				    REL_OFF(pdi->pld_ary[i].pld_rptr,
					base, n_base);
				n_pdi.pld_ary[i].pld_wptr =
				    REL_OFF(pdi->pld_ary[i].pld_wptr,
					base, n_base);
			}
		}

		/* add the new descriptor to the new Multidata */
		n_pd = mmd_addpdesc_int(n_mmd, &n_pdi, NULL, kmflags);

		if (n_pd == NULL || (pd->pd_pattbl != NULL &&
		    mmd_copy_pattbl(pd->pd_pattbl, n_mmd, n_pd, kmflags) < 0)) {
			freeb(n_bp);
			mutex_exit(&mmd->mmd_pd_slab_lock);
			return (NULL);
		}

		pd = pd_next;
	}
#undef REL_OFF
#undef FREE_PBUFS

	mutex_exit(&mmd->mmd_pd_slab_lock);
	return (n_bp);
}

/*
 * Given a Multidata message block, return the Multidata metadata handle.
 */
multidata_t *
mmd_getmultidata(mblk_t *mp)
{
	multidata_t *mmd;

	ASSERT(mp != NULL);

	if (DB_TYPE(mp) != M_MULTIDATA)
		return (NULL);

	mmd = (multidata_t *)mp->b_rptr;
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);

	return (mmd);
}

/*
 * Return the start and end addresses of the associated buffer(s).
 */
void
mmd_getregions(multidata_t *mmd, mbufinfo_t *mbi)
{
	int i;

	ASSERT(mmd != NULL);
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);
	ASSERT(mbi != NULL);

	bzero((void *)mbi, sizeof (mbufinfo_t));

	if (mmd->mmd_hbuf != NULL) {
		mbi->hbuf_rptr = mmd->mmd_hbuf->b_rptr;
		mbi->hbuf_wptr = mmd->mmd_hbuf->b_wptr;
	}

	mutex_enter(&mmd->mmd_pd_slab_lock);
	for (i = 0; i < mmd->mmd_pbuf_cnt; i++) {
		ASSERT(mmd->mmd_pbuf[i] != NULL);
		mbi->pbuf_ary[i].pbuf_rptr = mmd->mmd_pbuf[i]->b_rptr;
		mbi->pbuf_ary[i].pbuf_wptr = mmd->mmd_pbuf[i]->b_wptr;

	}
	mbi->pbuf_cnt = mmd->mmd_pbuf_cnt;
	mutex_exit(&mmd->mmd_pd_slab_lock);
}

/*
 * Return the Multidata statistics.
 */
uint_t
mmd_getcnt(multidata_t *mmd, uint_t *hbuf_ref, uint_t *pbuf_ref)
{
	uint_t pd_cnt;

	ASSERT(mmd != NULL);
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);

	mutex_enter(&(mmd->mmd_pd_slab_lock));
	if (hbuf_ref != NULL)
		*hbuf_ref = mmd->mmd_hbuf_ref;
	if (pbuf_ref != NULL)
		*pbuf_ref = mmd->mmd_pbuf_ref;
	pd_cnt = mmd->mmd_pd_cnt;
	mutex_exit(&(mmd->mmd_pd_slab_lock));

	return (pd_cnt);
}

#define	HBUF_REF_VALID(mmd, pdi)					\
	((mmd)->mmd_hbuf != NULL && (pdi)->hdr_rptr != NULL &&		\
	(pdi)->hdr_wptr != NULL && (pdi)->hdr_base != NULL &&		\
	(pdi)->hdr_lim != NULL && (pdi)->hdr_lim >= (pdi)->hdr_base &&	\
	(pdi)->hdr_wptr >= (pdi)->hdr_rptr &&				\
	(pdi)->hdr_base <= (pdi)->hdr_rptr &&				\
	(pdi)->hdr_lim >= (pdi)->hdr_wptr &&				\
	(pdi)->hdr_base >= (mmd)->mmd_hbuf->b_rptr &&			\
	MBLKIN((mmd)->mmd_hbuf,						\
	(pdi->hdr_base - (mmd)->mmd_hbuf->b_rptr),			\
	PDESC_HDRSIZE(pdi)))

/*
 * Bounds check payload area(s).
 */
static boolean_t
pbuf_ref_valid(multidata_t *mmd, pdescinfo_t *pdi)
{
	int i = 0, idx;
	boolean_t valid = B_TRUE;
	struct pld_ary_s *pa;

	mutex_enter(&mmd->mmd_pd_slab_lock);
	if (pdi->pld_cnt == 0 || pdi->pld_cnt > mmd->mmd_pbuf_cnt) {
		mutex_exit(&mmd->mmd_pd_slab_lock);
		return (B_FALSE);
	}

	pa = &pdi->pld_ary[0];
	while (valid && i < pdi->pld_cnt) {
		valid = (((idx = pa->pld_pbuf_idx) < mmd->mmd_pbuf_cnt) &&
		    pa->pld_rptr != NULL && pa->pld_wptr != NULL &&
		    pa->pld_wptr >= pa->pld_rptr &&
		    pa->pld_rptr >= mmd->mmd_pbuf[idx]->b_rptr &&
		    MBLKIN(mmd->mmd_pbuf[idx], (pa->pld_rptr -
			mmd->mmd_pbuf[idx]->b_rptr),
			PDESC_PLD_SPAN_SIZE(pdi, i)));

		if (!valid) {
			MMD_DEBUG((CE_WARN,
			    "pbuf_ref_valid: pdi 0x%p pld out of bound; "
			    "index %d has pld_cnt %d pbuf_idx %d "
			    "(mmd_pbuf_cnt %d), "
			    "pld_rptr 0x%p pld_wptr 0x%p len %d "
			    "(valid 0x%p-0x%p len %d)\n", (void *)pdi,
			    i, pdi->pld_cnt, idx, mmd->mmd_pbuf_cnt,
			    (void *)pa->pld_rptr,
			    (void *)pa->pld_wptr,
			    (int)PDESC_PLD_SPAN_SIZE(pdi, i),
			    (void *)mmd->mmd_pbuf[idx]->b_rptr,
			    (void *)mmd->mmd_pbuf[idx]->b_wptr,
			    (int)MBLKL(mmd->mmd_pbuf[idx])));
		}

		/* advance to next entry */
		i++;
		pa++;
	}

	mutex_exit(&mmd->mmd_pd_slab_lock);
	return (valid);
}

/*
 * Add a packet descriptor to the Multidata.
 */
pdesc_t *
mmd_addpdesc(multidata_t *mmd, pdescinfo_t *pdi, int *err, int kmflags)
{
	ASSERT(mmd != NULL);
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);
	ASSERT(pdi != NULL);
	ASSERT(pdi->flags & PDESC_HAS_REF);

	/* do the references refer to invalid memory regions? */
	if (!mmd_speed_over_safety &&
	    (((pdi->flags & PDESC_HBUF_REF) && !HBUF_REF_VALID(mmd, pdi)) ||
	    ((pdi->flags & PDESC_PBUF_REF) && !pbuf_ref_valid(mmd, pdi)))) {
		if (err != NULL)
			*err = EINVAL;
		return (NULL);
	}

	return (mmd_addpdesc_int(mmd, pdi, err, kmflags));
}

/*
 * Internal routine to add a packet descriptor, called when mmd_addpdesc
 * or mmd_copy tries to allocate and add a descriptor to a Multidata.
 */
static pdesc_t *
mmd_addpdesc_int(multidata_t *mmd, pdescinfo_t *pdi, int *err, int kmflags)
{
	pdesc_slab_t *slab, *slab_last;
	pdesc_t *pd;

	ASSERT(pdi->flags & PDESC_HAS_REF);
	ASSERT(!(pdi->flags & PDESC_HBUF_REF) || HBUF_REF_VALID(mmd, pdi));
	ASSERT(!(pdi->flags & PDESC_PBUF_REF) || pbuf_ref_valid(mmd, pdi));

	if (err != NULL)
		*err = 0;

	mutex_enter(&(mmd->mmd_pd_slab_lock));
	/*
	 * Is slab list empty or the last-added slab is full?  If so,
	 * allocate new slab for the descriptor; otherwise, use the
	 * last-added slab instead.
	 */
	slab_last = Q2PDSLAB(mmd->mmd_pd_slab_q.ql_prev);
	if (mmd->mmd_pd_slab_q.ql_next == &(mmd->mmd_pd_slab_q) ||
	    slab_last->pds_used == slab_last->pds_sz) {
		slab = kmem_cache_alloc(pd_slab_cache, kmflags);
		if (slab == NULL) {
			if (err != NULL)
				*err = ENOMEM;
			mutex_exit(&(mmd->mmd_pd_slab_lock));
			return (NULL);
		}
		slab->pds_mmd = mmd;

		ASSERT(slab->pds_used == 0);
		ASSERT(slab->pds_next == NULL && slab->pds_prev == NULL);

		/* insert slab at end of list */
		insque(&(slab->pds_next), mmd->mmd_pd_slab_q.ql_prev);
		mmd->mmd_slab_cnt++;
	} else {
		slab = slab_last;
	}
	ASSERT(slab->pds_used < slab->pds_sz);
	pd = &(slab->pds_free_desc[slab->pds_used++]);
	ASSERT(pd->pd_magic == PDESC_MAGIC);
	pd->pd_next = NULL;
	pd->pd_prev = NULL;
	pd->pd_slab = slab;
	pd->pd_pattbl = NULL;

	/* copy over the descriptor info from caller */
	PDI_COPY(pdi, &(pd->pd_pdi));

	if (pd->pd_flags & PDESC_HBUF_REF)
		mmd->mmd_hbuf_ref++;
	if (pd->pd_flags & PDESC_PBUF_REF)
		mmd->mmd_pbuf_ref += pd->pd_pdi.pld_cnt;
	mmd->mmd_pd_cnt++;

	/* insert descriptor at end of list */
	insque(&(pd->pd_next), mmd->mmd_pd_q.ql_prev);
	mutex_exit(&(mmd->mmd_pd_slab_lock));

	return (pd);
}

/*
 * Packet descriptor slab kmem cache constructor routine.
 */
/* ARGSUSED */
static int
pdslab_constructor(void *buf, void *cdrarg, int kmflags)
{
	pdesc_slab_t *slab;
	uint_t cnt = (uint_t)(uintptr_t)cdrarg;
	int i;

	ASSERT(cnt > 0);	/* slab size can't be zero */

	slab = (pdesc_slab_t *)buf;
	slab->pds_next = NULL;
	slab->pds_prev = NULL;
	slab->pds_mmd = NULL;
	slab->pds_used = 0;
	slab->pds_sz = cnt;

	for (i = 0; i < cnt; i++) {
		pdesc_t *pd = &(slab->pds_free_desc[i]);
		pd->pd_magic = PDESC_MAGIC;
	}
	return (0);
}

/*
 * Packet descriptor slab kmem cache destructor routine.
 */
/* ARGSUSED */
static void
pdslab_destructor(void *buf, void *cdrarg)
{
	pdesc_slab_t *slab;

	slab = (pdesc_slab_t *)buf;
	ASSERT(slab->pds_next == NULL);
	ASSERT(slab->pds_prev == NULL);
	ASSERT(slab->pds_mmd == NULL);
	ASSERT(slab->pds_used == 0);
	ASSERT(slab->pds_sz > 0);
}

/*
 * Remove a packet descriptor from the in-use descriptor list,
 * called by mmd_rempdesc or during free.
 */
static pdesc_t *
mmd_destroy_pdesc(multidata_t *mmd, pdesc_t *pd)
{
	pdesc_t *pd_next;

	pd_next = Q2PD(pd->pd_next);
	remque(&(pd->pd_next));

	/* remove all local attributes */
	if (pd->pd_pattbl != NULL)
		mmd_destroy_pattbl(&(pd->pd_pattbl));

	/* don't decrease counts for a removed descriptor */
	if (!(pd->pd_flags & PDESC_REM_DEFER)) {
		if (pd->pd_flags & PDESC_HBUF_REF) {
			ASSERT(mmd->mmd_hbuf_ref > 0);
			mmd->mmd_hbuf_ref--;
		}
		if (pd->pd_flags & PDESC_PBUF_REF) {
			ASSERT(mmd->mmd_pbuf_ref > 0);
			mmd->mmd_pbuf_ref -= pd->pd_pdi.pld_cnt;
		}
		ASSERT(mmd->mmd_pd_cnt > 0);
		mmd->mmd_pd_cnt--;
	}
	return (pd_next);
}

/*
 * Remove a packet descriptor from the Multidata.
 */
void
mmd_rempdesc(pdesc_t *pd)
{
	multidata_t *mmd;

	ASSERT(pd->pd_magic == PDESC_MAGIC);
	ASSERT(pd->pd_slab != NULL);

	mmd = pd->pd_slab->pds_mmd;
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);

	mutex_enter(&(mmd->mmd_pd_slab_lock));
	/*
	 * We can't deallocate the associated resources if the Multidata
	 * is shared with other threads, because it's possible that the
	 * descriptor handle value is held by those threads.  That's why
	 * we simply mark the entry as "removed" and decrement the counts.
	 * If there are no other threads, then we free the descriptor.
	 */
	if (mmd->mmd_dp->db_ref > 1) {
		pd->pd_flags |= PDESC_REM_DEFER;
		if (pd->pd_flags & PDESC_HBUF_REF) {
			ASSERT(mmd->mmd_hbuf_ref > 0);
			mmd->mmd_hbuf_ref--;
		}
		if (pd->pd_flags & PDESC_PBUF_REF) {
			ASSERT(mmd->mmd_pbuf_ref > 0);
			mmd->mmd_pbuf_ref -= pd->pd_pdi.pld_cnt;
		}
		ASSERT(mmd->mmd_pd_cnt > 0);
		mmd->mmd_pd_cnt--;
	} else {
		(void) mmd_destroy_pdesc(mmd, pd);
	}
	mutex_exit(&(mmd->mmd_pd_slab_lock));
}

/*
 * A generic routine to traverse the packet descriptor in-use list.
 */
static pdesc_t *
mmd_getpdesc(multidata_t *mmd, pdesc_t *pd, pdescinfo_t *pdi, uint_t forw,
    boolean_t mutex_held)
{
	pdesc_t *pd_head;

	ASSERT(pd == NULL || pd->pd_slab->pds_mmd == mmd);
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);
	ASSERT(!mutex_held || MUTEX_HELD(&(mmd->mmd_pd_slab_lock)));

	if (!mutex_held)
		mutex_enter(&(mmd->mmd_pd_slab_lock));
	pd_head = Q2PD(&(mmd->mmd_pd_q));

	if (pd == NULL) {
		/*
		 * We're called by mmd_get{first,last}pdesc, and so
		 * return either the first or last list element.
		 */
		pd = forw ? Q2PD(mmd->mmd_pd_q.ql_next) :
		    Q2PD(mmd->mmd_pd_q.ql_prev);
	} else {
		/*
		 * We're called by mmd_get{next,prev}pdesc, and so
		 * return either the next or previous list element.
		 */
		pd = forw ? Q2PD(pd->pd_next) : Q2PD(pd->pd_prev);
	}

	while (pd != pd_head) {
		/* skip element if it has been removed */
		if (!(pd->pd_flags & PDESC_REM_DEFER))
			break;
		pd = forw ? Q2PD(pd->pd_next) : Q2PD(pd->pd_prev);
	}
	if (!mutex_held)
		mutex_exit(&(mmd->mmd_pd_slab_lock));

	/* return NULL if we're back at the beginning */
	if (pd == pd_head)
		pd = NULL;

	/* got an entry; copy descriptor info to caller */
	if (pd != NULL && pdi != NULL)
		PDI_COPY(&(pd->pd_pdi), pdi);

	ASSERT(pd == NULL || pd->pd_magic == PDESC_MAGIC);
	return (pd);

}

/*
 * Return the first packet descriptor in the in-use list.
 */
pdesc_t *
mmd_getfirstpdesc(multidata_t *mmd, pdescinfo_t *pdi)
{
	return (mmd_getpdesc(mmd, NULL, pdi, 1, B_FALSE));
}

/*
 * Return the last packet descriptor in the in-use list.
 */
pdesc_t *
mmd_getlastpdesc(multidata_t *mmd, pdescinfo_t *pdi)
{
	return (mmd_getpdesc(mmd, NULL, pdi, 0, B_FALSE));
}

/*
 * Return the next packet descriptor in the in-use list.
 */
pdesc_t *
mmd_getnextpdesc(pdesc_t *pd, pdescinfo_t *pdi)
{
	return (mmd_getpdesc(pd->pd_slab->pds_mmd, pd, pdi, 1, B_FALSE));
}

/*
 * Return the previous packet descriptor in the in-use list.
 */
pdesc_t *
mmd_getprevpdesc(pdesc_t *pd, pdescinfo_t *pdi)
{
	return (mmd_getpdesc(pd->pd_slab->pds_mmd, pd, pdi, 0, B_FALSE));
}

/*
 * Check to see if pdi stretches over c_pdi; used to ensure that a packet
 * descriptor's header and payload span may not be extended beyond the
 * current boundaries.
 */
static boolean_t
pdi_in_range(pdescinfo_t *pdi, pdescinfo_t *c_pdi)
{
	int i;
	struct pld_ary_s *pa = &pdi->pld_ary[0];
	struct pld_ary_s *c_pa = &c_pdi->pld_ary[0];

	if (pdi->hdr_base < c_pdi->hdr_base || pdi->hdr_lim > c_pdi->hdr_lim)
		return (B_FALSE);

	/*
	 * We don't allow the number of span to be reduced, for the sake
	 * of simplicity.  Instead, we provide PDESC_PLD_SPAN_CLEAR() to
	 * clear a packet descriptor.  Note that we allow the span count to
	 * be increased, and the bounds check for the new one happens
	 * in pbuf_ref_valid.
	 */
	if (pdi->pld_cnt < c_pdi->pld_cnt)
		return (B_FALSE);

	/* compare only those which are currently defined */
	for (i = 0; i < c_pdi->pld_cnt; i++, pa++, c_pa++) {
		if (pa->pld_pbuf_idx != c_pa->pld_pbuf_idx ||
		    pa->pld_rptr < c_pa->pld_rptr ||
		    pa->pld_wptr > c_pa->pld_wptr)
			return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Modify the layout of a packet descriptor.
 */
pdesc_t *
mmd_adjpdesc(pdesc_t *pd, pdescinfo_t *pdi)
{
	multidata_t *mmd;
	pdescinfo_t *c_pdi;

	ASSERT(pd != NULL);
	ASSERT(pdi != NULL);
	ASSERT(pd->pd_magic == PDESC_MAGIC);

	mmd = pd->pd_slab->pds_mmd;
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);

	/* entry has been removed */
	if (pd->pd_flags & PDESC_REM_DEFER)
		return (NULL);

	/* caller doesn't intend to specify any buffer reference? */
	if (!(pdi->flags & PDESC_HAS_REF))
		return (NULL);

	/* do the references refer to invalid memory regions? */
	if (!mmd_speed_over_safety &&
	    (((pdi->flags & PDESC_HBUF_REF) && !HBUF_REF_VALID(mmd, pdi)) ||
	    ((pdi->flags & PDESC_PBUF_REF) && !pbuf_ref_valid(mmd, pdi))))
		return (NULL);

	/* they're not subsets of current references? */
	c_pdi = &(pd->pd_pdi);
	if (!pdi_in_range(pdi, c_pdi))
		return (NULL);

	/* copy over the descriptor info from caller */
	PDI_COPY(pdi, c_pdi);

	return (pd);
}

/*
 * Copy the contents of a packet descriptor into a new buffer.  If the
 * descriptor points to more than one buffer fragments, the contents
 * of both fragments will be joined, with the header buffer fragment
 * preceding the payload buffer fragment(s).
 */
mblk_t *
mmd_transform(pdesc_t *pd)
{
	multidata_t *mmd;
	pdescinfo_t *pdi;
	mblk_t *mp;
	int h_size = 0, p_size = 0;
	int i, len;

	ASSERT(pd != NULL);
	ASSERT(pd->pd_magic == PDESC_MAGIC);

	mmd = pd->pd_slab->pds_mmd;
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);

	/* entry has been removed */
	if (pd->pd_flags & PDESC_REM_DEFER)
		return (NULL);

	mutex_enter(&mmd->mmd_pd_slab_lock);
	pdi = &(pd->pd_pdi);
	if (pdi->flags & PDESC_HBUF_REF)
		h_size = PDESC_HDRL(pdi);
	if (pdi->flags & PDESC_PBUF_REF) {
		for (i = 0; i < pdi->pld_cnt; i++)
			p_size += PDESC_PLD_SPAN_SIZE(pdi, i);
	}

	/* allocate space large enough to hold the fragment(s) */
	ASSERT(h_size + p_size >= 0);
	if ((mp = allocb(h_size + p_size, BPRI_HI)) == NULL) {
		mutex_exit(&mmd->mmd_pd_slab_lock);
		return (NULL);
	}

	/* copy over the header fragment */
	if ((pdi->flags & PDESC_HBUF_REF) && h_size > 0) {
		bcopy(pdi->hdr_rptr, mp->b_wptr, h_size);
		mp->b_wptr += h_size;
	}

	/* copy over the payload fragment */
	if ((pdi->flags & PDESC_PBUF_REF) && p_size > 0) {
		for (i = 0; i < pdi->pld_cnt; i++) {
			len = PDESC_PLD_SPAN_SIZE(pdi, i);
			if (len > 0) {
				bcopy(pdi->pld_ary[i].pld_rptr,
				    mp->b_wptr, len);
				mp->b_wptr += len;
			}
		}
	}

	mutex_exit(&mmd->mmd_pd_slab_lock);
	return (mp);
}

/*
 * Return a chain of mblks representing the Multidata packet.
 */
mblk_t *
mmd_transform_link(pdesc_t *pd)
{
	multidata_t *mmd;
	pdescinfo_t *pdi;
	mblk_t *nmp = NULL;

	ASSERT(pd != NULL);
	ASSERT(pd->pd_magic == PDESC_MAGIC);

	mmd = pd->pd_slab->pds_mmd;
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);

	/* entry has been removed */
	if (pd->pd_flags & PDESC_REM_DEFER)
		return (NULL);

	pdi = &(pd->pd_pdi);

	/* duplicate header buffer */
	if ((pdi->flags & PDESC_HBUF_REF)) {
		if ((nmp = dupb(mmd->mmd_hbuf)) == NULL)
			return (NULL);
		nmp->b_rptr = pdi->hdr_rptr;
		nmp->b_wptr = pdi->hdr_wptr;
	}

	/* duplicate payload buffer(s) */
	if (pdi->flags & PDESC_PBUF_REF) {
		int i;
		mblk_t *mp;
		struct pld_ary_s *pa = &pdi->pld_ary[0];

		mutex_enter(&mmd->mmd_pd_slab_lock);
		for (i = 0; i < pdi->pld_cnt; i++, pa++) {
			ASSERT(mmd->mmd_pbuf[pa->pld_pbuf_idx] != NULL);

			/* skip empty ones */
			if (PDESC_PLD_SPAN_SIZE(pdi, i) == 0)
				continue;

			mp = dupb(mmd->mmd_pbuf[pa->pld_pbuf_idx]);
			if (mp == NULL) {
				if (nmp != NULL)
					freemsg(nmp);
				mutex_exit(&mmd->mmd_pd_slab_lock);
				return (NULL);
			}
			mp->b_rptr = pa->pld_rptr;
			mp->b_wptr = pa->pld_wptr;
			if (nmp == NULL)
				nmp = mp;
			else
				linkb(nmp, mp);
		}
		mutex_exit(&mmd->mmd_pd_slab_lock);
	}

	return (nmp);
}

/*
 * Return duplicate message block(s) of the associated buffer(s).
 */
int
mmd_dupbufs(multidata_t *mmd, mblk_t **hmp, mblk_t **pmp)
{
	ASSERT(mmd != NULL);
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);

	if (hmp != NULL) {
		*hmp = NULL;
		if (mmd->mmd_hbuf != NULL &&
		    (*hmp = dupb(mmd->mmd_hbuf)) == NULL)
			return (-1);
	}

	if (pmp != NULL) {
		int i;
		mblk_t *mp;

		mutex_enter(&mmd->mmd_pd_slab_lock);
		*pmp = NULL;
		for (i = 0; i < mmd->mmd_pbuf_cnt; i++) {
			ASSERT(mmd->mmd_pbuf[i] != NULL);
			mp = dupb(mmd->mmd_pbuf[i]);
			if (mp == NULL) {
				if (hmp != NULL && *hmp != NULL)
					freeb(*hmp);
				if (*pmp != NULL)
					freemsg(*pmp);
				mutex_exit(&mmd->mmd_pd_slab_lock);
				return (-1);
			}
			if (*pmp == NULL)
				*pmp = mp;
			else
				linkb(*pmp, mp);
		}
		mutex_exit(&mmd->mmd_pd_slab_lock);
	}

	return (0);
}

/*
 * Return the layout of a packet descriptor.
 */
int
mmd_getpdescinfo(pdesc_t *pd, pdescinfo_t *pdi)
{
	ASSERT(pd != NULL);
	ASSERT(pd->pd_magic == PDESC_MAGIC);
	ASSERT(pd->pd_slab != NULL);
	ASSERT(pd->pd_slab->pds_mmd->mmd_magic == MULTIDATA_MAGIC);
	ASSERT(pdi != NULL);

	/* entry has been removed */
	if (pd->pd_flags & PDESC_REM_DEFER)
		return (-1);

	/* copy descriptor info to caller */
	PDI_COPY(&(pd->pd_pdi), pdi);

	return (0);
}

/*
 * Add a global or local attribute to a Multidata.  Global attribute
 * association is specified by a NULL packet descriptor.
 */
pattr_t *
mmd_addpattr(multidata_t *mmd, pdesc_t *pd, pattrinfo_t *pai,
    boolean_t persistent, int kmflags)
{
	patbkt_t **tbl_p;
	patbkt_t *tbl, *o_tbl;
	patbkt_t *bkt;
	pattr_t *pa;
	uint_t size;

	ASSERT(mmd != NULL);
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);
	ASSERT(pd == NULL || pd->pd_magic == PDESC_MAGIC);
	ASSERT(pai != NULL);

	/* pointer to the attribute hash table (local or global) */
	tbl_p = pd != NULL ? &(pd->pd_pattbl) : &(mmd->mmd_pattbl);

	/*
	 * See if the hash table has not yet been created; if so,
	 * we create the table and store its address atomically.
	 */
	if ((tbl = *tbl_p) == NULL) {
		tbl = kmem_cache_alloc(pattbl_cache, kmflags);
		if (tbl == NULL)
			return (NULL);

		/* if someone got there first, use his table instead */
		if ((o_tbl = atomic_cas_ptr(tbl_p, NULL, tbl)) != NULL) {
			kmem_cache_free(pattbl_cache, tbl);
			tbl = o_tbl;
		}
	}

	ASSERT(tbl->pbkt_tbl_sz > 0);
	bkt = &(tbl[PATTBL_HASH(pai->type, tbl->pbkt_tbl_sz)]);

	/* attribute of the same type already exists? */
	if ((pa = mmd_find_pattr(bkt, pai->type)) != NULL)
		return (NULL);

	size = sizeof (*pa) + pai->len;
	if ((pa = kmem_zalloc(size, kmflags)) == NULL)
		return (NULL);

	pa->pat_magic = PATTR_MAGIC;
	pa->pat_lock = &(bkt->pbkt_lock);
	pa->pat_mmd = mmd;
	pa->pat_buflen = size;
	pa->pat_type = pai->type;
	pai->buf = pai->len > 0 ? ((uchar_t *)(pa + 1)) : NULL;

	if (persistent)
		pa->pat_flags = PATTR_PERSIST;

	/* insert attribute at end of hash chain */
	mutex_enter(&(bkt->pbkt_lock));
	insque(&(pa->pat_next), bkt->pbkt_pattr_q.ql_prev);
	mutex_exit(&(bkt->pbkt_lock));

	return (pa);
}

/*
 * Attribute hash table kmem cache constructor routine.
 */
/* ARGSUSED */
static int
pattbl_constructor(void *buf, void *cdrarg, int kmflags)
{
	patbkt_t *bkt;
	uint_t tbl_sz = (uint_t)(uintptr_t)cdrarg;
	uint_t i;

	ASSERT(tbl_sz > 0);	/* table size can't be zero */

	for (i = 0, bkt = (patbkt_t *)buf; i < tbl_sz; i++, bkt++) {
		mutex_init(&(bkt->pbkt_lock), NULL, MUTEX_DRIVER, NULL);
		QL_INIT(&(bkt->pbkt_pattr_q));

		/* first bucket contains the table size */
		bkt->pbkt_tbl_sz = i == 0 ? tbl_sz : 0;
	}
	return (0);
}

/*
 * Attribute hash table kmem cache destructor routine.
 */
/* ARGSUSED */
static void
pattbl_destructor(void *buf, void *cdrarg)
{
	patbkt_t *bkt;
	uint_t tbl_sz = (uint_t)(uintptr_t)cdrarg;
	uint_t i;

	ASSERT(tbl_sz > 0);	/* table size can't be zero */

	for (i = 0, bkt = (patbkt_t *)buf; i < tbl_sz; i++, bkt++) {
		mutex_destroy(&(bkt->pbkt_lock));
		ASSERT(bkt->pbkt_pattr_q.ql_next == &(bkt->pbkt_pattr_q));
		ASSERT(i > 0 || bkt->pbkt_tbl_sz == tbl_sz);
	}
}

/*
 * Destroy an attribute hash table, called by mmd_rempdesc or during free.
 */
static void
mmd_destroy_pattbl(patbkt_t **tbl)
{
	patbkt_t *bkt;
	pattr_t *pa, *pa_next;
	uint_t i, tbl_sz;

	ASSERT(tbl != NULL);
	bkt = *tbl;
	tbl_sz = bkt->pbkt_tbl_sz;

	/* make sure caller passes in the first bucket */
	ASSERT(tbl_sz > 0);

	/* destroy the contents of each bucket */
	for (i = 0; i < tbl_sz; i++, bkt++) {
		/* we ought to be exclusive at this point */
		ASSERT(MUTEX_NOT_HELD(&(bkt->pbkt_lock)));

		pa = Q2PATTR(bkt->pbkt_pattr_q.ql_next);
		while (pa != Q2PATTR(&(bkt->pbkt_pattr_q))) {
			ASSERT(pa->pat_magic == PATTR_MAGIC);
			pa_next = Q2PATTR(pa->pat_next);
			remque(&(pa->pat_next));
			kmem_free(pa, pa->pat_buflen);
			pa = pa_next;
		}
	}

	kmem_cache_free(pattbl_cache, *tbl);
	*tbl = NULL;

	/* commit all previous stores */
	membar_producer();
}

/*
 * Copy the contents of an attribute hash table, called by mmd_copy.
 */
static int
mmd_copy_pattbl(patbkt_t *src_tbl, multidata_t *n_mmd, pdesc_t *n_pd,
    int kmflags)
{
	patbkt_t *bkt;
	pattr_t *pa;
	pattrinfo_t pai;
	uint_t i, tbl_sz;

	ASSERT(src_tbl != NULL);
	bkt = src_tbl;
	tbl_sz = bkt->pbkt_tbl_sz;

	/* make sure caller passes in the first bucket */
	ASSERT(tbl_sz > 0);

	for (i = 0; i < tbl_sz; i++, bkt++) {
		mutex_enter(&(bkt->pbkt_lock));
		pa = Q2PATTR(bkt->pbkt_pattr_q.ql_next);
		while (pa != Q2PATTR(&(bkt->pbkt_pattr_q))) {
			pattr_t *pa_next = Q2PATTR(pa->pat_next);

			/* skip if it's removed */
			if (pa->pat_flags & PATTR_REM_DEFER) {
				pa = pa_next;
				continue;
			}

			pai.type = pa->pat_type;
			pai.len = pa->pat_buflen - sizeof (*pa);
			if (mmd_addpattr(n_mmd, n_pd, &pai, (pa->pat_flags &
			    PATTR_PERSIST) != 0, kmflags) == NULL) {
				mutex_exit(&(bkt->pbkt_lock));
				return (-1);
			}

			/* copy over the contents */
			if (pai.buf != NULL)
				bcopy(pa + 1, pai.buf, pai.len);

			pa = pa_next;
		}
		mutex_exit(&(bkt->pbkt_lock));
	}

	return (0);
}

/*
 * Search for an attribute type within an attribute hash bucket.
 */
static pattr_t *
mmd_find_pattr(patbkt_t *bkt, uint_t type)
{
	pattr_t *pa_head, *pa;

	mutex_enter(&(bkt->pbkt_lock));
	pa_head = Q2PATTR(&(bkt->pbkt_pattr_q));
	pa = Q2PATTR(bkt->pbkt_pattr_q.ql_next);

	while (pa != pa_head) {
		ASSERT(pa->pat_magic == PATTR_MAGIC);

		/* return a match; we treat removed entry as non-existent */
		if (pa->pat_type == type && !(pa->pat_flags & PATTR_REM_DEFER))
			break;
		pa = Q2PATTR(pa->pat_next);
	}
	mutex_exit(&(bkt->pbkt_lock));

	return (pa == pa_head ? NULL : pa);
}

/*
 * Remove an attribute from a Multidata.
 */
void
mmd_rempattr(pattr_t *pa)
{
	kmutex_t *pat_lock = pa->pat_lock;

	ASSERT(pa->pat_magic == PATTR_MAGIC);

	/* ignore if attribute was marked as persistent */
	if ((pa->pat_flags & PATTR_PERSIST) != 0)
		return;

	mutex_enter(pat_lock);
	/*
	 * We can't deallocate the associated resources if the Multidata
	 * is shared with other threads, because it's possible that the
	 * attribute handle value is held by those threads.  That's why
	 * we simply mark the entry as "removed".  If there are no other
	 * threads, then we free the attribute.
	 */
	if (pa->pat_mmd->mmd_dp->db_ref > 1) {
		pa->pat_flags |= PATTR_REM_DEFER;
	} else {
		remque(&(pa->pat_next));
		kmem_free(pa, pa->pat_buflen);
	}
	mutex_exit(pat_lock);
}

/*
 * Find an attribute (according to its type) and return its handle.
 */
pattr_t *
mmd_getpattr(multidata_t *mmd, pdesc_t *pd, pattrinfo_t *pai)
{
	patbkt_t *tbl, *bkt;
	pattr_t *pa;

	ASSERT(mmd != NULL);
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);
	ASSERT(pai != NULL);

	/* get the right attribute hash table (local or global) */
	tbl = pd != NULL ? pd->pd_pattbl : mmd->mmd_pattbl;

	/* attribute hash table doesn't exist? */
	if (tbl == NULL)
		return (NULL);

	ASSERT(tbl->pbkt_tbl_sz > 0);
	bkt = &(tbl[PATTBL_HASH(pai->type, tbl->pbkt_tbl_sz)]);

	if ((pa = mmd_find_pattr(bkt, pai->type)) != NULL) {
		ASSERT(pa->pat_buflen >= sizeof (*pa));
		pai->len = pa->pat_buflen - sizeof (*pa);
		pai->buf = pai->len > 0 ?
		    (uchar_t *)pa + sizeof (pattr_t) : NULL;
	}
	ASSERT(pa == NULL || pa->pat_magic == PATTR_MAGIC);
	return (pa);
}

/*
 * Return total size of buffers and total size of areas referenced
 * by all in-use (unremoved) packet descriptors.
 */
void
mmd_getsize(multidata_t *mmd, uint_t *ptotal, uint_t *pinuse)
{
	pdesc_t *pd;
	pdescinfo_t *pdi;
	int i;

	ASSERT(mmd != NULL);
	ASSERT(mmd->mmd_magic == MULTIDATA_MAGIC);

	mutex_enter(&mmd->mmd_pd_slab_lock);
	if (ptotal != NULL) {
		*ptotal = 0;

		if (mmd->mmd_hbuf != NULL)
			*ptotal += MBLKL(mmd->mmd_hbuf);

		for (i = 0; i < mmd->mmd_pbuf_cnt; i++) {
			ASSERT(mmd->mmd_pbuf[i] != NULL);
			*ptotal += MBLKL(mmd->mmd_pbuf[i]);
		}
	}
	if (pinuse != NULL) {
		*pinuse = 0;

		/* first pdesc */
		pd = mmd_getpdesc(mmd, NULL, NULL, 1, B_TRUE);
		while (pd != NULL) {
			pdi = &pd->pd_pdi;

			/* next pdesc */
			pd = mmd_getpdesc(mmd, pd, NULL, 1, B_TRUE);

			/* skip over removed descriptor */
			if (pdi->flags & PDESC_REM_DEFER)
				continue;

			if (pdi->flags & PDESC_HBUF_REF)
				*pinuse += PDESC_HDRL(pdi);

			if (pdi->flags & PDESC_PBUF_REF) {
				for (i = 0; i < pdi->pld_cnt; i++)
					*pinuse += PDESC_PLDL(pdi, i);
			}
		}
	}
	mutex_exit(&mmd->mmd_pd_slab_lock);
}
