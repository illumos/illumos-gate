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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/vnode.h>
#include <sys/vfs_opreg.h>
#include <sys/cmn_err.h>
#include <sys/swap.h>
#include <sys/mman.h>
#include <sys/vmsystm.h>
#include <sys/vtrace.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/vm.h>

#include <sys/fs/swapnode.h>

#include <vm/seg.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <fs/fs_subr.h>

#include <vm/seg_kp.h>

/*
 * Define the routines within this file.
 */
static int	swap_getpage(struct vnode *vp, offset_t off, size_t len,
    uint_t *protp, struct page **plarr, size_t plsz, struct seg *seg,
    caddr_t addr, enum seg_rw rw, struct cred *cr, caller_context_t *ct);
static int	swap_putpage(struct vnode *vp, offset_t off, size_t len,
    int flags, struct cred *cr, caller_context_t *ct);
static void	swap_inactive(struct vnode *vp, struct cred *cr,
    caller_context_t *ct);
static void	swap_dispose(vnode_t *vp, page_t *pp, int fl, int dn,
    cred_t *cr, caller_context_t *ct);

static int	swap_getapage(struct vnode *vp, u_offset_t off, size_t len,
    uint_t *protp, page_t **plarr, size_t plsz,
    struct seg *seg, caddr_t addr, enum seg_rw rw, struct cred *cr);

int	swap_getconpage(struct vnode *vp, u_offset_t off, size_t len,
    uint_t *protp, page_t **plarr, size_t plsz, page_t *conpp,
    uint_t *pszc, spgcnt_t *nreloc, struct seg *seg, caddr_t addr,
    enum seg_rw rw, struct cred *cr);

static int 	swap_putapage(struct vnode *vp, page_t *pp, u_offset_t *off,
    size_t *lenp, int flags, struct cred *cr);

const fs_operation_def_t swap_vnodeops_template[] = {
	VOPNAME_INACTIVE,	{ .vop_inactive = swap_inactive },
	VOPNAME_GETPAGE,	{ .vop_getpage = swap_getpage },
	VOPNAME_PUTPAGE,	{ .vop_putpage = swap_putpage },
	VOPNAME_DISPOSE,	{ .vop_dispose = swap_dispose },
	VOPNAME_SETFL,		{ .error = fs_error },
	VOPNAME_POLL,		{ .error = fs_error },
	VOPNAME_PATHCONF,	{ .error = fs_error },
	VOPNAME_GETSECATTR,	{ .error = fs_error },
	VOPNAME_SHRLOCK,	{ .error = fs_error },
	NULL,			NULL
};

vnodeops_t *swap_vnodeops;

/* ARGSUSED */
static void
swap_inactive(
	struct vnode *vp,
	struct cred *cr,
	caller_context_t *ct)
{
	SWAPFS_PRINT(SWAP_VOPS, "swap_inactive: vp %x\n", vp, 0, 0, 0, 0);
}

/*
 * Return all the pages from [off..off+len] in given file
 */
/*ARGSUSED*/
static int
swap_getpage(
	struct vnode *vp,
	offset_t off,
	size_t len,
	uint_t *protp,
	page_t *pl[],
	size_t plsz,
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	struct cred *cr,
	caller_context_t *ct)
{
	SWAPFS_PRINT(SWAP_VOPS, "swap_getpage: vp %p, off %llx, len %lx\n",
	    (void *)vp, off, len, 0, 0);

	TRACE_3(TR_FAC_SWAPFS, TR_SWAPFS_GETPAGE,
	    "swapfs getpage:vp %p off %llx len %ld",
	    (void *)vp, off, len);

	return (pvn_getpages(swap_getapage, vp, (u_offset_t)off, len, protp,
	    pl, plsz, seg, addr, rw, cr));
}

/*
 * Called from pvn_getpages to get a particular page.
 */
/*ARGSUSED*/
static int
swap_getapage(
	struct vnode *vp,
	u_offset_t off,
	size_t len,
	uint_t *protp,
	page_t *pl[],
	size_t plsz,
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	struct cred *cr)
{
	struct page *pp, *rpp;
	int flags;
	int err = 0;
	struct vnode *pvp = NULL;
	u_offset_t poff;
	int flag_noreloc;
	se_t lock;
	extern int kcage_on;
	int upgrade = 0;

	SWAPFS_PRINT(SWAP_VOPS, "swap_getapage: vp %p, off %llx, len %lx\n",
	    vp, off, len, 0, 0);

	/*
	 * Until there is a call-back mechanism to cause SEGKP
	 * pages to be unlocked, make them non-relocatable.
	 */
	if (SEG_IS_SEGKP(seg))
		flag_noreloc = PG_NORELOC;
	else
		flag_noreloc = 0;

	if (protp != NULL)
		*protp = PROT_ALL;

	lock = (rw == S_CREATE ? SE_EXCL : SE_SHARED);

again:
	if (pp = page_lookup(vp, off, lock)) {
		/*
		 * In very rare instances, a segkp page may have been
		 * relocated outside of the kernel by the kernel cage
		 * due to the window between page_unlock() and
		 * VOP_PUTPAGE() in segkp_unlock().  Due to the
		 * rareness of these occurances, the solution is to
		 * relocate the page to a P_NORELOC page.
		 */
		if (flag_noreloc != 0) {
			if (!PP_ISNORELOC(pp) && kcage_on) {
				if (lock != SE_EXCL) {
					upgrade = 1;
					if (!page_tryupgrade(pp)) {
						page_unlock(pp);
						lock = SE_EXCL;
						goto again;
					}
				}

				if (page_relocate_cage(&pp, &rpp) != 0)
					panic("swap_getapage: "
					    "page_relocate_cage failed");

				pp = rpp;
			}
		}

		if (pl) {
			if (upgrade)
				page_downgrade(pp);

			pl[0] = pp;
			pl[1] = NULL;
		} else {
			page_unlock(pp);
		}
	} else {
		pp = page_create_va(vp, off, PAGESIZE,
		    PG_WAIT | PG_EXCL | flag_noreloc,
		    seg, addr);
		/*
		 * Someone raced in and created the page after we did the
		 * lookup but before we did the create, so go back and
		 * try to look it up again.
		 */
		if (pp == NULL)
			goto again;
		if (rw != S_CREATE) {
			err = swap_getphysname(vp, off, &pvp, &poff);
			if (pvp) {
				struct anon *ap;
				kmutex_t *ahm;

				flags = (pl == NULL ? B_ASYNC|B_READ : B_READ);
				err = VOP_PAGEIO(pvp, pp, poff,
				    PAGESIZE, flags, cr, NULL);

				if (!err) {
					ahm = AH_MUTEX(vp, off);
					mutex_enter(ahm);

					ap = swap_anon(vp, off);
					if (ap == NULL) {
						panic("swap_getapage:"
						    " null anon");
					}

					if (ap->an_pvp == pvp &&
					    ap->an_poff == poff) {
						swap_phys_free(pvp, poff,
						    PAGESIZE);
						ap->an_pvp = NULL;
						ap->an_poff = NULL;
						hat_setmod(pp);
					}

					mutex_exit(ahm);
				}
			} else {
				if (!err)
					pagezero(pp, 0, PAGESIZE);

				/*
				 * If it's a fault ahead, release page_io_lock
				 * and SE_EXCL we grabbed in page_create_va
				 *
				 * If we are here, we haven't called VOP_PAGEIO
				 * and thus calling pvn_read_done(pp, B_READ)
				 * below may mislead that we tried i/o. Besides,
				 * in case of async, pvn_read_done() should
				 * not be called by *getpage()
				 */
				if (pl == NULL) {
					/*
					 * swap_getphysname can return error
					 * only when we are getting called from
					 * swapslot_free which passes non-NULL
					 * pl to VOP_GETPAGE.
					 */
					ASSERT(err == 0);
					page_io_unlock(pp);
					page_unlock(pp);
				}
			}
		}

		ASSERT(pp != NULL);

		if (err && pl)
			pvn_read_done(pp, B_ERROR);

		if (!err && pl)
			pvn_plist_init(pp, pl, plsz, off, PAGESIZE, rw);
	}
	TRACE_3(TR_FAC_SWAPFS, TR_SWAPFS_GETAPAGE,
	    "swapfs getapage:pp %p vp %p off %llx", pp, vp, off);
	return (err);
}

/*
 * Called from large page anon routines only! This is an ugly hack where
 * the anon layer directly calls into swapfs with a preallocated large page.
 * Another method would have been to change to VOP and add an extra arg for
 * the preallocated large page. This all could be cleaned up later when we
 * solve the anonymous naming problem and no longer need to loop across of
 * the VOP in PAGESIZE increments to fill in or initialize a large page as
 * is done today. I think the latter is better since it avoid a change to
 * the VOP interface that could later be avoided.
 */
int
swap_getconpage(
	struct vnode *vp,
	u_offset_t off,
	size_t len,
	uint_t *protp,
	page_t *pl[],
	size_t plsz,
	page_t	*conpp,
	uint_t	*pszc,
	spgcnt_t *nreloc,
	struct seg *seg,
	caddr_t addr,
	enum seg_rw rw,
	struct cred *cr)
{
	struct page	*pp;
	int 		err = 0;
	struct vnode	*pvp = NULL;
	u_offset_t	poff;

	ASSERT(len == PAGESIZE);
	ASSERT(pl != NULL);
	ASSERT(plsz == PAGESIZE);
	ASSERT(protp == NULL);
	ASSERT(nreloc != NULL);
	ASSERT(!SEG_IS_SEGKP(seg)); /* XXX for now not supported */
	SWAPFS_PRINT(SWAP_VOPS, "swap_getconpage: vp %p, off %llx, len %lx\n",
	    vp, off, len, 0, 0);

	/*
	 * If we are not using a preallocated page then we know one already
	 * exists. So just let the old code handle it.
	 */
	if (conpp == NULL) {
		err = swap_getapage(vp, (u_offset_t)off, len, protp, pl, plsz,
		    seg, addr, rw, cr);
		return (err);
	}
	ASSERT(conpp->p_szc != 0);
	ASSERT(PAGE_EXCL(conpp));


	ASSERT(conpp->p_next == conpp);
	ASSERT(conpp->p_prev == conpp);
	ASSERT(!PP_ISAGED(conpp));
	ASSERT(!PP_ISFREE(conpp));

	*nreloc = 0;
	pp = page_lookup_create(vp, off, SE_SHARED, conpp, nreloc, 0);

	/*
	 * If existing page is found we may need to relocate.
	 */
	if (pp != conpp) {
		ASSERT(rw != S_CREATE);
		ASSERT(pszc != NULL);
		ASSERT(PAGE_SHARED(pp));
		if (pp->p_szc < conpp->p_szc) {
			*pszc = pp->p_szc;
			page_unlock(pp);
			err = -1;
		} else if (pp->p_szc > conpp->p_szc &&
		    seg->s_szc > conpp->p_szc) {
			*pszc = MIN(pp->p_szc, seg->s_szc);
			page_unlock(pp);
			err = -2;
		} else {
			pl[0] = pp;
			pl[1] = NULL;
			if (page_pptonum(pp) &
			    (page_get_pagecnt(conpp->p_szc) - 1))
				cmn_err(CE_PANIC, "swap_getconpage: no root");
		}
		return (err);
	}

	ASSERT(PAGE_EXCL(pp));

	if (*nreloc != 0) {
		ASSERT(rw != S_CREATE);
		pl[0] = pp;
		pl[1] = NULL;
		return (0);
	}

	*nreloc = 1;

	/*
	 * If necessary do the page io.
	 */
	if (rw != S_CREATE) {
		/*
		 * Since we are only called now on behalf of an
		 * address space operation it's impossible for
		 * us to fail unlike swap_getapge() which
		 * also gets called from swapslot_free().
		 */
		if (swap_getphysname(vp, off, &pvp, &poff)) {
			cmn_err(CE_PANIC,
			    "swap_getconpage: swap_getphysname failed!");
		}

		if (pvp != NULL) {
			err = VOP_PAGEIO(pvp, pp, poff, PAGESIZE, B_READ,
			    cr, NULL);
			if (err == 0) {
				struct anon *ap;
				kmutex_t *ahm;

				ahm = AH_MUTEX(vp, off);
				mutex_enter(ahm);
				ap = swap_anon(vp, off);
				if (ap == NULL)
					panic("swap_getconpage: null anon");
				if (ap->an_pvp != pvp || ap->an_poff != poff)
					panic("swap_getconpage: bad anon");

				swap_phys_free(pvp, poff, PAGESIZE);
				ap->an_pvp = NULL;
				ap->an_poff = NULL;
				hat_setmod(pp);
				mutex_exit(ahm);
			}
		} else {
			pagezero(pp, 0, PAGESIZE);
		}
	}

	/*
	 * Normally we would let pvn_read_done() destroy
	 * the page on IO error. But since this is a preallocated
	 * page we'll let the anon layer handle it.
	 */
	page_io_unlock(pp);
	if (err != 0)
		page_hashout(pp, NULL);
	ASSERT(pp->p_next == pp);
	ASSERT(pp->p_prev == pp);

	TRACE_3(TR_FAC_SWAPFS, TR_SWAPFS_GETAPAGE,
	    "swapfs getconpage:pp %p vp %p off %llx", pp, vp, off);

	pl[0] = pp;
	pl[1] = NULL;
	return (err);
}

/* Async putpage klustering stuff */
int sw_pending_size;
extern int klustsize;
extern struct async_reqs *sw_getreq();
extern void sw_putreq(struct async_reqs *);
extern void sw_putbackreq(struct async_reqs *);
extern struct async_reqs *sw_getfree();
extern void sw_putfree(struct async_reqs *);

static size_t swap_putpagecnt, swap_pagespushed;
static size_t swap_otherfail, swap_otherpages;
static size_t swap_klustfail, swap_klustpages;
static size_t swap_getiofail, swap_getiopages;

/*
 * Flags are composed of {B_INVAL, B_DIRTY B_FREE, B_DONTNEED}.
 * If len == 0, do from off to EOF.
 */
static int swap_nopage = 0;	/* Don't do swap_putpage's if set */

/* ARGSUSED */
static int
swap_putpage(
	struct vnode *vp,
	offset_t off,
	size_t len,
	int flags,
	struct cred *cr,
	caller_context_t *ct)
{
	page_t *pp;
	u_offset_t io_off;
	size_t io_len = 0;
	int err = 0;
	int nowait;
	struct async_reqs *arg;

	if (swap_nopage)
		return (0);

	ASSERT(vp->v_count != 0);

	nowait = flags & B_PAGE_NOWAIT;

	/*
	 * Clear force flag so that p_lckcnt pages are not invalidated.
	 */
	flags &= ~(B_FORCE | B_PAGE_NOWAIT);

	SWAPFS_PRINT(SWAP_VOPS,
	    "swap_putpage: vp %p, off %llx len %lx, flags %x\n",
	    (void *)vp, off, len, flags, 0);
	TRACE_3(TR_FAC_SWAPFS, TR_SWAPFS_PUTPAGE,
	    "swapfs putpage:vp %p off %llx len %ld", (void *)vp, off, len);

	if (vp->v_flag & VNOMAP)
		return (ENOSYS);

	if (!vn_has_cached_data(vp))
		return (0);

	if (len == 0) {
		if (curproc == proc_pageout)
			cmn_err(CE_PANIC, "swapfs: pageout can't block");

		/* Search the entire vp list for pages >= off. */
		err = pvn_vplist_dirty(vp, (u_offset_t)off, swap_putapage,
		    flags, cr);
	} else {
		u_offset_t eoff;

		/*
		 * Loop over all offsets in the range [off...off + len]
		 * looking for pages to deal with.
		 */
		eoff = off + len;
		for (io_off = (u_offset_t)off; io_off < eoff;
		    io_off += io_len) {
			/*
			 * If we run out of the async req slot, put the page
			 * now instead of queuing.
			 */
			if (flags == (B_ASYNC | B_FREE) &&
			    sw_pending_size < klustsize &&
			    (arg = sw_getfree())) {
				/*
				 * If we are clustering, we should allow
				 * pageout to feed us more pages because # of
				 * pushes is limited by # of I/Os, and one
				 * cluster is considered to be one I/O.
				 */
				if (pushes)
					pushes--;

				arg->a_vp = vp;
				arg->a_off = io_off;
				arg->a_len = PAGESIZE;
				arg->a_flags = B_ASYNC | B_FREE;
				arg->a_cred = kcred;
				sw_putreq(arg);
				io_len = PAGESIZE;
				continue;
			}
			/*
			 * If we are not invalidating pages, use the
			 * routine page_lookup_nowait() to prevent
			 * reclaiming them from the free list.
			 */
			if (!nowait && ((flags & B_INVAL) ||
			    (flags & (B_ASYNC | B_FREE)) == B_FREE))
				pp = page_lookup(vp, io_off, SE_EXCL);
			else
				pp = page_lookup_nowait(vp, io_off,
				    (flags & (B_FREE | B_INVAL)) ?
				    SE_EXCL : SE_SHARED);

			if (pp == NULL || pvn_getdirty(pp, flags) == 0)
				io_len = PAGESIZE;
			else {
				err = swap_putapage(vp, pp, &io_off, &io_len,
				    flags, cr);
				if (err != 0)
					break;
			}
		}
	}
	/* If invalidating, verify all pages on vnode list are gone. */
	if (err == 0 && off == 0 && len == 0 &&
	    (flags & B_INVAL) && vn_has_cached_data(vp)) {
		cmn_err(CE_WARN,
		    "swap_putpage: B_INVAL, pages not gone");
	}
	return (err);
}

/*
 * Write out a single page.
 * For swapfs this means choose a physical swap slot and write the page
 * out using VOP_PAGEIO.
 * In the (B_ASYNC | B_FREE) case we try to find a bunch of other dirty
 * swapfs pages, a bunch of contiguous swap slots and then write them
 * all out in one clustered i/o.
 */
/*ARGSUSED*/
static int
swap_putapage(
	struct vnode *vp,
	page_t *pp,
	u_offset_t *offp,
	size_t *lenp,
	int flags,
	struct cred *cr)
{
	int err;
	struct vnode *pvp;
	u_offset_t poff, off;
	u_offset_t doff;
	size_t dlen;
	size_t klsz = 0;
	u_offset_t klstart = 0;
	struct vnode *klvp = NULL;
	page_t *pplist;
	se_t se;
	struct async_reqs *arg;
	size_t swap_klustsize;

	/*
	 * This check is added for callers who access swap_putpage with len = 0.
	 * swap_putpage calls swap_putapage page-by-page via pvn_vplist_dirty.
	 * And it's necessary to do the same queuing if users have the same
	 * B_ASYNC|B_FREE flags on.
	 */
	if (flags == (B_ASYNC | B_FREE) &&
	    sw_pending_size < klustsize && (arg = sw_getfree())) {

		hat_setmod(pp);
		page_io_unlock(pp);
		page_unlock(pp);

		arg->a_vp = vp;
		arg->a_off = pp->p_offset;
		arg->a_len = PAGESIZE;
		arg->a_flags = B_ASYNC | B_FREE;
		arg->a_cred = kcred;
		sw_putreq(arg);

		return (0);
	}

	SWAPFS_PRINT(SWAP_PUTP,
	    "swap_putapage: pp %p, vp %p, off %llx, flags %x\n",
	    pp, vp, pp->p_offset, flags, 0);

	ASSERT(PAGE_LOCKED(pp));

	off = pp->p_offset;

	doff = off;
	dlen = PAGESIZE;

	if (err = swap_newphysname(vp, off, &doff, &dlen, &pvp, &poff)) {
		err = (flags == (B_ASYNC | B_FREE) ? ENOMEM : 0);
		hat_setmod(pp);
		page_io_unlock(pp);
		page_unlock(pp);
		goto out;
	}

	klvp = pvp;
	klstart = poff;
	pplist = pp;
	/*
	 * If this is ASYNC | FREE and we've accumulated a bunch of such
	 * pending requests, kluster.
	 */
	if (flags == (B_ASYNC | B_FREE))
		swap_klustsize = klustsize;
	else
		swap_klustsize = PAGESIZE;
	se = (flags & B_FREE ? SE_EXCL : SE_SHARED);
	klsz = PAGESIZE;
	while (klsz < swap_klustsize) {
		if ((arg = sw_getreq()) == NULL) {
			swap_getiofail++;
			swap_getiopages += btop(klsz);
			break;
		}
		ASSERT(vn_matchops(arg->a_vp, swap_vnodeops));
		vp = arg->a_vp;
		off = arg->a_off;

		if ((pp = page_lookup_nowait(vp, off, se)) == NULL) {
			swap_otherfail++;
			swap_otherpages += btop(klsz);
			sw_putfree(arg);
			break;
		}
		if (pvn_getdirty(pp, flags | B_DELWRI) == 0) {
			sw_putfree(arg);
			continue;
		}
		/* Get new physical backing store for the page */
		doff = off;
		dlen = PAGESIZE;
		if (err = swap_newphysname(vp, off, &doff, &dlen,
		    &pvp, &poff)) {
			swap_otherfail++;
			swap_otherpages += btop(klsz);
			hat_setmod(pp);
			page_io_unlock(pp);
			page_unlock(pp);
			sw_putbackreq(arg);
			break;
		}
		/* Try to cluster new physical name with previous ones */
		if (klvp == pvp && poff == klstart + klsz) {
			klsz += PAGESIZE;
			page_add(&pplist, pp);
			pplist = pplist->p_next;
			sw_putfree(arg);
		} else if (klvp == pvp && poff == klstart - PAGESIZE) {
			klsz += PAGESIZE;
			klstart -= PAGESIZE;
			page_add(&pplist, pp);
			sw_putfree(arg);
		} else {
			swap_klustfail++;
			swap_klustpages += btop(klsz);
			hat_setmod(pp);
			page_io_unlock(pp);
			page_unlock(pp);
			sw_putbackreq(arg);
			break;
		}
	}

	err = VOP_PAGEIO(klvp, pplist, klstart, klsz,
	    B_WRITE | flags, cr, NULL);

	if ((flags & B_ASYNC) == 0)
		pvn_write_done(pp, ((err) ? B_ERROR : 0) | B_WRITE | flags);

	/* Statistics */
	if (!err) {
		swap_putpagecnt++;
		swap_pagespushed += btop(klsz);
	}
out:
	TRACE_4(TR_FAC_SWAPFS, TR_SWAPFS_PUTAPAGE,
	    "swapfs putapage:vp %p klvp %p, klstart %lx, klsz %lx",
	    vp, klvp, klstart, klsz);
	if (err && err != ENOMEM)
		cmn_err(CE_WARN, "swapfs_putapage: err %d\n", err);
	if (lenp)
		*lenp = PAGESIZE;
	return (err);
}

static void
swap_dispose(
	vnode_t *vp,
	page_t *pp,
	int fl,
	int dn,
	cred_t *cr,
	caller_context_t *ct)
{
	int err;
	u_offset_t off = pp->p_offset;
	vnode_t *pvp;
	u_offset_t poff;

	ASSERT(PAGE_EXCL(pp));

	/*
	 * The caller will free/invalidate large page in one shot instead of
	 * one small page at a time.
	 */
	if (pp->p_szc != 0) {
		page_unlock(pp);
		return;
	}

	err = swap_getphysname(vp, off, &pvp, &poff);
	if (!err && pvp != NULL)
		VOP_DISPOSE(pvp, pp, fl, dn, cr, ct);
	else
		fs_dispose(vp, pp, fl, dn, cr, ct);
}
