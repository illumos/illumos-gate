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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
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

/*
 * VM - segment of a mapped device.
 *
 * This segment driver is used when mapping character special devices.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/sysmacros.h>
#include <sys/vtrace.h>
#include <sys/systm.h>
#include <sys/vmsystm.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/ddidevmap.h>
#include <sys/ddi_implfuncs.h>
#include <sys/lgrp.h>

#include <vm/page.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_dev.h>
#include <vm/seg_kp.h>
#include <vm/seg_kmem.h>
#include <vm/vpage.h>

#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/fs/snode.h>


#if DEBUG
int segdev_debug;
#define	DEBUGF(level, args) { if (segdev_debug >= (level)) cmn_err args; }
#else
#define	DEBUGF(level, args)
#endif

/* Default timeout for devmap context management */
#define	CTX_TIMEOUT_VALUE 0

#define	HOLD_DHP_LOCK(dhp)  if (dhp->dh_flags & DEVMAP_ALLOW_REMAP) \
			{ mutex_enter(&dhp->dh_lock); }

#define	RELE_DHP_LOCK(dhp) if (dhp->dh_flags & DEVMAP_ALLOW_REMAP) \
			{ mutex_exit(&dhp->dh_lock); }

#define	round_down_p2(a, s)	((a) & ~((s) - 1))
#define	round_up_p2(a, s)	(((a) + (s) - 1) & ~((s) - 1))

/*
 * VA_PA_ALIGNED checks to see if both VA and PA are on pgsize boundary
 * VA_PA_PGSIZE_ALIGNED check to see if VA is aligned with PA w.r.t. pgsize
 */
#define	VA_PA_ALIGNED(uvaddr, paddr, pgsize)		\
	(((uvaddr | paddr) & (pgsize - 1)) == 0)
#define	VA_PA_PGSIZE_ALIGNED(uvaddr, paddr, pgsize)	\
	(((uvaddr ^ paddr) & (pgsize - 1)) == 0)

#define	vpgtob(n)	((n) * sizeof (struct vpage))	/* For brevity */

#define	VTOCVP(vp)	(VTOS(vp)->s_commonvp)	/* we "know" it's an snode */

static struct devmap_ctx *devmapctx_list = NULL;
static struct devmap_softlock *devmap_slist = NULL;

/*
 * mutex, vnode and page for the page of zeros we use for the trash mappings.
 * One trash page is allocated on the first ddi_umem_setup call that uses it
 * XXX Eventually, we may want to combine this with what segnf does when all
 * hat layers implement HAT_NOFAULT.
 *
 * The trash page is used when the backing store for a userland mapping is
 * removed but the application semantics do not take kindly to a SIGBUS.
 * In that scenario, the applications pages are mapped to some dummy page
 * which returns garbage on read and writes go into a common place.
 * (Perfect for NO_FAULT semantics)
 * The device driver is responsible to communicating to the app with some
 * other mechanism that such remapping has happened and the app should take
 * corrective action.
 * We can also use an anonymous memory page as there is no requirement to
 * keep the page locked, however this complicates the fault code. RFE.
 */
static struct vnode trashvp;
static struct page *trashpp;

/* Non-pageable kernel memory is allocated from the umem_np_arena. */
static vmem_t *umem_np_arena;

/* Set the cookie to a value we know will never be a valid umem_cookie */
#define	DEVMAP_DEVMEM_COOKIE	((ddi_umem_cookie_t)0x1)

/*
 * Macros to check if type of devmap handle
 */
#define	cookie_is_devmem(c)	\
	((c) == (struct ddi_umem_cookie *)DEVMAP_DEVMEM_COOKIE)

#define	cookie_is_pmem(c)	\
	((c) == (struct ddi_umem_cookie *)DEVMAP_PMEM_COOKIE)

#define	cookie_is_kpmem(c)	(!cookie_is_devmem(c) && !cookie_is_pmem(c) &&\
	((c)->type == KMEM_PAGEABLE))

#define	dhp_is_devmem(dhp)	\
	(cookie_is_devmem((struct ddi_umem_cookie *)((dhp)->dh_cookie)))

#define	dhp_is_pmem(dhp)	\
	(cookie_is_pmem((struct ddi_umem_cookie *)((dhp)->dh_cookie)))

#define	dhp_is_kpmem(dhp)	\
	(cookie_is_kpmem((struct ddi_umem_cookie *)((dhp)->dh_cookie)))

/*
 * Private seg op routines.
 */
static int	segdev_dup(struct seg *, struct seg *);
static int	segdev_unmap(struct seg *, caddr_t, size_t);
static void	segdev_free(struct seg *);
static faultcode_t segdev_fault(struct hat *, struct seg *, caddr_t, size_t,
		    enum fault_type, enum seg_rw);
static faultcode_t segdev_faulta(struct seg *, caddr_t);
static int	segdev_setprot(struct seg *, caddr_t, size_t, uint_t);
static int	segdev_checkprot(struct seg *, caddr_t, size_t, uint_t);
static void	segdev_badop(void);
static int	segdev_sync(struct seg *, caddr_t, size_t, int, uint_t);
static size_t	segdev_incore(struct seg *, caddr_t, size_t, char *);
static int	segdev_lockop(struct seg *, caddr_t, size_t, int, int,
		    ulong_t *, size_t);
static int	segdev_getprot(struct seg *, caddr_t, size_t, uint_t *);
static u_offset_t	segdev_getoffset(struct seg *, caddr_t);
static int	segdev_gettype(struct seg *, caddr_t);
static int	segdev_getvp(struct seg *, caddr_t, struct vnode **);
static int	segdev_advise(struct seg *, caddr_t, size_t, uint_t);
static void	segdev_dump(struct seg *);
static int	segdev_pagelock(struct seg *, caddr_t, size_t,
		    struct page ***, enum lock_type, enum seg_rw);
static int	segdev_setpagesize(struct seg *, caddr_t, size_t, uint_t);
static int	segdev_getmemid(struct seg *, caddr_t, memid_t *);
static lgrp_mem_policy_info_t	*segdev_getpolicy(struct seg *, caddr_t);
static int	segdev_capable(struct seg *, segcapability_t);

/*
 * XXX	this struct is used by rootnex_map_fault to identify
 *	the segment it has been passed. So if you make it
 *	"static" you'll need to fix rootnex_map_fault.
 */
struct seg_ops segdev_ops = {
	segdev_dup,
	segdev_unmap,
	segdev_free,
	segdev_fault,
	segdev_faulta,
	segdev_setprot,
	segdev_checkprot,
	(int (*)())segdev_badop,	/* kluster */
	(size_t (*)(struct seg *))NULL,	/* swapout */
	segdev_sync,			/* sync */
	segdev_incore,
	segdev_lockop,			/* lockop */
	segdev_getprot,
	segdev_getoffset,
	segdev_gettype,
	segdev_getvp,
	segdev_advise,
	segdev_dump,
	segdev_pagelock,
	segdev_setpagesize,
	segdev_getmemid,
	segdev_getpolicy,
	segdev_capable,
	seg_inherit_notsup
};

/*
 * Private segdev support routines
 */
static struct segdev_data *sdp_alloc(void);

static void segdev_softunlock(struct hat *, struct seg *, caddr_t,
    size_t, enum seg_rw);

static faultcode_t segdev_faultpage(struct hat *, struct seg *, caddr_t,
    struct vpage *, enum fault_type, enum seg_rw, devmap_handle_t *);

static faultcode_t segdev_faultpages(struct hat *, struct seg *, caddr_t,
    size_t, enum fault_type, enum seg_rw, devmap_handle_t *);

static struct devmap_ctx *devmap_ctxinit(dev_t, ulong_t);
static struct devmap_softlock *devmap_softlock_init(dev_t, ulong_t);
static void devmap_softlock_rele(devmap_handle_t *);
static void devmap_ctx_rele(devmap_handle_t *);

static void devmap_ctxto(void *);

static devmap_handle_t *devmap_find_handle(devmap_handle_t *dhp_head,
    caddr_t addr);

static ulong_t devmap_roundup(devmap_handle_t *dhp, ulong_t offset, size_t len,
    ulong_t *opfn, ulong_t *pagesize);

static void free_devmap_handle(devmap_handle_t *dhp);

static int devmap_handle_dup(devmap_handle_t *dhp, devmap_handle_t **new_dhp,
    struct seg *newseg);

static devmap_handle_t *devmap_handle_unmap(devmap_handle_t *dhp);

static void devmap_handle_unmap_head(devmap_handle_t *dhp, size_t len);

static void devmap_handle_unmap_tail(devmap_handle_t *dhp, caddr_t addr);

static int devmap_device(devmap_handle_t *dhp, struct as *as, caddr_t *addr,
    offset_t off, size_t len, uint_t flags);

static void devmap_get_large_pgsize(devmap_handle_t *dhp, size_t len,
    caddr_t addr, size_t *llen, caddr_t *laddr);

static void devmap_handle_reduce_len(devmap_handle_t *dhp, size_t len);

static void *devmap_alloc_pages(vmem_t *vmp, size_t size, int vmflag);
static void devmap_free_pages(vmem_t *vmp, void *inaddr, size_t size);

static void *devmap_umem_alloc_np(size_t size, size_t flags);
static void devmap_umem_free_np(void *addr, size_t size);

/*
 * routines to lock and unlock underlying segkp segment for
 * KMEM_PAGEABLE type cookies.
 */
static faultcode_t  acquire_kpmem_lock(struct ddi_umem_cookie *, size_t);
static void release_kpmem_lock(struct ddi_umem_cookie *, size_t);

/*
 * Routines to synchronize F_SOFTLOCK and F_INVAL faults for
 * drivers with devmap_access callbacks
 */
static int devmap_softlock_enter(struct devmap_softlock *, size_t,
	enum fault_type);
static void devmap_softlock_exit(struct devmap_softlock *, size_t,
	enum fault_type);

static kmutex_t devmapctx_lock;

static kmutex_t devmap_slock;

/*
 * Initialize the thread callbacks and thread private data.
 */
static struct devmap_ctx *
devmap_ctxinit(dev_t dev, ulong_t id)
{
	struct devmap_ctx	*devctx;
	struct devmap_ctx	*tmp;
	dev_info_t		*dip;

	tmp =  kmem_zalloc(sizeof (struct devmap_ctx), KM_SLEEP);

	mutex_enter(&devmapctx_lock);

	dip = e_ddi_hold_devi_by_dev(dev, 0);
	ASSERT(dip != NULL);
	ddi_release_devi(dip);

	for (devctx = devmapctx_list; devctx != NULL; devctx = devctx->next)
		if ((devctx->dip == dip) && (devctx->id == id))
			break;

	if (devctx == NULL) {
		devctx = tmp;
		devctx->dip = dip;
		devctx->id = id;
		mutex_init(&devctx->lock, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&devctx->cv, NULL, CV_DEFAULT, NULL);
		devctx->next = devmapctx_list;
		devmapctx_list = devctx;
	} else
		kmem_free(tmp, sizeof (struct devmap_ctx));

	mutex_enter(&devctx->lock);
	devctx->refcnt++;
	mutex_exit(&devctx->lock);
	mutex_exit(&devmapctx_lock);

	return (devctx);
}

/*
 * Timeout callback called if a CPU has not given up the device context
 * within dhp->dh_timeout_length ticks
 */
static void
devmap_ctxto(void *data)
{
	struct devmap_ctx *devctx = data;

	TRACE_1(TR_FAC_DEVMAP, TR_DEVMAP_CTXTO,
	    "devmap_ctxto:timeout expired, devctx=%p", (void *)devctx);
	mutex_enter(&devctx->lock);
	/*
	 * Set oncpu = 0 so the next mapping trying to get the device context
	 * can.
	 */
	devctx->oncpu = 0;
	devctx->timeout = 0;
	cv_signal(&devctx->cv);
	mutex_exit(&devctx->lock);
}

/*
 * Create a device segment.
 */
int
segdev_create(struct seg *seg, void *argsp)
{
	struct segdev_data *sdp;
	struct segdev_crargs *a = (struct segdev_crargs *)argsp;
	devmap_handle_t *dhp = (devmap_handle_t *)a->devmap_data;
	int error;

	/*
	 * Since the address space is "write" locked, we
	 * don't need the segment lock to protect "segdev" data.
	 */
	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as, &seg->s_as->a_lock));

	hat_map(seg->s_as->a_hat, seg->s_base, seg->s_size, HAT_MAP);

	sdp = sdp_alloc();

	sdp->mapfunc = a->mapfunc;
	sdp->offset = a->offset;
	sdp->prot = a->prot;
	sdp->maxprot = a->maxprot;
	sdp->type = a->type;
	sdp->pageprot = 0;
	sdp->softlockcnt = 0;
	sdp->vpage = NULL;

	if (sdp->mapfunc == NULL)
		sdp->devmap_data = dhp;
	else
		sdp->devmap_data = dhp = NULL;

	sdp->hat_flags = a->hat_flags;
	sdp->hat_attr = a->hat_attr;

	/*
	 * Currently, hat_flags supports only HAT_LOAD_NOCONSIST
	 */
	ASSERT(!(sdp->hat_flags & ~HAT_LOAD_NOCONSIST));

	/*
	 * Hold shadow vnode -- segdev only deals with
	 * character (VCHR) devices. We use the common
	 * vp to hang pages on.
	 */
	sdp->vp = specfind(a->dev, VCHR);
	ASSERT(sdp->vp != NULL);

	seg->s_ops = &segdev_ops;
	seg->s_data = sdp;

	while (dhp != NULL) {
		dhp->dh_seg = seg;
		dhp = dhp->dh_next;
	}

	/*
	 * Inform the vnode of the new mapping.
	 */
	/*
	 * It is ok to use pass sdp->maxprot to ADDMAP rather than to use
	 * dhp specific maxprot because spec_addmap does not use maxprot.
	 */
	error = VOP_ADDMAP(VTOCVP(sdp->vp), sdp->offset,
	    seg->s_as, seg->s_base, seg->s_size,
	    sdp->prot, sdp->maxprot, sdp->type, CRED(), NULL);

	if (error != 0) {
		sdp->devmap_data = NULL;
		hat_unload(seg->s_as->a_hat, seg->s_base, seg->s_size,
		    HAT_UNLOAD_UNMAP);
	} else {
		/*
		 * Mappings of /dev/null don't count towards the VSZ of a
		 * process.  Mappings of /dev/null have no mapping type.
		 */
		if ((SEGOP_GETTYPE(seg, (seg)->s_base) & (MAP_SHARED |
		    MAP_PRIVATE)) == 0) {
			seg->s_as->a_resvsize -= seg->s_size;
		}
	}

	return (error);
}

static struct segdev_data *
sdp_alloc(void)
{
	struct segdev_data *sdp;

	sdp = kmem_zalloc(sizeof (struct segdev_data), KM_SLEEP);
	rw_init(&sdp->lock, NULL, RW_DEFAULT, NULL);

	return (sdp);
}

/*
 * Duplicate seg and return new segment in newseg.
 */
static int
segdev_dup(struct seg *seg, struct seg *newseg)
{
	struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	struct segdev_data *newsdp;
	devmap_handle_t *dhp = (devmap_handle_t *)sdp->devmap_data;
	size_t npages;
	int ret;

	TRACE_2(TR_FAC_DEVMAP, TR_DEVMAP_DUP,
	    "segdev_dup:start dhp=%p, seg=%p", (void *)dhp, (void *)seg);

	DEBUGF(3, (CE_CONT, "segdev_dup: dhp %p seg %p\n",
	    (void *)dhp, (void *)seg));

	/*
	 * Since the address space is "write" locked, we
	 * don't need the segment lock to protect "segdev" data.
	 */
	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as, &seg->s_as->a_lock));

	newsdp = sdp_alloc();

	newseg->s_ops = seg->s_ops;
	newseg->s_data = (void *)newsdp;

	VN_HOLD(sdp->vp);
	newsdp->vp 	= sdp->vp;
	newsdp->mapfunc = sdp->mapfunc;
	newsdp->offset	= sdp->offset;
	newsdp->pageprot = sdp->pageprot;
	newsdp->prot	= sdp->prot;
	newsdp->maxprot = sdp->maxprot;
	newsdp->type = sdp->type;
	newsdp->hat_attr = sdp->hat_attr;
	newsdp->hat_flags = sdp->hat_flags;
	newsdp->softlockcnt = 0;

	/*
	 * Initialize per page data if the segment we are
	 * dup'ing has per page information.
	 */
	npages = seg_pages(newseg);

	if (sdp->vpage != NULL) {
		size_t nbytes = vpgtob(npages);

		newsdp->vpage = kmem_zalloc(nbytes, KM_SLEEP);
		bcopy(sdp->vpage, newsdp->vpage, nbytes);
	} else
		newsdp->vpage = NULL;

	/*
	 * duplicate devmap handles
	 */
	if (dhp != NULL) {
		ret = devmap_handle_dup(dhp,
		    (devmap_handle_t **)&newsdp->devmap_data, newseg);
		if (ret != 0) {
			TRACE_3(TR_FAC_DEVMAP, TR_DEVMAP_DUP_CK1,
			    "segdev_dup:ret1 ret=%x, dhp=%p seg=%p",
			    ret, (void *)dhp, (void *)seg);
			DEBUGF(1, (CE_CONT,
			    "segdev_dup: ret %x dhp %p seg %p\n",
			    ret, (void *)dhp, (void *)seg));
			return (ret);
		}
	}

	/*
	 * Inform the common vnode of the new mapping.
	 */
	return (VOP_ADDMAP(VTOCVP(newsdp->vp),
	    newsdp->offset, newseg->s_as,
	    newseg->s_base, newseg->s_size, newsdp->prot,
	    newsdp->maxprot, sdp->type, CRED(), NULL));
}

/*
 * duplicate devmap handles
 */
static int
devmap_handle_dup(devmap_handle_t *dhp, devmap_handle_t **new_dhp,
    struct seg *newseg)
{
	devmap_handle_t *newdhp_save = NULL;
	devmap_handle_t *newdhp = NULL;
	struct devmap_callback_ctl *callbackops;

	while (dhp != NULL) {
		newdhp = kmem_alloc(sizeof (devmap_handle_t), KM_SLEEP);

		/* Need to lock the original dhp while copying if REMAP */
		HOLD_DHP_LOCK(dhp);
		bcopy(dhp, newdhp, sizeof (devmap_handle_t));
		RELE_DHP_LOCK(dhp);
		newdhp->dh_seg = newseg;
		newdhp->dh_next = NULL;
		if (newdhp_save != NULL)
			newdhp_save->dh_next = newdhp;
		else
			*new_dhp = newdhp;
		newdhp_save = newdhp;

		callbackops = &newdhp->dh_callbackops;

		if (dhp->dh_softlock != NULL)
			newdhp->dh_softlock = devmap_softlock_init(
			    newdhp->dh_dev,
			    (ulong_t)callbackops->devmap_access);
		if (dhp->dh_ctx != NULL)
			newdhp->dh_ctx = devmap_ctxinit(newdhp->dh_dev,
			    (ulong_t)callbackops->devmap_access);

		/*
		 * Initialize dh_lock if we want to do remap.
		 */
		if (newdhp->dh_flags & DEVMAP_ALLOW_REMAP) {
			mutex_init(&newdhp->dh_lock, NULL, MUTEX_DEFAULT, NULL);
			newdhp->dh_flags |= DEVMAP_LOCK_INITED;
		}

		if (callbackops->devmap_dup != NULL) {
			int ret;

			/*
			 * Call the dup callback so that the driver can
			 * duplicate its private data.
			 */
			ret = (*callbackops->devmap_dup)(dhp, dhp->dh_pvtp,
			    (devmap_cookie_t *)newdhp, &newdhp->dh_pvtp);

			if (ret != 0) {
				/*
				 * We want to free up this segment as the driver
				 * has indicated that we can't dup it.  But we
				 * don't want to call the drivers, devmap_unmap,
				 * callback function as the driver does not
				 * think this segment exists. The caller of
				 * devmap_dup will call seg_free on newseg
				 * as it was the caller that allocated the
				 * segment.
				 */
				DEBUGF(1, (CE_CONT, "devmap_handle_dup ERROR: "
				    "newdhp %p dhp %p\n", (void *)newdhp,
				    (void *)dhp));
				callbackops->devmap_unmap = NULL;
				return (ret);
			}
		}

		dhp = dhp->dh_next;
	}

	return (0);
}

/*
 * Split a segment at addr for length len.
 */
/*ARGSUSED*/
static int
segdev_unmap(struct seg *seg, caddr_t addr, size_t len)
{
	register struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	register struct segdev_data *nsdp;
	register struct seg *nseg;
	register size_t	opages;		/* old segment size in pages */
	register size_t	npages;		/* new segment size in pages */
	register size_t	dpages;		/* pages being deleted (unmapped) */
	register size_t	nbytes;
	devmap_handle_t *dhp = (devmap_handle_t *)sdp->devmap_data;
	devmap_handle_t *dhpp;
	devmap_handle_t *newdhp;
	struct devmap_callback_ctl *callbackops;
	caddr_t nbase;
	offset_t off;
	ulong_t nsize;
	size_t mlen, sz;

	TRACE_4(TR_FAC_DEVMAP, TR_DEVMAP_UNMAP,
	    "segdev_unmap:start dhp=%p, seg=%p addr=%p len=%lx",
	    (void *)dhp, (void *)seg, (void *)addr, len);

	DEBUGF(3, (CE_CONT, "segdev_unmap: dhp %p seg %p addr %p len %lx\n",
	    (void *)dhp, (void *)seg, (void *)addr, len));

	/*
	 * Since the address space is "write" locked, we
	 * don't need the segment lock to protect "segdev" data.
	 */
	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as, &seg->s_as->a_lock));

	if ((sz = sdp->softlockcnt) > 0) {
		/*
		 * Fail the unmap if pages are SOFTLOCKed through this mapping.
		 * softlockcnt is protected from change by the as write lock.
		 */
		TRACE_1(TR_FAC_DEVMAP, TR_DEVMAP_UNMAP_CK1,
		    "segdev_unmap:error softlockcnt = %ld", sz);
		DEBUGF(1, (CE_CONT, "segdev_unmap: softlockcnt %ld\n", sz));
		return (EAGAIN);
	}

	/*
	 * Check for bad sizes
	 */
	if (addr < seg->s_base || addr + len > seg->s_base + seg->s_size ||
	    (len & PAGEOFFSET) || ((uintptr_t)addr & PAGEOFFSET))
		panic("segdev_unmap");

	if (dhp != NULL) {
		devmap_handle_t *tdhp;
		/*
		 * If large page size was used in hat_devload(),
		 * the same page size must be used in hat_unload().
		 */
		dhpp = tdhp = devmap_find_handle(dhp, addr);
		while (tdhp != NULL) {
			if (tdhp->dh_flags & DEVMAP_FLAG_LARGE) {
				break;
			}
			tdhp = tdhp->dh_next;
		}
		if (tdhp != NULL) {	/* found a dhp using large pages */
			size_t slen = len;
			size_t mlen;
			size_t soff;

			soff = (ulong_t)(addr - dhpp->dh_uvaddr);
			while (slen != 0) {
				mlen = MIN(slen, (dhpp->dh_len - soff));
				hat_unload(seg->s_as->a_hat, dhpp->dh_uvaddr,
				    dhpp->dh_len, HAT_UNLOAD_UNMAP);
				dhpp = dhpp->dh_next;
				ASSERT(slen >= mlen);
				slen -= mlen;
				soff = 0;
			}
		} else
			hat_unload(seg->s_as->a_hat, addr, len,
			    HAT_UNLOAD_UNMAP);
	} else {
		/*
		 * Unload any hardware translations in the range
		 * to be taken out.
		 */
		hat_unload(seg->s_as->a_hat, addr, len, HAT_UNLOAD_UNMAP);
	}

	/*
	 * get the user offset which will used in the driver callbacks
	 */
	off = sdp->offset + (offset_t)(addr - seg->s_base);

	/*
	 * Inform the vnode of the unmapping.
	 */
	ASSERT(sdp->vp != NULL);
	(void) VOP_DELMAP(VTOCVP(sdp->vp), off, seg->s_as, addr, len,
	    sdp->prot, sdp->maxprot, sdp->type, CRED(), NULL);

	/*
	 * Check for entire segment
	 */
	if (addr == seg->s_base && len == seg->s_size) {
		seg_free(seg);
		return (0);
	}

	opages = seg_pages(seg);
	dpages = btop(len);
	npages = opages - dpages;

	/*
	 * Check for beginning of segment
	 */
	if (addr == seg->s_base) {
		if (sdp->vpage != NULL) {
			register struct vpage *ovpage;

			ovpage = sdp->vpage;	/* keep pointer to vpage */

			nbytes = vpgtob(npages);
			sdp->vpage = kmem_alloc(nbytes, KM_SLEEP);
			bcopy(&ovpage[dpages], sdp->vpage, nbytes);

			/* free up old vpage */
			kmem_free(ovpage, vpgtob(opages));
		}

		/*
		 * free devmap handles from the beginning of the mapping.
		 */
		if (dhp != NULL)
			devmap_handle_unmap_head(dhp, len);

		sdp->offset += (offset_t)len;

		seg->s_base += len;
		seg->s_size -= len;

		return (0);
	}

	/*
	 * Check for end of segment
	 */
	if (addr + len == seg->s_base + seg->s_size) {
		if (sdp->vpage != NULL) {
			register struct vpage *ovpage;

			ovpage = sdp->vpage;	/* keep pointer to vpage */

			nbytes = vpgtob(npages);
			sdp->vpage = kmem_alloc(nbytes, KM_SLEEP);
			bcopy(ovpage, sdp->vpage, nbytes);

			/* free up old vpage */
			kmem_free(ovpage, vpgtob(opages));
		}
		seg->s_size -= len;

		/*
		 * free devmap handles from addr to the end of the mapping.
		 */
		if (dhp != NULL)
			devmap_handle_unmap_tail(dhp, addr);

		return (0);
	}

	/*
	 * The section to go is in the middle of the segment,
	 * have to make it into two segments.  nseg is made for
	 * the high end while seg is cut down at the low end.
	 */
	nbase = addr + len;				/* new seg base */
	nsize = (seg->s_base + seg->s_size) - nbase;	/* new seg size */
	seg->s_size = addr - seg->s_base;		/* shrink old seg */
	nseg = seg_alloc(seg->s_as, nbase, nsize);
	if (nseg == NULL)
		panic("segdev_unmap seg_alloc");

	TRACE_2(TR_FAC_DEVMAP, TR_DEVMAP_UNMAP_CK2,
	    "segdev_unmap: seg=%p nseg=%p", (void *)seg, (void *)nseg);
	DEBUGF(3, (CE_CONT, "segdev_unmap: segdev_dup seg %p nseg %p\n",
	    (void *)seg, (void *)nseg));
	nsdp = sdp_alloc();

	nseg->s_ops = seg->s_ops;
	nseg->s_data = (void *)nsdp;

	VN_HOLD(sdp->vp);
	nsdp->mapfunc = sdp->mapfunc;
	nsdp->offset = sdp->offset + (offset_t)(nseg->s_base - seg->s_base);
	nsdp->vp 	= sdp->vp;
	nsdp->pageprot = sdp->pageprot;
	nsdp->prot	= sdp->prot;
	nsdp->maxprot = sdp->maxprot;
	nsdp->type = sdp->type;
	nsdp->hat_attr = sdp->hat_attr;
	nsdp->hat_flags = sdp->hat_flags;
	nsdp->softlockcnt = 0;

	/*
	 * Initialize per page data if the segment we are
	 * dup'ing has per page information.
	 */
	if (sdp->vpage != NULL) {
		/* need to split vpage into two arrays */
		register size_t nnbytes;
		register size_t nnpages;
		register struct vpage *ovpage;

		ovpage = sdp->vpage;		/* keep pointer to vpage */

		npages = seg_pages(seg);	/* seg has shrunk */
		nbytes = vpgtob(npages);
		nnpages = seg_pages(nseg);
		nnbytes = vpgtob(nnpages);

		sdp->vpage = kmem_alloc(nbytes, KM_SLEEP);
		bcopy(ovpage, sdp->vpage, nbytes);

		nsdp->vpage = kmem_alloc(nnbytes, KM_SLEEP);
		bcopy(&ovpage[npages + dpages], nsdp->vpage, nnbytes);

		/* free up old vpage */
		kmem_free(ovpage, vpgtob(opages));
	} else
		nsdp->vpage = NULL;

	/*
	 * unmap dhps.
	 */
	if (dhp == NULL) {
		nsdp->devmap_data = NULL;
		return (0);
	}
	while (dhp != NULL) {
		callbackops = &dhp->dh_callbackops;
		TRACE_2(TR_FAC_DEVMAP, TR_DEVMAP_UNMAP_CK3,
		    "segdev_unmap: dhp=%p addr=%p", dhp, addr);
		DEBUGF(3, (CE_CONT, "unmap: dhp %p addr %p uvaddr %p len %lx\n",
		    (void *)dhp, (void *)addr,
		    (void *)dhp->dh_uvaddr, dhp->dh_len));

		if (addr == (dhp->dh_uvaddr + dhp->dh_len)) {
			dhpp = dhp->dh_next;
			dhp->dh_next = NULL;
			dhp = dhpp;
		} else if (addr > (dhp->dh_uvaddr + dhp->dh_len)) {
			dhp = dhp->dh_next;
		} else if (addr > dhp->dh_uvaddr &&
		    (addr + len) < (dhp->dh_uvaddr + dhp->dh_len)) {
			/*
			 * <addr, addr+len> is enclosed by dhp.
			 * create a newdhp that begins at addr+len and
			 * ends at dhp->dh_uvaddr+dhp->dh_len.
			 */
			newdhp = kmem_alloc(sizeof (devmap_handle_t), KM_SLEEP);
			HOLD_DHP_LOCK(dhp);
			bcopy(dhp, newdhp, sizeof (devmap_handle_t));
			RELE_DHP_LOCK(dhp);
			newdhp->dh_seg = nseg;
			newdhp->dh_next = dhp->dh_next;
			if (dhp->dh_softlock != NULL)
				newdhp->dh_softlock = devmap_softlock_init(
				    newdhp->dh_dev,
				    (ulong_t)callbackops->devmap_access);
			if (dhp->dh_ctx != NULL)
				newdhp->dh_ctx = devmap_ctxinit(newdhp->dh_dev,
				    (ulong_t)callbackops->devmap_access);
			if (newdhp->dh_flags & DEVMAP_LOCK_INITED) {
				mutex_init(&newdhp->dh_lock,
				    NULL, MUTEX_DEFAULT, NULL);
			}
			if (callbackops->devmap_unmap != NULL)
				(*callbackops->devmap_unmap)(dhp, dhp->dh_pvtp,
				    off, len, dhp, &dhp->dh_pvtp,
				    newdhp, &newdhp->dh_pvtp);
			mlen = len + (addr - dhp->dh_uvaddr);
			devmap_handle_reduce_len(newdhp, mlen);
			nsdp->devmap_data = newdhp;
			/* XX Changing len should recalculate LARGE flag */
			dhp->dh_len = addr - dhp->dh_uvaddr;
			dhpp = dhp->dh_next;
			dhp->dh_next = NULL;
			dhp = dhpp;
		} else if ((addr > dhp->dh_uvaddr) &&
		    ((addr + len) >= (dhp->dh_uvaddr + dhp->dh_len))) {
			mlen = dhp->dh_len + dhp->dh_uvaddr - addr;
			/*
			 * <addr, addr+len> spans over dhps.
			 */
			if (callbackops->devmap_unmap != NULL)
				(*callbackops->devmap_unmap)(dhp, dhp->dh_pvtp,
				    off, mlen, (devmap_cookie_t *)dhp,
				    &dhp->dh_pvtp, NULL, NULL);
			/* XX Changing len should recalculate LARGE flag */
			dhp->dh_len = addr - dhp->dh_uvaddr;
			dhpp = dhp->dh_next;
			dhp->dh_next = NULL;
			dhp = dhpp;
			nsdp->devmap_data = dhp;
		} else if ((addr + len) >= (dhp->dh_uvaddr + dhp->dh_len)) {
			/*
			 * dhp is enclosed by <addr, addr+len>.
			 */
			dhp->dh_seg = nseg;
			nsdp->devmap_data = dhp;
			dhp = devmap_handle_unmap(dhp);
			nsdp->devmap_data = dhp; /* XX redundant? */
		} else if (((addr + len) > dhp->dh_uvaddr) &&
		    ((addr + len) < (dhp->dh_uvaddr + dhp->dh_len))) {
			mlen = addr + len - dhp->dh_uvaddr;
			if (callbackops->devmap_unmap != NULL)
				(*callbackops->devmap_unmap)(dhp, dhp->dh_pvtp,
				    dhp->dh_uoff, mlen, NULL,
				    NULL, dhp, &dhp->dh_pvtp);
			devmap_handle_reduce_len(dhp, mlen);
			nsdp->devmap_data = dhp;
			dhp->dh_seg = nseg;
			dhp = dhp->dh_next;
		} else {
			dhp->dh_seg = nseg;
			dhp = dhp->dh_next;
		}
	}
	return (0);
}

/*
 * Utility function handles reducing the length of a devmap handle during unmap
 * Note that is only used for unmapping the front portion of the handler,
 * i.e., we are bumping up the offset/pfn etc up by len
 * Do not use if reducing length at the tail.
 */
static void
devmap_handle_reduce_len(devmap_handle_t *dhp, size_t len)
{
	struct ddi_umem_cookie *cp;
	struct devmap_pmem_cookie *pcp;
	/*
	 * adjust devmap handle fields
	 */
	ASSERT(len < dhp->dh_len);

	/* Make sure only page-aligned changes are done */
	ASSERT((len & PAGEOFFSET) == 0);

	dhp->dh_len -= len;
	dhp->dh_uoff += (offset_t)len;
	dhp->dh_roff += (offset_t)len;
	dhp->dh_uvaddr += len;
	/* Need to grab dhp lock if REMAP */
	HOLD_DHP_LOCK(dhp);
	cp = dhp->dh_cookie;
	if (!(dhp->dh_flags & DEVMAP_MAPPING_INVALID)) {
		if (cookie_is_devmem(cp)) {
			dhp->dh_pfn += btop(len);
		} else if (cookie_is_pmem(cp)) {
			pcp = (struct devmap_pmem_cookie *)dhp->dh_pcookie;
			ASSERT((dhp->dh_roff & PAGEOFFSET) == 0 &&
			    dhp->dh_roff < ptob(pcp->dp_npages));
		} else {
			ASSERT(dhp->dh_roff < cp->size);
			ASSERT(dhp->dh_cvaddr >= cp->cvaddr &&
			    dhp->dh_cvaddr < (cp->cvaddr + cp->size));
			ASSERT((dhp->dh_cvaddr + len) <=
			    (cp->cvaddr + cp->size));

			dhp->dh_cvaddr += len;
		}
	}
	/* XXX - Should recalculate the DEVMAP_FLAG_LARGE after changes */
	RELE_DHP_LOCK(dhp);
}

/*
 * Free devmap handle, dhp.
 * Return the next devmap handle on the linked list.
 */
static devmap_handle_t *
devmap_handle_unmap(devmap_handle_t *dhp)
{
	struct devmap_callback_ctl *callbackops = &dhp->dh_callbackops;
	struct segdev_data *sdp = (struct segdev_data *)dhp->dh_seg->s_data;
	devmap_handle_t *dhpp = (devmap_handle_t *)sdp->devmap_data;

	ASSERT(dhp != NULL);

	/*
	 * before we free up dhp, call the driver's devmap_unmap entry point
	 * to free resources allocated for this dhp.
	 */
	if (callbackops->devmap_unmap != NULL) {
		(*callbackops->devmap_unmap)(dhp, dhp->dh_pvtp, dhp->dh_uoff,
		    dhp->dh_len, NULL, NULL, NULL, NULL);
	}

	if (dhpp == dhp) {	/* releasing first dhp, change sdp data */
		sdp->devmap_data = dhp->dh_next;
	} else {
		while (dhpp->dh_next != dhp) {
			dhpp = dhpp->dh_next;
		}
		dhpp->dh_next = dhp->dh_next;
	}
	dhpp = dhp->dh_next;	/* return value is next dhp in chain */

	if (dhp->dh_softlock != NULL)
		devmap_softlock_rele(dhp);

	if (dhp->dh_ctx != NULL)
		devmap_ctx_rele(dhp);

	if (dhp->dh_flags & DEVMAP_LOCK_INITED) {
		mutex_destroy(&dhp->dh_lock);
	}
	kmem_free(dhp, sizeof (devmap_handle_t));

	return (dhpp);
}

/*
 * Free complete devmap handles from dhp for len bytes
 * dhp can be either the first handle or a subsequent handle
 */
static void
devmap_handle_unmap_head(devmap_handle_t *dhp, size_t len)
{
	struct devmap_callback_ctl *callbackops;

	/*
	 * free the devmap handles covered by len.
	 */
	while (len >= dhp->dh_len) {
		len -= dhp->dh_len;
		dhp = devmap_handle_unmap(dhp);
	}
	if (len != 0) {	/* partial unmap at head of first remaining dhp */
		callbackops = &dhp->dh_callbackops;

		/*
		 * Call the unmap callback so the drivers can make
		 * adjustment on its private data.
		 */
		if (callbackops->devmap_unmap != NULL)
			(*callbackops->devmap_unmap)(dhp, dhp->dh_pvtp,
			    dhp->dh_uoff, len, NULL, NULL, dhp, &dhp->dh_pvtp);
		devmap_handle_reduce_len(dhp, len);
	}
}

/*
 * Free devmap handles to truncate  the mapping after addr
 * RFE: Simpler to pass in dhp pointing at correct dhp (avoid find again)
 *	Also could then use the routine in middle unmap case too
 */
static void
devmap_handle_unmap_tail(devmap_handle_t *dhp, caddr_t addr)
{
	register struct seg *seg = dhp->dh_seg;
	register struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	register devmap_handle_t *dhph = (devmap_handle_t *)sdp->devmap_data;
	struct devmap_callback_ctl *callbackops;
	register devmap_handle_t *dhpp;
	size_t maplen;
	ulong_t off;
	size_t len;

	maplen = (size_t)(addr - dhp->dh_uvaddr);
	dhph = devmap_find_handle(dhph, addr);

	while (dhph != NULL) {
		if (maplen == 0) {
			dhph =  devmap_handle_unmap(dhph);
		} else {
			callbackops = &dhph->dh_callbackops;
			len = dhph->dh_len - maplen;
			off = (ulong_t)sdp->offset + (addr - seg->s_base);
			/*
			 * Call the unmap callback so the driver
			 * can make adjustments on its private data.
			 */
			if (callbackops->devmap_unmap != NULL)
				(*callbackops->devmap_unmap)(dhph,
				    dhph->dh_pvtp, off, len,
				    (devmap_cookie_t *)dhph,
				    &dhph->dh_pvtp, NULL, NULL);
			/* XXX Reducing len needs to recalculate LARGE flag */
			dhph->dh_len = maplen;
			maplen = 0;
			dhpp = dhph->dh_next;
			dhph->dh_next = NULL;
			dhph = dhpp;
		}
	} /* end while */
}

/*
 * Free a segment.
 */
static void
segdev_free(struct seg *seg)
{
	register struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	devmap_handle_t *dhp = (devmap_handle_t *)sdp->devmap_data;

	TRACE_2(TR_FAC_DEVMAP, TR_DEVMAP_FREE,
	    "segdev_free: dhp=%p seg=%p", (void *)dhp, (void *)seg);
	DEBUGF(3, (CE_CONT, "segdev_free: dhp %p seg %p\n",
	    (void *)dhp, (void *)seg));

	/*
	 * Since the address space is "write" locked, we
	 * don't need the segment lock to protect "segdev" data.
	 */
	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as, &seg->s_as->a_lock));

	while (dhp != NULL)
		dhp = devmap_handle_unmap(dhp);

	VN_RELE(sdp->vp);
	if (sdp->vpage != NULL)
		kmem_free(sdp->vpage, vpgtob(seg_pages(seg)));

	rw_destroy(&sdp->lock);
	kmem_free(sdp, sizeof (*sdp));
}

static void
free_devmap_handle(devmap_handle_t *dhp)
{
	register devmap_handle_t *dhpp;

	/*
	 * free up devmap handle
	 */
	while (dhp != NULL) {
		dhpp = dhp->dh_next;
		if (dhp->dh_flags & DEVMAP_LOCK_INITED) {
			mutex_destroy(&dhp->dh_lock);
		}

		if (dhp->dh_softlock != NULL)
			devmap_softlock_rele(dhp);

		if (dhp->dh_ctx != NULL)
			devmap_ctx_rele(dhp);

		kmem_free(dhp, sizeof (devmap_handle_t));
		dhp = dhpp;
	}
}

/*
 * routines to lock and unlock underlying segkp segment for
 * KMEM_PAGEABLE type cookies.
 * segkp only allows a single pending F_SOFTLOCK
 * we keep track of number of locks in the cookie so we can
 * have multiple pending faults and manage the calls to segkp.
 * RFE: if segkp supports either pagelock or can support multiple
 * calls to F_SOFTLOCK, then these routines can go away.
 *	If pagelock, segdev_faultpage can fault on a page by page basis
 *		and simplifies the code quite a bit.
 *	if multiple calls allowed but not partial ranges, then need for
 *	cookie->lock and locked count goes away, code can call as_fault directly
 */
static faultcode_t
acquire_kpmem_lock(struct ddi_umem_cookie *cookie, size_t npages)
{
	int err = 0;
	ASSERT(cookie_is_kpmem(cookie));
	/*
	 * Fault in pages in segkp with F_SOFTLOCK.
	 * We want to hold the lock until all pages have been loaded.
	 * segkp only allows single caller to hold SOFTLOCK, so cookie
	 * holds a count so we dont call into segkp multiple times
	 */
	mutex_enter(&cookie->lock);

	/*
	 * Check for overflow in locked field
	 */
	if ((UINT32_MAX - cookie->locked) < npages) {
		err = FC_MAKE_ERR(ENOMEM);
	} else if (cookie->locked == 0) {
		/* First time locking */
		err = as_fault(kas.a_hat, &kas, cookie->cvaddr,
		    cookie->size, F_SOFTLOCK, PROT_READ|PROT_WRITE);
	}
	if (!err) {
		cookie->locked += npages;
	}
	mutex_exit(&cookie->lock);
	return (err);
}

static void
release_kpmem_lock(struct ddi_umem_cookie *cookie, size_t npages)
{
	mutex_enter(&cookie->lock);
	ASSERT(cookie_is_kpmem(cookie));
	ASSERT(cookie->locked >= npages);
	cookie->locked -= (uint_t)npages;
	if (cookie->locked == 0) {
		/* Last unlock */
		if (as_fault(kas.a_hat, &kas, cookie->cvaddr,
		    cookie->size, F_SOFTUNLOCK, PROT_READ|PROT_WRITE))
			panic("segdev releasing kpmem lock %p", (void *)cookie);
	}
	mutex_exit(&cookie->lock);
}

/*
 * Routines to synchronize F_SOFTLOCK and F_INVAL faults for
 * drivers with devmap_access callbacks
 * slock->softlocked basically works like a rw lock
 *	-ve counts => F_SOFTLOCK in progress
 *	+ve counts => F_INVAL/F_PROT in progress
 * We allow only one F_SOFTLOCK at a time
 * but can have multiple pending F_INVAL/F_PROT calls
 *
 * This routine waits using cv_wait_sig so killing processes is more graceful
 * Returns EINTR if coming out of this routine due to a signal, 0 otherwise
 */
static int devmap_softlock_enter(
	struct devmap_softlock *slock,
	size_t npages,
	enum fault_type type)
{
	if (npages == 0)
		return (0);
	mutex_enter(&(slock->lock));
	switch (type) {
	case F_SOFTLOCK :
		while (slock->softlocked) {
			if (cv_wait_sig(&(slock)->cv, &(slock)->lock) == 0) {
				/* signalled */
				mutex_exit(&(slock->lock));
				return (EINTR);
			}
		}
		slock->softlocked -= npages; /* -ve count => locked */
		break;
	case F_INVAL :
	case F_PROT :
		while (slock->softlocked < 0)
			if (cv_wait_sig(&(slock)->cv, &(slock)->lock) == 0) {
				/* signalled */
				mutex_exit(&(slock->lock));
				return (EINTR);
			}
		slock->softlocked += npages; /* +ve count => f_invals */
		break;
	default:
		ASSERT(0);
	}
	mutex_exit(&(slock->lock));
	return (0);
}

static void devmap_softlock_exit(
	struct devmap_softlock *slock,
	size_t npages,
	enum fault_type type)
{
	if (slock == NULL)
		return;
	mutex_enter(&(slock->lock));
	switch (type) {
	case F_SOFTLOCK :
		ASSERT(-slock->softlocked >= npages);
		slock->softlocked += npages;	/* -ve count is softlocked */
		if (slock->softlocked == 0)
			cv_signal(&slock->cv);
		break;
	case F_INVAL :
	case F_PROT:
		ASSERT(slock->softlocked >= npages);
		slock->softlocked -= npages;
		if (slock->softlocked == 0)
			cv_signal(&slock->cv);
		break;
	default:
		ASSERT(0);
	}
	mutex_exit(&(slock->lock));
}

/*
 * Do a F_SOFTUNLOCK call over the range requested.
 * The range must have already been F_SOFTLOCK'ed.
 * The segment lock should be held, (but not the segment private lock?)
 *  The softunlock code below does not adjust for large page sizes
 *	assumes the caller already did any addr/len adjustments for
 *	pagesize mappings before calling.
 */
/*ARGSUSED*/
static void
segdev_softunlock(
	struct hat *hat,		/* the hat */
	struct seg *seg,		/* seg_dev of interest */
	caddr_t addr,			/* base address of range */
	size_t len,			/* number of bytes */
	enum seg_rw rw)			/* type of access at fault */
{
	struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	devmap_handle_t *dhp_head = (devmap_handle_t *)sdp->devmap_data;

	TRACE_4(TR_FAC_DEVMAP, TR_DEVMAP_SOFTUNLOCK,
	    "segdev_softunlock:dhp_head=%p sdp=%p addr=%p len=%lx",
	    dhp_head, sdp, addr, len);
	DEBUGF(3, (CE_CONT, "segdev_softunlock: dhp %p lockcnt %lx "
	    "addr %p len %lx\n",
	    (void *)dhp_head, sdp->softlockcnt, (void *)addr, len));

	hat_unlock(hat, addr, len);

	if (dhp_head != NULL) {
		devmap_handle_t *dhp;
		size_t mlen;
		size_t tlen = len;
		ulong_t off;

		dhp = devmap_find_handle(dhp_head, addr);
		ASSERT(dhp != NULL);

		off = (ulong_t)(addr - dhp->dh_uvaddr);
		while (tlen != 0) {
			mlen = MIN(tlen, (dhp->dh_len - off));

			/*
			 * unlock segkp memory, locked during F_SOFTLOCK
			 */
			if (dhp_is_kpmem(dhp)) {
				release_kpmem_lock(
				    (struct ddi_umem_cookie *)dhp->dh_cookie,
				    btopr(mlen));
			}

			/*
			 * Do the softlock accounting for devmap_access
			 */
			if (dhp->dh_callbackops.devmap_access != NULL) {
				devmap_softlock_exit(dhp->dh_softlock,
				    btopr(mlen), F_SOFTLOCK);
			}

			tlen -= mlen;
			dhp = dhp->dh_next;
			off = 0;
		}
	}

	mutex_enter(&freemem_lock);
	ASSERT(sdp->softlockcnt >= btopr(len));
	sdp->softlockcnt -= btopr(len);
	mutex_exit(&freemem_lock);
	if (sdp->softlockcnt == 0) {
		/*
		 * All SOFTLOCKS are gone. Wakeup any waiting
		 * unmappers so they can try again to unmap.
		 * Check for waiters first without the mutex
		 * held so we don't always grab the mutex on
		 * softunlocks.
		 */
		if (AS_ISUNMAPWAIT(seg->s_as)) {
			mutex_enter(&seg->s_as->a_contents);
			if (AS_ISUNMAPWAIT(seg->s_as)) {
				AS_CLRUNMAPWAIT(seg->s_as);
				cv_broadcast(&seg->s_as->a_cv);
			}
			mutex_exit(&seg->s_as->a_contents);
		}
	}

}

/*
 * Handle fault for a single page.
 * Done in a separate routine so we can handle errors more easily.
 * This routine is called only from segdev_faultpages()
 * when looping over the range of addresses requested. The segment lock is held.
 */
static faultcode_t
segdev_faultpage(
	struct hat *hat,		/* the hat */
	struct seg *seg,		/* seg_dev of interest */
	caddr_t addr,			/* address in as */
	struct vpage *vpage,		/* pointer to vpage for seg, addr */
	enum fault_type type,		/* type of fault */
	enum seg_rw rw,			/* type of access at fault */
	devmap_handle_t *dhp)		/* devmap handle if any for this page */
{
	struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	uint_t prot;
	pfn_t pfnum = PFN_INVALID;
	u_offset_t offset;
	uint_t hat_flags;
	dev_info_t *dip;

	TRACE_3(TR_FAC_DEVMAP, TR_DEVMAP_FAULTPAGE,
	    "segdev_faultpage: dhp=%p seg=%p addr=%p", dhp, seg, addr);
	DEBUGF(8, (CE_CONT, "segdev_faultpage: dhp %p seg %p addr %p \n",
	    (void *)dhp, (void *)seg, (void *)addr));

	/*
	 * Initialize protection value for this page.
	 * If we have per page protection values check it now.
	 */
	if (sdp->pageprot) {
		uint_t protchk;

		switch (rw) {
		case S_READ:
			protchk = PROT_READ;
			break;
		case S_WRITE:
			protchk = PROT_WRITE;
			break;
		case S_EXEC:
			protchk = PROT_EXEC;
			break;
		case S_OTHER:
		default:
			protchk = PROT_READ | PROT_WRITE | PROT_EXEC;
			break;
		}

		prot = VPP_PROT(vpage);
		if ((prot & protchk) == 0)
			return (FC_PROT);	/* illegal access type */
	} else {
		prot = sdp->prot;
		/* caller has already done segment level protection check */
	}

	if (type == F_SOFTLOCK) {
		mutex_enter(&freemem_lock);
		sdp->softlockcnt++;
		mutex_exit(&freemem_lock);
	}

	hat_flags = ((type == F_SOFTLOCK) ? HAT_LOAD_LOCK : HAT_LOAD);
	offset = sdp->offset + (u_offset_t)(addr - seg->s_base);
	/*
	 * In the devmap framework, sdp->mapfunc is set to NULL.  we can get
	 * pfnum from dhp->dh_pfn (at beginning of segment) and offset from
	 * seg->s_base.
	 */
	if (dhp == NULL) {
		/* If segment has devmap_data, then dhp should be non-NULL */
		ASSERT(sdp->devmap_data == NULL);
		pfnum = (pfn_t)cdev_mmap(sdp->mapfunc, sdp->vp->v_rdev,
		    (off_t)offset, prot);
		prot |= sdp->hat_attr;
	} else {
		ulong_t off;
		struct ddi_umem_cookie *cp;
		struct devmap_pmem_cookie *pcp;

		/* ensure the dhp passed in contains addr. */
		ASSERT(dhp == devmap_find_handle(
		    (devmap_handle_t *)sdp->devmap_data, addr));

		off = addr - dhp->dh_uvaddr;

		/*
		 * This routine assumes that the caller makes sure that the
		 * fields in dhp used below are unchanged due to remap during
		 * this call. Caller does HOLD_DHP_LOCK if neeed
		 */
		cp = dhp->dh_cookie;
		if (dhp->dh_flags & DEVMAP_MAPPING_INVALID) {
			pfnum = PFN_INVALID;
		} else if (cookie_is_devmem(cp)) {
			pfnum = dhp->dh_pfn + btop(off);
		} else if (cookie_is_pmem(cp)) {
			pcp = (struct devmap_pmem_cookie *)dhp->dh_pcookie;
			ASSERT((dhp->dh_roff & PAGEOFFSET) == 0 &&
			    dhp->dh_roff < ptob(pcp->dp_npages));
			pfnum = page_pptonum(
			    pcp->dp_pparray[btop(off + dhp->dh_roff)]);
		} else {
			ASSERT(dhp->dh_roff < cp->size);
			ASSERT(dhp->dh_cvaddr >= cp->cvaddr &&
			    dhp->dh_cvaddr < (cp->cvaddr + cp->size));
			ASSERT((dhp->dh_cvaddr + off) <=
			    (cp->cvaddr + cp->size));
			ASSERT((dhp->dh_cvaddr + off + PAGESIZE) <=
			    (cp->cvaddr + cp->size));

			switch (cp->type) {
			case UMEM_LOCKED :
				if (cp->pparray != NULL) {
					ASSERT((dhp->dh_roff &
					    PAGEOFFSET) == 0);
					pfnum = page_pptonum(
					    cp->pparray[btop(off +
					    dhp->dh_roff)]);
				} else {
					pfnum = hat_getpfnum(
					    ((proc_t *)cp->procp)->p_as->a_hat,
					    cp->cvaddr + off);
				}
			break;
			case UMEM_TRASH :
				pfnum = page_pptonum(trashpp);
				/*
				 * We should set hat_flags to HAT_NOFAULT also
				 * However, not all hat layers implement this
				 */
				break;
			case KMEM_PAGEABLE:
			case KMEM_NON_PAGEABLE:
				pfnum = hat_getpfnum(kas.a_hat,
				    dhp->dh_cvaddr + off);
				break;
			default :
				pfnum = PFN_INVALID;
				break;
			}
		}
		prot |= dhp->dh_hat_attr;
	}
	if (pfnum == PFN_INVALID) {
		return (FC_MAKE_ERR(EFAULT));
	}
	/* prot should already be OR'ed in with hat_attributes if needed */

	TRACE_4(TR_FAC_DEVMAP, TR_DEVMAP_FAULTPAGE_CK1,
	    "segdev_faultpage: pfnum=%lx memory=%x prot=%x flags=%x",
	    pfnum, pf_is_memory(pfnum), prot, hat_flags);
	DEBUGF(9, (CE_CONT, "segdev_faultpage: pfnum %lx memory %x "
	    "prot %x flags %x\n", pfnum, pf_is_memory(pfnum), prot, hat_flags));

	if (pf_is_memory(pfnum) || (dhp != NULL)) {
		/*
		 * It's not _really_ required here to pass sdp->hat_flags
		 * to hat_devload even though we do it.
		 * This is because hat figures it out DEVMEM mappings
		 * are non-consistent, anyway.
		 */
		hat_devload(hat, addr, PAGESIZE, pfnum,
		    prot, hat_flags | sdp->hat_flags);
		return (0);
	}

	/*
	 * Fall through to the case where devmap is not used and need to call
	 * up the device tree to set up the mapping
	 */

	dip = VTOS(VTOCVP(sdp->vp))->s_dip;
	ASSERT(dip);

	/*
	 * When calling ddi_map_fault, we do not OR in sdp->hat_attr
	 * This is because this calls drivers which may not expect
	 * prot to have any other values than PROT_ALL
	 * The root nexus driver has a hack to peek into the segment
	 * structure and then OR in sdp->hat_attr.
	 * XX In case the bus_ops interfaces are ever revisited
	 * we need to fix this. prot should include other hat attributes
	 */
	if (ddi_map_fault(dip, hat, seg, addr, NULL, pfnum, prot & PROT_ALL,
	    (uint_t)(type == F_SOFTLOCK)) != DDI_SUCCESS) {
		return (FC_MAKE_ERR(EFAULT));
	}
	return (0);
}

static faultcode_t
segdev_fault(
	struct hat *hat,		/* the hat */
	struct seg *seg,		/* the seg_dev of interest */
	caddr_t addr,			/* the address of the fault */
	size_t len,			/* the length of the range */
	enum fault_type type,		/* type of fault */
	enum seg_rw rw)			/* type of access at fault */
{
	struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	devmap_handle_t *dhp_head = (devmap_handle_t *)sdp->devmap_data;
	devmap_handle_t *dhp;
	struct devmap_softlock *slock = NULL;
	ulong_t slpage = 0;
	ulong_t off;
	caddr_t maddr = addr;
	int err;
	int err_is_faultcode = 0;

	TRACE_5(TR_FAC_DEVMAP, TR_DEVMAP_FAULT,
	    "segdev_fault: dhp_head=%p seg=%p addr=%p len=%lx type=%x",
	    (void *)dhp_head, (void *)seg, (void *)addr, len, type);
	DEBUGF(7, (CE_CONT, "segdev_fault: dhp_head %p seg %p "
	    "addr %p len %lx type %x\n",
	    (void *)dhp_head, (void *)seg, (void *)addr, len, type));

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	/* Handle non-devmap case */
	if (dhp_head == NULL)
		return (segdev_faultpages(hat, seg, addr, len, type, rw, NULL));

	/* Find devmap handle */
	if ((dhp = devmap_find_handle(dhp_head, addr)) == NULL)
		return (FC_NOMAP);

	/*
	 * The seg_dev driver does not implement copy-on-write,
	 * and always loads translations with maximal allowed permissions
	 * but we got an fault trying to access the device.
	 * Servicing the fault is not going to result in any better result
	 * RFE: If we want devmap_access callbacks to be involved in F_PROT
	 *	faults, then the code below is written for that
	 *	Pending resolution of the following:
	 *	- determine if the F_INVAL/F_SOFTLOCK syncing
	 *	is needed for F_PROT also or not. The code below assumes it does
	 *	- If driver sees F_PROT and calls devmap_load with same type,
	 *	then segdev_faultpages will fail with FC_PROT anyway, need to
	 *	change that so calls from devmap_load to segdev_faultpages for
	 *	F_PROT type are retagged to F_INVAL.
	 * RFE: Today we dont have drivers that use devmap and want to handle
	 *	F_PROT calls. The code in segdev_fault* is written to allow
	 *	this case but is not tested. A driver that needs this capability
	 *	should be able to remove the short-circuit case; resolve the
	 *	above issues and "should" work.
	 */
	if (type == F_PROT) {
		return (FC_PROT);
	}

	/*
	 * Loop through dhp list calling devmap_access or segdev_faultpages for
	 * each devmap handle.
	 * drivers which implement devmap_access can interpose on faults and do
	 * device-appropriate special actions before calling devmap_load.
	 */

	/*
	 * Unfortunately, this simple loop has turned out to expose a variety
	 * of complex problems which results in the following convoluted code.
	 *
	 * First, a desire to handle a serialization of F_SOFTLOCK calls
	 * to the driver within the framework.
	 *	This results in a dh_softlock structure that is on a per device
	 *	(or device instance) basis and serializes devmap_access calls.
	 *	Ideally we would need to do this for underlying
	 *	memory/device regions that are being faulted on
	 *	but that is hard to identify and with REMAP, harder
	 * Second, a desire to serialize F_INVAL(and F_PROT) calls w.r.t.
	 * 	to F_SOFTLOCK calls to the driver.
	 * These serializations are to simplify the driver programmer model.
	 * To support these two features, the code first goes through the
	 *	devmap handles and counts the pages (slpage) that are covered
	 *	by devmap_access callbacks.
	 * This part ends with a devmap_softlock_enter call
	 *	which allows only one F_SOFTLOCK active on a device instance,
	 *	but multiple F_INVAL/F_PROTs can be active except when a
	 *	F_SOFTLOCK is active
	 *
	 * Next, we dont short-circuit the fault code upfront to call
	 *	segdev_softunlock for F_SOFTUNLOCK, because we must use
	 *	the same length when we softlock and softunlock.
	 *
	 *	-Hat layers may not support softunlocking lengths less than the
	 *	original length when there is large page support.
	 *	-kpmem locking is dependent on keeping the lengths same.
	 *	-if drivers handled F_SOFTLOCK, they probably also expect to
	 *		see an F_SOFTUNLOCK of the same length
	 *	Hence, if extending lengths during softlock,
	 *	softunlock has to make the same adjustments and goes through
	 *	the same loop calling segdev_faultpages/segdev_softunlock
	 *	But some of the synchronization and error handling is different
	 */

	if (type != F_SOFTUNLOCK) {
		devmap_handle_t *dhpp = dhp;
		size_t slen = len;

		/*
		 * Calculate count of pages that are :
		 * a) within the (potentially extended) fault region
		 * b) AND covered by devmap handle with devmap_access
		 */
		off = (ulong_t)(addr - dhpp->dh_uvaddr);
		while (slen != 0) {
			size_t mlen;

			/*
			 * Softlocking on a region that allows remap is
			 * unsupported due to unresolved locking issues
			 * XXX: unclear what these are?
			 *	One potential is that if there is a pending
			 *	softlock, then a remap should not be allowed
			 *	until the unlock is done. This is easily
			 *	fixed by returning error in devmap*remap on
			 *	checking the dh->dh_softlock->softlocked value
			 */
			if ((type == F_SOFTLOCK) &&
			    (dhpp->dh_flags & DEVMAP_ALLOW_REMAP)) {
				return (FC_NOSUPPORT);
			}

			mlen = MIN(slen, (dhpp->dh_len - off));
			if (dhpp->dh_callbackops.devmap_access) {
				size_t llen;
				caddr_t laddr;
				/*
				 * use extended length for large page mappings
				 */
				HOLD_DHP_LOCK(dhpp);
				if ((sdp->pageprot == 0) &&
				    (dhpp->dh_flags & DEVMAP_FLAG_LARGE)) {
					devmap_get_large_pgsize(dhpp,
					    mlen, maddr, &llen, &laddr);
				} else {
					llen = mlen;
				}
				RELE_DHP_LOCK(dhpp);

				slpage += btopr(llen);
				slock = dhpp->dh_softlock;
			}
			maddr += mlen;
			ASSERT(slen >= mlen);
			slen -= mlen;
			dhpp = dhpp->dh_next;
			off = 0;
		}
		/*
		 * synchonize with other faulting threads and wait till safe
		 * devmap_softlock_enter might return due to signal in cv_wait
		 *
		 * devmap_softlock_enter has to be called outside of while loop
		 * to prevent a deadlock if len spans over multiple dhps.
		 * dh_softlock is based on device instance and if multiple dhps
		 * use the same device instance, the second dhp's LOCK call
		 * will hang waiting on the first to complete.
		 * devmap_setup verifies that slocks in a dhp_chain are same.
		 * RFE: this deadlock only hold true for F_SOFTLOCK. For
		 * 	F_INVAL/F_PROT, since we now allow multiple in parallel,
		 *	we could have done the softlock_enter inside the loop
		 *	and supported multi-dhp mappings with dissimilar devices
		 */
		if (err = devmap_softlock_enter(slock, slpage, type))
			return (FC_MAKE_ERR(err));
	}

	/* reset 'maddr' to the start addr of the range of fault. */
	maddr = addr;

	/* calculate the offset corresponds to 'addr' in the first dhp. */
	off = (ulong_t)(addr - dhp->dh_uvaddr);

	/*
	 * The fault length may span over multiple dhps.
	 * Loop until the total length is satisfied.
	 */
	while (len != 0) {
		size_t llen;
		size_t mlen;
		caddr_t laddr;

		/*
		 * mlen is the smaller of 'len' and the length
		 * from addr to the end of mapping defined by dhp.
		 */
		mlen = MIN(len, (dhp->dh_len - off));

		HOLD_DHP_LOCK(dhp);
		/*
		 * Pass the extended length and address to devmap_access
		 * if large pagesize is used for loading address translations.
		 */
		if ((sdp->pageprot == 0) &&
		    (dhp->dh_flags & DEVMAP_FLAG_LARGE)) {
			devmap_get_large_pgsize(dhp, mlen, maddr,
			    &llen, &laddr);
			ASSERT(maddr == addr || laddr == maddr);
		} else {
			llen = mlen;
			laddr = maddr;
		}

		if (dhp->dh_callbackops.devmap_access != NULL) {
			offset_t aoff;

			aoff = sdp->offset + (offset_t)(laddr - seg->s_base);

			/*
			 * call driver's devmap_access entry point which will
			 * call devmap_load/contextmgmt to load the translations
			 *
			 * We drop the dhp_lock before calling access so
			 * drivers can call devmap_*_remap within access
			 */
			RELE_DHP_LOCK(dhp);

			err = (*dhp->dh_callbackops.devmap_access)(
			    dhp, (void *)dhp->dh_pvtp, aoff, llen, type, rw);
		} else {
			/*
			 * If no devmap_access entry point, then load mappings
			 * hold dhp_lock across faultpages if REMAP
			 */
			err = segdev_faultpages(hat, seg, laddr, llen,
			    type, rw, dhp);
			err_is_faultcode = 1;
			RELE_DHP_LOCK(dhp);
		}

		if (err) {
			if ((type == F_SOFTLOCK) && (maddr > addr)) {
				/*
				 * If not first dhp, use
				 * segdev_fault(F_SOFTUNLOCK) for prior dhps
				 * While this is recursion, it is incorrect to
				 * call just segdev_softunlock
				 * if we are using either large pages
				 * or devmap_access. It will be more right
				 * to go through the same loop as above
				 * rather than call segdev_softunlock directly
				 * It will use the right lenghths as well as
				 * call into the driver devmap_access routines.
				 */
				size_t done = (size_t)(maddr - addr);
				(void) segdev_fault(hat, seg, addr, done,
				    F_SOFTUNLOCK, S_OTHER);
				/*
				 * reduce slpage by number of pages
				 * released by segdev_softunlock
				 */
				ASSERT(slpage >= btopr(done));
				devmap_softlock_exit(slock,
				    slpage - btopr(done), type);
			} else {
				devmap_softlock_exit(slock, slpage, type);
			}


			/*
			 * Segdev_faultpages() already returns a faultcode,
			 * hence, result from segdev_faultpages() should be
			 * returned directly.
			 */
			if (err_is_faultcode)
				return (err);
			return (FC_MAKE_ERR(err));
		}

		maddr += mlen;
		ASSERT(len >= mlen);
		len -= mlen;
		dhp = dhp->dh_next;
		off = 0;

		ASSERT(!dhp || len == 0 || maddr == dhp->dh_uvaddr);
	}
	/*
	 * release the softlock count at end of fault
	 * For F_SOFTLOCk this is done in the later F_SOFTUNLOCK
	 */
	if ((type == F_INVAL) || (type == F_PROT))
		devmap_softlock_exit(slock, slpage, type);
	return (0);
}

/*
 * segdev_faultpages
 *
 * Used to fault in seg_dev segment pages. Called by segdev_fault or devmap_load
 * This routine assumes that the callers makes sure that the fields
 * in dhp used below are not changed due to remap during this call.
 * Caller does HOLD_DHP_LOCK if neeed
 * This routine returns a faultcode_t as a return value for segdev_fault.
 */
static faultcode_t
segdev_faultpages(
	struct hat *hat,		/* the hat */
	struct seg *seg,		/* the seg_dev of interest */
	caddr_t addr,			/* the address of the fault */
	size_t len,			/* the length of the range */
	enum fault_type type,		/* type of fault */
	enum seg_rw rw,			/* type of access at fault */
	devmap_handle_t *dhp)		/* devmap handle */
{
	register struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	register caddr_t a;
	struct vpage *vpage;
	struct ddi_umem_cookie *kpmem_cookie = NULL;
	int err;

	TRACE_4(TR_FAC_DEVMAP, TR_DEVMAP_FAULTPAGES,
	    "segdev_faultpages: dhp=%p seg=%p addr=%p len=%lx",
	    (void *)dhp, (void *)seg, (void *)addr, len);
	DEBUGF(5, (CE_CONT, "segdev_faultpages: "
	    "dhp %p seg %p addr %p len %lx\n",
	    (void *)dhp, (void *)seg, (void *)addr, len));

	/*
	 * The seg_dev driver does not implement copy-on-write,
	 * and always loads translations with maximal allowed permissions
	 * but we got an fault trying to access the device.
	 * Servicing the fault is not going to result in any better result
	 * XXX: If we want to allow devmap_access to handle F_PROT calls,
	 * This code should be removed and let the normal fault handling
	 * take care of finding the error
	 */
	if (type == F_PROT) {
		return (FC_PROT);
	}

	if (type == F_SOFTUNLOCK) {
		segdev_softunlock(hat, seg, addr, len, rw);
		return (0);
	}

	/*
	 * For kernel pageable memory, fault/lock segkp pages
	 * We hold this until the completion of this
	 * fault (INVAL/PROT) or till unlock (SOFTLOCK).
	 */
	if ((dhp != NULL) && dhp_is_kpmem(dhp)) {
		kpmem_cookie = (struct ddi_umem_cookie *)dhp->dh_cookie;
		if (err = acquire_kpmem_lock(kpmem_cookie, btopr(len)))
			return (err);
	}

	/*
	 * If we have the same protections for the entire segment,
	 * insure that the access being attempted is legitimate.
	 */
	rw_enter(&sdp->lock, RW_READER);
	if (sdp->pageprot == 0) {
		uint_t protchk;

		switch (rw) {
		case S_READ:
			protchk = PROT_READ;
			break;
		case S_WRITE:
			protchk = PROT_WRITE;
			break;
		case S_EXEC:
			protchk = PROT_EXEC;
			break;
		case S_OTHER:
		default:
			protchk = PROT_READ | PROT_WRITE | PROT_EXEC;
			break;
		}

		if ((sdp->prot & protchk) == 0) {
			rw_exit(&sdp->lock);
			/* undo kpmem locking */
			if (kpmem_cookie != NULL) {
				release_kpmem_lock(kpmem_cookie, btopr(len));
			}
			return (FC_PROT);	/* illegal access type */
		}
	}

	/*
	 * we do a single hat_devload for the range if
	 *   - devmap framework (dhp is not NULL),
	 *   - pageprot == 0, i.e., no per-page protection set and
	 *   - is device pages, irrespective of whether we are using large pages
	 */
	if ((sdp->pageprot == 0) && (dhp != NULL) && dhp_is_devmem(dhp)) {
		pfn_t pfnum;
		uint_t hat_flags;

		if (dhp->dh_flags & DEVMAP_MAPPING_INVALID) {
			rw_exit(&sdp->lock);
			return (FC_NOMAP);
		}

		if (type == F_SOFTLOCK) {
			mutex_enter(&freemem_lock);
			sdp->softlockcnt += btopr(len);
			mutex_exit(&freemem_lock);
		}

		hat_flags = ((type == F_SOFTLOCK) ? HAT_LOAD_LOCK : HAT_LOAD);
		pfnum = dhp->dh_pfn + btop((uintptr_t)(addr - dhp->dh_uvaddr));
		ASSERT(!pf_is_memory(pfnum));

		hat_devload(hat, addr, len, pfnum, sdp->prot | dhp->dh_hat_attr,
		    hat_flags | sdp->hat_flags);
		rw_exit(&sdp->lock);
		return (0);
	}

	/* Handle cases where we have to loop through fault handling per-page */

	if (sdp->vpage == NULL)
		vpage = NULL;
	else
		vpage = &sdp->vpage[seg_page(seg, addr)];

	/* loop over the address range handling each fault */
	for (a = addr; a < addr + len; a += PAGESIZE) {
		if (err = segdev_faultpage(hat, seg, a, vpage, type, rw, dhp)) {
			break;
		}
		if (vpage != NULL)
			vpage++;
	}
	rw_exit(&sdp->lock);
	if (err && (type == F_SOFTLOCK)) { /* error handling for F_SOFTLOCK */
		size_t done = (size_t)(a - addr); /* pages fault successfully */
		if (done > 0) {
			/* use softunlock for those pages */
			segdev_softunlock(hat, seg, addr, done, S_OTHER);
		}
		if (kpmem_cookie != NULL) {
			/* release kpmem lock for rest of pages */
			ASSERT(len >= done);
			release_kpmem_lock(kpmem_cookie, btopr(len - done));
		}
	} else if ((kpmem_cookie != NULL) && (type != F_SOFTLOCK)) {
		/* for non-SOFTLOCK cases, release kpmem */
		release_kpmem_lock(kpmem_cookie, btopr(len));
	}
	return (err);
}

/*
 * Asynchronous page fault.  We simply do nothing since this
 * entry point is not supposed to load up the translation.
 */
/*ARGSUSED*/
static faultcode_t
segdev_faulta(struct seg *seg, caddr_t addr)
{
	TRACE_2(TR_FAC_DEVMAP, TR_DEVMAP_FAULTA,
	    "segdev_faulta: seg=%p addr=%p", (void *)seg, (void *)addr);
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	return (0);
}

static int
segdev_setprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	register struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	register devmap_handle_t *dhp;
	register struct vpage *vp, *evp;
	devmap_handle_t *dhp_head = (devmap_handle_t *)sdp->devmap_data;
	ulong_t off;
	size_t mlen, sz;

	TRACE_4(TR_FAC_DEVMAP, TR_DEVMAP_SETPROT,
	    "segdev_setprot:start seg=%p addr=%p len=%lx prot=%x",
	    (void *)seg, (void *)addr, len, prot);
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	if ((sz = sdp->softlockcnt) > 0 && dhp_head != NULL) {
		/*
		 * Fail the setprot if pages are SOFTLOCKed through this
		 * mapping.
		 * Softlockcnt is protected from change by the as read lock.
		 */
		TRACE_1(TR_FAC_DEVMAP, TR_DEVMAP_SETPROT_CK1,
		    "segdev_setprot:error softlockcnt=%lx", sz);
		DEBUGF(1, (CE_CONT, "segdev_setprot: softlockcnt %ld\n", sz));
		return (EAGAIN);
	}

	if (dhp_head != NULL) {
		if ((dhp = devmap_find_handle(dhp_head, addr)) == NULL)
			return (EINVAL);

		/*
		 * check if violate maxprot.
		 */
		off = (ulong_t)(addr - dhp->dh_uvaddr);
		mlen  = len;
		while (dhp) {
			if ((dhp->dh_maxprot & prot) != prot)
				return (EACCES);	/* violated maxprot */

			if (mlen > (dhp->dh_len - off)) {
				mlen -= dhp->dh_len - off;
				dhp = dhp->dh_next;
				off = 0;
			} else
				break;
		}
	} else {
		if ((sdp->maxprot & prot) != prot)
			return (EACCES);
	}

	rw_enter(&sdp->lock, RW_WRITER);
	if (addr == seg->s_base && len == seg->s_size && sdp->pageprot == 0) {
		if (sdp->prot == prot) {
			rw_exit(&sdp->lock);
			return (0);			/* all done */
		}
		sdp->prot = (uchar_t)prot;
	} else {
		sdp->pageprot = 1;
		if (sdp->vpage == NULL) {
			/*
			 * First time through setting per page permissions,
			 * initialize all the vpage structures to prot
			 */
			sdp->vpage = kmem_zalloc(vpgtob(seg_pages(seg)),
			    KM_SLEEP);
			evp = &sdp->vpage[seg_pages(seg)];
			for (vp = sdp->vpage; vp < evp; vp++)
				VPP_SETPROT(vp, sdp->prot);
		}
		/*
		 * Now go change the needed vpages protections.
		 */
		evp = &sdp->vpage[seg_page(seg, addr + len)];
		for (vp = &sdp->vpage[seg_page(seg, addr)]; vp < evp; vp++)
			VPP_SETPROT(vp, prot);
	}
	rw_exit(&sdp->lock);

	if (dhp_head != NULL) {
		devmap_handle_t *tdhp;
		/*
		 * If large page size was used in hat_devload(),
		 * the same page size must be used in hat_unload().
		 */
		dhp = tdhp = devmap_find_handle(dhp_head, addr);
		while (tdhp != NULL) {
			if (tdhp->dh_flags & DEVMAP_FLAG_LARGE) {
				break;
			}
			tdhp = tdhp->dh_next;
		}
		if (tdhp) {
			size_t slen = len;
			size_t mlen;
			size_t soff;

			soff = (ulong_t)(addr - dhp->dh_uvaddr);
			while (slen != 0) {
				mlen = MIN(slen, (dhp->dh_len - soff));
				hat_unload(seg->s_as->a_hat, dhp->dh_uvaddr,
				    dhp->dh_len, HAT_UNLOAD);
				dhp = dhp->dh_next;
				ASSERT(slen >= mlen);
				slen -= mlen;
				soff = 0;
			}
			return (0);
		}
	}

	if ((prot & ~PROT_USER) == PROT_NONE) {
		hat_unload(seg->s_as->a_hat, addr, len, HAT_UNLOAD);
	} else {
		/*
		 * RFE: the segment should keep track of all attributes
		 * allowing us to remove the deprecated hat_chgprot
		 * and use hat_chgattr.
		 */
		hat_chgprot(seg->s_as->a_hat, addr, len, prot);
	}

	return (0);
}

static int
segdev_checkprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	struct vpage *vp, *evp;

	TRACE_4(TR_FAC_DEVMAP, TR_DEVMAP_CHECKPROT,
	    "segdev_checkprot:start seg=%p addr=%p len=%lx prot=%x",
	    (void *)seg, (void *)addr, len, prot);
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	/*
	 * If segment protection can be used, simply check against them
	 */
	rw_enter(&sdp->lock, RW_READER);
	if (sdp->pageprot == 0) {
		register int err;

		err = ((sdp->prot & prot) != prot) ? EACCES : 0;
		rw_exit(&sdp->lock);
		return (err);
	}

	/*
	 * Have to check down to the vpage level
	 */
	evp = &sdp->vpage[seg_page(seg, addr + len)];
	for (vp = &sdp->vpage[seg_page(seg, addr)]; vp < evp; vp++) {
		if ((VPP_PROT(vp) & prot) != prot) {
			rw_exit(&sdp->lock);
			return (EACCES);
		}
	}
	rw_exit(&sdp->lock);
	return (0);
}

static int
segdev_getprot(struct seg *seg, caddr_t addr, size_t len, uint_t *protv)
{
	struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	size_t pgno;

	TRACE_4(TR_FAC_DEVMAP, TR_DEVMAP_GETPROT,
	    "segdev_getprot:start seg=%p addr=%p len=%lx protv=%p",
	    (void *)seg, (void *)addr, len, (void *)protv);
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	pgno = seg_page(seg, addr + len) - seg_page(seg, addr) + 1;
	if (pgno != 0) {
		rw_enter(&sdp->lock, RW_READER);
		if (sdp->pageprot == 0) {
			do {
				protv[--pgno] = sdp->prot;
			} while (pgno != 0);
		} else {
			size_t pgoff = seg_page(seg, addr);

			do {
				pgno--;
				protv[pgno] =
				    VPP_PROT(&sdp->vpage[pgno + pgoff]);
			} while (pgno != 0);
		}
		rw_exit(&sdp->lock);
	}
	return (0);
}

static u_offset_t
segdev_getoffset(register struct seg *seg, caddr_t addr)
{
	register struct segdev_data *sdp = (struct segdev_data *)seg->s_data;

	TRACE_2(TR_FAC_DEVMAP, TR_DEVMAP_GETOFFSET,
	    "segdev_getoffset:start seg=%p addr=%p", (void *)seg, (void *)addr);

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	return ((u_offset_t)sdp->offset + (addr - seg->s_base));
}

/*ARGSUSED*/
static int
segdev_gettype(register struct seg *seg, caddr_t addr)
{
	register struct segdev_data *sdp = (struct segdev_data *)seg->s_data;

	TRACE_2(TR_FAC_DEVMAP, TR_DEVMAP_GETTYPE,
	    "segdev_gettype:start seg=%p addr=%p", (void *)seg, (void *)addr);

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	return (sdp->type);
}


/*ARGSUSED*/
static int
segdev_getvp(register struct seg *seg, caddr_t addr, struct vnode **vpp)
{
	register struct segdev_data *sdp = (struct segdev_data *)seg->s_data;

	TRACE_2(TR_FAC_DEVMAP, TR_DEVMAP_GETVP,
	    "segdev_getvp:start seg=%p addr=%p", (void *)seg, (void *)addr);

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	/*
	 * Note that this vp is the common_vp of the device, where the
	 * pages are hung ..
	 */
	*vpp = VTOCVP(sdp->vp);

	return (0);
}

static void
segdev_badop(void)
{
	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_SEGDEV_BADOP,
	    "segdev_badop:start");
	panic("segdev_badop");
	/*NOTREACHED*/
}

/*
 * segdev pages are not in the cache, and thus can't really be controlled.
 * Hence, syncs are simply always successful.
 */
/*ARGSUSED*/
static int
segdev_sync(struct seg *seg, caddr_t addr, size_t len, int attr, uint_t flags)
{
	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_SYNC, "segdev_sync:start");

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	return (0);
}

/*
 * segdev pages are always "in core".
 */
/*ARGSUSED*/
static size_t
segdev_incore(struct seg *seg, caddr_t addr, size_t len, char *vec)
{
	size_t v = 0;

	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_INCORE, "segdev_incore:start");

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	for (len = (len + PAGEOFFSET) & PAGEMASK; len; len -= PAGESIZE,
	    v += PAGESIZE)
		*vec++ = 1;
	return (v);
}

/*
 * segdev pages are not in the cache, and thus can't really be controlled.
 * Hence, locks are simply always successful.
 */
/*ARGSUSED*/
static int
segdev_lockop(struct seg *seg, caddr_t addr,
    size_t len, int attr, int op, ulong_t *lockmap, size_t pos)
{
	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_LOCKOP, "segdev_lockop:start");

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	return (0);
}

/*
 * segdev pages are not in the cache, and thus can't really be controlled.
 * Hence, advise is simply always successful.
 */
/*ARGSUSED*/
static int
segdev_advise(struct seg *seg, caddr_t addr, size_t len, uint_t behav)
{
	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_ADVISE, "segdev_advise:start");

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as, &seg->s_as->a_lock));

	return (0);
}

/*
 * segdev pages are not dumped, so we just return
 */
/*ARGSUSED*/
static void
segdev_dump(struct seg *seg)
{}

/*
 * ddi_segmap_setup:	Used by drivers who wish specify mapping attributes
 *			for a segment.	Called from a drivers segmap(9E)
 *			routine.
 */
/*ARGSUSED*/
int
ddi_segmap_setup(dev_t dev, off_t offset, struct as *as, caddr_t *addrp,
    off_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cred,
    ddi_device_acc_attr_t *accattrp, uint_t rnumber)
{
	struct segdev_crargs dev_a;
	int (*mapfunc)(dev_t dev, off_t off, int prot);
	uint_t hat_attr;
	pfn_t pfn;
	int	error, i;

	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_SEGMAP_SETUP,
	    "ddi_segmap_setup:start");

	if ((mapfunc = devopsp[getmajor(dev)]->devo_cb_ops->cb_mmap) == nodev)
		return (ENODEV);

	/*
	 * Character devices that support the d_mmap
	 * interface can only be mmap'ed shared.
	 */
	if ((flags & MAP_TYPE) != MAP_SHARED)
		return (EINVAL);

	/*
	 * Check that this region is indeed mappable on this platform.
	 * Use the mapping function.
	 */
	if (ddi_device_mapping_check(dev, accattrp, rnumber, &hat_attr) == -1)
		return (ENXIO);

	/*
	 * Check to ensure that the entire range is
	 * legal and we are not trying to map in
	 * more than the device will let us.
	 */
	for (i = 0; i < len; i += PAGESIZE) {
		if (i == 0) {
			/*
			 * Save the pfn at offset here. This pfn will be
			 * used later to get user address.
			 */
			if ((pfn = (pfn_t)cdev_mmap(mapfunc, dev, offset,
			    maxprot)) == PFN_INVALID)
				return (ENXIO);
		} else {
			if (cdev_mmap(mapfunc, dev, offset + i, maxprot) ==
			    PFN_INVALID)
				return (ENXIO);
		}
	}

	as_rangelock(as);
	/* Pick an address w/o worrying about any vac alignment constraints. */
	error = choose_addr(as, addrp, len, ptob(pfn), ADDR_NOVACALIGN, flags);
	if (error != 0) {
		as_rangeunlock(as);
		return (error);
	}

	dev_a.mapfunc = mapfunc;
	dev_a.dev = dev;
	dev_a.offset = (offset_t)offset;
	dev_a.type = flags & MAP_TYPE;
	dev_a.prot = (uchar_t)prot;
	dev_a.maxprot = (uchar_t)maxprot;
	dev_a.hat_attr = hat_attr;
	dev_a.hat_flags = 0;
	dev_a.devmap_data = NULL;

	error = as_map(as, *addrp, len, segdev_create, &dev_a);
	as_rangeunlock(as);
	return (error);

}

/*ARGSUSED*/
static int
segdev_pagelock(struct seg *seg, caddr_t addr, size_t len,
    struct page ***ppp, enum lock_type type, enum seg_rw rw)
{
	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_PAGELOCK,
	    "segdev_pagelock:start");
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
segdev_setpagesize(struct seg *seg, caddr_t addr, size_t len,
    uint_t szc)
{
	return (ENOTSUP);
}

/*
 * devmap_device: Used by devmap framework to establish mapping
 *                called by devmap_seup(9F) during map setup time.
 */
/*ARGSUSED*/
static int
devmap_device(devmap_handle_t *dhp, struct as *as, caddr_t *addr,
    offset_t off, size_t len, uint_t flags)
{
	devmap_handle_t *rdhp, *maxdhp;
	struct segdev_crargs dev_a;
	int	err;
	uint_t maxprot = PROT_ALL;
	offset_t offset = 0;
	pfn_t pfn;
	struct devmap_pmem_cookie *pcp;

	TRACE_4(TR_FAC_DEVMAP, TR_DEVMAP_DEVICE,
	    "devmap_device:start dhp=%p addr=%p off=%llx, len=%lx",
	    (void *)dhp, (void *)addr, off, len);

	DEBUGF(2, (CE_CONT, "devmap_device: dhp %p addr %p off %llx len %lx\n",
	    (void *)dhp, (void *)addr, off, len));

	as_rangelock(as);
	if ((flags & MAP_FIXED) == 0) {
		offset_t aligned_off;

		rdhp = maxdhp = dhp;
		while (rdhp != NULL) {
			maxdhp = (maxdhp->dh_len > rdhp->dh_len) ?
			    maxdhp : rdhp;
			rdhp = rdhp->dh_next;
			maxprot |= dhp->dh_maxprot;
		}
		offset = maxdhp->dh_uoff - dhp->dh_uoff;

		/*
		 * Use the dhp that has the
		 * largest len to get user address.
		 */
		/*
		 * If MAPPING_INVALID, cannot use dh_pfn/dh_cvaddr,
		 * use 0 which is as good as any other.
		 */
		if (maxdhp->dh_flags & DEVMAP_MAPPING_INVALID) {
			aligned_off = (offset_t)0;
		} else if (dhp_is_devmem(maxdhp)) {
			aligned_off = (offset_t)ptob(maxdhp->dh_pfn) - offset;
		} else if (dhp_is_pmem(maxdhp)) {
			pcp = (struct devmap_pmem_cookie *)maxdhp->dh_pcookie;
			pfn = page_pptonum(
			    pcp->dp_pparray[btop(maxdhp->dh_roff)]);
			aligned_off = (offset_t)ptob(pfn) - offset;
		} else {
			aligned_off = (offset_t)(uintptr_t)maxdhp->dh_cvaddr -
			    offset;
		}

		/*
		 * Pick an address aligned to dh_cookie.
		 * for kernel memory/user memory, cookie is cvaddr.
		 * for device memory, cookie is physical address.
		 */
		map_addr(addr, len, aligned_off, 1, flags);
		if (*addr == NULL) {
			as_rangeunlock(as);
			return (ENOMEM);
		}
	} else {
		/*
		 * User-specified address; blow away any previous mappings.
		 */
		(void) as_unmap(as, *addr, len);
	}

	dev_a.mapfunc = NULL;
	dev_a.dev = dhp->dh_dev;
	dev_a.type = flags & MAP_TYPE;
	dev_a.offset = off;
	/*
	 * sdp->maxprot has the least restrict protection of all dhps.
	 */
	dev_a.maxprot = maxprot;
	dev_a.prot = dhp->dh_prot;
	/*
	 * devmap uses dhp->dh_hat_attr for hat.
	 */
	dev_a.hat_flags = 0;
	dev_a.hat_attr = 0;
	dev_a.devmap_data = (void *)dhp;

	err = as_map(as, *addr, len, segdev_create, &dev_a);
	as_rangeunlock(as);
	return (err);
}

int
devmap_do_ctxmgt(devmap_cookie_t dhc, void *pvtp, offset_t off, size_t len,
    uint_t type, uint_t rw, int (*ctxmgt)(devmap_cookie_t, void *, offset_t,
    size_t, uint_t, uint_t))
{
	register devmap_handle_t *dhp = (devmap_handle_t *)dhc;
	struct devmap_ctx *devctx;
	int do_timeout = 0;
	int ret;

#ifdef lint
	pvtp = pvtp;
#endif

	TRACE_3(TR_FAC_DEVMAP, TR_DEVMAP_DO_CTXMGT,
	    "devmap_do_ctxmgt:start dhp=%p off=%llx, len=%lx",
	    (void *)dhp, off, len);
	DEBUGF(7, (CE_CONT, "devmap_do_ctxmgt: dhp %p off %llx len %lx\n",
	    (void *)dhp, off, len));

	if (ctxmgt == NULL)
		return (FC_HWERR);

	devctx = dhp->dh_ctx;

	/*
	 * If we are on an MP system with more than one cpu running
	 * and if a thread on some CPU already has the context, wait
	 * for it to finish if there is a hysteresis timeout.
	 *
	 * We call cv_wait() instead of cv_wait_sig() because
	 * it does not matter much if it returned due to a signal
	 * or due to a cv_signal() or cv_broadcast().  In either event
	 * we need to complete the mapping otherwise the processes
	 * will die with a SEGV.
	 */
	if ((dhp->dh_timeout_length > 0) && (ncpus > 1)) {
		TRACE_2(TR_FAC_DEVMAP, TR_DEVMAP_DO_CTXMGT_CK1,
		    "devmap_do_ctxmgt:doing hysteresis, devctl %p dhp %p",
		    devctx, dhp);
		do_timeout = 1;
		mutex_enter(&devctx->lock);
		while (devctx->oncpu)
			cv_wait(&devctx->cv, &devctx->lock);
		devctx->oncpu = 1;
		mutex_exit(&devctx->lock);
	}

	/*
	 * Call the contextmgt callback so that the driver can handle
	 * the fault.
	 */
	ret = (*ctxmgt)(dhp, dhp->dh_pvtp, off, len, type, rw);

	/*
	 * If devmap_access() returned -1, then there was a hardware
	 * error so we need to convert the return value to something
	 * that trap() will understand.  Otherwise, the return value
	 * is already a fault code generated by devmap_unload()
	 * or devmap_load().
	 */
	if (ret) {
		TRACE_3(TR_FAC_DEVMAP, TR_DEVMAP_DO_CTXMGT_CK2,
		    "devmap_do_ctxmgt: ret=%x dhp=%p devctx=%p",
		    ret, dhp, devctx);
		DEBUGF(1, (CE_CONT, "devmap_do_ctxmgt: ret %x dhp %p\n",
		    ret, (void *)dhp));
		if (devctx->oncpu) {
			mutex_enter(&devctx->lock);
			devctx->oncpu = 0;
			cv_signal(&devctx->cv);
			mutex_exit(&devctx->lock);
		}
		return (FC_HWERR);
	}

	/*
	 * Setup the timeout if we need to
	 */
	if (do_timeout) {
		mutex_enter(&devctx->lock);
		if (dhp->dh_timeout_length > 0) {
			TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_DO_CTXMGT_CK3,
			    "devmap_do_ctxmgt:timeout set");
			devctx->timeout = timeout(devmap_ctxto,
			    devctx, dhp->dh_timeout_length);
		} else {
			/*
			 * We don't want to wait so set oncpu to
			 * 0 and wake up anyone waiting.
			 */
			TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_DO_CTXMGT_CK4,
			    "devmap_do_ctxmgt:timeout not set");
			devctx->oncpu = 0;
			cv_signal(&devctx->cv);
		}
		mutex_exit(&devctx->lock);
	}

	return (DDI_SUCCESS);
}

/*
 *                                       end of mapping
 *                    poff   fault_offset         |
 *            base     |        |                 |
 *              |      |        |                 |
 *              V      V        V                 V
 *  +-----------+---------------+-------+---------+-------+
 *              ^               ^       ^         ^
 *              |<--- offset--->|<-len->|         |
 *              |<--- dh_len(size of mapping) --->|
 *                     |<--  pg -->|
 *                              -->|rlen|<--
 */
static ulong_t
devmap_roundup(devmap_handle_t *dhp, ulong_t offset, size_t len,
    ulong_t *opfn, ulong_t *pagesize)
{
	register int level;
	ulong_t pg;
	ulong_t poff;
	ulong_t base;
	caddr_t uvaddr;
	long rlen;

	TRACE_3(TR_FAC_DEVMAP, TR_DEVMAP_ROUNDUP,
	    "devmap_roundup:start dhp=%p off=%lx len=%lx",
	    (void *)dhp, offset, len);
	DEBUGF(2, (CE_CONT, "devmap_roundup: dhp %p off %lx len %lx\n",
	    (void *)dhp, offset, len));

	/*
	 * get the max. pagesize that is aligned within the range
	 * <dh_pfn, dh_pfn+offset>.
	 *
	 * The calculations below use physical address to ddetermine
	 * the page size to use. The same calculations can use the
	 * virtual address to determine the page size.
	 */
	base = (ulong_t)ptob(dhp->dh_pfn);
	for (level = dhp->dh_mmulevel; level >= 0; level--) {
		pg = page_get_pagesize(level);
		poff = ((base + offset) & ~(pg - 1));
		uvaddr = dhp->dh_uvaddr + (poff - base);
		if ((poff >= base) &&
		    ((poff + pg) <= (base + dhp->dh_len)) &&
		    VA_PA_ALIGNED((uintptr_t)uvaddr, poff, pg))
			break;
	}

	TRACE_3(TR_FAC_DEVMAP, TR_DEVMAP_ROUNDUP_CK1,
	    "devmap_roundup: base=%lx poff=%lx dhp=%p",
	    base, poff, dhp);
	DEBUGF(2, (CE_CONT, "devmap_roundup: base %lx poff %lx pfn %lx\n",
	    base, poff, dhp->dh_pfn));

	ASSERT(VA_PA_ALIGNED((uintptr_t)uvaddr, poff, pg));
	ASSERT(level >= 0);

	*pagesize = pg;
	*opfn = dhp->dh_pfn + btop(poff - base);

	rlen = len + offset - (poff - base + pg);

	ASSERT(rlen < (long)len);

	TRACE_5(TR_FAC_DEVMAP, TR_DEVMAP_ROUNDUP_CK2,
	    "devmap_roundup:ret dhp=%p level=%x rlen=%lx psiz=%p opfn=%p",
	    (void *)dhp, level, rlen, pagesize, opfn);
	DEBUGF(1, (CE_CONT, "devmap_roundup: dhp %p "
	    "level %x rlen %lx psize %lx opfn %lx\n",
	    (void *)dhp, level, rlen, *pagesize, *opfn));

	return ((ulong_t)((rlen > 0) ? rlen : 0));
}

/*
 * find the dhp that contains addr.
 */
static devmap_handle_t *
devmap_find_handle(devmap_handle_t *dhp_head, caddr_t addr)
{
	devmap_handle_t *dhp;

	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_FIND_HANDLE,
	    "devmap_find_handle:start");

	dhp = dhp_head;
	while (dhp) {
		if (addr >= dhp->dh_uvaddr &&
		    addr < (dhp->dh_uvaddr + dhp->dh_len))
			return (dhp);
		dhp = dhp->dh_next;
	}

	return ((devmap_handle_t *)NULL);
}

/*
 * devmap_unload:
 *			Marks a segdev segment or pages if offset->offset+len
 *			is not the entire segment as intercept and unloads the
 *			pages in the range offset -> offset+len.
 */
int
devmap_unload(devmap_cookie_t dhc, offset_t offset, size_t len)
{
	register devmap_handle_t *dhp = (devmap_handle_t *)dhc;
	caddr_t	addr;
	ulong_t	size;
	ssize_t	soff;

	TRACE_3(TR_FAC_DEVMAP, TR_DEVMAP_UNLOAD,
	    "devmap_unload:start dhp=%p offset=%llx len=%lx",
	    (void *)dhp, offset, len);
	DEBUGF(7, (CE_CONT, "devmap_unload: dhp %p offset %llx len %lx\n",
	    (void *)dhp, offset, len));

	soff = (ssize_t)(offset - dhp->dh_uoff);
	soff = round_down_p2(soff, PAGESIZE);
	if (soff < 0 || soff >= dhp->dh_len)
		return (FC_MAKE_ERR(EINVAL));

	/*
	 * Address and size must be page aligned.  Len is set to the
	 * number of bytes in the number of pages that are required to
	 * support len.  Offset is set to the byte offset of the first byte
	 * of the page that contains offset.
	 */
	len = round_up_p2(len, PAGESIZE);

	/*
	 * If len is == 0, then calculate the size by getting
	 * the number of bytes from offset to the end of the segment.
	 */
	if (len == 0)
		size = dhp->dh_len - soff;
	else {
		size = len;
		if ((soff + size) > dhp->dh_len)
			return (FC_MAKE_ERR(EINVAL));
	}

	/*
	 * The address is offset bytes from the base address of
	 * the dhp.
	 */
	addr = (caddr_t)(soff + dhp->dh_uvaddr);

	/*
	 * If large page size was used in hat_devload(),
	 * the same page size must be used in hat_unload().
	 */
	if (dhp->dh_flags & DEVMAP_FLAG_LARGE) {
		hat_unload(dhp->dh_seg->s_as->a_hat, dhp->dh_uvaddr,
		    dhp->dh_len, HAT_UNLOAD|HAT_UNLOAD_OTHER);
	} else {
		hat_unload(dhp->dh_seg->s_as->a_hat,  addr, size,
		    HAT_UNLOAD|HAT_UNLOAD_OTHER);
	}

	return (0);
}

/*
 * calculates the optimal page size that will be used for hat_devload().
 */
static void
devmap_get_large_pgsize(devmap_handle_t *dhp, size_t len, caddr_t addr,
    size_t *llen, caddr_t *laddr)
{
	ulong_t off;
	ulong_t pfn;
	ulong_t pgsize;
	uint_t first = 1;

	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_GET_LARGE_PGSIZE,
	    "devmap_get_large_pgsize:start");

	/*
	 * RFE - Code only supports large page mappings for devmem
	 * This code could be changed in future if we want to support
	 * large page mappings for kernel exported memory.
	 */
	ASSERT(dhp_is_devmem(dhp));
	ASSERT(!(dhp->dh_flags & DEVMAP_MAPPING_INVALID));

	*llen = 0;
	off = (ulong_t)(addr - dhp->dh_uvaddr);
	while ((long)len > 0) {
		/*
		 * get the optimal pfn to minimize address translations.
		 * devmap_roundup() returns residue bytes for next round
		 * calculations.
		 */
		len = devmap_roundup(dhp, off, len, &pfn, &pgsize);

		if (first) {
			*laddr = dhp->dh_uvaddr + ptob(pfn - dhp->dh_pfn);
			first = 0;
		}

		*llen += pgsize;
		off = ptob(pfn - dhp->dh_pfn) + pgsize;
	}
	/* Large page mapping len/addr cover more range than original fault */
	ASSERT(*llen >= len && *laddr <= addr);
	ASSERT((*laddr + *llen) >= (addr + len));
}

/*
 * Initialize the devmap_softlock structure.
 */
static struct devmap_softlock *
devmap_softlock_init(dev_t dev, ulong_t id)
{
	struct devmap_softlock *slock;
	struct devmap_softlock *tmp;

	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_SOFTLOCK_INIT,
	    "devmap_softlock_init:start");

	tmp = kmem_zalloc(sizeof (struct devmap_softlock), KM_SLEEP);
	mutex_enter(&devmap_slock);

	for (slock = devmap_slist; slock != NULL; slock = slock->next)
		if ((slock->dev == dev) && (slock->id == id))
			break;

	if (slock == NULL) {
		slock = tmp;
		slock->dev = dev;
		slock->id = id;
		mutex_init(&slock->lock, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&slock->cv, NULL, CV_DEFAULT, NULL);
		slock->next = devmap_slist;
		devmap_slist = slock;
	} else
		kmem_free(tmp, sizeof (struct devmap_softlock));

	mutex_enter(&slock->lock);
	slock->refcnt++;
	mutex_exit(&slock->lock);
	mutex_exit(&devmap_slock);

	return (slock);
}

/*
 * Wake up processes that sleep on softlocked.
 * Free dh_softlock if refcnt is 0.
 */
static void
devmap_softlock_rele(devmap_handle_t *dhp)
{
	struct devmap_softlock *slock = dhp->dh_softlock;
	struct devmap_softlock *tmp;
	struct devmap_softlock *parent;

	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_SOFTLOCK_RELE,
	    "devmap_softlock_rele:start");

	mutex_enter(&devmap_slock);
	mutex_enter(&slock->lock);

	ASSERT(slock->refcnt > 0);

	slock->refcnt--;

	/*
	 * If no one is using the device, free up the slock data.
	 */
	if (slock->refcnt == 0) {
		slock->softlocked = 0;
		cv_signal(&slock->cv);

		if (devmap_slist == slock)
			devmap_slist = slock->next;
		else {
			parent = devmap_slist;
			for (tmp = devmap_slist->next; tmp != NULL;
			    tmp = tmp->next) {
				if (tmp == slock) {
					parent->next = tmp->next;
					break;
				}
				parent = tmp;
			}
		}
		mutex_exit(&slock->lock);
		mutex_destroy(&slock->lock);
		cv_destroy(&slock->cv);
		kmem_free(slock, sizeof (struct devmap_softlock));
	} else
		mutex_exit(&slock->lock);

	mutex_exit(&devmap_slock);
}

/*
 * Wake up processes that sleep on dh_ctx->locked.
 * Free dh_ctx if refcnt is 0.
 */
static void
devmap_ctx_rele(devmap_handle_t *dhp)
{
	struct devmap_ctx *devctx = dhp->dh_ctx;
	struct devmap_ctx *tmp;
	struct devmap_ctx *parent;
	timeout_id_t tid;

	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_CTX_RELE,
	    "devmap_ctx_rele:start");

	mutex_enter(&devmapctx_lock);
	mutex_enter(&devctx->lock);

	ASSERT(devctx->refcnt > 0);

	devctx->refcnt--;

	/*
	 * If no one is using the device, free up the devctx data.
	 */
	if (devctx->refcnt == 0) {
		/*
		 * Untimeout any threads using this mapping as they are about
		 * to go away.
		 */
		if (devctx->timeout != 0) {
			TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_CTX_RELE_CK1,
			    "devmap_ctx_rele:untimeout ctx->timeout");

			tid = devctx->timeout;
			mutex_exit(&devctx->lock);
			(void) untimeout(tid);
			mutex_enter(&devctx->lock);
		}

		devctx->oncpu = 0;
		cv_signal(&devctx->cv);

		if (devmapctx_list == devctx)
			devmapctx_list = devctx->next;
		else {
			parent = devmapctx_list;
			for (tmp = devmapctx_list->next; tmp != NULL;
			    tmp = tmp->next) {
				if (tmp == devctx) {
					parent->next = tmp->next;
					break;
				}
				parent = tmp;
			}
		}
		mutex_exit(&devctx->lock);
		mutex_destroy(&devctx->lock);
		cv_destroy(&devctx->cv);
		kmem_free(devctx, sizeof (struct devmap_ctx));
	} else
		mutex_exit(&devctx->lock);

	mutex_exit(&devmapctx_lock);
}

/*
 * devmap_load:
 *			Marks a segdev segment or pages if offset->offset+len
 *			is not the entire segment as nointercept and faults in
 *			the pages in the range offset -> offset+len.
 */
int
devmap_load(devmap_cookie_t dhc, offset_t offset, size_t len, uint_t type,
    uint_t rw)
{
	devmap_handle_t *dhp = (devmap_handle_t *)dhc;
	struct as *asp = dhp->dh_seg->s_as;
	caddr_t	addr;
	ulong_t	size;
	ssize_t	soff;	/* offset from the beginning of the segment */
	int rc;

	TRACE_3(TR_FAC_DEVMAP, TR_DEVMAP_LOAD,
	    "devmap_load:start dhp=%p offset=%llx len=%lx",
	    (void *)dhp, offset, len);

	DEBUGF(7, (CE_CONT, "devmap_load: dhp %p offset %llx len %lx\n",
	    (void *)dhp, offset, len));

	/*
	 *	Hat layer only supports devload to process' context for which
	 *	the as lock is held. Verify here and return error if drivers
	 *	inadvertently call devmap_load on a wrong devmap handle.
	 */
	if ((asp != &kas) && !AS_LOCK_HELD(asp, &asp->a_lock))
		return (FC_MAKE_ERR(EINVAL));

	soff = (ssize_t)(offset - dhp->dh_uoff);
	soff = round_down_p2(soff, PAGESIZE);
	if (soff < 0 || soff >= dhp->dh_len)
		return (FC_MAKE_ERR(EINVAL));

	/*
	 * Address and size must be page aligned.  Len is set to the
	 * number of bytes in the number of pages that are required to
	 * support len.  Offset is set to the byte offset of the first byte
	 * of the page that contains offset.
	 */
	len = round_up_p2(len, PAGESIZE);

	/*
	 * If len == 0, then calculate the size by getting
	 * the number of bytes from offset to the end of the segment.
	 */
	if (len == 0)
		size = dhp->dh_len - soff;
	else {
		size = len;
		if ((soff + size) > dhp->dh_len)
			return (FC_MAKE_ERR(EINVAL));
	}

	/*
	 * The address is offset bytes from the base address of
	 * the segment.
	 */
	addr = (caddr_t)(soff + dhp->dh_uvaddr);

	HOLD_DHP_LOCK(dhp);
	rc = segdev_faultpages(asp->a_hat,
	    dhp->dh_seg, addr, size, type, rw, dhp);
	RELE_DHP_LOCK(dhp);
	return (rc);
}

int
devmap_setup(dev_t dev, offset_t off, struct as *as, caddr_t *addrp,
    size_t len, uint_t prot, uint_t maxprot, uint_t flags, struct cred *cred)
{
	register devmap_handle_t *dhp;
	int (*devmap)(dev_t, devmap_cookie_t, offset_t, size_t,
	    size_t *, uint_t);
	int (*mmap)(dev_t, off_t, int);
	struct devmap_callback_ctl *callbackops;
	devmap_handle_t *dhp_head = NULL;
	devmap_handle_t *dhp_prev = NULL;
	devmap_handle_t *dhp_curr;
	caddr_t addr;
	int map_flag;
	int ret;
	ulong_t total_len;
	size_t map_len;
	size_t resid_len = len;
	offset_t map_off = off;
	struct devmap_softlock *slock = NULL;

#ifdef lint
	cred = cred;
#endif

	TRACE_2(TR_FAC_DEVMAP, TR_DEVMAP_SETUP,
	    "devmap_setup:start off=%llx len=%lx", off, len);
	DEBUGF(3, (CE_CONT, "devmap_setup: off %llx len %lx\n",
	    off, len));

	devmap = devopsp[getmajor(dev)]->devo_cb_ops->cb_devmap;
	mmap = devopsp[getmajor(dev)]->devo_cb_ops->cb_mmap;

	/*
	 * driver must provide devmap(9E) entry point in cb_ops to use the
	 * devmap framework.
	 */
	if (devmap == NULL || devmap == nulldev || devmap == nodev)
		return (EINVAL);

	/*
	 * To protect from an inadvertent entry because the devmap entry point
	 * is not NULL, return error if D_DEVMAP bit is not set in cb_flag and
	 * mmap is NULL.
	 */
	map_flag = devopsp[getmajor(dev)]->devo_cb_ops->cb_flag;
	if ((map_flag & D_DEVMAP) == 0 && (mmap == NULL || mmap == nulldev))
		return (EINVAL);

	/*
	 * devmap allows mmap(2) to map multiple registers.
	 * one devmap_handle is created for each register mapped.
	 */
	for (total_len = 0; total_len < len; total_len += map_len) {
		dhp = kmem_zalloc(sizeof (devmap_handle_t), KM_SLEEP);

		if (dhp_prev != NULL)
			dhp_prev->dh_next = dhp;
		else
			dhp_head = dhp;
		dhp_prev = dhp;

		dhp->dh_prot = prot;
		dhp->dh_orig_maxprot = dhp->dh_maxprot = maxprot;
		dhp->dh_dev = dev;
		dhp->dh_timeout_length = CTX_TIMEOUT_VALUE;
		dhp->dh_uoff = map_off;

		/*
		 * Get mapping specific info from
		 * the driver, such as rnumber, roff, len, callbackops,
		 * accattrp and, if the mapping is for kernel memory,
		 * ddi_umem_cookie.
		 */
		if ((ret = cdev_devmap(dev, dhp, map_off,
		    resid_len, &map_len, get_udatamodel())) != 0) {
			free_devmap_handle(dhp_head);
			return (ENXIO);
		}

		if (map_len & PAGEOFFSET) {
			free_devmap_handle(dhp_head);
			return (EINVAL);
		}

		callbackops = &dhp->dh_callbackops;

		if ((callbackops->devmap_access == NULL) ||
		    (callbackops->devmap_access == nulldev) ||
		    (callbackops->devmap_access == nodev)) {
			/*
			 * Normally devmap does not support MAP_PRIVATE unless
			 * the drivers provide a valid devmap_access routine.
			 */
			if ((flags & MAP_PRIVATE) != 0) {
				free_devmap_handle(dhp_head);
				return (EINVAL);
			}
		} else {
			/*
			 * Initialize dhp_softlock and dh_ctx if the drivers
			 * provide devmap_access.
			 */
			dhp->dh_softlock = devmap_softlock_init(dev,
			    (ulong_t)callbackops->devmap_access);
			dhp->dh_ctx = devmap_ctxinit(dev,
			    (ulong_t)callbackops->devmap_access);

			/*
			 * segdev_fault can only work when all
			 * dh_softlock in a multi-dhp mapping
			 * are same. see comments in segdev_fault
			 * This code keeps track of the first
			 * dh_softlock allocated in slock and
			 * compares all later allocations and if
			 * not similar, returns an error.
			 */
			if (slock == NULL)
				slock = dhp->dh_softlock;
			if (slock != dhp->dh_softlock) {
				free_devmap_handle(dhp_head);
				return (ENOTSUP);
			}
		}

		map_off += map_len;
		resid_len -= map_len;
	}

	/*
	 * get the user virtual address and establish the mapping between
	 * uvaddr and device physical address.
	 */
	if ((ret = devmap_device(dhp_head, as, addrp, off, len, flags))
	    != 0) {
		/*
		 * free devmap handles if error during the mapping.
		 */
		free_devmap_handle(dhp_head);

		return (ret);
	}

	/*
	 * call the driver's devmap_map callback to do more after the mapping,
	 * such as to allocate driver private data for context management.
	 */
	dhp = dhp_head;
	map_off = off;
	addr = *addrp;
	while (dhp != NULL) {
		callbackops = &dhp->dh_callbackops;
		dhp->dh_uvaddr = addr;
		dhp_curr = dhp;
		if (callbackops->devmap_map != NULL) {
			ret = (*callbackops->devmap_map)((devmap_cookie_t)dhp,
			    dev, flags, map_off,
			    dhp->dh_len, &dhp->dh_pvtp);
			if (ret != 0) {
				struct segdev_data *sdp;

				/*
				 * call driver's devmap_unmap entry point
				 * to free driver resources.
				 */
				dhp = dhp_head;
				map_off = off;
				while (dhp != dhp_curr) {
					callbackops = &dhp->dh_callbackops;
					if (callbackops->devmap_unmap != NULL) {
						(*callbackops->devmap_unmap)(
						    dhp, dhp->dh_pvtp,
						    map_off, dhp->dh_len,
						    NULL, NULL, NULL, NULL);
					}
					map_off += dhp->dh_len;
					dhp = dhp->dh_next;
				}
				sdp = dhp_head->dh_seg->s_data;
				sdp->devmap_data = NULL;
				free_devmap_handle(dhp_head);
				return (ENXIO);
			}
		}
		map_off += dhp->dh_len;
		addr += dhp->dh_len;
		dhp = dhp->dh_next;
	}

	return (0);
}

int
ddi_devmap_segmap(dev_t dev, off_t off, ddi_as_handle_t as, caddr_t *addrp,
    off_t len, uint_t prot, uint_t maxprot, uint_t flags, struct cred *cred)
{
	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_SEGMAP,
	    "devmap_segmap:start");
	return (devmap_setup(dev, (offset_t)off, (struct as *)as, addrp,
	    (size_t)len, prot, maxprot, flags, cred));
}

/*
 * Called from devmap_devmem_setup/remap to see if can use large pages for
 * this device mapping.
 * Also calculate the max. page size for this mapping.
 * this page size will be used in fault routine for
 * optimal page size calculations.
 */
static void
devmap_devmem_large_page_setup(devmap_handle_t *dhp)
{
	ASSERT(dhp_is_devmem(dhp));
	dhp->dh_mmulevel = 0;

	/*
	 * use large page size only if:
	 *  1. device memory.
	 *  2. mmu supports multiple page sizes,
	 *  3. Driver did not disallow it
	 *  4. dhp length is at least as big as the large pagesize
	 *  5. the uvaddr and pfn are large pagesize aligned
	 */
	if (page_num_pagesizes() > 1 &&
	    !(dhp->dh_flags & (DEVMAP_USE_PAGESIZE | DEVMAP_MAPPING_INVALID))) {
		ulong_t base;
		int level;

		base = (ulong_t)ptob(dhp->dh_pfn);
		for (level = 1; level < page_num_pagesizes(); level++) {
			size_t pgsize = page_get_pagesize(level);
			if ((dhp->dh_len < pgsize) ||
			    (!VA_PA_PGSIZE_ALIGNED((uintptr_t)dhp->dh_uvaddr,
			    base, pgsize))) {
				break;
			}
		}
		dhp->dh_mmulevel = level - 1;
	}
	if (dhp->dh_mmulevel > 0) {
		dhp->dh_flags |= DEVMAP_FLAG_LARGE;
	} else {
		dhp->dh_flags &= ~DEVMAP_FLAG_LARGE;
	}
}

/*
 * Called by driver devmap routine to pass device specific info to
 * the framework.    used for device memory mapping only.
 */
int
devmap_devmem_setup(devmap_cookie_t dhc, dev_info_t *dip,
    struct devmap_callback_ctl *callbackops, uint_t rnumber, offset_t roff,
    size_t len, uint_t maxprot, uint_t flags, ddi_device_acc_attr_t *accattrp)
{
	devmap_handle_t *dhp = (devmap_handle_t *)dhc;
	ddi_acc_handle_t handle;
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	int err;

	TRACE_4(TR_FAC_DEVMAP, TR_DEVMAP_DEVMEM_SETUP,
	    "devmap_devmem_setup:start dhp=%p offset=%llx rnum=%d len=%lx",
	    (void *)dhp, roff, rnumber, (uint_t)len);
	DEBUGF(2, (CE_CONT, "devmap_devmem_setup: dhp %p offset %llx "
	    "rnum %d len %lx\n", (void *)dhp, roff, rnumber, len));

	/*
	 * First to check if this function has been called for this dhp.
	 */
	if (dhp->dh_flags & DEVMAP_SETUP_DONE)
		return (DDI_FAILURE);

	if ((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) != dhp->dh_prot)
		return (DDI_FAILURE);

	if (flags & DEVMAP_MAPPING_INVALID) {
		/*
		 * Don't go up the tree to get pfn if the driver specifies
		 * DEVMAP_MAPPING_INVALID in flags.
		 *
		 * If DEVMAP_MAPPING_INVALID is specified, we have to grant
		 * remap permission.
		 */
		if (!(flags & DEVMAP_ALLOW_REMAP)) {
			return (DDI_FAILURE);
		}
		dhp->dh_pfn = PFN_INVALID;
	} else {
		handle = impl_acc_hdl_alloc(KM_SLEEP, NULL);
		if (handle == NULL)
			return (DDI_FAILURE);

		hp = impl_acc_hdl_get(handle);
		hp->ah_vers = VERS_ACCHDL;
		hp->ah_dip = dip;
		hp->ah_rnumber = rnumber;
		hp->ah_offset = roff;
		hp->ah_len = len;
		if (accattrp != NULL)
			hp->ah_acc = *accattrp;

		mr.map_op = DDI_MO_MAP_LOCKED;
		mr.map_type = DDI_MT_RNUMBER;
		mr.map_obj.rnumber = rnumber;
		mr.map_prot = maxprot & dhp->dh_orig_maxprot;
		mr.map_flags = DDI_MF_DEVICE_MAPPING;
		mr.map_handlep = hp;
		mr.map_vers = DDI_MAP_VERSION;

		/*
		 * up the device tree to get pfn.
		 * The rootnex_map_regspec() routine in nexus drivers has been
		 * modified to return pfn if map_flags is DDI_MF_DEVICE_MAPPING.
		 */
		err = ddi_map(dip, &mr, roff, len, (caddr_t *)&dhp->dh_pfn);
		dhp->dh_hat_attr = hp->ah_hat_flags;
		impl_acc_hdl_free(handle);

		if (err)
			return (DDI_FAILURE);
	}
	/* Should not be using devmem setup for memory pages */
	ASSERT(!pf_is_memory(dhp->dh_pfn));

	/* Only some of the flags bits are settable by the driver */
	dhp->dh_flags |= (flags & DEVMAP_SETUP_FLAGS);
	dhp->dh_len = ptob(btopr(len));

	dhp->dh_cookie = DEVMAP_DEVMEM_COOKIE;
	dhp->dh_roff = ptob(btop(roff));

	/* setup the dh_mmulevel and DEVMAP_FLAG_LARGE */
	devmap_devmem_large_page_setup(dhp);
	dhp->dh_maxprot = maxprot & dhp->dh_orig_maxprot;
	ASSERT((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) == dhp->dh_prot);


	if (callbackops != NULL) {
		bcopy(callbackops, &dhp->dh_callbackops,
		    sizeof (struct devmap_callback_ctl));
	}

	/*
	 * Initialize dh_lock if we want to do remap.
	 */
	if (dhp->dh_flags & DEVMAP_ALLOW_REMAP) {
		mutex_init(&dhp->dh_lock, NULL, MUTEX_DEFAULT, NULL);
		dhp->dh_flags |= DEVMAP_LOCK_INITED;
	}

	dhp->dh_flags |= DEVMAP_SETUP_DONE;

	return (DDI_SUCCESS);
}

int
devmap_devmem_remap(devmap_cookie_t dhc, dev_info_t *dip,
    uint_t rnumber, offset_t roff, size_t len, uint_t maxprot,
    uint_t flags, ddi_device_acc_attr_t *accattrp)
{
	devmap_handle_t *dhp = (devmap_handle_t *)dhc;
	ddi_acc_handle_t handle;
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	pfn_t	pfn;
	uint_t	hat_flags;
	int	err;

	TRACE_4(TR_FAC_DEVMAP, TR_DEVMAP_DEVMEM_REMAP,
	    "devmap_devmem_setup:start dhp=%p offset=%llx rnum=%d len=%lx",
	    (void *)dhp, roff, rnumber, (uint_t)len);
	DEBUGF(2, (CE_CONT, "devmap_devmem_remap: dhp %p offset %llx "
	    "rnum %d len %lx\n", (void *)dhp, roff, rnumber, len));

	/*
	 * Return failure if setup has not been done or no remap permission
	 * has been granted during the setup.
	 */
	if ((dhp->dh_flags & DEVMAP_SETUP_DONE) == 0 ||
	    (dhp->dh_flags & DEVMAP_ALLOW_REMAP) == 0)
		return (DDI_FAILURE);

	/* Only DEVMAP_MAPPING_INVALID flag supported for remap */
	if ((flags != 0) && (flags != DEVMAP_MAPPING_INVALID))
		return (DDI_FAILURE);

	if ((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) != dhp->dh_prot)
		return (DDI_FAILURE);

	if (!(flags & DEVMAP_MAPPING_INVALID)) {
		handle = impl_acc_hdl_alloc(KM_SLEEP, NULL);
		if (handle == NULL)
			return (DDI_FAILURE);
	}

	HOLD_DHP_LOCK(dhp);

	/*
	 * Unload the old mapping, so next fault will setup the new mappings
	 * Do this while holding the dhp lock so other faults dont reestablish
	 * the mappings
	 */
	hat_unload(dhp->dh_seg->s_as->a_hat, dhp->dh_uvaddr,
	    dhp->dh_len, HAT_UNLOAD|HAT_UNLOAD_OTHER);

	if (flags & DEVMAP_MAPPING_INVALID) {
		dhp->dh_flags |= DEVMAP_MAPPING_INVALID;
		dhp->dh_pfn = PFN_INVALID;
	} else {
		/* clear any prior DEVMAP_MAPPING_INVALID flag */
		dhp->dh_flags &= ~DEVMAP_MAPPING_INVALID;
		hp = impl_acc_hdl_get(handle);
		hp->ah_vers = VERS_ACCHDL;
		hp->ah_dip = dip;
		hp->ah_rnumber = rnumber;
		hp->ah_offset = roff;
		hp->ah_len = len;
		if (accattrp != NULL)
			hp->ah_acc = *accattrp;

		mr.map_op = DDI_MO_MAP_LOCKED;
		mr.map_type = DDI_MT_RNUMBER;
		mr.map_obj.rnumber = rnumber;
		mr.map_prot = maxprot & dhp->dh_orig_maxprot;
		mr.map_flags = DDI_MF_DEVICE_MAPPING;
		mr.map_handlep = hp;
		mr.map_vers = DDI_MAP_VERSION;

		/*
		 * up the device tree to get pfn.
		 * The rootnex_map_regspec() routine in nexus drivers has been
		 * modified to return pfn if map_flags is DDI_MF_DEVICE_MAPPING.
		 */
		err = ddi_map(dip, &mr, roff, len, (caddr_t *)&pfn);
		hat_flags = hp->ah_hat_flags;
		impl_acc_hdl_free(handle);
		if (err) {
			RELE_DHP_LOCK(dhp);
			return (DDI_FAILURE);
		}
		/*
		 * Store result of ddi_map first in local variables, as we do
		 * not want to overwrite the existing dhp with wrong data.
		 */
		dhp->dh_pfn = pfn;
		dhp->dh_hat_attr = hat_flags;
	}

	/* clear the large page size flag */
	dhp->dh_flags &= ~DEVMAP_FLAG_LARGE;

	dhp->dh_cookie = DEVMAP_DEVMEM_COOKIE;
	dhp->dh_roff = ptob(btop(roff));

	/* setup the dh_mmulevel and DEVMAP_FLAG_LARGE */
	devmap_devmem_large_page_setup(dhp);
	dhp->dh_maxprot = maxprot & dhp->dh_orig_maxprot;
	ASSERT((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) == dhp->dh_prot);

	RELE_DHP_LOCK(dhp);
	return (DDI_SUCCESS);
}

/*
 * called by driver devmap routine to pass kernel virtual address  mapping
 * info to the framework.    used only for kernel memory
 * allocated from ddi_umem_alloc().
 */
int
devmap_umem_setup(devmap_cookie_t dhc, dev_info_t *dip,
    struct devmap_callback_ctl *callbackops, ddi_umem_cookie_t cookie,
    offset_t off, size_t len, uint_t maxprot, uint_t flags,
    ddi_device_acc_attr_t *accattrp)
{
	devmap_handle_t *dhp = (devmap_handle_t *)dhc;
	struct ddi_umem_cookie *cp = (struct ddi_umem_cookie *)cookie;

#ifdef lint
	dip = dip;
#endif

	TRACE_4(TR_FAC_DEVMAP, TR_DEVMAP_UMEM_SETUP,
	    "devmap_umem_setup:start dhp=%p offset=%llx cookie=%p len=%lx",
	    (void *)dhp, off, cookie, len);
	DEBUGF(2, (CE_CONT, "devmap_umem_setup: dhp %p offset %llx "
	    "cookie %p len %lx\n", (void *)dhp, off, (void *)cookie, len));

	if (cookie == NULL)
		return (DDI_FAILURE);

	/* For UMEM_TRASH, this restriction is not needed */
	if ((off + len) > cp->size)
		return (DDI_FAILURE);

	/* check if the cache attributes are supported */
	if (i_ddi_check_cache_attr(flags) == B_FALSE)
		return (DDI_FAILURE);

	/*
	 * First to check if this function has been called for this dhp.
	 */
	if (dhp->dh_flags & DEVMAP_SETUP_DONE)
		return (DDI_FAILURE);

	if ((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) != dhp->dh_prot)
		return (DDI_FAILURE);

	if (flags & DEVMAP_MAPPING_INVALID) {
		/*
		 * If DEVMAP_MAPPING_INVALID is specified, we have to grant
		 * remap permission.
		 */
		if (!(flags & DEVMAP_ALLOW_REMAP)) {
			return (DDI_FAILURE);
		}
	} else {
		dhp->dh_cookie = cookie;
		dhp->dh_roff = ptob(btop(off));
		dhp->dh_cvaddr = cp->cvaddr + dhp->dh_roff;
		/* set HAT cache attributes */
		i_ddi_cacheattr_to_hatacc(flags, &dhp->dh_hat_attr);
		/* set HAT endianess attributes */
		i_ddi_devacc_to_hatacc(accattrp, &dhp->dh_hat_attr);
	}

	/*
	 * The default is _not_ to pass HAT_LOAD_NOCONSIST to hat_devload();
	 * we pass HAT_LOAD_NOCONSIST _only_ in cases where hat tries to
	 * create consistent mappings but our intention was to create
	 * non-consistent mappings.
	 *
	 * DEVMEM: hat figures it out it's DEVMEM and creates non-consistent
	 * mappings.
	 *
	 * kernel exported memory: hat figures it out it's memory and always
	 * creates consistent mappings.
	 *
	 * /dev/mem: non-consistent mappings. See comments in common/io/mem.c
	 *
	 * /dev/kmem: consistent mappings are created unless they are
	 * MAP_FIXED. We _explicitly_ tell hat to create non-consistent
	 * mappings by passing HAT_LOAD_NOCONSIST in case of MAP_FIXED
	 * mappings of /dev/kmem. See common/io/mem.c
	 */

	/* Only some of the flags bits are settable by the driver */
	dhp->dh_flags |= (flags & DEVMAP_SETUP_FLAGS);

	dhp->dh_len = ptob(btopr(len));
	dhp->dh_maxprot = maxprot & dhp->dh_orig_maxprot;
	ASSERT((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) == dhp->dh_prot);

	if (callbackops != NULL) {
		bcopy(callbackops, &dhp->dh_callbackops,
		    sizeof (struct devmap_callback_ctl));
	}
	/*
	 * Initialize dh_lock if we want to do remap.
	 */
	if (dhp->dh_flags & DEVMAP_ALLOW_REMAP) {
		mutex_init(&dhp->dh_lock, NULL, MUTEX_DEFAULT, NULL);
		dhp->dh_flags |= DEVMAP_LOCK_INITED;
	}

	dhp->dh_flags |= DEVMAP_SETUP_DONE;

	return (DDI_SUCCESS);
}

int
devmap_umem_remap(devmap_cookie_t dhc, dev_info_t *dip,
    ddi_umem_cookie_t cookie, offset_t off, size_t len, uint_t maxprot,
    uint_t flags, ddi_device_acc_attr_t *accattrp)
{
	devmap_handle_t *dhp = (devmap_handle_t *)dhc;
	struct ddi_umem_cookie *cp = (struct ddi_umem_cookie *)cookie;

	TRACE_4(TR_FAC_DEVMAP, TR_DEVMAP_UMEM_REMAP,
	    "devmap_umem_remap:start dhp=%p offset=%llx cookie=%p len=%lx",
	    (void *)dhp, off, cookie, len);
	DEBUGF(2, (CE_CONT, "devmap_umem_remap: dhp %p offset %llx "
	    "cookie %p len %lx\n", (void *)dhp, off, (void *)cookie, len));

#ifdef lint
	dip = dip;
	accattrp = accattrp;
#endif
	/*
	 * Reture failure if setup has not been done or no remap permission
	 * has been granted during the setup.
	 */
	if ((dhp->dh_flags & DEVMAP_SETUP_DONE) == 0 ||
	    (dhp->dh_flags & DEVMAP_ALLOW_REMAP) == 0)
		return (DDI_FAILURE);

	/* No flags supported for remap yet */
	if (flags != 0)
		return (DDI_FAILURE);

	/* check if the cache attributes are supported */
	if (i_ddi_check_cache_attr(flags) == B_FALSE)
		return (DDI_FAILURE);

	if ((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) != dhp->dh_prot)
		return (DDI_FAILURE);

	/* For UMEM_TRASH, this restriction is not needed */
	if ((off + len) > cp->size)
		return (DDI_FAILURE);

	HOLD_DHP_LOCK(dhp);
	/*
	 * Unload the old mapping, so next fault will setup the new mappings
	 * Do this while holding the dhp lock so other faults dont reestablish
	 * the mappings
	 */
	hat_unload(dhp->dh_seg->s_as->a_hat, dhp->dh_uvaddr,
	    dhp->dh_len, HAT_UNLOAD|HAT_UNLOAD_OTHER);

	dhp->dh_cookie = cookie;
	dhp->dh_roff = ptob(btop(off));
	dhp->dh_cvaddr = cp->cvaddr + dhp->dh_roff;
	/* set HAT cache attributes */
	i_ddi_cacheattr_to_hatacc(flags, &dhp->dh_hat_attr);
	/* set HAT endianess attributes */
	i_ddi_devacc_to_hatacc(accattrp, &dhp->dh_hat_attr);

	/* clear the large page size flag */
	dhp->dh_flags &= ~DEVMAP_FLAG_LARGE;

	dhp->dh_maxprot = maxprot & dhp->dh_orig_maxprot;
	ASSERT((dhp->dh_prot & dhp->dh_orig_maxprot & maxprot) == dhp->dh_prot);
	RELE_DHP_LOCK(dhp);
	return (DDI_SUCCESS);
}

/*
 * to set timeout value for the driver's context management callback, e.g.
 * devmap_access().
 */
void
devmap_set_ctx_timeout(devmap_cookie_t dhc, clock_t ticks)
{
	devmap_handle_t *dhp = (devmap_handle_t *)dhc;

	TRACE_2(TR_FAC_DEVMAP, TR_DEVMAP_SET_CTX_TIMEOUT,
	    "devmap_set_ctx_timeout:start dhp=%p ticks=%x",
	    (void *)dhp, ticks);
	dhp->dh_timeout_length = ticks;
}

int
devmap_default_access(devmap_cookie_t dhp, void *pvtp, offset_t off,
    size_t len, uint_t type, uint_t rw)
{
#ifdef lint
	pvtp = pvtp;
#endif

	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_DEFAULT_ACCESS,
	    "devmap_default_access:start");
	return (devmap_load(dhp, off, len, type, rw));
}

/*
 * segkmem_alloc() wrapper to allocate memory which is both
 * non-relocatable (for DR) and sharelocked, since the rest
 * of this segment driver requires it.
 */
static void *
devmap_alloc_pages(vmem_t *vmp, size_t size, int vmflag)
{
	ASSERT(vmp != NULL);
	ASSERT(kvseg.s_base != NULL);
	vmflag |= (VM_NORELOC | SEGKMEM_SHARELOCKED);
	return (segkmem_alloc(vmp, size, vmflag));
}

/*
 * This is where things are a bit incestuous with seg_kmem: unlike
 * seg_kp, seg_kmem does not keep its pages long-term sharelocked, so
 * we need to do a bit of a dance around that to prevent duplication of
 * code until we decide to bite the bullet and implement a new kernel
 * segment for driver-allocated memory that is exported to user space.
 */
static void
devmap_free_pages(vmem_t *vmp, void *inaddr, size_t size)
{
	page_t *pp;
	caddr_t addr = inaddr;
	caddr_t eaddr;
	pgcnt_t npages = btopr(size);

	ASSERT(vmp != NULL);
	ASSERT(kvseg.s_base != NULL);
	ASSERT(((uintptr_t)addr & PAGEOFFSET) == 0);

	hat_unload(kas.a_hat, addr, size, HAT_UNLOAD_UNLOCK);

	for (eaddr = addr + size; addr < eaddr; addr += PAGESIZE) {
		/*
		 * Use page_find() instead of page_lookup() to find the page
		 * since we know that it is hashed and has a shared lock.
		 */
		pp = page_find(&kvp, (u_offset_t)(uintptr_t)addr);

		if (pp == NULL)
			panic("devmap_free_pages: page not found");
		if (!page_tryupgrade(pp)) {
			page_unlock(pp);
			pp = page_lookup(&kvp, (u_offset_t)(uintptr_t)addr,
			    SE_EXCL);
			if (pp == NULL)
				panic("devmap_free_pages: page already freed");
		}
		/* Clear p_lckcnt so page_destroy() doesn't update availrmem */
		pp->p_lckcnt = 0;
		page_destroy(pp, 0);
	}
	page_unresv(npages);

	if (vmp != NULL)
		vmem_free(vmp, inaddr, size);
}

/*
 * devmap_umem_alloc_np() replaces kmem_zalloc() as the method for
 * allocating non-pageable kmem in response to a ddi_umem_alloc()
 * default request. For now we allocate our own pages and we keep
 * them long-term sharelocked, since: A) the fault routines expect the
 * memory to already be locked; B) pageable umem is already long-term
 * locked; C) it's a lot of work to make it otherwise, particularly
 * since the nexus layer expects the pages to never fault. An RFE is to
 * not keep the pages long-term locked, but instead to be able to
 * take faults on them and simply look them up in kvp in case we
 * fault on them. Even then, we must take care not to let pageout
 * steal them from us since the data must remain resident; if we
 * do this we must come up with some way to pin the pages to prevent
 * faults while a driver is doing DMA to/from them.
 */
static void *
devmap_umem_alloc_np(size_t size, size_t flags)
{
	void *buf;
	int vmflags = (flags & DDI_UMEM_NOSLEEP)? VM_NOSLEEP : VM_SLEEP;

	buf = vmem_alloc(umem_np_arena, size, vmflags);
	if (buf != NULL)
		bzero(buf, size);
	return (buf);
}

static void
devmap_umem_free_np(void *addr, size_t size)
{
	vmem_free(umem_np_arena, addr, size);
}

/*
 * allocate page aligned kernel memory for exporting to user land.
 * The devmap framework will use the cookie allocated by ddi_umem_alloc()
 * to find a user virtual address that is in same color as the address
 * allocated here.
 */
void *
ddi_umem_alloc(size_t size, int flags, ddi_umem_cookie_t *cookie)
{
	register size_t len = ptob(btopr(size));
	void *buf = NULL;
	struct ddi_umem_cookie *cp;
	int iflags = 0;

	*cookie = NULL;

	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_UMEM_ALLOC,
	    "devmap_umem_alloc:start");
	if (len == 0)
		return ((void *)NULL);

	/*
	 * allocate cookie
	 */
	if ((cp = kmem_zalloc(sizeof (struct ddi_umem_cookie),
	    flags & DDI_UMEM_NOSLEEP ? KM_NOSLEEP : KM_SLEEP)) == NULL) {
		ASSERT(flags & DDI_UMEM_NOSLEEP);
		return ((void *)NULL);
	}

	if (flags & DDI_UMEM_PAGEABLE) {
		/* Only one of the flags is allowed */
		ASSERT(!(flags & DDI_UMEM_TRASH));
		/* initialize resource with 0 */
		iflags = KPD_ZERO;

		/*
		 * to allocate unlocked pageable memory, use segkp_get() to
		 * create a segkp segment.  Since segkp can only service kas,
		 * other segment drivers such as segdev have to do
		 * as_fault(segkp, SOFTLOCK) in its fault routine,
		 */
		if (flags & DDI_UMEM_NOSLEEP)
			iflags |= KPD_NOWAIT;

		if ((buf = segkp_get(segkp, len, iflags)) == NULL) {
			kmem_free(cp, sizeof (struct ddi_umem_cookie));
			return ((void *)NULL);
		}
		cp->type = KMEM_PAGEABLE;
		mutex_init(&cp->lock, NULL, MUTEX_DEFAULT, NULL);
		cp->locked = 0;
	} else if (flags & DDI_UMEM_TRASH) {
		/* Only one of the flags is allowed */
		ASSERT(!(flags & DDI_UMEM_PAGEABLE));
		cp->type = UMEM_TRASH;
		buf = NULL;
	} else {
		if ((buf = devmap_umem_alloc_np(len, flags)) == NULL) {
			kmem_free(cp, sizeof (struct ddi_umem_cookie));
			return ((void *)NULL);
		}

		cp->type = KMEM_NON_PAGEABLE;
	}

	/*
	 * need to save size here.  size will be used when
	 * we do kmem_free.
	 */
	cp->size = len;
	cp->cvaddr = (caddr_t)buf;

	*cookie =  (void *)cp;
	return (buf);
}

void
ddi_umem_free(ddi_umem_cookie_t cookie)
{
	struct ddi_umem_cookie *cp;

	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_UMEM_FREE,
	    "devmap_umem_free:start");

	/*
	 * if cookie is NULL, no effects on the system
	 */
	if (cookie == NULL)
		return;

	cp = (struct ddi_umem_cookie *)cookie;

	switch (cp->type) {
	case KMEM_PAGEABLE :
		ASSERT(cp->cvaddr != NULL && cp->size != 0);
		/*
		 * Check if there are still any pending faults on the cookie
		 * while the driver is deleting it,
		 * XXX - could change to an ASSERT but wont catch errant drivers
		 */
		mutex_enter(&cp->lock);
		if (cp->locked) {
			mutex_exit(&cp->lock);
			panic("ddi_umem_free for cookie with pending faults %p",
			    (void *)cp);
			return;
		}

		segkp_release(segkp, cp->cvaddr);

		/*
		 * release mutex associated with this cookie.
		 */
		mutex_destroy(&cp->lock);
		break;
	case KMEM_NON_PAGEABLE :
		ASSERT(cp->cvaddr != NULL && cp->size != 0);
		devmap_umem_free_np(cp->cvaddr, cp->size);
		break;
	case UMEM_TRASH :
		break;
	case UMEM_LOCKED :
		/* Callers should use ddi_umem_unlock for this type */
		ddi_umem_unlock(cookie);
		/* Frees the cookie too */
		return;
	default:
		/* panic so we can diagnose the underlying cause */
		panic("ddi_umem_free: illegal cookie type 0x%x\n",
		    cp->type);
	}

	kmem_free(cookie, sizeof (struct ddi_umem_cookie));
}


static int
segdev_getmemid(struct seg *seg, caddr_t addr, memid_t *memidp)
{
	struct segdev_data *sdp = (struct segdev_data *)seg->s_data;

	/*
	 * It looks as if it is always mapped shared
	 */
	TRACE_0(TR_FAC_DEVMAP, TR_DEVMAP_GETMEMID,
	    "segdev_getmemid:start");
	memidp->val[0] = (uintptr_t)VTOCVP(sdp->vp);
	memidp->val[1] = sdp->offset + (uintptr_t)(addr - seg->s_base);
	return (0);
}

/*ARGSUSED*/
static lgrp_mem_policy_info_t *
segdev_getpolicy(struct seg *seg, caddr_t addr)
{
	return (NULL);
}

/*ARGSUSED*/
static int
segdev_capable(struct seg *seg, segcapability_t capability)
{
	return (0);
}

/*
 * ddi_umem_alloc() non-pageable quantum cache max size.
 * This is just a SWAG.
 */
#define	DEVMAP_UMEM_QUANTUM	(8*PAGESIZE)

/*
 * Initialize seg_dev from boot. This routine sets up the trash page
 * and creates the umem_np_arena used to back non-pageable memory
 * requests.
 */
void
segdev_init(void)
{
	struct seg kseg;

	umem_np_arena = vmem_create("umem_np", NULL, 0, PAGESIZE,
	    devmap_alloc_pages, devmap_free_pages, heap_arena,
	    DEVMAP_UMEM_QUANTUM, VM_SLEEP);

	kseg.s_as = &kas;
	trashpp = page_create_va(&trashvp, 0, PAGESIZE,
	    PG_NORELOC | PG_EXCL | PG_WAIT, &kseg, NULL);
	if (trashpp == NULL)
		panic("segdev_init: failed to create trash page");
	pagezero(trashpp, 0, PAGESIZE);
	page_downgrade(trashpp);
}

/*
 * Invoke platform-dependent support routines so that /proc can have
 * the platform code deal with curious hardware.
 */
int
segdev_copyfrom(struct seg *seg,
    caddr_t uaddr, const void *devaddr, void *kaddr, size_t len)
{
	struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	struct snode *sp = VTOS(VTOCVP(sdp->vp));

	return (e_ddi_copyfromdev(sp->s_dip,
	    (off_t)(uaddr - seg->s_base), devaddr, kaddr, len));
}

int
segdev_copyto(struct seg *seg,
    caddr_t uaddr, const void *kaddr, void *devaddr, size_t len)
{
	struct segdev_data *sdp = (struct segdev_data *)seg->s_data;
	struct snode *sp = VTOS(VTOCVP(sdp->vp));

	return (e_ddi_copytodev(sp->s_dip,
	    (off_t)(uaddr - seg->s_base), kaddr, devaddr, len));
}
