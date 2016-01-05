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
 * Copyright (c) 1986, 2010, Oracle and/or its affiliates. All rights reserved.
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

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/inline.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/vmsystm.h>
#include <sys/cpuvar.h>
#include <sys/mman.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/vm.h>

#include <sys/swap.h>
#include <sys/vtrace.h>
#include <sys/tnf_probe.h>
#include <sys/fs/snode.h>
#include <sys/copyops.h>
#include <sys/conf.h>
#include <sys/sdt.h>

#include <vm/anon.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/page.h>
#include <vm/seg_vn.h>
#include <vm/seg_kmem.h>

extern int maxphys;

void
minphys(struct buf *bp)
{
	if (bp->b_bcount > maxphys)
		bp->b_bcount = maxphys;
}

/*
 * use kmem_cache_create for physio buffers. This has shown
 * a better cache distribution compared to buffers on the
 * stack. It also avoids semaphore construction/deconstruction
 * per request
 */

static struct kmem_cache *physio_buf_cache;

/* ARGSUSED */
static int
physio_buf_constructor(void *buf, void *cdrarg, int kmflags)
{
	bioinit((struct buf *)buf);
	return (0);
}

/* ARGSUSED */
static void
physio_buf_destructor(void *buf, void *cdrarg)
{
	biofini((struct buf *)buf);
}

void
physio_bufs_init(void)
{
	physio_buf_cache = kmem_cache_create("physio_buf_cache",
	    sizeof (struct buf), 0, physio_buf_constructor,
	    physio_buf_destructor, NULL, NULL, NULL, 0);
}



/*
 * initiate raw I/O request
 *
 * allocate buf header if necessary
 * adjust max size of each I/O request
 * lock down user pages and verify access protections
 * call driver's strategy routine to submit request
 * wait for I/O completion
 * unlock user pages and free allocated buf header
 */

int
default_physio(int (*strat)(struct buf *), struct buf *bp, dev_t dev,
	int rw, void (*mincnt)(struct buf *), struct uio *uio)
{
	struct iovec *iov;
	struct proc *procp;
	struct as *asp;
	ssize_t c;
	char *a;
	int error = 0;
	page_t **pplist;
	int allocbuf = 0;

	TRACE_1(TR_FAC_PHYSIO, TR_PHYSIO_START, "physio_start: bp %p", bp);

	/* Kernel probe */
	TNF_PROBE_4(physio_start, "io rawio", /* CSTYLED */,
	    tnf_device,		device,		dev,
	    tnf_offset,		offset,		uio->uio_loffset,
	    tnf_size,		size,		uio->uio_resid,
	    tnf_bioflags,	rw,		rw);

	if (rw == B_READ) {
		CPU_STATS_ADD_K(sys, phread, 1);
	} else {
		CPU_STATS_ADD_K(sys, phwrite, 1);
	}

	TRACE_1(TR_FAC_PHYSIO, TR_PHYSIO_GETBUF_START,
	    "getbuf_start: bp %p", bp);

	if (bp == NULL) {
		bp = kmem_cache_alloc(physio_buf_cache, KM_SLEEP);
		bp->b_iodone = NULL;
		bp->b_resid = 0;
		allocbuf = 1;
	}
	TRACE_1(TR_FAC_PHYSIO, TR_PHYSIO_GETBUF_END, "getbuf_end: bp %p", bp);

	if (uio->uio_segflg == UIO_USERSPACE) {
		procp = ttoproc(curthread);
		asp = procp->p_as;
	} else {
		procp = NULL;
		asp = &kas;
	}
	ASSERT(SEMA_HELD(&bp->b_sem));

	/*
	 * We need to prepare this buffer for the io:::start probe, including
	 * NULL'ing out the file, clearing the offset, and filling in the
	 * b_dip field.
	 */
	bp->b_file = NULL;
	bp->b_offset = -1;

	if (dev != NODEV) {
		(void) devopsp[getmajor(dev)]->devo_getinfo(NULL,
		    DDI_INFO_DEVT2DEVINFO, (void *)dev, (void **)&bp->b_dip);
	} else {
		bp->b_dip = NULL;
	}

	while (uio->uio_iovcnt > 0) {
		iov = uio->uio_iov;

		bp->b_error = 0;
		bp->b_proc = procp;

		while (iov->iov_len > 0) {
			if (uio->uio_resid == 0)
				break;
			if (uio->uio_loffset < 0) {
				error = EINVAL;
				break;
			}
#ifdef	_ILP32
			/*
			 * For 32-bit kernels, check against SPEC_MAXOFFSET_T
			 * which represents the maximum size that can be
			 * supported by the IO subsystem.
			 * XXX this code assumes a D_64BIT driver.
			 */
			if (uio->uio_loffset > SPEC_MAXOFFSET_T) {
				error = EINVAL;
				break;
			}
#endif	/* _ILP32 */
			bp->b_flags = B_BUSY | B_PHYS | rw;
			bp->b_edev = dev;
			bp->b_lblkno = btodt(uio->uio_loffset);

			/*
			 * Don't count on b_addr remaining untouched by the
			 * code below (it may be reset because someone does
			 * a bp_mapin on the buffer) -- reset from the iov
			 * each time through, updating the iov's base address
			 * instead.
			 */
			a = bp->b_un.b_addr = iov->iov_base;
			bp->b_bcount = MIN(iov->iov_len, uio->uio_resid);
			(*mincnt)(bp);
			c = bp->b_bcount;

			TRACE_1(TR_FAC_PHYSIO, TR_PHYSIO_LOCK_START,
			    "as_pagelock_start: bp %p", bp);

			error = as_pagelock(asp, &pplist, a,
			    c, rw == B_READ? S_WRITE : S_READ);

			TRACE_0(TR_FAC_PHYSIO, TR_PHYSIO_LOCK_END,
			    "as_pagelock_end:");

			if (error != 0) {
				bp->b_flags |= B_ERROR;
				bp->b_error = error;
				bp->b_flags &= ~(B_BUSY|B_WANTED|B_PHYS);
				break;
			}
			bp->b_shadow = pplist;
			if (pplist != NULL) {
				bp->b_flags |= B_SHADOW;
			}

			DTRACE_IO1(start, struct buf *, bp);
			bp->b_flags |= B_STARTED;

			(void) (*strat)(bp);
			error = biowait(bp);

			/*
			 * unlock the pages
			 */
			TRACE_1(TR_FAC_PHYSIO, TR_PHYSIO_UNLOCK_START,
			    "as_pageunlock_start: bp %p", bp);

			as_pageunlock(asp, pplist, a, c,
			    rw == B_READ? S_WRITE : S_READ);

			TRACE_0(TR_FAC_PHYSIO, TR_PHYSIO_UNLOCK_END,
			    "as_pageunlock_end:");

			c -= bp->b_resid;
			iov->iov_base += c;
			iov->iov_len -= c;
			uio->uio_resid -= c;
			uio->uio_loffset += c;
			/* bp->b_resid - temp kludge for tape drives */
			if (bp->b_resid || error)
				break;
		}
		bp->b_flags &= ~(B_BUSY|B_WANTED|B_PHYS|B_SHADOW);
		/* bp->b_resid - temp kludge for tape drives */
		if (bp->b_resid || error)
			break;
		uio->uio_iov++;
		uio->uio_iovcnt--;
	}

	if (allocbuf) {
		kmem_cache_free(physio_buf_cache, bp);
	}

	/* Kernel probe */
	TNF_PROBE_1(physio_end, "io rawio", /* CSTYLED */,
		tnf_device,	device,		dev);

	TRACE_1(TR_FAC_PHYSIO, TR_PHYSIO_END, "physio_end: bp %p", bp);

	return (error);
}

/*
 * Returns 0 on success, or an error on failure.
 *
 * This function is no longer a part of the DDI/DKI.
 * However, for compatibility, its interface should not
 * be changed and it should not be removed from the kernel.
 */
int
useracc(void *addr, size_t count, int access)
{
	uint_t prot;

	prot = PROT_USER | ((access == B_READ) ? PROT_READ : PROT_WRITE);
	return (as_checkprot(ttoproc(curthread)->p_as, addr, count, prot));
}

#define	MAX_MAPIN_PAGES	8

/*
 * This function temporarily "borrows" user pages for kernel use. If
 * "cow" is on, it also sets up copy-on-write protection (only feasible
 * on MAP_PRIVATE segment) on the user mappings, to protect the borrowed
 * pages from any changes by the user. The caller is responsible for
 * unlocking and tearing down cow settings when it's done with the pages.
 * For an example, see kcfree().
 *
 * Pages behind [uaddr..uaddr+*lenp] under address space "as" are locked
 * (shared), and mapped into kernel address range [kaddr..kaddr+*lenp] if
 * kaddr != -1. On entering this function, cached_ppp contains a list
 * of pages that are mapped into [kaddr..kaddr+*lenp] already (from a
 * previous call). Thus if same pages remain behind [uaddr..uaddr+*lenp],
 * the kernel map won't need to be reloaded again.
 *
 * For cow == 1, if the pages are anonymous pages, it also bumps the anon
 * reference count, and change the user-mapping to read-only. This
 * scheme should work on all types of segment drivers. But to be safe,
 * we check against segvn here.
 *
 * Since this function is used to emulate copyin() semantic, it checks
 * to make sure the user-mappings allow "user-read".
 *
 * On exit "lenp" contains the number of bytes successfully locked and
 * mapped in. For the unsuccessful ones, the caller can fall back to
 * copyin().
 *
 * Error return:
 * ENOTSUP - operation like this is not supported either on this segment
 * type, or on this platform type.
 */
int
cow_mapin(struct as *as, caddr_t uaddr, caddr_t kaddr, struct page **cached_ppp,
    struct anon **app, size_t *lenp, int cow)
{
	struct		hat *hat;
	struct seg	*seg;
	caddr_t		base;
	page_t		*pp, *ppp[MAX_MAPIN_PAGES];
	long		i;
	int		flags;
	size_t		size, total = *lenp;
	char		first = 1;
	faultcode_t	res;

	*lenp = 0;
	if (cow) {
		AS_LOCK_ENTER(as, RW_WRITER);
		seg = as_findseg(as, uaddr, 0);
		if ((seg == NULL) || ((base = seg->s_base) > uaddr) ||
		    (uaddr + total) > base + seg->s_size) {
			AS_LOCK_EXIT(as);
			return (EINVAL);
		}
		/*
		 * The COW scheme should work for all segment types.
		 * But to be safe, we check against segvn.
		 */
		if (seg->s_ops != &segvn_ops) {
			AS_LOCK_EXIT(as);
			return (ENOTSUP);
		} else if ((SEGOP_GETTYPE(seg, uaddr) & MAP_PRIVATE) == 0) {
			AS_LOCK_EXIT(as);
			return (ENOTSUP);
		}
	}
	hat = as->a_hat;
	size = total;
tryagain:
	/*
	 * If (cow), hat_softlock will also change the usr protection to RO.
	 * This is the first step toward setting up cow. Before we
	 * bump up an_refcnt, we can't allow any cow-fault on this
	 * address. Otherwise segvn_fault will change the protection back
	 * to RW upon seeing an_refcnt == 1.
	 * The solution is to hold the writer lock on "as".
	 */
	res = hat_softlock(hat, uaddr, &size, &ppp[0], cow ? HAT_COW : 0);
	size = total - size;
	*lenp += size;
	size = size >> PAGESHIFT;
	i = 0;
	while (i < size) {
		pp = ppp[i];
		if (cow) {
			kmutex_t *ahm;
			/*
			 * Another solution is to hold SE_EXCL on pp, and
			 * disable PROT_WRITE. This also works for MAP_SHARED
			 * segment. The disadvantage is that it locks the
			 * page from being used by anybody else.
			 */
			ahm = AH_MUTEX(pp->p_vnode, pp->p_offset);
			mutex_enter(ahm);
			*app = swap_anon(pp->p_vnode, pp->p_offset);
			/*
			 * Since we are holding the as lock, this avoids a
			 * potential race with anon_decref. (segvn_unmap and
			 * segvn_free needs the as writer lock to do anon_free.)
			 */
			if (*app != NULL) {
#if 0
				if ((*app)->an_refcnt == 0)
				/*
				 * Consider the following senario (unlikey
				 * though):
				 * 1. an_refcnt == 2
				 * 2. we solftlock the page.
				 * 3. cow ocurrs on this addr. So a new ap,
				 * page and mapping is established on addr.
				 * 4. an_refcnt drops to 1 (segvn_faultpage
				 * -> anon_decref(oldap))
				 * 5. the last ref to ap also drops (from
				 * another as). It ends up blocked inside
				 * anon_decref trying to get page's excl lock.
				 * 6. Later kcfree unlocks the page, call
				 * anon_decref -> oops, ap is gone already.
				 *
				 * Holding as writer lock solves all problems.
				 */
					*app = NULL;
				else
#endif
					(*app)->an_refcnt++;
			}
			mutex_exit(ahm);
		} else {
			*app = NULL;
		}
		if (kaddr != (caddr_t)-1) {
			if (pp != *cached_ppp) {
				if (*cached_ppp == NULL)
					flags = HAT_LOAD_LOCK | HAT_NOSYNC |
					    HAT_LOAD_NOCONSIST;
				else
					flags = HAT_LOAD_REMAP |
					    HAT_LOAD_NOCONSIST;
				/*
				 * In order to cache the kernel mapping after
				 * the user page is unlocked, we call
				 * hat_devload instead of hat_memload so
				 * that the kernel mapping we set up here is
				 * "invisible" to the rest of the world. This
				 * is not very pretty. But as long as the
				 * caller bears the responsibility of keeping
				 * cache consistency, we should be ok -
				 * HAT_NOCONSIST will get us a uncached
				 * mapping on VAC. hat_softlock will flush
				 * a VAC_WRITEBACK cache. Therefore the kaddr
				 * doesn't have to be of the same vcolor as
				 * uaddr.
				 * The alternative is - change hat_devload
				 * to get a cached mapping. Allocate a kaddr
				 * with the same vcolor as uaddr. Then
				 * hat_softlock won't need to flush the VAC.
				 */
				hat_devload(kas.a_hat, kaddr, PAGESIZE,
				    page_pptonum(pp), PROT_READ, flags);
				*cached_ppp = pp;
			}
			kaddr += PAGESIZE;
		}
		cached_ppp++;
		app++;
		++i;
	}
	if (cow) {
		AS_LOCK_EXIT(as);
	}
	if (first && res == FC_NOMAP) {
		/*
		 * If the address is not mapped yet, we call as_fault to
		 * fault the pages in. We could've fallen back to copy and
		 * let it fault in the pages. But for a mapped file, we
		 * normally reference each page only once. For zero-copy to
		 * be of any use, we'd better fall in the page now and try
		 * again.
		 */
		first = 0;
		size = size << PAGESHIFT;
		uaddr += size;
		total -= size;
		size = total;
		res = as_fault(as->a_hat, as, uaddr, size, F_INVAL, S_READ);
		if (cow)
			AS_LOCK_ENTER(as, RW_WRITER);
		goto tryagain;
	}
	switch (res) {
	case FC_NOSUPPORT:
		return (ENOTSUP);
	case FC_PROT:	/* Pretend we don't know about it. This will be */
			/* caught by the caller when uiomove fails. */
	case FC_NOMAP:
	case FC_OBJERR:
	default:
		return (0);
	}
}
