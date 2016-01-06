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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

#include <sys/atomic.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cpuvar.h>
#include <sys/kmem.h>
#include <sys/strsubr.h>
#include <sys/sysmacros.h>
#include <sys/frame.h>
#include <sys/stack.h>
#include <sys/proc.h>
#include <sys/priv.h>
#include <sys/policy.h>
#include <sys/ontrap.h>
#include <sys/vmsystm.h>
#include <sys/prsystm.h>

#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_dev.h>
#include <vm/seg_vn.h>
#include <vm/seg_spt.h>
#include <vm/seg_kmem.h>

extern struct seg_ops segdev_ops;	/* needs a header file */
extern struct seg_ops segspt_shmops;	/* needs a header file */

static int
page_valid(struct seg *seg, caddr_t addr)
{
	struct segvn_data *svd;
	vnode_t *vp;
	vattr_t vattr;

	/*
	 * Fail if the page doesn't map to a page in the underlying
	 * mapped file, if an underlying mapped file exists.
	 */
	vattr.va_mask = AT_SIZE;
	if (seg->s_ops == &segvn_ops &&
	    SEGOP_GETVP(seg, addr, &vp) == 0 &&
	    vp != NULL && vp->v_type == VREG &&
	    VOP_GETATTR(vp, &vattr, 0, CRED(), NULL) == 0) {
		u_offset_t size = roundup(vattr.va_size, (u_offset_t)PAGESIZE);
		u_offset_t offset = SEGOP_GETOFFSET(seg, addr);

		if (offset >= size)
			return (0);
	}

	/*
	 * Fail if this is an ISM shared segment and the address is
	 * not within the real size of the spt segment that backs it.
	 */
	if (seg->s_ops == &segspt_shmops &&
	    addr >= seg->s_base + spt_realsize(seg))
		return (0);

	/*
	 * Fail if the segment is mapped from /dev/null.
	 * The key is that the mapping comes from segdev and the
	 * type is neither MAP_SHARED nor MAP_PRIVATE.
	 */
	if (seg->s_ops == &segdev_ops &&
	    ((SEGOP_GETTYPE(seg, addr) & (MAP_SHARED | MAP_PRIVATE)) == 0))
		return (0);

	/*
	 * Fail if the page is a MAP_NORESERVE page that has
	 * not actually materialized.
	 * We cheat by knowing that segvn is the only segment
	 * driver that supports MAP_NORESERVE.
	 */
	if (seg->s_ops == &segvn_ops &&
	    (svd = (struct segvn_data *)seg->s_data) != NULL &&
	    (svd->vp == NULL || svd->vp->v_type != VREG) &&
	    (svd->flags & MAP_NORESERVE)) {
		/*
		 * Guilty knowledge here.  We know that
		 * segvn_incore returns more than just the
		 * low-order bit that indicates the page is
		 * actually in memory.  If any bits are set,
		 * then there is backing store for the page.
		 */
		char incore = 0;
		(void) SEGOP_INCORE(seg, addr, PAGESIZE, &incore);
		if (incore == 0)
			return (0);
	}
	return (1);
}

/*
 * Map address "addr" in address space "as" into a kernel virtual address.
 * The memory is guaranteed to be resident and locked down.
 */
static caddr_t
mapin(struct as *as, caddr_t addr, int writing)
{
	page_t *pp;
	caddr_t kaddr;
	pfn_t pfnum;

	/*
	 * NB: Because of past mistakes, we have bits being returned
	 * by getpfnum that are actually the page type bits of the pte.
	 * When the object we are trying to map is a memory page with
	 * a page structure everything is ok and we can use the optimal
	 * method, ppmapin.  Otherwise, we have to do something special.
	 */
	pfnum = hat_getpfnum(as->a_hat, addr);
	if (pf_is_memory(pfnum)) {
		pp = page_numtopp_nolock(pfnum);
		if (pp != NULL) {
			ASSERT(PAGE_LOCKED(pp));
			kaddr = ppmapin(pp, writing ?
			    (PROT_READ | PROT_WRITE) : PROT_READ, (caddr_t)-1);
			return (kaddr + ((uintptr_t)addr & PAGEOFFSET));
		}
	}

	/*
	 * Oh well, we didn't have a page struct for the object we were
	 * trying to map in; ppmapin doesn't handle devices, but allocating a
	 * heap address allows ppmapout to free virutal space when done.
	 */
	kaddr = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);

	hat_devload(kas.a_hat, kaddr, PAGESIZE, pfnum,
	    writing ? (PROT_READ | PROT_WRITE) : PROT_READ, HAT_LOAD_LOCK);

	return (kaddr + ((uintptr_t)addr & PAGEOFFSET));
}

/*ARGSUSED*/
static void
mapout(struct as *as, caddr_t addr, caddr_t vaddr, int writing)
{
	vaddr = (caddr_t)(uintptr_t)((uintptr_t)vaddr & PAGEMASK);
	ppmapout(vaddr);
}

/*
 * Perform I/O to a given process. This will return EIO if we detect
 * corrupt memory and ENXIO if there is no such mapped address in the
 * user process's address space.
 */
static int
urw(proc_t *p, int writing, void *buf, size_t len, uintptr_t a)
{
	caddr_t addr = (caddr_t)a;
	caddr_t page;
	caddr_t vaddr;
	struct seg *seg;
	int error = 0;
	int err = 0;
	uint_t prot;
	uint_t prot_rw = writing ? PROT_WRITE : PROT_READ;
	int protchanged;
	on_trap_data_t otd;
	int retrycnt;
	struct as *as = p->p_as;
	enum seg_rw rw;

	/*
	 * Locate segment containing address of interest.
	 */
	page = (caddr_t)(uintptr_t)((uintptr_t)addr & PAGEMASK);
	retrycnt = 0;
	AS_LOCK_ENTER(as, RW_WRITER);
retry:
	if ((seg = as_segat(as, page)) == NULL ||
	    !page_valid(seg, page)) {
		AS_LOCK_EXIT(as);
		return (ENXIO);
	}
	SEGOP_GETPROT(seg, page, 0, &prot);

	protchanged = 0;
	if ((prot & prot_rw) == 0) {
		protchanged = 1;
		err = SEGOP_SETPROT(seg, page, PAGESIZE, prot | prot_rw);

		if (err == IE_RETRY) {
			protchanged = 0;
			ASSERT(retrycnt == 0);
			retrycnt++;
			goto retry;
		}

		if (err != 0) {
			AS_LOCK_EXIT(as);
			return (ENXIO);
		}
	}

	/*
	 * segvn may do a copy-on-write for F_SOFTLOCK/S_READ case to break
	 * sharing to avoid a copy on write of a softlocked page by another
	 * thread. But since we locked the address space as a writer no other
	 * thread can cause a copy on write. S_READ_NOCOW is passed as the
	 * access type to tell segvn that it's ok not to do a copy-on-write
	 * for this SOFTLOCK fault.
	 */
	if (writing)
		rw = S_WRITE;
	else if (seg->s_ops == &segvn_ops)
		rw = S_READ_NOCOW;
	else
		rw = S_READ;

	if (SEGOP_FAULT(as->a_hat, seg, page, PAGESIZE, F_SOFTLOCK, rw)) {
		if (protchanged)
			(void) SEGOP_SETPROT(seg, page, PAGESIZE, prot);
		AS_LOCK_EXIT(as);
		return (ENXIO);
	}
	CPU_STATS_ADD_K(vm, softlock, 1);

	/*
	 * Make sure we're not trying to read or write off the end of the page.
	 */
	ASSERT(len <= page + PAGESIZE - addr);

	/*
	 * Map in the locked page, copy to our local buffer,
	 * then map the page out and unlock it.
	 */
	vaddr = mapin(as, addr, writing);

	/*
	 * Since we are copying memory on behalf of the user process,
	 * protect against memory error correction faults.
	 */
	if (!on_trap(&otd, OT_DATA_EC)) {
		if (seg->s_ops == &segdev_ops) {
			/*
			 * Device memory can behave strangely; invoke
			 * a segdev-specific copy operation instead.
			 */
			if (writing) {
				if (segdev_copyto(seg, addr, buf, vaddr, len))
					error = ENXIO;
			} else {
				if (segdev_copyfrom(seg, addr, vaddr, buf, len))
					error = ENXIO;
			}
		} else {
			if (writing)
				bcopy(buf, vaddr, len);
			else
				bcopy(vaddr, buf, len);
		}
	} else {
		error = EIO;
	}
	no_trap();

	/*
	 * If we're writing to an executable page, we may need to sychronize
	 * the I$ with the modifications we made through the D$.
	 */
	if (writing && (prot & PROT_EXEC))
		sync_icache(vaddr, (uint_t)len);

	mapout(as, addr, vaddr, writing);

	if (rw == S_READ_NOCOW)
		rw = S_READ;

	(void) SEGOP_FAULT(as->a_hat, seg, page, PAGESIZE, F_SOFTUNLOCK, rw);

	if (protchanged)
		(void) SEGOP_SETPROT(seg, page, PAGESIZE, prot);

	AS_LOCK_EXIT(as);

	return (error);
}

int
uread(proc_t *p, void *buf, size_t len, uintptr_t a)
{
	return (urw(p, 0, buf, len, a));
}

int
uwrite(proc_t *p, void *buf, size_t len, uintptr_t a)
{
	return (urw(p, 1, buf, len, a));
}
