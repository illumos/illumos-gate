/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018 Joyent, Inc.
 * Copyright 2021 Oxide Computer Company
 */

/*
 * segvmm - Virtual-Machine-Memory segment
 *
 * The vmm segment driver was designed for mapping regions of kernel memory
 * allocated to an HVM instance into userspace for manipulation there.  It
 * draws direct lineage from the umap segment driver, but meant for larger
 * mappings with fewer restrictions.
 *
 * seg*k*vmm, in contrast, has mappings for every VMM into kas.  We use its
 * mappings here only to find the relevant PFNs in segvmm_fault_in().
 */


#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/lgrp.h>
#include <sys/mman.h>

#include <vm/hat.h>
#include <vm/hat_pte.h>
#include <vm/htable.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>

#include <sys/seg_vmm.h>

typedef struct segvmm_data {
	krwlock_t	svmd_lock;
	vm_object_t	svmd_obj;
	uintptr_t	svmd_obj_off;
	uchar_t		svmd_prot;
	size_t		svmd_softlockcnt;
} segvmm_data_t;


static int segvmm_dup(struct seg *, struct seg *);
static int segvmm_unmap(struct seg *, caddr_t, size_t);
static void segvmm_free(struct seg *);
static faultcode_t segvmm_fault(struct hat *, struct seg *, caddr_t, size_t,
    enum fault_type, enum seg_rw);
static faultcode_t segvmm_faulta(struct seg *, caddr_t);
static int segvmm_setprot(struct seg *, caddr_t, size_t, uint_t);
static int segvmm_checkprot(struct seg *, caddr_t, size_t, uint_t);
static int segvmm_sync(struct seg *, caddr_t, size_t, int, uint_t);
static size_t segvmm_incore(struct seg *, caddr_t, size_t, char *);
static int segvmm_lockop(struct seg *, caddr_t, size_t, int, int, ulong_t *,
    size_t);
static int segvmm_getprot(struct seg *, caddr_t, size_t, uint_t *);
static u_offset_t segvmm_getoffset(struct seg *, caddr_t);
static int segvmm_gettype(struct seg *, caddr_t);
static int segvmm_getvp(struct seg *, caddr_t, struct vnode **);
static int segvmm_advise(struct seg *, caddr_t, size_t, uint_t);
static void segvmm_dump(struct seg *);
static int segvmm_pagelock(struct seg *, caddr_t, size_t, struct page ***,
    enum lock_type, enum seg_rw);
static int segvmm_setpagesize(struct seg *, caddr_t, size_t, uint_t);
static int segvmm_getmemid(struct seg *, caddr_t, memid_t *);
static int segvmm_capable(struct seg *, segcapability_t);

static struct seg_ops segvmm_ops = {
	.dup		= segvmm_dup,
	.unmap		= segvmm_unmap,
	.free		= segvmm_free,
	.fault		= segvmm_fault,
	.faulta		= segvmm_faulta,
	.setprot	= segvmm_setprot,
	.checkprot	= segvmm_checkprot,
	.kluster	= NULL,
	.swapout	= NULL,
	.sync		= segvmm_sync,
	.incore		= segvmm_incore,
	.lockop		= segvmm_lockop,
	.getprot	= segvmm_getprot,
	.getoffset	= segvmm_getoffset,
	.gettype	= segvmm_gettype,
	.getvp		= segvmm_getvp,
	.advise		= segvmm_advise,
	.dump		= segvmm_dump,
	.pagelock	= segvmm_pagelock,
	.setpagesize	= segvmm_setpagesize,
	.getmemid	= segvmm_getmemid,
	.getpolicy	= NULL,
	.capable	= segvmm_capable,
	.inherit	= seg_inherit_notsup
};


/*
 * Create a kernel/user-mapped segment.  ->kaddr is the segkvmm mapping.
 */
int
segvmm_create(struct seg **segpp, void *argsp)
{
	struct seg *seg = *segpp;
	segvmm_crargs_t *cra = argsp;
	segvmm_data_t *data;

	data = kmem_zalloc(sizeof (*data), KM_SLEEP);
	rw_init(&data->svmd_lock, NULL, RW_DEFAULT, NULL);
	data->svmd_obj = cra->obj;
	data->svmd_obj_off = cra->offset;
	data->svmd_prot = cra->prot;

	/* Grab a hold on the VM object for the duration of this seg mapping */
	vm_object_reference(data->svmd_obj);

	seg->s_ops = &segvmm_ops;
	seg->s_data = data;
	return (0);
}

static int
segvmm_dup(struct seg *seg, struct seg *newseg)
{
	segvmm_data_t *svmd = seg->s_data;
	segvmm_data_t *newsvmd;

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	newsvmd = kmem_zalloc(sizeof (segvmm_data_t), KM_SLEEP);
	rw_init(&newsvmd->svmd_lock, NULL, RW_DEFAULT, NULL);
	newsvmd->svmd_obj = svmd->svmd_obj;
	newsvmd->svmd_obj_off = svmd->svmd_obj_off;
	newsvmd->svmd_prot = svmd->svmd_prot;

	/* Grab another hold for the duplicate segment */
	vm_object_reference(svmd->svmd_obj);

	newseg->s_ops = seg->s_ops;
	newseg->s_data = newsvmd;
	return (0);
}

static int
segvmm_unmap(struct seg *seg, caddr_t addr, size_t len)
{
	segvmm_data_t *svmd = seg->s_data;

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	/* Only allow unmap of entire segment */
	if (addr != seg->s_base || len != seg->s_size) {
		return (EINVAL);
	}
	if (svmd->svmd_softlockcnt != 0) {
		return (EAGAIN);
	}

	/* Unconditionally unload the entire segment range.  */
	hat_unload(seg->s_as->a_hat, addr, len, HAT_UNLOAD_UNMAP);

	/* Release the VM object hold this segment possessed */
	vm_object_deallocate(svmd->svmd_obj);

	seg_free(seg);
	return (0);
}

static void
segvmm_free(struct seg *seg)
{
	segvmm_data_t *data = seg->s_data;

	ASSERT(data != NULL);

	rw_destroy(&data->svmd_lock);
	VERIFY(data->svmd_softlockcnt == 0);
	kmem_free(data, sizeof (*data));
	seg->s_data = NULL;
}

static int
segvmm_fault_in(struct hat *hat, struct seg *seg, uintptr_t va, size_t len)
{
	segvmm_data_t *svmd = seg->s_data;
	const uintptr_t end = va + len;
	const uintptr_t prot = svmd->svmd_prot;

	va &= PAGEMASK;
	uintptr_t off = va - (uintptr_t)seg->s_base;
	do {
		pfn_t pfn;

		pfn = vm_object_pfn(svmd->svmd_obj, off);
		if (pfn == PFN_INVALID) {
			return (-1);
		}

		/* Ignore any large-page possibilities for now */
		hat_devload(hat, (caddr_t)va, PAGESIZE, pfn, prot, HAT_LOAD);
		va += PAGESIZE;
		off += PAGESIZE;
	} while (va < end);

	return (0);
}

/* ARGSUSED */
static faultcode_t
segvmm_fault(struct hat *hat, struct seg *seg, caddr_t addr, size_t len,
    enum fault_type type, enum seg_rw tw)
{
	segvmm_data_t *svmd = seg->s_data;
	int err = 0;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	if (type == F_PROT) {
		/*
		 * Since protection on the segment is fixed, there is nothing
		 * to do but report an error for protection faults.
		 */
		return (FC_PROT);
	} else if (type == F_SOFTUNLOCK) {
		size_t plen = btop(len);

		rw_enter(&svmd->svmd_lock, RW_WRITER);
		VERIFY(svmd->svmd_softlockcnt >= plen);
		svmd->svmd_softlockcnt -= plen;
		rw_exit(&svmd->svmd_lock);
		return (0);
	}

	VERIFY(type == F_INVAL || type == F_SOFTLOCK);
	rw_enter(&svmd->svmd_lock, RW_WRITER);

	err = segvmm_fault_in(hat, seg, (uintptr_t)addr, len);
	if (type == F_SOFTLOCK && err == 0) {
		size_t nval = svmd->svmd_softlockcnt + btop(len);

		if (svmd->svmd_softlockcnt >= nval) {
			rw_exit(&svmd->svmd_lock);
			return (FC_MAKE_ERR(EOVERFLOW));
		}
		svmd->svmd_softlockcnt = nval;
	}

	rw_exit(&svmd->svmd_lock);
	return (err);
}

/* ARGSUSED */
static faultcode_t
segvmm_faulta(struct seg *seg, caddr_t addr)
{
	/* Do nothing since asynch pagefault should not load translation. */
	return (0);
}

/* ARGSUSED */
static int
segvmm_setprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	/* The seg_vmm driver does not yet allow protection to be changed. */
	return (EACCES);
}

/* ARGSUSED */
static int
segvmm_checkprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	segvmm_data_t *svmd = seg->s_data;
	int error = 0;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	rw_enter(&svmd->svmd_lock, RW_READER);
	if ((svmd->svmd_prot & prot) != prot) {
		error = EACCES;
	}
	rw_exit(&svmd->svmd_lock);
	return (error);
}

/* ARGSUSED */
static int
segvmm_sync(struct seg *seg, caddr_t addr, size_t len, int attr, uint_t flags)
{
	/* Always succeed since there are no backing store to sync */
	return (0);
}

/* ARGSUSED */
static size_t
segvmm_incore(struct seg *seg, caddr_t addr, size_t len, char *vec)
{
	size_t sz = 0;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	len = (len + PAGEOFFSET) & PAGEMASK;
	while (len > 0) {
		*vec = 1;
		sz += PAGESIZE;
		vec++;
		len -= PAGESIZE;
	}
	return (sz);
}

/* ARGSUSED */
static int
segvmm_lockop(struct seg *seg, caddr_t addr, size_t len, int attr, int op,
    ulong_t *lockmap, size_t pos)
{
	/* Report success since kernel pages are always in memory. */
	return (0);
}

static int
segvmm_getprot(struct seg *seg, caddr_t addr, size_t len, uint_t *protv)
{
	segvmm_data_t *svmd = seg->s_data;
	size_t pgno;
	uint_t prot;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	rw_enter(&svmd->svmd_lock, RW_READER);
	prot = svmd->svmd_prot;
	rw_exit(&svmd->svmd_lock);

	/*
	 * Reporting protection is simple since it is not tracked per-page.
	 */
	pgno = seg_page(seg, addr + len) - seg_page(seg, addr) + 1;
	while (pgno > 0) {
		protv[--pgno] = prot;
	}
	return (0);
}

/* ARGSUSED */
static u_offset_t
segvmm_getoffset(struct seg *seg, caddr_t addr)
{
	/*
	 * To avoid leaking information about the layout of the kernel address
	 * space, always report '0' as the offset.
	 */
	return (0);
}

/* ARGSUSED */
static int
segvmm_gettype(struct seg *seg, caddr_t addr)
{
	/*
	 * Since already-existing vmm reservoir pages are being mapped into
	 * userspace, always report the segment type as shared.
	 */
	return (MAP_SHARED);
}

/* ARGSUSED */
static int
segvmm_getvp(struct seg *seg, caddr_t addr, struct vnode **vpp)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	*vpp = NULL;
	return (0);
}

/* ARGSUSED */
static int
segvmm_advise(struct seg *seg, caddr_t addr, size_t len, uint_t behav)
{
	if (behav == MADV_PURGE) {
		/* Purge does not make sense for this mapping */
		return (EINVAL);
	}
	/* Indicate success for everything else. */
	return (0);
}

/* ARGSUSED */
static void
segvmm_dump(struct seg *seg)
{
	/*
	 * Since this is a mapping to share kernel data with userspace, nothing
	 * additional should be dumped.
	 */
}

/* ARGSUSED */
static int
segvmm_pagelock(struct seg *seg, caddr_t addr, size_t len, struct page ***ppp,
    enum lock_type type, enum seg_rw rw)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static int
segvmm_setpagesize(struct seg *seg, caddr_t addr, size_t len, uint_t szc)
{
	return (ENOTSUP);
}

static int
segvmm_getmemid(struct seg *seg, caddr_t addr, memid_t *memidp)
{
	segvmm_data_t *svmd = seg->s_data;

	memidp->val[0] = (uintptr_t)svmd->svmd_obj;
	memidp->val[1] = (uintptr_t)(addr - seg->s_base) + svmd->svmd_obj_off;
	return (0);
}

/* ARGSUSED */
static int
segvmm_capable(struct seg *seg, segcapability_t capability)
{
	/* no special capablities */
	return (0);
}
