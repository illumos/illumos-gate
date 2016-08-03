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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * VM - Kernel-to-user mapping segment
 *
 * The umap segment driver was primarily designed to facilitate the comm page:
 * a portion of kernel memory shared with userspace so that certain (namely
 * clock-related) actions could operate without making an expensive trip into
 * the kernel.
 *
 * Since the initial requirements for the comm page are slim, advanced features
 * of the segment driver such as per-page protection have been left
 * unimplemented at this time.
 */


#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/kmem.h>
#include <sys/lgrp.h>
#include <sys/mman.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_umap.h>


static boolean_t segumap_verify_safe(caddr_t, size_t);
static int segumap_dup(struct seg *, struct seg *);
static int segumap_unmap(struct seg *, caddr_t, size_t);
static void segumap_free(struct seg *);
static faultcode_t segumap_fault(struct hat *, struct seg *, caddr_t, size_t,
    enum fault_type, enum seg_rw);
static faultcode_t segumap_faulta(struct seg *, caddr_t);
static int segumap_setprot(struct seg *, caddr_t, size_t, uint_t);
static int segumap_checkprot(struct seg *, caddr_t, size_t, uint_t);
static int segumap_sync(struct seg *, caddr_t, size_t, int, uint_t);
static size_t segumap_incore(struct seg *, caddr_t, size_t, char *);
static int segumap_lockop(struct seg *, caddr_t, size_t, int, int, ulong_t *,
    size_t);
static int segumap_getprot(struct seg *, caddr_t, size_t, uint_t *);
static u_offset_t segumap_getoffset(struct seg *, caddr_t);
static int segumap_gettype(struct seg *, caddr_t);
static int segumap_getvp(struct seg *, caddr_t, struct vnode **);
static int segumap_advise(struct seg *, caddr_t, size_t, uint_t);
static void segumap_dump(struct seg *);
static int segumap_pagelock(struct seg *, caddr_t, size_t, struct page ***,
    enum lock_type, enum seg_rw);
static int segumap_setpagesize(struct seg *, caddr_t, size_t, uint_t);
static int segumap_getmemid(struct seg *, caddr_t, memid_t *);
static int segumap_capable(struct seg *, segcapability_t);

static struct seg_ops segumap_ops = {
	segumap_dup,
	segumap_unmap,
	segumap_free,
	segumap_fault,
	segumap_faulta,
	segumap_setprot,
	segumap_checkprot,
	NULL,			/* kluster: disabled */
	NULL,			/* swapout: disabled */
	segumap_sync,
	segumap_incore,
	segumap_lockop,
	segumap_getprot,
	segumap_getoffset,
	segumap_gettype,
	segumap_getvp,
	segumap_advise,
	segumap_dump,
	segumap_pagelock,
	segumap_setpagesize,
	segumap_getmemid,
	NULL,			/* getpolicy: disabled */
	segumap_capable,
	seg_inherit_notsup
};


/*
 * Create a kernel/user-mapped segment.
 */
int
segumap_create(struct seg *seg, void *argsp)
{
	segumap_crargs_t *a = (struct segumap_crargs *)argsp;
	segumap_data_t *data;

	ASSERT((uintptr_t)a->kaddr > _userlimit);

	/*
	 * Check several aspects of the mapping request to ensure validity:
	 * - kernel pages must reside entirely in kernel space
	 * - target protection must be user-accessible
	 * - kernel address must be page-aligned
	 * - kernel address must reside inside a "safe" segment
	 */
	if ((uintptr_t)a->kaddr <= _userlimit ||
	    ((uintptr_t)a->kaddr + seg->s_size) < (uintptr_t)a->kaddr ||
	    (a->prot & PROT_USER) == 0 ||
	    ((uintptr_t)a->kaddr & PAGEOFFSET) != 0 ||
	    !segumap_verify_safe(a->kaddr, seg->s_size)) {
		return (EINVAL);
	}

	data = kmem_zalloc(sizeof (*data), KM_SLEEP);
	rw_init(&data->sud_lock, NULL, RW_DEFAULT, NULL);
	data->sud_kaddr = a->kaddr;
	data->sud_prot = a->prot;

	seg->s_ops = &segumap_ops;
	seg->s_data = data;
	return (0);
}

static boolean_t
segumap_verify_safe(caddr_t kaddr, size_t len)
{
	struct seg *seg;

	/*
	 * Presently, only pages which are backed by segkmem are allowed to be
	 * shared with userspace.  This prevents nasty paging behavior with
	 * other drivers such as seg_kp.  Furthermore, the backing kernel
	 * segment must completely contain the region to be mapped.
	 *
	 * Failing these checks is fatal for now since such mappings are done
	 * in a very limited context from the kernel.
	 */
	AS_LOCK_ENTER(&kas, RW_READER);
	seg = as_segat(&kas, kaddr);
	VERIFY(seg != NULL);
	VERIFY(seg->s_base + seg->s_size >= kaddr + len);
	VERIFY(seg->s_ops == &segkmem_ops);
	AS_LOCK_EXIT(&kas);

	return (B_TRUE);
}

static int
segumap_dup(struct seg *seg, struct seg *newseg)
{
	segumap_data_t *sud = (segumap_data_t *)seg->s_data;
	segumap_data_t *newsud;

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	newsud = kmem_zalloc(sizeof (segumap_data_t), KM_SLEEP);
	rw_init(&newsud->sud_lock, NULL, RW_DEFAULT, NULL);
	newsud->sud_kaddr = sud->sud_kaddr;
	newsud->sud_prot = sud->sud_prot;

	newseg->s_ops = seg->s_ops;
	newseg->s_data = newsud;
	return (0);
}

static int
segumap_unmap(struct seg *seg, caddr_t addr, size_t len)
{
	segumap_data_t *sud = (segumap_data_t *)seg->s_data;

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	/* Only allow unmap of entire segment */
	if (addr != seg->s_base || len != seg->s_size) {
		return (EINVAL);
	}
	if (sud->sud_softlockcnt != 0) {
		return (EAGAIN);
	}

	/*
	 * Unconditionally unload the entire segment range.
	 */
	hat_unload(seg->s_as->a_hat, addr, len, HAT_UNLOAD_UNMAP);

	seg_free(seg);
	return (0);
}

static void
segumap_free(struct seg *seg)
{
	segumap_data_t *data = (segumap_data_t *)seg->s_data;

	ASSERT(data != NULL);

	rw_destroy(&data->sud_lock);
	VERIFY(data->sud_softlockcnt == 0);
	kmem_free(data, sizeof (*data));
	seg->s_data = NULL;
}

/* ARGSUSED */
static faultcode_t
segumap_fault(struct hat *hat, struct seg *seg, caddr_t addr, size_t len,
    enum fault_type type, enum seg_rw tw)
{
	segumap_data_t *sud = (segumap_data_t *)seg->s_data;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	if (type == F_PROT) {
		/*
		 * Since protection on the segment is fixed, there is nothing
		 * to do but report an error for protection faults.
		 */
		return (FC_PROT);
	} else if (type == F_SOFTUNLOCK) {
		size_t plen = btop(len);

		rw_enter(&sud->sud_lock, RW_WRITER);
		VERIFY(sud->sud_softlockcnt >= plen);
		sud->sud_softlockcnt -= plen;
		rw_exit(&sud->sud_lock);
		return (0);
	}

	ASSERT(type == F_INVAL || type == F_SOFTLOCK);
	rw_enter(&sud->sud_lock, RW_WRITER);

	if (type == F_INVAL ||
	    (type == F_SOFTLOCK && sud->sud_softlockcnt == 0)) {
		/*
		 * Load the (entire) segment into the HAT.
		 *
		 * It's possible that threads racing into as_fault will cause
		 * seg_umap to load the same range multiple times in quick
		 * succession.  Redundant hat_devload operations are safe.
		 */
		for (uintptr_t i = 0; i < seg->s_size; i += PAGESIZE) {
			pfn_t pfn;

			pfn = hat_getpfnum(kas.a_hat, sud->sud_kaddr + i);
			VERIFY(pfn != PFN_INVALID);
			hat_devload(seg->s_as->a_hat, seg->s_base + i,
			    PAGESIZE, pfn, sud->sud_prot, HAT_LOAD);
		}
	}
	if (type == F_SOFTLOCK) {
		size_t nval = sud->sud_softlockcnt + btop(len);

		if (sud->sud_softlockcnt >= nval) {
			rw_exit(&sud->sud_lock);
			return (FC_MAKE_ERR(EOVERFLOW));
		}
		sud->sud_softlockcnt = nval;
	}

	rw_exit(&sud->sud_lock);
	return (0);
}

/* ARGSUSED */
static faultcode_t
segumap_faulta(struct seg *seg, caddr_t addr)
{
	/* Do nothing since asynch pagefault should not load translation. */
	return (0);
}

/* ARGSUSED */
static int
segumap_setprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	/*
	 * The seg_umap driver does not yet allow protection to be changed.
	 */
	return (EACCES);
}

/* ARGSUSED */
static int
segumap_checkprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	segumap_data_t *sud = (segumap_data_t *)seg->s_data;
	int error = 0;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	rw_enter(&sud->sud_lock, RW_READER);
	if ((sud->sud_prot & prot) != prot) {
		error = EACCES;
	}
	rw_exit(&sud->sud_lock);
	return (error);
}

/* ARGSUSED */
static int
segumap_sync(struct seg *seg, caddr_t addr, size_t len, int attr, uint_t flags)
{
	/* Always succeed since there are no backing store to sync */
	return (0);
}

/* ARGSUSED */
static size_t
segumap_incore(struct seg *seg, caddr_t addr, size_t len, char *vec)
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
segumap_lockop(struct seg *seg, caddr_t addr, size_t len, int attr, int op,
    ulong_t *lockmap, size_t pos)
{
	/* Report success since kernel pages are always in memory. */
	return (0);
}

static int
segumap_getprot(struct seg *seg, caddr_t addr, size_t len, uint_t *protv)
{
	segumap_data_t *sud = (segumap_data_t *)seg->s_data;
	size_t pgno;
	uint_t prot;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	rw_enter(&sud->sud_lock, RW_READER);
	prot = sud->sud_prot;
	rw_exit(&sud->sud_lock);

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
segumap_getoffset(struct seg *seg, caddr_t addr)
{
	/*
	 * To avoid leaking information about the layout of the kernel address
	 * space, always report '0' as the offset.
	 */
	return (0);
}

/* ARGSUSED */
static int
segumap_gettype(struct seg *seg, caddr_t addr)
{
	/*
	 * Since already-existing kernel pages are being mapped into userspace,
	 * always report the segment type as shared.
	 */
	return (MAP_SHARED);
}

/* ARGSUSED */
static int
segumap_getvp(struct seg *seg, caddr_t addr, struct vnode **vpp)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	*vpp = NULL;
	return (0);
}

/* ARGSUSED */
static int
segumap_advise(struct seg *seg, caddr_t addr, size_t len, uint_t behav)
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
segumap_dump(struct seg *seg)
{
	/*
	 * Since this is a mapping to share kernel data with userspace, nothing
	 * additional should be dumped.
	 */
}

/* ARGSUSED */
static int
segumap_pagelock(struct seg *seg, caddr_t addr, size_t len, struct page ***ppp,
    enum lock_type type, enum seg_rw rw)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static int
segumap_setpagesize(struct seg *seg, caddr_t addr, size_t len, uint_t szc)
{
	return (ENOTSUP);
}

static int
segumap_getmemid(struct seg *seg, caddr_t addr, memid_t *memidp)
{
	segumap_data_t *sud = (segumap_data_t *)seg->s_data;

	memidp->val[0] = (uintptr_t)sud->sud_kaddr;
	memidp->val[1] = (uintptr_t)(addr - seg->s_base);
	return (0);
}

/* ARGSUSED */
static int
segumap_capable(struct seg *seg, segcapability_t capability)
{
	/* no special capablities */
	return (0);
}
