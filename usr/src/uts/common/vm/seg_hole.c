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
#include <vm/seg_hole.h>


static int seghole_dup(struct seg *, struct seg *);
static int seghole_unmap(struct seg *, caddr_t, size_t);
static void seghole_free(struct seg *);
static faultcode_t seghole_fault(struct hat *, struct seg *, caddr_t, size_t,
    enum fault_type, enum seg_rw);
static faultcode_t seghole_faulta(struct seg *, caddr_t);
static int seghole_setprot(struct seg *, caddr_t, size_t, uint_t);
static int seghole_checkprot(struct seg *, caddr_t, size_t, uint_t);
static int seghole_sync(struct seg *, caddr_t, size_t, int, uint_t);
static size_t seghole_incore(struct seg *, caddr_t, size_t, char *);
static int seghole_lockop(struct seg *, caddr_t, size_t, int, int, ulong_t *,
    size_t);
static int seghole_getprot(struct seg *, caddr_t, size_t, uint_t *);
static u_offset_t seghole_getoffset(struct seg *, caddr_t);
static int seghole_gettype(struct seg *, caddr_t);
static int seghole_getvp(struct seg *, caddr_t, struct vnode **);
static int seghole_advise(struct seg *, caddr_t, size_t, uint_t);
static void seghole_dump(struct seg *);
static int seghole_pagelock(struct seg *, caddr_t, size_t, struct page ***,
    enum lock_type, enum seg_rw);
static int seghole_setpagesize(struct seg *, caddr_t, size_t, uint_t);
static int seghole_capable(struct seg *, segcapability_t);

static struct seg_ops seghole_ops = {
	seghole_dup,
	seghole_unmap,
	seghole_free,
	seghole_fault,
	seghole_faulta,
	seghole_setprot,
	seghole_checkprot,
	NULL,			/* kluster: disabled */
	NULL,			/* swapout: disabled */
	seghole_sync,
	seghole_incore,
	seghole_lockop,
	seghole_getprot,
	seghole_getoffset,
	seghole_gettype,
	seghole_getvp,
	seghole_advise,
	seghole_dump,
	seghole_pagelock,
	seghole_setpagesize,
	NULL,			/* getmemid: disabled */
	NULL,			/* getpolicy: disabled */
	seghole_capable,
	seg_inherit_notsup
};

/*
 * Create a hole in the AS.
 */
int
seghole_create(struct seg **segpp, void *argsp)
{
	struct seg *seg = *segpp;
	seghole_crargs_t *crargs = argsp;
	seghole_data_t *data;

	data = kmem_alloc(sizeof (seghole_data_t), KM_SLEEP);
	data->shd_name = crargs->name;

	seg->s_ops = &seghole_ops;
	seg->s_data = data;
	seg->s_flags = S_HOLE;

	return (0);
}

static int
seghole_dup(struct seg *seg, struct seg *newseg)
{
	seghole_data_t *shd = (seghole_data_t *)seg->s_data;
	seghole_data_t *newshd;

	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	newshd = kmem_zalloc(sizeof (seghole_data_t), KM_SLEEP);
	newshd->shd_name = shd->shd_name;

	newseg->s_ops = seg->s_ops;
	newseg->s_data = newshd;
	newseg->s_flags = S_HOLE;

	return (0);
}

static int
seghole_unmap(struct seg *seg, caddr_t addr, size_t len)
{
	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	/* Entire segment is being unmapped */
	if (addr == seg->s_base && len == seg->s_size) {
		seg_free(seg);
		return (0);
	}

	/* Shrinking from low address side */
	if (addr == seg->s_base) {
		seg->s_base += len;
		seg->s_size -= len;
		return (0);
	}

	/* Shrinking from high address side */
	if ((addr + len) == (seg->s_base + seg->s_size)) {
		seg->s_size -= len;
		return (0);
	}

	/* Do not tolerate splitting the segment */
	return (EINVAL);
}

static void
seghole_free(struct seg *seg)
{
	seghole_data_t *data = (seghole_data_t *)seg->s_data;

	ASSERT(data != NULL);

	kmem_free(data, sizeof (*data));
	seg->s_data = NULL;
}

/* ARGSUSED */
static faultcode_t
seghole_fault(struct hat *hat, struct seg *seg, caddr_t addr, size_t len,
    enum fault_type type, enum seg_rw tw)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	return (FC_NOMAP);
}

/* ARGSUSED */
static faultcode_t
seghole_faulta(struct seg *seg, caddr_t addr)
{
	return (FC_NOMAP);
}

/* ARGSUSED */
static int
seghole_setprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	return (ENOMEM);
}

/* ARGSUSED */
static int
seghole_checkprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	return (ENOMEM);
}

/* ARGSUSED */
static int
seghole_sync(struct seg *seg, caddr_t addr, size_t len, int attr, uint_t flags)
{
	/* Always succeed since there are no backing store to sync */
	return (0);
}

/* ARGSUSED */
static size_t
seghole_incore(struct seg *seg, caddr_t addr, size_t len, char *vec)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	return (0);
}

/* ARGSUSED */
static int
seghole_lockop(struct seg *seg, caddr_t addr, size_t len, int attr, int op,
    ulong_t *lockmap, size_t pos)
{
	/*
	 * Emit an error consistent with there being no segment in this hole in
	 * the AS.  The MC_LOCKAS and MC_UNLOCKAS commands will explicitly skip
	 * hole segments, allowing such operations to proceed as expected.
	 */
	return (ENOMEM);
}

static int
seghole_getprot(struct seg *seg, caddr_t addr, size_t len, uint_t *protv)
{
	size_t pgno;

	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	/*
	 * Few SEGOP_GETPROT callers actually check for an error, so it's
	 * necessary to report zeroed protection for the length of the request.
	 */
	pgno = seg_page(seg, addr + len) - seg_page(seg, addr) + 1;
	while (pgno > 0) {
		protv[--pgno] = 0;
	}

	return (ENOMEM);
}

/* ARGSUSED */
static u_offset_t
seghole_getoffset(struct seg *seg, caddr_t addr)
{
	/*
	 * To avoid leaking information about the layout of the kernel address
	 * space, always report '0' as the offset.
	 */
	return (0);
}

/* ARGSUSED */
static int
seghole_gettype(struct seg *seg, caddr_t addr)
{
	return (MAP_PRIVATE);
}

/* ARGSUSED */
static int
seghole_getvp(struct seg *seg, caddr_t addr, struct vnode **vpp)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	return (ENOMEM);
}

/* ARGSUSED */
static int
seghole_advise(struct seg *seg, caddr_t addr, size_t len, uint_t behav)
{
	return (ENOMEM);
}

/* ARGSUSED */
static void
seghole_dump(struct seg *seg)
{
	/* There's nothing to dump from a hole in the AS */
}

/* ARGSUSED */
static int
seghole_pagelock(struct seg *seg, caddr_t addr, size_t len, struct page ***ppp,
    enum lock_type type, enum seg_rw rw)
{
	return (EFAULT);
}

/* ARGSUSED */
static int
seghole_setpagesize(struct seg *seg, caddr_t addr, size_t len, uint_t szc)
{
	return (ENOMEM);
}

/* ARGSUSED */
static int
seghole_capable(struct seg *seg, segcapability_t capability)
{
	/* no special capablities */
	return (0);
}
