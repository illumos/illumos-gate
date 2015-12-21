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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * VM - segment for non-faulting loads.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/archsystm.h>
#include <sys/lgrp.h>

#include <vm/page.h>
#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/vpage.h>

/*
 * Private seg op routines.
 */
static int	segnf_dup(struct seg *seg, struct seg *newseg);
static int	segnf_unmap(struct seg *seg, caddr_t addr, size_t len);
static void	segnf_free(struct seg *seg);
static faultcode_t segnf_nomap(void);
static int	segnf_setprot(struct seg *seg, caddr_t addr,
		    size_t len, uint_t prot);
static int	segnf_checkprot(struct seg *seg, caddr_t addr,
		    size_t len, uint_t prot);
static void	segnf_badop(void);
static int	segnf_nop(void);
static int	segnf_getprot(struct seg *seg, caddr_t addr,
		    size_t len, uint_t *protv);
static u_offset_t segnf_getoffset(struct seg *seg, caddr_t addr);
static int	segnf_gettype(struct seg *seg, caddr_t addr);
static int	segnf_getvp(struct seg *seg, caddr_t addr, struct vnode **vpp);
static void	segnf_dump(struct seg *seg);
static int	segnf_pagelock(struct seg *seg, caddr_t addr, size_t len,
		    struct page ***ppp, enum lock_type type, enum seg_rw rw);
static int	segnf_setpagesize(struct seg *seg, caddr_t addr, size_t len,
		    uint_t szc);
static int	segnf_getmemid(struct seg *seg, caddr_t addr, memid_t *memidp);
static lgrp_mem_policy_info_t	*segnf_getpolicy(struct seg *seg,
    caddr_t addr);


struct seg_ops segnf_ops = {
	segnf_dup,
	segnf_unmap,
	segnf_free,
	(faultcode_t (*)(struct hat *, struct seg *, caddr_t, size_t,
	    enum fault_type, enum seg_rw))
		segnf_nomap,		/* fault */
	(faultcode_t (*)(struct seg *, caddr_t))
		segnf_nomap,		/* faulta */
	segnf_setprot,
	segnf_checkprot,
	(int (*)())segnf_badop,		/* kluster */
	(size_t (*)(struct seg *))NULL,	/* swapout */
	(int (*)(struct seg *, caddr_t, size_t, int, uint_t))
		segnf_nop,		/* sync */
	(size_t (*)(struct seg *, caddr_t, size_t, char *))
		segnf_nop,		/* incore */
	(int (*)(struct seg *, caddr_t, size_t, int, int, ulong_t *, size_t))
		segnf_nop,		/* lockop */
	segnf_getprot,
	segnf_getoffset,
	segnf_gettype,
	segnf_getvp,
	(int (*)(struct seg *, caddr_t, size_t, uint_t))
		segnf_nop,		/* advise */
	segnf_dump,
	segnf_pagelock,
	segnf_setpagesize,
	segnf_getmemid,
	segnf_getpolicy,
};

/*
 * vnode and page for the page of zeros we use for the nf mappings.
 */
static kmutex_t segnf_lock;
static struct vnode nfvp;
static struct page **nfpp;

#define	addr_to_vcolor(addr)                                            \
	(shm_alignment) ?						\
	((int)(((uintptr_t)(addr) & (shm_alignment - 1)) >> PAGESHIFT)) : 0

/*
 * We try to limit the number of Non-fault segments created.
 * Non fault segments are created to optimize sparc V9 code which uses
 * the sparc nonfaulting load ASI (ASI_PRIMARY_NOFAULT).
 *
 * There are several reasons why creating too many non-fault segments
 * could cause problems.
 *
 * 	First, excessive allocation of kernel resources for the seg
 *	structures and the HAT data to map the zero pages.
 *
 * 	Secondly, creating nofault segments actually uses up user virtual
 * 	address space. This makes it unavailable for subsequent mmap(0, ...)
 *	calls which use as_gap() to find empty va regions.  Creation of too
 *	many nofault segments could thus interfere with the ability of the
 *	runtime linker to load a shared object.
 */
#define	MAXSEGFORNF	(10000)
#define	MAXNFSEARCH	(5)


/*
 * Must be called from startup()
 */
void
segnf_init()
{
	mutex_init(&segnf_lock, NULL, MUTEX_DEFAULT, NULL);
}


/*
 * Create a no-fault segment.
 *
 * The no-fault segment is not technically necessary, as the code in
 * nfload() in trap.c will emulate the SPARC instruction and load
 * a value of zero in the destination register.
 *
 * However, this code tries to put a page of zero's at the nofault address
 * so that subsequent non-faulting loads to the same page will not
 * trap with a tlb miss.
 *
 * In order to help limit the number of segments we merge adjacent nofault
 * segments into a single segment.  If we get a large number of segments
 * we'll also try to delete a random other nf segment.
 */
/* ARGSUSED */
int
segnf_create(struct seg *seg, void *argsp)
{
	uint_t prot;
	pgcnt_t	vacpgs;
	u_offset_t off = 0;
	caddr_t	vaddr = NULL;
	int i, color;
	struct seg *s1;
	struct seg *s2;
	size_t size;
	struct as *as = seg->s_as;

	ASSERT(as && AS_WRITE_HELD(as));

	/*
	 * Need a page per virtual color or just 1 if no vac.
	 */
	mutex_enter(&segnf_lock);
	if (nfpp == NULL) {
		struct seg kseg;

		vacpgs = 1;
		if (shm_alignment > PAGESIZE) {
			vacpgs = shm_alignment >> PAGESHIFT;
		}

		nfpp = kmem_alloc(sizeof (*nfpp) * vacpgs, KM_SLEEP);

		kseg.s_as = &kas;
		for (i = 0; i < vacpgs; i++, off += PAGESIZE,
		    vaddr += PAGESIZE) {
			nfpp[i] = page_create_va(&nfvp, off, PAGESIZE,
			    PG_WAIT | PG_NORELOC, &kseg, vaddr);
			page_io_unlock(nfpp[i]);
			page_downgrade(nfpp[i]);
			pagezero(nfpp[i], 0, PAGESIZE);
		}
	}
	mutex_exit(&segnf_lock);

	hat_map(as->a_hat, seg->s_base, seg->s_size, HAT_MAP);

	/*
	 * s_data can't be NULL because of ASSERTS in the common vm code.
	 */
	seg->s_ops = &segnf_ops;
	seg->s_data = seg;
	seg->s_flags |= S_PURGE;

	mutex_enter(&as->a_contents);
	as->a_flags |= AS_NEEDSPURGE;
	mutex_exit(&as->a_contents);

	prot = PROT_READ;
	color = addr_to_vcolor(seg->s_base);
	if (as != &kas)
		prot |= PROT_USER;
	hat_memload(as->a_hat, seg->s_base, nfpp[color],
	    prot | HAT_NOFAULT, HAT_LOAD);

	/*
	 * At this point see if we can concatenate a segment to
	 * a non-fault segment immediately before and/or after it.
	 */
	if ((s1 = AS_SEGPREV(as, seg)) != NULL &&
	    s1->s_ops == &segnf_ops &&
	    s1->s_base + s1->s_size == seg->s_base) {
		size = s1->s_size;
		seg_free(s1);
		seg->s_base -= size;
		seg->s_size += size;
	}

	if ((s2 = AS_SEGNEXT(as, seg)) != NULL &&
	    s2->s_ops == &segnf_ops &&
	    seg->s_base + seg->s_size == s2->s_base) {
		size = s2->s_size;
		seg_free(s2);
		seg->s_size += size;
	}

	/*
	 * if we already have a lot of segments, try to delete some other
	 * nofault segment to reduce the probability of uncontrolled segment
	 * creation.
	 *
	 * the code looks around quickly (no more than MAXNFSEARCH segments
	 * each way) for another NF segment and then deletes it.
	 */
	if (avl_numnodes(&as->a_segtree) > MAXSEGFORNF) {
		size = 0;
		s2 = NULL;
		s1 = AS_SEGPREV(as, seg);
		while (size++ < MAXNFSEARCH && s1 != NULL) {
			if (s1->s_ops == &segnf_ops)
				s2 = s1;
			s1 = AS_SEGPREV(s1->s_as, seg);
		}
		if (s2 == NULL) {
			s1 = AS_SEGNEXT(as, seg);
			while (size-- > 0 && s1 != NULL) {
				if (s1->s_ops == &segnf_ops)
					s2 = s1;
				s1 = AS_SEGNEXT(as, seg);
			}
		}
		if (s2 != NULL)
			seg_unmap(s2);
	}

	return (0);
}

/*
 * Never really need "No fault" segments, so they aren't dup'd.
 */
/* ARGSUSED */
static int
segnf_dup(struct seg *seg, struct seg *newseg)
{
	panic("segnf_dup");
	return (0);
}

/*
 * Split a segment at addr for length len.
 */
static int
segnf_unmap(struct seg *seg, caddr_t addr, size_t len)
{
	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));

	/*
	 * Check for bad sizes.
	 */
	if (addr < seg->s_base || addr + len > seg->s_base + seg->s_size ||
	    (len & PAGEOFFSET) || ((uintptr_t)addr & PAGEOFFSET)) {
		cmn_err(CE_PANIC, "segnf_unmap: bad unmap size");
	}

	/*
	 * Unload any hardware translations in the range to be taken out.
	 */
	hat_unload(seg->s_as->a_hat, addr, len, HAT_UNLOAD_UNMAP);

	if (addr == seg->s_base && len == seg->s_size) {
		/*
		 * Freeing entire segment.
		 */
		seg_free(seg);
	} else if (addr == seg->s_base) {
		/*
		 * Freeing the beginning of the segment.
		 */
		seg->s_base += len;
		seg->s_size -= len;
	} else if (addr + len == seg->s_base + seg->s_size) {
		/*
		 * Freeing the end of the segment.
		 */
		seg->s_size -= len;
	} else {
		/*
		 * The section to go is in the middle of the segment, so we
		 * have to cut it into two segments.  We shrink the existing
		 * "seg" at the low end, and create "nseg" for the high end.
		 */
		caddr_t nbase = addr + len;
		size_t nsize = (seg->s_base + seg->s_size) - nbase;
		struct seg *nseg;

		/*
		 * Trim down "seg" before trying to stick "nseg" into the as.
		 */
		seg->s_size = addr - seg->s_base;
		nseg = seg_alloc(seg->s_as, nbase, nsize);
		if (nseg == NULL)
			cmn_err(CE_PANIC, "segnf_unmap: seg_alloc failed");

		/*
		 * s_data can't be NULL because of ASSERTs in common VM code.
		 */
		nseg->s_ops = seg->s_ops;
		nseg->s_data = nseg;
		nseg->s_flags |= S_PURGE;
		mutex_enter(&seg->s_as->a_contents);
		seg->s_as->a_flags |= AS_NEEDSPURGE;
		mutex_exit(&seg->s_as->a_contents);
	}

	return (0);
}

/*
 * Free a segment.
 */
static void
segnf_free(struct seg *seg)
{
	ASSERT(seg->s_as && AS_WRITE_HELD(seg->s_as));
}

/*
 * No faults allowed on segnf.
 */
static faultcode_t
segnf_nomap(void)
{
	return (FC_NOMAP);
}

/* ARGSUSED */
static int
segnf_setprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));
	return (EACCES);
}

/* ARGSUSED */
static int
segnf_checkprot(struct seg *seg, caddr_t addr, size_t len, uint_t prot)
{
	uint_t sprot;
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	sprot = seg->s_as == &kas ?  PROT_READ : PROT_READ|PROT_USER;
	return ((prot & sprot) == prot ? 0 : EACCES);
}

static void
segnf_badop(void)
{
	panic("segnf_badop");
	/*NOTREACHED*/
}

static int
segnf_nop(void)
{
	return (0);
}

static int
segnf_getprot(struct seg *seg, caddr_t addr, size_t len, uint_t *protv)
{
	size_t pgno = seg_page(seg, addr + len) - seg_page(seg, addr) + 1;
	size_t p;
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	for (p = 0; p < pgno; ++p)
		protv[p] = PROT_READ;
	return (0);
}

/* ARGSUSED */
static u_offset_t
segnf_getoffset(struct seg *seg, caddr_t addr)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	return ((u_offset_t)0);
}

/* ARGSUSED */
static int
segnf_gettype(struct seg *seg, caddr_t addr)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	return (MAP_SHARED);
}

/* ARGSUSED */
static int
segnf_getvp(struct seg *seg, caddr_t addr, struct vnode **vpp)
{
	ASSERT(seg->s_as && AS_LOCK_HELD(seg->s_as));

	*vpp = &nfvp;
	return (0);
}

/*
 * segnf pages are not dumped, so we just return
 */
/* ARGSUSED */
static void
segnf_dump(struct seg *seg)
{}

/*ARGSUSED*/
static int
segnf_pagelock(struct seg *seg, caddr_t addr, size_t len,
    struct page ***ppp, enum lock_type type, enum seg_rw rw)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
segnf_setpagesize(struct seg *seg, caddr_t addr, size_t len,
    uint_t szc)
{
	return (ENOTSUP);
}

/*ARGSUSED*/
static int
segnf_getmemid(struct seg *seg, caddr_t addr, memid_t *memidp)
{
	return (ENODEV);
}

/*ARGSUSED*/
static lgrp_mem_policy_info_t *
segnf_getpolicy(struct seg *seg, caddr_t addr)
{
	return (NULL);
}
