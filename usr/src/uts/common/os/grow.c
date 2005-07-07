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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/inttypes.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/var.h>
#include <sys/proc.h>
#include <sys/tuneable.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/vm.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/vmparam.h>
#include <sys/fcntl.h>
#include <sys/lwpchan_impl.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_dev.h>
#include <vm/seg_vn.h>

int use_brk_lpg = 1;
int use_stk_lpg = 1;
int use_zmap_lpg = 1;

static int brk_lpg(caddr_t nva);
static int grow_lpg(caddr_t sp);

int
brk(caddr_t nva)
{
	int error;
	proc_t *p = curproc;

	/*
	 * Serialize brk operations on an address space.
	 * This also serves as the lock protecting p_brksize
	 * and p_brkpageszc.
	 */
	as_rangelock(p->p_as);
	if (use_brk_lpg && (p->p_flag & SAUTOLPG) != 0) {
		error = brk_lpg(nva);
	} else {
		error = brk_internal(nva, p->p_brkpageszc);
	}
	as_rangeunlock(p->p_as);
	return ((error != 0 ? set_errno(error) : 0));
}

/*
 * Algorithm: call arch-specific map_pgsz to get best page size to use,
 * then call brk_internal().
 * Returns 0 on success.
 */
static int
brk_lpg(caddr_t nva)
{
	struct proc *p = curproc;
	size_t pgsz, len;
	caddr_t addr;
	caddr_t bssbase = p->p_bssbase;
	caddr_t brkbase = p->p_brkbase;
	int oszc, szc;
	int err;
	int remap = 0;

	oszc = p->p_brkpageszc;

	/*
	 * If p_brkbase has not yet been set, the first call
	 * to brk_internal() will initialize it.
	 */
	if (brkbase == 0) {
		return (brk_internal(nva, oszc));
	}

	len = nva - bssbase;

	pgsz = map_pgsz(MAPPGSZ_HEAP, p, bssbase, len, &remap);
	szc = page_szc(pgsz);

	/*
	 * Covers two cases:
	 * 1. page_szc() returns -1 for invalid page size, so we want to
	 * ignore it in that case.
	 * 2. By design we never decrease page size, as it is more stable.
	 */
	if (szc <= oszc) {
		err = brk_internal(nva, oszc);
		/* If failed, back off to base page size. */
		if (err != 0 && oszc != 0) {
			err = brk_internal(nva, 0);
		}
		return (err);
	}

	if (remap == 0) {
		/*
		 * Map from the current brk end up to the new page size
		 * alignment using the current page size.
		 */
		addr = brkbase + p->p_brksize;
		addr = (caddr_t)P2ROUNDUP((uintptr_t)addr, pgsz);
		if (addr < nva) {
			err = brk_internal(addr, oszc);
			/*
			 * In failure case, try again if oszc is not base page
			 * size, then return err.
			 */
			if (err != 0) {
				if (oszc != 0) {
					err = brk_internal(nva, 0);
				}
				return (err);
			}
		}
	}

	err = brk_internal(nva, szc);
	/* If using szc failed, map with base page size and return. */
	if (err != 0) {
		if (szc != 0) {
			err = brk_internal(nva, 0);
		}
		return (err);
	}

	if (remap != 0) {
		/*
		 * Round up brk base to a large page boundary and remap
		 * anything in the segment already faulted in beyond that
		 * point.
		 */
		addr = (caddr_t)P2ROUNDUP((uintptr_t)p->p_bssbase, pgsz);
		len = (brkbase + p->p_brksize) - addr;
		/* advisory, so ignore errors */
		(void) as_setpagesize(p->p_as, addr, len, szc, B_FALSE);
	}

	ASSERT(err == 0);
	return (err);		/* should always be 0 */
}

/*
 * Returns 0 on success.
 */
int
brk_internal(caddr_t nva, uint_t brkszc)
{
	caddr_t ova;			/* current break address */
	size_t size;
	int	error;
	struct proc *p = curproc;
	struct as *as = p->p_as;
	size_t pgsz;
	uint_t szc;
	rctl_qty_t as_rctl;

	/*
	 * extend heap to brkszc alignment but use current p->p_brkpageszc
	 * for the newly created segment. This allows the new extension
	 * segment to be concatenated successfully with the existing brk
	 * segment.
	 */
	if ((szc = brkszc) != 0) {
		pgsz = page_get_pagesize(szc);
		ASSERT(pgsz > PAGESIZE);
	} else {
		pgsz = PAGESIZE;
	}

	mutex_enter(&p->p_lock);
	as_rctl = rctl_enforced_value(rctlproc_legacy[RLIMIT_DATA],
	    p->p_rctls, p);
	mutex_exit(&p->p_lock);

	/*
	 * If p_brkbase has not yet been set, the first call
	 * to brk() will initialize it.
	 */
	if (p->p_brkbase == 0)
		p->p_brkbase = nva;

	/*
	 * Before multiple page size support existed p_brksize was the value
	 * not rounded to the pagesize (i.e. it stored the exact user request
	 * for heap size). If pgsz is greater than PAGESIZE calculate the
	 * heap size as the real new heap size by rounding it up to pgsz.
	 * This is useful since we may want to know where the heap ends
	 * without knowing heap pagesize (e.g. some old code) and also if
	 * heap pagesize changes we can update p_brkpageszc but delay adding
	 * new mapping yet still know from p_brksize where the heap really
	 * ends. The user requested heap end is stored in libc variable.
	 */
	if (pgsz > PAGESIZE) {
		caddr_t tnva = (caddr_t)P2ROUNDUP((uintptr_t)nva, pgsz);
		size = tnva - p->p_brkbase;
		if (tnva < p->p_brkbase || (size > p->p_brksize &&
		    size > (size_t)as_rctl)) {
			szc = 0;
			pgsz = PAGESIZE;
			size = nva - p->p_brkbase;
		}
	} else {
		size = nva - p->p_brkbase;
	}

	/*
	 * use PAGESIZE to roundup ova because we want to know the real value
	 * of the current heap end in case p_brkpageszc changes since the last
	 * p_brksize was computed.
	 */
	nva = (caddr_t)P2ROUNDUP((uintptr_t)nva, pgsz);
	ova = (caddr_t)P2ROUNDUP((uintptr_t)(p->p_brkbase + p->p_brksize),
		PAGESIZE);

	if ((nva < p->p_brkbase) || (size > p->p_brksize &&
	    size > as_rctl)) {
		mutex_enter(&p->p_lock);
		(void) rctl_action(rctlproc_legacy[RLIMIT_DATA], p->p_rctls, p,
		    RCA_SAFE);
		mutex_exit(&p->p_lock);
		return (ENOMEM);
	}

	if (nva > ova) {
		struct segvn_crargs crargs =
		    SEGVN_ZFOD_ARGS(PROT_ZFOD, PROT_ALL);

		if (!(p->p_datprot & PROT_EXEC)) {
			crargs.prot &= ~PROT_EXEC;
		}

		/*
		 * Add new zfod mapping to extend UNIX data segment
		 */
		crargs.szc = szc;
		crargs.lgrp_mem_policy_flags = LGRP_MP_FLAG_EXTEND_UP;
		error = as_map(as, ova, (size_t)(nva - ova), segvn_create,
		    &crargs);
		if (error) {
			return (error);
		}

	} else if (nva < ova) {
		/*
		 * Release mapping to shrink UNIX data segment.
		 */
		(void) as_unmap(as, nva, (size_t)(ova - nva));
	}
	p->p_brksize = size;
	p->p_brkpageszc = szc;
	return (0);
}

/*
 * Grow the stack to include sp.  Return 1 if successful, 0 otherwise.
 * This routine assumes that the stack grows downward.
 */
int
grow(caddr_t sp)
{
	struct proc *p = curproc;
	int err;

	/*
	 * Serialize grow operations on an address space.
	 * This also serves as the lock protecting p_stksize
	 * and p_stkpageszc.
	 */
	as_rangelock(p->p_as);
	if (use_stk_lpg && (p->p_flag & SAUTOLPG) != 0) {
		err = grow_lpg(sp);
	} else {
		err = grow_internal(sp, p->p_stkpageszc);
	}
	as_rangeunlock(p->p_as);
	return ((err == 0 ? 1 : 0));
}

/*
 * Algorithm: call arch-specific map_pgsz to get best page size to use,
 * then call grow_internal().
 * Returns 0 on success.
 */
static int
grow_lpg(caddr_t sp)
{
	struct proc *p = curproc;
	size_t pgsz;
	size_t len, newsize;
	caddr_t addr, oldsp;
	int oszc, szc;
	int err;
	int remap = 0;

	newsize = p->p_usrstack - sp;

	oszc = p->p_stkpageszc;
	pgsz = map_pgsz(MAPPGSZ_STK, p, sp, newsize, &remap);
	szc = page_szc(pgsz);

	/*
	 * Covers two cases:
	 * 1. page_szc() returns -1 for invalid page size, so we want to
	 * ignore it in that case.
	 * 2. By design we never decrease page size, as it is more stable.
	 * This shouldn't happen as the stack never shrinks.
	 */
	if (szc <= oszc) {
		err = grow_internal(sp, oszc);
		/* failed, fall back to base page size */
		if (err != 0 && oszc != 0) {
			err = grow_internal(sp, 0);
		}
		return (err);
	}

	/*
	 * We've grown sufficiently to switch to a new page size.
	 * If we're not going to remap the whole segment with the new
	 * page size, split the grow into two operations: map to the new
	 * page size alignment boundary with the existing page size, then
	 * map the rest with the new page size.
	 */
	err = 0;
	if (remap == 0) {
		oldsp = p->p_usrstack - p->p_stksize;
		addr = (caddr_t)P2ALIGN((uintptr_t)oldsp, pgsz);
		if (addr > sp) {
			err = grow_internal(addr, oszc);
			/*
			 * In this case, grow with oszc failed, so grow all the
			 * way to sp with base page size.
			 */
			if (err != 0) {
				if (oszc != 0) {
					err = grow_internal(sp, 0);
				}
				return (err);
			}
		}
	}

	err = grow_internal(sp, szc);
	/* The grow with szc failed, so fall back to base page size. */
	if (err != 0) {
		if (szc != 0) {
			err = grow_internal(sp, 0);
		}
		return (err);
	}

	if (remap) {
		/*
		 * Round up stack pointer to a large page boundary and remap
		 * any pgsz pages in the segment already faulted in beyond that
		 * point.
		 */
		addr = p->p_usrstack - p->p_stksize;
		addr = (caddr_t)P2ROUNDUP((uintptr_t)addr, pgsz);
		len = (caddr_t)P2ALIGN((uintptr_t)p->p_usrstack, pgsz) - addr;
		/* advisory, so ignore errors */
		(void) as_setpagesize(p->p_as, addr, len, szc, B_FALSE);
	}

	/* Update page size code for stack. */
	p->p_stkpageszc = szc;

	ASSERT(err == 0);
	return (err);		/* should always be 0 */
}

/*
 * This routine assumes that the stack grows downward.
 * Returns 0 on success, errno on failure.
 */
int
grow_internal(caddr_t sp, uint_t growszc)
{
	struct proc *p = curproc;
	struct as *as = p->p_as;
	size_t newsize = p->p_usrstack - sp;
	size_t oldsize;
	int    error;
	size_t pgsz;
	uint_t szc;
	struct segvn_crargs crargs = SEGVN_ZFOD_ARGS(PROT_ZFOD, PROT_ALL);

	ASSERT(sp < p->p_usrstack);

	/*
	 * grow to growszc alignment but use current p->p_stkpageszc for
	 * the segvn_crargs szc passed to segvn_create. For memcntl to
	 * increase the szc, this allows the new extension segment to be
	 * concatenated successfully with the existing stack segment.
	 */
	if ((szc = growszc) != 0) {
		pgsz = page_get_pagesize(szc);
		ASSERT(pgsz > PAGESIZE);
		newsize = P2ROUNDUP(newsize, pgsz);
		if (newsize > (size_t)p->p_stk_ctl) {
			szc = 0;
			pgsz = PAGESIZE;
			newsize = p->p_usrstack - sp;
		}
	} else {
		pgsz = PAGESIZE;
	}

	if (newsize > (size_t)p->p_stk_ctl) {
		(void) rctl_action(rctlproc_legacy[RLIMIT_STACK], p->p_rctls, p,
		    RCA_UNSAFE_ALL);

		return (ENOMEM);
	}

	oldsize = p->p_stksize;
	newsize = P2ROUNDUP(newsize, pgsz);
	ASSERT(P2PHASE(oldsize, PAGESIZE) == 0);

	if (newsize <= oldsize) {	/* prevent the stack from shrinking */
		return (0);
	}

	if (!(p->p_stkprot & PROT_EXEC)) {
		crargs.prot &= ~PROT_EXEC;
	}
	/*
	 * extend stack with the p_stkpageszc. growszc is different than
	 * p_stkpageszc only on a memcntl to increase the stack pagesize.
	 */
	crargs.szc = p->p_stkpageszc;
	crargs.lgrp_mem_policy_flags = LGRP_MP_FLAG_EXTEND_DOWN;

	if ((error = as_map(as, p->p_usrstack - newsize, newsize - oldsize,
	    segvn_create, &crargs)) != 0) {
		if (error == EAGAIN) {
			cmn_err(CE_WARN, "Sorry, no swap space to grow stack "
			    "for pid %d (%s)", p->p_pid, u.u_comm);
		}
		return (error);
	}
	p->p_stksize = newsize;


	/*
	 * Set up translations so the process doesn't have to fault in
	 * the stack pages we just gave it.
	 */
	(void) as_fault(as->a_hat, as,
	    p->p_usrstack - newsize, newsize - oldsize, F_INVAL, S_WRITE);

	return (0);
}

/*
 * Used for MAP_ANON - fast way to get anonymous pages
 */
static int
zmap(struct as *as, caddr_t *addrp, size_t len, uint_t uprot, int flags,
    offset_t pos)
{
	struct segvn_crargs a, b;
	struct proc *p = curproc;
	int err;
	size_t pgsz;
	size_t l0, l1, l2, l3, l4; /* 0th through 5th chunks */
	caddr_t ruaddr, ruaddr0; /* rounded up addresses */
	extern size_t auto_lpg_va_default;

	if (((PROT_ALL & uprot) != uprot))
		return (EACCES);

	if ((flags & MAP_FIXED) != 0) {
		caddr_t userlimit;

		/*
		 * Use the user address.  First verify that
		 * the address to be used is page aligned.
		 * Then make some simple bounds checks.
		 */
		if (((uintptr_t)*addrp & PAGEOFFSET) != 0)
			return (EINVAL);

		userlimit = flags & _MAP_LOW32 ?
		    (caddr_t)USERLIMIT32 : as->a_userlimit;
		switch (valid_usr_range(*addrp, len, uprot, as, userlimit)) {
		case RANGE_OKAY:
			break;
		case RANGE_BADPROT:
			return (ENOTSUP);
		case RANGE_BADADDR:
		default:
			return (ENOMEM);
		}
		(void) as_unmap(as, *addrp, len);
	} else {
		/*
		 * No need to worry about vac alignment for anonymous
		 * pages since this is a "clone" object that doesn't
		 * yet exist.
		 */
		map_addr(addrp, len, pos, 0, flags);
		if (*addrp == NULL)
			return (ENOMEM);
	}

	/*
	 * Use the seg_vn segment driver; passing in the NULL amp
	 * gives the desired "cloning" effect.
	 */
	a.vp = NULL;
	a.offset = 0;
	a.type = flags & MAP_TYPE;
	a.prot = uprot;
	a.maxprot = PROT_ALL;
	a.flags = flags & ~MAP_TYPE;
	a.cred = CRED();
	a.amp = NULL;
	a.szc = 0;
	a.lgrp_mem_policy_flags = 0;

	/*
	 * Call arch-specific map_pgsz routine to pick best page size to map
	 * this segment, and break the mapping up into parts if required.
	 *
	 * The parts work like this:
	 *
	 * addr		---------
	 *		|	| l0
	 *		---------
	 *		|	| l1
	 *		---------
	 *		|	| l2
	 *		---------
	 *		|	| l3
	 *		---------
	 *		|	| l4
	 *		---------
	 * addr+len
	 *
	 * Starting from the middle, l2 is the number of bytes mapped by the
	 * selected large page.  l1 and l3 are mapped by auto_lpg_va_default
	 * page size pages, and l0 and l4 are mapped by base page size pages.
	 * If auto_lpg_va_default is the base page size, then l0 == l4 == 0.
	 * If the requested address or length are aligned to the selected large
	 * page size, l1 or l3 may also be 0.
	 */
	if (use_zmap_lpg) {

		pgsz = map_pgsz(MAPPGSZ_VA, p, *addrp, len, NULL);
		if (pgsz <= PAGESIZE || len < pgsz) {
			return (as_map(as, *addrp, len, segvn_create, &a));
		}

		ruaddr = (caddr_t)P2ROUNDUP((uintptr_t)*addrp, pgsz);
		if (auto_lpg_va_default != MMU_PAGESIZE) {
			ruaddr0 = (caddr_t)P2ROUNDUP((uintptr_t)*addrp,
			    auto_lpg_va_default);
			l0 = ruaddr0 - *addrp;
		} else {
			l0 = 0;
			ruaddr0 = *addrp;
		}
		l1 = ruaddr - ruaddr0;
		l3 = P2PHASE(len - l0 - l1, pgsz);
		if (auto_lpg_va_default == MMU_PAGESIZE) {
			l4 = 0;
		} else {
			l4 = P2PHASE(l3, auto_lpg_va_default);
			l3 -= l4;
		}
		l2 = len - l0 - l1 - l3 - l4;

		if (l0) {
			b = a;
			err = as_map(as, *addrp, l0, segvn_create, &b);
			if (err) {
				return (err);
			}
		}

		if (l1) {
			b = a;
			b.szc = page_szc(auto_lpg_va_default);
			err = as_map(as, ruaddr0, l1, segvn_create, &b);
			if (err) {
				goto error1;
			}
		}

		if (l2) {
			b = a;
			b.szc = page_szc(pgsz);
			err = as_map(as, ruaddr, l2, segvn_create, &b);
			if (err) {
				goto error2;
			}
		}

		if (l3) {
			b = a;
			b.szc = page_szc(auto_lpg_va_default);
			err = as_map(as, ruaddr + l2, l3, segvn_create, &b);
			if (err) {
				goto error3;
			}
		}
		if (l4) {
			err = as_map(as, ruaddr + l2 + l3, l4, segvn_create,
			    &a);
			if (err) {
error3:
				if (l3) {
					(void) as_unmap(as, ruaddr + l2, l3);
				}
error2:
				if (l2) {
					(void) as_unmap(as, ruaddr, l2);
				}
error1:
				if (l1) {
					(void) as_unmap(as, ruaddr0, l1);
				}
				if (l0) {
					(void) as_unmap(as, *addrp, l0);
				}
				return (err);
			}
		}

		return (0);
	}

	return (as_map(as, *addrp, len, segvn_create, &a));
}

static int
smmap_common(caddr_t *addrp, size_t len,
    int prot, int flags, struct file *fp, offset_t pos)
{
	struct vnode *vp;
	struct as *as = curproc->p_as;
	uint_t uprot, maxprot, type;
	int error;

	if ((flags & ~(MAP_SHARED | MAP_PRIVATE | MAP_FIXED | _MAP_NEW |
	    _MAP_LOW32 | MAP_NORESERVE | MAP_ANON | MAP_ALIGN |
	    MAP_TEXT | MAP_INITDATA)) != 0) {
		/* | MAP_RENAME */	/* not implemented, let user know */
		return (EINVAL);
	}

	if ((flags & MAP_TEXT) && !(prot & PROT_EXEC)) {
		return (EINVAL);
	}

	if ((flags & (MAP_TEXT | MAP_INITDATA)) == (MAP_TEXT | MAP_INITDATA)) {
		return (EINVAL);
	}

#if defined(__sparc)
	/*
	 * See if this is an "old mmap call".  If so, remember this
	 * fact and convert the flags value given to mmap to indicate
	 * the specified address in the system call must be used.
	 * _MAP_NEW is turned set by all new uses of mmap.
	 */
	if ((flags & _MAP_NEW) == 0)
		flags |= MAP_FIXED;
#endif
	flags &= ~_MAP_NEW;

	type = flags & MAP_TYPE;
	if (type != MAP_PRIVATE && type != MAP_SHARED)
		return (EINVAL);


	if (flags & MAP_ALIGN) {

		if (flags & MAP_FIXED)
			return (EINVAL);

		/* alignment needs to be a power of 2 >= page size */
		if (((uintptr_t)*addrp < PAGESIZE && (uintptr_t)*addrp != 0) ||
			!ISP2((uintptr_t)*addrp))
			return (EINVAL);
	}
	/*
	 * Check for bad lengths and file position.
	 * We let the VOP_MAP routine check for negative lengths
	 * since on some vnode types this might be appropriate.
	 */
	if (len == 0 || (pos & (u_offset_t)PAGEOFFSET) != 0)
		return (EINVAL);

	maxprot = PROT_ALL;		/* start out allowing all accesses */
	uprot = prot | PROT_USER;

	if (fp == NULL) {
		ASSERT(flags & MAP_ANON);
		as_rangelock(as);
		error = zmap(as, addrp, len, uprot, flags, pos);
		as_rangeunlock(as);
		return (error);
	} else if ((flags & MAP_ANON) != 0)
		return (EINVAL);

	vp = fp->f_vnode;

	/* Can't execute code from "noexec" mounted filesystem. */
	if ((vp->v_vfsp->vfs_flag & VFS_NOEXEC) != 0)
		maxprot &= ~PROT_EXEC;

	/*
	 * These checks were added as part of large files.
	 *
	 * Return ENXIO if the initial position is negative; return EOVERFLOW
	 * if (offset + len) would overflow the maximum allowed offset for the
	 * type of file descriptor being used.
	 */
	if (vp->v_type == VREG) {
		if (pos < 0)
			return (ENXIO);
		if ((offset_t)len > (OFFSET_MAX(fp) - pos))
			return (EOVERFLOW);
	}

	if (type == MAP_SHARED && (fp->f_flag & FWRITE) == 0) {
		/* no write access allowed */
		maxprot &= ~PROT_WRITE;
	}

	/*
	 * XXX - Do we also adjust maxprot based on protections
	 * of the vnode?  E.g. if no execute permission is given
	 * on the vnode for the current user, maxprot probably
	 * should disallow PROT_EXEC also?  This is different
	 * from the write access as this would be a per vnode
	 * test as opposed to a per fd test for writability.
	 */

	/*
	 * Verify that the specified protections are not greater than
	 * the maximum allowable protections.  Also test to make sure
	 * that the file descriptor does allows for read access since
	 * "write only" mappings are hard to do since normally we do
	 * the read from the file before the page can be written.
	 */
	if (((maxprot & uprot) != uprot) || (fp->f_flag & FREAD) == 0)
		return (EACCES);

	/*
	 * If the user specified an address, do some simple checks here
	 */
	if ((flags & MAP_FIXED) != 0) {
		caddr_t userlimit;

		/*
		 * Use the user address.  First verify that
		 * the address to be used is page aligned.
		 * Then make some simple bounds checks.
		 */
		if (((uintptr_t)*addrp & PAGEOFFSET) != 0)
			return (EINVAL);

		userlimit = flags & _MAP_LOW32 ?
		    (caddr_t)USERLIMIT32 : as->a_userlimit;
		switch (valid_usr_range(*addrp, len, uprot, as, userlimit)) {
		case RANGE_OKAY:
			break;
		case RANGE_BADPROT:
			return (ENOTSUP);
		case RANGE_BADADDR:
		default:
			return (ENOMEM);
		}
	}


	/*
	 * Ok, now let the vnode map routine do its thing to set things up.
	 */
	error = VOP_MAP(vp, pos, as,
	    addrp, len, uprot, maxprot, flags, fp->f_cred);

	if (error == 0) {
		if (vp->v_type == VREG &&
		    (flags & (MAP_TEXT | MAP_INITDATA)) != 0) {
			/*
			 * Mark this as an executable vnode
			 */
			mutex_enter(&vp->v_lock);
			vp->v_flag |= VVMEXEC;
			mutex_exit(&vp->v_lock);
		}
	}

	return (error);
}

#ifdef _LP64
/*
 * LP64 mmap(2) system call: 64-bit offset, 64-bit address.
 *
 * The "large file" mmap routine mmap64(2) is also mapped to this routine
 * by the 64-bit version of libc.
 *
 * Eventually, this should be the only version, and have smmap_common()
 * folded back into it again.  Some day.
 */
caddr_t
smmap64(caddr_t addr, size_t len, int prot, int flags, int fd, off_t pos)
{
	struct file *fp;
	int error;

	if (flags & _MAP_LOW32)
		error = EINVAL;
	else if (fd == -1 && (flags & MAP_ANON) != 0)
		error = smmap_common(&addr, len, prot, flags,
		    NULL, (offset_t)pos);
	else if ((fp = getf(fd)) != NULL) {
		error = smmap_common(&addr, len, prot, flags,
		    fp, (offset_t)pos);
		releasef(fd);
	} else
		error = EBADF;

	return (error ? (caddr_t)(uintptr_t)set_errno(error) : addr);
}
#endif	/* _LP64 */

#if defined(_SYSCALL32_IMPL) || defined(_ILP32)

/*
 * ILP32 mmap(2) system call: 32-bit offset, 32-bit address.
 */
caddr_t
smmap32(caddr32_t addr, size32_t len, int prot, int flags, int fd, off32_t pos)
{
	struct file *fp;
	int error;
	caddr_t a = (caddr_t)(uintptr_t)addr;

	if (flags & _MAP_LOW32)
		error = EINVAL;
	else if (fd == -1 && (flags & MAP_ANON) != 0)
		error = smmap_common(&a, (size_t)len, prot,
		    flags | _MAP_LOW32, NULL, (offset_t)pos);
	else if ((fp = getf(fd)) != NULL) {
		error = smmap_common(&a, (size_t)len, prot,
		    flags | _MAP_LOW32, fp, (offset_t)pos);
		releasef(fd);
	} else
		error = EBADF;

	ASSERT(error != 0 || (uintptr_t)(a + len) < (uintptr_t)UINT32_MAX);

	return (error ? (caddr_t)(uintptr_t)set_errno(error) : a);
}

/*
 * ILP32 mmap64(2) system call: 64-bit offset, 32-bit address.
 *
 * Now things really get ugly because we can't use the C-style
 * calling convention for more than 6 args, and 64-bit parameter
 * passing on 32-bit systems is less than clean.
 */

struct mmaplf32a {
	caddr_t addr;
	size_t len;
#ifdef _LP64
	/*
	 * 32-bit contents, 64-bit cells
	 */
	uint64_t prot;
	uint64_t flags;
	uint64_t fd;
	uint64_t offhi;
	uint64_t offlo;
#else
	/*
	 * 32-bit contents, 32-bit cells
	 */
	uint32_t prot;
	uint32_t flags;
	uint32_t fd;
	uint32_t offhi;
	uint32_t offlo;
#endif
};

int
smmaplf32(struct mmaplf32a *uap, rval_t *rvp)
{
	struct file *fp;
	int error;
	caddr_t a = uap->addr;
	int flags = (int)uap->flags;
	int fd = (int)uap->fd;
#ifdef _BIG_ENDIAN
	offset_t off = ((u_offset_t)uap->offhi << 32) | (u_offset_t)uap->offlo;
#else
	offset_t off = ((u_offset_t)uap->offlo << 32) | (u_offset_t)uap->offhi;
#endif

	if (flags & _MAP_LOW32)
		error = EINVAL;
	else if (fd == -1 && (flags & MAP_ANON) != 0)
		error = smmap_common(&a, uap->len, (int)uap->prot,
		    flags | _MAP_LOW32, NULL, off);
	else if ((fp = getf(fd)) != NULL) {
		error = smmap_common(&a, uap->len, (int)uap->prot,
		    flags | _MAP_LOW32, fp, off);
		releasef(fd);
	} else
		error = EBADF;

	if (error == 0)
		rvp->r_val1 = (uintptr_t)a;
	return (error);
}

#endif	/* _SYSCALL32_IMPL || _ILP32 */

int
munmap(caddr_t addr, size_t len)
{
	struct proc *p = curproc;
	struct as *as = p->p_as;

	if (((uintptr_t)addr & PAGEOFFSET) != 0 || len == 0)
		return (set_errno(EINVAL));

	if (valid_usr_range(addr, len, 0, as, as->a_userlimit) != RANGE_OKAY)
		return (set_errno(EINVAL));

	/*
	 * Discard lwpchan mappings.
	 */
	if (p->p_lcp != NULL)
		lwpchan_delete_mapping(p, addr, addr + len);
	if (as_unmap(as, addr, len) != 0)
		return (set_errno(EINVAL));

	return (0);
}

int
mprotect(caddr_t addr, size_t len, int prot)
{
	struct as *as = curproc->p_as;
	uint_t uprot = prot | PROT_USER;
	int error;

	if (((uintptr_t)addr & PAGEOFFSET) != 0 || len == 0)
		return (set_errno(EINVAL));

	switch (valid_usr_range(addr, len, prot, as, as->a_userlimit)) {
	case RANGE_OKAY:
		break;
	case RANGE_BADPROT:
		return (set_errno(ENOTSUP));
	case RANGE_BADADDR:
	default:
		return (set_errno(ENOMEM));
	}

	error = as_setprot(as, addr, len, uprot);
	if (error)
		return (set_errno(error));
	return (0);
}

#define	MC_CACHE	128			/* internal result buffer */
#define	MC_QUANTUM	(MC_CACHE * PAGESIZE)	/* addresses covered in loop */

int
mincore(caddr_t addr, size_t len, char *vecp)
{
	struct as *as = curproc->p_as;
	caddr_t ea;			/* end address of loop */
	size_t rl;			/* inner result length */
	char vec[MC_CACHE];		/* local vector cache */
	int error;
	model_t model;
	long	llen;

	model = get_udatamodel();
	/*
	 * Validate form of address parameters.
	 */
	if (model == DATAMODEL_NATIVE) {
		llen = (long)len;
	} else {
		llen = (int32_t)(size32_t)len;
	}
	if (((uintptr_t)addr & PAGEOFFSET) != 0 || llen <= 0)
		return (set_errno(EINVAL));

	if (valid_usr_range(addr, len, 0, as, as->a_userlimit) != RANGE_OKAY)
		return (set_errno(ENOMEM));

	/*
	 * Loop over subranges of interval [addr : addr + len), recovering
	 * results internally and then copying them out to caller.  Subrange
	 * is based on the size of MC_CACHE, defined above.
	 */
	for (ea = addr + len; addr < ea; addr += MC_QUANTUM) {
		error = as_incore(as, addr,
		    (size_t)MIN(MC_QUANTUM, ea - addr), vec, &rl);
		if (rl != 0) {
			rl = (rl + PAGESIZE - 1) / PAGESIZE;
			if (copyout(vec, vecp, rl) != 0)
				return (set_errno(EFAULT));
			vecp += rl;
		}
		if (error != 0)
			return (set_errno(ENOMEM));
	}
	return (0);
}
