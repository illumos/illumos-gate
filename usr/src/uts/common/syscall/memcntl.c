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
 * Copyright (c) 2015 Joyent, Inc.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <sys/types.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/unistd.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/mman.h>
#include <sys/tuneable.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/vmsystm.h>
#include <sys/debug.h>
#include <sys/policy.h>

#include <vm/as.h>
#include <vm/seg.h>

static uint_t mem_getpgszc(size_t);

/*
 * Memory control operations
 */
int
memcntl(caddr_t addr, size_t len, int cmd, caddr_t arg, int attr, int mask)
{
	struct as *as = ttoproc(curthread)->p_as;
	struct proc *p = ttoproc(curthread);
	size_t pgsz;
	uint_t szc, oszc, pgcmd;
	int error = 0;
	faultcode_t fc;
	uintptr_t iarg;
	STRUCT_DECL(memcntl_mha, mha);

	if (mask)
		return (set_errno(EINVAL));
	if ((cmd == MC_LOCKAS) || (cmd == MC_UNLOCKAS)) {
		if ((addr != 0) || (len != 0)) {
			return (set_errno(EINVAL));
		}
	} else if (cmd != MC_HAT_ADVISE) {
		if (((uintptr_t)addr & PAGEOFFSET) != 0 || len == 0) {
			return (set_errno(EINVAL));
		}
		/*
		 * We're only concerned with the address range
		 * here, not the protections.  The protections
		 * are only used as a "filter" in this code,
		 * they aren't set or modified here.
		 */
		if (valid_usr_range(addr, len, 0, as,
		    as->a_userlimit) != RANGE_OKAY) {
			return (set_errno(ENOMEM));
		}
	}

	if (cmd == MC_HAT_ADVISE) {
		if (attr != 0 || mask != 0) {
			return (set_errno(EINVAL));
		}

	} else {
		if ((VALID_ATTR & attr) != attr) {
			return (set_errno(EINVAL));
		}
		if ((attr & SHARED) && (attr & PRIVATE)) {
			return (set_errno(EINVAL));
		}
		if (((cmd == MC_LOCKAS) || (cmd == MC_LOCK) ||
		    (cmd == MC_UNLOCKAS) || (cmd == MC_UNLOCK)) &&
		    (error = secpolicy_lock_memory(CRED())) != 0)
			return (set_errno(error));
	}
	if (attr) {
		attr |= PROT_USER;
	}

	switch (cmd) {
	case MC_SYNC:
		/*
		 * MS_SYNC used to be defined to be zero but is now non-zero.
		 * For binary compatibility we still accept zero
		 * (the absence of MS_ASYNC) to mean the same thing.
		 */
		iarg = (uintptr_t)arg;
		if ((iarg & ~MS_INVALIDATE) == 0)
			iarg |= MS_SYNC;

		if (((iarg & ~(MS_SYNC|MS_ASYNC|MS_INVALIDATE)) != 0) ||
		    ((iarg & (MS_SYNC|MS_ASYNC)) == (MS_SYNC|MS_ASYNC))) {
			error = set_errno(EINVAL);
		} else {
			error = as_ctl(as, addr, len, cmd, attr, iarg, NULL, 0);
			if (error) {
				(void) set_errno(error);
			}
		}
		return (error);
	case MC_LOCKAS:
		if ((uintptr_t)arg & ~(MCL_FUTURE|MCL_CURRENT) ||
		    (uintptr_t)arg == 0) {
			return (set_errno(EINVAL));
		}
		break;
	case MC_LOCK:
	case MC_UNLOCKAS:
	case MC_UNLOCK:
		break;
	case MC_HAT_ADVISE:
		/*
		 * Set prefered page size.
		 */
		STRUCT_INIT(mha, get_udatamodel());
		if (copyin(arg, STRUCT_BUF(mha), STRUCT_SIZE(mha))) {
			return (set_errno(EFAULT));
		}

		pgcmd = STRUCT_FGET(mha, mha_cmd);

		/*
		 * Currently only MHA_MAPSIZE_VA, MHA_MAPSIZE_STACK
		 * and MHA_MAPSIZE_BSSBRK are supported. Only one
		 * command may be specified at a time.
		 */
		if ((~(MHA_MAPSIZE_VA|MHA_MAPSIZE_STACK|MHA_MAPSIZE_BSSBRK) &
		    pgcmd) || pgcmd == 0 || !ISP2(pgcmd) ||
		    STRUCT_FGET(mha, mha_flags))
			return (set_errno(EINVAL));

		pgsz = STRUCT_FGET(mha, mha_pagesize);

		/*
		 * call platform specific map_pgsz() routine to get the
		 * optimal pgsz if pgsz is 0.
		 *
		 * For stack and heap operations addr and len must be zero.
		 */
		if ((pgcmd & (MHA_MAPSIZE_BSSBRK|MHA_MAPSIZE_STACK)) != 0) {
			if (addr != NULL || len != 0) {
				return (set_errno(EINVAL));
			}

			/*
			 * Disable autompss for this process unless pgsz == 0,
			 * which means the system should pick.  In the
			 * pgsz == 0 case, leave the SAUTOLPG setting alone, as
			 * we don't want to enable it when someone has
			 * disabled automatic large page selection for the
			 * whole system.
			 */
			mutex_enter(&p->p_lock);
			if (pgsz != 0) {
				p->p_flag &= ~SAUTOLPG;
			}
			mutex_exit(&p->p_lock);

			as_rangelock(as);

			if (pgsz == 0) {
				int	type;

				if (pgcmd == MHA_MAPSIZE_BSSBRK)
					type = MAPPGSZ_HEAP;
				else
					type = MAPPGSZ_STK;

				pgsz = map_pgsz(type, p, 0, 0, 1);
			}
		} else {
			/*
			 * addr and len must be valid for range specified.
			 */
			if (valid_usr_range(addr, len, 0, as,
			    as->a_userlimit) != RANGE_OKAY) {
				return (set_errno(ENOMEM));
			}
			/*
			 * Note that we don't disable automatic large page
			 * selection for anon segments based on use of
			 * memcntl().
			 */
			if (pgsz == 0) {
				error = as_set_default_lpsize(as, addr, len);
				if (error) {
					(void) set_errno(error);
				}
				return (error);
			}

			/*
			 * addr and len must be prefered page size aligned
			 */
			if (!IS_P2ALIGNED(addr, pgsz) ||
			    !IS_P2ALIGNED(len, pgsz)) {
				return (set_errno(EINVAL));
			}
		}

		szc = mem_getpgszc(pgsz);
		if (szc == (uint_t)-1) {
			if ((pgcmd & (MHA_MAPSIZE_BSSBRK|MHA_MAPSIZE_STACK))
			    != 0) {
				as_rangeunlock(as);
			}
			return (set_errno(EINVAL));
		}

		/*
		 * For stack and heap operations we first need to pad
		 * out existing range (create new mappings) to the new
		 * prefered page size boundary. Also the start of the
		 * .bss for the heap or user's stack base may not be on
		 * the new prefered page size boundary. For these cases
		 * we align the base of the request on the new prefered
		 * page size.
		 */
		if (pgcmd & MHA_MAPSIZE_BSSBRK) {
			if (szc == p->p_brkpageszc) {
				as_rangeunlock(as);
				return (0);
			}
			if (szc > p->p_brkpageszc) {
				error = brk_internal(p->p_brkbase
				    + p->p_brksize, szc);
				if (error) {
					as_rangeunlock(as);
					return (set_errno(error));
				}
			}
			/*
			 * It is possible for brk_internal to silently fail to
			 * promote the heap size, so don't panic or ASSERT.
			 */
			if (!IS_P2ALIGNED(p->p_brkbase + p->p_brksize, pgsz)) {
				as_rangeunlock(as);
				return (set_errno(ENOMEM));
			}
			oszc = p->p_brkpageszc;
			p->p_brkpageszc = szc;

			addr = (caddr_t)P2ROUNDUP((uintptr_t)p->p_bssbase,
			    pgsz);
			len = (p->p_brkbase + p->p_brksize) - addr;
			ASSERT(IS_P2ALIGNED(len, pgsz));
			/*
			 * Perhaps no existing pages to promote.
			 */
			if (len == 0) {
				as_rangeunlock(as);
				return (0);
			}
		}
		/*
		 * The code below, as does grow.c, assumes stacks always grow
		 * downward.
		 */
		if (pgcmd & MHA_MAPSIZE_STACK) {
			if (szc == p->p_stkpageszc) {
				as_rangeunlock(as);
				return (0);
			}

			if (szc > p->p_stkpageszc) {
				error = grow_internal(p->p_usrstack -
				    p->p_stksize, szc);
				if (error) {
					as_rangeunlock(as);
					return (set_errno(error));
				}
			}
			/*
			 * It is possible for grow_internal to silently fail to
			 * promote the stack size, so don't panic or ASSERT.
			 */
			if (!IS_P2ALIGNED(p->p_usrstack - p->p_stksize, pgsz)) {
				as_rangeunlock(as);
				return (set_errno(ENOMEM));
			}
			oszc = p->p_stkpageszc;
			p->p_stkpageszc = szc;

			addr = p->p_usrstack - p->p_stksize;
			len = P2ALIGN(p->p_stksize, pgsz);

			/*
			 * Perhaps nothing to promote.
			 */
			if (len == 0 || addr >= p->p_usrstack ||
			    (addr + len) < addr) {
				as_rangeunlock(as);
				return (0);
			}
		}
		ASSERT(IS_P2ALIGNED(addr, pgsz));
		ASSERT(IS_P2ALIGNED(len, pgsz));
		error = as_setpagesize(as, addr, len, szc, B_TRUE);

		/*
		 * On stack or heap failures restore original
		 * pg size code.
		 */
		if (error) {
			if ((pgcmd & MHA_MAPSIZE_BSSBRK) != 0) {
				p->p_brkpageszc = oszc;
			}
			if ((pgcmd & MHA_MAPSIZE_STACK) != 0) {
				p->p_stkpageszc = oszc;
			}
			(void) set_errno(error);
		}
		if ((pgcmd & (MHA_MAPSIZE_BSSBRK|MHA_MAPSIZE_STACK)) != 0) {
			as_rangeunlock(as);
		}
		return (error);
	case MC_ADVISE:
		if ((uintptr_t)arg == MADV_FREE ||
		    (uintptr_t)arg == MADV_PURGE) {
			len &= PAGEMASK;
		}
		switch ((uintptr_t)arg) {
		case MADV_WILLNEED:
			fc = as_faulta(as, addr, len);
			if (fc) {
				if (FC_CODE(fc) == FC_OBJERR)
					error = set_errno(FC_ERRNO(fc));
				else if (FC_CODE(fc) == FC_NOMAP)
					error = set_errno(ENOMEM);
				else
					error = set_errno(EINVAL);
				return (error);
			}
			break;

		case MADV_DONTNEED:
			/*
			 * For now, don't need is turned into an as_ctl(MC_SYNC)
			 * operation flagged for async invalidate.
			 */
			error = as_ctl(as, addr, len, MC_SYNC, attr,
			    MS_ASYNC | MS_INVALIDATE, NULL, 0);
			if (error)
				(void) set_errno(error);
			return (error);

		default:
			error = as_ctl(as, addr, len, cmd, attr,
			    (uintptr_t)arg, NULL, 0);
			if (error)
				(void) set_errno(error);
			return (error);
		}
		break;
	case MC_INHERIT_ZERO:
		if (arg != 0 || attr != 0 || mask != 0)
			return (set_errno(EINVAL));
		break;
	default:
		return (set_errno(EINVAL));
	}

	error = as_ctl(as, addr, len, cmd, attr, (uintptr_t)arg, NULL, 0);

	if (error)
		(void) set_errno(error);
	return (error);
}

/*
 * Return page size code for page size passed in. If
 * matching page size not found or supported, return -1.
 */
static uint_t
mem_getpgszc(size_t pgsz) {
	return ((uint_t)page_szc_user_filtered(pgsz));
}
