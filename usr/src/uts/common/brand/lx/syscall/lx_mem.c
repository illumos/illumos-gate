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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/policy.h>
#include <sys/lx_brand.h>
#include <vm/as.h>

/* From uts/common/os/grow.c */
extern int mprotect(caddr_t, size_t, int);
/* From uts/common/syscall/memcntl.c */
extern int memcntl(caddr_t, size_t, int, caddr_t, int, int);

/*
 * After Linux 2.6.8, an unprivileged process can lock memory up to its
 * RLIMIT_MEMLOCK resource limit.
 *
 * Within memcntl() it assumes we have PRIV_PROC_LOCK_MEMORY, or the check in
 * secpolicy_lock_memory() will fail when we attempt to lock memory. Thus,
 * to support the Linux semantics, we bypass memcntl() and perform the locking
 * operations directly.
 */

#define	LX_MADV_NORMAL		0
#define	LX_MADV_RANDOM		1
#define	LX_MADV_SEQUENTIAL	2
#define	LX_MADV_WILLNEED	3
#define	LX_MADV_DONTNEED	4
#define	LX_MADV_FREE		8
#define	LX_MADV_REMOVE		9
#define	LX_MADV_DONTFORK	10
#define	LX_MADV_DOFORK		11
#define	LX_MADV_MERGEABLE	12
#define	LX_MADV_UNMERGEABLE	13
#define	LX_MADV_HUGEPAGE	14
#define	LX_MADV_NOHUGEPAGE	15
#define	LX_MADV_DONTDUMP	16
#define	LX_MADV_DODUMP		17

#define	LX_VALID_MSYNC	(MS_ASYNC|MS_INVALIDATE|MS_SYNC)

#define	LX_PROT_GROWSDOWN	0x01000000
#define	LX_PROT_GROWSUP		0x02000000

/* For convenience */
#define	LX_PROT_GROWMASK	(LX_PROT_GROWSUP|LX_PROT_GROWSDOWN)

/* From lx_rlimit.c */
extern void lx_get_rctl(char *, struct rlimit64 *);

static int
lx_mlock_common(int op, uintptr_t addr, size_t len)
{
	int err;
	struct as *as = curproc->p_as;
	const uintptr_t align_addr = addr & (uintptr_t)PAGEMASK;
	const size_t align_len = P2ROUNDUP(len + (addr & PAGEOFFSET), PAGESIZE);

	if (len == 0) {
		/* Linux short-circuits to success on zero length */
		return (0);
	} else if ((align_addr + align_len) <= align_addr) {
		/* Catch overflow (including when aligning len) */
		return (set_errno(EINVAL));
	}

	err = as_ctl(as, (caddr_t)align_addr, align_len, op, 0, 0, NULL, 0);
	if (err == EAGAIN)
		err = ENOMEM;
	return (err == 0 ? 0 : set_errno(err));
}

int
lx_mlock(uintptr_t addr, size_t len)
{
	int err;

	/*
	 * If the the caller is not privileged and either the limit is 0, or
	 * the kernel version is earlier than 2.6.9, then fail with EPERM. See
	 * LTP mlock2.c.
	 */
	if ((err = secpolicy_lock_memory(CRED())) != 0) {
		struct rlimit64 rlim64;

		lx_get_rctl("process.max-locked-memory", &rlim64);
		if (rlim64.rlim_cur == 0 ||
		    lx_kern_release_cmp(curzone, "2.6.9") < 0)
			return (set_errno(err));
	}

	return (lx_mlock_common(MC_LOCK, addr, len));
}

int
lx_munlock(uintptr_t addr, size_t len)
{
	return (lx_mlock_common(MC_UNLOCK, addr, len));
}

int
lx_mlockall(int flags)
{
	int err;
	struct as *as = curproc->p_as;

	/*
	 * If the the caller is not privileged and either the limit is 0, or
	 * the kernel version is earlier than 2.6.9, then fail with EPERM. See
	 * LTP mlockall2.c.
	 */
	if ((err = secpolicy_lock_memory(CRED())) != 0) {
		struct rlimit64 rlim64;

		lx_get_rctl("process.max-locked-memory", &rlim64);
		if (rlim64.rlim_cur == 0 ||
		    lx_kern_release_cmp(curzone, "2.6.9") < 0)
			return (set_errno(err));
	}

	if ((flags & ~(MCL_FUTURE | MCL_CURRENT)) || flags == 0)
		return (set_errno(EINVAL));

	err = as_ctl(as, 0, 0, MC_LOCKAS, 0, (uintptr_t)flags, NULL, 0);
	if (err == EAGAIN)
		err = ENOMEM;
	return (err == 0 ? 0 : set_errno(err));
}

int
lx_munlockall(void)
{
	int err;
	struct as *as = curproc->p_as;

	if (lx_kern_release_cmp(curzone, "2.6.9") < 0) {
		if ((err = secpolicy_lock_memory(CRED())) != 0)
			return (set_errno(err));
	}

	err = as_ctl(as, 0, 0, MC_UNLOCKAS, 0, 0, NULL, 0);
	return (err == 0 ? 0 : set_errno(err));
}

int
lx_msync(uintptr_t addr, size_t len, int flags)
{
	const size_t align_len = P2ROUNDUP(len, PAGESIZE);

	if ((addr & PAGEOFFSET) != 0 ||
	    (flags & ~LX_VALID_MSYNC) != 0) {
		return (set_errno(EINVAL));
	} else if (len == 0) {
		/* Linux short-circuits to success on zero length */
		return (0);
	} else if ((addr + align_len) < addr) {
		/* Catch overflow (including when aligning len) */
		return (set_errno(ENOMEM));
	}

	return (memcntl((caddr_t)addr, align_len, MC_SYNC,
	    (caddr_t)(uintptr_t)flags, 0, 0));
}

int
lx_madvise(uintptr_t addr, size_t len, int advice)
{
	int err;
	const size_t align_len = P2ROUNDUP(len, PAGESIZE);

	switch (advice) {
	case LX_MADV_REMOVE:
		/* approximately similar */
		advice = MADV_FREE;
		break;

	case LX_MADV_DONTNEED:
		/*
		 * On Linux, MADV_DONTNEED implies an immediate purge of the
		 * specified region.  This is spuriously different from
		 * (nearly) every other Unix, having apparently been done to
		 * mimic the semantics on Digital Unix (!).  This is bad enough
		 * (MADV_FREE both has better semantics and results in better
		 * performance), but it gets worse:  Linux applications (and
		 * notably, jemalloc) have managed to depend on the busted
		 * semantics of MADV_DONTNEED on Linux.  We implement these
		 * semantics via MADV_PURGE -- and we translate our advice
		 * accordingly.
		 */
		advice = MADV_PURGE;
		break;

	case LX_MADV_FREE:
		advice = MADV_FREE;
		break;

	case LX_MADV_NORMAL:
	case LX_MADV_RANDOM:
	case LX_MADV_SEQUENTIAL:
	case LX_MADV_WILLNEED:
		/* These map directly to the illumos values */
		break;

	case LX_MADV_DONTFORK:
	case LX_MADV_DOFORK:
	case LX_MADV_HUGEPAGE:
	case LX_MADV_NOHUGEPAGE:
	case LX_MADV_DONTDUMP:
	case LX_MADV_DODUMP:
		/* harmless to pretend these work */
		return (0);
	default:
		return (set_errno(EINVAL));
	}

	if ((addr & PAGEOFFSET) != 0) {
		return (set_errno(EINVAL));
	} else if (len == 0) {
		/* Linux short-circuits to success on zero length */
		return (0);
	} else if ((addr + align_len) <= addr) {
		/*
		 * Catch overflow (including when aligning len).  Unlike
		 * similar syscalls, this is an EINVAL failure for madvise(2).
		 */
		return (set_errno(EINVAL));
	}

	err = memcntl((caddr_t)addr, align_len, MC_ADVISE,
	    (caddr_t)(intptr_t)advice, 0, 0);
	if (err == EBUSY) {
		if (advice != MADV_PURGE) {
			return (set_errno(EINVAL));
		}
		/*
		 * If we received an EBUSY from a MADV_PURGE, we will now try
		 * again with a MADV_DONTNEED: there are conditions (namely,
		 * with locked mappings that haven't yet been faulted in) where
		 * MADV_PURGE will fail but MADV_DONTNEED will succeed.  If
		 * this succeeds, we'll call the operation a success; if not,
		 * we'll kick back EINVAL.
		 */
		advice = MADV_DONTNEED;
		err = memcntl((caddr_t)addr, align_len, MC_ADVISE,
		    (caddr_t)(intptr_t)advice, 0, 0);
		if (err != 0) {
			return (set_errno(EINVAL));
		}
		/* Clear the old errno since success was eventually achieved. */
		ttolwp(curthread)->lwp_errno = 0;
	}
	return (err);
}

int
lx_mprotect(uintptr_t addr, size_t len, int prot)
{
	const size_t align_len = P2ROUNDUP(len, PAGESIZE);

	/*
	 * The flags for native mprotect(2) are essentially the same as those
	 * on Linux, with the exception of PROT_GROWSUP/PROT_GROWSDOWN, for
	 * which there is no native analog.  Those flags are presently ignored,
	 * unless they are both present, which represents an invalid argument.
	 */
	if ((prot & LX_PROT_GROWMASK) == LX_PROT_GROWMASK) {
		return (set_errno(EINVAL));
	}
	prot &= ~(LX_PROT_GROWMASK);

	if ((addr & PAGEOFFSET) != 0) {
		return (set_errno(EINVAL));
	} else if (len == 0) {
		/* Linux short-circuits to success on zero length */
		return (0);
	} else if ((addr + align_len) <= addr) {
		/* Catch overflow (including when aligning len) */
		return (set_errno(ENOMEM));
	}

	return (mprotect((void *)addr, align_len, prot));
}
