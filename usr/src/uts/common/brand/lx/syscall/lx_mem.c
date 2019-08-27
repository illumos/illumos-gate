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
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/policy.h>
#include <sys/lx_brand.h>
#include <sys/fcntl.h>
#include <sys/pathname.h>
#include <vm/seg_vn.h>
#include <vm/seg_spt.h>
#include <sys/shm_impl.h>
#include <vm/as.h>

/* From uts/common/os/grow.c */
extern int mprotect(caddr_t, size_t, int);
extern caddr_t smmap64(caddr_t, size_t, int, int, int, off_t);
extern int munmap(caddr_t, size_t);
/* From uts/common/syscall/close.c */
extern int close(int);
/* From uts/common/fs/proc/prsubr.c */
extern uint_t pr_getprot(struct seg *, int, void **, caddr_t *, caddr_t *,
    caddr_t);
/* From uts/common/vm/seg_spt.c */
extern struct seg_ops segspt_shmops;
/* From uts/common/syscall/memcntl.c */
extern int memcntl(caddr_t, size_t, int, caddr_t, int, int);
/* From uts/common/os/grow.c */
extern int smmap_common(caddr_t *, size_t, int, int, struct file *, offset_t);

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

/* Internal segment map flags */
#define	LX_SM_READ	0x01
#define	LX_SM_WRITE	0x02
#define	LX_SM_EXEC	0x04
#define	LX_SM_SHM	0x08
#define	LX_SM_ANON	0x10
#define	LX_SM_SHARED	0x20
#define	LX_SM_NORESERVE	0x40

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

/*
 * There are two forms of mmap, mmap() and mmap2().  The only difference is that
 * the final argument to mmap2() specifies the number of pages, not bytes. Also,
 * mmap2 is 32-bit only.
 *
 * Linux has a number of additional flags, but they are all deprecated.  We also
 * ignore the MAP_GROWSDOWN flag, which has no equivalent on Solaris.
 *
 * The Linux mmap() returns ENOMEM in some cases where illumos returns
 * EOVERFLOW, so we translate the errno as necessary.
 */

#define	LX_MAP_ANONYMOUS	0x00020
#define	LX_MAP_LOCKED		0x02000
#define	LX_MAP_NORESERVE	0x04000
#define	LX_MAP_32BIT		0x00040

#define	ONE_GB			0x40000000

static void lx_remap_anoncache_invalidate(uintptr_t, size_t);

static int
lx_ltos_mmap_flags(int flags)
{
	int new_flags;

	new_flags = flags & (MAP_TYPE | MAP_FIXED);

	if (flags & LX_MAP_ANONYMOUS)
		new_flags |= MAP_ANONYMOUS;
	if (flags & LX_MAP_NORESERVE)
		new_flags |= MAP_NORESERVE;

#if defined(_LP64)
	if (flags & LX_MAP_32BIT)
		new_flags |= MAP_32BIT;
#endif

	return (new_flags);
}

static void *
lx_mmap_common(void *addr, size_t len, int prot, int flags, int fd, off64_t off)
{
	caddr_t ret;
	lx_proc_data_t *lxpd = ptolxproc(curproc);

	/*
	 * Under Linux, the file descriptor is ignored when mapping zfod
	 * anonymous memory,  On illumos, we want the fd set to -1 for the
	 * same functionality.
	 */
	if (flags & LX_MAP_ANONYMOUS)
		fd = -1;

	/*
	 * We refuse, as a matter of principle, to overcommit memory.
	 * Unfortunately, several bits of important and popular software expect
	 * to be able to pre-allocate large amounts of virtual memory but then
	 * probably never use it.  One particularly bad example of this
	 * practice is golang. Another is the JVM.
	 *
	 * In the interest of running software, unsafe or not, we fudge
	 * something vaguely similar to overcommit by permanently enabling
	 * MAP_NORESERVE unless MAP_LOCKED was requested:
	 */
	if (!(flags & LX_MAP_LOCKED)) {
		flags |= LX_MAP_NORESERVE;
	}

	/*
	 * This is totally insane. The NOTES section in the linux mmap(2) man
	 * page claims that on some architectures, read protection may
	 * automatically include exec protection. It has been observed on a
	 * native linux system that the /proc/<pid>/maps file does indeed
	 * show that segments mmap'd from userland (such as libraries mapped in
	 * by the dynamic linker) all have exec the permission set, even for
	 * data segments.
	 *
	 * This insanity is tempered by the fact that the behavior is disabled
	 * for ELF binaries bearing a PT_GNU_STACK header which lacks PF_X
	 * (which most do).  Such a header will clear the READ_IMPLIES_EXEC
	 * flag from the process personality.
	 */
	if (prot & PROT_READ) {
		if ((lxpd->l_personality & LX_PER_READ_IMPLIES_EXEC) != 0) {
			prot |= PROT_EXEC;
		}
	}

	ret = smmap64(addr, len, prot, lx_ltos_mmap_flags(flags), fd, off);
	if (ttolwp(curthread)->lwp_errno != 0) {
		if (ttolwp(curthread)->lwp_errno == EOVERFLOW)
			(void) set_errno(ENOMEM);
		return ((void *)-1);
	}

	if (flags & LX_MAP_LOCKED) {
		(void) lx_mlock_common(MC_LOCK, (uintptr_t)ret, len);
		/* clear any errno from mlock */
		ttolwp(curthread)->lwp_errno = 0;
	}

	/*
	 * We have a new mapping; invalidate any cached anonymous regions that
	 * overlap(ped) with it.
	 */
	mutex_enter(&lxpd->l_remap_anoncache_lock);
	lx_remap_anoncache_invalidate((uintptr_t)ret, len);
	mutex_exit(&lxpd->l_remap_anoncache_lock);

	return (ret);
}

long
lx_mmap(void *addr, size_t len, int prot, int flags, int fd, off64_t off)
{
	return ((ssize_t)lx_mmap_common(addr, len, prot, flags, fd, off));
}

long
lx_mmap2(void *addr, size_t len, int prot, int flags,
    int fd, off_t off)
{
	return ((ssize_t)lx_mmap_common(addr, len, prot, flags, fd,
	    (off64_t)off * PAGESIZE));
}

long
lx_munmap(void *addr, size_t len)
{
	lx_proc_data_t *lxpd = ptolxproc(curproc);

	/*
	 * Invalidate any cached anonymous regions that overlap(ped) with it.
	 */
	mutex_enter(&lxpd->l_remap_anoncache_lock);
	lx_remap_anoncache_invalidate((uintptr_t)addr, len);
	mutex_exit(&lxpd->l_remap_anoncache_lock);

	return (munmap(addr, len));
}

#define	LX_MREMAP_MAYMOVE	1	/* mapping can be moved */
#define	LX_MREMAP_FIXED		2	/* address is fixed */

/*
 * Unfortunately, the Linux mremap() manpage contains a statement that is, at
 * best, grossly oversimplified: that mremap() "can be used to implement a
 * very efficient realloc(3)."  To the degree this is true at all, it is only
 * true narrowly (namely, when large buffers are being expanded but can't be
 * expanded in place due to virtual address space restrictions) -- but
 * apparently, someone took this very literally, because variants of glibc
 * appear to simply implement realloc() in terms of mremap().  This is
 * unfortunate because absent intelligent usage, it forces realloc() to have
 * an unncessary interaction with the VM system for small expansions -- and if
 * realloc() is itself abused (e.g., if a consumer repeatedly expands and
 * contracts the same memory buffer), the net result can be less efficient
 * than a much more naive realloc() implementation.  And if native Linux is
 * suboptimal in this case, we are deeply pathological, having not
 * historically supported mremap() for anonymous mappings at all.  To make
 * this at least palatable, we not only support remap for anonymous mappings
 * (see lx_remap_anon(), below), we also cache the metadata associated with
 * these anonymous remappings to reduce the need to search our address space.
 * We implement the anonymous metadata cache with l_remap_anoncache, an LRU
 * cache of lx_segmap_t's that correspond to anonymous segments that have been
 * resized (only anonymous mappings that have been remapped are cached). The
 * cache is part of the process's lx-brand-specifc data.
 */

/*
 * Search our address space (as) mappings to find the specified mapping. This
 * is derived from the procfs prgetmap() code. We implement the "reserved"
 * behavior on the segment so as to accommodate the case where an mmap()'d and
 * then ftruncate()'d file is being mremap()'d: we use the size of the
 * mapping (which we need to validate old_size).
 *
 * Return 0 if mapping is found, errno if there is a problem or if mapping
 * not found. If the mapping is found, we populate the mp parameter, vpp and
 * offp with the results.
 */
static int
lx_get_mapping(uintptr_t find_addr, size_t find_size, lx_segmap_t *mp,
    vnode_t **vpp, offset_t *offp)
{
	struct as *as = curproc->p_as;
	struct seg *seg;
	uint_t prot;
	caddr_t saddr, eaddr, naddr;

	/* pr_getprot asserts that the as is held as a writer */
	AS_LOCK_ENTER(as, RW_WRITER);

	seg = as_segat(as, (caddr_t)find_addr);
	if (seg == NULL || (seg->s_flags & S_HOLE) != 0) {
		AS_LOCK_EXIT(as);
		return (EFAULT);
	}

	/*
	 * We're interested in the reserved space, so we use the size of the
	 * segment itself.
	 */
	eaddr = seg->s_base + seg->s_size;
	for (saddr = seg->s_base; saddr < eaddr; saddr = naddr) {
		uintptr_t vaddr;
		size_t size;
		struct vnode *vp;
		void *tmp = NULL;

		prot = pr_getprot(seg, 1, &tmp, &saddr, &naddr, eaddr);
		if (saddr == naddr)
			continue;

		vaddr = (uintptr_t)saddr;
		size = (uintptr_t)naddr - (uintptr_t)saddr;

		if (vaddr == find_addr && find_size < size &&
		    (find_size & PAGEOFFSET) != 0) {
			/*
			 * We found a mapping but the size being requested is
			 * less than the mapping and not a multiple of our page
			 * size. If it is an anonymous mapping, that likely
			 * means the application did the initial mmap with this
			 * odd size. We'll round up to the next page boundary
			 * in this case.
			 */
			if (seg->s_ops == &segspt_shmops ||
			    (seg->s_ops == &segvn_ops &&
			    (SEGOP_GETVP(seg, saddr, &vp) != 0 ||
			    vp == NULL))) {
				/*
				 * It's anonymous, round up the size.
				 */
				find_size = ptob(btopr(find_size));
			}
		}

		/* Check if mapping matches our arguments */
		if (vaddr == find_addr && size == find_size) {
			struct vattr vattr;

			mp->lxsm_vaddr = vaddr;
			mp->lxsm_size = size;
			mp->lxsm_flags = 0;

			*offp = SEGOP_GETOFFSET(seg, saddr);

			if (prot & PROT_READ)
				mp->lxsm_flags |= LX_SM_READ;
			if (prot & PROT_WRITE)
				mp->lxsm_flags |= LX_SM_WRITE;
			if (prot & PROT_EXEC)
				mp->lxsm_flags |= LX_SM_EXEC;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_SHARED)
				mp->lxsm_flags |= LX_SM_SHARED;
			if (SEGOP_GETTYPE(seg, saddr) & MAP_NORESERVE)
				mp->lxsm_flags |= LX_SM_NORESERVE;
			if (seg->s_ops == &segspt_shmops ||
			    (seg->s_ops == &segvn_ops &&
			    (SEGOP_GETVP(seg, saddr, &vp) != 0 ||
			    vp == NULL)))
				mp->lxsm_flags |= LX_SM_ANON;

			if (seg->s_ops == &segspt_shmops) {
				mp->lxsm_flags |= LX_SM_SHM;
			} else if ((mp->lxsm_flags & LX_SM_SHARED) &&
			    curproc->p_segacct && shmgetid(curproc,
			    seg->s_base) != SHMID_NONE) {
				mp->lxsm_flags |= LX_SM_SHM;
			}

			vattr.va_mask = AT_FSID | AT_NODEID;
			if (seg->s_ops == &segvn_ops &&
			    SEGOP_GETVP(seg, saddr, &vp) == 0 &&
			    vp != NULL && vp->v_type == VREG &&
			    VOP_GETATTR(vp, &vattr, 0, CRED(),
			    NULL) == 0) {
				VN_HOLD(vp);
				*vpp = vp;
			} else {
				*vpp = NULL;
			}

			AS_LOCK_EXIT(as);
			return (0);
		}

		if (vaddr <= find_addr &&
		    find_addr + find_size < vaddr + size) {
			/*
			 * We have a mismatch, but our specified range is a
			 * subset of the actual segment; this is EINVAL.
			 */
			AS_LOCK_EXIT(as);
			DTRACE_PROBE2(lx__mremap__badsubset, caddr_t,
			    vaddr, size_t, size);
			return (EINVAL);
		}
	}

	AS_LOCK_EXIT(as);
	return (EFAULT);
}

static void
lx_remap_anoncache_invalidate(uintptr_t addr, size_t size)
{
	lx_proc_data_t *lxpd = ptolxproc(curproc);
	uint_t i;

	ASSERT(MUTEX_HELD(&lxpd->l_remap_anoncache_lock));

	if (lxpd->l_remap_anoncache_generation == 0)
		return;

	for (i = 0; i < LX_REMAP_ANONCACHE_NENTRIES; i++) {
		lx_segmap_t *map = &lxpd->l_remap_anoncache[i];

		/*
		 * If the ranges overlap at all, we zap it.
		 */
		if (addr < map->lxsm_vaddr + map->lxsm_size &&
		    map->lxsm_vaddr < addr + size) {
			bzero(map, sizeof (lx_segmap_t));
		}
	}
}

static void
lx_remap_anoncache_load(lx_segmap_t *map, size_t size)
{
	lx_proc_data_t *lxpd = ptolxproc(curproc);
	uint64_t oldest = UINT64_MAX;
	lx_segmap_t *evict = NULL;
	uint_t i;

	ASSERT(MUTEX_HELD(&lxpd->l_remap_anoncache_lock));

	for (i = 0; i < LX_REMAP_ANONCACHE_NENTRIES; i++) {
		lx_segmap_t *cp = &lxpd->l_remap_anoncache[i];

		if (cp->lxsm_vaddr == map->lxsm_vaddr) {
			/*
			 * We're already in the cache -- we just need to update
			 * our LRU field and size to reflect the hit.
			 */
			cp->lxsm_lru = lxpd->l_remap_anoncache_generation++;
			cp->lxsm_size = size;
			return;
		}

		if (cp->lxsm_vaddr == 0) {
			evict = cp;
			break;
		}

		if (cp->lxsm_lru < oldest) {
			oldest = cp->lxsm_lru;
			evict = cp;
		}
	}

	/* Update the entry we're evicting */
	ASSERT(evict != NULL);
	evict->lxsm_vaddr = map->lxsm_vaddr;
	evict->lxsm_size = size;
	evict->lxsm_flags = map->lxsm_flags;
	evict->lxsm_lru = lxpd->l_remap_anoncache_generation++;
}

static int lx_u2u_copy(void *, void *, size_t);

/*
 * As part of lx_remap() (see below) and to accommodate heavy realloc() use
 * cases (see the discussion of the l_remap_anoncache, above), we allow
 * anonymous segments to be "remapped" in that we are willing to truncate them
 * or append to them (as much as that's allowed by virtual address space
 * usage).  If we fall out of these cases, we take the more expensive option
 * of actually copying the data to a new segment -- but we locate the address
 * in a portion of the address space that should give us plenty of VA space to
 * expand.
 *
 * We return the address of the mapping or set errno if there is a problem.
 */
static long
lx_remap_anon(lx_segmap_t *mapin, size_t new_size, uint_t flags,
    uintptr_t new_addr)
{
	lx_segmap_t m;
	int mflags = MAP_ANON;
	int prot = 0;
	void *addr, *hint = NULL;

	ASSERT(MUTEX_HELD(&ptolxproc(curproc)->l_remap_anoncache_lock));

	/*
	 * Make a copy of the input lx_segmap_t argument since it might be
	 * a reference into the anon cache, and we're manipulating cache
	 * entries during this function.
	 */
	m = *mapin;

	/*
	 * If our new size is less than our old size and we're either not
	 * being ordered to move it or the address we're being ordered to
	 * move it to is our current address, we can just act as Procrustes
	 * and chop off anything larger than the new size.
	 */
	if (new_size < m.lxsm_size && (!(flags & LX_MREMAP_FIXED) ||
	    new_addr == m.lxsm_vaddr)) {
		if (munmap((void *)(m.lxsm_vaddr + new_size),
		    m.lxsm_size - new_size) != 0) {
			return (set_errno(EINVAL));
		}

		lx_remap_anoncache_load(&m, new_size);
		return (m.lxsm_vaddr);
	}

	if (m.lxsm_flags & LX_SM_SHM)
		return (set_errno(EINVAL));

	if (m.lxsm_flags & LX_SM_WRITE)
		prot |= PROT_WRITE;

	if (m.lxsm_flags & LX_SM_READ)
		prot |= PROT_READ;

	if (m.lxsm_flags & LX_SM_EXEC)
		prot |= PROT_EXEC;

	mflags |= (m.lxsm_flags & LX_SM_SHARED) ? MAP_SHARED : MAP_PRIVATE;

	if (m.lxsm_flags & LX_SM_NORESERVE)
		mflags |= MAP_NORESERVE;

	/*
	 * If we're not being told where to move it, let's try to expand our
	 * mapping in place by adding a fixed mapping after it.
	 */
	if (!(flags & LX_MREMAP_FIXED)) {
		void *tmp_addr = (void *)(m.lxsm_vaddr + m.lxsm_size);

		ASSERT(new_size > m.lxsm_size);
		addr = smmap64(tmp_addr, new_size - m.lxsm_size, prot,
		    mflags, -1, 0);
		if (ttolwp(curthread)->lwp_errno != 0) {
			/* There is no place to mmap some extra anon */
			return (set_errno(EINVAL));
		}

		if (addr == tmp_addr) {
			/* The expansion worked */
			lx_remap_anoncache_load(&m, new_size);
			return (m.lxsm_vaddr);
		}

		/*
		 * Our advisory address was not followed -- which, as a
		 * practical matter, means that the range conflicted with an
		 * extant mapping.  Unmap wherever our attempted expansion
		 * landed, and drop into the relocation case.
		 */
		(void) munmap(addr, new_size - m.lxsm_size);
	}

	lx_remap_anoncache_invalidate(m.lxsm_vaddr, m.lxsm_size);

	/*
	 * If we're here, we actually need to move this mapping -- so if we
	 * can't move it, we're done.
	 */
	if (!(flags & LX_MREMAP_MAYMOVE))
		return (set_errno(ENOMEM));

	/*
	 * If this is a shared private mapping, we can't remap it.
	 */
	if (m.lxsm_flags & LX_SM_SHARED)
		return (set_errno(EINVAL));

	if (flags & LX_MREMAP_FIXED) {
		mflags |= MAP_FIXED;
		hint = (void *)new_addr;
	} else {
		/*
		 * Search our address space for a gap to remap into. To give
		 * ourselves plenty of room for further mremap() expansion,
		 * we'll multiply our new size by 16 and look for a gap at
		 * least that big. Historically we looked for an empty gap
		 * around the 2GB region, so we start our search for the lowest
		 * gap in that vicinity.
		 */
		caddr_t base;
		size_t upper;

		base = (caddr_t)ONE_GB;
		upper = (uintptr_t)USERLIMIT - (uintptr_t)base;

		if (as_gap(curproc->p_as, (new_size << 4UL), &base, &upper,
		    AH_LO, NULL) != -1)
			hint = base;
	}

	addr = smmap64(hint, new_size, prot, mflags, -1, 0);
	if (ttolwp(curthread)->lwp_errno != 0) {
		return (ttolwp(curthread)->lwp_errno);
	}

	if (lx_u2u_copy((void *)m.lxsm_vaddr, addr, m.lxsm_size) != 0) {
		/* We couldn't complete the relocation, backout & fail */
		(void) munmap(addr, new_size);
		return (set_errno(ENOMEM));
	}

	(void) munmap((void *)m.lxsm_vaddr, m.lxsm_size);

	/*
	 * Add the relocated mapping to the cache.
	 */
	m.lxsm_vaddr = (uintptr_t)addr;
	lx_remap_anoncache_load(&m, new_size);

	return ((long)addr);
}

/*
 * We don't have a native mremap() (nor do we particularly want one), so
 * we emulate it strictly in lx.  The idea is simple: we just want to
 * mmap() the underlying object with the new size and rip down the old mapping.
 * However, this is slightly complicated because we don't actually have the
 * file descriptor that corresponds to the resized mapping. So to get a file
 * descriptor, we may have to search our address space for the mapping and use
 * the associated vnode to create a file descriptor. Assuming that this
 * succeeds, we then mmap() it and rip down the original mapping.  There are
 * clearly many reasons why this might fail; absent a more apt errno (e.g.,
 * ENOMEM in some cases), we return EINVAL to denote these cases.
 */
long
lx_mremap(uintptr_t old_addr, size_t old_size, size_t new_size, int flags,
    uintptr_t new_addr)
{
	int prot = 0, oflags, mflags = 0, i, res;
	lx_segmap_t map, *mp;
	int rval = 0;
	lx_proc_data_t *lxpd;
	offset_t off;
	struct vnode *vp = NULL;
	file_t *fp;
	caddr_t naddr;

	if (flags & LX_MREMAP_FIXED) {
		/* MREMAP_FIXED requires MREMAP_MAYMOVE */
		if ((flags & LX_MREMAP_MAYMOVE) == 0)
			return (set_errno(EINVAL));

		if (new_addr & PAGEOFFSET)
			return (set_errno(EINVAL));

		mflags |= MAP_FIXED;
	} else {
		if (new_size == old_size)
			return (old_addr);

		/* new_addr is optional and only valid when LX_MREMAP_FIXED. */
		new_addr = (uintptr_t)NULL;
	}

	if (old_addr & PAGEOFFSET)
		return (set_errno(EINVAL));

	if (new_size == 0)
		return (set_errno(EINVAL));

	/*
	 * First consult the anoncache; if we find the segment there, we'll
	 * drop straight into lx_remap_anon() and save ourself the pain of
	 * searching our address space.
	 */
	lxpd = ptolxproc(curproc);
	mutex_enter(&lxpd->l_remap_anoncache_lock);

	for (i = 0; i < LX_REMAP_ANONCACHE_NENTRIES; i++) {
		long rv;

		mp = &lxpd->l_remap_anoncache[i];

		if (mp->lxsm_vaddr != old_addr)
			continue;

		if (mp->lxsm_size != old_size)
			continue;

		/*
		 * lx_remap_anon will either:
		 * a) expand/contract in place, returning old_addr
		 * b) relocate & expand the mapping, returning a new address
		 * c) there will be an error of some sort and errno will be set
		 */
		rv = lx_remap_anon(mp, new_size, flags, new_addr);
		mutex_exit(&lxpd->l_remap_anoncache_lock);
		return (rv);
	}

	mutex_exit(&lxpd->l_remap_anoncache_lock);

	/*
	 * Search our address space to find the specified mapping.
	 */
	if ((res = lx_get_mapping(old_addr, old_size, &map, &vp, &off)) > 0)
		return (set_errno(res));

	/*
	 * We found the mapping.
	 */
	mp = &map;
	DTRACE_PROBE1(lx__mremap__seg, lx_segmap_t *, mp);

	if (mp->lxsm_flags & LX_SM_SHM) {
		/*
		 * If this is either ISM or System V shared memory, we're not
		 * going to remap it.
		 */
		rval = set_errno(EINVAL);
		goto out;
	}

	if (mp->lxsm_flags & LX_SM_ANON) {
		/*
		 * This is an anonymous mapping -- which is the one case in
		 * which we perform something that approaches a true remap.
		 */
		long rv;

		if (vp != NULL)
			VN_RELE(vp);
		mutex_enter(&lxpd->l_remap_anoncache_lock);
		rv = lx_remap_anon(mp, new_size, flags, new_addr);
		mutex_exit(&lxpd->l_remap_anoncache_lock);
		return (rv);
	}

	/* The rest of the code is for a 'named' mapping */

	if (!(flags & LX_MREMAP_MAYMOVE)) {
		/*
		 * If we're not allowed to move this mapping, we're going to
		 * act as if we can't expand it.
		 */
		rval = set_errno(ENOMEM);
		goto out;
	}

	if (!(mp->lxsm_flags & LX_SM_SHARED)) {
		/*
		 * If this is a private mapping, we're not going to remap it.
		 */
		rval = set_errno(EINVAL);
		goto out;
	}

	oflags = (mp->lxsm_flags & LX_SM_WRITE) ? (FWRITE | FREAD) : FREAD;
	if (vp == NULL) {
		/*
		 * If vp is NULL, the path might not exist. We're going to kick
		 * it back with EINVAL.
		 */
		rval = set_errno(EINVAL);
		goto out;
	}

	/* falloc cannot fail with a NULL fdp. */
	VERIFY0(falloc(vp, oflags, &fp, NULL));
	mutex_exit(&fp->f_tlock);

	if (mp->lxsm_flags & LX_SM_WRITE)
		prot |= PROT_WRITE;

	if (mp->lxsm_flags & LX_SM_READ)
		prot |= PROT_READ;

	if (mp->lxsm_flags & LX_SM_EXEC)
		prot |= PROT_EXEC;

	mflags |= MAP_SHARED;

	/*
	 * We're using smmap_common to pass the fp directly, instead of
	 * initializing a temporary file descriptor for smmap64(), so as to
	 * prevent any inadvertent use of that temporary fd within the
	 * application.
	 */
	naddr = (caddr_t)new_addr;
	rval = smmap_common(&naddr, new_size, prot, mflags, fp, off);

	mutex_enter(&fp->f_tlock);
	unfalloc(fp);

	if (rval != 0) {
		rval = set_errno(ENOMEM);
		goto out;
	}

	/*
	 * Our mapping succeeded; we're now going to rip down the old mapping.
	 */
	(void) munmap((void *)old_addr, old_size);

out:
	if (vp != NULL)
		VN_RELE(vp);

	if (rval == 0)
		return ((long)naddr);
	return ((long)rval);
}

#pragma GCC diagnostic ignored "-Wclobbered"
/*
 * During mremap we had to relocate the initial anonymous mapping to a new
 * location (a new anonymous mapping). Copy the user-level data from the first
 * mapping to the second mapping.
 *
 * We have to lock both sides to ensure there is no fault. We do this in 16MB
 * chunks at a time and we do not concern ourselves with the zone's
 * max-locked-memory rctl.
 *
 * Keep this function at the end since we're disabling the compiler's "clobber"
 * check due to the on_fault call.
 */
static int
lx_u2u_copy(void *src, void *dst, size_t len)
{
	size_t mlen;
	caddr_t sp, dp;
	int err;
	page_t **ppa_src, **ppa_dst;
	label_t ljb;
	struct as *p_as = curproc->p_as;

	/* Both sides should be page aligned since they're from smmap64 */
	ASSERT(((uintptr_t)src & PAGEOFFSET) == 0);
	ASSERT(((uintptr_t)dst & PAGEOFFSET) == 0);
	/* Both came from mmap, so they should be valid user pointers */
	ASSERT((uintptr_t)src < USERLIMIT && (uintptr_t)dst < USERLIMIT);

	sp = src;
	dp = dst;

	do {
		mlen = MIN(len, 16 * 1024 * 1024);

		err = as_pagelock(p_as, &ppa_src, sp, mlen, S_READ);
		if (err != 0) {
			return (err);
		}
		err = as_pagelock(p_as, &ppa_dst, dp, mlen, S_WRITE);
		if (err != 0) {
			as_pageunlock(p_as, ppa_src, sp, mlen, S_READ);
			return (err);
		}

		DTRACE_PROBE3(lx__mremap__copy, void *, sp, void *, dp,
		    size_t, mlen);

		/* on_fault calls smap_disable */
		if (on_fault(&ljb)) {
			/*
			 * Given that the pages are locked and smap is disabled,
			 * we really should never get here. If we somehow do
			 * get here, the copy fails just as if we could not
			 * lock the pages to begin with.
			 */
			as_pageunlock(p_as, ppa_dst, dp, mlen, S_WRITE);
			as_pageunlock(p_as, ppa_src, sp, mlen, S_READ);
			return (EFAULT);
		}
		ucopy(sp, dp, mlen);
		no_fault();		/* calls smap_enable */

		as_pageunlock(p_as, ppa_dst, dp, mlen, S_WRITE);
		as_pageunlock(p_as, ppa_src, sp, mlen, S_READ);

		len -= mlen;
		sp += mlen;
		dp += mlen;
	} while (len > 0);

	return (0);
}
