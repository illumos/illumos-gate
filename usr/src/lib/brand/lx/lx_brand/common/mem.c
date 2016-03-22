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
 * Copyright 2016 Joyent, Inc.
 */

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <procfs.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/lx_debug.h>
#include <sys/lx_misc.h>
#include <sys/lx_syscall.h>

/*
 * There are two forms of mmap, mmap() and mmap2().  The only difference is that
 * the final argument to mmap2() specifies the number of pages, not bytes.
 * Linux has a number of additional flags, but they are all deprecated.  We also
 * ignore the MAP_GROWSDOWN flag, which has no equivalent on Solaris.
 *
 * The Linux mmap() returns ENOMEM in some cases where Solaris returns
 * EOVERFLOW, so we translate the errno as necessary.
 */

int pagesize;	/* needed for mmap2() */

#define	LX_MAP_ANONYMOUS	0x00020
#define	LX_MAP_LOCKED		0x02000
#define	LX_MAP_NORESERVE	0x04000
#define	LX_MAP_32BIT		0x00040

#define	LX_MADV_REMOVE		9
#define	LX_MADV_DONTFORK	10
#define	LX_MADV_DOFORK		11
#define	LX_MADV_MERGEABLE	12
#define	LX_MADV_UNMERGEABLE	13
#define	LX_MADV_HUGEPAGE	14
#define	LX_MADV_NOHUGEPAGE	15
#define	LX_MADV_DONTDUMP	16
#define	LX_MADV_DODUMP		17

static void lx_remap_anoncache_invalidate(uintptr_t, size_t);

static int
ltos_mmap_flags(int flags)
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
mmap_common(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4,
    uintptr_t p5, off64_t p6)
{
	void *addr = (void *)p1;
	size_t len = p2;
	int prot = p3;
	int flags = p4;
	int fd = p5;
	off64_t off = p6;
	void *ret;

	if (LX_DEBUG_ISENABLED) {
		char *path, path_buf[MAXPATHLEN];

		path = lx_fd_to_path(fd, path_buf, sizeof (path_buf));
		if (path == NULL)
			path = "?";

		lx_debug("\tmmap_common(): fd = %d - %s", fd, path);
	}

	/*
	 * Under Linux, the file descriptor is ignored when mapping zfod
	 * anonymous memory,  On Solaris, we want the fd set to -1 for the
	 * same functionality.
	 */
	if (flags & LX_MAP_ANONYMOUS)
		fd = -1;

	/*
	 * We refuse, as a matter of principle, to overcommit memory.
	 * Unfortunately, several bits of important and popular software expect
	 * to be able to pre-allocate large amounts of virtual memory but then
	 * probably never use it.  One particularly bad example of this
	 * practice is golang.
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
		unsigned int personality;

		personality = syscall(SYS_brand, B_GET_PERSONALITY);
		if ((personality & LX_PER_READ_IMPLIES_EXEC) != 0) {
			prot |= PROT_EXEC;
		}
	}

	ret = mmap64(addr, len, prot, ltos_mmap_flags(flags), fd, off);

	if (ret == MAP_FAILED)
		return ((void *)(long)(errno == EOVERFLOW ? -ENOMEM : -errno));

	if (flags & LX_MAP_LOCKED)
		(void) mlock(ret, len);

	/*
	 * We have a new mapping; invalidate any cached anonymous regions that
	 * overlap(ped) with it.
	 */
	lx_remap_anoncache_invalidate((uintptr_t)ret, len);

	return (ret);
}

long
lx_mmap(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4,
    uintptr_t p5, uintptr_t p6)
{
	return ((ssize_t)mmap_common(p1, p2, p3, p4, p5, (off64_t)p6));
}

long
lx_mmap2(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4,
    uintptr_t p5, uintptr_t p6)
{
	if (pagesize == 0)
		pagesize = sysconf(_SC_PAGESIZE);

	return ((ssize_t)mmap_common(p1, p2, p3, p4, p5,
	    (off64_t)p6 * pagesize));
}


/*
 * The locking family of system calls, as well as msync(), are identical.  On
 * Solaris, they are layered on top of the memcntl syscall, so they cannot be
 * pass-thru.
 */
long
lx_mlock(uintptr_t addr, uintptr_t len)
{
	uintptr_t addr1 = addr & PAGEMASK;
	uintptr_t len1 = len + (addr & PAGEOFFSET);

	return (mlock((void *)addr1, (size_t)len1) ? -errno : 0);
}

long
lx_mlockall(uintptr_t flags)
{
	return (mlockall(flags) ? -errno : 0);
}

long
lx_munlock(uintptr_t addr, uintptr_t len)
{
	uintptr_t addr1 = addr & PAGEMASK;
	uintptr_t len1 = len + (addr & PAGEOFFSET);

	return (munlock((void *)addr1, (size_t)len1) ? -errno : 0);
}

long
lx_munlockall(void)
{
	return (munlockall() ? -errno : 0);
}

long
lx_msync(uintptr_t addr, uintptr_t len, uintptr_t flags)
{
	return (msync((void *)addr, (size_t)len, flags) ? -errno : 0);
}

/*
 * Illumos and Linux overlap on the basic flags, and are disjoint on the rest.
 * Linux also allows the length to be zero, while Illumos does not.
 */
long
lx_madvise(uintptr_t start, uintptr_t len, uintptr_t advice)
{
	int ret;

	if (len == 0)
		return (0);

	/* approximately similar */
	if (advice == LX_MADV_REMOVE)
		advice = MADV_FREE;

	switch (advice) {
	case MADV_NORMAL:
	case MADV_RANDOM:
	case MADV_SEQUENTIAL:
	case MADV_WILLNEED:
	case MADV_FREE:
	case MADV_DONTNEED:
		if (advice == MADV_DONTNEED) {
			/*
			 * On Linux, MADV_DONTNEED implies an immediate purge
			 * of the specified region.  This is spuriously
			 * different from (nearly) every other Unix, having
			 * apparently been done to mimic the semantics on
			 * Digital Unix (!).  This is bad enough (MADV_FREE
			 * both has better semantics and results in better
			 * performance), but it gets worse:  Linux applications
			 * (and notably, jemalloc) have managed to depend on
			 * the busted semantics of MADV_DONTNEED on Linux.  We
			 * implement these semantics via MADV_PURGE -- and
			 * we translate our advice accordingly.
			 */
			advice = MADV_PURGE;
		}

		ret = madvise((void *)start, len, advice);
		if (ret == -1) {
			if (errno == EBUSY) {
				if (advice != MADV_PURGE)
					return (-EINVAL);

				/*
				 * If we got an EBUSY from a MADV_PURGE, we
				 * will now try again with a MADV_DONTNEED:
				 * there are conditions (namely, with locked
				 * mappings that haven't yet been faulted in)
				 * where MADV_PURGE will fail but MADV_DONTNEED
				 * will succeed.  If this succeeds, we'll call
				 * the operation successful; if not, we'll kick
				 * back EINVAL.
				 */
				advice = MADV_DONTNEED;

				if (madvise((void *)start, len, advice) == 0)
					return (0);

				return (-EINVAL);
			}

			return (-errno);
		} else {
			return (0);
		}

	/* harmless to pretend these work */
	case LX_MADV_DONTFORK:
	case LX_MADV_DOFORK:
	case LX_MADV_HUGEPAGE:
	case LX_MADV_NOHUGEPAGE:
	case LX_MADV_DONTDUMP:
	case LX_MADV_DODUMP:
		return (0);

	/* we'll return an error for the rest of the Linux flags */
	default:
		return (-EINVAL);
	}
}

/*
 * mprotect() is identical except that we ignore the Linux flags PROT_GROWSDOWN
 * and PROT_GROWSUP, which have no equivalent on Solaris.
 */
#define	LX_PROT_GROWSDOWN	0x01000000
#define	LX_PROT_GROWSUP		0x02000000

long
lx_mprotect(uintptr_t start, uintptr_t len, uintptr_t prot)
{
	prot &= ~(LX_PROT_GROWSUP | LX_PROT_GROWSDOWN);

	return (mprotect((void *)start, len, prot) ? -errno : 0);
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
 * these mappings to save both the reads from /proc and the libmapmalloc
 * alloc/free.  We implement the anonymous metadata cache with
 * lx_remap_anoncache, an LRU cache of prmap_t's that correspond to anonymous
 * segments that have been resized.
 */
#define	LX_REMAP_ANONCACHE_NENTRIES	4

static prmap_t	lx_remap_anoncache[LX_REMAP_ANONCACHE_NENTRIES];
static int	lx_remap_anoncache_nentries = LX_REMAP_ANONCACHE_NENTRIES;
static offset_t	lx_remap_anoncache_generation;
static mutex_t	lx_remap_anoncache_lock = DEFAULTMUTEX;

static void
lx_remap_anoncache_invalidate(uintptr_t addr, size_t size)
{
	int i;

	if (lx_remap_anoncache_generation == 0)
		return;

	mutex_lock(&lx_remap_anoncache_lock);

	for (i = 0; i < LX_REMAP_ANONCACHE_NENTRIES; i++) {
		prmap_t *map = &lx_remap_anoncache[i];

		/*
		 * If the ranges overlap at all, we zap it by clearing the
		 * pr_vaddr.
		 */
		if (addr < map->pr_vaddr + map->pr_size &&
		    map->pr_vaddr < addr + size) {
			map->pr_vaddr = 0;
		}
	}

	mutex_unlock(&lx_remap_anoncache_lock);
}

static void
lx_remap_anoncache_evict(prmap_t *map)
{
	if (map >= &lx_remap_anoncache[0] &&
	    map < &lx_remap_anoncache[LX_REMAP_ANONCACHE_NENTRIES]) {
		/*
		 * We're already in the cache; we just need to zap our pr_vaddr
		 * to indicate that this has been evicted.
		 */
		map->pr_vaddr = 0;
	} else {
		/*
		 * We need to invalidate this by address and size.
		 */
		lx_remap_anoncache_invalidate(map->pr_vaddr, map->pr_size);
	}
}

static void
lx_remap_anoncache_load(prmap_t *map, size_t size)
{
	offset_t oldest = 0;
	prmap_t *evict = NULL;
	int i;

	if (map >= &lx_remap_anoncache[0] &&
	    map < &lx_remap_anoncache[LX_REMAP_ANONCACHE_NENTRIES]) {
		/*
		 * We're already in the cache -- we just need to update
		 * our LRU field (pr_offset) to reflect the hit.
		 */
		map->pr_offset = lx_remap_anoncache_generation++;
		map->pr_size = size;
		return;
	}

	mutex_lock(&lx_remap_anoncache_lock);

	for (i = 0; i < lx_remap_anoncache_nentries; i++) {
		if (lx_remap_anoncache[i].pr_vaddr == 0) {
			evict = &lx_remap_anoncache[i];
			break;
		}

		if (oldest == 0 || lx_remap_anoncache[i].pr_offset < oldest) {
			oldest = lx_remap_anoncache[i].pr_offset;
			evict = &lx_remap_anoncache[i];
		}
	}

	if (evict != NULL) {
		*evict = *map;
		evict->pr_offset = lx_remap_anoncache_generation++;
		evict->pr_size = size;
	}

	mutex_unlock(&lx_remap_anoncache_lock);
}

/*
 * As part of lx_remap() (see below) and to accommodate heavy realloc() use
 * cases (see the discussion of the lx_remap_anoncache, above), we allow
 * anonymous segments to be "remapped" in that we are willing to truncate them
 * or append to them (as much as that's allowed by virtual address space
 * usage).  If we fall out of these cases, we take the more expensive option
 * of actually copying the data to a new segment -- but we locate the address
 * in a portion of the address space that should give us plenty of VA space to
 * expand.
 */
static long
lx_remap_anon(prmap_t *map, prmap_t *maps, int nmap,
    uintptr_t new_size, uintptr_t flags, uintptr_t new_address)
{
	int mflags = MAP_ANON;
	int prot = 0, i;
	void *addr, *hint = NULL;

	/*
	 * If our new size is less than our old size and we're either not
	 * being ordered to move it or the address we're being ordered to
	 * move it to is our current address, we can just act as Procrustes
	 * and chop off anything larger than the new size.
	 */
	if (new_size < map->pr_size && (!(flags & LX_MREMAP_FIXED) ||
	    new_address == map->pr_vaddr)) {
		if (munmap((void *)(map->pr_vaddr + new_size),
		    map->pr_size - new_size) != 0) {
			return (-EINVAL);
		}

		lx_remap_anoncache_load(map, new_size);

		return (map->pr_vaddr);
	}

	if (map->pr_mflags & (MA_SHM | MA_ISM))
		return (-EINVAL);

	if (map->pr_mflags & MA_WRITE)
		prot |= PROT_WRITE;

	if (map->pr_mflags & MA_READ)
		prot |= PROT_READ;

	if (map->pr_mflags & MA_EXEC)
		prot |= PROT_EXEC;

	mflags |= (map->pr_mflags & MA_SHARED) ? MAP_SHARED : MAP_PRIVATE;

	if (map->pr_mflags & MA_NORESERVE)
		mflags |= MAP_NORESERVE;

	/*
	 * If we're not being told where to move it, or the address matches
	 * where we already are, let's try to expand our mapping in place
	 * by adding a fixed mapping after it.
	 */
	if (!(flags & LX_MREMAP_FIXED) || new_address == map->pr_vaddr) {
		addr = mmap((void *)(map->pr_vaddr + map->pr_size),
		    new_size - map->pr_size, prot, mflags, -1, 0);

		if (addr == (void *)-1)
			return (-EINVAL);

		if (addr == (void *)(map->pr_vaddr + map->pr_size)) {
			lx_remap_anoncache_load(map, new_size);
			return (map->pr_vaddr);
		}

		/*
		 * Our advisory address was not followed -- which, as a
		 * practical matter, means that the range conflicted with an
		 * extant mapping.  Unmap wherever we landed, and drop into
		 * the relocation case.
		 */
		(void) munmap(addr, new_size - map->pr_size);
	}

	lx_remap_anoncache_evict(map);

	/*
	 * If we're here, we actually need to move this mapping -- so if we
	 * can't move it, we're done.
	 */
	if (!(flags & LX_MREMAP_MAYMOVE))
		return (-ENOMEM);

	/*
	 * If this is a shared private mapping, we can't remap it.
	 */
	if (map->pr_mflags & MA_SHARED)
		return (-EINVAL);

	if (new_address != NULL && (flags & LX_MREMAP_FIXED)) {
		mflags |= MAP_FIXED;
		hint = (void *)new_address;
	} else {
		/*
		 * We're going to start at the bottom of the address space;
		 * once we hit an address above 2G, we'll treat that as the
		 * bottom of the top of the address space, and set our address
		 * hint below that.  To give ourselves plenty of room for
		 * further mremap() expansion, we'll multiply our new size by
		 * 16 and leave that much room between our lowest high address
		 * and our hint.
		 */
		for (i = 0; i < nmap; i++) {
			if (maps[i].pr_vaddr < (uintptr_t)(1 << 31UL))
				continue;

			hint = (void *)(maps[i].pr_vaddr - (new_size << 4UL));
			break;
		}
	}

	if ((addr = mmap(hint, new_size, prot, mflags, -1, 0)) == (void *)-1)
		return (-errno);

	bcopy((void *)map->pr_vaddr, addr, map->pr_size);
	(void) munmap((void *)map->pr_vaddr, map->pr_size);

	return ((long)addr);
}

/*
 * We don't have a native mremap() (and nor do we particularly want one), so
 * we emulate it strictly in user-land.  The idea is simple: we just want to
 * mmap() the underlying object with the new size and rip down the old mapping.
 * However, this is problematic because we don't actually have the file
 * descriptor that corresponds to the resized mapping (and indeed, the mapped
 * file may not exist in any file system name space).  So to get a file
 * descriptor, we find the (or rather, a) path to the mapped object via its
 * entry in /proc/self/path and attempt to open it.  Assuming that this
 * succeeds, we then mmap() it and rip down the original mapping.  There are
 * clearly many reasons why this might fail; absent a more apt errno (e.g.,
 * ENOMEM in some cases), we return EINVAL to denote these cases.
 */
long
lx_remap(uintptr_t old_address, uintptr_t old_size,
    uintptr_t new_size, uintptr_t flags, uintptr_t new_address)
{
	int prot = 0, oflags, mflags = 0, len, fd = -1, i, nmap;
	prmap_t *map = NULL, *maps;
	long rval;
	char path[256], buf[MAXPATHLEN + 1];
	struct stat st;
	ssize_t n;
	static uintptr_t pagesize = 0;

	if (pagesize == 0)
		pagesize = sysconf(_SC_PAGESIZE);

	if ((flags & (LX_MREMAP_MAYMOVE | LX_MREMAP_FIXED)) == LX_MREMAP_FIXED)
		return (-EINVAL);

	if (old_address & (pagesize - 1))
		return (-EINVAL);

	if (new_size == 0)
		return (-EINVAL);

	if ((flags & LX_MREMAP_FIXED) && (new_address & (pagesize - 1)))
		return (-EINVAL);

	if (new_size == old_size && !(flags & LX_MREMAP_FIXED))
		return (old_address);

	/*
	 * First consult the anoncache; if we find the segment there, we'll
	 * drop straight into lx_remap_anon() and save ourself the pain of
	 * the /proc reads.
	 */
	mutex_lock(&lx_remap_anoncache_lock);

	for (i = 0; i < lx_remap_anoncache_nentries; i++) {
		map = &lx_remap_anoncache[i];

		if (map->pr_vaddr != old_address)
			continue;

		if (map->pr_size != old_size)
			continue;

		if (lx_remap_anon(map, NULL,
		    0, new_size, 0, new_address) == old_address) {
			mutex_unlock(&lx_remap_anoncache_lock);
			return (old_address);
		}

		break;
	}

	mutex_unlock(&lx_remap_anoncache_lock);

	/*
	 * We need to search the mappings to find our specified mapping.  Note
	 * that to perform this search, we use /proc/self/rmap instead of
	 * /proc/self/map.  This is to accommodate the case where an mmap()'d
	 * and then ftruncate()'d file is being mremap()'d:  rmap will report
	 * the size of the mapping (which we need to validate old_size) where
	 * map will report the smaller of the size of the mapping and the
	 * size of the object.  (The "r" in "rmap" denotes "reserved".)
	 */
	if ((fd = open("/native/proc/self/rmap", O_RDONLY)) == -1 ||
	    fstat(fd, &st) != 0) {
		if (fd >= 0) {
			(void) close(fd);
		}
		return (-EINVAL);
	}

	/*
	 * Determine the number of mappings we need to read and allocate
	 * a buffer:
	 */
	nmap = st.st_size / sizeof (prmap_t);
	if ((maps = malloc((nmap + 1) * sizeof (prmap_t))) == NULL) {
		(void) close(fd);
		return (-EINVAL);
	}

	/*
	 * Read mappings from the kernel and determine how many complete
	 * mappings were read:
	 */
	if ((n = read(fd, maps, (nmap + 1) * sizeof (prmap_t))) < 0) {
		lx_debug("\rread of /proc/self/map failed: %s",
		    strerror(errno));
		(void) close(fd);
		rval = -EINVAL;
		goto out;
	}

	nmap = n / sizeof (prmap_t);
	lx_debug("\tfound %d mappings", nmap);

	/*
	 * Check if any mappings match our arguments:
	 */
	for (i = 0; i < nmap; i++) {
		if (maps[i].pr_vaddr == old_address &&
		    maps[i].pr_size == old_size) {
			map = &maps[i];
			break;
		}

		if (maps[i].pr_vaddr <= old_address &&
		    old_address + old_size < maps[i].pr_vaddr +
		    maps[i].pr_size) {
			/*
			 * We have a mismatch, but our specified range is
			 * a subset of the actual segment; this is EINVAL.
			 */
			rval = -EINVAL;
			goto out;
		}
	}

	(void) close(fd);

	if (i == nmap) {
		lx_debug("\tno matching mapping found");
		rval = -EFAULT;
		goto out;
	}

	if (map->pr_mflags & (MA_ISM | MA_SHM)) {
		/*
		 * If this is either ISM or System V shared memory, we're not
		 * going to remap it.
		 */
		rval = -EINVAL;
		goto out;
	}

	oflags = (map->pr_mflags & MA_WRITE) ? O_RDWR : O_RDONLY;

	if (map->pr_mflags & MA_ANON) {
		/*
		 * This is an anonymous mapping -- which is the one case in
		 * which we perform something that approaches a true remap.
		 */
		rval = lx_remap_anon(map, maps, nmap,
		    new_size, flags, new_address);
		goto out;
	}

	if (!(flags & LX_MREMAP_MAYMOVE)) {
		/*
		 * If we're not allowed to move this mapping, we're going to
		 * act as if we can't expand it.
		 */
		rval = -ENOMEM;
		goto out;
	}

	if (!(map->pr_mflags & MA_SHARED)) {
		/*
		 * If this is a private mapping, we're not going to remap it.
		 */
		rval = -EINVAL;
		goto out;
	}

	(void) snprintf(path, sizeof (path),
	    "/native/proc/self/path/%s", map->pr_mapname);

	if ((len = readlink(path, buf, sizeof (buf))) == -1 ||
	    len == sizeof (buf)) {
		/*
		 * If we failed to read the link, the path might not exist.
		 */
		rval = -EINVAL;
		goto out;
	}

	buf[len] = '\0';

	if ((fd = open(buf, oflags)) == -1) {
		/*
		 * If we failed to open the object, it may be because it's
		 * not named (i.e., it's anonymous) or because we somehow
		 * don't have permissions.  Either way, we're going to kick
		 * it back with EINVAL.
		 */
		rval = -EINVAL;
		goto out;
	}

	if (map->pr_mflags & MA_WRITE)
		prot |= PROT_WRITE;

	if (map->pr_mflags & MA_READ)
		prot |= PROT_READ;

	if (map->pr_mflags & MA_EXEC)
		prot |= PROT_EXEC;

	mflags = MAP_SHARED;

	if (new_address != NULL && (flags & LX_MREMAP_FIXED)) {
		mflags |= MAP_FIXED;
	} else {
		new_address = NULL;
	}

	rval = (long)mmap((void *)new_address, new_size,
	    prot, mflags, fd, map->pr_offset);
	(void) close(fd);

	if ((void *)rval == MAP_FAILED) {
		rval = -ENOMEM;
		goto out;
	}

	/*
	 * Our mapping succeeded; we're now going to rip down the old mapping.
	 */
	(void) munmap((void *)old_address, old_size);
out:
	free(maps);
	return (rval);
}
