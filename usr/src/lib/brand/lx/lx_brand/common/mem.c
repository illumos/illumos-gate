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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <procfs.h>
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

#define	LX_MADV_REMOVE		9
#define	LX_MADV_DONTFORK	10
#define	LX_MADV_DOFORK		11
#define	LX_MADV_MERGEABLE	12
#define	LX_MADV_UNMERGEABLE	13
#define	LX_MADV_HUGEPAGE	14
#define	LX_MADV_NOHUGEPAGE	15
#define	LX_MADV_DONTDUMP	16
#define	LX_MADV_DODUMP		17

static int
ltos_mmap_flags(int flags)
{
	int new_flags;

	new_flags = flags & (MAP_TYPE | MAP_FIXED);
	if (flags & LX_MAP_ANONYMOUS)
		new_flags |= MAP_ANONYMOUS;
	if (flags & LX_MAP_NORESERVE)
		new_flags |= MAP_NORESERVE;

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

	if (lx_debug_enabled != 0) {
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
	 * This is totally insane. The NOTES section in the linux mmap(2) man
	 * page claims that on some architectures, read protection may
	 * automatically include exec protection. It has been observed on a
	 * native linux system that the /proc/<pid>/maps file does indeed
	 * show that segments mmap'd from userland (such as libraries mapped in
	 * by the dynamic linker) all have exec the permission set, even for
	 * data segments.
	 */
	if (prot & PROT_READ)
		prot |= PROT_EXEC;

	ret = mmap64(addr, len, prot, ltos_mmap_flags(flags), fd, off);

	if (ret == MAP_FAILED)
		return ((void *)(long)(errno == EOVERFLOW ? -ENOMEM : -errno));

	if (flags & LX_MAP_LOCKED)
		(void) mlock(ret, len);

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
	case MADV_DONTNEED:
	case MADV_FREE:
		ret = madvise((void *)start, len, advice);
		if (ret == -1) {
			if (errno == EBUSY)
				return (-EINVAL);
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

long
lx_remap(uintptr_t old_address, uintptr_t old_size,
    uintptr_t new_size, uintptr_t flags, uintptr_t new_address)
{
	int prot = 0, oflags, mflags = 0, len, fd;
	prmap_t map;
	uintptr_t rval;
	char path[256], buf[MAXPATHLEN + 1];

	/*
	 * The kernel doesn't actually support mremap(), so to emulate it,
	 * we're going to mmap() the underlying object with the new size.
	 * We don't actually have a file descriptor (and indeed, the mapped
	 * file may not exist in any file system name space), so we'll
	 * find the path via the object's entry in /proc/self/path.  There are
	 * many reasons why this might fail; generally, we'll return EINVAL,
	 * but in some cases we'll return ENOMEM.
	 */
	if ((fd = open("/native/proc/self/map", O_RDONLY)) == -1)
		return (-EINVAL);

	do {
		if (read(fd, &map, sizeof (map)) < sizeof (map)) {
			/*
			 * This is either a short read or we've hit the end
			 * of the mappings.  Either way, our passed mapping is
			 * invalid; return EINVAL.
			 */
			(void) close(fd);
			return (-EINVAL);
		}
	} while (map.pr_vaddr != old_address || map.pr_size != old_size);

	(void) close(fd);

	if (!(map.pr_mflags & MA_SHARED)) {
		/*
		 * If this is a private mapping, we're not going to remap it.
		 */
		return (-EINVAL);
	}

	if (map.pr_mflags & (MA_ISM | MA_SHM)) {
		/*
		 * If this is either ISM or System V shared memory, we're not
		 * going to remap it.
		 */
		return (-EINVAL);
	}

	if (!(flags & LX_MREMAP_MAYMOVE)) {
		/*
		 * If we're not allowed to move this mapping, we're going to
		 * act as if we can't expand it.
		 */
		return (-ENOMEM);
	}

	oflags = (map.pr_mflags & MA_WRITE) ? O_RDWR : O_RDONLY;

	if (map.pr_mapname[0] == '\0') {
		/*
		 * This is likely an anonymous mapping.
		 */
		return (-EINVAL);
	}

	(void) snprintf(path, sizeof (path),
	    "/native/proc/self/path/%s", map.pr_mapname);

	if ((len = readlink(path, buf, sizeof (buf))) == -1 ||
	    len == sizeof (buf)) {
		/*
		 * If we failed to read the link, the path might not exist.
		 */
		return (-EINVAL);
	}
	buf[len] = '\0';

	if ((fd = open(buf, oflags)) == -1) {
		/*
		 * If we failed to open the object, it may be because it's
		 * not named (i.e., it's anonymous) or because we somehow
		 * don't have permissions.  Either way, we're going to kick
		 * it back with EINVAL.
		 */
		return (-EINVAL);
	}

	if (map.pr_mflags & MA_WRITE)
		prot |= PROT_WRITE;

	if (map.pr_mflags & MA_READ)
		prot |= PROT_READ;

	if (map.pr_mflags & MA_EXEC)
		prot |= PROT_EXEC;

	mflags = MAP_SHARED;

	if (new_address != NULL && (flags & LX_MREMAP_FIXED)) {
		mflags |= MAP_FIXED;
	} else {
		new_address = NULL;
	}

	rval = (uintptr_t)mmap((void *)new_address, new_size,
	    prot, mflags, fd, map.pr_offset);
	(void) close(fd);

	if ((void *)rval == MAP_FAILED)
		return ((long)-ENOMEM);

	/*
	 * Our mapping succeeded; we're now going to rip down the old mapping.
	 */
	(void) munmap((void *)old_address, old_size);

	return (rval);
}
