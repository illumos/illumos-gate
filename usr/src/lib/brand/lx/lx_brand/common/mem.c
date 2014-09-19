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
