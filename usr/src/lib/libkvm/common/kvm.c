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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2013, Joyent, Inc.  All rights reserved.
 */

#include <kvm.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <strings.h>
#include <errno.h>
#include <sys/mem.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/dumphdr.h>
#include <sys/sysmacros.h>

struct _kvmd {
	struct dumphdr	kvm_dump;
	char		*kvm_debug;
	int		kvm_openflag;
	int		kvm_corefd;
	int		kvm_kmemfd;
	int		kvm_memfd;
	size_t		kvm_coremapsize;
	char		*kvm_core;
	dump_map_t	*kvm_map;
	pfn_t		*kvm_pfn;
	struct as	*kvm_kas;
	proc_t		*kvm_practive;
	pid_t		kvm_pid;
	char		kvm_namelist[MAXNAMELEN + 1];
	boolean_t	kvm_namelist_core;
	proc_t		kvm_proc;
};

#define	PREAD	(ssize_t (*)(int, void *, size_t, offset_t))pread64
#define	PWRITE	(ssize_t (*)(int, void *, size_t, offset_t))pwrite64

static int kvm_nlist_core(kvm_t *kd, struct nlist nl[], const char *err);

static kvm_t *
fail(kvm_t *kd, const char *err, const char *message, ...)
{
	va_list args;

	va_start(args, message);
	if (err || (kd && kd->kvm_debug)) {
		(void) fprintf(stderr, "%s: ", err ? err : "KVM_DEBUG");
		(void) vfprintf(stderr, message, args);
		(void) fprintf(stderr, "\n");
	}
	va_end(args);
	if (kd != NULL)
		(void) kvm_close(kd);
	return (NULL);
}

/*ARGSUSED*/
kvm_t *
kvm_open(const char *namelist, const char *corefile, const char *swapfile,
	int flag, const char *err)
{
	kvm_t *kd;
	struct stat64 memstat, kmemstat, allkmemstat, corestat;
	struct nlist nl[3] = { { "kas" }, { "practive" }, { "" } };

	if ((kd = calloc(1, sizeof (kvm_t))) == NULL)
		return (fail(NULL, err, "cannot allocate space for kvm_t"));

	kd->kvm_corefd = kd->kvm_kmemfd = kd->kvm_memfd = -1;
	kd->kvm_debug = getenv("KVM_DEBUG");

	if ((kd->kvm_openflag = flag) != O_RDONLY && flag != O_RDWR)
		return (fail(kd, err, "illegal flag 0x%x to kvm_open()", flag));

	if (corefile == NULL)
		corefile = "/dev/kmem";

	if (stat64(corefile, &corestat) == -1)
		return (fail(kd, err, "cannot stat %s", corefile));

	if (S_ISCHR(corestat.st_mode)) {
		if (stat64("/dev/mem", &memstat) == -1)
			return (fail(kd, err, "cannot stat /dev/mem"));

		if (stat64("/dev/kmem", &kmemstat) == -1)
			return (fail(kd, err, "cannot stat /dev/kmem"));

		if (stat64("/dev/allkmem", &allkmemstat) == -1)
			return (fail(kd, err, "cannot stat /dev/allkmem"));
		if (corestat.st_rdev == memstat.st_rdev ||
		    corestat.st_rdev == kmemstat.st_rdev ||
		    corestat.st_rdev == allkmemstat.st_rdev) {
			char *kmem = (corestat.st_rdev == allkmemstat.st_rdev ?
			    "/dev/allkmem" : "/dev/kmem");

			if ((kd->kvm_kmemfd = open64(kmem, flag)) == -1)
				return (fail(kd, err, "cannot open %s", kmem));
			if ((kd->kvm_memfd = open64("/dev/mem", flag)) == -1)
				return (fail(kd, err, "cannot open /dev/mem"));
		}
	} else {
		if ((kd->kvm_corefd = open64(corefile, flag)) == -1)
			return (fail(kd, err, "cannot open %s", corefile));
		if (pread64(kd->kvm_corefd, &kd->kvm_dump,
		    sizeof (kd->kvm_dump), 0) != sizeof (kd->kvm_dump))
			return (fail(kd, err, "cannot read dump header"));
		if (kd->kvm_dump.dump_magic != DUMP_MAGIC)
			return (fail(kd, err, "%s is not a kernel core file "
			    "(bad magic number %x)", corefile,
			    kd->kvm_dump.dump_magic));
		if (kd->kvm_dump.dump_version != DUMP_VERSION)
			return (fail(kd, err,
			    "libkvm version (%u) != corefile version (%u)",
			    DUMP_VERSION, kd->kvm_dump.dump_version));
		if (kd->kvm_dump.dump_wordsize != DUMP_WORDSIZE)
			return (fail(kd, err, "%s is a %d-bit core file - "
			    "cannot examine with %d-bit libkvm", corefile,
			    kd->kvm_dump.dump_wordsize, DUMP_WORDSIZE));
		/*
		 * We try to mmap(2) the entire corefile for performance
		 * (so we can use bcopy(3C) rather than pread(2)).  Failing
		 * that, we insist on at least mmap(2)ing the dump map.
		 */
		kd->kvm_coremapsize = (size_t)corestat.st_size;
		if (corestat.st_size > LONG_MAX ||
		    (kd->kvm_core = mmap64(0, kd->kvm_coremapsize,
		    PROT_READ, MAP_SHARED, kd->kvm_corefd, 0)) == MAP_FAILED) {
			kd->kvm_coremapsize = kd->kvm_dump.dump_data;
			if ((kd->kvm_core = mmap64(0, kd->kvm_coremapsize,
			    PROT_READ, MAP_SHARED, kd->kvm_corefd, 0)) ==
			    MAP_FAILED)
				return (fail(kd, err, "cannot mmap corefile"));
		}
		kd->kvm_map = (void *)(kd->kvm_core + kd->kvm_dump.dump_map);
		kd->kvm_pfn = (void *)(kd->kvm_core + kd->kvm_dump.dump_pfn);
	}

	if (namelist == NULL)
		namelist = "/dev/ksyms";

	(void) strncpy(kd->kvm_namelist, namelist, MAXNAMELEN);

	if (kvm_nlist(kd, nl) == -1) {
		if (kd->kvm_corefd == -1) {
			return (fail(kd, err, "%s is not a %d-bit "
			    "kernel namelist", namelist, DUMP_WORDSIZE));
		}

		if (kvm_nlist_core(kd, nl, err) == -1)
			return (NULL);		/* fail() already called */
	}

	kd->kvm_kas = (struct as *)nl[0].n_value;
	kd->kvm_practive = (proc_t *)nl[1].n_value;

	(void) kvm_setproc(kd);
	return (kd);
}

int
kvm_close(kvm_t *kd)
{
	if (kd->kvm_core != NULL && kd->kvm_core != MAP_FAILED)
		(void) munmap(kd->kvm_core, kd->kvm_coremapsize);
	if (kd->kvm_corefd != -1)
		(void) close(kd->kvm_corefd);
	if (kd->kvm_kmemfd != -1)
		(void) close(kd->kvm_kmemfd);
	if (kd->kvm_memfd != -1)
		(void) close(kd->kvm_memfd);
	if (kd->kvm_namelist_core)
		(void) unlink(kd->kvm_namelist);
	free(kd);
	return (0);
}

const char *
kvm_namelist(kvm_t *kd)
{
	return (kd->kvm_namelist);
}

int
kvm_nlist(kvm_t *kd, struct nlist nl[])
{
	return (nlist(kd->kvm_namelist, nl));
}

/*
 * If we don't have a name list, try to dig it out of the kernel crash dump.
 * (The symbols have been present in the dump, uncompressed, for nearly a
 * decade as of this writing -- and it is frankly surprising that the archaic
 * notion of a disjoint symbol table managed to survive that change.)
 */
static int
kvm_nlist_core(kvm_t *kd, struct nlist nl[], const char *err)
{
	dumphdr_t *dump = &kd->kvm_dump;
	char *msg = "couldn't extract symbols from dump";
	char *template = "/tmp/.libkvm.kvm_nlist_core.pid%d.XXXXXX";
	int fd, rval;

	if (dump->dump_ksyms_size != dump->dump_ksyms_csize) {
		(void) fail(kd, err, "%s: kernel symbols are compressed", msg);
		return (-1);
	}

	if (dump->dump_ksyms + dump->dump_ksyms_size > kd->kvm_coremapsize) {
		(void) fail(kd, err, "%s: kernel symbols not mapped", msg);
		return (-1);
	}

	/*
	 * Beause this temporary file may be left as a turd if the caller
	 * does not properly call kvm_close(), we make sure that it clearly
	 * indicates its origins.
	 */
	(void) snprintf(kd->kvm_namelist, MAXNAMELEN, template, getpid());

	if ((fd = mkstemp(kd->kvm_namelist)) == -1) {
		(void) fail(kd, err, "%s: couldn't create temporary "
		    "symbols file: %s", msg, strerror(errno));
		return (-1);
	}

	kd->kvm_namelist_core = B_TRUE;

	do {
		rval = write(fd, (caddr_t)((uintptr_t)kd->kvm_core +
		    (uintptr_t)dump->dump_ksyms), dump->dump_ksyms_size);
	} while (rval < dump->dump_ksyms_size && errno == EINTR);

	if (rval < dump->dump_ksyms_size) {
		(void) fail(kd, err, "%s: couldn't write to temporary "
		    "symbols file: %s", msg, strerror(errno));
		(void) close(fd);
		return (-1);
	}

	(void) close(fd);

	if (kvm_nlist(kd, nl) == -1) {
		(void) fail(kd, err, "%s: symbols not valid", msg);
		return (-1);
	}

	return (0);
}

static offset_t
kvm_lookup(kvm_t *kd, struct as *as, uint64_t addr)
{
	uintptr_t pageoff = addr & (kd->kvm_dump.dump_pagesize - 1);
	uint64_t page = addr - pageoff;
	offset_t off = 0;

	if (kd->kvm_debug)
		fprintf(stderr, "kvm_lookup(%p, %llx):", (void *)as, addr);

	if (as == NULL) {		/* physical addressing mode */
		long first = 0;
		long last = kd->kvm_dump.dump_npages - 1;
		pfn_t target = (pfn_t)(page >> kd->kvm_dump.dump_pageshift);
		while (last >= first) {
			long middle = (first + last) / 2;
			pfn_t pfn = kd->kvm_pfn[middle];
			if (kd->kvm_debug)
				fprintf(stderr, " %ld ->", middle);
			if (pfn == target) {
				off = kd->kvm_dump.dump_data + pageoff +
				    ((uint64_t)middle <<
				    kd->kvm_dump.dump_pageshift);
				break;
			}
			if (pfn < target)
				first = middle + 1;
			else
				last = middle - 1;
		}
	} else {
		long hash = DUMP_HASH(&kd->kvm_dump, as, page);
		off = kd->kvm_map[hash].dm_first;
		while (off != 0) {
			dump_map_t *dmp = (void *)(kd->kvm_core + off);
			if (kd->kvm_debug)
				fprintf(stderr, " %llx ->", off);
			if (dmp < kd->kvm_map ||
			    dmp > kd->kvm_map + kd->kvm_dump.dump_hashmask ||
			    (off & (sizeof (offset_t) - 1)) != 0 ||
			    DUMP_HASH(&kd->kvm_dump, dmp->dm_as, dmp->dm_va) !=
			    hash) {
				if (kd->kvm_debug)
					fprintf(stderr, " dump map corrupt\n");
				return (0);
			}
			if (dmp->dm_va == page && dmp->dm_as == as) {
				off = dmp->dm_data + pageoff;
				break;
			}
			off = dmp->dm_next;
		}
	}
	if (kd->kvm_debug)
		fprintf(stderr, "%s found: %llx\n", off ? "" : " not", off);
	return (off);
}

static ssize_t
kvm_rw(kvm_t *kd, uint64_t addr, void *buf, size_t size,
	struct as *as, ssize_t (*prw)(int, void *, size_t, offset_t))
{
	offset_t off;
	size_t resid = size;

	/*
	 * read/write of zero bytes always succeeds
	 */
	if (size == 0)
		return (0);

	if (kd->kvm_core == NULL) {
		char procbuf[100];
		int procfd;
		ssize_t rval;

		if (as == kd->kvm_kas)
			return (prw(kd->kvm_kmemfd, buf, size, addr));
		if (as == NULL)
			return (prw(kd->kvm_memfd, buf, size, addr));

		(void) sprintf(procbuf, "/proc/%ld/as", kd->kvm_pid);
		if ((procfd = open64(procbuf, kd->kvm_openflag)) == -1)
			return (-1);
		rval = prw(procfd, buf, size, addr);
		(void) close(procfd);
		return (rval);
	}

	while (resid != 0) {
		uintptr_t pageoff = addr & (kd->kvm_dump.dump_pagesize - 1);
		ssize_t len = MIN(resid, kd->kvm_dump.dump_pagesize - pageoff);

		if ((off = kvm_lookup(kd, as, addr)) == 0)
			break;

		if (prw == PREAD && off < kd->kvm_coremapsize)
			bcopy(kd->kvm_core + off, buf, len);
		else if ((len = prw(kd->kvm_corefd, buf, len, off)) <= 0)
			break;
		resid -= len;
		addr += len;
		buf = (char *)buf + len;
	}
	return (resid < size ? size - resid : -1);
}

ssize_t
kvm_read(kvm_t *kd, uintptr_t addr, void *buf, size_t size)
{
	return (kvm_rw(kd, addr, buf, size, kd->kvm_kas, PREAD));
}

ssize_t
kvm_kread(kvm_t *kd, uintptr_t addr, void *buf, size_t size)
{
	return (kvm_rw(kd, addr, buf, size, kd->kvm_kas, PREAD));
}

ssize_t
kvm_uread(kvm_t *kd, uintptr_t addr, void *buf, size_t size)
{
	return (kvm_rw(kd, addr, buf, size, kd->kvm_proc.p_as, PREAD));
}

ssize_t
kvm_aread(kvm_t *kd, uintptr_t addr, void *buf, size_t size, struct as *as)
{
	return (kvm_rw(kd, addr, buf, size, as, PREAD));
}

ssize_t
kvm_pread(kvm_t *kd, uint64_t addr, void *buf, size_t size)
{
	return (kvm_rw(kd, addr, buf, size, NULL, PREAD));
}

ssize_t
kvm_write(kvm_t *kd, uintptr_t addr, const void *buf, size_t size)
{
	return (kvm_rw(kd, addr, (void *)buf, size, kd->kvm_kas, PWRITE));
}

ssize_t
kvm_kwrite(kvm_t *kd, uintptr_t addr, const void *buf, size_t size)
{
	return (kvm_rw(kd, addr, (void *)buf, size, kd->kvm_kas, PWRITE));
}

ssize_t
kvm_uwrite(kvm_t *kd, uintptr_t addr, const void *buf, size_t size)
{
	return (kvm_rw(kd, addr, (void *)buf, size, kd->kvm_proc.p_as, PWRITE));
}

ssize_t
kvm_awrite(kvm_t *kd, uintptr_t addr, const void *buf, size_t size,
    struct as *as)
{
	return (kvm_rw(kd, addr, (void *)buf, size, as, PWRITE));
}

ssize_t
kvm_pwrite(kvm_t *kd, uint64_t addr, const void *buf, size_t size)
{
	return (kvm_rw(kd, addr, (void *)buf, size, NULL, PWRITE));
}

uint64_t
kvm_physaddr(kvm_t *kd, struct as *as, uintptr_t addr)
{
	mem_vtop_t mem_vtop;
	offset_t off;

	if (kd->kvm_core == NULL) {
		mem_vtop.m_as = as;
		mem_vtop.m_va = (void *)addr;
		if (ioctl(kd->kvm_kmemfd, MEM_VTOP, &mem_vtop) == 0)
			return ((uint64_t)mem_vtop.m_pfn * getpagesize() +
			    (addr & (getpagesize() - 1)));
	} else {
		if ((off = kvm_lookup(kd, as, addr)) != 0) {
			long pfn_index =
			    (u_offset_t)(off - kd->kvm_dump.dump_data) >>
			    kd->kvm_dump.dump_pageshift;
			return (((uint64_t)kd->kvm_pfn[pfn_index] <<
			    kd->kvm_dump.dump_pageshift) +
			    (addr & (kd->kvm_dump.dump_pagesize - 1)));
		}
	}
	return (-1ULL);
}

struct proc *
kvm_getproc(kvm_t *kd, pid_t pid)
{
	(void) kvm_setproc(kd);
	while (kvm_nextproc(kd) != NULL)
		if (kd->kvm_pid == pid)
			return (&kd->kvm_proc);
	return (NULL);
}

struct proc *
kvm_nextproc(kvm_t *kd)
{
	if (kd->kvm_proc.p_next == NULL ||
	    kvm_kread(kd, (uintptr_t)kd->kvm_proc.p_next,
	    &kd->kvm_proc, sizeof (proc_t)) != sizeof (proc_t) ||
	    kvm_kread(kd, (uintptr_t)&kd->kvm_proc.p_pidp->pid_id,
	    &kd->kvm_pid, sizeof (pid_t)) != sizeof (pid_t))
		return (NULL);

	return (&kd->kvm_proc);
}

int
kvm_setproc(kvm_t *kd)
{
	(void) kvm_kread(kd, (uintptr_t)kd->kvm_practive,
	    &kd->kvm_proc.p_next, sizeof (proc_t *));
	kd->kvm_pid = -1;
	return (0);
}

/*ARGSUSED*/
struct user *
kvm_getu(kvm_t *kd, struct proc *p)
{
	return (&p->p_user);
}
