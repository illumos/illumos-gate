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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * KVM backend for hypervisor domain dumps.  We don't use libkvm for such
 * dumps, since they do not have a namelist file or the typical dump structures
 * we expect to aid bootstrapping.  Instead, we bootstrap based upon a
 * debug_info structure at a known VA, using the guest's own page tables to
 * resolve to physical addresses, and construct the namelist in a manner
 * similar to ksyms_snapshot().
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <gelf.h>
#include <errno.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/debug_info.h>
#include <sys/xen_mmu.h>
#include <sys/elf.h>
#include <sys/machelf.h>
#include <sys/modctl.h>
#include <sys/kobj.h>
#include <sys/kobj_impl.h>
#include <sys/sysmacros.h>
#include <sys/privmregs.h>
#include <vm/as.h>

#include <mdb/mdb_io.h>
#include <mdb/mdb_kb.h>
#include <mdb/mdb_target_impl.h>

#include <xen/public/xen.h>

#if defined(__i386)
#define	DEF_DEBUG_INFO_VA 0xfb3ff000
#define	PAE_DEBUG_INFO_VA 0xf4bff000
#elif defined(__amd64)
#define	DEF_DEBUG_INFO_VA 0xfffffffffb7ff000
#endif

#define	XKB_SHDR_NULL 0
#define	XKB_SHDR_SYMTAB 1
#define	XKB_SHDR_STRTAB 2
#define	XKB_SHDR_SHSTRTAB 3
#define	XKB_SHDR_NUM 4

#define	XKB_WALK_LOCAL 0x1
#define	XKB_WALK_GLOBAL 0x2
#define	XKB_WALK_STR 0x4
#define	XKB_WALK_ALL (XKB_WALK_LOCAL | XKB_WALK_GLOBAL | XKB_WALK_STR)

#define	PAGE_SIZE 0x1000
#define	PAGE_SHIFT 12
#define	PAGE_OFFSET(a) ((a) & (PAGE_SIZE - 1))
#define	PAGE_MASK(a) ((a) & ~(PAGE_SIZE - 1))
#define	PT_PADDR 0x000ffffffffff000ull
#define	PT_VALID 0x1

/*
 * Once the headers are available easily from within ON, we can use those, but
 * until then these definitions are duplicates.
 */

#define	XC_CORE_MAGIC 0xF00FEBED
#define	XC_CORE_MAGIC_HVM 0xF00FEBEE

#define	VGCF_HVM_GUEST (1<<1)

typedef struct xc_core_header {
	unsigned int xch_magic;
	unsigned int xch_nr_vcpus;
	unsigned int xch_nr_pages;
	unsigned int xch_ctxt_offset;
	unsigned int xch_index_offset;
	unsigned int xch_pages_offset;
} xc_core_header_t;

typedef struct mfn_map {
	mfn_t mm_mfn;
	char *mm_map;
} mfn_map_t;

typedef struct mmu_info {
	size_t mi_max;
	size_t mi_shift[4];
	size_t mi_ptes;
	size_t mi_ptesize;
} mmu_info_t;

typedef struct xkb {
	char *xkb_path;
	int xkb_fd;
	xc_core_header_t xkb_hdr;
	char *xkb_namelist;
	size_t xkb_namesize;
	struct vcpu_guest_context *xkb_ctxts;
	mfn_t xkb_max_mfn;
	mmu_info_t xkb_mmu;
	char *xkb_pages;
	mfn_t *xkb_p2m;
	void *xkb_p2m_buf;
	xen_pfn_t *xkb_m2p;
	debug_info_t xkb_info;
	mfn_map_t xkb_pt_map[4];
	mfn_map_t xkb_map;
} xkb_t;

static const char xkb_shstrtab[] = "\0.symtab\0.strtab\0.shstrtab\0";

typedef struct xkb_namelist {
	Ehdr	kh_elf_hdr;
	Phdr	kh_text_phdr;
	Phdr	kh_data_phdr;
	Shdr	kh_shdr[XKB_SHDR_NUM];
	char	shstrings[sizeof (xkb_shstrtab)];
} xkb_namelist_t;

static int xkb_build_ksyms(xkb_t *);
static offset_t xkb_mfn_to_offset(xkb_t *, mfn_t);
static mfn_t xkb_va_to_mfn(xkb_t *, uintptr_t, mfn_t);
static ssize_t xkb_read(xkb_t *, uintptr_t, void *, size_t);
static int xkb_read_word(xkb_t *, uintptr_t, uintptr_t *);
static char *xkb_map_mfn(xkb_t *, mfn_t, mfn_map_t *);
static int xkb_close(xkb_t *);

int
xkb_identify(const char *file, int *longmode)
{
	xc_core_header_t header;
	size_t sz;
	int fd;

	if ((fd = open64(file, O_RDONLY)) == -1)
		return (-1);

	if (pread64(fd, &header, sizeof (header), 0) != sizeof (header)) {
		(void) close(fd);
		return (0);
	}

	(void) close(fd);

	if (header.xch_magic != XC_CORE_MAGIC)
		return (0);

	*longmode = 0;

	/*
	 * Indeed.
	 */
	sz = header.xch_index_offset - header.xch_ctxt_offset;
#ifdef _LP64
	if (sizeof (struct vcpu_guest_context) * header.xch_nr_vcpus == sz)
		*longmode = 1;
#else
	if (sizeof (struct vcpu_guest_context) * header.xch_nr_vcpus != sz)
		*longmode = 1;
#endif /* _LP64 */

	return (1);
}

static void *
xkb_fail(xkb_t *xkb, const char *msg, ...)
{
	va_list args;

	va_start(args, msg);
	if (xkb != NULL)
		(void) fprintf(stderr, "%s: ", xkb->xkb_path);
	(void) vfprintf(stderr, msg, args);
	(void) fprintf(stderr, "\n");
	va_end(args);
	if (xkb != NULL)
		(void) xkb_close(xkb);
	return (NULL);
}

static int
xkb_build_m2p(xkb_t *xkb)
{
	size_t i;

	for (i = 0; i < xkb->xkb_hdr.xch_nr_pages; i++) {
		if (xkb->xkb_p2m[i] != MFN_INVALID &&
		    xkb->xkb_p2m[i] > xkb->xkb_max_mfn)
			xkb->xkb_max_mfn = xkb->xkb_p2m[i];
	}

	xkb->xkb_m2p = mdb_alloc((xkb->xkb_max_mfn + 1) * sizeof (xen_pfn_t),
	    UM_SLEEP);

	for (i = 0; i <= xkb->xkb_max_mfn; i++)
		xkb->xkb_m2p[i] = PFN_INVALID;

	for (i = 0; i < xkb->xkb_hdr.xch_nr_pages; i++) {
		if (xkb->xkb_p2m[i] != MFN_INVALID)
			xkb->xkb_m2p[xkb->xkb_p2m[i]] = i;
	}

	return (1);
}

/*
 * Just to make things jolly fun, they've not page-aligned the p2m table.
 */
static int
xkb_map_p2m(xkb_t *xkb)
{
	offset_t off;
	size_t size;
	size_t count = xkb->xkb_hdr.xch_nr_pages;
	size_t boff = xkb->xkb_hdr.xch_index_offset;

	size = sizeof (mfn_t) * count + (PAGE_SIZE) * 2;
	size = PAGE_MASK(size);
	off = PAGE_MASK(boff);

	/* LINTED - alignment */
	xkb->xkb_p2m_buf = (mfn_t *)mmap(NULL, size, PROT_READ,
	    MAP_SHARED, xkb->xkb_fd, off);

	if (xkb->xkb_p2m_buf == (xen_pfn_t *)MAP_FAILED) {
		(void) xkb_fail(xkb, "cannot map p2m table");
		return (0);
	}

	/* LINTED - alignment */
	xkb->xkb_p2m = (mfn_t *)((char *)xkb->xkb_p2m_buf +
	    PAGE_OFFSET(boff));

	return (1);
}

/*
 * Return the MFN of the top-level page table for the given as.
 */
static mfn_t
xkb_as_to_mfn(xkb_t *xkb, struct as *as)
{
	uintptr_t asp = (uintptr_t)as;
	uintptr_t hatp;
	uintptr_t htablep;
	uintptr_t pfn;

	if (!xkb_read_word(xkb, asp + offsetof(struct as, a_hat), &hatp))
		return (MFN_INVALID);
	if (!xkb_read_word(xkb, hatp + xkb->xkb_info.di_hat_htable_off,
	    &htablep))
		return (MFN_INVALID);
	if (!xkb_read_word(xkb, htablep + xkb->xkb_info.di_ht_pfn_off,
	    &pfn))
		return (MFN_INVALID);

	if (pfn >= xkb->xkb_hdr.xch_nr_pages)
		return (MFN_INVALID);

	return (xkb->xkb_p2m[pfn]);
}

static ssize_t
xkb_read_helper(xkb_t *xkb, struct as *as, int phys, uint64_t addr,
    void *buf, size_t size)
{
	size_t left = size;
	int windowed = xkb->xkb_pages == NULL;
	mfn_t tlmfn = xen_cr3_to_pfn(xkb->xkb_ctxts[0].ctrlreg[3]);

	if (as != NULL && (tlmfn = xkb_as_to_mfn(xkb, as)) == MFN_INVALID)
		return (-1);

	while (left) {
		uint64_t pos = addr + (size - left);
		char *outpos = (char *)buf + (size - left);
		size_t pageoff = PAGE_OFFSET(pos);
		size_t sz = MIN(left, PAGE_SIZE - pageoff);
		mfn_t mfn;

		if (!phys) {
			mfn = xkb_va_to_mfn(xkb, pos, tlmfn);
			if (mfn == MFN_INVALID)
				return (-1);
		} else {
			xen_pfn_t pfn = pos >> PAGE_SHIFT;
			if (pfn >= xkb->xkb_hdr.xch_nr_pages)
				return (-1);
			mfn = xkb->xkb_p2m[pfn];
			if (mfn == MFN_INVALID)
				return (-1);
		}

		/*
		 * If we're windowed then pread() is much faster.
		 */
		if (windowed) {
			offset_t off = xkb_mfn_to_offset(xkb, mfn);
			int ret;

			if (off == ~1ULL)
				return (-1);

			off += pageoff;

			ret = pread64(xkb->xkb_fd, outpos, sz, off);
			if (ret == -1)
				return (-1);
			if (ret != sz)
				return ((size - left) + ret);

			left -= ret;
		} else {
			if (xkb_map_mfn(xkb, mfn, &xkb->xkb_map) == NULL)
				return (-1);

			bcopy(xkb->xkb_map.mm_map + pageoff, outpos, sz);

			left -= sz;
		}
	}

	return (size);
}

static ssize_t
xkb_pread(xkb_t *xkb, uint64_t addr, void *buf, size_t size)
{
	return (xkb_read_helper(xkb, NULL, 1, addr, buf, size));
}

static ssize_t
xkb_aread(xkb_t *xkb, uintptr_t addr, void *buf, size_t size, struct as *as)
{
	return (xkb_read_helper(xkb, as, 0, addr, buf, size));
}

static ssize_t
xkb_read(xkb_t *xkb, uintptr_t addr, void *buf, size_t size)
{
	return (xkb_aread(xkb, addr, buf, size, NULL));
}

static int
xkb_read_word(xkb_t *xkb, uintptr_t addr, uintptr_t *buf)
{
	if (xkb_read(xkb, addr, buf, sizeof (uintptr_t)) !=
	    sizeof (uintptr_t))
		return (0);
	return (1);
}

static char *
xkb_readstr(xkb_t *xkb, uintptr_t addr)
{
	char *str = mdb_alloc(1024, UM_SLEEP);
	size_t i;

	for (i = 0; i < 1024; i++) {
		if (xkb_read(xkb, addr + i, &str[i], 1) != 1) {
			mdb_free(str, 1024);
			return (NULL);
		}

		if (str[i] == '\0')
			break;
	}

	if (i == 1024) {
		mdb_free(str, 1024);
		return (NULL);
	}

	return (str);
}

static offset_t
xkb_mfn_to_offset(xkb_t *xkb, mfn_t mfn)
{
	xen_pfn_t pfn;

	if (mfn > xkb->xkb_max_mfn)
		return (-1ULL);

	pfn = xkb->xkb_m2p[mfn];

	if (pfn == PFN_INVALID)
		return (-1ULL);

	return (xkb->xkb_hdr.xch_pages_offset + (PAGE_SIZE * pfn));
}

static char *
xkb_map_mfn(xkb_t *xkb, mfn_t mfn, mfn_map_t *mm)
{
	int windowed = xkb->xkb_pages == NULL;
	offset_t off;

	if (mm->mm_mfn == mfn)
		return (mm->mm_map);

	mm->mm_mfn = mfn;

	if (windowed) {
		if (mm->mm_map != (char *)MAP_FAILED) {
			(void) munmap(mm->mm_map, PAGE_SIZE);
			mm->mm_map = (void *)MAP_FAILED;
		}

		if ((off = xkb_mfn_to_offset(xkb, mfn)) == (-1ULL))
			return (NULL);

		mm->mm_map = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED,
		    xkb->xkb_fd, off);

		if (mm->mm_map == (char *)MAP_FAILED)
			return (NULL);
	} else {
		xen_pfn_t pfn;

		mm->mm_map = NULL;

		if (mfn > xkb->xkb_max_mfn)
			return (NULL);

		pfn = xkb->xkb_m2p[mfn];

		if (pfn == PFN_INVALID)
			return (NULL);

		mm->mm_map = xkb->xkb_pages + (PAGE_SIZE * pfn);
	}

	return (mm->mm_map);
}

static mfn_t
xkb_pte_to_mfn(mmu_info_t *mmu, char *ptep)
{
	/* LINTED - alignment */
	uint64_t pte = *((uint64_t *)ptep);

	if (mmu->mi_ptesize == 4) {
		/* LINTED - alignment */
		pte = *((uint32_t *)ptep);
	}

	if (!(pte & PT_VALID))
		return (MFN_INVALID);

	/* XXX: doesn't do large pages */
	pte &= PT_PADDR;

	return (pte >> PAGE_SHIFT);
}

/*
 * Resolve the given VA into an MFN, using the provided mfn as a top-level page
 * table.
 */
static mfn_t
xkb_va_to_mfn(xkb_t *xkb, uintptr_t va, mfn_t mfn)
{
	mmu_info_t *mmu = &xkb->xkb_mmu;
	size_t level;

	for (level = mmu->mi_max; ; --level) {
		size_t entry;
		char *tmp;

		if (xkb_map_mfn(xkb, mfn, &xkb->xkb_pt_map[level]) == NULL)
			return (MFN_INVALID);

		entry = (va >> mmu->mi_shift[level]) & (mmu->mi_ptes - 1);

		tmp = (char *)xkb->xkb_pt_map[level].mm_map +
		    entry * mmu->mi_ptesize;

		if ((mfn = xkb_pte_to_mfn(mmu, tmp)) == MFN_INVALID)
			return (MFN_INVALID);

		if (level == 0)
			break;
	}

	return (mfn);
}

static int
xkb_read_module(xkb_t *xkb, uintptr_t modulep, struct module *module,
    uintptr_t *sym_addr, uintptr_t *sym_count, uintptr_t *str_addr)
{
	if (xkb_read(xkb, modulep, module, sizeof (struct module)) !=
	    sizeof (struct module))
		return (0);

	if (!xkb_read_word(xkb, (uintptr_t)module->symhdr +
	    offsetof(Shdr, sh_addr), sym_addr))
		return (0);

	if (!xkb_read_word(xkb, (uintptr_t)module->strhdr +
	    offsetof(Shdr, sh_addr), str_addr))
		return (0);

	if (!xkb_read_word(xkb, (uintptr_t)module->symhdr +
	    offsetof(Shdr, sh_size), sym_count))
		return (0);
	*sym_count /= sizeof (Sym);

	return (1);
}

static int
xkb_read_modsyms(xkb_t *xkb, char **buf, size_t *sizes, int types,
    uintptr_t sym_addr, uintptr_t str_addr, uintptr_t sym_count)
{
	size_t i;

	for (i = 0; i < sym_count; i++) {
		Sym sym;
		char *name;
		size_t sz;
		int type = XKB_WALK_GLOBAL;

		if (xkb_read(xkb, sym_addr + i * sizeof (sym), &sym,
		    sizeof (sym)) != sizeof (sym))
			return (0);

		if (GELF_ST_BIND(sym.st_info) == STB_LOCAL)
			type = XKB_WALK_LOCAL;

		name = xkb_readstr(xkb, str_addr + sym.st_name);

		sym.st_shndx = SHN_ABS;
		sym.st_name = sizes[XKB_WALK_STR];

		sizes[type] += sizeof (sym);
		sz = strlen(name) + 1;
		sizes[XKB_WALK_STR] += sz;

		if (buf != NULL) {
			if (types & type) {
				bcopy(&sym, *buf, sizeof (sym));
				*buf += sizeof (sym);
			}
			if (types & XKB_WALK_STR) {
				bcopy(name, *buf, sz);
				*buf += sz;
			}
		}

		mdb_free(name, 1024);
	}

	return (1);
}

static int
xkb_walk_syms(xkb_t *xkb, uintptr_t modhead, char **buf,
    size_t *sizes, int types)
{
	uintptr_t modctl = modhead;
	uintptr_t modulep;
	struct module module;
	uintptr_t sym_count;
	uintptr_t sym_addr;
	uintptr_t str_addr;
	size_t max_iter = 500;

	bzero(sizes, sizeof (*sizes) * (XKB_WALK_STR + 1));

	/*
	 * empty first symbol
	 */
	sizes[XKB_WALK_LOCAL] += sizeof (Sym);
	sizes[XKB_WALK_STR] += 1;

	if (buf != NULL) {
		if (types & XKB_WALK_LOCAL) {
			Sym tmp;
			bzero(&tmp, sizeof (tmp));
			bcopy(&tmp, *buf, sizeof (tmp));
			*buf += sizeof (tmp);
		}
		if (types & XKB_WALK_STR) {
			**buf = '\0';
			(*buf)++;
		}
	}

	for (;;) {
		if (!xkb_read_word(xkb,
		    modctl + offsetof(struct modctl, mod_mp), &modulep))
			return (0);

		if (modulep == NULL)
			goto next;

		if (!xkb_read_module(xkb, modulep, &module, &sym_addr,
		    &sym_count, &str_addr))
			return (0);

		if ((module.flags & KOBJ_NOKSYMS))
			goto next;

		if (!xkb_read_modsyms(xkb, buf, sizes, types, sym_addr,
		    str_addr, sym_count))
			return (0);

next:
		if (!xkb_read_word(xkb,
		    modctl + offsetof(struct modctl, mod_next), &modctl))
			return (0);

		if (modctl == modhead)
			break;
		/*
		 * Try and prevent us looping forever if we have a broken list.
		 */
		if (--max_iter == 0)
			break;
	}

	return (1);
}

/*
 * Userspace equivalent of ksyms_snapshot().  Since we don't have a namelist
 * file for hypervisor images, we fabricate one here using code similar
 * to that of /dev/ksyms.
 */
static int
xkb_build_ksyms(xkb_t *xkb)
{
	debug_info_t *info = &xkb->xkb_info;
	size_t sizes[XKB_WALK_STR + 1];
	xkb_namelist_t *hdr;
	char *buf;
	struct modctl modules;
	uintptr_t module;
	Shdr *shp;

	if (xkb_read(xkb, info->di_modules, &modules,
	    sizeof (struct modctl)) != sizeof (struct modctl))
		return (0);

	module = (uintptr_t)modules.mod_mp;

	if (!xkb_walk_syms(xkb, info->di_modules, NULL, sizes,
	    XKB_WALK_LOCAL | XKB_WALK_GLOBAL | XKB_WALK_STR))
		return (0);

	xkb->xkb_namesize = sizeof (xkb_namelist_t);
	xkb->xkb_namesize += sizes[XKB_WALK_LOCAL];
	xkb->xkb_namesize += sizes[XKB_WALK_GLOBAL];
	xkb->xkb_namesize += sizes[XKB_WALK_STR];

	if ((xkb->xkb_namelist = mdb_zalloc(xkb->xkb_namesize, UM_SLEEP))
	    == NULL)
		return (0);

	/* LINTED - alignment */
	hdr = (xkb_namelist_t *)xkb->xkb_namelist;

	if (xkb_read(xkb, module + offsetof(struct module, hdr),
	    &hdr->kh_elf_hdr, sizeof (Ehdr)) != sizeof (Ehdr))
		return (0);

	hdr->kh_elf_hdr.e_phoff = offsetof(xkb_namelist_t, kh_text_phdr);
	hdr->kh_elf_hdr.e_shoff = offsetof(xkb_namelist_t, kh_shdr);
	hdr->kh_elf_hdr.e_phnum = 2;
	hdr->kh_elf_hdr.e_shnum = XKB_SHDR_NUM;
	hdr->kh_elf_hdr.e_shstrndx = XKB_SHDR_SHSTRTAB;

	hdr->kh_text_phdr.p_type = PT_LOAD;
	hdr->kh_text_phdr.p_vaddr = (Addr)info->di_s_text;
	hdr->kh_text_phdr.p_memsz = (Word)(info->di_e_text - info->di_s_text);
	hdr->kh_text_phdr.p_flags = PF_R | PF_X;

	hdr->kh_data_phdr.p_type = PT_LOAD;
	hdr->kh_data_phdr.p_vaddr = (Addr)info->di_s_data;
	hdr->kh_data_phdr.p_memsz = (Word)(info->di_e_data - info->di_s_data);
	hdr->kh_data_phdr.p_flags = PF_R | PF_W | PF_X;

	shp = &hdr->kh_shdr[XKB_SHDR_SYMTAB];
	shp->sh_name = 1;	/* xkb_shstrtab[1] = ".symtab" */
	shp->sh_type = SHT_SYMTAB;
	shp->sh_offset = sizeof (xkb_namelist_t);
	shp->sh_size = sizes[XKB_WALK_LOCAL] + sizes[XKB_WALK_GLOBAL];
	shp->sh_link = XKB_SHDR_STRTAB;
	shp->sh_info = sizes[XKB_WALK_LOCAL] / sizeof (Sym);
	shp->sh_addralign = sizeof (Addr);
	shp->sh_entsize = sizeof (Sym);
	shp->sh_addr = (Addr)(xkb->xkb_namelist + shp->sh_offset);


	shp = &hdr->kh_shdr[XKB_SHDR_STRTAB];
	shp->sh_name = 9;	/* xkb_shstrtab[9] = ".strtab" */
	shp->sh_type = SHT_STRTAB;
	shp->sh_offset = sizeof (xkb_namelist_t) +
	    sizes[XKB_WALK_LOCAL] + sizes[XKB_WALK_GLOBAL];
	shp->sh_size = sizes[XKB_WALK_STR];
	shp->sh_addralign = 1;
	shp->sh_addr = (Addr)(xkb->xkb_namelist + shp->sh_offset);


	shp = &hdr->kh_shdr[XKB_SHDR_SHSTRTAB];
	shp->sh_name = 17;	/* xkb_shstrtab[17] = ".shstrtab" */
	shp->sh_type = SHT_STRTAB;
	shp->sh_offset = offsetof(xkb_namelist_t, shstrings);
	shp->sh_size = sizeof (xkb_shstrtab);
	shp->sh_addralign = 1;
	shp->sh_addr = (Addr)(xkb->xkb_namelist + shp->sh_offset);

	bcopy(xkb_shstrtab, hdr->shstrings, sizeof (xkb_shstrtab));

	buf = xkb->xkb_namelist + sizeof (xkb_namelist_t);

	if (!xkb_walk_syms(xkb, info->di_modules, &buf, sizes,
	    XKB_WALK_LOCAL))
		return (0);
	if (!xkb_walk_syms(xkb, info->di_modules, &buf, sizes,
	    XKB_WALK_GLOBAL))
		return (0);
	if (!xkb_walk_syms(xkb, info->di_modules, &buf, sizes,
	    XKB_WALK_STR))
		return (0);

	return (1);
}

/*ARGSUSED*/
xkb_t *
xkb_open(const char *namelist, const char *corefile, const char *swapfile,
    int flag, const char *err)
{
	struct stat64 corestat;
	uintptr_t debug_va = DEF_DEBUG_INFO_VA;
	size_t sz;
	size_t i;
	xkb_t *xkb = NULL;

	if (stat64(corefile, &corestat) == -1)
		return (xkb_fail(xkb, "cannot stat %s", corefile));

	if (flag != O_RDONLY)
		return (xkb_fail(xkb, "invalid open flags"));

	xkb = mdb_zalloc(sizeof (*xkb), UM_SLEEP);

	for (i = 0; i < 4; i++)
		xkb->xkb_pt_map[i].mm_map = (char *)MAP_FAILED;

	xkb->xkb_map.mm_map = (char *)MAP_FAILED;
	xkb->xkb_p2m_buf = (char *)MAP_FAILED;

	xkb->xkb_path = strdup(corefile);

	if ((xkb->xkb_fd = open64(corefile, O_RDONLY)) == -1)
		return (xkb_fail(xkb, "cannot open %s", corefile));

	if (pread64(xkb->xkb_fd, &xkb->xkb_hdr, sizeof (xkb->xkb_hdr), 0) !=
	    sizeof (xkb->xkb_hdr))
		return (xkb_fail(xkb, "invalid dump file"));

	if (xkb->xkb_hdr.xch_magic == XC_CORE_MAGIC_HVM)
		return (xkb_fail(xkb, "cannot process HVM images"));

	if (xkb->xkb_hdr.xch_magic != XC_CORE_MAGIC) {
		return (xkb_fail(xkb, "invalid magic %d",
		    xkb->xkb_hdr.xch_magic));
	}

	sz = xkb->xkb_hdr.xch_nr_vcpus * sizeof (*xkb->xkb_ctxts);

	xkb->xkb_ctxts = mdb_alloc(sz, UM_SLEEP);

	if (pread64(xkb->xkb_fd, xkb->xkb_ctxts, sz,
	    xkb->xkb_hdr.xch_ctxt_offset) != sz)
		return (xkb_fail(xkb, "cannot read VCPU contexts"));

	if (xkb->xkb_ctxts[0].flags & VGCF_HVM_GUEST)
		return (xkb_fail(xkb, "cannot process HVM images"));

	/*
	 * Try to map all the data pages. If we can't, fall back to the
	 * window/pread() approach, which is significantly slower.
	 */
	xkb->xkb_pages = mmap(NULL, PAGE_SIZE * xkb->xkb_hdr.xch_nr_pages,
	    PROT_READ, MAP_SHARED, xkb->xkb_fd,
	    xkb->xkb_hdr.xch_pages_offset);

	if (xkb->xkb_pages == (char *)MAP_FAILED)
		xkb->xkb_pages = NULL;

#if defined(__amd64)
	xkb->xkb_mmu.mi_max = 3;
	xkb->xkb_mmu.mi_shift[0] = 12;
	xkb->xkb_mmu.mi_shift[1] = 21;
	xkb->xkb_mmu.mi_shift[2] = 30;
	xkb->xkb_mmu.mi_shift[3] = 39;
	xkb->xkb_mmu.mi_ptes = 512;
	xkb->xkb_mmu.mi_ptesize = 8;
#elif defined(__i386)
	/*
	 * We'd like to adapt for correctness' sake, but we have no way of
	 * detecting a PAE guest, since cr4 writes are disallowed.
	 */
	debug_va = PAE_DEBUG_INFO_VA;
	xkb->xkb_mmu.mi_max = 2;
	xkb->xkb_mmu.mi_shift[0] = 12;
	xkb->xkb_mmu.mi_shift[1] = 21;
	xkb->xkb_mmu.mi_shift[2] = 30;
	xkb->xkb_mmu.mi_ptes = 512;
	xkb->xkb_mmu.mi_ptesize = 8;
#endif

	if (!xkb_map_p2m(xkb))
		return (NULL);

	if (!xkb_build_m2p(xkb))
		return (NULL);

	if (xkb_read(xkb, debug_va, &xkb->xkb_info,
	    sizeof (xkb->xkb_info)) != sizeof (xkb->xkb_info))
		return (xkb_fail(xkb, "cannot read debug_info"));

	if (xkb->xkb_info.di_magic != DEBUG_INFO_MAGIC) {
		return (xkb_fail(xkb, "invalid debug info magic %d",
		    xkb->xkb_info.di_magic));
	}

	if (xkb->xkb_info.di_version != DEBUG_INFO_VERSION) {
		return (xkb_fail(xkb, "unknown debug info version %d",
		    xkb->xkb_info.di_version));
	}

	if (!xkb_build_ksyms(xkb))
		return (xkb_fail(xkb, "cannot construct namelist"));

	return (xkb);
}

int
xkb_close(xkb_t *xkb)
{
	size_t sz;
	size_t i;

	if (xkb == NULL)
		return (0);

	if (xkb->xkb_m2p != NULL) {
		mdb_free(xkb->xkb_m2p,
		    (xkb->xkb_max_mfn + 1) * sizeof (xen_pfn_t));
	}

	sz = sizeof (xen_pfn_t) * xkb->xkb_hdr.xch_nr_pages;

	if (xkb->xkb_p2m_buf != (xen_pfn_t *)MAP_FAILED)
		(void) munmap(xkb->xkb_p2m_buf, sz);

	if (xkb->xkb_pages != NULL) {
		(void) munmap((void *)xkb->xkb_pages,
		    PAGE_SIZE * xkb->xkb_hdr.xch_nr_pages);
	} else {
		for (i = 0; i < 4; i++) {
			char *addr = xkb->xkb_pt_map[i].mm_map;
			if (addr != (char *)MAP_FAILED)
				(void) munmap((void *)addr, PAGE_SIZE);
		}
		if (xkb->xkb_map.mm_map != (char *)MAP_FAILED) {
			(void) munmap((void *)xkb->xkb_map.mm_map,
			    PAGE_SIZE);
		}
	}

	if (xkb->xkb_ctxts != NULL) {
		mdb_free(xkb->xkb_ctxts, sizeof (struct vcpu_guest_context) *
		    xkb->xkb_hdr.xch_nr_vcpus);
	}

	if (xkb->xkb_namelist != NULL)
		mdb_free(xkb->xkb_namelist, xkb->xkb_namesize);

	if (xkb->xkb_fd != -1)
		(void) close(xkb->xkb_fd);

	free(xkb->xkb_path);

	mdb_free(xkb, sizeof (*xkb));
	return (0);
}

/*ARGSUSED*/
static mdb_io_t *
xkb_sym_io(xkb_t *xkb, const char *symfile)
{
	mdb_io_t *io = mdb_memio_create(xkb->xkb_namelist, xkb->xkb_namesize);

	if (io == NULL)
		mdb_warn("failed to create namelist from %s", xkb->xkb_path);

	return (io);
}

uint64_t
xkb_vtop(xkb_t *xkb, struct as *as, uintptr_t addr)
{
	mfn_t tlmfn = xen_cr3_to_pfn(xkb->xkb_ctxts[0].ctrlreg[3]);
	mfn_t mfn;

	if (as != NULL && (tlmfn = xkb_as_to_mfn(xkb, as)) == MFN_INVALID)
		return (-1ULL);

	mfn = xkb_va_to_mfn(xkb, addr, tlmfn);

	if (mfn == MFN_INVALID || mfn > xkb->xkb_max_mfn)
		return (-1ULL);

	return (((uint64_t)xkb->xkb_m2p[mfn] << PAGE_SHIFT)
	    | PAGE_OFFSET(addr));
}

static int
xkb_getmregs(xkb_t *xkb, uint_t cpu, struct privmregs *mregs)
{
	struct vcpu_guest_context *vcpu;
	struct cpu_user_regs *ur;
	struct regs *regs;

	if (cpu >= xkb->xkb_hdr.xch_nr_vcpus) {
		errno = EINVAL;
		return (-1);
	}

	bzero(mregs, sizeof (*mregs));

	vcpu = &xkb->xkb_ctxts[cpu];
	ur = &vcpu->user_regs;
	regs = &mregs->pm_gregs;

	regs->r_ss = ur->ss;
	regs->r_cs = ur->cs;
	regs->r_ds = ur->ds;
	regs->r_es = ur->es;
	regs->r_fs = ur->fs;
	regs->r_gs = ur->gs;
	regs->r_trapno = ur->entry_vector;
	regs->r_err = ur->error_code;
#ifdef __amd64
	regs->r_savfp = ur->rbp;
	regs->r_savpc = ur->rip;
	regs->r_rdi = ur->rdi;
	regs->r_rsi = ur->rsi;
	regs->r_rdx = ur->rdx;
	regs->r_rcx = ur->rcx;
	regs->r_r8 = ur->r8;
	regs->r_r9 = ur->r9;
	regs->r_rax = ur->rax;
	regs->r_rbx = ur->rbx;
	regs->r_rbp = ur->rbp;
	regs->r_r10 = ur->r10;
	regs->r_r11 = ur->r11;
	regs->r_r12 = ur->r12;
	regs->r_r13 = ur->r13;
	regs->r_r14 = ur->r14;
	regs->r_r15 = ur->r15;
	regs->r_rip = ur->rip;
	regs->r_rfl = ur->rflags;
	regs->r_rsp = ur->rsp;
#else
	regs->r_savfp = ur->ebp;
	regs->r_savpc = ur->eip;
	regs->r_edi = ur->edi;
	regs->r_esi = ur->esi;
	regs->r_ebp = ur->ebp;
	regs->r_esp = ur->esp;
	regs->r_ebx = ur->ebx;
	regs->r_edx = ur->edx;
	regs->r_ecx = ur->ecx;
	regs->r_eax = ur->eax;
	regs->r_eip = ur->eip;
	regs->r_efl = ur->eflags;
	regs->r_uesp = 0;
#endif

	bcopy(&vcpu->ctrlreg, &mregs->pm_cr, 8 * sizeof (ulong_t));
	bcopy(&vcpu->debugreg, &mregs->pm_dr, 8 * sizeof (ulong_t));

	mregs->pm_flags = PM_GREGS | PM_CRREGS | PM_DRREGS;

	return (0);
}

static mdb_kb_ops_t xpv_kb_ops = {
	.kb_open = (void *(*)())xkb_open,
	.kb_close = (int (*)())xkb_close,
	.kb_sym_io = (mdb_io_t *(*)())xkb_sym_io,
	.kb_kread = (ssize_t (*)())xkb_read,
	.kb_kwrite = (ssize_t (*)())mdb_tgt_notsup,
	.kb_aread = (ssize_t (*)())xkb_aread,
	.kb_awrite = (ssize_t (*)())mdb_tgt_notsup,
	.kb_pread = (ssize_t (*)())xkb_pread,
	.kb_pwrite = (ssize_t (*)())mdb_tgt_notsup,
	.kb_vtop = (uint64_t (*)())xkb_vtop,
	.kb_getmregs = (int (*)())xkb_getmregs
};

mdb_kb_ops_t *
mdb_kb_ops(void)
{
	return (&xpv_kb_ops);
}

static const mdb_dcmd_t dcmds[] = { NULL, };
static const mdb_walker_t walkers[] = { NULL, };
static const mdb_modinfo_t modinfo = { MDB_API_VERSION, dcmds, walkers };

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}

void
_mdb_fini(void)
{
}
