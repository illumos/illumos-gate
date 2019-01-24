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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * KVM backend for hypervisor domain dumps.  We don't use libkvm for
 * such dumps, since they do not have a namelist file or the typical
 * dump structures we expect to aid bootstrapping.  Instead, we
 * bootstrap based upon a debug_info structure at a known VA, using the
 * guest's own page tables to resolve to physical addresses, and
 * construct the namelist in a manner similar to ksyms_snapshot().
 *
 * Note that there are two formats understood by this module: the older,
 * ad hoc format, which we call 'core' within this file, and an
 * ELF-based format, known as 'elf'.
 *
 * We only support the older format generated on Solaris dom0: before we
 * fixed it, core dump files were broken whenever a PFN didn't map a
 * real MFN (!).
 */

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
#include <xen/public/version.h>
#include <xen/public/elfnote.h>

#define	XKB_SHDR_NULL 0
#define	XKB_SHDR_SYMTAB 1
#define	XKB_SHDR_STRTAB 2
#define	XKB_SHDR_SHSTRTAB 3
#define	XKB_SHDR_NUM 4

#define	XKB_WALK_LOCAL 0x1
#define	XKB_WALK_GLOBAL 0x2
#define	XKB_WALK_STR 0x4
#define	XKB_WALK_ALL (XKB_WALK_LOCAL | XKB_WALK_GLOBAL | XKB_WALK_STR)

#if defined(__i386)
#define	DEBUG_INFO 0xf4bff000
#define	DEBUG_INFO_HVM 0xfe7ff000
#elif defined(__amd64)
#define	DEBUG_INFO 0xfffffffffb7ff000
#define	DEBUG_INFO_HVM 0xfffffffffb7ff000
#endif

#define	PAGE_SIZE 0x1000
#define	PAGE_SHIFT 12
#define	PAGE_OFFSET(a) ((a) & (PAGE_SIZE - 1))
#define	PAGE_MASK(a) ((a) & ~(PAGE_SIZE - 1))
#define	PAGE_ALIGNED(a) (((a) & (PAGE_SIZE -1)) == 0)
#define	PT_PADDR_LGPG 0x000fffffffffe000ull
#define	PT_PADDR 0x000ffffffffff000ull
#define	PT_VALID 0x1
#define	PT_PAGESIZE 0x080
#define	PTE_IS_LGPG(p, l) ((l) > 0 && ((p) & PT_PAGESIZE))

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

struct xc_elf_header {
	uint64_t xeh_magic;
	uint64_t xeh_nr_vcpus;
	uint64_t xeh_nr_pages;
	uint64_t xeh_page_size;
};

struct xc_elf_version {
	uint64_t xev_major;
	uint64_t xev_minor;
	xen_extraversion_t xev_extra;
	xen_compile_info_t xev_compile_info;
	xen_capabilities_info_t xev_capabilities;
	xen_changeset_info_t xev_changeset;
	xen_platform_parameters_t xev_platform_parameters;
	uint64_t xev_pagesize;
};

/*
 * Either an old-style (3.0.4) core format, or the ELF format.
 */
typedef enum {
	XKB_FORMAT_UNKNOWN = 0,
	XKB_FORMAT_CORE = 1,
	XKB_FORMAT_ELF = 2
} xkb_type_t;

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

typedef struct xkb_core {
	xc_core_header_t xc_hdr;
	void *xc_p2m_buf;
} xkb_core_t;

typedef struct xkb_elf {
	mdb_gelf_file_t *xe_gelf;
	size_t *xe_off;
	struct xc_elf_header xe_hdr;
	struct xc_elf_version xe_version;
} xkb_elf_t;

typedef struct xkb {
	char *xkb_path;
	int xkb_fd;
	int xkb_is_hvm;

	xkb_type_t xkb_type;
	xkb_core_t xkb_core;
	xkb_elf_t xkb_elf;

	size_t xkb_nr_vcpus;
	size_t xkb_nr_pages;
	size_t xkb_pages_off;
	xen_pfn_t xkb_max_pfn;
	mfn_t xkb_max_mfn;
	int xkb_is_pae;

	mmu_info_t xkb_mmu;
	debug_info_t xkb_info;

	void *xkb_vcpu_data;
	size_t xkb_vcpu_data_sz;
	struct vcpu_guest_context **xkb_vcpus;

	char *xkb_pages;
	mfn_t *xkb_p2m;
	xen_pfn_t *xkb_m2p;
	mfn_map_t xkb_pt_map[4];
	mfn_map_t xkb_map;

	char *xkb_namelist;
	size_t xkb_namesize;
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

/*
 * Jump through the hoops we need to to correctly identify a core file
 * of either the old or new format.
 */
int
xkb_identify(const char *file, int *longmode)
{
	xc_core_header_t header;
	mdb_gelf_file_t *gf = NULL;
	mdb_gelf_sect_t *sect = NULL;
	mdb_io_t *io = NULL;
	char *notes = NULL;
	char *pos;
	int ret = 0;
	size_t sz;
	int fd;

	if ((fd = open64(file, O_RDONLY)) == -1)
		return (-1);

	if (pread64(fd, &header, sizeof (header), 0) != sizeof (header)) {
		(void) close(fd);
		return (0);
	}

	(void) close(fd);

	if (header.xch_magic == XC_CORE_MAGIC) {
		*longmode = 0;

		/*
		 * Indeed.
		 */
		sz = header.xch_index_offset - header.xch_ctxt_offset;
#ifdef _LP64
		if (sizeof (struct vcpu_guest_context) *
		    header.xch_nr_vcpus == sz)
			*longmode = 1;
#else
		if (sizeof (struct vcpu_guest_context) *
		    header.xch_nr_vcpus != sz)
			*longmode = 1;
#endif /* _LP64 */

		return (1);
	}

	if ((io = mdb_fdio_create_path(NULL, file, O_RDONLY, 0)) == NULL)
		return (-1);

	if ((gf = mdb_gelf_create(io, ET_NONE, GF_FILE)) == NULL)
		goto out;

	if ((sect = mdb_gelf_sect_by_name(gf, ".note.Xen")) == NULL)
		goto out;

	if ((notes = mdb_gelf_sect_load(gf, sect)) == NULL)
		goto out;

	for (pos = notes; pos < notes + sect->gs_shdr.sh_size; ) {
		struct xc_elf_version *vers;
		/* LINTED - alignment */
		Elf64_Nhdr *nhdr = (Elf64_Nhdr *)pos;
		char *desc;
		char *name;

		name = pos + sizeof (*nhdr);
		desc = (char *)P2ROUNDUP((uintptr_t)name + nhdr->n_namesz, 4);

		pos = desc + nhdr->n_descsz;

		if (nhdr->n_type != XEN_ELFNOTE_DUMPCORE_XEN_VERSION)
			continue;

		/*
		 * The contents of this struct differ between 32 and 64
		 * bit; however, not until past the 'xev_capabilities'
		 * member, so we can just about get away with this.
		 */

		/* LINTED - alignment */
		vers = (struct xc_elf_version *)desc;

		if (strstr(vers->xev_capabilities, "x86_64")) {
			/*
			 * 64-bit hypervisor, but it can still be
			 * a 32-bit domain core. 32-bit domain cores
			 * are also dumped in Elf64 format, but they
			 * have e_machine set to EM_386, not EM_AMD64.
			 */
			if (gf->gf_ehdr.e_machine == EM_386)
				*longmode = 0;
			else
				*longmode = 1;
		} else if (strstr(vers->xev_capabilities, "x86_32") ||
		    strstr(vers->xev_capabilities, "x86_32p")) {
			/*
			 * 32-bit hypervisor, can only be a 32-bit core.
			 */
			*longmode = 0;
		} else {
			mdb_warn("couldn't derive word size of dump; "
			    "assuming 64-bit");
			*longmode = 1;
		}
	}

	ret = 1;

out:
	if (gf != NULL)
		mdb_gelf_destroy(gf);
	else if (io != NULL)
		mdb_io_destroy(io);
	return (ret);
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

	errno = ENOEXEC;

	return (NULL);
}

static int
xkb_build_m2p(xkb_t *xkb)
{
	size_t i;

	for (i = 0; i <= xkb->xkb_max_pfn; i++) {
		if (xkb->xkb_p2m[i] != MFN_INVALID &&
		    xkb->xkb_p2m[i] > xkb->xkb_max_mfn)
			xkb->xkb_max_mfn = xkb->xkb_p2m[i];
	}

	xkb->xkb_m2p = mdb_alloc((xkb->xkb_max_mfn + 1) * sizeof (xen_pfn_t),
	    UM_SLEEP);

	for (i = 0; i <= xkb->xkb_max_mfn; i++)
		xkb->xkb_m2p[i] = PFN_INVALID;

	for (i = 0; i <= xkb->xkb_max_pfn; i++) {
		if (xkb->xkb_p2m[i] != MFN_INVALID)
			xkb->xkb_m2p[xkb->xkb_p2m[i]] = i;
	}

	return (1);
}

/*
 * With FORMAT_CORE, we can use the table in the dump file directly.
 * Just to make things fun, they've not page-aligned the p2m table.
 */
static int
xkb_map_p2m(xkb_t *xkb)
{
	offset_t off;
	size_t size;
	xkb_core_t *xc = &xkb->xkb_core;
	size_t count = xkb->xkb_nr_pages;
	size_t boff = xc->xc_hdr.xch_index_offset;

	size = (sizeof (mfn_t) * count) + (PAGE_SIZE * 2);
	size = PAGE_MASK(size);
	off = PAGE_MASK(boff);

	/* LINTED - alignment */
	xc->xc_p2m_buf = (mfn_t *)mmap(NULL, size, PROT_READ,
	    MAP_SHARED, xkb->xkb_fd, off);

	if (xc->xc_p2m_buf == (xen_pfn_t *)MAP_FAILED) {
		(void) xkb_fail(xkb, "cannot map p2m table");
		return (0);
	}

	/* LINTED - alignment */
	xkb->xkb_p2m = (mfn_t *)((char *)xc->xc_p2m_buf +
	    PAGE_OFFSET(boff));

	return (1);
}

/*
 * With FORMAT_ELF, we have a set of <pfn,mfn> pairs, which we convert
 * into a linear array indexed by pfn for convenience.  We also need to
 * track the mapping between mfn and the offset in the file: a pfn with
 * no mfn will not appear in the core file.
 */
static int
xkb_build_p2m(xkb_t *xkb)
{
	xkb_elf_t *xe = &xkb->xkb_elf;
	mdb_gelf_sect_t *sect;
	size_t size;
	size_t i;

	struct elf_p2m {
		uint64_t pfn;
		uint64_t gmfn;
	} *p2m;

	sect = mdb_gelf_sect_by_name(xe->xe_gelf, ".xen_p2m");

	if (sect == NULL) {
		(void) xkb_fail(xkb, "cannot find section .xen_p2m");
		return (0);
	}

	if ((p2m = mdb_gelf_sect_load(xe->xe_gelf, sect)) == NULL) {
		(void) xkb_fail(xkb, "couldn't read .xen_p2m");
		return (0);
	}

	for (i = 0; i < xkb->xkb_nr_pages; i++) {
		if (p2m[i].pfn > xkb->xkb_max_pfn)
			xkb->xkb_max_pfn = p2m[i].pfn;
	}

	size = sizeof (xen_pfn_t) * (xkb->xkb_max_pfn + 1);
	xkb->xkb_p2m = mdb_alloc(size, UM_SLEEP);
	size = sizeof (size_t) * (xkb->xkb_max_pfn + 1);
	xe->xe_off = mdb_alloc(size, UM_SLEEP);

	for (i = 0; i <= xkb->xkb_max_pfn; i++) {
		xkb->xkb_p2m[i] = PFN_INVALID;
		xe->xe_off[i] = (size_t)-1;
	}

	for (i = 0; i < xkb->xkb_nr_pages; i++) {
		xkb->xkb_p2m[p2m[i].pfn] = p2m[i].gmfn;
		xe->xe_off[p2m[i].pfn] = i;
	}

	return (1);
}

/*
 * For HVM images, we don't have the corresponding MFN list; the table
 * is just a mapping from page index in the dump to the corresponding
 * PFN.  To simplify the other code, we'll pretend that these PFNs are
 * really MFNs as well, by populating xkb_p2m.
 */
static int
xkb_build_fake_p2m(xkb_t *xkb)
{
	xkb_elf_t *xe = &xkb->xkb_elf;
	mdb_gelf_sect_t *sect;
	size_t size;
	size_t i;

	uint64_t *p2pfn;

	sect = mdb_gelf_sect_by_name(xe->xe_gelf, ".xen_pfn");

	if (sect == NULL) {
		(void) xkb_fail(xkb, "cannot find section .xen_pfn");
		return (0);
	}

	if ((p2pfn = mdb_gelf_sect_load(xe->xe_gelf, sect)) == NULL) {
		(void) xkb_fail(xkb, "couldn't read .xen_pfn");
		return (0);
	}

	for (i = 0; i < xkb->xkb_nr_pages; i++) {
		if (p2pfn[i] != PFN_INVALID && p2pfn[i] > xkb->xkb_max_pfn)
			xkb->xkb_max_pfn = p2pfn[i];
	}

	size = sizeof (xen_pfn_t) * (xkb->xkb_max_pfn + 1);
	xkb->xkb_p2m = mdb_alloc(size, UM_SLEEP);

	size = sizeof (size_t) * (xkb->xkb_max_pfn + 1);
	xe->xe_off = mdb_alloc(size, UM_SLEEP);

	for (i = 0; i <= xkb->xkb_max_pfn; i++) {
		xkb->xkb_p2m[i] = PFN_INVALID;
		xe->xe_off[i] = (size_t)-1;
	}

	for (i = 0; i < xkb->xkb_nr_pages; i++) {
		if (p2pfn[i] == PFN_INVALID)
			continue;
		xkb->xkb_p2m[p2pfn[i]] = p2pfn[i];
		xe->xe_off[p2pfn[i]] = i;
	}

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

	if (pfn > xkb->xkb_max_pfn)
		return (MFN_INVALID);

	return (xkb->xkb_p2m[pfn]);
}

static mfn_t
xkb_cr3_to_pfn(xkb_t *xkb)
{
	uint64_t cr3 = xkb->xkb_vcpus[0]->ctrlreg[3];
	if (xkb->xkb_is_hvm)
		return (cr3 >> PAGE_SHIFT);
	return (xen_cr3_to_pfn(cr3));
}

static ssize_t
xkb_read_helper(xkb_t *xkb, struct as *as, int phys, uint64_t addr,
    void *buf, size_t size)
{
	size_t left = size;
	int windowed = (xkb->xkb_pages == NULL);
	mfn_t tlmfn = xkb_cr3_to_pfn(xkb);

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
			if (pfn > xkb->xkb_max_pfn)
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
xkb_pfn_to_off(xkb_t *xkb, xen_pfn_t pfn)
{
	if (pfn == PFN_INVALID || pfn > xkb->xkb_max_pfn)
		return (-1ULL);

	if (xkb->xkb_type == XKB_FORMAT_CORE)
		return (PAGE_SIZE * pfn);

	return (PAGE_SIZE * (xkb->xkb_elf.xe_off[pfn]));
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

	return (xkb->xkb_pages_off + xkb_pfn_to_off(xkb, pfn));
}

static char *
xkb_map_mfn(xkb_t *xkb, mfn_t mfn, mfn_map_t *mm)
{
	int windowed = (xkb->xkb_pages == NULL);
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

		mm->mm_map = xkb->xkb_pages + xkb_pfn_to_off(xkb, pfn);
	}

	return (mm->mm_map);
}

static uint64_t
xkb_get_pte(mmu_info_t *mmu, char *ptep)
{
	uint64_t pte = 0;

	if (mmu->mi_ptesize == 8) {
		/* LINTED - alignment */
		pte = *((uint64_t *)ptep);
	} else {
		/* LINTED - alignment */
		pte = *((uint32_t *)ptep);
	}

	return (pte);
}

static mfn_t
xkb_pte_to_base_mfn(uint64_t pte, size_t level)
{
	if (PTE_IS_LGPG(pte, level)) {
		pte &= PT_PADDR_LGPG;
	} else {
		pte &= PT_PADDR;
	}

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
	uint64_t pte;
	size_t level;

	for (level = mmu->mi_max; ; --level) {
		size_t entry;

		if (xkb_map_mfn(xkb, mfn, &xkb->xkb_pt_map[level]) == NULL)
			return (MFN_INVALID);

		entry = (va >> mmu->mi_shift[level]) & (mmu->mi_ptes - 1);

		pte = xkb_get_pte(mmu, (char *)xkb->xkb_pt_map[level].mm_map +
		    entry * mmu->mi_ptesize);

		if ((mfn = xkb_pte_to_base_mfn(pte, level)) == MFN_INVALID)
			return (MFN_INVALID);

		if (level == 0)
			break;

		/*
		 * Currently 'mfn' refers to the base MFN of the
		 * large-page mapping.  Add on the 4K-sized index into
		 * the large-page mapping to get the right MFN within
		 * the mapping.
		 */
		if (PTE_IS_LGPG(pte, level)) {
			mfn += (va & ((1 << mmu->mi_shift[level]) - 1)) >>
			    PAGE_SHIFT;
			break;
		}
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

		if (modulep == 0)
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

static xkb_t *
xkb_open_core(xkb_t *xkb)
{
	xkb_core_t *xc = &xkb->xkb_core;
	size_t sz;
	int i;
	struct vcpu_guest_context *vcp;

	xkb->xkb_type = XKB_FORMAT_CORE;

	if ((xkb->xkb_fd = open64(xkb->xkb_path, O_RDONLY)) == -1)
		return (xkb_fail(xkb, "cannot open %s", xkb->xkb_path));

	if (pread64(xkb->xkb_fd, &xc->xc_hdr, sizeof (xc->xc_hdr), 0) !=
	    sizeof (xc->xc_hdr))
		return (xkb_fail(xkb, "invalid dump file"));

	if (xc->xc_hdr.xch_magic == XC_CORE_MAGIC_HVM)
		return (xkb_fail(xkb, "cannot process HVM images"));

	if (xc->xc_hdr.xch_magic != XC_CORE_MAGIC) {
		return (xkb_fail(xkb, "invalid magic %d",
		    xc->xc_hdr.xch_magic));
	}

	/*
	 * With FORMAT_CORE, all pages are in the dump (non-existing
	 * ones are zeroed out).
	 */
	xkb->xkb_nr_pages = xc->xc_hdr.xch_nr_pages;
	xkb->xkb_pages_off = xc->xc_hdr.xch_pages_offset;
	xkb->xkb_max_pfn = xc->xc_hdr.xch_nr_pages - 1;
	xkb->xkb_nr_vcpus = xc->xc_hdr.xch_nr_vcpus;

	sz = xkb->xkb_nr_vcpus * sizeof (struct vcpu_guest_context);
	xkb->xkb_vcpu_data_sz = sz;
	xkb->xkb_vcpu_data = mdb_alloc(sz, UM_SLEEP);

	if (pread64(xkb->xkb_fd, xkb->xkb_vcpu_data, sz,
	    xc->xc_hdr.xch_ctxt_offset) != sz)
		return (xkb_fail(xkb, "cannot read VCPU contexts"));

	sz = xkb->xkb_nr_vcpus * sizeof (struct vcpu_guest_context *);
	xkb->xkb_vcpus = mdb_alloc(sz, UM_SLEEP);

	vcp = xkb->xkb_vcpu_data;
	for (i = 0; i < xkb->xkb_nr_vcpus; i++)
		xkb->xkb_vcpus[i] = &vcp[i];

	/*
	 * Try to map all the data pages. If we can't, fall back to the
	 * window/pread() approach, which is significantly slower.
	 */
	xkb->xkb_pages = mmap(NULL, PAGE_SIZE * xkb->xkb_nr_pages,
	    PROT_READ, MAP_SHARED, xkb->xkb_fd, xc->xc_hdr.xch_pages_offset);

	if (xkb->xkb_pages == (char *)MAP_FAILED)
		xkb->xkb_pages = NULL;

	/*
	 * We'd like to adapt for correctness' sake, but we have no way of
	 * detecting a PAE guest, since cr4 writes are disallowed.
	 */
	xkb->xkb_is_pae = 1;

	if (!xkb_map_p2m(xkb))
		return (NULL);

	return (xkb);
}

static xkb_t *
xkb_open_elf(xkb_t *xkb)
{
	xkb_elf_t *xe = &xkb->xkb_elf;
	mdb_gelf_sect_t *sect;
	char *notes;
	char *pos;
	mdb_io_t *io;
	size_t sz;
	int i;
	void *dp;

	if ((io = mdb_fdio_create_path(NULL, xkb->xkb_path,
	    O_RDONLY, 0)) == NULL)
		return (xkb_fail(xkb, "failed to open"));

	xe->xe_gelf = mdb_gelf_create(io, ET_NONE, GF_FILE);

	if (xe->xe_gelf == NULL) {
		mdb_io_destroy(io);
		return (xkb);
	}

	xkb->xkb_fd = mdb_fdio_fileno(io);

	sect = mdb_gelf_sect_by_name(xe->xe_gelf, ".note.Xen");

	if (sect == NULL)
		return (xkb);

	if ((notes = mdb_gelf_sect_load(xe->xe_gelf, sect)) == NULL)
		return (xkb);

	/*
	 * Now we know this is indeed a hypervisor core dump, even if
	 * it's corrupted.
	 */
	xkb->xkb_type = XKB_FORMAT_ELF;

	for (pos = notes; pos < notes + sect->gs_shdr.sh_size; ) {
		/* LINTED - alignment */
		Elf64_Nhdr *nhdr = (Elf64_Nhdr *)pos;
		uint64_t vers;
		char *desc;
		char *name;

		name = pos + sizeof (*nhdr);
		desc = (char *)P2ROUNDUP((uintptr_t)name + nhdr->n_namesz, 4);

		pos = desc + nhdr->n_descsz;

		switch (nhdr->n_type) {
		case XEN_ELFNOTE_DUMPCORE_NONE:
			break;

		case XEN_ELFNOTE_DUMPCORE_HEADER:
			if (nhdr->n_descsz != sizeof (struct xc_elf_header)) {
				return (xkb_fail(xkb, "invalid ELF note "
				    "XEN_ELFNOTE_DUMPCORE_HEADER\n"));
			}

			bcopy(desc, &xe->xe_hdr,
			    sizeof (struct xc_elf_header));
			break;

		case XEN_ELFNOTE_DUMPCORE_XEN_VERSION:
			if (nhdr->n_descsz < sizeof (struct xc_elf_version)) {
				return (xkb_fail(xkb, "invalid ELF note "
				    "XEN_ELFNOTE_DUMPCORE_XEN_VERSION\n"));
			}

			bcopy(desc, &xe->xe_version,
			    sizeof (struct xc_elf_version));
			break;

		case XEN_ELFNOTE_DUMPCORE_FORMAT_VERSION:
			/* LINTED - alignment */
			vers = *((uint64_t *)desc);
			if ((vers >> 32) != 0) {
				return (xkb_fail(xkb, "unknown major "
				    "version %d (expected 0)\n",
				    (int)(vers >> 32)));
			}

			if ((vers & 0xffffffff) != 1) {
				mdb_warn("unexpected dump minor number "
				    "version %d (expected 1)\n",
				    (int)(vers & 0xffffffff));
			}
			break;

		default:
			mdb_warn("unknown ELF note %d(%s)\n",
			    nhdr->n_type, name);
			break;
		}
	}

	xkb->xkb_is_hvm = xe->xe_hdr.xeh_magic == XC_CORE_MAGIC_HVM;

	if (xe->xe_hdr.xeh_magic != XC_CORE_MAGIC &&
	    xe->xe_hdr.xeh_magic != XC_CORE_MAGIC_HVM) {
		return (xkb_fail(xkb, "invalid magic %d",
		    xe->xe_hdr.xeh_magic));
	}

	xkb->xkb_nr_pages = xe->xe_hdr.xeh_nr_pages;
	xkb->xkb_is_pae = (strstr(xe->xe_version.xev_capabilities,
	    "x86_32p") != NULL);

	sect = mdb_gelf_sect_by_name(xe->xe_gelf, ".xen_prstatus");

	if (sect == NULL)
		return (xkb_fail(xkb, "cannot find section .xen_prstatus"));

	if (sect->gs_shdr.sh_entsize < sizeof (vcpu_guest_context_t))
		return (xkb_fail(xkb, "invalid section .xen_prstatus"));

	xkb->xkb_nr_vcpus = sect->gs_shdr.sh_size / sect->gs_shdr.sh_entsize;

	xkb->xkb_vcpu_data = mdb_gelf_sect_load(xe->xe_gelf, sect);
	if (xkb->xkb_vcpu_data == NULL)
		return (xkb_fail(xkb, "cannot load section .xen_prstatus"));
	xkb->xkb_vcpu_data_sz = sect->gs_shdr.sh_size;

	/*
	 * The vcpu_guest_context structures saved in the core file
	 * are actually unions of the 64-bit and 32-bit versions.
	 * Don't rely on the entry size to match the size of
	 * the structure, but set up an array of pointers.
	 */
	sz = xkb->xkb_nr_vcpus * sizeof (struct vcpu_guest_context *);
	xkb->xkb_vcpus = mdb_alloc(sz, UM_SLEEP);
	for (i = 0; i < xkb->xkb_nr_vcpus; i++) {
		dp = ((char *)xkb->xkb_vcpu_data +
		    i * sect->gs_shdr.sh_entsize);
		xkb->xkb_vcpus[i] = dp;
	}

	sect = mdb_gelf_sect_by_name(xe->xe_gelf, ".xen_pages");

	if (sect == NULL)
		return (xkb_fail(xkb, "cannot find section .xen_pages"));

	if (!PAGE_ALIGNED(sect->gs_shdr.sh_offset))
		return (xkb_fail(xkb, ".xen_pages is not page aligned"));

	if (sect->gs_shdr.sh_entsize != PAGE_SIZE)
		return (xkb_fail(xkb, "invalid section .xen_pages"));

	xkb->xkb_pages_off = sect->gs_shdr.sh_offset;

	/*
	 * Try to map all the data pages. If we can't, fall back to the
	 * window/pread() approach, which is significantly slower.
	 */
	xkb->xkb_pages = mmap(NULL, PAGE_SIZE * xkb->xkb_nr_pages,
	    PROT_READ, MAP_SHARED, xkb->xkb_fd, xkb->xkb_pages_off);

	if (xkb->xkb_pages == (char *)MAP_FAILED)
		xkb->xkb_pages = NULL;

	if (xkb->xkb_is_hvm) {
		if (!xkb_build_fake_p2m(xkb))
			return (NULL);
	} else {
		if (!xkb_build_p2m(xkb))
			return (NULL);
	}

	return (xkb);
}

static void
xkb_init_mmu(xkb_t *xkb)
{
#if defined(__amd64)
	xkb->xkb_mmu.mi_max = 3;
	xkb->xkb_mmu.mi_shift[0] = 12;
	xkb->xkb_mmu.mi_shift[1] = 21;
	xkb->xkb_mmu.mi_shift[2] = 30;
	xkb->xkb_mmu.mi_shift[3] = 39;
	xkb->xkb_mmu.mi_ptes = 512;
	xkb->xkb_mmu.mi_ptesize = 8;
#elif defined(__i386)
	if (xkb->xkb_is_pae) {
		xkb->xkb_mmu.mi_max = 2;
		xkb->xkb_mmu.mi_shift[0] = 12;
		xkb->xkb_mmu.mi_shift[1] = 21;
		xkb->xkb_mmu.mi_shift[2] = 30;
		xkb->xkb_mmu.mi_ptes = 512;
		xkb->xkb_mmu.mi_ptesize = 8;
	} else {
		xkb->xkb_mmu.mi_max = 1;
		xkb->xkb_mmu.mi_shift[0] = 12;
		xkb->xkb_mmu.mi_shift[1] = 22;
		xkb->xkb_mmu.mi_ptes = 1024;
		xkb->xkb_mmu.mi_ptesize = 4;
	}
#endif
}

/*ARGSUSED*/
xkb_t *
xkb_open(const char *namelist, const char *corefile, const char *swapfile,
    int flag, const char *err)
{
	uintptr_t debug_info = DEBUG_INFO;
	struct stat64 corestat;
	xkb_t *xkb = NULL;
	size_t i;

	if (stat64(corefile, &corestat) == -1)
		return (xkb_fail(xkb, "cannot stat %s", corefile));

	if (flag != O_RDONLY)
		return (xkb_fail(xkb, "invalid open flags"));

	xkb = mdb_zalloc(sizeof (*xkb), UM_SLEEP);

	for (i = 0; i < 4; i++) {
		xkb->xkb_pt_map[i].mm_mfn = MFN_INVALID;
		xkb->xkb_pt_map[i].mm_map = (char *)MAP_FAILED;
	}

	xkb->xkb_type = XKB_FORMAT_UNKNOWN;
	xkb->xkb_map.mm_mfn = MFN_INVALID;
	xkb->xkb_map.mm_map = (char *)MAP_FAILED;
	xkb->xkb_core.xc_p2m_buf = (char *)MAP_FAILED;
	xkb->xkb_fd = -1;

	xkb->xkb_path = strdup(corefile);

	if ((xkb = xkb_open_elf(xkb)) == NULL)
		return (NULL);

	if (xkb->xkb_type == XKB_FORMAT_UNKNOWN) {
		if (!xkb_open_core(xkb))
			return (NULL);
	}

	xkb_init_mmu(xkb);

	if (!xkb_build_m2p(xkb))
		return (NULL);

	if (xkb->xkb_is_hvm)
		debug_info = DEBUG_INFO_HVM;

	if (xkb_read(xkb, debug_info, &xkb->xkb_info,
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
	size_t i, sz;

	if (xkb == NULL)
		return (0);

	if (xkb->xkb_m2p != NULL) {
		mdb_free(xkb->xkb_m2p,
		    (xkb->xkb_max_mfn + 1) * sizeof (xen_pfn_t));
	}

	if (xkb->xkb_pages != NULL) {
		(void) munmap((void *)xkb->xkb_pages,
		    PAGE_SIZE * xkb->xkb_nr_pages);
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

	if (xkb->xkb_namelist != NULL)
		mdb_free(xkb->xkb_namelist, xkb->xkb_namesize);

	if (xkb->xkb_type == XKB_FORMAT_ELF) {
		xkb_elf_t *xe = &xkb->xkb_elf;

		if (xe->xe_gelf != NULL)
			mdb_gelf_destroy(xe->xe_gelf);

		sz = sizeof (xen_pfn_t) * (xkb->xkb_max_pfn + 1);

		if (xkb->xkb_p2m != NULL)
			mdb_free(xkb->xkb_p2m, sz);

		sz = sizeof (size_t) * (xkb->xkb_max_pfn + 1);

		if (xe->xe_off != NULL)
			mdb_free(xe->xe_off, sz);

	} else if (xkb->xkb_type == XKB_FORMAT_CORE) {
		xkb_core_t *xc = &xkb->xkb_core;

		if (xkb->xkb_fd != -1)
			(void) close(xkb->xkb_fd);

		sz = (xkb->xkb_nr_pages * sizeof (mfn_t)) + (PAGE_SIZE * 2);
		sz = PAGE_MASK(sz);

		if (xc->xc_p2m_buf != (xen_pfn_t *)MAP_FAILED)
			(void) munmap(xc->xc_p2m_buf, sz);

		if (xkb->xkb_vcpu_data != NULL)
			mdb_free(xkb->xkb_vcpu_data, xkb->xkb_vcpu_data_sz);
	}

	if (xkb->xkb_vcpus != NULL) {
		sz = sizeof (struct vcpu_guest_context *) *
		    xkb->xkb_nr_vcpus;
		mdb_free(xkb->xkb_vcpus, sz);
	}

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
	mfn_t tlmfn = xkb_cr3_to_pfn(xkb);
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

	if (cpu >= xkb->xkb_nr_vcpus) {
		errno = EINVAL;
		return (-1);
	}

	bzero(mregs, sizeof (*mregs));

	vcpu = xkb->xkb_vcpus[cpu];
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
