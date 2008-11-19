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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains the functions for performing Fast Reboot -- a
 * reboot which bypasses the firmware and bootloader, considerably
 * reducing downtime.
 *
 * load_kernel(): This function is invoked by mdpreboot() in the reboot
 * path.  It loads the new kernel and boot archive into memory, builds
 * the data structure containing sufficient information about the new
 * kernel and boot archive to be passed to the fast reboot switcher
 * (see fb_swtch_src.s for details).  When invoked the switcher relocates
 * the new kernel and boot archive to physically contiguous low memory,
 * similar to where the boot loader would have loaded them, and jumps to
 * the new kernel.
 *
 * The physical addresses of the memory allocated for the new kernel, boot
 * archive and their page tables must be above where the boot archive ends
 * after it has been relocated by the switcher, otherwise the new files
 * and their page tables could be overridden during relocation.
 *
 * fast_reboot(): This function is invoked by mdboot() once it's determined
 * that the system is capable of fast reboot.  It jumps to the fast reboot
 * switcher with the data structure built by load_kernel() as the argument.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/segments.h>
#include <sys/sysmacros.h>
#include <sys/vm.h>

#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/kmem.h>

#include <sys/reboot.h>
#include <sys/uadmin.h>

#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/file.h>

#include <sys/cmn_err.h>
#include <sys/dumphdr.h>
#include <sys/bootconf.h>
#include <sys/ddidmareq.h>
#include <sys/varargs.h>
#include <sys/promif.h>
#include <sys/modctl.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/hat_i86.h>
#include <sys/vm_machparam.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/mman.h>
#include <sys/x86_archext.h>

#include <sys/fastboot.h>
#include <sys/machelf.h>
#include <sys/kobj.h>
#include <sys/multiboot.h>

/*
 * Data structure containing necessary information for the fast reboot
 * switcher to jump to the new kernel.
 */
fastboot_info_t newkernel = { 0 };

static char fastboot_filename[2][OBP_MAXPATHLEN] = { { 0 }, { 0 }};
static x86pte_t ptp_bits = PT_VALID | PT_REF | PT_USER | PT_WRITABLE;
static x86pte_t pte_bits =
    PT_VALID | PT_REF | PT_MOD | PT_NOCONSIST | PT_WRITABLE;
static uint_t fastboot_shift_amt_pae[] = {12, 21, 30, 39};

int fastboot_debug = 0;
int fastboot_contig = 0;

/*
 * Fake starting va for new kernel and boot archive.
 */
static uintptr_t fake_va = FASTBOOT_FAKE_VA;

/*
 * Below 1G for page tables as we are using 2G as the fake virtual address for
 * the new kernel and boot archive.
 */
static ddi_dma_attr_t fastboot_below_1G_dma_attr = {
	DMA_ATTR_V0,
	0x0000000008000000ULL,	/* dma_attr_addr_lo: 128MB */
	0x000000003FFFFFFFULL,	/* dma_attr_addr_hi: 1G */
	0x00000000FFFFFFFFULL,	/* dma_attr_count_max */
	0x0000000000001000ULL,	/* dma_attr_align: 4KB */
	1,			/* dma_attr_burstsize */
	1,			/* dma_attr_minxfer */
	0x00000000FFFFFFFFULL,	/* dma_attr_maxxfer */
	0x00000000FFFFFFFFULL,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	0x1000ULL,		/* dma_attr_granular */
	0,			/* dma_attr_flags */
};

static ddi_dma_attr_t fastboot_dma_attr = {
	DMA_ATTR_V0,
	0x0000000008000000ULL,	/* dma_attr_addr_lo: 128MB */
#ifdef	__amd64
	0xFFFFFFFFFFFFFFFFULL,	/* dma_attr_addr_hi: 2^64B */
#else
	0x0000000FFFFFFFFFULL,	/* dma_attr_addr_hi: 64GB */
#endif	/* __amd64 */
	0x00000000FFFFFFFFULL,	/* dma_attr_count_max */
	0x0000000000001000ULL,	/* dma_attr_align: 4KB */
	1,			/* dma_attr_burstsize */
	1,			/* dma_attr_minxfer */
	0x00000000FFFFFFFFULL,	/* dma_attr_maxxfer */
	0x00000000FFFFFFFFULL,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	0x1000ULL,		/* dma_attr_granular */
	0,			/* dma_attr_flags */
};

/*
 * Various information saved from the previous boot to reconstruct
 * multiboot_info.
 */
extern multiboot_info_t saved_mbi;
extern mb_memory_map_t saved_mmap[FASTBOOT_SAVED_MMAP_COUNT];
extern struct sol_netinfo saved_drives[FASTBOOT_SAVED_DRIVES_COUNT];
extern char saved_cmdline[FASTBOOT_SAVED_CMDLINE_LEN];
extern int saved_cmdline_len;

extern void* contig_alloc(size_t size, ddi_dma_attr_t *attr,
    uintptr_t align, int cansleep);
extern void contig_free(void *addr, size_t size);


/* PRINTLIKE */
extern void vprintf(const char *, va_list);


/*
 * Need to be able to get boot_archives from other places
 */
#define	BOOTARCHIVE64	"/platform/i86pc/amd64/boot_archive"
#define	BOOTARCHIVE32	"/platform/i86pc/boot_archive"
#define	BOOTARCHIVE_FAILSAFE	"/boot/x86.miniroot-safe"
#define	FAILSAFE_BOOTFILE	"/boot/platform/i86pc/kernel/unix"

static uint_t fastboot_vatoindex(fastboot_info_t *, uintptr_t, int);
static void fastboot_map_with_size(fastboot_info_t *, uintptr_t,
    paddr_t, size_t, int);
static void fastboot_build_pagetables(fastboot_info_t *);
static int fastboot_build_mbi(char *, fastboot_info_t *);

static const char fastboot_enomem_msg[] = "Fastboot: Couldn't allocate 0x%"
	PRIx64" bytes below %s to do fast reboot";

static void
dprintf(char *fmt, ...)
{
	va_list adx;

	if (!fastboot_debug)
		return;

	va_start(adx, fmt);
	vprintf(fmt, adx);
	va_end(adx);
}


/*
 * Return the index corresponding to a virt address at a given page table level.
 */
static uint_t
fastboot_vatoindex(fastboot_info_t *nk, uintptr_t va, int level)
{
	return ((va >> nk->fi_shift_amt[level]) & (nk->fi_ptes_per_table - 1));
}


/*
 * Add mapping from vstart to pstart for the specified size.
 * vstart, pstart and size should all have been aligned at 2M boundaries.
 */
static void
fastboot_map_with_size(fastboot_info_t *nk, uintptr_t vstart, paddr_t pstart,
    size_t size, int level)
{
	x86pte_t	pteval, *table;
	uintptr_t	vaddr;
	paddr_t		paddr;
	int		index, l;

	table = (x86pte_t *)(nk->fi_pagetable_va);

	for (l = nk->fi_top_level; l >= level; l--) {

		index = fastboot_vatoindex(nk, vstart, l);

		if (l == level) {
			/*
			 * Last level.  Program the page table entries.
			 */
			for (vaddr = vstart, paddr = pstart;
			    vaddr < vstart + size;
			    vaddr += (1ULL << nk->fi_shift_amt[l]),
			    paddr += (1ULL << nk->fi_shift_amt[l])) {

				uint_t index = fastboot_vatoindex(nk, vaddr, l);

				if (l > 0)
					pteval = paddr | pte_bits | PT_PAGESIZE;
				else
					pteval = paddr | pte_bits;

				table[index] = pteval;
			}
		} else if (table[index] & PT_VALID) {

			table = (x86pte_t *)
			    ((uintptr_t)(((paddr_t)table[index] & MMU_PAGEMASK)
			    - nk->fi_pagetable_pa) + nk->fi_pagetable_va);
		} else {
			/*
			 * Intermediate levels.
			 * Program with either valid bit or PTP bits.
			 */
			if (l == nk->fi_top_level) {
#ifdef	__amd64
				ASSERT(nk->fi_top_level == 3);
				table[index] = nk->fi_next_table_pa | ptp_bits;
#else
				table[index] = nk->fi_next_table_pa | PT_VALID;
#endif	/* __amd64 */
			} else {
				table[index] = nk->fi_next_table_pa | ptp_bits;
			}
			table = (x86pte_t *)(nk->fi_next_table_va);
			nk->fi_next_table_va += MMU_PAGESIZE;
			nk->fi_next_table_pa += MMU_PAGESIZE;
		}
	}
}

/*
 * Build page tables for the lower 1G of physical memory using 2M
 * pages, and prepare page tables for mapping new kernel and boot
 * archive pages using 4K pages.
 */
static void
fastboot_build_pagetables(fastboot_info_t *nk)
{
	/*
	 * Map lower 1G physical memory.  Use large pages.
	 */
	fastboot_map_with_size(nk, 0, 0, ONE_GIG, 1);

	/*
	 * Map one 4K page to get the middle page tables set up.
	 */
	fake_va = P2ALIGN_TYPED(fake_va, nk->fi_lpagesize, uintptr_t);
	fastboot_map_with_size(nk, fake_va,
	    nk->fi_files[0].fb_pte_list_va[0] & MMU_PAGEMASK, PAGESIZE, 0);
}


/*
 * Sanity check.  Look for dboot offset.
 */
static int
fastboot_elf64_find_dboot_load_offset(void *img, off_t imgsz, uint32_t *offp)
{
	Elf64_Ehdr	*ehdr = (Elf64_Ehdr *)img;
	Elf64_Phdr	*phdr;
	uint8_t		*phdrbase;
	int		i;

	if ((ehdr->e_phoff + ehdr->e_phnum * ehdr->e_phentsize) >= imgsz)
		return (-1);

	phdrbase = (uint8_t *)img + ehdr->e_phoff;

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = (Elf64_Phdr *)(phdrbase + ehdr->e_phentsize * i);

		if (phdr->p_type == PT_LOAD) {
			if (phdr->p_vaddr == phdr->p_paddr &&
			    phdr->p_vaddr == DBOOT_ENTRY_ADDRESS) {
				ASSERT(phdr->p_offset <= UINT32_MAX);
				*offp = (uint32_t)phdr->p_offset;
				return (0);
			}
		}
	}

	return (-1);
}


/*
 * Initialize text and data section information for 32-bit kernel.
 * sectcntp - is both input/output parameter.
 * On entry, *sectcntp contains maximum allowable number of sections;
 * on return, it contains the actual number of sections filled.
 */
static int
fastboot_elf32_find_loadables(void *img, off_t imgsz, fastboot_section_t *sectp,
    int *sectcntp, uint32_t *offp)
{
	Elf32_Ehdr	*ehdr = (Elf32_Ehdr *)img;
	Elf32_Phdr	*phdr;
	uint8_t		*phdrbase;
	int		i;
	int		used_sections = 0;
	const int	max_sectcnt = *sectcntp;

	if ((ehdr->e_phoff + ehdr->e_phnum * ehdr->e_phentsize) >= imgsz)
		return (-1);

	phdrbase = (uint8_t *)img + ehdr->e_phoff;

	for (i = 0; i < ehdr->e_phnum; i++) {
		phdr = (Elf32_Phdr *)(phdrbase + ehdr->e_phentsize * i);

		if (phdr->p_type == PT_INTERP)
			return (-1);

		if (phdr->p_type != PT_LOAD)
			continue;

		if (phdr->p_vaddr == phdr->p_paddr &&
		    phdr->p_paddr == DBOOT_ENTRY_ADDRESS) {
			*offp = (uint32_t)phdr->p_offset;
		} else {
			if (max_sectcnt <= used_sections)
				return (-1);

			sectp[used_sections].fb_sec_offset = phdr->p_offset;
			sectp[used_sections].fb_sec_paddr = phdr->p_paddr;
			sectp[used_sections].fb_sec_size = phdr->p_filesz;
			sectp[used_sections].fb_sec_bss_size =
			    (phdr->p_filesz < phdr->p_memsz) ?
			    (phdr->p_memsz - phdr->p_filesz) : 0;

			/* Extra sanity check for the input object file */
			if (sectp[used_sections].fb_sec_paddr +
			    sectp[used_sections].fb_sec_size +
			    sectp[used_sections].fb_sec_bss_size >=
			    DBOOT_ENTRY_ADDRESS)
				return (-1);

			used_sections++;
		}
	}

	*sectcntp = used_sections;
	return (0);
}

/*
 * Create multiboot info structure
 */
static int
fastboot_build_mbi(char *mdep, fastboot_info_t *nk)
{
	mb_module_t	*mbp;
	uintptr_t	next_addr;
	uintptr_t	new_mbi_pa;
	size_t		size;
	void		*buf = NULL;
	size_t		arglen;
	char		bootargs[OBP_MAXPATHLEN];

	bzero(bootargs, OBP_MAXPATHLEN);

	if (mdep != NULL && strlen(mdep) != 0) {
		arglen = strlen(mdep) + 1;
	} else {
		arglen = saved_cmdline_len;
	}

	size = PAGESIZE + P2ROUNDUP(arglen, PAGESIZE);
	buf = contig_alloc(size, &fastboot_below_1G_dma_attr, PAGESIZE, 0);
	if (buf == NULL) {
		cmn_err(CE_WARN, fastboot_enomem_msg, (uint64_t)size, "1G");
		return (-1);
	}

	bzero(buf, size);

	new_mbi_pa = mmu_ptob((uint64_t)hat_getpfnum(kas.a_hat, (caddr_t)buf));

	hat_devload(kas.a_hat, (caddr_t)new_mbi_pa, size,
	    mmu_btop(new_mbi_pa), PROT_READ | PROT_WRITE, HAT_LOAD_NOCONSIST);

	nk->fi_new_mbi_pa = (paddr_t)new_mbi_pa;

	bcopy(&saved_mbi, (void *)new_mbi_pa, sizeof (multiboot_info_t));

	next_addr = new_mbi_pa + sizeof (multiboot_info_t);
	((multiboot_info_t *)new_mbi_pa)->mods_addr = next_addr;
	mbp = (mb_module_t *)(uintptr_t)next_addr;
	mbp->mod_start = newkernel.fi_files[FASTBOOT_BOOTARCHIVE].fb_dest_pa;
	mbp->mod_end = newkernel.fi_files[FASTBOOT_BOOTARCHIVE].fb_next_pa;

	next_addr += sizeof (mb_module_t);
	bcopy(fastboot_filename[FASTBOOT_NAME_BOOTARCHIVE], (void *)next_addr,
	    strlen(fastboot_filename[FASTBOOT_NAME_BOOTARCHIVE]));

	mbp->mod_name = next_addr;
	mbp->reserved = 0;
	next_addr += strlen(fastboot_filename[FASTBOOT_NAME_BOOTARCHIVE]);
	*(char *)next_addr = '\0';
	next_addr++;
	next_addr = P2ROUNDUP_TYPED(next_addr, 16, uintptr_t);

	((multiboot_info_t *)new_mbi_pa)->mmap_addr = next_addr;
	bcopy((void *)(uintptr_t)saved_mmap, (void *)next_addr,
	    saved_mbi.mmap_length);
	next_addr += saved_mbi.mmap_length;

	((multiboot_info_t *)new_mbi_pa)->drives_addr = next_addr;
	bcopy((void *)(uintptr_t)saved_drives, (void *)next_addr,
	    saved_mbi.drives_length);
	next_addr += saved_mbi.drives_length;

	((multiboot_info_t *)new_mbi_pa)->cmdline = next_addr;

	if (mdep != NULL && strlen(mdep) != 0) {
		bcopy(mdep, (void *)(uintptr_t)
		    (((multiboot_info_t *)new_mbi_pa)->cmdline), (arglen - 1));
	} else {
		bcopy((void *)saved_cmdline, (void *)next_addr, (arglen - 1));
	}
	/* Terminate the string */
	((char *)(intptr_t)next_addr)[arglen - 1] = '\0';

	return (0);
}

/*
 * Initialize HAT related fields
 */
static void
fastboot_init_fields(fastboot_info_t *nk)
{
	if (x86_feature & X86_PAE) {
		nk->fi_has_pae = 1;
		nk->fi_shift_amt = fastboot_shift_amt_pae;
		nk->fi_ptes_per_table = 512;
		nk->fi_lpagesize = (2 << 20);	/* 2M */
#ifdef	__amd64
		nk->fi_top_level = 3;
#else
		nk->fi_top_level = 2;
#endif	/* __amd64 */
	}
}

/*
 * Process boot argument
 */
static void
fastboot_parse_mdep(char *mdep, char *kern_bootpath, int *bootpath_len,
    char *bootargs)
{
	int	i;

	/*
	 * If mdep is not NULL, it comes in the format of
	 *	mountpoint unix args
	 */
	if (mdep != NULL && strlen(mdep) != 0) {
		if (mdep[0] != '-') {
			/* First get the root argument */
			i = 0;
			while (mdep[i] != '\0' && mdep[i] != ' ') {
				i++;
			}

			if (i < 4 || strncmp(&mdep[i-4], "unix", 4) != 0) {
				/* mount point */
				bcopy(mdep, kern_bootpath, i);
				kern_bootpath[i] = '\0';
				*bootpath_len = i;

				/*
				 * Get the next argument. It should be unix as
				 * we have validated in in halt.c.
				 */
				if (strlen(mdep) > i) {
					mdep += (i + 1);
					i = 0;
					while (mdep[i] != '\0' &&
					    mdep[i] != ' ') {
						i++;
					}
				}

			}
			bcopy(mdep, kern_bootfile, i);
			kern_bootfile[i] = '\0';
			bcopy(mdep, bootargs, strlen(mdep));
		} else {
			int off = strlen(kern_bootfile);
			bcopy(kern_bootfile, bootargs, off);
			bcopy(" ", &bootargs[off++], 1);
			bcopy(mdep, &bootargs[off], strlen(mdep));
			off += strlen(mdep);
			bootargs[off] = '\0';
		}
	}
}

/*
 * Free up the memory we have allocated for this file
 */
static void
fastboot_free_file(fastboot_file_t *fb)
{
	size_t	fsize_roundup, pt_size;
	int	pt_entry_count;

	fsize_roundup = P2ROUNDUP_TYPED(fb->fb_size, PAGESIZE, size_t);
	contig_free((void *)fb->fb_va, fsize_roundup);

	pt_entry_count = (fsize_roundup >> PAGESHIFT) + 1;
	pt_size = P2ROUNDUP(pt_entry_count * 8, PAGESIZE);
	contig_free((void *)fb->fb_pte_list_va, pt_size);
}

/*
 * This function performs the following tasks:
 * - Read the sizes of the new kernel and boot archive.
 * - Allocate memory for the new kernel and boot archive.
 * - Allocate memory for page tables necessary for mapping the memory
 *   allocated for the files.
 * - Read the new kernel and boot archive into memory.
 * - Map in the fast reboot switcher.
 * - Load the fast reboot switcher to FASTBOOT_SWTCH_PA.
 * - Build the new multiboot_info structure
 * - Build page tables for the low 1G of physical memory.
 * - Mark the data structure as valid if all steps have succeeded.
 */
void
load_kernel(char *mdep)
{
	void		*buf = NULL;
	int		i;
	fastboot_file_t	*fb;
	uint32_t	dboot_start_offset;
	char		kern_bootpath[OBP_MAXPATHLEN];
	char		bootargs[OBP_MAXPATHLEN];
	extern uintptr_t postbootkernelbase;
	extern char	fb_swtch_image[];
	int		bootpath_len = 0;
	int		is_failsafe = 0;
	int		is_retry = 0;
	uint64_t	end_addr;

	ASSERT(fastreboot_capable);

	postbootkernelbase = 0;

	/*
	 * Initialize various HAT related fields in the data structure
	 */
	fastboot_init_fields(&newkernel);

	bzero(kern_bootpath, OBP_MAXPATHLEN);

	/*
	 * Process the boot argument
	 */
	bzero(bootargs, OBP_MAXPATHLEN);
	fastboot_parse_mdep(mdep, kern_bootpath, &bootpath_len, bootargs);

	/*
	 * Make sure we get the null character
	 */
	bcopy(kern_bootpath, fastboot_filename[FASTBOOT_NAME_UNIX],
	    bootpath_len);
	bcopy(kern_bootfile,
	    &fastboot_filename[FASTBOOT_NAME_UNIX][bootpath_len],
	    strlen(kern_bootfile) + 1);

	bcopy(kern_bootpath, fastboot_filename[FASTBOOT_NAME_BOOTARCHIVE],
	    bootpath_len);

	if (bcmp(kern_bootfile, FAILSAFE_BOOTFILE,
	    (sizeof (FAILSAFE_BOOTFILE) - 1)) == 0) {
		is_failsafe = 1;
	}

load_kernel_retry:
	/*
	 * Read in unix and boot_archive
	 */
	end_addr = DBOOT_ENTRY_ADDRESS;
	for (i = 0; i < FASTBOOT_MAX_FILES_MAP; i++) {
		struct _buf	*file;
		uintptr_t	va;
		uint64_t	fsize;
		size_t		fsize_roundup, pt_size;
		int		page_index;
		uintptr_t	offset;
		int		pt_entry_count;
		ddi_dma_attr_t dma_attr = fastboot_dma_attr;


		dprintf("fastboot_filename[%d] = %s\n",
		    i, fastboot_filename[i]);

		if ((file = kobj_open_file(fastboot_filename[i])) ==
		    (struct _buf *)-1) {
			cmn_err(CE_WARN, "Fastboot: Couldn't open %s",
			    fastboot_filename[i]);
			goto err_out;
		}

		if (kobj_get_filesize(file, &fsize) != 0) {
			cmn_err(CE_WARN,
			    "Fastboot: Couldn't get filesize for %s",
			    fastboot_filename[i]);
			goto err_out;
		}

		fsize_roundup = P2ROUNDUP_TYPED(fsize, PAGESIZE, size_t);

		/*
		 * Where the files end in physical memory after being
		 * relocated by the fast boot switcher.
		 */
		end_addr += fsize_roundup;
		if (end_addr > fastboot_below_1G_dma_attr.dma_attr_addr_hi) {
			cmn_err(CE_WARN, "Fastboot: boot archive is too big");
			goto err_out;
		}

		/*
		 * Adjust dma_attr_addr_lo so that the new kernel and boot
		 * archive will not be overridden during relocation.
		 */
		if (end_addr > fastboot_dma_attr.dma_attr_addr_lo ||
		    end_addr > fastboot_below_1G_dma_attr.dma_attr_addr_lo) {

			if (is_retry) {
				/*
				 * If we have already tried and didn't succeed,
				 * just give up.
				 */
				cmn_err(CE_WARN,
				    "Fastboot: boot archive is too big");
				goto err_out;
			} else {
				int j;

				/* Set the flag so we don't keep retrying */
				is_retry++;

				/* Adjust dma_attr_addr_lo */
				fastboot_dma_attr.dma_attr_addr_lo = end_addr;
				fastboot_below_1G_dma_attr.dma_attr_addr_lo =
				    end_addr;

				/*
				 * Free the memory we have already allocated
				 * whose physical addresses might not fit
				 * the new lo and hi constraints.
				 */
				for (j = 0; j < i; j++)
					fastboot_free_file(
					    &newkernel.fi_files[j]);
				goto load_kernel_retry;
			}
		}


		if (!fastboot_contig)
			dma_attr.dma_attr_sgllen = (fsize / PAGESIZE) +
			    (((fsize % PAGESIZE) == 0) ? 0 : 1);

		if ((buf = contig_alloc(fsize, &dma_attr, PAGESIZE, 0))
		    == NULL) {
			cmn_err(CE_WARN, fastboot_enomem_msg, fsize, "64G");
			goto err_out;
		}

		va = P2ROUNDUP_TYPED((uintptr_t)buf, PAGESIZE, uintptr_t);

		if (kobj_read_file(file, (char *)va, fsize, 0) < 0) {
			cmn_err(CE_WARN, "Fastboot: Couldn't read %s",
			    fastboot_filename[i]);
			goto err_out;
		}

		fb = &newkernel.fi_files[i];
		fb->fb_va = va;
		fb->fb_size = fsize;
		fb->fb_sectcnt = 0;

		/*
		 * Allocate one extra page table entry for terminating
		 * the list.
		 */
		pt_entry_count = (fsize_roundup >> PAGESHIFT) + 1;
		pt_size = P2ROUNDUP(pt_entry_count * 8, PAGESIZE);

		if ((fb->fb_pte_list_va =
		    (x86pte_t *)contig_alloc(pt_size,
		    &fastboot_below_1G_dma_attr, PAGESIZE, 0)) == NULL) {
			cmn_err(CE_WARN, fastboot_enomem_msg,
			    (uint64_t)pt_size, "1G");
			goto err_out;
		}

		bzero((void *)(fb->fb_pte_list_va), pt_size);

		fb->fb_pte_list_pa = mmu_ptob((uint64_t)hat_getpfnum(kas.a_hat,
		    (caddr_t)fb->fb_pte_list_va));

		for (page_index = 0, offset = 0; offset < fb->fb_size;
		    offset += PAGESIZE) {
			uint64_t paddr;

			paddr = mmu_ptob((uint64_t)hat_getpfnum(kas.a_hat,
			    (caddr_t)fb->fb_va + offset));

			ASSERT(paddr >= fastboot_dma_attr.dma_attr_addr_lo);

			/*
			 * Include the pte_bits so we don't have to make
			 * it in assembly.
			 */
			fb->fb_pte_list_va[page_index++] = (x86pte_t)
			    (paddr | pte_bits);
		}

		fb->fb_pte_list_va[page_index] = FASTBOOT_TERMINATE;

		if (i == FASTBOOT_UNIX) {
			Ehdr	*ehdr = (Ehdr *)va;
			int	j;

			/*
			 * Sanity checks:
			 */
			for (j = 0; j < SELFMAG; j++) {
				if (ehdr->e_ident[j] != ELFMAG[j]) {
					cmn_err(CE_WARN, "Fastboot: Bad ELF "
					    "signature");
					goto err_out;
				}
			}

			if (ehdr->e_ident[EI_CLASS] == ELFCLASS32 &&
			    ehdr->e_ident[EI_DATA] == ELFDATA2LSB &&
			    ehdr->e_machine == EM_386) {

				fb->fb_sectcnt = sizeof (fb->fb_sections) /
				    sizeof (fb->fb_sections[0]);

				if (fastboot_elf32_find_loadables((void *)va,
				    fsize, &fb->fb_sections[0],
				    &fb->fb_sectcnt, &dboot_start_offset) < 0) {
					cmn_err(CE_WARN, "Fastboot: ELF32 "
					    "program section failure");
					goto err_out;
				}

				if (fb->fb_sectcnt == 0) {
					cmn_err(CE_WARN, "Fastboot: No ELF32 "
					    "program sections found");
					goto err_out;
				}

				if (is_failsafe) {
					/* Failsafe boot_archive */
					bcopy(BOOTARCHIVE_FAILSAFE,
					    &fastboot_filename
					    [FASTBOOT_NAME_BOOTARCHIVE]
					    [bootpath_len],
					    sizeof (BOOTARCHIVE_FAILSAFE));
				} else {
					bcopy(BOOTARCHIVE32,
					    &fastboot_filename
					    [FASTBOOT_NAME_BOOTARCHIVE]
					    [bootpath_len],
					    sizeof (BOOTARCHIVE32));
				}

			} else if (ehdr->e_ident[EI_CLASS] == ELFCLASS64 &&
			    ehdr->e_ident[EI_DATA] == ELFDATA2LSB &&
			    ehdr->e_machine == EM_AMD64) {

				if (fastboot_elf64_find_dboot_load_offset(
				    (void *)va, fsize, &dboot_start_offset)
				    != 0) {
					cmn_err(CE_WARN, "Fastboot: Couldn't "
					    "find ELF64 dboot entry offset");
					goto err_out;
				}

				if ((x86_feature & X86_64) == 0 ||
				    (x86_feature & X86_PAE) == 0) {
					cmn_err(CE_WARN, "Fastboot: Cannot "
					    "reboot to %s: "
					    "not a 64-bit capable system",
					    kern_bootfile);
					goto err_out;
				}

				bcopy(BOOTARCHIVE64,
				    &fastboot_filename
				    [FASTBOOT_NAME_BOOTARCHIVE][bootpath_len],
				    sizeof (BOOTARCHIVE64));
			} else {
				cmn_err(CE_WARN, "Fastboot: Unknown ELF type");
				goto err_out;
			}

			fb->fb_dest_pa = DBOOT_ENTRY_ADDRESS -
			    dboot_start_offset;

			fb->fb_next_pa = DBOOT_ENTRY_ADDRESS + fsize_roundup;
		} else {
			fb->fb_dest_pa = newkernel.fi_files[i - 1].fb_next_pa;
			fb->fb_next_pa = fb->fb_dest_pa + fsize_roundup;
		}

		kobj_close_file(file);

	}

	/*
	 * Set fb_va to fake_va
	 */
	for (i = 0; i < FASTBOOT_MAX_FILES_MAP; i++) {
		newkernel.fi_files[i].fb_va = fake_va;

	}

	/*
	 * Add the function that will switch us to 32-bit protected mode
	 */
	fb = &newkernel.fi_files[FASTBOOT_SWTCH];
	fb->fb_va = fb->fb_dest_pa = FASTBOOT_SWTCH_PA;
	fb->fb_size = MMU_PAGESIZE;

	/*
	 * Map in FASTBOOT_SWTCH_PA
	 */
	hat_devload(kas.a_hat, (caddr_t)fb->fb_va, MMU_PAGESIZE,
	    mmu_btop(fb->fb_dest_pa),
	    PROT_READ | PROT_WRITE | PROT_EXEC, HAT_LOAD_NOCONSIST);

	bcopy((void *)fb_swtch_image, (void *)fb->fb_va, fb->fb_size);

	/*
	 * Build the new multiboot_info structure
	 */
	if (fastboot_build_mbi(bootargs, &newkernel) != 0) {
		goto err_out;
	}

	/*
	 * Build page table for low 1G physical memory. Use big pages.
	 * Allocate 4 (5 for amd64) pages for the page tables.
	 *    1 page for PML4 (amd64)
	 *    1 page for Page-Directory-Pointer Table
	 *    2 pages for Page Directory
	 *    1 page for Page Table.
	 * The page table entry will be rewritten to map the physical
	 * address as we do the copying.
	 */
	if (newkernel.fi_has_pae) {
#ifdef	__amd64
		size_t size = MMU_PAGESIZE * 5;
#else
		size_t size = MMU_PAGESIZE * 4;
#endif	/* __amd64 */

		if ((newkernel.fi_pagetable_va = (uintptr_t)
		    contig_alloc(size, &fastboot_below_1G_dma_attr,
		    MMU_PAGESIZE, 0)) == NULL) {
			cmn_err(CE_WARN, fastboot_enomem_msg,
			    (uint64_t)size, "1G");
			goto err_out;
		}

		bzero((void *)(newkernel.fi_pagetable_va), size);

		newkernel.fi_pagetable_pa =
		    mmu_ptob((uint64_t)hat_getpfnum(kas.a_hat,
		    (caddr_t)newkernel.fi_pagetable_va));

		newkernel.fi_last_table_pa = newkernel.fi_pagetable_pa +
		    size - MMU_PAGESIZE;

		newkernel.fi_next_table_va = newkernel.fi_pagetable_va +
		    MMU_PAGESIZE;
		newkernel.fi_next_table_pa = newkernel.fi_pagetable_pa +
		    MMU_PAGESIZE;

		fastboot_build_pagetables(&newkernel);
	}


	/* Mark it as valid */
	newkernel.fi_valid = 1;
	newkernel.fi_magic = FASTBOOT_MAGIC;

	return;

err_out:
	newkernel.fi_valid = 0;
}

/*
 * Jump to the fast reboot switcher.  This function never returns.
 */
void
fast_reboot()
{
	void (*fastboot_func)(fastboot_info_t *);

	fastboot_func = (void (*)())(newkernel.fi_files[FASTBOOT_SWTCH].fb_va);
	(*fastboot_func)(&newkernel);
}
