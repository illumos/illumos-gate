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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains the functions for performing Fast Reboot -- a
 * reboot which bypasses the firmware and bootloader, considerably
 * reducing downtime.
 *
 * fastboot_load_kernel(): This function is invoked by mdpreboot() in the
 * reboot path.  It loads the new kernel and boot archive into memory, builds
 * the data structure containing sufficient information about the new
 * kernel and boot archive to be passed to the fast reboot switcher
 * (see fb_swtch_src.s for details).  When invoked the switcher relocates
 * the new kernel and boot archive to physically contiguous low memory,
 * similar to where the boot loader would have loaded them, and jumps to
 * the new kernel.
 *
 * If fastreboot_onpanic is enabled, fastboot_load_kernel() is called
 * by fastreboot_post_startup() to load the back up kernel in case of
 * panic.
 *
 * The physical addresses of the memory allocated for the new kernel, boot
 * archive and their page tables must be above where the boot archive ends
 * after it has been relocated by the switcher, otherwise the new files
 * and their page tables could be overridden during relocation.
 *
 * fast_reboot(): This function is invoked by mdboot() once it's determined
 * that the system is capable of fast reboot.  It jumps to the fast reboot
 * switcher with the data structure built by fastboot_load_kernel() as the
 * argument.
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
#include <sys/smp_impldefs.h>
#include <sys/spl.h>

#include <sys/fastboot_impl.h>
#include <sys/machelf.h>
#include <sys/kobj.h>
#include <sys/multiboot.h>
#include <sys/kobj_lex.h>

/*
 * Macro to determine how many pages are needed for PTEs to map a particular
 * file.  Allocate one extra page table entry for terminating the list.
 */
#define	FASTBOOT_PTE_LIST_SIZE(fsize)	\
	P2ROUNDUP((((fsize) >> PAGESHIFT) + 1) * sizeof (x86pte_t), PAGESIZE)

/*
 * Data structure containing necessary information for the fast reboot
 * switcher to jump to the new kernel.
 */
fastboot_info_t newkernel = { 0 };
char		fastboot_args[OBP_MAXPATHLEN];

static char fastboot_filename[2][OBP_MAXPATHLEN] = { { 0 }, { 0 }};
static x86pte_t ptp_bits = PT_VALID | PT_REF | PT_USER | PT_WRITABLE;
static x86pte_t pte_bits =
    PT_VALID | PT_REF | PT_MOD | PT_NOCONSIST | PT_WRITABLE;
static uint_t fastboot_shift_amt_pae[] = {12, 21, 30, 39};

/* Index into Fast Reboot not supported message array */
static uint32_t fastreboot_nosup_id = FBNS_DEFAULT;

/* Fast Reboot not supported message array */
static const char * const fastreboot_nosup_desc[FBNS_END] = {
#define	fastboot_nosup_msg(id, str)	str,
#include <sys/fastboot_msg.h>
};

int fastboot_debug = 0;
int fastboot_contig = 0;

/*
 * Fake starting va for new kernel and boot archive.
 */
static uintptr_t fake_va = FASTBOOT_FAKE_VA;

/*
 * Reserve memory below PA 1G in preparation of fast reboot.
 *
 * This variable is only checked when fastreboot_capable is set, but
 * fastreboot_onpanic is not set.  The amount of memory reserved
 * is negligible, but just in case we are really short of low memory,
 * this variable will give us a backdoor to not consume memory at all.
 */
int reserve_mem_enabled = 1;

/*
 * Mutex to protect fastreboot_onpanic.
 */
kmutex_t fastreboot_config_mutex;

/*
 * Amount of memory below PA 1G to reserve for constructing the multiboot
 * data structure and the page tables as we tend to run out of those
 * when more drivers are loaded.
 */
static size_t fastboot_mbi_size = 0x2000;	/* 8K */
static size_t fastboot_pagetable_size = 0x5000;	/* 20K */

/*
 * Minimum system uptime in clock_t before Fast Reboot should be used
 * on panic.  Will be initialized in fastboot_post_startup().
 */
clock_t fastreboot_onpanic_uptime = LONG_MAX;

/*
 * lbolt value when the system booted.  This value will be used if the system
 * panics to calculate how long the system has been up.  If the uptime is less
 * than fastreboot_onpanic_uptime, a reboot through BIOS will be performed to
 * avoid a potential panic/reboot loop.
 */
clock_t lbolt_at_boot = LONG_MAX;

/*
 * Use below 1G for page tables as
 *	1. we are only doing 1:1 mapping of the bottom 1G of physical memory.
 *	2. we are using 2G as the fake virtual address for the new kernel and
 *	boot archive.
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
extern uint8_t saved_drives[FASTBOOT_SAVED_DRIVES_SIZE];
extern char saved_cmdline[FASTBOOT_SAVED_CMDLINE_LEN];
extern int saved_cmdline_len;
extern size_t saved_file_size[];

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
#define	BOOTARCHIVE32_FAILSAFE	"/boot/x86.miniroot-safe"
#define	BOOTARCHIVE64_FAILSAFE	"/boot/amd64/x86.miniroot-safe"
#define	FAILSAFE_BOOTFILE32	"/boot/platform/i86pc/kernel/unix"
#define	FAILSAFE_BOOTFILE64	"/boot/platform/i86pc/kernel/amd64/unix"

static uint_t fastboot_vatoindex(fastboot_info_t *, uintptr_t, int);
static void fastboot_map_with_size(fastboot_info_t *, uintptr_t,
    paddr_t, size_t, int);
static void fastboot_build_pagetables(fastboot_info_t *);
static int fastboot_build_mbi(char *, fastboot_info_t *);
static void fastboot_free_file(fastboot_file_t *);

static const char fastboot_enomem_msg[] = "!Fastboot: Couldn't allocate 0x%"
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
 * Create multiboot info structure (mbi) base on the saved mbi.
 * Recalculate values of the pointer type fields in the data
 * structure based on the new starting physical address of the
 * data structure.
 */
static int
fastboot_build_mbi(char *mdep, fastboot_info_t *nk)
{
	mb_module_t	*mbp;
	multiboot_info_t	*mbi;	/* pointer to multiboot structure */
	uintptr_t	start_addr_va;	/* starting VA of mbi */
	uintptr_t	start_addr_pa;	/* starting PA of mbi */
	size_t		offs = 0;	/* offset from the starting address */
	size_t		arglen;		/* length of the command line arg */
	size_t		size;	/* size of the memory reserved for mbi */
	size_t		mdnsz;	/* length of the boot archive name */

	/*
	 * If mdep is not NULL or empty, use the length of mdep + 1
	 * (for NULL terminating) as the length of the new command
	 * line; else use the saved command line length as the
	 * length for the new command line.
	 */
	if (mdep != NULL && strlen(mdep) != 0) {
		arglen = strlen(mdep) + 1;
	} else {
		arglen = saved_cmdline_len;
	}

	/*
	 * Allocate memory for the new multiboot info structure (mbi).
	 * If we have reserved memory for mbi but it's not enough,
	 * free it and reallocate.
	 */
	size = PAGESIZE + P2ROUNDUP(arglen, PAGESIZE);
	if (nk->fi_mbi_size && nk->fi_mbi_size < size) {
		contig_free((void *)nk->fi_new_mbi_va, nk->fi_mbi_size);
		nk->fi_mbi_size = 0;
	}

	if (nk->fi_mbi_size == 0) {
		if ((nk->fi_new_mbi_va =
		    (uintptr_t)contig_alloc(size, &fastboot_below_1G_dma_attr,
		    PAGESIZE, 0)) == NULL) {
			cmn_err(CE_NOTE, fastboot_enomem_msg,
			    (uint64_t)size, "1G");
			return (-1);
		}
		/*
		 * fi_mbi_size must be set after the allocation succeeds
		 * as it's used to determine how much memory to free.
		 */
		nk->fi_mbi_size = size;
	}

	/*
	 * Initalize memory
	 */
	bzero((void *)nk->fi_new_mbi_va, nk->fi_mbi_size);

	/*
	 * Get PA for the new mbi
	 */
	start_addr_va = nk->fi_new_mbi_va;
	start_addr_pa = mmu_ptob((uint64_t)hat_getpfnum(kas.a_hat,
	    (caddr_t)start_addr_va));
	nk->fi_new_mbi_pa = (paddr_t)start_addr_pa;

	/*
	 * Populate the rest of the fields in the data structure
	 */

	/*
	 * Copy from the saved mbi to preserve all non-pointer type fields.
	 */
	mbi = (multiboot_info_t *)start_addr_va;
	bcopy(&saved_mbi, mbi, sizeof (*mbi));

	/*
	 * Recalculate mods_addr.  Set mod_start and mod_end based on
	 * the physical address of the new boot archive.  Set mod_name
	 * to the name of the new boto archive.
	 */
	offs += sizeof (multiboot_info_t);
	mbi->mods_addr = start_addr_pa + offs;
	mbp = (mb_module_t *)(start_addr_va + offs);
	mbp->mod_start = nk->fi_files[FASTBOOT_BOOTARCHIVE].fb_dest_pa;
	mbp->mod_end = nk->fi_files[FASTBOOT_BOOTARCHIVE].fb_next_pa;

	offs += sizeof (mb_module_t);
	mdnsz = strlen(fastboot_filename[FASTBOOT_NAME_BOOTARCHIVE]) + 1;
	bcopy(fastboot_filename[FASTBOOT_NAME_BOOTARCHIVE],
	    (void *)(start_addr_va + offs), mdnsz);
	mbp->mod_name = start_addr_pa + offs;
	mbp->reserved = 0;

	/*
	 * Make sure the offset is 16-byte aligned to avoid unaligned access.
	 */
	offs += mdnsz;
	offs = P2ROUNDUP_TYPED(offs, 16, size_t);

	/*
	 * Recalculate mmap_addr
	 */
	mbi->mmap_addr = start_addr_pa + offs;
	bcopy((void *)(uintptr_t)saved_mmap, (void *)(start_addr_va + offs),
	    saved_mbi.mmap_length);
	offs += saved_mbi.mmap_length;

	/*
	 * Recalculate drives_addr
	 */
	mbi->drives_addr = start_addr_pa + offs;
	bcopy((void *)(uintptr_t)saved_drives, (void *)(start_addr_va + offs),
	    saved_mbi.drives_length);
	offs += saved_mbi.drives_length;

	/*
	 * Recalculate the address of cmdline.  Set cmdline to contain the
	 * new boot argument.
	 */
	mbi->cmdline = start_addr_pa + offs;

	if (mdep != NULL && strlen(mdep) != 0) {
		bcopy(mdep, (void *)(start_addr_va + offs), arglen);
	} else {
		bcopy((void *)saved_cmdline, (void *)(start_addr_va + offs),
		    arglen);
	}

	/* clear fields and flags that are not copied */
	bzero(&mbi->config_table,
	    sizeof (*mbi) - offsetof(multiboot_info_t, config_table));
	mbi->flags &= ~(MB_INFO_CONFIG_TABLE | MB_INFO_BOOT_LOADER_NAME |
	    MB_INFO_APM_TABLE | MB_INFO_VIDEO_INFO);

	return (0);
}

/*
 * Initialize HAT related fields
 */
static void
fastboot_init_fields(fastboot_info_t *nk)
{
	if (is_x86_feature(x86_featureset, X86FSET_PAE)) {
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
 * Reserve memory under PA 1G for mapping the new kernel and boot archive.
 * This function is only called if fastreboot_onpanic is *not* set.
 */
static void
fastboot_reserve_mem(fastboot_info_t *nk)
{
	int i;

	/*
	 * A valid kernel is in place.  No need to reserve any memory.
	 */
	if (nk->fi_valid)
		return;

	/*
	 * Reserve memory under PA 1G for PTE lists.
	 */
	for (i = 0; i < FASTBOOT_MAX_FILES_MAP; i++) {
		fastboot_file_t *fb = &nk->fi_files[i];
		size_t fsize_roundup, size;

		fsize_roundup = P2ROUNDUP_TYPED(saved_file_size[i],
		    PAGESIZE, size_t);
		size = FASTBOOT_PTE_LIST_SIZE(fsize_roundup);
		if ((fb->fb_pte_list_va = contig_alloc(size,
		    &fastboot_below_1G_dma_attr, PAGESIZE, 0)) == NULL) {
			return;
		}
		fb->fb_pte_list_size = size;
	}

	/*
	 * Reserve memory under PA 1G for page tables.
	 */
	if ((nk->fi_pagetable_va =
	    (uintptr_t)contig_alloc(fastboot_pagetable_size,
	    &fastboot_below_1G_dma_attr, PAGESIZE, 0)) == NULL) {
		return;
	}
	nk->fi_pagetable_size = fastboot_pagetable_size;

	/*
	 * Reserve memory under PA 1G for multiboot structure.
	 */
	if ((nk->fi_new_mbi_va = (uintptr_t)contig_alloc(fastboot_mbi_size,
	    &fastboot_below_1G_dma_attr, PAGESIZE, 0)) == NULL) {
		return;
	}
	nk->fi_mbi_size = fastboot_mbi_size;
}

/*
 * Calculate MD5 digest for the given fastboot_file.
 * Assumes that the file is allready loaded properly.
 */
static void
fastboot_cksum_file(fastboot_file_t *fb, uchar_t *md5_hash)
{
	MD5_CTX md5_ctx;

	MD5Init(&md5_ctx);
	MD5Update(&md5_ctx, (void *)fb->fb_va, fb->fb_size);
	MD5Final(md5_hash, &md5_ctx);
}

/*
 * Free up the memory we have allocated for a file
 */
static void
fastboot_free_file(fastboot_file_t *fb)
{
	size_t	fsize_roundup;

	fsize_roundup = P2ROUNDUP_TYPED(fb->fb_size, PAGESIZE, size_t);
	if (fsize_roundup) {
		contig_free((void *)fb->fb_va, fsize_roundup);
		fb->fb_va = NULL;
		fb->fb_size = 0;
	}
}

/*
 * Free up memory used by the PTEs for a file.
 */
static void
fastboot_free_file_pte(fastboot_file_t *fb, uint64_t endaddr)
{
	if (fb->fb_pte_list_size && fb->fb_pte_list_pa < endaddr) {
		contig_free((void *)fb->fb_pte_list_va, fb->fb_pte_list_size);
		fb->fb_pte_list_va = 0;
		fb->fb_pte_list_pa = 0;
		fb->fb_pte_list_size = 0;
	}
}

/*
 * Free up all the memory used for representing a kernel with
 * fastboot_info_t.
 */
static void
fastboot_free_mem(fastboot_info_t *nk, uint64_t endaddr)
{
	int i;

	for (i = 0; i < FASTBOOT_MAX_FILES_MAP; i++) {
		fastboot_free_file(nk->fi_files + i);
		fastboot_free_file_pte(nk->fi_files + i, endaddr);
	}

	if (nk->fi_pagetable_size && nk->fi_pagetable_pa < endaddr) {
		contig_free((void *)nk->fi_pagetable_va, nk->fi_pagetable_size);
		nk->fi_pagetable_va = 0;
		nk->fi_pagetable_pa = 0;
		nk->fi_pagetable_size = 0;
	}

	if (nk->fi_mbi_size && nk->fi_new_mbi_pa < endaddr) {
		contig_free((void *)nk->fi_new_mbi_va, nk->fi_mbi_size);
		nk->fi_new_mbi_va = 0;
		nk->fi_new_mbi_pa = 0;
		nk->fi_mbi_size = 0;
	}
}

/*
 * Only free up the memory allocated for the kernel and boot archive,
 * but not for the page tables.
 */
void
fastboot_free_newkernel(fastboot_info_t *nk)
{
	int i;

	nk->fi_valid = 0;
	/*
	 * Free the memory we have allocated
	 */
	for (i = 0; i < FASTBOOT_MAX_FILES_MAP; i++) {
		fastboot_free_file(&(nk->fi_files[i]));
	}
}

static void
fastboot_cksum_cdata(fastboot_info_t *nk, uchar_t *md5_hash)
{
	int i;
	MD5_CTX md5_ctx;

	MD5Init(&md5_ctx);
	for (i = 0; i < FASTBOOT_MAX_FILES_MAP; i++) {
		MD5Update(&md5_ctx, nk->fi_files[i].fb_pte_list_va,
		    nk->fi_files[i].fb_pte_list_size);
	}
	MD5Update(&md5_ctx, (void *)nk->fi_pagetable_va, nk->fi_pagetable_size);
	MD5Update(&md5_ctx, (void *)nk->fi_new_mbi_va, nk->fi_mbi_size);

	MD5Final(md5_hash, &md5_ctx);
}

/*
 * Generate MD5 checksum of the given kernel.
 */
static void
fastboot_cksum_generate(fastboot_info_t *nk)
{
	int i;

	for (i = 0; i < FASTBOOT_MAX_FILES_MAP; i++) {
		fastboot_cksum_file(nk->fi_files + i, nk->fi_md5_hash[i]);
	}
	fastboot_cksum_cdata(nk, nk->fi_md5_hash[i]);
}

/*
 * Calculate MD5 checksum of the given kernel and verify that
 * it matches with what was calculated before.
 */
int
fastboot_cksum_verify(fastboot_info_t *nk)
{
	int i;
	uchar_t md5_hash[MD5_DIGEST_LENGTH];

	for (i = 0; i < FASTBOOT_MAX_FILES_MAP; i++) {
		fastboot_cksum_file(nk->fi_files + i, md5_hash);
		if (bcmp(nk->fi_md5_hash[i], md5_hash,
		    sizeof (nk->fi_md5_hash[i])) != 0)
			return (i + 1);
	}

	fastboot_cksum_cdata(nk, md5_hash);
	if (bcmp(nk->fi_md5_hash[i], md5_hash,
	    sizeof (nk->fi_md5_hash[i])) != 0)
		return (i + 1);

	return (0);
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
fastboot_load_kernel(char *mdep)
{
	void		*buf = NULL;
	int		i;
	fastboot_file_t	*fb;
	uint32_t	dboot_start_offset;
	char		kern_bootpath[OBP_MAXPATHLEN];
	extern uintptr_t postbootkernelbase;
	uintptr_t	saved_kernelbase;
	int		bootpath_len = 0;
	int		is_failsafe = 0;
	int		is_retry = 0;
	uint64_t	end_addr;

	if (!fastreboot_capable)
		return;

	if (newkernel.fi_valid)
		fastboot_free_newkernel(&newkernel);

	saved_kernelbase = postbootkernelbase;

	postbootkernelbase = 0;

	/*
	 * Initialize various HAT related fields in the data structure
	 */
	fastboot_init_fields(&newkernel);

	bzero(kern_bootpath, OBP_MAXPATHLEN);

	/*
	 * Process the boot argument
	 */
	bzero(fastboot_args, OBP_MAXPATHLEN);
	fastboot_parse_mdep(mdep, kern_bootpath, &bootpath_len, fastboot_args);

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

	if (bcmp(kern_bootfile, FAILSAFE_BOOTFILE32,
	    (sizeof (FAILSAFE_BOOTFILE32) - 1)) == 0 ||
	    bcmp(kern_bootfile, FAILSAFE_BOOTFILE64,
	    (sizeof (FAILSAFE_BOOTFILE64) - 1)) == 0) {
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
		ddi_dma_attr_t dma_attr = fastboot_dma_attr;


		dprintf("fastboot_filename[%d] = %s\n",
		    i, fastboot_filename[i]);

		if ((file = kobj_open_file(fastboot_filename[i])) ==
		    (struct _buf *)-1) {
			cmn_err(CE_NOTE, "!Fastboot: Couldn't open %s",
			    fastboot_filename[i]);
			goto err_out;
		}

		if (kobj_get_filesize(file, &fsize) != 0) {
			cmn_err(CE_NOTE,
			    "!Fastboot: Couldn't get filesize for %s",
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
			cmn_err(CE_NOTE, "!Fastboot: boot archive is too big");
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
				cmn_err(CE_NOTE,
				    "!Fastboot: boot archive is too big");
				goto err_out;
			} else {
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
				fastboot_free_mem(&newkernel, end_addr);
				goto load_kernel_retry;
			}
		}


		if (!fastboot_contig)
			dma_attr.dma_attr_sgllen = (fsize / PAGESIZE) +
			    (((fsize % PAGESIZE) == 0) ? 0 : 1);

		if ((buf = contig_alloc(fsize, &dma_attr, PAGESIZE, 0))
		    == NULL) {
			cmn_err(CE_NOTE, fastboot_enomem_msg, fsize, "64G");
			goto err_out;
		}

		va = P2ROUNDUP_TYPED((uintptr_t)buf, PAGESIZE, uintptr_t);

		if (kobj_read_file(file, (char *)va, fsize, 0) < 0) {
			cmn_err(CE_NOTE, "!Fastboot: Couldn't read %s",
			    fastboot_filename[i]);
			goto err_out;
		}

		fb = &newkernel.fi_files[i];
		fb->fb_va = va;
		fb->fb_size = fsize;
		fb->fb_sectcnt = 0;

		pt_size = FASTBOOT_PTE_LIST_SIZE(fsize_roundup);

		/*
		 * If we have reserved memory but it not enough, free it.
		 */
		if (fb->fb_pte_list_size && fb->fb_pte_list_size < pt_size) {
			contig_free((void *)fb->fb_pte_list_va,
			    fb->fb_pte_list_size);
			fb->fb_pte_list_size = 0;
		}

		if (fb->fb_pte_list_size == 0) {
			if ((fb->fb_pte_list_va =
			    (x86pte_t *)contig_alloc(pt_size,
			    &fastboot_below_1G_dma_attr, PAGESIZE, 0))
			    == NULL) {
				cmn_err(CE_NOTE, fastboot_enomem_msg,
				    (uint64_t)pt_size, "1G");
				goto err_out;
			}
			/*
			 * fb_pte_list_size must be set after the allocation
			 * succeeds as it's used to determine how much memory to
			 * free.
			 */
			fb->fb_pte_list_size = pt_size;
		}

		bzero((void *)(fb->fb_pte_list_va), fb->fb_pte_list_size);

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
					cmn_err(CE_NOTE, "!Fastboot: Bad ELF "
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
					cmn_err(CE_NOTE, "!Fastboot: ELF32 "
					    "program section failure");
					goto err_out;
				}

				if (fb->fb_sectcnt == 0) {
					cmn_err(CE_NOTE, "!Fastboot: No ELF32 "
					    "program sections found");
					goto err_out;
				}

				if (is_failsafe) {
					/* Failsafe boot_archive */
					bcopy(BOOTARCHIVE32_FAILSAFE,
					    &fastboot_filename
					    [FASTBOOT_NAME_BOOTARCHIVE]
					    [bootpath_len],
					    sizeof (BOOTARCHIVE32_FAILSAFE));
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
					cmn_err(CE_NOTE, "!Fastboot: Couldn't "
					    "find ELF64 dboot entry offset");
					goto err_out;
				}

				if (!is_x86_feature(x86_featureset,
				    X86FSET_64) ||
				    !is_x86_feature(x86_featureset,
				    X86FSET_PAE)) {
					cmn_err(CE_NOTE, "Fastboot: Cannot "
					    "reboot to %s: "
					    "not a 64-bit capable system",
					    kern_bootfile);
					goto err_out;
				}

				if (is_failsafe) {
					/* Failsafe boot_archive */
					bcopy(BOOTARCHIVE64_FAILSAFE,
					    &fastboot_filename
					    [FASTBOOT_NAME_BOOTARCHIVE]
					    [bootpath_len],
					    sizeof (BOOTARCHIVE64_FAILSAFE));
				} else {
					bcopy(BOOTARCHIVE64,
					    &fastboot_filename
					    [FASTBOOT_NAME_BOOTARCHIVE]
					    [bootpath_len],
					    sizeof (BOOTARCHIVE64));
				}
			} else {
				cmn_err(CE_NOTE, "!Fastboot: Unknown ELF type");
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
	 * Add the function that will switch us to 32-bit protected mode
	 */
	fb = &newkernel.fi_files[FASTBOOT_SWTCH];
	fb->fb_va = fb->fb_dest_pa = FASTBOOT_SWTCH_PA;
	fb->fb_size = MMU_PAGESIZE;

	hat_devload(kas.a_hat, (caddr_t)fb->fb_va,
	    MMU_PAGESIZE, mmu_btop(fb->fb_dest_pa),
	    PROT_READ | PROT_WRITE | PROT_EXEC,
	    HAT_LOAD_NOCONSIST | HAT_LOAD_LOCK);

	/*
	 * Build the new multiboot_info structure
	 */
	if (fastboot_build_mbi(fastboot_args, &newkernel) != 0) {
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

		if (newkernel.fi_pagetable_size && newkernel.fi_pagetable_size
		    < size) {
			contig_free((void *)newkernel.fi_pagetable_va,
			    newkernel.fi_pagetable_size);
			newkernel.fi_pagetable_size = 0;
		}

		if (newkernel.fi_pagetable_size == 0) {
			if ((newkernel.fi_pagetable_va = (uintptr_t)
			    contig_alloc(size, &fastboot_below_1G_dma_attr,
			    MMU_PAGESIZE, 0)) == NULL) {
				cmn_err(CE_NOTE, fastboot_enomem_msg,
				    (uint64_t)size, "1G");
				goto err_out;
			}
			/*
			 * fi_pagetable_size must be set after the allocation
			 * succeeds as it's used to determine how much memory to
			 * free.
			 */
			newkernel.fi_pagetable_size = size;
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


	/* Generate MD5 checksums */
	fastboot_cksum_generate(&newkernel);

	/* Mark it as valid */
	newkernel.fi_valid = 1;
	newkernel.fi_magic = FASTBOOT_MAGIC;

	postbootkernelbase = saved_kernelbase;
	return;

err_out:
	postbootkernelbase = saved_kernelbase;
	newkernel.fi_valid = 0;
	fastboot_free_newkernel(&newkernel);
}


/* ARGSUSED */
static int
fastboot_xc_func(fastboot_info_t *nk, xc_arg_t unused2, xc_arg_t unused3)
{
	void (*fastboot_func)(fastboot_info_t *);
	fastboot_file_t	*fb = &nk->fi_files[FASTBOOT_SWTCH];
	fastboot_func = (void (*)())(fb->fb_va);
	kthread_t *t_intr = curthread->t_intr;

	if (&kas != curproc->p_as) {
		hat_devload(curproc->p_as->a_hat, (caddr_t)fb->fb_va,
		    MMU_PAGESIZE, mmu_btop(fb->fb_dest_pa),
		    PROT_READ | PROT_WRITE | PROT_EXEC,
		    HAT_LOAD_NOCONSIST | HAT_LOAD_LOCK);
	}

	/*
	 * If we have pinned a thread, make sure the address is mapped
	 * in the address space of the pinned thread.
	 */
	if (t_intr && t_intr->t_procp->p_as->a_hat != curproc->p_as->a_hat &&
	    t_intr->t_procp->p_as != &kas)
		hat_devload(t_intr->t_procp->p_as->a_hat, (caddr_t)fb->fb_va,
		    MMU_PAGESIZE, mmu_btop(fb->fb_dest_pa),
		    PROT_READ | PROT_WRITE | PROT_EXEC,
		    HAT_LOAD_NOCONSIST | HAT_LOAD_LOCK);

	(*psm_shutdownf)(A_SHUTDOWN, AD_FASTREBOOT);
	(*fastboot_func)(nk);

	/*NOTREACHED*/
	return (0);
}

/*
 * Jump to the fast reboot switcher.  This function never returns.
 */
void
fast_reboot()
{
	processorid_t bootcpuid = 0;
	extern uintptr_t postbootkernelbase;
	extern char	fb_swtch_image[];
	fastboot_file_t	*fb;
	int i;

	postbootkernelbase = 0;

	fb = &newkernel.fi_files[FASTBOOT_SWTCH];

	/*
	 * Map the address into both the current proc's address
	 * space and the kernel's address space in case the panic
	 * is forced by kmdb.
	 */
	if (&kas != curproc->p_as) {
		hat_devload(curproc->p_as->a_hat, (caddr_t)fb->fb_va,
		    MMU_PAGESIZE, mmu_btop(fb->fb_dest_pa),
		    PROT_READ | PROT_WRITE | PROT_EXEC,
		    HAT_LOAD_NOCONSIST | HAT_LOAD_LOCK);
	}

	bcopy((void *)fb_swtch_image, (void *)fb->fb_va, fb->fb_size);


	/*
	 * Set fb_va to fake_va
	 */
	for (i = 0; i < FASTBOOT_MAX_FILES_MAP; i++) {
		newkernel.fi_files[i].fb_va = fake_va;

	}

	if (panicstr && CPU->cpu_id != bootcpuid &&
	    CPU_ACTIVE(cpu_get(bootcpuid))) {
		extern void panic_idle(void);
		cpuset_t cpuset;

		CPUSET_ZERO(cpuset);
		CPUSET_ADD(cpuset, bootcpuid);
		xc_priority((xc_arg_t)&newkernel, 0, 0, CPUSET2BV(cpuset),
		    (xc_func_t)fastboot_xc_func);

		panic_idle();
	} else
		(void) fastboot_xc_func(&newkernel, 0, 0);
}


/*
 * Get boot property value for fastreboot_onpanic.
 *
 * NOTE: If fastreboot_onpanic is set to non-zero in /etc/system,
 * new setting passed in via "-B fastreboot_onpanic" is ignored.
 * This order of precedence is to enable developers debugging panics
 * that occur early in boot to utilize Fast Reboot on panic.
 */
static void
fastboot_get_bootprop(void)
{
	int		val = 0xaa, len, ret;
	dev_info_t	*devi;
	char		*propstr = NULL;

	devi = ddi_root_node();

	ret = ddi_prop_lookup_string(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    FASTREBOOT_ONPANIC, &propstr);

	if (ret == DDI_PROP_SUCCESS) {
		if (FASTREBOOT_ONPANIC_NOTSET(propstr))
			val = 0;
		else if (FASTREBOOT_ONPANIC_ISSET(propstr))
			val = UA_FASTREBOOT_ONPANIC;

		/*
		 * Only set fastreboot_onpanic to the value passed in
		 * if it's not already set to non-zero, and the value
		 * has indeed been passed in via command line.
		 */
		if (!fastreboot_onpanic && val != 0xaa)
			fastreboot_onpanic = val;
		ddi_prop_free(propstr);
	} else if (ret != DDI_PROP_NOT_FOUND && ret != DDI_PROP_UNDEFINED) {
		cmn_err(CE_NOTE, "!%s value is invalid, will be ignored",
		    FASTREBOOT_ONPANIC);
	}

	len = sizeof (fastreboot_onpanic_cmdline);
	ret = ddi_getlongprop_buf(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    FASTREBOOT_ONPANIC_CMDLINE, fastreboot_onpanic_cmdline, &len);

	if (ret == DDI_PROP_BUF_TOO_SMALL)
		cmn_err(CE_NOTE, "!%s value is too long, will be ignored",
		    FASTREBOOT_ONPANIC_CMDLINE);
}

/*
 * This function is called by main() to either load the backup kernel for panic
 * fast reboot, or to reserve low physical memory for fast reboot.
 */
void
fastboot_post_startup()
{
	lbolt_at_boot = ddi_get_lbolt();

	/* Default to 10 minutes */
	if (fastreboot_onpanic_uptime == LONG_MAX)
		fastreboot_onpanic_uptime = SEC_TO_TICK(10 * 60);

	if (!fastreboot_capable)
		return;

	mutex_enter(&fastreboot_config_mutex);

	fastboot_get_bootprop();

	if (fastreboot_onpanic)
		fastboot_load_kernel(fastreboot_onpanic_cmdline);
	else if (reserve_mem_enabled)
		fastboot_reserve_mem(&newkernel);

	mutex_exit(&fastreboot_config_mutex);
}

/*
 * Update boot configuration settings.
 * If the new fastreboot_onpanic setting is false, and a kernel has
 * been preloaded, free the memory;
 * if the new fastreboot_onpanic setting is true and newkernel is
 * not valid, load the new kernel.
 */
void
fastboot_update_config(const char *mdep)
{
	uint8_t boot_config = (uint8_t)*mdep;
	int cur_fastreboot_onpanic;

	if (!fastreboot_capable)
		return;

	mutex_enter(&fastreboot_config_mutex);

	cur_fastreboot_onpanic = fastreboot_onpanic;
	fastreboot_onpanic = boot_config & UA_FASTREBOOT_ONPANIC;

	if (fastreboot_onpanic && (!cur_fastreboot_onpanic ||
	    !newkernel.fi_valid))
		fastboot_load_kernel(fastreboot_onpanic_cmdline);
	if (cur_fastreboot_onpanic && !fastreboot_onpanic)
		fastboot_free_newkernel(&newkernel);

	mutex_exit(&fastreboot_config_mutex);
}

/*
 * This is an internal interface to disable Fast Reboot on Panic.
 * It frees up memory allocated for the backup kernel and sets
 * fastreboot_onpanic to zero.
 */
static void
fastreboot_onpanic_disable(void)
{
	uint8_t boot_config = (uint8_t)(~UA_FASTREBOOT_ONPANIC);
	fastboot_update_config((const char *)&boot_config);
}

/*
 * This is the interface to be called by fm_panic() in case FMA has diagnosed
 * a terminal machine check exception.  It does not free up memory allocated
 * for the backup kernel.  General disabling fastreboot_onpanic in a
 * non-panicking situation must go through fastboot_onpanic_disable().
 */
void
fastreboot_disable_highpil(void)
{
	fastreboot_onpanic = 0;
}

/*
 * This is an internal interface to disable Fast Reboot by Default.
 * It does not free up memory allocated for the backup kernel.
 */
static void
fastreboot_capable_disable(uint32_t msgid)
{
	if (fastreboot_capable != 0) {
		fastreboot_capable = 0;
		if (msgid < sizeof (fastreboot_nosup_desc) /
		    sizeof (fastreboot_nosup_desc[0]))
			fastreboot_nosup_id = msgid;
		else
			fastreboot_nosup_id = FBNS_DEFAULT;
	}
}

/*
 * This is the kernel interface for disabling
 * Fast Reboot by Default and Fast Reboot on Panic.
 * Frees up memory allocated for the backup kernel.
 * General disabling of the Fast Reboot by Default feature should be done
 * via the userland interface scf_fastreboot_default_set_transient().
 */
void
fastreboot_disable(uint32_t msgid)
{
	fastreboot_capable_disable(msgid);
	fastreboot_onpanic_disable();
}

/*
 * Returns Fast Reboot not support message for fastreboot_nosup_id.
 * If fastreboot_nosup_id contains invalid index, default
 * Fast Reboot not support message is returned.
 */
const char *
fastreboot_nosup_message(void)
{
	uint32_t msgid;

	msgid = fastreboot_nosup_id;
	if (msgid >= sizeof (fastreboot_nosup_desc) /
	    sizeof (fastreboot_nosup_desc[0]))
		msgid = FBNS_DEFAULT;

	return (fastreboot_nosup_desc[msgid]);
}

/*
 * A simplified interface for uadmin to call to update the configuration
 * setting and load a new kernel if necessary.
 */
void
fastboot_update_and_load(int fcn, char *mdep)
{
	if (fcn != AD_FASTREBOOT) {
		/*
		 * If user has explicitly requested reboot to prom,
		 * or uadmin(1M) was invoked with other functions,
		 * don't try to fast reboot after dumping.
		 */
		fastreboot_onpanic_disable();
	}

	mutex_enter(&fastreboot_config_mutex);

	if (fastreboot_onpanic)
		fastboot_load_kernel(mdep);

	mutex_exit(&fastreboot_config_mutex);
}
