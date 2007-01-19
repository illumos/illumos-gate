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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/machparam.h>
#include <sys/x86_archext.h>
#include <sys/systm.h>
#include <sys/mach_mmu.h>

#include <sys/multiboot.h>

extern multiboot_header_t mb_header;
extern int have_cpuid(void);
extern uint32_t get_cpuid_edx(uint32_t *eax);

#include <sys/inttypes.h>
#include <sys/bootinfo.h>
#include <sys/mach_mmu.h>
#include <sys/boot_console.h>

#include "dboot_printf.h"
#include "dboot_xboot.h"
#include "dboot_elfload.h"

/*
 * This file contains code that runs to transition us from either a multiboot
 * compliant loader (32 bit non-paging) or Xen domain loader to regular kernel
 * execution. Its task is to setup the kernel memory image and page tables.
 *
 * The code executes as:
 *	- 32 bits under GRUB (for 32 or 64 bit Solaris)
 * 	- 32 bit program for Xen 32 bit
 *	- 64 bit program for Xen 64 bit (at least that's my assumption for now)
 *
 * Under Xen, we must create mappings for any memory beyond the initial
 * start of day allocation (such as the kernel itself).
 *
 * When not under Xen, the mapping between maddr_t and paddr_t is 1:1.
 * Since we are running in real mode, so all such memory is accessible.
 */

/*
 * Standard bits used in PTE (page level) and PTP (internal levels)
 */
x86pte_t ptp_bits = PT_VALID | PT_REF | PT_USER | PT_WRITABLE | PT_USER;
x86pte_t pte_bits = PT_VALID | PT_REF | PT_MOD | PT_NOCONSIST | PT_WRITABLE;

/*
 * This is the target addresses (physical) where the kernel text and data
 * nucleus pages will be unpacked. On Xen this is actually a virtual address.
 */
paddr_t ktext_phys;
uint32_t ksize = 2 * FOUR_MEG;	/* kernel nucleus is 8Meg */

static uint64_t target_kernel_text;	/* value to use for KERNEL_TEXT */

/*
 * The stack is setup in assembler before entering startup_kernel()
 */
char stack_space[STACK_SIZE];

/*
 * Used to track physical memory allocation
 */
static paddr_t next_avail_addr = 0;

multiboot_info_t *mb_info;

/*
 * This contains information passed to the kernel
 */
struct xboot_info boot_info[2];	/* extra space to fix alignement for amd64 */
struct xboot_info *bi;

/*
 * Page table and memory stuff.
 */
static uint64_t max_mem;			/* maximum memory address */

/*
 * Information about processor MMU
 */
int amd64_support = 0;
int largepage_support = 0;
int pae_support = 0;
int pge_support = 0;
int NX_support = 0;

/*
 * Low 32 bits of kernel entry address passed back to assembler.
 * When running a 64 bit kernel, the high 32 bits are 0xffffffff.
 */
uint32_t entry_addr_low;

/*
 * Memlists for the kernel. We shouldn't need a lot of these.
 */
#define	MAX_MEMLIST (10)
struct boot_memlist memlists[MAX_MEMLIST];
uint_t memlists_used = 0;

#define	MAX_MODULES (10)
struct boot_modules modules[MAX_MODULES];
uint_t modules_used = 0;

/*
 * Debugging macros
 */
uint_t prom_debug = 0;
uint_t map_debug = 0;

/*
 * The Xen/Grub specific code builds the initial memlists. This code does
 * sort/merge/link for final use.
 */
static void
sort_physinstall(void)
{
	int i;
	int j;
	struct boot_memlist tmp;

	/*
	 * Now sort the memlists, in case they weren't in order.
	 * Yeah, this is a bubble sort; small, simple and easy to get right.
	 */
	DBG_MSG("Sorting phys-installed list\n");
	for (j = memlists_used - 1; j > 0; --j) {
		for (i = 0; i < j; ++i) {
			if (memlists[i].addr < memlists[i + 1].addr)
				continue;
			tmp = memlists[i];
			memlists[i] = memlists[i + 1];
			memlists[i + 1] = tmp;
		}
	}

	/*
	 * Merge any memlists that don't have holes between them.
	 */
	for (i = 0; i <= memlists_used - 1; ++i) {
		if (memlists[i].addr + memlists[i].size != memlists[i + 1].addr)
			continue;

		if (prom_debug)
			dboot_printf(
			    "merging mem segs %" PRIx64 "...%" PRIx64
			    " w/ %" PRIx64 "...%" PRIx64 "\n",
			    memlists[i].addr,
			    memlists[i].addr + memlists[i].size,
			    memlists[i + 1].addr,
			    memlists[i + 1].addr + memlists[i + 1].size);

		memlists[i].size += memlists[i + 1].size;
		for (j = i + 1; j < memlists_used - 1; ++j)
			memlists[j] = memlists[j + 1];
		--memlists_used;
		DBG(memlists_used);
		--i;	/* after merging we need to reexamine, so do this */
	}

	if (prom_debug) {
		dboot_printf("\nFinal memlists:\n");
		for (i = 0; i < memlists_used; ++i) {
			dboot_printf("\t%d: addr=%" PRIx64 " size=%"
			    PRIx64 "\n", i, memlists[i].addr, memlists[i].size);
		}
	}

	/*
	 * link together the memlists with native size pointers
	 */
	memlists[0].next = 0;
	memlists[0].prev = 0;
	for (i = 1; i < memlists_used; ++i) {
		memlists[i].prev = (native_ptr_t)(uintptr_t)(memlists + i - 1);
		memlists[i].next = 0;
		memlists[i - 1].next = (native_ptr_t)(uintptr_t)(memlists + i);
	}
	bi->bi_phys_install = (native_ptr_t)memlists;
	DBG(bi->bi_phys_install);
}

x86pte_t
get_pteval(paddr_t table, uint_t index)
{
	if (pae_support)
		return (((x86pte_t *)(uintptr_t)table)[index]);
	return (((x86pte32_t *)(uintptr_t)table)[index]);
}

/*ARGSUSED*/
void
set_pteval(paddr_t table, uint_t index, uint_t level, x86pte_t pteval)
{
	uintptr_t tab_addr = (uintptr_t)table;

	if (pae_support)
		((x86pte_t *)tab_addr)[index] = pteval;
	else
		((x86pte32_t *)tab_addr)[index] = (x86pte32_t)pteval;
	if (level == top_level && level == 2)
		reload_cr3();
}

paddr_t
make_ptable(x86pte_t *pteval, uint_t level)
{
	paddr_t new_table = (paddr_t)(uintptr_t)mem_alloc(MMU_PAGESIZE);

	if (level == top_level && level == 2)
		*pteval = pa_to_ma((uintptr_t)new_table) | PT_VALID;
	else
		*pteval = pa_to_ma((uintptr_t)new_table) | ptp_bits;

	if (map_debug)
		dboot_printf("new page table lvl=%d paddr=0x%lx ptp=0x%"
		    PRIx64 "\n", level, (ulong_t)new_table, *pteval);
	return (new_table);
}

x86pte_t *
map_pte(paddr_t table, uint_t index)
{
	return ((x86pte_t *)(uintptr_t)(table + index * pte_size));
}

#if 0	/* useful if debugging */
/*
 * dump out the contents of page tables...
 */
static void
dump_tables(void)
{
	uint_t save_index[4];	/* for recursion */
	char *save_table[4];	/* for recursion */
	uint_t	l;
	uint64_t va;
	uint64_t pgsize;
	int index;
	int i;
	x86pte_t pteval;
	char *table;
	static char *tablist = "\t\t\t";
	char *tabs = tablist + 3 - top_level;
	uint_t pa, pa1;

	dboot_printf("Finished pagetables:\n");
	table = (char *)top_page_table;
	l = top_level;
	va = 0;
	for (index = 0; index < ptes_per_table; ++index) {
		pgsize = 1ull << shift_amt[l];
		if (pae_support)
			pteval = ((x86pte_t *)table)[index];
		else
			pteval = ((x86pte32_t *)table)[index];
		if (pteval == 0)
			goto next_entry;

		dboot_printf("%s %lx[0x%x] = %" PRIx64 ", va=%" PRIx64,
		    tabs + l, table, index, (uint64_t)pteval, va);
		pa = ma_to_pa(pteval & MMU_PAGEMASK);
		dboot_printf(" physaddr=%" PRIx64 "\n", pa);

		/*
		 * Don't try to walk hypervisor private pagetables
		 */
		if ((l > 1 || (l == 1 && (pteval & PT_PAGESIZE) == 0))) {
			save_table[l] = table;
			save_index[l] = index;
			--l;
			index = -1;
			table = (char *)(uintptr_t)
			    ma_to_pa(pteval & MMU_PAGEMASK);
			goto recursion;
		}

		/*
		 * shorten dump for consecutive mappings
		 */
		for (i = 1; index + i < ptes_per_table; ++i) {
			if (pae_support)
				pteval = ((x86pte_t *)table)[index + i];
			else
				pteval = ((x86pte32_t *)table)[index + i];
			if (pteval == 0)
				break;
			pa1 = ma_to_pa(pteval & MMU_PAGEMASK);
			if (pa1 != pa + i * pgsize)
				break;
		}
		if (i > 2) {
			dboot_printf("%s...\n", tabs + l);
			va += pgsize * (i - 2);
			index += i - 2;
		}
next_entry:
		va += pgsize;
		if (l == 3 && index == 256)	/* VA hole */
			va = 0xffff800000000000ull;
recursion:
		;
	}
	if (l < top_level) {
		++l;
		index = save_index[l];
		table = save_table[l];
		goto recursion;
	}
}
#endif

/*
 * Add a mapping for the physical page at the given virtual address.
 */
static void
map_pa_at_va(paddr_t pa, native_ptr_t va, uint_t level)
{
	x86pte_t *ptep;
	x86pte_t pteval;

	pteval = pa_to_ma(pa) | pte_bits;
	if (level > 0)
		pteval |= PT_PAGESIZE;
	if (va >= target_kernel_text && pge_support)
		pteval |= PT_GLOBAL;

	if (map_debug && pa != va)
		dboot_printf("mapping pa=0x%" PRIx64 " va=0x%" PRIx64
		    " pte=0x%" PRIx64 " l=%d\n",
		    (uint64_t)pa, (uint64_t)va, pteval, level);

	/*
	 * Find the pte that will map this address. This creates any
	 * missing intermediate level page tables
	 */
	ptep = find_pte(va, NULL, level, 0);

	/*
	 * On Xen we must use hypervisor calls to modify the PTE, since
	 * paging is active. On real hardware we just write to the pagetables
	 * which aren't in use yet.
	 */
	if (va < 1024 * 1024)
		pteval |= PT_NOCACHE;		/* for video RAM */
	if (pae_support)
		*ptep = pteval;
	else
		*((x86pte32_t *)ptep) = (x86pte32_t)pteval;
}

/*
 * During memory allocation, find the highest address not used yet.
 */
static void
check_higher(paddr_t a)
{
	if (a < next_avail_addr)
		return;
	next_avail_addr = RNDUP(a + 1, MMU_PAGESIZE);
	DBG(next_avail_addr);
}

/*
 * Walk through the module information finding the last used address.
 * The first available address will become the top level page table.
 *
 * We then build the phys_install memlist from the multiboot information.
 */
static void
init_mem_alloc(void)
{
	mb_memory_map_t *mmap;
	mb_module_t *mod;
	uint64_t start;
	uint64_t end;
	uint64_t page_offset = MMU_PAGEOFFSET;	/* needs to be 64 bits */
	extern char _end[];
	int i;

	DBG_MSG("Entered init_mem_alloc()\n");
	DBG((uintptr_t)mb_info);

	/*
	 * search the modules to find the last used address
	 * we'll build the module list while we're walking through here
	 */
	DBG_MSG("\nFinding Modules\n");
	check_higher((paddr_t)&_end);
	for (mod = (mb_module_t *)(mb_info->mods_addr), i = 0;
	    i < mb_info->mods_count;
	    ++mod, ++i) {
		if (prom_debug) {
			dboot_printf("\tmodule #%d: %s at: 0x%lx, len 0x%lx\n",
			    i, (char *)(mod->mod_name),
			    (ulong_t)mod->mod_start, (ulong_t)mod->mod_end);
		}
		modules[i].bm_addr = mod->mod_start;
		modules[i].bm_size = mod->mod_end;

		check_higher(mod->mod_end);
	}
	bi->bi_modules = (native_ptr_t)modules;
	DBG(bi->bi_modules);
	bi->bi_module_cnt = mb_info->mods_count;
	DBG(bi->bi_module_cnt);

	/*
	 * Walk through the memory map from multiboot and build our memlist
	 * structures. Note these will have native format pointers.
	 */
	DBG_MSG("\nFinding Memory Map\n");
	DBG(mb_info->flags);
	max_mem = 0;
	if (mb_info->flags & 0x40) {
		DBG(mb_info->mmap_addr);
		DBG(mb_info->mmap_length);
		check_higher(mb_info->mmap_addr + mb_info->mmap_length);

		for (mmap = (mb_memory_map_t *)mb_info->mmap_addr;
		    (uint32_t)mmap < mb_info->mmap_addr + mb_info->mmap_length;
		    mmap = (mb_memory_map_t *)((uint32_t)mmap + mmap->size
		    + sizeof (mmap->size))) {

			start = ((uint64_t)mmap->base_addr_high << 32) +
			    mmap->base_addr_low;
			end = start + ((uint64_t)mmap->length_high << 32) +
			    mmap->length_low;

			if (prom_debug) {
				dboot_printf("\ttype: %d %" PRIx64 "..%"
				    PRIx64 "\n", mmap->type, start, end);
			}

			/*
			 * only type 1 is usable RAM
			 */
			if (mmap->type != 1)
				continue;

			/*
			 * page align start and end
			 */
			start = (start + page_offset) & ~page_offset;
			end &= ~page_offset;
			if (end <= start)
				continue;

			if (end > max_mem)
				max_mem = end;

			memlists[memlists_used].addr = start;
			memlists[memlists_used].size = end - start;
			++memlists_used;	/* no overflow check */
		}
	} else if (mb_info->flags & 0x01) {
		DBG(mb_info->mem_lower);
		memlists[memlists_used].addr = 0;
		memlists[memlists_used].size = mb_info->mem_lower * 1024;
		++memlists_used;
		DBG(mb_info->mem_upper);
		memlists[memlists_used].addr = 1024 * 1024;
		memlists[memlists_used].size = mb_info->mem_upper * 1024;
		++memlists_used;
	} else {
		dboot_panic("No memory info from boot loader!!!\n");
	}

	check_higher(bi->bi_cmdline);

	/*
	 * finish processing the physinstall list
	 */
	sort_physinstall();
}

/*
 * Simple memory allocator, allocates aligned physical memory.
 * Note that startup_kernel() only allocates memory, never frees.
 * Memory usage just grows in an upward direction.
 */
static void *
do_mem_alloc(uint32_t size, uint32_t align)
{
	uint_t i;
	uint64_t best;
	uint64_t start;
	uint64_t end;

	/*
	 * make sure size is a multiple of pagesize
	 */
	size = RNDUP(size, MMU_PAGESIZE);
	next_avail_addr = RNDUP(next_avail_addr, align);

	/*
	 * a really large bootarchive that causes you to run out of memory
	 * may cause this to blow up
	 */
	/* LINTED E_UNEXPECTED_UINT_PROMOTION */
	best = (uint64_t)-size;
	for (i = 0; i < memlists_used; ++i) {
		start = memlists[i].addr;
		end = start + memlists[i].size;

		/*
		 * did we find the desired address?
		 */
		if (start <= next_avail_addr && next_avail_addr + size <= end) {
			best = next_avail_addr;
			goto done;
		}

		/*
		 * if not is this address the best so far?
		 */
		if (start > next_avail_addr && start < best &&
		    RNDUP(start, align) + size <= end)
			best = RNDUP(start, align);
	}

	/*
	 * We didn't find exactly the address we wanted, due to going off the
	 * end of a memory region. Return the best found memory address.
	 */
done:
	next_avail_addr = best + size;
	(void) memset((void *)(uintptr_t)best, 0, size);
	return ((void *)(uintptr_t)best);
}

void *
mem_alloc(uint32_t size)
{
	return (do_mem_alloc(size, MMU_PAGESIZE));
}


/*
 * Build page tables to map all of memory used so far as well as the kernel.
 */
static void
build_page_tables(void)
{
	uint32_t psize;
	uint32_t level;
	uint32_t off;
	uint32_t i;
	uint64_t start;
	uint64_t end;
	uint64_t next_mapping;

	/*
	 * If we're not using Xen, we need to create the top level pagetable.
	 */
	top_page_table = (paddr_t)(uintptr_t)mem_alloc(MMU_PAGESIZE);
	DBG((uintptr_t)top_page_table);

	/*
	 * Determine if we'll use large mappings for kernel, then map it.
	 */
	if (largepage_support) {
		psize = lpagesize;
		level = 1;
	} else {
		psize = MMU_PAGESIZE;
		level = 0;
	}

	DBG_MSG("Mapping kernel\n");
	DBG(ktext_phys);
	DBG(target_kernel_text);
	DBG(ksize);
	DBG(psize);
	for (off = 0; off < ksize; off += psize)
		map_pa_at_va(ktext_phys + off, target_kernel_text + off, level);

	/*
	 * The kernel will need a 1 page window to work with page tables
	 */
	bi->bi_pt_window = (uintptr_t)mem_alloc(MMU_PAGESIZE);
	DBG(bi->bi_pt_window);
	bi->bi_pte_to_pt_window =
	    (uintptr_t)find_pte(bi->bi_pt_window, NULL, 0, 0);
	DBG(bi->bi_pte_to_pt_window);

	/*
	 * Under multiboot we need 1:1 mappings for all of low memory, which
	 * includes our pagetables. The following code works because our
	 * simple memory allocator only grows usage in an upwards direction.
	 *
	 * We map *all* possible addresses below 1 Meg, since things like
	 * the video RAM are down there.
	 *
	 * Skip memory between 1M and _start, this acts as a reserve
	 * of memory usable for DMA.
	 */
	next_mapping = (uintptr_t)_start & MMU_PAGEMASK;
	if (map_debug)
		dboot_printf("1:1 map pa=0..1Meg\n");
	for (start = 0; start < 1024 * 1024; start += MMU_PAGESIZE)
		map_pa_at_va(start, start, 0);

	for (i = 0; i < memlists_used; ++i) {
		start = memlists[i].addr;
		if (start < next_mapping)
			start = next_mapping;

		end = start + memlists[i].size;

		if (map_debug)
			dboot_printf("1:1 map pa=%" PRIx64 "..%" PRIx64 "\n",
			    start, end);
		while (start < end && start < next_avail_addr) {
			map_pa_at_va(start, start, 0);
			start += MMU_PAGESIZE;
		}
	}

	DBG_MSG("\nPage tables constructed\n");
}

#define	NO_MULTIBOOT	\
"multiboot is no longer used to boot the Solaris Operating System.\n\
The grub entry should be changed to:\n\
kernel$ /platform/i86pc/kernel/$ISADIR/unix\n\
module$ /platform/i86pc/$ISADIR/boot_archive\n\
See http://www.sun.com/msg/SUNOS-8000-AK for details.\n"

/*
 * startup_kernel has a pretty simple job. It builds pagetables which reflect
 * 1:1 mappings for all memory in use. It then also adds mappings for
 * the kernel nucleus at virtual address of target_kernel_text using large page
 * mappings. The page table pages are also accessible at 1:1 mapped
 * virtual addresses.
 */
/*ARGSUSED*/
void
startup_kernel(void)
{
	char *cmdline;
	uintptr_t addr;

	/*
	 * At this point we are executing in a 32 bit real mode.
	 */
	cmdline = (char *)mb_info->cmdline;
	prom_debug = (strstr(cmdline, "prom_debug") != NULL);
	map_debug = (strstr(cmdline, "map_debug") != NULL);
	bcons_init(cmdline);
	DBG_MSG("\n\nSolaris prekernel set: ");
	DBG_MSG(cmdline);
	DBG_MSG("\n");

	if (strstr(cmdline, "multiboot") != NULL) {
		dboot_panic(NO_MULTIBOOT);
	}

	/*
	 * boot info must be 16 byte aligned for 64 bit kernel ABI
	 */
	addr = (uintptr_t)boot_info;
	addr = (addr + 0xf) & ~0xf;
	bi = (struct xboot_info *)addr;
	DBG((uintptr_t)bi);
	bi->bi_cmdline = (native_ptr_t)(uintptr_t)cmdline;

	/*
	 * Need correct target_kernel_text value
	 */
#if defined(_BOOT_TARGET_amd64)
	target_kernel_text = KERNEL_TEXT_amd64;
#else
	target_kernel_text = KERNEL_TEXT_i386;
#endif
	DBG(target_kernel_text);

	/*
	 * use cpuid to enable MMU features
	 */
	if (have_cpuid()) {
		uint32_t eax, edx;

		eax = 1;
		edx = get_cpuid_edx(&eax);
		if (edx & CPUID_INTC_EDX_PSE)
			largepage_support = 1;
		if (edx & CPUID_INTC_EDX_PGE)
			pge_support = 1;
		if (edx & CPUID_INTC_EDX_PAE)
			pae_support = 1;

		eax = 0x80000000;
		edx = get_cpuid_edx(&eax);
		if (eax >= 0x80000001) {
			eax = 0x80000001;
			edx = get_cpuid_edx(&eax);
			if (edx & CPUID_AMD_EDX_LM)
				amd64_support = 1;
			if (edx & CPUID_AMD_EDX_NX)
				NX_support = 1;
		}
	} else {
		dboot_printf("cpuid not supported\n");
	}

#if defined(_BOOT_TARGET_amd64)
	if (amd64_support == 0)
		dboot_panic("long mode not supported, rebooting\n");
	else if (pae_support == 0)
		dboot_panic("long mode, but no PAE; rebooting\n");
#endif

	/*
	 * initialize our memory allocator
	 */
	init_mem_alloc();

	/*
	 * configure mmu information
	 */
#if !defined(_BOOT_TARGET_amd64)
	if (pae_support && (max_mem > FOUR_GIG || NX_support)) {
#endif
		shift_amt = shift_amt_pae;
		ptes_per_table = 512;
		pte_size = 8;
		lpagesize = TWO_MEG;
#if defined(_BOOT_TARGET_amd64)
		top_level = 3;
#else
		top_level = 2;
#endif
#if !defined(_BOOT_TARGET_amd64)
	} else {
		pae_support = 0;
		NX_support = 0;
		shift_amt = shift_amt_nopae;
		ptes_per_table = 1024;
		pte_size = 4;
		lpagesize = FOUR_MEG;
		top_level = 1;
	}
#endif

	DBG(pge_support);
	DBG(NX_support);
	DBG(largepage_support);
	DBG(amd64_support);
	DBG(top_level);
	DBG(pte_size);
	DBG(ptes_per_table);
	DBG(lpagesize);

	ktext_phys = FOUR_MEG;		/* from UNIX Mapfile */

#if defined(_BOOT_TARGET_amd64)
	/*
	 * For grub, copy kernel bits from the ELF64 file to final place.
	 */
	DBG_MSG("\nAllocating nucleus pages.\n");
	ktext_phys = (uintptr_t)do_mem_alloc(ksize, FOUR_MEG);
	if (ktext_phys == 0)
		dboot_panic("failed to allocate aligned kernel memory\n");
	if (dboot_elfload64(mb_header.load_addr) != 0)
		dboot_panic("failed to parse kernel ELF image, rebooting\n");

#endif
	DBG(ktext_phys);

	/*
	 * Allocate page tables.
	 */
	build_page_tables();

	/*
	 * return to assembly code to switch to running kernel
	 */
	entry_addr_low = (uint32_t)target_kernel_text;
	DBG(entry_addr_low);
	bi->bi_use_largepage = largepage_support;
	bi->bi_use_pae = pae_support;
	bi->bi_use_pge = pge_support;
	bi->bi_use_nx = NX_support;
	bi->bi_next_paddr = next_avail_addr;
	DBG(bi->bi_next_paddr);
	bi->bi_next_vaddr = (uintptr_t)next_avail_addr;
	DBG(bi->bi_next_vaddr);
	bi->bi_mb_info = (uintptr_t)mb_info;
	bi->bi_top_page_table = (uintptr_t)top_page_table;

	bi->bi_kseg_size = FOUR_MEG;
	DBG(bi->bi_kseg_size);

#if 0		/* useful if debugging initial page tables */
	if (prom_debug)
		dump_tables();
#endif

	DBG_MSG("\n\n*** DBOOT DONE -- back to asm to jump to kernel\n\n");
}
