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
 *
 * Copyright 2020 Joyent, Inc.
 */


#include <sys/types.h>
#include <sys/machparam.h>
#include <sys/x86_archext.h>
#include <sys/systm.h>
#include <sys/mach_mmu.h>
#include <sys/multiboot.h>
#include <sys/multiboot2.h>
#include <sys/multiboot2_impl.h>
#include <sys/sysmacros.h>
#include <sys/framebuffer.h>
#include <sys/sha1.h>
#include <util/string.h>
#include <util/strtolctype.h>
#include <sys/efi.h>

/*
 * Compile time debug knob. We do not have any early mechanism to control it
 * as the boot is the earliest mechanism we have, and we do not want to have
 * it being switched on by default.
 */
int dboot_debug = 0;

#if defined(__xpv)

#include <sys/hypervisor.h>
uintptr_t xen_virt_start;
pfn_t *mfn_to_pfn_mapping;

#else /* !__xpv */

extern multiboot_header_t mb_header;
extern uint32_t mb2_load_addr;
extern int have_cpuid(void);

#endif /* !__xpv */

#include <sys/inttypes.h>
#include <sys/bootinfo.h>
#include <sys/mach_mmu.h>
#include <sys/boot_console.h>

#include "dboot_asm.h"
#include "dboot_printf.h"
#include "dboot_xboot.h"
#include "dboot_elfload.h"

#define	SHA1_ASCII_LENGTH	(SHA1_DIGEST_LENGTH * 2)

#define	ULL(v) ((u_longlong_t)(v))

static void *page_alloc(void);

/*
 * This file contains code that runs to transition us from either a multiboot
 * compliant loader (32 bit non-paging) or a XPV domain loader to
 * regular kernel execution. Its task is to setup the kernel memory image
 * and page tables.
 *
 * The code executes as:
 *	- 32 bits under GRUB (for 32 or 64 bit Solaris)
 *	- a 32 bit program for the 32-bit PV hypervisor
 *	- a 64 bit program for the 64-bit PV hypervisor (at least for now)
 *
 * Under the PV hypervisor, we must create mappings for any memory beyond the
 * initial start of day allocation (such as the kernel itself).
 *
 * When on the metal, the mapping between maddr_t and paddr_t is 1:1.
 * Since we are running in real mode, so all such memory is accessible.
 */

/*
 * Standard bits used in PTE (page level) and PTP (internal levels)
 */
x86pte_t ptp_bits = PT_VALID | PT_REF | PT_WRITABLE | PT_USER;
x86pte_t pte_bits = PT_VALID | PT_REF | PT_WRITABLE | PT_MOD | PT_NOCONSIST;

/*
 * This is the target addresses (physical) where the kernel text and data
 * nucleus pages will be unpacked. On the hypervisor this is actually a
 * virtual address.
 */
paddr_t ktext_phys;
/*
 * Nucleus size is 8Mb, including text, data, and BSS.
 */
uint32_t ksize = 2 * FOUR_MEG;

static uint64_t target_kernel_text;	/* value to use for KERNEL_TEXT */

/*
 * The stack is setup in assembler before entering startup_kernel()
 */
char stack_space[STACK_SIZE];

/*
 * The highest address we build page tables for.
 */
static paddr_t boot_map_end;

/*
 * The dboot allocator. This is a small area we use for allocating the
 * kernel nucleus and pages for the identity page tables we build here.
 */
static paddr_t alloc_addr;
static paddr_t alloc_end;

#if defined(__xpv)
/*
 * Additional information needed for hypervisor memory allocation.
 * Only memory up to scratch_end is mapped by page tables.
 * mfn_base is the start of the hypervisor virtual image. It's ONE_GIG, so
 * to derive a pfn from a pointer, you subtract mfn_base.
 */

static paddr_t mfn_base;		/* addr corresponding to mfn_list[0] */
start_info_t *xen_info;

#else	/* __xpv */

/*
 * If on the metal, then we have a multiboot loader.
 */
uint32_t mb_magic;			/* magic from boot loader */
uint32_t mb_addr;			/* multiboot info package from loader */
int multiboot_version;
multiboot_info_t *mb_info;
multiboot2_info_header_t *mb2_info;
int num_entries;			/* mmap entry count */
boolean_t num_entries_set;		/* is mmap entry count set */
uintptr_t load_addr;
static boot_framebuffer_t framebuffer __aligned(16);
static boot_framebuffer_t *fb;

/* can not be automatic variables because of alignment */
static efi_guid_t smbios3 = SMBIOS3_TABLE_GUID;
static efi_guid_t smbios = SMBIOS_TABLE_GUID;
static efi_guid_t acpi2 = EFI_ACPI_TABLE_GUID;
static efi_guid_t acpi1 = ACPI_10_TABLE_GUID;
#endif	/* __xpv */

/*
 * This contains information passed to the kernel
 */
struct xboot_info boot_info __aligned(16);
struct xboot_info *bi;

/*
 * Page table and memory stuff.
 */
static paddr_t max_mem;			/* maximum memory address */

/*
 * Information about processor MMU
 */
int amd64_support = 0;
int largepage_support = 0;
int pae_support = 0;
int pge_support = 0;
int NX_support = 0;
int PAT_support = 0;

/*
 * Low 32 bits of kernel entry address passed back to assembler.
 * When running a 64 bit kernel, the high 32 bits are 0xffffffff.
 */
uint32_t entry_addr_low;

/*
 * Memlists for the kernel. We shouldn't need a lot of these.
 */
#define	MAX_MEMLIST (50)
struct boot_memlist memlists[MAX_MEMLIST];
uint_t memlists_used = 0;
struct boot_memlist pcimemlists[MAX_MEMLIST];
uint_t pcimemlists_used = 0;
struct boot_memlist rsvdmemlists[MAX_MEMLIST];
uint_t rsvdmemlists_used = 0;

/*
 * This should match what's in the bootloader.  It's arbitrary, but GRUB
 * in particular has limitations on how much space it can use before it
 * stops working properly.  This should be enough.
 */
struct boot_modules modules[MAX_BOOT_MODULES];
uint_t modules_used = 0;

#ifdef __xpv
/*
 * Xen strips the size field out of the mb_memory_map_t, see struct e820entry
 * definition in Xen source.
 */
typedef struct {
	uint32_t	base_addr_low;
	uint32_t	base_addr_high;
	uint32_t	length_low;
	uint32_t	length_high;
	uint32_t	type;
} mmap_t;

/*
 * There is 512KB of scratch area after the boot stack page.
 * We'll use that for everything except the kernel nucleus pages which are too
 * big to fit there and are allocated last anyway.
 */
#define	MAXMAPS	100
static mmap_t map_buffer[MAXMAPS];
#else
typedef mb_memory_map_t mmap_t;
#endif

/*
 * Debugging macros
 */
uint_t prom_debug = 0;
uint_t map_debug = 0;

static char noname[2] = "-";

static boolean_t
ranges_intersect(uint64_t s1, uint64_t e1, uint64_t s2, uint64_t e2)
{
	return (s1 < e2 && e1 >= s2);
}

/*
 * Either hypervisor-specific or grub-specific code builds the initial
 * memlists. This code does the sort/merge/link for final use.
 */
static void
sort_physinstall(void)
{
	int i;
#if !defined(__xpv)
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
#endif	/* __xpv */

	if (prom_debug) {
		dboot_printf("\nFinal memlists:\n");
		for (i = 0; i < memlists_used; ++i) {
			dboot_printf("\t%d: 0x%llx-0x%llx size=0x%llx\n",
			    i, ULL(memlists[i].addr), ULL(memlists[i].addr +
			    memlists[i].size), ULL(memlists[i].size));
		}

		dboot_printf("\nBoot modules:\n");
		for (i = 0; i < bi->bi_module_cnt; i++) {
			dboot_printf("\t%d: 0x%llx-0x%llx size=0x%llx\n",
			    i, ULL(modules[i].bm_addr), ULL(modules[i].bm_addr +
			    modules[i].bm_size), ULL(modules[i].bm_size));
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
	bi->bi_phys_install = (native_ptr_t)(uintptr_t)memlists;
	DBG(bi->bi_phys_install);
}

/*
 * build bios reserved memlists
 */
static void
build_rsvdmemlists(void)
{
	int i;

	rsvdmemlists[0].next = 0;
	rsvdmemlists[0].prev = 0;
	for (i = 1; i < rsvdmemlists_used; ++i) {
		rsvdmemlists[i].prev =
		    (native_ptr_t)(uintptr_t)(rsvdmemlists + i - 1);
		rsvdmemlists[i].next = 0;
		rsvdmemlists[i - 1].next =
		    (native_ptr_t)(uintptr_t)(rsvdmemlists + i);
	}
	bi->bi_rsvdmem = (native_ptr_t)(uintptr_t)rsvdmemlists;
	DBG(bi->bi_rsvdmem);
}

#if defined(__xpv)

/*
 * halt on the hypervisor after a delay to drain console output
 */
__NORETURN void
dboot_halt(void)
{
	uint_t i = 10000;

	while (--i)
		(void) HYPERVISOR_yield();
	(void) HYPERVISOR_shutdown(SHUTDOWN_poweroff);
	/* never reached */
	for (;;)
		;
}

/*
 * From a machine address, find the corresponding pseudo-physical address.
 * Pseudo-physical address are contiguous and run from mfn_base in each VM.
 * Machine addresses are the real underlying hardware addresses.
 * These are needed for page table entries. Note that this routine is
 * poorly protected. A bad value of "ma" will cause a page fault.
 */
paddr_t
ma_to_pa(maddr_t ma)
{
	ulong_t pgoff = ma & MMU_PAGEOFFSET;
	ulong_t pfn = mfn_to_pfn_mapping[mmu_btop(ma)];
	paddr_t pa;

	if (pfn >= xen_info->nr_pages)
		return (-(paddr_t)1);
	pa = mfn_base + mmu_ptob((paddr_t)pfn) + pgoff;
#ifdef DEBUG
	if (ma != pa_to_ma(pa))
		dboot_printf("ma_to_pa(%" PRIx64 ") got %" PRIx64 ", "
		    "pa_to_ma() says %" PRIx64 "\n", ma, pa, pa_to_ma(pa));
#endif
	return (pa);
}

/*
 * From a pseudo-physical address, find the corresponding machine address.
 */
maddr_t
pa_to_ma(paddr_t pa)
{
	pfn_t pfn;
	ulong_t mfn;

	pfn = mmu_btop(pa - mfn_base);
	if (pa < mfn_base || pfn >= xen_info->nr_pages)
		dboot_panic("pa_to_ma(): illegal address 0x%lx", (ulong_t)pa);
	mfn = ((ulong_t *)xen_info->mfn_list)[pfn];
#ifdef DEBUG
	if (mfn_to_pfn_mapping[mfn] != pfn)
		dboot_printf("pa_to_ma(pfn=%lx) got %lx ma_to_pa() says %lx\n",
		    pfn, mfn, mfn_to_pfn_mapping[mfn]);
#endif
	return (mfn_to_ma(mfn) | (pa & MMU_PAGEOFFSET));
}

#endif	/* __xpv */

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
#ifdef __xpv
	mmu_update_t t;
	maddr_t mtable = pa_to_ma(table);
	int retcnt;

	t.ptr = (mtable + index * pte_size) | MMU_NORMAL_PT_UPDATE;
	t.val = pteval;
	if (HYPERVISOR_mmu_update(&t, 1, &retcnt, DOMID_SELF) || retcnt != 1)
		dboot_panic("HYPERVISOR_mmu_update() failed");
#else /* __xpv */
	uintptr_t tab_addr = (uintptr_t)table;

	if (pae_support)
		((x86pte_t *)tab_addr)[index] = pteval;
	else
		((x86pte32_t *)tab_addr)[index] = (x86pte32_t)pteval;
	if (level == top_level && level == 2)
		reload_cr3();
#endif /* __xpv */
}

paddr_t
make_ptable(x86pte_t *pteval, uint_t level)
{
	paddr_t new_table = (paddr_t)(uintptr_t)page_alloc();

	if (level == top_level && level == 2)
		*pteval = pa_to_ma((uintptr_t)new_table) | PT_VALID;
	else
		*pteval = pa_to_ma((uintptr_t)new_table) | ptp_bits;

#ifdef __xpv
	/* Remove write permission to the new page table. */
	if (HYPERVISOR_update_va_mapping(new_table,
	    *pteval & ~(x86pte_t)PT_WRITABLE, UVMF_INVLPG | UVMF_LOCAL))
		dboot_panic("HYP_update_va_mapping error");
#endif

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
#if !defined(__xpv)
#define	maddr_t paddr_t
#endif /* !__xpv */

	dboot_printf("Finished pagetables:\n");
	table = (char *)(uintptr_t)top_page_table;
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

		dboot_printf("%s %p[0x%x] = %" PRIx64 ", va=%" PRIx64,
		    tabs + l, (void *)table, index, (uint64_t)pteval, va);
		pa = ma_to_pa(pteval & MMU_PAGEMASK);
		dboot_printf(" physaddr=%x\n", pa);

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
		if (l == 3 && index == 255)	/* VA hole */
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

/*
 * Add a mapping for the machine page at the given virtual address.
 */
static void
map_ma_at_va(maddr_t ma, native_ptr_t va, uint_t level)
{
	x86pte_t *ptep;
	x86pte_t pteval;

	pteval = ma | pte_bits;
	if (level > 0)
		pteval |= PT_PAGESIZE;
	if (va >= target_kernel_text && pge_support)
		pteval |= PT_GLOBAL;

	if (map_debug && ma != va)
		dboot_printf("mapping ma=0x%" PRIx64 " va=0x%" PRIx64
		    " pte=0x%" PRIx64 " l=%d\n",
		    (uint64_t)ma, (uint64_t)va, pteval, level);

#if defined(__xpv)
	/*
	 * see if we can avoid find_pte() on the hypervisor
	 */
	if (HYPERVISOR_update_va_mapping(va, pteval,
	    UVMF_INVLPG | UVMF_LOCAL) == 0)
		return;
#endif

	/*
	 * Find the pte that will map this address. This creates any
	 * missing intermediate level page tables
	 */
	ptep = find_pte(va, NULL, level, 0);

	/*
	 * When paravirtualized, we must use hypervisor calls to modify the
	 * PTE, since paging is active. On real hardware we just write to
	 * the pagetables which aren't in use yet.
	 */
#if defined(__xpv)
	ptep = ptep;	/* shut lint up */
	if (HYPERVISOR_update_va_mapping(va, pteval, UVMF_INVLPG | UVMF_LOCAL))
		dboot_panic("mmu_update failed-map_pa_at_va va=0x%" PRIx64
		    " l=%d ma=0x%" PRIx64 ", pte=0x%" PRIx64 "",
		    (uint64_t)va, level, (uint64_t)ma, pteval);
#else
	if (va < 1024 * 1024)
		pteval |= PT_NOCACHE;		/* for video RAM */
	if (pae_support)
		*ptep = pteval;
	else
		*((x86pte32_t *)ptep) = (x86pte32_t)pteval;
#endif
}

/*
 * Add a mapping for the physical page at the given virtual address.
 */
static void
map_pa_at_va(paddr_t pa, native_ptr_t va, uint_t level)
{
	map_ma_at_va(pa_to_ma(pa), va, level);
}

/*
 * This is called to remove start..end from the
 * possible range of PCI addresses.
 */
const uint64_t pci_lo_limit = 0x00100000ul;
const uint64_t pci_hi_limit = 0xfff00000ul;
static void
exclude_from_pci(uint64_t start, uint64_t end)
{
	int i;
	int j;
	struct boot_memlist *ml;

	for (i = 0; i < pcimemlists_used; ++i) {
		ml = &pcimemlists[i];

		/* delete the entire range? */
		if (start <= ml->addr && ml->addr + ml->size <= end) {
			--pcimemlists_used;
			for (j = i; j < pcimemlists_used; ++j)
				pcimemlists[j] = pcimemlists[j + 1];
			--i;	/* to revisit the new one at this index */
		}

		/* split a range? */
		else if (ml->addr < start && end < ml->addr + ml->size) {

			++pcimemlists_used;
			if (pcimemlists_used > MAX_MEMLIST)
				dboot_panic("too many pcimemlists");

			for (j = pcimemlists_used - 1; j > i; --j)
				pcimemlists[j] = pcimemlists[j - 1];
			ml->size = start - ml->addr;

			++ml;
			ml->size = (ml->addr + ml->size) - end;
			ml->addr = end;
			++i;	/* skip on to next one */
		}

		/* cut memory off the start? */
		else if (ml->addr < end && end < ml->addr + ml->size) {
			ml->size -= end - ml->addr;
			ml->addr = end;
		}

		/* cut memory off the end? */
		else if (ml->addr <= start && start < ml->addr + ml->size) {
			ml->size = start - ml->addr;
		}
	}
}

static int
dboot_loader_mmap_entries(void)
{
#if !defined(__xpv)
	if (num_entries_set == B_TRUE)
		return (num_entries);

	switch (multiboot_version) {
	case 1:
		DBG(mb_info->flags);
		if (mb_info->flags & 0x40) {
			mb_memory_map_t *mmap;
			caddr32_t mmap_addr;

			DBG(mb_info->mmap_addr);
			DBG(mb_info->mmap_length);

			for (mmap_addr = mb_info->mmap_addr;
			    mmap_addr < mb_info->mmap_addr +
			    mb_info->mmap_length;
			    mmap_addr += mmap->size + sizeof (mmap->size)) {
				mmap = (mb_memory_map_t *)(uintptr_t)mmap_addr;
				++num_entries;
			}

			num_entries_set = B_TRUE;
		}
		break;
	case 2:
		num_entries = dboot_multiboot2_efi_mmap_nentries(mb2_info);
		if (num_entries == 0)
			num_entries = dboot_multiboot2_mmap_nentries(mb2_info);
		if (num_entries == 0)
			dboot_panic("No memory map?\n");
		num_entries_set = B_TRUE;
		break;
	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}
	return (num_entries);
#else
	return (MAXMAPS);
#endif
}

#if !defined(__xpv)
static uint32_t
dboot_efi_to_smap_type(int index, uint32_t type)
{
	uint64_t addr;

	/*
	 * ACPI 6.1 tells the lower memory should be reported as
	 * normal memory, so we enforce page 0 type even as
	 * vmware maps it as acpi reclaimable.
	 */
	if (dboot_multiboot2_efi_mmap_get_base(mb2_info, index, &addr)) {
		if (addr == 0)
			return (1);
	}

	/* translate UEFI memory types to SMAP types */
	switch (type) {
	case EfiLoaderCode:
	case EfiLoaderData:
	case EfiBootServicesCode:
	case EfiBootServicesData:
	case EfiConventionalMemory:
		return (1);
	case EfiReservedMemoryType:
	case EfiRuntimeServicesCode:
	case EfiRuntimeServicesData:
	case EfiMemoryMappedIO:
	case EfiMemoryMappedIOPortSpace:
	case EfiPalCode:
	case EfiUnusableMemory:
		return (2);
	case EfiACPIReclaimMemory:
		return (3);
	case EfiACPIMemoryNVS:
		return (4);
	}

	return (2);
}
#endif

static uint32_t
dboot_loader_mmap_get_type(int index)
{
#if !defined(__xpv)
	mb_memory_map_t *mp, *mpend;
	uint32_t type;
	int i;

	switch (multiboot_version) {
	case 1:
		mp = (mb_memory_map_t *)(uintptr_t)mb_info->mmap_addr;
		mpend = (mb_memory_map_t *)(uintptr_t)
		    (mb_info->mmap_addr + mb_info->mmap_length);

		for (i = 0; mp < mpend && i != index; i++)
			mp = (mb_memory_map_t *)((uintptr_t)mp + mp->size +
			    sizeof (mp->size));
		if (mp >= mpend) {
			dboot_panic("dboot_loader_mmap_get_type(): index "
			    "out of bounds: %d\n", index);
		}
		return (mp->type);

	case 2:
		if (dboot_multiboot2_efi_mmap_get_type(mb2_info, index, &type))
			return (dboot_efi_to_smap_type(index, type));

		if (dboot_multiboot2_mmap_get_type(mb2_info, index, &type))
			return (type);

		dboot_panic("Can not get memory type for %d\n", index);

	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}
	return (0);
#else
	return (map_buffer[index].type);
#endif
}

static uint64_t
dboot_loader_mmap_get_base(int index)
{
#if !defined(__xpv)
	mb_memory_map_t *mp, *mpend;
	uint64_t base;
	int i;

	switch (multiboot_version) {
	case 1:
		mp = (mb_memory_map_t *)mb_info->mmap_addr;
		mpend = (mb_memory_map_t *)
		    (mb_info->mmap_addr + mb_info->mmap_length);

		for (i = 0; mp < mpend && i != index; i++)
			mp = (mb_memory_map_t *)((uintptr_t)mp + mp->size +
			    sizeof (mp->size));
		if (mp >= mpend) {
			dboot_panic("dboot_loader_mmap_get_base(): index "
			    "out of bounds: %d\n", index);
		}
		return (((uint64_t)mp->base_addr_high << 32) +
		    (uint64_t)mp->base_addr_low);

	case 2:
		if (dboot_multiboot2_efi_mmap_get_base(mb2_info, index, &base))
			return (base);

		if (dboot_multiboot2_mmap_get_base(mb2_info, index, &base))
			return (base);

		dboot_panic("Can not get memory address for %d\n", index);

	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}
	return (0);
#else
	return (((uint64_t)map_buffer[index].base_addr_high << 32) +
	    (uint64_t)map_buffer[index].base_addr_low);
#endif
}

static uint64_t
dboot_loader_mmap_get_length(int index)
{
#if !defined(__xpv)
	mb_memory_map_t *mp, *mpend;
	uint64_t length;
	int i;

	switch (multiboot_version) {
	case 1:
		mp = (mb_memory_map_t *)mb_info->mmap_addr;
		mpend = (mb_memory_map_t *)
		    (mb_info->mmap_addr + mb_info->mmap_length);

		for (i = 0; mp < mpend && i != index; i++)
			mp = (mb_memory_map_t *)((uintptr_t)mp + mp->size +
			    sizeof (mp->size));
		if (mp >= mpend) {
			dboot_panic("dboot_loader_mmap_get_length(): index "
			    "out of bounds: %d\n", index);
		}
		return (((uint64_t)mp->length_high << 32) +
		    (uint64_t)mp->length_low);

	case 2:
		if (dboot_multiboot2_efi_mmap_get_length(mb2_info,
		    index, &length))
			return (length);

		if (dboot_multiboot2_mmap_get_length(mb2_info,
		    index, &length))
			return (length);

		dboot_panic("Can not get memory length for %d\n", index);

	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}
	return (0);
#else
	return (((uint64_t)map_buffer[index].length_high << 32) +
	    (uint64_t)map_buffer[index].length_low);
#endif
}

static void
build_pcimemlists(void)
{
	uint64_t page_offset = MMU_PAGEOFFSET;	/* needs to be 64 bits */
	uint64_t start;
	uint64_t end;
	int i, num;

	if (prom_debug)
		dboot_printf("building pcimemlists:\n");
	/*
	 * initialize
	 */
	pcimemlists[0].addr = pci_lo_limit;
	pcimemlists[0].size = pci_hi_limit - pci_lo_limit;
	pcimemlists_used = 1;

	num = dboot_loader_mmap_entries();
	/*
	 * Fill in PCI memlists.
	 */
	for (i = 0; i < num; ++i) {
		start = dboot_loader_mmap_get_base(i);
		end = start + dboot_loader_mmap_get_length(i);

		if (prom_debug)
			dboot_printf("\ttype: %d %" PRIx64 "..%"
			    PRIx64 "\n", dboot_loader_mmap_get_type(i),
			    start, end);

		/*
		 * page align start and end
		 */
		start = (start + page_offset) & ~page_offset;
		end &= ~page_offset;
		if (end <= start)
			continue;

		exclude_from_pci(start, end);
	}

	/*
	 * Finish off the pcimemlist
	 */
	if (prom_debug) {
		for (i = 0; i < pcimemlists_used; ++i) {
			dboot_printf("pcimemlist entry 0x%" PRIx64 "..0x%"
			    PRIx64 "\n", pcimemlists[i].addr,
			    pcimemlists[i].addr + pcimemlists[i].size);
		}
	}
	pcimemlists[0].next = 0;
	pcimemlists[0].prev = 0;
	for (i = 1; i < pcimemlists_used; ++i) {
		pcimemlists[i].prev =
		    (native_ptr_t)(uintptr_t)(pcimemlists + i - 1);
		pcimemlists[i].next = 0;
		pcimemlists[i - 1].next =
		    (native_ptr_t)(uintptr_t)(pcimemlists + i);
	}
	bi->bi_pcimem = (native_ptr_t)(uintptr_t)pcimemlists;
	DBG(bi->bi_pcimem);
}

#if defined(__xpv)
static void
init_dboot_alloc(void)
{
	int	local;	/* variables needed to find start region */
	xen_memory_map_t map;

	DBG_MSG("Entered init_dboot_alloc()\n");

	/*
	 * Free memory follows the stack. There's at least 512KB of scratch
	 * space, rounded up to at least 2Mb alignment.  That should be enough
	 * for the page tables we'll need to build.  The nucleus memory is
	 * allocated last and will be outside the addressible range.  We'll
	 * switch to new page tables before we unpack the kernel
	 */
	alloc_addr = RNDUP((paddr_t)(uintptr_t)&local, MMU_PAGESIZE);
	DBG(alloc_addr);
	alloc_end = RNDUP((paddr_t)alloc_addr + 512 * 1024, TWO_MEG);
	DBG(alloc_end);

	/*
	 * For paranoia, leave some space between hypervisor data and ours.
	 * Use 500 instead of 512.
	 */
	alloc_addr = alloc_end - 500 * 1024;
	DBG(alloc_addr);

	/*
	 * The domain builder gives us at most 1 module
	 */
	DBG(xen_info->mod_len);
	if (xen_info->mod_len > 0) {
		DBG(xen_info->mod_start);
		modules[0].bm_addr =
		    (native_ptr_t)(uintptr_t)xen_info->mod_start;
		modules[0].bm_size = xen_info->mod_len;
		bi->bi_module_cnt = 1;
		bi->bi_modules = (native_ptr_t)(uintptr_t)modules;
	} else {
		bi->bi_module_cnt = 0;
		bi->bi_modules = (native_ptr_t)(uintptr_t)NULL;
	}
	DBG(bi->bi_module_cnt);
	DBG(bi->bi_modules);

	DBG(xen_info->mfn_list);
	DBG(xen_info->nr_pages);
	max_mem = (paddr_t)xen_info->nr_pages << MMU_PAGESHIFT;
	DBG(max_mem);

	/*
	 * Using pseudo-physical addresses, so only 1 memlist element
	 */
	memlists[0].addr = 0;
	DBG(memlists[0].addr);
	memlists[0].size = max_mem;
	DBG(memlists[0].size);
	memlists_used = 1;
	DBG(memlists_used);

	/*
	 * finish building physinstall list
	 */
	sort_physinstall();

	/*
	 * build bios reserved memlists
	 */
	build_rsvdmemlists();

	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		/*
		 * build PCI Memory list
		 */
		map.nr_entries = MAXMAPS;
		/*LINTED: constant in conditional context*/
		set_xen_guest_handle(map.buffer, map_buffer);
		if (HYPERVISOR_memory_op(XENMEM_machine_memory_map, &map) != 0)
			dboot_panic("getting XENMEM_machine_memory_map failed");
		build_pcimemlists();
	}
}

#else	/* !__xpv */

static void
dboot_multiboot1_xboot_consinfo(void)
{
	fb->framebuffer = 0;
}

static void
dboot_multiboot2_xboot_consinfo(void)
{
	multiboot_tag_framebuffer_t *fbtag;
	fbtag = dboot_multiboot2_find_tag(mb2_info,
	    MULTIBOOT_TAG_TYPE_FRAMEBUFFER);
	fb->framebuffer = (uint64_t)(uintptr_t)fbtag;
}

static int
dboot_multiboot_modcount(void)
{
	switch (multiboot_version) {
	case 1:
		return (mb_info->mods_count);

	case 2:
		return (dboot_multiboot2_modcount(mb2_info));

	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}
	return (0);
}

static uint32_t
dboot_multiboot_modstart(int index)
{
	switch (multiboot_version) {
	case 1:
		return (((mb_module_t *)mb_info->mods_addr)[index].mod_start);

	case 2:
		return (dboot_multiboot2_modstart(mb2_info, index));

	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}
	return (0);
}

static uint32_t
dboot_multiboot_modend(int index)
{
	switch (multiboot_version) {
	case 1:
		return (((mb_module_t *)mb_info->mods_addr)[index].mod_end);

	case 2:
		return (dboot_multiboot2_modend(mb2_info, index));

	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}
	return (0);
}

static char *
dboot_multiboot_modcmdline(int index)
{
	switch (multiboot_version) {
	case 1:
		return ((char *)((mb_module_t *)
		    mb_info->mods_addr)[index].mod_name);

	case 2:
		return (dboot_multiboot2_modcmdline(mb2_info, index));

	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}
	return (0);
}

/*
 * Find the modules used by console setup.
 * Since we need the console to print early boot messages, the console is set up
 * before anything else and therefore we need to pick up the needed modules.
 *
 * Note, we just will search for and if found, will pass the modules
 * to console setup, the proper module list processing will happen later.
 * Currently used modules are boot environment and console font.
 */
static void
dboot_find_console_modules(void)
{
	int i, modcount;
	uint32_t mod_start, mod_end;
	char *cmdline;

	modcount = dboot_multiboot_modcount();
	bi->bi_module_cnt = 0;
	for (i = 0; i < modcount; ++i) {
		cmdline = dboot_multiboot_modcmdline(i);
		if (cmdline == NULL)
			continue;

		if (strstr(cmdline, "type=console-font") != NULL)
			modules[bi->bi_module_cnt].bm_type = BMT_FONT;
		else if (strstr(cmdline, "type=environment") != NULL)
			modules[bi->bi_module_cnt].bm_type = BMT_ENV;
		else
			continue;

		mod_start = dboot_multiboot_modstart(i);
		mod_end = dboot_multiboot_modend(i);
		modules[bi->bi_module_cnt].bm_addr =
		    (native_ptr_t)(uintptr_t)mod_start;
		modules[bi->bi_module_cnt].bm_size = mod_end - mod_start;
		modules[bi->bi_module_cnt].bm_name =
		    (native_ptr_t)(uintptr_t)NULL;
		modules[bi->bi_module_cnt].bm_hash =
		    (native_ptr_t)(uintptr_t)NULL;
		bi->bi_module_cnt++;
	}
	if (bi->bi_module_cnt != 0)
		bi->bi_modules = (native_ptr_t)(uintptr_t)modules;
}

static boolean_t
dboot_multiboot_basicmeminfo(uint32_t *lower, uint32_t *upper)
{
	boolean_t rv = B_FALSE;

	switch (multiboot_version) {
	case 1:
		if (mb_info->flags & 0x01) {
			*lower = mb_info->mem_lower;
			*upper = mb_info->mem_upper;
			rv = B_TRUE;
		}
		break;

	case 2:
		return (dboot_multiboot2_basicmeminfo(mb2_info, lower, upper));

	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}
	return (rv);
}

static uint8_t
dboot_a2h(char v)
{
	if (v >= 'a')
		return (v - 'a' + 0xa);
	else if (v >= 'A')
		return (v - 'A' + 0xa);
	else if (v >= '0')
		return (v - '0');
	else
		dboot_panic("bad ASCII hex character %c\n", v);

	return (0);
}

static void
digest_a2h(const char *ascii, uint8_t *digest)
{
	unsigned int i;

	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		digest[i] = dboot_a2h(ascii[i * 2]) << 4;
		digest[i] |= dboot_a2h(ascii[i * 2 + 1]);
	}
}

/*
 * Generate a SHA-1 hash of the first len bytes of image, and compare it with
 * the ASCII-format hash found in the 40-byte buffer at ascii.  If they
 * match, return 0, otherwise -1.  This works only for images smaller than
 * 4 GB, which should not be a problem.
 */
static int
check_image_hash(uint_t midx)
{
	const char *ascii;
	const void *image;
	size_t len;
	SHA1_CTX ctx;
	uint8_t digest[SHA1_DIGEST_LENGTH];
	uint8_t baseline[SHA1_DIGEST_LENGTH];
	unsigned int i;

	ascii = (const char *)(uintptr_t)modules[midx].bm_hash;
	image = (const void *)(uintptr_t)modules[midx].bm_addr;
	len = (size_t)modules[midx].bm_size;

	digest_a2h(ascii, baseline);

	SHA1Init(&ctx);
	SHA1Update(&ctx, image, len);
	SHA1Final(digest, &ctx);

	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		if (digest[i] != baseline[i])
			return (-1);
	}

	return (0);
}

static const char *
type_to_str(boot_module_type_t type)
{
	switch (type) {
	case BMT_ROOTFS:
		return ("rootfs");
	case BMT_FILE:
		return ("file");
	case BMT_HASH:
		return ("hash");
	case BMT_ENV:
		return ("environment");
	case BMT_FONT:
		return ("console-font");
	default:
		return ("unknown");
	}
}

static void
check_images(void)
{
	uint_t i;
	char displayhash[SHA1_ASCII_LENGTH + 1];

	for (i = 0; i < modules_used; i++) {
		if (prom_debug) {
			dboot_printf("module #%d: name %s type %s "
			    "addr %lx size %lx\n",
			    i, (char *)(uintptr_t)modules[i].bm_name,
			    type_to_str(modules[i].bm_type),
			    (ulong_t)modules[i].bm_addr,
			    (ulong_t)modules[i].bm_size);
		}

		if (modules[i].bm_type == BMT_HASH ||
		    modules[i].bm_hash == (native_ptr_t)(uintptr_t)NULL) {
			DBG_MSG("module has no hash; skipping check\n");
			continue;
		}
		(void) memcpy(displayhash,
		    (void *)(uintptr_t)modules[i].bm_hash,
		    SHA1_ASCII_LENGTH);
		displayhash[SHA1_ASCII_LENGTH] = '\0';
		if (prom_debug) {
			dboot_printf("checking expected hash [%s]: ",
			    displayhash);
		}

		if (check_image_hash(i) != 0)
			dboot_panic("hash mismatch!\n");
		else
			DBG_MSG("OK\n");
	}
}

/*
 * Determine the module's starting address, size, name, and type, and fill the
 * boot_modules structure.  This structure is used by the bop code, except for
 * hashes which are checked prior to transferring control to the kernel.
 */
static void
process_module(int midx)
{
	uint32_t mod_start = dboot_multiboot_modstart(midx);
	uint32_t mod_end = dboot_multiboot_modend(midx);
	char *cmdline = dboot_multiboot_modcmdline(midx);
	char *p, *q;

	if (prom_debug) {
		dboot_printf("\tmodule #%d: '%s' at 0x%lx, end 0x%lx\n",
		    midx, cmdline, (ulong_t)mod_start, (ulong_t)mod_end);
	}

	if (mod_start > mod_end) {
		dboot_panic("module #%d: module start address 0x%lx greater "
		    "than end address 0x%lx", midx,
		    (ulong_t)mod_start, (ulong_t)mod_end);
	}

	/*
	 * A brief note on lengths and sizes: GRUB, for reasons unknown, passes
	 * the address of the last valid byte in a module plus 1 as mod_end.
	 * This is of course a bug; the multiboot specification simply states
	 * that mod_start and mod_end "contain the start and end addresses of
	 * the boot module itself" which is pretty obviously not what GRUB is
	 * doing.  However, fixing it requires that not only this code be
	 * changed but also that other code consuming this value and values
	 * derived from it be fixed, and that the kernel and GRUB must either
	 * both have the bug or neither.  While there are a lot of combinations
	 * that will work, there are also some that won't, so for simplicity
	 * we'll just cope with the bug.  That means we won't actually hash the
	 * byte at mod_end, and we will expect that mod_end for the hash file
	 * itself is one greater than some multiple of 41 (40 bytes of ASCII
	 * hash plus a newline for each module).  We set bm_size to the true
	 * correct number of bytes in each module, achieving exactly this.
	 */

	modules[midx].bm_addr = (native_ptr_t)(uintptr_t)mod_start;
	modules[midx].bm_size = mod_end - mod_start;
	modules[midx].bm_name = (native_ptr_t)(uintptr_t)cmdline;
	modules[midx].bm_hash = (native_ptr_t)(uintptr_t)NULL;
	modules[midx].bm_type = BMT_FILE;

	if (cmdline == NULL) {
		modules[midx].bm_name = (native_ptr_t)(uintptr_t)noname;
		return;
	}

	p = cmdline;
	modules[midx].bm_name =
	    (native_ptr_t)(uintptr_t)strsep(&p, " \t\f\n\r");

	while (p != NULL) {
		q = strsep(&p, " \t\f\n\r");
		if (strncmp(q, "name=", 5) == 0) {
			if (q[5] != '\0' && !isspace(q[5])) {
				modules[midx].bm_name =
				    (native_ptr_t)(uintptr_t)(q + 5);
			}
			continue;
		}

		if (strncmp(q, "type=", 5) == 0) {
			if (q[5] == '\0' || isspace(q[5]))
				continue;
			q += 5;
			if (strcmp(q, "rootfs") == 0) {
				modules[midx].bm_type = BMT_ROOTFS;
			} else if (strcmp(q, "hash") == 0) {
				modules[midx].bm_type = BMT_HASH;
			} else if (strcmp(q, "environment") == 0) {
				modules[midx].bm_type = BMT_ENV;
			} else if (strcmp(q, "console-font") == 0) {
				modules[midx].bm_type = BMT_FONT;
			} else if (strcmp(q, "file") != 0) {
				dboot_printf("\tmodule #%d: unknown module "
				    "type '%s'; defaulting to 'file'\n",
				    midx, q);
			}
			continue;
		}

		if (strncmp(q, "hash=", 5) == 0) {
			if (q[5] != '\0' && !isspace(q[5])) {
				modules[midx].bm_hash =
				    (native_ptr_t)(uintptr_t)(q + 5);
			}
			continue;
		}

		dboot_printf("ignoring unknown option '%s'\n", q);
	}
}

/*
 * Backward compatibility: if there are exactly one or two modules, both
 * of type 'file' and neither with an embedded hash value, we have been
 * given the legacy style modules.  In this case we need to treat the first
 * module as a rootfs and the second as a hash referencing that module.
 * Otherwise, even if the configuration is invalid, we assume that the
 * operator knows what he's doing or at least isn't being bitten by this
 * interface change.
 */
static void
fixup_modules(void)
{
	if (modules_used == 0 || modules_used > 2)
		return;

	if (modules[0].bm_type != BMT_FILE ||
	    (modules_used > 1 && modules[1].bm_type != BMT_FILE)) {
		return;
	}

	if (modules[0].bm_hash != (native_ptr_t)(uintptr_t)NULL ||
	    (modules_used > 1 &&
	    modules[1].bm_hash != (native_ptr_t)(uintptr_t)NULL)) {
		return;
	}

	modules[0].bm_type = BMT_ROOTFS;
	if (modules_used > 1) {
		modules[1].bm_type = BMT_HASH;
		modules[1].bm_name = modules[0].bm_name;
	}
}

/*
 * For modules that do not have assigned hashes but have a separate hash module,
 * find the assigned hash module and set the primary module's bm_hash to point
 * to the hash data from that module.  We will then ignore modules of type
 * BMT_HASH from this point forward.
 */
static void
assign_module_hashes(void)
{
	uint_t i, j;

	for (i = 0; i < modules_used; i++) {
		if (modules[i].bm_type == BMT_HASH ||
		    modules[i].bm_hash != (native_ptr_t)(uintptr_t)NULL) {
			continue;
		}

		for (j = 0; j < modules_used; j++) {
			if (modules[j].bm_type != BMT_HASH ||
			    strcmp((char *)(uintptr_t)modules[j].bm_name,
			    (char *)(uintptr_t)modules[i].bm_name) != 0) {
				continue;
			}

			if (modules[j].bm_size < SHA1_ASCII_LENGTH) {
				dboot_printf("Short hash module of length "
				    "0x%lx bytes; ignoring\n",
				    (ulong_t)modules[j].bm_size);
			} else {
				modules[i].bm_hash = modules[j].bm_addr;
			}
			break;
		}
	}
}

/*
 * Walk through the module information finding the last used address.
 * The first available address will become the top level page table.
 */
static void
dboot_process_modules(void)
{
	int i, modcount;

	DBG_MSG("\nFinding Modules\n");
	modcount = dboot_multiboot_modcount();
	if (modcount > MAX_BOOT_MODULES) {
		dboot_panic("Too many modules (%d) -- the maximum is %d.",
		    modcount, MAX_BOOT_MODULES);
	}

	/*
	 * search the modules to find the last used address
	 * we'll build the module list while we're walking through here
	 */
	for (i = 0; i < modcount; ++i) {
		process_module(i);
		modules_used++;
	}
	bi->bi_modules = (native_ptr_t)(uintptr_t)modules;
	DBG(bi->bi_modules);
	bi->bi_module_cnt = modcount;
	DBG(bi->bi_module_cnt);

	fixup_modules();
	assign_module_hashes();
	check_images();
}

#define	CORRUPT_REGION_START	0xc700000
#define	CORRUPT_REGION_SIZE	0x100000
#define	CORRUPT_REGION_END	(CORRUPT_REGION_START + CORRUPT_REGION_SIZE)

static void
dboot_add_memlist(struct boot_memlist *mlist, uint_t *indexp,
    uint32_t type, uint64_t start, uint64_t end)
{
	if (type != 1) {
		goto out;
	}

	if (end > max_mem)
		max_mem = end;

	/*
	 * Well, this is sad.  On some systems, there is a region of memory that
	 * can be corrupted until some number of seconds after we have booted.
	 * And the BIOS doesn't tell us that this memory is unsafe to use.  And
	 * we don't know how long it's dangerous.  So we'll chop out this range
	 * from any memory list that would otherwise be usable.  Note that any
	 * system of this type will give us the new-style (0x40) memlist, so we
	 * need not fix up the other path below.
	 *
	 * However, if we're boot-loaded from something that doesn't have a
	 * RICHMOND-16 workaround (which on many systems is just fine), it could
	 * actually use this region for the boot modules; if we remove it from
	 * the memlist, we'll keel over when trying to access the region.
	 *
	 * So, if we see that a module intersects the region, we presume it's
	 * OK.
	 */

	if (find_boot_prop("disable-RICHMOND-16") != NULL)
		goto out;

	for (uint32_t i = 0; i < bi->bi_module_cnt; i++) {
		native_ptr_t mod_start = modules[i].bm_addr;
		native_ptr_t mod_end = modules[i].bm_addr + modules[i].bm_size;

		if (ranges_intersect(mod_start, mod_end, CORRUPT_REGION_START,
		    CORRUPT_REGION_END)) {
			if (prom_debug) {
				dboot_printf("disabling RICHMOND-16 workaround "
				"due to module #%d: "
				"name %s addr %lx size %lx\n",
				    i, (char *)(uintptr_t)modules[i].bm_name,
				    (ulong_t)modules[i].bm_addr,
				    (ulong_t)modules[i].bm_size);
			}
			goto out;
		}
	}

	if (start < CORRUPT_REGION_START && end > CORRUPT_REGION_START) {
		if (memlists_used > MAX_MEMLIST)
			dboot_panic("too many memlists");

		/*
		 * Add segment [start, CORRUPT_REGION_START]
		 */
		if ((mlist[memlists_used].addr +
		    mlist[memlists_used].size) == start) {
			mlist[memlists_used].size =
			    CORRUPT_REGION_START - mlist[memlists_used].addr;
		} else {
			if (mlist[memlists_used].size != 0)
				memlists_used++;
			if (memlists_used > MAX_MEMLIST)
				dboot_panic("too many memlists");

			mlist[memlists_used].addr = start;
			mlist[memlists_used].size =
			    CORRUPT_REGION_START - start;
		}

		/*
		 * Add segment [CORRUPT_REGION_END, end]
		 */
		if (end > CORRUPT_REGION_END)
			start = CORRUPT_REGION_END;
		else
			return;
	}

	if (start >= CORRUPT_REGION_START && start < CORRUPT_REGION_END) {
		if (end <= CORRUPT_REGION_END)
			return;
		start = CORRUPT_REGION_END;
	}

out:
	if (memlists_used > MAX_MEMLIST)
		dboot_panic("too many memlists");
	if (rsvdmemlists_used > MAX_MEMLIST)
		dboot_panic("too many rsvdmemlists");

	if ((mlist[*indexp].addr + mlist[*indexp].size) == start) {
		mlist[*indexp].size = end - mlist[*indexp].addr;
		return;
	}
	/* do we need new entry? */
	if (mlist[*indexp].size != 0) {
		*indexp = *indexp + 1;
		if (*indexp > MAX_MEMLIST)
			return;
	}

	mlist[*indexp].addr = start;
	mlist[*indexp].size = end - start;
}

/*
 * We then build the phys_install memlist from the multiboot information.
 */
static void
dboot_process_mmap(void)
{
	uint64_t start;
	uint64_t end;
	uint64_t page_offset = MMU_PAGEOFFSET;	/* needs to be 64 bits */
	uint32_t lower, upper, type;
	int i, mmap_entries;

	/*
	 * Walk through the memory map from multiboot and build our memlist
	 * structures. Note these will have native format pointers.
	 */
	DBG_MSG("\nFinding Memory Map\n");
	num_entries = 0;
	num_entries_set = B_FALSE;
	max_mem = 0;
	if ((mmap_entries = dboot_loader_mmap_entries()) > 0) {
		for (i = 0; i < mmap_entries; i++) {
			start = dboot_loader_mmap_get_base(i);
			end = start + dboot_loader_mmap_get_length(i);
			type = dboot_loader_mmap_get_type(i);

			if (prom_debug)
				dboot_printf("\ttype: %u %" PRIx64 "..%"
				    PRIx64 "\n", type, start, end);

			/*
			 * page align start and end
			 */
			start = (start + page_offset) & ~page_offset;
			end &= ~page_offset;
			if (end <= start)
				continue;

			/*
			 * only type 1 is usable RAM
			 */
			switch (type) {
			case 1:
				dboot_add_memlist(memlists, &memlists_used,
				    type, start, end);
				break;
			case 2:
				dboot_add_memlist(rsvdmemlists,
				    &rsvdmemlists_used,
				    type, start, end);
				break;
			default:
				continue;
			}
		}

		if (memlists[memlists_used].size != 0) {
			memlists_used++;
		}
		if (rsvdmemlists[rsvdmemlists_used].size != 0) {
			rsvdmemlists_used++;
		}

		if (prom_debug) {
			for (i = 0; i < memlists_used; i++) {
				dboot_printf("memlists[%u] %"
				    PRIx64 "..%" PRIx64 "\n",
				    i,
				    memlists[i].addr,
				    memlists[i].size);
			}
			for (i = 0; i < rsvdmemlists_used; i++) {
				dboot_printf("rsvdmemlists[%u] %"
				    PRIx64 "..%" PRIx64 "\n",
				    i,
				    rsvdmemlists[i].addr,
				    rsvdmemlists[i].size);
			}
		}

		build_pcimemlists();
	} else if (dboot_multiboot_basicmeminfo(&lower, &upper)) {
		DBG(lower);
		memlists[memlists_used].addr = 0;
		memlists[memlists_used].size = lower * 1024;
		++memlists_used;
		DBG(upper);
		memlists[memlists_used].addr = 1024 * 1024;
		memlists[memlists_used].size = upper * 1024;
		++memlists_used;

		/*
		 * Old platform - assume I/O space at the end of memory.
		 */
		pcimemlists[0].addr = (upper * 1024) + (1024 * 1024);
		pcimemlists[0].size = pci_hi_limit - pcimemlists[0].addr;
		pcimemlists[0].next = 0;
		pcimemlists[0].prev = 0;
		bi->bi_pcimem = (native_ptr_t)(uintptr_t)pcimemlists;
		DBG(bi->bi_pcimem);
	} else {
		dboot_panic("No memory info from boot loader!!!");
	}

	/*
	 * finish processing the physinstall list
	 */
	sort_physinstall();

	/*
	 * build bios reserved mem lists
	 */
	build_rsvdmemlists();
}

/*
 * The highest address is used as the starting point for dboot's simple
 * memory allocator.
 *
 * Finding the highest address in case of Multiboot 1 protocol is
 * quite painful in the sense that some information provided by
 * the multiboot info structure points to BIOS data, and some to RAM.
 *
 * The module list was processed and checked already by dboot_process_modules(),
 * so we will check the command line string and the memory map.
 *
 * This list of to be checked items is based on our current knowledge of
 * allocations made by grub1 and will need to be reviewed if there
 * are updates about the information provided by Multiboot 1.
 *
 * In the case of the Multiboot 2, our life is much simpler, as the MB2
 * information tag list is one contiguous chunk of memory.
 */
static paddr_t
dboot_multiboot1_highest_addr(void)
{
	paddr_t addr = (paddr_t)(uintptr_t)NULL;
	char *cmdl = (char *)mb_info->cmdline;

	if (mb_info->flags & MB_INFO_CMDLINE)
		addr = ((paddr_t)((uintptr_t)cmdl + strlen(cmdl) + 1));

	if (mb_info->flags & MB_INFO_MEM_MAP)
		addr = MAX(addr,
		    ((paddr_t)(mb_info->mmap_addr + mb_info->mmap_length)));
	return (addr);
}

static uint64_t
dboot_multiboot_highest_addr(void)
{
	switch (multiboot_version) {
	case 1:
		return (dboot_multiboot1_highest_addr());
		break;
	case 2:
		return (dboot_multiboot2_highest_addr(mb2_info));
		break;
	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}
}

/*
 * Set up our simple physical memory allocator.  This is used to allocate both
 * the kernel nucleus (ksize) and our page table pages.
 *
 * We need to find a contiguous region in the memlists that is below 4Gb (as
 * we're 32-bit and need to use the addresses), and isn't otherwise in use by
 * dboot, multiboot allocations, or boot modules. The memlist is sorted and
 * merged by this point.
 *
 * Historically, this code always did the allocations past the end of the
 * highest used address, even if there was space below.  For reasons unclear, if
 * we don't do this, then we get massive corruption during early kernel boot.
 *
 * Note that find_kalloc_start() starts its search at the end of this
 * allocation.
 *
 * This all falls apart horribly on some EFI systems booting under iPXE, where
 * we end up with boot module allocation such that there is no room between the
 * highest used address and our 4Gb limit. To that end, we have an iPXE hack
 * that limits the maximum address used by its allocations in an attempt to give
 * us room.
 */
static void
init_dboot_alloc(void)
{
	extern char _end[];

	DBG_MSG("Entered init_dboot_alloc()\n");

	dboot_process_modules();
	dboot_process_mmap();

	size_t align = FOUR_MEG;

	/*
	 * We need enough alloc space for the nucleus memory...
	 */
	size_t size = RNDUP(ksize, align);

	/*
	 * And enough page table pages to cover potentially 4Gb. Each leaf PT
	 * covers 2Mb, so we need a maximum of 2048 pages for those. Next level
	 * up each covers 1Gb, and so on, so we'll just add a little slop (which
	 * gets aligned up anyway).
	 */
	size += RNDUP(MMU_PAGESIZE * (2048 + 256), align);

	uint64_t start = MAX(dboot_multiboot_highest_addr(),
	    (paddr_t)(uintptr_t)&_end);
	start = RNDUP(start, align);

	/*
	 * As mentioned above, only start our search after all the boot modules.
	 */
	for (uint_t i = 0; i < bi->bi_module_cnt; i++) {
		native_ptr_t mod_end = modules[i].bm_addr + modules[i].bm_size;

		start = MAX(start, RNDUP(mod_end, MMU_PAGESIZE));
	}

	uint64_t end = start + size;

	DBG(start);
	DBG(end);

	for (uint_t i = 0; i < memlists_used; i++) {
		uint64_t ml_start = memlists[i].addr;
		uint64_t ml_end = memlists[i].addr + memlists[i].size;

		/*
		 * If we're past our starting point for search, begin at this
		 * memlist.
		 */
		if (start < ml_start) {
			start = RNDUP(ml_start, align);
			end = start + size;
		}

		if (end >= (uint64_t)UINT32_MAX) {
			dboot_panic("couldn't find alloc space below 4Gb");
		}

		if (end < ml_end) {
			alloc_addr = start;
			alloc_end = end;
			DBG(alloc_addr);
			DBG(alloc_end);
			return;
		}
	}

	dboot_panic("couldn't find alloc space in memlists");
}

static int
dboot_same_guids(efi_guid_t *g1, efi_guid_t *g2)
{
	int i;

	if (g1->time_low != g2->time_low)
		return (0);
	if (g1->time_mid != g2->time_mid)
		return (0);
	if (g1->time_hi_and_version != g2->time_hi_and_version)
		return (0);
	if (g1->clock_seq_hi_and_reserved != g2->clock_seq_hi_and_reserved)
		return (0);
	if (g1->clock_seq_low != g2->clock_seq_low)
		return (0);

	for (i = 0; i < 6; i++) {
		if (g1->node_addr[i] != g2->node_addr[i])
			return (0);
	}
	return (1);
}

static void
process_efi32(EFI_SYSTEM_TABLE32 *efi)
{
	uint32_t entries;
	EFI_CONFIGURATION_TABLE32 *config;
	efi_guid_t VendorGuid;
	int i;

	entries = efi->NumberOfTableEntries;
	config = (EFI_CONFIGURATION_TABLE32 *)(uintptr_t)
	    efi->ConfigurationTable;

	for (i = 0; i < entries; i++) {
		(void) memcpy(&VendorGuid, &config[i].VendorGuid,
		    sizeof (VendorGuid));
		if (dboot_same_guids(&VendorGuid, &smbios3)) {
			bi->bi_smbios = (native_ptr_t)(uintptr_t)
			    config[i].VendorTable;
		}
		if (bi->bi_smbios == 0 &&
		    dboot_same_guids(&VendorGuid, &smbios)) {
			bi->bi_smbios = (native_ptr_t)(uintptr_t)
			    config[i].VendorTable;
		}
		if (dboot_same_guids(&VendorGuid, &acpi2)) {
			bi->bi_acpi_rsdp = (native_ptr_t)(uintptr_t)
			    config[i].VendorTable;
		}
		if (bi->bi_acpi_rsdp == 0 &&
		    dboot_same_guids(&VendorGuid, &acpi1)) {
			bi->bi_acpi_rsdp = (native_ptr_t)(uintptr_t)
			    config[i].VendorTable;
		}
	}
}

static void
process_efi64(EFI_SYSTEM_TABLE64 *efi)
{
	uint64_t entries;
	EFI_CONFIGURATION_TABLE64 *config;
	efi_guid_t VendorGuid;
	int i;

	entries = efi->NumberOfTableEntries;
	config = (EFI_CONFIGURATION_TABLE64 *)(uintptr_t)
	    efi->ConfigurationTable;

	for (i = 0; i < entries; i++) {
		(void) memcpy(&VendorGuid, &config[i].VendorGuid,
		    sizeof (VendorGuid));
		if (dboot_same_guids(&VendorGuid, &smbios3)) {
			bi->bi_smbios = (native_ptr_t)(uintptr_t)
			    config[i].VendorTable;
		}
		if (bi->bi_smbios == 0 &&
		    dboot_same_guids(&VendorGuid, &smbios)) {
			bi->bi_smbios = (native_ptr_t)(uintptr_t)
			    config[i].VendorTable;
		}
		/* Prefer acpi v2+ over v1. */
		if (dboot_same_guids(&VendorGuid, &acpi2)) {
			bi->bi_acpi_rsdp = (native_ptr_t)(uintptr_t)
			    config[i].VendorTable;
		}
		if (bi->bi_acpi_rsdp == 0 &&
		    dboot_same_guids(&VendorGuid, &acpi1)) {
			bi->bi_acpi_rsdp = (native_ptr_t)(uintptr_t)
			    config[i].VendorTable;
		}
	}
}

static void
dboot_multiboot_get_fwtables(void)
{
	multiboot_tag_new_acpi_t *nacpitagp;
	multiboot_tag_old_acpi_t *oacpitagp;
	multiboot_tag_efi64_t *efi64tagp = NULL;
	multiboot_tag_efi32_t *efi32tagp = NULL;

	/* no fw tables from multiboot 1 */
	if (multiboot_version != 2)
		return;

	efi64tagp = (multiboot_tag_efi64_t *)
	    dboot_multiboot2_find_tag(mb2_info, MULTIBOOT_TAG_TYPE_EFI64);
	if (efi64tagp != NULL) {
		bi->bi_uefi_arch = XBI_UEFI_ARCH_64;
		bi->bi_uefi_systab = (native_ptr_t)(uintptr_t)
		    efi64tagp->mb_pointer;
		process_efi64((EFI_SYSTEM_TABLE64 *)(uintptr_t)
		    efi64tagp->mb_pointer);
	} else {
		efi32tagp = (multiboot_tag_efi32_t *)
		    dboot_multiboot2_find_tag(mb2_info,
		    MULTIBOOT_TAG_TYPE_EFI32);
		if (efi32tagp != NULL) {
			bi->bi_uefi_arch = XBI_UEFI_ARCH_32;
			bi->bi_uefi_systab = (native_ptr_t)(uintptr_t)
			    efi32tagp->mb_pointer;
			process_efi32((EFI_SYSTEM_TABLE32 *)(uintptr_t)
			    efi32tagp->mb_pointer);
		}
	}

	/*
	 * The multiboot2 info contains a copy of the RSDP; stash a pointer to
	 * it (see find_rsdp() in fakebop).
	 */
	nacpitagp = (multiboot_tag_new_acpi_t *)
	    dboot_multiboot2_find_tag(mb2_info, MULTIBOOT_TAG_TYPE_ACPI_NEW);
	oacpitagp = (multiboot_tag_old_acpi_t *)
	    dboot_multiboot2_find_tag(mb2_info, MULTIBOOT_TAG_TYPE_ACPI_OLD);

	if (nacpitagp != NULL) {
		bi->bi_acpi_rsdp_copy = (native_ptr_t)(uintptr_t)
		    &nacpitagp->mb_rsdp[0];
	} else if (oacpitagp != NULL) {
		bi->bi_acpi_rsdp_copy = (native_ptr_t)(uintptr_t)
		    &oacpitagp->mb_rsdp[0];
	}
}

/* print out EFI version string with newline */
static void
dboot_print_efi_version(uint32_t ver)
{
	int rev;

	dboot_printf("%d.", EFI_REV_MAJOR(ver));

	rev = EFI_REV_MINOR(ver);
	if ((rev % 10) != 0) {
		dboot_printf("%d.%d\n", rev / 10, rev % 10);
	} else {
		dboot_printf("%d\n", rev / 10);
	}
}

static void
print_efi32(EFI_SYSTEM_TABLE32 *efi)
{
	uint16_t *data;
	EFI_CONFIGURATION_TABLE32 *conf;
	int i;

	dboot_printf("EFI32 signature: %llx\n",
	    (unsigned long long)efi->Hdr.Signature);
	dboot_printf("EFI system version: ");
	dboot_print_efi_version(efi->Hdr.Revision);
	dboot_printf("EFI system vendor: ");
	data = (uint16_t *)(uintptr_t)efi->FirmwareVendor;
	for (i = 0; data[i] != 0; i++)
		dboot_printf("%c", (char)data[i]);
	dboot_printf("\nEFI firmware revision: ");
	dboot_print_efi_version(efi->FirmwareRevision);
	dboot_printf("EFI system table number of entries: %d\n",
	    efi->NumberOfTableEntries);
	conf = (EFI_CONFIGURATION_TABLE32 *)(uintptr_t)
	    efi->ConfigurationTable;
	for (i = 0; i < (int)efi->NumberOfTableEntries; i++) {
		dboot_printf("%d: 0x%x 0x%x 0x%x 0x%x 0x%x", i,
		    conf[i].VendorGuid.time_low,
		    conf[i].VendorGuid.time_mid,
		    conf[i].VendorGuid.time_hi_and_version,
		    conf[i].VendorGuid.clock_seq_hi_and_reserved,
		    conf[i].VendorGuid.clock_seq_low);
		dboot_printf(" 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
		    conf[i].VendorGuid.node_addr[0],
		    conf[i].VendorGuid.node_addr[1],
		    conf[i].VendorGuid.node_addr[2],
		    conf[i].VendorGuid.node_addr[3],
		    conf[i].VendorGuid.node_addr[4],
		    conf[i].VendorGuid.node_addr[5]);
	}
}

static void
print_efi64(EFI_SYSTEM_TABLE64 *efi)
{
	uint16_t *data;
	EFI_CONFIGURATION_TABLE64 *conf;
	int i;

	dboot_printf("EFI64 signature: %llx\n",
	    (unsigned long long)efi->Hdr.Signature);
	dboot_printf("EFI system version: ");
	dboot_print_efi_version(efi->Hdr.Revision);
	dboot_printf("EFI system vendor: ");
	data = (uint16_t *)(uintptr_t)efi->FirmwareVendor;
	for (i = 0; data[i] != 0; i++)
		dboot_printf("%c", (char)data[i]);
	dboot_printf("\nEFI firmware revision: ");
	dboot_print_efi_version(efi->FirmwareRevision);
	dboot_printf("EFI system table number of entries: %" PRIu64 "\n",
	    efi->NumberOfTableEntries);
	conf = (EFI_CONFIGURATION_TABLE64 *)(uintptr_t)
	    efi->ConfigurationTable;
	for (i = 0; i < (int)efi->NumberOfTableEntries; i++) {
		dboot_printf("%d: 0x%x 0x%x 0x%x 0x%x 0x%x", i,
		    conf[i].VendorGuid.time_low,
		    conf[i].VendorGuid.time_mid,
		    conf[i].VendorGuid.time_hi_and_version,
		    conf[i].VendorGuid.clock_seq_hi_and_reserved,
		    conf[i].VendorGuid.clock_seq_low);
		dboot_printf(" 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n",
		    conf[i].VendorGuid.node_addr[0],
		    conf[i].VendorGuid.node_addr[1],
		    conf[i].VendorGuid.node_addr[2],
		    conf[i].VendorGuid.node_addr[3],
		    conf[i].VendorGuid.node_addr[4],
		    conf[i].VendorGuid.node_addr[5]);
	}
}
#endif /* !__xpv */

/*
 * Simple memory allocator for aligned physical memory from the area provided by
 * init_dboot_alloc().  This is a simple bump allocator, and it's never directly
 * freed by dboot.
 */
static void *
dboot_alloc(uint32_t size, uint32_t align)
{
	uint32_t start = RNDUP(alloc_addr, align);

	size = RNDUP(size, MMU_PAGESIZE);

	if (start + size > alloc_end) {
		dboot_panic("%s: couldn't allocate 0x%x bytes aligned 0x%x "
		    "alloc_addr = 0x%llx, alloc_end = 0x%llx", __func__,
		    size, align, (u_longlong_t)alloc_addr,
		    (u_longlong_t)alloc_end);
	}

	alloc_addr = start + size;

	if (map_debug) {
		dboot_printf("%s(0x%x, 0x%x) = 0x%x\n", __func__, size,
		    align, start);
	}

	(void) memset((void *)(uintptr_t)start, 0, size);
	return ((void *)(uintptr_t)start);
}

static void *
page_alloc(void)
{
	return (dboot_alloc(MMU_PAGESIZE, MMU_PAGESIZE));
}

/*
 * This is where we tell the kernel to start physical allocations from, beyond
 * the end of our allocation area and all boot modules. It might be beyond 4Gb,
 * so we can't touch that area ourselves.
 *
 * We might set kalloc_start to the end of a memlist; if so make sure we skip it
 * along to the next one.
 *
 * This is making the massive assumption that there is a suitably large area for
 * kernel allocations past the end of the last boot module and the dboot
 * allocated region. Worse, we don't have a simple way to assert that is so.
 */
static paddr_t
find_kalloc_start(void)
{
	paddr_t kalloc_start = alloc_end;
	uint_t i;

	for (i = 0; i < bi->bi_module_cnt; i++) {
		native_ptr_t mod_end = modules[i].bm_addr + modules[i].bm_size;

		kalloc_start = MAX(kalloc_start, RNDUP(mod_end, MMU_PAGESIZE));
	}

	boot_map_end = kalloc_start;
	DBG(boot_map_end);

	for (i = 0; i < memlists_used; i++) {
		uint64_t ml_start = memlists[i].addr;
		uint64_t ml_end = memlists[i].addr + memlists[i].size;

		if (kalloc_start >= ml_end)
			continue;

		if (kalloc_start < ml_start)
			kalloc_start = ml_start;
		break;
	}

	if (i == memlists_used) {
		dboot_panic("fell off the end of memlists finding a "
		    "kalloc_start value > 0x%llx", (u_longlong_t)kalloc_start);
	}

	DBG(kalloc_start);

	return (kalloc_start);
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
	uint64_t start;
#if !defined(__xpv)
	uint32_t i;
	uint64_t end;
#endif	/* __xpv */

	/*
	 * If we're on metal, we need to create the top level pagetable.
	 */
#if defined(__xpv)
	top_page_table = (paddr_t)(uintptr_t)xen_info->pt_base;
#else /* __xpv */
	top_page_table = (paddr_t)(uintptr_t)page_alloc();
#endif /* __xpv */
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
	bi->bi_pt_window = (native_ptr_t)(uintptr_t)page_alloc();
	DBG(bi->bi_pt_window);
	bi->bi_pte_to_pt_window =
	    (native_ptr_t)(uintptr_t)find_pte(bi->bi_pt_window, NULL, 0, 0);
	DBG(bi->bi_pte_to_pt_window);

#if defined(__xpv)
	if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
		/* If this is a domU we're done. */
		DBG_MSG("\nPage tables constructed\n");
		return;
	}
#endif /* __xpv */

	/*
	 * We need 1:1 mappings for the lower 1M of memory to access
	 * BIOS tables used by a couple of drivers during boot.
	 *
	 * The following code works because our simple memory allocator
	 * only grows usage in an upwards direction.
	 *
	 * Note that by this point in boot some mappings for low memory
	 * may already exist because we've already accessed device in low
	 * memory.  (Specifically the video frame buffer and keyboard
	 * status ports.)  If we're booting on raw hardware then GRUB
	 * created these mappings for us.  If we're booting under a
	 * hypervisor then we went ahead and remapped these devices into
	 * memory allocated within dboot itself.
	 */
	if (map_debug)
		dboot_printf("1:1 map pa=0..1Meg\n");
	for (start = 0; start < 1024 * 1024; start += MMU_PAGESIZE) {
#if defined(__xpv)
		map_ma_at_va(start, start, 0);
#else /* __xpv */
		map_pa_at_va(start, start, 0);
#endif /* __xpv */
	}

#if !defined(__xpv)

	/*
	 * Map every valid memlist address up until boot_map_end: this will
	 * cover at least our alloc region and all boot modules.
	 */
	for (i = 0; i < memlists_used; ++i) {
		start = memlists[i].addr;
		end = start + memlists[i].size;

		if (map_debug)
			dboot_printf("1:1 map pa=%" PRIx64 "..%" PRIx64 "\n",
			    start, end);
		while (start < end && start < boot_map_end) {
			map_pa_at_va(start, start, 0);
			start += MMU_PAGESIZE;
		}
		if (start >= boot_map_end)
			break;
	}

	/*
	 * Map framebuffer memory as PT_NOCACHE as this is memory from a
	 * device and therefore must not be cached.
	 */
	if (fb != NULL && fb->framebuffer != 0) {
		multiboot_tag_framebuffer_t *fb_tagp;
		fb_tagp = (multiboot_tag_framebuffer_t *)(uintptr_t)
		    fb->framebuffer;

		start = fb_tagp->framebuffer_common.framebuffer_addr;
		end = start + fb_tagp->framebuffer_common.framebuffer_height *
		    fb_tagp->framebuffer_common.framebuffer_pitch;

		if (map_debug)
			dboot_printf("FB 1:1 map pa=%" PRIx64 "..%" PRIx64 "\n",
			    start, end);
		pte_bits |= PT_NOCACHE;
		if (PAT_support != 0)
			pte_bits |= PT_PAT_4K;

		while (start < end) {
			map_pa_at_va(start, start, 0);
			start += MMU_PAGESIZE;
		}
		pte_bits &= ~PT_NOCACHE;
		if (PAT_support != 0)
			pte_bits &= ~PT_PAT_4K;
	}
#endif /* !__xpv */

	DBG_MSG("\nPage tables constructed\n");
}

#define	NO_MULTIBOOT	\
"multiboot is no longer used to boot the Solaris Operating System.\n\
The grub entry should be changed to:\n\
kernel$ /platform/i86pc/kernel/$ISADIR/unix\n\
module$ /platform/i86pc/$ISADIR/boot_archive\n\
See http://illumos.org/msg/SUNOS-8000-AK for details.\n"

static void
dboot_init_xboot_consinfo(void)
{
	bi = &boot_info;

#if !defined(__xpv)
	fb = &framebuffer;
	bi->bi_framebuffer = (native_ptr_t)(uintptr_t)fb;

	switch (multiboot_version) {
	case 1:
		dboot_multiboot1_xboot_consinfo();
		break;
	case 2:
		dboot_multiboot2_xboot_consinfo();
		break;
	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}
	dboot_find_console_modules();
#endif
}

/*
 * Set up basic data from the boot loader.
 * The load_addr is part of AOUT kludge setup in dboot_grub.s, to support
 * 32-bit dboot code setup used to set up and start 64-bit kernel.
 * AOUT kludge does allow 32-bit boot loader, such as grub1, to load and
 * start 64-bit illumos kernel.
 */
static void
dboot_loader_init(void)
{
#if !defined(__xpv)
	mb_info = NULL;
	mb2_info = NULL;

	switch (mb_magic) {
	case MB_BOOTLOADER_MAGIC:
		multiboot_version = 1;
		mb_info = (multiboot_info_t *)(uintptr_t)mb_addr;
#if defined(_BOOT_TARGET_amd64)
		load_addr = mb_header.load_addr;
#endif
		break;

	case MULTIBOOT2_BOOTLOADER_MAGIC:
		multiboot_version = 2;
		mb2_info = (multiboot2_info_header_t *)(uintptr_t)mb_addr;
#if defined(_BOOT_TARGET_amd64)
		load_addr = mb2_load_addr;
#endif
		break;

	default:
		dboot_panic("Unknown bootloader magic: 0x%x\n", mb_magic);
		break;
	}
#endif	/* !defined(__xpv) */
}

/* Extract the kernel command line from [multi]boot information. */
static char *
dboot_loader_cmdline(void)
{
	char *line = NULL;

#if defined(__xpv)
	line = (char *)xen_info->cmd_line;
#else /* __xpv */

	switch (multiboot_version) {
	case 1:
		if (mb_info->flags & MB_INFO_CMDLINE)
			line = (char *)mb_info->cmdline;
		break;

	case 2:
		line = dboot_multiboot2_cmdline(mb2_info);
		break;

	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}

#endif /* __xpv */

	/*
	 * Make sure we have valid pointer so the string operations
	 * will not crash us.
	 */
	if (line == NULL)
		line = "";

	return (line);
}

static char *
dboot_loader_name(void)
{
#if defined(__xpv)
	return (NULL);
#else /* __xpv */
	multiboot_tag_string_t *tag;

	switch (multiboot_version) {
	case 1:
		return ((char *)(uintptr_t)mb_info->boot_loader_name);

	case 2:
		tag = dboot_multiboot2_find_tag(mb2_info,
		    MULTIBOOT_TAG_TYPE_BOOT_LOADER_NAME);
		return (tag->mb_string);
	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}

	return (NULL);
#endif /* __xpv */
}

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
	char *bootloader;
#if defined(__xpv)
	physdev_set_iopl_t set_iopl;
#endif /* __xpv */

	if (dboot_debug == 1)
		bcons_init(NULL);	/* Set very early console to ttya. */
	dboot_loader_init();
	/*
	 * At this point we are executing in a 32 bit real mode.
	 */

	bootloader = dboot_loader_name();
	cmdline = dboot_loader_cmdline();

#if defined(__xpv)
	/*
	 * For dom0, before we initialize the console subsystem we'll
	 * need to enable io operations, so set I/O priveldge level to 1.
	 */
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		set_iopl.iopl = 1;
		(void) HYPERVISOR_physdev_op(PHYSDEVOP_set_iopl, &set_iopl);
	}
#endif /* __xpv */

	dboot_init_xboot_consinfo();
	bi->bi_cmdline = (native_ptr_t)(uintptr_t)cmdline;
	bcons_init(bi);		/* Now we can set the real console. */

	prom_debug = (find_boot_prop("prom_debug") != NULL);
	map_debug = (find_boot_prop("map_debug") != NULL);

#if !defined(__xpv)
	dboot_multiboot_get_fwtables();
#endif
	DBG_MSG("\n\nillumos prekernel set: ");
	DBG_MSG(cmdline);
	DBG_MSG("\n");

	if (bootloader != NULL && prom_debug) {
		dboot_printf("Kernel loaded by: %s\n", bootloader);
#if !defined(__xpv)
		dboot_printf("Using multiboot %d boot protocol.\n",
		    multiboot_version);
#endif
	}

	if (strstr(cmdline, "multiboot") != NULL) {
		dboot_panic(NO_MULTIBOOT);
	}

	DBG((uintptr_t)bi);
#if !defined(__xpv)
	DBG((uintptr_t)mb_info);
	DBG((uintptr_t)mb2_info);
	if (mb2_info != NULL)
		DBG(mb2_info->mbi_total_size);
	DBG(bi->bi_acpi_rsdp);
	DBG(bi->bi_acpi_rsdp_copy);
	DBG(bi->bi_smbios);
	DBG(bi->bi_uefi_arch);
	DBG(bi->bi_uefi_systab);

	if (bi->bi_uefi_systab && prom_debug) {
		if (bi->bi_uefi_arch == XBI_UEFI_ARCH_64) {
			print_efi64((EFI_SYSTEM_TABLE64 *)(uintptr_t)
			    bi->bi_uefi_systab);
		} else {
			print_efi32((EFI_SYSTEM_TABLE32 *)(uintptr_t)
			    bi->bi_uefi_systab);
		}
	}
#endif

	/*
	 * Need correct target_kernel_text value
	 */
#if defined(_BOOT_TARGET_amd64)
	target_kernel_text = KERNEL_TEXT;
#endif
	DBG(target_kernel_text);

#if defined(__xpv)

	/*
	 * XXPV	Derive this stuff from CPUID / what the hypervisor has enabled
	 */

#if defined(_BOOT_TARGET_amd64)
	/*
	 * 64-bit hypervisor.
	 */
	amd64_support = 1;
	pae_support = 1;

#else	/* _BOOT_TARGET_amd64 */

	/*
	 * See if we are running on a PAE Hypervisor
	 */
	{
		xen_capabilities_info_t caps;

		if (HYPERVISOR_xen_version(XENVER_capabilities, &caps) != 0)
			dboot_panic("HYPERVISOR_xen_version(caps) failed");
		caps[sizeof (caps) - 1] = 0;
		if (prom_debug)
			dboot_printf("xen capabilities %s\n", caps);
		if (strstr(caps, "x86_32p") != NULL)
			pae_support = 1;
	}

#endif	/* _BOOT_TARGET_amd64 */
	{
		xen_platform_parameters_t p;

		if (HYPERVISOR_xen_version(XENVER_platform_parameters, &p) != 0)
			dboot_panic("HYPERVISOR_xen_version(parms) failed");
		DBG(p.virt_start);
		mfn_to_pfn_mapping = (pfn_t *)(xen_virt_start = p.virt_start);
	}

	/*
	 * The hypervisor loads stuff starting at 1Gig
	 */
	mfn_base = ONE_GIG;
	DBG(mfn_base);

	/*
	 * enable writable page table mode for the hypervisor
	 */
	if (HYPERVISOR_vm_assist(VMASST_CMD_enable,
	    VMASST_TYPE_writable_pagetables) < 0)
		dboot_panic("HYPERVISOR_vm_assist(writable_pagetables) failed");

	/*
	 * check for NX support
	 */
	if (pae_support) {
		uint32_t eax = 0x80000000;
		uint32_t edx = get_cpuid_edx(&eax);

		if (eax >= 0x80000001) {
			eax = 0x80000001;
			edx = get_cpuid_edx(&eax);
			if (edx & CPUID_AMD_EDX_NX)
				NX_support = 1;
		}
	}

	/*
	 * check for PAT support
	 */
	{
		uint32_t eax = 1;
		uint32_t edx = get_cpuid_edx(&eax);

		if (edx & CPUID_INTC_EDX_PAT)
			PAT_support = 1;
	}
#if !defined(_BOOT_TARGET_amd64)

	/*
	 * The 32-bit hypervisor uses segmentation to protect itself from
	 * guests. This means when a guest attempts to install a flat 4GB
	 * code or data descriptor the 32-bit hypervisor will protect itself
	 * by silently shrinking the segment such that if the guest attempts
	 * any access where the hypervisor lives a #gp fault is generated.
	 * The problem is that some applications expect a full 4GB flat
	 * segment for their current thread pointer and will use negative
	 * offset segment wrap around to access data. TLS support in linux
	 * brand is one example of this.
	 *
	 * The 32-bit hypervisor can catch the #gp fault in these cases
	 * and emulate the access without passing the #gp fault to the guest
	 * but only if VMASST_TYPE_4gb_segments is explicitly turned on.
	 * Seems like this should have been the default.
	 * Either way, we want the hypervisor -- and not Solaris -- to deal
	 * to deal with emulating these accesses.
	 */
	if (HYPERVISOR_vm_assist(VMASST_CMD_enable,
	    VMASST_TYPE_4gb_segments) < 0)
		dboot_panic("HYPERVISOR_vm_assist(4gb_segments) failed");
#endif	/* !_BOOT_TARGET_amd64 */

#else	/* __xpv */

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
		if (edx & CPUID_INTC_EDX_PAT)
			PAT_support = 1;

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
#endif /* __xpv */


#if defined(_BOOT_TARGET_amd64)
	if (amd64_support == 0)
		dboot_panic("long mode not supported, rebooting");
	else if (pae_support == 0)
		dboot_panic("long mode, but no PAE; rebooting");
#else
	/*
	 * Allow the command line to over-ride use of PAE for 32 bit.
	 */
	if (strstr(cmdline, "disablePAE=true") != NULL) {
		pae_support = 0;
		NX_support = 0;
		amd64_support = 0;
	}
#endif

	/*
	 * initialize the simple memory allocator
	 */
	init_dboot_alloc();

#if !defined(__xpv) && !defined(_BOOT_TARGET_amd64)
	/*
	 * disable PAE on 32 bit h/w w/o NX and < 4Gig of memory
	 */
	if (max_mem < FOUR_GIG && NX_support == 0)
		pae_support = 0;
#endif

	/*
	 * configure mmu information
	 */
	if (pae_support) {
		shift_amt = shift_amt_pae;
		ptes_per_table = 512;
		pte_size = 8;
		lpagesize = TWO_MEG;
#if defined(_BOOT_TARGET_amd64)
		top_level = 3;
#else
		top_level = 2;
#endif
	} else {
		pae_support = 0;
		NX_support = 0;
		shift_amt = shift_amt_nopae;
		ptes_per_table = 1024;
		pte_size = 4;
		lpagesize = FOUR_MEG;
		top_level = 1;
	}

	DBG(PAT_support);
	DBG(pge_support);
	DBG(NX_support);
	DBG(largepage_support);
	DBG(amd64_support);
	DBG(top_level);
	DBG(pte_size);
	DBG(ptes_per_table);
	DBG(lpagesize);

#if defined(__xpv)
	ktext_phys = ONE_GIG;		/* from UNIX Mapfile */
#else
	ktext_phys = FOUR_MEG;		/* from UNIX Mapfile */
#endif

#if !defined(__xpv) && defined(_BOOT_TARGET_amd64)
	/*
	 * For grub, copy kernel bits from the ELF64 file to final place.
	 */
	DBG_MSG("\nAllocating nucleus pages.\n");
	ktext_phys = (uintptr_t)dboot_alloc(ksize, FOUR_MEG);

	if (ktext_phys == 0)
		dboot_panic("failed to allocate aligned kernel memory");
	DBG(load_addr);
	if (dboot_elfload64(load_addr) != 0)
		dboot_panic("failed to parse kernel ELF image, rebooting");
#endif

	DBG(ktext_phys);

	paddr_t kalloc_start = find_kalloc_start();

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

#if defined(__xpv)

	bi->bi_next_paddr = kalloc_start - mfn_base;
	DBG(bi->bi_next_paddr);
	bi->bi_next_vaddr = (native_ptr_t)kalloc_start;
	DBG(bi->bi_next_vaddr);

	/*
	 * unmap unused pages in start area to make them available for DMA
	 */
	while (alloc_addr < alloc_end) {
		(void) HYPERVISOR_update_va_mapping(alloc_addr,
		    0, UVMF_INVLPG | UVMF_LOCAL);
		alloc_addr += MMU_PAGESIZE;
	}

	bi->bi_xen_start_info = (native_ptr_t)(uintptr_t)xen_info;
	DBG((uintptr_t)HYPERVISOR_shared_info);
	bi->bi_shared_info = (native_ptr_t)HYPERVISOR_shared_info;
	bi->bi_top_page_table = (uintptr_t)top_page_table - mfn_base;

#else /* __xpv */

	bi->bi_next_paddr = kalloc_start;
	DBG(bi->bi_next_paddr);
	bi->bi_next_vaddr = (native_ptr_t)kalloc_start;
	DBG(bi->bi_next_vaddr);
	bi->bi_mb_version = multiboot_version;

	switch (multiboot_version) {
	case 1:
		bi->bi_mb_info = (native_ptr_t)(uintptr_t)mb_info;
		break;
	case 2:
		bi->bi_mb_info = (native_ptr_t)(uintptr_t)mb2_info;
		break;
	default:
		dboot_panic("Unknown multiboot version: %d\n",
		    multiboot_version);
		break;
	}
	bi->bi_top_page_table = (uintptr_t)top_page_table;

#endif /* __xpv */

	bi->bi_kseg_size = FOUR_MEG;
	DBG(bi->bi_kseg_size);

#ifndef __xpv
	if (map_debug)
		dump_tables();
#endif

	DBG_MSG("\n\n*** DBOOT DONE -- back to asm to jump to kernel\n\n");

#ifndef __xpv
	/* Update boot info with FB data */
	fb->cursor.origin.x = fb_info.cursor.origin.x;
	fb->cursor.origin.y = fb_info.cursor.origin.y;
	fb->cursor.pos.x = fb_info.cursor.pos.x;
	fb->cursor.pos.y = fb_info.cursor.pos.y;
	fb->cursor.visible = fb_info.cursor.visible;
#endif
}
