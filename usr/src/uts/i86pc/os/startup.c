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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/vm.h>
#include <sys/conf.h>
#include <sys/avintr.h>
#include <sys/autoconf.h>
#include <sys/disp.h>
#include <sys/class.h>
#include <sys/bitmap.h>

#include <sys/privregs.h>

#include <sys/proc.h>
#include <sys/buf.h>
#include <sys/kmem.h>
#include <sys/kstat.h>

#include <sys/reboot.h>

#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/file.h>

#include <sys/procfs.h>

#include <sys/vfs.h>
#include <sys/cmn_err.h>
#include <sys/utsname.h>
#include <sys/debug.h>
#include <sys/kdi.h>

#include <sys/dumphdr.h>
#include <sys/bootconf.h>
#include <sys/varargs.h>
#include <sys/promif.h>
#include <sys/modctl.h>		/* for "procfs" hack */

#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddidmareq.h>
#include <sys/psw.h>
#include <sys/regset.h>
#include <sys/clock.h>
#include <sys/pte.h>
#include <sys/tss.h>
#include <sys/stack.h>
#include <sys/trap.h>
#include <sys/fp.h>
#include <vm/anon.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_dev.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/seg_map.h>
#include <vm/seg_vn.h>
#include <vm/seg_kp.h>
#include <sys/memnode.h>
#include <vm/vm_dep.h>
#include <sys/thread.h>
#include <sys/sysconf.h>
#include <sys/vm_machparam.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <vm/hat.h>
#include <vm/hat_i86.h>
#include <sys/pmem.h>
#include <sys/smp_impldefs.h>
#include <sys/x86_archext.h>
#include <sys/segments.h>
#include <sys/clconf.h>
#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/cpc_impl.h>
#include <sys/chip.h>
#include <sys/x86_archext.h>
#include <sys/cpu_module.h>
#include <sys/smbios.h>

extern void progressbar_init(void);
extern void progressbar_start(void);

/*
 * XXX make declaration below "static" when drivers no longer use this
 * interface.
 */
extern caddr_t p0_va;	/* Virtual address for accessing physical page 0 */

/*
 * segkp
 */
extern int segkp_fromheap;

static void kvm_init(void);
static void startup_init(void);
static void startup_memlist(void);
static void startup_modules(void);
static void startup_bop_gone(void);
static void startup_vm(void);
static void startup_end(void);

/*
 * Declare these as initialized data so we can patch them.
 */
#ifdef __i386
/*
 * Due to virtual address space limitations running in 32 bit mode, restrict
 * the amount of physical memory configured to a max of PHYSMEM32 pages (16g).
 *
 * If the physical max memory size of 64g were allowed to be configured, the
 * size of user virtual address space will be less than 1g. A limited user
 * address space greatly reduces the range of applications that can run.
 *
 * If more physical memory than PHYSMEM32 is required, users should preferably
 * run in 64 bit mode which has no virtual address space limitation issues.
 *
 * If 64 bit mode is not available (as in IA32) and/or more physical memory
 * than PHYSMEM32 is required in 32 bit mode, physmem can be set to the desired
 * value or to 0 (to configure all available memory) via eeprom(1M). kernelbase
 * should also be carefully tuned to balance out the need of the user
 * application while minimizing the risk of kernel heap exhaustion due to
 * kernelbase being set too high.
 */
#define	PHYSMEM32	0x400000

pgcnt_t physmem = PHYSMEM32;
#else
pgcnt_t physmem = 0;	/* memory size in pages, patch if you want less */
#endif
pgcnt_t obp_pages;	/* Memory used by PROM for its text and data */

char *kobj_file_buf;
int kobj_file_bufsize;	/* set in /etc/system */

/* Global variables for MP support. Used in mp_startup */
caddr_t	rm_platter_va;
uint32_t rm_platter_pa;

int	auto_lpg_disable = 1;

/*
 * Some CPUs have holes in the middle of the 64-bit virtual address range.
 */
uintptr_t hole_start, hole_end;

/*
 * kpm mapping window
 */
caddr_t kpm_vbase;
size_t  kpm_size;
static int kpm_desired = 0;		/* Do we want to try to use segkpm? */

/*
 * VA range that must be preserved for boot until we release all of its
 * mappings.
 */
#if defined(__amd64)
static void *kmem_setaside;
#endif

/*
 * Configuration parameters set at boot time.
 */

caddr_t econtig;		/* end of first block of contiguous kernel */

struct bootops		*bootops = 0;	/* passed in from boot */
struct bootops		**bootopsp;
struct boot_syscalls	*sysp;		/* passed in from boot */

char bootblock_fstype[16];

char kern_bootargs[OBP_MAXPATHLEN];

/*
 * new memory fragmentations are possible in startup() due to BOP_ALLOCs. this
 * depends on number of BOP_ALLOC calls made and requested size, memory size
 * combination and whether boot.bin memory needs to be freed.
 */
#define	POSS_NEW_FRAGMENTS	12

/*
 * VM data structures
 */
long page_hashsz;		/* Size of page hash table (power of two) */
struct page *pp_base;		/* Base of initial system page struct array */
struct page **page_hash;	/* Page hash table */
struct seg ktextseg;		/* Segment used for kernel executable image */
struct seg kvalloc;		/* Segment used for "valloc" mapping */
struct seg kpseg;		/* Segment used for pageable kernel virt mem */
struct seg kmapseg;		/* Segment used for generic kernel mappings */
struct seg kdebugseg;		/* Segment used for the kernel debugger */

struct seg *segkmap = &kmapseg;	/* Kernel generic mapping segment */
struct seg *segkp = &kpseg;	/* Pageable kernel virtual memory segment */

#if defined(__amd64)
struct seg kvseg_core;		/* Segment used for the core heap */
struct seg kpmseg;		/* Segment used for physical mapping */
struct seg *segkpm = &kpmseg;	/* 64bit kernel physical mapping segment */
#else
struct seg *segkpm = NULL;	/* Unused on IA32 */
#endif

caddr_t segkp_base;		/* Base address of segkp */
#if defined(__amd64)
pgcnt_t segkpsize = btop(SEGKPDEFSIZE);	/* size of segkp segment in pages */
#else
pgcnt_t segkpsize = 0;
#endif

struct memseg *memseg_base;
struct vnode unused_pages_vp;

#define	FOURGB	0x100000000LL

struct memlist *memlist;

caddr_t s_text;		/* start of kernel text segment */
caddr_t e_text;		/* end of kernel text segment */
caddr_t s_data;		/* start of kernel data segment */
caddr_t e_data;		/* end of kernel data segment */
caddr_t modtext;	/* start of loadable module text reserved */
caddr_t e_modtext;	/* end of loadable module text reserved */
caddr_t moddata;	/* start of loadable module data reserved */
caddr_t e_moddata;	/* end of loadable module data reserved */

struct memlist *phys_install;	/* Total installed physical memory */
struct memlist *phys_avail;	/* Total available physical memory */

static void memlist_add(uint64_t, uint64_t, struct memlist *,
	struct memlist **);

/*
 * kphysm_init returns the number of pages that were processed
 */
static pgcnt_t kphysm_init(page_t *, struct memseg *, pgcnt_t, pgcnt_t);

#define	IO_PROP_SIZE	64	/* device property size */

/*
 * a couple useful roundup macros
 */
#define	ROUND_UP_PAGE(x)	\
	((uintptr_t)P2ROUNDUP((uintptr_t)(x), (uintptr_t)MMU_PAGESIZE))
#define	ROUND_UP_LPAGE(x)	\
	((uintptr_t)P2ROUNDUP((uintptr_t)(x), mmu.level_size[1]))
#define	ROUND_UP_4MEG(x)	\
	((uintptr_t)P2ROUNDUP((uintptr_t)(x), (uintptr_t)FOURMB_PAGESIZE))
#define	ROUND_UP_TOPLEVEL(x)	\
	((uintptr_t)P2ROUNDUP((uintptr_t)(x), mmu.level_size[mmu.max_level]))

/*
 *	32-bit Kernel's Virtual memory layout.
 *		+-----------------------+
 *		|	psm 1-1 map	|
 *		|	exec args area	|
 * 0xFFC00000  -|-----------------------|- ARGSBASE
 *		|	debugger	|
 * 0xFF800000  -|-----------------------|- SEGDEBUGBASE
 *		|      Kernel Data	|
 * 0xFEC00000  -|-----------------------|
 *              |      Kernel Text	|
 * 0xFE800000  -|-----------------------|- KERNEL_TEXT
 * 		|     LUFS sinkhole	|
 * 0xFE000000  -|-----------------------|- lufs_addr
 * ---         -|-----------------------|- valloc_base + valloc_sz
 * 		|   early pp structures	|
 * 		|   memsegs, memlists, 	|
 * 		|   page hash, etc.	|
 * ---	       -|-----------------------|- valloc_base (floating)
 * 		|     ptable_va    	|
 * 0xFDFFE000  -|-----------------------|- ekernelheap, ptable_va
 *		|			|  (segkp is an arena under the heap)
 *		|			|
 *		|	kvseg		|
 *		|			|
 *		|			|
 * ---         -|-----------------------|- kernelheap (floating)
 * 		|        Segkmap	|
 * 0xC3002000  -|-----------------------|- segkmap_start (floating)
 *		|	Red Zone	|
 * 0xC3000000  -|-----------------------|- kernelbase / userlimit (floating)
 *		|			|			||
 *		|     Shared objects	|			\/
 *		|			|
 *		:			:
 *		|	user data	|
 *		|-----------------------|
 *		|	user text	|
 * 0x08048000  -|-----------------------|
 *		|	user stack	|
 *		:			:
 *		|	invalid		|
 * 0x00000000	+-----------------------+
 *
 *
 *		64-bit Kernel's Virtual memory layout. (assuming 64 bit app)
 *			+-----------------------+
 *			|	psm 1-1 map	|
 *			|	exec args area	|
 * 0xFFFFFFFF.FFC00000  |-----------------------|- ARGSBASE
 *			|	debugger (?)	|
 * 0xFFFFFFFF.FF800000  |-----------------------|- SEGDEBUGBASE
 *			|      unused    	|
 *			+-----------------------+
 *			|      Kernel Data	|
 * 0xFFFFFFFF.FBC00000  |-----------------------|
 *			|      Kernel Text	|
 * 0xFFFFFFFF.FB800000  |-----------------------|- KERNEL_TEXT
 * 			|     LUFS sinkhole	|
 * 0xFFFFFFFF.FB000000 -|-----------------------|- lufs_addr
 * ---                  |-----------------------|- valloc_base + valloc_sz
 * 			|   early pp structures	|
 * 			|   memsegs, memlists, 	|
 * 			|   page hash, etc.	|
 * ---                  |-----------------------|- valloc_base
 * 			|     ptable_va    	|
 * ---                  |-----------------------|- ptable_va
 * 			|      Core heap	| (used for loadable modules)
 * 0xFFFFFFFF.C0000000  |-----------------------|- core_base / ekernelheap
 *			|	 Kernel		|
 *			|	  heap		|
 * 0xFFFFFXXX.XXX00000  |-----------------------|- kernelheap (floating)
 *			|	 segkmap	|
 * 0xFFFFFXXX.XXX00000  |-----------------------|- segkmap_start (floating)
 *			|    device mappings	|
 * 0xFFFFFXXX.XXX00000  |-----------------------|- toxic_addr (floating)
 *			|	  segkp		|
 * ---                  |-----------------------|- segkp_base
 *			|	 segkpm		|
 * 0xFFFFFE00.00000000  |-----------------------|
 *			|	Red Zone	|
 * 0xFFFFFD80.00000000  |-----------------------|- KERNELBASE
 *			|     User stack	|- User space memory
 * 			|			|
 * 			| shared objects, etc	|	(grows downwards)
 *			:			:
 * 			|			|
 * 0xFFFF8000.00000000  |-----------------------|
 * 			|			|
 * 			| VA Hole / unused	|
 * 			|			|
 * 0x00008000.00000000  |-----------------------|
 *			|			|
 *			|			|
 *			:			:
 *			|	user heap	|	(grows upwards)
 *			|			|
 *			|	user data	|
 *			|-----------------------|
 *			|	user text	|
 * 0x00000000.04000000  |-----------------------|
 *			|	invalid		|
 * 0x00000000.00000000	+-----------------------+
 *
 * A 32 bit app on the 64 bit kernel sees the same layout as on the 32 bit
 * kernel, except that userlimit is raised to 0xfe000000
 *
 * Floating values:
 *
 * valloc_base: start of the kernel's memory management/tracking data
 * structures.  This region contains page_t structures for the lowest 4GB
 * of physical memory, memsegs, memlists, and the page hash.
 *
 * core_base: start of the kernel's "core" heap area on 64-bit systems.
 * This area is intended to be used for global data as well as for module
 * text/data that does not fit into the nucleus pages.  The core heap is
 * restricted to a 2GB range, allowing every address within it to be
 * accessed using rip-relative addressing
 *
 * ekernelheap: end of kernelheap and start of segmap.
 *
 * kernelheap: start of kernel heap.  On 32-bit systems, this starts right
 * above a red zone that separates the user's address space from the
 * kernel's.  On 64-bit systems, it sits above segkp and segkpm.
 *
 * segkmap_start: start of segmap. The length of segmap can be modified
 * by changing segmapsize in /etc/system (preferred) or eeprom (deprecated).
 * The default length is 16MB on 32-bit systems and 64MB on 64-bit systems.
 *
 * kernelbase: On a 32-bit kernel the default value of 0xd4000000 will be
 * decreased by 2X the size required for page_t.  This allows the kernel
 * heap to grow in size with physical memory.  With sizeof(page_t) == 80
 * bytes, the following shows the values of kernelbase and kernel heap
 * sizes for different memory configurations (assuming default segmap and
 * segkp sizes).
 *
 *	mem	size for	kernelbase	kernel heap
 *	size	page_t's			size
 *	----	---------	----------	-----------
 *	1gb	0x01400000	0xd1800000	684MB
 *	2gb	0x02800000	0xcf000000	704MB
 *	4gb	0x05000000	0xca000000	744MB
 *	6gb	0x07800000	0xc5000000	784MB
 *	8gb	0x0a000000	0xc0000000	824MB
 *	16gb	0x14000000	0xac000000	984MB
 *	32gb	0x28000000	0x84000000	1304MB
 *	64gb	0x50000000	0x34000000	1944MB (*)
 *
 * kernelbase is less than the abi minimum of 0xc0000000 for memory
 * configurations above 8gb.
 *
 * (*) support for memory configurations above 32gb will require manual tuning
 * of kernelbase to balance out the need of user applications.
 */

/* real-time-clock initialization parameters */
long gmt_lag;		/* offset in seconds of gmt to local time */
extern long process_rtc_config_file(void);

char		*final_kernelheap;
char		*boot_kernelheap;
uintptr_t	kernelbase;
uintptr_t	eprom_kernelbase;
size_t		segmapsize;
static uintptr_t segmap_reserved;
uintptr_t	segkmap_start;
int		segmapfreelists;
pgcnt_t		boot_npages;
pgcnt_t		npages;
size_t		core_size;		/* size of "core" heap */
uintptr_t	core_base;		/* base address of "core" heap */

/*
 * List of bootstrap pages. We mark these as allocated in startup.
 * release_bootstrap() will free them when we're completely done with
 * the bootstrap.
 */
static page_t *bootpages, *rd_pages;

struct system_hardware system_hardware;

/*
 * Enable some debugging messages concerning memory usage...
 *
 * XX64 There should only be one print routine once memlist usage between
 * vmx and the kernel is cleaned up and there is a single memlist structure
 * shared between kernel and boot.
 */
static void
print_boot_memlist(char *title, struct memlist *mp)
{
	prom_printf("MEMLIST: %s:\n", title);
	while (mp != NULL)  {
		prom_printf("\tAddress 0x%" PRIx64 ", size 0x%" PRIx64 "\n",
		    mp->address, mp->size);
		mp = mp->next;
	}
}

static void
print_kernel_memlist(char *title, struct memlist *mp)
{
	prom_printf("MEMLIST: %s:\n", title);
	while (mp != NULL)  {
		prom_printf("\tAddress 0x%" PRIx64 ", size 0x%" PRIx64 "\n",
		    mp->address, mp->size);
		mp = mp->next;
	}
}

/*
 * XX64 need a comment here.. are these just default values, surely
 * we read the "cpuid" type information to figure this out.
 */
int	l2cache_sz = 0x80000;
int	l2cache_linesz = 0x40;
int	l2cache_assoc = 1;

/*
 * on 64 bit we use a predifined VA range for mapping devices in the kernel
 * on 32 bit the mappings are intermixed in the heap, so we use a bit map
 */
#ifdef __amd64

vmem_t		*device_arena;
uintptr_t	toxic_addr = (uintptr_t)NULL;
size_t		toxic_size = 1 * 1024 * 1024 * 1024; /* Sparc uses 1 gig too */

#else	/* __i386 */

ulong_t		*toxic_bit_map;	/* one bit for each 4k of VA in heap_arena */
size_t		toxic_bit_map_len = 0;	/* in bits */

#endif	/* __i386 */

/*
 * Simple boot time debug facilities
 */
static char *prm_dbg_str[] = {
	"%s:%d: '%s' is 0x%x\n",
	"%s:%d: '%s' is 0x%llx\n"
};

int prom_debug;

#define	PRM_DEBUG(q)	if (prom_debug) 	\
	prom_printf(prm_dbg_str[sizeof (q) >> 3], "startup.c", __LINE__, #q, q);
#define	PRM_POINT(q)	if (prom_debug) 	\
	prom_printf("%s:%d: %s\n", "startup.c", __LINE__, q);

/*
 * This structure is used to keep track of the intial allocations
 * done in startup_memlist(). The value of NUM_ALLOCATIONS needs to
 * be >= the number of ADD_TO_ALLOCATIONS() executed in the code.
 */
#define	NUM_ALLOCATIONS 7
int num_allocations = 0;
struct {
	void **al_ptr;
	size_t al_size;
} allocations[NUM_ALLOCATIONS];
size_t valloc_sz = 0;
uintptr_t valloc_base;
extern uintptr_t ptable_va;
extern size_t ptable_sz;

#define	ADD_TO_ALLOCATIONS(ptr, size) {					\
		size = ROUND_UP_PAGE(size);		 		\
		if (num_allocations == NUM_ALLOCATIONS)			\
			panic("too many ADD_TO_ALLOCATIONS()");		\
		allocations[num_allocations].al_ptr = (void**)&ptr;	\
		allocations[num_allocations].al_size = size;		\
		valloc_sz += size;					\
		++num_allocations;				 	\
	}

static void
perform_allocations(void)
{
	caddr_t mem;
	int i;

	mem = BOP_ALLOC(bootops, (caddr_t)valloc_base, valloc_sz, BO_NO_ALIGN);
	if (mem != (caddr_t)valloc_base)
		panic("BOP_ALLOC() failed");
	bzero(mem, valloc_sz);
	for (i = 0; i < num_allocations; ++i) {
		*allocations[i].al_ptr = (void *)mem;
		mem += allocations[i].al_size;
	}
}

/*
 * Our world looks like this at startup time.
 *
 * In a 32-bit OS, boot loads the kernel text at 0xfe800000 and kernel data
 * at 0xfec00000.  On a 64-bit OS, kernel text and data are loaded at
 * 0xffffffff.fe800000 and 0xffffffff.fec00000 respectively.  Those
 * addresses are fixed in the binary at link time.
 *
 * On the text page:
 * unix/genunix/krtld/module text loads.
 *
 * On the data page:
 * unix/genunix/krtld/module data loads and space for page_t's.
 */
/*
 * Machine-dependent startup code
 */
void
startup(void)
{
	extern void startup_bios_disk(void);
	extern void startup_pci_bios(void);
	/*
	 * Make sure that nobody tries to use sekpm until we have
	 * initialized it properly.
	 */
#if defined(__amd64)
	kpm_desired = kpm_enable;
#endif
	kpm_enable = 0;

	progressbar_init();
	startup_init();
	startup_memlist();
	startup_pci_bios();
	startup_modules();
	startup_bios_disk();
	startup_bop_gone();
	startup_vm();
	startup_end();
	progressbar_start();
}

static void
startup_init()
{
	PRM_POINT("startup_init() starting...");

	/*
	 * Complete the extraction of cpuid data
	 */
	cpuid_pass2(CPU);

	(void) check_boot_version(BOP_GETVERSION(bootops));

	/*
	 * Check for prom_debug in boot environment
	 */
	if (BOP_GETPROPLEN(bootops, "prom_debug") >= 0) {
		++prom_debug;
		PRM_POINT("prom_debug found in boot enviroment");
	}

	/*
	 * Collect node, cpu and memory configuration information.
	 */
	get_system_configuration();

	/*
	 * Halt if this is an unsupported processor.
	 */
	if (x86_type == X86_TYPE_486 || x86_type == X86_TYPE_CYRIX_486) {
		printf("\n486 processor (\"%s\") detected.\n",
		    CPU->cpu_brandstr);
		halt("This processor is not supported by this release "
		    "of Solaris.");
	}

	PRM_POINT("startup_init() done");
}

/*
 * Callback for copy_memlist_filter() to filter nucleus, kadb/kmdb, (ie.
 * everything mapped above KERNEL_TEXT) pages from phys_avail. Note it
 * also filters out physical page zero.  There is some reliance on the
 * boot loader allocating only a few contiguous physical memory chunks.
 */
static void
avail_filter(uint64_t *addr, uint64_t *size)
{
	uintptr_t va;
	uintptr_t next_va;
	pfn_t pfn;
	uint64_t pfn_addr;
	uint64_t pfn_eaddr;
	uint_t prot;
	size_t len;
	uint_t change;

	if (prom_debug)
		prom_printf("\tFilter: in: a=%" PRIx64 ", s=%" PRIx64 "\n",
		    *addr, *size);

	/*
	 * page zero is required for BIOS.. never make it available
	 */
	if (*addr == 0) {
		*addr += MMU_PAGESIZE;
		*size -= MMU_PAGESIZE;
	}

	/*
	 * First we trim from the front of the range. Since hat_boot_probe()
	 * walks ranges in virtual order, but addr/size are physical, we need
	 * to the list until no changes are seen.  This deals with the case
	 * where page "p" is mapped at v, page "p + PAGESIZE" is mapped at w
	 * but w < v.
	 */
	do {
		change = 0;
		for (va = KERNEL_TEXT;
		    *size > 0 && hat_boot_probe(&va, &len, &pfn, &prot) != 0;
		    va = next_va) {

			next_va = va + len;
			pfn_addr = ptob((uint64_t)pfn);
			pfn_eaddr = pfn_addr + len;

			if (pfn_addr <= *addr && pfn_eaddr > *addr) {
				change = 1;
				while (*size > 0 && len > 0) {
					*addr += MMU_PAGESIZE;
					*size -= MMU_PAGESIZE;
					len -= MMU_PAGESIZE;
				}
			}
		}
		if (change && prom_debug)
			prom_printf("\t\ttrim: a=%" PRIx64 ", s=%" PRIx64 "\n",
			    *addr, *size);
	} while (change);

	/*
	 * Trim pages from the end of the range.
	 */
	for (va = KERNEL_TEXT;
	    *size > 0 && hat_boot_probe(&va, &len, &pfn, &prot) != 0;
	    va = next_va) {

		next_va = va + len;
		pfn_addr = ptob((uint64_t)pfn);

		if (pfn_addr >= *addr && pfn_addr < *addr + *size)
			*size = pfn_addr - *addr;
	}

	if (prom_debug)
		prom_printf("\tFilter out: a=%" PRIx64 ", s=%" PRIx64 "\n",
		    *addr, *size);
}

static void
kpm_init()
{
	struct segkpm_crargs b;
	uintptr_t start, end;
	struct memlist	*pmem;

	/*
	 * These variables were all designed for sfmmu in which segkpm is
	 * mapped using a single pagesize - either 8KB or 4MB.  On x86, we
	 * might use 2+ page sizes on a single machine, so none of these
	 * variables have a single correct value.  They are set up as if we
	 * always use a 4KB pagesize, which should do no harm.  In the long
	 * run, we should get rid of KPM's assumption that only a single
	 * pagesize is used.
	 */
	kpm_pgshft = MMU_PAGESHIFT;
	kpm_pgsz =  MMU_PAGESIZE;
	kpm_pgoff = MMU_PAGEOFFSET;
	kpmp2pshft = 0;
	kpmpnpgs = 1;
	ASSERT(((uintptr_t)kpm_vbase & (kpm_pgsz - 1)) == 0);

	PRM_POINT("about to create segkpm");
	rw_enter(&kas.a_lock, RW_WRITER);

	if (seg_attach(&kas, kpm_vbase, kpm_size, segkpm) < 0)
		panic("cannot attach segkpm");

	b.prot = PROT_READ | PROT_WRITE;
	b.nvcolors = 1;

	if (segkpm_create(segkpm, (caddr_t)&b) != 0)
		panic("segkpm_create segkpm");

	rw_exit(&kas.a_lock);

	/*
	 * Map each of the memsegs into the kpm segment, coalesing adjacent
	 * memsegs to allow mapping with the largest possible pages.
	 */
	pmem = phys_install;
	start = pmem->address;
	end = start + pmem->size;
	for (;;) {
		if (pmem == NULL || pmem->address > end) {
			hat_devload(kas.a_hat, kpm_vbase + start,
			    end - start, mmu_btop(start),
			    PROT_READ | PROT_WRITE,
			    HAT_LOAD | HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);
			if (pmem == NULL)
				break;
			start = pmem->address;
		}
		end = pmem->address + pmem->size;
		pmem = pmem->next;
	}
}

/*
 * The purpose of startup memlist is to get the system to the
 * point where it can use kmem_alloc()'s that operate correctly
 * relying on BOP_ALLOC(). This includes allocating page_ts,
 * page hash table, vmem initialized, etc.
 *
 * Boot's versions of physinstalled and physavail are insufficient for
 * the kernel's purposes. Specifically we don't know which pages that
 * are not in physavail can be reclaimed after boot is gone.
 *
 * This code solves the problem by dividing the address space
 * into 3 regions as it takes over the MMU from the booter.
 *
 * 1) Any (non-nucleus) pages that are mapped at addresses above KERNEL_TEXT
 * can not be used by the kernel.
 *
 * 2) Any free page that happens to be mapped below kernelbase
 * is protected until the boot loader is released, but will then be reclaimed.
 *
 * 3) Boot shouldn't use any address in the remaining area between kernelbase
 * and KERNEL_TEXT.
 *
 * In the case of multiple mappings to the same page, region 1 has precedence
 * over region 2.
 */
static void
startup_memlist(void)
{
	size_t memlist_sz;
	size_t memseg_sz;
	size_t pagehash_sz;
	size_t pp_sz;
	uintptr_t va;
	size_t len;
	uint_t prot;
	pfn_t pfn;
	int memblocks;
	caddr_t pagecolor_mem;
	size_t pagecolor_memsz;
	caddr_t page_ctrs_mem;
	size_t page_ctrs_size;
	struct memlist *current;
	pgcnt_t orig_npages = 0;
	extern void startup_build_mem_nodes(struct memlist *);

	/* XX64 fix these - they should be in include files */
	extern ulong_t cr4_value;
	extern size_t page_coloring_init(uint_t, int, int);
	extern void page_coloring_setup(caddr_t);

	PRM_POINT("startup_memlist() starting...");

	/*
	 * Take the most current snapshot we can by calling mem-update.
	 * For this to work properly, we first have to ask boot for its
	 * end address.
	 */
	if (BOP_GETPROPLEN(bootops, "memory-update") == 0)
		(void) BOP_GETPROP(bootops, "memory-update", NULL);

	/*
	 * find if the kernel is mapped on a large page
	 */
	va = KERNEL_TEXT;
	if (hat_boot_probe(&va, &len, &pfn, &prot) == 0)
		panic("Couldn't find kernel text boot mapping");

	/*
	 * Use leftover large page nucleus text/data space for loadable modules.
	 * Use at most MODTEXT/MODDATA.
	 */
	if (len > MMU_PAGESIZE) {

		moddata = (caddr_t)ROUND_UP_PAGE(e_data);
		e_moddata = (caddr_t)ROUND_UP_4MEG(e_data);
		if (e_moddata - moddata > MODDATA)
			e_moddata = moddata + MODDATA;

		modtext = (caddr_t)ROUND_UP_PAGE(e_text);
		e_modtext = (caddr_t)ROUND_UP_4MEG(e_text);
		if (e_modtext - modtext > MODTEXT)
			e_modtext = modtext + MODTEXT;


	} else {

		PRM_POINT("Kernel NOT loaded on Large Page!");
		e_moddata = moddata = (caddr_t)ROUND_UP_PAGE(e_data);
		e_modtext = modtext = (caddr_t)ROUND_UP_PAGE(e_text);

	}
	econtig = e_moddata;

	PRM_DEBUG(modtext);
	PRM_DEBUG(e_modtext);
	PRM_DEBUG(moddata);
	PRM_DEBUG(e_moddata);
	PRM_DEBUG(econtig);

	/*
	 * For MP machines cr4_value must be set or the non-boot
	 * CPUs will not be able to start.
	 */
	if (x86_feature & X86_LARGEPAGE)
		cr4_value = getcr4();
	PRM_DEBUG(cr4_value);

	/*
	 * Examine the boot loaders physical memory map to find out:
	 * - total memory in system - physinstalled
	 * - the max physical address - physmax
	 * - the number of segments the intsalled memory comes in
	 */
	if (prom_debug)
		print_boot_memlist("boot physinstalled",
		    bootops->boot_mem->physinstalled);
	installed_top_size(bootops->boot_mem->physinstalled, &physmax,
	    &physinstalled, &memblocks);
	PRM_DEBUG(physmax);
	PRM_DEBUG(physinstalled);
	PRM_DEBUG(memblocks);

	if (prom_debug)
		print_boot_memlist("boot physavail",
		    bootops->boot_mem->physavail);

	/*
	 * Initialize hat's mmu parameters.
	 * Check for enforce-prot-exec in boot environment. It's used to
	 * enable/disable support for the page table entry NX bit.
	 * The default is to enforce PROT_EXEC on processors that support NX.
	 * Boot seems to round up the "len", but 8 seems to be big enough.
	 */
	mmu_init();

#ifdef	__i386
	/*
	 * physmax is lowered if there is more memory than can be
	 * physically addressed in 32 bit (PAE/non-PAE) modes.
	 */
	if (mmu.pae_hat) {
		if (PFN_ABOVE64G(physmax)) {
			physinstalled -= (physmax - (PFN_64G - 1));
			physmax = PFN_64G - 1;
		}
	} else {
		if (PFN_ABOVE4G(physmax)) {
			physinstalled -= (physmax - (PFN_4G - 1));
			physmax = PFN_4G - 1;
		}
	}
#endif

	startup_build_mem_nodes(bootops->boot_mem->physinstalled);

	if (BOP_GETPROPLEN(bootops, "enforce-prot-exec") >= 0) {
		int len = BOP_GETPROPLEN(bootops, "enforce-prot-exec");
		char value[8];

		if (len < 8)
			(void) BOP_GETPROP(bootops, "enforce-prot-exec", value);
		else
			(void) strcpy(value, "");
		if (strcmp(value, "off") == 0)
			mmu.pt_nx = 0;
	}
	PRM_DEBUG(mmu.pt_nx);

	/*
	 * We will need page_t's for every page in the system, except for
	 * memory mapped at or above above the start of the kernel text segment.
	 *
	 * pages above e_modtext are attributed to kernel debugger (obp_pages)
	 */
	npages = physinstalled - 1; /* avail_filter() skips page 0, so "- 1" */
	obp_pages = 0;
	va = KERNEL_TEXT;
	while (hat_boot_probe(&va, &len, &pfn, &prot) != 0) {
		npages -= len >> MMU_PAGESHIFT;
		if (va >= (uintptr_t)e_moddata)
			obp_pages += len >> MMU_PAGESHIFT;
		va += len;
	}
	PRM_DEBUG(npages);
	PRM_DEBUG(obp_pages);

	/*
	 * If physmem is patched to be non-zero, use it instead of
	 * the computed value unless it is larger than the real
	 * amount of memory on hand.
	 */
	if (physmem == 0 || physmem > npages) {
		physmem = npages;
	} else if (physmem < npages) {
		orig_npages = npages;
		npages = physmem;
	}
	PRM_DEBUG(physmem);

	/*
	 * We now compute the sizes of all the  initial allocations for
	 * structures the kernel needs in order do kmem_alloc(). These
	 * include:
	 *	memsegs
	 *	memlists
	 *	page hash table
	 *	page_t's
	 *	page coloring data structs
	 */
	memseg_sz = sizeof (struct memseg) * (memblocks + POSS_NEW_FRAGMENTS);
	ADD_TO_ALLOCATIONS(memseg_base, memseg_sz);
	PRM_DEBUG(memseg_sz);

	/*
	 * Reserve space for phys_avail/phys_install memlists.
	 * There's no real good way to know exactly how much room we'll need,
	 * but this should be a good upper bound.
	 */
	memlist_sz = ROUND_UP_PAGE(2 * sizeof (struct memlist) *
	    (memblocks + POSS_NEW_FRAGMENTS));
	ADD_TO_ALLOCATIONS(memlist, memlist_sz);
	PRM_DEBUG(memlist_sz);

	/*
	 * The page structure hash table size is a power of 2
	 * such that the average hash chain length is PAGE_HASHAVELEN.
	 */
	page_hashsz = npages / PAGE_HASHAVELEN;
	page_hashsz = 1 << highbit(page_hashsz);
	pagehash_sz = sizeof (struct page *) * page_hashsz;
	ADD_TO_ALLOCATIONS(page_hash, pagehash_sz);
	PRM_DEBUG(pagehash_sz);

	/*
	 * Set aside room for the page structures themselves.  Note: on
	 * 64-bit systems we don't allocate page_t's for every page here.
	 * We just allocate enough to map the lowest 4GB of physical
	 * memory, minus those pages that are used for the "nucleus" kernel
	 * text and data.  The remaining pages are allocated once we can
	 * map around boot.
	 *
	 * boot_npages is used to allocate an area big enough for our
	 * initial page_t's. kphym_init may use less than that.
	 */
	boot_npages = npages;
#if defined(__amd64)
	if (npages > mmu_btop(FOURGB - (econtig - s_text)))
		boot_npages = mmu_btop(FOURGB - (econtig - s_text));
#endif
	PRM_DEBUG(boot_npages);
	pp_sz = sizeof (struct page) * boot_npages;
	ADD_TO_ALLOCATIONS(pp_base, pp_sz);
	PRM_DEBUG(pp_sz);

	/*
	 * determine l2 cache info and memory size for page coloring
	 */
	(void) getl2cacheinfo(CPU,
	    &l2cache_sz, &l2cache_linesz, &l2cache_assoc);
	pagecolor_memsz =
	    page_coloring_init(l2cache_sz, l2cache_linesz, l2cache_assoc);
	ADD_TO_ALLOCATIONS(pagecolor_mem, pagecolor_memsz);
	PRM_DEBUG(pagecolor_memsz);

	page_ctrs_size = page_ctrs_sz();
	ADD_TO_ALLOCATIONS(page_ctrs_mem, page_ctrs_size);
	PRM_DEBUG(page_ctrs_size);

	/*
	 * valloc_base will be below kernel text
	 * The extra pages are for the HAT and kmdb to map page tables.
	 */
	valloc_sz = ROUND_UP_LPAGE(valloc_sz);
	valloc_base = KERNEL_TEXT - valloc_sz;
	PRM_DEBUG(valloc_base);
	ptable_va = valloc_base - ptable_sz;

#if defined(__amd64)
	if (eprom_kernelbase && eprom_kernelbase != KERNELBASE)
		cmn_err(CE_NOTE, "!kernelbase cannot be changed on 64-bit "
		    "systems.");
	kernelbase = (uintptr_t)KERNELBASE;
	core_base = (uintptr_t)COREHEAP_BASE;
	core_size = ptable_va - core_base;
#else	/* __i386 */
	/*
	 * We configure kernelbase based on:
	 *
	 * 1. user specified kernelbase via eeprom command. Value cannot exceed
	 *    KERNELBASE_MAX. we large page align eprom_kernelbase
	 *
	 * 2. Default to KERNELBASE and adjust to 2X less the size for page_t.
	 *    On large memory systems we must lower kernelbase to allow
	 *    enough room for page_t's for all of memory.
	 *
	 * The value set here, might be changed a little later.
	 */
	if (eprom_kernelbase) {
		kernelbase = eprom_kernelbase & mmu.level_mask[1];
		if (kernelbase > KERNELBASE_MAX)
			kernelbase = KERNELBASE_MAX;
	} else {
		kernelbase = (uintptr_t)KERNELBASE;
		kernelbase -= ROUND_UP_4MEG(2 * valloc_sz);
	}
	ASSERT((kernelbase & mmu.level_offset[1]) == 0);
	core_base = ptable_va;
	core_size = 0;
#endif

	PRM_DEBUG(kernelbase);
	PRM_DEBUG(core_base);
	PRM_DEBUG(core_size);

	/*
	 * At this point, we can only use a portion of the kernelheap that
	 * will be available after we boot.  Both 32-bit and 64-bit systems
	 * have this limitation, although the reasons are completely
	 * different.
	 *
	 * On 64-bit systems, the booter only supports allocations in the
	 * upper 4GB of memory, so we have to work with a reduced kernel
	 * heap until we take over all allocations.  The booter also sits
	 * in the lower portion of that 4GB range, so we have to raise the
	 * bottom of the heap even further.
	 *
	 * On 32-bit systems we have to leave room to place segmap below
	 * the heap.  We don't yet know how large segmap will be, so we
	 * have to be very conservative.
	 */
#if defined(__amd64)
	/*
	 * XX64: For now, we let boot have the lower 2GB of the top 4GB
	 * address range.  In the long run, that should be fixed.  It's
	 * insane for a booter to need 2 2GB address ranges.
	 */
	boot_kernelheap = (caddr_t)(BOOT_DOUBLEMAP_BASE + BOOT_DOUBLEMAP_SIZE);
	segmap_reserved = 0;

#else	/* __i386 */
	segkp_fromheap = 1;
	segmap_reserved = ROUND_UP_LPAGE(MAX(segmapsize, SEGMAPMAX));
	boot_kernelheap = (caddr_t)(ROUND_UP_LPAGE(kernelbase) +
	    segmap_reserved);
#endif
	PRM_DEBUG(boot_kernelheap);
	kernelheap = boot_kernelheap;
	ekernelheap = (char *)core_base;

	/*
	 * If segmap is too large we can push the bottom of the kernel heap
	 * higher than the base.  Or worse, it could exceed the top of the
	 * VA space entirely, causing it to wrap around.
	 */
	if (kernelheap >= ekernelheap || (uintptr_t)kernelheap < kernelbase)
		panic("too little memory available for kernelheap,"
			    " use a different kernelbase");

	/*
	 * Now that we know the real value of kernelbase,
	 * update variables that were initialized with a value of
	 * KERNELBASE (in common/conf/param.c).
	 *
	 * XXX	The problem with this sort of hackery is that the
	 *	compiler just may feel like putting the const declarations
	 *	(in param.c) into the .text section.  Perhaps they should
	 *	just be declared as variables there?
	 */

#if defined(__amd64)
	ASSERT(_kernelbase == KERNELBASE);
	ASSERT(_userlimit == USERLIMIT);
	/*
	 * As one final sanity check, verify that the "red zone" between
	 * kernel and userspace is exactly the size we expected.
	 */
	ASSERT(_kernelbase == (_userlimit + (2 * 1024 * 1024)));
#else
	*(uintptr_t *)&_kernelbase = kernelbase;
	*(uintptr_t *)&_userlimit = kernelbase;
	*(uintptr_t *)&_userlimit32 = _userlimit;
#endif
	PRM_DEBUG(_kernelbase);
	PRM_DEBUG(_userlimit);
	PRM_DEBUG(_userlimit32);

	/*
	 * do all the initial allocations
	 */
	perform_allocations();

	/*
	 * Initialize the kernel heap. Note 3rd argument must be > 1st.
	 */
	kernelheap_init(kernelheap, ekernelheap, kernelheap + MMU_PAGESIZE,
	    (void *)core_base, (void *)ptable_va);

	/*
	 * Build phys_install and phys_avail in kernel memspace.
	 * - phys_install should be all memory in the system.
	 * - phys_avail is phys_install minus any memory mapped before this
	 *    point above KERNEL_TEXT.
	 */
	current = phys_install = memlist;
	copy_memlist_filter(bootops->boot_mem->physinstalled, &current, NULL);
	if ((caddr_t)current > (caddr_t)memlist + memlist_sz)
		panic("physinstalled was too big!");
	if (prom_debug)
		print_kernel_memlist("phys_install", phys_install);

	phys_avail = current;
	PRM_POINT("Building phys_avail:\n");
	copy_memlist_filter(bootops->boot_mem->physinstalled, &current,
	    avail_filter);
	if ((caddr_t)current > (caddr_t)memlist + memlist_sz)
		panic("physavail was too big!");
	if (prom_debug)
		print_kernel_memlist("phys_avail", phys_avail);

	/*
	 * setup page coloring
	 */
	page_coloring_setup(pagecolor_mem);
	page_lock_init();	/* currently a no-op */

	/*
	 * free page list counters
	 */
	(void) page_ctrs_alloc(page_ctrs_mem);

	/*
	 * Initialize the page structures from the memory lists.
	 */
	availrmem_initial = availrmem = freemem = 0;
	PRM_POINT("Calling kphysm_init()...");
	boot_npages = kphysm_init(pp_base, memseg_base, 0, boot_npages);
	PRM_POINT("kphysm_init() done");
	PRM_DEBUG(boot_npages);

	/*
	 * Now that page_t's have been initialized, remove all the
	 * initial allocation pages from the kernel free page lists.
	 */
	boot_mapin((caddr_t)valloc_base, valloc_sz);

	/*
	 * Initialize kernel memory allocator.
	 */
	kmem_init();

	/*
	 * print this out early so that we know what's going on
	 */
	cmn_err(CE_CONT, "?features: %b\n", x86_feature, FMT_X86_FEATURE);

	/*
	 * Initialize bp_mapin().
	 */
	bp_init(MMU_PAGESIZE, HAT_STORECACHING_OK);

	/*
	 * orig_npages is non-zero if physmem has been configured for less
	 * than the available memory.
	 */
	if (orig_npages) {
#ifdef __i386
		/*
		 * use npages for physmem in case it has been temporarily
		 * modified via /etc/system in kmem_init/mod_read_system_file.
		 */
		if (npages == PHYSMEM32) {
			cmn_err(CE_WARN, "!Due to 32 bit virtual"
			    " address space limitations, limiting"
			    " physmem to 0x%lx of 0x%lx available pages",
			    npages, orig_npages);
		} else {
			cmn_err(CE_WARN, "!limiting physmem to 0x%lx of"
			    " 0x%lx available pages", npages, orig_npages);
		}
#else
		cmn_err(CE_WARN, "!limiting physmem to 0x%lx of"
		    " 0x%lx available pages", npages, orig_npages);
#endif
	}
#if defined(__i386)
	if (eprom_kernelbase && (eprom_kernelbase != kernelbase))
		cmn_err(CE_WARN, "kernelbase value, User specified 0x%lx, "
		    "System using 0x%lx",
		    (uintptr_t)eprom_kernelbase, (uintptr_t)kernelbase);
#endif

#ifdef	KERNELBASE_ABI_MIN
	if (kernelbase < (uintptr_t)KERNELBASE_ABI_MIN) {
		cmn_err(CE_NOTE, "!kernelbase set to 0x%lx, system is not "
		    "i386 ABI compliant.", (uintptr_t)kernelbase);
	}
#endif

	PRM_POINT("startup_memlist() done");
}

static void
startup_modules(void)
{
	unsigned int i;
	extern void prom_setup(void);

	PRM_POINT("startup_modules() starting...");
	/*
	 * Initialize ten-micro second timer so that drivers will
	 * not get short changed in their init phase. This was
	 * not getting called until clkinit which, on fast cpu's
	 * caused the drv_usecwait to be way too short.
	 */
	microfind();

	/*
	 * Read the GMT lag from /etc/rtc_config.
	 */
	gmt_lag = process_rtc_config_file();

	/*
	 * Calculate default settings of system parameters based upon
	 * maxusers, yet allow to be overridden via the /etc/system file.
	 */
	param_calc(0);

	mod_setup();

	/*
	 * Initialize system parameters.
	 */
	param_init();

	/*
	 * maxmem is the amount of physical memory we're playing with.
	 */
	maxmem = physmem;

	/*
	 * Initialize the hat layer.
	 */
	hat_init();

	/*
	 * Initialize segment management stuff.
	 */
	seg_init();

	if (modload("fs", "specfs") == -1)
		halt("Can't load specfs");

	if (modload("fs", "devfs") == -1)
		halt("Can't load devfs");

	(void) modloadonly("sys", "lbl_edition");

	dispinit();

	/*
	 * This is needed here to initialize hw_serial[] for cluster booting.
	 */
	if ((i = modload("misc", "sysinit")) != (unsigned int)-1)
		(void) modunload(i);
	else
		cmn_err(CE_CONT, "sysinit load failed");

	/* Read cluster configuration data. */
	clconf_init();

	/*
	 * Create a kernel device tree. First, create rootnex and
	 * then invoke bus specific code to probe devices.
	 */
	setup_ddi();

	/*
	 * Set up the CPU module subsystem.  Modifies the device tree, so it
	 * must be done after setup_ddi().
	 */
	cmi_init();

	/*
	 * Initialize the MCA handlers
	 */
	if (x86_feature & X86_MCA)
		cmi_mca_init();

	/*
	 * Fake a prom tree such that /dev/openprom continues to work
	 */
	prom_setup();

	/*
	 * Load all platform specific modules
	 */
	psm_modload();

	PRM_POINT("startup_modules() done");
}

static void
startup_bop_gone(void)
{
	PRM_POINT("startup_bop_gone() starting...");

	/*
	 * Do final allocations of HAT data structures that need to
	 * be allocated before quiescing the boot loader.
	 */
	PRM_POINT("Calling hat_kern_alloc()...");
	hat_kern_alloc();
	PRM_POINT("hat_kern_alloc() done");

	/*
	 * Setup MTRR (Memory type range registers)
	 */
	setup_mtrr();
	PRM_POINT("startup_bop_gone() done");
}

/*
 * Walk through the pagetables looking for pages mapped in by boot.  If the
 * setaside flag is set the pages are expected to be returned to the
 * kernel later in boot, so we add them to the bootpages list.
 */
static void
protect_boot_range(uintptr_t low, uintptr_t high, int setaside)
{
	uintptr_t va = low;
	size_t len;
	uint_t prot;
	pfn_t pfn;
	page_t *pp;
	pgcnt_t boot_protect_cnt = 0;

	while (hat_boot_probe(&va, &len, &pfn, &prot) != 0 && va < high) {
		if (va + len >= high)
			panic("0x%lx byte mapping at 0x%p exceeds boot's "
			    "legal range.", len, (void *)va);

		while (len > 0) {
			pp = page_numtopp_alloc(pfn);
			if (pp != NULL) {
				if (setaside == 0)
					panic("Unexpected mapping by boot.  "
					    "addr=%p pfn=%lx\n",
					    (void *)va, pfn);

				pp->p_next = bootpages;
				bootpages = pp;
				++boot_protect_cnt;
			}

			++pfn;
			len -= MMU_PAGESIZE;
			va += MMU_PAGESIZE;
		}
	}
	PRM_DEBUG(boot_protect_cnt);
}

static void
startup_vm(void)
{
	struct segmap_crargs a;
	extern void hat_kern_setup(void);
	pgcnt_t pages_left;

	extern int exec_lpg_disable, use_brk_lpg, use_stk_lpg, use_zmap_lpg;
	extern pgcnt_t auto_lpg_min_physmem;

	PRM_POINT("startup_vm() starting...");

	/*
	 * The next two loops are done in distinct steps in order
	 * to be sure that any page that is doubly mapped (both above
	 * KERNEL_TEXT and below kernelbase) is dealt with correctly.
	 * Note this may never happen, but it might someday.
	 */

	bootpages = NULL;
	PRM_POINT("Protecting boot pages");
	/*
	 * Protect any pages mapped above KERNEL_TEXT that somehow have
	 * page_t's. This can only happen if something weird allocated
	 * in this range (like kadb/kmdb).
	 */
	protect_boot_range(KERNEL_TEXT, (uintptr_t)-1, 0);

	/*
	 * Before we can take over memory allocation/mapping from the boot
	 * loader we must remove from our free page lists any boot pages that
	 * will stay mapped until release_bootstrap().
	 */
	protect_boot_range(0, kernelbase, 1);
#if defined(__amd64)
	protect_boot_range(BOOT_DOUBLEMAP_BASE,
	    BOOT_DOUBLEMAP_BASE + BOOT_DOUBLEMAP_SIZE, 0);
#endif

	/*
	 * Copy in boot's page tables, set up extra page tables for the kernel,
	 * and switch to the kernel's context.
	 */
	PRM_POINT("Calling hat_kern_setup()...");
	hat_kern_setup();

	/*
	 * It is no longer safe to call BOP_ALLOC(), so make sure we don't.
	 */
	bootops->bsys_alloc = NULL;
	PRM_POINT("hat_kern_setup() done");

	hat_cpu_online(CPU);

	/*
	 * Before we call kvm_init(), we need to establish the final size
	 * of the kernel's heap.  So, we need to figure out how much space
	 * to set aside for segkp, segkpm, and segmap.
	 */
	final_kernelheap = (caddr_t)ROUND_UP_LPAGE(kernelbase);
#if defined(__amd64)
	if (kpm_desired) {
		/*
		 * Segkpm appears at the bottom of the kernel's address
		 * range.  To detect accidental overruns of the user
		 * address space, we leave a "red zone" of unmapped memory
		 * between kernelbase and the beginning of segkpm.
		 */
		kpm_vbase = final_kernelheap + KERNEL_REDZONE_SIZE;
		kpm_size = mmu_ptob(physmax);
		PRM_DEBUG(kpm_vbase);
		PRM_DEBUG(kpm_size);
		final_kernelheap =
		    (caddr_t)ROUND_UP_TOPLEVEL(kpm_vbase + kpm_size);
	}

	if (!segkp_fromheap) {
		size_t sz = mmu_ptob(segkpsize);

		/*
		 * determine size of segkp and adjust the bottom of the
		 * kernel's heap.
		 */
		if (sz < SEGKPMINSIZE || sz > SEGKPMAXSIZE) {
			sz = SEGKPDEFSIZE;
			cmn_err(CE_WARN, "!Illegal value for segkpsize. "
			    "segkpsize has been reset to %ld pages",
			    mmu_btop(sz));
		}
		sz = MIN(sz, MAX(SEGKPMINSIZE, mmu_ptob(physmem)));

		segkpsize = mmu_btop(ROUND_UP_LPAGE(sz));
		segkp_base = final_kernelheap;
		PRM_DEBUG(segkpsize);
		PRM_DEBUG(segkp_base);
		final_kernelheap = segkp_base + mmu_ptob(segkpsize);
		PRM_DEBUG(final_kernelheap);
	}

	/*
	 * put the range of VA for device mappings next
	 */
	toxic_addr = (uintptr_t)final_kernelheap;
	PRM_DEBUG(toxic_addr);
	final_kernelheap = (char *)toxic_addr + toxic_size;
#endif
	PRM_DEBUG(final_kernelheap);
	ASSERT(final_kernelheap < boot_kernelheap);

	/*
	 * Users can change segmapsize through eeprom or /etc/system.
	 * If the variable is tuned through eeprom, there is no upper
	 * bound on the size of segmap.  If it is tuned through
	 * /etc/system on 32-bit systems, it must be no larger than we
	 * planned for in startup_memlist().
	 */
	segmapsize = MAX(ROUND_UP_LPAGE(segmapsize), SEGMAPDEFAULT);
	segkmap_start = ROUND_UP_LPAGE((uintptr_t)final_kernelheap);

#if defined(__i386)
	if (segmapsize > segmap_reserved) {
		cmn_err(CE_NOTE, "!segmapsize may not be set > 0x%lx in "
		    "/etc/system.  Use eeprom.", (long)SEGMAPMAX);
		segmapsize = segmap_reserved;
	}
	/*
	 * 32-bit systems don't have segkpm or segkp, so segmap appears at
	 * the bottom of the kernel's address range.  Set aside space for a
	 * red zone just below the start of segmap.
	 */
	segkmap_start += KERNEL_REDZONE_SIZE;
	segmapsize -= KERNEL_REDZONE_SIZE;
#endif
	final_kernelheap = (char *)(segkmap_start + segmapsize);

	PRM_DEBUG(segkmap_start);
	PRM_DEBUG(segmapsize);
	PRM_DEBUG(final_kernelheap);

	/*
	 * Initialize VM system
	 */
	PRM_POINT("Calling kvm_init()...");
	kvm_init();
	PRM_POINT("kvm_init() done");

	/*
	 * Tell kmdb that the VM system is now working
	 */
	if (boothowto & RB_DEBUG)
		kdi_dvec_vmready();

	/*
	 * Mangle the brand string etc.
	 */
	cpuid_pass3(CPU);

	PRM_DEBUG(final_kernelheap);

	/*
	 * Now that we can use memory outside the top 4GB (on 64-bit
	 * systems) and we know the size of segmap, we can set the final
	 * size of the kernel's heap.  Note: on 64-bit systems we still
	 * can't touch anything in the bottom half of the top 4GB range
	 * because boot still has pages mapped there.
	 */
	if (final_kernelheap < boot_kernelheap) {
		kernelheap_extend(final_kernelheap, boot_kernelheap);
#if defined(__amd64)
		kmem_setaside = vmem_xalloc(heap_arena, BOOT_DOUBLEMAP_SIZE,
		    MMU_PAGESIZE, 0, 0, (void *)(BOOT_DOUBLEMAP_BASE),
		    (void *)(BOOT_DOUBLEMAP_BASE + BOOT_DOUBLEMAP_SIZE),
		    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);
		PRM_DEBUG(kmem_setaside);
		if (kmem_setaside == NULL)
			panic("Could not protect boot's memory");
#endif
	}
	/*
	 * Now that the kernel heap may have grown significantly, we need
	 * to make all the remaining page_t's available to back that memory.
	 *
	 * XX64 this should probably wait till after release boot-strap too.
	 */
	pages_left = npages - boot_npages;
	if (pages_left > 0) {
		PRM_DEBUG(pages_left);
		(void) kphysm_init(NULL, memseg_base, boot_npages, pages_left);
	}

#if defined(__amd64)

	/*
	 * Create the device arena for toxic (to dtrace/kmdb) mappings.
	 */
	device_arena = vmem_create("device", (void *)toxic_addr,
	    toxic_size, MMU_PAGESIZE, NULL, NULL, NULL, 0, VM_SLEEP);

#else	/* __i386 */

	/*
	 * allocate the bit map that tracks toxic pages
	 */
	toxic_bit_map_len = btop((ulong_t)(ptable_va - kernelbase));
	PRM_DEBUG(toxic_bit_map_len);
	toxic_bit_map =
	    kmem_zalloc(BT_SIZEOFMAP(toxic_bit_map_len), KM_NOSLEEP);
	ASSERT(toxic_bit_map != NULL);
	PRM_DEBUG(toxic_bit_map);

#endif	/* __i386 */


	/*
	 * Now that we've got more VA, as well as the ability to allocate from
	 * it, tell the debugger.
	 */
	if (boothowto & RB_DEBUG)
		kdi_dvec_memavail();

	/*
	 * The following code installs a special page fault handler (#pf)
	 * to work around a pentium bug.
	 */
#if !defined(__amd64)
	if (x86_type == X86_TYPE_P5) {
		gate_desc_t *newidt;
		desctbr_t    newidt_r;

		if ((newidt = kmem_zalloc(MMU_PAGESIZE, KM_NOSLEEP)) == NULL)
			panic("failed to install pentium_pftrap");

		bcopy(idt0, newidt, sizeof (idt0));
		set_gatesegd(&newidt[T_PGFLT], &pentium_pftrap,
		    KCS_SEL, 0, SDT_SYSIGT, SEL_KPL);

		(void) as_setprot(&kas, (caddr_t)newidt, MMU_PAGESIZE,
		    PROT_READ|PROT_EXEC);

		newidt_r.dtr_limit = sizeof (idt0) - 1;
		newidt_r.dtr_base = (uintptr_t)newidt;
		CPU->cpu_idt = newidt;
		wr_idtr(&newidt_r);
	}
#endif	/* !__amd64 */

	/*
	 * Map page pfn=0 for drivers, such as kd, that need to pick up
	 * parameters left there by controllers/BIOS.
	 */
	PRM_POINT("setup up p0_va");
	p0_va = i86devmap(0, 1, PROT_READ);
	PRM_DEBUG(p0_va);

	cmn_err(CE_CONT, "?mem = %luK (0x%lx)\n",
	    physinstalled << (MMU_PAGESHIFT - 10), ptob(physinstalled));

	/*
	 * disable automatic large pages for small memory systems or
	 * when the disable flag is set.
	 */
	if (physmem < auto_lpg_min_physmem || auto_lpg_disable) {
		exec_lpg_disable = 1;
		use_brk_lpg = 0;
		use_stk_lpg = 0;
		use_zmap_lpg = 0;
	}

	PRM_POINT("Calling hat_init_finish()...");
	hat_init_finish();
	PRM_POINT("hat_init_finish() done");

	/*
	 * Initialize the segkp segment type.
	 */
	rw_enter(&kas.a_lock, RW_WRITER);
	if (!segkp_fromheap) {
		if (seg_attach(&kas, (caddr_t)segkp_base, mmu_ptob(segkpsize),
		    segkp) < 0) {
			panic("startup: cannot attach segkp");
			/*NOTREACHED*/
		}
	} else {
		/*
		 * For 32 bit x86 systems, we will have segkp under the heap.
		 * There will not be a segkp segment.  We do, however, need
		 * to fill in the seg structure.
		 */
		segkp->s_as = &kas;
	}
	if (segkp_create(segkp) != 0) {
		panic("startup: segkp_create failed");
		/*NOTREACHED*/
	}
	PRM_DEBUG(segkp);
	rw_exit(&kas.a_lock);

	/*
	 * kpm segment
	 */
	segmap_kpm = 0;
	if (kpm_desired) {
		kpm_init();
		kpm_enable = 1;
	}

	/*
	 * Now create segmap segment.
	 */
	rw_enter(&kas.a_lock, RW_WRITER);
	if (seg_attach(&kas, (caddr_t)segkmap_start, segmapsize, segkmap) < 0) {
		panic("cannot attach segkmap");
		/*NOTREACHED*/
	}
	PRM_DEBUG(segkmap);

	/*
	 * The 64 bit HAT permanently maps only segmap's page tables.
	 * The 32 bit HAT maps the heap's page tables too.
	 */
#if defined(__amd64)
	hat_kmap_init(segkmap_start, segmapsize);
#else /* __i386 */
	ASSERT(segkmap_start + segmapsize == (uintptr_t)final_kernelheap);
	hat_kmap_init(segkmap_start, (uintptr_t)ekernelheap - segkmap_start);
#endif /* __i386 */

	a.prot = PROT_READ | PROT_WRITE;
	a.shmsize = 0;
	a.nfreelist = segmapfreelists;

	if (segmap_create(segkmap, (caddr_t)&a) != 0)
		panic("segmap_create segkmap");
	rw_exit(&kas.a_lock);

	setup_vaddr_for_ppcopy(CPU);

	segdev_init();
	pmem_init();
	PRM_POINT("startup_vm() done");
}

static void
startup_end(void)
{
	extern void setx86isalist(void);

	PRM_POINT("startup_end() starting...");

	/*
	 * Perform tasks that get done after most of the VM
	 * initialization has been done but before the clock
	 * and other devices get started.
	 */
	kern_setup1();

	/*
	 * Perform CPC initialization for this CPU.
	 */
	kcpc_hw_init(CPU);

#if defined(__amd64)
	/*
	 * Validate support for syscall/sysret
	 * XX64 -- include SSE, SSE2, etc. here too?
	 */
	if ((x86_feature & X86_ASYSC) == 0) {
		cmn_err(CE_WARN,
		    "cpu%d does not support syscall/sysret", CPU->cpu_id);
	}
#endif

#if defined(OPTERON_WORKAROUND_6323525)
	if (opteron_workaround_6323525)
		patch_workaround_6323525();
#endif
	/*
	 * Configure the system.
	 */
	PRM_POINT("Calling configure()...");
	configure();		/* set up devices */
	PRM_POINT("configure() done");

	/*
	 * Set the isa_list string to the defined instruction sets we
	 * support.
	 */
	setx86isalist();
	cpu_intr_alloc(CPU, NINTR_THREADS);
	psm_install();

	/*
	 * We're done with bootops.  We don't unmap the bootstrap yet because
	 * we're still using bootsvcs.
	 */
	PRM_POINT("zeroing out bootops");
	*bootopsp = (struct bootops *)0;
	bootops = (struct bootops *)NULL;

	PRM_POINT("Enabling interrupts");
	(*picinitf)();
	sti();

	(void) add_avsoftintr((void *)&softlevel1_hdl, 1, softlevel1,
		"softlevel1", NULL, NULL); /* XXX to be moved later */

	PRM_POINT("startup_end() done");
}

extern char hw_serial[];
char *_hs1107 = hw_serial;
ulong_t  _bdhs34;

void
post_startup(void)
{
	/*
	 * Set the system wide, processor-specific flags to be passed
	 * to userland via the aux vector for performance hints and
	 * instruction set extensions.
	 */
	bind_hwcap();

	/*
	 * Load the System Management BIOS into the global ksmbios handle,
	 * if an SMBIOS is present on this system.
	 */
	ksmbios = smbios_open(NULL, SMB_VERSION, ksmbios_flags, NULL);

	/*
	 * Startup memory scrubber.
	 */
	memscrub_init();

	/*
	 * Complete CPU module initialization
	 */
	cmi_post_init();

	/*
	 * Perform forceloading tasks for /etc/system.
	 */
	(void) mod_sysctl(SYS_FORCELOAD, NULL);

	/*
	 * ON4.0: Force /proc module in until clock interrupt handle fixed
	 * ON4.0: This must be fixed or restated in /etc/systems.
	 */
	(void) modload("fs", "procfs");

#if defined(__i386)
	/*
	 * Check for required functional Floating Point hardware,
	 * unless FP hardware explicitly disabled.
	 */
	if (fpu_exists && (fpu_pentium_fdivbug || fp_kind == FP_NO))
		halt("No working FP hardware found");
#endif

	maxmem = freemem;

	add_cpunode2devtree(CPU->cpu_id, CPU->cpu_m.mcpu_cpi);

	/*
	 * Perform the formal initialization of the boot chip,
	 * and associate the boot cpu with it.
	 * This must be done after the cpu node for CPU has been
	 * added to the device tree, when the necessary probing to
	 * know the chip type and chip "id" is performed.
	 */
	chip_cpu_init(CPU);
	chip_cpu_assign(CPU);
}

static int
pp_in_ramdisk(page_t *pp)
{
	extern uint64_t ramdisk_start, ramdisk_end;

	return ((pp->p_pagenum >= btop(ramdisk_start)) &&
	    (pp->p_pagenum < btopr(ramdisk_end)));
}

void
release_bootstrap(void)
{
	int root_is_ramdisk;
	pfn_t pfn;
	page_t *pp;
	extern void kobj_boot_unmountroot(void);
	extern dev_t rootdev;

	/* unmount boot ramdisk and release kmem usage */
	kobj_boot_unmountroot();

	/*
	 * We're finished using the boot loader so free its pages.
	 */
	PRM_POINT("Unmapping lower boot pages");
	clear_boot_mappings(0, kernelbase);
#if defined(__amd64)
	PRM_POINT("Unmapping upper boot pages");
	clear_boot_mappings(BOOT_DOUBLEMAP_BASE,
	    BOOT_DOUBLEMAP_BASE + BOOT_DOUBLEMAP_SIZE);
#endif

	/*
	 * If root isn't on ramdisk, destroy the hardcoded
	 * ramdisk node now and release the memory. Else,
	 * ramdisk memory is kept in rd_pages.
	 */
	root_is_ramdisk = (getmajor(rootdev) == ddi_name_to_major("ramdisk"));
	if (!root_is_ramdisk) {
		dev_info_t *dip = ddi_find_devinfo("ramdisk", -1, 0);
		ASSERT(dip && ddi_get_parent(dip) == ddi_root_node());
		ndi_rele_devi(dip);	/* held from ddi_find_devinfo */
		(void) ddi_remove_child(dip, 0);
	}

	PRM_POINT("Releasing boot pages");
	while (bootpages) {
		pp = bootpages;
		bootpages = pp->p_next;
		if (root_is_ramdisk && pp_in_ramdisk(pp)) {
			pp->p_next = rd_pages;
			rd_pages = pp;
			continue;
		}
		pp->p_next = (struct page *)0;
		page_free(pp, 1);
	}

	/*
	 * Find 1 page below 1 MB so that other processors can boot up.
	 * Make sure it has a kernel VA as well as a 1:1 mapping.
	 * We should have just free'd one up.
	 */
	if (use_mp) {
		for (pfn = 1; pfn < btop(1*1024*1024); pfn++) {
			if (page_numtopp_alloc(pfn) == NULL)
				continue;
			rm_platter_va = i86devmap(pfn, 1,
			    PROT_READ | PROT_WRITE | PROT_EXEC);
			rm_platter_pa = ptob(pfn);
			hat_devload(kas.a_hat,
			    (caddr_t)(uintptr_t)rm_platter_pa, MMU_PAGESIZE,
			    pfn, PROT_READ | PROT_WRITE | PROT_EXEC,
			    HAT_LOAD_NOCONSIST);
			break;
		}
		if (pfn == btop(1*1024*1024))
			panic("No page available for starting "
			    "other processors");
	}

#if defined(__amd64)
	PRM_POINT("Returning boot's VA space to kernel heap");
	if (kmem_setaside != NULL)
		vmem_free(heap_arena, kmem_setaside, BOOT_DOUBLEMAP_SIZE);
#endif
}

/*
 * Initialize the platform-specific parts of a page_t.
 */
void
add_physmem_cb(page_t *pp, pfn_t pnum)
{
	pp->p_pagenum = pnum;
	pp->p_mapping = NULL;
	pp->p_embed = 0;
	pp->p_share = 0;
	pp->p_mlentry = 0;
}

/*
 * kphysm_init() initializes physical memory.
 */
static pgcnt_t
kphysm_init(
	page_t *inpp,
	struct memseg *memsegp,
	pgcnt_t start,
	pgcnt_t npages)
{
	struct memlist	*pmem;
	struct memseg	*cur_memseg;
	struct memseg	**memsegpp;
	pfn_t		base_pfn;
	pgcnt_t		num;
	pgcnt_t		total_skipped = 0;
	pgcnt_t		skipping = 0;
	pgcnt_t		pages_done = 0;
	pgcnt_t		largepgcnt;
	uint64_t	addr;
	uint64_t	size;
	page_t		*pp = inpp;
	int		dobreak = 0;
	extern pfn_t	ddiphysmin;

	ASSERT(page_hash != NULL && page_hashsz != 0);

	for (cur_memseg = memsegp; cur_memseg->pages != NULL; cur_memseg++);
	ASSERT(cur_memseg == memsegp || start > 0);

	for (pmem = phys_avail; pmem && npages; pmem = pmem->next) {
		/*
		 * In a 32 bit kernel can't use higher memory if we're
		 * not booting in PAE mode. This check takes care of that.
		 */
		addr = pmem->address;
		size = pmem->size;
		if (btop(addr) > physmax)
			continue;

		/*
		 * align addr and size - they may not be at page boundaries
		 */
		if ((addr & MMU_PAGEOFFSET) != 0) {
			addr += MMU_PAGEOFFSET;
			addr &= ~(uint64_t)MMU_PAGEOFFSET;
			size -= addr - pmem->address;
		}

		/* only process pages below or equal to physmax */
		if ((btop(addr + size) - 1) > physmax)
			size = ptob(physmax - btop(addr) + 1);

		num = btop(size);
		if (num == 0)
			continue;

		if (total_skipped < start) {
			if (start - total_skipped > num) {
				total_skipped += num;
				continue;
			}
			skipping = start - total_skipped;
			num -= skipping;
			addr += (MMU_PAGESIZE * skipping);
			total_skipped = start;
		}
		if (num == 0)
			continue;

		if (num > npages)
			num = npages;

		npages -= num;
		pages_done += num;
		base_pfn = btop(addr);

		/*
		 * If the caller didn't provide space for the page
		 * structures, carve them out of the memseg they will
		 * represent.
		 */
		if (pp == NULL) {
			pgcnt_t pp_pgs;

			if (num <= 1)
				continue;

			/*
			 * Compute how many of the pages we need to use for
			 * page_ts
			 */
			pp_pgs = (num * sizeof (page_t)) / MMU_PAGESIZE + 1;
			while (mmu_ptob(pp_pgs - 1) / sizeof (page_t) >=
			    num - pp_pgs + 1)
				--pp_pgs;
			PRM_DEBUG(pp_pgs);

			pp = vmem_alloc(heap_arena, mmu_ptob(pp_pgs),
			    VM_NOSLEEP);
			if (pp == NULL) {
				cmn_err(CE_WARN, "Unable to add %ld pages to "
				    "the system.", num);
				continue;
			}

			hat_devload(kas.a_hat, (void *)pp, mmu_ptob(pp_pgs),
			    base_pfn, PROT_READ | PROT_WRITE | HAT_UNORDERED_OK,
			    HAT_LOAD | HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);
			bzero(pp, mmu_ptob(pp_pgs));
			num -= pp_pgs;
			base_pfn += pp_pgs;
		}

		if (prom_debug)
			prom_printf("MEMSEG addr=0x%" PRIx64
			    " pgs=0x%lx pfn 0x%lx-0x%lx\n",
			    addr, num, base_pfn, base_pfn + num);

		/*
		 * drop pages below ddiphysmin to simplify ddi memory
		 * allocation with non-zero addr_lo requests.
		 */
		if (base_pfn < ddiphysmin) {
			if (base_pfn + num <= ddiphysmin) {
				/* drop entire range below ddiphysmin */
				continue;
			}
			/* adjust range to ddiphysmin */
			pp += (ddiphysmin - base_pfn);
			num -= (ddiphysmin - base_pfn);
			base_pfn = ddiphysmin;
		}
		/*
		 * Build the memsegs entry
		 */
		cur_memseg->pages = pp;
		cur_memseg->epages = pp + num;
		cur_memseg->pages_base = base_pfn;
		cur_memseg->pages_end = base_pfn + num;

		/*
		 * insert in memseg list in decreasing pfn range order.
		 * Low memory is typically more fragmented such that this
		 * ordering keeps the larger ranges at the front of the list
		 * for code that searches memseg.
		 */
		memsegpp = &memsegs;
		for (;;) {
			if (*memsegpp == NULL) {
				/* empty memsegs */
				memsegs = cur_memseg;
				break;
			}
			/* check for continuity with start of memsegpp */
			if (cur_memseg->pages_end == (*memsegpp)->pages_base) {
				if (cur_memseg->epages == (*memsegpp)->pages) {
					/*
					 * contiguous pfn and page_t's. Merge
					 * cur_memseg into *memsegpp. Drop
					 * cur_memseg
					 */
					(*memsegpp)->pages_base =
					    cur_memseg->pages_base;
					(*memsegpp)->pages =
					    cur_memseg->pages;
					/*
					 * check if contiguous with the end of
					 * the next memseg.
					 */
					if ((*memsegpp)->next &&
					    ((*memsegpp)->pages_base ==
					    (*memsegpp)->next->pages_end)) {
						cur_memseg = *memsegpp;
						memsegpp = &((*memsegpp)->next);
						dobreak = 1;
					} else {
						break;
					}
				} else {
					/*
					 * contiguous pfn but not page_t's.
					 * drop last pfn/page_t in cur_memseg
					 * to prevent creation of large pages
					 * with noncontiguous page_t's if not
					 * aligned to largest page boundary.
					 */
					largepgcnt = page_get_pagecnt(
					    page_num_pagesizes() - 1);

					if (cur_memseg->pages_end &
					    (largepgcnt - 1)) {
						num--;
						cur_memseg->epages--;
						cur_memseg->pages_end--;
					}
				}
			}

			/* check for continuity with end of memsegpp */
			if (cur_memseg->pages_base == (*memsegpp)->pages_end) {
				if (cur_memseg->pages == (*memsegpp)->epages) {
					/*
					 * contiguous pfn and page_t's. Merge
					 * cur_memseg into *memsegpp. Drop
					 * cur_memseg.
					 */
					if (dobreak) {
						/* merge previously done */
						cur_memseg->pages =
						    (*memsegpp)->pages;
						cur_memseg->pages_base =
						    (*memsegpp)->pages_base;
						cur_memseg->next =
						    (*memsegpp)->next;
					} else {
						(*memsegpp)->pages_end =
						    cur_memseg->pages_end;
						(*memsegpp)->epages =
						    cur_memseg->epages;
					}
					break;
				}
				/*
				 * contiguous pfn but not page_t's.
				 * drop first pfn/page_t in cur_memseg
				 * to prevent creation of large pages
				 * with noncontiguous page_t's if not
				 * aligned to largest page boundary.
				 */
				largepgcnt = page_get_pagecnt(
				    page_num_pagesizes() - 1);
				if (base_pfn & (largepgcnt - 1)) {
					num--;
					base_pfn++;
					cur_memseg->pages++;
					cur_memseg->pages_base++;
					pp = cur_memseg->pages;
				}
				if (dobreak)
					break;
			}

			if (cur_memseg->pages_base >=
			    (*memsegpp)->pages_end) {
				cur_memseg->next = *memsegpp;
				*memsegpp = cur_memseg;
				break;
			}
			if ((*memsegpp)->next == NULL) {
				cur_memseg->next = NULL;
				(*memsegpp)->next = cur_memseg;
				break;
			}
			memsegpp = &((*memsegpp)->next);
			ASSERT(*memsegpp != NULL);
		}

		/*
		 * add_physmem() initializes the PSM part of the page
		 * struct by calling the PSM back with add_physmem_cb().
		 * In addition it coalesces pages into larger pages as
		 * it initializes them.
		 */
		add_physmem(pp, num, base_pfn);
		cur_memseg++;
		availrmem_initial += num;
		availrmem += num;

		/*
		 * If the caller provided the page frames to us, then
		 * advance in that list.  Otherwise, prepare to allocate
		 * our own page frames for the next memseg.
		 */
		pp = (inpp == NULL) ? NULL : pp + num;
	}

	PRM_DEBUG(availrmem_initial);
	PRM_DEBUG(availrmem);
	PRM_DEBUG(freemem);
	build_pfn_hash();
	return (pages_done);
}

/*
 * Kernel VM initialization.
 */
static void
kvm_init(void)
{
#ifdef DEBUG
	extern void _start();

	ASSERT((caddr_t)_start == s_text);
#endif
	ASSERT((((uintptr_t)s_text) & MMU_PAGEOFFSET) == 0);

	/*
	 * Put the kernel segments in kernel address space.
	 */
	rw_enter(&kas.a_lock, RW_WRITER);
	as_avlinit(&kas);

	(void) seg_attach(&kas, s_text, e_moddata - s_text, &ktextseg);
	(void) segkmem_create(&ktextseg);

	(void) seg_attach(&kas, (caddr_t)valloc_base, valloc_sz, &kvalloc);
	(void) segkmem_create(&kvalloc);

	/*
	 * We're about to map out /boot.  This is the beginning of the
	 * system resource management transition. We can no longer
	 * call into /boot for I/O or memory allocations.
	 *
	 * XX64 - Is this still correct with kernelheap_extend() being called
	 * later than this????
	 */
	(void) seg_attach(&kas, final_kernelheap,
	    ekernelheap - final_kernelheap, &kvseg);
	(void) segkmem_create(&kvseg);

#if defined(__amd64)
	(void) seg_attach(&kas, (caddr_t)core_base, core_size, &kvseg_core);
	(void) segkmem_create(&kvseg_core);
#endif

	(void) seg_attach(&kas, (caddr_t)SEGDEBUGBASE, (size_t)SEGDEBUGSIZE,
	    &kdebugseg);
	(void) segkmem_create(&kdebugseg);

	rw_exit(&kas.a_lock);

	/*
	 * Ensure that the red zone at kernelbase is never accessible.
	 */
	(void) as_setprot(&kas, (caddr_t)kernelbase, KERNEL_REDZONE_SIZE, 0);

	/*
	 * Make the text writable so that it can be hot patched by DTrace.
	 */
	(void) as_setprot(&kas, s_text, e_modtext - s_text,
	    PROT_READ | PROT_WRITE | PROT_EXEC);

	/*
	 * Make data writable until end.
	 */
	(void) as_setprot(&kas, s_data, e_moddata - s_data,
	    PROT_READ | PROT_WRITE | PROT_EXEC);
}

/*
 * These are MTTR registers supported by P6
 */
static struct	mtrrvar	mtrrphys_arr[MAX_MTRRVAR];
static uint64_t mtrr64k, mtrr16k1, mtrr16k2;
static uint64_t mtrr4k1, mtrr4k2, mtrr4k3;
static uint64_t mtrr4k4, mtrr4k5, mtrr4k6;
static uint64_t mtrr4k7, mtrr4k8, mtrrcap;
uint64_t mtrrdef, pat_attr_reg;

/*
 * Disable reprogramming of MTRRs by default.
 */
int	enable_relaxed_mtrr = 0;

void
setup_mtrr(void)
{
	int i, ecx;
	int vcnt;
	struct	mtrrvar	*mtrrphys;

	if (!(x86_feature & X86_MTRR))
		return;

	mtrrcap = rdmsr(REG_MTRRCAP);
	mtrrdef = rdmsr(REG_MTRRDEF);
	if (mtrrcap & MTRRCAP_FIX) {
		mtrr64k = rdmsr(REG_MTRR64K);
		mtrr16k1 = rdmsr(REG_MTRR16K1);
		mtrr16k2 = rdmsr(REG_MTRR16K2);
		mtrr4k1 = rdmsr(REG_MTRR4K1);
		mtrr4k2 = rdmsr(REG_MTRR4K2);
		mtrr4k3 = rdmsr(REG_MTRR4K3);
		mtrr4k4 = rdmsr(REG_MTRR4K4);
		mtrr4k5 = rdmsr(REG_MTRR4K5);
		mtrr4k6 = rdmsr(REG_MTRR4K6);
		mtrr4k7 = rdmsr(REG_MTRR4K7);
		mtrr4k8 = rdmsr(REG_MTRR4K8);
	}
	if ((vcnt = (mtrrcap & MTRRCAP_VCNTMASK)) > MAX_MTRRVAR)
		vcnt = MAX_MTRRVAR;

	for (i = 0, ecx = REG_MTRRPHYSBASE0, mtrrphys = mtrrphys_arr;
		i <  vcnt - 1; i++, ecx += 2, mtrrphys++) {
		mtrrphys->mtrrphys_base = rdmsr(ecx);
		mtrrphys->mtrrphys_mask = rdmsr(ecx + 1);
		if ((x86_feature & X86_PAT) && enable_relaxed_mtrr) {
			mtrrphys->mtrrphys_mask &= ~MTRRPHYSMASK_V;
		}
	}
	if (x86_feature & X86_PAT) {
		if (enable_relaxed_mtrr)
			mtrrdef = MTRR_TYPE_WB|MTRRDEF_FE|MTRRDEF_E;
		pat_attr_reg = PAT_DEFAULT_ATTRIBUTE;
	}

	mtrr_sync();
}

/*
 * Sync current cpu mtrr with the incore copy of mtrr.
 * This function has to be invoked with interrupts disabled
 * Currently we do not capture other cpu's. This is invoked on cpu0
 * just after reading /etc/system.
 * On other cpu's its invoked from mp_startup().
 */
void
mtrr_sync(void)
{
	uint_t	crvalue, cr0_orig;
	int	vcnt, i, ecx;
	struct	mtrrvar	*mtrrphys;

	cr0_orig = crvalue = getcr0();
	crvalue |= CR0_CD;
	crvalue &= ~CR0_NW;
	setcr0(crvalue);
	invalidate_cache();
	setcr3(getcr3());

	if (x86_feature & X86_PAT)
		wrmsr(REG_MTRRPAT, pat_attr_reg);

	wrmsr(REG_MTRRDEF, rdmsr(REG_MTRRDEF) &
	    ~((uint64_t)(uintptr_t)MTRRDEF_E));

	if (mtrrcap & MTRRCAP_FIX) {
		wrmsr(REG_MTRR64K, mtrr64k);
		wrmsr(REG_MTRR16K1, mtrr16k1);
		wrmsr(REG_MTRR16K2, mtrr16k2);
		wrmsr(REG_MTRR4K1, mtrr4k1);
		wrmsr(REG_MTRR4K2, mtrr4k2);
		wrmsr(REG_MTRR4K3, mtrr4k3);
		wrmsr(REG_MTRR4K4, mtrr4k4);
		wrmsr(REG_MTRR4K5, mtrr4k5);
		wrmsr(REG_MTRR4K6, mtrr4k6);
		wrmsr(REG_MTRR4K7, mtrr4k7);
		wrmsr(REG_MTRR4K8, mtrr4k8);
	}
	if ((vcnt = (mtrrcap & MTRRCAP_VCNTMASK)) > MAX_MTRRVAR)
		vcnt = MAX_MTRRVAR;
	for (i = 0, ecx = REG_MTRRPHYSBASE0, mtrrphys = mtrrphys_arr;
	    i <  vcnt - 1; i++, ecx += 2, mtrrphys++) {
		wrmsr(ecx, mtrrphys->mtrrphys_base);
		wrmsr(ecx + 1, mtrrphys->mtrrphys_mask);
	}
	wrmsr(REG_MTRRDEF, mtrrdef);
	setcr3(getcr3());
	invalidate_cache();
	setcr0(cr0_orig);
}

/*
 * resync mtrr so that BIOS is happy. Called from mdboot
 */
void
mtrr_resync(void)
{
	if ((x86_feature & X86_PAT) && enable_relaxed_mtrr) {
		/*
		 * We could have changed the default mtrr definition.
		 * Put it back to uncached which is what it is at power on
		 */
		mtrrdef = MTRR_TYPE_UC|MTRRDEF_FE|MTRRDEF_E;
		mtrr_sync();
	}
}

void
get_system_configuration(void)
{
	char	prop[32];
	u_longlong_t nodes_ll, cpus_pernode_ll, lvalue;

	if (((BOP_GETPROPLEN(bootops, "nodes") > sizeof (prop)) ||
		(BOP_GETPROP(bootops, "nodes", prop) < 0) 	||
		(kobj_getvalue(prop, &nodes_ll) == -1) ||
		(nodes_ll > MAXNODES))			   ||
	    ((BOP_GETPROPLEN(bootops, "cpus_pernode") > sizeof (prop)) ||
		(BOP_GETPROP(bootops, "cpus_pernode", prop) < 0) ||
		(kobj_getvalue(prop, &cpus_pernode_ll) == -1))) {

		system_hardware.hd_nodes = 1;
		system_hardware.hd_cpus_per_node = 0;
	} else {
		system_hardware.hd_nodes = (int)nodes_ll;
		system_hardware.hd_cpus_per_node = (int)cpus_pernode_ll;
	}
	if ((BOP_GETPROPLEN(bootops, "kernelbase") > sizeof (prop)) ||
		(BOP_GETPROP(bootops, "kernelbase", prop) < 0) 	||
		(kobj_getvalue(prop, &lvalue) == -1))
			eprom_kernelbase = NULL;
	else
			eprom_kernelbase = (uintptr_t)lvalue;

	if ((BOP_GETPROPLEN(bootops, "segmapsize") > sizeof (prop)) ||
	    (BOP_GETPROP(bootops, "segmapsize", prop) < 0) ||
	    (kobj_getvalue(prop, &lvalue) == -1)) {
		segmapsize = SEGMAPDEFAULT;
	} else {
		segmapsize = (uintptr_t)lvalue;
	}

	if ((BOP_GETPROPLEN(bootops, "segmapfreelists") > sizeof (prop)) ||
	    (BOP_GETPROP(bootops, "segmapfreelists", prop) < 0) ||
	    (kobj_getvalue(prop, &lvalue) == -1)) {
		segmapfreelists = 0;	/* use segmap driver default */
	} else {
		segmapfreelists = (int)lvalue;
	}

	if ((BOP_GETPROPLEN(bootops, "physmem") <= sizeof (prop)) &&
	    (BOP_GETPROP(bootops, "physmem", prop) >= 0) &&
	    (kobj_getvalue(prop, &lvalue) != -1)) {
		physmem = (uintptr_t)lvalue;
	}
}

/*
 * Add to a memory list.
 * start = start of new memory segment
 * len = length of new memory segment in bytes
 * new = pointer to a new struct memlist
 * memlistp = memory list to which to add segment.
 */
static void
memlist_add(
	uint64_t start,
	uint64_t len,
	struct memlist *new,
	struct memlist **memlistp)
{
	struct memlist *cur;
	uint64_t end = start + len;

	new->address = start;
	new->size = len;

	cur = *memlistp;

	while (cur) {
		if (cur->address >= end) {
			new->next = cur;
			*memlistp = new;
			new->prev = cur->prev;
			cur->prev = new;
			return;
		}
		ASSERT(cur->address + cur->size <= start);
		if (cur->next == NULL) {
			cur->next = new;
			new->prev = cur;
			new->next = NULL;
			return;
		}
		memlistp = &cur->next;
		cur = cur->next;
	}
}

void
kobj_vmem_init(vmem_t **text_arena, vmem_t **data_arena)
{
	size_t tsize = e_modtext - modtext;
	size_t dsize = e_moddata - moddata;

	*text_arena = vmem_create("module_text", tsize ? modtext : NULL, tsize,
	    1, segkmem_alloc, segkmem_free, heaptext_arena, 0, VM_SLEEP);
	*data_arena = vmem_create("module_data", dsize ? moddata : NULL, dsize,
	    1, segkmem_alloc, segkmem_free, heap32_arena, 0, VM_SLEEP);
}

caddr_t
kobj_text_alloc(vmem_t *arena, size_t size)
{
	return (vmem_alloc(arena, size, VM_SLEEP | VM_BESTFIT));
}

/*ARGSUSED*/
caddr_t
kobj_texthole_alloc(caddr_t addr, size_t size)
{
	panic("unexpected call to kobj_texthole_alloc()");
	/*NOTREACHED*/
	return (0);
}

/*ARGSUSED*/
void
kobj_texthole_free(caddr_t addr, size_t size)
{
	panic("unexpected call to kobj_texthole_free()");
}

/*
 * This is called just after configure() in startup().
 *
 * The ISALIST concept is a bit hopeless on Intel, because
 * there's no guarantee of an ever-more-capable processor
 * given that various parts of the instruction set may appear
 * and disappear between different implementations.
 *
 * While it would be possible to correct it and even enhance
 * it somewhat, the explicit hardware capability bitmask allows
 * more flexibility.
 *
 * So, we just leave this alone.
 */
void
setx86isalist(void)
{
	char *tp;
	size_t len;
	extern char *isa_list;

#define	TBUFSIZE	1024

	tp = kmem_alloc(TBUFSIZE, KM_SLEEP);
	*tp = '\0';

#if defined(__amd64)
	(void) strcpy(tp, "amd64 ");
#endif

	switch (x86_vendor) {
	case X86_VENDOR_Intel:
	case X86_VENDOR_AMD:
	case X86_VENDOR_TM:
		if (x86_feature & X86_CMOV) {
			/*
			 * Pentium Pro or later
			 */
			(void) strcat(tp, "pentium_pro");
			(void) strcat(tp, x86_feature & X86_MMX ?
			    "+mmx pentium_pro " : " ");
		}
		/*FALLTHROUGH*/
	case X86_VENDOR_Cyrix:
		/*
		 * The Cyrix 6x86 does not have any Pentium features
		 * accessible while not at privilege level 0.
		 */
		if (x86_feature & X86_CPUID) {
			(void) strcat(tp, "pentium");
			(void) strcat(tp, x86_feature & X86_MMX ?
			    "+mmx pentium " : " ");
		}
		break;
	default:
		break;
	}
	(void) strcat(tp, "i486 i386 i86");
	len = strlen(tp) + 1;   /* account for NULL at end of string */
	isa_list = strcpy(kmem_alloc(len, KM_SLEEP), tp);
	kmem_free(tp, TBUFSIZE);

#undef TBUFSIZE
}


#ifdef __amd64

void *
device_arena_alloc(size_t size, int vm_flag)
{
	return (vmem_alloc(device_arena, size, vm_flag));
}

void
device_arena_free(void *vaddr, size_t size)
{
	vmem_free(device_arena, vaddr, size);
}

#else

void *
device_arena_alloc(size_t size, int vm_flag)
{
	caddr_t	vaddr;
	uintptr_t v;
	size_t	start;
	size_t	end;

	vaddr = vmem_alloc(heap_arena, size, vm_flag);
	if (vaddr == NULL)
		return (NULL);

	v = (uintptr_t)vaddr;
	ASSERT(v >= kernelbase);
	ASSERT(v + size <= ptable_va);

	start = btop(v - kernelbase);
	end = btop(v + size - 1 - kernelbase);
	ASSERT(start < toxic_bit_map_len);
	ASSERT(end < toxic_bit_map_len);

	while (start <= end) {
		BT_ATOMIC_SET(toxic_bit_map, start);
		++start;
	}
	return (vaddr);
}

void
device_arena_free(void *vaddr, size_t size)
{
	uintptr_t v = (uintptr_t)vaddr;
	size_t	start;
	size_t	end;

	ASSERT(v >= kernelbase);
	ASSERT(v + size <= ptable_va);

	start = btop(v - kernelbase);
	end = btop(v + size - 1 - kernelbase);
	ASSERT(start < toxic_bit_map_len);
	ASSERT(end < toxic_bit_map_len);

	while (start <= end) {
		ASSERT(BT_TEST(toxic_bit_map, start) != 0);
		BT_ATOMIC_CLEAR(toxic_bit_map, start);
		++start;
	}
	vmem_free(heap_arena, vaddr, size);
}

/*
 * returns 1st address in range that is in device arena, or NULL
 * if len is not NULL it returns the length of the toxic range
 */
void *
device_arena_contains(void *vaddr, size_t size, size_t *len)
{
	uintptr_t v = (uintptr_t)vaddr;
	uintptr_t eaddr = v + size;
	size_t start;
	size_t end;

	/*
	 * if called very early by kmdb, just return NULL
	 */
	if (toxic_bit_map == NULL)
		return (NULL);

	/*
	 * First check if we're completely outside the bitmap range.
	 */
	if (v >= ptable_va || eaddr < kernelbase)
		return (NULL);

	/*
	 * Trim ends of search to look at only what the bitmap covers.
	 */
	if (v < kernelbase)
		v = kernelbase;
	start = btop(v - kernelbase);
	end = btop(eaddr - kernelbase);
	if (end >= toxic_bit_map_len)
		end = toxic_bit_map_len;

	if (bt_range(toxic_bit_map, &start, &end, end) == 0)
		return (NULL);

	v = kernelbase + ptob(start);
	if (len != NULL)
		*len = ptob(end - start);
	return ((void *)v);
}

#endif
