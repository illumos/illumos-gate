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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2015 Joyent, Inc.
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

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
#include <sys/mem.h>
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
#include <sys/memlist_plat.h>
#include <sys/varargs.h>
#include <sys/promif.h>
#include <sys/modctl.h>

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
#include <vm/kboot_mmu.h>
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
#include <sys/cpuvar.h>
#include <sys/segments.h>
#include <sys/clconf.h>
#include <sys/kobj.h>
#include <sys/kobj_lex.h>
#include <sys/cpc_impl.h>
#include <sys/cpu_module.h>
#include <sys/smbios.h>
#include <sys/debug_info.h>
#include <sys/bootinfo.h>
#include <sys/ddi_periodic.h>
#include <sys/systeminfo.h>
#include <sys/multiboot.h>
#include <sys/ramdisk.h>

#ifdef	__xpv

#include <sys/hypervisor.h>
#include <sys/xen_mmu.h>
#include <sys/evtchn_impl.h>
#include <sys/gnttab.h>
#include <sys/xpv_panic.h>
#include <xen/sys/xenbus_comms.h>
#include <xen/public/physdev.h>

extern void xen_late_startup(void);

struct xen_evt_data cpu0_evt_data;

#else	/* __xpv */
#include <sys/memlist_impl.h>

extern void mem_config_init(void);
#endif /* __xpv */

extern void progressbar_init(void);
extern void brand_init(void);
extern void pcf_init(void);
extern void pg_init(void);
extern void ssp_init(void);

extern int size_pse_array(pgcnt_t, int);

#if defined(_SOFT_HOSTID)

#include <sys/rtc.h>

static int32_t set_soft_hostid(void);
static char hostid_file[] = "/etc/hostid";

#endif

void *gfx_devinfo_list;

#if defined(__amd64) && !defined(__xpv)
extern void immu_startup(void);
#endif

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
static void startup_kmem(void);
static void startup_modules(void);
static void startup_vm(void);
static void startup_end(void);
static void layout_kernel_va(void);

/*
 * Declare these as initialized data so we can patch them.
 */
#ifdef __i386

/*
 * Due to virtual address space limitations running in 32 bit mode, restrict
 * the amount of physical memory configured to a max of PHYSMEM pages (16g).
 *
 * If the physical max memory size of 64g were allowed to be configured, the
 * size of user virtual address space will be less than 1g. A limited user
 * address space greatly reduces the range of applications that can run.
 *
 * If more physical memory than PHYSMEM is required, users should preferably
 * run in 64 bit mode which has far looser virtual address space limitations.
 *
 * If 64 bit mode is not available (as in IA32) and/or more physical memory
 * than PHYSMEM is required in 32 bit mode, physmem can be set to the desired
 * value or to 0 (to configure all available memory) via eeprom(1M). kernelbase
 * should also be carefully tuned to balance out the need of the user
 * application while minimizing the risk of kernel heap exhaustion due to
 * kernelbase being set too high.
 */
#define	PHYSMEM	0x400000

#else /* __amd64 */

/*
 * For now we can handle memory with physical addresses up to about
 * 64 Terabytes. This keeps the kernel above the VA hole, leaving roughly
 * half the VA space for seg_kpm. When systems get bigger than 64TB this
 * code will need revisiting. There is an implicit assumption that there
 * are no *huge* holes in the physical address space too.
 */
#define	TERABYTE		(1ul << 40)
#define	PHYSMEM_MAX64		mmu_btop(64 * TERABYTE)
#define	PHYSMEM			PHYSMEM_MAX64
#define	AMD64_VA_HOLE_END	0xFFFF800000000000ul

#endif /* __amd64 */

pgcnt_t physmem = PHYSMEM;
pgcnt_t obp_pages;	/* Memory used by PROM for its text and data */

char *kobj_file_buf;
int kobj_file_bufsize;	/* set in /etc/system */

/* Global variables for MP support. Used in mp_startup */
caddr_t	rm_platter_va = 0;
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
static int kpm_desired;
#ifdef __amd64
static uintptr_t segkpm_base = (uintptr_t)SEGKPM_BASE;
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
char kern_bootfile[OBP_MAXPATHLEN];

/*
 * ZFS zio segment.  This allows us to exclude large portions of ZFS data that
 * gets cached in kmem caches on the heap.  If this is set to zero, we allocate
 * zio buffers from their own segment, otherwise they are allocated from the
 * heap.  The optimization of allocating zio buffers from their own segment is
 * only valid on 64-bit kernels.
 */
#if defined(__amd64)
int segzio_fromheap = 0;
#else
int segzio_fromheap = 1;
#endif

/*
 * Give folks an escape hatch for disabling SMAP via kmdb. Doesn't work
 * post-boot.
 */
int disable_smap = 0;

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
unsigned int page_hashsz_shift;	/* log2(page_hashsz) */
struct page *pp_base;		/* Base of initial system page struct array */
struct page **page_hash;	/* Page hash table */
pad_mutex_t *pse_mutex;		/* Locks protecting pp->p_selock */
size_t pse_table_size;		/* Number of mutexes in pse_mutex[] */
int pse_shift;			/* log2(pse_table_size) */
struct seg ktextseg;		/* Segment used for kernel executable image */
struct seg kvalloc;		/* Segment used for "valloc" mapping */
struct seg kpseg;		/* Segment used for pageable kernel virt mem */
struct seg kmapseg;		/* Segment used for generic kernel mappings */
struct seg kdebugseg;		/* Segment used for the kernel debugger */

struct seg *segkmap = &kmapseg;	/* Kernel generic mapping segment */
static struct seg *segmap = &kmapseg;	/* easier to use name for in here */

struct seg *segkp = &kpseg;	/* Pageable kernel virtual memory segment */

#if defined(__amd64)
struct seg kvseg_core;		/* Segment used for the core heap */
struct seg kpmseg;		/* Segment used for physical mapping */
struct seg *segkpm = &kpmseg;	/* 64bit kernel physical mapping segment */
#else
struct seg *segkpm = NULL;	/* Unused on IA32 */
#endif

caddr_t segkp_base;		/* Base address of segkp */
caddr_t segzio_base;		/* Base address of segzio */
#if defined(__amd64)
pgcnt_t segkpsize = btop(SEGKPDEFSIZE);	/* size of segkp segment in pages */
#else
pgcnt_t segkpsize = 0;
#endif
pgcnt_t segziosize = 0;		/* size of zio segment in pages */

/*
 * A static DR page_t VA map is reserved that can map the page structures
 * for a domain's entire RA space. The pages that back this space are
 * dynamically allocated and need not be physically contiguous.  The DR
 * map size is derived from KPM size.
 * This mechanism isn't used by x86 yet, so just stubs here.
 */
int ppvm_enable = 0;		/* Static virtual map for page structs */
page_t *ppvm_base = NULL;	/* Base of page struct map */
pgcnt_t ppvm_size = 0;		/* Size of page struct map */

/*
 * VA range available to the debugger
 */
const caddr_t kdi_segdebugbase = (const caddr_t)SEGDEBUGBASE;
const size_t kdi_segdebugsize = SEGDEBUGSIZE;

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
struct memlist *bios_rsvd;	/* Bios reserved memory */

/*
 * kphysm_init returns the number of pages that were processed
 */
static pgcnt_t kphysm_init(page_t *, pgcnt_t);

#define	IO_PROP_SIZE	64	/* device property size */

/*
 * a couple useful roundup macros
 */
#define	ROUND_UP_PAGE(x)	\
	((uintptr_t)P2ROUNDUP((uintptr_t)(x), (uintptr_t)MMU_PAGESIZE))
#define	ROUND_UP_LPAGE(x)	\
	((uintptr_t)P2ROUNDUP((uintptr_t)(x), mmu.level_size[1]))
#define	ROUND_UP_4MEG(x)	\
	((uintptr_t)P2ROUNDUP((uintptr_t)(x), (uintptr_t)FOUR_MEG))
#define	ROUND_UP_TOPLEVEL(x)	\
	((uintptr_t)P2ROUNDUP((uintptr_t)(x), mmu.level_size[mmu.max_level]))

/*
 *	32-bit Kernel's Virtual memory layout.
 *		+-----------------------+
 *		|			|
 * 0xFFC00000  -|-----------------------|- ARGSBASE
 *		|	debugger	|
 * 0xFF800000  -|-----------------------|- SEGDEBUGBASE
 *		|      Kernel Data	|
 * 0xFEC00000  -|-----------------------|
 *              |      Kernel Text	|
 * 0xFE800000  -|-----------------------|- KERNEL_TEXT (0xFB400000 on Xen)
 *		|---       GDT       ---|- GDT page (GDT_VA)
 *		|---    debug info   ---|- debug info (DEBUG_INFO_VA)
 *		|			|
 *		|   page_t structures	|
 *		|   memsegs, memlists,	|
 *		|   page hash, etc.	|
 * ---	       -|-----------------------|- ekernelheap, valloc_base (floating)
 *		|			|  (segkp is just an arena in the heap)
 *		|			|
 *		|	kvseg		|
 *		|			|
 *		|			|
 * ---         -|-----------------------|- kernelheap (floating)
 *		|        Segkmap	|
 * 0xC3002000  -|-----------------------|- segmap_start (floating)
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
 *			|			|
 * 0xFFFFFFFF.FFC00000  |-----------------------|- ARGSBASE
 *			|	debugger (?)	|
 * 0xFFFFFFFF.FF800000  |-----------------------|- SEGDEBUGBASE
 *			|      unused		|
 *			+-----------------------+
 *			|      Kernel Data	|
 * 0xFFFFFFFF.FBC00000  |-----------------------|
 *			|      Kernel Text	|
 * 0xFFFFFFFF.FB800000  |-----------------------|- KERNEL_TEXT
 *			|---       GDT       ---|- GDT page (GDT_VA)
 *			|---    debug info   ---|- debug info (DEBUG_INFO_VA)
 *			|			|
 *			|      Core heap	| (used for loadable modules)
 * 0xFFFFFFFF.C0000000  |-----------------------|- core_base / ekernelheap
 *			|	 Kernel		|
 *			|	  heap		|
 * 0xFFFFFXXX.XXX00000  |-----------------------|- kernelheap (floating)
 *			|	 segmap		|
 * 0xFFFFFXXX.XXX00000  |-----------------------|- segmap_start (floating)
 *			|    device mappings	|
 * 0xFFFFFXXX.XXX00000  |-----------------------|- toxic_addr (floating)
 *			|	  segzio	|
 * 0xFFFFFXXX.XXX00000  |-----------------------|- segzio_base (floating)
 *			|	  segkp		|
 * ---                  |-----------------------|- segkp_base (floating)
 *			|   page_t structures	|  valloc_base + valloc_sz
 *			|   memsegs, memlists,	|
 *			|   page hash, etc.	|
 * 0xFFFFFF00.00000000  |-----------------------|- valloc_base (lower if >256GB)
 *			|	 segkpm		|
 * 0xFFFFFE00.00000000  |-----------------------|
 *			|	Red Zone	|
 * 0xFFFFFD80.00000000  |-----------------------|- KERNELBASE (lower if >256GB)
 *			|     User stack	|- User space memory
 *			|			|
 *			| shared objects, etc	|	(grows downwards)
 *			:			:
 *			|			|
 * 0xFFFF8000.00000000  |-----------------------|
 *			|			|
 *			| VA Hole / unused	|
 *			|			|
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
 * structures.  This region contains page_t structures for
 * physical memory, memsegs, memlists, and the page hash.
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
 * segmap_start: start of segmap. The length of segmap can be modified
 * through eeprom. The default length is 16MB on 32-bit systems and 64MB
 * on 64-bit systems.
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
extern time_t process_rtc_config_file(void);

uintptr_t	kernelbase;
uintptr_t	postbootkernelbase;	/* not set till boot loader is gone */
uintptr_t	eprom_kernelbase;
size_t		segmapsize;
uintptr_t	segmap_start;
int		segmapfreelists;
pgcnt_t		npages;
pgcnt_t		orig_npages;
size_t		core_size;		/* size of "core" heap */
uintptr_t	core_base;		/* base address of "core" heap */

/*
 * List of bootstrap pages. We mark these as allocated in startup.
 * release_bootstrap() will free them when we're completely done with
 * the bootstrap.
 */
static page_t *bootpages;

/*
 * boot time pages that have a vnode from the ramdisk will keep that forever.
 */
static page_t *rd_pages;

/*
 * Lower 64K
 */
static page_t *lower_pages = NULL;
static int lower_pages_count = 0;

struct system_hardware system_hardware;

/*
 * Enable some debugging messages concerning memory usage...
 */
static void
print_memlist(char *title, struct memlist *mp)
{
	prom_printf("MEMLIST: %s:\n", title);
	while (mp != NULL)  {
		prom_printf("\tAddress 0x%" PRIx64 ", size 0x%" PRIx64 "\n",
		    mp->ml_address, mp->ml_size);
		mp = mp->ml_next;
	}
}

/*
 * XX64 need a comment here.. are these just default values, surely
 * we read the "cpuid" type information to figure this out.
 */
int	l2cache_sz = 0x80000;
int	l2cache_linesz = 0x40;
int	l2cache_assoc = 1;

static size_t	textrepl_min_gb = 10;

/*
 * on 64 bit we use a predifined VA range for mapping devices in the kernel
 * on 32 bit the mappings are intermixed in the heap, so we use a bit map
 */
#ifdef __amd64

vmem_t		*device_arena;
uintptr_t	toxic_addr = (uintptr_t)NULL;
size_t		toxic_size = 1024 * 1024 * 1024; /* Sparc uses 1 gig too */

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
#define	NUM_ALLOCATIONS 8
int num_allocations = 0;
struct {
	void **al_ptr;
	size_t al_size;
} allocations[NUM_ALLOCATIONS];
size_t valloc_sz = 0;
uintptr_t valloc_base;

#define	ADD_TO_ALLOCATIONS(ptr, size) {					\
		size = ROUND_UP_PAGE(size);		 		\
		if (num_allocations == NUM_ALLOCATIONS)			\
			panic("too many ADD_TO_ALLOCATIONS()");		\
		allocations[num_allocations].al_ptr = (void**)&ptr;	\
		allocations[num_allocations].al_size = size;		\
		valloc_sz += size;					\
		++num_allocations;				 	\
	}

/*
 * Allocate all the initial memory needed by the page allocator.
 */
static void
perform_allocations(void)
{
	caddr_t mem;
	int i;
	int valloc_align;

	PRM_DEBUG(valloc_base);
	PRM_DEBUG(valloc_sz);
	valloc_align = mmu.level_size[mmu.max_page_level > 0];
	mem = BOP_ALLOC(bootops, (caddr_t)valloc_base, valloc_sz, valloc_align);
	if (mem != (caddr_t)valloc_base)
		panic("BOP_ALLOC() failed");
	bzero(mem, valloc_sz);
	for (i = 0; i < num_allocations; ++i) {
		*allocations[i].al_ptr = (void *)mem;
		mem += allocations[i].al_size;
	}
}

/*
 * Set up and enable SMAP now before we start other CPUs, but after the kernel's
 * VM has been set up so we can use hot_patch_kernel_text().
 *
 * We can only patch 1, 2, or 4 bytes, but not three bytes. So instead, we
 * replace the four byte word at the patch point. See uts/intel/ia32/ml/copy.s
 * for more information on what's going on here.
 */
static void
startup_smap(void)
{
	int i;
	uint32_t inst;
	uint8_t *instp;
	char sym[128];

	extern int _smap_enable_patch_count;
	extern int _smap_disable_patch_count;

	if (disable_smap != 0)
		remove_x86_feature(x86_featureset, X86FSET_SMAP);

	if (is_x86_feature(x86_featureset, X86FSET_SMAP) == B_FALSE)
		return;

	for (i = 0; i < _smap_enable_patch_count; i++) {
		int sizep;

		VERIFY3U(i, <, _smap_enable_patch_count);
		VERIFY(snprintf(sym, sizeof (sym), "_smap_enable_patch_%d", i) <
		    sizeof (sym));
		instp = (uint8_t *)(void *)kobj_getelfsym(sym, NULL, &sizep);
		VERIFY(instp != 0);
		inst = (instp[3] << 24) | (SMAP_CLAC_INSTR & 0x00ffffff);
		hot_patch_kernel_text((caddr_t)instp, inst, 4);
	}

	for (i = 0; i < _smap_disable_patch_count; i++) {
		int sizep;

		VERIFY(snprintf(sym, sizeof (sym), "_smap_disable_patch_%d",
		    i) < sizeof (sym));
		instp = (uint8_t *)(void *)kobj_getelfsym(sym, NULL, &sizep);
		VERIFY(instp != 0);
		inst = (instp[3] << 24) | (SMAP_STAC_INSTR & 0x00ffffff);
		hot_patch_kernel_text((caddr_t)instp, inst, 4);
	}

	hot_patch_kernel_text((caddr_t)smap_enable, SMAP_CLAC_INSTR, 4);
	hot_patch_kernel_text((caddr_t)smap_disable, SMAP_STAC_INSTR, 4);
	setcr4(getcr4() | CR4_SMAP);
	smap_enable();
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
 * unix/genunix/krtld/module data loads.
 *
 * Machine-dependent startup code
 */
void
startup(void)
{
#if !defined(__xpv)
	extern void startup_pci_bios(void);
#endif
	extern cpuset_t cpu_ready_set;

	/*
	 * Make sure that nobody tries to use sekpm until we have
	 * initialized it properly.
	 */
#if defined(__amd64)
	kpm_desired = 1;
#endif
	kpm_enable = 0;
	CPUSET_ONLY(cpu_ready_set, 0);	/* cpu 0 is boot cpu */

#if defined(__xpv)	/* XXPV fix me! */
	{
		extern int segvn_use_regions;
		segvn_use_regions = 0;
	}
#endif
	ssp_init();
	progressbar_init();
	startup_init();
#if defined(__xpv)
	startup_xen_version();
#endif
	startup_memlist();
	startup_kmem();
	startup_vm();
#if !defined(__xpv)
	/*
	 * Note we need to do this even on fast reboot in order to access
	 * the irq routing table (used for pci labels).
	 */
	startup_pci_bios();
	startup_smap();
#endif
#if defined(__xpv)
	startup_xen_mca();
#endif
	startup_modules();

	startup_end();
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
	 * First we trim from the front of the range. Since kbm_probe()
	 * walks ranges in virtual order, but addr/size are physical, we need
	 * to the list until no changes are seen.  This deals with the case
	 * where page "p" is mapped at v, page "p + PAGESIZE" is mapped at w
	 * but w < v.
	 */
	do {
		change = 0;
		for (va = KERNEL_TEXT;
		    *size > 0 && kbm_probe(&va, &len, &pfn, &prot) != 0;
		    va = next_va) {

			next_va = va + len;
			pfn_addr = pfn_to_pa(pfn);
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
	    *size > 0 && kbm_probe(&va, &len, &pfn, &prot) != 0;
	    va = next_va) {

		next_va = va + len;
		pfn_addr = pfn_to_pa(pfn);

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
}

/*
 * The debug info page provides enough information to allow external
 * inspectors (e.g. when running under a hypervisor) to bootstrap
 * themselves into allowing full-blown kernel debugging.
 */
static void
init_debug_info(void)
{
	caddr_t mem;
	debug_info_t *di;

#ifndef __lint
	ASSERT(sizeof (debug_info_t) < MMU_PAGESIZE);
#endif

	mem = BOP_ALLOC(bootops, (caddr_t)DEBUG_INFO_VA, MMU_PAGESIZE,
	    MMU_PAGESIZE);

	if (mem != (caddr_t)DEBUG_INFO_VA)
		panic("BOP_ALLOC() failed");
	bzero(mem, MMU_PAGESIZE);

	di = (debug_info_t *)mem;

	di->di_magic = DEBUG_INFO_MAGIC;
	di->di_version = DEBUG_INFO_VERSION;
	di->di_modules = (uintptr_t)&modules;
	di->di_s_text = (uintptr_t)s_text;
	di->di_e_text = (uintptr_t)e_text;
	di->di_s_data = (uintptr_t)s_data;
	di->di_e_data = (uintptr_t)e_data;
	di->di_hat_htable_off = offsetof(hat_t, hat_htable);
	di->di_ht_pfn_off = offsetof(htable_t, ht_pfn);
}

/*
 * Build the memlists and other kernel essential memory system data structures.
 * This is everything at valloc_base.
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
	pfn_t rsvd_high_pfn;
	pgcnt_t rsvd_pgcnt;
	size_t rsvdmemlist_sz;
	int rsvdmemblocks;
	caddr_t pagecolor_mem;
	size_t pagecolor_memsz;
	caddr_t page_ctrs_mem;
	size_t page_ctrs_size;
	size_t pse_table_alloc_size;
	struct memlist *current;
	extern void startup_build_mem_nodes(struct memlist *);

	/* XX64 fix these - they should be in include files */
	extern size_t page_coloring_init(uint_t, int, int);
	extern void page_coloring_setup(caddr_t);

	PRM_POINT("startup_memlist() starting...");

	/*
	 * Use leftover large page nucleus text/data space for loadable modules.
	 * Use at most MODTEXT/MODDATA.
	 */
	len = kbm_nucleus_size;
	ASSERT(len > MMU_PAGESIZE);

	moddata = (caddr_t)ROUND_UP_PAGE(e_data);
	e_moddata = (caddr_t)P2ROUNDUP((uintptr_t)e_data, (uintptr_t)len);
	if (e_moddata - moddata > MODDATA)
		e_moddata = moddata + MODDATA;

	modtext = (caddr_t)ROUND_UP_PAGE(e_text);
	e_modtext = (caddr_t)P2ROUNDUP((uintptr_t)e_text, (uintptr_t)len);
	if (e_modtext - modtext > MODTEXT)
		e_modtext = modtext + MODTEXT;

	econtig = e_moddata;

	PRM_DEBUG(modtext);
	PRM_DEBUG(e_modtext);
	PRM_DEBUG(moddata);
	PRM_DEBUG(e_moddata);
	PRM_DEBUG(econtig);

	/*
	 * Examine the boot loader physical memory map to find out:
	 * - total memory in system - physinstalled
	 * - the max physical address - physmax
	 * - the number of discontiguous segments of memory.
	 */
	if (prom_debug)
		print_memlist("boot physinstalled",
		    bootops->boot_mem->physinstalled);
	installed_top_size_ex(bootops->boot_mem->physinstalled, &physmax,
	    &physinstalled, &memblocks);
	PRM_DEBUG(physmax);
	PRM_DEBUG(physinstalled);
	PRM_DEBUG(memblocks);

	/*
	 * Compute maximum physical address for memory DR operations.
	 * Memory DR operations are unsupported on xpv or 32bit OSes.
	 */
#ifdef	__amd64
	if (plat_dr_support_memory()) {
		if (plat_dr_physmax == 0) {
			uint_t pabits = UINT_MAX;

			cpuid_get_addrsize(CPU, &pabits, NULL);
			plat_dr_physmax = btop(1ULL << pabits);
		}
		if (plat_dr_physmax > PHYSMEM_MAX64)
			plat_dr_physmax = PHYSMEM_MAX64;
	} else
#endif
		plat_dr_physmax = 0;

	/*
	 * Examine the bios reserved memory to find out:
	 * - the number of discontiguous segments of memory.
	 */
	if (prom_debug)
		print_memlist("boot reserved mem",
		    bootops->boot_mem->rsvdmem);
	installed_top_size_ex(bootops->boot_mem->rsvdmem, &rsvd_high_pfn,
	    &rsvd_pgcnt, &rsvdmemblocks);
	PRM_DEBUG(rsvd_high_pfn);
	PRM_DEBUG(rsvd_pgcnt);
	PRM_DEBUG(rsvdmemblocks);

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
	while (kbm_probe(&va, &len, &pfn, &prot) != 0) {
		npages -= len >> MMU_PAGESHIFT;
		if (va >= (uintptr_t)e_moddata)
			obp_pages += len >> MMU_PAGESHIFT;
		va += len;
	}
	PRM_DEBUG(npages);
	PRM_DEBUG(obp_pages);

	/*
	 * If physmem is patched to be non-zero, use it instead of the computed
	 * value unless it is larger than the actual amount of memory on hand.
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
	 * Reserve space for memlists. There's no real good way to know exactly
	 * how much room we'll need, but this should be a good upper bound.
	 */
	memlist_sz = ROUND_UP_PAGE(2 * sizeof (struct memlist) *
	    (memblocks + POSS_NEW_FRAGMENTS));
	ADD_TO_ALLOCATIONS(memlist, memlist_sz);
	PRM_DEBUG(memlist_sz);

	/*
	 * Reserve space for bios reserved memlists.
	 */
	rsvdmemlist_sz = ROUND_UP_PAGE(2 * sizeof (struct memlist) *
	    (rsvdmemblocks + POSS_NEW_FRAGMENTS));
	ADD_TO_ALLOCATIONS(bios_rsvd, rsvdmemlist_sz);
	PRM_DEBUG(rsvdmemlist_sz);

	/* LINTED */
	ASSERT(P2SAMEHIGHBIT((1 << PP_SHIFT), sizeof (struct page)));
	/*
	 * The page structure hash table size is a power of 2
	 * such that the average hash chain length is PAGE_HASHAVELEN.
	 */
	page_hashsz = npages / PAGE_HASHAVELEN;
	page_hashsz_shift = highbit(page_hashsz);
	page_hashsz = 1 << page_hashsz_shift;
	pagehash_sz = sizeof (struct page *) * page_hashsz;
	ADD_TO_ALLOCATIONS(page_hash, pagehash_sz);
	PRM_DEBUG(pagehash_sz);

	/*
	 * Set aside room for the page structures themselves.
	 */
	PRM_DEBUG(npages);
	pp_sz = sizeof (struct page) * npages;
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
	 * Allocate the array that protects pp->p_selock.
	 */
	pse_shift = size_pse_array(physmem, max_ncpus);
	pse_table_size = 1 << pse_shift;
	pse_table_alloc_size = pse_table_size * sizeof (pad_mutex_t);
	ADD_TO_ALLOCATIONS(pse_mutex, pse_table_alloc_size);

#if defined(__amd64)
	valloc_sz = ROUND_UP_LPAGE(valloc_sz);
	valloc_base = VALLOC_BASE;

	/*
	 * The default values of VALLOC_BASE and SEGKPM_BASE should work
	 * for values of physmax up to 256GB (1/4 TB). They need adjusting when
	 * memory is at addresses above 256GB. When adjusted, segkpm_base must
	 * be aligned on KERNEL_REDZONE_SIZE boundary (span of top level pte).
	 *
	 * In the general case (>256GB), we use (4 * physmem) for the
	 * kernel's virtual addresses, which is divided approximately
	 * as follows:
	 *  - 1 * physmem for segkpm
	 *  - 1.5 * physmem for segzio
	 *  - 1.5 * physmem for heap
	 * Total: 4.0 * physmem
	 *
	 * Note that the segzio and heap sizes are more than physmem so that
	 * VA fragmentation does not prevent either of them from being
	 * able to use nearly all of physmem.  The value of 1.5x is determined
	 * experimentally and may need to change if the workload changes.
	 */
	if (physmax + 1 > mmu_btop(TERABYTE / 4) ||
	    plat_dr_physmax > mmu_btop(TERABYTE / 4)) {
		uint64_t kpm_resv_amount = mmu_ptob(physmax + 1);

		if (kpm_resv_amount < mmu_ptob(plat_dr_physmax)) {
			kpm_resv_amount = mmu_ptob(plat_dr_physmax);
		}

		/*
		 * This is what actually controls the KVA : UVA split.
		 * The kernel uses high VA, and this is lowering the
		 * boundary, thus increasing the amount of VA for the kernel.
		 * This gives the kernel 4 * (amount of physical memory) VA.
		 *
		 * The maximum VA is UINT64_MAX and we are using
		 * 64-bit 2's complement math, so e.g. if you have 512GB
		 * of memory, segkpm_base = -(4 * 512GB) == -2TB ==
		 * UINT64_MAX - 2TB (approximately).  So the kernel's
		 * VA is [UINT64_MAX-2TB to UINT64_MAX].
		 */
		segkpm_base = -(P2ROUNDUP((4 * kpm_resv_amount),
		    KERNEL_REDZONE_SIZE));

		/* make sure we leave some space for user apps above hole */
		segkpm_base = MAX(segkpm_base, AMD64_VA_HOLE_END + TERABYTE);
		if (segkpm_base > SEGKPM_BASE)
			segkpm_base = SEGKPM_BASE;
		PRM_DEBUG(segkpm_base);

		valloc_base = segkpm_base + P2ROUNDUP(kpm_resv_amount, ONE_GIG);
		if (valloc_base < segkpm_base)
			panic("not enough kernel VA to support memory size");
		PRM_DEBUG(valloc_base);
	}
#else	/* __i386 */
	valloc_base = (uintptr_t)(MISC_VA_BASE - valloc_sz);
	valloc_base = P2ALIGN(valloc_base, mmu.level_size[1]);
	PRM_DEBUG(valloc_base);
#endif	/* __i386 */

	/*
	 * do all the initial allocations
	 */
	perform_allocations();

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
		print_memlist("phys_install", phys_install);

	phys_avail = current;
	PRM_POINT("Building phys_avail:\n");
	copy_memlist_filter(bootops->boot_mem->physinstalled, &current,
	    avail_filter);
	if ((caddr_t)current > (caddr_t)memlist + memlist_sz)
		panic("physavail was too big!");
	if (prom_debug)
		print_memlist("phys_avail", phys_avail);
#ifndef	__xpv
	/*
	 * Free unused memlist items, which may be used by memory DR driver
	 * at runtime.
	 */
	if ((caddr_t)current < (caddr_t)memlist + memlist_sz) {
		memlist_free_block((caddr_t)current,
		    (caddr_t)memlist + memlist_sz - (caddr_t)current);
	}
#endif

	/*
	 * Build bios reserved memspace
	 */
	current = bios_rsvd;
	copy_memlist_filter(bootops->boot_mem->rsvdmem, &current, NULL);
	if ((caddr_t)current > (caddr_t)bios_rsvd + rsvdmemlist_sz)
		panic("bios_rsvd was too big!");
	if (prom_debug)
		print_memlist("bios_rsvd", bios_rsvd);
#ifndef	__xpv
	/*
	 * Free unused memlist items, which may be used by memory DR driver
	 * at runtime.
	 */
	if ((caddr_t)current < (caddr_t)bios_rsvd + rsvdmemlist_sz) {
		memlist_free_block((caddr_t)current,
		    (caddr_t)bios_rsvd + rsvdmemlist_sz - (caddr_t)current);
	}
#endif

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
	 * Size the pcf array based on the number of cpus in the box at
	 * boot time.
	 */

	pcf_init();

	/*
	 * Initialize the page structures from the memory lists.
	 */
	availrmem_initial = availrmem = freemem = 0;
	PRM_POINT("Calling kphysm_init()...");
	npages = kphysm_init(pp_base, npages);
	PRM_POINT("kphysm_init() done");
	PRM_DEBUG(npages);

	init_debug_info();

	/*
	 * Now that page_t's have been initialized, remove all the
	 * initial allocation pages from the kernel free page lists.
	 */
	boot_mapin((caddr_t)valloc_base, valloc_sz);
	boot_mapin((caddr_t)MISC_VA_BASE, MISC_VA_SIZE);
	PRM_POINT("startup_memlist() done");

	PRM_DEBUG(valloc_sz);

#if defined(__amd64)
	if ((availrmem >> (30 - MMU_PAGESHIFT)) >=
	    textrepl_min_gb && l2cache_sz <= 2 << 20) {
		extern size_t textrepl_size_thresh;
		textrepl_size_thresh = (16 << 20) - 1;
	}
#endif
}

/*
 * Layout the kernel's part of address space and initialize kmem allocator.
 */
static void
startup_kmem(void)
{
	extern void page_set_colorequiv_arr(void);

	PRM_POINT("startup_kmem() starting...");

#if defined(__amd64)
	if (eprom_kernelbase && eprom_kernelbase != KERNELBASE)
		cmn_err(CE_NOTE, "!kernelbase cannot be changed on 64-bit "
		    "systems.");
	kernelbase = segkpm_base - KERNEL_REDZONE_SIZE;
	core_base = (uintptr_t)COREHEAP_BASE;
	core_size = (size_t)MISC_VA_BASE - COREHEAP_BASE;
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
	core_base = valloc_base;
	core_size = 0;
#endif	/* __i386 */

	PRM_DEBUG(core_base);
	PRM_DEBUG(core_size);
	PRM_DEBUG(kernelbase);

#if defined(__i386)
	segkp_fromheap = 1;
#endif	/* __i386 */

	ekernelheap = (char *)core_base;
	PRM_DEBUG(ekernelheap);

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

	*(uintptr_t *)&_kernelbase = kernelbase;
	*(uintptr_t *)&_userlimit = kernelbase;
#if defined(__amd64)
	*(uintptr_t *)&_userlimit -= KERNELBASE - USERLIMIT;
#else
	*(uintptr_t *)&_userlimit32 = _userlimit;
#endif
	PRM_DEBUG(_kernelbase);
	PRM_DEBUG(_userlimit);
	PRM_DEBUG(_userlimit32);

	layout_kernel_va();

#if defined(__i386)
	/*
	 * If segmap is too large we can push the bottom of the kernel heap
	 * higher than the base.  Or worse, it could exceed the top of the
	 * VA space entirely, causing it to wrap around.
	 */
	if (kernelheap >= ekernelheap || (uintptr_t)kernelheap < kernelbase)
		panic("too little address space available for kernelheap,"
		    " use eeprom for lower kernelbase or smaller segmapsize");
#endif	/* __i386 */

	/*
	 * Initialize the kernel heap. Note 3rd argument must be > 1st.
	 */
	kernelheap_init(kernelheap, ekernelheap,
	    kernelheap + MMU_PAGESIZE,
	    (void *)core_base, (void *)(core_base + core_size));

#if defined(__xpv)
	/*
	 * Link pending events struct into cpu struct
	 */
	CPU->cpu_m.mcpu_evt_pend = &cpu0_evt_data;
#endif
	/*
	 * Initialize kernel memory allocator.
	 */
	kmem_init();

	/*
	 * Factor in colorequiv to check additional 'equivalent' bins
	 */
	page_set_colorequiv_arr();

	/*
	 * print this out early so that we know what's going on
	 */
	print_x86_featureset(x86_featureset);

	/*
	 * Initialize bp_mapin().
	 */
	bp_init(MMU_PAGESIZE, HAT_STORECACHING_OK);

	/*
	 * orig_npages is non-zero if physmem has been configured for less
	 * than the available memory.
	 */
	if (orig_npages) {
		cmn_err(CE_WARN, "!%slimiting physmem to 0x%lx of 0x%lx pages",
		    (npages == PHYSMEM ? "Due to virtual address space " : ""),
		    npages, orig_npages);
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

#ifndef __xpv
	if (plat_dr_support_memory()) {
		mem_config_init();
	}
#else	/* __xpv */
	/*
	 * Some of the xen start information has to be relocated up
	 * into the kernel's permanent address space.
	 */
	PRM_POINT("calling xen_relocate_start_info()");
	xen_relocate_start_info();
	PRM_POINT("xen_relocate_start_info() done");

	/*
	 * (Update the vcpu pointer in our cpu structure to point into
	 * the relocated shared info.)
	 */
	CPU->cpu_m.mcpu_vcpu_info =
	    &HYPERVISOR_shared_info->vcpu_info[CPU->cpu_id];
#endif	/* __xpv */

	PRM_POINT("startup_kmem() done");
}

#ifndef __xpv
/*
 * If we have detected that we are running in an HVM environment, we need
 * to prepend the PV driver directory to the module search path.
 */
#define	HVM_MOD_DIR "/platform/i86hvm/kernel"
static void
update_default_path()
{
	char *current, *newpath;
	int newlen;

	/*
	 * We are about to resync with krtld.  krtld will reset its
	 * internal module search path iff Solaris has set default_path.
	 * We want to be sure we're prepending this new directory to the
	 * right search path.
	 */
	current = (default_path == NULL) ? kobj_module_path : default_path;

	newlen = strlen(HVM_MOD_DIR) + strlen(current) + 2;
	newpath = kmem_alloc(newlen, KM_SLEEP);
	(void) strcpy(newpath, HVM_MOD_DIR);
	(void) strcat(newpath, " ");
	(void) strcat(newpath, current);

	default_path = newpath;
}
#endif

static void
startup_modules(void)
{
	int cnt;
	extern void prom_setup(void);
	int32_t v, h;
	char d[11];
	char *cp;
	cmi_hdl_t hdl;

	PRM_POINT("startup_modules() starting...");

#ifndef __xpv
	/*
	 * Initialize ten-micro second timer so that drivers will
	 * not get short changed in their init phase. This was
	 * not getting called until clkinit which, on fast cpu's
	 * caused the drv_usecwait to be way too short.
	 */
	microfind();

	if ((get_hwenv() & HW_XEN_HVM) != 0)
		update_default_path();
#endif

	/*
	 * Read the GMT lag from /etc/rtc_config.
	 */
	sgmtl(process_rtc_config_file());

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
	 * Initialize the default brands
	 */
	brand_init();

	/*
	 * maxmem is the amount of physical memory we're playing with.
	 */
	maxmem = physmem;

	/*
	 * Initialize segment management stuff.
	 */
	seg_init();

	if (modload("fs", "specfs") == -1)
		halt("Can't load specfs");

	if (modload("fs", "devfs") == -1)
		halt("Can't load devfs");

	if (modload("fs", "dev") == -1)
		halt("Can't load dev");

	if (modload("fs", "procfs") == -1)
		halt("Can't load procfs");

	(void) modloadonly("sys", "lbl_edition");

	dispinit();

	/* Read cluster configuration data. */
	clconf_init();

#if defined(__xpv)
	(void) ec_init();
	gnttab_init();
	(void) xs_early_init();
#endif /* __xpv */

	/*
	 * Create a kernel device tree. First, create rootnex and
	 * then invoke bus specific code to probe devices.
	 */
	setup_ddi();

#ifdef __xpv
	if (DOMAIN_IS_INITDOMAIN(xen_info))
#endif
	{
		id_t smid;
		smbios_system_t smsys;
		smbios_info_t sminfo;
		char *mfg;
		/*
		 * Load the System Management BIOS into the global ksmbios
		 * handle, if an SMBIOS is present on this system.
		 * Also set "si-hw-provider" property, if not already set.
		 */
		ksmbios = smbios_open(NULL, SMB_VERSION, ksmbios_flags, NULL);
		if (ksmbios != NULL &&
		    ((smid = smbios_info_system(ksmbios, &smsys)) != SMB_ERR) &&
		    (smbios_info_common(ksmbios, smid, &sminfo)) != SMB_ERR) {
			mfg = (char *)sminfo.smbi_manufacturer;
			if (BOP_GETPROPLEN(bootops, "si-hw-provider") < 0) {
				extern char hw_provider[];
				int i;
				for (i = 0; i < SYS_NMLN; i++) {
					if (isprint(mfg[i]))
						hw_provider[i] = mfg[i];
					else {
						hw_provider[i] = '\0';
						break;
					}
				}
				hw_provider[SYS_NMLN - 1] = '\0';
			}
		}
	}


	/*
	 * Originally clconf_init() apparently needed the hostid.  But
	 * this no longer appears to be true - it uses its own nodeid.
	 * By placing the hostid logic here, we are able to make use of
	 * the SMBIOS UUID.
	 */
	if ((h = set_soft_hostid()) == HW_INVALID_HOSTID) {
		cmn_err(CE_WARN, "Unable to set hostid");
	} else {
		for (v = h, cnt = 0; cnt < 10; cnt++) {
			d[cnt] = (char)(v % 10);
			v /= 10;
			if (v == 0)
				break;
		}
		for (cp = hw_serial; cnt >= 0; cnt--)
			*cp++ = d[cnt] + '0';
		*cp = 0;
	}

	/*
	 * Set up the CPU module subsystem for the boot cpu in the native
	 * case, and all physical cpu resource in the xpv dom0 case.
	 * Modifies the device tree, so this must be done after
	 * setup_ddi().
	 */
#ifdef __xpv
	/*
	 * If paravirtualized and on dom0 then we initialize all physical
	 * cpu handles now;  if paravirtualized on a domU then do not
	 * initialize.
	 */
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		xen_mc_lcpu_cookie_t cpi;

		for (cpi = xen_physcpu_next(NULL); cpi != NULL;
		    cpi = xen_physcpu_next(cpi)) {
			if ((hdl = cmi_init(CMI_HDL_SOLARIS_xVM_MCA,
			    xen_physcpu_chipid(cpi), xen_physcpu_coreid(cpi),
			    xen_physcpu_strandid(cpi))) != NULL &&
			    is_x86_feature(x86_featureset, X86FSET_MCA))
				cmi_mca_init(hdl);
		}
	}
#else
	/*
	 * Initialize a handle for the boot cpu - others will initialize
	 * as they startup.  Do not do this if we know we are in an HVM domU.
	 */
	if ((get_hwenv() & HW_XEN_HVM) == 0 &&
	    (hdl = cmi_init(CMI_HDL_NATIVE, cmi_ntv_hwchipid(CPU),
	    cmi_ntv_hwcoreid(CPU), cmi_ntv_hwstrandid(CPU))) != NULL &&
	    is_x86_feature(x86_featureset, X86FSET_MCA)) {
			cmi_mca_init(hdl);
			CPU->cpu_m.mcpu_cmi_hdl = hdl;
	}
#endif	/* __xpv */

	/*
	 * Fake a prom tree such that /dev/openprom continues to work
	 */
	PRM_POINT("startup_modules: calling prom_setup...");
	prom_setup();
	PRM_POINT("startup_modules: done");

	/*
	 * Load all platform specific modules
	 */
	PRM_POINT("startup_modules: calling psm_modload...");
	psm_modload();

	PRM_POINT("startup_modules() done");
}

/*
 * claim a "setaside" boot page for use in the kernel
 */
page_t *
boot_claim_page(pfn_t pfn)
{
	page_t *pp;

	pp = page_numtopp_nolock(pfn);
	ASSERT(pp != NULL);

	if (PP_ISBOOTPAGES(pp)) {
		if (pp->p_next != NULL)
			pp->p_next->p_prev = pp->p_prev;
		if (pp->p_prev == NULL)
			bootpages = pp->p_next;
		else
			pp->p_prev->p_next = pp->p_next;
	} else {
		/*
		 * htable_attach() expects a base pagesize page
		 */
		if (pp->p_szc != 0)
			page_boot_demote(pp);
		pp = page_numtopp(pfn, SE_EXCL);
	}
	return (pp);
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

	while (kbm_probe(&va, &len, &pfn, &prot) != 0 && va < high) {
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
				pp->p_prev = NULL;
				PP_SETBOOTPAGES(pp);
				if (bootpages != NULL) {
					bootpages->p_prev = pp;
				}
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

/*
 *
 */
static void
layout_kernel_va(void)
{
	PRM_POINT("layout_kernel_va() starting...");
	/*
	 * Establish the final size of the kernel's heap, size of segmap,
	 * segkp, etc.
	 */

#if defined(__amd64)

	kpm_vbase = (caddr_t)segkpm_base;
	if (physmax + 1 < plat_dr_physmax) {
		kpm_size = ROUND_UP_LPAGE(mmu_ptob(plat_dr_physmax));
	} else {
		kpm_size = ROUND_UP_LPAGE(mmu_ptob(physmax + 1));
	}
	if ((uintptr_t)kpm_vbase + kpm_size > (uintptr_t)valloc_base)
		panic("not enough room for kpm!");
	PRM_DEBUG(kpm_size);
	PRM_DEBUG(kpm_vbase);

	/*
	 * By default we create a seg_kp in 64 bit kernels, it's a little
	 * faster to access than embedding it in the heap.
	 */
	segkp_base = (caddr_t)valloc_base + valloc_sz;
	if (!segkp_fromheap) {
		size_t sz = mmu_ptob(segkpsize);

		/*
		 * determine size of segkp
		 */
		if (sz < SEGKPMINSIZE || sz > SEGKPMAXSIZE) {
			sz = SEGKPDEFSIZE;
			cmn_err(CE_WARN, "!Illegal value for segkpsize. "
			    "segkpsize has been reset to %ld pages",
			    mmu_btop(sz));
		}
		sz = MIN(sz, MAX(SEGKPMINSIZE, mmu_ptob(physmem)));

		segkpsize = mmu_btop(ROUND_UP_LPAGE(sz));
	}
	PRM_DEBUG(segkp_base);
	PRM_DEBUG(segkpsize);

	/*
	 * segzio is used for ZFS cached data. It uses a distinct VA
	 * segment (from kernel heap) so that we can easily tell not to
	 * include it in kernel crash dumps on 64 bit kernels. The trick is
	 * to give it lots of VA, but not constrain the kernel heap.
	 * We can use 1.5x physmem for segzio, leaving approximately
	 * another 1.5x physmem for heap.  See also the comment in
	 * startup_memlist().
	 */
	segzio_base = segkp_base + mmu_ptob(segkpsize);
	if (segzio_fromheap) {
		segziosize = 0;
	} else {
		size_t physmem_size = mmu_ptob(physmem);
		size_t size = (segziosize == 0) ?
		    physmem_size * 3 / 2 : mmu_ptob(segziosize);

		if (size < SEGZIOMINSIZE)
			size = SEGZIOMINSIZE;
		segziosize = mmu_btop(ROUND_UP_LPAGE(size));
	}
	PRM_DEBUG(segziosize);
	PRM_DEBUG(segzio_base);

	/*
	 * Put the range of VA for device mappings next, kmdb knows to not
	 * grep in this range of addresses.
	 */
	toxic_addr =
	    ROUND_UP_LPAGE((uintptr_t)segzio_base + mmu_ptob(segziosize));
	PRM_DEBUG(toxic_addr);
	segmap_start = ROUND_UP_LPAGE(toxic_addr + toxic_size);
#else /* __i386 */
	segmap_start = ROUND_UP_LPAGE(kernelbase);
#endif /* __i386 */
	PRM_DEBUG(segmap_start);

	/*
	 * Users can change segmapsize through eeprom. If the variable
	 * is tuned through eeprom, there is no upper bound on the
	 * size of segmap.
	 */
	segmapsize = MAX(ROUND_UP_LPAGE(segmapsize), SEGMAPDEFAULT);

#if defined(__i386)
	/*
	 * 32-bit systems don't have segkpm or segkp, so segmap appears at
	 * the bottom of the kernel's address range.  Set aside space for a
	 * small red zone just below the start of segmap.
	 */
	segmap_start += KERNEL_REDZONE_SIZE;
	segmapsize -= KERNEL_REDZONE_SIZE;
#endif

	PRM_DEBUG(segmap_start);
	PRM_DEBUG(segmapsize);
	kernelheap = (caddr_t)ROUND_UP_LPAGE(segmap_start + segmapsize);
	PRM_DEBUG(kernelheap);
	PRM_POINT("layout_kernel_va() done...");
}

/*
 * Finish initializing the VM system, now that we are no longer
 * relying on the boot time memory allocators.
 */
static void
startup_vm(void)
{
	struct segmap_crargs a;

	extern int use_brk_lpg, use_stk_lpg;

	PRM_POINT("startup_vm() starting...");

	/*
	 * Initialize the hat layer.
	 */
	hat_init();

	/*
	 * Do final allocations of HAT data structures that need to
	 * be allocated before quiescing the boot loader.
	 */
	PRM_POINT("Calling hat_kern_alloc()...");
	hat_kern_alloc((caddr_t)segmap_start, segmapsize, ekernelheap);
	PRM_POINT("hat_kern_alloc() done");

#ifndef __xpv
	/*
	 * Setup Page Attribute Table
	 */
	pat_sync();
#endif

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
	 * loader we must remove from our free page lists any boot allocated
	 * pages that stay mapped until release_bootstrap().
	 */
	protect_boot_range(0, kernelbase, 1);


	/*
	 * Switch to running on regular HAT (not boot_mmu)
	 */
	PRM_POINT("Calling hat_kern_setup()...");
	hat_kern_setup();

	/*
	 * It is no longer safe to call BOP_ALLOC(), so make sure we don't.
	 */
	bop_no_more_mem();

	PRM_POINT("hat_kern_setup() done");

	hat_cpu_online(CPU);

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

#if defined(__xpv)
	/*
	 * Populate the I/O pool on domain 0
	 */
	if (DOMAIN_IS_INITDOMAIN(xen_info)) {
		extern long populate_io_pool(void);
		long init_io_pool_cnt;

		PRM_POINT("Populating reserve I/O page pool");
		init_io_pool_cnt = populate_io_pool();
		PRM_DEBUG(init_io_pool_cnt);
	}
#endif
	/*
	 * Mangle the brand string etc.
	 */
	cpuid_pass3(CPU);

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
	toxic_bit_map_len = btop((ulong_t)(valloc_base - kernelbase));
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
#if !defined(__amd64) && !defined(__xpv)
	if (x86_type == X86_TYPE_P5) {
		desctbr_t idtr;
		gate_desc_t *newidt;

		if ((newidt = kmem_zalloc(MMU_PAGESIZE, KM_NOSLEEP)) == NULL)
			panic("failed to install pentium_pftrap");

		bcopy(idt0, newidt, NIDT * sizeof (*idt0));
		set_gatesegd(&newidt[T_PGFLT], &pentium_pftrap,
		    KCS_SEL, SDT_SYSIGT, TRP_KPL, 0);

		(void) as_setprot(&kas, (caddr_t)newidt, MMU_PAGESIZE,
		    PROT_READ | PROT_EXEC);

		CPU->cpu_idt = newidt;
		idtr.dtr_base = (uintptr_t)CPU->cpu_idt;
		idtr.dtr_limit = (NIDT * sizeof (*idt0)) - 1;
		wr_idtr(&idtr);
	}
#endif	/* !__amd64 */

#if !defined(__xpv)
	/*
	 * Map page pfn=0 for drivers, such as kd, that need to pick up
	 * parameters left there by controllers/BIOS.
	 */
	PRM_POINT("setup up p0_va");
	p0_va = i86devmap(0, 1, PROT_READ);
	PRM_DEBUG(p0_va);
#endif

	cmn_err(CE_CONT, "?mem = %luK (0x%lx)\n",
	    physinstalled << (MMU_PAGESHIFT - 10), ptob(physinstalled));

	/*
	 * disable automatic large pages for small memory systems or
	 * when the disable flag is set.
	 *
	 * Do not yet consider page sizes larger than 2m/4m.
	 */
	if (!auto_lpg_disable && mmu.max_page_level > 0) {
		max_uheap_lpsize = LEVEL_SIZE(1);
		max_ustack_lpsize = LEVEL_SIZE(1);
		max_privmap_lpsize = LEVEL_SIZE(1);
		max_uidata_lpsize = LEVEL_SIZE(1);
		max_utext_lpsize = LEVEL_SIZE(1);
		max_shm_lpsize = LEVEL_SIZE(1);
	}
	if (physmem < privm_lpg_min_physmem || mmu.max_page_level == 0 ||
	    auto_lpg_disable) {
		use_brk_lpg = 0;
		use_stk_lpg = 0;
	}
	mcntl0_lpsize = LEVEL_SIZE(mmu.umax_page_level);

	PRM_POINT("Calling hat_init_finish()...");
	hat_init_finish();
	PRM_POINT("hat_init_finish() done");

	/*
	 * Initialize the segkp segment type.
	 */
	rw_enter(&kas.a_lock, RW_WRITER);
	PRM_POINT("Attaching segkp");
	if (segkp_fromheap) {
		segkp->s_as = &kas;
	} else if (seg_attach(&kas, (caddr_t)segkp_base, mmu_ptob(segkpsize),
	    segkp) < 0) {
		panic("startup: cannot attach segkp");
		/*NOTREACHED*/
	}
	PRM_POINT("Doing segkp_create()");
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
	if (seg_attach(&kas, (caddr_t)segmap_start, segmapsize, segmap) < 0) {
		panic("cannot attach segmap");
		/*NOTREACHED*/
	}
	PRM_DEBUG(segmap);

	a.prot = PROT_READ | PROT_WRITE;
	a.shmsize = 0;
	a.nfreelist = segmapfreelists;

	if (segmap_create(segmap, (caddr_t)&a) != 0)
		panic("segmap_create segmap");
	rw_exit(&kas.a_lock);

	setup_vaddr_for_ppcopy(CPU);

	segdev_init();
#if defined(__xpv)
	if (DOMAIN_IS_INITDOMAIN(xen_info))
#endif
		pmem_init();

	PRM_POINT("startup_vm() done");
}

/*
 * Load a tod module for the non-standard tod part found on this system.
 */
static void
load_tod_module(char *todmod)
{
	if (modload("tod", todmod) == -1)
		halt("Can't load TOD module");
}

static void
startup_end(void)
{
	int i;
	extern void setx86isalist(void);
	extern void cpu_event_init(void);

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

	/*
	 * Initialize cpu event framework.
	 */
	cpu_event_init();

#if defined(OPTERON_WORKAROUND_6323525)
	if (opteron_workaround_6323525)
		patch_workaround_6323525();
#endif
	/*
	 * If needed, load TOD module now so that ddi_get_time(9F) etc. work
	 * (For now, "needed" is defined as set tod_module_name in /etc/system)
	 */
	if (tod_module_name != NULL) {
		PRM_POINT("load_tod_module()");
		load_tod_module(tod_module_name);
	}

#if defined(__xpv)
	/*
	 * Forceload interposing TOD module for the hypervisor.
	 */
	PRM_POINT("load_tod_module()");
	load_tod_module("xpvtod");
#endif

	/*
	 * Configure the system.
	 */
	PRM_POINT("Calling configure()...");
	configure();		/* set up devices */
	PRM_POINT("configure() done");

	/*
	 * We can now setup for XSAVE because fpu_probe is done in configure().
	 */
	if (fp_save_mech == FP_XSAVE) {
		xsave_setup_msr(CPU);
	}

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
	PRM_POINT("NULLing out bootops");
	*bootopsp = (struct bootops *)NULL;
	bootops = (struct bootops *)NULL;

#if defined(__xpv)
	ec_init_debug_irq();
	xs_domu_init();
#endif

#if defined(__amd64) && !defined(__xpv)
	/*
	 * Intel IOMMU has been setup/initialized in ddi_impl.c
	 * Start it up now.
	 */
	immu_startup();
#endif

	PRM_POINT("Enabling interrupts");
	(*picinitf)();
	sti();
#if defined(__xpv)
	ASSERT(CPU->cpu_m.mcpu_vcpu_info->evtchn_upcall_mask == 0);
	xen_late_startup();
#endif

	(void) add_avsoftintr((void *)&softlevel1_hdl, 1, softlevel1,
	    "softlevel1", NULL, NULL); /* XXX to be moved later */

	/*
	 * Register software interrupt handlers for ddi_periodic_add(9F).
	 * Software interrupts up to the level 10 are supported.
	 */
	for (i = DDI_IPL_1; i <= DDI_IPL_10; i++) {
		(void) add_avsoftintr((void *)&softlevel_hdl[i-1], i,
		    (avfunc)ddi_periodic_softintr, "ddi_periodic",
		    (caddr_t)(uintptr_t)i, NULL);
	}

#if !defined(__xpv)
	if (modload("drv", "amd_iommu") < 0) {
		PRM_POINT("No AMD IOMMU present\n");
	} else if (ddi_hold_installed_driver(ddi_name_to_major(
	    "amd_iommu")) == NULL) {
		prom_printf("ERROR: failed to attach AMD IOMMU\n");
	}
#endif
	post_startup_cpu_fixups();

	PRM_POINT("startup_end() done");
}

/*
 * Don't remove the following 2 variables.  They are necessary
 * for reading the hostid from the legacy file (/kernel/misc/sysinit).
 */
char *_hs1107 = hw_serial;
ulong_t  _bdhs34;

void
post_startup(void)
{
	extern void cpupm_init(cpu_t *);
	extern void cpu_event_init_cpu(cpu_t *);

	/*
	 * Set the system wide, processor-specific flags to be passed
	 * to userland via the aux vector for performance hints and
	 * instruction set extensions.
	 */
	bind_hwcap();

#ifdef __xpv
	if (DOMAIN_IS_INITDOMAIN(xen_info))
#endif
	{
#if defined(__xpv)
		xpv_panic_init();
#else
		/*
		 * Startup the memory scrubber.
		 * XXPV	This should be running somewhere ..
		 */
		if ((get_hwenv() & HW_VIRTUAL) == 0)
			memscrub_init();
#endif
	}

	/*
	 * Complete CPU module initialization
	 */
	cmi_post_startup();

	/*
	 * Perform forceloading tasks for /etc/system.
	 */
	(void) mod_sysctl(SYS_FORCELOAD, NULL);

	/*
	 * ON4.0: Force /proc module in until clock interrupt handle fixed
	 * ON4.0: This must be fixed or restated in /etc/systems.
	 */
	(void) modload("fs", "procfs");

	(void) i_ddi_attach_hw_nodes("pit_beep");

#if defined(__i386)
	/*
	 * Check for required functional Floating Point hardware,
	 * unless FP hardware explicitly disabled.
	 */
	if (fpu_exists && (fpu_pentium_fdivbug || fp_kind == FP_NO))
		halt("No working FP hardware found");
#endif

	maxmem = freemem;

	cpu_event_init_cpu(CPU);
	cpupm_init(CPU);
	(void) mach_cpu_create_device_node(CPU, NULL);

	pg_init();
}

static int
pp_in_range(page_t *pp, uint64_t low_addr, uint64_t high_addr)
{
	return ((pp->p_pagenum >= btop(low_addr)) &&
	    (pp->p_pagenum < btopr(high_addr)));
}

static int
pp_in_module(page_t *pp, const rd_existing_t *modranges)
{
	uint_t i;

	for (i = 0; modranges[i].phys != 0; i++) {
		if (pp_in_range(pp, modranges[i].phys,
		    modranges[i].phys + modranges[i].size))
			return (1);
	}

	return (0);
}

void
release_bootstrap(void)
{
	int root_is_ramdisk;
	page_t *pp;
	extern void kobj_boot_unmountroot(void);
	extern dev_t rootdev;
	uint_t i;
	char propname[32];
	rd_existing_t *modranges;
#if !defined(__xpv)
	pfn_t	pfn;
#endif

	/*
	 * Save the bootfs module ranges so that we can reserve them below
	 * for the real bootfs.
	 */
	modranges = kmem_alloc(sizeof (rd_existing_t) * MAX_BOOT_MODULES,
	    KM_SLEEP);
	for (i = 0; ; i++) {
		uint64_t start, size;

		modranges[i].phys = 0;

		(void) snprintf(propname, sizeof (propname),
		    "module-addr-%u", i);
		if (do_bsys_getproplen(NULL, propname) <= 0)
			break;
		(void) do_bsys_getprop(NULL, propname, &start);

		(void) snprintf(propname, sizeof (propname),
		    "module-size-%u", i);
		if (do_bsys_getproplen(NULL, propname) <= 0)
			break;
		(void) do_bsys_getprop(NULL, propname, &size);

		modranges[i].phys = start;
		modranges[i].size = size;
	}

	/* unmount boot ramdisk and release kmem usage */
	kobj_boot_unmountroot();

	/*
	 * We're finished using the boot loader so free its pages.
	 */
	PRM_POINT("Unmapping lower boot pages");

	clear_boot_mappings(0, _userlimit);

	postbootkernelbase = kernelbase;

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
		extern uint64_t ramdisk_start, ramdisk_end;
		pp = bootpages;
		bootpages = pp->p_next;


		/* Keep pages for the lower 64K */
		if (pp_in_range(pp, 0, 0x40000)) {
			pp->p_next = lower_pages;
			lower_pages = pp;
			lower_pages_count++;
			continue;
		}

		if (root_is_ramdisk && pp_in_range(pp, ramdisk_start,
		    ramdisk_end) || pp_in_module(pp, modranges)) {
			pp->p_next = rd_pages;
			rd_pages = pp;
			continue;
		}
		pp->p_next = (struct page *)0;
		pp->p_prev = (struct page *)0;
		PP_CLRBOOTPAGES(pp);
		page_free(pp, 1);
	}
	PRM_POINT("Boot pages released");

	kmem_free(modranges, sizeof (rd_existing_t) * 99);

#if !defined(__xpv)
/* XXPV -- note this following bunch of code needs to be revisited in Xen 3.0 */
	/*
	 * Find 1 page below 1 MB so that other processors can boot up or
	 * so that any processor can resume.
	 * Make sure it has a kernel VA as well as a 1:1 mapping.
	 * We should have just free'd one up.
	 */

	/*
	 * 0x10 pages is 64K.  Leave the bottom 64K alone
	 * for BIOS.
	 */
	for (pfn = 0x10; pfn < btop(1*1024*1024); pfn++) {
		if (page_numtopp_alloc(pfn) == NULL)
			continue;
		rm_platter_va = i86devmap(pfn, 1,
		    PROT_READ | PROT_WRITE | PROT_EXEC);
		rm_platter_pa = ptob(pfn);
		break;
	}
	if (pfn == btop(1*1024*1024) && use_mp)
		panic("No page below 1M available for starting "
		    "other processors or for resuming from system-suspend");
#endif	/* !__xpv */
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
	page_t *pp,
	pgcnt_t npages)
{
	struct memlist	*pmem;
	struct memseg	*cur_memseg;
	pfn_t		base_pfn;
	pfn_t		end_pfn;
	pgcnt_t		num;
	pgcnt_t		pages_done = 0;
	uint64_t	addr;
	uint64_t	size;
	extern pfn_t	ddiphysmin;
	extern int	mnode_xwa;
	int		ms = 0, me = 0;

	ASSERT(page_hash != NULL && page_hashsz != 0);

	cur_memseg = memseg_base;
	for (pmem = phys_avail; pmem && npages; pmem = pmem->ml_next) {
		/*
		 * In a 32 bit kernel can't use higher memory if we're
		 * not booting in PAE mode. This check takes care of that.
		 */
		addr = pmem->ml_address;
		size = pmem->ml_size;
		if (btop(addr) > physmax)
			continue;

		/*
		 * align addr and size - they may not be at page boundaries
		 */
		if ((addr & MMU_PAGEOFFSET) != 0) {
			addr += MMU_PAGEOFFSET;
			addr &= ~(uint64_t)MMU_PAGEOFFSET;
			size -= addr - pmem->ml_address;
		}

		/* only process pages below or equal to physmax */
		if ((btop(addr + size) - 1) > physmax)
			size = ptob(physmax - btop(addr) + 1);

		num = btop(size);
		if (num == 0)
			continue;

		if (num > npages)
			num = npages;

		npages -= num;
		pages_done += num;
		base_pfn = btop(addr);

		if (prom_debug)
			prom_printf("MEMSEG addr=0x%" PRIx64
			    " pgs=0x%lx pfn 0x%lx-0x%lx\n",
			    addr, num, base_pfn, base_pfn + num);

		/*
		 * Ignore pages below ddiphysmin to simplify ddi memory
		 * allocation with non-zero addr_lo requests.
		 */
		if (base_pfn < ddiphysmin) {
			if (base_pfn + num <= ddiphysmin)
				continue;
			pp += (ddiphysmin - base_pfn);
			num -= (ddiphysmin - base_pfn);
			base_pfn = ddiphysmin;
		}

		/*
		 * mnode_xwa is greater than 1 when large pages regions can
		 * cross memory node boundaries. To prevent the formation
		 * of these large pages, configure the memsegs based on the
		 * memory node ranges which had been made non-contiguous.
		 */
		if (mnode_xwa > 1) {

			end_pfn = base_pfn + num - 1;
			ms = PFN_2_MEM_NODE(base_pfn);
			me = PFN_2_MEM_NODE(end_pfn);

			if (ms != me) {
				/*
				 * current range spans more than 1 memory node.
				 * Set num to only the pfn range in the start
				 * memory node.
				 */
				num = mem_node_config[ms].physmax - base_pfn
				    + 1;
				ASSERT(end_pfn > mem_node_config[ms].physmax);
			}
		}

		for (;;) {
			/*
			 * Build the memsegs entry
			 */
			cur_memseg->pages = pp;
			cur_memseg->epages = pp + num;
			cur_memseg->pages_base = base_pfn;
			cur_memseg->pages_end = base_pfn + num;

			/*
			 * Insert into memseg list in decreasing pfn range
			 * order. Low memory is typically more fragmented such
			 * that this ordering keeps the larger ranges at the
			 * front of the list for code that searches memseg.
			 * This ASSERTS that the memsegs coming in from boot
			 * are in increasing physical address order and not
			 * contiguous.
			 */
			if (memsegs != NULL) {
				ASSERT(cur_memseg->pages_base >=
				    memsegs->pages_end);
				cur_memseg->next = memsegs;
			}
			memsegs = cur_memseg;

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

			pp += num;
			if (ms >= me)
				break;

			/* process next memory node range */
			ms++;
			base_pfn = mem_node_config[ms].physbase;
			num = MIN(mem_node_config[ms].physmax,
			    end_pfn) - base_pfn + 1;
		}
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

	(void) seg_attach(&kas, kernelheap,
	    ekernelheap - kernelheap, &kvseg);
	(void) segkmem_create(&kvseg);

	if (core_size > 0) {
		PRM_POINT("attaching kvseg_core");
		(void) seg_attach(&kas, (caddr_t)core_base, core_size,
		    &kvseg_core);
		(void) segkmem_create(&kvseg_core);
	}

	if (segziosize > 0) {
		PRM_POINT("attaching segzio");
		(void) seg_attach(&kas, segzio_base, mmu_ptob(segziosize),
		    &kzioseg);
		(void) segkmem_zio_create(&kzioseg);

		/* create zio area covering new segment */
		segkmem_zio_init(segzio_base, mmu_ptob(segziosize));
	}

	(void) seg_attach(&kas, kdi_segdebugbase, kdi_segdebugsize, &kdebugseg);
	(void) segkmem_create(&kdebugseg);

	rw_exit(&kas.a_lock);

	/*
	 * Ensure that the red zone at kernelbase is never accessible.
	 */
	PRM_POINT("protecting redzone");
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

#ifndef __xpv
/*
 * Solaris adds an entry for Write Combining caching to the PAT
 */
static uint64_t pat_attr_reg = PAT_DEFAULT_ATTRIBUTE;

void
pat_sync(void)
{
	ulong_t	cr0, cr0_orig, cr4;

	if (!is_x86_feature(x86_featureset, X86FSET_PAT))
		return;
	cr0_orig = cr0 = getcr0();
	cr4 = getcr4();

	/* disable caching and flush all caches and TLBs */
	cr0 |= CR0_CD;
	cr0 &= ~CR0_NW;
	setcr0(cr0);
	invalidate_cache();
	if (cr4 & CR4_PGE) {
		setcr4(cr4 & ~(ulong_t)CR4_PGE);
		setcr4(cr4);
	} else {
		reload_cr3();
	}

	/* add our entry to the PAT */
	wrmsr(REG_PAT, pat_attr_reg);

	/* flush TLBs and cache again, then reenable cr0 caching */
	if (cr4 & CR4_PGE) {
		setcr4(cr4 & ~(ulong_t)CR4_PGE);
		setcr4(cr4);
	} else {
		reload_cr3();
	}
	invalidate_cache();
	setcr0(cr0_orig);
}

#endif /* !__xpv */

#if defined(_SOFT_HOSTID)
/*
 * On platforms that do not have a hardware serial number, attempt
 * to set one based on the contents of /etc/hostid.  If this file does
 * not exist, assume that we are to generate a new hostid and set
 * it in the kernel, for subsequent saving by a userland process
 * once the system is up and the root filesystem is mounted r/w.
 *
 * In order to gracefully support upgrade on OpenSolaris, if
 * /etc/hostid does not exist, we will attempt to get a serial number
 * using the legacy method (/kernel/misc/sysinit).
 *
 * If that isn't present, we attempt to use an SMBIOS UUID, which is
 * a hardware serial number.  Note that we don't automatically trust
 * all SMBIOS UUIDs (some older platforms are defective and ship duplicate
 * UUIDs in violation of the standard), we check against a blacklist.
 *
 * In an attempt to make the hostid less prone to abuse
 * (for license circumvention, etc), we store it in /etc/hostid
 * in rot47 format.
 */
extern volatile unsigned long tenmicrodata;
static int atoi(char *);

/*
 * Set this to non-zero in /etc/system if you think your SMBIOS returns a
 * UUID that is not unique. (Also report it so that the smbios_uuid_blacklist
 * array can be updated.)
 */
int smbios_broken_uuid = 0;

/*
 * List of known bad UUIDs.  This is just the lower 32-bit values, since
 * that's what we use for the host id.  If your hostid falls here, you need
 * to contact your hardware OEM for a fix for your BIOS.
 */
static unsigned char
smbios_uuid_blacklist[][16] = {

	{	/* Reported bad UUID (Google search) */
		0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05,
		0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09,
	},
	{	/* Known bad DELL UUID */
		0x4C, 0x4C, 0x45, 0x44, 0x00, 0x00, 0x20, 0x10,
		0x80, 0x20, 0x80, 0xC0, 0x4F, 0x20, 0x20, 0x20,
	},
	{	/* Uninitialized flash */
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	},
	{	/* All zeros */
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	},
};

static int32_t
uuid_to_hostid(const uint8_t *uuid)
{
	/*
	 * Although the UUIDs are 128-bits, they may not distribute entropy
	 * evenly.  We would like to use SHA or MD5, but those are located
	 * in loadable modules and not available this early in boot.  As we
	 * don't need the values to be cryptographically strong, we just
	 * generate 32-bit vaue by xor'ing the various sequences together,
	 * which ensures that the entire UUID contributes to the hostid.
	 */
	uint32_t	id = 0;

	/* first check against the blacklist */
	for (int i = 0; i < (sizeof (smbios_uuid_blacklist) / 16); i++) {
		if (bcmp(smbios_uuid_blacklist[0], uuid, 16) == 0) {
			cmn_err(CE_CONT, "?Broken SMBIOS UUID. "
			    "Contact BIOS manufacturer for repair.\n");
			return ((int32_t)HW_INVALID_HOSTID);
		}
	}

	for (int i = 0; i < 16; i++)
		id ^= ((uuid[i]) << (8 * (i % sizeof (id))));

	/* Make sure return value is positive */
	return (id & 0x7fffffff);
}

static int32_t
set_soft_hostid(void)
{
	struct _buf *file;
	char tokbuf[MAXNAMELEN];
	token_t token;
	int done = 0;
	u_longlong_t tmp;
	int i;
	int32_t hostid = (int32_t)HW_INVALID_HOSTID;
	unsigned char *c;
	hrtime_t tsc;
	smbios_system_t smsys;

	/*
	 * If /etc/hostid file not found, we'd like to get a pseudo
	 * random number to use at the hostid.  A nice way to do this
	 * is to read the real time clock.  To remain xen-compatible,
	 * we can't poke the real hardware, so we use tsc_read() to
	 * read the real time clock.  However, there is an ominous
	 * warning in tsc_read that says it can return zero, so we
	 * deal with that possibility by falling back to using the
	 * (hopefully random enough) value in tenmicrodata.
	 */

	if ((file = kobj_open_file(hostid_file)) == (struct _buf *)-1) {
		/*
		 * hostid file not found - try to load sysinit module
		 * and see if it has a nonzero hostid value...use that
		 * instead of generating a new hostid here if so.
		 */
		if ((i = modload("misc", "sysinit")) != -1) {
			if (strlen(hw_serial) > 0)
				hostid = (int32_t)atoi(hw_serial);
			(void) modunload(i);
		}

		/*
		 * We try to use the SMBIOS UUID. But not if it is blacklisted
		 * in /etc/system.
		 */
		if ((hostid == HW_INVALID_HOSTID) &&
		    (smbios_broken_uuid == 0) &&
		    (ksmbios != NULL) &&
		    (smbios_info_system(ksmbios, &smsys) != SMB_ERR) &&
		    (smsys.smbs_uuidlen >= 16)) {
			hostid = uuid_to_hostid(smsys.smbs_uuid);
		}

		/*
		 * Generate a "random" hostid using the clock.  These
		 * hostids will change on each boot if the value is not
		 * saved to a persistent /etc/hostid file.
		 */
		if (hostid == HW_INVALID_HOSTID) {
			tsc = tsc_read();
			if (tsc == 0)	/* tsc_read can return zero sometimes */
				hostid = (int32_t)tenmicrodata & 0x0CFFFFF;
			else
				hostid = (int32_t)tsc & 0x0CFFFFF;
		}
	} else {
		/* hostid file found */
		while (!done) {
			token = kobj_lex(file, tokbuf, sizeof (tokbuf));

			switch (token) {
			case POUND:
				/*
				 * skip comments
				 */
				kobj_find_eol(file);
				break;
			case STRING:
				/*
				 * un-rot47 - obviously this
				 * nonsense is ascii-specific
				 */
				for (c = (unsigned char *)tokbuf;
				    *c != '\0'; c++) {
					*c += 47;
					if (*c > '~')
						*c -= 94;
					else if (*c < '!')
						*c += 94;
				}
				/*
				 * now we should have a real number
				 */

				if (kobj_getvalue(tokbuf, &tmp) != 0)
					kobj_file_err(CE_WARN, file,
					    "Bad value %s for hostid",
					    tokbuf);
				else
					hostid = (int32_t)tmp;

				break;
			case EOF:
				done = 1;
				/* FALLTHROUGH */
			case NEWLINE:
				kobj_newline(file);
				break;
			default:
				break;

			}
		}
		if (hostid == HW_INVALID_HOSTID) /* didn't find a hostid */
			kobj_file_err(CE_WARN, file,
			    "hostid missing or corrupt");

		kobj_close_file(file);
	}
	/*
	 * hostid is now the value read from /etc/hostid, or the
	 * new hostid we generated in this routine or HW_INVALID_HOSTID if not
	 * set.
	 */
	return (hostid);
}

static int
atoi(char *p)
{
	int i = 0;

	while (*p != '\0')
		i = 10 * i + (*p++ - '0');

	return (i);
}

#endif /* _SOFT_HOSTID */

void
get_system_configuration(void)
{
	char	prop[32];
	u_longlong_t nodes_ll, cpus_pernode_ll, lvalue;

	if (BOP_GETPROPLEN(bootops, "nodes") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "nodes", prop) < 0 ||
	    kobj_getvalue(prop, &nodes_ll) == -1 ||
	    nodes_ll > MAXNODES ||
	    BOP_GETPROPLEN(bootops, "cpus_pernode") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "cpus_pernode", prop) < 0 ||
	    kobj_getvalue(prop, &cpus_pernode_ll) == -1) {
		system_hardware.hd_nodes = 1;
		system_hardware.hd_cpus_per_node = 0;
	} else {
		system_hardware.hd_nodes = (int)nodes_ll;
		system_hardware.hd_cpus_per_node = (int)cpus_pernode_ll;
	}

	if (BOP_GETPROPLEN(bootops, "kernelbase") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "kernelbase", prop) < 0 ||
	    kobj_getvalue(prop, &lvalue) == -1)
		eprom_kernelbase = NULL;
	else
		eprom_kernelbase = (uintptr_t)lvalue;

	if (BOP_GETPROPLEN(bootops, "segmapsize") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "segmapsize", prop) < 0 ||
	    kobj_getvalue(prop, &lvalue) == -1)
		segmapsize = SEGMAPDEFAULT;
	else
		segmapsize = (uintptr_t)lvalue;

	if (BOP_GETPROPLEN(bootops, "segmapfreelists") > sizeof (prop) ||
	    BOP_GETPROP(bootops, "segmapfreelists", prop) < 0 ||
	    kobj_getvalue(prop, &lvalue) == -1)
		segmapfreelists = 0;	/* use segmap driver default */
	else
		segmapfreelists = (int)lvalue;

	/* physmem used to be here, but moved much earlier to fakebop.c */
}

/*
 * Add to a memory list.
 * start = start of new memory segment
 * len = length of new memory segment in bytes
 * new = pointer to a new struct memlist
 * memlistp = memory list to which to add segment.
 */
void
memlist_add(
	uint64_t start,
	uint64_t len,
	struct memlist *new,
	struct memlist **memlistp)
{
	struct memlist *cur;
	uint64_t end = start + len;

	new->ml_address = start;
	new->ml_size = len;

	cur = *memlistp;

	while (cur) {
		if (cur->ml_address >= end) {
			new->ml_next = cur;
			*memlistp = new;
			new->ml_prev = cur->ml_prev;
			cur->ml_prev = new;
			return;
		}
		ASSERT(cur->ml_address + cur->ml_size <= start);
		if (cur->ml_next == NULL) {
			cur->ml_next = new;
			new->ml_prev = cur;
			new->ml_next = NULL;
			return;
		}
		memlistp = &cur->ml_next;
		cur = cur->ml_next;
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
		if (is_x86_feature(x86_featureset, X86FSET_CMOV)) {
			/*
			 * Pentium Pro or later
			 */
			(void) strcat(tp, "pentium_pro");
			(void) strcat(tp,
			    is_x86_feature(x86_featureset, X86FSET_MMX) ?
			    "+mmx pentium_pro " : " ");
		}
		/*FALLTHROUGH*/
	case X86_VENDOR_Cyrix:
		/*
		 * The Cyrix 6x86 does not have any Pentium features
		 * accessible while not at privilege level 0.
		 */
		if (is_x86_feature(x86_featureset, X86FSET_CPUID)) {
			(void) strcat(tp, "pentium");
			(void) strcat(tp,
			    is_x86_feature(x86_featureset, X86FSET_MMX) ?
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

#else /* __i386 */

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
	ASSERT(v + size <= valloc_base);

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
	ASSERT(v + size <= valloc_base);

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
	if (v >= valloc_base || eaddr < kernelbase)
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

#endif	/* __i386 */
