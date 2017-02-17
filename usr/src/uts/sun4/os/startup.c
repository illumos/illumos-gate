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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <sys/machsystm.h>
#include <sys/archsystm.h>
#include <sys/vm.h>
#include <sys/cpu.h>
#include <sys/atomic.h>
#include <sys/reboot.h>
#include <sys/kdi.h>
#include <sys/bootconf.h>
#include <sys/memlist_plat.h>
#include <sys/memlist_impl.h>
#include <sys/prom_plat.h>
#include <sys/prom_isa.h>
#include <sys/autoconf.h>
#include <sys/ivintr.h>
#include <sys/fpu/fpusystm.h>
#include <sys/iommutsb.h>
#include <vm/vm_dep.h>
#include <vm/seg_dev.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/seg_map.h>
#include <vm/seg_kp.h>
#include <sys/sysconf.h>
#include <vm/hat_sfmmu.h>
#include <sys/kobj.h>
#include <sys/sun4asi.h>
#include <sys/clconf.h>
#include <sys/platform_module.h>
#include <sys/panic.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/clock.h>
#include <sys/cmn_err.h>
#include <sys/dumphdr.h>
#include <sys/promif.h>
#include <sys/prom_debug.h>
#include <sys/traptrace.h>
#include <sys/memnode.h>
#include <sys/mem_cage.h>
#include <sys/mmu.h>
#include <sys/swap.h>

extern void setup_trap_table(void);
extern int cpu_intrq_setup(struct cpu *);
extern void cpu_intrq_register(struct cpu *);
extern void contig_mem_init(void);
extern caddr_t contig_mem_prealloc(caddr_t, pgcnt_t);
extern void mach_dump_buffer_init(void);
extern void mach_descrip_init(void);
extern void mach_descrip_startup_fini(void);
extern void mach_memscrub(void);
extern void mach_fpras(void);
extern void mach_cpu_halt_idle(void);
extern void mach_hw_copy_limit(void);
extern void load_mach_drivers(void);
extern void load_tod_module(void);
#pragma weak load_tod_module

extern int ndata_alloc_mmfsa(struct memlist *ndata);
#pragma weak ndata_alloc_mmfsa

extern void cif_init(void);
#pragma weak cif_init

extern void parse_idprom(void);
extern void add_vx_handler(char *, int, void (*)(cell_t *));
extern void mem_config_init(void);
extern void memseg_remap_init(void);

extern void mach_kpm_init(void);
extern void pcf_init();
extern int size_pse_array(pgcnt_t, int);
extern void pg_init();

/*
 * External Data:
 */
extern int vac_size;	/* cache size in bytes */
extern uint_t vac_mask;	/* VAC alignment consistency mask */
extern uint_t vac_colors;

/*
 * Global Data Definitions:
 */

/*
 * XXX - Don't port this to new architectures
 * A 3rd party volume manager driver (vxdm) depends on the symbol romp.
 * 'romp' has no use with a prom with an IEEE 1275 client interface.
 * The driver doesn't use the value, but it depends on the symbol.
 */
void *romp;		/* veritas driver won't load without romp 4154976 */
/*
 * Declare these as initialized data so we can patch them.
 */
pgcnt_t physmem = 0;	/* memory size in pages, patch if you want less */
pgcnt_t segkpsize =
    btop(SEGKPDEFSIZE);	/* size of segkp segment in pages */
uint_t segmap_percent = 6; /* Size of segmap segment */

int use_cache = 1;		/* cache not reliable (605 bugs) with MP */
int vac_copyback = 1;
char *cache_mode = NULL;
int use_mix = 1;
int prom_debug = 0;

caddr_t boot_tba;		/* %tba at boot - used by kmdb */
uint_t	tba_taken_over = 0;

caddr_t s_text;			/* start of kernel text segment */
caddr_t e_text;			/* end of kernel text segment */
caddr_t s_data;			/* start of kernel data segment */
caddr_t e_data;			/* end of kernel data segment */

caddr_t modtext;		/* beginning of module text */
size_t	modtext_sz;		/* size of module text */
caddr_t moddata;		/* beginning of module data reserve */
caddr_t e_moddata;		/* end of module data reserve */

/*
 * End of first block of contiguous kernel in 32-bit virtual address space
 */
caddr_t		econtig32;	/* end of first blk of contiguous kernel */

caddr_t		ncbase;		/* beginning of non-cached segment */
caddr_t		ncend;		/* end of non-cached segment */

size_t	ndata_remain_sz;	/* bytes from end of data to 4MB boundary */
caddr_t	nalloc_base;		/* beginning of nucleus allocation */
caddr_t nalloc_end;		/* end of nucleus allocatable memory */
caddr_t valloc_base;		/* beginning of kvalloc segment	*/

caddr_t kmem64_base;		/* base of kernel mem segment in 64-bit space */
caddr_t kmem64_end;		/* end of kernel mem segment in 64-bit space */
size_t	kmem64_sz;		/* bytes in kernel mem segment, 64-bit space */
caddr_t kmem64_aligned_end;	/* end of large page, overmaps 64-bit space */
int	kmem64_szc;		/* page size code */
uint64_t kmem64_pabase = (uint64_t)-1;	/* physical address of kmem64_base */

uintptr_t shm_alignment;	/* VAC address consistency modulus */
struct memlist *phys_install;	/* Total installed physical memory */
struct memlist *phys_avail;	/* Available (unreserved) physical memory */
struct memlist *virt_avail;	/* Available (unmapped?) virtual memory */
struct memlist *nopp_list;	/* pages with no backing page structs */
struct memlist ndata;		/* memlist of nucleus allocatable memory */
int memexp_flag;		/* memory expansion card flag */
uint64_t ecache_flushaddr;	/* physical address used for flushing E$ */
pgcnt_t obp_pages;		/* Physical pages used by OBP */

/*
 * VM data structures
 */
long page_hashsz;		/* Size of page hash table (power of two) */
unsigned int page_hashsz_shift;	/* log2(page_hashsz) */
struct page *pp_base;		/* Base of system page struct array */
size_t pp_sz;			/* Size in bytes of page struct array */
struct page **page_hash;	/* Page hash table */
pad_mutex_t *pse_mutex;		/* Locks protecting pp->p_selock */
size_t pse_table_size;		/* Number of mutexes in pse_mutex[] */
int pse_shift;			/* log2(pse_table_size) */
struct seg ktextseg;		/* Segment used for kernel executable image */
struct seg kvalloc;		/* Segment used for "valloc" mapping */
struct seg kpseg;		/* Segment used for pageable kernel virt mem */
struct seg ktexthole;		/* Segment used for nucleus text hole */
struct seg kmapseg;		/* Segment used for generic kernel mappings */
struct seg kpmseg;		/* Segment used for physical mapping */
struct seg kdebugseg;		/* Segment used for the kernel debugger */

void *kpm_pp_base;		/* Base of system kpm_page array */
size_t	kpm_pp_sz;		/* Size of system kpm_page array */
pgcnt_t	kpm_npages;		/* How many kpm pages are managed */

struct seg *segkp = &kpseg;	/* Pageable kernel virtual memory segment */
struct seg *segkmap = &kmapseg;	/* Kernel generic mapping segment */
struct seg *segkpm = &kpmseg;	/* 64bit kernel physical mapping segment */

int segzio_fromheap = 0;	/* zio allocations occur from heap */
caddr_t segzio_base;		/* Base address of segzio */
pgcnt_t segziosize = 0;		/* size of zio segment in pages */

/*
 * A static DR page_t VA map is reserved that can map the page structures
 * for a domain's entire RA space. The pages that backs this space are
 * dynamically allocated and need not be physically contiguous.  The DR
 * map size is derived from KPM size.
 */
int ppvm_enable = 0;		/* Static virtual map for page structs */
page_t *ppvm_base;		/* Base of page struct map */
pgcnt_t ppvm_size = 0;		/* Size of page struct map */

/*
 * debugger pages (if allocated)
 */
struct vnode kdebugvp;

/*
 * VA range available to the debugger
 */
const caddr_t kdi_segdebugbase = (const caddr_t)SEGDEBUGBASE;
const size_t kdi_segdebugsize = SEGDEBUGSIZE;

/*
 * Segment for relocated kernel structures in 64-bit large RAM kernels
 */
struct seg kmem64;

struct memseg *memseg_free;

struct vnode unused_pages_vp;

/*
 * VM data structures allocated early during boot.
 */
size_t pagehash_sz;
uint64_t memlist_sz;

char tbr_wr_addr_inited = 0;

caddr_t	mpo_heap32_buf = NULL;
size_t	mpo_heap32_bufsz = 0;

/*
 * Static Routines:
 */
static int ndata_alloc_memseg(struct memlist *, size_t);
static void memlist_new(uint64_t, uint64_t, struct memlist **);
static void memlist_add(uint64_t, uint64_t,
	struct memlist **, struct memlist **);
static void kphysm_init(void);
static void kvm_init(void);
static void install_kmem64_tte(void);

static void startup_init(void);
static void startup_memlist(void);
static void startup_modules(void);
static void startup_bop_gone(void);
static void startup_vm(void);
static void startup_end(void);
static void setup_cage_params(void);
static void startup_create_io_node(void);

static pgcnt_t npages;
static struct memlist *memlist;
void *memlist_end;

static pgcnt_t bop_alloc_pages;
static caddr_t hblk_base;
uint_t hblk_alloc_dynamic = 0;
uint_t hblk1_min = H1MIN;


/*
 * Hooks for unsupported platforms and down-rev firmware
 */
int iam_positron(void);
#pragma weak iam_positron
static void do_prom_version_check(void);

/*
 * After receiving a thermal interrupt, this is the number of seconds
 * to delay before shutting off the system, assuming
 * shutdown fails.  Use /etc/system to change the delay if this isn't
 * large enough.
 */
int thermal_powerdown_delay = 1200;

/*
 * Used to hold off page relocations into the cage until OBP has completed
 * its boot-time handoff of its resources to the kernel.
 */
int page_relocate_ready = 0;

/*
 * Indicate if kmem64 allocation was done in small chunks
 */
int kmem64_smchunks = 0;

/*
 * Enable some debugging messages concerning memory usage...
 */
#ifdef  DEBUGGING_MEM
static int debugging_mem;
static void
printmemlist(char *title, struct memlist *list)
{
	if (!debugging_mem)
		return;

	printf("%s\n", title);

	while (list) {
		prom_printf("\taddr = 0x%x %8x, size = 0x%x %8x\n",
		    (uint32_t)(list->ml_address >> 32),
		    (uint32_t)list->ml_address,
		    (uint32_t)(list->ml_size >> 32),
		    (uint32_t)(list->ml_size));
		list = list->ml_next;
	}
}

void
printmemseg(struct memseg *memseg)
{
	if (!debugging_mem)
		return;

	printf("memseg\n");

	while (memseg) {
		prom_printf("\tpage = 0x%p, epage = 0x%p, "
		    "pfn = 0x%x, epfn = 0x%x\n",
		    memseg->pages, memseg->epages,
		    memseg->pages_base, memseg->pages_end);
		memseg = memseg->next;
	}
}

#define	debug_pause(str)	halt((str))
#define	MPRINTF(str)		if (debugging_mem) prom_printf((str))
#define	MPRINTF1(str, a)	if (debugging_mem) prom_printf((str), (a))
#define	MPRINTF2(str, a, b)	if (debugging_mem) prom_printf((str), (a), (b))
#define	MPRINTF3(str, a, b, c) \
	if (debugging_mem) prom_printf((str), (a), (b), (c))
#else	/* DEBUGGING_MEM */
#define	MPRINTF(str)
#define	MPRINTF1(str, a)
#define	MPRINTF2(str, a, b)
#define	MPRINTF3(str, a, b, c)
#endif	/* DEBUGGING_MEM */


/*
 *
 *                    Kernel's Virtual Memory Layout.
 *                       /-----------------------\
 * 0xFFFFFFFF.FFFFFFFF  -|                       |-
 *                       |   OBP's virtual page  |
 *                       |        tables         |
 * 0xFFFFFFFC.00000000  -|-----------------------|-
 *                       :                       :
 *                       :                       :
 *                      -|-----------------------|-
 *                       |       segzio          | (base and size vary)
 * 0xFFFFFE00.00000000  -|-----------------------|-
 *                       |                       |  Ultrasparc I/II support
 *                       |    segkpm segment     |  up to 2TB of physical
 *                       | (64-bit kernel ONLY)  |  memory, VAC has 2 colors
 *                       |                       |
 * 0xFFFFFA00.00000000  -|-----------------------|- 2TB segkpm alignment
 *                       :                       :
 *                       :                       :
 * 0xFFFFF810.00000000  -|-----------------------|- hole_end
 *                       |                       |      ^
 *                       |  UltraSPARC I/II call |      |
 *                       | bug requires an extra |      |
 *                       | 4 GB of space between |      |
 *                       |   hole and used RAM   |	|
 *                       |                       |      |
 * 0xFFFFF800.00000000  -|-----------------------|-     |
 *                       |                       |      |
 *                       | Virtual Address Hole  |   UltraSPARC
 *                       |  on UltraSPARC I/II   |  I/II * ONLY *
 *                       |                       |      |
 * 0x00000800.00000000  -|-----------------------|-     |
 *                       |                       |      |
 *                       |  UltraSPARC I/II call |      |
 *                       | bug requires an extra |      |
 *                       | 4 GB of space between |      |
 *                       |   hole and used RAM   |      |
 *                       |                       |      v
 * 0x000007FF.00000000  -|-----------------------|- hole_start -----
 *                       :                       :		   ^
 *                       :                       :		   |
 *                       |-----------------------|                 |
 *                       |                       |                 |
 *                       |  ecache flush area    |                 |
 *                       |  (twice largest e$)   |                 |
 *                       |                       |                 |
 * 0x00000XXX.XXX00000  -|-----------------------|- kmem64_	   |
 *                       | overmapped area       |   alignend_end  |
 *                       | (kmem64_alignsize     |		   |
 *                       |  boundary)            |		   |
 * 0x00000XXX.XXXXXXXX  -|-----------------------|- kmem64_end	   |
 *                       |                       |		   |
 *                       |   64-bit kernel ONLY  |		   |
 *                       |                       |		   |
 *                       |    kmem64 segment     |		   |
 *                       |                       |		   |
 *                       | (Relocated extra HME  |	     Approximately
 *                       |   block allocations,  |	    1 TB of virtual
 *                       |   memnode freelists,  |	     address space
 *                       |    HME hash buckets,  |		   |
 *                       | mml_table, kpmp_table,|		   |
 *                       |  page_t array and     |		   |
 *                       |  hashblock pool to    |		   |
 *                       |   avoid hard-coded    |		   |
 *                       |     32-bit vaddr      |		   |
 *                       |     limitations)      |		   |
 *                       |                       |		   v
 * 0x00000700.00000000  -|-----------------------|- SYSLIMIT (kmem64_base)
 *                       |                       |
 *                       |  segkmem segment      | (SYSLIMIT - SYSBASE = 4TB)
 *                       |                       |
 * 0x00000300.00000000  -|-----------------------|- SYSBASE
 *                       :                       :
 *                       :                       :
 *                      -|-----------------------|-
 *                       |                       |
 *                       |  segmap segment       |   SEGMAPSIZE (1/8th physmem,
 *                       |                       |               256G MAX)
 * 0x000002a7.50000000  -|-----------------------|- SEGMAPBASE
 *                       :                       :
 *                       :                       :
 *                      -|-----------------------|-
 *                       |                       |
 *                       |       segkp           |    SEGKPSIZE (2GB)
 *                       |                       |
 *                       |                       |
 * 0x000002a1.00000000  -|-----------------------|- SEGKPBASE
 *                       |                       |
 * 0x000002a0.00000000  -|-----------------------|- MEMSCRUBBASE
 *                       |                       |       (SEGKPBASE - 0x400000)
 * 0x0000029F.FFE00000  -|-----------------------|- ARGSBASE
 *                       |                       |       (MEMSCRUBBASE - NCARGS)
 * 0x0000029F.FFD80000  -|-----------------------|- PPMAPBASE
 *                       |                       |       (ARGSBASE - PPMAPSIZE)
 * 0x0000029F.FFD00000  -|-----------------------|- PPMAP_FAST_BASE
 *                       |                       |
 * 0x0000029F.FF980000  -|-----------------------|- PIOMAPBASE
 *                       |                       |
 * 0x0000029F.FF580000  -|-----------------------|- NARG_BASE
 *                       :                       :
 *                       :                       :
 * 0x00000000.FFFFFFFF  -|-----------------------|- OFW_END_ADDR
 *                       |                       |
 *                       |         OBP           |
 *                       |                       |
 * 0x00000000.F0000000  -|-----------------------|- OFW_START_ADDR
 *                       |         kmdb          |
 * 0x00000000.EDD00000  -|-----------------------|- SEGDEBUGBASE
 *                       :                       :
 *                       :                       :
 * 0x00000000.7c000000  -|-----------------------|- SYSLIMIT32
 *                       |                       |
 *                       |  segkmem32 segment    | (SYSLIMIT32 - SYSBASE32 =
 *                       |                       |    ~64MB)
 *			-|-----------------------|
 *			 |	IVSIZE		 |
 * 0x00000000.70004000  -|-----------------------|
 *                       |     panicbuf          |
 * 0x00000000.70002000	-|-----------------------|
 *			 |	PAGESIZE	 |
 * 0x00000000.70000000  -|-----------------------|- SYSBASE32
 *                       |       boot-time       |
 *                       |    temporary space    |
 * 0x00000000.4C000000  -|-----------------------|- BOOTTMPBASE
 *                       :                       :
 *                       :                       :
 *                       |                       |
 *                       |-----------------------|- econtig32
 *                       |    vm structures      |
 * 0x00000000.01C00000   |-----------------------|- nalloc_end
 *                       |         TSBs          |
 *                       |-----------------------|- end/nalloc_base
 *                       |   kernel data & bss   |
 * 0x00000000.01800000  -|-----------------------|
 *                       :   nucleus text hole   :
 * 0x00000000.01400000  -|-----------------------|
 *                       :                       :
 *                       |-----------------------|
 *                       |      module text      |
 *                       |-----------------------|- e_text/modtext
 *                       |      kernel text      |
 *                       |-----------------------|
 *                       |    trap table (48k)   |
 * 0x00000000.01000000  -|-----------------------|- KERNELBASE
 *                       | reserved for trapstat |} TSTAT_TOTAL_SIZE
 *                       |-----------------------|
 *                       |                       |
 *                       |        invalid        |
 *                       |                       |
 * 0x00000000.00000000  _|_______________________|
 *
 *
 *
 *                   32-bit User Virtual Memory Layout.
 *                       /-----------------------\
 *                       |                       |
 *                       |        invalid        |
 *                       |                       |
 *          0xFFC00000  -|-----------------------|- USERLIMIT
 *                       |       user stack      |
 *                       :                       :
 *                       :                       :
 *                       :                       :
 *                       |       user data       |
 *                      -|-----------------------|-
 *                       |       user text       |
 *          0x00002000  -|-----------------------|-
 *                       |       invalid         |
 *          0x00000000  _|_______________________|
 *
 *
 *
 *                   64-bit User Virtual Memory Layout.
 *                       /-----------------------\
 *                       |                       |
 *                       |        invalid        |
 *                       |                       |
 *  0xFFFFFFFF.80000000 -|-----------------------|- USERLIMIT
 *                       |       user stack      |
 *                       :                       :
 *                       :                       :
 *                       :                       :
 *                       |       user data       |
 *                      -|-----------------------|-
 *                       |       user text       |
 *  0x00000000.01000000 -|-----------------------|-
 *                       |       invalid         |
 *  0x00000000.00000000 _|_______________________|
 */

extern caddr_t ecache_init_scrub_flush_area(caddr_t alloc_base);
extern uint64_t ecache_flush_address(void);

#pragma weak load_platform_modules
#pragma weak plat_startup_memlist
#pragma weak ecache_init_scrub_flush_area
#pragma weak ecache_flush_address


/*
 * By default the DR Cage is enabled for maximum OS
 * MPSS performance.  Users needing to disable the cage mechanism
 * can set this variable to zero via /etc/system.
 * Disabling the cage on systems supporting Dynamic Reconfiguration (DR)
 * will result in loss of DR functionality.
 * Platforms wishing to disable kernel Cage by default
 * should do so in their set_platform_defaults() routine.
 */
int	kernel_cage_enable = 1;

static void
setup_cage_params(void)
{
	void (*func)(void);

	func = (void (*)(void))kobj_getsymvalue("set_platform_cage_params", 0);
	if (func != NULL) {
		(*func)();
		return;
	}

	if (kernel_cage_enable == 0) {
		return;
	}
	kcage_range_init(phys_avail, KCAGE_DOWN, total_pages / 256);

	if (kcage_on) {
		cmn_err(CE_NOTE, "!Kernel Cage is ENABLED");
	} else {
		cmn_err(CE_NOTE, "!Kernel Cage is DISABLED");
	}

}

/*
 * Machine-dependent startup code
 */
void
startup(void)
{
	startup_init();
	if (&startup_platform)
		startup_platform();
	startup_memlist();
	startup_modules();
	setup_cage_params();
	startup_bop_gone();
	startup_vm();
	startup_end();
}

struct regs sync_reg_buf;
uint64_t sync_tt;

void
sync_handler(void)
{
	struct  panic_trap_info 	ti;
	int i;

	/*
	 * Prevent trying to talk to the other CPUs since they are
	 * sitting in the prom and won't reply.
	 */
	for (i = 0; i < NCPU; i++) {
		if ((i != CPU->cpu_id) && CPU_XCALL_READY(i)) {
			cpu[i]->cpu_flags &= ~CPU_READY;
			cpu[i]->cpu_flags |= CPU_QUIESCED;
			CPUSET_DEL(cpu_ready_set, cpu[i]->cpu_id);
		}
	}

	/*
	 * Force a serial dump, since there are no CPUs to help.
	 */
	dump_plat_mincpu = 0;

	/*
	 * We've managed to get here without going through the
	 * normal panic code path. Try and save some useful
	 * information.
	 */
	if (!panicstr && (curthread->t_panic_trap == NULL)) {
		ti.trap_type = sync_tt;
		ti.trap_regs = &sync_reg_buf;
		ti.trap_addr = NULL;
		ti.trap_mmu_fsr = 0x0;

		curthread->t_panic_trap = &ti;
	}

	/*
	 * If we're re-entering the panic path, update the signature
	 * block so that the SC knows we're in the second part of panic.
	 */
	if (panicstr)
		CPU_SIGNATURE(OS_SIG, SIGST_EXIT, SIGSUBST_DUMP, -1);

	nopanicdebug = 1; /* do not perform debug_enter() prior to dump */
	panic("sync initiated");
}


static void
startup_init(void)
{
	/*
	 * We want to save the registers while we're still in OBP
	 * so that we know they haven't been fiddled with since.
	 * (In principle, OBP can't change them just because it
	 * makes a callback, but we'd rather not depend on that
	 * behavior.)
	 */
	char		sync_str[] =
	    "warning @ warning off : sync "
	    "%%tl-c %%tstate h# %p x! "
	    "%%g1 h# %p x! %%g2 h# %p x! %%g3 h# %p x! "
	    "%%g4 h# %p x! %%g5 h# %p x! %%g6 h# %p x! "
	    "%%g7 h# %p x! %%o0 h# %p x! %%o1 h# %p x! "
	    "%%o2 h# %p x! %%o3 h# %p x! %%o4 h# %p x! "
	    "%%o5 h# %p x! %%o6 h# %p x! %%o7 h# %p x! "
	    "%%tl-c %%tpc h# %p x! %%tl-c %%tnpc h# %p x! "
	    "%%y h# %p l! %%tl-c %%tt h# %p x! "
	    "sync ; warning !";

	/*
	 * 20 == num of %p substrings
	 * 16 == max num of chars %p will expand to.
	 */
	char 		bp[sizeof (sync_str) + 16 * 20];

	/*
	 * Initialize ptl1 stack for the 1st CPU.
	 */
	ptl1_init_cpu(&cpu0);

	/*
	 * Initialize the address map for cache consistent mappings
	 * to random pages; must be done after vac_size is set.
	 */
	ppmapinit();

	/*
	 * Initialize the PROM callback handler.
	 */
	init_vx_handler();

	/*
	 * have prom call sync_callback() to handle the sync and
	 * save some useful information which will be stored in the
	 * core file later.
	 */
	(void) sprintf((char *)bp, sync_str,
	    (void *)&sync_reg_buf.r_tstate, (void *)&sync_reg_buf.r_g1,
	    (void *)&sync_reg_buf.r_g2, (void *)&sync_reg_buf.r_g3,
	    (void *)&sync_reg_buf.r_g4, (void *)&sync_reg_buf.r_g5,
	    (void *)&sync_reg_buf.r_g6, (void *)&sync_reg_buf.r_g7,
	    (void *)&sync_reg_buf.r_o0, (void *)&sync_reg_buf.r_o1,
	    (void *)&sync_reg_buf.r_o2, (void *)&sync_reg_buf.r_o3,
	    (void *)&sync_reg_buf.r_o4, (void *)&sync_reg_buf.r_o5,
	    (void *)&sync_reg_buf.r_o6, (void *)&sync_reg_buf.r_o7,
	    (void *)&sync_reg_buf.r_pc, (void *)&sync_reg_buf.r_npc,
	    (void *)&sync_reg_buf.r_y, (void *)&sync_tt);
	prom_interpret(bp, 0, 0, 0, 0, 0);
	add_vx_handler("sync", 1, (void (*)(cell_t *))sync_handler);
}


size_t
calc_pp_sz(pgcnt_t npages)
{

	return (npages * sizeof (struct page));
}

size_t
calc_kpmpp_sz(pgcnt_t npages)
{

	kpm_pgshft = (kpm_smallpages == 0) ? MMU_PAGESHIFT4M : MMU_PAGESHIFT;
	kpm_pgsz = 1ull << kpm_pgshft;
	kpm_pgoff = kpm_pgsz - 1;
	kpmp2pshft = kpm_pgshft - PAGESHIFT;
	kpmpnpgs = 1 << kpmp2pshft;

	if (kpm_smallpages == 0) {
		/*
		 * Avoid fragmentation problems in kphysm_init()
		 * by allocating for all of physical memory
		 */
		kpm_npages = ptokpmpr(physinstalled);
		return (kpm_npages * sizeof (kpm_page_t));
	} else {
		kpm_npages = npages;
		return (kpm_npages * sizeof (kpm_spage_t));
	}
}

size_t
calc_pagehash_sz(pgcnt_t npages)
{
	/* LINTED */
	ASSERT(P2SAMEHIGHBIT((1 << PP_SHIFT), (sizeof (struct page))));
	/*
	 * The page structure hash table size is a power of 2
	 * such that the average hash chain length is PAGE_HASHAVELEN.
	 */
	page_hashsz = npages / PAGE_HASHAVELEN;
	page_hashsz_shift = MAX((AN_VPSHIFT + VNODE_ALIGN_LOG2 + 1),
	    highbit(page_hashsz));
	page_hashsz = 1 << page_hashsz_shift;
	return (page_hashsz * sizeof (struct page *));
}

int testkmem64_smchunks = 0;

int
alloc_kmem64(caddr_t base, caddr_t end)
{
	int i;
	caddr_t aligned_end = NULL;

	if (testkmem64_smchunks)
		return (1);

	/*
	 * Make one large memory alloc after figuring out the 64-bit size. This
	 * will enable use of the largest page size appropriate for the system
	 * architecture.
	 */
	ASSERT(mmu_exported_pagesize_mask & (1 << TTE8K));
	ASSERT(IS_P2ALIGNED(base, TTEBYTES(max_bootlp_tteszc)));
	for (i = max_bootlp_tteszc; i >= TTE8K; i--) {
		size_t alloc_size, alignsize;
#if !defined(C_OBP)
		unsigned long long pa;
#endif	/* !C_OBP */

		if ((mmu_exported_pagesize_mask & (1 << i)) == 0)
			continue;
		alignsize = TTEBYTES(i);
		kmem64_szc = i;

		/* limit page size for small memory */
		if (mmu_btop(alignsize) > (npages >> 2))
			continue;

		aligned_end = (caddr_t)roundup((uintptr_t)end, alignsize);
		alloc_size = aligned_end - base;
#if !defined(C_OBP)
		if (prom_allocate_phys(alloc_size, alignsize, &pa) == 0) {
			if (prom_claim_virt(alloc_size, base) != (caddr_t)-1) {
				kmem64_pabase = pa;
				kmem64_aligned_end = aligned_end;
				install_kmem64_tte();
				break;
			} else {
				prom_free_phys(alloc_size, pa);
			}
		}
#else	/* !C_OBP */
		if (prom_alloc(base, alloc_size, alignsize) == base) {
			kmem64_pabase = va_to_pa(kmem64_base);
			kmem64_aligned_end = aligned_end;
			break;
		}
#endif	/* !C_OBP */
		if (i == TTE8K) {
#ifdef sun4v
			/* return failure to try small allocations */
			return (1);
#else
			prom_panic("kmem64 allocation failure");
#endif
		}
	}
	ASSERT(aligned_end != NULL);
	return (0);
}

static prom_memlist_t *boot_physinstalled, *boot_physavail, *boot_virtavail;
static size_t boot_physinstalled_len, boot_physavail_len, boot_virtavail_len;

#if !defined(C_OBP)
/*
 * Install a temporary tte handler in OBP for kmem64 area.
 *
 * We map kmem64 area with large pages before the trap table is taken
 * over. Since OBP makes 8K mappings, it can create 8K tlb entries in
 * the same area. Duplicate tlb entries with different page sizes
 * cause unpredicatble behavior.  To avoid this, we don't create
 * kmem64 mappings via BOP_ALLOC (ends up as prom_alloc() call to
 * OBP).  Instead, we manage translations with a temporary va>tte-data
 * handler (kmem64-tte).  This handler is replaced by unix-tte when
 * the trap table is taken over.
 *
 * The temporary handler knows the physical address of the kmem64
 * area. It uses the prom's pgmap@ Forth word for other addresses.
 *
 * We have to use BOP_ALLOC() method for C-OBP platforms because
 * pgmap@ is not defined in C-OBP. C-OBP is only used on serengeti
 * sun4u platforms. On sun4u we flush tlb after trap table is taken
 * over if we use large pages for kernel heap and kmem64. Since sun4u
 * prom (unlike sun4v) calls va>tte-data first for client address
 * translation prom's ttes for kmem64 can't get into TLB even if we
 * later switch to prom's trap table again. C-OBP uses 4M pages for
 * client mappings when possible so on all platforms we get the
 * benefit from large mappings for kmem64 area immediately during
 * boot.
 *
 * pseudo code:
 * if (context != 0) {
 * 	return false
 * } else if (miss_va in range[kmem64_base, kmem64_end)) {
 *	tte = tte_template +
 *		(((miss_va & pagemask) - kmem64_base));
 *	return tte, true
 * } else {
 *	return pgmap@ result
 * }
 */
char kmem64_obp_str[] =
	"h# %lx constant kmem64-base "
	"h# %lx constant kmem64-end "
	"h# %lx constant kmem64-pagemask "
	"h# %lx constant kmem64-template "

	": kmem64-tte ( addr cnum -- false | tte-data true ) "
	"    if                                       ( addr ) "
	"       drop false exit then                  ( false ) "
	"    dup  kmem64-base kmem64-end  within  if  ( addr ) "
	"	kmem64-pagemask and                   ( addr' ) "
	"	kmem64-base -                         ( addr' ) "
	"	kmem64-template +                     ( tte ) "
	"	true                                  ( tte true ) "
	"    else                                     ( addr ) "
	"	pgmap@                                ( tte ) "
	"       dup 0< if true else drop false then   ( tte true  |  false ) "
	"    then                                     ( tte true  |  false ) "
	"; "

	"' kmem64-tte is va>tte-data "
;

static void
install_kmem64_tte()
{
	char b[sizeof (kmem64_obp_str) + (4 * 16)];
	tte_t tte;

	PRM_DEBUG(kmem64_pabase);
	PRM_DEBUG(kmem64_szc);
	sfmmu_memtte(&tte, kmem64_pabase >> MMU_PAGESHIFT,
	    PROC_DATA | HAT_NOSYNC, kmem64_szc);
	PRM_DEBUG(tte.ll);
	(void) sprintf(b, kmem64_obp_str,
	    kmem64_base, kmem64_end, TTE_PAGEMASK(kmem64_szc), tte.ll);
	ASSERT(strlen(b) < sizeof (b));
	prom_interpret(b, 0, 0, 0, 0, 0);
}
#endif	/* !C_OBP */

/*
 * As OBP takes up some RAM when the system boots, pages will already be "lost"
 * to the system and reflected in npages by the time we see it.
 *
 * We only want to allocate kernel structures in the 64-bit virtual address
 * space on systems with enough RAM to make the overhead of keeping track of
 * an extra kernel memory segment worthwhile.
 *
 * Since OBP has already performed its memory allocations by this point, if we
 * have more than MINMOVE_RAM_MB MB of RAM left free, go ahead and map
 * memory in the 64-bit virtual address space; otherwise keep allocations
 * contiguous with we've mapped so far in the 32-bit virtual address space.
 */
#define	MINMOVE_RAM_MB	((size_t)1900)
#define	MB_TO_BYTES(mb)	((mb) * 1048576ul)
#define	BYTES_TO_MB(b) ((b) / 1048576ul)

pgcnt_t	tune_npages = (pgcnt_t)
	(MB_TO_BYTES(MINMOVE_RAM_MB)/ (size_t)MMU_PAGESIZE);

#pragma weak page_set_colorequiv_arr_cpu
extern void page_set_colorequiv_arr_cpu(void);
extern void page_set_colorequiv_arr(void);

static pgcnt_t ramdisk_npages;
static struct memlist *old_phys_avail;

kcage_dir_t kcage_startup_dir = KCAGE_DOWN;

static void
startup_memlist(void)
{
	size_t hmehash_sz, pagelist_sz, tt_sz;
	size_t psetable_sz;
	caddr_t alloc_base;
	caddr_t memspace;
	struct memlist *cur;
	size_t syslimit = (size_t)SYSLIMIT;
	size_t sysbase = (size_t)SYSBASE;

	/*
	 * Initialize enough of the system to allow kmem_alloc to work by
	 * calling boot to allocate its memory until the time that
	 * kvm_init is completed.  The page structs are allocated after
	 * rounding up end to the nearest page boundary; the memsegs are
	 * initialized and the space they use comes from the kernel heap.
	 * With appropriate initialization, they can be reallocated later
	 * to a size appropriate for the machine's configuration.
	 *
	 * At this point, memory is allocated for things that will never
	 * need to be freed, this used to be "valloced".  This allows a
	 * savings as the pages don't need page structures to describe
	 * them because them will not be managed by the vm system.
	 */

	/*
	 * We're loaded by boot with the following configuration (as
	 * specified in the sun4u/conf/Mapfile):
	 *
	 * 	text:		4 MB chunk aligned on a 4MB boundary
	 * 	data & bss:	4 MB chunk aligned on a 4MB boundary
	 *
	 * These two chunks will eventually be mapped by 2 locked 4MB
	 * ttes and will represent the nucleus of the kernel.  This gives
	 * us some free space that is already allocated, some or all of
	 * which is made available to kernel module text.
	 *
	 * The free space in the data-bss chunk is used for nucleus
	 * allocatable data structures and we reserve it using the
	 * nalloc_base and nalloc_end variables.  This space is currently
	 * being used for hat data structures required for tlb miss
	 * handling operations.  We align nalloc_base to a l2 cache
	 * linesize because this is the line size the hardware uses to
	 * maintain cache coherency.
	 * 512K is carved out for module data.
	 */

	moddata = (caddr_t)roundup((uintptr_t)e_data, MMU_PAGESIZE);
	e_moddata = moddata + MODDATA;
	nalloc_base = e_moddata;

	nalloc_end = (caddr_t)roundup((uintptr_t)nalloc_base, MMU_PAGESIZE4M);
	valloc_base = nalloc_base;

	/*
	 * Calculate the start of the data segment.
	 */
	if (((uintptr_t)e_moddata & MMU_PAGEMASK4M) != (uintptr_t)s_data)
		prom_panic("nucleus data overflow");

	PRM_DEBUG(moddata);
	PRM_DEBUG(nalloc_base);
	PRM_DEBUG(nalloc_end);

	/*
	 * Remember any slop after e_text so we can give it to the modules.
	 */
	PRM_DEBUG(e_text);
	modtext = (caddr_t)roundup((uintptr_t)e_text, MMU_PAGESIZE);
	if (((uintptr_t)e_text & MMU_PAGEMASK4M) != (uintptr_t)s_text)
		prom_panic("nucleus text overflow");
	modtext_sz = (caddr_t)roundup((uintptr_t)modtext, MMU_PAGESIZE4M) -
	    modtext;
	PRM_DEBUG(modtext);
	PRM_DEBUG(modtext_sz);

	init_boot_memlists();
	copy_boot_memlists(&boot_physinstalled, &boot_physinstalled_len,
	    &boot_physavail, &boot_physavail_len,
	    &boot_virtavail, &boot_virtavail_len);

	/*
	 * Remember what the physically available highest page is
	 * so that dumpsys works properly, and find out how much
	 * memory is installed.
	 */
	installed_top_size_memlist_array(boot_physinstalled,
	    boot_physinstalled_len, &physmax, &physinstalled);
	PRM_DEBUG(physinstalled);
	PRM_DEBUG(physmax);

	/* Fill out memory nodes config structure */
	startup_build_mem_nodes(boot_physinstalled, boot_physinstalled_len);

	/*
	 * npages is the maximum of available physical memory possible.
	 * (ie. it will never be more than this)
	 *
	 * When we boot from a ramdisk, the ramdisk memory isn't free, so
	 * using phys_avail will underestimate what will end up being freed.
	 * A better initial guess is just total memory minus the kernel text
	 */
	npages = physinstalled - btop(MMU_PAGESIZE4M);

	/*
	 * First allocate things that can go in the nucleus data page
	 * (fault status, TSBs, dmv, CPUs)
	 */
	ndata_alloc_init(&ndata, (uintptr_t)nalloc_base, (uintptr_t)nalloc_end);

	if ((&ndata_alloc_mmfsa != NULL) && (ndata_alloc_mmfsa(&ndata) != 0))
		cmn_err(CE_PANIC, "no more nucleus memory after mfsa alloc");

	if (ndata_alloc_tsbs(&ndata, npages) != 0)
		cmn_err(CE_PANIC, "no more nucleus memory after tsbs alloc");

	if (ndata_alloc_dmv(&ndata) != 0)
		cmn_err(CE_PANIC, "no more nucleus memory after dmv alloc");

	if (ndata_alloc_page_mutexs(&ndata) != 0)
		cmn_err(CE_PANIC,
		    "no more nucleus memory after page free lists alloc");

	if (ndata_alloc_hat(&ndata) != 0)
		cmn_err(CE_PANIC, "no more nucleus memory after hat alloc");

	if (ndata_alloc_memseg(&ndata, boot_physavail_len) != 0)
		cmn_err(CE_PANIC, "no more nucleus memory after memseg alloc");

	/*
	 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING
	 *
	 * There are comments all over the SFMMU code warning of dire
	 * consequences if the TSBs are moved out of 32-bit space.  This
	 * is largely because the asm code uses "sethi %hi(addr)"-type
	 * instructions which will not provide the expected result if the
	 * address is a 64-bit one.
	 *
	 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING
	 */
	alloc_base = (caddr_t)roundup((uintptr_t)nalloc_end, MMU_PAGESIZE);
	PRM_DEBUG(alloc_base);

	alloc_base = sfmmu_ktsb_alloc(alloc_base);
	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base, ecache_alignsize);
	PRM_DEBUG(alloc_base);

	/*
	 * Allocate IOMMU TSB array.  We do this here so that the physical
	 * memory gets deducted from the PROM's physical memory list.
	 */
	alloc_base = iommu_tsb_init(alloc_base);
	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base, ecache_alignsize);
	PRM_DEBUG(alloc_base);

	/*
	 * Allow for an early allocation of physically contiguous memory.
	 */
	alloc_base = contig_mem_prealloc(alloc_base, npages);

	/*
	 * Platforms like Starcat and OPL need special structures assigned in
	 * 32-bit virtual address space because their probing routines execute
	 * FCode, and FCode can't handle 64-bit virtual addresses...
	 */
	if (&plat_startup_memlist) {
		alloc_base = plat_startup_memlist(alloc_base);
		alloc_base = (caddr_t)roundup((uintptr_t)alloc_base,
		    ecache_alignsize);
		PRM_DEBUG(alloc_base);
	}

	/*
	 * Save off where the contiguous allocations to date have ended
	 * in econtig32.
	 */
	econtig32 = alloc_base;
	PRM_DEBUG(econtig32);
	if (econtig32 > (caddr_t)KERNEL_LIMIT32)
		cmn_err(CE_PANIC, "econtig32 too big");

	pp_sz = calc_pp_sz(npages);
	PRM_DEBUG(pp_sz);
	if (kpm_enable) {
		kpm_pp_sz = calc_kpmpp_sz(npages);
		PRM_DEBUG(kpm_pp_sz);
	}

	hmehash_sz = calc_hmehash_sz(npages);
	PRM_DEBUG(hmehash_sz);

	pagehash_sz = calc_pagehash_sz(npages);
	PRM_DEBUG(pagehash_sz);

	pagelist_sz = calc_free_pagelist_sz();
	PRM_DEBUG(pagelist_sz);

#ifdef	TRAPTRACE
	tt_sz = calc_traptrace_sz();
	PRM_DEBUG(tt_sz);
#else
	tt_sz = 0;
#endif	/* TRAPTRACE */

	/*
	 * Place the array that protects pp->p_selock in the kmem64 wad.
	 */
	pse_shift = size_pse_array(npages, max_ncpus);
	PRM_DEBUG(pse_shift);
	pse_table_size = 1 << pse_shift;
	PRM_DEBUG(pse_table_size);
	psetable_sz = roundup(
	    pse_table_size * sizeof (pad_mutex_t), ecache_alignsize);
	PRM_DEBUG(psetable_sz);

	/*
	 * Now allocate the whole wad
	 */
	kmem64_sz = pp_sz + kpm_pp_sz + hmehash_sz + pagehash_sz +
	    pagelist_sz + tt_sz + psetable_sz;
	kmem64_sz = roundup(kmem64_sz, PAGESIZE);
	kmem64_base = (caddr_t)syslimit;
	kmem64_end = kmem64_base + kmem64_sz;
	if (alloc_kmem64(kmem64_base, kmem64_end)) {
		/*
		 * Attempt for kmem64 to allocate one big
		 * contiguous chunk of memory failed.
		 * We get here because we are sun4v.
		 * We will proceed by breaking up
		 * the allocation into two attempts.
		 * First, we allocate kpm_pp_sz, hmehash_sz,
		 * pagehash_sz, pagelist_sz, tt_sz & psetable_sz as
		 * one contiguous chunk. This is a much smaller
		 * chunk and we should get it, if not we panic.
		 * Note that hmehash and tt need to be physically
		 * (in the real address sense) contiguous.
		 * Next, we use bop_alloc_chunk() to
		 * to allocate the page_t structures.
		 * This will allow the page_t to be allocated
		 * in multiple smaller chunks.
		 * In doing so, the assumption that page_t is
		 * physically contiguous no longer hold, this is ok
		 * for sun4v but not for sun4u.
		 */
		size_t  tmp_size;
		caddr_t tmp_base;

		pp_sz  = roundup(pp_sz, PAGESIZE);

		/*
		 * Allocate kpm_pp_sz, hmehash_sz,
		 * pagehash_sz, pagelist_sz, tt_sz & psetable_sz
		 */
		tmp_base = kmem64_base + pp_sz;
		tmp_size = roundup(kpm_pp_sz + hmehash_sz + pagehash_sz +
		    pagelist_sz + tt_sz + psetable_sz, PAGESIZE);
		if (prom_alloc(tmp_base, tmp_size, PAGESIZE) == 0)
			prom_panic("kmem64 prom_alloc contig failed");
		PRM_DEBUG(tmp_base);
		PRM_DEBUG(tmp_size);

		/*
		 * Allocate the page_ts
		 */
		if (bop_alloc_chunk(kmem64_base, pp_sz, PAGESIZE) == 0)
			prom_panic("kmem64 bop_alloc_chunk page_t failed");
		PRM_DEBUG(kmem64_base);
		PRM_DEBUG(pp_sz);

		kmem64_aligned_end = kmem64_base + pp_sz + tmp_size;
		ASSERT(kmem64_aligned_end >= kmem64_end);

		kmem64_smchunks = 1;
	} else {

		/*
		 * We need to adjust pp_sz for the normal
		 * case where kmem64 can allocate one large chunk
		 */
		if (kpm_smallpages == 0) {
			npages -= kmem64_sz / (PAGESIZE + sizeof (struct page));
		} else {
			npages -= kmem64_sz / (PAGESIZE + sizeof (struct page) +
			    sizeof (kpm_spage_t));
		}
		pp_sz = npages * sizeof (struct page);
	}

	if (kmem64_aligned_end > (hole_start ? hole_start : kpm_vbase))
		cmn_err(CE_PANIC, "not enough kmem64 space");
	PRM_DEBUG(kmem64_base);
	PRM_DEBUG(kmem64_end);
	PRM_DEBUG(kmem64_aligned_end);

	/*
	 * ... and divy it up
	 */
	alloc_base = kmem64_base;

	pp_base = (page_t *)alloc_base;
	alloc_base += pp_sz;
	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base, ecache_alignsize);
	PRM_DEBUG(pp_base);
	PRM_DEBUG(npages);

	if (kpm_enable) {
		kpm_pp_base = alloc_base;
		if (kpm_smallpages == 0) {
			/* kpm_npages based on physinstalled, don't reset */
			kpm_pp_sz = kpm_npages * sizeof (kpm_page_t);
		} else {
			kpm_npages = ptokpmpr(npages);
			kpm_pp_sz = kpm_npages * sizeof (kpm_spage_t);
		}
		alloc_base += kpm_pp_sz;
		alloc_base =
		    (caddr_t)roundup((uintptr_t)alloc_base, ecache_alignsize);
		PRM_DEBUG(kpm_pp_base);
	}

	alloc_base = alloc_hmehash(alloc_base);
	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base, ecache_alignsize);
	PRM_DEBUG(alloc_base);

	page_hash = (page_t **)alloc_base;
	alloc_base += pagehash_sz;
	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base, ecache_alignsize);
	PRM_DEBUG(page_hash);

	alloc_base = alloc_page_freelists(alloc_base);
	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base, ecache_alignsize);
	PRM_DEBUG(alloc_base);

#ifdef	TRAPTRACE
	ttrace_buf = alloc_base;
	alloc_base += tt_sz;
	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base, ecache_alignsize);
	PRM_DEBUG(alloc_base);
#endif	/* TRAPTRACE */

	pse_mutex = (pad_mutex_t *)alloc_base;
	alloc_base += psetable_sz;
	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base, ecache_alignsize);
	PRM_DEBUG(alloc_base);

	/*
	 * Note that if we use small chunk allocations for
	 * kmem64, we need to ensure kmem64_end is the same as
	 * kmem64_aligned_end to prevent subsequent logic from
	 * trying to reuse the overmapping.
	 * Otherwise we adjust kmem64_end to what we really allocated.
	 */
	if (kmem64_smchunks) {
		kmem64_end = kmem64_aligned_end;
	} else {
		kmem64_end = (caddr_t)roundup((uintptr_t)alloc_base, PAGESIZE);
	}
	kmem64_sz = kmem64_end - kmem64_base;

	if (&ecache_init_scrub_flush_area) {
		alloc_base = ecache_init_scrub_flush_area(kmem64_aligned_end);
		ASSERT(alloc_base <= (hole_start ? hole_start : kpm_vbase));
	}

	/*
	 * If physmem is patched to be non-zero, use it instead of
	 * the monitor value unless physmem is larger than the total
	 * amount of memory on hand.
	 */
	if (physmem == 0 || physmem > npages)
		physmem = npages;

	/*
	 * root_is_ramdisk is set via /etc/system when the ramdisk miniroot
	 * is mounted as root. This memory is held down by OBP and unlike
	 * the stub boot_archive is never released.
	 *
	 * In order to get things sized correctly on lower memory
	 * machines (where the memory used by the ramdisk represents
	 * a significant portion of memory), physmem is adjusted.
	 *
	 * This is done by subtracting the ramdisk_size which is set
	 * to the size of the ramdisk (in Kb) in /etc/system at the
	 * time the miniroot archive is constructed.
	 */
	if (root_is_ramdisk == B_TRUE) {
		ramdisk_npages = (ramdisk_size * 1024) / PAGESIZE;
		physmem -= ramdisk_npages;
	}

	if (kpm_enable && (ndata_alloc_kpm(&ndata, kpm_npages) != 0))
		cmn_err(CE_PANIC, "no more nucleus memory after kpm alloc");

	/*
	 * Allocate space for the interrupt vector table.
	 */
	memspace = prom_alloc((caddr_t)intr_vec_table, IVSIZE, MMU_PAGESIZE);
	if (memspace != (caddr_t)intr_vec_table)
		prom_panic("interrupt vector table allocation failure");

	/*
	 * Between now and when we finish copying in the memory lists,
	 * allocations happen so the space gets fragmented and the
	 * lists longer.  Leave enough space for lists twice as
	 * long as we have now; then roundup to a pagesize.
	 */
	memlist_sz = sizeof (struct memlist) * (prom_phys_installed_len() +
	    prom_phys_avail_len() + prom_virt_avail_len());
	memlist_sz *= 2;
	memlist_sz = roundup(memlist_sz, PAGESIZE);
	memspace = ndata_alloc(&ndata, memlist_sz, ecache_alignsize);
	if (memspace == NULL)
		cmn_err(CE_PANIC, "no more nucleus memory after memlist alloc");

	memlist = (struct memlist *)memspace;
	memlist_end = (char *)memspace + memlist_sz;
	PRM_DEBUG(memlist);
	PRM_DEBUG(memlist_end);

	PRM_DEBUG(sysbase);
	PRM_DEBUG(syslimit);
	kernelheap_init((void *)sysbase, (void *)syslimit,
	    (caddr_t)sysbase + PAGESIZE, NULL, NULL);

	/*
	 * Take the most current snapshot we can by calling mem-update.
	 */
	copy_boot_memlists(&boot_physinstalled, &boot_physinstalled_len,
	    &boot_physavail, &boot_physavail_len,
	    &boot_virtavail, &boot_virtavail_len);

	/*
	 * Remove the space used by prom_alloc from the kernel heap
	 * plus the area actually used by the OBP (if any)
	 * ignoring virtual addresses in virt_avail, above syslimit.
	 */
	virt_avail = memlist;
	copy_memlist(boot_virtavail, boot_virtavail_len, &memlist);

	for (cur = virt_avail; cur->ml_next; cur = cur->ml_next) {
		uint64_t range_base, range_size;

		if ((range_base = cur->ml_address + cur->ml_size) <
		    (uint64_t)sysbase)
			continue;
		if (range_base >= (uint64_t)syslimit)
			break;
		/*
		 * Limit the range to end at syslimit.
		 */
		range_size = MIN(cur->ml_next->ml_address,
		    (uint64_t)syslimit) - range_base;
		(void) vmem_xalloc(heap_arena, (size_t)range_size, PAGESIZE,
		    0, 0, (void *)range_base, (void *)(range_base + range_size),
		    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);
	}

	phys_avail = memlist;
	copy_memlist(boot_physavail, boot_physavail_len, &memlist);

	/*
	 * Add any extra memory at the end of the ndata region if there's at
	 * least a page to add.  There might be a few more pages available in
	 * the middle of the ndata region, but for now they are ignored.
	 */
	nalloc_base = ndata_extra_base(&ndata, MMU_PAGESIZE, nalloc_end);
	if (nalloc_base == NULL)
		nalloc_base = nalloc_end;
	ndata_remain_sz = nalloc_end - nalloc_base;

	/*
	 * Copy physinstalled list into kernel space.
	 */
	phys_install = memlist;
	copy_memlist(boot_physinstalled, boot_physinstalled_len, &memlist);

	/*
	 * Create list of physical addrs we don't need pp's for:
	 * kernel text 4M page
	 * kernel data 4M page - ndata_remain_sz
	 * kmem64 pages
	 *
	 * NB if adding any pages here, make sure no kpm page
	 * overlaps can occur (see ASSERTs in kphysm_memsegs)
	 */
	nopp_list = memlist;
	memlist_new(va_to_pa(s_text), MMU_PAGESIZE4M, &memlist);
	memlist_add(va_to_pa(s_data), MMU_PAGESIZE4M - ndata_remain_sz,
	    &memlist, &nopp_list);

	/* Don't add to nopp_list if kmem64 was allocated in smchunks */
	if (!kmem64_smchunks)
		memlist_add(kmem64_pabase, kmem64_sz, &memlist, &nopp_list);

	if ((caddr_t)memlist > (memspace + memlist_sz))
		prom_panic("memlist overflow");

	/*
	 * Size the pcf array based on the number of cpus in the box at
	 * boot time.
	 */
	pcf_init();

	/*
	 * Initialize the page structures from the memory lists.
	 */
	kphysm_init();

	availrmem_initial = availrmem = freemem;
	PRM_DEBUG(availrmem);

	/*
	 * Some of the locks depend on page_hashsz being set!
	 * kmem_init() depends on this; so, keep it here.
	 */
	page_lock_init();

	/*
	 * Initialize kernel memory allocator.
	 */
	kmem_init();

	/*
	 * Factor in colorequiv to check additional 'equivalent' bins
	 */
	if (&page_set_colorequiv_arr_cpu != NULL)
		page_set_colorequiv_arr_cpu();
	else
		page_set_colorequiv_arr();

	/*
	 * Initialize bp_mapin().
	 */
	bp_init(shm_alignment, HAT_STRICTORDER);

	/*
	 * Reserve space for MPO mblock structs from the 32-bit heap.
	 */

	if (mpo_heap32_bufsz > (size_t)0) {
		(void) vmem_xalloc(heap32_arena, mpo_heap32_bufsz,
		    PAGESIZE, 0, 0, mpo_heap32_buf,
		    mpo_heap32_buf + mpo_heap32_bufsz,
		    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);
	}
	mem_config_init();
}

static void
startup_modules(void)
{
	int nhblk1, nhblk8;
	size_t  nhblksz;
	pgcnt_t pages_per_hblk;
	size_t hme8blk_sz, hme1blk_sz;

	/*
	 * The system file /etc/system was read already under startup_memlist.
	 */
	if (&set_platform_defaults)
		set_platform_defaults();

	/*
	 * Calculate default settings of system parameters based upon
	 * maxusers, yet allow to be overridden via the /etc/system file.
	 */
	param_calc(0);

	mod_setup();

	/*
	 * If this is a positron, complain and halt.
	 */
	if (&iam_positron && iam_positron()) {
		cmn_err(CE_WARN, "This hardware platform is not supported"
		    " by this release of Solaris.\n");
#ifdef DEBUG
		prom_enter_mon();	/* Type 'go' to resume */
		cmn_err(CE_WARN, "Booting an unsupported platform.\n");
		cmn_err(CE_WARN, "Booting with down-rev firmware.\n");

#else /* DEBUG */
		halt(0);
#endif /* DEBUG */
	}

	/*
	 * If we are running firmware that isn't 64-bit ready
	 * then complain and halt.
	 */
	do_prom_version_check();

	/*
	 * Initialize system parameters
	 */
	param_init();

	/*
	 * maxmem is the amount of physical memory we're playing with.
	 */
	maxmem = physmem;

	/* Set segkp limits. */
	ncbase = kdi_segdebugbase;
	ncend = kdi_segdebugbase;

	/*
	 * Initialize the hat layer.
	 */
	hat_init();

	/*
	 * Initialize segment management stuff.
	 */
	seg_init();

	/*
	 * Create the va>tte handler, so the prom can understand
	 * kernel translations.  The handler is installed later, just
	 * as we are about to take over the trap table from the prom.
	 */
	create_va_to_tte();

	/*
	 * Load the forthdebugger (optional)
	 */
	forthdebug_init();

	/*
	 * Create OBP node for console input callbacks
	 * if it is needed.
	 */
	startup_create_io_node();

	if (modloadonly("fs", "specfs") == -1)
		halt("Can't load specfs");

	if (modloadonly("fs", "devfs") == -1)
		halt("Can't load devfs");

	if (modloadonly("fs", "procfs") == -1)
		halt("Can't load procfs");

	if (modloadonly("misc", "swapgeneric") == -1)
		halt("Can't load swapgeneric");

	(void) modloadonly("sys", "lbl_edition");

	dispinit();

	/*
	 * Infer meanings to the members of the idprom buffer.
	 */
	parse_idprom();

	/* Read cluster configuration data. */
	clconf_init();

	setup_ddi();

	/*
	 * Lets take this opportunity to load the root device.
	 */
	if (loadrootmodules() != 0)
		debug_enter("Can't load the root filesystem");

	/*
	 * Load tod driver module for the tod part found on this system.
	 * Recompute the cpu frequency/delays based on tod as tod part
	 * tends to keep time more accurately.
	 */
	if (&load_tod_module)
		load_tod_module();

	/*
	 * Allow platforms to load modules which might
	 * be needed after bootops are gone.
	 */
	if (&load_platform_modules)
		load_platform_modules();

	setcpudelay();

	copy_boot_memlists(&boot_physinstalled, &boot_physinstalled_len,
	    &boot_physavail, &boot_physavail_len,
	    &boot_virtavail, &boot_virtavail_len);

	/*
	 * Calculation and allocation of hmeblks needed to remap
	 * the memory allocated by PROM till now.
	 * Overestimate the number of hblk1 elements by assuming
	 * worst case of TTE64K mappings.
	 * sfmmu_hblk_alloc will panic if this calculation is wrong.
	 */
	bop_alloc_pages = btopr(kmem64_end - kmem64_base);
	pages_per_hblk = btop(HMEBLK_SPAN(TTE64K));
	bop_alloc_pages = roundup(bop_alloc_pages, pages_per_hblk);
	nhblk1 = bop_alloc_pages / pages_per_hblk + hblk1_min;

	bop_alloc_pages = size_virtalloc(boot_virtavail, boot_virtavail_len);

	/* sfmmu_init_nucleus_hblks expects properly aligned data structures */
	hme8blk_sz = roundup(HME8BLK_SZ, sizeof (int64_t));
	hme1blk_sz = roundup(HME1BLK_SZ, sizeof (int64_t));

	bop_alloc_pages += btopr(nhblk1 * hme1blk_sz);

	pages_per_hblk = btop(HMEBLK_SPAN(TTE8K));
	nhblk8 = 0;
	while (bop_alloc_pages > 1) {
		bop_alloc_pages = roundup(bop_alloc_pages, pages_per_hblk);
		nhblk8 += bop_alloc_pages /= pages_per_hblk;
		bop_alloc_pages *= hme8blk_sz;
		bop_alloc_pages = btopr(bop_alloc_pages);
	}
	nhblk8 += 2;

	/*
	 * Since hblk8's can hold up to 64k of mappings aligned on a 64k
	 * boundary, the number of hblk8's needed to map the entries in the
	 * boot_virtavail list needs to be adjusted to take this into
	 * consideration.  Thus, we need to add additional hblk8's since it
	 * is possible that an hblk8 will not have all 8 slots used due to
	 * alignment constraints.  Since there were boot_virtavail_len entries
	 * in that list, we need to add that many hblk8's to the number
	 * already calculated to make sure we don't underestimate.
	 */
	nhblk8 += boot_virtavail_len;
	nhblksz = nhblk8 * hme8blk_sz + nhblk1 * hme1blk_sz;

	/* Allocate in pagesize chunks */
	nhblksz = roundup(nhblksz, MMU_PAGESIZE);
	hblk_base = kmem_zalloc(nhblksz, KM_SLEEP);
	sfmmu_init_nucleus_hblks(hblk_base, nhblksz, nhblk8, nhblk1);
}

static void
startup_bop_gone(void)
{

	/*
	 * Destroy the MD initialized at startup
	 * The startup initializes the MD framework
	 * using prom and BOP alloc free it now.
	 */
	mach_descrip_startup_fini();

	/*
	 * We're done with prom allocations.
	 */
	bop_fini();

	copy_boot_memlists(&boot_physinstalled, &boot_physinstalled_len,
	    &boot_physavail, &boot_physavail_len,
	    &boot_virtavail, &boot_virtavail_len);

	/*
	 * setup physically contiguous area twice as large as the ecache.
	 * this is used while doing displacement flush of ecaches
	 */
	if (&ecache_flush_address) {
		ecache_flushaddr = ecache_flush_address();
		if (ecache_flushaddr == (uint64_t)-1) {
			cmn_err(CE_PANIC,
			    "startup: no memory to set ecache_flushaddr");
		}
	}

	/*
	 * Virtual available next.
	 */
	ASSERT(virt_avail != NULL);
	memlist_free_list(virt_avail);
	virt_avail = memlist;
	copy_memlist(boot_virtavail, boot_virtavail_len, &memlist);

}


/*
 * startup_fixup_physavail - called from mach_sfmmu.c after the final
 * allocations have been performed.  We can't call it in startup_bop_gone
 * since later operations can cause obp to allocate more memory.
 */
void
startup_fixup_physavail(void)
{
	struct memlist *cur;
	size_t kmem64_overmap_size = kmem64_aligned_end - kmem64_end;

	PRM_DEBUG(kmem64_overmap_size);

	/*
	 * take the most current snapshot we can by calling mem-update
	 */
	copy_boot_memlists(&boot_physinstalled, &boot_physinstalled_len,
	    &boot_physavail, &boot_physavail_len,
	    &boot_virtavail, &boot_virtavail_len);

	/*
	 * Copy phys_avail list, again.
	 * Both the kernel/boot and the prom have been allocating
	 * from the original list we copied earlier.
	 */
	cur = memlist;
	copy_memlist(boot_physavail, boot_physavail_len, &memlist);

	/*
	 * Add any unused kmem64 memory from overmapped page
	 * (Note: va_to_pa does not work for kmem64_end)
	 */
	if (kmem64_overmap_size) {
		memlist_add(kmem64_pabase + (kmem64_end - kmem64_base),
		    kmem64_overmap_size, &memlist, &cur);
	}

	/*
	 * Add any extra memory after e_data we added to the phys_avail list
	 * back to the old list.
	 */
	if (ndata_remain_sz >= MMU_PAGESIZE)
		memlist_add(va_to_pa(nalloc_base),
		    (uint64_t)ndata_remain_sz, &memlist, &cur);

	/*
	 * There isn't any bounds checking on the memlist area
	 * so ensure it hasn't overgrown.
	 */
	if ((caddr_t)memlist > (caddr_t)memlist_end)
		cmn_err(CE_PANIC, "startup: memlist size exceeded");

	/*
	 * The kernel removes the pages that were allocated for it from
	 * the freelist, but we now have to find any -extra- pages that
	 * the prom has allocated for it's own book-keeping, and remove
	 * them from the freelist too. sigh.
	 */
	sync_memlists(phys_avail, cur);

	ASSERT(phys_avail != NULL);

	old_phys_avail = phys_avail;
	phys_avail = cur;
}

void
update_kcage_ranges(uint64_t addr, uint64_t len)
{
	pfn_t base = btop(addr);
	pgcnt_t num = btop(len);
	int rv;

	rv = kcage_range_add(base, num, kcage_startup_dir);

	if (rv == ENOMEM) {
		cmn_err(CE_WARN, "%ld megabytes not available to kernel cage",
		    (len == 0 ? 0 : BYTES_TO_MB(len)));
	} else if (rv != 0) {
		/* catch this in debug kernels */
		ASSERT(0);

		cmn_err(CE_WARN, "unexpected kcage_range_add"
		    " return value %d", rv);
	}
}

static void
startup_vm(void)
{
	size_t	i;
	struct segmap_crargs a;
	struct segkpm_crargs b;

	uint64_t avmem;
	caddr_t va;
	pgcnt_t	max_phys_segkp;
	int	mnode;

	extern int use_brk_lpg, use_stk_lpg;

	/*
	 * get prom's mappings, create hments for them and switch
	 * to the kernel context.
	 */
	hat_kern_setup();

	/*
	 * Take over trap table
	 */
	setup_trap_table();

	/*
	 * Install the va>tte handler, so that the prom can handle
	 * misses and understand the kernel table layout in case
	 * we need call into the prom.
	 */
	install_va_to_tte();

	/*
	 * Set a flag to indicate that the tba has been taken over.
	 */
	tba_taken_over = 1;

	/* initialize MMU primary context register */
	mmu_init_kcontext();

	/*
	 * The boot cpu can now take interrupts, x-calls, x-traps
	 */
	CPUSET_ADD(cpu_ready_set, CPU->cpu_id);
	CPU->cpu_flags |= (CPU_READY | CPU_ENABLE | CPU_EXISTS);

	/*
	 * Set a flag to tell write_scb_int() that it can access V_TBR_WR_ADDR.
	 */
	tbr_wr_addr_inited = 1;

	/*
	 * Initialize VM system, and map kernel address space.
	 */
	kvm_init();

	ASSERT(old_phys_avail != NULL && phys_avail != NULL);
	if (kernel_cage_enable) {
		diff_memlists(phys_avail, old_phys_avail, update_kcage_ranges);
	}
	memlist_free_list(old_phys_avail);

	/*
	 * If the following is true, someone has patched
	 * phsymem to be less than the number of pages that
	 * the system actually has.  Remove pages until system
	 * memory is limited to the requested amount.  Since we
	 * have allocated page structures for all pages, we
	 * correct the amount of memory we want to remove
	 * by the size of the memory used to hold page structures
	 * for the non-used pages.
	 */
	if (physmem + ramdisk_npages < npages) {
		pgcnt_t diff, off;
		struct page *pp;
		struct seg kseg;

		cmn_err(CE_WARN, "limiting physmem to %ld pages", physmem);

		off = 0;
		diff = npages - (physmem + ramdisk_npages);
		diff -= mmu_btopr(diff * sizeof (struct page));
		kseg.s_as = &kas;
		while (diff--) {
			pp = page_create_va(&unused_pages_vp, (offset_t)off,
			    MMU_PAGESIZE, PG_WAIT | PG_EXCL,
			    &kseg, (caddr_t)off);
			if (pp == NULL)
				cmn_err(CE_PANIC, "limited physmem too much!");
			page_io_unlock(pp);
			page_downgrade(pp);
			availrmem--;
			off += MMU_PAGESIZE;
		}
	}

	/*
	 * When printing memory, show the total as physmem less
	 * that stolen by a debugger.
	 */
	cmn_err(CE_CONT, "?mem = %ldK (0x%lx000)\n",
	    (ulong_t)(physinstalled) << (PAGESHIFT - 10),
	    (ulong_t)(physinstalled) << (PAGESHIFT - 12));

	avmem = (uint64_t)freemem << PAGESHIFT;
	cmn_err(CE_CONT, "?avail mem = %lld\n", (unsigned long long)avmem);

	/*
	 * For small memory systems disable automatic large pages.
	 */
	if (physmem < privm_lpg_min_physmem) {
		use_brk_lpg = 0;
		use_stk_lpg = 0;
	}

	/*
	 * Perform platform specific freelist processing
	 */
	if (&plat_freelist_process) {
		for (mnode = 0; mnode < max_mem_nodes; mnode++)
			if (mem_node_config[mnode].exists)
				plat_freelist_process(mnode);
	}

	/*
	 * Initialize the segkp segment type.  We position it
	 * after the configured tables and buffers (whose end
	 * is given by econtig) and before V_WKBASE_ADDR.
	 * Also in this area is segkmap (size SEGMAPSIZE).
	 */

	/* XXX - cache alignment? */
	va = (caddr_t)SEGKPBASE;
	ASSERT(((uintptr_t)va & PAGEOFFSET) == 0);

	max_phys_segkp = (physmem * 2);

	if (segkpsize < btop(SEGKPMINSIZE) || segkpsize > btop(SEGKPMAXSIZE)) {
		segkpsize = btop(SEGKPDEFSIZE);
		cmn_err(CE_WARN, "Illegal value for segkpsize. "
		    "segkpsize has been reset to %ld pages", segkpsize);
	}

	i = ptob(MIN(segkpsize, max_phys_segkp));

	rw_enter(&kas.a_lock, RW_WRITER);
	if (seg_attach(&kas, va, i, segkp) < 0)
		cmn_err(CE_PANIC, "startup: cannot attach segkp");
	if (segkp_create(segkp) != 0)
		cmn_err(CE_PANIC, "startup: segkp_create failed");
	rw_exit(&kas.a_lock);

	/*
	 * kpm segment
	 */
	segmap_kpm = kpm_enable &&
	    segmap_kpm && PAGESIZE == MAXBSIZE;

	if (kpm_enable) {
		rw_enter(&kas.a_lock, RW_WRITER);

		/*
		 * The segkpm virtual range range is larger than the
		 * actual physical memory size and also covers gaps in
		 * the physical address range for the following reasons:
		 * . keep conversion between segkpm and physical addresses
		 *   simple, cheap and unambiguous.
		 * . avoid extension/shrink of the the segkpm in case of DR.
		 * . avoid complexity for handling of virtual addressed
		 *   caches, segkpm and the regular mapping scheme must be
		 *   kept in sync wrt. the virtual color of mapped pages.
		 * Any accesses to virtual segkpm ranges not backed by
		 * physical memory will fall through the memseg pfn hash
		 * and will be handled in segkpm_fault.
		 * Additional kpm_size spaces needed for vac alias prevention.
		 */
		if (seg_attach(&kas, kpm_vbase, kpm_size * vac_colors,
		    segkpm) < 0)
			cmn_err(CE_PANIC, "cannot attach segkpm");

		b.prot = PROT_READ | PROT_WRITE;
		b.nvcolors = shm_alignment >> MMU_PAGESHIFT;

		if (segkpm_create(segkpm, (caddr_t)&b) != 0)
			panic("segkpm_create segkpm");

		rw_exit(&kas.a_lock);

		mach_kpm_init();
	}

	va = kpm_vbase + (kpm_size * vac_colors);

	if (!segzio_fromheap) {
		size_t size;
		size_t physmem_b = mmu_ptob(physmem);

		/* size is in bytes, segziosize is in pages */
		if (segziosize == 0) {
			size = physmem_b;
		} else {
			size = mmu_ptob(segziosize);
		}

		if (size < SEGZIOMINSIZE) {
			size = SEGZIOMINSIZE;
		} else if (size > SEGZIOMAXSIZE) {
			size = SEGZIOMAXSIZE;
			/*
			 * On 64-bit x86, we only have 2TB of KVA.  This exists
			 * for parity with x86.
			 *
			 * SEGZIOMAXSIZE is capped at 512gb so that segzio
			 * doesn't consume all of KVA.  However, if we have a
			 * system that has more thant 512gb of physical memory,
			 * we can actually consume about half of the difference
			 * between 512gb and the rest of the available physical
			 * memory.
			 */
			if (physmem_b > SEGZIOMAXSIZE) {
				size += (physmem_b - SEGZIOMAXSIZE) / 2;
		}
		}
		segziosize = mmu_btop(roundup(size, MMU_PAGESIZE));
		/* put the base of the ZIO segment after the kpm segment */
		segzio_base = va;
		va += mmu_ptob(segziosize);
		PRM_DEBUG(segziosize);
		PRM_DEBUG(segzio_base);

		/*
		 * On some platforms, kvm_init is called after the kpm
		 * sizes have been determined.  On SPARC, kvm_init is called
		 * before, so we have to attach the kzioseg after kvm is
		 * initialized, otherwise we'll try to allocate from the boot
		 * area since the kernel heap hasn't yet been configured.
		 */
		rw_enter(&kas.a_lock, RW_WRITER);

		(void) seg_attach(&kas, segzio_base, mmu_ptob(segziosize),
		    &kzioseg);
		(void) segkmem_zio_create(&kzioseg);

		/* create zio area covering new segment */
		segkmem_zio_init(segzio_base, mmu_ptob(segziosize));

		rw_exit(&kas.a_lock);
	}

	if (ppvm_enable) {
		caddr_t ppvm_max;

		/*
		 * ppvm refers to the static VA space used to map
		 * the page_t's for dynamically added memory.
		 *
		 * ppvm_base should not cross a potential VA hole.
		 *
		 * ppvm_size should be large enough to map the
		 * page_t's needed to manage all of KPM range.
		 */
		ppvm_size =
		    roundup(mmu_btop(kpm_size * vac_colors) * sizeof (page_t),
		    MMU_PAGESIZE);
		ppvm_max = (caddr_t)(0ull - ppvm_size);
		ppvm_base = (page_t *)va;

		if ((caddr_t)ppvm_base <= hole_end) {
			cmn_err(CE_WARN,
			    "Memory DR disabled: invalid DR map base: 0x%p\n",
			    (void *)ppvm_base);
			ppvm_enable = 0;
		} else if ((caddr_t)ppvm_base > ppvm_max) {
			uint64_t diff = (caddr_t)ppvm_base - ppvm_max;

			cmn_err(CE_WARN,
			    "Memory DR disabled: insufficient DR map size:"
			    " 0x%lx (needed 0x%lx)\n",
			    ppvm_size - diff, ppvm_size);
			ppvm_enable = 0;
		}
		PRM_DEBUG(ppvm_size);
		PRM_DEBUG(ppvm_base);
	}

	/*
	 * Now create generic mapping segment.  This mapping
	 * goes SEGMAPSIZE beyond SEGMAPBASE.  But if the total
	 * virtual address is greater than the amount of free
	 * memory that is available, then we trim back the
	 * segment size to that amount
	 */
	va = (caddr_t)SEGMAPBASE;

	/*
	 * 1201049: segkmap base address must be MAXBSIZE aligned
	 */
	ASSERT(((uintptr_t)va & MAXBOFFSET) == 0);

	/*
	 * Set size of segmap to percentage of freemem at boot,
	 * but stay within the allowable range
	 * Note we take percentage  before converting from pages
	 * to bytes to avoid an overflow on 32-bit kernels.
	 */
	i = mmu_ptob((freemem * segmap_percent) / 100);

	if (i < MINMAPSIZE)
		i = MINMAPSIZE;

	if (i > MIN(SEGMAPSIZE, mmu_ptob(freemem)))
		i = MIN(SEGMAPSIZE, mmu_ptob(freemem));

	i &= MAXBMASK;	/* 1201049: segkmap size must be MAXBSIZE aligned */

	rw_enter(&kas.a_lock, RW_WRITER);
	if (seg_attach(&kas, va, i, segkmap) < 0)
		cmn_err(CE_PANIC, "cannot attach segkmap");

	a.prot = PROT_READ | PROT_WRITE;
	a.shmsize = shm_alignment;
	a.nfreelist = 0;	/* use segmap driver defaults */

	if (segmap_create(segkmap, (caddr_t)&a) != 0)
		panic("segmap_create segkmap");
	rw_exit(&kas.a_lock);

	segdev_init();
}

static void
startup_end(void)
{
	if ((caddr_t)memlist > (caddr_t)memlist_end)
		panic("memlist overflow 2");
	memlist_free_block((caddr_t)memlist,
	    ((caddr_t)memlist_end - (caddr_t)memlist));
	memlist = NULL;

	/* enable page_relocation since OBP is now done */
	page_relocate_ready = 1;

	/*
	 * Perform tasks that get done after most of the VM
	 * initialization has been done but before the clock
	 * and other devices get started.
	 */
	kern_setup1();

	/*
	 * Perform CPC initialization for this CPU.
	 */
	kcpc_hw_init();

	/*
	 * Intialize the VM arenas for allocating physically
	 * contiguus memory chunk for interrupt queues snd
	 * allocate/register boot cpu's queues, if any and
	 * allocate dump buffer for sun4v systems to store
	 * extra crash information during crash dump
	 */
	contig_mem_init();
	mach_descrip_init();

	if (cpu_intrq_setup(CPU)) {
		cmn_err(CE_PANIC, "cpu%d: setup failed", CPU->cpu_id);
	}
	cpu_intrq_register(CPU);
	mach_htraptrace_setup(CPU->cpu_id);
	mach_htraptrace_configure(CPU->cpu_id);
	mach_dump_buffer_init();

	/*
	 * Initialize interrupt related stuff
	 */
	cpu_intr_alloc(CPU, NINTR_THREADS);

	(void) splzs();			/* allow hi clock ints but not zs */

	/*
	 * Initialize errors.
	 */
	error_init();

	/*
	 * Note that we may have already used kernel bcopy before this
	 * point - but if you really care about this, adb the use_hw_*
	 * variables to 0 before rebooting.
	 */
	mach_hw_copy_limit();

	/*
	 * Install the "real" preemption guards before DDI services
	 * are available.
	 */
	(void) prom_set_preprom(kern_preprom);
	(void) prom_set_postprom(kern_postprom);
	CPU->cpu_m.mutex_ready = 1;

	/*
	 * Initialize segnf (kernel support for non-faulting loads).
	 */
	segnf_init();

	/*
	 * Configure the root devinfo node.
	 */
	configure();		/* set up devices */
	mach_cpu_halt_idle();
}


void
post_startup(void)
{
#ifdef	PTL1_PANIC_DEBUG
	extern void init_ptl1_thread(void);
#endif	/* PTL1_PANIC_DEBUG */
	extern void abort_sequence_init(void);

	/*
	 * Set the system wide, processor-specific flags to be passed
	 * to userland via the aux vector for performance hints and
	 * instruction set extensions.
	 */
	bind_hwcap();

	/*
	 * Startup memory scrubber (if any)
	 */
	mach_memscrub();

	/*
	 * Allocate soft interrupt to handle abort sequence.
	 */
	abort_sequence_init();

	/*
	 * Configure the rest of the system.
	 * Perform forceloading tasks for /etc/system.
	 */
	(void) mod_sysctl(SYS_FORCELOAD, NULL);
	/*
	 * ON4.0: Force /proc module in until clock interrupt handle fixed
	 * ON4.0: This must be fixed or restated in /etc/systems.
	 */
	(void) modload("fs", "procfs");

	/* load machine class specific drivers */
	load_mach_drivers();

	/* load platform specific drivers */
	if (&load_platform_drivers)
		load_platform_drivers();

	/* load vis simulation module, if we are running w/fpu off */
	if (!fpu_exists) {
		if (modload("misc", "vis") == -1)
			halt("Can't load vis");
	}

	mach_fpras();

	maxmem = freemem;

	pg_init();

#ifdef	PTL1_PANIC_DEBUG
	init_ptl1_thread();
#endif	/* PTL1_PANIC_DEBUG */
}

#ifdef	PTL1_PANIC_DEBUG
int		ptl1_panic_test = 0;
int		ptl1_panic_xc_one_test = 0;
int		ptl1_panic_xc_all_test = 0;
int		ptl1_panic_xt_one_test = 0;
int		ptl1_panic_xt_all_test = 0;
kthread_id_t	ptl1_thread_p = NULL;
kcondvar_t	ptl1_cv;
kmutex_t	ptl1_mutex;
int		ptl1_recurse_count_threshold = 0x40;
int		ptl1_recurse_trap_threshold = 0x3d;
extern void	ptl1_recurse(int, int);
extern void	ptl1_panic_xt(int, int);

/*
 * Called once per second by timeout() to wake up
 * the ptl1_panic thread to see if it should cause
 * a trap to the ptl1_panic() code.
 */
/* ARGSUSED */
static void
ptl1_wakeup(void *arg)
{
	mutex_enter(&ptl1_mutex);
	cv_signal(&ptl1_cv);
	mutex_exit(&ptl1_mutex);
}

/*
 * ptl1_panic cross call function:
 *     Needed because xc_one() and xc_some() can pass
 *	64 bit args but ptl1_recurse() expects ints.
 */
static void
ptl1_panic_xc(void)
{
	ptl1_recurse(ptl1_recurse_count_threshold,
	    ptl1_recurse_trap_threshold);
}

/*
 * The ptl1 thread waits for a global flag to be set
 * and uses the recurse thresholds to set the stack depth
 * to cause a ptl1_panic() directly via a call to ptl1_recurse
 * or indirectly via the cross call and cross trap functions.
 *
 * This is useful testing stack overflows and normal
 * ptl1_panic() states with a know stack frame.
 *
 * ptl1_recurse() is an asm function in ptl1_panic.s that
 * sets the {In, Local, Out, and Global} registers to a
 * know state on the stack and just prior to causing a
 * test ptl1_panic trap.
 */
static void
ptl1_thread(void)
{
	mutex_enter(&ptl1_mutex);
	while (ptl1_thread_p) {
		cpuset_t	other_cpus;
		int		cpu_id;
		int		my_cpu_id;
		int		target_cpu_id;
		int		target_found;

		if (ptl1_panic_test) {
			ptl1_recurse(ptl1_recurse_count_threshold,
			    ptl1_recurse_trap_threshold);
		}

		/*
		 * Find potential targets for x-call and x-trap,
		 * if any exist while preempt is disabled we
		 * start a ptl1_panic if requested via a
		 * globals.
		 */
		kpreempt_disable();
		my_cpu_id = CPU->cpu_id;
		other_cpus = cpu_ready_set;
		CPUSET_DEL(other_cpus, CPU->cpu_id);
		target_found = 0;
		if (!CPUSET_ISNULL(other_cpus)) {
			/*
			 * Pick the first one
			 */
			for (cpu_id = 0; cpu_id < NCPU; cpu_id++) {
				if (cpu_id == my_cpu_id)
					continue;

				if (CPU_XCALL_READY(cpu_id)) {
					target_cpu_id = cpu_id;
					target_found = 1;
					break;
				}
			}
			ASSERT(target_found);

			if (ptl1_panic_xc_one_test) {
				xc_one(target_cpu_id,
				    (xcfunc_t *)ptl1_panic_xc, 0, 0);
			}
			if (ptl1_panic_xc_all_test) {
				xc_some(other_cpus,
				    (xcfunc_t *)ptl1_panic_xc, 0, 0);
			}
			if (ptl1_panic_xt_one_test) {
				xt_one(target_cpu_id,
				    (xcfunc_t *)ptl1_panic_xt, 0, 0);
			}
			if (ptl1_panic_xt_all_test) {
				xt_some(other_cpus,
				    (xcfunc_t *)ptl1_panic_xt, 0, 0);
			}
		}
		kpreempt_enable();
		(void) timeout(ptl1_wakeup, NULL, hz);
		(void) cv_wait(&ptl1_cv, &ptl1_mutex);
	}
	mutex_exit(&ptl1_mutex);
}

/*
 * Called during early startup to create the ptl1_thread
 */
void
init_ptl1_thread(void)
{
	ptl1_thread_p = thread_create(NULL, 0, ptl1_thread, NULL, 0,
	    &p0, TS_RUN, 0);
}
#endif	/* PTL1_PANIC_DEBUG */


static void
memlist_new(uint64_t start, uint64_t len, struct memlist **memlistp)
{
	struct memlist *new;

	new = *memlistp;
	new->ml_address = start;
	new->ml_size = len;
	*memlistp = new + 1;
}

/*
 * Add to a memory list.
 * start = start of new memory segment
 * len = length of new memory segment in bytes
 * memlistp = pointer to array of available memory segment structures
 * curmemlistp = memory list to which to add segment.
 */
static void
memlist_add(uint64_t start, uint64_t len, struct memlist **memlistp,
	struct memlist **curmemlistp)
{
	struct memlist *new = *memlistp;

	memlist_new(start, len, memlistp);
	memlist_insert(new, curmemlistp);
}

static int
ndata_alloc_memseg(struct memlist *ndata, size_t avail)
{
	int nseg;
	size_t memseg_sz;
	struct memseg *msp;

	/*
	 * The memseg list is for the chunks of physical memory that
	 * will be managed by the vm system.  The number calculated is
	 * a guess as boot may fragment it more when memory allocations
	 * are made before kphysm_init().
	 */
	memseg_sz = (avail + 10) * sizeof (struct memseg);
	memseg_sz = roundup(memseg_sz, PAGESIZE);
	nseg = memseg_sz / sizeof (struct memseg);
	msp = ndata_alloc(ndata, memseg_sz, ecache_alignsize);
	if (msp == NULL)
		return (1);
	PRM_DEBUG(memseg_free);

	while (nseg--) {
		msp->next = memseg_free;
		memseg_free = msp;
		msp++;
	}
	return (0);
}

/*
 * In the case of architectures that support dynamic addition of
 * memory at run-time there are two cases where memsegs need to
 * be initialized and added to the memseg list.
 * 1) memsegs that are constructed at startup.
 * 2) memsegs that are constructed at run-time on
 *    hot-plug capable architectures.
 * This code was originally part of the function kphysm_init().
 */

static void
memseg_list_add(struct memseg *memsegp)
{
	struct memseg **prev_memsegp;
	pgcnt_t num;

	/* insert in memseg list, decreasing number of pages order */

	num = MSEG_NPAGES(memsegp);

	for (prev_memsegp = &memsegs; *prev_memsegp;
	    prev_memsegp = &((*prev_memsegp)->next)) {
		if (num > MSEG_NPAGES(*prev_memsegp))
			break;
	}

	memsegp->next = *prev_memsegp;
	*prev_memsegp = memsegp;

	if (kpm_enable) {
		memsegp->nextpa = (memsegp->next) ?
		    va_to_pa(memsegp->next) : MSEG_NULLPTR_PA;

		if (prev_memsegp != &memsegs) {
			struct memseg *msp;
			msp = (struct memseg *)((caddr_t)prev_memsegp -
			    offsetof(struct memseg, next));
			msp->nextpa = va_to_pa(memsegp);
		} else {
			memsegspa = va_to_pa(memsegs);
		}
	}
}

/*
 * PSM add_physmem_cb(). US-II and newer processors have some
 * flavor of the prefetch capability implemented. We exploit
 * this capability for optimum performance.
 */
#define	PREFETCH_BYTES	64

void
add_physmem_cb(page_t *pp, pfn_t pnum)
{
	extern void	 prefetch_page_w(void *);

	pp->p_pagenum = pnum;

	/*
	 * Prefetch one more page_t into E$. To prevent future
	 * mishaps with the sizeof(page_t) changing on us, we
	 * catch this on debug kernels if we can't bring in the
	 * entire hpage with 2 PREFETCH_BYTES reads. See
	 * also, sun4u/cpu/cpu_module.c
	 */
	/*LINTED*/
	ASSERT(sizeof (page_t) <= 2*PREFETCH_BYTES);
	prefetch_page_w((char *)pp);
}

/*
 * Find memseg with given pfn
 */
static struct memseg *
memseg_find(pfn_t base, pfn_t *next)
{
	struct memseg *seg;

	if (next != NULL)
		*next = LONG_MAX;
	for (seg = memsegs; seg != NULL; seg = seg->next) {
		if (base >= seg->pages_base && base < seg->pages_end)
			return (seg);
		if (next != NULL && seg->pages_base > base &&
		    seg->pages_base < *next)
			*next = seg->pages_base;
	}
	return (NULL);
}

/*
 * Put page allocated by OBP on prom_ppages
 */
static void
kphysm_erase(uint64_t addr, uint64_t len)
{
	struct page *pp;
	struct memseg *seg;
	pfn_t base = btop(addr), next;
	pgcnt_t num = btop(len);

	while (num != 0) {
		pgcnt_t off, left;

		seg = memseg_find(base, &next);
		if (seg == NULL) {
			if (next == LONG_MAX)
				break;
			left = MIN(next - base, num);
			base += left, num -= left;
			continue;
		}
		off = base - seg->pages_base;
		pp = seg->pages + off;
		left = num - MIN(num, (seg->pages_end - seg->pages_base) - off);
		while (num != left) {
			/*
			 * init it, lock it, and hashin on prom_pages vp.
			 *
			 * Mark it as NONRELOC to let DR know the page
			 * is locked long term, otherwise DR hangs when
			 * trying to remove those pages.
			 *
			 * XXX	vnode offsets on the prom_ppages vnode
			 *	are page numbers (gack) for >32 bit
			 *	physical memory machines.
			 */
			PP_SETNORELOC(pp);
			add_physmem_cb(pp, base);
			if (page_trylock(pp, SE_EXCL) == 0)
				cmn_err(CE_PANIC, "prom page locked");
			(void) page_hashin(pp, &promvp,
			    (offset_t)base, NULL);
			(void) page_pp_lock(pp, 0, 1);
			pp++, base++, num--;
		}
	}
}

static page_t *ppnext;
static pgcnt_t ppleft;

static void *kpm_ppnext;
static pgcnt_t kpm_ppleft;

/*
 * Create a memseg
 */
static void
kphysm_memseg(uint64_t addr, uint64_t len)
{
	pfn_t base = btop(addr);
	pgcnt_t num = btop(len);
	struct memseg *seg;

	seg = memseg_free;
	memseg_free = seg->next;
	ASSERT(seg != NULL);

	seg->pages = ppnext;
	seg->epages = ppnext + num;
	seg->pages_base = base;
	seg->pages_end = base + num;
	ppnext += num;
	ppleft -= num;

	if (kpm_enable) {
		pgcnt_t kpnum = ptokpmpr(num);

		if (kpnum > kpm_ppleft)
			panic("kphysm_memseg: kpm_pp overflow");
		seg->pagespa = va_to_pa(seg->pages);
		seg->epagespa = va_to_pa(seg->epages);
		seg->kpm_pbase = kpmptop(ptokpmp(base));
		seg->kpm_nkpmpgs = kpnum;
		/*
		 * In the kpm_smallpage case, the kpm array
		 * is 1-1 wrt the page array
		 */
		if (kpm_smallpages) {
			kpm_spage_t *kpm_pp = kpm_ppnext;

			kpm_ppnext = kpm_pp + kpnum;
			seg->kpm_spages = kpm_pp;
			seg->kpm_pagespa = va_to_pa(seg->kpm_spages);
		} else {
			kpm_page_t *kpm_pp = kpm_ppnext;

			kpm_ppnext = kpm_pp + kpnum;
			seg->kpm_pages = kpm_pp;
			seg->kpm_pagespa = va_to_pa(seg->kpm_pages);
			/* ASSERT no kpm overlaps */
			ASSERT(
			    memseg_find(base - pmodkpmp(base), NULL) == NULL);
			ASSERT(memseg_find(
			    roundup(base + num, kpmpnpgs) - 1, NULL) == NULL);
		}
		kpm_ppleft -= kpnum;
	}

	memseg_list_add(seg);
}

/*
 * Add range to free list
 */
void
kphysm_add(uint64_t addr, uint64_t len, int reclaim)
{
	struct page *pp;
	struct memseg *seg;
	pfn_t base = btop(addr);
	pgcnt_t num = btop(len);

	seg = memseg_find(base, NULL);
	ASSERT(seg != NULL);
	pp = seg->pages + (base - seg->pages_base);

	if (reclaim) {
		struct page *rpp = pp;
		struct page *lpp = pp + num;

		/*
		 * page should be locked on prom_ppages
		 * unhash and unlock it
		 */
		while (rpp < lpp) {
			ASSERT(PAGE_EXCL(rpp) && rpp->p_vnode == &promvp);
			ASSERT(PP_ISNORELOC(rpp));
			PP_CLRNORELOC(rpp);
			page_pp_unlock(rpp, 0, 1);
			page_hashout(rpp, NULL);
			page_unlock(rpp);
			rpp++;
		}
	}

	/*
	 * add_physmem() initializes the PSM part of the page
	 * struct by calling the PSM back with add_physmem_cb().
	 * In addition it coalesces pages into larger pages as
	 * it initializes them.
	 */
	add_physmem(pp, num, base);
}

/*
 * kphysm_init() tackles the problem of initializing physical memory.
 */
static void
kphysm_init(void)
{
	struct memlist *pmem;

	ASSERT(page_hash != NULL && page_hashsz != 0);

	ppnext = pp_base;
	ppleft = npages;
	kpm_ppnext = kpm_pp_base;
	kpm_ppleft = kpm_npages;

	/*
	 * installed pages not on nopp_memlist go in memseg list
	 */
	diff_memlists(phys_install, nopp_list, kphysm_memseg);

	/*
	 * Free the avail list
	 */
	for (pmem = phys_avail; pmem != NULL; pmem = pmem->ml_next)
		kphysm_add(pmem->ml_address, pmem->ml_size, 0);

	/*
	 * Erase pages that aren't available
	 */
	diff_memlists(phys_install, phys_avail, kphysm_erase);

	build_pfn_hash();
}

/*
 * Kernel VM initialization.
 * Assumptions about kernel address space ordering:
 *	(1) gap (user space)
 *	(2) kernel text
 *	(3) kernel data/bss
 *	(4) gap
 *	(5) kernel data structures
 *	(6) gap
 *	(7) debugger (optional)
 *	(8) monitor
 *	(9) gap (possibly null)
 *	(10) dvma
 *	(11) devices
 */
static void
kvm_init(void)
{
	/*
	 * Put the kernel segments in kernel address space.
	 */
	rw_enter(&kas.a_lock, RW_WRITER);
	as_avlinit(&kas);

	(void) seg_attach(&kas, (caddr_t)KERNELBASE,
	    (size_t)(e_moddata - KERNELBASE), &ktextseg);
	(void) segkmem_create(&ktextseg);

	(void) seg_attach(&kas, (caddr_t)(KERNELBASE + MMU_PAGESIZE4M),
	    (size_t)(MMU_PAGESIZE4M), &ktexthole);
	(void) segkmem_create(&ktexthole);

	(void) seg_attach(&kas, (caddr_t)valloc_base,
	    (size_t)(econtig32 - valloc_base), &kvalloc);
	(void) segkmem_create(&kvalloc);

	if (kmem64_base) {
		(void) seg_attach(&kas, (caddr_t)kmem64_base,
		    (size_t)(kmem64_end - kmem64_base), &kmem64);
		(void) segkmem_create(&kmem64);
	}

	/*
	 * We're about to map out /boot.  This is the beginning of the
	 * system resource management transition. We can no longer
	 * call into /boot for I/O or memory allocations.
	 */
	(void) seg_attach(&kas, kernelheap, ekernelheap - kernelheap, &kvseg);
	(void) segkmem_create(&kvseg);
	hblk_alloc_dynamic = 1;

	/*
	 * we need to preallocate pages for DR operations before enabling large
	 * page kernel heap because of memseg_remap_init() hat_unload() hack.
	 */
	memseg_remap_init();

	/* at this point we are ready to use large page heap */
	segkmem_heap_lp_init();

	(void) seg_attach(&kas, (caddr_t)SYSBASE32, SYSLIMIT32 - SYSBASE32,
	    &kvseg32);
	(void) segkmem_create(&kvseg32);

	/*
	 * Create a segment for the debugger.
	 */
	(void) seg_attach(&kas, kdi_segdebugbase, kdi_segdebugsize, &kdebugseg);
	(void) segkmem_create(&kdebugseg);

	rw_exit(&kas.a_lock);
}

char obp_tte_str[] =
	"h# %x constant MMU_PAGESHIFT "
	"h# %x constant TTE8K "
	"h# %x constant SFHME_SIZE "
	"h# %x constant SFHME_TTE "
	"h# %x constant HMEBLK_TAG "
	"h# %x constant HMEBLK_NEXT "
	"h# %x constant HMEBLK_MISC "
	"h# %x constant HMEBLK_HME1 "
	"h# %x constant NHMENTS "
	"h# %x constant HBLK_SZMASK "
	"h# %x constant HBLK_RANGE_SHIFT "
	"h# %x constant HMEBP_HBLK "
	"h# %x constant HMEBLK_ENDPA "
	"h# %x constant HMEBUCKET_SIZE "
	"h# %x constant HTAG_SFMMUPSZ "
	"h# %x constant HTAG_BSPAGE_SHIFT "
	"h# %x constant HTAG_REHASH_SHIFT "
	"h# %x constant SFMMU_INVALID_SHMERID "
	"h# %x constant mmu_hashcnt "
	"h# %p constant uhme_hash "
	"h# %p constant khme_hash "
	"h# %x constant UHMEHASH_SZ "
	"h# %x constant KHMEHASH_SZ "
	"h# %p constant KCONTEXT "
	"h# %p constant KHATID "
	"h# %x constant ASI_MEM "

	": PHYS-X@ ( phys -- data ) "
	"   ASI_MEM spacex@ "
	"; "

	": PHYS-W@ ( phys -- data ) "
	"   ASI_MEM spacew@ "
	"; "

	": PHYS-L@ ( phys -- data ) "
	"   ASI_MEM spaceL@ "
	"; "

	": TTE_PAGE_SHIFT ( ttesz -- hmeshift ) "
	"   3 * MMU_PAGESHIFT + "
	"; "

	": TTE_IS_VALID ( ttep -- flag ) "
	"   PHYS-X@ 0< "
	"; "

	": HME_HASH_SHIFT ( ttesz -- hmeshift ) "
	"   dup TTE8K =  if "
	"      drop HBLK_RANGE_SHIFT "
	"   else "
	"      TTE_PAGE_SHIFT "
	"   then "
	"; "

	": HME_HASH_BSPAGE ( addr hmeshift -- bspage ) "
	"   tuck >> swap MMU_PAGESHIFT - << "
	"; "

	": HME_HASH_FUNCTION ( sfmmup addr hmeshift -- hmebp ) "
	"   >> over xor swap                    ( hash sfmmup ) "
	"   KHATID <>  if                       ( hash ) "
	"      UHMEHASH_SZ and                  ( bucket ) "
	"      HMEBUCKET_SIZE * uhme_hash +     ( hmebp ) "
	"   else                                ( hash ) "
	"      KHMEHASH_SZ and                  ( bucket ) "
	"      HMEBUCKET_SIZE * khme_hash +     ( hmebp ) "
	"   then                                ( hmebp ) "
	"; "

	": HME_HASH_TABLE_SEARCH "
	"       ( sfmmup hmebp hblktag --  sfmmup null | sfmmup hmeblkp ) "
	"   >r hmebp_hblk + phys-x@ begin ( sfmmup hmeblkp ) ( r: hblktag ) "
	"      dup HMEBLK_ENDPA <> if     ( sfmmup hmeblkp ) ( r: hblktag ) "
	"         dup hmeblk_tag + phys-x@ r@ = if ( sfmmup hmeblkp )	  "
	"	     dup hmeblk_tag + 8 + phys-x@ 2 pick = if		  "
	"		  true 	( sfmmup hmeblkp true ) ( r: hblktag )	  "
	"	     else						  "
	"	     	  hmeblk_next + phys-x@ false 			  "
	"			( sfmmup hmeblkp false ) ( r: hblktag )   "
	"	     then  						  "
	"	  else							  "
	"	     hmeblk_next + phys-x@ false 			  "
	"			( sfmmup hmeblkp false ) ( r: hblktag )   "
	"	  then 							  "
	"      else							  "
	"         drop 0 true 						  "
	"      then  							  "
	"   until r> drop 						  "
	"; "

	": HME_HASH_TAG ( sfmmup rehash addr -- hblktag ) "
	"   over HME_HASH_SHIFT HME_HASH_BSPAGE  ( sfmmup rehash bspage ) "
	"   HTAG_BSPAGE_SHIFT <<		 ( sfmmup rehash htag-bspage )"
	"   swap HTAG_REHASH_SHIFT << or	 ( sfmmup htag-bspage-rehash )"
	"   SFMMU_INVALID_SHMERID or nip	 ( hblktag ) "
	"; "

	": HBLK_TO_TTEP ( hmeblkp addr -- ttep ) "
	"   over HMEBLK_MISC + PHYS-L@ HBLK_SZMASK and  ( hmeblkp addr ttesz ) "
	"   TTE8K =  if                            ( hmeblkp addr ) "
	"      MMU_PAGESHIFT >> NHMENTS 1- and     ( hmeblkp hme-index ) "
	"   else                                   ( hmeblkp addr ) "
	"      drop 0                              ( hmeblkp 0 ) "
	"   then                                   ( hmeblkp hme-index ) "
	"   SFHME_SIZE * + HMEBLK_HME1 +           ( hmep ) "
	"   SFHME_TTE +                            ( ttep ) "
	"; "

	": unix-tte ( addr cnum -- false | tte-data true ) "
	"    KCONTEXT = if                   ( addr ) "
	"	KHATID                       ( addr khatid ) "
	"    else                            ( addr ) "
	"       drop false exit              ( false ) "
	"    then "
	"      ( addr khatid ) "
	"      mmu_hashcnt 1+ 1  do           ( addr sfmmup ) "
	"         2dup swap i HME_HASH_SHIFT  "
					"( addr sfmmup sfmmup addr hmeshift ) "
	"         HME_HASH_FUNCTION           ( addr sfmmup hmebp ) "
	"         over i 4 pick               "
				"( addr sfmmup hmebp sfmmup rehash addr ) "
	"         HME_HASH_TAG                ( addr sfmmup hmebp hblktag ) "
	"         HME_HASH_TABLE_SEARCH       "
					"( addr sfmmup { null | hmeblkp } ) "
	"         ?dup  if                    ( addr sfmmup hmeblkp ) "
	"            nip swap HBLK_TO_TTEP    ( ttep ) "
	"            dup TTE_IS_VALID  if     ( valid-ttep ) "
	"               PHYS-X@ true          ( tte-data true ) "
	"            else                     ( invalid-tte ) "
	"               drop false            ( false ) "
	"            then                     ( false | tte-data true ) "
	"            unloop exit              ( false | tte-data true ) "
	"         then                        ( addr sfmmup ) "
	"      loop                           ( addr sfmmup ) "
	"      2drop false                    ( false ) "
	"; "
;

void
create_va_to_tte(void)
{
	char *bp;
	extern int khmehash_num, uhmehash_num;
	extern struct hmehash_bucket *khme_hash, *uhme_hash;

#define	OFFSET(type, field)	((uintptr_t)(&((type *)0)->field))

	bp = (char *)kobj_zalloc(MMU_PAGESIZE, KM_SLEEP);

	/*
	 * Teach obp how to parse our sw ttes.
	 */
	(void) sprintf(bp, obp_tte_str,
	    MMU_PAGESHIFT,
	    TTE8K,
	    sizeof (struct sf_hment),
	    OFFSET(struct sf_hment, hme_tte),
	    OFFSET(struct hme_blk, hblk_tag),
	    OFFSET(struct hme_blk, hblk_nextpa),
	    OFFSET(struct hme_blk, hblk_misc),
	    OFFSET(struct hme_blk, hblk_hme),
	    NHMENTS,
	    HBLK_SZMASK,
	    HBLK_RANGE_SHIFT,
	    OFFSET(struct hmehash_bucket, hmeh_nextpa),
	    HMEBLK_ENDPA,
	    sizeof (struct hmehash_bucket),
	    HTAG_SFMMUPSZ,
	    HTAG_BSPAGE_SHIFT,
	    HTAG_REHASH_SHIFT,
	    SFMMU_INVALID_SHMERID,
	    mmu_hashcnt,
	    (caddr_t)va_to_pa((caddr_t)uhme_hash),
	    (caddr_t)va_to_pa((caddr_t)khme_hash),
	    UHMEHASH_SZ,
	    KHMEHASH_SZ,
	    KCONTEXT,
	    KHATID,
	    ASI_MEM);
	prom_interpret(bp, 0, 0, 0, 0, 0);

	kobj_free(bp, MMU_PAGESIZE);
}

void
install_va_to_tte(void)
{
	/*
	 * advise prom that it can use unix-tte
	 */
	prom_interpret("' unix-tte is va>tte-data", 0, 0, 0, 0, 0);
}

/*
 * Here we add "device-type=console" for /os-io node, for currently
 * our kernel console output only supports displaying text and
 * performing cursor-positioning operations (through kernel framebuffer
 * driver) and it doesn't support other functionalities required for a
 * standard "display" device as specified in 1275 spec. The main missing
 * interface defined by the 1275 spec is "draw-logo".
 * also see the comments above prom_stdout_is_framebuffer().
 */
static char *create_node =
	"\" /\" find-device "
	"new-device "
	"\" os-io\" device-name "
	"\" "OBP_DISPLAY_CONSOLE"\" device-type "
	": cb-r/w  ( adr,len method$ -- #read/#written ) "
	"   2>r swap 2 2r> ['] $callback  catch  if "
	"      2drop 3drop 0 "
	"   then "
	"; "
	": read ( adr,len -- #read ) "
	"       \" read\" ['] cb-r/w catch  if  2drop 2drop -2 exit then "
	"       ( retN ... ret1 N ) "
	"       ?dup  if "
	"               swap >r 1-  0  ?do  drop  loop  r> "
	"       else "
	"               -2 "
	"       then "
	";    "
	": write ( adr,len -- #written ) "
	"       \" write\" ['] cb-r/w catch  if  2drop 2drop 0 exit  then "
	"       ( retN ... ret1 N ) "
	"       ?dup  if "
	"               swap >r 1-  0  ?do  drop  loop  r> "
	"        else "
	"               0 "
	"       then "
	"; "
	": poll-tty ( -- ) ; "
	": install-abort  ( -- )  ['] poll-tty d# 10 alarm ; "
	": remove-abort ( -- )  ['] poll-tty 0 alarm ; "
	": cb-give/take ( $method -- ) "
	"       0 -rot ['] $callback catch  ?dup  if "
	"               >r 2drop 2drop r> throw "
	"       else "
	"               0  ?do  drop  loop "
	"       then "
	"; "
	": give ( -- )  \" exit-input\" cb-give/take ; "
	": take ( -- )  \" enter-input\" cb-give/take ; "
	": open ( -- ok? )  true ; "
	": close ( -- ) ; "
	"finish-device "
	"device-end ";

/*
 * Create the OBP input/output node (FCode serial driver).
 * It is needed for both USB console keyboard and for
 * the kernel terminal emulator.  It is too early to check for a
 * kernel console compatible framebuffer now, so we create this
 * so that we're ready if we need to enable kernel terminal emulation.
 *
 * When the USB software takes over the input device at the time
 * consconfig runs, OBP's stdin is redirected to this node.
 * Whenever the FORTH user interface is used after this switch,
 * the node will call back into the kernel for console input.
 * If a serial device such as ttya or a UART with a Type 5 keyboard
 * attached is used, OBP takes over the serial device when the system
 * goes to the debugger after the system is booted.  This sharing
 * of the relatively simple serial device is difficult but possible.
 * Sharing the USB host controller is impossible due its complexity.
 *
 * Similarly to USB keyboard input redirection, after consconfig_dacf
 * configures a kernel console framebuffer as the standard output
 * device, OBP's stdout is switched to to vector through the
 * /os-io node into the kernel terminal emulator.
 */
static void
startup_create_io_node(void)
{
	prom_interpret(create_node, 0, 0, 0, 0, 0);
}


static void
do_prom_version_check(void)
{
	int i;
	pnode_t node;
	char buf[64];
	static char drev[] = "Down-rev firmware detected%s\n"
	    "\tPlease upgrade to the following minimum version:\n"
	    "\t\t%s\n";

	i = prom_version_check(buf, sizeof (buf), &node);

	if (i == PROM_VER64_OK)
		return;

	if (i == PROM_VER64_UPGRADE) {
		cmn_err(CE_WARN, drev, "", buf);

#ifdef	DEBUG
		prom_enter_mon();	/* Type 'go' to continue */
		cmn_err(CE_WARN, "Booting with down-rev firmware\n");
		return;
#else
		halt(0);
#endif
	}

	/*
	 * The other possibility is that this is a server running
	 * good firmware, but down-rev firmware was detected on at
	 * least one other cpu board. We just complain if we see
	 * that.
	 */
	cmn_err(CE_WARN, drev, " on one or more CPU boards", buf);
}


/*
 * Must be defined in platform dependent code.
 */
extern caddr_t modtext;
extern size_t modtext_sz;
extern caddr_t moddata;

#define	HEAPTEXT_ARENA(addr)	\
	((uintptr_t)(addr) < KERNELBASE + 2 * MMU_PAGESIZE4M ? 0 : \
	(((uintptr_t)(addr) - HEAPTEXT_BASE) / \
	(HEAPTEXT_MAPPED + HEAPTEXT_UNMAPPED) + 1))

#define	HEAPTEXT_OVERSIZED(addr)	\
	((uintptr_t)(addr) >= HEAPTEXT_BASE + HEAPTEXT_SIZE - HEAPTEXT_OVERSIZE)

#define	HEAPTEXT_IN_NUCLEUSDATA(addr) \
	(((uintptr_t)(addr) >= KERNELBASE + 2 * MMU_PAGESIZE4M) && \
	((uintptr_t)(addr) < KERNELBASE + 3 * MMU_PAGESIZE4M))

vmem_t *texthole_source[HEAPTEXT_NARENAS];
vmem_t *texthole_arena[HEAPTEXT_NARENAS];
kmutex_t texthole_lock;

char kern_bootargs[OBP_MAXPATHLEN];
char kern_bootfile[OBP_MAXPATHLEN];

void
kobj_vmem_init(vmem_t **text_arena, vmem_t **data_arena)
{
	uintptr_t addr, limit;

	addr = HEAPTEXT_BASE;
	limit = addr + HEAPTEXT_SIZE - HEAPTEXT_OVERSIZE;

	/*
	 * Before we initialize the text_arena, we want to punch holes in the
	 * underlying heaptext_arena.  This guarantees that for any text
	 * address we can find a text hole less than HEAPTEXT_MAPPED away.
	 */
	for (; addr + HEAPTEXT_UNMAPPED <= limit;
	    addr += HEAPTEXT_MAPPED + HEAPTEXT_UNMAPPED) {
		(void) vmem_xalloc(heaptext_arena, HEAPTEXT_UNMAPPED, PAGESIZE,
		    0, 0, (void *)addr, (void *)(addr + HEAPTEXT_UNMAPPED),
		    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);
	}

	/*
	 * Allocate one page at the oversize to break up the text region
	 * from the oversized region.
	 */
	(void) vmem_xalloc(heaptext_arena, PAGESIZE, PAGESIZE, 0, 0,
	    (void *)limit, (void *)(limit + PAGESIZE),
	    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);

	*text_arena = vmem_create("module_text", modtext_sz ? modtext : NULL,
	    modtext_sz, sizeof (uintptr_t), segkmem_alloc, segkmem_free,
	    heaptext_arena, 0, VM_SLEEP);
	*data_arena = vmem_create("module_data", moddata, MODDATA, 1,
	    segkmem_alloc, segkmem_free, heap32_arena, 0, VM_SLEEP);
}

caddr_t
kobj_text_alloc(vmem_t *arena, size_t size)
{
	caddr_t rval, better;

	/*
	 * First, try a sleeping allocation.
	 */
	rval = vmem_alloc(arena, size, VM_SLEEP | VM_BESTFIT);

	if (size >= HEAPTEXT_MAPPED || !HEAPTEXT_OVERSIZED(rval))
		return (rval);

	/*
	 * We didn't get the area that we wanted.  We're going to try to do an
	 * allocation with explicit constraints.
	 */
	better = vmem_xalloc(arena, size, sizeof (uintptr_t), 0, 0, NULL,
	    (void *)(HEAPTEXT_BASE + HEAPTEXT_SIZE - HEAPTEXT_OVERSIZE),
	    VM_NOSLEEP | VM_BESTFIT);

	if (better != NULL) {
		/*
		 * That worked.  Free our first attempt and return.
		 */
		vmem_free(arena, rval, size);
		return (better);
	}

	/*
	 * That didn't work; we'll have to return our first attempt.
	 */
	return (rval);
}

caddr_t
kobj_texthole_alloc(caddr_t addr, size_t size)
{
	int arena = HEAPTEXT_ARENA(addr);
	char c[30];
	uintptr_t base;

	if (HEAPTEXT_OVERSIZED(addr) || HEAPTEXT_IN_NUCLEUSDATA(addr)) {
		/*
		 * If this is an oversized allocation or it is allocated in
		 * the nucleus data page, there is no text hole available for
		 * it; return NULL.
		 */
		return (NULL);
	}

	mutex_enter(&texthole_lock);

	if (texthole_arena[arena] == NULL) {
		ASSERT(texthole_source[arena] == NULL);

		if (arena == 0) {
			texthole_source[0] = vmem_create("module_text_holesrc",
			    (void *)(KERNELBASE + MMU_PAGESIZE4M),
			    MMU_PAGESIZE4M, PAGESIZE, NULL, NULL, NULL,
			    0, VM_SLEEP);
		} else {
			base = HEAPTEXT_BASE +
			    (arena - 1) * (HEAPTEXT_MAPPED + HEAPTEXT_UNMAPPED);

			(void) snprintf(c, sizeof (c),
			    "heaptext_holesrc_%d", arena);

			texthole_source[arena] = vmem_create(c, (void *)base,
			    HEAPTEXT_UNMAPPED, PAGESIZE, NULL, NULL, NULL,
			    0, VM_SLEEP);
		}

		(void) snprintf(c, sizeof (c), "heaptext_hole_%d", arena);

		texthole_arena[arena] = vmem_create(c, NULL, 0,
		    sizeof (uint32_t), segkmem_alloc_permanent, segkmem_free,
		    texthole_source[arena], 0, VM_SLEEP);
	}

	mutex_exit(&texthole_lock);

	ASSERT(texthole_arena[arena] != NULL);
	ASSERT(arena >= 0 && arena < HEAPTEXT_NARENAS);
	return (vmem_alloc(texthole_arena[arena], size,
	    VM_BESTFIT | VM_NOSLEEP));
}

void
kobj_texthole_free(caddr_t addr, size_t size)
{
	int arena = HEAPTEXT_ARENA(addr);

	ASSERT(arena >= 0 && arena < HEAPTEXT_NARENAS);
	ASSERT(texthole_arena[arena] != NULL);
	vmem_free(texthole_arena[arena], addr, size);
}

void
release_bootstrap(void)
{
	if (&cif_init)
		cif_init();
}
