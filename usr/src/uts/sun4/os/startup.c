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
#include <sys/intreg.h>
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
#include <sys/promif.h>
#include <sys/prom_debug.h>
#include <sys/traptrace.h>
#include <sys/memnode.h>
#include <sys/mem_cage.h>
#include <sys/mmu.h>

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
extern int size_pse_array(pgcnt_t, int);

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
uint_t segmap_percent = 12; /* Size of segmap segment */

int use_cache = 1;		/* cache not reliable (605 bugs) with MP */
int vac_copyback = 1;
char *cache_mode = NULL;
int use_mix = 1;
int prom_debug = 0;

struct bootops *bootops = 0;	/* passed in from boot in %o2 */
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
caddr_t		sdata;		/* beginning of data segment */

caddr_t		extra_etva;	/* beginning of unused nucleus text */
pgcnt_t		extra_etpg;	/* number of pages of unused nucleus text */

size_t	ndata_remain_sz;	/* bytes from end of data to 4MB boundary */
caddr_t	nalloc_base;		/* beginning of nucleus allocation */
caddr_t nalloc_end;		/* end of nucleus allocatable memory */
caddr_t valloc_base;		/* beginning of kvalloc segment	*/

caddr_t kmem64_base;		/* base of kernel mem segment in 64-bit space */
caddr_t kmem64_end;		/* end of kernel mem segment in 64-bit space */
caddr_t kmem64_aligned_end;	/* end of large page, overmaps 64-bit space */
int	kmem64_alignsize;	/* page size for mem segment in 64-bit space */
int	kmem64_szc;		/* page size code */
uint64_t kmem64_pabase = (uint64_t)-1;	/* physical address of kmem64_base */

uintptr_t shm_alignment;	/* VAC address consistency modulus */
struct memlist *phys_install;	/* Total installed physical memory */
struct memlist *phys_avail;	/* Available (unreserved) physical memory */
struct memlist *virt_avail;	/* Available (unmapped?) virtual memory */
struct memlist ndata;		/* memlist of nucleus allocatable memory */
int memexp_flag;		/* memory expansion card flag */
uint64_t ecache_flushaddr;	/* physical address used for flushing E$ */
pgcnt_t obp_pages;		/* Physical pages used by OBP */

/*
 * VM data structures
 */
long page_hashsz;		/* Size of page hash table (power of two) */
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

uintptr_t kpm_pp_base;		/* Base of system kpm_page array */
size_t	kpm_pp_sz;		/* Size of system kpm_page array */
pgcnt_t	kpm_npages;		/* How many kpm pages are managed */

struct seg *segkp = &kpseg;	/* Pageable kernel virtual memory segment */
struct seg *segkmap = &kmapseg;	/* Kernel generic mapping segment */
struct seg *segkpm = &kpmseg;	/* 64bit kernel physical mapping segment */

int segzio_fromheap = 0;	/* zio allocations occur from heap */
caddr_t segzio_base;		/* Base address of segzio */
pgcnt_t segziosize = 0;		/* size of zio segment in pages */

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

struct memseg *memseg_base;
size_t memseg_sz;		/* Used to translate a va to page */
struct vnode unused_pages_vp;

/*
 * VM data structures allocated early during boot.
 */
size_t pagehash_sz;
uint64_t memlist_sz;

char tbr_wr_addr_inited = 0;


/*
 * Static Routines:
 */
static void memlist_add(uint64_t, uint64_t, struct memlist **,
	struct memlist **);
static void kphysm_init(page_t *, struct memseg *, pgcnt_t, uintptr_t,
	pgcnt_t);
static void kvm_init(void);

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
static void kpm_init(void);
static void kpm_npages_setup(int);
static void kpm_memseg_init(void);

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
		    (uint32_t)(list->address >> 32), (uint32_t)list->address,
		    (uint32_t)(list->size >> 32), (uint32_t)(list->size));
		list = list->next;
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

/* Simple message to indicate that the bootops pointer has been zeroed */
#ifdef DEBUG
static int bootops_gone_on = 0;
#define	BOOTOPS_GONE() \
	if (bootops_gone_on) \
		prom_printf("The bootops vec is zeroed now!\n");
#else
#define	BOOTOPS_GONE()
#endif /* DEBUG */

/*
 * Monitor pages may not be where this says they are.
 * and the debugger may not be there either.
 *
 * Note that 'pages' here are *physical* pages, which are 8k on sun4u.
 *
 *                        Physical memory layout
 *                     (not necessarily contiguous)
 *                       (THIS IS SOMEWHAT WRONG)
 *                       /-----------------------\
 *                       |       monitor pages   |
 *             availmem -|-----------------------|
 *                       |                       |
 *                       |       page pool       |
 *                       |                       |
 *                       |-----------------------|
 *                       |   configured tables   |
 *                       |       buffers         |
 *            firstaddr -|-----------------------|
 *                       |   hat data structures |
 *                       |-----------------------|
 *                       |    kernel data, bss   |
 *                       |-----------------------|
 *                       |    interrupt stack    |
 *                       |-----------------------|
 *                       |    kernel text (RO)   |
 *                       |-----------------------|
 *                       |    trap table (4k)    |
 *                       |-----------------------|
 *               page 1  |      panicbuf         |
 *                       |-----------------------|
 *               page 0  |       reclaimed       |
 *                       |_______________________|
 *
 *
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
 * 0x00000000.78002000  -|-----------------------|
 *                       |     panicbuf          |
 * 0x00000000.78000000  -|-----------------------|- SYSBASE32
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
 *  0x00000000.00100000 -|-----------------------|-
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

	(void) check_boot_version(BOP_GETVERSION(bootops));

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

static u_longlong_t *boot_physinstalled, *boot_physavail, *boot_virtavail;
static size_t boot_physinstalled_len, boot_physavail_len, boot_virtavail_len;

#define	IVSIZE	((MAXIVNUM * sizeof (intr_vec_t *)) + \
		(MAX_RSVD_IV * sizeof (intr_vec_t)) + \
		(MAX_RSVD_IVX * sizeof (intr_vecx_t)))

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
	"h# %lx constant kmem64_base "
	"h# %lx constant kmem64_end "
	"h# %lx constant kmem64_pagemask "
	"h# %lx constant kmem64_template "

	": kmem64-tte ( addr cnum -- false | tte-data true ) "
	"    if                                       ( addr ) "
	"       drop false exit then                  ( false ) "
	"    dup  kmem64_base kmem64_end  within  if  ( addr ) "
	"	kmem64_pagemask and                   ( addr' ) "
	"	kmem64_base -                         ( addr' ) "
	"	kmem64_template +                     ( tte ) "
	"	true                                  ( tte true ) "
	"    else                                     ( addr ) "
	"	pgmap@                                ( tte ) "
	"       dup 0< if true else drop false then   ( tte true  |  false ) "
	"    then                                     ( tte true  |  false ) "
	"; "

	"' kmem64-tte is va>tte-data "
;

void
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

pgcnt_t	tune_npages = (pgcnt_t)
	(MB_TO_BYTES(MINMOVE_RAM_MB)/ (size_t)MMU_PAGESIZE);

#pragma weak page_set_colorequiv_arr_cpu
extern void page_set_colorequiv_arr_cpu(void);

static void
startup_memlist(void)
{
	size_t alloc_sz;
	size_t ctrs_sz;
	caddr_t alloc_base;
	caddr_t ctrs_base, ctrs_end;
	caddr_t memspace;
	caddr_t va;
	int memblocks = 0;
	struct memlist *cur;
	size_t syslimit = (size_t)SYSLIMIT;
	size_t sysbase = (size_t)SYSBASE;
	int alloc_alignsize = ecache_alignsize;
	int i;
	extern void page_coloring_init(void);
	extern void page_set_colorequiv_arr(void);

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
	 * 256K is carved out for module data.
	 */

	nalloc_base = (caddr_t)roundup((uintptr_t)e_data, MMU_PAGESIZE);
	moddata = nalloc_base;
	e_moddata = nalloc_base + MODDATA;
	nalloc_base = e_moddata;

	nalloc_end = (caddr_t)roundup((uintptr_t)nalloc_base, MMU_PAGESIZE4M);
	valloc_base = nalloc_base;

	/*
	 * Calculate the start of the data segment.
	 */
	sdata = (caddr_t)((uintptr_t)e_data & MMU_PAGEMASK4M);

	PRM_DEBUG(moddata);
	PRM_DEBUG(nalloc_base);
	PRM_DEBUG(nalloc_end);
	PRM_DEBUG(sdata);

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
	 * Get the list of physically available memory to size
	 * the number of page structures needed.
	 */
	size_physavail(boot_physavail, boot_physavail_len, &npages, &memblocks);
	/*
	 * This first snap shot of npages can represent the pages used
	 * by OBP's text and data approximately. This is used in the
	 * the calculation of the kernel size
	 */
	obp_pages = physinstalled - npages;


	/*
	 * On small-memory systems (<MODTEXT_SM_SIZE MB, currently 256MB), the
	 * in-nucleus module text is capped to MODTEXT_SM_CAP bytes (currently
	 * 2MB) and any excess pages are put on physavail.  The assumption is
	 * that small-memory systems will need more pages more than they'll
	 * need efficiently-mapped module texts.
	 */
	if ((physinstalled < mmu_btop(MODTEXT_SM_SIZE << 20)) &&
	    modtext_sz > MODTEXT_SM_CAP) {
		extra_etpg = mmu_btop(modtext_sz - MODTEXT_SM_CAP);
		modtext_sz = MODTEXT_SM_CAP;
		extra_etva = modtext + modtext_sz;
	}

	PRM_DEBUG(extra_etpg);
	PRM_DEBUG(modtext_sz);
	PRM_DEBUG(extra_etva);

	/*
	 * Account for any pages after e_text and e_data.
	 */
	npages += extra_etpg;
	npages += mmu_btopr(nalloc_end - nalloc_base);
	PRM_DEBUG(npages);

	/*
	 * npages is the maximum of available physical memory possible.
	 * (ie. it will never be more than this)
	 */

	/*
	 * initialize the nucleus memory allocator.
	 */
	ndata_alloc_init(&ndata, (uintptr_t)nalloc_base, (uintptr_t)nalloc_end);

	/*
	 * Allocate mmu fault status area from the nucleus data area.
	 */
	if ((&ndata_alloc_mmfsa != NULL) && (ndata_alloc_mmfsa(&ndata) != 0))
		cmn_err(CE_PANIC, "no more nucleus memory after mfsa alloc");

	/*
	 * Allocate kernel TSBs from the nucleus data area.
	 */
	if (ndata_alloc_tsbs(&ndata, npages) != 0)
		cmn_err(CE_PANIC, "no more nucleus memory after tsbs alloc");

	/*
	 * Allocate dmv dispatch table from the nucleus data area.
	 */
	if (ndata_alloc_dmv(&ndata) != 0)
		cmn_err(CE_PANIC, "no more nucleus memory after dmv alloc");


	page_coloring_init();

	/*
	 * Allocate page_freelists bin headers for memnode 0 from the
	 * nucleus data area.
	 */
	if (ndata_alloc_page_freelists(&ndata, 0) != 0)
		cmn_err(CE_PANIC,
		    "no more nucleus memory after page free lists alloc");

	if (kpm_enable) {
		kpm_init();
		/*
		 * kpm page space -- Update kpm_npages and make the
		 * same assumption about fragmenting as it is done
		 * for memseg_sz.
		 */
		kpm_npages_setup(memblocks + 4);
	}

	/*
	 * Allocate hat related structs from the nucleus data area.
	 */
	if (ndata_alloc_hat(&ndata, npages, kpm_npages) != 0)
		cmn_err(CE_PANIC, "no more nucleus memory after hat alloc");

	/*
	 * We want to do the BOP_ALLOCs before the real allocation of page
	 * structs in order to not have to allocate page structs for this
	 * memory.  We need to calculate a virtual address because we want
	 * the page structs to come before other allocations in virtual address
	 * space.  This is so some (if not all) of page structs can actually
	 * live in the nucleus.
	 */

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
	alloc_base = sfmmu_ktsb_alloc(alloc_base);
	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base, ecache_alignsize);
	PRM_DEBUG(alloc_base);

	/*
	 * Allocate IOMMU TSB array.  We do this here so that the physical
	 * memory gets deducted from the PROM's physical memory list.
	 */
	alloc_base = iommu_tsb_init(alloc_base);
	alloc_base = (caddr_t)roundup((uintptr_t)alloc_base,
	    ecache_alignsize);
	PRM_DEBUG(alloc_base);

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

	/*
	 * To avoid memory allocation collisions in the 32-bit virtual address
	 * space, make allocations from this point forward in 64-bit virtual
	 * address space starting at syslimit and working up.
	 *
	 * All this is needed because on large memory systems, the default
	 * Solaris allocations will collide with SYSBASE32, which is hard
	 * coded to be at the virtual address 0x78000000.  Therefore, on 64-bit
	 * kernels, move the allocations to a location in the 64-bit virtual
	 * address space space, allowing those structures to grow without
	 * worry.
	 *
	 * On current CPUs we'll run out of physical memory address bits before
	 * we need to worry about the allocations running into anything else in
	 * VM or the virtual address holes on US-I and II, as there's currently
	 * about 1 TB of addressable space before the US-I/II VA hole.
	 */
	kmem64_base = (caddr_t)syslimit;
	PRM_DEBUG(kmem64_base);

	/*
	 * Allocate addresses, but not physical memory. None of these locations
	 * can be touched until physical memory is allocated below.
	 */
	alloc_base = kmem64_base;

	/*
	 * If KHME and/or UHME hash buckets won't fit in the nucleus, allocate
	 * them here.
	 */
	if (khme_hash == NULL || uhme_hash == NULL) {
		/*
		 * alloc_hme_buckets() will align alloc_base properly before
		 * assigning the hash buckets, so we don't need to do it
		 * before the call...
		 */
		alloc_base = alloc_hme_buckets(alloc_base, alloc_alignsize);

		PRM_DEBUG(alloc_base);
		PRM_DEBUG(khme_hash);
		PRM_DEBUG(uhme_hash);
	}

	/*
	 * Allow for an early allocation of physically contiguous memory.
	 */
	alloc_base = contig_mem_prealloc(alloc_base, npages);

	/*
	 * Allocate the remaining page freelists.  NUMA systems can
	 * have lots of page freelists, one per node, which quickly
	 * outgrow the amount of nucleus memory available.
	 */
	if (max_mem_nodes > 1) {
		int mnode;

		for (mnode = 1; mnode < max_mem_nodes; mnode++) {
			alloc_base = alloc_page_freelists(mnode, alloc_base,
			    ecache_alignsize);
		}
		PRM_DEBUG(alloc_base);
	}

	if (!mml_table) {
		size_t mmltable_sz;

		/*
		 * We need to allocate the mml_table here because there
		 * was not enough space within the nucleus.
		 */
		mmltable_sz = sizeof (kmutex_t) * mml_table_sz;
		alloc_sz = roundup(mmltable_sz, alloc_alignsize);
		alloc_base = (caddr_t)roundup((uintptr_t)alloc_base,
		    alloc_alignsize);
		mml_table = (kmutex_t *)alloc_base;
		alloc_base += alloc_sz;
		PRM_DEBUG(mml_table);
		PRM_DEBUG(alloc_base);
	}

	if (kpm_enable && !(kpmp_table || kpmp_stable)) {
		size_t kpmptable_sz;
		caddr_t table;

		/*
		 * We need to allocate either kpmp_table or kpmp_stable here
		 * because there was not enough space within the nucleus.
		 */
		kpmptable_sz = (kpm_smallpages == 0) ?
		    sizeof (kpm_hlk_t) * kpmp_table_sz :
		    sizeof (kpm_shlk_t) * kpmp_stable_sz;

		alloc_sz = roundup(kpmptable_sz, alloc_alignsize);
		alloc_base = (caddr_t)roundup((uintptr_t)alloc_base,
		    alloc_alignsize);

		table = alloc_base;

		if (kpm_smallpages == 0) {
			kpmp_table = (kpm_hlk_t *)table;
			PRM_DEBUG(kpmp_table);
		} else {
			kpmp_stable = (kpm_shlk_t *)table;
			PRM_DEBUG(kpmp_stable);
		}

		alloc_base += alloc_sz;
		PRM_DEBUG(alloc_base);
	}

	if (&ecache_init_scrub_flush_area) {
		/*
		 * Pass alloc_base directly, as the routine itself is
		 * responsible for any special alignment requirements...
		 */
		alloc_base = ecache_init_scrub_flush_area(alloc_base);
		PRM_DEBUG(alloc_base);
	}

	/*
	 * Take the most current snapshot we can by calling mem-update.
	 */
	copy_boot_memlists(&boot_physinstalled, &boot_physinstalled_len,
	    &boot_physavail, &boot_physavail_len,
	    &boot_virtavail, &boot_virtavail_len);

	/*
	 * Reset npages and memblocks based on boot_physavail list.
	 */
	size_physavail(boot_physavail, boot_physavail_len, &npages, &memblocks);
	PRM_DEBUG(npages);

	/*
	 * Account for extra memory after e_text.
	 */
	npages += extra_etpg;

	/*
	 * Calculate the largest free memory chunk in the nucleus data area.
	 * We need to figure out if page structs can fit in there or not.
	 * We also make sure enough page structs get created for any physical
	 * memory we might be returning to the system.
	 */
	ndata_remain_sz = ndata_maxsize(&ndata);
	PRM_DEBUG(ndata_remain_sz);

	pp_sz = sizeof (struct page) * npages;

	/*
	 * Here's a nice bit of code based on somewhat recursive logic:
	 *
	 * If the page array would fit within the nucleus, we want to
	 * add npages to cover any extra memory we may be returning back
	 * to the system.
	 *
	 * HOWEVER, the page array is sized by calculating the size of
	 * (struct page * npages), as are the pagehash table, ctrs and
	 * memseg_list, so the very act of performing the calculation below may
	 * in fact make the array large enough that it no longer fits in the
	 * nucleus, meaning there would now be a much larger area of the
	 * nucleus free that should really be added to npages, which would
	 * make the page array that much larger, and so on.
	 *
	 * This also ignores the memory possibly used in the nucleus for the
	 * the page hash, ctrs and memseg list and the fact that whether they
	 * fit there or not varies with the npages calculation below, but we
	 * don't even factor them into the equation at this point; perhaps we
	 * should or perhaps we should just take the approach that the few
	 * extra pages we could add via this calculation REALLY aren't worth
	 * the hassle...
	 */
	if (ndata_remain_sz > pp_sz) {
		size_t spare = ndata_spare(&ndata, pp_sz, ecache_alignsize);

		npages += mmu_btop(spare);

		pp_sz = npages * sizeof (struct page);

		pp_base = ndata_alloc(&ndata, pp_sz, ecache_alignsize);
	}

	/*
	 * If physmem is patched to be non-zero, use it instead of
	 * the monitor value unless physmem is larger than the total
	 * amount of memory on hand.
	 */
	if (physmem == 0 || physmem > npages)
		physmem = npages;

	/*
	 * If pp_base is NULL that means the routines above have determined
	 * the page array will not fit in the nucleus; we'll have to
	 * BOP_ALLOC() ourselves some space for them.
	 */
	if (pp_base == NULL) {
		alloc_base = (caddr_t)roundup((uintptr_t)alloc_base,
		    alloc_alignsize);
		alloc_sz = roundup(pp_sz, alloc_alignsize);

		pp_base = (struct page *)alloc_base;

		alloc_base += alloc_sz;
	}

	/*
	 * The page structure hash table size is a power of 2
	 * such that the average hash chain length is PAGE_HASHAVELEN.
	 */
	page_hashsz = npages / PAGE_HASHAVELEN;
	page_hashsz = 1 << highbit((ulong_t)page_hashsz);
	pagehash_sz = sizeof (struct page *) * page_hashsz;

	/*
	 * We want to TRY to fit the page structure hash table,
	 * the page size free list counters, the memseg list and
	 * and the kpm page space in the nucleus if possible.
	 *
	 * alloc_sz counts how much memory needs to be allocated by
	 * BOP_ALLOC().
	 */
	page_hash = ndata_alloc(&ndata, pagehash_sz, ecache_alignsize);

	alloc_sz = (page_hash == NULL ? pagehash_sz : 0);

	/*
	 * Size up per page size free list counters.
	 */
	ctrs_sz = page_ctrs_sz();
	ctrs_base = ndata_alloc(&ndata, ctrs_sz, ecache_alignsize);

	if (ctrs_base == NULL)
		alloc_sz = roundup(alloc_sz, ecache_alignsize) + ctrs_sz;

	/*
	 * The memseg list is for the chunks of physical memory that
	 * will be managed by the vm system.  The number calculated is
	 * a guess as boot may fragment it more when memory allocations
	 * are made before kphysm_init().  Currently, there are two
	 * allocations before then, so we assume each causes fragmen-
	 * tation, and add a couple more for good measure.
	 */
	memseg_sz = sizeof (struct memseg) * (memblocks + 4);
	memseg_base = ndata_alloc(&ndata, memseg_sz, ecache_alignsize);

	if (memseg_base == NULL)
		alloc_sz = roundup(alloc_sz, ecache_alignsize) + memseg_sz;


	if (kpm_enable) {
		/*
		 * kpm page space -- Update kpm_npages and make the
		 * same assumption about fragmenting as it is done
		 * for memseg_sz above.
		 */
		kpm_npages_setup(memblocks + 4);
		kpm_pp_sz = (kpm_smallpages == 0) ?
		    kpm_npages * sizeof (kpm_page_t):
		    kpm_npages * sizeof (kpm_spage_t);

		kpm_pp_base = (uintptr_t)ndata_alloc(&ndata, kpm_pp_sz,
		    ecache_alignsize);

		if (kpm_pp_base == NULL)
			alloc_sz = roundup(alloc_sz, ecache_alignsize) +
			    kpm_pp_sz;
	}

	/*
	 * Allocate the array that protects pp->p_selock.
	 */
	pse_shift = size_pse_array(physmem, max_ncpus);
	pse_table_size = 1 << pse_shift;
	pse_mutex = ndata_alloc(&ndata, pse_table_size * sizeof (pad_mutex_t),
	    ecache_alignsize);
	if (pse_mutex == NULL)
		alloc_sz = roundup(alloc_sz, ecache_alignsize) +
		    pse_table_size * sizeof (pad_mutex_t);

	if (alloc_sz > 0) {
		uintptr_t bop_base;

		/*
		 * We need extra memory allocated through BOP_ALLOC.
		 */
		alloc_base = (caddr_t)roundup((uintptr_t)alloc_base,
		    alloc_alignsize);

		alloc_sz = roundup(alloc_sz, alloc_alignsize);

		bop_base = (uintptr_t)alloc_base;

		alloc_base += alloc_sz;

		if (page_hash == NULL) {
			page_hash = (struct page **)bop_base;
			bop_base = roundup(bop_base + pagehash_sz,
			    ecache_alignsize);
		}

		if (ctrs_base == NULL) {
			ctrs_base = (caddr_t)bop_base;
			bop_base = roundup(bop_base + ctrs_sz,
			    ecache_alignsize);
		}

		if (memseg_base == NULL) {
			memseg_base = (struct memseg *)bop_base;
			bop_base = roundup(bop_base + memseg_sz,
			    ecache_alignsize);
		}

		if (kpm_enable && kpm_pp_base == NULL) {
			kpm_pp_base = (uintptr_t)bop_base;
			bop_base = roundup(bop_base + kpm_pp_sz,
			    ecache_alignsize);
		}

		if (pse_mutex == NULL) {
			pse_mutex = (pad_mutex_t *)bop_base;
			bop_base = roundup(bop_base +
			    pse_table_size * sizeof (pad_mutex_t),
			    ecache_alignsize);
		}

		ASSERT(bop_base <= (uintptr_t)alloc_base);
	}

	PRM_DEBUG(page_hash);
	PRM_DEBUG(memseg_base);
	PRM_DEBUG(kpm_pp_base);
	PRM_DEBUG(kpm_pp_sz);
	PRM_DEBUG(pp_base);
	PRM_DEBUG(pp_sz);
	PRM_DEBUG(alloc_base);

#ifdef	TRAPTRACE
	alloc_base = trap_trace_alloc(alloc_base);
	PRM_DEBUG(alloc_base);
#endif	/* TRAPTRACE */

	/*
	 * In theory it's possible that kmem64 chunk is 0 sized
	 * (on very small machines). Check for that.
	 */
	if (alloc_base == kmem64_base) {
		kmem64_base = NULL;
		kmem64_end = NULL;
		kmem64_aligned_end = NULL;
		goto kmem64_alloced;
	}

	/*
	 * Allocate kmem64 memory.
	 * Round up to end of large page and overmap.
	 * kmem64_end..kmem64_aligned_end is added to memory list for reuse
	 */
	kmem64_end = (caddr_t)roundup((uintptr_t)alloc_base,
	    MMU_PAGESIZE);

	/*
	 * Make one large memory alloc after figuring out the 64-bit size. This
	 * will enable use of the largest page size appropriate for the system
	 * architecture.
	 */
	ASSERT(mmu_exported_pagesize_mask & (1 << TTE8K));
	ASSERT(IS_P2ALIGNED(kmem64_base, TTEBYTES(max_bootlp_tteszc)));
	for (i = max_bootlp_tteszc; i >= TTE8K; i--) {
		size_t asize;
#if !defined(C_OBP)
		unsigned long long pa;
#endif	/* !C_OBP */

		if ((mmu_exported_pagesize_mask & (1 << i)) == 0)
			continue;
		kmem64_alignsize = TTEBYTES(i);
		kmem64_szc = i;

		/* limit page size for small memory */
		if (mmu_btop(kmem64_alignsize) > (npages >> 2))
			continue;

		kmem64_aligned_end = (caddr_t)roundup((uintptr_t)kmem64_end,
		    kmem64_alignsize);
		asize = kmem64_aligned_end - kmem64_base;
#if !defined(C_OBP)
		if (prom_allocate_phys(asize, kmem64_alignsize, &pa) == 0) {
			if (prom_claim_virt(asize, kmem64_base) !=
			    (caddr_t)-1) {
				kmem64_pabase = pa;
				install_kmem64_tte();
				break;
			} else {
				prom_free_phys(asize, pa);
			}
		}
#else	/* !C_OBP */
		if ((caddr_t)BOP_ALLOC(bootops, kmem64_base, asize,
		    kmem64_alignsize) == kmem64_base) {
			kmem64_pabase = va_to_pa(kmem64_base);
			break;
		}
#endif	/* !C_OBP */
		if (i == TTE8K) {
			prom_panic("kmem64 allocation failure");
		}
	}

	PRM_DEBUG(kmem64_base);
	PRM_DEBUG(kmem64_end);
	PRM_DEBUG(kmem64_aligned_end);
	PRM_DEBUG(kmem64_alignsize);

	/*
	 * Now set pa using saved va from above.
	 */
	if (&ecache_init_scrub_flush_area) {
		(void) ecache_init_scrub_flush_area(NULL);
	}

kmem64_alloced:

	/*
	 * Initialize per page size free list counters.
	 */
	ctrs_end = page_ctrs_alloc(ctrs_base);
	ASSERT(ctrs_base + ctrs_sz >= ctrs_end);

	/*
	 * Allocate space for the interrupt vector table and also for the
	 * reserved interrupt vector data structures.
	 */
	memspace = (caddr_t)BOP_ALLOC(bootops, (caddr_t)intr_vec_table,
	    IVSIZE, MMU_PAGESIZE);
	if (memspace != (caddr_t)intr_vec_table)
		prom_panic("interrupt vector table allocation failure");

	/*
	 * The memory lists from boot are allocated from the heap arena
	 * so that later they can be freed and/or reallocated.
	 */
	if (BOP_GETPROP(bootops, "extent", &memlist_sz) == -1)
		prom_panic("could not retrieve property \"extent\"");

	/*
	 * Between now and when we finish copying in the memory lists,
	 * allocations happen so the space gets fragmented and the
	 * lists longer.  Leave enough space for lists twice as long
	 * as what boot says it has now; roundup to a pagesize.
	 * Also add space for the final phys-avail copy in the fixup
	 * routine.
	 */
	va = (caddr_t)(sysbase + PAGESIZE + PANICBUFSIZE +
	    roundup(IVSIZE, MMU_PAGESIZE));
	memlist_sz *= 4;
	memlist_sz = roundup(memlist_sz, MMU_PAGESIZE);
	memspace = (caddr_t)BOP_ALLOC(bootops, va, memlist_sz, BO_NO_ALIGN);
	if (memspace == NULL)
		halt("Boot allocation failed.");

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
	 * Remove the space used by BOP_ALLOC from the kernel heap
	 * plus the area actually used by the OBP (if any)
	 * ignoring virtual addresses in virt_avail, above syslimit.
	 */
	virt_avail = memlist;
	copy_memlist(boot_virtavail, boot_virtavail_len, &memlist);

	for (cur = virt_avail; cur->next; cur = cur->next) {
		uint64_t range_base, range_size;

		if ((range_base = cur->address + cur->size) < (uint64_t)sysbase)
			continue;
		if (range_base >= (uint64_t)syslimit)
			break;
		/*
		 * Limit the range to end at syslimit.
		 */
		range_size = MIN(cur->next->address,
		    (uint64_t)syslimit) - range_base;
		(void) vmem_xalloc(heap_arena, (size_t)range_size, PAGESIZE,
		    0, 0, (void *)range_base, (void *)(range_base + range_size),
		    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);
	}

	phys_avail = memlist;
	(void) copy_physavail(boot_physavail, boot_physavail_len,
	    &memlist, 0, 0);

	/*
	 * Add any unused kmem64 memory from overmapped page
	 * (Note: va_to_pa does not work for kmem64_end)
	 */
	if (kmem64_end < kmem64_aligned_end) {
		uint64_t overlap_size = kmem64_aligned_end - kmem64_end;
		uint64_t overlap_pa = kmem64_pabase +
		    (kmem64_end - kmem64_base);

		PRM_DEBUG(overlap_pa);
		PRM_DEBUG(overlap_size);
		memlist_add(overlap_pa, overlap_size, &memlist, &phys_avail);
	}

	/*
	 * Add any extra memory after e_text to the phys_avail list, as long
	 * as there's at least a page to add.
	 */
	if (extra_etpg)
		memlist_add(va_to_pa(extra_etva), mmu_ptob(extra_etpg),
		    &memlist, &phys_avail);

	/*
	 * Add any extra memory at the end of the ndata region if there's at
	 * least a page to add.  There might be a few more pages available in
	 * the middle of the ndata region, but for now they are ignored.
	 */
	nalloc_base = ndata_extra_base(&ndata, MMU_PAGESIZE, nalloc_end);
	if (nalloc_base == NULL)
		nalloc_base = nalloc_end;
	ndata_remain_sz = nalloc_end - nalloc_base;

	if (ndata_remain_sz >= MMU_PAGESIZE)
		memlist_add(va_to_pa(nalloc_base),
		    (uint64_t)ndata_remain_sz, &memlist, &phys_avail);

	PRM_DEBUG(memlist);
	PRM_DEBUG(memlist_sz);
	PRM_DEBUG(memspace);

	if ((caddr_t)memlist > (memspace + memlist_sz))
		prom_panic("memlist overflow");

	PRM_DEBUG(pp_base);
	PRM_DEBUG(memseg_base);
	PRM_DEBUG(npages);

	/*
	 * Initialize the page structures from the memory lists.
	 */
	kphysm_init(pp_base, memseg_base, npages, kpm_pp_base, kpm_npages);

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
	 * Reserve space for panicbuf, intr_vec_table and reserved interrupt
	 * vector data structures from the 32-bit heap.
	 */
	(void) vmem_xalloc(heap32_arena, PANICBUFSIZE, PAGESIZE, 0, 0,
	    panicbuf, panicbuf + PANICBUFSIZE,
	    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);

	(void) vmem_xalloc(heap32_arena, IVSIZE, PAGESIZE, 0, 0,
	    intr_vec_table, (caddr_t)intr_vec_table + IVSIZE,
	    VM_NOSLEEP | VM_BESTFIT | VM_PANIC);

	mem_config_init();
}

static void
startup_modules(void)
{
	int proplen, nhblk1, nhblk8;
	size_t  nhblksz;
	pgcnt_t pages_per_hblk;
	size_t hme8blk_sz, hme1blk_sz;

	/*
	 * Log any optional messages from the boot program
	 */
	proplen = (size_t)BOP_GETPROPLEN(bootops, "boot-message");
	if (proplen > 0) {
		char *msg;
		size_t len = (size_t)proplen;

		msg = kmem_zalloc(len, KM_SLEEP);
		(void) BOP_GETPROP(bootops, "boot-message", msg);
		cmn_err(CE_CONT, "?%s\n", msg);
		kmem_free(msg, len);
	}

	/*
	 * Let the platforms have a chance to change default
	 * values before reading system file.
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
	extern int bop_io_quiesced;

	/*
	 * Destroy the MD initialized at startup
	 * The startup initializes the MD framework
	 * using prom and BOP alloc free it now.
	 */
	mach_descrip_startup_fini();

	/*
	 * Call back into boot and release boots resources.
	 */
	BOP_QUIESCE_IO(bootops);
	bop_io_quiesced = 1;

	copy_boot_memlists(&boot_physinstalled, &boot_physinstalled_len,
	    &boot_physavail, &boot_physavail_len,
	    &boot_virtavail, &boot_virtavail_len);
	/*
	 * Copy physinstalled list into kernel space.
	 */
	phys_install = memlist;
	copy_memlist(boot_physinstalled, boot_physinstalled_len, &memlist);

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

	/*
	 * Last chance to ask our booter questions ..
	 */
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
	(void) copy_physavail(boot_physavail, boot_physavail_len,
	    &memlist, 0, 0);

	/*
	 * Add any unused kmem64 memory from overmapped page
	 * (Note: va_to_pa does not work for kmem64_end)
	 */
	if (kmem64_overmap_size) {
		memlist_add(kmem64_pabase + (kmem64_end - kmem64_base),
		    kmem64_overmap_size,
		    &memlist, &cur);
	}

	/*
	 * Add any extra memory after e_text we added to the phys_avail list
	 * back to the old list.
	 */
	if (extra_etpg)
		memlist_add(va_to_pa(extra_etva), mmu_ptob(extra_etpg),
		    &memlist, &cur);
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
	fix_prom_pages(phys_avail, cur);

	ASSERT(phys_avail != NULL);
	memlist_free_list(phys_avail);
	phys_avail = cur;

	/*
	 * We're done with boot.  Just after this point in time, boot
	 * gets unmapped, so we can no longer rely on its services.
	 * Zero the bootops to indicate this fact.
	 */
	bootops = (struct bootops *)NULL;
	BOOTOPS_GONE();
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

	/*
	 * XXX4U: previously, we initialized and turned on
	 * the caches at this point. But of course we have
	 * nothing to do, as the prom has already done this
	 * for us -- main memory must be E$able at all times.
	 */

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
	if (physmem < npages) {
		pgcnt_t diff, off;
		struct page *pp;
		struct seg kseg;

		cmn_err(CE_WARN, "limiting physmem to %ld pages", physmem);

		off = 0;
		diff = npages - physmem;
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
		segzio_base = kpm_vbase + (kpm_size * vac_colors);
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

#ifdef	PTL1_PANIC_DEBUG
	init_ptl1_thread();
#endif	/* PTL1_PANIC_DEBUG */

	if (&cif_init)
		cif_init();
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
	struct memlist *new;

	new = *memlistp;
	new->address = start;
	new->size = len;
	*memlistp = new + 1;

	memlist_insert(new, curmemlistp);
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
 * kphysm_init() tackles the problem of initializing physical memory.
 * The old startup made some assumptions about the kernel living in
 * physically contiguous space which is no longer valid.
 */
static void
kphysm_init(page_t *pp, struct memseg *memsegp, pgcnt_t npages,
	uintptr_t kpm_pp, pgcnt_t kpm_npages)
{
	struct memlist	*pmem;
	struct memseg	*msp;
	pfn_t		 base;
	pgcnt_t		 num;
	pfn_t		 lastseg_pages_end = 0;
	pgcnt_t		 nelem_used = 0;

	ASSERT(page_hash != NULL && page_hashsz != 0);

	msp = memsegp;
	for (pmem = phys_avail; pmem && npages; pmem = pmem->next) {

		/*
		 * Build the memsegs entry
		 */
		num = btop(pmem->size);
		if (num > npages)
			num = npages;
		npages -= num;
		base = btop(pmem->address);

		msp->pages = pp;
		msp->epages = pp + num;
		msp->pages_base = base;
		msp->pages_end = base + num;

		if (kpm_enable) {
			pfn_t pbase_a;
			pfn_t pend_a;
			pfn_t prev_pend_a;
			pgcnt_t	nelem;

			msp->pagespa = va_to_pa(pp);
			msp->epagespa = va_to_pa(pp + num);
			pbase_a = kpmptop(ptokpmp(base));
			pend_a = kpmptop(ptokpmp(base + num - 1)) + kpmpnpgs;
			nelem = ptokpmp(pend_a - pbase_a);
			msp->kpm_nkpmpgs = nelem;
			msp->kpm_pbase = pbase_a;
			if (lastseg_pages_end) {
				/*
				 * Assume phys_avail is in ascending order
				 * of physical addresses.
				 */
				ASSERT(base + num > lastseg_pages_end);
				prev_pend_a = kpmptop(
				    ptokpmp(lastseg_pages_end - 1)) + kpmpnpgs;

				if (prev_pend_a > pbase_a) {
					/*
					 * Overlap, more than one memseg may
					 * point to the same kpm_page range.
					 */
					if (kpm_smallpages == 0) {
						msp->kpm_pages =
						    (kpm_page_t *)kpm_pp - 1;
						kpm_pp = (uintptr_t)
						    ((kpm_page_t *)kpm_pp
						    + nelem - 1);
					} else {
						msp->kpm_spages =
						    (kpm_spage_t *)kpm_pp - 1;
						kpm_pp = (uintptr_t)
						    ((kpm_spage_t *)kpm_pp
						    + nelem - 1);
					}
					nelem_used += nelem - 1;

				} else {
					if (kpm_smallpages == 0) {
						msp->kpm_pages =
						    (kpm_page_t *)kpm_pp;
						kpm_pp = (uintptr_t)
						    ((kpm_page_t *)kpm_pp
						    + nelem);
					} else {
						msp->kpm_spages =
						    (kpm_spage_t *)kpm_pp;
						kpm_pp = (uintptr_t)
						    ((kpm_spage_t *)
						    kpm_pp + nelem);
					}
					nelem_used += nelem;
				}

			} else {
				if (kpm_smallpages == 0) {
					msp->kpm_pages = (kpm_page_t *)kpm_pp;
					kpm_pp = (uintptr_t)
					    ((kpm_page_t *)kpm_pp + nelem);
				} else {
					msp->kpm_spages = (kpm_spage_t *)kpm_pp;
					kpm_pp = (uintptr_t)
					    ((kpm_spage_t *)kpm_pp + nelem);
				}
				nelem_used = nelem;
			}

			if (nelem_used > kpm_npages)
				panic("kphysm_init: kpm_pp overflow\n");

			msp->kpm_pagespa = va_to_pa(msp->kpm_pages);
			lastseg_pages_end = msp->pages_end;
		}

		memseg_list_add(msp);

		/*
		 * add_physmem() initializes the PSM part of the page
		 * struct by calling the PSM back with add_physmem_cb().
		 * In addition it coalesces pages into larger pages as
		 * it initializes them.
		 */
		add_physmem(pp, num, base);
		pp += num;
		msp++;
	}

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
	"      dup if   		( sfmmup hmeblkp ) ( r: hblktag ) "
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
	"         true 							  "
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
	 * advise prom that he can use unix-tte
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

static void
kpm_init()
{
	kpm_pgshft = (kpm_smallpages == 0) ? MMU_PAGESHIFT4M : MMU_PAGESHIFT;
	kpm_pgsz = 1ull << kpm_pgshft;
	kpm_pgoff = kpm_pgsz - 1;
	kpmp2pshft = kpm_pgshft - PAGESHIFT;
	kpmpnpgs = 1 << kpmp2pshft;
	ASSERT(((uintptr_t)kpm_vbase & (kpm_pgsz - 1)) == 0);
}

void
kpm_npages_setup(int memblocks)
{
	/*
	 * npages can be scattered in a maximum of 'memblocks'
	 */
	kpm_npages = ptokpmpr(npages) + memblocks;
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

vmem_t *texthole_source[HEAPTEXT_NARENAS];
vmem_t *texthole_arena[HEAPTEXT_NARENAS];
kmutex_t texthole_lock;

char kern_bootargs[OBP_MAXPATHLEN];

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

	if (HEAPTEXT_OVERSIZED(addr)) {
		/*
		 * If this is an oversized allocation, there is no text hole
		 * available for it; return NULL.
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
