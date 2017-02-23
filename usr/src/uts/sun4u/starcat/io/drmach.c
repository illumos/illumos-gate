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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <sys/note.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/dditypes.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/poll.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/disp.h>
#include <sys/processor.h>
#include <sys/cheetahregs.h>
#include <sys/cpuvar.h>
#include <sys/mem_config.h>
#include <sys/ddi_impldefs.h>
#include <sys/systm.h>
#include <sys/machsystm.h>
#include <sys/autoconf.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/x_call.h>
#include <sys/promif.h>
#include <sys/prom_plat.h>
#include <sys/membar.h>
#include <vm/seg_kmem.h>
#include <sys/mem_cage.h>
#include <sys/stack.h>
#include <sys/archsystm.h>
#include <vm/hat_sfmmu.h>
#include <sys/pte.h>
#include <sys/mmu.h>
#include <sys/cpu_module.h>
#include <sys/obpdefs.h>
#include <sys/mboxsc.h>
#include <sys/plat_ecc_dimm.h>

#include <sys/hotplug/hpctrl.h>		/* XXX should be included by schpc.h */
#include <sys/schpc.h>
#include <sys/pci.h>

#include <sys/starcat.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/drmach.h>
#include <sys/dr_util.h>
#include <sys/dr_mbx.h>
#include <sys/sc_gptwocfg.h>
#include <sys/iosramreg.h>
#include <sys/iosramio.h>
#include <sys/iosramvar.h>
#include <sys/axq.h>
#include <sys/post/scat_dcd.h>
#include <sys/kobj.h>
#include <sys/taskq.h>
#include <sys/cmp.h>
#include <sys/sbd_ioctl.h>

#include <sys/sysevent.h>
#include <sys/sysevent/dr.h>
#include <sys/sysevent/eventdefs.h>

#include <sys/pci/pcisch.h>
#include <sys/pci/pci_regs.h>

#include <sys/ontrap.h>

/* defined in ../ml/drmach.il.cpp */
extern void		bcopy32_il(uint64_t, uint64_t);
extern void		flush_ecache_il(int64_t physaddr, int size, int linesz);
extern void		flush_dcache_il(void);
extern void		flush_icache_il(void);
extern void		flush_pcache_il(void);

/* defined in ../ml/drmach_asm.s */
extern uint64_t		lddmcdecode(uint64_t physaddr);
extern uint64_t		lddsafconfig(void);

/* XXX here until provided by sys/dman.h */
extern int man_dr_attach(dev_info_t *);
extern int man_dr_detach(dev_info_t *);

#define	DRMACH_BNUM2EXP(bnum)		((bnum) >> 1)
#define	DRMACH_BNUM2SLOT(bnum)		((bnum) & 1)
#define	DRMACH_EXPSLOT2BNUM(exp, slot)	(((exp) << 1) + (slot))

#define	DRMACH_SLICE_MASK		0x1Full
#define	DRMACH_SLICE_TO_PA(s)		(((s) & DRMACH_SLICE_MASK) << 37)
#define	DRMACH_PA_TO_SLICE(a)		(((a) >> 37) & DRMACH_SLICE_MASK)

/*
 * DRMACH_MEM_SLICE_SIZE and DRMACH_MEM_USABLE_SLICE_SIZE define the
 * available address space and the usable address space for every slice.
 * There must be a distinction between the available and usable do to a
 * restriction imposed by CDC memory size.
 */

#define	DRMACH_MEM_SLICE_SIZE		(1ull << 37)	/* 128GB */
#define	DRMACH_MEM_USABLE_SLICE_SIZE	(1ull << 36)	/* 64GB */

#define	DRMACH_MC_NBANKS		4

#define	DRMACH_MC_ADDR(mp, bank)	((mp)->madr_pa + 16 + 8 * (bank))
#define	DRMACH_MC_ASI_ADDR(mp, bank)	(DRMACH_MC_ADDR(mp, bank) & 0xFF)

#define	DRMACH_EMU_ACT_STATUS_OFFSET	0x50
#define	DRMACH_EMU_ACT_STATUS_ADDR(mp)	\
	((mp)->madr_pa + DRMACH_EMU_ACT_STATUS_OFFSET)

/*
 * The Cheetah's Safari Configuration Register and the Schizo's
 * Safari Control/Status Register place the LPA base and bound fields in
 * same bit locations with in their register word. This source code takes
 * advantage of this by defining only one set of LPA encoding/decoding macros
 * which are shared by various Cheetah and Schizo drmach routines.
 */
#define	DRMACH_LPA_BASE_MASK		(0x3Full	<< 3)
#define	DRMACH_LPA_BND_MASK		(0x3Full	<< 9)

#define	DRMACH_LPA_BASE_TO_PA(scr)	(((scr) & DRMACH_LPA_BASE_MASK) << 34)
#define	DRMACH_LPA_BND_TO_PA(scr)	(((scr) & DRMACH_LPA_BND_MASK) << 28)
#define	DRMACH_PA_TO_LPA_BASE(pa)	(((pa) >> 34) & DRMACH_LPA_BASE_MASK)
#define	DRMACH_PA_TO_LPA_BND(pa)	(((pa) >> 28) & DRMACH_LPA_BND_MASK)

#define	DRMACH_L1_SET_LPA(b)		\
	(((b)->flags & DRMACH_NULL_PROC_LPA) == 0)

#define	DRMACH_CPU_SRAM_ADDR    	0x7fff0900000ull
#define	DRMACH_CPU_SRAM_SIZE    	0x20000ull

/*
 * Name properties for frequently accessed device nodes.
 */
#define	DRMACH_CPU_NAMEPROP		"cpu"
#define	DRMACH_CMP_NAMEPROP		"cmp"
#define	DRMACH_AXQ_NAMEPROP		"address-extender-queue"
#define	DRMACH_PCI_NAMEPROP		"pci"

/*
 * Maximum value of processor Safari Timeout Log (TOL) field of
 * Safari Config reg (7 secs).
 */
#define	DRMACH_SAF_TOL_MAX		7 * 1000000

/*
 * drmach_board_t flag definitions
 */
#define	DRMACH_NULL_PROC_LPA		0x1

typedef struct {
	uint32_t	reg_addr_hi;
	uint32_t	reg_addr_lo;
	uint32_t	reg_size_hi;
	uint32_t	reg_size_lo;
} drmach_reg_t;

typedef struct {
	struct drmach_node	*node;
	void			*data;
} drmach_node_walk_args_t;

typedef struct drmach_node {
	void		*here;

	pnode_t		 (*get_dnode)(struct drmach_node *node);
	int		 (*walk)(struct drmach_node *node, void *data,
				int (*cb)(drmach_node_walk_args_t *args));
	dev_info_t	*(*n_getdip)(struct drmach_node *node);
	int		 (*n_getproplen)(struct drmach_node *node, char *name,
				int *len);
	int		 (*n_getprop)(struct drmach_node *node, char *name,
				void *buf, int len);
	int		 (*get_parent)(struct drmach_node *node,
				struct drmach_node *pnode);
} drmach_node_t;

typedef struct {
	int		 min_index;
	int		 max_index;
	int		 arr_sz;
	drmachid_t	*arr;
} drmach_array_t;

typedef struct {
	void		*isa;

	void		 (*dispose)(drmachid_t);
	sbd_error_t	*(*release)(drmachid_t);
	sbd_error_t	*(*status)(drmachid_t, drmach_status_t *);

	char		 name[MAXNAMELEN];
} drmach_common_t;

struct drmach_board;
typedef struct drmach_board drmach_board_t;

typedef struct {
	drmach_common_t	 cm;
	const char	*type;
	drmach_board_t	*bp;
	drmach_node_t	*node;
	int		 portid;
	int		 unum;
	int		 busy;
	int		 powered;
} drmach_device_t;

typedef struct drmach_cpu {
	drmach_device_t	 dev;
	uint64_t	 scr_pa;
	processorid_t	 cpuid;
	int		 coreid;
} drmach_cpu_t;

typedef struct drmach_mem {
	drmach_device_t	 dev;
	struct drmach_mem *next;
	uint64_t	 nbytes;
	uint64_t	 madr_pa;
} drmach_mem_t;

typedef struct drmach_io {
	drmach_device_t	 dev;
	uint64_t	 scsr_pa; /* PA of Schizo Control/Status Register */
} drmach_io_t;

struct drmach_board {
	drmach_common_t	 cm;
	int		 bnum;
	int		 assigned;
	int		 powered;
	int		 connected;
	int		 empty;
	int		 cond;
	uint_t		 cpu_impl;
	uint_t		 flags;
	drmach_node_t	*tree;
	drmach_array_t	*devices;
	drmach_mem_t	*mem;
	uint64_t	 stardrb_offset;
	char		 type[BD_TYPELEN];
};

typedef struct {
	int		 flags;
	drmach_device_t	*dp;
	sbd_error_t	*err;
	dev_info_t	*fdip;
} drmach_config_args_t;

typedef struct {
	drmach_board_t	*obj;
	int		 ndevs;
	void		*a;
	sbd_error_t	*(*found)(void *a, const char *, int, drmachid_t);
	sbd_error_t	*err;
} drmach_board_cb_data_t;

typedef struct drmach_casmslot {
	int	valid;
	int	slice;
} drmach_casmslot_t;

typedef enum {
	DRMACH_CR_OK,
	DRMACH_CR_MC_IDLE_ERR,
	DRMACH_CR_IOPAUSE_ERR,
	DRMACH_CR_ONTRAP_ERR
} drmach_cr_err_t;

typedef struct {
	void		*isa;
	caddr_t		 data;
	drmach_mem_t	*s_mp;
	drmach_mem_t	*t_mp;
	struct memlist	*c_ml;
	uint64_t	 s_copybasepa;
	uint64_t	 t_copybasepa;
	drmach_cr_err_t	 ecode;
	void		*earg;
} drmach_copy_rename_t;

/*
 * The following global is read as a boolean value, non-zero is true.
 * If zero, DR copy-rename and cpu poweron will not set the processor
 * LPA settings (CBASE, CBND of Safari config register) to correspond
 * to the current memory slice map. LPAs of processors present at boot
 * will remain as programmed by POST. LPAs of processors on boards added
 * by DR will remain NULL, as programmed by POST. This can be used to
 * to override the per-board L1SSFLG_THIS_L1_NULL_PROC_LPA flag set by
 * POST in the LDCD (and copied to the GDCD by SMS).
 *
 * drmach_reprogram_lpa and L1SSFLG_THIS_L1_NULL_PROC_LPA do not apply
 * to Schizo device LPAs. These are always set by DR.
 */
static int		 drmach_reprogram_lpa = 1;

/*
 * There is a known HW bug where a Jaguar CPU in Safari port 0 (SBX/P0)
 * can fail to receive an XIR. To workaround this issue until a hardware
 * fix is implemented, we will exclude the selection of these CPUs.
 * Setting this to 0 will allow their selection again.
 */
static int		 drmach_iocage_exclude_jaguar_port_zero = 1;

static int		 drmach_initialized;
static drmach_array_t	*drmach_boards;

static int		 drmach_cpu_delay = 1000;
static int		 drmach_cpu_ntries = 50000;

static uint32_t		 drmach_slice_table[AXQ_MAX_EXP];
static kmutex_t		 drmach_slice_table_lock;

tte_t			 drmach_cpu_sram_tte[NCPU];
caddr_t			 drmach_cpu_sram_va;

/*
 * Setting to non-zero will enable delay before all disconnect ops.
 */
static int		 drmach_unclaim_delay_all;
/*
 * Default delay is slightly greater than the max processor Safari timeout.
 * This delay is intended to ensure the outstanding Safari activity has
 * retired on this board prior to a board disconnect.
 */
static clock_t		 drmach_unclaim_usec_delay = DRMACH_SAF_TOL_MAX + 10;

/*
 * By default, DR of non-Panther procs is not allowed into a Panther
 * domain with large page sizes enabled.  Setting this to 0 will remove
 * the restriction.
 */
static int		 drmach_large_page_restriction = 1;

/*
 * Used to pass updated LPA values to procs.
 * Protocol is to clear the array before use.
 */
volatile uchar_t	*drmach_xt_mb;
volatile uint64_t	 drmach_xt_ready;
static kmutex_t		 drmach_xt_mb_lock;
static int		 drmach_xt_mb_size;

uint64_t		 drmach_bus_sync_list[18 * 4 * 4 + 1];
static kmutex_t		 drmach_bus_sync_lock;

static void		drmach_fini(void);

static sbd_error_t	*drmach_device_new(drmach_node_t *,
				drmach_board_t *, int, drmachid_t *);
static sbd_error_t	*drmach_cpu_new(drmach_device_t *, drmachid_t *);
static sbd_error_t	*drmach_mem_new(drmach_device_t *, drmachid_t *);
static sbd_error_t	*drmach_pci_new(drmach_device_t *, drmachid_t *);
static sbd_error_t	*drmach_io_new(drmach_device_t *, drmachid_t *);

static sbd_error_t 	*drmach_board_release(drmachid_t);
static sbd_error_t 	*drmach_board_status(drmachid_t, drmach_status_t *);

static void 		drmach_cpu_dispose(drmachid_t);
static sbd_error_t 	*drmach_cpu_release(drmachid_t);
static sbd_error_t 	*drmach_cpu_status(drmachid_t, drmach_status_t *);

static void 		drmach_mem_dispose(drmachid_t);
static sbd_error_t 	*drmach_mem_release(drmachid_t);
static sbd_error_t 	*drmach_mem_status(drmachid_t, drmach_status_t *);

static dev_info_t	*drmach_node_ddi_get_dip(drmach_node_t *np);
static int		 drmach_node_ddi_get_prop(drmach_node_t *np,
				char *name, void *buf, int len);
static int		 drmach_node_ddi_get_proplen(drmach_node_t *np,
				char *name, int *len);

static dev_info_t	*drmach_node_obp_get_dip(drmach_node_t *np);
static int		 drmach_node_obp_get_prop(drmach_node_t *np,
				char *name, void *buf, int len);
static int		 drmach_node_obp_get_proplen(drmach_node_t *np,
				char *name, int *len);

static sbd_error_t	*drmach_mbox_trans(uint8_t msgtype, int bnum,
				caddr_t obufp, int olen,
				caddr_t ibufp, int ilen);

sbd_error_t		*drmach_io_post_attach(drmachid_t id);
sbd_error_t		*drmach_io_post_release(drmachid_t id);

static sbd_error_t	*drmach_iocage_setup(dr_testboard_req_t *,
				drmach_device_t **dpp, cpu_flag_t *oflags);
static int		drmach_iocage_cpu_return(drmach_device_t *dp,
				cpu_flag_t oflags);
static sbd_error_t	*drmach_iocage_mem_return(dr_testboard_reply_t *tbr);
void			drmach_iocage_mem_scrub(uint64_t nbytes);

static sbd_error_t 	*drmach_i_status(drmachid_t id, drmach_status_t *stat);

static void		drmach_slot1_lpa_set(drmach_board_t *bp);

static void		drmach_cpu_read(uint64_t arg1, uint64_t arg2);
static int		drmach_cpu_read_scr(drmach_cpu_t *cp, uint64_t *scr);

static void		 drmach_bus_sync_list_update(void);
static void		 drmach_slice_table_update(drmach_board_t *, int);
static int		 drmach_portid2bnum(int);

static void		drmach_msg_memslice_init(dr_memslice_t slice_arr[]);
static void		drmach_msg_memregs_init(dr_memregs_t regs_arr[]);

static int		drmach_panther_boards(void);

static int		drmach_name2type_idx(char *);

#ifdef DEBUG

#define	DRMACH_PR		if (drmach_debug) printf
#define	DRMACH_MEMLIST_DUMP	if (drmach_debug) MEMLIST_DUMP
int drmach_debug = 0;		 /* set to non-zero to enable debug messages */
#else

#define	DRMACH_PR		_NOTE(CONSTANTCONDITION) if (0) printf
#define	DRMACH_MEMLIST_DUMP	_NOTE(CONSTANTCONDITION) if (0) MEMLIST_DUMP
#endif /* DEBUG */

#define	DRMACH_OBJ(id)		((drmach_common_t *)id)

#define	DRMACH_IS_BOARD_ID(id)	\
	((id != 0) &&		\
	(DRMACH_OBJ(id)->isa == (void *)drmach_board_new))

#define	DRMACH_IS_CPU_ID(id)	\
	((id != 0) &&		\
	(DRMACH_OBJ(id)->isa == (void *)drmach_cpu_new))

#define	DRMACH_IS_MEM_ID(id)	\
	((id != 0) &&		\
	(DRMACH_OBJ(id)->isa == (void *)drmach_mem_new))

#define	DRMACH_IS_IO_ID(id)	\
	((id != 0) &&		\
	(DRMACH_OBJ(id)->isa == (void *)drmach_io_new))

#define	DRMACH_IS_DEVICE_ID(id)					\
	((id != 0) &&						\
	(DRMACH_OBJ(id)->isa == (void *)drmach_cpu_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_mem_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_io_new))

#define	DRMACH_IS_ID(id)					\
	((id != 0) &&						\
	(DRMACH_OBJ(id)->isa == (void *)drmach_board_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_cpu_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_mem_new ||	\
	    DRMACH_OBJ(id)->isa == (void *)drmach_io_new))

#define	DRMACH_INTERNAL_ERROR() \
	drerr_new(1, ESTC_INTERNAL, drmach_ie_fmt, __LINE__)
static char		*drmach_ie_fmt = "drmach.c %d";

static struct {
	const char	 *name;
	const char	 *type;
	sbd_error_t	 *(*new)(drmach_device_t *, drmachid_t *);
} drmach_name2type[] = {
	{"cmp",			    DRMACH_DEVTYPE_CMP,    NULL },
	{"cpu",			    DRMACH_DEVTYPE_CPU,    drmach_cpu_new },
	{"SUNW,UltraSPARC-III",	    DRMACH_DEVTYPE_CPU,    drmach_cpu_new },
	{"SUNW,UltraSPARC-III+",    DRMACH_DEVTYPE_CPU,    drmach_cpu_new },
	{"memory-controller",	    DRMACH_DEVTYPE_MEM,    drmach_mem_new },
	{"pci",			    DRMACH_DEVTYPE_PCI,    drmach_pci_new },
	{"SUNW,wci",		    DRMACH_DEVTYPE_WCI,    drmach_io_new  },
};

/*
 * drmach autoconfiguration data structures and interfaces
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,
	"Sun Fire 15000 DR"
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

/*
 * drmach_boards_rwlock is used to synchronize read/write
 * access to drmach_boards array between status and board lookup
 * as READERS, and assign, and unassign threads as WRITERS.
 */
static krwlock_t	drmach_boards_rwlock;

static kmutex_t		drmach_i_lock;
static kmutex_t		drmach_iocage_lock;
static kcondvar_t 	drmach_iocage_cv;
static int		drmach_iocage_is_busy = 0;
uint64_t		drmach_iocage_paddr;
static caddr_t		drmach_iocage_vaddr;
static int		drmach_iocage_size = 0;
static int		drmach_is_cheetah = -1;

int
_init(void)
{
	int	err;

	mutex_init(&drmach_i_lock, NULL, MUTEX_DRIVER, NULL);
	rw_init(&drmach_boards_rwlock, NULL, RW_DEFAULT, NULL);
	drmach_xt_mb_size = NCPU * sizeof (uchar_t);
	drmach_xt_mb = (uchar_t *)vmem_alloc(static_alloc_arena,
	    drmach_xt_mb_size, VM_SLEEP);
	bzero((void *)drmach_xt_mb, drmach_xt_mb_size);
	if ((err = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&drmach_i_lock);
		rw_destroy(&drmach_boards_rwlock);
		vmem_free(static_alloc_arena, (void *)drmach_xt_mb,
		    drmach_xt_mb_size);
	}

	return (err);
}

int
_fini(void)
{
	int		err;

	if ((err = mod_remove(&modlinkage)) == 0)
		drmach_fini();

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * drmach_node_* routines serve the purpose of separating the
 * rest of the code from the device tree and OBP.  This is necessary
 * because of In-Kernel-Probing.  Devices probed after stod, are probed
 * by the in-kernel-prober, not OBP.  These devices, therefore, do not
 * have dnode ids.
 */

static int
drmach_node_obp_get_parent(drmach_node_t *np, drmach_node_t *pp)
{
	pnode_t		nodeid;
	static char	*fn = "drmach_node_obp_get_parent";

	nodeid = np->get_dnode(np);
	if (nodeid == OBP_NONODE) {
		cmn_err(CE_WARN, "%s: invalid dnode", fn);
		return (-1);
	}

	bcopy(np, pp, sizeof (drmach_node_t));

	pp->here = (void *)(uintptr_t)prom_parentnode(nodeid);
	if (pp->here == OBP_NONODE) {
		cmn_err(CE_WARN, "%s: invalid parent dnode", fn);
		return (-1);
	}

	return (0);
}

static pnode_t
drmach_node_obp_get_dnode(drmach_node_t *np)
{
	return ((pnode_t)(uintptr_t)np->here);
}

typedef struct {
	drmach_node_walk_args_t	*nwargs;
	int 			(*cb)(drmach_node_walk_args_t *args);
	int			err;
} drmach_node_ddi_walk_args_t;

int
drmach_node_ddi_walk_cb(dev_info_t *dip, void *arg)
{
	drmach_node_ddi_walk_args_t	*nargs;

	nargs = (drmach_node_ddi_walk_args_t *)arg;

	/*
	 * dip doesn't have to be held here as we are called
	 * from ddi_walk_devs() which holds the dip.
	 */
	nargs->nwargs->node->here = (void *)dip;

	nargs->err = nargs->cb(nargs->nwargs);

	/*
	 * Set "here" to NULL so that unheld dip is not accessible
	 * outside ddi_walk_devs()
	 */
	nargs->nwargs->node->here = NULL;

	if (nargs->err)
		return (DDI_WALK_TERMINATE);
	else
		return (DDI_WALK_CONTINUE);
}

static int
drmach_node_ddi_walk(drmach_node_t *np, void *data,
		int (*cb)(drmach_node_walk_args_t *args))
{
	drmach_node_walk_args_t		args;
	drmach_node_ddi_walk_args_t	nargs;

	/* initialized args structure for callback */
	args.node = np;
	args.data = data;

	nargs.nwargs = &args;
	nargs.cb = cb;
	nargs.err = 0;

	/*
	 * Root node doesn't have to be held in any way.
	 */
	ddi_walk_devs(ddi_root_node(), drmach_node_ddi_walk_cb, (void *)&nargs);

	return (nargs.err);
}

static int
drmach_node_obp_walk(drmach_node_t *np, void *data,
		int (*cb)(drmach_node_walk_args_t *args))
{
	pnode_t			nodeid;
	int			rv;
	drmach_node_walk_args_t	args;

	/* initialized args structure for callback */
	args.node = np;
	args.data = data;

	nodeid = prom_childnode(prom_rootnode());

	/* save our new position within the tree */
	np->here = (void *)(uintptr_t)nodeid;

	rv = 0;
	while (nodeid != OBP_NONODE) {

		pnode_t child;

		rv = (*cb)(&args);
		if (rv)
			break;

		child = prom_childnode(nodeid);
		np->here = (void *)(uintptr_t)child;

		while (child != OBP_NONODE) {
			rv = (*cb)(&args);
			if (rv)
				break;

			child = prom_nextnode(child);
			np->here = (void *)(uintptr_t)child;
		}

		nodeid = prom_nextnode(nodeid);

		/* save our new position within the tree */
		np->here = (void *)(uintptr_t)nodeid;
	}

	return (rv);
}

static int
drmach_node_ddi_get_parent(drmach_node_t *np, drmach_node_t *pp)
{
	dev_info_t	*ndip;
	static char	*fn = "drmach_node_ddi_get_parent";

	ndip = np->n_getdip(np);
	if (ndip == NULL) {
		cmn_err(CE_WARN, "%s: NULL dip", fn);
		return (-1);
	}

	bcopy(np, pp, sizeof (drmach_node_t));

	pp->here = (void *)ddi_get_parent(ndip);
	if (pp->here == NULL) {
		cmn_err(CE_WARN, "%s: NULL parent dip", fn);
		return (-1);
	}

	return (0);
}

/*ARGSUSED*/
static pnode_t
drmach_node_ddi_get_dnode(drmach_node_t *np)
{
	return ((pnode_t)NULL);
}

static drmach_node_t *
drmach_node_new(void)
{
	drmach_node_t *np;

	np = kmem_zalloc(sizeof (drmach_node_t), KM_SLEEP);

	if (drmach_initialized) {
		np->get_dnode = drmach_node_ddi_get_dnode;
		np->walk = drmach_node_ddi_walk;
		np->n_getdip = drmach_node_ddi_get_dip;
		np->n_getproplen = drmach_node_ddi_get_proplen;
		np->n_getprop = drmach_node_ddi_get_prop;
		np->get_parent = drmach_node_ddi_get_parent;
	} else {
		np->get_dnode = drmach_node_obp_get_dnode;
		np->walk = drmach_node_obp_walk;
		np->n_getdip = drmach_node_obp_get_dip;
		np->n_getproplen = drmach_node_obp_get_proplen;
		np->n_getprop = drmach_node_obp_get_prop;
		np->get_parent = drmach_node_obp_get_parent;
	}

	return (np);
}

static void
drmach_node_dispose(drmach_node_t *np)
{
	kmem_free(np, sizeof (*np));
}

/*
 * Check if a CPU node is part of a CMP.
 */
static int
drmach_is_cmp_child(dev_info_t *dip)
{
	dev_info_t *pdip;

	if (strcmp(ddi_node_name(dip), DRMACH_CPU_NAMEPROP) != 0) {
		return (0);
	}

	pdip = ddi_get_parent(dip);

	ASSERT(pdip);

	if (strcmp(ddi_node_name(pdip), DRMACH_CMP_NAMEPROP) == 0) {
		return (1);
	}

	return (0);
}

static dev_info_t *
drmach_node_obp_get_dip(drmach_node_t *np)
{
	pnode_t		nodeid;
	dev_info_t	*dip;

	nodeid = np->get_dnode(np);
	if (nodeid == OBP_NONODE)
		return (NULL);

	dip = e_ddi_nodeid_to_dip(nodeid);
	if (dip) {
		/*
		 * The branch rooted at dip will have been previously
		 * held, or it will be the child of a CMP. In either
		 * case, the hold acquired in e_ddi_nodeid_to_dip()
		 * is not needed.
		 */
		ddi_release_devi(dip);
		ASSERT(drmach_is_cmp_child(dip) || e_ddi_branch_held(dip));
	}

	return (dip);
}

static dev_info_t *
drmach_node_ddi_get_dip(drmach_node_t *np)
{
	return ((dev_info_t *)np->here);
}

static int
drmach_node_walk(drmach_node_t *np, void *param,
		int (*cb)(drmach_node_walk_args_t *args))
{
	return (np->walk(np, param, cb));
}

static int
drmach_node_ddi_get_prop(drmach_node_t *np, char *name, void *buf, int len)
{
	int		rv = 0;
	dev_info_t	*ndip;
	static char	*fn = "drmach_node_ddi_get_prop";

	ndip = np->n_getdip(np);
	if (ndip == NULL) {
		cmn_err(CE_WARN, "%s: NULL dip", fn);
		rv = -1;
	} else if (ddi_getlongprop_buf(DDI_DEV_T_ANY, ndip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, name,
	    (caddr_t)buf, &len) != DDI_PROP_SUCCESS) {
		rv = -1;
	}

	return (rv);
}

/* ARGSUSED */
static int
drmach_node_obp_get_prop(drmach_node_t *np, char *name, void *buf, int len)
{
	int		rv = 0;
	pnode_t		nodeid;
	static char	*fn = "drmach_node_obp_get_prop";

	nodeid = np->get_dnode(np);
	if (nodeid == OBP_NONODE) {
		cmn_err(CE_WARN, "%s: invalid dnode", fn);
		rv = -1;
	} else if (prom_getproplen(nodeid, (caddr_t)name) < 0) {
		rv = -1;
	} else {
		(void) prom_getprop(nodeid, (caddr_t)name, (caddr_t)buf);
	}

	return (rv);
}

static int
drmach_node_ddi_get_proplen(drmach_node_t *np, char *name, int *len)
{
	int		rv = 0;
	dev_info_t	*ndip;

	ndip = np->n_getdip(np);
	if (ndip == NULL) {
		rv = -1;
	} else if (ddi_getproplen(DDI_DEV_T_ANY, ndip, DDI_PROP_DONTPASS,
	    name, len) != DDI_PROP_SUCCESS) {
		rv = -1;
	}

	return (rv);
}

static int
drmach_node_obp_get_proplen(drmach_node_t *np, char *name, int *len)
{
	pnode_t	 nodeid;
	int	 rv;

	nodeid = np->get_dnode(np);
	if (nodeid == OBP_NONODE)
		rv = -1;
	else {
		*len = prom_getproplen(nodeid, (caddr_t)name);
		rv = (*len < 0 ? -1 : 0);
	}

	return (rv);
}

static drmachid_t
drmach_node_dup(drmach_node_t *np)
{
	drmach_node_t *dup;

	dup = drmach_node_new();
	dup->here = np->here;
	dup->get_dnode = np->get_dnode;
	dup->walk = np->walk;
	dup->n_getdip = np->n_getdip;
	dup->n_getproplen = np->n_getproplen;
	dup->n_getprop = np->n_getprop;
	dup->get_parent = np->get_parent;

	return (dup);
}

/*
 * drmach_array provides convenient array construction, access,
 * bounds checking and array destruction logic.
 */

static drmach_array_t *
drmach_array_new(int min_index, int max_index)
{
	drmach_array_t *arr;

	arr = kmem_zalloc(sizeof (drmach_array_t), KM_SLEEP);

	arr->arr_sz = (max_index - min_index + 1) * sizeof (void *);
	if (arr->arr_sz > 0) {
		arr->min_index = min_index;
		arr->max_index = max_index;

		arr->arr = kmem_zalloc(arr->arr_sz, KM_SLEEP);
		return (arr);
	} else {
		kmem_free(arr, sizeof (*arr));
		return (0);
	}
}

static int
drmach_array_set(drmach_array_t *arr, int idx, drmachid_t val)
{
	if (idx < arr->min_index || idx > arr->max_index)
		return (-1);
	else {
		arr->arr[idx - arr->min_index] = val;
		return (0);
	}
	/*NOTREACHED*/
}

static int
drmach_array_get(drmach_array_t *arr, int idx, drmachid_t *val)
{
	if (idx < arr->min_index || idx > arr->max_index)
		return (-1);
	else {
		*val = arr->arr[idx - arr->min_index];
		return (0);
	}
	/*NOTREACHED*/
}

static int
drmach_array_first(drmach_array_t *arr, int *idx, drmachid_t *val)
{
	int rv;

	*idx = arr->min_index;
	while ((rv = drmach_array_get(arr, *idx, val)) == 0 && *val == NULL)
		*idx += 1;

	return (rv);
}

static int
drmach_array_next(drmach_array_t *arr, int *idx, drmachid_t *val)
{
	int rv;

	*idx += 1;
	while ((rv = drmach_array_get(arr, *idx, val)) == 0 && *val == NULL)
		*idx += 1;

	return (rv);
}

static void
drmach_array_dispose(drmach_array_t *arr, void (*disposer)(drmachid_t))
{
	drmachid_t	val;
	int		idx;
	int		rv;

	rv = drmach_array_first(arr, &idx, &val);
	while (rv == 0) {
		(*disposer)(val);

		/* clear the array entry */
		rv = drmach_array_set(arr, idx, NULL);
		ASSERT(rv == 0);

		rv = drmach_array_next(arr, &idx, &val);
	}

	kmem_free(arr->arr, arr->arr_sz);
	kmem_free(arr, sizeof (*arr));
}


static gdcd_t *
drmach_gdcd_new()
{
	gdcd_t *gdcd;

	gdcd = kmem_zalloc(sizeof (gdcd_t), KM_SLEEP);

	/* read the gdcd, bail if magic or ver #s are not what is expected */
	if (iosram_rd(GDCD_MAGIC, 0, sizeof (gdcd_t), (caddr_t)gdcd)) {
bail:
		kmem_free(gdcd, sizeof (gdcd_t));
		return (NULL);
	} else if (gdcd->h.dcd_magic != GDCD_MAGIC) {
		goto bail;
	} else if (gdcd->h.dcd_version != DCD_VERSION) {
		goto bail;
	}

	return (gdcd);
}

static void
drmach_gdcd_dispose(gdcd_t *gdcd)
{
	kmem_free(gdcd, sizeof (gdcd_t));
}

/*ARGSUSED*/
sbd_error_t *
drmach_configure(drmachid_t id, int flags)
{
	drmach_device_t	*dp;
	dev_info_t	*rdip;
	sbd_error_t	*err = NULL;

	/*
	 * On Starcat, there is no CPU driver, so it is
	 * not necessary to configure any CPU nodes.
	 */
	if (DRMACH_IS_CPU_ID(id)) {
		return (NULL);
	}

	for (; id; ) {
		dev_info_t	*fdip = NULL;

		if (!DRMACH_IS_DEVICE_ID(id))
			return (drerr_new(0, ESTC_INAPPROP, NULL));
		dp = id;

		rdip = dp->node->n_getdip(dp->node);

		/*
		 * We held this branch earlier, so at a minimum its
		 * root should still be present in the device tree.
		 */
		ASSERT(rdip);

		DRMACH_PR("drmach_configure: configuring DDI branch");

		ASSERT(e_ddi_branch_held(rdip));
		if (e_ddi_branch_configure(rdip, &fdip, 0) != 0) {
			if (err == NULL) {
				/*
				 * Record first failure but don't stop
				 */
				char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
				dev_info_t *dip = (fdip != NULL) ? fdip : rdip;

				(void) ddi_pathname(dip, path);
				err = drerr_new(1, ESTC_DRVFAIL, path);

				kmem_free(path, MAXPATHLEN);
			}

			/*
			 * If non-NULL, fdip is returned held and must be
			 * released.
			 */
			if (fdip != NULL) {
				ddi_release_devi(fdip);
			}
		}

		if (DRMACH_IS_MEM_ID(id)) {
			drmach_mem_t	*mp = id;
			id = mp->next;
		} else {
			id = NULL;
		}
	}

	return (err);
}

static sbd_error_t *
drmach_device_new(drmach_node_t *node,
	drmach_board_t *bp, int portid, drmachid_t *idp)
{
	int		i, rv, device_id, unum;
	char		name[OBP_MAXDRVNAME];
	drmach_device_t	proto;

	rv = node->n_getprop(node, "name", name, OBP_MAXDRVNAME);
	if (rv) {
		sbd_error_t *err;

		/* every node is expected to have a name */
		err = drerr_new(1, ESTC_GETPROP,
		    "dip: 0x%p: property %s",
		    node->n_getdip(node), OBP_NAME);

		return (err);
	}

	i = drmach_name2type_idx(name);

	if (i < 0 || strcmp(name, "cmp") == 0) {
		/*
		 * Not a node of interest to dr - including "cmp",
		 * but it is in drmach_name2type[], which lets gptwocfg
		 * driver to check if node is OBP created.
		 */
		*idp = (drmachid_t)0;
		return (NULL);
	}

	/*
	 * Derive a best-guess unit number from the portid value.
	 * Some drmach_*_new constructors (drmach_pci_new, for example)
	 * will overwrite the prototype unum value with one that is more
	 * appropriate for the device.
	 */
	device_id = portid & 0x1f;
	if (device_id < 4)
		unum = device_id;
	else if (device_id == 8) {
		unum = 0;
	} else if (device_id == 9) {
		unum = 1;
	} else if (device_id == 0x1c) {
		unum = 0;
	} else if (device_id == 0x1d) {
		unum = 1;
	} else {
		return (DRMACH_INTERNAL_ERROR());
	}

	bzero(&proto, sizeof (proto));
	proto.type = drmach_name2type[i].type;
	proto.bp = bp;
	proto.node = node;
	proto.portid = portid;
	proto.unum = unum;

	return (drmach_name2type[i].new(&proto, idp));
}

static void
drmach_device_dispose(drmachid_t id)
{
	drmach_device_t *self = id;

	self->cm.dispose(id);
}

static drmach_board_t *
drmach_board_new(int bnum)
{
	drmach_board_t	*bp;

	bp = kmem_zalloc(sizeof (drmach_board_t), KM_SLEEP);

	bp->cm.isa = (void *)drmach_board_new;
	bp->cm.release = drmach_board_release;
	bp->cm.status = drmach_board_status;

	(void) drmach_board_name(bnum, bp->cm.name, sizeof (bp->cm.name));

	bp->bnum = bnum;
	bp->devices = NULL;
	bp->tree = drmach_node_new();

	(void) drmach_array_set(drmach_boards, bnum, bp);
	return (bp);
}

static void
drmach_board_dispose(drmachid_t id)
{
	drmach_board_t *bp;

	ASSERT(DRMACH_IS_BOARD_ID(id));
	bp = id;

	if (bp->tree)
		drmach_node_dispose(bp->tree);

	if (bp->devices)
		drmach_array_dispose(bp->devices, drmach_device_dispose);

	kmem_free(bp, sizeof (*bp));
}

static sbd_error_t *
drmach_board_status(drmachid_t id, drmach_status_t *stat)
{
	sbd_error_t	*err = NULL;
	drmach_board_t	*bp;
	caddr_t		obufp;
	dr_showboard_t	shb;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));

	bp = id;

	/*
	 * we need to know if the board's connected before
	 * issuing a showboard message.  If it's connected, we just
	 * reply with status composed of cached info
	 */

	if (!bp->connected) {
		obufp = kmem_zalloc(sizeof (dr_proto_hdr_t), KM_SLEEP);
		err = drmach_mbox_trans(DRMSG_SHOWBOARD, bp->bnum, obufp,
		    sizeof (dr_proto_hdr_t), (caddr_t)&shb,
		    sizeof (dr_showboard_t));

		kmem_free(obufp, sizeof (dr_proto_hdr_t));
		if (err)
			return (err);

		bp->connected = (shb.bd_assigned && shb.bd_active);
		(void) strncpy(bp->type, shb.board_type, sizeof (bp->type));
		stat->assigned = bp->assigned = shb.bd_assigned;
		stat->powered = bp->powered = shb.power_on;
		stat->empty = bp->empty = shb.slot_empty;

		switch (shb.test_status) {
			case DR_TEST_STATUS_UNKNOWN:
			case DR_TEST_STATUS_IPOST:
			case DR_TEST_STATUS_ABORTED:
				stat->cond = bp->cond = SBD_COND_UNKNOWN;
				break;
			case DR_TEST_STATUS_PASSED:
				stat->cond = bp->cond = SBD_COND_OK;
				break;
			case DR_TEST_STATUS_FAILED:
				stat->cond = bp->cond = SBD_COND_FAILED;
				break;
			default:
				stat->cond = bp->cond = SBD_COND_UNKNOWN;
				DRMACH_PR("Unknown test status=0x%x from SC\n",
				    shb.test_status);
				break;

		}

		(void) strncpy(stat->type, shb.board_type, sizeof (stat->type));
		(void) snprintf(stat->info, sizeof (stat->info),
		    "Test Level=%d", shb.test_level);
	} else {
		stat->assigned = bp->assigned;
		stat->powered = bp->powered;
		stat->empty = bp->empty;
		stat->cond = bp->cond;
		(void) strncpy(stat->type, bp->type, sizeof (stat->type));
	}

	stat->busy = 0;			/* assume not busy */
	stat->configured = 0;		/* assume not configured */
	if (bp->devices) {
		int		 rv;
		int		 d_idx;
		drmachid_t	 d_id;

		rv = drmach_array_first(bp->devices, &d_idx, &d_id);
		while (rv == 0) {
			drmach_status_t	d_stat;

			err = drmach_i_status(d_id, &d_stat);
			if (err)
				break;

			stat->busy |= d_stat.busy;
			stat->configured |= d_stat.configured;

			rv = drmach_array_next(bp->devices, &d_idx, &d_id);
		}
	}

	return (err);
}

typedef struct drmach_msglist {
	kcondvar_t		s_cv; 		/* condvar for sending msg */
	kmutex_t		s_lock;		/* mutex for sending */
	kcondvar_t		g_cv;		/* condvar for getting reply */
	kmutex_t		g_lock;		/* mutex for getting reply */
	struct drmach_msglist	*prev;		/* link to previous entry */
	struct drmach_msglist	*next;		/* link to next entry */
	struct drmach_msglist	*link;		/* link to related entry */
	caddr_t			o_buf;		/* address of output buffer */
	caddr_t			i_buf; 		/* address of input buffer */
	uint32_t		o_buflen;	/* output buffer length */
	uint32_t		i_buflen;	/* input buffer length */
	uint32_t		msgid;		/* message identifier */
	int			o_nretry;	/* number of sending retries */
	int			f_error;	/* mailbox framework error */
	uint8_t			e_code;		/* error code returned by SC */
	uint8_t			p_flag	:1,	/* successfully putmsg */
				m_reply	:1,	/* msg reply received */
				unused	:6;
} drmach_msglist_t;

kmutex_t		drmach_g_mbox_mutex;	/* mutex for mailbox globals */
kmutex_t		drmach_ri_mbox_mutex;	/* mutex for mailbox reinit */
kmutex_t		drmach_msglist_mutex;	/* mutex for message list */
drmach_msglist_t	*drmach_msglist_first;	/* first entry in msg list */
drmach_msglist_t	*drmach_msglist_last;	/* last entry in msg list */
uint32_t		drmach_msgid;		/* current message id */
kthread_t		*drmach_getmsg_thread;	/* ptr to getmsg thread */
volatile int		drmach_getmsg_thread_run; /* run flag for getmsg thr */
kmutex_t		drmach_sendmsg_mutex;	/* mutex for sendmsg cv */
kcondvar_t		drmach_sendmsg_cv;	/* signaled to send new msg */
kthread_t		*drmach_sendmsg_thread; /* ptr to sendmsg thread */
volatile int		drmach_sendmsg_thread_run; /* run flag for sendmsg */
int			drmach_mbox_istate;	/* mailbox init state */
int			drmach_mbox_iflag;	/* set if init'd with SC */
int			drmach_mbox_ipending;	/* set if reinit scheduled */

/*
 * Timeout values (in seconds) used when waiting for replies (from the SC) to
 * requests that we sent.  Since we only receive boardevent messages, and they
 * are events rather than replies, there is no boardevent timeout.
 */
int	drmach_to_mbxinit	= 60;		/* 1 minute */
int	drmach_to_assign	= 60;		/* 1 minute */
int	drmach_to_unassign	= 60;		/* 1 minute */
int	drmach_to_claim		= 3600;		/* 1 hour */
int	drmach_to_unclaim	= 3600;		/* 1 hour */
int	drmach_to_poweron	= 480;		/* 8 minutes */
int	drmach_to_poweroff	= 480;		/* 8 minutes */
int	drmach_to_testboard	= 43200;	/* 12 hours */
int	drmach_to_aborttest	= 180;		/* 3 minutes */
int	drmach_to_showboard	= 180;		/* 3 minutes */
int	drmach_to_unconfig	= 180;		/* 3 minutes */

/*
 * Delay (in seconds) used after receiving a non-transient error indication from
 * an mboxsc_getmsg call in the thread that loops waiting for incoming messages.
 */
int	drmach_mbxerr_delay	= 15;		/* 15 seconds */

/*
 * Timeout values (in milliseconds) for mboxsc_putmsg and mboxsc_getmsg calls.
 */
clock_t	drmach_to_putmsg;			/* set in drmach_mbox_init */
clock_t	drmach_to_getmsg	= 31000;	/* 31 seconds */

/*
 * Normally, drmach_to_putmsg is set dynamically during initialization in
 * drmach_mbox_init.  This has the potentially undesirable side effect of
 * clobbering any value that might have been set in /etc/system.  To prevent
 * dynamic setting of drmach_to_putmsg (thereby allowing it to be tuned in
 * /etc/system), set drmach_use_tuned_putmsg_to to 1.
 */
int	drmach_use_tuned_putmsg_to	= 0;


/* maximum conceivable message size for future mailbox protocol versions */
#define	DRMACH_MAX_MBOX_MSG_SIZE	4096

/*ARGSUSED*/
void
drmach_mbox_prmsg(dr_mbox_msg_t *mbp, int dir)
{
	int		i, j;
	dr_memregs_t	*memregs;
	dr_proto_hdr_t	*php = &mbp->p_hdr;
	dr_msg_t	*mp = &mbp->msgdata;

#ifdef DEBUG
	switch (php->command) {
		case DRMSG_BOARDEVENT:
			if (dir) {
				DRMACH_PR("ERROR!! outgoing BOARDEVENT\n");
			} else {
				DRMACH_PR("BOARDEVENT received:\n");
				DRMACH_PR("init=%d ins=%d rem=%d asgn=%d\n",
				    mp->dm_be.initialized,
				    mp->dm_be.board_insertion,
				    mp->dm_be.board_removal,
				    mp->dm_be.slot_assign);
				DRMACH_PR("unasgn=%d avail=%d unavail=%d\n",
				    mp->dm_be.slot_unassign,
				    mp->dm_be.slot_avail,
				    mp->dm_be.slot_unavail);
			}
			break;
		case DRMSG_MBOX_INIT:
			if (dir) {
				DRMACH_PR("MBOX_INIT Request:\n");
			} else {
				DRMACH_PR("MBOX_INIT Reply:\n");
			}
			break;
		case DRMSG_ASSIGN:
			if (dir) {
				DRMACH_PR("ASSIGN Request:\n");
			} else {
				DRMACH_PR("ASSIGN Reply:\n");
			}
			break;
		case DRMSG_UNASSIGN:
			if (dir) {
				DRMACH_PR("UNASSIGN Request:\n");
			} else {
				DRMACH_PR("UNASSIGN Reply:\n");
			}
			break;
		case DRMSG_CLAIM:
			if (!dir) {
				DRMACH_PR("CLAIM Reply:\n");
				break;
			}

			DRMACH_PR("CLAIM Request:\n");
			for (i = 0; i < 18; ++i) {
				DRMACH_PR("exp%d: val=%d slice=0x%x\n", i,
				    mp->dm_cr.mem_slice[i].valid,
				    mp->dm_cr.mem_slice[i].slice);
				memregs = &(mp->dm_cr.mem_regs[i]);
				for (j = 0; j < S0_LPORT_COUNT; j++) {
					DRMACH_PR("  MC %2d: "
					    "MADR[%d] = 0x%lx, "
					    "MADR[%d] = 0x%lx\n", j,
					    0, DRMACH_MCREG_TO_U64(
					    memregs->madr[j][0]),
					    1, DRMACH_MCREG_TO_U64(
					    memregs->madr[j][1]));
					DRMACH_PR("       : "
					    "MADR[%d] = 0x%lx, "
					    "MADR[%d] = 0x%lx\n",
					    2, DRMACH_MCREG_TO_U64(
					    memregs->madr[j][2]),
					    3, DRMACH_MCREG_TO_U64(
					    memregs->madr[j][3]));
				}
			}
			break;
		case DRMSG_UNCLAIM:
			if (!dir) {
				DRMACH_PR("UNCLAIM Reply:\n");
				break;
			}

			DRMACH_PR("UNCLAIM Request:\n");
			for (i = 0; i < 18; ++i) {
				DRMACH_PR("exp%d: val=%d slice=0x%x\n", i,
				    mp->dm_ur.mem_slice[i].valid,
				    mp->dm_ur.mem_slice[i].slice);
				memregs = &(mp->dm_ur.mem_regs[i]);
				for (j = 0; j < S0_LPORT_COUNT; j++) {
					DRMACH_PR("  MC %2d: "
					    "MADR[%d] = 0x%lx, "
					    "MADR[%d] = 0x%lx\n", j,
					    0, DRMACH_MCREG_TO_U64(
					    memregs->madr[j][0]),
					    1, DRMACH_MCREG_TO_U64(
					    memregs->madr[j][1]));
					DRMACH_PR("       : "
					    "MADR[%d] = 0x%lx, "
					    "MADR[%d] = 0x%lx\n",
					    2, DRMACH_MCREG_TO_U64(
					    memregs->madr[j][2]),
					    3, DRMACH_MCREG_TO_U64(
					    memregs->madr[j][3]));
				}
			}
			DRMACH_PR(" mem_clear=%d\n", mp->dm_ur.mem_clear);
			break;
		case DRMSG_UNCONFIG:
			if (!dir) {
				DRMACH_PR("UNCONFIG Reply:\n");
				break;
			}

			DRMACH_PR("UNCONFIG Request:\n");
			for (i = 0; i < 18; ++i) {
				DRMACH_PR("exp%d: val=%d slice=0x%x\n", i,
				    mp->dm_uc.mem_slice[i].valid,
				    mp->dm_uc.mem_slice[i].slice);
				memregs = &(mp->dm_uc.mem_regs[i]);
				for (j = 0; j < S0_LPORT_COUNT; j++) {
					DRMACH_PR("  MC %2d: "
					    "MADR[%d] = 0x%lx, "
					    "MADR[%d] = 0x%lx\n", j,
					    0, DRMACH_MCREG_TO_U64(
					    memregs->madr[j][0]),
					    1, DRMACH_MCREG_TO_U64(
					    memregs->madr[j][1]));
					DRMACH_PR("       : "
					    "MADR[%d] = 0x%lx, "
					    "MADR[%d] = 0x%lx\n",
					    2, DRMACH_MCREG_TO_U64(
					    memregs->madr[j][2]),
					    3, DRMACH_MCREG_TO_U64(
					    memregs->madr[j][3]));
				}
			}
			break;
		case DRMSG_POWERON:
			if (dir) {
				DRMACH_PR("POWERON Request:\n");
			} else {
				DRMACH_PR("POWERON Reply:\n");
			}
			break;
		case DRMSG_POWEROFF:
			if (dir) {
				DRMACH_PR("POWEROFF Request:\n");
			} else {
				DRMACH_PR("POWEROFF Reply:\n");
			}
			break;
		case DRMSG_TESTBOARD:
			if (dir) {
				DRMACH_PR("TESTBOARD Request:\n");
				DRMACH_PR("\tmemaddrhi=0x%x memaddrlo=0x%x ",
				    mp->dm_tb.memaddrhi,
				    mp->dm_tb.memaddrlo);
				DRMACH_PR("memlen=0x%x cpu_portid=0x%x\n",
				    mp->dm_tb.memlen, mp->dm_tb.cpu_portid);
				DRMACH_PR("\tforce=0x%x imm=0x%x\n",
				    mp->dm_tb.force, mp->dm_tb.immediate);
			} else {
				DRMACH_PR("TESTBOARD Reply:\n");
				DRMACH_PR("\tmemaddrhi=0x%x memaddrlo=0x%x ",
				    mp->dm_tr.memaddrhi,
				    mp->dm_tr.memaddrlo);
				DRMACH_PR("memlen=0x%x cpu_portid=0x%x\n",
				    mp->dm_tr.memlen, mp->dm_tr.cpu_portid);
				DRMACH_PR("\trecovered=0x%x test status=0x%x\n",
				    mp->dm_tr.cpu_recovered,
				    mp->dm_tr.test_status);

			}
			break;
		case DRMSG_ABORT_TEST:
			if (dir) {
				DRMACH_PR("ABORT_TEST Request:\n");
			} else {
				DRMACH_PR("ABORT_TEST Reply:\n");
			}

			DRMACH_PR("\tmemaddrhi=0x%x memaddrlo=0x%x ",
			    mp->dm_ta.memaddrhi,
			    mp->dm_ta.memaddrlo);
			DRMACH_PR("memlen=0x%x cpu_portid=0x%x\n",
			    mp->dm_ta.memlen, mp->dm_ta.cpu_portid);
			break;
		case DRMSG_SHOWBOARD:
			if (dir) {
				DRMACH_PR("SHOWBOARD Request:\n");
			} else {
				DRMACH_PR("SHOWBOARD Reply:\n");

				DRMACH_PR(": empty=%d power=%d assigned=%d",
				    mp->dm_sb.slot_empty,
				    mp->dm_sb.power_on,
				    mp->dm_sb.bd_assigned);
				DRMACH_PR(": active=%d t_status=%d t_level=%d ",
				    mp->dm_sb.bd_active,
				    mp->dm_sb.test_status,
				    mp->dm_sb.test_level);
				DRMACH_PR(": type=%s ", mp->dm_sb.board_type);
			}
			break;
		default:
			DRMACH_PR("Unknown message type\n");
			break;
	}

	DRMACH_PR("dr hdr:\n\tid=0x%x vers=0x%x cmd=0x%x exp=0x%x slot=0x%x\n",
	    php->message_id, php->drproto_version, php->command,
	    php->expbrd, php->slot);
#endif
	DRMACH_PR("\treply_status=0x%x error_code=0x%x\n", php->reply_status,
	    php->error_code);
}

/*
 * Callback function passed to taskq_dispatch when a mailbox reinitialization
 * handshake needs to be scheduled.  The handshake can't be performed by the
 * thread that determines it is needed, in most cases, so this function is
 * dispatched on the system-wide taskq pool of threads.  Failure is reported but
 * otherwise ignored, since any situation that requires a mailbox initialization
 * handshake will continue to request the handshake until it succeeds.
 */
static void
drmach_mbox_reinit(void *unused)
{
	_NOTE(ARGUNUSED(unused))

	caddr_t		obufp = NULL;
	sbd_error_t	*serr = NULL;

	DRMACH_PR("scheduled mailbox reinit running\n");

	mutex_enter(&drmach_ri_mbox_mutex);
	mutex_enter(&drmach_g_mbox_mutex);
	if (drmach_mbox_iflag == 0) {
		/* need to initialize the mailbox */
		mutex_exit(&drmach_g_mbox_mutex);

		cmn_err(CE_NOTE, "!reinitializing DR mailbox");
		obufp = kmem_zalloc(sizeof (dr_proto_hdr_t), KM_SLEEP);
		serr = drmach_mbox_trans(DRMSG_MBOX_INIT, 0, obufp,
		    sizeof (dr_proto_hdr_t), (caddr_t)NULL, 0);
		kmem_free(obufp, sizeof (dr_proto_hdr_t));

		if (serr) {
			cmn_err(CE_WARN,
			    "mbox_init: MBOX_INIT failed ecode=0x%x",
			    serr->e_code);
			sbd_err_clear(&serr);
		}
		mutex_enter(&drmach_g_mbox_mutex);
		if (!serr) {
			drmach_mbox_iflag = 1;
		}
	}
	drmach_mbox_ipending = 0;
	mutex_exit(&drmach_g_mbox_mutex);
	mutex_exit(&drmach_ri_mbox_mutex);
}

/*
 * To ensure sufficient compatibility with future versions of the DR mailbox
 * protocol, we use a buffer that is large enough to receive the largest message
 * that could possibly be sent to us.  However, since that ends up being fairly
 * large, allocating it on the stack is a bad idea.  Fortunately, this function
 * does not need to be MT-safe since it is only invoked by the mailbox
 * framework, which will never invoke it multiple times concurrently.  Since
 * that is the case, we can use a static buffer.
 */
void
drmach_mbox_event(void)
{
	static uint8_t	buf[DRMACH_MAX_MBOX_MSG_SIZE];
	dr_mbox_msg_t	*msg = (dr_mbox_msg_t *)buf;
	int		err;
	uint32_t	type = MBOXSC_MSG_EVENT;
	uint32_t	command = DRMSG_BOARDEVENT;
	uint64_t	transid = 0;
	uint32_t	length = DRMACH_MAX_MBOX_MSG_SIZE;
	char		*hint = "";
	int		logsys = 0;

	do {
		err = mboxsc_getmsg(KEY_SCDR, &type, &command, &transid,
		    &length, (void *)msg, 0);
	} while (err == EAGAIN);

	/* don't try to interpret anything with the wrong version number */
	if ((err == 0) && (msg->p_hdr.drproto_version != DRMBX_VERSION)) {
		cmn_err(CE_WARN, "mailbox version mismatch 0x%x vs 0x%x",
		    msg->p_hdr.drproto_version, DRMBX_VERSION);
		mutex_enter(&drmach_g_mbox_mutex);
		drmach_mbox_iflag = 0;
		/* schedule a reinit handshake if one isn't pending */
		if (!drmach_mbox_ipending) {
			if (taskq_dispatch(system_taskq, drmach_mbox_reinit,
			    NULL, TQ_NOSLEEP) != NULL) {
				drmach_mbox_ipending = 1;
			} else {
				cmn_err(CE_WARN,
				    "failed to schedule mailbox reinit");
			}
		}
		mutex_exit(&drmach_g_mbox_mutex);
		return;
	}

	if ((err != 0) || (msg->p_hdr.reply_status != DRMSG_REPLY_OK)) {
		cmn_err(CE_WARN,
		    "Unsolicited mboxsc_getmsg failed: err=0x%x code=0x%x",
		    err, msg->p_hdr.error_code);
	} else {
		dr_boardevent_t	*be;
		be = (dr_boardevent_t *)&msg->msgdata;

		/* check for initialization event */
		if (be->initialized) {
			mutex_enter(&drmach_g_mbox_mutex);
			drmach_mbox_iflag = 0;
			/* schedule a reinit handshake if one isn't pending */
			if (!drmach_mbox_ipending) {
				if (taskq_dispatch(system_taskq,
				    drmach_mbox_reinit, NULL, TQ_NOSLEEP)
				    != NULL) {
					drmach_mbox_ipending = 1;
				} else {
					cmn_err(CE_WARN, "failed to schedule "
					    "mailbox reinit");
				}
			}
			mutex_exit(&drmach_g_mbox_mutex);
			cmn_err(CE_NOTE, "!Mailbox Init event received");
		}

		/* anything else will be a log_sysevent call */

		if (be->board_insertion) {
			DRMACH_PR("Board Insertion event received");
			hint = DR_HINT_INSERT;
			logsys++;
	}
		if (be->board_removal) {
			DRMACH_PR("Board Removal event received");
			hint = DR_HINT_REMOVE;
			logsys++;
		}
		if (be->slot_assign) {
			DRMACH_PR("Slot Assign event received");
			logsys++;
		}
		if (be->slot_unassign) {
			DRMACH_PR("Slot Unassign event received");
			logsys++;
		}
		if (be->slot_avail) {
			DRMACH_PR("Slot Available event received");
			logsys++;
		}
		if (be->slot_unavail) {
			DRMACH_PR("Slot Unavailable event received");
			logsys++;
		}
		if (be->power_on) {
			DRMACH_PR("Power ON event received");
			logsys++;
		}
		if (be->power_off) {
			DRMACH_PR("Power OFF event received");
			logsys++;
		}

		if (logsys)
			(void) drmach_log_sysevent(
			    DRMACH_EXPSLOT2BNUM(msg->p_hdr.expbrd,
			    msg->p_hdr.slot), hint, SE_NOSLEEP, 1);
	}
}

static uint32_t
drmach_get_msgid()
{
	uint32_t	rv;
	mutex_enter(&drmach_msglist_mutex);
	if (!(++drmach_msgid))
		++drmach_msgid;
	rv = drmach_msgid;
	mutex_exit(&drmach_msglist_mutex);
	return (rv);
}

/*
 *	unlink an entry from the message transaction list
 *
 *	caller must hold drmach_msglist_mutex
 */
void
drmach_msglist_unlink(drmach_msglist_t *entry)
{
	ASSERT(mutex_owned(&drmach_msglist_mutex));
	if (entry->prev) {
		entry->prev->next = entry->next;
		if (entry->next)
			entry->next->prev = entry->prev;
	} else {
		drmach_msglist_first = entry->next;
		if (entry->next)
			entry->next->prev = NULL;
	}
	if (entry == drmach_msglist_last) {
		drmach_msglist_last = entry->prev;
	}
}

void
drmach_msglist_link(drmach_msglist_t *entry)
{
	mutex_enter(&drmach_msglist_mutex);
	if (drmach_msglist_last) {
		entry->prev = drmach_msglist_last;
		drmach_msglist_last->next = entry;
		drmach_msglist_last = entry;
	} else {
		drmach_msglist_last = drmach_msglist_first = entry;
	}
	mutex_exit(&drmach_msglist_mutex);
}

void
drmach_mbox_getmsg()
{
	int			err;
	register int		msgid;
	static uint8_t		buf[DRMACH_MAX_MBOX_MSG_SIZE];
	dr_mbox_msg_t		*msg = (dr_mbox_msg_t *)buf;
	dr_proto_hdr_t		*php;
	drmach_msglist_t	*found, *entry;
	uint32_t		type = MBOXSC_MSG_REPLY;
	uint32_t		command;
	uint64_t		transid;
	uint32_t		length;

	php = &msg->p_hdr;

	while (drmach_getmsg_thread_run != 0) {
		/* get a reply message */
		command = 0;
		transid = 0;
		length = DRMACH_MAX_MBOX_MSG_SIZE;
		err = mboxsc_getmsg(KEY_SCDR, &type, &command, &transid,
		    &length, (void *)msg, drmach_to_getmsg);

		if (err) {
			/*
			 * If mboxsc_getmsg returns ETIMEDOUT or EAGAIN, then
			 * the "error" is really just a normal, transient
			 * condition and we can retry the operation right away.
			 * Any other error suggests a more serious problem,
			 * ranging from a message being too big for our buffer
			 * (EMSGSIZE) to total failure of the mailbox layer.
			 * This second class of errors is much less "transient",
			 * so rather than retrying over and over (and getting
			 * the same error over and over) as fast as we can,
			 * we'll sleep for a while before retrying.
			 */
			if ((err != ETIMEDOUT) && (err != EAGAIN)) {
				cmn_err(CE_WARN,
				    "mboxsc_getmsg failed, err=0x%x", err);
				delay(drmach_mbxerr_delay * hz);
			}
			continue;
		}

		drmach_mbox_prmsg(msg, 0);

		if (php->drproto_version != DRMBX_VERSION) {
			cmn_err(CE_WARN,
			    "mailbox version mismatch 0x%x vs 0x%x",
			    php->drproto_version, DRMBX_VERSION);

			mutex_enter(&drmach_g_mbox_mutex);
			drmach_mbox_iflag = 0;
			/* schedule a reinit handshake if one isn't pending */
			if (!drmach_mbox_ipending) {
				if (taskq_dispatch(system_taskq,
				    drmach_mbox_reinit, NULL, TQ_NOSLEEP)
				    != NULL) {
					drmach_mbox_ipending = 1;
				} else {
					cmn_err(CE_WARN, "failed to schedule "
					    "mailbox reinit");
				}
			}
			mutex_exit(&drmach_g_mbox_mutex);

			continue;
		}

		msgid = php->message_id;
		found = NULL;
		mutex_enter(&drmach_msglist_mutex);
		entry = drmach_msglist_first;
		while (entry != NULL) {
			if (entry->msgid == msgid) {
				found = entry;
				drmach_msglist_unlink(entry);
				entry = NULL;
			} else
				entry = entry->next;
		}

		if (found) {
			mutex_enter(&found->g_lock);

			found->e_code = php->error_code;
			if (found->i_buflen > 0)
				bcopy((caddr_t)&msg->msgdata, found->i_buf,
				    found->i_buflen);
			found->m_reply = 1;

			cv_signal(&found->g_cv);
			mutex_exit(&found->g_lock);
		} else {
			cmn_err(CE_WARN, "!mbox_getmsg: no match for id 0x%x",
			    msgid);
			cmn_err(CE_WARN, "!    cmd = 0x%x, exb = %d, slot = %d",
			    php->command, php->expbrd, php->slot);
		}

		mutex_exit(&drmach_msglist_mutex);
	}
	cmn_err(CE_WARN, "mbox_getmsg: exiting");
	mutex_enter(&drmach_msglist_mutex);
	entry = drmach_msglist_first;
	while (entry != NULL) {
		if (entry->p_flag == 1) {
			entry->f_error = -1;
			mutex_enter(&entry->g_lock);
			cv_signal(&entry->g_cv);
			mutex_exit(&entry->g_lock);
			drmach_msglist_unlink(entry);
		}
		entry = entry->next;
	}
	mutex_exit(&drmach_msglist_mutex);
	drmach_getmsg_thread_run = -1;
	thread_exit();
}

void
drmach_mbox_sendmsg()
{
	int		err, retry;
	drmach_msglist_t *entry;
	dr_mbox_msg_t   *mp;
	dr_proto_hdr_t  *php;

	while (drmach_sendmsg_thread_run != 0) {
		/*
		 * Search through the list to find entries awaiting
		 * transmission to the SC
		 */
		mutex_enter(&drmach_msglist_mutex);
		entry = drmach_msglist_first;
		retry = 0;
		while (entry != NULL) {
			if (entry->p_flag == 1) {
				entry = entry->next;
				continue;
			}

			mutex_exit(&drmach_msglist_mutex);

			if (!retry)
				mutex_enter(&entry->s_lock);
			mp = (dr_mbox_msg_t *)entry->o_buf;
			php = &mp->p_hdr;

			drmach_mbox_prmsg(mp, 1);

			err = mboxsc_putmsg(KEY_DRSC, MBOXSC_MSG_REQUEST,
			    php->command, NULL, entry->o_buflen, (void *)mp,
			    drmach_to_putmsg);

			if (err) {
				switch (err) {

				case EAGAIN:
				case EBUSY:
					++retry;
					mutex_enter(&drmach_msglist_mutex);
					continue;

				case ETIMEDOUT:
					if (--entry->o_nretry <= 0) {
						mutex_enter(
						    &drmach_msglist_mutex);
						drmach_msglist_unlink(entry);
						mutex_exit(
						    &drmach_msglist_mutex);
						entry->f_error = err;
						entry->p_flag = 1;
						cv_signal(&entry->s_cv);
					} else {
						++retry;
						mutex_enter(
						    &drmach_msglist_mutex);
						continue;
					}
					break;
				default:
					mutex_enter(&drmach_msglist_mutex);
					drmach_msglist_unlink(entry);
					mutex_exit(&drmach_msglist_mutex);
					entry->f_error = err;
					entry->p_flag = 1;
					cv_signal(&entry->s_cv);
					break;
				}
			} else {
				entry->p_flag = 1;
				cv_signal(&entry->s_cv);
			}

			mutex_exit(&entry->s_lock);
			retry = 0;
			mutex_enter(&drmach_msglist_mutex);
			entry = drmach_msglist_first;
		}
		mutex_exit(&drmach_msglist_mutex);

		mutex_enter(&drmach_sendmsg_mutex);
		(void) cv_reltimedwait(&drmach_sendmsg_cv,
		    &drmach_sendmsg_mutex, (5 * hz), TR_CLOCK_TICK);
		mutex_exit(&drmach_sendmsg_mutex);
	}
	cmn_err(CE_WARN, "mbox_sendmsg: exiting");
	mutex_enter(&drmach_msglist_mutex);
	entry = drmach_msglist_first;
	while (entry != NULL) {
		if (entry->p_flag == 0) {
			entry->f_error = -1;
			mutex_enter(&entry->s_lock);
			cv_signal(&entry->s_cv);
			mutex_exit(&entry->s_lock);
			drmach_msglist_unlink(entry);
		}
		entry = entry->next;
	}
	mutex_exit(&drmach_msglist_mutex);
	cv_destroy(&drmach_sendmsg_cv);
	mutex_destroy(&drmach_sendmsg_mutex);

	drmach_sendmsg_thread_run = -1;
	thread_exit();
}

void
drmach_msglist_destroy(drmach_msglist_t *listp)
{
	if (listp != NULL) {
		drmach_msglist_t	*entry;

		mutex_enter(&drmach_msglist_mutex);
		entry = drmach_msglist_first;
		while (entry) {
			if (listp == entry) {
				drmach_msglist_unlink(listp);
				entry = NULL;
			} else
				entry = entry->next;
		}

		mutex_destroy(&listp->s_lock);
		cv_destroy(&listp->s_cv);
		mutex_destroy(&listp->g_lock);
		cv_destroy(&listp->g_cv);
		kmem_free(listp, sizeof (drmach_msglist_t));

		mutex_exit(&drmach_msglist_mutex);
	}
}

static drmach_msglist_t	*
drmach_msglist_new(caddr_t ibufp, uint32_t ilen, dr_proto_hdr_t *hdrp,
	uint32_t olen, int nrtry)
{
	drmach_msglist_t	*listp;

	listp = kmem_zalloc(sizeof (drmach_msglist_t), KM_SLEEP);
	mutex_init(&listp->s_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&listp->s_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&listp->g_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&listp->g_cv, NULL, CV_DRIVER, NULL);
	listp->o_buf = (caddr_t)hdrp;
	listp->o_buflen = olen;
	listp->i_buf = ibufp;
	listp->i_buflen = ilen;
	listp->o_nretry = nrtry;
	listp->msgid = hdrp->message_id;

	return (listp);
}

static drmach_msglist_t *
drmach_mbox_req_rply(dr_proto_hdr_t *hdrp, uint32_t olen, caddr_t ibufp,
	uint32_t ilen, int timeout, int nrtry, int nosig,
	drmach_msglist_t *link)
{
	int		crv;
	drmach_msglist_t *listp;
	clock_t		to_val;
	dr_proto_hdr_t	*php;

	/* setup transaction list entry */
	listp = drmach_msglist_new(ibufp, ilen, hdrp, olen, nrtry);

	/* send mailbox message, await reply */
	mutex_enter(&listp->s_lock);
	mutex_enter(&listp->g_lock);

	listp->link = link;
	drmach_msglist_link(listp);

	mutex_enter(&drmach_sendmsg_mutex);
	cv_signal(&drmach_sendmsg_cv);
	mutex_exit(&drmach_sendmsg_mutex);

	while (listp->p_flag == 0) {
		cv_wait(&listp->s_cv, &listp->s_lock);
	}

	to_val = ddi_get_lbolt() + (timeout * hz);

	if (listp->f_error) {
		listp->p_flag = 0;
		cmn_err(CE_WARN, "!mboxsc_putmsg failed: 0x%x", listp->f_error);
		php = (dr_proto_hdr_t *)listp->o_buf;
		cmn_err(CE_WARN, "!    cmd = 0x%x, exb = %d, slot = %d",
		    php->command, php->expbrd, php->slot);
	} else {
		while (listp->m_reply == 0 && listp->f_error == 0) {
			if (nosig)
				crv = cv_timedwait(&listp->g_cv, &listp->g_lock,
				    to_val);
			else
				crv = cv_timedwait_sig(&listp->g_cv,
				    &listp->g_lock, to_val);
			switch (crv) {
				case -1: /* timed out */
					cmn_err(CE_WARN,
					    "!msgid=0x%x reply timed out",
					    hdrp->message_id);
					php = (dr_proto_hdr_t *)listp->o_buf;
					cmn_err(CE_WARN, "!    cmd = 0x%x, "
					    "exb = %d, slot = %d", php->command,
					    php->expbrd, php->slot);
					listp->f_error = ETIMEDOUT;
					break;
				case 0: /* signal received */
					cmn_err(CE_WARN,
					    "operation interrupted by signal");
					listp->f_error = EINTR;
					break;
				default:
					break;
				}
		}

		/*
		 * If link is set for this entry, check to see if
		 * the linked entry has been replied to.  If not,
		 * wait for the response.
		 * Currently, this is only used for ABORT_TEST functionality,
		 * wherein a check is made for the TESTBOARD reply when
		 * the ABORT_TEST reply is received.
		 */

		if (link) {
			mutex_enter(&link->g_lock);
			/*
			 * If the reply to the linked entry hasn't been
			 * received, clear the existing link->f_error,
			 * and await the reply.
			 */
			if (link->m_reply == 0) {
				link->f_error = 0;
			}
			to_val =  ddi_get_lbolt() + (timeout * hz);
			while (link->m_reply == 0 && link->f_error == 0) {
				crv = cv_timedwait(&link->g_cv, &link->g_lock,
				    to_val);
				switch (crv) {
				case -1: /* timed out */
					cmn_err(CE_NOTE,
					    "!link msgid=0x%x reply timed out",
					    link->msgid);
					link->f_error = ETIMEDOUT;
					break;
				default:
					break;
				}
			}
			mutex_exit(&link->g_lock);
		}
	}
	mutex_exit(&listp->g_lock);
	mutex_exit(&listp->s_lock);
	return (listp);
}

static sbd_error_t *
drmach_mbx2sbderr(drmach_msglist_t *mlp)
{
	char		a_pnt[MAXNAMELEN];
	dr_proto_hdr_t	*php;
	int		bnum;

	if (mlp->f_error) {
		/*
		 * If framework failure is due to signal, return "no error"
		 * error.
		 */
		if (mlp->f_error == EINTR)
			return (drerr_new(0, ESTC_NONE, NULL));

		mutex_enter(&drmach_g_mbox_mutex);
		drmach_mbox_iflag = 0;
		mutex_exit(&drmach_g_mbox_mutex);
		if (!mlp->p_flag)
			return (drerr_new(1, ESTC_MBXRQST, NULL));
		else
			return (drerr_new(1, ESTC_MBXRPLY, NULL));
	}
	php = (dr_proto_hdr_t *)mlp->o_buf;
	bnum = 2 * php->expbrd + php->slot;
	a_pnt[0] = '\0';
	(void) drmach_board_name(bnum, a_pnt, MAXNAMELEN);

	switch (mlp->e_code) {
		case 0:
			return (NULL);
		case DRERR_NOACL:
			return (drerr_new(0, ESTC_NOACL, "%s", a_pnt));
		case DRERR_NOT_ASSIGNED:
			return (drerr_new(0, ESTC_NOT_ASSIGNED, "%s", a_pnt));
		case DRERR_NOT_ACTIVE:
			return (drerr_new(0, ESTC_NOT_ACTIVE, "%s", a_pnt));
		case DRERR_EMPTY_SLOT:
			return (drerr_new(0, ESTC_EMPTY_SLOT, "%s", a_pnt));
		case DRERR_POWER_OFF:
			return (drerr_new(0, ESTC_POWER_OFF, "%s", a_pnt));
		case DRERR_TEST_IN_PROGRESS:
			return (drerr_new(0, ESTC_TEST_IN_PROGRESS, "%s",
			    a_pnt));
		case DRERR_TESTING_BUSY:
			return (drerr_new(0, ESTC_TESTING_BUSY, "%s", a_pnt));
		case DRERR_TEST_REQUIRED:
			return (drerr_new(0, ESTC_TEST_REQUIRED, "%s", a_pnt));
		case DRERR_UNAVAILABLE:
			return (drerr_new(0, ESTC_UNAVAILABLE, "%s", a_pnt));
		case DRERR_RECOVERABLE:
			return (drerr_new(0, ESTC_SMS_ERR_RECOVERABLE, "%s",
			    a_pnt));
		case DRERR_UNRECOVERABLE:
			return (drerr_new(1, ESTC_SMS_ERR_UNRECOVERABLE, "%s",
			    a_pnt));
		default:
			return (drerr_new(1, ESTC_MBOX_UNKNOWN, NULL));
	}
}

static sbd_error_t *
drmach_mbox_trans(uint8_t msgtype, int bnum, caddr_t obufp, int olen,
	caddr_t ibufp, int ilen)
{
	int			timeout = 0;
	int			ntries = 0;
	int			nosignals = 0;
	dr_proto_hdr_t 		*hdrp;
	drmach_msglist_t 	*mlp;
	sbd_error_t		*err = NULL;

	if (msgtype != DRMSG_MBOX_INIT) {
		mutex_enter(&drmach_ri_mbox_mutex);
		mutex_enter(&drmach_g_mbox_mutex);
		if (drmach_mbox_iflag == 0) {
			/* need to initialize the mailbox */
			dr_proto_hdr_t	imsg;

			mutex_exit(&drmach_g_mbox_mutex);

			imsg.command = DRMSG_MBOX_INIT;

			imsg.message_id = drmach_get_msgid();
			imsg.drproto_version = DRMBX_VERSION;
			imsg.expbrd = 0;
			imsg.slot = 0;

			cmn_err(CE_WARN, "!reinitializing DR mailbox");
			mlp = drmach_mbox_req_rply(&imsg, sizeof (imsg), 0, 0,
			    10, 5, 0, NULL);
			err = drmach_mbx2sbderr(mlp);
			/*
			 * If framework failure incoming is encountered on
			 * the MBOX_INIT [timeout on SMS reply], the error
			 * type must be changed before returning to caller.
			 * This is to prevent drmach_board_connect() and
			 * drmach_board_disconnect() from marking boards
			 * UNUSABLE based on MBOX_INIT failures.
			 */
			if ((err != NULL) && (err->e_code == ESTC_MBXRPLY)) {
				cmn_err(CE_WARN,
				    "!Changed mbox incoming to outgoing"
				    " failure on reinit");
				sbd_err_clear(&err);
				err = drerr_new(0, ESTC_MBXRQST, NULL);
			}
			drmach_msglist_destroy(mlp);
			if (err) {
				mutex_exit(&drmach_ri_mbox_mutex);
				return (err);
			}
			mutex_enter(&drmach_g_mbox_mutex);
			drmach_mbox_iflag = 1;
		}
		mutex_exit(&drmach_g_mbox_mutex);
		mutex_exit(&drmach_ri_mbox_mutex);
	}

	hdrp = (dr_proto_hdr_t *)obufp;

	/* setup outgoing mailbox header */
	hdrp->command = msgtype;
	hdrp->message_id = drmach_get_msgid();
	hdrp->drproto_version = DRMBX_VERSION;
	hdrp->expbrd = DRMACH_BNUM2EXP(bnum);
	hdrp->slot = DRMACH_BNUM2SLOT(bnum);

	switch (msgtype) {

		case DRMSG_MBOX_INIT:
			timeout = drmach_to_mbxinit;
			ntries = 1;
			nosignals = 0;
			break;

		case DRMSG_ASSIGN:
			timeout = drmach_to_assign;
			ntries = 1;
			nosignals = 0;
			break;

		case DRMSG_UNASSIGN:
			timeout = drmach_to_unassign;
			ntries = 1;
			nosignals = 0;
			break;

		case DRMSG_POWERON:
			timeout = drmach_to_poweron;
			ntries = 1;
			nosignals = 0;
			break;

		case DRMSG_POWEROFF:
			timeout = drmach_to_poweroff;
			ntries = 1;
			nosignals = 0;
			break;

		case DRMSG_SHOWBOARD:
			timeout = drmach_to_showboard;
			ntries = 1;
			nosignals = 0;
			break;

		case DRMSG_CLAIM:
			timeout = drmach_to_claim;
			ntries = 1;
			nosignals = 1;
			break;

		case DRMSG_UNCLAIM:
			timeout = drmach_to_unclaim;
			ntries = 1;
			nosignals = 1;
			break;

		case DRMSG_UNCONFIG:
			timeout = drmach_to_unconfig;
			ntries = 1;
			nosignals = 0;
			break;

		case DRMSG_TESTBOARD:
			timeout = drmach_to_testboard;
			ntries = 1;
			nosignals = 0;
			break;

		default:
			cmn_err(CE_WARN, "Unknown outgoing message type 0x%x",
			    msgtype);
			err = DRMACH_INTERNAL_ERROR();
			break;
	}

	if (err == NULL) {
		mlp = drmach_mbox_req_rply(hdrp, olen, ibufp, ilen, timeout,
		    ntries, nosignals, NULL);
		err = drmach_mbx2sbderr(mlp);

		/*
		 * For DRMSG_TESTBOARD attempts which have timed out, or
		 * been aborted due to a signal received after mboxsc_putmsg()
		 * has succeeded in sending the message, a DRMSG_ABORT_TEST
		 * must be sent.
		 */
		if ((msgtype == DRMSG_TESTBOARD) && (err != NULL) &&
		    ((mlp->f_error == EINTR) || ((mlp->f_error == ETIMEDOUT) &&
		    (mlp->p_flag != 0)))) {
			drmach_msglist_t	*abmlp;
			dr_abort_test_t		abibuf;

			hdrp->command = DRMSG_ABORT_TEST;
			hdrp->message_id = drmach_get_msgid();
			abmlp = drmach_mbox_req_rply(hdrp,
			    sizeof (dr_abort_test_t), (caddr_t)&abibuf,
			    sizeof (abibuf), drmach_to_aborttest, 5, 1, mlp);
			cmn_err(CE_WARN, "test aborted");
			drmach_msglist_destroy(abmlp);
		}

		drmach_msglist_destroy(mlp);
	}

	return (err);
}

static int
drmach_mbox_init()
{
	int			err;
	caddr_t			obufp;
	sbd_error_t		*serr = NULL;
	mboxsc_timeout_range_t	mbxtoz;

	drmach_mbox_istate = 0;
	/* register the outgoing mailbox */
	if ((err = mboxsc_init(KEY_DRSC, MBOXSC_MBOX_OUT,
	    NULL)) != 0) {
		cmn_err(CE_WARN, "DR - SC mboxsc_init failed: 0x%x", err);
		return (-1);
	}
	drmach_mbox_istate = 1;

	/* setup the mboxsc_putmsg timeout value */
	if (drmach_use_tuned_putmsg_to) {
		cmn_err(CE_NOTE, "!using tuned drmach_to_putmsg = 0x%lx\n",
		    drmach_to_putmsg);
	} else {
		if ((err = mboxsc_ctrl(KEY_DRSC,
		    MBOXSC_CMD_PUTMSG_TIMEOUT_RANGE, &mbxtoz)) != 0) {
			cmn_err(CE_WARN, "mboxsc_ctrl failed: 0x%x", err);
			drmach_to_putmsg = 60000;
		} else {
			drmach_to_putmsg = mboxsc_putmsg_def_timeout() * 6;
			DRMACH_PR("putmsg range is 0x%lx - 0x%lx value"
			    " is 0x%lx\n", mbxtoz.min_timeout,
			    mbxtoz.max_timeout, drmach_to_putmsg);
		}
	}

	/* register the incoming mailbox */
	if ((err = mboxsc_init(KEY_SCDR, MBOXSC_MBOX_IN,
	    drmach_mbox_event)) != 0) {
		cmn_err(CE_WARN, "SC - DR mboxsc_init failed: 0x%x", err);
		return (-1);
	}
	drmach_mbox_istate = 2;

	/* initialize mutex for mailbox globals */
	mutex_init(&drmach_g_mbox_mutex, NULL, MUTEX_DRIVER, NULL);

	/* initialize mutex for mailbox re-init */
	mutex_init(&drmach_ri_mbox_mutex, NULL, MUTEX_DRIVER, NULL);

	/* initialize mailbox message list elements */
	drmach_msglist_first = drmach_msglist_last = NULL;
	mutex_init(&drmach_msglist_mutex, NULL, MUTEX_DRIVER, NULL);

	mutex_init(&drmach_sendmsg_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&drmach_sendmsg_cv, NULL, CV_DRIVER, NULL);

	drmach_mbox_istate = 3;

	/* start mailbox sendmsg thread */
	drmach_sendmsg_thread_run = 1;
	if (drmach_sendmsg_thread == NULL)
		drmach_sendmsg_thread = thread_create(NULL, 0,
		    (void (*)())drmach_mbox_sendmsg, NULL, 0, &p0,
		    TS_RUN, minclsyspri);

	/* start mailbox getmsg thread */
	drmach_getmsg_thread_run = 1;
	if (drmach_getmsg_thread == NULL)
		drmach_getmsg_thread = thread_create(NULL, 0,
		    (void (*)())drmach_mbox_getmsg, NULL, 0, &p0,
		    TS_RUN, minclsyspri);

	obufp = kmem_zalloc(sizeof (dr_proto_hdr_t), KM_SLEEP);
	serr = drmach_mbox_trans(DRMSG_MBOX_INIT, 0, obufp,
	    sizeof (dr_proto_hdr_t), (caddr_t)NULL, 0);
	kmem_free(obufp, sizeof (dr_proto_hdr_t));
	if (serr) {
		cmn_err(CE_WARN, "mbox_init: MBOX_INIT failed ecode=0x%x",
		    serr->e_code);
		sbd_err_clear(&serr);
		return (-1);
	}
	mutex_enter(&drmach_g_mbox_mutex);
	drmach_mbox_iflag = 1;
	drmach_mbox_ipending = 0;
	mutex_exit(&drmach_g_mbox_mutex);

	return (0);
}

static int
drmach_mbox_fini()
{
	int err, rv = 0;

	if (drmach_mbox_istate > 2) {
		drmach_getmsg_thread_run = 0;
		drmach_sendmsg_thread_run = 0;
		cmn_err(CE_WARN,
		    "drmach_mbox_fini: waiting for mbox threads...");
		while ((drmach_getmsg_thread_run == 0) ||
		    (drmach_sendmsg_thread_run == 0)) {
			continue;
		}
		cmn_err(CE_WARN, "drmach_mbox_fini: mbox threads done.");
		mutex_destroy(&drmach_msglist_mutex);

	}
	if (drmach_mbox_istate) {
		/* de-register the outgoing mailbox */
		if ((err = mboxsc_fini(KEY_DRSC)) != 0) {
			cmn_err(CE_WARN, "DR - SC mboxsc_fini failed: 0x%x",
			    err);
			rv = -1;
		}
	}
	if (drmach_mbox_istate > 1) {
		/* de-register the incoming mailbox */
		if ((err = mboxsc_fini(KEY_SCDR)) != 0) {
			cmn_err(CE_WARN, "SC - DR mboxsc_fini failed: 0x%x",
			    err);
			rv = -1;
		}
	}
	mutex_destroy(&drmach_g_mbox_mutex);
	mutex_destroy(&drmach_ri_mbox_mutex);
	return (rv);
}

static int
drmach_portid2bnum(int portid)
{
	int slot;

	switch (portid & 0x1f) {
	case 0: case 1: case 2: case 3:	/* cpu/wci devices */
	case 0x1e:			/* slot 0 axq registers */
		slot = 0;
		break;

	case 8: case 9:			/* cpu devices */
	case 0x1c: case 0x1d:		/* schizo/wci devices */
	case 0x1f:			/* slot 1 axq registers */
		slot = 1;
		break;

	default:
		ASSERT(0);		/* catch in debug kernels */
	}

	return (((portid >> 4) & 0x7e) | slot);
}

extern int axq_suspend_iopause;

static int
hold_rele_branch(dev_info_t *rdip, void *arg)
{
	int	i;
	int	*holdp	= (int *)arg;
	char	*name = ddi_node_name(rdip);

	/*
	 * For Starcat, we must be children of the root devinfo node
	 */
	ASSERT(ddi_get_parent(rdip) == ddi_root_node());

	i = drmach_name2type_idx(name);

	/*
	 * Only children of the root devinfo node need to be
	 * held/released since they are the only valid targets
	 * of tree operations. This corresponds to the node types
	 * listed in the drmach_name2type array.
	 */
	if (i < 0) {
		/* Not of interest to us */
		return (DDI_WALK_PRUNECHILD);
	}

	if (*holdp) {
		ASSERT(!e_ddi_branch_held(rdip));
		e_ddi_branch_hold(rdip);
	} else {
		ASSERT(e_ddi_branch_held(rdip));
		e_ddi_branch_rele(rdip);
	}

	return (DDI_WALK_PRUNECHILD);
}

static int
drmach_init(void)
{
	pnode_t 	nodeid;
	gdcd_t		*gdcd;
	int		bnum;
	dev_info_t	*rdip;
	int		hold, circ;

	mutex_enter(&drmach_i_lock);
	if (drmach_initialized) {
		mutex_exit(&drmach_i_lock);
		return (0);
	}

	gdcd = drmach_gdcd_new();
	if (gdcd == NULL) {
		mutex_exit(&drmach_i_lock);
		cmn_err(CE_WARN, "drmach_init: failed to access GDCD\n");
		return (-1);
	}

	drmach_boards = drmach_array_new(0, MAX_BOARDS - 1);

	nodeid = prom_childnode(prom_rootnode());
	do {
		int		 len;
		int		 portid;
		drmachid_t	 id;

		len = prom_getproplen(nodeid, "portid");
		if (len != sizeof (portid))
			continue;

		portid = -1;
		(void) prom_getprop(nodeid, "portid", (caddr_t)&portid);
		if (portid == -1)
			continue;

		bnum = drmach_portid2bnum(portid);

		if (drmach_array_get(drmach_boards, bnum, &id) == -1) {
			/* portid translated to an invalid board number */
			cmn_err(CE_WARN, "OBP node 0x%x has"
			    " invalid property value, %s=%u",
			    nodeid, "portid", portid);

			/* clean up */
			drmach_array_dispose(drmach_boards,
			    drmach_board_dispose);
			drmach_gdcd_dispose(gdcd);
			mutex_exit(&drmach_i_lock);
			return (-1);
		} else if (id == NULL) {
			drmach_board_t	*bp;
			l1_slot_stat_t	*dcd;
			int		exp, slot;

			bp = drmach_board_new(bnum);
			bp->assigned = !drmach_initialized;
			bp->powered = !drmach_initialized;

			exp = DRMACH_BNUM2EXP(bnum);
			slot = DRMACH_BNUM2SLOT(bnum);
			dcd = &gdcd->dcd_slot[exp][slot];
			bp->stardrb_offset =
			    dcd->l1ss_cpu_drblock_xwd_offset << 3;
			DRMACH_PR("%s: stardrb_offset=0x%lx\n", bp->cm.name,
			    bp->stardrb_offset);

			if (gdcd->dcd_slot[exp][slot].l1ss_flags &
			    L1SSFLG_THIS_L1_NULL_PROC_LPA) {
				bp->flags |= DRMACH_NULL_PROC_LPA;
				DRMACH_PR("%s: NULL proc LPA\n", bp->cm.name);
			}
		}
	} while ((nodeid = prom_nextnode(nodeid)) != OBP_NONODE);

	drmach_cpu_sram_va = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);

	if (gdcd->dcd_testcage_log2_mbytes_size != DCD_DR_TESTCAGE_DISABLED) {
		ASSERT(gdcd->dcd_testcage_log2_mbytes_size ==
		    gdcd->dcd_testcage_log2_mbytes_align);
		drmach_iocage_paddr =
		    (uint64_t)gdcd->dcd_testcage_mbyte_PA << 20;
		drmach_iocage_size =
		    1 << (gdcd->dcd_testcage_log2_mbytes_size + 20);

		drmach_iocage_vaddr = (caddr_t)vmem_alloc(heap_arena,
		    drmach_iocage_size, VM_SLEEP);
		hat_devload(kas.a_hat, drmach_iocage_vaddr, drmach_iocage_size,
		    mmu_btop(drmach_iocage_paddr),
		    PROT_READ | PROT_WRITE,
		    HAT_LOAD_LOCK | HAT_LOAD_NOCONSIST);

		DRMACH_PR("gdcd size=0x%x align=0x%x PA=0x%x\n",
		    gdcd->dcd_testcage_log2_mbytes_size,
		    gdcd->dcd_testcage_log2_mbytes_align,
		    gdcd->dcd_testcage_mbyte_PA);
		DRMACH_PR("drmach size=0x%x PA=0x%lx VA=0x%p\n",
		    drmach_iocage_size, drmach_iocage_paddr,
		    (void *)drmach_iocage_vaddr);
	}

	if (drmach_iocage_size == 0) {
		drmach_array_dispose(drmach_boards, drmach_board_dispose);
		drmach_boards = NULL;
		vmem_free(heap_arena, drmach_cpu_sram_va, PAGESIZE);
		drmach_gdcd_dispose(gdcd);
		mutex_exit(&drmach_i_lock);
		cmn_err(CE_WARN, "drmach_init: iocage not available\n");
		return (-1);
	}

	drmach_gdcd_dispose(gdcd);

	mutex_init(&drmach_iocage_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&drmach_iocage_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&drmach_xt_mb_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&drmach_bus_sync_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&drmach_slice_table_lock, NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&cpu_lock);
	mutex_enter(&drmach_iocage_lock);
	ASSERT(drmach_iocage_is_busy == 0);
	drmach_iocage_is_busy = 1;
	drmach_iocage_mem_scrub(drmach_iocage_size);
	drmach_iocage_is_busy = 0;
	cv_signal(&drmach_iocage_cv);
	mutex_exit(&drmach_iocage_lock);
	mutex_exit(&cpu_lock);


	if (drmach_mbox_init() == -1) {
		cmn_err(CE_WARN, "DR - SC mailbox initialization Failed");
	}

	/*
	 * Walk immediate children of devinfo root node and hold
	 * all devinfo branches of interest.
	 */
	hold = 1;
	rdip = ddi_root_node();

	ndi_devi_enter(rdip, &circ);
	ddi_walk_devs(ddi_get_child(rdip), hold_rele_branch, &hold);
	ndi_devi_exit(rdip, circ);

	drmach_initialized = 1;

	/*
	 * To avoid a circular patch dependency between DR and AXQ, the AXQ
	 * rev introducing the axq_iopause_*_all interfaces should not regress
	 * when installed without the DR rev using those interfaces. The default
	 * is for iopause to be enabled/disabled during axq suspend/resume. By
	 * setting the following axq flag to zero, axq will not enable iopause
	 * during suspend/resume, instead DR will call the axq_iopause_*_all
	 * interfaces during drmach_copy_rename.
	 */
	axq_suspend_iopause = 0;

	mutex_exit(&drmach_i_lock);

	return (0);
}

static void
drmach_fini(void)
{
	dev_info_t	*rdip;
	int		hold, circ;

	if (drmach_initialized) {
		rw_enter(&drmach_boards_rwlock, RW_WRITER);
		drmach_array_dispose(drmach_boards, drmach_board_dispose);
		drmach_boards = NULL;
		rw_exit(&drmach_boards_rwlock);

		mutex_destroy(&drmach_slice_table_lock);
		mutex_destroy(&drmach_xt_mb_lock);
		mutex_destroy(&drmach_bus_sync_lock);
		cv_destroy(&drmach_iocage_cv);
		mutex_destroy(&drmach_iocage_lock);

		vmem_free(heap_arena, drmach_cpu_sram_va, PAGESIZE);

		/*
		 * Walk immediate children of the root devinfo node
		 * releasing holds acquired on branches in drmach_init()
		 */
		hold = 0;
		rdip = ddi_root_node();

		ndi_devi_enter(rdip, &circ);
		ddi_walk_devs(ddi_get_child(rdip), hold_rele_branch, &hold);
		ndi_devi_exit(rdip, circ);

		drmach_initialized = 0;
	}

	(void) drmach_mbox_fini();
	if (drmach_xt_mb != NULL) {
		vmem_free(static_alloc_arena, (void *)drmach_xt_mb,
		    drmach_xt_mb_size);
	}
	rw_destroy(&drmach_boards_rwlock);
	mutex_destroy(&drmach_i_lock);
}

static void
drmach_mem_read_madr(drmach_mem_t *mp, int bank, uint64_t *madr)
{
	kpreempt_disable();

	/* get register address, read madr value */
	if (STARCAT_CPUID_TO_PORTID(CPU->cpu_id) == mp->dev.portid) {
		*madr = lddmcdecode(DRMACH_MC_ASI_ADDR(mp, bank));
	} else {
		*madr = lddphysio(DRMACH_MC_ADDR(mp, bank));
	}

	kpreempt_enable();
}


static uint64_t *
drmach_prep_mc_rename(uint64_t *p, int local,
	drmach_mem_t *mp, uint64_t current_basepa, uint64_t new_basepa)
{
	int bank;

	for (bank = 0; bank < DRMACH_MC_NBANKS; bank++) {
		uint64_t madr, bank_offset;

		/* fetch mc's bank madr register value */
		drmach_mem_read_madr(mp, bank, &madr);
		if (madr & DRMACH_MC_VALID_MASK) {
			uint64_t bankpa;

			bank_offset = (DRMACH_MC_UM_TO_PA(madr) |
			    DRMACH_MC_LM_TO_PA(madr)) - current_basepa;
			bankpa = new_basepa + bank_offset;

			/* encode new base pa into madr */
			madr &= ~DRMACH_MC_UM_MASK;
			madr |= DRMACH_MC_PA_TO_UM(bankpa);
			madr &= ~DRMACH_MC_LM_MASK;
			madr |= DRMACH_MC_PA_TO_LM(bankpa);

			if (local)
				*p++ = DRMACH_MC_ASI_ADDR(mp, bank);
			else
				*p++ = DRMACH_MC_ADDR(mp, bank);

			*p++ = madr;
		}
	}

	return (p);
}

static uint64_t *
drmach_prep_schizo_script(uint64_t *p, drmach_mem_t *mp, uint64_t new_basepa)
{
	drmach_board_t	*bp;
	int		 rv;
	int		 idx;
	drmachid_t	 id;
	uint64_t	 last_scsr_pa = 0;

	/* memory is always in slot 0 */
	ASSERT(DRMACH_BNUM2SLOT(mp->dev.bp->bnum) == 0);

	/* look up slot 1 board on same expander */
	idx = DRMACH_EXPSLOT2BNUM(DRMACH_BNUM2EXP(mp->dev.bp->bnum), 1);
	rv = drmach_array_get(drmach_boards, idx, &id);
	bp = id; /* bp will be NULL if board not found */

	/* look up should never be out of bounds */
	ASSERT(rv == 0);

	/* nothing to do when board is not found or has no devices */
	if (rv == -1 || bp == NULL || bp->devices == NULL)
		return (p);

	rv = drmach_array_first(bp->devices, &idx, &id);
	while (rv == 0) {
		if (DRMACH_IS_IO_ID(id)) {
			drmach_io_t *io = id;

			/*
			 * Skip all non-Schizo IO devices (only IO nodes
			 * that are Schizo devices have non-zero scsr_pa).
			 * Filter out "other" leaf to avoid writing to the
			 * same Schizo Control/Status Register twice.
			 */
			if (io->scsr_pa && io->scsr_pa != last_scsr_pa) {
				uint64_t scsr;

				scsr  = lddphysio(io->scsr_pa);
				scsr &= ~(DRMACH_LPA_BASE_MASK |
				    DRMACH_LPA_BND_MASK);
				scsr |= DRMACH_PA_TO_LPA_BASE(new_basepa);
				scsr |= DRMACH_PA_TO_LPA_BND(
				    new_basepa + DRMACH_MEM_SLICE_SIZE);

				*p++ = io->scsr_pa;
				*p++ = scsr;

				last_scsr_pa = io->scsr_pa;
			}
		}
		rv = drmach_array_next(bp->devices, &idx, &id);
	}

	return (p);
}

/*
 * For Panther MCs, append the MC idle reg address and drmach_mem_t pointer.
 * The latter is returned when drmach_rename fails to idle a Panther MC and
 * is used to identify the MC for error reporting.
 */
static uint64_t *
drmach_prep_pn_mc_idle(uint64_t *p, drmach_mem_t *mp, int local)
{
	/* only slot 0 has memory */
	ASSERT(DRMACH_BNUM2SLOT(mp->dev.bp->bnum) == 0);
	ASSERT(IS_PANTHER(mp->dev.bp->cpu_impl));

	for (mp = mp->dev.bp->mem; mp != NULL; mp = mp->next) {
		ASSERT(DRMACH_IS_MEM_ID(mp));

		if (mp->dev.portid == STARCAT_CPUID_TO_PORTID(CPU->cpu_id)) {
			if (local) {
				*p++ = ASI_EMU_ACT_STATUS_VA;	/* local ASI */
				*p++ = (uintptr_t)mp;
			}
		} else if (!local) {
			*p++ = DRMACH_EMU_ACT_STATUS_ADDR(mp);	/* PIO */
			*p++ = (uintptr_t)mp;
		}
	}

	return (p);
}

static sbd_error_t *
drmach_prep_rename_script(drmach_mem_t *s_mp, drmach_mem_t *t_mp,
	uint64_t t_slice_offset, caddr_t buf, int buflen)
{
	_NOTE(ARGUNUSED(buflen))

	uint64_t		*p = (uint64_t *)buf, *q;
	sbd_error_t		*err;
	int			 rv;
	drmach_mem_t		*mp, *skip_mp;
	uint64_t		 s_basepa, t_basepa;
	uint64_t		 s_new_basepa, t_new_basepa;

	/* verify supplied buffer space is adequate */
	ASSERT(buflen >=
	    /* addr for all possible MC banks */
	    (sizeof (uint64_t) * 4 * 4 * 18) +
	    /* list section terminator */
	    (sizeof (uint64_t) * 1) +
	    /* addr/id tuple for local Panther MC idle reg */
	    (sizeof (uint64_t) * 2) +
	    /* list section terminator */
	    (sizeof (uint64_t) * 1) +
	    /* addr/id tuple for 2 boards with 4 Panther MC idle regs */
	    (sizeof (uint64_t) * 2 * 2 * 4) +
	    /* list section terminator */
	    (sizeof (uint64_t) * 1) +
	    /* addr/val tuple for 1 proc with 4 MC banks */
	    (sizeof (uint64_t) * 2 * 4) +
	    /* list section terminator */
	    (sizeof (uint64_t) * 1) +
	    /* addr/val tuple for 2 boards w/ 2 schizos each */
	    (sizeof (uint64_t) * 2 * 2 * 2) +
	    /* addr/val tuple for 2 boards w/ 16 MC banks each */
	    (sizeof (uint64_t) * 2 * 2 * 16) +
	    /* list section terminator */
	    (sizeof (uint64_t) * 1) +
	    /* addr/val tuple for 18 AXQs w/ two slots each */
	    (sizeof (uint64_t) * 2 * 2 * 18) +
	    /* list section terminator */
	    (sizeof (uint64_t) * 1) +
	    /* list terminator */
	    (sizeof (uint64_t) * 1));

	/* copy bank list to rename script */
	mutex_enter(&drmach_bus_sync_lock);
	for (q = drmach_bus_sync_list; *q; q++, p++)
		*p = *q;
	mutex_exit(&drmach_bus_sync_lock);

	/* list section terminator */
	*p++ = 0;

	/*
	 * Write idle script for MC on this processor.  A script will be
	 * produced only if this is a Panther processor on the source or
	 * target board.
	 */
	if (IS_PANTHER(s_mp->dev.bp->cpu_impl))
		p = drmach_prep_pn_mc_idle(p, s_mp, 1);

	if (IS_PANTHER(t_mp->dev.bp->cpu_impl))
		p = drmach_prep_pn_mc_idle(p, t_mp, 1);

	/* list section terminator */
	*p++ = 0;

	/*
	 * Write idle script for all other MCs on source and target
	 * Panther boards.
	 */
	if (IS_PANTHER(s_mp->dev.bp->cpu_impl))
		p = drmach_prep_pn_mc_idle(p, s_mp, 0);

	if (IS_PANTHER(t_mp->dev.bp->cpu_impl))
		p = drmach_prep_pn_mc_idle(p, t_mp, 0);

	/* list section terminator */
	*p++ = 0;

	/*
	 * Step 1:	Write source base address to target MC
	 *		with present bit off.
	 * Step 2:	Now rewrite target reg with present bit on.
	 */
	err = drmach_mem_get_base_physaddr(s_mp, &s_basepa);
	ASSERT(err == NULL);
	err = drmach_mem_get_base_physaddr(t_mp, &t_basepa);
	ASSERT(err == NULL);

	/* exchange base pa. include slice offset in new target base pa */
	s_new_basepa = t_basepa & ~ (DRMACH_MEM_SLICE_SIZE - 1);
	t_new_basepa = (s_basepa & ~ (DRMACH_MEM_SLICE_SIZE - 1)) +
	    t_slice_offset;

	DRMACH_PR("s_new_basepa 0x%lx\n", s_new_basepa);
	DRMACH_PR("t_new_basepa 0x%lx\n", t_new_basepa);

	DRMACH_PR("preparing MC MADR rename script (master is CPU%d):\n",
	    CPU->cpu_id);

	/*
	 * Write rename script for MC on this processor.  A script will
	 * be produced only if this processor is on the source or target
	 * board.
	 */

	skip_mp = NULL;
	mp = s_mp->dev.bp->mem;
	while (mp != NULL && skip_mp == NULL) {
		if (mp->dev.portid == STARCAT_CPUID_TO_PORTID(CPU->cpu_id)) {
			skip_mp = mp;
			p = drmach_prep_mc_rename(p, 1, mp, s_basepa,
			    s_new_basepa);
		}

		mp = mp->next;
	}

	mp = t_mp->dev.bp->mem;
	while (mp != NULL && skip_mp == NULL) {
		if (mp->dev.portid == STARCAT_CPUID_TO_PORTID(CPU->cpu_id)) {
			skip_mp = mp;
			p = drmach_prep_mc_rename(p, 1, mp, t_basepa,
			    t_new_basepa);
		}

		mp = mp->next;
	}

	/* list section terminator */
	*p++ = 0;

	/*
	 * Write rename script for all other MCs on source and target
	 * boards.
	 */

	for (mp = s_mp->dev.bp->mem; mp; mp = mp->next) {
		if (mp == skip_mp)
			continue;
		p = drmach_prep_mc_rename(p, 0, mp, s_basepa, s_new_basepa);
	}

	for (mp = t_mp->dev.bp->mem; mp; mp = mp->next) {
		if (mp == skip_mp)
			continue;
		p = drmach_prep_mc_rename(p, 0, mp, t_basepa, t_new_basepa);
	}

	/* Write rename script for Schizo LPA_BASE/LPA_BND */
	p = drmach_prep_schizo_script(p, s_mp, s_new_basepa);
	p = drmach_prep_schizo_script(p, t_mp, t_new_basepa);

	/* list section terminator */
	*p++ = 0;

	DRMACH_PR("preparing AXQ CASM rename script (EXP%d <> EXP%d):\n",
	    DRMACH_BNUM2EXP(s_mp->dev.bp->bnum),
	    DRMACH_BNUM2EXP(t_mp->dev.bp->bnum));

	rv = axq_do_casm_rename_script(&p,
	    DRMACH_PA_TO_SLICE(s_new_basepa),
	    DRMACH_PA_TO_SLICE(t_new_basepa));
	if (rv == DDI_FAILURE)
		return (DRMACH_INTERNAL_ERROR());

	/* list section & final terminator */
	*p++ = 0;
	*p++ = 0;

#ifdef DEBUG
	{
		uint64_t *q = (uint64_t *)buf;

		/* paranoia */
		ASSERT((caddr_t)p <= buf + buflen);

		DRMACH_PR("MC bank base pa list:\n");
		while (*q) {
			uint64_t a = *q++;

			DRMACH_PR("0x%lx\n", a);
		}

		/* skip terminator */
		q += 1;

		DRMACH_PR("local Panther MC idle reg (via ASI 0x4a):\n");
		while (*q) {
			DRMACH_PR("addr=0x%lx, mp=0x%lx\n", *q, *(q + 1));
			q += 2;
		}

		/* skip terminator */
		q += 1;

		DRMACH_PR("non-local Panther MC idle reg (via ASI 0x15):\n");
		while (*q) {
			DRMACH_PR("addr=0x%lx, mp=0x%lx\n", *q, *(q + 1));
			q += 2;
		}

		/* skip terminator */
		q += 1;

		DRMACH_PR("MC reprogramming script (via ASI 0x72):\n");
		while (*q) {
			uint64_t r = *q++;	/* register address */
			uint64_t v = *q++;	/* new register value */

			DRMACH_PR("0x%lx = 0x%lx, basepa 0x%lx\n",
			    r, v, (long)(DRMACH_MC_UM_TO_PA(v)|
			    DRMACH_MC_LM_TO_PA(v)));
		}

		/* skip terminator */
		q += 1;

		DRMACH_PR("MC/SCHIZO reprogramming script:\n");
		while (*q) {
			DRMACH_PR("0x%lx = 0x%lx\n", *q, *(q + 1));
			q += 2;
		}

		/* skip terminator */
		q += 1;

		DRMACH_PR("AXQ reprogramming script:\n");
		while (*q) {
			DRMACH_PR("0x%lx = 0x%lx\n", *q, *(q + 1));
			q += 2;
		}

		/* verify final terminator is present */
		ASSERT(*(q + 1) == 0);

		DRMACH_PR("copy-rename script 0x%p, len %d\n",
		    (void *)buf, (int)((intptr_t)p - (intptr_t)buf));

		if (drmach_debug)
			DELAY(10000000);
	}
#endif

	return (NULL);
}

static void
drmach_prep_xt_mb_for_slice_update(drmach_board_t *bp, uchar_t slice)
{
	int		 rv;

	ASSERT(MUTEX_HELD(&drmach_xt_mb_lock));

	if (bp->devices) {
		int		 d_idx;
		drmachid_t	 d_id;

		rv = drmach_array_first(bp->devices, &d_idx, &d_id);
		while (rv == 0) {
			if (DRMACH_IS_CPU_ID(d_id)) {
				drmach_cpu_t	*cp = d_id;
				processorid_t	 cpuid = cp->cpuid;

				mutex_enter(&cpu_lock);
				if (cpu[cpuid] && cpu[cpuid]->cpu_flags)
					drmach_xt_mb[cpuid] = 0x80 | slice;
				mutex_exit(&cpu_lock);
			}
			rv = drmach_array_next(bp->devices, &d_idx, &d_id);
		}
	}
	if (DRMACH_BNUM2SLOT(bp->bnum) == 0) {
		drmach_board_t	*s1bp = NULL;

		rv = drmach_array_get(drmach_boards, bp->bnum + 1,
		    (void *) &s1bp);
		if (rv == 0 && s1bp != NULL) {
			ASSERT(DRMACH_IS_BOARD_ID(s1bp));
			ASSERT(DRMACH_BNUM2SLOT(s1bp->bnum) == 1);
			drmach_prep_xt_mb_for_slice_update(s1bp, slice);
		}
	}
}

sbd_error_t *
drmach_copy_rename_init(drmachid_t t_id, uint64_t t_slice_offset,
	drmachid_t s_id, struct memlist *c_ml, drmachid_t *cr_id)
{
	extern void drmach_rename(uint64_t *, uint_t *, uint64_t *);
	extern void drmach_rename_end(void);

	drmach_mem_t	*s_mp, *t_mp;
	struct memlist	*x_ml;
	uint64_t	 off_mask, s_copybasepa, t_copybasepa, t_basepa;
	int		 len;
	caddr_t		 bp, wp;
	uint_t		*p, *q;
	sbd_error_t	*err;
	tte_t		*tte;
	drmach_copy_rename_t *cr;

	if (!DRMACH_IS_MEM_ID(s_id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	if (!DRMACH_IS_MEM_ID(t_id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	s_mp = s_id;
	t_mp = t_id;

	/* get starting physical address of target memory */
	err = drmach_mem_get_base_physaddr(t_id, &t_basepa);
	if (err)
		return (err);

	/* calculate slice offset mask from slice size */
	off_mask = DRMACH_MEM_SLICE_SIZE - 1;

	/* calculate source and target base pa */
	s_copybasepa = c_ml->ml_address;
	t_copybasepa =
	    t_basepa + ((c_ml->ml_address & off_mask) - t_slice_offset);

	/* paranoia */
	ASSERT((c_ml->ml_address & off_mask) >= t_slice_offset);

	/* adjust copy memlist addresses to be relative to copy base pa */
	x_ml = c_ml;
	while (x_ml != NULL) {
		x_ml->ml_address -= s_copybasepa;
		x_ml = x_ml->ml_next;
	}

#ifdef DEBUG
	{
	uint64_t s_basepa, s_size, t_size;

	x_ml = c_ml;
	while (x_ml->ml_next != NULL)
		x_ml = x_ml->ml_next;

	DRMACH_PR("source copy span: base pa 0x%lx, end pa 0x%lx\n",
	    s_copybasepa,
	    s_copybasepa + x_ml->ml_address + x_ml->ml_size);

	DRMACH_PR("target copy span: base pa 0x%lx, end pa 0x%lx\n",
	    t_copybasepa,
	    t_copybasepa + x_ml->ml_address + x_ml->ml_size);

	DRMACH_PR("copy memlist (relative to copy base pa):\n");
	DRMACH_MEMLIST_DUMP(c_ml);

	err = drmach_mem_get_base_physaddr(s_id, &s_basepa);
	ASSERT(err == NULL);

	err = drmach_mem_get_size(s_id, &s_size);
	ASSERT(err == NULL);

	err = drmach_mem_get_size(t_id, &t_size);
	ASSERT(err == NULL);

	DRMACH_PR("current source base pa 0x%lx, size 0x%lx\n",
	    s_basepa, s_size);
	DRMACH_PR("current target base pa 0x%lx, size 0x%lx\n",
	    t_basepa, t_size);
	}
#endif /* DEBUG */

	/* Map in appropriate cpu sram page */
	tte = &drmach_cpu_sram_tte[CPU->cpu_id];
	ASSERT(TTE_IS_VALID(tte) && TTE_IS_8K(tte) &&
	    TTE_IS_PRIVILEGED(tte) && TTE_IS_LOCKED(tte));
	sfmmu_dtlb_ld_kva(drmach_cpu_sram_va, tte);
	sfmmu_itlb_ld_kva(drmach_cpu_sram_va, tte);

	bp = wp = drmach_cpu_sram_va;

	/* Make sure the rename routine will fit */
	len = (ptrdiff_t)drmach_rename_end - (ptrdiff_t)drmach_rename;
	ASSERT(wp + len < bp + PAGESIZE);

	/* copy text. standard bcopy not designed to work in nc space */
	p = (uint_t *)wp;
	q = (uint_t *)drmach_rename;
	while (q < (uint_t *)drmach_rename_end)
		*p++ = *q++;

	/* zero remainder. standard bzero not designed to work in nc space */
	while (p < (uint_t *)(bp + PAGESIZE))
		*p++ = 0;

	DRMACH_PR("drmach_rename function 0x%p, len %d\n", (void *)wp, len);
	wp += (len + 15) & ~15;

	err = drmach_prep_rename_script(s_mp, t_mp, t_slice_offset, wp,
	    PAGESIZE - (wp - bp));
	if (err) {
cleanup:
		xt_one(CPU->cpu_id, vtag_flushpage_tl1,
		    (uint64_t)drmach_cpu_sram_va, (uint64_t)ksfmmup);
		return (err);
	}

	/* disable and flush CDC */
	if (axq_cdc_disable_flush_all() != DDI_SUCCESS) {
		axq_cdc_enable_all();	/* paranoia */
		err = DRMACH_INTERNAL_ERROR();
		goto cleanup;
	}

	/* mark both memory units busy */
	t_mp->dev.busy++;
	s_mp->dev.busy++;

	cr = vmem_alloc(static_alloc_arena, sizeof (drmach_copy_rename_t),
	    VM_SLEEP);
	cr->isa = (void *)drmach_copy_rename_init;
	cr->data = wp;
	cr->c_ml = c_ml;
	cr->s_mp = s_mp;
	cr->t_mp = t_mp;
	cr->s_copybasepa = s_copybasepa;
	cr->t_copybasepa = t_copybasepa;
	cr->ecode = DRMACH_CR_OK;

	mutex_enter(&drmach_slice_table_lock);

	mutex_enter(&drmach_xt_mb_lock);
	bzero((void *)drmach_xt_mb, drmach_xt_mb_size);

	if (DRMACH_L1_SET_LPA(s_mp->dev.bp) && drmach_reprogram_lpa) {
		drmach_prep_xt_mb_for_slice_update(s_mp->dev.bp,
		    DRMACH_PA_TO_SLICE(t_copybasepa));
	}
	if (DRMACH_L1_SET_LPA(t_mp->dev.bp) && drmach_reprogram_lpa) {
		drmach_prep_xt_mb_for_slice_update(t_mp->dev.bp,
		    DRMACH_PA_TO_SLICE(s_copybasepa));
	}

	*cr_id = cr;
	return (NULL);
}

int drmach_rename_count;
int drmach_rename_ntries;

sbd_error_t *
drmach_copy_rename_fini(drmachid_t id)
{
	drmach_copy_rename_t	*cr = id;
	sbd_error_t		*err = NULL;
	dr_mbox_msg_t		*obufp;

	ASSERT(cr->isa == (void *)drmach_copy_rename_init);

	axq_cdc_enable_all();

	xt_one(CPU->cpu_id, vtag_flushpage_tl1,
	    (uint64_t)drmach_cpu_sram_va, (uint64_t)ksfmmup);

	switch (cr->ecode) {
	case DRMACH_CR_OK:
		break;
	case DRMACH_CR_MC_IDLE_ERR: {
		dev_info_t	*dip = NULL;
		drmach_mem_t	*mp = (drmach_mem_t *)cr->earg;
		char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		ASSERT(DRMACH_IS_MEM_ID(mp));

		err = drmach_get_dip(mp, &dip);

		ASSERT(err == NULL);
		ASSERT(dip != NULL);

		err = drerr_new(0, ESBD_MEMFAIL, NULL);
		(void) ddi_pathname(dip, path);
		cmn_err(CE_WARN, "failed to idle memory controller %s on %s: "
		    "copy-rename aborted", path, mp->dev.bp->cm.name);
		kmem_free(path, MAXPATHLEN);
		break;
	}
	case DRMACH_CR_IOPAUSE_ERR:
		ASSERT((uintptr_t)cr->earg >= 0 &&
		    (uintptr_t)cr->earg < AXQ_MAX_EXP);

		err = drerr_new(0,  ESBD_SUSPEND, "EX%d", (uintptr_t)cr->earg);
		cmn_err(CE_WARN, "failed to idle EX%ld AXQ slot1 activity prior"
		    " to copy-rename", (uintptr_t)cr->earg);
		break;
	case DRMACH_CR_ONTRAP_ERR:
		err = drerr_new(0, ESBD_MEMFAIL, NULL);
		cmn_err(CE_WARN, "copy-rename aborted due to uncorrectable "
		    "memory error");
		break;
	default:
		err = DRMACH_INTERNAL_ERROR();
		cmn_err(CE_WARN, "unknown copy-rename error code (%d)\n",
		    cr->ecode);
		break;
	}

#ifdef DEBUG
	if ((DRMACH_L1_SET_LPA(cr->s_mp->dev.bp) ||
	    DRMACH_L1_SET_LPA(cr->t_mp->dev.bp)) && drmach_reprogram_lpa) {
		int	i;
		for (i = 0; i < NCPU; i++) {
			if (drmach_xt_mb[i])
				DRMACH_PR("cpu%d ignored drmach_xt_mb", i);
		}
	}
#endif
	mutex_exit(&drmach_xt_mb_lock);

	if (cr->c_ml != NULL)
		memlist_delete(cr->c_ml);

	cr->t_mp->dev.busy--;
	cr->s_mp->dev.busy--;

	if (err) {
		mutex_exit(&drmach_slice_table_lock);
		goto done;
	}

	/* update casm shadow for target and source board */
	drmach_slice_table_update(cr->t_mp->dev.bp, 0);
	drmach_slice_table_update(cr->s_mp->dev.bp, 0);
	mutex_exit(&drmach_slice_table_lock);

	mutex_enter(&drmach_bus_sync_lock);
	drmach_bus_sync_list_update();
	mutex_exit(&drmach_bus_sync_lock);

	/*
	 * Make a good-faith effort to notify the SC about the copy-rename, but
	 * don't worry if it fails, since a subsequent claim/unconfig/unclaim
	 * will duplicate the update.
	 */
	obufp = kmem_zalloc(sizeof (dr_mbox_msg_t), KM_SLEEP);
	mutex_enter(&drmach_slice_table_lock);
	drmach_msg_memslice_init(obufp->msgdata.dm_uc.mem_slice);
	drmach_msg_memregs_init(obufp->msgdata.dm_uc.mem_regs);
	mutex_exit(&drmach_slice_table_lock);
	(void) drmach_mbox_trans(DRMSG_UNCONFIG, cr->s_mp->dev.bp->bnum,
	    (caddr_t)obufp, sizeof (dr_mbox_msg_t), (caddr_t)NULL, 0);
	kmem_free(obufp, sizeof (dr_mbox_msg_t));

done:
	vmem_free(static_alloc_arena, cr, sizeof (drmach_copy_rename_t));

	DRMACH_PR("waited %d out of %d tries for drmach_rename_wait on %d cpus",
	    drmach_rename_ntries, drmach_cpu_ntries, drmach_rename_count);

	return (err);
}

int drmach_slow_copy = 0;

void
drmach_copy_rename(drmachid_t id)
{
	extern uint_t		 getpstate(void);
	extern void		 setpstate(uint_t);

	extern xcfunc_t		 drmach_rename_wait;
	extern xcfunc_t		 drmach_rename_done;
	extern xcfunc_t		 drmach_rename_abort;

	drmach_copy_rename_t	*cr = id;
	uint64_t		 neer;
	struct memlist		*ml;
	int			 i, count;
	int			 csize, lnsize;
	uint64_t		 caddr;
	cpuset_t		 cpuset;
	uint_t			 pstate;
	uint32_t		 exp = 0;
	on_trap_data_t		 otd;
	xcfunc_t		*drmach_end_wait_xcall = drmach_rename_done;

	ASSERT(cr->isa == (void *)drmach_copy_rename_init);
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cr->ecode == DRMACH_CR_OK);

	/*
	 * Prevent slot1 IO from accessing Safari memory bus.
	 */
	if (axq_iopause_enable_all(&exp) != DDI_SUCCESS) {
		ASSERT(exp >= 0 && exp < AXQ_MAX_EXP);
		cr->ecode = DRMACH_CR_IOPAUSE_ERR;
		cr->earg = (void *)(uintptr_t)exp;
		return;
	}

	cpuset = cpu_ready_set;
	CPUSET_DEL(cpuset, CPU->cpu_id);
	count = ncpus - 1;
	drmach_rename_count = count;	/* for debug */

	drmach_xt_ready = 0;
	xt_some(cpuset, drmach_rename_wait, NULL, NULL);

	for (i = 0; i < drmach_cpu_ntries; i++) {
		if (drmach_xt_ready == count)
			break;
		DELAY(drmach_cpu_delay);
	}

	drmach_rename_ntries = i;	/* for debug */

	drmach_xt_ready = 0;		/* steal the line back */
	for (i = 0; i < NCPU; i++)	/* steal the line back, preserve data */
		drmach_xt_mb[i] = drmach_xt_mb[i];

	caddr = drmach_iocage_paddr;
	csize = cpunodes[CPU->cpu_id].ecache_size;
	lnsize = cpunodes[CPU->cpu_id].ecache_linesize;

	/* disable CE reporting */
	neer = get_error_enable();
	set_error_enable(neer & ~EN_REG_CEEN);

	/* disable interrupts (paranoia) */
	pstate = getpstate();
	setpstate(pstate & ~PSTATE_IE);

	/*
	 * Execute copy-rename under on_trap to protect against a panic due
	 * to an uncorrectable error. Instead, DR will abort the copy-rename
	 * operation and rely on the OS to do the error reporting.
	 *
	 * In general, trap handling on any cpu once the copy begins
	 * can result in an inconsistent memory image on the target.
	 */
	if (on_trap(&otd, OT_DATA_EC)) {
		cr->ecode = DRMACH_CR_ONTRAP_ERR;
		goto copy_rename_end;
	}

	/*
	 * DO COPY.
	 */
	for (ml = cr->c_ml; ml; ml = ml->ml_next) {
		uint64_t	s_pa, t_pa;
		uint64_t	nbytes;

		s_pa = cr->s_copybasepa + ml->ml_address;
		t_pa = cr->t_copybasepa + ml->ml_address;
		nbytes = ml->ml_size;

		while (nbytes != 0ull) {
			/* copy 32 bytes at src_pa to dst_pa */
			bcopy32_il(s_pa, t_pa);

			/* increment by 32 bytes */
			s_pa += (4 * sizeof (uint64_t));
			t_pa += (4 * sizeof (uint64_t));

			/* decrement by 32 bytes */
			nbytes -= (4 * sizeof (uint64_t));

			if (drmach_slow_copy) {	/* for debug */
				uint64_t i = 13 * 50;
				while (i--)
					;
			}
		}
	}

	/*
	 * XXX CHEETAH SUPPORT
	 * For cheetah, we need to grab the iocage lock since iocage
	 * memory is used for e$ flush.
	 *
	 * NOTE: This code block is dangerous at this point in the
	 * copy-rename operation. It modifies memory after the copy
	 * has taken place which means that any persistent state will
	 * be abandoned after the rename operation. The code is also
	 * performing thread synchronization at a time when all but
	 * one processors are paused. This is a potential deadlock
	 * situation.
	 *
	 * This code block must be moved to drmach_copy_rename_init.
	 */
	if (drmach_is_cheetah) {
		mutex_enter(&drmach_iocage_lock);
		while (drmach_iocage_is_busy)
			cv_wait(&drmach_iocage_cv, &drmach_iocage_lock);
		drmach_iocage_is_busy = 1;
		drmach_iocage_mem_scrub(ecache_size * 2);
		mutex_exit(&drmach_iocage_lock);
	}

	/*
	 * bcopy32_il is implemented as a series of ldxa/stxa via
	 * ASI_MEM instructions. Following the copy loop, the E$
	 * of the master (this) processor will have lines in state
	 * O that correspond to lines of home memory in state gI.
	 * An E$ flush is necessary to commit these lines before
	 * proceeding with the rename operation.
	 *
	 * Flushing the E$ will automatically flush the W$, but
	 * the D$ and I$ must be flushed separately and explicitly.
	 */
	flush_ecache_il(caddr, csize, lnsize);	/* inline version */

	/*
	 * Each line of home memory is now in state gM, except in
	 * the case of a cheetah processor when the E$ flush area
	 * is included within the copied region. In such a case,
	 * the lines of home memory for the upper half of the
	 * flush area are in state gS.
	 *
	 * Each line of target memory is in state gM.
	 *
	 * Each line of this processor's E$ is in state I, except
	 * those of a cheetah processor. All lines of a cheetah
	 * processor's E$ are in state S and correspond to the lines
	 * in upper half of the E$ flush area.
	 *
	 * It is vital at this point that none of the lines in the
	 * home or target memories are in state gI and that none
	 * of the lines in this processor's E$ are in state O or Os.
	 * A single instance of such a condition will cause loss of
	 * coherency following the rename operation.
	 */

	/*
	 * Rename
	 */
	(*(void(*)())drmach_cpu_sram_va)(cr->data, &cr->ecode, &cr->earg);

	/*
	 * Rename operation complete. The physical address space
	 * of the home and target memories have been swapped, the
	 * routing data in the respective CASM entries have been
	 * swapped, and LPA settings in the processor and schizo
	 * devices have been reprogrammed accordingly.
	 *
	 * In the case of a cheetah processor, the E$ remains
	 * populated with lines in state S that correspond to the
	 * lines in the former home memory. Now that the physical
	 * addresses have been swapped, these E$ lines correspond
	 * to lines in the new home memory which are in state gM.
	 * This combination is invalid. An additional E$ flush is
	 * necessary to restore coherency. The E$ flush will cause
	 * the lines of the new home memory for the flush region
	 * to transition from state gM to gS. The former home memory
	 * remains unmodified. This additional E$ flush has no effect
	 * on a cheetah+ processor.
	 */
	flush_ecache_il(caddr, csize, lnsize);	/* inline version */

	/*
	 * The D$ and I$ must be flushed to ensure that coherency is
	 * maintained. Any line in a cache that is in the valid
	 * state has its corresponding line of the new home memory
	 * in the gM state. This is an invalid condition. When the
	 * flushes are complete the cache line states will be
	 * resynchronized with those in the new home memory.
	 */
	flush_icache_il();			/* inline version */
	flush_dcache_il();			/* inline version */
	flush_pcache_il();			/* inline version */

copy_rename_end:

	no_trap();

	/* enable interrupts */
	setpstate(pstate);

	/* enable CE reporting */
	set_error_enable(neer);

	if (cr->ecode != DRMACH_CR_OK)
		drmach_end_wait_xcall = drmach_rename_abort;

	/*
	 * XXX CHEETAH SUPPORT
	 */
	if (drmach_is_cheetah) {
		mutex_enter(&drmach_iocage_lock);
		drmach_iocage_mem_scrub(ecache_size * 2);
		drmach_iocage_is_busy = 0;
		cv_signal(&drmach_iocage_cv);
		mutex_exit(&drmach_iocage_lock);
	}

	axq_iopause_disable_all();

	xt_some(cpuset, drmach_end_wait_xcall, NULL, NULL);
}

static void drmach_io_dispose(drmachid_t);
static sbd_error_t *drmach_io_release(drmachid_t);
static sbd_error_t *drmach_io_status(drmachid_t, drmach_status_t *);

static sbd_error_t *
drmach_pci_new(drmach_device_t *proto, drmachid_t *idp)
{
	drmach_node_t	*node = proto->node;
	sbd_error_t	*err;
	drmach_reg_t	 regs[3];
	int		 rv;
	int		 len = 0;

	rv = node->n_getproplen(node, "reg", &len);
	if (rv != 0 || len != sizeof (regs)) {
		sbd_error_t *err;

		/* pci nodes are expected to have regs */
		err = drerr_new(1, ESTC_GETPROP,
		    "Device Node 0x%x: property %s",
		    (uint_t)node->get_dnode(node), "reg");
		return (err);
	}

	rv = node->n_getprop(node, "reg", (void *)regs, sizeof (regs));
	if (rv) {
		sbd_error_t *err;

		err = drerr_new(1, ESTC_GETPROP,
		    "Device Node 0x%x: property %s",
		    (uint_t)node->get_dnode(node), "reg");

		return (err);
	}

	/*
	 * Fix up unit number so that Leaf A has a lower unit number
	 * than Leaf B.
	 */
	if ((proto->portid % 2) != 0) {
		if ((regs[0].reg_addr_lo & 0x700000) == 0x700000)
			proto->unum = 0;
		else
			proto->unum = 1;
	} else {
		if ((regs[0].reg_addr_lo & 0x700000) == 0x700000)
			proto->unum = 2;
		else
			proto->unum = 3;
	}

	err = drmach_io_new(proto, idp);
	if (err == NULL) {
		drmach_io_t *self = *idp;

		/* reassemble 64-bit base address */
		self->scsr_pa  = (uint64_t)regs[1].reg_addr_hi << 32;
		self->scsr_pa |= (uint64_t)regs[1].reg_addr_lo;
	}

	return (err);
}

static sbd_error_t *
drmach_io_new(drmach_device_t *proto, drmachid_t *idp)
{
	drmach_io_t	*ip;

	ip = kmem_zalloc(sizeof (drmach_io_t), KM_SLEEP);
	bcopy(proto, &ip->dev, sizeof (ip->dev));
	ip->dev.node = drmach_node_dup(proto->node);
	ip->dev.cm.isa = (void *)drmach_io_new;
	ip->dev.cm.dispose = drmach_io_dispose;
	ip->dev.cm.release = drmach_io_release;
	ip->dev.cm.status = drmach_io_status;

	(void) snprintf(ip->dev.cm.name, sizeof (ip->dev.cm.name), "%s%d",
	    ip->dev.type, ip->dev.unum);

	*idp = (drmachid_t)ip;
	return (NULL);
}

static void
drmach_io_dispose(drmachid_t id)
{
	drmach_io_t *self;

	ASSERT(DRMACH_IS_IO_ID(id));

	self = id;
	if (self->dev.node)
		drmach_node_dispose(self->dev.node);

	kmem_free(self, sizeof (*self));
}

/*ARGSUSED*/
sbd_error_t *
drmach_pre_op(int cmd, drmachid_t id, drmach_opts_t *opts)
{
	drmach_board_t	*bp = (drmach_board_t *)id;
	sbd_error_t	*err = NULL;

	if (id && DRMACH_IS_BOARD_ID(id)) {
		switch (cmd) {
			case SBD_CMD_TEST:
			case SBD_CMD_STATUS:
			case SBD_CMD_GETNCM:
				break;
			case SBD_CMD_CONNECT:
				if (bp->connected)
					err = drerr_new(0, ESBD_STATE, NULL);

				if (bp->cond == SBD_COND_UNUSABLE)
					err = drerr_new(0,
					    ESBD_FATAL_STATE, NULL);
				break;
			case SBD_CMD_DISCONNECT:
				if (!bp->connected)
					err = drerr_new(0, ESBD_STATE, NULL);

				if (bp->cond == SBD_COND_UNUSABLE)
					err = drerr_new(0,
					    ESBD_FATAL_STATE, NULL);
				break;
			default:
				if (bp->cond == SBD_COND_UNUSABLE)
					err = drerr_new(0,
					    ESBD_FATAL_STATE, NULL);
				break;

		}
	}

	return (err);
}

/*ARGSUSED*/
sbd_error_t *
drmach_post_op(int cmd, drmachid_t id, drmach_opts_t *opts)
{
	return (NULL);
}

sbd_error_t *
drmach_board_assign(int bnum, drmachid_t *id)
{
	sbd_error_t	*err = NULL;
	caddr_t		obufp;

	if (!drmach_initialized && drmach_init() == -1) {
		err = DRMACH_INTERNAL_ERROR();
	}

	rw_enter(&drmach_boards_rwlock, RW_WRITER);

	if (!err) {
		if (drmach_array_get(drmach_boards, bnum, id) == -1) {
			err = drerr_new(0, ESTC_BNUM, "%d", bnum);
		} else {
			drmach_board_t	*bp;

			if (*id)
				rw_downgrade(&drmach_boards_rwlock);

			obufp = kmem_zalloc(sizeof (dr_proto_hdr_t), KM_SLEEP);
			err = drmach_mbox_trans(DRMSG_ASSIGN, bnum, obufp,
			    sizeof (dr_proto_hdr_t), (caddr_t)NULL, 0);
			kmem_free(obufp, sizeof (dr_proto_hdr_t));

			if (!err) {
				bp = *id;
				if (!*id)
					bp = *id  =
					    (drmachid_t)drmach_board_new(bnum);
				bp->assigned = 1;
			}
		}
	}
	rw_exit(&drmach_boards_rwlock);
	return (err);
}

static uint_t
drmach_board_non_panther_cpus(gdcd_t *gdcd, uint_t exp, uint_t slot)
{
	uint_t	port, port_start, port_end;
	uint_t	non_panther_cpus = 0;
	uint_t	impl;

	ASSERT(gdcd != NULL);

	/*
	 * Determine PRD port indices based on slot location.
	 */
	switch (slot) {
	case 0:
		port_start = 0;
		port_end = 3;
		break;
	case 1:
		port_start = 4;
		port_end = 5;
		break;
	default:
		ASSERT(0);
		/* check all */
		port_start = 0;
		port_end = 5;
		break;
	}

	for (port = port_start; port <= port_end; port++) {
		if (gdcd->dcd_prd[exp][port].prd_ptype == SAFPTYPE_CPU &&
		    RSV_GOOD(gdcd->dcd_prd[exp][port].prd_prsv)) {
			/*
			 * This Safari port passed POST and represents a
			 * cpu, so check the implementation.
			 */
			impl = (gdcd->dcd_prd[exp][port].prd_ver_reg >> 32)
			    & 0xffff;

			switch (impl) {
			case CHEETAH_IMPL:
			case CHEETAH_PLUS_IMPL:
			case JAGUAR_IMPL:
				non_panther_cpus++;
				break;
			case PANTHER_IMPL:
				break;
			default:
				ASSERT(0);
				non_panther_cpus++;
				break;
			}
		}
	}

	DRMACH_PR("drmach_board_non_panther_cpus: exp=%d, slot=%d, "
	    "non_panther_cpus=%d", exp, slot, non_panther_cpus);

	return (non_panther_cpus);
}

sbd_error_t *
drmach_board_connect(drmachid_t id, drmach_opts_t *opts)
{
	_NOTE(ARGUNUSED(opts))

	drmach_board_t		*bp = (drmach_board_t *)id;
	sbd_error_t		*err;
	dr_mbox_msg_t		*obufp;
	gdcd_t			*gdcd = NULL;
	uint_t			exp, slot;
	sc_gptwocfg_cookie_t	scc;
	int			panther_pages_enabled;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));

	/*
	 * Build the casm info portion of the CLAIM message.
	 */
	obufp = kmem_zalloc(sizeof (dr_mbox_msg_t), KM_SLEEP);
	mutex_enter(&drmach_slice_table_lock);
	drmach_msg_memslice_init(obufp->msgdata.dm_cr.mem_slice);
	drmach_msg_memregs_init(obufp->msgdata.dm_cr.mem_regs);
	mutex_exit(&drmach_slice_table_lock);
	err = drmach_mbox_trans(DRMSG_CLAIM, bp->bnum, (caddr_t)obufp,
	    sizeof (dr_mbox_msg_t), (caddr_t)NULL, 0);
	kmem_free(obufp, sizeof (dr_mbox_msg_t));

	if (err) {
		/*
		 * if mailbox timeout or unrecoverable error from SC,
		 * board cannot be touched.  Mark the status as
		 * unusable.
		 */
		if ((err->e_code == ESTC_SMS_ERR_UNRECOVERABLE) ||
		    (err->e_code == ESTC_MBXRPLY))
			bp->cond = SBD_COND_UNUSABLE;
		return (err);
	}

	gdcd = drmach_gdcd_new();
	if (gdcd == NULL) {
		cmn_err(CE_WARN, "failed to read GDCD info for %s\n",
		    bp->cm.name);
		return (DRMACH_INTERNAL_ERROR());
	}

	/*
	 * Read CPU SRAM DR buffer offset from GDCD.
	 */
	exp = DRMACH_BNUM2EXP(bp->bnum);
	slot = DRMACH_BNUM2SLOT(bp->bnum);
	bp->stardrb_offset =
	    gdcd->dcd_slot[exp][slot].l1ss_cpu_drblock_xwd_offset << 3;
	DRMACH_PR("%s: stardrb_offset=0x%lx\n", bp->cm.name,
	    bp->stardrb_offset);

	/*
	 * Read board LPA setting from GDCD.
	 */
	bp->flags &= ~DRMACH_NULL_PROC_LPA;
	if (gdcd->dcd_slot[exp][slot].l1ss_flags &
	    L1SSFLG_THIS_L1_NULL_PROC_LPA) {
		bp->flags |= DRMACH_NULL_PROC_LPA;
		DRMACH_PR("%s: NULL proc LPA\n", bp->cm.name);
	}

	/*
	 * XXX Until the Solaris large pages support heterogeneous cpu
	 * domains, DR needs to prevent the addition of non-Panther cpus
	 * to an all-Panther domain with large pages enabled.
	 */
	panther_pages_enabled = (page_num_pagesizes() > DEFAULT_MMU_PAGE_SIZES);
	if (drmach_board_non_panther_cpus(gdcd, exp, slot) > 0 &&
	    panther_pages_enabled && drmach_large_page_restriction) {
		cmn_err(CE_WARN, "Domain shutdown is required to add a non-"
		    "UltraSPARC-IV+ board into an all UltraSPARC-IV+ domain");
		err = drerr_new(0, ESTC_SUPPORT, NULL);
	}

	if (err == NULL) {
		/* do saf configurator stuff */
		DRMACH_PR("calling sc_probe_board for bnum=%d\n", bp->bnum);
		scc = sc_probe_board(bp->bnum);
		if (scc == NULL)
			err = drerr_new(0, ESTC_PROBE, bp->cm.name);
	}

	if (err) {
		/* flush CDC srams */
		if (axq_cdc_flush_all() != DDI_SUCCESS) {
			goto out;
		}

		/*
		 * Build the casm info portion of the UNCLAIM message.
		 */
		obufp = kmem_zalloc(sizeof (dr_mbox_msg_t), KM_SLEEP);
		mutex_enter(&drmach_slice_table_lock);
		drmach_msg_memslice_init(obufp->msgdata.dm_ur.mem_slice);
		drmach_msg_memregs_init(obufp->msgdata.dm_ur.mem_regs);
		mutex_exit(&drmach_slice_table_lock);
		(void) drmach_mbox_trans(DRMSG_UNCLAIM, bp->bnum,
		    (caddr_t)obufp, sizeof (dr_mbox_msg_t),
		    (caddr_t)NULL, 0);

		kmem_free(obufp, sizeof (dr_mbox_msg_t));

		/*
		 * we clear the connected flag just in case it would have
		 * been set by a concurrent drmach_board_status() thread
		 * before the UNCLAIM completed.
		 */
		bp->connected = 0;
		goto out;
	}

	/*
	 * Now that the board has been successfully attached, obtain
	 * platform-specific DIMM serial id information for the board.
	 */
	if ((DRMACH_BNUM2SLOT(bp->bnum) == 0) &&
	    plat_ecc_capability_sc_get(PLAT_ECC_DIMM_SID_MESSAGE)) {
		(void) plat_request_mem_sids(DRMACH_BNUM2EXP(bp->bnum));
	}

out:
	if (gdcd != NULL)
		drmach_gdcd_dispose(gdcd);

	return (err);
}

static void
drmach_slice_table_update(drmach_board_t *bp, int invalidate)
{
	static char		*axq_name = "address-extender-queue";
	static dev_info_t	*axq_dip = NULL;
	static int		 axq_exp = -1;
	static int		 axq_slot;
	int			 e, s, slice;

	ASSERT(MUTEX_HELD(&drmach_slice_table_lock));

	e = DRMACH_BNUM2EXP(bp->bnum);
	if (invalidate) {
		ASSERT(DRMACH_BNUM2SLOT(bp->bnum) == 0);

		/* invalidate cached casm value */
		drmach_slice_table[e] = 0;

		/* invalidate cached axq info if for same exp */
		if (e == axq_exp && axq_dip) {
			ndi_rele_devi(axq_dip);
			axq_dip = NULL;
		}
	}

	if (axq_dip == NULL || !i_ddi_devi_attached(axq_dip)) {
		int i, portid;

		/* search for an attached slot0 axq instance */
		for (i = 0; i < AXQ_MAX_EXP * AXQ_MAX_SLOT_PER_EXP; i++) {
			if (axq_dip)
				ndi_rele_devi(axq_dip);
			axq_dip = ddi_find_devinfo(axq_name, i, 0);
			if (axq_dip && DDI_CF2(axq_dip)) {
				portid = ddi_getprop(DDI_DEV_T_ANY, axq_dip,
				    DDI_PROP_DONTPASS, "portid", -1);
				if (portid == -1) {
					DRMACH_PR("cant get portid of axq "
					    "instance %d\n", i);
					continue;
				}

				axq_exp = (portid >> 5) & 0x1f;
				axq_slot = portid & 1;

				if (invalidate && axq_exp == e)
					continue;

				if (axq_slot == 0)
					break;	/* found */
			}
		}

		if (i == AXQ_MAX_EXP * AXQ_MAX_SLOT_PER_EXP) {
			if (axq_dip) {
				ndi_rele_devi(axq_dip);
				axq_dip = NULL;
			}
			DRMACH_PR("drmach_slice_table_update: failed to "
			    "update axq dip\n");
			return;
		}

	}

	ASSERT(axq_dip);
	ASSERT(axq_slot == 0);

	if (invalidate)
		return;

	s = DRMACH_BNUM2SLOT(bp->bnum);
	DRMACH_PR("using AXQ casm %d.%d for slot%d.%d\n", axq_exp, axq_slot,
	    e, s);

	/* invalidate entry */
	drmach_slice_table[e] &= ~0x20;

	/*
	 * find a slice that routes to expander e. If no match
	 * is found, drmach_slice_table[e] will remain invalid.
	 *
	 * The CASM is a routing table indexed by slice number.
	 * Each element in the table contains permission bits,
	 * a destination expander number and a valid bit. The
	 * valid bit must true for the element to be meaningful.
	 *
	 * CASM entry structure
	 *   Bits 15..6 ignored
	 *   Bit  5	valid
	 *   Bits 0..4	expander number
	 *
	 * NOTE: the for loop is really enumerating the range of slices,
	 * which is ALWAYS equal to the range of expanders. Hence,
	 * AXQ_MAX_EXP is okay to use in this loop.
	 */
	for (slice = 0; slice < AXQ_MAX_EXP; slice++) {
		uint32_t casm = axq_casm_read(axq_exp, axq_slot, slice);

		if ((casm & 0x20) && (casm & 0x1f) == e)
			drmach_slice_table[e] = 0x20 | slice;
	}
}

/*
 * Get base and bound PAs for slot 1 board lpa programming
 * If a cpu/mem board is present in the same expander, use slice
 * information corresponding to the CASM.  Otherwise, set base and
 * bound PAs to 0.
 */
static void
drmach_lpa_bb_get(drmach_board_t *s1bp, uint64_t *basep, uint64_t *boundp)
{
	drmachid_t s0id;

	ASSERT(mutex_owned(&drmach_slice_table_lock));
	ASSERT(DRMACH_BNUM2SLOT(s1bp->bnum) == 1);

	*basep = *boundp = 0;
	if (drmach_array_get(drmach_boards, s1bp->bnum - 1, &s0id) == 0 &&
	    s0id != 0) {

		uint32_t slice;
		if ((slice = drmach_slice_table[DRMACH_BNUM2EXP(s1bp->bnum)])
		    & 0x20) {
			*basep = DRMACH_SLICE_TO_PA(slice & DRMACH_SLICE_MASK);
			*boundp = *basep + DRMACH_MEM_SLICE_SIZE;
		}
	}
}


/*
 * Reprogram slot 1 lpa's as required.
 * The purpose of this routine is maintain the LPA settings of the devices
 * in slot 1. To date we know Schizo and Cheetah are the only devices that
 * require this attention. The LPA setting must match the slice field in the
 * CASM element for the local expander. This field is guaranteed to be
 * programmed in accordance with the cacheable address space on the slot 0
 * board of the local expander. If no memory is present on the slot 0 board,
 * there is no cacheable address space and, hence, the CASM slice field will
 * be zero or its valid bit will be false (or both).
 */

static void
drmach_slot1_lpa_set(drmach_board_t *bp)
{
	drmachid_t	id;
	drmach_board_t	*s1bp = NULL;
	int		rv, idx, is_maxcat = 1;
	uint64_t	last_scsr_pa = 0;
	uint64_t	new_basepa, new_boundpa;

	if (DRMACH_BNUM2SLOT(bp->bnum)) {
		s1bp = bp;
		if (s1bp->devices == NULL) {
			DRMACH_PR("drmach...lpa_set: slot1=%d not present",
			    bp->bnum);
			return;
		}
	} else {
		rv = drmach_array_get(drmach_boards, bp->bnum + 1, &id);
		/* nothing to do when board is not found or has no devices */
		s1bp = id;
		if (rv == -1 || s1bp == NULL || s1bp->devices == NULL) {
			DRMACH_PR("drmach...lpa_set: slot1=%d not present",
			    bp->bnum + 1);
			return;
		}
		ASSERT(DRMACH_IS_BOARD_ID(id));
	}
	mutex_enter(&drmach_slice_table_lock);
	drmach_lpa_bb_get(s1bp, &new_basepa, &new_boundpa);
	DRMACH_PR("drmach_...lpa_set: bnum=%d base=0x%lx bound=0x%lx\n",
	    s1bp->bnum, new_basepa, new_boundpa);

	rv = drmach_array_first(s1bp->devices, &idx, &id);
	while (rv == 0) {
		if (DRMACH_IS_IO_ID(id)) {
			drmach_io_t *io = id;

			is_maxcat = 0;

			/*
			 * Skip all non-Schizo IO devices (only IO nodes
			 * that are Schizo devices have non-zero scsr_pa).
			 * Filter out "other" leaf to avoid writing to the
			 * same Schizo Control/Status Register twice.
			 */
			if (io->scsr_pa && io->scsr_pa != last_scsr_pa) {
				uint64_t scsr;

				scsr  = lddphysio(io->scsr_pa);
				DRMACH_PR("drmach...lpa_set: old scsr=0x%lx\n",
				    scsr);
				scsr &= ~(DRMACH_LPA_BASE_MASK |
				    DRMACH_LPA_BND_MASK);
				scsr |= DRMACH_PA_TO_LPA_BASE(new_basepa);
				scsr |= DRMACH_PA_TO_LPA_BND(new_boundpa);

				stdphysio(io->scsr_pa, scsr);
				DRMACH_PR("drmach...lpa_set: new scsr=0x%lx\n",
				    scsr);

				last_scsr_pa = io->scsr_pa;
			}
		}
		rv = drmach_array_next(s1bp->devices, &idx, &id);
	}

	if (is_maxcat && DRMACH_L1_SET_LPA(s1bp) && drmach_reprogram_lpa) {
		extern xcfunc_t	drmach_set_lpa;

		DRMACH_PR("reprogramming maxcat lpa's");

		mutex_enter(&cpu_lock);
		rv = drmach_array_first(s1bp->devices, &idx, &id);
		while (rv == 0 && id != NULL) {
			if (DRMACH_IS_CPU_ID(id)) {
				int ntries;
				processorid_t cpuid;

				cpuid = ((drmach_cpu_t *)id)->cpuid;

				/*
				 * Check for unconfigured or powered-off
				 * MCPUs.  If CPU_READY flag is clear, the
				 * MCPU cannot be xcalled.
				 */
				if ((cpu[cpuid] == NULL) ||
				    (cpu[cpuid]->cpu_flags &
				    CPU_READY) == 0) {

					rv = drmach_array_next(s1bp->devices,
					    &idx, &id);
					continue;
				}

				/*
				 * XXX CHEETAH SUPPORT
				 * for cheetah, we need to clear iocage
				 * memory since it will be used for e$ flush
				 * in drmach_set_lpa.
				 */
				if (drmach_is_cheetah) {
					mutex_enter(&drmach_iocage_lock);
					while (drmach_iocage_is_busy)
						cv_wait(&drmach_iocage_cv,
						    &drmach_iocage_lock);
					drmach_iocage_is_busy = 1;
					drmach_iocage_mem_scrub(ecache_size *
					    2);
					mutex_exit(&drmach_iocage_lock);
				}

				/*
				 * drmach_slice_table[*]
				 *	bit 5	valid
				 *	bit 0:4	slice number
				 *
				 * drmach_xt_mb[*] format for drmach_set_lpa
				 *	bit 7	valid
				 *	bit 6	set null LPA
				 *			(overrides bits 0:4)
				 *	bit 0:4	slice number
				 *
				 * drmach_set_lpa derives processor CBASE and
				 * CBND from bits 6 and 0:4 of drmach_xt_mb.
				 * If bit 6 is set, then CBASE = CBND = 0.
				 * Otherwise, CBASE = slice number;
				 * CBND = slice number + 1.
				 * No action is taken if bit 7 is zero.
				 */

				mutex_enter(&drmach_xt_mb_lock);
				bzero((void *)drmach_xt_mb,
				    drmach_xt_mb_size);

				if (new_basepa == 0 && new_boundpa == 0)
					drmach_xt_mb[cpuid] = 0x80 | 0x40;
				else
					drmach_xt_mb[cpuid] = 0x80 |
					    DRMACH_PA_TO_SLICE(new_basepa);

				drmach_xt_ready = 0;

				xt_one(cpuid, drmach_set_lpa, NULL, NULL);

				ntries = drmach_cpu_ntries;
				while (!drmach_xt_ready && ntries) {
					DELAY(drmach_cpu_delay);
					ntries--;
				}
				mutex_exit(&drmach_xt_mb_lock);
				drmach_xt_ready = 0;

				/*
				 * XXX CHEETAH SUPPORT
				 * for cheetah, we need to clear iocage
				 * memory since it was used for e$ flush
				 * in performed drmach_set_lpa.
				 */
				if (drmach_is_cheetah) {
					mutex_enter(&drmach_iocage_lock);
					drmach_iocage_mem_scrub(ecache_size *
					    2);
					drmach_iocage_is_busy = 0;
					cv_signal(&drmach_iocage_cv);
					mutex_exit(&drmach_iocage_lock);
				}
			}
			rv = drmach_array_next(s1bp->devices, &idx, &id);
		}
		mutex_exit(&cpu_lock);
	}
	mutex_exit(&drmach_slice_table_lock);
}

/*
 * Return the number of connected Panther boards in the domain.
 */
static int
drmach_panther_boards(void)
{
	int		rv;
	int		b_idx;
	drmachid_t	b_id;
	drmach_board_t	*bp;
	int		npanther = 0;

	rv = drmach_array_first(drmach_boards, &b_idx, &b_id);
	while (rv == 0) {
		ASSERT(DRMACH_IS_BOARD_ID(b_id));
		bp = b_id;

		if (IS_PANTHER(bp->cpu_impl))
			npanther++;

		rv = drmach_array_next(drmach_boards, &b_idx, &b_id);
	}

	return (npanther);
}

/*ARGSUSED*/
sbd_error_t *
drmach_board_disconnect(drmachid_t id, drmach_opts_t *opts)
{
	drmach_board_t	*bp;
	dr_mbox_msg_t	*obufp;
	sbd_error_t	*err = NULL;

	sc_gptwocfg_cookie_t	scc;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	bp = id;

	/*
	 * Build the casm info portion of the UNCLAIM message.
	 * This must be done prior to calling for saf configurator
	 * deprobe, to ensure that the associated axq instance
	 * is not detached.
	 */
	obufp = kmem_zalloc(sizeof (dr_mbox_msg_t), KM_SLEEP);
	mutex_enter(&drmach_slice_table_lock);
	drmach_msg_memslice_init(obufp->msgdata.dm_ur.mem_slice);

	/*
	 * If disconnecting slot 0 board, update the casm slice table
	 * info now, for use by drmach_slot1_lpa_set()
	 */
	if (DRMACH_BNUM2SLOT(bp->bnum) == 0)
		drmach_slice_table_update(bp, 1);

	drmach_msg_memregs_init(obufp->msgdata.dm_ur.mem_regs);
	mutex_exit(&drmach_slice_table_lock);

	/*
	 * Update LPA information for slot1 board
	 */
	drmach_slot1_lpa_set(bp);

	/* disable and flush CDC */
	if (axq_cdc_disable_flush_all() != DDI_SUCCESS) {
		axq_cdc_enable_all();	/* paranoia */
		err = DRMACH_INTERNAL_ERROR();
	}

	/*
	 * call saf configurator for deprobe
	 * It's done now before sending an UNCLAIM message because
	 * IKP will probe boards it doesn't know about <present at boot>
	 * prior to unprobing them.  If this happens after sending the
	 * UNCLAIM, it will cause a dstop for domain transgression error.
	 */

	if (!err) {
		scc = sc_unprobe_board(bp->bnum);
		axq_cdc_enable_all();
		if (scc != NULL) {
			err = drerr_new(0, ESTC_DEPROBE, bp->cm.name);
		}
	}

	/*
	 * If disconnecting a board from a Panther domain, wait a fixed-
	 * time delay for pending Safari transactions to complete on the
	 * disconnecting board's processors.  The bus sync list read used
	 * in drmach_shutdown_asm to synchronize with outstanding Safari
	 * transactions assumes no read-bypass-write mode for all memory
	 * controllers.  Since Panther supports read-bypass-write, a
	 * delay is used that is slightly larger than the maximum Safari
	 * timeout value in the Safari/Fireplane Config Reg.
	 */
	if (drmach_panther_boards() > 0 || drmach_unclaim_delay_all) {
		clock_t	stime = ddi_get_lbolt();

		delay(drv_usectohz(drmach_unclaim_usec_delay));

		stime = ddi_get_lbolt() - stime;
		DRMACH_PR("delayed %ld ticks (%ld secs) before disconnecting "
		    "board %s from domain\n", stime, stime / hz, bp->cm.name);
	}

	if (!err) {
		obufp->msgdata.dm_ur.mem_clear = 0;

		err = drmach_mbox_trans(DRMSG_UNCLAIM, bp->bnum, (caddr_t)obufp,
		    sizeof (dr_mbox_msg_t), (caddr_t)NULL, 0);

		if (err) {
			/*
			 * if mailbox timeout or unrecoverable error from SC,
			 * board cannot be touched.  Mark the status as
			 * unusable.
			 */
			if ((err->e_code == ESTC_SMS_ERR_UNRECOVERABLE) ||
			    (err->e_code == ESTC_MBXRPLY))
				bp->cond = SBD_COND_UNUSABLE;
			else {
				DRMACH_PR("UNCLAIM failed for bnum=%d\n",
				    bp->bnum);
				DRMACH_PR("calling sc_probe_board: bnum=%d\n",
				    bp->bnum);
				scc = sc_probe_board(bp->bnum);
				if (scc == NULL) {
					cmn_err(CE_WARN,
					"sc_probe_board failed for bnum=%d",
					    bp->bnum);
				} else {
					if (DRMACH_BNUM2SLOT(bp->bnum) == 0) {
						mutex_enter(
						    &drmach_slice_table_lock);
						drmach_slice_table_update(bp,
						    0);
						mutex_exit(
						    &drmach_slice_table_lock);
					}
					drmach_slot1_lpa_set(bp);
				}
			}
		} else {
			bp->connected = 0;
			/*
			 * Now that the board has been successfully detached,
			 * discard platform-specific DIMM serial id information
			 * for the board.
			 */
			if ((DRMACH_BNUM2SLOT(bp->bnum) == 0) &&
			    plat_ecc_capability_sc_get(
			    PLAT_ECC_DIMM_SID_MESSAGE)) {
				(void) plat_discard_mem_sids(
				    DRMACH_BNUM2EXP(bp->bnum));
			}
		}
	}
	kmem_free(obufp, sizeof (dr_mbox_msg_t));

	return (err);
}

static int
drmach_get_portid(drmach_node_t *np)
{
	drmach_node_t	pp;
	int		portid;
	char		type[OBP_MAXPROPNAME];

	if (np->n_getprop(np, "portid", &portid, sizeof (portid)) == 0)
		return (portid);

	/*
	 * Get the device_type property to see if we should
	 * continue processing this node.
	 */
	if (np->n_getprop(np, "device_type", &type, sizeof (type)) != 0)
		return (-1);

	/*
	 * If the device is a CPU without a 'portid' property,
	 * it is a CMP core. For such cases, the parent node
	 * has the portid.
	 */
	if (strcmp(type, DRMACH_CPU_NAMEPROP) == 0) {
		if (np->get_parent(np, &pp) != 0)
			return (-1);

		if (pp.n_getprop(&pp, "portid", &portid, sizeof (portid)) == 0)
			return (portid);
	}

	return (-1);
}

/*
 * This is a helper function to determine if a given
 * node should be considered for a dr operation according
 * to predefined dr type nodes and the node's name.
 * Formal Parameter : The name of a device node.
 * Return Value: -1, name does not map to a valid dr type.
 *		 A value greater or equal to 0, name is a valid dr type.
 */
static int
drmach_name2type_idx(char *name)
{
	int 	index, ntypes;

	if (name == NULL)
		return (-1);

	/*
	 * Determine how many possible types are currently supported
	 * for dr.
	 */
	ntypes = sizeof (drmach_name2type) / sizeof (drmach_name2type[0]);

	/* Determine if the node's name correspond to a predefined type. */
	for (index = 0; index < ntypes; index++) {
		if (strcmp(drmach_name2type[index].name, name) == 0)
			/* The node is an allowed type for dr. */
			return (index);
	}

	/*
	 * If the name of the node does not map to any of the
	 * types in the array drmach_name2type then the node is not of
	 * interest to dr.
	 */
	return (-1);
}

static int
drmach_board_find_devices_cb(drmach_node_walk_args_t *args)
{
	drmach_node_t			*node = args->node;
	drmach_board_cb_data_t		*data = args->data;
	drmach_board_t			*obj = data->obj;

	int		rv, portid;
	drmachid_t	id;
	drmach_device_t	*device;
	char	name[OBP_MAXDRVNAME];

	portid = drmach_get_portid(node);
	if (portid == -1) {
		/*
		 * if the node does not have a portid property, then
		 * by that information alone it is known that drmach
		 * is not interested in it.
		 */
		return (0);
	}
	rv = node->n_getprop(node, "name", name, OBP_MAXDRVNAME);

	/* The node must have a name */
	if (rv)
		return (0);

	/*
	 * Ignore devices whose portid do not map to this board,
	 * or that their name property is not mapped to a valid
	 * dr device name.
	 */
	if ((drmach_portid2bnum(portid) != obj->bnum) ||
	    (drmach_name2type_idx(name) < 0))
		return (0);

	/*
	 * Create a device data structure from this node data.
	 * The call may yield nothing if the node is not of interest
	 * to drmach.
	 */
	data->err = drmach_device_new(node, obj, portid, &id);
	if (data->err)
		return (-1);
	else if (!id) {
		/*
		 * drmach_device_new examined the node we passed in
		 * and determined that it was either one not of
		 * interest to drmach or the PIM dr layer.
		 * So, it is skipped.
		 */
		return (0);
	}

	rv = drmach_array_set(obj->devices, data->ndevs++, id);
	if (rv) {
		data->err = DRMACH_INTERNAL_ERROR();
		return (-1);
	}

	device = id;

#ifdef DEBUG
	DRMACH_PR("%d %s %d %p\n", portid, device->type, device->unum, id);
	if (DRMACH_IS_IO_ID(id))
		DRMACH_PR("ndevs = %d dip/node = %p", data->ndevs, node->here);
#endif

	data->err = (*data->found)(data->a, device->type, device->unum, id);
	return (data->err == NULL ? 0 : -1);
}

sbd_error_t *
drmach_board_find_devices(drmachid_t id, void *a,
	sbd_error_t *(*found)(void *a, const char *, int, drmachid_t))
{
	drmach_board_t		*bp = (drmach_board_t *)id;
	sbd_error_t		*err;
	int			 max_devices;
	int			 rv;
	drmach_board_cb_data_t	data;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));

	max_devices  = plat_max_cpu_units_per_board();
	max_devices += plat_max_mem_units_per_board();
	max_devices += plat_max_io_units_per_board();

	bp->devices = drmach_array_new(0, max_devices);

	if (bp->tree == NULL)
		bp->tree = drmach_node_new();

	data.obj = bp;
	data.ndevs = 0;
	data.found = found;
	data.a = a;
	data.err = NULL;

	mutex_enter(&drmach_slice_table_lock);
	mutex_enter(&drmach_bus_sync_lock);

	rv = drmach_node_walk(bp->tree, &data, drmach_board_find_devices_cb);

	drmach_slice_table_update(bp, 0);
	drmach_bus_sync_list_update();

	mutex_exit(&drmach_bus_sync_lock);
	mutex_exit(&drmach_slice_table_lock);

	if (rv == 0) {
		err = NULL;
		drmach_slot1_lpa_set(bp);
	} else {
		drmach_array_dispose(bp->devices, drmach_device_dispose);
		bp->devices = NULL;

		if (data.err)
			err = data.err;
		else
			err = DRMACH_INTERNAL_ERROR();
	}

	return (err);
}

int
drmach_board_lookup(int bnum, drmachid_t *id)
{
	int	rv = 0;

	if (!drmach_initialized && drmach_init() == -1) {
		*id = 0;
		return (-1);
	}
	rw_enter(&drmach_boards_rwlock, RW_WRITER);
	if (drmach_array_get(drmach_boards, bnum, id)) {
		*id = 0;
		rv = -1;
	} else {
		caddr_t		obufp;
		dr_showboard_t	shb;
		sbd_error_t	*err = NULL;
		drmach_board_t	*bp;

		bp = *id;

		if (bp)
			rw_downgrade(&drmach_boards_rwlock);

		obufp = kmem_zalloc(sizeof (dr_proto_hdr_t), KM_SLEEP);
		err = drmach_mbox_trans(DRMSG_SHOWBOARD, bnum, obufp,
		    sizeof (dr_proto_hdr_t), (caddr_t)&shb,
		    sizeof (dr_showboard_t));
		kmem_free(obufp, sizeof (dr_proto_hdr_t));

		if (err) {
			if (err->e_code == ESTC_UNAVAILABLE) {
				*id = 0;
				rv = -1;
			}
			sbd_err_clear(&err);
		} else {
			if (!bp)
				bp = *id  = (drmachid_t)drmach_board_new(bnum);
			bp->connected = (shb.bd_assigned && shb.bd_active);
			bp->empty = shb.slot_empty;

			switch (shb.test_status) {
				case DR_TEST_STATUS_UNKNOWN:
				case DR_TEST_STATUS_IPOST:
				case DR_TEST_STATUS_ABORTED:
					bp->cond = SBD_COND_UNKNOWN;
					break;
				case DR_TEST_STATUS_PASSED:
					bp->cond = SBD_COND_OK;
					break;
				case DR_TEST_STATUS_FAILED:
					bp->cond = SBD_COND_FAILED;
					break;
				default:
					bp->cond = SBD_COND_UNKNOWN;
				DRMACH_PR("Unknown test status=0x%x from SC\n",
				    shb.test_status);
					break;
			}
			(void) strncpy(bp->type, shb.board_type,
			    sizeof (bp->type));
			bp->assigned = shb.bd_assigned;
			bp->powered = shb.power_on;
		}
	}
	rw_exit(&drmach_boards_rwlock);
	return (rv);
}

sbd_error_t *
drmach_board_name(int bnum, char *buf, int buflen)
{
	(void) snprintf(buf, buflen, "%s%d", DRMACH_BNUM2SLOT(bnum) ?
	    "IO" : "SB", DRMACH_BNUM2EXP(bnum));

	return (NULL);
}

sbd_error_t *
drmach_board_poweroff(drmachid_t id)
{
	drmach_board_t	*bp;
	sbd_error_t	*err;
	drmach_status_t	 stat;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	bp = id;

	err = drmach_board_status(id, &stat);
	if (!err) {
		if (stat.configured || stat.busy)
			err = drerr_new(0, ESTC_CONFIGBUSY, bp->cm.name);
		else {
			caddr_t	obufp;

			obufp = kmem_zalloc(sizeof (dr_proto_hdr_t), KM_SLEEP);
			err = drmach_mbox_trans(DRMSG_POWEROFF, bp->bnum, obufp,
			    sizeof (dr_proto_hdr_t), (caddr_t)NULL, 0);
			kmem_free(obufp, sizeof (dr_proto_hdr_t));
			if (!err)
				bp->powered = 0;
		}
	}
	return (err);
}

sbd_error_t *
drmach_board_poweron(drmachid_t id)
{
	drmach_board_t	*bp;
	caddr_t		obufp;
	sbd_error_t	*err;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	bp = id;

	obufp = kmem_zalloc(sizeof (dr_proto_hdr_t), KM_SLEEP);
	err = drmach_mbox_trans(DRMSG_POWERON, bp->bnum, obufp,
	    sizeof (dr_proto_hdr_t), (caddr_t)NULL, 0);
	if (!err)
		bp->powered = 1;

	kmem_free(obufp, sizeof (dr_proto_hdr_t));

	return (err);
}

static sbd_error_t *
drmach_board_release(drmachid_t id)
{
	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	return (NULL);
}

sbd_error_t *
drmach_board_test(drmachid_t id, drmach_opts_t *opts, int force)
{
	drmach_board_t		*bp;
	drmach_device_t		*dp[MAX_CORES_PER_CMP];
	dr_mbox_msg_t		*obufp;
	sbd_error_t		*err;
	dr_testboard_reply_t	tbr;
	int			cpylen;
	char			*copts;
	int			is_io;
	cpu_flag_t		oflags[MAX_CORES_PER_CMP];

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	bp = id;

	/*
	 * If the board is an I/O or MAXCAT board, setup I/O cage for
	 * testing. Slot 1 indicates I/O or MAXCAT board.
	 */

	is_io = DRMACH_BNUM2SLOT(bp->bnum);

	obufp = kmem_zalloc(sizeof (dr_mbox_msg_t), KM_SLEEP);

	if (force)
		obufp->msgdata.dm_tb.force = 1;

	obufp->msgdata.dm_tb.immediate = 1;

	if ((opts->size > 0) && ((copts = opts->copts) != NULL)) {
		cpylen = (opts->size > DR_HPOPTLEN ? DR_HPOPTLEN : opts->size);
		bcopy(copts, obufp->msgdata.dm_tb.hpost_opts, cpylen);
	}

	if (is_io) {
		err = drmach_iocage_setup(&obufp->msgdata.dm_tb, dp, oflags);

		if (err) {
			kmem_free(obufp, sizeof (dr_mbox_msg_t));
			return (err);
		}
	}

	err = drmach_mbox_trans(DRMSG_TESTBOARD, bp->bnum, (caddr_t)obufp,
	    sizeof (dr_mbox_msg_t), (caddr_t)&tbr, sizeof (tbr));

	if (!err)
		bp->cond = SBD_COND_OK;
	else
		bp->cond = SBD_COND_UNKNOWN;

	if ((!err) && (tbr.test_status != DR_TEST_STATUS_PASSED)) {
		/* examine test status */
		switch (tbr.test_status) {
			case DR_TEST_STATUS_IPOST:
				bp->cond = SBD_COND_UNKNOWN;
				err = drerr_new(0, ESTC_TEST_IN_PROGRESS, NULL);
				break;
			case DR_TEST_STATUS_UNKNOWN:
				bp->cond = SBD_COND_UNKNOWN;
				err = drerr_new(1,
				    ESTC_TEST_STATUS_UNKNOWN, NULL);
				break;
			case DR_TEST_STATUS_FAILED:
				bp->cond = SBD_COND_FAILED;
				err = drerr_new(1, ESTC_TEST_FAILED, NULL);
				break;
			case DR_TEST_STATUS_ABORTED:
				bp->cond = SBD_COND_UNKNOWN;
				err = drerr_new(1, ESTC_TEST_ABORTED, NULL);
				break;
			default:
				bp->cond = SBD_COND_UNKNOWN;
				err = drerr_new(1, ESTC_TEST_RESULT_UNKNOWN,
				    NULL);
				break;
		}
	}

	/*
	 * If I/O cage test was performed, check for availability of the
	 * cpu used.  If cpu has been returned, it's OK to proceed with
	 * reconfiguring it for use.
	 */
	if (is_io) {
		DRMACH_PR("drmach_board_test: tbr.cpu_recovered: %d",
		    tbr.cpu_recovered);
		DRMACH_PR("drmach_board_test: port id: %d",
		    tbr.cpu_portid);

		/*
		 * Check the cpu_recovered flag in the testboard reply, or
		 * if the testboard request message was not sent to SMS due
		 * to an mboxsc_putmsg() failure, it's OK to recover the
		 * cpu since hpost hasn't touched it.
		 */
		if ((tbr.cpu_recovered && tbr.cpu_portid ==
		    obufp->msgdata.dm_tb.cpu_portid) ||
		    ((err) && (err->e_code == ESTC_MBXRQST))) {

			int i;

			mutex_enter(&cpu_lock);
			for (i = 0; i < MAX_CORES_PER_CMP; i++) {
				if (dp[i] != NULL) {
					(void) drmach_iocage_cpu_return(dp[i],
					    oflags[i]);
				}
			}
			mutex_exit(&cpu_lock);
		} else {
			cmn_err(CE_WARN, "Unable to recover port id %d "
			    "after I/O cage test: cpu_recovered=%d, "
			    "returned portid=%d",
			    obufp->msgdata.dm_tb.cpu_portid,
			    tbr.cpu_recovered, tbr.cpu_portid);
		}
		(void) drmach_iocage_mem_return(&tbr);
	}
	kmem_free(obufp, sizeof (dr_mbox_msg_t));

	return (err);
}

sbd_error_t *
drmach_board_unassign(drmachid_t id)
{
	drmach_board_t	*bp;
	sbd_error_t	*err;
	drmach_status_t	 stat;
	caddr_t		obufp;

	rw_enter(&drmach_boards_rwlock, RW_WRITER);

	if (!DRMACH_IS_BOARD_ID(id)) {
		rw_exit(&drmach_boards_rwlock);
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	}
	bp = id;

	err = drmach_board_status(id, &stat);
	if (err) {
		rw_exit(&drmach_boards_rwlock);
		return (err);
	}

	if (stat.configured || stat.busy) {
		err = drerr_new(0, ESTC_CONFIGBUSY, bp->cm.name);
	} else {

		obufp = kmem_zalloc(sizeof (dr_proto_hdr_t), KM_SLEEP);
		err = drmach_mbox_trans(DRMSG_UNASSIGN, bp->bnum, obufp,
		    sizeof (dr_proto_hdr_t), (caddr_t)NULL, 0);
		kmem_free(obufp, sizeof (dr_proto_hdr_t));
		if (!err) {
			if (drmach_array_set(drmach_boards, bp->bnum, 0) != 0)
				err = DRMACH_INTERNAL_ERROR();
			else
				drmach_board_dispose(bp);
		}
	}
	rw_exit(&drmach_boards_rwlock);
	return (err);
}

static sbd_error_t *
drmach_read_reg_addr(drmach_device_t *dp, uint64_t *p)
{
	int		len;
	drmach_reg_t	reg;
	drmach_node_t	pp;
	drmach_node_t	*np = dp->node;

	/*
	 * If the node does not have a portid property,
	 * it represents a CMP device. For a CMP, the reg
	 * property of the parent holds the information of
	 * interest.
	 */
	if (dp->node->n_getproplen(dp->node, "portid", &len) != 0) {

		if (dp->node->get_parent(dp->node, &pp) != 0) {
			return (DRMACH_INTERNAL_ERROR());
		}
		np = &pp;
	}

	if (np->n_getproplen(np, "reg", &len) != 0)
		return (DRMACH_INTERNAL_ERROR());

	if (len != sizeof (reg))
		return (DRMACH_INTERNAL_ERROR());

	if (np->n_getprop(np, "reg", &reg, sizeof (reg)) != 0)
		return (DRMACH_INTERNAL_ERROR());

	/* reassemble 64-bit base address */
	*p = ((uint64_t)reg.reg_addr_hi << 32) | reg.reg_addr_lo;

	return (NULL);
}

static void
drmach_cpu_read(uint64_t arg1, uint64_t arg2)
{
	uint64_t	*saf_config_reg = (uint64_t *)arg1;
	uint_t		*reg_read = (uint_t *)arg2;

	*saf_config_reg = lddsafconfig();
	*reg_read = 0x1;
}

/*
 * A return value of 1 indicates success and 0 indicates a failure
 */
static int
drmach_cpu_read_scr(drmach_cpu_t *cp, uint64_t *scr)
{

	int 	rv = 0x0;

	*scr = 0x0;

	/*
	 * Confirm cpu was in ready set when xc was issued.
	 * This is done by verifying rv which is
	 * set to 0x1 when xc_one is successful.
	 */
	xc_one(cp->dev.portid, (xcfunc_t *)drmach_cpu_read,
	    (uint64_t)scr, (uint64_t)&rv);

	return (rv);

}

static sbd_error_t *
drmach_cpu_read_cpuid(drmach_cpu_t *cp, processorid_t *cpuid)
{
	drmach_node_t	*np;

	np = cp->dev.node;

	/*
	 * If a CPU does not have a portid property, it must
	 * be a CMP device with a cpuid property.
	 */
	if (np->n_getprop(np, "portid", cpuid, sizeof (*cpuid)) != 0) {

		if (np->n_getprop(np, "cpuid", cpuid, sizeof (*cpuid)) != 0) {
			return (DRMACH_INTERNAL_ERROR());
		}
	}

	return (NULL);
}

/* Starcat CMP core id is bit 2 of the cpuid */
#define	DRMACH_COREID_MASK	(1u << 2)
#define	DRMACH_CPUID2SRAM_IDX(id) \
		((id & DRMACH_COREID_MASK) >> 1 | (id & 0x1))

static sbd_error_t *
drmach_cpu_new(drmach_device_t *proto, drmachid_t *idp)
{
	sbd_error_t	*err;
	uint64_t	scr_pa;
	drmach_cpu_t	*cp = NULL;
	pfn_t		pfn;
	uint64_t	cpu_stardrb_offset, cpu_sram_pa;
	int		idx;
	int		impl;
	processorid_t	cpuid;

	err = drmach_read_reg_addr(proto, &scr_pa);
	if (err) {
		goto fail;
	}

	cp = kmem_zalloc(sizeof (drmach_cpu_t), KM_SLEEP);
	bcopy(proto, &cp->dev, sizeof (cp->dev));
	cp->dev.node = drmach_node_dup(proto->node);
	cp->dev.cm.isa = (void *)drmach_cpu_new;
	cp->dev.cm.dispose = drmach_cpu_dispose;
	cp->dev.cm.release = drmach_cpu_release;
	cp->dev.cm.status = drmach_cpu_status;
	cp->scr_pa = scr_pa;

	err = drmach_cpu_read_cpuid(cp, &cpuid);
	if (err) {
		goto fail;
	}

	err = drmach_cpu_get_impl(cp, &impl);
	if (err) {
		goto fail;
	}

	cp->cpuid = cpuid;
	cp->coreid = STARCAT_CPUID_TO_COREID(cp->cpuid);
	cp->dev.unum = STARCAT_CPUID_TO_AGENT(cp->cpuid);

	/*
	 * Init the board cpu type.  Assumes all board cpus are the same type.
	 */
	if (cp->dev.bp->cpu_impl == 0) {
		cp->dev.bp->cpu_impl = impl;
	}
	ASSERT(cp->dev.bp->cpu_impl == impl);

	/*
	 * XXX CHEETAH SUPPORT
	 * determine if the domain uses Cheetah procs
	 */
	if (drmach_is_cheetah < 0) {
		drmach_is_cheetah = IS_CHEETAH(impl);
	}

	/*
	 * Initialize TTE for mapping CPU SRAM STARDRB buffer.
	 * The STARDRB buffer (16KB on Cheetah+ boards, 32KB on
	 * Jaguar/Panther boards) is shared by all cpus in a Safari port
	 * pair. Each cpu uses 8KB according to the following layout:
	 *
	 * Page 0:	even numbered Cheetah+'s and Panther/Jaguar core 0's
	 * Page 1:	odd numbered Cheetah+'s and Panther/Jaguar core 0's
	 * Page 2:	even numbered Panther/Jaguar core 1's
	 * Page 3:	odd numbered Panther/Jaguar core 1's
	 */
	idx = DRMACH_CPUID2SRAM_IDX(cp->cpuid);
	cpu_stardrb_offset = cp->dev.bp->stardrb_offset + (PAGESIZE * idx);
	cpu_sram_pa = DRMACH_CPU_SRAM_ADDR + cpu_stardrb_offset;
	pfn = cpu_sram_pa >> PAGESHIFT;

	ASSERT(drmach_cpu_sram_tte[cp->cpuid].tte_inthi == 0 &&
	    drmach_cpu_sram_tte[cp->cpuid].tte_intlo == 0);
	drmach_cpu_sram_tte[cp->cpuid].tte_inthi = TTE_PFN_INTHI(pfn) |
	    TTE_VALID_INT | TTE_SZ_INT(TTE8K);
	drmach_cpu_sram_tte[cp->cpuid].tte_intlo = TTE_PFN_INTLO(pfn) |
	    TTE_HWWR_INT | TTE_PRIV_INT | TTE_LCK_INT;

	DRMACH_PR("drmach_cpu_new: cpuid=%d, coreid=%d, stardrb_offset=0x%lx, "
	    "cpu_sram_offset=0x%lx, idx=%d\n", cp->cpuid, cp->coreid,
	    cp->dev.bp->stardrb_offset, cpu_stardrb_offset, idx);

	(void) snprintf(cp->dev.cm.name, sizeof (cp->dev.cm.name), "%s%d",
	    cp->dev.type, cp->dev.unum);

	*idp = (drmachid_t)cp;
	return (NULL);

fail:
	if (cp) {
		drmach_node_dispose(cp->dev.node);
		kmem_free(cp, sizeof (*cp));
	}

	*idp = (drmachid_t)0;
	return (err);
}

static void
drmach_cpu_dispose(drmachid_t id)
{
	drmach_cpu_t	*self;
	processorid_t	cpuid;

	ASSERT(DRMACH_IS_CPU_ID(id));

	self = id;
	if (self->dev.node)
		drmach_node_dispose(self->dev.node);

	cpuid = self->cpuid;
	ASSERT(TTE_IS_VALID(&drmach_cpu_sram_tte[cpuid]) &&
	    TTE_IS_8K(&drmach_cpu_sram_tte[cpuid]) &&
	    TTE_IS_PRIVILEGED(&drmach_cpu_sram_tte[cpuid]) &&
	    TTE_IS_LOCKED(&drmach_cpu_sram_tte[cpuid]));
	drmach_cpu_sram_tte[cpuid].tte_inthi = 0;
	drmach_cpu_sram_tte[cpuid].tte_intlo = 0;

	kmem_free(self, sizeof (*self));
}

static int
drmach_cpu_start(struct cpu *cp)
{
	extern xcfunc_t	drmach_set_lpa;
	extern void	restart_other_cpu(int);
	int		cpuid = cp->cpu_id;
	int		rv, bnum;
	drmach_board_t	*bp;

	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(cpunodes[cpuid].nodeid != (pnode_t)0);

	cp->cpu_flags &= ~CPU_POWEROFF;

	/*
	 * NOTE: restart_other_cpu pauses cpus during the
	 *	 slave cpu start.  This helps to quiesce the
	 *	 bus traffic a bit which makes the tick sync
	 *	 routine in the prom more robust.
	 */
	DRMACH_PR("COLD START for cpu (%d)\n", cpuid);

	if (prom_hotaddcpu(cpuid) != 0) {
		cmn_err(CE_PANIC, "prom_hotaddcpu() for cpuid=%d failed.",
		    cpuid);
	}

	restart_other_cpu(cpuid);

	bnum = drmach_portid2bnum(cpunodes[cpuid].portid);
	rv = drmach_array_get(drmach_boards, bnum, (drmachid_t)&bp);
	if (rv == -1 || bp == NULL) {
		DRMACH_PR("drmach_cpu_start: cannot read board info for "
		    "cpuid=%d: rv=%d, bp=%p\n", cpuid, rv, (void *)bp);
	} else if (DRMACH_L1_SET_LPA(bp) && drmach_reprogram_lpa) {
		int exp;
		int ntries;

		mutex_enter(&drmach_xt_mb_lock);
		mutex_enter(&drmach_slice_table_lock);
		bzero((void *)drmach_xt_mb, drmach_xt_mb_size);

		/*
		 * drmach_slice_table[*]
		 *	bit 5	valid
		 *	bit 0:4	slice number
		 *
		 * drmach_xt_mb[*] format for drmach_set_lpa
		 *	bit 7	valid
		 *	bit 6	set null LPA (overrides bits 0:4)
		 *	bit 0:4	slice number
		 *
		 * drmach_set_lpa derives processor CBASE and CBND
		 * from bits 6 and 0:4 of drmach_xt_mb.  If bit 6 is
		 * set, then CBASE = CBND = 0. Otherwise, CBASE = slice
		 * number; CBND = slice number + 1.
		 * No action is taken if bit 7 is zero.
		 */
		exp = (cpuid >> 5) & 0x1f;
		if (drmach_slice_table[exp] & 0x20) {
			drmach_xt_mb[cpuid] = 0x80 |
			    (drmach_slice_table[exp] & 0x1f);
		} else {
			drmach_xt_mb[cpuid] = 0x80 | 0x40;
		}

		drmach_xt_ready = 0;

		xt_one(cpuid, drmach_set_lpa, NULL, NULL);

		ntries = drmach_cpu_ntries;
		while (!drmach_xt_ready && ntries) {
			DELAY(drmach_cpu_delay);
			ntries--;
		}

		mutex_exit(&drmach_slice_table_lock);
		mutex_exit(&drmach_xt_mb_lock);

		DRMACH_PR(
		    "waited %d out of %d tries for drmach_set_lpa on cpu%d",
		    drmach_cpu_ntries - ntries, drmach_cpu_ntries,
		    cp->cpu_id);
	}

	xt_one(cpuid, vtag_flushpage_tl1, (uint64_t)drmach_cpu_sram_va,
	    (uint64_t)ksfmmup);

	return (0);
}

/*
 * A detaching CPU is xcalled with an xtrap to drmach_cpu_stop_self() after
 * it has been offlined. The function of this routine is to get the cpu
 * spinning in a safe place. The requirement is that the system will not
 * reference anything on the detaching board (memory and i/o is detached
 * elsewhere) and that the CPU not reference anything on any other board
 * in the system.  This isolation is required during and after the writes
 * to the domain masks to remove the board from the domain.
 *
 * To accomplish this isolation the following is done:
 *	1) Create a locked mapping to the STARDRB data buffer located
 *	   in this cpu's sram. There is one TTE per cpu, initialized in
 *	   drmach_cpu_new(). The cpuid is used to select which TTE to use.
 *	   Each Safari port pair shares the CPU SRAM on a Serengeti CPU/MEM
 *	   board. The STARDRB buffer is 16KB on Cheetah+ boards, 32KB on Jaguar
 *	   boards. Each STARDRB buffer is logically divided by DR into one
 *	   8KB page per cpu (or Jaguar core).
 *	2) Copy the target function (drmach_shutdown_asm) into buffer.
 *	3) Jump to function now in the cpu sram.
 *	   Function will:
 *	   3.1) Flush its Ecache (displacement).
 *	   3.2) Flush its Dcache with HW mechanism.
 *	   3.3) Flush its Icache with HW mechanism.
 *	   3.4) Flush all valid and _unlocked_ D-TLB and I-TLB entries.
 *	   3.5) Set LPA to NULL
 *	   3.6) Clear xt_mb to signal completion. Note: cache line is
 *	        recovered by drmach_cpu_poweroff().
 *	4) Jump into an infinite loop.
 */

static void
drmach_cpu_stop_self(void)
{
	extern void drmach_shutdown_asm(uint64_t, uint64_t, int, int, uint64_t);
	extern void drmach_shutdown_asm_end(void);

	tte_t		*tte;
	uint_t		*p, *q;
	uint64_t	 stack_pointer;

	ASSERT(((ptrdiff_t)drmach_shutdown_asm_end -
	    (ptrdiff_t)drmach_shutdown_asm) < PAGESIZE);

	tte = &drmach_cpu_sram_tte[CPU->cpu_id];
	ASSERT(TTE_IS_VALID(tte) && TTE_IS_8K(tte) && TTE_IS_PRIVILEGED(tte) &&
	    TTE_IS_LOCKED(tte));
	sfmmu_dtlb_ld_kva(drmach_cpu_sram_va, tte);
	sfmmu_itlb_ld_kva(drmach_cpu_sram_va, tte);

	/* copy text. standard bcopy not designed to work in nc space */
	p = (uint_t *)drmach_cpu_sram_va;
	q = (uint_t *)drmach_shutdown_asm;
	while (q < (uint_t *)drmach_shutdown_asm_end)
		*p++ = *q++;

	/* zero to assist debug */
	q = (uint_t *)(drmach_cpu_sram_va + PAGESIZE);
	while (p < q)
		*p++ = 0;

	/* a parking spot for the stack pointer */
	stack_pointer = (uint64_t)q;

	/* call copy of drmach_shutdown_asm */
	(*(void (*)())drmach_cpu_sram_va)(
	    stack_pointer,
	    drmach_iocage_paddr,
	    cpunodes[CPU->cpu_id].ecache_size,
	    cpunodes[CPU->cpu_id].ecache_linesize,
	    va_to_pa((void *)&drmach_xt_mb[CPU->cpu_id]));
}

static void
drmach_cpu_shutdown_self(void)
{
	cpu_t		*cp = CPU;
	int		cpuid = cp->cpu_id;
	extern void	flush_windows(void);

	flush_windows();

	(void) spl8();

	ASSERT(cp->cpu_intr_actv == 0);
	ASSERT(cp->cpu_thread == cp->cpu_idle_thread ||
	    cp->cpu_thread == cp->cpu_startup_thread);

	cp->cpu_flags = CPU_OFFLINE | CPU_QUIESCED | CPU_POWEROFF;

	drmach_cpu_stop_self();

	cmn_err(CE_PANIC, "CPU %d FAILED TO SHUTDOWN", cpuid);
}

static sbd_error_t *
drmach_cpu_release(drmachid_t id)
{
	drmach_cpu_t	*cp;
	struct cpu	*cpu;
	sbd_error_t	*err;

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	cp = id;

	ASSERT(MUTEX_HELD(&cpu_lock));

	cpu = cpu_get(cp->cpuid);
	if (cpu == NULL)
		err = DRMACH_INTERNAL_ERROR();
	else
		err = NULL;

	return (err);
}

static sbd_error_t *
drmach_cpu_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_cpu_t	*cp;
	drmach_device_t	*dp;

	ASSERT(DRMACH_IS_CPU_ID(id));
	cp = id;
	dp = &cp->dev;

	stat->assigned = dp->bp->assigned;
	stat->powered = dp->bp->powered;
	mutex_enter(&cpu_lock);
	stat->configured = (cpu_get(cp->cpuid) != NULL);
	mutex_exit(&cpu_lock);
	stat->busy = dp->busy;
	(void) strncpy(stat->type, dp->type, sizeof (stat->type));
	stat->info[0] = '\0';

	return (NULL);
}

sbd_error_t *
drmach_cpu_disconnect(drmachid_t id)
{
	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));

	return (NULL);
}

sbd_error_t *
drmach_cpu_get_id(drmachid_t id, processorid_t *cpuid)
{
	drmach_cpu_t	*cpu;

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	cpu = id;

	*cpuid = cpu->cpuid;
	return (NULL);
}

sbd_error_t *
drmach_cpu_get_impl(drmachid_t id, int *ip)
{
	drmach_node_t	*np;
	int		impl;

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));

	np = ((drmach_device_t *)id)->node;

	if (np->n_getprop(np, "implementation#", &impl, sizeof (impl)) == -1) {
		return (DRMACH_INTERNAL_ERROR());
	}

	*ip = impl;

	return (NULL);
}

/*
 * Flush this cpu's ecache, then ensure all outstanding safari
 * transactions have retired.
 */
void
drmach_cpu_flush_ecache_sync(void)
{
	uint64_t *p;

	ASSERT(curthread->t_bound_cpu == CPU);

	cpu_flush_ecache();

	mutex_enter(&drmach_bus_sync_lock);
	for (p = drmach_bus_sync_list; *p; p++)
		(void) ldphys(*p);
	mutex_exit(&drmach_bus_sync_lock);

	cpu_flush_ecache();
}

sbd_error_t *
drmach_get_dip(drmachid_t id, dev_info_t **dip)
{
	drmach_device_t	*dp;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	dp = id;

	*dip = dp->node->n_getdip(dp->node);
	return (NULL);
}

sbd_error_t *
drmach_io_is_attached(drmachid_t id, int *yes)
{
	drmach_device_t *dp;
	dev_info_t	*dip;
	int state;

	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	dp = id;

	dip = dp->node->n_getdip(dp->node);
	if (dip == NULL) {
		*yes = 0;
		return (NULL);
	}

	state = ddi_get_devstate(dip);
	*yes = i_ddi_devi_attached(dip) || (state == DDI_DEVSTATE_UP);

	return (NULL);
}

static int
drmach_dip_is_schizo_xmits_0_pci_b(dev_info_t *dip)
{
	char			dtype[OBP_MAXPROPNAME];
	int			portid;
	uint_t			pci_csr_base;
	struct pci_phys_spec	*regbuf = NULL;
	int			rv, len;

	ASSERT(dip != NULL);
	rv = ddi_getproplen(DDI_DEV_T_ANY, dip, 0, "device_type", &len);
	if ((rv != DDI_PROP_SUCCESS) || (len > sizeof (dtype)))
		return (0);

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0, "device_type",
	    (caddr_t)dtype, &len) == DDI_PROP_SUCCESS) {

		if (strncmp(dtype, "pci", 3) == 0) {

			/*
			 * Get safari portid. All schizo/xmits 0
			 * safari IDs end in 0x1C.
			 */
			rv = ddi_getproplen(DDI_DEV_T_ANY, dip, 0, "portid",
			    &len);

			if ((rv != DDI_PROP_SUCCESS) ||
			    (len > sizeof (portid)))
				return (0);

			rv = ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0,
			    "portid", (caddr_t)&portid, &len);

			if (rv != DDI_PROP_SUCCESS)
				return (0);

			if ((portid & 0x1F) != 0x1C)
				return (0);

			if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, "reg", (caddr_t)&regbuf,
			    &len) == DDI_PROP_SUCCESS) {

				pci_csr_base = regbuf[0].pci_phys_mid &
				    PCI_CONF_ADDR_MASK;
				kmem_free(regbuf, len);
				/*
				 * All PCI B-Leafs are at configspace 0x70.0000.
				 */
				if (pci_csr_base == 0x700000)
					return (1);
			}
		}
	}
	return (0);
}

#define	SCHIZO_BINDING_NAME		"pci108e,8001"
#define	XMITS_BINDING_NAME		"pci108e,8002"

/*
 * Verify if the dip is an instance of MAN 'eri'.
 */
static int
drmach_dip_is_man_eri(dev_info_t *dip)
{
	struct pci_phys_spec	*regbuf = NULL;
	dev_info_t		*parent_dip;
	char			*name;
	uint_t			pci_device;
	uint_t			pci_function;
	int			len;

	if (dip == NULL)
		return (0);
	/*
	 * Verify if the parent is schizo(xmits)0 and pci B leaf.
	 */
	if (((parent_dip = ddi_get_parent(dip)) == NULL) ||
	    ((name = ddi_binding_name(parent_dip)) == NULL))
		return (0);
	if (strcmp(name, SCHIZO_BINDING_NAME) != 0) {
		/*
		 * This RIO could be on XMITS, so get the dip to
		 * XMITS PCI Leaf.
		 */
		if ((parent_dip = ddi_get_parent(parent_dip)) == NULL)
			return (0);
		if (((name = ddi_binding_name(parent_dip)) == NULL) ||
		    (strcmp(name, XMITS_BINDING_NAME) != 0)) {
			return (0);
		}
	}
	if (!drmach_dip_is_schizo_xmits_0_pci_b(parent_dip))
		return (0);
	/*
	 * Finally make sure it is the MAN eri.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&regbuf, &len) == DDI_PROP_SUCCESS) {

		pci_device = PCI_REG_DEV_G(regbuf->pci_phys_hi);
		pci_function = PCI_REG_FUNC_G(regbuf->pci_phys_hi);
		kmem_free(regbuf, len);

		/*
		 * The network function of the RIO ASIC will always be
		 * device 3 and function 1 ("network@3,1").
		 */
		if ((pci_device == 3) && (pci_function == 1))
			return (1);
	}
	return (0);
}

typedef struct {
	int		iosram_inst;
	dev_info_t	*eri_dip;
	int		bnum;
} drmach_io_inst_t;

int
drmach_board_find_io_insts(dev_info_t *dip, void *args)
{
	drmach_io_inst_t	*ios = (drmach_io_inst_t *)args;

	int	rv;
	int	len;
	int	portid;
	char	name[OBP_MAXDRVNAME];

	rv = ddi_getproplen(DDI_DEV_T_ANY, dip, 0, "portid", &len);

	if ((rv != DDI_PROP_SUCCESS) || (len > sizeof (portid))) {
		return (DDI_WALK_CONTINUE);
	}

	rv = ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, 0,
	    "portid", (caddr_t)&portid, &len);
	if (rv != DDI_PROP_SUCCESS)
		return (DDI_WALK_CONTINUE);

	/* ignore devices that are not on this board */
	if (drmach_portid2bnum(portid) != ios->bnum)
		return (DDI_WALK_CONTINUE);

	if ((ios->iosram_inst < 0) || (ios->eri_dip == NULL)) {
		rv = ddi_getproplen(DDI_DEV_T_ANY, dip, 0, "name", &len);
		if (rv == DDI_PROP_SUCCESS) {

			rv = ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
			    0, "name",
			    (caddr_t)name, &len);
			if (rv != DDI_PROP_SUCCESS)
				return (DDI_WALK_CONTINUE);

			if (strncmp("iosram", name, 6) == 0) {
				ios->iosram_inst = ddi_get_instance(dip);
				if (ios->eri_dip == NULL)
					return (DDI_WALK_CONTINUE);
				else
					return (DDI_WALK_TERMINATE);
			} else {
				if (drmach_dip_is_man_eri(dip)) {
					ASSERT(ios->eri_dip == NULL);
					ndi_hold_devi(dip);
					ios->eri_dip = dip;
					if (ios->iosram_inst < 0)
						return (DDI_WALK_CONTINUE);
					else
						return (DDI_WALK_TERMINATE);
				}
			}
		}
	}
	return (DDI_WALK_CONTINUE);
}

sbd_error_t *
drmach_io_pre_release(drmachid_t id)
{
	drmach_io_inst_t	ios;
	drmach_board_t		*bp;
	int			rv = 0;
	sbd_error_t		*err = NULL;
	drmach_device_t		*dp;
	dev_info_t		*rdip;
	int			circ;

	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	dp = id;
	bp = dp->bp;

	rdip = dp->node->n_getdip(dp->node);

	/* walk device tree to find iosram instance for the board */
	ios.iosram_inst = -1;
	ios.eri_dip = NULL;
	ios.bnum = bp->bnum;

	ndi_devi_enter(rdip, &circ);
	ddi_walk_devs(ddi_get_child(rdip), drmach_board_find_io_insts,
	    (void *)&ios);

	DRMACH_PR("drmach_io_pre_release: bnum=%d iosram=%d eri=0x%p\n",
	    ios.bnum, ios.iosram_inst, (void *)ios.eri_dip);
	ndi_devi_exit(rdip, circ);

	if (ios.eri_dip) {
		/*
		 * Release hold acquired in drmach_board_find_io_insts()
		 */
		ndi_rele_devi(ios.eri_dip);
	}
	if (ios.iosram_inst >= 0) {
		/* call for tunnel switch */
		do {
			DRMACH_PR("calling iosram_switchfrom(%d)\n",
			    ios.iosram_inst);
			rv = iosram_switchfrom(ios.iosram_inst);
			if (rv)
				DRMACH_PR("iosram_switchfrom returned %d\n",
				    rv);
		} while (rv == EAGAIN);

		if (rv)
			err = drerr_new(0, ESTC_IOSWITCH, NULL);
	}
	return (err);
}

sbd_error_t *
drmach_io_unrelease(drmachid_t id)
{
	dev_info_t	*dip;
	sbd_error_t	*err = NULL;
	drmach_device_t	*dp;

	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	dp = id;

	dip = dp->node->n_getdip(dp->node);

	if (dip == NULL)
		err = DRMACH_INTERNAL_ERROR();
	else {
		int (*func)(dev_info_t *dip);

		func = (int (*)(dev_info_t *))kobj_getsymvalue("man_dr_attach",
		    0);

		if (func) {
			drmach_io_inst_t ios;
			dev_info_t	*pdip;
			int		circ;

			/*
			 * Walk device tree to find rio dip for the board
			 * Since we are not interested in iosram instance here,
			 * initialize it to 0, so that the walk terminates as
			 * soon as eri dip is found.
			 */
			ios.iosram_inst = 0;
			ios.eri_dip = NULL;
			ios.bnum = dp->bp->bnum;

			if (pdip = ddi_get_parent(dip)) {
				ndi_hold_devi(pdip);
				ndi_devi_enter(pdip, &circ);
			}
			/*
			 * Root node doesn't have to be held in any way.
			 */
			ddi_walk_devs(dip, drmach_board_find_io_insts,
			    (void *)&ios);

			if (pdip) {
				ndi_devi_exit(pdip, circ);
				ndi_rele_devi(pdip);
			}

			DRMACH_PR("drmach_io_unrelease: bnum=%d eri=0x%p\n",
			    ios.bnum, (void *)ios.eri_dip);

			if (ios.eri_dip) {
				DRMACH_PR("calling man_dr_attach\n");
				if ((*func)(ios.eri_dip))
					err = drerr_new(0, ESTC_NWSWITCH, NULL);
				/*
				 * Release hold acquired in
				 * drmach_board_find_io_insts()
				 */
				ndi_rele_devi(ios.eri_dip);
			}
		} else
			DRMACH_PR("man_dr_attach NOT present\n");
	}
	return (err);
}

static sbd_error_t *
drmach_io_release(drmachid_t id)
{
	dev_info_t	*dip;
	sbd_error_t	*err = NULL;
	drmach_device_t	*dp;

	if (!DRMACH_IS_IO_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	dp = id;

	dip = dp->node->n_getdip(dp->node);

	if (dip == NULL)
		err = DRMACH_INTERNAL_ERROR();
	else {
		int (*func)(dev_info_t *dip);

		func = (int (*)(dev_info_t *))kobj_getsymvalue("man_dr_detach",
		    0);

		if (func) {
			drmach_io_inst_t ios;
			dev_info_t	*pdip;
			int		circ;

			/*
			 * Walk device tree to find rio dip for the board
			 * Since we are not interested in iosram instance here,
			 * initialize it to 0, so that the walk terminates as
			 * soon as eri dip is found.
			 */
			ios.iosram_inst = 0;
			ios.eri_dip = NULL;
			ios.bnum = dp->bp->bnum;

			if (pdip = ddi_get_parent(dip)) {
				ndi_hold_devi(pdip);
				ndi_devi_enter(pdip, &circ);
			}
			/*
			 * Root node doesn't have to be held in any way.
			 */
			ddi_walk_devs(dip, drmach_board_find_io_insts,
			    (void *)&ios);

			if (pdip) {
				ndi_devi_exit(pdip, circ);
				ndi_rele_devi(pdip);
			}

			DRMACH_PR("drmach_io_release: bnum=%d eri=0x%p\n",
			    ios.bnum, (void *)ios.eri_dip);

			if (ios.eri_dip) {
				DRMACH_PR("calling man_dr_detach\n");
				if ((*func)(ios.eri_dip))
					err = drerr_new(0, ESTC_NWSWITCH, NULL);
				/*
				 * Release hold acquired in
				 * drmach_board_find_io_insts()
				 */
				ndi_rele_devi(ios.eri_dip);
			}
		} else
			DRMACH_PR("man_dr_detach NOT present\n");
	}
	return (err);
}

sbd_error_t *
drmach_io_post_release(drmachid_t id)
{
	char 		*path;
	dev_info_t	*rdip;
	drmach_device_t	*dp;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	dp = id;

	rdip = dp->node->n_getdip(dp->node);

	/*
	 * Always called after drmach_unconfigure() which on Starcat
	 * unconfigures the branch but doesn't remove it so the
	 * dip must always exist.
	 */
	ASSERT(rdip);

	ASSERT(e_ddi_branch_held(rdip));
#ifdef DEBUG
	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(rdip, path);
	DRMACH_PR("post_release dip path is: %s\n", path);
	kmem_free(path, MAXPATHLEN);
#endif

	if (strcmp(dp->type, DRMACH_DEVTYPE_PCI) == 0) {
		if (schpc_remove_pci(rdip)) {
			DRMACH_PR("schpc_remove_pci failed\n");
			return (drerr_new(0, ESBD_OFFLINE, NULL));
		} else {
			DRMACH_PR("schpc_remove_pci succeeded\n");
		}
	}

	return (NULL);
}

sbd_error_t *
drmach_io_post_attach(drmachid_t id)
{
	int		circ;
	dev_info_t	*dip;
	dev_info_t	*pdip;
	drmach_device_t	*dp;
	drmach_io_inst_t ios;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	dp = id;

	dip = dp->node->n_getdip(dp->node);

	/*
	 * We held the branch rooted at dip earlier, so at a minimum the
	 * root i.e. dip must be present in the device tree.
	 */
	ASSERT(dip);

	if (strcmp(dp->type, DRMACH_DEVTYPE_PCI) == 0) {
		if (schpc_add_pci(dip)) {
			DRMACH_PR("schpc_add_pci failed\n");
		} else {
			DRMACH_PR("schpc_add_pci succeeded\n");
		}
	}

	/*
	 * Walk device tree to find rio dip for the board
	 * Since we are not interested in iosram instance here,
	 * initialize it to 0, so that the walk terminates as
	 * soon as eri dip is found.
	 */
	ios.iosram_inst = 0;
	ios.eri_dip = NULL;
	ios.bnum = dp->bp->bnum;

	if (pdip = ddi_get_parent(dip)) {
		ndi_hold_devi(pdip);
		ndi_devi_enter(pdip, &circ);
	}
	/*
	 * Root node doesn't have to be held in any way.
	 */
	ddi_walk_devs(dip, drmach_board_find_io_insts, (void *)&ios);
	if (pdip) {
		ndi_devi_exit(pdip, circ);
		ndi_rele_devi(pdip);
	}

	DRMACH_PR("drmach_io_post_attach: bnum=%d eri=0x%p\n",
	    ios.bnum, (void *)ios.eri_dip);

	if (ios.eri_dip) {
		int (*func)(dev_info_t *dip);

		func =
		    (int (*)(dev_info_t *))kobj_getsymvalue("man_dr_attach", 0);

		if (func) {
			DRMACH_PR("calling man_dr_attach\n");
			(void) (*func)(ios.eri_dip);
		} else {
			DRMACH_PR("man_dr_attach NOT present\n");
		}

		/*
		 * Release hold acquired in drmach_board_find_io_insts()
		 */
		ndi_rele_devi(ios.eri_dip);

	}

	return (NULL);
}

static sbd_error_t *
drmach_io_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_device_t *dp;
	sbd_error_t	*err;
	int		 configured;

	ASSERT(DRMACH_IS_IO_ID(id));
	dp = id;

	err = drmach_io_is_attached(id, &configured);
	if (err)
		return (err);

	stat->assigned = dp->bp->assigned;
	stat->powered = dp->bp->powered;
	stat->configured = (configured != 0);
	stat->busy = dp->busy;
	(void) strncpy(stat->type, dp->type, sizeof (stat->type));
	stat->info[0] = '\0';

	return (NULL);
}

sbd_error_t *
drmach_mem_init_size(drmachid_t id)
{
	drmach_mem_t	*mp;
	sbd_error_t	*err;
	gdcd_t		*gdcd;
	mem_chunk_t	*chunk;
	uint64_t	 chunks, pa, mask, sz;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	mp = id;

	err = drmach_mem_get_base_physaddr(id, &pa);
	if (err)
		return (err);

	mask = ~ (DRMACH_MEM_SLICE_SIZE - 1);
	pa &= mask;

	gdcd = drmach_gdcd_new();
	if (gdcd == NULL)
		return (DRMACH_INTERNAL_ERROR());

	sz = 0;
	chunk = gdcd->dcd_chunk_list.dcl_chunk;
	chunks = gdcd->dcd_chunk_list.dcl_chunks;
	while (chunks-- != 0) {
		if ((chunk->mc_base_pa & mask) == pa) {
			sz += chunk->mc_mbytes * 1048576;
		}

		++chunk;
	}
	mp->nbytes = sz;

	drmach_gdcd_dispose(gdcd);
	return (NULL);
}

/*
 * Hardware registers are organized into consecutively
 * addressed registers.  The reg property's hi and lo fields
 * together describe the base address of the register set for
 * this memory-controller.  Register descriptions and offsets
 * (from the base address) are as follows:
 *
 * Description				Offset	Size (bytes)
 * Memory Timing Control Register I	0x00	8
 * Memory Timing Control Register II	0x08	8
 * Memory Address Decoding Register I	0x10	8
 * Memory Address Decoding Register II	0x18	8
 * Memory Address Decoding Register III	0x20	8
 * Memory Address Decoding Register IV	0x28	8
 * Memory Address Control Register	0x30	8
 * Memory Timing Control Register III	0x38	8
 * Memory Timing Control Register IV	0x40	8
 * Memory Timing Control Register V  	0x48	8 (Jaguar, Panther only)
 * EMU Activity Status Register		0x50	8 (Panther only)
 *
 * Only the Memory Address Decoding Register and EMU Activity Status
 * Register addresses are needed for DRMACH.
 */
static sbd_error_t *
drmach_mem_new(drmach_device_t *proto, drmachid_t *idp)
{
	sbd_error_t	*err;
	uint64_t	 madr_pa;
	drmach_mem_t	*mp;
	int		 bank, count;

	err = drmach_read_reg_addr(proto, &madr_pa);
	if (err)
		return (err);

	mp = kmem_zalloc(sizeof (drmach_mem_t), KM_SLEEP);
	bcopy(proto, &mp->dev, sizeof (mp->dev));
	mp->dev.node = drmach_node_dup(proto->node);
	mp->dev.cm.isa = (void *)drmach_mem_new;
	mp->dev.cm.dispose = drmach_mem_dispose;
	mp->dev.cm.release = drmach_mem_release;
	mp->dev.cm.status = drmach_mem_status;
	mp->madr_pa = madr_pa;

	(void) snprintf(mp->dev.cm.name,
	    sizeof (mp->dev.cm.name), "%s", mp->dev.type);

	for (count = bank = 0; bank < DRMACH_MC_NBANKS; bank++) {
		uint64_t madr;

		drmach_mem_read_madr(mp, bank, &madr);
		if (madr & DRMACH_MC_VALID_MASK) {
			count += 1;
			break;
		}
	}

	/*
	 * If none of the banks had their valid bit set, that means
	 * post did not configure this MC to participate in the
	 * domain.  So, pretend this node does not exist by returning
	 * a drmachid of zero.
	 */
	if (count == 0) {
		/* drmach_mem_dispose frees board mem list */
		drmach_node_dispose(mp->dev.node);
		kmem_free(mp, sizeof (*mp));
		*idp = (drmachid_t)0;
		return (NULL);
	}

	/*
	 * Only one mem unit per board is exposed to the
	 * PIM layer.  The first mem unit encountered during
	 * tree walk is used to represent all mem units on
	 * the same board.
	 */
	if (mp->dev.bp->mem == NULL) {
		/* start list of mem units on this board */
		mp->dev.bp->mem = mp;

		/*
		 * force unum to zero since this is the only mem unit
		 * that will be visible to the PIM layer.
		 */
		mp->dev.unum = 0;

		/*
		 * board memory size kept in this mem unit only
		 */
		err = drmach_mem_init_size(mp);
		if (err) {
			mp->dev.bp->mem = NULL;
			/* drmach_mem_dispose frees board mem list */
			drmach_node_dispose(mp->dev.node);
			kmem_free(mp, sizeof (*mp));
			*idp = (drmachid_t)0;
			return (NULL);
		}

		/*
		 * allow this instance (the first encountered on this board)
		 * to be visible to the PIM layer.
		 */
		*idp = (drmachid_t)mp;
	} else {
		drmach_mem_t *lp;

		/* hide this mem instance behind the first. */
		for (lp = mp->dev.bp->mem; lp->next; lp = lp->next)
			;
		lp->next = mp;

		/*
		 * hide this instance from the caller.
		 * See drmach_board_find_devices_cb() for details.
		 */
		*idp = (drmachid_t)0;
	}

	return (NULL);
}

static void
drmach_mem_dispose(drmachid_t id)
{
	drmach_mem_t *mp, *next;
	drmach_board_t *bp;

	ASSERT(DRMACH_IS_MEM_ID(id));

	mutex_enter(&drmach_bus_sync_lock);

	mp = id;
	bp = mp->dev.bp;

	do {
		if (mp->dev.node)
			drmach_node_dispose(mp->dev.node);

		next = mp->next;
		kmem_free(mp, sizeof (*mp));
		mp = next;
	} while (mp);

	bp->mem = NULL;

	drmach_bus_sync_list_update();
	mutex_exit(&drmach_bus_sync_lock);
}

sbd_error_t *
drmach_mem_add_span(drmachid_t id, uint64_t basepa, uint64_t size)
{
	pfn_t		basepfn = (pfn_t)(basepa >> PAGESHIFT);
	pgcnt_t		npages = (pgcnt_t)(size >> PAGESHIFT);
	int		rv;

	ASSERT(size != 0);

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));

	rv = kcage_range_add(basepfn, npages, KCAGE_DOWN);
	if (rv == ENOMEM) {
		cmn_err(CE_WARN, "%lu megabytes not available"
		    " to kernel cage", size >> 20);
	} else if (rv != 0) {
		/* catch this in debug kernels */
		ASSERT(0);

		cmn_err(CE_WARN, "unexpected kcage_range_add"
		    " return value %d", rv);
	}

	return (NULL);
}

sbd_error_t *
drmach_mem_del_span(drmachid_t id, uint64_t basepa, uint64_t size)
{
	pfn_t		 basepfn = (pfn_t)(basepa >> PAGESHIFT);
	pgcnt_t		 npages = (pgcnt_t)(size >> PAGESHIFT);
	int		 rv;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));

	if (size > 0) {
		rv = kcage_range_delete_post_mem_del(basepfn, npages);
		if (rv != 0) {
			cmn_err(CE_WARN,
			    "unexpected kcage_range_delete_post_mem_del"
			    " return value %d", rv);
			return (DRMACH_INTERNAL_ERROR());
		}
	}

	return (NULL);
}

sbd_error_t *
drmach_mem_disable(drmachid_t id)
{
	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	else
		return (NULL);
}

sbd_error_t *
drmach_mem_enable(drmachid_t id)
{
	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	else
		return (NULL);
}

sbd_error_t *
drmach_mem_get_alignment(drmachid_t id, uint64_t *mask)
{
#define	MB(mb) ((mb) * 1048576ull)

	static struct {
		uint_t		uk;
		uint64_t	segsz;
	}  uk2segsz[] = {
		{ 0x003,	MB(256)	  },
		{ 0x007,	MB(512)	  },
		{ 0x00f,	MB(1024)  },
		{ 0x01f,	MB(2048)  },
		{ 0x03f,	MB(4096)  },
		{ 0x07f,	MB(8192)  },
		{ 0x0ff,	MB(16384) },
		{ 0x1ff,	MB(32768) },
		{ 0x3ff,	MB(65536) },
		{ 0x7ff,	MB(131072) }
	};
	static int len = sizeof (uk2segsz) / sizeof (uk2segsz[0]);

#undef MB

	uint64_t	 largest_sz = 0;
	drmach_mem_t	*mp;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));

	/* prime the result with a default value */
	*mask = (DRMACH_MEM_SLICE_SIZE - 1);

	for (mp = id; mp; mp = mp->next) {
		int bank;

		for (bank = 0; bank < DRMACH_MC_NBANKS; bank++) {
			int		i;
			uint_t		uk;
			uint64_t	madr;

			/* get register value, extract uk and normalize */
			drmach_mem_read_madr(mp, bank, &madr);

			if (!(madr & DRMACH_MC_VALID_MASK))
				continue;

			uk = DRMACH_MC_UK(madr);

			/* match uk value */
			for (i = 0; i < len; i++)
				if (uk == uk2segsz[i].uk)
					break;

			if (i < len) {
				uint64_t sz = uk2segsz[i].segsz;

				/*
				 * remember largest segment size,
				 * update mask result
				 */
				if (sz > largest_sz) {
					largest_sz = sz;
					*mask = sz - 1;
				}
			} else {
				/*
				 * uk not in table, punt using
				 * entire slice size. no longer any
				 * reason to check other banks.
				 */
				*mask = (DRMACH_MEM_SLICE_SIZE - 1);
				return (NULL);
			}
		}
	}

	return (NULL);
}

sbd_error_t *
drmach_mem_get_base_physaddr(drmachid_t id, uint64_t *base_addr)
{
	drmach_mem_t *mp;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));

	*base_addr = (uint64_t)-1;
	for (mp = id; mp; mp = mp->next) {
		int bank;

		for (bank = 0; bank < DRMACH_MC_NBANKS; bank++) {
			uint64_t addr, madr;

			drmach_mem_read_madr(mp, bank, &madr);
			if (madr & DRMACH_MC_VALID_MASK) {
				addr = DRMACH_MC_UM_TO_PA(madr) |
				    DRMACH_MC_LM_TO_PA(madr);

				if (addr < *base_addr)
					*base_addr = addr;
			}
		}
	}

	/* should not happen, but ... */
	if (*base_addr == (uint64_t)-1)
		return (DRMACH_INTERNAL_ERROR());

	return (NULL);
}

void
drmach_bus_sync_list_update(void)
{
	int		rv, idx, cnt = 0;
	drmachid_t	id;

	ASSERT(MUTEX_HELD(&drmach_bus_sync_lock));

	rv = drmach_array_first(drmach_boards, &idx, &id);
	while (rv == 0) {
		drmach_board_t		*bp = id;
		drmach_mem_t		*mp = bp->mem;

		while (mp) {
			int bank;

			for (bank = 0; bank < DRMACH_MC_NBANKS; bank++) {
				uint64_t madr;

				drmach_mem_read_madr(mp, bank, &madr);
				if (madr & DRMACH_MC_VALID_MASK) {
					uint64_t pa;

					pa  = DRMACH_MC_UM_TO_PA(madr);
					pa |= DRMACH_MC_LM_TO_PA(madr);

					/*
					 * The list is zero terminated.
					 * Offset the pa by a doubleword
					 * to avoid confusing a pa value of
					 * of zero with the terminator.
					 */
					pa += sizeof (uint64_t);

					drmach_bus_sync_list[cnt++] = pa;
				}
			}

			mp = mp->next;
		}

		rv = drmach_array_next(drmach_boards, &idx, &id);
	}

	drmach_bus_sync_list[cnt] = 0;
}

sbd_error_t *
drmach_mem_get_memlist(drmachid_t id, struct memlist **ml)
{
	sbd_error_t	*err;
	struct memlist	*mlist;
	gdcd_t		*gdcd;
	mem_chunk_t	*chunk;
	uint64_t	 chunks, pa, mask;

	err = drmach_mem_get_base_physaddr(id, &pa);
	if (err)
		return (err);

	gdcd = drmach_gdcd_new();
	if (gdcd == NULL)
		return (DRMACH_INTERNAL_ERROR());

	mask = ~ (DRMACH_MEM_SLICE_SIZE - 1);
	pa &= mask;

	mlist = NULL;
	chunk = gdcd->dcd_chunk_list.dcl_chunk;
	chunks = gdcd->dcd_chunk_list.dcl_chunks;
	while (chunks-- != 0) {
		if ((chunk->mc_base_pa & mask) == pa) {
			mlist = memlist_add_span(mlist, chunk->mc_base_pa,
			    chunk->mc_mbytes * 1048576);
		}

		++chunk;
	}

	drmach_gdcd_dispose(gdcd);

#ifdef DEBUG
	DRMACH_PR("GDCD derived memlist:");
	memlist_dump(mlist);
#endif

	*ml = mlist;
	return (NULL);
}

sbd_error_t *
drmach_mem_get_size(drmachid_t id, uint64_t *bytes)
{
	drmach_mem_t	*mp;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	mp = id;

	ASSERT(mp->nbytes != 0);
	*bytes = mp->nbytes;

	return (NULL);
}

sbd_error_t *
drmach_mem_get_slice_size(drmachid_t id, uint64_t *bytes)
{
	sbd_error_t	*err;
	drmach_device_t	*mp;

	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	mp = id;

	switch (DRMACH_BNUM2SLOT(mp->bp->bnum)) {
		case 0:	*bytes = DRMACH_MEM_USABLE_SLICE_SIZE;
			err = NULL;
			break;

		case 1: *bytes = 0;
			err = NULL;
			break;

		default:
			err = DRMACH_INTERNAL_ERROR();
			break;
	}

	return (err);
}

processorid_t drmach_mem_cpu_affinity_nail;

processorid_t
drmach_mem_cpu_affinity(drmachid_t id)
{
	drmach_device_t	*mp;
	drmach_board_t	*bp;
	processorid_t	 cpuid;

	if (!DRMACH_IS_MEM_ID(id))
		return (CPU_CURRENT);

	if (drmach_mem_cpu_affinity_nail) {
		cpuid = drmach_mem_cpu_affinity_nail;

		if (cpuid < 0 || cpuid > NCPU)
			return (CPU_CURRENT);

		mutex_enter(&cpu_lock);
		if (cpu[cpuid] == NULL || !CPU_ACTIVE(cpu[cpuid]))
			cpuid = CPU_CURRENT;
		mutex_exit(&cpu_lock);

		return (cpuid);
	}

	/* try to choose a proc on the target board */
	mp = id;
	bp = mp->bp;
	if (bp->devices) {
		int		 rv;
		int		 d_idx;
		drmachid_t	 d_id;

		rv = drmach_array_first(bp->devices, &d_idx, &d_id);
		while (rv == 0) {
			if (DRMACH_IS_CPU_ID(d_id)) {
				drmach_cpu_t	*cp = d_id;

				mutex_enter(&cpu_lock);
				cpuid = cp->cpuid;
				if (cpu[cpuid] && CPU_ACTIVE(cpu[cpuid])) {
					mutex_exit(&cpu_lock);
					return (cpuid);
				} else {
					mutex_exit(&cpu_lock);
				}
			}

			rv = drmach_array_next(bp->devices, &d_idx, &d_id);
		}
	}

	/* otherwise, this proc, wherever it is */
	return (CPU_CURRENT);
}

static sbd_error_t *
drmach_mem_release(drmachid_t id)
{
	if (!DRMACH_IS_MEM_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	return (NULL);
}

static sbd_error_t *
drmach_mem_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_mem_t	*mp;
	sbd_error_t	*err;
	uint64_t	 pa, slice_size;
	struct memlist	*ml;

	ASSERT(DRMACH_IS_MEM_ID(id));
	mp = id;

	/* get starting physical address of target memory */
	err = drmach_mem_get_base_physaddr(id, &pa);
	if (err)
		return (err);

	/* round down to slice boundary */
	slice_size = DRMACH_MEM_SLICE_SIZE;
	pa &= ~ (slice_size - 1);

	/* stop at first span that is in slice */
	memlist_read_lock();
	for (ml = phys_install; ml; ml = ml->ml_next)
		if (ml->ml_address >= pa && ml->ml_address < pa + slice_size)
			break;
	memlist_read_unlock();

	stat->assigned = mp->dev.bp->assigned;
	stat->powered = mp->dev.bp->powered;
	stat->configured = (ml != NULL);
	stat->busy = mp->dev.busy;
	(void) strncpy(stat->type, mp->dev.type, sizeof (stat->type));
	stat->info[0] = '\0';

	return (NULL);
}

sbd_error_t *
drmach_board_deprobe(drmachid_t id)
{
	drmach_board_t	*bp;
	sbd_error_t	*err = NULL;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	bp = id;

	if (bp->tree) {
		drmach_node_dispose(bp->tree);
		bp->tree = NULL;
	}
	if (bp->devices) {
		drmach_array_dispose(bp->devices, drmach_device_dispose);
		bp->devices = NULL;
		bp->mem = NULL;  /* TODO: still needed? */
	}
	return (err);
}

/*ARGSUSED1*/
static sbd_error_t *
drmach_pt_showlpa(drmachid_t id, drmach_opts_t *opts)
{
	drmach_device_t	*dp;
	uint64_t	val;
	int		err = 1;

	if (DRMACH_IS_CPU_ID(id)) {
		drmach_cpu_t *cp = id;
		if (drmach_cpu_read_scr(cp, &val))
			err = 0;
	} else if (DRMACH_IS_IO_ID(id) && ((drmach_io_t *)id)->scsr_pa != 0) {
		drmach_io_t *io = id;
		val = lddphysio(io->scsr_pa);
		err = 0;
	}
	if (err)
		return (drerr_new(0, ESTC_INAPPROP, NULL));

	dp = id;
	uprintf("showlpa %s::%s portid %d, base pa %lx, bound pa %lx\n",
	    dp->bp->cm.name,
	    dp->cm.name,
	    dp->portid,
	    (long)(DRMACH_LPA_BASE_TO_PA(val)),
	    (long)(DRMACH_LPA_BND_TO_PA(val)));

	return (NULL);
}

/*ARGSUSED*/
static sbd_error_t *
drmach_pt_ikprobe(drmachid_t id, drmach_opts_t *opts)
{
	drmach_board_t		*bp = (drmach_board_t *)id;
	sbd_error_t		*err;
	sc_gptwocfg_cookie_t	scc;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));

	/* do saf configurator stuff */
	DRMACH_PR("calling sc_probe_board for bnum=%d\n", bp->bnum);
	scc = sc_probe_board(bp->bnum);
	if (scc == NULL) {
		err = drerr_new(0, ESTC_PROBE, bp->cm.name);
		return (err);
	}

	return (err);
}

/*ARGSUSED*/
static sbd_error_t *
drmach_pt_ikdeprobe(drmachid_t id, drmach_opts_t *opts)
{
	drmach_board_t	*bp;
	sbd_error_t	*err = NULL;
	sc_gptwocfg_cookie_t	scc;

	if (!DRMACH_IS_BOARD_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	bp = id;

	cmn_err(CE_CONT, "DR: in-kernel unprobe board %d\n", bp->bnum);
	scc = sc_unprobe_board(bp->bnum);
	if (scc != NULL) {
		err = drerr_new(0, ESTC_DEPROBE, bp->cm.name);
	}

	if (err == NULL)
		err = drmach_board_deprobe(id);

	return (err);
}

static sbd_error_t *
drmach_pt_readmem(drmachid_t id, drmach_opts_t *opts)
{
	_NOTE(ARGUNUSED(id))
	_NOTE(ARGUNUSED(opts))

	struct memlist	*ml;
	uint64_t	src_pa;
	uint64_t	dst_pa;
	uint64_t	dst;

	dst_pa = va_to_pa(&dst);

	memlist_read_lock();
	for (ml = phys_install; ml; ml = ml->ml_next) {
		uint64_t	nbytes;

		src_pa = ml->ml_address;
		nbytes = ml->ml_size;

		while (nbytes != 0ull) {

			/* copy 32 bytes at src_pa to dst_pa */
			bcopy32_il(src_pa, dst_pa);

			/* increment by 32 bytes */
			src_pa += (4 * sizeof (uint64_t));

			/* decrement by 32 bytes */
			nbytes -= (4 * sizeof (uint64_t));
		}
	}
	memlist_read_unlock();

	return (NULL);
}

static sbd_error_t *
drmach_pt_recovercpu(drmachid_t id, drmach_opts_t *opts)
{
	_NOTE(ARGUNUSED(opts))

	drmach_cpu_t	*cp;

	if (!DRMACH_IS_CPU_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	cp = id;

	mutex_enter(&cpu_lock);
	(void) drmach_iocage_cpu_return(&(cp->dev),
	    CPU_ENABLE | CPU_EXISTS | CPU_READY | CPU_RUNNING);
	mutex_exit(&cpu_lock);

	return (NULL);
}

/*
 * Starcat DR passthrus are for debugging purposes only.
 */
static struct {
	const char	*name;
	sbd_error_t	*(*handler)(drmachid_t id, drmach_opts_t *opts);
} drmach_pt_arr[] = {
	{ "showlpa",		drmach_pt_showlpa		},
	{ "ikprobe",		drmach_pt_ikprobe		},
	{ "ikdeprobe",		drmach_pt_ikdeprobe		},
	{ "readmem",		drmach_pt_readmem		},
	{ "recovercpu",		drmach_pt_recovercpu		},

	/* the following line must always be last */
	{ NULL,			NULL				}
};

/*ARGSUSED*/
sbd_error_t *
drmach_passthru(drmachid_t id, drmach_opts_t *opts)
{
	int		i;
	sbd_error_t	*err;

	i = 0;
	while (drmach_pt_arr[i].name != NULL) {
		int len = strlen(drmach_pt_arr[i].name);

		if (strncmp(drmach_pt_arr[i].name, opts->copts, len) == 0)
			break;

		i += 1;
	}

	if (drmach_pt_arr[i].name == NULL)
		err = drerr_new(0, ESTC_UNKPTCMD, opts->copts);
	else
		err = (*drmach_pt_arr[i].handler)(id, opts);

	return (err);
}

sbd_error_t *
drmach_release(drmachid_t id)
{
	drmach_common_t *cp;

	if (!DRMACH_IS_DEVICE_ID(id))
		return (drerr_new(0, ESTC_INAPPROP, NULL));
	cp = id;

	return (cp->release(id));
}

sbd_error_t *
drmach_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_common_t *cp;
	sbd_error_t	*err;

	rw_enter(&drmach_boards_rwlock, RW_READER);

	if (!DRMACH_IS_ID(id)) {
		rw_exit(&drmach_boards_rwlock);
		return (drerr_new(0, ESTC_NOTID, NULL));
	}

	cp = id;

	err = cp->status(id, stat);
	rw_exit(&drmach_boards_rwlock);
	return (err);
}

static sbd_error_t *
drmach_i_status(drmachid_t id, drmach_status_t *stat)
{
	drmach_common_t *cp;

	if (!DRMACH_IS_ID(id))
		return (drerr_new(0, ESTC_NOTID, NULL));
	cp = id;

	return (cp->status(id, stat));
}

/*ARGSUSED*/
sbd_error_t *
drmach_unconfigure(drmachid_t id, int flags)
{
	drmach_device_t	*dp;
	dev_info_t 	*rdip;

	char	name[OBP_MAXDRVNAME];
	int rv;

	/*
	 * Since CPU nodes are not configured, it is
	 * necessary to skip the unconfigure step as
	 * well.
	 */
	if (DRMACH_IS_CPU_ID(id)) {
		return (NULL);
	}

	for (; id; ) {
		dev_info_t	*fdip = NULL;

		if (!DRMACH_IS_DEVICE_ID(id))
			return (drerr_new(0, ESTC_INAPPROP, NULL));
		dp = id;

		rdip = dp->node->n_getdip(dp->node);

		/*
		 * drmach_unconfigure() is always called on a configured branch.
		 * So the root of the branch was held earlier and must exist.
		 */
		ASSERT(rdip);

		DRMACH_PR("drmach_unconfigure: unconfiguring DDI branch");

		rv = dp->node->n_getprop(dp->node,
		    "name", name, OBP_MAXDRVNAME);

		/* The node must have a name */
		if (rv)
			return (0);

		if (drmach_name2type_idx(name) < 0) {
			if (DRMACH_IS_MEM_ID(id)) {
				drmach_mem_t	*mp = id;
				id = mp->next;
			} else {
				id = NULL;
			}
			continue;
		}

		/*
		 * NOTE: FORCE flag is no longer needed under devfs
		 */
		ASSERT(e_ddi_branch_held(rdip));
		if (e_ddi_branch_unconfigure(rdip, &fdip, 0) != 0) {
			sbd_error_t *err = NULL;
			char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

			/*
			 * If non-NULL, fdip is returned held and must be
			 * released.
			 */
			if (fdip != NULL) {
				(void) ddi_pathname(fdip, path);
				ddi_release_devi(fdip);
			} else {
				(void) ddi_pathname(rdip, path);
			}

			err = drerr_new(1, ESTC_DRVFAIL, path);

			kmem_free(path, MAXPATHLEN);

			/*
			 * If we were unconfiguring an IO board, a call was
			 * made to man_dr_detach.  We now need to call
			 * man_dr_attach to regain man use of the eri.
			 */
			if (DRMACH_IS_IO_ID(id)) {
				int (*func)(dev_info_t *dip);

				func = (int (*)(dev_info_t *))kobj_getsymvalue\
				    ("man_dr_attach", 0);

				if (func) {
					drmach_io_inst_t ios;
					dev_info_t 	*pdip;
					int		circ;

					/*
					 * Walk device tree to find rio dip for
					 * the board
					 * Since we are not interested in iosram
					 * instance here, initialize it to 0, so
					 * that the walk terminates as soon as
					 * eri dip is found.
					 */
					ios.iosram_inst = 0;
					ios.eri_dip = NULL;
					ios.bnum = dp->bp->bnum;

					if (pdip = ddi_get_parent(rdip)) {
						ndi_hold_devi(pdip);
						ndi_devi_enter(pdip, &circ);
					}
					/*
					 * Root node doesn't have to be held in
					 * any way.
					 */
					ASSERT(e_ddi_branch_held(rdip));
					ddi_walk_devs(rdip,
					    drmach_board_find_io_insts,
					    (void *)&ios);

					DRMACH_PR("drmach_unconfigure: bnum=%d"
					    " eri=0x%p\n",
					    ios.bnum, (void *)ios.eri_dip);

					if (pdip) {
						ndi_devi_exit(pdip, circ);
						ndi_rele_devi(pdip);
					}

					if (ios.eri_dip) {
						DRMACH_PR("calling"
						    " man_dr_attach\n");
						(void) (*func)(ios.eri_dip);
						/*
						 * Release hold acquired in
						 * drmach_board_find_io_insts()
						 */
						ndi_rele_devi(ios.eri_dip);
					}
				}
			}
			return (err);
		}

		if (DRMACH_IS_MEM_ID(id)) {
			drmach_mem_t	*mp = id;
			id = mp->next;
		} else {
			id = NULL;
		}
	}

	return (NULL);
}

/*
 * drmach interfaces to legacy Starfire platmod logic
 * linkage via runtime symbol look up, called from plat_cpu_power*
 */

/*
 * Start up a cpu.  It is possible that we're attempting to restart
 * the cpu after an UNCONFIGURE in which case the cpu will be
 * spinning in its cache.  So, all we have to do is wake it up.
 * Under normal circumstances the cpu will be coming from a previous
 * CONNECT and thus will be spinning in OBP.  In both cases, the
 * startup sequence is the same.
 */
int
drmach_cpu_poweron(struct cpu *cp)
{
	DRMACH_PR("drmach_cpu_poweron: starting cpuid %d\n", cp->cpu_id);

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (drmach_cpu_start(cp) != 0)
		return (EBUSY);
	else
		return (0);
}

int
drmach_cpu_poweroff(struct cpu *cp)
{
	int		ntries;
	processorid_t	cpuid;
	void		drmach_cpu_shutdown_self(void);

	DRMACH_PR("drmach_cpu_poweroff: stopping cpuid %d\n", cp->cpu_id);

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * XXX CHEETAH SUPPORT
	 * for cheetah, we need to grab the iocage lock since iocage
	 * memory is used for e$ flush.
	 */
	if (drmach_is_cheetah) {
		mutex_enter(&drmach_iocage_lock);
		while (drmach_iocage_is_busy)
			cv_wait(&drmach_iocage_cv, &drmach_iocage_lock);
		drmach_iocage_is_busy = 1;
		drmach_iocage_mem_scrub(ecache_size * 2);
		mutex_exit(&drmach_iocage_lock);
	}

	cpuid = cp->cpu_id;

	/*
	 * Set affinity to ensure consistent reading and writing of
	 * drmach_xt_mb[cpuid] by one "master" CPU directing
	 * the shutdown of the target CPU.
	 */
	affinity_set(CPU->cpu_id);

	/*
	 * Capture all CPUs (except for detaching proc) to prevent
	 * crosscalls to the detaching proc until it has cleared its
	 * bit in cpu_ready_set.
	 *
	 * The CPUs remain paused and the prom_mutex is known to be free.
	 * This prevents blocking when doing prom IEEE-1275 calls at a
	 * high PIL level.
	 */
	promsafe_pause_cpus();

	/*
	 * Quiesce interrupts on the target CPU. We do this by setting
	 * the CPU 'not ready'- (i.e. removing the CPU from cpu_ready_set) to
	 * prevent it from receiving cross calls and cross traps.
	 * This prevents the processor from receiving any new soft interrupts.
	 */
	mp_cpu_quiesce(cp);

	(void) prom_hotremovecpu(cpuid);

	start_cpus();

	/* setup xt_mb, will be cleared by drmach_shutdown_asm when ready */
	drmach_xt_mb[cpuid] = 0x80;

	xt_one_unchecked(cp->cpu_id, (xcfunc_t *)idle_stop_xcall,
	    (uint64_t)drmach_cpu_shutdown_self, NULL);

	ntries = drmach_cpu_ntries;
	while (drmach_xt_mb[cpuid] && ntries) {
		DELAY(drmach_cpu_delay);
		ntries--;
	}

	drmach_xt_mb[cpuid] = 0;	/* steal the cache line back */

	membar_sync();			/* make sure copy-back retires */

	affinity_clear();

	/*
	 * XXX CHEETAH SUPPORT
	 */
	if (drmach_is_cheetah) {
		mutex_enter(&drmach_iocage_lock);
		drmach_iocage_mem_scrub(ecache_size * 2);
		drmach_iocage_is_busy = 0;
		cv_signal(&drmach_iocage_cv);
		mutex_exit(&drmach_iocage_lock);
	}

	DRMACH_PR("waited %d out of %d tries for "
	    "drmach_cpu_shutdown_self on cpu%d",
	    drmach_cpu_ntries - ntries, drmach_cpu_ntries, cp->cpu_id);

	/*
	 * Do this here instead of drmach_cpu_shutdown_self() to
	 * avoid an assertion failure panic in turnstile.c.
	 */
	CPU_SIGNATURE(OS_SIG, SIGST_DETACHED, SIGSUBST_NULL, cpuid);

	return (0);
}

void
drmach_iocage_mem_scrub(uint64_t nbytes)
{
	extern uint32_t drmach_bc_bzero(void*, size_t);
	uint32_t	rv;

	ASSERT(MUTEX_HELD(&cpu_lock));

	affinity_set(CPU->cpu_id);

	rv = drmach_bc_bzero(drmach_iocage_vaddr, nbytes);
	if (rv != 0) {
		DRMACH_PR(
		"iocage scrub failed, drmach_bc_bzero returned %d\n", rv);
		rv = drmach_bc_bzero(drmach_iocage_vaddr, drmach_iocage_size);
		if (rv != 0)
			cmn_err(CE_PANIC,
			    "iocage scrub failed, drmach_bc_bzero rv=%d\n",
			    rv);
	}

	cpu_flush_ecache();

	affinity_clear();
}

#define	ALIGN(x, a)	((a) == 0 ? (uintptr_t)(x) : \
	(((uintptr_t)(x) + (uintptr_t)(a) - 1l) & ~((uintptr_t)(a) - 1l)))

static sbd_error_t *
drmach_iocage_mem_get(dr_testboard_req_t *tbrq)
{
	pfn_t		basepfn;
	pgcnt_t		npages;
	extern int	memscrub_delete_span(pfn_t, pgcnt_t);
	uint64_t	drmach_iocage_paddr_mbytes;

	ASSERT(drmach_iocage_paddr != -1);

	basepfn = (pfn_t)(drmach_iocage_paddr >> PAGESHIFT);
	npages = (pgcnt_t)(drmach_iocage_size >> PAGESHIFT);

	(void) memscrub_delete_span(basepfn, npages);

	mutex_enter(&cpu_lock);
	drmach_iocage_mem_scrub(drmach_iocage_size);
	mutex_exit(&cpu_lock);

	/*
	 * HPOST wants the address of the cage to be 64 megabyte-aligned
	 * and in megabyte units.
	 * The size of the cage is also in megabyte units.
	 */
	ASSERT(drmach_iocage_paddr == ALIGN(drmach_iocage_paddr, 0x4000000));

	drmach_iocage_paddr_mbytes = drmach_iocage_paddr / 0x100000;

	tbrq->memaddrhi = (uint32_t)(drmach_iocage_paddr_mbytes >> 32);
	tbrq->memaddrlo = (uint32_t)drmach_iocage_paddr_mbytes;
	tbrq->memlen = drmach_iocage_size / 0x100000;

	DRMACH_PR("drmach_iocage_mem_get: hi: 0x%x", tbrq->memaddrhi);
	DRMACH_PR("drmach_iocage_mem_get: lo: 0x%x", tbrq->memaddrlo);
	DRMACH_PR("drmach_iocage_mem_get: size: 0x%x", tbrq->memlen);

	return (NULL);
}

static sbd_error_t *
drmach_iocage_mem_return(dr_testboard_reply_t *tbr)
{
	_NOTE(ARGUNUSED(tbr))

	pfn_t		basepfn;
	pgcnt_t		npages;
	extern int	memscrub_add_span(pfn_t, pgcnt_t);

	ASSERT(drmach_iocage_paddr != -1);

	basepfn = (pfn_t)(drmach_iocage_paddr >> PAGESHIFT);
	npages = (pgcnt_t)(drmach_iocage_size >> PAGESHIFT);

	(void) memscrub_add_span(basepfn, npages);

	mutex_enter(&cpu_lock);
	mutex_enter(&drmach_iocage_lock);
	drmach_iocage_mem_scrub(drmach_iocage_size);
	drmach_iocage_is_busy = 0;
	cv_signal(&drmach_iocage_cv);
	mutex_exit(&drmach_iocage_lock);
	mutex_exit(&cpu_lock);

	return (NULL);
}

static int
drmach_cpu_intr_disable(cpu_t *cp)
{
	if (cpu_intr_disable(cp) != 0)
		return (-1);
	return (0);
}

static int
drmach_iocage_cpu_acquire(drmach_device_t *dp, cpu_flag_t *oflags)
{
	struct cpu	*cp;
	processorid_t	cpuid;
	static char	*fn = "drmach_iocage_cpu_acquire";
	sbd_error_t 	*err;
	int 		impl;

	ASSERT(DRMACH_IS_CPU_ID(dp));
	ASSERT(MUTEX_HELD(&cpu_lock));

	cpuid = ((drmach_cpu_t *)dp)->cpuid;

	DRMACH_PR("%s: attempting to acquire CPU id %d", fn, cpuid);

	if (dp->busy)
		return (-1);

	if ((cp = cpu_get(cpuid)) == NULL) {
		DRMACH_PR("%s: cpu_get(%d) returned NULL", fn, cpuid);
		return (-1);
	}

	if (!CPU_ACTIVE(cp)) {
		DRMACH_PR("%s: skipping offlined CPU id %d", fn, cpuid);
		return (-1);
	}

	/*
	 * There is a known HW bug where a Jaguar CPU in Safari port 0 (SBX/P0)
	 * can fail to receive an XIR. To workaround this issue until a hardware
	 * fix is implemented, we will exclude the selection of these CPUs.
	 *
	 * Once a fix is implemented in hardware, this code should be updated
	 * to allow Jaguar CPUs that have the fix to be used. However, support
	 * must be retained to skip revisions that do not have this fix.
	 */

	err = drmach_cpu_get_impl(dp, &impl);
	if (err) {
		DRMACH_PR("%s: error getting impl. of CPU id %d", fn, cpuid);
		sbd_err_clear(&err);
		return (-1);
	}

	if (IS_JAGUAR(impl) && (STARCAT_CPUID_TO_LPORT(cpuid) == 0) &&
	    drmach_iocage_exclude_jaguar_port_zero) {
		DRMACH_PR("%s: excluding CPU id %d: port 0 on jaguar",
		    fn, cpuid);
		return (-1);
	}

	ASSERT(oflags);
	*oflags = cp->cpu_flags;

	if (cpu_offline(cp, 0)) {
		DRMACH_PR("%s: cpu_offline failed for CPU id %d", fn, cpuid);
		return (-1);
	}

	if (cpu_poweroff(cp)) {
		DRMACH_PR("%s: cpu_poweroff failed for CPU id %d", fn, cpuid);
		if (cpu_online(cp)) {
			cmn_err(CE_WARN, "failed to online CPU id %d "
			    "during I/O cage test selection", cpuid);
		}
		if (CPU_ACTIVE(cp) && cpu_flagged_nointr(*oflags) &&
		    drmach_cpu_intr_disable(cp) != 0) {
			cmn_err(CE_WARN, "failed to restore CPU id %d "
			    "no-intr during I/O cage test selection", cpuid);
		}
		return (-1);
	}

	if (cpu_unconfigure(cpuid)) {
		DRMACH_PR("%s: cpu_unconfigure failed for CPU id %d", fn,
		    cpuid);
		(void) cpu_configure(cpuid);
		if ((cp = cpu_get(cpuid)) == NULL) {
			cmn_err(CE_WARN, "failed to reconfigure CPU id %d "
			    "during I/O cage test selection", cpuid);
			dp->busy = 1;
			return (-1);
		}
		if (cpu_poweron(cp) || cpu_online(cp)) {
			cmn_err(CE_WARN, "failed to %s CPU id %d "
			    "during I/O cage test selection",
			    cpu_is_poweredoff(cp) ?
			    "poweron" : "online", cpuid);
		}
		if (CPU_ACTIVE(cp) && cpu_flagged_nointr(*oflags) &&
		    drmach_cpu_intr_disable(cp) != 0) {
			cmn_err(CE_WARN, "failed to restore CPU id %d "
			    "no-intr during I/O cage test selection", cpuid);
		}
		return (-1);
	}

	dp->busy = 1;

	DRMACH_PR("%s: acquired CPU id %d", fn, cpuid);

	return (0);
}

/*
 * Attempt to acquire all the CPU devices passed in. It is
 * assumed that all the devices in the list are the cores of
 * a single CMP device. Non CMP devices can be handled as a
 * single core CMP by passing in a one element list.
 *
 * Success is only returned if *all* the devices in the list
 * can be acquired. In the failure case, none of the devices
 * in the list will be held as acquired.
 */
static int
drmach_iocage_cmp_acquire(drmach_device_t **dpp, cpu_flag_t *oflags)
{
	int	curr;
	int	i;
	int	rv = 0;

	ASSERT((dpp != NULL) && (*dpp != NULL));

	/*
	 * Walk the list of CPU devices (cores of a CMP)
	 * and attempt to acquire them. Bail out if an
	 * error is encountered.
	 */
	for (curr = 0; curr < MAX_CORES_PER_CMP; curr++) {

		/* check for the end of the list */
		if (dpp[curr] == NULL) {
			break;
		}

		ASSERT(DRMACH_IS_CPU_ID(dpp[curr]));
		ASSERT(dpp[curr]->portid == (*dpp)->portid);

		rv = drmach_iocage_cpu_acquire(dpp[curr], &oflags[curr]);
		if (rv != 0) {
			break;
		}
	}

	/*
	 * Check for an error.
	 */
	if (rv != 0) {
		/*
		 * Make a best effort attempt to return any cores
		 * that were already acquired before the error was
		 * encountered.
		 */
		for (i = 0; i < curr; i++) {
			(void) drmach_iocage_cpu_return(dpp[i], oflags[i]);
		}
	}

	return (rv);
}

static int
drmach_iocage_cpu_return(drmach_device_t *dp, cpu_flag_t oflags)
{
	processorid_t	cpuid;
	struct cpu	*cp;
	int		rv = 0;
	static char	*fn = "drmach_iocage_cpu_return";

	ASSERT(DRMACH_IS_CPU_ID(dp));
	ASSERT(MUTEX_HELD(&cpu_lock));

	cpuid = ((drmach_cpu_t *)dp)->cpuid;

	DRMACH_PR("%s: attempting to return CPU id: %d", fn, cpuid);

	if (cpu_configure(cpuid)) {
		cmn_err(CE_WARN, "failed to reconfigure CPU id %d "
		    "after I/O cage test", cpuid);
		/*
		 * The component was never set to unconfigured during the IO
		 * cage test, so we need to leave marked as busy to prevent
		 * further DR operations involving this component.
		 */
		return (-1);
	}

	if ((cp = cpu_get(cpuid)) == NULL) {
		cmn_err(CE_WARN, "cpu_get failed on CPU id %d after "
		    "I/O cage test", cpuid);
		dp->busy = 0;
		return (-1);
	}

	if (cpu_poweron(cp) || cpu_online(cp)) {
		cmn_err(CE_WARN, "failed to %s CPU id %d after I/O "
		    "cage test", cpu_is_poweredoff(cp) ?
		    "poweron" : "online", cpuid);
		rv = -1;
	}

	/*
	 * drmach_iocage_cpu_acquire will accept cpus in state P_ONLINE or
	 * P_NOINTR. Need to return to previous user-visible state.
	 */
	if (CPU_ACTIVE(cp) && cpu_flagged_nointr(oflags) &&
	    drmach_cpu_intr_disable(cp) != 0) {
		cmn_err(CE_WARN, "failed to restore CPU id %d "
		    "no-intr after I/O cage test", cpuid);
		rv = -1;
	}

	dp->busy = 0;

	DRMACH_PR("%s: returned CPU id: %d", fn, cpuid);

	return (rv);
}

static sbd_error_t *
drmach_iocage_cpu_get(dr_testboard_req_t *tbrq, drmach_device_t **dpp,
    cpu_flag_t *oflags)
{
	drmach_board_t	*bp;
	int		b_rv;
	int		b_idx;
	drmachid_t	b_id;
	int		found;

	mutex_enter(&cpu_lock);

	ASSERT(drmach_boards != NULL);

	found = 0;

	/*
	 * Walk the board list.
	 */
	b_rv = drmach_array_first(drmach_boards, &b_idx, &b_id);

	while (b_rv == 0) {

		int		d_rv;
		int		d_idx;
		drmachid_t	d_id;

		bp = b_id;

		if (bp->connected == 0 || bp->devices == NULL) {
			b_rv = drmach_array_next(drmach_boards, &b_idx, &b_id);
			continue;
		}

		/* An AXQ restriction disqualifies MCPU's as candidates. */
		if (DRMACH_BNUM2SLOT(bp->bnum) == 1) {
			b_rv = drmach_array_next(drmach_boards, &b_idx, &b_id);
			continue;
		}

		/*
		 * Walk the device list of this board.
		 */
		d_rv = drmach_array_first(bp->devices, &d_idx, &d_id);

		while (d_rv == 0) {

			drmach_device_t	*ndp;

			/* only interested in CPU devices */
			if (!DRMACH_IS_CPU_ID(d_id)) {
				d_rv = drmach_array_next(bp->devices, &d_idx,
				    &d_id);
				continue;
			}

			/*
			 * The following code assumes two properties
			 * of a CMP device:
			 *
			 *   1. All cores of a CMP are grouped together
			 *	in the device list.
			 *
			 *   2. There will only be a maximum of two cores
			 *	present in the CMP.
			 *
			 * If either of these two properties change,
			 * this code will have to be revisited.
			 */

			dpp[0] = d_id;
			dpp[1] = NULL;

			/*
			 * Get the next device. It may or may not be used.
			 */
			d_rv = drmach_array_next(bp->devices, &d_idx, &d_id);
			ndp = d_id;

			if ((d_rv == 0) && DRMACH_IS_CPU_ID(d_id)) {
				/*
				 * The second device is only interesting for
				 * this pass if it has the same portid as the
				 * first device. This implies that both are
				 * cores of the same CMP.
				 */
				if (dpp[0]->portid == ndp->portid) {
					dpp[1] = d_id;
				}
			}

			/*
			 * Attempt to acquire all cores of the CMP.
			 */
			if (drmach_iocage_cmp_acquire(dpp, oflags) == 0) {
				found = 1;
				break;
			}

			/*
			 * Check if the search for the second core was
			 * successful. If not, the next iteration should
			 * use that device.
			 */
			if (dpp[1] == NULL) {
				continue;
			}

			d_rv = drmach_array_next(bp->devices, &d_idx, &d_id);
		}

		if (found)
			break;

		b_rv = drmach_array_next(drmach_boards, &b_idx, &b_id);
	}

	mutex_exit(&cpu_lock);

	if (!found) {
		return (drerr_new(1, ESTC_IOCAGE_NO_CPU_AVAIL, NULL));
	}

	tbrq->cpu_portid = (*dpp)->portid;

	return (NULL);
}

/*
 * Setup an iocage by acquiring a cpu and memory.
 */
static sbd_error_t *
drmach_iocage_setup(dr_testboard_req_t *tbrq, drmach_device_t **dpp,
    cpu_flag_t *oflags)
{
	sbd_error_t *err;

	err = drmach_iocage_cpu_get(tbrq, dpp, oflags);
	if (!err) {
		mutex_enter(&drmach_iocage_lock);
		while (drmach_iocage_is_busy)
			cv_wait(&drmach_iocage_cv, &drmach_iocage_lock);
		drmach_iocage_is_busy = 1;
		mutex_exit(&drmach_iocage_lock);
		err = drmach_iocage_mem_get(tbrq);
		if (err) {
			mutex_enter(&drmach_iocage_lock);
			drmach_iocage_is_busy = 0;
			cv_signal(&drmach_iocage_cv);
			mutex_exit(&drmach_iocage_lock);
		}
	}
	return (err);
}

#define	DRMACH_SCHIZO_PCI_LEAF_MAX	2
#define	DRMACH_SCHIZO_PCI_SLOT_MAX	8
#define	DRMACH_S1P_SAMPLE_MAX		2

typedef enum {
	DRMACH_POST_SUSPEND = 0,
	DRMACH_PRE_RESUME
} drmach_sr_iter_t;

typedef struct {
	dev_info_t	*dip;
	uint32_t	portid;
	uint32_t	pcr_sel_save;
	uint32_t	pic_l2_io_q[DRMACH_S1P_SAMPLE_MAX];
	uint64_t	reg_basepa;
} drmach_s1p_axq_t;

typedef struct {
	dev_info_t		*dip;
	uint32_t		portid;
	uint64_t		csr_basepa;
	struct {
		uint64_t 	slot_intr_state_diag;
		uint64_t 	obio_intr_state_diag;
		uint_t		nmap_regs;
		uint64_t	*intr_map_regs;
	} regs[DRMACH_S1P_SAMPLE_MAX];
} drmach_s1p_pci_t;

typedef struct {
	uint64_t		csr_basepa;
	struct {
		uint64_t	csr;
		uint64_t	errctrl;
		uint64_t	errlog;
	} regs[DRMACH_S1P_SAMPLE_MAX];
	drmach_s1p_pci_t	pci[DRMACH_SCHIZO_PCI_LEAF_MAX];
} drmach_s1p_schizo_t;

typedef struct {
	drmach_s1p_axq_t	axq;
	drmach_s1p_schizo_t	schizo[STARCAT_SLOT1_IO_MAX];
} drmach_slot1_pause_t;

/*
 * Table of saved state for paused slot1 devices.
 */
static drmach_slot1_pause_t *drmach_slot1_paused[STARCAT_BDSET_MAX];
static int drmach_slot1_pause_init = 1;

#ifdef DEBUG
int drmach_slot1_pause_debug = 1;
#else
int drmach_slot1_pause_debug = 0;
#endif /* DEBUG */

static int
drmach_is_slot1_pause_axq(dev_info_t *dip, char *name, int *id, uint64_t *reg)
{
	int		portid, exp, slot, i;
	drmach_reg_t	regs[2];
	int		reglen = sizeof (regs);

	if ((portid = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "portid", -1)) == -1) {
		return (0);
	}

	exp = (portid >> 5) & 0x1f;
	slot = portid & 0x1;

	if (slot == 0 || strncmp(name, DRMACH_AXQ_NAMEPROP,
	    strlen(DRMACH_AXQ_NAMEPROP))) {
		return (0);
	}

	mutex_enter(&cpu_lock);
	for (i = 0; i < STARCAT_SLOT1_CPU_MAX; i++) {
		if (cpu[MAKE_CPUID(exp, slot, i)]) {
			/* maxcat cpu present */
			mutex_exit(&cpu_lock);
			return (0);
		}
	}
	mutex_exit(&cpu_lock);

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)regs, &reglen) != DDI_PROP_SUCCESS) {
		DRMACH_PR("drmach_is_slot1_pause_axq: no reg prop for "
		    "axq dip=%p\n", (void *)dip);
		return (0);
	}

	ASSERT(id && reg);
	*reg = (uint64_t)regs[0].reg_addr_hi << 32;
	*reg |= (uint64_t)regs[0].reg_addr_lo;
	*id = portid;

	return (1);
}

/*
 * Allocate an entry in the slot1_paused state table.
 */
static void
drmach_slot1_pause_add_axq(dev_info_t *axq_dip, char *axq_name, int axq_portid,
    uint64_t reg, drmach_slot1_pause_t **slot1_paused)
{
	int	axq_exp;
	drmach_slot1_pause_t *slot1;

	axq_exp = (axq_portid >> 5) & 0x1f;

	ASSERT(axq_portid & 0x1);
	ASSERT(slot1_paused[axq_exp] == NULL);
	ASSERT(strncmp(axq_name, DRMACH_AXQ_NAMEPROP,
	    strlen(DRMACH_AXQ_NAMEPROP)) == 0);

	slot1 = kmem_zalloc(sizeof (*slot1), KM_SLEEP);

	/*
	 * XXX This dip should really be held (via ndi_hold_devi())
	 * before saving it in the axq pause structure. However that
	 * would prevent DR as the pause data structures persist until
	 * the next suspend. drmach code should be modified to free the
	 * the slot 1 pause data structures for a boardset when its
	 * slot 1 board is DRed out. The dip can then be released via
	 * ndi_rele_devi() when the pause data structure is freed
	 * allowing DR to proceed. Until this change is made, drmach
	 * code should be careful about dereferencing the saved dip
	 * as it may no longer exist.
	 */
	slot1->axq.dip = axq_dip;
	slot1->axq.portid = axq_portid;
	slot1->axq.reg_basepa = reg;
	slot1_paused[axq_exp] = slot1;
}

static void
drmach_s1p_pci_free(drmach_s1p_pci_t *pci)
{
	int	i;

	for (i = 0; i < DRMACH_S1P_SAMPLE_MAX; i++) {
		if (pci->regs[i].intr_map_regs != NULL) {
			ASSERT(pci->regs[i].nmap_regs > 0);
			kmem_free(pci->regs[i].intr_map_regs,
			    pci->regs[i].nmap_regs * sizeof (uint64_t));
		}
	}
}

static void
drmach_slot1_pause_free(drmach_slot1_pause_t **slot1_paused)
{
	int	i, j, k;
	drmach_slot1_pause_t *slot1;

	for (i = 0; i < STARCAT_BDSET_MAX; i++) {
		if ((slot1 = slot1_paused[i]) == NULL)
			continue;

		for (j = 0; j < STARCAT_SLOT1_IO_MAX; j++)
			for (k = 0; k < DRMACH_SCHIZO_PCI_LEAF_MAX; k++)
				drmach_s1p_pci_free(&slot1->schizo[j].pci[k]);

		kmem_free(slot1, sizeof (*slot1));
		slot1_paused[i] = NULL;
	}
}

/*
 * Tree walk callback routine. If dip represents a Schizo PCI leaf,
 * fill in the appropriate info in the slot1_paused state table.
 */
static int
drmach_find_slot1_io(dev_info_t *dip, void *arg)
{
	int		portid, exp, ioc_unum, leaf_unum;
	char		buf[OBP_MAXDRVNAME];
	int		buflen = sizeof (buf);
	drmach_reg_t	regs[3];
	int		reglen = sizeof (regs);
	uint32_t	leaf_offset;
	uint64_t	schizo_csr_pa, pci_csr_pa;
	drmach_s1p_pci_t *pci;
	drmach_slot1_pause_t **slot1_paused = (drmach_slot1_pause_t **)arg;

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "name", (caddr_t)buf, &buflen) != DDI_PROP_SUCCESS ||
	    strncmp(buf, DRMACH_PCI_NAMEPROP, strlen(DRMACH_PCI_NAMEPROP))) {
		return (DDI_WALK_CONTINUE);
	}

	if ((portid = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "portid", -1)) == -1) {
		return (DDI_WALK_CONTINUE);
	}

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)regs, &reglen) != DDI_PROP_SUCCESS) {
		DRMACH_PR("drmach_find_slot1_io: no reg prop for pci "
		    "dip=%p\n", (void *)dip);
		return (DDI_WALK_CONTINUE);
	}

	exp = portid >> 5;
	ioc_unum = portid & 0x1;
	leaf_offset = regs[0].reg_addr_lo & 0x7fffff;
	pci_csr_pa = (uint64_t)regs[0].reg_addr_hi << 32;
	pci_csr_pa |= (uint64_t)regs[0].reg_addr_lo;
	schizo_csr_pa = (uint64_t)regs[1].reg_addr_hi << 32;
	schizo_csr_pa |= (uint64_t)regs[1].reg_addr_lo;

	ASSERT(exp >= 0 && exp < STARCAT_BDSET_MAX);
	ASSERT(slot1_paused[exp] != NULL);
	ASSERT(leaf_offset == 0x600000 || leaf_offset == 0x700000);
	ASSERT(slot1_paused[exp]->schizo[ioc_unum].csr_basepa == 0x0UL ||
	    slot1_paused[exp]->schizo[ioc_unum].csr_basepa == schizo_csr_pa);

	leaf_unum = (leaf_offset == 0x600000) ? 0 : 1;
	slot1_paused[exp]->schizo[ioc_unum].csr_basepa = schizo_csr_pa;
	pci = &slot1_paused[exp]->schizo[ioc_unum].pci[leaf_unum];

	/*
	 * XXX This dip should really be held (via ndi_hold_devi())
	 * before saving it in the pci pause structure. However that
	 * would prevent DR as the pause data structures persist until
	 * the next suspend. drmach code should be modified to free the
	 * the slot 1 pause data structures for a boardset when its
	 * slot 1 board is DRed out. The dip can then be released via
	 * ndi_rele_devi() when the pause data structure is freed
	 * allowing DR to proceed. Until this change is made, drmach
	 * code should be careful about dereferencing the saved dip as
	 * it may no longer exist.
	 */
	pci->dip = dip;
	pci->portid = portid;
	pci->csr_basepa = pci_csr_pa;

	DRMACH_PR("drmach_find_slot1_io: name=%s, portid=0x%x, dip=%p\n",
	    buf, portid, (void *)dip);

	return (DDI_WALK_PRUNECHILD);
}

static void
drmach_slot1_pause_add_io(drmach_slot1_pause_t **slot1_paused)
{
	/*
	 * Root node doesn't have to be held
	 */
	ddi_walk_devs(ddi_root_node(), drmach_find_slot1_io,
	    (void *)slot1_paused);
}

/*
 * Save the interrupt mapping registers for each non-idle interrupt
 * represented by the bit pairs in the saved interrupt state
 * diagnostic registers for this PCI leaf.
 */
static void
drmach_s1p_intr_map_reg_save(drmach_s1p_pci_t *pci, drmach_sr_iter_t iter)
{
	int	 i, cnt, ino;
	uint64_t reg;
	char	 *dname;
	uchar_t	 Xmits;

	dname = ddi_binding_name(pci->dip);
	Xmits = (strcmp(dname, XMITS_BINDING_NAME) == 0)  ?  1 : 0;

	/*
	 * 1st pass allocates, 2nd pass populates.
	 */
	for (i = 0; i < 2; i++) {
		cnt = ino = 0;

		/*
		 * PCI slot interrupts
		 */
		reg = pci->regs[iter].slot_intr_state_diag;
		while (reg) {
			/*
			 * Xmits Interrupt Number Offset(ino) Assignments
			 *   00-17 PCI Slot Interrupts
			 *   18-1f Not Used
			 */
			if ((Xmits) && (ino > 0x17))
				break;
			if ((reg & COMMON_CLEAR_INTR_REG_MASK) !=
			    COMMON_CLEAR_INTR_REG_IDLE) {
				if (i) {
					pci->regs[iter].intr_map_regs[cnt] =
					    lddphysio(pci->csr_basepa +
					    SCHIZO_IB_INTR_MAP_REG_OFFSET +
					    ino * sizeof (reg));
				}
				++cnt;
			}
			++ino;
			reg >>= 2;
		}

		/*
		 * Xmits Interrupt Number Offset(ino) Assignments
		 *   20-2f Not Used
		 *   30-37 Internal interrupts
		 *   38-3e Not Used
		 */
		ino = (Xmits)  ?  0x30 : 0x20;

		/*
		 * OBIO and internal schizo interrupts
		 * Each PCI leaf has a set of mapping registers for all
		 * possible interrupt sources except the NewLink interrupts.
		 */
		reg = pci->regs[iter].obio_intr_state_diag;
		while (reg && ino <= 0x38) {
			if ((reg & COMMON_CLEAR_INTR_REG_MASK) !=
			    COMMON_CLEAR_INTR_REG_IDLE) {
				if (i) {
					pci->regs[iter].intr_map_regs[cnt] =
					    lddphysio(pci->csr_basepa +
					    SCHIZO_IB_INTR_MAP_REG_OFFSET +
					    ino * sizeof (reg));
				}
				++cnt;
			}
			++ino;
			reg >>= 2;
		}

		if (!i) {
			pci->regs[iter].nmap_regs = cnt;
			pci->regs[iter].intr_map_regs =
			    kmem_zalloc(cnt * sizeof (reg), KM_SLEEP);
		}
	}
}

static void
drmach_s1p_axq_update(drmach_s1p_axq_t *axq, drmach_sr_iter_t iter)
{
	uint32_t	reg;

	if (axq->reg_basepa == 0x0UL)
		return;

	if (iter == DRMACH_POST_SUSPEND) {
		axq->pcr_sel_save = ldphysio(axq->reg_basepa +
		    AXQ_SLOT1_PERFCNT_SEL);
		/*
		 * Select l2_io_queue counter by writing L2_IO_Q mux
		 * input to bits 0-6 of perf cntr select reg.
		 */
		reg = axq->pcr_sel_save;
		reg &= ~AXQ_PIC_CLEAR_MASK;
		reg |= L2_IO_Q;

		stphysio(axq->reg_basepa + AXQ_SLOT1_PERFCNT_SEL, reg);
	}

	axq->pic_l2_io_q[iter] = ldphysio(axq->reg_basepa + AXQ_SLOT1_PERFCNT0);

	if (iter == DRMACH_PRE_RESUME) {
		stphysio(axq->reg_basepa + AXQ_SLOT1_PERFCNT_SEL,
		    axq->pcr_sel_save);
	}

	DRMACH_PR("drmach_s1p_axq_update: axq #%d pic_l2_io_q[%d]=%d\n",
	    ddi_get_instance(axq->dip), iter, axq->pic_l2_io_q[iter]);
}

static void
drmach_s1p_schizo_update(drmach_s1p_schizo_t *schizo, drmach_sr_iter_t iter)
{
	int	i;
	drmach_s1p_pci_t *pci;

	if (schizo->csr_basepa == 0x0UL)
		return;

	schizo->regs[iter].csr =
	    lddphysio(schizo->csr_basepa + SCHIZO_CB_CSR_OFFSET);
	schizo->regs[iter].errctrl =
	    lddphysio(schizo->csr_basepa + SCHIZO_CB_ERRCTRL_OFFSET);
	schizo->regs[iter].errlog =
	    lddphysio(schizo->csr_basepa + SCHIZO_CB_ERRLOG_OFFSET);

	for (i = 0; i < DRMACH_SCHIZO_PCI_LEAF_MAX; i++) {
		pci = &schizo->pci[i];
		if (pci->dip != NULL && pci->csr_basepa != 0x0UL) {
			pci->regs[iter].slot_intr_state_diag =
			    lddphysio(pci->csr_basepa +
			    COMMON_IB_SLOT_INTR_STATE_DIAG_REG);

			pci->regs[iter].obio_intr_state_diag =
			    lddphysio(pci->csr_basepa +
			    COMMON_IB_OBIO_INTR_STATE_DIAG_REG);

			drmach_s1p_intr_map_reg_save(pci, iter);
		}
	}
}

/*
 * Called post-suspend and pre-resume to snapshot the suspend state
 * of slot1 AXQs and Schizos.
 */
static void
drmach_slot1_pause_update(drmach_slot1_pause_t **slot1_paused,
    drmach_sr_iter_t iter)
{
	int	i, j;
	drmach_slot1_pause_t *slot1;

	for (i = 0; i < STARCAT_BDSET_MAX; i++) {
		if ((slot1 = slot1_paused[i]) == NULL)
			continue;

		drmach_s1p_axq_update(&slot1->axq, iter);
		for (j = 0; j < STARCAT_SLOT1_IO_MAX; j++)
			drmach_s1p_schizo_update(&slot1->schizo[j], iter);
	}
}

/*
 * Starcat hPCI Schizo devices.
 *
 * The name field is overloaded. NULL means the slot (interrupt concentrator
 * bus) is not used. intr_mask is a bit mask representing the 4 possible
 * interrupts per slot, on if valid (rio does not use interrupt lines 0, 1).
 */
static struct {
	char	*name;
	uint8_t	intr_mask;
} drmach_schz_slot_intr[][DRMACH_SCHIZO_PCI_LEAF_MAX] = {
	/* Schizo 0 */		/* Schizo 1 */
	{{"C3V0", 0xf},		{"C3V1", 0xf}},		/* slot 0 */
	{{"C5V0", 0xf},		{"C5V1", 0xf}},		/* slot 1 */
	{{"rio", 0xc},		{NULL, 0x0}},		/* slot 2 */
	{{NULL, 0x0},		{NULL, 0x0}},		/* slot 3 */
	{{"sbbc", 0xf},		{NULL, 0x0}},		/* slot 4 */
	{{NULL, 0x0},		{NULL, 0x0}},		/* slot 5 */
	{{NULL, 0x0},		{NULL, 0x0}},		/* slot 6 */
	{{NULL, 0x0},		{NULL, 0x0}}		/* slot 7 */
};

/*
 * See Schizo Specification, Revision 51 (May 23, 2001), Section 22.4.4
 * "Interrupt Registers", Table 22-69, page 306.
 */
static char *
drmach_schz_internal_ino2str(int ino)
{
	int	intr;

	ASSERT(ino >= 0x30 && ino <= 0x37);

	intr = ino & 0x7;
	switch (intr) {
		case (0x0):	return ("Uncorrectable ECC error");
		case (0x1):	return ("Correctable ECC error");
		case (0x2):	return ("PCI Bus A Error");
		case (0x3):	return ("PCI Bus B Error");
		case (0x4):	return ("Safari Bus Error");
		default:	return ("Reserved");
	}
}

#define	DRMACH_INTR_MASK_SHIFT(ino)	((ino) << 1)

static void
drmach_s1p_decode_slot_intr(int exp, int unum, drmach_s1p_pci_t *pci,
    int ino, drmach_sr_iter_t iter)
{
	uint8_t		intr_mask;
	char		*slot_devname;
	char		namebuf[OBP_MAXDRVNAME];
	int		slot, intr_line, slot_valid, intr_valid;

	ASSERT(ino >= 0 && ino <= 0x1f);
	ASSERT((pci->regs[iter].slot_intr_state_diag &
	    (COMMON_CLEAR_INTR_REG_MASK << DRMACH_INTR_MASK_SHIFT(ino))) !=
	    COMMON_CLEAR_INTR_REG_IDLE);

	slot = (ino >> 2) & 0x7;
	intr_line = ino & 0x3;

	slot_devname = drmach_schz_slot_intr[slot][unum].name;
	slot_valid = (slot_devname == NULL) ? 0 : 1;
	if (!slot_valid) {
		(void) snprintf(namebuf, sizeof (namebuf), "slot %d (INVALID)",
		    slot);
		slot_devname = namebuf;
	}

	intr_mask = drmach_schz_slot_intr[slot][unum].intr_mask;
	intr_valid = (1 << intr_line) & intr_mask;

	prom_printf("IO%d/P%d PCI slot interrupt: ino=0x%x, source device=%s, "
	    "interrupt line=%d%s\n", exp, unum, ino, slot_devname, intr_line,
	    (slot_valid && !intr_valid) ? " (INVALID)" : "");
}

/*
 * Log interrupt source device info for all valid, pending interrupts
 * on each Schizo PCI leaf. Called if Schizo has logged a Safari bus
 * error in the error ctrl reg.
 */
static void
drmach_s1p_schizo_log_intr(drmach_s1p_schizo_t *schizo, int exp,
    int unum, drmach_sr_iter_t iter)
{
	uint64_t	reg;
	int		i, n, ino;
	drmach_s1p_pci_t *pci;

	ASSERT(exp >= 0 && exp < STARCAT_BDSET_MAX);
	ASSERT(unum < STARCAT_SLOT1_IO_MAX);

	/*
	 * Check the saved interrupt mapping registers. If interrupt is valid,
	 * map the ino to the Schizo source device and check that the pci
	 * slot and interrupt line are valid.
	 */
	for (i = 0; i < DRMACH_SCHIZO_PCI_LEAF_MAX; i++) {
		pci = &schizo->pci[i];
		for (n = 0; n < pci->regs[iter].nmap_regs; n++) {
			reg = pci->regs[iter].intr_map_regs[n];
			if (reg & COMMON_INTR_MAP_REG_VALID) {
				ino = reg & COMMON_INTR_MAP_REG_INO;

				if (ino <= 0x1f) {
					/*
					 * PCI slot interrupt
					 */
					drmach_s1p_decode_slot_intr(exp, unum,
					    pci, ino, iter);
				} else if (ino <= 0x2f) {
					/*
					 * OBIO interrupt
					 */
					prom_printf("IO%d/P%d OBIO interrupt: "
					    "ino=0x%x\n", exp, unum, ino);
				} else if (ino <= 0x37) {
					/*
					 * Internal interrupt
					 */
					prom_printf("IO%d/P%d Internal "
					    "interrupt: ino=0x%x (%s)\n",
					    exp, unum, ino,
					    drmach_schz_internal_ino2str(ino));
				} else {
					/*
					 * NewLink interrupt
					 */
					prom_printf("IO%d/P%d NewLink "
					    "interrupt: ino=0x%x\n", exp,
					    unum, ino);
				}

				DRMACH_PR("drmach_s1p_schizo_log_intr: "
				    "exp=%d, schizo=%d, pci_leaf=%c, "
				    "ino=0x%x, intr_map_reg=0x%lx\n",
				    exp, unum, (i == 0) ? 'A' : 'B', ino, reg);
			}
		}
	}
}

/*
 * See Schizo Specification, Revision 51 (May 23, 2001), Section 22.2.4
 * "Safari Error Control/Log Registers", Table 22-11, page 248.
 */
#define	DRMACH_SCHIZO_SAFARI_UNMAPPED_ERR	(0x1ull << 4)

/*
 * Check for possible error indicators prior to resuming the
 * AXQ driver, which will de-assert slot1 AXQ_DOMCTRL_PAUSE.
 */
static void
drmach_slot1_pause_verify(drmach_slot1_pause_t **slot1_paused,
    drmach_sr_iter_t iter)
{
	int	i, j;
	int 	errflag = 0;
	drmach_slot1_pause_t *slot1;

	/*
	 * Check for logged schizo bus error and pending interrupts.
	 */
	for (i = 0; i < STARCAT_BDSET_MAX; i++) {
		if ((slot1 = slot1_paused[i]) == NULL)
			continue;

		for (j = 0; j < STARCAT_SLOT1_IO_MAX; j++) {
			if (slot1->schizo[j].csr_basepa == 0x0UL)
				continue;

			if (slot1->schizo[j].regs[iter].errlog &
			    DRMACH_SCHIZO_SAFARI_UNMAPPED_ERR) {
				if (!errflag) {
					prom_printf("DR WARNING: interrupt "
					    "attempt detected during "
					    "copy-rename (%s):\n",
					    (iter == DRMACH_POST_SUSPEND) ?
					    "post suspend" : "pre resume");
					++errflag;
				}
				drmach_s1p_schizo_log_intr(&slot1->schizo[j],
				    i, j, iter);
			}
		}
	}

	/*
	 * Check for changes in axq l2_io_q performance counters (2nd pass only)
	 */
	if (iter == DRMACH_PRE_RESUME) {
		for (i = 0; i < STARCAT_BDSET_MAX; i++) {
			if ((slot1 = slot1_paused[i]) == NULL)
				continue;

			if (slot1->axq.pic_l2_io_q[DRMACH_POST_SUSPEND] !=
			    slot1->axq.pic_l2_io_q[DRMACH_PRE_RESUME]) {
				prom_printf("DR WARNING: IO transactions "
				    "detected on IO%d during copy-rename: "
				    "AXQ l2_io_q performance counter "
				    "start=%d, end=%d\n", i,
				    slot1->axq.pic_l2_io_q[DRMACH_POST_SUSPEND],
				    slot1->axq.pic_l2_io_q[DRMACH_PRE_RESUME]);
			}
		}
	}
}

struct drmach_sr_list {
	dev_info_t		*dip;
	struct drmach_sr_list	*next;
	struct drmach_sr_list	*prev;
};

static struct drmach_sr_ordered {
	char			*name;
	struct drmach_sr_list	*ring;
} drmach_sr_ordered[] = {
	{ "iosram",			NULL },
	{ "address-extender-queue",	NULL },
	{ NULL,				NULL }, /* terminator -- required */
};

static void
drmach_sr_insert(struct drmach_sr_list **lp, dev_info_t *dip)
{
	struct drmach_sr_list *np;

	DRMACH_PR("drmach_sr_insert: adding dip %p\n", (void *)dip);

	np = (struct drmach_sr_list *)kmem_alloc(
	    sizeof (struct drmach_sr_list), KM_SLEEP);

	ndi_hold_devi(dip);
	np->dip = dip;

	if (*lp == NULL) {
		/* establish list */
		*lp = np->next = np->prev = np;
	} else {
		/* place new node behind head node on ring list */
		np->prev = (*lp)->prev;
		np->next = *lp;
		np->prev->next = np;
		np->next->prev = np;
	}
}

static void
drmach_sr_delete(struct drmach_sr_list **lp, dev_info_t *dip)
{
	DRMACH_PR("drmach_sr_delete: searching for dip %p\n", (void *)dip);

	if (*lp) {
		struct drmach_sr_list *xp;

		/* start search with mostly likely node */
		xp = (*lp)->prev;
		do {
			if (xp->dip == dip) {
				xp->prev->next = xp->next;
				xp->next->prev = xp->prev;

				if (xp == *lp)
					*lp = xp->next;
				if (xp == *lp)
					*lp = NULL;
				xp->dip = NULL;
				ndi_rele_devi(dip);
				kmem_free(xp, sizeof (*xp));

				DRMACH_PR("drmach_sr_delete:"
				    " disposed sr node for dip %p",
				    (void *)dip);
				return;
			}

			DRMACH_PR("drmach_sr_delete: still searching\n");

			xp = xp->prev;
		} while (xp != (*lp)->prev);
	}

	/* every dip should be found during resume */
	DRMACH_PR("ERROR: drmach_sr_delete: can't find dip %p", (void *)dip);
}

int
drmach_verify_sr(dev_info_t *dip, int sflag)
{
	int	rv;
	int	len;
	char    name[OBP_MAXDRVNAME];

	if (drmach_slot1_pause_debug) {
		if (sflag && drmach_slot1_pause_init) {
			drmach_slot1_pause_free(drmach_slot1_paused);
			drmach_slot1_pause_init = 0;
		} else if (!sflag && !drmach_slot1_pause_init) {
			/* schedule init for next suspend */
			drmach_slot1_pause_init = 1;
		}
	}

	rv = ddi_getproplen(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "name", &len);
	if (rv == DDI_PROP_SUCCESS) {
		int		portid;
		uint64_t	reg;
		struct drmach_sr_ordered *op;

		rv = ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "name", (caddr_t)name, &len);

		if (rv != DDI_PROP_SUCCESS)
			return (0);

		if (drmach_slot1_pause_debug && sflag &&
		    drmach_is_slot1_pause_axq(dip, name, &portid, &reg)) {
			drmach_slot1_pause_add_axq(dip, name, portid, reg,
			    drmach_slot1_paused);
		}

		for (op = drmach_sr_ordered; op->name; op++) {
			if (strncmp(op->name, name, strlen(op->name)) == 0) {
				if (sflag)
					drmach_sr_insert(&op->ring, dip);
				else
					drmach_sr_delete(&op->ring, dip);
				return (1);
			}
		}
	}

	return (0);
}

static void
drmach_sr_dip(dev_info_t *dip, int suspend)
{
	int	 rv;
	major_t	 maj;
	char	*name, *name_addr, *aka;

	if ((name = ddi_get_name(dip)) == NULL)
		name = "<null name>";
	else if ((maj = ddi_name_to_major(name)) != -1)
		aka = ddi_major_to_name(maj);
	else
		aka = "<unknown>";

	if ((name_addr = ddi_get_name_addr(dip)) == NULL)
		name_addr = "<null>";

	prom_printf("\t%s %s@%s (aka %s)\n",
	    suspend ? "suspending" : "resuming",
	    name, name_addr, aka);

	if (suspend) {
		rv = devi_detach(dip, DDI_SUSPEND);
	} else {
		rv = devi_attach(dip, DDI_RESUME);
	}

	if (rv != DDI_SUCCESS) {
		prom_printf("\tFAILED to %s %s@%s\n",
		    suspend ? "suspend" : "resume",
		    name, name_addr);
	}
}

void
drmach_suspend_last()
{
	struct drmach_sr_ordered *op;

	if (drmach_slot1_pause_debug)
		drmach_slot1_pause_add_io(drmach_slot1_paused);

	/*
	 * The ordering array declares the strict sequence in which
	 * the named drivers are to suspended. Each element in
	 * the array may have a double-linked ring list of driver
	 * instances (dip) in the order in which they were presented
	 * to drmach_verify_sr. If present, walk the list in the
	 * forward direction to suspend each instance.
	 */
	for (op = drmach_sr_ordered; op->name; op++) {
		if (op->ring) {
			struct drmach_sr_list *rp;

			rp = op->ring;
			do {
				drmach_sr_dip(rp->dip, 1);
				rp = rp->next;
			} while (rp != op->ring);
		}
	}

	if (drmach_slot1_pause_debug) {
		drmach_slot1_pause_update(drmach_slot1_paused,
		    DRMACH_POST_SUSPEND);
		drmach_slot1_pause_verify(drmach_slot1_paused,
		    DRMACH_POST_SUSPEND);
	}
}

void
drmach_resume_first()
{
	struct drmach_sr_ordered *op = drmach_sr_ordered +
	    (sizeof (drmach_sr_ordered) / sizeof (drmach_sr_ordered[0]));

	if (drmach_slot1_pause_debug) {
		drmach_slot1_pause_update(drmach_slot1_paused,
		    DRMACH_PRE_RESUME);
		drmach_slot1_pause_verify(drmach_slot1_paused,
		    DRMACH_PRE_RESUME);
	}

	op -= 1;	/* point at terminating element */

	/*
	 * walk ordering array and rings backwards to resume dips
	 * in reverse order in which they were suspended
	 */
	while (--op >= drmach_sr_ordered) {
		if (op->ring) {
			struct drmach_sr_list *rp;

			rp = op->ring->prev;
			do {
				drmach_sr_dip(rp->dip, 0);
				rp = rp->prev;
			} while (rp != op->ring->prev);
		}
	}
}

/*
 * Log a DR sysevent.
 * Return value: 0 success, non-zero failure.
 */
int
drmach_log_sysevent(int board, char *hint, int flag, int verbose)
{
	sysevent_t			*ev;
	sysevent_id_t			eid;
	int				rv, km_flag;
	sysevent_value_t		evnt_val;
	sysevent_attr_list_t		*evnt_attr_list = NULL;
	char				attach_pnt[MAXNAMELEN];

	km_flag = (flag == SE_SLEEP) ? KM_SLEEP : KM_NOSLEEP;
	attach_pnt[0] = '\0';
	if (drmach_board_name(board, attach_pnt, MAXNAMELEN)) {
		rv = -1;
		goto logexit;
	}
	if (verbose)
		DRMACH_PR("drmach_log_sysevent: %s %s, flag: %d, verbose: %d\n",
		    attach_pnt, hint, flag, verbose);

	if ((ev = sysevent_alloc(EC_DR, ESC_DR_AP_STATE_CHANGE,
	    SUNW_KERN_PUB"dr", km_flag)) == NULL) {
		rv = -2;
		goto logexit;
	}
	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = attach_pnt;
	if ((rv = sysevent_add_attr(&evnt_attr_list, DR_AP_ID,
	    &evnt_val, km_flag)) != 0)
		goto logexit;

	evnt_val.value_type = SE_DATA_TYPE_STRING;
	evnt_val.value.sv_string = hint;
	if ((rv = sysevent_add_attr(&evnt_attr_list, DR_HINT,
	    &evnt_val, km_flag)) != 0) {
		sysevent_free_attr(evnt_attr_list);
		goto logexit;
	}

	(void) sysevent_attach_attributes(ev, evnt_attr_list);

	/*
	 * Log the event but do not sleep waiting for its
	 * delivery. This provides insulation from syseventd.
	 */
	rv = log_sysevent(ev, SE_NOSLEEP, &eid);

logexit:
	if (ev)
		sysevent_free(ev);
	if ((rv != 0) && verbose)
		cmn_err(CE_WARN,
		    "drmach_log_sysevent failed (rv %d) for %s  %s\n",
		    rv, attach_pnt, hint);

	return (rv);
}

/*
 * Initialize the mem_slice portion of a claim/unconfig/unclaim mailbox message.
 * Only the valid entries are modified, so the array should be zeroed out
 * initially.
 */
static void
drmach_msg_memslice_init(dr_memslice_t slice_arr[]) {
	int	i;
	char	c;

	ASSERT(mutex_owned(&drmach_slice_table_lock));

	for (i = 0; i < AXQ_MAX_EXP; i++) {
		c = drmach_slice_table[i];

		if (c & 0x20) {
			slice_arr[i].valid = 1;
			slice_arr[i].slice = c & 0x1f;
		}
	}
}

/*
 * Initialize the mem_regs portion of a claim/unconfig/unclaim mailbox message.
 * Only the valid entries are modified, so the array should be zeroed out
 * initially.
 */
static void
drmach_msg_memregs_init(dr_memregs_t regs_arr[]) {
	int		rv, exp, mcnum, bank;
	uint64_t	madr;
	drmachid_t	id;
	drmach_board_t	*bp;
	drmach_mem_t	*mp;
	dr_memregs_t	*memregs;

	/* CONSTCOND */
	ASSERT(DRMACH_MC_NBANKS == (PMBANKS_PER_PORT * LMBANKS_PER_PMBANK));

	for (exp = 0; exp < 18; exp++) {
		rv = drmach_array_get(drmach_boards,
		    DRMACH_EXPSLOT2BNUM(exp, 0), &id);
		ASSERT(rv == 0);	/* should never be out of bounds */
		if (id == NULL) {
			continue;
		}

		memregs = &regs_arr[exp];
		bp = (drmach_board_t *)id;
		for (mp = bp->mem; mp != NULL; mp = mp->next) {
			mcnum = mp->dev.portid & 0x3;
			for (bank = 0; bank < DRMACH_MC_NBANKS; bank++) {
				drmach_mem_read_madr(mp, bank, &madr);
				if (madr & DRMACH_MC_VALID_MASK) {
					DRMACH_PR("%d.%d.%d.madr = 0x%lx\n",
					    exp, mcnum, bank, madr);
					memregs->madr[mcnum][bank].hi =
					    DRMACH_U64_TO_MCREGHI(madr);
					memregs->madr[mcnum][bank].lo =
					    DRMACH_U64_TO_MCREGLO(madr);
				}
			}
		}
	}
}

/*
 * Do not allow physical address range modification if either board on this
 * expander has processors in NULL LPA mode (CBASE=CBND=NULL).
 *
 * A side effect of NULL proc LPA mode in Starcat SSM is that local reads will
 * install the cache line as owned/dirty as a result of the RTSR transaction.
 * See section 5.2.3 of the Safari spec.  All processors will read the bus sync
 * list before the rename after flushing local caches.  When copy-rename
 * requires changing the physical address ranges (i.e. smaller memory target),
 * the bus sync list contains physical addresses that will not exist after the
 * rename.  If these cache lines are owned due to a RTSR, a system error can
 * occur following the rename when these cache lines are evicted and a writeback
 * is attempted.
 *
 * Incoming parameter represents either the copy-rename source or a candidate
 * target memory board.  On Starcat, only slot0 boards may have memory.
 */
int
drmach_allow_memrange_modify(drmachid_t s0id)
{
	drmach_board_t	*s0bp, *s1bp;
	drmachid_t	s1id;
	int		rv;

	s0bp = s0id;

	ASSERT(DRMACH_IS_BOARD_ID(s0id));
	ASSERT(DRMACH_BNUM2SLOT(s0bp->bnum) == 0);

	if (s0bp->flags & DRMACH_NULL_PROC_LPA) {
		/*
		 * This is reason enough to fail the request, no need
		 * to check the device list for cpus.
		 */
		return (0);
	}

	/*
	 * Check for MCPU board on the same expander.
	 *
	 * The board flag DRMACH_NULL_PROC_LPA can be set for all board
	 * types, as it is derived at from the POST gdcd board flag
	 * L1SSFLG_THIS_L1_NULL_PROC_LPA, which can be set (and should be
	 * ignored) for boards with no processors.  Since NULL proc LPA
	 * applies only to processors, we walk the devices array to detect
	 * MCPUs.
	 */
	rv = drmach_array_get(drmach_boards, s0bp->bnum + 1, &s1id);
	s1bp = s1id;
	if (rv == 0 && s1bp != NULL) {

		ASSERT(DRMACH_IS_BOARD_ID(s1id));
		ASSERT(DRMACH_BNUM2SLOT(s1bp->bnum) == 1);
		ASSERT(DRMACH_BNUM2EXP(s0bp->bnum) ==
		    DRMACH_BNUM2EXP(s1bp->bnum));

		if ((s1bp->flags & DRMACH_NULL_PROC_LPA) &&
		    s1bp->devices != NULL) {
			int		d_idx;
			drmachid_t	d_id;

			rv = drmach_array_first(s1bp->devices, &d_idx, &d_id);
			while (rv == 0) {
				if (DRMACH_IS_CPU_ID(d_id)) {
					/*
					 * Fail MCPU in NULL LPA mode.
					 */
					return (0);
				}

				rv = drmach_array_next(s1bp->devices, &d_idx,
				    &d_id);
			}
		}
	}

	return (1);
}
