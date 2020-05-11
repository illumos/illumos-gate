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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2008
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/async.h>
#include <sys/machcpuvar.h>
#include <sys/machsystm.h>
#include <sys/promif.h>
#include <sys/ksynch.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/kmem.h>
#include <sys/fm/io/opl_mc_fm.h>
#include <sys/memlist.h>
#include <sys/param.h>
#include <sys/disp.h>
#include <vm/page.h>
#include <sys/mc-opl.h>
#include <sys/opl.h>
#include <sys/opl_dimm.h>
#include <sys/scfd/scfostoescf.h>
#include <sys/cpu_module.h>
#include <vm/seg_kmem.h>
#include <sys/vmem.h>
#include <vm/hat_sfmmu.h>
#include <sys/vmsystm.h>
#include <sys/membar.h>
#include <sys/mem.h>

/*
 * Function prototypes
 */
static int mc_open(dev_t *, int, int, cred_t *);
static int mc_close(dev_t, int, int, cred_t *);
static int mc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int mc_attach(dev_info_t *, ddi_attach_cmd_t);
static int mc_detach(dev_info_t *, ddi_detach_cmd_t);

static int mc_poll_init(void);
static void mc_poll_fini(void);
static int mc_board_add(mc_opl_t *mcp);
static int mc_board_del(mc_opl_t *mcp);
static int mc_suspend(mc_opl_t *mcp, uint32_t flag);
static int mc_resume(mc_opl_t *mcp, uint32_t flag);
int opl_mc_suspend(void);
int opl_mc_resume(void);

static void insert_mcp(mc_opl_t *mcp);
static void delete_mcp(mc_opl_t *mcp);

static int pa_to_maddr(mc_opl_t *mcp, uint64_t pa, mc_addr_t *maddr);

static int mc_rangecheck_pa(mc_opl_t *mcp, uint64_t pa);

int mc_get_mem_unum(int, uint64_t, char *, int, int *);
int mc_get_mem_addr(char *unum, char *sid, uint64_t offset, uint64_t *paddr);
int mc_get_mem_offset(uint64_t paddr, uint64_t *offp);
int mc_get_mem_sid(char *unum, char *buf, int buflen, int *lenp);
int mc_get_mem_sid_dimm(mc_opl_t *mcp, char *dname, char *buf,
    int buflen, int *lenp);
mc_dimm_info_t *mc_get_dimm_list(mc_opl_t *mcp);
mc_dimm_info_t *mc_prepare_dimmlist(board_dimm_info_t *bd_dimmp);
int mc_set_mem_sid(mc_opl_t *mcp, char *buf, int buflen, int lsb, int bank,
    uint32_t mf_type, uint32_t d_slot);
static void mc_free_dimm_list(mc_dimm_info_t *d);
static void mc_get_mlist(mc_opl_t *);
static void mc_polling(void);
static int mc_opl_get_physical_board(int);

static void mc_clear_rewrite(mc_opl_t *mcp, int i);
static void mc_set_rewrite(mc_opl_t *mcp, int bank, uint32_t addr, int state);
static int mc_scf_log_event(mc_flt_page_t *flt_pag);

#ifdef	DEBUG
static int mc_ioctl_debug(dev_t, int, intptr_t, int, cred_t *, int *);
void mc_dump_dimm(char *buf, int dnamesz, int serialsz, int partnumsz);
void mc_dump_dimm_info(board_dimm_info_t *bd_dimmp);
#endif

#pragma weak opl_get_physical_board
extern int opl_get_physical_board(int);
extern int plat_max_boards(void);

/*
 * Configuration data structures
 */
static struct cb_ops mc_cb_ops = {
	mc_open,			/* open */
	mc_close,			/* close */
	nulldev,			/* strategy */
	nulldev,			/* print */
	nodev,				/* dump */
	nulldev,			/* read */
	nulldev,			/* write */
	mc_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_MP | D_NEW | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* cb_aread */
	nodev				/* cb_awrite */
};

static struct dev_ops mc_ops = {
	DEVO_REV,			/* rev */
	0,				/* refcnt  */
	ddi_getinfo_1to1,		/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	mc_attach,			/* attach */
	mc_detach,			/* detach */
	nulldev,			/* reset */
	&mc_cb_ops,			/* cb_ops */
	(struct bus_ops *)0,		/* bus_ops */
	nulldev,			/* power */
	ddi_quiesce_not_needed,			/* quiesce */
};

/*
 * Driver globals
 */

static enum {
	MODEL_FF1,
	MODEL_FF2,
	MODEL_DC,
	MODEL_IKKAKU
} plat_model = MODEL_DC;	/* The default behaviour is DC */

static struct plat_model_names {
	const char *unit_name;
	const char *mem_name;
} model_names[] = {
	{ "MBU_A", "MEMB" },
	{ "MBU_B", "MEMB" },
	{ "CMU", "" },
	{ "MBU_A", "" }
};

/*
 * The DIMM Names for DC platform.
 * The index into this table is made up of (bank, dslot),
 * Where dslot occupies bits 0-1 and bank occupies 2-4.
 */
static char *mc_dc_dimm_unum_table[OPL_MAX_DIMMS] = {
	/* --------CMUnn----------- */
	/* --CS0-----|--CS1------ */
	/* -H-|--L-- | -H- | -L-- */
	"03A", "02A", "03B", "02B", /* Bank 0 (MAC 0 bank 0) */
	"13A", "12A", "13B", "12B", /* Bank 1 (MAC 0 bank 1) */
	"23A", "22A", "23B", "22B", /* Bank 2 (MAC 1 bank 0) */
	"33A", "32A", "33B", "32B", /* Bank 3 (MAC 1 bank 1) */
	"01A", "00A", "01B", "00B", /* Bank 4 (MAC 2 bank 0) */
	"11A", "10A", "11B", "10B", /* Bank 5 (MAC 2 bank 1) */
	"21A", "20A", "21B", "20B", /* Bank 6 (MAC 3 bank 0) */
	"31A", "30A", "31B", "30B"  /* Bank 7 (MAC 3 bank 1) */
};

/*
 * The DIMM Names for FF1/FF2/IKKAKU platforms.
 * The index into this table is made up of (board, bank, dslot),
 * Where dslot occupies bits 0-1, bank occupies 2-4 and
 * board occupies the bit 5.
 */
static char *mc_ff_dimm_unum_table[2 * OPL_MAX_DIMMS] = {
	/* --------CMU0---------- */
	/* --CS0-----|--CS1------ */
	/* -H-|--L-- | -H- | -L-- */
	"03A", "02A", "03B", "02B", /* Bank 0 (MAC 0 bank 0) */
	"01A", "00A", "01B", "00B", /* Bank 1 (MAC 0 bank 1) */
	"13A", "12A", "13B", "12B", /* Bank 2 (MAC 1 bank 0) */
	"11A", "10A", "11B", "10B", /* Bank 3 (MAC 1 bank 1) */
	"23A", "22A", "23B", "22B", /* Bank 4 (MAC 2 bank 0) */
	"21A", "20A", "21B", "20B", /* Bank 5 (MAC 2 bank 1) */
	"33A", "32A", "33B", "32B", /* Bank 6 (MAC 3 bank 0) */
	"31A", "30A", "31B", "30B", /* Bank 7 (MAC 3 bank 1) */
	/* --------CMU1---------- */
	/* --CS0-----|--CS1------ */
	/* -H-|--L-- | -H- | -L-- */
	"43A", "42A", "43B", "42B", /* Bank 0 (MAC 0 bank 0) */
	"41A", "40A", "41B", "40B", /* Bank 1 (MAC 0 bank 1) */
	"53A", "52A", "53B", "52B", /* Bank 2 (MAC 1 bank 0) */
	"51A", "50A", "51B", "50B", /* Bank 3 (MAC 1 bank 1) */
	"63A", "62A", "63B", "62B", /* Bank 4 (MAC 2 bank 0) */
	"61A", "60A", "61B", "60B", /* Bank 5 (MAC 2 bank 1) */
	"73A", "72A", "73B", "72B", /* Bank 6 (MAC 3 bank 0) */
	"71A", "70A", "71B", "70B"  /* Bank 7 (MAC 3 bank 1) */
};

#define	BD_BK_SLOT_TO_INDEX(bd, bk, s)			\
	(((bd & 0x01) << 5) | ((bk & 0x07) << 2) | (s & 0x03))

#define	INDEX_TO_BANK(i)			(((i) & 0x1C) >> 2)
#define	INDEX_TO_SLOT(i)			((i) & 0x03)

#define	SLOT_TO_CS(slot)	((slot & 0x3) >> 1)

/* Isolation unit size is 64 MB */
#define	MC_ISOLATION_BSIZE	(64 * 1024 * 1024)

#define	MC_MAX_SPEEDS 7

typedef struct {
	uint32_t mc_speeds;
	uint32_t mc_period;
} mc_scan_speed_t;

#define	MC_CNTL_SPEED_SHIFT 26

/*
 * In mirror mode, we normalized the bank idx to "even" since
 * the HW treats them as one unit w.r.t programming.
 * This bank index will be the "effective" bank index.
 * All mirrored bank state info on mc_period, mc_speedup_period
 * will be stored in the even bank structure to avoid code duplication.
 */
#define	MIRROR_IDX(bankidx)	(bankidx & ~1)

static mc_scan_speed_t	mc_scan_speeds[MC_MAX_SPEEDS] = {
	{0x6 << MC_CNTL_SPEED_SHIFT, 0},
	{0x5 << MC_CNTL_SPEED_SHIFT, 32},
	{0x4 << MC_CNTL_SPEED_SHIFT, 64},
	{0x3 << MC_CNTL_SPEED_SHIFT, 128},
	{0x2 << MC_CNTL_SPEED_SHIFT, 256},
	{0x1 << MC_CNTL_SPEED_SHIFT, 512},
	{0x0 << MC_CNTL_SPEED_SHIFT, 1024}
};

static uint32_t	mc_max_speed = (0x6 << 26);

int mc_isolation_bsize = MC_ISOLATION_BSIZE;
int mc_patrol_interval_sec = MC_PATROL_INTERVAL_SEC;
int mc_max_scf_retry = 16;
int mc_max_scf_logs = 64;
int mc_max_errlog_processed = BANKNUM_PER_SB*2;
int mc_scan_period = 12 * 60 * 60;	/* 12 hours period */
int mc_max_rewrite_loop = 100;
int mc_rewrite_delay = 10;
/*
 * it takes SCF about 300 m.s. to process a requst.  We can bail out
 * if it is busy.  It does not pay to wait for it too long.
 */
int mc_max_scf_loop = 2;
int mc_scf_delay = 100;
int mc_pce_dropped = 0;
int mc_poll_priority = MINCLSYSPRI;
int mc_max_rewrite_retry = 6 * 60;


/*
 * Mutex hierarchy in mc-opl
 * If both mcmutex and mc_lock must be held,
 * mcmutex must be acquired first, and then mc_lock.
 */

static kmutex_t mcmutex;
mc_opl_t *mc_instances[OPL_MAX_BOARDS];

static kmutex_t mc_polling_lock;
static kcondvar_t mc_polling_cv;
static kcondvar_t mc_poll_exit_cv;
static int mc_poll_cmd = 0;
static int mc_pollthr_running = 0;
int mc_timeout_period = 0; /* this is in m.s. */
void *mc_statep;

#ifdef	DEBUG
int oplmc_debug = 0;
#endif

static int mc_debug_show_all = 0;

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,			/* module type, this one is a driver */
	"OPL Memory-controller",	/* module name */
	&mc_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* rev */
	(void *)&modldrv,
	NULL
};

#pragma weak opl_get_mem_unum
#pragma weak opl_get_mem_sid
#pragma weak opl_get_mem_offset
#pragma weak opl_get_mem_addr

extern int (*opl_get_mem_unum)(int, uint64_t, char *, int, int *);
extern int (*opl_get_mem_sid)(char *unum, char *buf, int buflen, int *lenp);
extern int (*opl_get_mem_offset)(uint64_t paddr, uint64_t *offp);
extern int (*opl_get_mem_addr)(char *unum, char *sid, uint64_t offset,
    uint64_t *paddr);


/*
 * pseudo-mc node portid format
 *
 *		[10]   = 0
 *		[9]    = 1
 *		[8]    = LSB_ID[4] = 0
 *		[7:4]  = LSB_ID[3:0]
 *		[3:0]  = 0
 *
 */

/*
 * These are the module initialization routines.
 */
int
_init(void)
{
	int	error;
	int	plen;
	char	model[20];
	pnode_t	node;


	if ((error = ddi_soft_state_init(&mc_statep,
	    sizeof (mc_opl_t), 1)) != 0)
		return (error);

	if ((error = mc_poll_init()) != 0) {
		ddi_soft_state_fini(&mc_statep);
		return (error);
	}

	mutex_init(&mcmutex, NULL, MUTEX_DRIVER, NULL);
	if (&opl_get_mem_unum)
		opl_get_mem_unum = mc_get_mem_unum;
	if (&opl_get_mem_sid)
		opl_get_mem_sid = mc_get_mem_sid;
	if (&opl_get_mem_offset)
		opl_get_mem_offset = mc_get_mem_offset;
	if (&opl_get_mem_addr)
		opl_get_mem_addr = mc_get_mem_addr;

	node = prom_rootnode();
	plen = prom_getproplen(node, "model");

	if (plen > 0 && plen < sizeof (model)) {
		(void) prom_getprop(node, "model", model);
		model[plen] = '\0';
		if (strcmp(model, "FF1") == 0)
			plat_model = MODEL_FF1;
		else if (strcmp(model, "FF2") == 0)
			plat_model = MODEL_FF2;
		else if (strncmp(model, "DC", 2) == 0)
			plat_model = MODEL_DC;
		else if (strcmp(model, "IKKAKU") == 0)
			plat_model = MODEL_IKKAKU;
	}

	error =  mod_install(&modlinkage);
	if (error != 0) {
		if (&opl_get_mem_unum)
			opl_get_mem_unum = NULL;
		if (&opl_get_mem_sid)
			opl_get_mem_sid = NULL;
		if (&opl_get_mem_offset)
			opl_get_mem_offset = NULL;
		if (&opl_get_mem_addr)
			opl_get_mem_addr = NULL;
		mutex_destroy(&mcmutex);
		mc_poll_fini();
		ddi_soft_state_fini(&mc_statep);
	}
	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	if (&opl_get_mem_unum)
		opl_get_mem_unum = NULL;
	if (&opl_get_mem_sid)
		opl_get_mem_sid = NULL;
	if (&opl_get_mem_offset)
		opl_get_mem_offset = NULL;
	if (&opl_get_mem_addr)
		opl_get_mem_addr = NULL;

	mutex_destroy(&mcmutex);
	mc_poll_fini();
	ddi_soft_state_fini(&mc_statep);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
mc_polling_thread()
{
	mutex_enter(&mc_polling_lock);
	mc_pollthr_running = 1;
	while (!(mc_poll_cmd & MC_POLL_EXIT)) {
		mc_polling();
		(void) cv_reltimedwait(&mc_polling_cv, &mc_polling_lock,
		    mc_timeout_period, TR_CLOCK_TICK);
	}
	mc_pollthr_running = 0;

	/*
	 * signal if any one is waiting for this thread to exit.
	 */
	cv_signal(&mc_poll_exit_cv);
	mutex_exit(&mc_polling_lock);
	thread_exit();
	/* NOTREACHED */
}

static int
mc_poll_init()
{
	mutex_init(&mc_polling_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&mc_polling_cv, NULL, CV_DRIVER, NULL);
	cv_init(&mc_poll_exit_cv, NULL, CV_DRIVER, NULL);
	return (0);
}

static void
mc_poll_fini()
{
	mutex_enter(&mc_polling_lock);
	if (mc_pollthr_running) {
		mc_poll_cmd = MC_POLL_EXIT;
		cv_signal(&mc_polling_cv);
		while (mc_pollthr_running) {
			cv_wait(&mc_poll_exit_cv, &mc_polling_lock);
		}
	}
	mutex_exit(&mc_polling_lock);
	mutex_destroy(&mc_polling_lock);
	cv_destroy(&mc_polling_cv);
	cv_destroy(&mc_poll_exit_cv);
}

static int
mc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	mc_opl_t *mcp;
	int instance;
	int rv;

	/* get the instance of this devi */
	instance = ddi_get_instance(devi);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		mcp = ddi_get_soft_state(mc_statep, instance);
		rv = mc_resume(mcp, MC_DRIVER_SUSPENDED);
		return (rv);
	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(mc_statep, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(devi, "mc-opl", S_IFCHR, instance,
	    "ddi_mem_ctrl", 0) != DDI_SUCCESS) {
		MC_LOG("mc_attach: create_minor_node failed\n");
		return (DDI_FAILURE);
	}

	if ((mcp = ddi_get_soft_state(mc_statep, instance)) == NULL) {
		goto bad;
	}

	if (mc_timeout_period == 0) {
		mc_patrol_interval_sec = (int)ddi_getprop(DDI_DEV_T_ANY, devi,
		    DDI_PROP_DONTPASS, "mc-timeout-interval-sec",
		    mc_patrol_interval_sec);
		mc_timeout_period = drv_usectohz(1000000 *
		    mc_patrol_interval_sec / OPL_MAX_BOARDS);
	}

	/* set informations in mc state */
	mcp->mc_dip = devi;

	if (mc_board_add(mcp))
		goto bad;

	insert_mcp(mcp);

	/*
	 * Start the polling thread if it is not running already.
	 */
	mutex_enter(&mc_polling_lock);
	if (!mc_pollthr_running) {
		(void) thread_create(NULL, 0, (void (*)())mc_polling_thread,
		    NULL, 0, &p0, TS_RUN, mc_poll_priority);
	}
	mutex_exit(&mc_polling_lock);
	ddi_report_dev(devi);

	return (DDI_SUCCESS);

bad:
	ddi_remove_minor_node(devi, NULL);
	ddi_soft_state_free(mc_statep, instance);
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
mc_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int rv;
	int instance;
	mc_opl_t *mcp;

	/* get the instance of this devi */
	instance = ddi_get_instance(devi);
	if ((mcp = ddi_get_soft_state(mc_statep, instance)) == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_SUSPEND:
		rv = mc_suspend(mcp, MC_DRIVER_SUSPENDED);
		return (rv);
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	delete_mcp(mcp);
	if (mc_board_del(mcp) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	ddi_remove_minor_node(devi, NULL);

	/* free up the soft state */
	ddi_soft_state_free(mc_statep, instance);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
mc_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	return (0);
}

/* ARGSUSED */
static int
mc_close(dev_t devp, int flag, int otyp, cred_t *credp)
{
	return (0);
}

/* ARGSUSED */
static int
mc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	mc_flt_page_t flt_page;

	if (cmd == MCIOC_FAULT_PAGE) {
		if (arg == (intptr_t)NULL)
			return (EINVAL);

		if (ddi_copyin((const void *)arg, (void *)&flt_page,
		    sizeof (mc_flt_page_t), 0) < 0)
			return (EFAULT);

		return (mc_scf_log_event(&flt_page));
	}
#ifdef DEBUG
	return (mc_ioctl_debug(dev, cmd, arg, mode, credp, rvalp));
#else
	return (ENOTTY);
#endif
}

/*
 * PA validity check:
 * This function return 1 if the PA is a valid PA
 * in the running Solaris instance i.e. in physinstall
 * Otherwise, return 0.
 */

/* ARGSUSED */
static int
pa_is_valid(mc_opl_t *mcp, uint64_t addr)
{
	if (mcp->mlist == NULL)
		mc_get_mlist(mcp);

	if (mcp->mlist && address_in_memlist(mcp->mlist, addr, 0)) {
		return (1);
	}
	return (0);
}

/*
 * mac-pa translation routines.
 *
 *    Input: mc driver state, (LSB#, Bank#, DIMM address)
 *    Output: physical address
 *
 *    Valid   - return value:  0
 *    Invalid - return value: -1
 */
static int
mcaddr_to_pa(mc_opl_t *mcp, mc_addr_t *maddr, uint64_t *pa)
{
	int i;
	uint64_t pa_offset = 0;
	int cs = (maddr->ma_dimm_addr >> CS_SHIFT) & 1;
	int bank = maddr->ma_bank;
	mc_addr_t maddr1;
	int bank0, bank1;

	MC_LOG("mcaddr /LSB%d/B%d/%x\n", maddr->ma_bd, bank,
	    maddr->ma_dimm_addr);

	/* loc validity check */
	ASSERT(maddr->ma_bd >= 0 && OPL_BOARD_MAX > maddr->ma_bd);
	ASSERT(bank >= 0 && OPL_BANK_MAX > bank);

	/* Do translation */
	for (i = 0; i < PA_BITS_FOR_MAC; i++) {
		int pa_bit = 0;
		int mc_bit = mcp->mc_trans_table[cs][i];
		if (mc_bit < MC_ADDRESS_BITS) {
			pa_bit = (maddr->ma_dimm_addr >> mc_bit) & 1;
		} else if (mc_bit == MP_NONE) {
			pa_bit = 0;
		} else if (mc_bit == MP_BANK_0) {
			pa_bit = bank & 1;
		} else if (mc_bit == MP_BANK_1) {
			pa_bit = (bank >> 1) & 1;
		} else if (mc_bit == MP_BANK_2) {
			pa_bit = (bank >> 2) & 1;
		}
		pa_offset |= ((uint64_t)pa_bit) << i;
	}
	*pa = mcp->mc_start_address + pa_offset;
	MC_LOG("pa = %lx\n", *pa);

	if (pa_to_maddr(mcp, *pa, &maddr1) == -1) {
		cmn_err(CE_WARN, "mcaddr_to_pa: /LSB%d/B%d/%x failed to "
		    "convert PA %lx\n", maddr->ma_bd, bank,
		    maddr->ma_dimm_addr, *pa);
		return (-1);
	}

	/*
	 * In mirror mode, PA is always translated to the even bank.
	 */
	if (IS_MIRROR(mcp, maddr->ma_bank)) {
		bank0 = maddr->ma_bank & ~(1);
		bank1 = maddr1.ma_bank & ~(1);
	} else {
		bank0 = maddr->ma_bank;
		bank1 = maddr1.ma_bank;
	}
	/*
	 * there is no need to check ma_bd because it is generated from
	 * mcp.  They are the same.
	 */
	if ((bank0 == bank1) && (maddr->ma_dimm_addr ==
	    maddr1.ma_dimm_addr)) {
		return (0);
	} else {
		MC_LOG("Translation error source /LSB%d/B%d/%x, "
		    "PA %lx, target /LSB%d/B%d/%x\n", maddr->ma_bd, bank,
		    maddr->ma_dimm_addr, *pa, maddr1.ma_bd, maddr1.ma_bank,
		    maddr1.ma_dimm_addr);
		return (-1);
	}
}

/*
 * PA to CS (used by pa_to_maddr).
 */
static int
pa_to_cs(mc_opl_t *mcp, uint64_t pa_offset)
{
	int i;
	int cs = 1;

	for (i = 0; i < PA_BITS_FOR_MAC; i++) {
		/* MAC address bit<29> is arranged on the same PA bit */
		/* on both table. So we may use any table. */
		if (mcp->mc_trans_table[0][i] == CS_SHIFT) {
			cs = (pa_offset >> i) & 1;
			break;
		}
	}
	return (cs);
}

/*
 * PA to DIMM (used by pa_to_maddr).
 */
/* ARGSUSED */
static uint32_t
pa_to_dimm(mc_opl_t *mcp, uint64_t pa_offset)
{
	int i;
	int cs = pa_to_cs(mcp, pa_offset);
	uint32_t dimm_addr = 0;

	for (i = 0; i < PA_BITS_FOR_MAC; i++) {
		int pa_bit_value = (pa_offset >> i) & 1;
		int mc_bit = mcp->mc_trans_table[cs][i];
		if (mc_bit < MC_ADDRESS_BITS) {
			dimm_addr |= pa_bit_value << mc_bit;
		}
	}
	dimm_addr |= cs << CS_SHIFT;
	return (dimm_addr);
}

/*
 * PA to Bank (used by pa_to_maddr).
 */
static int
pa_to_bank(mc_opl_t *mcp, uint64_t pa_offset)
{
	int i;
	int cs = pa_to_cs(mcp, pa_offset);
	int bankno = mcp->mc_trans_table[cs][INDEX_OF_BANK_SUPPLEMENT_BIT];


	for (i = 0; i < PA_BITS_FOR_MAC; i++) {
		int pa_bit_value = (pa_offset >> i) & 1;
		int mc_bit = mcp->mc_trans_table[cs][i];
		switch (mc_bit) {
		case MP_BANK_0:
			bankno |= pa_bit_value;
			break;
		case MP_BANK_1:
			bankno |= pa_bit_value << 1;
			break;
		case MP_BANK_2:
			bankno |= pa_bit_value << 2;
			break;
		}
	}

	return (bankno);
}

/*
 * PA to MAC address translation
 *
 *   Input: MAC driver state, physicall adress
 *   Output: LSB#, Bank id, mac address
 *
 *    Valid   - return value:  0
 *    Invalid - return value: -1
 */

int
pa_to_maddr(mc_opl_t *mcp, uint64_t pa, mc_addr_t *maddr)
{
	uint64_t pa_offset;

	if (!mc_rangecheck_pa(mcp, pa))
		return (-1);

	/* Do translation */
	pa_offset = pa - mcp->mc_start_address;

	maddr->ma_bd = mcp->mc_board_num;
	maddr->ma_phys_bd = mcp->mc_phys_board_num;
	maddr->ma_bank = pa_to_bank(mcp, pa_offset);
	maddr->ma_dimm_addr = pa_to_dimm(mcp, pa_offset);
	MC_LOG("pa %lx -> mcaddr /LSB%d/B%d/%x\n", pa_offset, maddr->ma_bd,
	    maddr->ma_bank, maddr->ma_dimm_addr);
	return (0);
}

/*
 * UNUM format for DC is "/CMUnn/MEMxyZ", where
 *	nn = 00..03 for DC1 and 00..07 for DC2 and 00..15 for DC3.
 *	x = MAC 0..3
 *	y = 0..3 (slot info).
 *	Z = 'A' or 'B'
 *
 * UNUM format for FF1 is "/MBU_A/MEMBx/MEMyZ", where
 *	x = 0..3 (MEMB number)
 *	y = 0..3 (slot info).
 *	Z = 'A' or 'B'
 *
 * UNUM format for FF2 is "/MBU_B/MEMBx/MEMyZ", where
 *	x = 0..7 (MEMB number)
 *	y = 0..3 (slot info).
 *	Z = 'A' or 'B'
 *
 * UNUM format for IKKAKU is "/MBU_A/MEMyZ", where
 *	y = 0..3 (slot info).
 *	Z = 'A' or 'B'
 *
 */
int
mc_set_mem_unum(char *buf, int buflen, int sb, int bank,
    uint32_t mf_type, uint32_t d_slot)
{
	char *dimmnm;
	char memb_num;
	int cs;
	int i;
	int j;

	cs = SLOT_TO_CS(d_slot);

	switch (plat_model) {
	case MODEL_DC:
		if (mf_type == FLT_TYPE_INTERMITTENT_CE ||
		    mf_type == FLT_TYPE_PERMANENT_CE) {
			i = BD_BK_SLOT_TO_INDEX(0, bank, d_slot);
			dimmnm = mc_dc_dimm_unum_table[i];
			(void) snprintf(buf, buflen, "/%s%02d/MEM%s",
			    model_names[plat_model].unit_name, sb, dimmnm);
		} else {
			i = BD_BK_SLOT_TO_INDEX(0, bank, 0);
			j = (cs == 0) ?  i : i + 2;
			(void) snprintf(buf, buflen, "/%s%02d/MEM%s MEM%s",
			    model_names[plat_model].unit_name, sb,
			    mc_dc_dimm_unum_table[j],
			    mc_dc_dimm_unum_table[j + 1]);
		}
		break;
	case MODEL_FF1:
	case MODEL_FF2:
		if (mf_type == FLT_TYPE_INTERMITTENT_CE ||
		    mf_type == FLT_TYPE_PERMANENT_CE) {
			i = BD_BK_SLOT_TO_INDEX(sb, bank, d_slot);
			dimmnm = mc_ff_dimm_unum_table[i];
			memb_num = dimmnm[0];
			(void) snprintf(buf, buflen, "/%s/%s%c/MEM%s",
			    model_names[plat_model].unit_name,
			    model_names[plat_model].mem_name,
			    memb_num, &dimmnm[1]);
		} else {
			i = BD_BK_SLOT_TO_INDEX(sb, bank, 0);
			j = (cs == 0) ?  i : i + 2;
			memb_num = mc_ff_dimm_unum_table[i][0],
			    (void) snprintf(buf, buflen, "/%s/%s%c/MEM%s MEM%s",
			    model_names[plat_model].unit_name,
			    model_names[plat_model].mem_name, memb_num,
			    &mc_ff_dimm_unum_table[j][1],
			    &mc_ff_dimm_unum_table[j + 1][1]);
		}
		break;
	case MODEL_IKKAKU:
		if (mf_type == FLT_TYPE_INTERMITTENT_CE ||
		    mf_type == FLT_TYPE_PERMANENT_CE) {
			i = BD_BK_SLOT_TO_INDEX(sb, bank, d_slot);
			dimmnm = mc_ff_dimm_unum_table[i];
			(void) snprintf(buf, buflen, "/%s/MEM%s",
			    model_names[plat_model].unit_name, &dimmnm[1]);
		} else {
			i = BD_BK_SLOT_TO_INDEX(sb, bank, 0);
			j = (cs == 0) ?  i : i + 2;
			memb_num = mc_ff_dimm_unum_table[i][0],
			    (void) snprintf(buf, buflen, "/%s/MEM%s MEM%s",
			    model_names[plat_model].unit_name,
			    &mc_ff_dimm_unum_table[j][1],
			    &mc_ff_dimm_unum_table[j + 1][1]);
		}
		break;
	default:
		return (-1);
	}
	return (0);
}

static void
mc_ereport_post(mc_aflt_t *mc_aflt)
{
	char buf[FM_MAX_CLASS];
	char device_path[MAXPATHLEN];
	char sid[MAXPATHLEN];
	nv_alloc_t *nva = NULL;
	nvlist_t *ereport, *detector, *resource;
	errorq_elem_t *eqep;
	int nflts;
	mc_flt_stat_t *flt_stat;
	int i, n;
	int blen = MAXPATHLEN;
	char *p, *s = NULL;
	uint32_t values[2], synd[2], dslot[2];
	uint64_t offset = (uint64_t)-1;
	int ret = -1;

	if (panicstr) {
		eqep = errorq_reserve(ereport_errorq);
		if (eqep == NULL)
			return;
		ereport = errorq_elem_nvl(ereport_errorq, eqep);
		nva = errorq_elem_nva(ereport_errorq, eqep);
	} else {
		ereport = fm_nvlist_create(nva);
	}

	/*
	 * Create the scheme "dev" FMRI.
	 */
	detector = fm_nvlist_create(nva);
	resource = fm_nvlist_create(nva);

	nflts = mc_aflt->mflt_nflts;

	ASSERT(nflts >= 1 && nflts <= 2);

	flt_stat = mc_aflt->mflt_stat[0];
	(void) ddi_pathname(mc_aflt->mflt_mcp->mc_dip, device_path);
	(void) fm_fmri_dev_set(detector, FM_DEV_SCHEME_VERSION, NULL,
	    device_path, NULL, NULL);

	/*
	 * Encode all the common data into the ereport.
	 */
	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s-%s", MC_OPL_ERROR_CLASS,
	    mc_aflt->mflt_is_ptrl ? MC_OPL_PTRL_SUBCLASS : MC_OPL_MI_SUBCLASS,
	    mc_aflt->mflt_erpt_class);

	MC_LOG("mc_ereport_post: ereport %s\n", buf);


	fm_ereport_set(ereport, FM_EREPORT_VERSION, buf,
	    fm_ena_generate(mc_aflt->mflt_id, FM_ENA_FMT1), detector, NULL);

	/*
	 * Set payload.
	 */
	fm_payload_set(ereport, MC_OPL_BOARD, DATA_TYPE_UINT32,
	    flt_stat->mf_flt_maddr.ma_bd, NULL);

	fm_payload_set(ereport, MC_OPL_PA, DATA_TYPE_UINT64,
	    flt_stat->mf_flt_paddr, NULL);

	if (flt_stat->mf_type == FLT_TYPE_INTERMITTENT_CE ||
	    flt_stat->mf_type == FLT_TYPE_PERMANENT_CE) {
		fm_payload_set(ereport, MC_OPL_FLT_TYPE, DATA_TYPE_UINT8,
		    ECC_STICKY, NULL);
	}

	for (i = 0; i < nflts; i++)
		values[i] = mc_aflt->mflt_stat[i]->mf_flt_maddr.ma_bank;

	fm_payload_set(ereport, MC_OPL_BANK, DATA_TYPE_UINT32_ARRAY, nflts,
	    values, NULL);

	for (i = 0; i < nflts; i++)
		values[i] = mc_aflt->mflt_stat[i]->mf_cntl;

	fm_payload_set(ereport, MC_OPL_STATUS, DATA_TYPE_UINT32_ARRAY, nflts,
	    values, NULL);

	for (i = 0; i < nflts; i++)
		values[i] = mc_aflt->mflt_stat[i]->mf_err_add;

	/* offset is set only for PCE and ICE */
	if (mc_aflt->mflt_stat[0]->mf_type == FLT_TYPE_INTERMITTENT_CE ||
	    mc_aflt->mflt_stat[0]->mf_type == FLT_TYPE_PERMANENT_CE) {
		offset = values[0];

	}
	fm_payload_set(ereport, MC_OPL_ERR_ADD, DATA_TYPE_UINT32_ARRAY, nflts,
	    values, NULL);

	for (i = 0; i < nflts; i++)
		values[i] = mc_aflt->mflt_stat[i]->mf_err_log;

	fm_payload_set(ereport, MC_OPL_ERR_LOG, DATA_TYPE_UINT32_ARRAY, nflts,
	    values, NULL);

	for (i = 0; i < nflts; i++) {
		flt_stat = mc_aflt->mflt_stat[i];
		if (flt_stat->mf_errlog_valid) {
			synd[i] = flt_stat->mf_synd;
			dslot[i] = flt_stat->mf_dimm_slot;
			values[i] = flt_stat->mf_dram_place;
		} else {
			synd[i] = 0;
			dslot[i] = 0;
			values[i] = 0;
		}
	}

	fm_payload_set(ereport, MC_OPL_ERR_SYND, DATA_TYPE_UINT32_ARRAY, nflts,
	    synd, NULL);

	fm_payload_set(ereport, MC_OPL_ERR_DIMMSLOT, DATA_TYPE_UINT32_ARRAY,
	    nflts, dslot, NULL);

	fm_payload_set(ereport, MC_OPL_ERR_DRAM, DATA_TYPE_UINT32_ARRAY, nflts,
	    values, NULL);

	device_path[0] = 0;
	p = &device_path[0];
	sid[0] = 0;
	s = &sid[0];
	ret = 0;

	for (i = 0; i < nflts; i++) {
		int bank;

		flt_stat = mc_aflt->mflt_stat[i];
		bank = flt_stat->mf_flt_maddr.ma_bank;
		ret = mc_set_mem_unum(p + strlen(p), blen,
		    flt_stat->mf_flt_maddr.ma_phys_bd, bank, flt_stat->mf_type,
		    flt_stat->mf_dimm_slot);

		if (ret != 0) {
			cmn_err(CE_WARN,
			    "mc_ereport_post: Failed to determine the unum "
			    "for board=%d bank=%d type=0x%x slot=0x%x",
			    flt_stat->mf_flt_maddr.ma_bd, bank,
			    flt_stat->mf_type, flt_stat->mf_dimm_slot);
			continue;
		}
		n = strlen(device_path);
		blen = MAXPATHLEN - n;
		p = &device_path[n];
		if (i < (nflts - 1)) {
			(void) snprintf(p, blen, " ");
			blen--;
			p++;
		}

		if (ret == 0) {
			ret = mc_set_mem_sid(mc_aflt->mflt_mcp, s + strlen(s),
			    blen, flt_stat->mf_flt_maddr.ma_phys_bd, bank,
			    flt_stat->mf_type, flt_stat->mf_dimm_slot);

		}
	}

	(void) fm_fmri_mem_set(resource, FM_MEM_SCHEME_VERSION, NULL,
	    device_path, (ret == 0) ? sid : NULL, (ret == 0) ? offset :
	    (uint64_t)-1);

	fm_payload_set(ereport, MC_OPL_RESOURCE, DATA_TYPE_NVLIST, resource,
	    NULL);

	if (panicstr) {
		errorq_commit(ereport_errorq, eqep, ERRORQ_SYNC);
	} else {
		(void) fm_ereport_post(ereport, EVCH_TRYHARD);
		fm_nvlist_destroy(ereport, FM_NVA_FREE);
		fm_nvlist_destroy(detector, FM_NVA_FREE);
		fm_nvlist_destroy(resource, FM_NVA_FREE);
	}
}


static void
mc_err_drain(mc_aflt_t *mc_aflt)
{
	int rv;
	uint64_t pa = (uint64_t)(-1);
	int i;

	MC_LOG("mc_err_drain: %s\n", mc_aflt->mflt_erpt_class);
	/*
	 * we come here only when we have:
	 * In mirror mode: MUE, SUE
	 * In normal mode: UE, Permanent CE, Intermittent CE
	 */
	for (i = 0; i < mc_aflt->mflt_nflts; i++) {
		rv = mcaddr_to_pa(mc_aflt->mflt_mcp,
		    &(mc_aflt->mflt_stat[i]->mf_flt_maddr), &pa);

		/* Ensure the pa is valid (not in isolated memory block) */
		if (rv == 0 && pa_is_valid(mc_aflt->mflt_mcp, pa))
			mc_aflt->mflt_stat[i]->mf_flt_paddr = pa;
		else
			mc_aflt->mflt_stat[i]->mf_flt_paddr = (uint64_t)-1;
	}

	MC_LOG("mc_err_drain:pa = %lx\n", pa);

	switch (page_retire_check(pa, NULL)) {
	case 0:
	case EAGAIN:
		MC_LOG("Page retired or pending\n");
		return;
	case EIO:
		/*
		 * Do page retirement except for the PCE and ICE cases.
		 * This is taken care by the OPL DE
		 */
		if (mc_aflt->mflt_stat[0]->mf_type !=
		    FLT_TYPE_INTERMITTENT_CE &&
		    mc_aflt->mflt_stat[0]->mf_type != FLT_TYPE_PERMANENT_CE) {
			MC_LOG("offline page at pa %lx error %x\n", pa,
			    mc_aflt->mflt_pr);
			(void) page_retire(pa, mc_aflt->mflt_pr);
		}
		break;
	case EINVAL:
	default:
		/*
		 * Some memory do not have page structure so
		 * we keep going in case of EINVAL.
		 */
		break;
	}

	for (i = 0; i < mc_aflt->mflt_nflts; i++) {
		mc_aflt_t mc_aflt0;
		if (mc_aflt->mflt_stat[i]->mf_flt_paddr != (uint64_t)-1) {
			mc_aflt0 = *mc_aflt;
			mc_aflt0.mflt_nflts = 1;
			mc_aflt0.mflt_stat[0] = mc_aflt->mflt_stat[i];
			mc_ereport_post(&mc_aflt0);
		}
	}
}

/*
 * The restart address is actually defined in unit of PA[37:6]
 * the mac patrol will convert that to dimm offset.  If the
 * address is not in the bank, it will continue to search for
 * the next PA that is within the bank.
 *
 * Also the mac patrol scans the dimms based on PA, not
 * dimm offset.
 */
static int
restart_patrol(mc_opl_t *mcp, int bank, mc_rsaddr_info_t *rsaddr_info)
{
	uint64_t pa;
	int rv;

	if (MC_REWRITE_MODE(mcp, bank)) {
		return (0);
	}
	if (rsaddr_info == NULL || (rsaddr_info->mi_valid == 0)) {
		MAC_PTRL_START(mcp, bank);
		return (0);
	}

	rv = mcaddr_to_pa(mcp, &rsaddr_info->mi_restartaddr, &pa);
	if (rv != 0) {
		MC_LOG("cannot convert mcaddr to pa. use auto restart\n");
		MAC_PTRL_START(mcp, bank);
		return (0);
	}

	if (!mc_rangecheck_pa(mcp, pa)) {
		/* pa is not on this board, just retry */
		cmn_err(CE_WARN, "restart_patrol: invalid address %lx "
		    "on board %d\n", pa, mcp->mc_board_num);
		MAC_PTRL_START(mcp, bank);
		return (0);
	}

	MC_LOG("restart_patrol: pa = %lx\n", pa);

	if (!rsaddr_info->mi_injectrestart) {
		/*
		 * For non-error injection restart we need to
		 * determine if the current restart pa/page is
		 * a "good" page. A "good" page is a page that
		 * has not been page retired. If the current
		 * page that contains the pa is "good", we will
		 * do a HW auto restart and let HW patrol continue
		 * where it last stopped. Most desired scenario.
		 *
		 * If the current page is not "good", we will advance
		 * to the next page to find the next "good" page and
		 * restart the patrol from there.
		 */
		int wrapcount = 0;
		uint64_t origpa = pa;
		while (wrapcount < 2) {
			if (!pa_is_valid(mcp, pa)) {
			/*
			 * Not in physinstall - advance to the
			 * next memory isolation blocksize
			 */
			MC_LOG("Invalid PA\n");
			pa = roundup(pa + 1, mc_isolation_bsize);
			} else {
			int rv;
			if ((rv = page_retire_check(pa, NULL)) != 0 &&
			    rv != EAGAIN) {
					/*
					 * The page is "good" (not retired),
					 * we will use automatic HW restart
					 * algorithm if this is the original
					 * current starting page.
					 */
				if (pa == origpa) {
					MC_LOG("Page has no error. "
					    "Auto restart\n");
					MAC_PTRL_START(mcp, bank);
					return (0);
				} else {
					/*
					 * found a subsequent good page
					 */
					break;
				}
			}

			/*
			 * Skip to the next page
			 */
			pa = roundup(pa + 1, PAGESIZE);
			MC_LOG("Skipping bad page to %lx\n", pa);
			}

		    /* Check to see if we hit the end of the memory range */
			if (pa >= (mcp->mc_start_address + mcp->mc_size)) {
			MC_LOG("Wrap around\n");
			pa = mcp->mc_start_address;
			wrapcount++;
			}
		}

		if (wrapcount > 1) {
			MC_LOG("Failed to find a good page. Just restart\n");
			MAC_PTRL_START(mcp, bank);
			return (0);
		}
	}

	/*
	 * We reached here either:
	 * 1. We are doing an error injection restart that specify
	 *    the exact pa/page to restart. OR
	 * 2. We found a subsequent good page different from the
	 *    original restart pa/page.
	 * Restart MAC patrol: PA[37:6]
	 */
	MC_LOG("restart at pa = %lx\n", pa);
	ST_MAC_REG(MAC_RESTART_ADD(mcp, bank), MAC_RESTART_PA(pa));
	MAC_PTRL_START_ADD(mcp, bank);

	return (0);
}

static void
mc_retry_info_put(mc_retry_info_t **q, mc_retry_info_t *p)
{
	ASSERT(p != NULL);
	p->ri_next = *q;
	*q = p;
}

static mc_retry_info_t *
mc_retry_info_get(mc_retry_info_t **q)
{
	mc_retry_info_t *p;

	if ((p = *q) != NULL) {
		*q = p->ri_next;
		return (p);
	} else {
		return (NULL);
	}
}

/*
 * Rewriting is used for two purposes.
 *  - to correct the error in memory.
 *  - to determine whether the error is permanent or intermittent.
 * It's done by writing the address in MAC_BANKm_REWRITE_ADD
 * and issuing REW_REQ command in MAC_BANKm_PTRL_CNRL. After that,
 * REW_END (and REW_CE/REW_UE if some error detected) is set when
 * rewrite operation is done. See 4.7.3 and 4.7.11 in Columbus2 PRM.
 *
 * Note that rewrite operation doesn't change RAW_UE to Marked UE.
 * Therefore, we use it only CE case.
 */

static uint32_t
do_rewrite(mc_opl_t *mcp, int bank, uint32_t dimm_addr, int retrying)
{
	uint32_t cntl;
	int count = 0;
	int max_count;
	int retry_state;

	if (retrying)
		max_count = 1;
	else
		max_count = mc_max_rewrite_loop;

	retry_state = RETRY_STATE_PENDING;

	if (!retrying && MC_REWRITE_MODE(mcp, bank)) {
		goto timeout;
	}

	retry_state = RETRY_STATE_ACTIVE;

	/* first wait to make sure PTRL_STATUS is 0 */
	while (count++ < max_count) {
		cntl = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank));
		if (!(cntl & MAC_CNTL_PTRL_STATUS)) {
			count = 0;
			break;
		}
		drv_usecwait(mc_rewrite_delay);
	}
	if (count >= max_count)
		goto timeout;

	count = 0;

	ST_MAC_REG(MAC_REWRITE_ADD(mcp, bank), dimm_addr);
	MAC_REW_REQ(mcp, bank);

	retry_state = RETRY_STATE_REWRITE;

	do {
		if (count++ > max_count) {
			goto timeout;
		} else {
			drv_usecwait(mc_rewrite_delay);
		}
		cntl = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank));
	/*
	 * If there are other MEMORY or PCI activities, this
	 * will be BUSY, else it should be set immediately
	 */
	} while (!(cntl & MAC_CNTL_REW_END));

	MAC_CLEAR_ERRS(mcp, bank, MAC_CNTL_REW_ERRS);
	return (cntl);
timeout:
	mc_set_rewrite(mcp, bank, dimm_addr, retry_state);

	return (0);
}

void
mc_clear_rewrite(mc_opl_t *mcp, int bank)
{
	struct mc_bank *bankp;
	mc_retry_info_t *retry;
	uint32_t rew_addr;

	bankp = &(mcp->mc_bank[bank]);
	retry = bankp->mcb_active;
	bankp->mcb_active = NULL;
	mc_retry_info_put(&bankp->mcb_retry_freelist, retry);

again:
	bankp->mcb_rewrite_count = 0;

	while (retry = mc_retry_info_get(&bankp->mcb_retry_pending)) {
		rew_addr = retry->ri_addr;
		mc_retry_info_put(&bankp->mcb_retry_freelist, retry);
		if (do_rewrite(mcp, bank, rew_addr, 1) == 0)
			break;
	}

	/* we break out if no more pending rewrite or we got timeout again */

	if (!bankp->mcb_active && !bankp->mcb_retry_pending) {
		if (!IS_MIRROR(mcp, bank)) {
			MC_CLEAR_REWRITE_MODE(mcp, bank);
		} else {
			int mbank = bank ^ 1;
			bankp = &(mcp->mc_bank[mbank]);
			if (!bankp->mcb_active && !bankp->mcb_retry_pending) {
			MC_CLEAR_REWRITE_MODE(mcp, bank);
			MC_CLEAR_REWRITE_MODE(mcp, mbank);
			} else {
			bank = mbank;
			goto again;
			}
		}
	}
}

void
mc_set_rewrite(mc_opl_t *mcp, int bank, uint32_t addr, int state)
{
	mc_retry_info_t *retry;
	struct mc_bank *bankp;

	bankp = &mcp->mc_bank[bank];

	retry = mc_retry_info_get(&bankp->mcb_retry_freelist);

	if (retry == NULL) {
		mc_addr_t maddr;
		uint64_t paddr;
		/*
		 * previous rewrite request has not completed yet.
		 * So we discard this rewrite request.
		 */
		maddr.ma_bd = mcp->mc_board_num;
		maddr.ma_bank =  bank;
		maddr.ma_dimm_addr = addr;
		if (mcaddr_to_pa(mcp, &maddr, &paddr) == 0) {
			cmn_err(CE_WARN, "Discard CE rewrite request"
			    " for 0x%lx (/LSB%d/B%d/%x).\n",
			    paddr, mcp->mc_board_num, bank, addr);
		} else {
			cmn_err(CE_WARN, "Discard CE rewrite request"
			    " for /LSB%d/B%d/%x.\n",
			    mcp->mc_board_num, bank, addr);
		}
		return;
	}

	retry->ri_addr = addr;
	retry->ri_state = state;

	MC_SET_REWRITE_MODE(mcp, bank);

	if ((state > RETRY_STATE_PENDING)) {
		ASSERT(bankp->mcb_active == NULL);
		bankp->mcb_active = retry;
	} else {
		mc_retry_info_put(&bankp->mcb_retry_pending, retry);
	}

	if (IS_MIRROR(mcp, bank)) {
		int mbank = bank ^1;
		MC_SET_REWRITE_MODE(mcp, mbank);
	}
}

void
mc_process_scf_log(mc_opl_t *mcp)
{
	int count;
	int n = 0;
	scf_log_t *p;
	int bank;

	for (bank = 0; bank < BANKNUM_PER_SB; bank++) {
		while ((p = mcp->mc_scf_log[bank]) != NULL &&
		    (n < mc_max_errlog_processed)) {
		ASSERT(bank == p->sl_bank);
		count = 0;
		while ((LD_MAC_REG(MAC_STATIC_ERR_ADD(mcp, p->sl_bank))
		    & MAC_STATIC_ERR_VLD)) {
			if (count++ >= (mc_max_scf_loop)) {
				break;
			}
			drv_usecwait(mc_scf_delay);
		}

		if (count < mc_max_scf_loop) {
			ST_MAC_REG(MAC_STATIC_ERR_LOG(mcp, p->sl_bank),
			    p->sl_err_log);

			ST_MAC_REG(MAC_STATIC_ERR_ADD(mcp, p->sl_bank),
			    p->sl_err_add|MAC_STATIC_ERR_VLD);
			mcp->mc_scf_retry[bank] = 0;
		} else {
			/*
			 * if we try too many times, just drop the req
			 */
			if (mcp->mc_scf_retry[bank]++ <=
			    mc_max_scf_retry) {
				return;
			} else {
				if ((++mc_pce_dropped & 0xff) == 0) {
					cmn_err(CE_WARN, "Cannot "
					    "report CE to SCF\n");
				}
			}
		}
		n++;
		mcp->mc_scf_log[bank] = p->sl_next;
		mcp->mc_scf_total[bank]--;
		ASSERT(mcp->mc_scf_total[bank] >= 0);
		kmem_free(p, sizeof (scf_log_t));
		}
	}
}
void
mc_queue_scf_log(mc_opl_t *mcp, mc_flt_stat_t *flt_stat, int bank)
{
	scf_log_t *p;

	if (mcp->mc_scf_total[bank] >= mc_max_scf_logs) {
		if ((++mc_pce_dropped & 0xff) == 0) {
			cmn_err(CE_WARN, "Too many CE requests.\n");
		}
		return;
	}
	p = kmem_zalloc(sizeof (scf_log_t), KM_SLEEP);
	p->sl_next = 0;
	p->sl_err_add = flt_stat->mf_err_add;
	p->sl_err_log = flt_stat->mf_err_log;
	p->sl_bank = bank;

	if (mcp->mc_scf_log[bank] == NULL) {
		/*
		 * we rely on mc_scf_log to detect NULL queue.
		 * mc_scf_log_tail is irrelevant is such case.
		 */
		mcp->mc_scf_log_tail[bank] = mcp->mc_scf_log[bank] = p;
	} else {
		mcp->mc_scf_log_tail[bank]->sl_next = p;
		mcp->mc_scf_log_tail[bank] = p;
	}
	mcp->mc_scf_total[bank]++;
}
/*
 * This routine determines what kind of CE happens, intermittent
 * or permanent as follows. (See 4.7.3 in Columbus2 PRM.)
 * - Do rewrite by issuing REW_REQ command to MAC_PTRL_CNTL register.
 * - If CE is still detected on the same address even after doing
 *   rewrite operation twice, it is determined as permanent error.
 * - If error is not detected anymore, it is determined as intermittent
 *   error.
 * - If UE is detected due to rewrite operation, it should be treated
 *   as UE.
 */

/* ARGSUSED */
static void
mc_scrub_ce(mc_opl_t *mcp, int bank, mc_flt_stat_t *flt_stat, int ptrl_error)
{
	uint32_t cntl;
	int i;

	flt_stat->mf_type = FLT_TYPE_PERMANENT_CE;
	/*
	 * rewrite request 1st time reads and correct error data
	 * and write to DIMM.  2nd rewrite request must be issued
	 * after REW_CE/UE/END is 0.  When the 2nd request is completed,
	 * if REW_CE = 1, then it is permanent CE.
	 */
	for (i = 0; i < 2; i++) {
		cntl = do_rewrite(mcp, bank, flt_stat->mf_err_add, 0);

		if (cntl == 0) {
			/* timeout case */
			return;
		}
		/*
		 * If the error becomes UE or CMPE
		 * we return to the caller immediately.
		 */
		if (cntl & MAC_CNTL_REW_UE) {
			if (ptrl_error)
				flt_stat->mf_cntl |= MAC_CNTL_PTRL_UE;
			else
				flt_stat->mf_cntl |= MAC_CNTL_MI_UE;
			flt_stat->mf_type = FLT_TYPE_UE;
			return;
		}
		if (cntl & MAC_CNTL_REW_CMPE) {
			if (ptrl_error)
				flt_stat->mf_cntl |= MAC_CNTL_PTRL_CMPE;
			else
				flt_stat->mf_cntl |= MAC_CNTL_MI_CMPE;
			flt_stat->mf_type = FLT_TYPE_CMPE;
			return;
		}
	}
	if (!(cntl & MAC_CNTL_REW_CE)) {
		flt_stat->mf_type = FLT_TYPE_INTERMITTENT_CE;
	}

	if (flt_stat->mf_type == FLT_TYPE_PERMANENT_CE) {
		/* report PERMANENT_CE to SP via SCF */
		if (!(flt_stat->mf_err_log & MAC_ERR_LOG_INVALID)) {
			mc_queue_scf_log(mcp, flt_stat, bank);
		}
	}
}

#define	IS_CMPE(cntl, f)	((cntl) & ((f) ? MAC_CNTL_PTRL_CMPE :\
				MAC_CNTL_MI_CMPE))
#define	IS_UE(cntl, f)	((cntl) & ((f) ? MAC_CNTL_PTRL_UE : MAC_CNTL_MI_UE))
#define	IS_CE(cntl, f)	((cntl) & ((f) ? MAC_CNTL_PTRL_CE : MAC_CNTL_MI_CE))
#define	IS_OK(cntl, f)	(!((cntl) & ((f) ? MAC_CNTL_PTRL_ERRS : \
			MAC_CNTL_MI_ERRS)))


static int
IS_CE_ONLY(uint32_t cntl, int ptrl_error)
{
	if (ptrl_error) {
		return ((cntl & MAC_CNTL_PTRL_ERRS) == MAC_CNTL_PTRL_CE);
	} else {
		return ((cntl & MAC_CNTL_MI_ERRS) == MAC_CNTL_MI_CE);
	}
}

void
mc_write_cntl(mc_opl_t *mcp, int bank, uint32_t value)
{
	int ebank = (IS_MIRROR(mcp, bank)) ? MIRROR_IDX(bank) : bank;

	if (mcp->mc_speedup_period[ebank] > 0)
		value |= mc_max_speed;
	else
		value |= mcp->mc_speed;
	ST_MAC_REG(MAC_PTRL_CNTL(mcp, bank), value);
}

static void
mc_read_ptrl_reg(mc_opl_t *mcp, int bank, mc_flt_stat_t *flt_stat)
{
	flt_stat->mf_cntl = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank)) &
	    MAC_CNTL_PTRL_ERRS;
	flt_stat->mf_err_add = LD_MAC_REG(MAC_PTRL_ERR_ADD(mcp, bank));
	flt_stat->mf_err_log = LD_MAC_REG(MAC_PTRL_ERR_LOG(mcp, bank));
	flt_stat->mf_flt_maddr.ma_bd = mcp->mc_board_num;
	flt_stat->mf_flt_maddr.ma_phys_bd = mcp->mc_phys_board_num;
	flt_stat->mf_flt_maddr.ma_bank = bank;
	flt_stat->mf_flt_maddr.ma_dimm_addr = flt_stat->mf_err_add;
}

static void
mc_read_mi_reg(mc_opl_t *mcp, int bank, mc_flt_stat_t *flt_stat)
{
	uint32_t status, old_status;

	status = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank)) & MAC_CNTL_MI_ERRS;
	old_status = 0;

	/* we keep reading until the status is stable */
	while (old_status != status) {
		old_status = status;
		flt_stat->mf_err_add = LD_MAC_REG(MAC_MI_ERR_ADD(mcp, bank));
		flt_stat->mf_err_log = LD_MAC_REG(MAC_MI_ERR_LOG(mcp, bank));
		status = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank)) &
		    MAC_CNTL_MI_ERRS;
		if (status == old_status) {
			break;
		}
	}

	flt_stat->mf_cntl = status;
	flt_stat->mf_flt_maddr.ma_bd = mcp->mc_board_num;
	flt_stat->mf_flt_maddr.ma_phys_bd = mcp->mc_phys_board_num;
	flt_stat->mf_flt_maddr.ma_bank = bank;
	flt_stat->mf_flt_maddr.ma_dimm_addr = flt_stat->mf_err_add;
}


/*
 * Error philosophy for mirror mode:
 *
 * PTRL (The error address for both banks are same, since ptrl stops if it
 * detects error.)
 * - Compare error  log CMPE.
 *
 * - UE-UE           Report MUE.  No rewrite.
 *
 * - UE-*	     UE-(CE/OK). Rewrite to scrub UE.  Report SUE.
 *
 * - CE-*            CE-(CE/OK). Scrub to determine if CE is permanent.
 *                   If CE is permanent, inform SCF.  Once for each
 *		     Dimm.  If CE becomes UE or CMPE, go back to above.
 *
 *
 * MI (The error addresses for each bank are the same or different.)
 * - Compare  error  If addresses are the same.  Just CMPE, so log CMPE.
 *		     If addresses are different (this could happen
 *		     as a result of scrubbing.  Report each separately.
 *		     Only report error info on each side.
 *
 * - UE-UE           Addresses are the same.  Report MUE.
 *		     Addresses are different.  Report SUE on each bank.
 *		     Rewrite to clear UE.
 *
 * - UE-*	     UE-(CE/OK)
 *		     Rewrite to clear UE.  Report SUE for the bank.
 *
 * - CE-*            CE-(CE/OK).  Scrub to determine if CE is permanent.
 *                   If CE becomes UE or CMPE, go back to above.
 *
 */

static int
mc_process_error_mir(mc_opl_t *mcp, mc_aflt_t *mc_aflt, mc_flt_stat_t *flt_stat)
{
	int ptrl_error = mc_aflt->mflt_is_ptrl;
	int i;
	int rv = 0;
	int bank;
	int rewrite_timeout = 0;

	MC_LOG("process mirror errors cntl[0] = %x, cntl[1] = %x\n",
	    flt_stat[0].mf_cntl, flt_stat[1].mf_cntl);

	if (ptrl_error) {
		if (((flt_stat[0].mf_cntl | flt_stat[1].mf_cntl) &
		    MAC_CNTL_PTRL_ERRS) == 0)
			return (0);
	} else {
		if (((flt_stat[0].mf_cntl | flt_stat[1].mf_cntl) &
		    MAC_CNTL_MI_ERRS) == 0)
			return (0);
	}

	/*
	 * First we take care of the case of CE
	 * because they can become UE or CMPE
	 */
	for (i = 0; i < 2; i++) {
		if (IS_CE_ONLY(flt_stat[i].mf_cntl, ptrl_error)) {
			bank = flt_stat[i].mf_flt_maddr.ma_bank;
			MC_LOG("CE detected on bank %d\n", bank);
			mc_scrub_ce(mcp, bank, &flt_stat[i], ptrl_error);
			if (MC_REWRITE_ACTIVE(mcp, bank)) {
				rewrite_timeout = 1;
			}
			rv = 1;
		}
	}

	if (rewrite_timeout)
		return (0);

	/* The above scrubbing can turn CE into UE or CMPE */

	/*
	 * Now we distinguish two cases: same address or not
	 * the same address.  It might seem more intuitive to
	 * distinguish PTRL v.s. MI error but it is more
	 * complicated that way.
	 */

	if (flt_stat[0].mf_err_add == flt_stat[1].mf_err_add) {

		if (IS_CMPE(flt_stat[0].mf_cntl, ptrl_error) ||
		    IS_CMPE(flt_stat[1].mf_cntl, ptrl_error)) {
			flt_stat[0].mf_type = FLT_TYPE_CMPE;
			flt_stat[1].mf_type = FLT_TYPE_CMPE;
			mc_aflt->mflt_erpt_class = MC_OPL_CMPE;
			mc_aflt->mflt_nflts = 2;
			mc_aflt->mflt_stat[0] = &flt_stat[0];
			mc_aflt->mflt_stat[1] = &flt_stat[1];
			mc_aflt->mflt_pr = PR_UE;
			/*
			 * Compare error is result of MAC internal error, so
			 * simply log it instead of publishing an ereport. SCF
			 * diagnoses all the MAC internal and its i/f error.
			 */
			MC_LOG("cmpe error detected\n");
			return (1);
		}

		if (IS_UE(flt_stat[0].mf_cntl, ptrl_error) &&
		    IS_UE(flt_stat[1].mf_cntl, ptrl_error)) {
			/* Both side are UE's */

			MAC_SET_ERRLOG_INFO(&flt_stat[0]);
			MAC_SET_ERRLOG_INFO(&flt_stat[1]);
			MC_LOG("MUE detected\n");
			flt_stat[0].mf_type = FLT_TYPE_MUE;
			flt_stat[1].mf_type = FLT_TYPE_MUE;
			mc_aflt->mflt_erpt_class = MC_OPL_MUE;
			mc_aflt->mflt_nflts = 2;
			mc_aflt->mflt_stat[0] = &flt_stat[0];
			mc_aflt->mflt_stat[1] = &flt_stat[1];
			mc_aflt->mflt_pr = PR_UE;
			mc_err_drain(mc_aflt);
			return (1);
		}

		/* Now the only case is UE/CE, UE/OK, or don't care */
		for (i = 0; i < 2; i++) {
			if (IS_UE(flt_stat[i].mf_cntl, ptrl_error)) {

			/* rewrite can clear the one side UE error */

			if (IS_OK(flt_stat[i^1].mf_cntl, ptrl_error)) {
				(void) do_rewrite(mcp,
				    flt_stat[i].mf_flt_maddr.ma_bank,
				    flt_stat[i].mf_flt_maddr.ma_dimm_addr, 0);
			}
			flt_stat[i].mf_type = FLT_TYPE_UE;
			MAC_SET_ERRLOG_INFO(&flt_stat[i]);
			mc_aflt->mflt_erpt_class = MC_OPL_SUE;
			mc_aflt->mflt_stat[0] = &flt_stat[i];
			mc_aflt->mflt_nflts = 1;
			mc_aflt->mflt_pr = PR_MCE;
			mc_err_drain(mc_aflt);
			/* Once we hit a UE/CE or UE/OK case, done */
			return (1);
			}
		}

	} else {
		/*
		 * addresses are different. That means errors
		 * on the 2 banks are not related at all.
		 */
		for (i = 0; i < 2; i++) {
			if (IS_CMPE(flt_stat[i].mf_cntl, ptrl_error)) {
				flt_stat[i].mf_type = FLT_TYPE_CMPE;
				mc_aflt->mflt_erpt_class = MC_OPL_CMPE;
				mc_aflt->mflt_nflts = 1;
				mc_aflt->mflt_stat[0] = &flt_stat[i];
				mc_aflt->mflt_pr = PR_UE;
				/*
				 * Compare error is result of MAC internal
				 * error, so simply log it instead of
				 * publishing an ereport. SCF diagnoses all
				 * the MAC internal and its interface error.
				 */
				MC_LOG("cmpe error detected\n");
				/* no more report on this bank */
				flt_stat[i].mf_cntl = 0;
				rv = 1;
			}
		}

		/* rewrite can clear the one side UE error */

		for (i = 0; i < 2; i++) {
			if (IS_UE(flt_stat[i].mf_cntl, ptrl_error)) {
				(void) do_rewrite(mcp,
				    flt_stat[i].mf_flt_maddr.ma_bank,
				    flt_stat[i].mf_flt_maddr.ma_dimm_addr,
				    0);
				flt_stat[i].mf_type = FLT_TYPE_UE;
				MAC_SET_ERRLOG_INFO(&flt_stat[i]);
				mc_aflt->mflt_erpt_class = MC_OPL_SUE;
				mc_aflt->mflt_stat[0] = &flt_stat[i];
				mc_aflt->mflt_nflts = 1;
				mc_aflt->mflt_pr = PR_MCE;
				mc_err_drain(mc_aflt);
				rv = 1;
			}
		}
	}
	return (rv);
}
static void
mc_error_handler_mir(mc_opl_t *mcp, int bank, mc_rsaddr_info_t *rsaddr)
{
	mc_aflt_t mc_aflt;
	mc_flt_stat_t flt_stat[2], mi_flt_stat[2];
	int i;
	int mi_valid;

	ASSERT(rsaddr);

	bzero(&mc_aflt, sizeof (mc_aflt_t));
	bzero(&flt_stat, 2 * sizeof (mc_flt_stat_t));
	bzero(&mi_flt_stat, 2 * sizeof (mc_flt_stat_t));


	mc_aflt.mflt_mcp = mcp;
	mc_aflt.mflt_id = gethrtime();

	/* Now read all the registers into flt_stat */

	for (i = 0; i < 2; i++) {
		MC_LOG("Reading registers of bank %d\n", bank);
		/* patrol registers */
		mc_read_ptrl_reg(mcp, bank, &flt_stat[i]);

		/*
		 * In mirror mode, it is possible that only one bank
		 * may report the error. We need to check for it to
		 * ensure we pick the right addr value for patrol restart.
		 * Note that if both banks reported errors, we pick the
		 * 2nd one. Both banks should reported the same error address.
		 */
		if (flt_stat[i].mf_cntl & MAC_CNTL_PTRL_ERRS)
			rsaddr->mi_restartaddr = flt_stat[i].mf_flt_maddr;

		MC_LOG("ptrl registers cntl %x add %x log %x\n",
		    flt_stat[i].mf_cntl, flt_stat[i].mf_err_add,
		    flt_stat[i].mf_err_log);

		/* MI registers */
		mc_read_mi_reg(mcp, bank, &mi_flt_stat[i]);

		MC_LOG("MI registers cntl %x add %x log %x\n",
		    mi_flt_stat[i].mf_cntl, mi_flt_stat[i].mf_err_add,
		    mi_flt_stat[i].mf_err_log);

		bank = bank^1;
	}

	/* clear errors once we read all the registers */
	MAC_CLEAR_ERRS(mcp, bank, (MAC_CNTL_PTRL_ERRS|MAC_CNTL_MI_ERRS));

	MAC_CLEAR_ERRS(mcp, bank ^ 1, (MAC_CNTL_PTRL_ERRS|MAC_CNTL_MI_ERRS));

	/* Process MI errors first */

	/* if not error mode, cntl1 is 0 */
	if ((mi_flt_stat[0].mf_err_add & MAC_ERR_ADD_INVALID) ||
	    (mi_flt_stat[0].mf_err_log & MAC_ERR_LOG_INVALID))
		mi_flt_stat[0].mf_cntl = 0;

	if ((mi_flt_stat[1].mf_err_add & MAC_ERR_ADD_INVALID) ||
	    (mi_flt_stat[1].mf_err_log & MAC_ERR_LOG_INVALID))
		mi_flt_stat[1].mf_cntl = 0;

	mc_aflt.mflt_is_ptrl = 0;
	mi_valid = mc_process_error_mir(mcp, &mc_aflt, &mi_flt_stat[0]);

	if ((((flt_stat[0].mf_cntl & MAC_CNTL_PTRL_ERRS) >>
	    MAC_CNTL_PTRL_ERR_SHIFT) == ((mi_flt_stat[0].mf_cntl &
	    MAC_CNTL_MI_ERRS) >> MAC_CNTL_MI_ERR_SHIFT)) &&
	    (flt_stat[0].mf_err_add ==
	    ROUNDDOWN(mi_flt_stat[0].mf_err_add, MC_BOUND_BYTE)) &&
	    (((flt_stat[1].mf_cntl & MAC_CNTL_PTRL_ERRS) >>
	    MAC_CNTL_PTRL_ERR_SHIFT) == ((mi_flt_stat[1].mf_cntl &
	    MAC_CNTL_MI_ERRS) >> MAC_CNTL_MI_ERR_SHIFT)) &&
	    (flt_stat[1].mf_err_add ==
	    ROUNDDOWN(mi_flt_stat[1].mf_err_add, MC_BOUND_BYTE))) {
#ifdef DEBUG
		MC_LOG("discarding PTRL error because "
		    "it is the same as MI\n");
#endif
		rsaddr->mi_valid = mi_valid;
		return;
	}
	/* if not error mode, cntl1 is 0 */
	if ((flt_stat[0].mf_err_add & MAC_ERR_ADD_INVALID) ||
	    (flt_stat[0].mf_err_log & MAC_ERR_LOG_INVALID))
		flt_stat[0].mf_cntl = 0;

	if ((flt_stat[1].mf_err_add & MAC_ERR_ADD_INVALID) ||
	    (flt_stat[1].mf_err_log & MAC_ERR_LOG_INVALID))
		flt_stat[1].mf_cntl = 0;

	mc_aflt.mflt_is_ptrl = 1;
	rsaddr->mi_valid = mc_process_error_mir(mcp, &mc_aflt, &flt_stat[0]);
}
static int
mc_process_error(mc_opl_t *mcp, int bank, mc_aflt_t *mc_aflt,
    mc_flt_stat_t *flt_stat)
{
	int ptrl_error = mc_aflt->mflt_is_ptrl;
	int rv = 0;

	mc_aflt->mflt_erpt_class = NULL;
	if (IS_UE(flt_stat->mf_cntl, ptrl_error)) {
		MC_LOG("UE detected\n");
		flt_stat->mf_type = FLT_TYPE_UE;
		mc_aflt->mflt_erpt_class = MC_OPL_UE;
		mc_aflt->mflt_pr = PR_UE;
		MAC_SET_ERRLOG_INFO(flt_stat);
		rv = 1;
	} else if (IS_CE(flt_stat->mf_cntl, ptrl_error)) {
		MC_LOG("CE detected\n");
		MAC_SET_ERRLOG_INFO(flt_stat);

		/* Error type can change after scrubbing */
		mc_scrub_ce(mcp, bank, flt_stat, ptrl_error);
		if (MC_REWRITE_ACTIVE(mcp, bank)) {
			return (0);
		}

		if (flt_stat->mf_type == FLT_TYPE_INTERMITTENT_CE) {
			mc_aflt->mflt_erpt_class = MC_OPL_ICE;
			mc_aflt->mflt_pr = PR_MCE;
		} else if (flt_stat->mf_type == FLT_TYPE_PERMANENT_CE) {
			mc_aflt->mflt_erpt_class = MC_OPL_CE;
			mc_aflt->mflt_pr = PR_MCE;
		} else if (flt_stat->mf_type == FLT_TYPE_UE) {
			mc_aflt->mflt_erpt_class = MC_OPL_UE;
			mc_aflt->mflt_pr = PR_UE;
		}
		rv = 1;
	}
	MC_LOG("mc_process_error: fault type %x erpt %s\n", flt_stat->mf_type,
	    mc_aflt->mflt_erpt_class);
	if (mc_aflt->mflt_erpt_class) {
		mc_aflt->mflt_stat[0] = flt_stat;
		mc_aflt->mflt_nflts = 1;
		mc_err_drain(mc_aflt);
	}
	return (rv);
}

static void
mc_error_handler(mc_opl_t *mcp, int bank, mc_rsaddr_info_t *rsaddr)
{
	mc_aflt_t mc_aflt;
	mc_flt_stat_t flt_stat, mi_flt_stat;
	int mi_valid;

	bzero(&mc_aflt, sizeof (mc_aflt_t));
	bzero(&flt_stat, sizeof (mc_flt_stat_t));
	bzero(&mi_flt_stat, sizeof (mc_flt_stat_t));

	mc_aflt.mflt_mcp = mcp;
	mc_aflt.mflt_id = gethrtime();

	/* patrol registers */
	mc_read_ptrl_reg(mcp, bank, &flt_stat);

	ASSERT(rsaddr);
	rsaddr->mi_restartaddr = flt_stat.mf_flt_maddr;

	MC_LOG("ptrl registers cntl %x add %x log %x\n", flt_stat.mf_cntl,
	    flt_stat.mf_err_add, flt_stat.mf_err_log);

	/* MI registers */
	mc_read_mi_reg(mcp, bank, &mi_flt_stat);


	MC_LOG("MI registers cntl %x add %x log %x\n", mi_flt_stat.mf_cntl,
	    mi_flt_stat.mf_err_add, mi_flt_stat.mf_err_log);

	/* clear errors once we read all the registers */
	MAC_CLEAR_ERRS(mcp, bank, (MAC_CNTL_PTRL_ERRS|MAC_CNTL_MI_ERRS));

	mc_aflt.mflt_is_ptrl = 0;
	if ((mi_flt_stat.mf_cntl & MAC_CNTL_MI_ERRS) &&
	    ((mi_flt_stat.mf_err_add & MAC_ERR_ADD_INVALID) == 0) &&
	    ((mi_flt_stat.mf_err_log & MAC_ERR_LOG_INVALID) == 0)) {
		mi_valid = mc_process_error(mcp, bank, &mc_aflt, &mi_flt_stat);
	}

	if ((((flt_stat.mf_cntl & MAC_CNTL_PTRL_ERRS) >>
	    MAC_CNTL_PTRL_ERR_SHIFT) == ((mi_flt_stat.mf_cntl &
	    MAC_CNTL_MI_ERRS) >> MAC_CNTL_MI_ERR_SHIFT)) &&
	    (flt_stat.mf_err_add ==
	    ROUNDDOWN(mi_flt_stat.mf_err_add, MC_BOUND_BYTE))) {
#ifdef DEBUG
		MC_LOG("discarding PTRL error because "
		    "it is the same as MI\n");
#endif
		rsaddr->mi_valid = mi_valid;
		return;
	}

	mc_aflt.mflt_is_ptrl = 1;
	if ((flt_stat.mf_cntl & MAC_CNTL_PTRL_ERRS) &&
	    ((flt_stat.mf_err_add & MAC_ERR_ADD_INVALID) == 0) &&
	    ((flt_stat.mf_err_log & MAC_ERR_LOG_INVALID) == 0)) {
		rsaddr->mi_valid = mc_process_error(mcp, bank, &mc_aflt,
		    &flt_stat);
	}
}
/*
 *	memory patrol error handling algorithm:
 *	timeout() is used to do periodic polling
 *	This is the flow chart.
 *	timeout ->
 *	mc_check_errors()
 *	    if memory bank is installed, read the status register
 *	    if any error bit is set,
 *	    -> mc_error_handler()
 *		-> read all error registers
 *	        -> mc_process_error()
 *	            determine error type
 *	            rewrite to clear error or scrub to determine CE type
 *	            inform SCF on permanent CE
 *	        -> mc_err_drain
 *	            page offline processing
 *	            -> mc_ereport_post()
 */

static void
mc_process_rewrite(mc_opl_t *mcp, int bank)
{
	uint32_t rew_addr, cntl;
	mc_retry_info_t *retry;
	struct mc_bank *bankp;

	bankp = &(mcp->mc_bank[bank]);
	retry = bankp->mcb_active;
	if (retry == NULL)
		return;

	if (retry->ri_state <= RETRY_STATE_ACTIVE) {
		cntl = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank));
		if (cntl & MAC_CNTL_PTRL_STATUS)
			return;
		rew_addr = retry->ri_addr;
		ST_MAC_REG(MAC_REWRITE_ADD(mcp, bank), rew_addr);
		MAC_REW_REQ(mcp, bank);

		retry->ri_state = RETRY_STATE_REWRITE;
	}

	cntl = ldphysio(MAC_PTRL_CNTL(mcp, bank));

	if (cntl & MAC_CNTL_REW_END) {
		MAC_CLEAR_ERRS(mcp, bank,
		    MAC_CNTL_REW_ERRS);
		mc_clear_rewrite(mcp, bank);
	} else {
		/*
		 * If the rewrite does not complete in
		 * 1 hour, we have to consider this a HW
		 * failure.  However, there is no recovery
		 * mechanism.  The only thing we can do
		 * to to print a warning message to the
		 * console.  We continue to increment the
		 * counter but we only print the message
		 * once.  It will take the counter a long
		 * time to wrap around and the user might
		 * see a second message.  In practice,
		 * we have never hit this condition but
		 * we have to keep the code here just in case.
		 */
		if (++mcp->mc_bank[bank].mcb_rewrite_count
		    == mc_max_rewrite_retry) {
			cmn_err(CE_WARN, "Memory patrol feature is"
			" partly suspended on /LSB%d/B%d"
			" due to heavy memory load,"
			" and it will restart"
			" automatically.\n", mcp->mc_board_num,
			    bank);
		}
	}
}

static void
mc_check_errors_func(mc_opl_t *mcp)
{
	mc_rsaddr_info_t rsaddr_info;
	int i, error_count = 0;
	uint32_t stat, cntl;
	int running;
	int wrapped;
	int ebk;

	/*
	 * scan errors.
	 */
	if (mcp->mc_status & MC_MEMORYLESS)
		return;

	for (i = 0; i < BANKNUM_PER_SB; i++) {
		if (mcp->mc_bank[i].mcb_status & BANK_INSTALLED) {
			if (MC_REWRITE_ACTIVE(mcp, i)) {
				mc_process_rewrite(mcp, i);
			}
			stat = ldphysio(MAC_PTRL_STAT(mcp, i));
			cntl = ldphysio(MAC_PTRL_CNTL(mcp, i));
			running = cntl & MAC_CNTL_PTRL_START;
			wrapped = cntl & MAC_CNTL_PTRL_ADD_MAX;

			/* Compute the effective bank idx */
			ebk = (IS_MIRROR(mcp, i)) ? MIRROR_IDX(i) : i;

			if (mc_debug_show_all || stat) {
				MC_LOG("/LSB%d/B%d stat %x cntl %x\n",
				    mcp->mc_board_num, i, stat, cntl);
			}

			/*
			 * Update stats and reset flag if the HW patrol
			 * wrapped around in its scan.
			 */
			if (wrapped) {
				MAC_CLEAR_MAX(mcp, i);
				mcp->mc_period[ebk]++;
				if (IS_MIRROR(mcp, i)) {
					MC_LOG("mirror mc period %ld on "
					    "/LSB%d/B%d\n", mcp->mc_period[ebk],
					    mcp->mc_board_num, i);
				} else {
					MC_LOG("mc period %ld on "
					    "/LSB%d/B%d\n", mcp->mc_period[ebk],
					    mcp->mc_board_num, i);
				}
			}

			if (running) {
				/*
				 * Mac patrol HW is still running.
				 * Normally when an error is detected,
				 * the HW patrol will stop so that we
				 * can collect error data for reporting.
				 * Certain errors (MI errors) detected may not
				 * cause the HW patrol to stop which is a
				 * problem since we cannot read error data while
				 * the HW patrol is running. SW is not allowed
				 * to stop the HW patrol while it is running
				 * as it may cause HW inconsistency. This is
				 * described in a HW errata.
				 * In situations where we detected errors
				 * that may not cause the HW patrol to stop.
				 * We speed up the HW patrol scanning in
				 * the hope that it will find the 'real' PTRL
				 * errors associated with the previous errors
				 * causing the HW to finally stop so that we
				 * can do the reporting.
				 */
				/*
				 * Check to see if we did speed up
				 * the HW patrol due to previous errors
				 * detected that did not cause the patrol
				 * to stop. We only do it if HW patrol scan
				 * wrapped (counted as completing a 'period').
				 */
				if (mcp->mc_speedup_period[ebk] > 0) {
					if (wrapped &&
					    (--mcp->mc_speedup_period[ebk] ==
					    0)) {
						/*
						 * We did try to speed up.
						 * The speed up period has
						 * expired and the HW patrol
						 * is still running.  The
						 * errors must be intermittent.
						 * We have no choice but to
						 * ignore them, reset the scan
						 * speed to normal and clear
						 * the MI error bits. For
						 * mirror mode, we need to
						 * clear errors on both banks.
						 */
						MC_LOG("Clearing MI errors\n");
						MAC_CLEAR_ERRS(mcp, i,
						    MAC_CNTL_MI_ERRS);

						if (IS_MIRROR(mcp, i)) {
							MC_LOG("Clearing "
							    "Mirror MI errs\n");
							MAC_CLEAR_ERRS(mcp,
							    i^1,
							    MAC_CNTL_MI_ERRS);
						}
					}
				} else if (stat & MAC_STAT_MI_ERRS) {
					/*
					 * MI errors detected but we cannot
					 * report them since the HW patrol
					 * is still running.
					 * We will attempt to speed up the
					 * scanning and hopefully the HW
					 * can detect PRTL errors at the same
					 * location that cause the HW patrol
					 * to stop.
					 */
					mcp->mc_speedup_period[ebk] = 2;
					MAC_CMD(mcp, i, 0);
				}
			} else if (stat & (MAC_STAT_PTRL_ERRS |
			    MAC_STAT_MI_ERRS)) {
				/*
				 * HW Patrol has stopped and we found errors.
				 * Proceed to collect and report error info.
				 */
				mcp->mc_speedup_period[ebk] = 0;
				rsaddr_info.mi_valid = 0;
				rsaddr_info.mi_injectrestart = 0;
				if (IS_MIRROR(mcp, i)) {
					mc_error_handler_mir(mcp, i,
					    &rsaddr_info);
				} else {
					mc_error_handler(mcp, i, &rsaddr_info);
				}

				error_count++;
				(void) restart_patrol(mcp, i, &rsaddr_info);
			} else {
				/*
				 * HW patrol scan has apparently stopped
				 * but no errors detected/flagged.
				 * Restart the HW patrol just to be sure.
				 * In mirror mode, the odd bank might have
				 * reported errors that caused the patrol to
				 * stop. We'll defer the restart to the odd
				 * bank in this case.
				 */
				if (!IS_MIRROR(mcp, i) || (i & 0x1))
					(void) restart_patrol(mcp, i, NULL);
			}
		}
	}
	if (error_count > 0)
		mcp->mc_last_error += error_count;
	else
		mcp->mc_last_error = 0;
}

/*
 * mc_polling -- Check errors for only one instance,
 * but process errors for all instances to make sure we drain the errors
 * faster than they can be accumulated.
 *
 * Polling on each board should be done only once per each
 * mc_patrol_interval_sec.  This is equivalent to setting mc_tick_left
 * to OPL_MAX_BOARDS and decrement by 1 on each timeout.
 * Once mc_tick_left becomes negative, the board becomes a candidate
 * for polling because it has waited for at least
 * mc_patrol_interval_sec's long.    If mc_timeout_period is calculated
 * differently, this has to be updated accordingly.
 */

static void
mc_polling(void)
{
	int i, scan_error;
	mc_opl_t *mcp;


	scan_error = 1;
	for (i = 0; i < OPL_MAX_BOARDS; i++) {
		mutex_enter(&mcmutex);
		if ((mcp = mc_instances[i]) == NULL) {
			mutex_exit(&mcmutex);
			continue;
		}
		mutex_enter(&mcp->mc_lock);
		mutex_exit(&mcmutex);
		if (!(mcp->mc_status & MC_POLL_RUNNING)) {
			mutex_exit(&mcp->mc_lock);
			continue;
		}
		if (scan_error && mcp->mc_tick_left <= 0) {
			mc_check_errors_func((void *)mcp);
			mcp->mc_tick_left = OPL_MAX_BOARDS;
			scan_error = 0;
		} else {
			mcp->mc_tick_left--;
		}
		mc_process_scf_log(mcp);
		mutex_exit(&mcp->mc_lock);
	}
}

static void
get_ptrl_start_address(mc_opl_t *mcp, int bank, mc_addr_t *maddr)
{
	maddr->ma_bd = mcp->mc_board_num;
	maddr->ma_bank = bank;
	maddr->ma_dimm_addr = 0;
}

typedef struct mc_mem_range {
	uint64_t	addr;
	uint64_t	size;
} mc_mem_range_t;

static int
get_base_address(mc_opl_t *mcp)
{
	mc_mem_range_t *mem_range;
	int len;

	if (ddi_getlongprop(DDI_DEV_T_ANY, mcp->mc_dip, DDI_PROP_DONTPASS,
	    "sb-mem-ranges", (caddr_t)&mem_range, &len) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	mcp->mc_start_address = mem_range->addr;
	mcp->mc_size = mem_range->size;

	kmem_free(mem_range, len);
	return (DDI_SUCCESS);
}

struct mc_addr_spec {
	uint32_t bank;
	uint32_t phys_hi;
	uint32_t phys_lo;
};

#define	REGS_PA(m, i) ((((uint64_t)m[i].phys_hi)<<32) | m[i].phys_lo)

static char *mc_tbl_name[] = {
	"cs0-mc-pa-trans-table",
	"cs1-mc-pa-trans-table"
};

/*
 * This routine performs a rangecheck for a given PA
 * to see if it belongs to the memory range for this board.
 * Return 1 if it is valid (within the range) and 0 otherwise
 */
static int
mc_rangecheck_pa(mc_opl_t *mcp, uint64_t pa)
{
	if ((pa < mcp->mc_start_address) || (mcp->mc_start_address +
	    mcp->mc_size <= pa))
		return (0);
	else
		return (1);
}

static void
mc_memlist_delete(struct memlist *mlist)
{
	struct memlist *ml;

	for (ml = mlist; ml; ml = mlist) {
		mlist = ml->ml_next;
		kmem_free(ml, sizeof (struct memlist));
	}
}

static struct memlist *
mc_memlist_dup(struct memlist *mlist)
{
	struct memlist *hl = NULL, *tl, **mlp;

	if (mlist == NULL)
		return (NULL);

	mlp = &hl;
	tl = *mlp;
	for (; mlist; mlist = mlist->ml_next) {
		*mlp = kmem_alloc(sizeof (struct memlist), KM_SLEEP);
		(*mlp)->ml_address = mlist->ml_address;
		(*mlp)->ml_size = mlist->ml_size;
		(*mlp)->ml_prev = tl;
		tl = *mlp;
		mlp = &((*mlp)->ml_next);
	}
	*mlp = NULL;

	return (hl);
}


static struct memlist *
mc_memlist_del_span(struct memlist *mlist, uint64_t base, uint64_t len)
{
	uint64_t	end;
	struct memlist	*ml, *tl, *nlp;

	if (mlist == NULL)
		return (NULL);

	end = base + len;
	if ((end <= mlist->ml_address) || (base == end))
		return (mlist);

	for (tl = ml = mlist; ml; tl = ml, ml = nlp) {
		uint64_t	mend;

		nlp = ml->ml_next;

		if (end <= ml->ml_address)
			break;

		mend = ml->ml_address + ml->ml_size;
		if (base < mend) {
			if (base <= ml->ml_address) {
				ml->ml_address = end;
				if (end >= mend)
					ml->ml_size = 0ull;
				else
					ml->ml_size = mend - ml->ml_address;
			} else {
				ml->ml_size = base - ml->ml_address;
				if (end < mend) {
					struct memlist	*nl;
					/*
					 * splitting an memlist entry.
					 */
					nl = kmem_alloc(sizeof (struct memlist),
					    KM_SLEEP);
					nl->ml_address = end;
					nl->ml_size = mend - nl->ml_address;
					if ((nl->ml_next = nlp) != NULL)
						nlp->ml_prev = nl;
					nl->ml_prev = ml;
					ml->ml_next = nl;
					nlp = nl;
				}
			}
			if (ml->ml_size == 0ull) {
				if (ml == mlist) {
					if ((mlist = nlp) != NULL)
						nlp->ml_prev = NULL;
					kmem_free(ml, sizeof (struct memlist));
					if (mlist == NULL)
						break;
					ml = nlp;
				} else {
					if ((tl->ml_next = nlp) != NULL)
						nlp->ml_prev = tl;
					kmem_free(ml, sizeof (struct memlist));
					ml = tl;
				}
			}
		}
	}

	return (mlist);
}

static void
mc_get_mlist(mc_opl_t *mcp)
{
	struct memlist *mlist;

	memlist_read_lock();
	mlist = mc_memlist_dup(phys_install);
	memlist_read_unlock();

	if (mlist) {
		mlist = mc_memlist_del_span(mlist, 0ull, mcp->mc_start_address);
	}

	if (mlist) {
		uint64_t startpa, endpa;

		startpa = mcp->mc_start_address + mcp->mc_size;
		endpa = ptob(physmax + 1);
		if (endpa > startpa) {
			mlist = mc_memlist_del_span(mlist, startpa,
			    endpa - startpa);
		}
	}

	if (mlist) {
		mcp->mlist = mlist;
	}
}

int
mc_board_add(mc_opl_t *mcp)
{
	struct mc_addr_spec *macaddr;
	cs_status_t *cs_status;
	int len, len1, i, bk, cc;
	mc_rsaddr_info_t rsaddr;
	uint32_t mirr;
	int nbanks = 0;
	uint64_t nbytes = 0;
	int mirror_mode = 0;
	int ret;

	/*
	 * Get configurations from "pseudo-mc" node which includes:
	 * board# : LSB number
	 * mac-addr : physical base address of MAC registers
	 * csX-mac-pa-trans-table: translation table from DIMM address
	 *			to physical address or vice versa.
	 */
	mcp->mc_board_num = (int)ddi_getprop(DDI_DEV_T_ANY, mcp->mc_dip,
	    DDI_PROP_DONTPASS, "board#", -1);

	if (mcp->mc_board_num == -1) {
		return (DDI_FAILURE);
	}

	/*
	 * Get start address in this CAB. It can be gotten from
	 * "sb-mem-ranges" property.
	 */

	if (get_base_address(mcp) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}
	/* get mac-pa trans tables */
	for (i = 0; i < MC_TT_CS; i++) {
		len = MC_TT_ENTRIES;
		cc = ddi_getlongprop_buf(DDI_DEV_T_ANY, mcp->mc_dip,
		    DDI_PROP_DONTPASS, mc_tbl_name[i],
		    (caddr_t)mcp->mc_trans_table[i], &len);

		if (cc != DDI_SUCCESS) {
			bzero(mcp->mc_trans_table[i], MC_TT_ENTRIES);
		}
	}
	mcp->mlist = NULL;

	mc_get_mlist(mcp);

	/* initialize bank informations */
	cc = ddi_getlongprop(DDI_DEV_T_ANY, mcp->mc_dip, DDI_PROP_DONTPASS,
	    "mc-addr", (caddr_t)&macaddr, &len);
	if (cc != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Cannot get mc-addr. err=%d\n", cc);
		return (DDI_FAILURE);
	}

	cc = ddi_getlongprop(DDI_DEV_T_ANY, mcp->mc_dip, DDI_PROP_DONTPASS,
	    "cs-status", (caddr_t)&cs_status, &len1);

	if (cc != DDI_SUCCESS) {
		if (len > 0)
			kmem_free(macaddr, len);
		cmn_err(CE_WARN, "Cannot get cs-status. err=%d\n", cc);
		return (DDI_FAILURE);
	}
	/* get the physical board number for a given logical board number */
	mcp->mc_phys_board_num = mc_opl_get_physical_board(mcp->mc_board_num);

	if (mcp->mc_phys_board_num < 0) {
		if (len > 0)
			kmem_free(macaddr, len);
		cmn_err(CE_WARN, "Unable to obtain the physical board number");
		return (DDI_FAILURE);
	}

	mutex_init(&mcp->mc_lock, NULL, MUTEX_DRIVER, NULL);

	for (i = 0; i < len1 / sizeof (cs_status_t); i++) {
		nbytes += ((uint64_t)cs_status[i].cs_avail_hi << 32) |
		    ((uint64_t)cs_status[i].cs_avail_low);
	}
	if (len1 > 0)
		kmem_free(cs_status, len1);
	nbanks = len / sizeof (struct mc_addr_spec);

	if (nbanks > 0)
		nbytes /= nbanks;
	else {
		/* No need to free macaddr because len must be 0 */
		mcp->mc_status |= MC_MEMORYLESS;
		return (DDI_SUCCESS);
	}

	for (i = 0; i < BANKNUM_PER_SB; i++) {
		mcp->mc_scf_retry[i] = 0;
		mcp->mc_period[i] = 0;
		mcp->mc_speedup_period[i] = 0;
	}

	/*
	 * Get the memory size here. Let it be B (bytes).
	 * Let T be the time in u.s. to scan 64 bytes.
	 * If we want to complete 1 round of scanning in P seconds.
	 *
	 *	B * T * 10^(-6)	= P
	 *	---------------
	 *		64
	 *
	 *	T = P * 64 * 10^6
	 *	    -------------
	 *		B
	 *
	 *	  = P * 64 * 10^6
	 *	    -------------
	 *		B
	 *
	 *	The timing bits are set in PTRL_CNTL[28:26] where
	 *
	 *	0	- 1 m.s
	 *	1	- 512 u.s.
	 *	10	- 256 u.s.
	 *	11	- 128 u.s.
	 *	100	- 64 u.s.
	 *	101	- 32 u.s.
	 *	110	- 0 u.s.
	 *	111	- reserved.
	 *
	 *
	 *	a[0] = 110, a[1] = 101, ... a[6] = 0
	 *
	 *	cs-status property is int x 7
	 *	0 - cs#
	 *	1 - cs-status
	 *	2 - cs-avail.hi
	 *	3 - cs-avail.lo
	 *	4 - dimm-capa.hi
	 *	5 - dimm-capa.lo
	 *	6 - #of dimms
	 */

	if (nbytes > 0) {
		int i;
		uint64_t ms;
		ms = ((uint64_t)mc_scan_period * 64 * 1000000)/nbytes;
		mcp->mc_speed = mc_scan_speeds[MC_MAX_SPEEDS - 1].mc_speeds;
		for (i = 0; i < MC_MAX_SPEEDS - 1; i++) {
			if (ms < mc_scan_speeds[i + 1].mc_period) {
				mcp->mc_speed = mc_scan_speeds[i].mc_speeds;
				break;
			}
		}
	} else
		mcp->mc_speed = 0;


	for (i = 0; i < len / sizeof (struct mc_addr_spec); i++) {
		struct mc_bank *bankp;
		mc_retry_info_t *retry;
		uint32_t reg;
		int k;

		/*
		 * setup bank
		 */
		bk = macaddr[i].bank;
		bankp = &(mcp->mc_bank[bk]);
		bankp->mcb_status = BANK_INSTALLED;
		bankp->mcb_reg_base = REGS_PA(macaddr, i);

		bankp->mcb_retry_freelist = NULL;
		bankp->mcb_retry_pending = NULL;
		bankp->mcb_active = NULL;
		retry = &bankp->mcb_retry_infos[0];
		for (k = 0; k < MC_RETRY_COUNT; k++, retry++) {
			mc_retry_info_put(&bankp->mcb_retry_freelist, retry);
		}

		reg = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bk));
		bankp->mcb_ptrl_cntl = (reg & MAC_CNTL_PTRL_PRESERVE_BITS);

		/*
		 * check if mirror mode
		 */
		mirr = LD_MAC_REG(MAC_MIRR(mcp, bk));

		if (mirr & MAC_MIRR_MIRROR_MODE) {
			MC_LOG("Mirror -> /LSB%d/B%d\n", mcp->mc_board_num,
			    bk);
			bankp->mcb_status |= BANK_MIRROR_MODE;
			mirror_mode = 1;
			/*
			 * The following bit is only used for
			 * error injection.  We should clear it
			 */
			if (mirr & MAC_MIRR_BANK_EXCLUSIVE)
				ST_MAC_REG(MAC_MIRR(mcp, bk), 0);
		}

		/*
		 * restart if not mirror mode or the other bank
		 * of the mirror is not running
		 */
		if (!(mirr & MAC_MIRR_MIRROR_MODE) ||
		    !(mcp->mc_bank[bk^1].mcb_status & BANK_PTRL_RUNNING)) {
			MC_LOG("Starting up /LSB%d/B%d\n", mcp->mc_board_num,
			    bk);
			get_ptrl_start_address(mcp, bk, &rsaddr.mi_restartaddr);
			rsaddr.mi_valid = 0;
			rsaddr.mi_injectrestart = 0;
			(void) restart_patrol(mcp, bk, &rsaddr);
		} else {
			MC_LOG("Not starting up /LSB%d/B%d\n",
			    mcp->mc_board_num, bk);
		}
		bankp->mcb_status |= BANK_PTRL_RUNNING;
	}
	if (len > 0)
		kmem_free(macaddr, len);

	ret = ndi_prop_update_int(DDI_DEV_T_NONE, mcp->mc_dip, "mirror-mode",
	    mirror_mode);
	if (ret != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "Unable to update mirror-mode property");
	}

	mcp->mc_dimm_list = mc_get_dimm_list(mcp);

	/*
	 * set interval in HZ.
	 */
	mcp->mc_last_error = 0;

	/* restart memory patrol checking */
	mcp->mc_status |= MC_POLL_RUNNING;

	return (DDI_SUCCESS);
}

int
mc_board_del(mc_opl_t *mcp)
{
	int i;
	scf_log_t *p;

	/*
	 * cleanup mac state
	 */
	mutex_enter(&mcp->mc_lock);
	if (mcp->mc_status & MC_MEMORYLESS) {
		mutex_exit(&mcp->mc_lock);
		mutex_destroy(&mcp->mc_lock);
		return (DDI_SUCCESS);
	}
	for (i = 0; i < BANKNUM_PER_SB; i++) {
		if (mcp->mc_bank[i].mcb_status & BANK_INSTALLED) {
			mcp->mc_bank[i].mcb_status &= ~BANK_INSTALLED;
		}
	}

	/* stop memory patrol checking */
	mcp->mc_status &= ~MC_POLL_RUNNING;

	/* just throw away all the scf logs */
	for (i = 0; i < BANKNUM_PER_SB; i++) {
		while ((p = mcp->mc_scf_log[i]) != NULL) {
			mcp->mc_scf_log[i] = p->sl_next;
			mcp->mc_scf_total[i]--;
			kmem_free(p, sizeof (scf_log_t));
		}
	}

	if (mcp->mlist)
		mc_memlist_delete(mcp->mlist);

	if (mcp->mc_dimm_list)
		mc_free_dimm_list(mcp->mc_dimm_list);

	mutex_exit(&mcp->mc_lock);

	mutex_destroy(&mcp->mc_lock);
	return (DDI_SUCCESS);
}

int
mc_suspend(mc_opl_t *mcp, uint32_t flag)
{
	/* stop memory patrol checking */
	mutex_enter(&mcp->mc_lock);
	if (mcp->mc_status & MC_MEMORYLESS) {
		mutex_exit(&mcp->mc_lock);
		return (DDI_SUCCESS);
	}

	mcp->mc_status &= ~MC_POLL_RUNNING;

	mcp->mc_status |= flag;
	mutex_exit(&mcp->mc_lock);

	return (DDI_SUCCESS);
}

void
opl_mc_update_mlist(void)
{
	int i;
	mc_opl_t *mcp;

	/*
	 * memory information is not updated until
	 * the post attach/detach stage during DR.
	 * This interface is used by dr_mem to inform
	 * mc-opl to update the mlist.
	 */

	mutex_enter(&mcmutex);
	for (i = 0; i < OPL_MAX_BOARDS; i++) {
		if ((mcp = mc_instances[i]) == NULL)
			continue;
		mutex_enter(&mcp->mc_lock);
		if (mcp->mlist)
			mc_memlist_delete(mcp->mlist);
		mcp->mlist = NULL;
		mc_get_mlist(mcp);
		mutex_exit(&mcp->mc_lock);
	}
	mutex_exit(&mcmutex);
}

/* caller must clear the SUSPEND bits or this will do nothing */

int
mc_resume(mc_opl_t *mcp, uint32_t flag)
{
	int i;
	uint64_t basepa;

	mutex_enter(&mcp->mc_lock);
	if (mcp->mc_status & MC_MEMORYLESS) {
		mutex_exit(&mcp->mc_lock);
		return (DDI_SUCCESS);
	}
	basepa = mcp->mc_start_address;
	if (get_base_address(mcp) == DDI_FAILURE) {
		mutex_exit(&mcp->mc_lock);
		return (DDI_FAILURE);
	}

	if (basepa != mcp->mc_start_address) {
		if (mcp->mlist)
			mc_memlist_delete(mcp->mlist);
		mcp->mlist = NULL;
		mc_get_mlist(mcp);
	}

	mcp->mc_status &= ~flag;

	if (mcp->mc_status & (MC_SOFT_SUSPENDED | MC_DRIVER_SUSPENDED)) {
		mutex_exit(&mcp->mc_lock);
		return (DDI_SUCCESS);
	}

	if (!(mcp->mc_status & MC_POLL_RUNNING)) {
		/* restart memory patrol checking */
		mcp->mc_status |= MC_POLL_RUNNING;
		for (i = 0; i < BANKNUM_PER_SB; i++) {
			if (mcp->mc_bank[i].mcb_status & BANK_INSTALLED) {
				mc_check_errors_func(mcp);
			}
		}
	}
	mutex_exit(&mcp->mc_lock);

	return (DDI_SUCCESS);
}

static mc_opl_t *
mc_pa_to_mcp(uint64_t pa)
{
	mc_opl_t *mcp;
	int i;

	ASSERT(MUTEX_HELD(&mcmutex));
	for (i = 0; i < OPL_MAX_BOARDS; i++) {
		if ((mcp = mc_instances[i]) == NULL)
			continue;
		/* if mac patrol is suspended, we cannot rely on it */
		if (!(mcp->mc_status & MC_POLL_RUNNING) ||
		    (mcp->mc_status & MC_SOFT_SUSPENDED))
			continue;
		if (mc_rangecheck_pa(mcp, pa)) {
			return (mcp);
		}
	}
	return (NULL);
}

/*
 * Get Physical Board number from Logical one.
 */
static int
mc_opl_get_physical_board(int sb)
{
	if (&opl_get_physical_board) {
		return (opl_get_physical_board(sb));
	}

	cmn_err(CE_NOTE, "!opl_get_physical_board() not loaded\n");
	return (-1);
}

/* ARGSUSED */
int
mc_get_mem_unum(int synd_code, uint64_t flt_addr, char *buf, int buflen,
    int *lenp)
{
	int i;
	int j;
	int sb;
	int bank;
	int cs;
	int rv = 0;
	mc_opl_t *mcp;
	char memb_num;

	mutex_enter(&mcmutex);

	if (((mcp = mc_pa_to_mcp(flt_addr)) == NULL) ||
	    (!pa_is_valid(mcp, flt_addr))) {
		mutex_exit(&mcmutex);
		if (snprintf(buf, buflen, "UNKNOWN") >= buflen) {
			return (ENOSPC);
		} else {
			if (lenp)
				*lenp = strlen(buf);
		}
		return (0);
	}

	bank = pa_to_bank(mcp, flt_addr - mcp->mc_start_address);
	sb = mcp->mc_phys_board_num;
	cs = pa_to_cs(mcp, flt_addr - mcp->mc_start_address);

	if (sb == -1) {
		mutex_exit(&mcmutex);
		return (ENXIO);
	}

	switch (plat_model) {
	case MODEL_DC:
		i = BD_BK_SLOT_TO_INDEX(0, bank, 0);
		j = (cs == 0) ? i : i + 2;
		(void) snprintf(buf, buflen, "/%s%02d/MEM%s MEM%s",
		    model_names[plat_model].unit_name, sb,
		    mc_dc_dimm_unum_table[j],
		    mc_dc_dimm_unum_table[j + 1]);
		break;
	case MODEL_FF2:
	case MODEL_FF1:
		i = BD_BK_SLOT_TO_INDEX(sb, bank, 0);
		j = (cs == 0) ? i : i + 2;
		memb_num = mc_ff_dimm_unum_table[i][0];
		(void) snprintf(buf, buflen, "/%s/%s%c/MEM%s MEM%s",
		    model_names[plat_model].unit_name,
		    model_names[plat_model].mem_name, memb_num,
		    &mc_ff_dimm_unum_table[j][1],
		    &mc_ff_dimm_unum_table[j + 1][1]);
		break;
	case MODEL_IKKAKU:
		i = BD_BK_SLOT_TO_INDEX(sb, bank, 0);
		j = (cs == 0) ? i : i + 2;
		(void) snprintf(buf, buflen, "/%s/MEM%s MEM%s",
		    model_names[plat_model].unit_name,
		    &mc_ff_dimm_unum_table[j][1],
		    &mc_ff_dimm_unum_table[j + 1][1]);
		break;
	default:
		rv = ENXIO;
	}
	if (lenp) {
		*lenp = strlen(buf);
	}
	mutex_exit(&mcmutex);
	return (rv);
}

int
opl_mc_suspend(void)
{
	mc_opl_t *mcp;
	int i;

	mutex_enter(&mcmutex);
	for (i = 0; i < OPL_MAX_BOARDS; i++) {
		if ((mcp = mc_instances[i]) == NULL)
			continue;
		(void) mc_suspend(mcp, MC_SOFT_SUSPENDED);
	}
	mutex_exit(&mcmutex);

	return (0);
}

int
opl_mc_resume(void)
{
	mc_opl_t *mcp;
	int i;

	mutex_enter(&mcmutex);
	for (i = 0; i < OPL_MAX_BOARDS; i++) {
		if ((mcp = mc_instances[i]) == NULL)
			continue;
		(void) mc_resume(mcp, MC_SOFT_SUSPENDED);
	}
	mutex_exit(&mcmutex);

	return (0);
}
static void
insert_mcp(mc_opl_t *mcp)
{
	mutex_enter(&mcmutex);
	if (mc_instances[mcp->mc_board_num] != NULL) {
		MC_LOG("mc-opl instance for board# %d already exists\n",
		    mcp->mc_board_num);
	}
	mc_instances[mcp->mc_board_num] = mcp;
	mutex_exit(&mcmutex);
}

static void
delete_mcp(mc_opl_t *mcp)
{
	mutex_enter(&mcmutex);
	mc_instances[mcp->mc_board_num] = 0;
	mutex_exit(&mcmutex);
}

/* Error injection interface */

static void
mc_lock_va(uint64_t pa, caddr_t new_va)
{
	tte_t tte;

	vtag_flushpage(new_va, (uint64_t)ksfmmup);
	sfmmu_memtte(&tte, pa >> PAGESHIFT, PROC_DATA|HAT_NOSYNC, TTE8K);
	tte.tte_intlo |= TTE_LCK_INT;
	sfmmu_dtlb_ld_kva(new_va, &tte);
}

static void
mc_unlock_va(caddr_t va)
{
	vtag_flushpage(va, (uint64_t)ksfmmup);
}

/* ARGSUSED */
int
mc_inject_error(int error_type, uint64_t pa, uint32_t flags)
{
	mc_opl_t *mcp;
	int bank;
	uint32_t dimm_addr;
	uint32_t cntl;
	mc_rsaddr_info_t rsaddr;
	uint32_t data, stat;
	int both_sides = 0;
	uint64_t pa0;
	int extra_injection_needed = 0;
	extern void cpu_flush_ecache(void);

	MC_LOG("HW mc_inject_error(%x, %lx, %x)\n", error_type, pa, flags);

	mutex_enter(&mcmutex);
	if ((mcp = mc_pa_to_mcp(pa)) == NULL) {
		mutex_exit(&mcmutex);
		MC_LOG("mc_inject_error: invalid pa\n");
		return (ENOTSUP);
	}

	mutex_enter(&mcp->mc_lock);
	mutex_exit(&mcmutex);

	if (mcp->mc_status & (MC_SOFT_SUSPENDED | MC_DRIVER_SUSPENDED)) {
		mutex_exit(&mcp->mc_lock);
		MC_LOG("mc-opl has been suspended.  No error injection.\n");
		return (EBUSY);
	}

	/* convert pa to offset within the board */
	MC_LOG("pa %lx, offset %lx\n", pa, pa - mcp->mc_start_address);

	if (!pa_is_valid(mcp, pa)) {
		mutex_exit(&mcp->mc_lock);
		return (EINVAL);
	}

	pa0 = pa - mcp->mc_start_address;

	bank = pa_to_bank(mcp, pa0);

	if (flags & MC_INJECT_FLAG_OTHER)
		bank = bank ^ 1;

	if (MC_INJECT_MIRROR(error_type) && !IS_MIRROR(mcp, bank)) {
		mutex_exit(&mcp->mc_lock);
		MC_LOG("Not mirror mode\n");
		return (EINVAL);
	}

	dimm_addr = pa_to_dimm(mcp, pa0);

	MC_LOG("injecting error to /LSB%d/B%d/%x\n", mcp->mc_board_num, bank,
	    dimm_addr);


	switch (error_type) {
	case MC_INJECT_INTERMITTENT_MCE:
	case MC_INJECT_PERMANENT_MCE:
	case MC_INJECT_MUE:
		both_sides = 1;
	}

	if (flags & MC_INJECT_FLAG_RESET)
		ST_MAC_REG(MAC_EG_CNTL(mcp, bank), 0);

	ST_MAC_REG(MAC_EG_ADD(mcp, bank), dimm_addr & MAC_EG_ADD_MASK);

	if (both_sides) {
		ST_MAC_REG(MAC_EG_CNTL(mcp, bank^1), 0);
		ST_MAC_REG(MAC_EG_ADD(mcp, bank^1), dimm_addr &
		    MAC_EG_ADD_MASK);
	}

	switch (error_type) {
	case MC_INJECT_SUE:
		extra_injection_needed = 1;
		/*FALLTHROUGH*/
	case MC_INJECT_UE:
	case MC_INJECT_MUE:
		if (flags & MC_INJECT_FLAG_PATH) {
			cntl = MAC_EG_ADD_FIX | MAC_EG_FORCE_READ00 |
			    MAC_EG_FORCE_READ16 | MAC_EG_RDERR_ONCE;
		} else {
			cntl = MAC_EG_ADD_FIX | MAC_EG_FORCE_DERR00 |
			    MAC_EG_FORCE_DERR16 | MAC_EG_DERR_ONCE;
		}
		flags |= MC_INJECT_FLAG_ST;
		break;
	case MC_INJECT_INTERMITTENT_CE:
	case MC_INJECT_INTERMITTENT_MCE:
		if (flags & MC_INJECT_FLAG_PATH) {
			cntl = MAC_EG_ADD_FIX |MAC_EG_FORCE_READ00 |
			    MAC_EG_RDERR_ONCE;
		} else {
			cntl = MAC_EG_ADD_FIX | MAC_EG_FORCE_DERR16 |
			    MAC_EG_DERR_ONCE;
		}
		extra_injection_needed = 1;
		flags |= MC_INJECT_FLAG_ST;
		break;
	case MC_INJECT_PERMANENT_CE:
	case MC_INJECT_PERMANENT_MCE:
		if (flags & MC_INJECT_FLAG_PATH) {
			cntl = MAC_EG_ADD_FIX | MAC_EG_FORCE_READ00 |
			    MAC_EG_RDERR_ALWAYS;
		} else {
			cntl = MAC_EG_ADD_FIX | MAC_EG_FORCE_DERR16 |
			    MAC_EG_DERR_ALWAYS;
		}
		flags |= MC_INJECT_FLAG_ST;
		break;
	case MC_INJECT_CMPE:
		data = 0xabcdefab;
		stphys(pa, data);
		cpu_flush_ecache();
		MC_LOG("CMPE: writing data %x to %lx\n", data, pa);
		ST_MAC_REG(MAC_MIRR(mcp, bank), MAC_MIRR_BANK_EXCLUSIVE);
		stphys(pa, data ^ 0xffffffff);
		membar_sync();
		cpu_flush_ecache();
		ST_MAC_REG(MAC_MIRR(mcp, bank), 0);
		MC_LOG("CMPE: write new data %xto %lx\n", data, pa);
		cntl = 0;
		break;
	case MC_INJECT_NOP:
		cntl = 0;
		break;
	default:
		MC_LOG("mc_inject_error: invalid option\n");
		cntl = 0;
	}

	if (cntl) {
		ST_MAC_REG(MAC_EG_CNTL(mcp, bank), cntl & MAC_EG_SETUP_MASK);
		ST_MAC_REG(MAC_EG_CNTL(mcp, bank), cntl);

		if (both_sides) {
			ST_MAC_REG(MAC_EG_CNTL(mcp, bank^1), cntl &
			    MAC_EG_SETUP_MASK);
			ST_MAC_REG(MAC_EG_CNTL(mcp, bank^1), cntl);
		}
	}

	/*
	 * For all injection cases except compare error, we
	 * must write to the PA to trigger the error.
	 */

	if (flags & MC_INJECT_FLAG_ST) {
		data = 0xf0e0d0c0;
		MC_LOG("Writing %x to %lx\n", data, pa);
		stphys(pa, data);
		cpu_flush_ecache();
	}


	if (flags & MC_INJECT_FLAG_LD) {
		if (flags & MC_INJECT_FLAG_PREFETCH) {
			/*
			 * Use strong prefetch operation to
			 * inject MI errors.
			 */
			page_t *pp;
			extern void mc_prefetch(caddr_t);

			MC_LOG("prefetch\n");

			pp = page_numtopp_nolock(pa >> PAGESHIFT);
			if (pp != NULL) {
				caddr_t	va, va1;

				va = ppmapin(pp, PROT_READ|PROT_WRITE,
				    (caddr_t)-1);
				kpreempt_disable();
				mc_lock_va((uint64_t)pa, va);
				va1 = va + (pa & (PAGESIZE - 1));
				mc_prefetch(va1);
				mc_unlock_va(va);
				kpreempt_enable();
				ppmapout(va);

				/*
				 * For MI errors, we need one extra
				 * injection for HW patrol to stop.
				 */
				extra_injection_needed = 1;
			} else {
				cmn_err(CE_WARN, "Cannot find page structure"
				    " for PA %lx\n", pa);
			}
		} else {
			MC_LOG("Reading from %lx\n", pa);
			data = ldphys(pa);
			MC_LOG("data = %x\n", data);
		}

		if (extra_injection_needed) {
			/*
			 * These are the injection cases where the
			 * requested injected errors will not cause the HW
			 * patrol to stop. For these cases, we need to inject
			 * an extra 'real' PTRL error to force the
			 * HW patrol to stop so that we can report the
			 * errors injected. Note that we cannot read
			 * and report error status while the HW patrol
			 * is running.
			 */
			ST_MAC_REG(MAC_EG_CNTL(mcp, bank),
			    cntl & MAC_EG_SETUP_MASK);
			ST_MAC_REG(MAC_EG_CNTL(mcp, bank), cntl);

			if (both_sides) {
				ST_MAC_REG(MAC_EG_CNTL(mcp, bank^1), cntl &
				    MAC_EG_SETUP_MASK);
				ST_MAC_REG(MAC_EG_CNTL(mcp, bank^1), cntl);
			}
			data = 0xf0e0d0c0;
			MC_LOG("Writing %x to %lx\n", data, pa);
			stphys(pa, data);
			cpu_flush_ecache();
		}
	}

	if (flags & MC_INJECT_FLAG_RESTART) {
		MC_LOG("Restart patrol\n");
		rsaddr.mi_restartaddr.ma_bd = mcp->mc_board_num;
		rsaddr.mi_restartaddr.ma_bank = bank;
		rsaddr.mi_restartaddr.ma_dimm_addr = dimm_addr;
		rsaddr.mi_valid = 1;
		rsaddr.mi_injectrestart = 1;
		(void) restart_patrol(mcp, bank, &rsaddr);
	}

	if (flags & MC_INJECT_FLAG_POLL) {
		int running;
		int ebank = (IS_MIRROR(mcp, bank)) ? MIRROR_IDX(bank) : bank;

		MC_LOG("Poll patrol error\n");
		stat = LD_MAC_REG(MAC_PTRL_STAT(mcp, bank));
		cntl = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank));
		running = cntl & MAC_CNTL_PTRL_START;

		if (!running &&
		    (stat & (MAC_STAT_PTRL_ERRS|MAC_STAT_MI_ERRS))) {
			/*
			 * HW patrol stopped and we have errors to
			 * report. Do it.
			 */
			mcp->mc_speedup_period[ebank] = 0;
			rsaddr.mi_valid = 0;
			rsaddr.mi_injectrestart = 0;
			if (IS_MIRROR(mcp, bank)) {
				mc_error_handler_mir(mcp, bank, &rsaddr);
			} else {
				mc_error_handler(mcp, bank, &rsaddr);
			}

			(void) restart_patrol(mcp, bank, &rsaddr);
		} else {
			/*
			 * We are expecting to report injected
			 * errors but the HW patrol is still running.
			 * Speed up the scanning
			 */
			mcp->mc_speedup_period[ebank] = 2;
			MAC_CMD(mcp, bank, 0);
			(void) restart_patrol(mcp, bank, NULL);
		}
	}

	mutex_exit(&mcp->mc_lock);
	return (0);
}

void
mc_stphysio(uint64_t pa, uint32_t data)
{
	MC_LOG("0x%x -> pa(%lx)\n", data, pa);
	stphysio(pa, data);

	/* force the above write to be processed by mac patrol */
	data = ldphysio(pa);
	MC_LOG("pa(%lx) = 0x%x\n", pa, data);
}

uint32_t
mc_ldphysio(uint64_t pa)
{
	uint32_t rv;

	rv = ldphysio(pa);
	MC_LOG("pa(%lx) = 0x%x\n", pa, rv);
	return (rv);
}

#define	isdigit(ch)	((ch) >= '0' && (ch) <= '9')

/*
 * parse_unum_memory -- extract the board number and the DIMM name from
 * the unum.
 *
 * Return 0 for success and non-zero for a failure.
 */
int
parse_unum_memory(char *unum, int *board, char *dname)
{
	char *c;
	char x, y, z;

	if ((c = strstr(unum, "CMU")) != NULL) {
		/* DC Model */
		c += 3;
		*board = (uint8_t)stoi(&c);
		if ((c = strstr(c, "MEM")) == NULL) {
			return (1);
		}
		c += 3;
		if (strlen(c) < 3) {
			return (2);
		}
		if ((!isdigit(c[0])) || (!(isdigit(c[1]))) ||
		    ((c[2] != 'A') && (c[2] != 'B'))) {
			return (3);
		}
		x = c[0];
		y = c[1];
		z = c[2];
	} else if ((c = strstr(unum, "MBU_")) != NULL) {
		/*  FF1/FF2/Ikkaku Model */
		c += 4;
		if ((c[0] != 'A') && (c[0] != 'B')) {
			return (4);
		}
		if (plat_model == MODEL_IKKAKU) {
			/* Ikkaku Model */
			x = '0';
			*board = 0;
		} else {
			/* FF1/FF2 Model */
			if ((c = strstr(c, "MEMB")) == NULL) {
				return (5);
			}
			c += 4;

			x = c[0];
			*board =  ((uint8_t)stoi(&c)) / 4;
		}

		if ((c = strstr(c, "MEM")) == NULL) {
			return (6);
		}
		c += 3;
		if (strlen(c) < 2) {
			return (7);
		}
		if ((!isdigit(c[0])) || ((c[1] != 'A') && (c[1] != 'B'))) {
			return (8);
		}
		y = c[0];
		z = c[1];
	} else {
		return (9);
	}
	if (*board < 0) {
		return (10);
	}
	dname[0] = x;
	dname[1] = y;
	dname[2] = z;
	dname[3] = '\0';
	return (0);
}

/*
 * mc_get_mem_sid_dimm -- Get the serial-ID for a given board and
 * the DIMM name.
 */
int
mc_get_mem_sid_dimm(mc_opl_t *mcp, char *dname, char *buf,
    int buflen, int *lenp)
{
	int		ret = ENODEV;
	mc_dimm_info_t	*d = NULL;

	if ((d = mcp->mc_dimm_list) == NULL) {
		MC_LOG("mc_get_mem_sid_dimm: mc_dimm_list is NULL\n");
		return (EINVAL);
		}

	for (; d != NULL; d = d->md_next) {
		if (strcmp(d->md_dimmname, dname) == 0) {
			break;
		}
	}
	if (d != NULL) {
		*lenp = strlen(d->md_serial) + strlen(d->md_partnum);
		if (buflen <=  *lenp) {
			cmn_err(CE_WARN, "mc_get_mem_sid_dimm: "
			    "buflen is smaller than %d\n", *lenp);
			ret = ENOSPC;
		} else {
			(void) snprintf(buf, buflen, "%s:%s",
			    d->md_serial, d->md_partnum);
			ret = 0;
		}
	}
	MC_LOG("mc_get_mem_sid_dimm: Ret=%d Name=%s Serial-ID=%s\n",
	    ret, dname, (ret == 0) ? buf : "");
	return (ret);
}

int
mc_set_mem_sid(mc_opl_t *mcp, char *buf, int buflen, int sb,
    int bank, uint32_t mf_type, uint32_t d_slot)
{
	int	lenp = buflen;
	int	id;
	int	ret;
	char	*dimmnm;

	if (mf_type == FLT_TYPE_INTERMITTENT_CE ||
	    mf_type == FLT_TYPE_PERMANENT_CE) {
		if (plat_model == MODEL_DC) {
			/*
			 * All DC models
			 */
			id = BD_BK_SLOT_TO_INDEX(0, bank, d_slot);
			dimmnm = mc_dc_dimm_unum_table[id];
		} else {
			/*
			 * All FF and Ikkaku models
			 */
			id = BD_BK_SLOT_TO_INDEX(sb, bank, d_slot);
			dimmnm = mc_ff_dimm_unum_table[id];
		}
		if ((ret = mc_get_mem_sid_dimm(mcp, dimmnm, buf, buflen,
		    &lenp)) != 0) {
			return (ret);
		}
	} else {
		return (1);
	}

	return (0);
}

/*
 * mc_get_mem_sid -- get the DIMM serial-ID corresponding to the unum.
 */
int
mc_get_mem_sid(char *unum, char *buf, int buflen, int *lenp)
{
	int	i;
	int	ret = ENODEV;
	int	board;
	char	dname[MCOPL_MAX_DIMMNAME + 1];
	mc_opl_t *mcp;

	MC_LOG("mc_get_mem_sid: unum=%s buflen=%d\n", unum, buflen);
	if ((ret = parse_unum_memory(unum, &board, dname)) != 0) {
		MC_LOG("mc_get_mem_sid: unum(%s) parsing failed ret=%d\n",
		    unum, ret);
		return (EINVAL);
	}

	if (board < 0) {
		MC_LOG("mc_get_mem_sid: Invalid board=%d dimm=%s\n",
		    board, dname);
		return (EINVAL);
	}

	mutex_enter(&mcmutex);
	/*
	 * return ENOENT if we can not find the matching board.
	 */
	ret = ENOENT;
	for (i = 0; i < OPL_MAX_BOARDS; i++) {
		if ((mcp = mc_instances[i]) == NULL)
			continue;
		mutex_enter(&mcp->mc_lock);
		if (mcp->mc_phys_board_num != board) {
			mutex_exit(&mcp->mc_lock);
			continue;
		}
		ret = mc_get_mem_sid_dimm(mcp, dname, buf, buflen, lenp);
		if (ret == 0) {
			mutex_exit(&mcp->mc_lock);
			break;
		}
		mutex_exit(&mcp->mc_lock);
	}
	mutex_exit(&mcmutex);
	return (ret);
}

/*
 * mc_get_mem_offset -- get the offset in a DIMM for a given physical address.
 */
int
mc_get_mem_offset(uint64_t paddr, uint64_t *offp)
{
	int		i;
	int		ret = ENODEV;
	mc_addr_t	maddr;
	mc_opl_t	*mcp;

	mutex_enter(&mcmutex);
	for (i = 0; ((i < OPL_MAX_BOARDS) && (ret != 0)); i++) {
		if ((mcp = mc_instances[i]) == NULL)
			continue;
		mutex_enter(&mcp->mc_lock);
		if (!pa_is_valid(mcp, paddr)) {
			mutex_exit(&mcp->mc_lock);
			continue;
		}
		if (pa_to_maddr(mcp, paddr, &maddr) == 0) {
			*offp = maddr.ma_dimm_addr;
			ret = 0;
		}
		mutex_exit(&mcp->mc_lock);
	}
	mutex_exit(&mcmutex);
	MC_LOG("mc_get_mem_offset: Ret=%d paddr=0x%lx offset=0x%lx\n",
	    ret, paddr, *offp);
	return (ret);
}

/*
 * dname_to_bankslot - Get the bank and slot number from the DIMM name.
 */
int
dname_to_bankslot(char *dname, int *bank, int *slot)
{
	int i;
	int tsz;
	char **tbl;

	if (plat_model == MODEL_DC) {
		/*
		 * All DC models
		 */
		tbl = mc_dc_dimm_unum_table;
		tsz = OPL_MAX_DIMMS;
	} else {
		/*
		 * All FF and Ikkaku models
		 */
		tbl = mc_ff_dimm_unum_table;
		tsz = 2 * OPL_MAX_DIMMS;
	}

	for (i = 0; i < tsz; i++) {
		if (strcmp(dname,  tbl[i]) == 0) {
			break;
		}
	}
	if (i == tsz) {
		return (1);
	}
	*bank = INDEX_TO_BANK(i);
	*slot = INDEX_TO_SLOT(i);
	return (0);
}

/*
 * mc_get_mem_addr -- get the physical address of a DIMM corresponding
 * to the unum and sid.
 */
int
mc_get_mem_addr(char *unum, char *sid, uint64_t offset, uint64_t *paddr)
{
	int	board;
	int	bank;
	int	slot;
	int	i;
	int	ret = ENODEV;
	char	dname[MCOPL_MAX_DIMMNAME + 1];
	mc_addr_t maddr;
	mc_opl_t *mcp;

	MC_LOG("mc_get_mem_addr: unum=%s sid=%s offset=0x%lx\n",
	    unum, sid, offset);
	if (parse_unum_memory(unum, &board, dname) != 0) {
		MC_LOG("mc_get_mem_sid: unum(%s) parsing failed ret=%d\n",
		    unum, ret);
		return (EINVAL);
	}

	if (board < 0) {
		MC_LOG("mc_get_mem_addr: Invalid board=%d dimm=%s\n",
		    board, dname);
		return (EINVAL);
	}

	mutex_enter(&mcmutex);
	for (i = 0; i < OPL_MAX_BOARDS; i++) {
		if ((mcp = mc_instances[i]) == NULL)
			continue;
		mutex_enter(&mcp->mc_lock);
		if (mcp->mc_phys_board_num != board) {
			mutex_exit(&mcp->mc_lock);
			continue;
		}

		ret = dname_to_bankslot(dname, &bank, &slot);
		MC_LOG("mc_get_mem_addr: bank=%d slot=%d\n", bank, slot);
		if (ret != 0) {
			MC_LOG("mc_get_mem_addr: dname_to_bankslot failed\n");
			ret = ENODEV;
		} else {
			maddr.ma_bd = mcp->mc_board_num;
			maddr.ma_bank =  bank;
			maddr.ma_dimm_addr = offset;
			ret = mcaddr_to_pa(mcp, &maddr, paddr);
			if (ret != 0) {
				MC_LOG("mc_get_mem_addr: "
				    "mcaddr_to_pa failed\n");
				ret = ENODEV;
				mutex_exit(&mcp->mc_lock);
				continue;
			}
			mutex_exit(&mcp->mc_lock);
			break;
		}
		mutex_exit(&mcp->mc_lock);
	}
	mutex_exit(&mcmutex);
	MC_LOG("mc_get_mem_addr: Ret=%d, Paddr=0x%lx\n", ret, *paddr);
	return (ret);
}

static void
mc_free_dimm_list(mc_dimm_info_t *d)
{
	mc_dimm_info_t *next;

	while (d != NULL) {
		next = d->md_next;
		kmem_free(d, sizeof (mc_dimm_info_t));
		d = next;
	}
}

/*
 * mc_get_dimm_list -- get the list of dimms with serial-id info
 * from the SP.
 */
mc_dimm_info_t *
mc_get_dimm_list(mc_opl_t *mcp)
{
	uint32_t	bufsz;
	uint32_t	maxbufsz;
	int		ret;
	int		sexp;
	board_dimm_info_t *bd_dimmp;
	mc_dimm_info_t	*dimm_list = NULL;

	maxbufsz = bufsz = sizeof (board_dimm_info_t) +
	    ((MCOPL_MAX_DIMMNAME +  MCOPL_MAX_SERIAL +
	    MCOPL_MAX_PARTNUM) * OPL_MAX_DIMMS);

	bd_dimmp = (board_dimm_info_t *)kmem_alloc(bufsz, KM_SLEEP);
	ret = scf_get_dimminfo(mcp->mc_board_num, (void *)bd_dimmp, &bufsz);

	MC_LOG("mc_get_dimm_list:  scf_service_getinfo returned=%d\n", ret);
	if (ret == 0) {
		sexp = sizeof (board_dimm_info_t) +
		    ((bd_dimmp->bd_dnamesz +  bd_dimmp->bd_serialsz +
		    bd_dimmp->bd_partnumsz) * bd_dimmp->bd_numdimms);

		if ((bd_dimmp->bd_version == OPL_DIMM_INFO_VERSION) &&
		    (bd_dimmp->bd_dnamesz <= MCOPL_MAX_DIMMNAME) &&
		    (bd_dimmp->bd_serialsz <= MCOPL_MAX_SERIAL) &&
		    (bd_dimmp->bd_partnumsz <= MCOPL_MAX_PARTNUM) &&
		    (sexp <= bufsz)) {

#ifdef DEBUG
			if (oplmc_debug)
				mc_dump_dimm_info(bd_dimmp);
#endif
			dimm_list = mc_prepare_dimmlist(bd_dimmp);

		} else {
			cmn_err(CE_WARN, "DIMM info version mismatch\n");
		}
	}
	kmem_free(bd_dimmp, maxbufsz);
	MC_LOG("mc_get_dimm_list: dimmlist=0x%p\n", (void *)dimm_list);
	return (dimm_list);
}

/*
 * mc_prepare_dimmlist - Prepare the dimm list from the information
 * received from the SP.
 */
mc_dimm_info_t *
mc_prepare_dimmlist(board_dimm_info_t *bd_dimmp)
{
	char	*dimm_name;
	char	*serial;
	char	*part;
	int	dimm;
	int	dnamesz = bd_dimmp->bd_dnamesz;
	int	sersz = bd_dimmp->bd_serialsz;
	int	partsz = bd_dimmp->bd_partnumsz;
	mc_dimm_info_t	*dimm_list = NULL;
	mc_dimm_info_t	*d;

	dimm_name = (char *)(bd_dimmp + 1);
	for (dimm = 0; dimm < bd_dimmp->bd_numdimms; dimm++) {

		d = (mc_dimm_info_t *)kmem_alloc(sizeof (mc_dimm_info_t),
		    KM_SLEEP);

		bcopy(dimm_name, d->md_dimmname, dnamesz);
		d->md_dimmname[dnamesz] = 0;

		serial = dimm_name + dnamesz;
		bcopy(serial, d->md_serial, sersz);
		d->md_serial[sersz] = 0;

		part = serial + sersz;
		bcopy(part, d->md_partnum, partsz);
		d->md_partnum[partsz] = 0;

		d->md_next = dimm_list;
		dimm_list = d;
		dimm_name = part + partsz;
	}
	return (dimm_list);
}

static int
mc_get_mem_fmri(mc_flt_page_t *fpag, char **unum)
{
	if (fpag->fmri_addr == 0 || fpag->fmri_sz > MEM_FMRI_MAX_BUFSIZE)
		return (EINVAL);

	*unum = kmem_alloc(fpag->fmri_sz, KM_SLEEP);
	if (copyin((void *)fpag->fmri_addr, *unum, fpag->fmri_sz) != 0) {
		kmem_free(*unum, fpag->fmri_sz);
		return (EFAULT);
	}
	return (0);
}

static int
mc_scf_log_event(mc_flt_page_t *flt_pag)
{
	mc_opl_t *mcp;
	int board, bank, slot;
	int len, rv = 0;
	char *unum, *sid;
	char dname[MCOPL_MAX_DIMMNAME + 1];
	size_t sid_sz;
	uint64_t pa;
	mc_flt_stat_t flt_stat;

	if ((sid_sz = cpu_get_name_bufsize()) == 0)
		return (ENOTSUP);

	if ((rv = mc_get_mem_fmri(flt_pag, &unum)) != 0) {
		MC_LOG("mc_scf_log_event: mc_get_mem_fmri failed\n");
		return (rv);
	}

	sid = kmem_zalloc(sid_sz, KM_SLEEP);

	if ((rv = mc_get_mem_sid(unum, sid, sid_sz, &len)) != 0) {
		MC_LOG("mc_scf_log_event: mc_get_mem_sid failed\n");
		goto out;
	}

	if ((rv = mc_get_mem_addr(unum, sid, (uint64_t)flt_pag->err_add,
	    &pa)) != 0) {
		MC_LOG("mc_scf_log_event: mc_get_mem_addr failed\n");
		goto out;
	}

	if (parse_unum_memory(unum, &board, dname) != 0) {
		MC_LOG("mc_scf_log_event: parse_unum_memory failed\n");
		rv = EINVAL;
		goto out;
	}

	if (board < 0) {
		MC_LOG("mc_scf_log_event: Invalid board=%d dimm=%s\n",
		    board, dname);
		rv = EINVAL;
		goto out;
	}

	if (dname_to_bankslot(dname, &bank, &slot) != 0) {
		MC_LOG("mc_scf_log_event: dname_to_bankslot failed\n");
		rv = EINVAL;
		goto out;
	}

	mutex_enter(&mcmutex);

	flt_stat.mf_err_add = flt_pag->err_add;
	flt_stat.mf_err_log = flt_pag->err_log;
	flt_stat.mf_flt_paddr = pa;

	if ((mcp = mc_pa_to_mcp(pa)) == NULL) {
		mutex_exit(&mcmutex);
		MC_LOG("mc_scf_log_event: invalid pa\n");
		rv = EINVAL;
		goto out;
	}

	MC_LOG("mc_scf_log_event: DIMM%s, /LSB%d/B%d/%x, pa %lx elog %x\n",
	    unum, mcp->mc_board_num, bank, flt_pag->err_add, pa,
	    flt_pag->err_log);

	mutex_enter(&mcp->mc_lock);

	if (!pa_is_valid(mcp, pa)) {
		mutex_exit(&mcp->mc_lock);
		mutex_exit(&mcmutex);
		rv = EINVAL;
		goto out;
	}

	rv = 0;

	mc_queue_scf_log(mcp, &flt_stat, bank);

	mutex_exit(&mcp->mc_lock);
	mutex_exit(&mcmutex);

out:
	kmem_free(unum, flt_pag->fmri_sz);
	kmem_free(sid, sid_sz);

	return (rv);
}

#ifdef DEBUG
void
mc_dump_dimm(char *buf, int dnamesz, int serialsz, int partnumsz)
{
	char dname[MCOPL_MAX_DIMMNAME + 1];
	char serial[MCOPL_MAX_SERIAL + 1];
	char part[ MCOPL_MAX_PARTNUM + 1];
	char *b;

	b = buf;
	bcopy(b, dname, dnamesz);
	dname[dnamesz] = 0;

	b += dnamesz;
	bcopy(b, serial, serialsz);
	serial[serialsz] = 0;

	b += serialsz;
	bcopy(b, part, partnumsz);
	part[partnumsz] = 0;

	printf("DIMM=%s  Serial=%s PartNum=%s\n", dname, serial, part);
}

void
mc_dump_dimm_info(board_dimm_info_t *bd_dimmp)
{
	int	dimm;
	int	dnamesz = bd_dimmp->bd_dnamesz;
	int	sersz = bd_dimmp->bd_serialsz;
	int	partsz = bd_dimmp->bd_partnumsz;
	char	*buf;

	printf("Version=%d Board=%02d DIMMs=%d NameSize=%d "
	    "SerialSize=%d PartnumSize=%d\n", bd_dimmp->bd_version,
	    bd_dimmp->bd_boardnum, bd_dimmp->bd_numdimms, bd_dimmp->bd_dnamesz,
	    bd_dimmp->bd_serialsz, bd_dimmp->bd_partnumsz);
	printf("======================================================\n");

	buf = (char *)(bd_dimmp + 1);
	for (dimm = 0; dimm < bd_dimmp->bd_numdimms; dimm++) {
		mc_dump_dimm(buf, dnamesz, sersz, partsz);
		buf += dnamesz + sersz + partsz;
	}
	printf("======================================================\n");
}


/* ARGSUSED */
static int
mc_ioctl_debug(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	caddr_t	buf, kbuf;
	uint64_t pa;
	int rv = 0;
	int i;
	uint32_t flags;
	static uint32_t offset = 0;


	flags = (cmd >> 4) & 0xfffffff;

	cmd &= 0xf;

	MC_LOG("mc_ioctl(cmd = %x, flags = %x)\n", cmd, flags);

	if (arg != NULL) {
		if (ddi_copyin((const void *)arg, (void *)&pa,
		    sizeof (uint64_t), 0) < 0) {
			rv = EFAULT;
			return (rv);
		}
		buf = NULL;
	} else {
		buf = (caddr_t)kmem_alloc(PAGESIZE, KM_SLEEP);

		pa = va_to_pa(buf);
		pa += offset;

		offset += 64;
		if (offset >= PAGESIZE)
			offset = 0;
	}

	switch (cmd) {
	case MCI_CE:
		(void) mc_inject_error(MC_INJECT_INTERMITTENT_CE, pa, flags);
		break;
	case MCI_PERM_CE:
		(void) mc_inject_error(MC_INJECT_PERMANENT_CE, pa, flags);
		break;
	case MCI_UE:
		(void) mc_inject_error(MC_INJECT_UE, pa, flags);
		break;
	case MCI_M_CE:
		(void) mc_inject_error(MC_INJECT_INTERMITTENT_MCE, pa, flags);
		break;
	case MCI_M_PCE:
		(void) mc_inject_error(MC_INJECT_PERMANENT_MCE, pa, flags);
		break;
	case MCI_M_UE:
		(void) mc_inject_error(MC_INJECT_MUE, pa, flags);
		break;
	case MCI_CMP:
		(void) mc_inject_error(MC_INJECT_CMPE, pa, flags);
		break;
	case MCI_NOP:
		(void) mc_inject_error(MC_INJECT_NOP, pa, flags); break;
	case MCI_SHOW_ALL:
		mc_debug_show_all = 1;
		break;
	case MCI_SHOW_NONE:
		mc_debug_show_all = 0;
		break;
	case MCI_ALLOC:
		/*
		 * just allocate some kernel memory and never free it
		 * 512 MB seems to be the maximum size supported.
		 */
		cmn_err(CE_NOTE, "Allocating kmem %d MB\n", flags * 512);
		for (i = 0; i < flags; i++) {
			kbuf = kmem_alloc(512 * 1024 * 1024, KM_SLEEP);
			cmn_err(CE_NOTE, "kmem buf %llx PA %llx\n",
			    (u_longlong_t)kbuf, (u_longlong_t)va_to_pa(kbuf));
		}
		break;
	case MCI_SUSPEND:
		(void) opl_mc_suspend();
		break;
	case MCI_RESUME:
		(void) opl_mc_resume();
		break;
	default:
		rv = ENXIO;
	}
	if (buf)
		kmem_free(buf, PAGESIZE);

	return (rv);
}

#endif /* DEBUG */
