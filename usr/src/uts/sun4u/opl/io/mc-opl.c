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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/async.h>
#include <sys/machsystm.h>
#include <sys/ksynch.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/kmem.h>
#include <sys/fm/io/opl_mc_fm.h>
#include <sys/memlist.h>
#include <sys/param.h>
#include <sys/ontrap.h>
#include <vm/page.h>
#include <sys/mc-opl.h>

/*
 * Function prototypes
 */
static int mc_open(dev_t *, int, int, cred_t *);
static int mc_close(dev_t, int, int, cred_t *);
static int mc_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int mc_attach(dev_info_t *, ddi_attach_cmd_t);
static int mc_detach(dev_info_t *, ddi_detach_cmd_t);

static int mc_board_add(mc_opl_t *mcp);
static int mc_board_del(mc_opl_t *mcp);
static int mc_suspend(mc_opl_t *mcp, uint32_t flag);
static int mc_resume(mc_opl_t *mcp, uint32_t flag);

static void insert_mcp(mc_opl_t *mcp);
static void delete_mcp(mc_opl_t *mcp);

static int pa_to_maddr(mc_opl_t *mcp, uint64_t pa, mc_addr_t *maddr);

static int mc_valid_pa(mc_opl_t *mcp, uint64_t pa);

int mc_get_mem_unum(int, uint64_t, char *, int, int *);
extern int plat_max_boards(void);

static void mc_get_mlist(mc_opl_t *);

#pragma weak opl_get_physical_board
extern int opl_get_physical_board(int);
static int mc_opl_get_physical_board(int);

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
	nulldev				/* power */
};

/*
 * Driver globals
 */
int mc_patrol_interval_sec = 10;

int inject_op_delay = 5;

mc_inst_list_t *mc_instances;
static kmutex_t mcmutex;

void *mc_statep;

#ifdef	DEBUG
int oplmc_debug = 0;
#endif

static int mc_debug_show_all;

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,			/* module type, this one is a driver */
	"OPL Memory-controller 1.1",	/* module name */
	&mc_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* rev */
	(void *)&modldrv,
	NULL
};

#pragma weak opl_get_mem_unum
extern int (*opl_get_mem_unum)(int, uint64_t, char *, int, int *);

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
	int error;


	if ((error = ddi_soft_state_init(&mc_statep,
	    sizeof (mc_opl_t), 1)) != 0)
		return (error);

	mutex_init(&mcmutex, NULL, MUTEX_DRIVER, NULL);
	if (&opl_get_mem_unum)
		opl_get_mem_unum = mc_get_mem_unum;

	error =  mod_install(&modlinkage);
	if (error != 0) {
		if (&opl_get_mem_unum)
			opl_get_mem_unum = NULL;
		mutex_destroy(&mcmutex);
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

	mutex_destroy(&mcmutex);

	if (&opl_get_mem_unum)
		opl_get_mem_unum = NULL;

	ddi_soft_state_fini(&mc_statep);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
mc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	mc_opl_t *mcp;
	int instance;

	/* get the instance of this devi */
	instance = ddi_get_instance(devi);

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		mcp = ddi_get_soft_state(mc_statep, instance);
		return (mc_resume(mcp, MC_DRIVER_SUSPENDED));
	default:
		return (DDI_FAILURE);
	}


	if (ddi_soft_state_zalloc(mc_statep, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if ((mcp = ddi_get_soft_state(mc_statep, instance)) == NULL) {
		goto bad;
	}

	/* set informations in mc state */
	mcp->mc_dip = devi;

	if (mc_board_add(mcp))
		goto bad;

	insert_mcp(mcp);
	ddi_report_dev(devi);

	return (DDI_SUCCESS);

bad:
	ddi_soft_state_free(mc_statep, instance);
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
mc_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	mc_opl_t *mcp;

	/* get the instance of this devi */
	instance = ddi_get_instance(devi);
	if ((mcp = ddi_get_soft_state(mc_statep, instance)) == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_SUSPEND:
		return (mc_suspend(mcp, MC_DRIVER_SUSPENDED));
	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&mcmutex);
	if (mc_board_del(mcp) != DDI_SUCCESS) {
		mutex_exit(&mcmutex);
		return (DDI_FAILURE);
	}

	delete_mcp(mcp);
	mutex_exit(&mcmutex);

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
	return (ENXIO);
}

/*
 * PA validity check:
 * This function return 1 if the PA is valid, otherwise
 * return 0.
 */

/* ARGSUSED */
static int
pa_is_valid(mc_opl_t *mcp, uint64_t addr)
{
	/*
	 * Check if the addr is on the board.
	 */
	if ((addr < mcp->mc_start_address) ||
	    (mcp->mc_start_address + mcp->mc_size <= addr))
		return (0);

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
		return (-1);
	}


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
	if ((bank0 == bank1) &&
		(maddr->ma_dimm_addr == maddr1.ma_dimm_addr)) {
		return (0);
	} else {
		cmn_err(CE_WARN, "Translation error source /LSB%d/B%d/%x, "
			"PA %lx, target /LSB%d/B%d/%x\n",
			maddr->ma_bd, bank, maddr->ma_dimm_addr,
			*pa, maddr1.ma_bd, maddr1.ma_bank,
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
	int cs = 0;

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

	/* PA validity check */
	if (!pa_is_valid(mcp, pa))
		return (-1);


	/* Do translation */
	pa_offset = pa - mcp->mc_start_address;

	maddr->ma_bd = mcp->mc_board_num;
	maddr->ma_bank = pa_to_bank(mcp, pa_offset);
	maddr->ma_dimm_addr = pa_to_dimm(mcp, pa_offset);
	MC_LOG("pa %lx -> mcaddr /LSB%d/B%d/%x\n",
		pa_offset, maddr->ma_bd, maddr->ma_bank, maddr->ma_dimm_addr);
	return (0);
}

static void
mc_ereport_post(mc_aflt_t *mc_aflt)
{
	char buf[FM_MAX_CLASS];
	char device_path[MAXPATHLEN];
	nv_alloc_t *nva = NULL;
	nvlist_t *ereport, *detector, *resource;
	errorq_elem_t *eqep;
	int nflts;
	mc_flt_stat_t *flt_stat;
	int i, n, blen;
	char *p;
	uint32_t values[2], synd[2], dslot[2];

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
	    device_path, NULL);

	/*
	 * Encode all the common data into the ereport.
	 */
	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s-%s",
		MC_OPL_ERROR_CLASS,
		mc_aflt->mflt_is_ptrl ? MC_OPL_PTRL_SUBCLASS :
		MC_OPL_MI_SUBCLASS,
		mc_aflt->mflt_erpt_class);

	MC_LOG("mc_ereport_post: ereport %s\n", buf);


	fm_ereport_set(ereport, FM_EREPORT_VERSION, buf,
		fm_ena_generate(mc_aflt->mflt_id, FM_ENA_FMT1),
		detector, NULL);

	/*
	 * Set payload.
	 */
	fm_payload_set(ereport, MC_OPL_BOARD, DATA_TYPE_UINT32,
		flt_stat->mf_flt_maddr.ma_bd, NULL);

	fm_payload_set(ereport, MC_OPL_PA, DATA_TYPE_UINT64,
		flt_stat->mf_flt_paddr, NULL);

	if (flt_stat->mf_type == FLT_TYPE_PERMANENT_CE) {
		fm_payload_set(ereport, MC_OPL_FLT_TYPE,
			DATA_TYPE_UINT8, ECC_STICKY, NULL);
	}

	for (i = 0; i < nflts; i++)
		values[i] = mc_aflt->mflt_stat[i]->mf_flt_maddr.ma_bank;

	fm_payload_set(ereport, MC_OPL_BANK, DATA_TYPE_UINT32_ARRAY,
		nflts, values, NULL);

	for (i = 0; i < nflts; i++)
		values[i] = mc_aflt->mflt_stat[i]->mf_cntl;

	fm_payload_set(ereport, MC_OPL_STATUS, DATA_TYPE_UINT32_ARRAY,
		nflts, values, NULL);

	for (i = 0; i < nflts; i++)
		values[i] = mc_aflt->mflt_stat[i]->mf_err_add;

	fm_payload_set(ereport, MC_OPL_ERR_ADD, DATA_TYPE_UINT32_ARRAY,
		nflts, values, NULL);

	for (i = 0; i < nflts; i++)
		values[i] = mc_aflt->mflt_stat[i]->mf_err_log;

	fm_payload_set(ereport, MC_OPL_ERR_LOG, DATA_TYPE_UINT32_ARRAY,
		nflts, values, NULL);

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

	fm_payload_set(ereport, MC_OPL_ERR_SYND,
		DATA_TYPE_UINT32_ARRAY, nflts, synd, NULL);

	fm_payload_set(ereport, MC_OPL_ERR_DIMMSLOT,
		DATA_TYPE_UINT32_ARRAY, nflts, dslot, NULL);

	fm_payload_set(ereport, MC_OPL_ERR_DRAM,
		DATA_TYPE_UINT32_ARRAY, nflts, values, NULL);

	blen = MAXPATHLEN;
	device_path[0] = 0;
	p = &device_path[0];

	for (i = 0; i < nflts; i++) {
		int bank = flt_stat->mf_flt_maddr.ma_bank;
		int psb = -1;

		flt_stat = mc_aflt->mflt_stat[i];
		psb = mc_opl_get_physical_board(
		    flt_stat->mf_flt_maddr.ma_bd);

		if (psb != -1) {
			snprintf(p, blen, "/CMU%d/B%d", psb, bank);
		} else {
			snprintf(p, blen, "/CMU/B%d", bank);
		}

		if (flt_stat->mf_errlog_valid) {
			snprintf(p + strlen(p), blen, "/MEM%d%d%c",
			    bank/2, (bank & 0x1) * 2 + dslot[i] & 1,
			    (dslot[i] & 0x2) ? 'B' : 'A');
		}

		n = strlen(&device_path[0]);
		blen = MAXPATHLEN - n;
		p = &device_path[n];
		if (i < (nflts - 1)) {
			snprintf(p, blen, " ");
			n += 1; blen -= 1; p += 1;
		}
	}

	/*
	 * UNUM format /LSB#/B#/MEMxyZ
	 * where x is the MAC# = Bank#/2
	 * y is slot info = (Bank# & 0x1)*2 + {0, 1} 0 for DIMM-L, 1 for DIMM-H
	 * DIMM-L is 0 in bit 13, DIMM-H is 1 in bit 13.
	 * Z is A(CS0) or B(CS1) given by bit 14
	 */
	(void) fm_fmri_mem_set(resource, FM_MEM_SCHEME_VERSION,
		NULL, device_path, NULL, 0);

	fm_payload_set(ereport, MC_OPL_RESOURCE, DATA_TYPE_NVLIST,
		resource, NULL);

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
	page_t *pp;
	uint64_t errors;
	uint64_t pa = (uint64_t)(-1);

	MC_LOG("mc_err_drain: %s\n",
		mc_aflt->mflt_erpt_class);
	/*
	 * we come here only when we have:
	 * In mirror mode: CMPE, MUE, SUE
	 * In normal mode: UE, Permanent CE
	 */
	rv = mcaddr_to_pa(mc_aflt->mflt_mcp,
		&(mc_aflt->mflt_stat[0]->mf_flt_maddr), &pa);
	if (rv == 0)
		mc_aflt->mflt_stat[0]->mf_flt_paddr = pa;
	else
		mc_aflt->mflt_stat[0]->mf_flt_paddr = (uint64_t)-1;
	if (rv == 0) {
		MC_LOG("mc_err_drain:pa = %lx\n", pa);
		pp = page_numtopp_nolock(pa >> PAGESHIFT);

		if (pp) {
			/*
			 * Don't keep retiring and make ereports
			 * on bad pages in PTRL case
			 */
			MC_LOG("mc_err_drain:pp = %p\n", pp);
			if (mc_aflt->mflt_is_ptrl) {
				errors = 0;
				if (page_retire_check(pa, &errors) == 0) {
					MC_LOG("Page retired\n");
					return;
				}
				if (errors & mc_aflt->mflt_pr) {
					MC_LOG("errors %lx, mflt_pr %x\n",
						errors, mc_aflt->mflt_pr);
					return;
				}
			}
			MC_LOG("offline page %p error %x\n", pp,
				mc_aflt->mflt_pr);
			(void) page_retire(pa, mc_aflt->mflt_pr);
		}
	}
	mc_ereport_post(mc_aflt);
}

#define	DIMM_SIZE 0x80000000

#define	INC_DIMM_ADDR(p, n) \
	(p)->ma_dimm_addr += n; \
	(p)->ma_dimm_addr &= (DIMM_SIZE - 1)

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
restart_patrol(mc_opl_t *mcp, int bank, mc_addr_info_t *maddr_info)
{
	page_t *pp;
	uint32_t reg;
	uint64_t pa;
	int rv;
	int loop_count = 0;

	reg = ldphysio(MAC_PTRL_CNTL(mcp, bank));

	/* already running, so we just return */
	if (reg & MAC_CNTL_PTRL_START)
		return (0);

	if (maddr_info == NULL || (maddr_info->mi_valid == 0)) {
		MAC_PTRL_START(mcp, bank);
		return (0);
	}


	rv = mcaddr_to_pa(mcp, &maddr_info->mi_maddr, &pa);
	if (rv != 0) {
		MC_LOG("cannot convert mcaddr to pa. use auto restart\n");
		MAC_PTRL_START(mcp, bank);
		return (0);
	}

	/*
	 * pa is the last address scanned by the mac patrol
	 * we  calculate the next restart address as follows:
	 * first we always advance it by 64 byte. Then begin the loop.
	 * loop {
	 * if it is not in phys_install, we advance to next 64 MB boundary
	 * if it is not backed by a page structure, done
	 * if the page is bad, advance to the next page boundary.
	 * else done
	 * if the new address exceeds the board, wrap around.
	 * } <stop if we come back to the same page>
	 */

	if (pa < mcp->mc_start_address || pa >= (mcp->mc_start_address
		+ mcp->mc_size)) {
		/* pa is not on this board, just retry */
		cmn_err(CE_WARN, "restart_patrol: invalid address %lx "
			"on board %d\n", pa, mcp->mc_board_num);
		MAC_PTRL_START(mcp, bank);
		return (0);
	}

	MC_LOG("restart_patrol: pa = %lx\n", pa);
	if (maddr_info->mi_advance) {
		uint64_t new_pa;

		if (IS_MIRROR(mcp, bank))
			new_pa = pa + 64 * 2;
		else
			new_pa = pa + 64;

		if (!mc_valid_pa(mcp, new_pa)) {
			/* Isolation unit size is 64 MB */
#define	MC_ISOLATION_BSIZE	(64 * 1024 * 1024)
			MC_LOG("Invalid PA\n");
			pa = roundup(new_pa + 1, MC_ISOLATION_BSIZE);
		} else {
			pp = page_numtopp_nolock(new_pa >> PAGESHIFT);
			if (pp != NULL) {
				uint64_t errors = 0;
				if (page_retire_check(new_pa, &errors) &&
					(errors == 0)) {
					MC_LOG("Page has no error\n");
					MAC_PTRL_START(mcp, bank);
					return (0);
				}
				/*
				 * skip bad pages
				 * and let the following loop to take care
				 */
				pa = roundup(new_pa + 1, PAGESIZE);
				MC_LOG("Skipping bad page to %lx\n", pa);
			} else {
				MC_LOG("Page has no page structure\n");
				MAC_PTRL_START(mcp, bank);
				return (0);
			}
		}
	}

	/*
	 * if we wrap around twice, we just give up and let
	 * mac patrol decide.
	 */
	MC_LOG("pa is now %lx\n", pa);
	while (loop_count <= 1) {
		if (!mc_valid_pa(mcp, pa)) {
			MC_LOG("pa is not valid. round up to 64 MB\n");
			pa = roundup(pa + 1, 64 * 1024 * 1024);
		} else {
			pp = page_numtopp_nolock(pa >> PAGESHIFT);
			if (pp != NULL) {
				uint64_t errors = 0;
				if (page_retire_check(pa, &errors) &&
					(errors == 0)) {
					MC_LOG("Page has no error\n");
					break;
				}
				/* skip bad pages */
				pa = roundup(pa + 1, PAGESIZE);
				MC_LOG("Skipping bad page to %lx\n", pa);
			} else {
				MC_LOG("Page has no page structure\n");
				break;
			}
		}
		if (pa >= (mcp->mc_start_address + mcp->mc_size)) {
			MC_LOG("Wrap around\n");
			pa = mcp->mc_start_address;
			loop_count++;
		}
	}

	/* retstart MAC patrol: PA[37:6] */
	MC_LOG("restart at pa = %lx\n", pa);
	ST_MAC_REG(MAC_RESTART_ADD(mcp, bank), MAC_RESTART_PA(pa));
	MAC_PTRL_START_ADD(mcp, bank);

	return (0);
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
do_rewrite(mc_opl_t *mcp, int bank, uint32_t dimm_addr)
{
	uint32_t cntl;
	int count = 0;

	/* first wait to make sure PTRL_STATUS is 0 */
	while (count++ < MAX_MC_LOOP_COUNT) {
		cntl = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank));
		if (!(cntl & MAC_CNTL_PTRL_STATUS))
			break;
		delay(drv_usectohz(10 * 1000));	/* 10 m.s. */
	}
	if (count >= MAX_MC_LOOP_COUNT)
		goto bad;

	count = 0;

	ST_MAC_REG(MAC_REWRITE_ADD(mcp, bank), dimm_addr);
	MAC_REW_REQ(mcp, bank);

	do {
		cntl = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank));
		if (count++ >= MAX_MC_LOOP_COUNT) {
			goto bad;
		} else
			delay(drv_usectohz(10 * 1000));	/* 10 m.s. */
	/*
	 * If there are other MEMORY or PCI activities, this
	 * will be BUSY, else it should be set immediately
	 */
	} while (!(cntl & MAC_CNTL_REW_END));

	MAC_CLEAR_ERRS(mcp, bank, MAC_CNTL_REW_ERRS);
	return (cntl);
bad:
	/* This is bad.  Just reset the circuit */
	cmn_err(CE_WARN, "mc-opl rewrite timeout on /LSB%d/B%d\n",
		mcp->mc_board_num, bank);
	cntl = MAC_CNTL_REW_END;
	MAC_CMD(mcp, bank, MAC_CNTL_PTRL_RESET);
	MAC_CLEAR_ERRS(mcp, bank, MAC_CNTL_REW_ERRS);
	return (cntl);
}

void
mc_process_scf_log(mc_opl_t *mcp)
{
	int count = 0;
	scf_log_t *p;
	int bank;

	while ((p = mcp->mc_scf_log) != NULL) {
		bank = p->sl_bank;
		while ((LD_MAC_REG(MAC_STATIC_ERR_ADD(mcp, p->sl_bank))
			& MAC_STATIC_ERR_VLD)) {
			if (count++ >= (MAX_MC_LOOP_COUNT)) {
				break;
			}
			delay(drv_usectohz(10 * 1000));	/* 10 m.s. */
		}

		if (count < MAX_MC_LOOP_COUNT) {
			ST_MAC_REG(MAC_STATIC_ERR_LOG(mcp, p->sl_bank),
				p->sl_err_log);

			ST_MAC_REG(MAC_STATIC_ERR_ADD(mcp, p->sl_bank),
				p->sl_err_add|MAC_STATIC_ERR_VLD);
			mcp->mc_scf_retry[bank] = 0;
		} else {
			/* if we try too many times, just drop the req */
			if (mcp->mc_scf_retry[bank]++ <= MAX_SCF_RETRY) {
				return;
			} else {
				cmn_err(CE_WARN, "SCF is not responding. "
					"Dropping the SCF LOG\n");
			}
		}
		mcp->mc_scf_log = p->sl_next;
		mcp->mc_scf_total--;
		ASSERT(mcp->mc_scf_total >= 0);
		kmem_free(p, sizeof (scf_log_t));
	}
}

void
mc_queue_scf_log(mc_opl_t *mcp, mc_flt_stat_t *flt_stat, int bank)
{
	scf_log_t *p;

	if (mcp->mc_scf_total >= MAX_SCF_LOGS) {
		cmn_err(CE_WARN,
			"Max# SCF logs excceded on /LSB%d/B%d\n",
			mcp->mc_board_num, bank);
		return;
	}
	p = kmem_zalloc(sizeof (scf_log_t), KM_SLEEP);
	p->sl_next = 0;
	p->sl_err_add = flt_stat->mf_err_add;
	p->sl_err_log = flt_stat->mf_err_log;
	p->sl_bank = bank;

	if (mcp->mc_scf_log == NULL) {
		/*
		 * we rely on mc_scf_log to detect NULL queue.
		 * mc_scf_log_tail is irrelevant is such case.
		 */
		mcp->mc_scf_log_tail = mcp->mc_scf_log = p;
	} else {
		mcp->mc_scf_log_tail->sl_next = p;
		mcp->mc_scf_log_tail = p;
	}
	mcp->mc_scf_total++;
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
		cntl = do_rewrite(mcp, bank, flt_stat->mf_err_add);
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
	value |= mcp->mc_bank[bank].mcb_ptrl_cntl;
	ST_MAC_REG(MAC_PTRL_CNTL(mcp, bank), value);
}

static int
mc_stop(mc_opl_t *mcp, int bank)
{
	uint32_t reg;
	int count = 0;

	reg = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank));

	if (reg & MAC_CNTL_PTRL_START)
		MAC_PTRL_STOP(mcp, bank);

	while (count++ <= MAX_MC_LOOP_COUNT) {
		reg = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank));
		if ((reg & MAC_CNTL_PTRL_STATUS) == 0)
			return (0);
		delay(drv_usectohz(10 * 1000));	/* 10 m.s. */
	}
	return (-1);
}

static void
mc_read_ptrl_reg(mc_opl_t *mcp, int bank, mc_flt_stat_t *flt_stat)
{
	flt_stat->mf_cntl = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank)) &
		MAC_CNTL_PTRL_ERRS;
	flt_stat->mf_err_add = LD_MAC_REG(MAC_PTRL_ERR_ADD(mcp, bank));
	flt_stat->mf_err_log = LD_MAC_REG(MAC_PTRL_ERR_LOG(mcp, bank));
	flt_stat->mf_flt_maddr.ma_bd = mcp->mc_board_num;
	flt_stat->mf_flt_maddr.ma_bank = bank;
	flt_stat->mf_flt_maddr.ma_dimm_addr = flt_stat->mf_err_add;
}

static void
mc_read_mi_reg(mc_opl_t *mcp, int bank, mc_flt_stat_t *flt_stat)
{
	uint32_t status, old_status;

	status = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank)) &
		MAC_CNTL_MI_ERRS;
	old_status = 0;

	/* we keep reading until the status is stable */
	while (old_status != status) {
		old_status = status;
		flt_stat->mf_err_add =
			LD_MAC_REG(MAC_MI_ERR_ADD(mcp, bank));
		flt_stat->mf_err_log =
			LD_MAC_REG(MAC_MI_ERR_LOG(mcp, bank));
		status = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank)) &
			MAC_CNTL_MI_ERRS;
		if (status == old_status) {
			break;
		}
	}

	flt_stat->mf_cntl = status;
	flt_stat->mf_flt_maddr.ma_bd = mcp->mc_board_num;
	flt_stat->mf_flt_maddr.ma_bank = bank;
	flt_stat->mf_flt_maddr.ma_dimm_addr = flt_stat->mf_err_add;
}


/*
 * Error philosophy for mirror mode:
 *
 * PTRL (The error address for both banks are same, since ptrl stops if it
 * detects error.)
 * - Compaire error  Report CMPE.
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
 * - Compair  error  If addresses are the same.  Just CMPE.
 *		     If addresses are different (this could happen
 *		     as a result of scrubbing.  Report each seperately.
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

	MC_LOG("process mirror errors cntl[0] = %x, cntl[1] = %x\n",
		flt_stat[0].mf_cntl, flt_stat[1].mf_cntl);

	if (ptrl_error) {
		if (((flt_stat[0].mf_cntl | flt_stat[1].mf_cntl)
			& MAC_CNTL_PTRL_ERRS) == 0)
			return (0);
	} else {
		if (((flt_stat[0].mf_cntl | flt_stat[1].mf_cntl)
			& MAC_CNTL_MI_ERRS) == 0)
			return (0);
	}

	/*
	 * First we take care of the case of CE
	 * because they can become UE or CMPE
	 */
	for (i = 0; i < 2; i++) {
		if (IS_CE_ONLY(flt_stat[i].mf_cntl, ptrl_error)) {
			MC_LOG("CE detected on bank %d\n",
				flt_stat[i].mf_flt_maddr.ma_bank);
			mc_scrub_ce(mcp, flt_stat[i].mf_flt_maddr.ma_bank,
				&flt_stat[i], ptrl_error);
			rv = 1;
		}
	}

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
			MC_LOG("cmpe error detected\n");
			mc_aflt->mflt_nflts = 2;
			mc_aflt->mflt_stat[0] = &flt_stat[0];
			mc_aflt->mflt_stat[1] = &flt_stat[1];
			mc_aflt->mflt_pr = PR_UE;
			mc_err_drain(mc_aflt);
			return (1);
		}

		if (IS_UE(flt_stat[0].mf_cntl, ptrl_error) &&
			IS_UE(flt_stat[1].mf_cntl, ptrl_error)) {
			/* Both side are UE's */

			MAC_SET_ERRLOG_INFO(&flt_stat[0]);
			MAC_SET_ERRLOG_INFO(&flt_stat[1]);
			MC_LOG("MUE detected\n");
			flt_stat[0].mf_type = flt_stat[1].mf_type =
				FLT_TYPE_MUE;
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
			/* If we have CE, we would have done REW */
			if (IS_OK(flt_stat[i^1].mf_cntl, ptrl_error)) {
				(void) do_rewrite(mcp,
				    flt_stat[i].mf_flt_maddr.ma_bank,
				    flt_stat[i].mf_flt_maddr.ma_dimm_addr);
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
			MC_LOG("cmpe error detected\n");
			mc_aflt->mflt_nflts = 1;
			mc_aflt->mflt_stat[0] = &flt_stat[i];
			mc_aflt->mflt_pr = PR_UE;
			mc_err_drain(mc_aflt);
			/* no more report on this bank */
			flt_stat[i].mf_cntl = 0;
			rv = 1;
		    }
		}

		for (i = 0; i < 2; i++) {
		    if (IS_UE(flt_stat[i].mf_cntl, ptrl_error)) {
			(void) do_rewrite(mcp,
				flt_stat[i].mf_flt_maddr.ma_bank,
				flt_stat[i].mf_flt_maddr.ma_dimm_addr);
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
mc_error_handler_mir(mc_opl_t *mcp, int bank, mc_addr_info_t *maddr)
{
	mc_aflt_t mc_aflt;
	mc_flt_stat_t flt_stat[2], mi_flt_stat[2];
	int other_bank;

	if (mc_stop(mcp, bank)) {
		cmn_err(CE_WARN, "Cannot stop Memory Patrol at /LSB%d/B%d\n",
			mcp->mc_board_num, bank);
		return;
	}
	bzero(&mc_aflt, sizeof (mc_aflt_t));
	bzero(&flt_stat, 2 * sizeof (mc_flt_stat_t));
	bzero(&mi_flt_stat, 2 * sizeof (mc_flt_stat_t));

	mc_aflt.mflt_mcp = mcp;
	mc_aflt.mflt_id = gethrtime();

	/* Now read all the registers into flt_stat */

	MC_LOG("Reading registers of bank %d\n", bank);
	/* patrol registers */
	mc_read_ptrl_reg(mcp, bank, &flt_stat[0]);

	ASSERT(maddr);
	maddr->mi_maddr = flt_stat[0].mf_flt_maddr;

	MC_LOG("ptrl registers cntl %x add %x log %x\n",
		flt_stat[0].mf_cntl,
		flt_stat[0].mf_err_add,
		flt_stat[0].mf_err_log);

	/* MI registers */
	mc_read_mi_reg(mcp, bank, &mi_flt_stat[0]);

	MC_LOG("MI registers cntl %x add %x log %x\n",
		mi_flt_stat[0].mf_cntl,
		mi_flt_stat[0].mf_err_add,
		mi_flt_stat[0].mf_err_log);

	other_bank = bank^1;

	MC_LOG("Reading registers of bank %d\n", other_bank);

	ASSERT(mcp->mc_bank[other_bank].mcb_status & BANK_INSTALLED);

	mc_read_ptrl_reg(mcp, other_bank, &flt_stat[1]);
	MC_LOG("ptrl registers cntl %x add %x log %x\n",
		flt_stat[1].mf_cntl,
		flt_stat[1].mf_err_add,
		flt_stat[1].mf_err_log);

	/* MI registers */
	mc_read_mi_reg(mcp, other_bank, &mi_flt_stat[1]);
	MC_LOG("MI registers cntl %x add %x log %x\n",
		mi_flt_stat[1].mf_cntl,
		mi_flt_stat[1].mf_err_add,
		mi_flt_stat[1].mf_err_log);

	/* clear errors once we read all the registers */
	MAC_CLEAR_ERRS(mcp, other_bank,
		(MAC_CNTL_PTRL_ERRS|MAC_CNTL_MI_ERRS));

	MAC_CLEAR_ERRS(mcp, bank, (MAC_CNTL_PTRL_ERRS|MAC_CNTL_MI_ERRS));

	/* Process PTRL errors first */

	/* if not error mode, cntl1 is 0 */
	if ((flt_stat[0].mf_err_add & MAC_ERR_ADD_INVALID) ||
		(flt_stat[0].mf_err_log & MAC_ERR_LOG_INVALID))
		flt_stat[0].mf_cntl = 0;

	if ((flt_stat[1].mf_err_add & MAC_ERR_ADD_INVALID) ||
		(flt_stat[1].mf_err_log & MAC_ERR_LOG_INVALID))
		flt_stat[1].mf_cntl = 0;

	mc_aflt.mflt_is_ptrl = 1;
	maddr->mi_valid = mc_process_error_mir(mcp, &mc_aflt, &flt_stat[0]);

	mc_aflt.mflt_is_ptrl = 0;
	mc_process_error_mir(mcp, &mc_aflt, &mi_flt_stat[0]);
}

static int
mc_process_error(mc_opl_t *mcp, int bank, mc_aflt_t *mc_aflt,
	mc_flt_stat_t *flt_stat)
{
	int ptrl_error = mc_aflt->mflt_is_ptrl;
	int rv = 0;

	mc_aflt->mflt_erpt_class = NULL;
	if (IS_UE(flt_stat->mf_cntl, ptrl_error)) {
		MC_LOG("UE deteceted\n");
		flt_stat->mf_type = FLT_TYPE_UE;
		mc_aflt->mflt_erpt_class = MC_OPL_UE;
		mc_aflt->mflt_pr = PR_UE;
		MAC_SET_ERRLOG_INFO(flt_stat);
		rv = 1;
	} else if (IS_CE(flt_stat->mf_cntl, ptrl_error)) {
		MC_LOG("CE deteceted\n");
		MAC_SET_ERRLOG_INFO(flt_stat);

		/* Error type can change after scrubing */
		mc_scrub_ce(mcp, bank, flt_stat, ptrl_error);

		if (flt_stat->mf_type == FLT_TYPE_PERMANENT_CE) {
			mc_aflt->mflt_erpt_class = MC_OPL_CE;
			mc_aflt->mflt_pr = PR_MCE;
		} else if (flt_stat->mf_type == FLT_TYPE_UE) {
			mc_aflt->mflt_erpt_class = MC_OPL_UE;
			mc_aflt->mflt_pr = PR_UE;
		}
		rv = 1;
	}
	MC_LOG("mc_process_error: fault type %x erpt %s\n",
		flt_stat->mf_type,
		mc_aflt->mflt_erpt_class);
	if (mc_aflt->mflt_erpt_class) {
		mc_aflt->mflt_stat[0] = flt_stat;
		mc_aflt->mflt_nflts = 1;
		mc_err_drain(mc_aflt);
	}
	return (rv);
}

static void
mc_error_handler(mc_opl_t *mcp, int bank, mc_addr_info_t *maddr)
{
	mc_aflt_t mc_aflt;
	mc_flt_stat_t flt_stat, mi_flt_stat;

	if (mc_stop(mcp, bank)) {
		cmn_err(CE_WARN, "Cannot stop Memory Patrol at /LSB%d/B%d\n",
			mcp->mc_board_num, bank);
		return;
	}

	bzero(&mc_aflt, sizeof (mc_aflt_t));
	bzero(&flt_stat, sizeof (mc_flt_stat_t));
	bzero(&mi_flt_stat, sizeof (mc_flt_stat_t));

	mc_aflt.mflt_mcp = mcp;
	mc_aflt.mflt_id = gethrtime();

	/* patrol registers */
	mc_read_ptrl_reg(mcp, bank, &flt_stat);

	ASSERT(maddr);
	maddr->mi_maddr = flt_stat.mf_flt_maddr;

	MC_LOG("ptrl registers cntl %x add %x log %x\n",
		flt_stat.mf_cntl,
		flt_stat.mf_err_add,
		flt_stat.mf_err_log);

	/* MI registers */
	mc_read_mi_reg(mcp, bank, &mi_flt_stat);

	MC_LOG("MI registers cntl %x add %x log %x\n",
		mi_flt_stat.mf_cntl,
		mi_flt_stat.mf_err_add,
		mi_flt_stat.mf_err_log);

	/* clear errors once we read all the registers */
	MAC_CLEAR_ERRS(mcp, bank, (MAC_CNTL_PTRL_ERRS|MAC_CNTL_MI_ERRS));

	mc_aflt.mflt_is_ptrl = 1;
	if ((flt_stat.mf_cntl & MAC_CNTL_PTRL_ERRS) &&
		((flt_stat.mf_err_add & MAC_ERR_ADD_INVALID) == 0) &&
		((flt_stat.mf_err_log & MAC_ERR_LOG_INVALID) == 0)) {
		maddr->mi_valid = mc_process_error(mcp, bank,
			&mc_aflt, &flt_stat);
	}
	mc_aflt.mflt_is_ptrl = 0;
	if ((mi_flt_stat.mf_cntl & MAC_CNTL_MI_ERRS) &&
		((mi_flt_stat.mf_err_add & MAC_ERR_ADD_INVALID) == 0) &&
		((mi_flt_stat.mf_err_log & MAC_ERR_LOG_INVALID) == 0)) {
		mc_process_error(mcp, bank, &mc_aflt, &mi_flt_stat);
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
 *	        -> mc_stop()
 *		-> read all error regsiters
 *	        -> mc_process_error()
 *	            determine error type
 *	            rewrite to clear error or scrub to determine CE type
 *	            inform SCF on permanent CE
 *	        -> mc_err_drain
 *	            page offline processing
 *	            -> mc_ereport_post()
 */

static void
mc_check_errors_func(mc_opl_t *mcp)
{
	mc_addr_info_t maddr_info;
	int i, error_count = 0;
	uint32_t stat, cntl;

	/*
	 * scan errors.
	 */
	for (i = 0; i < BANKNUM_PER_SB; i++) {
		if (mcp->mc_bank[i].mcb_status & BANK_INSTALLED) {
			stat = ldphysio(MAC_PTRL_STAT(mcp, i));
			cntl = ldphysio(MAC_PTRL_CNTL(mcp, i));
			if (cntl & MAC_CNTL_PTRL_ADD_MAX) {
				mcp->mc_period++;
				MC_LOG("mc period %ld on "
				    "/LSB%d/B%d\n", mcp->mc_period,
				    mcp->mc_board_num, i);
				MAC_CLEAR_MAX(mcp, i);
			}
			if (mc_debug_show_all) {
				MC_LOG("/LSB%d/B%d stat %x cntl %x\n",
					mcp->mc_board_num, i,
					stat, cntl);
			}
			if (stat & (MAC_STAT_PTRL_ERRS|MAC_STAT_MI_ERRS)) {
				maddr_info.mi_valid = 0;
				maddr_info.mi_advance = 1;
				if (IS_MIRROR(mcp, i))
					mc_error_handler_mir(mcp, i,
						&maddr_info);
				else
					mc_error_handler(mcp, i, &maddr_info);

				error_count++;
				restart_patrol(mcp, i, &maddr_info);
			} else {
				restart_patrol(mcp, i, NULL);
			}
		}
	}
	mc_process_scf_log(mcp);
	if (error_count > 0)
		mcp->mc_last_error += error_count;
	else
		mcp->mc_last_error = 0;
}

/* this is just a wrapper for the above func */

static void
mc_check_errors(void *arg)
{
	mc_opl_t *mcp = (mc_opl_t *)arg;
	clock_t interval;

	/*
	 * scan errors.
	 */
	mutex_enter(&mcp->mc_lock);
	mcp->mc_tid = 0;
	if ((mcp->mc_status & MC_POLL_RUNNING) &&
		!(mcp->mc_status & MC_SOFT_SUSPENDED)) {
		mc_check_errors_func(mcp);

		if (mcp->mc_last_error > 0) {
			interval = (mcp->mc_interval_hz) >> mcp->mc_last_error;
			if (interval < 1)
				interval = 1;
		} else
			interval = mcp->mc_interval_hz;

		mcp->mc_tid = timeout(mc_check_errors, mcp,
		    interval);
	}
	mutex_exit(&mcp->mc_lock);
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

static int
mc_valid_pa(mc_opl_t *mcp, uint64_t pa)
{
	struct memlist *ml;

	if (mcp->mlist == NULL)
		mc_get_mlist(mcp);

	for (ml = mcp->mlist; ml; ml = ml->next) {
		if (ml->address <= pa && pa < (ml->address + ml->size))
			return (1);
	}
	return (0);
}

static void
mc_memlist_delete(struct memlist *mlist)
{
	struct memlist *ml;

	for (ml = mlist; ml; ml = mlist) {
		mlist = ml->next;
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
	for (; mlist; mlist = mlist->next) {
		*mlp = kmem_alloc(sizeof (struct memlist), KM_SLEEP);
		(*mlp)->address = mlist->address;
		(*mlp)->size = mlist->size;
		(*mlp)->prev = tl;
		tl = *mlp;
		mlp = &((*mlp)->next);
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
	if ((end <= mlist->address) || (base == end))
		return (mlist);

	for (tl = ml = mlist; ml; tl = ml, ml = nlp) {
		uint64_t	mend;

		nlp = ml->next;

		if (end <= ml->address)
			break;

		mend = ml->address + ml->size;
		if (base < mend) {
			if (base <= ml->address) {
				ml->address = end;
				if (end >= mend)
					ml->size = 0ull;
				else
					ml->size = mend - ml->address;
			} else {
				ml->size = base - ml->address;
				if (end < mend) {
					struct memlist	*nl;
					/*
					 * splitting an memlist entry.
					 */
					nl = kmem_alloc(sizeof (struct memlist),
						KM_SLEEP);
					nl->address = end;
					nl->size = mend - nl->address;
					if ((nl->next = nlp) != NULL)
						nlp->prev = nl;
					nl->prev = ml;
					ml->next = nl;
					nlp = nl;
				}
			}
			if (ml->size == 0ull) {
				if (ml == mlist) {
					if ((mlist = nlp) != NULL)
						nlp->prev = NULL;
					kmem_free(ml, sizeof (struct memlist));
					if (mlist == NULL)
						break;
					ml = nlp;
				} else {
					if ((tl->next = nlp) != NULL)
						nlp->prev = tl;
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
			mlist = mc_memlist_del_span(mlist,
				startpa, endpa - startpa);
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
	int len, i, bk, cc;
	mc_addr_info_t maddr;
	uint32_t mirr;

	mutex_init(&mcp->mc_lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Get configurations from "pseudo-mc" node which includes:
	 * board# : LSB number
	 * mac-addr : physical base address of MAC registers
	 * csX-mac-pa-trans-table: translation table from DIMM address
	 *			to physical address or vice versa.
	 */
	mcp->mc_board_num = (int)ddi_getprop(DDI_DEV_T_ANY, mcp->mc_dip,
		DDI_PROP_DONTPASS, "board#", -1);

	/*
	 * Get start address in this CAB. It can be gotten from
	 * "sb-mem-ranges" property.
	 */

	if (get_base_address(mcp) == DDI_FAILURE) {
		mutex_destroy(&mcp->mc_lock);
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
		mutex_destroy(&mcp->mc_lock);
		return (DDI_FAILURE);
	}

	for (i = 0; i < len / sizeof (struct mc_addr_spec); i++) {
		struct mc_bank *bankp;
		uint32_t reg;

		/*
		 * setup bank
		 */
		bk = macaddr[i].bank;
		bankp = &(mcp->mc_bank[bk]);
		bankp->mcb_status = BANK_INSTALLED;
		bankp->mcb_reg_base = REGS_PA(macaddr, i);

		reg = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bk));
		bankp->mcb_ptrl_cntl = (reg & MAC_CNTL_PTRL_PRESERVE_BITS);

		/*
		 * check if mirror mode
		 */
		mirr = LD_MAC_REG(MAC_MIRR(mcp, bk));

		if (mirr & MAC_MIRR_MIRROR_MODE) {
			MC_LOG("Mirror -> /LSB%d/B%d\n",
				mcp->mc_board_num, bk);
			bankp->mcb_status |= BANK_MIRROR_MODE;
			/*
			 * The following bit is only used for
			 * error injection.  We should clear it
			 */
			if (mirr & MAC_MIRR_BANK_EXCLUSIVE)
				ST_MAC_REG(MAC_MIRR(mcp, bk),
					0);
		}

		/*
		 * restart if not mirror mode or the other bank
		 * of the mirror is not running
		 */
		if (!(mirr & MAC_MIRR_MIRROR_MODE) ||
			!(mcp->mc_bank[bk^1].mcb_status &
			BANK_PTRL_RUNNING)) {
			MC_LOG("Starting up /LSB%d/B%d\n",
				mcp->mc_board_num, bk);
			get_ptrl_start_address(mcp, bk, &maddr.mi_maddr);
			maddr.mi_valid = 1;
			maddr.mi_advance = 0;
			restart_patrol(mcp, bk, &maddr);
		} else {
			MC_LOG("Not starting up /LSB%d/B%d\n",
				mcp->mc_board_num, bk);
		}
		bankp->mcb_status |= BANK_PTRL_RUNNING;
	}
	kmem_free(macaddr, len);

	/*
	 * set interval in HZ.
	 */
	for (i = 0; i < BANKNUM_PER_SB; i++) {
		mcp->mc_scf_retry[i] = 0;
	}
	mcp->mc_last_error = 0;
	mcp->mc_period = 0;

	mcp->mc_interval_hz = drv_usectohz(mc_patrol_interval_sec * 1000000);
	/* restart memory patrol checking */
	mcp->mc_status |= MC_POLL_RUNNING;
	mcp->mc_tid = timeout(mc_check_errors, mcp, mcp->mc_interval_hz);

	return (DDI_SUCCESS);
}

int
mc_board_del(mc_opl_t *mcp)
{
	int i;
	scf_log_t *p;
	timeout_id_t tid = 0;

	/*
	 * cleanup mac state
	 */
	mutex_enter(&mcp->mc_lock);
	for (i = 0; i < BANKNUM_PER_SB; i++) {
		if (mcp->mc_bank[i].mcb_status & BANK_INSTALLED) {
			if (mc_stop(mcp, i)) {
				mutex_exit(&mcp->mc_lock);
				return (-1);
			}
			mcp->mc_bank[i].mcb_status &= ~BANK_INSTALLED;
		}
	}

	/* stop memory patrol checking */
	if (mcp->mc_status & MC_POLL_RUNNING) {
		mcp->mc_status &= ~MC_POLL_RUNNING;
		tid = mcp->mc_tid;
		mcp->mc_tid = 0;
	}

	/* just throw away all the scf logs */
	while ((p = mcp->mc_scf_log) != NULL) {
		mcp->mc_scf_log = p->sl_next;
		mcp->mc_scf_total--;
		kmem_free(p, sizeof (scf_log_t));
	}

	if (mcp->mlist)
		mc_memlist_delete(mcp->mlist);

	mutex_exit(&mcp->mc_lock);
	if (tid)
		(void) untimeout(tid);

	mutex_destroy(&mcp->mc_lock);
	return (DDI_SUCCESS);
}

int
mc_suspend(mc_opl_t *mcp, uint32_t flag)
{
	timeout_id_t tid = 0;
	int i;
	/* stop memory patrol checking */
	mutex_enter(&mcp->mc_lock);
	if (mcp->mc_status & MC_POLL_RUNNING) {
		for (i = 0; i < BANKNUM_PER_SB; i++) {
			if (mcp->mc_bank[i].mcb_status & BANK_INSTALLED) {
				if (mc_stop(mcp, i)) {
					mutex_exit(&mcp->mc_lock);
					return (-1);
				}
			}
		}
		mcp->mc_status &= ~MC_POLL_RUNNING;
		tid = mcp->mc_tid;
	}
	mcp->mc_status |= flag;
	mcp->mc_tid = 0;
	mutex_exit(&mcp->mc_lock);
	if (tid)
		(void) untimeout(tid);

	return (DDI_SUCCESS);
}

/* caller must clear the SUSPEND bits or this will do nothing */

int
mc_resume(mc_opl_t *mcp, uint32_t flag)
{
	int i;
	uint64_t basepa;

	mutex_enter(&mcp->mc_lock);
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
	mcp->mc_list->mc_start_address = mcp->mc_start_address;

	if (mcp->mc_status & (MC_SOFT_SUSPENDED | MC_DRIVER_SUSPENDED)) {
		mutex_exit(&mcp->mc_lock);
		return (DDI_SUCCESS);
	}

	if (!(mcp->mc_status & MC_POLL_RUNNING)) {
		/* restart memory patrol checking */
		mcp->mc_status |= MC_POLL_RUNNING;
		for (i = 0; i < BANKNUM_PER_SB; i++) {
			if (mcp->mc_bank[i].mcb_status & BANK_INSTALLED) {
				restart_patrol(mcp, i, NULL);
			}
		}
		/* check error asap */
		mcp->mc_tid = timeout(mc_check_errors, mcp, 1);
	}
	mutex_exit(&mcp->mc_lock);

	return (DDI_SUCCESS);
}

static mc_opl_t *
mc_pa_to_mcp(uint64_t pa)
{
	mc_inst_list_t *p;
	ASSERT(MUTEX_HELD(&mcmutex));
	for (p = mc_instances; p; p = p->next) {
		/* if mac patrol is suspended, we cannot rely on it */
		if (!(p->mc_opl->mc_status & MC_POLL_RUNNING) ||
			(p->mc_opl->mc_status & MC_SOFT_SUSPENDED))
			continue;
		if ((p->mc_start_address <= pa) &&
			(pa < (p->mc_start_address + p->mc_size))) {
			return (p->mc_opl);
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
	mc_opl_t *mcp;
	int bank;
	int sb;

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
	sb = mc_opl_get_physical_board(mcp->mc_board_num);

	if (sb == -1) {
		mutex_exit(&mcmutex);
		return (ENXIO);
	}

	if (snprintf(buf, buflen, "/CMU%d/B%d", sb, bank) >= buflen) {
		mutex_exit(&mcmutex);
		return (ENOSPC);
	} else {
		if (lenp)
			*lenp = strlen(buf);
	}
	mutex_exit(&mcmutex);
	return (0);
}

int
opl_mc_suspend()
{
	mc_opl_t *mcp;
	mc_inst_list_t *p;

	mutex_enter(&mcmutex);

	for (p = mc_instances; p; p = p->next) {
		mcp = p->mc_opl;
		(void) mc_suspend(mcp, MC_SOFT_SUSPENDED);
	}

	mutex_exit(&mcmutex);
	return (0);
}

int
opl_mc_resume()
{
	mc_opl_t *mcp;
	mc_inst_list_t *p;

	mutex_enter(&mcmutex);

	for (p = mc_instances; p; p = p->next) {
		mcp = p->mc_opl;
		(void) mc_resume(mcp, MC_SOFT_SUSPENDED);
	}

	mutex_exit(&mcmutex);
	return (0);
}

static void
insert_mcp(mc_opl_t *mcp)
{
	mc_inst_list_t	*p;

	p = kmem_zalloc(sizeof (mc_inst_list_t), KM_SLEEP);
	p->mc_opl = mcp;
	p->mc_board_num = mcp->mc_board_num;
	p->mc_start_address = mcp->mc_start_address;
	p->mc_size = mcp->mc_size;
	mcp->mc_list = p;

	mutex_enter(&mcmutex);

	p->next = mc_instances;
	mc_instances = p;

	mutex_exit(&mcmutex);
}

static void
delete_mcp(mc_opl_t *mcp)
{
	mc_inst_list_t *prev, *current;
	mc_inst_list_t *p;

	p = mcp->mc_list;

	if (mc_instances == p) {
		mc_instances = p->next;
		kmem_free(p, sizeof (mc_inst_list_t));
		return;
	}
	prev = mc_instances;
	for (current = mc_instances; current != NULL; current = current->next) {
		if (current == p) {
			prev->next = p->next;
			kmem_free(p, sizeof (mc_inst_list_t));
			return;
		}
		prev = current;
	}
}

/* Error injection interface */

/* ARGSUSED */
int
mc_inject_error(int error_type, uint64_t pa, uint32_t flags)
{
	mc_opl_t *mcp;
	int bank;
	uint32_t dimm_addr;
	uint32_t cntl;
	mc_addr_info_t maddr;
	uint32_t data, stat;
	int both_sides = 0;
	uint64_t pa0;
	on_trap_data_t otd;
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

	MC_LOG("injecting error to /LSB%d/B%d/D%x\n",
		mcp->mc_board_num, bank, dimm_addr);


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
		ST_MAC_REG(MAC_EG_ADD(mcp, bank^1),
			dimm_addr & MAC_EG_ADD_MASK);
	}

	switch (error_type) {
	case MC_INJECT_UE:
	case MC_INJECT_SUE:
	case MC_INJECT_MUE:
		if (flags & MC_INJECT_FLAG_PATH) {
			cntl = MAC_EG_ADD_FIX
				|MAC_EG_FORCE_READ00|MAC_EG_FORCE_READ16
				|MAC_EG_DERR_ONCE;
		} else {
			cntl = MAC_EG_ADD_FIX|MAC_EG_FORCE_DERR00
				|MAC_EG_FORCE_DERR16|MAC_EG_DERR_ONCE;
		}
		flags |= MC_INJECT_FLAG_ST;
		break;
	case MC_INJECT_INTERMITTENT_CE:
	case MC_INJECT_INTERMITTENT_MCE:
		if (flags & MC_INJECT_FLAG_PATH) {
			cntl = MAC_EG_ADD_FIX
				|MAC_EG_FORCE_READ00
				|MAC_EG_DERR_ONCE;
		} else {
			cntl = MAC_EG_ADD_FIX
				|MAC_EG_FORCE_DERR16
				|MAC_EG_DERR_ONCE;
		}
		flags |= MC_INJECT_FLAG_ST;
		break;
	case MC_INJECT_PERMANENT_CE:
	case MC_INJECT_PERMANENT_MCE:
		if (flags & MC_INJECT_FLAG_PATH) {
			cntl = MAC_EG_ADD_FIX
				|MAC_EG_FORCE_READ00
				|MAC_EG_DERR_ALWAYS;
		} else {
			cntl = MAC_EG_ADD_FIX
				|MAC_EG_FORCE_DERR16
				|MAC_EG_DERR_ALWAYS;
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

	delay(inject_op_delay * drv_usectohz(1000 * 1000));


	if (flags & MC_INJECT_FLAG_LD) {
		if (flags & MC_INJECT_FLAG_NO_TRAP) {
			if (on_trap(&otd, OT_DATA_EC)) {
				no_trap();
				MC_LOG("Trap occurred\n");
			} else {
				MC_LOG("On-trap Reading from %lx\n", pa);
				data = ldphys(pa);
				no_trap();
				MC_LOG("data = %x\n", data);
			}
		} else {
			MC_LOG("Reading from %lx\n", pa);
			data = ldphys(pa);
			MC_LOG("data = %x\n", data);
		}
	}

	if (flags & MC_INJECT_FLAG_RESTART) {
		delay(inject_op_delay * drv_usectohz(1000 * 1000));

		MC_LOG("Restart patrol\n");
		if (mc_stop(mcp, bank)) {
			cmn_err(CE_WARN, "Cannot stop Memory Patrol at "
				"/LSB%d/B%d\n", mcp->mc_board_num, bank);
			mutex_exit(&mcp->mc_lock);
			return (EIO);
		}
		maddr.mi_maddr.ma_bd = mcp->mc_board_num;
		maddr.mi_maddr.ma_bank = bank;
		maddr.mi_maddr.ma_dimm_addr = dimm_addr;
		maddr.mi_valid = 1;
		maddr.mi_advance = 0;
		restart_patrol(mcp, bank, &maddr);
	}

	if (flags & MC_INJECT_FLAG_POLL) {
		delay(inject_op_delay * drv_usectohz(1000 * 1000));

		MC_LOG("Poll patrol error\n");
		stat = LD_MAC_REG(MAC_PTRL_STAT(mcp, bank));
		cntl = LD_MAC_REG(MAC_PTRL_CNTL(mcp, bank));
		if (stat & (MAC_STAT_PTRL_ERRS|MAC_STAT_MI_ERRS)) {
			maddr.mi_valid = 0;
			maddr.mi_advance = 1;
			if (IS_MIRROR(mcp, bank))
				mc_error_handler_mir(mcp, bank,
					&maddr);
			else
				mc_error_handler(mcp, bank, &maddr);

			restart_patrol(mcp, bank, &maddr);
		} else
			restart_patrol(mcp, bank, NULL);
	}

	mutex_exit(&mcp->mc_lock);
	return (0);
}

void
mc_stphysio(uint64_t pa, uint32_t data)
{
	MC_LOG("0x%x -> pa(%lx)\n", data, pa);
	stphysio(pa, data);
}

uint32_t
mc_ldphysio(uint64_t pa)
{
	uint32_t rv;

	rv = ldphysio(pa);
	MC_LOG("pa(%lx) = 0x%x\n", pa, rv);
	return (rv);
}
