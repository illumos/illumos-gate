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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/autoconf.h>
#include <sys/modctl.h>
#include <sys/sunndi.h>

#include <sys/axq.h>
#include <sys/promif.h>
#include <sys/cpuvar.h>
#include <sys/starcat.h>
#include <sys/callb.h>

#define	REG_ADDR(b, o)	(uint32_t *)((caddr_t)(b) + (o))

/*
 * Function prototypes
 */

/* autoconfig entry point function definitions */
static int axq_attach(dev_info_t *, ddi_attach_cmd_t);
static int axq_detach(dev_info_t *, ddi_detach_cmd_t);
static int axq_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

/* internal axq definitions */
static void axq_init(struct axq_soft_state *);
static void axq_init_local(struct axq_local_regs *);

/* axq kstats */
static void axq_add_picN_kstats(dev_info_t *dip);
static void axq_add_kstats(struct axq_soft_state *);
static int axq_counters_kstat_update(kstat_t *, int);

/*
 * Configuration data structures
 */
static struct cb_ops axq_cb_ops = {
	nulldev,			/* open */
	nulldev,			/* close */
	nulldev,			/* strategy */
	nulldev,			/* print */
	nodev,				/* dump */
	nulldev,			/* read */
	nulldev,			/* write */
	nulldev,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_MP | D_NEW,			/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* cb_aread */
	nodev				/* cb_awrite */
};

static struct dev_ops axq_ops = {
	DEVO_REV,			/* rev */
	0,				/* refcnt  */
	axq_getinfo,			/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	axq_attach,			/* attach */
	axq_detach,			/* detach */
	nulldev,			/* reset */
	&axq_cb_ops,			/* cb_ops */
	(struct bus_ops *)0,		/* bus_ops */
	nulldev,			/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};


/*
 * AXQ globals
 */
struct axq_soft_state *axq_array[AXQ_MAX_EXP][AXQ_MAX_SLOT_PER_EXP];
krwlock_t axq_array_lock;
struct axq_local_regs axq_local;
int use_axq_iopause = 1;	/* enable flag axq iopause by default */
/*
 * If non-zero, iopause will be asserted during DDI_SUSPEND.
 * Clients using the axq_iopause_*_all interfaces should set this to zero.
 */
int axq_suspend_iopause = 1;

/*
 * loadable module support
 */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"AXQ driver",	/* name of module */
	&axq_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

static void *axq_softp;

/*
 * AXQ Performance counters
 * We statically declare a array of the known
 * AXQ event-names and event masks. The number
 * of events in this array is AXQ_NUM_EVENTS.
 */
static axq_event_mask_t axq_events[AXQ_NUM_EVENTS] = {
	{"count_clk", COUNT_CLK}, {"freeze_cnt", FREEZE_CNT},
	{"ha_input_fifo", HA_INPUT_FIFO}, {"ha_intr_info", HA_INTR_INFO},
	{"ha_pio_fifo", HA_PIO_FIFO}, {"ha_adr_fifo_lk3", HA_ADR_FIFO_LK3},
	{"ha_adr_fifo_lk2", HA_ADR_FIFO_LK2},
	{"ha_adr_fifo_lk1", HA_ADR_FIFO_LK1},
	{"ha_adr_fifo_lk0", HA_ADR_FIFO_LK0},
	{"ha_dump_q", HA_DUMP_Q},
	{"ha_rd_f_stb_q", HA_RD_F_STB_Q},
	{"ha_dp_wr_q", HA_DP_WR_Q},
	{"ha_int_q", HA_INT_Q},
	{"ha_wrb_q", HA_WRB_Q},
	{"ha_wr_mp_q", HA_WR_MP_Q},
	{"ha_wrtag_q", HA_WRTAG_Q},
	{"ha_wt_wait_fifo", HA_WT_WAIT_FIFO},
	{"ha_wrb_stb_fifo", HA_WRB_STB_FIFO},
	{"ha_ap0_q", HA_AP0_Q},
	{"ha_ap1_q", HA_AP1_Q},
	{"ha_new_wr_q", HA_NEW_WR_Q},
	{"ha_dp_rd_q", HA_DP_RD_Q},
	{"ha_unlock_q", HA_UNLOCK_Q},
	{"ha_cdc_upd_q", HA_CDC_UPD_Q},
	{"ha_ds_q", HA_DS_Q},
	{"ha_unlk_wait_q", HA_UNLK_WAIT_Q},
	{"ha_rd_mp_q", HA_RD_MP_Q},
	{"l2_io_q", L2_IO_Q},
	{"l2_sb_q", L2_SB_Q},
	{"l2_ra_q", L2_RA_Q},
	{"l2_ha_q", L2_HA_Q},
	{"l2_sa_q", L2_SA_Q},
	{"ra_wait_fifo", RA_WAIT_FIFO},
	{"ra_wrb_inv_fifo", RA_WRB_INV_FIFO},
	{"ra_wrb_fifo", RA_WRB_FIFO},
	{"ra_cc_ptr_fifo", RA_CC_PTR_FIFO},
	{"ra_io_ptr_fifo", RA_IO_PTR_FIFO},
	{"ra_int_ptr_fifo", RA_INT_PTR_FIFO},
	{"ra_rp_q", RA_RP_Q},
	{"ra_wrb_rp_q", RA_WRB_RP_Q},
	{"ra_dp_q", RA_DP_Q},
	{"ra_dp_stb_q", RA_DP_STB_Q},
	{"ra_gtarg_q", RA_GTARG_Q},
	{"sdc_recv_q",	SDC_RECV_Q},
	{"sdc_redir_io_q", SDC_REDIR_IO_Q},
	{"sdc_redir_sb_q", SDC_REDIR_SB_Q},
	{"sdc_outb_io_q", SDC_OUTB_IO_Q},
	{"sdc_outb_sb_q", SDC_OUTB_SB_Q},
	{"sa_add1_input_q", SA_ADD1_INPUT_Q},
	{"sa_add2_input_q", SA_ADD2_INPUT_Q},
	{"sa_inv_q", SA_INV_Q},
	{"sa_no_inv_q", SA_NO_INV_Q},
	{"sa_int_dp_q", SA_INT_DP_Q},
	{"sa_dp_q", SA_DP_Q},
	{"sl_wrtag_q", SL_WRTAG_Q},
	{"sl_rto_dp_q", SL_RTO_DP_Q},
	{"syreg_input_q", SYSREG_INPUT_Q},
	{"sdi_sys_status1", SDI_SYS_STATUS1},
	{"sdi_sys_status0", SDI_SYS_STATUS0},
	{"cdc_hits", CDC_HITS},
	{"total_cdc_read", TOTAL_CDC_READ},
	{"ha_watranid_sd", HA_WATRANID_SD},
	{"ha_stb_sd", HA_STB_SD},
	{"ha_l2_irq_sd", HA_L2_IRQ_SD},
	{"ha_sl_wrtag_sd", HA_SL_WRTAG_SD},
	{"aa_home_cc_full", AA_HOME_CC_FULL},
	{"aa_home_io_full", AA_HOME_IO_FULL},
	{"aa_slave_full", AA_SLAVE_FULL},
	{"aa_rp_full", AA_RP_FULL}
};

static kstat_t *axq_picN_ksp[AXQ_NUM_PICS];	/* picN kstats */
static int axq_attachcnt = 0;		/* # of instances attached */
static kmutex_t axq_attachcnt_lock;	/* lock for attachcnt */

static int axq_map_phys(dev_info_t *, struct regspec *,  caddr_t *,
    ddi_device_acc_attr_t *, ddi_acc_handle_t *);
static void axq_unmap_phys(ddi_acc_handle_t *);

int starcat_axq_pio_workaround(dev_info_t *);
static int axq_slot1_idle(struct axq_soft_state *);

static boolean_t axq_panic_callb(void *, int);
static callb_id_t axq_panic_cb_id;

/*
 * These are the module initialization routines.
 */

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&axq_softp,
	    sizeof (struct axq_soft_state), 1)) != 0)
		return (error);

	rw_init(&axq_array_lock, NULL, RW_DEFAULT, NULL);

	mutex_init(&axq_local.axq_local_lock, NULL, MUTEX_DRIVER, NULL);

	mutex_init(&axq_attachcnt_lock, NULL, MUTEX_DRIVER, NULL);

	axq_local.initflag = 0;

	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&axq_softp);
		mutex_destroy(&axq_attachcnt_lock);
		mutex_destroy(&axq_local.axq_local_lock);
		rw_destroy(&axq_array_lock);
		return (error);
	}

	axq_panic_cb_id = callb_add(axq_panic_callb, (void *)NULL,
	    CB_CL_PANIC, "axq_panic");

	return (0);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	ddi_soft_state_fini(&axq_softp);
	mutex_destroy(&axq_attachcnt_lock);
	mutex_destroy(&axq_local.axq_local_lock);
	rw_destroy(&axq_array_lock);

	(void) callb_delete(axq_panic_cb_id);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
axq_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance;
	struct axq_soft_state *softsp;
	ddi_device_acc_attr_t attr;
	extern uint64_t va_to_pa(void *);

	instance = ddi_get_instance(devi);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		/*
		 * Reenable the axq io pause if it is
		 * employed. See the DDI_SUSPEND comments
		 */
		softsp = ddi_get_soft_state(axq_softp, instance);
		if (softsp->slotnum && softsp->paused && use_axq_iopause &&
		    axq_suspend_iopause) {
			*softsp->axq_domain_ctrl &= ~AXQ_DOMCTRL_PAUSE;
			softsp->paused = 0;
		}
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(axq_softp, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	softsp = ddi_get_soft_state(axq_softp, instance);

	/* Set the dip in the soft state */
	softsp->dip = devi;

	/* Get the "portid" property */
	if ((softsp->portid = (int)ddi_getprop(DDI_DEV_T_ANY, softsp->dip,
	    DDI_PROP_DONTPASS, "portid", -1)) == -1) {
		cmn_err(CE_WARN, "Unable to retrieve safari portid"
		    "property.");
		goto bad;
	}

	softsp->expid = softsp->portid >> 5;

	/*
	 * derive the slot # from the portid - for starcat, it is
	 * either 0 or 1 based on the lsb of the axq portid.
	 */
	softsp->slotnum = softsp->portid & 0x1;

	/*
	 * map in the regs. There are two regspecs - one
	 * in safari config space and the other in local space.
	 */
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	if (ddi_regs_map_setup(softsp->dip, 0, &softsp->address, 0, 0,
	    &attr, &softsp->ac0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: unable to map reg set 0\n",
		    ddi_get_name(softsp->dip),
		    ddi_get_instance(softsp->dip));
		goto bad;
	}

	/*
	 * This is a hack for support DR copy rename scripting
	 * Get the physical address of the start of the
	 * AXQ config space and save it.
	 */
	softsp->axq_phyaddr = va_to_pa((caddr_t)softsp->address);

	axq_init(softsp);

	/*
	 * Map in the regs for local space access
	 * This is global for all axq instances.
	 * Make sure that some axq instance does
	 * it for the rest of the gang..
	 * Note that this mapping is never removed.
	 */
	mutex_enter(&axq_local.axq_local_lock);
	if (!axq_local.initflag) {
		/* initialize and map in the local space */
		if (ddi_regs_map_setup(softsp->dip, 1,
		    &axq_local.laddress, 0, 0,
		    &attr, &axq_local.ac) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: unable to map reg set 1\n",
			    ddi_get_name(softsp->dip),
			    ddi_get_instance(softsp->dip));
			ddi_regs_map_free(&softsp->ac0);
			mutex_exit(&axq_local.axq_local_lock);
			goto bad;
		}
		axq_init_local(&axq_local);
		axq_local.initflag = 1;
	}
	mutex_exit(&axq_local.axq_local_lock);

	mutex_init(&softsp->axq_lock, NULL, MUTEX_DRIVER, NULL);

	/* update the axq array for this new instance */
	rw_enter(&axq_array_lock, RW_WRITER);
	ASSERT(axq_array[softsp->expid][softsp->slotnum] == NULL);
	axq_array[softsp->expid][softsp->slotnum] = softsp;
	rw_exit(&axq_array_lock);

	axq_add_kstats(softsp);

	ddi_report_dev(devi);

	return (DDI_SUCCESS);

bad:
	ddi_soft_state_free(axq_softp, instance);
	return (DDI_FAILURE);
}


static void
axq_init(struct axq_soft_state *softsp)
{
	int i;

	/*
	 * Setup the AXQ registers
	 * Some offsets and availability are dependent on the slot type
	 */
	if (softsp->slotnum == 0) {
		/* This is a slot type 0 AXQ */
		softsp->axq_domain_ctrl = REG_ADDR(softsp->address,
		    AXQ_SLOT0_DOMCTRL);
		softsp->axq_cdc_addrtest = REG_ADDR(softsp->address,
		    AXQ_SLOT0_CDC_ADR_TEST);
		softsp->axq_cdc_ctrltest = REG_ADDR(softsp->address,
		    AXQ_SLOT0_CDC_CTL_TEST);
		softsp->axq_cdc_datawrite0 = REG_ADDR(softsp->address,
		    AXQ_SLOT0_CDC_DATA_WR0);
		softsp->axq_cdc_datawrite1 = REG_ADDR(softsp->address,
		    AXQ_SLOT0_CDC_DATA_WR1);
		softsp->axq_cdc_datawrite2 = REG_ADDR(softsp->address,
		    AXQ_SLOT0_CDC_DATA_WR2);
		softsp->axq_cdc_datawrite3 = REG_ADDR(softsp->address,
		    AXQ_SLOT0_CDC_DATA_WR3);
		softsp->axq_cdc_counter = REG_ADDR(softsp->address,
		    AXQ_SLOT0_CDC_CNT_TEST);
		softsp->axq_cdc_readdata0 = REG_ADDR(softsp->address,
		    AXQ_SLOT0_CDC_RD_DATA0);
		softsp->axq_cdc_readdata1 = REG_ADDR(softsp->address,
		    AXQ_SLOT0_CDC_RD_DATA1);
		softsp->axq_cdc_readdata2 = REG_ADDR(softsp->address,
		    AXQ_SLOT0_CDC_RD_DATA2);
		softsp->axq_cdc_readdata3 = REG_ADDR(softsp->address,
		    AXQ_SLOT0_CDC_RD_DATA3);
		softsp->axq_pcr = REG_ADDR(softsp->address,
		    AXQ_SLOT0_PERFCNT_SEL);
		softsp->axq_pic0 = REG_ADDR(softsp->address,
		    AXQ_SLOT0_PERFCNT0);
		softsp->axq_pic1 = REG_ADDR(softsp->address,
		    AXQ_SLOT0_PERFCNT1);
		softsp->axq_pic2 = REG_ADDR(softsp->address,
		    AXQ_SLOT0_PERFCNT2);
		softsp->axq_nasm = REG_ADDR(softsp->address, AXQ_SLOT0_NASM);
	} else {
		/* slot type 1 AXQ */
		softsp->axq_domain_ctrl = REG_ADDR(softsp->address,
		    AXQ_SLOT1_DOMCTRL);
		softsp->axq_pcr = REG_ADDR(softsp->address,
		    AXQ_SLOT1_PERFCNT_SEL);
		softsp->axq_pic0 = REG_ADDR(softsp->address,
		    AXQ_SLOT1_PERFCNT0);
		softsp->axq_pic1 = REG_ADDR(softsp->address,
		    AXQ_SLOT1_PERFCNT1);
		softsp->axq_pic2 = REG_ADDR(softsp->address,
		    AXQ_SLOT1_PERFCNT2);
		softsp->axq_nasm = REG_ADDR(softsp->address, AXQ_SLOT1_NASM);
	}

	/* setup CASM slots */
	for (i = 0; i < AXQ_MAX_EXP; i++) {
		softsp->axq_casm_slot[i] = REG_ADDR(softsp->address,
		    (AXQ_CASM_SLOT_START + AXQ_REGOFF(i)));
	}

	/* setup SDI timeout register accesses */
	softsp->axq_sdi_timeout_rd = REG_ADDR(softsp->address,
	    AXQ_SLOT_SDI_TIMEOUT_RD);
	softsp->axq_sdi_timeout_rdclr = REG_ADDR(softsp->address,
	    AXQ_SLOT_SDI_TIMEOUT_RDCLR);

	/*
	 * Save the CDC state (enabled or disabled)
	 * as originally setup by Post.
	 */
	if (softsp->slotnum == 0) {
		softsp->axq_cdc_state = *softsp->axq_cdc_ctrltest &
		    AXQ_CDC_DIS;
	}

#ifndef _AXQ_LOCAL_ACCESS_SUPPORTED
	/*
	 * Setup cpu2ssc intr register in explicit expander
	 * space. Local space addressing for this is broken,
	 * we'll use explicit addressing for now.
	 */
	softsp->axq_cpu2ssc_intr = REG_ADDR(softsp->address,
	    AXQ_SLOT_CPU2SSC_INTR);
#endif /* _AXQ_LOCAL_ACCESS_SUPPORTED */
}


static void
axq_init_local(struct axq_local_regs *localregs)
{
	/*
	 * local access to cpu2ssc intr register will
	 * be the only one that may work properly in the
	 * next revision of the AXQ asics.
	 * Set it up here for now.
	 */
	localregs->axq_cpu2ssc_intr = REG_ADDR(localregs->laddress,
	    AXQ_SLOT_CPU2SSC_INTR);
}

/* ARGSUSED */
static int
axq_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	int i;
	struct axq_soft_state *softsp;
	processorid_t cpuid;

	/* get the instance of this devi */
	instance = ddi_get_instance(devi);

	/* get the soft state pointer for this device node */
	softsp = ddi_get_soft_state(axq_softp, instance);

	switch (cmd) {
	case DDI_SUSPEND:
		/*
		 * Depending on the variable "use_axq_iopause"
		 * we set the axq iopause bit as a paranoid
		 * safety net. This is assuming all the devices
		 * associated with the slot are already suspended.
		 * Care must be taken to not set iopause when CPUs
		 * are known to be present on the slot 1 board,
		 * i.e. MCPU board type.
		 * This io pause bit only applies to slot 1 axq,
		 */
		if (softsp->slotnum && use_axq_iopause && axq_suspend_iopause) {
			/*
			 * Do not enable AXQ_DOMCTRL_PAUSE if CPUs are
			 * known to be present in slot 1.
			 */
			mutex_enter(&cpu_lock);
			for (i = 0; i < STARCAT_SLOT1_CPU_MAX; i++) {
				cpuid = MAKE_CPUID(softsp->expid,
				    softsp->slotnum, i);
				if (cpu[cpuid]) {
					mutex_exit(&cpu_lock);
					return (DDI_SUCCESS);
				}
			}
			mutex_exit(&cpu_lock);

			/*
			 * Make sure that there is no outstanding
			 * I/O activity by reading the domain ctrl reg.
			 * A non-zero lsb indicates no I/O activity.
			 */
			if (axq_slot1_idle(softsp) == DDI_FAILURE) {
				cmn_err(CE_WARN, "%s%d: busy! suspend failed",
				    ddi_get_name(softsp->dip),
				    ddi_get_instance(softsp->dip));
				return (DDI_FAILURE);
			}

			*softsp->axq_domain_ctrl |= AXQ_DOMCTRL_PAUSE;
			softsp->paused = 1;
		}
		return (DDI_SUCCESS);

	case DDI_DETACH:
		rw_enter(&axq_array_lock, RW_WRITER);
		ASSERT(axq_array[softsp->expid][softsp->slotnum]
		    != NULL);
		axq_array[softsp->expid][softsp->slotnum] = NULL;
		rw_exit(&axq_array_lock);

		ddi_regs_map_free(&softsp->ac0);

		/*
		 * remove counter kstats for this device
		 */
		if (softsp->axq_counters_ksp != (kstat_t *)NULL) {
			kstat_delete(softsp->axq_counters_ksp);
		}

		/*
		 * See if we are the last instance to detach.
		 * If so, we need to remove the picN kstats
		 */
		mutex_enter(&axq_attachcnt_lock);
		if (--axq_attachcnt == 0) {
			for (i = 0; i < AXQ_NUM_PICS; i++) {
				if (axq_picN_ksp[i] != (kstat_t *)NULL) {
					kstat_delete(axq_picN_ksp[i]);
					axq_picN_ksp[i] = NULL;
				}
			}
		}
		mutex_exit(&axq_attachcnt_lock);

		ddi_soft_state_free(axq_softp, instance);

		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}


/* ARGSUSED0 */
static int
axq_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t dev = (dev_t)arg;
	struct axq_soft_state *softsp;
	int instance, ret;

	instance = getminor(dev);

	switch (infocmd) {
		case DDI_INFO_DEVT2DEVINFO:
			softsp = (struct axq_soft_state *)
			    ddi_get_soft_state(axq_softp, instance);
			if (softsp == NULL) {
				ret = DDI_FAILURE;
			} else {
				*result = softsp->dip;
				ret = DDI_SUCCESS;
			}
			break;
		case DDI_INFO_DEVT2INSTANCE:
			*result = (void *)(uintptr_t)instance;
			ret = DDI_SUCCESS;
			break;
		default:
			ret = DDI_FAILURE;
			break;
	}
	return (ret);
}

/*
 * Flush the CDC Sram of the slot0 axq
 * indicated by the expid argument
 */
int
axq_cdc_flush(uint32_t expid, int held, int disabled)
{
	struct axq_soft_state *softsp;
	uint32_t axq_ctrl_test_save0;
	uint32_t tmpval;
	int retval = 0;
	int i;

	if (!held)
		rw_enter(&axq_array_lock, RW_READER);

	ASSERT(axq_array[expid][SLOT0_AXQ] != NULL);

	softsp = axq_array[expid][SLOT0_AXQ];

	mutex_enter(&softsp->axq_lock);

	/* save the value of the ctrl test reg */
	axq_ctrl_test_save0 = *softsp->axq_cdc_ctrltest;

	/* disable sram and setup the ctrl test reg for flushing */
	tmpval = axq_ctrl_test_save0 & (AXQ_CDC_DATA_ECC_CHK_EN |
	    AXQ_CDC_ADR_PAR_CHK_EN |
	    AXQ_CDC_DATA_ECC_GEN_EN |
	    AXQ_CDC_ADR_PAR_GEN_EN);
	*softsp->axq_cdc_ctrltest = tmpval | AXQ_CDC_TMODE_WR
	    | AXQ_CDC_DATA2PAR_MUX_SEL_DATA
	    | AXQ_CDC_ADR2SRAM_MUX_SEL_TEST
	    | AXQ_CDC_ADR_INCR_XOR_CTRL
	    | AXQ_CDC_DIS;

	/* Enable CDC test in the CDC Address test reg */
	*softsp->axq_cdc_addrtest = AXQ_CDC_ADR_TEST_EN;

	/* clear the CDC Data write regs */
	*softsp->axq_cdc_datawrite0 = *softsp->axq_cdc_datawrite1 = 0;
	*softsp->axq_cdc_datawrite2 = *softsp->axq_cdc_datawrite3 = 0;

	/*
	 * write in the size of the sram to clear
	 * into the CDC Counter test reg
	 */
	*softsp->axq_cdc_counter = AXQ_CDC_SRAM_SIZE;

	/* wait for flush to complete */
	for (i = 0; i < AXQ_CDC_FLUSH_WAIT; i++) {
		DELAY(3000); /* should take only 1750 usecs */
		if (((*softsp->axq_cdc_counter) &
		    AXQ_CDC_CNT_TEST_DONE) != 0) {
			break;
		}
	}
	if (i >= AXQ_CDC_FLUSH_WAIT) {
		retval = DDI_FAILURE;
		cmn_err(CE_WARN, "axq_cdc_flush failed on expander %d",
		    expid);
	}

	/*
	 * Disable test mode in CDC address test reg
	 */
	*softsp->axq_cdc_addrtest = 0;

	/*
	 * If "disabled" option is requested, leave
	 * the CDC disabled.
	 */
	if (disabled) {
		axq_ctrl_test_save0 |= AXQ_CDC_DIS;
		*softsp->axq_cdc_ctrltest = axq_ctrl_test_save0;
	} else {
		*softsp->axq_cdc_ctrltest = axq_ctrl_test_save0;
	}

	mutex_exit(&softsp->axq_lock);

	if (!held)
		rw_exit(&axq_array_lock);

	return (retval);
}


/*
 * Flush all the CDC srams for all the AXQs in
 * the local domain.
 */
int
axq_cdc_flush_all()
{
	int retval;
	int i;

	rw_enter(&axq_array_lock, RW_READER);

	for (i = 0; i < AXQ_MAX_EXP; i++) {
		if (axq_array[i][SLOT0_AXQ] != NULL) {
			retval = axq_cdc_flush(i, 1, 0);
			if (retval != DDI_SUCCESS) break;
		}
	}
	rw_exit(&axq_array_lock);
	return (retval);
}

/*
 * Disable and flush all CDC srams for all the AXQs
 * in the local domain.
 */
int
axq_cdc_disable_flush_all()
{
	int retval;
	int i;

	rw_enter(&axq_array_lock, RW_READER);

	/*
	 * Disable and flush all the CDC srams
	 */
	for (i = 0; i < AXQ_MAX_EXP; i++) {
		if (axq_array[i][SLOT0_AXQ] != NULL) {
			retval = axq_cdc_flush(i, 1, 1);
			if (retval != DDI_SUCCESS) break;
		}
	}
	rw_exit(&axq_array_lock);

	if (retval != DDI_SUCCESS) {
		axq_cdc_enable_all();
	}
	return (retval);
}


/*
 * Enable the CDC srams for all the AXQs in the
 * the local domain. This routine is used in
 * conjunction with axq_cdc_disable_flush_all().
 */
void
axq_cdc_enable_all()
{
	struct axq_soft_state *softsp;
	int i;

	rw_enter(&axq_array_lock, RW_READER);

	/*
	 * Enable all the CDC sram
	 */
	for (i = 0; i < AXQ_MAX_EXP; i++) {
		if ((softsp = axq_array[i][SLOT0_AXQ]) != NULL) {
			mutex_enter(&softsp->axq_lock);
			if (softsp->axq_cdc_state != AXQ_CDC_DIS) {
				*softsp->axq_cdc_ctrltest &= ~AXQ_CDC_DIS;
			}
			mutex_exit(&softsp->axq_lock);
		}
	}
	rw_exit(&axq_array_lock);
}

/*
 * Interface for DR to enable slot1 iopause after cpus have been idled.
 * Precondition is for all devices to have been suspended (including axq).
 * This routine avoids locks as it is called by DR with cpus paused.
 */
int
axq_iopause_enable_all(uint32_t *errexp)
{
	int i, j;
	int retval = DDI_SUCCESS;
	processorid_t cpuid;
	struct axq_soft_state *softsp;

	DELAY(1000);
	for (i = 0; i < AXQ_MAX_EXP; i++) {
		if ((softsp = axq_array[i][SLOT1_AXQ]) != NULL &&
		    use_axq_iopause) {
			/*
			 * Do not enable if cpus configured in slot1.
			 * Unconfigured cpus should be idle in nc space.
			 */
			for (j = 0; j < STARCAT_SLOT1_CPU_MAX; j++) {
				cpuid = MAKE_CPUID(softsp->expid,
				    softsp->slotnum, j);
				if (cpu[cpuid]) {
					break;
				}
			}
			if (j < STARCAT_SLOT1_CPU_MAX) {
				continue;
			}

			retval = axq_slot1_idle(softsp);
			if (retval == DDI_FAILURE) {
				break;
			}

			*softsp->axq_domain_ctrl |= AXQ_DOMCTRL_PAUSE;
			softsp->paused = 1;
		}
	}

	if (retval != DDI_SUCCESS) {
		ASSERT(errexp);
		*errexp = i;
		axq_iopause_disable_all();
	}
	return (retval);
}

/*
 * De-assert axq iopause on all slot1 boards. This routine avoids locks
 * as it is called by DR with cpus paused.
 */
void
axq_iopause_disable_all()
{
	int i;
	struct axq_soft_state *softsp;

	for (i = 0; i < AXQ_MAX_EXP; i++) {
		if ((softsp = axq_array[i][SLOT1_AXQ]) != NULL &&
		    softsp->paused) {
			*softsp->axq_domain_ctrl &= ~AXQ_DOMCTRL_PAUSE;
			softsp->paused = 0;
		}
	}
}

/*
 * Attempt to wait for slot1 activity to go idle.
 */
static int
axq_slot1_idle(struct axq_soft_state *softsp)
{
	int i;

	ASSERT(softsp->slotnum == SLOT1_AXQ);
	for (i = 0; i < 10; i++) {
		if ((*(softsp->axq_domain_ctrl) & AXQ_DOMCTRL_BUSY) != 0) {
			return (DDI_SUCCESS);
		}
		DELAY(50);
	}
	return (DDI_FAILURE);
}

/*
 * Read a particular NASM entry
 */
int
axq_nasm_read(uint32_t expid, uint32_t slot, uint32_t nasm_entry,
    uint32_t *data)
{
	axq_nasm_read_u aread;
	axq_nasm_write_u awrite;
	struct axq_soft_state *softsp;

	if (slot > AXQ_MAX_SLOT_PER_EXP ||
	    expid > AXQ_MAX_EXP ||
	    nasm_entry > AXQ_NASM_SIZE) {
		return (DDI_FAILURE);
	}

	awrite.bit.rw = 0;	/* read operation */
	awrite.bit.addr = nasm_entry;
	awrite.bit.data = 0;

	rw_enter(&axq_array_lock, RW_READER);

	softsp = axq_array[expid][slot];
	if (softsp == NULL) {
		rw_exit(&axq_array_lock);
		return (DDI_FAILURE);
	}

	mutex_enter(&softsp->axq_lock);

	*(softsp->axq_nasm) = awrite.val;
	aread.val = *(softsp->axq_nasm);

	mutex_exit(&softsp->axq_lock);
	rw_exit(&axq_array_lock);

	if (aread.bit.valid) {
		*data = aread.bit.data;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*
 * Write a particular NASM entry
 */
static int
axq_nasm_write_one(uint32_t expid, uint32_t slot, uint32_t nasm_entry,
    uint32_t data)
{
	axq_nasm_write_u awrite;
	struct axq_soft_state *softsp;

	/*
	 * Note: need to make sure axq_array_lock held first, so that a
	 * paused thread is not holding softsp->axq_lock, which could
	 * result in deadlock.
	 */
	ASSERT(RW_LOCK_HELD(&axq_array_lock));

	if (slot > AXQ_MAX_SLOT_PER_EXP ||
	    expid > AXQ_MAX_EXP ||
	    nasm_entry > AXQ_NASM_SIZE) {
		return (DDI_FAILURE);
	}

	awrite.bit.rw = 1;	/* write operation */
	awrite.bit.addr = nasm_entry;
	awrite.bit.data = data;

	softsp = axq_array[expid][slot];
	if (softsp == NULL) {
		return (DDI_FAILURE);
	}

	mutex_enter(&softsp->axq_lock);

	*(softsp->axq_nasm) = awrite.val;

	mutex_exit(&softsp->axq_lock);

	return (DDI_SUCCESS);
}

int
axq_nasm_write(uint32_t expid, uint32_t slot, uint32_t nasm_entry,
    uint32_t data)
{
	int rc;

	rw_enter(&axq_array_lock, RW_READER);
	rc = axq_nasm_write_one(expid, slot, nasm_entry, data);
	rw_exit(&axq_array_lock);
	return (rc);
}

/*
 * Write a particular NASM entry for all the
 * axqs in the domain
 * Note: other CPUs are paused when this function called.
 */
int
axq_nasm_write_all(uint32_t nasm_entry, uint32_t data)
{
	int i;
	int rc;

	ASSERT(RW_WRITE_HELD(&axq_array_lock));

	for (i = 0; i < AXQ_MAX_EXP; i++) {
		if (axq_array[i][SLOT0_AXQ] != NULL) {
			rc = axq_nasm_write_one(i, SLOT0_AXQ, nasm_entry,
			    data);
			if (rc != DDI_SUCCESS) {
				return (DDI_FAILURE);
			}
		}
		if (axq_array[i][SLOT1_AXQ] != NULL) {
			rc = axq_nasm_write_one(i, SLOT1_AXQ, nasm_entry,
			    data);
			if (rc != DDI_SUCCESS) {
				return (DDI_FAILURE);
			}
		}
	}

	return (DDI_SUCCESS);
}

/*
 * Take write lock for axq_nasm_write_all() outside
 * critical section where other CPUs are paused.
 */
void
axq_array_rw_enter(void)
{
	rw_enter(&axq_array_lock, RW_WRITER);
}

/*
 * Release write lock for axq_nasm_write_all() outside
 * critical section where other CPUs are paused.
 */
void
axq_array_rw_exit(void)
{
	rw_exit(&axq_array_lock);
}

/*
 * Read a particular CASM entry
 */
uint32_t
axq_casm_read(uint32_t expid, uint32_t slot, int casmslot)
{
	struct axq_soft_state *softsp;
	uint32_t retval;

	rw_enter(&axq_array_lock, RW_READER);

	ASSERT(axq_array[expid][slot] != NULL);
	ASSERT(casmslot >= 0 && casmslot < AXQ_MAX_EXP);

	softsp = axq_array[expid][slot];

	mutex_enter(&softsp->axq_lock);

	retval = *(softsp->axq_casm_slot[casmslot]);

	mutex_exit(&softsp->axq_lock);
	rw_exit(&axq_array_lock);

	return (retval);
}


/*
 * Write a particular CASM entry
 */

int
axq_casm_write(uint32_t expid, uint32_t slot, int casmslot,
		uint32_t value)
{
	struct axq_soft_state *softsp;
	int retval;

	rw_enter(&axq_array_lock, RW_READER);

	ASSERT(axq_array[expid][slot] != NULL);
	ASSERT(casmslot >= 0 && casmslot < AXQ_MAX_EXP);

	softsp = axq_array[expid][slot];

	mutex_enter(&softsp->axq_lock);

	/*
	 * first read the casm slot in question
	 * it should be non-zero to indicate that
	 * we have write permission to update it.
	 * Note that if we write it without valid
	 * permission, we can get an exception.
	 */
	if (*(softsp->axq_casm_slot[casmslot])) {
		*(softsp->axq_casm_slot[casmslot]) = value;
		retval = DDI_SUCCESS;
	} else {
		retval = DDI_FAILURE;
	}

	mutex_exit(&softsp->axq_lock);
	rw_exit(&axq_array_lock);
	return (retval);
}

/*
 * Write a particular CASM entry for all the
 * axqs in the domain
 */

int
axq_casm_write_all(int casmslot, uint32_t value)
{
	int i;
	struct axq_soft_state *softsp;

	/*
	 * Since we are updating all the AXQs,
	 * it will be easier to simply grab
	 * exclusive access to the AXQs by obtaining
	 * the RW_WRITER access to the axq_array.
	 */
	rw_enter(&axq_array_lock, RW_WRITER);

	/*
	 * Paranoid check: run thru all the avail AXQs
	 * and make sure we can write into that slot in question
	 * We check it by reading the slot and it should be
	 * non-zero.
	 */
	for (i = 0; i < AXQ_MAX_EXP; i++) {
		if ((softsp = axq_array[i][SLOT0_AXQ]) != NULL) {
			if (*(softsp->axq_casm_slot[casmslot])
			    == 0) {
				break;
			}
		}
		if ((softsp = axq_array[i][SLOT1_AXQ]) != NULL) {
			if (*(softsp->axq_casm_slot[casmslot])
			    == 0) {
				break;
			}
		}
	}

	if (i < AXQ_MAX_EXP) {
		/*
		 * We have no write permission for some AXQ
		 * for the CASM slot in question. Flag it
		 * as an error
		 */
		rw_exit(&axq_array_lock);
		return (DDI_FAILURE);
	}

	/*
	 * everything looks good - do the update
	 */
	for (i = 0; i < AXQ_MAX_EXP; i++) {
		if ((softsp = axq_array[i][SLOT0_AXQ]) != NULL) {
			*softsp->axq_casm_slot[casmslot] = value;
		}
		if ((softsp = axq_array[i][SLOT1_AXQ]) != NULL) {
			*softsp->axq_casm_slot[casmslot] = value;
		}
	}

	rw_exit(&axq_array_lock);
	return (DDI_SUCCESS);
}


/*
 * Construct a script of <physicaladdr, data> tuple pairs that
 * reprogram the all the AXQs in the local domain to swap the
 * contents of casmslot0 with casmslot1.
 */
int
axq_do_casm_rename_script(uint64_t **script_elm, int casmslot0,
	int casmslot1)
{
	struct axq_soft_state *softsp;
	int i, slot;
	uint32_t val0, val1;
	uint64_t *s_elm = *script_elm;
	uint64_t paddr;

	/*
	 * There should be some global locking at the
	 * DR level to do this - since this is one of
	 * the sequence of steps in copyrename.
	 * For now, we grab the RW_WRITER lock for
	 * script construction.
	 */
	rw_enter(&axq_array_lock, RW_WRITER);

	/*
	 * Construct the <physicaladdr, data> tuple pairs
	 * for reprogramming the AXQs so that the value in
	 * casmslot0 is swapped with the content in casmslot1.
	 * Paranoid check: We make sure that we can write to
	 * both slots in all the AXQs by reading the slots and
	 * they should be non-zero.
	 */
	for (slot = SLOT0_AXQ; slot <= SLOT1_AXQ; slot++) {
		for (i = 0; i < AXQ_MAX_EXP; i++) {
		if ((softsp = axq_array[i][slot]) != NULL) {
			paddr = softsp->axq_phyaddr;
			val0 = *(softsp->axq_casm_slot[casmslot0]);
			val1 = *(softsp->axq_casm_slot[casmslot1]);
			if (val0 != 0 && val1 != 0) {
				*s_elm++ = paddr + AXQ_CASM_SLOT_START +
				    AXQ_REGOFF(casmslot0);
				*s_elm++ = val1;
				*s_elm++ = paddr + AXQ_CASM_SLOT_START +
				    AXQ_REGOFF(casmslot1);
				*s_elm++ = val0;
			} else {
				/*
				 * Somehow we can't access one of
				 * the casm slot - quit.
				 */
				break;
			}
		}
		}
		if (i < AXQ_MAX_EXP) break;
	}

	rw_exit(&axq_array_lock);

	if (slot > SLOT1_AXQ) {
		/* successful */
		*script_elm = s_elm;
		return (DDI_SUCCESS);
	} else {
		return (DDI_FAILURE);
	}
}


/*
 * Send an interrupt to the SSC passing
 * a 8 bit cookie value
 */
int
axq_cpu2ssc_intr(uint8_t cookie)
{
	int retval, i;
	volatile uint32_t *intr_reg;

#ifndef	_AXQ_LOCAL_SPACE_SUPPORTED
	/* Local space access not available */

	int exp, slot;

	rw_enter(&axq_array_lock, RW_READER);

	/* Make sure the current cpu is not switched out */
	kpreempt_disable();

	/*
	 * Compute the exp# and slot# of the current cpu
	 * so that we know which AXQ cpu2ssc intr reg to
	 * use.
	 */
	exp = CPU->cpu_id >> 5;
	slot = (CPU->cpu_id >> 3) & 0x1;

	intr_reg = axq_array[exp][slot]->axq_cpu2ssc_intr;
#else
	/* use local space */
	intr_reg = axq_local.axq_cpu2ssc_intr;
#endif /* _AXQ_LOCAL_SPACE_SUPPORTED */

	ASSERT(intr_reg != 0);

	retval = DDI_FAILURE;
	for (i = 0; i < AXQ_INTR_PEND_WAIT; i++) {
		if (!(*intr_reg & AXQ_CPU2SSC_INTR_PEND)) {
			*intr_reg = cookie;
			retval = DDI_SUCCESS;
			break;
		}
		DELAY(200);
	}

#ifndef	_AXQ_LOCAL_SPACE_SUPPORTED
	kpreempt_enable();
	rw_exit(&axq_array_lock);
#endif
	return (retval);
}


/*
 * Read the SDI timeout register (SRD use)
 * This routine accepts a clear flag to indicate
 * whether the register should be cleared after
 * the read.
 */
uint32_t
axq_read_sdi_timeout_reg(uint32_t expid, uint32_t slot, int clearflag)
{
	struct axq_soft_state *softsp;
	uint32_t retval;

	rw_enter(&axq_array_lock, RW_READER);

	ASSERT(axq_array[expid][slot] != NULL);

	softsp = axq_array[expid][slot];

	mutex_enter(&softsp->axq_lock);

	if (clearflag) {
		/* read and then clear register */
		retval = *softsp->axq_sdi_timeout_rdclr;
	} else {
		retval = *softsp->axq_sdi_timeout_rd;
	}

	mutex_exit(&softsp->axq_lock);
	rw_exit(&axq_array_lock);

	return (retval);
}


/*
 * Routine to create a kstat for each %pic that
 * the AXQ has (there are 3 of them). These read-only
 * kstats export event names that the respective %pic
 * supports. Pic0 and Pic1 are similar and they both have
 * a 128-input mux. Pic2 counts the clock and can set up
 * to count or freeze.
 * Note that all AXQ instances use the same events, we only
 * need to create one set of the picN kstats.
 */
static void
axq_add_picN_kstats(dev_info_t *dip)
{
	struct kstat_named *axq_pic_named_data;
	int event, pic;
	int instance = ddi_get_instance(dip);
	int pic_shift = 0;

	/*
	 * Create the picN kstat for Pic0 and Pic1
	 * Both have similar set of events. Add one
	 * extra event for the clear_event mask.
	 */
	for (pic = 0; pic < AXQ_NUM_PICS; pic++) {
		char pic_name[20];
		int num_events, i;

		(void) sprintf(pic_name, "pic%d", pic);

		num_events = (pic <= 1) ? AXQ_PIC0_1_NUM_EVENTS :
		    AXQ_PIC2_NUM_EVENTS;

		if ((axq_picN_ksp[pic] = kstat_create("axq",
		    instance, pic_name, "bus", KSTAT_TYPE_NAMED,
		    num_events + 1, NULL)) == NULL) {
			cmn_err(CE_WARN, "axq %s: kstat_create failed",
			    pic_name);

			/* remove pic kstats that was created earlier */
			for (i = 0; i < pic; i++) {
				kstat_delete(axq_picN_ksp[i]);
				axq_picN_ksp[i] = NULL;
			}
			return;
		}

		axq_pic_named_data =
		    (struct kstat_named *)(axq_picN_ksp[pic]->ks_data);

		pic_shift = pic * AXQ_PIC_SHIFT;

		/*
		 * for each picN event, write a kstat record of
		 * name = EVENT & value.ui64 = PCR_MASK.
		 */
		for (event = 0; event < num_events; event++) {
			/* pcr_mask */
			axq_pic_named_data[event].value.ui64 =
			    axq_events[event].pcr_mask << pic_shift;

			/* event name */
			kstat_named_init(&axq_pic_named_data[event],
			    axq_events[event].event_name,
			    KSTAT_DATA_UINT64);
		}

		/*
		 * Add the clear pic event and mask as the last
		 * record in the kstat.
		 */
		axq_pic_named_data[num_events].value.ui64 =
		    (uint32_t)~(AXQ_PIC_CLEAR_MASK << pic_shift);

		kstat_named_init(&axq_pic_named_data[num_events],
		    "clear_pic", KSTAT_DATA_UINT64);

		kstat_install(axq_picN_ksp[pic]);
	}
}


static  void
axq_add_kstats(struct axq_soft_state *softsp)
{
	struct kstat *axq_counters_ksp;
	struct kstat_named *axq_counters_named_data;

	/*
	 * Create the picN kstats if we are the first instance
	 * to attach. We use axq_attachcnt as a count of how
	 * many instances have attached. This is protected by
	 * a lock.
	 */
	mutex_enter(&axq_attachcnt_lock);
	if (axq_attachcnt++ == 0)
		axq_add_picN_kstats(softsp->dip);

	mutex_exit(&axq_attachcnt_lock);

	/*
	 * A "counter" kstat is created for each axq
	 * instance that provides access to the %pcr and %pic
	 * registers for that instance.
	 *
	 * The size of this kstat is AXQ_NUM_PICS + 1 for %pcr
	 */
	if ((axq_counters_ksp = kstat_create("axq",
	    ddi_get_instance(softsp->dip), "counters",
	    "bus", KSTAT_TYPE_NAMED, AXQ_NUM_PICS + 1,
	    KSTAT_FLAG_WRITABLE)) == NULL) {
			cmn_err(CE_WARN, "axq%d counters: kstat_create"
			" failed", ddi_get_instance(softsp->dip));
		return;
	}

	axq_counters_named_data =
	    (struct kstat_named *)(axq_counters_ksp->ks_data);

	/* initialize the named kstats */
	kstat_named_init(&axq_counters_named_data[0],
	    "pcr", KSTAT_DATA_UINT32);

	kstat_named_init(&axq_counters_named_data[1],
	    "pic0", KSTAT_DATA_UINT32);

	kstat_named_init(&axq_counters_named_data[2],
	    "pic1", KSTAT_DATA_UINT32);

	kstat_named_init(&axq_counters_named_data[3],
	    "pic2", KSTAT_DATA_UINT32);

	axq_counters_ksp->ks_update = axq_counters_kstat_update;
	axq_counters_ksp->ks_private = (void *)softsp;

	kstat_install(axq_counters_ksp);

	/* update the softstate */
	softsp->axq_counters_ksp = axq_counters_ksp;
}


static  int
axq_counters_kstat_update(kstat_t *ksp, int rw)
{
	struct kstat_named *axq_counters_data;
	struct axq_soft_state *softsp;

	axq_counters_data = (struct kstat_named *)ksp->ks_data;
	softsp = (struct axq_soft_state *)ksp->ks_private;

	if (rw == KSTAT_WRITE) {
		/*
		 * Write the pcr value to the softsp->axq_pcr.
		 * The pic register is read-only so we don't
		 * attempt to write to it.
		 */
		*softsp->axq_pcr = (uint32_t)axq_counters_data[0].value.ui64;
	} else {
		/*
		 * Read %pcr and %pic register values and write them
		 * into counters kstat.
		 *
		 */

		/* pcr */
		axq_counters_data[0].value.ui64 = (uint64_t)
		    (*softsp->axq_pcr);

		/* pic0 */
		axq_counters_data[1].value.ui64 = (uint64_t)
		    (*softsp->axq_pic0);

		/* pic1 */
		axq_counters_data[2].value.ui64 = (uint64_t)
		    *softsp->axq_pic1;

		/* pic2 */
		axq_counters_data[3].value.ui64 = (uint64_t)
		    *softsp->axq_pic2;
	}
	return (0);
}

struct gptwo_phys_spec {
	uint_t gptwo_phys_hi;   /* child's address, hi word */
	uint_t gptwo_phys_low;  /* child's address, low word */
	uint_t gptwo_size_hi;   /* high word of size field */
	uint_t gptwo_size_low;  /* low word of size field */
};

int axq_pio_workaround_disable = 0;
int axq_pio_limit = 3;

int
starcat_axq_pio_workaround(dev_info_t *dip)
{
	dev_info_t *axq_dip, *cdip, *pdip;
	int portid, axq_portid;
	char *name;
	int size, circ;
	uint_t *base_addr, *io_domain_control_addr;
	int32_t io_domain_control;
	ddi_device_acc_attr_t acc;
	ddi_acc_handle_t handle;
	struct gptwo_phys_spec *gptwo_spec;
	struct regspec phys_spec;

	if (axq_pio_workaround_disable)
		return (0);

	/*
	 * Get the portid for the PCI (Schizo) device).
	 */
	if ((portid = ddi_getprop(DDI_DEV_T_ANY, dip, 0, "portid", -1)) < 0) {
		cmn_err(CE_WARN, "%s: no portid\n", ddi_get_name(dip));
		return (0);
	}

	/*
	 * Calculate the portid for the Slot 1 AXQ.  The portid for
	 * Schizo 0 EEEEE11100
	 * Schizo 1 EEEEE11101
	 * AXQ 0    EEEEE11110
	 * AXQ 1    EEEEE11111
	 * where EEEEE is the 5 bit expander number.  So the portid for
	 * AXQ 1 can be easily calculated by oring a 3 to the portid of
	 * Schizo 0 or 1.
	 */
	axq_portid = portid | 3;

	/*
	 * Look for AXQ nodes that have the portid we calculated.
	 */
	axq_dip = NULL;
	pdip = ddi_root_node();
	ndi_devi_enter(pdip, &circ);
	for (cdip = ddi_get_child(pdip); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {

		if (ddi_getlongprop(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS, "name", (caddr_t)&name, &size)
		    != DDI_PROP_SUCCESS) {
			continue;
		}

		if (strcmp(name, "address-extender-queue") != 0) {
			kmem_free(name, size);
			continue;
		}

		/*
		 * Found an AXQ node.
		 */

		kmem_free(name, size);

		portid = ddi_getprop(DDI_DEV_T_ANY, cdip, 0, "portid", -1);

		if (portid == axq_portid) {

			/*
			 * We found the correct AXQ node.
			 */
			ndi_hold_devi(cdip);
			axq_dip = cdip;
			break;
		}
	}
	ndi_devi_exit(pdip, circ);

	if (axq_dip == NULL) {
		cmn_err(CE_WARN, "can't find axq node with portid=0x%x\n",
		    axq_portid);
		return (0);
	}

	if (ddi_getlongprop(DDI_DEV_T_ANY, axq_dip, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&gptwo_spec, &size) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "%s: no regspec\n", ddi_get_name(axq_dip));
		ndi_rele_devi(axq_dip);
		return (0);
	}

	phys_spec.regspec_bustype = gptwo_spec->gptwo_phys_hi;
	phys_spec.regspec_addr = gptwo_spec->gptwo_phys_low;
	phys_spec.regspec_size = gptwo_spec->gptwo_size_low;

	acc.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	acc.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	acc.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;

	if (axq_map_phys(axq_dip, &phys_spec, (caddr_t *)&base_addr,
	    &acc, &handle)) {
		cmn_err(CE_WARN, "%s: map phys failed\n",
		    ddi_get_name(axq_dip));
		kmem_free(gptwo_spec, size);
		ndi_rele_devi(axq_dip);
		return (0);
	}

	kmem_free(gptwo_spec, size);

	io_domain_control_addr = REG_ADDR(base_addr, AXQ_SLOT1_DOMCTRL);

	if (ddi_peek32(axq_dip, (int32_t *)io_domain_control_addr,
	    (int32_t *)&io_domain_control)) {
		cmn_err(CE_WARN, "%s: peek failed\n", ddi_get_name(axq_dip));
		ndi_rele_devi(axq_dip);
		return (0);
	}

	axq_unmap_phys(&handle);

	ndi_rele_devi(axq_dip);

	/*
	 * If bit 6 of the IO Domain Control Register is a one,
	 * then this AXQ version does not have the PIO Limit problem.
	 */
	if (io_domain_control & AXQ_DOMCTRL_PIOFIX)
		return (0);

	return (axq_pio_limit);
}

static int
axq_map_phys(dev_info_t *dip, struct regspec *phys_spec,
	caddr_t *addrp, ddi_device_acc_attr_t *accattrp,
	ddi_acc_handle_t *handlep)
{
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	int result;
	struct regspec *ph;

	*handlep = impl_acc_hdl_alloc(KM_SLEEP, NULL);
	hp = impl_acc_hdl_get(*handlep);
	hp->ah_vers = VERS_ACCHDL;
	hp->ah_dip = dip;
	hp->ah_rnumber = 0;
	hp->ah_offset = 0;
	hp->ah_len = 0;
	hp->ah_acc = *accattrp;
	ph = kmem_zalloc(sizeof (struct regspec), KM_SLEEP);
	*ph = *phys_spec;
	hp->ah_bus_private = ph;	/* cache a copy of the reg spec */

	mr.map_op = DDI_MO_MAP_LOCKED;
	mr.map_type = DDI_MT_REGSPEC;
	mr.map_obj.rp = phys_spec;
	mr.map_prot = PROT_READ | PROT_WRITE;
	mr.map_flags = DDI_MF_KERNEL_MAPPING;
	mr.map_handlep = hp;
	mr.map_vers = DDI_MAP_VERSION;

	result = ddi_map(dip, &mr, 0, 0, addrp);

	if (result != DDI_SUCCESS) {
		impl_acc_hdl_free(*handlep);
		*handlep = NULL;
	} else {
		hp->ah_addr = *addrp;
	}

	return (result);
}

static void
axq_unmap_phys(ddi_acc_handle_t *handlep)
{
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	struct regspec *ph;

	hp = impl_acc_hdl_get(*handlep);
	ASSERT(hp);
	ph = hp->ah_bus_private;

	mr.map_op = DDI_MO_UNMAP;
	mr.map_type = DDI_MT_REGSPEC;
	mr.map_obj.rp = ph;
	mr.map_prot = PROT_READ | PROT_WRITE;
	mr.map_flags = DDI_MF_KERNEL_MAPPING;
	mr.map_handlep = hp;
	mr.map_vers = DDI_MAP_VERSION;

	(void) ddi_map(hp->ah_dip, &mr, hp->ah_offset,
	    hp->ah_len, &hp->ah_addr);

	impl_acc_hdl_free(*handlep);
	kmem_free(ph, sizeof (struct regspec));	/* Free the cached copy */
	*handlep = NULL;
}

/* ARGSUSED */
static boolean_t
axq_panic_callb(void *arg, int code)
{
	axq_iopause_disable_all();
	return (B_TRUE);
}
