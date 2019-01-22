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
 * Copyright (c) 2019 Peter Tribble.
 */

/*
 * Netra ct800 and Netra ct400 (MonteCarlo/Tonga)
 * System Controller and Status Boards STREAMS driver.
 *
 * This driver handles all communications with the Netra ct400 and ct800
 * System Controller Boards.
 * I/O to the SCB is through the PCF8584 I2C controller.
 * The SCB I2C interface and driver interface are provided by the
 * Xilinx XCS40XL.
 *
 * N.B.: The design choice of using STREAMS was dictated because
 *	 the original system monitor card had to multiplex 2 pcf8574's
 *	 as one device.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/cred.h>
#include <sys/log.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/signal.h>

#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/poll.h>

#include <sys/debug.h>

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>

#include <sys/i2c/misc/i2c_svc.h>

#include <sys/mct_topology.h>
#include <sys/netract_gen.h>
#include <sys/scsbioctl.h>
#include <sys/scsb.h>
#include <sys/scsb_cbi.h>

#include <sys/hotplug/hpctrl.h>
#include <sys/hsc.h>
#include <sys/hscimpl.h>

#define	CPCI_HOTSWAP_SUPPORT

#define	ALARM_CARD_ON_SLOT	1
#define	SCSB_FRU_OP_GET_REG	1
#define	SCSB_FRU_OP_SET_REGBIT	2
#define	SCSB_FRU_OP_GET_BITVAL	3
#define	SCSB_FRU_OP_GET_REGDATA	4

/*
 * (internal only)
 * scsb build version format is "CCYYMMDD"
 * for integer compares.
 */
#define	SCSB_BUILD_VERSION	"20001206"

#define	MUTEX_UNINIT	0
#define	MUTEX_INIT	2

static	int scsb_err_threshold = 0; /* max allowed i2c errors */
static	int scsb_freeze_count = 3; /* #I2C errors to indicate SCB removal */
static	int scsb_shutdown_count = 5; /* #polls before passing shutdown evt */
static	int scsb_in_postintr = 0;	/* 1 if scsb is processing intr */
static	kmutex_t *scb_intr_mutex;	 /* SCSB interrupt mutex */
static	int	nct_mutex_init = MUTEX_UNINIT;

extern	int	scsb_hsc_board_healthy();

static	char	*scsb_name = SCSB_DEVICE_NAME;
static	char	*scsb_clone_name = SCSB_DEVICE_NAME "clone";
static	char	*scsb_build_version = SCSB_BUILD_VERSION;
/*
 * cb_ops section of scsb driver.
 */
static	int	sm_open(queue_t *, dev_t *, int, int, cred_t *);
static	int	sm_close(queue_t *, int, cred_t *);

static	int	sm_rput(queue_t *, mblk_t *);	/* from i2c below */
static	int	sm_wput(queue_t *, mblk_t *);	/* from above */

uint_t	scsb_intr_preprocess(caddr_t arg);
void	scsb_intr(caddr_t arg);
static	void	smf_ioctl(queue_t *, mblk_t *);
static	void	sm_ioc_rdwr(queue_t *, mblk_t *, int);

static int scsb_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int scsb_attach(dev_info_t *, ddi_attach_cmd_t);
static int scsb_detach(dev_info_t *, ddi_detach_cmd_t);
static int initialize_scb(scsb_state_t *);

static dev_info_t *scsb_dip;		/* private copy of devinfo pointer */

static struct module_info info = {
	0, SCSB_DEVICE_NAME, 0, INFPSZ, 512, 128
};

static struct qinit sm_rinit = {
	sm_rput, NULL, sm_open, sm_close, NULL, &info
};

static struct qinit sm_winit = {
	sm_wput, NULL, sm_open, sm_close, NULL, &info
};

struct streamtab sm_st  = {
	&sm_rinit, &sm_winit, NULL, NULL
};

static struct cb_ops scsb_cb_ops = {

	nulldev,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev, 			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	&sm_st,			/* streamtab  */
	D_MP,			/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* int (*cb_aread)() */
	nodev				/* int (*cb_awrite)() */
};

static struct dev_ops scsb_ops = {

	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	scsb_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	scsb_attach,		/* attach */
	scsb_detach,		/* detach */
	nodev,			/* reset */
	&scsb_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * Module linkage information for the kernel.
 */

static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
#ifdef DEBUG
	"SCB/SSB driver DBG" SCSB_BUILD_VERSION,
#else
	"v1.33 Netra ct System Control/Status Board driver",
#endif
	&scsb_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/*
 * local declarations and definitions
 */
#if defined(DEBUG)
	uint32_t	scsb_debug = 0x00000000;
#else
static	uint32_t	scsb_debug = 0;
#endif

static	hrtime_t scb_pre_s, scb_pre_e, scb_post_s, scb_post_e;

static	int		scsb_pil = SCSB_INTR_PIL;
static	int		hsc_pil  = SCSB_INTR_PIL;
static 	void		*scsb_state;
static 	uint32_t	scsb_global_state;
static 	uint32_t	scsb_event_code;	/* for event polling */
static 	struct system_info	mct_system_info;
static 	int		scsb_healthy_poll_count = 16;

static fru_id_t		fru_id_table[MCT_MAX_FRUS];
static uchar_t		scb_intr_regs[SCTRL_MAX_GROUP_NUMREGS];

static	uint32_t	evc_fifo[EVC_FIFO_SIZE];
static	uint32_t	evc_fifo_count = 0;
static	uint32_t	*evc_rptr = evc_fifo;
static	uint32_t	*evc_wptr = evc_fifo;
static	void		*evc_procs[EVC_PROCS_MAX];
static	int		evc_proc_count = 0;
static timeout_id_t scsb_intr_tid;

int nct_i2c_transfer(i2c_client_hdl_t i2c_hdl, i2c_transfer_t *i2c_tran);

/*
 * kstat functions
 */
static	int	scsb_alloc_kstats(scsb_state_t *);
static	void	scsb_free_kstats(scsb_state_t *);
static	int	update_ks_leddata(kstat_t *, int);
static	int	update_ks_state(kstat_t *, int);
static	int	update_ks_topology(kstat_t *, int);
static	int	update_ks_evcreg(kstat_t *, int);

/*
 * local functions
 */
static	void	free_resources(dev_info_t *, scsb_state_t *, int);
static	i2c_transfer_t	*scsb_alloc_i2ctx(i2c_client_hdl_t, uint_t);
static	fru_info_t	*find_fru_info(fru_id_t fru_id);
static	int	scsb_fake_intr(scsb_state_t *, uint32_t);
static	int	scsb_get_status(scsb_state_t *, scsb_status_t *);
static	int	scsb_leds_switch(scsb_state_t *, scsb_ustate_t);
static	void	scsb_freeze(scsb_state_t *scsb);
static	void	scsb_freeze_check(scsb_state_t *scsb);
static	void	scsb_restore(scsb_state_t *scsb);
static	int	scsb_polled_int(scsb_state_t *, int, uint32_t *);
static	int	scsb_check_config_status(scsb_state_t *scsb);
static	int	scsb_set_scfg_pres_leds(scsb_state_t *, fru_info_t *);
static	void	scsb_set_topology(scsb_state_t *);
static	void	scsb_free_topology(scsb_state_t *);
int	scsb_read_bhealthy(scsb_state_t *scsb);
int	scsb_read_slot_health(scsb_state_t *, int);
static	void	tonga_slotnum_check(scsb_state_t *scsb, scsb_uinfo_t *suip);
static	int	tonga_psl_to_ssl(scsb_state_t *scsb, int slotnum);
static	uchar_t	tonga_slotnum_led_shift(scsb_state_t *scsb, uchar_t data);
static	int	scsb_clear_intptrs(scsb_state_t *scsb);
static	int	scsb_clear_intmasks(scsb_state_t *scsb);
static	int	scsb_setall_intmasks(scsb_state_t *scsb);
static	int	scsb_write_mask(scsb_state_t *, uchar_t, uchar_t, uchar_t,
				uchar_t);
static	int	scsb_rdwr_register(scsb_state_t *, int, uchar_t, int,
				uchar_t *, int);
static	int	scsb_readall_regs(scsb_state_t *);
static	int	scsb_get_led_regnum(scsb_state_t *, scsb_uinfo_t *, uchar_t *,
				int *, scsb_led_t);
static	void	scsb_free_i2ctx(i2c_client_hdl_t, i2c_transfer_t *);
static	void	check_fru_info(scsb_state_t *, int);
static	void	update_fru_info(scsb_state_t *, fru_info_t *);
static	int	event_to_index(uint32_t);
static	void	add_event_code(scsb_state_t *, uint32_t);
static	uint32_t	del_event_code();
static	uint32_t	get_event_code();
static	int	add_event_proc(scsb_state_t *, pid_t);
static	int	del_event_proc(scsb_state_t *, pid_t);
static	void	rew_event_proc(scsb_state_t *);
static	int	event_proc_count(scsb_state_t *);
static	int	find_evc_proc(pid_t pid);
static	void	signal_evc_procs(scsb_state_t *);
static	int	check_event_procs();
static	int	scsb_is_alarm_card_slot(scsb_state_t *, int);
	int	scsb_get_slot_state(scsb_state_t *, int, int *);
static	int	scsb_fru_op(scsb_state_t *, scsb_utype_t, int, int, int);
static	int	scsb_queue_put(queue_t *, int, uint32_t *, char *);
static	int	scsb_queue_ops(scsb_state_t *, int, int, void *, char *);
static	int scsb_blind_read(scsb_state_t *, int, uchar_t, int, uchar_t *, int);
static	int scsb_toggle_psmint(scsb_state_t *, int);
static	int scsb_quiesce_psmint(scsb_state_t *);
static	int scsb_invoke_intr_chain();
int	scsb_intr_register(int (*)(void *), void *, fru_id_t);
void scsb_intr_unregister(fru_id_t);

#ifdef	DEBUG
static	void	mct_topology_dump(scsb_state_t *, int);
static	void	scsb_failing_event(scsb_state_t *scsb);
#endif

int
_init(void)
{
	int	i, status;

	if (scsb_debug & 0x0005)
		cmn_err(CE_NOTE, "scsb: _init()");
	(void) ddi_soft_state_init(&scsb_state, sizeof (scsb_state_t),
	    SCSB_NO_OF_BOARDS);
	(void) hsc_init();
	if ((status = mod_install(&modlinkage)) != 0) {
		if (scsb_debug & 0x0006)
			cmn_err(CE_NOTE, "scsb: _init(): mod_install failed");
		ddi_soft_state_fini(&scsb_state);
		(void) hsc_fini();
		return (status);
	}
	/*
	 * initialize the FRU ID Table, using real FRU IDs where available
	 * such as I2C Addresses for FRUs with I2C support
	 */
	for (i = 0; i < MCT_MAX_FRUS; ++i)
		fru_id_table[i] = i + 1;
	fru_id_table[event_to_index(SCTRL_EVENT_PS1)] = (fru_id_t)MCT_I2C_PS1;
	fru_id_table[event_to_index(SCTRL_EVENT_PS2)] = (fru_id_t)MCT_I2C_PS2;
	fru_id_table[event_to_index(SCTRL_EVENT_FAN1)] = (fru_id_t)MCT_I2C_FAN1;
	fru_id_table[event_to_index(SCTRL_EVENT_FAN2)] = (fru_id_t)MCT_I2C_FAN2;
	fru_id_table[event_to_index(SCTRL_EVENT_FAN3)] = (fru_id_t)MCT_I2C_FAN3;
	fru_id_table[event_to_index(SCTRL_EVENT_SCB)] = (fru_id_t)MCT_I2C_SCB;
	return (status);
}

int
_fini(void)
{
	int	status;

	if (scsb_debug & 0x0005)
		cmn_err(CE_NOTE, "scsb: _fini()");

	if ((status = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&scsb_state);
		(void) hsc_fini();
	}
	if (scsb_debug & 0x0006)
		cmn_err(CE_NOTE, "scsb: _fini, error %x\n", status);

	return (status);
}

int
_info(struct modinfo *modinfop)
{
	if (scsb_debug & 0x0005)
		cmn_err(CE_NOTE, "scsb: _info()");

	return (mod_info(&modlinkage, modinfop));
}

static int
scsb_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;
	scsb_state_t	*scsb;
	register int	i;
	int		*regs;
	uint_t		len;
	uchar_t		reg, wdata, rmask;

	instance = ddi_get_instance(dip);

	if (scsb_debug & 0x0005)
		cmn_err(CE_NOTE, "scsb_attach[%d]", instance);

	if (cmd != DDI_ATTACH) {
		if (scsb_debug & 0x0006)
			cmn_err(CE_NOTE,
			    "scsb_attach[%d]: cmd 0x%x != DDI_ATTACH",
			    instance, cmd);
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(scsb_state, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "scsb%d: cannot allocate soft state",
		    instance);
		return (DDI_FAILURE);
	}

	scsb = (scsb_state_t *)ddi_get_soft_state(scsb_state, instance);
	if (scsb == NULL) {
		cmn_err(CE_WARN, "scsb%d: cannot get soft state", instance);
		ddi_soft_state_free(scsb_state, instance);
		return (DDI_FAILURE);
	}
	scsb->scsb_instance = instance;
	scsb->scsb_state = 0;	/* just checking strange mutex behavior */

	/*
	 * make sure this is the SCB's known address
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &regs, &len) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "scsb%d: Failed to get \"reg\" property", instance);
		ddi_soft_state_free(scsb_state, instance);
		return (DDI_FAILURE);
	}
	scsb->scsb_i2c_addr = regs[1] & SCSB_I2C_ADDR_MASK;
	if (scsb->scsb_i2c_addr != SCSB_I2C_ADDR) {
		cmn_err(CE_WARN, "scsb%d: I2C Addr reg %x %x must be %x",
		    instance, regs[0], regs[1], SCSB_I2C_ADDR);
		ddi_soft_state_free(scsb_state, instance);
		ddi_prop_free(regs);
		return (DDI_FAILURE);
	}
	/* done with array lookup, free resource */
	ddi_prop_free(regs);
	/*
	 * initialize synchronization mutex and condition var.
	 * for this instance.
	 */
	mutex_init(&scsb->scsb_mutex, NULL, MUTEX_DRIVER, NULL);
	scsb->scsb_state |= SCSB_UMUTEX;
	cv_init(&scsb->scsb_cv, NULL, CV_DRIVER, NULL);
	scsb->scsb_state |= SCSB_CONDVAR;

	/*
	 * 1. Read interrupt property of the board and register its handler.
	 * 2. Get scsb private handle for communication via I2C Services.
	 * 3. Allocate and save an i2c_transfer_t for I2C transfers.
	 */
	/* 1 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS,
	    "interrupt-priorities") != 1) {
		int tmp[2];
		tmp[0] = scsb_pil;
		tmp[1] = hsc_pil;
		(void) ddi_prop_update_int_array(DDI_DEV_T_NONE, dip,
		"interrupt-priorities", tmp, 2);
		scsb->scsb_state |= SCSB_PROP_CREATE;
	}
	if ((i = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "interrupts", -1)) >= 0)
		scsb->scsb_state |= SCSB_P06_INTR_ON;
	else
		scsb->scsb_state |= SCSB_P06_NOINT_KLUGE;

	/*
	 * Look for the device-err-threshold property which specifies
	 * on how many errors will scsb send a warning event about it's
	 * health. The scsb_err_threshold is 10 by default.
	 */
	if ((i = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "device-err-threshold", -1)) >= 0) {
		scsb_err_threshold = i;
#ifdef	DEBUG
		cmn_err(CE_NOTE, "?scsb_attach: Found device-err-threshold"
		    " property, value %d", scsb_err_threshold);
#endif
	}
	scsb->scsb_i2c_errcnt = 0;
	scsb->scsb_err_flag = B_FALSE;
	scsb->scsb_kstat_flag = B_FALSE;

	/*
	 * If all went well, create the minor node for user level access.
	 */
	if (ddi_create_minor_node(dip, scsb_name, S_IFCHR, instance,
	    "ddi_ctl:pcihpc", NULL) == DDI_FAILURE) {
		cmn_err(CE_WARN, "scsb_attach: Failed to create minor node");
		free_resources(dip, scsb, instance);
		return (DDI_FAILURE);
	}
	scsb->scsb_state |= SCSB_MINOR_NODE;
	scsb->scsb_dev = dip;
	if (ddi_create_minor_node(dip, scsb_clone_name, S_IFCHR,
	    instance|SCSB_CLONE, "ddi_ctl:pcihpc", NULL)
	    == DDI_FAILURE) {
		cmn_err(CE_WARN, "scsb_attach: Failed to create clone node");
		free_resources(dip, scsb, instance);
		return (DDI_FAILURE);
	}
	/* CLONE */
	bzero(scsb->clone_devs, sizeof (clone_dev_t) * SCSB_CLONES_MAX);
	/* 2 */
	if (i2c_client_register(dip, &scsb->scsb_phandle) != I2C_SUCCESS) {
		cmn_err(CE_WARN,
		    "scsb_attach: Failed I2C Services registration");
		free_resources(dip, scsb, instance);
		return (DDI_FAILURE);
	}
	scsb->scsb_state |= SCSB_I2C_PHANDLE;
	/* 3 */
	if ((scsb->scsb_i2ctp = scsb_alloc_i2ctx(scsb->scsb_phandle,
	    I2C_SLEEP)) == NULL) {
		cmn_err(CE_WARN,
		    "scsb%d: i2c_transfer allocation failed", instance);
		free_resources(dip, scsb, instance);
		return (DDI_FAILURE);
	}
	scsb->scsb_state |= SCSB_I2C_TRANSFER;
	/*
	 * Now it's time to INITIALIZE the boards.
	 *
	 *  1. make sure we can do I2C bus transfers to/from the SCB.
	 *	Read the SCB PROM version for a check.
	 *  2. set SCB_INITIALIZED bit in SysCommand registers (SYS_CMD_BASE)
	 *  3. clear all LED Data registers (8) by writing 0's to turn off
	 *	all LEDs on the SSB.
	 *  4. read System Configuration Status registers (SCTRL_CFG)
	 *	to find present FRUs and set corresponding FRU bits at
	 *	LED_DATA_BASE.
	 *	Also enable devices in Topology map for the current MP_ID
	 *	and set the OK LEDs on the SSB.
	 *  5. read Brd_Hlthy registers (2 @ BRD_HLTHY_BASE)
	 *  6. Disable PSM Interrupts during initialization, mask all
	 *	interrupts, and clear Interrupt Pointer registers
	 *	by writing 0xFF to each register.
	 *  7. set SCB EEPROM address bits SPA2-SPA0 at SYS_CMD_BASE + 1
	 *  8. Install the interrupt handler if appropriate.
	 *  9. clear appropriate bits in Interrupt Mask register for those
	 *	devices that can be present for this MP_ID Topology.
	 * 10. enable PSM Interrupt by writing '1' to PSM_INT_EN bit at
	 *	SYS_CMD_BASE + 1
	 *	Also update all shadow registers for test utility
	 *	if scsb_debug is set.
	 * 11. Check if Alarm Card present at boot and set flags
	 * 12. Call hsc_attach() for slot registration.
	 * 13. Allocate, initialze, and install the kstat structures.
	 * 14. Set scsb_state_t flags to indicate SCB is ready
	 *	and announce the driver is loaded.
	 */

	/* 1. through 7. */
	if (initialize_scb(scsb) != DDI_SUCCESS) {
		if (!(scsb_debug)) {
			free_resources(dip, scsb, instance);
			return (DDI_FAILURE);
		}
	}
	/* 8. */
	/*
	 * P0.6 No Interrupt Support
	 * Instead of installing the handler, it will be called from a user
	 * program via smf_ioctl().  This flag provides knowledge of the
	 * necessary workarounds to several scsb routines.
	 */
	/*
	 * Now Install interrupt handler
	 */
	if (scsb->scsb_state & SCSB_P06_INTR_ON) {
		if (ddi_get_iblock_cookie(dip, instance,
		    &scsb->scsb_iblock) == DDI_SUCCESS) {
			mutex_init(&scsb->scsb_imutex, NULL, MUTEX_DRIVER,
			    (void *)scsb->scsb_iblock);
			scsb->scsb_state |= SCSB_IMUTEX;
			if (ddi_add_intr(dip, instance, &scsb->scsb_iblock,
			    NULL, scsb_intr_preprocess,
			    (caddr_t)scsb) != DDI_SUCCESS) {
				cmn_err(CE_WARN,
				    "scsb_attach: failed interrupt "
				    "handler registration");
				free_resources(dip, scsb, instance);
				return (DDI_FAILURE);
			}
			scb_intr_mutex = &scsb->scsb_imutex;
			nct_mutex_init |= MUTEX_INIT;
		} else {
			cmn_err(CE_WARN, "scsb_attach: failed interrupt "
			    "mutex initialization");
			if (scsb_debug) {
				scsb->scsb_state |= SCSB_P06_NOINT_KLUGE;
				scsb->scsb_state &= ~SCSB_P06_INTR_ON;
			} else {
				free_resources(dip, scsb, instance);
				return (DDI_FAILURE);
			}
		}
	}
	/* 9. */
	if (i = scsb_clear_intmasks(scsb)) {
		cmn_err(CE_WARN,
		    "scsb%d: I2C TRANSFER Failed", instance);
		if (!scsb_debug) {
			free_resources(dip, scsb, instance);
			return (DDI_FAILURE);
		}
	}

	/* 10. */
	/*
	 * For P0.6 No Interrupt Support, don't enable PSM Interrupt
	 */
	if (!(scsb->scsb_state & SCSB_P06_NOINT_KLUGE)) {
		rmask = 0x00;
		wdata = 1 << SYS_OFFSET(SCTRL_SYS_PSM_INT_ENABLE);
		i = SYS_REG_INDEX(SCTRL_SYS_PSM_INT_ENABLE,
		    SCTRL_SYS_CMD_BASE);
		reg = SCSB_REG_ADDR(i);
		if (i = scsb_write_mask(scsb, reg, rmask, wdata, (uchar_t)0)) {
			cmn_err(CE_WARN,
			    "scsb%d: I2C TRANSFER Failed", instance);
			if (!scsb_debug) {
				free_resources(dip, scsb, instance);
				return (DDI_FAILURE);
			}
		} else
			scsb->scsb_state |= SCSB_PSM_INT_ENABLED;
	}
	if (scsb_debug) {
		/*
		 * For smctrl test utility,
		 * so all data is available in shadow registers
		 *
		 * DEBUG_MODE enables private testing interfaces
		 * DIAGS_MODE permits limited testing interfaces
		 */
		scsb->scsb_state |= SCSB_DEBUG_MODE;
		mutex_enter(&scsb->scsb_mutex);
		if (scsb_readall_regs(scsb))
			cmn_err(CE_WARN,
			    "scsb_attach: scsb_readall FAILED");
		mutex_exit(&scsb->scsb_mutex);
	}
	/* 11. */
	/* Check if Alarm Card present at boot and set flags */
	if (scsb_fru_op(scsb, ALARM, 1, SCTRL_SYSCFG_BASE,
	    SCSB_FRU_OP_GET_BITVAL))
		scsb->scsb_hsc_state |= SCSB_ALARM_CARD_PRES;

	/* 12. */
	if (scsb_debug & 0x0004)
		cmn_err(CE_NOTE,
		    "scsb_attach: registering cPCI slots");
	if (scsb_hsc_attach(dip, scsb, instance) != DDI_SUCCESS) {
		if (scsb_debug & 0x00008000) {
			cmn_err(CE_WARN,
			"scsb: Hotswap controller initialisation"
			    " failed\n");
		}
	} else
		scsb->scsb_hsc_state |= SCSB_HSC_INIT;
	/* 13. */
	/*
	 * allocate and install the kstat data structures
	 */
	if (scsb_alloc_kstats(scsb) != DDI_SUCCESS) {
		if (scsb_debug & 0x0006)
			cmn_err(CE_WARN, "scsb_attach: ERROR adding kstats");
	}
	/* 14. */
	scsb->scsb_state |= SCSB_UP;
	scsb_global_state |= SCSB_UP;
	ddi_report_dev(scsb->scsb_dev);
	cmn_err(CE_CONT, "?%s%d: "
	"Prom Version %s, Midplane Id %x\n",
	    ddi_driver_name(scsb->scsb_dev),
	    scsb->scsb_instance,
	    (scsb->scsb_state & SCSB_P06_PROM) ? "0.6" :
	    (scsb->scsb_state & SCSB_P10_PROM) ? "1.0" :
	    (scsb->scsb_state & SCSB_P15_PROM) ? "1.5" :
	    (scsb->scsb_state & SCSB_P20_PROM) ? "2.0" : "Unknown",
	    mct_system_info.mid_plane.fru_id);
	return (DDI_SUCCESS);
}

/*
 * This funciton is called from scsb_attach(), and from scsb_intr() as part
 * of Hot Insertion support, to check the SCB PROM ID register and set
 * scsb_state bits and register table pointers as necessary.
 */
static int
scb_check_version(scsb_state_t *scsb)
{
	int		hotswap = 0;
	uchar_t		data;
	if (scsb->scsb_state & SCSB_UP) {
		/*
		 * If driver is UP, then this call is from scsb_intr()
		 * as part of Hot Insertion support.
		 */
		hotswap = 1;
	}
	/* Read the SCB PROM ID */
	if (scsb_rdwr_register(scsb, I2C_WR_RD, (uchar_t)SCTRL_PROM_VERSION, 1,
	    &data, 1)) {
		if (!(hotswap && scsb->scsb_state & SCSB_FROZEN))
			cmn_err(CE_WARN, "scsb%d: I2C TRANSFER Failed",
			    scsb->scsb_instance);
		if (scsb_debug & 0x0006) {
				cmn_err(CE_WARN,
				    "scsb_attach(%d): failed read of PROM ID",
				    scsb->scsb_instance);
		}
		return (DDI_FAILURE);
	}
	/*
	 * compare with stored version number, and if different,
	 * report a warning and keep the driver FROZEN
	 */
	if (hotswap) {
		if (((mct_system_info.fru_info_list[SCB])[0].fru_version & 0xf)
		    == (data & 0xf)) {
			return (DDI_SUCCESS);
		}
		if (scsb_debug & 0x00020000) {
			cmn_err(CE_NOTE,
			    "scb_check_version: SCB version %d "
			    "replacing version %d", data,
			    (mct_system_info.fru_info_list[SCB])[0].
			    fru_version & 0xf);
		}
	}
	if ((data & 0xf) == SCTRL_PROM_P06) {
		scsb->scsb_state |= SCSB_P06_PROM;
	} else if ((data & 0xf) == SCTRL_PROM_P10) {
		scsb->scsb_state |= SCSB_P10_PROM;
	} else if ((data & 0xf) == SCTRL_PROM_P15) {
		scsb->scsb_state |= SCSB_P15_PROM;
	} else if ((data & 0xf) == SCTRL_PROM_P20) {
		scsb->scsb_state |= SCSB_P20_PROM;
	}
	if (!(scsb->scsb_state & SCSB_SCB_PRESENT))
		scsb->scsb_state |= SCSB_SCB_PRESENT;
	if (IS_SCB_P10) {
		scb_reg_index  = scb_10_reg_index;
		scb_numregs    = scb_10_numregs;
		scb_fru_offset = scb_10_fru_offset;
		scb_sys_offset = scb_10_sys_offset;
	} else { /* if (IS_SCB_P15) */
		scb_reg_index  = scb_15_reg_index;
		scb_numregs    = scb_15_numregs;
		scb_fru_offset = scb_15_fru_offset;
		scb_sys_offset = scb_15_sys_offset;
	}
	if (!(IS_SCB_P15) && !(IS_SCB_P10)) {
		cmn_err(CE_WARN, "scsb%d: SCB Version %d not recognized",
		    scsb->scsb_instance, data);
		if (hotswap)
			scsb->scsb_state |= SCSB_FROZEN;
		if (!(scsb_debug)) {
			return (DDI_FAILURE);
		}
		/*
		 * DEBUG: Assume SCB15
		 */
		scsb->scsb_state |= SCSB_P15_PROM;
	}
	return (DDI_SUCCESS);
}

/*
 * SCB initialization steps to be called from scsb_attach()
 * or from scsb_intr() calling scsb_restore() on Hot Insertion.
 */
static int
initialize_scb(scsb_state_t *scsb)
{
	register int	i;
	uchar_t		reg, wdata, rmask;
	/*
	 * If called from scsb_intr(), we've already done this
	 */
	if (!(scsb->scsb_state & SCSB_IN_INTR))
		if (scb_check_version(scsb) != DDI_SUCCESS)
			return (DDI_FAILURE);
	/*
	 * 2. Set the SCB_INIT bit in the System Command register
	 */
	rmask = 0x00;	/* P1.0: 0x60; */
	wdata = 1 << SYS_OFFSET(SCTRL_SYS_SCB_INIT);
	i = SYS_REG_INDEX(SCTRL_SYS_SCB_INIT, SCTRL_SYS_CMD_BASE);
	reg = SCSB_REG_ADDR(i);
	if (i = scsb_write_mask(scsb, reg, rmask, wdata, 0)) {
		cmn_err(CE_WARN,
		    "scsb%d: I2C TRANSFER Failed", scsb->scsb_instance);
		if (scsb_debug & 0x0006) {
			cmn_err(CE_NOTE,
			"scsb_attach: failed to set SCB_INIT");
		}
		return (DDI_FAILURE);
	}
	/* 3. For P1.0 and previous system, turn off all LEDs */
	if (IS_SCB_P10) {
		if (scsb_debug & 0x0004) {
			cmn_err(CE_NOTE, "scsb_attach(%d): turning LEDs off",
			    scsb->scsb_instance);
		}
		if (i = scsb_leds_switch(scsb, OFF)) {
			cmn_err(CE_WARN, "scsb%d: I2C TRANSFER Failed",
			    scsb->scsb_instance);
			return (DDI_FAILURE);
		}
	}
	/* 4. Read the SYSCFG registers, update FRU info and SSB LEDs */
	if (scsb_debug & 0x0004)
		cmn_err(CE_NOTE, "scsb_attach(%d): reading config registers",
		    scsb->scsb_instance);
	if ((i = scsb_check_config_status(scsb)) == 0) {
		if (!(scsb->scsb_state & SCSB_TOPOLOGY)) {
			scsb_set_topology(scsb);
			if (scsb_debug & 0x0004)
				cmn_err(CE_NOTE, "scsb_attach(%d): mpid = 0x%x",
				    scsb->scsb_instance,
				    mct_system_info.mid_plane.fru_id);
		} else {
			fru_info_t	*fru_ptr;
			/*
			 * walk through FRUs and update FRU info
			 */
			for (i = 0; i < SCSB_UNIT_TYPES; ++i) {
				fru_ptr = mct_system_info.fru_info_list[i];
				while (fru_ptr != NULL) {
					update_fru_info(scsb, fru_ptr);
					fru_ptr = fru_ptr->next;
				}
			}
		}
		i = scsb_set_scfg_pres_leds(scsb, NULL);
	}
	if (i) {
		cmn_err(CE_WARN, "scsb%d: I2C TRANSFER Failed",
		    scsb->scsb_instance);
		return (DDI_FAILURE);
	}
	/* 5. read the Board Healthy registers */
	if (scsb_debug & 0x0004)
		cmn_err(CE_NOTE, "scsb_attach(%d): reading Brd_Hlthy registers",
		    scsb->scsb_instance);
	i = scsb_read_bhealthy(scsb);
	if (i) {
		cmn_err(CE_WARN, "scsb%d: I2C TRANSFER Failed",
		    scsb->scsb_instance);
		return (DDI_FAILURE);
	}
	/* 6. Clear Interrupt Source registers */
	/*
	 * Due to some registration problems, we must first disable
	 * global interrupts which may be the default reset value
	 * itself. However, this is a safe step to do in case of
	 * implementation changes.
	 *
	 * Disable Global SCB Interrupts now
	 */
	rmask = 0x00;	/* P1.0: 0x60; */
	wdata = 1 << SYS_OFFSET(SCTRL_SYS_PSM_INT_ENABLE);
	i = SYS_REG_INDEX(SCTRL_SYS_PSM_INT_ENABLE, SCTRL_SYS_CMD_BASE);
	reg = SCSB_REG_ADDR(i);
	if (i = scsb_write_mask(scsb, reg, rmask, (uchar_t)0, wdata)) {
		cmn_err(CE_WARN, "scsb%d: Cannot turn off PSM_INT",
		    scsb->scsb_instance);
		return (DDI_FAILURE);
	}
	/* Mask all interrupt sources */
	if (i = scsb_setall_intmasks(scsb)) {
		cmn_err(CE_WARN, "scsb%d: I2C TRANSFER Failed",
		    scsb->scsb_instance);
		return (DDI_FAILURE);
	}
	/* Clear any latched interrupts */
	if (i = scsb_clear_intptrs(scsb)) {
		cmn_err(CE_WARN, "scsb%d: I2C TRANSFER Failed",
		    scsb->scsb_instance);
		return (DDI_FAILURE);
	}
	/* 7. set SCB EEPROM address: NOT USED */
	return (DDI_SUCCESS);
}

/*
 * Based on MC conditions, scsb_detach should eventually be made to always
 * return FAILURE, as the driver should not be allowed to detach after some
 * hs slots have been used.
 */
static int
scsb_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	scsb_state_t	*scsb;
	uchar_t		reg, wdata;

	/*
	 * TBD: make sure there are no outstanding operations on the system
	 * monitor card before detaching.
	 */
	instance = ddi_get_instance(dip);
	if (scsb_debug & 0x0005)
		cmn_err(CE_NOTE, "scsb_detach[%d]", instance);
	if (cmd != DDI_DETACH) {
		if (scsb_debug & 0x0006)
			cmn_err(CE_NOTE,
			    "scsb_detach(%d): command %x is not DDI_DETACH\n",
			    instance, cmd);
		return (DDI_FAILURE);
	}
	scsb = (scsb_state_t *)ddi_get_soft_state(scsb_state, instance);
	scsb->scsb_state &= ~SCSB_UP;
	scsb_global_state &= ~SCSB_UP;
	if (scsb->scsb_hsc_state & SCSB_HSC_INIT) {
		(void) scsb_hsc_detach(dip, scsb, instance);
		scsb->scsb_hsc_state &= ~SCSB_HSC_INIT;
	}
	if (scsb->scsb_state & SCSB_PSM_INT_ENABLED) {
		/*
		 * Disable Global SCB Interrupts now
		 */
		wdata = 1 << SYS_OFFSET(SCTRL_SYS_PSM_INT_ENABLE);
		reg = SYS_REG_INDEX(SCTRL_SYS_PSM_INT_ENABLE,
		    SCTRL_SYS_CMD_BASE);
		if (scsb_write_mask(scsb, reg, (uchar_t)0, (uchar_t)0, wdata)) {
			cmn_err(CE_WARN,
			    "scsb%d: Cannot turn off PSM_INT", instance);
			if (!scsb_debug) {
				(void) free_resources(dip, scsb, instance);
				return (DDI_FAILURE);
			}
		}
		/* Mask all interrupts */
		if (scsb_setall_intmasks(scsb)) {
			cmn_err(CE_WARN,
			    "scsb%d: I2C TRANSFER Failed", instance);
			if (!scsb_debug) {
				(void) free_resources(dip, scsb, instance);
				return (DDI_FAILURE);
			}
		}
		/* Clear all latched interrupts */
		if (scsb_clear_intptrs(scsb)) {
			cmn_err(CE_WARN,
			    "scsb%d: I2C TRANSFER Failed", instance);
			if (!scsb_debug) {
				(void) free_resources(dip, scsb, instance);
				return (DDI_FAILURE);
			}
		}
	}
	if (scsb->scsb_opens && scsb->scsb_rq != NULL)
		qprocsoff(scsb->scsb_rq);
	/* CLONE */
	(void) scsb_queue_ops(scsb, QPROCSOFF, 0, NULL, NULL);
	/*
	 * free the allocated resources
	 */
	free_resources(dip, scsb, instance);
	return (DDI_SUCCESS);
}

static void
free_resources(dev_info_t *dip, scsb_state_t *scsb, int instance)
{
	if (scsb_debug & 0x0005) {
		cmn_err(CE_NOTE, "free_resources[%d], scsb_state=0x%x",
		    instance, scsb->scsb_state);
		drv_usecwait(500000);
	}
	if (scsb->scsb_state & SCSB_P06_INTR_ON &&
	    scsb->scsb_state & SCSB_IMUTEX) {
		scsb->scsb_state &= ~SCSB_P06_INTR_ON;
		ddi_remove_intr(dip, 0, scsb->scsb_iblock);
	}
	if (scsb->scsb_state & SCSB_KSTATS) {
		scsb_free_kstats(scsb);
		scsb->scsb_state &= ~SCSB_KSTATS;
	}
	if (scsb->scsb_state & SCSB_TOPOLOGY) {
		scsb_free_topology(scsb);
		scsb->scsb_state &= ~SCSB_TOPOLOGY;
	}

	nct_mutex_init = MUTEX_UNINIT;
	if (scsb->scsb_state & SCSB_IMUTEX) {
		scsb->scsb_state &= ~SCSB_IMUTEX;
		mutex_destroy(&scsb->scsb_imutex);
	}
	if (scsb->scsb_state & SCSB_I2C_TRANSFER) {
		scsb->scsb_state &= ~SCSB_I2C_TRANSFER;
		i2c_transfer_free(scsb->scsb_phandle, scsb->scsb_i2ctp);
	}
	if (scsb->scsb_state & SCSB_I2C_PHANDLE) {
		scsb->scsb_state &= ~SCSB_I2C_PHANDLE;
		i2c_client_unregister(scsb->scsb_phandle);
	}
	if (scsb->scsb_state & SCSB_MINOR_NODE) {
		scsb->scsb_state &= ~SCSB_MINOR_NODE;
		ddi_remove_minor_node(dip, NULL);
	}
	if (scsb->scsb_state & SCSB_PROP_CREATE) {
		scsb->scsb_state &= ~SCSB_PROP_CREATE;
		(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
		    "interrupt-priorities");
	}
	/* ddi_prop_remove_all(dip); */
	if (scsb->scsb_state & SCSB_CONDVAR) {
		scsb->scsb_state &= ~SCSB_CONDVAR;
		cv_destroy(&scsb->scsb_cv);
	}
	if (scsb->scsb_state & SCSB_UMUTEX) {
		scsb->scsb_state &= ~SCSB_UMUTEX;
		mutex_destroy(&scsb->scsb_mutex);
	}
	ddi_soft_state_free(scsb_state, instance);
}

/*
 * Just for testing scsb's poll function
 */
static int
scsb_fake_intr(scsb_state_t *scsb, uint32_t evcode)
{
	if (evcode == 0)
		evcode = scsb_event_code;
	else
		scsb_event_code = evcode;
	if (scsb_debug & 0x4001) {
		cmn_err(CE_NOTE, "scsb_fake_intr: event = 0x%x, scsb_rq=0x%p",
		    scsb_event_code, (void *)scsb->scsb_rq);
	}
	/*
	 * Allow access to shadow registers even though SCB is removed
	 *
	 * if (scsb->scsb_state & SCSB_FROZEN) {
	 *	return (EAGAIN);
	 * }
	 */
	if (scsb_debug & 0x00040000) {
		check_fru_info(scsb, evcode);
		add_event_code(scsb, evcode);
	}
	/* just inform user-level via poll about this event */
	if (scsb_queue_ops(scsb, QPUT_INT32, 1, &evcode, "scsb_fake_intr")
	    == QOP_FAILED)
		return (ENOMEM);
	return (0);
}

/* ARGSUSED */
static int
scsb_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int	retval = DDI_FAILURE;

	if (scsb_debug & 0x0001)
		cmn_err(CE_NOTE, "scsb_info()");

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (getminor((dev_t)arg) == 0 && scsb_dip != NULL) {
			*result = (void *) scsb_dip;
			retval = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		if (getminor((dev_t)arg) == 0) {
			*result = (void *)0;
			retval = DDI_SUCCESS;
		}
		break;

	default:
		break;
	}

	return (retval);
}


/*
 * SCSB STREAMS routines
 */
/*ARGSUSED*/
static int
sm_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	int		instance, clone;
	minor_t		minor_dev;
	clone_dev_t	*clptr;
	scsb_state_t	*scsb;

	minor_dev = getminor(*devp);
	instance = SCSB_GET_INSTANCE(minor_dev);
	scsb = ddi_get_soft_state(scsb_state, instance);
	if (scsb == NULL)
		return (ENXIO);

	if (scsb_debug & 0x0009) {
		cmn_err(CE_NOTE, "sm_open(%d) q=0x%p", instance, (void *)q);
	}
	if (!(scsb->scsb_state & SCSB_UP)) {
		return (ENODEV);
	}
	/*
	 * Don't fail the open if SCB removed since we still want to satisfy
	 * read requests from the shadow registers, the last know register
	 * contents.  On new SCB insertion, all will be re-initialized,
	 * including envmond and it's policies.
	 *
	 * if (scsb->scsb_state & SCSB_FROZEN) {
	 *	return (EAGAIN);
	 * }
	 */
	ASSERT(credp != NULL);
	/*
	 * XXX check for root access here, return EPERM if not root open
	 */
	if (sflag == MODOPEN) {
		/* scsb module is being pushed */
		if (scsb_debug & 0x0008)
			cmn_err(CE_NOTE, "sm_open(%d): MODOPEN", instance);
		/*
		 * this is no longer supported
		 */
		return (ENXIO);
	} else if (sflag == CLONEOPEN) {
		/* scsb is being opened as a clonable driver */
		if (scsb_debug & 0x0008)
			cmn_err(CE_NOTE, "sm_open(%d): CLONEOPEN", instance);
		/*
		 * The cloned stream is not handled via the clone driver.
		 * See the minor device code below.
		 */
		return (ENXIO);
	} else if (minor_dev & SCSB_CLONE) {
		/*
		 * First check for the SCSB_CLONE device.
		 *	Find an available clone_devs[] entry, or return ENXIO.
		 *	Make new dev_t and store in *devp.
		 */
		if (scsb_debug & 0x0008)
			cmn_err(CE_NOTE,
			    "sm_open(%d): SCSB_CLONE OPEN", instance);
		mutex_enter(&scsb->scsb_mutex);
		if ((clone = scsb_queue_ops(scsb, QFIRST_AVAILABLE, 0, NULL,
		"scsb_open")) == QOP_FAILED) {
			mutex_exit(&scsb->scsb_mutex);
			return (ENXIO);
		}
		clptr = &scsb->clone_devs[clone];
		clptr->cl_flags = SCSB_OPEN;
		clptr->cl_rq = RD(q);
		clptr->cl_minor = SCSB_MAKE_MINOR(instance, clone);
		*devp = makedevice(getmajor(*devp), clptr->cl_minor);
		scsb->scsb_clopens++;
		if (scsb_debug & 0x0008)
			cmn_err(CE_NOTE,
			    "sm_open(%d): new clone device minor: 0x%x"
			    " stream queue is 0x%p",
			    instance, clptr->cl_minor, (void *)q);
	} else {
		/* scsb is being opened as a regular driver */
		if (scsb_debug & 0x0008)
			cmn_err(CE_NOTE, "sm_open(%d): DEVOPEN", instance);
		mutex_enter(&scsb->scsb_mutex);
		if (scsb->scsb_state & SCSB_EXCL) {
			if (scsb_debug & 0x0008)
				cmn_err(CE_NOTE,
				    "sm_open(%d): can't open, state is EXCL",
				    instance);
			mutex_exit(&scsb->scsb_mutex);
			return (EBUSY);
		}
		if (flag & FEXCL) {
			if (scsb_debug & 0x0008)
				cmn_err(CE_NOTE, "sm_open(%d): is EXCL",
				    instance);
			if (scsb->scsb_state & SCSB_OPEN) {
				if (scsb_debug & 0x0008)
					cmn_err(CE_NOTE,
					    "sm_open(%d): cannot open EXCL",
					    instance);
				mutex_exit(&scsb->scsb_mutex);
				return (EBUSY);
			}
			scsb->scsb_state |= SCSB_EXCL;
		}
		if (scsb->scsb_opens && scsb->scsb_rq != NULL &&
		    scsb->scsb_rq != RD(q)) {
			if (scsb_debug & 0x000a)
				cmn_err(CE_WARN, "sm_open[%d]: q (0x%p) != "
				    "scsb_rq (0x%p)",
				    instance, (void *)RD(q),
				    (void *)scsb->scsb_rq);
		}
		scsb->scsb_rq = RD(q);
		scsb->scsb_opens++;
	}
	scsb->scsb_state |= SCSB_OPEN;
	mutex_exit(&scsb->scsb_mutex);
	RD(q)->q_ptr = WR(q)->q_ptr = scsb;
	qprocson(q);
	return (0);
}

/*ARGSUSED*/
static int
sm_close(queue_t *q, int flag, cred_t *credp)
{
	scsb_state_t	*scsb;
	int		clone;
	clone_dev_t	*clptr = NULL;

	scsb = (scsb_state_t *)q->q_ptr;
	if (scsb_debug & 0x0009)
		cmn_err(CE_NOTE, "sm_close[%d](0x%p)", scsb->scsb_instance,
		    (void *)q);
	if (scsb->scsb_clopens) {
		mutex_enter(&scsb->scsb_mutex);
		if ((clone = scsb_queue_ops(scsb, QFIND_QUEUE, 0,
		    (void *) RD(q), "scsb_close")) != QOP_FAILED) {
			clptr = &scsb->clone_devs[clone];
			clptr->cl_flags = 0;
			clptr->cl_rq = NULL;
			scsb->scsb_clopens--;
		}
		mutex_exit(&scsb->scsb_mutex);
		if (scsb_debug & 0x0008 && clone < SCSB_CLONES_MAX &&
		    clone >= SCSB_CLONES_FIRST)
			cmn_err(CE_NOTE, "sm_close(%d): SCSB_CLONE 0x%x",
			    scsb->scsb_instance, clptr->cl_minor);
	}
	if (clptr == NULL && scsb->scsb_opens) {
		if (scsb_debug & 0x0008)
			cmn_err(CE_NOTE, "sm_close(%d): DEVOPEN, opens=%d",
			    scsb->scsb_instance, scsb->scsb_opens);
		if (RD(q) != scsb->scsb_rq) {
			if (scsb_debug & 0x0008)
				cmn_err(CE_WARN,
				    "sm_close(%d): DEVOPEN, q != scsb_rq",
				    scsb->scsb_instance);
		}
		mutex_enter(&scsb->scsb_mutex);
		scsb->scsb_opens = 0;
		if (scsb->scsb_state & SCSB_EXCL) {
			scsb->scsb_state &= ~SCSB_EXCL;
		}
		scsb->scsb_rq = (queue_t *)NULL;
		mutex_exit(&scsb->scsb_mutex);
	}
	if (scsb->scsb_opens == 0 && scsb->scsb_clopens == 0) {
		scsb->scsb_state &= ~SCSB_OPEN;
	}
	RD(q)->q_ptr = WR(q)->q_ptr = NULL;
	qprocsoff(q);
	return (0);
}

/*ARGSUSED*/
static int
sm_rput(queue_t *q, mblk_t *mp)
{
	if (scsb_debug & 0x0010)
		cmn_err(CE_NOTE, "sm_rput");
	return (0);
}

static int
sm_wput(queue_t *q, mblk_t *mp)
{
	scsb_state_t	*scsb = (scsb_state_t *)WR(q)->q_ptr;

	if (scsb_debug & 0x0010)
		cmn_err(CE_NOTE, "sm_wput(%d): mp %p", scsb->scsb_instance,
		    (void *)mp);

	switch (mp->b_datap->db_type) {
	default:
		freemsg(mp);
		break;

	case M_FLUSH:	/* canonical flush handling */
		if (*mp->b_rptr & FLUSHW) {
			flushq(q, FLUSHDATA);
			/* free any messages tied to scsb */
		}

		if (*mp->b_rptr & FLUSHR) {
			*mp->b_rptr &= ~FLUSHW;
			qreply(q, mp);
		} else
			freemsg(mp);
		break;

	case M_IOCTL:
		if (scsb_debug & 0x0010)
			cmn_err(CE_NOTE, "sm_wput(%d): M_IOCTL",
			    scsb->scsb_instance);
		/* do ioctl */
		smf_ioctl(q, mp);
		break;

	case M_DATA:
		if (scsb_debug & 0x0010)
			cmn_err(CE_NOTE, "sm_wput(%d): M_DATA",
			    scsb->scsb_instance);
		if (!(scsb->scsb_state & SCSB_UP)) {
			freemsg(mp);
			return (0);
		}
		freemsg(mp);
		break;

	case M_CTL:
		if (scsb_debug & 0x0010)
			cmn_err(CE_NOTE, "sm_wput(%d): M_CTL",
			    scsb->scsb_instance);
		freemsg(mp);
		break;
	}

	return (0);
}


/*
 * These are the system monitor upper ioctl functions.
 */
static void
smf_ioctl(queue_t *q, mblk_t *mp)
{
	scsb_state_t	*scsb = (scsb_state_t *)q->q_ptr;
	struct iocblk	*iocp = (struct iocblk *)mp->b_rptr;

	if (scsb_debug & 0x0020)
		cmn_err(CE_NOTE, "smf_ioctl(%d): (%p)->cmd=%x",
		    scsb->scsb_instance, (void *)mp, iocp->ioc_cmd);

	if (!(scsb->scsb_state & SCSB_UP)) {
		miocnak(q, mp, 0, ENXIO);
		return;
	}
	/*
	 * Don't fail ALL commands if the SCB removed, since we still want to
	 * satisfy some requests from the shadow registers, the last known
	 * register contents.
	 *
	 * if (scsb->scsb_state & SCSB_FROZEN) {
	 *	iocp->ioc_error = EAGAIN;
	 *	mp->b_datap->db_type = M_IOCNAK;
	 *	qreply(q, mp);
	 *	return;
	 * }
	 */

	iocp->ioc_error = 0;
	switch (iocp->ioc_cmd) {
	default:
		/* if we don't understand the ioctl */
		if (scsb_debug & 0x0022)
			cmn_err(CE_NOTE, "smf_ioctl(%d):unkown ioctl %x",
			    scsb->scsb_instance, iocp->ioc_cmd);
		iocp->ioc_error = EINVAL;
		break;

	case ENVC_IOC_GETMODE:
	{
		uint8_t *curr_mode;

		iocp->ioc_error = miocpullup(mp, sizeof (uint8_t));
		if (iocp->ioc_error != 0)
			break;

		curr_mode = (uint8_t *)mp->b_cont->b_rptr;
		if (scsb->scsb_state & SCSB_DEBUG_MODE)
			*curr_mode = (uint8_t)ENVC_DEBUG_MODE;
		else if (scsb->scsb_state & SCSB_DIAGS_MODE)
			*curr_mode = (uint8_t)ENVCTRL_DIAG_MODE;
		else
			*curr_mode = (uint8_t)ENVCTRL_NORMAL_MODE;

		if (scsb_debug & 0x20) {
			cmn_err(CE_NOTE, "IOC_GETMODE: returning mode 0x%x",
			    *curr_mode);
		}
		break;
	}

	case ENVC_IOC_SETMODE:
	{
		uint8_t	*curr_mode;

		iocp->ioc_error = miocpullup(mp, sizeof (uint8_t));
		if (iocp->ioc_error != 0)
			break;

		curr_mode = (uint8_t *)mp->b_cont->b_rptr;
		switch (*curr_mode) {
		case ENVCTRL_NORMAL_MODE:
			scsb->scsb_state &=
			    ~(SCSB_DEBUG_MODE | SCSB_DIAGS_MODE);
			break;
		case ENVCTRL_DIAG_MODE:
			scsb->scsb_state |=  SCSB_DIAGS_MODE;
			scsb->scsb_state &= ~SCSB_DEBUG_MODE;
			break;
		case ENVC_DEBUG_MODE:
			if (scsb->scsb_state &
			    (SCSB_DIAGS_MODE | SCSB_DEBUG_MODE)) {
				scsb->scsb_state &= ~SCSB_DIAGS_MODE;
				scsb->scsb_state |=  SCSB_DEBUG_MODE;
			} else {
				iocp->ioc_error = EACCES;
			}
			break;
		default:
			if (scsb_debug & 0x22) {
				cmn_err(CE_WARN,
				    "IOC_SETMODE: Invalid mode 0x%x",
				    *curr_mode);
			}
			iocp->ioc_error = EINVAL;
			break;
		}
		break;
	}

	case ENVC_IOC_ACQUIRE_SLOT_LED_CTRL:
		if (scsb->scsb_state & SCSB_APP_SLOTLED_CTRL)
			iocp->ioc_error = EAGAIN;
		else {
			scsb->scsb_state |= SCSB_APP_SLOTLED_CTRL;
			iocp->ioc_error = 0;
		}
		break;

	case ENVC_IOC_RELEASE_SLOT_LED_CTRL:
		scsb->scsb_state &= ~SCSB_APP_SLOTLED_CTRL;
		iocp->ioc_error = 0;
		break;

	/*
	 * Not an exposed interface, only used by development utilities.
	 */
	case SCSBIOC_GET_VERSIONS:
	{
		uint8_t *ppromid, promid;
		scsb_ids_t *sids;

		if (iocp->ioc_count == sizeof (uint8_t)) {
			iocp->ioc_error = miocpullup(mp, sizeof (uint8_t));
			if (iocp->ioc_error != 0)
				break;

			ppromid = (uint8_t *)mp->b_cont->b_rptr;
			*ppromid = (uint8_t)(mct_system_info.
			    fru_info_list[SCB])->fru_version;
			promid = *ppromid;
		} else {
			iocp->ioc_error = miocpullup(mp, sizeof (scsb_ids_t));
			if (iocp->ioc_error != 0)
				break;

			sids = (scsb_ids_t *)mp->b_cont->b_rptr;
			bcopy(modldrv.drv_linkinfo, sids->modldrv_string,
			    SCSB_MODSTR_LEN);
			bcopy(scsb_build_version, sids->scsb_version,
			    SCSB_VERSTR_LEN);
			sids->promid = (uint8_t)(mct_system_info.
			    fru_info_list[SCB])->fru_version;

			promid = sids->promid;
			if (scsb_debug & 0x20) {
				cmn_err(CE_NOTE,
				    "IOC_GET_VERSIONS: sizeof(scsb_ids_t) "
				    "= %lu", sizeof (scsb_ids_t));
			}
		}
		if (scsb_debug & 0x20) {
			cmn_err(CE_NOTE,
			    "IOC_GET_VERSIONS: SCB PROMID = 0x%x", promid);
		}
		break;
	}

#ifdef	DEBUG
	case ENVC_IOC_REGISTER_PID:
		iocp->ioc_error = miocpullup(mp, sizeof (pid_t));
		if (iocp->ioc_error == 0) {
			if (add_event_proc(scsb, *(pid_t *)mp->b_cont->b_rptr))
				iocp->ioc_error = ENOMEM;
		}
		break;

	case ENVC_IOC_UNREGISTER_PID:
		iocp->ioc_error = miocpullup(mp, sizeof (pid_t));
		if (iocp->ioc_error == 0) {
			if (del_event_proc(scsb, *(pid_t *)mp->b_cont->b_rptr))
				iocp->ioc_error = EINVAL;
		}
		break;

	case SCSBIOC_VALUE_MODE:
	{
		uint32_t *mode_vals;
		int	three_vals = 0;

		if (!(scsb->scsb_state & SCSB_DEBUG_MODE)) {
			iocp->ioc_error = EINVAL;
			break;
		}

		if (iocp->ioc_count == sizeof (uint32_t) * 3)
			three_vals = 1;
		else if (iocp->ioc_count != sizeof (uint32_t) * 2) {
			iocp->ioc_error = EINVAL;
			break;
		}

		iocp->ioc_error = miocpullup(mp, iocp->ioc_count);
		if (iocp->ioc_error != 0)
			break;

		/*
		 * check mode_vals[0] for get/set option.  setting
		 * scsb_state is not valid for now.  0 == GET, 1 == SET
		 */
		mode_vals = (uint32_t *)mp->b_cont->b_rptr;
		if (mode_vals[0]) {
			scsb_debug = mode_vals[1];
		} else {
			mode_vals[0] = scsb->scsb_state;
			if (three_vals) {
				mode_vals[1] = scsb->scsb_hsc_state;
				mode_vals[2] = scsb_debug;
			} else
				mode_vals[1] = scsb_debug;
		}
		if ((scsb_debug & 0x20) && three_vals) {
			cmn_err(CE_NOTE, "IOC_VALUE_MODE: mode_vals: "
			    "0x%x/0x%x/0x%x; ioc_count = 0x%lx",
			    mode_vals[0], mode_vals[1], mode_vals[2],
			    iocp->ioc_count);
		}
		break;
	}

#ifdef DEBUG
	case SCSBIOC_GET_SLOT_INFO:
	{
		hsc_slot_t	*slot_info = NULL;
		uint32_t	*slot_vals;
		int		pslotnum;

		if (!(scsb->scsb_state & SCSB_DEBUG_MODE)) {
			iocp->ioc_error = EINVAL;
			break;
		}

		iocp->ioc_error = miocpullup(mp, sizeof (uint32_t) * 2);
		if (iocp->ioc_error != 0)
			break;

		slot_vals = (uint32_t *)mp->b_cont->b_rptr;
		pslotnum = (int)*slot_vals;
		hsc_ac_op((int)scsb->scsb_instance, pslotnum,
		    SCSB_HSC_AC_GET_SLOT_INFO, &slot_info);
		if (slot_info == NULL) {
			iocp->ioc_error = ENODEV;
			break;
		}
		*slot_vals = (uint32_t)slot_info->hs_flags;
		*(++slot_vals) = (uint32_t)slot_info->hs_slot_state;
		if (scsb_debug & 0x20) {
			cmn_err(CE_NOTE, "IOC_GET_SLOT_STATE: slot_vals: "
			    "0x%x/0x%x; ioc_count = 0x%lx",
			    slot_vals[0], slot_vals[1], iocp->ioc_count);
		}
		break;
	}
#endif /* DEBUG */

	case SCSBIOC_GET_FAN_STATUS:
	case SCSBIOC_GET_INTR_ARRAY:
		/* for now we don't understand these ioctls */
		if (scsb_debug & 0x0022)
			cmn_err(CE_NOTE, "smf_ioctl(%d):unknown ioctl %x",
			    scsb->scsb_instance, iocp->ioc_cmd);
		iocp->ioc_error = EINVAL;
		break;
#endif	/* DEBUG */

	case SCSBIOC_LED_OK_GET:
	case SCSBIOC_LED_NOK_GET:
	case SCSBIOC_LED_OK_SET:
	case SCSBIOC_LED_NOK_SET:
	case SCSBIOC_BHEALTHY_GET:
	case SCSBIOC_SLOT_OCCUPANCY:
	case SCSBIOC_RESET_UNIT:
		if (!(scsb->scsb_state & (SCSB_DIAGS_MODE | SCSB_DEBUG_MODE))) {
			iocp->ioc_error = EACCES;
			break;
		}
		/*FALLTHROUGH*/

	case ENVC_IOC_GETDSKLED:
	case ENVC_IOC_SETDSKLED:
	case ENVC_IOC_SETFSP:
	{
		scsb_uinfo_t *suip;

		iocp->ioc_error = miocpullup(mp, sizeof (scsb_uinfo_t));
		if (iocp->ioc_error != 0)
			break;

		suip = (scsb_uinfo_t *)mp->b_cont->b_rptr;
		switch (iocp->ioc_cmd) {
		case SCSBIOC_LED_OK_GET:
			iocp->ioc_error = scsb_led_get(scsb, suip, OK);
			break;
		case SCSBIOC_LED_NOK_GET:
			iocp->ioc_error = scsb_led_get(scsb, suip, NOK);
			break;
		case SCSBIOC_LED_OK_SET:
			iocp->ioc_error = scsb_led_set(scsb, suip, OK);
			break;
		case SCSBIOC_LED_NOK_SET:
			iocp->ioc_error = scsb_led_set(scsb, suip, NOK);
			break;
		case SCSBIOC_BHEALTHY_GET:
			iocp->ioc_error = scsb_bhealthy_slot(scsb, suip);
			break;
		case SCSBIOC_SLOT_OCCUPANCY:
			iocp->ioc_error = scsb_slot_occupancy(scsb, suip);
			break;
		case SCSBIOC_RESET_UNIT:
			iocp->ioc_error = scsb_reset_unit(scsb, suip);
			break;
		case ENVC_IOC_GETDSKLED:
			if (suip->unit_type != DISK) {
				iocp->ioc_error = EINVAL;
				break;
			}
			iocp->ioc_error = scsb_led_get(scsb, suip, NOUSE);
			break;
		case ENVC_IOC_SETDSKLED:
			if (suip->unit_type != DISK) {
				iocp->ioc_error = EINVAL;
				break;
			}
			iocp->ioc_error = scsb_led_set(scsb, suip, NOUSE);
			break;
		case ENVC_IOC_SETFSP:
			if (scsb->scsb_state & SCSB_FROZEN) {
				iocp->ioc_error = EAGAIN;
				break;
			}
			iocp->ioc_error = scsb_led_set(scsb, suip, NOUSE);
			break;
		}
		break;
	}

	case SCSBIOC_FAKE_INTR: {
		uint32_t	ui;

		if (!(scsb->scsb_state & SCSB_DEBUG_MODE)) {
			iocp->ioc_error = EINVAL;
			break;
		}
		if (mp->b_cont == NULL)
			ui = 0;
		else {
			iocp->ioc_error = miocpullup(mp, sizeof (uint32_t));
			if (iocp->ioc_error != 0)
				break;
			ui = *(uint32_t *)mp->b_cont->b_rptr;
		}
		iocp->ioc_error = scsb_fake_intr(scsb, ui);
		break;
	}

	case SCSBIOC_GET_STATUS :
		if (!(scsb->scsb_state & SCSB_DEBUG_MODE)) {
			iocp->ioc_error = EINVAL;
			break;
		}
		iocp->ioc_error = miocpullup(mp, sizeof (scsb_status_t));
		if (iocp->ioc_error == 0)
			iocp->ioc_error = scsb_get_status(scsb,
			    (scsb_status_t *)mp->b_cont->b_rptr);
		break;

	case SCSBIOC_ALL_LEDS_ON :
		if (!(scsb->scsb_state & (SCSB_DIAGS_MODE | SCSB_DEBUG_MODE)))
			iocp->ioc_error = EACCES;
		else
			iocp->ioc_error = scsb_leds_switch(scsb, ON);
		break;

	case SCSBIOC_ALL_LEDS_OFF :
		if (!(scsb->scsb_state & (SCSB_DIAGS_MODE | SCSB_DEBUG_MODE)))
			iocp->ioc_error = EACCES;
		else
			iocp->ioc_error = scsb_leds_switch(scsb, OFF);
		break;

	case SCSBIOC_REG_READ:
	case SCSBIOC_REG_WRITE:
		if (!(scsb->scsb_state & (SCSB_DIAGS_MODE | SCSB_DEBUG_MODE))) {
			iocp->ioc_error = EACCES;
		} else {
			scsb_ioc_rdwr_t	*iocrdwrp;

			if (scsb->scsb_state & SCSB_FROZEN &&
			    !(scsb->scsb_state & SCSB_DEBUG_MODE)) {
				iocp->ioc_error = EAGAIN;
				break;
			}

			iocp->ioc_error = miocpullup(mp, sizeof (*iocrdwrp));
			if (iocp->ioc_error == 0) {
				iocrdwrp =
				    (scsb_ioc_rdwr_t *)mp->b_cont->b_rptr;

				if (iocp->ioc_cmd == SCSBIOC_REG_READ) {
					if (iocrdwrp->ioc_rlen > 0) {
						sm_ioc_rdwr(q, mp, I2C_WR_RD);
						return;
					}
				} else {
					if (iocrdwrp->ioc_wlen > 0) {
						sm_ioc_rdwr(q, mp, I2C_WR);
						return;
					}
				}
				iocp->ioc_error = EINVAL;
				break;
			}
		}
		break;

	case SCSBIOC_SHUTDOWN_POLL:
	case SCSBIOC_INTEVENT_POLL:
		if (!(scsb->scsb_state & SCSB_DEBUG_MODE)) {
			iocp->ioc_error = EINVAL;
			break;
		}
		iocp->ioc_error = miocpullup(mp, sizeof (uint32_t));
		if (iocp->ioc_error == 0)
			iocp->ioc_error = scsb_polled_int(scsb, iocp->ioc_cmd,
			    (uint32_t *)mp->b_cont->b_rptr);
		break;

	case SCSBIOC_RESTORE :
		if (!(scsb->scsb_state & (SCSB_DIAGS_MODE | SCSB_DEBUG_MODE)))
			iocp->ioc_error = EACCES;
		else {
			scsb_restore(scsb);
			(void) scsb_toggle_psmint(scsb, 1);
			iocp->ioc_error = 0;
		}
		break;

	case SCSBIOC_FREEZE :
		if (!(scsb->scsb_state & (SCSB_DIAGS_MODE | SCSB_DEBUG_MODE)))
			iocp->ioc_error = EACCES;
		else {
			scsb_freeze_check(scsb);
			scsb_freeze(scsb);
			iocp->ioc_error = 0;
		}
		break;

	/*
	 * envmond:alarmcard.so response to SCTRL_EVENT_ALARM_INSERTION
	 */
	case ENVC_IOC_ACCONF_RESTORED:
		(void) scsb_hsc_ac_op(scsb, scsb->ac_slotnum,
		    SCSB_HSC_AC_SET_BUSY);
		break;

	/*
	 * envmond:alarmcard.so response to SCTRL_EVENT_ALARM_REMOVAL
	 */
	case ENVC_IOC_ACCONF_STORED:
		if (scsb->scsb_state & SCSB_FROZEN) {
			iocp->ioc_error = EAGAIN;
			break;
		}
		(void) scsb_hsc_ac_op(scsb, scsb->ac_slotnum,
		    SCSB_HSC_AC_UNCONFIGURE);
		break;

#ifdef	DEBUG
	case SCSBIOC_TOPOLOGY_DUMP:
		if (!(scsb->scsb_state & SCSB_DEBUG_MODE))
			iocp->ioc_error = EINVAL;
		else {
			mct_topology_dump(scsb, 1);
			iocp->ioc_error = 0;
		}
		break;
#endif
	}
	if (iocp->ioc_error)
		mp->b_datap->db_type = M_IOCNAK;
	else
		mp->b_datap->db_type = M_IOCACK;
	qreply(q, mp);
}

static fru_info_t *
find_fru_info(fru_id_t fru_id)
{
	int		i;
	fru_info_t	*fru_ptr;

	if (scsb_debug & 0x00100001)
		cmn_err(CE_NOTE, "find_fru_info(0x%x)", fru_id);
	if (fru_id == (fru_id_t)0)
		return ((fru_info_t *)NULL);
	for (i = 0; i < SCSB_UNIT_TYPES; ++i) {
		fru_ptr = mct_system_info.fru_info_list[i];
		while (fru_ptr != NULL) {
			if (fru_ptr->fru_id == fru_id)
				return (fru_ptr);
			fru_ptr = fru_ptr->next;
		}
	}
	return ((fru_info_t *)NULL);
}


struct scsb_cb_entry {
	void			*cb_softstate_ptr;
	fru_id_t		cb_fru_id;
	scsb_fru_event_t	cb_event;
	void			(*cb_func)
				(void *, scsb_fru_event_t, scsb_fru_status_t);
	fru_info_t		*cb_fru_ptr;
	struct scsb_cb_entry	*cb_next;
};

#ifdef DEBUG
int	scsb_cb_count = 0;
#else
static
#endif
struct scsb_cb_entry	*scsb_cb_table;

/*
 * global function for interested FRU drivers to register a callback function,
 * to be called when FRU presence status changes.
 */
scsb_fru_status_t
scsb_fru_register(void (*cb_func)(void *, scsb_fru_event_t, scsb_fru_status_t),
			void *soft_ptr, fru_id_t fru_id)
{
	struct scsb_cb_entry	*cbe_ptr;

	if (scsb_debug & 0x00800001) {
		cmn_err(CE_NOTE,
		    "scsb_fru_register: FRU_ID 0x%x", (int)fru_id);
	}
	if (!(scsb_global_state & SCSB_UP)) {
		return (FRU_NOT_AVAILABLE);
	}
	if (cb_func == NULL || fru_id == (fru_id_t)0)
		return (FRU_NOT_AVAILABLE);
	if (scsb_cb_table == NULL)
		scsb_cb_table = (struct scsb_cb_entry *)
		    kmem_zalloc(sizeof (struct scsb_cb_entry), KM_SLEEP);
	cbe_ptr = scsb_cb_table;
	while (cbe_ptr->cb_softstate_ptr != NULL) {
		if (cbe_ptr->cb_next == (struct scsb_cb_entry *)NULL) {
			cbe_ptr->cb_next = (struct scsb_cb_entry *)
			    kmem_zalloc(sizeof (struct scsb_cb_entry),
			    KM_SLEEP);
			cbe_ptr = cbe_ptr->cb_next;
			break;
		}
		cbe_ptr = cbe_ptr->cb_next;
	}
	cbe_ptr->cb_softstate_ptr = soft_ptr;
	cbe_ptr->cb_fru_id = fru_id;
	cbe_ptr->cb_func = cb_func;
	cbe_ptr->cb_next = (struct scsb_cb_entry *)NULL;
	cbe_ptr->cb_fru_ptr = find_fru_info(fru_id);
#ifdef DEBUG
	scsb_cb_count++;
#endif
	if (scsb_debug & 0x00800000) {
		cmn_err(CE_NOTE,
		    "scsb_fru_register: FRU_ID 0x%x, status=%d",
		    (int)fru_id,
		    (cbe_ptr->cb_fru_ptr == (fru_info_t *)NULL) ?
		    0xff : cbe_ptr->cb_fru_ptr->fru_status);
	}
	if (cbe_ptr->cb_fru_ptr == (fru_info_t *)NULL)
		return (FRU_NOT_AVAILABLE);
	if (cbe_ptr->cb_fru_ptr->fru_status & FRU_PRESENT)
		return (FRU_PRESENT);
	return (FRU_NOT_PRESENT);
}

void
scsb_fru_unregister(void *soft_ptr, fru_id_t fru_id)
{
	struct scsb_cb_entry	*prev_ptr, *cbe_ptr;

	if (scsb_debug & 0x00800001) {
		cmn_err(CE_NOTE, "scsb_fru_unregister(0x%p, 0x%x)",
		    soft_ptr, (int)fru_id);
	}
	if ((cbe_ptr = scsb_cb_table) == NULL || fru_id == (fru_id_t)0)
		return;
	prev_ptr = cbe_ptr;
	do {
		if (cbe_ptr->cb_softstate_ptr == soft_ptr &&
		    cbe_ptr->cb_fru_id == fru_id) {
			if (cbe_ptr == scsb_cb_table)
				scsb_cb_table = cbe_ptr->cb_next;
			else
				prev_ptr->cb_next = cbe_ptr->cb_next;
			kmem_free(cbe_ptr, sizeof (struct scsb_cb_entry));
#ifdef DEBUG
			scsb_cb_count--;
#endif
			return;
		}
		prev_ptr = cbe_ptr;
	} while ((cbe_ptr = cbe_ptr->cb_next) != NULL);
}

/*
 * global function for interested FRU drivers to call to check
 * FRU presence status.
 */
scsb_fru_status_t
scsb_fru_status(uchar_t fru_id)
{
	fru_info_t		*fru_ptr;

	fru_ptr = find_fru_info(fru_id);
	if (scsb_debug & 0x00800001) {
		cmn_err(CE_NOTE, "scsb_fru_status(0x%x): status=0x%x",
		    fru_id, (fru_ptr == (fru_info_t *)NULL) ? 0xff :
		    (int)fru_ptr->fru_status);
	}
	if (fru_ptr == (fru_info_t *)NULL)
		return (FRU_NOT_AVAILABLE);
	return (fru_ptr->fru_status);
}

/*
 * Global function for the other interruptible FRU device sharing the
 * same interrupt line to register the interrupt handler with scsb.
 * This enables all the handlers to be called whenever the interrupt
 * line is asserted by anyone shaing the interrupt line.
 */

/*
 * The interrupt handler table is currently a linked list. probably a
 * hash table will be more efficient. Usage of these facilities can
 * happen even before scsb is attached, so do not depend on scsb
 * structure being present.
 */
struct fru_intr_entry {
	void	*softstate_ptr;
	int	(*fru_intr_handler)(void *);
	fru_id_t	fru_id;
	struct fru_intr_entry	*fru_intr_next;
} *fru_intr_table = NULL;

int
scsb_intr_register(int (*intr_handler)(void *), void * soft_ptr,
		fru_id_t fru_id)
{
	struct fru_intr_entry *intr_table_entry;
	intr_table_entry = (struct fru_intr_entry *)
	    kmem_zalloc(sizeof (struct fru_intr_entry), KM_SLEEP);

	if (intr_table_entry == NULL) {
		return (DDI_FAILURE);
	}

	if (intr_handler == NULL || soft_ptr == NULL || fru_id == 0) {
		kmem_free(intr_table_entry, sizeof (struct fru_intr_entry));
		return (DDI_FAILURE);
	}

	intr_table_entry->softstate_ptr = soft_ptr;
	intr_table_entry->fru_intr_handler = intr_handler;
	intr_table_entry->fru_id = fru_id;
	intr_table_entry->fru_intr_next = fru_intr_table;
	fru_intr_table = intr_table_entry;

	return (DDI_SUCCESS);
}

/*
 * Removed interrupt_handler of fru from interrupt call chain
 */
void
scsb_intr_unregister(fru_id_t fru_id)
{
	struct fru_intr_entry *intr_entry = fru_intr_table,
	    *prev_entry = intr_entry;

	if (fru_id == 0) {
		return;
	}

	do {
		if (intr_entry->fru_id == fru_id) {
			/* found a match, remove entry */
			if (intr_entry == fru_intr_table)
				fru_intr_table = intr_entry->fru_intr_next;
			else
				prev_entry->fru_intr_next =
				    intr_entry->fru_intr_next;

			kmem_free(intr_entry,
			    sizeof (struct fru_intr_entry));
			return;
		}
		prev_entry = intr_entry;

	} while ((intr_entry = intr_entry->fru_intr_next) != NULL);
}

/*
 * Invoke all the registered interrupt handlers, whenever scsb_intr
 * is called. This function will go through the list of entries
 * in the fru interrupt table and invoke each function. Returns
 * whether interrupt is claimed or unclaimed.
 */
static int
scsb_invoke_intr_chain()
{
	int retval = DDI_INTR_UNCLAIMED;
	struct fru_intr_entry *intr_entry = fru_intr_table;

	while (intr_entry != NULL) {
		retval = (*intr_entry->
		    fru_intr_handler)(intr_entry->softstate_ptr);
		if (retval == DDI_INTR_CLAIMED) {
			return (retval);
		}

		intr_entry = intr_entry->fru_intr_next;
	}

	return (retval);
}


/*
 * The scsb_ioc_rdwr_t is similar enough to an i2c_transfer_t that we can
 * translate the structures and use the i2c_transfer() service.
 */
static void
sm_ioc_rdwr(queue_t *q, mblk_t *mp, int op)
{
	scsb_state_t	*scsb = (scsb_state_t *)q->q_ptr;
	struct iocblk	*iocp = (struct iocblk *)mp->b_rptr;
	scsb_ioc_rdwr_t	*iocrdwrp;
	int		len, error;
	uchar_t		*uc, reg;

	if (scsb_debug & 0x0040)
		cmn_err(CE_CONT, "sm_ioc_rdwr[%d]:", scsb->scsb_instance);
	iocrdwrp  = (scsb_ioc_rdwr_t *)mp->b_cont->b_rptr;
	if (op == I2C_WR) {
		len = iocrdwrp->ioc_wlen;
		uc = iocrdwrp->ioc_wbuf;
	} else {
		len = iocrdwrp->ioc_rlen;
		uc = iocrdwrp->ioc_rbuf;
	}
	/*
	 * Check SCB register index boundries and requested len of read/write
	 */
	reg = iocrdwrp->ioc_regindex;
	if (reg < SCSB_REG_ADDR_START || (reg + len) >
	    (SCSB_REG_ADDR_START + SCTRL_TOTAL_NUMREGS))
		error = EINVAL;
	else
		error = scsb_rdwr_register(scsb, op, reg, len, uc, 1);
	if (error) {
		if (scsb_debug & 0x0042)
			cmn_err(CE_WARN,
			    "sm_ioc_rdwr: rdwr_register failure: %d", error);
		mp->b_datap->db_type = M_IOCNAK;
	} else
		mp->b_datap->db_type = M_IOCACK;
	iocp->ioc_error = error;
	qreply(q, mp);
}

/*
 * names for (scsb_utype_t) FRU types
 */
static char *led_name[SCSB_LED_TYPES] = { "NOK", "OK" };
static char *unit_type_name[SCSB_UNIT_TYPES] = {
	"SLOT", "PDU", "POWER SUPPLY", "DISK", "FAN", "ALARM",
	"SCB",  "SSB", "CFTM", "CRTM", "PRTM"
};

/*
 * Discover the register and bit-offset for LEDs and Reset registers,
 * according to unit_type, unit_number, and led_type.
 */
static int
scsb_get_led_regnum(scsb_state_t	*scsb,
		    scsb_uinfo_t	*suip,
		    uchar_t		*regptr,
		    int			*unitptr,
		    scsb_led_t		led_type)
{
	int		code, base, error;

	/* OK here means presence (OK) LEDs */
	if (led_type == OK)
		base = (SCTRL_LED_OK_BASE);
	else
		base = (SCTRL_LED_NOK_BASE);
	error = 0;
	if (scsb_debug & 0x0100) {
		cmn_err(CE_NOTE, "get_led_regnum: suip <%x, %x, %x, %x>\n",
		    suip->unit_type, suip->unit_number,
		    led_type, suip->unit_state);
	}
	/*
	 * It was requested that the scsb driver allow accesses to SCB device
	 * registers for FRUs that cannot be present.
	 * So except for SLOTs, if the unit_number check fails, we now
	 * just log a message, but ONLY if scsb_debug error messages are
	 * enabled.
	 */
	switch (suip->unit_type) {
	case SLOT:
		if (suip->unit_number < 1 || suip->unit_number >
		    ((scsb->scsb_state & SCSB_IS_TONGA) ?
		    TG_MAX_SLOTS : MC_MAX_SLOTS)) {
			error = EINVAL;
			break;
		}
		code = FRU_UNIT_TO_EVCODE(SLOT, suip->unit_number);
		break;

	case PDU:
		if (suip->unit_number < 1 || suip->unit_number >
		    ((scsb->scsb_state & SCSB_IS_TONGA) ?
		    TG_MAX_PDU : MC_MAX_PDU)) {
			if (scsb_debug & 0x0002) {
				cmn_err(CE_WARN,
				    "get_led_regnum: unit number %d "
				    "is out of range", suip->unit_number);
			}
			error = EINVAL;
			break;
		}
		code = FRU_UNIT_TO_EVCODE(PDU, suip->unit_number);
		break;

	case PS:
		if ((suip->unit_number < 1 || suip->unit_number >
		    ((scsb->scsb_state & SCSB_IS_TONGA) ?
		    TG_MAX_PS : MC_MAX_PS))) {
			if (scsb_debug & 0x0002) {
				cmn_err(CE_WARN,
				    "get_led_regnum: unit number %d "
				    "is out of range", suip->unit_number);
			}
			error = EINVAL;
			break;
		}
		code = FRU_UNIT_TO_EVCODE(PS, suip->unit_number);
		break;

	case DISK:
		if ((suip->unit_number < 1 || suip->unit_number >
		    ((scsb->scsb_state & SCSB_IS_TONGA) ?
		    TG_MAX_DISK : MC_MAX_DISK))) {
			if (scsb_debug & 0x0002) {
				cmn_err(CE_WARN,
				    "get_led_regnum: unit number %d "
				    "is out of range", suip->unit_number);
			}
			if (!(scsb_debug & 0x20000000)) {
				error = EINVAL;
				break;
			}
		}
		code = FRU_UNIT_TO_EVCODE(DISK, suip->unit_number);
		break;

	case FAN:
		if (suip->unit_number < 1 || suip->unit_number >
		    ((scsb->scsb_state & SCSB_IS_TONGA) ?
		    TG_MAX_FAN : MC_MAX_FAN)) {
			if (scsb_debug & 0x0002) {
				cmn_err(CE_WARN,
				    "get_led_regnum: unit number %d "
				    "is out of range", suip->unit_number);
			}
			error = EINVAL;
			break;
		}
		code = FRU_UNIT_TO_EVCODE(FAN, suip->unit_number);
		break;

	case CFTM:
		if (suip->unit_number < 1 || suip->unit_number >
		    ((scsb->scsb_state & SCSB_IS_TONGA) ?
		    TG_MAX_CFTM : MC_MAX_CFTM)) {
			if (scsb_debug & 0x0002) {
				cmn_err(CE_WARN,
				    "get_led_regnum: unit number %d "
				    "is out of range", suip->unit_number);
			}
			error = EINVAL;
			break;
		}
		code = FRU_UNIT_TO_EVCODE(CFTM, suip->unit_number);
		break;

	case SCB:
		if (suip->unit_number < 1 || suip->unit_number >
		    ((scsb->scsb_state & SCSB_IS_TONGA) ?
		    TG_MAX_SCB : MC_MAX_SCB)) {
			if (scsb_debug & 0x0002) {
				cmn_err(CE_WARN,
				    "get_led_regnum: unit number %d "
				    "is out of range", suip->unit_number);
			}
			error = EINVAL;
			break;
		}
		code = FRU_UNIT_TO_EVCODE(SCB, suip->unit_number);
		break;

	case ALARM:
		error = EINVAL;
		break;

	default:
		if (scsb_debug & 0x0102) {
			cmn_err(CE_WARN,
			    "scsb_get_led_regnum(): unknown unit type %d",
			    suip->unit_type);
		}
		error = EINVAL;
		break;
	}
	if (!error) {
		*unitptr = FRU_OFFSET(code, base);
		*regptr = FRU_REG_ADDR(code, base);
		if (scsb_debug & 0x0100) {
			cmn_err(CE_NOTE, "get_led_regnum: unitptr=%x, "
			    "regptr=%x, code = %x\n",
			    *unitptr, *regptr, code);
		}
	}
	return (error);
}

/*
 * P1.0 and P1.5
 * Map 1.0 Tonga Slot Numbers: SCB to user interface and back.
 * User interface means positional slot numbers, as on P1.0 SSB,
 * which are used by hpcsvc/hsc and kstat/ioctl interfaces.
 */

/* HSC slotnum (Positional SLotnum) to SCB CFG bit-offset */
static	int	psl2sco[TG_MAX_SLOTS + 1] = { -1 };

/*
 * MAP Positional (HSC) slot number to SCB CFG register bit-offset
 */
static int
tonga_pslotnum_to_cfgbit(scsb_state_t *scsb, int sln)
{
	int	base = SCTRL_SYSCFG_BASE;
	if (!(scsb->scsb_state & SCSB_IS_TONGA)) {
		return (sln);
	}
	if (sln < 1 || sln > TG_MAX_SLOTS) {
		return (sln);
	}
	/*
	 * Should move this to _init(), but for now,
	 * check for initialized table
	 */
	if (psl2sco[0]) {
		psl2sco[0] = 0;
		psl2sco[1] = FRU_OFFSET(SCTRL_EVENT_SLOT5, base);
		psl2sco[2] = FRU_OFFSET(SCTRL_EVENT_SLOT2, base);
		psl2sco[3] = FRU_OFFSET(SCTRL_EVENT_SLOT1, base);
		psl2sco[4] = FRU_OFFSET(SCTRL_EVENT_SLOT3, base);
		psl2sco[5] = FRU_OFFSET(SCTRL_EVENT_SLOT4, base);
	}
#ifdef DEBUG
	if (scsb_debug & 0x10000000) {
		cmn_err(CE_NOTE, "tonga_pslotnum_to_cfgbit: old/new: %d/%d",
		    sln, psl2sco[sln]);
	}
#endif
	return (psl2sco[sln]);
}

/* positional slotnum to SCB slotnum */
static	int	psl2ssl[6] = {
	0, 5, 2, 1, 3, 4
};

/* SCB slotnum to positional slotnum */
static	int	ssl2psl[6] = {
	0, 3, 2, 4, 5, 1
};

/*
 * P1.0 and P1.5
 * HSC Slot numbers (physical positions or positional slotnum)
 *  to
 * SCB slot numbers (reset,present,healthy)
 *
 * These requests come mainly from application interface and
 * HSC using the scsb_uinfo_t structure.
 */
static void
tonga_slotnum_check(scsb_state_t *scsb, scsb_uinfo_t *suip)
{
	if (!(scsb->scsb_state & SCSB_IS_TONGA && scsb->scsb_state &
	    (SCSB_P10_PROM | SCSB_P15_PROM | SCSB_P20_PROM))) {
		return;
	}
	if (suip->unit_number < 1 || suip->unit_number > TG_MAX_SLOTS) {
		return;
	}
#ifdef DEBUG
	if (scsb_debug & 0x10000000) {
		cmn_err(CE_NOTE, "tonga_slotnum_check: old/new: %d/%d",
		    suip->unit_number, psl2ssl[suip->unit_number]);
	}
#endif
	suip->unit_number = psl2ssl[suip->unit_number];
}

/*
 * P1.0 and P1.5
 */
static int
tonga_psl_to_ssl(scsb_state_t *scsb, int slotnum)
{
	if (!(scsb->scsb_state & SCSB_IS_TONGA && scsb->scsb_state &
	    (SCSB_P10_PROM | SCSB_P15_PROM | SCSB_P20_PROM))) {
		return (slotnum);
	}
	if (slotnum < 1 || slotnum > TG_MAX_SLOTS) {
		return (slotnum);
	}
#ifdef DEBUG
	if (scsb_debug & 0x10000000) {
		cmn_err(CE_NOTE, "tonga_psl_to_ssl: old/new: %d/%d",
		    slotnum, psl2ssl[slotnum]);
	}
#endif
	return (psl2ssl[slotnum]);
}

/*
 * P1.0 and P1.5
 */
static int
tonga_ssl_to_psl(scsb_state_t *scsb, int slotnum)
{
	if (!(scsb->scsb_state & SCSB_IS_TONGA && scsb->scsb_state &
	    (SCSB_P10_PROM | SCSB_P15_PROM | SCSB_P20_PROM))) {
		return (slotnum);
	}
	if (slotnum < 1 || slotnum > TG_MAX_SLOTS) {
		return (slotnum);
	}
#ifdef DEBUG
	if (scsb_debug & 0x10000000) {
		cmn_err(CE_NOTE, "tonga_ssl_to_psl: old/new: %d/%d",
		    slotnum, ssl2psl[slotnum]);
	}
#endif
	return (ssl2psl[slotnum]);
}
/*
 * tonga_slotnum_led_shift: this function remaps slot bits ONLY for Slots 1-5
 * and ONLY for the register sets in bit-offset groups 1,2:
 * LEDs, Confg/Status, Reset, BrdHlthy
 *
 * IN  bits: SCB slot numbers (led,reset,present,healthy)
 *  to
 * OUT bits: HSC Slot numbers (positional slot numbers as marked on the SSB)
 */
static uchar_t
tonga_slotnum_led_shift(scsb_state_t *scsb, uchar_t data)
{
	int	i;
	uchar_t mask, new_data = 0;
#ifdef DEBUG
	uchar_t	old_data = data;
#endif
	if (!(scsb->scsb_state & SCSB_IS_TONGA)) {
		return (data);
	}
	/*
	 * P1.0 and P1.5 slot 1-5 offsets are the same
	 */
	for (i = 1; i <= TG_MAX_SLOTS; ++i) {
		mask = 1 << (i - 1);
		switch (i) {
		case 1:		/* map to slot 3 */
			new_data |= (data & mask) << 2;
			data &= ~(mask);
			break;
		case 2:		/* map to slot 2 */
			new_data |= (data & mask);
			data &= ~(mask);
			break;
		case 3:		/* map to slot 4 */
		case 4:		/* map to slot 5 */
			new_data |= (data & mask) << 1;
			data &= ~(mask);
			break;
		case 5:		/* map to slot 1 */
			new_data |= (data & mask) >> 4;
			data &= ~(mask);
			break;
		}
	}
	new_data |= data;	/* set any remaining bits */
#ifdef DEBUG
	if (scsb_debug & 0x10000000) {
		cmn_err(CE_NOTE, "tonga_slotnum_led_shift: old/new: 0x%x/0x%x",
		    old_data, new_data);
	}
#endif
	return (new_data);
}

/*
 * P1.0 and P1.5
 */
int
scsb_led_get(scsb_state_t *scsb, scsb_uinfo_t *suip, scsb_led_t led_type)
{
	int		error;
	int		unit_number;
	uchar_t		reg;
	int		index;

	/*
	 * Allow access to shadow registers even though SCB is removed
	 *
	 * if (scsb->scsb_state & SCSB_FROZEN) {
	 *	return (EAGAIN);
	 * }
	 */
	if (suip == NULL) {
		return (EFAULT);
	}
	if (led_type == NOUSE) {
		led_type = suip->led_type;
	}
	if (led_type != OK && led_type != NOK) {
		cmn_err(CE_NOTE, "scsb_led_get(%d): unknown led type %x",
		    scsb->scsb_instance, led_type);
		return (EINVAL);
	}
	error = 0;
	if (scsb_debug & 0x0100) {
		cmn_err(CE_NOTE, "scsb_led_get: %s %s %d",
		    led_name[led_type], unit_type_name[suip->unit_type],
		    suip->unit_number);
	}
	/*
	 * Map to Tonga Slot Number, if NOT P1.0 SCB
	 * P1.0 SSB workaround
	 */
	if (suip->unit_type == SLOT && !(scsb->scsb_state & SCSB_P10_PROM)) {
		tonga_slotnum_check(scsb, suip);
	}
	/* discover the register and index we need to operate on */
	if ((error = scsb_get_led_regnum(scsb, suip, &reg, &unit_number,
	    led_type)) == 0) {
		index = SCSB_REG_INDEX(reg);
		mutex_enter(&scsb->scsb_mutex);
		if (scsb->scsb_data_reg[index] & (1 << unit_number)) {
			suip->unit_state = ON;
			if (led_type == OK) {
				int code = FRU_UNIT_TO_EVCODE(suip->unit_type,
				    suip->unit_number);
				reg = FRU_REG_ADDR(code, SCTRL_BLINK_OK_BASE);
				index = SCSB_REG_INDEX(reg);
				if (scsb->scsb_data_reg[index] &
				    (1 << unit_number))
					suip->unit_state = BLINK;
			}
		} else {
			suip->unit_state = OFF;
		}
		mutex_exit(&scsb->scsb_mutex);
	}
	return (error);
}

int
scsb_led_set(scsb_state_t *scsb, scsb_uinfo_t *suip, scsb_led_t led_type)
{
	int		error;
	int		unit_number;
	uchar_t		reg;
	int		code, index;

	/* we should really allow led state changes while frozen... */
	if (scsb->scsb_state & SCSB_FROZEN)
		return (EAGAIN);

	if (suip == NULL) {
		return (EFAULT);
	}

	/*
	 * Sanity check, make sure we got plausible values for set command.
	 * Also check for application only control of slot leds using NOUSE
	 * interface
	 */
	if (led_type == NOUSE) {
		led_type = suip->led_type;
	} else if (suip->unit_type == SLOT &&
	    scsb->scsb_state & SCSB_APP_SLOTLED_CTRL &&
	    !(scsb->scsb_state &
	    (SCSB_DIAGS_MODE | SCSB_DEBUG_MODE))) {
		/*
		 * kernel modules using this interface need to think they are
		 * succeeding, so we won't return an error for this
		 * application configuration
		 */
		return (0);
	}
	if (led_type != OK && led_type != NOK) {
		return (EINVAL);
	}
	if (suip->unit_state != OFF && suip->unit_state != ON &&
	    suip->unit_state != BLINK) {
		return (EINVAL);
	}
	if (suip->unit_state == BLINK) {
		if (led_type != OK)
			return (EINVAL);
		if (suip->unit_type != SLOT && scsb->scsb_state &
		    (SCSB_P06_PROM | SCSB_P10_PROM))
			return (EINVAL);
	}
	if (scsb_debug & 0x0100) {
		cmn_err(CE_NOTE,
		    "scsb_led_set: led %s, type %s, unit %d, state %s",
		    led_name[led_type],
		    unit_type_name[suip->unit_type], suip->unit_number,
		    suip->unit_state == ON ? "ON":
		    suip->unit_state == OFF ? "OFF": "BLINK");
	}
	/*
	 * Map to Tonga Slot Number, if NOT P1.0 SCB
	 * P1.0 SSB workaround
	 */
	if (suip->unit_type == SLOT && !(scsb->scsb_state & SCSB_P10_PROM)) {
		tonga_slotnum_check(scsb, suip);
	}
	/*
	 * discover the register and index we need to access
	 */
	if ((error = scsb_get_led_regnum(scsb, suip, &reg, &unit_number,
	    led_type)) == 0) {
		index = SCSB_REG_INDEX(reg);
		mutex_enter(&scsb->scsb_mutex);
		if (suip->unit_state == ON || suip->unit_state == BLINK)
			scsb->scsb_data_reg[index] |=  (1 << unit_number);
		else
			scsb->scsb_data_reg[index] &= ~(1 << unit_number);

		if (scsb_debug & 0x0100) {
			cmn_err(CE_NOTE, "Writing %x to Reg %x",
			    scsb->scsb_data_reg[index], reg);
		}
		error = scsb_rdwr_register(scsb, I2C_WR, reg, 1,
		    &scsb->scsb_data_reg[index], 1);
		if (error) {
			cmn_err(CE_WARN, "%s#%d: Could not Update %s LEDs.",
			    ddi_driver_name(scsb->scsb_dev),
			    ddi_get_instance(scsb->scsb_dev),
			    led_name[led_type]);
			goto ledset_done;
		}
		if (led_type != OK ||
		    (IS_SCB_P10 && suip->unit_type != SLOT) ||
		    suip->unit_type == ALARM ||
		    suip->unit_type == SSB ||
		    suip->unit_type == CRTM ||
		    suip->unit_type == PRTM) {
			goto ledset_done;
		}
		code = FRU_UNIT_TO_EVCODE(suip->unit_type, suip->unit_number);
		reg = FRU_REG_ADDR(code, SCTRL_BLINK_OK_BASE);
		index = SCSB_REG_INDEX(reg);
		if (suip->unit_state == BLINK)
			scsb->scsb_data_reg[index] |=  (1 << unit_number);
		else
			scsb->scsb_data_reg[index] &= ~(1 << unit_number);
		if (scsb_debug & 0x0100) {
			cmn_err(CE_NOTE, "Writing %x to Reg %x",
			    scsb->scsb_data_reg[index], reg);
		}
		error = scsb_rdwr_register(scsb, I2C_WR, reg, 1,
		    &scsb->scsb_data_reg[index], 1);
		if (error) {
			cmn_err(CE_WARN, "%s#%d: Could not Blink %s LEDs.",
			    ddi_driver_name(scsb->scsb_dev),
			    ddi_get_instance(scsb->scsb_dev),
			    led_name[led_type]);
		}
ledset_done:
		mutex_exit(&scsb->scsb_mutex);
	}
	return (error);
}

struct ps_auto_on {
	scsb_state_t	*scsb;
	scsb_utype_t	utype;
	scsb_unum_t	unit;
};

static struct ps_auto_on pao;

static void
scsb_ps_auto_on(void *arg)
{
	struct ps_auto_on 	*ppao = (struct ps_auto_on *)arg;
	uchar_t			rmask = 0;
	uchar_t			ondata, sysreg;
	int			tmp, bit_index;
	/*
	 * Turn on the PSU.
	 * Notice: not checking Power Supply unit number
	 */
	bit_index = SCTRL_SYS_PS_ON_BASE + (ppao->unit - 1);
	ondata = 1 << SYS_OFFSET(bit_index);
	tmp = SYS_REG_INDEX(bit_index, SCTRL_SYS_CMD_BASE);
	sysreg = SCSB_REG_ADDR(tmp);
	if (scsb_write_mask(ppao->scsb, sysreg, rmask, ondata, (uchar_t)0)) {
		cmn_err(CE_WARN, "scsb%d: " "I2C TRANSFER Failed",
		    ppao->scsb->scsb_instance);
	}
	ppao->scsb->scsb_btid = 0;
}

/*
 * called with mutex held from
 * scsb_attach()	with int_fru_ptr == NULL
 * scsb_intr()		with int_fru_ptr == info for FRU that caused interrupt
 */
static int
scsb_set_scfg_pres_leds(scsb_state_t *scsb, fru_info_t *int_fru_ptr)
{
	int		i, error = 0;
	int		cfg_idx, led_idx, blink_idx, lid, bid;
	int		cfg_bit, led_bit;
	uchar_t		*puc, reg, led_reg, led_data[SCSB_LEDDATA_REGISTERS];
	uchar_t		blink_bit, blink_reg, blink[SCSB_LEDDATA_REGISTERS];
	uchar_t		update_reg = 0;
	scsb_utype_t	fru_type;
	fru_info_t	*fru_ptr;

	if (scsb->scsb_state & SCSB_FROZEN &&
	    !(scsb->scsb_state & SCSB_IN_INTR)) {
		return (EAGAIN);
	}
	for (i = 0; i < SCTRL_LED_OK_NUMREGS; ++i) {
		led_data[i] = 0;
		blink[i] = 0;
	}
	led_reg = SCSB_REG_ADDR(SCTRL_LED_OK_BASE);
	reg = SCSB_REG_ADDR(SCTRL_BLINK_OK_BASE);
	lid = SCSB_REG_INDEX(led_reg);		/* the LED Index Delta */
	bid = SCSB_REG_INDEX(reg);		/* the Blink Index Delta */
	blink_reg = 0;
	if (int_fru_ptr != NULL) {
		update_reg = int_fru_ptr->i2c_info->ledata_reg;
	}
	for (fru_type = 0; fru_type < SCSB_UNIT_TYPES; ++fru_type) {
		int	is_present;
		fru_ptr = mct_system_info.fru_info_list[fru_type];
		for (; fru_ptr != NULL; fru_ptr = fru_ptr->next) {
			is_present = 0;
			if (fru_type == SLOT && (scsb->scsb_state &
			    SCSB_APP_SLOTLED_CTRL))
				break;
			if (fru_ptr->i2c_info == NULL)
				continue;
			if ((led_reg = fru_ptr->i2c_info->ledata_reg) == 0) {
				/*
				 * No LED exceptions: SSB,CRTM,PRTM
				 */
				continue;
			}
			if (update_reg && update_reg != led_reg)
				continue;
			led_idx = SCSB_REG_INDEX(led_reg) - lid;
			led_bit = fru_ptr->i2c_info->ledata_bit;
			if ((reg = fru_ptr->i2c_info->syscfg_reg) == 0) {
				if (fru_type != SCB)
					continue;
				/*
				 * exception: SCB
				 */
				if (scsb->scsb_state & SCSB_SCB_PRESENT) {
					led_data[led_idx] |= 1 << led_bit;
					is_present = 1;
				} else {
					led_data[led_idx] &= ~(1 << led_bit);
				}
				if (IS_SCB_P10)
					continue;
			} else {
				cfg_idx = SCSB_REG_INDEX(reg);
				cfg_bit = fru_ptr->i2c_info->syscfg_bit;
				if (scsb->scsb_data_reg[cfg_idx] &
				    (1 << cfg_bit)) {
					is_present = 1;
				}
			}
			if (is_present) {
				/*
				 * If the FRU is a Power Supply, AND
				 * the call is from scsb_attach() OR
				 * from scsb_intr() and FRUs match,
				 * turn it on.
				 */
				if (fru_type == PS && (int_fru_ptr == NULL ||
				    (int_fru_ptr == fru_ptr))) {
					pao.scsb = scsb;
					pao.utype = fru_type;
					pao.unit = fru_ptr->fru_unit;
#ifdef	PS_ON_DELAY
					/*
					 * HW recommended not implementing
					 * this delay for now.
					 * The code is tested on PSUs:
					 *	-06
					 *	-07 rev 2
					 *	-08 plus
					 */
					if (int_fru_ptr) {
						/*
						 * Hot insertion, so give it
						 * the 3 seconds it needs to
						 * become stable
						 */
						if (!scsb->scsb_btid)
							scsb->scsb_btid =
							    timeout(
							    scsb_ps_auto_on,
							    &pao, (4 *
							    drv_usectohz(
							    1000000)));
					} else
#endif	/* PS_ON_DELAY */
						scsb_ps_auto_on((void *)&pao);
				}
				/*
				 * Special SLOT handling.
				 * Make sure the OK LED is on for the CPU Slot
				 * and for the FTC (CFTM) Slot for MonteCarlo.
				 * Both will report as FRU_PRESENT.
				 */
				if (fru_type != SLOT || (fru_type == SLOT &&
				    (fru_ptr->fru_type ==
				    (scsb_utype_t)OC_CPU ||
				    fru_ptr->fru_type ==
				    (scsb_utype_t)OC_CTC))) {
					/*
					 * Set OK (green) LED register bit
					 */
					led_data[led_idx] |= 1 << led_bit;
				}
				if (IS_SCB_P10)
					continue;
				/*
				 * Turn off BLINK register bit.
				 * If single register update, then save the
				 * corresponding blink register in blink_reg.
				 */
				reg = fru_ptr->i2c_info->blink_reg;
				if (!reg)
					continue;
				blink_bit = fru_ptr->i2c_info->blink_bit;
				blink_idx = SCSB_REG_INDEX(reg) - bid;
				blink[blink_idx] |= 1 << blink_bit;
				if (update_reg && update_reg == led_reg)
					blink_reg = reg;
			}
		}
	}
	if (update_reg) {
		reg = update_reg;
		i = SCSB_REG_INDEX(reg);
		puc = &led_data[i - lid];
		i = 1;
	} else {
		reg = SCSB_REG_ADDR(SCTRL_LED_OK_BASE);
		puc = led_data;
		i = SCTRL_LED_OK_NUMREGS;
	}
	if (scsb_debug & 0x0100) {
		cmn_err(CE_NOTE, "scsb_set_scfg_pres(): writing %d bytes "
		    "to 0x%x", i, reg);
	}
	if ((error = scsb_rdwr_register(scsb, I2C_WR, reg, i, puc, 1)) != 0) {
		if (scsb_debug & 0x0102)
			cmn_err(CE_NOTE, "scsb_set_scfg_pres(): "
			    "I2C write to 0x%x failed", reg);
		error = EIO;
	} else {
		/*
		 * Now see which BLINK bits need to be turned off for the
		 * corresponding OK LED bits.
		 */
		reg = SCSB_REG_ADDR(SCTRL_BLINK_OK_BASE);
		for (i = 0; i < SCTRL_BLINK_NUMREGS; ++i, ++reg) {
			if (blink_reg && blink_reg != reg)
				continue;
			if (!blink[i]) {
				continue;
			}
			if (scsb_debug & 0x0100) {
				cmn_err(CE_NOTE, "scsb_set_scfg_pres(): turn "
				    "OFF Blink bits 0x%x in 0x%x",
				    blink[i], reg);
			}
			if (scsb_write_mask(scsb, reg, 0, 0, blink[i])) {
				if (scsb_debug & 0x0102)
					cmn_err(CE_NOTE,
					    "scsb_set_scfg_pres(): "
					    "Write to 0x%x failed", reg);
				error = EIO;
				break;
			}
		}
	}
	return (error);
}

static int
scsb_check_config_status(scsb_state_t *scsb)
{
	int		error;
	uchar_t		reg;
	int		index, p06;

	if (scsb_debug & 0x0201) {
		cmn_err(CE_NOTE, "scsb_check_config_status:");
	}
	/*
	 * Base of register set
	 */
	reg = SCSB_REG_ADDR(SCTRL_SYSCFG_BASE);
	index = SCSB_REG_INDEX(reg);
	/*
	 * SCB P0.6 workaround: read registers twice, use 2nd value set
	 */
	mutex_enter(&scsb->scsb_mutex);
	p06 = 2;
	do {
		if (error = scsb_rdwr_register(scsb, I2C_WR_RD, reg,
		    SCTRL_CFG_NUMREGS, &scsb->scsb_data_reg[index], 1)) {
			break;
		}
		if (p06 == 1) {
			if (scsb_debug & 0x0200)
				cmn_err(CE_NOTE,
				"scsb_check_config_status: P0.6 workaround");
		}
		/*
		 * If not P0.6 PROM, just break here
		 */
		if (!(scsb->scsb_state & SCSB_P06_PROM))
			break;
	} while (--p06);
	mutex_exit(&scsb->scsb_mutex);

	if (error == 0) {
		if (!(scsb->scsb_state & SCSB_SCB_PRESENT))
			scsb->scsb_state |= SCSB_SCB_PRESENT;
		if (scsb_fru_op(scsb, SSB, 1, SCTRL_SYSCFG_BASE,
		    SCSB_FRU_OP_GET_BITVAL))
			scsb->scsb_state |= SCSB_SSB_PRESENT;
		else
			scsb->scsb_state &= ~SCSB_SSB_PRESENT;
	}
	return (error);
}

static void
scsb_set_topology(scsb_state_t *scsb)
{
	int		i, t, index, unit, is_tonga = 0;
	int		alarm_slot_num, cpu_slot_num, ctc_slot_num;
	fru_info_t	*fru_ptr, *last_ptr, *acslot_ptr, *ctcslot_ptr;
	uchar_t		syscfg, led_reg, blink_reg, t_uchar;
	uchar_t		bit_num, led_bit, blink_bit;
	int		pad = 0;

	/*
	 * Get the presence status from the SysConfigStatus shadow registers
	 * in scsb->scsb_data_reg[]
	 */
	/* Mid Plane */
	i = SYS_REG_INDEX(SCTRL_CFG_MPID0, SCTRL_SYSCFG_BASE);
	t_uchar = SCSB_REG_ADDR(i);
	index = SCSB_REG_INDEX(t_uchar);
	mct_system_info.mid_plane.fru_type = MIDPLANE;
	mct_system_info.mid_plane.fru_version = (fru_version_t)0;
	t = SYS_OFFSET(SCTRL_CFG_MPID0);
	mct_system_info.mid_plane.fru_id = (int)((scsb->scsb_data_reg[index] &
	    (SCTRL_MPID_MASK << t)) >> t);
	switch (mct_system_info.mid_plane.fru_id) {
	case SCTRL_MPID_HALF:		/* Monte Carlo		*/
		if (scsb_debug & 0x00100005)
			cmn_err(CE_NOTE, "scsb_set_topology: Monte Carlo");
		cpu_slot_num = SC_MC_CPU_SLOT;
		ctc_slot_num = SC_MC_CTC_SLOT;
		alarm_slot_num = scsb->ac_slotnum = SC_MC_AC_SLOT;
		mct_system_info.max_units[SLOT] = MC_MAX_SLOTS;
		mct_system_info.max_units[ALARM] = MC_MAX_AC;
		mct_system_info.max_units[DISK] = MC_MAX_DISK;
		mct_system_info.max_units[FAN] = MC_MAX_FAN;
		mct_system_info.max_units[PS] = MC_MAX_PS;
		mct_system_info.max_units[PDU] = MC_MAX_PDU;
		mct_system_info.max_units[SCB] = MC_MAX_SCB;
		mct_system_info.max_units[SSB] = MC_MAX_SCB;
		mct_system_info.max_units[CFTM] = MC_MAX_CFTM;
		mct_system_info.max_units[CRTM] = MC_MAX_CRTM;
		mct_system_info.max_units[PRTM] = MC_MAX_PRTM;
		break;
	case SCTRL_MPID_QUARTER_NODSK:	/* Tonga w/o disk	*/
	case SCTRL_MPID_QUARTER:	/* Tonga w/  disk	*/
		scsb->scsb_state |= SCSB_IS_TONGA;
		is_tonga = 1;
		ctc_slot_num = -1;
		ctcslot_ptr = NULL;
		if (scsb_debug & 0x00100005)
			cmn_err(CE_NOTE, "scsb_set_topology: Tonga%s",
			    mct_system_info.mid_plane.fru_id ==
			    SCTRL_MPID_QUARTER_NODSK ?
			    ", no disk" : " with disk");
		cpu_slot_num = SC_TG_CPU_SLOT;
		alarm_slot_num = scsb->ac_slotnum = SC_TG_AC_SLOT;
		mct_system_info.max_units[SLOT] = TG_MAX_SLOTS;
		mct_system_info.max_units[ALARM] = TG_MAX_AC;
		mct_system_info.max_units[DISK] = TG_MAX_DISK;
		mct_system_info.max_units[FAN] = TG_MAX_FAN;
		mct_system_info.max_units[PS] = TG_MAX_PS;
		mct_system_info.max_units[PDU] = TG_MAX_PDU;
		mct_system_info.max_units[SCB] = TG_MAX_SCB;
		mct_system_info.max_units[SSB] = TG_MAX_SCB;
		mct_system_info.max_units[CFTM] = TG_MAX_CFTM;
		mct_system_info.max_units[CRTM] = TG_MAX_CRTM;
		mct_system_info.max_units[PRTM] = TG_MAX_PRTM;
		break;
	default:
		cmn_err(CE_WARN, "%s#%d: Unknown MidPlane Id %x",
		    ddi_driver_name(scsb->scsb_dev),
		    ddi_get_instance(scsb->scsb_dev),
		    mct_system_info.mid_plane.fru_id);
		if (scsb_debug & 0x00100005)
			cmn_err(CE_NOTE, "scsb_set_topology: 0x%x: unknown!",
			    mct_system_info.mid_plane.fru_id);
		return;
	}
	/*
	 * cPCI Slots
	 *
	 * NOTE: The Tonga slot fru_unit needs to get mapped to the logical
	 * slot number in slot_table[].  The field is not in the slot_table
	 * at least until we know the format of the OBP slot table for the FCS
	 * release.
	 */
	mct_system_info.fru_info_list[SLOT] = (fru_info_t *)
	    kmem_zalloc(sizeof (fru_info_t) *
	    (mct_system_info.max_units[SLOT] + pad), KM_SLEEP);
	fru_ptr = mct_system_info.fru_info_list[SLOT];
	for (unit = 1; unit <= mct_system_info.max_units[SLOT]; ++unit) {
		int	iunit;
		if (unit == cpu_slot_num) {
			fru_ptr->fru_type = (scsb_utype_t)OC_CPU;
		} else if (unit == ctc_slot_num) {
			/* fru_ptr saved for Transition Card Presence check */
			ctcslot_ptr = fru_ptr;
			fru_ptr->fru_type = (scsb_utype_t)OC_UNKN;
		} else if (unit == alarm_slot_num) {
			/* fru_ptr saved for Alarm Card Presence check below */
			acslot_ptr = fru_ptr;
			fru_ptr->fru_type = (scsb_utype_t)OC_UNKN;
		} else {
			fru_ptr->fru_type = (scsb_utype_t)OC_UNKN;
		}
		/*
		 * Get the slot event code (t), then use it to get the
		 * slot bit-offsets for LED, BLINK, and SYSCFG registers.
		 * On a P1.5 Tonga, the internal slot number must be used to
		 * find the event code.
		 * The P1.0 Tonga does not get mapped due to a SSB difference.
		 */
		if (IS_SCB_P15) {
			iunit = tonga_psl_to_ssl(scsb, unit);
			t = FRU_UNIT_TO_EVCODE(SLOT, iunit);
		} else {
			t = FRU_UNIT_TO_EVCODE(SLOT, unit);
		}
		led_bit = FRU_OFFSET(t, SCTRL_LED_OK_BASE);
		blink_bit = FRU_OFFSET(t, SCTRL_BLINK_OK_BASE);
		blink_reg = FRU_REG_ADDR(t, SCTRL_BLINK_OK_BASE);
		if (is_tonga && unit <= TG_MAX_SLOTS) {
			bit_num = tonga_pslotnum_to_cfgbit(scsb, unit);
		} else {
			bit_num = FRU_OFFSET(t, SCTRL_SYSCFG_BASE);
		}
		/*
		 * get the registers addresses and shadow register index for
		 * the SYSCFG register
		 */
		syscfg = FRU_REG_ADDR(t, SCTRL_SYSCFG_BASE);
		index = SCSB_REG_INDEX(syscfg);
		led_reg = FRU_REG_ADDR(t, SCTRL_LED_OK_BASE);
		/*
		 * check and set presence status
		 */
		if (scsb->scsb_state & SCSB_P06_PROM) {
			fru_ptr->fru_status = FRU_NOT_PRESENT;
		} else if (scsb->scsb_data_reg[index] & (1 << bit_num)) {
			fru_ptr->fru_status = FRU_PRESENT;
		} else {
			fru_ptr->fru_status = FRU_NOT_PRESENT;
		}
		fru_ptr->fru_unit = (scsb_unum_t)unit;
		fru_ptr->fru_id = fru_id_table[event_to_index(
		    FRU_UNIT_TO_EVCODE(SLOT, unit))];
		fru_ptr->fru_version = (fru_version_t)0;
		fru_ptr->type_list = (fru_options_t *)NULL;
		fru_ptr->i2c_info = (fru_i2c_info_t *)
		    kmem_zalloc(sizeof (fru_i2c_info_t), KM_SLEEP);
		fru_ptr->i2c_info->syscfg_reg = syscfg;
		fru_ptr->i2c_info->syscfg_bit = bit_num;
		fru_ptr->i2c_info->ledata_reg = led_reg;
		fru_ptr->i2c_info->ledata_bit = led_bit;
		fru_ptr->i2c_info->blink_reg = blink_reg;
		fru_ptr->i2c_info->blink_bit = blink_bit;
		last_ptr = fru_ptr;
		fru_ptr++;
		last_ptr->next = fru_ptr;
	}
	last_ptr->next = (fru_info_t *)NULL;
	/*
	 * PDU
	 */
	mct_system_info.fru_info_list[PDU] = (fru_info_t *)
	    kmem_zalloc(sizeof (fru_info_t) *
	    (mct_system_info.max_units[PDU] + pad), KM_SLEEP);
	fru_ptr = mct_system_info.fru_info_list[PDU];
	for (unit = 1; unit <= mct_system_info.max_units[PDU]; ++unit) {
		fru_ptr->fru_type = PDU;
		/* SCB15 */
		/*
		 * get the FRU event code (t), then use it to get the
		 * FRU bit-offsets for LED and SYSCFG registers
		 */
		t = FRU_UNIT_TO_EVCODE(PDU, unit);
		led_bit = FRU_OFFSET(t, SCTRL_LED_OK_BASE);
		bit_num = FRU_OFFSET(t, SCTRL_SYSCFG_BASE);
		if (IS_SCB_P15) {
			blink_bit = FRU_OFFSET(t, SCTRL_BLINK_OK_BASE);
			i = FRU_REG_INDEX(t, SCTRL_BLINK_OK_BASE);
			blink_reg = SCSB_REG_ADDR(i);
		} else {
			blink_bit = 0;
			blink_reg = 0;
		}
		/*
		 * get the registers addresses and shadow register index for
		 * the SYSCFG register
		 */
		i = FRU_REG_INDEX(t, SCTRL_SYSCFG_BASE);
		syscfg = SCSB_REG_ADDR(i);
		index = SCSB_REG_INDEX(syscfg);
		i = FRU_REG_INDEX(t, SCTRL_LED_OK_BASE);
		led_reg = SCSB_REG_ADDR(i);
		/*
		 * check and set presence status
		 */
		if (scsb->scsb_data_reg[index] & (1 << bit_num)) {
			fru_ptr->fru_status = FRU_PRESENT;
			fru_ptr->fru_version = (fru_version_t)0;
		} else {
			fru_ptr->fru_status = FRU_NOT_PRESENT;
			fru_ptr->fru_version = (fru_version_t)0;
		}
		fru_ptr->fru_unit = (scsb_unum_t)unit;
		fru_ptr->fru_id = fru_id_table[event_to_index(t)];
		fru_ptr->type_list = (fru_options_t *)NULL;
		fru_ptr->i2c_info = (fru_i2c_info_t *)
		    kmem_zalloc(sizeof (fru_i2c_info_t), KM_SLEEP);
		fru_ptr->i2c_info->syscfg_reg = syscfg;
		fru_ptr->i2c_info->syscfg_bit = bit_num;
		fru_ptr->i2c_info->ledata_reg = led_reg;
		fru_ptr->i2c_info->ledata_bit = led_bit;
		fru_ptr->i2c_info->blink_reg = blink_reg;
		fru_ptr->i2c_info->blink_bit = blink_bit;
		last_ptr = fru_ptr;
		fru_ptr++;
		last_ptr->next = fru_ptr;
	}
	last_ptr->next = (fru_info_t *)NULL;
	/*
	 * Power Supplies
	 */
	mct_system_info.fru_info_list[PS] = (fru_info_t *)
	    kmem_zalloc(sizeof (fru_info_t) *
	    (mct_system_info.max_units[PS] + pad), KM_SLEEP);
	fru_ptr = mct_system_info.fru_info_list[PS];
	for (unit = 1; unit <= mct_system_info.max_units[PS]; ++unit) {
		/*
		 * get the FRU event code (t), then use it to get the
		 * FRU bit-offsets for LED and SYSCFG registers
		 */
		t = FRU_UNIT_TO_EVCODE(PS, unit);
		led_bit = FRU_OFFSET(t, SCTRL_LED_OK_BASE);
		bit_num = FRU_OFFSET(t, SCTRL_SYSCFG_BASE);
		if (IS_SCB_P15) {
			blink_bit = FRU_OFFSET(t, SCTRL_BLINK_OK_BASE);
			i = FRU_REG_INDEX(t, SCTRL_BLINK_OK_BASE);
			blink_reg = SCSB_REG_ADDR(i);
		} else {
			blink_bit = 0;
			blink_reg = 0;
		}
		/*
		 * get the registers addresses and shadow register index for
		 * the SYSCFG register
		 */
		i = FRU_REG_INDEX(t, SCTRL_SYSCFG_BASE);
		syscfg = SCSB_REG_ADDR(i);
		index = SCSB_REG_INDEX(syscfg);
		i = FRU_REG_INDEX(t, SCTRL_LED_OK_BASE);
		led_reg = SCSB_REG_ADDR(i);
		/*
		 * check and set presence status
		 */
		if (scsb->scsb_data_reg[index] & (1 << bit_num)) {
			fru_ptr->fru_status = FRU_PRESENT;
		} else {
			fru_ptr->fru_status = FRU_NOT_PRESENT;
		}
		fru_ptr->fru_type = PS;
		fru_ptr->fru_unit = (scsb_unum_t)unit;
		fru_ptr->fru_id = fru_id_table[event_to_index(t)];
		fru_ptr->fru_version = (fru_version_t)0;
		fru_ptr->type_list = (fru_options_t *)NULL;
		fru_ptr->i2c_info = (fru_i2c_info_t *)
		    kmem_zalloc(sizeof (fru_i2c_info_t), KM_SLEEP);
		fru_ptr->i2c_info->syscfg_reg = syscfg;
		fru_ptr->i2c_info->syscfg_bit = bit_num;
		fru_ptr->i2c_info->ledata_reg = led_reg;
		fru_ptr->i2c_info->ledata_bit = led_bit;
		fru_ptr->i2c_info->blink_reg = blink_reg;
		fru_ptr->i2c_info->blink_bit = blink_bit;
		last_ptr = fru_ptr;
		fru_ptr++;
		last_ptr->next = fru_ptr;
	}
	last_ptr->next = (fru_info_t *)NULL;
	/*
	 * SCSI Disks and removable media
	 */
	mct_system_info.fru_info_list[DISK] = (fru_info_t *)
	    kmem_zalloc(sizeof (fru_info_t) *
	    (mct_system_info.max_units[DISK] + pad), KM_SLEEP);
	fru_ptr = mct_system_info.fru_info_list[DISK];
	for (unit = 1; unit <= mct_system_info.max_units[DISK]; ++unit) {
		/* SCB15 */
		/*
		 * get the FRU event code (t), then use it to get the
		 * FRU bit-offsets for LED and SYSCFG registers
		 */
		t = FRU_UNIT_TO_EVCODE(DISK, unit);
		led_bit = FRU_OFFSET(t, SCTRL_LED_OK_BASE);
		bit_num = FRU_OFFSET(t, SCTRL_SYSCFG_BASE);
		if (IS_SCB_P15) {
			blink_bit = FRU_OFFSET(t, SCTRL_BLINK_OK_BASE);
			i = FRU_REG_INDEX(t, SCTRL_BLINK_OK_BASE);
			blink_reg = SCSB_REG_ADDR(i);
		} else {
			blink_bit = 0;
			blink_reg = 0;
		}
		/*
		 * get the registers addresses and shadow register index for
		 * the SYSCFG register
		 */
		i = FRU_REG_INDEX(t, SCTRL_SYSCFG_BASE);
		syscfg = SCSB_REG_ADDR(i);
		index = SCSB_REG_INDEX(syscfg);
		i = FRU_REG_INDEX(t, SCTRL_LED_OK_BASE);
		led_reg = SCSB_REG_ADDR(i);
		/*
		 * check and set presence status
		 */
		if (scsb->scsb_data_reg[index] & (1 << bit_num)) {
			fru_ptr->fru_status = FRU_PRESENT;
			fru_ptr->fru_version = (fru_version_t)0;
		} else
			fru_ptr->fru_status = FRU_NOT_PRESENT;
		fru_ptr->fru_type = DISK;
		fru_ptr->fru_unit = (scsb_unum_t)unit;
		fru_ptr->fru_id = fru_id_table[event_to_index(t)];
		fru_ptr->type_list = (fru_options_t *)NULL;
		fru_ptr->i2c_info = (fru_i2c_info_t *)
		    kmem_zalloc(sizeof (fru_i2c_info_t), KM_SLEEP);
		fru_ptr->i2c_info->syscfg_reg = syscfg;
		fru_ptr->i2c_info->syscfg_bit = bit_num;
		fru_ptr->i2c_info->ledata_reg = led_reg;
		fru_ptr->i2c_info->ledata_bit = led_bit;
		fru_ptr->i2c_info->blink_reg = blink_reg;
		fru_ptr->i2c_info->blink_bit = blink_bit;
		last_ptr = fru_ptr;
		fru_ptr++;
		last_ptr->next = fru_ptr;
	}
	last_ptr->next = (fru_info_t *)NULL;
	/*
	 * Fan Trays
	 */
	mct_system_info.fru_info_list[FAN] = (fru_info_t *)
	    kmem_zalloc(sizeof (fru_info_t) *
	    (mct_system_info.max_units[FAN] + pad), KM_SLEEP);
	fru_ptr = mct_system_info.fru_info_list[FAN];
	for (unit = 1; unit <= mct_system_info.max_units[FAN]; ++unit) {
		int		bit_num;
		/* SCB15 */
		/*
		 * get the FRU event code (t), then use it to get the
		 * FRU bit-offsets for LED and SYSCFG registers
		 */
		t = FRU_UNIT_TO_EVCODE(FAN, unit);
		led_bit = FRU_OFFSET(t, SCTRL_LED_OK_BASE);
		bit_num = FRU_OFFSET(t, SCTRL_SYSCFG_BASE);
		if (IS_SCB_P15) {
			blink_bit = FRU_OFFSET(t, SCTRL_BLINK_OK_BASE);
			i = FRU_REG_INDEX(t, SCTRL_BLINK_OK_BASE);
			blink_reg = SCSB_REG_ADDR(i);
		} else {
			blink_bit = 0;
			blink_reg = 0;
		}
		/*
		 * get the registers addresses and shadow register index for
		 * the SYSCFG register
		 */
		i = FRU_REG_INDEX(t, SCTRL_SYSCFG_BASE);
		syscfg = SCSB_REG_ADDR(i);
		index = SCSB_REG_INDEX(syscfg);
		i = FRU_REG_INDEX(t, SCTRL_LED_OK_BASE);
		led_reg = SCSB_REG_ADDR(i);
		/*
		 * check and set presence status
		 */
		if (scsb->scsb_data_reg[index] & (1 << bit_num)) {
			fru_ptr->fru_status = FRU_PRESENT;
		} else {
			fru_ptr->fru_status = FRU_NOT_PRESENT;
		}
		fru_ptr->fru_type = FAN;
		fru_ptr->fru_unit = (scsb_unum_t)unit;
		fru_ptr->fru_id = fru_id_table[event_to_index(t)];
		fru_ptr->fru_version = (fru_version_t)0;
		fru_ptr->type_list = (fru_options_t *)NULL;
		fru_ptr->i2c_info = (fru_i2c_info_t *)
		    kmem_zalloc(sizeof (fru_i2c_info_t), KM_SLEEP);
		fru_ptr->i2c_info->syscfg_reg = syscfg;
		fru_ptr->i2c_info->syscfg_bit = bit_num;
		fru_ptr->i2c_info->ledata_reg = led_reg;
		fru_ptr->i2c_info->ledata_bit = led_bit;
		fru_ptr->i2c_info->blink_reg = blink_reg;
		fru_ptr->i2c_info->blink_bit = blink_bit;
		last_ptr = fru_ptr;
		fru_ptr++;
		last_ptr->next = fru_ptr;
	}
	last_ptr->next = (fru_info_t *)NULL;
	/*
	 * Alarm Cards
	 */
	mct_system_info.fru_info_list[ALARM] = (fru_info_t *)
	    kmem_zalloc(sizeof (fru_info_t) *
	    (mct_system_info.max_units[ALARM] + pad), KM_SLEEP);
	fru_ptr = mct_system_info.fru_info_list[ALARM];
	for (unit = 1; unit <= mct_system_info.max_units[ALARM]; ++unit) {
		int		bit_num;

		/*
		 * get the FRU event code (t), then use it to get the
		 * FRU bit-offsets for SYSCFG register
		 */
		t = FRU_UNIT_TO_EVCODE(ALARM, unit);
		bit_num = FRU_OFFSET(t, SCTRL_SYSCFG_BASE);
		/*
		 * get the registers addresses and shadow register index for
		 * the SYSCFG register
		 */
		i = FRU_REG_INDEX(t, SCTRL_SYSCFG_BASE);
		syscfg = SCSB_REG_ADDR(i);
		index = SCSB_REG_INDEX(syscfg);
		/*
		 * check and set presence status
		 */
		if (scsb->scsb_data_reg[index] & (1 << bit_num)) {
			fru_ptr->fru_status = FRU_PRESENT;
			if (acslot_ptr != NULL && acslot_ptr->fru_status ==
			    FRU_PRESENT) {
				acslot_ptr->fru_type = (scsb_utype_t)OC_AC;
				/*
				 * acslot_ptr->fru_id =
				 *	fru_id_table[event_to_index(t)];
				 */
			}
		} else {
			fru_ptr->fru_status = FRU_NOT_PRESENT;
		}

		fru_ptr->fru_type = ALARM;
		fru_ptr->fru_unit = (scsb_unum_t)unit;
		fru_ptr->fru_id = fru_id_table[event_to_index(t)];
		fru_ptr->fru_version = (fru_version_t)0;
		fru_ptr->type_list = (fru_options_t *)NULL;
		fru_ptr->i2c_info = (fru_i2c_info_t *)
		    kmem_zalloc(sizeof (fru_i2c_info_t), KM_SLEEP);
		fru_ptr->i2c_info->syscfg_reg = syscfg;
		fru_ptr->i2c_info->syscfg_bit = bit_num;
		fru_ptr->i2c_info->ledata_reg = 0;
		fru_ptr->i2c_info->ledata_bit = 0;
		fru_ptr->i2c_info->blink_reg = 0;
		fru_ptr->i2c_info->blink_bit = 0;
		last_ptr = fru_ptr;
		fru_ptr++;
		last_ptr->next = fru_ptr;
	}
	last_ptr->next = (fru_info_t *)NULL;
	/*
	 * SCB
	 */
	mct_system_info.fru_info_list[SCB] = (fru_info_t *)
	    kmem_zalloc(sizeof (fru_info_t) *
	    (mct_system_info.max_units[SCB] + pad), KM_SLEEP);
	fru_ptr = mct_system_info.fru_info_list[SCB];
	unit = 1;
	/* SCB15 */
	/*
	 * get the FRU event code (t), then use it to get the
	 * FRU bit-offset for LED register
	 */
	t = FRU_UNIT_TO_EVCODE(SCB, unit);
	led_bit = FRU_OFFSET(t, SCTRL_LED_OK_BASE);
	i = FRU_REG_INDEX(t, SCTRL_LED_OK_BASE);
	led_reg = SCSB_REG_ADDR(i);
	if (IS_SCB_P15) {
		blink_bit = FRU_OFFSET(t, SCTRL_BLINK_OK_BASE);
		i = FRU_REG_INDEX(t, SCTRL_BLINK_OK_BASE);
		blink_reg = SCSB_REG_ADDR(i);
	} else {
		blink_bit = 0;
		blink_reg = 0;
	}
	i = SYS_REG_INDEX(SCTRL_SCBID0, SCTRL_SCBID_BASE);
	index = SCSB_REG_ADDR(i);
	/*
	 * check and set presence status
	 */
	if (scsb->scsb_state & SCSB_SCB_PRESENT) {
		fru_ptr->fru_status = FRU_PRESENT;
	} else {
		fru_ptr->fru_status = FRU_NOT_PRESENT;
	}
	fru_ptr->fru_type = SCB;
	fru_ptr->fru_unit = (scsb_unum_t)unit;
	fru_ptr->fru_id = fru_id_table[event_to_index(t)];
	/* get PROM_VERSION from shadow registers */
	if (scsb_rdwr_register(scsb, I2C_WR_RD, index, 1, &t_uchar, 1))
		fru_ptr->fru_version = (fru_version_t)0;
	else
		fru_ptr->fru_version = (fru_version_t)t_uchar;
	fru_ptr->type_list = (fru_options_t *)NULL;
	fru_ptr->i2c_info = (fru_i2c_info_t *)
	    kmem_zalloc(sizeof (fru_i2c_info_t), KM_SLEEP);
	fru_ptr->i2c_info->syscfg_reg = 0;
	fru_ptr->i2c_info->syscfg_bit = 0;
	fru_ptr->i2c_info->ledata_reg = led_reg;
	fru_ptr->i2c_info->ledata_bit = led_bit;
	fru_ptr->i2c_info->blink_reg = blink_reg;
	fru_ptr->i2c_info->blink_bit = blink_bit;
	fru_ptr->next = (fru_info_t *)NULL;
	/*
	 * SSB
	 */
	mct_system_info.fru_info_list[SSB] = (fru_info_t *)
	    kmem_zalloc(sizeof (fru_info_t) *
	    (mct_system_info.max_units[SSB] + pad), KM_SLEEP);
	fru_ptr = mct_system_info.fru_info_list[SSB];
	unit = 1;
	/* SCB15 */
	/*
	 * get the FRU event code (t), then use it to get the
	 * FRU bit-offset for SYSCFG register
	 */
	t = FRU_UNIT_TO_EVCODE(SSB, unit);
	bit_num = FRU_OFFSET(t, SCTRL_SYSCFG_BASE);
	/*
	 * get the registers addresses and shadow register index for
	 * the SYSCFG register
	 */
	i = FRU_REG_INDEX(t, SCTRL_SYSCFG_BASE);
	syscfg = SCSB_REG_ADDR(i);
	index = SCSB_REG_INDEX(syscfg);
	/*
	 * check and set presence status
	 */
	if (scsb->scsb_data_reg[index] & (1 << bit_num)) {
		fru_ptr->fru_status = FRU_PRESENT;
	} else {
		fru_ptr->fru_status = FRU_NOT_PRESENT;
	}
	fru_ptr->fru_type = SSB;
	fru_ptr->fru_unit = (scsb_unum_t)unit;
	fru_ptr->fru_id = fru_id_table[event_to_index(t)];
	fru_ptr->fru_version = (fru_version_t)0;
	fru_ptr->type_list = (fru_options_t *)NULL;
	fru_ptr->i2c_info = (fru_i2c_info_t *)
	    kmem_zalloc(sizeof (fru_i2c_info_t), KM_SLEEP);
	fru_ptr->i2c_info->syscfg_reg = syscfg;
	fru_ptr->i2c_info->syscfg_bit = bit_num;
	fru_ptr->i2c_info->ledata_reg = 0;
	fru_ptr->i2c_info->ledata_bit = 0;
	fru_ptr->i2c_info->blink_reg = 0;
	fru_ptr->i2c_info->blink_bit = 0;
	fru_ptr->next = (fru_info_t *)NULL;
	/*
	 * CFTM
	 */
	mct_system_info.fru_info_list[CFTM] = (fru_info_t *)
	    kmem_zalloc(sizeof (fru_info_t) *
	    (mct_system_info.max_units[CFTM] + pad), KM_SLEEP);
	fru_ptr = mct_system_info.fru_info_list[CFTM];
	unit = 1;
	/* SCB15 */
	/*
	 * get the FRU event code (t), then use it to get the
	 * FRU bit-offsets for LED and SYSCFG registers
	 */
	t = FRU_UNIT_TO_EVCODE(CFTM, unit);
	led_bit = FRU_OFFSET(t, SCTRL_LED_OK_BASE);
	bit_num = FRU_OFFSET(t, SCTRL_SYSCFG_BASE);
	if (IS_SCB_P15) {
		blink_bit = FRU_OFFSET(t, SCTRL_BLINK_OK_BASE);
		i = FRU_REG_INDEX(t, SCTRL_BLINK_OK_BASE);
		blink_reg = SCSB_REG_ADDR(i);
	} else {
		blink_bit = 0;
		blink_reg = 0;
	}
	/*
	 * get the registers addresses and shadow register index for
	 * the SYSCFG register
	 */
	i = FRU_REG_INDEX(t, SCTRL_SYSCFG_BASE);
	syscfg = SCSB_REG_ADDR(i);
	index = SCSB_REG_INDEX(syscfg);
	i = FRU_REG_INDEX(t, SCTRL_LED_OK_BASE);
	led_reg = SCSB_REG_ADDR(i);
	/*
	 * check and set presence status
	 */
	if (scsb->scsb_data_reg[index] & (1 << bit_num)) {
		fru_ptr->fru_status = FRU_PRESENT;
		if (ctcslot_ptr != NULL && ctcslot_ptr->fru_status ==
		    FRU_PRESENT) {
			ctcslot_ptr->fru_type = (scsb_utype_t)OC_CTC;
			scsb->scsb_hsc_state |= SCSB_HSC_CTC_PRES;
		}
	} else {
		fru_ptr->fru_status = FRU_NOT_PRESENT;
	}
	fru_ptr->fru_type = CFTM;
	fru_ptr->fru_unit = (scsb_unum_t)1;
	fru_ptr->fru_id = fru_id_table[event_to_index(t)];
	fru_ptr->fru_version = (fru_version_t)0;
	fru_ptr->type_list = (fru_options_t *)NULL;
	fru_ptr->i2c_info = (fru_i2c_info_t *)
	    kmem_zalloc(sizeof (fru_i2c_info_t), KM_SLEEP);
	fru_ptr->i2c_info->syscfg_reg = syscfg;
	fru_ptr->i2c_info->syscfg_bit = bit_num;
	fru_ptr->i2c_info->ledata_reg = led_reg;
	fru_ptr->i2c_info->ledata_bit = led_bit;
	fru_ptr->i2c_info->blink_reg = blink_reg;
	fru_ptr->i2c_info->blink_bit = blink_bit;
	fru_ptr->next = (fru_info_t *)NULL;
	/*
	 * CRTM
	 */
	mct_system_info.fru_info_list[CRTM] = (fru_info_t *)
	    kmem_zalloc(sizeof (fru_info_t) *
	    (mct_system_info.max_units[CRTM] + pad),
	    KM_SLEEP);
	fru_ptr = mct_system_info.fru_info_list[CRTM];
	unit = 1;
	/* SCB15 */
	/*
	 * get the FRU event code (t), then use it to get the
	 * FRU bit-offsets for LED and SYSCFG registers
	 */
	t = FRU_UNIT_TO_EVCODE(CRTM, unit);
	bit_num = FRU_OFFSET(t, SCTRL_SYSCFG_BASE);
	/*
	 * get the registers addresses and shadow register index for
	 * the SYSCFG register
	 */
	i = FRU_REG_INDEX(t, SCTRL_SYSCFG_BASE);
	syscfg = SCSB_REG_ADDR(i);
	index = SCSB_REG_INDEX(syscfg);
	/*
	 * check and set presence status
	 */
	if (scsb->scsb_data_reg[index] & (1 << bit_num)) {
		fru_ptr->fru_status = FRU_PRESENT;
	} else {
		fru_ptr->fru_status = FRU_NOT_PRESENT;
	}
	fru_ptr->fru_type = CRTM;
	fru_ptr->fru_unit = (scsb_unum_t)unit;
	fru_ptr->fru_id = fru_id_table[event_to_index(t)];
	fru_ptr->fru_version = (fru_version_t)0;
	fru_ptr->type_list = (fru_options_t *)NULL;
	fru_ptr->i2c_info = (fru_i2c_info_t *)
	    kmem_zalloc(sizeof (fru_i2c_info_t), KM_SLEEP);
	fru_ptr->i2c_info->syscfg_reg = syscfg;
	fru_ptr->i2c_info->syscfg_bit = bit_num;
	fru_ptr->i2c_info->ledata_reg = 0;
	fru_ptr->i2c_info->ledata_bit = 0;
	fru_ptr->i2c_info->blink_reg = 0;
	fru_ptr->i2c_info->blink_bit = 0;
	fru_ptr->next = (fru_info_t *)NULL;
	/*
	 * PRTM
	 */
	mct_system_info.fru_info_list[PRTM] = (fru_info_t *)
	    kmem_zalloc(sizeof (fru_info_t) *
	    (mct_system_info.max_units[PRTM] + pad), KM_SLEEP);
	fru_ptr = mct_system_info.fru_info_list[PRTM];
	unit = 1;
	/*
	 * SCB15
	 * get the FRU event code (t), then use it to get the
	 * FRU bit-offsets for LED and SYSCFG registers
	 */
	t = FRU_UNIT_TO_EVCODE(PRTM, unit);
	bit_num = FRU_OFFSET(t, SCTRL_SYSCFG_BASE);
	/*
	 * get the registers addresses and shadow register index for
	 * the SYSCFG register
	 */
	i = FRU_REG_INDEX(t, SCTRL_SYSCFG_BASE);
	syscfg = SCSB_REG_ADDR(i);
	index = SCSB_REG_INDEX(syscfg);
	/*
	 * check and set presence status
	 */
	if (scsb->scsb_data_reg[index] & (1 << bit_num)) {
		fru_ptr->fru_status = FRU_PRESENT;
	} else {
		fru_ptr->fru_status = FRU_NOT_PRESENT;
	}
	fru_ptr->fru_type = PRTM;
	fru_ptr->fru_unit = (scsb_unum_t)unit;
	fru_ptr->fru_id = fru_id_table[event_to_index(t)];
	fru_ptr->fru_version = (fru_version_t)0;
	fru_ptr->type_list = (fru_options_t *)NULL;
	fru_ptr->i2c_info = (fru_i2c_info_t *)
	    kmem_zalloc(sizeof (fru_i2c_info_t), KM_SLEEP);
	fru_ptr->i2c_info->syscfg_reg = syscfg;
	fru_ptr->i2c_info->syscfg_bit = bit_num;
	fru_ptr->i2c_info->ledata_reg = 0;
	fru_ptr->i2c_info->ledata_bit = 0;
	fru_ptr->i2c_info->blink_reg = 0;
	fru_ptr->i2c_info->blink_bit = 0;
	fru_ptr->next = (fru_info_t *)NULL;

	scsb->scsb_state |= SCSB_TOPOLOGY;
#ifdef DEBUG
	mct_topology_dump(scsb, 0);
#endif
}

/*ARGSUSED*/
static void
scsb_free_topology(scsb_state_t *scsb)
{
	int		i;
	fru_info_t	*fru_ptr;

	if (scsb_debug & 0x00100005)
		cmn_err(CE_NOTE, "scsb_free_topology:");
	for (i = 0; i < SCSB_UNIT_TYPES; ++i) {
		fru_ptr = mct_system_info.fru_info_list[i];
		while (fru_ptr != NULL) {
			if (fru_ptr->i2c_info != (fru_i2c_info_t *)NULL)
				kmem_free(fru_ptr->i2c_info,
				    sizeof (fru_i2c_info_t));
			fru_ptr = fru_ptr->next;
		}
		if ((fru_ptr = mct_system_info.fru_info_list[i]) !=
		    (fru_info_t *)NULL) {
			kmem_free(fru_ptr, sizeof (fru_info_t) *
			    mct_system_info.max_units[i]);
			mct_system_info.fru_info_list[i] = (fru_info_t *)NULL;
		}
	}
}

#ifdef DEBUG
static void
mct_topology_dump(scsb_state_t *scsb, int force)
{
	int		i;
	fru_info_t	*fru_ptr;

	if (!force && !(scsb_debug & 0x00200000))
		return;
	if (force && !(scsb->scsb_state & (SCSB_DIAGS_MODE | SCSB_DEBUG_MODE)))
		return;
	if (!(scsb->scsb_state & SCSB_TOPOLOGY)) {
		cmn_err(CE_NOTE, "mct_topology_dump: Topology not set!");
		return;
	}
	for (i = 0; i < SCSB_UNIT_TYPES; ++i) {
		fru_ptr = mct_system_info.fru_info_list[i];
		switch ((scsb_utype_t)i) {
		case SLOT:
			cmn_err(CE_NOTE, "MCT: Number of Slots: %d",
			    mct_system_info.max_units[SLOT]);
			break;
		case ALARM:
			cmn_err(CE_NOTE, "MCT: MAX Number of Alarm Cards: %d",
			    mct_system_info.max_units[ALARM]);
			break;
		case DISK:
			cmn_err(CE_NOTE, "MCT: MAX Number of SCSI Devices: %d",
			    mct_system_info.max_units[DISK]);
			break;
		case FAN:
			cmn_err(CE_NOTE, "MCT: MAX Number of Fan Trays: %d",
			    mct_system_info.max_units[FAN]);
			break;
		case PDU:
			cmn_err(CE_NOTE, "MCT: MAX Number of PDUs: %d",
			    mct_system_info.max_units[PDU]);
			break;
		case PS:
			cmn_err(CE_NOTE,
			    "MCT: MAX Number of Power Supplies: %d",
			    mct_system_info.max_units[PS]);
			break;
		case SCB:
			cmn_err(CE_NOTE, "MCT: MAX Number of SCBs: %d",
			    mct_system_info.max_units[SCB]);
			break;
		case SSB:
			cmn_err(CE_NOTE, "MCT: MAX Number of SSBs: %d",
			    mct_system_info.max_units[SSB]);
			break;
		}
		while (fru_ptr != NULL) {
			if (fru_ptr->fru_status & FRU_PRESENT) {
				cmn_err(CE_NOTE,
				    "MCT:   type=%d, unit=%d, id=0x%x, "
				    "version=0x%x",
				    fru_ptr->fru_type,
				    fru_ptr->fru_unit,
				    fru_ptr->fru_id,
				    fru_ptr->fru_version);
			}
			fru_ptr = fru_ptr->next;
		}
	}
}

/*
 * Sends an event when the system controller board I2C errors
 * exceed the threshold.
 */
static void
scsb_failing_event(scsb_state_t *scsb)
{
	uint32_t scsb_event_code = SCTRL_EVENT_SCB;

	add_event_code(scsb, scsb_event_code);
	(void) scsb_queue_ops(scsb, QPUT_INT32, 1, &scsb_event_code,
	"scsb_intr");
}
#endif

int
scsb_read_bhealthy(scsb_state_t *scsb)
{
	int		error;
	uchar_t		reg;
	int		index;

	if (scsb_debug & 0x8001) {
		cmn_err(CE_NOTE, "scsb_read_bhealthy()");
	}
	reg = SCSB_REG_ADDR(SCTRL_BHLTHY_BASE);
	index = SCSB_REG_INDEX(reg);
	error = scsb_rdwr_register(scsb, I2C_WR_RD, reg,
	    SCTRL_BHLTHY_NUMREGS, &scsb->scsb_data_reg[index], 1);
	return (error);
}

/*
 * Returns the health status of a slot
 */
int
scsb_read_slot_health(scsb_state_t *scsb, int pslotnum)
{
	int slotnum = tonga_psl_to_ssl(scsb, pslotnum);
	return (scsb_fru_op(scsb, SLOT, slotnum,
	    SCTRL_BHLTHY_BASE, SCSB_FRU_OP_GET_BITVAL));
}

/*
 * DIAGNOSTIC and DEBUG only.
 * Called from ioctl command (SCSBIOC_BHEALTHY_GET)
 */
int
scsb_bhealthy_slot(scsb_state_t *scsb, scsb_uinfo_t *suip)
{
	int		error = 0;
	int		base, code, unit_number;
	uchar_t		reg;
	int		index;

	if (scsb->scsb_state & SCSB_FROZEN)
		return (EAGAIN);

	/* operation valid for slots only */
	if (suip == NULL || suip->unit_type != SLOT) {
		return (EINVAL);
	}

	if (scsb_debug & 0x8001)
		cmn_err(CE_NOTE, "scsb_bhealthy_slot: slot %d",
		    suip->unit_number);
	if (suip->unit_number > mct_system_info.max_units[SLOT]) {
		return (EINVAL);
	}
	/*
	 * Map 1.0 Tonga Slot Number, if necessary
	 */
	tonga_slotnum_check(scsb, suip);
	base = SCTRL_BHLTHY_BASE;
	code = FRU_UNIT_TO_EVCODE(suip->unit_type, suip->unit_number);
	unit_number = FRU_OFFSET(code, base);
	index = FRU_REG_INDEX(code, base);
	reg = SCSB_REG_ADDR(index);
	index = SCSB_REG_INDEX(reg);		/* shadow index */

	if (scsb->scsb_state & SCSB_P10_PROM) {
		error = scsb_read_bhealthy(scsb);
	}
	/* else shadow regs are updated by interrupt handler */
	if (error == 0) {
		if (scsb->scsb_data_reg[index] & (1 << unit_number))
			suip->unit_state = ON;
		else
			suip->unit_state = OFF;
	}
	return (error);
}

/*
 * Called from HSC and ioctl command (SCSBIOC_RESET_UNIT)
 * to reset one specified slot
 */
int
scsb_reset_unit(scsb_state_t *scsb, scsb_uinfo_t *suip)
{
	int		error;
	int		unit_number;
	uchar_t		reg;
	int		index, slotnum, reset_state;

	if (scsb->scsb_state & SCSB_FROZEN)
		return (EAGAIN);
	if (scsb_debug & 0x8001) {
		cmn_err(CE_NOTE, "scsb_reset_slot(%d): slot %d, state %d\n",
		    scsb->scsb_instance, suip->unit_number,
		    suip->unit_state);
	}
	if (suip->unit_type != ALARM && !(scsb->scsb_state &
	    (SCSB_DIAGS_MODE | SCSB_DEBUG_MODE))) {
		return (EINVAL);
	}
	if (suip->unit_state != ON && suip->unit_state != OFF) {
		return (EINVAL);
	}
	error = 0;
	switch (suip->unit_type) {
	case ALARM:
	{
		int	i, code;
		if (suip->unit_number != 1)
			return (EINVAL);
		code = FRU_UNIT_TO_EVCODE(suip->unit_type, suip->unit_number);
		unit_number = FRU_OFFSET(code, SCTRL_RESET_BASE);
		i = ALARM_RESET_REG_INDEX(code, SCTRL_RESET_BASE);
		reg = SCSB_REG_ADDR(i);
		break;
	}
	case SLOT:
		slotnum = suip->unit_number;
		reset_state = (suip->unit_state == ON) ? SCSB_RESET_SLOT :
		    SCSB_UNRESET_SLOT;
		if (scsb->scsb_state & SCSB_IS_TONGA) {
			if (slotnum > TG_MAX_SLOTS ||
			    slotnum == SC_TG_CPU_SLOT) {
				return (EINVAL);
			}
		} else {
			if (slotnum > MC_MAX_SLOTS ||
			    slotnum == SC_MC_CPU_SLOT ||
			    (scsb->scsb_hsc_state & SCSB_HSC_CTC_PRES &&
			    slotnum == SC_MC_CTC_SLOT)) {
				return (EINVAL);
			}
		}
		return (scsb_reset_slot(scsb, slotnum, reset_state));
	default:
		return (EINVAL);
	}
	index = SCSB_REG_INDEX(reg);
	mutex_enter(&scsb->scsb_mutex);
	if (suip->unit_state == ON)
		scsb->scsb_data_reg[index] |= (1 << unit_number);
	else /* OFF */
		scsb->scsb_data_reg[index] &= ~(1 << unit_number);
	if ((error = scsb_rdwr_register(scsb, I2C_WR, reg, 1,
	    &scsb->scsb_data_reg[index], 0)) != 0) {
		if (scsb_debug & 0x8002)
			cmn_err(CE_WARN,
			    "scsb_leds: write failure to 0x%x", reg);
		return (error);
	}
	mutex_exit(&scsb->scsb_mutex);
	return (error);
}

/*
 * Diagnostic and DEBUG
 * This is a helper function for the helper ioctl to pretend that
 * scsb h/w is doing its job!!!
 */
int
scsb_slot_occupancy(scsb_state_t *scsb, scsb_uinfo_t *suip)
{
	int		error;
	int		saved_unit_number;

	if (!(scsb->scsb_state & (SCSB_DEBUG_MODE | SCSB_DIAGS_MODE)))
		return (EACCES);
	if (scsb->scsb_state & SCSB_FROZEN) {
		return (EAGAIN);
	}
	error = 0;
	switch (suip->unit_type) {
	case ALARM:
		if (suip->unit_number !=
		    (mct_system_info.fru_info_list[ALARM])->fru_unit) {
			return (EINVAL);
		}
		break;

	case SLOT:
		/*
		 * All slots are acceptable, except slots 11 & 12.
		 */
		if (suip->unit_number < 1 || suip->unit_number >
		    mct_system_info.max_units[ALARM]) {
			error = EINVAL;
			break;
		}
		/* Map 1.0 Tonga Slot Numbers if necessary */
		saved_unit_number = suip->unit_number;
		tonga_slotnum_check(scsb, suip);
		break;

	default:
		error = EINVAL;
		break;
	}

	if (error)
		return (error);
	if (suip->unit_state == ON) {
		if (hsc_slot_occupancy(saved_unit_number, B_TRUE, 0, B_TRUE)
		    != 0)
			error = EFAULT;
	} else {
		if (hsc_slot_occupancy(saved_unit_number, B_FALSE, 0, B_FALSE)
		    != 0)
			error = EFAULT;
	}

	return (error);
}

static int
scsb_clear_intptrs(scsb_state_t *scsb)
{
	int		i, error;
	uchar_t		wbuf[SCTRL_MAX_GROUP_NUMREGS];
	error = 0;
	for (i = 1; i <= SCTRL_INTR_NUMREGS; ++i) {
		wbuf[i] = 0xff;
	}
	if (error = scsb_rdwr_register(scsb, I2C_WR,
	    SCSB_REG_ADDR(SCTRL_INTSRC_BASE),
	    SCTRL_INTR_NUMREGS, wbuf, 1)) {
		if (scsb_debug & 0x0402)
			cmn_err(CE_NOTE, "scsb_clear_intptrs(): "
			    "write to 0x%x failed",
			    SCSB_REG_ADDR(SCTRL_INTSRC_BASE));
	}
	return (error);
}

static int
scsb_setall_intmasks(scsb_state_t *scsb)
{
	int		error;
	uchar_t		reg, wdata, rmask;
	int		i;

	/*
	 * write loop for Interrupt Mask registers
	 */
	if (scsb_debug & 0x0401)
		cmn_err(CE_NOTE, "setall_intmasks()");
	error = 0;
	rmask = 0;
	wdata = 0xff;
	reg = SCSB_REG_ADDR(SCTRL_INTMASK_BASE);
	for (i = 0; i < SCTRL_MASK_NUMREGS; ++i, ++reg) {
		if (error = scsb_write_mask(scsb, reg, rmask, wdata, 0)) {
			if (scsb_debug & 0x0402)
				cmn_err(CE_NOTE, "scsb_setall_intmasks: "
				    "write to 0x%x failed: %d", reg, error);
			error = EIO;
			break;
		}
	}
	return (error);
}


/*
 * Clear Interrupt masks based on the FRUs that could be installed
 * for this particular topology, determined by the MidPlane ID
 * from SCTRL_SYSCFG registers
 *	case SCTRL_MPID_HALF:
 *		1 CPU, 1 AlarmCard, 1 SCB/SSB, 2 PS, 3 FAN, 3 SCSI, 8 Slots
 *	case SCTRL_MPID_QUARTER:
 *		1 CPU, 1 AlarmCard, 1 SCB/SSB, 1 PS, 2 FAN, 1 SCSI, 4 Slots
 *	case SCTRL_MPID_QUARTER_NODSK:
 *		1 CPU, 1 AlarmCard, 1 SCB/SSB, 1 PS, 2 FAN, 0 SCSI, 4 Slots
 */
static int
scsb_clear_intmasks(scsb_state_t *scsb)
{
	int		error;
	uchar_t		msk_reg, reg, wdata, rmask;
	uchar_t		mask_data[SCTRL_MAX_GROUP_NUMREGS];
	int		tmp, idx, code, unit, offset, mbid;
	scsb_utype_t    fru_type;
	fru_info_t	*fru_ptr;

	if (scsb->scsb_state & SCSB_FROZEN &&
	    !(scsb->scsb_state & SCSB_IN_INTR)) {
		return (EAGAIN);
	}
	error = 0;
	for (tmp = 0; tmp < SCTRL_MASK_NUMREGS; ++tmp)
		mask_data[tmp] = 0;
	msk_reg = SCSB_REG_ADDR(SCTRL_INTMASK_BASE);
	mbid    = SCSB_REG_INDEX(msk_reg); /* the Mask Base Index Delta */
	if (scsb_debug & 0x0400) {
		cmn_err(CE_NOTE, "clear_intmasks: msk_reg=0x%x; mbid=%d",
		    msk_reg, mbid);
	}
	for (fru_type = 0; fru_type < SCSB_UNIT_TYPES; ++fru_type) {
		if (fru_type == SCB)
			continue;	/* handle below, 2 reg offsets */
		fru_ptr = mct_system_info.fru_info_list[fru_type];
		for (; fru_ptr != NULL; fru_ptr = fru_ptr->next) {
			unit = fru_ptr->fru_unit;
			code   = FRU_UNIT_TO_EVCODE(fru_type, unit);
			offset = FRU_OFFSET(code, SCTRL_INTMSK_BASE);
			reg    = FRU_REG_ADDR(code, SCTRL_INTMSK_BASE);
			idx    = SCSB_REG_INDEX(reg);
			tmp = idx - mbid;
			mask_data[tmp] |= (1 << offset);
			if (scsb_debug & 0x0400)
				cmn_err(CE_NOTE,
				"clear_intmasks:%d:%d: PRES mask[%d]:0x%x",
				    fru_type, unit, tmp, mask_data[tmp]);
			if ((fru_type == SLOT) && (IS_SCB_P15)) {
				/*
				 * Unmask the corresponding Slot HLTHY mask
				 * Use Slot bit and register offsets,
				 *  but with SCTRL_INTMASK_HLTHY_BASE
				 */
				reg = FRU_REG_ADDR(code,
				    SCTRL_INTMASK_HLTHY_BASE);
				idx = SCSB_REG_INDEX(reg);
				tmp = idx - mbid;
				mask_data[tmp] |= (1 << offset);
				if (scsb_debug & 0x0400) {
					cmn_err(CE_NOTE,
				"clear_intmasks:Slot:%d: HLTHY mask[%d]:0x%x"
				"; reg=0x%x, idx=%d, mbid=%d",
					    unit, tmp, mask_data[tmp],
					    reg, idx, mbid);
				}
			}
		}
	}
	/*
	 * Now unmask these non-fru interrupt events
	 *	SCTRL_EVENT_PWRDWN	(almost normal)
	 *	SCTRL_EVENT_REPLACE	(not used)
	 *	SCTRL_EVENT_ALARM_INT	(not working in P0.6/P1.0)
	 *	SCTRL_EVENT_SCB		(SCB 1.5 ONLY; plus SCB_INT_OFFSET)
	 */
	code   = SCTRL_EVENT_PWRDWN;
	offset = FRU_OFFSET(code, SCTRL_INTMSK_BASE);
	reg    = FRU_REG_ADDR(code, SCTRL_INTMSK_BASE);
	idx    = SCSB_REG_INDEX(reg);
	tmp = idx - mbid;
	mask_data[tmp] |= (1 << offset);
	if (IS_SCB_P15) {
		code   = SCTRL_EVENT_SCB;
		offset = FRU_OFFSET(code, SCTRL_INTMSK_BASE);
		reg    = FRU_REG_ADDR(code, SCTRL_INTMSK_BASE) + SCB_INT_OFFSET;
		idx    = SCSB_REG_INDEX(reg);
		tmp = idx - mbid;
		mask_data[tmp] |= (1 << offset);
		code   = SCTRL_EVENT_ALARM_INT;
		offset = FRU_OFFSET(code, SCTRL_INTMSK_BASE);
		reg    = FRU_REG_ADDR(code, SCTRL_INTMSK_BASE);
		idx    = SCSB_REG_INDEX(reg);
		tmp = idx - mbid;
		mask_data[tmp] |= (1 << offset);
	}
	for (tmp = 0; tmp < SCTRL_MASK_NUMREGS; ++tmp) {
		rmask = 0;
		wdata = mask_data[tmp];
		if (scsb_debug & 0x0400)
			cmn_err(CE_NOTE, "clear_intmasks:0x%x: ~(0x%x),0x%x",
			    msk_reg, (~wdata) & 0xff, wdata);
		mutex_enter(&scsb->scsb_mutex);
		if (error = scsb_write_mask(scsb, msk_reg, rmask,
		    (~wdata) & 0xff, wdata)) {
			mutex_exit(&scsb->scsb_mutex);
			if (scsb_debug & 0x0402)
				cmn_err(CE_NOTE, "scsb_clear_intmasks: "
				    "write to 0x%x failed: %d",
				    msk_reg, error);
			error = EIO;
			break;
		}
		mutex_exit(&scsb->scsb_mutex);
		++msk_reg;
	}
	return (error);
}

static int
scsb_get_status(scsb_state_t *scsb, scsb_status_t *smp)
{
	register int 	i;

	if (smp == NULL) {
		return (EFAULT);
	}
	if (scsb_debug & 0x40000000 &&
	    (scsb->scsb_state & SCSB_DEBUG_MODE ||
	    scsb->scsb_state & SCSB_DIAGS_MODE)) {
		if (scsb->scsb_state & SCSB_FROZEN) {
			return (EAGAIN);
		}
		mutex_enter(&scsb->scsb_mutex);
		if (scsb_debug & 0x80000000) {
			if ((i = scsb_readall_regs(scsb)) != 0 &&
			    scsb->scsb_state & SCSB_DEBUG_MODE)
				cmn_err(CE_WARN, "scsb_get_status: "
				    "scsb_readall_regs() FAILED");
		} else {
			if ((i = scsb_check_config_status(scsb)) == 0) {
				i = scsb_set_scfg_pres_leds(scsb, NULL);
			}
		}
		mutex_exit(&scsb->scsb_mutex);
		if (i) {
			cmn_err(CE_WARN,
			    "scsb_get_status: FAILED Presence LEDs update");
			return (EIO);
		}
	}
	for (i = 0; i < SCSB_DATA_REGISTERS; ++i)
		smp->scsb_reg[i] = scsb->scsb_data_reg[i];
	return (0);
}

/*
 * scsb_freeze_check:
 *	Turn all the leds off on the system monitor card, without changing
 *	the state of what we have for scsb. This routine is called only when
 *	replacing system monitor card, so the state of the card leds could be
 *	restored, using scsb_restore().
 *	Also, set state to SCSB_FROZEN which denies access to scsb while in
 *	freeze mode.
 */
static char  *BAD_BOARD_MSG =
	"SCSB: Should NOT remove SCB(%d) while cPCI Slot %d is "
	"in RESET with a possible bad board.";
static int	slots_in_reset[SCTRL_MAX_GROUP_NUMREGS];

static void
scsb_freeze_check(scsb_state_t *scsb)
{
	register int	i;
	int		offset;
	int		unit, slotnum;
	int		index;
	fru_info_t	*fru_ptr;
	uint32_t	code;
	uchar_t		reg;

	if (scsb_debug & 0x20001)
		cmn_err(CE_NOTE, "scsb_freeze_check(%d):", scsb->scsb_instance);

	if (scsb->scsb_state & SCSB_FROZEN) {
		return;
	}
	mutex_enter(&scsb->scsb_mutex);
	for (i = 0; i < SCTRL_MAX_GROUP_NUMREGS; ++i)
		slots_in_reset[i] = 0;
	/*
	 * We allow the SCB to be removed only if none of
	 * the cPCI resets are asserted for occupied slots.
	 * There shouldn't be a bad board plugged in the system
	 * while swapping the SCB.
	 */
	fru_ptr = mct_system_info.fru_info_list[SLOT];
	for (unit = 1; unit <= mct_system_info.max_units[SLOT]; ++unit) {
		if (IS_SCB_P15) {
			slotnum = tonga_psl_to_ssl(scsb, unit);
		} else {
			slotnum = unit;
		}
		code = FRU_UNIT_TO_EVCODE(SLOT, slotnum);
		offset = FRU_OFFSET(code, SCTRL_RESET_BASE);
		reg = FRU_REG_ADDR(code, SCTRL_RESET_BASE);
		index = SCSB_REG_INDEX(reg);
		if (scsb->scsb_data_reg[index] & (1 << offset)) {
			if (fru_ptr[unit - 1].fru_status == FRU_PRESENT) {
				slots_in_reset[unit - 1] = unit;
				cmn_err(CE_NOTE, BAD_BOARD_MSG,
				    scsb->scsb_instance, unit);
			}
		}
	}
	mutex_exit(&scsb->scsb_mutex);
}

static void
scsb_freeze(scsb_state_t *scsb)
{
	uint32_t	code;
	if (scsb_debug & 0x00020002) {
		cmn_err(CE_WARN, "scsb_freeze: SCB%d possibly removed",
		    scsb->scsb_instance);
	}
	if (scsb->scsb_state & SCSB_FROZEN)
		return;
	scsb->scsb_state |= SCSB_FROZEN;
	scsb->scsb_state &= ~SCSB_SCB_PRESENT;
	(void) scsb_hsc_freeze(scsb->scsb_dev);
	/*
	 * Send the EVENT_SCB since there is evidence that the
	 * System Controller Board has been removed.
	 */
	code = SCTRL_EVENT_SCB;
	if (!(scsb->scsb_state & SCSB_IN_INTR))
		scsb_event_code = code;
	check_fru_info(scsb, code);
	add_event_code(scsb, code);
	(void) scsb_queue_ops(scsb, QPUT_INT32, 1, &code, "scsb_freeze");
}

/*
 * scsb_restore will only be called from the interrupt handler context on
 * INIT_SCB interrupt for newly inserted SCB.
 * Called with mutex held.
 */
static void
scsb_restore(scsb_state_t *scsb)
{
	if (scsb_debug & 0x20001)
		cmn_err(CE_NOTE, "scsb_restore(%d):", scsb->scsb_instance);

	if (initialize_scb(scsb) != DDI_SUCCESS) {
		if (scsb_debug & 0x00020002) {
			cmn_err(CE_WARN, "scsb_restore: INIT Failed");
		return;
		}
	}
	/* 9. Clear all Interrupts */
	if (scsb_clear_intmasks(scsb)) {
		cmn_err(CE_WARN,
		    "scsb%d: I2C TRANSFER Failed", scsb->scsb_instance);
		if (scsb_debug & 0x00020002) {
			cmn_err(CE_WARN, "scsb_restore: clear_intmasks Failed");
		}
		return;
	}

	/* 10. */
	/* Check if Alarm Card present at boot and set flags */
	if (scsb_fru_op(scsb, ALARM, 1, SCTRL_SYSCFG_BASE,
	    SCSB_FRU_OP_GET_BITVAL))
		scsb->scsb_hsc_state |= SCSB_ALARM_CARD_PRES;
	else
		scsb->scsb_hsc_state &= ~SCSB_ALARM_CARD_PRES;

	scsb->scsb_state &= ~SCSB_FROZEN;
	(void) scsb_hsc_restore(scsb->scsb_dev);
}

/*
 * Given an Event Code,
 * Return:
 *	FRU type    in LSByte
 *	unit number in MSByte
 */
uint16_t
event_to_type(uint32_t evcode)
{
	int		i, li, unit;
	uint32_t	ec;
	uint16_t	ret;
	for (i = li = 0; i < SCSB_UNIT_TYPES; ++i) {
		if (evcode == type_to_code1[i]) {
			ret = (uint16_t)(0x0100 | i);
			return (ret);
		}
		if (evcode < type_to_code1[i]) {
			unit = 1;
			ec = type_to_code1[li];
			while (ec < evcode)
				ec = ec << 1, ++unit;
			ret = (unit << 8) | li;
			return (ret);
		}
		li = i;
	}
	return ((uint16_t)0xffff);
}

/*
 * scsb interrupt handler for (MC) PSM_INT vector
 * P0.6: HW shipped to beta customers
 *	1. did not have Slot Occupant Presense support
 *	2. I2C interrupt-map properties not yet tested, using polling daemon
 *	3. Polling detects each event reliably twice.
 *	   clr_bits# are used to keep track of events to be ignored 2nd time
 *
 * retval flags allow all events to be checked, and still returning the
 * correct DDI value.
 *
 */
#define	SCSB_INTR_CLAIMED	1
#define	SCSB_INTR_UNCLAIMED	2
#define	SCSB_INTR_EVENT		4

/*
 * Does preprocessing of the interrupt. The only thing this
 * needs to do is to ask scsb to release the interrupt line.
 * and then schedule delayed actual processing using timeout()
 */
uint_t
scsb_intr_preprocess(caddr_t arg)
{
	scsb_state_t	*scsb = (scsb_state_t *)arg;

	scb_pre_s = gethrtime();

	/*
	 * If SCSB_IN_INTR is already set in scsb_state,
	 * it means we are being interrupted by someone else. This can
	 * happen only if the interrupt does not belong to scsb, and some
	 * other device, e.g. a FAN or PS is interrupting. So, we
	 * cancel the previous timeout().
	 */

	if (scsb->scsb_state & SCSB_IN_INTR) {
		(void) untimeout(scsb_intr_tid);
		(void) scsb_invoke_intr_chain();
		(void) scsb_toggle_psmint(scsb, 1);
		scsb->scsb_state &= ~SCSB_IN_INTR;
		goto intr_end;
	}
	scsb->scsb_state |= SCSB_IN_INTR;

	/*
	 * Stop scsb from interrupting first.
	 */
	if (scsb_quiesce_psmint(scsb) != DDI_SUCCESS) {
		goto intr_end;
	}

	/*
	 * Schedule a timeout to actually process the
	 * interrupt.
	 */
	scsb_intr_tid = timeout((void (*)(void *))scsb_intr, arg,
	    drv_usectohz(1000));

intr_end:

	scb_pre_e = gethrtime();
	return (DDI_INTR_CLAIMED);
}

static void scsb_healthy_intr(scsb_state_t *scsb, int pslotnum);
void
scsb_intr(caddr_t arg)
{
	scsb_state_t	*scsb = (scsb_state_t *)arg;
	int		i, idx, offset, unit, numregs, error;
	int		intr_idx, index, offset_base, retval, slotnum, val;
	uint32_t	code;
	uchar_t		intr_reg, tmp_reg, intr_addr, clr_bits = 0;
	uchar_t		ac_slot = B_FALSE;
	uchar_t		*int_masks;
	uchar_t		cstatus_regs[SCTRL_MAX_GROUP_NUMREGS];
	scsb_utype_t	fru_type;
	fru_info_t	*fru_ptr;
	int		ac_present;

	/*
	 * Avoid mayhem, make sure we have only one timeout thread running.
	 */
	mutex_enter(&scsb->scsb_mutex);
	while (scsb_in_postintr)
		cv_wait(&scsb->scsb_cv, &scsb->scsb_mutex);
	scsb_in_postintr = 1;
	mutex_exit(&scsb->scsb_mutex);

	scb_post_s = gethrtime();
	if (scsb_debug & 0x00002000)
		cmn_err(CE_NOTE, "scsb_intr(%d)", scsb->scsb_instance);
	retval = 0;
	tmp_reg = 0;
	/*
	 * XXX: Problem, when we want to support swapping between SCB
	 * versions, then we need to check the SCB PROM ID (CF) register here
	 * before assuming the same SCB version was re-inserted.
	 * We will have to duplicate some of the scb_initialization()
	 * code to set the scsb_state PROM ID bits and to set up the
	 * register table pointers.
	 *
	 * Only if NOT SSB_PRESENT, check the SCB PROM ID
	 */
	if (!(scsb->scsb_state & SCSB_SSB_PRESENT)) {
		if (scb_check_version(scsb) != DDI_SUCCESS) {
#ifdef DEBUG
			if (scsb->scsb_state & SCSB_SSB_PRESENT &&
			    scsb->scsb_i2c_errcnt > scsb_err_threshold)
				scsb_failing_event(scsb);
#endif
			goto intr_error;
		}
	}
	if (IS_SCB_P15) {
		int_masks = scb_15_int_masks;
	} else {
		int_masks = scb_10_int_masks;
	}
	/*
	 * Now check the INTSRC registers for set bits.
	 * Do a quick check by OR'ing INTSRC registers together as we copy
	 * them from the transfer buffer. For P1.0 or earlier we had already
	 * read the interrupt source registers and wrote them back to stop
	 * interrupt. So we need to do this step only for P1.5 or later.
	 * We already read INTSRC6 to take care of SCB insertion case, so
	 * do not read INTSRC6 again.
	 */

	if (IS_SCB_P15) {
		intr_addr = SCSB_REG_ADDR(SCTRL_INTSRC_BASE);
		/* read the interrupt register from scsb */
		if (scsb_rdwr_register(scsb, I2C_WR_RD, intr_addr,
		    SCTRL_INTR_NUMREGS - 1, scb_intr_regs, 1)) {
			cmn_err(CE_WARN, "scsb_intr: "
			    " Failed read of interrupt registers.");
#ifdef DEBUG
			if (scsb->scsb_state & SCSB_SSB_PRESENT &&
			    scsb->scsb_i2c_errcnt > scsb_err_threshold)
				scsb_failing_event(scsb);
#endif
			goto intr_error;
		}
	}

	/*
	 * We have seen that an interrupt source bit can be set
	 * even though the corresponding interrupt mask bit
	 * has been set to mask the interrupt. So we must
	 * clear all bits set in the interrupt source register.
	 */
	for (i = 0; i < SCTRL_INTR_NUMREGS; ++i) {
		retval |= scb_intr_regs[i];		/* Quick INTSRC check */
#ifdef DEBUG
		if (scsb_debug & 0x08000000) {
			if (tmp_reg || scb_intr_regs[i]) {
				cmn_err(CE_NOTE, "scsb_intr: INTSRC%d=0x%x",
				    i + 1, scb_intr_regs[i]);
				++tmp_reg;
			}
		}
#endif
	}
	/*
	 * Any bits from quick check? If this is not our interrupt,
	 * something is wrong. FAN/PS interrupts are supposed to be
	 * blocked, but we can not be sure. So, go ahead and call the
	 * emergency interrupt handlers for FAN/PS devices and mask
	 * their interrupts, if they aren't already masked.
	 */
	if (retval == 0) {
		goto intr_error;
	}

	retval = 0;

	/*
	 * If SCB 1.5 or 2.0, check for the INIT_SCB Interrupt
	 * to support Hot SCB Insertion.
	 * The check was moved here during debugging of the SCB hot insertion.
	 * Theoretically, this code could be moved back to the check for
	 * SCTRL_EVENT_SCB in the processing loop below.
	 */
	if (IS_SCB_P15) {
		int	iid;
		iid = SCSB_REG_INDEX(intr_addr);
		offset = FRU_OFFSET(SCTRL_EVENT_SCB, SCTRL_INTPTR_BASE);
		tmp_reg = SCSB_REG_ADDR(SCTRL_INTSRC_SCB_P15);
		intr_idx = SCSB_REG_INDEX(tmp_reg) - iid;
		clr_bits = 1 << offset;
		if (scb_intr_regs[intr_idx] & clr_bits) {
			/*
			 * Must be newly inserted SCB
			 * Time to re-initialize.
			 */
			if (scsb_debug & 0x00023000) {
				cmn_err(CE_NOTE,
				    "scsb_intr(%d): INIT_SCB INT",
				    scsb->scsb_instance);
			}
			scsb_restore(scsb);
			retval |= (SCSB_INTR_CLAIMED | SCSB_INTR_EVENT);
			/*
			 * The INTSRC bit will be cleared by the
			 * scsb_restore() function.
			 * Also, leave the bit set in scb_intr_regs[] so we can
			 * report the event code as we check for other
			 * interrupt source bits.
			 *
			 * scsb_write_mask(scsb, tmp_reg, 0, clr_bits, 0);
			 * scb_intr_regs[intr_idx] &= ~clr_bits;
			 */
		}
		/*
		 * In case this is a power down interrupt, check the validity
		 * of the request to make sure it's not an I2C noise
		 */
		offset = FRU_OFFSET(SCTRL_EVENT_PWRDWN,
		    SCTRL_INTPTR_BASE);
		clr_bits = 1 << offset;
		intr_reg = scb_intr_regs[intr_idx];
		if (intr_reg & clr_bits) {
			/*
			 * A shutdown request has been detected. Poll
			 * the corresponding register ? more times to
			 * make sure it's a genuine shutdown request.
			 */
			for (i = 0; i < scsb_shutdown_count; i++) {
				drv_usecwait(1000);
				if (scsb_rdwr_register(scsb, I2C_WR_RD, tmp_reg,
				    1, &intr_reg, 1)) {
					cmn_err(CE_WARN, "Failed to read "
					    " interrupt register");
					goto intr_error;
				}
				if (scsb_debug & 0x08000000) {
					cmn_err(CE_NOTE, "scsb_intr: "
					    " INTSRC6[%d]=0x%x", i,
					    intr_reg);
				}
				if (!(intr_reg & clr_bits)) {
					scb_intr_regs[intr_idx] &= ~clr_bits;
					break;
				}
			}
		}
	}
	/*
	 * if retval == 0, then we didn't call scsb_restore,
	 * so we update the shadow copy of SYSCFG registers
	 * We *MUST* read the syscfg registers before any attempt
	 * to clear the interrupt source registers is made.
	 */
	if (retval == 0 && scsb_check_config_status(scsb)) {
		cmn_err(CE_WARN,
		    "scsb_intr: Failed read of config/status registers");
		if (scsb->scsb_state & SCSB_P06_NOINT_KLUGE) {
			if (!scsb_debug) {
				goto intr_error;
			}
		}
#ifdef DEBUG
		if (scsb->scsb_state & SCSB_SSB_PRESENT &&
		    scsb->scsb_i2c_errcnt > scsb_err_threshold) {
			scsb_failing_event(scsb);
		}
#endif
		/*
		 * Allow to go on so we clear the INTSRC bits
		 */
	}

	/*
	 * Read the board healthy registers here, if any of the healthy
	 * interrupts are set.
	 */
	if (IS_SCB_P15) {
		intr_idx = intr_reg = 0;
		intr_addr = SCSB_REG_ADDR(SCTRL_INTSRC_BASE);
		index = SCSB_REG_INDEX(intr_addr);
		for (i = 0; i < SCTRL_BHLTHY_NUMREGS; ++i, ++intr_idx) {
			scsb->scsb_data_reg[index++] =
			    scb_intr_regs[intr_idx] & int_masks[intr_idx];
			intr_reg |= scb_intr_regs[i];
		}

		if (intr_reg &&	scsb_read_bhealthy(scsb) != 0) {
			cmn_err(CE_WARN, "%s#%d: Error Reading Healthy# "
			    " Registers", ddi_driver_name(scsb->scsb_dev),
			    ddi_get_instance(scsb->scsb_dev));
#ifdef DEBUG
			if (scsb->scsb_state & SCSB_SSB_PRESENT &&
			    scsb->scsb_i2c_errcnt > scsb_err_threshold) {
				scsb_failing_event(scsb);
			}
#endif
			goto intr_error;
		}
	}

	/*
	 * We clear the interrupt source registers now itself so that
	 * future interrupts can be latched quickly, instead of after
	 * finishing processing of all interrupt conditions. The global
	 * interrupt mask however remain disabled.
	 */
	if (IS_SCB_P15) {
		if (scsb_rdwr_register(scsb, I2C_WR, intr_addr,
		    SCTRL_INTR_NUMREGS, scb_intr_regs, 1)) {
			cmn_err(CE_WARN, "scsb_intr: Failed write to interrupt"
			    " registers.");
#ifdef DEBUG
			if (scsb->scsb_state & SCSB_SSB_PRESENT &&
			    scsb->scsb_i2c_errcnt > scsb_err_threshold) {
				scsb_failing_event(scsb);
			}
#endif
			goto intr_error;
		}
	}

	/*
	 * At this point, all interrupt source registers are read.
	 * We only handle interrups which are not masked
	 */
	for (i = 0; i < SCTRL_INTR_NUMREGS; ++i) {
		scb_intr_regs[i] &= int_masks[i];
	}

	/*
	 * We are here means that there was some bit set in the interrupt
	 * source register. So we must claim the interrupt no matter
	 * whatever error we may encounter in the course of processing.
	 */
	retval |= SCSB_INTR_CLAIMED;

	/* store config status data */
	tmp_reg = SCSB_REG_ADDR(SCTRL_SYSCFG_BASE);
	index = SCSB_REG_INDEX(tmp_reg);
	for (i = 0; i < SCTRL_CFG_NUMREGS; ++i)
		cstatus_regs[i] = scsb->scsb_data_reg[index + i];
	/*
	 * Clear the event code,
	 * then check to see what kind(s) of events we were interrupted for.
	 * Check all SCTRL_INTSRC registers
	 */
	scsb_event_code = 0;
	clr_bits = 0;
	intr_idx = 0;
	numregs = SCTRL_INTR_NUMREGS;
	index = SCSB_REG_INDEX(intr_addr);
	/*
	 * If SCB 1.5, adjust some variables to skip the SCTRL_BHLTHY_REGS
	 * which will be handled last in this function.
	 */
	if (IS_SCB_P15) {
		i = SCTRL_BHLTHY_NUMREGS;
		intr_idx += i;
		intr_addr += i;
		index += i;
	}
	/*
	 * For the rest of the INTSRC registers, we walk through the
	 * scb_fru_offset[] table, matching register offsets with our offset
	 * counter.  Then we check for the scb_fru_offset[] bit in intr_reg.
	 * The scb_fru_offset[] index is now the SCTRL_EVENT code.
	 * The code is then compared to type_to_code1[] entries to find the
	 * fru_type.  The fru_type will help us recognize when to do
	 * SLOT Hot Swap processing.
	 *
	 * offset_base:		the appropriate scb_fru_offset[] base index
	 *			for the INTPTR_BASE register group
	 * offset:		bit offset found in INTSRC register
	 * intr_idx:		index to temporary INTSRC register copies
	 * intr:		modified copy of current INTR register
	 * intr_addr:		SCB register address of current INTR register
	 * index:		index to current INTR shadow register
	 * idx:			bit-number of current INTR event bit
	 * uc:			uchar_t from scb_fru_offset[] table,
	 *			containing register and FRU offsets.
	 * j:			used to walk fru_offset[] table, which is also
	 *			the bit-number of the current event code
	 * code:		manufactured event code for current INT event
	 */
	offset_base = FRU_OFFSET_BASE(SCTRL_INTPTR_BASE);
	for (offset = 0; intr_idx < numregs;
	    ++offset, ++intr_idx, ++intr_addr, ++index) {
		scsb->scsb_data_reg[index] = scb_intr_regs[intr_idx];
		intr_reg = scb_intr_regs[intr_idx];
		while (intr_reg) {	/* for each INTSRC bit that's set */
			int		j;
			uint16_t	ui;
			uchar_t		uc;
			idx = event_to_index((uint32_t)intr_reg); /* offset */
			code = (1 << idx);		/* back to bit mask */
			clr_bits |= code;
			intr_reg = intr_reg & ~code;	/* clear this one   */
			for (j = 0; j < MCT_MAX_FRUS; ++j) {
				/*
				 * Get register offset from table and check
				 * for a match with our loop offset counter.
				 * Then check for intr_reg bit-offset match
				 * with bit-offset from table entry.
				 */
				uc = scb_fru_offset[offset_base + j];
				if (offset != ((uc >> 4) & 0xf)) {
					if (IS_SCB_P10)
						continue;
					if (j != FRU_INDEX(SCTRL_EVENT_SCB))
						continue;
					if (offset != ((uc >> 4) & 0xf)
					    + SCB_INT_OFFSET)
						continue;
				}
				if (idx == (uc & 0xf))
					break;
			}
			if (uc == 0xff) {
				/*
				 * bit idx not recognized, check another.
				 */
				continue;
			}
			/*
			 * We found the fru_offset[] entry, now use the index
			 * to get the event code.
			 */
			code = (uint32_t)(1 << j);
			if (scsb_debug & 0x00002000) {
				cmn_err(CE_NOTE, "scsb_intr: code=0x%x", code);
			}
			/*
			 * Now check for the NON-FRU type events.
			 */
			if (code ==  SCTRL_EVENT_PWRDWN) {
				if (scsb_debug & 0x1002) {
					cmn_err(CE_NOTE,
					    "scsb_intr(%d): power down req."
					    " INT.", scsb->scsb_instance);
				}
				scsb_event_code |= code;
				if (scsb->scsb_state & SCSB_OPEN &&
				    scsb->scsb_rq != (queue_t *)NULL) {
					/*
					 * inform applications using poll(2)
					 * about this event, and provide the
					 * event code to EnvMon scsb policy
					 */
					if (!(scsb_debug & 0x00040000))
					(void) scsb_queue_put(scsb->scsb_rq, 1,
					    &scsb_event_code, "scsb_intr");
					goto intr_error;
				}
				continue;
			} else if (code == SCTRL_EVENT_REPLACE) {
				if (scsb_debug & 0x1002) {
					cmn_err(CE_NOTE,
					    "scsb_intr(%d): replacement "
					    "req. INT.",
					    scsb->scsb_instance);
				}
				scsb_freeze_check(scsb);
				scsb_freeze(scsb);
				scsb_event_code |= code;
				retval |= (SCSB_INTR_CLAIMED | SCSB_INTR_EVENT);
				continue;
			} else if (code == SCTRL_EVENT_SCB) {
				int	tmp;
				/*
				 * Must be newly inserted SCB
				 * Time to re-initialize.
				 */
				if (scsb_debug & 0x1002) {
					cmn_err(CE_NOTE,
					    "scsb_intr(%d): INIT SCB INTR",
					    scsb->scsb_instance);
				}
				/*
				 * SCB initialization already handled, but we
				 * set the event code bit here in order to
				 * report the event to interested utilities.
				 *
				 * scsb_restore(scsb);
				 * The INTSRC bit is already cleared,
				 * so we won't do it again.
				 */
				tmp = FRU_OFFSET(SCTRL_EVENT_SCB,
				    SCTRL_INTPTR_BASE);
				clr_bits &= ~(1 << tmp);
				scsb_event_code |= code;
				retval |= (SCSB_INTR_CLAIMED | SCSB_INTR_EVENT);
				continue;
			} else if (code == SCTRL_EVENT_ALARM_INT) {
				/*
				 * P0.6/P1.0: SCTRL_INTR_ALARM_INT is always
				 * set and cannot be cleared, so ignore it.
				 */
				if (!IS_SCB_P15) {
					continue;
				}
				if (scsb_debug & 0x1002) {
					cmn_err(CE_NOTE,
					    "scsb_intr(%d): Alarm INT.",
					    scsb->scsb_instance);
				}
				scsb_event_code |= code;
				retval |= (SCSB_INTR_CLAIMED | SCSB_INTR_EVENT);
				/*
				 * XXX:
				 * Must service the Alarm INT by clearing INT
				 * condition on Alarm Card,
				 * then clear the SCTRL_INTR_ALARM_INT bit here.
				 * Waiting for specs and test environment.
				 */
				continue;
			} else if ((ui = event_to_type(code)) == 0xffff) {
				/*
				 * FRU type not found
				 */
				break;
			}
			/*
			 * Check for special processing
			 * now that we found the FRU type.
			 */
			fru_type = (scsb_utype_t)(ui & 0xff);
			unit = (ui >> 8) & 0xff;
			if (scsb_debug & 0x00002000) {
				cmn_err(CE_NOTE, "scsb_intr: "
				    "FRU type/unit/code %d/%d/0x%x",
				    fru_type, unit, code);
			}
			switch (fru_type) {
			case PDU:
				break;
			case PS:
				break;
			case DISK:
				break;
			case FAN:
				break;
			case SSB:
				/*
				 * in check_fru_info() below, we see if the
				 * SSB has been removed, then check for
				 * occupied slots in reset to see if we should
				 * WARN agains SCB removal
				 */
				break;
			case CFTM:
				break;
			case CRTM:
				break;
			case PRTM:
				break;
			case SLOT:
				slotnum = tonga_ssl_to_psl(scsb, unit);
				if (scsb_debug & 0x00002000) {
					cmn_err(CE_NOTE, "scsb_intr: "
					    "unit/slot %d/%d",
					    unit, slotnum);
				}

				/*
				 * If the slot number is not valid, continue.
				 */
				if (scsb->scsb_state & SCSB_IS_TONGA) {
					if (slotnum > TG_MAX_SLOTS ||
					    slotnum == SC_TG_CPU_SLOT) {
						continue;
					}
					/*
					 * For a tonga, we need to return
					 * the code corresponding to the
					 * actual physical slot
					 */
					code = FRU_UNIT_TO_EVCODE(SLOT,
					    slotnum);
				} else {
					if (slotnum > MC_MAX_SLOTS ||
					    slotnum == SC_MC_CPU_SLOT ||
					    (scsb->scsb_hsc_state &
					    SCSB_HSC_CTC_PRES &&
					    slotnum == SC_MC_CTC_SLOT)) {
						continue;
					}
				}
			/* FALLTHROUGH */
			case ALARM:
		/*
		 * INDENT CHEATING, 2 indentations
		 */
		ac_present = 0;
		/*
		 * If it is an Alarm Card Interrupt, we just do some sanity
		 * checks and then wait for the slot interrupt to take
		 * connect or disconnect action.
		 * XXX - Is there a gaurantee that ALARM int will occur first ?
		 */
		if (fru_type == ALARM) {
			DEBUG2("AC Intr %d(%d)\n", scsb->ac_slotnum, idx+1);
			val = scsb_fru_op(scsb, SLOT,
			    tonga_ssl_to_psl(scsb, scsb->ac_slotnum),
			    SCTRL_SYSCFG_BASE, SCSB_FRU_OP_GET_BITVAL);
			ac_present = scsb_fru_op(scsb, ALARM, 1,
			    SCTRL_SYSCFG_BASE,
			    SCSB_FRU_OP_GET_BITVAL);
			/*
			 * It is observed that slot presence and Alarm
			 * presence bits do not go ON at the same time.
			 * Hence we wait till both events happen.
			 */
#ifdef DEBUG
			if ((((val) && (!ac_present)) ||
			    ((!val) && (ac_present))) &&
			    (scsb->scsb_hsc_state &
			    SCSB_AC_SLOT_INTR_DONE))

				cmn_err(CE_WARN, "?Alarm and Slot presence "
				    "state bits do not match! (%x,%x)",
				    val, ac_present);
#endif
			if (scsb->scsb_hsc_state & SCSB_AC_SLOT_INTR_DONE)
				scsb->scsb_hsc_state &= ~SCSB_AC_SLOT_INTR_DONE;
			else
				scsb->scsb_hsc_state |= SCSB_AC_SLOT_INTR_DONE;
			break;	/* we break and wait for slot interrupt. */
		}

		/*
		 * cPCI slot interrupt event
		 */
		if (scsb->scsb_state & SCSB_IS_TONGA) {
			if (slotnum > TG_MAX_SLOTS ||
			    slotnum == SC_TG_CPU_SLOT) {
				continue;
			}
		} else {
			if (slotnum > MC_MAX_SLOTS ||
			    slotnum == SC_MC_CPU_SLOT ||
			    (scsb->scsb_hsc_state & SCSB_HSC_CTC_PRES &&
			    slotnum == SC_MC_CTC_SLOT)) {
				continue;
			}
		}
		if (scsb_is_alarm_card_slot(scsb, slotnum) == B_TRUE) {
			DEBUG2("AC slot Intr %d(%d)\n", slotnum, idx+1);
			ac_slot = B_TRUE;
		}
		val = scsb_fru_op(scsb, SLOT, unit, SCTRL_SYSCFG_BASE,
		    SCSB_FRU_OP_GET_BITVAL);
		if (ac_slot == B_TRUE) {
			ac_present = scsb_fru_op(scsb, ALARM, 1,
			    SCTRL_SYSCFG_BASE,
			    SCSB_FRU_OP_GET_BITVAL);
#ifdef DEBUG
			if ((((val) && (!ac_present)) ||
			    ((!val) && (ac_present))) &&
			    (scsb->scsb_hsc_state &
			    SCSB_AC_SLOT_INTR_DONE)) {

				cmn_err(CE_WARN, "?Alarm and Slot presence "
				    "state bits do not match! (%x,%x)",
				    val, ac_present);
			}
#endif
			if (scsb->scsb_hsc_state & SCSB_AC_SLOT_INTR_DONE)
				scsb->scsb_hsc_state &= ~SCSB_AC_SLOT_INTR_DONE;
			else
				scsb->scsb_hsc_state |= SCSB_AC_SLOT_INTR_DONE;
		}
		if (val) {
			if (ac_present) {
				DEBUG1("AC insertion on slot %d!\n", slotnum);
				if (scsb_debug & 0x00010000) {
					cmn_err(CE_NOTE, "scsb_intr: "
					"AC_PRES slot %d", slotnum);
				}
				scsb->scsb_hsc_state |= SCSB_ALARM_CARD_PRES;
			}
#ifndef	lint
			else
				DEBUG1("IO Insertion on slot %d!\n", slotnum);
#endif
			/*
			 * Special case : check MPID type.
			 * If MC midplane type,
			 * check to make sure the Alarm Card present
			 * bit is ON. If not, this is a regular IO card.
			 */
			(void) scsb_connect_slot(scsb, slotnum, B_FALSE);
		} else {
			if ((ac_slot == B_TRUE) &&
			    (scsb->scsb_hsc_state & SCSB_ALARM_CARD_PRES)) {

				DEBUG1("AC Removal on slot %d!\n", slotnum);
#ifdef DEBUG
				if (scsb_debug & 0x00010000) {
					cmn_err(CE_NOTE, "scsb_intr: "
					    "!AC_PRES slot %d",
					    slotnum);
				}
#endif /* DEBUG */
				scsb->scsb_hsc_state &= ~SCSB_ALARM_CARD_PRES;
			}
#ifndef	lint
			else
				DEBUG1("IO Removal on slot %d!\n", slotnum);
#endif
			(void) scsb_disconnect_slot(scsb, B_FALSE, slotnum);
		}
		/*
		 * END INDENT CHEATING, 2 indentations
		 */

				break;
			default:
				/*
				 * ERROR: Did not find cause of INTSRC bit
				 */
				if (scsb_debug & 0x00000002) {
					cmn_err(CE_WARN,
					    "scsb_intr: FRU type %d"
					    " not recognized", fru_type);
				}
				continue;
			}
			scsb_event_code |= code;
			retval |= (SCSB_INTR_CLAIMED | SCSB_INTR_EVENT);
			if (fru_type == SLOT)
				continue;
			error = 0;
			fru_ptr = mct_system_info.fru_info_list[fru_type];
			for (; fru_ptr != NULL; fru_ptr = fru_ptr->next) {
				if (unit != fru_ptr->fru_unit)
					continue;
				if (fru_ptr->i2c_info == NULL ||
				    (tmp_reg = fru_ptr->i2c_info->
				    ledata_reg) == 0)
					continue;
				error = scsb_set_scfg_pres_leds(scsb, fru_ptr);
				if (error) {
					cmn_err(CE_WARN, "scsb_intr(): "
					    "I2C write error to 0x%x",
					    tmp_reg);
					if (!(scsb->scsb_state &
					    SCSB_DEBUG_MODE)) {
						goto intr_error;
					}
				}
				break;
			}
		}
		if (clr_bits) {
			clr_bits = 0;
		}
	}
	/*
	 * Check for SCB 1.5 interrupt for SLOT HEALTHY changes
	 */
	clr_bits = 0;
	intr_idx = 0;
	numregs = SCTRL_INTR_NUMREGS;
	intr_addr = SCSB_REG_ADDR(SCTRL_INTSRC_BASE);
	index = SCSB_REG_INDEX(intr_addr);
	if (IS_SCB_P15) {
		for (i = 0; i < SCTRL_BHLTHY_NUMREGS;
		    ++i, ++intr_idx, ++intr_addr) {
			scsb->scsb_data_reg[index++] = scb_intr_regs[intr_idx];
			intr_reg = scb_intr_regs[i];
			while (intr_reg) {
				idx = event_to_index((uint32_t)intr_reg);
				code = (1 << idx);
				clr_bits |= code;
				intr_reg = intr_reg & ~code;
				/* idx + 1 because bit 0 is for Slot 1 */
				slotnum = tonga_ssl_to_psl(scsb, idx + 1);
				if (scsb->scsb_state & SCSB_IS_TONGA) {
					if (slotnum > TG_MAX_SLOTS ||
					    slotnum == SC_TG_CPU_SLOT) {
						continue;
					}
				} else {
					if (slotnum > MC_MAX_SLOTS ||
					    slotnum == SC_MC_CPU_SLOT ||
					    (scsb->scsb_hsc_state &
					    SCSB_HSC_CTC_PRES &&
					    slotnum == SC_MC_CTC_SLOT)) {
						continue;
					}
				}
				scsb_healthy_intr(scsb, slotnum);
			}
			if (clr_bits) {
				clr_bits = 0;
			}
		}
	}
	code = scsb_event_code;
	if (retval & SCSB_INTR_EVENT &&
	    !(scsb->scsb_state & SCSB_P06_NOINT_KLUGE)) {
		check_fru_info(scsb, code);
		add_event_code(scsb, code);
		(void) scsb_queue_ops(scsb, QPUT_INT32, 1, &scsb_event_code,
		"scsb_intr");
	}
intr_error:
	scb_post_e = gethrtime();

	if (scsb_debug & 0x8000000)
		cmn_err(CE_NOTE, "Summary of times in nsec: pre_time %llu, \
			post_time %llu", scb_pre_e - scb_pre_s,
		    scb_post_e - scb_post_s);


	mutex_enter(&scsb->scsb_mutex);
	scsb_in_postintr = 0;
	cv_broadcast(&scsb->scsb_cv);
	mutex_exit(&scsb->scsb_mutex);

	/*
	 * Re-enable interrupt now.
	 */
	(void) scsb_toggle_psmint(scsb, 1);
	scsb->scsb_state &= ~SCSB_IN_INTR;
}

static int
scsb_polled_int(scsb_state_t *scsb, int cmd, uint32_t *set)
{
	if (scsb_debug & 0x4000)
		cmn_err(CE_NOTE, "scsb_polled_int(scsb,0x%x)", cmd);
	*set = 0;
	if (cmd == SCSBIOC_SHUTDOWN_POLL) {
		return (EINVAL);
	}
	if (cmd != SCSBIOC_INTEVENT_POLL) {
		return (EINVAL);
	}
	if (scsb->scsb_state & SCSB_P06_NOINT_KLUGE) {
		/*
		 * scsb_intr() may modify scsb_event_code
		 */
		scsb_event_code = SCTRL_EVENT_NONE;
		(void) scsb_intr((caddr_t)scsb);
		*set = scsb_event_code;
		scsb_event_code = 0;
	} else {
		/*
		 * SCSB_P06_INTR_ON, we know there was an event
		 * and we're retrieving the event code from the event FIFO.
		 */
		*set = get_event_code();
	}
	if (scsb_debug & 0x01004000) {
		cmn_err(CE_NOTE, "scsb_polled_int: event_code = 0x%x", *set);
	}
	return (0);
}

static int
scsb_leds_switch(scsb_state_t *scsb, scsb_ustate_t op)
{
	register int 	i;
	int		index;
	uchar_t		reg, idata, rwbuf[SCTRL_MAX_GROUP_NUMREGS];

	if (scsb->scsb_state & SCSB_FROZEN &&
	    !(scsb->scsb_state & SCSB_IN_INTR)) {
		return (EAGAIN);
	}
	if (scsb_debug & 0x0101) {
		cmn_err(CE_NOTE, "scsb_leds_switch(%s):",
		    op == ON ? "ON" : "OFF");
	}
	/* Step 1: turn ON/OFF all NOK LEDs. */
	if (scsb_debug & 0x0100) {
		cmn_err(CE_NOTE, "scsb%d: turning all NOK LEDs %s",
		    scsb->scsb_instance,
		    op == ON ? "ON" : "OFF");
	}
	if (op == ON)
		idata = 0xff;
	else	/* off */
		idata = 0x00;
	reg = SCSB_REG_ADDR(SCTRL_LED_NOK_BASE);
	index = SCSB_REG_INDEX(reg);
	for (i = 0; i < SCTRL_LED_NOK_NUMREGS;  ++i) {
		rwbuf[i] = idata;
		scsb->scsb_data_reg[index + i] = idata;
	}
	mutex_enter(&scsb->scsb_mutex);
	i = scsb_rdwr_register(scsb, I2C_WR, reg, SCTRL_LED_NOK_NUMREGS,
	    rwbuf, 1);
	mutex_exit(&scsb->scsb_mutex);
	if (i) {
		if (scsb_debug & 0x0102)
			cmn_err(CE_WARN, "scsb_leds_switch(): "
			    "Failed to turn %s NOK LEDs",
			    op == ON ? "ON" : "OFF");
	}
	/* Step 2: turn ON/OFF all OK LEDs. */
	if (scsb_debug & 0x0100) {
		cmn_err(CE_NOTE, "scsb%d: turning all OK LEDs %s",
		    scsb->scsb_instance,
		    op == ON ? "ON" : "OFF");
	}
	reg = SCSB_REG_ADDR(SCTRL_LED_OK_BASE);
	index = SCSB_REG_INDEX(reg);
	for (i = 0; i < SCTRL_LED_OK_NUMREGS;  ++i) {
		rwbuf[i] = idata;
		scsb->scsb_data_reg[index + i] = idata;
	}
	mutex_enter(&scsb->scsb_mutex);
	i = scsb_rdwr_register(scsb, I2C_WR, reg, SCTRL_LED_OK_NUMREGS,
	    rwbuf, 1);
	mutex_exit(&scsb->scsb_mutex);
	if (i) {
		if (scsb_debug & 0x0102)
			cmn_err(CE_WARN, "scsb_leds_switch(): "
			    "Failed to turn %s NOK LEDs",
			    op == ON ? "ON" : "OFF");
	}
	/* Step 3: turn OFF all BLINK LEDs. */
	if (op == OFF) {
		reg = SCSB_REG_ADDR(SCTRL_BLINK_OK_BASE);
		index = SCSB_REG_INDEX(reg);
		for (i = 0; i < SCTRL_BLINK_NUMREGS;  ++i) {
			rwbuf[i] = idata;
			scsb->scsb_data_reg[index + i] = idata;
		}
		mutex_enter(&scsb->scsb_mutex);
		i = scsb_rdwr_register(scsb, I2C_WR, reg, SCTRL_BLINK_NUMREGS,
		    rwbuf, 1);
		mutex_exit(&scsb->scsb_mutex);
		if (i) {
			if (scsb_debug & 0x0102)
				cmn_err(CE_WARN, "scsb_leds_switch(): "
				    "Failed to turn %s BLINK BITs",
				    op == ON ? "ON" : "OFF");
		}
	}
	return (0);
}

static int
scsb_readall_regs(scsb_state_t *scsb)
{
	int		error;
	int		index;
	uchar_t		reg;

	if (!(scsb_debug & 0x40000000))
		return (0);
	if (scsb_debug & 0x0005) {
		cmn_err(CE_NOTE, "scsb_readall_regs:");
	}
	if (scsb->scsb_state & SCSB_FROZEN) {
		return (EAGAIN);
	}
	reg = SCSB_REG_ADDR_START;	/* 1st register in set */
	index = SCSB_REG_INDEX(reg);
	error = scsb_rdwr_register(scsb, I2C_WR_RD, reg, SCSB_DATA_REGISTERS,
	    &scsb->scsb_data_reg[index], 1);
	return (error);
}


/*
 * read 1-byte register, mask with read bits (rmask),
 * turn ON bits in on_mask, turn OFF bits in off_mask
 * write the byte back to register
 * NOTE: MUST be called with mutex held
 */
static int
scsb_write_mask(scsb_state_t *scsb,
		uchar_t reg,
		uchar_t rmask,
		uchar_t on_mask,
		uchar_t off_mask)
{
	i2c_transfer_t	*i2cxferp;
	int		index, error = 0;
	uchar_t		reg_data;

	if (scsb_debug & 0x0800) {
		cmn_err(CE_NOTE, "scsb_write_mask(,%x,,%x,%x):",
		    reg, on_mask, off_mask);
	}
	if (scsb->scsb_state & SCSB_FROZEN &&
	    !(scsb->scsb_state & SCSB_IN_INTR)) {
		return (EAGAIN);
	}
	/* select the register address and read the register */
	i2cxferp = (i2c_transfer_t *)scsb->scsb_i2ctp;
	i2cxferp->i2c_flags = I2C_WR_RD;
	i2cxferp->i2c_wlen = 1;
	i2cxferp->i2c_rlen = 1;
	i2cxferp->i2c_wbuf[0] = reg;
	i2cxferp->i2c_rbuf[0] = 0;
	scsb->scsb_kstat_flag = B_TRUE;	/* we did a i2c transaction */
	if (error = nct_i2c_transfer(scsb->scsb_phandle, i2cxferp)) {
		error = EIO;
		goto wm_error;
	}
	scsb->scsb_i2c_errcnt = 0;
	if (scsb_debug & 0x0800)
		cmn_err(CE_NOTE, "scsb_write_mask() read 0x%x",
		    i2cxferp->i2c_rbuf[0]);
	reg_data = i2cxferp->i2c_rbuf[0];
	if (rmask)
		reg_data &= rmask;
	if (off_mask)
		reg_data &= ~off_mask;
	if (on_mask)
		reg_data |= on_mask;
	i2cxferp->i2c_flags = I2C_WR;
	i2cxferp->i2c_wlen = 2;
	i2cxferp->i2c_wbuf[0] = reg;
	i2cxferp->i2c_wbuf[1] = reg_data;
	if (error = nct_i2c_transfer(scsb->scsb_phandle, i2cxferp)) {
		error = EIO;
		goto wm_error;
	}
	/* keep shadow registers updated */
	index = SCSB_REG_INDEX(reg);
	scsb->scsb_data_reg[index] = reg_data;
	if (scsb_debug & 0x0800)
		cmn_err(CE_NOTE, "scsb_write_mask() wrote 0x%x", reg_data);
	scsb->scsb_i2c_errcnt = 0;
	return (error);
wm_error:
	scsb->scsb_i2c_errcnt++;
	if (scsb->scsb_i2c_errcnt > scsb_err_threshold)
		scsb->scsb_err_flag = B_TRUE; /* latch error */
	if (scsb->scsb_state & SCSB_SSB_PRESENT) {
		if (scsb_debug & 0x0802)
			cmn_err(CE_WARN,
			    "scsb_write_mask(): reg %x %s error, data=%x",
			    reg,
			    i2cxferp->i2c_flags & I2C_WR ? "write" : "read",
			    i2cxferp->i2c_flags & I2C_WR ?
			    i2cxferp->i2c_wbuf[1] : i2cxferp->i2c_rbuf[0]);
	} else {
		if (scsb->scsb_i2c_errcnt >= scsb_freeze_count)
			scsb_freeze(scsb);
		return (EAGAIN);
	}
	return (error);
}

/*
 * read/write len consecutive single byte registers to/from rbuf
 * NOTE: should be called with mutex held
 */
static int
scsb_rdwr_register(scsb_state_t *scsb, int op, uchar_t reg, int len,
				uchar_t *rwbuf, int i2c_alloc)
{
	i2c_transfer_t	*i2cxferp;
	int		i, rlen, wlen, index, error = 0;

	if (scsb_debug & 0x0800) {
		cmn_err(CE_NOTE, "scsb_rdwr_register(scsb,%s,%x,%x,buf):",
		    (op == I2C_WR) ? "write" : "read",  reg, len);
	}
	if (scsb->scsb_state & SCSB_FROZEN &&
	    !(scsb->scsb_state & SCSB_IN_INTR)) {
		return (EAGAIN);
	}
	if (i2c_alloc) {
		i2cxferp = scsb_alloc_i2ctx(scsb->scsb_phandle, I2C_NOSLEEP);
		if (i2cxferp == NULL) {
			if (scsb_debug & 0x0042)
				cmn_err(CE_WARN, "scsb_rdwr_register: "
				    "i2ctx allocation failure");
			return (ENOMEM);
		}
	} else {
		i2cxferp = scsb->scsb_i2ctp;
	}
	index = SCSB_REG_INDEX(reg);
	switch (op) {
	case I2C_WR:
		wlen = len + 1;	/* add the address */
		rlen = 0;
		i2cxferp->i2c_wbuf[0] = reg;
		for (i = 0; i < len; ++i) {
			scsb->scsb_data_reg[index + i] =
			    i2cxferp->i2c_wbuf[1 + i] = rwbuf[i];
			if (scsb_debug & 0x0080)
				cmn_err(CE_NOTE,
				"scsb_rdwr_register: writing rwbuf[%d]=0x%x",
				    i, rwbuf[i]);
		}
		break;
	case I2C_WR_RD:
		wlen = 1;	/* for the address */
		rlen = len;
		i2cxferp->i2c_wbuf[0] = reg;
		break;
	default:
		if (i2c_alloc)
			scsb_free_i2ctx(scsb->scsb_phandle, i2cxferp);
		return (EINVAL);
	}
	/* select the register address */
	i2cxferp->i2c_flags = op;
	i2cxferp->i2c_rlen = rlen;
	i2cxferp->i2c_wlen = wlen;
	i2cxferp->i2c_wbuf[0] = reg;
	scsb->scsb_kstat_flag = B_TRUE;	/* we did a i2c transaction */
	if (error = nct_i2c_transfer(scsb->scsb_phandle, i2cxferp)) {
		error = EIO;
	} else if (rlen) {
		/* copy to rwbuf[] and keep shadow registers updated */
		for (i = 0; i < len; ++i) {
			scsb->scsb_data_reg[index + i] = rwbuf[i] =
			    i2cxferp->i2c_rbuf[i];
			if (scsb_debug & 0x0080)
				cmn_err(CE_NOTE,
				"scsb_rdwr_register: read rwbuf[%d]=0x%x",
				    i, rwbuf[i]);
		}
	}
	if (i2c_alloc)
		scsb_free_i2ctx(scsb->scsb_phandle, i2cxferp);
	if (error) {
		scsb->scsb_i2c_errcnt++;
		if (scsb->scsb_i2c_errcnt > scsb_err_threshold)
			scsb->scsb_err_flag = B_TRUE; /* latch error */
		if (!(scsb->scsb_state & SCSB_SSB_PRESENT)) {
			if (scsb->scsb_i2c_errcnt >= scsb_freeze_count)
				scsb_freeze(scsb);
			return (EAGAIN);
		} else {
			cmn_err(CE_WARN,
			    "scsb_rdwr_register(): I2C read error from %x",
			    reg);
		}
	} else {
		scsb->scsb_i2c_errcnt = 0;
	}

	return (error);
}

/*
 * Called from scsb_intr()
 * First find the fru_info for this fru_id, and set fru_status for callback.
 * Then check for a registered call_back entry for this fru_id,
 * and if found, call it.
 * Recursize call until no EVENTS left in evcode.
 */
static	void
check_fru_info(scsb_state_t *scsb, int evcode)
{
	struct scsb_cb_entry	*cbe_ptr;
	fru_info_t		*fru_ptr;
	fru_id_t		fru_id;
	scsb_fru_status_t	fru_status;
	int			i, new_evcode;

	if (scsb_debug & 0x00100001)
		cmn_err(CE_NOTE, "check_fru_info(scsb,0x%x)", evcode);
	if (evcode == 0)
		return;
	i = event_to_index((uint32_t)evcode);
	new_evcode = evcode & ~(1 << i);
	if (i > MCT_MAX_FRUS) {
		if (scsb_debug & 0x00100000)
			cmn_err(CE_NOTE,
			    "check_fru_info: index %d out of range", i);
		check_fru_info(scsb, new_evcode);
		return;
	}
	fru_id = fru_id_table[i];
	fru_ptr = find_fru_info(fru_id);
	if (fru_ptr == (fru_info_t *)NULL) {
		check_fru_info(scsb, new_evcode);
		return;
	}
	update_fru_info(scsb, fru_ptr);
	if (fru_ptr->fru_status & FRU_PRESENT) {
		fru_status = FRU_PRESENT;
	} else {
		fru_status = FRU_NOT_PRESENT;
		if (fru_ptr->fru_type == SSB) {
			/*
			 * WARN against SCB removal if any
			 * occupied slots are in reset
			 */
			scsb_freeze_check(scsb);
		}
	}
	/*
	 * check for an entry in the CallBack table
	 */
	for (cbe_ptr = scsb_cb_table; cbe_ptr != NULL;
	    cbe_ptr = cbe_ptr->cb_next) {
		if (cbe_ptr->cb_fru_id == fru_id &&
		    cbe_ptr->cb_fru_ptr == fru_ptr) {
			if (scsb_debug & 0x00800000)
				cmn_err(CE_NOTE,
				    "check_fru_info: callback for FRU_ID "
				    "0x%x; device is %spresent",
				    (int)fru_id,
				    fru_status == FRU_PRESENT ?
				    "" : "not ");
			(*cbe_ptr->cb_func)(
			    cbe_ptr->cb_softstate_ptr,
			    cbe_ptr->cb_event,
			    fru_status);
			break;
		}
	}
	check_fru_info(scsb, new_evcode);
}

/*
 * -----------------------------
 * scsb kstat support functions.
 * -----------------------------
 */
/*
 * Create and initialize the kstat data structures
 */
static int
scsb_alloc_kstats(scsb_state_t *scsb)
{
	kstat_named_t   *kn;
	/*
	 * scsb_ks_leddata_t for "scsb_leddata"
	 */
	if (scsb_debug & 0x00080001)
		cmn_err(CE_NOTE,
		    "scsb_alloc_kstats: create scsb_leddata: %lu bytes",
		    sizeof (scsb_ks_leddata_t));
	if ((scsb->ks_leddata = kstat_create(scsb_name, scsb->scsb_instance,
	    SCSB_KS_LEDDATA, "misc", KSTAT_TYPE_RAW,
	    sizeof (scsb_ks_leddata_t), KSTAT_FLAG_PERSISTENT))
	    == NULL) {
		scsb->scsb_state |= SCSB_KSTATS;
		scsb_free_kstats(scsb);
		return (DDI_FAILURE);
	}
	scsb->ks_leddata->ks_update = update_ks_leddata;
	scsb->ks_leddata->ks_private = (void *)scsb;
	if (update_ks_leddata(scsb->ks_leddata, KSTAT_READ) != DDI_SUCCESS) {
		scsb->scsb_state |= SCSB_KSTATS;
		scsb_free_kstats(scsb);
		return (DDI_FAILURE);
	}
	kstat_install(scsb->ks_leddata);
	/*
	 * scsb_ks_state_t for "scsb_state"
	 */
	if (scsb_debug & 0x00080000)
		cmn_err(CE_NOTE,
		    "scsb_alloc_kstats: create scsb_state: %lu bytes",
		    sizeof (scsb_ks_state_t));
	if ((scsb->ks_state = kstat_create(scsb_name, scsb->scsb_instance,
	    SCSB_KS_STATE, "misc", KSTAT_TYPE_RAW,
	    sizeof (scsb_ks_state_t), KSTAT_FLAG_PERSISTENT))
	    == NULL) {
		scsb->scsb_state |= SCSB_KSTATS;
		scsb_free_kstats(scsb);
		return (DDI_FAILURE);
	}
	scsb->ks_state->ks_update = update_ks_state;
	scsb->ks_state->ks_private = (void *)scsb;
	if (update_ks_state(scsb->ks_state, KSTAT_READ) != DDI_SUCCESS) {
		scsb->scsb_state |= SCSB_KSTATS;
		scsb_free_kstats(scsb);
		return (DDI_FAILURE);
	}
	kstat_install(scsb->ks_state);
	/*
	 * mct_topology_t for "env_topology"
	 */
	if (scsb_debug & 0x00080000)
		cmn_err(CE_NOTE,
		    "scsb_alloc_kstats: create env_toploogy: %lu bytes",
		    sizeof (mct_topology_t));
	if ((scsb->ks_topology = kstat_create(scsb_name, scsb->scsb_instance,
	    SCSB_KS_TOPOLOGY, "misc", KSTAT_TYPE_RAW,
	    sizeof (mct_topology_t), KSTAT_FLAG_PERSISTENT))
	    == NULL) {
		scsb->scsb_state |= SCSB_KSTATS;
		scsb_free_kstats(scsb);
		return (DDI_FAILURE);
	}
	scsb->ks_topology->ks_update = update_ks_topology;
	scsb->ks_topology->ks_private = (void *)scsb;
	if (update_ks_topology(scsb->ks_topology, KSTAT_READ) != DDI_SUCCESS) {
		scsb->scsb_state |= SCSB_KSTATS;
		scsb_free_kstats(scsb);
		return (DDI_FAILURE);
	}
	kstat_install(scsb->ks_topology);
	/*
	 * kstat_named_t * 2 for "scsb_evc_register"
	 */
	if (scsb_debug & 0x00080001)
		cmn_err(CE_NOTE,
		    "scsb_alloc_kstats: create scsb_evc_register: %lu bytes",
		    sizeof (kstat_named_t) * 2);
	if ((scsb->ks_evcreg = kstat_create(scsb_name, scsb->scsb_instance,
	    SCSB_KS_EVC_REGISTER, "misc", KSTAT_TYPE_NAMED, 2,
	    KSTAT_FLAG_PERSISTENT|KSTAT_FLAG_WRITABLE)) == NULL) {
		scsb->scsb_state |= SCSB_KSTATS;
		scsb_free_kstats(scsb);
		return (DDI_FAILURE);
	}
	scsb->ks_evcreg->ks_update = update_ks_evcreg;
	scsb->ks_evcreg->ks_private = (void *)scsb;
	kn = KSTAT_NAMED_PTR(scsb->ks_evcreg);
	kstat_named_init(&kn[0], "pid_register", KSTAT_DATA_INT64);
	kstat_named_init(&kn[1], "pid_unregister", KSTAT_DATA_INT64);
	kstat_install(scsb->ks_evcreg);
	/*
	 * Done, set the flag for scsb_detach() and other checks
	 */
	scsb->scsb_state |= SCSB_KSTATS;
	return (DDI_SUCCESS);
}

static int
update_ks_leddata(kstat_t *ksp, int rw)
{
	scsb_state_t		*scsb;
	scsb_ks_leddata_t	*pks_leddata;
	int			i, numregs, index, error = DDI_SUCCESS;
	uchar_t			reg;

	scsb = (scsb_state_t *)ksp->ks_private;
	if (scsb_debug & 0x00080001)
		cmn_err(CE_NOTE, "update_ks_leddata: KS_UPDATE%sset",
		    scsb->scsb_state & SCSB_KS_UPDATE ? " " : " not ");
	/*
	 * Since this is satisfied from the shadow registers, let it succeed
	 * even if the SCB is not present.  It would be nice to return the
	 * shadow values with a warning.
	 *
	 * if (scsb->scsb_state & SCSB_FROZEN) {
	 *	return (DDI_FAILURE);
	 * }
	 */
	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}
	mutex_enter(&scsb->scsb_mutex);
	while (scsb->scsb_state & SCSB_KS_UPDATE) {
		if (cv_wait_sig(&scsb->scsb_cv, &scsb->scsb_mutex) <= 0) {
			mutex_exit(&scsb->scsb_mutex);
			return (EINTR);
		}
	}
	scsb->scsb_state |= SCSB_KS_UPDATE;
	mutex_exit(&scsb->scsb_mutex);
	if (scsb_debug & 0x00080001)
		cmn_err(CE_NOTE, "update_ks_leddata: updating data");
	pks_leddata = (scsb_ks_leddata_t *)ksp->ks_data;
	/*
	 * Call tonga_slotnum_led_shift() for each register that
	 * contains Slot 1-5 information, the first register at each base:
	 * NOK_BASE, OK_BASE, BLINK_OK_BASE
	 * XXX: breaking register table access rules by not using macros.
	 */
	/* NOK */
	reg = SCSB_REG_ADDR(SCTRL_LED_NOK_BASE);
	index = SCSB_REG_INDEX(reg);
	numregs = SCTRL_LED_NOK_NUMREGS;
	i = 0;
	if (IS_SCB_P15)
		reg = tonga_slotnum_led_shift(scsb, scsb->scsb_data_reg[index]);
	else
		reg = scsb->scsb_data_reg[index];
	pks_leddata->scb_led_regs[i] = reg;
	for (++i, ++index; i < numregs; ++i, ++index)
		pks_leddata->scb_led_regs[i] = scsb->scsb_data_reg[index];
	/* OK */
	reg = SCSB_REG_ADDR(SCTRL_LED_OK_BASE);
	index = SCSB_REG_INDEX(reg);
	numregs += SCTRL_LED_OK_NUMREGS;
	if (IS_SCB_P15)
		reg = tonga_slotnum_led_shift(scsb, scsb->scsb_data_reg[index]);
	else
		reg = scsb->scsb_data_reg[index];
	pks_leddata->scb_led_regs[i] = reg;
	for (++i, ++index; i < numregs; ++i, ++index)
		pks_leddata->scb_led_regs[i] = scsb->scsb_data_reg[index];
	/* BLINK */
	reg = SCSB_REG_ADDR(SCTRL_BLINK_OK_BASE);
	index = SCSB_REG_INDEX(reg);
	numregs += SCTRL_BLINK_NUMREGS;
	if (IS_SCB_P15)
		reg = tonga_slotnum_led_shift(scsb, scsb->scsb_data_reg[index]);
	else
		reg = scsb->scsb_data_reg[index];
	pks_leddata->scb_led_regs[i] = reg;
	for (++i, ++index; i < numregs; ++i, ++index)
		pks_leddata->scb_led_regs[i] = scsb->scsb_data_reg[index];
	mutex_enter(&scsb->scsb_mutex);
	scsb->scsb_state &= ~SCSB_KS_UPDATE;
	cv_signal(&scsb->scsb_cv);
	mutex_exit(&scsb->scsb_mutex);
	if (scsb_debug & 0x00080001)
		cmn_err(CE_NOTE, "update_ks_leddata: returning");
	return (error);
}

static int
update_ks_evcreg(kstat_t *ksp, int rw)
{
	scsb_state_t		*scsb;
	int			error = 0;
	kstat_named_t		*kn = KSTAT_NAMED_PTR(ksp);
	pid_t			pid;

	scsb = (scsb_state_t *)ksp->ks_private;
	if (scsb_debug & 0x00080001)
		cmn_err(CE_NOTE, "update_ks_evcreg: %s(%d), KS_UPDATE%sset",
		    rw == KSTAT_READ ? "read" : "write", rw,
		    scsb->scsb_state & SCSB_KS_UPDATE ? " " : " not ");
	/*
	 * Let this registration succeed
	 *
	 * if (scsb->scsb_state & SCSB_FROZEN) {
	 *	return (DDI_FAILURE);
	 * }
	 */
	mutex_enter(&scsb->scsb_mutex);
	while (scsb->scsb_state & SCSB_KS_UPDATE) {
		if (cv_wait_sig(&scsb->scsb_cv, &scsb->scsb_mutex) <= 0) {
			mutex_exit(&scsb->scsb_mutex);
			return (EINTR);
		}
	}
	scsb->scsb_state |= SCSB_KS_UPDATE;
	mutex_exit(&scsb->scsb_mutex);
	if (rw == KSTAT_READ) {
		kn[0].value.i64 = (int64_t)0;
		kn[1].value.i64 = (int64_t)0;
	} else if (rw == KSTAT_WRITE) {
		/*
		 * kn[0] is "pid_register", kn[1] is "pid_unregister"
		 */
		if (kn[0].value.i64 != 0 && kn[1].value.i64 == 0) {
			pid = (pid_t)kn[0].value.i64;
			if (add_event_proc(scsb, pid)) {
				if (scsb_debug & 0x02000002) {
					cmn_err(CE_WARN,
					    "update_ks_evcreg: "
					    "process add failed for %d",
					    pid);
				}
				error = EOVERFLOW;
			}
		} else if (kn[0].value.i64 == 0 && kn[1].value.i64 != 0) {
			pid = (pid_t)kn[1].value.i64;
			if (del_event_proc(scsb, pid)) {
				if (scsb_debug & 0x02000000) {
					cmn_err(CE_NOTE,
					    "update_ks_evcreg: "
					    "process delete failed for %d",
					    pid);
				}
				error = EOVERFLOW;
			}
		} else if (kn[0].value.i64 == 0 && kn[1].value.i64 == 0) {
			/*
			 * rewind the pointers and counts, zero the table.
			 */
			rew_event_proc(scsb);
		} else {
			error = EINVAL;
		}
	} else {
		error = EINVAL;
	}
	mutex_enter(&scsb->scsb_mutex);
	scsb->scsb_state &= ~SCSB_KS_UPDATE;
	cv_signal(&scsb->scsb_cv);
	mutex_exit(&scsb->scsb_mutex);
	return (error);
}

static int
update_ks_state(kstat_t *ksp, int rw)
{
	scsb_state_t		*scsb;
	scsb_ks_state_t		*pks_state;
	int			error = DDI_SUCCESS;
	uint32_t		current_evc;

	scsb = (scsb_state_t *)ksp->ks_private;
	if (scsb_debug & 0x00080001)
		cmn_err(CE_NOTE, "update_ks_state: KS_UPDATE%sset",
		    scsb->scsb_state & SCSB_KS_UPDATE ? " " : " not ");
	/*
	 * Let this succeed based on last known data
	 *
	 * if (scsb->scsb_state & SCSB_FROZEN) {
	 *	return (DDI_FAILURE);
	 * }
	 */
	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}
	mutex_enter(&scsb->scsb_mutex);
	while (scsb->scsb_state & SCSB_KS_UPDATE) {
		if (cv_wait_sig(&scsb->scsb_cv, &scsb->scsb_mutex) <= 0) {
			mutex_exit(&scsb->scsb_mutex);
			return (EINTR);
		}
	}
	scsb->scsb_state |= SCSB_KS_UPDATE;
	/*
	 * If SSB not present and scsb not SCSB_FROZEN, check for SCB presence
	 * by initiating an I2C read from the SCB.  If an error occurs,
	 * scsb_freeze() will be called to update SCB info and scsb state.
	 */
	if (!(scsb->scsb_state & SCSB_SSB_PRESENT) &&
	    !(scsb->scsb_state & SCSB_FROZEN)) {
		uchar_t		data;
		/* Read the SCB PROM ID */
		if (data = scsb_rdwr_register(scsb, I2C_WR_RD,
		    (uchar_t)SCTRL_PROM_VERSION, 1, &data, 1))
			if (scsb_debug & 0x00080002)
				cmn_err(CE_NOTE, "update_ks_state: SCB/I2C "
				    "failure %d", data);
	}
	mutex_exit(&scsb->scsb_mutex);
	pks_state = (scsb_ks_state_t *)ksp->ks_data;
	pks_state->scb_present = (scsb->scsb_state & SCSB_SCB_PRESENT) ? 1 : 0;
	pks_state->ssb_present = (scsb->scsb_state & SCSB_SSB_PRESENT) ? 1 : 0;
	pks_state->scsb_frozen = (scsb->scsb_state & SCSB_FROZEN) ? 1 : 0;
	if (scsb->scsb_state & SCSB_DEBUG_MODE)
		pks_state->scsb_mode = (uint8_t)ENVC_DEBUG_MODE;
	else if (scsb->scsb_state & SCSB_DIAGS_MODE)
		pks_state->scsb_mode = (uint8_t)ENVCTRL_DIAG_MODE;
	else
		pks_state->scsb_mode = (uint8_t)ENVCTRL_NORMAL_MODE;
	/*
	 * If scsb_attach() has not completed the kstat installs,
	 * then there are no event processes to check for.
	 */
	if (scsb->scsb_state & SCSB_KSTATS) {
		switch (check_event_procs(&current_evc)) {
		case EVC_NO_EVENT_CODE:
			pks_state->event_code = 0;
			break;
		case EVC_NEW_EVENT_CODE:
		/* FALLTHROUGH */
		case EVC_NO_CURR_PROC:
			pks_state->event_code = current_evc;
			break;
		case EVC_OR_EVENT_CODE:
			pks_state->event_code |= current_evc;
			break;
		case EVC_FAILURE:
			pks_state->event_code = 0;
			error = DDI_FAILURE;
			break;
		}
	} else {
		pks_state->event_code = 0;
	}
	mutex_enter(&scsb->scsb_mutex);
	scsb->scsb_state &= ~SCSB_KS_UPDATE;
	cv_signal(&scsb->scsb_cv);
	mutex_exit(&scsb->scsb_mutex);
	return (error);
}

static int
update_ks_topology(kstat_t *ksp, int rw)
{
	scsb_state_t		*scsb;
	mct_topology_t		*pks_topo;
	fru_info_t		*fru_ptr;
	int			i, val, error = DDI_SUCCESS, slotnum;

	scsb = (scsb_state_t *)ksp->ks_private;
	if (scsb_debug & 0x00080001)
		cmn_err(CE_NOTE, "update_ks_topology: KS_UPDATE%sset",
		    scsb->scsb_state & SCSB_KS_UPDATE ? " " : " not ");
	/*
	 * Let this succeed based on last known data
	 *
	 * if (scsb->scsb_state & SCSB_FROZEN) {
	 *	return (DDI_FAILURE);
	 * }
	 */
	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}
	mutex_enter(&scsb->scsb_mutex);
	while (scsb->scsb_state & SCSB_KS_UPDATE) {
		if (cv_wait_sig(&scsb->scsb_cv, &scsb->scsb_mutex) <= 0) {
			mutex_exit(&scsb->scsb_mutex);
			return (EINTR);
		}
	}
	scsb->scsb_state |= SCSB_KS_UPDATE;
	/*
	 * If SSB not present and scsb not SCSB_FROZEN, check for SCB presence
	 * by initiating an I2C read from the SCB.  If an error occurs,
	 * scsb_freeze() will be called to update SCB info and scsb state.
	 */
	if (!(scsb->scsb_state & SCSB_SSB_PRESENT) &&
	    !(scsb->scsb_state & SCSB_FROZEN)) {
		uchar_t		data;
		/* Read the SCB PROM ID */
		if (data = scsb_rdwr_register(scsb, I2C_WR_RD,
		    (uchar_t)SCTRL_PROM_VERSION, 1, &data, 1))
			if (scsb_debug & 0x00080002)
				cmn_err(CE_NOTE, "update_ks_topology: SCB/I2C "
				    "failure %d", data);
	}
	mutex_exit(&scsb->scsb_mutex);
	pks_topo = (mct_topology_t *)ksp->ks_data;
	for (i = SLOT; i < SCSB_UNIT_TYPES; ++i) {
		pks_topo->max_units[i] = mct_system_info.max_units[i];
	}

	pks_topo->mid_plane.fru_status = FRU_PRESENT;
	pks_topo->mid_plane.fru_unit = (scsb_unum_t)1;
	pks_topo->mid_plane.fru_type = mct_system_info.mid_plane.fru_type;
	pks_topo->mid_plane.fru_id = mct_system_info.mid_plane.fru_id;
	pks_topo->mid_plane.fru_version = mct_system_info.mid_plane.fru_version;
	pks_topo->mid_plane.fru_health = MCT_HEALTH_OK;
	fru_ptr = mct_system_info.fru_info_list[SLOT];
	for (i = 0; i < pks_topo->max_units[SLOT]; ++i, ++fru_ptr) {
		pks_topo->mct_slots[i].fru_status = fru_ptr->fru_status;
		pks_topo->mct_slots[i].fru_type = fru_ptr->fru_type;
		pks_topo->mct_slots[i].fru_unit = fru_ptr->fru_unit;
		pks_topo->mct_slots[i].fru_id = fru_ptr->fru_id;
		pks_topo->mct_slots[i].fru_version = fru_ptr->fru_version;
		/*
		 * XXX: need to check healthy regs to set fru_health
		 */
		slotnum = tonga_psl_to_ssl(scsb, i+1);
		val = scsb_fru_op(scsb, SLOT, slotnum, SCTRL_BHLTHY_BASE,
		    SCSB_FRU_OP_GET_BITVAL);
		pks_topo->mct_slots[i].fru_health = (val) ?
		    MCT_HEALTH_OK : MCT_HEALTH_NOK;
	}
	fru_ptr = mct_system_info.fru_info_list[PDU];
	for (i = 0; i < pks_topo->max_units[PDU]; ++i, ++fru_ptr) {
		pks_topo->mct_pdu[i].fru_status = fru_ptr->fru_status;
		pks_topo->mct_pdu[i].fru_type = fru_ptr->fru_type;
		pks_topo->mct_pdu[i].fru_unit = fru_ptr->fru_unit;
		pks_topo->mct_pdu[i].fru_id = fru_ptr->fru_id;
		pks_topo->mct_pdu[i].fru_version = fru_ptr->fru_version;
		pks_topo->mct_pdu[i].fru_health = MCT_HEALTH_NA;
	}
	fru_ptr = mct_system_info.fru_info_list[PS];
	for (i = 0; i < pks_topo->max_units[PS]; ++i, ++fru_ptr) {
		pks_topo->mct_ps[i].fru_status = fru_ptr->fru_status;
		pks_topo->mct_ps[i].fru_type = fru_ptr->fru_type;
		pks_topo->mct_ps[i].fru_unit = fru_ptr->fru_unit;
		pks_topo->mct_ps[i].fru_id = fru_ptr->fru_id;
		pks_topo->mct_ps[i].fru_version = fru_ptr->fru_version;
		pks_topo->mct_ps[i].fru_health = MCT_HEALTH_NA;
	}
	fru_ptr = mct_system_info.fru_info_list[DISK];
	for (i = 0; i < pks_topo->max_units[DISK]; ++i, ++fru_ptr) {
		pks_topo->mct_disk[i].fru_status = fru_ptr->fru_status;
		pks_topo->mct_disk[i].fru_type = fru_ptr->fru_type;
		pks_topo->mct_disk[i].fru_unit = fru_ptr->fru_unit;
		pks_topo->mct_disk[i].fru_id = fru_ptr->fru_id;
		pks_topo->mct_disk[i].fru_version = fru_ptr->fru_version;
		pks_topo->mct_disk[i].fru_health = MCT_HEALTH_NA;
	}
	fru_ptr = mct_system_info.fru_info_list[FAN];
	for (i = 0; i < pks_topo->max_units[FAN]; ++i, ++fru_ptr) {
		pks_topo->mct_fan[i].fru_status = fru_ptr->fru_status;
		pks_topo->mct_fan[i].fru_type = fru_ptr->fru_type;
		pks_topo->mct_fan[i].fru_unit = fru_ptr->fru_unit;
		pks_topo->mct_fan[i].fru_id = fru_ptr->fru_id;
		pks_topo->mct_fan[i].fru_version = fru_ptr->fru_version;
		pks_topo->mct_fan[i].fru_health = MCT_HEALTH_NA;
	}
	fru_ptr = mct_system_info.fru_info_list[SCB];
	for (i = 0; i < pks_topo->max_units[SCB]; ++i, ++fru_ptr) {
		pks_topo->mct_scb[i].fru_status = fru_ptr->fru_status;
		pks_topo->mct_scb[i].fru_type = fru_ptr->fru_type;
		pks_topo->mct_scb[i].fru_unit = fru_ptr->fru_unit;
		pks_topo->mct_scb[i].fru_id = fru_ptr->fru_id;
		pks_topo->mct_scb[i].fru_version = fru_ptr->fru_version;
		/*
		 * To get the scsb health, if there was no i2c transaction
		 * until this read, generate an i2c transaction.
		 */
		if (scsb->scsb_kstat_flag == B_FALSE) {
			uchar_t		data;
			(void) scsb_blind_read(scsb, I2C_WR_RD,
			    (uchar_t)SCTRL_PROM_VERSION, 1, &data, 1);
		}
		pks_topo->mct_scb[i].fru_health = ((scsb->scsb_err_flag ==
		    B_TRUE || scsb->scsb_i2c_errcnt > scsb_err_threshold)
		    ?  MCT_HEALTH_NOK : MCT_HEALTH_OK);
#ifdef DEBUG
		if (pks_topo->mct_scb[i].fru_health == MCT_HEALTH_NOK)
			cmn_err(CE_WARN, "SCSB kstat health:%d", pks_topo->
			    mct_scb[i].fru_health);
#endif
		scsb->scsb_err_flag = B_FALSE; /* clear error flag once read */
		scsb->scsb_kstat_flag = B_FALSE; /* false? read from i2c */
	}
	fru_ptr = mct_system_info.fru_info_list[SSB];
	for (i = 0; i < pks_topo->max_units[SSB]; ++i, ++fru_ptr) {
		pks_topo->mct_ssb[i].fru_status = fru_ptr->fru_status;
		pks_topo->mct_ssb[i].fru_type = fru_ptr->fru_type;
		pks_topo->mct_ssb[i].fru_unit = fru_ptr->fru_unit;
		pks_topo->mct_ssb[i].fru_id = fru_ptr->fru_id;
		pks_topo->mct_ssb[i].fru_version = fru_ptr->fru_version;
		pks_topo->mct_ssb[i].fru_health = MCT_HEALTH_NA;
	}
	fru_ptr = mct_system_info.fru_info_list[ALARM];
	for (i = 0; i < pks_topo->max_units[ALARM]; ++i, ++fru_ptr) {
		pks_topo->mct_alarm[i].fru_status = fru_ptr->fru_status;
		pks_topo->mct_alarm[i].fru_type = fru_ptr->fru_type;
		pks_topo->mct_alarm[i].fru_unit = fru_ptr->fru_unit;
		pks_topo->mct_alarm[i].fru_id = fru_ptr->fru_id;
		pks_topo->mct_alarm[i].fru_version = fru_ptr->fru_version;
		pks_topo->mct_alarm[i].fru_health = MCT_HEALTH_NA;
	}
	fru_ptr = mct_system_info.fru_info_list[CFTM];
	for (i = 0; i < pks_topo->max_units[CFTM]; ++i, ++fru_ptr) {
		pks_topo->mct_cftm[i].fru_status = fru_ptr->fru_status;
		pks_topo->mct_cftm[i].fru_type = fru_ptr->fru_type;
		pks_topo->mct_cftm[i].fru_unit = fru_ptr->fru_unit;
		pks_topo->mct_cftm[i].fru_id = fru_ptr->fru_id;
		pks_topo->mct_cftm[i].fru_version = fru_ptr->fru_version;
		pks_topo->mct_cftm[i].fru_health = MCT_HEALTH_NA;
	}
	fru_ptr = mct_system_info.fru_info_list[CRTM];
	for (i = 0; i < pks_topo->max_units[CRTM]; ++i, ++fru_ptr) {
		pks_topo->mct_crtm[i].fru_status = fru_ptr->fru_status;
		pks_topo->mct_crtm[i].fru_type = fru_ptr->fru_type;
		pks_topo->mct_crtm[i].fru_unit = fru_ptr->fru_unit;
		pks_topo->mct_crtm[i].fru_id = fru_ptr->fru_id;
		pks_topo->mct_crtm[i].fru_version = fru_ptr->fru_version;
		pks_topo->mct_crtm[i].fru_health = MCT_HEALTH_NA;
	}
	fru_ptr = mct_system_info.fru_info_list[PRTM];
	for (i = 0; i < pks_topo->max_units[PRTM]; ++i, ++fru_ptr) {
		pks_topo->mct_prtm[i].fru_status = fru_ptr->fru_status;
		pks_topo->mct_prtm[i].fru_type = fru_ptr->fru_type;
		pks_topo->mct_prtm[i].fru_unit = fru_ptr->fru_unit;
		pks_topo->mct_prtm[i].fru_id = fru_ptr->fru_id;
		pks_topo->mct_prtm[i].fru_version = fru_ptr->fru_version;
		pks_topo->mct_prtm[i].fru_health = MCT_HEALTH_NA;
	}
	mutex_enter(&scsb->scsb_mutex);
	scsb->scsb_state &= ~SCSB_KS_UPDATE;
	cv_signal(&scsb->scsb_cv);
	mutex_exit(&scsb->scsb_mutex);
	return (error);
}

static void
scsb_free_kstats(scsb_state_t *scsb)
{
	if (!(scsb->scsb_state & SCSB_KSTATS))
		return;
	/*
	 * free the allocated kstat data
	 */
	if (scsb->ks_evcreg != NULL) {
		kstat_delete(scsb->ks_evcreg);
	}
	if (scsb->ks_topology != NULL) {
		kstat_delete(scsb->ks_topology);
	}
	if (scsb->ks_state != NULL) {
		kstat_delete(scsb->ks_state);
	}
	if (scsb->ks_leddata != NULL) {
		kstat_delete(scsb->ks_leddata);
	}
	scsb->ks_leddata = NULL;
	scsb->ks_state = NULL;
	scsb->ks_topology = NULL;
	scsb->ks_evcreg = NULL;
	scsb->scsb_state &= ~SCSB_KSTATS;
}


/*
 * --------------------------------------
 * Miscellaneous scsb internal functions.
 * --------------------------------------
 *
 * allocate I2C transfer structure
 */
static i2c_transfer_t *
scsb_alloc_i2ctx(i2c_client_hdl_t phandle, uint_t sleep)
{
	i2c_transfer_t	*tp;

	if (i2c_transfer_alloc(phandle, &tp, SCSB_DATA_REGISTERS + 2,
	    SCSB_DATA_REGISTERS + 2, sleep) == I2C_FAILURE) {
		return (NULL);
	}
	return (tp);
}

/*
 * free I2C transfer structure
 */
static void
scsb_free_i2ctx(i2c_client_hdl_t phandle, i2c_transfer_t *tp)
{
	i2c_transfer_free(phandle, tp);
}

static	void
update_fru_info(scsb_state_t *scsb, fru_info_t *fru_ptr)
{
	int		index;
	uchar_t		reg, bit;
	fru_info_t	*acslot_ptr = NULL;
	fru_id_t	acslot_id = 0;
	if (scsb_debug & 0x00100001)
		cmn_err(CE_NOTE, "update_fru_info(scsb,0x%p)", (void *)fru_ptr);
	if (fru_ptr == (fru_info_t *)NULL ||
	    fru_ptr->i2c_info == (fru_i2c_info_t *)NULL)
		return;
	/*
	 * If this is an Alarm Card update, then we also need to get
	 * Alarm Card Slot fru_ptr to update it's fru_type, and maybe fru_id
	 */
	if (fru_ptr->fru_id == fru_id_table[FRU_INDEX(SCTRL_EVENT_ALARM)]) {
		/*
		 * SCTRL_EVENT_SLOT1 == 0x01 so
		 * fru_id_table[] index for Slot 1 == 0
		 */
		acslot_id = fru_id_table[(scsb->ac_slotnum - 1)];
		acslot_ptr = find_fru_info(acslot_id);
	}
	reg = fru_ptr->i2c_info->syscfg_reg;
	bit = fru_ptr->i2c_info->syscfg_bit;
	if (reg == 0 && fru_ptr->fru_type == SCB) {
		if (scsb->scsb_state & SCSB_SCB_PRESENT)
			fru_ptr->fru_status = FRU_PRESENT;
		else
			fru_ptr->fru_status = FRU_NOT_PRESENT;
	} else if (reg) {
		index = SCSB_REG_INDEX(reg);
		if (scsb->scsb_data_reg[index] & (1 << bit)) {
			fru_ptr->fru_status = FRU_PRESENT;
			/*
			 * XXX:	need to add version register, and maybe a
			 *	 method, to the fru_ptr->i2c_info structure.
			 *
			 * fru_ptr->fru_version = (fru_version_t)0;
			 */
			/*
			 * Because scsb_intr() sometimes gets the AC present
			 * INT before the ACSLOT present INT,
			 * do not check the ACSLOT fru_status
			 *
			 * if (acslot_ptr != NULL && acslot_ptr->fru_status ==
			 *					FRU_PRESENT)
			 */
			if (acslot_ptr != NULL)
				acslot_ptr->fru_type = (scsb_utype_t)OC_AC;
		} else {
			fru_ptr->fru_status = FRU_NOT_PRESENT;
			/*
			 * fru_ptr->fru_version = (fru_version_t)0;
			 */
			if (acslot_ptr != NULL) {
				/* AC just removed, but AC Slot is occupied? */
				if (acslot_ptr->fru_status == FRU_PRESENT)
					/* for now it's unknown */
					acslot_ptr->fru_type =
					    (scsb_utype_t)OC_UNKN;
				else
					acslot_ptr->fru_type =
					    (scsb_utype_t)OC_UNKN;
			}
		}
	}
	if (scsb_debug & 0x00100000)
		cmn_err(CE_NOTE,
		    "update_fru_info: type %d unit %d is %spresent",
		    fru_ptr->fru_type, fru_ptr->fru_unit,
		    fru_ptr->fru_status == FRU_PRESENT
		    ? "" : "not ");
}

/*
 * Convert EVENT code to FRU index
 * by finding the highest bit number in 32 bit word
 */
static int
event_to_index(uint32_t evcode)
{
	int	i = 0;
	if (evcode == 0)
		return (MCT_MAX_FRUS - 1);
	for (; (evcode >>= 1); i++)
		;
	return (i);
}

#ifdef DEBUG
void
scsb_debug_prnt(char *fmt, uintptr_t a1, uintptr_t a2, uintptr_t a3,
	uintptr_t a4, uintptr_t a5)
{
	if (scsb_debug & 0x8000 ||
	    (*fmt == 'X' && scsb_debug & 0x00010000)) {
		if (*fmt == 'X')
			++fmt;
		prom_printf("scsb: ");
		prom_printf(fmt, a1, a2, a3, a4, a5);
		prom_printf("\n");
	}
}
#endif

/*
 * event code functions to deliver event codes
 * and to manage:
 *	the event code fifo
 *	the process handle table for registered processes interested in
 *	  event codes
 */
/*
 * Send signal to processes registered for event code delivery
 */
static void
signal_evc_procs(scsb_state_t *scsb)
{
	int	i = 0, c = 0;
	if (evc_proc_count == 0)
		return;
	for (; i < EVC_PROCS_MAX; ++i) {
		if (evc_procs[i] != NULL) {
			if (proc_signal(evc_procs[i], SIGPOLL)) {
				if (scsb_debug & 0x02000002)
					cmn_err(CE_WARN,
					    "scsb:signal_evc_procs: "
					    "signal to %d failed",
					    ((struct pid *)
					    evc_procs[i])->pid_id);
				(void) del_event_proc(scsb,
				    ((struct pid *)evc_procs[i])->pid_id);
			}
			if (++c >= evc_proc_count) {
				if (scsb_debug & 0x02000000) {
					cmn_err(CE_NOTE,
					    "signal_evc_procs: signaled "
					    "%d/%d processes", c,
					    evc_proc_count);
				}
				break;
			}
		}
	}
}

/*
 * bump FIFO ptr, taking care of wrap around
 */
static uint32_t *
inc_fifo_ptr(uint32_t *ptr)
{
	if (++ptr >= evc_fifo + EVC_FIFO_SIZE)
		ptr = evc_fifo;
	return (ptr);
}

/* ARGSUSED */
static void
reset_evc_fifo(scsb_state_t *scsb)
{
	evc_wptr = evc_fifo;
	evc_rptr = evc_fifo;
	evc_fifo_count = 0;
}

/*
 * Called from scsb_intr() when a new event occurs, to put new code in FIFO,
 * and signal any interested processes in evc_procs[].
 * Always succeeds.
 */
static void
add_event_code(scsb_state_t *scsb, uint32_t event_code)
{
	if (event_proc_count(scsb) == 0) {
		return;
	}
	*evc_wptr = event_code;
	evc_wptr = inc_fifo_ptr(evc_wptr);
	if (++evc_fifo_count > EVC_FIFO_SIZE) {
		--evc_fifo_count;		/* lose the oldest event */
		evc_rptr = inc_fifo_ptr(evc_rptr);
	}
	if (scsb_debug & 0x01000000) {
		cmn_err(CE_NOTE, "add_event_code: 0x%x, FIFO size = %d",
		    event_code, evc_fifo_count);
	}
	signal_evc_procs(scsb);
}

/*
 * called from check_event_procs() when the last registered process
 * retrieved the oldest event
 */
static uint32_t
del_event_code()
{
	uint32_t evc = 0;
	if (!evc_fifo_count)
		return (scsb_event_code);
	evc = *evc_rptr;
	evc_rptr = inc_fifo_ptr(evc_rptr);
	--evc_fifo_count;
	if (scsb_debug & 0x01000000) {
		cmn_err(CE_NOTE, "del_event_code: 0x%x, FIFO size = %d",
		    evc, evc_fifo_count);
	}
	return (evc);
}

/*
 * called from check_event_procs() to retrieve the current event code
 */
static uint32_t
get_event_code()
{
	if (!evc_fifo_count)
		return (0);
	return (*evc_rptr);
}

/*
 * called from an application interface (ie: an ioctl command)
 * to register a process id interested in SCB events.
 * NOTE: proc_ref() must be called from USER context, so since this is a
 * streams driver, a kstat interface is used for process registration.
 * return:
 *	0 = event_proc was added
 *	1 = out of space
 */
/* ARGSUSED */
static int
add_event_proc(scsb_state_t *scsb, pid_t pid)
{
	int	i = 0;
	void	*curr_proc;
	pid_t	curr_pid;
	if (evc_proc_count >= EVC_PROCS_MAX)
		return (1);
	curr_proc = proc_ref();
	curr_pid = (pid_t)(((struct pid *)curr_proc)->pid_id);
	if (curr_pid != pid) {
		if (scsb_debug & 0x02000000) {
			cmn_err(CE_WARN,
			    "add_event_proc: current %d != requestor %d",
			    curr_pid, pid);
		} else {
			proc_unref(curr_proc);
			return (1);
		}
	}
	for (; i < EVC_PROCS_MAX; ++i) {
		if (evc_procs[i] == NULL) {
			evc_procs[i] = curr_proc;
			evc_proc_count++;
			if (scsb_debug & 0x02000000) {
				cmn_err(CE_NOTE,
				    "add_event_proc: %d; evc_proc_count=%d",
				    pid, evc_proc_count);
			}
			return (0);
		}
	}
	proc_unref(curr_proc);
	return (1);
}

/*
 * called from an application interface (ie: an ioctl command)
 * to unregister a process id interested in SCB events.
 * return:
 *	0 = event_proc was deleted
 *	1 = event_proc was not found, or table was empty
 */
/* ARGSUSED */
static int
del_event_proc(scsb_state_t *scsb, pid_t pid)
{
	int	i = 0;
	int	cnt = 0;
	void	*this_proc;
	if (evc_proc_count == 0)
		return (1);
	for (; i < EVC_PROCS_MAX; ++i) {
		if (evc_procs[i] == NULL)
			continue;
		this_proc = evc_procs[i];
		if (pid == ((struct pid *)this_proc)->pid_id) {
			evc_procs[i] = NULL;
			if (--evc_proc_count == 0) {
				/*
				 * reset evc fifo cound and pointers
				 */
				reset_evc_fifo(scsb);
			}
			if (scsb_debug & 0x02000000) {
				cmn_err(CE_NOTE,
				    "del_event_proc: %d; evc_proc_count=%d",
				    pid, evc_proc_count);
			}
			proc_unref(this_proc);
			return (0);
		}
		if (++cnt >= evc_proc_count)
			break;
	}
	return (1);
}

/*
 * Can be called from an application interface
 * to rewind the pointers and counters, and zero the table
 * return:
 */
/* ARGSUSED */
static void
rew_event_proc(scsb_state_t *scsb)
{
	int	i = 0;
	if (scsb_debug & 0x02000001) {
		cmn_err(CE_NOTE, "rew_event_proc: evc_proc_count=%d",
		    evc_proc_count);
	}
	for (; i < EVC_PROCS_MAX; ++i) {
		if (evc_procs[i] != NULL) {
			proc_unref(evc_procs[i]);
			evc_procs[i] = NULL;
		}
	}
	evc_proc_count = 0;
}

/* ARGSUSED */
static int
event_proc_count(scsb_state_t *scsb)
{
	return (evc_proc_count);
}

/*
 * return:
 *	1 = pid was found
 *	0 = pid was not found, or table was empty
 */
static int
find_evc_proc(pid_t pid)
{
	int	i = 0;
	int	cnt = 0;
	if (evc_proc_count == 0)
		return (0);
	for (; i < EVC_PROCS_MAX; ++i) {
		if (evc_procs[i] == NULL)
			continue;
		if (pid == ((struct pid *)evc_procs[i])->pid_id)
			return (1);
		if (++cnt >= evc_proc_count)
			break;
	}
	return (0);
}

/*
 * called from update_ks_state() to compare evc_proc_count with
 * evc_requests, also mainted by this same function
 * This function could check the current process id, since this will be a user
 * context call, and only bump evc_requests if the calling process is
 * registered for event code delivery.
 * return:
 *	EVC_NO_EVENT_CODE	: no event_code on fifo
 *	EVC_NO_CURR_PROC	: current process not in table,
 *				  but have an event_code
 *	EVC_NEW_EVENT_CODE	: return_evc is new ks_state->event_code
 *	EVC_OR_EVENT_CODE	: OR return_evc with ks_state->event_code
 *	EVC_FAILURE		: unrecoverable error condition.
 */
static int
check_event_procs(uint32_t *return_evc)
{
	void		*curr_proc;
	pid_t		curr_pid = 0;
	int		return_val = 0;
	static int	evc_requests = 0;
	/*
	 * get current process handle, and check the event_procs table
	 */
	if (evc_proc_count == 0) {
		*return_evc = del_event_code();
		return_val = EVC_NO_CURR_PROC;
	} else {
		curr_proc = proc_ref();
		curr_pid = ((struct pid *)curr_proc)->pid_id;
		proc_unref(curr_proc);
		if (!find_evc_proc(curr_pid)) {
			*return_evc = get_event_code();
			return_val = EVC_NO_CURR_PROC;
		} else if (++evc_requests >= evc_proc_count) {
			evc_requests = 0;
			*return_evc = del_event_code();
			return_val = EVC_NEW_EVENT_CODE;
		} else {
			*return_evc = get_event_code();
		}
		if (!return_val)
			return_val = EVC_OR_EVENT_CODE;
	}
	if (scsb_debug & 0x02000000) {
		cmn_err(CE_NOTE, "check_event_procs: pid=%d, evc=0x%x, "
		    "requests=%d, returning 0x%x", curr_pid,
		    *return_evc, evc_requests, return_val);
	}
	return (return_val);
}

static int
scsb_queue_put(queue_t *rq, int count, uint32_t *data, char *caller)
{
	mblk_t		*mp;
	if (scsb_debug & 0x4001) {
		cmn_err(CE_NOTE, "scsb_queue_put(0x%p, %d, 0x%x, %s)",
		    (void *)rq, count, *data, caller);
	}
	mp = allocb(sizeof (uint32_t) * count, BPRI_HI);
	if (mp == NULL) {
		cmn_err(CE_WARN, "%s: allocb failed",
		    caller);
		return (B_FALSE);
	}
	while (count--) {
		*((uint32_t *)mp->b_wptr) = *data;
		mp->b_wptr += sizeof (*data);
		++data;
	}
	putnext(rq, mp);
	return (B_TRUE);
}

/* CLONE */
static int
scsb_queue_ops(scsb_state_t	*scsb,
		int		op,
		int		oparg,
		void		*opdata,
		char		*caller)
{
	clone_dev_t	*clptr;
	int		clone, find_open, find_available, retval = QOP_FAILED;

	switch (op) {
	case QPUT_INT32:
		if (scsb->scsb_opens && scsb->scsb_rq != NULL &&
		    scsb_queue_put(scsb->scsb_rq, oparg,
		    (uint32_t *)opdata, caller) == B_FALSE) {
			return (QOP_FAILED);
		}
	/*FALLTHROUGH*/	/* to look for opened clones */
	case QPROCSOFF:
		retval = QOP_OK;
	/*FALLTHROUGH*/
	case QFIRST_OPEN:
	case QFIND_QUEUE:
		find_open = 1;
		find_available = 0;
		break;
	case QFIRST_AVAILABLE:
		find_available = 1;
		find_open = 0;
		break;
	}
	for (clone = SCSB_CLONES_FIRST; clone < SCSB_CLONES_MAX; clone++) {
		clptr = &scsb->clone_devs[clone];
		if (find_open && clptr->cl_flags & SCSB_OPEN) {
			if (clptr->cl_rq == NULL) {
				cmn_err(CE_WARN, "%s: Clone %d has no queue",
				    caller, clptr->cl_minor);
				return (QOP_FAILED);
			}
			switch (op) {
			case QPROCSOFF:
				qprocsoff(clptr->cl_rq);
				break;
			case QPUT_INT32:
				if (scsb_queue_put(clptr->cl_rq, oparg,
				    (uint32_t *)opdata, caller)
				    == B_FALSE) {
					retval = QOP_FAILED;
				}
				break;
			case QFIRST_OPEN:
				return (clone);
			case QFIND_QUEUE:
				if (clptr->cl_rq == (queue_t *)opdata) {
					return (clone);
				}
				break;
			}
		} else if (find_available && clptr->cl_flags == 0) {
			switch (op) {
			case QFIRST_AVAILABLE:
				return (clone);
			}
		}
	}
	return (retval);
}

/*
 * Find out if a bit is set for the FRU type and unit number in the register
 * set defined by the register base table index, base.
 * Returns TRUE if bit is set, or FALSE.
 */
static int
scsb_fru_op(scsb_state_t *scsb, scsb_utype_t fru_type, int unit, int base,
									int op)
{
	int		rc;
	uchar_t		reg;
	int		tmp, idx, code, offset;

#if 0
		reg = SCSB_REG_ADDR(i);
		ac_mask = 1 << FRU_OFFSET(SCTRL_EVENT_ALARM, SCTRL_RESET_BASE);
		ac_val = scsb->scsb_data_reg[index+1] & ac_mask;
#endif
	/* get the event code based on which we get the reg and bit offsets */
	code   = FRU_UNIT_TO_EVCODE(fru_type, unit);
	/* get the bit offset in the 8bit register corresponding to the event */
	offset = FRU_OFFSET(code, base);
	/* register offset from the base register, based on the event code */
	if ((fru_type == ALARM) && (base == SCTRL_RESET_BASE))
		tmp = ALARM_RESET_REG_INDEX(code, base);
	else
		tmp = FRU_REG_INDEX(code, base);
	/* get the global offset of the register in the parent address space */
	reg    = SCSB_REG_ADDR(tmp);
	/* get the global index of the register in this SCSB's address space */
	idx    = SCSB_REG_INDEX(reg);
	DEBUG4("scsb_fru_op(start): code=%x, offset=%x, tmp=%x, reg=%x\n",
	    code, offset, tmp, reg);
	switch (op) {
		case SCSB_FRU_OP_GET_REG:
			rc = reg;
			break;
		case SCSB_FRU_OP_GET_BITVAL:
			rc = (scsb->scsb_data_reg[idx] & (1 << offset))
			    >> offset;
			break;
		case SCSB_FRU_OP_GET_REGDATA:
			rc = scsb->scsb_data_reg[idx];
			break;
		case SCSB_FRU_OP_SET_REGBIT:
			rc = (1 << offset) & 0xff;
			break;
		default:
			break;
	}
	DEBUG4("scsb_fru_op: unit=%x, base=%x, op=%d, rc=%x\n", unit, base,
	    op, rc);
	return (rc);
}

/*
 * All HSC related functions can fail, but an attempt is made to atleast
 * return the right shadow state  on get-state function when SCB is removed.
 */
int
scsb_get_slot_state(scsb_state_t *scsb, int pslotnum, int *rstate)
{
	int		slotnum, val = 0, rc;

	/*
	 * When SCB is removed, we could be called with the lock held.
	 * We call check_config_status anyway since it is a read-only operation
	 * and HSC could be invoking this function at interrupt context.
	 * If scsb is already in the doing interrupt postprocess, wait..
	 */

	rc = scsb_check_config_status(scsb);

	/* check if error is because SCB is removed */
	if ((rc != EAGAIN) && (rc != DDI_SUCCESS))
		return (DDI_FAILURE);
	slotnum = tonga_psl_to_ssl(scsb, pslotnum);
	val = scsb_fru_op(scsb, SLOT, slotnum, SCTRL_SYSCFG_BASE,
	    SCSB_FRU_OP_GET_BITVAL);
	if (! val) {
		*rstate = HPC_SLOT_EMPTY;
		return (0);
	}
	/*
	 * now, lets determine if it is connected or disconnected.
	 * If reset is asserted, then the slot is disconnected.
	 */
	rc = scsb_reset_slot(scsb, pslotnum, SCSB_GET_SLOT_RESET_STATUS);
	/* check if error is because SCB is removed */
	if ((rc != EAGAIN) && (rc != DDI_SUCCESS))
		return (DDI_FAILURE);
	val = scsb_fru_op(scsb, SLOT, slotnum, SCTRL_RESET_BASE,
	    SCSB_FRU_OP_GET_BITVAL);
	if (val)
		*rstate = HPC_SLOT_DISCONNECTED;
	else {
		if (scsb_fru_op(scsb, SLOT, slotnum, SCTRL_BHLTHY_BASE,
		    SCSB_FRU_OP_GET_BITVAL)) {
			*rstate = HPC_SLOT_CONNECTED;
		} else {
			cmn_err(CE_WARN, "%s#%d: Reset Not Asserted on "
			    "Healthy# Failed slot %d!",
			    ddi_driver_name(scsb->scsb_dev),
			    ddi_get_instance(scsb->scsb_dev), slotnum);
			*rstate = HPC_SLOT_DISCONNECTED;
		}
	}
	return (0);
}

int
scsb_reset_slot(scsb_state_t *scsb, int pslotnum, int reset_flag)
{
	int		slotnum, error, val, alarm_card = 0;
	i2c_transfer_t	*i2cxferp;
	uchar_t		reg;
	int		index, condition_exists = 0, ac_val;

	if (scsb_debug & 0x8001)
		cmn_err(CE_NOTE, "scsb_reset_slot(%d), flag %x", pslotnum,
		    reset_flag);
	if (scsb->scsb_state & SCSB_FROZEN)
		return (EAGAIN);
	if ((i2cxferp = scsb_alloc_i2ctx(scsb->scsb_phandle,
	    I2C_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}
	slotnum = tonga_psl_to_ssl(scsb, pslotnum);

	if (scsb_is_alarm_card_slot(scsb, pslotnum) == B_TRUE) {
		DEBUG0("alarm card  reset/unreset op:\n");
		alarm_card = 1;
	}
	reg = SCSB_REG_ADDR(SCTRL_RESET_BASE);
	index = SCSB_REG_INDEX(reg);

	mutex_enter(&scsb->scsb_mutex);
	i2cxferp->i2c_flags = I2C_WR_RD;
	i2cxferp->i2c_rlen = SCTRL_RESET_NUMREGS;
	i2cxferp->i2c_wbuf[0] = reg;
	i2cxferp->i2c_wlen = 1;
	scsb->scsb_kstat_flag = B_TRUE;	/* we did an i2c transaction */
	if ((error = nct_i2c_transfer(scsb->scsb_phandle, i2cxferp)) == 0) {
		scsb->scsb_i2c_errcnt = 0;
		/*
		 * XXX: following statements assume 2 reset registers,
		 * which is the case for our current SCB revisions.
		 */
		scsb->scsb_data_reg[index]   = i2cxferp->i2c_rbuf[0];
		scsb->scsb_data_reg[index+1] = i2cxferp->i2c_rbuf[1];
	} else {
		scsb->scsb_i2c_errcnt++;
		if (scsb->scsb_i2c_errcnt > scsb_err_threshold)
			scsb->scsb_err_flag = B_TRUE; /* latch until kstat */
		if (!(scsb->scsb_state & SCSB_SSB_PRESENT)) {
			if (scsb->scsb_i2c_errcnt >= scsb_freeze_count)
				mutex_exit(&scsb->scsb_mutex);
				scsb_freeze(scsb);
				mutex_enter(&scsb->scsb_mutex);
		}
		cmn_err(CE_WARN, "%s#%d: scsb_reset_slot: error"
		    " reading Reset regs\n",
		    ddi_driver_name(scsb->scsb_dev),
		    ddi_get_instance(scsb->scsb_dev));
		error = DDI_FAILURE;
	}

	DEBUG2("pre-reset regs = %x,%x\n", scsb->scsb_data_reg[index],
	    scsb->scsb_data_reg[index+1]);
	if ((reset_flag == SCSB_GET_SLOT_RESET_STATUS) || (error)) {
		mutex_exit(&scsb->scsb_mutex);
		scsb_free_i2ctx(scsb->scsb_phandle, i2cxferp);
		return (error);
	}

	val = scsb_fru_op(scsb, SLOT, slotnum, SCTRL_RESET_BASE,
	    SCSB_FRU_OP_GET_BITVAL);
	if (alarm_card) {
		ac_val = scsb_fru_op(scsb, ALARM, 1, SCTRL_RESET_BASE,
		    SCSB_FRU_OP_GET_BITVAL);
	}
	if (val && (reset_flag == SCSB_RESET_SLOT)) {
		if (alarm_card) {
			if (ac_val) {
				condition_exists = 1;
				DEBUG0("Alarm_RST# already active.\n");
			}
#ifndef	lint
			else
				DEBUG1("Alarm_RST# not active! "
				    "Slot%d_RST# active!\n", pslotnum);
#endif
		} else {
			condition_exists = 1;
			DEBUG1("Slot%d_RST# already active!\n", pslotnum);
		}
	}
	else
		if ((val == 0) && (reset_flag == SCSB_UNRESET_SLOT)) {
			if (alarm_card) {
				if (!ac_val) {
					DEBUG0("Alarm_RST# not active.\n");
					condition_exists = 1;
				}
#ifndef	lint
				else
					DEBUG1("Alarm_RST# active"
					    " Slot%d_RST# not active!\n",
					    pslotnum);
#endif
			} else {
				condition_exists = 1;
				DEBUG1("Slot%d_RST# already not active!\n",
				    pslotnum);
			}
		}

	if (! condition_exists) {
		i2cxferp->i2c_flags = I2C_WR;
		i2cxferp->i2c_wlen = 2;
		i2cxferp->i2c_wbuf[0] = scsb_fru_op(scsb, SLOT, slotnum,
		    SCTRL_RESET_BASE, SCSB_FRU_OP_GET_REG);
		if (reset_flag == SCSB_RESET_SLOT) {
			i2cxferp->i2c_wbuf[1] =
			    scsb_fru_op(scsb, SLOT, slotnum,
			    SCTRL_RESET_BASE,
			    SCSB_FRU_OP_GET_REGDATA) |
			    scsb_fru_op(scsb, SLOT, slotnum,
			    SCTRL_RESET_BASE,
			    SCSB_FRU_OP_SET_REGBIT);
#ifdef	DEBUG		/* dont reset Alarm Card line unless in debug mode */
			if (alarm_card)
				i2cxferp->i2c_wbuf[1] |=
				    scsb_fru_op(scsb, ALARM, 1,
				    SCTRL_RESET_BASE,
				    SCSB_FRU_OP_SET_REGBIT);
#endif
		} else {
			i2cxferp->i2c_wbuf[1] =
			    scsb_fru_op(scsb, SLOT, slotnum,
			    SCTRL_RESET_BASE,
			    SCSB_FRU_OP_GET_REGDATA) &
			    ~(scsb_fru_op(scsb, SLOT, slotnum,
			    SCTRL_RESET_BASE,
			    SCSB_FRU_OP_SET_REGBIT));
#ifdef	DEBUG		/* dont Unreset Alarm Card line unless in debug mode */
			if (alarm_card)
				i2cxferp->i2c_wbuf[1] &=
				    scsb_fru_op(scsb, ALARM, 1,
				    SCTRL_RESET_BASE,
				    SCSB_FRU_OP_SET_REGBIT);
#endif
		}

		if (error = nct_i2c_transfer(scsb->scsb_phandle, i2cxferp)) {
			scsb->scsb_i2c_errcnt++;
			if (scsb->scsb_i2c_errcnt > scsb_err_threshold)
				scsb->scsb_err_flag = B_TRUE; /* latch error */
			mutex_exit(&scsb->scsb_mutex);
			if (!(scsb->scsb_state & SCSB_SSB_PRESENT)) {
				if (scsb->scsb_i2c_errcnt >= scsb_freeze_count)
					scsb_freeze(scsb);
			}
			cmn_err(CE_WARN, "%s#%d: reset_slot: error writing to"
			    " Reset regs (op=%d, data=%x)\n",
			    ddi_driver_name(scsb->scsb_dev),
			    ddi_get_instance(scsb->scsb_dev),
			    reset_flag, i2cxferp->i2c_wbuf[1]);
			scsb_free_i2ctx(scsb->scsb_phandle, i2cxferp);
			return (DDI_FAILURE);
		}

		scsb->scsb_i2c_errcnt = 0;
		/* now read back and update our scsb structure */
		i2cxferp->i2c_flags = I2C_WR_RD;
		i2cxferp->i2c_rlen = SCTRL_RESET_NUMREGS;
		i2cxferp->i2c_wbuf[0] = reg;
		i2cxferp->i2c_wlen = 1;
		if ((error = nct_i2c_transfer(scsb->scsb_phandle,
		    i2cxferp)) == 0) {
			scsb->scsb_i2c_errcnt = 0;
			scsb->scsb_data_reg[index]   = i2cxferp->i2c_rbuf[0];
			scsb->scsb_data_reg[index+1] = i2cxferp->i2c_rbuf[1];
		} else {
			scsb->scsb_i2c_errcnt++;
			if (scsb->scsb_i2c_errcnt > scsb_err_threshold)
				scsb->scsb_err_flag = B_TRUE; /* latch error */
			mutex_exit(&scsb->scsb_mutex);
			if (!(scsb->scsb_state & SCSB_SSB_PRESENT)) {
				if (scsb->scsb_i2c_errcnt >= scsb_freeze_count)
					scsb_freeze(scsb);
			}
			cmn_err(CE_WARN, "%s#%d: scsb_reset_slot: error"
			    " reading Reset regs (post reset)\n",
			    ddi_driver_name(scsb->scsb_dev),
			    ddi_get_instance(scsb->scsb_dev));
			scsb_free_i2ctx(scsb->scsb_phandle, i2cxferp);
			return (DDI_FAILURE);
		}
		/* XXX: P1.5 */
		DEBUG2("post-reset regs = %x,%x\n", scsb->scsb_data_reg[index],
		    scsb->scsb_data_reg[index+1]);
		val = scsb_fru_op(scsb, SLOT, slotnum, SCTRL_RESET_BASE,
		    SCSB_FRU_OP_GET_BITVAL);
#ifdef	DEBUG
		if (alarm_card)
			ac_val = scsb_fru_op(scsb, ALARM, 1, SCTRL_RESET_BASE,
			    SCSB_FRU_OP_GET_BITVAL);
#endif
		if (val && (reset_flag == SCSB_UNRESET_SLOT)) {
			cmn_err(CE_WARN, "Cannot UnReset Slot %d (reg=%x)\n",
			    pslotnum,
			    scsb_fru_op(scsb, SLOT, slotnum,
			    SCTRL_RESET_BASE,
			    SCSB_FRU_OP_GET_REGDATA));
#ifdef	DEBUG
			if (alarm_card) {
				if (ac_val)
					cmn_err(CE_WARN, "Cannot Unreset "
					    "Alarm_RST#.\n");
			}
#endif
		}
		else
			if ((val == 0) && (reset_flag == SCSB_RESET_SLOT)) {
				cmn_err(CE_WARN, "Cannot Reset Slot %d, "
				    "reg=%x\n", pslotnum,
				    scsb_fru_op(scsb, SLOT, slotnum,
				    SCTRL_RESET_BASE,
				    SCSB_FRU_OP_GET_REGDATA));
#ifdef	DEBUG
				if (alarm_card) {
					if (!ac_val)
						cmn_err(CE_WARN, "Cannot reset "
						    "Alarm_RST#.\n");
				}
#endif
			}
	}

	mutex_exit(&scsb->scsb_mutex);
	scsb_free_i2ctx(scsb->scsb_phandle, i2cxferp);

	return (error);
}

int
scsb_connect_slot(scsb_state_t *scsb, int pslotnum, int healthy)
{
	int slotnum, count = 0, val;
	int slot_flag = 0;

	/*
	 * If Power needs to be handled, it should be done here.
	 * Since there is no power handling for now, lets disable
	 * reset, wait for healthy to come on and then call it
	 * connected.
	 * If HLTHY# does not come on (in how long is the question)
	 * then we stay disconnected.
	 */
	slotnum = tonga_psl_to_ssl(scsb, pslotnum);

	/*
	 * P1.5 doesnt require polling healthy as we get an
	 * interrupt. So we could just update our state as disconnected
	 * and return waiting for the healthy# interrupt. To make it
	 * more efficient, lets poll for healthy# a short while since we are
	 * in the interrupt context anyway. If we dont get a healthy# we
	 * return, and then wait for the interrupt. Probably the warning
	 * message needs to be removed then. Need a PROM check flag here.
	 */
	while ((healthy == B_FALSE) && (count < scsb_healthy_poll_count)) {
		if (scsb_read_bhealthy(scsb) != 0)
			return (DDI_FAILURE);
		val = scsb_fru_op(scsb, SLOT, slotnum, SCTRL_BHLTHY_BASE,
		    SCSB_FRU_OP_GET_BITVAL);
		if (val) {
			healthy = B_TRUE;
			break;
		}
		count++;
		drv_usecwait(100);	/* cant delay(9f) in intr context */
	}

	if (healthy == B_FALSE && count == scsb_healthy_poll_count) {
		if (scsb_debug & 0x00004000)
			cmn_err(CE_WARN, "%s#%d: no HEALTHY# signal on"
			    " slot %d", ddi_driver_name(scsb->scsb_dev),
			    ddi_get_instance(scsb->scsb_dev), pslotnum);
	}

	if ((scsb_is_alarm_card_slot(scsb, pslotnum) == B_TRUE) &&
	    (scsb->scsb_hsc_state & SCSB_ALARM_CARD_PRES))
		slot_flag = ALARM_CARD_ON_SLOT;
	return (hsc_slot_occupancy(pslotnum, 1, slot_flag, healthy));
}

int
scsb_disconnect_slot(scsb_state_t *scsb, int occupied, int slotnum)
{
	int slot_flag = 0;

	/* Reset is must at extraction. Move on even if failure. */
	if (scsb_reset_slot(scsb, slotnum, SCSB_RESET_SLOT) != 0) {
		/*
		 * If board is still in slot, which means there is a manual
		 * disconnection in progress, return failure.
		 * Otherwise, a board was removed anyway; so we need to
		 * update the status and move on.
		 */
		if (occupied == B_TRUE)
			return (DDI_FAILURE);
	}
	/*
	 * the following bug needs to be fixed.
	 * When this function is called from scsb_intr, scsb_state already
	 * clears the 'AC card present' bit.
	 * However, hsc module doesn't depend on slot_flag during removal.
	 */
	if ((scsb_is_alarm_card_slot(scsb, slotnum) == B_TRUE) &&
	    (scsb->scsb_hsc_state & SCSB_ALARM_CARD_PRES))
		slot_flag = ALARM_CARD_ON_SLOT;
	return (hsc_slot_occupancy(slotnum, occupied, slot_flag, B_FALSE));
}

static int
scsb_is_alarm_card_slot(scsb_state_t *scsb, int slotnum)
{
	return ((scsb->ac_slotnum == slotnum)? B_TRUE:B_FALSE);
}

/*
 * Invoked both by the hsc and the scsb module to exchanges necessary
 * information regarding the alarm card.
 * scsb calls this function to unconfigure the alarm card while the
 * hsc calls this function at different times to check busy status,
 * and during post hotswap insert operation so that the user process
 * if one waiting can configure the alarm card.
 */
int
scsb_hsc_ac_op(scsb_state_t *scsb, int pslotnum, int op)
{
	int		rc = B_FALSE;
	uint32_t	event_code;

	if (!(scsb->scsb_hsc_state & SCSB_HSC_INIT &&
	    scsb->scsb_hsc_state & SCSB_ALARM_CARD_PRES)) {
		cmn_err(CE_WARN,
		    "scsb: HSC not initialized or AC not present!");
		return (rc);
	}
	switch (op) {
		/* hsc -> scsb */
		case SCSB_HSC_AC_BUSY:
			if (scsb->scsb_hsc_state & SCSB_ALARM_CARD_IN_USE)
				rc = B_TRUE;
			break;

		/* API -> scsb */
		/*
		 * NOTE: this could be called multiple times from envmond if
		 * the daemon is reinitialized with SIGHUP, or stopped and
		 * restarted.
		 */
		case SCSB_HSC_AC_SET_BUSY:
			DEBUG0("AC SET BUSY\n");
			if (scsb_debug & 0x00010000) {
				cmn_err(CE_NOTE,
				    "scsb_hsc_ac_op(SCSB_HSC_AC_SET_BUSY)");
			}
			scsb->scsb_hsc_state |= SCSB_ALARM_CARD_IN_USE;
			rc = B_TRUE;
			break;

		/* hsc -> scsb */
		case SCSB_HSC_AC_CONFIGURED:
			DEBUG0("AC configured\n");
			if (scsb_debug & 0x00010000) {
				cmn_err(CE_NOTE,
				"scsb_hsc_ac_op(SCSB_HSC_AC_CONFIGURED)");
			}
			/*
			 * wakeup anyone waiting on AC to be configured
			 * Send the ALARM_CARD_CONFIGURE Event to all scsb
			 * open streams.
			 */
			event_code = SCTRL_EVENT_ALARM_INSERTION;
			(void) scsb_queue_ops(scsb, QPUT_INT32, 1,
			    &event_code, "scsb_hsc_ac_op");
			rc = B_TRUE;
			break;

		/* hsc -> scsb */
		case SCSB_HSC_AC_REMOVAL_ALERT:
			DEBUG0("AC removal alert\n");
			if (scsb_debug & 0x00010000) {
				cmn_err(CE_NOTE,
				"scsb_hsc_ac_op(SCSB_HSC_AC_REMOVAL_ALERT)");
			}
			/*
			 * Inform (envmond)alarmcard.so that it should save
			 * the AC configuration, stop the
			 * heartbeat, and shutdown the RSC link.
			 */
			event_code = SCTRL_EVENT_ALARM_REMOVAL;
			(void) scsb_queue_ops(scsb, QPUT_INT32, 1,
			    &event_code, "scsb_hsc_ac_op");
			rc = B_TRUE;
			break;

		/* API -> scsb -> hsc */
		case SCSB_HSC_AC_UNCONFIGURE:
			DEBUG0("AC unconfigure\n");
			if (scsb_debug & 0x00010000) {
				cmn_err(CE_NOTE,
				    "scsb_hsc_ac_op(SCSB_HSC_AC_UNCONFIG"
				    "URE), AC NOT BUSY");
			}
			/*
			 * send notification back to HSC to
			 * unconfigure the AC, now that the env monitor
			 * has given permission to do so.
			 */
			scsb->scsb_hsc_state &= ~SCSB_ALARM_CARD_IN_USE;
			hsc_ac_op((int)scsb->scsb_instance, pslotnum,
			    SCSB_HSC_AC_UNCONFIGURE, NULL);
			rc = B_TRUE;
			break;
		default:
			break;
	}

	return (rc);
}

static void
scsb_healthy_intr(scsb_state_t *scsb, int pslotnum)
{
	int val, slotnum;
	int healthy = B_FALSE;

	DEBUG1("Healthy Intr on slot %d\n", pslotnum);
	/*
	 * The interrupt source register can have the healthy
	 * bit set for non-existing slot, e.g slot 7 on Tonga.
	 * It can also be seen on the Tonga CPU slot. So we make
	 * sure we have a valid slot before proceeding.
	 */
	if (scsb->scsb_state & SCSB_IS_TONGA) {
		if (pslotnum > TG_MAX_SLOTS || pslotnum == SC_TG_CPU_SLOT) {
			if (scsb_debug & 0x08000000)
				cmn_err(CE_NOTE, "Healthy interrupt bit set for"
				    " slot %d", pslotnum);
		return;
		}
	} else {
		if (pslotnum > MC_MAX_SLOTS || pslotnum == SC_MC_CPU_SLOT ||
		    (scsb->scsb_hsc_state & SCSB_HSC_CTC_PRES &&
		    pslotnum == SC_MC_CTC_SLOT)) {
			if (scsb_debug & 0x08000000)
				cmn_err(CE_NOTE, "Healthy interrupt bit set for"
				    " slot %d", pslotnum);
		return;
		}
	}

	/*
	 * The board healthy registers are already read before entering
	 * this routine
	 */
	slotnum = tonga_psl_to_ssl(scsb, pslotnum);

	/*
	 * P1.5. Following works since slots 1 through 8 are in the same reg
	 */
	val = scsb_fru_op(scsb, SLOT, slotnum, SCTRL_BHLTHY_BASE,
	    SCSB_FRU_OP_GET_BITVAL);
	if (val)
		healthy = B_TRUE;
	(void) scsb_hsc_board_healthy(pslotnum, healthy);
}

/*
 * This function will try to read from scsb irrespective of whether
 * SSB is present or SCB is frozen, to get the health kstat information.
 */
static int
scsb_blind_read(scsb_state_t *scsb, int op, uchar_t reg, int len,
				uchar_t *rwbuf, int i2c_alloc)
{
	i2c_transfer_t	*i2cxferp;
	int		i, rlen, wlen, error = 0;

	if (scsb_debug & 0x0800) {
		cmn_err(CE_NOTE, "scsb_rdwr_register(scsb,%s,%x,%x,buf):",
		    (op == I2C_WR) ? "write" : "read",  reg, len);
	}

	if (i2c_alloc) {
		i2cxferp = scsb_alloc_i2ctx(scsb->scsb_phandle, I2C_NOSLEEP);
		if (i2cxferp == NULL) {
			if (scsb_debug & 0x0042)
				cmn_err(CE_WARN, "scsb_rdwr_register: "
				    "i2ctx allocation failure");
			return (ENOMEM);
		}
	} else {
		i2cxferp = scsb->scsb_i2ctp;
	}
	switch (op) {
	case I2C_WR:
		wlen = len + 1;	/* add the address */
		rlen = 0;
		i2cxferp->i2c_wbuf[0] = reg;
		for (i = 0; i < len; ++i) {
				i2cxferp->i2c_wbuf[1 + i] = rwbuf[i];
			if (scsb_debug & 0x0080)
				cmn_err(CE_NOTE,
				"scsb_rdwr_register: writing rwbuf[%d]=0x%x",
				    i, rwbuf[i]);
		}
		break;
	case I2C_WR_RD:
		wlen = 1;	/* for the address */
		rlen = len;
		i2cxferp->i2c_wbuf[0] = reg;
		break;
	default:
		if (i2c_alloc)
			scsb_free_i2ctx(scsb->scsb_phandle, i2cxferp);
		return (EINVAL);
	}
	/* select the register address */
	i2cxferp->i2c_flags = op;
	i2cxferp->i2c_rlen = rlen;
	i2cxferp->i2c_wlen = wlen;
	i2cxferp->i2c_wbuf[0] = reg;
	scsb->scsb_kstat_flag = B_TRUE;	/* we did a i2c transaction */
	if (error = nct_i2c_transfer(scsb->scsb_phandle, i2cxferp)) {
		error = EIO;
	} else if (rlen) {
		/* copy to rwbuf[] */
		for (i = 0; i < len; ++i) {
			rwbuf[i] = i2cxferp->i2c_rbuf[i];
			if (scsb_debug & 0x0080)
				cmn_err(CE_NOTE,
				"scsb_rdwr_register: read rwbuf[%d]=0x%x",
				    i, rwbuf[i]);
		}
	}
	if (i2c_alloc)
		scsb_free_i2ctx(scsb->scsb_phandle, i2cxferp);
	if (error) {
		scsb->scsb_i2c_errcnt++;
		if (scsb->scsb_i2c_errcnt > scsb_err_threshold)
			scsb->scsb_err_flag = B_TRUE; /* latch error */
	} else {
		scsb->scsb_i2c_errcnt = 0;
	}

	return (error);
}

/*
 * This function will quiesce the PSM_INT line by masking the
 * global PSM_INT and writing 1 to SCB_INIT ( for P1.5 and later )
 * This effectively translates to writing 0x20 to 0xE1 register.
 */
static int
scsb_quiesce_psmint(scsb_state_t *scsb)
{
	register int	i;
	uchar_t	reg, wdata = 0;
	uchar_t	tmp_reg, intr_addr, clr_bits = 0;
	int error, iid, intr_idx, offset;

	/*
	 * For P1.5, set the SCB_INIT bit in the System Command register,
	 * and disable global PSM_INT. Before this we need to read the
	 * interrupt source register corresponding to INIT_SCB and
	 * clear if set.
	 */
	if (IS_SCB_P15) {
		/*
		 * Read INTSRC6 and write back 0x20 in case INIT_SCB is set
		 */
		intr_addr = SCSB_REG_ADDR(SCTRL_INTSRC_BASE);
		tmp_reg = SCSB_REG_ADDR(SCTRL_INTSRC_SCB_P15);
		iid = SCSB_REG_INDEX(intr_addr);
		intr_idx = SCSB_REG_INDEX(tmp_reg) - iid;
		offset = FRU_OFFSET(SCTRL_EVENT_SCB, SCTRL_INTPTR_BASE);
		clr_bits = 1 << offset;

		error = scsb_rdwr_register(scsb, I2C_WR_RD, tmp_reg,
		    1, &scb_intr_regs[intr_idx], 0);
		/*
		 * Now mask the global PSM_INT and write INIT_SCB in case
		 * this is an INIT_SCB interrupt
		 */
		wdata = 1 << SYS_OFFSET(SCTRL_SYS_SCB_INIT);
		i = SYS_REG_INDEX(SCTRL_SYS_SCB_INIT, SCTRL_SYS_CMD_BASE);
		reg = SCSB_REG_ADDR(i);
		error = scsb_rdwr_register(scsb, I2C_WR, reg, 1,
		    &wdata, 0);

		if (scb_intr_regs[intr_idx] & clr_bits) {
			/*
			 * There is an SCB_INIT interrupt, which we must clear
			 * first to keep SCB_INIT from keeping PSM_INT asserted.
			 */
			error = scsb_rdwr_register(scsb, I2C_WR, tmp_reg,
			    1, &clr_bits, 0);
		}

		if (error) {
			cmn_err(CE_WARN, "scsb%d:scsb_quiesce_psmint: "
			    " I2C TRANSFER Failed", scsb->scsb_instance);
			if (scsb_debug & 0x0006) {
				cmn_err(CE_NOTE, "scsb_attach: "
				    " failed to set SCB_INIT");
			}
		}
		scsb->scsb_state &= ~SCSB_PSM_INT_ENABLED;
	} else { /* P1.0 or earlier */
		/*
		 * read the interrupt source registers, and then
		 * write them back.
		 */
		/* read the interrupt register from scsb */
		if (error = scsb_rdwr_register(scsb, I2C_WR_RD, intr_addr,
		    SCTRL_INTR_NUMREGS, scb_intr_regs, 0)) {
			cmn_err(CE_WARN, "scsb_intr: "
			    " Failed read of interrupt registers.");
			scsb->scsb_state &= ~SCSB_IN_INTR;
		}

		/*
		 * Write to the interrupt source registers to stop scsb
		 * from interrupting.
		 */
		if (error = scsb_rdwr_register(scsb, I2C_WR, intr_addr,
		    SCTRL_INTR_NUMREGS, scb_intr_regs, 0)) {
			cmn_err(CE_WARN, "scsb_intr: Failed write to interrupt"
			    " registers.");
			scsb->scsb_state &= ~SCSB_IN_INTR;
		}

	}

	if (error)
		return (DDI_FAILURE);
	else
		return (DDI_SUCCESS);
}

/*
 * Enables or disables the global PSM_INT interrupt for P1.5, depending
 * on the flag, flag = 0 => disable, else enable.
 */
static int
scsb_toggle_psmint(scsb_state_t *scsb, int enable)
{
	int i;
	uchar_t reg, on = 0, rmask = 0x0, off = 0;

	if (enable == B_TRUE) {
		on = 1 << SYS_OFFSET(SCTRL_SYS_PSM_INT_ENABLE);
	} else {
		off = 1 << SYS_OFFSET(SCTRL_SYS_PSM_INT_ENABLE);
	}

	i = SYS_REG_INDEX(SCTRL_SYS_PSM_INT_ENABLE, SCTRL_SYS_CMD_BASE);
	reg = SCSB_REG_ADDR(i);
	if (scsb_write_mask(scsb, reg, rmask, on, off)) {
		cmn_err(CE_WARN, "scsb_toggle_psmint: Cannot turn %s PSM_INT",
		    enable == 1 ? "on" : "off");
		return (DDI_FAILURE);
	}
	if (enable == 0) {
		scsb->scsb_state &= ~SCSB_PSM_INT_ENABLED;
	} else {
		scsb->scsb_state |= SCSB_PSM_INT_ENABLED;
	}

	return (DDI_SUCCESS);
}

/*
 * This routine is to be used by all the drivers using this i2c bus
 * to synchronize their transfer operations.
 */
int
nct_i2c_transfer(i2c_client_hdl_t i2c_hdl, i2c_transfer_t *i2c_tran)
{
	int retval, initmux = nct_mutex_init;

	/*
	 * If scsb interrupt mutex is initialized, also hold the
	 * interrupt mutex to let the i2c_transfer() to complete
	 */

	if (initmux & MUTEX_INIT) {
		mutex_enter(scb_intr_mutex);
	}

	retval = i2c_transfer(i2c_hdl, i2c_tran);

	if (initmux & MUTEX_INIT) {
		mutex_exit(scb_intr_mutex);
	}

	return (retval);
}
