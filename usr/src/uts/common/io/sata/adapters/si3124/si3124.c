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
 * SiliconImage 3124/3132/3531 sata controller driver
 */

/*
 *
 *
 * 			Few Design notes
 *
 *
 * I. General notes
 *
 * Even though the driver is named as si3124, it is actually meant to
 * work with SiI3124, SiI3132 and SiI3531 controllers.
 *
 * The current file si3124.c is the main driver code. The si3124reg.h
 * holds the register definitions from SiI 3124/3132/3531 data sheets. The
 * si3124var.h holds the driver specific definitions which are not
 * directly derived from data sheets.
 *
 *
 * II. Data structures
 *
 * si_ctl_state_t: This holds the driver private information for each
 * 	controller instance. Each of the sata ports within a single
 *	controller are represented by si_port_state_t. The
 *	sictl_global_acc_handle and sictl_global_address map the
 *	controller-wide global register space and are derived from pci
 *	BAR 0. The sictl_port_acc_handle and sictl_port_addr map the
 *	per-port register space and are derived from pci BAR 1.
 *
 * si_port_state_t: This holds the per port information. The siport_mutex
 *	holds the per port mutex. The siport_pending_tags is the bit mask of
 * 	commands posted to controller. The siport_slot_pkts[] holds the
 * 	pending sata packets. The siport_port_type holds the device type
 *	connected directly to the port while the siport_portmult_state
 * 	holds the similar information for the devices behind a port
 *	multiplier.
 *
 * si_prb_t: This contains the PRB being posted to the controller.
 *	The two SGE entries contained within si_prb_t itself are not
 *	really used to hold any scatter gather entries. The scatter gather
 *	list is maintained external to PRB and is linked from one
 * 	of the contained SGEs inside the PRB. For atapi devices, the
 *	first contained SGE holds the PACKET and second contained
 *	SGE holds the link to an external SGT. For non-atapi devices,
 *	the first contained SGE works as link to external SGT while
 *	second SGE is blank.
 *
 * external SGT tables: The external SGT tables pointed to from
 *	within si_prb_t are actually abstracted as si_sgblock_t. Each
 *	si_sgblock_t contains si_dma_sg_number number of
 *	SGT tables linked in a chain. Currently this default value of
 *	SGT tables per block is at 85 as  which translates
 *	to a maximum of 256 dma cookies per single dma transfer.
 *	This value can be changed through the global var: si_dma_sg_number
 *	in /etc/system, the maxium is at 21844 as which translates to 65535
 *	dma cookies per single dma transfer.
 *
 *
 * III. Driver operation
 *
 * Command Issuing: We use the "indirect method of command issuance". The
 *	PRB contains the command [and atapi PACKET] and a link to the
 *	external SGT chain. We write the physical address of the PRB into
 *	command activation register. There are 31 command slots for
 *	each port. After posting a command, we remember the posted slot &
 *	the sata packet in siport_pending_tags & siport_slot_pkts[]
 *	respectively.
 *
 * Command completion: On a successful completion, intr_command_complete()
 * 	receives the control. The slot_status register holds the outstanding
 *	commands. Any reading of slot_status register automatically clears
 *	the interrupt. By comparing the slot_status register contents with
 *	per port siport_pending_tags, we determine which of the previously
 *	posted commands have finished.
 *
 * Timeout handling: Every 5 seconds, the watchdog handler scans thru the
 * 	pending packets. The satapkt->satapkt_hba_driver_private field is
 * 	overloaded with the count of watchdog cycles a packet has survived.
 *	If a packet has not completed within satapkt->satapkt_time, it is
 *	failed with error code of SATA_PKT_TIMEOUT. There is one watchdog
 *	handler running for each instance of controller.
 *
 * Error handling: For 3124, whenever any single command has encountered
 *	an error, the whole port execution completely stalls; there is no
 *	way of canceling or aborting the particular failed command. If
 * 	the port is connected to a port multiplier, we can however RESUME
 *	other non-error devices connected to the port multiplier.
 *	The only way to recover the failed commands is to either initialize
 *	the port or reset the port/device. Both port initialize and reset
 *	operations result in discarding any of pending commands on the port.
 *	All such discarded commands are sent up to framework with PKT_RESET
 *	satapkt_reason. The assumption is that framework [and sd] would
 *	retry these commands again. The failed command itself however is
 *	sent up with PKT_DEV_ERROR.
 *
 *	Here is the implementation strategy based on SiliconImage email
 *	regarding how they handle the errors for their Windows driver:
 *
 *	  a) for DEVICEERROR:
 *		If the port is connected to port multiplier, then
 *		 1) Resume the port
 *		 2) Wait for all the non-failed commands to complete
 *		 3) Perform a Port Initialize
 *
 *		If the port is not connected to port multiplier, issue
 *		a Port Initialize.
 *
 *	  b) for SDBERROR: [SDBERROR means failed command is an NCQ command]
 * 		Handle exactly like DEVICEERROR handling.
 *		After the Port Initialize done, do a Read Log Extended.
 *
 *	  c) for SENDFISERROR:
 *		If the port is connected to port multiplier, then
 *		 1) Resume the port
 *		 2) Wait for all the non-failed commands to complete
 *		 3) Perform a Port Initialize
 *
 *		If the port is not connected to port multiplier, issue
 * 		a Device Reset.
 *
 *	  d) for DATAFISERROR:
 *		If the port was executing an NCQ command, issue a Device
 *		Reset.
 *
 *		Otherwise, follow the same error recovery as DEVICEERROR.
 *
 *	  e) for any other error, simply issue a Device Reset.
 *
 * 	To synchronize the interactions between various control flows (e.g.
 *	error recovery, timeout handling, si_poll_timeout, incoming flow
 *	from framework etc.), the following precautions are taken care of:
 *		a) During mopping_in_progress, no more commands are
 *		accepted from the framework.
 *
 *		b) While draining the port multiplier commands, we should
 *		handle the possibility of any of the other waited commands
 *		failing (possibly with a different error code)
 *
 * Atapi handling: For atapi devices, we use the first SGE within the PRB
 * 	to fill the scsi cdb while the second SGE points to external SGT.
 *
 * Queuing: Queue management is achieved external to the driver inside sd.
 *	Based on sata_hba_tran->qdepth and IDENTIFY data, the framework
 *	enables or disables the queuing. The qdepth for si3124 is 31
 *	commands.
 *
 * Port Multiplier: Enumeration of port multiplier is handled during the
 *	controller initialization and also during the a hotplug operation.
 *	Current logic takes care of situation where a port multiplier
 *	is hotplugged into a port which had a cdisk connected previously
 *	and vice versa.
 *
 * Register poll timeouts: Currently most of poll timeouts on register
 *	reads is set to 0.5 seconds except for a value of 10 seconds
 *	while reading the device signature. [Such a big timeout values
 *	for device signature were found needed during cold reboots
 *	for devices behind port multiplier].
 *
 *
 * IV. Known Issues
 *
 * 1) Currently the atapi packet length is hard coded to 12 bytes
 *	This is wrong. The framework should determine it just like they
 * 	determine ad_cdb_len in legacy atapi.c. It should even reject
 *	init_pkt() for greater CDB lengths. See atapi.c. Revisit this
 *	in 2nd phase of framework project.
 *
 * 2) Do real REQUEST SENSE command instead of faking for ATAPI case.
 *
 */


#include <sys/note.h>
#include <sys/scsi/scsi.h>
#include <sys/pci.h>
#include <sys/sata/sata_hba.h>
#include <sys/sata/adapters/si3124/si3124reg.h>
#include <sys/sata/adapters/si3124/si3124var.h>
#include <sys/sdt.h>

/*
 * FMA header files
 */
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

/*
 * Function prototypes for driver entry points
 */
static	int si_attach(dev_info_t *, ddi_attach_cmd_t);
static	int si_detach(dev_info_t *, ddi_detach_cmd_t);
static	int si_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static	int si_power(dev_info_t *, int, int);
static	int si_quiesce(dev_info_t *);
/*
 * Function prototypes for SATA Framework interfaces
 */
static	int si_register_sata_hba_tran(si_ctl_state_t *);
static	int si_unregister_sata_hba_tran(si_ctl_state_t *);

static	int si_tran_probe_port(dev_info_t *, sata_device_t *);
static	int si_tran_start(dev_info_t *, sata_pkt_t *spkt);
static	int si_tran_abort(dev_info_t *, sata_pkt_t *, int);
static	int si_tran_reset_dport(dev_info_t *, sata_device_t *);
static	int si_tran_hotplug_port_activate(dev_info_t *, sata_device_t *);
static	int si_tran_hotplug_port_deactivate(dev_info_t *, sata_device_t *);

/*
 * Local function prototypes
 */

static	int si_alloc_port_state(si_ctl_state_t *, int);
static	void si_dealloc_port_state(si_ctl_state_t *, int);
static	int si_alloc_sgbpool(si_ctl_state_t *, int);
static	void si_dealloc_sgbpool(si_ctl_state_t *, int);
static	int si_alloc_prbpool(si_ctl_state_t *, int);
static	void si_dealloc_prbpool(si_ctl_state_t *, int);

static void si_find_dev_signature(si_ctl_state_t *, si_port_state_t *,
						int, int);
static void si_poll_cmd(si_ctl_state_t *, si_port_state_t *, int, int,
						sata_pkt_t *);
static	int si_claim_free_slot(si_ctl_state_t *, si_port_state_t *, int);
static	int si_deliver_satapkt(si_ctl_state_t *, si_port_state_t *, int,
						sata_pkt_t *);

static	int si_initialize_controller(si_ctl_state_t *);
static	void si_deinitialize_controller(si_ctl_state_t *);
static void si_init_port(si_ctl_state_t *, int);
static	int si_enumerate_port_multiplier(si_ctl_state_t *,
						si_port_state_t *, int);
static int si_read_portmult_reg(si_ctl_state_t *, si_port_state_t *,
						int, int, int, uint32_t *);
static int si_write_portmult_reg(si_ctl_state_t *, si_port_state_t *,
						int, int, int, uint32_t);
static void si_set_sense_data(sata_pkt_t *, int);

static uint_t si_intr(caddr_t, caddr_t);
static int si_intr_command_complete(si_ctl_state_t *,
					si_port_state_t *, int);
static void si_schedule_intr_command_error(si_ctl_state_t *,
					si_port_state_t *, int);
static void si_do_intr_command_error(void *);
static int si_intr_command_error(si_ctl_state_t *,
					si_port_state_t *, int);
static void si_error_recovery_DEVICEERROR(si_ctl_state_t *,
					si_port_state_t *, int);
static void si_error_recovery_SDBERROR(si_ctl_state_t *,
					si_port_state_t *, int);
static void si_error_recovery_DATAFISERROR(si_ctl_state_t *,
					si_port_state_t *, int);
static void si_error_recovery_SENDFISERROR(si_ctl_state_t *,
					si_port_state_t *, int);
static void si_error_recovery_default(si_ctl_state_t *,
					si_port_state_t *, int);
static uint8_t si_read_log_ext(si_ctl_state_t *,
					si_port_state_t *si_portp, int);
static void si_log_error_message(si_ctl_state_t *, int, uint32_t);
static int si_intr_port_ready(si_ctl_state_t *, si_port_state_t *, int);
static int si_intr_pwr_change(si_ctl_state_t *, si_port_state_t *, int);
static int si_intr_phy_ready_change(si_ctl_state_t *, si_port_state_t *, int);
static int si_intr_comwake_rcvd(si_ctl_state_t *, si_port_state_t *, int);
static int si_intr_unrecognised_fis(si_ctl_state_t *, si_port_state_t *, int);
static int si_intr_dev_xchanged(si_ctl_state_t *, si_port_state_t *, int);
static int si_intr_decode_err_threshold(si_ctl_state_t *,
					si_port_state_t *, int);
static int si_intr_crc_err_threshold(si_ctl_state_t *, si_port_state_t *, int);
static int si_intr_handshake_err_threshold(si_ctl_state_t *,
					si_port_state_t *, int);
static int si_intr_set_devbits_notify(si_ctl_state_t *, si_port_state_t *, int);

static	void si_enable_port_interrupts(si_ctl_state_t *, int);
static	void si_enable_all_interrupts(si_ctl_state_t *);
static	void si_disable_port_interrupts(si_ctl_state_t *, int);
static	void si_disable_all_interrupts(si_ctl_state_t *);
static 	void fill_dev_sregisters(si_ctl_state_t *, int, sata_device_t *);
static 	int si_add_legacy_intrs(si_ctl_state_t *);
static 	int si_add_msi_intrs(si_ctl_state_t *);
static 	void si_rem_intrs(si_ctl_state_t *);

static	int si_reset_dport_wait_till_ready(si_ctl_state_t *,
				si_port_state_t *, int, int);
static int si_clear_port(si_ctl_state_t *, int);
static void si_schedule_port_initialize(si_ctl_state_t *,
				si_port_state_t *, int);
static void si_do_initialize_port(void *);
static	int si_initialize_port_wait_till_ready(si_ctl_state_t *, int);

static void si_timeout_pkts(si_ctl_state_t *, si_port_state_t *, int, uint32_t);
static	void si_watchdog_handler(si_ctl_state_t *);

/*
 * FMA Prototypes
 */
static void si_fm_init(si_ctl_state_t *);
static void si_fm_fini(si_ctl_state_t *);
static int si_fm_error_cb(dev_info_t *, ddi_fm_error_t *, const void *);
static int si_check_acc_handle(ddi_acc_handle_t);
static int si_check_dma_handle(ddi_dma_handle_t);
static int si_check_ctl_handles(si_ctl_state_t *);
static int si_check_port_handles(si_port_state_t *);
static void si_fm_ereport(si_ctl_state_t *, char *, char *);

static	void si_log(si_ctl_state_t *, si_port_state_t *, char *, ...);

static void si_copy_out_regs(sata_cmd_t *, si_ctl_state_t *, uint8_t, uint8_t);

/*
 * DMA attributes for the data buffer
 */

static ddi_dma_attr_t buffer_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo: lowest bus address */
	0xffffffffffffffffull,	/* dma_attr_addr_hi: highest bus address */
	0xffffffffull,		/* dma_attr_count_max i.e. for one cookie */
	1,			/* dma_attr_align: single byte aligned */
	1,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_maxxfer i.e. includes all cookies */
	0xffffffffull,		/* dma_attr_seg */
	SI_DEFAULT_SGL_LENGTH,	/* dma_attr_sgllen */
	512,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};

/*
 * DMA attributes for incore RPB and SGT pool
 */
static ddi_dma_attr_t prb_sgt_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo: lowest bus address */
	0xffffffffffffffffull,	/* dma_attr_addr_hi: highest bus address */
	0xffffffffull,		/* dma_attr_count_max i.e. for one cookie */
	8,			/* dma_attr_align: quad word aligned */
	1,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_maxxfer i.e. includes all cookies */
	0xffffffffull,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};

/* Device access attributes */
static ddi_device_acc_attr_t accattr = {
    DDI_DEVICE_ATTR_V1,
    DDI_STRUCTURE_LE_ACC,
    DDI_STRICTORDER_ACC,
    DDI_DEFAULT_ACC
};


static struct dev_ops sictl_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	si_getinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	si_attach,		/* attach */
	si_detach,		/* detach */
	nodev,			/* no reset */
	(struct cb_ops *)0,	/* driver operations */
	NULL,			/* bus operations */
	si_power,		/* power */
	si_quiesce,		/* devo_quiesce */
};

static sata_tran_hotplug_ops_t si_tran_hotplug_ops = {
	SATA_TRAN_HOTPLUG_OPS_REV_1,
	si_tran_hotplug_port_activate,
	si_tran_hotplug_port_deactivate
};


static int si_watchdog_timeout = 5; /* 5 seconds */
static int si_watchdog_tick;

extern struct mod_ops mod_driverops;

static  struct modldrv modldrv = {
	&mod_driverops,	/* driverops */
	"si3124 driver",
	&sictl_dev_ops,	/* driver ops */
};

static  struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};


/* The following are needed for si_log() */
static kmutex_t si_log_mutex;
static char si_log_buf[SI_LOGBUF_LEN];
uint32_t si_debug_flags =
    SIDBG_ERRS|SIDBG_INIT|SIDBG_EVENT|SIDBG_TIMEOUT|SIDBG_RESET;

static int is_msi_supported = 0;

/*
 * The below global variables are tunable via /etc/system
 *
 * si_dma_sg_number
 */

int si_dma_sg_number = SI_DEFAULT_SGT_TABLES_PER_PRB;

/* Opaque state pointer to be initialized by ddi_soft_state_init() */
static void *si_statep	= NULL;

/*
 *  si3124 module initialization.
 *
 */
int
_init(void)
{
	int	error;

	error = ddi_soft_state_init(&si_statep, sizeof (si_ctl_state_t), 0);
	if (error != 0) {
		return (error);
	}

	mutex_init(&si_log_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((error = sata_hba_init(&modlinkage)) != 0) {
		mutex_destroy(&si_log_mutex);
		ddi_soft_state_fini(&si_statep);
		return (error);
	}

	error = mod_install(&modlinkage);
	if (error != 0) {
		sata_hba_fini(&modlinkage);
		mutex_destroy(&si_log_mutex);
		ddi_soft_state_fini(&si_statep);
		return (error);
	}

	si_watchdog_tick = drv_usectohz((clock_t)si_watchdog_timeout * 1000000);

	return (error);
}

/*
 * si3124 module uninitialize.
 *
 */
int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);
	if (error != 0) {
		return (error);
	}

	/* Remove the resources allocated in _init(). */
	sata_hba_fini(&modlinkage);
	mutex_destroy(&si_log_mutex);
	ddi_soft_state_fini(&si_statep);

	return (error);
}

/*
 * _info entry point
 *
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * The attach entry point for dev_ops.
 *
 * We initialize the controller, initialize the soft state, register
 * the interrupt handlers and then register ourselves with sata framework.
 */
static int
si_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	si_ctl_state_t *si_ctlp;
	int instance;
	int status;
	int attach_state;
	int intr_types;
	sata_device_t sdevice;

	SIDBG(SIDBG_ENTRY, "si_attach enter", NULL);
	instance = ddi_get_instance(dip);
	attach_state = ATTACH_PROGRESS_NONE;

	switch (cmd) {

	case DDI_ATTACH:

		/* Allocate si_softc. */
		status = ddi_soft_state_zalloc(si_statep, instance);
		if (status != DDI_SUCCESS) {
			goto err_out;
		}

		si_ctlp = ddi_get_soft_state(si_statep, instance);
		si_ctlp->sictl_devinfop = dip;

		attach_state |= ATTACH_PROGRESS_STATEP_ALLOC;

		/* Initialize FMA */
		si_ctlp->fm_capabilities = ddi_getprop(DDI_DEV_T_ANY, dip,
		    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "fm-capable",
		    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
		    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);

		si_fm_init(si_ctlp);

		attach_state |= ATTACH_PROGRESS_INIT_FMA;

		/* Configure pci config space handle. */
		status = pci_config_setup(dip, &si_ctlp->sictl_pci_conf_handle);
		if (status != DDI_SUCCESS) {
			goto err_out;
		}

		si_ctlp->sictl_devid =
		    pci_config_get16(si_ctlp->sictl_pci_conf_handle,
		    PCI_CONF_DEVID);
		switch (si_ctlp->sictl_devid) {
			case SI3124_DEV_ID:
				si_ctlp->sictl_num_ports = SI3124_MAX_PORTS;
				break;

			case SI3132_DEV_ID:
				si_ctlp->sictl_num_ports = SI3132_MAX_PORTS;
				break;

			case SI3531_DEV_ID:
				si_ctlp->sictl_num_ports = SI3531_MAX_PORTS;
				break;

			default:
				/*
				 * Driver should not have attatched if device
				 * ID is not already known and is supported.
				 */
				goto err_out;
		}

		attach_state |= ATTACH_PROGRESS_CONF_HANDLE;

		/* Now map the bar0; the bar0 contains the global registers. */
		status = ddi_regs_map_setup(dip,
		    PCI_BAR0,
		    (caddr_t *)&si_ctlp->sictl_global_addr,
		    0,
		    0,
		    &accattr,
		    &si_ctlp->sictl_global_acc_handle);
		if (status != DDI_SUCCESS) {
			goto err_out;
		}

		attach_state |= ATTACH_PROGRESS_BAR0_MAP;

		/* Now map bar1; the bar1 contains the port registers. */
		status = ddi_regs_map_setup(dip,
		    PCI_BAR1,
		    (caddr_t *)&si_ctlp->sictl_port_addr,
		    0,
		    0,
		    &accattr,
		    &si_ctlp->sictl_port_acc_handle);
		if (status != DDI_SUCCESS) {
			goto err_out;
		}

		attach_state |= ATTACH_PROGRESS_BAR1_MAP;

		/*
		 * Disable all the interrupts before adding interrupt
		 * handler(s). The interrupts shall be re-enabled selectively
		 * out of si_init_port().
		 */
		si_disable_all_interrupts(si_ctlp);

		/* Get supported interrupt types. */
		if (ddi_intr_get_supported_types(dip, &intr_types)
		    != DDI_SUCCESS) {
			SIDBG_C(SIDBG_INIT, si_ctlp,
			    "ddi_intr_get_supported_types failed", NULL);
			goto err_out;
		}

		SIDBG_C(SIDBG_INIT, si_ctlp,
		    "ddi_intr_get_supported_types() returned: 0x%x",
		    intr_types);

		if (is_msi_supported && (intr_types & DDI_INTR_TYPE_MSI)) {
			SIDBG_C(SIDBG_INIT, si_ctlp,
			    "Using MSI interrupt type", NULL);

			/*
			 * Try MSI first, but fall back to legacy if MSI
			 * attach fails.
			 */
			if (si_add_msi_intrs(si_ctlp) == DDI_SUCCESS) {
				si_ctlp->sictl_intr_type = DDI_INTR_TYPE_MSI;
				attach_state |= ATTACH_PROGRESS_INTR_ADDED;
				SIDBG_C(SIDBG_INIT, si_ctlp,
				    "MSI interrupt setup done", NULL);
			} else {
				SIDBG_C(SIDBG_INIT, si_ctlp,
				    "MSI registration failed "
				    "will try Legacy interrupts", NULL);
			}
		}

		if (!(attach_state & ATTACH_PROGRESS_INTR_ADDED) &&
		    (intr_types & DDI_INTR_TYPE_FIXED)) {
			/*
			 * Either the MSI interrupt setup has failed or only
			 * fixed interrupts are available on the system.
			 */
			SIDBG_C(SIDBG_INIT, si_ctlp,
			    "Using Legacy interrupt type", NULL);

			if (si_add_legacy_intrs(si_ctlp) == DDI_SUCCESS) {
				si_ctlp->sictl_intr_type = DDI_INTR_TYPE_FIXED;
				attach_state |= ATTACH_PROGRESS_INTR_ADDED;
				SIDBG_C(SIDBG_INIT, si_ctlp,
				    "Legacy interrupt setup done", NULL);
			} else {
				SIDBG_C(SIDBG_INIT, si_ctlp,
				    "legacy interrupt setup failed", NULL);
				goto err_out;
			}
		}

		if (!(attach_state & ATTACH_PROGRESS_INTR_ADDED)) {
			SIDBG_C(SIDBG_INIT, si_ctlp,
			    "si3124: No interrupts registered", NULL);
			goto err_out;
		}


		/* Initialize the mutex. */
		mutex_init(&si_ctlp->sictl_mutex, NULL, MUTEX_DRIVER,
		    (void *)(uintptr_t)si_ctlp->sictl_intr_pri);

		attach_state |= ATTACH_PROGRESS_MUTEX_INIT;

		/*
		 * Initialize the controller and driver core.
		 */
		si_ctlp->sictl_flags |= SI_ATTACH;
		status = si_initialize_controller(si_ctlp);
		si_ctlp->sictl_flags &= ~SI_ATTACH;
		if (status) {
			goto err_out;
		}

		attach_state |= ATTACH_PROGRESS_HW_INIT;

		if (si_register_sata_hba_tran(si_ctlp)) {
			SIDBG_C(SIDBG_INIT, si_ctlp,
			    "si3124: setting sata hba tran failed", NULL);
			goto err_out;
		}

		si_ctlp->sictl_timeout_id = timeout(
		    (void (*)(void *))si_watchdog_handler,
		    (caddr_t)si_ctlp, si_watchdog_tick);

		si_ctlp->sictl_power_level = PM_LEVEL_D0;

		return (DDI_SUCCESS);

	case DDI_RESUME:
		si_ctlp = ddi_get_soft_state(si_statep, instance);

		status = si_initialize_controller(si_ctlp);
		if (status) {
			return (DDI_FAILURE);
		}

		si_ctlp->sictl_timeout_id = timeout(
		    (void (*)(void *))si_watchdog_handler,
		    (caddr_t)si_ctlp, si_watchdog_tick);

		(void) pm_power_has_changed(dip, 0, PM_LEVEL_D0);

		/* Notify SATA framework about RESUME. */
		if (sata_hba_attach(si_ctlp->sictl_devinfop,
		    si_ctlp->sictl_sata_hba_tran,
		    DDI_RESUME) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		/*
		 * Notify the "framework" that it should reprobe ports to see
		 * if any device got changed while suspended.
		 */
		bzero((void *)&sdevice, sizeof (sata_device_t));
		sata_hba_event_notify(dip, &sdevice,
		    SATA_EVNT_PWR_LEVEL_CHANGED);
		SIDBG_C(SIDBG_INIT|SIDBG_EVENT, si_ctlp,
		    "sending event up: SATA_EVNT_PWR_LEVEL_CHANGED", NULL);

		(void) pm_idle_component(si_ctlp->sictl_devinfop, 0);

		si_ctlp->sictl_power_level = PM_LEVEL_D0;

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);

	}

err_out:
	if (attach_state & ATTACH_PROGRESS_HW_INIT) {
		si_ctlp->sictl_flags |= SI_DETACH;
		/* We want to set SI_DETACH to deallocate all memory */
		si_deinitialize_controller(si_ctlp);
		si_ctlp->sictl_flags &= ~SI_DETACH;
	}

	if (attach_state & ATTACH_PROGRESS_MUTEX_INIT) {
		mutex_destroy(&si_ctlp->sictl_mutex);
	}

	if (attach_state & ATTACH_PROGRESS_INTR_ADDED) {
		si_rem_intrs(si_ctlp);
	}

	if (attach_state & ATTACH_PROGRESS_BAR1_MAP) {
		ddi_regs_map_free(&si_ctlp->sictl_port_acc_handle);
	}

	if (attach_state & ATTACH_PROGRESS_BAR0_MAP) {
		ddi_regs_map_free(&si_ctlp->sictl_global_acc_handle);
	}

	if (attach_state & ATTACH_PROGRESS_CONF_HANDLE) {
		pci_config_teardown(&si_ctlp->sictl_pci_conf_handle);
	}

	if (attach_state & ATTACH_PROGRESS_INIT_FMA) {
		si_fm_fini(si_ctlp);
	}

	if (attach_state & ATTACH_PROGRESS_STATEP_ALLOC) {
		ddi_soft_state_free(si_statep, instance);
	}

	return (DDI_FAILURE);
}


/*
 * The detach entry point for dev_ops.
 *
 * We undo the things we did in si_attach().
 */
static int
si_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	si_ctl_state_t *si_ctlp;
	int instance;

	SIDBG(SIDBG_ENTRY, "si_detach enter", NULL);
	instance = ddi_get_instance(dip);
	si_ctlp = ddi_get_soft_state(si_statep, instance);

	switch (cmd) {

	case DDI_DETACH:

		mutex_enter(&si_ctlp->sictl_mutex);

		/* disable the interrupts for an uninterrupted detach */
		si_disable_all_interrupts(si_ctlp);

		mutex_exit(&si_ctlp->sictl_mutex);
		/* unregister from the sata framework. */
		if (si_unregister_sata_hba_tran(si_ctlp) != SI_SUCCESS) {
			si_enable_all_interrupts(si_ctlp);
			return (DDI_FAILURE);
		}
		mutex_enter(&si_ctlp->sictl_mutex);

		/* now cancel the timeout handler. */
		si_ctlp->sictl_flags |= SI_NO_TIMEOUTS;
		(void) untimeout(si_ctlp->sictl_timeout_id);
		si_ctlp->sictl_flags &= ~SI_NO_TIMEOUTS;

		/* de-initialize the controller. */
		si_ctlp->sictl_flags |= SI_DETACH;
		si_deinitialize_controller(si_ctlp);
		si_ctlp->sictl_flags &= ~SI_DETACH;

		/* destroy any mutexes */
		mutex_exit(&si_ctlp->sictl_mutex);
		mutex_destroy(&si_ctlp->sictl_mutex);

		/* remove the interrupts */
		si_rem_intrs(si_ctlp);

		/* remove the reg maps. */
		ddi_regs_map_free(&si_ctlp->sictl_port_acc_handle);
		ddi_regs_map_free(&si_ctlp->sictl_global_acc_handle);
		pci_config_teardown(&si_ctlp->sictl_pci_conf_handle);

		/* deinit FMA */
		si_fm_fini(si_ctlp);

		/* free the soft state. */
		ddi_soft_state_free(si_statep, instance);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		/* Inform SATA framework */
		if (sata_hba_detach(dip, cmd) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		mutex_enter(&si_ctlp->sictl_mutex);

		/*
		 * Device needs to be at full power in case it is needed to
		 * handle dump(9e) to save CPR state after DDI_SUSPEND
		 * completes.  This is OK since presumably power will be
		 * removed anyways.  No outstanding transactions should be
		 * on the controller since the children are already quiesced.
		 *
		 * If any ioctls/cfgadm support is added that touches
		 * hardware, those entry points will need to check for
		 * suspend and then block or return errors until resume.
		 *
		 */
		if (pm_busy_component(si_ctlp->sictl_devinfop, 0) ==
		    DDI_SUCCESS) {
			mutex_exit(&si_ctlp->sictl_mutex);
			(void) pm_raise_power(si_ctlp->sictl_devinfop, 0,
			    PM_LEVEL_D0);
			mutex_enter(&si_ctlp->sictl_mutex);
		}

		si_deinitialize_controller(si_ctlp);

		si_ctlp->sictl_flags |= SI_NO_TIMEOUTS;
		(void) untimeout(si_ctlp->sictl_timeout_id);
		si_ctlp->sictl_flags &= ~SI_NO_TIMEOUTS;

		SIDBG_C(SIDBG_POWER, si_ctlp, "si3124%d: DDI_SUSPEND",
		    instance);

		mutex_exit(&si_ctlp->sictl_mutex);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);

	}

}

static int
si_power(dev_info_t *dip, int component, int level)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(component))
#endif /* __lock_lint */

	si_ctl_state_t *si_ctlp;
	int instance = ddi_get_instance(dip);
	int rval = DDI_SUCCESS;
	int old_level;
	sata_device_t sdevice;

	si_ctlp = ddi_get_soft_state(si_statep, instance);

	if (si_ctlp == NULL) {
		return (DDI_FAILURE);
	}

	SIDBG_C(SIDBG_ENTRY, si_ctlp, "si_power enter", NULL);

	mutex_enter(&si_ctlp->sictl_mutex);
	old_level = si_ctlp->sictl_power_level;

	switch (level) {
	case PM_LEVEL_D0: /* fully on */
		pci_config_put16(si_ctlp->sictl_pci_conf_handle,
		    PM_CSR(si_ctlp->sictl_devid), PCI_PMCSR_D0);
#ifndef __lock_lint
		delay(drv_usectohz(10000));
#endif  /* __lock_lint */
		si_ctlp->sictl_power_level = PM_LEVEL_D0;
		(void) pci_restore_config_regs(si_ctlp->sictl_devinfop);

		SIDBG_C(SIDBG_POWER, si_ctlp,
		    "si3124%d: turning power ON. old level %d",
		    instance, old_level);
		/*
		 * If called from attach, just raise device power,
		 * restore config registers (if they were saved
		 * from a previous detach that lowered power),
		 * and exit.
		 */
		if (si_ctlp->sictl_flags & SI_ATTACH)
			break;

		mutex_exit(&si_ctlp->sictl_mutex);
		(void) si_initialize_controller(si_ctlp);
		mutex_enter(&si_ctlp->sictl_mutex);

		si_ctlp->sictl_timeout_id = timeout(
		    (void (*)(void *))si_watchdog_handler,
		    (caddr_t)si_ctlp, si_watchdog_tick);

		bzero((void *)&sdevice, sizeof (sata_device_t));
		sata_hba_event_notify(
		    si_ctlp->sictl_sata_hba_tran->sata_tran_hba_dip,
		    &sdevice, SATA_EVNT_PWR_LEVEL_CHANGED);
		SIDBG_C(SIDBG_EVENT|SIDBG_POWER, si_ctlp,
		    "sending event up: PWR_LEVEL_CHANGED", NULL);

		break;

	case PM_LEVEL_D3: /* fully off */
		if (!(si_ctlp->sictl_flags & SI_DETACH)) {
			si_ctlp->sictl_flags |= SI_NO_TIMEOUTS;
			(void) untimeout(si_ctlp->sictl_timeout_id);
			si_ctlp->sictl_flags &= ~SI_NO_TIMEOUTS;

			si_deinitialize_controller(si_ctlp);

			si_ctlp->sictl_power_level = PM_LEVEL_D3;
		}

		(void) pci_save_config_regs(si_ctlp->sictl_devinfop);

		pci_config_put16(si_ctlp->sictl_pci_conf_handle,
		    PM_CSR(si_ctlp->sictl_devid), PCI_PMCSR_D3HOT);

		SIDBG_C(SIDBG_POWER, si_ctlp, "si3124%d: turning power OFF. "
		    "old level %d", instance, old_level);

		break;

	default:
		SIDBG_C(SIDBG_POWER, si_ctlp, "si3124%d: turning power OFF. "
		    "old level %d", instance, old_level);
		rval = DDI_FAILURE;
		break;
	}

	mutex_exit(&si_ctlp->sictl_mutex);

	return (rval);
}


/*
 * The info entry point for dev_ops.
 *
 */
static int
si_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
		void *arg,
		void **result)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(dip))
#endif /* __lock_lint */
	si_ctl_state_t *si_ctlp;
	int instance;
	dev_t dev;

	dev = (dev_t)arg;
	instance = getminor(dev);

	switch (infocmd) {
		case DDI_INFO_DEVT2DEVINFO:
			si_ctlp = ddi_get_soft_state(si_statep,  instance);
			if (si_ctlp != NULL) {
				*result = si_ctlp->sictl_devinfop;
				return (DDI_SUCCESS);
			} else {
				*result = NULL;
				return (DDI_FAILURE);
			}
		case DDI_INFO_DEVT2INSTANCE:
			*(int *)result = instance;
			break;
		default:
			break;
	}
	return (DDI_SUCCESS);
}



/*
 * Registers the si3124 with sata framework.
 */
static int
si_register_sata_hba_tran(si_ctl_state_t *si_ctlp)
{
	struct 	sata_hba_tran	*sata_hba_tran;

	SIDBG_C(SIDBG_ENTRY, si_ctlp,
	    "si_register_sata_hba_tran entry", NULL);

	mutex_enter(&si_ctlp->sictl_mutex);

	/* Allocate memory for the sata_hba_tran  */
	sata_hba_tran = kmem_zalloc(sizeof (sata_hba_tran_t), KM_SLEEP);

	sata_hba_tran->sata_tran_hba_rev = SATA_TRAN_HBA_REV;
	sata_hba_tran->sata_tran_hba_dip = si_ctlp->sictl_devinfop;

	if (si_dma_sg_number > SI_MAX_SGT_TABLES_PER_PRB) {
		si_dma_sg_number = SI_MAX_SGT_TABLES_PER_PRB;
	} else if (si_dma_sg_number < SI_MIN_SGT_TABLES_PER_PRB) {
		si_dma_sg_number = SI_MIN_SGT_TABLES_PER_PRB;
	}

	if (si_dma_sg_number != SI_DEFAULT_SGT_TABLES_PER_PRB) {
		buffer_dma_attr.dma_attr_sgllen = SGE_LENGTH(si_dma_sg_number);
	}
	sata_hba_tran->sata_tran_hba_dma_attr = &buffer_dma_attr;

	sata_hba_tran->sata_tran_hba_num_cports = si_ctlp->sictl_num_ports;
	sata_hba_tran->sata_tran_hba_features_support = 0;
	sata_hba_tran->sata_tran_hba_qdepth = SI_NUM_SLOTS;

	sata_hba_tran->sata_tran_probe_port = si_tran_probe_port;
	sata_hba_tran->sata_tran_start = si_tran_start;
	sata_hba_tran->sata_tran_abort = si_tran_abort;
	sata_hba_tran->sata_tran_reset_dport = si_tran_reset_dport;
	sata_hba_tran->sata_tran_selftest = NULL;
	sata_hba_tran->sata_tran_hotplug_ops = &si_tran_hotplug_ops;
	sata_hba_tran->sata_tran_pwrmgt_ops = NULL;
	sata_hba_tran->sata_tran_ioctl = NULL;
	mutex_exit(&si_ctlp->sictl_mutex);

	/* Attach it to SATA framework */
	if (sata_hba_attach(si_ctlp->sictl_devinfop, sata_hba_tran, DDI_ATTACH)
	    != DDI_SUCCESS) {
		kmem_free((void *)sata_hba_tran, sizeof (sata_hba_tran_t));
		return (SI_FAILURE);
	}

	mutex_enter(&si_ctlp->sictl_mutex);
	si_ctlp->sictl_sata_hba_tran = sata_hba_tran;
	mutex_exit(&si_ctlp->sictl_mutex);

	return (SI_SUCCESS);
}


/*
 * Unregisters the si3124 with sata framework.
 */
static int
si_unregister_sata_hba_tran(si_ctl_state_t *si_ctlp)
{

	/* Detach from the SATA framework. */
	if (sata_hba_detach(si_ctlp->sictl_devinfop, DDI_DETACH) !=
	    DDI_SUCCESS) {
		return (SI_FAILURE);
	}

	/* Deallocate sata_hba_tran. */
	kmem_free((void *)si_ctlp->sictl_sata_hba_tran,
	    sizeof (sata_hba_tran_t));

	si_ctlp->sictl_sata_hba_tran = NULL;

	return (SI_SUCCESS);
}

/*
 * Called by sata framework to probe a port. We return the
 * cached information from a previous hardware probe.
 *
 * The actual hardware probing itself was done either from within
 * si_initialize_controller() during the driver attach or
 * from a phy ready change interrupt handler.
 */
static int
si_tran_probe_port(dev_info_t *dip, sata_device_t *sd)
{

	si_ctl_state_t	*si_ctlp;
	uint8_t cport = sd->satadev_addr.cport;
	uint8_t pmport = sd->satadev_addr.pmport;
	uint8_t qual = sd->satadev_addr.qual;
	uint8_t port_type;
	si_port_state_t *si_portp;
	si_portmult_state_t *si_portmultp;

	si_ctlp = ddi_get_soft_state(si_statep, ddi_get_instance(dip));

	SIDBG_C(SIDBG_ENTRY, si_ctlp,
	    "si_tran_probe_port: cport: 0x%x, pmport: 0x%x, qual: 0x%x",
	    cport, pmport, qual);

	if (cport >= SI_MAX_PORTS) {
		sd->satadev_type = SATA_DTYPE_NONE;
		sd->satadev_state = SATA_STATE_UNKNOWN; /* invalid port */
		return (SATA_FAILURE);
	}

	mutex_enter(&si_ctlp->sictl_mutex);
	si_portp = si_ctlp->sictl_ports[cport];
	mutex_exit(&si_ctlp->sictl_mutex);
	if (si_portp == NULL) {
		sd->satadev_type = SATA_DTYPE_NONE;
		sd->satadev_state = SATA_STATE_UNKNOWN;
		return (SATA_FAILURE);
	}

	mutex_enter(&si_portp->siport_mutex);

	if (qual == SATA_ADDR_PMPORT) {
		if (pmport >= si_portp->siport_portmult_state.sipm_num_ports) {
			sd->satadev_type = SATA_DTYPE_NONE;
			sd->satadev_state = SATA_STATE_UNKNOWN;
			mutex_exit(&si_portp->siport_mutex);
			return (SATA_FAILURE);
		} else {
			si_portmultp = 	&si_portp->siport_portmult_state;
			port_type = si_portmultp->sipm_port_type[pmport];
		}
	} else {
		port_type = si_portp->siport_port_type;
	}

	switch (port_type) {

	case PORT_TYPE_DISK:
		sd->satadev_type = SATA_DTYPE_ATADISK;
		break;

	case PORT_TYPE_ATAPI:
		sd->satadev_type = SATA_DTYPE_ATAPICD;
		break;

	case PORT_TYPE_MULTIPLIER:
		sd->satadev_type = SATA_DTYPE_PMULT;
		sd->satadev_add_info =
		    si_portp->siport_portmult_state.sipm_num_ports;
		break;

	case PORT_TYPE_UNKNOWN:
		sd->satadev_type = SATA_DTYPE_UNKNOWN;
		break;

	default:
		/* we don't support any other device types. */
		sd->satadev_type = SATA_DTYPE_NONE;
		break;
	}
	sd->satadev_state = SATA_STATE_READY;

	if (qual == SATA_ADDR_PMPORT) {
		(void) si_read_portmult_reg(si_ctlp, si_portp, cport,
		    pmport, PSCR_REG0, &sd->satadev_scr.sstatus);
		(void) si_read_portmult_reg(si_ctlp, si_portp, cport,
		    pmport, PSCR_REG1, &sd->satadev_scr.serror);
		(void) si_read_portmult_reg(si_ctlp, si_portp, cport,
		    pmport, PSCR_REG2, &sd->satadev_scr.scontrol);
		(void) si_read_portmult_reg(si_ctlp, si_portp, cport,
		    pmport, PSCR_REG3, &sd->satadev_scr.sactive);
	} else {
		fill_dev_sregisters(si_ctlp, cport, sd);
		if (!(si_portp->siport_active)) {
			/*
			 * Since we are implementing the port deactivation
			 * in software only, we need to fake a valid value
			 * for sstatus when the device is in deactivated state.
			 */
			SSTATUS_SET_DET(sd->satadev_scr.sstatus,
			    SSTATUS_DET_PHYOFFLINE);
			SSTATUS_SET_IPM(sd->satadev_scr.sstatus,
			    SSTATUS_IPM_NODEV_NOPHY);
			sd->satadev_state = SATA_PSTATE_SHUTDOWN;
		}
	}

	mutex_exit(&si_portp->siport_mutex);
	return (SATA_SUCCESS);
}

/*
 * Called by sata framework to transport a sata packet down stream.
 *
 * The actual work of building the FIS & transporting it to the hardware
 * is done out of the subroutine si_deliver_satapkt().
 */
static int
si_tran_start(dev_info_t *dip, sata_pkt_t *spkt)
{
	si_ctl_state_t *si_ctlp;
	uint8_t	cport;
	si_port_state_t *si_portp;
	int slot;

	cport = spkt->satapkt_device.satadev_addr.cport;
	si_ctlp = ddi_get_soft_state(si_statep, ddi_get_instance(dip));
	mutex_enter(&si_ctlp->sictl_mutex);
	si_portp = si_ctlp->sictl_ports[cport];
	mutex_exit(&si_ctlp->sictl_mutex);

	SIDBG_P(SIDBG_ENTRY, si_portp,
	    "si_tran_start entry", NULL);

	mutex_enter(&si_portp->siport_mutex);

	if ((si_portp->siport_port_type == PORT_TYPE_NODEV) ||
	    !si_portp->siport_active) {
		/*
		 * si_intr_phy_ready_change() may have rendered it to
		 * PORT_TYPE_NODEV. cfgadm operation may have rendered
		 * it inactive.
		 */
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		fill_dev_sregisters(si_ctlp, cport, &spkt->satapkt_device);
		mutex_exit(&si_portp->siport_mutex);
		return (SATA_TRAN_PORT_ERROR);
	}

	if (spkt->satapkt_cmd.satacmd_flags.sata_clear_dev_reset) {
		si_portp->siport_reset_in_progress = 0;
		SIDBG_P(SIDBG_RESET, si_portp,
		    "si_tran_start clearing the "
		    "reset_in_progress for port", NULL);
	}

	if (si_portp->siport_reset_in_progress &&
	    ! spkt->satapkt_cmd.satacmd_flags.sata_ignore_dev_reset &&
	    ! ddi_in_panic()) {

		spkt->satapkt_reason = SATA_PKT_BUSY;
		SIDBG_P(SIDBG_RESET, si_portp,
		    "si_tran_start returning BUSY while "
		    "reset in progress for port", NULL);
		mutex_exit(&si_portp->siport_mutex);
		return (SATA_TRAN_BUSY);
	}

	if (si_portp->mopping_in_progress > 0) {
		spkt->satapkt_reason = SATA_PKT_BUSY;
		SIDBG_P(SIDBG_RESET, si_portp,
		    "si_tran_start returning BUSY while "
		    "mopping in progress for port", NULL);
		mutex_exit(&si_portp->siport_mutex);
		return (SATA_TRAN_BUSY);
	}

	if ((slot = si_deliver_satapkt(si_ctlp, si_portp, cport, spkt))
	    == SI_FAILURE) {
		spkt->satapkt_reason = SATA_PKT_QUEUE_FULL;
		SIDBG_P(SIDBG_ERRS, si_portp,
		    "si_tran_start returning QUEUE_FULL",
		    NULL);
		mutex_exit(&si_portp->siport_mutex);
		return (SATA_TRAN_QUEUE_FULL);
	}

	if (spkt->satapkt_op_mode & (SATA_OPMODE_POLLING|SATA_OPMODE_SYNCH)) {
		/* we need to poll now */
		si_poll_cmd(si_ctlp, si_portp, cport, slot, spkt);
		/*
		 * The command has completed, and spkt will be freed by the
		 * sata module, so don't keep a pointer to it lying around.
		 */
		si_portp->siport_slot_pkts[slot] = NULL;
	}

	mutex_exit(&si_portp->siport_mutex);
	return (SATA_TRAN_ACCEPTED);
}

#define	SENDUP_PACKET(si_portp, satapkt, reason)			\
	if (satapkt) {							\
		if ((satapkt->satapkt_cmd.satacmd_cmd_reg ==		\
					SATAC_WRITE_FPDMA_QUEUED) ||	\
		    (satapkt->satapkt_cmd.satacmd_cmd_reg ==		\
					SATAC_READ_FPDMA_QUEUED)) {	\
			si_portp->siport_pending_ncq_count--;		\
		}							\
		satapkt->satapkt_reason = reason;			\
		/*							\
		 * We set the satapkt_reason in both synch and		\
		 * non-synch cases.					\
		 */							\
		if (!(satapkt->satapkt_op_mode & SATA_OPMODE_SYNCH) &&	\
			satapkt->satapkt_comp) {			\
			mutex_exit(&si_portp->siport_mutex);		\
			(*satapkt->satapkt_comp)(satapkt);		\
			mutex_enter(&si_portp->siport_mutex);		\
		}							\
	}

/*
 * Mopping is necessitated because of the si3124 hardware limitation.
 * The only way to recover from errors or to abort a command is to
 * reset the port/device but such a reset also results in throwing
 * away all the unfinished pending commands.
 *
 * A port or device is reset in four scenarios:
 *	a) some commands failed with errors
 *	b) or we need to timeout some commands
 *	c) or we need to abort some commands
 *	d) or we need reset the port at the request of sata framework
 *
 * In all these scenarios, we need to send any pending unfinished
 * commands up to sata framework.
 *
 * WARNING!!! siport_mutex should be acquired before the function is called.
 */
static void
si_mop_commands(si_ctl_state_t *si_ctlp,
		si_port_state_t *si_portp,
		uint8_t	port,

		uint32_t slot_status,
		uint32_t failed_tags,
		uint32_t timedout_tags,
		uint32_t aborting_tags,
		uint32_t reset_tags)
{
	uint32_t finished_tags, unfinished_tags;
	int tmpslot;
	sata_pkt_t *satapkt;
	struct sata_cmd_flags *flagsp;

	SIDBG_P(SIDBG_ERRS, si_portp,
	    "si_mop_commands entered: slot_status: 0x%x",
	    slot_status);

	SIDBG_P(SIDBG_ERRS, si_portp,
	    "si_mop_commands: failed_tags: 0x%x, timedout_tags: 0x%x"
	    "aborting_tags: 0x%x, reset_tags: 0x%x",
	    failed_tags,
	    timedout_tags,
	    aborting_tags,
	    reset_tags);

	/*
	 * We could be here for four reasons: abort, reset,
	 * timeout or error handling. Only one such mopping
	 * is allowed at a time.
	 */

	finished_tags =  si_portp->siport_pending_tags &
	    ~slot_status & SI_SLOT_MASK;

	unfinished_tags = slot_status & SI_SLOT_MASK &
	    ~failed_tags &
	    ~aborting_tags &
	    ~reset_tags &
	    ~timedout_tags;

	/* Send up the finished_tags with SATA_PKT_COMPLETED. */
	while (finished_tags) {
		tmpslot = ddi_ffs(finished_tags) - 1;
		if (tmpslot == -1) {
			break;
		}

		satapkt = si_portp->siport_slot_pkts[tmpslot];

		if (satapkt != NULL &&
		    satapkt->satapkt_cmd.satacmd_flags.sata_special_regs) {
			si_copy_out_regs(&satapkt->satapkt_cmd, si_ctlp,
			    port, tmpslot);
		}

		SIDBG_P(SIDBG_ERRS, si_portp,
		    "si_mop_commands sending up completed satapkt: %x",
		    satapkt);

		CLEAR_BIT(si_portp->siport_pending_tags, tmpslot);
		CLEAR_BIT(finished_tags, tmpslot);
		SENDUP_PACKET(si_portp, satapkt, SATA_PKT_COMPLETED);
	}

	ASSERT(finished_tags == 0);

	/* Send up failed_tags with SATA_PKT_DEV_ERROR. */
	while (failed_tags) {
		tmpslot = ddi_ffs(failed_tags) - 1;
		if (tmpslot == -1) {
			break;
		}
		SIDBG_P(SIDBG_ERRS, si_portp, "si3124: si_mop_commands: "
		    "handling failed slot: 0x%x", tmpslot);

		satapkt = si_portp->siport_slot_pkts[tmpslot];

		if (satapkt != NULL) {

			if (satapkt->satapkt_device.satadev_type ==
			    SATA_DTYPE_ATAPICD) {
				si_set_sense_data(satapkt, SATA_PKT_DEV_ERROR);
			}


			flagsp = &satapkt->satapkt_cmd.satacmd_flags;

			flagsp->sata_copy_out_lba_low_msb = B_TRUE;
			flagsp->sata_copy_out_lba_mid_msb = B_TRUE;
			flagsp->sata_copy_out_lba_high_msb = B_TRUE;
			flagsp->sata_copy_out_lba_low_lsb = B_TRUE;
			flagsp->sata_copy_out_lba_mid_lsb = B_TRUE;
			flagsp->sata_copy_out_lba_high_lsb = B_TRUE;
			flagsp->sata_copy_out_error_reg = B_TRUE;
			flagsp->sata_copy_out_sec_count_msb = B_TRUE;
			flagsp->sata_copy_out_sec_count_lsb = B_TRUE;
			flagsp->sata_copy_out_device_reg = B_TRUE;

			si_copy_out_regs(&satapkt->satapkt_cmd, si_ctlp,
			    port, tmpslot);

			/*
			 * In the case of NCQ command failures, the error is
			 * overwritten by the one obtained from issuing of a
			 * READ LOG EXTENDED command.
			 */
			if (si_portp->siport_err_tags_SDBERROR &
			    (1 << tmpslot)) {
				satapkt->satapkt_cmd.satacmd_error_reg =
				    si_read_log_ext(si_ctlp, si_portp, port);
			}
		}

		CLEAR_BIT(failed_tags, tmpslot);
		CLEAR_BIT(si_portp->siport_pending_tags, tmpslot);
		SENDUP_PACKET(si_portp, satapkt, SATA_PKT_DEV_ERROR);
	}

	ASSERT(failed_tags == 0);

	/* Send up timedout_tags with SATA_PKT_TIMEOUT. */
	while (timedout_tags) {
		tmpslot = ddi_ffs(timedout_tags) - 1;
		if (tmpslot == -1) {
			break;
		}

		satapkt = si_portp->siport_slot_pkts[tmpslot];
		SIDBG_P(SIDBG_ERRS, si_portp,
		    "si_mop_commands sending "
		    "spkt up with PKT_TIMEOUT: %x",
		    satapkt);

		CLEAR_BIT(si_portp->siport_pending_tags, tmpslot);
		CLEAR_BIT(timedout_tags, tmpslot);
		SENDUP_PACKET(si_portp, satapkt, SATA_PKT_TIMEOUT);
	}

	ASSERT(timedout_tags == 0);

	/* Send up aborting packets with SATA_PKT_ABORTED. */
	while (aborting_tags) {
		tmpslot = ddi_ffs(aborting_tags) - 1;
		if (tmpslot == -1) {
			break;
		}

		satapkt = si_portp->siport_slot_pkts[tmpslot];
		SIDBG_P(SIDBG_ERRS, si_portp,
		    "si_mop_commands aborting spkt: %x",
		    satapkt);
		if (satapkt != NULL && satapkt->satapkt_device.satadev_type ==
		    SATA_DTYPE_ATAPICD) {
			si_set_sense_data(satapkt, SATA_PKT_ABORTED);
		}

		CLEAR_BIT(si_portp->siport_pending_tags, tmpslot);
		CLEAR_BIT(aborting_tags, tmpslot);
		SENDUP_PACKET(si_portp, satapkt, SATA_PKT_ABORTED);

	}

	ASSERT(aborting_tags == 0);

	/* Reset tags are sent up to framework with SATA_PKT_RESET. */
	while (reset_tags) {
		tmpslot = ddi_ffs(reset_tags) - 1;
		if (tmpslot == -1) {
			break;
		}
		satapkt = si_portp->siport_slot_pkts[tmpslot];
		SIDBG_P(SIDBG_ERRS, si_portp,
		    "si_mop_commands sending PKT_RESET for "
		    "reset spkt: %x",
		    satapkt);

		CLEAR_BIT(reset_tags, tmpslot);
		CLEAR_BIT(si_portp->siport_pending_tags, tmpslot);
		SENDUP_PACKET(si_portp, satapkt, SATA_PKT_RESET);
	}

	ASSERT(reset_tags == 0);

	/* Send up the unfinished_tags with SATA_PKT_RESET. */
	while (unfinished_tags) {
		tmpslot = ddi_ffs(unfinished_tags) - 1;
		if (tmpslot == -1) {
			break;
		}
		satapkt = si_portp->siport_slot_pkts[tmpslot];
		SIDBG_P(SIDBG_ERRS, si_portp,
		    "si_mop_commands sending SATA_PKT_RESET for "
		    "retry spkt: %x",
		    satapkt);

		CLEAR_BIT(unfinished_tags, tmpslot);
		CLEAR_BIT(si_portp->siport_pending_tags, tmpslot);
		SENDUP_PACKET(si_portp, satapkt, SATA_PKT_RESET);
	}

	ASSERT(unfinished_tags == 0);

	si_portp->mopping_in_progress--;
	ASSERT(si_portp->mopping_in_progress >= 0);
}

/*
 * Called by the sata framework to abort the previously sent packet(s).
 *
 * We reset the device and mop the commands on the port.
 */
static int
si_tran_abort(dev_info_t *dip, sata_pkt_t *spkt, int flag)
{
	uint32_t slot_status;
	uint8_t	port;
	int tmpslot;
	uint32_t aborting_tags;
	uint32_t finished_tags;
	si_port_state_t *si_portp;
	si_ctl_state_t *si_ctlp;

	port = spkt->satapkt_device.satadev_addr.cport;
	si_ctlp = ddi_get_soft_state(si_statep, ddi_get_instance(dip));
	mutex_enter(&si_ctlp->sictl_mutex);
	si_portp = si_ctlp->sictl_ports[port];
	mutex_exit(&si_ctlp->sictl_mutex);

	SIDBG_P(SIDBG_ERRS, si_portp, "si_tran_abort on port: %x", port);

	mutex_enter(&si_portp->siport_mutex);

	/*
	 * If already mopping, then no need to abort anything.
	 */
	if (si_portp->mopping_in_progress > 0) {
		SIDBG_P(SIDBG_ERRS, si_portp,
		    "si_tran_abort: port %d mopping "
		    "in progress, so just return", port);
		mutex_exit(&si_portp->siport_mutex);
		return (SATA_SUCCESS);
	}

	if ((si_portp->siport_port_type == PORT_TYPE_NODEV) ||
	    !si_portp->siport_active) {
		/*
		 * si_intr_phy_ready_change() may have rendered it to
		 * PORT_TYPE_NODEV. cfgadm operation may have rendered
		 * it inactive.
		 */
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		fill_dev_sregisters(si_ctlp, port, &spkt->satapkt_device);
		mutex_exit(&si_portp->siport_mutex);
		return (SATA_FAILURE);
	}

	if (flag == SATA_ABORT_ALL_PACKETS) {
		aborting_tags = si_portp->siport_pending_tags;
	} else {
		/*
		 * Need to abort a single packet.
		 * Search our siport_slot_pkts[] list for matching spkt.
		 */
		aborting_tags = 0xffffffff; /* 0xffffffff is impossible tag */
		for (tmpslot = 0; tmpslot < SI_NUM_SLOTS; tmpslot++) {
			if (si_portp->siport_slot_pkts[tmpslot] == spkt) {
				aborting_tags = (0x1 << tmpslot);
				break;
			}
		}

		if (aborting_tags == 0xffffffff) {
			/* requested packet is not on pending list. */
			fill_dev_sregisters(si_ctlp, port,
			    &spkt->satapkt_device);
			mutex_exit(&si_portp->siport_mutex);
			return (SATA_FAILURE);
		}
	}

	si_portp->mopping_in_progress++;

	slot_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SLOT_STATUS(si_ctlp, port)));
	(void) si_reset_dport_wait_till_ready(si_ctlp, si_portp,
	    port, SI_DEVICE_RESET);

	/*
	 * Compute which have finished and which need to be retried.
	 *
	 * The finished tags are siport_pending_tags minus the slot_status.
	 * The aborting_tags have to be reduced by finished_tags since we
	 * can't possibly abort a tag which had finished already.
	 */
	finished_tags =  si_portp->siport_pending_tags &
	    ~slot_status & SI_SLOT_MASK;
	aborting_tags &= ~finished_tags;

	si_mop_commands(si_ctlp,
	    si_portp,
	    port,
	    slot_status,
	    0, /* failed_tags */
	    0, /* timedout_tags */
	    aborting_tags,
	    0); /* reset_tags */

	fill_dev_sregisters(si_ctlp, port, &spkt->satapkt_device);
	mutex_exit(&si_portp->siport_mutex);
	return (SATA_SUCCESS);
}


/*
 * Used to reject all the pending packets on a port during a reset
 * operation.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static void
si_reject_all_reset_pkts(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	uint32_t slot_status;
	uint32_t reset_tags;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	SIDBG_P(SIDBG_RESET, si_portp,
	    "si_reject_all_reset_pkts on port: %x",
	    port);

	slot_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SLOT_STATUS(si_ctlp, port)));

	/* Compute which tags need to be sent up. */
	reset_tags = slot_status & SI_SLOT_MASK;

	si_portp->mopping_in_progress++;

	si_mop_commands(si_ctlp,
	    si_portp,
	    port,
	    slot_status,
	    0, /* failed_tags */
	    0, /* timedout_tags */
	    0, /* aborting_tags */
	    reset_tags);
}


/*
 * Called by sata framework to reset a port(s) or device.
 *
 */
static int
si_tran_reset_dport(dev_info_t *dip, sata_device_t *sd)
{
	si_ctl_state_t	*si_ctlp;
	uint8_t port = sd->satadev_addr.cport;
	int i;
	si_port_state_t *si_portp;
	int retval = SI_SUCCESS;

	si_ctlp = ddi_get_soft_state(si_statep, ddi_get_instance(dip));
	SIDBG_C(SIDBG_RESET, si_ctlp,
	    "si_tran_reset_port entry: port: 0x%x",
	    port);

	switch (sd->satadev_addr.qual) {
	case SATA_ADDR_CPORT:
		mutex_enter(&si_ctlp->sictl_mutex);
		si_portp = si_ctlp->sictl_ports[port];
		mutex_exit(&si_ctlp->sictl_mutex);

		mutex_enter(&si_portp->siport_mutex);

		/*
		 * If already mopping, then no need to reset or mop again.
		 */
		if (si_portp->mopping_in_progress > 0) {
			SIDBG_P(SIDBG_RESET, si_portp,
			    "si_tran_reset_dport: CPORT port %d mopping "
			    "in progress, so just return", port);
			mutex_exit(&si_portp->siport_mutex);
			retval = SI_SUCCESS;
			break;
		}

		retval = si_reset_dport_wait_till_ready(si_ctlp, si_portp, port,
		    SI_PORT_RESET);
		si_reject_all_reset_pkts(si_ctlp,  si_portp, port);
		mutex_exit(&si_portp->siport_mutex);

		break;

	case SATA_ADDR_DCPORT:
		mutex_enter(&si_ctlp->sictl_mutex);
		si_portp = si_ctlp->sictl_ports[port];
		mutex_exit(&si_ctlp->sictl_mutex);

		mutex_enter(&si_portp->siport_mutex);

		if ((si_portp->siport_port_type == PORT_TYPE_NODEV) ||
		    !si_portp->siport_active) {
			mutex_exit(&si_portp->siport_mutex);
			retval = SI_FAILURE;
			break;
		}

		/*
		 * If already mopping, then no need to reset or mop again.
		 */
		if (si_portp->mopping_in_progress > 0) {
			SIDBG_P(SIDBG_RESET, si_portp,
			    "si_tran_reset_dport: DCPORT port %d mopping "
			    "in progress, so just return", port);
			mutex_exit(&si_portp->siport_mutex);
			retval = SI_SUCCESS;
			break;
		}

		retval = si_reset_dport_wait_till_ready(si_ctlp, si_portp, port,
		    SI_DEVICE_RESET);
		si_reject_all_reset_pkts(si_ctlp,  si_portp, port);
		mutex_exit(&si_portp->siport_mutex);

		break;

	case SATA_ADDR_CNTRL:
		for (i = 0; i < si_ctlp->sictl_num_ports; i++) {
			mutex_enter(&si_ctlp->sictl_mutex);
			si_portp = si_ctlp->sictl_ports[i];
			mutex_exit(&si_ctlp->sictl_mutex);

			mutex_enter(&si_portp->siport_mutex);

			/*
			 * If mopping, then all the pending commands are being
			 * mopped, therefore there is nothing else to do.
			 */
			if (si_portp->mopping_in_progress > 0) {
				SIDBG_P(SIDBG_RESET, si_portp,
				    "si_tran_reset_dport: CNTRL port %d mopping"
				    " in progress, so just return", i);
				mutex_exit(&si_portp->siport_mutex);
				retval = SI_SUCCESS;
				break;
			}

			retval = si_reset_dport_wait_till_ready(si_ctlp,
			    si_portp, i, SI_PORT_RESET);
			if (retval) {
				mutex_exit(&si_portp->siport_mutex);
				break;
			}
			si_reject_all_reset_pkts(si_ctlp,  si_portp, i);
			mutex_exit(&si_portp->siport_mutex);
		}
		break;

	case SATA_ADDR_PMPORT:
	case SATA_ADDR_DPMPORT:
		SIDBG_P(SIDBG_RESET, si_portp,
		    "port mult reset not implemented yet", NULL);
		/* FALLTHROUGH */

	default:
		retval = SI_FAILURE;

	}

	return (retval);
}


/*
 * Called by sata framework to activate a port as part of hotplug.
 *
 * Note: Not port-mult aware.
 */
static int
si_tran_hotplug_port_activate(dev_info_t *dip, sata_device_t *satadev)
{
	si_ctl_state_t *si_ctlp;
	si_port_state_t *si_portp;
	uint8_t	port;

	si_ctlp = ddi_get_soft_state(si_statep, ddi_get_instance(dip));
	port = satadev->satadev_addr.cport;
	mutex_enter(&si_ctlp->sictl_mutex);
	si_portp = si_ctlp->sictl_ports[port];
	mutex_exit(&si_ctlp->sictl_mutex);

	SIDBG_P(SIDBG_EVENT, si_portp, "si_tran_hotplug_port_activate entry",
	    NULL);

	mutex_enter(&si_portp->siport_mutex);
	si_enable_port_interrupts(si_ctlp, port);

	/*
	 * Reset the device so that a si_find_dev_signature() would trigger.
	 * But this reset is an internal operation; the sata framework does
	 * not need to know about it.
	 */
	(void) si_reset_dport_wait_till_ready(si_ctlp, si_portp, port,
	    SI_DEVICE_RESET|SI_RESET_NO_EVENTS_UP);

	satadev->satadev_state = SATA_STATE_READY;

	si_portp->siport_active = PORT_ACTIVE;

	fill_dev_sregisters(si_ctlp, port, satadev);

	mutex_exit(&si_portp->siport_mutex);
	return (SATA_SUCCESS);
}

/*
 * Called by sata framework to deactivate a port as part of hotplug.
 *
 * Note: Not port-mult aware.
 */
static int
si_tran_hotplug_port_deactivate(dev_info_t *dip, sata_device_t *satadev)
{
	si_ctl_state_t *si_ctlp;
	si_port_state_t *si_portp;
	uint8_t	port;

	si_ctlp = ddi_get_soft_state(si_statep, ddi_get_instance(dip));
	port = satadev->satadev_addr.cport;
	mutex_enter(&si_ctlp->sictl_mutex);
	si_portp = si_ctlp->sictl_ports[port];
	mutex_exit(&si_ctlp->sictl_mutex);

	SIDBG(SIDBG_EVENT, "si_tran_hotplug_port_deactivate entry", NULL);

	mutex_enter(&si_portp->siport_mutex);
	if (si_portp->siport_pending_tags & SI_SLOT_MASK) {
		/*
		 * There are pending commands on this port.
		 * Fail the deactivate request.
		 */
		satadev->satadev_state = SATA_STATE_READY;
		mutex_exit(&si_portp->siport_mutex);
		return (SATA_FAILURE);
	}

	/* mark the device as not accessible any more. */
	si_portp->siport_active = PORT_INACTIVE;

	/* disable the interrupts on the port. */
	si_disable_port_interrupts(si_ctlp, port);

	satadev->satadev_state = SATA_PSTATE_SHUTDOWN;

	fill_dev_sregisters(si_ctlp, port, satadev);
	/*
	 * Since we are implementing the port deactivation in software only,
	 * we need to fake a valid value for sstatus.
	 */
	SSTATUS_SET_DET(satadev->satadev_scr.sstatus, SSTATUS_DET_PHYOFFLINE);
	SSTATUS_SET_IPM(satadev->satadev_scr.sstatus, SSTATUS_IPM_NODEV_NOPHY);

	mutex_exit(&si_portp->siport_mutex);
	return (SATA_SUCCESS);
}


/*
 * Allocates the si_port_state_t.
 */
static int
si_alloc_port_state(si_ctl_state_t *si_ctlp, int port)
{
	si_port_state_t *si_portp;

	si_ctlp->sictl_ports[port] = (si_port_state_t *)kmem_zalloc(
	    sizeof (si_port_state_t), KM_SLEEP);

	si_portp = si_ctlp->sictl_ports[port];
	mutex_init(&si_portp->siport_mutex, NULL, MUTEX_DRIVER,
	    (void *)(uintptr_t)si_ctlp->sictl_intr_pri);
	mutex_enter(&si_portp->siport_mutex);

	/* allocate prb & sgt pkts for this port. */
	if (si_alloc_prbpool(si_ctlp, port)) {
		mutex_exit(&si_portp->siport_mutex);
		kmem_free(si_ctlp->sictl_ports[port], sizeof (si_port_state_t));
		return (SI_FAILURE);
	}
	if (si_alloc_sgbpool(si_ctlp, port)) {
		si_dealloc_prbpool(si_ctlp, port);
		mutex_exit(&si_portp->siport_mutex);
		kmem_free(si_ctlp->sictl_ports[port], sizeof (si_port_state_t));
		return (SI_FAILURE);
	}

	/* Allocate the argument for the timeout */
	si_portp->siport_event_args =
	    kmem_zalloc(sizeof (si_event_arg_t), KM_SLEEP);

	si_portp->siport_active = PORT_ACTIVE;
	mutex_exit(&si_portp->siport_mutex);

	return (SI_SUCCESS);

}

/*
 * Deallocates the si_port_state_t.
 */
static void
si_dealloc_port_state(si_ctl_state_t *si_ctlp, int port)
{
	si_port_state_t *si_portp;
	si_portp = si_ctlp->sictl_ports[port];

	mutex_enter(&si_portp->siport_mutex);
	kmem_free(si_portp->siport_event_args, sizeof (si_event_arg_t));
	si_dealloc_sgbpool(si_ctlp, port);
	si_dealloc_prbpool(si_ctlp, port);
	mutex_exit(&si_portp->siport_mutex);

	mutex_destroy(&si_portp->siport_mutex);

	kmem_free(si_ctlp->sictl_ports[port], sizeof (si_port_state_t));

}

/*
 * Allocates the SGB (Scatter Gather Block) incore buffer.
 */
static int
si_alloc_sgbpool(si_ctl_state_t *si_ctlp, int port)
{
	si_port_state_t *si_portp;
	uint_t cookie_count;
	size_t incore_sgbpool_size = SI_NUM_SLOTS * sizeof (si_sgblock_t)
	    * si_dma_sg_number;
	size_t ret_len;
	ddi_dma_cookie_t sgbpool_dma_cookie;

	si_portp = si_ctlp->sictl_ports[port];

	/* allocate sgbpool dma handle. */
	if (ddi_dma_alloc_handle(si_ctlp->sictl_devinfop,
	    &prb_sgt_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &si_portp->siport_sgbpool_dma_handle) !=
	    DDI_SUCCESS) {

		return (SI_FAILURE);
	}

	/* allocate the memory for sgbpool. */
	if (ddi_dma_mem_alloc(si_portp->siport_sgbpool_dma_handle,
	    incore_sgbpool_size,
	    &accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    (caddr_t *)&si_portp->siport_sgbpool,
	    &ret_len,
	    &si_portp->siport_sgbpool_acc_handle) != NULL) {

		/*  error.. free the dma handle. */
		ddi_dma_free_handle(&si_portp->siport_sgbpool_dma_handle);
		return (SI_FAILURE);
	}

	/* now bind it */
	if (ddi_dma_addr_bind_handle(si_portp->siport_sgbpool_dma_handle,
	    NULL,
	    (caddr_t)si_portp->siport_sgbpool,
	    incore_sgbpool_size,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &sgbpool_dma_cookie,
	    &cookie_count) !=  DDI_DMA_MAPPED) {
		/*  error.. free the dma handle & free the memory. */
		ddi_dma_mem_free(&si_portp->siport_sgbpool_acc_handle);
		ddi_dma_free_handle(&si_portp->siport_sgbpool_dma_handle);
		return (SI_FAILURE);
	}

	si_portp->siport_sgbpool_physaddr = sgbpool_dma_cookie.dmac_laddress;
	return (SI_SUCCESS);
}

/*
 * Deallocates the SGB (Scatter Gather Block) incore buffer.
 */
static void
si_dealloc_sgbpool(si_ctl_state_t *si_ctlp, int port)
{
	si_port_state_t *si_portp = si_ctlp->sictl_ports[port];

	/* Unbind the dma handle first. */
	(void) ddi_dma_unbind_handle(si_portp->siport_sgbpool_dma_handle);

	/* Then free the underlying memory. */
	ddi_dma_mem_free(&si_portp->siport_sgbpool_acc_handle);

	/* Now free the handle itself. */
	ddi_dma_free_handle(&si_portp->siport_sgbpool_dma_handle);

}

/*
 * Allocates the PRB (Port Request Block) incore packets.
 */
static int
si_alloc_prbpool(si_ctl_state_t *si_ctlp, int port)
{
	si_port_state_t *si_portp;
	uint_t cookie_count;
	size_t incore_pkt_size = SI_NUM_SLOTS * sizeof (si_prb_t);
	size_t ret_len;
	ddi_dma_cookie_t prbpool_dma_cookie;

	si_portp = si_ctlp->sictl_ports[port];

	/* allocate prb pkts. */
	if (ddi_dma_alloc_handle(si_ctlp->sictl_devinfop,
	    &prb_sgt_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &si_portp->siport_prbpool_dma_handle) !=
	    DDI_SUCCESS) {

		return (SI_FAILURE);
	}

	if (ddi_dma_mem_alloc(si_portp->siport_prbpool_dma_handle,
	    incore_pkt_size,
	    &accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    (caddr_t *)&si_portp->siport_prbpool,
	    &ret_len,
	    &si_portp->siport_prbpool_acc_handle) != NULL) {

		/* error.. free the dma handle. */
		ddi_dma_free_handle(&si_portp->siport_prbpool_dma_handle);
		return (SI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(si_portp->siport_prbpool_dma_handle,
	    NULL,
	    (caddr_t)si_portp->siport_prbpool,
	    incore_pkt_size,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &prbpool_dma_cookie,
	    &cookie_count) !=  DDI_DMA_MAPPED) {
		/*  error.. free the dma handle & free the memory. */
		ddi_dma_mem_free(&si_portp->siport_prbpool_acc_handle);
		ddi_dma_free_handle(&si_portp->siport_prbpool_dma_handle);
		return (SI_FAILURE);
	}

	si_portp->siport_prbpool_physaddr =
	    prbpool_dma_cookie.dmac_laddress;
	return (SI_SUCCESS);
}

/*
 * Deallocates the PRB (Port Request Block) incore packets.
 */
static void
si_dealloc_prbpool(si_ctl_state_t *si_ctlp, int port)
{
	si_port_state_t *si_portp = si_ctlp->sictl_ports[port];

	/* Unbind the prb dma handle first. */
	(void) ddi_dma_unbind_handle(si_portp->siport_prbpool_dma_handle);

	/* Then free the underlying memory. */
	ddi_dma_mem_free(&si_portp->siport_prbpool_acc_handle);

	/* Now free the handle itself. */
	ddi_dma_free_handle(&si_portp->siport_prbpool_dma_handle);

}



/*
 * Soft-reset the port to find the signature of the device connected to
 * the port.
 */
static void
si_find_dev_signature(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port,
	int pmp)
{
	si_prb_t *prb;
	uint32_t slot_status, signature;
	int slot, loop_count;

	SIDBG_P(SIDBG_INIT, si_portp,
	    "si_find_dev_signature enter: port: %x, pmp: %x",
	    port, pmp);

	/* Build a Soft Reset PRB in host memory. */
	mutex_enter(&si_portp->siport_mutex);

	slot = si_claim_free_slot(si_ctlp, si_portp, port);
	if (slot == SI_FAILURE) {
		/* Empty slot could not be found. */
		if (pmp != PORTMULT_CONTROL_PORT) {
			/* We are behind port multiplier. */
			si_portp->siport_portmult_state.sipm_port_type[pmp] =
			    PORT_TYPE_NODEV;
		} else {
			si_portp->siport_port_type = PORT_TYPE_NODEV;
		}

		mutex_exit(&si_portp->siport_mutex);
		return;
	}
	prb = &si_portp->siport_prbpool[slot];
	bzero((void *)prb, sizeof (si_prb_t));

	SET_FIS_PMP(prb->prb_fis, pmp);
	SET_PRB_CONTROL_SOFT_RESET(prb);

#if SI_DEBUG
	if (si_debug_flags & SIDBG_DUMP_PRB) {
		char *ptr;
		int j;

		ptr = (char *)prb;
		cmn_err(CE_WARN, "si_find_dev_signature, prb: ");
		for (j = 0; j < (sizeof (si_prb_t)); j++) {
			if (j%4 == 0) {
				cmn_err(CE_WARN, "----");
			}
			cmn_err(CE_WARN, "%x ", ptr[j]);
		}

	}
#endif /* SI_DEBUG */

	/* deliver soft reset prb to empty slot. */
	POST_PRB_ADDR(si_ctlp, si_portp, port, slot);

	loop_count = 0;
	/* Loop till the soft reset is finished. */
	do {
		slot_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)(PORT_SLOT_STATUS(si_ctlp, port)));

		if (loop_count++ > SI_POLLRATE_SOFT_RESET) {
			/* We are effectively timing out after 10 sec. */
			break;
		}

		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(SI_10MS_TICKS);
#endif /* __lock_lint */

	} while (slot_status & SI_SLOT_MASK & (0x1 << slot));

	SIDBG_P(SIDBG_POLL_LOOP, si_portp,
	    "si_find_dev_signature: loop count: %d, slot_status: 0x%x",
	    loop_count, slot_status);

	CLEAR_BIT(si_portp->siport_pending_tags, slot);

	/* Read device signature from command slot. */
	signature = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SIGNATURE_MSB(si_ctlp, port, slot)));
	signature <<= 8;
	signature |= (0xff & ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SIGNATURE_LSB(si_ctlp,
	    port, slot))));

	SIDBG_P(SIDBG_INIT, si_portp, "Device signature: 0x%x", signature);

	if (signature == SI_SIGNATURE_PORT_MULTIPLIER) {

		SIDBG_P(SIDBG_INIT, si_portp,
		    "Found multiplier at cport: 0x%d, pmport: 0x%x",
		    port, pmp);

		if (pmp != PORTMULT_CONTROL_PORT) {
			/*
			 * It is wrong to chain a port multiplier behind
			 * another port multiplier.
			 */
			si_portp->siport_portmult_state.sipm_port_type[pmp] =
			    PORT_TYPE_NODEV;
		} else {
			si_portp->siport_port_type = PORT_TYPE_MULTIPLIER;
			mutex_exit(&si_portp->siport_mutex);
			(void) si_enumerate_port_multiplier(si_ctlp,
			    si_portp, port);
			mutex_enter(&si_portp->siport_mutex);
		}
		si_init_port(si_ctlp, port);

	} else if (signature == SI_SIGNATURE_ATAPI) {
		if (pmp != PORTMULT_CONTROL_PORT) {
			/* We are behind port multiplier. */
			si_portp->siport_portmult_state.sipm_port_type[pmp] =
			    PORT_TYPE_ATAPI;
		} else {
			si_portp->siport_port_type = PORT_TYPE_ATAPI;
			si_init_port(si_ctlp, port);
		}
		SIDBG_P(SIDBG_INIT, si_portp,
		    "Found atapi at : cport: %x, pmport: %x",
		    port, pmp);

	} else if (signature == SI_SIGNATURE_DISK) {

		if (pmp != PORTMULT_CONTROL_PORT) {
			/* We are behind port multiplier. */
			si_portp->siport_portmult_state.sipm_port_type[pmp] =
			    PORT_TYPE_DISK;
		} else {
			si_portp->siport_port_type = PORT_TYPE_DISK;
			si_init_port(si_ctlp, port);
		}
		SIDBG_P(SIDBG_INIT, si_portp,
		    "found disk at : cport: %x, pmport: %x",
		    port, pmp);

	} else {
		if (pmp != PORTMULT_CONTROL_PORT) {
			/* We are behind port multiplier. */
			si_portp->siport_portmult_state.sipm_port_type[pmp] =
			    PORT_TYPE_UNKNOWN;
		} else {
			si_portp->siport_port_type = PORT_TYPE_UNKNOWN;
		}
		SIDBG_P(SIDBG_INIT, si_portp,
		    "Found unknown signature 0x%x at: port: %x, pmp: %x",
		    signature, port, pmp);
	}

	mutex_exit(&si_portp->siport_mutex);
}


/*
 * Polls for the completion of the command. This is safe with both
 * interrupts enabled or disabled.
 */
static void
si_poll_cmd(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port,
	int slot,
	sata_pkt_t *satapkt)
{
	uint32_t slot_status;
	int pkt_timeout_ticks;
	uint32_t port_intr_status;
	int in_panic = ddi_in_panic();

	SIDBG_P(SIDBG_ENTRY, si_portp, "si_poll_cmd entered: port: 0x%x", port);

	pkt_timeout_ticks = drv_usectohz((clock_t)satapkt->satapkt_time *
	    1000000);


	/* we start out with SATA_PKT_COMPLETED as the satapkt_reason */
	satapkt->satapkt_reason = SATA_PKT_COMPLETED;

	do {
		slot_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)(PORT_SLOT_STATUS(si_ctlp, port)));

		if (slot_status & SI_SLOT_MASK & (0x1 << slot)) {
			if (in_panic) {
				/*
				 * If we are in panic, we can't rely on
				 * timers; so, busy wait instead of delay().
				 */
				mutex_exit(&si_portp->siport_mutex);
				drv_usecwait(SI_1MS_USECS);
				mutex_enter(&si_portp->siport_mutex);
			} else {
				mutex_exit(&si_portp->siport_mutex);
#ifndef __lock_lint
				delay(SI_1MS_TICKS);
#endif /* __lock_lint */
				mutex_enter(&si_portp->siport_mutex);
			}
		} else {
			break;
		}

		pkt_timeout_ticks -= SI_1MS_TICKS;

	} while (pkt_timeout_ticks > 0);

	if (satapkt->satapkt_reason != SATA_PKT_COMPLETED) {
		/* The si_mop_command() got to our packet before us */

		return;
	}

	/*
	 * Interrupts and timers may not be working properly in a crash dump
	 * situation; we may need to handle all the three conditions here:
	 * successful completion, packet failure and packet timeout.
	 */
	if (IS_ATTENTION_RAISED(slot_status)) { /* error seen on port */

		port_intr_status = ddi_get32(si_ctlp->sictl_global_acc_handle,
		    (uint32_t *)PORT_INTERRUPT_STATUS(si_ctlp, port));

		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "si_poll_cmd: port_intr_status: 0x%x, port: %x",
		    port_intr_status, port);

		if (port_intr_status & INTR_COMMAND_ERROR) {
			mutex_exit(&si_portp->siport_mutex);
			(void) si_intr_command_error(si_ctlp, si_portp, port);
			mutex_enter(&si_portp->siport_mutex);

			return;

			/*
			 * Why do we need to call si_intr_command_error() ?
			 *
			 * Answer: Even if the current packet is not the
			 * offending command, we need to restart the stalled
			 * port; (may be, the interrupts are not working well
			 * in panic condition). The call to routine
			 * si_intr_command_error() will achieve that.
			 *
			 * What if the interrupts are working fine and the
			 * si_intr_command_error() gets called once more from
			 * interrupt context ?
			 *
			 * Answer: The second instance of routine
			 * si_intr_command_error() will not mop anything
			 * since the first error handler has already blown
			 * away the hardware pending queues through reset.
			 *
			 * Will the si_intr_command_error() hurt current
			 * packet ?
			 *
			 * Answer: No.
			 */
		} else {
			/* Ignore any non-error interrupts at this stage */
			ddi_put32(si_ctlp->sictl_port_acc_handle,
			    (uint32_t *)(PORT_INTERRUPT_STATUS(si_ctlp,
			    port)),
			    port_intr_status & INTR_MASK);
		}

	} else if (slot_status & SI_SLOT_MASK & (0x1 << slot)) {
		satapkt->satapkt_reason = SATA_PKT_TIMEOUT;

	} /* else: the command completed successfully */

	if (satapkt->satapkt_cmd.satacmd_flags.sata_special_regs) {
		si_copy_out_regs(&satapkt->satapkt_cmd, si_ctlp, port, slot);
	}

	if ((satapkt->satapkt_cmd.satacmd_cmd_reg ==
	    SATAC_WRITE_FPDMA_QUEUED) ||
	    (satapkt->satapkt_cmd.satacmd_cmd_reg ==
	    SATAC_READ_FPDMA_QUEUED)) {
		si_portp->siport_pending_ncq_count--;
	}

	CLEAR_BIT(si_portp->siport_pending_tags, slot);

	/*
	 * tidbit: What is the interaction of abort with polling ?
	 * What happens if the current polled pkt is aborted in parallel ?
	 *
	 * Answer: Assuming that the si_mop_commands() completes ahead
	 * of polling, all it does is to set the satapkt_reason to
	 * SPKT_PKT_ABORTED. That would be fine with us.
	 *
	 * The same logic applies to reset interacting with polling.
	 */
}


/*
 * Searches for and claims a free slot.
 *
 * Returns: 	SI_FAILURE if no slots found
 *		claimed slot number if successful
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
/*ARGSUSED*/
static int
si_claim_free_slot(si_ctl_state_t *si_ctlp, si_port_state_t *si_portp, int port)
{
	uint32_t free_slots;
	int slot;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	SIDBG_P(SIDBG_ENTRY, si_portp,
	    "si_claim_free_slot entry: siport_pending_tags: %x",
	    si_portp->siport_pending_tags);

	free_slots = (~si_portp->siport_pending_tags) & SI_SLOT_MASK;
	slot = ddi_ffs(free_slots) - 1;
	if (slot == -1) {
		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "si_claim_free_slot: no empty slots", NULL);
		return (SI_FAILURE);
	}

	si_portp->siport_pending_tags |= (0x1 << slot);
	SIDBG_P(SIDBG_VERBOSE, si_portp, "si_claim_free_slot: found slot: 0x%x",
	    slot);
	return (slot);
}

/*
 * Builds the PRB for the sata packet and delivers it to controller.
 *
 * Returns:
 *	slot number if we can obtain a slot successfully
 *	otherwise, return SI_FAILURE
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static int
si_deliver_satapkt(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port,
	sata_pkt_t *spkt)
{
	int slot;
	si_prb_t *prb;
	sata_cmd_t *cmd;
	si_sge_t *sgep; /* scatter gather entry pointer */
	si_sgt_t *sgtp; /* scatter gather table pointer */
	si_sgblock_t *sgbp; /* scatter gather block pointer */
	int i, j, cookie_index;
	int ncookies;
	int is_atapi = 0;
	ddi_dma_cookie_t cookie;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	slot = si_claim_free_slot(si_ctlp, si_portp, port);
	if (slot == SI_FAILURE) {
		return (SI_FAILURE);
	}

	if (spkt->satapkt_device.satadev_type == SATA_DTYPE_ATAPICD) {
		is_atapi = 1;
	}

	if ((si_portp->siport_port_type == PORT_TYPE_NODEV) ||
	    !si_portp->siport_active) {
		/*
		 * si_intr_phy_ready_change() may have rendered it to
		 * PORT_TYPE_NODEV. cfgadm operation may have rendered
		 * it inactive.
		 */
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		fill_dev_sregisters(si_ctlp, port, &spkt->satapkt_device);
		CLEAR_BIT(si_portp->siport_pending_tags, slot);

		return (SI_FAILURE);
	}


	prb =  &(si_portp->siport_prbpool[slot]);
	bzero((void *)prb, sizeof (si_prb_t));

	cmd = &spkt->satapkt_cmd;

	SIDBG_P(SIDBG_ENTRY, si_portp,
	    "si_deliver_satpkt entry: cmd_reg: 0x%x, slot: 0x%x, \
		port: %x, satapkt: %x",
	    cmd->satacmd_cmd_reg, slot, port, (uint32_t)(intptr_t)spkt);

	/* Now fill the prb. */
	if (is_atapi) {
		if (spkt->satapkt_cmd.satacmd_flags.sata_data_direction ==
		    SATA_DIR_READ) {
			SET_PRB_CONTROL_PKT_READ(prb);
		} else if (spkt->satapkt_cmd.satacmd_flags.sata_data_direction
		    == SATA_DIR_WRITE) {
			SET_PRB_CONTROL_PKT_WRITE(prb);
		}
	}

	SET_FIS_TYPE(prb->prb_fis, REGISTER_FIS_H2D);
	if ((spkt->satapkt_device.satadev_addr.qual == SATA_ADDR_PMPORT) ||
	    (spkt->satapkt_device.satadev_addr.qual == SATA_ADDR_DPMPORT)) {
		SET_FIS_PMP(prb->prb_fis,
		    spkt->satapkt_device.satadev_addr.pmport);
	}
	SET_FIS_CDMDEVCTL(prb->prb_fis, 1);
	SET_FIS_COMMAND(prb->prb_fis, cmd->satacmd_cmd_reg);
	SET_FIS_FEATURES(prb->prb_fis, cmd->satacmd_features_reg);
	SET_FIS_SECTOR_COUNT(prb->prb_fis, cmd->satacmd_sec_count_lsb);

	switch (cmd->satacmd_addr_type) {

	case 0:
		/*
		 * satacmd_addr_type will be 0 for the commands below:
		 * 	SATAC_PACKET
		 * 	SATAC_IDLE_IM
		 * 	SATAC_STANDBY_IM
		 * 	SATAC_DOWNLOAD_MICROCODE
		 * 	SATAC_FLUSH_CACHE
		 * 	SATAC_SET_FEATURES
		 * 	SATAC_SMART
		 * 	SATAC_ID_PACKET_DEVICE
		 * 	SATAC_ID_DEVICE
		 * 	SATAC_READ_PORTMULT
		 * 	SATAC_WRITE_PORTMULT
		 */
		/* FALLTHRU */

	case ATA_ADDR_LBA:
		/* FALLTHRU */

	case ATA_ADDR_LBA28:
		/* LBA[7:0] */
		SET_FIS_SECTOR(prb->prb_fis, cmd->satacmd_lba_low_lsb);

		/* LBA[15:8] */
		SET_FIS_CYL_LOW(prb->prb_fis, cmd->satacmd_lba_mid_lsb);

		/* LBA[23:16] */
		SET_FIS_CYL_HI(prb->prb_fis, cmd->satacmd_lba_high_lsb);

		/* LBA [27:24] (also called dev_head) */
		SET_FIS_DEV_HEAD(prb->prb_fis, cmd->satacmd_device_reg);

		break;

	case ATA_ADDR_LBA48:
		/* LBA[7:0] */
		SET_FIS_SECTOR(prb->prb_fis, cmd->satacmd_lba_low_lsb);

		/* LBA[15:8] */
		SET_FIS_CYL_LOW(prb->prb_fis, cmd->satacmd_lba_mid_lsb);

		/* LBA[23:16] */
		SET_FIS_CYL_HI(prb->prb_fis, cmd->satacmd_lba_high_lsb);

		/* LBA [31:24] */
		SET_FIS_SECTOR_EXP(prb->prb_fis, cmd->satacmd_lba_low_msb);

		/* LBA [39:32] */
		SET_FIS_CYL_LOW_EXP(prb->prb_fis, cmd->satacmd_lba_mid_msb);

		/* LBA [47:40] */
		SET_FIS_CYL_HI_EXP(prb->prb_fis, cmd->satacmd_lba_high_msb);

		/* Set dev_head */
		SET_FIS_DEV_HEAD(prb->prb_fis, cmd->satacmd_device_reg);

		/* Set the extended sector count and features */
		SET_FIS_SECTOR_COUNT_EXP(prb->prb_fis,
		    cmd->satacmd_sec_count_msb);
		SET_FIS_FEATURES_EXP(prb->prb_fis,
		    cmd->satacmd_features_reg_ext);

		break;

	}

	if (cmd->satacmd_flags.sata_queued) {
		/*
		 * For queued commands, the TAG for the sector count lsb is
		 * generated from current slot number.
		 */
		SET_FIS_SECTOR_COUNT(prb->prb_fis, slot << 3);
	}

	if ((cmd->satacmd_cmd_reg == SATAC_WRITE_FPDMA_QUEUED) ||
	    (cmd->satacmd_cmd_reg == SATAC_READ_FPDMA_QUEUED)) {
		si_portp->siport_pending_ncq_count++;
	}

	/* *** now fill the scatter gather list ******* */

	if (is_atapi) { /* It is an ATAPI drive */
		/* atapi command goes into sge0 */
		bcopy(cmd->satacmd_acdb, &prb->prb_sge0, sizeof (si_sge_t));

		/* Now fill sge1 with pointer to external SGT. */
		if (spkt->satapkt_cmd.satacmd_num_dma_cookies) {
			prb->prb_sge1.sge_addr =
			    si_portp->siport_sgbpool_physaddr +
			    slot * sizeof (si_sgblock_t) * si_dma_sg_number;
			SET_SGE_LNK(prb->prb_sge1);
		} else {
			SET_SGE_TRM(prb->prb_sge1);
		}
	} else {
		/* Fill the sge0 */
		if (spkt->satapkt_cmd.satacmd_num_dma_cookies) {
			prb->prb_sge0.sge_addr =
			    si_portp->siport_sgbpool_physaddr +
			    slot * sizeof (si_sgblock_t) * si_dma_sg_number;
			SET_SGE_LNK(prb->prb_sge0);

		} else {
			SET_SGE_TRM(prb->prb_sge0);
		}

		/* sge1 is left empty in non-ATAPI case */
	}

	bzero(&si_portp->siport_sgbpool[slot * si_dma_sg_number],
	    sizeof (si_sgblock_t) * si_dma_sg_number);

	ncookies = spkt->satapkt_cmd.satacmd_num_dma_cookies;
	ASSERT(ncookies <= (SGE_LENGTH(si_dma_sg_number)));

	SIDBG_P(SIDBG_COOKIES, si_portp, "total ncookies: %d", ncookies);
	if (ncookies == 0) {
		sgbp = &si_portp->siport_sgbpool[slot * si_dma_sg_number];
		sgtp = &sgbp->sgb_sgt[0];
		sgep = &sgtp->sgt_sge[0];

		/* No cookies. Terminate the chain. */
		SIDBG_P(SIDBG_COOKIES, si_portp, "empty cookies: terminating.",
		    NULL);

		sgep->sge_addr_low = 0;
		sgep->sge_addr_high = 0;
		sgep->sge_data_count = 0;
		SET_SGE_TRM((*sgep));

		goto sgl_fill_done;
	}

	for (i = 0, cookie_index = 0,
	    sgbp = &si_portp->siport_sgbpool[slot * si_dma_sg_number];
	    i < si_dma_sg_number; i++) {

		sgtp = &sgbp->sgb_sgt[0] + i;

		/* Now fill the first 3 entries of SGT in the loop below. */
		for (j = 0, sgep = &sgtp->sgt_sge[0];
		    ((j < 3) && (cookie_index < ncookies-1));
		    j++, cookie_index++, sgep++)  {
			ASSERT(cookie_index < ncookies);
			SIDBG_P(SIDBG_COOKIES, si_portp,
			    "inner loop: cookie_index: %d, ncookies: %d",
			    cookie_index,
			    ncookies);
			cookie = spkt->satapkt_cmd.
			    satacmd_dma_cookie_list[cookie_index];

			sgep->sge_addr_low = cookie._dmu._dmac_la[0];
			sgep->sge_addr_high = cookie._dmu._dmac_la[1];
			sgep->sge_data_count = (uint32_t)cookie.dmac_size;
		}

		/*
		 * If this happens to be the last cookie, we terminate it here.
		 * Otherwise, we link to next SGT.
		 */

		if (cookie_index == ncookies-1) {
			/* This is the last cookie. Terminate the chain. */
			SIDBG_P(SIDBG_COOKIES, si_portp,
			    "filling the last: cookie_index: %d, "
			    "ncookies: %d",
			    cookie_index,
			    ncookies);
			cookie = spkt->satapkt_cmd.
			    satacmd_dma_cookie_list[cookie_index];

			sgep->sge_addr_low = cookie._dmu._dmac_la[0];
			sgep->sge_addr_high = cookie._dmu._dmac_la[1];
			sgep->sge_data_count = (uint32_t)cookie.dmac_size;
			SET_SGE_TRM((*sgep));

			break; /* we break the loop */

		} else {
			/* This is not the last one. So link it. */
			SIDBG_P(SIDBG_COOKIES, si_portp,
			    "linking SGT: cookie_index: %d, ncookies: %d",
			    cookie_index,
			    ncookies);
			sgep->sge_addr = si_portp->siport_sgbpool_physaddr +
			    slot * sizeof (si_sgblock_t) * si_dma_sg_number +
			    (i+1) * sizeof (si_sgt_t);

			SET_SGE_LNK((*sgep));
		}

	}

	/* *** finished filling the scatter gather list ******* */

sgl_fill_done:
	/* Now remember the sata packet in siport_slot_pkts[]. */
	si_portp->siport_slot_pkts[slot] = spkt;

	/*
	 * We are overloading satapkt_hba_driver_private with
	 * watched_cycle count.
	 */
	spkt->satapkt_hba_driver_private = (void *)(intptr_t)0;

	if (is_atapi) {
		/* program the packet_lenth if it is atapi device. */


#ifdef ATAPI_2nd_PHASE
		/*
		 * Framework needs to calculate the acdb_len based on
		 * identify packet data. This needs to be accomplished
		 * in second phase of the project.
		 */
		ASSERT((cmd->satacmd_acdb_len == 12) ||
		    (cmd->satacmd_acdb_len == 16));
		SIDBG_P(SIDBG_VERBOSE, si_portp, "deliver: acdb_len: %d",
		    cmd->satacmd_acdb_len);

		if (cmd->satacmd_acdb_len == 16) {
			ddi_put32(si_ctlp->sictl_port_acc_handle,
			    (uint32_t *)PORT_CONTROL_SET(si_ctlp, port),
			    PORT_CONTROL_SET_BITS_PACKET_LEN);
		} else {
			ddi_put32(si_ctlp->sictl_port_acc_handle,
			    (uint32_t *)PORT_CONTROL_CLEAR(si_ctlp, port),
			    PORT_CONTROL_CLEAR_BITS_PACKET_LEN);
		}

#else /* ATAPI_2nd_PHASE */
		/* hard coding for now to 12 bytes */
		ddi_put32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_CONTROL_CLEAR(si_ctlp, port),
		    PORT_CONTROL_CLEAR_BITS_PACKET_LEN);
#endif /* ATAPI_2nd_PHASE */
	}


#if SI_DEBUG
	if (si_debug_flags & SIDBG_DUMP_PRB) {
		if (!(is_atapi && (prb->prb_sge0.sge_addr_low == 0))) {
			/*
			 * Do not dump the atapi Test-Unit-Ready commands.
			 * The sd_media_watch spews too many of these.
			 */
			int *ptr;
			si_sge_t *tmpsgep;
			int j;

			ptr = (int *)(void *)prb;
			cmn_err(CE_WARN, "si_deliver_satpkt prb: ");
			for (j = 0; j < (sizeof (si_prb_t)/4); j++) {
				cmn_err(CE_WARN, "%x ", ptr[j]);
			}

			cmn_err(CE_WARN,
			    "si_deliver_satpkt sgt: low, high, count link");
			for (j = 0,
			    tmpsgep = (si_sge_t *)
			    &si_portp->siport_sgbpool[slot * si_dma_sg_number];
			    j < (sizeof (si_sgblock_t)/ sizeof (si_sge_t))
			    *si_dma_sg_number;
			    j++, tmpsgep++) {
				ptr = (int *)(void *)tmpsgep;
				cmn_err(CE_WARN, "%x %x %x %x",
				    ptr[0],
				    ptr[1],
				    ptr[2],
				    ptr[3]);
				if (IS_SGE_TRM_SET((*tmpsgep))) {
					break;
				}

			}
		}

	}
#endif  /* SI_DEBUG */

	/* Deliver PRB */
	POST_PRB_ADDR(si_ctlp, si_portp, port, slot);

	return (slot);
}

/*
 * Initialize the controller and set up driver data structures.
 *
 * This routine can be called from three separate cases: DDI_ATTACH, PM_LEVEL_D0
 * and DDI_RESUME. The DDI_ATTACH case is different from other two cases; the
 * memory allocation & device signature probing are attempted only during
 * DDI_ATTACH case. In the case of PM_LEVEL_D0 & DDI_RESUME, we are starting
 * from a previously initialized state; so there is no need to allocate memory
 * or to attempt probing the device signatures.
 */
static int
si_initialize_controller(si_ctl_state_t *si_ctlp)
{
	uint32_t port_status;
	uint32_t SStatus;
	uint32_t SControl;
	uint8_t port;
	int loop_count = 0;
	si_port_state_t *si_portp;

	SIDBG_C(SIDBG_INIT, si_ctlp,
	    "si3124: si_initialize_controller entered", NULL);

	mutex_enter(&si_ctlp->sictl_mutex);

	/* Remove the Global Reset. */
	ddi_put32(si_ctlp->sictl_global_acc_handle,
	    (uint32_t *)GLOBAL_CONTROL_REG(si_ctlp),
	    GLOBAL_CONTROL_REG_BITS_CLEAR);

	for (port = 0; port < si_ctlp->sictl_num_ports; port++) {

		if (si_ctlp->sictl_flags & SI_ATTACH) {
			/*
			 * We allocate the port state only during attach
			 * sequence. We don't want to do it during
			 * suspend/resume sequence.
			 */
			if (si_alloc_port_state(si_ctlp, port)) {
				mutex_exit(&si_ctlp->sictl_mutex);
				return (SI_FAILURE);
			}
		}

		si_portp = si_ctlp->sictl_ports[port];
		mutex_enter(&si_portp->siport_mutex);
		si_portp->siport_ctlp = si_ctlp;
		si_portp->siport_port_num = port;

		/* Clear Port Reset. */
		ddi_put32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_CONTROL_SET(si_ctlp, port),
		    PORT_CONTROL_SET_BITS_PORT_RESET);
		ddi_put32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_CONTROL_CLEAR(si_ctlp, port),
		    PORT_CONTROL_CLEAR_BITS_PORT_RESET);

		/*
		 * Arm the interrupts for: Cmd completion, Cmd error,
		 * Port Ready, PM Change, PhyRdyChange, Commwake,
		 * UnrecFIS, Devxchanged, SDBNotify.
		 */
		ddi_put32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_INTERRUPT_ENABLE_SET(si_ctlp, port),
		    (INTR_COMMAND_COMPLETE |
		    INTR_COMMAND_ERROR |
		    INTR_PORT_READY |
		    INTR_POWER_CHANGE |
		    INTR_PHYRDY_CHANGE |
		    INTR_COMWAKE_RECEIVED |
		    INTR_UNRECOG_FIS |
		    INTR_DEV_XCHANGED |
		    INTR_SETDEVBITS_NOTIFY));

		/* Now enable the interrupts. */
		si_enable_port_interrupts(si_ctlp, port);

		/*
		 * The following PHY initialization is redundant in
		 * in x86 since the BIOS anyway does this as part of
		 * device enumeration during the power up. But this
		 * is a required step in sparc since there is no BIOS.
		 *
		 * The way to initialize the PHY is to write a 1 and then
		 * a 0 to DET field of SControl register.
		 */

		/*
		 * Fetch the current SControl before writing the
		 * DET part with 1
		 */
		SControl = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_SCONTROL(si_ctlp, port));
		SCONTROL_SET_DET(SControl, SCONTROL_DET_COMRESET);
		ddi_put32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)(PORT_SCONTROL(si_ctlp, port)),
		    SControl);
#ifndef __lock_lint
		delay(SI_10MS_TICKS); /* give time for COMRESET to percolate */
#endif /* __lock_lint */

		/*
		 * Now fetch the SControl again and rewrite the
		 * DET part with 0
		 */
		SControl = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_SCONTROL(si_ctlp, port));
		SCONTROL_SET_DET(SControl, SCONTROL_DET_NOACTION);
		ddi_put32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)(PORT_SCONTROL(si_ctlp, port)),
		    SControl);

		/*
		 * PHY may be initialized by now. Check the DET field of
		 * SStatus to determine if there is a device present.
		 *
		 * The DET field is valid only if IPM field indicates that
		 * the interface is in active state.
		 */

		loop_count = 0;
		do {
			SStatus = ddi_get32(si_ctlp->sictl_port_acc_handle,
			    (uint32_t *)PORT_SSTATUS(si_ctlp, port));

			if (SSTATUS_GET_IPM(SStatus) !=
			    SSTATUS_IPM_INTERFACE_ACTIVE) {
				/*
				 * If the interface is not active, the DET field
				 * is considered not accurate. So we want to
				 * continue looping.
				 */
				SSTATUS_SET_DET(SStatus,
				    SSTATUS_DET_NODEV_NOPHY);
			}

			if (loop_count++ > SI_POLLRATE_SSTATUS) {
				/*
				 * We are effectively timing out after 0.1 sec.
				 */
				break;
			}

			/* Wait for 10 millisec */
#ifndef __lock_lint
			delay(SI_10MS_TICKS);
#endif /* __lock_lint */

		} while (SSTATUS_GET_DET(SStatus) !=
		    SSTATUS_DET_DEVPRESENT_PHYONLINE);

		SIDBG_P(SIDBG_POLL_LOOP, si_portp,
		    "si_initialize_controller: 1st loop count: %d, "
		    "SStatus: 0x%x",
		    loop_count,
		    SStatus);

		if ((SSTATUS_GET_IPM(SStatus) !=
		    SSTATUS_IPM_INTERFACE_ACTIVE) ||
		    (SSTATUS_GET_DET(SStatus) !=
		    SSTATUS_DET_DEVPRESENT_PHYONLINE)) {
			/*
			 * Either the port is not active or there
			 * is no device present.
			 */
			si_ctlp->sictl_ports[port]->siport_port_type =
			    PORT_TYPE_NODEV;
			mutex_exit(&si_portp->siport_mutex);
			continue;
		}

		/* Wait until Port Ready */
		loop_count = 0;
		do {
			port_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
			    (uint32_t *)PORT_STATUS(si_ctlp, port));

			if (loop_count++ > SI_POLLRATE_PORTREADY) {
				/*
				 * We are effectively timing out after 0.5 sec.
				 */
				break;
			}

			/* Wait for 10 millisec */
#ifndef __lock_lint
			delay(SI_10MS_TICKS);
#endif /* __lock_lint */

		} while (!(port_status & PORT_STATUS_BITS_PORT_READY));

		SIDBG_P(SIDBG_POLL_LOOP, si_portp,
		    "si_initialize_controller: 2nd loop count: %d",
		    loop_count);

		if (si_ctlp->sictl_flags & SI_ATTACH) {
			/*
			 * We want to probe for dev signature only during attach
			 * case. Don't do it during suspend/resume sequence.
			 */
			if (port_status & PORT_STATUS_BITS_PORT_READY) {
				mutex_exit(&si_portp->siport_mutex);
				si_find_dev_signature(si_ctlp, si_portp, port,
				    PORTMULT_CONTROL_PORT);
				mutex_enter(&si_portp->siport_mutex);
			} else {
				si_ctlp->sictl_ports[port]->siport_port_type =
				    PORT_TYPE_NODEV;
			}
		}

		if (si_check_ctl_handles(si_ctlp) != DDI_SUCCESS ||
		    si_check_port_handles(si_portp) != DDI_SUCCESS) {
			ddi_fm_service_impact(si_ctlp->sictl_devinfop,
			    DDI_SERVICE_LOST);
			mutex_exit(&si_portp->siport_mutex);
			mutex_exit(&si_ctlp->sictl_mutex);
			return (SI_FAILURE);
		}

		mutex_exit(&si_portp->siport_mutex);
	}

	mutex_exit(&si_ctlp->sictl_mutex);
	return (SI_SUCCESS);
}

/*
 * Reverse of si_initialize_controller().
 *
 * WARNING, WARNING: The caller is expected to obtain the sictl_mutex
 * before calling us.
 */
static void
si_deinitialize_controller(si_ctl_state_t *si_ctlp)
{
	int port;

	_NOTE(ASSUMING_PROTECTED(si_ctlp))

	SIDBG_C(SIDBG_INIT, si_ctlp,
	    "si3124: si_deinitialize_controller entered", NULL);

	/* disable all the interrupts. */
	si_disable_all_interrupts(si_ctlp);

	if (si_ctlp->sictl_flags & SI_DETACH) {
		/*
		 * We want to dealloc all the memory in detach case.
		 */
		for (port = 0; port < si_ctlp->sictl_num_ports; port++) {
			si_dealloc_port_state(si_ctlp, port);
		}
	}

}

/*
 * Prepare the port ready for usage.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static void
si_init_port(si_ctl_state_t *si_ctlp, int port)
{

	SIDBG_C(SIDBG_INIT, si_ctlp,
	    "si_init_port entered: port: 0x%x",
	    port);

	/* Initialize the port. */
	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_CONTROL_SET(si_ctlp, port),
	    PORT_CONTROL_SET_BITS_PORT_INITIALIZE);

	/*
	 * Clear the InterruptNCOR (Interrupt No Clear on Read).
	 * This step ensures that a mere reading of slot_status will clear
	 * the interrupt; no explicit clearing of interrupt condition
	 * will be needed for successful completion of commands.
	 */
	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_CONTROL_CLEAR(si_ctlp, port),
	    PORT_CONTROL_CLEAR_BITS_INTR_NCoR);

	/* clear any pending interrupts at this point */
	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_INTERRUPT_STATUS(si_ctlp, port)),
	    INTR_MASK);

}


/*
 * Enumerate the devices connected to the port multiplier.
 * Once a device is detected, we call si_find_dev_signature()
 * to find the type of device connected. Even though we are
 * called from within si_find_dev_signature(), there is no
 * recursion possible.
 */
static int
si_enumerate_port_multiplier(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	uint32_t num_dev_ports = 0;
	int pmport;
	uint32_t SControl = 0;
	uint32_t SStatus = 0;
	uint32_t SError = 0;
	int loop_count = 0;

	SIDBG_P(SIDBG_INIT, si_portp,
	    "si_enumerate_port_multiplier entered: port: %d",
	    port);

	mutex_enter(&si_portp->siport_mutex);

	/* Enable Port Multiplier context switching. */
	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_CONTROL_SET(si_ctlp, port),
	    PORT_CONTROL_SET_BITS_PM_ENABLE);

	/*
	 * Read the num dev ports connected.
	 * GSCR[2] contains the number of device ports.
	 */
	if (si_read_portmult_reg(si_ctlp, si_portp, port, PORTMULT_CONTROL_PORT,
	    PSCR_REG2, &num_dev_ports)) {
		mutex_exit(&si_portp->siport_mutex);
		return (SI_FAILURE);
	}
	si_portp->siport_portmult_state.sipm_num_ports = num_dev_ports;

	SIDBG_P(SIDBG_INIT, si_portp,
	    "si_enumerate_port_multiplier: ports found: %d",
	    num_dev_ports);

	for (pmport = 0; pmport < num_dev_ports-1; pmport++) {
		/*
		 * Enable PHY by writing a 1, then a 0 to SControl
		 * (i.e. PSCR[2]) DET field.
		 */
		if (si_read_portmult_reg(si_ctlp, si_portp, port, pmport,
		    PSCR_REG2, &SControl)) {
			continue;
		}

		/* First write a 1 to DET field of SControl. */
		SCONTROL_SET_DET(SControl, SCONTROL_DET_COMRESET);
		if (si_write_portmult_reg(si_ctlp, si_portp, port, pmport,
		    PSCR_REG2, SControl)) {
			continue;
		}
#ifndef __lock_lint
		delay(SI_10MS_TICKS); /* give time for COMRESET to percolate */
#endif /* __lock_lint */

		/* Then write a 0 to the DET field of SControl. */
		SCONTROL_SET_DET(SControl, SCONTROL_DET_NOACTION);
		if (si_write_portmult_reg(si_ctlp, si_portp, port, pmport,
		    PSCR_REG2, SControl)) {
			continue;
		}

		/* Wait for PHYRDY by polling SStatus (i.e. PSCR[0]). */
		loop_count = 0;
		do {
			if (si_read_portmult_reg(si_ctlp, si_portp, port,
			    pmport, PSCR_REG0, &SStatus)) {
				break;
			}
			SIDBG_P(SIDBG_POLL_LOOP, si_portp,
			    "looping for PHYRDY: SStatus: %x",
			    SStatus);

			if (SSTATUS_GET_IPM(SStatus) !=
			    SSTATUS_IPM_INTERFACE_ACTIVE) {
				/*
				 * If the interface is not active, the DET field
				 * is considered not accurate. So we want to
				 * continue looping.
				 */
				SSTATUS_SET_DET(SStatus,
				    SSTATUS_DET_NODEV_NOPHY);
			}

			if (loop_count++ > SI_POLLRATE_SSTATUS) {
				/*
				 * We are effectively timing out after 0.1 sec.
				 */
				break;
			}

			/* Wait for 10 millisec */
#ifndef __lock_lint
			delay(SI_10MS_TICKS);
#endif /* __lock_lint */

		} while (SSTATUS_GET_DET(SStatus) !=
		    SSTATUS_DET_DEVPRESENT_PHYONLINE);

		SIDBG_P(SIDBG_POLL_LOOP, si_portp,
		    "si_enumerate_port_multiplier: "
		    "loop count: %d, SStatus: 0x%x",
		    loop_count,
		    SStatus);

		if ((SSTATUS_GET_IPM(SStatus) ==
		    SSTATUS_IPM_INTERFACE_ACTIVE) &&
		    (SSTATUS_GET_DET(SStatus) ==
		    SSTATUS_DET_DEVPRESENT_PHYONLINE)) {
			/* The interface is active and the device is present */
			SIDBG_P(SIDBG_INIT, si_portp,
			    "Status: %x, device exists",
			    SStatus);
			/*
			 * Clear error bits in SError register (i.e. PSCR[1]
			 * by writing back error bits.
			 */
			if (si_read_portmult_reg(si_ctlp, si_portp, port,
			    pmport, PSCR_REG1, &SError)) {
				continue;
			}
			SIDBG_P(SIDBG_INIT, si_portp,
			    "SError bits are: %x", SError);
			if (si_write_portmult_reg(si_ctlp, si_portp, port,
			    pmport, PSCR_REG1, SError)) {
				continue;
			}

			/* There exists a device. */
			mutex_exit(&si_portp->siport_mutex);
			si_find_dev_signature(si_ctlp, si_portp, port, pmport);
			mutex_enter(&si_portp->siport_mutex);
		}
	}

	mutex_exit(&si_portp->siport_mutex);

	return (SI_SUCCESS);
}


/*
 * Read a port multiplier register.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static int
si_read_portmult_reg(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port,
	int pmport,
	int regnum,
	uint32_t *regval)
{
	int slot;
	si_prb_t *prb;
	uint32_t *prb_word_ptr;
	int i;
	uint32_t slot_status;
	int loop_count = 0;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	SIDBG_P(SIDBG_ENTRY, si_portp, "si_read_portmult_reg: port: %x,"
	    "pmport: %x, regnum: %x",
	    port, pmport, regnum);

	slot = si_claim_free_slot(si_ctlp, si_portp, port);
	if (slot == SI_FAILURE) {
		return (SI_FAILURE);
	}

	prb =  &(si_portp->siport_prbpool[slot]);
	bzero((void *)prb, sizeof (si_prb_t));

	/* Now fill the prb. */
	SET_FIS_TYPE(prb->prb_fis, REGISTER_FIS_H2D);
	SET_FIS_PMP(prb->prb_fis, PORTMULT_CONTROL_PORT);
	SET_FIS_CDMDEVCTL(prb->prb_fis, 1);
	SET_FIS_COMMAND(prb->prb_fis, SATAC_READ_PM_REG);

	SET_FIS_DEV_HEAD(prb->prb_fis, pmport);
	SET_FIS_FEATURES(prb->prb_fis, regnum);

	/* no real data transfer is involved. */
	SET_SGE_TRM(prb->prb_sge0);

#if SI_DEBUG
	if (si_debug_flags & SIDBG_DUMP_PRB) {
		int *ptr;
		int j;

		ptr = (int *)(void *)prb;
		cmn_err(CE_WARN, "read_port_mult_reg, prb: ");
		for (j = 0; j < (sizeof (si_prb_t)/4); j++) {
			cmn_err(CE_WARN, "%x ", ptr[j]);
		}

	}
#endif /* SI_DEBUG */

	/* Deliver PRB */
	POST_PRB_ADDR(si_ctlp, si_portp, port, slot);

	/* Loop till the command is finished. */
	do {
		slot_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)(PORT_SLOT_STATUS(si_ctlp, port)));

		SIDBG_P(SIDBG_POLL_LOOP, si_portp,
		    "looping read_pm slot_status: 0x%x",
		    slot_status);

		if (loop_count++ > SI_POLLRATE_SLOTSTATUS) {
			/* We are effectively timing out after 0.5 sec. */
			break;
		}

		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(SI_10MS_TICKS);
#endif /* __lock_lint */

	} while (slot_status & SI_SLOT_MASK & (0x1 << slot));

	SIDBG_P(SIDBG_POLL_LOOP, si_portp,
	    "read_portmult_reg: loop count: %d",
	    loop_count);

	CLEAR_BIT(si_portp->siport_pending_tags, slot);

	/* Now inspect the port LRAM for the modified FIS. */
	prb_word_ptr = (uint32_t *)(void *)prb;
	for (i = 0; i < (sizeof (si_prb_t)/4); i++) {
		prb_word_ptr[i] = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)(PORT_LRAM(si_ctlp, port, slot)+i*4));
	}

	if (si_check_ctl_handles(si_ctlp) != DDI_SUCCESS ||
	    si_check_port_handles(si_portp) != DDI_SUCCESS) {
		ddi_fm_service_impact(si_ctlp->sictl_devinfop,
		    DDI_SERVICE_UNAFFECTED);
		return (SI_FAILURE);
	}

	if (((GET_FIS_COMMAND(prb->prb_fis) & 0x1) != 0) ||
	    (GET_FIS_FEATURES(prb->prb_fis) != 0)) {
		/* command failed. */
		return (SI_FAILURE);
	}

	/* command succeeded. */
	*regval = (GET_FIS_SECTOR_COUNT(prb->prb_fis) & 0xff) |
	    ((GET_FIS_SECTOR(prb->prb_fis) << 8)  & 0xff00) |
	    ((GET_FIS_CYL_LOW(prb->prb_fis) << 16)  & 0xff0000) |
	    ((GET_FIS_CYL_HI(prb->prb_fis) << 24)  & 0xff000000);

	return (SI_SUCCESS);
}

/*
 * Write a port multiplier register.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static int
si_write_portmult_reg(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port,
	int pmport,
	int regnum,
	uint32_t regval)
{
	int slot;
	si_prb_t *prb;
	uint32_t *prb_word_ptr;
	uint32_t slot_status;
	int i;
	int loop_count = 0;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	SIDBG_P(SIDBG_ENTRY, si_portp,
	    "si_write_portmult_reg: port: %x, pmport: %x,"
	    "regnum: %x, regval: %x",
	    port, pmport, regnum, regval);

	slot = si_claim_free_slot(si_ctlp, si_portp, port);
	if (slot == SI_FAILURE) {
		return (SI_FAILURE);
	}

	prb =  &(si_portp->siport_prbpool[slot]);
	bzero((void *)prb, sizeof (si_prb_t));

	/* Now fill the prb. */
	SET_FIS_TYPE(prb->prb_fis, REGISTER_FIS_H2D);
	SET_FIS_PMP(prb->prb_fis, PORTMULT_CONTROL_PORT);
	SET_FIS_CDMDEVCTL(prb->prb_fis, 1);

	SET_FIS_COMMAND(prb->prb_fis, SATAC_WRITE_PM_REG);
	SET_FIS_DEV_HEAD(prb->prb_fis, pmport);
	SET_FIS_FEATURES(prb->prb_fis, regnum);

	SET_FIS_SECTOR_COUNT(prb->prb_fis, regval & 0xff);
	SET_FIS_SECTOR(prb->prb_fis, (regval >> 8) & 0xff);
	SET_FIS_CYL_LOW(prb->prb_fis, (regval >> 16) & 0xff);
	SET_FIS_CYL_HI(prb->prb_fis, (regval >> 24)  & 0xff);

	/* no real data transfer is involved. */
	SET_SGE_TRM(prb->prb_sge0);

#if SI_DEBUG
	if (si_debug_flags & SIDBG_DUMP_PRB) {
		int *ptr;
		int j;

		ptr = (int *)(void *)prb;
		cmn_err(CE_WARN, "read_port_mult_reg, prb: ");
		for (j = 0; j < (sizeof (si_prb_t)/4); j++) {
			cmn_err(CE_WARN, "%x ", ptr[j]);
		}

	}
#endif /* SI_DEBUG */

	/* Deliver PRB */
	POST_PRB_ADDR(si_ctlp, si_portp, port, slot);

	/* Loop till the command is finished. */
	do {
		slot_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)(PORT_SLOT_STATUS(si_ctlp, port)));

		SIDBG_P(SIDBG_POLL_LOOP, si_portp,
		    "looping write_pmp slot_status: 0x%x",
		    slot_status);

		if (loop_count++ > SI_POLLRATE_SLOTSTATUS) {
			/* We are effectively timing out after 0.5 sec. */
			break;
		}

		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(SI_10MS_TICKS);
#endif /* __lock_lint */

	} while (slot_status & SI_SLOT_MASK & (0x1 << slot));

	SIDBG_P(SIDBG_POLL_LOOP, si_portp,
	    "write_portmult_reg: loop count: %d",
	    loop_count);

	CLEAR_BIT(si_portp->siport_pending_tags, slot);

	/* Now inspect the port LRAM for the modified FIS. */
	prb_word_ptr = (uint32_t *)(void *)prb;
	for (i = 0; i < (sizeof (si_prb_t)/4); i++) {
		prb_word_ptr[i] = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)(PORT_LRAM(si_ctlp, port, slot)+i*4));
	}

	if (si_check_ctl_handles(si_ctlp) != DDI_SUCCESS ||
	    si_check_port_handles(si_portp) != DDI_SUCCESS) {
		ddi_fm_service_impact(si_ctlp->sictl_devinfop,
		    DDI_SERVICE_UNAFFECTED);
		return (SI_FAILURE);
	}

	if (((GET_FIS_COMMAND(prb->prb_fis) & 0x1) != 0) ||
	    (GET_FIS_FEATURES(prb->prb_fis) != 0)) {
		/* command failed */
		return (SI_FAILURE);
	}

	/* command succeeded */
	return (SI_SUCCESS);
}


/*
 * Set the auto sense data for ATAPI devices.
 *
 * Note: Currently the sense data is simulated; this code will be enhanced
 * in second phase to fetch the real sense data from the atapi device.
 */
static void
si_set_sense_data(sata_pkt_t *satapkt, int reason)
{
	struct scsi_extended_sense *sense;

	sense = (struct scsi_extended_sense *)
	    satapkt->satapkt_cmd.satacmd_rqsense;
	bzero(sense, sizeof (struct scsi_extended_sense));
	sense->es_valid = 1;		/* Valid sense */
	sense->es_class = 7;		/* Response code 0x70 - current err */
	sense->es_key = 0;
	sense->es_info_1 = 0;
	sense->es_info_2 = 0;
	sense->es_info_3 = 0;
	sense->es_info_4 = 0;
	sense->es_add_len = 6;		/* Additional length */
	sense->es_cmd_info[0] = 0;
	sense->es_cmd_info[1] = 0;
	sense->es_cmd_info[2] = 0;
	sense->es_cmd_info[3] = 0;
	sense->es_add_code = 0;
	sense->es_qual_code = 0;

	if ((reason == SATA_PKT_DEV_ERROR) || (reason == SATA_PKT_TIMEOUT)) {
		sense->es_key = KEY_HARDWARE_ERROR;
	}
}


/*
 * Interrupt service handler. We loop through each of the ports to find
 * if the interrupt belongs to any of them.
 *
 * Bulk of the interrupt handling is actually done out of subroutines
 * like si_intr_command_complete() etc.
 */
/*ARGSUSED*/
static uint_t
si_intr(caddr_t arg1, caddr_t arg2)
{
	si_ctl_state_t *si_ctlp = (si_ctl_state_t *)(void *)arg1;
	si_port_state_t *si_portp;
	uint32_t global_intr_status;
	uint32_t mask, port_intr_status;
	int port;

	global_intr_status = ddi_get32(si_ctlp->sictl_global_acc_handle,
	    (uint32_t *)GLOBAL_INTERRUPT_STATUS(si_ctlp));

	SIDBG_C(SIDBG_INTR, si_ctlp,
	    "si_intr: global_int_status: 0x%x",
	    global_intr_status);

	if (si_check_acc_handle(si_ctlp->sictl_global_acc_handle) !=
	    DDI_SUCCESS) {
		ddi_fm_service_impact(si_ctlp->sictl_devinfop,
		    DDI_SERVICE_UNAFFECTED);
		return (DDI_INTR_UNCLAIMED);
	}

	if (!(global_intr_status & SI31xx_INTR_PORT_MASK)) {
		/* Sorry, the interrupt is not ours. */
		return (DDI_INTR_UNCLAIMED);
	}

	/* Loop for all the ports. */
	for (port = 0; port < si_ctlp->sictl_num_ports; port++) {

		mask = 0x1 << port;
		if (!(global_intr_status & mask)) {
			continue;
		}

		mutex_enter(&si_ctlp->sictl_mutex);
		si_portp = si_ctlp->sictl_ports[port];
		mutex_exit(&si_ctlp->sictl_mutex);

		port_intr_status = ddi_get32(si_ctlp->sictl_global_acc_handle,
		    (uint32_t *)PORT_INTERRUPT_STATUS(si_ctlp, port));

		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "s_intr: port_intr_status: 0x%x, port: %x",
		    port_intr_status,
		    port);

		if (port_intr_status & INTR_COMMAND_COMPLETE) {
			(void) si_intr_command_complete(si_ctlp, si_portp,
			    port);

			mutex_enter(&si_portp->siport_mutex);
			if (si_check_ctl_handles(si_ctlp) != DDI_SUCCESS ||
			    si_check_port_handles(si_portp) != DDI_SUCCESS) {
				ddi_fm_service_impact(si_ctlp->sictl_devinfop,
				    DDI_SERVICE_UNAFFECTED);
				si_schedule_port_initialize(si_ctlp, si_portp,
				    port);
			}
			mutex_exit(&si_portp->siport_mutex);
		} else {
			/* Clear the interrupts */
			ddi_put32(si_ctlp->sictl_port_acc_handle,
			    (uint32_t *)(PORT_INTERRUPT_STATUS(si_ctlp, port)),
			    port_intr_status & INTR_MASK);
		}

		/*
		 * Note that we did not clear the interrupt for command
		 * completion interrupt. Reading of slot_status takes care
		 * of clearing the interrupt for command completion case.
		 */

		if (port_intr_status & INTR_COMMAND_ERROR) {
			si_schedule_intr_command_error(si_ctlp, si_portp, port);
		}

		if (port_intr_status & INTR_PORT_READY) {
			(void) si_intr_port_ready(si_ctlp, si_portp, port);
		}

		if (port_intr_status & INTR_POWER_CHANGE) {
			(void) si_intr_pwr_change(si_ctlp, si_portp, port);
		}

		if (port_intr_status & INTR_PHYRDY_CHANGE) {
			(void) si_intr_phy_ready_change(si_ctlp, si_portp,
			    port);
		}

		if (port_intr_status & INTR_COMWAKE_RECEIVED) {
			(void) si_intr_comwake_rcvd(si_ctlp, si_portp,
			    port);
		}

		if (port_intr_status & INTR_UNRECOG_FIS) {
			(void) si_intr_unrecognised_fis(si_ctlp, si_portp,
			    port);
		}

		if (port_intr_status & INTR_DEV_XCHANGED) {
			(void) si_intr_dev_xchanged(si_ctlp, si_portp, port);
		}

		if (port_intr_status & INTR_8B10B_DECODE_ERROR) {
			(void) si_intr_decode_err_threshold(si_ctlp, si_portp,
			    port);
		}

		if (port_intr_status & INTR_CRC_ERROR) {
			(void) si_intr_crc_err_threshold(si_ctlp, si_portp,
			    port);
		}

		if (port_intr_status & INTR_HANDSHAKE_ERROR) {
			(void) si_intr_handshake_err_threshold(si_ctlp,
			    si_portp, port);
		}

		if (port_intr_status & INTR_SETDEVBITS_NOTIFY) {
			(void) si_intr_set_devbits_notify(si_ctlp, si_portp,
			    port);
		}
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * Interrupt which indicates that one or more commands have successfully
 * completed.
 *
 * Since we disabled W1C (write-one-to-clear) previously, mere reading
 * of slot_status register clears the interrupt. There is no need to
 * explicitly clear the interrupt.
 */
static int
si_intr_command_complete(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{

	uint32_t slot_status;
	uint32_t finished_tags;
	int finished_slot;
	sata_pkt_t *satapkt;

	SIDBG_P(SIDBG_INTR, si_portp,
	    "si_intr_command_complete enter", NULL);

	mutex_enter(&si_portp->siport_mutex);

	slot_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SLOT_STATUS(si_ctlp, port)));

	if (!si_portp->siport_pending_tags) {
		/*
		 * Spurious interrupt. Nothing to be done.
		 * The interrupt was cleared when slot_status was read.
		 */
		mutex_exit(&si_portp->siport_mutex);
		return (SI_SUCCESS);
	}

	SIDBG_P(SIDBG_VERBOSE, si_portp, "si3124: si_intr_command_complete: "
	    "pending_tags: %x, slot_status: %x",
	    si_portp->siport_pending_tags,
	    slot_status);

	finished_tags =  si_portp->siport_pending_tags &
	    ~slot_status & SI_SLOT_MASK;
	while (finished_tags) {

		finished_slot = ddi_ffs(finished_tags) - 1;
		if (finished_slot == -1) {
			break;
		}

		satapkt = si_portp->siport_slot_pkts[finished_slot];

		if (satapkt->satapkt_cmd.satacmd_flags.sata_special_regs) {
			si_copy_out_regs(&satapkt->satapkt_cmd, si_ctlp, port,
			    finished_slot);
		}

		CLEAR_BIT(si_portp->siport_pending_tags, finished_slot);
		CLEAR_BIT(finished_tags, finished_slot);
		SENDUP_PACKET(si_portp, satapkt, SATA_PKT_COMPLETED);
	}

	SIDBG_P(SIDBG_PKTCOMP, si_portp,
	    "command_complete done: pend_tags: 0x%x, slot_status: 0x%x",
	    si_portp->siport_pending_tags,
	    slot_status);

	/*
	 * tidbit: no need to clear the interrupt since reading of
	 * slot_status automatically clears the interrupt in the case
	 * of a successful command completion.
	 */

	mutex_exit(&si_portp->siport_mutex);

	return (SI_SUCCESS);
}

/*
 * Schedule a call to si_intr_command_error using a timeout to get it done
 * off the interrupt thread.
 */
static void
si_schedule_intr_command_error(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	si_event_arg_t *args;

	mutex_enter(&si_portp->siport_mutex);

	args = si_portp->siport_event_args;
	if (args->siea_ctlp != NULL) {
		cmn_err(CE_WARN, "si_schedule_intr_command_error: "
		    "args->si_ctlp != NULL");
		mutex_exit(&si_portp->siport_mutex);
		return;
	}

	args->siea_ctlp = si_ctlp;
	args->siea_port = port;

	(void) timeout(si_do_intr_command_error, si_portp, 1);

	mutex_exit(&si_portp->siport_mutex);
}

/*
 * Called from timeout()
 * Unpack the arguments and call si_intr_command_error()
 */
static void
si_do_intr_command_error(void *arg)
{
	si_event_arg_t *args;
	si_ctl_state_t *si_ctlp;
	si_port_state_t *si_portp;
	int port;

	si_portp = arg;
	mutex_enter(&si_portp->siport_mutex);

	args = si_portp->siport_event_args;
	si_ctlp = args->siea_ctlp;
	port = args->siea_port;
	args->siea_ctlp = NULL;	/* mark siport_event_args as free */

	mutex_exit(&si_portp->siport_mutex);
	(void) si_intr_command_error(si_ctlp, si_portp, port);
}

/*
 * Interrupt which indicates that a command did not complete successfully.
 *
 * The port halts whenever a command error interrupt is received.
 * The only way to restart it is to reset or reinitialize the port
 * but such an operation throws away all the pending commands on
 * the port.
 *
 * We reset the device and mop the commands on the port.
 */
static int
si_intr_command_error(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	uint32_t command_error, slot_status;
	uint32_t failed_tags;

	command_error = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_COMMAND_ERROR(si_ctlp, port)));

	SIDBG_P(SIDBG_ERRS, si_portp,
	    "si_intr_command_error: command_error: 0x%x",
	    command_error);

	mutex_enter(&si_portp->siport_mutex);

	/*
	 * Remember the slot_status since any of the recovery handler
	 * can blow it away with reset operation.
	 */
	slot_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SLOT_STATUS(si_ctlp, port)));

	si_log_error_message(si_ctlp, port, command_error);

	switch (command_error) {

	case CMD_ERR_DEVICEERRROR:
		si_error_recovery_DEVICEERROR(si_ctlp, si_portp, port);
		break;

	case CMD_ERR_SDBERROR:
		si_fm_ereport(si_ctlp, DDI_FM_DEVICE_INTERN_CORR, "SBD error");
		si_error_recovery_SDBERROR(si_ctlp, si_portp, port);
		ddi_fm_service_impact(si_ctlp->sictl_devinfop,
		    DDI_SERVICE_UNAFFECTED);
		break;

	case CMD_ERR_DATAFISERROR:
		si_fm_ereport(si_ctlp, DDI_FM_DEVICE_INTERN_CORR,
		    "Data FIS error");
		si_error_recovery_DATAFISERROR(si_ctlp, si_portp, port);
		ddi_fm_service_impact(si_ctlp->sictl_devinfop,
		    DDI_SERVICE_UNAFFECTED);
		break;

	case CMD_ERR_SENDFISERROR:
		si_fm_ereport(si_ctlp, DDI_FM_DEVICE_INTERN_CORR,
		    "Send FIS error");
		si_error_recovery_SENDFISERROR(si_ctlp, si_portp, port);
		ddi_fm_service_impact(si_ctlp->sictl_devinfop,
		    DDI_SERVICE_UNAFFECTED);
		break;

	default:
		si_fm_ereport(si_ctlp, DDI_FM_DEVICE_INTERN_CORR,
		    "Unknown error");
		si_error_recovery_default(si_ctlp, si_portp, port);
		ddi_fm_service_impact(si_ctlp->sictl_devinfop,
		    DDI_SERVICE_UNAFFECTED);
		break;

	}

	/*
	 * Compute the failed_tags by adding up the error tags.
	 *
	 * The siport_err_tags_SDBERROR and siport_err_tags_nonSDBERROR
	 * were filled in by the si_error_recovery_* routines.
	 */
	failed_tags = si_portp->siport_pending_tags &
	    (si_portp->siport_err_tags_SDBERROR |
	    si_portp->siport_err_tags_nonSDBERROR);

	SIDBG_P(SIDBG_ERRS, si_portp, "si_intr_command_error: "
	    "err_tags_SDBERROR: 0x%x, "
	    "err_tags_nonSDBERRROR: 0x%x, "
	    "failed_tags: 0x%x",
	    si_portp->siport_err_tags_SDBERROR,
	    si_portp->siport_err_tags_nonSDBERROR,
	    failed_tags);

	SIDBG_P(SIDBG_ERRS, si_portp,
	    "si3124: si_intr_command_error: "
	    "slot_status:0x%x, pending_tags: 0x%x",
	    slot_status,
	    si_portp->siport_pending_tags);

	si_portp->mopping_in_progress++;

	si_mop_commands(si_ctlp,
	    si_portp,
	    port,
	    slot_status,
	    failed_tags,
	    0, 	/* timedout_tags */
	    0, 	/* aborting_tags */
	    0); 	/* reset_tags */

	ASSERT(si_portp->siport_pending_tags == 0);

	si_portp->siport_err_tags_SDBERROR = 0;
	si_portp->siport_err_tags_nonSDBERROR = 0;

	mutex_exit(&si_portp->siport_mutex);

	return (SI_SUCCESS);
}

/*
 * There is a subtle difference between errors on a normal port and
 * a port-mult port. When an error happens on a normal port, the port
 * is halted effectively until the port is reset or initialized.
 * However, in port-mult port errors, port does not get halted since
 * other non-error devices behind the port multiplier can still
 * continue to operate. So we wait till all the commands are drained
 * instead of resetting it right away.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static void
si_recover_portmult_errors(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	uint32_t command_error, slot_status, port_status;
	int failed_slot;
	int loop_count = 0;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	SIDBG_P(SIDBG_ERRS, si_portp,
	    "si_recover_portmult_errors: port: 0x%x",
	    port);

	/* Resume the port */
	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_CONTROL_SET(si_ctlp, port),
	    PORT_CONTROL_SET_BITS_RESUME);

	port_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_STATUS(si_ctlp, port));

	failed_slot = (port_status >> 16) & SI_NUM_SLOTS;
	command_error = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_COMMAND_ERROR(si_ctlp, port)));

	if (command_error ==  CMD_ERR_SDBERROR) {
		si_portp->siport_err_tags_SDBERROR |= (0x1 << failed_slot);
	} else {
		si_portp->siport_err_tags_nonSDBERROR |= (0x1 << failed_slot);
	}

	/* Now we drain the pending commands. */
	do {
		slot_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)(PORT_SLOT_STATUS(si_ctlp, port)));

		/*
		 * Since we have not yet returned DDI_INTR_CLAIMED,
		 * our interrupt handler is guaranteed not to be called again.
		 * So we need to check IS_ATTENTION_RAISED() for further
		 * decisions.
		 *
		 * This is a too big a delay for an interrupt context.
		 * But this is supposed to be a rare condition.
		 */

		if (IS_ATTENTION_RAISED(slot_status)) {
			/* Resume again */
			ddi_put32(si_ctlp->sictl_port_acc_handle,
			    (uint32_t *)PORT_CONTROL_SET(si_ctlp, port),
			    PORT_CONTROL_SET_BITS_RESUME);

			port_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
			    (uint32_t *)PORT_STATUS(si_ctlp, port));
			failed_slot = (port_status >> 16) & SI_NUM_SLOTS;
			command_error = ddi_get32(
			    si_ctlp->sictl_port_acc_handle,
			    (uint32_t *)(PORT_COMMAND_ERROR(si_ctlp,
			    port)));
			if (command_error ==  CMD_ERR_SDBERROR) {
				si_portp->siport_err_tags_SDBERROR |=
				    (0x1 << failed_slot);
			} else {
				si_portp->siport_err_tags_nonSDBERROR |=
				    (0x1 << failed_slot);
			}
		}

		if (loop_count++ > SI_POLLRATE_RECOVERPORTMULT) {
			/* We are effectively timing out after 10 sec. */
			break;
		}

		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(SI_10MS_TICKS);
#endif /* __lock_lint */

	} while (slot_status & SI_SLOT_MASK);

	/*
	 * The above loop can be improved for 3132 since we could obtain the
	 * Port Multiplier Context of the device in error. Then we could
	 * do a better job in filtering out commands for the device in error.
	 * The loop could finish much earlier with such a logic.
	 */

	/* Clear the RESUME bit. */
	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_CONTROL_CLEAR(si_ctlp, port),
	    PORT_CONTROL_CLEAR_BITS_RESUME);

}

/*
 * If we are connected to port multiplier, drain the non-failed devices.
 * Otherwise, we initialize the port (which effectively fails all the
 * pending commands in the hope that sd would retry them later).
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static void
si_error_recovery_DEVICEERROR(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	uint32_t port_status;
	int failed_slot;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	SIDBG_P(SIDBG_ERRS, si_portp,
	    "si_error_recovery_DEVICEERROR: port: 0x%x",
	    port);

	if (si_portp->siport_port_type == PORT_TYPE_MULTIPLIER) {
		si_recover_portmult_errors(si_ctlp, si_portp, port);
	} else {
		port_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_STATUS(si_ctlp, port));
		failed_slot = (port_status >> 16) & SI_NUM_SLOTS;
		si_portp->siport_err_tags_nonSDBERROR |= (0x1 << failed_slot);
	}

	/* In either case (port-mult or not), we reinitialize the port. */
	(void) si_initialize_port_wait_till_ready(si_ctlp, port);
}

/*
 * Handle exactly like DEVICEERROR. Remember the tags with SDBERROR
 * to perform read_log_ext on them later. SDBERROR means that the
 * error was for an NCQ command.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static void
si_error_recovery_SDBERROR(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	uint32_t port_status;
	int failed_slot;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	SIDBG_P(SIDBG_ERRS, si_portp,
	    "si3124: si_error_recovery_SDBERROR: port: 0x%x",
	    port);

	if (si_portp->siport_port_type == PORT_TYPE_MULTIPLIER) {
		si_recover_portmult_errors(si_ctlp, si_portp, port);
	} else {
		port_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_STATUS(si_ctlp, port));
		failed_slot = (port_status >> 16) & SI_NUM_SLOTS;
		si_portp->siport_err_tags_SDBERROR |= (0x1 << failed_slot);
	}

	/* In either case (port-mult or not), we reinitialize the port. */
	(void) si_initialize_port_wait_till_ready(si_ctlp, port);
}

/*
 * Handle exactly like DEVICEERROR except resetting the port if there was
 * an NCQ command on the port.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static void
si_error_recovery_DATAFISERROR(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	uint32_t port_status;
	int failed_slot;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	SIDBG_P(SIDBG_ERRS, si_portp,
	    "si3124: si_error_recovery_DATAFISERROR: port: 0x%x",
	    port);

	/* reset device if we were waiting for any ncq commands. */
	if (si_portp->siport_pending_ncq_count) {
		port_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_STATUS(si_ctlp, port));
		failed_slot = (port_status >> 16) & SI_NUM_SLOTS;
		si_portp->siport_err_tags_nonSDBERROR |= (0x1 << failed_slot);
		(void) si_reset_dport_wait_till_ready(si_ctlp, si_portp, port,
		    SI_DEVICE_RESET);
		return;
	}

	/*
	 * If we don't have any ncq commands pending, the rest of
	 * the process is similar to the one for DEVICEERROR.
	 */
	si_error_recovery_DEVICEERROR(si_ctlp, si_portp, port);
}

/*
 * We handle just like DEVICERROR except that we reset the device instead
 * of initializing the port.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static void
si_error_recovery_SENDFISERROR(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	uint32_t port_status;
	int failed_slot;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	SIDBG_P(SIDBG_ERRS, si_portp,
	    "si3124: si_error_recovery_SENDFISERROR: port: 0x%x",
	    port);

	if (si_portp->siport_port_type == PORT_TYPE_MULTIPLIER) {
		si_recover_portmult_errors(si_ctlp, si_portp, port);
	} else {
		port_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_STATUS(si_ctlp, port));
		failed_slot = (port_status >> 16) & SI_NUM_SLOTS;
		si_portp->siport_err_tags_nonSDBERROR |= (0x1 << failed_slot);
		(void) si_reset_dport_wait_till_ready(si_ctlp, si_portp, port,
		    SI_DEVICE_RESET);
	}
}

/*
 * The default behavior for all other errors is to reset the device.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static void
si_error_recovery_default(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	uint32_t port_status;
	int failed_slot;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	SIDBG_P(SIDBG_ERRS, si_portp,
	    "si3124: si_error_recovery_default: port: 0x%x",
	    port);

	port_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_STATUS(si_ctlp, port));
	failed_slot = (port_status >> 16) & SI_NUM_SLOTS;
	si_portp->siport_err_tags_nonSDBERROR |= (0x1 << failed_slot);

	(void) si_reset_dport_wait_till_ready(si_ctlp, si_portp, port,
	    SI_DEVICE_RESET);
}

/*
 * Read Log Ext with PAGE 10 to retrieve the error for an NCQ command.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static uint8_t
si_read_log_ext(si_ctl_state_t *si_ctlp, si_port_state_t *si_portp, int port)
{
	int slot;
	si_prb_t *prb;
	int i;
	uint32_t slot_status;
	int loop_count = 0;
	uint32_t *prb_word_ptr;
	uint8_t error;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	SIDBG_P(SIDBG_ERRS, si_portp,
	    "si_read_log_ext: port: %x", port);

	slot = si_claim_free_slot(si_ctlp, si_portp, port);
	if (slot == SI_FAILURE) {
		return (0);
	}

	prb =  &(si_portp->siport_prbpool[slot]);
	bzero((void *)prb, sizeof (si_prb_t));

	/* Now fill the prb */
	SET_FIS_TYPE(prb->prb_fis, REGISTER_FIS_H2D);
	SET_FIS_PMP(prb->prb_fis, PORTMULT_CONTROL_PORT);
	SET_FIS_CDMDEVCTL(prb->prb_fis, 1);
	SET_FIS_COMMAND(prb->prb_fis, SATAC_READ_LOG_EXT);
	SET_FIS_SECTOR(prb->prb_fis, SATA_LOG_PAGE_10);

	/* no real data transfer is involved */
	SET_SGE_TRM(prb->prb_sge0);

#if SI_DEBUG
	if (si_debug_flags & SIDBG_DUMP_PRB) {
		int *ptr;
		int j;

		ptr = (int *)(void *)prb;
		cmn_err(CE_WARN, "read_port_mult_reg, prb: ");
		for (j = 0; j < (sizeof (si_prb_t)/4); j++) {
			cmn_err(CE_WARN, "%x ", ptr[j]);
		}

	}
#endif /* SI_DEBUG */

	/* Deliver PRB */
	POST_PRB_ADDR(si_ctlp, si_portp, port, slot);

	/* Loop till the command is finished. */
	do {
		slot_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)(PORT_SLOT_STATUS(si_ctlp, port)));

		SIDBG_P(SIDBG_POLL_LOOP, si_portp,
		    "looping read_log_ext slot_status: 0x%x",
		    slot_status);

		if (loop_count++ > SI_POLLRATE_SLOTSTATUS) {
			/* We are effectively timing out after 0.5 sec. */
			break;
		}

		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(SI_10MS_TICKS);
#endif /* __lock_lint */

	} while (slot_status & SI_SLOT_MASK & (0x1 << slot));

	if (slot_status & SI_SLOT_MASK & (0x1 << slot)) {
		/*
		 * If we fail with the READ LOG EXT command, we need to
		 * initialize the port to clear the slot_status register.
		 * We don't need to worry about any other valid commands
		 * being thrown away because we are already in recovery
		 * mode and READ LOG EXT is the only pending command.
		 */
		(void) si_initialize_port_wait_till_ready(si_ctlp, port);
	}

	SIDBG_P(SIDBG_POLL_LOOP, si_portp,
	    "read_portmult_reg: loop count: %d",
	    loop_count);

	/*
	 * The LRAM contains the the modified FIS.
	 * Read the modified FIS to obtain the Error.
	 */
	prb_word_ptr = (uint32_t *)(void *)prb;
	for (i = 0; i < (sizeof (si_prb_t)/4); i++) {
		prb_word_ptr[i] = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)(PORT_LRAM(si_ctlp, port, slot)+i*4));
	}

	if (si_check_ctl_handles(si_ctlp) != DDI_SUCCESS ||
	    si_check_port_handles(si_portp) != DDI_SUCCESS) {
		ddi_fm_service_impact(si_ctlp->sictl_devinfop,
		    DDI_SERVICE_UNAFFECTED);
	}

	error = GET_FIS_FEATURES(prb->prb_fis);

	CLEAR_BIT(si_portp->siport_pending_tags, slot);

	return (error);

}

/*
 * Dump the error message to the log.
 */
static void
si_log_error_message(si_ctl_state_t *si_ctlp, int port, uint32_t command_error)
{
#if SI_DEBUG
#ifndef __lock_lint
	_NOTE(ARGUNUSED(si_ctlp))
        _NOTE(ARGUNUSED(port))
#endif  /* __lock_lint */

	char *errstr;
	si_port_state_t *si_portp = si_ctlp->sictl_ports[port];

	switch (command_error) {

	case CMD_ERR_DEVICEERRROR:
		errstr = "Standard Error: Error bit set in register - device"
		    " to host FIS";
		break;

	case CMD_ERR_SDBERROR:
		errstr = "NCQ Error: Error bit set in register - device"
		    " to host FIS";
		break;

	case CMD_ERR_DATAFISERROR:
		errstr = "Error in data FIS not detected by device";
		break;

	case CMD_ERR_SENDFISERROR:
		errstr = "Initial command FIS transmission failed";
		break;

	case CMD_ERR_INCONSISTENTSTATE:
		errstr = "Inconsistency in protocol";
		break;

	case CMD_ERR_DIRECTIONERROR:
		errstr = "DMA direction flag does not match the command";
		break;

	case CMD_ERR_UNDERRUNERROR:
		errstr = "Run out of scatter gather entries while writing data";
		break;

	case CMD_ERR_OVERRUNERROR:
		errstr = "Run out of scatter gather entries while reading data";
		break;

	case CMD_ERR_PACKETPROTOCOLERROR:
		errstr = "Packet protocol error";
		break;

	case CMD_ERR_PLDSGTERRORBOUNDARY:
		errstr = "Scatter/gather table not on quadword boundary";
		break;

	case CMD_ERR_PLDSGTERRORTARETABORT:
		errstr = "PCI(X) Target abort while fetching scatter/gather"
		    " table";
		break;

	case CMD_ERR_PLDSGTERRORMASTERABORT:
		errstr = "PCI(X) Master abort while fetching scatter/gather"
		    " table";
		break;

	case CMD_ERR_PLDSGTERRORPCIERR:
		errstr = "PCI(X) parity error while fetching scatter/gather"
		    " table";
		break;

	case CMD_ERR_PLDCMDERRORBOUNDARY:
		errstr = "PRB not on quadword boundary";
		break;

	case CMD_ERR_PLDCMDERRORTARGETABORT:
		errstr = "PCI(X) Target abort while fetching PRB";
		break;

	case CMD_ERR_PLDCMDERRORMASTERABORT:
		errstr = "PCI(X) Master abort while fetching PRB";
		break;

	case CMD_ERR_PLDCMDERORPCIERR:
		errstr = "PCI(X) parity error while fetching PRB";
		break;

	case CMD_ERR_PSDERRORTARGETABORT:
		errstr = "PCI(X) Target abort during data transfer";
		break;

	case CMD_ERR_PSDERRORMASTERABORT:
		errstr = "PCI(X) Master abort during data transfer";
		break;

	case CMD_ERR_PSDERRORPCIERR:
		errstr = "PCI(X) parity error during data transfer";
		break;

	case CMD_ERR_SENDSERVICEERROR:
		errstr = "FIS received while sending service FIS in"
		    " legacy queuing operation";
		break;

	default:
		errstr = "Unknown Error";
		break;

	}

	SIDBG_P(SIDBG_ERRS, si_portp,
	    "command error: error: %s",
	    errstr);
#else
#ifndef __lock_lint
        _NOTE(ARGUNUSED(si_ctlp))
        _NOTE(ARGUNUSED(port))
        _NOTE(ARGUNUSED(command_error))
#endif  /* __lock_lint */

#endif	/* SI_DEBUG */
}


/*
 * Interrupt which indicates that the Port Ready state has changed
 * from zero to one.
 *
 * We are not interested in this interrupt; we just log a debug message.
 */
/*ARGSUSED*/
static int
si_intr_port_ready(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	SIDBG_P(SIDBG_INTR, si_portp, "si_intr_ready", NULL);
	return (SI_SUCCESS);
}

/*
 * Interrupt which indicates that the port power management state
 * has been modified.
 *
 * We are not interested in this interrupt; we just log a debug message.
 */
/*ARGSUSED*/
static int
si_intr_pwr_change(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	SIDBG_P(SIDBG_INTR, si_portp, "si_intr_pwr_change", NULL);
	return (SI_SUCCESS);
}

/*
 * Interrupt which indicates that the PHY state has changed either from
 * Not-Ready to Ready or from Ready to Not-Ready.
 */
static int
si_intr_phy_ready_change(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	sata_device_t sdevice;
	uint32_t SStatus = 0; /* No dev present & PHY not established. */
	int dev_exists_now = 0;
	int dev_existed_previously = 0;

	SIDBG_P(SIDBG_INTR, si_portp,
	    "si_intr_phy_rdy_change", NULL);

	mutex_enter(&si_ctlp->sictl_mutex);
	if ((si_ctlp->sictl_sata_hba_tran == NULL) || (si_portp == NULL)) {
		/* the whole controller setup is not yet done. */
		mutex_exit(&si_ctlp->sictl_mutex);
		return (SI_SUCCESS);
	}

	mutex_exit(&si_ctlp->sictl_mutex);

	mutex_enter(&si_portp->siport_mutex);

	/* SStatus tells the presence of device. */
	SStatus = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_SSTATUS(si_ctlp, port));
	dev_exists_now =
	    (SSTATUS_GET_DET(SStatus) == SSTATUS_DET_DEVPRESENT_PHYONLINE);

	if (si_portp->siport_port_type != PORT_TYPE_NODEV) {
		dev_existed_previously = 1;
	}

	bzero((void *)&sdevice, sizeof (sata_device_t));

	sdevice.satadev_addr.cport = (uint8_t)port;
	sdevice.satadev_addr.pmport = PORTMULT_CONTROL_PORT;

	/* we don't have a way of determining the exact port-mult port. */
	if (si_portp->siport_port_type == PORT_TYPE_MULTIPLIER) {
		sdevice.satadev_addr.qual = SATA_ADDR_PMPORT;
	} else {
		sdevice.satadev_addr.qual = SATA_ADDR_CPORT;
	}

	sdevice.satadev_state = SATA_STATE_READY; /* port state */

	if (dev_exists_now) {
		if (dev_existed_previously) {

			/* Things are fine now. The loss was temporary. */
			SIDBG_P(SIDBG_INTR, si_portp,
			    "phyrdy: doing BOTH EVENTS TOGETHER", NULL);
			if (si_portp->siport_active) {
				SIDBG_P(SIDBG_EVENT, si_portp,
				    "sending event: LINK_LOST & "
				    "LINK_ESTABLISHED", NULL);

				sata_hba_event_notify(
				    si_ctlp->sictl_sata_hba_tran->\
				    sata_tran_hba_dip,
				    &sdevice,
				    SATA_EVNT_LINK_LOST|
				    SATA_EVNT_LINK_ESTABLISHED);
			}

		} else {

			/* A new device has been detected. */
			mutex_exit(&si_portp->siport_mutex);
			si_find_dev_signature(si_ctlp, si_portp, port,
			    PORTMULT_CONTROL_PORT);
			mutex_enter(&si_portp->siport_mutex);
			SIDBG_P(SIDBG_INTR, si_portp,
			    "phyrdy: doing ATTACH event", NULL);
			if (si_portp->siport_active) {
				SIDBG_P(SIDBG_EVENT, si_portp,
				    "sending event up: LINK_ESTABLISHED", NULL);

				sata_hba_event_notify(
				    si_ctlp->sictl_sata_hba_tran->\
				    sata_tran_hba_dip,
				    &sdevice,
				    SATA_EVNT_LINK_ESTABLISHED);
			}

		}
	} else { /* No device exists now */

		if (dev_existed_previously) {

			/* An existing device is lost. */
			if (si_portp->siport_active) {
				SIDBG_P(SIDBG_EVENT, si_portp,
				    "sending event up: LINK_LOST", NULL);

				sata_hba_event_notify(
				    si_ctlp->sictl_sata_hba_tran->
				    sata_tran_hba_dip,
				    &sdevice,
				    SATA_EVNT_LINK_LOST);
			}
			si_portp->siport_port_type = PORT_TYPE_NODEV;

		} else {

			/* spurious interrupt */
			SIDBG_P(SIDBG_INTR, si_portp,
			    "spurious phy ready interrupt", NULL);
		}
	}

	mutex_exit(&si_portp->siport_mutex);
	return (SI_SUCCESS);
}


/*
 * Interrupt which indicates that a COMWAKE OOB signal has been decoded
 * on the receiver.
 *
 * We are not interested in this interrupt; we just log a debug message.
 */
/*ARGSUSED*/
static int
si_intr_comwake_rcvd(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	SIDBG_P(SIDBG_INTR, si_portp,
	    "si_intr_commwake_rcvd", NULL);
	return (SI_SUCCESS);
}

/*
 * Interrupt which indicates that the F-bit has been set in SError
 * Diag field.
 *
 * We are not interested in this interrupt; we just log a debug message.
 */
/*ARGSUSED*/
static int
si_intr_unrecognised_fis(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	SIDBG_P(SIDBG_INTR, si_portp,
	    "si_intr_unrecognised_fis", NULL);
	return (SI_SUCCESS);
}

/*
 * Interrupt which indicates that the X-bit has been set in SError
 * Diag field.
 *
 * We are not interested in this interrupt; we just log a debug message.
 */
/*ARGSUSED*/
static int
si_intr_dev_xchanged(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{

	SIDBG_P(SIDBG_INTR, si_portp,
	    "si_intr_dev_xchanged", NULL);
	return (SI_SUCCESS);
}

/*
 * Interrupt which indicates that the 8b/10b Decode Error counter has
 * exceeded the programmed non-zero threshold value.
 *
 * We are not interested in this interrupt; we just log a debug message.
 */
/*ARGSUSED*/
static int
si_intr_decode_err_threshold(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	SIDBG_P(SIDBG_INTR, si_portp,
	    "si_intr_err_threshold", NULL);
	return (SI_SUCCESS);
}

/*
 * Interrupt which indicates that the CRC Error counter has exceeded the
 * programmed non-zero threshold value.
 *
 * We are not interested in this interrupt; we just log a debug message.
 */
/*ARGSUSED*/
static int
si_intr_crc_err_threshold(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	SIDBG_P(SIDBG_INTR, si_portp,
	    "si_intr_crc_threshold", NULL);
	return (SI_SUCCESS);
}

/*
 * Interrupt which indicates that the Handshake Error counter has
 * exceeded the programmed non-zero threshold value.
 *
 * We are not interested in this interrupt; we just log a debug message.
 */
/*ARGSUSED*/
static int
si_intr_handshake_err_threshold(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	SIDBG_P(SIDBG_INTR, si_portp,
	    "si_intr_handshake_err_threshold", NULL);
	return (SI_SUCCESS);
}

/*
 * Interrupt which indicates that a "Set Device Bits" FIS has been
 * received with N-bit set in the control field.
 *
 * We are not interested in this interrupt; we just log a debug message.
 */
/*ARGSUSED*/
static int
si_intr_set_devbits_notify(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	SIDBG_P(SIDBG_INTR, si_portp,
	    "si_intr_set_devbits_notify", NULL);
	return (SI_SUCCESS);
}


/*
 * Enable the interrupts for a particular port.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static void
si_enable_port_interrupts(si_ctl_state_t *si_ctlp, int port)
{
	uint32_t mask;
	si_port_state_t *si_portp = si_ctlp->sictl_ports[port];

	/* get the current settings first. */
	mask = ddi_get32(si_ctlp->sictl_global_acc_handle,
	    (uint32_t *)GLOBAL_CONTROL_REG(si_ctlp));

	SIDBG_P(SIDBG_INIT, si_portp,
	    "si_enable_port_interrupts: current mask: 0x%x",
	    mask);

	/* enable the bit for current port. */
	SET_BIT(mask, port);

	/* now use this mask to enable the interrupt. */
	ddi_put32(si_ctlp->sictl_global_acc_handle,
	    (uint32_t *)GLOBAL_CONTROL_REG(si_ctlp),
	    mask);
}

/*
 * Enable interrupts for all the ports.
 */
static void
si_enable_all_interrupts(si_ctl_state_t *si_ctlp)
{
	int port;

	for (port = 0; port < si_ctlp->sictl_num_ports; port++) {
		si_enable_port_interrupts(si_ctlp, port);
	}
}

/*
 * Disable interrupts for a particular port.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static void
si_disable_port_interrupts(si_ctl_state_t *si_ctlp, int port)
{
	uint32_t mask;

	/* get the current settings first. */
	mask = ddi_get32(si_ctlp->sictl_global_acc_handle,
	    (uint32_t *)GLOBAL_CONTROL_REG(si_ctlp));

	/* clear the bit for current port. */
	CLEAR_BIT(mask, port);

	/* now use this mask to disable the interrupt. */
	ddi_put32(si_ctlp->sictl_global_acc_handle,
	    (uint32_t *)GLOBAL_CONTROL_REG(si_ctlp),
	    mask);

}

/*
 * Disable interrupts for all the ports.
 */
static void
si_disable_all_interrupts(si_ctl_state_t *si_ctlp)
{
	int port;

	for (port = 0; port < si_ctlp->sictl_num_ports; port++) {
		si_disable_port_interrupts(si_ctlp, port);
	}
}

/*
 * Fetches the latest sstatus, scontrol, serror, sactive registers
 * and stuffs them into sata_device_t structure.
 */
static void
fill_dev_sregisters(si_ctl_state_t *si_ctlp, int port, sata_device_t *satadev)
{
	satadev->satadev_scr.sstatus = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SSTATUS(si_ctlp, port)));
	satadev->satadev_scr.serror = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SERROR(si_ctlp, port)));
	satadev->satadev_scr.sactive = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SACTIVE(si_ctlp, port)));
	satadev->satadev_scr.scontrol =
	    ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SCONTROL(si_ctlp, port)));

}

/*
 * si_add_legacy_intrs() handles INTx and legacy interrupts.
 */
static int
si_add_legacy_intrs(si_ctl_state_t *si_ctlp)
{
	dev_info_t	*devinfo = si_ctlp->sictl_devinfop;
	int		actual, count = 0;
	int		x, y, rc, inum = 0;

	SIDBG_C(SIDBG_INIT, si_ctlp, "si_add_legacy_intrs", NULL);

	/* get number of interrupts. */
	rc = ddi_intr_get_nintrs(devinfo, DDI_INTR_TYPE_FIXED, &count);
	if ((rc != DDI_SUCCESS) || (count == 0)) {
		SIDBG_C(SIDBG_ERRS, si_ctlp,
		    "ddi_intr_get_nintrs() failed, "
		    "rc %d count %d\n", rc, count);
		return (DDI_FAILURE);
	}

	/* Allocate an array of interrupt handles. */
	si_ctlp->sictl_intr_size = count * sizeof (ddi_intr_handle_t);
	si_ctlp->sictl_htable = kmem_zalloc(si_ctlp->sictl_intr_size, KM_SLEEP);

	/* call ddi_intr_alloc(). */
	rc = ddi_intr_alloc(devinfo, si_ctlp->sictl_htable, DDI_INTR_TYPE_FIXED,
	    inum, count, &actual, DDI_INTR_ALLOC_STRICT);

	if ((rc != DDI_SUCCESS) || (actual == 0)) {
		SIDBG_C(SIDBG_ERRS, si_ctlp,
		    "ddi_intr_alloc() failed, rc %d\n", rc);
		kmem_free(si_ctlp->sictl_htable, si_ctlp->sictl_intr_size);
		return (DDI_FAILURE);
	}

	if (actual < count) {
		SIDBG_C(SIDBG_ERRS, si_ctlp,
		    "Requested: %d, Received: %d", count, actual);

		for (x = 0; x < actual; x++) {
			(void) ddi_intr_free(si_ctlp->sictl_htable[x]);
		}

		kmem_free(si_ctlp->sictl_htable, si_ctlp->sictl_intr_size);
		return (DDI_FAILURE);
	}

	si_ctlp->sictl_intr_cnt = actual;

	/* Get intr priority. */
	if (ddi_intr_get_pri(si_ctlp->sictl_htable[0],
	    &si_ctlp->sictl_intr_pri) != DDI_SUCCESS) {
		SIDBG_C(SIDBG_ERRS, si_ctlp,
		    "ddi_intr_get_pri() failed", NULL);

		for (x = 0; x < actual; x++) {
			(void) ddi_intr_free(si_ctlp->sictl_htable[x]);
		}

		kmem_free(si_ctlp->sictl_htable, si_ctlp->sictl_intr_size);
		return (DDI_FAILURE);
	}

	/* Test for high level mutex. */
	if (si_ctlp->sictl_intr_pri >= ddi_intr_get_hilevel_pri()) {
		SIDBG_C(SIDBG_ERRS, si_ctlp,
		    "si_add_legacy_intrs: Hi level intr not supported", NULL);

		for (x = 0; x < actual; x++) {
			(void) ddi_intr_free(si_ctlp->sictl_htable[x]);
		}

		kmem_free(si_ctlp->sictl_htable, sizeof (ddi_intr_handle_t));

		return (DDI_FAILURE);
	}

	/* Call ddi_intr_add_handler(). */
	for (x = 0; x < actual; x++) {
		if (ddi_intr_add_handler(si_ctlp->sictl_htable[x], si_intr,
		    (caddr_t)si_ctlp, NULL) != DDI_SUCCESS) {
			SIDBG_C(SIDBG_ERRS, si_ctlp,
			    "ddi_intr_add_handler() failed", NULL);

			for (y = 0; y < actual; y++) {
				(void) ddi_intr_free(si_ctlp->sictl_htable[y]);
			}

			kmem_free(si_ctlp->sictl_htable,
			    si_ctlp->sictl_intr_size);
			return (DDI_FAILURE);
		}
	}

	/* Call ddi_intr_enable() for legacy interrupts. */
	for (x = 0; x < si_ctlp->sictl_intr_cnt; x++) {
		(void) ddi_intr_enable(si_ctlp->sictl_htable[x]);
	}

	return (DDI_SUCCESS);
}

/*
 * si_add_msictl_intrs() handles MSI interrupts.
 */
static int
si_add_msi_intrs(si_ctl_state_t *si_ctlp)
{
	dev_info_t	*devinfo = si_ctlp->sictl_devinfop;
	int		count, avail, actual;
	int		x, y, rc, inum = 0;

	SIDBG_C(SIDBG_INIT, si_ctlp, "si_add_msi_intrs", NULL);

	/* get number of interrupts. */
	rc = ddi_intr_get_nintrs(devinfo, DDI_INTR_TYPE_MSI, &count);
	if ((rc != DDI_SUCCESS) || (count == 0)) {
		SIDBG_C(SIDBG_ERRS, si_ctlp,
		    "ddi_intr_get_nintrs() failed, "
		    "rc %d count %d\n", rc, count);
		return (DDI_FAILURE);
	}

	/* get number of available interrupts. */
	rc = ddi_intr_get_navail(devinfo, DDI_INTR_TYPE_MSI, &avail);
	if ((rc != DDI_SUCCESS) || (avail == 0)) {
		SIDBG_C(SIDBG_ERRS, si_ctlp,
		    "ddi_intr_get_navail() failed, "
		    "rc %d avail %d\n", rc, avail);
		return (DDI_FAILURE);
	}

	if (avail < count) {
		SIDBG_C(SIDBG_INIT, si_ctlp,
		    "ddi_intr_get_nvail returned %d, navail() returned %d",
		    count, avail);
	}

	/* Allocate an array of interrupt handles. */
	si_ctlp->sictl_intr_size = count * sizeof (ddi_intr_handle_t);
	si_ctlp->sictl_htable = kmem_alloc(si_ctlp->sictl_intr_size, KM_SLEEP);

	/* call ddi_intr_alloc(). */
	rc = ddi_intr_alloc(devinfo, si_ctlp->sictl_htable, DDI_INTR_TYPE_MSI,
	    inum, count, &actual, DDI_INTR_ALLOC_NORMAL);

	if ((rc != DDI_SUCCESS) || (actual == 0)) {
		SIDBG_C(SIDBG_ERRS, si_ctlp,
		    "ddi_intr_alloc() failed, rc %d\n", rc);
		kmem_free(si_ctlp->sictl_htable, si_ctlp->sictl_intr_size);
		return (DDI_FAILURE);
	}

	/* use interrupt count returned */
	if (actual < count) {
		SIDBG_C(SIDBG_INIT, si_ctlp,
		    "Requested: %d, Received: %d", count, actual);
	}

	si_ctlp->sictl_intr_cnt = actual;

	/*
	 * Get priority for first msi, assume remaining are all the same.
	 */
	if (ddi_intr_get_pri(si_ctlp->sictl_htable[0],
	    &si_ctlp->sictl_intr_pri) != DDI_SUCCESS) {
		SIDBG_C(SIDBG_ERRS, si_ctlp, "ddi_intr_get_pri() failed", NULL);

		/* Free already allocated intr. */
		for (y = 0; y < actual; y++) {
			(void) ddi_intr_free(si_ctlp->sictl_htable[y]);
		}

		kmem_free(si_ctlp->sictl_htable, si_ctlp->sictl_intr_size);
		return (DDI_FAILURE);
	}

	/* Test for high level mutex. */
	if (si_ctlp->sictl_intr_pri >= ddi_intr_get_hilevel_pri()) {
		SIDBG_C(SIDBG_ERRS, si_ctlp,
		    "si_add_msi_intrs: Hi level intr not supported", NULL);

		/* Free already allocated intr. */
		for (y = 0; y < actual; y++) {
			(void) ddi_intr_free(si_ctlp->sictl_htable[y]);
		}

		kmem_free(si_ctlp->sictl_htable, sizeof (ddi_intr_handle_t));

		return (DDI_FAILURE);
	}

	/* Call ddi_intr_add_handler(). */
	for (x = 0; x < actual; x++) {
		if (ddi_intr_add_handler(si_ctlp->sictl_htable[x], si_intr,
		    (caddr_t)si_ctlp, NULL) != DDI_SUCCESS) {
			SIDBG_C(SIDBG_ERRS, si_ctlp,
			    "ddi_intr_add_handler() failed", NULL);

			/* Free already allocated intr. */
			for (y = 0; y < actual; y++) {
				(void) ddi_intr_free(si_ctlp->sictl_htable[y]);
			}

			kmem_free(si_ctlp->sictl_htable,
			    si_ctlp->sictl_intr_size);
			return (DDI_FAILURE);
		}
	}

	(void) ddi_intr_get_cap(si_ctlp->sictl_htable[0],
	    &si_ctlp->sictl_intr_cap);

	if (si_ctlp->sictl_intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI. */
		(void) ddi_intr_block_enable(si_ctlp->sictl_htable,
		    si_ctlp->sictl_intr_cnt);
	} else {
		/* Call ddi_intr_enable() for MSI non block enable. */
		for (x = 0; x < si_ctlp->sictl_intr_cnt; x++) {
			(void) ddi_intr_enable(si_ctlp->sictl_htable[x]);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * Removes the registered interrupts irrespective of whether they
 * were legacy or MSI.
 */
static void
si_rem_intrs(si_ctl_state_t *si_ctlp)
{
	int x;

	SIDBG_C(SIDBG_INIT, si_ctlp, "si_rem_intrs entered", NULL);

	/* Disable all interrupts. */
	if ((si_ctlp->sictl_intr_type == DDI_INTR_TYPE_MSI) &&
	    (si_ctlp->sictl_intr_cap & DDI_INTR_FLAG_BLOCK)) {
		/* Call ddi_intr_block_disable(). */
		(void) ddi_intr_block_disable(si_ctlp->sictl_htable,
		    si_ctlp->sictl_intr_cnt);
	} else {
		for (x = 0; x < si_ctlp->sictl_intr_cnt; x++) {
			(void) ddi_intr_disable(si_ctlp->sictl_htable[x]);
		}
	}

	/* Call ddi_intr_remove_handler(). */
	for (x = 0; x < si_ctlp->sictl_intr_cnt; x++) {
		(void) ddi_intr_remove_handler(si_ctlp->sictl_htable[x]);
		(void) ddi_intr_free(si_ctlp->sictl_htable[x]);
	}

	kmem_free(si_ctlp->sictl_htable, si_ctlp->sictl_intr_size);
}

/*
 * Resets either the port or the device connected to the port based on
 * the flag variable.
 *
 * The reset effectively throws away all the pending commands. So, the caller
 * has to make provision to handle the pending commands.
 *
 * After the reset, we wait till the port is ready again.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 *
 * Note: Not port-mult aware.
 */
static int
si_reset_dport_wait_till_ready(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port,
	int flag)
{
	uint32_t port_status;
	int loop_count = 0;
	sata_device_t sdevice;
	uint32_t SStatus;
	uint32_t SControl;
	uint32_t port_intr_status;

	_NOTE(ASSUMING_PROTECTED(si_portp))

	if (flag == SI_PORT_RESET) {
		ddi_put32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_CONTROL_SET(si_ctlp, port),
		    PORT_CONTROL_SET_BITS_PORT_RESET);

		/* Port reset is not self clearing. So clear it now. */
		ddi_put32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_CONTROL_CLEAR(si_ctlp, port),
		    PORT_CONTROL_CLEAR_BITS_PORT_RESET);
	} else {
		/* Reset the device. */
		ddi_put32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_CONTROL_SET(si_ctlp, port),
		    PORT_CONTROL_SET_BITS_DEV_RESET);

		/*
		 * tidbit: this bit is self clearing; so there is no need
		 * for manual clear as we did for port reset.
		 */
	}

	/* Set the reset in progress flag */
	if (!(flag & SI_RESET_NO_EVENTS_UP)) {
		si_portp->siport_reset_in_progress = 1;
	}


	/*
	 * Every reset needs a PHY initialization.
	 *
	 * The way to initialize the PHY is to write a 1 and then
	 * a 0 to DET field of SControl register.
	 */

	/* Fetch the current SControl before writing the DET part with 1. */
	SControl = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_SCONTROL(si_ctlp, port));
	SCONTROL_SET_DET(SControl, SCONTROL_DET_COMRESET);
	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SCONTROL(si_ctlp, port)),
	    SControl);
#ifndef __lock_lint
	delay(SI_10MS_TICKS); /* give time for COMRESET to percolate */
#endif /* __lock_lint */

	/* Now fetch the SControl again and rewrite the DET part with 0 */
	SControl = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_SCONTROL(si_ctlp, port));
	SCONTROL_SET_DET(SControl, SCONTROL_DET_NOACTION);
	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SCONTROL(si_ctlp, port)),
	    SControl);

	/*
	 * PHY may be initialized by now. Check the DET field of SStatus
	 * to determine if there is a device present.
	 *
	 * The DET field is valid only if IPM field indicates that
	 * the interface is in active state.
	 */

	loop_count = 0;
	do {
		SStatus = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_SSTATUS(si_ctlp, port));

		if (SSTATUS_GET_IPM(SStatus) !=
		    SSTATUS_IPM_INTERFACE_ACTIVE) {
			/*
			 * If the interface is not active, the DET field
			 * is considered not accurate. So we want to
			 * continue looping.
			 */
			SSTATUS_SET_DET(SStatus, SSTATUS_DET_NODEV_NOPHY);
		}

		if (loop_count++ > SI_POLLRATE_SSTATUS) {
			/* We are effectively timing out after 0.1 sec. */
			break;
		}

		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(SI_10MS_TICKS);
#endif /* __lock_lint */

	} while (SSTATUS_GET_DET(SStatus) != SSTATUS_DET_DEVPRESENT_PHYONLINE);

	SIDBG_P(SIDBG_POLL_LOOP, si_portp,
	    "si_reset_dport_wait_till_ready: loop count: %d, \
		SStatus: 0x%x",
	    loop_count,
	    SStatus);

	/* Now check for port readiness. */
	loop_count = 0;
	do {
		port_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_STATUS(si_ctlp, port));

		if (loop_count++ > SI_POLLRATE_PORTREADY) {
			/* We are effectively timing out after 0.5 sec. */
			break;
		}

		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(SI_10MS_TICKS);
#endif /* __lock_lint */

	} while (!(port_status & PORT_STATUS_BITS_PORT_READY));

	SIDBG_P(SIDBG_POLL_LOOP, si_portp,
	    "si_reset_dport_wait_till_ready: loop count: %d, \
		port_status: 0x%x, SStatus: 0x%x",
	    loop_count,
	    port_status,
	    SStatus);

	/* Indicate to the framework that a reset has happened. */
	if (!(flag & SI_RESET_NO_EVENTS_UP)) {

		bzero((void *)&sdevice, sizeof (sata_device_t));

		sdevice.satadev_addr.cport = (uint8_t)port;
		sdevice.satadev_addr.pmport = PORTMULT_CONTROL_PORT;

		if (si_portp->siport_port_type == PORT_TYPE_MULTIPLIER) {
			sdevice.satadev_addr.qual = SATA_ADDR_DPMPORT;
		} else {
			sdevice.satadev_addr.qual = SATA_ADDR_DCPORT;
		}
		sdevice.satadev_state = SATA_DSTATE_RESET |
		    SATA_DSTATE_PWR_ACTIVE;
		if (si_ctlp->sictl_sata_hba_tran) {
			sata_hba_event_notify(
			    si_ctlp->sictl_sata_hba_tran->sata_tran_hba_dip,
			    &sdevice,
			    SATA_EVNT_DEVICE_RESET);
		}

		SIDBG_P(SIDBG_EVENT, si_portp,
		    "sending event up: SATA_EVNT_RESET", NULL);
	}

	if ((SSTATUS_GET_IPM(SStatus) == SSTATUS_IPM_INTERFACE_ACTIVE) &&
	    (SSTATUS_GET_DET(SStatus) ==
	    SSTATUS_DET_DEVPRESENT_PHYONLINE)) {
		/* The interface is active and the device is present */
		if (!(port_status & PORT_STATUS_BITS_PORT_READY)) {
			/* But the port is is not ready for some reason */
			SIDBG_P(SIDBG_POLL_LOOP, si_portp,
			    "si_reset_dport_wait_till_ready failed", NULL);
			return (SI_FAILURE);
		}
	}


	/*
	 * For some reason, we are losing the interrupt enablement after
	 * any reset condition. So restore them back now.
	 */

	SIDBG_P(SIDBG_INIT, si_portp,
	    "current interrupt enable set: 0x%x",
	    ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_INTERRUPT_ENABLE_SET(si_ctlp, port)));

	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_INTERRUPT_ENABLE_SET(si_ctlp, port),
	    (INTR_COMMAND_COMPLETE |
	    INTR_COMMAND_ERROR |
	    INTR_PORT_READY |
	    INTR_POWER_CHANGE |
	    INTR_PHYRDY_CHANGE |
	    INTR_COMWAKE_RECEIVED |
	    INTR_UNRECOG_FIS |
	    INTR_DEV_XCHANGED |
	    INTR_SETDEVBITS_NOTIFY));

	si_enable_port_interrupts(si_ctlp, port);

	/*
	 * make sure interrupts are cleared
	 */
	port_intr_status = ddi_get32(si_ctlp->sictl_global_acc_handle,
	    (uint32_t *)PORT_INTERRUPT_STATUS(si_ctlp, port));

	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_INTERRUPT_STATUS(si_ctlp,
	    port)),
	    port_intr_status & INTR_MASK);


	SIDBG_P(SIDBG_POLL_LOOP, si_portp,
	    "si_reset_dport_wait_till_ready returning success", NULL);

	return (SI_SUCCESS);
}

/*
 * Schedule an initialization of the port using a timeout to get it done
 * off an interrupt thread.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static void
si_schedule_port_initialize(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port)
{
	si_event_arg_t *args;

	ASSERT(mutex_owned(&si_portp->siport_mutex));

	args = si_portp->siport_event_args;
	if (args->siea_ctlp != NULL) {
		cmn_err(CE_WARN, "si_schedule_port_initialize: "
		    "args->si_ctlp != NULL");
		return;
	}

	args->siea_ctlp = si_ctlp;
	args->siea_port = port;

	(void) timeout(si_do_initialize_port, si_portp, 1);
}

/*
 * Called from timeout()
 * Unpack the arguments and call si_initialize_port_wait_till_ready()
 */
static void
si_do_initialize_port(void *arg)
{
	si_event_arg_t *args;
	si_ctl_state_t *si_ctlp;
	si_port_state_t *si_portp;
	int port;

	si_portp = arg;
	mutex_enter(&si_portp->siport_mutex);

	args = si_portp->siport_event_args;
	si_ctlp = args->siea_ctlp;
	port = args->siea_port;
	args->siea_ctlp = NULL;	/* mark siport_event_args as free */
	(void) si_initialize_port_wait_till_ready(si_ctlp, port);

	mutex_exit(&si_portp->siport_mutex);
}


/*
 * Initializes the port.
 *
 * Initialization effectively throws away all the pending commands on
 * the port. So, the caller  has to make provision to handle the pending
 * commands.
 *
 * After the port initialization, we wait till the port is ready again.
 *
 * WARNING, WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static int
si_initialize_port_wait_till_ready(si_ctl_state_t *si_ctlp, int port)
{
	uint32_t port_status;
	int loop_count = 0;
	uint32_t SStatus;
	si_port_state_t *si_portp = si_ctlp->sictl_ports[port];

	/* Initialize the port. */
	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_CONTROL_SET(si_ctlp, port),
	    PORT_CONTROL_SET_BITS_PORT_INITIALIZE);

	/* Wait until Port Ready */
	loop_count = 0;
	do {
		port_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)PORT_STATUS(si_ctlp, port));

		if (loop_count++ > SI_POLLRATE_PORTREADY) {
			SIDBG_P(SIDBG_INTR, si_portp,
			    "si_initialize_port_wait is timing out: "
			    "port_status: %x",
			    port_status);
			/* We are effectively timing out after 0.5 sec. */
			break;
		}

		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(SI_10MS_TICKS);
#endif /* __lock_lint */

	} while (!(port_status & PORT_STATUS_BITS_PORT_READY));

	SIDBG_P(SIDBG_POLL_LOOP, si_portp,
	    "si_initialize_port_wait_till_ready: loop count: %d",
	    loop_count);

	SStatus = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_SSTATUS(si_ctlp, port));

	if ((SSTATUS_GET_IPM(SStatus) == SSTATUS_IPM_INTERFACE_ACTIVE) &&
	    (SSTATUS_GET_DET(SStatus) ==
	    SSTATUS_DET_DEVPRESENT_PHYONLINE)) {
		/* The interface is active and the device is present */
		if (!(port_status & PORT_STATUS_BITS_PORT_READY)) {
			/* But the port is is not ready for some reason */
			return (SI_FAILURE);
		}
	}

	return (SI_SUCCESS);
}


/*
 * si_watchdog_handler() calls us if it detects that there are some
 * commands which timed out. We recalculate the timed out commands once
 * again since some of them may have finished recently.
 */
static void
si_timeout_pkts(
	si_ctl_state_t *si_ctlp,
	si_port_state_t *si_portp,
	int port,
	uint32_t timedout_tags)
{
	uint32_t slot_status;
	uint32_t finished_tags;

	SIDBG_P(SIDBG_TIMEOUT, si_portp,
	    "si_timeout_pkts entry", NULL);

	mutex_enter(&si_portp->siport_mutex);
	slot_status = ddi_get32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)(PORT_SLOT_STATUS(si_ctlp, port)));

	si_portp->mopping_in_progress++;

	/*
	 * Initialize the controller. The only way to timeout the commands
	 * is to reset or initialize the controller. We mop commands after
	 * the initialization.
	 */
	(void) si_initialize_port_wait_till_ready(si_ctlp, port);

	/*
	 * Recompute the timedout tags since some of them may have finished
	 * meanwhile.
	 */
	finished_tags =  si_portp->siport_pending_tags &
	    ~slot_status & SI_SLOT_MASK;
	timedout_tags &= ~finished_tags;

	SIDBG_P(SIDBG_TIMEOUT, si_portp,
	    "si_timeout_pkts: finished: %x, timeout: %x",
	    finished_tags,
	    timedout_tags);

	si_mop_commands(si_ctlp,
	    si_portp,
	    port,
	    slot_status,
	    0, /* failed_tags */
	    timedout_tags,
	    0, /* aborting_tags */
	    0);  /* reset_tags */

	mutex_exit(&si_portp->siport_mutex);
}



/*
 * Watchdog handler kicks in every 5 seconds to timeout any commands pending
 * for long time.
 */
static void
si_watchdog_handler(si_ctl_state_t *si_ctlp)
{
	uint32_t pending_tags = 0;
	uint32_t timedout_tags = 0;
	si_port_state_t *si_portp;
	int port;
	int tmpslot;
	sata_pkt_t *satapkt;

	/* max number of cycles this packet should survive */
	int max_life_cycles;

	/* how many cycles this packet survived so far */
	int watched_cycles;

	mutex_enter(&si_ctlp->sictl_mutex);
	SIDBG_C(SIDBG_ENTRY, si_ctlp,
	    "si_watchdog_handler entered", NULL);

	for (port = 0; port < si_ctlp->sictl_num_ports; port++) {

		si_portp = si_ctlp->sictl_ports[port];
		if (si_portp == NULL) {
			continue;
		}

		mutex_enter(&si_portp->siport_mutex);

		if (si_portp->siport_port_type == PORT_TYPE_NODEV) {
			mutex_exit(&si_portp->siport_mutex);
			continue;
		}

		/* Skip the check for those ports in error recovery */
		if (si_portp->mopping_in_progress > 0) {
			SIDBG_P(SIDBG_INFO, si_portp,
			    "si_watchdog_handler: port %d mopping "
			    "in progress, so just return", port);
			mutex_exit(&si_portp->siport_mutex);
			continue;
		}

		pending_tags =  si_portp->siport_pending_tags;
		timedout_tags = 0;
		while (pending_tags) {
			tmpslot = ddi_ffs(pending_tags) - 1;
			if (tmpslot == -1) {
				break;
			}
			satapkt = si_portp->siport_slot_pkts[tmpslot];

			if ((satapkt != NULL) && satapkt->satapkt_time) {

				/*
				 * We are overloading satapkt_hba_driver_private
				 * with watched_cycle count.
				 *
				 * If a packet has survived for more than it's
				 * max life cycles, it is a candidate for time
				 * out.
				 */
				watched_cycles = (int)(intptr_t)
				    satapkt->satapkt_hba_driver_private;
				watched_cycles++;
				max_life_cycles = (satapkt->satapkt_time +
				    si_watchdog_timeout - 1) /
				    si_watchdog_timeout;
				if (watched_cycles > max_life_cycles) {
					timedout_tags |= (0x1 << tmpslot);
					SIDBG_P(SIDBG_TIMEOUT,
					    si_portp,
					    "watchdog: timedout_tags: 0x%x",
					    timedout_tags);
				}
				satapkt->satapkt_hba_driver_private =
				    (void *)(intptr_t)watched_cycles;
			}

			CLEAR_BIT(pending_tags, tmpslot);
		}

		if (timedout_tags) {
			mutex_exit(&si_portp->siport_mutex);
			mutex_exit(&si_ctlp->sictl_mutex);
			si_timeout_pkts(si_ctlp, si_portp, port, timedout_tags);
			mutex_enter(&si_ctlp->sictl_mutex);
			mutex_enter(&si_portp->siport_mutex);
		}

		mutex_exit(&si_portp->siport_mutex);
	}

	/* Reinstall the watchdog timeout handler. */
	if (!(si_ctlp->sictl_flags & SI_NO_TIMEOUTS)) {
		si_ctlp->sictl_timeout_id =
		    timeout((void (*)(void *))si_watchdog_handler,
		    (caddr_t)si_ctlp, si_watchdog_tick);
	}
	mutex_exit(&si_ctlp->sictl_mutex);
}

/*
 * FMA Functions
 */

/*
 * The IO fault service error handling callback function
 */
/*ARGSUSED*/
static int
si_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	/*
	 * as the driver can always deal with an error in any dma or
	 * access handle, we can just return the fme_status value.
	 */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

/*
 * si_fm_init - initialize fma capabilities and register with IO
 *              fault services.
 */
static void
si_fm_init(si_ctl_state_t *si_ctlp)
{
	/*
	 * Need to change iblock to priority for new MSI intr
	 */
	ddi_iblock_cookie_t fm_ibc;

	/* Only register with IO Fault Services if we have some capability */
	if (si_ctlp->fm_capabilities) {
		/* Adjust access and dma attributes for FMA */
		accattr.devacc_attr_access = DDI_FLAGERR_ACC;
		prb_sgt_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		buffer_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;

		/*
		 * Register capabilities with IO Fault Services.
		 * fm_capabilities will be updated to indicate
		 * capabilities actually supported (not requested.)
		 */
		ddi_fm_init(si_ctlp->sictl_devinfop, &si_ctlp->fm_capabilities,
		    &fm_ibc);

		if (si_ctlp->fm_capabilities == DDI_FM_NOT_CAPABLE)
			cmn_err(CE_WARN, "si_fm_init: ddi_fm_init fail");

		/*
		 * Initialize pci ereport capabilities if ereport
		 * capable (should always be.)
		 */
		if (DDI_FM_EREPORT_CAP(si_ctlp->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(si_ctlp->fm_capabilities)) {
			pci_ereport_setup(si_ctlp->sictl_devinfop);
		}

		/*
		 * Register error callback if error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(si_ctlp->fm_capabilities)) {
			ddi_fm_handler_register(si_ctlp->sictl_devinfop,
			    si_fm_error_cb, (void *) si_ctlp);
		}
	}
}

/*
 * si_fm_fini - Releases fma capabilities and un-registers with IO
 *              fault services.
 */
static void
si_fm_fini(si_ctl_state_t *si_ctlp)
{
	/* Only unregister FMA capabilities if registered */
	if (si_ctlp->fm_capabilities) {
		/*
		 * Un-register error callback if error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(si_ctlp->fm_capabilities)) {
			ddi_fm_handler_unregister(si_ctlp->sictl_devinfop);
		}

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(si_ctlp->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(si_ctlp->fm_capabilities)) {
			pci_ereport_teardown(si_ctlp->sictl_devinfop);
		}

		/* Unregister from IO Fault Services */
		ddi_fm_fini(si_ctlp->sictl_devinfop);

		/* Adjust access and dma attributes for FMA */
		accattr.devacc_attr_access = DDI_DEFAULT_ACC;
		prb_sgt_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		buffer_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
	}
}

static int
si_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;

	ASSERT(handle != NULL);
	ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

static int
si_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t de;

	ASSERT(handle != NULL);
	ddi_fm_dma_err_get(handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

static int
si_check_ctl_handles(si_ctl_state_t *si_ctlp)
{
	if ((si_check_acc_handle(si_ctlp->sictl_pci_conf_handle)
	    != DDI_SUCCESS) ||
	    (si_check_acc_handle(si_ctlp->sictl_global_acc_handle)
	    != DDI_SUCCESS) ||
	    (si_check_acc_handle(si_ctlp->sictl_port_acc_handle)
	    != DDI_SUCCESS)) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * WARNING: The caller is expected to obtain the siport_mutex
 * before calling us.
 */
static int
si_check_port_handles(si_port_state_t *si_portp)
{
	if ((si_check_dma_handle(si_portp->siport_prbpool_dma_handle)
	    != DDI_SUCCESS) ||
	    (si_check_acc_handle(si_portp->siport_prbpool_acc_handle)
	    != DDI_SUCCESS) ||
	    (si_check_dma_handle(si_portp->siport_sgbpool_dma_handle)
	    != DDI_SUCCESS) ||
	    (si_check_acc_handle(si_portp->siport_sgbpool_acc_handle)
	    != DDI_SUCCESS)) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
si_fm_ereport(si_ctl_state_t *si_ctlp, char *detail, char *payload)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);

	if (DDI_FM_EREPORT_CAP(si_ctlp->fm_capabilities)) {
		ddi_fm_ereport_post(si_ctlp->sictl_devinfop, buf, ena,
		    DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERSION,
		    "detailed_err_type", DATA_TYPE_STRING, payload,
		    NULL);
	}
}

/*
 * Logs the message.
 */
static void
si_log(si_ctl_state_t *si_ctlp, si_port_state_t *si_portp, char *fmt, ...)
{
	va_list ap;

	mutex_enter(&si_log_mutex);

	va_start(ap, fmt);

	if (si_portp == NULL && si_ctlp == NULL) {
		sata_vtrace_debug(NULL, fmt, ap);
		va_end(ap);
		mutex_exit(&si_log_mutex);
		return;
	}

	if (si_portp == NULL && si_ctlp != NULL) {
		sata_vtrace_debug(si_ctlp->sictl_devinfop, fmt, ap);
		va_end(ap);
		mutex_exit(&si_log_mutex);
		return;
	}

	/*
	 * si_portp is not NULL, but si_ctlp might be.
	 * Reference si_portp for both port and dip.
	 */
	(void) snprintf(si_log_buf, SI_LOGBUF_LEN, "port%d: %s",
	    si_portp->siport_port_num, fmt);

	if (si_portp->siport_ctlp == NULL) {
		sata_vtrace_debug(NULL, si_log_buf, ap);
		va_end(ap);
		mutex_exit(&si_log_mutex);
		return;
	}

	sata_vtrace_debug(si_portp->siport_ctlp->sictl_devinfop,
	    si_log_buf, ap);

	va_end(ap);

	mutex_exit(&si_log_mutex);

}

static void
si_copy_out_regs(sata_cmd_t *scmd, si_ctl_state_t *si_ctlp, uint8_t port,
	uint8_t slot)
{
	uint32_t *fis_word_ptr;
	si_prb_t *prb;
	int i;
	si_port_state_t *si_portp = si_ctlp->sictl_ports[port];

	/*
	 * The LRAM contains the the modified FIS after command completion, so
	 * first copy it back to the in-core PRB pool.  To save read cycles,
	 * just copy over the FIS portion of the PRB pool.
	 */
	prb =  &si_ctlp->sictl_ports[port]->siport_prbpool[slot];

	fis_word_ptr = (uint32_t *)(void *)(&prb->prb_fis);

	for (i = 0; i < (sizeof (fis_reg_h2d_t)/4); i++) {
		fis_word_ptr[i] = ddi_get32(
		    si_ctlp->sictl_port_acc_handle,
		    (uint32_t *)(PORT_LRAM(si_ctlp, port,
		    slot) + i * 4 + 0x08));
	}

	/*
	 * always get the status register
	 */
	scmd->satacmd_status_reg = GET_FIS_COMMAND(prb->prb_fis);

	DTRACE_PROBE1(satacmd_status_reg, int, scmd->satacmd_status_reg);

	if (scmd->satacmd_flags.sata_copy_out_sec_count_msb) {
		scmd->satacmd_sec_count_msb =
		    GET_FIS_SECTOR_COUNT_EXP(prb->prb_fis);
		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "copyout satacmd_sec_count_msb %x\n",
		    scmd->satacmd_sec_count_msb);
	}

	if (scmd->satacmd_flags.sata_copy_out_lba_low_msb) {
		scmd->satacmd_lba_low_msb = GET_FIS_SECTOR_EXP(prb->prb_fis);
		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "copyout satacmd_lba_low_msb %x\n",
		    scmd->satacmd_lba_low_msb);
	}

	if (scmd->satacmd_flags.sata_copy_out_lba_mid_msb) {
		scmd->satacmd_lba_mid_msb = GET_FIS_CYL_LOW_EXP(prb->prb_fis);
		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "copyout satacmd_lba_mid_msb %x\n",
		    scmd->satacmd_lba_mid_msb);
	}

	if (scmd->satacmd_flags.sata_copy_out_lba_high_msb) {
		scmd->satacmd_lba_high_msb = GET_FIS_CYL_HI_EXP(prb->prb_fis);
		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "copyout satacmd_lba_high_msb %x\n",
		    scmd->satacmd_lba_high_msb);
	}

	if (scmd->satacmd_flags.sata_copy_out_sec_count_lsb) {
		scmd->satacmd_sec_count_lsb =
		    GET_FIS_SECTOR_COUNT(prb->prb_fis);
		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "copyout satacmd_sec_count_lsb %x\n",
		    scmd->satacmd_sec_count_lsb);
	}

	if (scmd->satacmd_flags.sata_copy_out_lba_low_lsb) {
		scmd->satacmd_lba_low_lsb = GET_FIS_SECTOR(prb->prb_fis);
		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "copyout satacmd_lba_low_lsb %x\n",
		    scmd->satacmd_lba_low_lsb);
	}

	if (scmd->satacmd_flags.sata_copy_out_lba_mid_lsb) {
		scmd->satacmd_lba_mid_lsb = GET_FIS_CYL_LOW(prb->prb_fis);
		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "copyout satacmd_lba_mid_lsb %x\n",
		    scmd->satacmd_lba_mid_lsb);
	}

	if (scmd->satacmd_flags.sata_copy_out_lba_high_lsb) {
		scmd->satacmd_lba_high_lsb = GET_FIS_CYL_HI(prb->prb_fis);
		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "copyout satacmd_lba_high_lsb %x\n",
		    scmd->satacmd_lba_high_lsb);
	}

	if (scmd->satacmd_flags.sata_copy_out_device_reg) {
		scmd->satacmd_device_reg = GET_FIS_DEV_HEAD(prb->prb_fis);
		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "copyout satacmd_device_reg %x\n",
		    scmd->satacmd_device_reg);
	}

	if (scmd->satacmd_flags.sata_copy_out_error_reg) {
		scmd->satacmd_error_reg = GET_FIS_FEATURES(prb->prb_fis);
		SIDBG_P(SIDBG_VERBOSE, si_portp,
		    "copyout satacmd_error_reg %x\n",
		    scmd->satacmd_error_reg);
	}
}

/*
 * This function clear the special port by send the PORT RESET
 * After reset was sent, all commands running on the port
 * is aborted
 */
static int
si_clear_port(si_ctl_state_t *si_ctlp, int port)
{

	if (si_ctlp == NULL)
		return (SI_FAILURE);
	/*
	 * reset this port so that all existing command
	 * is clear
	 */
	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_CONTROL_SET(si_ctlp, port),
	    PORT_CONTROL_SET_BITS_PORT_RESET);

	/* Port reset is not self clearing. So clear it now. */
	ddi_put32(si_ctlp->sictl_port_acc_handle,
	    (uint32_t *)PORT_CONTROL_CLEAR(si_ctlp, port),
	    PORT_CONTROL_CLEAR_BITS_PORT_RESET);
	return (SI_SUCCESS);
}

/*
 * quiesce(9E) entry point.
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
si_quiesce(dev_info_t *dip)
{
	si_ctl_state_t *si_ctlp;
	int instance;
	int port;

	instance = ddi_get_instance(dip);
	si_ctlp = ddi_get_soft_state(si_statep, instance);
	if (si_ctlp == NULL)
		return (DDI_FAILURE);

	SIDBG_C(SIDBG_ENTRY, si_ctlp, "si_quiesce enter", NULL);
	/*
	 * Disable all the interrupts before quiesce
	 */

	for (port = 0; port < si_ctlp->sictl_num_ports; port++) {
		si_disable_port_interrupts(si_ctlp, port);
		(void) si_clear_port(si_ctlp, port);
	}

	return (DDI_SUCCESS);
}
