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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * AHCI (Advanced Host Controller Interface) SATA HBA Driver
 *
 * Power Management Support
 * ------------------------
 *
 * At the moment, the ahci driver only implements suspend/resume to
 * support Suspend to RAM on X86 feature. Device power management isn't
 * implemented, link power management is disabled, and hot plug isn't
 * allowed during the period from suspend to resume.
 *
 * For s/r support, the ahci driver only need to implement DDI_SUSPEND
 * and DDI_RESUME entries, and don't need to take care of new requests
 * sent down after suspend because the target driver (sd) has already
 * handled these conditions, and blocked these requests. For the detailed
 * information, please check with sdopen, sdclose and sdioctl routines.
 *
 */

#include <sys/note.h>
#include <sys/scsi/scsi.h>
#include <sys/pci.h>
#include <sys/disp.h>
#include <sys/sata/sata_hba.h>
#include <sys/sata/adapters/ahci/ahcireg.h>
#include <sys/sata/adapters/ahci/ahcivar.h>

/*
 * FMA header files
 */
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

/*
 * This is the string displayed by modinfo, etc.
 */
static char ahci_ident[] = "ahci driver";

/*
 * Function prototypes for driver entry points
 */
static	int ahci_attach(dev_info_t *, ddi_attach_cmd_t);
static	int ahci_detach(dev_info_t *, ddi_detach_cmd_t);
static	int ahci_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static	int ahci_quiesce(dev_info_t *);

/*
 * Function prototypes for SATA Framework interfaces
 */
static	int ahci_register_sata_hba_tran(ahci_ctl_t *, uint32_t);
static	int ahci_unregister_sata_hba_tran(ahci_ctl_t *);

static	int ahci_tran_probe_port(dev_info_t *, sata_device_t *);
static	int ahci_tran_start(dev_info_t *, sata_pkt_t *spkt);
static	int ahci_tran_abort(dev_info_t *, sata_pkt_t *, int);
static	int ahci_tran_reset_dport(dev_info_t *, sata_device_t *);
static	int ahci_tran_hotplug_port_activate(dev_info_t *, sata_device_t *);
static	int ahci_tran_hotplug_port_deactivate(dev_info_t *, sata_device_t *);
#if defined(__lock_lint)
static	int ahci_selftest(dev_info_t *, sata_device_t *);
#endif

/*
 * FMA Prototypes
 */
static	void ahci_fm_init(ahci_ctl_t *);
static	void ahci_fm_fini(ahci_ctl_t *);
static	int ahci_fm_error_cb(dev_info_t *, ddi_fm_error_t *, const void*);
int	ahci_check_acc_handle(ddi_acc_handle_t);
int	ahci_check_dma_handle(ddi_dma_handle_t);
void	ahci_fm_ereport(ahci_ctl_t *, char *);
static	int ahci_check_all_handle(ahci_ctl_t *);
static	int ahci_check_ctl_handle(ahci_ctl_t *);
static	int ahci_check_port_handle(ahci_ctl_t *, int);
static	int ahci_check_slot_handle(ahci_port_t *, int);

/*
 * Local function prototypes
 */
static	int ahci_setup_port_base_addresses(ahci_ctl_t *, ahci_port_t *);
static	int ahci_alloc_ports_state(ahci_ctl_t *);
static	void ahci_dealloc_ports_state(ahci_ctl_t *);
static	int ahci_alloc_port_state(ahci_ctl_t *, uint8_t);
static	void ahci_dealloc_port_state(ahci_ctl_t *, uint8_t);
static	int ahci_alloc_rcvd_fis(ahci_ctl_t *, ahci_port_t *);
static	void ahci_dealloc_rcvd_fis(ahci_port_t *);
static	int ahci_alloc_cmd_list(ahci_ctl_t *, ahci_port_t *);
static	void ahci_dealloc_cmd_list(ahci_ctl_t *, ahci_port_t *);
static  int ahci_alloc_cmd_tables(ahci_ctl_t *, ahci_port_t *);
static  void ahci_dealloc_cmd_tables(ahci_ctl_t *, ahci_port_t *);
static	void ahci_alloc_pmult(ahci_ctl_t *, ahci_port_t *);
static	void ahci_dealloc_pmult(ahci_ctl_t *, ahci_port_t *);

static	int ahci_initialize_controller(ahci_ctl_t *);
static	void ahci_uninitialize_controller(ahci_ctl_t *);
static	int ahci_initialize_port(ahci_ctl_t *, ahci_port_t *, ahci_addr_t *);
static	int ahci_config_space_init(ahci_ctl_t *);
static	void ahci_staggered_spin_up(ahci_ctl_t *, uint8_t);

static	void ahci_drain_ports_taskq(ahci_ctl_t *);
static	int ahci_rdwr_pmult(ahci_ctl_t *, ahci_addr_t *, uint8_t, uint32_t *,
    uint8_t);
static	int ahci_read_pmult(ahci_ctl_t *, ahci_addr_t *, uint8_t, uint32_t *);
static	int ahci_write_pmult(ahci_ctl_t *, ahci_addr_t *, uint8_t, uint32_t);
static	int ahci_update_pmult_pscr(ahci_ctl_t *, ahci_addr_t *,
    sata_device_t *);
static	int ahci_update_pmult_gscr(ahci_ctl_t *, ahci_addr_t *,
    sata_pmult_gscr_t *);
static	int ahci_initialize_pmult(ahci_ctl_t *, ahci_port_t *, ahci_addr_t *,
    sata_device_t *);
static	int ahci_initialize_pmport(ahci_ctl_t *, ahci_port_t *, ahci_addr_t *);
static	int ahci_probe_pmult(ahci_ctl_t *, ahci_port_t *, ahci_addr_t *);
static	int ahci_probe_pmport(ahci_ctl_t *, ahci_port_t *, ahci_addr_t *,
    sata_device_t *);

static	void ahci_disable_interface_pm(ahci_ctl_t *, uint8_t);
static	int ahci_start_port(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	void ahci_find_dev_signature(ahci_ctl_t *, ahci_port_t *,
    ahci_addr_t *);
static	void ahci_update_sata_registers(ahci_ctl_t *, uint8_t, sata_device_t *);
static	int ahci_deliver_satapkt(ahci_ctl_t *, ahci_port_t *,
    ahci_addr_t *, sata_pkt_t *);
static	int ahci_do_sync_start(ahci_ctl_t *, ahci_port_t *,
    ahci_addr_t *, sata_pkt_t *);
static	int ahci_claim_free_slot(ahci_ctl_t *, ahci_port_t *,
    ahci_addr_t *, int);
static  void ahci_copy_err_cnxt(sata_cmd_t *, ahci_fis_d2h_register_t *);
static	void ahci_copy_ncq_err_page(sata_cmd_t *,
    struct sata_ncq_error_recovery_page *);
static	void ahci_copy_out_regs(sata_cmd_t *, ahci_fis_d2h_register_t *);
static	void ahci_add_doneq(ahci_port_t *, sata_pkt_t *, int);
static	void ahci_flush_doneq(ahci_port_t *);

static	int ahci_software_reset(ahci_ctl_t *, ahci_port_t *, ahci_addr_t *);
static	int ahci_hba_reset(ahci_ctl_t *);
static	int ahci_port_reset(ahci_ctl_t *, ahci_port_t *, ahci_addr_t *);
static	int ahci_pmport_reset(ahci_ctl_t *, ahci_port_t *, ahci_addr_t *);
static	void ahci_reject_all_abort_pkts(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_reset_device_reject_pkts(ahci_ctl_t *, ahci_port_t *,
    ahci_addr_t *);
static	int ahci_reset_pmdevice_reject_pkts(ahci_ctl_t *, ahci_port_t *,
    ahci_addr_t *);
static	int ahci_reset_port_reject_pkts(ahci_ctl_t *, ahci_port_t *,
    ahci_addr_t *);
static	int ahci_reset_hba_reject_pkts(ahci_ctl_t *);
static	int ahci_put_port_into_notrunning_state(ahci_ctl_t *, ahci_port_t *,
    uint8_t);
static	int ahci_restart_port_wait_till_ready(ahci_ctl_t *, ahci_port_t *,
    uint8_t, int, int *);
static	void ahci_mop_commands(ahci_ctl_t *, ahci_port_t *, uint32_t,
    uint32_t, uint32_t, uint32_t, uint32_t);
static	uint32_t ahci_get_rdlogext_data(ahci_ctl_t *, ahci_port_t *, uint8_t);
static void ahci_get_rqsense_data(ahci_ctl_t *, ahci_port_t *,
    uint8_t, sata_pkt_t *);
static	void ahci_fatal_error_recovery_handler(ahci_ctl_t *, ahci_port_t *,
    ahci_addr_t *, uint32_t);
static	void ahci_pmult_error_recovery_handler(ahci_ctl_t *, ahci_port_t *,
    uint8_t, uint32_t);
static	void ahci_timeout_pkts(ahci_ctl_t *, ahci_port_t *,
    uint8_t, uint32_t);
static	void ahci_events_handler(void *);
static	void ahci_watchdog_handler(ahci_ctl_t *);

static	uint_t ahci_intr(caddr_t, caddr_t);
static	void ahci_port_intr(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_add_intrs(ahci_ctl_t *, int);
static	void ahci_rem_intrs(ahci_ctl_t *);
static	void ahci_enable_all_intrs(ahci_ctl_t *);
static	void ahci_disable_all_intrs(ahci_ctl_t *);
static	void ahci_enable_port_intrs(ahci_ctl_t *, uint8_t);
static	void ahci_disable_port_intrs(ahci_ctl_t *, uint8_t);

static  int ahci_intr_cmd_cmplt(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_set_device_bits(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_ncq_events(ahci_ctl_t *, ahci_port_t *, ahci_addr_t *);
static	int ahci_intr_pmult_sntf_events(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_port_connect_change(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_device_mechanical_presence_status(ahci_ctl_t *,
    ahci_port_t *, uint8_t);
static	int ahci_intr_phyrdy_change(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_non_fatal_error(ahci_ctl_t *, ahci_port_t *,
    uint8_t, uint32_t);
static  int ahci_intr_fatal_error(ahci_ctl_t *, ahci_port_t *,
    uint8_t, uint32_t);
static	int ahci_intr_cold_port_detect(ahci_ctl_t *, ahci_port_t *, uint8_t);

static	void ahci_get_ahci_addr(ahci_ctl_t *, sata_device_t *, ahci_addr_t *);
static	int ahci_get_num_implemented_ports(uint32_t);
static  void ahci_log_fatal_error_message(ahci_ctl_t *, uint8_t, uint32_t);
static	void ahci_dump_commands(ahci_ctl_t *, uint8_t, uint32_t);
static	void ahci_log_serror_message(ahci_ctl_t *, uint8_t, uint32_t, int);
#if AHCI_DEBUG
static	void ahci_log(ahci_ctl_t *, uint_t, char *, ...);
#endif


/*
 * DMA attributes for the data buffer
 *
 * dma_attr_addr_hi will be changed to 0xffffffffull if the HBA
 * does not support 64-bit addressing
 */
static ddi_dma_attr_t buffer_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0x0ull,			/* dma_attr_addr_lo: lowest bus address */
	0xffffffffffffffffull,	/* dma_attr_addr_hi: highest bus address */
	0x3fffffull,		/* dma_attr_count_max i.e. for one cookie */
	0x2ull,			/* dma_attr_align: word aligned */
	1,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_maxxfer i.e. includes all cookies */
	0xffffffffull,		/* dma_attr_seg */
	AHCI_PRDT_NUMBER,	/* dma_attr_sgllen */
	512,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};

/*
 * DMA attributes for the rcvd FIS
 *
 * dma_attr_addr_hi will be changed to 0xffffffffull if the HBA
 * does not support 64-bit addressing
 */
static ddi_dma_attr_t rcvd_fis_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0x0ull,			/* dma_attr_addr_lo: lowest bus address */
	0xffffffffffffffffull,	/* dma_attr_addr_hi: highest bus address */
	0xffffffffull,		/* dma_attr_count_max i.e. for one cookie */
	0x100ull,		/* dma_attr_align: 256-byte aligned */
	1,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_maxxfer i.e. includes all cookies */
	0xffffffffull,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};

/*
 * DMA attributes for the command list
 *
 * dma_attr_addr_hi will be changed to 0xffffffffull if the HBA
 * does not support 64-bit addressing
 */
static ddi_dma_attr_t cmd_list_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0x0ull,			/* dma_attr_addr_lo: lowest bus address */
	0xffffffffffffffffull,	/* dma_attr_addr_hi: highest bus address */
	0xffffffffull,		/* dma_attr_count_max i.e. for one cookie */
	0x400ull,		/* dma_attr_align: 1K-byte aligned */
	1,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_maxxfer i.e. includes all cookies */
	0xffffffffull,		/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};

/*
 * DMA attributes for cmd tables
 *
 * dma_attr_addr_hi will be changed to 0xffffffffull if the HBA
 * does not support 64-bit addressing
 */
static ddi_dma_attr_t cmd_table_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0x0ull,			/* dma_attr_addr_lo: lowest bus address */
	0xffffffffffffffffull,	/* dma_attr_addr_hi: highest bus address */
	0xffffffffull,		/* dma_attr_count_max i.e. for one cookie */
	0x80ull,		/* dma_attr_align: 128-byte aligned */
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


static struct dev_ops ahcictl_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	ahci_getinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	ahci_attach,		/* attach */
	ahci_detach,		/* detach */
	nodev,			/* no reset */
	(struct cb_ops *)0,	/* driver operations */
	NULL,			/* bus operations */
	NULL,			/* power */
	ahci_quiesce,		/* quiesce */
};

static sata_tran_hotplug_ops_t ahci_tran_hotplug_ops = {
	SATA_TRAN_HOTPLUG_OPS_REV_1,
	ahci_tran_hotplug_port_activate,
	ahci_tran_hotplug_port_deactivate
};

extern struct mod_ops mod_driverops;

static  struct modldrv modldrv = {
	&mod_driverops,		/* driverops */
	ahci_ident,		/* short description */
	&ahcictl_dev_ops,	/* driver ops */
};

static  struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/* The following variables are watchdog handler related */
static clock_t ahci_watchdog_timeout = 5; /* 5 seconds */
static clock_t ahci_watchdog_tick;

/*
 * This static variable indicates the size of command table,
 * and it's changeable with prdt number, which ahci_dma_prdt_number
 * indicates.
 */
static size_t ahci_cmd_table_size;

/*
 * The below global variables are tunable via /etc/system
 *
 *	ahci_dma_prdt_number
 *	ahci_msi_enabled
 *	ahci_buf_64bit_dma
 *	ahci_commu_64bit_dma
 */

/* The number of Physical Region Descriptor Table(PRDT) in Command Table */
int ahci_dma_prdt_number = AHCI_PRDT_NUMBER;

/* AHCI MSI is tunable */
boolean_t ahci_msi_enabled = B_TRUE;

/*
 * 64-bit dma addressing for data buffer is tunable
 *
 * The variable controls only the below value:
 *	DBAU (upper 32-bits physical address of data block)
 */
boolean_t ahci_buf_64bit_dma = B_TRUE;

/*
 * 64-bit dma addressing for communication system descriptors is tunable
 *
 * The variable controls the below three values:
 *
 *	PxCLBU (upper 32-bits for the command list base physical address)
 *	PxFBU (upper 32-bits for the received FIS base physical address)
 *	CTBAU (upper 32-bits of command table base)
 */
boolean_t ahci_commu_64bit_dma = B_TRUE;

/*
 * By default, 64-bit dma for data buffer will be disabled for AMD/ATI SB600
 * chipset. If the users want to have a try with 64-bit dma, please change
 * the below variable value to enable it.
 */
boolean_t sb600_buf_64bit_dma_disable = B_TRUE;

/*
 * By default, 64-bit dma for command buffer will be disabled for AMD/ATI
 * SB600/700/710/750/800. If the users want to have a try with 64-bit dma,
 * please change the below value to enable it.
 */
boolean_t sbxxx_commu_64bit_dma_disable = B_TRUE;


/*
 * End of global tunable variable definition
 */

#if AHCI_DEBUG
uint32_t ahci_debug_flags = 0;
#else
uint32_t ahci_debug_flags = (AHCIDBG_ERRS|AHCIDBG_TIMEOUT);
#endif


#if AHCI_DEBUG
/* The following is needed for ahci_log() */
static kmutex_t ahci_log_mutex;
static char ahci_log_buf[512];
#endif

/* Opaque state pointer initialized by ddi_soft_state_init() */
static void *ahci_statep = NULL;

/*
 *  ahci module initialization.
 */
int
_init(void)
{
	int	ret;

	ret = ddi_soft_state_init(&ahci_statep, sizeof (ahci_ctl_t), 0);
	if (ret != 0) {
		goto err_out;
	}

#if AHCI_DEBUG
	mutex_init(&ahci_log_mutex, NULL, MUTEX_DRIVER, NULL);
#endif

	if ((ret = sata_hba_init(&modlinkage)) != 0) {
#if AHCI_DEBUG
		mutex_destroy(&ahci_log_mutex);
#endif
		ddi_soft_state_fini(&ahci_statep);
		goto err_out;
	}

	/* watchdog tick */
	ahci_watchdog_tick = drv_usectohz(
	    (clock_t)ahci_watchdog_timeout * 1000000);

	ret = mod_install(&modlinkage);
	if (ret != 0) {
		sata_hba_fini(&modlinkage);
#if AHCI_DEBUG
		mutex_destroy(&ahci_log_mutex);
#endif
		ddi_soft_state_fini(&ahci_statep);
		goto err_out;
	}

	return (ret);

err_out:
	cmn_err(CE_WARN, "!ahci: Module init failed");
	return (ret);
}

/*
 * ahci module uninitialize.
 */
int
_fini(void)
{
	int	ret;

	ret = mod_remove(&modlinkage);
	if (ret != 0) {
		return (ret);
	}

	/* Remove the resources allocated in _init(). */
	sata_hba_fini(&modlinkage);
#if AHCI_DEBUG
	mutex_destroy(&ahci_log_mutex);
#endif
	ddi_soft_state_fini(&ahci_statep);

	return (ret);
}

/*
 * _info entry point
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * The attach entry point for dev_ops.
 */
static int
ahci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ahci_ctl_t *ahci_ctlp = NULL;
	int instance = ddi_get_instance(dip);
	int status;
	int attach_state;
	uint32_t cap_status, ahci_version;
	uint32_t ghc_control;
	int intr_types;
	int i;
	pci_regspec_t *regs;
	int regs_length;
	int rnumber;
#if AHCI_DEBUG
	int speed;
#endif

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp, "ahci_attach enter",
	    NULL);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:

		/*
		 * During DDI_RESUME, the hardware state of the device
		 * (power may have been removed from the device) must be
		 * restored, allow pending requests to continue, and
		 * service new requests.
		 */
		ahci_ctlp = ddi_get_soft_state(ahci_statep, instance);
		mutex_enter(&ahci_ctlp->ahcictl_mutex);

		/*
		 * GHC.AE must be set to 1 before any other AHCI register
		 * is accessed
		 */
		ghc_control = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp));
		ghc_control |= AHCI_HBA_GHC_AE;
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp), ghc_control);

		/* Restart watch thread */
		if (ahci_ctlp->ahcictl_timeout_id == 0)
			ahci_ctlp->ahcictl_timeout_id = timeout(
			    (void (*)(void *))ahci_watchdog_handler,
			    (caddr_t)ahci_ctlp, ahci_watchdog_tick);

		mutex_exit(&ahci_ctlp->ahcictl_mutex);

		/*
		 * Re-initialize the controller and enable the interrupts and
		 * restart all the ports.
		 *
		 * Note that so far we don't support hot-plug during
		 * suspend/resume.
		 */
		if (ahci_initialize_controller(ahci_ctlp) != AHCI_SUCCESS) {
			AHCIDBG(AHCIDBG_ERRS|AHCIDBG_PM, ahci_ctlp,
			    "Failed to initialize the controller "
			    "during DDI_RESUME", NULL);
			return (DDI_FAILURE);
		}

		mutex_enter(&ahci_ctlp->ahcictl_mutex);
		ahci_ctlp->ahcictl_flags &= ~AHCI_SUSPEND;
		mutex_exit(&ahci_ctlp->ahcictl_mutex);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	attach_state = AHCI_ATTACH_STATE_NONE;

	/* Allocate soft state */
	status = ddi_soft_state_zalloc(ahci_statep, instance);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!ahci%d: Cannot allocate soft state",
		    instance);
		goto err_out;
	}

	ahci_ctlp = ddi_get_soft_state(ahci_statep, instance);
	ahci_ctlp->ahcictl_flags |= AHCI_ATTACH;
	ahci_ctlp->ahcictl_dip = dip;

	/* Initialize the cport/port mapping */
	for (i = 0; i < AHCI_MAX_PORTS; i++) {
		ahci_ctlp->ahcictl_port_to_cport[i] = 0xff;
		ahci_ctlp->ahcictl_cport_to_port[i] = 0xff;
	}

	attach_state |= AHCI_ATTACH_STATE_STATEP_ALLOC;

	/* Initialize FMA properties */
	ahci_fm_init(ahci_ctlp);

	attach_state |= AHCI_ATTACH_STATE_FMA;

	/*
	 * Now map the AHCI base address; which includes global
	 * registers and port control registers
	 *
	 * According to the spec, the AHCI Base Address is BAR5,
	 * but BAR0-BAR4 are optional, so we need to check which
	 * rnumber is used for BAR5.
	 */

	/*
	 * search through DDI "reg" property for the AHCI register set
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", (int **)&regs,
	    (uint_t *)&regs_length) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "!ahci%d: Cannot lookup reg property",
		    instance);
		goto err_out;
	}

	/* AHCI Base Address is located at 0x24 offset */
	for (rnumber = 0; rnumber < regs_length; ++rnumber) {
		if ((regs[rnumber].pci_phys_hi & PCI_REG_REG_M)
		    == AHCI_PCI_RNUM)
			break;
	}

	ddi_prop_free(regs);

	if (rnumber == regs_length) {
		cmn_err(CE_WARN, "!ahci%d: Cannot find AHCI register set",
		    instance);
		goto err_out;
	}

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp, "rnumber = %d", rnumber);

	status = ddi_regs_map_setup(dip,
	    rnumber,
	    (caddr_t *)&ahci_ctlp->ahcictl_ahci_addr,
	    0,
	    0,
	    &accattr,
	    &ahci_ctlp->ahcictl_ahci_acc_handle);
	if (status != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!ahci%d: Cannot map register space",
		    instance);
		goto err_out;
	}

	attach_state |= AHCI_ATTACH_STATE_REG_MAP;

	/*
	 * GHC.AE must be set to 1 before any other AHCI register
	 * is accessed
	 */
	ghc_control = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp));
	ghc_control |= AHCI_HBA_GHC_AE;
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp), ghc_control);

	/* Get the AHCI version information */
	ahci_version = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_VS(ahci_ctlp));

	cmn_err(CE_NOTE, "!ahci%d: hba AHCI version = %x.%x", instance,
	    (ahci_version & 0xffff0000) >> 16,
	    ((ahci_version & 0x0000ff00) >> 4 |
	    (ahci_version & 0x000000ff)));

	/* We don't support controllers whose versions are lower than 1.0 */
	if (!(ahci_version & 0xffff0000)) {
		cmn_err(CE_WARN, "ahci%d: Don't support AHCI HBA with lower "
		    "than version 1.0", instance);
		goto err_out;
	}

	/* Get the HBA capabilities information */
	cap_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_CAP(ahci_ctlp));

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp, "hba capabilities = 0x%x",
	    cap_status);

	/* CAP2 (HBA Capabilities Extended) is available since AHCI spec 1.2 */
	if (ahci_version >= 0x00010200) {
		uint32_t cap2_status;

		/* Get the HBA capabilities extended information */
		cap2_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_GLOBAL_CAP2(ahci_ctlp));

		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "hba capabilities extended = 0x%x", cap2_status);
	}

#if AHCI_DEBUG
	/* Get the interface speed supported by the HBA */
	speed = (cap_status & AHCI_HBA_CAP_ISS) >> AHCI_HBA_CAP_ISS_SHIFT;
	if (speed == 0x01) {
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "hba interface speed support: Gen 1 (1.5Gbps)", NULL);
	} else if (speed == 0x10) {
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "hba interface speed support: Gen 2 (3 Gbps)", NULL);
	} else if (speed == 0x11) {
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "hba interface speed support: Gen 3 (6 Gbps)", NULL);
	}
#endif

	/* Get the number of command slots supported by the HBA */
	ahci_ctlp->ahcictl_num_cmd_slots =
	    ((cap_status & AHCI_HBA_CAP_NCS) >>
	    AHCI_HBA_CAP_NCS_SHIFT) + 1;

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp, "hba number of cmd slots: %d",
	    ahci_ctlp->ahcictl_num_cmd_slots);

	/* Get the bit map which indicates ports implemented by the HBA */
	ahci_ctlp->ahcictl_ports_implemented =
	    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_PI(ahci_ctlp));

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp, "hba implementation of ports: 0x%x",
	    ahci_ctlp->ahcictl_ports_implemented);

	/* Max port number implemented */
	ahci_ctlp->ahcictl_num_ports =
	    ddi_fls(ahci_ctlp->ahcictl_ports_implemented);

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp, "hba number of ports: %d",
	    (cap_status & AHCI_HBA_CAP_NP) + 1);

	/* Get the number of implemented ports by the HBA */
	ahci_ctlp->ahcictl_num_implemented_ports =
	    ahci_get_num_implemented_ports(
	    ahci_ctlp->ahcictl_ports_implemented);

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
	    "hba number of implemented ports: %d",
	    ahci_ctlp->ahcictl_num_implemented_ports);

	/* Check whether HBA supports 64bit DMA addressing */
	if (!(cap_status & AHCI_HBA_CAP_S64A)) {
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_BUF_32BIT_DMA;
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_COMMU_32BIT_DMA;
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "hba does not support 64-bit addressing", NULL);
	}

	/* Checking for the support of Port Multiplier */
	if (cap_status & AHCI_HBA_CAP_SPM) {
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_PMULT_CBSS;
		AHCIDBG(AHCIDBG_INIT|AHCIDBG_PMULT, ahci_ctlp,
		    "hba supports port multiplier (CBSS)", NULL);

		/* Support FIS-based switching ? */
		if (cap_status & AHCI_HBA_CAP_FBSS) {
			ahci_ctlp->ahcictl_cap |= AHCI_CAP_PMULT_FBSS;
			AHCIDBG(AHCIDBG_INIT|AHCIDBG_PMULT, ahci_ctlp,
			    "hba supports FIS-based switching (FBSS)", NULL);
		}
	}

	/* Checking for Support Command List Override */
	if (cap_status & AHCI_HBA_CAP_SCLO) {
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_SCLO;
		AHCIDBG(AHCIDBG_INIT|AHCIDBG_PMULT, ahci_ctlp,
		    "hba supports command list override.", NULL);
	}

	/* Checking for Asynchronous Notification */
	if (cap_status & AHCI_HBA_CAP_SSNTF) {
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_SNTF;
		AHCIDBG(AHCIDBG_INIT|AHCIDBG_PMULT, ahci_ctlp,
		    "hba supports asynchronous notification.", NULL);
	}

	if (pci_config_setup(dip, &ahci_ctlp->ahcictl_pci_conf_handle)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!ahci%d: Cannot set up pci configure space",
		    instance);
		goto err_out;
	}

	attach_state |= AHCI_ATTACH_STATE_PCICFG_SETUP;

	/*
	 * Check the pci configuration space, and set caps. We also
	 * handle the hardware defect in this function.
	 *
	 * For example, force ATI SB600 to use 32-bit dma addressing
	 * since it doesn't support 64-bit dma though its CAP register
	 * declares it support.
	 */
	if (ahci_config_space_init(ahci_ctlp) == AHCI_FAILURE) {
		cmn_err(CE_WARN, "!ahci%d: ahci_config_space_init failed",
		    instance);
		goto err_out;
	}

	/*
	 * Disable the whole controller interrupts before adding
	 * interrupt handlers(s).
	 */
	ahci_disable_all_intrs(ahci_ctlp);

	/* Get supported interrupt types */
	if (ddi_intr_get_supported_types(dip, &intr_types) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!ahci%d: ddi_intr_get_supported_types failed",
		    instance);
		goto err_out;
	}

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_INTR, ahci_ctlp,
	    "ddi_intr_get_supported_types() returned: 0x%x",
	    intr_types);

	if (ahci_msi_enabled && (intr_types & DDI_INTR_TYPE_MSI)) {
		/*
		 * Try MSI first, but fall back to FIXED if failed
		 */
		if (ahci_add_intrs(ahci_ctlp, DDI_INTR_TYPE_MSI) ==
		    DDI_SUCCESS) {
			ahci_ctlp->ahcictl_intr_type = DDI_INTR_TYPE_MSI;
			AHCIDBG(AHCIDBG_INIT|AHCIDBG_INTR, ahci_ctlp,
			    "Using MSI interrupt type", NULL);
			goto intr_done;
		}

		AHCIDBG(AHCIDBG_INIT|AHCIDBG_INTR, ahci_ctlp,
		    "MSI registration failed, "
		    "trying FIXED interrupts", NULL);
	}

	if (intr_types & DDI_INTR_TYPE_FIXED) {
		if (ahci_add_intrs(ahci_ctlp, DDI_INTR_TYPE_FIXED) ==
		    DDI_SUCCESS) {
			ahci_ctlp->ahcictl_intr_type = DDI_INTR_TYPE_FIXED;
			AHCIDBG(AHCIDBG_INIT|AHCIDBG_INTR, ahci_ctlp,
			    "Using FIXED interrupt type", NULL);
			goto intr_done;
		}

		AHCIDBG(AHCIDBG_INIT|AHCIDBG_INTR, ahci_ctlp,
		    "FIXED interrupt registration failed", NULL);
	}

	cmn_err(CE_WARN, "!ahci%d: Interrupt registration failed", instance);

	goto err_out;

intr_done:

	attach_state |= AHCI_ATTACH_STATE_INTR_ADDED;

	/* Initialize the controller mutex */
	mutex_init(&ahci_ctlp->ahcictl_mutex, NULL, MUTEX_DRIVER,
	    (void *)(uintptr_t)ahci_ctlp->ahcictl_intr_pri);

	attach_state |= AHCI_ATTACH_STATE_MUTEX_INIT;

	if (ahci_dma_prdt_number < AHCI_MIN_PRDT_NUMBER) {
		ahci_dma_prdt_number = AHCI_MIN_PRDT_NUMBER;
	} else if (ahci_dma_prdt_number > AHCI_MAX_PRDT_NUMBER) {
		ahci_dma_prdt_number = AHCI_MAX_PRDT_NUMBER;
	}

	ahci_cmd_table_size = (sizeof (ahci_cmd_table_t) +
	    (ahci_dma_prdt_number - AHCI_PRDT_NUMBER) *
	    sizeof (ahci_prdt_item_t));

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
	    "ahci_attach: ahci_dma_prdt_number set by user is 0x%x,"
	    " ahci_cmd_table_size is 0x%x",
	    ahci_dma_prdt_number, ahci_cmd_table_size);

	if (ahci_dma_prdt_number != AHCI_PRDT_NUMBER)
		ahci_ctlp->ahcictl_buffer_dma_attr.dma_attr_sgllen =
		    ahci_dma_prdt_number;

	ahci_ctlp->ahcictl_buffer_dma_attr = buffer_dma_attr;
	ahci_ctlp->ahcictl_rcvd_fis_dma_attr = rcvd_fis_dma_attr;
	ahci_ctlp->ahcictl_cmd_list_dma_attr = cmd_list_dma_attr;
	ahci_ctlp->ahcictl_cmd_table_dma_attr = cmd_table_dma_attr;

	/*
	 * enable 64bit dma for data buffer for SB600 if
	 * sb600_buf_64bit_dma_disable is B_FALSE
	 */
	if ((ahci_buf_64bit_dma == B_FALSE) ||
	    ((ahci_ctlp->ahcictl_cap & AHCI_CAP_BUF_32BIT_DMA) &&
	    !(sb600_buf_64bit_dma_disable == B_FALSE &&
	    ahci_ctlp->ahcictl_venid == 0x1002 &&
	    ahci_ctlp->ahcictl_devid == 0x4380))) {
		ahci_ctlp->ahcictl_buffer_dma_attr.dma_attr_addr_hi =
		    0xffffffffull;
	}

	/*
	 * enable 64bit dma for command buffer for SB600/700/710/800
	 * if sbxxx_commu_64bit_dma_disable is B_FALSE
	 */
	if ((ahci_commu_64bit_dma == B_FALSE) ||
	    ((ahci_ctlp->ahcictl_cap & AHCI_CAP_COMMU_32BIT_DMA) &&
	    !(sbxxx_commu_64bit_dma_disable == B_FALSE &&
	    ahci_ctlp->ahcictl_venid == 0x1002 &&
	    (ahci_ctlp->ahcictl_devid == 0x4380 ||
	    ahci_ctlp->ahcictl_devid == 0x4391)))) {
		ahci_ctlp->ahcictl_rcvd_fis_dma_attr.dma_attr_addr_hi =
		    0xffffffffull;
		ahci_ctlp->ahcictl_cmd_list_dma_attr.dma_attr_addr_hi =
		    0xffffffffull;
		ahci_ctlp->ahcictl_cmd_table_dma_attr.dma_attr_addr_hi =
		    0xffffffffull;
	}

	/* Allocate the ports structure */
	status = ahci_alloc_ports_state(ahci_ctlp);
	if (status != AHCI_SUCCESS) {
		cmn_err(CE_WARN, "!ahci%d: Cannot allocate ports structure",
		    instance);
		goto err_out;
	}

	attach_state |= AHCI_ATTACH_STATE_PORT_ALLOC;

	/*
	 * Initialize the controller and ports.
	 */
	status = ahci_initialize_controller(ahci_ctlp);
	if (status != AHCI_SUCCESS) {
		cmn_err(CE_WARN, "!ahci%d: HBA initialization failed",
		    instance);
		goto err_out;
	}

	attach_state |= AHCI_ATTACH_STATE_HW_INIT;

	/* Start one thread to check packet timeouts */
	ahci_ctlp->ahcictl_timeout_id = timeout(
	    (void (*)(void *))ahci_watchdog_handler,
	    (caddr_t)ahci_ctlp, ahci_watchdog_tick);

	attach_state |= AHCI_ATTACH_STATE_TIMEOUT_ENABLED;

	if (ahci_register_sata_hba_tran(ahci_ctlp, cap_status)) {
		cmn_err(CE_WARN, "!ahci%d: sata hba tran registration failed",
		    instance);
		goto err_out;
	}

	/* Check all handles at the end of the attach operation. */
	if (ahci_check_all_handle(ahci_ctlp) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!ahci%d: invalid dma/acc handles",
		    instance);
		goto err_out;
	}

	ahci_ctlp->ahcictl_flags &= ~AHCI_ATTACH;

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp, "ahci_attach success!", NULL);

	return (DDI_SUCCESS);

err_out:
	/* FMA message */
	ahci_fm_ereport(ahci_ctlp, DDI_FM_DEVICE_NO_RESPONSE);
	ddi_fm_service_impact(ahci_ctlp->ahcictl_dip, DDI_SERVICE_LOST);

	if (attach_state & AHCI_ATTACH_STATE_TIMEOUT_ENABLED) {
		mutex_enter(&ahci_ctlp->ahcictl_mutex);
		(void) untimeout(ahci_ctlp->ahcictl_timeout_id);
		ahci_ctlp->ahcictl_timeout_id = 0;
		mutex_exit(&ahci_ctlp->ahcictl_mutex);
	}

	if (attach_state & AHCI_ATTACH_STATE_HW_INIT) {
		ahci_uninitialize_controller(ahci_ctlp);
	}

	if (attach_state & AHCI_ATTACH_STATE_PORT_ALLOC) {
		ahci_dealloc_ports_state(ahci_ctlp);
	}

	if (attach_state & AHCI_ATTACH_STATE_MUTEX_INIT) {
		mutex_destroy(&ahci_ctlp->ahcictl_mutex);
	}

	if (attach_state & AHCI_ATTACH_STATE_INTR_ADDED) {
		ahci_rem_intrs(ahci_ctlp);
	}

	if (attach_state & AHCI_ATTACH_STATE_PCICFG_SETUP) {
		pci_config_teardown(&ahci_ctlp->ahcictl_pci_conf_handle);
	}

	if (attach_state & AHCI_ATTACH_STATE_REG_MAP) {
		ddi_regs_map_free(&ahci_ctlp->ahcictl_ahci_acc_handle);
	}

	if (attach_state & AHCI_ATTACH_STATE_FMA) {
		ahci_fm_fini(ahci_ctlp);
	}

	if (attach_state & AHCI_ATTACH_STATE_STATEP_ALLOC) {
		ddi_soft_state_free(ahci_statep, instance);
	}

	return (DDI_FAILURE);
}

/*
 * The detach entry point for dev_ops.
 */
static int
ahci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ahci_ctl_t *ahci_ctlp;
	int instance;
	int ret;

	instance = ddi_get_instance(dip);
	ahci_ctlp = ddi_get_soft_state(ahci_statep, instance);

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp, "ahci_detach enter", NULL);

	switch (cmd) {
	case DDI_DETACH:

		/* disable the interrupts for an uninterrupted detach */
		mutex_enter(&ahci_ctlp->ahcictl_mutex);
		ahci_disable_all_intrs(ahci_ctlp);
		mutex_exit(&ahci_ctlp->ahcictl_mutex);

		/* unregister from the sata framework. */
		ret = ahci_unregister_sata_hba_tran(ahci_ctlp);
		if (ret != AHCI_SUCCESS) {
			mutex_enter(&ahci_ctlp->ahcictl_mutex);
			ahci_enable_all_intrs(ahci_ctlp);
			mutex_exit(&ahci_ctlp->ahcictl_mutex);
			return (DDI_FAILURE);
		}

		mutex_enter(&ahci_ctlp->ahcictl_mutex);

		/* stop the watchdog handler */
		(void) untimeout(ahci_ctlp->ahcictl_timeout_id);
		ahci_ctlp->ahcictl_timeout_id = 0;

		mutex_exit(&ahci_ctlp->ahcictl_mutex);

		/* uninitialize the controller */
		ahci_uninitialize_controller(ahci_ctlp);

		/* remove the interrupts */
		ahci_rem_intrs(ahci_ctlp);

		/* deallocate the ports structures */
		ahci_dealloc_ports_state(ahci_ctlp);

		/* destroy mutex */
		mutex_destroy(&ahci_ctlp->ahcictl_mutex);

		/* teardown the pci config */
		pci_config_teardown(&ahci_ctlp->ahcictl_pci_conf_handle);

		/* remove the reg maps. */
		ddi_regs_map_free(&ahci_ctlp->ahcictl_ahci_acc_handle);

		/* release fma resource */
		ahci_fm_fini(ahci_ctlp);

		/* free the soft state. */
		ddi_soft_state_free(ahci_statep, instance);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:

		/*
		 * The steps associated with suspension must include putting
		 * the underlying device into a quiescent state so that it
		 * will not generate interrupts or modify or access memory.
		 */
		mutex_enter(&ahci_ctlp->ahcictl_mutex);
		if (ahci_ctlp->ahcictl_flags & AHCI_SUSPEND) {
			mutex_exit(&ahci_ctlp->ahcictl_mutex);
			return (DDI_SUCCESS);
		}

		ahci_ctlp->ahcictl_flags |= AHCI_SUSPEND;

		/* stop the watchdog handler */
		if (ahci_ctlp->ahcictl_timeout_id) {
			(void) untimeout(ahci_ctlp->ahcictl_timeout_id);
			ahci_ctlp->ahcictl_timeout_id = 0;
		}

		mutex_exit(&ahci_ctlp->ahcictl_mutex);

		/*
		 * drain the taskq
		 */
		ahci_drain_ports_taskq(ahci_ctlp);

		/*
		 * Disable the interrupts and stop all the ports.
		 */
		ahci_uninitialize_controller(ahci_ctlp);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * The info entry point for dev_ops.
 *
 */
static int
ahci_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(dip))
#endif /* __lock_lint */

	ahci_ctl_t *ahci_ctlp;
	int instance;
	dev_t dev;

	dev = (dev_t)arg;
	instance = getminor(dev);

	switch (infocmd) {
		case DDI_INFO_DEVT2DEVINFO:
			ahci_ctlp = ddi_get_soft_state(ahci_statep,  instance);
			if (ahci_ctlp != NULL) {
				*result = ahci_ctlp->ahcictl_dip;
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
 * Registers the ahci with sata framework.
 */
static int
ahci_register_sata_hba_tran(ahci_ctl_t *ahci_ctlp, uint32_t cap_status)
{
	struct 	sata_hba_tran	*sata_hba_tran;

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_register_sata_hba_tran enter", NULL);

	mutex_enter(&ahci_ctlp->ahcictl_mutex);

	/* Allocate memory for the sata_hba_tran  */
	sata_hba_tran = kmem_zalloc(sizeof (sata_hba_tran_t), KM_SLEEP);

	sata_hba_tran->sata_tran_hba_rev = SATA_TRAN_HBA_REV;
	sata_hba_tran->sata_tran_hba_dip = ahci_ctlp->ahcictl_dip;
	sata_hba_tran->sata_tran_hba_dma_attr =
	    &ahci_ctlp->ahcictl_buffer_dma_attr;

	/* Report the number of implemented ports */
	sata_hba_tran->sata_tran_hba_num_cports =
	    ahci_ctlp->ahcictl_num_implemented_ports;

	/* Support ATAPI device */
	sata_hba_tran->sata_tran_hba_features_support = SATA_CTLF_ATAPI;

	/* Get the data transfer capability for PIO command by the HBA */
	if (cap_status & AHCI_HBA_CAP_PMD) {
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_PIO_MDRQ;
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp, "HBA supports multiple "
		    "DRQ block data transfer for PIO command protocol", NULL);
	}

	/*
	 * According to the AHCI spec, the ATA/ATAPI-7 queued feature set
	 * is not supported by AHCI (including the READ QUEUED (EXT), WRITE
	 * QUEUED (EXT), and SERVICE commands). Queued operations are
	 * supported in AHCI using the READ FPDMA QUEUED and WRITE FPDMA
	 * QUEUED commands when the HBA and device support native command
	 * queuing(NCQ).
	 *
	 * SATA_CTLF_NCQ will be set to sata_tran_hba_features_support if the
	 * CAP register of the HBA indicates NCQ is supported.
	 *
	 * SATA_CTLF_NCQ cannot be set if AHCI_CAP_NO_MCMDLIST_NONQUEUE is
	 * set because the previous register content of PxCI can be re-written
	 * in the register write.
	 */
	if ((cap_status & AHCI_HBA_CAP_SNCQ) &&
	    !(ahci_ctlp->ahcictl_cap & AHCI_CAP_NO_MCMDLIST_NONQUEUE)) {
		sata_hba_tran->sata_tran_hba_features_support |= SATA_CTLF_NCQ;
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_NCQ;
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp, "HBA supports Native "
		    "Command Queuing", NULL);
	}

	/* Support port multiplier? */
	if (cap_status & AHCI_HBA_CAP_SPM) {
		sata_hba_tran->sata_tran_hba_features_support |=
		    SATA_CTLF_PORT_MULTIPLIER;

		/* Support FIS-based switching for port multiplier? */
		if (cap_status & AHCI_HBA_CAP_FBSS) {
			sata_hba_tran->sata_tran_hba_features_support |=
			    SATA_CTLF_PMULT_FBS;
		}
	}

	/* Report the number of command slots */
	sata_hba_tran->sata_tran_hba_qdepth = ahci_ctlp->ahcictl_num_cmd_slots;

	sata_hba_tran->sata_tran_probe_port = ahci_tran_probe_port;
	sata_hba_tran->sata_tran_start = ahci_tran_start;
	sata_hba_tran->sata_tran_abort = ahci_tran_abort;
	sata_hba_tran->sata_tran_reset_dport = ahci_tran_reset_dport;
	sata_hba_tran->sata_tran_hotplug_ops = &ahci_tran_hotplug_ops;
#ifdef __lock_lint
	sata_hba_tran->sata_tran_selftest = ahci_selftest;
#endif
	/*
	 * When SATA framework adds support for pwrmgt the
	 * pwrmgt_ops needs to be updated
	 */
	sata_hba_tran->sata_tran_pwrmgt_ops = NULL;
	sata_hba_tran->sata_tran_ioctl = NULL;

	ahci_ctlp->ahcictl_sata_hba_tran = sata_hba_tran;

	mutex_exit(&ahci_ctlp->ahcictl_mutex);

	/* Attach it to SATA framework */
	if (sata_hba_attach(ahci_ctlp->ahcictl_dip, sata_hba_tran, DDI_ATTACH)
	    != DDI_SUCCESS) {
		kmem_free((void *)sata_hba_tran, sizeof (sata_hba_tran_t));
		mutex_enter(&ahci_ctlp->ahcictl_mutex);
		ahci_ctlp->ahcictl_sata_hba_tran = NULL;
		mutex_exit(&ahci_ctlp->ahcictl_mutex);
		return (AHCI_FAILURE);
	}

	return (AHCI_SUCCESS);
}

/*
 * Unregisters the ahci with sata framework.
 */
static int
ahci_unregister_sata_hba_tran(ahci_ctl_t *ahci_ctlp)
{
	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_unregister_sata_hba_tran enter", NULL);

	/* Detach from the SATA framework. */
	if (sata_hba_detach(ahci_ctlp->ahcictl_dip, DDI_DETACH) !=
	    DDI_SUCCESS) {
		return (AHCI_FAILURE);
	}

	/* Deallocate sata_hba_tran. */
	kmem_free((void *)ahci_ctlp->ahcictl_sata_hba_tran,
	    sizeof (sata_hba_tran_t));

	mutex_enter(&ahci_ctlp->ahcictl_mutex);
	ahci_ctlp->ahcictl_sata_hba_tran = NULL;
	mutex_exit(&ahci_ctlp->ahcictl_mutex);

	return (AHCI_SUCCESS);
}

#define	SET_PORTSTR(str, addrp)						\
	if (AHCI_ADDR_IS_PORT(addrp))					\
		(void) sprintf((str), "%d", (addrp)->aa_port);		\
	else if (AHCI_ADDR_IS_PMULT(addrp))				\
		(void) sprintf((str), "%d (pmult)", (addrp)->aa_port);	\
	else								\
		(void) sprintf((str), "%d:%d", (addrp)->aa_port,	\
		    (addrp)->aa_pmport);

/*
 * ahci_tran_probe_port is called by SATA framework. It returns port state,
 * port status registers and an attached device type via sata_device
 * structure.
 *
 * We return the cached information from a previous hardware probe. The
 * actual hardware probing itself was done either from within
 * ahci_initialize_controller() during the driver attach or from a phy
 * ready change interrupt handler.
 */
static int
ahci_tran_probe_port(dev_info_t *dip, sata_device_t *sd)
{
	ahci_ctl_t *ahci_ctlp;
	ahci_port_t *ahci_portp;
	ahci_addr_t addr, pmult_addr;
	uint8_t cport = sd->satadev_addr.cport;
	char portstr[10];
	uint8_t device_type;
	uint32_t port_state;
	uint8_t port;
	int rval = SATA_SUCCESS, rval_init;

	ahci_ctlp = ddi_get_soft_state(ahci_statep, ddi_get_instance(dip));
	port = ahci_ctlp->ahcictl_cport_to_port[cport];

	ahci_portp = ahci_ctlp->ahcictl_ports[port];

	mutex_enter(&ahci_portp->ahciport_mutex);

	ahci_get_ahci_addr(ahci_ctlp, sd, &addr);
	ASSERT(AHCI_ADDR_IS_VALID(&addr));
	SET_PORTSTR(portstr, &addr);

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_tran_probe_port enter: port %s", portstr);

	if ((AHCI_ADDR_IS_PMULT(&addr) || AHCI_ADDR_IS_PMPORT(&addr)) &&
	    (ahci_portp->ahciport_device_type != SATA_DTYPE_PMULT ||
	    ahci_portp->ahciport_pmult_info == NULL)) {
		/* port mutliplier is removed. */
		AHCIDBG(AHCIDBG_PMULT, ahci_ctlp,
		    "ahci_tran_probe_port: "
		    "pmult is removed from port %s", portstr);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_FAILURE);
	}

	/*
	 * The sata_device may refer to
	 * 1. A controller port.
	 *    A controller port should be ready here.
	 * 2. A port multiplier.
	 *    SATA_ADDR_PMULT_SPEC - if it is not initialized yet, initialize
	 *    it and register the port multiplier to the framework.
	 *    SATA_ADDR_PMULT - check the status of all its device ports.
	 * 3. A port multiplier port.
	 *    If it has not been initialized, initialized it.
	 *
	 * A port multiplier or a port multiplier port may require some
	 * initialization because we cannot do these time-consuming jobs in an
	 * interrupt context.
	 */
	if (sd->satadev_addr.qual & SATA_ADDR_PMULT_SPEC) {
		AHCI_ADDR_SET_PMULT(&pmult_addr, port);
		/* Initialize registers on a port multiplier */
		rval_init = ahci_initialize_pmult(ahci_ctlp,
		    ahci_portp, &pmult_addr, sd);
		if (rval_init != AHCI_SUCCESS) {
			AHCIDBG(AHCIDBG_PMULT, ahci_ctlp,
			    "ahci_tran_probe_port: "
			    "pmult initialization failed.", NULL);
			mutex_exit(&ahci_portp->ahciport_mutex);
			return (SATA_FAILURE);
		}
	} else if (sd->satadev_addr.qual & SATA_ADDR_PMULT) {
		/* Check pmports hotplug events */
		(void) ahci_probe_pmult(ahci_ctlp, ahci_portp, &addr);
	} else if (sd->satadev_addr.qual & (SATA_ADDR_PMPORT |
	    SATA_ADDR_DPMPORT)) {
		if (ahci_probe_pmport(ahci_ctlp, ahci_portp,
		    &addr, sd) != AHCI_SUCCESS) {
			rval = SATA_FAILURE;
			goto out;
		}
	}

	/* Update port state and device type */
	port_state = AHCIPORT_GET_STATE(ahci_portp, &addr);

	switch (port_state) {

	case SATA_PSTATE_FAILED:
		sd->satadev_state = SATA_PSTATE_FAILED;
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_probe_port: port %s PORT FAILED", portstr);
		goto out;

	case SATA_PSTATE_SHUTDOWN:
		sd->satadev_state = SATA_PSTATE_SHUTDOWN;
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_probe_port: port %s PORT SHUTDOWN", portstr);
		goto out;

	case SATA_PSTATE_PWROFF:
		sd->satadev_state = SATA_PSTATE_PWROFF;
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_probe_port: port %s PORT PWROFF", portstr);
		goto out;

	case SATA_PSTATE_PWRON:
		sd->satadev_state = SATA_PSTATE_PWRON;
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port: port %s PORT PWRON", portstr);
		break;

	default:
		sd->satadev_state = port_state;
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port: port %s PORT NORMAL %x",
		    portstr, port_state);
		break;
	}

	device_type = AHCIPORT_GET_DEV_TYPE(ahci_portp, &addr);

	switch (device_type) {

	case SATA_DTYPE_ATADISK:
		sd->satadev_type = SATA_DTYPE_ATADISK;
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port: port %s DISK found", portstr);
		break;

	case SATA_DTYPE_ATAPI:
		/*
		 * HBA driver only knows it's an ATAPI device, and don't know
		 * it's CD/DVD, tape or ATAPI disk because the ATAPI device
		 * type need to be determined by checking IDENTIFY PACKET
		 * DEVICE data
		 */
		sd->satadev_type = SATA_DTYPE_ATAPI;
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port: port %s ATAPI found", portstr);
		break;

	case SATA_DTYPE_PMULT:
		ASSERT(AHCI_ADDR_IS_PORT(&addr) || AHCI_ADDR_IS_PMULT(&addr));
		sd->satadev_type = SATA_DTYPE_PMULT;

		/* Update the number of pmports. */
		ASSERT(ahci_portp->ahciport_pmult_info != NULL);
		sd->satadev_add_info = ahci_portp->
		    ahciport_pmult_info->ahcipmi_num_dev_ports;

		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port: port %s Port Multiplier found",
		    portstr);
		break;

	case SATA_DTYPE_UNKNOWN:
		sd->satadev_type = SATA_DTYPE_UNKNOWN;
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port: port %s Unknown device found",
		    portstr);
		break;

	default:
		/* we don't support any other device types */
		sd->satadev_type = SATA_DTYPE_NONE;
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port: port %s No device found", portstr);
		break;
	}

out:
	/* Register update only fails while probing a pmult/pmport */
	if (AHCI_ADDR_IS_PORT(&addr) || AHCI_ADDR_IS_PMULT(&addr)) {
		ahci_update_sata_registers(ahci_ctlp, port, sd);
	} else if (AHCI_ADDR_IS_PMPORT(&addr)) {
		if (port_state & SATA_STATE_READY)
			if (ahci_update_pmult_pscr(ahci_ctlp,
			    &addr, sd) != AHCI_SUCCESS)
				rval = SATA_FAILURE;
	}

	/* Check handles for the sata registers access */
	if ((ahci_check_ctl_handle(ahci_ctlp) != DDI_SUCCESS) ||
	    (ahci_check_port_handle(ahci_ctlp, port) != DDI_SUCCESS)) {
		ddi_fm_service_impact(ahci_ctlp->ahcictl_dip,
		    DDI_SERVICE_UNAFFECTED);
		rval = SATA_FAILURE;
	}

	mutex_exit(&ahci_portp->ahciport_mutex);
	return (rval);
}

/*
 * There are four operation modes in sata framework:
 * SATA_OPMODE_INTERRUPTS
 * SATA_OPMODE_POLLING
 * SATA_OPMODE_ASYNCH
 * SATA_OPMODE_SYNCH
 *
 * Their combined meanings as following:
 *
 * SATA_OPMODE_SYNCH
 * The command has to be completed before sata_tran_start functions returns.
 * Either interrupts or polling could be used - it's up to the driver.
 * Mode used currently for internal, sata-module initiated operations.
 *
 * SATA_OPMODE_SYNCH | SATA_OPMODE_INTERRUPTS
 * It is the same as the one above.
 *
 * SATA_OPMODE_SYNCH | SATA_OPMODE_POLLING
 * The command has to be completed before sata_tran_start function returns.
 * No interrupt used, polling only. This should be the mode used for scsi
 * packets with FLAG_NOINTR.
 *
 * SATA_OPMODE_ASYNCH | SATA_OPMODE_INTERRUPTS
 * The command may be queued (callback function specified). Interrupts could
 * be used. It's normal operation mode.
 */
/*
 * Called by sata framework to transport a sata packet down stream.
 */
static int
ahci_tran_start(dev_info_t *dip, sata_pkt_t *spkt)
{
	ahci_ctl_t *ahci_ctlp;
	ahci_port_t *ahci_portp;
	ahci_addr_t addr;
	uint8_t	cport = spkt->satapkt_device.satadev_addr.cport;
	uint8_t port;
	char portstr[10];

	ahci_ctlp = ddi_get_soft_state(ahci_statep, ddi_get_instance(dip));
	port = ahci_ctlp->ahcictl_cport_to_port[cport];

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_tran_start enter: cport %d satapkt 0x%p",
	    cport, (void *)spkt);

	ahci_portp = ahci_ctlp->ahcictl_ports[port];

	mutex_enter(&ahci_portp->ahciport_mutex);
	ahci_get_ahci_addr(ahci_ctlp, &spkt->satapkt_device, &addr);
	SET_PORTSTR(portstr, &addr);

	/* Sanity check */
	if (AHCI_ADDR_IS_PMPORT(&addr)) {
		if (ahci_portp->ahciport_device_type != SATA_DTYPE_PMULT ||
		    ahci_portp->ahciport_pmult_info == NULL) {

			spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
			spkt->satapkt_device.satadev_type = SATA_DTYPE_NONE;
			spkt->satapkt_device.satadev_state = SATA_STATE_UNKNOWN;
			ahci_update_sata_registers(ahci_ctlp, port,
			    &spkt->satapkt_device);
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_tran_start returning PORT_ERROR while "
			    "pmult removed: port: %s", portstr);
			mutex_exit(&ahci_portp->ahciport_mutex);
			return (SATA_TRAN_PORT_ERROR);
		}

		if (!(AHCIPORT_GET_STATE(ahci_portp, &addr) &
		    SATA_STATE_READY)) {
			if (!ddi_in_panic() ||
			    ahci_initialize_pmport(ahci_ctlp,
			    ahci_portp, &addr) != AHCI_SUCCESS) {
				spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
				spkt->satapkt_device.satadev_type =
				    AHCIPORT_GET_DEV_TYPE(ahci_portp, &addr);
				spkt->satapkt_device.satadev_state =
				    AHCIPORT_GET_STATE(ahci_portp, &addr);
				ahci_update_sata_registers(ahci_ctlp, port,
				    &spkt->satapkt_device);
				AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
				    "ahci_tran_start returning PORT_ERROR "
				    "while sub-link is not initialized "
				    "at port: %s", portstr);
				mutex_exit(&ahci_portp->ahciport_mutex);
				return (SATA_TRAN_PORT_ERROR);
			}
		}
	}

	if (AHCIPORT_GET_STATE(ahci_portp, &addr) & SATA_PSTATE_FAILED ||
	    AHCIPORT_GET_STATE(ahci_portp, &addr) & SATA_PSTATE_SHUTDOWN||
	    AHCIPORT_GET_STATE(ahci_portp, &addr) & SATA_PSTATE_PWROFF) {
		/*
		 * In case the target driver would send the packet before
		 * sata framework can have the opportunity to process those
		 * event reports.
		 */
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		spkt->satapkt_device.satadev_state =
		    ahci_portp->ahciport_port_state;
		ahci_update_sata_registers(ahci_ctlp, port,
		    &spkt->satapkt_device);
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start returning PORT_ERROR while "
		    "port in FAILED/SHUTDOWN/PWROFF state: "
		    "port: %s", portstr);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_PORT_ERROR);
	}

	if (AHCIPORT_GET_DEV_TYPE(ahci_portp, &addr) == SATA_DTYPE_NONE) {
		/*
		 * ahci_intr_phyrdy_change() may have rendered it to
		 * SATA_DTYPE_NONE.
		 */
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		spkt->satapkt_device.satadev_type = SATA_DTYPE_NONE;
		spkt->satapkt_device.satadev_state =
		    ahci_portp->ahciport_port_state;
		ahci_update_sata_registers(ahci_ctlp, port,
		    &spkt->satapkt_device);
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start returning PORT_ERROR while "
		    "no device attached: port: %s", portstr);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_PORT_ERROR);
	}

	/* R/W PMULT command will occupy the whole HBA port */
	if (RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp)) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start returning BUSY while "
		    "executing READ/WRITE PORT-MULT command: "
		    "port: %s", portstr);
		spkt->satapkt_reason = SATA_PKT_BUSY;
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_BUSY);
	}

	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_HOTPLUG) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start returning BUSY while "
		    "hot-plug in progress: port: %s", portstr);
		spkt->satapkt_reason = SATA_PKT_BUSY;
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_BUSY);
	}

	/*
	 * SATA HBA driver should remember that a device was reset and it
	 * is supposed to reject any packets which do not specify either
	 * SATA_IGNORE_DEV_RESET_STATE or SATA_CLEAR_DEV_RESET_STATE.
	 *
	 * This is to prevent a race condition when a device was arbitrarily
	 * reset by the HBA driver (and lost it's setting) and a target
	 * driver sending some commands to a device before the sata framework
	 * has a chance to restore the device setting (such as cache enable/
	 * disable or other resettable stuff).
	 */
	/*
	 * It is unnecessary to use specific flags to indicate
	 * reset_in_progress for a pmport. While mopping, all command will be
	 * mopped so that the entire HBA port is being dealt as a single
	 * object.
	 */
	if (spkt->satapkt_cmd.satacmd_flags.sata_clear_dev_reset) {
		ahci_portp->ahciport_reset_in_progress = 0;
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start [CLEAR] the "
		    "reset_in_progress for port: %d", port);
	}

	if (ahci_portp->ahciport_reset_in_progress &&
	    ! spkt->satapkt_cmd.satacmd_flags.sata_ignore_dev_reset &&
	    ! ddi_in_panic()) {
		spkt->satapkt_reason = SATA_PKT_BUSY;
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start returning BUSY while "
		    "reset in progress: port: %d", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_BUSY);
	}

#ifdef AHCI_DEBUG
	if (spkt->satapkt_cmd.satacmd_flags.sata_ignore_dev_reset) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start: packet 0x%p [PASSTHRU] at port %d",
		    spkt, port);
	}
#endif

	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_MOPPING) {
		spkt->satapkt_reason = SATA_PKT_BUSY;
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start returning BUSY while "
		    "mopping in progress: port: %d", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_BUSY);
	}

	if (ahci_check_ctl_handle(ahci_ctlp) != DDI_SUCCESS) {
		ddi_fm_service_impact(ahci_ctlp->ahcictl_dip,
		    DDI_SERVICE_UNAFFECTED);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_BUSY);
	}

	if (spkt->satapkt_op_mode &
	    (SATA_OPMODE_SYNCH | SATA_OPMODE_POLLING)) {
		/*
		 * If a SYNC command to be executed in interrupt context,
		 * bounce it back to sata module.
		 */
		if (!(spkt->satapkt_op_mode & SATA_OPMODE_POLLING) &&
		    servicing_interrupt()) {
			spkt->satapkt_reason = SATA_PKT_BUSY;
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_tran_start returning BUSY while "
			    "sending SYNC mode under interrupt context: "
			    "port : %d", port);
			mutex_exit(&ahci_portp->ahciport_mutex);
			return (SATA_TRAN_BUSY);
		}

		/* We need to do the sync start now */
		if (ahci_do_sync_start(ahci_ctlp, ahci_portp, &addr,
		    spkt) == AHCI_FAILURE) {
			goto fail_out;
		}
	} else {
		/* Async start, using interrupt */
		if (ahci_deliver_satapkt(ahci_ctlp, ahci_portp, &addr, spkt)
		    == AHCI_FAILURE) {
			spkt->satapkt_reason = SATA_PKT_QUEUE_FULL;
			goto fail_out;
		}
	}

	AHCIDBG(AHCIDBG_INFO, ahci_ctlp, "ahci_tran_start "
	    "sata tran accepted: port %s", portstr);

	mutex_exit(&ahci_portp->ahciport_mutex);
	return (SATA_TRAN_ACCEPTED);

fail_out:
	/*
	 * Failed to deliver packet to the controller.
	 * Check if it's caused by invalid handles.
	 */
	if (ahci_check_ctl_handle(ahci_ctlp) != DDI_SUCCESS ||
	    ahci_check_port_handle(ahci_ctlp, port) != DDI_SUCCESS) {
		spkt->satapkt_device.satadev_type =
		    AHCIPORT_GET_DEV_TYPE(ahci_portp, &addr);
		spkt->satapkt_device.satadev_state =
		    AHCIPORT_GET_STATE(ahci_portp, &addr);
		spkt->satapkt_reason = SATA_PKT_DEV_ERROR;
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_PORT_ERROR);
	}

	AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_tran_start "
	    "return QUEUE_FULL: port %d", port);
	mutex_exit(&ahci_portp->ahciport_mutex);
	return (SATA_TRAN_QUEUE_FULL);
}

/*
 * SATA_OPMODE_SYNCH flag is set
 *
 * If SATA_OPMODE_POLLING flag is set, then we must poll the command
 * without interrupt, otherwise we can still use the interrupt.
 */
static int
ahci_do_sync_start(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    ahci_addr_t *addrp, sata_pkt_t *spkt)
{
	int pkt_timeout_ticks;
	uint32_t timeout_tags;
	int rval;
	int instance = ddi_get_instance(ahci_ctlp->ahcictl_dip);
	uint8_t port = addrp->aa_port;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp, "ahci_do_sync_start enter: "
	    "port %d:%d spkt 0x%p", port, addrp->aa_pmport, spkt);

	if (spkt->satapkt_op_mode & SATA_OPMODE_POLLING) {
		ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_POLLING;
		if ((rval = ahci_deliver_satapkt(ahci_ctlp, ahci_portp,
		    addrp, spkt)) == AHCI_FAILURE) {
			ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_POLLING;
			return (rval);
		}

		pkt_timeout_ticks =
		    drv_usectohz((clock_t)spkt->satapkt_time * 1000000);

		while (spkt->satapkt_reason == SATA_PKT_BUSY) {
			/* Simulate the interrupt */
			mutex_exit(&ahci_portp->ahciport_mutex);
			ahci_port_intr(ahci_ctlp, ahci_portp, port);
			mutex_enter(&ahci_portp->ahciport_mutex);

			if (spkt->satapkt_reason != SATA_PKT_BUSY)
				break;

			mutex_exit(&ahci_portp->ahciport_mutex);
			drv_usecwait(AHCI_1MS_USECS);
			mutex_enter(&ahci_portp->ahciport_mutex);

			pkt_timeout_ticks -= AHCI_1MS_TICKS;
			if (pkt_timeout_ticks < 0) {
				cmn_err(CE_WARN, "!ahci%d: ahci_do_sync_start "
				    "port %d satapkt 0x%p timed out\n",
				    instance, port, (void *)spkt);
				timeout_tags = (0x1 << rval);
				mutex_exit(&ahci_portp->ahciport_mutex);
				ahci_timeout_pkts(ahci_ctlp, ahci_portp,
				    port, timeout_tags);
				mutex_enter(&ahci_portp->ahciport_mutex);
			}
		}

		ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_POLLING;
		return (AHCI_SUCCESS);

	} else {
		if ((rval = ahci_deliver_satapkt(ahci_ctlp, ahci_portp,
		    addrp, spkt)) == AHCI_FAILURE)
			return (rval);

#if AHCI_DEBUG
		/*
		 * Note that the driver always uses the slot 0 to deliver
		 * REQUEST SENSE or READ LOG EXT command
		 */
		if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp))
			ASSERT(rval == 0);
#endif

		while (spkt->satapkt_reason == SATA_PKT_BUSY)
			cv_wait(&ahci_portp->ahciport_cv,
			    &ahci_portp->ahciport_mutex);

		return (AHCI_SUCCESS);
	}
}

/*
 * Searches for and claims a free command slot.
 *
 * Returns value:
 *
 * AHCI_FAILURE returned only if
 *	1. No empty slot left
 *	2. Non-queued command requested while queued command(s) is outstanding
 *	3. Queued command requested while non-queued command(s) is outstanding
 *	4. HBA doesn't support multiple-use of command list while already a
 *	   non-queued command is oustanding
 *	5. Queued command requested while some queued command(s) has been
 *	   outstanding on a different port multiplier port. (AHCI spec 1.2,
 *	   9.1.2)
 *
 * claimed slot number returned if succeeded
 *
 * NOTE: it will always return slot 0 for following commands to simplify the
 * algorithm.
 * 	1. REQUEST SENSE or READ LOG EXT command during error recovery process
 * 	2. READ/WRITE PORTMULT command
 */
static int
ahci_claim_free_slot(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    ahci_addr_t *addrp, int command_type)
{
	uint32_t port_cmd_issue;
	uint32_t free_slots;
	int slot;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp, "ahci_claim_free_slot enter "
	    "ahciport_pending_tags = 0x%x "
	    "ahciport_pending_ncq_tags = 0x%x",
	    ahci_portp->ahciport_pending_tags,
	    ahci_portp->ahciport_pending_ncq_tags);

	/*
	 * According to the AHCI spec, system software is responsible to
	 * ensure that queued and non-queued commands are not mixed in
	 * the command list.
	 */
	if (command_type == AHCI_NON_NCQ_CMD) {
		/* Non-NCQ command request */
		if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
			AHCIDBG(AHCIDBG_INFO|AHCIDBG_NCQ, ahci_ctlp,
			    "ahci_claim_free_slot: there is still pending "
			    "queued command(s) in the command list, "
			    "so no available slot for the non-queued "
			    "command", NULL);
			return (AHCI_FAILURE);
		}
		if (RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp)) {
			AHCIDBG(AHCIDBG_INFO|AHCIDBG_PMULT, ahci_ctlp,
			    "ahci_claim_free_slot: there is still pending "
			    "read/write port-mult command(s) in command list, "
			    "so no available slot for the non-queued command",
			    NULL);
			return (AHCI_FAILURE);
		}
		if ((ahci_ctlp->ahcictl_cap & AHCI_CAP_NO_MCMDLIST_NONQUEUE) &&
		    NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
			AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
			    "ahci_claim_free_slot: HBA cannot support multiple-"
			    "use of the command list for non-queued commands",
			    NULL);
			return (AHCI_FAILURE);
		}
		free_slots = (~ahci_portp->ahciport_pending_tags) &
		    AHCI_SLOT_MASK(ahci_ctlp);
	} else if (command_type == AHCI_NCQ_CMD) {
		/* NCQ command request */
		if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
			AHCIDBG(AHCIDBG_INFO|AHCIDBG_NCQ, ahci_ctlp,
			    "ahci_claim_free_slot: there is still pending "
			    "non-queued command(s) in the command list, "
			    "so no available slot for the queued command",
			    NULL);
			return (AHCI_FAILURE);
		}

		/*
		 * NCQ commands cannot be sent to different port multiplier
		 * ports in Command-Based Switching mode
		 */
		/*
		 * NOTE: In Command-Based Switching mode, AHCI controller
		 * usually reports a 'Handshake Error' when multiple NCQ
		 * commands are outstanding simultaneously.
		 */
		if (AHCIPORT_DEV_TYPE(ahci_portp, addrp) == SATA_DTYPE_PMULT) {
			ASSERT(ahci_portp->ahciport_pmult_info != NULL);
			if (!(ahci_ctlp->ahcictl_cap & AHCI_CAP_PMULT_FBSS) &&
			    NCQ_CMD_IN_PROGRESS(ahci_portp) &&
			    AHCIPORT_NCQ_PMPORT(ahci_portp) !=
			    addrp->aa_pmport) {
				AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
				    "ahci_claim_free_slot: there is still "
				    "pending queued command(s) in the "
				    "command list for another Port Multiplier "
				    "port, so no available slot.", NULL);
				return (AHCI_FAILURE);
			}
		}

		free_slots = (~ahci_portp->ahciport_pending_ncq_tags) &
		    AHCI_NCQ_SLOT_MASK(ahci_portp);
	} else if (command_type == AHCI_ERR_RETRI_CMD) {
		/* Error retrieval command request */
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_claim_free_slot: slot 0 is allocated for REQUEST "
		    "SENSE or READ LOG EXT command", NULL);
		slot = 0;
		goto out;
	} else if (command_type == AHCI_RDWR_PMULT_CMD) {
		/*
		 * An extra check on PxCI. Sometimes PxCI bits may not be
		 * cleared during hot-plug or error recovery process.
		 */
		port_cmd_issue = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, addrp->aa_port));

		if (port_cmd_issue != 0) {
			AHCIDBG(AHCIDBG_INFO|AHCIDBG_PMULT, ahci_ctlp,
			    "ahci_claim_free_slot: there is still pending "
			    "command(s) in command list (0x%x/0x%x, PxCI %x),"
			    "so no available slot for R/W PMULT command.",
			    NON_NCQ_CMD_IN_PROGRESS(ahci_portp),
			    NCQ_CMD_IN_PROGRESS(ahci_portp),
			    port_cmd_issue);
			return (AHCI_FAILURE);
		}

		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_claim_free_slot: slot 0 is allocated for "
		    "READ/WRITE PORTMULT command", NULL);
		slot = 0;
		goto out;
	}

	slot = ddi_ffs(free_slots) - 1;
	if (slot == -1) {
		AHCIDBG(AHCIDBG_VERBOSE, ahci_ctlp,
		    "ahci_claim_free_slot: no empty slots", NULL);
		return (AHCI_FAILURE);
	}

	/*
	 * According to the AHCI spec, to allow a simple mechanism for the
	 * HBA to map command list slots to queue entries, software must
	 * match the tag number it uses to the slot it is placing the command
	 * in. For example, if a queued command is placed in slot 5, the tag
	 * for that command must be 5.
	 */
	if (command_type == AHCI_NCQ_CMD) {
		ahci_portp->ahciport_pending_ncq_tags |= (0x1 << slot);
		if (AHCI_ADDR_IS_PMPORT(addrp)) {
			ASSERT(ahci_portp->ahciport_pmult_info != NULL);
			AHCIPORT_NCQ_PMPORT(ahci_portp) = addrp->aa_pmport;
		}
	}

	ahci_portp->ahciport_pending_tags |= (0x1 << slot);

out:
	AHCIDBG(AHCIDBG_VERBOSE, ahci_ctlp,
	    "ahci_claim_free_slot: found slot: 0x%x", slot);

	return (slot);
}

/*
 * Builds the Command Table for the sata packet and delivers it to controller.
 *
 * Returns:
 * 	slot number if we can obtain a slot successfully
 *	otherwise, return AHCI_FAILURE
 */
static int
ahci_deliver_satapkt(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    ahci_addr_t *addrp, sata_pkt_t *spkt)
{
	int cmd_slot;
	sata_cmd_t *scmd;
	ahci_fis_h2d_register_t *h2d_register_fisp;
	ahci_cmd_table_t *cmd_table;
	ahci_cmd_header_t *cmd_header;
	int ncookies;
	int i;
	int command_type = AHCI_NON_NCQ_CMD;
	int ncq_qdepth;
	int instance = ddi_get_instance(ahci_ctlp->ahcictl_dip);
	uint8_t port, pmport;
#if AHCI_DEBUG
	uint32_t *ptr;
	uint8_t *ptr2;
#endif

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	port = addrp->aa_port;
	pmport = addrp->aa_pmport;

	spkt->satapkt_reason = SATA_PKT_BUSY;

	scmd = &spkt->satapkt_cmd;

	/* Check if the command is a NCQ command */
	if (scmd->satacmd_cmd_reg == SATAC_READ_FPDMA_QUEUED ||
	    scmd->satacmd_cmd_reg == SATAC_WRITE_FPDMA_QUEUED) {
		command_type = AHCI_NCQ_CMD;

		/*
		 * When NCQ is support, system software must determine the
		 * maximum tag allowed by the device and the HBA, and it
		 * must use a value not beyond of the lower bound of the two.
		 *
		 * Sata module is going to calculate the qdepth and send
		 * down to HBA driver via sata_cmd.
		 */
		ncq_qdepth = scmd->satacmd_flags.sata_max_queue_depth + 1;

		/*
		 * At the moment, the driver doesn't support the dynamic
		 * setting of the maximum ncq depth, and the value can be
		 * set either during the attach or after hot-plug insertion.
		 */
		if (ahci_portp->ahciport_max_ncq_tags == 0) {
			ahci_portp->ahciport_max_ncq_tags = ncq_qdepth;
			AHCIDBG(AHCIDBG_NCQ, ahci_ctlp,
			    "ahci_deliver_satapkt: port %d the max tags for "
			    "NCQ command is %d", port, ncq_qdepth);
		} else {
			if (ncq_qdepth != ahci_portp->ahciport_max_ncq_tags) {
				cmn_err(CE_WARN, "!ahci%d: ahci_deliver_satapkt"
				    " port %d the max tag for NCQ command is "
				    "requested to change from %d to %d, at the"
				    " moment the driver doesn't support the "
				    "dynamic change so it's going to "
				    "still use the previous tag value",
				    instance, port,
				    ahci_portp->ahciport_max_ncq_tags,
				    ncq_qdepth);
			}
		}
	}

	/* Check if the command is an error retrieval command */
	if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp))
		command_type = AHCI_ERR_RETRI_CMD;

	/* Check if the command is an read/write pmult command */
	if (RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp))
		command_type = AHCI_RDWR_PMULT_CMD;

	/* Check if there is an empty command slot */
	cmd_slot = ahci_claim_free_slot(ahci_ctlp, ahci_portp,
	    addrp, command_type);
	if (cmd_slot == AHCI_FAILURE) {
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp, "no free command slot", NULL);
		return (AHCI_FAILURE);
	}

	AHCIDBG(AHCIDBG_ENTRY|AHCIDBG_INFO, ahci_ctlp,
	    "ahci_deliver_satapkt enter: cmd_reg: 0x%x, cmd_slot: 0x%x, "
	    "port: %d, satapkt: 0x%p", scmd->satacmd_cmd_reg,
	    cmd_slot, port, (void *)spkt);

	cmd_table = ahci_portp->ahciport_cmd_tables[cmd_slot];
	bzero((void *)cmd_table, ahci_cmd_table_size);

	/* For data transfer operations, it is the H2D Register FIS */
	h2d_register_fisp =
	    &(cmd_table->ahcict_command_fis.ahcifc_fis.ahcifc_h2d_register);

	SET_FIS_TYPE(h2d_register_fisp, AHCI_H2D_REGISTER_FIS_TYPE);

	/*
	 * PMP field only make sense when target is a port multiplier or a
	 * device behind a port multiplier. Otherwise should set it to 0.
	 */
	if (AHCI_ADDR_IS_PMULT(addrp) || AHCI_ADDR_IS_PMPORT(addrp))
		SET_FIS_PMP(h2d_register_fisp, pmport);

	SET_FIS_CDMDEVCTL(h2d_register_fisp, 1);
	SET_FIS_COMMAND(h2d_register_fisp, scmd->satacmd_cmd_reg);
	SET_FIS_FEATURES(h2d_register_fisp, scmd->satacmd_features_reg);
	SET_FIS_SECTOR_COUNT(h2d_register_fisp, scmd->satacmd_sec_count_lsb);

	switch (scmd->satacmd_addr_type) {

	case 0:
		/*
		 * satacmd_addr_type will be 0 for the commands below:
		 * 	ATAPI command
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
		SET_FIS_SECTOR(h2d_register_fisp, scmd->satacmd_lba_low_lsb);

		/* LBA[15:8] */
		SET_FIS_CYL_LOW(h2d_register_fisp, scmd->satacmd_lba_mid_lsb);

		/* LBA[23:16] */
		SET_FIS_CYL_HI(h2d_register_fisp, scmd->satacmd_lba_high_lsb);

		/* LBA [27:24] (also called dev_head) */
		SET_FIS_DEV_HEAD(h2d_register_fisp, scmd->satacmd_device_reg);

		break;

	case ATA_ADDR_LBA48:
		/* LBA[7:0] */
		SET_FIS_SECTOR(h2d_register_fisp, scmd->satacmd_lba_low_lsb);

		/* LBA[15:8] */
		SET_FIS_CYL_LOW(h2d_register_fisp, scmd->satacmd_lba_mid_lsb);

		/* LBA[23:16] */
		SET_FIS_CYL_HI(h2d_register_fisp, scmd->satacmd_lba_high_lsb);

		/* LBA [31:24] */
		SET_FIS_SECTOR_EXP(h2d_register_fisp,
		    scmd->satacmd_lba_low_msb);

		/* LBA [39:32] */
		SET_FIS_CYL_LOW_EXP(h2d_register_fisp,
		    scmd->satacmd_lba_mid_msb);

		/* LBA [47:40] */
		SET_FIS_CYL_HI_EXP(h2d_register_fisp,
		    scmd->satacmd_lba_high_msb);

		/* Set dev_head */
		SET_FIS_DEV_HEAD(h2d_register_fisp,
		    scmd->satacmd_device_reg);

		/* Set the extended sector count and features */
		SET_FIS_SECTOR_COUNT_EXP(h2d_register_fisp,
		    scmd->satacmd_sec_count_msb);
		SET_FIS_FEATURES_EXP(h2d_register_fisp,
		    scmd->satacmd_features_reg_ext);
		break;
	}

	/*
	 * For NCQ command (READ/WRITE FPDMA QUEUED), sector count 7:0 is
	 * filled into features field, and sector count 8:15 is filled into
	 * features (exp) field. The hba driver doesn't need to anything
	 * special with regard to this, since sata framework has already
	 * done so.
	 *
	 * However the driver needs to make sure TAG is filled into sector
	 * field.
	 */
	if (command_type == AHCI_NCQ_CMD) {
		SET_FIS_SECTOR_COUNT(h2d_register_fisp,
		    (cmd_slot << SATA_TAG_QUEUING_SHIFT));
	}

	ncookies = scmd->satacmd_num_dma_cookies;
	AHCIDBG(AHCIDBG_PRDT, ahci_ctlp,
	    "ncookies = 0x%x, ahci_dma_prdt_number = 0x%x",
	    ncookies, ahci_dma_prdt_number);

	ASSERT(ncookies <= ahci_dma_prdt_number);
	ahci_portp->ahciport_prd_bytecounts[cmd_slot] = 0;

	/* *** now fill the scatter gather list ******* */
	for (i = 0; i < ncookies; i++) {
		cmd_table->ahcict_prdt[i].ahcipi_data_base_addr =
		    scmd->satacmd_dma_cookie_list[i]._dmu._dmac_la[0];
		cmd_table->ahcict_prdt[i].ahcipi_data_base_addr_upper =
		    scmd->satacmd_dma_cookie_list[i]._dmu._dmac_la[1];
		cmd_table->ahcict_prdt[i].ahcipi_descr_info =
		    scmd->satacmd_dma_cookie_list[i].dmac_size - 1;
		ahci_portp->ahciport_prd_bytecounts[cmd_slot] +=
		    scmd->satacmd_dma_cookie_list[i].dmac_size;
	}

	AHCIDBG(AHCIDBG_PRDT, ahci_ctlp,
	    "ahciport_prd_bytecounts 0x%x for cmd_slot 0x%x",
	    ahci_portp->ahciport_prd_bytecounts[cmd_slot], cmd_slot);

	/* The ACMD field is filled in for ATAPI command */
	if (scmd->satacmd_cmd_reg == SATAC_PACKET) {
		bcopy(scmd->satacmd_acdb, cmd_table->ahcict_atapi_cmd,
		    SATA_ATAPI_MAX_CDB_LEN);
	}

	/* Set Command Header in Command List */
	cmd_header = &ahci_portp->ahciport_cmd_list[cmd_slot];
	BZERO_DESCR_INFO(cmd_header);
	BZERO_PRD_BYTE_COUNT(cmd_header);

	/* Set the number of entries in the PRD table */
	SET_PRD_TABLE_LENGTH(cmd_header, ncookies);

	/* Set the length of the command in the CFIS area */
	SET_COMMAND_FIS_LENGTH(cmd_header, AHCI_H2D_REGISTER_FIS_LENGTH);

	/*
	 * PMP field only make sense when target is a port multiplier or a
	 * device behind a port multiplier. Otherwise should set it to 0.
	 */
	if (AHCI_ADDR_IS_PMULT(addrp) || AHCI_ADDR_IS_PMPORT(addrp))
		SET_PORT_MULTI_PORT(cmd_header, pmport);

	AHCIDBG(AHCIDBG_INFO, ahci_ctlp, "command data direction is "
	    "sata_data_direction = 0x%x",
	    scmd->satacmd_flags.sata_data_direction);

	/* Set A bit if it is an ATAPI command */
	if (scmd->satacmd_cmd_reg == SATAC_PACKET)
		SET_ATAPI(cmd_header, AHCI_CMDHEAD_ATAPI);

	/* Set W bit if data is going to the device */
	if (scmd->satacmd_flags.sata_data_direction == SATA_DIR_WRITE)
		SET_WRITE(cmd_header, AHCI_CMDHEAD_DATA_WRITE);

	/*
	 * Set the prefetchable bit - this bit is only valid if the PRDTL
	 * field is non-zero or the ATAPI 'A' bit is set in the command
	 * header. This bit cannot be set when using native command
	 * queuing commands or when using FIS-based switching with a Port
	 * multiplier.
	 */
	if (command_type != AHCI_NCQ_CMD)
		SET_PREFETCHABLE(cmd_header, AHCI_CMDHEAD_PREFETCHABLE);

	/*
	 * Now remember the sata packet in ahciport_slot_pkts[].
	 * Error retrieval command and r/w port multiplier command will
	 * be stored specifically for each port.
	 */
	if (!ERR_RETRI_CMD_IN_PROGRESS(ahci_portp) &&
	    !RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp))
		ahci_portp->ahciport_slot_pkts[cmd_slot] = spkt;

	/*
	 * Keep the timeout value
	 */
	ahci_portp->ahciport_slot_timeout[cmd_slot] = spkt->satapkt_time;

	/*
	 * If the intial timout is less than 1 tick, then make it longer by
	 * 1 tick to avoid immediate timeout
	 */
	if (ahci_portp->ahciport_slot_timeout[cmd_slot] <=
	    ahci_watchdog_timeout)
		ahci_portp->ahciport_slot_timeout[cmd_slot] +=
		    ahci_watchdog_timeout;

#if AHCI_DEBUG
	if (ahci_debug_flags & AHCIDBG_ATACMD &&
	    scmd->satacmd_cmd_reg != SATAC_PACKET ||
	    ahci_debug_flags & AHCIDBG_ATAPICMD &&
	    scmd->satacmd_cmd_reg == SATAC_PACKET) {

		/* Dump the command header and table */
		ahci_log(ahci_ctlp, CE_WARN, "\n");
		ahci_log(ahci_ctlp, CE_WARN, "Command header&table for spkt "
		    "0x%p cmd_reg 0x%x port %d", spkt,
		    scmd->satacmd_cmd_reg, port);
		ptr = (uint32_t *)cmd_header;
		ahci_log(ahci_ctlp, CE_WARN,
		    "  Command Header:%8x %8x %8x %8x",
		    ptr[0], ptr[1], ptr[2], ptr[3]);

		/* Dump the H2D register FIS */
		ptr = (uint32_t *)h2d_register_fisp;
		ahci_log(ahci_ctlp, CE_WARN,
		    "  Command FIS:   %8x %8x %8x %8x",
		    ptr[0], ptr[1], ptr[2], ptr[3]);

		/* Dump the ACMD register FIS */
		ptr2 = (uint8_t *)&(cmd_table->ahcict_atapi_cmd);
		for (i = 0; i < SATA_ATAPI_MAX_CDB_LEN/8; i++)
			if (ahci_debug_flags & AHCIDBG_ATAPICMD)
				ahci_log(ahci_ctlp, CE_WARN,
				    "  ATAPI command: %2x %2x %2x %2x "
				    "%2x %2x %2x %2x",
				    ptr2[8 * i], ptr2[8 * i + 1],
				    ptr2[8 * i + 2], ptr2[8 * i + 3],
				    ptr2[8 * i + 4], ptr2[8 * i + 5],
				    ptr2[8 * i + 6], ptr2[8 * i + 7]);

		/* Dump the PRDT */
		for (i = 0; i < ncookies; i++) {
			ptr = (uint32_t *)&(cmd_table->ahcict_prdt[i]);
			ahci_log(ahci_ctlp, CE_WARN,
			    "  Cookie %d:      %8x %8x %8x %8x",
			    i, ptr[0], ptr[1], ptr[2], ptr[3]);
		}
	}
#endif

	(void) ddi_dma_sync(
	    ahci_portp->ahciport_cmd_tables_dma_handle[cmd_slot],
	    0,
	    ahci_cmd_table_size,
	    DDI_DMA_SYNC_FORDEV);

	(void) ddi_dma_sync(ahci_portp->ahciport_cmd_list_dma_handle,
	    cmd_slot * sizeof (ahci_cmd_header_t),
	    sizeof (ahci_cmd_header_t),
	    DDI_DMA_SYNC_FORDEV);

	if ((ahci_check_dma_handle(ahci_portp->
	    ahciport_cmd_tables_dma_handle[cmd_slot]) != DDI_FM_OK) ||
	    ahci_check_dma_handle(ahci_portp->
	    ahciport_cmd_list_dma_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ahci_ctlp->ahcictl_dip,
		    DDI_SERVICE_UNAFFECTED);
		return (AHCI_FAILURE);
	}

	/* Set the corresponding bit in the PxSACT.DS for queued command */
	if (command_type == AHCI_NCQ_CMD) {
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port),
		    (0x1 << cmd_slot));
	}

	/* Indicate to the HBA that a command is active. */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port),
	    (0x1 << cmd_slot));

	AHCIDBG(AHCIDBG_INFO, ahci_ctlp, "ahci_deliver_satapkt "
	    "exit: port %d", port);

	/* Make sure the command is started by the PxSACT/PxCI */
	if (ahci_check_acc_handle(ahci_ctlp->
	    ahcictl_ahci_acc_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(ahci_ctlp->ahcictl_dip,
		    DDI_SERVICE_UNAFFECTED);
		return (AHCI_FAILURE);
	}

	return (cmd_slot);
}

/*
 * Called by the sata framework to abort the previously sent packet(s).
 *
 * Reset device to abort commands.
 */
static int
ahci_tran_abort(dev_info_t *dip, sata_pkt_t *spkt, int flag)
{
	ahci_ctl_t *ahci_ctlp;
	ahci_port_t *ahci_portp;
	uint32_t slot_status = 0;
	uint32_t aborted_tags = 0;
	uint32_t finished_tags = 0;
	uint8_t cport = spkt->satapkt_device.satadev_addr.cport;
	uint8_t port;
	int tmp_slot;
	int instance = ddi_get_instance(dip);

	ahci_ctlp = ddi_get_soft_state(ahci_statep, instance);
	port = ahci_ctlp->ahcictl_cport_to_port[cport];

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_tran_abort enter: port %d", port);

	ahci_portp = ahci_ctlp->ahcictl_ports[port];
	mutex_enter(&ahci_portp->ahciport_mutex);

	/*
	 * If AHCI_PORT_FLAG_MOPPING flag is set, it means all the pending
	 * commands are being mopped, therefore there is nothing else to do
	 */
	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_MOPPING) {
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_abort: port %d is in "
		    "mopping process, so just return directly ", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_SUCCESS);
	}

	/*
	 * If AHCI_PORT_FLAG_RDWR_PMULT flag is set, it means a R/W PMULT
	 * command is being executed so no other commands is outstanding,
	 * nothing to do.
	 */
	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_RDWR_PMULT) {
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_abort: port %d is reading/writing "
		    "port multiplier, so just return directly ", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_SUCCESS);
	}

	if (ahci_portp->ahciport_port_state & SATA_PSTATE_FAILED |
	    ahci_portp->ahciport_port_state & SATA_PSTATE_SHUTDOWN |
	    ahci_portp->ahciport_port_state & SATA_PSTATE_PWROFF) {
		/*
		 * In case the targer driver would send the request before
		 * sata framework can have the opportunity to process those
		 * event reports.
		 */
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		spkt->satapkt_device.satadev_state =
		    ahci_portp->ahciport_port_state;
		ahci_update_sata_registers(ahci_ctlp, port,
		    &spkt->satapkt_device);
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_abort returning SATA_FAILURE while "
		    "port in FAILED/SHUTDOWN/PWROFF state: "
		    "port: %d", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_FAILURE);
	}

	if (ahci_portp->ahciport_device_type == SATA_DTYPE_NONE) {
		/*
		 * ahci_intr_phyrdy_change() may have rendered it to
		 * AHCI_PORT_TYPE_NODEV.
		 */
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		spkt->satapkt_device.satadev_type = SATA_DTYPE_NONE;
		spkt->satapkt_device.satadev_state =
		    ahci_portp->ahciport_port_state;
		ahci_update_sata_registers(ahci_ctlp, port,
		    &spkt->satapkt_device);
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_abort returning SATA_FAILURE while "
		    "no device attached: port: %d", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_FAILURE);
	}

	if (flag == SATA_ABORT_ALL_PACKETS) {
		if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp))
			aborted_tags = ahci_portp->ahciport_pending_tags;
		else if (NCQ_CMD_IN_PROGRESS(ahci_portp))
			aborted_tags = ahci_portp->ahciport_pending_ncq_tags;

		cmn_err(CE_NOTE, "!ahci%d: ahci port %d abort all packets",
		    instance, port);
	} else {
		aborted_tags = 0xffffffff;
		/*
		 * Aborting one specific packet, first search the
		 * ahciport_slot_pkts[] list for matching spkt.
		 */
		for (tmp_slot = 0;
		    tmp_slot < ahci_ctlp->ahcictl_num_cmd_slots; tmp_slot++) {
			if (ahci_portp->ahciport_slot_pkts[tmp_slot] == spkt) {
				aborted_tags = (0x1 << tmp_slot);
				break;
			}
		}

		if (aborted_tags == 0xffffffff) {
			/* request packet is not on the pending list */
			AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
			    "Cannot find the aborting pkt 0x%p on the "
			    "pending list", (void *)spkt);
			ahci_update_sata_registers(ahci_ctlp, port,
			    &spkt->satapkt_device);
			mutex_exit(&ahci_portp->ahciport_mutex);
			return (SATA_FAILURE);
		}
		cmn_err(CE_NOTE, "!ahci%d: ahci port %d abort satapkt 0x%p",
		    instance, port, (void *)spkt);
	}

	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp))
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));
	else if (NCQ_CMD_IN_PROGRESS(ahci_portp))
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));

	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_MOPPING;
	ahci_portp->ahciport_mop_in_progress++;

	/*
	 * To abort the packet(s), first we are trying to clear PxCMD.ST
	 * to stop the port, and if the port can be stopped
	 * successfully with PxTFD.STS.BSY and PxTFD.STS.DRQ cleared to '0',
	 * then we just send back the aborted packet(s) with ABORTED flag
	 * and then restart the port by setting PxCMD.ST and PxCMD.FRE.
	 * If PxTFD.STS.BSY or PxTFD.STS.DRQ is set to '1', then we
	 * perform a COMRESET.
	 */
	(void) ahci_restart_port_wait_till_ready(ahci_ctlp,
	    ahci_portp, port, NULL, NULL);

	/*
	 * Compute which have finished and which need to be retried.
	 *
	 * The finished tags are ahciport_pending_tags/ahciport_pending_ncq_tags
	 * minus the slot_status. The aborted_tags has to be deducted by
	 * finished_tags since we can't possibly abort a tag which had finished
	 * already.
	 */
	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp))
		finished_tags = ahci_portp->ahciport_pending_tags &
		    ~slot_status & AHCI_SLOT_MASK(ahci_ctlp);
	else if (NCQ_CMD_IN_PROGRESS(ahci_portp))
		finished_tags = ahci_portp->ahciport_pending_ncq_tags &
		    ~slot_status & AHCI_NCQ_SLOT_MASK(ahci_portp);

	aborted_tags &= ~finished_tags;

	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    slot_status,
	    0, /* failed tags */
	    0, /* timeout tags */
	    aborted_tags,
	    0); /* reset tags */

	ahci_update_sata_registers(ahci_ctlp, port, &spkt->satapkt_device);
	mutex_exit(&ahci_portp->ahciport_mutex);

	return (SATA_SUCCESS);
}

/*
 * Used to do device reset and reject all the pending packets on a device
 * during the reset operation.
 *
 * NOTE: ONLY called by ahci_tran_reset_dport
 */
static int
ahci_reset_device_reject_pkts(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, ahci_addr_t *addrp)
{
	uint32_t slot_status = 0;
	uint32_t reset_tags = 0;
	uint32_t finished_tags = 0;
	uint8_t port = addrp->aa_port;
	sata_device_t sdevice;
	int ret;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_reset_device_reject_pkts on port: %d", port);

	/*
	 * If AHCI_PORT_FLAG_MOPPING flag is set, it means all the pending
	 * commands are being mopped, therefore there is nothing else to do
	 */
	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_MOPPING) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_reset_device_reject_pkts: port %d is in "
		    "mopping process, so return directly ", port);
		return (SATA_SUCCESS);
	}

	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));
		reset_tags = slot_status & AHCI_SLOT_MASK(ahci_ctlp);
	} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));
		reset_tags = slot_status & AHCI_NCQ_SLOT_MASK(ahci_portp);
	}

	if (ahci_software_reset(ahci_ctlp, ahci_portp, addrp)
	    != AHCI_SUCCESS) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "Try to do a port reset after software "
		    "reset failed", port);
		ret = ahci_port_reset(ahci_ctlp, ahci_portp, addrp);
		if (ret != AHCI_SUCCESS) {
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_reset_device_reject_pkts: port %d "
			    "failed", port);
			return (SATA_FAILURE);
		}
	}
	/* Set the reset in progress flag */
	ahci_portp->ahciport_reset_in_progress = 1;

	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_MOPPING;
	ahci_portp->ahciport_mop_in_progress++;

	/* Indicate to the framework that a reset has happened */
	bzero((void *)&sdevice, sizeof (sata_device_t));
	sdevice.satadev_addr.cport = ahci_ctlp->ahcictl_port_to_cport[port];
	sdevice.satadev_addr.pmport = 0;
	sdevice.satadev_addr.qual = SATA_ADDR_DCPORT;
	sdevice.satadev_state = SATA_DSTATE_RESET |
	    SATA_DSTATE_PWR_ACTIVE;
	mutex_exit(&ahci_portp->ahciport_mutex);
	sata_hba_event_notify(
	    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
	    &sdevice,
	    SATA_EVNT_DEVICE_RESET);
	mutex_enter(&ahci_portp->ahciport_mutex);

	AHCIDBG(AHCIDBG_EVENT, ahci_ctlp,
	    "port %d sending event up: SATA_EVNT_DEVICE_RESET", port);

	/* Next try to mop the pending commands */
	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp))
		finished_tags = ahci_portp->ahciport_pending_tags &
		    ~slot_status & AHCI_SLOT_MASK(ahci_ctlp);
	else if (NCQ_CMD_IN_PROGRESS(ahci_portp))
		finished_tags = ahci_portp->ahciport_pending_ncq_tags &
		    ~slot_status & AHCI_NCQ_SLOT_MASK(ahci_portp);

	reset_tags &= ~finished_tags;

	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    slot_status,
	    0, /* failed tags */
	    0, /* timeout tags */
	    0, /* aborted tags */
	    reset_tags); /* reset tags */

	return (SATA_SUCCESS);
}

/*
 * Used to do device reset and reject all the pending packets on a device
 * during the reset operation.
 *
 * NOTE: ONLY called by ahci_tran_reset_dport
 */
static int
ahci_reset_pmdevice_reject_pkts(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, ahci_addr_t *addrp)
{
	uint32_t finished_tags = 0, reset_tags = 0, slot_status = 0;
	uint8_t port = addrp->aa_port;
	uint8_t pmport = addrp->aa_pmport;
	sata_device_t sdevice;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY|AHCIDBG_PMULT, ahci_ctlp,
	    "ahci_reset_pmdevice_reject_pkts at port %d:%d", port, pmport);

	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_MOPPING) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_reset_pmdevice_reject_pkts: port %d is in "
		    "mopping process, so return directly ", port);
		return (SATA_SUCCESS);
	}

	/* Checking for outstanding commands */
	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));
		reset_tags = slot_status & AHCI_SLOT_MASK(ahci_ctlp);
	} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));
		reset_tags = slot_status & AHCI_NCQ_SLOT_MASK(ahci_portp);
	}

	/* Issue SOFTWARE reset command. */
	if (ahci_software_reset(ahci_ctlp, ahci_portp, addrp)
	    != AHCI_SUCCESS) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "Try to do a port reset after software "
		    "reset failed", port);
		return (SATA_FAILURE);
	}

	/* Set the reset in progress flag */
	ahci_portp->ahciport_reset_in_progress = 1;

	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_MOPPING;
	ahci_portp->ahciport_mop_in_progress++;

	/* Indicate to the framework that a reset has happened */
	bzero((void *)&sdevice, sizeof (sata_device_t));
	sdevice.satadev_addr.cport = ahci_ctlp->ahcictl_port_to_cport[port];
	sdevice.satadev_addr.pmport = pmport;
	if (AHCI_ADDR_IS_PMULT(addrp))
		sdevice.satadev_addr.qual = SATA_ADDR_PMULT;
	else
		sdevice.satadev_addr.qual = SATA_ADDR_DPMPORT;
	sdevice.satadev_state = SATA_DSTATE_RESET |
	    SATA_DSTATE_PWR_ACTIVE;
	mutex_exit(&ahci_portp->ahciport_mutex);
	sata_hba_event_notify(
	    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
	    &sdevice,
	    SATA_EVNT_DEVICE_RESET);
	mutex_enter(&ahci_portp->ahciport_mutex);

	AHCIDBG(AHCIDBG_EVENT, ahci_ctlp,
	    "port %d:%d sending event up: SATA_EVNT_DEVICE_RESET",
	    port, pmport);

	/* Next try to mop the pending commands */
	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp))
		finished_tags = ahci_portp->ahciport_pending_tags &
		    ~slot_status & AHCI_SLOT_MASK(ahci_ctlp);
	else if (NCQ_CMD_IN_PROGRESS(ahci_portp))
		finished_tags = ahci_portp->ahciport_pending_ncq_tags &
		    ~slot_status & AHCI_NCQ_SLOT_MASK(ahci_portp);
	reset_tags &= ~finished_tags;

	AHCIDBG(AHCIDBG_EVENT|AHCIDBG_PMULT, ahci_ctlp,
	    "reset_tags = %x, finished_tags = %x, slot_status = %x",
	    reset_tags, finished_tags, slot_status);

	/*
	 * NOTE: Because PxCI be only erased by unset PxCMD.ST bit, so even we
	 * try to reset a single device behind a port multiplier will
	 * terminate all the commands on that HBA port. We need mop these
	 * commands as well.
	 */
	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    slot_status,
	    0, /* failed tags */
	    0, /* timeout tags */
	    0, /* aborted tags */
	    reset_tags); /* reset tags */

	return (SATA_SUCCESS);
}

/*
 * Used to do port reset and reject all the pending packets on a port during
 * the reset operation.
 */
static int
ahci_reset_port_reject_pkts(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, ahci_addr_t *addrp)
{
	uint32_t slot_status = 0;
	uint32_t reset_tags = 0;
	uint32_t finished_tags = 0;
	uint8_t port = addrp->aa_port;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_reset_port_reject_pkts at port: %d", port);

	/*
	 * If AHCI_PORT_FLAG_MOPPING flag is set, it means all the pending
	 * commands are being mopped, therefore there is nothing else to do
	 */
	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_MOPPING) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_reset_port_reject_pkts: port %d is in "
		    "mopping process, so return directly ", port);
		return (SATA_SUCCESS);
	}

	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_MOPPING;
	ahci_portp->ahciport_mop_in_progress++;

	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));
		reset_tags = slot_status & AHCI_SLOT_MASK(ahci_ctlp);
	} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));
		reset_tags = slot_status & AHCI_NCQ_SLOT_MASK(ahci_portp);
	}

	if (ahci_restart_port_wait_till_ready(ahci_ctlp,
	    ahci_portp, port, AHCI_PORT_RESET|AHCI_RESET_NO_EVENTS_UP,
	    NULL) != AHCI_SUCCESS) {

		/* Clear mop flag */
		ahci_portp->ahciport_mop_in_progress--;
		if (ahci_portp->ahciport_mop_in_progress == 0)
			ahci_portp->ahciport_flags &=
			    ~AHCI_PORT_FLAG_MOPPING;
		return (SATA_FAILURE);
	}

	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp))
		finished_tags = ahci_portp->ahciport_pending_tags &
		    ~slot_status & AHCI_SLOT_MASK(ahci_ctlp);
	else if (NCQ_CMD_IN_PROGRESS(ahci_portp))
		finished_tags = ahci_portp->ahciport_pending_ncq_tags &
		    ~slot_status & AHCI_NCQ_SLOT_MASK(ahci_portp);

	reset_tags &= ~finished_tags;

	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    slot_status,
	    0, /* failed tags */
	    0, /* timeout tags */
	    0, /* aborted tags */
	    reset_tags); /* reset tags */

	return (SATA_SUCCESS);
}

/*
 * Used to do hba reset and reject all the pending packets on all ports
 * during the reset operation.
 */
static int
ahci_reset_hba_reject_pkts(ahci_ctl_t *ahci_ctlp)
{
	ahci_port_t *ahci_portp;
	uint32_t slot_status[AHCI_MAX_PORTS];
	uint32_t reset_tags[AHCI_MAX_PORTS];
	uint32_t finished_tags[AHCI_MAX_PORTS];
	int port;
	int ret = SATA_SUCCESS;

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_reset_hba_reject_pkts enter", NULL);

	bzero(slot_status, sizeof (slot_status));
	bzero(reset_tags, sizeof (reset_tags));
	bzero(finished_tags, sizeof (finished_tags));

	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			continue;
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];

		mutex_enter(&ahci_portp->ahciport_mutex);
		ahci_portp->ahciport_reset_in_progress = 1;
		if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
			slot_status[port] = ddi_get32(
			    ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));
			reset_tags[port] = slot_status[port] &
			    AHCI_SLOT_MASK(ahci_ctlp);
			AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
			    "port %d: reset_tags = 0x%x pending_tags = 0x%x",
			    port, reset_tags[port],
			    ahci_portp->ahciport_pending_tags);
		} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
			slot_status[port] = ddi_get32(
			    ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));
			reset_tags[port] = slot_status[port] &
			    AHCI_NCQ_SLOT_MASK(ahci_portp);
			AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
			    "port %d: reset_tags = 0x%x pending_tags = 0x%x",
			    port, reset_tags[port],
			    ahci_portp->ahciport_pending_tags);
		}
		mutex_exit(&ahci_portp->ahciport_mutex);
	}

	if (ahci_hba_reset(ahci_ctlp) != AHCI_SUCCESS) {
		ret = SATA_FAILURE;
	}

	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			continue;
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];

		mutex_enter(&ahci_portp->ahciport_mutex);
		/*
		 * To prevent recursive enter to ahci_mop_commands, we need
		 * check AHCI_PORT_FLAG_MOPPING flag.
		 */
		if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_MOPPING) {
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_reset_hba_reject_pkts: port %d is in "
			    "mopping process, so return directly ", port);
			mutex_exit(&ahci_portp->ahciport_mutex);
			continue;
		}

		ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_MOPPING;
		ahci_portp->ahciport_mop_in_progress++;

		if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp))
			finished_tags[port]  =
			    ahci_portp->ahciport_pending_tags &
			    ~slot_status[port] & AHCI_SLOT_MASK(ahci_ctlp);
		else if (NCQ_CMD_IN_PROGRESS(ahci_portp))
			finished_tags[port] =
			    ahci_portp->ahciport_pending_ncq_tags &
			    ~slot_status[port] & AHCI_NCQ_SLOT_MASK(ahci_portp);

		reset_tags[port] &= ~finished_tags[port];

		ahci_mop_commands(ahci_ctlp,
		    ahci_portp,
		    slot_status[port],
		    0, /* failed tags */
		    0, /* timeout tags */
		    0, /* aborted tags */
		    reset_tags[port]); /* reset tags */
		mutex_exit(&ahci_portp->ahciport_mutex);
	}
out:
	return (ret);
}

/*
 * Called by sata framework to reset a port(s) or device.
 */
static int
ahci_tran_reset_dport(dev_info_t *dip, sata_device_t *sd)
{
	ahci_ctl_t *ahci_ctlp;
	ahci_port_t *ahci_portp;
	ahci_addr_t addr;
	uint8_t cport = sd->satadev_addr.cport;
	uint8_t pmport = sd->satadev_addr.pmport;
	uint8_t port;
	int ret = SATA_SUCCESS;
	int instance = ddi_get_instance(dip);

	ahci_ctlp = ddi_get_soft_state(ahci_statep, instance);
	port = ahci_ctlp->ahcictl_cport_to_port[cport];
	ahci_portp = ahci_ctlp->ahcictl_ports[port];

	ahci_get_ahci_addr(ahci_ctlp, sd, &addr);

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_tran_reset_dport enter: cport %d", cport);

	switch (sd->satadev_addr.qual) {
	case SATA_ADDR_PMPORT:
		/*
		 * If we want to issue a COMRESET on a pmport, we need to
		 * reject the outstanding commands on that pmport. According
		 * to AHCI spec, PxCI register could only be cleared by
		 * clearing PxCMD.ST, which will halt the controller port - as
		 * well as other pmports.
		 *
		 * Therefore we directly reset the controller port for
		 * simplicity. ahci_tran_probe_port() will handle reset stuff
		 * like initializing the given pmport.
		 */
		/* FALLTHRU */
	case SATA_ADDR_CPORT:
		/* Port reset */
		ahci_portp = ahci_ctlp->ahcictl_ports[port];
		cmn_err(CE_NOTE, "!ahci%d: ahci_tran_reset_dport "
		    "port %d reset port", instance, port);

		mutex_enter(&ahci_portp->ahciport_mutex);
		ret = ahci_reset_port_reject_pkts(ahci_ctlp, ahci_portp, &addr);
		mutex_exit(&ahci_portp->ahciport_mutex);

		break;

	case SATA_ADDR_DPMPORT:
		cmn_err(CE_NOTE, "!ahci%d: ahci_tran_reset_dport "
		    "port %d:%d reset device", instance, port, pmport);
		/* FALLTHRU */
	case SATA_ADDR_DCPORT:
		/* Device reset */
		if (sd->satadev_addr.qual == SATA_ADDR_DCPORT)
			cmn_err(CE_NOTE, "!ahci%d: ahci_tran_reset_dport "
			    "port %d reset device", instance, port);

		mutex_enter(&ahci_portp->ahciport_mutex);
		/*
		 * software reset request must be sent to SATA_PMULT_HOSTPORT
		 * if target is a port multiplier:
		 */
		if (sd->satadev_addr.qual == SATA_ADDR_DCPORT &&
		    ahci_portp->ahciport_device_type == SATA_DTYPE_PMULT)
			AHCI_ADDR_SET_PMULT(&addr, port);

		if (ahci_portp->ahciport_port_state & SATA_PSTATE_FAILED |
		    ahci_portp->ahciport_port_state & SATA_PSTATE_SHUTDOWN |
		    ahci_portp->ahciport_port_state & SATA_PSTATE_PWROFF) {
			/*
			 * In case the targer driver would send the request
			 * before sata framework can have the opportunity to
			 * process those event reports.
			 */
			sd->satadev_state = ahci_portp->ahciport_port_state;
			ahci_update_sata_registers(ahci_ctlp, port, sd);
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_tran_reset_dport returning SATA_FAILURE "
			    "while port in FAILED/SHUTDOWN/PWROFF state: "
			    "port: %d", port);
			mutex_exit(&ahci_portp->ahciport_mutex);
			ret = SATA_FAILURE;
			break;
		}

		if (AHCIPORT_GET_DEV_TYPE(ahci_portp, &addr) ==
		    SATA_DTYPE_NONE) {
			/*
			 * ahci_intr_phyrdy_change() may have rendered it to
			 * AHCI_PORT_TYPE_NODEV.
			 */
			sd->satadev_type = SATA_DTYPE_NONE;
			sd->satadev_state = AHCIPORT_GET_STATE(ahci_portp,
			    &addr);
			ahci_update_sata_registers(ahci_ctlp, port, sd);
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_tran_reset_dport returning SATA_FAILURE "
			    "while no device attached: port: %d", port);
			mutex_exit(&ahci_portp->ahciport_mutex);
			ret = SATA_FAILURE;
			break;
		}

		if (AHCI_ADDR_IS_PORT(&addr)) {
			ret = ahci_reset_device_reject_pkts(ahci_ctlp,
			    ahci_portp, &addr);
		} else {
			ret = ahci_reset_pmdevice_reject_pkts(ahci_ctlp,
			    ahci_portp, &addr);
		}

		mutex_exit(&ahci_portp->ahciport_mutex);
		break;

	case SATA_ADDR_CNTRL:
		/* Reset the whole controller */
		cmn_err(CE_NOTE, "!ahci%d: ahci_tran_reset_dport "
		    "reset the whole hba", instance);
		ret = ahci_reset_hba_reject_pkts(ahci_ctlp);
		break;

	default:
		ret = SATA_FAILURE;
	}

	return (ret);
}

/*
 * Called by sata framework to activate a port as part of hotplug.
 * (cfgadm -c connect satax/y)
 * Support port multiplier.
 */
static int
ahci_tran_hotplug_port_activate(dev_info_t *dip, sata_device_t *satadev)
{
	ahci_ctl_t *ahci_ctlp;
	ahci_port_t *ahci_portp;
	ahci_addr_t addr;
	uint8_t	cport = satadev->satadev_addr.cport;
	uint8_t	pmport = satadev->satadev_addr.pmport;
	uint8_t port;
	int instance = ddi_get_instance(dip);

	ahci_ctlp = ddi_get_soft_state(ahci_statep, instance);
	port = ahci_ctlp->ahcictl_cport_to_port[cport];

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_tran_hotplug_port_activate enter: cport %d", cport);

	ahci_portp = ahci_ctlp->ahcictl_ports[port];

	mutex_enter(&ahci_portp->ahciport_mutex);
	ahci_get_ahci_addr(ahci_ctlp, satadev, &addr);
	ASSERT(AHCI_ADDR_IS_PORT(&addr) || AHCI_ADDR_IS_PMPORT(&addr));

	if (AHCI_ADDR_IS_PORT(&addr)) {
		cmn_err(CE_NOTE, "!ahci%d: ahci port %d is activated",
		    instance, port);

		/* Enable the interrupts on the port */
		ahci_enable_port_intrs(ahci_ctlp, port);

		/*
		 * Reset the port so that the PHY communication would be
		 * re-established.  But this reset is an internal operation
		 * and the sata module doesn't need to know about it.
		 * Moreover, the port with a device attached will be started
		 * too.
		 */
		(void) ahci_restart_port_wait_till_ready(ahci_ctlp,
		    ahci_portp, port,
		    AHCI_PORT_RESET|AHCI_RESET_NO_EVENTS_UP,
		    NULL);

		/*
		 * Need to check the link status and device status of the port
		 * and consider raising power if the port was in D3 state
		 */
		ahci_portp->ahciport_port_state |= SATA_PSTATE_PWRON;
		ahci_portp->ahciport_port_state &= ~SATA_PSTATE_PWROFF;
		ahci_portp->ahciport_port_state &= ~SATA_PSTATE_SHUTDOWN;
	} else if (AHCI_ADDR_IS_PMPORT(&addr)) {
		cmn_err(CE_NOTE, "!ahci%d: ahci port %d:%d is activated",
		    instance, port, pmport);
		/* AHCI_ADDR_PMPORT */
		AHCIPORT_PMSTATE(ahci_portp, &addr) |= SATA_PSTATE_PWRON;
		AHCIPORT_PMSTATE(ahci_portp, &addr) &=
		    ~(SATA_PSTATE_PWROFF|SATA_PSTATE_SHUTDOWN);
	}

	satadev->satadev_state = ahci_portp->ahciport_port_state;

	ahci_update_sata_registers(ahci_ctlp, port, satadev);

	mutex_exit(&ahci_portp->ahciport_mutex);
	return (SATA_SUCCESS);
}

/*
 * Called by sata framework to deactivate a port as part of hotplug.
 * (cfgadm -c disconnect satax/y)
 * Support port multiplier.
 */
static int
ahci_tran_hotplug_port_deactivate(dev_info_t *dip, sata_device_t *satadev)
{
	ahci_ctl_t *ahci_ctlp;
	ahci_port_t *ahci_portp;
	ahci_addr_t addr;
	uint8_t	cport = satadev->satadev_addr.cport;
	uint8_t	pmport = satadev->satadev_addr.pmport;
	uint8_t port;
	uint32_t port_scontrol;
	int instance = ddi_get_instance(dip);

	ahci_ctlp = ddi_get_soft_state(ahci_statep, instance);
	port = ahci_ctlp->ahcictl_cport_to_port[cport];

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_tran_hotplug_port_deactivate enter: cport %d", cport);

	ahci_portp = ahci_ctlp->ahcictl_ports[port];
	mutex_enter(&ahci_portp->ahciport_mutex);
	ahci_get_ahci_addr(ahci_ctlp, satadev, &addr);
	ASSERT(AHCI_ADDR_IS_PORT(&addr) || AHCI_ADDR_IS_PMPORT(&addr));

	if (AHCI_ADDR_IS_PORT(&addr)) {
		cmn_err(CE_NOTE, "!ahci%d: ahci port %d is deactivated",
		    instance, port);

		/* Disable the interrupts on the port */
		ahci_disable_port_intrs(ahci_ctlp, port);

		if (ahci_portp->ahciport_device_type != SATA_DTYPE_NONE) {

			/* First to abort all the pending commands */
			ahci_reject_all_abort_pkts(ahci_ctlp, ahci_portp, port);

			/* Then stop the port */
			(void) ahci_put_port_into_notrunning_state(ahci_ctlp,
			    ahci_portp, port);
		}

		/* Next put the PHY offline */
		port_scontrol = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port));
		SCONTROL_SET_DET(port_scontrol, SCONTROL_DET_DISABLE);
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle, (uint32_t *)
		    AHCI_PORT_PxSCTL(ahci_ctlp, port), port_scontrol);
	} else if (AHCI_ADDR_IS_PMPORT(&addr)) {
		cmn_err(CE_NOTE, "!ahci%d: ahci port %d:%d is deactivated",
		    instance, port, pmport);

		ahci_disable_port_intrs(ahci_ctlp, port);
		if (AHCIPORT_GET_DEV_TYPE(ahci_portp, &addr)
		    != SATA_DTYPE_NONE)
			ahci_reject_all_abort_pkts(ahci_ctlp, ahci_portp, port);

		/* Re-enable the interrupts for the other pmports */
		ahci_enable_port_intrs(ahci_ctlp, port);
	}

	/* Update port state */
	AHCIPORT_SET_STATE(ahci_portp, &addr, SATA_PSTATE_SHUTDOWN);
	satadev->satadev_state = SATA_PSTATE_SHUTDOWN;

	ahci_update_sata_registers(ahci_ctlp, port, satadev);

	mutex_exit(&ahci_portp->ahciport_mutex);
	return (SATA_SUCCESS);
}

/*
 * To be used to mark all the outstanding pkts with SATA_PKT_ABORTED
 * when a device is unplugged or a port is deactivated.
 */
static void
ahci_reject_all_abort_pkts(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t slot_status = 0;
	uint32_t abort_tags = 0;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY|AHCIDBG_INTR, ahci_ctlp,
	    "ahci_reject_all_abort_pkts at port: %d", port);

	/* Read/write port multiplier command takes highest priority */
	if (RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp)) {
		slot_status = 0x1;
		abort_tags = 0x1;
		goto out;
	}

	/*
	 * When AHCI_PORT_FLAG_MOPPING is set, we need to check whether a
	 * REQUEST SENSE command or READ LOG EXT command is delivered to HBA
	 * to get the error data, if yes when the device is removed, the
	 * command needs to be aborted too.
	 */
	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_MOPPING) {
		if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp)) {
			slot_status = 0x1;
			abort_tags = 0x1;
			goto out;
		} else {
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_reject_all_abort_pkts return directly "
			    "port %d no needs to reject any outstanding "
			    "commands", port);
			return;
		}
	}

	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));
		abort_tags = slot_status & AHCI_SLOT_MASK(ahci_ctlp);
	} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));
		abort_tags = slot_status & AHCI_NCQ_SLOT_MASK(ahci_portp);
	}

out:
	/* No need to do mop when there is no outstanding commands */
	if (slot_status != 0) {
		ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_MOPPING;
		ahci_portp->ahciport_mop_in_progress++;

		ahci_mop_commands(ahci_ctlp,
		    ahci_portp,
		    slot_status,
		    0, /* failed tags */
		    0, /* timeout tags */
		    abort_tags, /* aborting tags */
		    0); /* reset tags */
	}
}

#if defined(__lock_lint)
static int
ahci_selftest(dev_info_t *dip, sata_device_t *device)
{
	return (SATA_SUCCESS);
}
#endif

/*
 * Initialize fma capabilities and register with IO fault services.
 */
static void
ahci_fm_init(ahci_ctl_t *ahci_ctlp)
{
	/*
	 * Need to change iblock to priority for new MSI intr
	 */
	ddi_iblock_cookie_t fm_ibc;

	ahci_ctlp->ahcictl_fm_cap = ddi_getprop(DDI_DEV_T_ANY,
	    ahci_ctlp->ahcictl_dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "fm-capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);

	/* Only register with IO Fault Services if we have some capability */
	if (ahci_ctlp->ahcictl_fm_cap) {
		/* Adjust access and dma attributes for FMA */
		accattr.devacc_attr_access = DDI_FLAGERR_ACC;
		buffer_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		rcvd_fis_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		cmd_list_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		cmd_table_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;

		/*
		 * Register capabilities with IO Fault Services.
		 * ahcictl_fm_cap will be updated to indicate
		 * capabilities actually supported (not requested.)
		 */
		ddi_fm_init(ahci_ctlp->ahcictl_dip,
		    &ahci_ctlp->ahcictl_fm_cap, &fm_ibc);

		if (ahci_ctlp->ahcictl_fm_cap == DDI_FM_NOT_CAPABLE) {
			cmn_err(CE_WARN, "!ahci%d: fma init failed.",
			    ddi_get_instance(ahci_ctlp->ahcictl_dip));
			return;
		}
		/*
		 * Initialize pci ereport capabilities if ereport
		 * capable (should always be.)
		 */
		if (DDI_FM_EREPORT_CAP(ahci_ctlp->ahcictl_fm_cap) ||
		    DDI_FM_ERRCB_CAP(ahci_ctlp->ahcictl_fm_cap)) {
			pci_ereport_setup(ahci_ctlp->ahcictl_dip);
		}

		/*
		 * Register error callback if error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(ahci_ctlp->ahcictl_fm_cap)) {
			ddi_fm_handler_register(ahci_ctlp->ahcictl_dip,
			    ahci_fm_error_cb, (void *) ahci_ctlp);
		}

		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "ahci_fm_fini: fma enabled.", NULL);
	}
}

/*
 * Releases fma capabilities and un-registers with IO fault services.
 */
static void
ahci_fm_fini(ahci_ctl_t *ahci_ctlp)
{
	/* Only unregister FMA capabilities if registered */
	if (ahci_ctlp->ahcictl_fm_cap) {
		/*
		 * Un-register error callback if error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(ahci_ctlp->ahcictl_fm_cap)) {
			ddi_fm_handler_unregister(ahci_ctlp->ahcictl_dip);
		}

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(ahci_ctlp->ahcictl_fm_cap) ||
		    DDI_FM_ERRCB_CAP(ahci_ctlp->ahcictl_fm_cap)) {
			pci_ereport_teardown(ahci_ctlp->ahcictl_dip);
		}

		/* Unregister from IO Fault Services */
		ddi_fm_fini(ahci_ctlp->ahcictl_dip);

		/* Adjust access and dma attributes for FMA */
		accattr.devacc_attr_access = DDI_DEFAULT_ACC;
		buffer_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		rcvd_fis_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		cmd_list_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		cmd_table_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;

		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "ahci_fm_fini: fma disabled.", NULL);
	}
}

/*ARGSUSED*/
static int
ahci_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	/*
	 * as the driver can always deal with an error in any dma or
	 * access handle, we can just return the fme_status value.
	 */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

int
ahci_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

int
ahci_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t de;

	ddi_fm_dma_err_get(handle, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

/*
 * Generate an ereport
 */
void
ahci_fm_ereport(ahci_ctl_t *ahci_ctlp, char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(ahci_ctlp->ahcictl_fm_cap)) {
		ddi_fm_ereport_post(ahci_ctlp->ahcictl_dip, buf, ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8,
		    FM_EREPORT_VERSION, NULL);
	}
}

/*
 * Check if all handles are correctly allocated.
 */
static int
ahci_check_all_handle(ahci_ctl_t *ahci_ctlp)
{
	int port;

	if (ahci_check_ctl_handle(ahci_ctlp) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		ahci_port_t *ahci_portp;

		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port))
			continue;

		ahci_portp = ahci_ctlp->ahcictl_ports[port];

		mutex_enter(&ahci_portp->ahciport_mutex);
		if (ahci_check_port_handle(ahci_ctlp, port) != DDI_SUCCESS) {
			mutex_exit(&ahci_portp->ahciport_mutex);
			return (DDI_FAILURE);
		}
		mutex_exit(&ahci_portp->ahciport_mutex);
	}

	return (DDI_SUCCESS);
}

/*
 * Check the access handles for the controller. Note that
 * ahcictl_pci_conf_handle is only used in attach process.
 */
static int
ahci_check_ctl_handle(ahci_ctl_t *ahci_ctlp)
{
	if ((ahci_check_acc_handle(ahci_ctlp->
	    ahcictl_pci_conf_handle) != DDI_FM_OK) ||
	    (ahci_check_acc_handle(ahci_ctlp->
	    ahcictl_ahci_acc_handle) != DDI_FM_OK)) {
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Check the DMA handles and the access handles of a controller port.
 */
static int
ahci_check_port_handle(ahci_ctl_t *ahci_ctlp, int port)
{
	ahci_port_t *ahci_portp = ahci_ctlp->ahcictl_ports[port];
	int slot;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	if ((ahci_check_dma_handle(ahci_portp->
	    ahciport_rcvd_fis_dma_handle) != DDI_FM_OK) ||
	    (ahci_check_dma_handle(ahci_portp->
	    ahciport_cmd_list_dma_handle) != DDI_FM_OK) ||
	    (ahci_check_acc_handle(ahci_portp->
	    ahciport_rcvd_fis_acc_handle) != DDI_FM_OK) ||
	    (ahci_check_acc_handle(ahci_portp->
	    ahciport_cmd_list_acc_handle) != DDI_FM_OK)) {
		return (DDI_FAILURE);
	}
	for (slot = 0; slot < ahci_ctlp->ahcictl_num_cmd_slots; slot++) {
		if (ahci_check_slot_handle(ahci_portp, slot)
		    != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}
	return (DDI_SUCCESS);
}

/*
 * Check the DMA handles and the access handles of a cmd table slot.
 */
static int
ahci_check_slot_handle(ahci_port_t *ahci_portp, int slot)
{
	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	if ((ahci_check_acc_handle(ahci_portp->
	    ahciport_cmd_tables_acc_handle[slot]) != DDI_FM_OK) ||
	    (ahci_check_dma_handle(ahci_portp->
	    ahciport_cmd_tables_dma_handle[slot]) != DDI_FM_OK)) {
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Allocate the ports structure, only called by ahci_attach
 */
static int
ahci_alloc_ports_state(ahci_ctl_t *ahci_ctlp)
{
	int port, cport = 0;

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_alloc_ports_state enter", NULL);

	mutex_enter(&ahci_ctlp->ahcictl_mutex);

	/* Allocate structures only for the implemented ports */
	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
			    "hba port %d not implemented", port);
			continue;
		}

		ahci_ctlp->ahcictl_cport_to_port[cport] = (uint8_t)port;
		ahci_ctlp->ahcictl_port_to_cport[port] =
		    (uint8_t)cport++;

		if (ahci_alloc_port_state(ahci_ctlp, port) != AHCI_SUCCESS) {
			goto err_out;
		}
	}

	mutex_exit(&ahci_ctlp->ahcictl_mutex);
	return (AHCI_SUCCESS);

err_out:
	for (port--; port >= 0; port--) {
		if (AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			ahci_dealloc_port_state(ahci_ctlp, port);
		}
	}

	mutex_exit(&ahci_ctlp->ahcictl_mutex);
	return (AHCI_FAILURE);
}

/*
 * Reverse of ahci_alloc_ports_state(), only called by ahci_detach
 */
static void
ahci_dealloc_ports_state(ahci_ctl_t *ahci_ctlp)
{
	int port;

	mutex_enter(&ahci_ctlp->ahcictl_mutex);
	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		/* if this port is implemented by the HBA */
		if (AHCI_PORT_IMPLEMENTED(ahci_ctlp, port))
			ahci_dealloc_port_state(ahci_ctlp, port);
	}
	mutex_exit(&ahci_ctlp->ahcictl_mutex);
}

/*
 * Drain the taskq.
 */
static void
ahci_drain_ports_taskq(ahci_ctl_t *ahci_ctlp)
{
	ahci_port_t *ahci_portp;
	int port;

	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			continue;
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];

		mutex_enter(&ahci_portp->ahciport_mutex);
		ddi_taskq_wait(ahci_portp->ahciport_event_taskq);
		mutex_exit(&ahci_portp->ahciport_mutex);
	}
}

/*
 * Initialize the controller and all ports. And then try to start the ports
 * if there are devices attached.
 *
 * This routine can be called from three seperate cases: DDI_ATTACH,
 * PM_LEVEL_D0 and DDI_RESUME. The DDI_ATTACH case is different from
 * other two cases; device signature probing are attempted only during
 * DDI_ATTACH case.
 */
static int
ahci_initialize_controller(ahci_ctl_t *ahci_ctlp)
{
	ahci_port_t *ahci_portp;
	ahci_addr_t addr;
	int port;

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_initialize_controller enter", NULL);

	/* Disable the whole controller interrupts */
	mutex_enter(&ahci_ctlp->ahcictl_mutex);
	ahci_disable_all_intrs(ahci_ctlp);
	mutex_exit(&ahci_ctlp->ahcictl_mutex);

	/* Initialize the implemented ports and structures */
	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			continue;
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];
		mutex_enter(&ahci_portp->ahciport_mutex);

		/*
		 * Ensure that the controller is not in the running state
		 * by checking every implemented port's PxCMD register
		 */
		AHCI_ADDR_SET_PORT(&addr, (uint8_t)port);

		if (ahci_initialize_port(ahci_ctlp, ahci_portp, &addr)
		    != AHCI_SUCCESS) {
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_initialize_controller: failed to "
			    "initialize port %d", port);
			/*
			 * Set the port state to SATA_PSTATE_FAILED if
			 * failed to initialize it.
			 */
			ahci_portp->ahciport_port_state = SATA_PSTATE_FAILED;
		}

		mutex_exit(&ahci_portp->ahciport_mutex);
	}

	/* Enable the whole controller interrupts */
	mutex_enter(&ahci_ctlp->ahcictl_mutex);
	ahci_enable_all_intrs(ahci_ctlp);
	mutex_exit(&ahci_ctlp->ahcictl_mutex);

	return (AHCI_SUCCESS);
}

/*
 * Reverse of ahci_initialize_controller()
 *
 * We only need to stop the ports and disable the interrupt.
 */
static void
ahci_uninitialize_controller(ahci_ctl_t *ahci_ctlp)
{
	ahci_port_t *ahci_portp;
	int port;

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
	    "ahci_uninitialize_controller enter", NULL);

	/* disable all the interrupts. */
	mutex_enter(&ahci_ctlp->ahcictl_mutex);
	ahci_disable_all_intrs(ahci_ctlp);
	mutex_exit(&ahci_ctlp->ahcictl_mutex);

	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			continue;
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];

		/* Stop the port by clearing PxCMD.ST */
		mutex_enter(&ahci_portp->ahciport_mutex);

		/*
		 * Here we must disable the port interrupt because
		 * ahci_disable_all_intrs only clear GHC.IE, and IS
		 * register will be still set if PxIE is enabled.
		 * When ahci shares one IRQ with other drivers, the
		 * intr handler may claim the intr mistakenly.
		 */
		ahci_disable_port_intrs(ahci_ctlp, port);
		(void) ahci_put_port_into_notrunning_state(ahci_ctlp,
		    ahci_portp, port);
		mutex_exit(&ahci_portp->ahciport_mutex);
	}
}

/*
 * ahci_alloc_pmult()
 * 1. Setting HBA port registers which are necessary for a port multiplier.
 *    (Set PxCMD.PMA while PxCMD.ST is '0')
 * 2. Allocate ahci_pmult_info structure.
 *
 * NOTE: Must stop port before the function is called.
 */
static void
ahci_alloc_pmult(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
	uint32_t port_cmd_status;
	uint8_t port = ahci_portp->ahciport_port_num;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	/* The port must have been stopped before. */
	ASSERT(!(port_cmd_status & AHCI_CMD_STATUS_ST));

	if (!(port_cmd_status & AHCI_CMD_STATUS_PMA)) {
		/* set PMA bit */
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
		    port_cmd_status|AHCI_CMD_STATUS_PMA);

		AHCIDBG(AHCIDBG_INIT|AHCIDBG_PMULT, ahci_ctlp,
		    "ahci_alloc_pmult: "
		    "PxCMD.PMA bit set at port %d.", port);
	}

	/* Allocate port multiplier information structure */
	if (ahci_portp->ahciport_pmult_info == NULL) {
		ahci_portp->ahciport_pmult_info = (ahci_pmult_info_t *)
		    kmem_zalloc(sizeof (ahci_pmult_info_t), KM_SLEEP);
	}

	ASSERT(ahci_portp->ahciport_pmult_info != NULL);
}

/*
 * ahci_dealloc_pmult()
 * 1. Clearing related registers when a port multiplier is detached.
 *    (Clear PxCMD.PMA while PxCMD.ST is '0')
 * 2. Deallocate ahci_pmult_info structure.
 *
 * NOTE: Must stop port before the function is called.
 */
static void
ahci_dealloc_pmult(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
	uint32_t port_cmd_status;
	uint8_t port = ahci_portp->ahciport_port_num;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	if (port_cmd_status & AHCI_CMD_STATUS_PMA) {
		/* Clear PMA bit */
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
		    (port_cmd_status & (~AHCI_CMD_STATUS_PMA)));

		AHCIDBG(AHCIDBG_INIT|AHCIDBG_PMULT, ahci_ctlp,
		    "ahci_dealloc_pmult: "
		    "PxCMD.PMA bit cleared at port %d.", port);
	}

	/* Release port multiplier information structure */
	if (ahci_portp->ahciport_pmult_info != NULL) {
		kmem_free(ahci_portp->ahciport_pmult_info,
		    sizeof (ahci_pmult_info_t));
		ahci_portp->ahciport_pmult_info = NULL;
	}
}

/*
 * Staggered Spin-up.
 */
static void
ahci_staggered_spin_up(ahci_ctl_t *ahci_ctlp, uint8_t port)
{
	uint32_t cap_status;
	uint32_t port_cmd_status;

	ASSERT(MUTEX_HELD(&ahci_ctlp->ahcictl_ports[port]->ahciport_mutex));

	cap_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_CAP(ahci_ctlp));

	/* Check for staggered spin-up support */
	if (!(cap_status & AHCI_HBA_CAP_SSS))
		return;

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	/* If PxCMD.SUD == 1, no staggered spin-up is needed */
	if (port_cmd_status & AHCI_CMD_STATUS_SUD)
		return;

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp, "Spin-up at port %d", port);

	/* Set PxCMD.SUD */
	port_cmd_status |= AHCI_CMD_STATUS_SUD;
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
	    port_cmd_status);
}

/*
 * The routine is to initialize a port. First put the port in NotRunning
 * state, then enable port interrupt and clear Serror register. And under
 * AHCI_ATTACH case, find device signature and then try to start the port.
 *
 * Called by
 *    1. ahci_initialize_controller
 *    2. ahci_intr_phyrdy_change (hotplug)
 */
static int
ahci_initialize_port(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    ahci_addr_t *addrp)
{
	uint32_t port_sstatus, port_task_file, port_cmd_status;
	uint8_t port = addrp->aa_port;
	boolean_t resuming = B_TRUE;	/*  processing DDI_RESUME */
	int ret;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	/* AHCI_ADDR_PORT: We've no idea of the attached device here.  */
	ASSERT(AHCI_ADDR_IS_PORT(addrp));

	/*
	 * At the time being, only probe ports/devices and get the types of
	 * attached devices during DDI_ATTACH. In fact, the device can be
	 * changed during power state changes, but at the time being, we
	 * don't support the situation.
	 */
	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_HOTPLUG) {
		resuming = B_FALSE;
	} else {
		/* check for DDI_RESUME case */
		mutex_exit(&ahci_portp->ahciport_mutex);
		mutex_enter(&ahci_ctlp->ahcictl_mutex);
		if (ahci_ctlp->ahcictl_flags & AHCI_ATTACH)
			resuming = B_FALSE;
		mutex_exit(&ahci_ctlp->ahcictl_mutex);
		mutex_enter(&ahci_portp->ahciport_mutex);
	}

	if (resuming) {
		/*
		 * During the resume, we need to set the PxCLB, PxCLBU, PxFB
		 * and PxFBU registers in case these registers were cleared
		 * during the suspend.
		 */
		AHCIDBG(AHCIDBG_PM, ahci_ctlp,
		    "ahci_initialize_port: port %d "
		    "set PxCLB, PxCLBU, PxFB and PxFBU "
		    "during resume", port);

		if (ahci_setup_port_base_addresses(ahci_ctlp, ahci_portp) !=
		    AHCI_SUCCESS)
			return (AHCI_FAILURE);
	}

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_initialize_port: port %d ", port);

	/*
	 * Check whether the port is in NotRunning state, if not,
	 * put the port in NotRunning state
	 */
	if (port_cmd_status &
	    (AHCI_CMD_STATUS_ST |
	    AHCI_CMD_STATUS_CR |
	    AHCI_CMD_STATUS_FRE |
	    AHCI_CMD_STATUS_FR)) {
		(void) ahci_put_port_into_notrunning_state(ahci_ctlp,
		    ahci_portp, port);
	}

	/* Make sure the drive is spun-up */
	ahci_staggered_spin_up(ahci_ctlp, port);

	/* Disable interrupt */
	ahci_disable_port_intrs(ahci_ctlp, port);

	/* Device is unknown at first */
	AHCIPORT_SET_DEV_TYPE(ahci_portp, addrp, SATA_DTYPE_UNKNOWN);

	/* Disable the interface power management */
	ahci_disable_interface_pm(ahci_ctlp, port);

	port_sstatus = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSSTS(ahci_ctlp, port));
	port_task_file = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));

	/* Check physcial link status */
	if (SSTATUS_GET_IPM(port_sstatus) == SSTATUS_IPM_NODEV_NOPHYCOM ||
	    SSTATUS_GET_DET(port_sstatus) == SSTATUS_DET_DEVPRE_NOPHYCOM ||

	    /* Check interface status */
	    port_task_file & AHCI_TFD_STS_BSY ||
	    port_task_file & AHCI_TFD_STS_DRQ ||

	    /* Check whether port reset must be executed */
	    ahci_ctlp->ahcictl_cap & AHCI_CAP_INIT_PORT_RESET ||

	    /* Always reset port on RESUME */
	    resuming != B_FALSE) {

		/* Something went wrong, we need do some reset things */
		ret = ahci_port_reset(ahci_ctlp, ahci_portp, addrp);

		/* Does port reset succeed on HBA port? */
		if (ret != AHCI_SUCCESS) {
			AHCIDBG(AHCIDBG_INIT|AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_initialize_port:"
			    "port reset failed at port %d", port);
			return (AHCI_FAILURE);
		}

		/* Is port failed? */
		if (AHCIPORT_GET_STATE(ahci_portp, addrp) &
		    SATA_PSTATE_FAILED) {
			AHCIDBG(AHCIDBG_INIT|AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_initialize_port: port %d state 0x%x",
			    port, ahci_portp->ahciport_port_state);
			return (AHCI_FAILURE);
		}
	}

	AHCIPORT_SET_STATE(ahci_portp, addrp, SATA_STATE_READY);
	AHCIDBG(AHCIDBG_INIT, ahci_ctlp, "port %d is ready now.", port);

	/*
	 * Try to get the device signature if the port is not empty.
	 */
	if (!resuming && AHCIPORT_DEV_TYPE(ahci_portp, addrp) !=
	    SATA_DTYPE_NONE)
		ahci_find_dev_signature(ahci_ctlp, ahci_portp, addrp);

	/* Return directly if no device connected */
	if (AHCIPORT_DEV_TYPE(ahci_portp, addrp) == SATA_DTYPE_NONE) {
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "No device connected to port %d", port);
		goto out;
	}

	/* If this is a port multiplier, we need do some initialization */
	if (AHCIPORT_DEV_TYPE(ahci_portp, addrp) == SATA_DTYPE_PMULT) {
		AHCIDBG(AHCIDBG_INFO|AHCIDBG_PMULT, ahci_ctlp,
		    "Port multiplier found at port %d", port);
		ahci_alloc_pmult(ahci_ctlp, ahci_portp);
	}

	/* Try to start the port */
	if (ahci_start_port(ahci_ctlp, ahci_portp, port)
	    != AHCI_SUCCESS) {
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "failed to start port %d", port);
		return (AHCI_FAILURE);
	}
out:
	/* Enable port interrupts */
	ahci_enable_port_intrs(ahci_ctlp, port);

	return (AHCI_SUCCESS);
}

/*
 *  Handle hardware defect, and check the capabilities. For example,
 *  power management capabilty and MSI capability.
 */
static int
ahci_config_space_init(ahci_ctl_t *ahci_ctlp)
{
	ushort_t caps_ptr, cap_count, cap;
#if AHCI_DEBUG
	ushort_t pmcap, pmcsr;
	ushort_t msimc;
#endif
	uint8_t revision;

	ahci_ctlp->ahcictl_venid =
	    pci_config_get16(ahci_ctlp->ahcictl_pci_conf_handle,
	    PCI_CONF_VENID);

	ahci_ctlp->ahcictl_devid =
	    pci_config_get16(ahci_ctlp->ahcictl_pci_conf_handle,
	    PCI_CONF_DEVID);

	/*
	 * Modify dma_attr_align of ahcictl_buffer_dma_attr. For VT8251, those
	 * controllers with 0x00 revision id work on 4-byte aligned buffer,
	 * which is a bug and was fixed after 0x00 revision id controllers.
	 *
	 * Moreover, VT8251 cannot use multiple command slots in the command
	 * list for non-queued commands because the previous register content
	 * of PxCI can be re-written in the register write, so a flag will be
	 * set to record this defect - AHCI_CAP_NO_MCMDLIST_NONQUEUE.
	 *
	 * For VT8251, software reset also has the same defect as the below
	 * AMD/ATI chipset. That is, software reset will get failed if 0xf
	 * is filled in pmport field. Therefore, another software reset need
	 * to be done with 0 filled in pmport field.
	 */
	if (ahci_ctlp->ahcictl_venid == VIA_VENID) {
		revision = pci_config_get8(ahci_ctlp->ahcictl_pci_conf_handle,
		    PCI_CONF_REVID);
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "revision id = 0x%x", revision);
		if (revision == 0x00) {
			ahci_ctlp->ahcictl_buffer_dma_attr.dma_attr_align = 0x4;
			AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
			    "change ddi_attr_align to 0x4", NULL);
		}

		ahci_ctlp->ahcictl_cap |= AHCI_CAP_NO_MCMDLIST_NONQUEUE;
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "VT8251 cannot use multiple command lists for "
		    "non-queued commands", NULL);

		ahci_ctlp->ahcictl_cap |= AHCI_CAP_SRST_NO_HOSTPORT;
	}

	/*
	 * AMD/ATI SB600 (0x1002,0x4380) AHCI chipset doesn't support 64-bit
	 * DMA addressing for communication memory descriptors though S64A bit
	 * of CAP register declares it supports. Even though 64-bit DMA for
	 * data buffer works on ASUS M2A-VM with newer BIOS, three other
	 * motherboards are known not, so both AHCI_CAP_BUF_32BIT_DMA and
	 * AHCI_CAP_COMMU_32BIT_DMA are set for this controller.
	 *
	 * Due to certain hardware issue, the chipset must do port reset during
	 * initialization, otherwise, when retrieving device signature,
	 * software reset will get time out. So AHCI_CAP_INIT_PORT_RESET flag
	 * need to set.
	 *
	 * For this chipset software reset will get failure if the pmport of
	 * Register FIS was set with SATA_PMULT_HOSTPORT (0xf) and no port
	 * multiplier is connected to the port. In order to fix the issue,
	 * AHCI_CAP_SRST_NO_HOSTPORT flag need to be set, and once software
	 * reset got failure, the driver will try to do another software reset
	 * with pmport 0.
	 */
	if (ahci_ctlp->ahcictl_venid == 0x1002 &&
	    ahci_ctlp->ahcictl_devid == 0x4380) {
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_BUF_32BIT_DMA;
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_COMMU_32BIT_DMA;
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_INIT_PORT_RESET;
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_SRST_NO_HOSTPORT;

		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "ATI SB600 cannot do 64-bit DMA for both data buffer and "
		    "communication memory descriptors though CAP indicates "
		    "support, so force it to use 32-bit DMA", NULL);
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "ATI SB600 need to do a port reset during initialization",
		    NULL);
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "ATI SB600 will get software reset failure if pmport "
		    "is set 0xf and no port multiplier is attached", NULL);
	}

	/*
	 * AMD/ATI SB700/710/750/800 and SP5100 AHCI chipset share the same
	 * vendor ID and device ID (0x1002,0x4391).
	 *
	 * SB700/750 AHCI chipset on some boards doesn't support 64-bit
	 * DMA addressing for communication memory descriptors though S64A bit
	 * of CAP register declares the support. However, it does support
	 * 64-bit DMA for data buffer. So only AHCI_CAP_COMMU_32BIT_DMA is
	 * set for this controller.
	 *
	 * SB710 has the same initialization issue as SB600, so it also need
	 * a port reset. That is AHCI_CAP_INIT_PORT_RESET need to set for it.
	 *
	 * SB700 also has the same issue about software reset, and thus
	 * AHCI_CAP_SRST_NO_HOSTPORT flag also is needed.
	 */
	if (ahci_ctlp->ahcictl_venid == 0x1002 &&
	    ahci_ctlp->ahcictl_devid == 0x4391) {
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_COMMU_32BIT_DMA;
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_INIT_PORT_RESET;
		ahci_ctlp->ahcictl_cap |= AHCI_CAP_SRST_NO_HOSTPORT;

		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "ATI SB700/750 cannot do 64-bit DMA for communication "
		    "memory descriptors though CAP indicates support, "
		    "so force it to use 32-bit DMA", NULL);
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "ATI SB710 need to do a port reset during initialization",
		    NULL);
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "ATI SB700 will get software reset failure if pmport "
		    "is set 0xf and no port multiplier is attached", NULL);
	}

	/*
	 * Check if capabilities list is supported and if so,
	 * get initial capabilities pointer and clear bits 0,1.
	 */
	if (pci_config_get16(ahci_ctlp->ahcictl_pci_conf_handle,
	    PCI_CONF_STAT) & PCI_STAT_CAP) {
		caps_ptr = P2ALIGN(pci_config_get8(
		    ahci_ctlp->ahcictl_pci_conf_handle,
		    PCI_CONF_CAP_PTR), 4);
	} else {
		caps_ptr = PCI_CAP_NEXT_PTR_NULL;
	}

	/*
	 * Walk capabilities if supported.
	 */
	for (cap_count = 0; caps_ptr != PCI_CAP_NEXT_PTR_NULL; ) {

		/*
		 * Check that we haven't exceeded the maximum number of
		 * capabilities and that the pointer is in a valid range.
		 */
		if (++cap_count > PCI_CAP_MAX_PTR) {
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "too many device capabilities", NULL);
			return (AHCI_FAILURE);
		}
		if (caps_ptr < PCI_CAP_PTR_OFF) {
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "capabilities pointer 0x%x out of range",
			    caps_ptr);
			return (AHCI_FAILURE);
		}

		/*
		 * Get next capability and check that it is valid.
		 * For now, we only support power management.
		 */
		cap = pci_config_get8(ahci_ctlp->ahcictl_pci_conf_handle,
		    caps_ptr);
		switch (cap) {
		case PCI_CAP_ID_PM:

			/* power management supported */
			ahci_ctlp->ahcictl_cap |= AHCI_CAP_PM;

			/* Save PMCSR offset */
			ahci_ctlp->ahcictl_pmcsr_offset = caps_ptr + PCI_PMCSR;

#if AHCI_DEBUG
			pmcap = pci_config_get16(
			    ahci_ctlp->ahcictl_pci_conf_handle,
			    caps_ptr + PCI_PMCAP);
			pmcsr = pci_config_get16(
			    ahci_ctlp->ahcictl_pci_conf_handle,
			    ahci_ctlp->ahcictl_pmcsr_offset);
			AHCIDBG(AHCIDBG_PM, ahci_ctlp,
			    "Power Management capability found PCI_PMCAP "
			    "= 0x%x PCI_PMCSR = 0x%x", pmcap, pmcsr);
			if ((pmcap & 0x3) == 0x3)
				AHCIDBG(AHCIDBG_PM, ahci_ctlp,
				    "PCI Power Management Interface "
				    "spec 1.2 compliant", NULL);
#endif
			break;

		case PCI_CAP_ID_MSI:
#if AHCI_DEBUG
			msimc = pci_config_get16(
			    ahci_ctlp->ahcictl_pci_conf_handle,
			    caps_ptr + PCI_MSI_CTRL);
			AHCIDBG(AHCIDBG_MSI, ahci_ctlp,
			    "Message Signaled Interrupt capability found "
			    "MSICAP_MC.MMC = 0x%x", (msimc & 0xe) >> 1);
#endif
			AHCIDBG(AHCIDBG_MSI, ahci_ctlp,
			    "MSI capability found", NULL);
			break;

		case PCI_CAP_ID_PCIX:
			AHCIDBG(AHCIDBG_PM, ahci_ctlp,
			    "PCI-X capability found", NULL);
			break;

		case PCI_CAP_ID_PCI_E:
			AHCIDBG(AHCIDBG_PM, ahci_ctlp,
			    "PCI Express capability found", NULL);
			break;

		case PCI_CAP_ID_MSI_X:
			AHCIDBG(AHCIDBG_PM, ahci_ctlp,
			    "MSI-X capability found", NULL);
			break;

		case PCI_CAP_ID_SATA:
			AHCIDBG(AHCIDBG_PM, ahci_ctlp,
			    "SATA capability found", NULL);
			break;

		case PCI_CAP_ID_VS:
			AHCIDBG(AHCIDBG_PM, ahci_ctlp,
			    "Vendor Specific capability found", NULL);
			break;

		default:
			AHCIDBG(AHCIDBG_PM, ahci_ctlp,
			    "unrecognized capability 0x%x", cap);
			break;
		}

		/*
		 * Get next capabilities pointer and clear bits 0,1.
		 */
		caps_ptr = P2ALIGN(pci_config_get8(
		    ahci_ctlp->ahcictl_pci_conf_handle,
		    (caps_ptr + PCI_CAP_NEXT_PTR)), 4);
	}

	return (AHCI_SUCCESS);
}

/*
 * Read/Write a register at port multiplier by SATA READ PORTMULT / SATA WRITE
 * PORTMULT command. SYNC & POLLING mode is used.
 */
static int
ahci_rdwr_pmult(ahci_ctl_t *ahci_ctlp, ahci_addr_t *addrp,
    uint8_t regn, uint32_t *pregv, uint8_t type)
{
	ahci_port_t *ahci_portp;
	ahci_addr_t pmult_addr;
	sata_pkt_t *spkt;
	sata_cmd_t *scmd;
	sata_device_t sata_device;
	uint8_t port = addrp->aa_port;
	uint8_t pmport = addrp->aa_pmport;
	uint8_t cport;
	uint32_t intr_mask;
	int rval;
	char portstr[10];

	SET_PORTSTR(portstr, addrp);
	cport = ahci_ctlp->ahcictl_port_to_cport[port];
	ahci_portp = ahci_ctlp->ahcictl_ports[port];

	ASSERT(AHCI_ADDR_IS_PMPORT(addrp) || AHCI_ADDR_IS_PMULT(addrp));
	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	/* Check the existence of the port multiplier */
	if (ahci_portp->ahciport_device_type != SATA_DTYPE_PMULT)
		return (AHCI_FAILURE);

	/* Request a READ/WRITE PORTMULT sata packet. */
	bzero(&sata_device, sizeof (sata_device_t));
	sata_device.satadev_addr.cport = cport;
	sata_device.satadev_addr.pmport = pmport;
	sata_device.satadev_addr.qual = SATA_ADDR_PMULT;
	sata_device.satadev_rev = SATA_DEVICE_REV;

	/*
	 * Make sure no command is outstanding here. All R/W PMULT requests
	 * come from
	 *
	 * 1. ahci_attach()
	 *    The port should be empty.
	 *
	 * 2. ahci_tran_probe_port()
	 *    Any request from SATA framework (via ahci_tran_start) should be
	 *    rejected if R/W PMULT command is outstanding.
	 *
	 *    If we are doing mopping, do not check those flags because no
	 *    command will be actually outstanding.
	 *
	 *    If the port has been occupied by any other commands, the probe
	 *    function will return a SATA_RETRY. SATA framework will retry
	 *    later.
	 */
	if (RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp)) {
		AHCIDBG(AHCIDBG_ERRS|AHCIDBG_PMULT, ahci_ctlp,
		    "R/W PMULT failed: R/W PMULT in progress at port %d.",
		    port, ahci_portp->ahciport_flags);
		return (AHCI_FAILURE);
	}

	if (!(ahci_portp->ahciport_flags & AHCI_PORT_FLAG_MOPPING) && (
	    ERR_RETRI_CMD_IN_PROGRESS(ahci_portp) ||
	    NCQ_CMD_IN_PROGRESS(ahci_portp) ||
	    NON_NCQ_CMD_IN_PROGRESS(ahci_portp))) {
		AHCIDBG(AHCIDBG_ERRS|AHCIDBG_PMULT, ahci_ctlp,
		    "R/W PMULT failed: port %d is occupied (flags 0x%x).",
		    port, ahci_portp->ahciport_flags);
		return (AHCI_FAILURE);
	}

	/*
	 * The port multiplier is gone. This may happen when
	 * 1. Cutting off the power of an enclosure. The device lose the power
	 *    before port multiplier.
	 * 2. Disconnecting the port multiplier during hot-plugging a sub-drive.
	 *
	 * The issued command should be aborted and the following command
	 * should not be continued.
	 */
	if (!(ahci_portp->ahciport_port_state & SATA_STATE_READY)) {
		AHCIDBG(AHCIDBG_ERRS|AHCIDBG_PMULT, ahci_ctlp,
		    "READ/WRITE PMULT failed: "
		    "port-mult is removed from port %d", port);
		return (AHCI_FAILURE);
	}

	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_RDWR_PMULT;

	spkt = sata_get_rdwr_pmult_pkt(ahci_ctlp->ahcictl_dip,
	    &sata_device, regn, *pregv, type);

	/*
	 * READ/WRITE PORTMULT command is intended to sent to the control port
	 * of the port multiplier.
	 */
	AHCI_ADDR_SET_PMULT(&pmult_addr, addrp->aa_port);

	ahci_portp->ahciport_rdwr_pmult_pkt = spkt;

	/* No interrupt here. Store the interrupt enable mask. */
	intr_mask = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxIE(ahci_ctlp, port));
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxIE(ahci_ctlp, port), 0);

	rval = ahci_do_sync_start(ahci_ctlp, ahci_portp, &pmult_addr, spkt);

	if (rval == AHCI_SUCCESS &&
	    spkt->satapkt_reason == SATA_PKT_COMPLETED) {
		if (type == SATA_RDWR_PMULT_PKT_TYPE_READ) {
			scmd = &spkt->satapkt_cmd;
			*pregv = scmd->satacmd_lba_high_lsb << 24 |
			    scmd->satacmd_lba_mid_lsb << 16 |
			    scmd->satacmd_lba_low_lsb << 8 |
			    scmd->satacmd_sec_count_lsb;
		}
	} else {
		/* Failed or not completed. */
		AHCIDBG(AHCIDBG_ERRS|AHCIDBG_PMULT, ahci_ctlp,
		    "ahci_rdwr_pmult: cannot [%s] %s[%d] at port %s",
		    type == SATA_RDWR_PMULT_PKT_TYPE_READ?"Read":"Write",
		    AHCI_ADDR_IS_PMULT(addrp)?"gscr":"pscr", regn, portstr);
		rval = AHCI_FAILURE;
	}
out:
	/* Restore the interrupt mask */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxIE(ahci_ctlp, port), intr_mask);

	ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_RDWR_PMULT;
	ahci_portp->ahciport_rdwr_pmult_pkt = NULL;
	sata_free_rdwr_pmult_pkt(spkt);
	return (rval);
}

static int
ahci_read_pmult(ahci_ctl_t *ahci_ctlp, ahci_addr_t *addrp,
    uint8_t regn, uint32_t *pregv)
{
	return ahci_rdwr_pmult(ahci_ctlp, addrp, regn, pregv,
	    SATA_RDWR_PMULT_PKT_TYPE_READ);
}

static int
ahci_write_pmult(ahci_ctl_t *ahci_ctlp, ahci_addr_t *addrp,
    uint8_t regn, uint32_t regv)
{
	return ahci_rdwr_pmult(ahci_ctlp, addrp, regn, &regv,
	    SATA_RDWR_PMULT_PKT_TYPE_WRITE);
}

#define	READ_PMULT(addrp, r, pv, out)					\
	if (ahci_read_pmult(ahci_ctlp, addrp, r, pv) != AHCI_SUCCESS)	\
		goto out;

#define	WRITE_PMULT(addrp, r, v, out)					\
	if (ahci_write_pmult(ahci_ctlp, addrp, r, v) != AHCI_SUCCESS)	\
		goto out;

/*
 * Update sata registers on port multiplier, including GSCR/PSCR registers.
 * ahci_update_pmult_gscr()
 * ahci_update_pmult_pscr()
 */
static int
ahci_update_pmult_gscr(ahci_ctl_t *ahci_ctlp, ahci_addr_t *addrp,
    sata_pmult_gscr_t *sg)
{
	ASSERT(MUTEX_HELD(
	    &ahci_ctlp->ahcictl_ports[addrp->aa_port]->ahciport_mutex));

	READ_PMULT(addrp, SATA_PMULT_GSCR0, &sg->gscr0, err);
	READ_PMULT(addrp, SATA_PMULT_GSCR1, &sg->gscr1, err);
	READ_PMULT(addrp, SATA_PMULT_GSCR2, &sg->gscr2, err);
	READ_PMULT(addrp, SATA_PMULT_GSCR64, &sg->gscr64, err);

	return (AHCI_SUCCESS);

err:	/* R/W PMULT error */
	return (AHCI_FAILURE);
}

static int
ahci_update_pmult_pscr(ahci_ctl_t *ahci_ctlp, ahci_addr_t *addrp,
    sata_device_t *sd)
{
	ASSERT(AHCI_ADDR_IS_PMPORT(addrp));
	ASSERT(MUTEX_HELD(
	    &ahci_ctlp->ahcictl_ports[addrp->aa_port]->ahciport_mutex));

	READ_PMULT(addrp, SATA_PMULT_REG_SSTS, &sd->satadev_scr.sstatus, err);
	READ_PMULT(addrp, SATA_PMULT_REG_SERR, &sd->satadev_scr.serror, err);
	READ_PMULT(addrp, SATA_PMULT_REG_SCTL, &sd->satadev_scr.scontrol, err);
	READ_PMULT(addrp, SATA_PMULT_REG_SACT, &sd->satadev_scr.sactive, err);

	return (AHCI_SUCCESS);

err:	/* R/W PMULT error */
	return (AHCI_FAILURE);
}

/*
 * ahci_initialize_pmult()
 *
 * Initialize a port multiplier, including
 * 1. Enable FEATURES register at port multiplier. (SATA Chp.16)
 * 2. Redefine MASK register. (SATA Chap 16.?)
 */
static int
ahci_initialize_pmult(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    ahci_addr_t *addrp, sata_device_t *sd)
{
	sata_pmult_gscr_t sg;
	uint32_t gscr64;
	uint8_t port = addrp->aa_port;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_INFO|AHCIDBG_PMULT, ahci_ctlp,
	    "[Initialize] Port-multiplier at port %d.", port);

	/*
	 * Enable features of port multiplier. Currently only
	 * Asynchronous Notification is enabled.
	 */
	/* Check gscr64 for supported features. */
	READ_PMULT(addrp, SATA_PMULT_GSCR64, &gscr64, err);

	if (gscr64 & SATA_PMULT_CAP_SNOTIF) {
		AHCIDBG(AHCIDBG_INFO|AHCIDBG_PMULT, ahci_ctlp,
		    "port %d: Port Multiplier supports "
		    "Asynchronous Notification.", port);

		/* Write to gscr96 to enabled features */
		WRITE_PMULT(addrp, SATA_PMULT_GSCR96,
		    SATA_PMULT_CAP_SNOTIF, err);

		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSNTF(ahci_ctlp, port),
		    AHCI_SNOTIF_CLEAR_ALL);
		AHCIDBG(AHCIDBG_INFO|AHCIDBG_PMULT, ahci_ctlp,
		    "port %d: PMult PxSNTF cleared.", port);

	}

	/*
	 * Now we need to update gscr33 register to enable hot-plug interrupt
	 * for sub devices behind port multiplier.
	 */
	WRITE_PMULT(addrp, SATA_PMULT_GSCR33, (0x1ffff), err);
	AHCIDBG(AHCIDBG_INFO|AHCIDBG_PMULT, ahci_ctlp,
	    "port %d: gscr33 mask set to %x.", port, (0x1ffff));

	/*
	 * Fetch the number of device ports of the port multiplier
	 */
	if (ahci_update_pmult_gscr(ahci_ctlp, addrp, &sg) != AHCI_SUCCESS)
		return (AHCI_FAILURE);

	/* Register the port multiplier to SATA Framework. */
	mutex_exit(&ahci_portp->ahciport_mutex);
	sata_register_pmult(ahci_ctlp->ahcictl_dip, sd, &sg);
	mutex_enter(&ahci_portp->ahciport_mutex);

	ahci_portp->ahciport_pmult_info->ahcipmi_num_dev_ports =
	    sd->satadev_add_info & SATA_PMULT_PORTNUM_MASK;

	AHCIDBG(AHCIDBG_INFO|AHCIDBG_PMULT, ahci_ctlp,
	    "port %d: pmult sub-port number updated to %x.", port,
	    ahci_portp->ahciport_pmult_info->ahcipmi_num_dev_ports);

	/* Till now port-mult is successfully initialized */
	ahci_portp->ahciport_port_state |= SATA_DSTATE_PMULT_INIT;
	return (AHCI_SUCCESS);

err:	/* R/W PMULT error */
	return (AHCI_FAILURE);
}

/*
 * Initialize a port multiplier port. According to spec, firstly we need
 * issue a COMRESET, then a software reset to get its signature.
 *
 * NOTE: This function should only be called in ahci_probe_pmport()
 */
static int
ahci_initialize_pmport(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    ahci_addr_t *addrp)
{
	uint32_t finished_tags = 0, reset_tags = 0, slot_status = 0;
	uint8_t port = addrp->aa_port;
	uint8_t pmport = addrp->aa_pmport;
	int ret = AHCI_FAILURE;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));
	ASSERT(AHCI_ADDR_IS_PMPORT(addrp));

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_initialize_pmport: port %d:%d", port, pmport);

	/* Check HBA port state */
	if (ahci_portp->ahciport_port_state & SATA_PSTATE_FAILED) {
		AHCIDBG(AHCIDBG_INIT|AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_initialize_pmport:"
		    "port %d:%d Port Multiplier is failed.",
		    port, pmport);
		return (AHCI_FAILURE);
	}

	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_HOTPLUG) {
		return (AHCI_FAILURE);
	}
	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_HOTPLUG;

	/* Checking for outstanding commands */
	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));
		reset_tags = slot_status & AHCI_SLOT_MASK(ahci_ctlp);
	} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));
		reset_tags = slot_status & AHCI_NCQ_SLOT_MASK(ahci_portp);
	}

	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_MOPPING;
	ahci_portp->ahciport_mop_in_progress++;

	/* Clear status */
	AHCIPORT_SET_STATE(ahci_portp, addrp, SATA_STATE_UNKNOWN);

	/* Firstly assume an unknown device */
	AHCIPORT_SET_DEV_TYPE(ahci_portp, addrp, SATA_DTYPE_UNKNOWN);

	ahci_disable_port_intrs(ahci_ctlp, port);

	/* port reset is necessary for port multiplier port */
	if (ahci_pmport_reset(ahci_ctlp, ahci_portp, addrp) != AHCI_SUCCESS) {
		AHCIDBG(AHCIDBG_INIT|AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_initialize_pmport:"
		    "port reset failed at port %d:%d",
		    port, pmport);
		goto out;
	}

	/* Is port failed? */
	if (AHCIPORT_GET_STATE(ahci_portp, addrp) &
	    SATA_PSTATE_FAILED) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_initialize_pmport: port %d:%d failed. "
		    "state = 0x%x", port, pmport,
		    ahci_portp->ahciport_port_state);
		goto out;
	}

	/* Is there any device attached? */
	if (AHCIPORT_GET_DEV_TYPE(ahci_portp, addrp)
	    == SATA_DTYPE_NONE) {
		/* Do not waste time on an empty port */
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_initialize_pmport: No device is found "
		    "at port %d:%d", port, pmport);
		ret = AHCI_SUCCESS;
		goto out;
	}

	AHCIPORT_SET_STATE(ahci_portp, addrp, SATA_STATE_READY);
	AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
	    "port %d:%d is ready now.", port, pmport);

	/*
	 * Till now we can assure a device attached to that HBA port and work
	 * correctly. Now try to get the device signature. This is an optional
	 * step. If failed, unknown device is assumed, then SATA module will
	 * continue to use IDENTIFY DEVICE to get the information of the
	 * device.
	 */
	ahci_find_dev_signature(ahci_ctlp, ahci_portp, addrp);

	ret = AHCI_SUCCESS;

out:
	/* Next try to mop the pending commands */
	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp))
		finished_tags = ahci_portp->ahciport_pending_tags &
		    ~slot_status & AHCI_SLOT_MASK(ahci_ctlp);
	else if (NCQ_CMD_IN_PROGRESS(ahci_portp))
		finished_tags = ahci_portp->ahciport_pending_ncq_tags &
		    ~slot_status & AHCI_NCQ_SLOT_MASK(ahci_portp);
	reset_tags &= ~finished_tags;

	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    slot_status,
	    0, /* failed tags */
	    0, /* timeout tags */
	    0, /* aborted tags */
	    reset_tags); /* reset tags */

	/* Clear PxSNTF register if supported. */
	if (ahci_ctlp->ahcictl_cap & AHCI_CAP_SNTF) {
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSNTF(ahci_ctlp, port),
		    AHCI_SNOTIF_CLEAR_ALL);
	}

	ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_HOTPLUG;
	ahci_enable_port_intrs(ahci_ctlp, port);
	return (ret);
}

/*
 * ahci_probe_pmult()
 *
 * This function will be called to probe a port multiplier, which will
 * handle hotplug events on port multiplier ports.
 *
 * NOTE: Only called from ahci_tran_probe_port()
 */
static int
ahci_probe_pmult(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    ahci_addr_t *addrp)
{
	sata_device_t sdevice;
	ahci_addr_t pmport_addr;
	uint32_t gscr32, port_hotplug_tags;
	uint32_t pmport_sstatus;
	int dev_exists_now = 0, dev_existed_previously = 0;
	uint8_t port = addrp->aa_port;
	int npmport;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	/* The bits in GSCR32 refers to the pmport that has a hot-plug event. */
	READ_PMULT(addrp, SATA_PMULT_GSCR32, &gscr32, err);
	port_hotplug_tags = gscr32 & AHCI_PMPORT_MASK(ahci_portp);

	do {
		npmport = ddi_ffs(port_hotplug_tags) - 1;
		if (npmport == -1)
			/* no pending hot plug events. */
			return (AHCI_SUCCESS);

		AHCIDBG(AHCIDBG_EVENT|AHCIDBG_PMULT, ahci_ctlp,
		    "hot-plug event at port %d:%d", port, npmport);

		AHCI_ADDR_SET_PMPORT(&pmport_addr, port, (uint8_t)npmport);

		/* Check previous device at that port */
		if (AHCIPORT_GET_DEV_TYPE(ahci_portp, &pmport_addr)
		    != SATA_DTYPE_NONE)
			dev_existed_previously = 1;

		/* PxSStatus tells the presence of device. */
		READ_PMULT(&pmport_addr, SATA_PMULT_REG_SSTS,
		    &pmport_sstatus, err);

		if (SSTATUS_GET_DET(pmport_sstatus) ==
		    SSTATUS_DET_DEVPRE_PHYCOM)
			dev_exists_now = 1;

		/*
		 * Clear PxSERR is critical. The transition from 0 to 1 will
		 * emit a FIS which generates an asynchronous notification
		 * event at controller. If we fail to clear the PxSERR, the
		 * Async Notif events will no longer be activated on this
		 * pmport.
		 */
		WRITE_PMULT(&pmport_addr, SATA_PMULT_REG_SERR,
		    AHCI_SERROR_CLEAR_ALL, err);

		bzero((void *)&sdevice, sizeof (sata_device_t));
		sdevice.satadev_addr.cport = ahci_ctlp->
		    ahcictl_port_to_cport[port];
		sdevice.satadev_addr.qual = SATA_ADDR_PMPORT;
		sdevice.satadev_addr.pmport = (uint8_t)npmport;
		sdevice.satadev_state = SATA_PSTATE_PWRON;

		AHCIDBG(AHCIDBG_EVENT|AHCIDBG_PMULT, ahci_ctlp,
		    "[Existence] %d -> %d", dev_existed_previously,
		    dev_exists_now);

		if (dev_exists_now) {
			if (dev_existed_previously) {
				/* Link (may) not change: Exist -> Exist * */
				AHCIDBG(AHCIDBG_EVENT, ahci_ctlp,
				    "ahci_probe_pmult: port %d:%d "
				    "device link lost/established",
				    port, npmport);

				mutex_exit(&ahci_portp->ahciport_mutex);
				sata_hba_event_notify(
				    ahci_ctlp->ahcictl_sata_hba_tran->
				    sata_tran_hba_dip,
				    &sdevice,
				    SATA_EVNT_LINK_LOST|
				    SATA_EVNT_LINK_ESTABLISHED);
				mutex_enter(&ahci_portp->ahciport_mutex);
			} else {
				/* Link change: None -> Exist */
				AHCIDBG(AHCIDBG_EVENT|AHCIDBG_PMULT, ahci_ctlp,
				    "ahci_probe_pmult: port %d:%d "
				    "device link established", port, npmport);

				/* Clear port state */
				AHCIPORT_SET_STATE(ahci_portp, &pmport_addr,
				    SATA_STATE_UNKNOWN);
				AHCIDBG(AHCIDBG_EVENT|AHCIDBG_PMULT, ahci_ctlp,
				    "ahci_probe_pmult: port %d "
				    "ahciport_port_state [Cleared].", port);

				mutex_exit(&ahci_portp->ahciport_mutex);
				sata_hba_event_notify(
				    ahci_ctlp->ahcictl_sata_hba_tran->
				    sata_tran_hba_dip,
				    &sdevice,
				    SATA_EVNT_LINK_ESTABLISHED);
				mutex_enter(&ahci_portp->ahciport_mutex);
			}
		} else { /* No device exists now */
			if (dev_existed_previously) {

				/* Link change: Exist -> None */
				AHCIDBG(AHCIDBG_EVENT|AHCIDBG_PMULT, ahci_ctlp,
				    "ahci_probe_pmult: port %d:%d "
				    "device link lost", port, npmport);

				/* An existing device is lost. */
				AHCIPORT_SET_STATE(ahci_portp, &pmport_addr,
				    SATA_STATE_UNKNOWN);
				AHCIPORT_SET_DEV_TYPE(ahci_portp, &pmport_addr,
				    SATA_DTYPE_NONE);

				mutex_exit(&ahci_portp->ahciport_mutex);
				sata_hba_event_notify(
				    ahci_ctlp->ahcictl_sata_hba_tran->
				    sata_tran_hba_dip,
				    &sdevice,
				    SATA_EVNT_LINK_LOST);
				mutex_enter(&ahci_portp->ahciport_mutex);
			}
		}

		CLEAR_BIT(port_hotplug_tags, npmport);
	} while (port_hotplug_tags != 0);

	return (AHCI_SUCCESS);

err:	/* R/W PMULT error */
	return (AHCI_FAILURE);
}

/*
 * Probe and initialize a port multiplier port.
 * A port multiplier port could only be initilaizer here.
 */
static int
ahci_probe_pmport(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    ahci_addr_t *addrp, sata_device_t *sd)
{
	uint32_t port_state;
	uint8_t port = addrp->aa_port;
	ahci_addr_t addr_pmult;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	/*
	 * Check the parent - port multiplier first.
	 */

	/*
	 * Parent port multiplier might have been removed. This event will be
	 * ignored and failure.
	 */
	if (ahci_portp->ahciport_device_type == SATA_DTYPE_NONE ||
	    ahci_portp->ahciport_device_type != SATA_DTYPE_PMULT) {
		AHCIDBG(AHCIDBG_ERRS|AHCIDBG_PMULT, ahci_ctlp,
		    "ahci_tran_probe_port: "
		    "parent device removed, ignore event.", NULL);

		return (AHCI_FAILURE);
	}

	/* The port is ready? */
	port_state = ahci_portp->ahciport_port_state;
	if (!(port_state & SATA_STATE_READY)) {
		AHCIDBG(AHCIDBG_ERRS|AHCIDBG_PMULT, ahci_ctlp,
		    "ahci_tran_probe_port: "
		    "parent port-mult is NOT ready.", NULL);

		if (ahci_restart_port_wait_till_ready(ahci_ctlp,
		    ahci_portp, port, AHCI_PORT_RESET, NULL) !=
		    AHCI_SUCCESS) {
			AHCIDBG(AHCIDBG_ERRS|AHCIDBG_PMULT, ahci_ctlp,
			    "ahci_tran_probe_port: "
			    "restart port-mult failed.", NULL);
			return (AHCI_FAILURE);
		}
	}

	/*
	 * If port-mult is restarted due to some reason, we need
	 * re-initialized the PMult.
	 */
	if (!(port_state & SATA_DSTATE_PMULT_INIT)) {
		/* Initialize registers on a port multiplier */
		AHCI_ADDR_SET_PMULT(&addr_pmult, addrp->aa_port);
		if (ahci_initialize_pmult(ahci_ctlp, ahci_portp,
		    &addr_pmult, sd) != AHCI_SUCCESS)
			return (AHCI_FAILURE);
	}

	/*
	 * Then we check the port-mult port
	 */
	/* Is this pmport initialized? */
	port_state = AHCIPORT_GET_STATE(ahci_portp, addrp);
	if (!(port_state & SATA_STATE_READY)) {

		/* ahci_initialize_pmport() will set READY state */
		if (ahci_initialize_pmport(ahci_ctlp,
		    ahci_portp, addrp) != AHCI_SUCCESS)
			return (AHCI_FAILURE);
	}

	return (AHCI_SUCCESS);
}

/*
 * AHCI device reset ...; a single device on one of the ports is reset,
 * but the HBA and physical communication remain intact. This is the
 * least intrusive.
 *
 * When issuing a software reset sequence, there should not be other
 * commands in the command list, so we will first clear and then re-set
 * PxCMD.ST to clear PxCI. And before issuing the software reset,
 * the port must be idle and PxTFD.STS.BSY and PxTFD.STS.DRQ must be
 * cleared unless command list override (PxCMD.CLO) is supported.
 */
static int
ahci_software_reset(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    ahci_addr_t *addrp)
{
	ahci_fis_h2d_register_t *h2d_register_fisp;
	ahci_cmd_table_t *cmd_table;
	ahci_cmd_header_t *cmd_header;
	uint32_t port_cmd_status, port_cmd_issue, port_task_file;
	int slot, loop_count;
	uint8_t port = addrp->aa_port;
	uint8_t pmport = addrp->aa_pmport;
	int rval = AHCI_FAILURE;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "port %d:%d device software resetting (FIS)", port, pmport);

	/* First clear PxCMD.ST (AHCI v1.2 10.4.1) */
	if (ahci_put_port_into_notrunning_state(ahci_ctlp, ahci_portp,
	    port) != AHCI_SUCCESS) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_software_reset: cannot stop HBA port %d.", port);
		goto out;
	}

	/* Check PxTFD.STS.BSY and PxTFD.STS.DRQ */
	port_task_file = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));

	if (port_task_file & AHCI_TFD_STS_BSY ||
	    port_task_file & AHCI_TFD_STS_DRQ) {
		if (!(ahci_ctlp->ahcictl_cap & AHCI_CAP_SCLO)) {
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "PxTFD.STS.BSY/DRQ is set (PxTFD=0x%x), "
			    "cannot issue a software reset.", port_task_file);
			goto out;
		}

		/*
		 * If HBA Support CLO, as Command List Override (CAP.SCLO is
		 * set), PxCMD.CLO bit should be set before set PxCMD.ST, in
		 * order to clear PxTFD.STS.BSY and PxTFD.STS.DRQ.
		 */
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "PxTFD.STS.BSY/DRQ is set, try SCLO.", NULL)

		port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
		    port_cmd_status|AHCI_CMD_STATUS_CLO);

		/* Waiting till PxCMD.SCLO bit is cleared */
		loop_count = 0;
		do {
			/* Wait for 10 millisec */
			drv_usecwait(AHCI_10MS_USECS);

			/* We are effectively timing out after 1 sec. */
			if (loop_count++ > 100) {
				AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
				    "SCLO time out. port %d is busy.", port);
				goto out;
			}

			port_cmd_status =
			    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));
		} while (port_cmd_status & AHCI_CMD_STATUS_CLO);

		/* Re-check */
		port_task_file = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));
		if (port_task_file & AHCI_TFD_STS_BSY ||
		    port_task_file & AHCI_TFD_STS_DRQ) {
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "SCLO cannot clear PxTFD.STS.BSY/DRQ (PxTFD=0x%x)",
			    port_task_file);
			goto out;
		}
	}

	/* Then start port */
	if (ahci_start_port(ahci_ctlp, ahci_portp, port)
	    != AHCI_SUCCESS) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_software_reset: cannot start AHCI port %d.", port);
		goto out;
	}

	/*
	 * When ahci_port.ahciport_mop_in_progress is set, A non-zero
	 * ahci_port.ahciport_pending_ncq_tags may fail
	 * ahci_claim_free_slot(). Actually according to spec, by clearing
	 * PxCMD.ST there is no command outstanding while executing software
	 * reseting. Hence we directly use slot 0 instead of
	 * ahci_claim_free_slot().
	 */
	slot = 0;

	/* Now send the first H2D Register FIS with SRST set to 1 */
	cmd_table = ahci_portp->ahciport_cmd_tables[slot];
	bzero((void *)cmd_table, ahci_cmd_table_size);

	h2d_register_fisp =
	    &(cmd_table->ahcict_command_fis.ahcifc_fis.ahcifc_h2d_register);

	SET_FIS_TYPE(h2d_register_fisp, AHCI_H2D_REGISTER_FIS_TYPE);
	SET_FIS_PMP(h2d_register_fisp, pmport);
	SET_FIS_DEVCTL(h2d_register_fisp, SATA_DEVCTL_SRST);

	/* Set Command Header in Command List */
	cmd_header = &ahci_portp->ahciport_cmd_list[slot];
	BZERO_DESCR_INFO(cmd_header);
	BZERO_PRD_BYTE_COUNT(cmd_header);
	SET_COMMAND_FIS_LENGTH(cmd_header, 5);
	SET_PORT_MULTI_PORT(cmd_header, pmport);

	SET_CLEAR_BUSY_UPON_R_OK(cmd_header, 1);
	SET_RESET(cmd_header, 1);
	SET_WRITE(cmd_header, 1);

	(void) ddi_dma_sync(ahci_portp->ahciport_cmd_tables_dma_handle[slot],
	    0,
	    ahci_cmd_table_size,
	    DDI_DMA_SYNC_FORDEV);

	(void) ddi_dma_sync(ahci_portp->ahciport_cmd_list_dma_handle,
	    slot * sizeof (ahci_cmd_header_t),
	    sizeof (ahci_cmd_header_t),
	    DDI_DMA_SYNC_FORDEV);

	/* Indicate to the HBA that a command is active. */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port),
	    (0x1 << slot));

	loop_count = 0;

	/* Loop till the first command is finished */
	do {
		port_cmd_issue = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

		/* We are effectively timing out after 1 sec. */
		if (loop_count++ > AHCI_POLLRATE_PORT_SOFTRESET) {
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "the first SRST FIS is timed out, "
			    "loop_count = %d", loop_count);
			goto out;
		}
		/* Wait for 10 millisec */
		drv_usecwait(AHCI_10MS_USECS);
	} while (port_cmd_issue & AHCI_SLOT_MASK(ahci_ctlp) & (0x1 << slot));

	AHCIDBG(AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_software_reset: 1st loop count: %d, "
	    "port_cmd_issue = 0x%x, slot = 0x%x",
	    loop_count, port_cmd_issue, slot);

	/* According to ATA spec, we need wait at least 5 microsecs here. */
	drv_usecwait(AHCI_1MS_USECS);

	/* Now send the second H2D Register FIS with SRST cleard to zero */
	cmd_table = ahci_portp->ahciport_cmd_tables[slot];
	bzero((void *)cmd_table, ahci_cmd_table_size);

	h2d_register_fisp =
	    &(cmd_table->ahcict_command_fis.ahcifc_fis.ahcifc_h2d_register);

	SET_FIS_TYPE(h2d_register_fisp, AHCI_H2D_REGISTER_FIS_TYPE);
	SET_FIS_PMP(h2d_register_fisp, pmport);

	/* Set Command Header in Command List */
	cmd_header = &ahci_portp->ahciport_cmd_list[slot];
	BZERO_DESCR_INFO(cmd_header);
	BZERO_PRD_BYTE_COUNT(cmd_header);
	SET_COMMAND_FIS_LENGTH(cmd_header, 5);
	SET_PORT_MULTI_PORT(cmd_header, pmport);

	SET_WRITE(cmd_header, 1);

	(void) ddi_dma_sync(ahci_portp->ahciport_cmd_tables_dma_handle[slot],
	    0,
	    ahci_cmd_table_size,
	    DDI_DMA_SYNC_FORDEV);

	(void) ddi_dma_sync(ahci_portp->ahciport_cmd_list_dma_handle,
	    slot * sizeof (ahci_cmd_header_t),
	    sizeof (ahci_cmd_header_t),
	    DDI_DMA_SYNC_FORDEV);

	/* Indicate to the HBA that a command is active. */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port),
	    (0x1 << slot));

	loop_count = 0;

	/* Loop till the second command is finished */
	do {
		port_cmd_issue = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

		/* We are effectively timing out after 1 sec. */
		if (loop_count++ > AHCI_POLLRATE_PORT_SOFTRESET) {
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "the second SRST FIS is timed out, "
			    "loop_count = %d", loop_count);
			goto out;
		}

		/* Wait for 10 millisec */
		drv_usecwait(AHCI_10MS_USECS);
	} while (port_cmd_issue & AHCI_SLOT_MASK(ahci_ctlp) & (0x1 << slot));

	AHCIDBG(AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_software_reset: 2nd loop count: %d, "
	    "port_cmd_issue = 0x%x, slot = 0x%x",
	    loop_count, port_cmd_issue, slot);

	if ((ahci_check_ctl_handle(ahci_ctlp) != DDI_SUCCESS) ||
	    (ahci_check_port_handle(ahci_ctlp, port) != DDI_SUCCESS)) {
		ddi_fm_service_impact(ahci_ctlp->ahcictl_dip,
		    DDI_SERVICE_UNAFFECTED);
		goto out;
	}

	rval = AHCI_SUCCESS;
out:
	AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
	    "ahci_software_reset: %s at port %d:%d",
	    rval == AHCI_SUCCESS ? "succeed" : "failed",
	    port, pmport);

	return (rval);
}

/*
 * AHCI port reset ...; the physical communication between the HBA and device
 * on a port are disabled. This is more intrusive.
 *
 * When an HBA or port reset occurs, Phy communication is going to
 * be re-established with the device through a COMRESET followed by the
 * normal out-of-band communication sequence defined in Serial ATA. At
 * the end of reset, the device, if working properly, will send a D2H
 * Register FIS, which contains the device signature. When the HBA receives
 * this FIS, it updates PxTFD.STS and PxTFD.ERR register fields, and updates
 * the PxSIG register with the signature.
 *
 * NOTE: It is expected both PxCMD.ST and PxCMD.CR are cleared before the
 * function is called. If not, it is assumed the interface is in hung
 * condition.
 */
static int
ahci_port_reset(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    ahci_addr_t *addrp)
{
	ahci_addr_t pmult_addr;
	uint32_t port_cmd_status;
	uint32_t port_scontrol, port_sstatus;
	uint32_t port_task_file;
	uint32_t port_state;
	uint8_t port = addrp->aa_port;

	int loop_count;
	int instance = ddi_get_instance(ahci_ctlp->ahcictl_dip);

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	/* Target is a port multiplier port? */
	if (AHCI_ADDR_IS_PMPORT(addrp))
		return (ahci_pmport_reset(ahci_ctlp, ahci_portp, addrp));

	/* Otherwise it must be an HBA port. */
	ASSERT(AHCI_ADDR_IS_PORT(addrp));

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "Port %d port resetting...", port);
	ahci_portp->ahciport_port_state = 0;

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	/*
	 * According to the spec, SUD bit should be set here,
	 * but JMicron JMB363 doesn't follow it, so print
	 * a debug message.
	 */
	if (!(port_cmd_status & AHCI_CMD_STATUS_SUD))
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_port_reset: port %d SUD bit not set", port);

	port_scontrol = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port));
	SCONTROL_SET_DET(port_scontrol, SCONTROL_DET_COMRESET);

	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port),
	    port_scontrol);

	/* Enable PxCMD.FRE to read device */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
	    port_cmd_status|AHCI_CMD_STATUS_FRE);

	/*
	 * The port enters P:StartComm state, and the HBA tells the link layer
	 * to start communication, which involves sending COMRESET to the
	 * device. And the HBA resets PxTFD.STS to 7Fh.
	 *
	 * Give time for COMRESET to percolate, according to the AHCI
	 * spec, software shall wait at least 1 millisecond before
	 * clearing PxSCTL.DET
	 */
	drv_usecwait(AHCI_1MS_USECS * 2);

	/* Fetch the SCONTROL again and rewrite the DET part with 0 */
	port_scontrol = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port));
	SCONTROL_SET_DET(port_scontrol, SCONTROL_DET_NOACTION);
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port),
	    port_scontrol);

	/*
	 * When a COMINIT is received from the device, then the port enters
	 * P:ComInit state. And HBA sets PxTFD.STS to FFh or 80h. HBA sets
	 * PxSSTS.DET to 1h to indicate a device is detected but communication
	 * is not yet established. HBA sets PxSERR.DIAG.X to '1' to indicate
	 * a COMINIT has been received.
	 */
	/*
	 * The DET field is valid only if IPM field indicates
	 * that the interface is in active state.
	 */
	loop_count = 0;
	for (;;) {
		port_sstatus = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSSTS(ahci_ctlp, port));

		if (SSTATUS_GET_IPM(port_sstatus) != SSTATUS_IPM_ACTIVE) {
			/*
			 * If the interface is not active, the DET field
			 * is considered not accurate. So we want to
			 * continue looping.
			 */
			SSTATUS_SET_DET(port_sstatus, SSTATUS_DET_NODEV);
		}

		if (SSTATUS_GET_DET(port_sstatus) == SSTATUS_DET_DEVPRE_PHYCOM)
			break;

		if (loop_count++ > AHCI_POLLRATE_PORT_SSTATUS) {
			/*
			 * We are effectively timing out after 0.1 sec.
			 */
			break;
		}

		/* Wait for 10 millisec */
		drv_usecwait(AHCI_10MS_USECS);
	}

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_port_reset: 1st loop count: %d, "
	    "port_sstatus = 0x%x port %d",
	    loop_count, port_sstatus, port);

	if (SSTATUS_GET_DET(port_sstatus) != SSTATUS_DET_DEVPRE_PHYCOM) {
		/*
		 * Either the port is not active or there
		 * is no device present.
		 */
		AHCIPORT_SET_DEV_TYPE(ahci_portp, addrp, SATA_DTYPE_NONE);
		return (AHCI_SUCCESS);
	}

	/* Clear port serror register for the port */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port),
	    AHCI_SERROR_CLEAR_ALL);

	/*
	 * Devices should return a FIS contains its signature to HBA after
	 * COMINIT signal. Check whether a D2H Register FIS is received by
	 * polling PxTFD.STS.
	 */
	loop_count = 0;
	for (;;) {
		port_task_file =
		    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));

		if ((port_task_file & (AHCI_TFD_STS_BSY | AHCI_TFD_STS_DRQ |
		    AHCI_TFD_STS_ERR)) == 0)
			break;

		if (loop_count++ > AHCI_POLLRATE_PORT_TFD_ERROR) {
			/*
			 * We are effectively timing out after 11 sec.
			 */
			cmn_err(CE_WARN, "!ahci%d: ahci_port_reset port %d "
			    "the device hardware has been initialized and "
			    "the power-up diagnostics failed",
			    instance, port);

			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_port_reset: "
			    "port %d: some or all of BSY, DRQ and ERR in "
			    "PxTFD.STS are not clear. We need another "
			    "software reset.", port);

			/* Clear port serror register for the port */
			ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port),
			    AHCI_SERROR_CLEAR_ALL);

			AHCI_ADDR_SET_PMULT(&pmult_addr, port);

			/* Try another software reset. */
			if (ahci_software_reset(ahci_ctlp, ahci_portp,
			    &pmult_addr) != AHCI_SUCCESS) {
				AHCIPORT_SET_STATE(ahci_portp, addrp,
				    SATA_PSTATE_FAILED);
				return (AHCI_FAILURE);
			}
			break;
		}

		/* Wait for 10 millisec */
		drv_usecwait(AHCI_10MS_USECS);
	}

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_port_reset: 2nd loop count: %d, "
	    "port_task_file = 0x%x port %d",
	    loop_count, port_task_file, port);

	/* Clear port serror register for the port */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port),
	    AHCI_SERROR_CLEAR_ALL);

	/* Set port as ready */
	port_state = AHCIPORT_GET_STATE(ahci_portp, addrp);
	AHCIPORT_SET_STATE(ahci_portp, addrp, port_state|SATA_STATE_READY);

	AHCIDBG(AHCIDBG_INFO|AHCIDBG_ERRS, ahci_ctlp,
	    "ahci_port_reset: succeed at port %d.", port);
	return (AHCI_SUCCESS);
}

/*
 * COMRESET on a port multiplier port.
 *
 * NOTE: Only called in ahci_port_reset()
 */
static int
ahci_pmport_reset(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    ahci_addr_t *addrp)
{
	uint32_t port_scontrol, port_sstatus, port_serror;
	uint32_t port_cmd_status, port_intr_status;
	uint32_t port_state;
	uint8_t port = addrp->aa_port;
	uint8_t pmport = addrp->aa_pmport;
	int loop_count;
	int instance = ddi_get_instance(ahci_ctlp->ahcictl_dip);

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "port %d:%d: pmport resetting", port, pmport);

	/* Initialize pmport state */
	AHCIPORT_SET_STATE(ahci_portp, addrp, 0);

	READ_PMULT(addrp, SATA_PMULT_REG_SCTL, &port_scontrol, err);
	SCONTROL_SET_DET(port_scontrol, SCONTROL_DET_COMRESET);
	WRITE_PMULT(addrp, SATA_PMULT_REG_SCTL, port_scontrol, err);

	/* PxCMD.FRE should be set before. */
	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));
	ASSERT(port_cmd_status & AHCI_CMD_STATUS_FRE);
	if (!(port_cmd_status & AHCI_CMD_STATUS_FRE))
		return (AHCI_FAILURE);

	/*
	 * Give time for COMRESET to percolate, according to the AHCI
	 * spec, software shall wait at least 1 millisecond before
	 * clearing PxSCTL.DET
	 */
	drv_usecwait(AHCI_1MS_USECS*2);

	/*
	 * Fetch the SCONTROL again and rewrite the DET part with 0
	 * This will generate an Asychronous Notification events.
	 */
	READ_PMULT(addrp, SATA_PMULT_REG_SCTL, &port_scontrol, err);
	SCONTROL_SET_DET(port_scontrol, SCONTROL_DET_NOACTION);
	WRITE_PMULT(addrp, SATA_PMULT_REG_SCTL, port_scontrol, err);

	/*
	 * The port enters P:StartComm state, and HBA tells link layer to
	 * start communication, which involves sending COMRESET to device.
	 * And the HBA resets PxTFD.STS to 7Fh.
	 *
	 * When a COMINIT is received from the device, then the port enters
	 * P:ComInit state. And HBA sets PxTFD.STS to FFh or 80h. HBA sets
	 * PxSSTS.DET to 1h to indicate a device is detected but communication
	 * is not yet established. HBA sets PxSERR.DIAG.X to '1' to indicate
	 * a COMINIT has been received.
	 */
	/*
	 * The DET field is valid only if IPM field indicates
	 * that the interface is in active state.
	 */
	loop_count = 0;
	do {
		READ_PMULT(addrp, SATA_PMULT_REG_SSTS, &port_sstatus, err);

		if (SSTATUS_GET_IPM(port_sstatus) != SSTATUS_IPM_ACTIVE) {
			/*
			 * If the interface is not active, the DET field
			 * is considered not accurate. So we want to
			 * continue looping.
			 */
			SSTATUS_SET_DET(port_sstatus, SSTATUS_DET_NODEV);
		}

		if (loop_count++ > AHCI_POLLRATE_PORT_SSTATUS) {
			/*
			 * We are effectively timing out after 0.1 sec.
			 */
			break;
		}

		/* Wait for 10 millisec */
		drv_usecwait(AHCI_10MS_USECS);

	} while (SSTATUS_GET_DET(port_sstatus) != SSTATUS_DET_DEVPRE_PHYCOM);

	AHCIDBG(AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_pmport_reset: 1st loop count: %d, "
	    "port_sstatus = 0x%x port %d:%d",
	    loop_count, port_sstatus, port, pmport);

	if ((SSTATUS_GET_IPM(port_sstatus) != SSTATUS_IPM_ACTIVE) ||
	    (SSTATUS_GET_DET(port_sstatus) != SSTATUS_DET_DEVPRE_PHYCOM)) {
		/*
		 * Either the port is not active or there
		 * is no device present.
		 */
		AHCIDBG(AHCIDBG_INIT|AHCIDBG_INFO, ahci_ctlp,
		    "ahci_pmport_reset: "
		    "no device attached to port %d:%d",
		    port, pmport);
		AHCIPORT_SET_DEV_TYPE(ahci_portp, addrp, SATA_DTYPE_NONE);
		return (AHCI_SUCCESS);
	}

	/* Now we can make sure there is a device connected to the port */
	/* COMINIT signal is supposed to be received (PxSERR.DIAG.X = '1') */
	READ_PMULT(addrp, SATA_PMULT_REG_SERR, &port_serror, err);

	if (!(port_serror & (1 << 26))) {
		cmn_err(CE_WARN, "!ahci%d: ahci_pmport_reset: "
		    "COMINIT signal from the device not received port %d:%d",
		    instance, port, pmport);

		AHCIPORT_SET_STATE(ahci_portp, addrp, SATA_PSTATE_FAILED);
		return (AHCI_FAILURE);
	}

	/*
	 * After clear PxSERR register, we will receive a D2H FIS.
	 * Normally this FIS will cause a IPMS error according to AHCI spec
	 * v1.2 because there is no command outstanding for it. So we need
	 * to ignore this error.
	 */
	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_IGNORE_IPMS;
	WRITE_PMULT(addrp, SATA_PMULT_REG_SERR, AHCI_SERROR_CLEAR_ALL, err);

	/* Now we need to check the D2H FIS by checking IPMS error. */
	loop_count = 0;
	do {
		port_intr_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxIS(ahci_ctlp, port));

		if (loop_count++ > AHCI_POLLRATE_PORT_TFD_ERROR) {
			/*
			 * No D2H FIS received. This is possible according
			 * to SATA 2.6 spec.
			 */
			cmn_err(CE_WARN, "ahci_port_reset: port %d:%d "
			    "PxIS.IPMS is not set, we need another "
			    "software reset.", port, pmport);

			break;
		}

		/* Wait for 10 millisec */
		mutex_exit(&ahci_portp->ahciport_mutex);
		delay(AHCI_10MS_TICKS);
		mutex_enter(&ahci_portp->ahciport_mutex);

	} while (!(port_intr_status & AHCI_INTR_STATUS_IPMS));

	AHCIDBG(AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_pmport_reset: 2st loop count: %d, "
	    "port_sstatus = 0x%x port %d:%d",
	    loop_count, port_sstatus, port, pmport);

	/* Clear IPMS */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxIS(ahci_ctlp, port),
	    AHCI_INTR_STATUS_IPMS);
	ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_IGNORE_IPMS;

	/* This pmport is now ready for ahci_tran_start() */
	port_state = AHCIPORT_GET_STATE(ahci_portp, addrp);
	AHCIPORT_SET_STATE(ahci_portp, addrp, port_state|SATA_STATE_READY);

	AHCIDBG(AHCIDBG_INFO|AHCIDBG_ERRS, ahci_ctlp,
	    "ahci_pmport_reset: succeed at port %d:%d", port, pmport);
	return (AHCI_SUCCESS);

err:	/* R/W PMULT error */
	/* IPMS flags might be set before. */
	ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_IGNORE_IPMS;
	AHCIDBG(AHCIDBG_INFO|AHCIDBG_ERRS, ahci_ctlp,
	    "ahci_pmport_reset: failed at port %d:%d", port, pmport);

	return (AHCI_FAILURE);
}

/*
 * AHCI HBA reset ...; the entire HBA is reset, and all ports are disabled.
 * This is the most intrusive.
 *
 * When an HBA reset occurs, Phy communication will be re-established with
 * the device through a COMRESET followed by the normal out-of-band
 * communication sequence defined in Serial ATA. At the end of reset, the
 * device, if working properly, will send a D2H Register FIS, which contains
 * the device signature. When the HBA receives this FIS, it updates PxTFD.STS
 * and PxTFD.ERR register fields, and updates the PxSIG register with the
 * signature.
 *
 * Remember to set GHC.AE to 1 before calling ahci_hba_reset.
 */
static int
ahci_hba_reset(ahci_ctl_t *ahci_ctlp)
{
	ahci_port_t *ahci_portp;
	uint32_t ghc_control;
	uint8_t port;
	int loop_count;
	int rval = AHCI_SUCCESS;

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp, "HBA resetting",
	    NULL);

	mutex_enter(&ahci_ctlp->ahcictl_mutex);

	ghc_control = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp));

	/* Setting GHC.HR to 1, remember GHC.AE is already set to 1 before */
	ghc_control |= AHCI_HBA_GHC_HR;
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp), ghc_control);

	/*
	 * Wait until HBA Reset complete or timeout
	 */
	loop_count = 0;
	do {
		ghc_control = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp));

		if (loop_count++ > AHCI_POLLRATE_HBA_RESET) {
			AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
			    "ahci hba reset is timing out, "
			    "ghc_control = 0x%x", ghc_control);
			/* We are effectively timing out after 1 sec. */
			break;
		}

		/* Wait for 10 millisec */
		drv_usecwait(AHCI_10MS_USECS);
	} while (ghc_control & AHCI_HBA_GHC_HR);

	AHCIDBG(AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_hba_reset: 1st loop count: %d, "
	    "ghc_control = 0x%x", loop_count, ghc_control);

	if (ghc_control & AHCI_HBA_GHC_HR) {
		/* The hba is not reset for some reasons */
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "hba reset failed: HBA in a hung or locked state", NULL);
		mutex_exit(&ahci_ctlp->ahcictl_mutex);
		return (AHCI_FAILURE);
	}

	/*
	 * HBA reset will clear (AHCI Spec v1.2 10.4.3) GHC.IE / GHC.AE
	 */
	ghc_control = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp));
	ghc_control |= (AHCI_HBA_GHC_AE | AHCI_HBA_GHC_IE);
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp), ghc_control);

	mutex_exit(&ahci_ctlp->ahcictl_mutex);

	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		/* Only check implemented ports */
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			continue;
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];
		mutex_enter(&ahci_portp->ahciport_mutex);

		/* Make sure the drive is spun-up */
		ahci_staggered_spin_up(ahci_ctlp, port);

		if (ahci_restart_port_wait_till_ready(ahci_ctlp, ahci_portp,
		    port, AHCI_PORT_RESET|AHCI_RESET_NO_EVENTS_UP, NULL) !=
		    AHCI_SUCCESS) {
			rval = AHCI_FAILURE;
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_hba_reset: port %d failed", port);
			/*
			 * Set the port state to SATA_PSTATE_FAILED if
			 * failed to initialize it.
			 */
			ahci_portp->ahciport_port_state = SATA_PSTATE_FAILED;
		}

		mutex_exit(&ahci_portp->ahciport_mutex);
	}

	return (rval);
}

/*
 * This routine is only called from AHCI_ATTACH or phyrdy change
 * case. It first calls software reset, then stop the port and try to
 * read PxSIG register to find the type of device attached to the port.
 *
 * The caller should make sure a valid device exists on specified port and
 * physical communication has been established so that the signature could
 * be retrieved by software reset.
 *
 * NOTE: The port interrupts should be disabled before the function is called.
 */
static void
ahci_find_dev_signature(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    ahci_addr_t *addrp)
{
	ahci_addr_t dev_addr;
	uint32_t signature;
	uint8_t port = addrp->aa_port;
	uint8_t pmport = addrp->aa_pmport;
	int rval;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));
	ASSERT(AHCI_ADDR_IS_VALID(addrp));

	/*
	 * If the HBA doesn't support port multiplier, then the driver
	 * doesn't need to bother to check port multiplier device.
	 *
	 * The second port of ICH7 on ASUS P5W DH deluxe motherboard is
	 * connected to Silicon Image 4723, to which the two sata drives
	 * attached can be set with RAID1, RAID0 or Spanning mode.
	 *
	 * We found software reset will get failure if port multiplier address
	 * 0xf is used by software reset, so just ignore the check since
	 * ICH7 doesn't support port multiplier device at all.
	 */
	if (AHCI_ADDR_IS_PORT(addrp) &&
	    (ahci_ctlp->ahcictl_cap & AHCI_CAP_PMULT_CBSS)) {
		AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
		    "ahci_find_dev_signature enter: port %d", port);

		/*
		 * NOTE: when the ahci address is a HBA port, we do not know
		 * it is a device or a port multiplier that attached. we need
		 * try a software reset at port multiplier address (0xf
		 * pmport)
		 */
		AHCI_ADDR_SET_PMULT(&dev_addr, addrp->aa_port);
	} else {
		AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
		    "ahci_find_dev_signature enter: port %d:%d",
		    port, pmport);
		dev_addr = *addrp;
	}

	/* Assume it is unknown. */
	AHCIPORT_SET_DEV_TYPE(ahci_portp, addrp, SATA_DTYPE_UNKNOWN);

	/* Issue a software reset to get the signature */
	rval = ahci_software_reset(ahci_ctlp, ahci_portp, &dev_addr);
	if (rval != AHCI_SUCCESS) {

		/*
		 * Try to do software reset again with pmport set with 0 if
		 * the controller is set with AHCI_CAP_SRST_NO_HOSTPORT and
		 * the original pmport is set with SATA_PMULT_HOSTPORT (0xf)
		 */
		if ((ahci_ctlp->ahcictl_cap & AHCI_CAP_SRST_NO_HOSTPORT) &&
		    (dev_addr.aa_pmport == SATA_PMULT_HOSTPORT)) {
			dev_addr.aa_pmport = 0;
			rval = ahci_software_reset(ahci_ctlp, ahci_portp,
			    &dev_addr);
		}

		if (rval != AHCI_SUCCESS) {
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_find_dev_signature: software reset failed "
			    "at port %d:%d, cannot get signature.",
			    port, pmport);

			AHCIPORT_SET_STATE(ahci_portp, addrp,
			    SATA_PSTATE_FAILED);
			return;
		}
	}

	/*
	 * ahci_software_reset has started the port, so we need manually stop
	 * the port again.
	 */
	if (AHCI_ADDR_IS_PORT(addrp)) {
		if (ahci_put_port_into_notrunning_state(ahci_ctlp,
		    ahci_portp, port) != AHCI_SUCCESS) {
			AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
			    "ahci_find_dev_signature: cannot stop port %d.",
			    port);
			ahci_portp->ahciport_port_state = SATA_PSTATE_FAILED;
			return;
		}
	}

	/* Now we can make sure that a valid signature is received. */
	signature = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSIG(ahci_ctlp, port));

	if (AHCI_ADDR_IS_PMPORT(addrp)) {
		AHCIDBG(AHCIDBG_INIT|AHCIDBG_INFO|AHCIDBG_PMULT, ahci_ctlp,
		    "ahci_find_dev_signature: signature = 0x%x at port %d:%d",
		    signature, port, pmport);
	} else {
		AHCIDBG(AHCIDBG_INIT|AHCIDBG_INFO, ahci_ctlp,
		    "ahci_find_dev_signature: signature = 0x%x at port %d",
		    signature, port);
	}

	/* NOTE: Only support ATAPI device at controller port. */
	if (signature == AHCI_SIGNATURE_ATAPI && !AHCI_ADDR_IS_PORT(addrp))
		signature = SATA_DTYPE_UNKNOWN;

	switch (signature) {

	case AHCI_SIGNATURE_DISK:
		AHCIPORT_SET_DEV_TYPE(ahci_portp, addrp, SATA_DTYPE_ATADISK);
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "Disk is found at port: %d", port);
		break;

	case AHCI_SIGNATURE_ATAPI:
		AHCIPORT_SET_DEV_TYPE(ahci_portp, addrp, SATA_DTYPE_ATAPI);
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ATAPI device is found at port: %d", port);
		break;

	case AHCI_SIGNATURE_PORT_MULTIPLIER:
		/* Port Multiplier cannot recursively attached. */
		ASSERT(AHCI_ADDR_IS_PORT(addrp));
		AHCIPORT_SET_DEV_TYPE(ahci_portp, addrp, SATA_DTYPE_PMULT);
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "Port Multiplier is found at port: %d", port);
		break;

	default:
		AHCIPORT_SET_DEV_TYPE(ahci_portp, addrp, SATA_DTYPE_UNKNOWN);
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "Unknown device is found at port: %d", port);
	}
}

/*
 * According to the spec, to reliably detect hot plug removals, software
 * must disable interface power management. Software should perform the
 * following initialization on a port after a device is attached:
 *   Set PxSCTL.IPM to 3h to disable interface state transitions
 *   Set PxCMD.ALPE to '0' to disable aggressive power management
 *   Disable device initiated interface power management by SET FEATURE
 *
 * We can ignore the last item because by default the feature is disabled
 */
static void
ahci_disable_interface_pm(ahci_ctl_t *ahci_ctlp, uint8_t port)
{
	uint32_t port_scontrol, port_cmd_status;

	port_scontrol = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port));
	SCONTROL_SET_IPM(port_scontrol, SCONTROL_IPM_DISABLE_BOTH);
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port), port_scontrol);

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));
	port_cmd_status &= ~AHCI_CMD_STATUS_ALPE;
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port), port_cmd_status);
}

/*
 * Start the port - set PxCMD.ST to 1, if PxCMD.FRE is not set
 * to 1, then set it firstly.
 *
 * Each port contains two major DMA engines. One DMA engine walks through
 * the command list, and is controlled by PxCMD.ST. The second DMA engine
 * copies received FISes into system memory, and is controlled by PxCMD.FRE.
 *
 * Software shall not set PxCMD.ST to '1' until it verifies that PxCMD.CR
 * is '0' and has set PxCMD.FRE is '1'. And software shall not clear
 * PxCMD.FRE while PxCMD.ST or PxCMD.CR is set '1'.
 *
 * Software shall not set PxCMD.ST to '1' unless a functional device is
 * present on the port(as determined by PxTFD.STS.BSY = '0',
 * PxTFD.STS.DRQ = '0', and PxSSTS.DET = 3h).
 */
static int
ahci_start_port(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_cmd_status;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp, "ahci_start_port: %d enter", port);

	if (ahci_portp->ahciport_port_state & SATA_PSTATE_FAILED) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_start_port failed "
		    "the state for port %d is 0x%x",
		    port, ahci_portp->ahciport_port_state);
		return (AHCI_FAILURE);
	}

	if (ahci_portp->ahciport_device_type == SATA_DTYPE_NONE) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_start_port failed "
		    "no device is attached at port %d", port);
		return (AHCI_FAILURE);
	}

	/* First to set PxCMD.FRE before setting PxCMD.ST. */
	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	if (!(port_cmd_status & AHCI_CMD_STATUS_FRE)) {
		port_cmd_status |= AHCI_CMD_STATUS_FRE;
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
		    port_cmd_status);
	}

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	port_cmd_status |= AHCI_CMD_STATUS_ST;

	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
	    port_cmd_status);

	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_STARTED;

	AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_start_port: "
	    "PxCMD.ST set to '1' at port %d", port);

	return (AHCI_SUCCESS);
}

/*
 * Setup PxCLB, PxCLBU, PxFB, and PxFBU for particular port. First, we need
 * to make sure PxCMD.ST, PxCMD.CR, PxCMD.FRE, and PxCMD.FR are all cleared.
 * Then set PxCLB, PxCLBU, PxFB, and PxFBU.
 */
static int
ahci_setup_port_base_addresses(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
	uint8_t port = ahci_portp->ahciport_port_num;
	uint32_t port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	/* Step 1: Make sure both PxCMD.ST and PxCMD.CR are cleared. */
	if (port_cmd_status & (AHCI_CMD_STATUS_ST | AHCI_CMD_STATUS_CR)) {
		if (ahci_put_port_into_notrunning_state(ahci_ctlp, ahci_portp,
		    port) != AHCI_SUCCESS)
			return (AHCI_FAILURE);

		port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));
	}

	/* Step 2: Make sure both PxCMD.FRE and PxCMD.FR are cleared. */
	if (port_cmd_status & (AHCI_CMD_STATUS_FRE | AHCI_CMD_STATUS_FR)) {
		int loop_count = 0;

		/* Clear PxCMD.FRE */
		port_cmd_status &= ~AHCI_CMD_STATUS_FRE;
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
		    port_cmd_status);

		/* Wait until PxCMD.FR is cleared */
		for (;;) {
			port_cmd_status =
			    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

			if (!(port_cmd_status & AHCI_CMD_STATUS_FR))
				break;

			if (loop_count++ >= AHCI_POLLRATE_PORT_IDLE_FR) {
				AHCIDBG(AHCIDBG_INIT | AHCIDBG_ERRS, ahci_ctlp,
				    "ahci_setup_port_base_addresses: cannot "
				    "clear PxCMD.FR for port %d.", port);

				/*
				 * We are effectively timing out after 0.5 sec.
				 * This value is specified in AHCI spec.
				 */
				return (AHCI_FAILURE);
			}

			/* Wait for 1 millisec */
			drv_usecwait(AHCI_1MS_USECS);
		}
	}

	/* Step 3: Config Port Command List Base Address */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCLB(ahci_ctlp, port),
	    ahci_portp->ahciport_cmd_list_dma_cookie.dmac_address);

	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCLBU(ahci_ctlp, port),
	    ahci_portp->ahciport_cmd_list_dma_cookie.dmac_notused);

	/* Step 4: Config Port Received FIS Base Address */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxFB(ahci_ctlp, port),
	    ahci_portp->ahciport_rcvd_fis_dma_cookie.dmac_address);

	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxFBU(ahci_ctlp, port),
	    ahci_portp->ahciport_rcvd_fis_dma_cookie.dmac_notused);

	return (AHCI_SUCCESS);
}

/*
 * Allocate the ahci_port_t including Received FIS and Command List.
 * The argument - port is the physical port number, and not logical
 * port number seen by the SATA framework.
 */
static int
ahci_alloc_port_state(ahci_ctl_t *ahci_ctlp, uint8_t port)
{
	dev_info_t *dip = ahci_ctlp->ahcictl_dip;
	ahci_port_t *ahci_portp;
	char taskq_name[64] = "event_handle_taskq";

	ASSERT(MUTEX_HELD(&ahci_ctlp->ahcictl_mutex));

	ahci_portp =
	    (ahci_port_t *)kmem_zalloc(sizeof (ahci_port_t), KM_SLEEP);

	ahci_ctlp->ahcictl_ports[port] = ahci_portp;
	ahci_portp->ahciport_port_num = port;

	/* Initialize the port condition variable */
	cv_init(&ahci_portp->ahciport_cv, NULL, CV_DRIVER, NULL);

	/* Initialize the port mutex */
	mutex_init(&ahci_portp->ahciport_mutex, NULL, MUTEX_DRIVER,
	    (void *)(uintptr_t)ahci_ctlp->ahcictl_intr_pri);

	mutex_enter(&ahci_portp->ahciport_mutex);

	/*
	 * Allocate memory for received FIS structure and
	 * command list for this port
	 */
	if (ahci_alloc_rcvd_fis(ahci_ctlp, ahci_portp) != AHCI_SUCCESS) {
		goto err_case1;
	}

	if (ahci_alloc_cmd_list(ahci_ctlp, ahci_portp) != AHCI_SUCCESS) {
		goto err_case2;
	}

	/* Setup PxCMD.CLB, PxCMD.CLBU, PxCMD.FB, and PxCMD.FBU */
	if (ahci_setup_port_base_addresses(ahci_ctlp, ahci_portp) !=
	    AHCI_SUCCESS) {
		goto err_case3;
	}

	(void) snprintf(taskq_name + strlen(taskq_name),
	    sizeof (taskq_name) - strlen(taskq_name),
	    "_port%d", port);

	/* Create the taskq for the port */
	if ((ahci_portp->ahciport_event_taskq = ddi_taskq_create(dip,
	    taskq_name, 2, TASKQ_DEFAULTPRI, 0)) == NULL) {
		cmn_err(CE_WARN, "!ahci%d: ddi_taskq_create failed for event "
		    "handle", ddi_get_instance(ahci_ctlp->ahcictl_dip));
		goto err_case3;
	}

	/* Allocate the argument for the taskq */
	ahci_portp->ahciport_event_args =
	    kmem_zalloc(sizeof (ahci_event_arg_t), KM_SLEEP);

	ahci_portp->ahciport_event_args->ahciea_addrp =
	    kmem_zalloc(sizeof (ahci_addr_t), KM_SLEEP);

	if (ahci_portp->ahciport_event_args == NULL)
		goto err_case4;

	/* Initialize the done queue */
	ahci_portp->ahciport_doneq = NULL;
	ahci_portp->ahciport_doneqtail = &ahci_portp->ahciport_doneq;
	ahci_portp->ahciport_doneq_len = 0;

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);

err_case4:
	ddi_taskq_destroy(ahci_portp->ahciport_event_taskq);

err_case3:
	ahci_dealloc_cmd_list(ahci_ctlp, ahci_portp);

err_case2:
	ahci_dealloc_rcvd_fis(ahci_portp);

err_case1:
	mutex_exit(&ahci_portp->ahciport_mutex);
	mutex_destroy(&ahci_portp->ahciport_mutex);
	cv_destroy(&ahci_portp->ahciport_cv);

	kmem_free(ahci_portp, sizeof (ahci_port_t));

	return (AHCI_FAILURE);
}

/*
 * Reverse of ahci_alloc_port_state().
 */
static void
ahci_dealloc_port_state(ahci_ctl_t *ahci_ctlp, uint8_t port)
{
	ahci_port_t *ahci_portp = ahci_ctlp->ahcictl_ports[port];

	ASSERT(MUTEX_HELD(&ahci_ctlp->ahcictl_mutex));
	ASSERT(ahci_portp != NULL);

	mutex_enter(&ahci_portp->ahciport_mutex);
	kmem_free(ahci_portp->ahciport_event_args->ahciea_addrp,
	    sizeof (ahci_addr_t));
	ahci_portp->ahciport_event_args->ahciea_addrp = NULL;
	kmem_free(ahci_portp->ahciport_event_args, sizeof (ahci_event_arg_t));
	ahci_portp->ahciport_event_args = NULL;
	ddi_taskq_destroy(ahci_portp->ahciport_event_taskq);
	ahci_dealloc_cmd_list(ahci_ctlp, ahci_portp);
	ahci_dealloc_rcvd_fis(ahci_portp);
	ahci_dealloc_pmult(ahci_ctlp, ahci_portp);
	mutex_exit(&ahci_portp->ahciport_mutex);

	mutex_destroy(&ahci_portp->ahciport_mutex);
	cv_destroy(&ahci_portp->ahciport_cv);

	kmem_free(ahci_portp, sizeof (ahci_port_t));

	ahci_ctlp->ahcictl_ports[port] = NULL;
}

/*
 * Allocates memory for the Received FIS Structure
 */
static int
ahci_alloc_rcvd_fis(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
	size_t rcvd_fis_size;
	size_t ret_len;
	uint_t cookie_count;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	rcvd_fis_size = sizeof (ahci_rcvd_fis_t);

	/* allocate rcvd FIS dma handle. */
	if (ddi_dma_alloc_handle(ahci_ctlp->ahcictl_dip,
	    &ahci_ctlp->ahcictl_rcvd_fis_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &ahci_portp->ahciport_rcvd_fis_dma_handle) !=
	    DDI_SUCCESS) {
		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "rcvd FIS dma handle alloc failed", NULL);

		return (AHCI_FAILURE);
	}

	if (ddi_dma_mem_alloc(ahci_portp->ahciport_rcvd_fis_dma_handle,
	    rcvd_fis_size,
	    &accattr,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    (caddr_t *)&ahci_portp->ahciport_rcvd_fis,
	    &ret_len,
	    &ahci_portp->ahciport_rcvd_fis_acc_handle) != NULL) {

		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "rcvd FIS dma mem alloc fail", NULL);
		/* error.. free the dma handle. */
		ddi_dma_free_handle(&ahci_portp->ahciport_rcvd_fis_dma_handle);
		return (AHCI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(ahci_portp->ahciport_rcvd_fis_dma_handle,
	    NULL,
	    (caddr_t)ahci_portp->ahciport_rcvd_fis,
	    rcvd_fis_size,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &ahci_portp->ahciport_rcvd_fis_dma_cookie,
	    &cookie_count) !=  DDI_DMA_MAPPED) {

		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "rcvd FIS dma handle bind fail", NULL);
		/*  error.. free the dma handle & free the memory. */
		ddi_dma_mem_free(&ahci_portp->ahciport_rcvd_fis_acc_handle);
		ddi_dma_free_handle(&ahci_portp->ahciport_rcvd_fis_dma_handle);
		return (AHCI_FAILURE);
	}

	bzero((void *)ahci_portp->ahciport_rcvd_fis, rcvd_fis_size);

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp, "64-bit, dma address: 0x%llx",
	    ahci_portp->ahciport_rcvd_fis_dma_cookie.dmac_laddress);
	AHCIDBG(AHCIDBG_INIT, ahci_ctlp, "32-bit, dma address: 0x%x",
	    ahci_portp->ahciport_rcvd_fis_dma_cookie.dmac_address);

	return (AHCI_SUCCESS);
}

/*
 * Deallocates the Received FIS Structure
 */
static void
ahci_dealloc_rcvd_fis(ahci_port_t *ahci_portp)
{
	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	/* Unbind the cmd list dma handle first. */
	(void) ddi_dma_unbind_handle(ahci_portp->ahciport_rcvd_fis_dma_handle);

	/* Then free the underlying memory. */
	ddi_dma_mem_free(&ahci_portp->ahciport_rcvd_fis_acc_handle);

	/* Now free the handle itself. */
	ddi_dma_free_handle(&ahci_portp->ahciport_rcvd_fis_dma_handle);
}

/*
 * Allocates memory for the Command List, which contains up to 32 entries.
 * Each entry contains a command header, which is a 32-byte structure that
 * includes the pointer to the command table.
 */
static int
ahci_alloc_cmd_list(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
	size_t cmd_list_size;
	size_t ret_len;
	uint_t cookie_count;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	cmd_list_size =
	    ahci_ctlp->ahcictl_num_cmd_slots * sizeof (ahci_cmd_header_t);

	/* allocate cmd list dma handle. */
	if (ddi_dma_alloc_handle(ahci_ctlp->ahcictl_dip,
	    &ahci_ctlp->ahcictl_cmd_list_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &ahci_portp->ahciport_cmd_list_dma_handle) != DDI_SUCCESS) {

		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "cmd list dma handle alloc failed", NULL);
		return (AHCI_FAILURE);
	}

	if (ddi_dma_mem_alloc(ahci_portp->ahciport_cmd_list_dma_handle,
	    cmd_list_size,
	    &accattr,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    (caddr_t *)&ahci_portp->ahciport_cmd_list,
	    &ret_len,
	    &ahci_portp->ahciport_cmd_list_acc_handle) != NULL) {

		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "cmd list dma mem alloc fail", NULL);
		/* error.. free the dma handle. */
		ddi_dma_free_handle(&ahci_portp->ahciport_cmd_list_dma_handle);
		return (AHCI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(ahci_portp->ahciport_cmd_list_dma_handle,
	    NULL,
	    (caddr_t)ahci_portp->ahciport_cmd_list,
	    cmd_list_size,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &ahci_portp->ahciport_cmd_list_dma_cookie,
	    &cookie_count) !=  DDI_DMA_MAPPED) {

		AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
		    "cmd list dma handle bind fail", NULL);
		/*  error.. free the dma handle & free the memory. */
		ddi_dma_mem_free(&ahci_portp->ahciport_cmd_list_acc_handle);
		ddi_dma_free_handle(&ahci_portp->ahciport_cmd_list_dma_handle);
		return (AHCI_FAILURE);
	}

	bzero((void *)ahci_portp->ahciport_cmd_list, cmd_list_size);

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp, "64-bit, dma address: 0x%llx",
	    ahci_portp->ahciport_cmd_list_dma_cookie.dmac_laddress);

	AHCIDBG(AHCIDBG_INIT, ahci_ctlp, "32-bit, dma address: 0x%x",
	    ahci_portp->ahciport_cmd_list_dma_cookie.dmac_address);

	if (ahci_alloc_cmd_tables(ahci_ctlp, ahci_portp) != AHCI_SUCCESS) {
		goto err_out;
	}

	return (AHCI_SUCCESS);

err_out:
	/* Unbind the cmd list dma handle first. */
	(void) ddi_dma_unbind_handle(ahci_portp->ahciport_cmd_list_dma_handle);

	/* Then free the underlying memory. */
	ddi_dma_mem_free(&ahci_portp->ahciport_cmd_list_acc_handle);

	/* Now free the handle itself. */
	ddi_dma_free_handle(&ahci_portp->ahciport_cmd_list_dma_handle);

	return (AHCI_FAILURE);
}

/*
 * Deallocates the Command List
 */
static void
ahci_dealloc_cmd_list(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	/* First dealloc command table */
	ahci_dealloc_cmd_tables(ahci_ctlp, ahci_portp);

	/* Unbind the cmd list dma handle first. */
	(void) ddi_dma_unbind_handle(ahci_portp->ahciport_cmd_list_dma_handle);

	/* Then free the underlying memory. */
	ddi_dma_mem_free(&ahci_portp->ahciport_cmd_list_acc_handle);

	/* Now free the handle itself. */
	ddi_dma_free_handle(&ahci_portp->ahciport_cmd_list_dma_handle);
}

/*
 * Allocates memory for all Command Tables, which contains Command FIS,
 * ATAPI Command and Physical Region Descriptor Table.
 */
static int
ahci_alloc_cmd_tables(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
	size_t ret_len;
	ddi_dma_cookie_t cmd_table_dma_cookie;
	uint_t cookie_count;
	int slot;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_alloc_cmd_tables: port %d enter",
	    ahci_portp->ahciport_port_num);

	for (slot = 0; slot < ahci_ctlp->ahcictl_num_cmd_slots; slot++) {
		/* Allocate cmd table dma handle. */
		if (ddi_dma_alloc_handle(ahci_ctlp->ahcictl_dip,
		    &ahci_ctlp->ahcictl_cmd_table_dma_attr,
		    DDI_DMA_SLEEP,
		    NULL,
		    &ahci_portp->ahciport_cmd_tables_dma_handle[slot]) !=
		    DDI_SUCCESS) {

			AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
			    "cmd table dma handle alloc failed", NULL);

			goto err_out;
		}

		if (ddi_dma_mem_alloc(
		    ahci_portp->ahciport_cmd_tables_dma_handle[slot],
		    ahci_cmd_table_size,
		    &accattr,
		    DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP,
		    NULL,
		    (caddr_t *)&ahci_portp->ahciport_cmd_tables[slot],
		    &ret_len,
		    &ahci_portp->ahciport_cmd_tables_acc_handle[slot]) !=
		    NULL) {

			AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
			    "cmd table dma mem alloc fail", NULL);

			/* error.. free the dma handle. */
			ddi_dma_free_handle(
			    &ahci_portp->ahciport_cmd_tables_dma_handle[slot]);
			goto err_out;
		}

		if (ddi_dma_addr_bind_handle(
		    ahci_portp->ahciport_cmd_tables_dma_handle[slot],
		    NULL,
		    (caddr_t)ahci_portp->ahciport_cmd_tables[slot],
		    ahci_cmd_table_size,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP,
		    NULL,
		    &cmd_table_dma_cookie,
		    &cookie_count) !=  DDI_DMA_MAPPED) {

			AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
			    "cmd table dma handle bind fail", NULL);
			/*  error.. free the dma handle & free the memory. */
			ddi_dma_mem_free(
			    &ahci_portp->ahciport_cmd_tables_acc_handle[slot]);
			ddi_dma_free_handle(
			    &ahci_portp->ahciport_cmd_tables_dma_handle[slot]);
			goto err_out;
		}

		bzero((void *)ahci_portp->ahciport_cmd_tables[slot],
		    ahci_cmd_table_size);

		/* Config Port Command Table Base Address */
		SET_COMMAND_TABLE_BASE_ADDR(
		    (&ahci_portp->ahciport_cmd_list[slot]),
		    cmd_table_dma_cookie.dmac_laddress & 0xffffffffull);

#ifndef __lock_lint
		SET_COMMAND_TABLE_BASE_ADDR_UPPER(
		    (&ahci_portp->ahciport_cmd_list[slot]),
		    cmd_table_dma_cookie.dmac_laddress >> 32);
#endif
	}

	return (AHCI_SUCCESS);
err_out:

	for (slot--; slot >= 0; slot--) {
		/* Unbind the cmd table dma handle first */
		(void) ddi_dma_unbind_handle(
		    ahci_portp->ahciport_cmd_tables_dma_handle[slot]);

		/* Then free the underlying memory */
		ddi_dma_mem_free(
		    &ahci_portp->ahciport_cmd_tables_acc_handle[slot]);

		/* Now free the handle itself */
		ddi_dma_free_handle(
		    &ahci_portp->ahciport_cmd_tables_dma_handle[slot]);
	}

	return (AHCI_FAILURE);
}

/*
 * Deallocates memory for all Command Tables.
 */
static void
ahci_dealloc_cmd_tables(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
	int slot;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_dealloc_cmd_tables: %d enter",
	    ahci_portp->ahciport_port_num);

	for (slot = 0; slot < ahci_ctlp->ahcictl_num_cmd_slots; slot++) {
		/* Unbind the cmd table dma handle first. */
		(void) ddi_dma_unbind_handle(
		    ahci_portp->ahciport_cmd_tables_dma_handle[slot]);

		/* Then free the underlying memory. */
		ddi_dma_mem_free(
		    &ahci_portp->ahciport_cmd_tables_acc_handle[slot]);

		/* Now free the handle itself. */
		ddi_dma_free_handle(
		    &ahci_portp->ahciport_cmd_tables_dma_handle[slot]);
	}
}

/*
 * Update SATA registers at controller ports
 */
static void
ahci_update_sata_registers(ahci_ctl_t *ahci_ctlp, uint8_t port,
    sata_device_t *sd)
{
	ASSERT(MUTEX_HELD(&ahci_ctlp->ahcictl_ports[port]->ahciport_mutex));

	sd->satadev_scr.sstatus =
	    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)(AHCI_PORT_PxSSTS(ahci_ctlp, port)));
	sd->satadev_scr.serror =
	    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)(AHCI_PORT_PxSERR(ahci_ctlp, port)));
	sd->satadev_scr.scontrol =
	    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)(AHCI_PORT_PxSCTL(ahci_ctlp, port)));
	sd->satadev_scr.sactive =
	    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)(AHCI_PORT_PxSACT(ahci_ctlp, port)));
}

/*
 * For poll mode, ahci_port_intr will be called to emulate the interrupt
 */
static void
ahci_port_intr(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_intr_status;
	uint32_t port_intr_enable;

	AHCIDBG(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_port_intr enter: port %d", port);

	mutex_enter(&ahci_portp->ahciport_mutex);
	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_POLLING) {
		/* For SATA_OPMODE_POLLING commands */
		port_intr_enable =
		    (AHCI_INTR_STATUS_DHRS |
		    AHCI_INTR_STATUS_PSS |
		    AHCI_INTR_STATUS_SDBS |
		    AHCI_INTR_STATUS_UFS |
		    AHCI_INTR_STATUS_PCS |
		    AHCI_INTR_STATUS_PRCS |
		    AHCI_INTR_STATUS_OFS |
		    AHCI_INTR_STATUS_INFS |
		    AHCI_INTR_STATUS_IFS |
		    AHCI_INTR_STATUS_HBDS |
		    AHCI_INTR_STATUS_HBFS |
		    AHCI_INTR_STATUS_TFES);
	} else {
		/*
		 * port_intr_enable indicates that the corresponding interrrupt
		 * reporting is enabled.
		 */
		port_intr_enable = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxIE(ahci_ctlp, port));
	}

	/* IPMS error in port reset should be ignored according AHCI spec. */
	if (!(ahci_portp->ahciport_flags & AHCI_PORT_FLAG_IGNORE_IPMS))
		port_intr_enable |= AHCI_INTR_STATUS_IPMS;
	mutex_exit(&ahci_portp->ahciport_mutex);

	/*
	 * port_intr_stats indicates that the corresponding interrupt
	 * condition is active.
	 */
	port_intr_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxIS(ahci_ctlp, port));

	AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
	    "ahci_port_intr: port %d, port_intr_status = 0x%x, "
	    "port_intr_enable = 0x%x",
	    port, port_intr_status, port_intr_enable);

	port_intr_status &= port_intr_enable;

	/*
	 * Pending interrupt events are indicated by the PxIS register.
	 * Make sure we don't miss any event.
	 */
	if (ahci_check_ctl_handle(ahci_ctlp) != DDI_SUCCESS) {
		ddi_fm_service_impact(ahci_ctlp->ahcictl_dip,
		    DDI_SERVICE_UNAFFECTED);
		ddi_fm_acc_err_clear(ahci_ctlp->ahcictl_ahci_acc_handle,
		    DDI_FME_VERSION);
		return;
	}

	/* First clear the port interrupts status */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxIS(ahci_ctlp, port),
	    port_intr_status);

	/* Check the completed non-queued commands */
	if (port_intr_status & (AHCI_INTR_STATUS_DHRS |
	    AHCI_INTR_STATUS_PSS)) {
		(void) ahci_intr_cmd_cmplt(ahci_ctlp,
		    ahci_portp, port);
	}

	/* Check the completed queued commands */
	if (port_intr_status & AHCI_INTR_STATUS_SDBS) {
		(void) ahci_intr_set_device_bits(ahci_ctlp,
		    ahci_portp, port);
	}

	/* Check the port connect change status interrupt bit */
	if (port_intr_status & AHCI_INTR_STATUS_PCS) {
		(void) ahci_intr_port_connect_change(ahci_ctlp,
		    ahci_portp, port);
	}

	/* Check the device mechanical presence status interrupt bit */
	if (port_intr_status & AHCI_INTR_STATUS_DMPS) {
		(void) ahci_intr_device_mechanical_presence_status(
		    ahci_ctlp, ahci_portp, port);
	}

	/* Check the PhyRdy change status interrupt bit */
	if (port_intr_status & AHCI_INTR_STATUS_PRCS) {
		(void) ahci_intr_phyrdy_change(ahci_ctlp, ahci_portp,
		    port);
	}

	/*
	 * Check the non-fatal error interrupt bits, there are four
	 * kinds of non-fatal errors at the time being:
	 *
	 *    PxIS.UFS - Unknown FIS Error
	 *    PxIS.OFS - Overflow Error
	 *    PxIS.INFS - Interface Non-Fatal Error
	 *    PxIS.IPMS - Incorrect Port Multiplier Status Error
	 *
	 * For these non-fatal errors, the HBA can continue to operate,
	 * so the driver just log the error messages.
	 */
	if (port_intr_status & (AHCI_INTR_STATUS_UFS |
	    AHCI_INTR_STATUS_OFS |
	    AHCI_INTR_STATUS_IPMS |
	    AHCI_INTR_STATUS_INFS)) {
		(void) ahci_intr_non_fatal_error(ahci_ctlp, ahci_portp,
		    port, port_intr_status);
	}

	/*
	 * Check the fatal error interrupt bits, there are four kinds
	 * of fatal errors for AHCI controllers:
	 *
	 *    PxIS.HBFS - Host Bus Fatal Error
	 *    PxIS.HBDS - Host Bus Data Error
	 *    PxIS.IFS - Interface Fatal Error
	 *    PxIS.TFES - Task File Error
	 *
	 * The fatal error means the HBA can not recover from it by
	 * itself, and it will try to abort the transfer, and the software
	 * must intervene to restart the port.
	 */
	if (port_intr_status & (AHCI_INTR_STATUS_IFS |
	    AHCI_INTR_STATUS_HBDS |
	    AHCI_INTR_STATUS_HBFS |
	    AHCI_INTR_STATUS_TFES))
		(void) ahci_intr_fatal_error(ahci_ctlp, ahci_portp,
		    port, port_intr_status);

	/* Check the cold port detect interrupt bit */
	if (port_intr_status & AHCI_INTR_STATUS_CPDS) {
		(void) ahci_intr_cold_port_detect(ahci_ctlp, ahci_portp, port);
	}

	/* Second clear the corresponding bit in IS.IPS */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_IS(ahci_ctlp), (0x1 << port));

	/* Try to recover at the end of the interrupt handler. */
	if (ahci_check_acc_handle(ahci_ctlp->ahcictl_ahci_acc_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(ahci_ctlp->ahcictl_dip,
		    DDI_SERVICE_UNAFFECTED);
		ddi_fm_acc_err_clear(ahci_ctlp->ahcictl_ahci_acc_handle,
		    DDI_FME_VERSION);
	}
}

/*
 * Interrupt service handler
 */
static uint_t
ahci_intr(caddr_t arg1, caddr_t arg2)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(arg2))
#endif
	/* LINTED */
	ahci_ctl_t *ahci_ctlp = (ahci_ctl_t *)arg1;
	ahci_port_t *ahci_portp;
	int32_t global_intr_status;
	uint8_t port;

	/*
	 * global_intr_status indicates that the corresponding port has
	 * an interrupt pending.
	 */
	global_intr_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_IS(ahci_ctlp));

	if (!(global_intr_status & ahci_ctlp->ahcictl_ports_implemented)) {
		/* The interrupt is not ours */
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Check the handle after reading global_intr_status - we don't want
	 * to miss any port with pending interrupts.
	 */
	if (ahci_check_acc_handle(ahci_ctlp->ahcictl_ahci_acc_handle) !=
	    DDI_FM_OK) {
		ddi_fm_service_impact(ahci_ctlp->ahcictl_dip,
		    DDI_SERVICE_UNAFFECTED);
		ddi_fm_acc_err_clear(ahci_ctlp->ahcictl_ahci_acc_handle,
		    DDI_FME_VERSION);
		return (DDI_INTR_UNCLAIMED);
	}

	/* Loop for all the ports */
	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			continue;
		}
		if (!((0x1 << port) & global_intr_status)) {
			continue;
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];

		/* Call ahci_port_intr */
		ahci_port_intr(ahci_ctlp, ahci_portp, port);
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * For non-queued commands, when the corresponding bit in the PxCI register
 * is cleared, it means the command is completed successfully. And according
 * to the HBA state machine, there are three conditions which possibly will
 * try to clear the PxCI register bit.
 *	1. Receive one D2H Register FIS which is with 'I' bit set
 *	2. Update PIO Setup FIS
 *	3. Transmit a command and receive R_OK if CTBA.C is set (software reset)
 *
 * Process completed non-queued commands when the interrupt status bit -
 * AHCI_INTR_STATUS_DHRS or AHCI_INTR_STATUS_PSS is set.
 *
 * AHCI_INTR_STATUS_DHRS means a D2H Register FIS has been received
 * with the 'I' bit set. And the following commands will send thus
 * FIS with 'I' bit set upon the successful completion:
 * 	1. Non-data commands
 * 	2. DMA data-in command
 * 	3. DMA data-out command
 * 	4. PIO data-out command
 *	5. PACKET non-data commands
 *	6. PACKET PIO data-in command
 *	7. PACKET PIO data-out command
 *	8. PACKET DMA data-in command
 *	9. PACKET DMA data-out command
 *
 * AHCI_INTR_STATUS_PSS means a PIO Setup FIS has been received
 * with the 'I' bit set. And the following commands will send this
 * FIS upon the successful completion:
 * 	1. PIO data-in command
 */
static int
ahci_intr_cmd_cmplt(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_cmd_issue = 0;
	uint32_t finished_tags;
	int finished_slot;
	sata_pkt_t *satapkt;
	ahci_fis_d2h_register_t *rcvd_fisp;
#if AHCI_DEBUG
	ahci_cmd_header_t *cmd_header;
	uint32_t cmd_dmacount;
#endif

	mutex_enter(&ahci_portp->ahciport_mutex);

	if (!ERR_RETRI_CMD_IN_PROGRESS(ahci_portp) &&
	    !RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp) &&
	    !NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		/*
		 * Spurious interrupt. Nothing to be done.
		 */
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_SUCCESS);
	}

	port_cmd_issue = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

	/* If the PxCI corrupts, don't complete the commmands. */
	if (ahci_check_acc_handle(ahci_ctlp->ahcictl_ahci_acc_handle)
	    != DDI_FM_OK) {
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_FAILURE);
	}

	if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp)) {
		/* Slot 0 is always used during error recovery */
		finished_tags = 0x1 & ~port_cmd_issue;
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_intr_cmd_cmplt: port %d the sata pkt for error "
		    "retrieval is finished, and finished_tags = 0x%x",
		    port, finished_tags);
	} else if (RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp)) {
		finished_tags = 0x1 & ~port_cmd_issue;
		AHCIDBG(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_intr_cmd_cmplt: port %d the sata pkt for r/w "
		    "port multiplier is finished, and finished_tags = 0x%x",
		    port, finished_tags);

	} else {

		finished_tags = ahci_portp->ahciport_pending_tags &
		    ~port_cmd_issue & AHCI_SLOT_MASK(ahci_ctlp);
	}

	AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
	    "ahci_intr_cmd_cmplt: pending_tags = 0x%x, "
	    "port_cmd_issue = 0x%x finished_tags = 0x%x",
	    ahci_portp->ahciport_pending_tags, port_cmd_issue,
	    finished_tags);

	if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp) &&
	    (finished_tags == 0x1)) {
		satapkt = ahci_portp->ahciport_err_retri_pkt;
		ASSERT(satapkt != NULL);

		AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
		    "ahci_intr_cmd_cmplt: sending up pkt 0x%p "
		    "with SATA_PKT_COMPLETED", (void *)satapkt);

		ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_COMPLETED);
		goto out;
	}

	if (RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp) &&
	    (finished_tags == 0x1)) {
		satapkt = ahci_portp->ahciport_rdwr_pmult_pkt;
		ASSERT(satapkt != NULL);

		AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
		    "ahci_intr_cmd_cmplt: sending up pkt 0x%p "
		    "with SATA_PKT_COMPLETED", (void *)satapkt);

		/* READ PORTMULT need copy out FIS content. */
		if (satapkt->satapkt_cmd.satacmd_flags.sata_special_regs) {
			rcvd_fisp = &(ahci_portp->ahciport_rcvd_fis->
			    ahcirf_d2h_register_fis);
			satapkt->satapkt_cmd.satacmd_status_reg =
			    GET_RFIS_STATUS(rcvd_fisp);
			ahci_copy_out_regs(&satapkt->satapkt_cmd, rcvd_fisp);
		}

		ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_COMPLETED);
		goto out;
	}

	while (finished_tags) {
		finished_slot = ddi_ffs(finished_tags) - 1;
		if (finished_slot == -1) {
			goto out;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[finished_slot];
		ASSERT(satapkt != NULL);
#if AHCI_DEBUG
		/*
		 * For non-native queued commands, the PRD byte count field
		 * shall contain an accurate count of the number of bytes
		 * transferred for the command before the PxCI bit is cleared
		 * to '0' for the command.
		 *
		 * The purpose of this field is to let software know how many
		 * bytes transferred for a given operation in order to
		 * determine if underflow occurred. When issuing native command
		 * queuing commands, this field should not be used and is not
		 * required to be valid since in this case underflow is always
		 * illegal.
		 *
		 * For data reads, the HBA will update its PRD byte count with
		 * the total number of bytes received from the last FIS, and
		 * may be able to continue normally. For data writes, the
		 * device will detect an error, and HBA most likely will get
		 * a fatal error.
		 *
		 * Therefore, here just put code to debug part. And please
		 * refer to the comment above ahci_intr_fatal_error for the
		 * definition of underflow error.
		 */
		cmd_dmacount =
		    ahci_portp->ahciport_prd_bytecounts[finished_slot];
		if (cmd_dmacount) {
			cmd_header =
			    &ahci_portp->ahciport_cmd_list[finished_slot];
			AHCIDBG(AHCIDBG_INTR|AHCIDBG_PRDT, ahci_ctlp,
			    "ahci_intr_cmd_cmplt: port %d, "
			    "PRD Byte Count = 0x%x, "
			    "ahciport_prd_bytecounts = 0x%x", port,
			    cmd_header->ahcich_prd_byte_count,
			    cmd_dmacount);

			if (cmd_header->ahcich_prd_byte_count != cmd_dmacount) {
				AHCIDBG(AHCIDBG_UNDERFLOW, ahci_ctlp,
				    "ahci_intr_cmd_cmplt: port %d, "
				    "an underflow occurred", port);
			}
		}
#endif

		/*
		 * For SATAC_SMART command with SATA_SMART_RETURN_STATUS
		 * feature, sata_special_regs flag will be set, and the
		 * driver should copy the status and the other corresponding
		 * register values in the D2H Register FIS received (It's
		 * working on Non-data protocol) from the device back to
		 * the sata_cmd.
		 *
		 * For every AHCI port, there is only one Received FIS
		 * structure, which contains the FISes received from the
		 * device, So we're trying to copy the content of D2H
		 * Register FIS in the Received FIS structure back to
		 * the sata_cmd.
		 */
		if (satapkt->satapkt_cmd.satacmd_flags.sata_special_regs) {
			rcvd_fisp = &(ahci_portp->ahciport_rcvd_fis->
			    ahcirf_d2h_register_fis);
			satapkt->satapkt_cmd.satacmd_status_reg =
			    GET_RFIS_STATUS(rcvd_fisp);
			ahci_copy_out_regs(&satapkt->satapkt_cmd, rcvd_fisp);
		}

		AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
		    "ahci_intr_cmd_cmplt: sending up pkt 0x%p "
		    "with SATA_PKT_COMPLETED", (void *)satapkt);

		CLEAR_BIT(ahci_portp->ahciport_pending_tags, finished_slot);
		CLEAR_BIT(finished_tags, finished_slot);
		ahci_portp->ahciport_slot_pkts[finished_slot] = NULL;

		ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_COMPLETED);
	}
out:
	AHCIDBG(AHCIDBG_PKTCOMP, ahci_ctlp,
	    "ahci_intr_cmd_cmplt: pending_tags = 0x%x",
	    ahci_portp->ahciport_pending_tags);

	ahci_flush_doneq(ahci_portp);

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * AHCI_INTR_STATUS_SDBS means a Set Device Bits FIS has been received
 * with the 'I' bit set and has been copied into system memory. It will
 * be sent under the following situations:
 *
 * 1. NCQ command is completed
 *
 * The completion of NCQ commands (READ/WRITE FPDMA QUEUED) is performed
 * via the Set Device Bits FIS. When such event is generated, the software
 * needs to read PxSACT register and compares the current value to the
 * list of commands previously issue by software. ahciport_pending_ncq_tags
 * keeps the tags of previously issued commands.
 *
 * 2. Asynchronous Notification
 *
 * Asynchronous Notification is a feature in SATA spec 2.6.
 *
 * 1) ATAPI device will send a signal to the host when media is inserted or
 * removed and avoids polling the device for media changes. The signal
 * sent to the host is a Set Device Bits FIS with the 'I' and 'N' bits
 * set to '1'. At the moment, it's not supported yet.
 *
 * 2) Port multiplier will send a signal to the host when a hot plug event
 * has occured on a port multiplier port. It is used when command based
 * switching is employed. This is handled by ahci_intr_pmult_sntf_events()
 */
static int
ahci_intr_set_device_bits(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	ahci_addr_t addr;

	AHCIDBG(AHCIDBG_ENTRY|AHCIDBG_INTR, ahci_ctlp,
	    "ahci_intr_set_device_bits enter: port %d", port);

	/* Initialize HBA port address */
	AHCI_ADDR_SET_PORT(&addr, port);

	/* NCQ plug handler */
	(void) ahci_intr_ncq_events(ahci_ctlp, ahci_portp, &addr);

	/* Check port multiplier's asynchronous notification events */
	if (ahci_ctlp->ahcictl_cap & AHCI_CAP_SNTF) {
		(void) ahci_intr_pmult_sntf_events(ahci_ctlp,
		    ahci_portp, port);
	}

	/* ATAPI events is not supported yet */

	return (AHCI_SUCCESS);
}
/*
 * NCQ interrupt handler. Called upon a NCQ command is completed.
 * Only be called from ahci_intr_set_device_bits().
 */
static int
ahci_intr_ncq_events(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, ahci_addr_t *addrp)
{
	uint32_t port_sactive;
	uint32_t port_cmd_issue;
	uint32_t issued_tags;
	int issued_slot;
	uint32_t finished_tags;
	int finished_slot;
	uint8_t port = addrp->aa_port;
	sata_pkt_t *satapkt;

	AHCIDBG(AHCIDBG_ENTRY|AHCIDBG_INTR|AHCIDBG_NCQ, ahci_ctlp,
	    "ahci_intr_set_device_bits enter: port %d", port);

	mutex_enter(&ahci_portp->ahciport_mutex);
	if (!NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_SUCCESS);
	}

	/*
	 * First the handler got which commands are finished by checking
	 * PxSACT register
	 */
	port_sactive = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));

	finished_tags = ahci_portp->ahciport_pending_ncq_tags &
	    ~port_sactive & AHCI_NCQ_SLOT_MASK(ahci_portp);

	AHCIDBG(AHCIDBG_INTR|AHCIDBG_NCQ, ahci_ctlp,
	    "ahci_intr_set_device_bits: port %d pending_ncq_tags = 0x%x "
	    "port_sactive = 0x%x", port,
	    ahci_portp->ahciport_pending_ncq_tags, port_sactive);

	AHCIDBG(AHCIDBG_INTR|AHCIDBG_NCQ, ahci_ctlp,
	    "ahci_intr_set_device_bits: finished_tags = 0x%x", finished_tags);

	/*
	 * For NCQ commands, the software can determine which command has
	 * already been transmitted to the device by checking PxCI register.
	 */
	port_cmd_issue = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

	issued_tags = ahci_portp->ahciport_pending_tags &
	    ~port_cmd_issue & AHCI_SLOT_MASK(ahci_ctlp);

	/* If the PxSACT/PxCI corrupts, don't complete the NCQ commmands. */
	if (ahci_check_acc_handle(ahci_ctlp->ahcictl_ahci_acc_handle)
	    != DDI_FM_OK) {
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_FAILURE);
	}

	AHCIDBG(AHCIDBG_INTR|AHCIDBG_NCQ, ahci_ctlp,
	    "ahci_intr_set_device_bits: port %d pending_tags = 0x%x "
	    "port_cmd_issue = 0x%x", port,
	    ahci_portp->ahciport_pending_tags, port_cmd_issue);

	AHCIDBG(AHCIDBG_INTR|AHCIDBG_NCQ, ahci_ctlp,
	    "ahci_intr_set_device_bits: issued_tags = 0x%x", issued_tags);

	/*
	 * Clear ahciport_pending_tags bit when the corresponding command
	 * is already sent down to the device.
	 */
	while (issued_tags) {
		issued_slot = ddi_ffs(issued_tags) - 1;
		if (issued_slot == -1) {
			goto next;
		}
		CLEAR_BIT(ahci_portp->ahciport_pending_tags, issued_slot);
		CLEAR_BIT(issued_tags, issued_slot);
	}

next:
	while (finished_tags) {
		finished_slot = ddi_ffs(finished_tags) - 1;
		if (finished_slot == -1) {
			goto out;
		}

		/* The command is certainly transmitted to the device */
		ASSERT(!(ahci_portp->ahciport_pending_tags &
		    (0x1 << finished_slot)));

		satapkt = ahci_portp->ahciport_slot_pkts[finished_slot];
		ASSERT(satapkt != NULL);

		AHCIDBG(AHCIDBG_INTR|AHCIDBG_NCQ, ahci_ctlp,
		    "ahci_intr_set_device_bits: sending up pkt 0x%p "
		    "with SATA_PKT_COMPLETED", (void *)satapkt);

		CLEAR_BIT(ahci_portp->ahciport_pending_ncq_tags, finished_slot);
		CLEAR_BIT(finished_tags, finished_slot);
		ahci_portp->ahciport_slot_pkts[finished_slot] = NULL;

		ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_COMPLETED);
	}
out:
	AHCIDBG(AHCIDBG_PKTCOMP|AHCIDBG_NCQ, ahci_ctlp,
	    "ahci_intr_set_device_bits: port %d "
	    "pending_ncq_tags = 0x%x pending_tags = 0x%x",
	    port, ahci_portp->ahciport_pending_ncq_tags,
	    ahci_portp->ahciport_pending_tags);

	ahci_flush_doneq(ahci_portp);

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * Port multiplier asynchronous notification event handler. Called upon a
 * device is hot plugged/pulled.
 *
 * The async-notification event will only be recorded by ahcipmi_snotif_tags
 * here and will be handled by ahci_probe_pmult().
 *
 * NOTE: called only from ahci_port_intr().
 */
static int
ahci_intr_pmult_sntf_events(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    uint8_t port)
{
	sata_device_t sdevice;

	AHCIDBG(AHCIDBG_ENTRY|AHCIDBG_INTR, ahci_ctlp,
	    "ahci_intr_pmult_sntf_events enter: port %d ", port);

	/* no hot-plug while attaching process */
	mutex_enter(&ahci_ctlp->ahcictl_mutex);
	if (ahci_ctlp->ahcictl_flags & AHCI_ATTACH) {
		mutex_exit(&ahci_ctlp->ahcictl_mutex);
		return (AHCI_SUCCESS);
	}
	mutex_exit(&ahci_ctlp->ahcictl_mutex);

	mutex_enter(&ahci_portp->ahciport_mutex);
	if (ahci_portp->ahciport_device_type != SATA_DTYPE_PMULT) {
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_SUCCESS);
	}

	ASSERT(ahci_portp->ahciport_pmult_info != NULL);

	ahci_portp->ahciport_pmult_info->ahcipmi_snotif_tags =
	    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSNTF(ahci_ctlp, port));
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSNTF(ahci_ctlp, port),
	    AHCI_SNOTIF_CLEAR_ALL);

	if (ahci_portp->ahciport_pmult_info->ahcipmi_snotif_tags == 0) {
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_SUCCESS);
	}

	/* Port Multiplier sub-device hot-plug handler */
	if (RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp)) {
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_SUCCESS);
	}

	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_PMULT_SNTF) {
		/* Not allowed to re-enter. */
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_SUCCESS);
	}

	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_PMULT_SNTF;

	/*
	 * NOTE:
	 * Even if Asynchronous Notification is supported (and enabled) by
	 * both controller and the port multiplier, the content of PxSNTF
	 * register is always set to 0x8000 by async notification event. We
	 * need to check GSCR[32] on the port multiplier to find out the
	 * owner of this event.
	 * This is not accord with SATA spec 2.6 and needs further
	 * clarification.
	 */
	/* hot-plug will not reported while reseting. */
	if (ahci_portp->ahciport_reset_in_progress == 1) {
		AHCIDBG(AHCIDBG_INFO|AHCIDBG_PMULT, ahci_ctlp,
		    "port %d snotif event ignored", port);
		ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_PMULT_SNTF;
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_SUCCESS);
	}

	AHCIDBG(AHCIDBG_INFO|AHCIDBG_PMULT, ahci_ctlp,
	    "PxSNTF is set to 0x%x by port multiplier",
	    ahci_portp->ahciport_pmult_info->ahcipmi_snotif_tags);

	/*
	 * Now we need do some necessary operation and inform SATA framework
	 * that link/device events has happened.
	 */
	bzero((void *)&sdevice, sizeof (sata_device_t));
	sdevice.satadev_addr.cport = ahci_ctlp->
	    ahcictl_port_to_cport[port];
	sdevice.satadev_addr.pmport = SATA_PMULT_HOSTPORT;
	sdevice.satadev_addr.qual = SATA_ADDR_PMULT;
	sdevice.satadev_state = SATA_PSTATE_PWRON;

	/* Just reject packets, do not stop that port. */
	ahci_reject_all_abort_pkts(ahci_ctlp, ahci_portp, port);

	mutex_exit(&ahci_portp->ahciport_mutex);
	sata_hba_event_notify(
	    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
	    &sdevice,
	    SATA_EVNT_PMULT_LINK_CHANGED);
	mutex_enter(&ahci_portp->ahciport_mutex);

	ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_PMULT_SNTF;
	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * 1=Change in Current Connect Status. 0=No change in Current Connect Status.
 * This bit reflects the state of PxSERR.DIAG.X. This bit is only cleared
 * when PxSERR.DIAG.X is cleared. When PxSERR.DIAG.X is set to one, it
 * indicates a COMINIT signal was received.
 *
 * Hot plug insertion is detected by reception of a COMINIT signal from the
 * device. On reception of unsolicited COMINIT, the HBA shall generate a
 * COMRESET. If the COMINIT is in responce to a COMRESET, then the HBA shall
 * begin the normal communication negotiation sequence as outlined in the
 * Serial ATA 1.0a specification. When a COMRESET is sent to the device the
 * PxSSTS.DET field shall be cleared to 0h. When a COMINIT is received, the
 * PxSSTS.DET field shall be set to 1h. When the communication negotiation
 * sequence is complete and PhyRdy is true the PxSSTS.DET field	shall be set
 * to 3h. Therefore, at the moment the ahci driver is going to check PhyRdy
 * to handle hot plug insertion. In this interrupt handler, just do nothing
 * but print some log message and clear the bit.
 */
static int
ahci_intr_port_connect_change(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
#if AHCI_DEBUG
	uint32_t port_serror;
#endif

	mutex_enter(&ahci_portp->ahciport_mutex);

#if AHCI_DEBUG
	port_serror = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port));

	AHCIDBG(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_port_connect_change: port %d, "
	    "port_serror = 0x%x", port, port_serror);
#endif

	/* Clear PxSERR.DIAG.X to clear the interrupt bit */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port),
	    SERROR_EXCHANGED_ERR);

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * Hot Plug Operation for platforms that support Mechanical Presence
 * Switches.
 *
 * When set, it indicates that a mechanical presence switch attached to this
 * port has been opened or closed, which may lead to a change in the connection
 * state of the device. This bit is only valid if both CAP.SMPS and PxCMD.MPSP
 * are set to '1'.
 *
 * At the moment, this interrupt is not needed and disabled and we just log
 * the debug message.
 */
static int
ahci_intr_device_mechanical_presence_status(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t cap_status, port_cmd_status;

	AHCIDBG(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_device_mechanical_presence_status enter, "
	    "port %d", port);

	cap_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_CAP(ahci_ctlp));

	mutex_enter(&ahci_portp->ahciport_mutex);
	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	if (!(cap_status & AHCI_HBA_CAP_SMPS) ||
	    !(port_cmd_status & AHCI_CMD_STATUS_MPSP)) {
		AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
		    "CAP.SMPS or PxCMD.MPSP is not set, so just ignore "
		    "the interrupt: cap_status = 0x%x, "
		    "port_cmd_status = 0x%x", cap_status, port_cmd_status);
		mutex_exit(&ahci_portp->ahciport_mutex);

		return (AHCI_SUCCESS);
	}

#if AHCI_DEBUG
	if (port_cmd_status & AHCI_CMD_STATUS_MPSS) {
		AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
		    "The mechanical presence switch is open: "
		    "port %d, port_cmd_status = 0x%x",
		    port, port_cmd_status);
	} else {
		AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
		    "The mechanical presence switch is close: "
		    "port %d, port_cmd_status = 0x%x",
		    port, port_cmd_status);
	}
#endif

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * Native Hot Plug Support.
 *
 * When set, it indicates that the internal PHYRDY signal changed state.
 * This bit reflects the state of PxSERR.DIAG.N.
 *
 * There are three kinds of conditions to generate this interrupt event:
 * 1. a device is inserted
 * 2. a device is disconnected
 * 3. when the link enters/exits a Partial or Slumber interface power
 *    management state
 *
 * If inteface power management is enabled for a port, the PxSERR.DIAG.N
 * bit may be set due to the link entering the Partial or Slumber power
 * management state, rather than due to a hot plug insertion or removal
 * event. So far, the interface power management is disabled, so the
 * driver can reliably get removal detection notification via the
 * PxSERR.DIAG.N bit.
 */
static int
ahci_intr_phyrdy_change(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_sstatus = 0; /* No dev present & PHY not established. */
	sata_device_t sdevice;
	int dev_exists_now = 0;
	int dev_existed_previously = 0;
	ahci_addr_t port_addr;

	AHCIDBG(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_phyrdy_change enter, port %d", port);

	/* Clear PxSERR.DIAG.N to clear the interrupt bit */
	mutex_enter(&ahci_portp->ahciport_mutex);
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port),
	    SERROR_PHY_RDY_CHG);
	mutex_exit(&ahci_portp->ahciport_mutex);

	mutex_enter(&ahci_ctlp->ahcictl_mutex);
	if ((ahci_ctlp->ahcictl_sata_hba_tran == NULL) ||
	    (ahci_portp == NULL)) {
		/* The whole controller setup is not yet done. */
		mutex_exit(&ahci_ctlp->ahcictl_mutex);
		return (AHCI_SUCCESS);
	}
	mutex_exit(&ahci_ctlp->ahcictl_mutex);

	mutex_enter(&ahci_portp->ahciport_mutex);

	/* SStatus tells the presence of device. */
	port_sstatus = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSSTS(ahci_ctlp, port));

	if (SSTATUS_GET_DET(port_sstatus) == SSTATUS_DET_DEVPRE_PHYCOM) {
		dev_exists_now = 1;
	}

	if (ahci_portp->ahciport_device_type != SATA_DTYPE_NONE) {
		dev_existed_previously = 1;
	}

	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_NODEV) {
		ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_NODEV;
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_intr_phyrdy_change: port %d "
		    "AHCI_PORT_FLAG_NODEV is cleared", port);
		if (dev_exists_now == 0)
			dev_existed_previously = 1;
	}

	bzero((void *)&sdevice, sizeof (sata_device_t));
	sdevice.satadev_addr.cport = ahci_ctlp->ahcictl_port_to_cport[port];
	sdevice.satadev_addr.qual = SATA_ADDR_CPORT;
	sdevice.satadev_addr.pmport = 0;
	sdevice.satadev_state = SATA_PSTATE_PWRON;
	ahci_portp->ahciport_port_state = SATA_PSTATE_PWRON;

	AHCI_ADDR_SET_PORT(&port_addr, port);

	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_HOTPLUG;
	if (dev_exists_now) {
		if (dev_existed_previously) { /* 1 -> 1 */
			/* Things are fine now. The loss was temporary. */
			AHCIDBG(AHCIDBG_EVENT, ahci_ctlp,
			    "ahci_intr_phyrdy_change  port %d "
			    "device link lost/established", port);

			mutex_exit(&ahci_portp->ahciport_mutex);
			sata_hba_event_notify(
			    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
			    &sdevice,
			    SATA_EVNT_LINK_LOST|SATA_EVNT_LINK_ESTABLISHED);
			mutex_enter(&ahci_portp->ahciport_mutex);

		} else { /* 0 -> 1 */
			AHCIDBG(AHCIDBG_EVENT, ahci_ctlp,
			    "ahci_intr_phyrdy_change: port %d "
			    "device link established", port);

			/*
			 * A new device has been detected. The new device
			 * might be a port multiplier instead of a drive, so
			 * we cannot update the signature directly.
			 */
			(void) ahci_initialize_port(ahci_ctlp,
			    ahci_portp, &port_addr);

			/* Try to start the port */
			if (ahci_start_port(ahci_ctlp, ahci_portp, port)
			    != AHCI_SUCCESS) {
				sdevice.satadev_state |= SATA_PSTATE_FAILED;
				AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
				    "ahci_intr_phyrdy_change: port %d failed "
				    "at start port", port);
			}

			/* Clear the max queue depth for inserted device */
			ahci_portp->ahciport_max_ncq_tags = 0;

			mutex_exit(&ahci_portp->ahciport_mutex);
			sata_hba_event_notify(
			    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
			    &sdevice,
			    SATA_EVNT_LINK_ESTABLISHED);
			mutex_enter(&ahci_portp->ahciport_mutex);

		}
	} else { /* No device exists now */

		if (dev_existed_previously) { /* 1 -> 0 */
			AHCIDBG(AHCIDBG_EVENT, ahci_ctlp,
			    "ahci_intr_phyrdy_change: port %d "
			    "device link lost", port);

			ahci_reject_all_abort_pkts(ahci_ctlp, ahci_portp, port);
			(void) ahci_put_port_into_notrunning_state(ahci_ctlp,
			    ahci_portp, port);

			if (ahci_portp->ahciport_device_type ==
			    SATA_DTYPE_PMULT) {
				ahci_dealloc_pmult(ahci_ctlp, ahci_portp);
			}

			/* An existing device is lost. */
			ahci_portp->ahciport_device_type = SATA_DTYPE_NONE;
			ahci_portp->ahciport_port_state = SATA_STATE_UNKNOWN;

			mutex_exit(&ahci_portp->ahciport_mutex);
			sata_hba_event_notify(
			    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
			    &sdevice,
			    SATA_EVNT_LINK_LOST);
			mutex_enter(&ahci_portp->ahciport_mutex);
		}
	}
	ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_HOTPLUG;

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * PxIS.UFS - Unknown FIS Error
 *
 * This interrupt event means an unknown FIS was received and has been
 * copied into system memory. An unknown FIS is not considered an illegal
 * FIS, unless the length received is more than 64 bytes. If an unknown
 * FIS arrives with length <= 64 bytes, it is posted and the HBA continues
 * normal operation. If the unknown FIS is more than 64 bytes, then it
 * won't be posted to memory and PxSERR.ERR.P will be set, which is then
 * a fatal error.
 *
 * PxIS.IPMS - Incorrect Port Multiplier Status
 *
 * IPMS Indicates that the HBA received a FIS from a device that did not
 * have a command outstanding. The IPMS bit may be set during enumeration
 * of devices on a Port Multiplier due to the normal Port Multiplier
 * enumeration process. It is recommended that IPMS only be used after
 * enumeration is complete on the Port Multiplier (copied from spec).
 *
 * PxIS.OFS - Overflow Error
 *
 * Command list overflow is defined as software building a command table
 * that has fewer total bytes than the transaction given to the device.
 * On device writes, the HBA will run out of data, and on reads, there
 * will be no room to put the data.
 *
 * For an overflow on data read, either PIO or DMA, the HBA will set
 * PxIS.OFS, and the HBA will do a best effort to continue, and it's a
 * non-fatal error when the HBA can continues. Sometimes, it will cause
 * a fatal error and need the software to do something.
 *
 * For an overflow on data write, setting PxIS.OFS is optional for both
 * DMA and PIO, and it's a fatal error, and a COMRESET is required by
 * software to clean up from this serious error.
 *
 * PxIS.INFS - Interface Non-Fatal Error
 *
 * This interrupt event indicates that the HBA encountered an error on
 * the Serial ATA interface but was able to continue operation. The kind
 * of error usually occurred during a non-Data FIS, and under this condition
 * the FIS will be re-transmitted by HBA automatically.
 *
 * When the FMA is implemented, there should be a stat structure to
 * record how many every kind of error happens.
 */
static int
ahci_intr_non_fatal_error(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    uint8_t port, uint32_t intr_status)
{
	uint32_t port_serror;
#if AHCI_DEBUG
	uint32_t port_cmd_status;
	uint32_t port_cmd_issue;
	uint32_t port_sactive;
	int current_slot;
	uint32_t current_tags;
	sata_pkt_t *satapkt;
	ahci_cmd_header_t *cmd_header;
	uint32_t cmd_dmacount;
#endif

	mutex_enter(&ahci_portp->ahciport_mutex);

	port_serror = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port));

	AHCIDBG(AHCIDBG_INTR|AHCIDBG_ENTRY|AHCIDBG_ERRS, ahci_ctlp,
	    "ahci_intr_non_fatal_error: port %d, "
	    "PxSERR = 0x%x, PxIS = 0x%x ", port, port_serror, intr_status);

	ahci_log_serror_message(ahci_ctlp, port, port_serror, 1);

	if (intr_status & AHCI_INTR_STATUS_UFS) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci port %d has unknown FIS error", port);

		/* Clear the interrupt bit by clearing PxSERR.DIAG.F */
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port),
		    SERROR_FIS_TYPE);
	}

#if AHCI_DEBUG
	if (intr_status & AHCI_INTR_STATUS_IPMS) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci port %d "
		    "has Incorrect Port Multiplier Status error", port);
	}

	if (intr_status & AHCI_INTR_STATUS_OFS) {
		AHCIDBG(AHCIDBG_INTR|AHCIDBG_ERRS, ahci_ctlp,
		    "ahci port %d has overflow error", port);
	}

	if (intr_status & AHCI_INTR_STATUS_INFS) {
		AHCIDBG(AHCIDBG_INTR|AHCIDBG_ERRS, ahci_ctlp,
		    "ahci port %d has interface non fatal error", port);
	}

	/*
	 * Record the error occurred command's slot.
	 */
	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp) ||
	    ERR_RETRI_CMD_IN_PROGRESS(ahci_portp)) {
		port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

		current_slot = (port_cmd_status & AHCI_CMD_STATUS_CCS) >>
		    AHCI_CMD_STATUS_CCS_SHIFT;

		if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp)) {
			satapkt = ahci_portp->ahciport_err_retri_pkt;
			ASSERT(satapkt != NULL);
			ASSERT(current_slot == 0);
		} else {
			satapkt = ahci_portp->ahciport_slot_pkts[current_slot];
		}

		if (satapkt != NULL) {
			AHCIDBG(AHCIDBG_INTR|AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_intr_non_fatal_error: pending_tags = 0x%x "
			    "cmd 0x%x", ahci_portp->ahciport_pending_tags,
			    satapkt->satapkt_cmd.satacmd_cmd_reg);

			AHCIDBG(AHCIDBG_INTR|AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_intr_non_fatal_error: port %d, "
			    "satapkt 0x%p is being processed when error occurs",
			    port, (void *)satapkt);

			/*
			 * PRD Byte Count field of command header is not
			 * required to reflect the total number of bytes
			 * transferred when an overflow occurs, so here
			 * just log the value.
			 */
			cmd_dmacount =
			    ahci_portp->ahciport_prd_bytecounts[current_slot];
			if (cmd_dmacount) {
				cmd_header = &ahci_portp->
				    ahciport_cmd_list[current_slot];
				AHCIDBG(AHCIDBG_INTR|AHCIDBG_ERRS, ahci_ctlp,
				    "ahci_intr_non_fatal_error: port %d, "
				    "PRD Byte Count = 0x%x, "
				    "ahciport_prd_bytecounts = 0x%x", port,
				    cmd_header->ahcich_prd_byte_count,
				    cmd_dmacount);
			}
		}
	} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		/*
		 * For queued command, list those command which have already
		 * been transmitted to the device and still not completed.
		 */
		port_sactive = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));

		port_cmd_issue = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

		AHCIDBG(AHCIDBG_INTR|AHCIDBG_NCQ|AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_intr_non_fatal_error: pending_ncq_tags = 0x%x "
		    "port_sactive = 0x%x port_cmd_issue = 0x%x",
		    ahci_portp->ahciport_pending_ncq_tags,
		    port_sactive, port_cmd_issue);

		current_tags = ahci_portp->ahciport_pending_ncq_tags &
		    port_sactive & ~port_cmd_issue &
		    AHCI_NCQ_SLOT_MASK(ahci_portp);

		while (current_tags) {
			current_slot = ddi_ffs(current_tags) - 1;
			if (current_slot == -1) {
				goto out;
			}

			satapkt = ahci_portp->ahciport_slot_pkts[current_slot];
			AHCIDBG(AHCIDBG_INTR|AHCIDBG_NCQ|AHCIDBG_ERRS,
			    ahci_ctlp, "ahci_intr_non_fatal_error: "
			    "port %d, satapkt 0x%p is outstanding when "
			    "error occurs", port, (void *)satapkt);

			CLEAR_BIT(current_tags, current_slot);
		}
	}
out:
#endif
	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * According to the AHCI spec, the error types include system memory
 * errors, interface errors, port multiplier errors, device errors,
 * command list overflow, command list underflow, native command
 * queuing tag errors and pio data transfer errors.
 *
 * System memory errors such as target abort, master abort, and parity
 * may cause the host to stop, and they are serious errors and needed
 * to be recovered with software intervention. When system software
 * has given a pointer to the HBA that doesn't exist in physical memory,
 * a master/target abort error occurs, and PxIS.HBFS will be set. A
 * data error such as CRC or parity occurs, the HBA aborts the transfer
 * (if necessary) and PxIS.HBDS will be set.
 *
 * Interface errors are errors that occur due to electrical issues on
 * the interface, or protocol miscommunication between the device and
 * HBA, and the respective PxSERR register bit will be set. And PxIS.IFS
 * (fatal) or PxIS.INFS (non-fatal) will be set. The conditions that
 * causes PxIS.IFS/PxIS.INFS to be set are
 * 	1. in PxSERR.ERR, P bit is set to '1'
 *	2. in PxSERR.DIAG, C or H bit is set to '1'
 *	3. PhyRdy drop unexpectly, N bit is set to '1'
 * If the error occurred during a non-data FIS, the FIS must be
 * retransmitted, and the error is non-fatal and PxIS.INFS is set. If
 * the error occurred during a data FIS, the transfer will stop, so
 * the error is fatal and PxIS.IFS is set.
 *
 * When a FIS arrives that updates the taskfile, the HBA checks to see
 * if PxTFD.STS.ERR is set. If yes, PxIS.TFES will be set and the HBA
 * stops processing any more commands.
 *
 * Command list overflow is defined as software building a command table
 * that has fewer total bytes than the transaction given to the device.
 * On device writes, the HBA will run out of data, and on reads, there
 * will be no room to put the data. For an overflow on data read, either
 * PIO or DMA, the HBA will set PxIS.OFS, and it's a non-fatal error.
 * For an overflow on data write, setting PxIS.OFS is optional for both
 * DMA and PIO, and a COMRESET is required by software to clean up from
 * this serious error.
 *
 * Command list underflow is defined as software building a command
 * table that has more total bytes than the transaction given to the
 * device. For data writes, both PIO and DMA, the device will detect
 * an error and end the transfer. And these errors are most likely going
 * to be fatal errors that will cause the port to be restarted. For
 * data reads, the HBA updates its PRD byte count, and may be
 * able to continue normally, but is not required to. And The HBA is
 * not required to detect underflow conditions for native command
 * queuing command.
 *
 * The HBA does not actively check incoming DMA Setup FISes to ensure
 * that the PxSACT register bit for that slot is set. Existing error
 * mechanisms, such as host bus failure, or bad protocol, are used to
 * recover from this case.
 *
 * In accordance with Serial ATA 1.0a, DATA FISes prior to the final
 * DATA FIS must be an integral number of Dwords. If the HBA receives
 * a request which is not an integral number of Dwords, the HBA
 * set PxSERR.ERR.P to '1', set PxIS.IFS to '1' and stop running until
 * software restarts the port. And the HBA ensures that the size
 * of the DATA FIS received during a PIO command matches the size in
 * the Transfer Cound field of the preceding PIO Setup FIS, if not, the
 * HBA sets PxSERR.ERR.P to '1', set PxIS.IFS to '1', and then
 * stop running until software restarts the port.
 */
/*
 * the fatal errors include PxIS.IFS, PxIS.HBDS, PxIS.HBFS and PxIS.TFES.
 *
 * PxIS.IFS indicates that the hba encountered an error on the serial ata
 * interface which caused the transfer to stop.
 *
 * PxIS.HBDS indicates that the hba encountered a data error
 * (uncorrectable ecc/parity) when reading from or writing to system memory.
 *
 * PxIS.HBFS indicates that the hba encountered a host bus error that it
 * cannot recover from, such as a bad software pointer.
 *
 * PxIS.TFES is set whenever the status register is updated by the device
 * and the error bit (bit 0) is set.
 */
static int
ahci_intr_fatal_error(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port, uint32_t intr_status)
{
	uint32_t port_cmd_status;
	uint32_t port_serror;
	uint32_t task_file_status;
	int failed_slot;
	sata_pkt_t *spkt = NULL;
	uint8_t err_byte;
	ahci_event_arg_t *args;
	int instance = ddi_get_instance(ahci_ctlp->ahcictl_dip);
	uint32_t failed_tags = 0;
	int task_fail_flag = 0, task_abort_flag = 0;
	uint32_t slot_status;

	mutex_enter(&ahci_portp->ahciport_mutex);

	/*
	 * ahci_intr_phyrdy_change() may have rendered it to
	 * SATA_DTYPE_NONE.
	 */
	if (ahci_portp->ahciport_device_type == SATA_DTYPE_NONE) {
		AHCIDBG(AHCIDBG_ENTRY|AHCIDBG_INTR, ahci_ctlp,
		    "ahci_intr_fatal_error: port %d no device attached, "
		    "and just return without doing anything", port);
		goto out0;
	}

	if (intr_status & AHCI_INTR_STATUS_TFES) {
		task_file_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));
		AHCIDBG(AHCIDBG_INTR|AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_intr_fatal_error: port %d "
		    "task_file_status = 0x%x", port, task_file_status);
		task_fail_flag = 1;

		err_byte = (task_file_status & AHCI_TFD_ERR_MASK)
		    >> AHCI_TFD_ERR_SHIFT;
		if (err_byte == SATA_ERROR_ABORT)
			task_abort_flag = 1;
	}

	/*
	 * Here we just log the fatal error info in interrupt context.
	 * Misc recovery processing will be handled in task queue.
	 */
	if (task_fail_flag  == 1) {
		if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
			/*
			 * Read PxCMD.CCS to determine the slot that the HBA
			 * was processing when the error occurred.
			 */
			port_cmd_status = ddi_get32(
			    ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));
			failed_slot = (port_cmd_status & AHCI_CMD_STATUS_CCS) >>
			    AHCI_CMD_STATUS_CCS_SHIFT;
			failed_tags = 0x1 << failed_slot;

			spkt = ahci_portp->ahciport_slot_pkts[failed_slot];
			AHCIDBG(AHCIDBG_INTR|AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_intr_fatal_error: spkt 0x%p is being "
			    "processed when fatal error occurred for port %d",
			    spkt, port);

			/*
			 * Won't emit the error message if it is an IDENTIFY
			 * DEVICE command sent to an ATAPI device.
			 */
			if ((spkt != NULL) &&
			    (spkt->satapkt_cmd.satacmd_cmd_reg ==
			    SATAC_ID_DEVICE) &&
			    (task_abort_flag == 1))
			goto out1;

			/*
			 * Won't emit the error message if it is an ATAPI PACKET
			 * command
			 */
			if ((spkt != NULL) &&
			    (spkt->satapkt_cmd.satacmd_cmd_reg == SATAC_PACKET))
				goto out1;

		} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
			slot_status = ddi_get32(
			    ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));
			failed_tags = slot_status &
			    AHCI_NCQ_SLOT_MASK(ahci_portp);
		}
	}

	/* print the fatal error type */
	ahci_log_fatal_error_message(ahci_ctlp, port, intr_status);
	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_ERRPRINT;

	port_serror = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port));

	/* print PxSERR related error message */
	ahci_log_serror_message(ahci_ctlp, port, port_serror, 0);

	/* print task file register value */
	if (task_fail_flag == 1) {
		cmn_err(CE_WARN, "!ahci%d: ahci port %d task_file_status "
		    "= 0x%x", instance, port, task_file_status);
		if (task_abort_flag == 1) {
			cmn_err(CE_WARN, "!ahci%d: the below command (s) on "
			    "port %d are aborted", instance, port);
			ahci_dump_commands(ahci_ctlp, port, failed_tags);
		}
	}

out1:
	/* Prepare the argument for the taskq */
	args = ahci_portp->ahciport_event_args;
	args->ahciea_ctlp = (void *)ahci_ctlp;
	args->ahciea_portp = (void *)ahci_portp;
	args->ahciea_event = intr_status;
	AHCI_ADDR_SET_PORT((ahci_addr_t *)args->ahciea_addrp, port);

	/* Start the taskq to handle error recovery */
	if ((ddi_taskq_dispatch(ahci_portp->ahciport_event_taskq,
	    ahci_events_handler,
	    (void *)args, DDI_NOSLEEP)) != DDI_SUCCESS) {
		ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_ERRPRINT;
		cmn_err(CE_WARN, "!ahci%d: start taskq for error recovery "
		    "port %d failed", instance, port);
	}
out0:
	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * Hot Plug Operation for platforms that support Cold Presence Detect.
 *
 * When set, a device status has changed as detected by the cold presence
 * detect logic. This bit can either be set due to a non-connected port
 * receiving a device, or a connected port having its device removed.
 * This bit is only valid if the port supports cold presence detect as
 * indicated by PxCMD.CPD set to '1'.
 *
 * At the moment, this interrupt is not needed and disabled and we just
 * log the debug message.
 */
static int
ahci_intr_cold_port_detect(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_cmd_status;
	sata_device_t sdevice;

	AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
	    "ahci_intr_cold_port_detect enter, port %d", port);

	mutex_enter(&ahci_portp->ahciport_mutex);

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));
	if (!(port_cmd_status & AHCI_CMD_STATUS_CPD)) {
		AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
		    "port %d does not support cold presence detect, so "
		    "we just ignore this interrupt", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_SUCCESS);
	}

	AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
	    "port %d device status has changed", port);

	bzero((void *)&sdevice, sizeof (sata_device_t));
	sdevice.satadev_addr.cport = ahci_ctlp->ahcictl_port_to_cport[port];
	sdevice.satadev_addr.qual = SATA_ADDR_CPORT;
	sdevice.satadev_addr.pmport = 0;
	sdevice.satadev_state = SATA_PSTATE_PWRON;

	if (port_cmd_status & AHCI_CMD_STATUS_CPS) {
		AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
		    "port %d: a device is hot plugged", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		sata_hba_event_notify(
		    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
		    &sdevice,
		    SATA_EVNT_DEVICE_ATTACHED);
		mutex_enter(&ahci_portp->ahciport_mutex);

	} else {
		AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
		    "port %d: a device is hot unplugged", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		sata_hba_event_notify(
		    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
		    &sdevice,
		    SATA_EVNT_DEVICE_DETACHED);
		mutex_enter(&ahci_portp->ahciport_mutex);
	}

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * Enable the interrupts for a particular port.
 */
static void
ahci_enable_port_intrs(ahci_ctl_t *ahci_ctlp, uint8_t port)
{
	ASSERT(MUTEX_HELD(&ahci_ctlp->ahcictl_ports[port]->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_enable_port_intrs enter, port %d", port);

	/*
	 * Clear port interrupt status before enabling interrupt
	 */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxIS(ahci_ctlp, port),
	    AHCI_PORT_INTR_MASK);

	/*
	 * Clear the pending bit from IS.IPS
	 */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_IS(ahci_ctlp), (1 << port));

	/*
	 * Enable the following interrupts:
	 *	Device to Host Register FIS Interrupt (DHRS)
	 *	PIO Setup FIS Interrupt (PSS)
	 *	Set Device Bits Interrupt (SDBS)
	 *	Unknown FIS Interrupt (UFS)
	 *	Port Connect Change Status (PCS)
	 *	PhyRdy Change Status (PRCS)
	 *	Overflow Status (OFS)
	 *	Interface Non-fatal Error Status (INFS)
	 *	Interface Fatal Error Status (IFS)
	 *	Host Bus Data Error Status (HBDS)
	 *	Host Bus Fatal Error Status (HBFS)
	 *	Task File Error Status (TFES)
	 */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxIE(ahci_ctlp, port),
	    (AHCI_INTR_STATUS_DHRS |
	    AHCI_INTR_STATUS_PSS |
	    AHCI_INTR_STATUS_SDBS |
	    AHCI_INTR_STATUS_UFS |
	    AHCI_INTR_STATUS_DPS |
	    AHCI_INTR_STATUS_PCS |
	    AHCI_INTR_STATUS_PRCS |
	    AHCI_INTR_STATUS_OFS |
	    AHCI_INTR_STATUS_INFS |
	    AHCI_INTR_STATUS_IFS |
	    AHCI_INTR_STATUS_HBDS |
	    AHCI_INTR_STATUS_HBFS |
	    AHCI_INTR_STATUS_TFES));
}

/*
 * Enable interrupts for all the ports.
 */
static void
ahci_enable_all_intrs(ahci_ctl_t *ahci_ctlp)
{
	uint32_t ghc_control;

	ASSERT(MUTEX_HELD(&ahci_ctlp->ahcictl_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp, "ahci_enable_all_intrs enter", NULL);

	ghc_control = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp));

	ghc_control |= AHCI_HBA_GHC_IE;

	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp), ghc_control);
}

/*
 * Disable interrupts for a particular port.
 */
static void
ahci_disable_port_intrs(ahci_ctl_t *ahci_ctlp, uint8_t port)
{
	ASSERT(ahci_ctlp->ahcictl_flags & AHCI_QUIESCE ||
	    MUTEX_HELD(&ahci_ctlp->ahcictl_ports[port]->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_disable_port_intrs enter, port %d", port);

	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxIE(ahci_ctlp, port), 0);
}

/*
 * Disable interrupts for the whole HBA.
 *
 * The global bit is cleared, then all interrupt sources from all
 * ports are disabled.
 */
static void
ahci_disable_all_intrs(ahci_ctl_t *ahci_ctlp)
{
	uint32_t ghc_control;

	ASSERT(ahci_ctlp->ahcictl_flags & (AHCI_ATTACH | AHCI_QUIESCE) ||
	    MUTEX_HELD(&ahci_ctlp->ahcictl_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp, "ahci_disable_all_intrs enter",
	    NULL);

	ghc_control = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp));

	ghc_control &= ~AHCI_HBA_GHC_IE;

	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp), ghc_control);
}

/*
 * Handle FIXED or MSI interrupts.
 */
/*
 * According to AHCI spec, the HBA may support several interrupt modes:
 *	* pin based interrupts (FIXED)
 *	* single MSI message interrupts
 *	* multiple MSI based message interrupts
 *
 * For pin based interrupts, the software interrupt handler need to check IS
 * register to find out which port has pending interrupts. And then check
 * PxIS register to find out which interrupt events happened on that port.
 *
 * For single MSI message interrupts, MSICAP.MC.MSIE is set with '1', and
 * MSICAP.MC.MME is set with '0'. This mode is similar to pin based interrupts
 * in that software interrupt handler need to check IS register to determine
 * which port triggered the interrupts since it uses a single message for all
 * port interrupts.
 *
 * HBA may optionally support multiple MSI message for better performance. In
 * this mode, each port may have its own interrupt message, and thus generation
 * of interrupts is no longer controlled through the IS register. MSICAP.MC.MMC
 * represents a power-of-2 wrapper on the number of implemented ports, and
 * the mapping of ports to interrupts is done in a 1-1 relationship, up to the
 * maximum number of assigned interrupts. When the number of MSI messages
 * allocated is less than the number requested, then hardware may have two
 * implementation behaviors:
 *	* assign each ports its own interrupt and then force all additional
 *	  ports to share the last interrupt message, and this condition is
 *	  indicated by clearing GHC.MRSM to '0'
 *	* revert to single MSI mode, indicated by setting GHC.MRSM to '1'
 * When multiple-message MSI is enabled, hardware will still set IS register
 * as single message case. And this IS register may be used by software when
 * fewer than the requested number of messages is granted in order to determine
 * which port had the interrupt.
 *
 * Note: The current ahci driver only supports the first two interrupt modes:
 * pin based interrupts and single MSI message interrupts, and the reason
 * is indicated in below code.
 */
static int
ahci_add_intrs(ahci_ctl_t *ahci_ctlp, int intr_type)
{
	dev_info_t *dip = ahci_ctlp->ahcictl_dip;
	int		count, avail, actual;
	int		i, rc;

	AHCIDBG(AHCIDBG_ENTRY|AHCIDBG_INIT|AHCIDBG_INTR, ahci_ctlp,
	    "ahci_add_intrs enter interrupt type 0x%x", intr_type);

	/* get number of interrupts. */
	rc = ddi_intr_get_nintrs(dip, intr_type, &count);
	if ((rc != DDI_SUCCESS) || (count == 0)) {
		AHCIDBG(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_get_nintrs() failed, "
		    "rc %d count %d\n", rc, count);
		return (DDI_FAILURE);
	}

	/* get number of available interrupts. */
	rc = ddi_intr_get_navail(dip, intr_type, &avail);
	if ((rc != DDI_SUCCESS) || (avail == 0)) {
		AHCIDBG(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_get_navail() failed, "
		    "rc %d avail %d\n", rc, avail);
		return (DDI_FAILURE);
	}

#if AHCI_DEBUG
	if (avail < count) {
		AHCIDBG(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_get_nintrs returned %d, navail() returned %d",
		    count, avail);
	}
#endif

	/*
	 * Note: So far Solaris restricts the maximum number of messages for
	 * x86 to 2, that is avail is 2, so here we set the count with 1 to
	 * force the driver to use single MSI message interrupt. In future if
	 * Solaris remove the restriction, then we need to delete the below
	 * code and try to use multiple interrupt routine to gain better
	 * performance.
	 */
	if ((intr_type == DDI_INTR_TYPE_MSI) && (count > 1)) {
		AHCIDBG(AHCIDBG_INTR, ahci_ctlp,
		    "force to use one interrupt routine though the "
		    "HBA supports %d interrupt", count);
		count = 1;
	}

	/* Allocate an array of interrupt handles. */
	ahci_ctlp->ahcictl_intr_size = count * sizeof (ddi_intr_handle_t);
	ahci_ctlp->ahcictl_intr_htable =
	    kmem_alloc(ahci_ctlp->ahcictl_intr_size, KM_SLEEP);

	/* call ddi_intr_alloc(). */
	rc = ddi_intr_alloc(dip, ahci_ctlp->ahcictl_intr_htable,
	    intr_type, 0, count, &actual, DDI_INTR_ALLOC_NORMAL);

	if ((rc != DDI_SUCCESS) || (actual == 0)) {
		AHCIDBG(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_alloc() failed, rc %d count %d actual %d "
		    "avail %d\n", rc, count, actual, avail);
		kmem_free(ahci_ctlp->ahcictl_intr_htable,
		    ahci_ctlp->ahcictl_intr_size);
		return (DDI_FAILURE);
	}

	/* use interrupt count returned */
#if AHCI_DEBUG
	if (actual < count) {
		AHCIDBG(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "Requested: %d, Received: %d", count, actual);
	}
#endif

	ahci_ctlp->ahcictl_intr_cnt = actual;

	/*
	 * Get priority for first, assume remaining are all the same.
	 */
	if (ddi_intr_get_pri(ahci_ctlp->ahcictl_intr_htable[0],
	    &ahci_ctlp->ahcictl_intr_pri) != DDI_SUCCESS) {
		AHCIDBG(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_get_pri() failed", NULL);

		/* Free already allocated intr. */
		for (i = 0; i < actual; i++) {
			(void) ddi_intr_free(ahci_ctlp->ahcictl_intr_htable[i]);
		}

		kmem_free(ahci_ctlp->ahcictl_intr_htable,
		    ahci_ctlp->ahcictl_intr_size);
		return (DDI_FAILURE);
	}

	/* Test for high level interrupt. */
	if (ahci_ctlp->ahcictl_intr_pri >= ddi_intr_get_hilevel_pri()) {
		AHCIDBG(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ahci_add_intrs: Hi level intr not supported", NULL);

		/* Free already allocated intr. */
		for (i = 0; i < actual; i++) {
			(void) ddi_intr_free(ahci_ctlp->ahcictl_intr_htable[i]);
		}

		kmem_free(ahci_ctlp->ahcictl_intr_htable,
		    sizeof (ddi_intr_handle_t));

		return (DDI_FAILURE);
	}

	/* Call ddi_intr_add_handler(). */
	for (i = 0; i < actual; i++) {
		if (ddi_intr_add_handler(ahci_ctlp->ahcictl_intr_htable[i],
		    ahci_intr, (caddr_t)ahci_ctlp, NULL) != DDI_SUCCESS) {
			AHCIDBG(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
			    "ddi_intr_add_handler() failed", NULL);

			/* Free already allocated intr. */
			for (i = 0; i < actual; i++) {
				(void) ddi_intr_free(
				    ahci_ctlp->ahcictl_intr_htable[i]);
			}

			kmem_free(ahci_ctlp->ahcictl_intr_htable,
			    ahci_ctlp->ahcictl_intr_size);
			return (DDI_FAILURE);
		}
	}

	if (ddi_intr_get_cap(ahci_ctlp->ahcictl_intr_htable[0],
	    &ahci_ctlp->ahcictl_intr_cap) != DDI_SUCCESS) {
		AHCIDBG(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_get_cap() failed", NULL);

		/* Free already allocated intr. */
		for (i = 0; i < actual; i++) {
			(void) ddi_intr_free(
			    ahci_ctlp->ahcictl_intr_htable[i]);
		}

		kmem_free(ahci_ctlp->ahcictl_intr_htable,
		    ahci_ctlp->ahcictl_intr_size);
		return (DDI_FAILURE);
	}

	if (ahci_ctlp->ahcictl_intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI. */
		(void) ddi_intr_block_enable(ahci_ctlp->ahcictl_intr_htable,
		    ahci_ctlp->ahcictl_intr_cnt);
	} else {
		/* Call ddi_intr_enable() for FIXED or MSI non block enable. */
		for (i = 0; i < ahci_ctlp->ahcictl_intr_cnt; i++) {
			(void) ddi_intr_enable(
			    ahci_ctlp->ahcictl_intr_htable[i]);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * Removes the registered interrupts irrespective of whether they
 * were legacy or MSI.
 *
 * NOTE: The controller interrupts must be disabled before calling
 * this routine.
 */
static void
ahci_rem_intrs(ahci_ctl_t *ahci_ctlp)
{
	int x;

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp, "ahci_rem_intrs entered", NULL);

	/* Disable all interrupts. */
	if ((ahci_ctlp->ahcictl_intr_type == DDI_INTR_TYPE_MSI) &&
	    (ahci_ctlp->ahcictl_intr_cap & DDI_INTR_FLAG_BLOCK)) {
		/* Call ddi_intr_block_disable(). */
		(void) ddi_intr_block_disable(ahci_ctlp->ahcictl_intr_htable,
		    ahci_ctlp->ahcictl_intr_cnt);
	} else {
		for (x = 0; x < ahci_ctlp->ahcictl_intr_cnt; x++) {
			(void) ddi_intr_disable(
			    ahci_ctlp->ahcictl_intr_htable[x]);
		}
	}

	/* Call ddi_intr_remove_handler(). */
	for (x = 0; x < ahci_ctlp->ahcictl_intr_cnt; x++) {
		(void) ddi_intr_remove_handler(
		    ahci_ctlp->ahcictl_intr_htable[x]);
		(void) ddi_intr_free(ahci_ctlp->ahcictl_intr_htable[x]);
	}

	kmem_free(ahci_ctlp->ahcictl_intr_htable, ahci_ctlp->ahcictl_intr_size);
}

/*
 * This routine tries to put port into P:NotRunning state by clearing
 * PxCMD.ST. HBA will clear PxCI to 0h, PxSACT to 0h, PxCMD.CCS to 0h
 * and PxCMD.CR to '0'.
 */
static int
ahci_put_port_into_notrunning_state(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_cmd_status;
	int loop_count;

	ASSERT(ahci_ctlp->ahcictl_flags & AHCI_QUIESCE ||
	    MUTEX_HELD(&ahci_ctlp->ahcictl_ports[port]->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_put_port_into_notrunning_state enter: port %d", port);

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	port_cmd_status &= ~AHCI_CMD_STATUS_ST;
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port), port_cmd_status);

	/* Wait until PxCMD.CR is cleared */
	loop_count = 0;
	do {
		port_cmd_status =
		    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

		if (loop_count++ > AHCI_POLLRATE_PORT_IDLE) {
			AHCIDBG(AHCIDBG_INIT, ahci_ctlp,
			    "clearing port %d CMD.CR timeout, "
			    "port_cmd_status = 0x%x", port,
			    port_cmd_status);
			/*
			 * We are effectively timing out after 0.5 sec.
			 * This value is specified in AHCI spec.
			 */
			break;
		}

		/* Wait for 10 millisec */
		drv_usecwait(AHCI_10MS_USECS);
	} while (port_cmd_status & AHCI_CMD_STATUS_CR);

	ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_STARTED;

	if (port_cmd_status & AHCI_CMD_STATUS_CR) {
		AHCIDBG(AHCIDBG_INIT|AHCIDBG_POLL_LOOP, ahci_ctlp,
		    "ahci_put_port_into_notrunning_state: failed to clear "
		    "PxCMD.CR to '0' after loop count: %d, and "
		    "port_cmd_status = 0x%x", loop_count, port_cmd_status);
		return (AHCI_FAILURE);
	} else {
		AHCIDBG(AHCIDBG_INIT|AHCIDBG_POLL_LOOP, ahci_ctlp,
		    "ahci_put_port_into_notrunning_state: succeeded to clear "
		    "PxCMD.CR to '0' after loop count: %d, and "
		    "port_cmd_status = 0x%x", loop_count, port_cmd_status);
		return (AHCI_SUCCESS);
	}
}

/*
 * First clear PxCMD.ST, and then check PxTFD. If both PxTFD.STS.BSY
 * and PxTFD.STS.DRQ cleared to '0', it means the device is in a
 * stable state, then set PxCMD.ST to '1' to start the port directly.
 * If PxTFD.STS.BSY or PxTFD.STS.DRQ is set to '1', then issue a
 * COMRESET to the device to put it in an idle state.
 *
 * The fifth argument returns whether the port reset is involved during
 * the process.
 *
 * The routine will be called under following scenarios:
 * 	+ To reset the HBA
 *	+ To abort the packet(s)
 *	+ To reset the port
 *	+ To activate the port
 *	+ Fatal error recovery
 *	+ To abort the timeout packet(s)
 *
 * NOTES!!! During this procedure, PxSERR register will be cleared, and
 * according to the spec, the clearance of three bits will also clear
 * three interrupt status bits.
 *	1. PxSERR.DIAG.F will clear PxIS.UFS
 *	2. PxSERR.DIAG.X will clear PxIS.PCS
 *	3. PxSERR.DIAG.N will clear PxIS.PRCS
 *
 * Among these three interrupt events, the driver needs to take care of
 * PxIS.PRCS, which is the hot plug event. When the driver found out
 * a device was unplugged, it will call the interrupt handler.
 */
static int
ahci_restart_port_wait_till_ready(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port, int flag, int *reset_flag)
{
	uint32_t port_sstatus;
	uint32_t task_file_status;
	sata_device_t sdevice;
	int rval;
	ahci_addr_t addr_port;
	ahci_pmult_info_t *pminfo = NULL;
	int dev_exists_begin = 0;
	int dev_exists_end = 0;
	uint32_t previous_dev_type = ahci_portp->ahciport_device_type;
	int npmport = 0;
	uint8_t cport = ahci_ctlp->ahcictl_port_to_cport[port];

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_restart_port_wait_till_ready: port %d enter", port);

	AHCI_ADDR_SET_PORT(&addr_port, port);

	if (ahci_portp->ahciport_device_type != SATA_DTYPE_NONE)
		dev_exists_begin = 1;

	/* First clear PxCMD.ST */
	rval = ahci_put_port_into_notrunning_state(ahci_ctlp, ahci_portp,
	    port);
	if (rval != AHCI_SUCCESS)
		/*
		 * If PxCMD.CR does not clear within a reasonable time, it
		 * may assume the interface is in a hung condition and may
		 * continue with issuing the port reset.
		 */
		goto reset;

	/* Then clear PxSERR */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port),
	    AHCI_SERROR_CLEAR_ALL);

	/* Then get PxTFD */
	task_file_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));

	/*
	 * Check whether the device is in a stable status, if yes,
	 * then start the port directly. However for ahci_tran_reset_dport,
	 * we may have to perform a port reset.
	 */
	if (!(task_file_status & (AHCI_TFD_STS_BSY | AHCI_TFD_STS_DRQ)) &&
	    !(flag & AHCI_PORT_RESET))
		goto out;

reset:
	/*
	 * If PxTFD.STS.BSY or PxTFD.STS.DRQ is set to '1', then issue
	 * a COMRESET to the device
	 */
	ahci_disable_port_intrs(ahci_ctlp, port);
	rval = ahci_port_reset(ahci_ctlp, ahci_portp, &addr_port);
	ahci_enable_port_intrs(ahci_ctlp, port);

#ifdef AHCI_DEBUG
	if (rval != AHCI_SUCCESS)
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_restart_port_wait_till_ready: port %d failed",
		    port);
#endif

	if (reset_flag != NULL)
		*reset_flag = 1;

	/* Indicate to the framework that a reset has happened. */
	if ((ahci_portp->ahciport_device_type != SATA_DTYPE_NONE) &&
	    (ahci_portp->ahciport_device_type != SATA_DTYPE_PMULT) &&
	    !(flag & AHCI_RESET_NO_EVENTS_UP)) {
		/* Set the reset in progress flag */
		ahci_portp->ahciport_reset_in_progress = 1;

		bzero((void *)&sdevice, sizeof (sata_device_t));
		sdevice.satadev_addr.cport =
		    ahci_ctlp->ahcictl_port_to_cport[port];
		sdevice.satadev_addr.pmport = 0;
		sdevice.satadev_addr.qual = SATA_ADDR_DCPORT;

		sdevice.satadev_state = SATA_DSTATE_RESET |
		    SATA_DSTATE_PWR_ACTIVE;
		if (ahci_ctlp->ahcictl_sata_hba_tran) {
			mutex_exit(&ahci_portp->ahciport_mutex);
			sata_hba_event_notify(
			    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
			    &sdevice,
			    SATA_EVNT_DEVICE_RESET);
			mutex_enter(&ahci_portp->ahciport_mutex);
		}

		AHCIDBG(AHCIDBG_EVENT, ahci_ctlp,
		    "port %d sending event up: SATA_EVNT_DEVICE_RESET", port);
	} else {
		ahci_portp->ahciport_reset_in_progress = 0;
	}

out:
	(void) ahci_start_port(ahci_ctlp, ahci_portp, port);

	/* SStatus tells the presence of device. */
	port_sstatus = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSSTS(ahci_ctlp, port));

	if (SSTATUS_GET_DET(port_sstatus) == SSTATUS_DET_DEVPRE_PHYCOM) {
		dev_exists_end = 1;
	}

	if (dev_exists_begin == 0 && dev_exists_end == 0) /* 0 -> 0 */
		return (rval);

	/* Check whether a hot plug event happened */
	if (dev_exists_begin == 1 && dev_exists_end == 0) { /* 1 -> 0 */
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_restart_port_wait_till_ready: port %d "
		    "device is removed", port);
		ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_NODEV;
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_restart_port_wait_till_ready: port %d "
		    "AHCI_PORT_FLAG_NODEV flag is set", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		(void) ahci_intr_phyrdy_change(ahci_ctlp, ahci_portp, port);
		mutex_enter(&ahci_portp->ahciport_mutex);

		return (rval);
	}


	/* 0/1 -> 1 : device may change */
	/*
	 * May be called by ahci_fatal_error_recovery_handler, so
	 * don't issue software if the previous device is ATAPI.
	 */
	if (ahci_portp->ahciport_device_type == SATA_DTYPE_ATAPI)
		return (rval);

	/*
	 * The COMRESET will make port multiplier enter legacy mode.
	 * Issue a software reset to make it work again.
	 */
	ahci_disable_port_intrs(ahci_ctlp, port);
	ahci_find_dev_signature(ahci_ctlp, ahci_portp, &addr_port);
	ahci_enable_port_intrs(ahci_ctlp, port);

	/*
	 * Following codes are specific for the port multiplier
	 */
	if (previous_dev_type != SATA_DTYPE_PMULT &&
	    ahci_portp->ahciport_device_type != SATA_DTYPE_PMULT) {
		/* in case previous_dev_type is corrupt */
		ahci_dealloc_pmult(ahci_ctlp, ahci_portp);
		(void) ahci_start_port(ahci_ctlp, ahci_portp, port);
		return (rval);
	}

	/* Device change: PMult -> Non-PMult */
	if (previous_dev_type == SATA_DTYPE_PMULT &&
	    ahci_portp->ahciport_device_type != SATA_DTYPE_PMULT) {
		/*
		 * This might happen because
		 * 1. Software reset failed. Port multiplier is not correctly
		 *    enumerated.
		 * 2. Another non-port-multiplier device is attached. Perhaps
		 *    the port multiplier was replaced by another device by
		 *    whatever reason, but AHCI driver missed hot-plug event.
		 *
		 * Now that the port has been initialized, we just need to
		 * update the port structure according new device, then report
		 * and wait SATA framework to probe new device.
		 */

		/* Force to release pmult resource */
		ahci_dealloc_pmult(ahci_ctlp, ahci_portp);
		(void) ahci_start_port(ahci_ctlp, ahci_portp, port);

		bzero((void *)&sdevice, sizeof (sata_device_t));
		sdevice.satadev_addr.cport =
		    ahci_ctlp->ahcictl_port_to_cport[port];
		sdevice.satadev_addr.pmport = 0;
		sdevice.satadev_addr.qual = SATA_ADDR_DCPORT;

		sdevice.satadev_state = SATA_DSTATE_RESET |
		    SATA_DSTATE_PWR_ACTIVE;

		mutex_exit(&ahci_portp->ahciport_mutex);
		sata_hba_event_notify(
		    ahci_ctlp->ahcictl_dip,
		    &sdevice,
		    SATA_EVNT_DEVICE_RESET);
		mutex_enter(&ahci_portp->ahciport_mutex);

		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "Port multiplier is [Gone] at port %d ", port);
		AHCIDBG(AHCIDBG_EVENT, ahci_ctlp,
		    "port %d sending event up: SATA_EVNT_DEVICE_RESET", port);

		return (AHCI_SUCCESS);
	}

	/* Device change: Non-PMult -> PMult */
	if (ahci_portp->ahciport_device_type == SATA_DTYPE_PMULT) {

		/* NOTE: The PxCMD.PMA may be cleared by HBA reset. */
		ahci_alloc_pmult(ahci_ctlp, ahci_portp);

		(void) ahci_start_port(ahci_ctlp, ahci_portp, port);
	}
	pminfo = ahci_portp->ahciport_pmult_info;
	ASSERT(pminfo != NULL);

	/* Device (may) change: PMult -> PMult */
	/*
	 * First initialize port multiplier. Set state to READY and wait for
	 * probe entry point to initialize it
	 */
	ahci_portp->ahciport_port_state = SATA_STATE_READY;

	/*
	 * It's a little complicated while target is a port multiplier. we
	 * need to COMRESET all pmports behind that PMult otherwise those
	 * sub-links between the PMult and the sub-devices will be in an
	 * inactive state (indicated by PSCR0/PxSSTS) and the following access
	 * to those sub-devices will be rejected by Link-Fatal-Error.
	 */
	/*
	 * The PxSNTF will be set soon after the pmult is plugged. While the
	 * pmult itself is attaching, sata_hba_event_notfiy will fail. so we
	 * simply mark every sub-port as 'unknown', then ahci_probe_pmport
	 * will initialized it.
	 */
	for (npmport = 0; npmport < pminfo->ahcipmi_num_dev_ports; npmport++)
		pminfo->ahcipmi_port_state[npmport] = SATA_STATE_UNKNOWN;

	/* Report reset event. */
	ahci_portp->ahciport_reset_in_progress = 1;

	bzero((void *)&sdevice, sizeof (sata_device_t));
	sdevice.satadev_addr.cport = cport;
	sdevice.satadev_addr.pmport = SATA_PMULT_HOSTPORT;
	sdevice.satadev_addr.qual = SATA_ADDR_PMULT;
	sdevice.satadev_state = SATA_DSTATE_RESET | SATA_DSTATE_PWR_ACTIVE;
	sata_hba_event_notify(ahci_ctlp->ahcictl_dip, &sdevice,
	    SATA_EVNT_DEVICE_RESET);

	return (rval);
}

/*
 * This routine may be called under four scenarios:
 *	a) do the recovery from fatal error
 *	b) or we need to timeout some commands
 *	c) or we need to abort some commands
 *	d) or we need reset device/port/controller
 *
 * In all these scenarios, we need to send any pending unfinished
 * commands up to sata framework.
 */
static void
ahci_mop_commands(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp,
    uint32_t slot_status,
    uint32_t failed_tags,
    uint32_t timeout_tags,
    uint32_t aborted_tags,
    uint32_t reset_tags)
{
	uint32_t finished_tags = 0;
	uint32_t unfinished_tags = 0;
	int tmp_slot;
	sata_pkt_t *satapkt;
	int ncq_cmd_in_progress = 0;
	int err_retri_cmd_in_progress = 0;
	int rdwr_pmult_cmd_in_progress = 0;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_ERRS|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_mop_commands entered: port: %d slot_status: 0x%x",
	    ahci_portp->ahciport_port_num, slot_status);

	AHCIDBG(AHCIDBG_ERRS|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_mop_commands: failed_tags: 0x%x, "
	    "timeout_tags: 0x%x aborted_tags: 0x%x, "
	    "reset_tags: 0x%x", failed_tags,
	    timeout_tags, aborted_tags, reset_tags);

#ifdef AHCI_DEBUG
	if (ahci_debug_flags & AHCIDBG_ERRS) {
		int i;
		char msg_buf[200] = {0, };
		for (i = 0x1f; i >= 0; i--) {
			if (ahci_portp->ahciport_slot_pkts[i] != NULL)
				msg_buf[i] = 'X';
			else
				msg_buf[i] = '.';
		}
		msg_buf[0x20] = '\0';
		cmn_err(CE_NOTE, "port[%d] slots: %s",
		    ahci_portp->ahciport_port_num, msg_buf);
		cmn_err(CE_NOTE, "[ERR-RT] %p [RW-PM] %p ",
		    (void *)ahci_portp->ahciport_err_retri_pkt,
		    (void *)ahci_portp->ahciport_rdwr_pmult_pkt);
	}
#endif

	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		finished_tags = ahci_portp->ahciport_pending_tags &
		    ~slot_status & AHCI_SLOT_MASK(ahci_ctlp);

		unfinished_tags = slot_status &
		    AHCI_SLOT_MASK(ahci_ctlp) &
		    ~failed_tags &
		    ~aborted_tags &
		    ~reset_tags &
		    ~timeout_tags;
	} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		ncq_cmd_in_progress = 1;
		finished_tags = ahci_portp->ahciport_pending_ncq_tags &
		    ~slot_status & AHCI_NCQ_SLOT_MASK(ahci_portp);

		unfinished_tags = slot_status &
		    AHCI_NCQ_SLOT_MASK(ahci_portp) &
		    ~failed_tags &
		    ~aborted_tags &
		    ~reset_tags &
		    ~timeout_tags;
	} else if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp)) {

		/*
		 * When AHCI_PORT_FLAG_RQSENSE or AHCI_PORT_FLAG_RDLOGEXT is
		 * set, it means REQUEST SENSE or READ LOG EXT command doesn't
		 * complete successfully due to one of the following three
		 * conditions:
		 *
		 *	1. Fatal error - failed_tags includes its slot
		 *	2. Timed out - timeout_tags includes its slot
		 *	3. Aborted when hot unplug - aborted_tags includes its
		 *	   slot
		 *
		 * Please note that the command is always sent down in Slot 0
		 */
		err_retri_cmd_in_progress = 1;
		AHCIDBG(AHCIDBG_ERRS|AHCIDBG_NCQ, ahci_ctlp,
		    "ahci_mop_commands is called for port %d while "
		    "REQUEST SENSE or READ LOG EXT for error retrieval "
		    "is being executed slot_status = 0x%x",
		    ahci_portp->ahciport_port_num, slot_status);
		ASSERT(ahci_portp->ahciport_mop_in_progress > 1);
		ASSERT(slot_status == 0x1);
	} else if (RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp)) {
		rdwr_pmult_cmd_in_progress = 1;
		AHCIDBG(AHCIDBG_ERRS|AHCIDBG_PMULT, ahci_ctlp,
		    "ahci_mop_commands is called for port %d while "
		    "READ/WRITE PORTMULT command is being executed",
		    ahci_portp->ahciport_port_num);

		ASSERT(slot_status == 0x1);
	}

#ifdef AHCI_DEBUG
	AHCIDBG(AHCIDBG_ERRS|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_mop_commands: finished_tags: 0x%x, "
	    "unfinished_tags 0x%x", finished_tags, unfinished_tags);
#endif

	/* Send up finished packets with SATA_PKT_COMPLETED */
	while (finished_tags) {
		tmp_slot = ddi_ffs(finished_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(satapkt != NULL);

		AHCIDBG(AHCIDBG_INFO, ahci_ctlp, "ahci_mop_commands: "
		    "sending up pkt 0x%p with SATA_PKT_COMPLETED",
		    (void *)satapkt);

		/*
		 * Cannot fetch the return register content since the port
		 * was restarted, so the corresponding tag will be set to
		 * aborted tags.
		 */
		if (satapkt->satapkt_cmd.satacmd_flags.sata_special_regs) {
			CLEAR_BIT(finished_tags, tmp_slot);
			aborted_tags |= tmp_slot;
			continue;
		}

		if (ncq_cmd_in_progress)
			CLEAR_BIT(ahci_portp->ahciport_pending_ncq_tags,
			    tmp_slot);
		CLEAR_BIT(ahci_portp->ahciport_pending_tags, tmp_slot);
		CLEAR_BIT(finished_tags, tmp_slot);
		ahci_portp->ahciport_slot_pkts[tmp_slot] = NULL;

		ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_COMPLETED);
	}

	/* Send up failed packets with SATA_PKT_DEV_ERROR. */
	while (failed_tags) {
		if (err_retri_cmd_in_progress) {
			satapkt = ahci_portp->ahciport_err_retri_pkt;
			ASSERT(satapkt != NULL);
			ASSERT(failed_tags == 0x1);

			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
			    "sending up pkt 0x%p with SATA_PKT_DEV_ERROR",
			    (void *)satapkt);
			ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_DEV_ERROR);
			break;
		}
		if (rdwr_pmult_cmd_in_progress) {
			satapkt = ahci_portp->ahciport_rdwr_pmult_pkt;
			ASSERT(satapkt != NULL);
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_mop_commands: sending up "
			    "rdwr pmult pkt 0x%p with SATA_PKT_DEV_ERROR",
			    (void *)satapkt);
			ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_DEV_ERROR);
			break;
		}

		tmp_slot = ddi_ffs(failed_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(satapkt != NULL);

		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
		    "sending up pkt 0x%p with SATA_PKT_DEV_ERROR",
		    (void *)satapkt);

		if (ncq_cmd_in_progress)
			CLEAR_BIT(ahci_portp->ahciport_pending_ncq_tags,
			    tmp_slot);
		CLEAR_BIT(ahci_portp->ahciport_pending_tags, tmp_slot);
		CLEAR_BIT(failed_tags, tmp_slot);
		ahci_portp->ahciport_slot_pkts[tmp_slot] = NULL;

		ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_DEV_ERROR);
	}

	/* Send up timeout packets with SATA_PKT_TIMEOUT. */
	while (timeout_tags) {
		if (err_retri_cmd_in_progress) {
			satapkt = ahci_portp->ahciport_err_retri_pkt;
			ASSERT(satapkt != NULL);
			ASSERT(timeout_tags == 0x1);

			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
			    "sending up pkt 0x%p with SATA_PKT_TIMEOUT",
			    (void *)satapkt);
			ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_TIMEOUT);
			break;
		}
		if (rdwr_pmult_cmd_in_progress) {
			satapkt = ahci_portp->ahciport_rdwr_pmult_pkt;
			ASSERT(satapkt != NULL);
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_mop_commands: sending up "
			    "rdwr pmult pkt 0x%p with SATA_PKT_TIMEOUT",
			    (void *)satapkt);
			ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_TIMEOUT);
			break;
		}

		tmp_slot = ddi_ffs(timeout_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(satapkt != NULL);

		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
		    "sending up pkt 0x%p with SATA_PKT_TIMEOUT",
		    (void *)satapkt);

		if (ncq_cmd_in_progress)
			CLEAR_BIT(ahci_portp->ahciport_pending_ncq_tags,
			    tmp_slot);
		CLEAR_BIT(ahci_portp->ahciport_pending_tags, tmp_slot);
		CLEAR_BIT(timeout_tags, tmp_slot);
		ahci_portp->ahciport_slot_pkts[tmp_slot] = NULL;

		ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_TIMEOUT);
	}

	/* Send up aborted packets with SATA_PKT_ABORTED */
	while (aborted_tags) {
		if (err_retri_cmd_in_progress) {
			satapkt = ahci_portp->ahciport_err_retri_pkt;
			ASSERT(satapkt != NULL);
			ASSERT(aborted_tags == 0x1);

			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
			    "sending up pkt 0x%p with SATA_PKT_ABORTED",
			    (void *)satapkt);
			ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_ABORTED);
			break;
		}
		if (rdwr_pmult_cmd_in_progress) {
			satapkt = ahci_portp->ahciport_rdwr_pmult_pkt;
			ASSERT(satapkt != NULL);
			ASSERT(aborted_tags == 0x1);
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_mop_commands: sending up "
			    "rdwr pmult pkt 0x%p with SATA_PKT_ABORTED",
			    (void *)satapkt);
			ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_ABORTED);
			break;
		}

		tmp_slot = ddi_ffs(aborted_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(satapkt != NULL);

		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
		    "sending up pkt 0x%p with SATA_PKT_ABORTED",
		    (void *)satapkt);

		if (ncq_cmd_in_progress)
			CLEAR_BIT(ahci_portp->ahciport_pending_ncq_tags,
			    tmp_slot);
		CLEAR_BIT(ahci_portp->ahciport_pending_tags, tmp_slot);
		CLEAR_BIT(aborted_tags, tmp_slot);
		ahci_portp->ahciport_slot_pkts[tmp_slot] = NULL;

		ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_ABORTED);
	}

	/* Send up reset packets with SATA_PKT_RESET. */
	while (reset_tags) {
		if (rdwr_pmult_cmd_in_progress) {
			satapkt = ahci_portp->ahciport_rdwr_pmult_pkt;
			ASSERT(satapkt != NULL);
			ASSERT(aborted_tags == 0x1);
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_mop_commands: sending up "
			    "rdwr pmult pkt 0x%p with SATA_PKT_RESET",
			    (void *)satapkt);
			ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_RESET);
			break;
		}

		tmp_slot = ddi_ffs(reset_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(satapkt != NULL);

		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
		    "sending up pkt 0x%p with SATA_PKT_RESET",
		    (void *)satapkt);

		if (ncq_cmd_in_progress)
			CLEAR_BIT(ahci_portp->ahciport_pending_ncq_tags,
			    tmp_slot);
		CLEAR_BIT(ahci_portp->ahciport_pending_tags, tmp_slot);
		CLEAR_BIT(reset_tags, tmp_slot);
		ahci_portp->ahciport_slot_pkts[tmp_slot] = NULL;

		ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_RESET);
	}

	/* Send up unfinished packets with SATA_PKT_RESET */
	while (unfinished_tags) {
		tmp_slot = ddi_ffs(unfinished_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(satapkt != NULL);

		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
		    "sending up pkt 0x%p with SATA_PKT_RESET",
		    (void *)satapkt);

		if (ncq_cmd_in_progress)
			CLEAR_BIT(ahci_portp->ahciport_pending_ncq_tags,
			    tmp_slot);
		CLEAR_BIT(ahci_portp->ahciport_pending_tags, tmp_slot);
		CLEAR_BIT(unfinished_tags, tmp_slot);
		ahci_portp->ahciport_slot_pkts[tmp_slot] = NULL;

		ahci_add_doneq(ahci_portp, satapkt, SATA_PKT_RESET);
	}

	ahci_portp->ahciport_mop_in_progress--;
	ASSERT(ahci_portp->ahciport_mop_in_progress >= 0);

	if (ahci_portp->ahciport_mop_in_progress == 0)
		ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_MOPPING;

	ahci_flush_doneq(ahci_portp);
}

/*
 * This routine is going to first request a READ LOG EXT sata pkt from sata
 * module, and then deliver it to the HBA to get the ncq failure context.
 * The return value is the exactly failed tags.
 */
static uint32_t
ahci_get_rdlogext_data(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    uint8_t port)
{
	sata_device_t	sdevice;
	sata_pkt_t	*rdlog_spkt, *spkt;
	ddi_dma_handle_t buf_dma_handle;
	ahci_addr_t	addr;
	int		loop_count;
	int		rval;
	int		failed_slot;
	uint32_t	failed_tags = 0;
	struct sata_ncq_error_recovery_page *ncq_err_page;

	AHCIDBG(AHCIDBG_ENTRY|AHCIDBG_NCQ, ahci_ctlp,
	    "ahci_get_rdlogext_data enter: port %d", port);

	/* Prepare the sdevice data */
	bzero((void *)&sdevice, sizeof (sata_device_t));
	sdevice.satadev_addr.cport = ahci_ctlp->ahcictl_port_to_cport[port];

	sdevice.satadev_addr.qual = SATA_ADDR_DCPORT;
	sdevice.satadev_addr.pmport = 0;

	/* Translate sata_device.satadev_addr -> ahci_addr */
	ahci_get_ahci_addr(ahci_ctlp, &sdevice, &addr);

	/*
	 * Call the sata hba interface to get a rdlog spkt
	 */
	loop_count = 0;
loop:
	rdlog_spkt = sata_get_error_retrieval_pkt(ahci_ctlp->ahcictl_dip,
	    &sdevice, SATA_ERR_RETR_PKT_TYPE_NCQ);
	if (rdlog_spkt == NULL) {
		if (loop_count++ < AHCI_POLLRATE_GET_SPKT) {
			/* Sleep for a while */
			drv_usecwait(AHCI_10MS_USECS);
			goto loop;
		}
		/* Timed out after 1s */
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "failed to get rdlog spkt for port %d", port);
		return (failed_tags);
	}

	ASSERT(rdlog_spkt->satapkt_op_mode & SATA_OPMODE_SYNCH);

	/*
	 * This flag is used to handle the specific error recovery when the
	 * READ LOG EXT command gets a failure (fatal error or time-out).
	 */
	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_RDLOGEXT;

	/*
	 * This start is not supposed to fail because after port is restarted,
	 * the whole command list is empty.
	 */
	ahci_portp->ahciport_err_retri_pkt = rdlog_spkt;
	(void) ahci_do_sync_start(ahci_ctlp, ahci_portp, &addr, rdlog_spkt);
	ahci_portp->ahciport_err_retri_pkt = NULL;

	/* Remove the flag after READ LOG EXT command is completed */
	ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_RDLOGEXT;

	if (rdlog_spkt->satapkt_reason == SATA_PKT_COMPLETED) {
		/* Update the request log data */
		buf_dma_handle = *(ddi_dma_handle_t *)
		    (rdlog_spkt->satapkt_cmd.satacmd_err_ret_buf_handle);
		rval = ddi_dma_sync(buf_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		if (rval == DDI_SUCCESS) {
			ncq_err_page =
			    (struct sata_ncq_error_recovery_page *)rdlog_spkt->
			    satapkt_cmd.satacmd_bp->b_un.b_addr;

			/* Get the failed tag */
			failed_slot = ncq_err_page->ncq_tag;
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_get_rdlogext_data: port %d "
			    "failed slot %d", port, failed_slot);
			if (failed_slot & NQ) {
				AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
				    "the failed slot is not a valid tag", NULL);
				goto out;
			}

			failed_slot &= NCQ_TAG_MASK;
			spkt = ahci_portp->ahciport_slot_pkts[failed_slot];
			AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_get_rdlogext_data: failed spkt 0x%p",
			    (void *)spkt);
			if (spkt == NULL) {
				AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
				    "the failed slot spkt is NULL", NULL);
				goto out;
			}

			failed_tags = 0x1 << failed_slot;

			/* Fill out the error context */
			ahci_copy_ncq_err_page(&spkt->satapkt_cmd,
			    ncq_err_page);
			ahci_update_sata_registers(ahci_ctlp, port,
			    &spkt->satapkt_device);
		}
	}
out:
	sata_free_error_retrieval_pkt(rdlog_spkt);

	return (failed_tags);
}

/*
 * This routine is going to first request a REQUEST SENSE sata pkt from sata
 * module, and then deliver it to the HBA to get the sense data and copy
 * the sense data back to the orignal failed sata pkt, and free the REQUEST
 * SENSE sata pkt later.
 */
static void
ahci_get_rqsense_data(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    uint8_t port, sata_pkt_t *spkt)
{
	sata_device_t	sdevice;
	sata_pkt_t	*rs_spkt;
	sata_cmd_t	*sata_cmd;
	ddi_dma_handle_t buf_dma_handle;
	ahci_addr_t	addr;
	int		loop_count;
#if AHCI_DEBUG
	struct scsi_extended_sense *rqsense;
#endif

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_get_rqsense_data enter: port %d", port);

	/* Prepare the sdevice data */
	bzero((void *)&sdevice, sizeof (sata_device_t));
	sdevice.satadev_addr.cport = ahci_ctlp->ahcictl_port_to_cport[port];

	sdevice.satadev_addr.qual = SATA_ADDR_DCPORT;
	sdevice.satadev_addr.pmport = 0;

	/* Translate sata_device.satadev_addr -> ahci_addr */
	ahci_get_ahci_addr(ahci_ctlp, &sdevice, &addr);

	sata_cmd = &spkt->satapkt_cmd;

	/*
	 * Call the sata hba interface to get a rs spkt
	 */
	loop_count = 0;
loop:
	rs_spkt = sata_get_error_retrieval_pkt(ahci_ctlp->ahcictl_dip,
	    &sdevice, SATA_ERR_RETR_PKT_TYPE_ATAPI);
	if (rs_spkt == NULL) {
		if (loop_count++ < AHCI_POLLRATE_GET_SPKT) {
			/* Sleep for a while */
			drv_usecwait(AHCI_10MS_USECS);
			goto loop;

		}
		/* Timed out after 1s */
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "failed to get rs spkt for port %d", port);
		return;
	}

	ASSERT(rs_spkt->satapkt_op_mode & SATA_OPMODE_SYNCH);

	/*
	 * This flag is used to handle the specific error recovery when the
	 * REQUEST SENSE command gets a faiure (fatal error or time-out).
	 */
	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_RQSENSE;

	/*
	 * This start is not supposed to fail because after port is restarted,
	 * the whole command list is empty.
	 */
	ahci_portp->ahciport_err_retri_pkt = rs_spkt;
	(void) ahci_do_sync_start(ahci_ctlp, ahci_portp, &addr, rs_spkt);
	ahci_portp->ahciport_err_retri_pkt = NULL;

	/* Remove the flag after REQUEST SENSE command is completed */
	ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_RQSENSE;

	if (rs_spkt->satapkt_reason == SATA_PKT_COMPLETED) {
		/* Update the request sense data */
		buf_dma_handle = *(ddi_dma_handle_t *)
		    (rs_spkt->satapkt_cmd.satacmd_err_ret_buf_handle);
		(void) ddi_dma_sync(buf_dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORKERNEL);
		/* Copy the request sense data */
		bcopy(rs_spkt->
		    satapkt_cmd.satacmd_bp->b_un.b_addr,
		    &sata_cmd->satacmd_rqsense,
		    SATA_ATAPI_MIN_RQSENSE_LEN);
#if AHCI_DEBUG
		rqsense = (struct scsi_extended_sense *)
		    sata_cmd->satacmd_rqsense;

		/* Dump the sense data */
		AHCIDBG(AHCIDBG_SENSEDATA, ahci_ctlp, "\n", NULL);
		AHCIDBG(AHCIDBG_SENSEDATA, ahci_ctlp,
		    "Sense data for satapkt %p ATAPI cmd 0x%x",
		    spkt, sata_cmd->satacmd_acdb[0]);
		AHCIDBG(AHCIDBG_SENSEDATA, ahci_ctlp,
		    "  es_code 0x%x es_class 0x%x "
		    "es_key 0x%x es_add_code 0x%x "
		    "es_qual_code 0x%x",
		    rqsense->es_code, rqsense->es_class,
		    rqsense->es_key, rqsense->es_add_code,
		    rqsense->es_qual_code);
#endif
	}

	sata_free_error_retrieval_pkt(rs_spkt);
}

/*
 * Fatal errors will cause the HBA to enter the ERR: Fatal state. To recover,
 * the port must be restarted. When the HBA detects thus error, it may try
 * to abort a transfer. And if the transfer was aborted, the device is
 * expected to send a D2H Register FIS with PxTFD.STS.ERR set to '1' and both
 * PxTFD.STS.BSY and PxTFD.STS.DRQ cleared to '0'. Then system software knows
 * that the device is in a stable status and transfers may be restarted without
 * issuing a COMRESET to the device. If PxTFD.STS.BSY or PxTFD.STS.DRQ is set,
 * then the software will send the COMRESET to do the port reset.
 *
 * Software should perform the appropriate error recovery actions based on
 * whether non-queued commands were being issued or natived command queuing
 * commands were being issued.
 *
 * And software will complete the command that had the error with error mark
 * to higher level software.
 *
 * Fatal errors include the following:
 *	PxIS.IFS - Interface Fatal Error Status
 *	PxIS.HBDS - Host Bus Data Error Status
 *	PxIS.HBFS - Host Bus Fatal Error Status
 *	PxIS.TFES - Task File Error Status
 */
static void
ahci_fatal_error_recovery_handler(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, ahci_addr_t *addrp, uint32_t intr_status)
{
	uint32_t	port_cmd_status;
	uint32_t	slot_status = 0;
	uint32_t	failed_tags = 0;
	int		failed_slot;
	int		reset_flag = 0, flag = 0;
	ahci_fis_d2h_register_t	*ahci_rcvd_fisp;
	sata_cmd_t	*sata_cmd = NULL;
	sata_pkt_t	*spkt = NULL;
#if AHCI_DEBUG
	ahci_cmd_header_t *cmd_header;
#endif
	uint8_t		port = addrp->aa_port;
	int		instance = ddi_get_instance(ahci_ctlp->ahcictl_dip);
	int		rval;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_fatal_error_recovery_handler enter: port %d", port);

	/* Port multiplier error */
	if (ahci_portp->ahciport_device_type == SATA_DTYPE_PMULT) {
		/* FBS code is neither completed nor tested. */
		ahci_pmult_error_recovery_handler(ahci_ctlp, ahci_portp,
		    port, intr_status);

		/* Force a port reset */
		flag = AHCI_PORT_RESET;
	}

	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp) ||
	    ERR_RETRI_CMD_IN_PROGRESS(ahci_portp)) {

		/* Read PxCI to see which commands are still outstanding */
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

		/*
		 * Read PxCMD.CCS to determine the slot that the HBA
		 * was processing when the error occurred.
		 */
		port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));
		failed_slot = (port_cmd_status & AHCI_CMD_STATUS_CCS) >>
		    AHCI_CMD_STATUS_CCS_SHIFT;

		if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp)) {
			spkt = ahci_portp->ahciport_err_retri_pkt;
			ASSERT(spkt != NULL);
		} else {
			spkt = ahci_portp->ahciport_slot_pkts[failed_slot];
			if (spkt == NULL) {
				/* May happen when interface errors occur? */
				goto next;
			}
		}

#if AHCI_DEBUG
		/*
		 * Debugging purpose...
		 */
		if (ahci_portp->ahciport_prd_bytecounts[failed_slot]) {
			cmd_header =
			    &ahci_portp->ahciport_cmd_list[failed_slot];
			AHCIDBG(AHCIDBG_INTR|AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_fatal_error_recovery_handler: port %d, "
			    "PRD Byte Count = 0x%x, "
			    "ahciport_prd_bytecounts = 0x%x", port,
			    cmd_header->ahcich_prd_byte_count,
			    ahci_portp->ahciport_prd_bytecounts[failed_slot]);
		}
#endif

		sata_cmd = &spkt->satapkt_cmd;

		/* Fill out the status and error registers for PxIS.TFES */
		if (intr_status & AHCI_INTR_STATUS_TFES) {
			ahci_rcvd_fisp = &(ahci_portp->ahciport_rcvd_fis->
			    ahcirf_d2h_register_fis);

			/* Copy the error context back to the sata_cmd */
			ahci_copy_err_cnxt(sata_cmd, ahci_rcvd_fisp);
		}

		/* The failed command must be one of the outstanding commands */
		failed_tags = 0x1 << failed_slot;
		ASSERT(failed_tags & slot_status);

		/* Update the sata registers, especially PxSERR register */
		ahci_update_sata_registers(ahci_ctlp, port,
		    &spkt->satapkt_device);

	} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		/* Read PxSACT to see which commands are still outstanding */
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));
	}
next:

#if AHCI_DEBUG
	/*
	 * When AHCI_PORT_FLAG_RQSENSE or AHCI_PORT_FLAG_RDLOGEXT flag is
	 * set, it means a fatal error happened after REQUEST SENSE command
	 * or READ LOG EXT command is delivered to the HBA during the error
	 * recovery process. At this time, the only outstanding command is
	 * supposed to be REQUEST SENSE command or READ LOG EXT command.
	 */
	if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp)) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_fatal_error_recovery_handler: port %d REQUEST SENSE "
		    "command or READ LOG EXT command for error data retrieval "
		    "failed", port);
		ASSERT(slot_status == 0x1);
		ASSERT(failed_slot == 0);
		ASSERT(spkt->satapkt_cmd.satacmd_acdb[0] ==
		    SCMD_REQUEST_SENSE ||
		    spkt->satapkt_cmd.satacmd_cmd_reg ==
		    SATAC_READ_LOG_EXT);
	}
#endif

	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_MOPPING;
	ahci_portp->ahciport_mop_in_progress++;

	rval = ahci_restart_port_wait_till_ready(ahci_ctlp, ahci_portp,
	    port, flag, &reset_flag);

	if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_ERRPRINT) {
		ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_ERRPRINT;
		if (rval == AHCI_SUCCESS)
			cmn_err(CE_WARN, "!ahci%d: error recovery for port %d "
			    "succeed", instance, port);
		else
			cmn_err(CE_WARN, "!ahci%d: error recovery for port %d "
			    "failed", instance, port);
	}

	/*
	 * Won't retrieve error information:
	 * 1. Port reset was involved to recover
	 * 2. Device is gone
	 * 3. IDENTIFY DEVICE command sent to ATAPI device
	 * 4. REQUEST SENSE or READ LOG EXT command during error recovery
	 */
	if (reset_flag ||
	    ahci_portp->ahciport_device_type == SATA_DTYPE_NONE ||
	    spkt && spkt->satapkt_cmd.satacmd_cmd_reg == SATAC_ID_DEVICE ||
	    ERR_RETRI_CMD_IN_PROGRESS(ahci_portp))
		goto out;

	/*
	 * Deliver READ LOG EXT to gather information about the error when
	 * a COMRESET has not been performed as part of the error recovery
	 * during NCQ command processing.
	 */
	if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		failed_tags = ahci_get_rdlogext_data(ahci_ctlp,
		    ahci_portp, port);
		goto out;
	}

	/*
	 * Deliver REQUEST SENSE for ATAPI command to gather information about
	 * the error when a COMRESET has not been performed as part of the
	 * error recovery.
	 */
	if (spkt && ahci_portp->ahciport_device_type == SATA_DTYPE_ATAPI)
		ahci_get_rqsense_data(ahci_ctlp, ahci_portp, port, spkt);
out:
	AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
	    "ahci_fatal_error_recovery_handler: port %d fatal error "
	    "occurred slot_status = 0x%x, pending_tags = 0x%x, "
	    "pending_ncq_tags = 0x%x failed_tags = 0x%x",
	    port, slot_status, ahci_portp->ahciport_pending_tags,
	    ahci_portp->ahciport_pending_ncq_tags, failed_tags);

	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    slot_status,
	    failed_tags, /* failed tags */
	    0, /* timeout tags */
	    0, /* aborted tags */
	    0); /* reset tags */
}

/*
 * Used to recovery a PMULT pmport fatal error under FIS-based switching.
 * 	1. device specific.PxFBS.SDE=1
 * 	2. Non-Deivce specific.
 * Nothing will be done when Command-based switching is employed.
 *
 * Currently code is neither completed nor tested.
 */
static void
ahci_pmult_error_recovery_handler(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port, uint32_t intr_status)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(intr_status))
#endif
	uint32_t	port_fbs_ctrl;
	int loop_count = 0;
	ahci_addr_t	addr;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	/* Nothing will be done under Command-based switching. */
	if (!(ahci_ctlp->ahcictl_cap & AHCI_CAP_PMULT_FBSS))
		return;

	port_fbs_ctrl = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxFBS(ahci_ctlp, port));

	if (!(port_fbs_ctrl & AHCI_FBS_EN))
		/* FBS is not enabled. */
		return;

	/* Problem's getting complicated now. */
	/*
	 * If FIS-based switching is used, we need to check
	 * the PxFBS to see the error type.
	 */
	port_fbs_ctrl = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxFBS(ahci_ctlp, port));

	/* Refer to spec(v1.2) 9.3.6.1 */
	if (port_fbs_ctrl & AHCI_FBS_SDE) {
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp,
		    "A Device Sepcific Error: port %d", port);
		/*
		 * Controller has paused commands for all other
		 * sub-devices until PxFBS.DEC is set.
		 */
		ahci_reject_all_abort_pkts(ahci_ctlp,
		    ahci_portp, 0);

		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxFBS(ahci_ctlp, port),
		    port_fbs_ctrl | AHCI_FBS_DEC);

		/*
		 * Wait controller clear PxFBS.DEC,
		 * then we can continue.
		 */
		loop_count = 0;
		do {
			port_fbs_ctrl = ddi_get32(ahci_ctlp->
			    ahcictl_ahci_acc_handle, (uint32_t *)
			    AHCI_PORT_PxFBS(ahci_ctlp, port));

			if (loop_count++ > 1000)
				/*
				 * Esclate the error. Follow
				 * non-device specific error
				 * procedure.
				 */
				return;

			drv_usecwait(AHCI_100US_USECS);
		} while (port_fbs_ctrl & AHCI_FBS_DEC);

		/*
		 * Issue a software reset to ensure drive is in
		 * a known state.
		 */
		(void) ahci_software_reset(ahci_ctlp,
		    ahci_portp, &addr);

	} else {

		/* Process Non-Device Specific Error. */
		/* This will be handled later on. */
		cmn_err(CE_NOTE, "!FBS is not supported now.");
	}
}
/*
 * Handle events - fatal error recovery
 */
static void
ahci_events_handler(void *args)
{
	ahci_event_arg_t *ahci_event_arg;
	ahci_ctl_t *ahci_ctlp;
	ahci_port_t *ahci_portp;
	ahci_addr_t *addrp;
	uint32_t event;
	int instance;

	ahci_event_arg = (ahci_event_arg_t *)args;

	ahci_ctlp = ahci_event_arg->ahciea_ctlp;
	ahci_portp = ahci_event_arg->ahciea_portp;
	addrp = ahci_event_arg->ahciea_addrp;
	event = ahci_event_arg->ahciea_event;
	instance = ddi_get_instance(ahci_ctlp->ahcictl_dip);

	AHCIDBG(AHCIDBG_ENTRY|AHCIDBG_INTR|AHCIDBG_ERRS, ahci_ctlp,
	    "ahci_events_handler enter: port %d intr_status = 0x%x",
	    ahci_portp->ahciport_port_num, event);

	mutex_enter(&ahci_portp->ahciport_mutex);

	/*
	 * ahci_intr_phyrdy_change() may have rendered it to
	 * SATA_DTYPE_NONE.
	 */
	if (ahci_portp->ahciport_device_type == SATA_DTYPE_NONE) {
		AHCIDBG(AHCIDBG_ENTRY|AHCIDBG_INTR, ahci_ctlp,
		    "ahci_events_handler: port %d no device attached, "
		    "and just return without doing anything",
		    ahci_portp->ahciport_port_num);

		if (ahci_portp->ahciport_flags & AHCI_PORT_FLAG_ERRPRINT) {
			ahci_portp->ahciport_flags &= ~AHCI_PORT_FLAG_ERRPRINT;
			cmn_err(CE_WARN, "!ahci%d: error recovery for port %d "
			    "succeed", instance, ahci_portp->ahciport_port_num);
		}

		goto out;
	}

	if (event & (AHCI_INTR_STATUS_IFS |
	    AHCI_INTR_STATUS_HBDS |
	    AHCI_INTR_STATUS_HBFS |
	    AHCI_INTR_STATUS_TFES))
		ahci_fatal_error_recovery_handler(ahci_ctlp, ahci_portp,
		    addrp, event);

out:
	mutex_exit(&ahci_portp->ahciport_mutex);
}

/*
 * ahci_watchdog_handler() and ahci_do_sync_start will call us if they
 * detect there are some commands which are timed out.
 */
static void
ahci_timeout_pkts(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    uint8_t port, uint32_t tmp_timeout_tags)
{
	uint32_t slot_status = 0;
	uint32_t finished_tags = 0;
	uint32_t timeout_tags = 0;

	AHCIDBG(AHCIDBG_TIMEOUT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_timeout_pkts enter: port %d", port);

	mutex_enter(&ahci_portp->ahciport_mutex);

	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp) ||
	    RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp) ||
	    ERR_RETRI_CMD_IN_PROGRESS(ahci_portp)) {
		/* Read PxCI to see which commands are still outstanding */
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));
	} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		/* Read PxSACT to see which commands are still outstanding */
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));
	}

#if AHCI_DEBUG
	/*
	 * When AHCI_PORT_FLAG_RQSENSE or AHCI_PORT_FLAG_RDLOGEXT flag is
	 * set, it means a fatal error happened after REQUEST SENSE command
	 * or READ LOG EXT command is delivered to the HBA during the error
	 * recovery process. At this time, the only outstanding command is
	 * supposed to be REQUEST SENSE command or READ LOG EXT command.
	 */
	if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp)) {
		AHCIDBG(AHCIDBG_ERRS|AHCIDBG_TIMEOUT, ahci_ctlp,
		    "ahci_timeout_pkts called while REQUEST SENSE "
		    "command or READ LOG EXT command for error recovery "
		    "timed out timeout_tags = 0x%x, slot_status = 0x%x, "
		    "pending_tags = 0x%x, pending_ncq_tags = 0x%x",
		    tmp_timeout_tags, slot_status,
		    ahci_portp->ahciport_pending_tags,
		    ahci_portp->ahciport_pending_ncq_tags);
		ASSERT(slot_status == 0x1);
	} else if (RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp)) {
		AHCIDBG(AHCIDBG_ERRS|AHCIDBG_TIMEOUT, ahci_ctlp,
		    "ahci_timeout_pkts called while executing R/W PMULT "
		    "command timeout_tags = 0x%x, slot_status = 0x%x",
		    tmp_timeout_tags, slot_status);
		ASSERT(slot_status == 0x1);
	}
#endif

	ahci_portp->ahciport_flags |= AHCI_PORT_FLAG_MOPPING;
	ahci_portp->ahciport_mop_in_progress++;

	(void) ahci_restart_port_wait_till_ready(ahci_ctlp, ahci_portp,
	    port, AHCI_PORT_RESET, NULL);

	/*
	 * Re-identify timeout tags because some previously checked commands
	 * could already complete.
	 */
	if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		finished_tags = ahci_portp->ahciport_pending_tags &
		    ~slot_status & AHCI_SLOT_MASK(ahci_ctlp);
		timeout_tags = tmp_timeout_tags & ~finished_tags;

		AHCIDBG(AHCIDBG_TIMEOUT, ahci_ctlp,
		    "ahci_timeout_pkts: port %d, finished_tags = 0x%x, "
		    "timeout_tags = 0x%x, port_cmd_issue = 0x%x, "
		    "pending_tags = 0x%x ",
		    port, finished_tags, timeout_tags,
		    slot_status, ahci_portp->ahciport_pending_tags);
	} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
		finished_tags = ahci_portp->ahciport_pending_ncq_tags &
		    ~slot_status & AHCI_NCQ_SLOT_MASK(ahci_portp);
		timeout_tags = tmp_timeout_tags & ~finished_tags;

		AHCIDBG(AHCIDBG_TIMEOUT|AHCIDBG_NCQ, ahci_ctlp,
		    "ahci_timeout_pkts: port %d, finished_tags = 0x%x, "
		    "timeout_tags = 0x%x, port_sactive = 0x%x, "
		    "pending_ncq_tags = 0x%x ",
		    port, finished_tags, timeout_tags,
		    slot_status, ahci_portp->ahciport_pending_ncq_tags);
	} else if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp) ||
	    RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp)) {
		timeout_tags = tmp_timeout_tags;
	}

	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    slot_status,
	    0,			/* failed tags */
	    timeout_tags,	/* timeout tags */
	    0,			/* aborted tags */
	    0);			/* reset tags */

	mutex_exit(&ahci_portp->ahciport_mutex);
}

/*
 * Watchdog handler kicks in every 5 seconds to timeout any commands pending
 * for long time.
 */
static void
ahci_watchdog_handler(ahci_ctl_t *ahci_ctlp)
{
	ahci_port_t *ahci_portp;
	sata_pkt_t *spkt;
	uint32_t pending_tags;
	uint32_t timeout_tags;
	uint32_t port_cmd_status;
	uint32_t port_sactive;
	uint8_t port;
	int tmp_slot;
	int current_slot;
	uint32_t current_tags;
	int instance = ddi_get_instance(ahci_ctlp->ahcictl_dip);

	mutex_enter(&ahci_ctlp->ahcictl_mutex);

	AHCIDBG(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_watchdog_handler entered", NULL);

	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			continue;
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];

		mutex_enter(&ahci_portp->ahciport_mutex);
		if (ahci_portp->ahciport_device_type == SATA_DTYPE_NONE) {
			mutex_exit(&ahci_portp->ahciport_mutex);
			continue;
		}

		/* Skip the check for those ports in error recovery */
		if ((ahci_portp->ahciport_flags & AHCI_PORT_FLAG_MOPPING) &&
		    !(ERR_RETRI_CMD_IN_PROGRESS(ahci_portp))) {
			mutex_exit(&ahci_portp->ahciport_mutex);
			continue;
		}

		pending_tags = 0;
		port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

		if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp) ||
		    RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp)) {
			current_slot = 0;
			pending_tags = 0x1;
		} else if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp)) {
			current_slot =
			    (port_cmd_status & AHCI_CMD_STATUS_CCS) >>
			    AHCI_CMD_STATUS_CCS_SHIFT;
			pending_tags = ahci_portp->ahciport_pending_tags;
		} else if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
			port_sactive = ddi_get32(
			    ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxSACT(ahci_ctlp, port));
			current_tags = port_sactive &
			    ~port_cmd_status &
			    AHCI_NCQ_SLOT_MASK(ahci_portp);
			pending_tags = ahci_portp->ahciport_pending_ncq_tags;
		}

		timeout_tags = 0;
		while (pending_tags) {
			tmp_slot = ddi_ffs(pending_tags) - 1;
			if (tmp_slot == -1) {
				break;
			}

			if (ERR_RETRI_CMD_IN_PROGRESS(ahci_portp))
				spkt = ahci_portp->ahciport_err_retri_pkt;
			else if (RDWR_PMULT_CMD_IN_PROGRESS(ahci_portp))
				spkt = ahci_portp->ahciport_rdwr_pmult_pkt;
			else
				spkt = ahci_portp->ahciport_slot_pkts[tmp_slot];

			if ((spkt != NULL) && spkt->satapkt_time &&
			    !(spkt->satapkt_op_mode & SATA_OPMODE_POLLING)) {
				/*
				 * If a packet has survived for more than it's
				 * max life cycles, it is a candidate for time
				 * out.
				 */
				ahci_portp->ahciport_slot_timeout[tmp_slot] -=
				    ahci_watchdog_timeout;

				if (ahci_portp->ahciport_slot_timeout[tmp_slot]
				    > 0)
					goto next;

#if AHCI_DEBUG
				if (NCQ_CMD_IN_PROGRESS(ahci_portp)) {
					AHCIDBG(AHCIDBG_ERRS|AHCIDBG_TIMEOUT,
					    ahci_ctlp, "watchdog: the current "
					    "tags is 0x%x", current_tags);
				} else {
					AHCIDBG(AHCIDBG_ERRS|AHCIDBG_TIMEOUT,
					    ahci_ctlp, "watchdog: the current "
					    "slot is %d", current_slot);
				}
#endif

				/*
				 * We need to check whether the HBA has
				 * begun to execute the command, if not,
				 * then re-set the timer of the command.
				 */
				if (NON_NCQ_CMD_IN_PROGRESS(ahci_portp) &&
				    (tmp_slot != current_slot) ||
				    NCQ_CMD_IN_PROGRESS(ahci_portp) &&
				    ((0x1 << tmp_slot) & current_tags)) {
					ahci_portp->ahciport_slot_timeout \
					    [tmp_slot] = spkt->satapkt_time;
				} else {
					timeout_tags |= (0x1 << tmp_slot);
					cmn_err(CE_WARN, "!ahci%d: watchdog "
					    "port %d satapkt 0x%p timed out\n",
					    instance, port, (void *)spkt);
				}
			}
next:
			CLEAR_BIT(pending_tags, tmp_slot);
		}

		if (timeout_tags) {
			mutex_exit(&ahci_portp->ahciport_mutex);
			mutex_exit(&ahci_ctlp->ahcictl_mutex);
			ahci_timeout_pkts(ahci_ctlp, ahci_portp,
			    port, timeout_tags);
			mutex_enter(&ahci_ctlp->ahcictl_mutex);
			mutex_enter(&ahci_portp->ahciport_mutex);
		}

		mutex_exit(&ahci_portp->ahciport_mutex);
	}

	/* Re-install the watchdog timeout handler */
	if (ahci_ctlp->ahcictl_timeout_id != 0) {
		ahci_ctlp->ahcictl_timeout_id =
		    timeout((void (*)(void *))ahci_watchdog_handler,
		    (caddr_t)ahci_ctlp, ahci_watchdog_tick);
	}

	mutex_exit(&ahci_ctlp->ahcictl_mutex);
}

/*
 * Fill the error context into sata_cmd for non-queued command error.
 */
static void
ahci_copy_err_cnxt(sata_cmd_t *scmd, ahci_fis_d2h_register_t *rfisp)
{
	scmd->satacmd_status_reg = GET_RFIS_STATUS(rfisp);
	scmd->satacmd_error_reg = GET_RFIS_ERROR(rfisp);
	scmd->satacmd_sec_count_lsb = GET_RFIS_SECTOR_COUNT(rfisp);
	scmd->satacmd_lba_low_lsb = GET_RFIS_CYL_LOW(rfisp);
	scmd->satacmd_lba_mid_lsb = GET_RFIS_CYL_MID(rfisp);
	scmd->satacmd_lba_high_lsb = GET_RFIS_CYL_HI(rfisp);
	scmd->satacmd_device_reg = GET_RFIS_DEV_HEAD(rfisp);

	if (scmd->satacmd_addr_type == ATA_ADDR_LBA48) {
		scmd->satacmd_sec_count_msb = GET_RFIS_SECTOR_COUNT_EXP(rfisp);
		scmd->satacmd_lba_low_msb = GET_RFIS_CYL_LOW_EXP(rfisp);
		scmd->satacmd_lba_mid_msb = GET_RFIS_CYL_MID_EXP(rfisp);
		scmd->satacmd_lba_high_msb = GET_RFIS_CYL_HI_EXP(rfisp);
	}
}

/*
 * Fill the ncq error page into sata_cmd for queued command error.
 */
static void
ahci_copy_ncq_err_page(sata_cmd_t *scmd,
    struct sata_ncq_error_recovery_page *ncq_err_page)
{
	scmd->satacmd_sec_count_msb = ncq_err_page->ncq_sector_count_ext;
	scmd->satacmd_sec_count_lsb = ncq_err_page->ncq_sector_count;
	scmd->satacmd_lba_low_msb = ncq_err_page->ncq_sector_number_ext;
	scmd->satacmd_lba_low_lsb = ncq_err_page->ncq_sector_number;
	scmd->satacmd_lba_mid_msb = ncq_err_page->ncq_cyl_low_ext;
	scmd->satacmd_lba_mid_lsb = ncq_err_page->ncq_cyl_low;
	scmd->satacmd_lba_high_msb = ncq_err_page->ncq_cyl_high_ext;
	scmd->satacmd_lba_high_lsb = ncq_err_page->ncq_cyl_high;
	scmd->satacmd_device_reg = ncq_err_page->ncq_dev_head;
	scmd->satacmd_status_reg = ncq_err_page->ncq_status;
	scmd->satacmd_error_reg = ncq_err_page->ncq_error;
}

/*
 * Put the respective register value to sata_cmd_t for satacmd_flags.
 */
static void
ahci_copy_out_regs(sata_cmd_t *scmd, ahci_fis_d2h_register_t *rfisp)
{
	if (scmd->satacmd_flags.sata_copy_out_sec_count_msb)
		scmd->satacmd_sec_count_msb = GET_RFIS_SECTOR_COUNT_EXP(rfisp);
	if (scmd->satacmd_flags.sata_copy_out_lba_low_msb)
		scmd->satacmd_lba_low_msb = GET_RFIS_CYL_LOW_EXP(rfisp);
	if (scmd->satacmd_flags.sata_copy_out_lba_mid_msb)
		scmd->satacmd_lba_mid_msb = GET_RFIS_CYL_MID_EXP(rfisp);
	if (scmd->satacmd_flags.sata_copy_out_lba_high_msb)
		scmd->satacmd_lba_high_msb = GET_RFIS_CYL_HI_EXP(rfisp);
	if (scmd->satacmd_flags.sata_copy_out_sec_count_lsb)
		scmd->satacmd_sec_count_lsb = GET_RFIS_SECTOR_COUNT(rfisp);
	if (scmd->satacmd_flags.sata_copy_out_lba_low_lsb)
		scmd->satacmd_lba_low_lsb = GET_RFIS_CYL_LOW(rfisp);
	if (scmd->satacmd_flags.sata_copy_out_lba_mid_lsb)
		scmd->satacmd_lba_mid_lsb = GET_RFIS_CYL_MID(rfisp);
	if (scmd->satacmd_flags.sata_copy_out_lba_high_lsb)
		scmd->satacmd_lba_high_lsb = GET_RFIS_CYL_HI(rfisp);
	if (scmd->satacmd_flags.sata_copy_out_device_reg)
		scmd->satacmd_device_reg = GET_RFIS_DEV_HEAD(rfisp);
	if (scmd->satacmd_flags.sata_copy_out_error_reg)
		scmd->satacmd_error_reg = GET_RFIS_ERROR(rfisp);
}

static void
ahci_log_fatal_error_message(ahci_ctl_t *ahci_ctlp, uint8_t port,
    uint32_t intr_status)
{
	int instance = ddi_get_instance(ahci_ctlp->ahcictl_dip);

	if (intr_status & AHCI_INTR_STATUS_IFS)
		cmn_err(CE_WARN, "!ahci%d: ahci port %d has interface fatal "
		    "error", instance, port);

	if (intr_status & AHCI_INTR_STATUS_HBDS)
		cmn_err(CE_WARN, "!ahci%d: ahci port %d has bus data error",
		    instance, port);

	if (intr_status & AHCI_INTR_STATUS_HBFS)
		cmn_err(CE_WARN, "!ahci%d: ahci port %d has bus fatal error",
		    instance, port);

	if (intr_status & AHCI_INTR_STATUS_TFES)
		cmn_err(CE_WARN, "!ahci%d: ahci port %d has task file error",
		    instance, port);

	cmn_err(CE_WARN, "!ahci%d: ahci port %d is trying to do error "
	    "recovery", instance, port);
}

static void
ahci_dump_commands(ahci_ctl_t *ahci_ctlp, uint8_t port,
    uint32_t slot_tags)
{
	ahci_port_t *ahci_portp;
	int tmp_slot;
	sata_pkt_t *spkt;
	sata_cmd_t cmd;

	ahci_portp = ahci_ctlp->ahcictl_ports[port];
	ASSERT(ahci_portp != NULL);

	while (slot_tags) {
		tmp_slot = ddi_ffs(slot_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		spkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(spkt != NULL);
		cmd = spkt->satapkt_cmd;

		cmn_err(CE_WARN, "!satapkt 0x%p: cmd_reg = 0x%x "
		    "features_reg = 0x%x sec_count_msb = 0x%x "
		    "lba_low_msb = 0x%x lba_mid_msb = 0x%x "
		    "lba_high_msb = 0x%x sec_count_lsb = 0x%x "
		    "lba_low_lsb = 0x%x lba_mid_lsb = 0x%x "
		    "lba_high_lsb = 0x%x device_reg = 0x%x "
		    "addr_type = 0x%x cmd_flags = 0x%x", (void *)spkt,
		    cmd.satacmd_cmd_reg, cmd.satacmd_features_reg,
		    cmd.satacmd_sec_count_msb, cmd.satacmd_lba_low_msb,
		    cmd.satacmd_lba_mid_msb, cmd.satacmd_lba_high_msb,
		    cmd.satacmd_sec_count_lsb, cmd.satacmd_lba_low_lsb,
		    cmd.satacmd_lba_mid_lsb, cmd.satacmd_lba_high_lsb,
		    cmd.satacmd_device_reg, cmd.satacmd_addr_type,
		    *((uint32_t *)&(cmd.satacmd_flags)));

		CLEAR_BIT(slot_tags, tmp_slot);
	}
}

/*
 * Dump the serror message to the log.
 */
static void
ahci_log_serror_message(ahci_ctl_t *ahci_ctlp, uint8_t port,
    uint32_t port_serror, int debug_only)
{
	static char err_buf[512];
	static char err_msg_header[16];
	char *err_msg = err_buf;

	*err_buf = '\0';
	*err_msg_header = '\0';

	if (port_serror & SERROR_DATA_ERR_FIXED) {
		err_msg = strcat(err_msg,
		    "\tRecovered Data Integrity Error (I)\n");
	}

	if (port_serror & SERROR_COMM_ERR_FIXED) {
		err_msg = strcat(err_msg,
		    "\tRecovered Communication Error (M)\n");
	}

	if (port_serror & SERROR_DATA_ERR) {
		err_msg = strcat(err_msg,
		    "\tTransient Data Integrity Error (T)\n");
	}

	if (port_serror & SERROR_PERSISTENT_ERR) {
		err_msg = strcat(err_msg,
		    "\tPersistent Communication or Data Integrity Error (C)\n");
	}

	if (port_serror & SERROR_PROTOCOL_ERR) {
		err_msg = strcat(err_msg, "\tProtocol Error (P)\n");
	}

	if (port_serror & SERROR_INT_ERR) {
		err_msg = strcat(err_msg, "\tInternal Error (E)\n");
	}

	if (port_serror & SERROR_PHY_RDY_CHG) {
		err_msg = strcat(err_msg, "\tPhyRdy Change (N)\n");
	}

	if (port_serror & SERROR_PHY_INT_ERR) {
		err_msg = strcat(err_msg, "\tPhy Internal Error (I)\n");
	}

	if (port_serror & SERROR_COMM_WAKE) {
		err_msg = strcat(err_msg, "\tComm Wake (W)\n");
	}

	if (port_serror & SERROR_10B_TO_8B_ERR) {
		err_msg = strcat(err_msg, "\t10B to 8B Decode Error (B)\n");
	}

	if (port_serror & SERROR_DISPARITY_ERR) {
		err_msg = strcat(err_msg, "\tDisparity Error (D)\n");
	}

	if (port_serror & SERROR_CRC_ERR) {
		err_msg = strcat(err_msg, "\tCRC Error (C)\n");
	}

	if (port_serror & SERROR_HANDSHAKE_ERR) {
		err_msg = strcat(err_msg, "\tHandshake Error (H)\n");
	}

	if (port_serror & SERROR_LINK_SEQ_ERR) {
		err_msg = strcat(err_msg, "\tLink Sequence Error (S)\n");
	}

	if (port_serror & SERROR_TRANS_ERR) {
		err_msg = strcat(err_msg,
		    "\tTransport state transition error (T)\n");
	}

	if (port_serror & SERROR_FIS_TYPE) {
		err_msg = strcat(err_msg, "\tUnknown FIS Type (F)\n");
	}

	if (port_serror & SERROR_EXCHANGED_ERR) {
		err_msg = strcat(err_msg, "\tExchanged (X)\n");
	}

	if (*err_msg == '\0')
		return;

	if (debug_only) {
		(void) sprintf(err_msg_header, "port %d", port);
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, err_msg_header, NULL);
		AHCIDBG(AHCIDBG_ERRS, ahci_ctlp, err_msg, NULL);
	} else if (ahci_ctlp) {
		cmn_err(CE_WARN, "!ahci%d: %s %s",
		    ddi_get_instance(ahci_ctlp->ahcictl_dip),
		    err_msg_header, err_msg);

		/* sata trace debug */
		sata_trace_debug(ahci_ctlp->ahcictl_dip,
		    "ahci%d: %s %s", ddi_get_instance(ahci_ctlp->ahcictl_dip),
		    err_msg_header, err_msg);
	} else {
		cmn_err(CE_WARN, "!ahci: %s %s", err_msg_header, err_msg);

		/* sata trace debug */
		sata_trace_debug(NULL, "ahci: %s %s", err_msg_header, err_msg);
	}
}

/*
 * Translate the sata_address_t type into the ahci_addr_t type.
 * sata_device.satadev_addr structure is used as source.
 */
static void
ahci_get_ahci_addr(ahci_ctl_t *ahci_ctlp, sata_device_t *sd,
    ahci_addr_t *ahci_addrp)
{
	sata_address_t *sata_addrp = &sd->satadev_addr;
	ahci_addrp->aa_port =
	    ahci_ctlp->ahcictl_cport_to_port[sata_addrp->cport];
	ahci_addrp->aa_pmport = sata_addrp->pmport;

	switch (sata_addrp->qual) {
	case SATA_ADDR_DCPORT:
	case SATA_ADDR_CPORT:
		ahci_addrp->aa_qual = AHCI_ADDR_PORT;
		break;
	case SATA_ADDR_PMULT:
	case SATA_ADDR_PMULT_SPEC:
		ahci_addrp->aa_qual = AHCI_ADDR_PMULT;
		break;
	case SATA_ADDR_DPMPORT:
	case SATA_ADDR_PMPORT:
		ahci_addrp->aa_qual = AHCI_ADDR_PMPORT;
		break;
	case SATA_ADDR_NULL:
	default:
		/* something went wrong */
		ahci_addrp->aa_qual = AHCI_ADDR_NULL;
		break;
	}
}

/*
 * This routine is to calculate the total number of ports implemented
 * by the HBA.
 */
static int
ahci_get_num_implemented_ports(uint32_t ports_implemented)
{
	uint8_t i;
	int num = 0;

	for (i = 0; i < AHCI_MAX_PORTS; i++) {
		if (((uint32_t)0x1 << i) & ports_implemented)
			num++;
	}

	return (num);
}

#if AHCI_DEBUG
static void
ahci_log(ahci_ctl_t *ahci_ctlp, uint_t level, char *fmt, ...)
{
	static char name[16];
	va_list ap;

	mutex_enter(&ahci_log_mutex);

	va_start(ap, fmt);
	if (ahci_ctlp) {
		(void) sprintf(name, "ahci%d: ",
		    ddi_get_instance(ahci_ctlp->ahcictl_dip));
	} else {
		(void) sprintf(name, "ahci: ");
	}

	(void) vsprintf(ahci_log_buf, fmt, ap);
	va_end(ap);

	cmn_err(level, "%s%s", name, ahci_log_buf);

	mutex_exit(&ahci_log_mutex);
}
#endif

/*
 * quiesce(9E) entry point.
 *
 * This function is called when the system is single-threaded at high
 * PIL with preemption disabled. Therefore, this function must not be
 * blocked.
 *
 * This function returns DDI_SUCCESS on success, or DDI_FAILURE on failure.
 * DDI_FAILURE indicates an error condition and should almost never happen.
 */
static int
ahci_quiesce(dev_info_t *dip)
{
	ahci_ctl_t *ahci_ctlp;
	ahci_port_t *ahci_portp;
	int instance, port;

	instance = ddi_get_instance(dip);
	ahci_ctlp = ddi_get_soft_state(ahci_statep, instance);

	if (ahci_ctlp == NULL)
		return (DDI_FAILURE);

#if AHCI_DEBUG
	ahci_debug_flags = 0;
#endif

	ahci_ctlp->ahcictl_flags |= AHCI_QUIESCE;

	/* disable all the interrupts. */
	ahci_disable_all_intrs(ahci_ctlp);

	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			continue;
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];

		/*
		 * Stop the port by clearing PxCMD.ST
		 *
		 * Here we must disable the port interrupt because
		 * ahci_disable_all_intrs only clear GHC.IE, and IS
		 * register will be still set if PxIE is enabled.
		 * When ahci shares one IRQ with other drivers, the
		 * intr handler may claim the intr mistakenly.
		 */
		ahci_disable_port_intrs(ahci_ctlp, port);
		(void) ahci_put_port_into_notrunning_state(ahci_ctlp,
		    ahci_portp, port);
	}

	ahci_ctlp->ahcictl_flags &= ~AHCI_QUIESCE;

	return (DDI_SUCCESS);
}

/*
 * The function will add a sata packet to the done queue.
 */
static void
ahci_add_doneq(ahci_port_t *ahci_portp, sata_pkt_t *satapkt, int reason)
{
	ASSERT(satapkt != NULL);
	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	/* set the reason for all packets */
	satapkt->satapkt_reason = reason;
	satapkt->satapkt_hba_driver_private = NULL;

	if (! (satapkt->satapkt_op_mode & SATA_OPMODE_SYNCH) &&
	    satapkt->satapkt_comp) {
		/*
		 * only add to queue when mode is not synch and there is
		 * completion callback
		 */
		*ahci_portp->ahciport_doneqtail = satapkt;
		ahci_portp->ahciport_doneqtail =
		    (sata_pkt_t **)&(satapkt->satapkt_hba_driver_private);
		ahci_portp->ahciport_doneq_len++;

	} else if ((satapkt->satapkt_op_mode & SATA_OPMODE_SYNCH) &&
	    ! (satapkt->satapkt_op_mode & SATA_OPMODE_POLLING))
		/*
		 * for sync/non-poll mode, just call cv_broadcast
		 */
		cv_broadcast(&ahci_portp->ahciport_cv);
}

/*
 * The function will call completion callback of sata packet on the
 * completed queue
 */
static void
ahci_flush_doneq(ahci_port_t *ahci_portp)
{
	sata_pkt_t *satapkt, *next;

	ASSERT(MUTEX_HELD(&ahci_portp->ahciport_mutex));

	if (ahci_portp->ahciport_doneq) {
		satapkt = ahci_portp->ahciport_doneq;

		ahci_portp->ahciport_doneq = NULL;
		ahci_portp->ahciport_doneqtail = &ahci_portp->ahciport_doneq;
		ahci_portp->ahciport_doneq_len = 0;

		mutex_exit(&ahci_portp->ahciport_mutex);

		while (satapkt != NULL) {
			next = satapkt->satapkt_hba_driver_private;
			satapkt->satapkt_hba_driver_private = NULL;

			/* Call the callback */
			(*satapkt->satapkt_comp)(satapkt);

			satapkt = next;
		}

		mutex_enter(&ahci_portp->ahciport_mutex);
	}
}
