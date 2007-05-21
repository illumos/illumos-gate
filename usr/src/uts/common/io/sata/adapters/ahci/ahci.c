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

/*
 * AHCI (Advanced Host Controller Interface) SATA HBA Driver
 */

#include <sys/scsi/scsi.h>
#include <sys/pci.h>
#include <sys/sata/sata_hba.h>
#include <sys/sata/adapters/ahci/ahcireg.h>
#include <sys/sata/adapters/ahci/ahcivar.h>

/*
 * Function prototypes for driver entry points
 */
static	int ahci_attach(dev_info_t *, ddi_attach_cmd_t);
static	int ahci_detach(dev_info_t *, ddi_detach_cmd_t);
static	int ahci_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

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
 * Local function prototypes
 */
static	int ahci_initialize_controller(ahci_ctl_t *);
static	void ahci_deallocate_controller(ahci_ctl_t *);


static	int ahci_alloc_port_state(ahci_ctl_t *, uint8_t);
static	void ahci_dealloc_port_state(ahci_ctl_t *, uint8_t);
static	int ahci_alloc_rcvd_fis(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	void ahci_dealloc_rcvd_fis(ahci_ctl_t *, ahci_port_t *);
static	int ahci_alloc_cmd_list(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	void ahci_dealloc_cmd_list(ahci_ctl_t *, ahci_port_t *);
static  int ahci_alloc_cmd_tables(ahci_ctl_t *, ahci_port_t *);
static  void ahci_dealloc_cmd_tables(ahci_ctl_t *, ahci_port_t *);

static	int ahci_initialize_port(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_start_port(ahci_ctl_t *, uint8_t);
static	int ahci_find_dev_signature(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	void ahci_update_sata_registers(ahci_ctl_t *, uint8_t, sata_device_t *);
static	int ahci_deliver_satapkt(ahci_ctl_t *, ahci_port_t *,
    uint8_t, sata_pkt_t *);
static	void ahci_poll_cmd(ahci_ctl_t *, ahci_port_t *, uint8_t,
    int, sata_pkt_t *);
static	int ahci_claim_free_slot(ahci_ctl_t *, ahci_port_t *);
static	void ahci_copy_out_regs(sata_cmd_t *, ahci_fis_d2h_register_t *);
static	void ahci_set_sense_data(sata_pkt_t *, int);

static	int ahci_software_reset(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_hba_reset(ahci_ctl_t *);
static	int ahci_port_reset(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	void ahci_reject_all_abort_pkts(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_reset_device_reject_pkts(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_reset_port_reject_pkts(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_reset_hba_reject_pkts(ahci_ctl_t *);
static	int ahci_port_into_notrunning_state(ahci_ctl_t *, ahci_port_t *,
    uint8_t);
static	int ahci_restart_port_wait_till_ready(ahci_ctl_t *, ahci_port_t *,
    uint8_t, int);
static	void ahci_mop_commands(ahci_ctl_t *, ahci_port_t *, uint8_t,
    uint32_t, uint32_t, uint32_t, uint32_t, uint32_t);
static	int ahci_recovery_fatal_error(ahci_ctl_t *,
    ahci_port_t *, uint8_t, uint32_t);
static	void ahci_timeout_pkts(ahci_ctl_t *, ahci_port_t *, uint8_t, uint32_t);
static	void ahci_watchdog_handler(ahci_ctl_t *);

static	uint_t ahci_intr(caddr_t, caddr_t);
static	int ahci_add_legacy_intrs(ahci_ctl_t *);
static	int ahci_add_msi_intrs(ahci_ctl_t *);
static	void ahci_rem_intrs(ahci_ctl_t *);
static	void ahci_enable_all_intrs(ahci_ctl_t *);
static	void ahci_disable_all_intrs(ahci_ctl_t *);
static	void ahci_enable_port_intrs(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	void ahci_disable_port_intrs(ahci_ctl_t *, ahci_port_t *, uint8_t);

static	int ahci_intr_d2h_register_fis(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_pio_setup_fis(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_dma_setup_fis(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_set_device_bits_fis(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_unknown_fis(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_descriptor_processed(ahci_ctl_t *, ahci_port_t *,
    uint8_t);
static	int ahci_intr_port_connect_change(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_device_mechanical_presence_status(ahci_ctl_t *,
    ahci_port_t *, uint8_t);
static	int ahci_intr_phyrdy_change(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_incorrect_port_multiplier(ahci_ctl_t *,
    ahci_port_t *, uint8_t);
static	int ahci_intr_overflow(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_interface_non_fatal_error(ahci_ctl_t *,
    ahci_port_t *, uint8_t);
static	int ahci_intr_interface_fatal_error(ahci_ctl_t *, ahci_port_t *,
    uint8_t);
static	int ahci_intr_host_bus_data_error(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_host_bus_fatal_error(ahci_ctl_t *, ahci_port_t *,
    uint8_t);
static	int ahci_intr_task_file_error(ahci_ctl_t *, ahci_port_t *, uint8_t);
static	int ahci_intr_cold_port_detect(ahci_ctl_t *, ahci_port_t *, uint8_t);

static	int ahci_get_num_implemented_ports(uint32_t);
static	void ahci_log_error_message(ahci_ctl_t *, uint8_t, uint32_t);
static	void ahci_log(ahci_ctl_t *, uint_t, char *, ...);


/*
 * DMA attributes for the data buffer
 *
 * dma_attr_addr_hi will be changed to 0xffffffffull if the HBA
 * does not support 64-bit addressing
 */
static ddi_dma_attr_t buffer_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo: lowest bus address */
	0xffffffffffffffffull,	/* dma_attr_addr_hi: highest bus address */
	0x3fffffull,		/* dma_attr_count_max i.e. for one cookie */
	2,			/* dma_attr_align: word aligned */
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
	0,			/* dma_attr_addr_lo: lowest bus address */
	0xffffffffffffffffull,	/* dma_attr_addr_hi: highest bus address */
	0xffffffffull,		/* dma_attr_count_max i.e. for one cookie */
	0x100,			/* dma_attr_align: 256-byte aligned */
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
	0,			/* dma_attr_addr_lo: lowest bus address */
	0xffffffffffffffffull,	/* dma_attr_addr_hi: highest bus address */
	0xffffffffull,		/* dma_attr_count_max i.e. for one cookie */
	0x400,			/* dma_attr_align: 1K-byte aligned */
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
	0,			/* dma_attr_addr_lo: lowest bus address */
	0xffffffffffffffffull,	/* dma_attr_addr_hi: highest bus address */
	0xffffffffull,		/* dma_attr_count_max i.e. for one cookie */
	0x80,			/* dma_attr_align: 128-byte aligned */
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
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
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
	NULL			/* power */
};

static sata_tran_hotplug_ops_t ahci_tran_hotplug_ops = {
	SATA_TRAN_HOTPLUG_OPS_REV_1,
	ahci_tran_hotplug_port_activate,
	ahci_tran_hotplug_port_deactivate
};

extern struct mod_ops mod_driverops;

static  struct modldrv modldrv = {
	&mod_driverops,		/* driverops */
	"ahci driver %I%",
	&ahcictl_dev_ops,	/* driver ops */
};

static  struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

static int ahci_watchdog_timeout = 5; /* 5 seconds */
static int ahci_watchdog_tick;

/* The following is needed for ahci_log() */
static kmutex_t ahci_log_mutex;
static char ahci_log_buf[512];

static size_t ahci_cmd_table_size;

/* The number of Physical Region Descriptor Table(PRDT) in Command Table */
int ahci_dma_prdt_number = AHCI_PRDT_NUMBER;

/*
 * AHCI MSI tunable:
 *
 * MSI will be enabled in phase 2.
 */
boolean_t ahci_msi_enabled = B_FALSE;

#if AHCI_DEBUG
uint32_t ahci_debug_flags = 0;
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

	mutex_init(&ahci_log_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((ret = sata_hba_init(&modlinkage)) != 0) {
		mutex_destroy(&ahci_log_mutex);
		ddi_soft_state_fini(&ahci_statep);
		goto err_out;
	}

	ret = mod_install(&modlinkage);
	if (ret != 0) {
		sata_hba_fini(&modlinkage);
		mutex_destroy(&ahci_log_mutex);
		ddi_soft_state_fini(&ahci_statep);
		goto err_out;
	}

	/* watchdog tick */
	ahci_watchdog_tick = drv_usectohz(
	    (clock_t)ahci_watchdog_timeout * 1000000);
	return (ret);

err_out:
	cmn_err(CE_WARN, "!Module init failed");
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
	mutex_destroy(&ahci_log_mutex);
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
	ahci_ctl_t *ahci_ctlp;
	int instance = ddi_get_instance(dip);
	int status;
	int attach_state;
	uint32_t cap_status, ahci_version;
	int intr_types;
	ushort_t venid;
	uint8_t revision;

	AHCIDBG0(AHCIDBG_INIT|AHCIDBG_ENTRY, NULL, "ahci_attach enter");

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		/* It will be implemented in Phase 2 */
		return (DDI_FAILURE);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	attach_state = AHCI_ATTACH_STATE_NONE;

	/* Allocate soft state */
	status = ddi_soft_state_zalloc(ahci_statep, instance);
	if (status != DDI_SUCCESS) {
		goto err_out;
	}

	ahci_ctlp = ddi_get_soft_state(ahci_statep, instance);
	ahci_ctlp->ahcictl_dip = dip;

	attach_state |= AHCI_ATTACH_STATE_STATEP_ALLOC;

	/*
	 * Now map the AHCI base address; which includes global
	 * registers and port control registers
	 */
	status = ddi_regs_map_setup(dip,
	    AHCI_BASE_REG,
	    (caddr_t *)&ahci_ctlp->ahcictl_ahci_addr,
	    0,
	    0,
	    &accattr,
	    &ahci_ctlp->ahcictl_ahci_acc_handle);
	if (status != DDI_SUCCESS) {
		goto err_out;
	}

	attach_state |= AHCI_ATTACH_STATE_REG_MAP;

	/* Get the AHCI version information */
	ahci_version = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_VS(ahci_ctlp));

	AHCIDBG2(AHCIDBG_INIT, ahci_ctlp, "hba AHCI version = %x.%x",
	    (ahci_version & 0xffff0000) >> 16,
	    ((ahci_version & 0x0000ff00) >> 4 |
	    (ahci_version & 0x000000ff)));

	/* We don't support controllers whose versions are lower than 1.0 */
	if (!(ahci_version & 0xffff0000)) {
		AHCIDBG0(AHCIDBG_ERRS, ahci_ctlp, "No support for lower than "
		    "AHCI version 1.0");
		goto err_out;
	}

	/* Get the HBA capabilities information */
	cap_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_CAP(ahci_ctlp));

	AHCIDBG1(AHCIDBG_INIT, ahci_ctlp, "hba capabilites = 0x%x",
	    cap_status);

	/* Get the number of command slots supported by the HBA */
	ahci_ctlp->ahcictl_num_cmd_slots =
	    ((cap_status & AHCI_HBA_CAP_NCS) >>
	    AHCI_HBA_CAP_NCS_SHIFT) + 1;

	AHCIDBG1(AHCIDBG_INIT, ahci_ctlp, "hba number of cmd slots: 0x%x",
	    ahci_ctlp->ahcictl_num_cmd_slots);

	/* Get the bit map which indicates ports implemented by the HBA */
	ahci_ctlp->ahcictl_ports_implemented =
	    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_PI(ahci_ctlp));

	AHCIDBG1(AHCIDBG_INIT, ahci_ctlp, "hba implementation of ports: 0x%x",
	    ahci_ctlp->ahcictl_ports_implemented);

	/*
	 * According to the AHCI spec, CAP.NP should indicate the maximum
	 * number of ports supported by the HBA silicon, but we found
	 * this value of ICH8 chipset only indicates the number of ports
	 * implemented (exposed) by it. Therefore, the driver should calculate
	 * the potential maximum value by checking PI register, and use
	 * the maximum of this value and CAP.NP.
	 */
	ahci_ctlp->ahcictl_num_ports = max(
	    (cap_status & AHCI_HBA_CAP_NP) + 1,
	    ddi_fls(ahci_ctlp->ahcictl_ports_implemented));

	AHCIDBG1(AHCIDBG_INIT, ahci_ctlp, "hba number of ports: %d",
	    ahci_ctlp->ahcictl_num_ports);

	/* Get the number of implemented ports by the HBA */
	ahci_ctlp->ahcictl_num_implemented_ports =
	    ahci_get_num_implemented_ports(
	    ahci_ctlp->ahcictl_ports_implemented);

	AHCIDBG1(AHCIDBG_INIT, ahci_ctlp,
	    "hba number of implemented ports: 0x%x",
	    ahci_ctlp->ahcictl_num_implemented_ports);

	ahci_ctlp->ahcictl_buffer_dma_attr = buffer_dma_attr;

	if (!(cap_status & AHCI_HBA_CAP_S64A)) {
		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
		    "hba does not support 64-bit addressing");
		ahci_ctlp->ahcictl_buffer_dma_attr.dma_attr_addr_hi =
		    0xffffffffull;
	}

	/*
	 * Modify dma_attr_align of ahcictl_buffer_dma_attr. For VT8251, those
	 * controllers with 0x00 revision id work on 4-byte aligned buffer,
	 * which is a bug and was fixed after 0x00 revision id controllers.
	 */
	if (pci_config_setup(dip, &ahci_ctlp->ahcictl_pci_conf_handle)
	    != DDI_SUCCESS) {
		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp, "pci_config_setup failed");
		goto err_out;
	}

	venid = pci_config_get16(ahci_ctlp->ahcictl_pci_conf_handle,
	    PCI_CONF_VENID);

	if (venid == VIA_VENID) {
		revision = pci_config_get8(ahci_ctlp->ahcictl_pci_conf_handle,
		    PCI_CONF_REVID);
		AHCIDBG1(AHCIDBG_INIT, ahci_ctlp,
		    "revision id = 0x%x", revision);
		if (revision == 0x00) {
			ahci_ctlp->ahcictl_buffer_dma_attr.dma_attr_align = 0x4;
			AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
			    "change ddi_attr_align to 0x4");
		}
	}

	pci_config_teardown(&ahci_ctlp->ahcictl_pci_conf_handle);

	/*
	 * Disable the whole controller interrupts before adding
	 * interrupt handlers(s).
	 */
	ahci_disable_all_intrs(ahci_ctlp);

	/* Get supported interrupt types */
	if (ddi_intr_get_supported_types(dip, &intr_types) != DDI_SUCCESS) {
		AHCIDBG0(AHCIDBG_INIT|AHCIDBG_INTR, ahci_ctlp,
		    "ddi_intr_get_supported_types failed");
		goto err_out;
	}

	AHCIDBG1(AHCIDBG_INIT|AHCIDBG_INTR, ahci_ctlp,
	    "ddi_intr_get_supported_types() returned: 0x%x",
	    intr_types);

	if (ahci_msi_enabled && (intr_types & DDI_INTR_TYPE_MSI)) {
		/*
		 * Try MSI first, but fall back to FIXED if failed
		 */
		if (ahci_add_msi_intrs(ahci_ctlp) == DDI_SUCCESS) {
			ahci_ctlp->ahcictl_intr_type = DDI_INTR_TYPE_MSI;
			AHCIDBG0(AHCIDBG_INIT|AHCIDBG_INTR, ahci_ctlp,
			    "Using MSI interrupt type");
			goto intr_done;
		}

		AHCIDBG0(AHCIDBG_INIT|AHCIDBG_INTR, ahci_ctlp,
		    "MSI registration failed, "
		    "trying FIXED interrupts");
	}

	if (intr_types & DDI_INTR_TYPE_FIXED) {
		if (ahci_add_legacy_intrs(ahci_ctlp) == DDI_SUCCESS) {
			ahci_ctlp->ahcictl_intr_type = DDI_INTR_TYPE_FIXED;
			AHCIDBG0(AHCIDBG_INIT|AHCIDBG_INTR, NULL,
			    "Using FIXED interrupt type");
			goto intr_done;
		}

		AHCIDBG0(AHCIDBG_INIT|AHCIDBG_INTR, ahci_ctlp,
		    "FIXED interrupt registration failed");
	}

	cmn_err(CE_WARN, "!Interrupt registration failed");

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

	AHCIDBG2(AHCIDBG_INIT, ahci_ctlp,
	    "ahci_attach: ahci_dma_prdt_number set by user is 0x%x,"
	    " ahci_cmd_table_size is 0x%x",
	    ahci_dma_prdt_number, ahci_cmd_table_size);

	if (ahci_dma_prdt_number != AHCI_PRDT_NUMBER)
		ahci_ctlp->ahcictl_buffer_dma_attr.dma_attr_sgllen =
		    ahci_dma_prdt_number;

	/*
	 * Initialize the controller and driver core.
	 */
	ahci_ctlp->ahcictl_flags |= AHCI_ATTACH;
	status = ahci_initialize_controller(ahci_ctlp);
	ahci_ctlp->ahcictl_flags &= ~AHCI_ATTACH;
	if (status != AHCI_SUCCESS) {
		goto err_out;
	}

	attach_state |= AHCI_ATTACH_STATE_HW_INIT;

	/* Start one thread to check packet timeouts */
	ahci_ctlp->ahcictl_timeout_id = timeout(
	    (void (*)(void *))ahci_watchdog_handler,
	    (caddr_t)ahci_ctlp, ahci_watchdog_tick);

	attach_state |= AHCI_ATTACH_STATE_TIMEOUT_ENABLED;

	if (ahci_register_sata_hba_tran(ahci_ctlp, cap_status)) {
		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
		    "ahci: setting sata hba tran failed");
		goto err_out;
	}

	AHCIDBG0(AHCIDBG_INIT, ahci_ctlp, "ahci_attach success!");

	return (DDI_SUCCESS);

err_out:
	if (attach_state & AHCI_ATTACH_STATE_TIMEOUT_ENABLED) {
		mutex_enter(&ahci_ctlp->ahcictl_mutex);
		(void) untimeout(ahci_ctlp->ahcictl_timeout_id);
		ahci_ctlp->ahcictl_timeout_id = 0;
		mutex_exit(&ahci_ctlp->ahcictl_mutex);
	}

	if (attach_state & AHCI_ATTACH_STATE_HW_INIT) {
		mutex_enter(&ahci_ctlp->ahcictl_mutex);
		ahci_ctlp->ahcictl_flags |= AHCI_DETACH;
		ahci_deallocate_controller(ahci_ctlp);
		ahci_ctlp->ahcictl_flags &= ~AHCI_DETACH;
		mutex_exit(&ahci_ctlp->ahcictl_mutex);
	}

	if (attach_state & AHCI_ATTACH_STATE_MUTEX_INIT) {
		mutex_destroy(&ahci_ctlp->ahcictl_mutex);
	}

	if (attach_state & AHCI_ATTACH_STATE_INTR_ADDED) {
		ahci_rem_intrs(ahci_ctlp);
	}

	if (attach_state & AHCI_ATTACH_STATE_REG_MAP) {
		ddi_regs_map_free(&ahci_ctlp->ahcictl_ahci_acc_handle);
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

	AHCIDBG0(AHCIDBG_ENTRY, ahci_ctlp, "ahci_detach enter");

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

		/* deallocate the controller structures */
		ahci_ctlp->ahcictl_flags |= AHCI_DETACH;
		ahci_deallocate_controller(ahci_ctlp);
		ahci_ctlp->ahcictl_flags &= ~AHCI_DETACH;

		/* destroy any mutexes */
		mutex_exit(&ahci_ctlp->ahcictl_mutex);

		(void) pm_lower_power(ahci_ctlp->ahcictl_dip, 0,
		    PM_LEVEL_D3);

		mutex_destroy(&ahci_ctlp->ahcictl_mutex);

		/* remove the interrupts */
		ahci_rem_intrs(ahci_ctlp);

		/* remove the reg maps. */
		ddi_regs_map_free(&ahci_ctlp->ahcictl_ahci_acc_handle);

		/* free the soft state. */
		ddi_soft_state_free(ahci_statep, instance);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		/* It will be implemented in Phase 2 */
		return (DDI_FAILURE);

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

	AHCIDBG0(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_register_sata_hba_tran enter");

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

	sata_hba_tran->sata_tran_hba_features_support = 0;

	/* Get the data transfer capability for PIO command by the HBA */
	if (cap_status & AHCI_HBA_CAP_PMD) {
		ahci_ctlp->ahcictl_flags |= AHCI_PMD;
		AHCIDBG0(AHCIDBG_INFO, ahci_ctlp, "HBA supports multiple "
		    "DRQ block data transfer for PIO command protocol");
	} else {
		AHCIDBG0(AHCIDBG_INFO, ahci_ctlp, "HBA only supports single "
		    "DRQ block data transfer for PIO command protocol");
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
	AHCIDBG0(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_unregister_sata_hba_tran enter");

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
	uint8_t	cport = sd->satadev_addr.cport;
	uint8_t pmport = sd->satadev_addr.pmport;
	uint8_t qual = sd->satadev_addr.qual;
	uint8_t	device_type;
	uint32_t port_state;
	uint8_t port;

	ahci_ctlp = ddi_get_soft_state(ahci_statep, ddi_get_instance(dip));
	port = ahci_ctlp->ahcictl_cport_to_port[cport];

	AHCIDBG3(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_tran_probe_port enter: cport: 0x%x, "
	    "pmport: 0x%x, qual: 0x%x", cport, pmport, qual);

	ahci_portp = ahci_ctlp->ahcictl_ports[port];

	mutex_enter(&ahci_portp->ahciport_mutex);

	port_state = ahci_portp->ahciport_port_state;
	switch (port_state) {

	case SATA_PSTATE_FAILED:
		sd->satadev_state = SATA_PSTATE_FAILED;
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_probe_port %d: PORT FAILED", port);
		goto out;

	case SATA_PSTATE_SHUTDOWN:
		sd->satadev_state = SATA_PSTATE_SHUTDOWN;
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_probe_port %d: PORT SHUTDOWN", port);
		goto out;

	case SATA_PSTATE_PWROFF:
		sd->satadev_state = SATA_PSTATE_PWROFF;
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_probe_port %d: PORT PWROFF", port);
		goto out;

	case SATA_PSTATE_PWRON:
		sd->satadev_state = SATA_PSTATE_PWRON;
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port %d: PORT PWRON", port);
		break;

	default:
		sd->satadev_state = port_state;
		AHCIDBG2(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port %d: PORT NORMAL %x",
		    port, port_state);
		break;
	}

	device_type = ahci_portp->ahciport_device_type;

	switch (device_type) {

	case SATA_DTYPE_ATADISK:
		sd->satadev_type = SATA_DTYPE_ATADISK;
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port %d: DISK found", port);
		break;

	case SATA_DTYPE_ATAPICD:
		sd->satadev_type = SATA_DTYPE_ATAPICD;
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port %d: ATAPI found", port);
		break;

	case SATA_DTYPE_PMULT:
		sd->satadev_type = SATA_DTYPE_PMULT;
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port %d: Port Multiplier found",
		    port);
		break;

	case SATA_DTYPE_UNKNOWN:
		sd->satadev_type = SATA_DTYPE_UNKNOWN;
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port %d: Unknown device found", port);
		break;

	default:
		/* we don't support any other device types */
		sd->satadev_type = SATA_DTYPE_NONE;
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_probe_port %d: No device found", port);
		break;
	}

out:
	ahci_update_sata_registers(ahci_ctlp, port, sd);
	mutex_exit(&ahci_portp->ahciport_mutex);

	return (SATA_SUCCESS);
}

/*
 * Called by sata framework to transport a sata packet down stream.
 */
static int
ahci_tran_start(dev_info_t *dip, sata_pkt_t *spkt)
{
	ahci_ctl_t *ahci_ctlp;
	ahci_port_t *ahci_portp;
	uint8_t	cport = spkt->satapkt_device.satadev_addr.cport;
	uint8_t port;
	int slot;

	ahci_ctlp = ddi_get_soft_state(ahci_statep, ddi_get_instance(dip));
	port = ahci_ctlp->ahcictl_cport_to_port[cport];

	AHCIDBG2(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_tran_start enter: cport %d satapkt 0x%p",
	    cport, (void *)spkt);

	ahci_portp = ahci_ctlp->ahcictl_ports[port];

	mutex_enter(&ahci_portp->ahciport_mutex);

	if (ahci_portp->ahciport_port_state & SATA_PSTATE_FAILED |
	    ahci_portp->ahciport_port_state & SATA_PSTATE_SHUTDOWN |
	    ahci_portp->ahciport_port_state & SATA_PSTATE_PWROFF) {
		/*
		 * In case the targer driver would send the packet before
		 * sata framework can have the opportunity to process those
		 * event reports.
		 */
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		spkt->satapkt_device.satadev_state =
		    ahci_portp->ahciport_port_state;
		ahci_update_sata_registers(ahci_ctlp, port,
		    &spkt->satapkt_device);
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start returning PORT_ERROR while "
		    "port in FAILED/SHUTDOWN/PWROFF state: "
		    "cport: 0x%x", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_PORT_ERROR);
	}

	if (ahci_portp->ahciport_device_type == SATA_DTYPE_NONE) {
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
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start returning PORT_ERROR while "
		    "no device attached: cport: 0x%x", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_PORT_ERROR);
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
	if (spkt->satapkt_cmd.satacmd_flags.sata_clear_dev_reset) {
		ahci_portp->ahciport_reset_in_progress = 0;
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start clearing the "
		    "reset_in_progress for port: 0x%x", port);
	}

	if (ahci_portp->ahciport_reset_in_progress &&
	    ! spkt->satapkt_cmd.satacmd_flags.sata_ignore_dev_reset &&
	    ! ddi_in_panic()) {
		spkt->satapkt_reason = SATA_PKT_BUSY;
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start returning BUSY while "
		    "reset in progress: cport: 0x%x", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_BUSY);
	}

	if (ahci_portp->ahciport_flags & AHCI_PORT_STATE_MOPPING) {
		spkt->satapkt_reason = SATA_PKT_BUSY;
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_start returning BUSY while "
		    "mopping in progress: port: 0x%x", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_BUSY);
	}

	if ((slot = ahci_deliver_satapkt(ahci_ctlp, ahci_portp, port, spkt))
	    == AHCI_FAILURE) {
		spkt->satapkt_reason = SATA_PKT_QUEUE_FULL;
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp, "ahci_tran_start "
		    "returning QUEUE_FULL: port %d", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_TRAN_QUEUE_FULL);
	}

	if (spkt->satapkt_op_mode &
	    (SATA_OPMODE_POLLING | SATA_OPMODE_SYNCH)) {
		/* we need to poll now */
		mutex_exit(&ahci_portp->ahciport_mutex);
		ahci_poll_cmd(ahci_ctlp, ahci_portp, port, slot, spkt);
		mutex_enter(&ahci_portp->ahciport_mutex);
	}

	mutex_exit(&ahci_portp->ahciport_mutex);

	AHCIDBG1(AHCIDBG_INFO, ahci_ctlp, "ahci_tran_start "
	    "sata tran accepted: port %d", port);

	return (SATA_TRAN_ACCEPTED);
}

#define	SENDUP_PACKET(ahci_portp, satapkt, reason)			\
	if (satapkt) {							\
		satapkt->satapkt_reason = reason;			\
		/*							\
		 * We set the satapkt_reason in both sync and		\
		 * non-sync cases.					\
		 */							\
	}								\
	if (satapkt &&							\
	    !(satapkt->satapkt_op_mode & SATA_OPMODE_SYNCH) &&		\
	    satapkt->satapkt_comp) {					\
		mutex_exit(&ahci_portp->ahciport_mutex);		\
		(*satapkt->satapkt_comp)(satapkt);			\
		mutex_enter(&ahci_portp->ahciport_mutex);		\
	}

/*
 * Searches for and claims a free slot.
 *
 * Returns:     AHCI_FAILURE if no slots found
 *              claimed slot number if successful
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
/*ARGSUSED*/
static int
ahci_claim_free_slot(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
	uint32_t free_slots;
	int slot;

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp, "ahci_claim_free_slot enter "
	    "ahciport_pending_tags = 0x%x",
	    ahci_portp->ahciport_pending_tags);

	free_slots = (~ahci_portp->ahciport_pending_tags)
	    & AHCI_SLOT_MASK(ahci_ctlp);

	slot = ddi_ffs(free_slots) - 1;
	if (slot == -1) {
		AHCIDBG0(AHCIDBG_VERBOSE, ahci_ctlp,
		    "ahci_claim_free_slot: no empty slots");
		return (AHCI_FAILURE);
	}

	ahci_portp->ahciport_pending_tags |= (0x1 << slot);

	AHCIDBG1(AHCIDBG_VERBOSE, ahci_ctlp,
	    "ahci_claim_free_slot: found slot: 0x%x", slot);

	return (slot);
}

/*
 * Builds the Command Table for the sata packet and delivers it to controller.
 *
 * Returns:
 * 	slot number if we can obtain a slot successfully
 *	otherwise, return AHCI_FAILURE
 *
 * WARNING!!! ahciport_mutex should be acquired before the function is called.
 */
static int
ahci_deliver_satapkt(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    uint8_t port, sata_pkt_t *spkt)
{
	int slot;
	sata_cmd_t *cmd;
	ahci_fis_h2d_register_t *h2d_register_fisp;
	ahci_cmd_table_t *cmd_table;
	ahci_cmd_header_t *cmd_header;
	int ncookies;
	int i;

	spkt->satapkt_reason = SATA_PKT_BUSY;

	cmd = &spkt->satapkt_cmd;

	/* Check if there is an empty command slot */
	slot = ahci_claim_free_slot(ahci_ctlp, ahci_portp);
	if (slot == AHCI_FAILURE) {
		AHCIDBG0(AHCIDBG_INFO, ahci_ctlp, "no free slot");
		return (AHCI_FAILURE);
	}

	AHCIDBG4(AHCIDBG_ENTRY|AHCIDBG_INFO, ahci_ctlp,
	    "ahci_deliver_satapkt enter: cmd_reg: 0x%x, slot: 0x%x, "
	    "port: %d, satapkt: 0x%p", cmd->satacmd_cmd_reg,
	    slot, port, (void *)spkt);

	cmd_table = ahci_portp->ahciport_cmd_tables[slot];
	bzero((void *)cmd_table, ahci_cmd_table_size);

	/* For data transfer operations, this is the H2D Register FIS */
	h2d_register_fisp =
	    &(cmd_table->ahcict_command_fis.ahcifc_fis.ahcifc_h2d_register);

	SET_FIS_TYPE(h2d_register_fisp, AHCI_H2D_REGISTER_FIS_TYPE);
	if ((spkt->satapkt_device.satadev_addr.qual == SATA_ADDR_PMPORT) ||
	    (spkt->satapkt_device.satadev_addr.qual == SATA_ADDR_DPMPORT)) {
		SET_FIS_PMP(h2d_register_fisp,
		    spkt->satapkt_device.satadev_addr.pmport);
	}

	SET_FIS_CDMDEVCTL(h2d_register_fisp, 1);
	SET_FIS_COMMAND(h2d_register_fisp, cmd->satacmd_cmd_reg);
	SET_FIS_FEATURES(h2d_register_fisp, cmd->satacmd_features_reg);
	SET_FIS_SECTOR_COUNT(h2d_register_fisp, cmd->satacmd_sec_count_lsb);

	switch (cmd->satacmd_addr_type) {

	case ATA_ADDR_LBA:
		/* fallthrough */

	case ATA_ADDR_LBA28:
		/* LBA[7:0] */
		SET_FIS_SECTOR(h2d_register_fisp, cmd->satacmd_lba_low_lsb);

		/* LBA[15:8] */
		SET_FIS_CYL_LOW(h2d_register_fisp, cmd->satacmd_lba_mid_lsb);

		/* LBA[23:16] */
		SET_FIS_CYL_HI(h2d_register_fisp, cmd->satacmd_lba_high_lsb);

		/* LBA [27:24] (also called dev_head) */
		SET_FIS_DEV_HEAD(h2d_register_fisp, cmd->satacmd_device_reg);

		break;

	case ATA_ADDR_LBA48:
		/* LBA[7:0] */
		SET_FIS_SECTOR(h2d_register_fisp, cmd->satacmd_lba_low_lsb);

		/* LBA[15:8] */
		SET_FIS_CYL_LOW(h2d_register_fisp, cmd->satacmd_lba_mid_lsb);

		/* LBA[23:16] */
		SET_FIS_CYL_HI(h2d_register_fisp, cmd->satacmd_lba_high_lsb);

		/* LBA [31:24] */
		SET_FIS_SECTOR_EXP(h2d_register_fisp,
		    cmd->satacmd_lba_low_msb);

		/* LBA [39:32] */
		SET_FIS_CYL_LOW_EXP(h2d_register_fisp,
		    cmd->satacmd_lba_mid_msb);

		/* LBA [47:40] */
		SET_FIS_CYL_HI_EXP(h2d_register_fisp,
		    cmd->satacmd_lba_high_msb);

		/* Set dev_head */
		SET_FIS_DEV_HEAD(h2d_register_fisp,
		    cmd->satacmd_device_reg);

		/* Set the extended sector count and features */
		SET_FIS_SECTOR_COUNT_EXP(h2d_register_fisp,
		    cmd->satacmd_sec_count_msb);
		SET_FIS_FEATURES_EXP(h2d_register_fisp,
		    cmd->satacmd_features_reg_ext);
		break;
	}

	ncookies = cmd->satacmd_num_dma_cookies;
	AHCIDBG2(AHCIDBG_INFO, ahci_ctlp,
	    "ncookies = 0x%x, ahci_dma_prdt_number = 0x%x",
	    ncookies, ahci_dma_prdt_number);

	ASSERT(ncookies <= ahci_dma_prdt_number);

	/* *** now fill the scatter gather list ******* */
	for (i = 0; i < ncookies; i++) {
		cmd_table->ahcict_prdt[i].ahcipi_data_base_addr =
		    cmd->satacmd_dma_cookie_list[i]._dmu._dmac_la[0];
		cmd_table->ahcict_prdt[i].ahcipi_data_base_addr_upper =
		    cmd->satacmd_dma_cookie_list[i]._dmu._dmac_la[1];
		cmd_table->ahcict_prdt[i].ahcipi_descr_info =
		    cmd->satacmd_dma_cookie_list[i].dmac_size - 1;
	}

	/* Set Command Header in Command List */
	cmd_header = &ahci_portp->ahciport_cmd_list[slot];
	BZERO_DESCR_INFO(cmd_header);
	BZERO_PRD_BYTE_COUNT(cmd_header);
	SET_PRD_TABLE_LENGTH(cmd_header, ncookies);
	SET_COMMAND_FIS_LENGTH(cmd_header, AHCI_H2D_REGISTER_FIS_LENGTH);

	AHCIDBG1(AHCIDBG_INFO, ahci_ctlp, "command data direction is "
	    "sata_data_direction = 0x%x",
	    cmd->satacmd_flags.sata_data_direction);

	if (cmd->satacmd_flags.sata_data_direction == SATA_DIR_WRITE)
		SET_WRITE(cmd_header, AHCI_CMDHEAD_DATA_WRITE);

	SET_PREFETCHABLE(cmd_header, AHCI_CMDHEAD_PREFETCHABLE);

	/* Now remember the sata packet in ahciport_slot_pkts[]. */
	ahci_portp->ahciport_slot_pkts[slot] = spkt;

	/*
	 * We are overloading satapkt_hba_driver_private with
	 * watched_cycle count.
	 */
	spkt->satapkt_hba_driver_private = (void *)(intptr_t)0;

	/* *** finished filling the scatter gather list , sync******* */
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

	AHCIDBG1(AHCIDBG_INFO, ahci_ctlp, "ahci_deliver_satapkt "
	    "exit: port %d", port);

	return (slot);
}

/*
 * Polls for the completion of the command. This is safe with both
 * interrupts enabled or disabled.
 */
static void
ahci_poll_cmd(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    uint8_t port, int slot, sata_pkt_t *spkt)
{
	uint32_t slot_status;
	int pkt_timeout_ticks;
	int in_panic = ddi_in_panic();

	AHCIDBG1(AHCIDBG_ENTRY|AHCIDBG_INFO, ahci_ctlp,
	    "ahci_poll_cmd entered, port: %x", port);

	pkt_timeout_ticks =
	    drv_usectohz((clock_t)spkt->satapkt_time * 1000000);

	mutex_enter(&ahci_portp->ahciport_mutex);

	/* we start out with SATA_PKT_COMPLETED as the satapkt_reason */
	spkt->satapkt_reason = SATA_PKT_COMPLETED;

	/*
	 * The interrupt handler will return directly for poll commands in case
	 * the interrupt has been generated before interrupts were disabled.
	 */
	ahci_disable_port_intrs(ahci_ctlp, ahci_portp, port);

	do {
		slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

		if (slot_status & (0x1 << slot)) {
			if (in_panic) {
				/*
				 * If we are in panic, we can't rely on
				 * timers; so, busy wait instead of delay().
				 */
				mutex_exit(&ahci_portp->ahciport_mutex);
				drv_usecwait(AHCI_1MS_USECS);
				mutex_enter(&ahci_portp->ahciport_mutex);
			} else {
				mutex_exit(&ahci_portp->ahciport_mutex);
#ifndef __lock_lint
				delay(AHCI_1MS_TICKS);
#endif /* __lock_lint */
				mutex_enter(&ahci_portp->ahciport_mutex);
			}
		} else {
			AHCIDBG0(AHCIDBG_INFO, ahci_ctlp, "poll_cmd finished");
			break;
		}

		pkt_timeout_ticks -= AHCI_1MS_TICKS;

	} while (pkt_timeout_ticks > 0);

	if (spkt->satapkt_reason != SATA_PKT_COMPLETED) {
		goto poll_done;
	}

	if (slot_status & AHCI_SLOT_MASK(ahci_ctlp) & (0x1 << slot)) {
		spkt->satapkt_reason = SATA_PKT_TIMEOUT;
	}

	CLEAR_BIT(ahci_portp->ahciport_pending_tags, slot);
	ahci_portp->ahciport_slot_pkts[slot] = NULL;

poll_done:
	ahci_enable_port_intrs(ahci_ctlp, ahci_portp, port);
	mutex_exit(&ahci_portp->ahciport_mutex);
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
	uint32_t slot_status;
	uint32_t aborted_tags, finished_tags;
	uint8_t cport = spkt->satapkt_device.satadev_addr.cport;
	uint8_t port;
	int tmp_slot;

	ahci_ctlp = ddi_get_soft_state(ahci_statep, ddi_get_instance(dip));
	port = ahci_ctlp->ahcictl_cport_to_port[cport];

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_tran_abort on cport %d", cport);

	ahci_portp = ahci_ctlp->ahcictl_ports[port];

	mutex_enter(&ahci_portp->ahciport_mutex);

	/*
	 * To prevent recursive enter to ahci_mop_commands, we need
	 * check AHCI_PORT_STATE_MOPPING flag.
	 */
	if (ahci_portp->ahciport_flags & AHCI_PORT_STATE_MOPPING) {
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_tran_abort: port %d is in "
		    "mopping process, so just return directly ", port);
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
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_abort returning SATA_FAILURE while "
		    "port in FAILED/SHUTDOWN/PWROFF state: "
		    "cport: 0x%x", port);
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
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_tran_abort returning SATA_FAILURE while "
		    "no device attached: cport: 0x%x", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (SATA_FAILURE);
	}

	if (flag == SATA_ABORT_ALL_PACKETS) {
		aborted_tags = ahci_portp->ahciport_pending_tags;
		cmn_err(CE_NOTE, "!ahci port %d abort all packets", port);
	} else {
		aborted_tags = 0xffffffff;
		/*
		 * Aborting one specific packet, first search our
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
			AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
			    "Cannot find the aborting pkt 0x%p on the "
			    "pending list", (void *)spkt);
			ahci_update_sata_registers(ahci_ctlp, port,
			    &spkt->satapkt_device);
			mutex_exit(&ahci_portp->ahciport_mutex);
			return (SATA_FAILURE);
		}
		cmn_err(CE_NOTE, "!ahci port %d abort satapkt 0x%p",
		    port, (void *)spkt);
	}

	slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

	ahci_portp->ahciport_flags |= AHCI_PORT_STATE_MOPPING;

	/*
	 * To abort the packet(s), first we are trying to clear PxCMD.ST
	 * and PxCMD.FRE to stop the port, and if the port can be stopped
	 * successfully with PxTFD.STS.BSY and PxTFD.STS.DRQ cleared to '0',
	 * then we just send back the aborted packet(s) with ABORTED flag
	 * and then restart the port by setting PxCMD.ST and PxCMD.FRE.
	 * If PxTFD.STS.BSY or PxTFD.STS.DRQ is set to '1', then we
	 * perform a COMRESET.
	 */
	(void) ahci_restart_port_wait_till_ready(ahci_ctlp,
	    ahci_portp, port, NULL);

	/*
	 * Compute which have finished and which need to be retried.
	 *
	 * The finished tags are ahciport_pending_tags minus the slot_status.
	 * The aborted_tags have to be reduced by finished_tags since we
	 * can't possibly abort a tag which had finished already.
	 */
	finished_tags = ahci_portp->ahciport_pending_tags &
	    ~slot_status & AHCI_SLOT_MASK(ahci_ctlp);

	aborted_tags &= ~finished_tags;

	mutex_exit(&ahci_portp->ahciport_mutex);
	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    port,
	    slot_status,
	    0, /* failed tags */
	    0, /* timeout tags */
	    aborted_tags,
	    0); /* reset tags */

	mutex_enter(&ahci_portp->ahciport_mutex);
	ahci_update_sata_registers(ahci_ctlp, port, &spkt->satapkt_device);
	mutex_exit(&ahci_portp->ahciport_mutex);

	return (SATA_SUCCESS);
}

/*
 * Used to do device reset and reject all the pending packets on a device
 * during the reset operation.
 *
 * WARNING!!! ahciport_mutex should be acquired before the function is called.
 */
static int
ahci_reset_device_reject_pkts(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t slot_status;
	uint32_t reset_tags, finished_tags;
	sata_device_t sdevice;
	int ret;

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_reset_device_reject_pkts on port: %d", port);

	/*
	 * To prevent recursive enter to ahci_mop_commands, we need
	 * check AHCI_PORT_STATE_MOPPING flag.
	 */
	if (ahci_portp->ahciport_flags & AHCI_PORT_STATE_MOPPING) {
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_reset_device_reject_pkts: port %d is in "
		    "mopping process, so return directly ", port);
		return (SATA_SUCCESS);
	}

	slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

	reset_tags = slot_status & AHCI_SLOT_MASK(ahci_ctlp);

	if (ahci_software_reset(ahci_ctlp, ahci_portp, port)
	    != AHCI_SUCCESS) {
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "Try to do a port reset after software "
		    "reset failed", port);
		ret = ahci_port_reset(ahci_ctlp, ahci_portp, port);
		if (ret != AHCI_SUCCESS) {
			ahci_portp->ahciport_port_state = SATA_PSTATE_FAILED;
			AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_reset_device_reject_pkts: port %d "
			    "failed", port);
			return (SATA_FAILURE);
		}
	}
	/* Set the reset in progress flag */
	ahci_portp->ahciport_reset_in_progress = 1;

	ahci_portp->ahciport_flags |= AHCI_PORT_STATE_MOPPING;

	/* Indicate to the framework that a reset has happened */
	bzero((void *)&sdevice, sizeof (sata_device_t));
	sdevice.satadev_addr.cport = ahci_ctlp->ahcictl_port_to_cport[port];
	sdevice.satadev_addr.pmport = AHCI_PORTMULT_CONTROL_PORT;

	if (ahci_portp->ahciport_device_type == SATA_DTYPE_PMULT) {
		sdevice.satadev_addr.qual = SATA_ADDR_DPMPORT;
	} else {
		sdevice.satadev_addr.qual = SATA_ADDR_DCPORT;
	}

	sdevice.satadev_state = SATA_DSTATE_RESET |
	    SATA_DSTATE_PWR_ACTIVE;
	mutex_exit(&ahci_portp->ahciport_mutex);
	sata_hba_event_notify(
	    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
	    &sdevice,
	    SATA_EVNT_DEVICE_RESET);
	mutex_enter(&ahci_portp->ahciport_mutex);

	AHCIDBG1(AHCIDBG_EVENT, ahci_ctlp,
	    "port %d sending event up: SATA_EVNT_RESET", port);

	/* Next try to mop the pending commands */
	finished_tags = ahci_portp->ahciport_pending_tags &
	    ~slot_status & AHCI_SLOT_MASK(ahci_ctlp);

	reset_tags &= ~finished_tags;

	mutex_exit(&ahci_portp->ahciport_mutex);
	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    port,
	    slot_status,
	    0, /* failed tags */
	    0, /* timeout tags */
	    0, /* aborted tags */
	    reset_tags); /* reset tags */
	mutex_enter(&ahci_portp->ahciport_mutex);

	return (SATA_SUCCESS);
}

/*
 * Used to do port reset and reject all the pending packets on a port during
 * the reset operation.
 *
 * WARNING!!! ahciport_mutex should be acquired before the function is called.
 */
static int
ahci_reset_port_reject_pkts(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t slot_status;
	uint32_t reset_tags, finished_tags;

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_reset_port_reject_pkts on port: %d", port);

	/*
	 * To prevent recursive enter to ahci_mop_commands, we need
	 * check AHCI_PORT_STATE_MOPPING flag.
	 */
	if (ahci_portp->ahciport_flags & AHCI_PORT_STATE_MOPPING) {
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_reset_port_reject_pkts: port %d is in "
		    "mopping process, so return directly ", port);
		return (SATA_SUCCESS);
	}

	ahci_portp->ahciport_flags |= AHCI_PORT_STATE_MOPPING;

	slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

	reset_tags = slot_status & AHCI_SLOT_MASK(ahci_ctlp);

	if (ahci_restart_port_wait_till_ready(ahci_ctlp,
	    ahci_portp, port, AHCI_PORT_RESET) != AHCI_SUCCESS)
		return (SATA_FAILURE);

	finished_tags = ahci_portp->ahciport_pending_tags &
	    ~slot_status & AHCI_SLOT_MASK(ahci_ctlp);

	reset_tags &= ~finished_tags;

	mutex_exit(&ahci_portp->ahciport_mutex);
	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    port,
	    slot_status,
	    0, /* failed tags */
	    0, /* timeout tags */
	    0, /* aborted tags */
	    reset_tags); /* reset tags */
	mutex_enter(&ahci_portp->ahciport_mutex);

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
	sata_device_t sdevice[AHCI_MAX_PORTS];
	uint8_t port;
	int ret = SATA_SUCCESS;

	AHCIDBG0(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_reset_hba_reject_pkts enter");

	mutex_enter(&ahci_ctlp->ahcictl_mutex);

	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			continue;
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];

		mutex_enter(&ahci_portp->ahciport_mutex);
		slot_status[port] = ddi_get32(
		    ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));
		reset_tags[port] = slot_status[port]
		    & AHCI_SLOT_MASK(ahci_ctlp);
		mutex_exit(&ahci_portp->ahciport_mutex);
	}

	if (ahci_hba_reset(ahci_ctlp) != AHCI_SUCCESS) {
		ret = SATA_FAILURE;
		goto out;
	}

	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			continue;
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];

		mutex_enter(&ahci_portp->ahciport_mutex);
		/*
		 * To prevent recursive enter to ahci_mop_commands, we need
		 * check AHCI_PORT_STATE_MOPPING flag.
		 */
		if (ahci_portp->ahciport_flags & AHCI_PORT_STATE_MOPPING) {
			AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_reset_hba_reject_pkts: port %d is in "
			    "mopping process, so return directly ", port);
			mutex_exit(&ahci_portp->ahciport_mutex);
			continue;
		}

		ahci_portp->ahciport_flags |= AHCI_PORT_STATE_MOPPING;

		/* Indicate to the framework that a reset has happened */
		bzero((void *)&sdevice[port], sizeof (sata_device_t));
		sdevice[port].satadev_addr.cport =
		    ahci_ctlp->ahcictl_port_to_cport[port];
		sdevice[port].satadev_addr.pmport = AHCI_PORTMULT_CONTROL_PORT;

		if (ahci_portp->ahciport_device_type == SATA_DTYPE_PMULT) {
			sdevice[port].satadev_addr.qual = SATA_ADDR_DPMPORT;
		} else {
			sdevice[port].satadev_addr.qual = SATA_ADDR_DCPORT;
		}
		sdevice[port].satadev_state = SATA_DSTATE_RESET |
		    SATA_DSTATE_PWR_ACTIVE;
		mutex_exit(&ahci_portp->ahciport_mutex);
		sata_hba_event_notify(
		    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
		    &sdevice[port],
		    SATA_EVNT_DEVICE_RESET);
		mutex_enter(&ahci_portp->ahciport_mutex);

		AHCIDBG1(AHCIDBG_EVENT, ahci_ctlp,
		    "port %d sending event up: SATA_EVNT_RESET",
		    port);

		finished_tags[port]  = ahci_portp->ahciport_pending_tags &
		    ~slot_status[port] & AHCI_SLOT_MASK(ahci_ctlp);

		reset_tags[port] &= ~finished_tags[port];

		mutex_exit(&ahci_portp->ahciport_mutex);
		ahci_mop_commands(ahci_ctlp,
		    ahci_portp,
		    port,
		    slot_status[port],
		    0, /* failed tags */
		    0, /* timeout tags */
		    0, /* aborted tags */
		    reset_tags[port]); /* reset tags */
	}
out:
	mutex_exit(&ahci_ctlp->ahcictl_mutex);

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
	uint8_t cport = sd->satadev_addr.cport;
	uint8_t port;
	int ret = SATA_SUCCESS;

	ahci_ctlp = ddi_get_soft_state(ahci_statep, ddi_get_instance(dip));
	port = ahci_ctlp->ahcictl_cport_to_port[cport];

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_tran_reset_port enter: cport: 0x%x", cport);

	switch (sd->satadev_addr.qual) {
	case SATA_ADDR_CPORT:
		/* Port reset */
		ahci_portp = ahci_ctlp->ahcictl_ports[port];
		cmn_err(CE_NOTE, "!ahci port %d reset port", port);

		mutex_enter(&ahci_portp->ahciport_mutex);
		ret = ahci_reset_port_reject_pkts(ahci_ctlp, ahci_portp, port);
		mutex_exit(&ahci_portp->ahciport_mutex);

		break;

	case SATA_ADDR_DCPORT:
		/* Device reset */
		ahci_portp = ahci_ctlp->ahcictl_ports[port];
		cmn_err(CE_NOTE, "!ahci port %d reset device", port);

		mutex_enter(&ahci_portp->ahciport_mutex);
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
			AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_tran_reset_dport returning SATA_FAILURE "
			    "while port in FAILED/SHUTDOWN/PWROFF state: "
			    "cport: 0x%x", port);
			mutex_exit(&ahci_portp->ahciport_mutex);
			ret = SATA_FAILURE;
			break;
		}

		if (ahci_portp->ahciport_device_type == SATA_DTYPE_NONE) {
			/*
			 * ahci_intr_phyrdy_change() may have rendered it to
			 * AHCI_PORT_TYPE_NODEV.
			 */
			sd->satadev_type = SATA_DTYPE_NONE;
			sd->satadev_state = ahci_portp->ahciport_port_state;
			ahci_update_sata_registers(ahci_ctlp, port, sd);
			AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_tran_reset_dport returning SATA_FAILURE "
			    "while no device attached: cport: 0x%x", port);
			mutex_exit(&ahci_portp->ahciport_mutex);
			ret = SATA_FAILURE;
			break;
		}

		ret = ahci_reset_device_reject_pkts(ahci_ctlp,
		    ahci_portp, port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		break;

	case SATA_ADDR_CNTRL:
		/* Reset the whole controller */
		cmn_err(CE_NOTE, "!ahci port %d reset the whole hba", port);
		ret = ahci_reset_hba_reject_pkts(ahci_ctlp);
		break;

	case SATA_ADDR_PMPORT:
	case SATA_ADDR_DPMPORT:
		AHCIDBG0(AHCIDBG_INFO, ahci_ctlp,
		    "port multiplier will be supported later");
		/* FALLSTHROUGH */
	default:
		ret = SATA_FAILURE;
	}

	return (ret);
}

/*
 * Called by sata framework to activate a port as part of hotplug.
 * (cfgadm -c connect satax/y)
 * Note: Not port-mult aware.
 */
static int
ahci_tran_hotplug_port_activate(dev_info_t *dip, sata_device_t *satadev)
{
	ahci_ctl_t *ahci_ctlp;
	ahci_port_t *ahci_portp;
	uint8_t	cport = satadev->satadev_addr.cport;
	uint8_t port;

	ahci_ctlp = ddi_get_soft_state(ahci_statep, ddi_get_instance(dip));
	port = ahci_ctlp->ahcictl_cport_to_port[cport];

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_tran_hotplug_port_activate cport %d enter", cport);

	ahci_portp = ahci_ctlp->ahcictl_ports[port];

	mutex_enter(&ahci_portp->ahciport_mutex);
	cmn_err(CE_NOTE, "!ahci port %d activate", port);

	/* Enable the interrupts on the port. */
	ahci_enable_port_intrs(ahci_ctlp, ahci_portp, port);

	/*
	 * Reset the port so that the PHY communication would be re-established.
	 * But this reset is an internal operation; the sata framework does
	 * not need to know about it.
	 */
	(void) ahci_restart_port_wait_till_ready(ahci_ctlp,
	    ahci_portp, port, AHCI_PORT_RESET|AHCI_RESET_NO_EVENTS_UP);

	/*
	 * Need to check the link status and device status of the port
	 * and consider raising power if the port was in D3 state
	 */
	ahci_portp->ahciport_port_state = SATA_PSTATE_PWRON;
	satadev->satadev_state = SATA_PSTATE_PWRON;

	ahci_update_sata_registers(ahci_ctlp, port, satadev);

	mutex_exit(&ahci_portp->ahciport_mutex);
	return (SATA_SUCCESS);
}

/*
 * Called by sata framework to deactivate a port as part of hotplug.
 * (cfgadm -c disconnect satax/y)
 * Note: Not port-mult aware.
 */
static int
ahci_tran_hotplug_port_deactivate(dev_info_t *dip, sata_device_t *satadev)
{
	ahci_ctl_t *ahci_ctlp;
	ahci_port_t *ahci_portp;
	uint8_t cport = satadev->satadev_addr.cport;
	uint8_t port;

	ahci_ctlp = ddi_get_soft_state(ahci_statep, ddi_get_instance(dip));
	port = ahci_ctlp->ahcictl_cport_to_port[cport];

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_tran_hotplug_port_deactivate cport %d enter", cport);

	ahci_portp = ahci_ctlp->ahcictl_ports[port];

	mutex_enter(&ahci_portp->ahciport_mutex);
	cmn_err(CE_NOTE, "!ahci port %d deactivate", port);

	/* Disable the interrupts on the port. */
	ahci_disable_port_intrs(ahci_ctlp, ahci_portp, port);

	/* First to abort all the pending commands */
	ahci_reject_all_abort_pkts(ahci_ctlp, ahci_portp, port);

	/* Then shut down the port */
	(void) ahci_port_into_notrunning_state(ahci_ctlp,
	    ahci_portp, port);

	/* Update ahciport_port_state */
	ahci_portp->ahciport_port_state = SATA_PSTATE_SHUTDOWN;

	satadev->satadev_state = SATA_PSTATE_SHUTDOWN;

	ahci_update_sata_registers(ahci_ctlp, port, satadev);

	mutex_exit(&ahci_portp->ahciport_mutex);
	return (SATA_SUCCESS);
}

/*
 * To be used to mark all the pending pkts with ABORTED
 * when a device is unplugged or a port is deactivated.
 *
 * WARNING!!! ahciport_mutex should be acquired before the function is called.
 */
static void
ahci_reject_all_abort_pkts(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t slot_status;
	uint32_t abort_tags;

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_reject_all_abort_pkts on port: %d", port);

	/*
	 * To prevent recursive enter to ahci_mop_commands, we need
	 * check AHCI_PORT_STATE_MOPPING flag.
	 */
	if (ahci_portp->ahciport_flags & AHCI_PORT_STATE_MOPPING) {
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_reject_all_abort_pkts: port %d is in "
		    "mopping process, so return directly ", port);
		return;
	}

	ahci_portp->ahciport_flags |= AHCI_PORT_STATE_MOPPING;

	slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

	abort_tags = slot_status & AHCI_SLOT_MASK(ahci_ctlp);

	mutex_exit(&ahci_portp->ahciport_mutex);
	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    port,
	    slot_status,
	    0, /* failed tags */
	    0, /* timeout tags */
	    abort_tags, /* aborting tags */
	    0); /* reset tags */
	mutex_enter(&ahci_portp->ahciport_mutex);
}

#if defined(__lock_lint)
static int
ahci_selftest(dev_info_t *dip, sata_device_t *device)
{
	return (SATA_SUCCESS);
}
#endif

/*
 * Initialize the controller and set up driver data structures.
 *
 * This routine can be called from three seperate cases: DDI_ATTACH,
 * PM_LEVEL_D0 and DDI_RESUME. The DDI_ATTACH case is different from
 * other two cases; the memory allocation and device signature probing
 * are attempted only during DDI_ATTACH case.
 *
 * WARNING!!! Disable the whole controller's interrupts before calling and
 * the interrupts will be enabled upon successfully return.
 */
static int
ahci_initialize_controller(ahci_ctl_t *ahci_ctlp)
{
	ahci_port_t *ahci_portp;
	uint32_t ghc_control;
	int port, cport = 0;

	AHCIDBG0(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_initialize_controller enter");

	mutex_enter(&ahci_ctlp->ahcictl_mutex);

	/*
	 * Indicate that system software is AHCI aware by setting
	 * GHC.AE to 1
	 */
	ghc_control = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp));

	ghc_control |= AHCI_HBA_GHC_AE;
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp),
	    ghc_control);

	/* Initialize the implemented ports and structures */
	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			AHCIDBG1(AHCIDBG_INIT, ahci_ctlp,
			    "hba port %d not implemented", port);
			continue;
		}

		/* only allocate port during attach */
		if (ahci_ctlp->ahcictl_flags & AHCI_ATTACH) {
#ifndef __lock_lint
			ahci_ctlp->ahcictl_cport_to_port[cport] = (uint8_t)port;
			ahci_ctlp->ahcictl_port_to_cport[port] =
			    (uint8_t)cport++;
#endif /* __lock_lint */
			if (ahci_alloc_port_state(ahci_ctlp, port) !=
			    AHCI_SUCCESS) {
				goto err_out;
			}
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];
		mutex_enter(&ahci_portp->ahciport_mutex);

		/*
		 * Ensure that the controller is not in the running state
		 * by checking every implemented port's PxCMD register
		 */
		if (ahci_initialize_port(ahci_ctlp, ahci_portp, port)
		    != AHCI_SUCCESS) {
			AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_initialize_controller: failed to "
			    "initialize port %d", port);
			/*
			 * Set the port state to SATA_PSTATE_FAILED if
			 * failed to initialize it.
			 */
			ahci_portp->ahciport_port_state |= SATA_PSTATE_FAILED;
		}

		mutex_exit(&ahci_portp->ahciport_mutex);
	}

	/* Enable the whole controller interrupts */
	ahci_enable_all_intrs(ahci_ctlp);
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
 * Reverse of ahci_initialize_controller(), only need to de-allocate
 * all ports' state structures for AHCI_DETACH case.
 *
 * WARNING!!! ahcictl_mutex should be acquired before the function is called.
 */
static void
ahci_deallocate_controller(ahci_ctl_t *ahci_ctlp)
{
	uint8_t port;

	AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
	    "ahci_deallocate_controller enter");

	/* disable all the interrupts. */
	ahci_disable_all_intrs(ahci_ctlp);

	if (ahci_ctlp->ahcictl_flags & AHCI_DETACH) {
		for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {

			/* if this port is implemented by the HBA */
			if (AHCI_PORT_IMPLEMENTED(ahci_ctlp, port))
				ahci_dealloc_port_state(ahci_ctlp, port);
		}
	}
}

/*
 * The routine is to initialize the port. First put the port in NOTRunning
 * state, then enable port interrupt and clear Serror register. And under
 * AHCI_ATTACH case, find device signature and then try to start the port.
 *
 * WARNING!!! ahcictl_mutex and ahciport_mutex should be acquired before
 * the function is called.
 */
static int
ahci_initialize_port(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_cmd_status;

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	AHCIDBG2(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_initialize_port: port %d "
	    "port_cmd_status = 0x%x", port, port_cmd_status);
	/*
	 * Check whether the port is in NotRunning state, if not,
	 * put the port in NotRunning state
	 */
	if (!(port_cmd_status &
	    (AHCI_CMD_STATUS_ST |
	    AHCI_CMD_STATUS_CR |
	    AHCI_CMD_STATUS_FRE |
	    AHCI_CMD_STATUS_FR))) {

		goto done_out;
	}

	if (ahci_restart_port_wait_till_ready(ahci_ctlp, ahci_portp,
	    port, AHCI_RESET_NO_EVENTS_UP|AHCI_PORT_INIT) != AHCI_SUCCESS)
		return (AHCI_FAILURE);

done_out:
	AHCIDBG1(AHCIDBG_INIT, ahci_ctlp,
	    "port %d is in NotRunning state", port);

	/* Enable port interrupts */
	ahci_enable_port_intrs(ahci_ctlp, ahci_portp, port);

	/*
	 * Only probe ports/devices and get the types of attached
	 * devices during attach.
	 */
	if (ahci_ctlp->ahcictl_flags & AHCI_ATTACH) {
		if (ahci_find_dev_signature(ahci_ctlp,
		    ahci_portp, port) != AHCI_SUCCESS) {

			return (AHCI_FAILURE);
		}

		/* Try to start the port */
		if ((ahci_portp->ahciport_device_type
		    == SATA_DTYPE_ATADISK) &&
		    (ahci_start_port(ahci_ctlp, port)
		    != AHCI_SUCCESS)) {

			return (AHCI_FAILURE);
		}
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
 * cleared.
 *
 * WARNING!!! ahciport_mutex should be acquired and PxCMD.FRE should be
 * set before the function is called.
 */
static int
ahci_software_reset(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    uint8_t port)
{
	ahci_fis_h2d_register_t *h2d_register_fisp;
	ahci_cmd_table_t *cmd_table;
	ahci_cmd_header_t *cmd_header;
	int32_t port_cmd_status, port_cmd_issue, port_task_file;
	int slot, loop_count;

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "Port %d device resetting", port);

	/* First to clear PxCMD.ST */
	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	port_cmd_status &= ~AHCI_CMD_STATUS_ST;

	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
	    port_cmd_status|AHCI_CMD_STATUS_ST);

	/* And then to re-set PxCMD.ST */
	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
	    port_cmd_status|AHCI_CMD_STATUS_ST);

	/* Check PxTFD.STS.BSY and PxTFD.STS.DRQ */
	port_task_file = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));

	if (port_task_file & AHCI_TFD_STS_BSY ||
	    port_task_file & AHCI_TFD_STS_DRQ) {
		if (!(port_cmd_status & AHCI_CMD_STATUS_CLO)) {
			AHCIDBG0(AHCIDBG_ERRS, ahci_ctlp,
			    "PxTFD.STS.BSY or PxTFD.STS.DRQ is still set, "
			    "but PxCMD.CLO isn't supported, so a port "
			    "reset is needed.");
			return (AHCI_FAILURE);
		}
	}

	slot = ahci_claim_free_slot(ahci_ctlp, ahci_portp);
	if (slot == AHCI_FAILURE) {
		AHCIDBG0(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_software_reset: no free slot");
		return (AHCI_FAILURE);
	}

	/* Now send the first R2H FIS with SRST set to 1 */
	cmd_table = ahci_portp->ahciport_cmd_tables[slot];
	bzero((void *)cmd_table, ahci_cmd_table_size);

	h2d_register_fisp =
	    &(cmd_table->ahcict_command_fis.ahcifc_fis.ahcifc_h2d_register);

	SET_FIS_TYPE(h2d_register_fisp, AHCI_H2D_REGISTER_FIS_TYPE);
	SET_FIS_PMP(h2d_register_fisp, AHCI_PORTMULT_CONTROL_PORT);
	SET_FIS_DEVCTL(h2d_register_fisp, SATA_DEVCTL_SRST);

	/* Set Command Header in Command List */
	cmd_header = &ahci_portp->ahciport_cmd_list[slot];
	BZERO_DESCR_INFO(cmd_header);
	BZERO_PRD_BYTE_COUNT(cmd_header);
	SET_COMMAND_FIS_LENGTH(cmd_header, 5);

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

		if (loop_count++ > AHCI_POLLRATE_PORT_SOFTRESET) {
			/* We are effectively timing out after 0.1 sec. */
			break;
		}
		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(AHCI_10MS_TICKS);
#endif /* __lock_lint */
	} while (port_cmd_issue	& AHCI_SLOT_MASK(ahci_ctlp) & (0x1 << slot));

	AHCIDBG3(AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_software_reset: 1st loop count: %d, "
	    "port_cmd_issue = 0x%x, slot = 0x%x",
	    loop_count, port_cmd_issue, slot);

	CLEAR_BIT(ahci_portp->ahciport_pending_tags, slot);
	ahci_portp->ahciport_slot_pkts[slot] = NULL;

	/* Now send the second R2H FIS with SRST cleard to zero */
	cmd_table = ahci_portp->ahciport_cmd_tables[slot];
	bzero((void *)cmd_table, ahci_cmd_table_size);

	h2d_register_fisp =
	    &(cmd_table->ahcict_command_fis.ahcifc_fis.ahcifc_h2d_register);

	SET_FIS_TYPE(h2d_register_fisp, AHCI_H2D_REGISTER_FIS_TYPE);
	SET_FIS_PMP(h2d_register_fisp, AHCI_PORTMULT_CONTROL_PORT);

	/* Set Command Header in Command List */
	cmd_header = &ahci_portp->ahciport_cmd_list[slot];
	BZERO_DESCR_INFO(cmd_header);
	BZERO_PRD_BYTE_COUNT(cmd_header);
	SET_COMMAND_FIS_LENGTH(cmd_header, 5);

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

		if (loop_count++ > AHCI_POLLRATE_PORT_SOFTRESET) {
			/* We are effectively timing out after 0.1 sec. */
			break;
		}
		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(AHCI_10MS_TICKS);
#endif /* __lock_lint */
	} while (port_cmd_issue	& AHCI_SLOT_MASK(ahci_ctlp) & (0x1 << slot));

	AHCIDBG3(AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_software_reset: 2nd loop count: %d, "
	    "port_cmd_issue = 0x%x, slot = 0x%x",
	    loop_count, port_cmd_issue, slot);

	CLEAR_BIT(ahci_portp->ahciport_pending_tags, slot);
	ahci_portp->ahciport_slot_pkts[slot] = NULL;

	return (AHCI_SUCCESS);
}

/*
 * AHCI port reset ...; the physical communication between the HBA and device
 * on a port are disabled. This is more intrusive.
 *
 * When an HBA or port reset occurs, Phy communication shall
 * be re-established with the device through a COMRESET followed by the
 * normal out-of-band communication sequence defined in Serial ATA. AT
 * the end of reset, the device, if working properly, will send a D2H
 * Register FIS, which contains the device signature. When the HBA receives
 * this FIS, it updates PxTFD.STS and PxTFD.ERR register fields, and updates
 * the PxSIG register with the signature.
 *
 * Staggered spin-up is an optional feature in SATA II, and it enables an HBA
 * to individually spin-up attached devices. Please refer to chapter 10.9 of
 * AHCI 1.1 spec.
 */
/*
 * WARNING!!! ahciport_mutex should be acquired, intr should be disabled,
 * and PxCMD.ST and PxCMD.FRE should be also cleared before the function
 * is called.
 */
static int
ahci_port_reset(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t cap_status, port_cmd_status;
	uint32_t port_scontrol, port_sstatus;
	uint32_t port_signature, port_intr_status, port_task_file;
	int loop_count;

	AHCIDBG1(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "Port %d port resetting...", port);

	cap_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_CAP(ahci_ctlp));

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	if (cap_status & AHCI_HBA_CAP_SSS) {
		/*
		 * HBA support staggered spin-up, if the port has
		 * not spin up yet, then force it to do spin-up
		 */
		if (!(port_cmd_status & AHCI_CMD_STATUS_SUD)) {
			if (!(ahci_portp->ahciport_flags
			    & AHCI_PORT_STATE_SPINUP)) {
				AHCIDBG1(AHCIDBG_INIT, ahci_ctlp,
				    "Port %d PxCMD.SUD is zero, force "
				    "it to do spin-up", port);
				ahci_portp->ahciport_flags |=
				    AHCI_PORT_STATE_SPINUP;
			}
		}
	} else {
		/*
		 * HBA doesn't support stagger spin-up, force it
		 * to do normal COMRESET
		 */
		ASSERT(port_cmd_status & AHCI_CMD_STATUS_SUD);
		if (ahci_portp->ahciport_flags &
		    AHCI_PORT_STATE_SPINUP) {
			AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
			    "HBA does not support staggered spin-up "
			    "force it to do normal COMRESET");
			ahci_portp->ahciport_flags &=
			    ~AHCI_PORT_STATE_SPINUP;
		}
	}

	if (!(ahci_portp->ahciport_flags & AHCI_PORT_STATE_SPINUP)) {
		/* Do normal COMRESET */
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_port_reset: do normal COMRESET", port);

		ASSERT(port_cmd_status & AHCI_CMD_STATUS_SUD);

		port_scontrol = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port));
		AHCI_SCONTROL_SET_DET(port_scontrol,
		    AHCI_SCONTROL_DET_COMRESET);

		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port),
		    port_scontrol);

		/* Enable PxCMD.FRE to read device */
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
		    port_cmd_status|AHCI_CMD_STATUS_FRE);

		/* give time for COMRESET to percolate */
#ifndef __lock_lint
		delay(AHCI_1MS_TICKS*2);
#endif /* __lock_lint */

		/* Fetch the SCONTROL again and rewrite the DET part with 0 */
		port_scontrol = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port));
		AHCI_SCONTROL_SET_DET(port_scontrol,
		    AHCI_SCONTROL_DET_NOACTION);
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port),
		    port_scontrol);
	} else {
		/* Do staggered spin-up */
		port_scontrol = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port));
		AHCI_SCONTROL_SET_DET(port_scontrol,
		    AHCI_SCONTROL_DET_NOACTION);

		/* PxSCTL.DET must be 0 */
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSCTL(ahci_ctlp, port),
		    port_scontrol);

		port_cmd_status &= ~AHCI_CMD_STATUS_SUD;
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
		    port_cmd_status);

		/* 0 -> 1 edge */
#ifndef __lock_lint
		delay(AHCI_1MS_TICKS*2);
#endif /* __lock_lint */

		/* Set PxCMD.SUD to 1 */
		port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));
		port_cmd_status |= AHCI_CMD_STATUS_SUD;
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
		    port_cmd_status);

		/* Enable PxCMD.FRE to read device */
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
		    port_cmd_status|AHCI_CMD_STATUS_FRE);
	}

	/*
	 * After PxSCTL.DET is set to 0h, software should wait for
	 * communication to be re-established as indicated by bit 0
	 * of PxSSTS.DET being set to '1'.
	 */
	loop_count = 0;
	do {
		port_intr_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxIS(ahci_ctlp, port));

		if (port_intr_status & AHCI_INTR_STATUS_PCS) {
			AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
			    "COMINIT signal is received", port);
			/*
			 * Clear PxSERR.DIAG.X to update PxTFD by the D2H FIS
			 * received by HBA
			 */
			ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port),
			    AHCI_SERROR_DIAG_X);
		}

		if (loop_count++ > AHCI_POLLRATE_PORT_COMRESET) {
			/*
			 * We are effectively timing out after 0.1 sec.
			 */
			break;
		}

		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(AHCI_10MS_TICKS);
#endif /* __lock_lint */

	} while (!(port_intr_status & AHCI_INTR_STATUS_PCS));

	AHCIDBG2(AHCIDBG_INIT|AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_port_reset: 1st loop count: %d, "
	    "port_intr_status = 0x%x", loop_count, port_intr_status);

	/*
	 * The DET field is valid only if IPM field indicates
	 * that the interface is in active state.
	 */
	loop_count = 0;
	do {
		port_sstatus = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSSTS(ahci_ctlp, port));

		if (AHCI_SSTATUS_GET_IPM(port_sstatus) !=
		    AHCI_SSTATUS_IPM_INTERFACE_ACTIVE) {
			/*
			 * If the interface is not active, the DET field
			 * is considered not accurate. So we want to
			 * continue looping.
			 */
			AHCI_SSTATUS_SET_DET(port_sstatus,
			    AHCI_SSTATUS_DET_NODEV_NOPHY);
		}

		if (loop_count++ > AHCI_POLLRATE_PORT_SSTATUS) {
			/*
			 * We are effectively timing out after 0.1 sec.
			 */
			break;
		}

		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(AHCI_10MS_TICKS);
#endif /* __lock_lint */

	} while (AHCI_SSTATUS_GET_DET(port_sstatus) !=
	    AHCI_SSTATUS_DET_DEVPRESENT_PHYONLINE);

	AHCIDBG2(AHCIDBG_INIT|AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_port_reset: 2nd loop count: %d, "
	    "port_sstatus = 0x%x", loop_count, port_sstatus);

	if ((AHCI_SSTATUS_GET_IPM(port_sstatus) !=
	    AHCI_SSTATUS_IPM_INTERFACE_ACTIVE) ||
	    (AHCI_SSTATUS_GET_DET(port_sstatus) !=
	    AHCI_SSTATUS_DET_DEVPRESENT_PHYONLINE)) {
		/*
		 * Either the port is not active or there
		 * is no device present.
		 */
		ahci_portp->ahciport_device_type = SATA_DTYPE_NONE;

		(void) ahci_port_into_notrunning_state(ahci_ctlp,
		    ahci_portp, port);
	}

	if (AHCI_SSTATUS_GET_DET(port_sstatus) ==
	    AHCI_SSTATUS_DET_DEVPRESENT_PHYONLINE) {
		/*
		 * If device exist, then first check PxTFD.STS.BSY
		 */
		loop_count = 0;
		do {
			port_task_file =
			    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));

			if (loop_count++ > AHCI_POLLRATE_PORT_TFD_BSY) {
				/*
				 * We are effectively timing out after 11 sec.
				 */
				break;
			}

			port_intr_status =
			    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxIS(ahci_ctlp, port));

			if (port_intr_status & AHCI_INTR_STATUS_PCS) {
				/*
				 * Clear PxSERR.DIAG.X to update PxTFD by
				 * the D2H FIS received by HBA.
				 */
				ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
				    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp,
				    port), AHCI_SERROR_DIAG_X);
			}

			/* Wait for 10 millisec */
#ifndef __lock_lint
			delay(AHCI_10MS_TICKS);
#endif /* __lock_lint */

		} while (port_task_file & AHCI_TFD_STS_BSY);

		AHCIDBG2(AHCIDBG_INIT|AHCIDBG_POLL_LOOP, ahci_ctlp,
		    "ahci_port_reset: 3rd loop count: %d, "
		    "port_task_file = 0x%x",
		    loop_count, port_task_file);

		/*
		 * Next check COMRESET is completed successfully
		 */
		loop_count = 0;
		do {
			port_task_file =
			    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));

			if (((port_task_file & AHCI_TFD_ERR_MASK)
			    >> AHCI_TFD_ERR_SHIFT) == 0x1) {
				AHCIDBG0(AHCIDBG_INFO, ahci_ctlp,
				    "COMRESET success, D2H register FIS "
				    "post to received FIS structure");
				break;
			}

			if (loop_count++ > AHCI_POLLRATE_PORT_TFD_ERROR) {
				/*
				 * We are effectively timing out after 0.1 sec.
				 */
				break;
			}

			/* Wait for 10 millisec */
#ifndef __lock_lint
			delay(AHCI_10MS_TICKS);
#endif /* __lock_lint */

		} while (((port_task_file & AHCI_TFD_ERR_MASK)
		    >> AHCI_TFD_ERR_SHIFT) != 0x1);

		AHCIDBG2(AHCIDBG_INIT|AHCIDBG_POLL_LOOP, ahci_ctlp,
		    "ahci_port_reset: 4th loop count: %d, "
		    "port_task_file = 0x%x",
		    loop_count, port_task_file);

		port_signature = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxSIG(ahci_ctlp, port));
		AHCIDBG2(AHCIDBG_INFO, ahci_ctlp, "Port %d signature = 0x%x",
		    port, port_signature);

		/*
		 * Check device status, if keep busy or COMRESET error
		 * do device reset to patch some SATA disks' issue
		 *
		 * For VT8251, sometimes need to do the device reset
		 */
		if (port_task_file & AHCI_TFD_STS_BSY) {
			AHCIDBG1(AHCIDBG_INFO, ahci_ctlp, "port %d keep busy "
			    "need to do device reset", port);

			if (ahci_software_reset(ahci_ctlp, ahci_portp, port)
			    != AHCI_SUCCESS) {
				AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
				    "port %d device reset failed", port);
				return (AHCI_FAILURE);
			}

			port_task_file =
			    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));

			if (port_task_file & AHCI_TFD_STS_BSY) {
				AHCIDBG2(AHCIDBG_INFO, ahci_ctlp,
				    "port %d keep busy after device reset "
				    "port_task_file = 0x%x",
				    port, port_task_file);
				return (AHCI_FAILURE);
			}
		}
	}

	/* Clear port serror register for each implemented port. */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port),
	    AHCI_SERROR_CLEAR_ALL);

	return (AHCI_SUCCESS);
}

/*
 * AHCI HBA reset ...; the entire HBA is reset, and all ports are disabled.
 * This is the most intrusive.
 *
 * When an HBA reset occurs, Phy communication shall
 * be re-established with the device through a COMRESET followed by the
 * normal out-of-band communication sequence defined in Serial ATA. AT
 * the end of reset, the device, if working properly, will send a D2H
 * Register FIS, which contains the device signature. When the HBA receives
 * this FIS, it updates PxTFD.STS and PxTFD.ERR register fields, and updates
 * the PxSIG register with the signature.
 *
 * Remember to set GHC.AE to 1 before calling ahci_hba_reset.
 *
 * WARNING!!! ahcictl_mutex should be already held before the function
 * is called.
 */
static int
ahci_hba_reset(ahci_ctl_t *ahci_ctlp)
{
	ahci_port_t *ahci_portp;
	uint32_t ghc_control;
	uint8_t port;
	int loop_count;
	int rval = AHCI_SUCCESS;

	AHCIDBG0(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp, "HBA resetting");

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
			AHCIDBG1(AHCIDBG_INIT, ahci_ctlp,
			    "ahci hba reset is timing out, "
			    "ghc_control = 0x%x", ghc_control);
			/* We are effectively timing out after 1 sec. */
			break;
		}

		/* Wait for 10 millisec */
#ifndef __lock_lint
		delay(AHCI_10MS_TICKS);
#endif /* __lock_lint */

	} while (ghc_control & AHCI_HBA_GHC_HR);

	AHCIDBG2(AHCIDBG_INIT|AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_hba_reset: 1st loop count: %d, "
	    "ghc_control = 0x%x", loop_count, ghc_control);

	if (ghc_control & AHCI_HBA_GHC_HR) {
		/* The hba is not reset for some reasons */
		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
		    "hba reset failed: HBA in a hung or locked state");
		return (AHCI_FAILURE);
	}

	for (port = 0; port < ahci_ctlp->ahcictl_num_ports; port++) {
		/* Only check implemented ports */
		if (!AHCI_PORT_IMPLEMENTED(ahci_ctlp, port)) {
			continue;
		}

		ahci_portp = ahci_ctlp->ahcictl_ports[port];
		mutex_enter(&ahci_portp->ahciport_mutex);

		if (ahci_port_reset(ahci_ctlp, ahci_portp, port)
		    != AHCI_SUCCESS) {
			ahci_portp->ahciport_port_state = SATA_PSTATE_FAILED;
			rval = AHCI_FAILURE;
			AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
			    "ahci_hba_reset: port %d failed", port);
		}

		mutex_exit(&ahci_portp->ahciport_mutex);
	}

	/*
	 * Indicate that system software is AHCI aware by setting
	 * GHC.AE to 1
	 */
	ghc_control = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp));

	ghc_control |= AHCI_HBA_GHC_AE;
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp), ghc_control);

	return (rval);
}

/*
 * This routine is only called from AHCI_ATTACH or phyrdy change
 * case. It first calls port reset to initialize port, probe port and probe
 * device, then read PxSIG register to find the type of device attached to
 * the port.
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
static int
ahci_find_dev_signature(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t signature;
	int ret = AHCI_SUCCESS;

	AHCIDBG1(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "port %d: ahci_find_dev_signature enter", port);

	ahci_disable_port_intrs(ahci_ctlp, ahci_portp, port);

	/* Call port reset to check link status and get device signature */
	if (ahci_port_reset(ahci_ctlp, ahci_portp, port) != AHCI_SUCCESS) {
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_find_dev_signature failed for port %d: ", port);
		ahci_enable_port_intrs(ahci_ctlp, ahci_portp, port);
		return (AHCI_FAILURE);
	}

	ahci_enable_port_intrs(ahci_ctlp, ahci_portp, port);

	signature = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSIG(ahci_ctlp, port));

	AHCIDBG2(AHCIDBG_INIT|AHCIDBG_INFO, ahci_ctlp,
	    "port %d signature = 0x%x", port, signature);

	switch (signature) {

	case AHCI_SIGNATURE_DISK:
		ahci_portp->ahciport_device_type = SATA_DTYPE_ATADISK;
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "Disk is found at port: %d", port);
		break;

	case AHCI_SIGNATURE_ATAPI:
		ahci_portp->ahciport_device_type = SATA_DTYPE_ATAPICD;
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "ATAPI device is found at port: %d", port);
		break;

	case AHCI_SIGNATURE_PORT_MULTIPLIER:
		ahci_portp->ahciport_device_type = SATA_DTYPE_PMULT;
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "Port Multiplier is found at port: %d", port);
		break;

	case AHCI_SIGNATURE_NONE:
		ahci_portp->ahciport_device_type = SATA_DTYPE_NONE;
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "No device is found at port: %d", port);
		break;

	default:
		ahci_portp->ahciport_device_type = SATA_DTYPE_UNKNOWN;
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "Unknown device is found at port: %d", port);
	}

	return (ret);
}

/*
 * Try to start the port - set PxCMD.ST to 1, if PxCMD.FRE is not set
 * to 1, then set it.
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
static int
ahci_start_port(ahci_ctl_t *ahci_ctlp, uint8_t port)
{
	uint32_t port_task_file, port_cmd_status;

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_start_port: %d enter", port);

	port_task_file = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));

	if (port_task_file & AHCI_TFD_STS_BSY ||
	    port_task_file & AHCI_TFD_STS_DRQ) {

		AHCIDBG2(AHCIDBG_INIT|AHCIDBG_INFO, ahci_ctlp,
		    "Port %d cannot start!!! port_task_file = 0x%x",
		    port, port_task_file);
		return (AHCI_FAILURE);

	} else {
		AHCIDBG2(AHCIDBG_INIT|AHCIDBG_INFO, ahci_ctlp,
		    "Port %d start!!! port_task_file = 0x%x",
		    port, port_task_file);

		/* First to set PxCMD.FRE before setting PxCMD.ST. */
		port_cmd_status =
		    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

		if (!(port_cmd_status & AHCI_CMD_STATUS_FRE)) {
			port_cmd_status |= AHCI_CMD_STATUS_FRE;
			ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
			    port_cmd_status);
		}

		port_cmd_status =
		    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

		port_cmd_status |= AHCI_CMD_STATUS_ST;

		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
		    port_cmd_status);

		return (AHCI_SUCCESS);
	}
}

/*
 * Allocate the ahci_port_t including Received FIS and Command List.
 * The argument - port is the physical port number, and not logical
 * port number seen by the SATA framework.
 *
 * WARNING!!! ahcictl_mutex should be acquired before the function
 * is called.
 */
static int
ahci_alloc_port_state(ahci_ctl_t *ahci_ctlp, uint8_t port)
{
	ahci_port_t *ahci_portp;

	ahci_portp =
	    (ahci_port_t *)kmem_zalloc(sizeof (ahci_port_t), KM_SLEEP);

#ifndef __lock_lint
	ahci_ctlp->ahcictl_ports[port] = ahci_portp;
#endif /* __lock_lint */

	ahci_portp->ahciport_port_num = port;

	mutex_init(&ahci_portp->ahciport_mutex, NULL, MUTEX_DRIVER,
	    (void *)(uintptr_t)ahci_ctlp->ahcictl_intr_pri);
	mutex_enter(&ahci_portp->ahciport_mutex);

	/*
	 * Allocate memory for received FIS structure and
	 * command list for this port
	 */
	if (ahci_alloc_rcvd_fis(ahci_ctlp, ahci_portp, port) != AHCI_SUCCESS) {
		goto err_case1;
	}

	if (ahci_alloc_cmd_list(ahci_ctlp, ahci_portp, port) != AHCI_SUCCESS) {
		goto err_case2;
	}

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);

err_case2:
	ahci_dealloc_rcvd_fis(ahci_ctlp, ahci_portp);

err_case1:
	mutex_exit(&ahci_portp->ahciport_mutex);

	mutex_destroy(&ahci_portp->ahciport_mutex);

	kmem_free(ahci_portp, sizeof (ahci_port_t));

	return (AHCI_FAILURE);
}

/*
 * Reverse of ahci_dealloc_port_state().
 *
 * WARNING!!! ahcictl_mutex should be acquired before the function
 * is called.
 */
static void
ahci_dealloc_port_state(ahci_ctl_t *ahci_ctlp, uint8_t port)
{
	ahci_port_t *ahci_portp = ahci_ctlp->ahcictl_ports[port];

	ASSERT(ahci_portp != NULL);

	mutex_enter(&ahci_portp->ahciport_mutex);
	ahci_dealloc_cmd_list(ahci_ctlp, ahci_portp);
	ahci_dealloc_rcvd_fis(ahci_ctlp, ahci_portp);
	mutex_exit(&ahci_portp->ahciport_mutex);

	mutex_destroy(&ahci_portp->ahciport_mutex);

	kmem_free(ahci_portp, sizeof (ahci_port_t));

#ifndef __lock_lint
	ahci_ctlp->ahcictl_ports[port] = NULL;
#endif /* __lock_lint */
}

/*
 * Allocates memory for the Received FIS Structure
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
static int
ahci_alloc_rcvd_fis(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    uint8_t port)
{
	size_t rcvd_fis_size;
	size_t ret_len;
	ddi_dma_cookie_t rcvd_fis_dma_cookie;
	uint_t cookie_count;
	uint32_t cap_status;

	rcvd_fis_size = sizeof (ahci_rcvd_fis_t);

	/* Check whether the HBA can access 64-bit data structures */
	cap_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_CAP(ahci_ctlp));

	ahci_ctlp->ahcictl_rcvd_fis_dma_attr = rcvd_fis_dma_attr;

	/*
	 * If 64-bit addressing is not supported,
	 * change dma_attr_addr_hi of ahcictl_rcvd_fis_dma_attr
	 */
	if (!(cap_status & AHCI_HBA_CAP_S64A)) {
		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
		    "hba does not support 64-bit addressing");
		ahci_ctlp->ahcictl_rcvd_fis_dma_attr.dma_attr_addr_hi =
		    0xffffffffull;
	}

	/* allocate rcvd FIS dma handle. */
	if (ddi_dma_alloc_handle(ahci_ctlp->ahcictl_dip,
	    &ahci_ctlp->ahcictl_rcvd_fis_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &ahci_portp->ahciport_rcvd_fis_dma_handle) !=
	    DDI_SUCCESS) {
		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
		    "rcvd FIS dma handle alloc failed");

		return (AHCI_FAILURE);
	}

	if (ddi_dma_mem_alloc(ahci_portp->ahciport_rcvd_fis_dma_handle,
	    rcvd_fis_size,
	    &accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    (caddr_t *)&ahci_portp->ahciport_rcvd_fis,
	    &ret_len,
	    &ahci_portp->ahciport_rcvd_fis_acc_handle) != NULL) {

		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
		    "rcvd FIS dma mem alloc fail");
		/* error.. free the dma handle. */
		ddi_dma_free_handle(&ahci_portp->ahciport_rcvd_fis_dma_handle);
		return (AHCI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(ahci_portp->ahciport_rcvd_fis_dma_handle,
	    NULL,
	    (caddr_t)ahci_portp->ahciport_rcvd_fis,
	    rcvd_fis_size,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &rcvd_fis_dma_cookie,
	    &cookie_count) !=  DDI_DMA_MAPPED) {

		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
		    "rcvd FIS dma handle bind fail");
		/*  error.. free the dma handle & free the memory. */
		ddi_dma_mem_free(&ahci_portp->ahciport_rcvd_fis_acc_handle);
		ddi_dma_free_handle(&ahci_portp->ahciport_rcvd_fis_dma_handle);
		return (AHCI_FAILURE);
	}

	bzero((void *)ahci_portp->ahciport_rcvd_fis, rcvd_fis_size);

	/* Config Port Received FIS Base Address */
	ddi_put64(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint64_t *)AHCI_PORT_PxFB(ahci_ctlp, port),
	    rcvd_fis_dma_cookie.dmac_laddress);

	AHCIDBG1(AHCIDBG_INIT, ahci_ctlp, "64-bit, dma address: 0x%llx",
	    rcvd_fis_dma_cookie.dmac_laddress);
	AHCIDBG1(AHCIDBG_INIT, ahci_ctlp, "32-bit, dma address: 0x%x",
	    rcvd_fis_dma_cookie.dmac_address);

	return (AHCI_SUCCESS);
}

/*
 * Deallocates the Received FIS Structure
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
static void
ahci_dealloc_rcvd_fis(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_dealloc_rcvd_fis: port %d enter",
	    ahci_portp->ahciport_port_num);

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
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
static int
ahci_alloc_cmd_list(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    uint8_t port)
{
	size_t cmd_list_size;
	size_t ret_len;
	ddi_dma_cookie_t cmd_list_dma_cookie;
	uint_t cookie_count;
	uint32_t cap_status;

	cmd_list_size =
	    ahci_ctlp->ahcictl_num_cmd_slots * sizeof (ahci_cmd_header_t);

	cap_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_CAP(ahci_ctlp));

	ahci_ctlp->ahcictl_cmd_list_dma_attr = cmd_list_dma_attr;

	/*
	 * If 64-bit addressing is not supported,
	 * change dma_attr_addr_hi of ahcictl_cmd_list_dma_attr
	 */
	if (!(cap_status & AHCI_HBA_CAP_S64A)) {
		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
		    "hba does not support 64-bit addressing");
		ahci_ctlp->ahcictl_cmd_list_dma_attr.dma_attr_addr_hi =
		    0xffffffffull;
	}

	/* allocate cmd list dma handle. */
	if (ddi_dma_alloc_handle(ahci_ctlp->ahcictl_dip,
	    &ahci_ctlp->ahcictl_cmd_list_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL,
	    &ahci_portp->ahciport_cmd_list_dma_handle) != DDI_SUCCESS) {

		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
		    "cmd list dma handle alloc failed");
		return (AHCI_FAILURE);
	}

	if (ddi_dma_mem_alloc(ahci_portp->ahciport_cmd_list_dma_handle,
	    cmd_list_size,
	    &accattr,
	    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    (caddr_t *)&ahci_portp->ahciport_cmd_list,
	    &ret_len,
	    &ahci_portp->ahciport_cmd_list_acc_handle) != NULL) {

		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
		    "cmd list dma mem alloc fail");
		/* error.. free the dma handle. */
		ddi_dma_free_handle(&ahci_portp->ahciport_cmd_list_dma_handle);
		return (AHCI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(ahci_portp->ahciport_cmd_list_dma_handle,
	    NULL,
	    (caddr_t)ahci_portp->ahciport_cmd_list,
	    cmd_list_size,
	    DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP,
	    NULL,
	    &cmd_list_dma_cookie,
	    &cookie_count) !=  DDI_DMA_MAPPED) {

		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
		    "cmd list dma handle bind fail");
		/*  error.. free the dma handle & free the memory. */
		ddi_dma_mem_free(&ahci_portp->ahciport_cmd_list_acc_handle);
		ddi_dma_free_handle(&ahci_portp->ahciport_cmd_list_dma_handle);
		return (AHCI_FAILURE);
	}

	bzero((void *)ahci_portp->ahciport_cmd_list, cmd_list_size);

	/* Config Port Command List Base Address */
	ddi_put64(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint64_t *)AHCI_PORT_PxCLB(ahci_ctlp, port),
	    cmd_list_dma_cookie.dmac_laddress);

	AHCIDBG1(AHCIDBG_INIT, ahci_ctlp, "64-bit, dma address: 0x%llx",
	    cmd_list_dma_cookie.dmac_laddress);

	AHCIDBG1(AHCIDBG_INIT, ahci_ctlp, "32-bit, dma address: 0x%x",
	    cmd_list_dma_cookie.dmac_address);

	if (ahci_alloc_cmd_tables(ahci_ctlp, ahci_portp) != AHCI_SUCCESS) {
		ahci_dealloc_cmd_list(ahci_ctlp, ahci_portp);
		return (AHCI_FAILURE);
	}

	return (AHCI_SUCCESS);
}

/*
 * Deallocates the Command List
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
static void
ahci_dealloc_cmd_list(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
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
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
static int
ahci_alloc_cmd_tables(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
	size_t ret_len;
	ddi_dma_cookie_t cmd_table_dma_cookie;
	uint_t cookie_count;
	uint32_t cap_status;
	int slot;

	AHCIDBG1(AHCIDBG_INIT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_alloc_cmd_tables: port %d enter",
	    ahci_portp->ahciport_port_num);

	/* Check whether the HBA can access 64-bit data structures */
	cap_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_CAP(ahci_ctlp));

	ahci_ctlp->ahcictl_cmd_table_dma_attr = cmd_table_dma_attr;

	/*
	 * If 64-bit addressing is not supported,
	 * change dma_attr_addr_hi of ahcictl_cmd_table_dma_attr
	 */
	if (!(cap_status & AHCI_HBA_CAP_S64A)) {
		AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
		    "hba does not support 64-bit addressing");
		ahci_ctlp->ahcictl_cmd_table_dma_attr.dma_attr_addr_hi =
		    0xffffffffull;
	}

	for (slot = 0; slot < ahci_ctlp->ahcictl_num_cmd_slots; slot++) {
		/* Allocate cmd table dma handle. */
		if (ddi_dma_alloc_handle(ahci_ctlp->ahcictl_dip,
		    &ahci_ctlp->ahcictl_cmd_table_dma_attr,
		    DDI_DMA_SLEEP,
		    NULL,
		    &ahci_portp->ahciport_cmd_tables_dma_handle[slot]) !=
		    DDI_SUCCESS) {

			AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
			    "cmd table dma handle alloc failed");

			goto err_out;
		}

		if (ddi_dma_mem_alloc(
		    ahci_portp->ahciport_cmd_tables_dma_handle[slot],
		    ahci_cmd_table_size,
		    &accattr,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP,
		    NULL,
		    (caddr_t *)&ahci_portp->ahciport_cmd_tables[slot],
		    &ret_len,
		    &ahci_portp->ahciport_cmd_tables_acc_handle[slot]) !=
		    NULL) {

			AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
			    "cmd table dma mem alloc fail");

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
		    DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP,
		    NULL,
		    &cmd_table_dma_cookie,
		    &cookie_count) !=  DDI_DMA_MAPPED) {

			AHCIDBG0(AHCIDBG_INIT, ahci_ctlp,
			    "cmd table dma handle bind fail");
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
#endif /* __lock_lint */
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
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
static void
ahci_dealloc_cmd_tables(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp)
{
	int slot;

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
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
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
static void
ahci_update_sata_registers(ahci_ctl_t *ahci_ctlp, uint8_t port,
    sata_device_t *sd)
{
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
 * Set the auto sense data for ATAPI devices.
 *
 * Note: Currently the sense data is simulated; this code will be enhanced
 * in second phase to fetch the real sense data from the atapi device.
 */
static void
ahci_set_sense_data(sata_pkt_t *satapkt, int reason)
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
 * Interrupt service handler
 */
/* ARGSUSED1 */
static uint_t
ahci_intr(caddr_t arg1, caddr_t arg2)
{
	ahci_ctl_t *ahci_ctlp = (ahci_ctl_t *)arg1;
	ahci_port_t *ahci_portp;
	int32_t global_intr_status, port_intr_status;
	int32_t port_intr_enable;
	uint8_t port;

	/*
	 * global_intr_status indicates that the corresponding port has
	 * an interrupt pending.
	 */
	global_intr_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_IS(ahci_ctlp));

	AHCIDBG1(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr enter: global_intr_status = 0x%x", global_intr_status);

	if (!(global_intr_status & ahci_ctlp->ahcictl_ports_implemented)) {
		/* The interrupt is not ours */
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

		/*
		 * port_intr_stats indicates that the corresponding interrupt
		 * condition is active.
		 */
		port_intr_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxIS(ahci_ctlp, port));

		/*
		 * port_intr_enable indicates that the corresponding interrrupt
		 * reporting is enabled.
		 */
		port_intr_enable = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxIE(ahci_ctlp, port));

		AHCIDBG3(AHCIDBG_INTR, ahci_ctlp,
		    "ahci_intr: port %d, port_intr_status = 0x%x, "
		    "port_intr_enable = 0x%x", port,
		    port_intr_status, port_intr_enable);

		port_intr_status &= port_intr_enable;

		/* First clear the port interrupts status */
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxIS(ahci_ctlp, port),
		    port_intr_status);

		if (port_intr_status & AHCI_INTR_STATUS_DHRS) {
			(void) ahci_intr_d2h_register_fis(ahci_ctlp, ahci_portp,
			    port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_PSS) {
			(void) ahci_intr_pio_setup_fis(ahci_ctlp, ahci_portp,
			    port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_DSS) {
			(void) ahci_intr_dma_setup_fis(ahci_ctlp, ahci_portp,
			    port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_SDBS) {
			(void) ahci_intr_set_device_bits_fis(ahci_ctlp,
			    ahci_portp, port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_UFS) {
			(void) ahci_intr_unknown_fis(ahci_ctlp, ahci_portp,
			    port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_DPS) {
			(void) ahci_intr_descriptor_processed(ahci_ctlp,
			    ahci_portp, port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_PCS) {
			(void) ahci_intr_port_connect_change(ahci_ctlp,
			    ahci_portp, port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_DMPS) {
			(void) ahci_intr_device_mechanical_presence_status(
			    ahci_ctlp, ahci_portp, port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_PRCS) {
			(void) ahci_intr_phyrdy_change(ahci_ctlp, ahci_portp,
			    port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_IPMS) {
			(void) ahci_intr_incorrect_port_multiplier(ahci_ctlp,
			    ahci_portp, port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_OFS) {
			(void) ahci_intr_overflow(ahci_ctlp, ahci_portp, port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_INFS) {
			(void) ahci_intr_interface_non_fatal_error(ahci_ctlp,
			    ahci_portp, port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_IFS) {
			(void) ahci_intr_interface_fatal_error(ahci_ctlp,
			    ahci_portp, port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_HBDS) {
			(void) ahci_intr_host_bus_data_error(ahci_ctlp,
			    ahci_portp, port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_HBFS) {
			(void) ahci_intr_host_bus_fatal_error(ahci_ctlp,
			    ahci_portp, port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_TFES) {
			(void) ahci_intr_task_file_error(ahci_ctlp, ahci_portp,
			    port);
		}

		if (port_intr_status & AHCI_INTR_STATUS_CPDS) {
			(void) ahci_intr_cold_port_detect(ahci_ctlp,
			    ahci_portp, port);
		}

		/* Second clear the corresponding bit in IS.IPS */
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_GLOBAL_IS(ahci_ctlp), (0x1 << port));
	}

	return (DDI_INTR_CLAIMED);
}

/*
 * A D2H Register FIS has been received with the 'I' bit set.
 *
 * The following commands will send this FIS upon the successful completion:
 * 	1. Non-data commands
 * 	2. DMA data-in command
 * 	3. DMA data-out command
 * 	4. PIO data-out command
 */
static int
ahci_intr_d2h_register_fis(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_cmd_issue;
	uint32_t finished_tags;
	int finished_slot, i, num = 0;
	sata_pkt_t *satapkt;
	ahci_fis_d2h_register_t *rcvd_fisp;

	AHCIDBG1(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_d2h_register_fis enter, port %d", port);

	mutex_enter(&ahci_portp->ahciport_mutex);

	port_cmd_issue = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

	if (!ahci_portp->ahciport_pending_tags) {
		/*
		 * Spurious interrupt. Nothing to be done.
		 */
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_SUCCESS);
	}

	finished_tags = ahci_portp->ahciport_pending_tags &
	    ~port_cmd_issue & AHCI_SLOT_MASK(ahci_ctlp);

	AHCIDBG3(AHCIDBG_INTR, ahci_ctlp,
	    "ahci_intr_d2h_reigster_fis: pending_tags = 0x%x, "
	    "port_cmd_issue = 0x%x, finished_tags = 0x%x,",
	    ahci_portp->ahciport_pending_tags, port_cmd_issue,
	    finished_tags);

	for (i = 0; i < ahci_ctlp->ahcictl_num_cmd_slots; i++) {
		if ((0x1 << i) & finished_tags)
			num++;
	}

	ASSERT(num <= 1);

	finished_slot = ddi_ffs(finished_tags) - 1;
	if (finished_slot == -1) {
		goto out;
	}

	satapkt = ahci_portp->ahciport_slot_pkts[finished_slot];
	ASSERT(satapkt != NULL);

	/*
	 * In case the interrupt generates before disabling for poll commands.
	 */
	if (satapkt->satapkt_op_mode &
	    (SATA_OPMODE_POLLING | SATA_OPMODE_SYNCH)) {
		goto out;
	}

	rcvd_fisp = &(ahci_portp->ahciport_rcvd_fis->ahcirf_d2h_register_fis);

	/* Return the status */
	satapkt->satapkt_cmd.satacmd_status_reg = GET_RFIS_STATUS(rcvd_fisp);

	if (satapkt->satapkt_cmd.satacmd_flags.sata_special_regs)
		ahci_copy_out_regs(&satapkt->satapkt_cmd, rcvd_fisp);

	AHCIDBG1(AHCIDBG_INTR, ahci_ctlp,
	    "ahci_intr_d2h_register_fis: sending up pkt 0x%p "
	    "with SATA_PKT_COMPLETED", (void *)satapkt);

	CLEAR_BIT(ahci_portp->ahciport_pending_tags, finished_slot);
	ahci_portp->ahciport_slot_pkts[finished_slot] = NULL;

	SENDUP_PACKET(ahci_portp, satapkt, SATA_PKT_COMPLETED);
out:
	AHCIDBG1(AHCIDBG_PKTCOMP, ahci_ctlp,
	    "ahci_intr_d2h_register_fis pending_tags = 0x%x",
	    ahci_portp->ahciport_pending_tags);

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * A PIO Setup FIS has been received with the 'I' bit set.
 *
 * The following commands will send this FIS upon the successful completion:
 * 	PIO data-in command
 */
static int
ahci_intr_pio_setup_fis(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_cmd_issue;
	uint32_t finished_tags;
	int finished_slot, i, num = 0;
	sata_pkt_t *satapkt;
	ahci_fis_d2h_register_t *rcvd_fisp;

	AHCIDBG1(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_pio_setup_fis enter, port %d", port);

	mutex_enter(&ahci_portp->ahciport_mutex);

	port_cmd_issue = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

	if (!ahci_portp->ahciport_pending_tags) {
		/*
		 * Spurious interrupt. Nothing to be done.
		 */
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_SUCCESS);
	}

	finished_tags = ahci_portp->ahciport_pending_tags &
	    ~port_cmd_issue & AHCI_SLOT_MASK(ahci_ctlp);

	AHCIDBG3(AHCIDBG_INTR, ahci_ctlp,
	    "ahci_intr_pio_setup_fis: pending_tags = 0x%x, "
	    "port_cmd_issue = 0x%x, finished_tags = 0x%x,",
	    ahci_portp->ahciport_pending_tags, port_cmd_issue,
	    finished_tags);

	for (i = 0; i < ahci_ctlp->ahcictl_num_cmd_slots; i++) {
		if ((0x1 << i) & finished_tags)
			num++;
	}

	ASSERT(num <= 1);

	finished_slot = ddi_ffs(finished_tags) - 1;
	if (finished_slot == -1) {
		goto out;
	}

	satapkt = ahci_portp->ahciport_slot_pkts[finished_slot];
	ASSERT(satapkt != NULL);

	/*
	 * In case the interrupt generates before disabling.
	 */
	if (satapkt->satapkt_op_mode &
	    (SATA_OPMODE_POLLING | SATA_OPMODE_SYNCH)) {
		goto out;
	}

	rcvd_fisp = &(ahci_portp->ahciport_rcvd_fis->ahcirf_d2h_register_fis);

	/* Return the status */
	satapkt->satapkt_cmd.satacmd_status_reg = GET_RFIS_STATUS(rcvd_fisp);

	if (satapkt->satapkt_cmd.satacmd_flags.sata_special_regs)
		ahci_copy_out_regs(&satapkt->satapkt_cmd, rcvd_fisp);

	AHCIDBG1(AHCIDBG_INTR, ahci_ctlp,
	    "ahci_intr_pio_setup_fis: sending up pkt 0x%p "
	    "with SATA_PKT_COMPLETED", (void *)satapkt);

	CLEAR_BIT(ahci_portp->ahciport_pending_tags, finished_slot);
	ahci_portp->ahciport_slot_pkts[finished_slot] = NULL;

	SENDUP_PACKET(ahci_portp, satapkt, SATA_PKT_COMPLETED);
out:
	AHCIDBG1(AHCIDBG_PKTCOMP, ahci_ctlp,
	    "ahci_intr_pio_setup_fis pending_tags = 0x%x",
	    ahci_portp->ahciport_pending_tags);

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * A DMA Setup FIS has been received with the 'I' bit set
 *
 * DMA Setup FIS will be used during NCQ transfers to activate data
 * transfer.
 *
 * For the first phase, this interrupt is disabled and we just
 * log a debug message.
 */
/* ARGSUSED */
static int
ahci_intr_dma_setup_fis(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	AHCIDBG1(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_dma_setup_fis enter, port %d", port);

	return (AHCI_SUCCESS);
}

/*
 * A Set Device Bits FIS has been received with the 'I' bit set
 *
 * Set Device Bits FIS will be sent during NCQ completion.
 *
 * For the first phase, this interrupt is disabled and we just log
 * the debug message.
 */
/* ARGSUSED */
static int
ahci_intr_set_device_bits_fis(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	AHCIDBG1(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_set_device_bits_fis enter, port %d", port);

	return (AHCI_SUCCESS);
}

/*
 * An unknown FIS was received and has been copied into system memory.
 *
 * An unknown FIS is not considered an illegal FIS, unless the length
 * received is more than 64 bytes. If an unknown FIS arrives with length
 * <= 64 bytes, it is posted and the HBA continues normal operation.
 *
 * Therefore we just need to clear PxSERR.DIAG.F to clear the intr bit
 * and log the debug message.
 */
static int
ahci_intr_unknown_fis(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_serror;

	mutex_enter(&ahci_portp->ahciport_mutex);

	port_serror = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port));

	AHCIDBG2(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_unknown_fis: port %d, port_serror = 0x%x",
	    port, port_serror);

	/* Clear the interrupt bit by clearing PxSERR.DIAG.F */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port),
	    AHCI_SERROR_DIAG_F);

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * A PRD with the 'I' bit set has tranfered all of its data.
 *
 * The PRD Interrupt is an opportunistic interrupt. And it should not
 * be used to definitively indicate the end of a transfer since two
 * PRD interrupts could happen close in time together such that the
 * second interrupt is missed when the first PRD interrupt is being
 * cleared.
 *
 * For the first phase, this interrupt is disabled and we just
 * log the debug message.
 */
/* ARGSUSED */
static int
ahci_intr_descriptor_processed(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	AHCIDBG1(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_descriptor_processed enter, port %d", port);

	return (AHCI_SUCCESS);
}

/*
 * 1=Change in Current Connect Status. 0=No change in Current Connect Status.
 * This bit reflects the state of PxSERR.DIAG.X. This bit is only cleared
 * when PxSERR.DIAG.X is cleared.
 *
 * When PxSERR.DIAG.X is set to one, it indicates a COMINIT signal was received.
 *
 * For the first phase, this interrupt is disabled.
 */
static int
ahci_intr_port_connect_change(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_serror, port_cmd_status;

	mutex_enter(&ahci_portp->ahciport_mutex);

	port_serror = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port));

	AHCIDBG2(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_port_connect_change: port %d, "
	    "port_serror = 0x%x", port, port_serror);

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	AHCIDBG2(AHCIDBG_INTR, ahci_ctlp,
	    "ahci_intr_port_connect_change: port %d, "
	    "port_command_status = 0x%x", port, port_cmd_status);

	/* Clear PxSERR.DIAG.X to clear the interrupt bit */
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port),
	    AHCI_SERROR_DIAG_X);

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
 * For the first phase, this interrupt is disabled and we just log
 * the debug message.
 */
/* ARGSUSED */
static int
ahci_intr_device_mechanical_presence_status(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t cap_status, port_cmd_status;

	AHCIDBG1(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_device_mechanical_presence_status enter, "
	    "port %d", port);

	cap_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_CAP(ahci_ctlp));

	mutex_enter(&ahci_portp->ahciport_mutex);
	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	if (!(cap_status & AHCI_HBA_CAP_SMPS) ||
	    !(port_cmd_status & AHCI_CMD_STATUS_MPSP)) {
		AHCIDBG2(AHCIDBG_INTR, ahci_ctlp,
		    "CAP.SMPS or PxCMD.MPSP is not set, so just ignore "
		    "the interrupt: cap_status = 0x%x, "
		    "port_cmd_status = 0x%x", cap_status, port_cmd_status);
		mutex_exit(&ahci_portp->ahciport_mutex);

		return (AHCI_SUCCESS);
	}

	if (port_cmd_status & AHCI_CMD_STATUS_MPSS) {
		AHCIDBG2(AHCIDBG_INTR, ahci_ctlp,
		    "The mechanical presence switch is open: "
		    "port %d, port_cmd_status = 0x%x",
		    port, port_cmd_status);
	} else {
		AHCIDBG2(AHCIDBG_INTR, ahci_ctlp,
		    "The mechanical presence switch is close: "
		    "port %d, port_cmd_status = 0x%x",
		    port, port_cmd_status);
	}

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * Native Hot Plug Support.
 *
 * When set, it indicates that the internal PHYRDY signal changed state.
 * This bit reflects the state of PxSERR.DIAG.N.
 */
static int
ahci_intr_phyrdy_change(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_sstatus = 0; /* No dev present & PHY not established. */
	sata_device_t sdevice;
	int dev_exists_now = 0;
	int dev_existed_previously = 0;

	AHCIDBG1(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_phyrdy_change enter, port %d", port);

	/* Clear PxSERR.DIAG.N to clear the interrupt bit */
	mutex_enter(&ahci_portp->ahciport_mutex);
	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port),
	    AHCI_SERROR_DIAG_N);
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

	dev_exists_now = (AHCI_SSTATUS_GET_DET(port_sstatus) ==
	    AHCI_SSTATUS_DET_DEVPRESENT_PHYONLINE);

	if (ahci_portp->ahciport_device_type != SATA_DTYPE_NONE) {
		dev_existed_previously = 1;
	}

	bzero((void *)&sdevice, sizeof (sata_device_t));
	sdevice.satadev_addr.cport = ahci_ctlp->ahcictl_port_to_cport[port];
	sdevice.satadev_addr.qual = SATA_ADDR_CPORT;
	sdevice.satadev_addr.pmport = 0;
	sdevice.satadev_state = SATA_PSTATE_PWRON;
	ahci_portp->ahciport_port_state = SATA_PSTATE_PWRON;

	if (dev_exists_now) {
		if (dev_existed_previously) {
			/* Things are fine now. The loss was temporary. */
			cmn_err(CE_NOTE, "!ahci phyrdy: port %d "
			    "device link lost/established", port);

			mutex_exit(&ahci_portp->ahciport_mutex);
			sata_hba_event_notify(
			    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
			    &sdevice,
			    SATA_EVNT_LINK_LOST|SATA_EVNT_LINK_ESTABLISHED);
			mutex_enter(&ahci_portp->ahciport_mutex);

		} else {
			cmn_err(CE_NOTE, "!ahci phyrdy: port %d "
			    "device link established", port);

			/* A new device has been detected. */
			if (ahci_find_dev_signature(ahci_ctlp, ahci_portp, port)
			    != AHCI_SUCCESS) {
				ahci_portp->ahciport_port_state =
				    SATA_PSTATE_FAILED;
				AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
				    "phyrdy: port %d failed "
				    "at find dev signature", port);
			}

			if ((ahci_portp->ahciport_device_type
			    == SATA_DTYPE_ATADISK) &&
			    (ahci_start_port(ahci_ctlp, port)
			    != AHCI_SUCCESS)) {
				ahci_portp->ahciport_port_state =
				    SATA_PSTATE_FAILED;
				AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
				    "phyrdy: port %d failed "
				    "at start port", port);
			}

			mutex_exit(&ahci_portp->ahciport_mutex);
			sata_hba_event_notify(
			    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
			    &sdevice,
			    SATA_EVNT_LINK_ESTABLISHED);
			mutex_enter(&ahci_portp->ahciport_mutex);

		}
	} else { /* No device exists now */

		if (dev_existed_previously) {

			cmn_err(CE_NOTE, "!ahci phyrdy: port %d "
			    "device link lost", port);

			ahci_reject_all_abort_pkts(ahci_ctlp, ahci_portp, port);
			(void) ahci_port_into_notrunning_state(ahci_ctlp,
			    ahci_portp, port);

			/* An existing device is lost. */
			ahci_portp->ahciport_device_type = SATA_DTYPE_NONE;

			mutex_exit(&ahci_portp->ahciport_mutex);
			sata_hba_event_notify(
			    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
			    &sdevice,
			    SATA_EVNT_LINK_LOST);
			mutex_enter(&ahci_portp->ahciport_mutex);

		} else {

			/* Spurious interrupt */
			AHCIDBG0(AHCIDBG_INTR, ahci_ctlp,
			    "spurious phy ready interrupt");
		}
	}

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * PxIS.IPMS - Port Multiplier Errors.
 *
 * Which indicates that the HBA received a FIS from a device whose Port
 * Multiplier field did not match what was expected.
 *
 * For the first phase, this interrupt is disabled, and we just log
 * the debug message.
 */
/* ARGSUSED */
static int
ahci_intr_incorrect_port_multiplier(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	AHCIDBG1(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_incorrect_port_multiplier enter, port %d", port);

	return (AHCI_SUCCESS);
}

/*
 * PxIS.OFS - Fatal Error
 *
 * Which indicates that the HBA received more bytes from a device than
 * was specified in the PRD table for the command.
 *
 * Overflow is a serious error, thus software should perform a fatal error
 * recovery procedure to ensure that the HBA is brought back to a known
 * condition before continuing.
 */
static int
ahci_intr_overflow(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	AHCIDBG1(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_overflow enter, port %d", port);

	mutex_enter(&ahci_portp->ahciport_mutex);

	cmn_err(CE_NOTE, "!ahci port %d has overflow error", port);

	(void) ahci_recovery_fatal_error(ahci_ctlp, ahci_portp,
	    port, AHCI_INTR_STATUS_OFS);

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * PxIS.IFS and PxIS.INFS are errors that occur due to eletrical issues
 * on the interface, or protocol miscommunication between the device
 * and HBA.
 *
 * The conditions that causes PxIS.IFS/PxIS.INFS to be set are
 * 	1. in PxSERR.ERR, P bit is set to '1'
 *	2. in PxSERR.DIAG, C or H bit is set to '1'
 *	3. PhyRdy drop unexpectly, N bit is set to '1'
 */
/*
 * PxIS.INFS - Interface Error
 *
 * Which indicates that the HBA encountered an error on the Serial ATA interface
 * but was able to continue operation. It's non-fatal error, so we just log
 * the debug message.
 *
 * The error occurred during a non-Data FIS, and the FIS will be
 * re-transmitted by HBA automatically.
 */
static int
ahci_intr_interface_non_fatal_error(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	sata_pkt_t *satapkt;
	uint32_t port_serror;
	uint32_t port_cmd_status;
	int current_slot;

	mutex_enter(&ahci_portp->ahciport_mutex);

	port_serror = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port));

	AHCIDBG2(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_interface_non_fatal_error: port %d, "
	    "port_serror = 0x%x", port, port_serror);

	ahci_log_error_message(ahci_ctlp, port, port_serror);

	cmn_err(CE_NOTE, "!ahci port %d has interface non fatal error", port);

	/*
	 * Record the error occurred command's slot.
	 */
#if AHCI_DEBUG
	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	current_slot = (port_cmd_status & AHCI_CMD_STATUS_CCS) >>
	    AHCI_CMD_STATUS_CCS_SHIFT;

	satapkt = ahci_portp->ahciport_slot_pkts[current_slot];

	if (satapkt != NULL) {
		AHCIDBG1(AHCIDBG_INTR, ahci_ctlp,
		    "ahci_intr_interface_non_fatal_error: "
		    "pending_tags= 0x%x ",
		    ahci_portp->ahciport_pending_tags);

		AHCIDBG1(AHCIDBG_INTR, ahci_ctlp,
		    "ahci_intr_interface_non_fatal_error: cmd= 0x%x ",
		    satapkt->satapkt_cmd.satacmd_cmd_reg);

		AHCIDBG2(AHCIDBG_INTR, ahci_ctlp,
		    "ahci_intr_interface_non_fatal_error: port %d, "
		    "satapkt = %p will be re-transmitted",
		    port, (void *)satapkt);
	}
#endif
	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * PxIS.IFS - Interface Error and Fatal Error
 *
 * Which indicates that the HBA encountered an error on the Serial ATA interface
 * which caused the transfer to stop.
 *
 * The error occurred during a Data FIS, the transfer shall stop.
 */
static int
ahci_intr_interface_fatal_error(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_serror;

	mutex_enter(&ahci_portp->ahciport_mutex);

	port_serror = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port));

	AHCIDBG2(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_interface_fatal_error: port %d, "
	    "port_serror = 0x%x", port, port_serror);

	ahci_log_error_message(ahci_ctlp, port, port_serror);

	cmn_err(CE_NOTE, "!ahci port %d has interface fatal error", port);

	(void) ahci_recovery_fatal_error(ahci_ctlp, ahci_portp,
	    port, AHCI_INTR_STATUS_IFS);

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * PxIS.HBDS - System Memory Error and Fatal Error
 *
 * Which indicates that the HBA encountered a data error
 * (uncorrectable ECC/parity) when reading from or writing to system memory.
 */
static int
ahci_intr_host_bus_data_error(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_serror;

	mutex_enter(&ahci_portp->ahciport_mutex);

	port_serror = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port));

	AHCIDBG2(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_host_bus_data_error: port %d, "
	    "port_serror = 0x%x", port, port_serror);

	ahci_log_error_message(ahci_ctlp, port, port_serror);

	cmn_err(CE_NOTE, "!ahci port %d has bus data error", port);

	(void) ahci_recovery_fatal_error(ahci_ctlp, ahci_portp,
	    port, AHCI_INTR_STATUS_HBDS);

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * PxIS.HBFS - System Memory Error and Fatal Error
 *
 * Which indicates that the HBA encountered a host bus error that it cannot
 * recover from, such as a bad software pointer.
 */
static int
ahci_intr_host_bus_fatal_error(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_serror;

	mutex_enter(&ahci_portp->ahciport_mutex);

	port_serror = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxSERR(ahci_ctlp, port));

	AHCIDBG2(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_host_bus_fatal_error: port %d, "
	    "port_serror = 0x%x", port, port_serror);

	ahci_log_error_message(ahci_ctlp, port, port_serror);

	cmn_err(CE_NOTE, "!ahci port %d has bus fatal error", port);

	(void) ahci_recovery_fatal_error(ahci_ctlp, ahci_portp,
	    port, AHCI_INTR_STATUS_HBFS);

	mutex_exit(&ahci_portp->ahciport_mutex);

	return (AHCI_SUCCESS);
}

/*
 * PxIS.TFES - Device Error and Fatal Error
 *
 * This bit is set whenever the status register is updated by the device
 * and the error bit (bit 0) is set.
 */
static int
ahci_intr_task_file_error(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t task_file_status;

	mutex_enter(&ahci_portp->ahciport_mutex);

	task_file_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));

	AHCIDBG2(AHCIDBG_INTR|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_intr_task_file_error: port %d: "
	    "task_file_status = 0x%x", port, task_file_status);

	cmn_err(CE_NOTE, "!ahci port %d has task file error", port);

	(void) ahci_recovery_fatal_error(ahci_ctlp, ahci_portp,
	    port, AHCI_INTR_STATUS_TFES);

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
 * For the first phase, this interrupt is disabled and we just log
 * the debug message.
 */
/* ARGSUSED */
static int
ahci_intr_cold_port_detect(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	uint32_t port_cmd_status;
	sata_device_t sdevice;

	AHCIDBG1(AHCIDBG_INTR, ahci_ctlp,
	    "ahci_intr_cold_port_detect enter, port %d", port);

	mutex_enter(&ahci_portp->ahciport_mutex);

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));
	if (!(port_cmd_status & AHCI_CMD_STATUS_CPD)) {
		AHCIDBG1(AHCIDBG_INTR, ahci_ctlp,
		    "port %d does not support cold presence detect, so "
		    "we just ignore this interrupt", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return (AHCI_SUCCESS);
	}

	AHCIDBG1(AHCIDBG_INTR, ahci_ctlp,
	    "port %d device status has changed", port);

	bzero((void *)&sdevice, sizeof (sata_device_t));
	sdevice.satadev_addr.cport = ahci_ctlp->ahcictl_port_to_cport[port];
	sdevice.satadev_addr.qual = SATA_ADDR_CPORT;
	sdevice.satadev_addr.pmport = 0;
	sdevice.satadev_state = SATA_PSTATE_PWRON;

	if (port_cmd_status & AHCI_CMD_STATUS_CPS) {
		AHCIDBG1(AHCIDBG_INTR, ahci_ctlp,
		    "port %d: a device is hot plugged", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		sata_hba_event_notify(
		    ahci_ctlp->ahcictl_sata_hba_tran->sata_tran_hba_dip,
		    &sdevice,
		    SATA_EVNT_DEVICE_ATTACHED);
		mutex_enter(&ahci_portp->ahciport_mutex);

	} else {
		AHCIDBG1(AHCIDBG_INTR, ahci_ctlp,
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
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
/* ARGSUSED */
static void
ahci_enable_port_intrs(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
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
	    AHCI_INTR_STATUS_UFS |
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
 *
 * WARNING!!! ahcictl_mutex should be acquired before the function
 * is called.
 */
static void
ahci_enable_all_intrs(ahci_ctl_t *ahci_ctlp)
{
	uint32_t ghc_control;

	AHCIDBG0(AHCIDBG_ENTRY, ahci_ctlp, "ahci_enable_all_intrs enter");

	ghc_control = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp));

	ghc_control |= AHCI_HBA_GHC_IE;

	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp), ghc_control);
}

/*
 * Disable interrupts for a particular port.
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
/* ARGSUSED */
static void
ahci_disable_port_intrs(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port)
{
	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_disable_port_intrs enter, port %d", port);

	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxIE(ahci_ctlp, port), 0);
}

/*
 * Disable interrupts for the whole HBA.
 *
 * The global bit is cleared, then all interrupt sources from all
 * ports are disabled.
 *
 * WARNING!!! ahcictl_mutex should be acquired before the function
 * is called.
 */
static void
ahci_disable_all_intrs(ahci_ctl_t *ahci_ctlp)
{
	uint32_t ghc_control;

	AHCIDBG0(AHCIDBG_ENTRY, ahci_ctlp, "ahci_disable_all_intrs enter");

	ghc_control = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp));

	ghc_control &= ~ AHCI_HBA_GHC_IE;

	ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_GLOBAL_GHC(ahci_ctlp), ghc_control);
}

/*
 * Handle INTx and legacy interrupts.
 */
static int
ahci_add_legacy_intrs(ahci_ctl_t *ahci_ctlp)
{
	dev_info_t	*dip = ahci_ctlp->ahcictl_dip;
	int		actual, count = 0;
	int		x, y, rc, inum = 0;

	AHCIDBG0(AHCIDBG_ENTRY|AHCIDBG_INIT, ahci_ctlp,
	    "ahci_add_legacy_intrs enter");

	/* get number of interrupts. */
	rc = ddi_intr_get_nintrs(dip, DDI_INTR_TYPE_FIXED, &count);
	if ((rc != DDI_SUCCESS) || (count == 0)) {
		AHCIDBG2(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_get_nintrs() failed, "
		    "rc %d count %d\n", rc, count);
		return (DDI_FAILURE);
	}

	/* Allocate an array of interrupt handles. */
	ahci_ctlp->ahcictl_intr_size = count * sizeof (ddi_intr_handle_t);
	ahci_ctlp->ahcictl_intr_htable =
	    kmem_zalloc(ahci_ctlp->ahcictl_intr_size, KM_SLEEP);

	/* call ddi_intr_alloc(). */
	rc = ddi_intr_alloc(dip, ahci_ctlp->ahcictl_intr_htable,
	    DDI_INTR_TYPE_FIXED,
	    inum, count, &actual, DDI_INTR_ALLOC_STRICT);

	if ((rc != DDI_SUCCESS) || (actual == 0)) {
		AHCIDBG1(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_alloc() failed, rc %d\n", rc);
		kmem_free(ahci_ctlp->ahcictl_intr_htable,
		    ahci_ctlp->ahcictl_intr_size);
		return (DDI_FAILURE);
	}

	if (actual < count) {
		AHCIDBG2(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "Requested: %d, Received: %d", count, actual);

		for (x = 0; x < actual; x++) {
			(void) ddi_intr_free(ahci_ctlp->ahcictl_intr_htable[x]);
		}

		kmem_free(ahci_ctlp->ahcictl_intr_htable,
		    ahci_ctlp->ahcictl_intr_size);
		return (DDI_FAILURE);
	}

	ahci_ctlp->ahcictl_intr_cnt = actual;

	/* Get intr priority. */
	if (ddi_intr_get_pri(ahci_ctlp->ahcictl_intr_htable[0],
	    &ahci_ctlp->ahcictl_intr_pri) != DDI_SUCCESS) {
		AHCIDBG0(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_get_pri() failed");

		for (x = 0; x < actual; x++) {
			(void) ddi_intr_free(ahci_ctlp->ahcictl_intr_htable[x]);
		}

		kmem_free(ahci_ctlp->ahcictl_intr_htable,
		    ahci_ctlp->ahcictl_intr_size);
		return (DDI_FAILURE);
	}

	/* Test for high level interrupt. */
	if (ahci_ctlp->ahcictl_intr_pri >= ddi_intr_get_hilevel_pri()) {
		AHCIDBG0(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ahci_add_legacy_intrs: Hi level intr not supported");

		for (x = 0; x < actual; x++) {
			(void) ddi_intr_free(ahci_ctlp->ahcictl_intr_htable[x]);
		}

		kmem_free(ahci_ctlp->ahcictl_intr_htable,
		    sizeof (ddi_intr_handle_t));

		return (DDI_FAILURE);
	}

	/* Call ddi_intr_add_handler(). */
	for (x = 0; x < actual; x++) {
		if (ddi_intr_add_handler(ahci_ctlp->ahcictl_intr_htable[x],
		    ahci_intr, (caddr_t)ahci_ctlp, NULL) != DDI_SUCCESS) {
			AHCIDBG0(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
			    "ddi_intr_add_handler() failed");

			for (y = 0; y < actual; y++) {
				(void) ddi_intr_free(
				    ahci_ctlp->ahcictl_intr_htable[y]);
			}

			kmem_free(ahci_ctlp->ahcictl_intr_htable,
			    ahci_ctlp->ahcictl_intr_size);
			return (DDI_FAILURE);
		}
	}

	/* Call ddi_intr_enable() for legacy interrupts. */
	for (x = 0; x < ahci_ctlp->ahcictl_intr_cnt; x++) {
		(void) ddi_intr_enable(ahci_ctlp->ahcictl_intr_htable[x]);
	}

	return (DDI_SUCCESS);
}

/*
 * Handle MSI interrupts.
 */
static int
ahci_add_msi_intrs(ahci_ctl_t *ahci_ctlp)
{
	dev_info_t *dip = ahci_ctlp->ahcictl_dip;
	int		count, avail, actual;
	int		x, y, rc, inum = 0;

	AHCIDBG0(AHCIDBG_ENTRY|AHCIDBG_INIT, ahci_ctlp,
	    "ahci_add_msi_intrs enter");

	/* get number of interrupts. */
	rc = ddi_intr_get_nintrs(dip, DDI_INTR_TYPE_MSI, &count);
	if ((rc != DDI_SUCCESS) || (count == 0)) {
		AHCIDBG2(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_get_nintrs() failed, "
		    "rc %d count %d\n", rc, count);
		return (DDI_FAILURE);
	}

	/* get number of available interrupts. */
	rc = ddi_intr_get_navail(dip, DDI_INTR_TYPE_MSI, &avail);
	if ((rc != DDI_SUCCESS) || (avail == 0)) {
		AHCIDBG2(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_get_navail() failed, "
		    "rc %d avail %d\n", rc, avail);
		return (DDI_FAILURE);
	}

	if (avail < count) {
		AHCIDBG2(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_get_nvail returned %d, navail() returned %d",
		    count, avail);
	}

	/* Allocate an array of interrupt handles. */
	ahci_ctlp->ahcictl_intr_size = count * sizeof (ddi_intr_handle_t);
	ahci_ctlp->ahcictl_intr_htable =
	    kmem_alloc(ahci_ctlp->ahcictl_intr_size, KM_SLEEP);

	/* call ddi_intr_alloc(). */
	rc = ddi_intr_alloc(dip, ahci_ctlp->ahcictl_intr_htable,
	    DDI_INTR_TYPE_MSI, inum, count, &actual, DDI_INTR_ALLOC_NORMAL);

	if ((rc != DDI_SUCCESS) || (actual == 0)) {
		AHCIDBG1(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_alloc() failed, rc %d\n", rc);
		kmem_free(ahci_ctlp->ahcictl_intr_htable,
		    ahci_ctlp->ahcictl_intr_size);
		return (DDI_FAILURE);
	}

	/* use interrupt count returned */
	if (actual < count) {
		AHCIDBG2(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "Requested: %d, Received: %d", count, actual);
	}

	ahci_ctlp->ahcictl_intr_cnt = actual;

	/*
	 * Get priority for first msi, assume remaining are all the same.
	 */
	if (ddi_intr_get_pri(ahci_ctlp->ahcictl_intr_htable[0],
	    &ahci_ctlp->ahcictl_intr_pri) != DDI_SUCCESS) {
		AHCIDBG0(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ddi_intr_get_pri() failed");

		/* Free already allocated intr. */
		for (y = 0; y < actual; y++) {
			(void) ddi_intr_free(ahci_ctlp->ahcictl_intr_htable[y]);
		}

		kmem_free(ahci_ctlp->ahcictl_intr_htable,
		    ahci_ctlp->ahcictl_intr_size);
		return (DDI_FAILURE);
	}

	/* Test for high level interrupt. */
	if (ahci_ctlp->ahcictl_intr_pri >= ddi_intr_get_hilevel_pri()) {
		AHCIDBG0(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
		    "ahci_add_msi_intrs: Hi level intr not supported");

		/* Free already allocated intr. */
		for (y = 0; y < actual; y++) {
			(void) ddi_intr_free(ahci_ctlp->ahcictl_intr_htable[y]);
		}

		kmem_free(ahci_ctlp->ahcictl_intr_htable,
		    sizeof (ddi_intr_handle_t));

		return (DDI_FAILURE);
	}

	/* Call ddi_intr_add_handler(). */
	for (x = 0; x < actual; x++) {
		if (ddi_intr_add_handler(ahci_ctlp->ahcictl_intr_htable[x],
		    ahci_intr, (caddr_t)ahci_ctlp, NULL) != DDI_SUCCESS) {
			AHCIDBG0(AHCIDBG_INTR|AHCIDBG_INIT, ahci_ctlp,
			    "ddi_intr_add_handler() failed");

			/* Free already allocated intr. */
			for (y = 0; y < actual; y++) {
				(void) ddi_intr_free(
				    ahci_ctlp->ahcictl_intr_htable[y]);
			}

			kmem_free(ahci_ctlp->ahcictl_intr_htable,
			    ahci_ctlp->ahcictl_intr_size);
			return (DDI_FAILURE);
		}
	}


	(void) ddi_intr_get_cap(ahci_ctlp->ahcictl_intr_htable[0],
	    &ahci_ctlp->ahcictl_intr_cap);

	if (ahci_ctlp->ahcictl_intr_cap & DDI_INTR_FLAG_BLOCK) {
		/* Call ddi_intr_block_enable() for MSI. */
		(void) ddi_intr_block_enable(ahci_ctlp->ahcictl_intr_htable,
		    ahci_ctlp->ahcictl_intr_cnt);
	} else {
		/* Call ddi_intr_enable() for MSI non block enable. */
		for (x = 0; x < ahci_ctlp->ahcictl_intr_cnt; x++) {
			(void) ddi_intr_enable(
			    ahci_ctlp->ahcictl_intr_htable[x]);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * Removes the registered interrupts irrespective of whether they
 * were legacy or MSI.
 *
 * WARNING!!! The controller interrupts must be disabled before calling
 * this routine.
 */
static void
ahci_rem_intrs(ahci_ctl_t *ahci_ctlp)
{
	int x;

	AHCIDBG0(AHCIDBG_ENTRY, ahci_ctlp, "ahci_rem_intrs entered");

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
 * This routine tries to put port into NotRunning state by clearing
 * PxCMD.ST and PxCMD.FRE. Remember to clear PxCMD.FRE before clearing
 * PxCMD.ST.
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
/* ARGSUSED */
static int
ahci_port_into_notrunning_state(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_port, uint8_t port)
{
	uint32_t port_cmd_status;
	int loop_count;

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_port_into_notrunning_state enter: port %d", port);

	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	if (!(port_cmd_status & AHCI_CMD_STATUS_ST))
		goto clear_fre;

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
			AHCIDBG2(AHCIDBG_INIT, ahci_ctlp,
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
#ifndef __lock_lint
		delay(AHCI_10MS_TICKS);
#endif /* __lock_lint */

	} while (port_cmd_status & AHCI_CMD_STATUS_CR);

	AHCIDBG2(AHCIDBG_INIT|AHCIDBG_POLL_LOOP, ahci_ctlp,
	    "ahci_port_into_notrunning_state: 1st loop count: %d, "
	    "port_cmd_status = 0x%x", loop_count, port_cmd_status);

clear_fre:
	if (port_cmd_status & AHCI_CMD_STATUS_FRE) {

		port_cmd_status &= ~AHCI_CMD_STATUS_FRE;
		ddi_put32(ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port),
		    port_cmd_status);

		/* Wait until PxCMD.FR is cleared */
		loop_count = 0;
		do {
			port_cmd_status =
			    ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
			    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

			if (loop_count++ > AHCI_POLLRATE_PORT_IDLE) {
				AHCIDBG2(AHCIDBG_INIT, ahci_ctlp,
				    "clearing port %d CMD.FR "
				    "timeout, port_cmd_status = 0x%x",
				    port, port_cmd_status);
				/*
				 * We are effectively timing out after 0.5 sec.
				 * This value is specified in AHCI spec.
				 */
				break;
			}

			/* Wait for 10 millisec */
#ifndef __lock_lint
			delay(AHCI_10MS_TICKS);
#endif /* __lock_lint */
		} while (port_cmd_status & AHCI_CMD_STATUS_FR);

		AHCIDBG2(AHCIDBG_INIT|AHCIDBG_POLL_LOOP, ahci_ctlp,
		    "ahci_port_into_notrunning_state: 2nd loop count: "
		    "%d, port_cmd_status = 0x%x",
		    loop_count, port_cmd_status);
	}

	if (port_cmd_status &
	    (AHCI_CMD_STATUS_ST |
	    AHCI_CMD_STATUS_CR |
	    AHCI_CMD_STATUS_FRE |
	    AHCI_CMD_STATUS_FR)) {

		AHCIDBG1(AHCIDBG_INIT, ahci_ctlp,
		    "port %d cannot be put in NotRunning state", port);
		return (AHCI_FAILURE);

	} else {

		AHCIDBG1(AHCIDBG_INIT, ahci_ctlp,
		    "port %d is put in NotRunning state", port);
		return (AHCI_SUCCESS);
	}
}

/*
 * This routine will be called under five scenarios:
 *	1. Initialize the port
 *	2. To abort the packet(s)
 *	3. To reset the port
 *	4. Fatal error recovery
 *	5. To abort the timeout packet(s)
 *
 * WARNING!!! ahciport_mutex should be acquired before the function
 * is called.
 */
static int
ahci_restart_port_wait_till_ready(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port, int flag)
{
	uint32_t task_file_status;
	sata_device_t sdevice;
	int rval;

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_restart_port_wait_till_ready: port %d enter", port);

	ahci_disable_port_intrs(ahci_ctlp, ahci_portp, port);

	rval = ahci_port_into_notrunning_state(ahci_ctlp, ahci_portp, port);

	if (rval == AHCI_SUCCESS) {
		task_file_status = ddi_get32(
		    ahci_ctlp->ahcictl_ahci_acc_handle,
		    (uint32_t *)AHCI_PORT_PxTFD(ahci_ctlp, port));

		if (task_file_status & AHCI_TFD_STS_BSY ||
		    task_file_status & AHCI_TFD_STS_DRQ)
			rval = AHCI_FAILURE;
	}

	if (!(flag & AHCI_PORT_RESET) && (rval == AHCI_SUCCESS))
		goto out;

	/* Set the reset in progress flag */
	if (!(flag & AHCI_RESET_NO_EVENTS_UP)) {
		ahci_portp->ahciport_reset_in_progress = 1;
	}

	rval = ahci_port_reset(ahci_ctlp, ahci_portp, port);
	if (rval != AHCI_SUCCESS) {
		ahci_portp->ahciport_port_state = SATA_PSTATE_FAILED;
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_restart_port_wait_till_ready: port %d failed",
		    port);
	}

	/* Indicate to the framework that a reset has happened. */
	if (!(flag & AHCI_RESET_NO_EVENTS_UP)) {

		bzero((void *)&sdevice, sizeof (sata_device_t));
		sdevice.satadev_addr.cport =
		    ahci_ctlp->ahcictl_port_to_cport[port];
		sdevice.satadev_addr.pmport = AHCI_PORTMULT_CONTROL_PORT;

		if (ahci_portp->ahciport_device_type == SATA_DTYPE_PMULT) {
			sdevice.satadev_addr.qual = SATA_ADDR_DPMPORT;
		} else {
			sdevice.satadev_addr.qual = SATA_ADDR_DCPORT;
		}
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

		AHCIDBG0(AHCIDBG_EVENT, ahci_ctlp,
		    "sending event up: SATA_EVNT_RESET");
	}
out:
	if (!(flag & AHCI_PORT_INIT)) {
		(void) ahci_start_port(ahci_ctlp, port);
		ahci_enable_port_intrs(ahci_ctlp, ahci_portp, port);
	}

	return (rval);
}

/*
 * This routine is called under four scenarios:
 *	a) some commands failed with errors
 *	b) or we need to timeout some commands
 *	c) or we need to abort some commands
 *	d) or we need reset device/port/controller
 *
 * In all these scenarios, we need to send any pending unfinished
 * commands up to sata framework.
 *
 * Only one mopping process at a time is allowed; this is achieved
 * by checking AHCI_PORT_STATE_MOPPING by the caller.
 */
static void
ahci_mop_commands(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp,
    uint8_t port,
    uint32_t slot_status,
    uint32_t failed_tags,
    uint32_t timeout_tags,
    uint32_t aborted_tags,
    uint32_t reset_tags)
{
	uint32_t finished_tags, unfinished_tags;
	int tmp_slot;
	sata_pkt_t *satapkt;
	int i, num = 0;
	ahci_fis_d2h_register_t *rcvd_fisp;

	AHCIDBG2(AHCIDBG_ERRS|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_mop_commands entered: port: %d slot_status: 0x%x",
	    port, slot_status);

	AHCIDBG4(AHCIDBG_ERRS|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_mop_commands: failed_tags: 0x%x, "
	    "timeout_tags: 0x%x aborted_tags: 0x%x, "
	    "reset_tags: 0x%x", failed_tags,
	    timeout_tags, aborted_tags, reset_tags);

	/*
	 * We could be here for four reasons: abort, reset,
	 * timeout or error handling. Only one such mopping
	 * is allowed at a time.
	 */
	mutex_enter(&ahci_portp->ahciport_mutex);

	finished_tags = ahci_portp->ahciport_pending_tags &
	    ~slot_status & AHCI_SLOT_MASK(ahci_ctlp);

	unfinished_tags = slot_status &
	    AHCI_SLOT_MASK(ahci_ctlp) &
	    ~failed_tags &
	    ~aborted_tags &
	    ~reset_tags &
	    ~timeout_tags;

	/*
	 * Try to check if there are more than one command which have
	 * been finished.
	 */
	for (i = 0; i < ahci_ctlp->ahcictl_num_cmd_slots; i++) {
		if ((0x1 << i) & finished_tags)
			num++;
	}
	ASSERT(num <= 1);

	/* Set finished packets with SATA_PKT_COMPLETED */
	while (finished_tags) {
		tmp_slot = ddi_ffs(finished_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(satapkt != NULL);

		rcvd_fisp =
		    &(ahci_portp->ahciport_rcvd_fis->ahcirf_d2h_register_fis);

		/* Return the status */
		satapkt->satapkt_cmd.satacmd_status_reg =
		    GET_RFIS_STATUS(rcvd_fisp);

		if (satapkt->satapkt_cmd.satacmd_flags.sata_special_regs)
			ahci_copy_out_regs(&satapkt->satapkt_cmd, rcvd_fisp);

		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp, "ahci_mop_commands: "
		    "sending up pkt 0x%p with SATA_PKT_COMPLETED",
		    (void *)satapkt);

		CLEAR_BIT(ahci_portp->ahciport_pending_tags, tmp_slot);
		CLEAR_BIT(finished_tags, tmp_slot);
		ahci_portp->ahciport_slot_pkts[tmp_slot] = NULL;

		SENDUP_PACKET(ahci_portp, satapkt, SATA_PKT_COMPLETED);
	}

	ASSERT(finished_tags == 0);

	/* Send up failed_tags with SATA_PKT_DEV_ERROR. */
	while (failed_tags) {
		tmp_slot = ddi_ffs(failed_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(satapkt != NULL);

		if (satapkt->satapkt_device.satadev_type ==
		    SATA_DTYPE_ATAPICD) {
			ahci_set_sense_data(satapkt, SATA_PKT_ABORTED);
		}

		rcvd_fisp =
		    &(ahci_portp->ahciport_rcvd_fis->ahcirf_d2h_register_fis);

		/* Return the status */
		satapkt->satapkt_cmd.satacmd_status_reg =
		    GET_RFIS_STATUS(rcvd_fisp);

		if (satapkt->satapkt_cmd.satacmd_flags.sata_special_regs)
			ahci_copy_out_regs(&satapkt->satapkt_cmd, rcvd_fisp);

		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
		    "sending up pkt 0x%p with SATA_PKT_DEV_ERROR",
		    (void *)satapkt);

		CLEAR_BIT(ahci_portp->ahciport_pending_tags, tmp_slot);
		CLEAR_BIT(failed_tags, tmp_slot);
		ahci_portp->ahciport_slot_pkts[tmp_slot] = NULL;

		SENDUP_PACKET(ahci_portp, satapkt, SATA_PKT_DEV_ERROR);
	}

	ASSERT(failed_tags == 0);

	/* Send up timeout_tags with SATA_PKT_TIMEOUT. */
	while (timeout_tags) {
		tmp_slot = ddi_ffs(timeout_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(satapkt != NULL);

		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
		    "sending up pkt 0x%p with SATA_PKT_TIMEOUT",
		    (void *)satapkt);

		CLEAR_BIT(ahci_portp->ahciport_pending_tags, tmp_slot);
		CLEAR_BIT(timeout_tags, tmp_slot);
		ahci_portp->ahciport_slot_pkts[tmp_slot] = NULL;

		SENDUP_PACKET(ahci_portp, satapkt, SATA_PKT_TIMEOUT);
	}

	ASSERT(timeout_tags == 0);

	/* Set aborted packets with SATA_PKT_ABORTED */
	while (aborted_tags) {
		tmp_slot = ddi_ffs(aborted_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(satapkt != NULL);

		if (satapkt->satapkt_device.satadev_type ==
		    SATA_DTYPE_ATAPICD) {
			ahci_set_sense_data(satapkt, SATA_PKT_ABORTED);
		}

		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
		    "sending up pkt 0x%p with SATA_PKT_ABORTED",
		    (void *)satapkt);

		CLEAR_BIT(ahci_portp->ahciport_pending_tags, tmp_slot);
		CLEAR_BIT(aborted_tags, tmp_slot);
		ahci_portp->ahciport_slot_pkts[tmp_slot] = NULL;

		SENDUP_PACKET(ahci_portp, satapkt, SATA_PKT_ABORTED);
	}

	ASSERT(aborted_tags == 0);

	/* Reset tags are sent up to framework with SATA_PKT_RESET. */
	while (reset_tags) {
		tmp_slot = ddi_ffs(reset_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(satapkt != NULL);

		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
		    "sending up pkt 0x%p with SATA_PKT_RESET",
		    (void *)satapkt);

		CLEAR_BIT(ahci_portp->ahciport_pending_tags, tmp_slot);
		CLEAR_BIT(reset_tags, tmp_slot);
		ahci_portp->ahciport_slot_pkts[tmp_slot] = NULL;

		SENDUP_PACKET(ahci_portp, satapkt, SATA_PKT_RESET);
	}

	ASSERT(reset_tags == 0);

	/* Set unfinished packets with SATA_PKT_BUSY */
	while (unfinished_tags) {
		tmp_slot = ddi_ffs(unfinished_tags) - 1;
		if (tmp_slot == -1) {
			break;
		}

		satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
		ASSERT(satapkt != NULL);

		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp, "ahci_mop_commands: "
		    "sending up pkt 0x%p with SATA_PKT_BUSY",
		    (void *)satapkt);

		CLEAR_BIT(ahci_portp->ahciport_pending_tags, tmp_slot);
		CLEAR_BIT(unfinished_tags, tmp_slot);
		ahci_portp->ahciport_slot_pkts[tmp_slot] = NULL;

		SENDUP_PACKET(ahci_portp, satapkt, SATA_PKT_BUSY);
	}

	ASSERT(unfinished_tags == 0);

	ahci_portp->ahciport_flags &= ~AHCI_PORT_STATE_MOPPING;

	mutex_exit(&ahci_portp->ahciport_mutex);
}

/*
 * Fatal errors will cause the HBA to enter the ERR: Fatal state. To recover,
 * the port must be restarted.
 *
 * Fatal errors include the following:
 * 	PxIS.OFS - Overflow Status
 * 	PxIS.IFS - Interface Fatal Error Status
 * 	PxIS.HBDS - Host Bus Data Error Status
 * 	PxIS.HBFS - Host Bus Fatal Error Status
 *	PxIS.TFES - Task File Error Status
 *
 * WARNING!!! ahciport_mutex should be acquired before the function is called.
 */
static int
ahci_recovery_fatal_error(ahci_ctl_t *ahci_ctlp,
    ahci_port_t *ahci_portp, uint8_t port, uint32_t error)
{
	uint32_t port_cmd_status, slot_status;
	uint32_t failed_tags;
	int current_slot;
	sata_pkt_t *spkt;
	ahci_fis_d2h_register_t *ahci_rcvd_fisp;

	AHCIDBG1(AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_recovery_fatal_error enter port %d", port);

	if (ahci_portp->ahciport_device_type == SATA_DTYPE_NONE) {
		/*
		 * ahci_intr_phyrdy_change() may have rendered it to
		 * SATA_DTYPE_NONE.
		 */
		AHCIDBG1(AHCIDBG_INTR, ahci_ctlp,
		    "ahci_recovery_fatal_error: no device attached, and just "
		    "return without doing anything", port);
		return (SATA_SUCCESS);
	}

	/* Record the error occurred command slot */
	port_cmd_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCMD(ahci_ctlp, port));

	current_slot = (port_cmd_status & AHCI_CMD_STATUS_CCS) >>
	    AHCI_CMD_STATUS_CCS_SHIFT;

	spkt = ahci_portp->ahciport_slot_pkts[current_slot];
	if (spkt == NULL) {
		/*
		 * For example, sometimes PxIS.OFS and PxIS.IFS can be set
		 * concurrently.
		 */
		AHCIDBG1(AHCIDBG_INTR, ahci_ctlp,
		    "ahci_recovery_fatal_error: port %d has done "
		    "fatal error recovery, so return directory", port);
		return (SATA_SUCCESS);
	}

	/*
	 * To prevent recursive enter to ahci_mop_commands, we need
	 * check AHCI_PORT_STATE_MOPPING flag.
	 */
	if (ahci_portp->ahciport_flags & AHCI_PORT_STATE_MOPPING) {
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_recovery_fatal_error: port %d is in "
		    "mopping process, so return directly", port);
		return (SATA_SUCCESS);
	}

	ahci_portp->ahciport_flags |= AHCI_PORT_STATE_MOPPING;

	failed_tags = 0x1 << current_slot;

	switch (error) {
	case AHCI_INTR_STATUS_IFS:
	case AHCI_INTR_STATUS_HBFS:
	case AHCI_INTR_STATUS_HBDS:
		/*
		 * For PxIS.IFS, PxIS.HBFS and PxIS.HBDS, we need to return
		 * PxSERR in satapkt.
		 */
		ahci_update_sata_registers(ahci_ctlp, port,
		    &spkt->satapkt_device);
		break;

	case AHCI_INTR_STATUS_TFES:
		/*
		 * For PxIS.TFES, we need to return the status and error
		 * registers in sata_cmd structure
		 */
		ahci_rcvd_fisp =
		    &(ahci_portp->ahciport_rcvd_fis->ahcirf_d2h_register_fis);

		spkt->satapkt_cmd.satacmd_status_reg =
		    GET_RFIS_STATUS(ahci_rcvd_fisp);

		spkt->satapkt_cmd.satacmd_error_reg =
		    GET_RFIS_ERROR(ahci_rcvd_fisp);
		break;

	case AHCI_INTR_STATUS_OFS:
		/*
		 * For PxIS.OFS, until now have no way to send the error
		 * to sata framework.
		 */
		AHCIDBG1(AHCIDBG_ERRS, ahci_ctlp,
		    "ahci_recovery_fatal_error: "
		    "PxOFS occured for port %d", port);

		break;

	default:
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "Not supported error 0x%x for port %d",
		    error, port);
		break;
	}

	slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

	AHCIDBG2(AHCIDBG_INFO, ahci_ctlp,
	    "ahci_recovery_fatal_error: current_slot = 0x%x "
	    "slot_status = 0x%x", current_slot, slot_status);

	(void) ahci_restart_port_wait_till_ready(ahci_ctlp,
	    ahci_portp, port, NULL);

	mutex_exit(&ahci_portp->ahciport_mutex);
	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    port,
	    slot_status,
	    failed_tags, /* failed tags */
	    0, /* timeout tags */
	    0, /* aborted tags */
	    0); /* reset tags */
	mutex_enter(&ahci_portp->ahciport_mutex);

	return (SATA_SUCCESS);
}

/*
 * ahci_watchdog_handler() calls us if it detects that there are some
 * commands which timed out.
 */
static void
ahci_timeout_pkts(ahci_ctl_t *ahci_ctlp, ahci_port_t *ahci_portp,
    uint8_t port, uint32_t tmp_timeout_tags)
{
	uint32_t slot_status;
	uint32_t finished_tags, timeout_tags;

	AHCIDBG0(AHCIDBG_TIMEOUT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_timeout_pkts entered");

	mutex_enter(&ahci_portp->ahciport_mutex);

	/*
	 * To prevent recursive enter to ahci_mop_commands, we need
	 * check AHCI_PORT_STATE_MOPPING flag.
	 */
	if (ahci_portp->ahciport_flags & AHCI_PORT_STATE_MOPPING) {
		AHCIDBG1(AHCIDBG_INFO, ahci_ctlp,
		    "ahci_timeout_pkts: port %d is in "
		    "mopping process, so return directly ", port);
		mutex_exit(&ahci_portp->ahciport_mutex);
		return;
	}

	ahci_portp->ahciport_flags |= AHCI_PORT_STATE_MOPPING;

	slot_status = ddi_get32(ahci_ctlp->ahcictl_ahci_acc_handle,
	    (uint32_t *)AHCI_PORT_PxCI(ahci_ctlp, port));

	(void) ahci_restart_port_wait_till_ready(ahci_ctlp, ahci_portp,
	    port, NULL);
	/*
	 * Re-identify timeout tags because some previously checked commands
	 * could already complete.
	 */
	finished_tags = ahci_portp->ahciport_pending_tags &
	    ~slot_status & AHCI_SLOT_MASK(ahci_ctlp);

	timeout_tags = tmp_timeout_tags & ~finished_tags;

	AHCIDBG3(AHCIDBG_TIMEOUT, ahci_ctlp,
	    "ahci_timeout_pkts: port %d, finished_tags = 0x%x, "
	    "timeout_tags = 0x%x", port,
	    finished_tags, timeout_tags);

	mutex_exit(&ahci_portp->ahciport_mutex);
	ahci_mop_commands(ahci_ctlp,
	    ahci_portp,
	    port,
	    slot_status,
	    0, /* failed tags */
	    timeout_tags, /* timeout tags */
	    0, /* aborted tags */
	    0); /* reset tags */
}

/*
 * Watchdog handler kicks in every 5 seconds to timeout any commands pending
 * for long time.
 */
static void
ahci_watchdog_handler(ahci_ctl_t *ahci_ctlp)
{
	ahci_port_t *ahci_portp;
	sata_pkt_t *satapkt;
	uint32_t pending_tags = 0;
	uint32_t timeout_tags = 0;
	uint8_t port;
	int tmp_slot;
	/* max number of cycles this packet should survive */
	int max_life_cycles;

	/* how many cycles this packet survived so far */
	int watched_cycles;

	mutex_enter(&ahci_ctlp->ahcictl_mutex);

	AHCIDBG0(AHCIDBG_TIMEOUT|AHCIDBG_ENTRY, ahci_ctlp,
	    "ahci_watchdog_handler entered");

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

		pending_tags = ahci_portp->ahciport_pending_tags;
		timeout_tags = 0;
		while (pending_tags) {
			tmp_slot = ddi_ffs(pending_tags) - 1;
			if (tmp_slot == -1) {
				break;
			}

			satapkt = ahci_portp->ahciport_slot_pkts[tmp_slot];
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
				    ahci_watchdog_timeout - 1) /
				    ahci_watchdog_timeout;
				if (watched_cycles > max_life_cycles) {
					timeout_tags |= (0x1 << tmp_slot);
					cmn_err(CE_NOTE, "!ahci watchdog: "
					    "port %d satapkt 0x%p timed out\n",
					    port, (void *)satapkt);
				}
				satapkt->satapkt_hba_driver_private =
				    (void *)(intptr_t)watched_cycles;
			}

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
 * Put a copy back to sata_cmd_t.
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

/*
 * Dump the serror message to the log.
 */
static void
ahci_log_error_message(ahci_ctl_t *ahci_ctlp, uint8_t port,
    uint32_t port_serror)
{
	char *err_str;

	if (port_serror & AHCI_SERROR_ERR_I) {
		err_str = "Recovered Data Integrity Error (I)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_ERR_M) {
		err_str = "Recovered Communication Error (M)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_ERR_T) {
		err_str = "Transient Data Integrity Error (T)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_ERR_C) {
		err_str =
		    "Persistent Communication or Data Integrity Error (C)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_ERR_P) {
		err_str = "Protocol Error (P)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_ERR_E) {
		err_str = "Internal Error (E)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_DIAG_N) {
		err_str = "PhyRdy Change (N)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_DIAG_I) {
		err_str = "Phy Internal Error (I)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_DIAG_W) {
		err_str = "Comm Wake (W)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_DIAG_B) {
		err_str = "10B to 8B Decode Error (B)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_DIAG_D) {
		err_str = "Disparity Error (D)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_DIAG_C) {
		err_str = "CRC Error (C)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_DIAG_H) {
		err_str = "Handshake Error (H)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_DIAG_S) {
		err_str = "Link Sequence Error (S)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_DIAG_T) {
		err_str = "Transport state transition error (T)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_DIAG_F) {
		err_str = "Unknown FIS Type (F)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
	}

	if (port_serror & AHCI_SERROR_DIAG_X) {
		err_str = "Exchanged (X)";
		AHCIDBG2(AHCIDBG_ERRS, ahci_ctlp,
		    "command error: port: %d, error: %s",
		    port, err_str);
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

static void
ahci_log(ahci_ctl_t *ahci_ctlp, uint_t level, char *fmt, ...)
{
	va_list ap;

	mutex_enter(&ahci_log_mutex);

	va_start(ap, fmt);
	if (ahci_ctlp) {
		(void) sprintf(ahci_log_buf, "%s-[%d]:",
		    ddi_get_name(ahci_ctlp->ahcictl_dip),
		    ddi_get_instance(ahci_ctlp->ahcictl_dip));
	} else {
		(void) sprintf(ahci_log_buf, "ahci:");
	}

	(void) vsprintf(ahci_log_buf, fmt, ap);
	va_end(ap);

	cmn_err(level, "%s", ahci_log_buf);

	mutex_exit(&ahci_log_mutex);
}
