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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 * nv_sata is a combo SATA HBA driver for ck804/mcp55 based chipsets.
 *
 * NCQ
 * ---
 *
 * A portion of the NCQ is in place, but is incomplete.  NCQ is disabled
 * and is likely to be revisited in the future.
 *
 *
 * Power Management
 * ----------------
 *
 * Normally power management would be responsible for ensuring the device
 * is quiescent and then changing power states to the device, such as
 * powering down parts or all of the device.  mcp55/ck804 is unique in
 * that it is only available as part of a larger southbridge chipset, so
 * removing power to the device isn't possible.  Switches to control
 * power management states D0/D3 in the PCI configuration space appear to
 * be supported but changes to these states are apparently are ignored.
 * The only further PM that the driver _could_ do is shut down the PHY,
 * but in order to deliver the first rev of the driver sooner than later,
 * that will be deferred until some future phase.
 *
 * Since the driver currently will not directly change any power state to
 * the device, no power() entry point will be required.  However, it is
 * possible that in ACPI power state S3, aka suspend to RAM, that power
 * can be removed to the device, and the driver cannot rely on BIOS to
 * have reset any state.  For the time being, there is no known
 * non-default configurations that need to be programmed.  This judgement
 * is based on the port of the legacy ata driver not having any such
 * functionality and based on conversations with the PM team.  If such a
 * restoration is later deemed necessary it can be incorporated into the
 * DDI_RESUME processing.
 *
 */

#include <sys/scsi/scsi.h>
#include <sys/pci.h>
#include <sys/byteorder.h>
#include <sys/sata/sata_hba.h>
#include <sys/sata/adapters/nv_sata/nv_sata.h>
#include <sys/disp.h>
#include <sys/note.h>
#include <sys/promif.h>


/*
 * Function prototypes for driver entry points
 */
static int nv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int nv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int nv_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result);

/*
 * Function prototypes for entry points from sata service module
 * These functions are distinguished from other local functions
 * by the prefix "nv_sata_"
 */
static int nv_sata_start(dev_info_t *dip, sata_pkt_t *spkt);
static int nv_sata_abort(dev_info_t *dip, sata_pkt_t *spkt, int);
static int nv_sata_reset(dev_info_t *dip, sata_device_t *sd);
static int nv_sata_activate(dev_info_t *dip, sata_device_t *sd);
static int nv_sata_deactivate(dev_info_t *dip, sata_device_t *sd);

/*
 * Local function prototypes
 */
static uint_t mcp55_intr(caddr_t arg1, caddr_t arg2);
static uint_t mcp04_intr(caddr_t arg1, caddr_t arg2);
static int nv_add_legacy_intrs(nv_ctl_t *nvc);
#ifdef NV_MSI_SUPPORTED
static int nv_add_msi_intrs(nv_ctl_t *nvc);
#endif
static void nv_rem_intrs(nv_ctl_t *nvc);
static int nv_start_common(nv_port_t *nvp, sata_pkt_t *spkt);
static int nv_start_nodata(nv_port_t *nvp, int slot);
static void nv_intr_nodata(nv_port_t *nvp, nv_slot_t *spkt);
static int nv_start_pio_in(nv_port_t *nvp, int slot);
static int nv_start_pio_out(nv_port_t *nvp, int slot);
static void nv_intr_pio_in(nv_port_t *nvp, nv_slot_t *spkt);
static void nv_intr_pio_out(nv_port_t *nvp, nv_slot_t *spkt);
static int nv_start_dma(nv_port_t *nvp, int slot);
static void nv_intr_dma(nv_port_t *nvp, struct nv_slot *spkt);
static void nv_log(uint_t flag, nv_ctl_t *nvc, nv_port_t *nvp, char *fmt, ...);
static void nv_uninit_ctl(nv_ctl_t *nvc);
static void mcp55_reg_init(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle);
static void mcp04_reg_init(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle);
static void nv_uninit_port(nv_port_t *nvp);
static int nv_init_port(nv_port_t *nvp);
static int nv_init_ctl(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle);
static int mcp55_packet_complete_intr(nv_ctl_t *nvc, nv_port_t *nvp);
#ifdef NCQ
static int mcp55_dma_setup_intr(nv_ctl_t *nvc, nv_port_t *nvp);
#endif
static void nv_start_dma_engine(nv_port_t *nvp, int slot);
static void nv_port_state_change(nv_port_t *nvp, int event, uint8_t addr_type,
    int state);
static boolean_t nv_check_link(uint32_t sstatus);
static void nv_common_reg_init(nv_ctl_t *nvc);
static void mcp04_intr_process(nv_ctl_t *nvc, uint8_t intr_status);
static void nv_reset(nv_port_t *nvp);
static void nv_complete_io(nv_port_t *nvp,  sata_pkt_t *spkt, int slot);
static void nv_timeout(void *);
static int nv_poll_wait(nv_port_t *nvp, sata_pkt_t *spkt);
static void nv_cmn_err(int ce, nv_ctl_t *nvc, nv_port_t *nvp, char *fmt, ...);
static void nv_read_signature(nv_port_t *nvp);
static void mcp55_set_intr(nv_port_t *nvp, int flag);
static void mcp04_set_intr(nv_port_t *nvp, int flag);
static void nv_resume(nv_port_t *nvp);
static void nv_suspend(nv_port_t *nvp);
static int nv_start_sync(nv_port_t *nvp, sata_pkt_t *spkt);
static int nv_abort_active(nv_port_t *nvp, sata_pkt_t *spkt, int abort_reason);
static void nv_copy_registers(nv_port_t *nvp, sata_device_t *sd,
    sata_pkt_t *spkt);
static void nv_report_add_remove(nv_port_t *nvp, int flags);
static int nv_start_async(nv_port_t *nvp, sata_pkt_t *spkt);
static int nv_wait3(nv_port_t *nvp, uchar_t onbits1, uchar_t offbits1,
    uchar_t failure_onbits2, uchar_t failure_offbits2,
    uchar_t failure_onbits3, uchar_t failure_offbits3,
    uint_t timeout_usec, int type_wait);
static int nv_wait(nv_port_t *nvp, uchar_t onbits, uchar_t offbits,
    uint_t timeout_usec, int type_wait);


/*
 * DMA attributes for the data buffer for x86.  dma_attr_burstsizes is unused.
 * Verify if needed if ported to other ISA.
 */
static ddi_dma_attr_t buffer_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo: lowest bus address */
	0xffffffffull,		/* dma_attr_addr_hi: */
	NV_BM_64K_BOUNDARY - 1,	/* dma_attr_count_max i.e for one cookie */
	4,			/* dma_attr_align */
	1,			/* dma_attr_burstsizes. */
	1,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_max xfer including all cookies */
	0xffffffffull,		/* dma_attr_seg */
	NV_DMA_NSEGS,		/* dma_attr_sgllen */
	512,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};


/*
 * DMA attributes for PRD tables
 */
ddi_dma_attr_t nv_prd_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo */
	0xffffffffull,		/* dma_attr_addr_hi */
	NV_BM_64K_BOUNDARY - 1,	/* dma_attr_count_max */
	4,			/* dma_attr_align */
	1,			/* dma_attr_burstsizes */
	1,			/* dma_attr_minxfer */
	NV_BM_64K_BOUNDARY,	/* dma_attr_maxxfer */
	NV_BM_64K_BOUNDARY - 1,	/* dma_attr_seg */
	1,			/* dma_attr_sgllen */
	1,			/* dma_attr_granular */
	0			/* dma_attr_flags */
};

/*
 * Device access attributes
 */
static ddi_device_acc_attr_t accattr = {
    DDI_DEVICE_ATTR_V0,
    DDI_STRUCTURE_LE_ACC,
    DDI_STRICTORDER_ACC
};


static struct dev_ops nv_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	nv_getinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	nv_attach,		/* attach */
	nv_detach,		/* detach */
	nodev,			/* no reset */
	(struct cb_ops *)0,	/* driver operations */
	NULL,			/* bus operations */
	NULL			/* power */
};

static sata_tran_hotplug_ops_t nv_hotplug_ops;

extern struct mod_ops mod_driverops;

static  struct modldrv modldrv = {
	&mod_driverops,	/* driverops */
	"Nvidia ck804/mcp55 HBA v%I%",
	&nv_dev_ops,	/* driver ops */
};

static  struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};


/*
 * wait between checks of reg status
 */
int nv_usec_delay = NV_WAIT_REG_CHECK;

/*
 * The following is needed for nv_vcmn_err()
 */
static kmutex_t nv_log_mutex; /* protects nv_log_buf */
static char nv_log_buf[NV_STRING_512];
int nv_debug_flags = NVDBG_ALWAYS;
int nv_log_to_console = B_FALSE;

int nv_log_delay = 0;
int nv_prom_print = B_FALSE;

/*
 * for debugging
 */
#ifdef DEBUG
int ncq_commands = 0;
int non_ncq_commands = 0;
#endif

/*
 * Opaque state pointer to be initialized by ddi_soft_state_init()
 */
static void *nv_statep	= NULL;


static sata_tran_hotplug_ops_t nv_hotplug_ops = {
	SATA_TRAN_HOTPLUG_OPS_REV_1,	/* structure version */
	nv_sata_activate,	/* activate port. cfgadm -c connect */
	nv_sata_deactivate	/* deactivate port. cfgadm -c disconnect */
};


/*
 *  nv module initialization
 */
int
_init(void)
{
	int	error;

	error = ddi_soft_state_init(&nv_statep, sizeof (nv_ctl_t), 0);

	if (error != 0) {

		return (error);
	}

	mutex_init(&nv_log_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((error = sata_hba_init(&modlinkage)) != 0) {
		ddi_soft_state_fini(&nv_statep);
		mutex_destroy(&nv_log_mutex);

		return (error);
	}

	error = mod_install(&modlinkage);
	if (error != 0) {
		sata_hba_fini(&modlinkage);
		ddi_soft_state_fini(&nv_statep);
		mutex_destroy(&nv_log_mutex);

		return (error);
	}

	return (error);
}


/*
 * nv module uninitialize
 */
int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);

	if (error != 0) {
		return (error);
	}

	/*
	 * remove the resources allocated in _init()
	 */
	mutex_destroy(&nv_log_mutex);
	sata_hba_fini(&modlinkage);
	ddi_soft_state_fini(&nv_statep);

	return (error);
}


/*
 * nv _info entry point
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * these wrappers for ddi_{get,put}8 are for observability
 * with dtrace
 */
#ifdef DEBUG

static void
nv_put8(ddi_acc_handle_t handle, uint8_t *dev_addr, uint8_t value)
{
	ddi_put8(handle, dev_addr, value);
}

static void
nv_put32(ddi_acc_handle_t handle, uint32_t *dev_addr, uint32_t value)
{
	ddi_put32(handle, dev_addr, value);
}

static uint32_t
nv_get32(ddi_acc_handle_t handle, uint32_t *dev_addr)
{
	return (ddi_get32(handle, dev_addr));
}

static void
nv_put16(ddi_acc_handle_t handle, uint16_t *dev_addr, uint16_t value)
{
	ddi_put16(handle, dev_addr, value);
}

static uint16_t
nv_get16(ddi_acc_handle_t handle, uint16_t *dev_addr)
{
	return (ddi_get16(handle, dev_addr));
}

static uint8_t
nv_get8(ddi_acc_handle_t handle, uint8_t *dev_addr)
{
	return (ddi_get8(handle, dev_addr));
}

#else

#define	nv_put8 ddi_put8
#define	nv_put32 ddi_put32
#define	nv_get32 ddi_get32
#define	nv_put16 ddi_put16
#define	nv_get16 ddi_get16
#define	nv_get8 ddi_get8

#endif


/*
 * Driver attach
 */
static int
nv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int status, attach_state, intr_types, bar, i, command;
	int inst = ddi_get_instance(dip);
	ddi_acc_handle_t pci_conf_handle;
	nv_ctl_t *nvc;
	uint8_t subclass;
	uint32_t reg32;

	switch (cmd) {

	case DDI_ATTACH:

		NVLOG((NVDBG_INIT, NULL, NULL,
		    "nv_attach(): DDI_ATTACH inst %d", inst));

		attach_state = ATTACH_PROGRESS_NONE;

		status = ddi_soft_state_zalloc(nv_statep, inst);

		if (status != DDI_SUCCESS) {
			break;
		}

		nvc = ddi_get_soft_state(nv_statep, inst);

		nvc->nvc_dip = dip;

		attach_state |= ATTACH_PROGRESS_STATEP_ALLOC;

		if (pci_config_setup(dip, &pci_conf_handle) == DDI_SUCCESS) {
			nvc->nvc_revid = pci_config_get8(pci_conf_handle,
			    PCI_CONF_REVID);
			NVLOG((NVDBG_INIT, NULL, NULL,
			    "inst %d: silicon revid is %x nv_debug_flags=%x",
			    inst, nvc->nvc_revid, nv_debug_flags));
		} else {
			break;
		}

		attach_state |= ATTACH_PROGRESS_CONF_HANDLE;

		/*
		 * If a device is attached after a suspend/resume, sometimes
		 * the command register is zero, as it might not be set by
		 * BIOS or a parent.  Set it again here.
		 */
		command = pci_config_get16(pci_conf_handle, PCI_CONF_COMM);

		if (command == 0) {
			cmn_err(CE_WARN, "nv_sata%d: restoring PCI command"
			    " register", inst);
			pci_config_put16(pci_conf_handle, PCI_CONF_COMM,
			    PCI_COMM_IO|PCI_COMM_MAE|PCI_COMM_ME);
		}

		subclass = pci_config_get8(pci_conf_handle, PCI_CONF_SUBCLASS);

		if (subclass & PCI_MASS_RAID) {
			cmn_err(CE_WARN,
			    "attach failed: RAID mode not supported");
			break;
		}

		/*
		 * the 6 bars of the controller are:
		 * 0: port 0 task file
		 * 1: port 0 status
		 * 2: port 1 task file
		 * 3: port 1 status
		 * 4: bus master for both ports
		 * 5: extended registers for SATA features
		 */
		for (bar = 0; bar < 6; bar++) {
			status = ddi_regs_map_setup(dip, bar + 1,
			    (caddr_t *)&nvc->nvc_bar_addr[bar], 0, 0, &accattr,
			    &nvc->nvc_bar_hdl[bar]);

			if (status != DDI_SUCCESS) {
				NVLOG((NVDBG_INIT, nvc, NULL,
				    "ddi_regs_map_setup failure for bar"
				    " %d status = %d", bar, status));
				break;
			}
		}

		attach_state |= ATTACH_PROGRESS_BARS;

		/*
		 * initialize controller and driver core
		 */
		status = nv_init_ctl(nvc, pci_conf_handle);

		if (status == NV_FAILURE) {
			NVLOG((NVDBG_INIT, nvc, NULL, "nv_init_ctl failed"));

			break;
		}

		attach_state |= ATTACH_PROGRESS_CTL_SETUP;

		/*
		 * initialize mutexes
		 */
		mutex_init(&nvc->nvc_mutex, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(nvc->nvc_intr_pri));

		attach_state |= ATTACH_PROGRESS_MUTEX_INIT;

		/*
		 * get supported interrupt types
		 */
		if (ddi_intr_get_supported_types(dip, &intr_types) !=
		    DDI_SUCCESS) {
			nv_cmn_err(CE_WARN, nvc, NULL,
			    "!ddi_intr_get_supported_types failed");
			NVLOG((NVDBG_INIT, nvc, NULL,
			    "interrupt supported types failed"));

			break;
		}

		NVLOG((NVDBG_INIT, nvc, NULL,
		    "ddi_intr_get_supported_types() returned: 0x%x",
		    intr_types));

#ifdef NV_MSI_SUPPORTED
		if (intr_types & DDI_INTR_TYPE_MSI) {
			NVLOG((NVDBG_INIT, nvc, NULL,
			    "using MSI interrupt type"));

			/*
			 * Try MSI first, but fall back to legacy if MSI
			 * attach fails
			 */
			if (nv_add_msi_intrs(nvc) == DDI_SUCCESS) {
				nvc->nvc_intr_type = DDI_INTR_TYPE_MSI;
				attach_state |= ATTACH_PROGRESS_INTR_ADDED;
				NVLOG((NVDBG_INIT, nvc, NULL,
				    "MSI interrupt setup done"));
			} else {
				nv_cmn_err(CE_CONT, nvc, NULL,
				    "!MSI registration failed "
				    "will try Legacy interrupts");
			}
		}
#endif

		/*
		 * Either the MSI interrupt setup has failed or only
		 * the fixed interrupts are available on the system.
		 */
		if (!(attach_state & ATTACH_PROGRESS_INTR_ADDED) &&
		    (intr_types & DDI_INTR_TYPE_FIXED)) {

			NVLOG((NVDBG_INIT, nvc, NULL,
			    "using Legacy interrupt type"));

			if (nv_add_legacy_intrs(nvc) == DDI_SUCCESS) {
				nvc->nvc_intr_type = DDI_INTR_TYPE_FIXED;
				attach_state |= ATTACH_PROGRESS_INTR_ADDED;
				NVLOG((NVDBG_INIT, nvc, NULL,
				    "Legacy interrupt setup done"));
			} else {
				nv_cmn_err(CE_WARN, nvc, NULL,
				    "!legacy interrupt setup failed");
				NVLOG((NVDBG_INIT, nvc, NULL,
				    "legacy interrupt setup failed"));
				break;
			}
		}

		if (!(attach_state & ATTACH_PROGRESS_INTR_ADDED)) {
			NVLOG((NVDBG_INIT, nvc, NULL,
			    "no interrupts registered"));
			break;
		}

		/*
		 * attach to sata module
		 */
		if (sata_hba_attach(nvc->nvc_dip,
		    &nvc->nvc_sata_hba_tran,
		    DDI_ATTACH) != DDI_SUCCESS) {
			attach_state |= ATTACH_PROGRESS_SATA_MODULE;

			break;
		}

		pci_config_teardown(&pci_conf_handle);

		NVLOG((NVDBG_INIT, nvc, NULL, "nv_attach DDI_SUCCESS"));

		return (DDI_SUCCESS);

	case DDI_RESUME:

		nvc = ddi_get_soft_state(nv_statep, inst);

		NVLOG((NVDBG_INIT, nvc, NULL,
		    "nv_attach(): DDI_RESUME inst %d", inst));

		if (pci_config_setup(dip, &pci_conf_handle) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		/*
		 * If a device is attached after a suspend/resume, sometimes
		 * the command register is zero, as it might not be set by
		 * BIOS or a parent.  Set it again here.
		 */
		command = pci_config_get16(pci_conf_handle, PCI_CONF_COMM);

		if (command == 0) {
			pci_config_put16(pci_conf_handle, PCI_CONF_COMM,
			    PCI_COMM_IO|PCI_COMM_MAE|PCI_COMM_ME);
		}

		/*
		 * Need to set bit 2 to 1 at config offset 0x50
		 * to enable access to the bar5 registers.
		 */
		reg32 = pci_config_get32(pci_conf_handle, NV_SATA_CFG_20);

		if ((reg32 & NV_BAR5_SPACE_EN) != NV_BAR5_SPACE_EN) {
			pci_config_put32(pci_conf_handle, NV_SATA_CFG_20,
			    reg32 | NV_BAR5_SPACE_EN);
		}

		nvc->nvc_state &= ~NV_CTRL_SUSPEND;

		for (i = 0; i < NV_MAX_PORTS(nvc); i++) {
			nv_resume(&(nvc->nvc_port[i]));
		}

		pci_config_teardown(&pci_conf_handle);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}


	/*
	 * DDI_ATTACH failure path starts here
	 */

	if (attach_state & ATTACH_PROGRESS_INTR_ADDED) {
		nv_rem_intrs(nvc);
	}

	if (attach_state & ATTACH_PROGRESS_SATA_MODULE) {
		/*
		 * Remove timers
		 */
		int port = 0;
		nv_port_t *nvp;

		for (; port < NV_MAX_PORTS(nvc); port++) {
			nvp = &(nvc->nvc_port[port]);
			if (nvp->nvp_timeout_id != 0) {
				(void) untimeout(nvp->nvp_timeout_id);
			}
		}
	}

	if (attach_state & ATTACH_PROGRESS_MUTEX_INIT) {
		mutex_destroy(&nvc->nvc_mutex);
	}

	if (attach_state & ATTACH_PROGRESS_CTL_SETUP) {
		nv_uninit_ctl(nvc);
	}

	if (attach_state & ATTACH_PROGRESS_BARS) {
		while (--bar >= 0) {
			ddi_regs_map_free(&nvc->nvc_bar_hdl[bar]);
		}
	}

	if (attach_state & ATTACH_PROGRESS_STATEP_ALLOC) {
		ddi_soft_state_free(nv_statep, inst);
	}

	if (attach_state & ATTACH_PROGRESS_CONF_HANDLE) {
		pci_config_teardown(&pci_conf_handle);
	}

	cmn_err(CE_WARN, "nv_sata%d attach failed", inst);

	return (DDI_FAILURE);
}


static int
nv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int i, port, inst = ddi_get_instance(dip);
	nv_ctl_t *nvc;
	nv_port_t *nvp;

	nvc = ddi_get_soft_state(nv_statep, inst);

	switch (cmd) {

	case DDI_DETACH:

		NVLOG((NVDBG_INIT, nvc, NULL, "nv_detach: DDI_DETACH"));

		/*
		 * Remove interrupts
		 */
		nv_rem_intrs(nvc);

		/*
		 * Remove timers
		 */
		for (port = 0; port < NV_MAX_PORTS(nvc); port++) {
			nvp = &(nvc->nvc_port[port]);
			if (nvp->nvp_timeout_id != 0) {
				(void) untimeout(nvp->nvp_timeout_id);
			}
		}

		/*
		 * Remove maps
		 */
		for (i = 0; i < 6; i++) {
			ddi_regs_map_free(&nvc->nvc_bar_hdl[i]);
		}

		/*
		 * Destroy mutexes
		 */
		mutex_destroy(&nvc->nvc_mutex);

		/*
		 * Uninitialize the controller
		 */
		nv_uninit_ctl(nvc);

		/*
		 * unregister from the sata module
		 */
		(void) sata_hba_detach(nvc->nvc_dip, DDI_DETACH);

		/*
		 * Free soft state
		 */
		ddi_soft_state_free(nv_statep, inst);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		/*
		 * The PM functions for suspend and resume are incomplete
		 * and need additional work.  It may or may not work in
		 * the current state.
		 */
		NVLOG((NVDBG_INIT, nvc, NULL, "nv_detach: DDI_SUSPEND"));

		for (i = 0; i < NV_MAX_PORTS(nvc); i++) {
			nv_suspend(&(nvc->nvc_port[i]));
		}

		nvc->nvc_state |= NV_CTRL_SUSPEND;

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


/*ARGSUSED*/
static int
nv_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	nv_ctl_t *nvc;
	int instance;
	dev_t dev;

	dev = (dev_t)arg;
	instance = getminor(dev);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		nvc = ddi_get_soft_state(nv_statep,  instance);
		if (nvc != NULL) {
			*result = nvc->nvc_dip;
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
 * Called by sata module to probe a port.  Port and device state
 * are not changed here... only reported back to the sata module.
 *
 * If probe confirms a device is present for the first time, it will
 * initiate a device reset, then probe will be called again and the
 * signature will be check.  If the signature is valid, data structures
 * will be initialized.
 */
static int
nv_sata_probe(dev_info_t *dip, sata_device_t *sd)
{
	nv_ctl_t *nvc = ddi_get_soft_state(nv_statep, ddi_get_instance(dip));
	uint8_t cport = sd->satadev_addr.cport;
	uint8_t pmport = sd->satadev_addr.pmport;
	uint8_t qual = sd->satadev_addr.qual;
	clock_t nv_lbolt = ddi_get_lbolt();
	nv_port_t *nvp;

	if (cport >= NV_MAX_PORTS(nvc)) {
		sd->satadev_type = SATA_DTYPE_NONE;
		sd->satadev_state = SATA_STATE_UNKNOWN;

		return (SATA_FAILURE);
	}

	ASSERT(nvc->nvc_port != NULL);
	nvp = &(nvc->nvc_port[cport]);
	ASSERT(nvp != NULL);

	NVLOG((NVDBG_PROBE, nvc, nvp,
	    "nv_sata_probe: enter cport: 0x%x, pmport: 0x%x, "
	    "qual: 0x%x", cport, pmport, qual));

	mutex_enter(&nvp->nvp_mutex);

	/*
	 * This check seems to be done in the SATA module.
	 * It may not be required here
	 */
	if (nvp->nvp_state & NV_PORT_INACTIVE) {
		nv_cmn_err(CE_WARN, nvc, nvp,
		    "port inactive.  Use cfgadm to activate");
		sd->satadev_type = SATA_DTYPE_UNKNOWN;
		sd->satadev_state = SATA_PSTATE_SHUTDOWN;
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_FAILURE);
	}

	if (qual == SATA_ADDR_PMPORT) {
		sd->satadev_type = SATA_DTYPE_NONE;
		sd->satadev_state = SATA_STATE_UNKNOWN;
		mutex_exit(&nvp->nvp_mutex);
		nv_cmn_err(CE_WARN, nvc, nvp,
		    "controller does not support port multiplier");

		return (SATA_FAILURE);
	}

	sd->satadev_state = SATA_PSTATE_PWRON;

	nv_copy_registers(nvp, sd, NULL);

	/*
	 * determine link status
	 */
	if (nv_check_link(sd->satadev_scr.sstatus) == B_FALSE) {
		uint8_t det;

		/*
		 * Reset will cause the link to go down for a short period of
		 * time.  If link is lost for less than 2 seconds ignore it
		 * so that the reset can progress.
		 */
		if (nvp->nvp_state & NV_PORT_RESET_PROBE) {

			if (nvp->nvp_link_lost_time == 0) {
				nvp->nvp_link_lost_time = nv_lbolt;
			}

			if (TICK_TO_SEC(nv_lbolt -
			    nvp->nvp_link_lost_time) < NV_LINK_LOST_OK) {
				NVLOG((NVDBG_ALWAYS, nvp->nvp_ctlp, nvp,
				    "probe: intermittent link lost while"
				    " resetting"));
				/*
				 * fake status of link so that probe continues
				 */
				SSTATUS_SET_IPM(sd->satadev_scr.sstatus,
				    SSTATUS_IPM_ACTIVE);
				SSTATUS_SET_DET(sd->satadev_scr.sstatus,
				    SSTATUS_DET_DEVPRE_PHYCOM);
				sd->satadev_type = SATA_DTYPE_UNKNOWN;
				mutex_exit(&nvp->nvp_mutex);

				return (SATA_SUCCESS);
			} else {
				nvp->nvp_state &=
				    ~(NV_PORT_RESET_PROBE|NV_PORT_RESET);
			}
		}

		/*
		 * no link, so tear down port and abort all active packets
		 */

		det = (sd->satadev_scr.sstatus & SSTATUS_DET) >>
		    SSTATUS_DET_SHIFT;

		switch (det) {
		case SSTATUS_DET_NODEV:
		case SSTATUS_DET_PHYOFFLINE:
			sd->satadev_type = SATA_DTYPE_NONE;
			break;
		default:
			sd->satadev_type = SATA_DTYPE_UNKNOWN;
			break;
		}

		NVLOG((NVDBG_PROBE, nvp->nvp_ctlp, nvp,
		    "probe: link lost invoking nv_abort_active"));

		(void) nv_abort_active(nvp, NULL, SATA_PKT_TIMEOUT);
		nv_uninit_port(nvp);

		mutex_exit(&nvp->nvp_mutex);

		return (SATA_SUCCESS);
	} else {
		nvp->nvp_link_lost_time = 0;
	}

	/*
	 * A device is present so clear hotremoved flag
	 */
	nvp->nvp_state &= ~NV_PORT_HOTREMOVED;

	/*
	 * If the signature was acquired previously there is no need to
	 * do it again.
	 */
	if (nvp->nvp_signature != 0) {
		NVLOG((NVDBG_PROBE, nvp->nvp_ctlp, nvp,
		    "probe: signature acquired previously"));
		sd->satadev_type = nvp->nvp_type;
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_SUCCESS);
	}

	/*
	 * If NV_PORT_RESET is not set, this is the first time through
	 * so perform reset and return.
	 */
	if ((nvp->nvp_state & NV_PORT_RESET) == 0) {
		NVLOG((NVDBG_PROBE, nvp->nvp_ctlp, nvp,
		    "probe: first reset to get sig"));
		nvp->nvp_state |= NV_PORT_RESET_PROBE;
		nv_reset(nvp);
		sd->satadev_type = nvp->nvp_type = SATA_DTYPE_UNKNOWN;
		nvp->nvp_probe_time = nv_lbolt;
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_SUCCESS);
	}

	/*
	 * Reset was done previously.  see if the signature is
	 * available.
	 */
	nv_read_signature(nvp);
	sd->satadev_type = nvp->nvp_type;

	/*
	 * Some drives may require additional resets to get a
	 * valid signature.  If a drive was not just powered up, the signature
	 * should arrive within half a second of reset.  Therefore if more
	 * than 5 seconds has elapsed while waiting for a signature, reset
	 * again.  These extra resets do not appear to create problems when
	 * the drive is spinning up for more than this reset period.
	 */
	if (nvp->nvp_signature == 0) {
		if (TICK_TO_SEC(nv_lbolt - nvp->nvp_reset_time) > 5) {
			NVLOG((NVDBG_PROBE, nvc, nvp, "additional reset"
			    " during signature acquisition"));
			nv_reset(nvp);
		}

		mutex_exit(&nvp->nvp_mutex);

		return (SATA_SUCCESS);
	}

	NVLOG((NVDBG_PROBE, nvc, nvp, "signature acquired after %d ms",
	    TICK_TO_MSEC(nv_lbolt - nvp->nvp_probe_time)));

	/*
	 * nv_sata only deals with ATA disks so far.  If it is
	 * not an ATA disk, then just return.
	 */
	if (nvp->nvp_type != SATA_DTYPE_ATADISK) {
		nv_cmn_err(CE_WARN, nvc, nvp, "Driver currently handles only"
		    " disks.  Signature acquired was %X", nvp->nvp_signature);
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_SUCCESS);
	}

	/*
	 * make sure structures are initialized
	 */
	if (nv_init_port(nvp) == NV_SUCCESS) {
		NVLOG((NVDBG_PROBE, nvc, nvp,
		    "device detected and set up at port %d", cport));
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_SUCCESS);
	} else {
		nv_cmn_err(CE_WARN, nvc, nvp, "failed to set up data "
		    "structures for port %d", cport);
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_FAILURE);
	}
	/*NOTREACHED*/
}


/*
 * Called by sata module to start a new command.
 */
static int
nv_sata_start(dev_info_t *dip, sata_pkt_t *spkt)
{
	int cport = spkt->satapkt_device.satadev_addr.cport;
	nv_ctl_t *nvc = ddi_get_soft_state(nv_statep, ddi_get_instance(dip));
	nv_port_t *nvp = &(nvc->nvc_port[cport]);
	int ret;

	NVLOG((NVDBG_ENTRY, nvc, nvp, "nv_sata_start: opmode: 0x%x cmd=%x",
	    spkt->satapkt_op_mode, spkt->satapkt_cmd.satacmd_cmd_reg));

	mutex_enter(&nvp->nvp_mutex);

	/*
	 * hotremoved is an intermediate state where the link was lost,
	 * but the hotplug event has not yet been processed by the sata
	 * module.  Fail the request.
	 */
	if (nvp->nvp_state & NV_PORT_HOTREMOVED) {
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		spkt->satapkt_device.satadev_state = SATA_STATE_UNKNOWN;
		NVLOG((NVDBG_ERRS, nvc, nvp,
		    "nv_sata_start: NV_PORT_HOTREMOVED"));
		nv_copy_registers(nvp, &spkt->satapkt_device, NULL);
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_PORT_ERROR);
	}

	if (nvp->nvp_state & NV_PORT_RESET) {
		NVLOG((NVDBG_ERRS, nvc, nvp,
		    "still waiting for reset completion"));
		spkt->satapkt_reason = SATA_PKT_BUSY;
		mutex_exit(&nvp->nvp_mutex);

		/*
		 * If in panic, timeouts do not occur, so fake one
		 * so that the signature can be acquired to complete
		 * the reset handling.
		 */
		if (ddi_in_panic()) {
			nv_timeout(nvp);
		}

		return (SATA_TRAN_BUSY);
	}

	if (nvp->nvp_type == SATA_DTYPE_NONE) {
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		NVLOG((NVDBG_ERRS, nvc, nvp,
		    "nv_sata_start: SATA_DTYPE_NONE"));
		nv_copy_registers(nvp, &spkt->satapkt_device, NULL);
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_PORT_ERROR);
	}

	if (spkt->satapkt_device.satadev_type == SATA_DTYPE_ATAPICD) {
		ASSERT(nvp->nvp_type == SATA_DTYPE_ATAPICD);
		nv_cmn_err(CE_WARN, nvc, nvp,
		    "optical devices not supported");
		spkt->satapkt_reason = SATA_PKT_CMD_UNSUPPORTED;
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_CMD_UNSUPPORTED);
	}

	if (spkt->satapkt_device.satadev_type == SATA_DTYPE_PMULT) {
		ASSERT(nvp->nvp_type == SATA_DTYPE_PMULT);
		nv_cmn_err(CE_WARN, nvc, nvp,
		    "port multipliers not supported by controller");
		spkt->satapkt_reason = SATA_PKT_CMD_UNSUPPORTED;
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_CMD_UNSUPPORTED);
	}

	if ((nvp->nvp_state & NV_PORT_INIT) == 0) {
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		NVLOG((NVDBG_ERRS, nvc, nvp,
		    "nv_sata_start: port not yet initialized"));
		nv_copy_registers(nvp, &spkt->satapkt_device, NULL);
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_PORT_ERROR);
	}

	if (nvp->nvp_state & NV_PORT_INACTIVE) {
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		NVLOG((NVDBG_ERRS, nvc, nvp,
		    "nv_sata_start: NV_PORT_INACTIVE"));
		nv_copy_registers(nvp, &spkt->satapkt_device, NULL);
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_PORT_ERROR);
	}

	if (nvp->nvp_state & NV_PORT_FAILED) {
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		NVLOG((NVDBG_ERRS, nvc, nvp,
		    "nv_sata_start: NV_PORT_FAILED state"));
		nv_copy_registers(nvp, &spkt->satapkt_device, NULL);
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_PORT_ERROR);
	}

	/*
	 * after a device reset, and then when sata module restore processing
	 * is complete, the sata module will set sata_clear_dev_reset which
	 * indicates that restore processing has completed and normal
	 * non-restore related commands should be processed.
	 */
	if (spkt->satapkt_cmd.satacmd_flags.sata_clear_dev_reset) {
		nvp->nvp_state &= ~NV_PORT_RESTORE;
		NVLOG((NVDBG_ENTRY, nvc, nvp,
		    "nv_sata_start: clearing NV_PORT_RESTORE"));
	}

	/*
	 * if the device was recently reset as indicated by NV_PORT_RESTORE,
	 * only allow commands which restore device state.  The sata module
	 * marks such commands with with sata_ignore_dev_reset.
	 *
	 * during coredump, nv_reset is called and but then the restore
	 * doesn't happen.  For now, workaround by ignoring the wait for
	 * restore if the system is panicing.
	 */
	if ((nvp->nvp_state & NV_PORT_RESTORE) &&
	    !(spkt->satapkt_cmd.satacmd_flags.sata_ignore_dev_reset) &&
	    (ddi_in_panic() == 0)) {
		spkt->satapkt_reason = SATA_PKT_BUSY;
		NVLOG((NVDBG_ENTRY, nvc, nvp,
		    "nv_sata_start: waiting for restore "));
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_BUSY);
	}

	if (nvp->nvp_state & NV_PORT_ABORTING) {
		spkt->satapkt_reason = SATA_PKT_BUSY;
		NVLOG((NVDBG_ERRS, nvc, nvp,
		    "nv_sata_start: NV_PORT_ABORTING"));
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_BUSY);
	}

	if (spkt->satapkt_op_mode &
	    (SATA_OPMODE_POLLING|SATA_OPMODE_SYNCH)) {

		ret = nv_start_sync(nvp, spkt);

		mutex_exit(&nvp->nvp_mutex);

		return (ret);
	}

	/*
	 * start command asynchronous command
	 */
	ret = nv_start_async(nvp, spkt);

	mutex_exit(&nvp->nvp_mutex);

	return (ret);
}


/*
 * SATA_OPMODE_POLLING implies the driver is in a
 * synchronous mode, and SATA_OPMODE_SYNCH is also set.
 * If only SATA_OPMODE_SYNCH is set, the driver can use
 * interrupts and sleep wait on a cv.
 *
 * If SATA_OPMODE_POLLING is set, the driver can't use
 * interrupts and must busy wait and simulate the
 * interrupts by waiting for BSY to be cleared.
 *
 * Synchronous mode has to return BUSY if there are
 * any other commands already on the drive.
 */
static int
nv_start_sync(nv_port_t *nvp, sata_pkt_t *spkt)
{
	nv_ctl_t *nvc = nvp->nvp_ctlp;
	int ret;

	NVLOG((NVDBG_SYNC, nvp->nvp_ctlp, nvp, "nv_sata_satapkt_sync: entry"));

	if (nvp->nvp_ncq_run != 0 || nvp->nvp_non_ncq_run != 0) {
		spkt->satapkt_reason = SATA_PKT_BUSY;
		NVLOG((NVDBG_SYNC, nvp->nvp_ctlp, nvp,
		    "nv_sata_satapkt_sync: device is busy, sync cmd rejected"
		    "ncq_run: %d non_ncq_run: %d  spkt: %p",
		    nvp->nvp_ncq_run, nvp->nvp_non_ncq_run,
		    (&(nvp->nvp_slot[0]))->nvslot_spkt));

		return (SATA_TRAN_BUSY);
	}

	/*
	 * if SYNC but not POLL, verify that this is not on interrupt thread.
	 */
	if (!(spkt->satapkt_op_mode & SATA_OPMODE_POLLING) &&
	    servicing_interrupt()) {
		spkt->satapkt_reason = SATA_PKT_BUSY;
		nv_cmn_err(CE_WARN, nvp->nvp_ctlp, nvp,
		    "SYNC mode not allowed during interrupt");

		return (SATA_TRAN_BUSY);

	}

	/*
	 * disable interrupt generation if in polled mode
	 */
	if (spkt->satapkt_op_mode & SATA_OPMODE_POLLING) {
		(*(nvc->nvc_set_intr))(nvp, NV_INTR_DISABLE);
	}

	if ((ret = nv_start_common(nvp, spkt)) != SATA_TRAN_ACCEPTED) {
		if (spkt->satapkt_op_mode & SATA_OPMODE_POLLING) {
			(*(nvc->nvc_set_intr))(nvp, NV_INTR_ENABLE);
		}

		return (ret);
	}

	if (spkt->satapkt_op_mode & SATA_OPMODE_POLLING) {
		mutex_exit(&nvp->nvp_mutex);
		ret = nv_poll_wait(nvp, spkt);
		mutex_enter(&nvp->nvp_mutex);

		(*(nvc->nvc_set_intr))(nvp, NV_INTR_ENABLE);

		NVLOG((NVDBG_SYNC, nvp->nvp_ctlp, nvp, "nv_sata_satapkt_sync:"
		    " done % reason %d", ret));

		return (ret);
	}

	/*
	 * non-polling synchronous mode handling.  The interrupt will signal
	 * when the IO is completed.
	 */
	cv_wait(&nvp->nvp_poll_cv, &nvp->nvp_mutex);

	if (spkt->satapkt_reason != SATA_PKT_COMPLETED) {

		spkt->satapkt_reason = SATA_PKT_TIMEOUT;
	}

	NVLOG((NVDBG_SYNC, nvp->nvp_ctlp, nvp, "nv_sata_satapkt_sync:"
	    " done % reason %d", spkt->satapkt_reason));

	return (SATA_TRAN_ACCEPTED);
}


static int
nv_poll_wait(nv_port_t *nvp, sata_pkt_t *spkt)
{
	int ret;
	nv_ctl_t *nvc = nvp->nvp_ctlp;
#if ! defined(__lock_lint)
	nv_slot_t *nv_slotp = &(nvp->nvp_slot[0]); /* not NCQ aware */
#endif

	NVLOG((NVDBG_SYNC, nvc, nvp, "nv_poll_wait: enter"));

	for (;;) {

		NV_DELAY_NSEC(400);

		NVLOG((NVDBG_SYNC, nvc, nvp, "nv_poll_wait: before nv_wait"));
		if (nv_wait(nvp, 0, SATA_STATUS_BSY,
		    NV_SEC2USEC(spkt->satapkt_time), NV_NOSLEEP) == B_FALSE) {
			mutex_enter(&nvp->nvp_mutex);
			spkt->satapkt_reason = SATA_PKT_TIMEOUT;
			nv_copy_registers(nvp, &spkt->satapkt_device, spkt);
			nv_reset(nvp);
			nv_complete_io(nvp, spkt, 0);
			mutex_exit(&nvp->nvp_mutex);
			NVLOG((NVDBG_SYNC, nvc, nvp, "nv_poll_wait: "
			    "SATA_STATUS_BSY"));

			return (SATA_TRAN_ACCEPTED);
		}

		NVLOG((NVDBG_SYNC, nvc, nvp, "nv_poll_wait: before nvc_intr"));

		/*
		 * Simulate interrupt.
		 */
		ret = (*(nvc->nvc_interrupt))((caddr_t)nvc, NULL);
		NVLOG((NVDBG_SYNC, nvc, nvp, "nv_poll_wait: after nvc_intr"));

		if (ret != DDI_INTR_CLAIMED) {
			NVLOG((NVDBG_SYNC, nvc, nvp, "nv_poll_wait:"
			    " unclaimed -- resetting"));
			mutex_enter(&nvp->nvp_mutex);
			nv_copy_registers(nvp, &spkt->satapkt_device, spkt);
			nv_reset(nvp);
			spkt->satapkt_reason = SATA_PKT_TIMEOUT;
			nv_complete_io(nvp, spkt, 0);
			mutex_exit(&nvp->nvp_mutex);

			return (SATA_TRAN_ACCEPTED);
		}

#if ! defined(__lock_lint)
		if (nv_slotp->nvslot_flags == NVSLOT_COMPLETE) {
			/*
			 * packet is complete
			 */
			return (SATA_TRAN_ACCEPTED);
		}
#endif
	}
	/*NOTREACHED*/
}


/*
 * Called by sata module to abort outstanding packets.
 */
/*ARGSUSED*/
static int
nv_sata_abort(dev_info_t *dip, sata_pkt_t *spkt, int flag)
{
	int cport = spkt->satapkt_device.satadev_addr.cport;
	nv_ctl_t *nvc = ddi_get_soft_state(nv_statep, ddi_get_instance(dip));
	nv_port_t *nvp = &(nvc->nvc_port[cport]);
	int c_a, ret;

	ASSERT(cport < NV_MAX_PORTS(nvc));
	NVLOG((NVDBG_ENTRY, nvc, nvp, "nv_sata_abort %d %p", flag, spkt));

	mutex_enter(&nvp->nvp_mutex);

	if (nvp->nvp_state & NV_PORT_INACTIVE) {
		mutex_exit(&nvp->nvp_mutex);
		nv_cmn_err(CE_WARN, nvc, nvp,
		    "abort request failed: port inactive");

		return (SATA_FAILURE);
	}

	/*
	 * spkt == NULL then abort all commands
	 */
	c_a = nv_abort_active(nvp, spkt, SATA_PKT_ABORTED);

	if (c_a) {
		NVLOG((NVDBG_ENTRY, nvc, nvp,
		    "packets aborted running=%d", c_a));
		ret = SATA_SUCCESS;
	} else {
		if (spkt == NULL) {
			NVLOG((NVDBG_ENTRY, nvc, nvp, "no spkts to abort"));
		} else {
			NVLOG((NVDBG_ENTRY, nvc, nvp,
			    "can't find spkt to abort"));
		}
		ret = SATA_FAILURE;
	}

	mutex_exit(&nvp->nvp_mutex);

	return (ret);
}


/*
 * if spkt == NULL abort all pkts running, otherwise
 * abort the requested packet.  must be called with nv_mutex
 * held and returns with it held.  Not NCQ aware.
 */
static int
nv_abort_active(nv_port_t *nvp, sata_pkt_t *spkt, int abort_reason)
{
	int aborted = 0, i, reset_once = B_FALSE;
	struct nv_slot *nv_slotp;
	sata_pkt_t *spkt_slot;

	ASSERT(MUTEX_HELD(&nvp->nvp_mutex));

	/*
	 * return if the port is not configured
	 */
	if (nvp->nvp_slot == NULL) {
		NVLOG((NVDBG_ENTRY, nvp->nvp_ctlp, nvp,
		    "nv_abort_active: not configured so returning"));

		return (0);
	}

	NVLOG((NVDBG_ENTRY, nvp->nvp_ctlp, nvp, "nv_abort_active"));

	nvp->nvp_state |= NV_PORT_ABORTING;

	for (i = 0; i < nvp->nvp_queue_depth; i++) {

		nv_slotp = &(nvp->nvp_slot[i]);
		spkt_slot = nv_slotp->nvslot_spkt;

		/*
		 * skip if not active command in slot
		 */
		if (spkt_slot == NULL) {
			continue;
		}

		/*
		 * if a specific packet was requested, skip if
		 * this is not a match
		 */
		if ((spkt != NULL) && (spkt != spkt_slot)) {
			continue;
		}

		/*
		 * stop the hardware.  This could need reworking
		 * when NCQ is enabled in the driver.
		 */
		if (reset_once == B_FALSE) {
			ddi_acc_handle_t bmhdl = nvp->nvp_bm_hdl;

			/*
			 * stop DMA engine
			 */
			nv_put8(bmhdl, nvp->nvp_bmicx,  0);

			nv_reset(nvp);
			reset_once = B_TRUE;
		}

		spkt_slot->satapkt_reason = abort_reason;
		nv_complete_io(nvp, spkt_slot, i);
		aborted++;
	}

	nvp->nvp_state &= ~NV_PORT_ABORTING;

	return (aborted);
}


/*
 * Called by sata module to reset a port, device, or the controller.
 */
static int
nv_sata_reset(dev_info_t *dip, sata_device_t *sd)
{
	int cport = sd->satadev_addr.cport;
	nv_ctl_t *nvc = ddi_get_soft_state(nv_statep, ddi_get_instance(dip));
	nv_port_t *nvp = &(nvc->nvc_port[cport]);
	int ret = SATA_SUCCESS;

	ASSERT(cport < NV_MAX_PORTS(nvc));

	NVLOG((NVDBG_ENTRY, nvc, nvp, "nv_sata_reset"));

	mutex_enter(&nvp->nvp_mutex);

	switch (sd->satadev_addr.qual) {

	case SATA_ADDR_CPORT:
		/*FALLTHROUGH*/
	case SATA_ADDR_DCPORT:
		nv_reset(nvp);
		(void) nv_abort_active(nvp, NULL, SATA_PKT_RESET);

		break;
	case SATA_ADDR_CNTRL:
		NVLOG((NVDBG_ENTRY, nvc, nvp,
		    "nv_sata_reset: constroller reset not supported"));

		break;
	case SATA_ADDR_PMPORT:
	case SATA_ADDR_DPMPORT:
		NVLOG((NVDBG_ENTRY, nvc, nvp,
		    "nv_sata_reset: port multipliers not supported"));
		/*FALLTHROUGH*/
	default:
		/*
		 * unsupported case
		 */
		ret = SATA_FAILURE;
		break;
	}

	if (ret == SATA_SUCCESS) {
		/*
		 * If the port is inactive, do a quiet reset and don't attempt
		 * to wait for reset completion or do any post reset processing
		 */
		if (nvp->nvp_state & NV_PORT_INACTIVE) {
			nvp->nvp_state &= ~NV_PORT_RESET;
			nvp->nvp_reset_time = 0;
		}

		/*
		 * clear the port failed flag
		 */
		nvp->nvp_state &= ~NV_PORT_FAILED;
	}

	mutex_exit(&nvp->nvp_mutex);

	return (ret);
}


/*
 * Sata entry point to handle port activation.  cfgadm -c connect
 */
static int
nv_sata_activate(dev_info_t *dip, sata_device_t *sd)
{
	int cport = sd->satadev_addr.cport;
	nv_ctl_t *nvc = ddi_get_soft_state(nv_statep, ddi_get_instance(dip));
	nv_port_t *nvp = &(nvc->nvc_port[cport]);

	ASSERT(cport < NV_MAX_PORTS(nvc));
	NVLOG((NVDBG_ENTRY, nvc, nvp, "nv_sata_activate"));

	mutex_enter(&nvp->nvp_mutex);

	sd->satadev_state = SATA_STATE_READY;

	nv_copy_registers(nvp, sd, NULL);

	(*(nvc->nvc_set_intr))(nvp, NV_INTR_ENABLE);

	nvp->nvp_state = 0;

	mutex_exit(&nvp->nvp_mutex);

	return (SATA_SUCCESS);
}


/*
 * Sata entry point to handle port deactivation.  cfgadm -c disconnect
 */
static int
nv_sata_deactivate(dev_info_t *dip, sata_device_t *sd)
{
	int cport = sd->satadev_addr.cport;
	nv_ctl_t *nvc = ddi_get_soft_state(nv_statep, ddi_get_instance(dip));
	nv_port_t *nvp = &(nvc->nvc_port[cport]);

	ASSERT(cport < NV_MAX_PORTS(nvc));
	NVLOG((NVDBG_ENTRY, nvc, nvp, "nv_sata_deactivate"));

	mutex_enter(&nvp->nvp_mutex);

	(void) nv_abort_active(nvp, NULL, SATA_PKT_RESET);

	/*
	 * mark the device as inaccessible
	 */
	nvp->nvp_state &= ~NV_PORT_INACTIVE;

	/*
	 * disable the interrupts on port
	 */
	(*(nvc->nvc_set_intr))(nvp, NV_INTR_DISABLE);

	nv_uninit_port(nvp);

	sd->satadev_state = SATA_PSTATE_SHUTDOWN;
	nv_copy_registers(nvp, sd, NULL);

	mutex_exit(&nvp->nvp_mutex);

	return (SATA_SUCCESS);
}


/*
 * find an empty slot in the driver's queue, increment counters,
 * and then invoke the appropriate PIO or DMA start routine.
 */
static int
nv_start_common(nv_port_t *nvp, sata_pkt_t *spkt)
{
	sata_cmd_t *sata_cmdp = &spkt->satapkt_cmd;
	int on_bit = 0x01, slot, sactive, ret, ncq = 0;
	uint8_t cmd = spkt->satapkt_cmd.satacmd_cmd_reg;
	int direction = sata_cmdp->satacmd_flags.sata_data_direction;
	nv_ctl_t *nvc = nvp->nvp_ctlp;
	nv_slot_t *nv_slotp;
	boolean_t dma_cmd;

	NVLOG((NVDBG_DELIVER, nvc, nvp, "nv_start_common  entered: cmd: 0x%x",
	    sata_cmdp->satacmd_cmd_reg));

	if ((cmd == SATAC_WRITE_FPDMA_QUEUED) ||
	    (cmd == SATAC_READ_FPDMA_QUEUED)) {
		nvp->nvp_ncq_run++;
		/*
		 * search for an empty NCQ slot.  by the time, it's already
		 * been determined by the caller that there is room on the
		 * queue.
		 */
		for (slot = 0; slot < nvp->nvp_queue_depth; slot++,
		    on_bit <<= 1) {
			if ((nvp->nvp_sactive_cache & on_bit) == 0) {
				break;
			}
		}

		/*
		 * the first empty slot found, should not exceed the queue
		 * depth of the drive.  if it does it's an error.
		 */
		ASSERT(slot != nvp->nvp_queue_depth);

		sactive = nv_get32(nvc->nvc_bar_hdl[5],
		    nvp->nvp_sactive);
		ASSERT((sactive & on_bit) == 0);
		nv_put32(nvc->nvc_bar_hdl[5], nvp->nvp_sactive, on_bit);
		NVLOG((NVDBG_INIT, nvc, nvp, "setting SACTIVE onbit: %X",
		    on_bit));
		nvp->nvp_sactive_cache |= on_bit;

		ncq = NVSLOT_NCQ;

	} else {
		nvp->nvp_non_ncq_run++;
		slot = 0;
	}

	nv_slotp = (nv_slot_t *)&nvp->nvp_slot[slot];

	ASSERT(nv_slotp->nvslot_spkt == NULL);

	nv_slotp->nvslot_spkt = spkt;
	nv_slotp->nvslot_flags = ncq;

	/*
	 * the sata module doesn't indicate which commands utilize the
	 * DMA engine, so find out using this switch table.
	 */
	switch (spkt->satapkt_cmd.satacmd_cmd_reg) {
	case SATAC_READ_DMA_EXT:
	case SATAC_WRITE_DMA_EXT:
	case SATAC_WRITE_DMA:
	case SATAC_READ_DMA:
	case SATAC_READ_DMA_QUEUED:
	case SATAC_READ_DMA_QUEUED_EXT:
	case SATAC_WRITE_DMA_QUEUED:
	case SATAC_WRITE_DMA_QUEUED_EXT:
	case SATAC_READ_FPDMA_QUEUED:
	case SATAC_WRITE_FPDMA_QUEUED:
		dma_cmd = B_TRUE;
		break;
	default:
		dma_cmd = B_FALSE;
	}

	if (sata_cmdp->satacmd_num_dma_cookies != 0 && dma_cmd == B_TRUE) {
		NVLOG((NVDBG_DELIVER, nvc,  nvp, "DMA command"));
		nv_slotp->nvslot_start = nv_start_dma;
		nv_slotp->nvslot_intr = nv_intr_dma;
	} else if (direction == SATA_DIR_NODATA_XFER) {
		NVLOG((NVDBG_DELIVER, nvc, nvp, "non-data command"));
		nv_slotp->nvslot_start = nv_start_nodata;
		nv_slotp->nvslot_intr = nv_intr_nodata;
	} else if (direction == SATA_DIR_READ) {
		NVLOG((NVDBG_DELIVER, nvc, nvp, "pio in command"));
		nv_slotp->nvslot_start = nv_start_pio_in;
		nv_slotp->nvslot_intr = nv_intr_pio_in;
		nv_slotp->nvslot_byte_count =
		    spkt->satapkt_cmd.satacmd_bp->b_bcount;
		nv_slotp->nvslot_v_addr =
		    spkt->satapkt_cmd.satacmd_bp->b_un.b_addr;
	} else if (direction == SATA_DIR_WRITE) {
		NVLOG((NVDBG_DELIVER, nvc, nvp, "pio out command"));
		nv_slotp->nvslot_start = nv_start_pio_out;
		nv_slotp->nvslot_intr = nv_intr_pio_out;
		nv_slotp->nvslot_byte_count =
		    spkt->satapkt_cmd.satacmd_bp->b_bcount;
		nv_slotp->nvslot_v_addr =
		    spkt->satapkt_cmd.satacmd_bp->b_un.b_addr;
	} else {
		nv_cmn_err(CE_WARN, nvc, nvp, "malformed command: direction"
		    " %d cookies %d cmd %x",
		    sata_cmdp->satacmd_flags.sata_data_direction,
		    sata_cmdp->satacmd_num_dma_cookies,  cmd);
		spkt->satapkt_reason = SATA_PKT_CMD_UNSUPPORTED;
		ret = SATA_TRAN_CMD_UNSUPPORTED;

		goto fail;
	}

	if ((ret = (*nv_slotp->nvslot_start)(nvp, slot)) ==
	    SATA_TRAN_ACCEPTED) {
		nv_slotp->nvslot_stime = ddi_get_lbolt();

		/*
		 * start timer if it's not already running and this packet
		 * is not requesting polled mode.
		 */
		if ((nvp->nvp_timeout_id == 0) &&
		    ((spkt->satapkt_op_mode & SATA_OPMODE_POLLING) == 0)) {
			nvp->nvp_timeout_id = timeout(nv_timeout, (void *)nvp,
			    drv_usectohz(NV_ONE_SEC));
		}

		return (SATA_TRAN_ACCEPTED);
	}

	fail:

	spkt->satapkt_reason = SATA_TRAN_PORT_ERROR;

	if (ncq == NVSLOT_NCQ) {
		nvp->nvp_ncq_run--;
		nvp->nvp_sactive_cache &= ~on_bit;
	} else {
		nvp->nvp_non_ncq_run--;
	}
	nv_slotp->nvslot_spkt = NULL;
	nv_slotp->nvslot_flags = 0;

	return (ret);
}


/*
 * Check if the signature is ready and if non-zero translate
 * it into a solaris sata defined type.
 */
static void
nv_read_signature(nv_port_t *nvp)
{
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;

	nvp->nvp_signature = nv_get8(cmdhdl, nvp->nvp_count);
	nvp->nvp_signature |= (nv_get8(cmdhdl, nvp->nvp_sect) << 8);
	nvp->nvp_signature |= (nv_get8(cmdhdl, nvp->nvp_lcyl) << 16);
	nvp->nvp_signature |= (nv_get8(cmdhdl, nvp->nvp_hcyl) << 24);

	switch (nvp->nvp_signature) {

	case NV_SIG_DISK:
		NVLOG((NVDBG_INIT, nvp->nvp_ctlp, nvp, "drive is a disk"));
		nvp->nvp_type = SATA_DTYPE_ATADISK;
		break;
	case NV_SIG_ATAPI:
		NVLOG((NVDBG_INIT, nvp->nvp_ctlp, nvp,
		    "drive is an optical device"));
		nvp->nvp_type = SATA_DTYPE_ATAPICD;
		break;
	case NV_SIG_PM:
		NVLOG((NVDBG_INIT, nvp->nvp_ctlp, nvp,
		    "device is a port multiplier"));
		nvp->nvp_type = SATA_DTYPE_PMULT;
		break;
	case NV_SIG_NOTREADY:
		NVLOG((NVDBG_INIT, nvp->nvp_ctlp, nvp,
		    "signature not ready"));
		nvp->nvp_type = SATA_DTYPE_UNKNOWN;
		break;
	default:
		nv_cmn_err(CE_WARN, nvp->nvp_ctlp, nvp, "signature %X not"
		    " recognized", nvp->nvp_signature);
		nvp->nvp_type = SATA_DTYPE_UNKNOWN;
		break;
	}

	if (nvp->nvp_signature) {
		nvp->nvp_state &= ~(NV_PORT_RESET_PROBE|NV_PORT_RESET);
	}
}


/*
 * Reset the port
 */
static void
nv_reset(nv_port_t *nvp)
{
	ddi_acc_handle_t bar5_hdl = nvp->nvp_ctlp->nvc_bar_hdl[5];
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
	nv_ctl_t *nvc = nvp->nvp_ctlp;
	uint32_t sctrl;

	NVLOG((NVDBG_ENTRY, nvc, nvp, "nv_reset()"));

	ASSERT(mutex_owned(&nvp->nvp_mutex));

	/*
	 * clear signature registers
	 */
	nv_put8(cmdhdl, nvp->nvp_sect, 0);
	nv_put8(cmdhdl, nvp->nvp_lcyl, 0);
	nv_put8(cmdhdl, nvp->nvp_hcyl, 0);
	nv_put8(cmdhdl, nvp->nvp_count, 0);

	nvp->nvp_signature = 0;
	nvp->nvp_type = 0;
	nvp->nvp_state |= NV_PORT_RESET;
	nvp->nvp_reset_time = ddi_get_lbolt();
	nvp->nvp_link_lost_time = 0;

	/*
	 * assert reset in PHY by writing a 1 to bit 0 scontrol
	 */
	sctrl = nv_get32(bar5_hdl, nvp->nvp_sctrl);

	nv_put32(bar5_hdl, nvp->nvp_sctrl, sctrl | SCONTROL_DET_COMRESET);

	/*
	 * wait 1ms
	 */
	drv_usecwait(1000);

	/*
	 * de-assert reset in PHY
	 */
	nv_put32(bar5_hdl, nvp->nvp_sctrl, sctrl);

	/*
	 * make sure timer is running
	 */
	if (nvp->nvp_timeout_id == 0) {
		nvp->nvp_timeout_id = timeout(nv_timeout, (void *)nvp,
		    drv_usectohz(NV_ONE_SEC));
	}
}


/*
 * Initialize register handling specific to mcp55
 */
/* ARGSUSED */
static void
mcp55_reg_init(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle)
{
	nv_port_t *nvp;
	uchar_t *bar5  = nvc->nvc_bar_addr[5];
	uint8_t off, port;

	nvc->nvc_mcp55_ctl = (uint32_t *)(bar5 + MCP55_CTL);
	nvc->nvc_mcp55_ncq = (uint32_t *)(bar5 + MCP55_NCQ);

	for (port = 0, off = 0; port < NV_MAX_PORTS(nvc); port++, off += 2) {
		nvp = &(nvc->nvc_port[port]);
		nvp->nvp_mcp55_int_status =
		    (uint16_t *)(bar5 + MCP55_INT_STATUS + off);
		nvp->nvp_mcp55_int_ctl =
		    (uint16_t *)(bar5 + MCP55_INT_CTL + off);

		/*
		 * clear any previous interrupts asserted
		 */
		nv_put16(nvc->nvc_bar_hdl[5], nvp->nvp_mcp55_int_status,
		    MCP55_INT_CLEAR);

		/*
		 * These are the interrupts to accept for now.  The spec
		 * says these are enable bits, but nvidia has indicated
		 * these are masking bits.  Even though they may be masked
		 * out to prevent asserting the main interrupt, they can
		 * still be asserted while reading the interrupt status
		 * register, so that needs to be considered in the interrupt
		 * handler.
		 */
		nv_put16(nvc->nvc_bar_hdl[5], nvp->nvp_mcp55_int_ctl,
		    ~(MCP55_INT_IGNORE));
	}

	/*
	 * Allow the driver to program the BM on the first command instead
	 * of waiting for an interrupt.
	 */
#ifdef NCQ
	flags = MCP_SATA_AE_NCQ_PDEV_FIRST_CMD | MCP_SATA_AE_NCQ_SDEV_FIRST_CMD;
	nv_put32(nvc->nvc_bar_hdl[5], nvc->nvc_mcp55_ncq, flags);
	flags = MCP_SATA_AE_CTL_PRI_SWNCQ | MCP_SATA_AE_CTL_SEC_SWNCQ;
	nv_put32(nvc->nvc_bar_hdl[5], nvc->nvc_mcp55_ctl, flags);
#endif


#if 0
	/*
	 * This caused problems on some but not all mcp55 based systems.
	 * DMA writes would never complete.  This happens even on small
	 * mem systems, and only setting NV_40BIT_PRD below and not
	 * buffer_dma_attr.dma_attr_addr_hi, so it seems to be a hardware
	 * issue that needs further investigation.
	 */

	/*
	 * mcp55 rev A03 and above supports 40-bit physical addressing.
	 * Enable DMA to take advantage of that.
	 *
	 */
	if (nvc->nvc_revid >= 0xa3) {
		uint32_t reg32;
		NVLOG((NVDBG_INIT, nvp->nvp_ctlp, nvp, "rev id is %X and"
		    " is capable of 40-bit addressing", nvc->nvc_revid));
		buffer_dma_attr.dma_attr_addr_hi = 0xffffffffffull;
		reg32 = pci_config_get32(pci_conf_handle, NV_SATA_CFG_20);
		pci_config_put32(pci_conf_handle, NV_SATA_CFG_20,
		    reg32 |NV_40BIT_PRD);
	} else {
		NVLOG((NVDBG_INIT, nvp->nvp_ctlp, nvp, "rev is %X and is "
		    "not capable of 40-bit addressing", nvc->nvc_revid));
	}
#endif

}


/*
 * Initialize register handling specific to mcp04
 */
static void
mcp04_reg_init(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle)
{
	uchar_t *bar5  = nvc->nvc_bar_addr[5];
	uint32_t reg32;
	uint16_t reg16;
	nv_port_t *nvp;
	int j;

	/*
	 * delay hotplug interrupts until PHYRDY.
	 */
	reg32 = pci_config_get32(pci_conf_handle, NV_SATA_CFG_42);
	pci_config_put32(pci_conf_handle, NV_SATA_CFG_42,
	    reg32 | MCP04_CFG_DELAY_HOTPLUG_INTR);

	/*
	 * enable hot plug interrupts for channel x and y
	 */
	reg16 = nv_get16(nvc->nvc_bar_hdl[5],
	    (uint16_t *)(bar5 + NV_ADMACTL_X));
	nv_put16(nvc->nvc_bar_hdl[5], (uint16_t *)(bar5 + NV_ADMACTL_X),
	    NV_HIRQ_EN | reg16);


	reg16 = nv_get16(nvc->nvc_bar_hdl[5],
	    (uint16_t *)(bar5 + NV_ADMACTL_Y));
	nv_put16(nvc->nvc_bar_hdl[5], (uint16_t *)(bar5 + NV_ADMACTL_Y),
	    NV_HIRQ_EN | reg16);

	nvc->nvc_mcp04_int_status = (uint8_t *)(bar5 + MCP04_SATA_INT_STATUS);

	/*
	 * clear any existing interrupt pending then enable
	 */
	for (j = 0; j < NV_MAX_PORTS(nvc); j++) {
		nvp = &(nvc->nvc_port[j]);
		mutex_enter(&nvp->nvp_mutex);
		(*(nvp->nvp_ctlp->nvc_set_intr))(nvp,
		    NV_INTR_CLEAR_ALL|NV_INTR_ENABLE);
		mutex_exit(&nvp->nvp_mutex);
	}
}


/*
 * Initialize the controller and set up driver data structures.
 * determine if ck804 or mcp55 class.
 */
static int
nv_init_ctl(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle)
{
	struct sata_hba_tran stran;
	nv_port_t *nvp;
	int j, ck804 = B_TRUE;
	uchar_t *cmd_addr, *ctl_addr, *bm_addr;
	ddi_acc_handle_t bar5_hdl = nvc->nvc_bar_hdl[5];
	uchar_t *bar5  = nvc->nvc_bar_addr[5];
	uint32_t reg32;
	uint8_t reg8, reg8_save;

	NVLOG((NVDBG_INIT, nvc, NULL, "nv_init_ctl entered"));

	/*
	 * Need to set bit 2 to 1 at config offset 0x50
	 * to enable access to the bar5 registers.
	 */
	reg32 = pci_config_get32(pci_conf_handle, NV_SATA_CFG_20);
	pci_config_put32(pci_conf_handle, NV_SATA_CFG_20,
	    reg32 | NV_BAR5_SPACE_EN);

	/*
	 * Determine if this is ck804 or mcp55.  ck804 will map in the
	 * task file registers into bar5 while mcp55 won't.  The offset of
	 * the task file registers in mcp55's space is unused, so it will
	 * return zero.  So check one of the task file registers to see if it is
	 * writable and reads back what was written.  If it's mcp55 it will
	 * return back 0xff whereas ck804 will return the value written.
	 */
	reg8_save = nv_get8(bar5_hdl,
	    (uint8_t *)(bar5 + NV_BAR5_TRAN_LEN_CH_X));


	for (j = 1; j < 3; j++) {

		nv_put8(bar5_hdl, (uint8_t *)(bar5 + NV_BAR5_TRAN_LEN_CH_X), j);
		reg8 = nv_get8(bar5_hdl,
		    (uint8_t *)(bar5 + NV_BAR5_TRAN_LEN_CH_X));

		if (reg8 != j) {
			ck804 = B_FALSE;
			break;
		}
	}

	nv_put8(bar5_hdl, (uint8_t *)(bar5 + NV_BAR5_TRAN_LEN_CH_X), reg8_save);

	if (ck804 == B_TRUE) {
		NVLOG((NVDBG_INIT, nvc, NULL, "controller is CK804"));
		nvc->nvc_interrupt = mcp04_intr;
		nvc->nvc_reg_init = mcp04_reg_init;
		nvc->nvc_set_intr = mcp04_set_intr;
	} else {
		NVLOG((NVDBG_INIT, nvc, NULL, "controller is MCP55"));
		nvc->nvc_interrupt = mcp55_intr;
		nvc->nvc_reg_init = mcp55_reg_init;
		nvc->nvc_set_intr = mcp55_set_intr;
	}


	stran.sata_tran_hba_rev = SATA_TRAN_HBA_REV;
	stran.sata_tran_hba_dip = nvc->nvc_dip;
	stran.sata_tran_hba_dma_attr = &buffer_dma_attr;
	stran.sata_tran_hba_num_cports = NV_NUM_CPORTS;
	stran.sata_tran_hba_features_support =
	    SATA_CTLF_HOTPLUG | SATA_CTLF_ASN;
	stran.sata_tran_hba_qdepth = NV_QUEUE_SLOTS;
	stran.sata_tran_probe_port = nv_sata_probe;
	stran.sata_tran_start = nv_sata_start;
	stran.sata_tran_abort = nv_sata_abort;
	stran.sata_tran_reset_dport = nv_sata_reset;
	stran.sata_tran_selftest = NULL;
	stran.sata_tran_hotplug_ops = &nv_hotplug_ops;
	stran.sata_tran_pwrmgt_ops = NULL;
	stran.sata_tran_ioctl = NULL;
	nvc->nvc_sata_hba_tran = stran;

	nvc->nvc_port = kmem_zalloc(sizeof (nv_port_t) * NV_MAX_PORTS(nvc),
	    KM_SLEEP);

	/*
	 * initialize registers common to all chipsets
	 */
	nv_common_reg_init(nvc);

	for (j = 0; j < NV_MAX_PORTS(nvc); j++) {
		nvp = &(nvc->nvc_port[j]);

		cmd_addr = nvp->nvp_cmd_addr;
		ctl_addr = nvp->nvp_ctl_addr;
		bm_addr = nvp->nvp_bm_addr;

		mutex_init(&nvp->nvp_mutex, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(nvc->nvc_intr_pri));

		cv_init(&nvp->nvp_poll_cv, NULL, CV_DRIVER, NULL);

		nvp->nvp_data	= cmd_addr + NV_DATA;
		nvp->nvp_error	= cmd_addr + NV_ERROR;
		nvp->nvp_feature = cmd_addr + NV_FEATURE;
		nvp->nvp_count	= cmd_addr + NV_COUNT;
		nvp->nvp_sect	= cmd_addr + NV_SECT;
		nvp->nvp_lcyl	= cmd_addr + NV_LCYL;
		nvp->nvp_hcyl	= cmd_addr + NV_HCYL;
		nvp->nvp_drvhd	= cmd_addr + NV_DRVHD;
		nvp->nvp_status	= cmd_addr + NV_STATUS;
		nvp->nvp_cmd	= cmd_addr + NV_CMD;
		nvp->nvp_altstatus = ctl_addr + NV_ALTSTATUS;
		nvp->nvp_devctl	= ctl_addr + NV_DEVCTL;

		nvp->nvp_bmicx	= bm_addr + BMICX_REG;
		nvp->nvp_bmisx	= bm_addr + BMISX_REG;
		nvp->nvp_bmidtpx = (uint32_t *)(bm_addr + BMIDTPX_REG);

		nvp->nvp_state = 0;
	}

	/*
	 * initialize register by calling chip specific reg initialization
	 */
	(*(nvc->nvc_reg_init))(nvc, pci_conf_handle);

	return (NV_SUCCESS);
}


/*
 * Initialize data structures with enough slots to handle queuing, if
 * enabled.  NV_QUEUE_SLOTS will be set to 1 or 32, depending on whether
 * NCQ support is built into the driver and enabled.  It might have been
 * better to derive the true size from the drive itself, but the sata
 * module only sends down that information on the first NCQ command,
 * which means possibly re-sizing the structures on an interrupt stack,
 * making error handling more messy.  The easy way is to just allocate
 * all 32 slots, which is what most drives support anyway.
 */
static int
nv_init_port(nv_port_t *nvp)
{
	nv_ctl_t *nvc = nvp->nvp_ctlp;
	size_t	prd_size = sizeof (prde_t) * NV_DMA_NSEGS;
	dev_info_t *dip = nvc->nvc_dip;
	ddi_device_acc_attr_t dev_attr;
	size_t buf_size;
	ddi_dma_cookie_t cookie;
	uint_t count;
	int rc, i;

	dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	dev_attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (nvp->nvp_state & NV_PORT_INIT) {
		NVLOG((NVDBG_INIT, nvc, nvp,
		    "nv_init_port previously initialized"));

		return (NV_SUCCESS);
	} else {
		NVLOG((NVDBG_INIT, nvc, nvp, "nv_init_port initializing"));
	}

	nvp->nvp_sg_dma_hdl = kmem_zalloc(sizeof (ddi_dma_handle_t) *
	    NV_QUEUE_SLOTS, KM_SLEEP);

	nvp->nvp_sg_acc_hdl = kmem_zalloc(sizeof (ddi_acc_handle_t) *
	    NV_QUEUE_SLOTS, KM_SLEEP);

	nvp->nvp_sg_addr = kmem_zalloc(sizeof (caddr_t) *
	    NV_QUEUE_SLOTS, KM_SLEEP);

	nvp->nvp_sg_paddr = kmem_zalloc(sizeof (uint32_t) *
	    NV_QUEUE_SLOTS, KM_SLEEP);

	nvp->nvp_slot = kmem_zalloc(sizeof (nv_slot_t) * NV_QUEUE_SLOTS,
	    KM_SLEEP);

	for (i = 0; i < NV_QUEUE_SLOTS; i++) {

		rc = ddi_dma_alloc_handle(dip, &nv_prd_dma_attr,
		    DDI_DMA_SLEEP, NULL, &(nvp->nvp_sg_dma_hdl[i]));

		if (rc != DDI_SUCCESS) {
			nv_uninit_port(nvp);

			return (NV_FAILURE);
		}

		rc = ddi_dma_mem_alloc(nvp->nvp_sg_dma_hdl[i], prd_size,
		    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
		    NULL, &(nvp->nvp_sg_addr[i]), &buf_size,
		    &(nvp->nvp_sg_acc_hdl[i]));

		if (rc != DDI_SUCCESS) {
			nv_uninit_port(nvp);

			return (NV_FAILURE);
		}

		rc = ddi_dma_addr_bind_handle(nvp->nvp_sg_dma_hdl[i], NULL,
		    nvp->nvp_sg_addr[i], buf_size,
		    DDI_DMA_WRITE | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP, NULL, &cookie, &count);

		if (rc != DDI_DMA_MAPPED) {
			nv_uninit_port(nvp);

			return (NV_FAILURE);
		}

		ASSERT(count == 1);
		ASSERT((cookie.dmac_address & (sizeof (int) - 1)) == 0);

		ASSERT(cookie.dmac_laddress <= UINT32_MAX);

		nvp->nvp_sg_paddr[i] = cookie.dmac_address;
	}

	/*
	 * nvp_queue_depth represents the actual drive queue depth, not the
	 * number of slots allocated in the structures (which may be more).
	 * Actual queue depth is only learned after the first NCQ command, so
	 * initialize it to 1 for now.
	 */
	nvp->nvp_queue_depth = 1;

	nvp->nvp_state |= NV_PORT_INIT;

	return (NV_SUCCESS);
}


/*
 * Free dynamically allocated structures for port.
 */
static void
nv_uninit_port(nv_port_t *nvp)
{
	int i;

	/*
	 * It is possible to reach here before a port has been initialized or
	 * after it has already been uninitialized.  Just return in that case.
	 */
	if (nvp->nvp_slot == NULL) {

		return;
	}

	NVLOG((NVDBG_INIT, nvp->nvp_ctlp, nvp,
	    "nv_uninit_port uninitializing"));

	nvp->nvp_type = SATA_DTYPE_NONE;

	for (i = 0; i < NV_QUEUE_SLOTS; i++) {
		if (nvp->nvp_sg_paddr[i]) {
			(void) ddi_dma_unbind_handle(nvp->nvp_sg_dma_hdl[i]);
		}

		if (nvp->nvp_sg_acc_hdl[i] != NULL) {
			ddi_dma_mem_free(&(nvp->nvp_sg_acc_hdl[i]));
		}

		if (nvp->nvp_sg_dma_hdl[i] != NULL) {
			ddi_dma_free_handle(&(nvp->nvp_sg_dma_hdl[i]));
		}
	}

	kmem_free(nvp->nvp_slot, sizeof (nv_slot_t) * NV_QUEUE_SLOTS);
	nvp->nvp_slot = NULL;

	kmem_free(nvp->nvp_sg_dma_hdl,
	    sizeof (ddi_dma_handle_t) * NV_QUEUE_SLOTS);
	nvp->nvp_sg_dma_hdl = NULL;

	kmem_free(nvp->nvp_sg_acc_hdl,
	    sizeof (ddi_acc_handle_t) * NV_QUEUE_SLOTS);
	nvp->nvp_sg_acc_hdl = NULL;

	kmem_free(nvp->nvp_sg_addr, sizeof (caddr_t) * NV_QUEUE_SLOTS);
	nvp->nvp_sg_addr = NULL;

	kmem_free(nvp->nvp_sg_paddr, sizeof (uint32_t) * NV_QUEUE_SLOTS);
	nvp->nvp_sg_paddr = NULL;

	nvp->nvp_state &= ~NV_PORT_INIT;
	nvp->nvp_signature = 0;
}


/*
 * Cache register offsets and access handles to frequently accessed registers
 * which are common to either chipset.
 */
static void
nv_common_reg_init(nv_ctl_t *nvc)
{
	uchar_t *bar5_addr = nvc->nvc_bar_addr[5];
	uchar_t *bm_addr_offset, *sreg_offset;
	uint8_t bar, port;
	nv_port_t *nvp;

	for (port = 0; port < NV_MAX_PORTS(nvc); port++) {
		if (port == 0) {
			bar = NV_BAR_0;
			bm_addr_offset = 0;
			sreg_offset = (uchar_t *)(CH0_SREG_OFFSET + bar5_addr);
		} else {
			bar = NV_BAR_2;
			bm_addr_offset = (uchar_t *)8;
			sreg_offset = (uchar_t *)(CH1_SREG_OFFSET + bar5_addr);
		}

		nvp = &(nvc->nvc_port[port]);
		nvp->nvp_ctlp = nvc;
		nvp->nvp_port_num = port;
		NVLOG((NVDBG_INIT, nvc, nvp, "setting up port mappings"));

		nvp->nvp_cmd_hdl = nvc->nvc_bar_hdl[bar];
		nvp->nvp_cmd_addr = nvc->nvc_bar_addr[bar];
		nvp->nvp_ctl_hdl = nvc->nvc_bar_hdl[bar + 1];
		nvp->nvp_ctl_addr = nvc->nvc_bar_addr[bar + 1];
		nvp->nvp_bm_hdl = nvc->nvc_bar_hdl[NV_BAR_4];
		nvp->nvp_bm_addr = nvc->nvc_bar_addr[NV_BAR_4] +
		    (long)bm_addr_offset;

		nvp->nvp_sstatus = (uint32_t *)(sreg_offset + NV_SSTATUS);
		nvp->nvp_serror = (uint32_t *)(sreg_offset + NV_SERROR);
		nvp->nvp_sactive = (uint32_t *)(sreg_offset + NV_SACTIVE);
		nvp->nvp_sctrl = (uint32_t *)(sreg_offset + NV_SCTRL);
	}
}


static void
nv_uninit_ctl(nv_ctl_t *nvc)
{
	int port;
	nv_port_t *nvp;

	NVLOG((NVDBG_INIT, nvc, NULL, "nv_uninit_ctl entered"));

	for (port = 0; port < NV_MAX_PORTS(nvc); port++) {
		nvp = &(nvc->nvc_port[port]);
		mutex_enter(&nvp->nvp_mutex);
		NVLOG((NVDBG_INIT, nvc, nvp, "uninitializing port"));
		nv_uninit_port(nvp);
		mutex_exit(&nvp->nvp_mutex);
		mutex_destroy(&nvp->nvp_mutex);
		cv_destroy(&nvp->nvp_poll_cv);
	}

	kmem_free(nvc->nvc_port, NV_MAX_PORTS(nvc) * sizeof (nv_port_t));
	nvc->nvc_port = NULL;
}


/*
 * mcp04 interrupt.  This is a wrapper around mcp04_intr_process so
 * that interrupts from other devices can be disregarded while dtracing.
 */
/* ARGSUSED */
static uint_t
mcp04_intr(caddr_t arg1, caddr_t arg2)
{
	nv_ctl_t *nvc = (nv_ctl_t *)arg1;
	uint8_t intr_status;
	ddi_acc_handle_t bar5_hdl = nvc->nvc_bar_hdl[5];

	intr_status = ddi_get8(bar5_hdl, nvc->nvc_mcp04_int_status);

	if (intr_status == 0) {

		return (DDI_INTR_UNCLAIMED);
	}

	mcp04_intr_process(nvc, intr_status);

	return (DDI_INTR_CLAIMED);
}


/*
 * Main interrupt handler for ck804.  handles normal device
 * interrupts as well as port hot plug and remove interrupts.
 *
 */
static void
mcp04_intr_process(nv_ctl_t *nvc, uint8_t intr_status)
{

	int port, i;
	nv_port_t *nvp;
	nv_slot_t *nv_slotp;
	uchar_t	status;
	sata_pkt_t *spkt;
	uint8_t bmstatus, clear_bits;
	ddi_acc_handle_t bmhdl;
	int nvcleared = 0;
	ddi_acc_handle_t bar5_hdl = nvc->nvc_bar_hdl[5];
	uint32_t sstatus;
	int port_mask_hot[] = {
		MCP04_INT_PDEV_HOT, MCP04_INT_SDEV_HOT,
	};
	int port_mask_pm[] = {
		MCP04_INT_PDEV_PM, MCP04_INT_SDEV_PM,
	};

	NVLOG((NVDBG_INTR, nvc, NULL,
	    "mcp04_intr_process entered intr_status=%x", intr_status));

	/*
	 * For command completion interrupt, explicit clear is not required.
	 * however, for the error cases explicit clear is performed.
	 */
	for (port = 0; port < NV_MAX_PORTS(nvc); port++) {

		int port_mask[] = {MCP04_INT_PDEV_INT, MCP04_INT_SDEV_INT};

		if ((port_mask[port] & intr_status) == 0) {
			continue;
		}

		NVLOG((NVDBG_INTR, nvc, NULL,
		    "mcp04_intr_process interrupt on port %d", port));

		nvp = &(nvc->nvc_port[port]);

		mutex_enter(&nvp->nvp_mutex);

		/*
		 * there was a corner case found where an interrupt
		 * arrived before nvp_slot was set.  Should
		 * probably should track down why that happens and try
		 * to eliminate that source and then get rid of this
		 * check.
		 */
		if (nvp->nvp_slot == NULL) {
			status = nv_get8(nvp->nvp_ctl_hdl, nvp->nvp_status);
			NVLOG((NVDBG_ALWAYS, nvc, nvp, "spurious interrupt "
			    "received before initialization "
			    "completed status=%x", status));
			mutex_exit(&nvp->nvp_mutex);

			/*
			 * clear interrupt bits
			 */
			nv_put8(bar5_hdl, nvc->nvc_mcp04_int_status,
			    port_mask[port]);

			continue;
		}

		if ((&(nvp->nvp_slot[0]))->nvslot_spkt == NULL)  {
			status = nv_get8(nvp->nvp_ctl_hdl, nvp->nvp_status);
			NVLOG((NVDBG_ALWAYS, nvc, nvp, "spurious interrupt "
			    " no command in progress status=%x", status));
			mutex_exit(&nvp->nvp_mutex);

			/*
			 * clear interrupt bits
			 */
			nv_put8(bar5_hdl, nvc->nvc_mcp04_int_status,
			    port_mask[port]);

			continue;
		}

		bmhdl = nvp->nvp_bm_hdl;
		bmstatus = nv_get8(bmhdl, nvp->nvp_bmisx);

		if (!(bmstatus & BMISX_IDEINTS)) {
			mutex_exit(&nvp->nvp_mutex);

			continue;
		}

		status = nv_get8(nvp->nvp_ctl_hdl, nvp->nvp_altstatus);

		if (status & SATA_STATUS_BSY) {
			mutex_exit(&nvp->nvp_mutex);

			continue;
		}

		nv_slotp = &(nvp->nvp_slot[0]);

		ASSERT(nv_slotp);

		spkt = nv_slotp->nvslot_spkt;

		if (spkt == NULL) {
			mutex_exit(&nvp->nvp_mutex);

			continue;
		}

		(*nv_slotp->nvslot_intr)(nvp, nv_slotp);

		nv_copy_registers(nvp, &spkt->satapkt_device, spkt);

		/*
		 * If there is no link cannot be certain about the completion
		 * of the packet, so abort it.
		 */
		if (nv_check_link((&spkt->satapkt_device)->
		    satadev_scr.sstatus) == B_FALSE) {

			(void) nv_abort_active(nvp, NULL, SATA_PKT_PORT_ERROR);

		} else if (nv_slotp->nvslot_flags == NVSLOT_COMPLETE) {

			nv_complete_io(nvp, spkt, 0);
		}

		mutex_exit(&nvp->nvp_mutex);
	}

	/*
	 * mcp04 often doesn't correctly distinguish hot add/remove
	 * interrupts.  Frequently both the ADD and the REMOVE bits
	 * are asserted, whether it was a remove or add.  Use sstatus
	 * to distinguish hot add from hot remove.
	 */

	for (port = 0; port < NV_MAX_PORTS(nvc); port++) {
		clear_bits = 0;

		nvp = &(nvc->nvc_port[port]);
		mutex_enter(&nvp->nvp_mutex);

		if ((port_mask_pm[port] & intr_status) != 0) {
			clear_bits = port_mask_pm[port];
			NVLOG((NVDBG_HOT, nvc, nvp,
			    "clearing PM interrupt bit: %x",
			    intr_status & port_mask_pm[port]));
		}

		if ((port_mask_hot[port] & intr_status) == 0) {
			if (clear_bits != 0) {
				goto clear;
			} else {
				mutex_exit(&nvp->nvp_mutex);
				continue;
			}
		}

		/*
		 * reaching here means there was a hot add or remove.
		 */
		clear_bits |= port_mask_hot[port];

		ASSERT(nvc->nvc_port[port].nvp_sstatus);

		sstatus = nv_get32(bar5_hdl,
		    nvc->nvc_port[port].nvp_sstatus);

		if ((sstatus & SSTATUS_DET_DEVPRE_PHYCOM) ==
		    SSTATUS_DET_DEVPRE_PHYCOM) {
			nv_report_add_remove(nvp, 0);
		} else {
			nv_report_add_remove(nvp, NV_PORT_HOTREMOVED);
		}
	clear:
		/*
		 * clear interrupt bits.  explicit interrupt clear is
		 * required for hotplug interrupts.
		 */
		nv_put8(bar5_hdl, nvc->nvc_mcp04_int_status, clear_bits);

		/*
		 * make sure it's flushed and cleared.  If not try
		 * again.  Sometimes it has been observed to not clear
		 * on the first try.
		 */
		intr_status = nv_get8(bar5_hdl, nvc->nvc_mcp04_int_status);

		/*
		 * make 10 additional attempts to clear the interrupt
		 */
		for (i = 0; (intr_status & clear_bits) && (i < 10); i++) {
			NVLOG((NVDBG_ALWAYS, nvc, nvp, "inst_status=%x "
			    "still not clear try=%d", intr_status,
			    ++nvcleared));
			nv_put8(bar5_hdl, nvc->nvc_mcp04_int_status,
			    clear_bits);
			intr_status = nv_get8(bar5_hdl,
			    nvc->nvc_mcp04_int_status);
		}

		/*
		 * if still not clear, log a message and disable the
		 * port. highly unlikely that this path is taken, but it
		 * gives protection against a wedged interrupt.
		 */
		if (intr_status & clear_bits) {
			(*(nvc->nvc_set_intr))(nvp, NV_INTR_DISABLE);
			nv_port_state_change(nvp, SATA_EVNT_PORT_FAILED,
			    SATA_ADDR_CPORT, SATA_PSTATE_FAILED);
			nvp->nvp_state |= NV_PORT_FAILED;
			(void) nv_abort_active(nvp, NULL, SATA_PKT_DEV_ERROR);
			nv_cmn_err(CE_WARN, nvc, nvp, "unable to clear "
			    "interrupt.  disabling port intr_status=%X",
			    intr_status);
		}

		mutex_exit(&nvp->nvp_mutex);
	}
}


/*
 * Interrupt handler for mcp55.  It is invoked by the wrapper for each port
 * on the controller, to handle completion and hot plug and remove events.
 *
 */
static uint_t
mcp55_intr_port(nv_port_t *nvp)
{
	nv_ctl_t *nvc = nvp->nvp_ctlp;
	ddi_acc_handle_t bar5_hdl = nvc->nvc_bar_hdl[5];
	uint8_t clear = 0, intr_cycles = 0;
	int ret = DDI_INTR_UNCLAIMED;
	uint16_t int_status;

	NVLOG((NVDBG_INTR, nvc, nvp, "mcp55_intr_port entered"));

	for (;;) {
		/*
		 * read current interrupt status
		 */
		int_status = nv_get16(bar5_hdl, nvp->nvp_mcp55_int_status);

		NVLOG((NVDBG_INTR, nvc, nvp, "int_status = %x", int_status));

		/*
		 * MCP55_INT_IGNORE interrupts will show up in the status,
		 * but are masked out from causing an interrupt to be generated
		 * to the processor.  Ignore them here by masking them out.
		 */
		int_status &= ~(MCP55_INT_IGNORE);

		/*
		 * exit the loop when no more interrupts to process
		 */
		if (int_status == 0) {

			break;
		}

		if (int_status & MCP55_INT_COMPLETE) {
			NVLOG((NVDBG_INTR, nvc, nvp,
			    "mcp55_packet_complete_intr"));
			/*
			 * since int_status was set, return DDI_INTR_CLAIMED
			 * from the DDI's perspective even though the packet
			 * completion may not have succeeded.  If it fails,
			 * need to manually clear the interrupt, otherwise
			 * clearing is implicit.
			 */
			ret = DDI_INTR_CLAIMED;
			if (mcp55_packet_complete_intr(nvc, nvp) ==
			    NV_FAILURE) {
				clear = MCP55_INT_COMPLETE;
			} else {
				intr_cycles = 0;
			}
		}

		if (int_status & MCP55_INT_DMA_SETUP) {
			NVLOG((NVDBG_INTR, nvc, nvp, "mcp55_dma_setup_intr"));

			/*
			 * Needs to be cleared before starting the BM, so do it
			 * now.  make sure this is still working.
			 */
			nv_put16(bar5_hdl, nvp->nvp_mcp55_int_status,
			    MCP55_INT_DMA_SETUP);
#ifdef NCQ
			ret = mcp55_dma_setup_intr(nvc, nvp);
#endif
		}

		if (int_status & MCP55_INT_REM) {
			NVLOG((NVDBG_INTR, nvc, nvp, "mcp55 device removed"));
			clear = MCP55_INT_REM;
			ret = DDI_INTR_CLAIMED;

			mutex_enter(&nvp->nvp_mutex);
			nv_report_add_remove(nvp, NV_PORT_HOTREMOVED);
			mutex_exit(&nvp->nvp_mutex);

		} else if (int_status & MCP55_INT_ADD) {
			NVLOG((NVDBG_HOT, nvc, nvp, "mcp55 device added"));
			clear = MCP55_INT_ADD;
			ret = DDI_INTR_CLAIMED;

			mutex_enter(&nvp->nvp_mutex);
			nv_report_add_remove(nvp, 0);
			mutex_exit(&nvp->nvp_mutex);
		}

		if (clear) {
			nv_put16(bar5_hdl, nvp->nvp_mcp55_int_status, clear);
			clear = 0;
		}

		if (intr_cycles++ == NV_MAX_INTR_LOOP) {
			nv_cmn_err(CE_WARN, nvc, nvp, "excessive interrupt "
			    "processing.  Disabling port int_status=%X"
			    " clear=%X", int_status, clear);
			mutex_enter(&nvp->nvp_mutex);
			(*(nvc->nvc_set_intr))(nvp, NV_INTR_DISABLE);
			nv_port_state_change(nvp, SATA_EVNT_PORT_FAILED,
			    SATA_ADDR_CPORT, SATA_PSTATE_FAILED);
			nvp->nvp_state |= NV_PORT_FAILED;
			(void) nv_abort_active(nvp, NULL, SATA_PKT_DEV_ERROR);
			mutex_exit(&nvp->nvp_mutex);
		}
	}

	NVLOG((NVDBG_INTR, nvc, nvp, "mcp55_intr_port: finished ret=%d", ret));

	return (ret);
}


/* ARGSUSED */
static uint_t
mcp55_intr(caddr_t arg1, caddr_t arg2)
{
	nv_ctl_t *nvc = (nv_ctl_t *)arg1;
	int ret;

	ret = mcp55_intr_port(&(nvc->nvc_port[0]));
	ret |= mcp55_intr_port(&(nvc->nvc_port[1]));

	return (ret);
}


#ifdef NCQ
/*
 * with software driven NCQ on mcp55, an interrupt occurs right
 * before the drive is ready to do a DMA transfer.  At this point,
 * the PRD table needs to be programmed and the DMA engine enabled
 * and ready to go.
 *
 * -- MCP_SATA_AE_INT_STATUS_SDEV_DMA_SETUP indicates the interrupt
 * -- MCP_SATA_AE_NCQ_PDEV_DMA_SETUP_TAG shows which command is ready
 * -- clear bit 0 of master command reg
 * -- program PRD
 * -- clear the interrupt status bit for the DMA Setup FIS
 * -- set bit 0 of the bus master command register
 */
static int
mcp55_dma_setup_intr(nv_ctl_t *nvc, nv_port_t *nvp)
{
	int slot;
	ddi_acc_handle_t bmhdl = nvp->nvp_bm_hdl;
	uint8_t bmicx;
	int port = nvp->nvp_port_num;
	uint8_t tag_shift[] = {MCP_SATA_AE_NCQ_PDEV_DMA_SETUP_TAG_SHIFT,
	    MCP_SATA_AE_NCQ_SDEV_DMA_SETUP_TAG_SHIFT};

	nv_cmn_err(CE_PANIC, nvc, nvp,
	    "this is should not be executed at all until NCQ");

	mutex_enter(&nvp->nvp_mutex);

	slot = nv_get32(nvc->nvc_bar_hdl[5], nvc->nvc_mcp55_ncq);

	slot = (slot >> tag_shift[port]) & MCP_SATA_AE_NCQ_DMA_SETUP_TAG_MASK;

	NVLOG((NVDBG_INTR, nvc, nvp, "mcp55_dma_setup_intr slot %d"
	    " nvp_slot_sactive %X", slot, nvp->nvp_sactive_cache));

	/*
	 * halt the DMA engine.  This step is necessary according to
	 * the mcp55 spec, probably since there may have been a "first" packet
	 * that already programmed the DMA engine, but may not turn out to
	 * be the first one processed.
	 */
	bmicx = nv_get8(bmhdl, nvp->nvp_bmicx);

#if 0
	if (bmicx & BMICX_SSBM) {
		NVLOG((NVDBG_INTR, nvc, nvp, "BM was already enabled for "
		    "another packet.  Cancelling and reprogramming"));
		nv_put8(bmhdl, nvp->nvp_bmicx,  bmicx & ~BMICX_SSBM);
	}
#endif
	nv_put8(bmhdl, nvp->nvp_bmicx,  bmicx & ~BMICX_SSBM);

	nv_start_dma_engine(nvp, slot);

	mutex_exit(&nvp->nvp_mutex);

	return (DDI_INTR_CLAIMED);
}
#endif /* NCQ */


/*
 * packet completion interrupt.  If the packet is complete, invoke
 * the packet completion callback.
 */
static int
mcp55_packet_complete_intr(nv_ctl_t *nvc, nv_port_t *nvp)
{
	uint8_t status, bmstatus;
	ddi_acc_handle_t bmhdl = nvp->nvp_bm_hdl;
	int sactive;
	int active_pkt_bit = 0, active_pkt = 0, ncq_command = B_FALSE;
	sata_pkt_t *spkt;
	nv_slot_t *nv_slotp;

	mutex_enter(&nvp->nvp_mutex);

	bmstatus = nv_get8(bmhdl, nvp->nvp_bmisx);

	if (!(bmstatus & BMISX_IDEINTS)) {
		NVLOG((NVDBG_INTR, nvc, nvp, "BMISX_IDEINTS not set"));
		mutex_exit(&nvp->nvp_mutex);

		return (NV_FAILURE);
	}

	/*
	 * If the just completed item is a non-ncq command, the busy
	 * bit should not be set
	 */
	if (nvp->nvp_non_ncq_run) {
		status = nv_get8(nvp->nvp_ctl_hdl, nvp->nvp_altstatus);
		if (status & SATA_STATUS_BSY) {
			nv_cmn_err(CE_WARN, nvc, nvp,
			    "unexpected SATA_STATUS_BSY set");
			mutex_exit(&nvp->nvp_mutex);
			/*
			 * calling function will clear interrupt.  then
			 * the real interrupt will either arrive or the
			 * packet timeout handling will take over and
			 * reset.
			 */
			return (NV_FAILURE);
		}

	} else {
		/*
		 * NCQ check for BSY here and wait if still bsy before
		 * continuing. Rather than wait for it to be cleared
		 * when starting a packet and wasting CPU time, the starting
		 * thread can exit immediate, but might have to spin here
		 * for a bit possibly.  Needs more work and experimentation.
		 */
		ASSERT(nvp->nvp_ncq_run);
	}


	if (nvp->nvp_ncq_run) {
		ncq_command = B_TRUE;
		ASSERT(nvp->nvp_non_ncq_run == 0);
	} else {
		ASSERT(nvp->nvp_non_ncq_run != 0);
	}

	/*
	 * active_pkt_bit will represent the bitmap of the single completed
	 * packet.  Because of the nature of sw assisted NCQ, only one
	 * command will complete per interrupt.
	 */

	if (ncq_command == B_FALSE) {
		active_pkt = 0;
	} else {
		/*
		 * NCQ: determine which command just completed, by examining
		 * which bit cleared in the register since last written.
		 */
		sactive = nv_get32(nvc->nvc_bar_hdl[5], nvp->nvp_sactive);

		active_pkt_bit = ~sactive & nvp->nvp_sactive_cache;

		ASSERT(active_pkt_bit);


		/*
		 * this failure path needs more work to handle the
		 * error condition and recovery.
		 */
		if (active_pkt_bit == 0) {
			ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;

			nv_cmn_err(CE_CONT, nvc, nvp, "ERROR sactive = %X  "
			    "nvp->nvp_sactive %X", sactive,
			    nvp->nvp_sactive_cache);

			(void) nv_get8(cmdhdl, nvp->nvp_status);

			mutex_exit(&nvp->nvp_mutex);

			return (NV_FAILURE);
		}

		for (active_pkt = 0; (active_pkt_bit & 0x1) != 0x1;
		    active_pkt++, active_pkt_bit >>= 1) {
		}

		/*
		 * make sure only one bit is ever turned on
		 */
		ASSERT(active_pkt_bit == 1);

		nvp->nvp_sactive_cache &= ~(0x01 << active_pkt);
	}

	nv_slotp = &(nvp->nvp_slot[active_pkt]);

	spkt = nv_slotp->nvslot_spkt;

	ASSERT(spkt != NULL);

	(*nv_slotp->nvslot_intr)(nvp, nv_slotp);

	nv_copy_registers(nvp, &spkt->satapkt_device, spkt);

	/*
	 * If there is no link cannot be certain about the completion
	 * of the packet, so abort it.
	 */
	if (nv_check_link((&spkt->satapkt_device)->
	    satadev_scr.sstatus) == B_FALSE) {
		(void) nv_abort_active(nvp, NULL, SATA_PKT_PORT_ERROR);

	} else if (nv_slotp->nvslot_flags == NVSLOT_COMPLETE) {

		nv_complete_io(nvp, spkt, active_pkt);
	}

	mutex_exit(&nvp->nvp_mutex);

	return (NV_SUCCESS);
}


static void
nv_complete_io(nv_port_t *nvp, sata_pkt_t *spkt, int slot)
{

	ASSERT(MUTEX_HELD(&nvp->nvp_mutex));

	if ((&(nvp->nvp_slot[slot]))->nvslot_flags & NVSLOT_NCQ) {
		nvp->nvp_ncq_run--;
	} else {
		nvp->nvp_non_ncq_run--;
	}

	/*
	 * mark the packet slot idle so it can be reused.  Do this before
	 * calling satapkt_comp so the slot can be reused.
	 */
	(&(nvp->nvp_slot[slot]))->nvslot_spkt = NULL;

	if (spkt->satapkt_op_mode & SATA_OPMODE_SYNCH) {
		/*
		 * If this is not timed polled mode cmd, which has an
		 * active thread monitoring for completion, then need
		 * to signal the sleeping thread that the cmd is complete.
		 */
		if ((spkt->satapkt_op_mode & SATA_OPMODE_POLLING) == 0) {
			cv_signal(&nvp->nvp_poll_cv);
		}

		return;
	}

	if (spkt->satapkt_comp != NULL) {
		mutex_exit(&nvp->nvp_mutex);
		(*spkt->satapkt_comp)(spkt);
		mutex_enter(&nvp->nvp_mutex);
	}
}


/*
 * check whether packet is ncq command or not.  for ncq command,
 * start it if there is still room on queue.  for non-ncq command only
 * start if no other command is running.
 */
static int
nv_start_async(nv_port_t *nvp, sata_pkt_t *spkt)
{
	uint8_t cmd, ncq;

	NVLOG((NVDBG_ENTRY, nvp->nvp_ctlp, nvp, "nv_start_async: entry"));

	cmd = spkt->satapkt_cmd.satacmd_cmd_reg;

	ncq = ((cmd == SATAC_WRITE_FPDMA_QUEUED) ||
	    (cmd == SATAC_READ_FPDMA_QUEUED));

	if (ncq == B_FALSE) {

		if ((nvp->nvp_non_ncq_run == 1) ||
		    (nvp->nvp_ncq_run > 0)) {
			/*
			 * next command is non-ncq which can't run
			 * concurrently.  exit and return queue full.
			 */
			spkt->satapkt_reason = SATA_PKT_QUEUE_FULL;

			return (SATA_TRAN_QUEUE_FULL);
		}

		return (nv_start_common(nvp, spkt));
	}

	/*
	 * ncq == B_TRUE
	 */
	if (nvp->nvp_non_ncq_run == 1) {
		/*
		 * cannot start any NCQ commands when there
		 * is a non-NCQ command running.
		 */
		spkt->satapkt_reason = SATA_PKT_QUEUE_FULL;

		return (SATA_TRAN_QUEUE_FULL);
	}

#ifdef NCQ
	/*
	 * this is not compiled for now as satapkt_device.satadev_qdepth
	 * is being pulled out until NCQ support is later addressed
	 *
	 * nvp_queue_depth is initialized by the first NCQ command
	 * received.
	 */
	if (nvp->nvp_queue_depth == 1) {
		nvp->nvp_queue_depth =
		    spkt->satapkt_device.satadev_qdepth;

		ASSERT(nvp->nvp_queue_depth > 1);

		NVLOG((NVDBG_ENTRY, nvp->nvp_ctlp, nvp,
		    "nv_process_queue: nvp_queue_depth set to %d",
		    nvp->nvp_queue_depth));
	}
#endif

	if (nvp->nvp_ncq_run >= nvp->nvp_queue_depth) {
		/*
		 * max number of NCQ commands already active
		 */
		spkt->satapkt_reason = SATA_PKT_QUEUE_FULL;

		return (SATA_TRAN_QUEUE_FULL);
	}

	return (nv_start_common(nvp, spkt));
}


/*
 * configure INTx and legacy interrupts
 */
static int
nv_add_legacy_intrs(nv_ctl_t *nvc)
{
	dev_info_t	*devinfo = nvc->nvc_dip;
	int		actual, count = 0;
	int		x, y, rc, inum = 0;

	NVLOG((NVDBG_ENTRY, nvc, NULL, "nv_add_legacy_intrs"));

	/*
	 * get number of interrupts
	 */
	rc = ddi_intr_get_nintrs(devinfo, DDI_INTR_TYPE_FIXED, &count);
	if ((rc != DDI_SUCCESS) || (count == 0)) {
		NVLOG((NVDBG_INTR, nvc, NULL,
		    "ddi_intr_get_nintrs() failed, "
		    "rc %d count %d", rc, count));

		return (DDI_FAILURE);
	}

	/*
	 * allocate an array of interrupt handles
	 */
	nvc->nvc_intr_size = count * sizeof (ddi_intr_handle_t);
	nvc->nvc_htable = kmem_zalloc(nvc->nvc_intr_size, KM_SLEEP);

	/*
	 * call ddi_intr_alloc()
	 */
	rc = ddi_intr_alloc(devinfo, nvc->nvc_htable, DDI_INTR_TYPE_FIXED,
	    inum, count, &actual, DDI_INTR_ALLOC_STRICT);

	if ((rc != DDI_SUCCESS) || (actual == 0)) {
		nv_cmn_err(CE_WARN, nvc, NULL,
		    "ddi_intr_alloc() failed, rc %d", rc);
		kmem_free(nvc->nvc_htable, nvc->nvc_intr_size);

		return (DDI_FAILURE);
	}

	if (actual < count) {
		nv_cmn_err(CE_WARN, nvc, NULL,
		    "ddi_intr_alloc: requested: %d, received: %d",
		    count, actual);

		goto failure;
	}

	nvc->nvc_intr_cnt = actual;

	/*
	 * get intr priority
	 */
	if (ddi_intr_get_pri(nvc->nvc_htable[0], &nvc->nvc_intr_pri) !=
	    DDI_SUCCESS) {
		nv_cmn_err(CE_WARN, nvc, NULL, "ddi_intr_get_pri() failed");

		goto failure;
	}

	/*
	 * Test for high level mutex
	 */
	if (nvc->nvc_intr_pri >= ddi_intr_get_hilevel_pri()) {
		nv_cmn_err(CE_WARN, nvc, NULL,
		    "nv_add_legacy_intrs: high level intr not supported");

		goto failure;
	}

	for (x = 0; x < actual; x++) {
		if (ddi_intr_add_handler(nvc->nvc_htable[x],
		    nvc->nvc_interrupt, (caddr_t)nvc, NULL) != DDI_SUCCESS) {
			nv_cmn_err(CE_WARN, nvc, NULL,
			    "ddi_intr_add_handler() failed");

			goto failure;
		}
	}

	/*
	 * call ddi_intr_enable() for legacy interrupts
	 */
	for (x = 0; x < nvc->nvc_intr_cnt; x++) {
		(void) ddi_intr_enable(nvc->nvc_htable[x]);
	}

	return (DDI_SUCCESS);

	failure:
	/*
	 * free allocated intr and nvc_htable
	 */
	for (y = 0; y < actual; y++) {
		(void) ddi_intr_free(nvc->nvc_htable[y]);
	}

	kmem_free(nvc->nvc_htable, nvc->nvc_intr_size);

	return (DDI_FAILURE);
}

#ifdef	NV_MSI_SUPPORTED
/*
 * configure MSI interrupts
 */
static int
nv_add_msi_intrs(nv_ctl_t *nvc)
{
	dev_info_t	*devinfo = nvc->nvc_dip;
	int		count, avail, actual;
	int		x, y, rc, inum = 0;

	NVLOG((NVDBG_ENTRY, nvc, NULL, "nv_add_msi_intrs"));

	/*
	 * get number of interrupts
	 */
	rc = ddi_intr_get_nintrs(devinfo, DDI_INTR_TYPE_MSI, &count);
	if ((rc != DDI_SUCCESS) || (count == 0)) {
		nv_cmn_err(CE_WARN, nvc, NULL,
		    "ddi_intr_get_nintrs() failed, "
		    "rc %d count %d", rc, count);

		return (DDI_FAILURE);
	}

	/*
	 * get number of available interrupts
	 */
	rc = ddi_intr_get_navail(devinfo, DDI_INTR_TYPE_MSI, &avail);
	if ((rc != DDI_SUCCESS) || (avail == 0)) {
		nv_cmn_err(CE_WARN, nvc, NULL,
		    "ddi_intr_get_navail() failed, "
		    "rc %d avail %d", rc, avail);

		return (DDI_FAILURE);
	}

	if (avail < count) {
		nv_cmn_err(CE_WARN, nvc, NULL,
		    "ddi_intr_get_nvail returned %d ddi_intr_get_nintrs: %d",
		    avail, count);
	}

	/*
	 * allocate an array of interrupt handles
	 */
	nvc->nvc_intr_size = count * sizeof (ddi_intr_handle_t);
	nvc->nvc_htable = kmem_alloc(nvc->nvc_intr_size, KM_SLEEP);

	rc = ddi_intr_alloc(devinfo, nvc->nvc_htable, DDI_INTR_TYPE_MSI,
	    inum, count, &actual, DDI_INTR_ALLOC_NORMAL);

	if ((rc != DDI_SUCCESS) || (actual == 0)) {
		nv_cmn_err(CE_WARN, nvc, NULL,
		    "ddi_intr_alloc() failed, rc %d", rc);
		kmem_free(nvc->nvc_htable, nvc->nvc_intr_size);

		return (DDI_FAILURE);
	}

	/*
	 * Use interrupt count returned or abort?
	 */
	if (actual < count) {
		NVLOG((NVDBG_INIT, nvc, NULL,
		    "Requested: %d, Received: %d", count, actual));
	}

	nvc->nvc_intr_cnt = actual;

	/*
	 * get priority for first msi, assume remaining are all the same
	 */
	if (ddi_intr_get_pri(nvc->nvc_htable[0], &nvc->nvc_intr_pri) !=
	    DDI_SUCCESS) {
		nv_cmn_err(CE_WARN, nvc, NULL, "ddi_intr_get_pri() failed");

		goto failure;
	}

	/*
	 * test for high level mutex
	 */
	if (nvc->nvc_intr_pri >= ddi_intr_get_hilevel_pri()) {
		nv_cmn_err(CE_WARN, nvc, NULL,
		    "nv_add_msi_intrs: high level intr not supported");

		goto failure;
	}

	/*
	 * Call ddi_intr_add_handler()
	 */
	for (x = 0; x < actual; x++) {
		if (ddi_intr_add_handler(nvc->nvc_htable[x],
		    nvc->nvc_interrupt, (caddr_t)nvc, NULL) != DDI_SUCCESS) {
			nv_cmn_err(CE_WARN, nvc, NULL,
			    "ddi_intr_add_handler() failed");

			goto failure;
		}
	}

	(void) ddi_intr_get_cap(nvc->nvc_htable[0], &nvc->nvc_intr_cap);

	if (nvc->nvc_intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_enable(nvc->nvc_htable,
		    nvc->nvc_intr_cnt);
	} else {
		/*
		 * Call ddi_intr_enable() for MSI non block enable
		 */
		for (x = 0; x < nvc->nvc_intr_cnt; x++) {
			(void) ddi_intr_enable(nvc->nvc_htable[x]);
		}
	}

	return (DDI_SUCCESS);

	failure:
	/*
	 * free allocated intr and nvc_htable
	 */
	for (y = 0; y < actual; y++) {
		(void) ddi_intr_free(nvc->nvc_htable[y]);
	}

	kmem_free(nvc->nvc_htable, nvc->nvc_intr_size);

	return (DDI_FAILURE);
}
#endif


static void
nv_rem_intrs(nv_ctl_t *nvc)
{
	int x, i;
	nv_port_t *nvp;

	NVLOG((NVDBG_ENTRY, nvc, NULL, "nv_rem_intrs"));

	/*
	 * prevent controller from generating interrupts by
	 * masking them out.  This is an extra precaution.
	 */
	for (i = 0; i < NV_MAX_PORTS(nvc); i++) {
		nvp = (&nvc->nvc_port[i]);
		mutex_enter(&nvp->nvp_mutex);
		(*(nvc->nvc_set_intr))(nvp, NV_INTR_DISABLE);
		mutex_exit(&nvp->nvp_mutex);
	}

	/*
	 * disable all interrupts
	 */
	if ((nvc->nvc_intr_type == DDI_INTR_TYPE_MSI) &&
	    (nvc->nvc_intr_cap & DDI_INTR_FLAG_BLOCK)) {
		(void) ddi_intr_block_disable(nvc->nvc_htable,
		    nvc->nvc_intr_cnt);
	} else {
		for (x = 0; x < nvc->nvc_intr_cnt; x++) {
			(void) ddi_intr_disable(nvc->nvc_htable[x]);
		}
	}

	for (x = 0; x < nvc->nvc_intr_cnt; x++) {
		(void) ddi_intr_remove_handler(nvc->nvc_htable[x]);
		(void) ddi_intr_free(nvc->nvc_htable[x]);
	}

	kmem_free(nvc->nvc_htable, nvc->nvc_intr_size);
}


/*
 * variable argument wrapper for cmn_err.  prefixes the instance and port
 * number if possible
 */
static void
nv_vcmn_err(int ce, nv_ctl_t *nvc, nv_port_t *nvp, char *fmt, va_list ap)
{
	char port[NV_STRING_10];
	char inst[NV_STRING_10];

	mutex_enter(&nv_log_mutex);

	if (nvc) {
		(void) snprintf(inst, NV_STRING_10, "inst %d",
		    ddi_get_instance(nvc->nvc_dip));
	} else {
		inst[0] = '\0';
	}

	if (nvp) {
		(void) sprintf(port, " port %d", nvp->nvp_port_num);
	} else {
		port[0] = '\0';
	}

	(void) sprintf(nv_log_buf, "nv_sata %s%s%s", inst, port,
	    (inst[0]|port[0] ? ": " :""));

	(void) vsnprintf(&nv_log_buf[strlen(nv_log_buf)],
	    NV_STRING_512 - strlen(nv_log_buf), fmt, ap);

	/*
	 * normally set to log to console but in some debug situations it
	 * may be useful to log only to a file.
	 */
	if (nv_log_to_console) {
		if (nv_prom_print) {
			prom_printf("%s\n", nv_log_buf);
		} else {
			cmn_err(ce, "%s", nv_log_buf);
		}


	} else {
		cmn_err(ce, "!%s", nv_log_buf);
	}

	mutex_exit(&nv_log_mutex);
}


/*
 * wrapper for cmn_err
 */
static void
nv_cmn_err(int ce, nv_ctl_t *nvc, nv_port_t *nvp, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	nv_vcmn_err(ce, nvc, nvp, fmt, ap);
	va_end(ap);
}


#if defined(DEBUG)
/*
 * prefixes the instance and port number if possible to the debug message
 */
static void
nv_log(uint_t flag, nv_ctl_t *nvc, nv_port_t *nvp, char *fmt, ...)
{
	va_list ap;

	if ((nv_debug_flags & flag) == 0) {
		return;
	}

	va_start(ap, fmt);
	nv_vcmn_err(CE_NOTE, nvc, nvp, fmt, ap);
	va_end(ap);

	/*
	 * useful for some debugging situations
	 */
	if (nv_log_delay) {
		drv_usecwait(nv_log_delay);
	}

}
#endif /* DEBUG */


/*
 * program registers which are common to all commands
 */
static void
nv_program_taskfile_regs(nv_port_t *nvp, int slot)
{
	nv_slot_t *nv_slotp = &(nvp->nvp_slot[slot]);
	sata_pkt_t *spkt;
	sata_cmd_t *satacmd;
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
	uint8_t cmd, ncq = B_FALSE;

	spkt = nv_slotp->nvslot_spkt;
	satacmd = &spkt->satapkt_cmd;
	cmd = satacmd->satacmd_cmd_reg;

	ASSERT(nvp->nvp_slot);

	if ((cmd == SATAC_WRITE_FPDMA_QUEUED) ||
	    (cmd == SATAC_READ_FPDMA_QUEUED)) {
		ncq = B_TRUE;
	}

	/*
	 * select the drive
	 */
	nv_put8(cmdhdl, nvp->nvp_drvhd, satacmd->satacmd_device_reg);

	/*
	 * make certain the drive selected
	 */
	if (nv_wait(nvp, SATA_STATUS_DRDY, SATA_STATUS_BSY,
	    NV_SEC2USEC(5), 0) == B_FALSE) {

		return;
	}

	switch (spkt->satapkt_cmd.satacmd_addr_type) {

	case ATA_ADDR_LBA:
		NVLOG((NVDBG_DELIVER, nvp->nvp_ctlp, nvp, "ATA_ADDR_LBA mode"));

		nv_put8(cmdhdl, nvp->nvp_count, satacmd->satacmd_sec_count_lsb);
		nv_put8(cmdhdl, nvp->nvp_hcyl, satacmd->satacmd_lba_high_lsb);
		nv_put8(cmdhdl, nvp->nvp_lcyl, satacmd->satacmd_lba_mid_lsb);
		nv_put8(cmdhdl, nvp->nvp_sect, satacmd->satacmd_lba_low_lsb);

		break;

	case ATA_ADDR_LBA28:
		NVLOG((NVDBG_DELIVER, nvp->nvp_ctlp, nvp,
		    "ATA_ADDR_LBA28 mode"));
		/*
		 * NCQ only uses 48-bit addressing
		 */
		ASSERT(ncq != B_TRUE);

		nv_put8(cmdhdl, nvp->nvp_count, satacmd->satacmd_sec_count_lsb);
		nv_put8(cmdhdl, nvp->nvp_hcyl, satacmd->satacmd_lba_high_lsb);
		nv_put8(cmdhdl, nvp->nvp_lcyl, satacmd->satacmd_lba_mid_lsb);
		nv_put8(cmdhdl, nvp->nvp_sect, satacmd->satacmd_lba_low_lsb);

		break;

	case ATA_ADDR_LBA48:
		NVLOG((NVDBG_DELIVER, nvp->nvp_ctlp, nvp,
		    "ATA_ADDR_LBA48 mode"));

		/*
		 * for NCQ, tag goes into count register and real sector count
		 * into features register.  The sata module does the translation
		 * in the satacmd.
		 */
		if (ncq == B_TRUE) {
			nv_put8(cmdhdl, nvp->nvp_count, slot << 3);
			nv_put8(cmdhdl, nvp->nvp_feature,
			    satacmd->satacmd_features_reg_ext);
			nv_put8(cmdhdl, nvp->nvp_feature,
			    satacmd->satacmd_features_reg);
		} else {
			nv_put8(cmdhdl, nvp->nvp_count,
			    satacmd->satacmd_sec_count_msb);
			nv_put8(cmdhdl, nvp->nvp_count,
			    satacmd->satacmd_sec_count_lsb);
		}

		/*
		 * send the high-order half first
		 */
		nv_put8(cmdhdl, nvp->nvp_hcyl, satacmd->satacmd_lba_high_msb);
		nv_put8(cmdhdl, nvp->nvp_lcyl, satacmd->satacmd_lba_mid_msb);
		nv_put8(cmdhdl, nvp->nvp_sect, satacmd->satacmd_lba_low_msb);
		/*
		 * Send the low-order half
		 */
		nv_put8(cmdhdl, nvp->nvp_hcyl, satacmd->satacmd_lba_high_lsb);
		nv_put8(cmdhdl, nvp->nvp_lcyl, satacmd->satacmd_lba_mid_lsb);
		nv_put8(cmdhdl, nvp->nvp_sect, satacmd->satacmd_lba_low_lsb);

		break;

	case 0:
		/*
		 * non-media access commands such as identify and features
		 * take this path.
		 */
		nv_put8(cmdhdl, nvp->nvp_count, satacmd->satacmd_sec_count_lsb);
		nv_put8(cmdhdl, nvp->nvp_feature,
		    satacmd->satacmd_features_reg);
		nv_put8(cmdhdl, nvp->nvp_hcyl, satacmd->satacmd_lba_high_lsb);
		nv_put8(cmdhdl, nvp->nvp_lcyl, satacmd->satacmd_lba_mid_lsb);
		nv_put8(cmdhdl, nvp->nvp_sect, satacmd->satacmd_lba_low_lsb);

		break;

	default:
		break;
	}

	ASSERT(nvp->nvp_slot);
}


/*
 * start a command that involves no media access
 */
static int
nv_start_nodata(nv_port_t *nvp, int slot)
{
	nv_slot_t *nv_slotp = &(nvp->nvp_slot[slot]);
	sata_pkt_t *spkt = nv_slotp->nvslot_spkt;
	sata_cmd_t *sata_cmdp = &spkt->satapkt_cmd;
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;

	nv_program_taskfile_regs(nvp, slot);

	/*
	 * This next one sets the controller in motion
	 */
	nv_put8(cmdhdl, nvp->nvp_cmd, sata_cmdp->satacmd_cmd_reg);

	return (SATA_TRAN_ACCEPTED);
}


int
nv_bm_status_clear(nv_port_t *nvp)
{
	ddi_acc_handle_t bmhdl = nvp->nvp_bm_hdl;
	uchar_t	status, ret;

	/*
	 * Get the current BM status
	 */
	ret = status = nv_get8(bmhdl, nvp->nvp_bmisx);

	status = (status & BMISX_MASK) | BMISX_IDERR | BMISX_IDEINTS;

	/*
	 * Clear the latches (and preserve the other bits)
	 */
	nv_put8(bmhdl, nvp->nvp_bmisx, status);

	return (ret);
}


/*
 * program the bus master DMA engine with the PRD address for
 * the active slot command, and start the DMA engine.
 */
static void
nv_start_dma_engine(nv_port_t *nvp, int slot)
{
	nv_slot_t *nv_slotp = &(nvp->nvp_slot[slot]);
	ddi_acc_handle_t bmhdl = nvp->nvp_bm_hdl;
	uchar_t direction;

	ASSERT(nv_slotp->nvslot_spkt != NULL);

	if (nv_slotp->nvslot_spkt->satapkt_cmd.satacmd_flags.sata_data_direction
	    == SATA_DIR_READ) {
		direction = BMICX_RWCON_WRITE_TO_MEMORY;
	} else {
		direction = BMICX_RWCON_READ_FROM_MEMORY;
	}

	NVLOG((NVDBG_DELIVER, nvp->nvp_ctlp, nvp,
	    "nv_start_dma_engine entered"));

	/*
	 * reset the controller's interrupt and error status bits
	 */
	(void) nv_bm_status_clear(nvp);

	/*
	 * program the PRD table physical start address
	 */
	nv_put32(bmhdl, nvp->nvp_bmidtpx, nvp->nvp_sg_paddr[slot]);

	/*
	 * set the direction control and start the DMA controller
	 */
	nv_put8(bmhdl, nvp->nvp_bmicx, direction | BMICX_SSBM);
}

/*
 * start dma command, either in or out
 */
static int
nv_start_dma(nv_port_t *nvp, int slot)
{
	nv_slot_t *nv_slotp = &(nvp->nvp_slot[slot]);
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
	sata_pkt_t *spkt = nv_slotp->nvslot_spkt;
	sata_cmd_t *sata_cmdp = &spkt->satapkt_cmd;
	uint8_t cmd = sata_cmdp->satacmd_cmd_reg;
#ifdef NCQ
	uint8_t ncq = B_FALSE;
#endif
	ddi_acc_handle_t sghdl = nvp->nvp_sg_acc_hdl[slot];
	uint_t *dstp = (uint_t *)nvp->nvp_sg_addr[slot];
	int sg_count = sata_cmdp->satacmd_num_dma_cookies, idx;
	ddi_dma_cookie_t  *srcp = sata_cmdp->satacmd_dma_cookie_list;

	ASSERT(sg_count != 0);

	if (sata_cmdp->satacmd_num_dma_cookies > NV_DMA_NSEGS) {
		nv_cmn_err(CE_WARN, nvp->nvp_ctlp, nvp, "NV_DMA_NSEGS=%d <"
		    " satacmd_num_dma_cookies=%d", NV_DMA_NSEGS,
		    sata_cmdp->satacmd_num_dma_cookies);

		return (NV_FAILURE);
	}

	nv_program_taskfile_regs(nvp, slot);

	/*
	 * start the drive in motion
	 */
	nv_put8(cmdhdl, nvp->nvp_cmd, cmd);

	/*
	 * the drive starts processing the transaction when the cmd register
	 * is written.  This is done here before programming the DMA engine to
	 * parallelize and save some time.  In the event that the drive is ready
	 * before DMA, it will wait.
	 */
#ifdef NCQ
	if ((cmd == SATAC_WRITE_FPDMA_QUEUED) ||
	    (cmd == SATAC_READ_FPDMA_QUEUED)) {
		ncq = B_TRUE;
	}
#endif

	/*
	 * copy the PRD list to PRD table in DMA accessible memory
	 * so that the controller can access it.
	 */
	for (idx = 0; idx < sg_count; idx++, srcp++) {
		uint32_t size;

		ASSERT(srcp->dmac_size <= UINT16_MAX);

		nv_put32(sghdl, dstp++, srcp->dmac_address);

		size = srcp->dmac_size;

		/*
		 * If this is a 40-bit address, copy bits 32-40 of the
		 * physical address to bits 16-24 of the PRD count.
		 */
		if (srcp->dmac_laddress > UINT32_MAX) {
			size |= ((srcp->dmac_laddress & 0xff00000000) >> 16);
		}

		/*
		 * set the end of table flag for the last entry
		 */
		if (idx == (sg_count - 1)) {
			size |= PRDE_EOT;
		}

		nv_put32(sghdl, dstp++, size);
	}

	(void) ddi_dma_sync(nvp->nvp_sg_dma_hdl[slot], 0,
	    sizeof (prde_t) * NV_DMA_NSEGS, DDI_DMA_SYNC_FORDEV);

	nv_start_dma_engine(nvp, slot);

#ifdef NCQ
	/*
	 * optimization:  for SWNCQ, start DMA engine if this is the only
	 * command running.  Preliminary NCQ efforts indicated this needs
	 * more debugging.
	 *
	 * if (nvp->nvp_ncq_run <= 1)
	 */

	if (ncq == B_FALSE) {
		NVLOG((NVDBG_DELIVER, nvp->nvp_ctlp, nvp,
		    "NOT NCQ so starting DMA NOW non_ncq_commands=%d"
		    " cmd = %X", non_ncq_commands++, cmd));
		nv_start_dma_engine(nvp, slot);
	} else {
		NVLOG((NVDBG_DELIVER, nvp->nvp_ctlp, nvp, "?NCQ, so program "
		    "DMA later ncq_commands=%d cmd = %X", ncq_commands++, cmd));
	}
#endif /* NCQ */

	return (SATA_TRAN_ACCEPTED);
}


/*
 * start a PIO data-in ATA command
 */
static int
nv_start_pio_in(nv_port_t *nvp, int slot)
{

	nv_slot_t *nv_slotp = &(nvp->nvp_slot[slot]);
	sata_pkt_t *spkt = nv_slotp->nvslot_spkt;
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;

	nv_program_taskfile_regs(nvp, slot);

	/*
	 * This next one sets the drive in motion
	 */
	nv_put8(cmdhdl, nvp->nvp_cmd, spkt->satapkt_cmd.satacmd_cmd_reg);

	return (SATA_TRAN_ACCEPTED);
}


/*
 * start a PIO data-out ATA command
 */
static int
nv_start_pio_out(nv_port_t *nvp, int slot)
{
	nv_slot_t *nv_slotp = &(nvp->nvp_slot[slot]);
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
	sata_pkt_t *spkt = nv_slotp->nvslot_spkt;

	nv_program_taskfile_regs(nvp, slot);

	/*
	 * this next one sets the drive in motion
	 */
	nv_put8(cmdhdl, nvp->nvp_cmd, spkt->satapkt_cmd.satacmd_cmd_reg);

	/*
	 * wait for the busy bit to settle
	 */
	NV_DELAY_NSEC(400);

	/*
	 * wait for the drive to assert DRQ to send the first chunk
	 * of data. Have to busy wait because there's no interrupt for
	 * the first chunk. This is bad... uses a lot of cycles if the
	 * drive responds too slowly or if the wait loop granularity
	 * is too large. It's even worse if the drive is defective and
	 * the loop times out.
	 */
	if (nv_wait3(nvp, SATA_STATUS_DRQ, SATA_STATUS_BSY, /* okay */
	    SATA_STATUS_ERR, SATA_STATUS_BSY, /* cmd failed */
	    SATA_STATUS_DF, SATA_STATUS_BSY, /* drive failed */
	    4000000, 0) == B_FALSE) {
		spkt->satapkt_reason = SATA_PKT_TIMEOUT;

		goto error;
	}

	/*
	 * send the first block.
	 */
	nv_intr_pio_out(nvp, nv_slotp);

	/*
	 * If nvslot_flags is not set to COMPLETE yet, then processing
	 * is OK so far, so return.  Otherwise, fall into error handling
	 * below.
	 */
	if (nv_slotp->nvslot_flags != NVSLOT_COMPLETE) {

		return (SATA_TRAN_ACCEPTED);
	}

	error:
	/*
	 * there was an error so reset the device and complete the packet.
	 */
	nv_copy_registers(nvp, &spkt->satapkt_device, spkt);
	nv_complete_io(nvp, spkt, 0);
	nv_reset(nvp);

	return (SATA_TRAN_PORT_ERROR);
}


/*
 * Interrupt processing for a non-data ATA command.
 */
static void
nv_intr_nodata(nv_port_t *nvp, nv_slot_t *nv_slotp)
{
	uchar_t status;
	sata_pkt_t *spkt = nv_slotp->nvslot_spkt;
	sata_cmd_t *sata_cmdp = &spkt->satapkt_cmd;
	ddi_acc_handle_t ctlhdl = nvp->nvp_ctl_hdl;
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;

	NVLOG((NVDBG_INTR, nvp->nvp_ctlp, nvp, "nv_intr_nodata entered"));

	status = nv_get8(cmdhdl, nvp->nvp_status);

	/*
	 * check for errors
	 */
	if (status & (SATA_STATUS_DF | SATA_STATUS_ERR)) {
		spkt->satapkt_reason = SATA_PKT_DEV_ERROR;
		sata_cmdp->satacmd_status_reg = nv_get8(ctlhdl,
		    nvp->nvp_altstatus);
		sata_cmdp->satacmd_error_reg = nv_get8(cmdhdl, nvp->nvp_error);
	} else {
		spkt->satapkt_reason = SATA_PKT_COMPLETED;
	}

	nv_slotp->nvslot_flags = NVSLOT_COMPLETE;
}


/*
 * ATA command, PIO data in
 */
static void
nv_intr_pio_in(nv_port_t *nvp, nv_slot_t *nv_slotp)
{
	uchar_t	status;
	sata_pkt_t *spkt = nv_slotp->nvslot_spkt;
	sata_cmd_t *sata_cmdp = &spkt->satapkt_cmd;
	ddi_acc_handle_t ctlhdl = nvp->nvp_ctl_hdl;
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
	int count;

	status = nv_get8(cmdhdl, nvp->nvp_status);

	if (status & SATA_STATUS_BSY) {
		spkt->satapkt_reason = SATA_PKT_TIMEOUT;
		nv_slotp->nvslot_flags = NVSLOT_COMPLETE;
		sata_cmdp->satacmd_status_reg = nv_get8(ctlhdl,
		    nvp->nvp_altstatus);
		sata_cmdp->satacmd_error_reg = nv_get8(cmdhdl, nvp->nvp_error);
		nv_reset(nvp);

		return;
	}

	/*
	 * check for errors
	 */
	if ((status & (SATA_STATUS_DRQ | SATA_STATUS_DF |
	    SATA_STATUS_ERR)) != SATA_STATUS_DRQ) {
		nv_copy_registers(nvp, &spkt->satapkt_device, spkt);
		nv_slotp->nvslot_flags = NVSLOT_COMPLETE;
		spkt->satapkt_reason = SATA_PKT_DEV_ERROR;

		return;
	}

	/*
	 * read the next chunk of data (if any)
	 */
	count = min(nv_slotp->nvslot_byte_count, NV_BYTES_PER_SEC);

	/*
	 * read count bytes
	 */
	ASSERT(count != 0);

	ddi_rep_get16(cmdhdl, (ushort_t *)nv_slotp->nvslot_v_addr,
	    (ushort_t *)nvp->nvp_data, (count >> 1), DDI_DEV_NO_AUTOINCR);

	nv_slotp->nvslot_v_addr += count;
	nv_slotp->nvslot_byte_count -= count;


	if (nv_slotp->nvslot_byte_count != 0) {
		/*
		 * more to transfer.  Wait for next interrupt.
		 */
		return;
	}

	/*
	 * transfer is complete. wait for the busy bit to settle.
	 */
	NV_DELAY_NSEC(400);

	spkt->satapkt_reason = SATA_PKT_COMPLETED;
	nv_slotp->nvslot_flags = NVSLOT_COMPLETE;
}


/*
 * ATA command PIO data out
 */
static void
nv_intr_pio_out(nv_port_t *nvp, nv_slot_t *nv_slotp)
{
	sata_pkt_t *spkt = nv_slotp->nvslot_spkt;
	sata_cmd_t *sata_cmdp = &spkt->satapkt_cmd;
	uchar_t status;
	ddi_acc_handle_t ctlhdl = nvp->nvp_ctl_hdl;
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
	int count;

	/*
	 * clear the IRQ
	 */
	status = nv_get8(cmdhdl, nvp->nvp_status);

	if (status & SATA_STATUS_BSY) {
		/*
		 * this should not happen
		 */
		spkt->satapkt_reason = SATA_PKT_TIMEOUT;
		nv_slotp->nvslot_flags = NVSLOT_COMPLETE;
		sata_cmdp->satacmd_status_reg = nv_get8(ctlhdl,
		    nvp->nvp_altstatus);
		sata_cmdp->satacmd_error_reg = nv_get8(cmdhdl, nvp->nvp_error);

		return;
	}

	/*
	 * check for errors
	 */
	if (status & (SATA_STATUS_DF | SATA_STATUS_ERR)) {
		nv_copy_registers(nvp,  &spkt->satapkt_device, spkt);
		nv_slotp->nvslot_flags = NVSLOT_COMPLETE;
		spkt->satapkt_reason = SATA_PKT_DEV_ERROR;

		return;
	}

	/*
	 * this is the condition which signals the drive is
	 * no longer ready to transfer.  Likely that the transfer
	 * completed successfully, but check that byte_count is
	 * zero.
	 */
	if ((status & SATA_STATUS_DRQ) == 0) {

		if (nv_slotp->nvslot_byte_count == 0) {
			/*
			 * complete; successful transfer
			 */
			spkt->satapkt_reason = SATA_PKT_COMPLETED;
		} else {
			/*
			 * error condition, incomplete transfer
			 */
			nv_copy_registers(nvp, &spkt->satapkt_device, spkt);
			spkt->satapkt_reason = SATA_PKT_DEV_ERROR;
		}
		nv_slotp->nvslot_flags = NVSLOT_COMPLETE;

		return;
	}

	/*
	 * write the next chunk of data
	 */
	count = min(nv_slotp->nvslot_byte_count, NV_BYTES_PER_SEC);

	/*
	 * read or write count bytes
	 */

	ASSERT(count != 0);

	ddi_rep_put16(cmdhdl, (ushort_t *)nv_slotp->nvslot_v_addr,
	    (ushort_t *)nvp->nvp_data, (count >> 1), DDI_DEV_NO_AUTOINCR);

	nv_slotp->nvslot_v_addr += count;
	nv_slotp->nvslot_byte_count -= count;
}


/*
 * ATA command, DMA data in/out
 */
static void
nv_intr_dma(nv_port_t *nvp, struct nv_slot *nv_slotp)
{
	uchar_t status;
	sata_pkt_t *spkt = nv_slotp->nvslot_spkt;
	sata_cmd_t *sata_cmdp = &spkt->satapkt_cmd;
	ddi_acc_handle_t ctlhdl = nvp->nvp_ctl_hdl;
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
	ddi_acc_handle_t bmhdl = nvp->nvp_bm_hdl;
	uchar_t	bmicx;
	uchar_t bm_status;

	nv_slotp->nvslot_flags = NVSLOT_COMPLETE;

	/*
	 * stop DMA engine.
	 */
	bmicx = nv_get8(bmhdl, nvp->nvp_bmicx);
	nv_put8(bmhdl, nvp->nvp_bmicx,  bmicx & ~BMICX_SSBM);

	/*
	 * get the status and clear the IRQ, and check for DMA error
	 */
	status = nv_get8(cmdhdl, nvp->nvp_status);

	/*
	 * check for drive errors
	 */
	if (status & (SATA_STATUS_DF | SATA_STATUS_ERR)) {
		nv_copy_registers(nvp, &spkt->satapkt_device, spkt);
		spkt->satapkt_reason = SATA_PKT_DEV_ERROR;
		(void) nv_bm_status_clear(nvp);

		return;
	}

	bm_status = nv_bm_status_clear(nvp);

	/*
	 * check for bus master errors
	 */
	if (bm_status & BMISX_IDERR) {
		spkt->satapkt_reason = SATA_PKT_RESET;
		sata_cmdp->satacmd_status_reg = nv_get8(ctlhdl,
		    nvp->nvp_altstatus);
		sata_cmdp->satacmd_error_reg = nv_get8(cmdhdl, nvp->nvp_error);
		nv_reset(nvp);

		return;
	}

	spkt->satapkt_reason = SATA_PKT_COMPLETED;
}


/*
 * Wait for a register of a controller to achieve a specific state.
 * To return normally, all the bits in the first sub-mask must be ON,
 * all the bits in the second sub-mask must be OFF.
 * If timeout_usec microseconds pass without the controller achieving
 * the desired bit configuration, return TRUE, else FALSE.
 *
 * hybrid waiting algorithm: if not in interrupt context, busy looping will
 * occur for the first 250 us, then switch over to a sleeping wait.
 *
 */
int
nv_wait(nv_port_t *nvp, uchar_t onbits, uchar_t offbits, uint_t timeout_usec,
    int type_wait)
{
	ddi_acc_handle_t ctlhdl = nvp->nvp_ctl_hdl;
	hrtime_t end, cur, start_sleep, start;
	int first_time = B_TRUE;
	ushort_t val;

	for (;;) {
		val = nv_get8(ctlhdl, nvp->nvp_altstatus);

		if ((val & onbits) == onbits && (val & offbits) == 0) {

			return (B_TRUE);
		}

		cur = gethrtime();

		/*
		 * store the start time and calculate the end
		 * time.  also calculate "start_sleep" which is
		 * the point after which the driver will stop busy
		 * waiting and change to sleep waiting.
		 */
		if (first_time) {
			first_time = B_FALSE;
			/*
			 * start and end are in nanoseconds
			 */
			start = cur;
			end = start + timeout_usec * 1000;
			/*
			 * add 1 ms to start
			 */
			start_sleep =  start + 250000;

			if (servicing_interrupt()) {
				type_wait = NV_NOSLEEP;
			}
		}

		if (cur > end) {

			break;
		}

		if ((type_wait != NV_NOSLEEP) && (cur > start_sleep)) {
#if ! defined(__lock_lint)
			delay(1);
#endif
		} else {
			drv_usecwait(nv_usec_delay);
		}
	}

	return (B_FALSE);
}


/*
 * This is a slightly more complicated version that checks
 * for error conditions and bails-out rather than looping
 * until the timeout is exceeded.
 *
 * hybrid waiting algorithm: if not in interrupt context, busy looping will
 * occur for the first 250 us, then switch over to a sleeping wait.
 */
int
nv_wait3(
	nv_port_t	*nvp,
	uchar_t		onbits1,
	uchar_t		offbits1,
	uchar_t		failure_onbits2,
	uchar_t		failure_offbits2,
	uchar_t		failure_onbits3,
	uchar_t		failure_offbits3,
	uint_t		timeout_usec,
	int		type_wait)
{
	ddi_acc_handle_t ctlhdl = nvp->nvp_ctl_hdl;
	hrtime_t end, cur, start_sleep, start;
	int first_time = B_TRUE;
	ushort_t val;

	for (;;) {
		val = nv_get8(ctlhdl, nvp->nvp_altstatus);

		/*
		 * check for expected condition
		 */
		if ((val & onbits1) == onbits1 && (val & offbits1) == 0) {

			return (B_TRUE);
		}

		/*
		 * check for error conditions
		 */
		if ((val & failure_onbits2) == failure_onbits2 &&
		    (val & failure_offbits2) == 0) {

			return (B_FALSE);
		}

		if ((val & failure_onbits3) == failure_onbits3 &&
		    (val & failure_offbits3) == 0) {

			return (B_FALSE);
		}

		/*
		 * store the start time and calculate the end
		 * time.  also calculate "start_sleep" which is
		 * the point after which the driver will stop busy
		 * waiting and change to sleep waiting.
		 */
		if (first_time) {
			first_time = B_FALSE;
			/*
			 * start and end are in nanoseconds
			 */
			cur = start = gethrtime();
			end = start + timeout_usec * 1000;
			/*
			 * add 1 ms to start
			 */
			start_sleep =  start + 250000;

			if (servicing_interrupt()) {
				type_wait = NV_NOSLEEP;
			}
		} else {
			cur = gethrtime();
		}

		if (cur > end) {

			break;
		}

		if ((type_wait != NV_NOSLEEP) && (cur > start_sleep)) {
#if ! defined(__lock_lint)
			delay(1);
#endif
		} else {
			drv_usecwait(nv_usec_delay);
		}
	}

	return (B_FALSE);
}


/*
 * nv_check_link() checks if a specified link is active device present
 * and communicating.
 */
static boolean_t
nv_check_link(uint32_t sstatus)
{
	uint8_t det;

	det = (sstatus & SSTATUS_DET) >> SSTATUS_DET_SHIFT;

	return (det == SSTATUS_DET_DEVPRE_PHYCOM);
}


/*
 * nv_port_state_change() reports the state of the port to the
 * sata module by calling sata_hba_event_notify().  This
 * function is called any time the state of the port is changed
 */
static void
nv_port_state_change(nv_port_t *nvp, int event, uint8_t addr_type, int state)
{
	sata_device_t sd;

	bzero((void *)&sd, sizeof (sata_device_t));
	sd.satadev_rev = SATA_DEVICE_REV;
	nv_copy_registers(nvp, &sd, NULL);

	/*
	 * When NCQ is implemented sactive and snotific field need to be
	 * updated.
	 */
	sd.satadev_addr.cport = nvp->nvp_port_num;
	sd.satadev_addr.qual = addr_type;
	sd.satadev_state = state;

	sata_hba_event_notify(nvp->nvp_ctlp->nvc_dip, &sd, event);
}


/*
 * timeout processing:
 *
 * Check if any packets have crossed a timeout threshold.  If so, then
 * abort the packet.  This function is not NCQ aware.
 *
 * If reset was invoked in any other place than nv_sata_probe(), then
 * monitor for reset completion here.
 *
 */
static void
nv_timeout(void *arg)
{
	nv_port_t *nvp = arg;
	nv_slot_t *nv_slotp;
	int restart_timeout = B_FALSE;

	mutex_enter(&nvp->nvp_mutex);

	/*
	 * If the probe entry point is driving the reset and signature
	 * acquisition, just return.
	 */
	if (nvp->nvp_state & NV_PORT_RESET_PROBE) {
		goto finished;
	}

	/*
	 * If the port is not in the init state, it likely
	 * means the link was lost while a timeout was active.
	 */
	if ((nvp->nvp_state & NV_PORT_INIT) == 0) {
		NVLOG((NVDBG_TIMEOUT, nvp->nvp_ctlp, nvp,
		    "nv_timeout: port uninitialized"));

		goto finished;
	}

	if (nvp->nvp_state & NV_PORT_RESET) {
		ddi_acc_handle_t bar5_hdl = nvp->nvp_ctlp->nvc_bar_hdl[5];
		uint32_t sstatus;

		NVLOG((NVDBG_TIMEOUT, nvp->nvp_ctlp, nvp,
		    "nv_timeout(): port waiting for signature"));

		sstatus = nv_get32(bar5_hdl, nvp->nvp_sstatus);

		/*
		 * check for link presence.  If the link remains
		 * missing for more than 2 seconds, send a remove
		 * event and abort signature acquisition.
		 */
		if (nv_check_link(sstatus) == B_FALSE) {
			clock_t e_link_lost = ddi_get_lbolt();

			if (nvp->nvp_link_lost_time == 0) {
				nvp->nvp_link_lost_time = e_link_lost;
			}
			if (TICK_TO_SEC(e_link_lost -
			    nvp->nvp_link_lost_time) < NV_LINK_LOST_OK) {
				NVLOG((NVDBG_TIMEOUT, nvp->nvp_ctlp, nvp,
				    "probe: intermittent link lost while"
				    " resetting"));
				restart_timeout = B_TRUE;
			} else {
				NVLOG((NVDBG_TIMEOUT, nvp->nvp_ctlp, nvp,
				    "link lost during signature acquisition."
				    "  Giving up"));
				nv_port_state_change(nvp,
				    SATA_EVNT_DEVICE_DETACHED|
				    SATA_EVNT_LINK_LOST,
				    SATA_ADDR_CPORT, 0);
				nvp->nvp_state |= NV_PORT_HOTREMOVED;
				nvp->nvp_state &= ~NV_PORT_RESET;
			}

			goto finished;
		} else {

			nvp->nvp_link_lost_time = 0;
		}

		nv_read_signature(nvp);

		if (nvp->nvp_signature != 0) {
			if (nvp->nvp_type == SATA_DTYPE_ATADISK) {
				nvp->nvp_state |= NV_PORT_RESTORE;
				nv_port_state_change(nvp,
				    SATA_EVNT_DEVICE_RESET,
				    SATA_ADDR_DCPORT,
				    SATA_DSTATE_RESET|SATA_DSTATE_PWR_ACTIVE);
			}

			goto finished;
		}

		/*
		 * Reset if more than 5 seconds has passed without
		 * acquiring a signature.
		 */
		if (TICK_TO_SEC(ddi_get_lbolt() - nvp->nvp_reset_time) > 5) {
			nv_reset(nvp);
		}

		restart_timeout = B_TRUE;
		goto finished;
	}


	/*
	 * not yet NCQ aware
	 */
	nv_slotp = &(nvp->nvp_slot[0]);

	/*
	 * this happens early on before nv_slotp is set
	 * up OR when a device was unexpectedly removed and
	 * there was an active packet.
	 */
	if (nv_slotp == NULL) {
		NVLOG((NVDBG_TIMEOUT, nvp->nvp_ctlp, nvp,
		    "nv_timeout: nv_slotp == NULL"));

		goto finished;
	}

	/*
	 * perform timeout checking and processing only if there is an
	 * active packet on the port
	 */
	if (nv_slotp->nvslot_spkt != NULL)  {
		sata_pkt_t *spkt = nv_slotp->nvslot_spkt;
		sata_cmd_t *satacmd = &spkt->satapkt_cmd;
		uint8_t cmd = satacmd->satacmd_cmd_reg;
		uint64_t lba;

#if ! defined(__lock_lint) && defined(DEBUG)

		lba = (uint64_t)satacmd->satacmd_lba_low_lsb |
		    ((uint64_t)satacmd->satacmd_lba_mid_lsb << 8) |
		    ((uint64_t)satacmd->satacmd_lba_high_lsb << 16) |
		    ((uint64_t)satacmd->satacmd_lba_low_msb << 24) |
		    ((uint64_t)satacmd->satacmd_lba_mid_msb << 32) |
		    ((uint64_t)satacmd->satacmd_lba_high_msb << 40);
#endif

		/*
		 * timeout not needed if there is a polling thread
		 */
		if (spkt->satapkt_op_mode & SATA_OPMODE_POLLING) {

			goto finished;
		}

		if (TICK_TO_SEC(ddi_get_lbolt() - nv_slotp->nvslot_stime) >
		    spkt->satapkt_time) {
			NVLOG((NVDBG_TIMEOUT, nvp->nvp_ctlp, nvp,
			    "abort timeout: "
			    "nvslot_stime: %ld max ticks till timeout: "
			    "%ld cur_time: %ld cmd=%x lba=%d",
			    nv_slotp->nvslot_stime, drv_usectohz(MICROSEC *
			    spkt->satapkt_time), ddi_get_lbolt(), cmd, lba));

			(void) nv_abort_active(nvp, spkt, SATA_PKT_TIMEOUT);

		} else {
			NVLOG((NVDBG_TIMEOUT, nvp->nvp_ctlp, nvp, "nv_timeout:"
			    " still in use so restarting timeout"));
		}
		restart_timeout = B_TRUE;

	} else {
		/*
		 * there was no active packet, so do not re-enable timeout
		 */
		NVLOG((NVDBG_TIMEOUT, nvp->nvp_ctlp, nvp,
		    "nv_timeout: no active packet so not re-arming timeout"));
	}

	finished:

	if (restart_timeout == B_TRUE) {
		nvp->nvp_timeout_id = timeout(nv_timeout, (void *)nvp,
		    drv_usectohz(NV_ONE_SEC));
	} else {
		nvp->nvp_timeout_id = 0;
	}
	mutex_exit(&nvp->nvp_mutex);
}


/*
 * enable or disable the 3 interrupt types the driver is
 * interested in: completion, add and remove.
 */
static void
mcp04_set_intr(nv_port_t *nvp, int flag)
{
	nv_ctl_t *nvc = nvp->nvp_ctlp;
	ddi_acc_handle_t bar5_hdl = nvc->nvc_bar_hdl[5];
	uchar_t *bar5  = nvc->nvc_bar_addr[5];
	uint8_t intr_bits[] = { MCP04_INT_PDEV_HOT|MCP04_INT_PDEV_INT,
	    MCP04_INT_SDEV_HOT|MCP04_INT_SDEV_INT };
	uint8_t clear_all_bits[] = { MCP04_INT_PDEV_ALL, MCP04_INT_SDEV_ALL };
	uint8_t int_en, port = nvp->nvp_port_num, intr_status;

	ASSERT(mutex_owned(&nvp->nvp_mutex));

	/*
	 * controller level lock also required since access to an 8-bit
	 * interrupt register is shared between both channels.
	 */
	mutex_enter(&nvc->nvc_mutex);

	if (flag & NV_INTR_CLEAR_ALL) {
		NVLOG((NVDBG_INTR, nvc, nvp,
		    "mcp04_set_intr: NV_INTR_CLEAR_ALL"));

		intr_status = nv_get8(nvc->nvc_bar_hdl[5],
		    (uint8_t *)(nvc->nvc_mcp04_int_status));

		if (intr_status & clear_all_bits[port]) {

			nv_put8(nvc->nvc_bar_hdl[5],
			    (uint8_t *)(nvc->nvc_mcp04_int_status),
			    clear_all_bits[port]);

			NVLOG((NVDBG_INTR, nvc, nvp,
			    "interrupt bits cleared %x",
			    intr_status & clear_all_bits[port]));
		}
	}

	if (flag & NV_INTR_DISABLE) {
		NVLOG((NVDBG_INTR, nvc, nvp,
		    "mcp04_set_intr: NV_INTR_DISABLE"));
		int_en = nv_get8(bar5_hdl,
		    (uint8_t *)(bar5 + MCP04_SATA_INT_EN));
		int_en &= ~intr_bits[port];
		nv_put8(bar5_hdl, (uint8_t *)(bar5 + MCP04_SATA_INT_EN),
		    int_en);
	}

	if (flag & NV_INTR_ENABLE) {
		NVLOG((NVDBG_INTR, nvc, nvp, "mcp04_set_intr: NV_INTR_ENABLE"));
		int_en = nv_get8(bar5_hdl,
		    (uint8_t *)(bar5 + MCP04_SATA_INT_EN));
		int_en |= intr_bits[port];
		nv_put8(bar5_hdl, (uint8_t *)(bar5 + MCP04_SATA_INT_EN),
		    int_en);
	}

	mutex_exit(&nvc->nvc_mutex);
}


/*
 * enable or disable the 3 interrupts the driver is interested in:
 * completion interrupt, hot add, and hot remove interrupt.
 */
static void
mcp55_set_intr(nv_port_t *nvp, int flag)
{
	nv_ctl_t *nvc = nvp->nvp_ctlp;
	ddi_acc_handle_t bar5_hdl = nvc->nvc_bar_hdl[5];
	uint16_t intr_bits =
	    MCP55_INT_ADD|MCP55_INT_REM|MCP55_INT_COMPLETE;
	uint16_t int_en;

	ASSERT(mutex_owned(&nvp->nvp_mutex));

	NVLOG((NVDBG_HOT, nvc, nvp, "mcp055_set_intr: enter flag: %d", flag));

	if (flag & NV_INTR_CLEAR_ALL) {
		NVLOG((NVDBG_INTR, nvc, nvp,
		    "mcp55_set_intr: NV_INTR_CLEAR_ALL"));
		nv_put16(bar5_hdl, nvp->nvp_mcp55_int_status, MCP55_INT_CLEAR);
	}

	if (flag & NV_INTR_ENABLE) {
		NVLOG((NVDBG_INTR, nvc, nvp, "mcp55_set_intr: NV_INTR_ENABLE"));
		int_en = nv_get16(bar5_hdl, nvp->nvp_mcp55_int_ctl);
		int_en |= intr_bits;
		nv_put16(bar5_hdl, nvp->nvp_mcp55_int_ctl, int_en);
	}

	if (flag & NV_INTR_DISABLE) {
		NVLOG((NVDBG_INTR, nvc, nvp,
		    "mcp55_set_intr: NV_INTR_DISABLE"));
		int_en = nv_get16(bar5_hdl, nvp->nvp_mcp55_int_ctl);
		int_en &= ~intr_bits;
		nv_put16(bar5_hdl, nvp->nvp_mcp55_int_ctl, int_en);
	}
}


/*
 * The PM functions for suspend and resume are incomplete and need additional
 * work.  It may or may not work in the current state.
 */
static void
nv_resume(nv_port_t *nvp)
{
	NVLOG((NVDBG_INIT, nvp->nvp_ctlp, nvp, "nv_resume()"));

	mutex_enter(&nvp->nvp_mutex);

	if (nvp->nvp_state & NV_PORT_INACTIVE) {
		mutex_exit(&nvp->nvp_mutex);

		return;
	}

	(*(nvp->nvp_ctlp->nvc_set_intr))(nvp, NV_INTR_CLEAR_ALL|NV_INTR_ENABLE);

	/*
	 * power may have been removed to the port and the
	 * drive, and/or a drive may have been added or removed.
	 * Force a reset which will cause a probe and re-establish
	 * any state needed on the drive.
	 * nv_reset(nvp);
	 */

	nv_reset(nvp);

	mutex_exit(&nvp->nvp_mutex);
}

/*
 * The PM functions for suspend and resume are incomplete and need additional
 * work.  It may or may not work in the current state.
 */
static void
nv_suspend(nv_port_t *nvp)
{
	NVLOG((NVDBG_INIT, nvp->nvp_ctlp, nvp, "nv_suspend()"));

	mutex_enter(&nvp->nvp_mutex);

	if (nvp->nvp_state & NV_PORT_INACTIVE) {
		mutex_exit(&nvp->nvp_mutex);

		return;
	}

	(*(nvp->nvp_ctlp->nvc_set_intr))(nvp, NV_INTR_DISABLE);

	/*
	 * power may have been removed to the port and the
	 * drive, and/or a drive may have been added or removed.
	 * Force a reset which will cause a probe and re-establish
	 * any state needed on the drive.
	 * nv_reset(nvp);
	 */

	mutex_exit(&nvp->nvp_mutex);
}


static void
nv_copy_registers(nv_port_t *nvp, sata_device_t *sd, sata_pkt_t *spkt)
{
	ddi_acc_handle_t bar5_hdl = nvp->nvp_ctlp->nvc_bar_hdl[5];
	sata_cmd_t *scmd = &spkt->satapkt_cmd;
	ddi_acc_handle_t ctlhdl = nvp->nvp_ctl_hdl;
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
	uchar_t status;
	struct sata_cmd_flags flags;

	NVLOG((NVDBG_INIT, nvp->nvp_ctlp, nvp, "nv_copy_registers()"));

	sd->satadev_scr.sstatus = nv_get32(bar5_hdl, nvp->nvp_sstatus);
	sd->satadev_scr.serror = nv_get32(bar5_hdl, nvp->nvp_serror);
	sd->satadev_scr.scontrol = nv_get32(bar5_hdl, nvp->nvp_sctrl);

	if (spkt == NULL) {

		return;
	}

	/*
	 * in the error case, implicitly set the return of regs needed
	 * for error handling.
	 */
	status = scmd->satacmd_status_reg = nv_get8(ctlhdl,
	    nvp->nvp_altstatus);

	flags = scmd->satacmd_flags;

	if (status & SATA_STATUS_ERR) {
		flags.sata_copy_out_lba_low_msb = B_TRUE;
		flags.sata_copy_out_lba_mid_msb = B_TRUE;
		flags.sata_copy_out_lba_high_msb = B_TRUE;
		flags.sata_copy_out_lba_low_lsb = B_TRUE;
		flags.sata_copy_out_lba_mid_lsb = B_TRUE;
		flags.sata_copy_out_lba_high_lsb = B_TRUE;
		flags.sata_copy_out_error_reg = B_TRUE;
		flags.sata_copy_out_sec_count_msb = B_TRUE;
		flags.sata_copy_out_sec_count_lsb = B_TRUE;
		scmd->satacmd_status_reg = status;
	}

	if (scmd->satacmd_addr_type & ATA_ADDR_LBA48) {

		/*
		 * set HOB so that high byte will be read
		 */
		nv_put8(ctlhdl, nvp->nvp_devctl, ATDC_HOB|ATDC_D3);

		/*
		 * get the requested high bytes
		 */
		if (flags.sata_copy_out_sec_count_msb) {
			scmd->satacmd_sec_count_msb =
			    nv_get8(cmdhdl, nvp->nvp_count);
		}

		if (flags.sata_copy_out_lba_low_msb) {
			scmd->satacmd_lba_low_msb =
			    nv_get8(cmdhdl, nvp->nvp_sect);
		}

		if (flags.sata_copy_out_lba_mid_msb) {
			scmd->satacmd_lba_mid_msb =
			    nv_get8(cmdhdl, nvp->nvp_lcyl);
		}

		if (flags.sata_copy_out_lba_high_msb) {
			scmd->satacmd_lba_high_msb =
			    nv_get8(cmdhdl, nvp->nvp_hcyl);
		}
	}

	/*
	 * disable HOB so that low byte is read
	 */
	nv_put8(ctlhdl, nvp->nvp_devctl, ATDC_D3);

	/*
	 * get the requested low bytes
	 */
	if (flags.sata_copy_out_sec_count_lsb) {
		scmd->satacmd_sec_count_lsb = nv_get8(cmdhdl, nvp->nvp_count);
	}

	if (flags.sata_copy_out_lba_low_lsb) {
		scmd->satacmd_lba_low_lsb = nv_get8(cmdhdl, nvp->nvp_sect);
	}

	if (flags.sata_copy_out_lba_mid_lsb) {
		scmd->satacmd_lba_mid_lsb = nv_get8(cmdhdl, nvp->nvp_lcyl);
	}

	if (flags.sata_copy_out_lba_high_lsb) {
		scmd->satacmd_lba_high_lsb = nv_get8(cmdhdl, nvp->nvp_hcyl);
	}

	/*
	 * get the device register if requested
	 */
	if (flags.sata_copy_out_device_reg) {
		scmd->satacmd_device_reg =  nv_get8(cmdhdl, nvp->nvp_drvhd);
	}

	/*
	 * get the error register if requested
	 */
	if (flags.sata_copy_out_error_reg) {
		scmd->satacmd_error_reg = nv_get8(cmdhdl, nvp->nvp_error);
	}
}


/*
 * Hot plug and remove interrupts can occur when the device is reset.  Just
 * masking the interrupt doesn't always work well because if a
 * different interrupt arrives on the other port, the driver can still
 * end up checking the state of the other port and discover the hot
 * interrupt flag is set even though it was masked.  Checking for recent
 * reset activity and then ignoring turns out to be the easiest way.
 */
static void
nv_report_add_remove(nv_port_t *nvp, int flags)
{
	ddi_acc_handle_t bar5_hdl = nvp->nvp_ctlp->nvc_bar_hdl[5];
	clock_t time_diff = ddi_get_lbolt() - nvp->nvp_reset_time;
	uint32_t sstatus;
	int i;

	/*
	 * If reset within last 1 second ignore.  This should be
	 * reworked and improved instead of having this somewhat
	 * heavy handed clamping job.
	 */
	if (time_diff < drv_usectohz(NV_ONE_SEC)) {
		NVLOG((NVDBG_HOT, nvp->nvp_ctlp, nvp, "nv_report_add_remove()"
		    "ignoring plug interrupt was %dms ago",
		    TICK_TO_MSEC(time_diff)));

		return;
	}

	/*
	 * wait up to 1ms for sstatus to settle and reflect the true
	 * status of the port.  Failure to do so can create confusion
	 * in probe, where the incorrect sstatus value can still
	 * persist.
	 */
	for (i = 0; i < 1000; i++) {
		sstatus = nv_get32(bar5_hdl, nvp->nvp_sstatus);

		if ((flags == NV_PORT_HOTREMOVED) &&
		    ((sstatus & SSTATUS_DET_DEVPRE_PHYCOM) !=
		    SSTATUS_DET_DEVPRE_PHYCOM)) {
			break;
		}

		if ((flags != NV_PORT_HOTREMOVED) &&
		    ((sstatus & SSTATUS_DET_DEVPRE_PHYCOM) ==
		    SSTATUS_DET_DEVPRE_PHYCOM)) {
			break;
		}
		drv_usecwait(1);
	}

	NVLOG((NVDBG_HOT, nvp->nvp_ctlp, nvp,
	    "sstatus took %i us for DEVPRE_PHYCOM to settle", i));

	if (flags == NV_PORT_HOTREMOVED) {
		NVLOG((NVDBG_HOT, nvp->nvp_ctlp, nvp,
		    "nv_report_add_remove() hot removed"));
		nv_port_state_change(nvp,
		    SATA_EVNT_DEVICE_DETACHED,
		    SATA_ADDR_CPORT, 0);

		nvp->nvp_state |= NV_PORT_HOTREMOVED;
	} else {
		NVLOG((NVDBG_HOT, nvp->nvp_ctlp, nvp,
		    "nv_report_add_remove() hot plugged"));
		nv_port_state_change(nvp, SATA_EVNT_DEVICE_ATTACHED,
		    SATA_ADDR_CPORT, 0);
	}
}
