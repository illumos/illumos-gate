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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 *
 * nv_sata is a combo SATA HBA driver for CK804/MCP04 (ck804) and
 * MCP55/MCP51/MCP61 (mcp5x) based chipsets.
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
 * powering down parts or all of the device.  mcp5x/ck804 is unique in
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
#include <sys/sunddi.h>
#include <sys/sata/sata_hba.h>
#ifdef SGPIO_SUPPORT
#include <sys/sata/adapters/nv_sata/nv_sgpio.h>
#include <sys/devctl.h>
#include <sys/sdt.h>
#endif
#include <sys/sata/adapters/nv_sata/nv_sata.h>
#include <sys/disp.h>
#include <sys/note.h>
#include <sys/promif.h>


/*
 * Function prototypes for driver entry points
 */
static int nv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int nv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int nv_quiesce(dev_info_t *dip);
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
static uint_t mcp5x_intr(caddr_t arg1, caddr_t arg2);
static uint_t ck804_intr(caddr_t arg1, caddr_t arg2);
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
static int nv_start_pkt_pio(nv_port_t *nvp, int slot);
static void nv_intr_pkt_pio(nv_port_t *nvp, nv_slot_t *nv_slotp);
static int nv_start_dma(nv_port_t *nvp, int slot);
static void nv_intr_dma(nv_port_t *nvp, struct nv_slot *spkt);
static void nv_uninit_ctl(nv_ctl_t *nvc);
static void mcp5x_reg_init(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle);
static void ck804_reg_init(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle);
static void nv_uninit_port(nv_port_t *nvp);
static void nv_init_port(nv_port_t *nvp);
static int nv_init_ctl(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle);
static int mcp5x_packet_complete_intr(nv_ctl_t *nvc, nv_port_t *nvp);
#ifdef NCQ
static int mcp5x_dma_setup_intr(nv_ctl_t *nvc, nv_port_t *nvp);
#endif
static void nv_start_dma_engine(nv_port_t *nvp, int slot);
static void nv_port_state_change(nv_port_t *nvp, int event, uint8_t addr_type,
    int state);
static void nv_common_reg_init(nv_ctl_t *nvc);
static void ck804_intr_process(nv_ctl_t *nvc, uint8_t intr_status);
static void nv_reset(nv_port_t *nvp, char *reason);
static void nv_complete_io(nv_port_t *nvp,  sata_pkt_t *spkt, int slot);
static void nv_timeout(void *);
static int nv_poll_wait(nv_port_t *nvp, sata_pkt_t *spkt);
static void nv_cmn_err(int ce, nv_ctl_t *nvc, nv_port_t *nvp, char *fmt, ...);
static void nv_read_signature(nv_port_t *nvp);
static void mcp5x_set_intr(nv_port_t *nvp, int flag);
static void ck804_set_intr(nv_port_t *nvp, int flag);
static void nv_resume(nv_port_t *nvp);
static void nv_suspend(nv_port_t *nvp);
static int nv_start_sync(nv_port_t *nvp, sata_pkt_t *spkt);
static int nv_abort_active(nv_port_t *nvp, sata_pkt_t *spkt, int abort_reason,
    boolean_t reset);
static void nv_copy_registers(nv_port_t *nvp, sata_device_t *sd,
    sata_pkt_t *spkt);
static void nv_link_event(nv_port_t *nvp, int flags);
static int nv_start_async(nv_port_t *nvp, sata_pkt_t *spkt);
static int nv_wait3(nv_port_t *nvp, uchar_t onbits1, uchar_t offbits1,
    uchar_t failure_onbits2, uchar_t failure_offbits2,
    uchar_t failure_onbits3, uchar_t failure_offbits3,
    uint_t timeout_usec, int type_wait);
static int nv_wait(nv_port_t *nvp, uchar_t onbits, uchar_t offbits,
    uint_t timeout_usec, int type_wait);
static int nv_start_rqsense_pio(nv_port_t *nvp, nv_slot_t *nv_slotp);
static void nv_setup_timeout(nv_port_t *nvp, clock_t microseconds);
static clock_t nv_monitor_reset(nv_port_t *nvp);
static int nv_bm_status_clear(nv_port_t *nvp);
static void nv_log(nv_ctl_t *nvc, nv_port_t *nvp, const char *fmt, ...);

#ifdef SGPIO_SUPPORT
static int nv_open(dev_t *devp, int flag, int otyp, cred_t *credp);
static int nv_close(dev_t dev, int flag, int otyp, cred_t *credp);
static int nv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp);

static void nv_sgp_led_init(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle);
static int nv_sgp_detect(ddi_acc_handle_t pci_conf_handle, uint16_t *csrpp,
    uint32_t *cbpp);
static int nv_sgp_init(nv_ctl_t *nvc);
static int nv_sgp_check_set_cmn(nv_ctl_t *nvc);
static int nv_sgp_csr_read(nv_ctl_t *nvc);
static void nv_sgp_csr_write(nv_ctl_t *nvc, uint32_t val);
static int nv_sgp_write_data(nv_ctl_t *nvc);
static void nv_sgp_activity_led_ctl(void *arg);
static void nv_sgp_drive_connect(nv_ctl_t *nvc, int drive);
static void nv_sgp_drive_disconnect(nv_ctl_t *nvc, int drive);
static void nv_sgp_drive_active(nv_ctl_t *nvc, int drive);
static void nv_sgp_locate(nv_ctl_t *nvc, int drive, int value);
static void nv_sgp_error(nv_ctl_t *nvc, int drive, int value);
static void nv_sgp_cleanup(nv_ctl_t *nvc);
#endif


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
	0xffffffffull,		/* dma_attr_maxxfer including all cookies */
	0xffffffffull,		/* dma_attr_seg */
	NV_DMA_NSEGS,		/* dma_attr_sgllen */
	512,			/* dma_attr_granular */
	0,			/* dma_attr_flags */
};
static ddi_dma_attr_t buffer_dma_40bit_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* dma_attr_addr_lo: lowest bus address */
	0xffffffffffull,	/* dma_attr_addr_hi: */
	NV_BM_64K_BOUNDARY - 1,	/* dma_attr_count_max i.e for one cookie */
	4,			/* dma_attr_align */
	1,			/* dma_attr_burstsizes. */
	1,			/* dma_attr_minxfer */
	0xffffffffull,		/* dma_attr_maxxfer including all cookies */
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


#ifdef SGPIO_SUPPORT
static struct cb_ops nv_cb_ops = {
	nv_open,		/* open */
	nv_close,		/* close */
	nodev,			/* strategy (block) */
	nodev,			/* print (block) */
	nodev,			/* dump (block) */
	nodev,			/* read */
	nodev,			/* write */
	nv_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* chpoll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streams */
	D_NEW | D_MP |
	D_64BIT | D_HOTPLUG,	/* flags */
	CB_REV			/* rev */
};
#endif  /* SGPIO_SUPPORT */


static struct dev_ops nv_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt  */
	nv_getinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	nv_attach,		/* attach */
	nv_detach,		/* detach */
	nodev,			/* no reset */
#ifdef SGPIO_SUPPORT
	&nv_cb_ops,		/* driver operations */
#else
	(struct cb_ops *)0,	/* driver operations */
#endif
	NULL,			/* bus operations */
	NULL,			/* power */
	nv_quiesce		/* quiesce */
};


/*
 * Request Sense CDB for ATAPI
 */
static const uint8_t nv_rqsense_cdb[16] = {
	SCMD_REQUEST_SENSE,
	0,
	0,
	0,
	SATA_ATAPI_MIN_RQSENSE_LEN,
	0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0	/* pad out to max CDB length */
};


static sata_tran_hotplug_ops_t nv_hotplug_ops;

extern struct mod_ops mod_driverops;

static  struct modldrv modldrv = {
	&mod_driverops,	/* driverops */
	"NVIDIA CK804/MCP04/MCP51/MCP55/MCP61 HBA",
	&nv_dev_ops,	/* driver ops */
};

static  struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * Maximum number of consecutive interrupts processed in the loop in the
 * single invocation of the port interrupt routine.
 */
int nv_max_intr_loops = NV_MAX_INTR_PER_DEV;

/*
 * wait between checks of reg status
 */
int nv_usec_delay = NV_WAIT_REG_CHECK;

/*
 * The following used for nv_vcmn_err() and nv_log()
 */

/*
 * temp buffer to save from wasting limited stack space
 */
static char nv_log_buf[NV_LOGBUF_LEN];

/*
 * protects nv_log_buf
 */
static kmutex_t nv_log_mutex;

/*
 * these on-by-default flags were chosen so that the driver
 * logs as much non-usual run-time information as possible
 * without overflowing the ring with useless information or
 * causing any significant performance penalty.
 */
int nv_debug_flags =
    NVDBG_HOT|NVDBG_RESET|NVDBG_ALWAYS|NVDBG_TIMEOUT|NVDBG_EVENT;

/*
 * normally debug information is not logged to the console
 * but this allows it to be enabled.
 */
int nv_log_to_console = B_FALSE;

/*
 * normally debug information is not logged to cmn_err but
 * in some cases it may be desired.
 */
int nv_log_to_cmn_err = B_FALSE;

/*
 * using prom print avoids using cmn_err/syslog and goes right
 * to the console which may be desirable in some situations, but
 * it may be synchronous, which would change timings and
 * impact performance.  Use with caution.
 */
int nv_prom_print = B_FALSE;

/*
 * Opaque state pointer to be initialized by ddi_soft_state_init()
 */
static void *nv_statep	= NULL;

/*
 * Map from CBP to shared space
 *
 * When a MCP55/IO55 parts supports SGPIO, there is a single CBP (SGPIO
 * Control Block Pointer as well as the corresponding Control Block) that
 * is shared across all driver instances associated with that part.  The
 * Control Block is used to update and query the LED state for the devices
 * on the controllers associated with those instances.  There is also some
 * driver state (called the 'common' area here) associated with each SGPIO
 * Control Block.  The nv_sgp_cpb2cmn is used to map a given CBP to its
 * control area.
 *
 * The driver can also use this mapping array to determine whether the
 * common area for a given CBP has been initialized, and, if it isn't
 * initialized, initialize it.
 *
 * When a driver instance with a CBP value that is already in the array is
 * initialized, it will use the pointer to the previously initialized common
 * area associated with that SGPIO CBP value, rather than initialize it
 * itself.
 *
 * nv_sgp_c2c_mutex is used to synchronize access to this mapping array.
 */
#ifdef SGPIO_SUPPORT
static kmutex_t nv_sgp_c2c_mutex;
static struct nv_sgp_cbp2cmn nv_sgp_cbp2cmn[NV_MAX_CBPS];
#endif

/*
 * control whether 40bit DMA is used or not
 */
int nv_sata_40bit_dma = B_TRUE;

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
#ifdef SGPIO_SUPPORT
	int	i;
#endif

	error = ddi_soft_state_init(&nv_statep, sizeof (nv_ctl_t), 0);

	if (error != 0) {

		return (error);
	}

	mutex_init(&nv_log_mutex, NULL, MUTEX_DRIVER, NULL);
#ifdef SGPIO_SUPPORT
	mutex_init(&nv_sgp_c2c_mutex, NULL, MUTEX_DRIVER, NULL);

	for (i = 0; i < NV_MAX_CBPS; i++) {
		nv_sgp_cbp2cmn[i].c2cm_cbp = 0;
		nv_sgp_cbp2cmn[i].c2cm_cmn = NULL;
	}
#endif

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
#ifdef SGPIO_SUPPORT
	mutex_destroy(&nv_sgp_c2c_mutex);
#endif
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
	int status, attach_state, intr_types, bar, i, j, command;
	int inst = ddi_get_instance(dip);
	ddi_acc_handle_t pci_conf_handle;
	nv_ctl_t *nvc;
	uint8_t subclass;
	uint32_t reg32;
#ifdef SGPIO_SUPPORT
	pci_regspec_t *regs;
	int rlen;
#endif

	switch (cmd) {

	case DDI_ATTACH:

		attach_state = ATTACH_PROGRESS_NONE;

		status = ddi_soft_state_zalloc(nv_statep, inst);

		if (status != DDI_SUCCESS) {
			break;
		}

		nvc = ddi_get_soft_state(nv_statep, inst);

		nvc->nvc_dip = dip;

		NVLOG(NVDBG_INIT, nvc, NULL, "nv_attach(): DDI_ATTACH", NULL);

		attach_state |= ATTACH_PROGRESS_STATEP_ALLOC;

		if (pci_config_setup(dip, &pci_conf_handle) == DDI_SUCCESS) {
			nvc->nvc_devid = pci_config_get16(pci_conf_handle,
			    PCI_CONF_DEVID);
			nvc->nvc_revid = pci_config_get8(pci_conf_handle,
			    PCI_CONF_REVID);
			NVLOG(NVDBG_INIT, nvc, NULL,
			    "inst %d: devid is %x silicon revid is %x"
			    " nv_debug_flags=%x", inst, nvc->nvc_devid,
			    nvc->nvc_revid, nv_debug_flags);
		} else {
			break;
		}

		attach_state |= ATTACH_PROGRESS_CONF_HANDLE;

		/*
		 * Set the PCI command register: enable IO/MEM/Master.
		 */
		command = pci_config_get16(pci_conf_handle, PCI_CONF_COMM);
		pci_config_put16(pci_conf_handle, PCI_CONF_COMM,
		    command|PCI_COMM_IO|PCI_COMM_MAE|PCI_COMM_ME);

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
				NVLOG(NVDBG_INIT, nvc, NULL,
				    "ddi_regs_map_setup failure for bar"
				    " %d status = %d", bar, status);
				break;
			}
		}

		attach_state |= ATTACH_PROGRESS_BARS;

		/*
		 * initialize controller structures
		 */
		status = nv_init_ctl(nvc, pci_conf_handle);

		if (status == NV_FAILURE) {
			NVLOG(NVDBG_INIT, nvc, NULL, "nv_init_ctl failed",
			    NULL);

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
			    "ddi_intr_get_supported_types failed");

			break;
		}

		NVLOG(NVDBG_INIT, nvc, NULL,
		    "ddi_intr_get_supported_types() returned: 0x%x",
		    intr_types);

#ifdef NV_MSI_SUPPORTED
		if (intr_types & DDI_INTR_TYPE_MSI) {
			NVLOG(NVDBG_INIT, nvc, NULL,
			    "using MSI interrupt type", NULL);

			/*
			 * Try MSI first, but fall back to legacy if MSI
			 * attach fails
			 */
			if (nv_add_msi_intrs(nvc) == DDI_SUCCESS) {
				nvc->nvc_intr_type = DDI_INTR_TYPE_MSI;
				attach_state |= ATTACH_PROGRESS_INTR_ADDED;
				NVLOG(NVDBG_INIT, nvc, NULL,
				    "MSI interrupt setup done", NULL);
			} else {
				nv_cmn_err(CE_CONT, nvc, NULL,
				    "MSI registration failed "
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

			NVLOG(NVDBG_INIT, nvc, NULL,
			    "using Legacy interrupt type", NULL);

			if (nv_add_legacy_intrs(nvc) == DDI_SUCCESS) {
				nvc->nvc_intr_type = DDI_INTR_TYPE_FIXED;
				attach_state |= ATTACH_PROGRESS_INTR_ADDED;
				NVLOG(NVDBG_INIT, nvc, NULL,
				    "Legacy interrupt setup done", NULL);
			} else {
				nv_cmn_err(CE_WARN, nvc, NULL,
				    "legacy interrupt setup failed");
				NVLOG(NVDBG_INIT, nvc, NULL,
				    "legacy interrupt setup failed", NULL);
				break;
			}
		}

		if (!(attach_state & ATTACH_PROGRESS_INTR_ADDED)) {
			NVLOG(NVDBG_INIT, nvc, NULL,
			    "no interrupts registered", NULL);
			break;
		}

#ifdef SGPIO_SUPPORT
		/*
		 * save off the controller number
		 */
		(void) ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)&regs, &rlen);
		nvc->nvc_ctlr_num = PCI_REG_FUNC_G(regs->pci_phys_hi);
		kmem_free(regs, rlen);

		/*
		 * initialize SGPIO
		 */
		nv_sgp_led_init(nvc, pci_conf_handle);
#endif	/* SGPIO_SUPPORT */

		/*
		 * Do initial reset so that signature can be gathered
		 */
		for (j = 0; j < NV_NUM_PORTS; j++) {
			ddi_acc_handle_t bar5_hdl;
			uint32_t sstatus;
			nv_port_t *nvp;

			nvp = &(nvc->nvc_port[j]);
			bar5_hdl = nvp->nvp_ctlp->nvc_bar_hdl[5];
			sstatus = ddi_get32(bar5_hdl, nvp->nvp_sstatus);

			if (SSTATUS_GET_DET(sstatus) ==
			    SSTATUS_DET_DEVPRE_PHYCOM) {

				nvp->nvp_state |= NV_ATTACH;
				nvp->nvp_type = SATA_DTYPE_UNKNOWN;
				mutex_enter(&nvp->nvp_mutex);
				nv_reset(nvp, "attach");

				while (nvp->nvp_state & NV_RESET) {
					cv_wait(&nvp->nvp_reset_cv,
					    &nvp->nvp_mutex);
				}

				mutex_exit(&nvp->nvp_mutex);
			}
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

		NVLOG(NVDBG_INIT, nvc, NULL, "nv_attach DDI_SUCCESS", NULL);

		return (DDI_SUCCESS);

	case DDI_RESUME:

		nvc = ddi_get_soft_state(nv_statep, inst);

		NVLOG(NVDBG_INIT, nvc, NULL,
		    "nv_attach(): DDI_RESUME inst %d", inst);

		if (pci_config_setup(dip, &pci_conf_handle) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		/*
		 * Set the PCI command register: enable IO/MEM/Master.
		 */
		command = pci_config_get16(pci_conf_handle, PCI_CONF_COMM);
		pci_config_put16(pci_conf_handle, PCI_CONF_COMM,
		    command|PCI_COMM_IO|PCI_COMM_MAE|PCI_COMM_ME);

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

		NVLOG(NVDBG_INIT, nvc, NULL, "nv_detach: DDI_DETACH", NULL);

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
		 * Uninitialize the controller structures
		 */
		nv_uninit_ctl(nvc);

#ifdef SGPIO_SUPPORT
		/*
		 * release SGPIO resources
		 */
		nv_sgp_cleanup(nvc);
#endif

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

		NVLOG(NVDBG_INIT, nvc, NULL, "nv_detach: DDI_SUSPEND", NULL);

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


#ifdef SGPIO_SUPPORT
/* ARGSUSED */
static int
nv_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	nv_ctl_t *nvc = ddi_get_soft_state(nv_statep, getminor(*devp));

	if (nvc == NULL) {
		return (ENXIO);
	}

	return (0);
}


/* ARGSUSED */
static int
nv_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}


/* ARGSUSED */
static int
nv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	nv_ctl_t *nvc;
	int inst;
	int status;
	int ctlr, port;
	int drive;
	uint8_t curr_led;
	struct dc_led_ctl led;

	inst = getminor(dev);
	if (inst == -1) {
		return (EBADF);
	}

	nvc = ddi_get_soft_state(nv_statep, inst);
	if (nvc == NULL) {
		return (EBADF);
	}

	if ((nvc->nvc_sgp_cbp == NULL) || (nvc->nvc_sgp_cmn == NULL)) {
		return (EIO);
	}

	switch (cmd) {
	case DEVCTL_SET_LED:
		status = ddi_copyin((void *)arg, &led,
		    sizeof (struct dc_led_ctl), mode);
		if (status != 0)
			return (EFAULT);

		/*
		 * Since only the first two controller currently support
		 * SGPIO (as per NVIDIA docs), this code will as well.
		 * Note that this validate the port value within led_state
		 * as well.
		 */

		ctlr = SGP_DRV_TO_CTLR(led.led_number);
		if ((ctlr != 0) && (ctlr != 1))
			return (ENXIO);

		if ((led.led_state & DCL_STATE_FAST_BLNK) ||
		    (led.led_state & DCL_STATE_SLOW_BLNK)) {
			return (EINVAL);
		}

		drive = led.led_number;

		if ((led.led_ctl_active == DCL_CNTRL_OFF) ||
		    (led.led_state == DCL_STATE_OFF)) {

			if (led.led_type == DCL_TYPE_DEVICE_FAIL) {
				nv_sgp_error(nvc, drive, TR_ERROR_DISABLE);
			} else if (led.led_type == DCL_TYPE_DEVICE_OK2RM) {
				nv_sgp_locate(nvc, drive, TR_LOCATE_DISABLE);
			} else {
				return (ENXIO);
			}

			port = SGP_DRV_TO_PORT(led.led_number);
			nvc->nvc_port[port].nvp_sgp_ioctl_mod |= led.led_type;
		}

		if (led.led_ctl_active == DCL_CNTRL_ON) {
			if (led.led_type == DCL_TYPE_DEVICE_FAIL) {
				nv_sgp_error(nvc, drive, TR_ERROR_ENABLE);
			} else if (led.led_type == DCL_TYPE_DEVICE_OK2RM) {
				nv_sgp_locate(nvc, drive, TR_LOCATE_ENABLE);
			} else {
				return (ENXIO);
			}

			port = SGP_DRV_TO_PORT(led.led_number);
			nvc->nvc_port[port].nvp_sgp_ioctl_mod |= led.led_type;
		}

		break;

	case DEVCTL_GET_LED:
		status = ddi_copyin((void *)arg, &led,
		    sizeof (struct dc_led_ctl), mode);
		if (status != 0)
			return (EFAULT);

		/*
		 * Since only the first two controller currently support
		 * SGPIO (as per NVIDIA docs), this code will as well.
		 * Note that this validate the port value within led_state
		 * as well.
		 */

		ctlr = SGP_DRV_TO_CTLR(led.led_number);
		if ((ctlr != 0) && (ctlr != 1))
			return (ENXIO);

		curr_led = SGPIO0_TR_DRV(nvc->nvc_sgp_cbp->sgpio0_tr,
		    led.led_number);

		port = SGP_DRV_TO_PORT(led.led_number);
		if (nvc->nvc_port[port].nvp_sgp_ioctl_mod & led.led_type) {
			led.led_ctl_active = DCL_CNTRL_ON;

			if (led.led_type == DCL_TYPE_DEVICE_FAIL) {
				if (TR_ERROR(curr_led) == TR_ERROR_DISABLE)
					led.led_state = DCL_STATE_OFF;
				else
					led.led_state = DCL_STATE_ON;
			} else if (led.led_type == DCL_TYPE_DEVICE_OK2RM) {
				if (TR_LOCATE(curr_led) == TR_LOCATE_DISABLE)
					led.led_state = DCL_STATE_OFF;
				else
					led.led_state = DCL_STATE_ON;
			} else {
				return (ENXIO);
			}
		} else {
			led.led_ctl_active = DCL_CNTRL_OFF;
			/*
			 * Not really off, but never set and no constant for
			 * tri-state
			 */
			led.led_state = DCL_STATE_OFF;
		}

		status = ddi_copyout(&led, (void *)arg,
		    sizeof (struct dc_led_ctl), mode);
		if (status != 0)
			return (EFAULT);

		break;

	case DEVCTL_NUM_LEDS:
		led.led_number = SGPIO_DRV_CNT_VALUE;
		led.led_ctl_active = 1;
		led.led_type = 3;

		/*
		 * According to documentation, NVIDIA SGPIO is supposed to
		 * support blinking, but it does not seem to work in practice.
		 */
		led.led_state = DCL_STATE_ON;

		status = ddi_copyout(&led, (void *)arg,
		    sizeof (struct dc_led_ctl), mode);
		if (status != 0)
			return (EFAULT);

		break;

	default:
		return (EINVAL);
	}

	return (0);
}
#endif	/* SGPIO_SUPPORT */


/*
 * Called by sata module to probe a port.  Port and device state
 * are not changed here... only reported back to the sata module.
 *
 */
static int
nv_sata_probe(dev_info_t *dip, sata_device_t *sd)
{
	nv_ctl_t *nvc = ddi_get_soft_state(nv_statep, ddi_get_instance(dip));
	uint8_t cport = sd->satadev_addr.cport;
	uint8_t pmport = sd->satadev_addr.pmport;
	uint8_t qual = sd->satadev_addr.qual;
	uint8_t det;

	nv_port_t *nvp;

	if (cport >= NV_MAX_PORTS(nvc)) {
		sd->satadev_type = SATA_DTYPE_NONE;
		sd->satadev_state = SATA_STATE_UNKNOWN;

		return (SATA_FAILURE);
	}

	ASSERT(nvc->nvc_port != NULL);
	nvp = &(nvc->nvc_port[cport]);
	ASSERT(nvp != NULL);

	NVLOG(NVDBG_ENTRY, nvc, nvp,
	    "nv_sata_probe: enter cport: 0x%x, pmport: 0x%x, "
	    "qual: 0x%x", cport, pmport, qual);

	mutex_enter(&nvp->nvp_mutex);

	/*
	 * This check seems to be done in the SATA module.
	 * It may not be required here
	 */
	if (nvp->nvp_state & NV_DEACTIVATED) {
		nv_cmn_err(CE_WARN, nvc, nvp,
		    "port inactive.  Use cfgadm to activate");
		sd->satadev_type = SATA_DTYPE_UNKNOWN;
		sd->satadev_state = SATA_PSTATE_SHUTDOWN;
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_SUCCESS);
	}

	if (nvp->nvp_state & NV_FAILED) {
		NVLOG(NVDBG_RESET, nvp->nvp_ctlp, nvp,
		    "probe: port failed", NULL);
		sd->satadev_type = nvp->nvp_type;
		sd->satadev_state = SATA_PSTATE_FAILED;
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_SUCCESS);
	}

	if (qual == SATA_ADDR_PMPORT) {
		sd->satadev_type = SATA_DTYPE_NONE;
		sd->satadev_state = SATA_STATE_UNKNOWN;
		mutex_exit(&nvp->nvp_mutex);
		nv_cmn_err(CE_WARN, nvc, nvp,
		    "controller does not support port multiplier");

		return (SATA_SUCCESS);
	}

	sd->satadev_state = SATA_PSTATE_PWRON;

	nv_copy_registers(nvp, sd, NULL);

	if (nvp->nvp_state & (NV_RESET|NV_LINK_EVENT)) {
		/*
		 * during a reset or link event, fake the status
		 * as it may be changing as a result of the reset
		 * or link event.
		 */
		DTRACE_PROBE(state_reset_link_event_faking_status_p);
		DTRACE_PROBE1(nvp_state_h, int, nvp->nvp_state);

		SSTATUS_SET_IPM(sd->satadev_scr.sstatus,
		    SSTATUS_IPM_ACTIVE);
		SSTATUS_SET_DET(sd->satadev_scr.sstatus,
		    SSTATUS_DET_DEVPRE_PHYCOM);
		sd->satadev_type = nvp->nvp_type;
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_SUCCESS);
	}

	det = SSTATUS_GET_DET(sd->satadev_scr.sstatus);

	/*
	 * determine link status
	 */
	if (det != SSTATUS_DET_DEVPRE_PHYCOM) {
		switch (det) {

		case SSTATUS_DET_NODEV:
		case SSTATUS_DET_PHYOFFLINE:
			sd->satadev_type = SATA_DTYPE_NONE;
			break;

		default:
			sd->satadev_type = SATA_DTYPE_UNKNOWN;
			break;
		}

		mutex_exit(&nvp->nvp_mutex);

		return (SATA_SUCCESS);
	}

	/*
	 * Just report the current port state
	 */
	sd->satadev_type = nvp->nvp_type;
	DTRACE_PROBE1(nvp_type_h, int, nvp->nvp_type);

	mutex_exit(&nvp->nvp_mutex);

	return (SATA_SUCCESS);
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

	NVLOG(NVDBG_ENTRY, nvc, nvp, "nv_sata_start: opmode: 0x%x cmd=%x",
	    spkt->satapkt_op_mode, spkt->satapkt_cmd.satacmd_cmd_reg);

	mutex_enter(&nvp->nvp_mutex);

	if (nvp->nvp_state & NV_DEACTIVATED) {

		NVLOG(NVDBG_ERRS, nvc, nvp,
		    "nv_sata_start: NV_DEACTIVATED", NULL);
		DTRACE_PROBE(nvp_state_inactive_p);

		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		nv_copy_registers(nvp, &spkt->satapkt_device, NULL);
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_PORT_ERROR);
	}

	if (nvp->nvp_state & NV_FAILED) {

		NVLOG(NVDBG_ERRS, nvc, nvp,
		    "nv_sata_start: NV_FAILED state", NULL);
		DTRACE_PROBE(nvp_state_failed_p);

		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		nv_copy_registers(nvp, &spkt->satapkt_device, NULL);
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_PORT_ERROR);
	}

	if (nvp->nvp_state & NV_RESET) {

		NVLOG(NVDBG_ERRS, nvc, nvp,
		    "still waiting for reset completion", NULL);
		DTRACE_PROBE(nvp_state_reset_p);

		spkt->satapkt_reason = SATA_PKT_BUSY;

		/*
		 * If in panic, timeouts do not occur, so invoke
		 * reset handling directly so that the signature
		 * can be acquired to complete the reset handling.
		 */
		if (ddi_in_panic()) {
			NVLOG(NVDBG_ERRS, nvc, nvp,
			    "nv_sata_start: calling nv_monitor_reset "
			    "synchronously", NULL);

			(void) nv_monitor_reset(nvp);
		}

		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_BUSY);
	}

	if (nvp->nvp_state & NV_LINK_EVENT) {

		NVLOG(NVDBG_ERRS, nvc, nvp,
		    "nv_sata_start(): link event ret bsy", NULL);
		DTRACE_PROBE(nvp_state_link_event_p);

		spkt->satapkt_reason = SATA_PKT_BUSY;

		if (ddi_in_panic()) {
			NVLOG(NVDBG_ERRS, nvc, nvp,
			    "nv_sata_start: calling nv_timeout "
			    "synchronously", NULL);

			nv_timeout(nvp);
		}

		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_BUSY);
	}


	if ((nvp->nvp_type == SATA_DTYPE_NONE) ||
	    (nvp->nvp_type == SATA_DTYPE_UNKNOWN)) {

		NVLOG(NVDBG_ERRS, nvc, nvp,
		    "nv_sata_start: nvp_type 0x%x", nvp->nvp_type);
		DTRACE_PROBE1(not_ready_nvp_type_h, int, nvp->nvp_type);

		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		nv_copy_registers(nvp, &spkt->satapkt_device, NULL);
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_PORT_ERROR);
	}

	if (spkt->satapkt_device.satadev_type == SATA_DTYPE_PMULT) {

		nv_cmn_err(CE_WARN, nvc, nvp,
		    "port multiplier not supported by controller");

		ASSERT(nvp->nvp_type == SATA_DTYPE_PMULT);
		spkt->satapkt_reason = SATA_PKT_CMD_UNSUPPORTED;
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_CMD_UNSUPPORTED);
	}

	/*
	 * after a device reset, and then when sata module restore processing
	 * is complete, the sata module will set sata_clear_dev_reset which
	 * indicates that restore processing has completed and normal
	 * non-restore related commands should be processed.
	 */
	if (spkt->satapkt_cmd.satacmd_flags.sata_clear_dev_reset) {

		NVLOG(NVDBG_RESET, nvc, nvp,
		    "nv_sata_start: clearing NV_RESTORE", NULL);
		DTRACE_PROBE(clearing_restore_p);
		DTRACE_PROBE1(nvp_state_before_clear_h, int, nvp->nvp_state);

		nvp->nvp_state &= ~NV_RESTORE;
	}

	/*
	 * if the device was recently reset as indicated by NV_RESTORE,
	 * only allow commands which restore device state.  The sata module
	 * marks such commands with sata_ignore_dev_reset.
	 *
	 * during coredump, nv_reset is called but the restore isn't
	 * processed, so ignore the wait for restore if the system
	 * is panicing.
	 */
	if ((nvp->nvp_state & NV_RESTORE) &&
	    !(spkt->satapkt_cmd.satacmd_flags.sata_ignore_dev_reset) &&
	    (ddi_in_panic() == 0)) {

		NVLOG(NVDBG_RESET, nvc, nvp,
		    "nv_sata_start: waiting for restore ", NULL);
		DTRACE_PROBE1(restore_no_ignore_reset_nvp_state_h,
		    int, nvp->nvp_state);

		spkt->satapkt_reason = SATA_PKT_BUSY;
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_BUSY);
	}

	if (nvp->nvp_state & NV_ABORTING) {

		NVLOG(NVDBG_ERRS, nvc, nvp,
		    "nv_sata_start: NV_ABORTING", NULL);
		DTRACE_PROBE1(aborting_nvp_state_h, int, nvp->nvp_state);

		spkt->satapkt_reason = SATA_PKT_BUSY;
		mutex_exit(&nvp->nvp_mutex);

		return (SATA_TRAN_BUSY);
	}

	/*
	 * record command sequence for debugging.
	 */
	nvp->nvp_seq++;

	DTRACE_PROBE2(command_start, int *, nvp, int,
	    spkt->satapkt_cmd.satacmd_cmd_reg);

	/*
	 * clear SError to be able to check errors after the command failure
	 */
	nv_put32(nvp->nvp_ctlp->nvc_bar_hdl[5], nvp->nvp_serror, 0xffffffff);

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

	NVLOG(NVDBG_SYNC, nvp->nvp_ctlp, nvp, "nv_sata_satapkt_sync: entry",
	    NULL);

	if (nvp->nvp_ncq_run != 0 || nvp->nvp_non_ncq_run != 0) {
		spkt->satapkt_reason = SATA_PKT_BUSY;
		NVLOG(NVDBG_SYNC, nvp->nvp_ctlp, nvp,
		    "nv_sata_satapkt_sync: device is busy, sync cmd rejected"
		    "ncq_run: %d non_ncq_run: %d  spkt: %p",
		    nvp->nvp_ncq_run, nvp->nvp_non_ncq_run,
		    (&(nvp->nvp_slot[0]))->nvslot_spkt);

		return (SATA_TRAN_BUSY);
	}

	/*
	 * if SYNC but not POLL, verify that this is not on interrupt thread.
	 */
	if (!(spkt->satapkt_op_mode & SATA_OPMODE_POLLING) &&
	    servicing_interrupt()) {
		spkt->satapkt_reason = SATA_PKT_BUSY;
		NVLOG(NVDBG_SYNC, nvp->nvp_ctlp, nvp,
		    "SYNC mode not allowed during interrupt", NULL);

		return (SATA_TRAN_BUSY);

	}

	/*
	 * disable interrupt generation if in polled mode
	 */
	if (spkt->satapkt_op_mode & SATA_OPMODE_POLLING) {
		(*(nvc->nvc_set_intr))(nvp, NV_INTR_DISABLE);
	}

	/*
	 * overload the satapkt_reason with BUSY so code below
	 * will know when it's done
	 */
	spkt->satapkt_reason = SATA_PKT_BUSY;

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

		NVLOG(NVDBG_SYNC, nvp->nvp_ctlp, nvp, "nv_sata_satapkt_sync:"
		    " done % reason %d", ret);

		return (ret);
	}

	/*
	 * non-polling synchronous mode handling.  The interrupt will signal
	 * when device IO is completed.
	 */
	while (spkt->satapkt_reason == SATA_PKT_BUSY) {
		cv_wait(&nvp->nvp_sync_cv, &nvp->nvp_mutex);
	}


	NVLOG(NVDBG_SYNC, nvp->nvp_ctlp, nvp, "nv_sata_satapkt_sync:"
	    " done % reason %d", spkt->satapkt_reason);

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

	NVLOG(NVDBG_SYNC, nvc, nvp, "nv_poll_wait: enter", NULL);

	for (;;) {

		NV_DELAY_NSEC(400);

		NVLOG(NVDBG_SYNC, nvc, nvp, "nv_poll_wait: before nv_wait",
		    NULL);
		if (nv_wait(nvp, 0, SATA_STATUS_BSY,
		    NV_SEC2USEC(spkt->satapkt_time), NV_NOSLEEP) == B_FALSE) {
			mutex_enter(&nvp->nvp_mutex);
			spkt->satapkt_reason = SATA_PKT_TIMEOUT;
			nv_copy_registers(nvp, &spkt->satapkt_device, spkt);
			nv_reset(nvp, "poll_wait");
			nv_complete_io(nvp, spkt, 0);
			mutex_exit(&nvp->nvp_mutex);
			NVLOG(NVDBG_SYNC, nvc, nvp, "nv_poll_wait: "
			    "SATA_STATUS_BSY", NULL);

			return (SATA_TRAN_ACCEPTED);
		}

		NVLOG(NVDBG_SYNC, nvc, nvp, "nv_poll_wait: before nvc_intr",
		    NULL);

		/*
		 * Simulate interrupt.
		 */
		ret = (*(nvc->nvc_interrupt))((caddr_t)nvc, NULL);
		NVLOG(NVDBG_SYNC, nvc, nvp, "nv_poll_wait: after nvc_intr",
		    NULL);

		if (ret != DDI_INTR_CLAIMED) {
			NVLOG(NVDBG_SYNC, nvc, nvp, "nv_poll_wait:"
			    " unclaimed -- resetting", NULL);
			mutex_enter(&nvp->nvp_mutex);
			nv_copy_registers(nvp, &spkt->satapkt_device, spkt);
			nv_reset(nvp, "poll_wait intr not claimed");
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
	NVLOG(NVDBG_ENTRY, nvc, nvp, "nv_sata_abort %d %p", flag, spkt);

	mutex_enter(&nvp->nvp_mutex);

	if (nvp->nvp_state & NV_DEACTIVATED) {
		mutex_exit(&nvp->nvp_mutex);
		nv_cmn_err(CE_WARN, nvc, nvp,
		    "abort request failed: port inactive");

		return (SATA_FAILURE);
	}

	/*
	 * spkt == NULL then abort all commands
	 */
	c_a = nv_abort_active(nvp, spkt, SATA_PKT_ABORTED, B_TRUE);

	if (c_a) {
		NVLOG(NVDBG_ENTRY, nvc, nvp,
		    "packets aborted running=%d", c_a);
		ret = SATA_SUCCESS;
	} else {
		if (spkt == NULL) {
			NVLOG(NVDBG_ENTRY, nvc, nvp, "no spkts to abort", NULL);
		} else {
			NVLOG(NVDBG_ENTRY, nvc, nvp,
			    "can't find spkt to abort", NULL);
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
nv_abort_active(nv_port_t *nvp, sata_pkt_t *spkt, int abort_reason,
    boolean_t reset)
{
	int aborted = 0, i, reset_once = B_FALSE;
	struct nv_slot *nv_slotp;
	sata_pkt_t *spkt_slot;

	ASSERT(MUTEX_HELD(&nvp->nvp_mutex));

	NVLOG(NVDBG_ENTRY, nvp->nvp_ctlp, nvp, "nv_abort_active", NULL);

	nvp->nvp_state |= NV_ABORTING;

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

			/*
			 * Reset only if explicitly specified by the arg reset
			 */
			if (reset == B_TRUE) {
				reset_once = B_TRUE;
				nv_reset(nvp, "abort_active");
			}
		}

		spkt_slot->satapkt_reason = abort_reason;
		nv_complete_io(nvp, spkt_slot, i);
		aborted++;
	}

	nvp->nvp_state &= ~NV_ABORTING;

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
	int ret = SATA_FAILURE;

	ASSERT(cport < NV_MAX_PORTS(nvc));

	NVLOG(NVDBG_ENTRY, nvc, nvp, "nv_sata_reset", NULL);

	mutex_enter(&nvp->nvp_mutex);

	switch (sd->satadev_addr.qual) {

	case SATA_ADDR_CPORT:
		/*FALLTHROUGH*/
	case SATA_ADDR_DCPORT:

		ret = SATA_SUCCESS;

		/*
		 * If a reset is already in progress, don't disturb it
		 */
		if ((nvp->nvp_state & (NV_RESET|NV_RESTORE)) &&
		    (ddi_in_panic() == 0)) {
			NVLOG(NVDBG_RESET, nvc, nvp,
			    "nv_sata_reset: reset already in progress", NULL);
			DTRACE_PROBE(reset_already_in_progress_p);

			break;
		}

		/*
		 * log the pre-reset state of the driver because dumping the
		 * blocks will disturb it.
		 */
		if (ddi_in_panic() == 1) {
			NVLOG(NVDBG_RESET, nvc, nvp, "in_panic.  nvp_state: "
			    "0x%x nvp_reset_time: %d nvp_last_cmd: 0x%x "
			    "nvp_previous_cmd: 0x%x nvp_reset_count: %d "
			    "nvp_first_reset_reason: %s "
			    "nvp_reset_reason: %s nvp_seq: %d "
			    "in_interrupt: %d", nvp->nvp_state,
			    nvp->nvp_reset_time, nvp->nvp_last_cmd,
			    nvp->nvp_previous_cmd, nvp->nvp_reset_count,
			    nvp->nvp_first_reset_reason,
			    nvp->nvp_reset_reason, nvp->nvp_seq,
			    servicing_interrupt());
		}

		nv_reset(nvp, "sata_reset");

		(void) nv_abort_active(nvp, NULL, SATA_PKT_RESET, B_FALSE);

		/*
		 * If the port is inactive, do a quiet reset and don't attempt
		 * to wait for reset completion or do any post reset processing
		 *
		 */
		if (nvp->nvp_state & NV_DEACTIVATED) {
			nvp->nvp_state &= ~NV_RESET;
			nvp->nvp_reset_time = 0;

			break;
		}

		/*
		 * clear the port failed flag.  It will get set again
		 * if the port is still not functioning.
		 */
		nvp->nvp_state &= ~NV_FAILED;

		/*
		 * timeouts are not available while the system is
		 * dropping core, so call nv_monitor_reset() directly
		 */
		if (ddi_in_panic() != 0) {
			while (nvp->nvp_state & NV_RESET) {
				drv_usecwait(1000);
				(void) nv_monitor_reset(nvp);
			}

			break;
		}

		break;
	case SATA_ADDR_CNTRL:
		NVLOG(NVDBG_ENTRY, nvc, nvp,
		    "nv_sata_reset: controller reset not supported", NULL);

		break;
	case SATA_ADDR_PMPORT:
	case SATA_ADDR_DPMPORT:
		NVLOG(NVDBG_ENTRY, nvc, nvp,
		    "nv_sata_reset: port multipliers not supported", NULL);
		/*FALLTHROUGH*/
	default:
		/*
		 * unsupported case
		 */
		break;
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
	ddi_acc_handle_t bar5_hdl = nvp->nvp_ctlp->nvc_bar_hdl[5];
	uint32_t sstatus;

	ASSERT(cport < NV_MAX_PORTS(nvc));
	NVLOG(NVDBG_ENTRY, nvc, nvp, "nv_sata_activate", NULL);

	mutex_enter(&nvp->nvp_mutex);

	sd->satadev_state = SATA_STATE_READY;

	nv_copy_registers(nvp, sd, NULL);

	(*(nvc->nvc_set_intr))(nvp, NV_INTR_ENABLE);

	/*
	 * initiate link probing and device signature acquisition
	 */

	bar5_hdl = nvp->nvp_ctlp->nvc_bar_hdl[5];

	sstatus = ddi_get32(bar5_hdl, nvp->nvp_sstatus);

	nvp->nvp_type = SATA_DTYPE_NONE;
	nvp->nvp_signature = NV_NO_SIG;
	nvp->nvp_state &= ~NV_DEACTIVATED;

	if (SSTATUS_GET_DET(sstatus) ==
	    SSTATUS_DET_DEVPRE_PHYCOM) {

		nvp->nvp_state |= NV_ATTACH;
		nvp->nvp_type = SATA_DTYPE_UNKNOWN;
		nv_reset(nvp, "sata_activate");

		while (nvp->nvp_state & NV_RESET) {
			cv_wait(&nvp->nvp_reset_cv, &nvp->nvp_mutex);
		}

	}

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
	NVLOG(NVDBG_ENTRY, nvc, nvp, "nv_sata_deactivate", NULL);

	mutex_enter(&nvp->nvp_mutex);

	(void) nv_abort_active(nvp, NULL, SATA_PKT_ABORTED, B_FALSE);

	/*
	 * make the device inaccessible
	 */
	nvp->nvp_state |= NV_DEACTIVATED;

	/*
	 * disable the interrupts on port
	 */
	(*(nvc->nvc_set_intr))(nvp, NV_INTR_DISABLE);

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

	NVLOG(NVDBG_DELIVER, nvc, nvp, "nv_start_common  entered: cmd: 0x%x",
	    sata_cmdp->satacmd_cmd_reg);

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
		NVLOG(NVDBG_DELIVER, nvc, nvp, "setting SACTIVE onbit: %X",
		    on_bit);
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
	case SATAC_DSM:
		dma_cmd = B_TRUE;
		break;
	default:
		dma_cmd = B_FALSE;
	}

	if (sata_cmdp->satacmd_num_dma_cookies != 0 && dma_cmd == B_TRUE) {
		NVLOG(NVDBG_DELIVER, nvc,  nvp, "DMA command", NULL);
		nv_slotp->nvslot_start = nv_start_dma;
		nv_slotp->nvslot_intr = nv_intr_dma;
	} else if (spkt->satapkt_cmd.satacmd_cmd_reg == SATAC_PACKET) {
		NVLOG(NVDBG_DELIVER, nvc,  nvp, "packet command", NULL);
		nv_slotp->nvslot_start = nv_start_pkt_pio;
		nv_slotp->nvslot_intr = nv_intr_pkt_pio;
		if ((direction == SATA_DIR_READ) ||
		    (direction == SATA_DIR_WRITE)) {
			nv_slotp->nvslot_byte_count =
			    spkt->satapkt_cmd.satacmd_bp->b_bcount;
			nv_slotp->nvslot_v_addr =
			    spkt->satapkt_cmd.satacmd_bp->b_un.b_addr;
			/*
			 * Freeing DMA resources allocated by the sata common
			 * module to avoid buffer overwrite (dma sync) problems
			 * when the buffer is released at command completion.
			 * Primarily an issue on systems with more than
			 * 4GB of memory.
			 */
			sata_free_dma_resources(spkt);
		}
	} else if (direction == SATA_DIR_NODATA_XFER) {
		NVLOG(NVDBG_DELIVER, nvc, nvp, "non-data command", NULL);
		nv_slotp->nvslot_start = nv_start_nodata;
		nv_slotp->nvslot_intr = nv_intr_nodata;
	} else if (direction == SATA_DIR_READ) {
		NVLOG(NVDBG_DELIVER, nvc, nvp, "pio in command", NULL);
		nv_slotp->nvslot_start = nv_start_pio_in;
		nv_slotp->nvslot_intr = nv_intr_pio_in;
		nv_slotp->nvslot_byte_count =
		    spkt->satapkt_cmd.satacmd_bp->b_bcount;
		nv_slotp->nvslot_v_addr =
		    spkt->satapkt_cmd.satacmd_bp->b_un.b_addr;
		/*
		 * Freeing DMA resources allocated by the sata common module to
		 * avoid buffer overwrite (dma sync) problems when the buffer
		 * is released at command completion.  This is not an issue
		 * for write because write does not update the buffer.
		 * Primarily an issue on systems with more than 4GB of memory.
		 */
		sata_free_dma_resources(spkt);
	} else if (direction == SATA_DIR_WRITE) {
		NVLOG(NVDBG_DELIVER, nvc, nvp, "pio out command", NULL);
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
#ifdef SGPIO_SUPPORT
		nv_sgp_drive_active(nvp->nvp_ctlp,
		    (nvp->nvp_ctlp->nvc_ctlr_num * 2) + nvp->nvp_port_num);
#endif
		nv_slotp->nvslot_stime = ddi_get_lbolt();

		/*
		 * start timer if it's not already running and this packet
		 * is not requesting polled mode.
		 */
		if ((nvp->nvp_timeout_id == 0) &&
		    ((spkt->satapkt_op_mode & SATA_OPMODE_POLLING) == 0)) {
			nv_setup_timeout(nvp, NV_ONE_SEC);
		}

		nvp->nvp_previous_cmd = nvp->nvp_last_cmd;
		nvp->nvp_last_cmd = spkt->satapkt_cmd.satacmd_cmd_reg;

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
	int retry_count = 0;

	retry:

	nvp->nvp_signature = nv_get8(cmdhdl, nvp->nvp_count);
	nvp->nvp_signature |= (nv_get8(cmdhdl, nvp->nvp_sect) << 8);
	nvp->nvp_signature |= (nv_get8(cmdhdl, nvp->nvp_lcyl) << 16);
	nvp->nvp_signature |= (nv_get8(cmdhdl, nvp->nvp_hcyl) << 24);

	NVLOG(NVDBG_VERBOSE, nvp->nvp_ctlp, nvp,
	    "nv_read_signature: 0x%x ", nvp->nvp_signature);

	switch (nvp->nvp_signature) {

	case NV_DISK_SIG:
		NVLOG(NVDBG_RESET, nvp->nvp_ctlp, nvp, "drive is a disk", NULL);
		DTRACE_PROBE(signature_is_disk_device_p)
		nvp->nvp_type = SATA_DTYPE_ATADISK;

		break;
	case NV_ATAPI_SIG:
		NVLOG(NVDBG_RESET, nvp->nvp_ctlp, nvp,
		    "drive is an optical device", NULL);
		DTRACE_PROBE(signature_is_optical_device_p)
		nvp->nvp_type = SATA_DTYPE_ATAPICD;
		break;
	case NV_PM_SIG:
		NVLOG(NVDBG_RESET, nvp->nvp_ctlp, nvp,
		    "device is a port multiplier", NULL);
		DTRACE_PROBE(signature_is_port_multiplier_p)
		nvp->nvp_type = SATA_DTYPE_PMULT;
		break;
	case NV_NO_SIG:
		NVLOG(NVDBG_VERBOSE, nvp->nvp_ctlp, nvp,
		    "signature not available", NULL);
		DTRACE_PROBE(sig_not_available_p);
		nvp->nvp_type = SATA_DTYPE_UNKNOWN;
		break;
	default:
		if (retry_count++ == 0) {
			/*
			 * this is a rare corner case where the controller
			 * is updating the task file registers as the driver
			 * is reading them.  If this happens, wait a bit and
			 * retry once.
			 */
			NV_DELAY_NSEC(1000000);
			NVLOG(NVDBG_VERBOSE, nvp->nvp_ctlp, nvp,
			    "invalid signature 0x%x retry once",
			    nvp->nvp_signature);
			DTRACE_PROBE1(signature_invalid_retry_once_h,
			    int, nvp->nvp_signature);

			goto retry;
		}

		nv_cmn_err(CE_WARN, nvp->nvp_ctlp, nvp,
		    "invalid signature 0x%x", nvp->nvp_signature);
		nvp->nvp_type = SATA_DTYPE_UNKNOWN;

		break;
	}
}


/*
 * Set up a new timeout or complete a timeout in microseconds.
 * If microseconds is zero, no new timeout is scheduled.  Must be
 * called at the end of the timeout routine.
 */
static void
nv_setup_timeout(nv_port_t *nvp, clock_t microseconds)
{
	clock_t old_duration = nvp->nvp_timeout_duration;

	if (microseconds == 0) {

		return;
	}

	if (nvp->nvp_timeout_id != 0 && nvp->nvp_timeout_duration == 0) {
		/*
		 * Since we are dropping the mutex for untimeout,
		 * the timeout may be executed while we are trying to
		 * untimeout and setting up a new timeout.
		 * If nvp_timeout_duration is 0, then this function
		 * was re-entered. Just exit.
		 */
		cmn_err(CE_WARN, "nv_setup_timeout re-entered");

		return;
	}

	nvp->nvp_timeout_duration = 0;

	if (nvp->nvp_timeout_id == 0) {
		/*
		 * start new timer
		 */
		nvp->nvp_timeout_id = timeout(nv_timeout, (void *)nvp,
		    drv_usectohz(microseconds));
	} else {
		/*
		 * If the currently running timeout is due later than the
		 * requested one, restart it with a new expiration.
		 * Our timeouts do not need to be accurate - we would be just
		 * checking that the specified time was exceeded.
		 */
		if (old_duration > microseconds) {
			mutex_exit(&nvp->nvp_mutex);
			(void) untimeout(nvp->nvp_timeout_id);
			mutex_enter(&nvp->nvp_mutex);
			nvp->nvp_timeout_id = timeout(nv_timeout, (void *)nvp,
			    drv_usectohz(microseconds));
		}
	}

	nvp->nvp_timeout_duration = microseconds;
}



int nv_reset_length = NV_RESET_LENGTH;

/*
 * Reset the port
 */
static void
nv_reset(nv_port_t *nvp, char *reason)
{
	ddi_acc_handle_t bar5_hdl = nvp->nvp_ctlp->nvc_bar_hdl[5];
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
	nv_ctl_t *nvc = nvp->nvp_ctlp;
	uint32_t sctrl, serr, sstatus;
	uint8_t bmicx;
	int i, j;
	boolean_t reset_success = B_FALSE;

	ASSERT(mutex_owned(&nvp->nvp_mutex));

	/*
	 * If the port is reset right after the controller receives
	 * the DMA activate command (or possibly any other FIS),
	 * controller operation freezes without any known recovery
	 * procedure.  Until Nvidia advises on a recovery mechanism,
	 * avoid the situation by waiting sufficiently long to
	 * ensure the link is not actively transmitting any FIS.
	 * 100ms was empirically determined to be large enough to
	 * ensure no transaction was left in flight but not too long
	 * as to cause any significant thread delay.
	 */
	drv_usecwait(100000);

	serr = nv_get32(bar5_hdl, nvp->nvp_serror);
	DTRACE_PROBE1(serror_h, int, serr);

	/*
	 * stop DMA engine.
	 */
	bmicx = nv_get8(nvp->nvp_bm_hdl, nvp->nvp_bmicx);
	nv_put8(nvp->nvp_bm_hdl, nvp->nvp_bmicx,  bmicx & ~BMICX_SSBM);

	/*
	 * the current setting of the NV_RESET in nvp_state indicates whether
	 * this is the first reset attempt or a retry.
	 */
	if (nvp->nvp_state & NV_RESET) {
		nvp->nvp_reset_retry_count++;

		NVLOG(NVDBG_RESET, nvc, nvp, "npv_reset_retry_count: %d",
		    nvp->nvp_reset_retry_count);

	} else {
		nvp->nvp_reset_retry_count = 0;
		nvp->nvp_reset_count++;
		nvp->nvp_state |= NV_RESET;

		NVLOG(NVDBG_RESET, nvc, nvp, "nvp_reset_count: %d reason: %s "
		    "serror: 0x%x seq: %d run: %d cmd: 0x%x",
		    nvp->nvp_reset_count, reason, serr, nvp->nvp_seq,
		    nvp->nvp_non_ncq_run, nvp->nvp_last_cmd);
	}

	/*
	 * a link event could have occurred slightly before excessive
	 * interrupt processing invokes a reset.  Reset handling overrides
	 * link event processing so it's safe to clear it here.
	 */
	nvp->nvp_state &= ~(NV_RESTORE|NV_LINK_EVENT);

	nvp->nvp_reset_time = ddi_get_lbolt();

	if ((nvp->nvp_state & (NV_ATTACH|NV_HOTPLUG)) == 0) {
		nv_cmn_err(CE_NOTE, nvc, nvp, "nv_reset: reason: %s serr 0x%x"
		    " nvp_state: 0x%x", reason, serr, nvp->nvp_state);
		/*
		 * keep a record of why the first reset occurred, for debugging
		 */
		if (nvp->nvp_first_reset_reason[0] == '\0') {
			(void) strncpy(nvp->nvp_first_reset_reason,
			    reason, NV_REASON_LEN);
			nvp->nvp_first_reset_reason[NV_REASON_LEN - 1] = '\0';
		}
	}

	(void) strncpy(nvp->nvp_reset_reason, reason, NV_REASON_LEN);

	/*
	 * ensure there is terminating NULL
	 */
	nvp->nvp_reset_reason[NV_REASON_LEN - 1] = '\0';

	/*
	 * Issue hardware reset; retry if necessary.
	 */
	for (i = 0; i < NV_COMRESET_ATTEMPTS; i++) {

		/*
		 * clear signature registers and the error register too
		 */
		nv_put8(cmdhdl, nvp->nvp_sect, 0);
		nv_put8(cmdhdl, nvp->nvp_lcyl, 0);
		nv_put8(cmdhdl, nvp->nvp_hcyl, 0);
		nv_put8(cmdhdl, nvp->nvp_count, 0);

		nv_put8(nvp->nvp_cmd_hdl, nvp->nvp_error, 0);

		/*
		 * assert reset in PHY by writing a 1 to bit 0 scontrol
		 */
		sctrl = nv_get32(bar5_hdl, nvp->nvp_sctrl);

		nv_put32(bar5_hdl, nvp->nvp_sctrl,
		    sctrl | SCONTROL_DET_COMRESET);

		/* Wait at least 1ms, as required by the spec */
		drv_usecwait(nv_reset_length);

		serr = nv_get32(bar5_hdl, nvp->nvp_serror);
		DTRACE_PROBE1(aftercomreset_serror_h, int, serr);

		/* Reset all accumulated error bits */
		nv_put32(bar5_hdl, nvp->nvp_serror, 0xffffffff);


		sstatus = nv_get32(bar5_hdl, nvp->nvp_sstatus);
		sctrl = nv_get32(bar5_hdl, nvp->nvp_sctrl);
		NVLOG(NVDBG_RESET, nvc, nvp, "nv_reset: applied (%d); "
		    "sctrl 0x%x, sstatus 0x%x", i, sctrl, sstatus);

		/* de-assert reset in PHY */
		nv_put32(bar5_hdl, nvp->nvp_sctrl,
		    sctrl & ~SCONTROL_DET_COMRESET);

		/*
		 * Wait up to 10ms for COMINIT to arrive, indicating that
		 * the device recognized COMRESET.
		 */
		for (j = 0; j < 10; j++) {
			drv_usecwait(NV_ONE_MSEC);
			sstatus = nv_get32(bar5_hdl, nvp->nvp_sstatus);
			if ((SSTATUS_GET_IPM(sstatus) == SSTATUS_IPM_ACTIVE) &&
			    (SSTATUS_GET_DET(sstatus) ==
			    SSTATUS_DET_DEVPRE_PHYCOM)) {
				reset_success = B_TRUE;
				break;
			}
		}

		if (reset_success == B_TRUE)
			break;
	}


	serr = nv_get32(bar5_hdl, nvp->nvp_serror);
	DTRACE_PROBE1(last_serror_h, int, serr);

	if (reset_success == B_FALSE) {
		NVLOG(NVDBG_RESET, nvc, nvp, "nv_reset not succeeded "
		    "after %d attempts. serr: 0x%x", i, serr);
	} else {
		NVLOG(NVDBG_RESET, nvc, nvp, "nv_reset succeeded"
		    " after %dms. serr: 0x%x", TICK_TO_MSEC(ddi_get_lbolt() -
		    nvp->nvp_reset_time), serr);
	}

	nvp->nvp_wait_sig  = NV_WAIT_SIG;
	nv_setup_timeout(nvp, nvp->nvp_wait_sig);
}


/*
 * Initialize register handling specific to mcp51/mcp55/mcp61
 */
/* ARGSUSED */
static void
mcp5x_reg_init(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle)
{
	nv_port_t *nvp;
	uchar_t *bar5  = nvc->nvc_bar_addr[5];
	uint8_t off, port;

	nvc->nvc_mcp5x_ctl = (uint32_t *)(bar5 + MCP5X_CTL);
	nvc->nvc_mcp5x_ncq = (uint32_t *)(bar5 + MCP5X_NCQ);

	for (port = 0, off = 0; port < NV_MAX_PORTS(nvc); port++, off += 2) {
		nvp = &(nvc->nvc_port[port]);
		nvp->nvp_mcp5x_int_status =
		    (uint16_t *)(bar5 + MCP5X_INT_STATUS + off);
		nvp->nvp_mcp5x_int_ctl =
		    (uint16_t *)(bar5 + MCP5X_INT_CTL + off);

		/*
		 * clear any previous interrupts asserted
		 */
		nv_put16(nvc->nvc_bar_hdl[5], nvp->nvp_mcp5x_int_status,
		    MCP5X_INT_CLEAR);

		/*
		 * These are the interrupts to accept for now.  The spec
		 * says these are enable bits, but nvidia has indicated
		 * these are masking bits.  Even though they may be masked
		 * out to prevent asserting the main interrupt, they can
		 * still be asserted while reading the interrupt status
		 * register, so that needs to be considered in the interrupt
		 * handler.
		 */
		nv_put16(nvc->nvc_bar_hdl[5], nvp->nvp_mcp5x_int_ctl,
		    ~(MCP5X_INT_IGNORE));
	}

	/*
	 * Allow the driver to program the BM on the first command instead
	 * of waiting for an interrupt.
	 */
#ifdef NCQ
	flags = MCP_SATA_AE_NCQ_PDEV_FIRST_CMD | MCP_SATA_AE_NCQ_SDEV_FIRST_CMD;
	nv_put32(nvc->nvc_bar_hdl[5], nvc->nvc_mcp5x_ncq, flags);
	flags = MCP_SATA_AE_CTL_PRI_SWNCQ | MCP_SATA_AE_CTL_SEC_SWNCQ;
	nv_put32(nvc->nvc_bar_hdl[5], nvc->nvc_mcp5x_ctl, flags);
#endif

	/*
	 * mcp55 rev A03 and above supports 40-bit physical addressing.
	 * Enable DMA to take advantage of that.
	 *
	 */
	if ((nvc->nvc_devid > 0x37f) ||
	    ((nvc->nvc_devid == 0x37f) && (nvc->nvc_revid >= 0xa3))) {
		if (nv_sata_40bit_dma == B_TRUE) {
			uint32_t reg32;
			NVLOG(NVDBG_INIT, nvp->nvp_ctlp, nvp,
			    "devid is %X revid is %X. 40-bit DMA"
			    " addressing enabled", nvc->nvc_devid,
			    nvc->nvc_revid);
			nvc->dma_40bit = B_TRUE;

			reg32 = pci_config_get32(pci_conf_handle,
			    NV_SATA_CFG_20);
			pci_config_put32(pci_conf_handle, NV_SATA_CFG_20,
			    reg32 | NV_40BIT_PRD);

			/*
			 * CFG_23 bits 0-7 contain the top 8 bits (of 40
			 * bits) for the primary PRD table, and bits 8-15
			 * contain the top 8 bits for the secondary.  Set
			 * to zero because the DMA attribute table for PRD
			 * allocation forces it into 32 bit address space
			 * anyway.
			 */
			reg32 = pci_config_get32(pci_conf_handle,
			    NV_SATA_CFG_23);
			pci_config_put32(pci_conf_handle, NV_SATA_CFG_23,
			    reg32 & 0xffff0000);
		} else {
			NVLOG(NVDBG_INIT, nvp->nvp_ctlp, nvp,
			    "40-bit DMA disabled by nv_sata_40bit_dma", NULL);
		}
	} else {
		nv_cmn_err(CE_NOTE, nvp->nvp_ctlp, nvp, "devid is %X revid is"
		    " %X. Not capable of 40-bit DMA addressing",
		    nvc->nvc_devid, nvc->nvc_revid);
	}
}


/*
 * Initialize register handling specific to ck804
 */
static void
ck804_reg_init(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle)
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
	    reg32 | CK804_CFG_DELAY_HOTPLUG_INTR);

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

	nvc->nvc_ck804_int_status = (uint8_t *)(bar5 + CK804_SATA_INT_STATUS);

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
 * determine if ck804 or mcp5x class.
 */
static int
nv_init_ctl(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle)
{
	struct sata_hba_tran stran;
	nv_port_t *nvp;
	int j;
	uchar_t *cmd_addr, *ctl_addr, *bm_addr;
	ddi_acc_handle_t bar5_hdl = nvc->nvc_bar_hdl[5];
	uchar_t *bar5  = nvc->nvc_bar_addr[5];
	uint32_t reg32;
	uint8_t reg8, reg8_save;

	NVLOG(NVDBG_INIT, nvc, NULL, "nv_init_ctl entered", NULL);

	nvc->nvc_mcp5x_flag = B_FALSE;

	/*
	 * Need to set bit 2 to 1 at config offset 0x50
	 * to enable access to the bar5 registers.
	 */
	reg32 = pci_config_get32(pci_conf_handle, NV_SATA_CFG_20);
	if (!(reg32 & NV_BAR5_SPACE_EN)) {
		pci_config_put32(pci_conf_handle, NV_SATA_CFG_20,
		    reg32 | NV_BAR5_SPACE_EN);
	}

	/*
	 * Determine if this is ck804 or mcp5x.  ck804 will map in the
	 * task file registers into bar5 while mcp5x won't.  The offset of
	 * the task file registers in mcp5x's space is unused, so it will
	 * return zero.  So check one of the task file registers to see if it is
	 * writable and reads back what was written.  If it's mcp5x it will
	 * return back 0xff whereas ck804 will return the value written.
	 */
	reg8_save = nv_get8(bar5_hdl,
	    (uint8_t *)(bar5 + NV_BAR5_TRAN_LEN_CH_X));


	for (j = 1; j < 3; j++) {

		nv_put8(bar5_hdl, (uint8_t *)(bar5 + NV_BAR5_TRAN_LEN_CH_X), j);
		reg8 = nv_get8(bar5_hdl,
		    (uint8_t *)(bar5 + NV_BAR5_TRAN_LEN_CH_X));

		if (reg8 != j) {
			nvc->nvc_mcp5x_flag = B_TRUE;
			break;
		}
	}

	nv_put8(bar5_hdl, (uint8_t *)(bar5 + NV_BAR5_TRAN_LEN_CH_X), reg8_save);

	if (nvc->nvc_mcp5x_flag == B_FALSE) {
		NVLOG(NVDBG_INIT, nvc, NULL, "controller is CK804/MCP04",
		    NULL);
		nvc->nvc_interrupt = ck804_intr;
		nvc->nvc_reg_init = ck804_reg_init;
		nvc->nvc_set_intr = ck804_set_intr;
	} else {
		NVLOG(NVDBG_INIT, nvc, NULL, "controller is MCP51/MCP55/MCP61",
		    NULL);
		nvc->nvc_interrupt = mcp5x_intr;
		nvc->nvc_reg_init = mcp5x_reg_init;
		nvc->nvc_set_intr = mcp5x_set_intr;
	}


	stran.sata_tran_hba_rev = SATA_TRAN_HBA_REV;
	stran.sata_tran_hba_dip = nvc->nvc_dip;
	stran.sata_tran_hba_num_cports = NV_NUM_PORTS;
	stran.sata_tran_hba_features_support =
	    SATA_CTLF_HOTPLUG | SATA_CTLF_ASN | SATA_CTLF_ATAPI;
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

		cv_init(&nvp->nvp_sync_cv, NULL, CV_DRIVER, NULL);
		cv_init(&nvp->nvp_reset_cv, NULL, CV_DRIVER, NULL);

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

		/*
		 * Initialize dma handles, etc.
		 * If it fails, the port is in inactive state.
		 */
		nv_init_port(nvp);
	}

	/*
	 * initialize register by calling chip specific reg initialization
	 */
	(*(nvc->nvc_reg_init))(nvc, pci_conf_handle);

	/* initialize the hba dma attribute */
	if (nvc->dma_40bit == B_TRUE)
		nvc->nvc_sata_hba_tran.sata_tran_hba_dma_attr =
		    &buffer_dma_40bit_attr;
	else
		nvc->nvc_sata_hba_tran.sata_tran_hba_dma_attr =
		    &buffer_dma_attr;

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
static void
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

			return;
		}

		rc = ddi_dma_mem_alloc(nvp->nvp_sg_dma_hdl[i], prd_size,
		    &dev_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP,
		    NULL, &(nvp->nvp_sg_addr[i]), &buf_size,
		    &(nvp->nvp_sg_acc_hdl[i]));

		if (rc != DDI_SUCCESS) {
			nv_uninit_port(nvp);

			return;
		}

		rc = ddi_dma_addr_bind_handle(nvp->nvp_sg_dma_hdl[i], NULL,
		    nvp->nvp_sg_addr[i], buf_size,
		    DDI_DMA_WRITE | DDI_DMA_CONSISTENT,
		    DDI_DMA_SLEEP, NULL, &cookie, &count);

		if (rc != DDI_DMA_MAPPED) {
			nv_uninit_port(nvp);

			return;
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

	/*
	 * Port is initialized whether the device is attached or not.
	 * Link processing and device identification will be started later,
	 * after interrupts are initialized.
	 */
	nvp->nvp_type = SATA_DTYPE_NONE;
}


/*
 * Free dynamically allocated structures for port.
 */
static void
nv_uninit_port(nv_port_t *nvp)
{
	int i;

	NVLOG(NVDBG_INIT, nvp->nvp_ctlp, nvp,
	    "nv_uninit_port uninitializing", NULL);

#ifdef SGPIO_SUPPORT
	if (nvp->nvp_type == SATA_DTYPE_ATADISK) {
		nv_sgp_drive_disconnect(nvp->nvp_ctlp, SGP_CTLR_PORT_TO_DRV(
		    nvp->nvp_ctlp->nvc_ctlr_num, nvp->nvp_port_num));
	}
#endif

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
		NVLOG(NVDBG_INIT, nvc, nvp, "setting up port mappings", NULL);

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

	NVLOG(NVDBG_INIT, nvc, NULL, "nv_uninit_ctl entered", NULL);

	for (port = 0; port < NV_MAX_PORTS(nvc); port++) {
		nvp = &(nvc->nvc_port[port]);
		mutex_enter(&nvp->nvp_mutex);
		NVLOG(NVDBG_INIT, nvc, nvp, "uninitializing port", NULL);
		nv_uninit_port(nvp);
		mutex_exit(&nvp->nvp_mutex);
		mutex_destroy(&nvp->nvp_mutex);
		cv_destroy(&nvp->nvp_sync_cv);
		cv_destroy(&nvp->nvp_reset_cv);
	}

	kmem_free(nvc->nvc_port, NV_MAX_PORTS(nvc) * sizeof (nv_port_t));
	nvc->nvc_port = NULL;
}


/*
 * ck804 interrupt.  This is a wrapper around ck804_intr_process so
 * that interrupts from other devices can be disregarded while dtracing.
 */
/* ARGSUSED */
static uint_t
ck804_intr(caddr_t arg1, caddr_t arg2)
{
	nv_ctl_t *nvc = (nv_ctl_t *)arg1;
	uint8_t intr_status;
	ddi_acc_handle_t bar5_hdl = nvc->nvc_bar_hdl[5];

	if (nvc->nvc_state & NV_CTRL_SUSPEND)
		return (DDI_INTR_UNCLAIMED);

	intr_status = ddi_get8(bar5_hdl, nvc->nvc_ck804_int_status);

	if (intr_status == 0) {

		return (DDI_INTR_UNCLAIMED);
	}

	ck804_intr_process(nvc, intr_status);

	return (DDI_INTR_CLAIMED);
}


/*
 * Main interrupt handler for ck804.  handles normal device
 * interrupts and hot plug and remove interrupts.
 *
 */
static void
ck804_intr_process(nv_ctl_t *nvc, uint8_t intr_status)
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
		CK804_INT_PDEV_HOT, CK804_INT_SDEV_HOT,
	};
	int port_mask_pm[] = {
		CK804_INT_PDEV_PM, CK804_INT_SDEV_PM,
	};

	NVLOG(NVDBG_INTR, nvc, NULL,
	    "ck804_intr_process entered intr_status=%x", intr_status);

	/*
	 * For command completion interrupt, explicit clear is not required.
	 * however, for the error cases explicit clear is performed.
	 */
	for (port = 0; port < NV_MAX_PORTS(nvc); port++) {

		int port_mask[] = {CK804_INT_PDEV_INT, CK804_INT_SDEV_INT};

		if ((port_mask[port] & intr_status) == 0) {

			continue;
		}

		NVLOG(NVDBG_INTR, nvc, NULL,
		    "ck804_intr_process interrupt on port %d", port);

		nvp = &(nvc->nvc_port[port]);

		mutex_enter(&nvp->nvp_mutex);

		/*
		 * this case might be encountered when the other port
		 * is active
		 */
		if (nvp->nvp_state & NV_DEACTIVATED) {

			/*
			 * clear interrupt bits
			 */
			nv_put8(bar5_hdl, nvc->nvc_ck804_int_status,
			    port_mask[port]);

			mutex_exit(&nvp->nvp_mutex);

			continue;
		}


		if ((&(nvp->nvp_slot[0]))->nvslot_spkt == NULL)  {
			status = nv_get8(nvp->nvp_ctl_hdl, nvp->nvp_status);
			NVLOG(NVDBG_ALWAYS, nvc, nvp, "spurious interrupt "
			    " no command in progress status=%x", status);
			mutex_exit(&nvp->nvp_mutex);

			/*
			 * clear interrupt bits
			 */
			nv_put8(bar5_hdl, nvc->nvc_ck804_int_status,
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

		if (nv_slotp->nvslot_flags == NVSLOT_COMPLETE) {

			nv_complete_io(nvp, spkt, 0);
		}

		mutex_exit(&nvp->nvp_mutex);
	}

	/*
	 * ck804 often doesn't correctly distinguish hot add/remove
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
			NVLOG(NVDBG_HOT, nvc, nvp,
			    "clearing PM interrupt bit: %x",
			    intr_status & port_mask_pm[port]);
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
			nv_link_event(nvp, NV_REM_DEV);
		} else {
			nv_link_event(nvp, NV_ADD_DEV);
		}
	clear:
		/*
		 * clear interrupt bits.  explicit interrupt clear is
		 * required for hotplug interrupts.
		 */
		nv_put8(bar5_hdl, nvc->nvc_ck804_int_status, clear_bits);

		/*
		 * make sure it's flushed and cleared.  If not try
		 * again.  Sometimes it has been observed to not clear
		 * on the first try.
		 */
		intr_status = nv_get8(bar5_hdl, nvc->nvc_ck804_int_status);

		/*
		 * make 10 additional attempts to clear the interrupt
		 */
		for (i = 0; (intr_status & clear_bits) && (i < 10); i++) {
			NVLOG(NVDBG_ALWAYS, nvc, nvp, "inst_status=%x "
			    "still not clear try=%d", intr_status,
			    ++nvcleared);
			nv_put8(bar5_hdl, nvc->nvc_ck804_int_status,
			    clear_bits);
			intr_status = nv_get8(bar5_hdl,
			    nvc->nvc_ck804_int_status);
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
			nvp->nvp_state |= NV_FAILED;
			(void) nv_abort_active(nvp, NULL, SATA_PKT_DEV_ERROR,
			    B_TRUE);
			nv_cmn_err(CE_WARN, nvc, nvp, "unable to clear "
			    "interrupt.  disabling port intr_status=%X",
			    intr_status);
		}

		mutex_exit(&nvp->nvp_mutex);
	}
}


/*
 * Interrupt handler for mcp5x.  It is invoked by the wrapper for each port
 * on the controller, to handle completion and hot plug and remove events.
 */
static uint_t
mcp5x_intr_port(nv_port_t *nvp)
{
	nv_ctl_t *nvc = nvp->nvp_ctlp;
	ddi_acc_handle_t bar5_hdl = nvc->nvc_bar_hdl[5];
	uint8_t clear = 0, intr_cycles = 0;
	int ret = DDI_INTR_UNCLAIMED;
	uint16_t int_status;
	clock_t intr_time;
	int loop_cnt = 0;

	nvp->intr_start_time = ddi_get_lbolt();

	NVLOG(NVDBG_INTR, nvc, nvp, "mcp55_intr_port entered", NULL);

	do {
		/*
		 * read current interrupt status
		 */
		int_status = nv_get16(bar5_hdl, nvp->nvp_mcp5x_int_status);

		/*
		 * if the port is deactivated, just clear the interrupt and
		 * return.  can get here even if interrupts were disabled
		 * on this port but enabled on the other.
		 */
		if (nvp->nvp_state & NV_DEACTIVATED) {
			nv_put16(bar5_hdl, nvp->nvp_mcp5x_int_status,
			    int_status);

			return (DDI_INTR_CLAIMED);
		}

		NVLOG(NVDBG_INTR, nvc, nvp, "int_status = %x", int_status);

		DTRACE_PROBE1(int_status_before_h, int, int_status);

		/*
		 * MCP5X_INT_IGNORE interrupts will show up in the status,
		 * but are masked out from causing an interrupt to be generated
		 * to the processor.  Ignore them here by masking them out.
		 */
		int_status &= ~(MCP5X_INT_IGNORE);

		DTRACE_PROBE1(int_status_after_h, int, int_status);

		/*
		 * exit the loop when no more interrupts to process
		 */
		if (int_status == 0) {

			break;
		}

		if (int_status & MCP5X_INT_COMPLETE) {
			NVLOG(NVDBG_INTR, nvc, nvp,
			    "mcp5x_packet_complete_intr", NULL);
			/*
			 * since int_status was set, return DDI_INTR_CLAIMED
			 * from the DDI's perspective even though the packet
			 * completion may not have succeeded.  If it fails,
			 * need to manually clear the interrupt, otherwise
			 * clearing is implicit as a result of reading the
			 * task file status register.
			 */
			ret = DDI_INTR_CLAIMED;
			if (mcp5x_packet_complete_intr(nvc, nvp) ==
			    NV_FAILURE) {
				clear |= MCP5X_INT_COMPLETE;
			} else {
				intr_cycles = 0;
			}
		}

		if (int_status & MCP5X_INT_DMA_SETUP) {
			NVLOG(NVDBG_INTR, nvc, nvp, "mcp5x_dma_setup_intr",
			    NULL);

			/*
			 * Needs to be cleared before starting the BM, so do it
			 * now.  make sure this is still working.
			 */
			nv_put16(bar5_hdl, nvp->nvp_mcp5x_int_status,
			    MCP5X_INT_DMA_SETUP);
#ifdef NCQ
			ret = mcp5x_dma_setup_intr(nvc, nvp);
#endif
		}

		if (int_status & MCP5X_INT_REM) {
			clear |= MCP5X_INT_REM;
			ret = DDI_INTR_CLAIMED;

			mutex_enter(&nvp->nvp_mutex);
			nv_link_event(nvp, NV_REM_DEV);
			mutex_exit(&nvp->nvp_mutex);

		} else if (int_status & MCP5X_INT_ADD) {
			clear |= MCP5X_INT_ADD;
			ret = DDI_INTR_CLAIMED;

			mutex_enter(&nvp->nvp_mutex);
			nv_link_event(nvp, NV_ADD_DEV);
			mutex_exit(&nvp->nvp_mutex);
		}
		if (clear) {
			nv_put16(bar5_hdl, nvp->nvp_mcp5x_int_status, clear);
			clear = 0;
		}

		/*
		 * protect against a stuck interrupt
		 */
		if (intr_cycles++ == NV_MAX_INTR_LOOP) {

			NVLOG(NVDBG_INTR, nvc, nvp, "excessive interrupt "
			    "processing.  Disabling interrupts int_status=%X"
			    " clear=%X", int_status, clear);
			DTRACE_PROBE(excessive_interrupts_f);

			mutex_enter(&nvp->nvp_mutex);
			(*(nvc->nvc_set_intr))(nvp, NV_INTR_DISABLE);
			/*
			 * reset the device.  If it remains inaccessible
			 * after a reset it will be failed then.
			 */
			(void) nv_abort_active(nvp, NULL, SATA_PKT_DEV_ERROR,
			    B_TRUE);
			mutex_exit(&nvp->nvp_mutex);
		}

	} while (loop_cnt++ < nv_max_intr_loops);

	if (loop_cnt > nvp->intr_loop_cnt) {
		NVLOG(NVDBG_INTR, nvp->nvp_ctlp, nvp,
		    "Exiting with multiple intr loop count %d", loop_cnt);
		nvp->intr_loop_cnt = loop_cnt;
	}

	if ((nv_debug_flags & (NVDBG_INTR | NVDBG_VERBOSE)) ==
	    (NVDBG_INTR | NVDBG_VERBOSE)) {
		uint8_t status, bmstatus;
		uint16_t int_status2;

		if (int_status & MCP5X_INT_COMPLETE) {
			status = nv_get8(nvp->nvp_ctl_hdl, nvp->nvp_altstatus);
			bmstatus = nv_get8(nvp->nvp_bm_hdl, nvp->nvp_bmisx);
			int_status2 = nv_get16(nvp->nvp_ctlp->nvc_bar_hdl[5],
			    nvp->nvp_mcp5x_int_status);
			NVLOG(NVDBG_TIMEOUT, nvp->nvp_ctlp, nvp,
			    "mcp55_intr_port: Exiting with altstatus %x, "
			    "bmicx %x, int_status2 %X, int_status %X, ret %x,"
			    " loop_cnt %d ", status, bmstatus, int_status2,
			    int_status, ret, loop_cnt);
		}
	}

	NVLOG(NVDBG_INTR, nvc, nvp, "mcp55_intr_port: finished ret=%d", ret);

	/*
	 * To facilitate debugging, keep track of the length of time spent in
	 * the port interrupt routine.
	 */
	intr_time = ddi_get_lbolt() - nvp->intr_start_time;
	if (intr_time > nvp->intr_duration)
		nvp->intr_duration = intr_time;

	return (ret);
}


/* ARGSUSED */
static uint_t
mcp5x_intr(caddr_t arg1, caddr_t arg2)
{
	nv_ctl_t *nvc = (nv_ctl_t *)arg1;
	int ret;

	if (nvc->nvc_state & NV_CTRL_SUSPEND)
		return (DDI_INTR_UNCLAIMED);

	ret = mcp5x_intr_port(&(nvc->nvc_port[0]));
	ret |= mcp5x_intr_port(&(nvc->nvc_port[1]));

	return (ret);
}


#ifdef NCQ
/*
 * with software driven NCQ on mcp5x, an interrupt occurs right
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
mcp5x_dma_setup_intr(nv_ctl_t *nvc, nv_port_t *nvp)
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

	slot = nv_get32(nvc->nvc_bar_hdl[5], nvc->nvc_mcp5x_ncq);

	slot = (slot >> tag_shift[port]) & MCP_SATA_AE_NCQ_DMA_SETUP_TAG_MASK;

	NVLOG(NVDBG_INTR, nvc, nvp, "mcp5x_dma_setup_intr slot %d"
	    " nvp_slot_sactive %X", slot, nvp->nvp_sactive_cache);

	/*
	 * halt the DMA engine.  This step is necessary according to
	 * the mcp5x spec, probably since there may have been a "first" packet
	 * that already programmed the DMA engine, but may not turn out to
	 * be the first one processed.
	 */
	bmicx = nv_get8(bmhdl, nvp->nvp_bmicx);

	if (bmicx & BMICX_SSBM) {
		NVLOG(NVDBG_INTR, nvc, nvp, "BM was already enabled for "
		    "another packet.  Cancelling and reprogramming", NULL);
		nv_put8(bmhdl, nvp->nvp_bmicx,  bmicx & ~BMICX_SSBM);
	}
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
mcp5x_packet_complete_intr(nv_ctl_t *nvc, nv_port_t *nvp)
{
	uint8_t status, bmstatus;
	ddi_acc_handle_t bmhdl = nvp->nvp_bm_hdl;
	int sactive;
	int active_pkt_bit = 0, active_pkt = 0, ncq_command = B_FALSE;
	sata_pkt_t *spkt;
	nv_slot_t *nv_slotp;

	mutex_enter(&nvp->nvp_mutex);

	bmstatus = nv_get8(bmhdl, nvp->nvp_bmisx);

	if (!(bmstatus & (BMISX_IDEINTS | BMISX_IDERR))) {
		DTRACE_PROBE1(bmstatus_h, int, bmstatus);
		NVLOG(NVDBG_INTR, nvc, nvp, "BMISX_IDEINTS not set %x",
		    bmstatus);
		mutex_exit(&nvp->nvp_mutex);

		return (NV_FAILURE);
	}

	/*
	 * Commands may have been processed by abort or timeout before
	 * interrupt processing acquired the mutex. So we may be processing
	 * an interrupt for packets that were already removed.
	 * For functioning NCQ processing all slots may be checked, but
	 * with NCQ disabled (current code), relying on *_run flags is OK.
	 */
	if (nvp->nvp_non_ncq_run) {
		/*
		 * If the just completed item is a non-ncq command, the busy
		 * bit should not be set
		 */
		status = nv_get8(nvp->nvp_ctl_hdl, nvp->nvp_altstatus);
		if (status & SATA_STATUS_BSY) {
			nv_cmn_err(CE_WARN, nvc, nvp,
			    "unexpected SATA_STATUS_BSY set");
			DTRACE_PROBE(unexpected_status_bsy_p);
			mutex_exit(&nvp->nvp_mutex);
			/*
			 * calling function will clear interrupt.  then
			 * the real interrupt will either arrive or the
			 * packet timeout handling will take over and
			 * reset.
			 */
			return (NV_FAILURE);
		}
		ASSERT(nvp->nvp_ncq_run == 0);
	} else {
		ASSERT(nvp->nvp_non_ncq_run == 0);
		/*
		 * Pre-NCQ code!
		 * Nothing to do. The packet for the command that just
		 * completed is already gone. Just clear the interrupt.
		 */
		(void) nv_bm_status_clear(nvp);
		(void) nv_get8(nvp->nvp_cmd_hdl, nvp->nvp_status);
		mutex_exit(&nvp->nvp_mutex);
		return (NV_SUCCESS);

		/*
		 * NCQ check for BSY here and wait if still bsy before
		 * continuing. Rather than wait for it to be cleared
		 * when starting a packet and wasting CPU time, the starting
		 * thread can exit immediate, but might have to spin here
		 * for a bit possibly.  Needs more work and experimentation.
		 *
		 */
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

	if (nv_slotp->nvslot_flags == NVSLOT_COMPLETE) {

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
			cv_signal(&nvp->nvp_sync_cv);
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

	NVLOG(NVDBG_ENTRY, nvp->nvp_ctlp, nvp, "nv_start_async: entry", NULL);

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

		NVLOG(NVDBG_ENTRY, nvp->nvp_ctlp, nvp,
		    "nv_process_queue: nvp_queue_depth set to %d",
		    nvp->nvp_queue_depth);
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

	NVLOG(NVDBG_INIT, nvc, NULL, "nv_add_legacy_intrs", NULL);

	/*
	 * get number of interrupts
	 */
	rc = ddi_intr_get_nintrs(devinfo, DDI_INTR_TYPE_FIXED, &count);
	if ((rc != DDI_SUCCESS) || (count == 0)) {
		NVLOG(NVDBG_INIT, nvc, NULL,
		    "ddi_intr_get_nintrs() failed, "
		    "rc %d count %d", rc, count);

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

	NVLOG(NVDBG_INIT, nvc, NULL, "nv_add_msi_intrs", NULL);

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
		NVLOG(NVDBG_INIT, nvc, NULL,
		    "Requested: %d, Received: %d", count, actual);
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

	NVLOG(NVDBG_INIT, nvc, NULL, "nv_rem_intrs", NULL);

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
nv_vcmn_err(int ce, nv_ctl_t *nvc, nv_port_t *nvp, const char *fmt, va_list ap,
    boolean_t log_to_sata_ring)
{
	char port[NV_STR_LEN];
	char inst[NV_STR_LEN];
	dev_info_t *dip;

	if (nvc) {
		(void) snprintf(inst, NV_STR_LEN, "inst%d ",
		    ddi_get_instance(nvc->nvc_dip));
		dip = nvc->nvc_dip;
	} else {
		inst[0] = '\0';
	}

	if (nvp) {
		(void) snprintf(port, NV_STR_LEN, "port%d",
		    nvp->nvp_port_num);
		dip = nvp->nvp_ctlp->nvc_dip;
	} else {
		port[0] = '\0';
	}

	mutex_enter(&nv_log_mutex);

	(void) sprintf(nv_log_buf, "%s%s%s", inst, port,
	    (inst[0]|port[0] ? ": " :""));

	(void) vsnprintf(&nv_log_buf[strlen(nv_log_buf)],
	    NV_LOGBUF_LEN - strlen(nv_log_buf), fmt, ap);

	/*
	 * Log to console or log to file, depending on
	 * nv_log_to_console setting.
	 */
	if (nv_log_to_console) {
		if (nv_prom_print) {
			prom_printf("%s\n", nv_log_buf);
		} else {
			cmn_err(ce, "%s\n", nv_log_buf);
		}
	} else {
		cmn_err(ce, "!%s", nv_log_buf);
	}

	if (log_to_sata_ring == B_TRUE) {
		(void) sprintf(nv_log_buf, "%s%s", port, (port[0] ? ": " :""));

		(void) vsnprintf(&nv_log_buf[strlen(nv_log_buf)],
		    NV_LOGBUF_LEN - strlen(nv_log_buf), fmt, ap);

		sata_trace_debug(dip, nv_log_buf);
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
	nv_vcmn_err(ce, nvc, nvp, fmt, ap, B_TRUE);
	va_end(ap);
}


static void
nv_log(nv_ctl_t *nvc, nv_port_t *nvp, const char *fmt, ...)
{
	va_list ap;

	if (nv_log_to_cmn_err == B_TRUE) {
		va_start(ap, fmt);
		nv_vcmn_err(CE_CONT, nvc, nvp, fmt, ap, B_FALSE);
		va_end(ap);

	}

	va_start(ap, fmt);

	if (nvp == NULL && nvc == NULL) {
		sata_vtrace_debug(NULL, fmt, ap);
		va_end(ap);

		return;
	}

	if (nvp == NULL && nvc != NULL) {
		sata_vtrace_debug(nvc->nvc_dip, fmt, ap);
		va_end(ap);

		return;
	}

	/*
	 * nvp is not NULL, but nvc might be.  Reference nvp for both
	 * port and dip, to get the port number prefixed on the
	 * message.
	 */
	mutex_enter(&nv_log_mutex);

	(void) snprintf(nv_log_buf, NV_LOGBUF_LEN, "port%d: %s",
	    nvp->nvp_port_num, fmt);

	sata_vtrace_debug(nvp->nvp_ctlp->nvc_dip, nv_log_buf, ap);

	mutex_exit(&nv_log_mutex);

	va_end(ap);
}


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
		NVLOG(NVDBG_DELIVER, nvp->nvp_ctlp, nvp, "ATA_ADDR_LBA mode",
		    NULL);

		nv_put8(cmdhdl, nvp->nvp_count, satacmd->satacmd_sec_count_lsb);
		nv_put8(cmdhdl, nvp->nvp_hcyl, satacmd->satacmd_lba_high_lsb);
		nv_put8(cmdhdl, nvp->nvp_lcyl, satacmd->satacmd_lba_mid_lsb);
		nv_put8(cmdhdl, nvp->nvp_sect, satacmd->satacmd_lba_low_lsb);
		nv_put8(cmdhdl, nvp->nvp_feature,
		    satacmd->satacmd_features_reg);


		break;

	case ATA_ADDR_LBA28:
		NVLOG(NVDBG_DELIVER, nvp->nvp_ctlp, nvp,
		    "ATA_ADDR_LBA28 mode", NULL);
		/*
		 * NCQ only uses 48-bit addressing
		 */
		ASSERT(ncq != B_TRUE);

		nv_put8(cmdhdl, nvp->nvp_count, satacmd->satacmd_sec_count_lsb);
		nv_put8(cmdhdl, nvp->nvp_hcyl, satacmd->satacmd_lba_high_lsb);
		nv_put8(cmdhdl, nvp->nvp_lcyl, satacmd->satacmd_lba_mid_lsb);
		nv_put8(cmdhdl, nvp->nvp_sect, satacmd->satacmd_lba_low_lsb);
		nv_put8(cmdhdl, nvp->nvp_feature,
		    satacmd->satacmd_features_reg);

		break;

	case ATA_ADDR_LBA48:
		NVLOG(NVDBG_DELIVER, nvp->nvp_ctlp, nvp,
		    "ATA_ADDR_LBA48 mode", NULL);

		/*
		 * for NCQ, tag goes into count register and real sector count
		 * into features register.  The sata module does the translation
		 * in the satacmd.
		 */
		if (ncq == B_TRUE) {
			nv_put8(cmdhdl, nvp->nvp_count, slot << 3);
		} else {
			nv_put8(cmdhdl, nvp->nvp_count,
			    satacmd->satacmd_sec_count_msb);
			nv_put8(cmdhdl, nvp->nvp_count,
			    satacmd->satacmd_sec_count_lsb);
		}

		nv_put8(cmdhdl, nvp->nvp_feature,
		    satacmd->satacmd_features_reg_ext);
		nv_put8(cmdhdl, nvp->nvp_feature,
		    satacmd->satacmd_features_reg);

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


static int
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

	NVLOG(NVDBG_DELIVER, nvp->nvp_ctlp, nvp,
	    "nv_start_dma_engine entered", NULL);

#if NOT_USED
	/*
	 * NOT NEEDED. Left here of historical reason.
	 * Reset the controller's interrupt and error status bits.
	 */
	(void) nv_bm_status_clear(nvp);
#endif
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

		nv_put32(sghdl, dstp++, srcp->dmac_address);

		/* Set the number of bytes to transfer, 0 implies 64KB */
		size = srcp->dmac_size;
		if (size == 0x10000)
			size = 0;

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
		NVLOG(NVDBG_DELIVER, nvp->nvp_ctlp, nvp,
		    "NOT NCQ so starting DMA NOW non_ncq_commands=%d"
		    " cmd = %X", non_ncq_commands++, cmd);
		nv_start_dma_engine(nvp, slot);
	} else {
		NVLOG(NVDBG_DELIVER, nvp->nvp_ctlp, nvp, "NCQ, so program "
		    "DMA later ncq_commands=%d cmd = %X", ncq_commands++, cmd);
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
	nv_reset(nvp, "pio_out");

	return (SATA_TRAN_PORT_ERROR);
}


/*
 * start a ATAPI Packet command (PIO data in or out)
 */
static int
nv_start_pkt_pio(nv_port_t *nvp, int slot)
{
	nv_slot_t *nv_slotp = &(nvp->nvp_slot[slot]);
	sata_pkt_t *spkt = nv_slotp->nvslot_spkt;
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
	sata_cmd_t *satacmd = &spkt->satapkt_cmd;

	NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
	    "nv_start_pkt_pio: start", NULL);

	/*
	 * Write the PACKET command to the command register.  Normally
	 * this would be done through nv_program_taskfile_regs().  It
	 * is done here because some values need to be overridden.
	 */

	/* select the drive */
	nv_put8(cmdhdl, nvp->nvp_drvhd, satacmd->satacmd_device_reg);

	/* make certain the drive selected */
	if (nv_wait(nvp, SATA_STATUS_DRDY, SATA_STATUS_BSY,
	    NV_SEC2USEC(5), 0) == B_FALSE) {
		NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
		    "nv_start_pkt_pio: drive select failed", NULL);
		return (SATA_TRAN_PORT_ERROR);
	}

	/*
	 * The command is always sent via PIO, despite whatever the SATA
	 * common module sets in the command.  Overwrite the DMA bit to do this.
	 * Also, overwrite the overlay bit to be safe (it shouldn't be set).
	 */
	nv_put8(cmdhdl, nvp->nvp_feature, 0);	/* deassert DMA and OVL */

	/* set appropriately by the sata common module */
	nv_put8(cmdhdl, nvp->nvp_hcyl, satacmd->satacmd_lba_high_lsb);
	nv_put8(cmdhdl, nvp->nvp_lcyl, satacmd->satacmd_lba_mid_lsb);
	nv_put8(cmdhdl, nvp->nvp_sect, satacmd->satacmd_lba_low_lsb);
	nv_put8(cmdhdl, nvp->nvp_count, satacmd->satacmd_sec_count_lsb);

	/* initiate the command by writing the command register last */
	nv_put8(cmdhdl, nvp->nvp_cmd, spkt->satapkt_cmd.satacmd_cmd_reg);

	/* Give the host controller time to do its thing */
	NV_DELAY_NSEC(400);

	/*
	 * Wait for the device to indicate that it is ready for the command
	 * ATAPI protocol state - HP0: Check_Status_A
	 */

	if (nv_wait3(nvp, SATA_STATUS_DRQ, SATA_STATUS_BSY, /* okay */
	    SATA_STATUS_ERR, SATA_STATUS_BSY, /* cmd failed */
	    SATA_STATUS_DF, SATA_STATUS_BSY, /* drive failed */
	    4000000, 0) == B_FALSE) {
		/*
		 * Either an error or device fault occurred or the wait
		 * timed out.  According to the ATAPI protocol, command
		 * completion is also possible.  Other implementations of
		 * this protocol don't handle this last case, so neither
		 * does this code.
		 */

		if (nv_get8(cmdhdl, nvp->nvp_status) &
		    (SATA_STATUS_ERR | SATA_STATUS_DF)) {
			spkt->satapkt_reason = SATA_PKT_DEV_ERROR;

			NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
			    "nv_start_pkt_pio: device error (HP0)", NULL);
		} else {
			spkt->satapkt_reason = SATA_PKT_TIMEOUT;

			NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
			    "nv_start_pkt_pio: timeout (HP0)", NULL);
		}

		nv_copy_registers(nvp, &spkt->satapkt_device, spkt);
		nv_complete_io(nvp, spkt, 0);
		nv_reset(nvp, "start_pkt_pio");

		return (SATA_TRAN_PORT_ERROR);
	}

	/*
	 * Put the ATAPI command in the data register
	 * ATAPI protocol state - HP1: Send_Packet
	 */

	ddi_rep_put16(cmdhdl, (ushort_t *)spkt->satapkt_cmd.satacmd_acdb,
	    (ushort_t *)nvp->nvp_data,
	    (spkt->satapkt_cmd.satacmd_acdb_len >> 1), DDI_DEV_NO_AUTOINCR);

	/*
	 * See you in nv_intr_pkt_pio.
	 * ATAPI protocol state - HP3: INTRQ_wait
	 */

	NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
	    "nv_start_pkt_pio: exiting into HP3", NULL);

	return (SATA_TRAN_ACCEPTED);
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

	NVLOG(NVDBG_INTR, nvp->nvp_ctlp, nvp, "nv_intr_nodata entered", NULL);

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
		nv_reset(nvp, "intr_pio_in");

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
 * ATAPI PACKET command, PIO in/out interrupt
 *
 * Under normal circumstances, one of four different interrupt scenarios
 * will result in this function being called:
 *
 * 1. Packet command data transfer
 * 2. Packet command completion
 * 3. Request sense data transfer
 * 4. Request sense command completion
 */
static void
nv_intr_pkt_pio(nv_port_t *nvp, nv_slot_t *nv_slotp)
{
	uchar_t	status;
	sata_pkt_t *spkt = nv_slotp->nvslot_spkt;
	sata_cmd_t *sata_cmdp = &spkt->satapkt_cmd;
	int direction = sata_cmdp->satacmd_flags.sata_data_direction;
	ddi_acc_handle_t ctlhdl = nvp->nvp_ctl_hdl;
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
	uint16_t ctlr_count;
	int count;

	/* ATAPI protocol state - HP2: Check_Status_B */

	status = nv_get8(cmdhdl, nvp->nvp_status);
	NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
	    "nv_intr_pkt_pio: status 0x%x", status);

	if (status & SATA_STATUS_BSY) {
		if ((nv_slotp->nvslot_flags & NVSLOT_RQSENSE) != 0) {
			nv_slotp->nvslot_flags = NVSLOT_COMPLETE;
			spkt->satapkt_reason = SATA_PKT_DEV_ERROR;
		} else {
			nv_slotp->nvslot_flags = NVSLOT_COMPLETE;
			spkt->satapkt_reason = SATA_PKT_TIMEOUT;
			nv_reset(nvp, "intr_pkt_pio");
		}

		NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
		    "nv_intr_pkt_pio: busy - status 0x%x", status);

		return;
	}

	if ((status & SATA_STATUS_DF) != 0) {
		/*
		 * On device fault, just clean up and bail.  Request sense
		 * will just default to its NO SENSE initialized value.
		 */

		if ((nv_slotp->nvslot_flags & NVSLOT_RQSENSE) == 0) {
			nv_copy_registers(nvp, &spkt->satapkt_device, spkt);
		}

		nv_slotp->nvslot_flags = NVSLOT_COMPLETE;
		spkt->satapkt_reason = SATA_PKT_DEV_ERROR;

		sata_cmdp->satacmd_status_reg = nv_get8(ctlhdl,
		    nvp->nvp_altstatus);
		sata_cmdp->satacmd_error_reg = nv_get8(cmdhdl,
		    nvp->nvp_error);

		NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
		    "nv_intr_pkt_pio: device fault", NULL);

		return;
	}

	if ((status & SATA_STATUS_ERR) != 0) {
		/*
		 * On command error, figure out whether we are processing a
		 * request sense.  If so, clean up and bail.  Otherwise,
		 * do a REQUEST SENSE.
		 */

		if ((nv_slotp->nvslot_flags & NVSLOT_RQSENSE) == 0) {
			nv_slotp->nvslot_flags |= NVSLOT_RQSENSE;
			if (nv_start_rqsense_pio(nvp, nv_slotp) ==
			    NV_FAILURE) {
				nv_copy_registers(nvp, &spkt->satapkt_device,
				    spkt);
				nv_slotp->nvslot_flags = NVSLOT_COMPLETE;
				spkt->satapkt_reason = SATA_PKT_DEV_ERROR;
			}

			sata_cmdp->satacmd_status_reg = nv_get8(ctlhdl,
			    nvp->nvp_altstatus);
			sata_cmdp->satacmd_error_reg = nv_get8(cmdhdl,
			    nvp->nvp_error);
		} else {
			nv_slotp->nvslot_flags = NVSLOT_COMPLETE;
			spkt->satapkt_reason = SATA_PKT_DEV_ERROR;

			nv_copy_registers(nvp, &spkt->satapkt_device, spkt);
		}

		NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
		    "nv_intr_pkt_pio: error (status 0x%x)", status);

		return;
	}

	if ((nv_slotp->nvslot_flags & NVSLOT_RQSENSE) != 0) {
		/*
		 * REQUEST SENSE command processing
		 */

		if ((status & (SATA_STATUS_DRQ)) != 0) {
			/* ATAPI state - HP4: Transfer_Data */

			/* read the byte count from the controller */
			ctlr_count =
			    (uint16_t)nv_get8(cmdhdl, nvp->nvp_hcyl) << 8;
			ctlr_count |= nv_get8(cmdhdl, nvp->nvp_lcyl);

			NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
			    "nv_intr_pkt_pio: ctlr byte count - %d",
			    ctlr_count);

			if (ctlr_count == 0) {
				/* no data to transfer - some devices do this */

				spkt->satapkt_reason = SATA_PKT_DEV_ERROR;
				nv_slotp->nvslot_flags = NVSLOT_COMPLETE;

				NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
				    "nv_intr_pkt_pio: done (no data)", NULL);

				return;
			}

			count = min(ctlr_count, SATA_ATAPI_RQSENSE_LEN);

			/* transfer the data */
			ddi_rep_get16(cmdhdl,
			    (ushort_t *)nv_slotp->nvslot_rqsense_buff,
			    (ushort_t *)nvp->nvp_data, (count >> 1),
			    DDI_DEV_NO_AUTOINCR);

			/* consume residual bytes */
			ctlr_count -= count;

			if (ctlr_count > 0) {
				for (; ctlr_count > 0; ctlr_count -= 2)
					(void) ddi_get16(cmdhdl,
					    (ushort_t *)nvp->nvp_data);
			}

			NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
			    "nv_intr_pkt_pio: transition to HP2", NULL);
		} else {
			/* still in ATAPI state - HP2 */

			/*
			 * In order to avoid clobbering the rqsense data
			 * set by the SATA common module, the sense data read
			 * from the device is put in a separate buffer and
			 * copied into the packet after the request sense
			 * command successfully completes.
			 */
			bcopy(nv_slotp->nvslot_rqsense_buff,
			    spkt->satapkt_cmd.satacmd_rqsense,
			    SATA_ATAPI_RQSENSE_LEN);

			nv_slotp->nvslot_flags = NVSLOT_COMPLETE;
			spkt->satapkt_reason = SATA_PKT_DEV_ERROR;

			NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
			    "nv_intr_pkt_pio: request sense done", NULL);
		}

		return;
	}

	/*
	 * Normal command processing
	 */

	if ((status & (SATA_STATUS_DRQ)) != 0) {
		/* ATAPI protocol state - HP4: Transfer_Data */

		/* read the byte count from the controller */
		ctlr_count = (uint16_t)nv_get8(cmdhdl, nvp->nvp_hcyl) << 8;
		ctlr_count |= nv_get8(cmdhdl, nvp->nvp_lcyl);

		if (ctlr_count == 0) {
			/* no data to transfer - some devices do this */

			spkt->satapkt_reason = SATA_PKT_COMPLETED;
			nv_slotp->nvslot_flags = NVSLOT_COMPLETE;

			NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
			    "nv_intr_pkt_pio: done (no data)", NULL);

			return;
		}

		count = min(ctlr_count, nv_slotp->nvslot_byte_count);

		NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
		    "nv_intr_pkt_pio: drive_bytes 0x%x", ctlr_count);

		NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
		    "nv_intr_pkt_pio: byte_count 0x%x",
		    nv_slotp->nvslot_byte_count);

		/* transfer the data */

		if (direction == SATA_DIR_READ) {
			ddi_rep_get16(cmdhdl,
			    (ushort_t *)nv_slotp->nvslot_v_addr,
			    (ushort_t *)nvp->nvp_data, (count >> 1),
			    DDI_DEV_NO_AUTOINCR);

			ctlr_count -= count;

			if (ctlr_count > 0) {
				/* consume remaining bytes */

				for (; ctlr_count > 0;
				    ctlr_count -= 2)
					(void) ddi_get16(cmdhdl,
					    (ushort_t *)nvp->nvp_data);

				NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
				    "nv_intr_pkt_pio: bytes remained", NULL);
			}
		} else {
			ddi_rep_put16(cmdhdl,
			    (ushort_t *)nv_slotp->nvslot_v_addr,
			    (ushort_t *)nvp->nvp_data, (count >> 1),
			    DDI_DEV_NO_AUTOINCR);
		}

		nv_slotp->nvslot_v_addr += count;
		nv_slotp->nvslot_byte_count -= count;

		NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
		    "nv_intr_pkt_pio: transition to HP2", NULL);
	} else {
		/* still in ATAPI state - HP2 */

		spkt->satapkt_reason = SATA_PKT_COMPLETED;
		nv_slotp->nvslot_flags = NVSLOT_COMPLETE;

		NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
		    "nv_intr_pkt_pio: done", NULL);
	}
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
		spkt->satapkt_reason = SATA_PKT_PORT_ERROR;
		sata_cmdp->satacmd_status_reg = nv_get8(ctlhdl,
		    nvp->nvp_altstatus);
		sata_cmdp->satacmd_error_reg = nv_get8(cmdhdl, nvp->nvp_error);
		nv_reset(nvp, "intr_dma");

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
 * nv_port_state_change() reports the state of the port to the
 * sata module by calling sata_hba_event_notify().  This
 * function is called any time the state of the port is changed
 */
static void
nv_port_state_change(nv_port_t *nvp, int event, uint8_t addr_type, int state)
{
	sata_device_t sd;

	NVLOG(NVDBG_EVENT, nvp->nvp_ctlp, nvp,
	    "nv_port_state_change: event 0x%x type 0x%x state 0x%x "
	    "lbolt %ld (ticks)", event, addr_type, state, ddi_get_lbolt());

	if (ddi_in_panic() != 0) {

		return;
	}

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
 * Monitor reset progress and signature gathering.
 */
static clock_t
nv_monitor_reset(nv_port_t *nvp)
{
	ddi_acc_handle_t bar5_hdl = nvp->nvp_ctlp->nvc_bar_hdl[5];
	uint32_t sstatus;

	ASSERT(MUTEX_HELD(&nvp->nvp_mutex));

	sstatus = nv_get32(bar5_hdl, nvp->nvp_sstatus);

	/*
	 * Check the link status. The link needs to be active before
	 * checking the link's status.
	 */
	if ((SSTATUS_GET_IPM(sstatus) != SSTATUS_IPM_ACTIVE) ||
	    (SSTATUS_GET_DET(sstatus) != SSTATUS_DET_DEVPRE_PHYCOM)) {
		/*
		 * Either link is not active or there is no device
		 * If the link remains down for more than NV_LINK_EVENT_DOWN
		 * (milliseconds), abort signature acquisition and complete
		 * reset processing.  The link will go down when COMRESET is
		 * sent by nv_reset().
		 */

		if (TICK_TO_MSEC(ddi_get_lbolt() - nvp->nvp_reset_time) >=
		    NV_LINK_EVENT_DOWN) {

			nv_cmn_err(CE_NOTE, nvp->nvp_ctlp, nvp,
			    "nv_monitor_reset: no link - ending signature "
			    "acquisition; time after reset %ldms",
			    TICK_TO_MSEC(ddi_get_lbolt() -
			    nvp->nvp_reset_time));

			DTRACE_PROBE(no_link_reset_giving_up_f);

			/*
			 * If the drive was previously present and configured
			 * and then subsequently removed, then send a removal
			 * event to sata common module.
			 */
			if (nvp->nvp_type != SATA_DTYPE_NONE) {
				nv_port_state_change(nvp,
				    SATA_EVNT_DEVICE_DETACHED,
				    SATA_ADDR_CPORT, 0);
			}

			nvp->nvp_type = SATA_DTYPE_NONE;
			nvp->nvp_signature = NV_NO_SIG;
			nvp->nvp_state &= ~(NV_DEACTIVATED);

#ifdef SGPIO_SUPPORT
			nv_sgp_drive_disconnect(nvp->nvp_ctlp,
			    SGP_CTLR_PORT_TO_DRV(
			    nvp->nvp_ctlp->nvc_ctlr_num,
			    nvp->nvp_port_num));
#endif

			cv_signal(&nvp->nvp_reset_cv);

			return (0);
		}

		DTRACE_PROBE(link_lost_reset_keep_trying_p);

		return (nvp->nvp_wait_sig);
	}

	NVLOG(NVDBG_RESET, nvp->nvp_ctlp, nvp,
	    "nv_monitor_reset: link up.  time since reset %ldms",
	    TICK_TO_MSEC(ddi_get_lbolt() - nvp->nvp_reset_time));

	nv_read_signature(nvp);


	if (nvp->nvp_signature != NV_NO_SIG) {
		/*
		 * signature has been acquired, send the appropriate
		 * event to the sata common module.
		 */
		if (nvp->nvp_state & (NV_ATTACH|NV_HOTPLUG)) {
			char *source;

			if (nvp->nvp_state & NV_HOTPLUG) {

				source = "hotplugged";
				nv_port_state_change(nvp,
				    SATA_EVNT_DEVICE_ATTACHED,
				    SATA_ADDR_CPORT, SATA_DSTATE_PWR_ACTIVE);
				DTRACE_PROBE1(got_sig_for_hotplugged_device_h,
				    int, nvp->nvp_state);

			} else {
				source = "activated or attached";
				DTRACE_PROBE1(got_sig_for_existing_device_h,
				    int, nvp->nvp_state);
			}

			NVLOG(NVDBG_RESET, nvp->nvp_ctlp, nvp,
			    "signature acquired for %s device. sig:"
			    " 0x%x state: 0x%x nvp_type: 0x%x", source,
			    nvp->nvp_signature, nvp->nvp_state, nvp->nvp_type);


			nvp->nvp_state &= ~(NV_RESET|NV_ATTACH|NV_HOTPLUG);

#ifdef SGPIO_SUPPORT
			if (nvp->nvp_type == SATA_DTYPE_ATADISK) {
				nv_sgp_drive_connect(nvp->nvp_ctlp,
				    SGP_CTLR_PORT_TO_DRV(
				    nvp->nvp_ctlp->nvc_ctlr_num,
				    nvp->nvp_port_num));
			} else {
				nv_sgp_drive_disconnect(nvp->nvp_ctlp,
				    SGP_CTLR_PORT_TO_DRV(
				    nvp->nvp_ctlp->nvc_ctlr_num,
				    nvp->nvp_port_num));
			}
#endif

			cv_signal(&nvp->nvp_reset_cv);

			return (0);
		}

		/*
		 * Since this was not an attach, it was a reset of an
		 * existing device
		 */
		nvp->nvp_state &= ~NV_RESET;
		nvp->nvp_state |= NV_RESTORE;



		DTRACE_PROBE(got_signature_reset_complete_p);
		DTRACE_PROBE1(nvp_signature_h, int, nvp->nvp_signature);
		DTRACE_PROBE1(nvp_state_h, int, nvp->nvp_state);

		NVLOG(NVDBG_RESET, nvp->nvp_ctlp, nvp,
		    "signature acquired reset complete. sig: 0x%x"
		    " state: 0x%x", nvp->nvp_signature, nvp->nvp_state);

		/*
		 * interrupts may have been disabled so just make sure
		 * they are cleared and re-enabled.
		 */

		(*(nvp->nvp_ctlp->nvc_set_intr))(nvp,
		    NV_INTR_CLEAR_ALL|NV_INTR_ENABLE);

		nv_port_state_change(nvp, SATA_EVNT_DEVICE_RESET,
		    SATA_ADDR_DCPORT,
		    SATA_DSTATE_RESET | SATA_DSTATE_PWR_ACTIVE);

		return (0);
	}


	if (TICK_TO_MSEC(ddi_get_lbolt() - nvp->nvp_reset_time) >
	    NV_RETRY_RESET_SIG) {


		if (nvp->nvp_reset_retry_count >= NV_MAX_RESET_RETRY) {

			nvp->nvp_state |= NV_FAILED;
			nvp->nvp_state &= ~(NV_RESET|NV_ATTACH|NV_HOTPLUG);

			DTRACE_PROBE(reset_exceeded_waiting_for_sig_p);
			DTRACE_PROBE(reset_exceeded_waiting_for_sig_f);
			DTRACE_PROBE1(nvp_state_h, int, nvp->nvp_state);
			NVLOG(NVDBG_RESET, nvp->nvp_ctlp, nvp,
			    "reset time exceeded waiting for sig nvp_state %x",
			    nvp->nvp_state);

			nv_port_state_change(nvp, SATA_EVNT_PORT_FAILED,
			    SATA_ADDR_CPORT, 0);

			cv_signal(&nvp->nvp_reset_cv);

			return (0);
		}

		nv_reset(nvp, "retry");

		return (nvp->nvp_wait_sig);
	}

	/*
	 * signature not received, keep trying
	 */
	DTRACE_PROBE(no_sig_keep_waiting_p);

	/*
	 * double the wait time for sig since the last try but cap it off at
	 * 1 second.
	 */
	nvp->nvp_wait_sig = nvp->nvp_wait_sig * 2;

	return (nvp->nvp_wait_sig > NV_ONE_SEC ? NV_ONE_SEC :
	    nvp->nvp_wait_sig);
}


/*
 * timeout processing:
 *
 * Check if any packets have crossed a timeout threshold.  If so,
 * abort the packet.  This function is not NCQ-aware.
 *
 * If reset is in progress, call reset monitoring function.
 *
 * Timeout frequency may be lower for checking packet timeout
 * and higher for reset monitoring.
 *
 */
static void
nv_timeout(void *arg)
{
	nv_port_t *nvp = arg;
	nv_slot_t *nv_slotp;
	clock_t next_timeout_us = NV_ONE_SEC;
	uint16_t int_status;
	uint8_t status, bmstatus;
	static int intr_warn_once = 0;
	uint32_t serror;


	ASSERT(nvp != NULL);

	mutex_enter(&nvp->nvp_mutex);
	nvp->nvp_timeout_id = 0;

	if (nvp->nvp_state & (NV_DEACTIVATED|NV_FAILED)) {
		next_timeout_us = 0;

		goto finished;
	}

	if (nvp->nvp_state & NV_RESET) {
		next_timeout_us = nv_monitor_reset(nvp);

		goto finished;
	}

	if (nvp->nvp_state & NV_LINK_EVENT) {
		boolean_t device_present = B_FALSE;
		uint32_t sstatus;
		ddi_acc_handle_t bar5_hdl = nvp->nvp_ctlp->nvc_bar_hdl[5];

		if (TICK_TO_USEC(ddi_get_lbolt() -
		    nvp->nvp_link_event_time) < NV_LINK_EVENT_SETTLE) {

			next_timeout_us = 10 * NV_ONE_MSEC;

			DTRACE_PROBE(link_event_set_no_timeout_keep_waiting_p);

			goto finished;
		}

		DTRACE_PROBE(link_event_settled_now_process_p);

		nvp->nvp_state &= ~NV_LINK_EVENT;

		/*
		 * ck804 routinely reports the wrong hotplug/unplug event,
		 * and it's been seen on mcp55 when there are signal integrity
		 * issues.  Therefore need to infer the event from the
		 * current link status.
		 */

		sstatus = nv_get32(bar5_hdl, nvp->nvp_sstatus);

		if ((SSTATUS_GET_IPM(sstatus) == SSTATUS_IPM_ACTIVE) &&
		    (SSTATUS_GET_DET(sstatus) ==
		    SSTATUS_DET_DEVPRE_PHYCOM)) {
			device_present = B_TRUE;
		}

		if ((nvp->nvp_signature != NV_NO_SIG) &&
		    (device_present == B_FALSE)) {

			NVLOG(NVDBG_HOT, nvp->nvp_ctlp, nvp,
			    "nv_timeout: device detached", NULL);

			DTRACE_PROBE(device_detached_p);

			(void) nv_abort_active(nvp, NULL, SATA_PKT_PORT_ERROR,
			    B_FALSE);

			nv_port_state_change(nvp, SATA_EVNT_DEVICE_DETACHED,
			    SATA_ADDR_CPORT, 0);

			nvp->nvp_signature = NV_NO_SIG;
			nvp->nvp_rem_time = ddi_get_lbolt();
			nvp->nvp_type = SATA_DTYPE_NONE;
			next_timeout_us = 0;

#ifdef SGPIO_SUPPORT
			nv_sgp_drive_disconnect(nvp->nvp_ctlp,
			    SGP_CTLR_PORT_TO_DRV(nvp->nvp_ctlp->nvc_ctlr_num,
			    nvp->nvp_port_num));
#endif

			goto finished;
		}

		/*
		 * if the device was already present, and it's still present,
		 * then abort any outstanding command and issue a reset.
		 * This may result from transient link errors.
		 */

		if ((nvp->nvp_signature != NV_NO_SIG) &&
		    (device_present == B_TRUE)) {

			NVLOG(NVDBG_HOT, nvp->nvp_ctlp, nvp,
			    "nv_timeout: spurious link event", NULL);
			DTRACE_PROBE(spurious_link_event_p);

			(void) nv_abort_active(nvp, NULL, SATA_PKT_PORT_ERROR,
			    B_FALSE);

			nvp->nvp_signature = NV_NO_SIG;
			nvp->nvp_trans_link_time = ddi_get_lbolt();
			nvp->nvp_trans_link_count++;
			next_timeout_us = 0;

			nv_reset(nvp, "transient link event");

			goto finished;
		}


		/*
		 * a new device has been inserted
		 */
		if ((nvp->nvp_signature == NV_NO_SIG) &&
		    (device_present == B_TRUE)) {
			NVLOG(NVDBG_HOT, nvp->nvp_ctlp, nvp,
			    "nv_timeout: device attached", NULL);

			DTRACE_PROBE(device_attached_p);
			nvp->nvp_add_time = ddi_get_lbolt();
			next_timeout_us = 0;
			nvp->nvp_reset_count = 0;
			nvp->nvp_state = NV_HOTPLUG;
			nvp->nvp_type = SATA_DTYPE_UNKNOWN;
			nv_reset(nvp, "hotplug");

			goto finished;
		}

		/*
		 * no link, and no prior device.  Nothing to do, but
		 * log this.
		 */
		NVLOG(NVDBG_HOT, nvp->nvp_ctlp, nvp,
		    "nv_timeout: delayed hot processing no link no prior"
		    " device", NULL);
		DTRACE_PROBE(delayed_hotplug_no_link_no_prior_device_p);

		nvp->nvp_trans_link_time = ddi_get_lbolt();
		nvp->nvp_trans_link_count++;
		next_timeout_us = 0;

		goto finished;
	}

	/*
	 * Not yet NCQ-aware - there is only one command active.
	 */
	nv_slotp = &(nvp->nvp_slot[0]);

	/*
	 * perform timeout checking and processing only if there is an
	 * active packet on the port
	 */
	if (nv_slotp != NULL && nv_slotp->nvslot_spkt != NULL)  {
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
			next_timeout_us = 0;

			goto finished;
		}

		if (TICK_TO_SEC(ddi_get_lbolt() - nv_slotp->nvslot_stime) >
		    spkt->satapkt_time) {

			serror = nv_get32(nvp->nvp_ctlp->nvc_bar_hdl[5],
			    nvp->nvp_serror);
			status = nv_get8(nvp->nvp_ctl_hdl,
			    nvp->nvp_altstatus);
			bmstatus = nv_get8(nvp->nvp_bm_hdl,
			    nvp->nvp_bmisx);

			nv_cmn_err(CE_NOTE, nvp->nvp_ctlp, nvp,
			    "nv_timeout: aborting: "
			    "nvslot_stime: %ld max ticks till timeout: %ld "
			    "cur_time: %ld cmd = 0x%x lba = %d seq = %d",
			    nv_slotp->nvslot_stime,
			    drv_usectohz(MICROSEC *
			    spkt->satapkt_time), ddi_get_lbolt(),
			    cmd, lba, nvp->nvp_seq);

			NVLOG(NVDBG_TIMEOUT, nvp->nvp_ctlp, nvp,
			    "nv_timeout: altstatus = 0x%x  bmicx = 0x%x "
			    "serror = 0x%x previous_cmd = "
			    "0x%x", status, bmstatus, serror,
			    nvp->nvp_previous_cmd);


			DTRACE_PROBE1(nv_timeout_packet_p, int, nvp);

			if (nvp->nvp_mcp5x_int_status != NULL) {

				int_status = nv_get16(
				    nvp->nvp_ctlp->nvc_bar_hdl[5],
				    nvp->nvp_mcp5x_int_status);
				NVLOG(NVDBG_TIMEOUT, nvp->nvp_ctlp, nvp,
				    "int_status = 0x%x", int_status);

				if (int_status & MCP5X_INT_COMPLETE) {
					/*
					 * Completion interrupt was missed.
					 * Issue warning message once.
					 */
					if (!intr_warn_once) {

						nv_cmn_err(CE_WARN,
						    nvp->nvp_ctlp,
						    nvp,
						    "nv_sata: missing command "
						    "completion interrupt");
						intr_warn_once = 1;

					}

					NVLOG(NVDBG_TIMEOUT, nvp->nvp_ctlp,
					    nvp, "timeout detected with "
					    "interrupt ready - calling "
					    "int directly", NULL);

					mutex_exit(&nvp->nvp_mutex);
					(void) mcp5x_intr_port(nvp);
					mutex_enter(&nvp->nvp_mutex);

				} else {
					/*
					 * True timeout and not a missing
					 * interrupt.
					 */
					DTRACE_PROBE1(timeout_abort_active_p,
					    int *, nvp);
					(void) nv_abort_active(nvp, spkt,
					    SATA_PKT_TIMEOUT, B_TRUE);
				}
			} else {
				(void) nv_abort_active(nvp, spkt,
				    SATA_PKT_TIMEOUT, B_TRUE);
			}

		} else {
			NVLOG(NVDBG_VERBOSE, nvp->nvp_ctlp, nvp,
			    "nv_timeout:"
			    " still in use so restarting timeout",
			    NULL);

			next_timeout_us = NV_ONE_SEC;
		}
	} else {
		/*
		 * there was no active packet, so do not re-enable timeout
		 */
		next_timeout_us = 0;
		NVLOG(NVDBG_VERBOSE, nvp->nvp_ctlp, nvp,
		    "nv_timeout: no active packet so not re-arming "
		    "timeout", NULL);
	}

finished:

	nv_setup_timeout(nvp, next_timeout_us);

	mutex_exit(&nvp->nvp_mutex);
}


/*
 * enable or disable the 3 interrupt types the driver is
 * interested in: completion, add and remove.
 */
static void
ck804_set_intr(nv_port_t *nvp, int flag)
{
	nv_ctl_t *nvc = nvp->nvp_ctlp;
	ddi_acc_handle_t bar5_hdl = nvc->nvc_bar_hdl[5];
	uchar_t *bar5  = nvc->nvc_bar_addr[5];
	uint8_t intr_bits[] = { CK804_INT_PDEV_HOT|CK804_INT_PDEV_INT,
	    CK804_INT_SDEV_HOT|CK804_INT_SDEV_INT };
	uint8_t clear_all_bits[] = { CK804_INT_PDEV_ALL, CK804_INT_SDEV_ALL };
	uint8_t int_en, port = nvp->nvp_port_num, intr_status;

	if (flag & NV_INTR_DISABLE_NON_BLOCKING) {
		int_en = nv_get8(bar5_hdl,
		    (uint8_t *)(bar5 + CK804_SATA_INT_EN));
		int_en &= ~intr_bits[port];
		nv_put8(bar5_hdl, (uint8_t *)(bar5 + CK804_SATA_INT_EN),
		    int_en);
		return;
	}

	ASSERT(mutex_owned(&nvp->nvp_mutex));

	/*
	 * controller level lock also required since access to an 8-bit
	 * interrupt register is shared between both channels.
	 */
	mutex_enter(&nvc->nvc_mutex);

	if (flag & NV_INTR_CLEAR_ALL) {
		NVLOG(NVDBG_INTR, nvc, nvp,
		    "ck804_set_intr: NV_INTR_CLEAR_ALL", NULL);

		intr_status = nv_get8(nvc->nvc_bar_hdl[5],
		    (uint8_t *)(nvc->nvc_ck804_int_status));

		if (intr_status & clear_all_bits[port]) {

			nv_put8(nvc->nvc_bar_hdl[5],
			    (uint8_t *)(nvc->nvc_ck804_int_status),
			    clear_all_bits[port]);

			NVLOG(NVDBG_INTR, nvc, nvp,
			    "interrupt bits cleared %x",
			    intr_status & clear_all_bits[port]);
		}
	}

	if (flag & NV_INTR_DISABLE) {
		NVLOG(NVDBG_INTR, nvc, nvp,
		    "ck804_set_intr: NV_INTR_DISABLE", NULL);
		int_en = nv_get8(bar5_hdl,
		    (uint8_t *)(bar5 + CK804_SATA_INT_EN));
		int_en &= ~intr_bits[port];
		nv_put8(bar5_hdl, (uint8_t *)(bar5 + CK804_SATA_INT_EN),
		    int_en);
	}

	if (flag & NV_INTR_ENABLE) {
		NVLOG(NVDBG_INTR, nvc, nvp, "ck804_set_intr: NV_INTR_ENABLE",
		    NULL);
		int_en = nv_get8(bar5_hdl,
		    (uint8_t *)(bar5 + CK804_SATA_INT_EN));
		int_en |= intr_bits[port];
		nv_put8(bar5_hdl, (uint8_t *)(bar5 + CK804_SATA_INT_EN),
		    int_en);
	}

	mutex_exit(&nvc->nvc_mutex);
}


/*
 * enable or disable the 3 interrupts the driver is interested in:
 * completion interrupt, hot add, and hot remove interrupt.
 */
static void
mcp5x_set_intr(nv_port_t *nvp, int flag)
{
	nv_ctl_t *nvc = nvp->nvp_ctlp;
	ddi_acc_handle_t bar5_hdl = nvc->nvc_bar_hdl[5];
	uint16_t intr_bits =
	    MCP5X_INT_ADD|MCP5X_INT_REM|MCP5X_INT_COMPLETE;
	uint16_t int_en;

	if (flag & NV_INTR_DISABLE_NON_BLOCKING) {
		int_en = nv_get16(bar5_hdl, nvp->nvp_mcp5x_int_ctl);
		int_en &= ~intr_bits;
		nv_put16(bar5_hdl, nvp->nvp_mcp5x_int_ctl, int_en);
		return;
	}

	ASSERT(mutex_owned(&nvp->nvp_mutex));

	NVLOG(NVDBG_INTR, nvc, nvp, "mcp055_set_intr: enter flag: %d", flag);

	if (flag & NV_INTR_CLEAR_ALL) {
		NVLOG(NVDBG_INTR, nvc, nvp,
		    "mcp5x_set_intr: NV_INTR_CLEAR_ALL", NULL);
		nv_put16(bar5_hdl, nvp->nvp_mcp5x_int_status, MCP5X_INT_CLEAR);
	}

	if (flag & NV_INTR_ENABLE) {
		NVLOG(NVDBG_INTR, nvc, nvp, "mcp5x_set_intr: NV_INTR_ENABLE",
		    NULL);
		int_en = nv_get16(bar5_hdl, nvp->nvp_mcp5x_int_ctl);
		int_en |= intr_bits;
		nv_put16(bar5_hdl, nvp->nvp_mcp5x_int_ctl, int_en);
	}

	if (flag & NV_INTR_DISABLE) {
		NVLOG(NVDBG_INTR, nvc, nvp,
		    "mcp5x_set_intr: NV_INTR_DISABLE", NULL);
		int_en = nv_get16(bar5_hdl, nvp->nvp_mcp5x_int_ctl);
		int_en &= ~intr_bits;
		nv_put16(bar5_hdl, nvp->nvp_mcp5x_int_ctl, int_en);
	}
}


static void
nv_resume(nv_port_t *nvp)
{
	NVLOG(NVDBG_INIT, nvp->nvp_ctlp, nvp, "nv_resume()", NULL);

	mutex_enter(&nvp->nvp_mutex);

	if (nvp->nvp_state & NV_DEACTIVATED) {
		mutex_exit(&nvp->nvp_mutex);

		return;
	}

	/* Enable interrupt */
	(*(nvp->nvp_ctlp->nvc_set_intr))(nvp, NV_INTR_CLEAR_ALL|NV_INTR_ENABLE);

	/*
	 * Power may have been removed to the port and the
	 * drive, and/or a drive may have been added or removed.
	 * Force a reset which will cause a probe and re-establish
	 * any state needed on the drive.
	 */
	nv_reset(nvp, "resume");

	mutex_exit(&nvp->nvp_mutex);
}


static void
nv_suspend(nv_port_t *nvp)
{
	NVLOG(NVDBG_INIT, nvp->nvp_ctlp, nvp, "nv_suspend()", NULL);

	mutex_enter(&nvp->nvp_mutex);

#ifdef SGPIO_SUPPORT
	if (nvp->nvp_type == SATA_DTYPE_ATADISK) {
		nv_sgp_drive_disconnect(nvp->nvp_ctlp, SGP_CTLR_PORT_TO_DRV(
		    nvp->nvp_ctlp->nvc_ctlr_num, nvp->nvp_port_num));
	}
#endif

	if (nvp->nvp_state & NV_DEACTIVATED) {
		mutex_exit(&nvp->nvp_mutex);

		return;
	}

	/*
	 * Stop the timeout handler.
	 * (It will be restarted in nv_reset() during nv_resume().)
	 */
	if (nvp->nvp_timeout_id) {
		(void) untimeout(nvp->nvp_timeout_id);
		nvp->nvp_timeout_id = 0;
	}

	/* Disable interrupt */
	(*(nvp->nvp_ctlp->nvc_set_intr))(nvp,
	    NV_INTR_CLEAR_ALL|NV_INTR_DISABLE);

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
 * hot plug and remove interrupts can occur when the device is reset.
 * Masking the interrupt doesn't always work well because if a
 * different interrupt arrives on the other port, the driver can still
 * end up checking the state of the other port and discover the hot
 * interrupt flag is set even though it was masked.  Also, when there are
 * errors on the link there can be transient link events which need to be
 * masked and eliminated as well.
 */
static void
nv_link_event(nv_port_t *nvp, int flag)
{

	NVLOG(NVDBG_HOT, nvp->nvp_ctlp, nvp, "nv_link_event: flag: %s",
	    flag ? "add" : "remove");

	ASSERT(MUTEX_HELD(&nvp->nvp_mutex));

	nvp->nvp_link_event_time = ddi_get_lbolt();

	/*
	 * if a port has been deactivated, ignore all link events
	 */
	if (nvp->nvp_state & NV_DEACTIVATED) {
		NVLOG(NVDBG_HOT, nvp->nvp_ctlp, nvp, "ignoring link event"
		    " port deactivated", NULL);
		DTRACE_PROBE(ignoring_link_port_deactivated_p);

		return;
	}

	/*
	 * if the drive has been reset, ignore any transient events.  If it's
	 * a real removal event, nv_monitor_reset() will handle it.
	 */
	if (nvp->nvp_state & NV_RESET) {
		NVLOG(NVDBG_HOT, nvp->nvp_ctlp, nvp, "ignoring link event"
		    " during reset", NULL);
		DTRACE_PROBE(ignoring_link_event_during_reset_p);

		return;
	}

	/*
	 * if link event processing is already enabled, nothing to
	 * do.
	 */
	if (nvp->nvp_state & NV_LINK_EVENT) {

		NVLOG(NVDBG_HOT, nvp->nvp_ctlp, nvp,
		    "received link event while processing already in "
		    "progress", NULL);
		DTRACE_PROBE(nv_link_event_already_set_p);

		return;
	}

	DTRACE_PROBE1(link_event_p, int, nvp);

	nvp->nvp_state |= NV_LINK_EVENT;

	nv_setup_timeout(nvp, NV_LINK_EVENT_SETTLE);
}


/*
 * Get request sense data and stuff it the command's sense buffer.
 * Start a request sense command in order to get sense data to insert
 * in the sata packet's rqsense buffer.  The command completion
 * processing is in nv_intr_pkt_pio.
 *
 * The sata common module provides a function to allocate and set-up a
 * request sense packet command. The reasons it is not being used here is:
 * a) it cannot be called in an interrupt context and this function is
 *    called in an interrupt context.
 * b) it allocates DMA resources that are not used here because this is
 *    implemented using PIO.
 *
 * If, in the future, this is changed to use DMA, the sata common module
 * should be used to allocate and set-up the error retrieval (request sense)
 * command.
 */
static int
nv_start_rqsense_pio(nv_port_t *nvp, nv_slot_t *nv_slotp)
{
	sata_pkt_t *spkt = nv_slotp->nvslot_spkt;
	sata_cmd_t *satacmd = &spkt->satapkt_cmd;
	ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
	int cdb_len = spkt->satapkt_cmd.satacmd_acdb_len;

	NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
	    "nv_start_rqsense_pio: start", NULL);

	/* clear the local request sense buffer before starting the command */
	bzero(nv_slotp->nvslot_rqsense_buff, SATA_ATAPI_RQSENSE_LEN);

	/* Write the request sense PACKET command */

	/* select the drive */
	nv_put8(cmdhdl, nvp->nvp_drvhd, satacmd->satacmd_device_reg);

	/* make certain the drive selected */
	if (nv_wait(nvp, SATA_STATUS_DRDY, SATA_STATUS_BSY,
	    NV_SEC2USEC(5), 0) == B_FALSE) {
		NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
		    "nv_start_rqsense_pio: drive select failed", NULL);
		return (NV_FAILURE);
	}

	/* set up the command */
	nv_put8(cmdhdl, nvp->nvp_feature, 0);	/* deassert DMA and OVL */
	nv_put8(cmdhdl, nvp->nvp_hcyl, SATA_ATAPI_MAX_BYTES_PER_DRQ >> 8);
	nv_put8(cmdhdl, nvp->nvp_lcyl, SATA_ATAPI_MAX_BYTES_PER_DRQ & 0xff);
	nv_put8(cmdhdl, nvp->nvp_sect, 0);
	nv_put8(cmdhdl, nvp->nvp_count, 0);	/* no tag */

	/* initiate the command by writing the command register last */
	nv_put8(cmdhdl, nvp->nvp_cmd, SATAC_PACKET);

	/* Give the host ctlr time to do its thing, according to ATA/ATAPI */
	NV_DELAY_NSEC(400);

	/*
	 * Wait for the device to indicate that it is ready for the command
	 * ATAPI protocol state - HP0: Check_Status_A
	 */

	if (nv_wait3(nvp, SATA_STATUS_DRQ, SATA_STATUS_BSY, /* okay */
	    SATA_STATUS_ERR, SATA_STATUS_BSY, /* cmd failed */
	    SATA_STATUS_DF, SATA_STATUS_BSY, /* drive failed */
	    4000000, 0) == B_FALSE) {
		if (nv_get8(cmdhdl, nvp->nvp_status) &
		    (SATA_STATUS_ERR | SATA_STATUS_DF)) {
			spkt->satapkt_reason = SATA_PKT_DEV_ERROR;
			NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
			    "nv_start_rqsense_pio: rqsense dev error (HP0)",
			    NULL);
		} else {
			spkt->satapkt_reason = SATA_PKT_TIMEOUT;
			NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
			    "nv_start_rqsense_pio: rqsense timeout (HP0)",
			    NULL);
		}

		nv_copy_registers(nvp, &spkt->satapkt_device, spkt);
		nv_complete_io(nvp, spkt, 0);
		nv_reset(nvp, "rqsense_pio");

		return (NV_FAILURE);
	}

	/*
	 * Put the ATAPI command in the data register
	 * ATAPI protocol state - HP1: Send_Packet
	 */

	ddi_rep_put16(cmdhdl, (ushort_t *)nv_rqsense_cdb,
	    (ushort_t *)nvp->nvp_data,
	    (cdb_len >> 1), DDI_DEV_NO_AUTOINCR);

	NVLOG(NVDBG_ATAPI, nvp->nvp_ctlp, nvp,
	    "nv_start_rqsense_pio: exiting into HP3", NULL);

	return (NV_SUCCESS);
}

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
nv_quiesce(dev_info_t *dip)
{
	int port, instance = ddi_get_instance(dip);
	nv_ctl_t *nvc;

	if ((nvc = (nv_ctl_t *)ddi_get_soft_state(nv_statep, instance)) == NULL)
		return (DDI_FAILURE);

	for (port = 0; port < NV_MAX_PORTS(nvc); port++) {
		nv_port_t *nvp = &(nvc->nvc_port[port]);
		ddi_acc_handle_t cmdhdl = nvp->nvp_cmd_hdl;
		ddi_acc_handle_t bar5_hdl = nvp->nvp_ctlp->nvc_bar_hdl[5];
		uint32_t sctrl;

		/*
		 * Stop the controllers from generating interrupts.
		 */
		(*(nvc->nvc_set_intr))(nvp, NV_INTR_DISABLE_NON_BLOCKING);

		/*
		 * clear signature registers
		 */
		nv_put8(cmdhdl, nvp->nvp_sect, 0);
		nv_put8(cmdhdl, nvp->nvp_lcyl, 0);
		nv_put8(cmdhdl, nvp->nvp_hcyl, 0);
		nv_put8(cmdhdl, nvp->nvp_count, 0);

		nvp->nvp_signature = NV_NO_SIG;
		nvp->nvp_type = SATA_DTYPE_NONE;
		nvp->nvp_state |= NV_RESET;
		nvp->nvp_reset_time = ddi_get_lbolt();

		/*
		 * assert reset in PHY by writing a 1 to bit 0 scontrol
		 */
		sctrl = nv_get32(bar5_hdl, nvp->nvp_sctrl);

		nv_put32(bar5_hdl, nvp->nvp_sctrl,
		    sctrl | SCONTROL_DET_COMRESET);

		/*
		 * wait 1ms
		 */
		drv_usecwait(1000);

		/*
		 * de-assert reset in PHY
		 */
		nv_put32(bar5_hdl, nvp->nvp_sctrl, sctrl);
	}

	return (DDI_SUCCESS);
}


#ifdef SGPIO_SUPPORT
/*
 * NVIDIA specific SGPIO LED support
 * Please refer to the NVIDIA documentation for additional details
 */

/*
 * nv_sgp_led_init
 * Detect SGPIO support.  If present, initialize.
 */
static void
nv_sgp_led_init(nv_ctl_t *nvc, ddi_acc_handle_t pci_conf_handle)
{
	uint16_t csrp;		/* SGPIO_CSRP from PCI config space */
	uint32_t cbp;		/* SGPIO_CBP from PCI config space */
	nv_sgp_cmn_t *cmn;	/* shared data structure */
	int i;
	char tqname[SGPIO_TQ_NAME_LEN];
	extern caddr_t psm_map_phys_new(paddr_t, size_t, int);

	/*
	 * Initialize with appropriately invalid values in case this function
	 * exits without initializing SGPIO (for example, there is no SGPIO
	 * support).
	 */
	nvc->nvc_sgp_csr = 0;
	nvc->nvc_sgp_cbp = NULL;
	nvc->nvc_sgp_cmn = NULL;

	/*
	 * Only try to initialize SGPIO LED support if this property
	 * indicates it should be.
	 */
	if (ddi_getprop(DDI_DEV_T_ANY, nvc->nvc_dip, DDI_PROP_DONTPASS,
	    "enable-sgpio-leds", 0) != 1)
		return;

	/*
	 * CK804 can pass the sgpio_detect test even though it does not support
	 * SGPIO, so don't even look at a CK804.
	 */
	if (nvc->nvc_mcp5x_flag != B_TRUE)
		return;

	/*
	 * The NVIDIA SGPIO support can nominally handle 6 drives.
	 * However, the current implementation only supports 4 drives.
	 * With two drives per controller, that means only look at the
	 * first two controllers.
	 */
	if ((nvc->nvc_ctlr_num != 0) && (nvc->nvc_ctlr_num != 1))
		return;

	/* confirm that the SGPIO registers are there */
	if (nv_sgp_detect(pci_conf_handle, &csrp, &cbp) != NV_SUCCESS) {
		NVLOG(NVDBG_INIT, nvc, NULL,
		    "SGPIO registers not detected", NULL);
		return;
	}

	/* save off the SGPIO_CSR I/O address */
	nvc->nvc_sgp_csr = csrp;

	/* map in Control Block */
	nvc->nvc_sgp_cbp = (nv_sgp_cb_t *)psm_map_phys_new(cbp,
	    sizeof (nv_sgp_cb_t), PROT_READ | PROT_WRITE);

	/* initialize the SGPIO h/w */
	if (nv_sgp_init(nvc) == NV_FAILURE) {
		nv_cmn_err(CE_WARN, nvc, NULL,
		    "Unable to initialize SGPIO");
	}

	/*
	 * Initialize the shared space for this instance.  This could
	 * involve allocating the space, saving a pointer to the space
	 * and starting the taskq that actually turns the LEDs on and off.
	 * Or, it could involve just getting the pointer to the already
	 * allocated space.
	 */

	mutex_enter(&nv_sgp_c2c_mutex);

	/* try and find our CBP in the mapping table */
	cmn = NULL;
	for (i = 0; i < NV_MAX_CBPS; i++) {
		if (nv_sgp_cbp2cmn[i].c2cm_cbp == cbp) {
			cmn = nv_sgp_cbp2cmn[i].c2cm_cmn;
			break;
		}

		if (nv_sgp_cbp2cmn[i].c2cm_cbp == 0)
			break;
	}

	if (i >= NV_MAX_CBPS) {
		/*
		 * CBP to shared space mapping table is full
		 */
		nvc->nvc_sgp_cmn = NULL;
		nv_cmn_err(CE_WARN, nvc, NULL,
		    "LED handling not initialized - too many controllers");
	} else if (cmn == NULL) {
		/*
		 * Allocate the shared space, point the SGPIO scratch register
		 * at it and start the led update taskq.
		 */

		/* allocate shared space */
		cmn = (nv_sgp_cmn_t *)kmem_zalloc(sizeof (nv_sgp_cmn_t),
		    KM_SLEEP);
		if (cmn == NULL) {
			nv_cmn_err(CE_WARN, nvc, NULL,
			    "Failed to allocate shared data");
			return;
		}

		nvc->nvc_sgp_cmn = cmn;

		/* initialize the shared data structure */
		cmn->nvs_in_use = (1 << nvc->nvc_ctlr_num);
		cmn->nvs_connected = 0;
		cmn->nvs_activity = 0;
		cmn->nvs_cbp = cbp;

		mutex_init(&cmn->nvs_slock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&cmn->nvs_tlock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&cmn->nvs_cv, NULL, CV_DRIVER, NULL);

		/* put the address in the SGPIO scratch register */
#if defined(__amd64)
		nvc->nvc_sgp_cbp->sgpio_sr = (uint64_t)cmn;
#else
		nvc->nvc_sgp_cbp->sgpio_sr = (uint32_t)cmn;
#endif

		/* add an entry to the cbp to cmn mapping table */

		/* i should be the next available table position */
		nv_sgp_cbp2cmn[i].c2cm_cbp = cbp;
		nv_sgp_cbp2cmn[i].c2cm_cmn = cmn;

		/* start the activity LED taskq */

		/*
		 * The taskq name should be unique and the time
		 */
		(void) snprintf(tqname, SGPIO_TQ_NAME_LEN,
		    "nvSataLed%x", (short)(ddi_get_lbolt() & 0xffff));
		cmn->nvs_taskq = ddi_taskq_create(nvc->nvc_dip, tqname, 1,
		    TASKQ_DEFAULTPRI, 0);
		if (cmn->nvs_taskq == NULL) {
			cmn->nvs_taskq_delay = 0;
			nv_cmn_err(CE_WARN, nvc, NULL,
			    "Failed to start activity LED taskq");
		} else {
			cmn->nvs_taskq_delay = SGPIO_LOOP_WAIT_USECS;
			(void) ddi_taskq_dispatch(cmn->nvs_taskq,
			    nv_sgp_activity_led_ctl, nvc, DDI_SLEEP);
		}
	} else {
		nvc->nvc_sgp_cmn = cmn;
		cmn->nvs_in_use |= (1 << nvc->nvc_ctlr_num);
	}

	mutex_exit(&nv_sgp_c2c_mutex);
}

/*
 * nv_sgp_detect
 * Read the SGPIO_CSR and SGPIO_CBP values from PCI config space and
 * report back whether both were readable.
 */
static int
nv_sgp_detect(ddi_acc_handle_t pci_conf_handle, uint16_t *csrpp,
    uint32_t *cbpp)
{
	/* get the SGPIO_CSRP */
	*csrpp = pci_config_get16(pci_conf_handle, SGPIO_CSRP);
	if (*csrpp == 0) {
		return (NV_FAILURE);
	}

	/* SGPIO_CSRP is good, get the SGPIO_CBP */
	*cbpp = pci_config_get32(pci_conf_handle, SGPIO_CBP);
	if (*cbpp == 0) {
		return (NV_FAILURE);
	}

	/* SGPIO_CBP is good, so we must support SGPIO */
	return (NV_SUCCESS);
}

/*
 * nv_sgp_init
 * Initialize SGPIO.
 * The initialization process is described by NVIDIA, but the hardware does
 * not always behave as documented, so several steps have been changed and/or
 * omitted.
 */
static int
nv_sgp_init(nv_ctl_t *nvc)
{
	int seq;
	int rval = NV_SUCCESS;
	hrtime_t start, end;
	uint32_t cmd;
	uint32_t status;
	int drive_count;

	status = nv_sgp_csr_read(nvc);
	if (SGPIO_CSR_SSTAT(status) == SGPIO_STATE_RESET) {
		/* SGPIO logic is in reset state and requires initialization */

		/* noting the Sequence field value */
		seq = SGPIO_CSR_SEQ(status);

		/* issue SGPIO_CMD_READ_PARAMS command */
		cmd = SGPIO_CSR_CMD_SET(SGPIO_CMD_READ_PARAMS);
		nv_sgp_csr_write(nvc, cmd);

		DTRACE_PROBE2(sgpio__cmd, int, cmd, int, status);

		/* poll for command completion */
		start = gethrtime();
		end = start + NV_SGP_CMD_TIMEOUT;
		for (;;) {
			status = nv_sgp_csr_read(nvc);

			/* break on error */
			if (SGPIO_CSR_CSTAT(status) == SGPIO_CMD_ERROR) {
				NVLOG(NVDBG_VERBOSE, nvc, NULL,
				    "Command error during initialization",
				    NULL);
				rval = NV_FAILURE;
				break;
			}

			/* command processing is taking place */
			if (SGPIO_CSR_CSTAT(status) == SGPIO_CMD_OK) {
				if (SGPIO_CSR_SEQ(status) != seq) {
					NVLOG(NVDBG_VERBOSE, nvc, NULL,
					    "Sequence number change error",
					    NULL);
				}

				break;
			}

			/* if completion not detected in 2000ms ... */

			if (gethrtime() > end)
				break;

			/* wait 400 ns before checking again */
			NV_DELAY_NSEC(400);
		}
	}

	if (rval == NV_FAILURE)
		return (rval);

	if (SGPIO_CSR_SSTAT(status) != SGPIO_STATE_OPERATIONAL) {
		NVLOG(NVDBG_VERBOSE, nvc, NULL,
		    "SGPIO logic not operational after init - state %d",
		    SGPIO_CSR_SSTAT(status));
		/*
		 * Should return (NV_FAILURE) but the hardware can be
		 * operational even if the SGPIO Status does not indicate
		 * this.
		 */
	}

	/*
	 * NVIDIA recommends reading the supported drive count even
	 * though they also indicate that it is always 4 at this time.
	 */
	drive_count = SGP_CR0_DRV_CNT(nvc->nvc_sgp_cbp->sgpio_cr0);
	if (drive_count != SGPIO_DRV_CNT_VALUE) {
		NVLOG(NVDBG_INIT, nvc, NULL,
		    "SGPIO reported undocumented drive count - %d",
		    drive_count);
	}

	NVLOG(NVDBG_INIT, nvc, NULL,
	    "initialized ctlr: %d csr: 0x%08x",
	    nvc->nvc_ctlr_num, nvc->nvc_sgp_csr);

	return (rval);
}

static int
nv_sgp_check_set_cmn(nv_ctl_t *nvc)
{
	nv_sgp_cmn_t *cmn = nvc->nvc_sgp_cmn;

	if (cmn == NULL)
		return (NV_FAILURE);

	mutex_enter(&cmn->nvs_slock);
	cmn->nvs_in_use |= (1 << nvc->nvc_ctlr_num);
	mutex_exit(&cmn->nvs_slock);

	return (NV_SUCCESS);
}

/*
 * nv_sgp_csr_read
 * This is just a 32-bit port read from the value that was obtained from the
 * PCI config space.
 *
 * XXX It was advised to use the in[bwl] function for this, even though they
 * are obsolete interfaces.
 */
static int
nv_sgp_csr_read(nv_ctl_t *nvc)
{
	return (inl(nvc->nvc_sgp_csr));
}

/*
 * nv_sgp_csr_write
 * This is just a 32-bit I/O port write.  The port number was obtained from
 * the PCI config space.
 *
 * XXX It was advised to use the out[bwl] function for this, even though they
 * are obsolete interfaces.
 */
static void
nv_sgp_csr_write(nv_ctl_t *nvc, uint32_t val)
{
	outl(nvc->nvc_sgp_csr, val);
}

/*
 * nv_sgp_write_data
 * Cause SGPIO to send Control Block data
 */
static int
nv_sgp_write_data(nv_ctl_t *nvc)
{
	hrtime_t start, end;
	uint32_t status;
	uint32_t cmd;

	/* issue command */
	cmd = SGPIO_CSR_CMD_SET(SGPIO_CMD_WRITE_DATA);
	nv_sgp_csr_write(nvc, cmd);

	/* poll for completion */
	start = gethrtime();
	end = start + NV_SGP_CMD_TIMEOUT;
	for (;;) {
		status = nv_sgp_csr_read(nvc);

		/* break on error completion */
		if (SGPIO_CSR_CSTAT(status) == SGPIO_CMD_ERROR)
			break;

		/* break on successful completion */
		if (SGPIO_CSR_CSTAT(status) == SGPIO_CMD_OK)
			break;

		/* Wait 400 ns and try again */
		NV_DELAY_NSEC(400);

		if (gethrtime() > end)
			break;
	}

	if (SGPIO_CSR_CSTAT(status) == SGPIO_CMD_OK)
		return (NV_SUCCESS);

	return (NV_FAILURE);
}

/*
 * nv_sgp_activity_led_ctl
 * This is run as a taskq.  It wakes up at a fixed interval and checks to
 * see if any of the activity LEDs need to be changed.
 */
static void
nv_sgp_activity_led_ctl(void *arg)
{
	nv_ctl_t *nvc = (nv_ctl_t *)arg;
	nv_sgp_cmn_t *cmn;
	volatile nv_sgp_cb_t *cbp;
	clock_t ticks;
	uint8_t drv_leds;
	uint32_t old_leds;
	uint32_t new_led_state;
	int i;

	cmn = nvc->nvc_sgp_cmn;
	cbp = nvc->nvc_sgp_cbp;

	do {
		/* save off the old state of all of the LEDs */
		old_leds = cbp->sgpio0_tr;

		DTRACE_PROBE3(sgpio__activity__state,
		    int, cmn->nvs_connected, int, cmn->nvs_activity,
		    int, old_leds);

		new_led_state = 0;

		/* for each drive */
		for (i = 0; i < SGPIO_DRV_CNT_VALUE; i++) {

			/* get the current state of the LEDs for the drive */
			drv_leds = SGPIO0_TR_DRV(old_leds, i);

			if ((cmn->nvs_connected & (1 << i)) == 0) {
				/* if not connected, turn off activity */
				drv_leds &= ~TR_ACTIVE_MASK;
				drv_leds |= TR_ACTIVE_SET(TR_ACTIVE_DISABLE);

				new_led_state &= SGPIO0_TR_DRV_CLR(i);
				new_led_state |=
				    SGPIO0_TR_DRV_SET(drv_leds, i);

				continue;
			}

			if ((cmn->nvs_activity & (1 << i)) == 0) {
				/* connected, but not active */
				drv_leds &= ~TR_ACTIVE_MASK;
				drv_leds |= TR_ACTIVE_SET(TR_ACTIVE_ENABLE);

				new_led_state &= SGPIO0_TR_DRV_CLR(i);
				new_led_state |=
				    SGPIO0_TR_DRV_SET(drv_leds, i);

				continue;
			}

			/* connected and active */
			if (TR_ACTIVE(drv_leds) == TR_ACTIVE_ENABLE) {
				/* was enabled, so disable */
				drv_leds &= ~TR_ACTIVE_MASK;
				drv_leds |=
				    TR_ACTIVE_SET(TR_ACTIVE_DISABLE);

				new_led_state &= SGPIO0_TR_DRV_CLR(i);
				new_led_state |=
				    SGPIO0_TR_DRV_SET(drv_leds, i);
			} else {
				/* was disabled, so enable */
				drv_leds &= ~TR_ACTIVE_MASK;
				drv_leds |= TR_ACTIVE_SET(TR_ACTIVE_ENABLE);

				new_led_state &= SGPIO0_TR_DRV_CLR(i);
				new_led_state |=
				    SGPIO0_TR_DRV_SET(drv_leds, i);
			}

			/*
			 * clear the activity bit
			 * if there is drive activity again within the
			 * loop interval (now 1/16 second), nvs_activity
			 * will be reset and the "connected and active"
			 * condition above will cause the LED to blink
			 * off and on at the loop interval rate.  The
			 * rate may be increased (interval shortened) as
			 * long as it is not more than 1/30 second.
			 */
			mutex_enter(&cmn->nvs_slock);
			cmn->nvs_activity &= ~(1 << i);
			mutex_exit(&cmn->nvs_slock);
		}

		DTRACE_PROBE1(sgpio__new__led__state, int, new_led_state);

		/* write out LED values */

		mutex_enter(&cmn->nvs_slock);
		cbp->sgpio0_tr &= ~TR_ACTIVE_MASK_ALL;
		cbp->sgpio0_tr |= new_led_state;
		cbp->sgpio_cr0 = SGP_CR0_ENABLE_MASK;
		mutex_exit(&cmn->nvs_slock);

		if (nv_sgp_write_data(nvc) == NV_FAILURE) {
			NVLOG(NVDBG_VERBOSE, nvc, NULL,
			    "nv_sgp_write_data failure updating active LED",
			    NULL);
		}

		/* now rest for the interval */
		mutex_enter(&cmn->nvs_tlock);
		ticks = drv_usectohz(cmn->nvs_taskq_delay);
		if (ticks > 0)
			(void) cv_reltimedwait(&cmn->nvs_cv, &cmn->nvs_tlock,
			    ticks, TR_CLOCK_TICK);
		mutex_exit(&cmn->nvs_tlock);
	} while (ticks > 0);
}

/*
 * nv_sgp_drive_connect
 * Set the flag used to indicate that the drive is attached to the HBA.
 * Used to let the taskq know that it should turn the Activity LED on.
 */
static void
nv_sgp_drive_connect(nv_ctl_t *nvc, int drive)
{
	nv_sgp_cmn_t *cmn;

	if (nv_sgp_check_set_cmn(nvc) == NV_FAILURE)
		return;
	cmn = nvc->nvc_sgp_cmn;

	mutex_enter(&cmn->nvs_slock);
	cmn->nvs_connected |= (1 << drive);
	mutex_exit(&cmn->nvs_slock);
}

/*
 * nv_sgp_drive_disconnect
 * Clears the flag used to indicate that the drive is no longer attached
 * to the HBA.  Used to let the taskq know that it should turn the
 * Activity LED off.  The flag that indicates that the drive is in use is
 * also cleared.
 */
static void
nv_sgp_drive_disconnect(nv_ctl_t *nvc, int drive)
{
	nv_sgp_cmn_t *cmn;

	if (nv_sgp_check_set_cmn(nvc) == NV_FAILURE)
		return;
	cmn = nvc->nvc_sgp_cmn;

	mutex_enter(&cmn->nvs_slock);
	cmn->nvs_connected &= ~(1 << drive);
	cmn->nvs_activity &= ~(1 << drive);
	mutex_exit(&cmn->nvs_slock);
}

/*
 * nv_sgp_drive_active
 * Sets the flag used to indicate that the drive has been accessed and the
 * LED should be flicked off, then on.  It is cleared at a fixed time
 * interval by the LED taskq and set by the sata command start.
 */
static void
nv_sgp_drive_active(nv_ctl_t *nvc, int drive)
{
	nv_sgp_cmn_t *cmn;

	if (nv_sgp_check_set_cmn(nvc) == NV_FAILURE)
		return;
	cmn = nvc->nvc_sgp_cmn;

	DTRACE_PROBE1(sgpio__active, int, drive);

	mutex_enter(&cmn->nvs_slock);
	cmn->nvs_activity |= (1 << drive);
	mutex_exit(&cmn->nvs_slock);
}


/*
 * nv_sgp_locate
 * Turns the Locate/OK2RM LED off or on for a particular drive.  State is
 * maintained in the SGPIO Control Block.
 */
static void
nv_sgp_locate(nv_ctl_t *nvc, int drive, int value)
{
	uint8_t leds;
	volatile nv_sgp_cb_t *cb = nvc->nvc_sgp_cbp;
	nv_sgp_cmn_t *cmn;

	if (nv_sgp_check_set_cmn(nvc) == NV_FAILURE)
		return;
	cmn = nvc->nvc_sgp_cmn;

	if ((drive < 0) || (drive >= SGPIO_DRV_CNT_VALUE))
		return;

	DTRACE_PROBE2(sgpio__locate, int, drive, int, value);

	mutex_enter(&cmn->nvs_slock);

	leds = SGPIO0_TR_DRV(cb->sgpio0_tr, drive);

	leds &= ~TR_LOCATE_MASK;
	leds |= TR_LOCATE_SET(value);

	cb->sgpio0_tr &= SGPIO0_TR_DRV_CLR(drive);
	cb->sgpio0_tr |= SGPIO0_TR_DRV_SET(leds, drive);

	cb->sgpio_cr0 = SGP_CR0_ENABLE_MASK;

	mutex_exit(&cmn->nvs_slock);

	if (nv_sgp_write_data(nvc) == NV_FAILURE) {
		nv_cmn_err(CE_WARN, nvc, NULL,
		    "nv_sgp_write_data failure updating OK2RM/Locate LED");
	}
}

/*
 * nv_sgp_error
 * Turns the Error/Failure LED off or on for a particular drive.  State is
 * maintained in the SGPIO Control Block.
 */
static void
nv_sgp_error(nv_ctl_t *nvc, int drive, int value)
{
	uint8_t leds;
	volatile nv_sgp_cb_t *cb = nvc->nvc_sgp_cbp;
	nv_sgp_cmn_t *cmn;

	if (nv_sgp_check_set_cmn(nvc) == NV_FAILURE)
		return;
	cmn = nvc->nvc_sgp_cmn;

	if ((drive < 0) || (drive >= SGPIO_DRV_CNT_VALUE))
		return;

	DTRACE_PROBE2(sgpio__error, int, drive, int, value);

	mutex_enter(&cmn->nvs_slock);

	leds = SGPIO0_TR_DRV(cb->sgpio0_tr, drive);

	leds &= ~TR_ERROR_MASK;
	leds |= TR_ERROR_SET(value);

	cb->sgpio0_tr &= SGPIO0_TR_DRV_CLR(drive);
	cb->sgpio0_tr |= SGPIO0_TR_DRV_SET(leds, drive);

	cb->sgpio_cr0 = SGP_CR0_ENABLE_MASK;

	mutex_exit(&cmn->nvs_slock);

	if (nv_sgp_write_data(nvc) == NV_FAILURE) {
		nv_cmn_err(CE_WARN, nvc, NULL,
		    "nv_sgp_write_data failure updating Fail/Error LED");
	}
}

static void
nv_sgp_cleanup(nv_ctl_t *nvc)
{
	int drive, i;
	uint8_t drv_leds;
	uint32_t led_state;
	volatile nv_sgp_cb_t *cb = nvc->nvc_sgp_cbp;
	nv_sgp_cmn_t *cmn = nvc->nvc_sgp_cmn;
	extern void psm_unmap_phys(caddr_t, size_t);

	/*
	 * If the SGPIO Control Block isn't mapped or the shared data
	 * structure isn't present in this instance, there isn't much that
	 * can be cleaned up.
	 */
	if ((cb == NULL) || (cmn == NULL))
		return;

	/* turn off activity LEDs for this controller */
	drv_leds = TR_ACTIVE_SET(TR_ACTIVE_DISABLE);

	/* get the existing LED state */
	led_state = cb->sgpio0_tr;

	/* turn off port 0 */
	drive = SGP_CTLR_PORT_TO_DRV(nvc->nvc_ctlr_num, 0);
	led_state &= SGPIO0_TR_DRV_CLR(drive);
	led_state |= SGPIO0_TR_DRV_SET(drv_leds, drive);

	/* turn off port 1 */
	drive = SGP_CTLR_PORT_TO_DRV(nvc->nvc_ctlr_num, 1);
	led_state &= SGPIO0_TR_DRV_CLR(drive);
	led_state |= SGPIO0_TR_DRV_SET(drv_leds, drive);

	/* set the new led state, which should turn off this ctrl's LEDs */
	cb->sgpio_cr0 = SGP_CR0_ENABLE_MASK;
	(void) nv_sgp_write_data(nvc);

	/* clear the controller's in use bit */
	mutex_enter(&cmn->nvs_slock);
	cmn->nvs_in_use &= ~(1 << nvc->nvc_ctlr_num);
	mutex_exit(&cmn->nvs_slock);

	if (cmn->nvs_in_use == 0) {
		/* if all "in use" bits cleared, take everything down */

		if (cmn->nvs_taskq != NULL) {
			/* allow activity taskq to exit */
			cmn->nvs_taskq_delay = 0;
			cv_broadcast(&cmn->nvs_cv);

			/* then destroy it */
			ddi_taskq_destroy(cmn->nvs_taskq);
		}

		/* turn off all of the LEDs */
		cb->sgpio0_tr = 0;
		cb->sgpio_cr0 = SGP_CR0_ENABLE_MASK;
		(void) nv_sgp_write_data(nvc);

		cb->sgpio_sr = 0;

		/* zero out the CBP to cmn mapping */
		for (i = 0; i < NV_MAX_CBPS; i++) {
			if (nv_sgp_cbp2cmn[i].c2cm_cbp == cmn->nvs_cbp) {
				nv_sgp_cbp2cmn[i].c2cm_cmn = NULL;
				break;
			}

			if (nv_sgp_cbp2cmn[i].c2cm_cbp == 0)
				break;
		}

		/* free resources */
		cv_destroy(&cmn->nvs_cv);
		mutex_destroy(&cmn->nvs_tlock);
		mutex_destroy(&cmn->nvs_slock);

		kmem_free(nvc->nvc_sgp_cmn, sizeof (nv_sgp_cmn_t));
	}

	nvc->nvc_sgp_cmn = NULL;

	/* unmap the SGPIO Control Block */
	psm_unmap_phys((caddr_t)nvc->nvc_sgp_cbp, sizeof (nv_sgp_cb_t));
}
#endif	/* SGPIO_SUPPORT */
