/*
 * mr_sas.c: source for mr_sas driver
 *
 * Solaris MegaRAID device driver for SAS2.0 controllers
 * Copyright (c) 2008-2012, LSI Logic Corporation.
 * All rights reserved.
 *
 * Version:
 * Author:
 *		Swaminathan K S
 *		Arun Chandrashekhar
 *		Manju R
 *		Rasheed
 *		Shakeel Bukhari
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the author nor the names of its contributors may be
 *    used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2015, 2017 Citrus IT Limited. All rights reserved.
 * Copyright 2015 Garrett D'Amore <garrett@damore.org>
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/pci.h>
#include <sys/scsi/scsi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/signal.h>
#include <sys/byteorder.h>
#include <sys/sdt.h>
#include <sys/fs/dv_node.h>	/* devfs_clean */

#include "mr_sas.h"

/*
 * FMA header files
 */
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

/* Macros to help Skinny and stock 2108/MFI live together. */
#define	WR_IB_PICK_QPORT(addr, instance) \
	if ((instance)->skinny) { \
		WR_IB_LOW_QPORT((addr), (instance)); \
		WR_IB_HIGH_QPORT(0, (instance)); \
	} else { \
		WR_IB_QPORT((addr), (instance)); \
	}

/*
 * Local static data
 */
static void	*mrsas_state = NULL;
static volatile boolean_t	mrsas_relaxed_ordering = B_TRUE;
volatile int	debug_level_g = CL_NONE;
static volatile int	msi_enable = 1;
static volatile int 	ctio_enable = 1;

/* Default Timeout value to issue online controller reset */
volatile int  debug_timeout_g  = 0xF0;		/* 0xB4; */
/* Simulate consecutive firmware fault */
static volatile int  debug_fw_faults_after_ocr_g  = 0;
#ifdef OCRDEBUG
/* Simulate three consecutive timeout for an IO */
static volatile int  debug_consecutive_timeout_after_ocr_g  = 0;
#endif

#pragma weak scsi_hba_open
#pragma weak scsi_hba_close
#pragma weak scsi_hba_ioctl

/* Local static prototypes. */
static int	mrsas_getinfo(dev_info_t *, ddi_info_cmd_t,  void *, void **);
static int	mrsas_attach(dev_info_t *, ddi_attach_cmd_t);
#ifdef __sparc
static int	mrsas_reset(dev_info_t *, ddi_reset_cmd_t);
#else
static int	mrsas_quiesce(dev_info_t *);
#endif
static int	mrsas_detach(dev_info_t *, ddi_detach_cmd_t);
static int	mrsas_open(dev_t *, int, int, cred_t *);
static int	mrsas_close(dev_t, int, int, cred_t *);
static int	mrsas_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static int	mrsas_tran_tgt_init(dev_info_t *, dev_info_t *,
		    scsi_hba_tran_t *, struct scsi_device *);
static struct scsi_pkt *mrsas_tran_init_pkt(struct scsi_address *, register
		    struct scsi_pkt *, struct buf *, int, int, int, int,
		    int (*)(), caddr_t);
static int	mrsas_tran_start(struct scsi_address *,
		    register struct scsi_pkt *);
static int	mrsas_tran_abort(struct scsi_address *, struct scsi_pkt *);
static int	mrsas_tran_reset(struct scsi_address *, int);
static int	mrsas_tran_getcap(struct scsi_address *, char *, int);
static int	mrsas_tran_setcap(struct scsi_address *, char *, int, int);
static void	mrsas_tran_destroy_pkt(struct scsi_address *,
		    struct scsi_pkt *);
static void	mrsas_tran_dmafree(struct scsi_address *, struct scsi_pkt *);
static void	mrsas_tran_sync_pkt(struct scsi_address *, struct scsi_pkt *);
static int	mrsas_tran_quiesce(dev_info_t *dip);
static int	mrsas_tran_unquiesce(dev_info_t *dip);
static uint_t	mrsas_isr();
static uint_t	mrsas_softintr();
static void	mrsas_undo_resources(dev_info_t *, struct mrsas_instance *);

static void	free_space_for_mfi(struct mrsas_instance *);
static uint32_t	read_fw_status_reg_ppc(struct mrsas_instance *);
static void	issue_cmd_ppc(struct mrsas_cmd *, struct mrsas_instance *);
static int	issue_cmd_in_poll_mode_ppc(struct mrsas_instance *,
		    struct mrsas_cmd *);
static int	issue_cmd_in_sync_mode_ppc(struct mrsas_instance *,
		    struct mrsas_cmd *);
static void	enable_intr_ppc(struct mrsas_instance *);
static void	disable_intr_ppc(struct mrsas_instance *);
static int	intr_ack_ppc(struct mrsas_instance *);
static void	flush_cache(struct mrsas_instance *instance);
void	display_scsi_inquiry(caddr_t);
static int	start_mfi_aen(struct mrsas_instance *instance);
static int	handle_drv_ioctl(struct mrsas_instance *instance,
		    struct mrsas_ioctl *ioctl, int mode);
static int	handle_mfi_ioctl(struct mrsas_instance *instance,
		    struct mrsas_ioctl *ioctl, int mode);
static int	handle_mfi_aen(struct mrsas_instance *instance,
		    struct mrsas_aen *aen);
static struct mrsas_cmd *build_cmd(struct mrsas_instance *,
    struct scsi_address *, struct scsi_pkt *, uchar_t *);
static int	alloc_additional_dma_buffer(struct mrsas_instance *);
static void	complete_cmd_in_sync_mode(struct mrsas_instance *,
		struct mrsas_cmd *);
static int	mrsas_kill_adapter(struct mrsas_instance *);
static int	mrsas_issue_init_mfi(struct mrsas_instance *);
static int	mrsas_reset_ppc(struct mrsas_instance *);
static uint32_t mrsas_initiate_ocr_if_fw_is_faulty(struct mrsas_instance *);
static int	wait_for_outstanding(struct mrsas_instance *instance);
static int	register_mfi_aen(struct mrsas_instance *instance,
		    uint32_t seq_num, uint32_t class_locale_word);
static int	issue_mfi_pthru(struct mrsas_instance *instance, struct
		    mrsas_ioctl *ioctl, struct mrsas_cmd *cmd, int mode);
static int	issue_mfi_dcmd(struct mrsas_instance *instance, struct
		    mrsas_ioctl *ioctl, struct mrsas_cmd *cmd, int mode);
static int	issue_mfi_smp(struct mrsas_instance *instance, struct
		    mrsas_ioctl *ioctl, struct mrsas_cmd *cmd, int mode);
static int	issue_mfi_stp(struct mrsas_instance *instance, struct
		    mrsas_ioctl *ioctl, struct mrsas_cmd *cmd, int mode);
static int	abort_aen_cmd(struct mrsas_instance *instance,
		    struct mrsas_cmd *cmd_to_abort);

static void	mrsas_rem_intrs(struct mrsas_instance *instance);
static int	mrsas_add_intrs(struct mrsas_instance *instance, int intr_type);

static void	mrsas_tran_tgt_free(dev_info_t *, dev_info_t *,
		    scsi_hba_tran_t *, struct scsi_device *);
static int	mrsas_tran_bus_config(dev_info_t *, uint_t,
		    ddi_bus_config_op_t, void *, dev_info_t **);
static int	mrsas_parse_devname(char *, int *, int *);
static int	mrsas_config_all_devices(struct mrsas_instance *);
static int	mrsas_config_ld(struct mrsas_instance *, uint16_t,
			uint8_t, dev_info_t **);
static int	mrsas_name_node(dev_info_t *, char *, int);
static void	mrsas_issue_evt_taskq(struct mrsas_eventinfo *);
static void	free_additional_dma_buffer(struct mrsas_instance *);
static void io_timeout_checker(void *);
static void mrsas_fm_init(struct mrsas_instance *);
static void mrsas_fm_fini(struct mrsas_instance *);

static struct mrsas_function_template mrsas_function_template_ppc = {
	.read_fw_status_reg = read_fw_status_reg_ppc,
	.issue_cmd = issue_cmd_ppc,
	.issue_cmd_in_sync_mode = issue_cmd_in_sync_mode_ppc,
	.issue_cmd_in_poll_mode = issue_cmd_in_poll_mode_ppc,
	.enable_intr = enable_intr_ppc,
	.disable_intr = disable_intr_ppc,
	.intr_ack = intr_ack_ppc,
	.init_adapter = mrsas_init_adapter_ppc
};


static struct mrsas_function_template mrsas_function_template_fusion = {
	.read_fw_status_reg = tbolt_read_fw_status_reg,
	.issue_cmd = tbolt_issue_cmd,
	.issue_cmd_in_sync_mode = tbolt_issue_cmd_in_sync_mode,
	.issue_cmd_in_poll_mode = tbolt_issue_cmd_in_poll_mode,
	.enable_intr = tbolt_enable_intr,
	.disable_intr = tbolt_disable_intr,
	.intr_ack = tbolt_intr_ack,
	.init_adapter = mrsas_init_adapter_tbolt
};


ddi_dma_attr_t mrsas_generic_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* low DMA address range */
	0xFFFFFFFFU,		/* high DMA address range */
	0xFFFFFFFFU,		/* DMA counter register	 */
	8,			/* DMA address alignment */
	0x07,			/* DMA burstsizes  */
	1,			/* min DMA size */
	0xFFFFFFFFU,		/* max DMA size */
	0xFFFFFFFFU,		/* segment boundary */
	MRSAS_MAX_SGE_CNT,	/* dma_attr_sglen */
	512,			/* granularity of device */
	0			/* bus specific DMA flags */
};

int32_t mrsas_max_cap_maxxfer = 0x1000000;

/*
 * Fix for: Thunderbolt controller IO timeout when IO write size is 1MEG,
 * Limit size to 256K
 */
uint32_t mrsas_tbolt_max_cap_maxxfer = (512 * 512);

/*
 * cb_ops contains base level routines
 */
static struct cb_ops mrsas_cb_ops = {
	mrsas_open,		/* open */
	mrsas_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	mrsas_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	nodev,			/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_HOTPLUG,	/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

/*
 * dev_ops contains configuration routines
 */
static struct dev_ops mrsas_ops = {
	DEVO_REV,		/* rev, */
	0,			/* refcnt */
	mrsas_getinfo,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	mrsas_attach,		/* attach */
	mrsas_detach,		/* detach */
#ifdef	__sparc
	mrsas_reset,		/* reset */
#else	/* __sparc */
	nodev,
#endif	/* __sparc */
	&mrsas_cb_ops,		/* char/block ops */
	NULL,			/* bus ops */
	NULL,			/* power */
#ifdef __sparc
	ddi_quiesce_not_needed
#else	/* __sparc */
	mrsas_quiesce	/* quiesce */
#endif	/* __sparc */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* module type - driver */
	MRSAS_VERSION,
	&mrsas_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,	/* ml_rev - must be MODREV_1 */
	&modldrv,	/* ml_linkage */
	NULL		/* end of driver linkage */
};

static struct ddi_device_acc_attr endian_attr = {
	DDI_DEVICE_ATTR_V1,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

/* Use the LSI Fast Path for the 2208 (tbolt) commands. */
unsigned int enable_fp = 1;


/*
 * ************************************************************************** *
 *									      *
 *	   common entry points - for loadable kernel modules		      *
 *									      *
 * ************************************************************************** *
 */

/*
 * _init - initialize a loadable module
 * @void
 *
 * The driver should perform any one-time resource allocation or data
 * initialization during driver loading in _init(). For example, the driver
 * should initialize any mutexes global to the driver in this routine.
 * The driver should not, however, use _init() to allocate or initialize
 * anything that has to do with a particular instance of the device.
 * Per-instance initialization must be done in attach().
 */
int
_init(void)
{
	int ret;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	ret = ddi_soft_state_init(&mrsas_state,
	    sizeof (struct mrsas_instance), 0);

	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "mr_sas: could not init state");
		return (ret);
	}

	if ((ret = scsi_hba_init(&modlinkage)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "mr_sas: could not init scsi hba");
		ddi_soft_state_fini(&mrsas_state);
		return (ret);
	}

	ret = mod_install(&modlinkage);

	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "mr_sas: mod_install failed");
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini(&mrsas_state);
	}

	return (ret);
}

/*
 * _info - returns information about a loadable module.
 * @void
 *
 * _info() is called to return module information. This is a typical entry
 * point that does predefined role. It simply calls mod_info().
 */
int
_info(struct modinfo *modinfop)
{
	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	return (mod_info(&modlinkage, modinfop));
}

/*
 * _fini - prepare a loadable module for unloading
 * @void
 *
 * In _fini(), the driver should release any resources that were allocated in
 * _init(). The driver must remove itself from the system module list.
 */
int
_fini(void)
{
	int ret;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	if ((ret = mod_remove(&modlinkage)) != DDI_SUCCESS) {
		con_log(CL_ANN1,
		    (CE_WARN, "_fini: mod_remove() failed, error 0x%X", ret));
		return (ret);
	}

	scsi_hba_fini(&modlinkage);
	con_log(CL_DLEVEL1, (CE_NOTE, "_fini: scsi_hba_fini() done."));

	ddi_soft_state_fini(&mrsas_state);
	con_log(CL_DLEVEL1, (CE_NOTE, "_fini: ddi_soft_state_fini() done."));

	return (ret);
}


/*
 * ************************************************************************** *
 *									      *
 *		 common entry points - for autoconfiguration		      *
 *									      *
 * ************************************************************************** *
 */
/*
 * attach - adds a device to the system as part of initialization
 * @dip:
 * @cmd:
 *
 * The kernel calls a driver's attach() entry point to attach an instance of
 * a device (for MegaRAID, it is instance of a controller) or to resume
 * operation for an instance of a device that has been suspended or has been
 * shut down by the power management framework
 * The attach() entry point typically includes the following types of
 * processing:
 * - allocate a soft-state structure for the device instance (for MegaRAID,
 *   controller instance)
 * - initialize per-instance mutexes
 * - initialize condition variables
 * - register the device's interrupts (for MegaRAID, controller's interrupts)
 * - map the registers and memory of the device instance (for MegaRAID,
 *   controller instance)
 * - create minor device nodes for the device instance (for MegaRAID,
 *   controller instance)
 * - report that the device instance (for MegaRAID, controller instance) has
 *   attached
 */
static int
mrsas_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance_no;
	int		nregs;
	int		i = 0;
	uint8_t		irq;
	uint16_t	vendor_id;
	uint16_t	device_id;
	uint16_t	subsysvid;
	uint16_t	subsysid;
	uint16_t	command;
	off_t		reglength = 0;
	int		intr_types = 0;
	char		*data;

	scsi_hba_tran_t		*tran;
	ddi_dma_attr_t	tran_dma_attr;
	struct mrsas_instance	*instance;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	instance_no = ddi_get_instance(dip);

	/*
	 * check to see whether this device is in a DMA-capable slot.
	 */
	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "Device in slave-only slot, unused");
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_ATTACH:
		/* allocate the soft state for the instance */
		if (ddi_soft_state_zalloc(mrsas_state, instance_no)
		    != DDI_SUCCESS) {
			dev_err(dip, CE_WARN, "Failed to allocate soft state");
			return (DDI_FAILURE);
		}

		instance = (struct mrsas_instance *)ddi_get_soft_state
		    (mrsas_state, instance_no);

		if (instance == NULL) {
			dev_err(dip, CE_WARN, "Bad soft state");
			ddi_soft_state_free(mrsas_state, instance_no);
			return (DDI_FAILURE);
		}

		instance->unroll.softs	= 1;

		/* Setup the PCI configuration space handles */
		if (pci_config_setup(dip, &instance->pci_handle) !=
		    DDI_SUCCESS) {
			dev_err(dip, CE_WARN, "pci config setup failed");

			ddi_soft_state_free(mrsas_state, instance_no);
			return (DDI_FAILURE);
		}

		if (ddi_dev_nregs(dip, &nregs) != DDI_SUCCESS) {
			dev_err(dip, CE_WARN, "Failed to get registers");

			pci_config_teardown(&instance->pci_handle);
			ddi_soft_state_free(mrsas_state, instance_no);
			return (DDI_FAILURE);
		}

		vendor_id = pci_config_get16(instance->pci_handle,
		    PCI_CONF_VENID);
		device_id = pci_config_get16(instance->pci_handle,
		    PCI_CONF_DEVID);

		subsysvid = pci_config_get16(instance->pci_handle,
		    PCI_CONF_SUBVENID);
		subsysid = pci_config_get16(instance->pci_handle,
		    PCI_CONF_SUBSYSID);

		pci_config_put16(instance->pci_handle, PCI_CONF_COMM,
		    (pci_config_get16(instance->pci_handle,
		    PCI_CONF_COMM) | PCI_COMM_ME));
		irq = pci_config_get8(instance->pci_handle,
		    PCI_CONF_ILINE);

		dev_err(dip, CE_CONT,
		    "?0x%x:0x%x 0x%x:0x%x, irq:%d drv-ver:%s\n",
		    vendor_id, device_id, subsysvid,
		    subsysid, irq, MRSAS_VERSION);

		/* enable bus-mastering */
		command = pci_config_get16(instance->pci_handle,
		    PCI_CONF_COMM);

		if (!(command & PCI_COMM_ME)) {
			command |= PCI_COMM_ME;

			pci_config_put16(instance->pci_handle,
			    PCI_CONF_COMM, command);

			con_log(CL_ANN, (CE_CONT, "mr_sas%d: "
			    "enable bus-mastering", instance_no));
		} else {
			con_log(CL_DLEVEL1, (CE_CONT, "mr_sas%d: "
			    "bus-mastering already set", instance_no));
		}

		/* initialize function pointers */
		switch (device_id) {
		case PCI_DEVICE_ID_LSI_INVADER:
		case PCI_DEVICE_ID_LSI_FURY:
		case PCI_DEVICE_ID_LSI_INTRUDER:
		case PCI_DEVICE_ID_LSI_INTRUDER_24:
		case PCI_DEVICE_ID_LSI_CUTLASS_52:
		case PCI_DEVICE_ID_LSI_CUTLASS_53:
			dev_err(dip, CE_CONT, "?Gen3 device detected\n");
			instance->gen3 = 1;
			/* FALLTHROUGH */
		case PCI_DEVICE_ID_LSI_TBOLT:
			dev_err(dip, CE_CONT, "?TBOLT device detected\n");

			instance->func_ptr =
			    &mrsas_function_template_fusion;
			instance->tbolt = 1;
			break;

		case PCI_DEVICE_ID_LSI_SKINNY:
		case PCI_DEVICE_ID_LSI_SKINNY_NEW:
			/*
			 * FALLTHRU to PPC-style functions, but mark this
			 * instance as Skinny, because the register set is
			 * slightly different (See WR_IB_PICK_QPORT), and
			 * certain other features are available to a Skinny
			 * HBA.
			 */
			dev_err(dip, CE_CONT, "?Skinny device detected\n");
			instance->skinny = 1;
			/* FALLTHRU */

		case PCI_DEVICE_ID_LSI_2108VDE:
		case PCI_DEVICE_ID_LSI_2108V:
			dev_err(dip, CE_CONT,
			    "?2108 Liberator device detected\n");

			instance->func_ptr =
			    &mrsas_function_template_ppc;
			break;

		default:
			dev_err(dip, CE_WARN, "Invalid device detected");

			pci_config_teardown(&instance->pci_handle);
			ddi_soft_state_free(mrsas_state, instance_no);
			return (DDI_FAILURE);
		}

		instance->baseaddress = pci_config_get32(
		    instance->pci_handle, PCI_CONF_BASE0);
		instance->baseaddress &= 0x0fffc;

		instance->dip		= dip;
		instance->vendor_id	= vendor_id;
		instance->device_id	= device_id;
		instance->subsysvid	= subsysvid;
		instance->subsysid	= subsysid;
		instance->instance	= instance_no;

		/* Initialize FMA */
		instance->fm_capabilities = ddi_prop_get_int(
		    DDI_DEV_T_ANY, instance->dip, DDI_PROP_DONTPASS,
		    "fm-capable", DDI_FM_EREPORT_CAPABLE |
		    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE
		    | DDI_FM_ERRCB_CAPABLE);

		mrsas_fm_init(instance);

		/* Setup register map */
		if ((ddi_dev_regsize(instance->dip,
		    REGISTER_SET_IO_2108, &reglength) != DDI_SUCCESS) ||
		    reglength < MINIMUM_MFI_MEM_SZ) {
			goto fail_attach;
		}
		if (reglength > DEFAULT_MFI_MEM_SZ) {
			reglength = DEFAULT_MFI_MEM_SZ;
			con_log(CL_DLEVEL1, (CE_NOTE,
			    "mr_sas: register length to map is 0x%lx bytes",
			    reglength));
		}
		if (ddi_regs_map_setup(instance->dip,
		    REGISTER_SET_IO_2108, &instance->regmap, 0,
		    reglength, &endian_attr, &instance->regmap_handle)
		    != DDI_SUCCESS) {
			dev_err(dip, CE_WARN, "couldn't map control registers");
			goto fail_attach;
		}

		instance->unroll.regs = 1;

		/*
		 * Disable Interrupt Now.
		 * Setup Software interrupt
		 */
		instance->func_ptr->disable_intr(instance);

		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
		    "mrsas-enable-msi", &data) == DDI_SUCCESS) {
			if (strncmp(data, "no", 3) == 0) {
				msi_enable = 0;
				con_log(CL_ANN1, (CE_WARN,
				    "msi_enable = %d disabled", msi_enable));
			}
			ddi_prop_free(data);
		}

		dev_err(dip, CE_CONT, "?msi_enable = %d\n", msi_enable);

		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
		    "mrsas-enable-fp", &data) == DDI_SUCCESS) {
			if (strncmp(data, "no", 3) == 0) {
				enable_fp = 0;
				dev_err(dip, CE_NOTE,
				    "enable_fp = %d, Fast-Path disabled.\n",
				    enable_fp);
			}

			ddi_prop_free(data);
		}

		dev_err(dip, CE_CONT, "?enable_fp = %d\n", enable_fp);

		/* Check for all supported interrupt types */
		if (ddi_intr_get_supported_types(
		    dip, &intr_types) != DDI_SUCCESS) {
			dev_err(dip, CE_WARN,
			    "ddi_intr_get_supported_types() failed");
			goto fail_attach;
		}

		con_log(CL_DLEVEL1, (CE_NOTE,
		    "ddi_intr_get_supported_types() ret: 0x%x", intr_types));

		/* Initialize and Setup Interrupt handler */
		if (msi_enable && (intr_types & DDI_INTR_TYPE_MSIX)) {
			if (mrsas_add_intrs(instance, DDI_INTR_TYPE_MSIX) !=
			    DDI_SUCCESS) {
				dev_err(dip, CE_WARN,
				    "MSIX interrupt query failed");
				goto fail_attach;
			}
			instance->intr_type = DDI_INTR_TYPE_MSIX;
		} else if (msi_enable && (intr_types & DDI_INTR_TYPE_MSI)) {
			if (mrsas_add_intrs(instance, DDI_INTR_TYPE_MSI) !=
			    DDI_SUCCESS) {
				dev_err(dip, CE_WARN,
				    "MSI interrupt query failed");
				goto fail_attach;
			}
			instance->intr_type = DDI_INTR_TYPE_MSI;
		} else if (intr_types & DDI_INTR_TYPE_FIXED) {
			msi_enable = 0;
			if (mrsas_add_intrs(instance, DDI_INTR_TYPE_FIXED) !=
			    DDI_SUCCESS) {
				dev_err(dip, CE_WARN,
				    "FIXED interrupt query failed");
				goto fail_attach;
			}
			instance->intr_type = DDI_INTR_TYPE_FIXED;
		} else {
			dev_err(dip, CE_WARN, "Device cannot "
			    "suppport either FIXED or MSI/X "
			    "interrupts");
			goto fail_attach;
		}

		instance->unroll.intr = 1;

		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0,
		    "mrsas-enable-ctio", &data) == DDI_SUCCESS) {
			if (strncmp(data, "no", 3) == 0) {
				ctio_enable = 0;
				con_log(CL_ANN1, (CE_WARN,
				    "ctio_enable = %d disabled", ctio_enable));
			}
			ddi_prop_free(data);
		}

		dev_err(dip, CE_CONT, "?ctio_enable = %d\n", ctio_enable);

		/* setup the mfi based low level driver */
		if (mrsas_init_adapter(instance) != DDI_SUCCESS) {
			dev_err(dip, CE_WARN,
			    "could not initialize the low level driver");

			goto fail_attach;
		}

		/* Initialize all Mutex */
		INIT_LIST_HEAD(&instance->completed_pool_list);
		mutex_init(&instance->completed_pool_mtx, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(instance->intr_pri));

		mutex_init(&instance->sync_map_mtx, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(instance->intr_pri));

		mutex_init(&instance->app_cmd_pool_mtx, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(instance->intr_pri));

		mutex_init(&instance->config_dev_mtx, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(instance->intr_pri));

		mutex_init(&instance->cmd_pend_mtx, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(instance->intr_pri));

		mutex_init(&instance->ocr_flags_mtx, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(instance->intr_pri));

		mutex_init(&instance->int_cmd_mtx, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(instance->intr_pri));
		cv_init(&instance->int_cmd_cv, NULL, CV_DRIVER, NULL);

		mutex_init(&instance->cmd_pool_mtx, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(instance->intr_pri));

		mutex_init(&instance->reg_write_mtx, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(instance->intr_pri));

		if (instance->tbolt) {
			mutex_init(&instance->cmd_app_pool_mtx, NULL,
			    MUTEX_DRIVER, DDI_INTR_PRI(instance->intr_pri));

			mutex_init(&instance->chip_mtx, NULL,
			    MUTEX_DRIVER, DDI_INTR_PRI(instance->intr_pri));

		}

		instance->unroll.mutexs = 1;

		instance->timeout_id = (timeout_id_t)-1;

		/* Register our soft-isr for highlevel interrupts. */
		instance->isr_level = instance->intr_pri;
		if (!(instance->tbolt)) {
			if (instance->isr_level == HIGH_LEVEL_INTR) {
				if (ddi_add_softintr(dip,
				    DDI_SOFTINT_HIGH,
				    &instance->soft_intr_id, NULL, NULL,
				    mrsas_softintr, (caddr_t)instance) !=
				    DDI_SUCCESS) {
					dev_err(dip, CE_WARN,
					    "Software ISR did not register");

					goto fail_attach;
				}

				instance->unroll.soft_isr = 1;

			}
		}

		instance->softint_running = 0;

		/* Allocate a transport structure */
		tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP);

		if (tran == NULL) {
			dev_err(dip, CE_WARN,
			    "scsi_hba_tran_alloc failed");
			goto fail_attach;
		}

		instance->tran = tran;
		instance->unroll.tran = 1;

		tran->tran_hba_private	= instance;
		tran->tran_tgt_init	= mrsas_tran_tgt_init;
		tran->tran_tgt_probe	= scsi_hba_probe;
		tran->tran_tgt_free	= mrsas_tran_tgt_free;
		tran->tran_init_pkt	= mrsas_tran_init_pkt;
		if (instance->tbolt)
			tran->tran_start = mrsas_tbolt_tran_start;
		else
			tran->tran_start = mrsas_tran_start;
		tran->tran_abort	= mrsas_tran_abort;
		tran->tran_reset	= mrsas_tran_reset;
		tran->tran_getcap	= mrsas_tran_getcap;
		tran->tran_setcap	= mrsas_tran_setcap;
		tran->tran_destroy_pkt	= mrsas_tran_destroy_pkt;
		tran->tran_dmafree	= mrsas_tran_dmafree;
		tran->tran_sync_pkt	= mrsas_tran_sync_pkt;
		tran->tran_quiesce	= mrsas_tran_quiesce;
		tran->tran_unquiesce	= mrsas_tran_unquiesce;
		tran->tran_bus_config	= mrsas_tran_bus_config;

		if (mrsas_relaxed_ordering)
			mrsas_generic_dma_attr.dma_attr_flags |=
			    DDI_DMA_RELAXED_ORDERING;


		tran_dma_attr = mrsas_generic_dma_attr;
		tran_dma_attr.dma_attr_sgllen = instance->max_num_sge;

		/* Attach this instance of the hba */
		if (scsi_hba_attach_setup(dip, &tran_dma_attr, tran, 0)
		    != DDI_SUCCESS) {
			dev_err(dip, CE_WARN,
			    "scsi_hba_attach failed");

			goto fail_attach;
		}
		instance->unroll.tranSetup = 1;
		con_log(CL_ANN1,
		    (CE_CONT, "scsi_hba_attach_setup()	done."));

		/* create devctl node for cfgadm command */
		if (ddi_create_minor_node(dip, "devctl",
		    S_IFCHR, INST2DEVCTL(instance_no),
		    DDI_NT_SCSI_NEXUS, 0) == DDI_FAILURE) {
			dev_err(dip, CE_WARN, "failed to create devctl node.");

			goto fail_attach;
		}

		instance->unroll.devctl = 1;

		/* create scsi node for cfgadm command */
		if (ddi_create_minor_node(dip, "scsi", S_IFCHR,
		    INST2SCSI(instance_no), DDI_NT_SCSI_ATTACHMENT_POINT, 0) ==
		    DDI_FAILURE) {
			dev_err(dip, CE_WARN, "failed to create scsi node.");

			goto fail_attach;
		}

		instance->unroll.scsictl = 1;

		(void) snprintf(instance->iocnode, sizeof (instance->iocnode),
		    "%d:lsirdctl", instance_no);

		/*
		 * Create a node for applications
		 * for issuing ioctl to the driver.
		 */
		if (ddi_create_minor_node(dip, instance->iocnode,
		    S_IFCHR, INST2LSIRDCTL(instance_no), DDI_PSEUDO, 0) ==
		    DDI_FAILURE) {
			dev_err(dip, CE_WARN, "failed to create ioctl node.");

			goto fail_attach;
		}

		instance->unroll.ioctl = 1;

		/* Create a taskq to handle dr events */
		if ((instance->taskq = ddi_taskq_create(dip,
		    "mrsas_dr_taskq", 1, TASKQ_DEFAULTPRI, 0)) == NULL) {
			dev_err(dip, CE_WARN, "failed to create taskq.");
			instance->taskq = NULL;
			goto fail_attach;
		}
		instance->unroll.taskq = 1;
		con_log(CL_ANN1, (CE_CONT, "ddi_taskq_create() done."));

		/* enable interrupt */
		instance->func_ptr->enable_intr(instance);

		/* initiate AEN */
		if (start_mfi_aen(instance)) {
			dev_err(dip, CE_WARN, "failed to initiate AEN.");
			goto fail_attach;
		}
		instance->unroll.aenPend = 1;
		con_log(CL_ANN1,
		    (CE_CONT, "AEN started for instance %d.", instance_no));

		/* Finally! We are on the air.	*/
		ddi_report_dev(dip);

		/* FMA handle checking. */
		if (mrsas_check_acc_handle(instance->regmap_handle) !=
		    DDI_SUCCESS) {
			goto fail_attach;
		}
		if (mrsas_check_acc_handle(instance->pci_handle) !=
		    DDI_SUCCESS) {
			goto fail_attach;
		}

		instance->mr_ld_list =
		    kmem_zalloc(MRDRV_MAX_LD * sizeof (struct mrsas_ld),
		    KM_SLEEP);
		instance->unroll.ldlist_buff = 1;

		if (instance->tbolt || instance->skinny) {
			instance->mr_tbolt_pd_max = MRSAS_TBOLT_PD_TGT_MAX;
			instance->mr_tbolt_pd_list =
			    kmem_zalloc(MRSAS_TBOLT_GET_PD_MAX(instance) *
			    sizeof (struct mrsas_tbolt_pd), KM_SLEEP);
			ASSERT(instance->mr_tbolt_pd_list);
			for (i = 0; i < instance->mr_tbolt_pd_max; i++) {
				instance->mr_tbolt_pd_list[i].lun_type =
				    MRSAS_TBOLT_PD_LUN;
				instance->mr_tbolt_pd_list[i].dev_id =
				    (uint8_t)i;
			}

			instance->unroll.pdlist_buff = 1;
		}
		break;
	case DDI_PM_RESUME:
		con_log(CL_ANN, (CE_NOTE, "mr_sas: DDI_PM_RESUME"));
		break;
	case DDI_RESUME:
		con_log(CL_ANN, (CE_NOTE, "mr_sas: DDI_RESUME"));
		break;
	default:
		con_log(CL_ANN,
		    (CE_WARN, "mr_sas: invalid attach cmd=%x", cmd));
		return (DDI_FAILURE);
	}


	con_log(CL_DLEVEL1,
	    (CE_NOTE, "mrsas_attach() return SUCCESS instance_num %d",
	    instance_no));
	return (DDI_SUCCESS);

fail_attach:

	mrsas_undo_resources(dip, instance);

	mrsas_fm_ereport(instance, DDI_FM_DEVICE_NO_RESPONSE);
	ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);

	mrsas_fm_fini(instance);

	pci_config_teardown(&instance->pci_handle);
	ddi_soft_state_free(mrsas_state, instance_no);

	return (DDI_FAILURE);
}

/*
 * getinfo - gets device information
 * @dip:
 * @cmd:
 * @arg:
 * @resultp:
 *
 * The system calls getinfo() to obtain configuration information that only
 * the driver knows. The mapping of minor numbers to device instance is
 * entirely under the control of the driver. The system sometimes needs to ask
 * the driver which device a particular dev_t represents.
 * Given the device number return the devinfo pointer from the scsi_device
 * structure.
 */
/*ARGSUSED*/
static int
mrsas_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,  void *arg, void **resultp)
{
	int	rval;
	int	mrsas_minor = getminor((dev_t)arg);

	struct mrsas_instance	*instance;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	switch (cmd) {
		case DDI_INFO_DEVT2DEVINFO:
			instance = (struct mrsas_instance *)
			    ddi_get_soft_state(mrsas_state,
			    MINOR2INST(mrsas_minor));

			if (instance == NULL) {
				*resultp = NULL;
				rval = DDI_FAILURE;
			} else {
				*resultp = instance->dip;
				rval = DDI_SUCCESS;
			}
			break;
		case DDI_INFO_DEVT2INSTANCE:
			*resultp = (void *)(intptr_t)
			    (MINOR2INST(getminor((dev_t)arg)));
			rval = DDI_SUCCESS;
			break;
		default:
			*resultp = NULL;
			rval = DDI_FAILURE;
	}

	return (rval);
}

/*
 * detach - detaches a device from the system
 * @dip: pointer to the device's dev_info structure
 * @cmd: type of detach
 *
 * A driver's detach() entry point is called to detach an instance of a device
 * that is bound to the driver. The entry point is called with the instance of
 * the device node to be detached and with DDI_DETACH, which is specified as
 * the cmd argument to the entry point.
 * This routine is called during driver unload. We free all the allocated
 * resources and call the corresponding LLD so that it can also release all
 * its resources.
 */
static int
mrsas_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int	instance_no;

	struct mrsas_instance	*instance;

	con_log(CL_ANN, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));


	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	instance_no = ddi_get_instance(dip);

	instance = (struct mrsas_instance *)ddi_get_soft_state(mrsas_state,
	    instance_no);

	if (!instance) {
		dev_err(dip, CE_WARN, "could not get instance in detach");

		return (DDI_FAILURE);
	}

	switch (cmd) {
		case DDI_DETACH:
			con_log(CL_ANN, (CE_NOTE,
			    "mrsas_detach: DDI_DETACH"));

			mutex_enter(&instance->config_dev_mtx);
			if (instance->timeout_id != (timeout_id_t)-1) {
				mutex_exit(&instance->config_dev_mtx);
				(void) untimeout(instance->timeout_id);
				instance->timeout_id = (timeout_id_t)-1;
				mutex_enter(&instance->config_dev_mtx);
				instance->unroll.timer = 0;
			}
			mutex_exit(&instance->config_dev_mtx);

			if (instance->unroll.tranSetup == 1) {
				if (scsi_hba_detach(dip) != DDI_SUCCESS) {
					dev_err(dip, CE_WARN,
					    "failed to detach");
					return (DDI_FAILURE);
				}
				instance->unroll.tranSetup = 0;
				con_log(CL_ANN1,
				    (CE_CONT, "scsi_hba_dettach()  done."));
			}

			flush_cache(instance);

			mrsas_undo_resources(dip, instance);

			mrsas_fm_fini(instance);

			pci_config_teardown(&instance->pci_handle);
			ddi_soft_state_free(mrsas_state, instance_no);
			break;

		case DDI_PM_SUSPEND:
			con_log(CL_ANN, (CE_NOTE,
			    "mrsas_detach: DDI_PM_SUSPEND"));

			break;
		case DDI_SUSPEND:
			con_log(CL_ANN, (CE_NOTE,
			    "mrsas_detach: DDI_SUSPEND"));

			break;
		default:
			con_log(CL_ANN, (CE_WARN,
			    "invalid detach command:0x%x", cmd));
			return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


static void
mrsas_undo_resources(dev_info_t *dip, struct mrsas_instance *instance)
{
	con_log(CL_ANN, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	if (instance->unroll.ioctl == 1) {
		ddi_remove_minor_node(dip, instance->iocnode);
		instance->unroll.ioctl = 0;
	}

	if (instance->unroll.scsictl == 1) {
		ddi_remove_minor_node(dip, "scsi");
		instance->unroll.scsictl = 0;
	}

	if (instance->unroll.devctl == 1) {
		ddi_remove_minor_node(dip, "devctl");
		instance->unroll.devctl = 0;
	}

	if (instance->unroll.tranSetup == 1) {
		if (scsi_hba_detach(dip) != DDI_SUCCESS) {
			dev_err(dip, CE_WARN, "failed to detach");
			return;	 /* DDI_FAILURE */
		}
		instance->unroll.tranSetup = 0;
		con_log(CL_ANN1, (CE_CONT, "scsi_hba_dettach()	done."));
	}

	if (instance->unroll.tran == 1)	 {
		scsi_hba_tran_free(instance->tran);
		instance->unroll.tran = 0;
		con_log(CL_ANN1, (CE_CONT, "scsi_hba_tran_free()  done."));
	}

	if (instance->unroll.syncCmd == 1) {
		if (instance->tbolt) {
			if (abort_syncmap_cmd(instance,
			    instance->map_update_cmd)) {
				dev_err(dip, CE_WARN, "mrsas_detach: "
				    "failed to abort previous syncmap command");
			}

			instance->unroll.syncCmd = 0;
			con_log(CL_ANN1, (CE_CONT, "sync cmd aborted, done."));
		}
	}

	if (instance->unroll.aenPend == 1) {
		if (abort_aen_cmd(instance, instance->aen_cmd))
			dev_err(dip, CE_WARN, "mrsas_detach: "
			    "failed to abort prevous AEN command");

		instance->unroll.aenPend = 0;
		con_log(CL_ANN1, (CE_CONT, "aen cmd aborted, done."));
		/* This means the controller is fully initialized and running */
		/* Shutdown should be a last command to controller. */
		/* shutdown_controller(); */
	}


	if (instance->unroll.timer == 1)	 {
		if (instance->timeout_id != (timeout_id_t)-1) {
			(void) untimeout(instance->timeout_id);
			instance->timeout_id = (timeout_id_t)-1;

			instance->unroll.timer = 0;
		}
	}

	instance->func_ptr->disable_intr(instance);


	if (instance->unroll.mutexs == 1) {
		mutex_destroy(&instance->cmd_pool_mtx);
		mutex_destroy(&instance->app_cmd_pool_mtx);
		mutex_destroy(&instance->cmd_pend_mtx);
		mutex_destroy(&instance->completed_pool_mtx);
		mutex_destroy(&instance->sync_map_mtx);
		mutex_destroy(&instance->int_cmd_mtx);
		cv_destroy(&instance->int_cmd_cv);
		mutex_destroy(&instance->config_dev_mtx);
		mutex_destroy(&instance->ocr_flags_mtx);
		mutex_destroy(&instance->reg_write_mtx);

		if (instance->tbolt) {
			mutex_destroy(&instance->cmd_app_pool_mtx);
			mutex_destroy(&instance->chip_mtx);
		}

		instance->unroll.mutexs = 0;
		con_log(CL_ANN1, (CE_CONT, "Destroy mutex & cv,	 done."));
	}


	if (instance->unroll.soft_isr == 1) {
		ddi_remove_softintr(instance->soft_intr_id);
		instance->unroll.soft_isr = 0;
	}

	if (instance->unroll.intr == 1) {
		mrsas_rem_intrs(instance);
		instance->unroll.intr = 0;
	}


	if (instance->unroll.taskq == 1)	 {
		if (instance->taskq) {
			ddi_taskq_destroy(instance->taskq);
			instance->unroll.taskq = 0;
		}

	}

	/*
	 * free dma memory allocated for
	 * cmds/frames/queues/driver version etc
	 */
	if (instance->unroll.verBuff == 1) {
		(void) mrsas_free_dma_obj(instance, instance->drv_ver_dma_obj);
		instance->unroll.verBuff = 0;
	}

	if (instance->unroll.pdlist_buff == 1)	{
		if (instance->mr_tbolt_pd_list != NULL) {
			kmem_free(instance->mr_tbolt_pd_list,
			    MRSAS_TBOLT_GET_PD_MAX(instance) *
			    sizeof (struct mrsas_tbolt_pd));
		}

		instance->mr_tbolt_pd_list = NULL;
		instance->unroll.pdlist_buff = 0;
	}

	if (instance->unroll.ldlist_buff == 1)	{
		if (instance->mr_ld_list != NULL) {
			kmem_free(instance->mr_ld_list, MRDRV_MAX_LD
			    * sizeof (struct mrsas_ld));
		}

		instance->mr_ld_list = NULL;
		instance->unroll.ldlist_buff = 0;
	}

	if (instance->tbolt) {
		if (instance->unroll.alloc_space_mpi2 == 1) {
			free_space_for_mpi2(instance);
			instance->unroll.alloc_space_mpi2 = 0;
		}
	} else {
		if (instance->unroll.alloc_space_mfi == 1) {
			free_space_for_mfi(instance);
			instance->unroll.alloc_space_mfi = 0;
		}
	}

	if (instance->unroll.regs == 1)	 {
		ddi_regs_map_free(&instance->regmap_handle);
		instance->unroll.regs = 0;
		con_log(CL_ANN1, (CE_CONT, "ddi_regs_map_free()	 done."));
	}
}



/*
 * ************************************************************************** *
 *									      *
 *	       common entry points - for character driver types		      *
 *									      *
 * ************************************************************************** *
 */
/*
 * open - gets access to a device
 * @dev:
 * @openflags:
 * @otyp:
 * @credp:
 *
 * Access to a device by one or more application programs is controlled
 * through the open() and close() entry points. The primary function of
 * open() is to verify that the open request is allowed.
 */
static	int
mrsas_open(dev_t *dev, int openflags, int otyp, cred_t *credp)
{
	int	rval = 0;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	/* Check root permissions */
	if (drv_priv(credp) != 0) {
		con_log(CL_ANN, (CE_WARN,
		    "mr_sas: Non-root ioctl access denied!"));
		return (EPERM);
	}

	/* Verify we are being opened as a character device */
	if (otyp != OTYP_CHR) {
		con_log(CL_ANN, (CE_WARN,
		    "mr_sas: ioctl node must be a char node"));
		return (EINVAL);
	}

	if (ddi_get_soft_state(mrsas_state, MINOR2INST(getminor(*dev)))
	    == NULL) {
		return (ENXIO);
	}

	if (scsi_hba_open) {
		rval = scsi_hba_open(dev, openflags, otyp, credp);
	}

	return (rval);
}

/*
 * close - gives up access to a device
 * @dev:
 * @openflags:
 * @otyp:
 * @credp:
 *
 * close() should perform any cleanup necessary to finish using the minor
 * device, and prepare the device (and driver) to be opened again.
 */
static	int
mrsas_close(dev_t dev, int openflags, int otyp, cred_t *credp)
{
	int	rval = 0;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	/* no need for locks! */

	if (scsi_hba_close) {
		rval = scsi_hba_close(dev, openflags, otyp, credp);
	}

	return (rval);
}

/*
 * ioctl - performs a range of I/O commands for character drivers
 * @dev:
 * @cmd:
 * @arg:
 * @mode:
 * @credp:
 * @rvalp:
 *
 * ioctl() routine must make sure that user data is copied into or out of the
 * kernel address space explicitly using copyin(), copyout(), ddi_copyin(),
 * and ddi_copyout(), as appropriate.
 * This is a wrapper routine to serialize access to the actual ioctl routine.
 * ioctl() should return 0 on success, or the appropriate error number. The
 * driver may also set the value returned to the calling process through rvalp.
 */

static int
mrsas_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int	rval = 0;

	struct mrsas_instance	*instance;
	struct mrsas_ioctl	*ioctl;
	struct mrsas_aen	aen;
	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	instance = ddi_get_soft_state(mrsas_state, MINOR2INST(getminor(dev)));

	if (instance == NULL) {
		/* invalid minor number */
		con_log(CL_ANN, (CE_WARN, "mr_sas: adapter not found."));
		return (ENXIO);
	}

	ioctl = (struct mrsas_ioctl *)kmem_zalloc(sizeof (struct mrsas_ioctl),
	    KM_SLEEP);
	ASSERT(ioctl);

	switch ((uint_t)cmd) {
		case MRSAS_IOCTL_FIRMWARE:
			if (ddi_copyin((void *)arg, ioctl,
			    sizeof (struct mrsas_ioctl), mode)) {
				con_log(CL_ANN, (CE_WARN, "mrsas_ioctl: "
				    "ERROR IOCTL copyin"));
				kmem_free(ioctl, sizeof (struct mrsas_ioctl));
				return (EFAULT);
			}

			if (ioctl->control_code == MRSAS_DRIVER_IOCTL_COMMON) {
				rval = handle_drv_ioctl(instance, ioctl, mode);
			} else {
				rval = handle_mfi_ioctl(instance, ioctl, mode);
			}

			if (ddi_copyout((void *)ioctl, (void *)arg,
			    (sizeof (struct mrsas_ioctl) - 1), mode)) {
				con_log(CL_ANN, (CE_WARN,
				    "mrsas_ioctl: copy_to_user failed"));
				rval = 1;
			}

			break;
		case MRSAS_IOCTL_AEN:
			if (ddi_copyin((void *) arg, &aen,
			    sizeof (struct mrsas_aen), mode)) {
				con_log(CL_ANN, (CE_WARN,
				    "mrsas_ioctl: ERROR AEN copyin"));
				kmem_free(ioctl, sizeof (struct mrsas_ioctl));
				return (EFAULT);
			}

			rval = handle_mfi_aen(instance, &aen);

			if (ddi_copyout((void *) &aen, (void *)arg,
			    sizeof (struct mrsas_aen), mode)) {
				con_log(CL_ANN, (CE_WARN,
				    "mrsas_ioctl: copy_to_user failed"));
				rval = 1;
			}

			break;
		default:
			rval = scsi_hba_ioctl(dev, cmd, arg,
			    mode, credp, rvalp);

			con_log(CL_DLEVEL1, (CE_NOTE, "mrsas_ioctl: "
			    "scsi_hba_ioctl called, ret = %x.", rval));
	}

	kmem_free(ioctl, sizeof (struct mrsas_ioctl));
	return (rval);
}

/*
 * ************************************************************************** *
 *									      *
 *		 common entry points - for block driver types		      *
 *									      *
 * ************************************************************************** *
 */
#ifdef __sparc
/*
 * reset - TBD
 * @dip:
 * @cmd:
 *
 * TBD
 */
/*ARGSUSED*/
static int
mrsas_reset(dev_info_t *dip, ddi_reset_cmd_t cmd)
{
	int	instance_no;

	struct mrsas_instance	*instance;

	instance_no = ddi_get_instance(dip);
	instance = (struct mrsas_instance *)ddi_get_soft_state
	    (mrsas_state, instance_no);

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	if (!instance) {
		con_log(CL_ANN, (CE_WARN, "mr_sas:%d could not get adapter "
		    "in reset", instance_no));
		return (DDI_FAILURE);
	}

	instance->func_ptr->disable_intr(instance);

	con_log(CL_ANN1, (CE_CONT, "flushing cache for instance %d",
	    instance_no));

	flush_cache(instance);

	return (DDI_SUCCESS);
}
#else /* __sparc */
/*ARGSUSED*/
static int
mrsas_quiesce(dev_info_t *dip)
{
	int	instance_no;

	struct mrsas_instance	*instance;

	instance_no = ddi_get_instance(dip);
	instance = (struct mrsas_instance *)ddi_get_soft_state
	    (mrsas_state, instance_no);

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	if (!instance) {
		con_log(CL_ANN1, (CE_WARN, "mr_sas:%d could not get adapter "
		    "in quiesce", instance_no));
		return (DDI_FAILURE);
	}
	if (instance->deadadapter || instance->adapterresetinprogress) {
		con_log(CL_ANN1, (CE_WARN, "mr_sas:%d adapter is not in "
		    "healthy state", instance_no));
		return (DDI_FAILURE);
	}

	if (abort_aen_cmd(instance, instance->aen_cmd)) {
		con_log(CL_ANN1, (CE_WARN, "mrsas_quiesce: "
		    "failed to abort prevous AEN command QUIESCE"));
	}

	if (instance->tbolt) {
		if (abort_syncmap_cmd(instance,
		    instance->map_update_cmd)) {
			dev_err(dip, CE_WARN,
			    "mrsas_detach: failed to abort "
			    "previous syncmap command");
			return (DDI_FAILURE);
		}
	}

	instance->func_ptr->disable_intr(instance);

	con_log(CL_ANN1, (CE_CONT, "flushing cache for instance %d",
	    instance_no));

	flush_cache(instance);

	if (wait_for_outstanding(instance)) {
		con_log(CL_ANN1,
		    (CE_CONT, "wait_for_outstanding: return FAIL.\n"));
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}
#endif	/* __sparc */

/*
 * ************************************************************************** *
 *									      *
 *			    entry points (SCSI HBA)			      *
 *									      *
 * ************************************************************************** *
 */
/*
 * tran_tgt_init - initialize a target device instance
 * @hba_dip:
 * @tgt_dip:
 * @tran:
 * @sd:
 *
 * The tran_tgt_init() entry point enables the HBA to allocate and initialize
 * any per-target resources. tran_tgt_init() also enables the HBA to qualify
 * the device's address as valid and supportable for that particular HBA.
 * By returning DDI_FAILURE, the instance of the target driver for that device
 * is not probed or attached.
 */
/*ARGSUSED*/
static int
mrsas_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	struct mrsas_instance *instance;
	uint16_t tgt = sd->sd_address.a_target;
	uint8_t lun = sd->sd_address.a_lun;
	dev_info_t *child = NULL;

	con_log(CL_DLEVEL2, (CE_NOTE, "mrsas_tgt_init target %d lun %d",
	    tgt, lun));

	instance = ADDR2MR(&sd->sd_address);

	if (ndi_dev_is_persistent_node(tgt_dip) == 0) {
		/*
		 * If no persistent node exists, we don't allow .conf node
		 * to be created.
		 */
		if ((child = mrsas_find_child(instance, tgt, lun)) != NULL) {
			con_log(CL_DLEVEL2,
			    (CE_NOTE, "mrsas_tgt_init find child ="
			    " %p t = %d l = %d", (void *)child, tgt, lun));
			if (ndi_merge_node(tgt_dip, mrsas_name_node) !=
			    DDI_SUCCESS)
				/* Create this .conf node */
				return (DDI_SUCCESS);
		}
		con_log(CL_DLEVEL2, (CE_NOTE, "mrsas_tgt_init in ndi_per "
		    "DDI_FAILURE t = %d l = %d", tgt, lun));
		return (DDI_FAILURE);

	}

	con_log(CL_DLEVEL2, (CE_NOTE, "mrsas_tgt_init dev_dip %p tgt_dip %p",
	    (void *)instance->mr_ld_list[tgt].dip, (void *)tgt_dip));

	if (tgt < MRDRV_MAX_LD && lun == 0) {
		if (instance->mr_ld_list[tgt].dip == NULL &&
		    strcmp(ddi_driver_name(sd->sd_dev), "sd") == 0) {
			mutex_enter(&instance->config_dev_mtx);
			instance->mr_ld_list[tgt].dip = tgt_dip;
			instance->mr_ld_list[tgt].lun_type = MRSAS_LD_LUN;
			instance->mr_ld_list[tgt].flag = MRDRV_TGT_VALID;
			mutex_exit(&instance->config_dev_mtx);
		}
	} else if (instance->tbolt || instance->skinny) {
		if (instance->mr_tbolt_pd_list[tgt].dip == NULL) {
			mutex_enter(&instance->config_dev_mtx);
			instance->mr_tbolt_pd_list[tgt].dip = tgt_dip;
			instance->mr_tbolt_pd_list[tgt].flag =
			    MRDRV_TGT_VALID;
			mutex_exit(&instance->config_dev_mtx);
			con_log(CL_ANN1, (CE_NOTE, "mrsas_tran_tgt_init:"
			    "t%xl%x", tgt, lun));
		}
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static void
mrsas_tran_tgt_free(dev_info_t *hba_dip, dev_info_t *tgt_dip,
    scsi_hba_tran_t *hba_tran, struct scsi_device *sd)
{
	struct mrsas_instance *instance;
	int tgt = sd->sd_address.a_target;
	int lun = sd->sd_address.a_lun;

	instance = ADDR2MR(&sd->sd_address);

	con_log(CL_DLEVEL2, (CE_NOTE, "tgt_free t = %d l = %d", tgt, lun));

	if (tgt < MRDRV_MAX_LD && lun == 0) {
		if (instance->mr_ld_list[tgt].dip == tgt_dip) {
			mutex_enter(&instance->config_dev_mtx);
			instance->mr_ld_list[tgt].dip = NULL;
			mutex_exit(&instance->config_dev_mtx);
		}
	} else if (instance->tbolt || instance->skinny) {
		mutex_enter(&instance->config_dev_mtx);
		instance->mr_tbolt_pd_list[tgt].dip = NULL;
		mutex_exit(&instance->config_dev_mtx);
		con_log(CL_ANN1, (CE_NOTE, "tgt_free: Setting dip = NULL"
		    "for tgt:%x", tgt));
	}
}

dev_info_t *
mrsas_find_child(struct mrsas_instance *instance, uint16_t tgt, uint8_t lun)
{
	dev_info_t *child = NULL;
	char addr[SCSI_MAXNAMELEN];
	char tmp[MAXNAMELEN];

	(void) snprintf(addr, sizeof (addr), "%x,%x", tgt, lun);
	for (child = ddi_get_child(instance->dip); child;
	    child = ddi_get_next_sibling(child)) {

		if (ndi_dev_is_persistent_node(child) == 0) {
			continue;
		}

		if (mrsas_name_node(child, tmp, MAXNAMELEN) !=
		    DDI_SUCCESS) {
			continue;
		}

		if (strcmp(addr, tmp) == 0) {
			break;
		}
	}
	con_log(CL_DLEVEL2, (CE_NOTE, "mrsas_find_child: return child = %p",
	    (void *)child));
	return (child);
}

/*
 * mrsas_name_node -
 * @dip:
 * @name:
 * @len:
 */
static int
mrsas_name_node(dev_info_t *dip, char *name, int len)
{
	int tgt, lun;

	tgt = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "target", -1);
	con_log(CL_DLEVEL2, (CE_NOTE,
	    "mrsas_name_node: dip %p tgt %d", (void *)dip, tgt));
	if (tgt == -1) {
		return (DDI_FAILURE);
	}
	lun = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "lun", -1);
	con_log(CL_DLEVEL2,
	    (CE_NOTE, "mrsas_name_node: tgt %d lun %d", tgt, lun));
	if (lun == -1) {
		return (DDI_FAILURE);
	}
	(void) snprintf(name, len, "%x,%x", tgt, lun);
	return (DDI_SUCCESS);
}

/*
 * tran_init_pkt - allocate & initialize a scsi_pkt structure
 * @ap:
 * @pkt:
 * @bp:
 * @cmdlen:
 * @statuslen:
 * @tgtlen:
 * @flags:
 * @callback:
 *
 * The tran_init_pkt() entry point allocates and initializes a scsi_pkt
 * structure and DMA resources for a target driver request. The
 * tran_init_pkt() entry point is called when the target driver calls the
 * SCSA function scsi_init_pkt(). Each call of the tran_init_pkt() entry point
 * is a request to perform one or more of three possible services:
 *  - allocation and initialization of a scsi_pkt structure
 *  - allocation of DMA resources for data transfer
 *  - reallocation of DMA resources for the next portion of the data transfer
 */
static struct scsi_pkt *
mrsas_tran_init_pkt(struct scsi_address *ap, register struct scsi_pkt *pkt,
    struct buf *bp, int cmdlen, int statuslen, int tgtlen,
    int flags, int (*callback)(), caddr_t arg)
{
	struct scsa_cmd	*acmd;
	struct mrsas_instance	*instance;
	struct scsi_pkt	*new_pkt;

	con_log(CL_DLEVEL1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	instance = ADDR2MR(ap);

	/* step #1 : pkt allocation */
	if (pkt == NULL) {
		pkt = scsi_hba_pkt_alloc(instance->dip, ap, cmdlen, statuslen,
		    tgtlen, sizeof (struct scsa_cmd), callback, arg);
		if (pkt == NULL) {
			return (NULL);
		}

		acmd = PKT2CMD(pkt);

		/*
		 * Initialize the new pkt - we redundantly initialize
		 * all the fields for illustrative purposes.
		 */
		acmd->cmd_pkt		= pkt;
		acmd->cmd_flags		= 0;
		acmd->cmd_scblen	= statuslen;
		acmd->cmd_cdblen	= cmdlen;
		acmd->cmd_dmahandle	= NULL;
		acmd->cmd_ncookies	= 0;
		acmd->cmd_cookie	= 0;
		acmd->cmd_cookiecnt	= 0;
		acmd->cmd_nwin		= 0;

		pkt->pkt_address	= *ap;
		pkt->pkt_comp		= (void (*)())NULL;
		pkt->pkt_flags		= 0;
		pkt->pkt_time		= 0;
		pkt->pkt_resid		= 0;
		pkt->pkt_state		= 0;
		pkt->pkt_statistics	= 0;
		pkt->pkt_reason		= 0;
		new_pkt			= pkt;
	} else {
		acmd = PKT2CMD(pkt);
		new_pkt = NULL;
	}

	/* step #2 : dma allocation/move */
	if (bp && bp->b_bcount != 0) {
		if (acmd->cmd_dmahandle == NULL) {
			if (mrsas_dma_alloc(instance, pkt, bp, flags,
			    callback) == DDI_FAILURE) {
				if (new_pkt) {
					scsi_hba_pkt_free(ap, new_pkt);
				}
				return ((struct scsi_pkt *)NULL);
			}
		} else {
			if (mrsas_dma_move(instance, pkt, bp) == DDI_FAILURE) {
				return ((struct scsi_pkt *)NULL);
			}
		}
	}

	return (pkt);
}

/*
 * tran_start - transport a SCSI command to the addressed target
 * @ap:
 * @pkt:
 *
 * The tran_start() entry point for a SCSI HBA driver is called to transport a
 * SCSI command to the addressed target. The SCSI command is described
 * entirely within the scsi_pkt structure, which the target driver allocated
 * through the HBA driver's tran_init_pkt() entry point. If the command
 * involves a data transfer, DMA resources must also have been allocated for
 * the scsi_pkt structure.
 *
 * Return Values :
 *	TRAN_BUSY - request queue is full, no more free scbs
 *	TRAN_ACCEPT - pkt has been submitted to the instance
 */
static int
mrsas_tran_start(struct scsi_address *ap, register struct scsi_pkt *pkt)
{
	uchar_t		cmd_done = 0;

	struct mrsas_instance	*instance = ADDR2MR(ap);
	struct mrsas_cmd	*cmd;

	con_log(CL_DLEVEL1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));
	if (instance->deadadapter == 1) {
		con_log(CL_ANN1, (CE_WARN,
		    "mrsas_tran_start: return TRAN_FATAL_ERROR "
		    "for IO, as the HBA doesnt take any more IOs"));
		if (pkt) {
			pkt->pkt_reason		= CMD_DEV_GONE;
			pkt->pkt_statistics	= STAT_DISCON;
		}
		return (TRAN_FATAL_ERROR);
	}

	if (instance->adapterresetinprogress) {
		con_log(CL_ANN1, (CE_NOTE, "mrsas_tran_start: Reset flag set, "
		    "returning mfi_pkt and setting TRAN_BUSY\n"));
		return (TRAN_BUSY);
	}

	con_log(CL_ANN1, (CE_CONT, "chkpnt:%s:%d:SCSI CDB[0]=0x%x time:%x",
	    __func__, __LINE__, pkt->pkt_cdbp[0], pkt->pkt_time));

	pkt->pkt_reason	= CMD_CMPLT;
	*pkt->pkt_scbp = STATUS_GOOD; /* clear arq scsi_status */

	cmd = build_cmd(instance, ap, pkt, &cmd_done);

	/*
	 * Check if the command is already completed by the mrsas_build_cmd()
	 * routine. In which case the busy_flag would be clear and scb will be
	 * NULL and appropriate reason provided in pkt_reason field
	 */
	if (cmd_done) {
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_scbp[0] = STATUS_GOOD;
		pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET
		    | STATE_SENT_CMD;
		if (((pkt->pkt_flags & FLAG_NOINTR) == 0) && pkt->pkt_comp) {
			(*pkt->pkt_comp)(pkt);
		}

		return (TRAN_ACCEPT);
	}

	if (cmd == NULL) {
		return (TRAN_BUSY);
	}

	if ((pkt->pkt_flags & FLAG_NOINTR) == 0) {
		if (instance->fw_outstanding > instance->max_fw_cmds) {
			con_log(CL_ANN, (CE_CONT, "mr_sas:Firmware busy"));
			DTRACE_PROBE2(start_tran_err,
			    uint16_t, instance->fw_outstanding,
			    uint16_t, instance->max_fw_cmds);
			mrsas_return_mfi_pkt(instance, cmd);
			return (TRAN_BUSY);
		}

		/* Synchronize the Cmd frame for the controller */
		(void) ddi_dma_sync(cmd->frame_dma_obj.dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORDEV);
		con_log(CL_ANN, (CE_CONT, "issue_cmd_ppc: SCSI CDB[0]=0x%x"
		    "cmd->index:%x\n", pkt->pkt_cdbp[0], cmd->index));
		instance->func_ptr->issue_cmd(cmd, instance);

	} else {
		struct mrsas_header *hdr = &cmd->frame->hdr;

		instance->func_ptr->issue_cmd_in_poll_mode(instance, cmd);

		pkt->pkt_reason		= CMD_CMPLT;
		pkt->pkt_statistics	= 0;
		pkt->pkt_state |= STATE_XFERRED_DATA | STATE_GOT_STATUS;

		switch (ddi_get8(cmd->frame_dma_obj.acc_handle,
		    &hdr->cmd_status)) {
		case MFI_STAT_OK:
			pkt->pkt_scbp[0] = STATUS_GOOD;
			break;

		case MFI_STAT_SCSI_DONE_WITH_ERROR:
			con_log(CL_ANN, (CE_CONT,
			    "mrsas_tran_start: scsi done with error"));
			pkt->pkt_reason	= CMD_CMPLT;
			pkt->pkt_statistics = 0;

			((struct scsi_status *)pkt->pkt_scbp)->sts_chk = 1;
			break;

		case MFI_STAT_DEVICE_NOT_FOUND:
			con_log(CL_ANN, (CE_CONT,
			    "mrsas_tran_start: device not found error"));
			pkt->pkt_reason		= CMD_DEV_GONE;
			pkt->pkt_statistics	= STAT_DISCON;
			break;

		default:
			((struct scsi_status *)pkt->pkt_scbp)->sts_busy = 1;
		}

		(void) mrsas_common_check(instance, cmd);
		DTRACE_PROBE2(start_nointr_done, uint8_t, hdr->cmd,
		    uint8_t, hdr->cmd_status);
		mrsas_return_mfi_pkt(instance, cmd);

		if (pkt->pkt_comp) {
			(*pkt->pkt_comp)(pkt);
		}

	}

	return (TRAN_ACCEPT);
}

/*
 * tran_abort - Abort any commands that are currently in transport
 * @ap:
 * @pkt:
 *
 * The tran_abort() entry point for a SCSI HBA driver is called to abort any
 * commands that are currently in transport for a particular target. This entry
 * point is called when a target driver calls scsi_abort(). The tran_abort()
 * entry point should attempt to abort the command denoted by the pkt
 * parameter. If the pkt parameter is NULL, tran_abort() should attempt to
 * abort all outstanding commands in the transport layer for the particular
 * target or logical unit.
 */
/*ARGSUSED*/
static int
mrsas_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	/* abort command not supported by H/W */

	return (DDI_FAILURE);
}

/*
 * tran_reset - reset either the SCSI bus or target
 * @ap:
 * @level:
 *
 * The tran_reset() entry point for a SCSI HBA driver is called to reset either
 * the SCSI bus or a particular SCSI target device. This entry point is called
 * when a target driver calls scsi_reset(). The tran_reset() entry point must
 * reset the SCSI bus if level is RESET_ALL. If level is RESET_TARGET, just the
 * particular target or logical unit must be reset.
 */
/*ARGSUSED*/
static int
mrsas_tran_reset(struct scsi_address *ap, int level)
{
	struct mrsas_instance *instance = ADDR2MR(ap);

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	if (wait_for_outstanding(instance)) {
		con_log(CL_ANN1,
		    (CE_CONT, "wait_for_outstanding: return FAIL.\n"));
		return (DDI_FAILURE);
	} else {
		return (DDI_SUCCESS);
	}
}

/*
 * tran_getcap - get one of a set of SCSA-defined capabilities
 * @ap:
 * @cap:
 * @whom:
 *
 * The target driver can request the current setting of the capability for a
 * particular target by setting the whom parameter to nonzero. A whom value of
 * zero indicates a request for the current setting of the general capability
 * for the SCSI bus or for adapter hardware. The tran_getcap() should return -1
 * for undefined capabilities or the current value of the requested capability.
 */
/*ARGSUSED*/
static int
mrsas_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	int	rval = 0;

	struct mrsas_instance	*instance = ADDR2MR(ap);

	con_log(CL_DLEVEL2, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	/* we do allow inquiring about capabilities for other targets */
	if (cap == NULL) {
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_DMA_MAX:
		if (instance->tbolt) {
			/* Limit to 256k max transfer */
			rval = mrsas_tbolt_max_cap_maxxfer;
		} else {
			/* Limit to 16MB max transfer */
			rval = mrsas_max_cap_maxxfer;
		}
		break;
	case SCSI_CAP_MSG_OUT:
		rval = 1;
		break;
	case SCSI_CAP_DISCONNECT:
		rval = 0;
		break;
	case SCSI_CAP_SYNCHRONOUS:
		rval = 0;
		break;
	case SCSI_CAP_WIDE_XFER:
		rval = 1;
		break;
	case SCSI_CAP_TAGGED_QING:
		rval = 1;
		break;
	case SCSI_CAP_UNTAGGED_QING:
		rval = 1;
		break;
	case SCSI_CAP_PARITY:
		rval = 1;
		break;
	case SCSI_CAP_INITIATOR_ID:
		rval = instance->init_id;
		break;
	case SCSI_CAP_ARQ:
		rval = 1;
		break;
	case SCSI_CAP_LINKED_CMDS:
		rval = 0;
		break;
	case SCSI_CAP_RESET_NOTIFICATION:
		rval = 1;
		break;
	case SCSI_CAP_GEOMETRY:
		rval = -1;

		break;
	default:
		con_log(CL_DLEVEL2, (CE_NOTE, "Default cap coming 0x%x",
		    scsi_hba_lookup_capstr(cap)));
		rval = -1;
		break;
	}

	return (rval);
}

/*
 * tran_setcap - set one of a set of SCSA-defined capabilities
 * @ap:
 * @cap:
 * @value:
 * @whom:
 *
 * The target driver might request that the new value be set for a particular
 * target by setting the whom parameter to nonzero. A whom value of zero
 * means that request is to set the new value for the SCSI bus or for adapter
 * hardware in general.
 * The tran_setcap() should return the following values as appropriate:
 * - -1 for undefined capabilities
 * - 0 if the HBA driver cannot set the capability to the requested value
 * - 1 if the HBA driver is able to set the capability to the requested value
 */
/*ARGSUSED*/
static int
mrsas_tran_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	int		rval = 1;

	con_log(CL_DLEVEL2, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	/* We don't allow setting capabilities for other targets */
	if (cap == NULL || whom == 0) {
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
		case SCSI_CAP_DMA_MAX:
		case SCSI_CAP_MSG_OUT:
		case SCSI_CAP_PARITY:
		case SCSI_CAP_LINKED_CMDS:
		case SCSI_CAP_RESET_NOTIFICATION:
		case SCSI_CAP_DISCONNECT:
		case SCSI_CAP_SYNCHRONOUS:
		case SCSI_CAP_UNTAGGED_QING:
		case SCSI_CAP_WIDE_XFER:
		case SCSI_CAP_INITIATOR_ID:
		case SCSI_CAP_ARQ:
			/*
			 * None of these are settable via
			 * the capability interface.
			 */
			break;
		case SCSI_CAP_TAGGED_QING:
			rval = 1;
			break;
		case SCSI_CAP_SECTOR_SIZE:
			rval = 1;
			break;

		case SCSI_CAP_TOTAL_SECTORS:
			rval = 1;
			break;
		default:
			rval = -1;
			break;
	}

	return (rval);
}

/*
 * tran_destroy_pkt - deallocate scsi_pkt structure
 * @ap:
 * @pkt:
 *
 * The tran_destroy_pkt() entry point is the HBA driver function that
 * deallocates scsi_pkt structures. The tran_destroy_pkt() entry point is
 * called when the target driver calls scsi_destroy_pkt(). The
 * tran_destroy_pkt() entry point must free any DMA resources that have been
 * allocated for the packet. An implicit DMA synchronization occurs if the
 * DMA resources are freed and any cached data remains after the completion
 * of the transfer.
 */
static void
mrsas_tran_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct scsa_cmd *acmd = PKT2CMD(pkt);

	con_log(CL_DLEVEL2, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	if (acmd->cmd_flags & CFLAG_DMAVALID) {
		acmd->cmd_flags &= ~CFLAG_DMAVALID;

		(void) ddi_dma_unbind_handle(acmd->cmd_dmahandle);

		ddi_dma_free_handle(&acmd->cmd_dmahandle);

		acmd->cmd_dmahandle = NULL;
	}

	/* free the pkt */
	scsi_hba_pkt_free(ap, pkt);
}

/*
 * tran_dmafree - deallocates DMA resources
 * @ap:
 * @pkt:
 *
 * The tran_dmafree() entry point deallocates DMAQ resources that have been
 * allocated for a scsi_pkt structure. The tran_dmafree() entry point is
 * called when the target driver calls scsi_dmafree(). The tran_dmafree() must
 * free only DMA resources allocated for a scsi_pkt structure, not the
 * scsi_pkt itself. When DMA resources are freed, a DMA synchronization is
 * implicitly performed.
 */
/*ARGSUSED*/
static void
mrsas_tran_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	register struct scsa_cmd *acmd = PKT2CMD(pkt);

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	if (acmd->cmd_flags & CFLAG_DMAVALID) {
		acmd->cmd_flags &= ~CFLAG_DMAVALID;

		(void) ddi_dma_unbind_handle(acmd->cmd_dmahandle);

		ddi_dma_free_handle(&acmd->cmd_dmahandle);

		acmd->cmd_dmahandle = NULL;
	}
}

/*
 * tran_sync_pkt - synchronize the DMA object allocated
 * @ap:
 * @pkt:
 *
 * The tran_sync_pkt() entry point synchronizes the DMA object allocated for
 * the scsi_pkt structure before or after a DMA transfer. The tran_sync_pkt()
 * entry point is called when the target driver calls scsi_sync_pkt(). If the
 * data transfer direction is a DMA read from device to memory, tran_sync_pkt()
 * must synchronize the CPU's view of the data. If the data transfer direction
 * is a DMA write from memory to device, tran_sync_pkt() must synchronize the
 * device's view of the data.
 */
/*ARGSUSED*/
static void
mrsas_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	register struct scsa_cmd	*acmd = PKT2CMD(pkt);

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	if (acmd->cmd_flags & CFLAG_DMAVALID) {
		(void) ddi_dma_sync(acmd->cmd_dmahandle, acmd->cmd_dma_offset,
		    acmd->cmd_dma_len, (acmd->cmd_flags & CFLAG_DMASEND) ?
		    DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU);
	}
}

/*ARGSUSED*/
static int
mrsas_tran_quiesce(dev_info_t *dip)
{
	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	return (1);
}

/*ARGSUSED*/
static int
mrsas_tran_unquiesce(dev_info_t *dip)
{
	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	return (1);
}


/*
 * mrsas_isr(caddr_t)
 *
 * The Interrupt Service Routine
 *
 * Collect status for all completed commands and do callback
 *
 */
static uint_t
mrsas_isr(struct mrsas_instance *instance)
{
	int		need_softintr;
	uint32_t	producer;
	uint32_t	consumer;
	uint32_t	context;
	int		retval;

	struct mrsas_cmd	*cmd;
	struct mrsas_header	*hdr;
	struct scsi_pkt		*pkt;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));
	ASSERT(instance);
	if (instance->tbolt) {
		mutex_enter(&instance->chip_mtx);
		if ((instance->intr_type == DDI_INTR_TYPE_FIXED) &&
		    !(instance->func_ptr->intr_ack(instance))) {
			mutex_exit(&instance->chip_mtx);
			return (DDI_INTR_UNCLAIMED);
		}
		retval = mr_sas_tbolt_process_outstanding_cmd(instance);
		mutex_exit(&instance->chip_mtx);
		return (retval);
	} else {
		if ((instance->intr_type == DDI_INTR_TYPE_FIXED) &&
		    !instance->func_ptr->intr_ack(instance)) {
			return (DDI_INTR_UNCLAIMED);
		}
	}

	(void) ddi_dma_sync(instance->mfi_internal_dma_obj.dma_handle,
	    0, 0, DDI_DMA_SYNC_FORCPU);

	if (mrsas_check_dma_handle(instance->mfi_internal_dma_obj.dma_handle)
	    != DDI_SUCCESS) {
		mrsas_fm_ereport(instance, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);
		con_log(CL_ANN1, (CE_WARN,
		    "mr_sas_isr(): FMA check, returning DDI_INTR_UNCLAIMED"));
		return (DDI_INTR_CLAIMED);
	}
	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

#ifdef OCRDEBUG
	if (debug_consecutive_timeout_after_ocr_g == 1) {
		con_log(CL_ANN1, (CE_NOTE,
		    "simulating consecutive timeout after ocr"));
		return (DDI_INTR_CLAIMED);
	}
#endif

	mutex_enter(&instance->completed_pool_mtx);
	mutex_enter(&instance->cmd_pend_mtx);

	producer = ddi_get32(instance->mfi_internal_dma_obj.acc_handle,
	    instance->producer);
	consumer = ddi_get32(instance->mfi_internal_dma_obj.acc_handle,
	    instance->consumer);

	con_log(CL_ANN, (CE_CONT, " producer %x consumer %x ",
	    producer, consumer));
	if (producer == consumer) {
		con_log(CL_ANN, (CE_WARN, "producer ==	consumer case"));
		DTRACE_PROBE2(isr_pc_err, uint32_t, producer,
		    uint32_t, consumer);
		mutex_exit(&instance->cmd_pend_mtx);
		mutex_exit(&instance->completed_pool_mtx);
		return (DDI_INTR_CLAIMED);
	}

	while (consumer != producer) {
		context = ddi_get32(instance->mfi_internal_dma_obj.acc_handle,
		    &instance->reply_queue[consumer]);
		cmd = instance->cmd_list[context];

		if (cmd->sync_cmd == MRSAS_TRUE) {
			hdr = (struct mrsas_header *)&cmd->frame->hdr;
			if (hdr) {
				mlist_del_init(&cmd->list);
			}
		} else {
			pkt = cmd->pkt;
			if (pkt) {
				mlist_del_init(&cmd->list);
			}
		}

		mlist_add_tail(&cmd->list, &instance->completed_pool_list);

		consumer++;
		if (consumer == (instance->max_fw_cmds + 1)) {
			consumer = 0;
		}
	}
	ddi_put32(instance->mfi_internal_dma_obj.acc_handle,
	    instance->consumer, consumer);
	mutex_exit(&instance->cmd_pend_mtx);
	mutex_exit(&instance->completed_pool_mtx);

	(void) ddi_dma_sync(instance->mfi_internal_dma_obj.dma_handle,
	    0, 0, DDI_DMA_SYNC_FORDEV);

	if (instance->softint_running) {
		need_softintr = 0;
	} else {
		need_softintr = 1;
	}

	if (instance->isr_level == HIGH_LEVEL_INTR) {
		if (need_softintr) {
			ddi_trigger_softintr(instance->soft_intr_id);
		}
	} else {
		/*
		 * Not a high-level interrupt, therefore call the soft level
		 * interrupt explicitly
		 */
		(void) mrsas_softintr(instance);
	}

	return (DDI_INTR_CLAIMED);
}


/*
 * ************************************************************************** *
 *									      *
 *				    libraries				      *
 *									      *
 * ************************************************************************** *
 */
/*
 * get_mfi_pkt : Get a command from the free pool
 * After successful allocation, the caller of this routine
 * must clear the frame buffer (memset to zero) before
 * using the packet further.
 *
 * ***** Note *****
 * After clearing the frame buffer the context id of the
 * frame buffer SHOULD be restored back.
 */
struct mrsas_cmd *
mrsas_get_mfi_pkt(struct mrsas_instance *instance)
{
	mlist_t			*head = &instance->cmd_pool_list;
	struct mrsas_cmd	*cmd = NULL;

	mutex_enter(&instance->cmd_pool_mtx);

	if (!mlist_empty(head)) {
		cmd = mlist_entry(head->next, struct mrsas_cmd, list);
		mlist_del_init(head->next);
	}
	if (cmd != NULL) {
		cmd->pkt = NULL;
		cmd->retry_count_for_ocr = 0;
		cmd->drv_pkt_time = 0;

	}
	mutex_exit(&instance->cmd_pool_mtx);

	return (cmd);
}

static struct mrsas_cmd *
get_mfi_app_pkt(struct mrsas_instance *instance)
{
	mlist_t				*head = &instance->app_cmd_pool_list;
	struct mrsas_cmd	*cmd = NULL;

	mutex_enter(&instance->app_cmd_pool_mtx);

	if (!mlist_empty(head)) {
		cmd = mlist_entry(head->next, struct mrsas_cmd, list);
		mlist_del_init(head->next);
	}
	if (cmd != NULL) {
		cmd->pkt = NULL;
		cmd->retry_count_for_ocr = 0;
		cmd->drv_pkt_time = 0;
	}

	mutex_exit(&instance->app_cmd_pool_mtx);

	return (cmd);
}
/*
 * return_mfi_pkt : Return a cmd to free command pool
 */
void
mrsas_return_mfi_pkt(struct mrsas_instance *instance, struct mrsas_cmd *cmd)
{
	mutex_enter(&instance->cmd_pool_mtx);
	/* use mlist_add_tail for debug assistance */
	mlist_add_tail(&cmd->list, &instance->cmd_pool_list);

	mutex_exit(&instance->cmd_pool_mtx);
}

static void
return_mfi_app_pkt(struct mrsas_instance *instance, struct mrsas_cmd *cmd)
{
	mutex_enter(&instance->app_cmd_pool_mtx);

	mlist_add(&cmd->list, &instance->app_cmd_pool_list);

	mutex_exit(&instance->app_cmd_pool_mtx);
}
void
push_pending_mfi_pkt(struct mrsas_instance *instance, struct mrsas_cmd *cmd)
{
	struct scsi_pkt *pkt;
	struct mrsas_header	*hdr;
	con_log(CL_DLEVEL2, (CE_NOTE, "push_pending_pkt(): Called\n"));
	mutex_enter(&instance->cmd_pend_mtx);
	mlist_del_init(&cmd->list);
	mlist_add_tail(&cmd->list, &instance->cmd_pend_list);
	if (cmd->sync_cmd == MRSAS_TRUE) {
		hdr = (struct mrsas_header *)&cmd->frame->hdr;
		if (hdr) {
			con_log(CL_ANN1, (CE_CONT,
			    "push_pending_mfi_pkt: "
			    "cmd %p index %x "
			    "time %llx",
			    (void *)cmd, cmd->index,
			    gethrtime()));
			/* Wait for specified interval	*/
			cmd->drv_pkt_time = ddi_get16(
			    cmd->frame_dma_obj.acc_handle, &hdr->timeout);
			if (cmd->drv_pkt_time < debug_timeout_g)
				cmd->drv_pkt_time = (uint16_t)debug_timeout_g;
				con_log(CL_ANN1, (CE_CONT,
				    "push_pending_pkt(): "
				    "Called IO Timeout Value %x\n",
				    cmd->drv_pkt_time));
		}
		if (hdr && instance->timeout_id == (timeout_id_t)-1) {
			instance->timeout_id = timeout(io_timeout_checker,
			    (void *) instance, drv_usectohz(MRSAS_1_SECOND));
		}
	} else {
		pkt = cmd->pkt;
		if (pkt) {
			con_log(CL_ANN1, (CE_CONT,
			    "push_pending_mfi_pkt: "
			    "cmd %p index %x pkt %p, "
			    "time %llx",
			    (void *)cmd, cmd->index, (void *)pkt,
			    gethrtime()));
			cmd->drv_pkt_time = (uint16_t)debug_timeout_g;
		}
		if (pkt && instance->timeout_id == (timeout_id_t)-1) {
			instance->timeout_id = timeout(io_timeout_checker,
			    (void *) instance, drv_usectohz(MRSAS_1_SECOND));
		}
	}

	mutex_exit(&instance->cmd_pend_mtx);

}

int
mrsas_print_pending_cmds(struct mrsas_instance *instance)
{
	mlist_t *head = &instance->cmd_pend_list;
	mlist_t *tmp = head;
	struct mrsas_cmd *cmd = NULL;
	struct mrsas_header	*hdr;
	unsigned int		flag = 1;
	struct scsi_pkt *pkt;
	int saved_level;
	int cmd_count = 0;

	saved_level = debug_level_g;
	debug_level_g = CL_ANN1;

	dev_err(instance->dip, CE_NOTE,
	    "mrsas_print_pending_cmds(): Called");

	while (flag) {
		mutex_enter(&instance->cmd_pend_mtx);
		tmp	=	tmp->next;
		if (tmp == head) {
			mutex_exit(&instance->cmd_pend_mtx);
			flag = 0;
			con_log(CL_ANN1, (CE_CONT, "mrsas_print_pending_cmds():"
			    " NO MORE CMDS PENDING....\n"));
			break;
		} else {
			cmd = mlist_entry(tmp, struct mrsas_cmd, list);
			mutex_exit(&instance->cmd_pend_mtx);
			if (cmd) {
				if (cmd->sync_cmd == MRSAS_TRUE) {
					hdr = (struct mrsas_header *)
					    &cmd->frame->hdr;
					if (hdr) {
						con_log(CL_ANN1, (CE_CONT,
						    "print: cmd %p index 0x%x "
						    "drv_pkt_time 0x%x (NO-PKT)"
						    " hdr %p\n", (void *)cmd,
						    cmd->index,
						    cmd->drv_pkt_time,
						    (void *)hdr));
					}
				} else {
					pkt = cmd->pkt;
					if (pkt) {
					con_log(CL_ANN1, (CE_CONT,
					    "print: cmd %p index 0x%x "
					    "drv_pkt_time 0x%x pkt %p \n",
					    (void *)cmd, cmd->index,
					    cmd->drv_pkt_time, (void *)pkt));
					}
				}

				if (++cmd_count == 1) {
					mrsas_print_cmd_details(instance, cmd,
					    0xDD);
				} else {
					mrsas_print_cmd_details(instance, cmd,
					    1);
				}

			}
		}
	}
	con_log(CL_ANN1, (CE_CONT, "mrsas_print_pending_cmds(): Done\n"));


	debug_level_g = saved_level;

	return (DDI_SUCCESS);
}


int
mrsas_complete_pending_cmds(struct mrsas_instance *instance)
{

	struct mrsas_cmd *cmd = NULL;
	struct scsi_pkt *pkt;
	struct mrsas_header *hdr;

	struct mlist_head		*pos, *next;

	con_log(CL_ANN1, (CE_NOTE,
	    "mrsas_complete_pending_cmds(): Called"));

	mutex_enter(&instance->cmd_pend_mtx);
	mlist_for_each_safe(pos, next, &instance->cmd_pend_list) {
		cmd = mlist_entry(pos, struct mrsas_cmd, list);
		if (cmd) {
			pkt = cmd->pkt;
			if (pkt) { /* for IO */
				if (((pkt->pkt_flags & FLAG_NOINTR)
				    == 0) && pkt->pkt_comp) {
					pkt->pkt_reason
					    = CMD_DEV_GONE;
					pkt->pkt_statistics
					    = STAT_DISCON;
					con_log(CL_ANN1, (CE_CONT,
					    "fail and posting to scsa "
					    "cmd %p index %x"
					    " pkt %p "
					    "time : %llx",
					    (void *)cmd, cmd->index,
					    (void *)pkt, gethrtime()));
					(*pkt->pkt_comp)(pkt);
				}
			} else { /* for DCMDS */
				if (cmd->sync_cmd == MRSAS_TRUE) {
				hdr = (struct mrsas_header *)&cmd->frame->hdr;
				con_log(CL_ANN1, (CE_CONT,
				    "posting invalid status to application "
				    "cmd %p index %x"
				    " hdr %p "
				    "time : %llx",
				    (void *)cmd, cmd->index,
				    (void *)hdr, gethrtime()));
				hdr->cmd_status = MFI_STAT_INVALID_STATUS;
				complete_cmd_in_sync_mode(instance, cmd);
				}
			}
			mlist_del_init(&cmd->list);
		} else {
			con_log(CL_ANN1, (CE_CONT,
			    "mrsas_complete_pending_cmds:"
			    "NULL command\n"));
		}
		con_log(CL_ANN1, (CE_CONT,
		    "mrsas_complete_pending_cmds:"
		    "looping for more commands\n"));
	}
	mutex_exit(&instance->cmd_pend_mtx);

	con_log(CL_ANN1, (CE_CONT, "mrsas_complete_pending_cmds(): DONE\n"));
	return (DDI_SUCCESS);
}

void
mrsas_print_cmd_details(struct mrsas_instance *instance, struct mrsas_cmd *cmd,
    int detail)
{
	struct scsi_pkt *pkt = cmd->pkt;
	Mpi2RaidSCSIIORequest_t *scsi_io = cmd->scsi_io_request;
	int i;
	int saved_level;
	ddi_acc_handle_t acc_handle =
	    instance->mpi2_frame_pool_dma_obj.acc_handle;

	if (detail == 0xDD) {
		saved_level = debug_level_g;
		debug_level_g = CL_ANN1;
	}


	if (instance->tbolt) {
		con_log(CL_ANN1, (CE_CONT, "print_cmd_details: cmd %p "
		    "cmd->index 0x%x SMID 0x%x timer 0x%x sec\n",
		    (void *)cmd, cmd->index, cmd->SMID, cmd->drv_pkt_time));
	} else {
		con_log(CL_ANN1, (CE_CONT, "print_cmd_details: cmd %p "
		    "cmd->index 0x%x timer 0x%x sec\n",
		    (void *)cmd, cmd->index, cmd->drv_pkt_time));
	}

	if (pkt) {
		con_log(CL_ANN1, (CE_CONT, "scsi_pkt CDB[0]=0x%x",
		    pkt->pkt_cdbp[0]));
	} else {
		con_log(CL_ANN1, (CE_CONT, "NO-PKT"));
	}

	if ((detail == 0xDD) && instance->tbolt) {
		con_log(CL_ANN1, (CE_CONT, "RAID_SCSI_IO_REQUEST\n"));
		con_log(CL_ANN1, (CE_CONT, "DevHandle=0x%X Function=0x%X "
		    "IoFlags=0x%X SGLFlags=0x%X DataLength=0x%X\n",
		    ddi_get16(acc_handle, &scsi_io->DevHandle),
		    ddi_get8(acc_handle, &scsi_io->Function),
		    ddi_get16(acc_handle, &scsi_io->IoFlags),
		    ddi_get16(acc_handle, &scsi_io->SGLFlags),
		    ddi_get32(acc_handle, &scsi_io->DataLength)));

		for (i = 0; i < 32; i++) {
			con_log(CL_ANN1, (CE_CONT, "CDB[%d]=0x%x ", i,
			    ddi_get8(acc_handle, &scsi_io->CDB.CDB32[i])));
		}

		con_log(CL_ANN1, (CE_CONT, "RAID-CONTEXT\n"));
		con_log(CL_ANN1, (CE_CONT, "status=0x%X extStatus=0x%X "
		    "ldTargetId=0x%X timeoutValue=0x%X regLockFlags=0x%X "
		    "RAIDFlags=0x%X regLockRowLBA=0x%" PRIu64
		    " regLockLength=0x%X spanArm=0x%X\n",
		    ddi_get8(acc_handle, &scsi_io->RaidContext.status),
		    ddi_get8(acc_handle, &scsi_io->RaidContext.extStatus),
		    ddi_get16(acc_handle, &scsi_io->RaidContext.ldTargetId),
		    ddi_get16(acc_handle, &scsi_io->RaidContext.timeoutValue),
		    ddi_get8(acc_handle, &scsi_io->RaidContext.regLockFlags),
		    ddi_get8(acc_handle, &scsi_io->RaidContext.RAIDFlags),
		    ddi_get64(acc_handle, &scsi_io->RaidContext.regLockRowLBA),
		    ddi_get32(acc_handle, &scsi_io->RaidContext.regLockLength),
		    ddi_get8(acc_handle, &scsi_io->RaidContext.spanArm)));
	}

	if (detail == 0xDD) {
		debug_level_g = saved_level;
	}
}


int
mrsas_issue_pending_cmds(struct mrsas_instance *instance)
{
	mlist_t *head	=	&instance->cmd_pend_list;
	mlist_t *tmp	=	head->next;
	struct mrsas_cmd *cmd = NULL;
	struct scsi_pkt *pkt;

	con_log(CL_ANN1, (CE_NOTE, "mrsas_issue_pending_cmds(): Called"));
	while (tmp != head) {
		mutex_enter(&instance->cmd_pend_mtx);
		cmd = mlist_entry(tmp, struct mrsas_cmd, list);
		tmp = tmp->next;
		mutex_exit(&instance->cmd_pend_mtx);
		if (cmd) {
			con_log(CL_ANN1, (CE_CONT,
			    "mrsas_issue_pending_cmds(): "
			    "Got a cmd: cmd %p index 0x%x drv_pkt_time 0x%x ",
			    (void *)cmd, cmd->index, cmd->drv_pkt_time));

			/* Reset command timeout value */
			if (cmd->drv_pkt_time < debug_timeout_g)
				cmd->drv_pkt_time = (uint16_t)debug_timeout_g;

			cmd->retry_count_for_ocr++;

			dev_err(instance->dip, CE_CONT,
			    "cmd retry count = %d\n",
			    cmd->retry_count_for_ocr);

			if (cmd->retry_count_for_ocr > IO_RETRY_COUNT) {
				dev_err(instance->dip,
				    CE_WARN, "mrsas_issue_pending_cmds(): "
				    "cmd->retry_count exceeded limit >%d\n",
				    IO_RETRY_COUNT);
				mrsas_print_cmd_details(instance, cmd, 0xDD);

				dev_err(instance->dip, CE_WARN,
				    "mrsas_issue_pending_cmds():"
				    "Calling KILL Adapter");
				if (instance->tbolt)
					mrsas_tbolt_kill_adapter(instance);
				else
					(void) mrsas_kill_adapter(instance);
				return (DDI_FAILURE);
			}

			pkt = cmd->pkt;
			if (pkt) {
				con_log(CL_ANN1, (CE_CONT,
				    "PENDING PKT-CMD ISSUE: cmd %p index %x "
				    "pkt %p time %llx",
				    (void *)cmd, cmd->index,
				    (void *)pkt,
				    gethrtime()));

			} else {
				dev_err(instance->dip, CE_CONT,
				    "mrsas_issue_pending_cmds(): NO-PKT, "
				    "cmd %p index 0x%x drv_pkt_time 0x%x",
				    (void *)cmd, cmd->index, cmd->drv_pkt_time);
			}


			if (cmd->sync_cmd == MRSAS_TRUE) {
				dev_err(instance->dip, CE_CONT,
				    "mrsas_issue_pending_cmds(): "
				    "SYNC_CMD == TRUE \n");
				instance->func_ptr->issue_cmd_in_sync_mode(
				    instance, cmd);
			} else {
				instance->func_ptr->issue_cmd(cmd, instance);
			}
		} else {
			con_log(CL_ANN1, (CE_CONT,
			    "mrsas_issue_pending_cmds: NULL command\n"));
		}
		con_log(CL_ANN1, (CE_CONT,
		    "mrsas_issue_pending_cmds:"
		    "looping for more commands"));
	}
	con_log(CL_ANN1, (CE_CONT, "mrsas_issue_pending_cmds(): DONE\n"));
	return (DDI_SUCCESS);
}



/*
 * destroy_mfi_frame_pool
 */
void
destroy_mfi_frame_pool(struct mrsas_instance *instance)
{
	int		i;
	uint32_t	max_cmd = instance->max_fw_cmds;

	struct mrsas_cmd	*cmd;

	/* return all frames to pool */

	for (i = 0; i < max_cmd; i++) {

		cmd = instance->cmd_list[i];

		if (cmd->frame_dma_obj_status == DMA_OBJ_ALLOCATED)
			(void) mrsas_free_dma_obj(instance, cmd->frame_dma_obj);

		cmd->frame_dma_obj_status  = DMA_OBJ_FREED;
	}

}

/*
 * create_mfi_frame_pool
 */
int
create_mfi_frame_pool(struct mrsas_instance *instance)
{
	int		i = 0;
	int		cookie_cnt;
	uint16_t	max_cmd;
	uint16_t	sge_sz;
	uint32_t	sgl_sz;
	uint32_t	tot_frame_size;
	struct mrsas_cmd	*cmd;
	int			retval = DDI_SUCCESS;

	max_cmd = instance->max_fw_cmds;
	sge_sz	= sizeof (struct mrsas_sge_ieee);
	/* calculated the number of 64byte frames required for SGL */
	sgl_sz		= sge_sz * instance->max_num_sge;
	tot_frame_size	= sgl_sz + MRMFI_FRAME_SIZE + SENSE_LENGTH;

	con_log(CL_DLEVEL3, (CE_NOTE, "create_mfi_frame_pool: "
	    "sgl_sz %x tot_frame_size %x", sgl_sz, tot_frame_size));

	while (i < max_cmd) {
		cmd = instance->cmd_list[i];

		cmd->frame_dma_obj.size	= tot_frame_size;
		cmd->frame_dma_obj.dma_attr = mrsas_generic_dma_attr;
		cmd->frame_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		cmd->frame_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
		cmd->frame_dma_obj.dma_attr.dma_attr_sgllen = 1;
		cmd->frame_dma_obj.dma_attr.dma_attr_align = 64;

		cookie_cnt = mrsas_alloc_dma_obj(instance, &cmd->frame_dma_obj,
		    (uchar_t)DDI_STRUCTURE_LE_ACC);

		if (cookie_cnt == -1 || cookie_cnt > 1) {
			dev_err(instance->dip, CE_WARN,
			    "create_mfi_frame_pool: could not alloc.");
			retval = DDI_FAILURE;
			goto mrsas_undo_frame_pool;
		}

		bzero(cmd->frame_dma_obj.buffer, tot_frame_size);

		cmd->frame_dma_obj_status = DMA_OBJ_ALLOCATED;
		cmd->frame = (union mrsas_frame *)cmd->frame_dma_obj.buffer;
		cmd->frame_phys_addr =
		    cmd->frame_dma_obj.dma_cookie[0].dmac_address;

		cmd->sense = (uint8_t *)(((unsigned long)
		    cmd->frame_dma_obj.buffer) +
		    tot_frame_size - SENSE_LENGTH);
		cmd->sense_phys_addr =
		    cmd->frame_dma_obj.dma_cookie[0].dmac_address +
		    tot_frame_size - SENSE_LENGTH;

		if (!cmd->frame || !cmd->sense) {
			dev_err(instance->dip, CE_WARN,
			    "pci_pool_alloc failed");
			retval = ENOMEM;
			goto mrsas_undo_frame_pool;
		}

		ddi_put32(cmd->frame_dma_obj.acc_handle,
		    &cmd->frame->io.context, cmd->index);
		i++;

		con_log(CL_DLEVEL3, (CE_NOTE, "[%x]-%x",
		    cmd->index, cmd->frame_phys_addr));
	}

	return (DDI_SUCCESS);

mrsas_undo_frame_pool:
	if (i > 0)
		destroy_mfi_frame_pool(instance);

	return (retval);
}

/*
 * free_additional_dma_buffer
 */
static void
free_additional_dma_buffer(struct mrsas_instance *instance)
{
	if (instance->mfi_internal_dma_obj.status == DMA_OBJ_ALLOCATED) {
		(void) mrsas_free_dma_obj(instance,
		    instance->mfi_internal_dma_obj);
		instance->mfi_internal_dma_obj.status = DMA_OBJ_FREED;
	}

	if (instance->mfi_evt_detail_obj.status == DMA_OBJ_ALLOCATED) {
		(void) mrsas_free_dma_obj(instance,
		    instance->mfi_evt_detail_obj);
		instance->mfi_evt_detail_obj.status = DMA_OBJ_FREED;
	}
}

/*
 * alloc_additional_dma_buffer
 */
static int
alloc_additional_dma_buffer(struct mrsas_instance *instance)
{
	uint32_t	reply_q_sz;
	uint32_t	internal_buf_size = PAGESIZE*2;

	/* max cmds plus 1 + producer & consumer */
	reply_q_sz = sizeof (uint32_t) * (instance->max_fw_cmds + 1 + 2);

	instance->mfi_internal_dma_obj.size = internal_buf_size;
	instance->mfi_internal_dma_obj.dma_attr	= mrsas_generic_dma_attr;
	instance->mfi_internal_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
	instance->mfi_internal_dma_obj.dma_attr.dma_attr_count_max =
	    0xFFFFFFFFU;
	instance->mfi_internal_dma_obj.dma_attr.dma_attr_sgllen	= 1;

	if (mrsas_alloc_dma_obj(instance, &instance->mfi_internal_dma_obj,
	    (uchar_t)DDI_STRUCTURE_LE_ACC) != 1) {
		dev_err(instance->dip, CE_WARN,
		    "could not alloc reply queue");
		return (DDI_FAILURE);
	}

	bzero(instance->mfi_internal_dma_obj.buffer, internal_buf_size);

	instance->mfi_internal_dma_obj.status |= DMA_OBJ_ALLOCATED;

	instance->producer = (uint32_t *)((unsigned long)
	    instance->mfi_internal_dma_obj.buffer);
	instance->consumer = (uint32_t *)((unsigned long)
	    instance->mfi_internal_dma_obj.buffer + 4);
	instance->reply_queue = (uint32_t *)((unsigned long)
	    instance->mfi_internal_dma_obj.buffer + 8);
	instance->internal_buf = (caddr_t)(((unsigned long)
	    instance->mfi_internal_dma_obj.buffer) + reply_q_sz + 8);
	instance->internal_buf_dmac_add =
	    instance->mfi_internal_dma_obj.dma_cookie[0].dmac_address +
	    (reply_q_sz + 8);
	instance->internal_buf_size = internal_buf_size -
	    (reply_q_sz + 8);

	/* allocate evt_detail */
	instance->mfi_evt_detail_obj.size = sizeof (struct mrsas_evt_detail);
	instance->mfi_evt_detail_obj.dma_attr = mrsas_generic_dma_attr;
	instance->mfi_evt_detail_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
	instance->mfi_evt_detail_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
	instance->mfi_evt_detail_obj.dma_attr.dma_attr_sgllen = 1;
	instance->mfi_evt_detail_obj.dma_attr.dma_attr_align = 1;

	if (mrsas_alloc_dma_obj(instance, &instance->mfi_evt_detail_obj,
	    (uchar_t)DDI_STRUCTURE_LE_ACC) != 1) {
		dev_err(instance->dip, CE_WARN, "alloc_additional_dma_buffer: "
		    "could not allocate data transfer buffer.");
		goto mrsas_undo_internal_buff;
	}

	bzero(instance->mfi_evt_detail_obj.buffer,
	    sizeof (struct mrsas_evt_detail));

	instance->mfi_evt_detail_obj.status |= DMA_OBJ_ALLOCATED;

	return (DDI_SUCCESS);

mrsas_undo_internal_buff:
	if (instance->mfi_internal_dma_obj.status == DMA_OBJ_ALLOCATED) {
		(void) mrsas_free_dma_obj(instance,
		    instance->mfi_internal_dma_obj);
		instance->mfi_internal_dma_obj.status = DMA_OBJ_FREED;
	}

	return (DDI_FAILURE);
}


void
mrsas_free_cmd_pool(struct mrsas_instance *instance)
{
	int		i;
	uint32_t	max_cmd;
	size_t		sz;

	/* already freed */
	if (instance->cmd_list == NULL) {
		return;
	}

	max_cmd = instance->max_fw_cmds;

	/* size of cmd_list array */
	sz = sizeof (struct mrsas_cmd *) * max_cmd;

	/* First free each cmd */
	for (i = 0; i < max_cmd; i++) {
		if (instance->cmd_list[i] != NULL) {
			kmem_free(instance->cmd_list[i],
			    sizeof (struct mrsas_cmd));
		}

		instance->cmd_list[i] = NULL;
	}

	/* Now, free cmd_list array */
	if (instance->cmd_list != NULL)
		kmem_free(instance->cmd_list, sz);

	instance->cmd_list = NULL;

	INIT_LIST_HEAD(&instance->cmd_pool_list);
	INIT_LIST_HEAD(&instance->cmd_pend_list);
	if (instance->tbolt) {
		INIT_LIST_HEAD(&instance->cmd_app_pool_list);
	} else {
		INIT_LIST_HEAD(&instance->app_cmd_pool_list);
	}

}


/*
 * mrsas_alloc_cmd_pool
 */
int
mrsas_alloc_cmd_pool(struct mrsas_instance *instance)
{
	int		i;
	int		count;
	uint32_t	max_cmd;
	uint32_t	reserve_cmd;
	size_t		sz;

	struct mrsas_cmd	*cmd;

	max_cmd = instance->max_fw_cmds;
	con_log(CL_ANN1, (CE_NOTE, "mrsas_alloc_cmd_pool: "
	    "max_cmd %x", max_cmd));


	sz = sizeof (struct mrsas_cmd *) * max_cmd;

	/*
	 * instance->cmd_list is an array of struct mrsas_cmd pointers.
	 * Allocate the dynamic array first and then allocate individual
	 * commands.
	 */
	instance->cmd_list = kmem_zalloc(sz, KM_SLEEP);
	ASSERT(instance->cmd_list);

	/* create a frame pool and assign one frame to each cmd */
	for (count = 0; count < max_cmd; count++) {
		instance->cmd_list[count] =
		    kmem_zalloc(sizeof (struct mrsas_cmd), KM_SLEEP);
		ASSERT(instance->cmd_list[count]);
	}

	/* add all the commands to command pool */

	INIT_LIST_HEAD(&instance->cmd_pool_list);
	INIT_LIST_HEAD(&instance->cmd_pend_list);
	INIT_LIST_HEAD(&instance->app_cmd_pool_list);

	/*
	 * When max_cmd is lower than MRSAS_APP_RESERVED_CMDS, how do I split
	 * into app_cmd and regular cmd?  For now, just take
	 * max(1/8th of max, 4);
	 */
	reserve_cmd = min(MRSAS_APP_RESERVED_CMDS,
	    max(max_cmd >> 3, MRSAS_APP_MIN_RESERVED_CMDS));

	for (i = 0; i < reserve_cmd; i++) {
		cmd = instance->cmd_list[i];
		cmd->index = i;
		mlist_add_tail(&cmd->list, &instance->app_cmd_pool_list);
	}


	for (i = reserve_cmd; i < max_cmd; i++) {
		cmd = instance->cmd_list[i];
		cmd->index = i;
		mlist_add_tail(&cmd->list, &instance->cmd_pool_list);
	}

	return (DDI_SUCCESS);

mrsas_undo_cmds:
	if (count > 0) {
		/* free each cmd */
		for (i = 0; i < count; i++) {
			if (instance->cmd_list[i] != NULL) {
				kmem_free(instance->cmd_list[i],
				    sizeof (struct mrsas_cmd));
			}
			instance->cmd_list[i] = NULL;
		}
	}

mrsas_undo_cmd_list:
	if (instance->cmd_list != NULL)
		kmem_free(instance->cmd_list, sz);
	instance->cmd_list = NULL;

	return (DDI_FAILURE);
}


/*
 * free_space_for_mfi
 */
static void
free_space_for_mfi(struct mrsas_instance *instance)
{

	/* already freed */
	if (instance->cmd_list == NULL) {
		return;
	}

	/* Free additional dma buffer */
	free_additional_dma_buffer(instance);

	/* Free the MFI frame pool */
	destroy_mfi_frame_pool(instance);

	/* Free all the commands in the cmd_list */
	/* Free the cmd_list buffer itself */
	mrsas_free_cmd_pool(instance);
}

/*
 * alloc_space_for_mfi
 */
static int
alloc_space_for_mfi(struct mrsas_instance *instance)
{
	/* Allocate command pool (memory for cmd_list & individual commands) */
	if (mrsas_alloc_cmd_pool(instance)) {
		dev_err(instance->dip, CE_WARN, "error creating cmd pool");
		return (DDI_FAILURE);
	}

	/* Allocate MFI Frame pool */
	if (create_mfi_frame_pool(instance)) {
		dev_err(instance->dip, CE_WARN,
		    "error creating frame DMA pool");
		goto mfi_undo_cmd_pool;
	}

	/* Allocate additional DMA buffer */
	if (alloc_additional_dma_buffer(instance)) {
		dev_err(instance->dip, CE_WARN,
		    "error creating frame DMA pool");
		goto mfi_undo_frame_pool;
	}

	return (DDI_SUCCESS);

mfi_undo_frame_pool:
	destroy_mfi_frame_pool(instance);

mfi_undo_cmd_pool:
	mrsas_free_cmd_pool(instance);

	return (DDI_FAILURE);
}



/*
 * get_ctrl_info
 */
static int
get_ctrl_info(struct mrsas_instance *instance,
    struct mrsas_ctrl_info *ctrl_info)
{
	int	ret = 0;

	struct mrsas_cmd		*cmd;
	struct mrsas_dcmd_frame	*dcmd;
	struct mrsas_ctrl_info	*ci;

	if (instance->tbolt) {
		cmd = get_raid_msg_mfi_pkt(instance);
	} else {
		cmd = mrsas_get_mfi_pkt(instance);
	}

	if (!cmd) {
		con_log(CL_ANN, (CE_WARN,
		    "Failed to get a cmd for ctrl info"));
		DTRACE_PROBE2(info_mfi_err, uint16_t, instance->fw_outstanding,
		    uint16_t, instance->max_fw_cmds);
		return (DDI_FAILURE);
	}

	/* Clear the frame buffer and assign back the context id */
	(void) memset((char *)&cmd->frame[0], 0, sizeof (union mrsas_frame));
	ddi_put32(cmd->frame_dma_obj.acc_handle, &cmd->frame->hdr.context,
	    cmd->index);

	dcmd = &cmd->frame->dcmd;

	ci = (struct mrsas_ctrl_info *)instance->internal_buf;

	if (!ci) {
		dev_err(instance->dip, CE_WARN,
		    "Failed to alloc mem for ctrl info");
		mrsas_return_mfi_pkt(instance, cmd);
		return (DDI_FAILURE);
	}

	(void) memset(ci, 0, sizeof (struct mrsas_ctrl_info));

	/* for( i = 0; i < DCMD_MBOX_SZ; i++ ) dcmd->mbox.b[i] = 0; */
	(void) memset(dcmd->mbox.b, 0, DCMD_MBOX_SZ);

	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->cmd, MFI_CMD_OP_DCMD);
	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->cmd_status,
	    MFI_CMD_STATUS_POLL_MODE);
	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->sge_count, 1);
	ddi_put16(cmd->frame_dma_obj.acc_handle, &dcmd->flags,
	    MFI_FRAME_DIR_READ);
	ddi_put16(cmd->frame_dma_obj.acc_handle, &dcmd->timeout, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->data_xfer_len,
	    sizeof (struct mrsas_ctrl_info));
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->opcode,
	    MR_DCMD_CTRL_GET_INFO);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->sgl.sge32[0].phys_addr,
	    instance->internal_buf_dmac_add);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->sgl.sge32[0].length,
	    sizeof (struct mrsas_ctrl_info));

	cmd->frame_count = 1;

	if (instance->tbolt) {
		mr_sas_tbolt_build_mfi_cmd(instance, cmd);
	}

	if (!instance->func_ptr->issue_cmd_in_poll_mode(instance, cmd)) {
		ret = 0;

		ctrl_info->max_request_size = ddi_get32(
		    cmd->frame_dma_obj.acc_handle, &ci->max_request_size);

		ctrl_info->ld_present_count = ddi_get16(
		    cmd->frame_dma_obj.acc_handle, &ci->ld_present_count);

		ctrl_info->properties.on_off_properties = ddi_get32(
		    cmd->frame_dma_obj.acc_handle,
		    &ci->properties.on_off_properties);
		ddi_rep_get8(cmd->frame_dma_obj.acc_handle,
		    (uint8_t *)(ctrl_info->product_name),
		    (uint8_t *)(ci->product_name), 80 * sizeof (char),
		    DDI_DEV_AUTOINCR);
		/* should get more members of ci with ddi_get when needed */
	} else {
		dev_err(instance->dip, CE_WARN,
		    "get_ctrl_info: Ctrl info failed");
		ret = -1;
	}

	if (mrsas_common_check(instance, cmd) != DDI_SUCCESS) {
		ret = -1;
	}
	if (instance->tbolt) {
		return_raid_msg_mfi_pkt(instance, cmd);
	} else {
		mrsas_return_mfi_pkt(instance, cmd);
	}

	return (ret);
}

/*
 * abort_aen_cmd
 */
static int
abort_aen_cmd(struct mrsas_instance *instance,
    struct mrsas_cmd *cmd_to_abort)
{
	int	ret = 0;

	struct mrsas_cmd		*cmd;
	struct mrsas_abort_frame	*abort_fr;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt: abort_aen:%d", __LINE__));

	if (instance->tbolt) {
		cmd = get_raid_msg_mfi_pkt(instance);
	} else {
		cmd = mrsas_get_mfi_pkt(instance);
	}

	if (!cmd) {
		con_log(CL_ANN1, (CE_WARN,
		    "abort_aen_cmd():Failed to get a cmd for abort_aen_cmd"));
		DTRACE_PROBE2(abort_mfi_err, uint16_t, instance->fw_outstanding,
		    uint16_t, instance->max_fw_cmds);
		return (DDI_FAILURE);
	}

	/* Clear the frame buffer and assign back the context id */
	(void) memset((char *)&cmd->frame[0], 0, sizeof (union mrsas_frame));
	ddi_put32(cmd->frame_dma_obj.acc_handle, &cmd->frame->hdr.context,
	    cmd->index);

	abort_fr = &cmd->frame->abort;

	/* prepare and issue the abort frame */
	ddi_put8(cmd->frame_dma_obj.acc_handle,
	    &abort_fr->cmd, MFI_CMD_OP_ABORT);
	ddi_put8(cmd->frame_dma_obj.acc_handle, &abort_fr->cmd_status,
	    MFI_CMD_STATUS_SYNC_MODE);
	ddi_put16(cmd->frame_dma_obj.acc_handle, &abort_fr->flags, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &abort_fr->abort_context,
	    cmd_to_abort->index);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &abort_fr->abort_mfi_phys_addr_lo, cmd_to_abort->frame_phys_addr);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &abort_fr->abort_mfi_phys_addr_hi, 0);

	instance->aen_cmd->abort_aen = 1;

	cmd->frame_count = 1;

	if (instance->tbolt) {
		mr_sas_tbolt_build_mfi_cmd(instance, cmd);
	}

	if (instance->func_ptr->issue_cmd_in_poll_mode(instance, cmd)) {
		con_log(CL_ANN1, (CE_WARN,
		    "abort_aen_cmd: issue_cmd_in_poll_mode failed"));
		ret = -1;
	} else {
		ret = 0;
	}

	instance->aen_cmd->abort_aen = 1;
	instance->aen_cmd = 0;

	if (instance->tbolt) {
		return_raid_msg_mfi_pkt(instance, cmd);
	} else {
		mrsas_return_mfi_pkt(instance, cmd);
	}

	atomic_add_16(&instance->fw_outstanding, (-1));

	return (ret);
}


static int
mrsas_build_init_cmd(struct mrsas_instance *instance,
    struct mrsas_cmd **cmd_ptr)
{
	struct mrsas_cmd		*cmd;
	struct mrsas_init_frame		*init_frame;
	struct mrsas_init_queue_info	*initq_info;
	struct mrsas_drv_ver		drv_ver_info;


	/*
	 * Prepare a init frame. Note the init frame points to queue info
	 * structure. Each frame has SGL allocated after first 64 bytes. For
	 * this frame - since we don't need any SGL - we use SGL's space as
	 * queue info structure
	 */
	cmd = *cmd_ptr;


	/* Clear the frame buffer and assign back the context id */
	(void) memset((char *)&cmd->frame[0], 0, sizeof (union mrsas_frame));
	ddi_put32(cmd->frame_dma_obj.acc_handle, &cmd->frame->hdr.context,
	    cmd->index);

	init_frame = (struct mrsas_init_frame *)cmd->frame;
	initq_info = (struct mrsas_init_queue_info *)
	    ((unsigned long)init_frame + 64);

	(void) memset(init_frame, 0, MRMFI_FRAME_SIZE);
	(void) memset(initq_info, 0, sizeof (struct mrsas_init_queue_info));

	ddi_put32(cmd->frame_dma_obj.acc_handle, &initq_info->init_flags, 0);

	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->reply_queue_entries, instance->max_fw_cmds + 1);

	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->producer_index_phys_addr_hi, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->producer_index_phys_addr_lo,
	    instance->mfi_internal_dma_obj.dma_cookie[0].dmac_address);

	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->consumer_index_phys_addr_hi, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->consumer_index_phys_addr_lo,
	    instance->mfi_internal_dma_obj.dma_cookie[0].dmac_address + 4);

	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->reply_queue_start_phys_addr_hi, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->reply_queue_start_phys_addr_lo,
	    instance->mfi_internal_dma_obj.dma_cookie[0].dmac_address + 8);

	ddi_put8(cmd->frame_dma_obj.acc_handle,
	    &init_frame->cmd, MFI_CMD_OP_INIT);
	ddi_put8(cmd->frame_dma_obj.acc_handle, &init_frame->cmd_status,
	    MFI_CMD_STATUS_POLL_MODE);
	ddi_put16(cmd->frame_dma_obj.acc_handle, &init_frame->flags, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &init_frame->queue_info_new_phys_addr_lo,
	    cmd->frame_phys_addr + 64);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &init_frame->queue_info_new_phys_addr_hi, 0);


	/* fill driver version information */
	fill_up_drv_ver(&drv_ver_info);

	/* allocate the driver version data transfer buffer */
	instance->drv_ver_dma_obj.size = sizeof (drv_ver_info.drv_ver);
	instance->drv_ver_dma_obj.dma_attr = mrsas_generic_dma_attr;
	instance->drv_ver_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
	instance->drv_ver_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
	instance->drv_ver_dma_obj.dma_attr.dma_attr_sgllen = 1;
	instance->drv_ver_dma_obj.dma_attr.dma_attr_align = 1;

	if (mrsas_alloc_dma_obj(instance, &instance->drv_ver_dma_obj,
	    (uchar_t)DDI_STRUCTURE_LE_ACC) != 1) {
		con_log(CL_ANN, (CE_WARN,
		    "init_mfi : Could not allocate driver version buffer."));
		return (DDI_FAILURE);
	}
	/* copy driver version to dma buffer */
	(void) memset(instance->drv_ver_dma_obj.buffer, 0,
	    sizeof (drv_ver_info.drv_ver));
	ddi_rep_put8(cmd->frame_dma_obj.acc_handle,
	    (uint8_t *)drv_ver_info.drv_ver,
	    (uint8_t *)instance->drv_ver_dma_obj.buffer,
	    sizeof (drv_ver_info.drv_ver), DDI_DEV_AUTOINCR);


	/* copy driver version physical address to init frame */
	ddi_put64(cmd->frame_dma_obj.acc_handle, &init_frame->driverversion,
	    instance->drv_ver_dma_obj.dma_cookie[0].dmac_address);

	ddi_put32(cmd->frame_dma_obj.acc_handle, &init_frame->data_xfer_len,
	    sizeof (struct mrsas_init_queue_info));

	cmd->frame_count = 1;

	*cmd_ptr = cmd;

	return (DDI_SUCCESS);
}


/*
 * mrsas_init_adapter_ppc - Initialize MFI interface adapter.
 */
int
mrsas_init_adapter_ppc(struct mrsas_instance *instance)
{
	struct mrsas_cmd		*cmd;

	/*
	 * allocate memory for mfi adapter(cmd pool, individual commands, mfi
	 * frames etc
	 */
	if (alloc_space_for_mfi(instance) != DDI_SUCCESS) {
		con_log(CL_ANN, (CE_NOTE,
		    "Error, failed to allocate memory for MFI adapter"));
		return (DDI_FAILURE);
	}

	/* Build INIT command */
	cmd = mrsas_get_mfi_pkt(instance);
	if (cmd == NULL) {
		DTRACE_PROBE2(init_adapter_mfi_err, uint16_t,
		    instance->fw_outstanding, uint16_t, instance->max_fw_cmds);
		return (DDI_FAILURE);
	}

	if (mrsas_build_init_cmd(instance, &cmd) != DDI_SUCCESS) {
		con_log(CL_ANN,
		    (CE_NOTE, "Error, failed to build INIT command"));

		goto fail_undo_alloc_mfi_space;
	}

	/*
	 * Disable interrupt before sending init frame ( see linux driver code)
	 * send INIT MFI frame in polled mode
	 */
	if (instance->func_ptr->issue_cmd_in_poll_mode(instance, cmd)) {
		con_log(CL_ANN, (CE_WARN, "failed to init firmware"));
		goto fail_fw_init;
	}

	if (mrsas_common_check(instance, cmd) != DDI_SUCCESS)
		goto fail_fw_init;
	mrsas_return_mfi_pkt(instance, cmd);

	if (ctio_enable &&
	    (instance->func_ptr->read_fw_status_reg(instance) & 0x04000000)) {
		con_log(CL_ANN, (CE_NOTE, "mr_sas: IEEE SGL's supported"));
		instance->flag_ieee = 1;
	} else {
		instance->flag_ieee = 0;
	}

	ASSERT(!instance->skinny || instance->flag_ieee);

	instance->unroll.alloc_space_mfi = 1;
	instance->unroll.verBuff = 1;

	return (DDI_SUCCESS);


fail_fw_init:
	(void) mrsas_free_dma_obj(instance, instance->drv_ver_dma_obj);

fail_undo_alloc_mfi_space:
	mrsas_return_mfi_pkt(instance, cmd);
	free_space_for_mfi(instance);

	return (DDI_FAILURE);

}

/*
 * mrsas_init_adapter - Initialize adapter.
 */
int
mrsas_init_adapter(struct mrsas_instance *instance)
{
	struct mrsas_ctrl_info		ctrl_info;


	/* we expect the FW state to be READY */
	if (mfi_state_transition_to_ready(instance)) {
		con_log(CL_ANN, (CE_WARN, "mr_sas: F/W is not ready"));
		return (DDI_FAILURE);
	}

	/* get various operational parameters from status register */
	instance->max_num_sge =
	    (instance->func_ptr->read_fw_status_reg(instance) &
	    0xFF0000) >> 0x10;
	instance->max_num_sge =
	    (instance->max_num_sge > MRSAS_MAX_SGE_CNT) ?
	    MRSAS_MAX_SGE_CNT : instance->max_num_sge;

	/*
	 * Reduce the max supported cmds by 1. This is to ensure that the
	 * reply_q_sz (1 more than the max cmd that driver may send)
	 * does not exceed max cmds that the FW can support
	 */
	instance->max_fw_cmds =
	    instance->func_ptr->read_fw_status_reg(instance) & 0xFFFF;
	instance->max_fw_cmds = instance->max_fw_cmds - 1;



	/* Initialize adapter */
	if (instance->func_ptr->init_adapter(instance) != DDI_SUCCESS) {
		con_log(CL_ANN,
		    (CE_WARN, "mr_sas: could not initialize adapter"));
		return (DDI_FAILURE);
	}

	/* gather misc FW related information */
	instance->disable_online_ctrl_reset = 0;

	if (!get_ctrl_info(instance, &ctrl_info)) {
		instance->max_sectors_per_req = ctrl_info.max_request_size;
		con_log(CL_ANN1, (CE_NOTE,
		    "product name %s ld present %d",
		    ctrl_info.product_name, ctrl_info.ld_present_count));
	} else {
		instance->max_sectors_per_req = instance->max_num_sge *
		    PAGESIZE / 512;
	}

	if (ctrl_info.properties.on_off_properties & DISABLE_OCR_PROP_FLAG)
		instance->disable_online_ctrl_reset = 1;

	return (DDI_SUCCESS);

}



static int
mrsas_issue_init_mfi(struct mrsas_instance *instance)
{
	struct mrsas_cmd		*cmd;
	struct mrsas_init_frame		*init_frame;
	struct mrsas_init_queue_info	*initq_info;

/*
 * Prepare a init frame. Note the init frame points to queue info
 * structure. Each frame has SGL allocated after first 64 bytes. For
 * this frame - since we don't need any SGL - we use SGL's space as
 * queue info structure
 */
	con_log(CL_ANN1, (CE_NOTE,
	    "mrsas_issue_init_mfi: entry\n"));
	cmd = get_mfi_app_pkt(instance);

	if (!cmd) {
		con_log(CL_ANN1, (CE_WARN,
		    "mrsas_issue_init_mfi: get_pkt failed\n"));
		return (DDI_FAILURE);
	}

	/* Clear the frame buffer and assign back the context id */
	(void) memset((char *)&cmd->frame[0], 0, sizeof (union mrsas_frame));
	ddi_put32(cmd->frame_dma_obj.acc_handle, &cmd->frame->hdr.context,
	    cmd->index);

	init_frame = (struct mrsas_init_frame *)cmd->frame;
	initq_info = (struct mrsas_init_queue_info *)
	    ((unsigned long)init_frame + 64);

	(void) memset(init_frame, 0, MRMFI_FRAME_SIZE);
	(void) memset(initq_info, 0, sizeof (struct mrsas_init_queue_info));

	ddi_put32(cmd->frame_dma_obj.acc_handle, &initq_info->init_flags, 0);

	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->reply_queue_entries, instance->max_fw_cmds + 1);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->producer_index_phys_addr_hi, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->producer_index_phys_addr_lo,
	    instance->mfi_internal_dma_obj.dma_cookie[0].dmac_address);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->consumer_index_phys_addr_hi, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->consumer_index_phys_addr_lo,
	    instance->mfi_internal_dma_obj.dma_cookie[0].dmac_address + 4);

	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->reply_queue_start_phys_addr_hi, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &initq_info->reply_queue_start_phys_addr_lo,
	    instance->mfi_internal_dma_obj.dma_cookie[0].dmac_address + 8);

	ddi_put8(cmd->frame_dma_obj.acc_handle,
	    &init_frame->cmd, MFI_CMD_OP_INIT);
	ddi_put8(cmd->frame_dma_obj.acc_handle, &init_frame->cmd_status,
	    MFI_CMD_STATUS_POLL_MODE);
	ddi_put16(cmd->frame_dma_obj.acc_handle, &init_frame->flags, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &init_frame->queue_info_new_phys_addr_lo,
	    cmd->frame_phys_addr + 64);
	ddi_put32(cmd->frame_dma_obj.acc_handle,
	    &init_frame->queue_info_new_phys_addr_hi, 0);

	ddi_put32(cmd->frame_dma_obj.acc_handle, &init_frame->data_xfer_len,
	    sizeof (struct mrsas_init_queue_info));

	cmd->frame_count = 1;

	/* issue the init frame in polled mode */
	if (instance->func_ptr->issue_cmd_in_poll_mode(instance, cmd)) {
		con_log(CL_ANN1, (CE_WARN,
		    "mrsas_issue_init_mfi():failed to "
		    "init firmware"));
		return_mfi_app_pkt(instance, cmd);
		return (DDI_FAILURE);
	}

	if (mrsas_common_check(instance, cmd) != DDI_SUCCESS) {
		return_mfi_app_pkt(instance, cmd);
		return (DDI_FAILURE);
	}

	return_mfi_app_pkt(instance, cmd);
	con_log(CL_ANN1, (CE_CONT, "mrsas_issue_init_mfi: Done"));

	return (DDI_SUCCESS);
}
/*
 * mfi_state_transition_to_ready	: Move the FW to READY state
 *
 * @reg_set			: MFI register set
 */
int
mfi_state_transition_to_ready(struct mrsas_instance *instance)
{
	int		i;
	uint8_t		max_wait;
	uint32_t	fw_ctrl = 0;
	uint32_t	fw_state;
	uint32_t	cur_state;
	uint32_t	cur_abs_reg_val;
	uint32_t	prev_abs_reg_val;
	uint32_t	status;

	cur_abs_reg_val =
	    instance->func_ptr->read_fw_status_reg(instance);
	fw_state =
	    cur_abs_reg_val & MFI_STATE_MASK;
	con_log(CL_ANN1, (CE_CONT,
	    "mfi_state_transition_to_ready:FW state = 0x%x", fw_state));

	while (fw_state != MFI_STATE_READY) {
		con_log(CL_ANN, (CE_CONT,
		    "mfi_state_transition_to_ready:FW state%x", fw_state));

		switch (fw_state) {
		case MFI_STATE_FAULT:
			con_log(CL_ANN, (CE_NOTE,
			    "mr_sas: FW in FAULT state!!"));

			return (ENODEV);
		case MFI_STATE_WAIT_HANDSHAKE:
			/* set the CLR bit in IMR0 */
			con_log(CL_ANN1, (CE_NOTE,
			    "mr_sas: FW waiting for HANDSHAKE"));
			/*
			 * PCI_Hot Plug: MFI F/W requires
			 * (MFI_INIT_CLEAR_HANDSHAKE|MFI_INIT_HOTPLUG)
			 * to be set
			 */
			/* WR_IB_MSG_0(MFI_INIT_CLEAR_HANDSHAKE, instance); */
			if (!instance->tbolt && !instance->skinny) {
				WR_IB_DOORBELL(MFI_INIT_CLEAR_HANDSHAKE |
				    MFI_INIT_HOTPLUG, instance);
			} else {
				WR_RESERVED0_REGISTER(MFI_INIT_CLEAR_HANDSHAKE |
				    MFI_INIT_HOTPLUG, instance);
			}
			max_wait	= (instance->tbolt == 1) ? 180 : 2;
			cur_state	= MFI_STATE_WAIT_HANDSHAKE;
			break;
		case MFI_STATE_BOOT_MESSAGE_PENDING:
			/* set the CLR bit in IMR0 */
			con_log(CL_ANN1, (CE_NOTE,
			    "mr_sas: FW state boot message pending"));
			/*
			 * PCI_Hot Plug: MFI F/W requires
			 * (MFI_INIT_CLEAR_HANDSHAKE|MFI_INIT_HOTPLUG)
			 * to be set
			 */
			if (!instance->tbolt && !instance->skinny) {
				WR_IB_DOORBELL(MFI_INIT_HOTPLUG, instance);
			} else {
				WR_RESERVED0_REGISTER(MFI_INIT_HOTPLUG,
				    instance);
			}
			max_wait	= (instance->tbolt == 1) ? 180 : 10;
			cur_state	= MFI_STATE_BOOT_MESSAGE_PENDING;
			break;
		case MFI_STATE_OPERATIONAL:
			/* bring it to READY state; assuming max wait 2 secs */
			instance->func_ptr->disable_intr(instance);
			con_log(CL_ANN1, (CE_NOTE,
			    "mr_sas: FW in OPERATIONAL state"));
			/*
			 * PCI_Hot Plug: MFI F/W requires
			 * (MFI_INIT_READY | MFI_INIT_MFIMODE | MFI_INIT_ABORT)
			 * to be set
			 */
			/* WR_IB_DOORBELL(MFI_INIT_READY, instance); */
			if (!instance->tbolt && !instance->skinny) {
				WR_IB_DOORBELL(MFI_RESET_FLAGS, instance);
			} else {
				WR_RESERVED0_REGISTER(MFI_RESET_FLAGS,
				    instance);

				for (i = 0; i < (10 * 1000); i++) {
					status =
					    RD_RESERVED0_REGISTER(instance);
					if (status & 1) {
						delay(1 *
						    drv_usectohz(MILLISEC));
					} else {
						break;
					}
				}

			}
			max_wait	= (instance->tbolt == 1) ? 180 : 10;
			cur_state	= MFI_STATE_OPERATIONAL;
			break;
		case MFI_STATE_UNDEFINED:
			/* this state should not last for more than 2 seconds */
			con_log(CL_ANN1, (CE_NOTE, "FW state undefined"));

			max_wait	= (instance->tbolt == 1) ? 180 : 2;
			cur_state	= MFI_STATE_UNDEFINED;
			break;
		case MFI_STATE_BB_INIT:
			max_wait	= (instance->tbolt == 1) ? 180 : 2;
			cur_state	= MFI_STATE_BB_INIT;
			break;
		case MFI_STATE_FW_INIT:
			max_wait	= (instance->tbolt == 1) ? 180 : 2;
			cur_state	= MFI_STATE_FW_INIT;
			break;
		case MFI_STATE_FW_INIT_2:
			max_wait	= 180;
			cur_state	= MFI_STATE_FW_INIT_2;
			break;
		case MFI_STATE_DEVICE_SCAN:
			max_wait	= 180;
			cur_state	= MFI_STATE_DEVICE_SCAN;
			prev_abs_reg_val = cur_abs_reg_val;
			con_log(CL_NONE, (CE_NOTE,
			    "Device scan in progress ...\n"));
			break;
		case MFI_STATE_FLUSH_CACHE:
			max_wait	= 180;
			cur_state	= MFI_STATE_FLUSH_CACHE;
			break;
		default:
			con_log(CL_ANN1, (CE_NOTE,
			    "mr_sas: Unknown state 0x%x", fw_state));
			return (ENODEV);
		}

		/* the cur_state should not last for more than max_wait secs */
		for (i = 0; i < (max_wait * MILLISEC); i++) {
			/* fw_state = RD_OB_MSG_0(instance) & MFI_STATE_MASK; */
			cur_abs_reg_val =
			    instance->func_ptr->read_fw_status_reg(instance);
			fw_state = cur_abs_reg_val & MFI_STATE_MASK;

			if (fw_state == cur_state) {
				delay(1 * drv_usectohz(MILLISEC));
			} else {
				break;
			}
		}
		if (fw_state == MFI_STATE_DEVICE_SCAN) {
			if (prev_abs_reg_val != cur_abs_reg_val) {
				continue;
			}
		}

		/* return error if fw_state hasn't changed after max_wait */
		if (fw_state == cur_state) {
			con_log(CL_ANN1, (CE_WARN,
			    "FW state hasn't changed in %d secs", max_wait));
			return (ENODEV);
		}
	};

	/* This may also need to apply to Skinny, but for now, don't worry. */
	if (!instance->tbolt && !instance->skinny) {
		fw_ctrl = RD_IB_DOORBELL(instance);
		con_log(CL_ANN1, (CE_CONT,
		    "mfi_state_transition_to_ready:FW ctrl = 0x%x", fw_ctrl));

		/*
		 * Write 0xF to the doorbell register to do the following.
		 * - Abort all outstanding commands (bit 0).
		 * - Transition from OPERATIONAL to READY state (bit 1).
		 * - Discard (possible) low MFA posted in 64-bit mode (bit-2).
		 * - Set to release FW to continue running (i.e. BIOS handshake
		 *   (bit 3).
		 */
		WR_IB_DOORBELL(0xF, instance);
	}

	if (mrsas_check_acc_handle(instance->regmap_handle) != DDI_SUCCESS) {
		return (EIO);
	}

	return (DDI_SUCCESS);
}

/*
 * get_seq_num
 */
static int
get_seq_num(struct mrsas_instance *instance,
    struct mrsas_evt_log_info *eli)
{
	int	ret = DDI_SUCCESS;

	dma_obj_t			dcmd_dma_obj;
	struct mrsas_cmd		*cmd;
	struct mrsas_dcmd_frame		*dcmd;
	struct mrsas_evt_log_info *eli_tmp;
	if (instance->tbolt) {
		cmd = get_raid_msg_mfi_pkt(instance);
	} else {
		cmd = mrsas_get_mfi_pkt(instance);
	}

	if (!cmd) {
		dev_err(instance->dip, CE_WARN, "failed to get a cmd");
		DTRACE_PROBE2(seq_num_mfi_err, uint16_t,
		    instance->fw_outstanding, uint16_t, instance->max_fw_cmds);
		return (ENOMEM);
	}

	/* Clear the frame buffer and assign back the context id */
	(void) memset((char *)&cmd->frame[0], 0, sizeof (union mrsas_frame));
	ddi_put32(cmd->frame_dma_obj.acc_handle, &cmd->frame->hdr.context,
	    cmd->index);

	dcmd = &cmd->frame->dcmd;

	/* allocate the data transfer buffer */
	dcmd_dma_obj.size = sizeof (struct mrsas_evt_log_info);
	dcmd_dma_obj.dma_attr = mrsas_generic_dma_attr;
	dcmd_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
	dcmd_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
	dcmd_dma_obj.dma_attr.dma_attr_sgllen = 1;
	dcmd_dma_obj.dma_attr.dma_attr_align = 1;

	if (mrsas_alloc_dma_obj(instance, &dcmd_dma_obj,
	    (uchar_t)DDI_STRUCTURE_LE_ACC) != 1) {
		dev_err(instance->dip, CE_WARN,
		    "get_seq_num: could not allocate data transfer buffer.");
		return (DDI_FAILURE);
	}

	(void) memset(dcmd_dma_obj.buffer, 0,
	    sizeof (struct mrsas_evt_log_info));

	(void) memset(dcmd->mbox.b, 0, DCMD_MBOX_SZ);

	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->cmd, MFI_CMD_OP_DCMD);
	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->cmd_status, 0);
	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->sge_count, 1);
	ddi_put16(cmd->frame_dma_obj.acc_handle, &dcmd->flags,
	    MFI_FRAME_DIR_READ);
	ddi_put16(cmd->frame_dma_obj.acc_handle, &dcmd->timeout, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->data_xfer_len,
	    sizeof (struct mrsas_evt_log_info));
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->opcode,
	    MR_DCMD_CTRL_EVENT_GET_INFO);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->sgl.sge32[0].length,
	    sizeof (struct mrsas_evt_log_info));
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->sgl.sge32[0].phys_addr,
	    dcmd_dma_obj.dma_cookie[0].dmac_address);

	cmd->sync_cmd = MRSAS_TRUE;
	cmd->frame_count = 1;

	if (instance->tbolt) {
		mr_sas_tbolt_build_mfi_cmd(instance, cmd);
	}

	if (instance->func_ptr->issue_cmd_in_sync_mode(instance, cmd)) {
		dev_err(instance->dip, CE_WARN, "get_seq_num: "
		    "failed to issue MRSAS_DCMD_CTRL_EVENT_GET_INFO");
		ret = DDI_FAILURE;
	} else {
		eli_tmp = (struct mrsas_evt_log_info *)dcmd_dma_obj.buffer;
		eli->newest_seq_num = ddi_get32(cmd->frame_dma_obj.acc_handle,
		    &eli_tmp->newest_seq_num);
		ret = DDI_SUCCESS;
	}

	if (mrsas_free_dma_obj(instance, dcmd_dma_obj) != DDI_SUCCESS)
		ret = DDI_FAILURE;

	if (instance->tbolt) {
		return_raid_msg_mfi_pkt(instance, cmd);
	} else {
		mrsas_return_mfi_pkt(instance, cmd);
	}

	return (ret);
}

/*
 * start_mfi_aen
 */
static int
start_mfi_aen(struct mrsas_instance *instance)
{
	int	ret = 0;

	struct mrsas_evt_log_info	eli;
	union mrsas_evt_class_locale	class_locale;

	/* get the latest sequence number from FW */
	(void) memset(&eli, 0, sizeof (struct mrsas_evt_log_info));

	if (get_seq_num(instance, &eli)) {
		dev_err(instance->dip, CE_WARN,
		    "start_mfi_aen: failed to get seq num");
		return (-1);
	}

	/* register AEN with FW for latest sequence number plus 1 */
	class_locale.members.reserved	= 0;
	class_locale.members.locale	= LE_16(MR_EVT_LOCALE_ALL);
	class_locale.members.class	= MR_EVT_CLASS_INFO;
	class_locale.word	= LE_32(class_locale.word);
	ret = register_mfi_aen(instance, eli.newest_seq_num + 1,
	    class_locale.word);

	if (ret) {
		dev_err(instance->dip, CE_WARN,
		    "start_mfi_aen: aen registration failed");
		return (-1);
	}


	return (ret);
}

/*
 * flush_cache
 */
static void
flush_cache(struct mrsas_instance *instance)
{
	struct mrsas_cmd		*cmd = NULL;
	struct mrsas_dcmd_frame		*dcmd;
	if (instance->tbolt) {
		cmd = get_raid_msg_mfi_pkt(instance);
	} else {
		cmd = mrsas_get_mfi_pkt(instance);
	}

	if (!cmd) {
		con_log(CL_ANN1, (CE_WARN,
		    "flush_cache():Failed to get a cmd for flush_cache"));
		DTRACE_PROBE2(flush_cache_err, uint16_t,
		    instance->fw_outstanding, uint16_t, instance->max_fw_cmds);
		return;
	}

	/* Clear the frame buffer and assign back the context id */
	(void) memset((char *)&cmd->frame[0], 0, sizeof (union mrsas_frame));
	ddi_put32(cmd->frame_dma_obj.acc_handle, &cmd->frame->hdr.context,
	    cmd->index);

	dcmd = &cmd->frame->dcmd;

	(void) memset(dcmd->mbox.b, 0, DCMD_MBOX_SZ);

	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->cmd, MFI_CMD_OP_DCMD);
	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->cmd_status, 0x0);
	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->sge_count, 0);
	ddi_put16(cmd->frame_dma_obj.acc_handle, &dcmd->flags,
	    MFI_FRAME_DIR_NONE);
	ddi_put16(cmd->frame_dma_obj.acc_handle, &dcmd->timeout, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->data_xfer_len, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->opcode,
	    MR_DCMD_CTRL_CACHE_FLUSH);
	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->mbox.b[0],
	    MR_FLUSH_CTRL_CACHE | MR_FLUSH_DISK_CACHE);

	cmd->frame_count = 1;

	if (instance->tbolt) {
		mr_sas_tbolt_build_mfi_cmd(instance, cmd);
	}

	if (instance->func_ptr->issue_cmd_in_poll_mode(instance, cmd)) {
		con_log(CL_ANN1, (CE_WARN,
	    "flush_cache: failed to issue MFI_DCMD_CTRL_CACHE_FLUSH"));
	}
	con_log(CL_ANN1, (CE_CONT, "flush_cache done"));
	if (instance->tbolt) {
		return_raid_msg_mfi_pkt(instance, cmd);
	} else {
		mrsas_return_mfi_pkt(instance, cmd);
	}

}

/*
 * service_mfi_aen-	Completes an AEN command
 * @instance:			Adapter soft state
 * @cmd:			Command to be completed
 *
 */
void
service_mfi_aen(struct mrsas_instance *instance, struct mrsas_cmd *cmd)
{
	uint32_t	seq_num;
	struct mrsas_evt_detail *evt_detail =
	    (struct mrsas_evt_detail *)instance->mfi_evt_detail_obj.buffer;
	int		rval = 0;
	int		tgt = 0;
	uint8_t		dtype;
	mrsas_pd_address_t	*pd_addr;
	ddi_acc_handle_t		acc_handle;

	con_log(CL_ANN, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	acc_handle = cmd->frame_dma_obj.acc_handle;
	cmd->cmd_status = ddi_get8(acc_handle, &cmd->frame->io.cmd_status);
	if (cmd->cmd_status == ENODATA) {
		cmd->cmd_status = 0;
	}

	/*
	 * log the MFI AEN event to the sysevent queue so that
	 * application will get noticed
	 */
	if (ddi_log_sysevent(instance->dip, DDI_VENDOR_LSI, "LSIMEGA", "SAS",
	    NULL, NULL, DDI_NOSLEEP) != DDI_SUCCESS) {
		int	instance_no = ddi_get_instance(instance->dip);
		con_log(CL_ANN, (CE_WARN,
		    "mr_sas%d: Failed to log AEN event", instance_no));
	}
	/*
	 * Check for any ld devices that has changed state. i.e. online
	 * or offline.
	 */
	con_log(CL_ANN1, (CE_CONT,
	    "AEN: code = %x class = %x locale = %x args = %x",
	    ddi_get32(acc_handle, &evt_detail->code),
	    evt_detail->cl.members.class,
	    ddi_get16(acc_handle, &evt_detail->cl.members.locale),
	    ddi_get8(acc_handle, &evt_detail->arg_type)));

	switch (ddi_get32(acc_handle, &evt_detail->code)) {
	case MR_EVT_CFG_CLEARED: {
		for (tgt = 0; tgt < MRDRV_MAX_LD; tgt++) {
			if (instance->mr_ld_list[tgt].dip != NULL) {
				mutex_enter(&instance->config_dev_mtx);
				instance->mr_ld_list[tgt].flag =
				    (uint8_t)~MRDRV_TGT_VALID;
				mutex_exit(&instance->config_dev_mtx);
				rval = mrsas_service_evt(instance, tgt, 0,
				    MRSAS_EVT_UNCONFIG_TGT, NULL);
				con_log(CL_ANN1, (CE_WARN,
				    "mr_sas: CFG CLEARED AEN rval = %d "
				    "tgt id = %d", rval, tgt));
			}
		}
		break;
	}

	case MR_EVT_LD_DELETED: {
		tgt = ddi_get16(acc_handle, &evt_detail->args.ld.target_id);
		mutex_enter(&instance->config_dev_mtx);
		instance->mr_ld_list[tgt].flag = (uint8_t)~MRDRV_TGT_VALID;
		mutex_exit(&instance->config_dev_mtx);
		rval = mrsas_service_evt(instance,
		    ddi_get16(acc_handle, &evt_detail->args.ld.target_id), 0,
		    MRSAS_EVT_UNCONFIG_TGT, NULL);
		con_log(CL_ANN1, (CE_WARN, "mr_sas: LD DELETED AEN rval = %d "
		    "tgt id = %d index = %d", rval,
		    ddi_get16(acc_handle, &evt_detail->args.ld.target_id),
		    ddi_get8(acc_handle, &evt_detail->args.ld.ld_index)));
		break;
	} /* End of MR_EVT_LD_DELETED */

	case MR_EVT_LD_CREATED: {
		rval = mrsas_service_evt(instance,
		    ddi_get16(acc_handle, &evt_detail->args.ld.target_id), 0,
		    MRSAS_EVT_CONFIG_TGT, NULL);
		con_log(CL_ANN1, (CE_WARN, "mr_sas: LD CREATED AEN rval = %d "
		    "tgt id = %d index = %d", rval,
		    ddi_get16(acc_handle, &evt_detail->args.ld.target_id),
		    ddi_get8(acc_handle, &evt_detail->args.ld.ld_index)));
		break;
	} /* End of MR_EVT_LD_CREATED */

	case MR_EVT_PD_REMOVED_EXT: {
		if (instance->tbolt || instance->skinny) {
			pd_addr = &evt_detail->args.pd_addr;
			dtype = pd_addr->scsi_dev_type;
			con_log(CL_DLEVEL1, (CE_NOTE,
			    " MR_EVT_PD_REMOVED_EXT: dtype = %x,"
			    " arg_type = %d ", dtype, evt_detail->arg_type));
			tgt = ddi_get16(acc_handle,
			    &evt_detail->args.pd.device_id);
			mutex_enter(&instance->config_dev_mtx);
			instance->mr_tbolt_pd_list[tgt].flag =
			    (uint8_t)~MRDRV_TGT_VALID;
			mutex_exit(&instance->config_dev_mtx);
			rval = mrsas_service_evt(instance, ddi_get16(
			    acc_handle, &evt_detail->args.pd.device_id),
			    1, MRSAS_EVT_UNCONFIG_TGT, NULL);
			con_log(CL_ANN1, (CE_WARN, "mr_sas: PD_REMOVED:"
			    "rval = %d tgt id = %d ", rval,
			    ddi_get16(acc_handle,
			    &evt_detail->args.pd.device_id)));
		}
		break;
	} /* End of MR_EVT_PD_REMOVED_EXT */

	case MR_EVT_PD_INSERTED_EXT: {
		if (instance->tbolt || instance->skinny) {
			rval = mrsas_service_evt(instance,
			    ddi_get16(acc_handle,
			    &evt_detail->args.pd.device_id),
			    1, MRSAS_EVT_CONFIG_TGT, NULL);
			con_log(CL_ANN1, (CE_WARN, "mr_sas: PD_INSERTEDi_EXT:"
			    "rval = %d tgt id = %d ", rval,
			    ddi_get16(acc_handle,
			    &evt_detail->args.pd.device_id)));
		}
		break;
	} /* End of MR_EVT_PD_INSERTED_EXT */

	case MR_EVT_PD_STATE_CHANGE: {
		if (instance->tbolt || instance->skinny) {
			tgt = ddi_get16(acc_handle,
			    &evt_detail->args.pd.device_id);
			if ((evt_detail->args.pd_state.prevState ==
			    PD_SYSTEM) &&
			    (evt_detail->args.pd_state.newState != PD_SYSTEM)) {
				mutex_enter(&instance->config_dev_mtx);
				instance->mr_tbolt_pd_list[tgt].flag =
				    (uint8_t)~MRDRV_TGT_VALID;
				mutex_exit(&instance->config_dev_mtx);
				rval = mrsas_service_evt(instance,
				    ddi_get16(acc_handle,
				    &evt_detail->args.pd.device_id),
				    1, MRSAS_EVT_UNCONFIG_TGT, NULL);
				con_log(CL_ANN1, (CE_WARN, "mr_sas: PD_REMOVED:"
				    "rval = %d tgt id = %d ", rval,
				    ddi_get16(acc_handle,
				    &evt_detail->args.pd.device_id)));
				break;
			}
			if ((evt_detail->args.pd_state.prevState
			    == UNCONFIGURED_GOOD) &&
			    (evt_detail->args.pd_state.newState == PD_SYSTEM)) {
				rval = mrsas_service_evt(instance,
				    ddi_get16(acc_handle,
				    &evt_detail->args.pd.device_id),
				    1, MRSAS_EVT_CONFIG_TGT, NULL);
				con_log(CL_ANN1, (CE_WARN,
				    "mr_sas: PD_INSERTED: rval = %d "
				    " tgt id = %d ", rval,
				    ddi_get16(acc_handle,
				    &evt_detail->args.pd.device_id)));
				break;
			}
		}
		break;
	}

	} /* End of Main Switch */

	/* get copy of seq_num and class/locale for re-registration */
	seq_num = ddi_get32(acc_handle, &evt_detail->seq_num);
	seq_num++;
	(void) memset(instance->mfi_evt_detail_obj.buffer, 0,
	    sizeof (struct mrsas_evt_detail));

	ddi_put8(acc_handle, &cmd->frame->dcmd.cmd_status, 0x0);
	ddi_put32(acc_handle, &cmd->frame->dcmd.mbox.w[0], seq_num);

	instance->aen_seq_num = seq_num;

	cmd->frame_count = 1;

	cmd->retry_count_for_ocr = 0;
	cmd->drv_pkt_time = 0;

	/* Issue the aen registration frame */
	instance->func_ptr->issue_cmd(cmd, instance);
}

/*
 * complete_cmd_in_sync_mode -	Completes an internal command
 * @instance:			Adapter soft state
 * @cmd:			Command to be completed
 *
 * The issue_cmd_in_sync_mode() function waits for a command to complete
 * after it issues a command. This function wakes up that waiting routine by
 * calling wake_up() on the wait queue.
 */
static void
complete_cmd_in_sync_mode(struct mrsas_instance *instance,
    struct mrsas_cmd *cmd)
{
	cmd->cmd_status = ddi_get8(cmd->frame_dma_obj.acc_handle,
	    &cmd->frame->io.cmd_status);

	cmd->sync_cmd = MRSAS_FALSE;

	con_log(CL_ANN1, (CE_NOTE, "complete_cmd_in_sync_mode called %p \n",
	    (void *)cmd));

	mutex_enter(&instance->int_cmd_mtx);
	if (cmd->cmd_status == ENODATA) {
		cmd->cmd_status = 0;
	}
	cv_broadcast(&instance->int_cmd_cv);
	mutex_exit(&instance->int_cmd_mtx);

}

/*
 * Call this function inside mrsas_softintr.
 * mrsas_initiate_ocr_if_fw_is_faulty  - Initiates OCR if FW status is faulty
 * @instance:			Adapter soft state
 */

static uint32_t
mrsas_initiate_ocr_if_fw_is_faulty(struct mrsas_instance *instance)
{
	uint32_t	cur_abs_reg_val;
	uint32_t	fw_state;

	cur_abs_reg_val =  instance->func_ptr->read_fw_status_reg(instance);
	fw_state = cur_abs_reg_val & MFI_STATE_MASK;
	if (fw_state == MFI_STATE_FAULT) {
		if (instance->disable_online_ctrl_reset == 1) {
			dev_err(instance->dip, CE_WARN,
			    "mrsas_initiate_ocr_if_fw_is_faulty: "
			    "FW in Fault state, detected in ISR: "
			    "FW doesn't support ocr ");

			return (ADAPTER_RESET_NOT_REQUIRED);
		} else {
			con_log(CL_ANN, (CE_NOTE,
			    "mrsas_initiate_ocr_if_fw_is_faulty: FW in Fault "
			    "state, detected in ISR: FW supports ocr "));

			return (ADAPTER_RESET_REQUIRED);
		}
	}

	return (ADAPTER_RESET_NOT_REQUIRED);
}

/*
 * mrsas_softintr - The Software ISR
 * @param arg	: HBA soft state
 *
 * called from high-level interrupt if hi-level interrupt are not there,
 * otherwise triggered as a soft interrupt
 */
static uint_t
mrsas_softintr(struct mrsas_instance *instance)
{
	struct scsi_pkt		*pkt;
	struct scsa_cmd		*acmd;
	struct mrsas_cmd	*cmd;
	struct mlist_head	*pos, *next;
	mlist_t			process_list;
	struct mrsas_header	*hdr;
	struct scsi_arq_status	*arqstat;

	con_log(CL_ANN1, (CE_NOTE, "mrsas_softintr() called."));

	ASSERT(instance);

	mutex_enter(&instance->completed_pool_mtx);

	if (mlist_empty(&instance->completed_pool_list)) {
		mutex_exit(&instance->completed_pool_mtx);
		return (DDI_INTR_CLAIMED);
	}

	instance->softint_running = 1;

	INIT_LIST_HEAD(&process_list);
	mlist_splice(&instance->completed_pool_list, &process_list);
	INIT_LIST_HEAD(&instance->completed_pool_list);

	mutex_exit(&instance->completed_pool_mtx);

	/* perform all callbacks first, before releasing the SCBs */
	mlist_for_each_safe(pos, next, &process_list) {
		cmd = mlist_entry(pos, struct mrsas_cmd, list);

		/* syncronize the Cmd frame for the controller */
		(void) ddi_dma_sync(cmd->frame_dma_obj.dma_handle,
		    0, 0, DDI_DMA_SYNC_FORCPU);

		if (mrsas_check_dma_handle(cmd->frame_dma_obj.dma_handle) !=
		    DDI_SUCCESS) {
			mrsas_fm_ereport(instance, DDI_FM_DEVICE_NO_RESPONSE);
			ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);
			con_log(CL_ANN1, (CE_WARN,
			    "mrsas_softintr: "
			    "FMA check reports DMA handle failure"));
			return (DDI_INTR_CLAIMED);
		}

		hdr = &cmd->frame->hdr;

		/* remove the internal command from the process list */
		mlist_del_init(&cmd->list);

		switch (ddi_get8(cmd->frame_dma_obj.acc_handle, &hdr->cmd)) {
		case MFI_CMD_OP_PD_SCSI:
		case MFI_CMD_OP_LD_SCSI:
		case MFI_CMD_OP_LD_READ:
		case MFI_CMD_OP_LD_WRITE:
			/*
			 * MFI_CMD_OP_PD_SCSI and MFI_CMD_OP_LD_SCSI
			 * could have been issued either through an
			 * IO path or an IOCTL path. If it was via IOCTL,
			 * we will send it to internal completion.
			 */
			if (cmd->sync_cmd == MRSAS_TRUE) {
				complete_cmd_in_sync_mode(instance, cmd);
				break;
			}

			/* regular commands */
			acmd =	cmd->cmd;
			pkt =	CMD2PKT(acmd);

			if (acmd->cmd_flags & CFLAG_DMAVALID) {
				if (acmd->cmd_flags & CFLAG_CONSISTENT) {
					(void) ddi_dma_sync(acmd->cmd_dmahandle,
					    acmd->cmd_dma_offset,
					    acmd->cmd_dma_len,
					    DDI_DMA_SYNC_FORCPU);
				}
			}

			pkt->pkt_reason		= CMD_CMPLT;
			pkt->pkt_statistics	= 0;
			pkt->pkt_state = STATE_GOT_BUS
			    | STATE_GOT_TARGET | STATE_SENT_CMD
			    | STATE_XFERRED_DATA | STATE_GOT_STATUS;

			con_log(CL_ANN, (CE_CONT,
			    "CDB[0] = %x completed for %s: size %lx context %x",
			    pkt->pkt_cdbp[0], ((acmd->islogical) ? "LD" : "PD"),
			    acmd->cmd_dmacount, hdr->context));
			DTRACE_PROBE3(softintr_cdb, uint8_t, pkt->pkt_cdbp[0],
			    uint_t, acmd->cmd_cdblen, ulong_t,
			    acmd->cmd_dmacount);

			if (pkt->pkt_cdbp[0] == SCMD_INQUIRY) {
				struct scsi_inquiry	*inq;

				if (acmd->cmd_dmacount != 0) {
					bp_mapin(acmd->cmd_buf);
					inq = (struct scsi_inquiry *)
					    acmd->cmd_buf->b_un.b_addr;

					if (hdr->cmd_status == MFI_STAT_OK) {
						display_scsi_inquiry(
						    (caddr_t)inq);
					}
				}
			}

			DTRACE_PROBE2(softintr_done, uint8_t, hdr->cmd,
			    uint8_t, hdr->cmd_status);

			switch (hdr->cmd_status) {
			case MFI_STAT_OK:
				pkt->pkt_scbp[0] = STATUS_GOOD;
				break;
			case MFI_STAT_LD_CC_IN_PROGRESS:
			case MFI_STAT_LD_RECON_IN_PROGRESS:
				pkt->pkt_scbp[0] = STATUS_GOOD;
				break;
			case MFI_STAT_LD_INIT_IN_PROGRESS:
				con_log(CL_ANN,
				    (CE_WARN, "Initialization in Progress"));
				pkt->pkt_reason	= CMD_TRAN_ERR;

				break;
			case MFI_STAT_SCSI_DONE_WITH_ERROR:
				con_log(CL_ANN, (CE_CONT, "scsi_done error"));

				pkt->pkt_reason	= CMD_CMPLT;
				((struct scsi_status *)
				    pkt->pkt_scbp)->sts_chk = 1;

				if (pkt->pkt_cdbp[0] == SCMD_TEST_UNIT_READY) {
					con_log(CL_ANN,
					    (CE_WARN, "TEST_UNIT_READY fail"));
				} else {
					pkt->pkt_state |= STATE_ARQ_DONE;
					arqstat = (void *)(pkt->pkt_scbp);
					arqstat->sts_rqpkt_reason = CMD_CMPLT;
					arqstat->sts_rqpkt_resid = 0;
					arqstat->sts_rqpkt_state |=
					    STATE_GOT_BUS | STATE_GOT_TARGET
					    | STATE_SENT_CMD
					    | STATE_XFERRED_DATA;
					*(uint8_t *)&arqstat->sts_rqpkt_status =
					    STATUS_GOOD;
					ddi_rep_get8(
					    cmd->frame_dma_obj.acc_handle,
					    (uint8_t *)
					    &(arqstat->sts_sensedata),
					    cmd->sense,
					    sizeof (struct scsi_extended_sense),
					    DDI_DEV_AUTOINCR);
				}
				break;
			case MFI_STAT_LD_OFFLINE:
			case MFI_STAT_DEVICE_NOT_FOUND:
				con_log(CL_ANN, (CE_CONT,
				"mrsas_softintr:device not found error"));
				pkt->pkt_reason	= CMD_DEV_GONE;
				pkt->pkt_statistics  = STAT_DISCON;
				break;
			case MFI_STAT_LD_LBA_OUT_OF_RANGE:
				pkt->pkt_state |= STATE_ARQ_DONE;
				pkt->pkt_reason	= CMD_CMPLT;
				((struct scsi_status *)
				    pkt->pkt_scbp)->sts_chk = 1;

				arqstat = (void *)(pkt->pkt_scbp);
				arqstat->sts_rqpkt_reason = CMD_CMPLT;
				arqstat->sts_rqpkt_resid = 0;
				arqstat->sts_rqpkt_state |= STATE_GOT_BUS
				    | STATE_GOT_TARGET | STATE_SENT_CMD
				    | STATE_XFERRED_DATA;
				*(uint8_t *)&arqstat->sts_rqpkt_status =
				    STATUS_GOOD;

				arqstat->sts_sensedata.es_valid = 1;
				arqstat->sts_sensedata.es_key =
				    KEY_ILLEGAL_REQUEST;
				arqstat->sts_sensedata.es_class =
				    CLASS_EXTENDED_SENSE;

				/*
				 * LOGICAL BLOCK ADDRESS OUT OF RANGE:
				 * ASC: 0x21h; ASCQ: 0x00h;
				 */
				arqstat->sts_sensedata.es_add_code = 0x21;
				arqstat->sts_sensedata.es_qual_code = 0x00;

				break;

			default:
				con_log(CL_ANN, (CE_CONT, "Unknown status!"));
				pkt->pkt_reason	= CMD_TRAN_ERR;

				break;
			}

			atomic_add_16(&instance->fw_outstanding, (-1));

			(void) mrsas_common_check(instance, cmd);

			if (acmd->cmd_dmahandle) {
				if (mrsas_check_dma_handle(
				    acmd->cmd_dmahandle) != DDI_SUCCESS) {
					ddi_fm_service_impact(instance->dip,
					    DDI_SERVICE_UNAFFECTED);
					pkt->pkt_reason = CMD_TRAN_ERR;
					pkt->pkt_statistics = 0;
				}
			}

			mrsas_return_mfi_pkt(instance, cmd);

			/* Call the callback routine */
			if (((pkt->pkt_flags & FLAG_NOINTR) == 0) &&
			    pkt->pkt_comp) {
				(*pkt->pkt_comp)(pkt);
			}

			break;

		case MFI_CMD_OP_SMP:
		case MFI_CMD_OP_STP:
			complete_cmd_in_sync_mode(instance, cmd);
			break;

		case MFI_CMD_OP_DCMD:
			/* see if got an event notification */
			if (ddi_get32(cmd->frame_dma_obj.acc_handle,
			    &cmd->frame->dcmd.opcode) ==
			    MR_DCMD_CTRL_EVENT_WAIT) {
				if ((instance->aen_cmd == cmd) &&
				    (instance->aen_cmd->abort_aen)) {
					con_log(CL_ANN, (CE_WARN,
					    "mrsas_softintr: "
					    "aborted_aen returned"));
				} else {
					atomic_add_16(&instance->fw_outstanding,
					    (-1));
					service_mfi_aen(instance, cmd);
				}
			} else {
				complete_cmd_in_sync_mode(instance, cmd);
			}

			break;

		case MFI_CMD_OP_ABORT:
			con_log(CL_ANN, (CE_NOTE, "MFI_CMD_OP_ABORT complete"));
			/*
			 * MFI_CMD_OP_ABORT successfully completed
			 * in the synchronous mode
			 */
			complete_cmd_in_sync_mode(instance, cmd);
			break;

		default:
			mrsas_fm_ereport(instance, DDI_FM_DEVICE_NO_RESPONSE);
			ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);

			if (cmd->pkt != NULL) {
				pkt = cmd->pkt;
				if (((pkt->pkt_flags & FLAG_NOINTR) == 0) &&
				    pkt->pkt_comp) {

					con_log(CL_ANN1, (CE_CONT, "posting to "
					    "scsa cmd %p index %x pkt %p"
					    "time %llx, default ", (void *)cmd,
					    cmd->index, (void *)pkt,
					    gethrtime()));

					(*pkt->pkt_comp)(pkt);

				}
			}
			con_log(CL_ANN, (CE_WARN, "Cmd type unknown !"));
			break;
		}
	}

	instance->softint_running = 0;

	return (DDI_INTR_CLAIMED);
}

/*
 * mrsas_alloc_dma_obj
 *
 * Allocate the memory and other resources for an dma object.
 */
int
mrsas_alloc_dma_obj(struct mrsas_instance *instance, dma_obj_t *obj,
    uchar_t endian_flags)
{
	int	i;
	size_t	alen = 0;
	uint_t	cookie_cnt;
	struct ddi_device_acc_attr tmp_endian_attr;

	tmp_endian_attr = endian_attr;
	tmp_endian_attr.devacc_attr_endian_flags = endian_flags;
	tmp_endian_attr.devacc_attr_access = DDI_DEFAULT_ACC;

	i = ddi_dma_alloc_handle(instance->dip, &obj->dma_attr,
	    DDI_DMA_SLEEP, NULL, &obj->dma_handle);
	if (i != DDI_SUCCESS) {

		switch (i) {
			case DDI_DMA_BADATTR :
				con_log(CL_ANN, (CE_WARN,
				"Failed ddi_dma_alloc_handle- Bad attribute"));
				break;
			case DDI_DMA_NORESOURCES :
				con_log(CL_ANN, (CE_WARN,
				"Failed ddi_dma_alloc_handle- No Resources"));
				break;
			default :
				con_log(CL_ANN, (CE_WARN,
				"Failed ddi_dma_alloc_handle: "
				"unknown status %d", i));
				break;
		}

		return (-1);
	}

	if ((ddi_dma_mem_alloc(obj->dma_handle, obj->size, &tmp_endian_attr,
	    DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
	    &obj->buffer, &alen, &obj->acc_handle) != DDI_SUCCESS) ||
	    alen < obj->size) {

		ddi_dma_free_handle(&obj->dma_handle);

		con_log(CL_ANN, (CE_WARN, "Failed : ddi_dma_mem_alloc"));

		return (-1);
	}

	if (ddi_dma_addr_bind_handle(obj->dma_handle, NULL, obj->buffer,
	    obj->size, DDI_DMA_RDWR | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &obj->dma_cookie[0], &cookie_cnt) != DDI_SUCCESS) {

		ddi_dma_mem_free(&obj->acc_handle);
		ddi_dma_free_handle(&obj->dma_handle);

		con_log(CL_ANN, (CE_WARN, "Failed : ddi_dma_addr_bind_handle"));

		return (-1);
	}

	if (mrsas_check_dma_handle(obj->dma_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);
		return (-1);
	}

	if (mrsas_check_acc_handle(obj->acc_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);
		return (-1);
	}

	return (cookie_cnt);
}

/*
 * mrsas_free_dma_obj(struct mrsas_instance *, dma_obj_t)
 *
 * De-allocate the memory and other resources for an dma object, which must
 * have been alloated by a previous call to mrsas_alloc_dma_obj()
 */
int
mrsas_free_dma_obj(struct mrsas_instance *instance, dma_obj_t obj)
{

	if ((obj.dma_handle == NULL) || (obj.acc_handle == NULL)) {
		return (DDI_SUCCESS);
	}

	/*
	 * NOTE: These check-handle functions fail if *_handle == NULL, but
	 * this function succeeds because of the previous check.
	 */
	if (mrsas_check_dma_handle(obj.dma_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_UNAFFECTED);
		return (DDI_FAILURE);
	}

	if (mrsas_check_acc_handle(obj.acc_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_UNAFFECTED);
		return (DDI_FAILURE);
	}

	(void) ddi_dma_unbind_handle(obj.dma_handle);
	ddi_dma_mem_free(&obj.acc_handle);
	ddi_dma_free_handle(&obj.dma_handle);
	obj.acc_handle = NULL;
	return (DDI_SUCCESS);
}

/*
 * mrsas_dma_alloc(instance_t *, struct scsi_pkt *, struct buf *,
 * int, int (*)())
 *
 * Allocate dma resources for a new scsi command
 */
int
mrsas_dma_alloc(struct mrsas_instance *instance, struct scsi_pkt *pkt,
    struct buf *bp, int flags, int (*callback)())
{
	int	dma_flags;
	int	(*cb)(caddr_t);
	int	i;

	ddi_dma_attr_t	tmp_dma_attr = mrsas_generic_dma_attr;
	struct scsa_cmd	*acmd = PKT2CMD(pkt);

	acmd->cmd_buf = bp;

	if (bp->b_flags & B_READ) {
		acmd->cmd_flags &= ~CFLAG_DMASEND;
		dma_flags = DDI_DMA_READ;
	} else {
		acmd->cmd_flags |= CFLAG_DMASEND;
		dma_flags = DDI_DMA_WRITE;
	}

	if (flags & PKT_CONSISTENT) {
		acmd->cmd_flags |= CFLAG_CONSISTENT;
		dma_flags |= DDI_DMA_CONSISTENT;
	}

	if (flags & PKT_DMA_PARTIAL) {
		dma_flags |= DDI_DMA_PARTIAL;
	}

	dma_flags |= DDI_DMA_REDZONE;

	cb = (callback == NULL_FUNC) ? DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

	tmp_dma_attr.dma_attr_sgllen = instance->max_num_sge;
	tmp_dma_attr.dma_attr_addr_hi = 0xffffffffffffffffull;
	if (instance->tbolt) {
		/* OCR-RESET FIX */
		tmp_dma_attr.dma_attr_count_max =
		    (U64)mrsas_tbolt_max_cap_maxxfer;  /* limit to 256K */
		tmp_dma_attr.dma_attr_maxxfer =
		    (U64)mrsas_tbolt_max_cap_maxxfer;  /* limit to 256K */
	}

	if ((i = ddi_dma_alloc_handle(instance->dip, &tmp_dma_attr,
	    cb, 0, &acmd->cmd_dmahandle)) != DDI_SUCCESS) {
		switch (i) {
		case DDI_DMA_BADATTR:
			bioerror(bp, EFAULT);
			return (DDI_FAILURE);

		case DDI_DMA_NORESOURCES:
			bioerror(bp, 0);
			return (DDI_FAILURE);

		default:
			con_log(CL_ANN, (CE_PANIC, "ddi_dma_alloc_handle: "
			    "impossible result (0x%x)", i));
			bioerror(bp, EFAULT);
			return (DDI_FAILURE);
		}
	}

	i = ddi_dma_buf_bind_handle(acmd->cmd_dmahandle, bp, dma_flags,
	    cb, 0, &acmd->cmd_dmacookies[0], &acmd->cmd_ncookies);

	switch (i) {
	case DDI_DMA_PARTIAL_MAP:
		if ((dma_flags & DDI_DMA_PARTIAL) == 0) {
			con_log(CL_ANN, (CE_PANIC, "ddi_dma_buf_bind_handle: "
			    "DDI_DMA_PARTIAL_MAP impossible"));
			goto no_dma_cookies;
		}

		if (ddi_dma_numwin(acmd->cmd_dmahandle, &acmd->cmd_nwin) ==
		    DDI_FAILURE) {
			con_log(CL_ANN, (CE_PANIC, "ddi_dma_numwin failed"));
			goto no_dma_cookies;
		}

		if (ddi_dma_getwin(acmd->cmd_dmahandle, acmd->cmd_curwin,
		    &acmd->cmd_dma_offset, &acmd->cmd_dma_len,
		    &acmd->cmd_dmacookies[0], &acmd->cmd_ncookies) ==
		    DDI_FAILURE) {

			con_log(CL_ANN, (CE_PANIC, "ddi_dma_getwin failed"));
			goto no_dma_cookies;
		}

		goto get_dma_cookies;
	case DDI_DMA_MAPPED:
		acmd->cmd_nwin = 1;
		acmd->cmd_dma_len = 0;
		acmd->cmd_dma_offset = 0;

get_dma_cookies:
		i = 0;
		acmd->cmd_dmacount = 0;
		for (;;) {
			acmd->cmd_dmacount +=
			    acmd->cmd_dmacookies[i++].dmac_size;

			if (i == instance->max_num_sge ||
			    i == acmd->cmd_ncookies)
				break;

			ddi_dma_nextcookie(acmd->cmd_dmahandle,
			    &acmd->cmd_dmacookies[i]);
		}

		acmd->cmd_cookie = i;
		acmd->cmd_cookiecnt = i;

		acmd->cmd_flags |= CFLAG_DMAVALID;

		if (bp->b_bcount >= acmd->cmd_dmacount) {
			pkt->pkt_resid = bp->b_bcount - acmd->cmd_dmacount;
		} else {
			pkt->pkt_resid = 0;
		}

		return (DDI_SUCCESS);
	case DDI_DMA_NORESOURCES:
		bioerror(bp, 0);
		break;
	case DDI_DMA_NOMAPPING:
		bioerror(bp, EFAULT);
		break;
	case DDI_DMA_TOOBIG:
		bioerror(bp, EINVAL);
		break;
	case DDI_DMA_INUSE:
		con_log(CL_ANN, (CE_PANIC, "ddi_dma_buf_bind_handle:"
		    " DDI_DMA_INUSE impossible"));
		break;
	default:
		con_log(CL_ANN, (CE_PANIC, "ddi_dma_buf_bind_handle: "
		    "impossible result (0x%x)", i));
		break;
	}

no_dma_cookies:
	ddi_dma_free_handle(&acmd->cmd_dmahandle);
	acmd->cmd_dmahandle = NULL;
	acmd->cmd_flags &= ~CFLAG_DMAVALID;
	return (DDI_FAILURE);
}

/*
 * mrsas_dma_move(struct mrsas_instance *, struct scsi_pkt *, struct buf *)
 *
 * move dma resources to next dma window
 *
 */
int
mrsas_dma_move(struct mrsas_instance *instance, struct scsi_pkt *pkt,
    struct buf *bp)
{
	int	i = 0;

	struct scsa_cmd	*acmd = PKT2CMD(pkt);

	/*
	 * If there are no more cookies remaining in this window,
	 * must move to the next window first.
	 */
	if (acmd->cmd_cookie == acmd->cmd_ncookies) {
		if (acmd->cmd_curwin == acmd->cmd_nwin && acmd->cmd_nwin == 1) {
			return (DDI_SUCCESS);
		}

		/* at last window, cannot move */
		if (++acmd->cmd_curwin >= acmd->cmd_nwin) {
			return (DDI_FAILURE);
		}

		if (ddi_dma_getwin(acmd->cmd_dmahandle, acmd->cmd_curwin,
		    &acmd->cmd_dma_offset, &acmd->cmd_dma_len,
		    &acmd->cmd_dmacookies[0], &acmd->cmd_ncookies) ==
		    DDI_FAILURE) {
			return (DDI_FAILURE);
		}

		acmd->cmd_cookie = 0;
	} else {
		/* still more cookies in this window - get the next one */
		ddi_dma_nextcookie(acmd->cmd_dmahandle,
		    &acmd->cmd_dmacookies[0]);
	}

	/* get remaining cookies in this window, up to our maximum */
	for (;;) {
		acmd->cmd_dmacount += acmd->cmd_dmacookies[i++].dmac_size;
		acmd->cmd_cookie++;

		if (i == instance->max_num_sge ||
		    acmd->cmd_cookie == acmd->cmd_ncookies) {
			break;
		}

		ddi_dma_nextcookie(acmd->cmd_dmahandle,
		    &acmd->cmd_dmacookies[i]);
	}

	acmd->cmd_cookiecnt = i;

	if (bp->b_bcount >= acmd->cmd_dmacount) {
		pkt->pkt_resid = bp->b_bcount - acmd->cmd_dmacount;
	} else {
		pkt->pkt_resid = 0;
	}

	return (DDI_SUCCESS);
}

/*
 * build_cmd
 */
static struct mrsas_cmd *
build_cmd(struct mrsas_instance *instance, struct scsi_address *ap,
    struct scsi_pkt *pkt, uchar_t *cmd_done)
{
	uint16_t	flags = 0;
	uint32_t	i;
	uint32_t	context;
	uint32_t	sge_bytes;
	uint32_t	tmp_data_xfer_len;
	ddi_acc_handle_t acc_handle;
	struct mrsas_cmd		*cmd;
	struct mrsas_sge64		*mfi_sgl;
	struct mrsas_sge_ieee		*mfi_sgl_ieee;
	struct scsa_cmd			*acmd = PKT2CMD(pkt);
	struct mrsas_pthru_frame	*pthru;
	struct mrsas_io_frame		*ldio;

	/* find out if this is logical or physical drive command.  */
	acmd->islogical = MRDRV_IS_LOGICAL(ap);
	acmd->device_id = MAP_DEVICE_ID(instance, ap);
	*cmd_done = 0;

	/* get the command packet */
	if (!(cmd = mrsas_get_mfi_pkt(instance))) {
		DTRACE_PROBE2(build_cmd_mfi_err, uint16_t,
		    instance->fw_outstanding, uint16_t, instance->max_fw_cmds);
		return (NULL);
	}

	acc_handle = cmd->frame_dma_obj.acc_handle;

	/* Clear the frame buffer and assign back the context id */
	(void) memset((char *)&cmd->frame[0], 0, sizeof (union mrsas_frame));
	ddi_put32(acc_handle, &cmd->frame->hdr.context, cmd->index);

	cmd->pkt = pkt;
	cmd->cmd = acmd;
	DTRACE_PROBE3(build_cmds, uint8_t, pkt->pkt_cdbp[0],
	    ulong_t, acmd->cmd_dmacount, ulong_t, acmd->cmd_dma_len);

	/* lets get the command directions */
	if (acmd->cmd_flags & CFLAG_DMASEND) {
		flags = MFI_FRAME_DIR_WRITE;

		if (acmd->cmd_flags & CFLAG_CONSISTENT) {
			(void) ddi_dma_sync(acmd->cmd_dmahandle,
			    acmd->cmd_dma_offset, acmd->cmd_dma_len,
			    DDI_DMA_SYNC_FORDEV);
		}
	} else if (acmd->cmd_flags & ~CFLAG_DMASEND) {
		flags = MFI_FRAME_DIR_READ;

		if (acmd->cmd_flags & CFLAG_CONSISTENT) {
			(void) ddi_dma_sync(acmd->cmd_dmahandle,
			    acmd->cmd_dma_offset, acmd->cmd_dma_len,
			    DDI_DMA_SYNC_FORCPU);
		}
	} else {
		flags = MFI_FRAME_DIR_NONE;
	}

	if (instance->flag_ieee) {
		flags |= MFI_FRAME_IEEE;
	}
	flags |= MFI_FRAME_SGL64;

	switch (pkt->pkt_cdbp[0]) {

	/*
	 * case SCMD_SYNCHRONIZE_CACHE:
	 *	flush_cache(instance);
	 *	mrsas_return_mfi_pkt(instance, cmd);
	 *	*cmd_done = 1;
	 *
	 *	return (NULL);
	 */

	case SCMD_READ:
	case SCMD_WRITE:
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
	case SCMD_READ_G4:
	case SCMD_WRITE_G4:
	case SCMD_READ_G5:
	case SCMD_WRITE_G5:
		if (acmd->islogical) {
			ldio = (struct mrsas_io_frame *)cmd->frame;

			/*
			 * preare the Logical IO frame:
			 * 2nd bit is zero for all read cmds
			 */
			ddi_put8(acc_handle, &ldio->cmd,
			    (pkt->pkt_cdbp[0] & 0x02) ? MFI_CMD_OP_LD_WRITE
			    : MFI_CMD_OP_LD_READ);
			ddi_put8(acc_handle, &ldio->cmd_status, 0x0);
			ddi_put8(acc_handle, &ldio->scsi_status, 0x0);
			ddi_put8(acc_handle, &ldio->target_id, acmd->device_id);
			ddi_put16(acc_handle, &ldio->timeout, 0);
			ddi_put8(acc_handle, &ldio->reserved_0, 0);
			ddi_put16(acc_handle, &ldio->pad_0, 0);
			ddi_put16(acc_handle, &ldio->flags, flags);

			/* Initialize sense Information */
			bzero(cmd->sense, SENSE_LENGTH);
			ddi_put8(acc_handle, &ldio->sense_len, SENSE_LENGTH);
			ddi_put32(acc_handle, &ldio->sense_buf_phys_addr_hi, 0);
			ddi_put32(acc_handle, &ldio->sense_buf_phys_addr_lo,
			    cmd->sense_phys_addr);
			ddi_put32(acc_handle, &ldio->start_lba_hi, 0);
			ddi_put8(acc_handle, &ldio->access_byte,
			    (acmd->cmd_cdblen != 6) ? pkt->pkt_cdbp[1] : 0);
			ddi_put8(acc_handle, &ldio->sge_count,
			    acmd->cmd_cookiecnt);
			if (instance->flag_ieee) {
				mfi_sgl_ieee =
				    (struct mrsas_sge_ieee *)&ldio->sgl;
			} else {
				mfi_sgl = (struct mrsas_sge64	*)&ldio->sgl;
			}

			context = ddi_get32(acc_handle, &ldio->context);

			if (acmd->cmd_cdblen == CDB_GROUP0) {
				/* 6-byte cdb */
				ddi_put32(acc_handle, &ldio->lba_count, (
				    (uint16_t)(pkt->pkt_cdbp[4])));

				ddi_put32(acc_handle, &ldio->start_lba_lo, (
				    ((uint32_t)(pkt->pkt_cdbp[3])) |
				    ((uint32_t)(pkt->pkt_cdbp[2]) << 8) |
				    ((uint32_t)((pkt->pkt_cdbp[1]) & 0x1F)
				    << 16)));
			} else if (acmd->cmd_cdblen == CDB_GROUP1) {
				/* 10-byte cdb */
				ddi_put32(acc_handle, &ldio->lba_count, (
				    ((uint16_t)(pkt->pkt_cdbp[8])) |
				    ((uint16_t)(pkt->pkt_cdbp[7]) << 8)));

				ddi_put32(acc_handle, &ldio->start_lba_lo, (
				    ((uint32_t)(pkt->pkt_cdbp[5])) |
				    ((uint32_t)(pkt->pkt_cdbp[4]) << 8) |
				    ((uint32_t)(pkt->pkt_cdbp[3]) << 16) |
				    ((uint32_t)(pkt->pkt_cdbp[2]) << 24)));
			} else if (acmd->cmd_cdblen == CDB_GROUP5) {
				/* 12-byte cdb */
				ddi_put32(acc_handle, &ldio->lba_count, (
				    ((uint32_t)(pkt->pkt_cdbp[9])) |
				    ((uint32_t)(pkt->pkt_cdbp[8]) << 8) |
				    ((uint32_t)(pkt->pkt_cdbp[7]) << 16) |
				    ((uint32_t)(pkt->pkt_cdbp[6]) << 24)));

				ddi_put32(acc_handle, &ldio->start_lba_lo, (
				    ((uint32_t)(pkt->pkt_cdbp[5])) |
				    ((uint32_t)(pkt->pkt_cdbp[4]) << 8) |
				    ((uint32_t)(pkt->pkt_cdbp[3]) << 16) |
				    ((uint32_t)(pkt->pkt_cdbp[2]) << 24)));
			} else if (acmd->cmd_cdblen == CDB_GROUP4) {
				/* 16-byte cdb */
				ddi_put32(acc_handle, &ldio->lba_count, (
				    ((uint32_t)(pkt->pkt_cdbp[13])) |
				    ((uint32_t)(pkt->pkt_cdbp[12]) << 8) |
				    ((uint32_t)(pkt->pkt_cdbp[11]) << 16) |
				    ((uint32_t)(pkt->pkt_cdbp[10]) << 24)));

				ddi_put32(acc_handle, &ldio->start_lba_lo, (
				    ((uint32_t)(pkt->pkt_cdbp[9])) |
				    ((uint32_t)(pkt->pkt_cdbp[8]) << 8) |
				    ((uint32_t)(pkt->pkt_cdbp[7]) << 16) |
				    ((uint32_t)(pkt->pkt_cdbp[6]) << 24)));

				ddi_put32(acc_handle, &ldio->start_lba_hi, (
				    ((uint32_t)(pkt->pkt_cdbp[5])) |
				    ((uint32_t)(pkt->pkt_cdbp[4]) << 8) |
				    ((uint32_t)(pkt->pkt_cdbp[3]) << 16) |
				    ((uint32_t)(pkt->pkt_cdbp[2]) << 24)));
			}

			break;
		}
		/* fall through For all non-rd/wr and physical disk cmds */
	default:

		switch (pkt->pkt_cdbp[0]) {
		case SCMD_MODE_SENSE:
		case SCMD_MODE_SENSE_G1: {
			union scsi_cdb	*cdbp;
			uint16_t	page_code;

			cdbp = (void *)pkt->pkt_cdbp;
			page_code = (uint16_t)cdbp->cdb_un.sg.scsi[0];
			switch (page_code) {
			case 0x3:
			case 0x4:
				(void) mrsas_mode_sense_build(pkt);
				mrsas_return_mfi_pkt(instance, cmd);
				*cmd_done = 1;
				return (NULL);
			}
			break;
		}
		default:
			break;
		}

		pthru	= (struct mrsas_pthru_frame *)cmd->frame;

		/* prepare the DCDB frame */
		ddi_put8(acc_handle, &pthru->cmd, (acmd->islogical) ?
		    MFI_CMD_OP_LD_SCSI : MFI_CMD_OP_PD_SCSI);
		ddi_put8(acc_handle, &pthru->cmd_status, 0x0);
		ddi_put8(acc_handle, &pthru->scsi_status, 0x0);
		ddi_put8(acc_handle, &pthru->target_id, acmd->device_id);
		ddi_put8(acc_handle, &pthru->lun, 0);
		ddi_put8(acc_handle, &pthru->cdb_len, acmd->cmd_cdblen);
		ddi_put16(acc_handle, &pthru->timeout, 0);
		ddi_put16(acc_handle, &pthru->flags, flags);
		tmp_data_xfer_len = 0;
		for (i = 0; i < acmd->cmd_cookiecnt; i++) {
			tmp_data_xfer_len += acmd->cmd_dmacookies[i].dmac_size;
		}
		ddi_put32(acc_handle, &pthru->data_xfer_len,
		    tmp_data_xfer_len);
		ddi_put8(acc_handle, &pthru->sge_count, acmd->cmd_cookiecnt);
		if (instance->flag_ieee) {
			mfi_sgl_ieee = (struct mrsas_sge_ieee *)&pthru->sgl;
		} else {
			mfi_sgl	= (struct mrsas_sge64 *)&pthru->sgl;
		}

		bzero(cmd->sense, SENSE_LENGTH);
		ddi_put8(acc_handle, &pthru->sense_len, SENSE_LENGTH);
		ddi_put32(acc_handle, &pthru->sense_buf_phys_addr_hi, 0);
		ddi_put32(acc_handle, &pthru->sense_buf_phys_addr_lo,
		    cmd->sense_phys_addr);

		context = ddi_get32(acc_handle, &pthru->context);
		ddi_rep_put8(acc_handle, (uint8_t *)pkt->pkt_cdbp,
		    (uint8_t *)pthru->cdb, acmd->cmd_cdblen, DDI_DEV_AUTOINCR);

		break;
	}
#ifdef lint
	context = context;
#endif
	/* prepare the scatter-gather list for the firmware */
	if (instance->flag_ieee) {
		for (i = 0; i < acmd->cmd_cookiecnt; i++, mfi_sgl_ieee++) {
			ddi_put64(acc_handle, &mfi_sgl_ieee->phys_addr,
			    acmd->cmd_dmacookies[i].dmac_laddress);
			ddi_put32(acc_handle, &mfi_sgl_ieee->length,
			    acmd->cmd_dmacookies[i].dmac_size);
		}
		sge_bytes = sizeof (struct mrsas_sge_ieee)*acmd->cmd_cookiecnt;
	} else {
		for (i = 0; i < acmd->cmd_cookiecnt; i++, mfi_sgl++) {
			ddi_put64(acc_handle, &mfi_sgl->phys_addr,
			    acmd->cmd_dmacookies[i].dmac_laddress);
			ddi_put32(acc_handle, &mfi_sgl->length,
			    acmd->cmd_dmacookies[i].dmac_size);
		}
		sge_bytes = sizeof (struct mrsas_sge64)*acmd->cmd_cookiecnt;
	}

	cmd->frame_count = (sge_bytes / MRMFI_FRAME_SIZE) +
	    ((sge_bytes % MRMFI_FRAME_SIZE) ? 1 : 0) + 1;

	if (cmd->frame_count >= 8) {
		cmd->frame_count = 8;
	}

	return (cmd);
}

/*
 * wait_for_outstanding -	Wait for all outstanding cmds
 * @instance:				Adapter soft state
 *
 * This function waits for upto MRDRV_RESET_WAIT_TIME seconds for FW to
 * complete all its outstanding commands. Returns error if one or more IOs
 * are pending after this time period.
 */
static int
wait_for_outstanding(struct mrsas_instance *instance)
{
	int		i;
	uint32_t	wait_time = 90;

	for (i = 0; i < wait_time; i++) {
		if (!instance->fw_outstanding) {
			break;
		}

		drv_usecwait(MILLISEC); /* wait for 1000 usecs */;
	}

	if (instance->fw_outstanding) {
		return (1);
	}

	return (0);
}

/*
 * issue_mfi_pthru
 */
static int
issue_mfi_pthru(struct mrsas_instance *instance, struct mrsas_ioctl *ioctl,
    struct mrsas_cmd *cmd, int mode)
{
	void		*ubuf;
	uint32_t	kphys_addr = 0;
	uint32_t	xferlen = 0;
	uint32_t	new_xfer_length = 0;
	uint_t		model;
	ddi_acc_handle_t	acc_handle = cmd->frame_dma_obj.acc_handle;
	dma_obj_t			pthru_dma_obj;
	struct mrsas_pthru_frame	*kpthru;
	struct mrsas_pthru_frame	*pthru;
	int i;
	pthru = &cmd->frame->pthru;
	kpthru = (struct mrsas_pthru_frame *)&ioctl->frame[0];

	if (instance->adapterresetinprogress) {
		con_log(CL_ANN1, (CE_WARN, "issue_mfi_pthru: Reset flag set, "
		"returning mfi_pkt and setting TRAN_BUSY\n"));
		return (DDI_FAILURE);
	}
	model = ddi_model_convert_from(mode & FMODELS);
	if (model == DDI_MODEL_ILP32) {
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_pthru: DDI_MODEL_LP32"));

		xferlen	= kpthru->sgl.sge32[0].length;

		ubuf	= (void *)(ulong_t)kpthru->sgl.sge32[0].phys_addr;
	} else {
#ifdef _ILP32
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_pthru: DDI_MODEL_LP32"));
		xferlen	= kpthru->sgl.sge32[0].length;
		ubuf	= (void *)(ulong_t)kpthru->sgl.sge32[0].phys_addr;
#else
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_pthru: DDI_MODEL_LP64"));
		xferlen	= kpthru->sgl.sge64[0].length;
		ubuf	= (void *)(ulong_t)kpthru->sgl.sge64[0].phys_addr;
#endif
	}

	if (xferlen) {
		/* means IOCTL requires DMA */
		/* allocate the data transfer buffer */
		/* pthru_dma_obj.size = xferlen; */
		MRSAS_GET_BOUNDARY_ALIGNED_LEN(xferlen, new_xfer_length,
		    PAGESIZE);
		pthru_dma_obj.size = new_xfer_length;
		pthru_dma_obj.dma_attr = mrsas_generic_dma_attr;
		pthru_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		pthru_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
		pthru_dma_obj.dma_attr.dma_attr_sgllen = 1;
		pthru_dma_obj.dma_attr.dma_attr_align = 1;

		/* allocate kernel buffer for DMA */
		if (mrsas_alloc_dma_obj(instance, &pthru_dma_obj,
		    (uchar_t)DDI_STRUCTURE_LE_ACC) != 1) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_pthru: "
			    "could not allocate data transfer buffer."));
			return (DDI_FAILURE);
		}
		(void) memset(pthru_dma_obj.buffer, 0, xferlen);

		/* If IOCTL requires DMA WRITE, do ddi_copyin IOCTL data copy */
		if (kpthru->flags & MFI_FRAME_DIR_WRITE) {
			for (i = 0; i < xferlen; i++) {
				if (ddi_copyin((uint8_t *)ubuf+i,
				    (uint8_t *)pthru_dma_obj.buffer+i,
				    1, mode)) {
					con_log(CL_ANN, (CE_WARN,
					    "issue_mfi_pthru : "
					    "copy from user space failed"));
					return (DDI_FAILURE);
				}
			}
		}

		kphys_addr = pthru_dma_obj.dma_cookie[0].dmac_address;
	}

	ddi_put8(acc_handle, &pthru->cmd, kpthru->cmd);
	ddi_put8(acc_handle, &pthru->sense_len, SENSE_LENGTH);
	ddi_put8(acc_handle, &pthru->cmd_status, 0);
	ddi_put8(acc_handle, &pthru->scsi_status, 0);
	ddi_put8(acc_handle, &pthru->target_id, kpthru->target_id);
	ddi_put8(acc_handle, &pthru->lun, kpthru->lun);
	ddi_put8(acc_handle, &pthru->cdb_len, kpthru->cdb_len);
	ddi_put8(acc_handle, &pthru->sge_count, kpthru->sge_count);
	ddi_put16(acc_handle, &pthru->timeout, kpthru->timeout);
	ddi_put32(acc_handle, &pthru->data_xfer_len, kpthru->data_xfer_len);

	ddi_put32(acc_handle, &pthru->sense_buf_phys_addr_hi, 0);
	pthru->sense_buf_phys_addr_lo = cmd->sense_phys_addr;
	/* ddi_put32(acc_handle, &pthru->sense_buf_phys_addr_lo, 0); */

	ddi_rep_put8(acc_handle, (uint8_t *)kpthru->cdb, (uint8_t *)pthru->cdb,
	    pthru->cdb_len, DDI_DEV_AUTOINCR);

	ddi_put16(acc_handle, &pthru->flags, kpthru->flags & ~MFI_FRAME_SGL64);
	ddi_put32(acc_handle, &pthru->sgl.sge32[0].length, xferlen);
	ddi_put32(acc_handle, &pthru->sgl.sge32[0].phys_addr, kphys_addr);

	cmd->sync_cmd = MRSAS_TRUE;
	cmd->frame_count = 1;

	if (instance->tbolt) {
		mr_sas_tbolt_build_mfi_cmd(instance, cmd);
	}

	if (instance->func_ptr->issue_cmd_in_sync_mode(instance, cmd)) {
		con_log(CL_ANN, (CE_WARN,
		    "issue_mfi_pthru: fw_ioctl failed"));
	} else {
		if (xferlen && kpthru->flags & MFI_FRAME_DIR_READ) {
			for (i = 0; i < xferlen; i++) {
				if (ddi_copyout(
				    (uint8_t *)pthru_dma_obj.buffer+i,
				    (uint8_t *)ubuf+i, 1, mode)) {
					con_log(CL_ANN, (CE_WARN,
					    "issue_mfi_pthru : "
					    "copy to user space failed"));
					return (DDI_FAILURE);
				}
			}
		}
	}

	kpthru->cmd_status = ddi_get8(acc_handle, &pthru->cmd_status);
	kpthru->scsi_status = ddi_get8(acc_handle, &pthru->scsi_status);

	con_log(CL_ANN, (CE_CONT, "issue_mfi_pthru: cmd_status %x, "
	    "scsi_status %x", kpthru->cmd_status, kpthru->scsi_status));
	DTRACE_PROBE3(issue_pthru, uint8_t, kpthru->cmd, uint8_t,
	    kpthru->cmd_status, uint8_t, kpthru->scsi_status);

	if (kpthru->sense_len) {
		uint_t sense_len = SENSE_LENGTH;
		void *sense_ubuf =
		    (void *)(ulong_t)kpthru->sense_buf_phys_addr_lo;
		if (kpthru->sense_len <= SENSE_LENGTH) {
			sense_len = kpthru->sense_len;
		}

		for (i = 0; i < sense_len; i++) {
			if (ddi_copyout(
			    (uint8_t *)cmd->sense+i,
			    (uint8_t *)sense_ubuf+i, 1, mode)) {
				con_log(CL_ANN, (CE_WARN,
				    "issue_mfi_pthru : "
				    "copy to user space failed"));
			}
			con_log(CL_DLEVEL1, (CE_WARN,
			    "Copying Sense info sense_buff[%d] = 0x%X",
			    i, *((uint8_t *)cmd->sense + i)));
		}
	}
	(void) ddi_dma_sync(cmd->frame_dma_obj.dma_handle, 0, 0,
	    DDI_DMA_SYNC_FORDEV);

	if (xferlen) {
		/* free kernel buffer */
		if (mrsas_free_dma_obj(instance, pthru_dma_obj) != DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * issue_mfi_dcmd
 */
static int
issue_mfi_dcmd(struct mrsas_instance *instance, struct mrsas_ioctl *ioctl,
    struct mrsas_cmd *cmd, int mode)
{
	void		*ubuf;
	uint32_t	kphys_addr = 0;
	uint32_t	xferlen = 0;
	uint32_t	new_xfer_length = 0;
	uint32_t	model;
	dma_obj_t	dcmd_dma_obj;
	struct mrsas_dcmd_frame	*kdcmd;
	struct mrsas_dcmd_frame	*dcmd;
	ddi_acc_handle_t	acc_handle = cmd->frame_dma_obj.acc_handle;
	int i;
	dcmd = &cmd->frame->dcmd;
	kdcmd = (struct mrsas_dcmd_frame *)&ioctl->frame[0];

	if (instance->adapterresetinprogress) {
		con_log(CL_ANN1, (CE_NOTE, "Reset flag set, "
		"returning mfi_pkt and setting TRAN_BUSY"));
		return (DDI_FAILURE);
	}
	model = ddi_model_convert_from(mode & FMODELS);
	if (model == DDI_MODEL_ILP32) {
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_dcmd: DDI_MODEL_ILP32"));

		xferlen	= kdcmd->sgl.sge32[0].length;

		ubuf	= (void *)(ulong_t)kdcmd->sgl.sge32[0].phys_addr;
	} else {
#ifdef _ILP32
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_dcmd: DDI_MODEL_ILP32"));
		xferlen	= kdcmd->sgl.sge32[0].length;
		ubuf	= (void *)(ulong_t)kdcmd->sgl.sge32[0].phys_addr;
#else
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_dcmd: DDI_MODEL_LP64"));
		xferlen	= kdcmd->sgl.sge64[0].length;
		ubuf	= (void *)(ulong_t)kdcmd->sgl.sge64[0].phys_addr;
#endif
	}
	if (xferlen) {
		/* means IOCTL requires DMA */
		/* allocate the data transfer buffer */
		/* dcmd_dma_obj.size = xferlen; */
		MRSAS_GET_BOUNDARY_ALIGNED_LEN(xferlen, new_xfer_length,
		    PAGESIZE);
		dcmd_dma_obj.size = new_xfer_length;
		dcmd_dma_obj.dma_attr = mrsas_generic_dma_attr;
		dcmd_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		dcmd_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
		dcmd_dma_obj.dma_attr.dma_attr_sgllen = 1;
		dcmd_dma_obj.dma_attr.dma_attr_align = 1;

		/* allocate kernel buffer for DMA */
			if (mrsas_alloc_dma_obj(instance, &dcmd_dma_obj,
			    (uchar_t)DDI_STRUCTURE_LE_ACC) != 1) {
				con_log(CL_ANN,
				    (CE_WARN, "issue_mfi_dcmd: could not "
				    "allocate data transfer buffer."));
				return (DDI_FAILURE);
			}
		(void) memset(dcmd_dma_obj.buffer, 0, xferlen);

		/* If IOCTL requires DMA WRITE, do ddi_copyin IOCTL data copy */
		if (kdcmd->flags & MFI_FRAME_DIR_WRITE) {
			for (i = 0; i < xferlen; i++) {
				if (ddi_copyin((uint8_t *)ubuf + i,
				    (uint8_t *)dcmd_dma_obj.buffer + i,
				    1, mode)) {
					con_log(CL_ANN, (CE_WARN,
					    "issue_mfi_dcmd : "
					    "copy from user space failed"));
					return (DDI_FAILURE);
				}
			}
		}

		kphys_addr = dcmd_dma_obj.dma_cookie[0].dmac_address;
	}

	ddi_put8(acc_handle, &dcmd->cmd, kdcmd->cmd);
	ddi_put8(acc_handle, &dcmd->cmd_status, 0);
	ddi_put8(acc_handle, &dcmd->sge_count, kdcmd->sge_count);
	ddi_put16(acc_handle, &dcmd->timeout, kdcmd->timeout);
	ddi_put32(acc_handle, &dcmd->data_xfer_len, kdcmd->data_xfer_len);
	ddi_put32(acc_handle, &dcmd->opcode, kdcmd->opcode);

	ddi_rep_put8(acc_handle, (uint8_t *)kdcmd->mbox.b,
	    (uint8_t *)dcmd->mbox.b, DCMD_MBOX_SZ, DDI_DEV_AUTOINCR);

	ddi_put16(acc_handle, &dcmd->flags, kdcmd->flags & ~MFI_FRAME_SGL64);
	ddi_put32(acc_handle, &dcmd->sgl.sge32[0].length, xferlen);
	ddi_put32(acc_handle, &dcmd->sgl.sge32[0].phys_addr, kphys_addr);

	cmd->sync_cmd = MRSAS_TRUE;
	cmd->frame_count = 1;

	if (instance->tbolt) {
		mr_sas_tbolt_build_mfi_cmd(instance, cmd);
	}

	if (instance->func_ptr->issue_cmd_in_sync_mode(instance, cmd)) {
		con_log(CL_ANN, (CE_WARN, "issue_mfi_dcmd: fw_ioctl failed"));
	} else {
		if (xferlen && (kdcmd->flags & MFI_FRAME_DIR_READ)) {
			for (i = 0; i < xferlen; i++) {
				if (ddi_copyout(
				    (uint8_t *)dcmd_dma_obj.buffer + i,
				    (uint8_t *)ubuf + i,
				    1, mode)) {
					con_log(CL_ANN, (CE_WARN,
					    "issue_mfi_dcmd : "
					    "copy to user space failed"));
					return (DDI_FAILURE);
				}
			}
		}
	}

	kdcmd->cmd_status = ddi_get8(acc_handle, &dcmd->cmd_status);
	con_log(CL_ANN,
	    (CE_CONT, "issue_mfi_dcmd: cmd_status %x", kdcmd->cmd_status));
	DTRACE_PROBE3(issue_dcmd, uint32_t, kdcmd->opcode, uint8_t,
	    kdcmd->cmd, uint8_t, kdcmd->cmd_status);

	if (xferlen) {
		/* free kernel buffer */
		if (mrsas_free_dma_obj(instance, dcmd_dma_obj) != DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * issue_mfi_smp
 */
static int
issue_mfi_smp(struct mrsas_instance *instance, struct mrsas_ioctl *ioctl,
    struct mrsas_cmd *cmd, int mode)
{
	void		*request_ubuf;
	void		*response_ubuf;
	uint32_t	request_xferlen = 0;
	uint32_t	response_xferlen = 0;
	uint32_t	new_xfer_length1 = 0;
	uint32_t	new_xfer_length2 = 0;
	uint_t		model;
	dma_obj_t			request_dma_obj;
	dma_obj_t			response_dma_obj;
	ddi_acc_handle_t	acc_handle = cmd->frame_dma_obj.acc_handle;
	struct mrsas_smp_frame		*ksmp;
	struct mrsas_smp_frame		*smp;
	struct mrsas_sge32		*sge32;
#ifndef _ILP32
	struct mrsas_sge64		*sge64;
#endif
	int i;
	uint64_t			tmp_sas_addr;

	smp = &cmd->frame->smp;
	ksmp = (struct mrsas_smp_frame *)&ioctl->frame[0];

	if (instance->adapterresetinprogress) {
		con_log(CL_ANN1, (CE_WARN, "Reset flag set, "
		"returning mfi_pkt and setting TRAN_BUSY\n"));
		return (DDI_FAILURE);
	}
	model = ddi_model_convert_from(mode & FMODELS);
	if (model == DDI_MODEL_ILP32) {
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_smp: DDI_MODEL_ILP32"));

		sge32			= &ksmp->sgl[0].sge32[0];
		response_xferlen	= sge32[0].length;
		request_xferlen		= sge32[1].length;
		con_log(CL_ANN, (CE_CONT, "issue_mfi_smp: "
		    "response_xferlen = %x, request_xferlen = %x",
		    response_xferlen, request_xferlen));

		response_ubuf	= (void *)(ulong_t)sge32[0].phys_addr;
		request_ubuf	= (void *)(ulong_t)sge32[1].phys_addr;
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_smp: "
		    "response_ubuf = %p, request_ubuf = %p",
		    response_ubuf, request_ubuf));
	} else {
#ifdef _ILP32
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_smp: DDI_MODEL_ILP32"));

		sge32			= &ksmp->sgl[0].sge32[0];
		response_xferlen	= sge32[0].length;
		request_xferlen		= sge32[1].length;
		con_log(CL_ANN, (CE_CONT, "issue_mfi_smp: "
		    "response_xferlen = %x, request_xferlen = %x",
		    response_xferlen, request_xferlen));

		response_ubuf	= (void *)(ulong_t)sge32[0].phys_addr;
		request_ubuf	= (void *)(ulong_t)sge32[1].phys_addr;
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_smp: "
		    "response_ubuf = %p, request_ubuf = %p",
		    response_ubuf, request_ubuf));
#else
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_smp: DDI_MODEL_LP64"));

		sge64			= &ksmp->sgl[0].sge64[0];
		response_xferlen	= sge64[0].length;
		request_xferlen		= sge64[1].length;

		response_ubuf	= (void *)(ulong_t)sge64[0].phys_addr;
		request_ubuf	= (void *)(ulong_t)sge64[1].phys_addr;
#endif
	}
	if (request_xferlen) {
		/* means IOCTL requires DMA */
		/* allocate the data transfer buffer */
		/* request_dma_obj.size = request_xferlen; */
		MRSAS_GET_BOUNDARY_ALIGNED_LEN(request_xferlen,
		    new_xfer_length1, PAGESIZE);
		request_dma_obj.size = new_xfer_length1;
		request_dma_obj.dma_attr = mrsas_generic_dma_attr;
		request_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		request_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
		request_dma_obj.dma_attr.dma_attr_sgllen = 1;
		request_dma_obj.dma_attr.dma_attr_align = 1;

		/* allocate kernel buffer for DMA */
		if (mrsas_alloc_dma_obj(instance, &request_dma_obj,
		    (uchar_t)DDI_STRUCTURE_LE_ACC) != 1) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_smp: "
			    "could not allocate data transfer buffer."));
			return (DDI_FAILURE);
		}
		(void) memset(request_dma_obj.buffer, 0, request_xferlen);

		/* If IOCTL requires DMA WRITE, do ddi_copyin IOCTL data copy */
		for (i = 0; i < request_xferlen; i++) {
			if (ddi_copyin((uint8_t *)request_ubuf + i,
			    (uint8_t *)request_dma_obj.buffer + i,
			    1, mode)) {
				con_log(CL_ANN, (CE_WARN, "issue_mfi_smp: "
				    "copy from user space failed"));
				return (DDI_FAILURE);
			}
		}
	}

	if (response_xferlen) {
		/* means IOCTL requires DMA */
		/* allocate the data transfer buffer */
		/* response_dma_obj.size = response_xferlen; */
		MRSAS_GET_BOUNDARY_ALIGNED_LEN(response_xferlen,
		    new_xfer_length2, PAGESIZE);
		response_dma_obj.size = new_xfer_length2;
		response_dma_obj.dma_attr = mrsas_generic_dma_attr;
		response_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		response_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
		response_dma_obj.dma_attr.dma_attr_sgllen = 1;
		response_dma_obj.dma_attr.dma_attr_align = 1;

		/* allocate kernel buffer for DMA */
		if (mrsas_alloc_dma_obj(instance, &response_dma_obj,
		    (uchar_t)DDI_STRUCTURE_LE_ACC) != 1) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_smp: "
			    "could not allocate data transfer buffer."));
			return (DDI_FAILURE);
		}
		(void) memset(response_dma_obj.buffer, 0, response_xferlen);

		/* If IOCTL requires DMA WRITE, do ddi_copyin IOCTL data copy */
		for (i = 0; i < response_xferlen; i++) {
			if (ddi_copyin((uint8_t *)response_ubuf + i,
			    (uint8_t *)response_dma_obj.buffer + i,
			    1, mode)) {
				con_log(CL_ANN, (CE_WARN, "issue_mfi_smp: "
				    "copy from user space failed"));
				return (DDI_FAILURE);
			}
		}
	}

	ddi_put8(acc_handle, &smp->cmd, ksmp->cmd);
	ddi_put8(acc_handle, &smp->cmd_status, 0);
	ddi_put8(acc_handle, &smp->connection_status, 0);
	ddi_put8(acc_handle, &smp->sge_count, ksmp->sge_count);
	/* smp->context		= ksmp->context; */
	ddi_put16(acc_handle, &smp->timeout, ksmp->timeout);
	ddi_put32(acc_handle, &smp->data_xfer_len, ksmp->data_xfer_len);

	bcopy((void *)&ksmp->sas_addr, (void *)&tmp_sas_addr,
	    sizeof (uint64_t));
	ddi_put64(acc_handle, &smp->sas_addr, tmp_sas_addr);

	ddi_put16(acc_handle, &smp->flags, ksmp->flags & ~MFI_FRAME_SGL64);

	model = ddi_model_convert_from(mode & FMODELS);
	if (model == DDI_MODEL_ILP32) {
		con_log(CL_ANN1, (CE_CONT,
		    "issue_mfi_smp: DDI_MODEL_ILP32"));

		sge32 = &smp->sgl[0].sge32[0];
		ddi_put32(acc_handle, &sge32[0].length, response_xferlen);
		ddi_put32(acc_handle, &sge32[0].phys_addr,
		    response_dma_obj.dma_cookie[0].dmac_address);
		ddi_put32(acc_handle, &sge32[1].length, request_xferlen);
		ddi_put32(acc_handle, &sge32[1].phys_addr,
		    request_dma_obj.dma_cookie[0].dmac_address);
	} else {
#ifdef _ILP32
		con_log(CL_ANN1, (CE_CONT,
		    "issue_mfi_smp: DDI_MODEL_ILP32"));
		sge32 = &smp->sgl[0].sge32[0];
		ddi_put32(acc_handle, &sge32[0].length, response_xferlen);
		ddi_put32(acc_handle, &sge32[0].phys_addr,
		    response_dma_obj.dma_cookie[0].dmac_address);
		ddi_put32(acc_handle, &sge32[1].length, request_xferlen);
		ddi_put32(acc_handle, &sge32[1].phys_addr,
		    request_dma_obj.dma_cookie[0].dmac_address);
#else
		con_log(CL_ANN1, (CE_CONT,
		    "issue_mfi_smp: DDI_MODEL_LP64"));
		sge64 = &smp->sgl[0].sge64[0];
		ddi_put32(acc_handle, &sge64[0].length, response_xferlen);
		ddi_put64(acc_handle, &sge64[0].phys_addr,
		    response_dma_obj.dma_cookie[0].dmac_address);
		ddi_put32(acc_handle, &sge64[1].length, request_xferlen);
		ddi_put64(acc_handle, &sge64[1].phys_addr,
		    request_dma_obj.dma_cookie[0].dmac_address);
#endif
	}
	con_log(CL_ANN1, (CE_CONT, "issue_mfi_smp : "
	    "smp->response_xferlen = %d, smp->request_xferlen = %d "
	    "smp->data_xfer_len = %d", ddi_get32(acc_handle, &sge32[0].length),
	    ddi_get32(acc_handle, &sge32[1].length),
	    ddi_get32(acc_handle, &smp->data_xfer_len)));

	cmd->sync_cmd = MRSAS_TRUE;
	cmd->frame_count = 1;

	if (instance->tbolt) {
		mr_sas_tbolt_build_mfi_cmd(instance, cmd);
	}

	if (instance->func_ptr->issue_cmd_in_sync_mode(instance, cmd)) {
		con_log(CL_ANN, (CE_WARN,
		    "issue_mfi_smp: fw_ioctl failed"));
	} else {
		con_log(CL_ANN1, (CE_CONT,
		    "issue_mfi_smp: copy to user space"));

		if (request_xferlen) {
			for (i = 0; i < request_xferlen; i++) {
				if (ddi_copyout(
				    (uint8_t *)request_dma_obj.buffer +
				    i, (uint8_t *)request_ubuf + i,
				    1, mode)) {
					con_log(CL_ANN, (CE_WARN,
					    "issue_mfi_smp : copy to user space"
					    " failed"));
					return (DDI_FAILURE);
				}
			}
		}

		if (response_xferlen) {
			for (i = 0; i < response_xferlen; i++) {
				if (ddi_copyout(
				    (uint8_t *)response_dma_obj.buffer
				    + i, (uint8_t *)response_ubuf
				    + i, 1, mode)) {
					con_log(CL_ANN, (CE_WARN,
					    "issue_mfi_smp : copy to "
					    "user space failed"));
					return (DDI_FAILURE);
				}
			}
		}
	}

	ksmp->cmd_status = ddi_get8(acc_handle, &smp->cmd_status);
	con_log(CL_ANN1, (CE_NOTE, "issue_mfi_smp: smp->cmd_status = %d",
	    ksmp->cmd_status));
	DTRACE_PROBE2(issue_smp, uint8_t, ksmp->cmd, uint8_t, ksmp->cmd_status);

	if (request_xferlen) {
		/* free kernel buffer */
		if (mrsas_free_dma_obj(instance, request_dma_obj) !=
		    DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	if (response_xferlen) {
		/* free kernel buffer */
		if (mrsas_free_dma_obj(instance, response_dma_obj) !=
		    DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * issue_mfi_stp
 */
static int
issue_mfi_stp(struct mrsas_instance *instance, struct mrsas_ioctl *ioctl,
    struct mrsas_cmd *cmd, int mode)
{
	void		*fis_ubuf;
	void		*data_ubuf;
	uint32_t	fis_xferlen = 0;
	uint32_t   new_xfer_length1 = 0;
	uint32_t   new_xfer_length2 = 0;
	uint32_t	data_xferlen = 0;
	uint_t		model;
	dma_obj_t	fis_dma_obj;
	dma_obj_t	data_dma_obj;
	struct mrsas_stp_frame	*kstp;
	struct mrsas_stp_frame	*stp;
	ddi_acc_handle_t	acc_handle = cmd->frame_dma_obj.acc_handle;
	int i;

	stp = &cmd->frame->stp;
	kstp = (struct mrsas_stp_frame *)&ioctl->frame[0];

	if (instance->adapterresetinprogress) {
		con_log(CL_ANN1, (CE_WARN, "Reset flag set, "
		"returning mfi_pkt and setting TRAN_BUSY\n"));
		return (DDI_FAILURE);
	}
	model = ddi_model_convert_from(mode & FMODELS);
	if (model == DDI_MODEL_ILP32) {
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_stp: DDI_MODEL_ILP32"));

		fis_xferlen	= kstp->sgl.sge32[0].length;
		data_xferlen	= kstp->sgl.sge32[1].length;

		fis_ubuf	= (void *)(ulong_t)kstp->sgl.sge32[0].phys_addr;
		data_ubuf	= (void *)(ulong_t)kstp->sgl.sge32[1].phys_addr;
	} else {
#ifdef _ILP32
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_stp: DDI_MODEL_ILP32"));

		fis_xferlen	= kstp->sgl.sge32[0].length;
		data_xferlen	= kstp->sgl.sge32[1].length;

		fis_ubuf	= (void *)(ulong_t)kstp->sgl.sge32[0].phys_addr;
		data_ubuf	= (void *)(ulong_t)kstp->sgl.sge32[1].phys_addr;
#else
		con_log(CL_ANN1, (CE_CONT, "issue_mfi_stp: DDI_MODEL_LP64"));

		fis_xferlen	= kstp->sgl.sge64[0].length;
		data_xferlen	= kstp->sgl.sge64[1].length;

		fis_ubuf	= (void *)(ulong_t)kstp->sgl.sge64[0].phys_addr;
		data_ubuf	= (void *)(ulong_t)kstp->sgl.sge64[1].phys_addr;
#endif
	}


	if (fis_xferlen) {
		con_log(CL_ANN, (CE_CONT, "issue_mfi_stp: "
		    "fis_ubuf = %p fis_xferlen = %x", fis_ubuf, fis_xferlen));

		/* means IOCTL requires DMA */
		/* allocate the data transfer buffer */
		/* fis_dma_obj.size = fis_xferlen; */
		MRSAS_GET_BOUNDARY_ALIGNED_LEN(fis_xferlen,
		    new_xfer_length1, PAGESIZE);
		fis_dma_obj.size = new_xfer_length1;
		fis_dma_obj.dma_attr = mrsas_generic_dma_attr;
		fis_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		fis_dma_obj.dma_attr.dma_attr_count_max	= 0xFFFFFFFFU;
		fis_dma_obj.dma_attr.dma_attr_sgllen = 1;
		fis_dma_obj.dma_attr.dma_attr_align = 1;

		/* allocate kernel buffer for DMA */
		if (mrsas_alloc_dma_obj(instance, &fis_dma_obj,
		    (uchar_t)DDI_STRUCTURE_LE_ACC) != 1) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_stp : "
			    "could not allocate data transfer buffer."));
			return (DDI_FAILURE);
		}
		(void) memset(fis_dma_obj.buffer, 0, fis_xferlen);

		/* If IOCTL requires DMA WRITE, do ddi_copyin IOCTL data copy */
		for (i = 0; i < fis_xferlen; i++) {
			if (ddi_copyin((uint8_t *)fis_ubuf + i,
			    (uint8_t *)fis_dma_obj.buffer + i, 1, mode)) {
				con_log(CL_ANN, (CE_WARN, "issue_mfi_stp: "
				    "copy from user space failed"));
				return (DDI_FAILURE);
			}
		}
	}

	if (data_xferlen) {
		con_log(CL_ANN, (CE_CONT, "issue_mfi_stp: data_ubuf = %p "
		    "data_xferlen = %x", data_ubuf, data_xferlen));

		/* means IOCTL requires DMA */
		/* allocate the data transfer buffer */
		/* data_dma_obj.size = data_xferlen; */
		MRSAS_GET_BOUNDARY_ALIGNED_LEN(data_xferlen, new_xfer_length2,
		    PAGESIZE);
		data_dma_obj.size = new_xfer_length2;
		data_dma_obj.dma_attr = mrsas_generic_dma_attr;
		data_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		data_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
		data_dma_obj.dma_attr.dma_attr_sgllen = 1;
		data_dma_obj.dma_attr.dma_attr_align = 1;

		/* allocate kernel buffer for DMA */
		if (mrsas_alloc_dma_obj(instance, &data_dma_obj,
		    (uchar_t)DDI_STRUCTURE_LE_ACC) != 1) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_stp: "
			    "could not allocate data transfer buffer."));
			return (DDI_FAILURE);
		}
		(void) memset(data_dma_obj.buffer, 0, data_xferlen);

		/* If IOCTL requires DMA WRITE, do ddi_copyin IOCTL data copy */
		for (i = 0; i < data_xferlen; i++) {
			if (ddi_copyin((uint8_t *)data_ubuf + i,
			    (uint8_t *)data_dma_obj.buffer + i, 1, mode)) {
				con_log(CL_ANN, (CE_WARN, "issue_mfi_stp: "
				    "copy from user space failed"));
				return (DDI_FAILURE);
			}
		}
	}

	ddi_put8(acc_handle, &stp->cmd, kstp->cmd);
	ddi_put8(acc_handle, &stp->cmd_status, 0);
	ddi_put8(acc_handle, &stp->connection_status, 0);
	ddi_put8(acc_handle, &stp->target_id, kstp->target_id);
	ddi_put8(acc_handle, &stp->sge_count, kstp->sge_count);

	ddi_put16(acc_handle, &stp->timeout, kstp->timeout);
	ddi_put32(acc_handle, &stp->data_xfer_len, kstp->data_xfer_len);

	ddi_rep_put8(acc_handle, (uint8_t *)kstp->fis, (uint8_t *)stp->fis, 10,
	    DDI_DEV_AUTOINCR);

	ddi_put16(acc_handle, &stp->flags, kstp->flags & ~MFI_FRAME_SGL64);
	ddi_put32(acc_handle, &stp->stp_flags, kstp->stp_flags);
	ddi_put32(acc_handle, &stp->sgl.sge32[0].length, fis_xferlen);
	ddi_put32(acc_handle, &stp->sgl.sge32[0].phys_addr,
	    fis_dma_obj.dma_cookie[0].dmac_address);
	ddi_put32(acc_handle, &stp->sgl.sge32[1].length, data_xferlen);
	ddi_put32(acc_handle, &stp->sgl.sge32[1].phys_addr,
	    data_dma_obj.dma_cookie[0].dmac_address);

	cmd->sync_cmd = MRSAS_TRUE;
	cmd->frame_count = 1;

	if (instance->tbolt) {
		mr_sas_tbolt_build_mfi_cmd(instance, cmd);
	}

	if (instance->func_ptr->issue_cmd_in_sync_mode(instance, cmd)) {
		con_log(CL_ANN, (CE_WARN, "issue_mfi_stp: fw_ioctl failed"));
	} else {

		if (fis_xferlen) {
			for (i = 0; i < fis_xferlen; i++) {
				if (ddi_copyout(
				    (uint8_t *)fis_dma_obj.buffer + i,
				    (uint8_t *)fis_ubuf + i, 1, mode)) {
					con_log(CL_ANN, (CE_WARN,
					    "issue_mfi_stp : copy to "
					    "user space failed"));
					return (DDI_FAILURE);
				}
			}
		}
	}
	if (data_xferlen) {
		for (i = 0; i < data_xferlen; i++) {
			if (ddi_copyout(
			    (uint8_t *)data_dma_obj.buffer + i,
			    (uint8_t *)data_ubuf + i, 1, mode)) {
				con_log(CL_ANN, (CE_WARN,
				    "issue_mfi_stp : copy to"
				    " user space failed"));
				return (DDI_FAILURE);
			}
		}
	}

	kstp->cmd_status = ddi_get8(acc_handle, &stp->cmd_status);
	con_log(CL_ANN1, (CE_NOTE, "issue_mfi_stp: stp->cmd_status = %d",
	    kstp->cmd_status));
	DTRACE_PROBE2(issue_stp, uint8_t, kstp->cmd, uint8_t, kstp->cmd_status);

	if (fis_xferlen) {
		/* free kernel buffer */
		if (mrsas_free_dma_obj(instance, fis_dma_obj) != DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	if (data_xferlen) {
		/* free kernel buffer */
		if (mrsas_free_dma_obj(instance, data_dma_obj) != DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * fill_up_drv_ver
 */
void
fill_up_drv_ver(struct mrsas_drv_ver *dv)
{
	(void) memset(dv, 0, sizeof (struct mrsas_drv_ver));

	(void) memcpy(dv->signature, "$LSI LOGIC$", strlen("$LSI LOGIC$"));
	(void) memcpy(dv->os_name, "Solaris", strlen("Solaris"));
	(void) memcpy(dv->drv_name, "mr_sas", strlen("mr_sas"));
	(void) memcpy(dv->drv_ver, MRSAS_VERSION, strlen(MRSAS_VERSION));
	(void) memcpy(dv->drv_rel_date, MRSAS_RELDATE,
	    strlen(MRSAS_RELDATE));

}

/*
 * handle_drv_ioctl
 */
static int
handle_drv_ioctl(struct mrsas_instance *instance, struct mrsas_ioctl *ioctl,
    int mode)
{
	int	i;
	int	rval = DDI_SUCCESS;
	int	*props = NULL;
	void	*ubuf;

	uint8_t		*pci_conf_buf;
	uint32_t	xferlen;
	uint32_t	num_props;
	uint_t		model;
	struct mrsas_dcmd_frame	*kdcmd;
	struct mrsas_drv_ver	dv;
	struct mrsas_pci_information pi;

	kdcmd = (struct mrsas_dcmd_frame *)&ioctl->frame[0];

	model = ddi_model_convert_from(mode & FMODELS);
	if (model == DDI_MODEL_ILP32) {
		con_log(CL_ANN1, (CE_CONT,
		    "handle_drv_ioctl: DDI_MODEL_ILP32"));

		xferlen	= kdcmd->sgl.sge32[0].length;

		ubuf = (void *)(ulong_t)kdcmd->sgl.sge32[0].phys_addr;
	} else {
#ifdef _ILP32
		con_log(CL_ANN1, (CE_CONT,
		    "handle_drv_ioctl: DDI_MODEL_ILP32"));
		xferlen	= kdcmd->sgl.sge32[0].length;
		ubuf = (void *)(ulong_t)kdcmd->sgl.sge32[0].phys_addr;
#else
		con_log(CL_ANN1, (CE_CONT,
		    "handle_drv_ioctl: DDI_MODEL_LP64"));
		xferlen	= kdcmd->sgl.sge64[0].length;
		ubuf = (void *)(ulong_t)kdcmd->sgl.sge64[0].phys_addr;
#endif
	}
	con_log(CL_ANN1, (CE_CONT, "handle_drv_ioctl: "
	    "dataBuf=%p size=%d bytes", ubuf, xferlen));

	switch (kdcmd->opcode) {
	case MRSAS_DRIVER_IOCTL_DRIVER_VERSION:
		con_log(CL_ANN1, (CE_CONT, "handle_drv_ioctl: "
		    "MRSAS_DRIVER_IOCTL_DRIVER_VERSION"));

		fill_up_drv_ver(&dv);

		if (ddi_copyout(&dv, ubuf, xferlen, mode)) {
			con_log(CL_ANN, (CE_WARN, "handle_drv_ioctl: "
			    "MRSAS_DRIVER_IOCTL_DRIVER_VERSION : "
			    "copy to user space failed"));
			kdcmd->cmd_status = 1;
			rval = 1;
		} else {
			kdcmd->cmd_status = 0;
		}
		break;
	case MRSAS_DRIVER_IOCTL_PCI_INFORMATION:
		con_log(CL_ANN1, (CE_NOTE, "handle_drv_ioctl: "
		    "MRSAS_DRIVER_IOCTL_PCI_INFORMAITON"));

		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, instance->dip,
		    0, "reg", &props, &num_props)) {
			con_log(CL_ANN, (CE_WARN, "handle_drv_ioctl: "
			    "MRSAS_DRIVER_IOCTL_PCI_INFORMATION : "
			    "ddi_prop_look_int_array failed"));
			rval = DDI_FAILURE;
		} else {

			pi.busNumber = (props[0] >> 16) & 0xFF;
			pi.deviceNumber = (props[0] >> 11) & 0x1f;
			pi.functionNumber = (props[0] >> 8) & 0x7;
			ddi_prop_free((void *)props);
		}

		pci_conf_buf = (uint8_t *)&pi.pciHeaderInfo;

		for (i = 0; i < (sizeof (struct mrsas_pci_information) -
		    offsetof(struct mrsas_pci_information, pciHeaderInfo));
		    i++) {
			pci_conf_buf[i] =
			    pci_config_get8(instance->pci_handle, i);
		}

		if (ddi_copyout(&pi, ubuf, xferlen, mode)) {
			con_log(CL_ANN, (CE_WARN, "handle_drv_ioctl: "
			    "MRSAS_DRIVER_IOCTL_PCI_INFORMATION : "
			    "copy to user space failed"));
			kdcmd->cmd_status = 1;
			rval = 1;
		} else {
			kdcmd->cmd_status = 0;
		}
		break;
	default:
		con_log(CL_ANN, (CE_WARN, "handle_drv_ioctl: "
		    "invalid driver specific IOCTL opcode = 0x%x",
		    kdcmd->opcode));
		kdcmd->cmd_status = 1;
		rval = DDI_FAILURE;
		break;
	}

	return (rval);
}

/*
 * handle_mfi_ioctl
 */
static int
handle_mfi_ioctl(struct mrsas_instance *instance, struct mrsas_ioctl *ioctl,
    int mode)
{
	int	rval = DDI_SUCCESS;

	struct mrsas_header	*hdr;
	struct mrsas_cmd	*cmd;

	if (instance->tbolt) {
		cmd = get_raid_msg_mfi_pkt(instance);
	} else {
		cmd = mrsas_get_mfi_pkt(instance);
	}
	if (!cmd) {
		con_log(CL_ANN, (CE_WARN, "mr_sas: "
		    "failed to get a cmd packet"));
		DTRACE_PROBE2(mfi_ioctl_err, uint16_t,
		    instance->fw_outstanding, uint16_t, instance->max_fw_cmds);
		return (DDI_FAILURE);
	}

	/* Clear the frame buffer and assign back the context id */
	(void) memset((char *)&cmd->frame[0], 0, sizeof (union mrsas_frame));
	ddi_put32(cmd->frame_dma_obj.acc_handle, &cmd->frame->hdr.context,
	    cmd->index);

	hdr = (struct mrsas_header *)&ioctl->frame[0];

	switch (ddi_get8(cmd->frame_dma_obj.acc_handle, &hdr->cmd)) {
	case MFI_CMD_OP_DCMD:
		rval = issue_mfi_dcmd(instance, ioctl, cmd, mode);
		break;
	case MFI_CMD_OP_SMP:
		rval = issue_mfi_smp(instance, ioctl, cmd, mode);
		break;
	case MFI_CMD_OP_STP:
		rval = issue_mfi_stp(instance, ioctl, cmd, mode);
		break;
	case MFI_CMD_OP_LD_SCSI:
	case MFI_CMD_OP_PD_SCSI:
		rval = issue_mfi_pthru(instance, ioctl, cmd, mode);
		break;
	default:
		con_log(CL_ANN, (CE_WARN, "handle_mfi_ioctl: "
		    "invalid mfi ioctl hdr->cmd = %d", hdr->cmd));
		rval = DDI_FAILURE;
		break;
	}

	if (mrsas_common_check(instance, cmd) != DDI_SUCCESS)
		rval = DDI_FAILURE;

	if (instance->tbolt) {
		return_raid_msg_mfi_pkt(instance, cmd);
	} else {
		mrsas_return_mfi_pkt(instance, cmd);
	}

	return (rval);
}

/*
 * AEN
 */
static int
handle_mfi_aen(struct mrsas_instance *instance, struct mrsas_aen *aen)
{
	int	rval = 0;

	rval = register_mfi_aen(instance, instance->aen_seq_num,
	    aen->class_locale_word);

	aen->cmd_status = (uint8_t)rval;

	return (rval);
}

static int
register_mfi_aen(struct mrsas_instance *instance, uint32_t seq_num,
    uint32_t class_locale_word)
{
	int	ret_val;

	struct mrsas_cmd	*cmd, *aen_cmd;
	struct mrsas_dcmd_frame	*dcmd;
	union mrsas_evt_class_locale	curr_aen;
	union mrsas_evt_class_locale	prev_aen;

	con_log(CL_ANN, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));
	/*
	 * If there an AEN pending already (aen_cmd), check if the
	 * class_locale of that pending AEN is inclusive of the new
	 * AEN request we currently have. If it is, then we don't have
	 * to do anything. In other words, whichever events the current
	 * AEN request is subscribing to, have already been subscribed
	 * to.
	 *
	 * If the old_cmd is _not_ inclusive, then we have to abort
	 * that command, form a class_locale that is superset of both
	 * old and current and re-issue to the FW
	 */

	curr_aen.word = LE_32(class_locale_word);
	curr_aen.members.locale = LE_16(curr_aen.members.locale);
	aen_cmd = instance->aen_cmd;
	if (aen_cmd) {
		prev_aen.word = ddi_get32(aen_cmd->frame_dma_obj.acc_handle,
		    &aen_cmd->frame->dcmd.mbox.w[1]);
		prev_aen.word = LE_32(prev_aen.word);
		prev_aen.members.locale = LE_16(prev_aen.members.locale);
		/*
		 * A class whose enum value is smaller is inclusive of all
		 * higher values. If a PROGRESS (= -1) was previously
		 * registered, then a new registration requests for higher
		 * classes need not be sent to FW. They are automatically
		 * included.
		 *
		 * Locale numbers don't have such hierarchy. They are bitmap
		 * values
		 */
		if ((prev_aen.members.class <= curr_aen.members.class) &&
		    !((prev_aen.members.locale & curr_aen.members.locale) ^
		    curr_aen.members.locale)) {
			/*
			 * Previously issued event registration includes
			 * current request. Nothing to do.
			 */

			return (0);
		} else {
			curr_aen.members.locale |= prev_aen.members.locale;

			if (prev_aen.members.class < curr_aen.members.class)
				curr_aen.members.class = prev_aen.members.class;

			ret_val = abort_aen_cmd(instance, aen_cmd);

			if (ret_val) {
				con_log(CL_ANN, (CE_WARN, "register_mfi_aen: "
				    "failed to abort prevous AEN command"));

				return (ret_val);
			}
		}
	} else {
		curr_aen.word = LE_32(class_locale_word);
		curr_aen.members.locale = LE_16(curr_aen.members.locale);
	}

	if (instance->tbolt) {
		cmd = get_raid_msg_mfi_pkt(instance);
	} else {
		cmd = mrsas_get_mfi_pkt(instance);
	}

	if (!cmd) {
		DTRACE_PROBE2(mfi_aen_err, uint16_t, instance->fw_outstanding,
		    uint16_t, instance->max_fw_cmds);
		return (ENOMEM);
	}

	/* Clear the frame buffer and assign back the context id */
	(void) memset((char *)&cmd->frame[0], 0, sizeof (union mrsas_frame));
	ddi_put32(cmd->frame_dma_obj.acc_handle, &cmd->frame->hdr.context,
	    cmd->index);

	dcmd = &cmd->frame->dcmd;

	/* for(i = 0; i < DCMD_MBOX_SZ; i++) dcmd->mbox.b[i] = 0; */
	(void) memset(dcmd->mbox.b, 0, DCMD_MBOX_SZ);

	(void) memset(instance->mfi_evt_detail_obj.buffer, 0,
	    sizeof (struct mrsas_evt_detail));

	/* Prepare DCMD for aen registration */
	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->cmd, MFI_CMD_OP_DCMD);
	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->cmd_status, 0x0);
	ddi_put8(cmd->frame_dma_obj.acc_handle, &dcmd->sge_count, 1);
	ddi_put16(cmd->frame_dma_obj.acc_handle, &dcmd->flags,
	    MFI_FRAME_DIR_READ);
	ddi_put16(cmd->frame_dma_obj.acc_handle, &dcmd->timeout, 0);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->data_xfer_len,
	    sizeof (struct mrsas_evt_detail));
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->opcode,
	    MR_DCMD_CTRL_EVENT_WAIT);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->mbox.w[0], seq_num);
	curr_aen.members.locale = LE_16(curr_aen.members.locale);
	curr_aen.word = LE_32(curr_aen.word);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->mbox.w[1],
	    curr_aen.word);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->sgl.sge32[0].phys_addr,
	    instance->mfi_evt_detail_obj.dma_cookie[0].dmac_address);
	ddi_put32(cmd->frame_dma_obj.acc_handle, &dcmd->sgl.sge32[0].length,
	    sizeof (struct mrsas_evt_detail));

	instance->aen_seq_num = seq_num;


	/*
	 * Store reference to the cmd used to register for AEN. When an
	 * application wants us to register for AEN, we have to abort this
	 * cmd and re-register with a new EVENT LOCALE supplied by that app
	 */
	instance->aen_cmd = cmd;

	cmd->frame_count = 1;

	/* Issue the aen registration frame */
	/* atomic_add_16 (&instance->fw_outstanding, 1); */
	if (instance->tbolt) {
		mr_sas_tbolt_build_mfi_cmd(instance, cmd);
	}
	instance->func_ptr->issue_cmd(cmd, instance);

	return (0);
}

void
display_scsi_inquiry(caddr_t scsi_inq)
{
#define	MAX_SCSI_DEVICE_CODE	14
	int		i;
	char		inquiry_buf[256] = {0};
	int		len;
	const char	*const scsi_device_types[] = {
		"Direct-Access	  ",
		"Sequential-Access",
		"Printer	  ",
		"Processor	  ",
		"WORM		  ",
		"CD-ROM		  ",
		"Scanner	  ",
		"Optical Device	  ",
		"Medium Changer	  ",
		"Communications	  ",
		"Unknown	  ",
		"Unknown	  ",
		"Unknown	  ",
		"Enclosure	  ",
	};

	len = 0;

	len += snprintf(inquiry_buf + len, 265 - len, "	 Vendor: ");
	for (i = 8; i < 16; i++) {
		len += snprintf(inquiry_buf + len, 265 - len, "%c",
		    scsi_inq[i]);
	}

	len += snprintf(inquiry_buf + len, 265 - len, "	 Model: ");

	for (i = 16; i < 32; i++) {
		len += snprintf(inquiry_buf + len, 265 - len, "%c",
		    scsi_inq[i]);
	}

	len += snprintf(inquiry_buf + len, 265 - len, "	 Rev: ");

	for (i = 32; i < 36; i++) {
		len += snprintf(inquiry_buf + len, 265 - len, "%c",
		    scsi_inq[i]);
	}

	len += snprintf(inquiry_buf + len, 265 - len, "\n");


	i = scsi_inq[0] & 0x1f;


	len += snprintf(inquiry_buf + len, 265 - len, "	 Type:	 %s ",
	    i < MAX_SCSI_DEVICE_CODE ? scsi_device_types[i] :
	    "Unknown	      ");


	len += snprintf(inquiry_buf + len, 265 - len,
	    "		      ANSI SCSI revision: %02x", scsi_inq[2] & 0x07);

	if ((scsi_inq[2] & 0x07) == 1 && (scsi_inq[3] & 0x0f) == 1) {
		len += snprintf(inquiry_buf + len, 265 - len, " CCS\n");
	} else {
		len += snprintf(inquiry_buf + len, 265 - len, "\n");
	}

	con_log(CL_DLEVEL2, (CE_CONT, inquiry_buf));
}

static void
io_timeout_checker(void *arg)
{
	struct scsi_pkt *pkt;
	struct mrsas_instance *instance = arg;
	struct mrsas_cmd	*cmd = NULL;
	struct mrsas_header	*hdr;
	int time = 0;
	int counter = 0;
	struct mlist_head	*pos, *next;
	mlist_t			process_list;

	if (instance->adapterresetinprogress == 1) {
		con_log(CL_ANN, (CE_NOTE, "io_timeout_checker:"
		    " reset in progress"));

		instance->timeout_id = timeout(io_timeout_checker,
		    (void *) instance, drv_usectohz(MRSAS_1_SECOND));
		return;
	}

	/* See if this check needs to be in the beginning or last in ISR */
	if (mrsas_initiate_ocr_if_fw_is_faulty(instance) ==  1) {
		dev_err(instance->dip, CE_WARN, "io_timeout_checker: "
		    "FW Fault, calling reset adapter");
		dev_err(instance->dip, CE_CONT, "io_timeout_checker: "
		    "fw_outstanding 0x%X max_fw_cmds 0x%X",
		    instance->fw_outstanding, instance->max_fw_cmds);
		if (instance->adapterresetinprogress == 0) {
			instance->adapterresetinprogress = 1;
			if (instance->tbolt)
				(void) mrsas_tbolt_reset_ppc(instance);
			else
				(void) mrsas_reset_ppc(instance);
			instance->adapterresetinprogress = 0;
		}
		instance->timeout_id = timeout(io_timeout_checker,
		    (void *) instance, drv_usectohz(MRSAS_1_SECOND));
		return;
	}

	INIT_LIST_HEAD(&process_list);

	mutex_enter(&instance->cmd_pend_mtx);
	mlist_for_each_safe(pos, next, &instance->cmd_pend_list) {
		cmd = mlist_entry(pos, struct mrsas_cmd, list);

		if (cmd == NULL) {
			continue;
		}

		if (cmd->sync_cmd == MRSAS_TRUE) {
			hdr = (struct mrsas_header *)&cmd->frame->hdr;
			if (hdr == NULL) {
				continue;
			}
			time = --cmd->drv_pkt_time;
		} else {
			pkt = cmd->pkt;
			if (pkt == NULL) {
				continue;
			}
			time = --cmd->drv_pkt_time;
		}
		if (time <= 0) {
			dev_err(instance->dip, CE_WARN, "%llx: "
			    "io_timeout_checker: TIMING OUT: pkt: %p, "
			    "cmd %p fw_outstanding 0x%X max_fw_cmds 0x%X",
			    gethrtime(), (void *)pkt, (void *)cmd,
			    instance->fw_outstanding, instance->max_fw_cmds);

			counter++;
			break;
		}
	}
	mutex_exit(&instance->cmd_pend_mtx);

	if (counter) {
		if (instance->disable_online_ctrl_reset == 1) {
			dev_err(instance->dip, CE_WARN, "%s(): OCR is NOT "
			    "supported by Firmware, KILL adapter!!!",
			    __func__);

			if (instance->tbolt)
				mrsas_tbolt_kill_adapter(instance);
			else
				(void) mrsas_kill_adapter(instance);

			return;
		} else {
			if (cmd->retry_count_for_ocr <=	 IO_RETRY_COUNT) {
				if (instance->adapterresetinprogress == 0) {
					if (instance->tbolt) {
						(void) mrsas_tbolt_reset_ppc(
						    instance);
					} else {
						(void) mrsas_reset_ppc(
						    instance);
					}
				}
			} else {
				dev_err(instance->dip, CE_WARN,
				    "io_timeout_checker: "
				    "cmd %p cmd->index %d "
				    "timed out even after 3 resets: "
				    "so KILL adapter", (void *)cmd, cmd->index);

				mrsas_print_cmd_details(instance, cmd, 0xDD);

				if (instance->tbolt)
					mrsas_tbolt_kill_adapter(instance);
				else
					(void) mrsas_kill_adapter(instance);
				return;
			}
		}
	}
	con_log(CL_ANN, (CE_NOTE, "mrsas: "
	    "schedule next timeout check: "
	    "do timeout \n"));
	instance->timeout_id =
	    timeout(io_timeout_checker, (void *)instance,
	    drv_usectohz(MRSAS_1_SECOND));
}

static uint32_t
read_fw_status_reg_ppc(struct mrsas_instance *instance)
{
	return ((uint32_t)RD_OB_SCRATCH_PAD_0(instance));
}

static void
issue_cmd_ppc(struct mrsas_cmd *cmd, struct mrsas_instance *instance)
{
	struct scsi_pkt *pkt;
	atomic_inc_16(&instance->fw_outstanding);

	pkt = cmd->pkt;
	if (pkt) {
		con_log(CL_DLEVEL1, (CE_NOTE, "%llx : issue_cmd_ppc:"
		    "ISSUED CMD TO FW : called : cmd:"
		    ": %p instance : %p pkt : %p pkt_time : %x\n",
		    gethrtime(), (void *)cmd, (void *)instance,
		    (void *)pkt, cmd->drv_pkt_time));
		if (instance->adapterresetinprogress) {
			cmd->drv_pkt_time = (uint16_t)debug_timeout_g;
			con_log(CL_ANN1, (CE_NOTE, "Reset the scsi_pkt timer"));
		} else {
			push_pending_mfi_pkt(instance, cmd);
		}

	} else {
		con_log(CL_DLEVEL1, (CE_NOTE, "%llx : issue_cmd_ppc:"
		    "ISSUED CMD TO FW : called : cmd : %p, instance: %p"
		    "(NO PKT)\n", gethrtime(), (void *)cmd, (void *)instance));
	}

	mutex_enter(&instance->reg_write_mtx);
	/* Issue the command to the FW */
	WR_IB_PICK_QPORT((cmd->frame_phys_addr) |
	    (((cmd->frame_count - 1) << 1) | 1), instance);
	mutex_exit(&instance->reg_write_mtx);

}

/*
 * issue_cmd_in_sync_mode
 */
static int
issue_cmd_in_sync_mode_ppc(struct mrsas_instance *instance,
    struct mrsas_cmd *cmd)
{
	int	i;
	uint32_t	msecs = MFI_POLL_TIMEOUT_SECS * MILLISEC;
	struct mrsas_header *hdr = &cmd->frame->hdr;

	con_log(CL_ANN1, (CE_NOTE, "issue_cmd_in_sync_mode_ppc: called"));

	if (instance->adapterresetinprogress) {
		cmd->drv_pkt_time = ddi_get16(
		    cmd->frame_dma_obj.acc_handle, &hdr->timeout);
		if (cmd->drv_pkt_time < debug_timeout_g)
			cmd->drv_pkt_time = (uint16_t)debug_timeout_g;

		con_log(CL_ANN1, (CE_NOTE, "sync_mode_ppc: "
		    "issue and return in reset case\n"));
		WR_IB_PICK_QPORT((cmd->frame_phys_addr) |
		    (((cmd->frame_count - 1) << 1) | 1), instance);

		return (DDI_SUCCESS);
	} else {
		con_log(CL_ANN1, (CE_NOTE, "sync_mode_ppc: pushing the pkt\n"));
		push_pending_mfi_pkt(instance, cmd);
	}

	cmd->cmd_status	= ENODATA;

	mutex_enter(&instance->reg_write_mtx);
	/* Issue the command to the FW */
	WR_IB_PICK_QPORT((cmd->frame_phys_addr) |
	    (((cmd->frame_count - 1) << 1) | 1), instance);
	mutex_exit(&instance->reg_write_mtx);

	mutex_enter(&instance->int_cmd_mtx);
	for (i = 0; i < msecs && (cmd->cmd_status == ENODATA); i++) {
		cv_wait(&instance->int_cmd_cv, &instance->int_cmd_mtx);
	}
	mutex_exit(&instance->int_cmd_mtx);

	con_log(CL_ANN1, (CE_NOTE, "issue_cmd_in_sync_mode_ppc: done"));

	if (i < (msecs -1)) {
		return (DDI_SUCCESS);
	} else {
		return (DDI_FAILURE);
	}
}

/*
 * issue_cmd_in_poll_mode
 */
static int
issue_cmd_in_poll_mode_ppc(struct mrsas_instance *instance,
    struct mrsas_cmd *cmd)
{
	int		i;
	uint16_t	flags;
	uint32_t	msecs = MFI_POLL_TIMEOUT_SECS * MILLISEC;
	struct mrsas_header *frame_hdr;

	con_log(CL_ANN1, (CE_NOTE, "issue_cmd_in_poll_mode_ppc: called"));

	frame_hdr = (struct mrsas_header *)cmd->frame;
	ddi_put8(cmd->frame_dma_obj.acc_handle, &frame_hdr->cmd_status,
	    MFI_CMD_STATUS_POLL_MODE);
	flags = ddi_get16(cmd->frame_dma_obj.acc_handle, &frame_hdr->flags);
	flags	|= MFI_FRAME_DONT_POST_IN_REPLY_QUEUE;

	ddi_put16(cmd->frame_dma_obj.acc_handle, &frame_hdr->flags, flags);

	/* issue the frame using inbound queue port */
	WR_IB_PICK_QPORT((cmd->frame_phys_addr) |
	    (((cmd->frame_count - 1) << 1) | 1), instance);

	/* wait for cmd_status to change from 0xFF */
	for (i = 0; i < msecs && (
	    ddi_get8(cmd->frame_dma_obj.acc_handle, &frame_hdr->cmd_status)
	    == MFI_CMD_STATUS_POLL_MODE); i++) {
		drv_usecwait(MILLISEC); /* wait for 1000 usecs */
	}

	if (ddi_get8(cmd->frame_dma_obj.acc_handle, &frame_hdr->cmd_status)
	    == MFI_CMD_STATUS_POLL_MODE) {
		con_log(CL_ANN, (CE_NOTE, "issue_cmd_in_poll_mode: "
		    "cmd polling timed out"));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
enable_intr_ppc(struct mrsas_instance *instance)
{
	uint32_t	mask;

	con_log(CL_ANN1, (CE_NOTE, "enable_intr_ppc: called"));

	if (instance->skinny) {
		/* For SKINNY, write ~0x1, from BSD's mfi driver. */
		WR_OB_INTR_MASK(0xfffffffe, instance);
	} else {
		/* WR_OB_DOORBELL_CLEAR(0xFFFFFFFF, instance); */
		WR_OB_DOORBELL_CLEAR(OB_DOORBELL_CLEAR_MASK, instance);

		/* WR_OB_INTR_MASK(~0x80000000, instance); */
		WR_OB_INTR_MASK(~(MFI_REPLY_2108_MESSAGE_INTR_MASK), instance);
	}

	/* dummy read to force PCI flush */
	mask = RD_OB_INTR_MASK(instance);

	con_log(CL_ANN1, (CE_NOTE, "enable_intr_ppc: "
	    "outbound_intr_mask = 0x%x", mask));
}

static void
disable_intr_ppc(struct mrsas_instance *instance)
{
	uint32_t	mask;

	con_log(CL_ANN1, (CE_NOTE, "disable_intr_ppc: called"));

	con_log(CL_ANN1, (CE_NOTE, "disable_intr_ppc: before : "
	    "outbound_intr_mask = 0x%x", RD_OB_INTR_MASK(instance)));

	/* For now, assume there are no extras needed for Skinny support. */

	WR_OB_INTR_MASK(OB_INTR_MASK, instance);

	con_log(CL_ANN1, (CE_NOTE, "disable_intr_ppc: after : "
	    "outbound_intr_mask = 0x%x", RD_OB_INTR_MASK(instance)));

	/* dummy read to force PCI flush */
	mask = RD_OB_INTR_MASK(instance);
#ifdef lint
	mask = mask;
#endif
}

static int
intr_ack_ppc(struct mrsas_instance *instance)
{
	uint32_t	status;
	int ret = DDI_INTR_CLAIMED;

	con_log(CL_ANN1, (CE_NOTE, "intr_ack_ppc: called"));

	/* check if it is our interrupt */
	status = RD_OB_INTR_STATUS(instance);

	con_log(CL_ANN1, (CE_NOTE, "intr_ack_ppc: status = 0x%x", status));

	/*
	 * NOTE:  Some drivers call out SKINNY here, but the return is the same
	 * for SKINNY and 2108.
	 */
	if (!(status & MFI_REPLY_2108_MESSAGE_INTR)) {
		ret = DDI_INTR_UNCLAIMED;
	}

	if (mrsas_check_acc_handle(instance->regmap_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);
		ret = DDI_INTR_UNCLAIMED;
	}

	if (ret == DDI_INTR_UNCLAIMED) {
		return (ret);
	}

	/*
	 * Clear the interrupt by writing back the same value.
	 * Another case where SKINNY is slightly different.
	 */
	if (instance->skinny) {
		WR_OB_INTR_STATUS(status, instance);
	} else {
		WR_OB_DOORBELL_CLEAR(status, instance);
	}

	/* dummy READ */
	status = RD_OB_INTR_STATUS(instance);

	con_log(CL_ANN1, (CE_NOTE, "intr_ack_ppc: interrupt cleared"));

	return (ret);
}

/*
 * Marks HBA as bad. This will be called either when an
 * IO packet times out even after 3 FW resets
 * or FW is found to be fault even after 3 continuous resets.
 */

static int
mrsas_kill_adapter(struct mrsas_instance *instance)
{
	if (instance->deadadapter == 1)
		return (DDI_FAILURE);

	con_log(CL_ANN1, (CE_NOTE, "mrsas_kill_adapter: "
	    "Writing to doorbell with MFI_STOP_ADP "));
	mutex_enter(&instance->ocr_flags_mtx);
	instance->deadadapter = 1;
	mutex_exit(&instance->ocr_flags_mtx);
	instance->func_ptr->disable_intr(instance);
	WR_IB_DOORBELL(MFI_STOP_ADP, instance);
	(void) mrsas_complete_pending_cmds(instance);
	return (DDI_SUCCESS);
}


static int
mrsas_reset_ppc(struct mrsas_instance *instance)
{
	uint32_t status;
	uint32_t retry = 0;
	uint32_t cur_abs_reg_val;
	uint32_t fw_state;

	con_log(CL_ANN, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	if (instance->deadadapter == 1) {
		dev_err(instance->dip, CE_WARN, "mrsas_reset_ppc: "
		    "no more resets as HBA has been marked dead ");
		return (DDI_FAILURE);
	}
	mutex_enter(&instance->ocr_flags_mtx);
	instance->adapterresetinprogress = 1;
	mutex_exit(&instance->ocr_flags_mtx);
	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc: adpterresetinprogress "
	    "flag set, time %llx", gethrtime()));

	instance->func_ptr->disable_intr(instance);
retry_reset:
	WR_IB_WRITE_SEQ(0, instance);
	WR_IB_WRITE_SEQ(4, instance);
	WR_IB_WRITE_SEQ(0xb, instance);
	WR_IB_WRITE_SEQ(2, instance);
	WR_IB_WRITE_SEQ(7, instance);
	WR_IB_WRITE_SEQ(0xd, instance);
	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc: magic number written "
	    "to write sequence register\n"));
	delay(100 * drv_usectohz(MILLISEC));
	status = RD_OB_DRWE(instance);

	while (!(status & DIAG_WRITE_ENABLE)) {
		delay(100 * drv_usectohz(MILLISEC));
		status = RD_OB_DRWE(instance);
		if (retry++ == 100) {
			dev_err(instance->dip, CE_WARN,
			    "mrsas_reset_ppc: DRWE bit "
			    "check retry count %d", retry);
			return (DDI_FAILURE);
		}
	}
	WR_IB_DRWE(status | DIAG_RESET_ADAPTER, instance);
	delay(100 * drv_usectohz(MILLISEC));
	status = RD_OB_DRWE(instance);
	while (status & DIAG_RESET_ADAPTER) {
		delay(100 * drv_usectohz(MILLISEC));
		status = RD_OB_DRWE(instance);
		if (retry++ == 100) {
			dev_err(instance->dip, CE_WARN, "mrsas_reset_ppc: "
			    "RESET FAILED. KILL adapter called.");

			(void) mrsas_kill_adapter(instance);
			return (DDI_FAILURE);
		}
	}
	con_log(CL_ANN, (CE_NOTE, "mrsas_reset_ppc: Adapter reset complete"));
	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc: "
	    "Calling mfi_state_transition_to_ready"));

	/* Mark HBA as bad, if FW is fault after 3 continuous resets */
	if (mfi_state_transition_to_ready(instance) ||
	    debug_fw_faults_after_ocr_g == 1) {
		cur_abs_reg_val =
		    instance->func_ptr->read_fw_status_reg(instance);
		fw_state	= cur_abs_reg_val & MFI_STATE_MASK;

#ifdef OCRDEBUG
		con_log(CL_ANN1, (CE_NOTE,
		    "mrsas_reset_ppc :before fake: FW is not ready "
		    "FW state = 0x%x", fw_state));
		if (debug_fw_faults_after_ocr_g == 1)
			fw_state = MFI_STATE_FAULT;
#endif

		con_log(CL_ANN1, (CE_NOTE,  "mrsas_reset_ppc : FW is not ready "
		    "FW state = 0x%x", fw_state));

		if (fw_state == MFI_STATE_FAULT) {
			/* increment the count */
			instance->fw_fault_count_after_ocr++;
			if (instance->fw_fault_count_after_ocr
			    < MAX_FW_RESET_COUNT) {
				dev_err(instance->dip, CE_WARN,
				    "mrsas_reset_ppc: "
				    "FW is in fault after OCR count %d "
				    "Retry Reset",
				    instance->fw_fault_count_after_ocr);
				goto retry_reset;

			} else {
				dev_err(instance->dip, CE_WARN,
				    "mrsas_reset_ppc: "
				    "Max Reset Count exceeded >%d"
				    "Mark HBA as bad, KILL adapter",
				    MAX_FW_RESET_COUNT);

				(void) mrsas_kill_adapter(instance);
				return (DDI_FAILURE);
			}
		}
	}
	/* reset the counter as FW is up after OCR */
	instance->fw_fault_count_after_ocr = 0;


	ddi_put32(instance->mfi_internal_dma_obj.acc_handle,
	    instance->producer, 0);

	ddi_put32(instance->mfi_internal_dma_obj.acc_handle,
	    instance->consumer, 0);

	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc: "
	    " after resetting produconsumer chck indexs:"
	    "producer %x consumer %x", *instance->producer,
	    *instance->consumer));

	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc: "
	    "Calling mrsas_issue_init_mfi"));
	(void) mrsas_issue_init_mfi(instance);
	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc: "
	    "mrsas_issue_init_mfi Done"));

	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc: "
	    "Calling mrsas_print_pending_cmd\n"));
	(void) mrsas_print_pending_cmds(instance);
	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc: "
	    "mrsas_print_pending_cmd done\n"));

	instance->func_ptr->enable_intr(instance);
	instance->fw_outstanding = 0;

	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc: "
	    "Calling mrsas_issue_pending_cmds"));
	(void) mrsas_issue_pending_cmds(instance);
	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc: "
	    "issue_pending_cmds done.\n"));

	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc: "
	    "Calling aen registration"));


	instance->aen_cmd->retry_count_for_ocr = 0;
	instance->aen_cmd->drv_pkt_time = 0;

	instance->func_ptr->issue_cmd(instance->aen_cmd, instance);
	con_log(CL_ANN1, (CE_NOTE, "Unsetting adpresetinprogress flag.\n"));

	mutex_enter(&instance->ocr_flags_mtx);
	instance->adapterresetinprogress = 0;
	mutex_exit(&instance->ocr_flags_mtx);
	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc: "
	    "adpterresetinprogress flag unset"));

	con_log(CL_ANN1, (CE_NOTE, "mrsas_reset_ppc done\n"));
	return (DDI_SUCCESS);
}

/*
 * FMA functions.
 */
int
mrsas_common_check(struct mrsas_instance *instance, struct  mrsas_cmd *cmd)
{
	int ret = DDI_SUCCESS;

	if (cmd != NULL &&
	    mrsas_check_dma_handle(cmd->frame_dma_obj.dma_handle) !=
	    DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_UNAFFECTED);
		if (cmd->pkt != NULL) {
			cmd->pkt->pkt_reason = CMD_TRAN_ERR;
			cmd->pkt->pkt_statistics = 0;
		}
		ret = DDI_FAILURE;
	}
	if (mrsas_check_dma_handle(instance->mfi_internal_dma_obj.dma_handle)
	    != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_UNAFFECTED);
		if (cmd != NULL && cmd->pkt != NULL) {
			cmd->pkt->pkt_reason = CMD_TRAN_ERR;
			cmd->pkt->pkt_statistics = 0;
		}
		ret = DDI_FAILURE;
	}
	if (mrsas_check_dma_handle(instance->mfi_evt_detail_obj.dma_handle) !=
	    DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_UNAFFECTED);
		if (cmd != NULL && cmd->pkt != NULL) {
			cmd->pkt->pkt_reason = CMD_TRAN_ERR;
			cmd->pkt->pkt_statistics = 0;
		}
		ret = DDI_FAILURE;
	}
	if (mrsas_check_acc_handle(instance->regmap_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_UNAFFECTED);

		ddi_fm_acc_err_clear(instance->regmap_handle, DDI_FME_VER0);

		if (cmd != NULL && cmd->pkt != NULL) {
			cmd->pkt->pkt_reason = CMD_TRAN_ERR;
			cmd->pkt->pkt_statistics = 0;
		}
		ret = DDI_FAILURE;
	}

	return (ret);
}

/*ARGSUSED*/
static int
mrsas_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	/*
	 * as the driver can always deal with an error in any dma or
	 * access handle, we can just return the fme_status value.
	 */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

static void
mrsas_fm_init(struct mrsas_instance *instance)
{
	/* Need to change iblock to priority for new MSI intr */
	ddi_iblock_cookie_t fm_ibc;

	/* Only register with IO Fault Services if we have some capability */
	if (instance->fm_capabilities) {
		/* Adjust access and dma attributes for FMA */
		endian_attr.devacc_attr_access = DDI_FLAGERR_ACC;
		mrsas_generic_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;

		/*
		 * Register capabilities with IO Fault Services.
		 * fm_capabilities will be updated to indicate
		 * capabilities actually supported (not requested.)
		 */

		ddi_fm_init(instance->dip, &instance->fm_capabilities, &fm_ibc);

		/*
		 * Initialize pci ereport capabilities if ereport
		 * capable (should always be.)
		 */

		if (DDI_FM_EREPORT_CAP(instance->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(instance->fm_capabilities)) {
			pci_ereport_setup(instance->dip);
		}

		/*
		 * Register error callback if error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(instance->fm_capabilities)) {
			ddi_fm_handler_register(instance->dip,
			    mrsas_fm_error_cb, (void*) instance);
		}
	} else {
		endian_attr.devacc_attr_access = DDI_DEFAULT_ACC;
		mrsas_generic_dma_attr.dma_attr_flags = 0;
	}
}

static void
mrsas_fm_fini(struct mrsas_instance *instance)
{
	/* Only unregister FMA capabilities if registered */
	if (instance->fm_capabilities) {
		/*
		 * Un-register error callback if error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(instance->fm_capabilities)) {
			ddi_fm_handler_unregister(instance->dip);
		}

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(instance->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(instance->fm_capabilities)) {
			pci_ereport_teardown(instance->dip);
		}

		/* Unregister from IO Fault Services */
		ddi_fm_fini(instance->dip);

		/* Adjust access and dma attributes for FMA */
		endian_attr.devacc_attr_access = DDI_DEFAULT_ACC;
		mrsas_generic_dma_attr.dma_attr_flags = 0;
	}
}

int
mrsas_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;

	if (handle == NULL) {
		return (DDI_FAILURE);
	}

	ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);

	return (de.fme_status);
}

int
mrsas_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t de;

	if (handle == NULL) {
		return (DDI_FAILURE);
	}

	ddi_fm_dma_err_get(handle, &de, DDI_FME_VERSION);

	return (de.fme_status);
}

void
mrsas_fm_ereport(struct mrsas_instance *instance, char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(instance->fm_capabilities)) {
		ddi_fm_ereport_post(instance->dip, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERSION, NULL);
	}
}

static int
mrsas_add_intrs(struct mrsas_instance *instance, int intr_type)
{

	dev_info_t *dip = instance->dip;
	int	avail, actual, count;
	int	i, flag, ret;

	con_log(CL_DLEVEL1, (CE_NOTE, "mrsas_add_intrs: intr_type = %x",
	    intr_type));

	/* Get number of interrupts */
	ret = ddi_intr_get_nintrs(dip, intr_type, &count);
	if ((ret != DDI_SUCCESS) || (count == 0)) {
		con_log(CL_ANN, (CE_WARN, "ddi_intr_get_nintrs() failed:"
		    "ret %d count %d", ret, count));

		return (DDI_FAILURE);
	}

	con_log(CL_DLEVEL1, (CE_NOTE, "mrsas_add_intrs: count = %d ", count));

	/* Get number of available interrupts */
	ret = ddi_intr_get_navail(dip, intr_type, &avail);
	if ((ret != DDI_SUCCESS) || (avail == 0)) {
		con_log(CL_ANN, (CE_WARN, "ddi_intr_get_navail() failed:"
		    "ret %d avail %d", ret, avail));

		return (DDI_FAILURE);
	}
	con_log(CL_DLEVEL1, (CE_NOTE, "mrsas_add_intrs: avail = %d ", avail));

	/* Only one interrupt routine. So limit the count to 1 */
	if (count > 1) {
		count = 1;
	}

	/*
	 * Allocate an array of interrupt handlers. Currently we support
	 * only one interrupt. The framework can be extended later.
	 */
	instance->intr_htable_size = count * sizeof (ddi_intr_handle_t);
	instance->intr_htable = kmem_zalloc(instance->intr_htable_size,
	    KM_SLEEP);
	ASSERT(instance->intr_htable);

	flag = ((intr_type == DDI_INTR_TYPE_MSI) ||
	    (intr_type == DDI_INTR_TYPE_MSIX)) ?
	    DDI_INTR_ALLOC_STRICT : DDI_INTR_ALLOC_NORMAL;

	/* Allocate interrupt */
	ret = ddi_intr_alloc(dip, instance->intr_htable, intr_type, 0,
	    count, &actual, flag);

	if ((ret != DDI_SUCCESS) || (actual == 0)) {
		con_log(CL_ANN, (CE_WARN, "mrsas_add_intrs: "
		    "avail = %d", avail));
		goto mrsas_free_htable;
	}

	if (actual < count) {
		con_log(CL_ANN, (CE_WARN, "mrsas_add_intrs: "
		    "Requested = %d  Received = %d", count, actual));
	}
	instance->intr_cnt = actual;

	/*
	 * Get the priority of the interrupt allocated.
	 */
	if ((ret = ddi_intr_get_pri(instance->intr_htable[0],
	    &instance->intr_pri)) != DDI_SUCCESS) {
		con_log(CL_ANN, (CE_WARN, "mrsas_add_intrs: "
		    "get priority call failed"));
		goto mrsas_free_handles;
	}

	/*
	 * Test for high level mutex. we don't support them.
	 */
	if (instance->intr_pri >= ddi_intr_get_hilevel_pri()) {
		con_log(CL_ANN, (CE_WARN, "mrsas_add_intrs: "
		    "High level interrupts not supported."));
		goto mrsas_free_handles;
	}

	con_log(CL_DLEVEL1, (CE_NOTE, "mrsas_add_intrs: intr_pri = 0x%x ",
	    instance->intr_pri));

	/* Call ddi_intr_add_handler() */
	for (i = 0; i < actual; i++) {
		ret = ddi_intr_add_handler(instance->intr_htable[i],
		    (ddi_intr_handler_t *)mrsas_isr, (caddr_t)instance,
		    (caddr_t)(uintptr_t)i);

		if (ret != DDI_SUCCESS) {
			con_log(CL_ANN, (CE_WARN, "mrsas_add_intrs:"
			    "failed %d", ret));
			goto mrsas_free_handles;
		}

	}

	con_log(CL_DLEVEL1, (CE_NOTE, " ddi_intr_add_handler done"));

	if ((ret = ddi_intr_get_cap(instance->intr_htable[0],
	    &instance->intr_cap)) != DDI_SUCCESS) {
		con_log(CL_ANN, (CE_WARN, "ddi_intr_get_cap() failed %d",
		    ret));
		goto mrsas_free_handlers;
	}

	if (instance->intr_cap &  DDI_INTR_FLAG_BLOCK) {
		con_log(CL_ANN, (CE_WARN, "Calling ddi_intr_block _enable"));

		(void) ddi_intr_block_enable(instance->intr_htable,
		    instance->intr_cnt);
	} else {
		con_log(CL_ANN, (CE_NOTE, " calling ddi_intr_enable"));

		for (i = 0; i < instance->intr_cnt; i++) {
			(void) ddi_intr_enable(instance->intr_htable[i]);
			con_log(CL_ANN, (CE_NOTE, "ddi intr enable returns "
			    "%d", i));
		}
	}

	return (DDI_SUCCESS);

mrsas_free_handlers:
	for (i = 0; i < actual; i++)
		(void) ddi_intr_remove_handler(instance->intr_htable[i]);

mrsas_free_handles:
	for (i = 0; i < actual; i++)
		(void) ddi_intr_free(instance->intr_htable[i]);

mrsas_free_htable:
	if (instance->intr_htable != NULL)
		kmem_free(instance->intr_htable, instance->intr_htable_size);

	instance->intr_htable = NULL;
	instance->intr_htable_size = 0;

	return (DDI_FAILURE);

}


static void
mrsas_rem_intrs(struct mrsas_instance *instance)
{
	int i;

	con_log(CL_ANN, (CE_NOTE, "mrsas_rem_intrs called"));

	/* Disable all interrupts first */
	if (instance->intr_cap & DDI_INTR_FLAG_BLOCK) {
		(void) ddi_intr_block_disable(instance->intr_htable,
		    instance->intr_cnt);
	} else {
		for (i = 0; i < instance->intr_cnt; i++) {
			(void) ddi_intr_disable(instance->intr_htable[i]);
		}
	}

	/* Remove all the handlers */

	for (i = 0; i < instance->intr_cnt; i++) {
		(void) ddi_intr_remove_handler(instance->intr_htable[i]);
		(void) ddi_intr_free(instance->intr_htable[i]);
	}

	if (instance->intr_htable != NULL)
		kmem_free(instance->intr_htable, instance->intr_htable_size);

	instance->intr_htable = NULL;
	instance->intr_htable_size = 0;

}

static int
mrsas_tran_bus_config(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
	struct mrsas_instance *instance;
	int config;
	int rval  = NDI_SUCCESS;

	char *ptr = NULL;
	int tgt, lun;

	con_log(CL_ANN1, (CE_NOTE, "Bus config called for op = %x", op));

	if ((instance = ddi_get_soft_state(mrsas_state,
	    ddi_get_instance(parent))) == NULL) {
		return (NDI_FAILURE);
	}

	/* Hold nexus during bus_config */
	ndi_devi_enter(parent, &config);
	switch (op) {
	case BUS_CONFIG_ONE: {

		/* parse wwid/target name out of name given */
		if ((ptr = strchr((char *)arg, '@')) == NULL) {
			rval = NDI_FAILURE;
			break;
		}
		ptr++;

		if (mrsas_parse_devname(arg, &tgt, &lun) != 0) {
			rval = NDI_FAILURE;
			break;
		}

		if (lun == 0) {
			rval = mrsas_config_ld(instance, tgt, lun, childp);
		} else if ((instance->tbolt || instance->skinny) && lun != 0) {
			rval = mrsas_tbolt_config_pd(instance,
			    tgt, lun, childp);
		} else {
			rval = NDI_FAILURE;
		}

		break;
	}
	case BUS_CONFIG_DRIVER:
	case BUS_CONFIG_ALL: {

		rval = mrsas_config_all_devices(instance);

		rval = NDI_SUCCESS;
		break;
	}
	}

	if (rval == NDI_SUCCESS) {
		rval = ndi_busop_bus_config(parent, flags, op, arg, childp, 0);

	}
	ndi_devi_exit(parent, config);

	con_log(CL_ANN1, (CE_NOTE, "mrsas_tran_bus_config: rval = %x",
	    rval));
	return (rval);
}

static int
mrsas_config_all_devices(struct mrsas_instance *instance)
{
	int rval, tgt;

	for (tgt = 0; tgt < MRDRV_MAX_LD; tgt++) {
		(void) mrsas_config_ld(instance, tgt, 0, NULL);

	}

	/* Config PD devices connected to the card */
	if (instance->tbolt || instance->skinny) {
		for (tgt = 0; tgt < instance->mr_tbolt_pd_max; tgt++) {
			(void) mrsas_tbolt_config_pd(instance, tgt, 1, NULL);
		}
	}

	rval = NDI_SUCCESS;
	return (rval);
}

static int
mrsas_parse_devname(char *devnm, int *tgt, int *lun)
{
	char devbuf[SCSI_MAXNAMELEN];
	char *addr;
	char *p,  *tp, *lp;
	long num;

	/* Parse dev name and address */
	(void) strcpy(devbuf, devnm);
	addr = "";
	for (p = devbuf; *p != '\0'; p++) {
		if (*p == '@') {
			addr = p + 1;
			*p = '\0';
		} else if (*p == ':') {
			*p = '\0';
			break;
		}
	}

	/* Parse target and lun */
	for (p = tp = addr, lp = NULL; *p != '\0'; p++) {
		if (*p == ',') {
			lp = p + 1;
			*p = '\0';
			break;
		}
	}
	if (tgt && tp) {
		if (ddi_strtol(tp, NULL, 0x10, &num)) {
			return (DDI_FAILURE); /* Can declare this as constant */
		}
			*tgt = (int)num;
	}
	if (lun && lp) {
		if (ddi_strtol(lp, NULL, 0x10, &num)) {
			return (DDI_FAILURE);
		}
			*lun = (int)num;
	}
	return (DDI_SUCCESS);  /* Success case */
}

static int
mrsas_config_ld(struct mrsas_instance *instance, uint16_t tgt,
    uint8_t lun, dev_info_t **ldip)
{
	struct scsi_device *sd;
	dev_info_t *child;
	int rval;

	con_log(CL_DLEVEL1, (CE_NOTE, "mrsas_config_ld: t = %d l = %d",
	    tgt, lun));

	if ((child = mrsas_find_child(instance, tgt, lun)) != NULL) {
		if (ldip) {
			*ldip = child;
		}
		if (instance->mr_ld_list[tgt].flag != MRDRV_TGT_VALID) {
			rval = mrsas_service_evt(instance, tgt, 0,
			    MRSAS_EVT_UNCONFIG_TGT, NULL);
			con_log(CL_ANN1, (CE_WARN,
			    "mr_sas: DELETING STALE ENTRY rval = %d "
			    "tgt id = %d ", rval, tgt));
			return (NDI_FAILURE);
		}
		return (NDI_SUCCESS);
	}

	sd = kmem_zalloc(sizeof (struct scsi_device), KM_SLEEP);
	sd->sd_address.a_hba_tran = instance->tran;
	sd->sd_address.a_target = (uint16_t)tgt;
	sd->sd_address.a_lun = (uint8_t)lun;

	if (scsi_hba_probe(sd, NULL) == SCSIPROBE_EXISTS)
		rval = mrsas_config_scsi_device(instance, sd, ldip);
	else
		rval = NDI_FAILURE;

	/* sd_unprobe is blank now. Free buffer manually */
	if (sd->sd_inq) {
		kmem_free(sd->sd_inq, SUN_INQSIZE);
		sd->sd_inq = (struct scsi_inquiry *)NULL;
	}

	kmem_free(sd, sizeof (struct scsi_device));
	con_log(CL_DLEVEL1, (CE_NOTE, "mrsas_config_ld: return rval = %d",
	    rval));
	return (rval);
}

int
mrsas_config_scsi_device(struct mrsas_instance *instance,
    struct scsi_device *sd, dev_info_t **dipp)
{
	char *nodename = NULL;
	char **compatible = NULL;
	int ncompatible = 0;
	char *childname;
	dev_info_t *ldip = NULL;
	int tgt = sd->sd_address.a_target;
	int lun = sd->sd_address.a_lun;
	int dtype = sd->sd_inq->inq_dtype & DTYPE_MASK;
	int rval;

	con_log(CL_DLEVEL1, (CE_NOTE, "mr_sas: scsi_device t%dL%d", tgt, lun));
	scsi_hba_nodename_compatible_get(sd->sd_inq, NULL, dtype,
	    NULL, &nodename, &compatible, &ncompatible);

	if (nodename == NULL) {
		con_log(CL_ANN1, (CE_WARN, "mr_sas: Found no compatible driver "
		    "for t%dL%d", tgt, lun));
		rval = NDI_FAILURE;
		goto finish;
	}

	childname = (dtype == DTYPE_DIRECT) ? "sd" : nodename;
	con_log(CL_DLEVEL1, (CE_NOTE,
	    "mr_sas: Childname = %2s nodename = %s", childname, nodename));

	/* Create a dev node */
	rval = ndi_devi_alloc(instance->dip, childname, DEVI_SID_NODEID, &ldip);
	con_log(CL_DLEVEL1, (CE_NOTE,
	    "mr_sas_config_scsi_device: ndi_devi_alloc rval = %x", rval));
	if (rval == NDI_SUCCESS) {
		if (ndi_prop_update_int(DDI_DEV_T_NONE, ldip, "target", tgt) !=
		    DDI_PROP_SUCCESS) {
			con_log(CL_ANN1, (CE_WARN, "mr_sas: unable to create "
			    "property for t%dl%d target", tgt, lun));
			rval = NDI_FAILURE;
			goto finish;
		}
		if (ndi_prop_update_int(DDI_DEV_T_NONE, ldip, "lun", lun) !=
		    DDI_PROP_SUCCESS) {
			con_log(CL_ANN1, (CE_WARN, "mr_sas: unable to create "
			    "property for t%dl%d lun", tgt, lun));
			rval = NDI_FAILURE;
			goto finish;
		}

		if (ndi_prop_update_string_array(DDI_DEV_T_NONE, ldip,
		    "compatible", compatible, ncompatible) !=
		    DDI_PROP_SUCCESS) {
			con_log(CL_ANN1, (CE_WARN, "mr_sas: unable to create "
			    "property for t%dl%d compatible", tgt, lun));
			rval = NDI_FAILURE;
			goto finish;
		}

		rval = ndi_devi_online(ldip, NDI_ONLINE_ATTACH);
		if (rval != NDI_SUCCESS) {
			con_log(CL_ANN1, (CE_WARN, "mr_sas: unable to online "
			    "t%dl%d", tgt, lun));
			ndi_prop_remove_all(ldip);
			(void) ndi_devi_free(ldip);
		} else {
			con_log(CL_ANN1, (CE_CONT, "mr_sas: online Done :"
			    "0 t%dl%d", tgt, lun));
		}

	}
finish:
	if (dipp) {
		*dipp = ldip;
	}

	con_log(CL_DLEVEL1, (CE_NOTE,
	    "mr_sas: config_scsi_device rval = %d t%dL%d",
	    rval, tgt, lun));
	scsi_hba_nodename_compatible_free(nodename, compatible);
	return (rval);
}

/*ARGSUSED*/
int
mrsas_service_evt(struct mrsas_instance *instance, int tgt, int lun, int event,
    uint64_t wwn)
{
	struct mrsas_eventinfo *mrevt = NULL;

	con_log(CL_ANN1, (CE_NOTE,
	    "mrsas_service_evt called for t%dl%d event = %d",
	    tgt, lun, event));

	if ((instance->taskq == NULL) || (mrevt =
	    kmem_zalloc(sizeof (struct mrsas_eventinfo), KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}

	mrevt->instance = instance;
	mrevt->tgt = tgt;
	mrevt->lun = lun;
	mrevt->event = event;
	mrevt->wwn = wwn;

	if ((ddi_taskq_dispatch(instance->taskq,
	    (void (*)(void *))mrsas_issue_evt_taskq, mrevt, DDI_NOSLEEP)) !=
	    DDI_SUCCESS) {
		con_log(CL_ANN1, (CE_NOTE,
		    "mr_sas: Event task failed for t%dl%d event = %d",
		    tgt, lun, event));
		kmem_free(mrevt, sizeof (struct mrsas_eventinfo));
		return (DDI_FAILURE);
	}
	DTRACE_PROBE3(service_evt, int, tgt, int, lun, int, event);
	return (DDI_SUCCESS);
}

static void
mrsas_issue_evt_taskq(struct mrsas_eventinfo *mrevt)
{
	struct mrsas_instance *instance = mrevt->instance;
	dev_info_t *dip, *pdip;
	int circ1 = 0;
	char *devname;

	con_log(CL_ANN1, (CE_NOTE, "mrsas_issue_evt_taskq: called for"
	    " tgt %d lun %d event %d",
	    mrevt->tgt, mrevt->lun, mrevt->event));

	if (mrevt->tgt < MRDRV_MAX_LD && mrevt->lun == 0) {
		mutex_enter(&instance->config_dev_mtx);
		dip = instance->mr_ld_list[mrevt->tgt].dip;
		mutex_exit(&instance->config_dev_mtx);
	} else {
		mutex_enter(&instance->config_dev_mtx);
		dip = instance->mr_tbolt_pd_list[mrevt->tgt].dip;
		mutex_exit(&instance->config_dev_mtx);
	}


	ndi_devi_enter(instance->dip, &circ1);
	switch (mrevt->event) {
	case MRSAS_EVT_CONFIG_TGT:
		if (dip == NULL) {

			if (mrevt->lun == 0) {
				(void) mrsas_config_ld(instance, mrevt->tgt,
				    0, NULL);
			} else if (instance->tbolt || instance->skinny) {
				(void) mrsas_tbolt_config_pd(instance,
				    mrevt->tgt,
				    1, NULL);
			}
			con_log(CL_ANN1, (CE_NOTE,
			    "mr_sas: EVT_CONFIG_TGT called:"
			    " for tgt %d lun %d event %d",
			    mrevt->tgt, mrevt->lun, mrevt->event));

		} else {
			con_log(CL_ANN1, (CE_NOTE,
			    "mr_sas: EVT_CONFIG_TGT dip != NULL:"
			    " for tgt %d lun %d event %d",
			    mrevt->tgt, mrevt->lun, mrevt->event));
		}
		break;
	case MRSAS_EVT_UNCONFIG_TGT:
		if (dip) {
			if (i_ddi_devi_attached(dip)) {

				pdip = ddi_get_parent(dip);

				devname = kmem_zalloc(MAXNAMELEN + 1, KM_SLEEP);
				(void) ddi_deviname(dip, devname);

				(void) devfs_clean(pdip, devname + 1,
				    DV_CLEAN_FORCE);
				kmem_free(devname, MAXNAMELEN + 1);
			}
			(void) ndi_devi_offline(dip, NDI_DEVI_REMOVE);
			con_log(CL_ANN1, (CE_NOTE,
			    "mr_sas: EVT_UNCONFIG_TGT called:"
			    " for tgt %d lun %d event %d",
			    mrevt->tgt, mrevt->lun, mrevt->event));
		} else {
			con_log(CL_ANN1, (CE_NOTE,
			    "mr_sas: EVT_UNCONFIG_TGT dip == NULL:"
			    " for tgt %d lun %d event %d",
			    mrevt->tgt, mrevt->lun, mrevt->event));
		}
		break;
	}
	kmem_free(mrevt, sizeof (struct mrsas_eventinfo));
	ndi_devi_exit(instance->dip, circ1);
}


int
mrsas_mode_sense_build(struct scsi_pkt *pkt)
{
	union scsi_cdb		*cdbp;
	uint16_t		page_code;
	struct scsa_cmd		*acmd;
	struct buf		*bp;
	struct mode_header	*modehdrp;

	cdbp = (void *)pkt->pkt_cdbp;
	page_code = cdbp->cdb_un.sg.scsi[0];
	acmd = PKT2CMD(pkt);
	bp = acmd->cmd_buf;
	if ((!bp) && bp->b_un.b_addr && bp->b_bcount && acmd->cmd_dmacount) {
		con_log(CL_ANN1, (CE_WARN, "Failing MODESENSE Command"));
		/* ADD pkt statistics as Command failed. */
		return (NULL);
	}

	bp_mapin(bp);
	bzero(bp->b_un.b_addr, bp->b_bcount);

	switch (page_code) {
		case 0x3: {
			struct mode_format *page3p = NULL;
			modehdrp = (struct mode_header *)(bp->b_un.b_addr);
			modehdrp->bdesc_length = MODE_BLK_DESC_LENGTH;

			page3p = (void *)((caddr_t)modehdrp +
			    MODE_HEADER_LENGTH + MODE_BLK_DESC_LENGTH);
			page3p->mode_page.code = 0x3;
			page3p->mode_page.length =
			    (uchar_t)(sizeof (struct mode_format));
			page3p->data_bytes_sect = 512;
			page3p->sect_track = 63;
			break;
		}
		case 0x4: {
			struct mode_geometry *page4p = NULL;
			modehdrp = (struct mode_header *)(bp->b_un.b_addr);
			modehdrp->bdesc_length = MODE_BLK_DESC_LENGTH;

			page4p = (void *)((caddr_t)modehdrp +
			    MODE_HEADER_LENGTH + MODE_BLK_DESC_LENGTH);
			page4p->mode_page.code = 0x4;
			page4p->mode_page.length =
			    (uchar_t)(sizeof (struct mode_geometry));
			page4p->heads = 255;
			page4p->rpm = 10000;
			break;
		}
		default:
			break;
	}
	return (NULL);
}
