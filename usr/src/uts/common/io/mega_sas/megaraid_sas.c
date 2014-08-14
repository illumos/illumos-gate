/*
 * megaraid_sas.c: source for mega_sas driver
 *
 * MegaRAID device driver for SAS controllers
 * Copyright (c) 2005-2008, LSI Logic Corporation.
 * All rights reserved.
 *
 * Version:
 * Author:
 *        	Rajesh Prabhakaran<Rajesh.Prabhakaran@lsil.com>
 *        	Seokmann Ju
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
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

#include "megaraid_sas.h"

/*
 * FMA header files
 */
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

/*
 * Local static data
 */
static void	*megasas_state = NULL;
static int 	debug_level_g = CL_ANN;

#pragma weak scsi_hba_open
#pragma weak scsi_hba_close
#pragma weak scsi_hba_ioctl

static ddi_dma_attr_t megasas_generic_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0,			/* low DMA address range */
	0xFFFFFFFFU,		/* high DMA address range */
	0xFFFFFFFFU,		/* DMA counter register  */
	8,			/* DMA address alignment */
	0x07,			/* DMA burstsizes  */
	1,			/* min DMA size */
	0xFFFFFFFFU,		/* max DMA size */
	0xFFFFFFFFU,		/* segment boundary */
	MEGASAS_MAX_SGE_CNT,	/* dma_attr_sglen */
	512,			/* granularity of device */
	0			/* bus specific DMA flags */
};

int32_t megasas_max_cap_maxxfer = 0x1000000;

/*
 * cb_ops contains base level routines
 */
static struct cb_ops megasas_cb_ops = {
	megasas_open,		/* open */
	megasas_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	megasas_ioctl,		/* ioctl */
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
static struct dev_ops megasas_ops = {
	DEVO_REV,		/* rev, */
	0,			/* refcnt */
	megasas_getinfo,	/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	megasas_attach,		/* attach */
	megasas_detach,		/* detach */
	megasas_reset,		/* reset */
	&megasas_cb_ops,	/* char/block ops */
	NULL,			/* bus ops */
	NULL,			/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* module type - driver */
	MEGASAS_VERSION,
	&megasas_ops,		/* driver ops */
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


/*
 * ************************************************************************** *
 *                                                                            *
 *         common entry points - for loadable kernel modules                  *
 *                                                                            *
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

	ret = ddi_soft_state_init(&megasas_state,
	    sizeof (struct megasas_instance), 0);

	if (ret != 0) {
		con_log(CL_ANN, (CE_WARN, "megaraid: could not init state"));
		return (ret);
	}

	if ((ret = scsi_hba_init(&modlinkage)) != 0) {
		con_log(CL_ANN, (CE_WARN, "megaraid: could not init scsi hba"));
		ddi_soft_state_fini(&megasas_state);
		return (ret);
	}

	ret = mod_install(&modlinkage);

	if (ret != 0) {
		con_log(CL_ANN, (CE_WARN, "megaraid: mod_install failed"));
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini(&megasas_state);
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

	if ((ret = mod_remove(&modlinkage)) != 0)
		return (ret);

	scsi_hba_fini(&modlinkage);

	ddi_soft_state_fini(&megasas_state);

	return (ret);
}


/*
 * ************************************************************************** *
 *                                                                            *
 *               common entry points - for autoconfiguration                  *
 *                                                                            *
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
megasas_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance_no;
	int		nregs;
	uint8_t		added_isr_f = 0;
	uint8_t		added_soft_isr_f = 0;
	uint8_t		create_devctl_node_f = 0;
	uint8_t		create_scsi_node_f = 0;
	uint8_t		create_ioc_node_f = 0;
	uint8_t		tran_alloc_f = 0;
	uint8_t 	irq;
	uint16_t	vendor_id;
	uint16_t	device_id;
	uint16_t	subsysvid;
	uint16_t	subsysid;
	uint16_t	command;

	scsi_hba_tran_t		*tran;
	ddi_dma_attr_t  tran_dma_attr;
	struct megasas_instance	*instance;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	instance_no = ddi_get_instance(dip);

	/*
	 * Since we know that some instantiations of this device can be
	 * plugged into slave-only SBus slots, check to see whether this is
	 * one such.
	 */
	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		con_log(CL_ANN, (CE_WARN,
		    "mega%d: Device in slave-only slot, unused", instance_no));
		return (DDI_FAILURE);
	}

	switch (cmd) {
		case DDI_ATTACH:
			con_log(CL_DLEVEL1, (CE_NOTE, "megasas: DDI_ATTACH"));
			/* allocate the soft state for the instance */
			if (ddi_soft_state_zalloc(megasas_state, instance_no)
			    != DDI_SUCCESS) {
				con_log(CL_ANN, (CE_WARN,
				    "mega%d: Failed to allocate soft state",
				    instance_no));

				return (DDI_FAILURE);
			}

			instance = (struct megasas_instance *)ddi_get_soft_state
			    (megasas_state, instance_no);

			if (instance == NULL) {
				con_log(CL_ANN, (CE_WARN,
				    "mega%d: Bad soft state", instance_no));

				ddi_soft_state_free(megasas_state, instance_no);

				return (DDI_FAILURE);
			}

			bzero((caddr_t)instance,
			    sizeof (struct megasas_instance));

			instance->func_ptr = kmem_zalloc(
			    sizeof (struct megasas_func_ptr), KM_SLEEP);
			ASSERT(instance->func_ptr);

			/* Setup the PCI configuration space handles */
			if (pci_config_setup(dip, &instance->pci_handle) !=
			    DDI_SUCCESS) {
				con_log(CL_ANN, (CE_WARN,
				    "mega%d: pci config setup failed ",
				    instance_no));

				kmem_free(instance->func_ptr,
				    sizeof (struct megasas_func_ptr));
				ddi_soft_state_free(megasas_state, instance_no);

				return (DDI_FAILURE);
			}

			if (ddi_dev_nregs(dip, &nregs) != DDI_SUCCESS) {
				con_log(CL_ANN, (CE_WARN,
				    "megaraid: failed to get registers."));

				pci_config_teardown(&instance->pci_handle);
				kmem_free(instance->func_ptr,
				    sizeof (struct megasas_func_ptr));
				ddi_soft_state_free(megasas_state, instance_no);

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

			con_log(CL_DLEVEL1, (CE_CONT, "megasas%d: "
			    "0x%x:0x%x 0x%x:0x%x, irq:%d drv-ver:%s\n",
			    instance_no, vendor_id, device_id, subsysvid,
			    subsysid, irq, MEGASAS_VERSION));

			/* enable bus-mastering */
			command = pci_config_get16(instance->pci_handle,
			    PCI_CONF_COMM);

			if (!(command & PCI_COMM_ME)) {
				command |= PCI_COMM_ME;

				pci_config_put16(instance->pci_handle,
				    PCI_CONF_COMM, command);

				con_log(CL_ANN, (CE_CONT, "megaraid%d: "
				    "enable bus-mastering\n", instance_no));
			} else {
				con_log(CL_DLEVEL1, (CE_CONT, "megaraid%d: "
				"bus-mastering already set\n", instance_no));
			}

			/* initialize function pointers */
			if ((device_id == PCI_DEVICE_ID_LSI_1078) ||
			    (device_id == PCI_DEVICE_ID_LSI_1078DE)) {
				con_log(CL_DLEVEL1, (CE_CONT, "megasas%d: "
				    "1078R/DE detected\n", instance_no));
				instance->func_ptr->read_fw_status_reg =
				    read_fw_status_reg_ppc;
				instance->func_ptr->issue_cmd = issue_cmd_ppc;
				instance->func_ptr->issue_cmd_in_sync_mode =
				    issue_cmd_in_sync_mode_ppc;
				instance->func_ptr->issue_cmd_in_poll_mode =
				    issue_cmd_in_poll_mode_ppc;
				instance->func_ptr->enable_intr =
				    enable_intr_ppc;
				instance->func_ptr->disable_intr =
				    disable_intr_ppc;
				instance->func_ptr->intr_ack = intr_ack_ppc;
			} else {
				con_log(CL_DLEVEL1, (CE_CONT, "megasas%d: "
				    "1064/8R detected\n", instance_no));
				instance->func_ptr->read_fw_status_reg =
				    read_fw_status_reg_xscale;
				instance->func_ptr->issue_cmd =
				    issue_cmd_xscale;
				instance->func_ptr->issue_cmd_in_sync_mode =
				    issue_cmd_in_sync_mode_xscale;
				instance->func_ptr->issue_cmd_in_poll_mode =
				    issue_cmd_in_poll_mode_xscale;
				instance->func_ptr->enable_intr =
				    enable_intr_xscale;
				instance->func_ptr->disable_intr =
				    disable_intr_xscale;
				instance->func_ptr->intr_ack =
				    intr_ack_xscale;
			}

			instance->baseaddress = pci_config_get32(
			    instance->pci_handle, PCI_CONF_BASE0);
			instance->baseaddress &= 0x0fffc;

			instance->dip		= dip;
			instance->vendor_id	= vendor_id;
			instance->device_id	= device_id;
			instance->subsysvid	= subsysvid;
			instance->subsysid	= subsysid;

			/* Initialize FMA */
			instance->fm_capabilities = ddi_prop_get_int(
			    DDI_DEV_T_ANY, instance->dip, DDI_PROP_DONTPASS,
			    "fm-capable", DDI_FM_EREPORT_CAPABLE |
			    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE
			    | DDI_FM_ERRCB_CAPABLE);

			megasas_fm_init(instance);

			/* setup the mfi based low level driver */
			if (init_mfi(instance) != DDI_SUCCESS) {
				con_log(CL_ANN, (CE_WARN, "megaraid: "
				"could not initialize the low level driver"));

				goto fail_attach;
			}

			/*
			 * Allocate the interrupt blocking cookie.
			 * It represents the information the framework
			 * needs to block interrupts. This cookie will
			 * be used by the locks shared accross our ISR.
			 * These locks must be initialized before we
			 * register our ISR.
			 * ddi_add_intr(9F)
			 */
			if (ddi_get_iblock_cookie(dip, 0,
			    &instance->iblock_cookie) != DDI_SUCCESS) {

				goto fail_attach;
			}

			if (ddi_get_soft_iblock_cookie(dip, DDI_SOFTINT_HIGH,
			    &instance->soft_iblock_cookie) != DDI_SUCCESS) {

				goto fail_attach;
			}

			/*
			 * Initialize the driver mutexes common to
			 * normal/high level isr
			 */
			if (ddi_intr_hilevel(dip, 0)) {
				instance->isr_level = HIGH_LEVEL_INTR;
				mutex_init(&instance->cmd_pool_mtx,
				    "cmd_pool_mtx", MUTEX_DRIVER,
				    instance->soft_iblock_cookie);
				mutex_init(&instance->cmd_pend_mtx,
				    "cmd_pend_mtx", MUTEX_DRIVER,
				    instance->soft_iblock_cookie);
			} else {
				/*
				 * Initialize the driver mutexes
				 * specific to soft-isr
				 */
				instance->isr_level = NORMAL_LEVEL_INTR;
				mutex_init(&instance->cmd_pool_mtx,
				    "cmd_pool_mtx", MUTEX_DRIVER,
				    instance->iblock_cookie);
				mutex_init(&instance->cmd_pend_mtx,
				    "cmd_pend_mtx", MUTEX_DRIVER,
				    instance->iblock_cookie);
			}

			mutex_init(&instance->completed_pool_mtx,
			    "completed_pool_mtx", MUTEX_DRIVER,
			    instance->iblock_cookie);
			mutex_init(&instance->int_cmd_mtx, "int_cmd_mtx",
			    MUTEX_DRIVER, instance->iblock_cookie);
			mutex_init(&instance->aen_cmd_mtx, "aen_cmd_mtx",
			    MUTEX_DRIVER, instance->iblock_cookie);
			mutex_init(&instance->abort_cmd_mtx, "abort_cmd_mtx",
			    MUTEX_DRIVER, instance->iblock_cookie);

			cv_init(&instance->int_cmd_cv, NULL, CV_DRIVER, NULL);
			cv_init(&instance->abort_cmd_cv, NULL, CV_DRIVER, NULL);

			INIT_LIST_HEAD(&instance->completed_pool_list);

			/* Register our isr. */
			if (ddi_add_intr(dip, 0, NULL, NULL, megasas_isr,
			    (caddr_t)instance) != DDI_SUCCESS) {
				con_log(CL_ANN, (CE_WARN,
				    " ISR did not register"));

				goto fail_attach;
			}

			added_isr_f = 1;

			/* Register our soft-isr for highlevel interrupts. */
			if (instance->isr_level == HIGH_LEVEL_INTR) {
				if (ddi_add_softintr(dip, DDI_SOFTINT_HIGH,
				    &instance->soft_intr_id, NULL, NULL,
				    megasas_softintr, (caddr_t)instance) !=
				    DDI_SUCCESS) {
					con_log(CL_ANN, (CE_WARN,
					    " Software ISR did not register"));

					goto fail_attach;
				}

				added_soft_isr_f = 1;
			}

			/* Allocate a transport structure */
			tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP);

			if (tran == NULL) {
				con_log(CL_ANN, (CE_WARN,
				    "scsi_hba_tran_alloc failed"));
				goto fail_attach;
			}

			tran_alloc_f = 1;

			instance->tran = tran;

			tran->tran_hba_private	= instance;
			tran->tran_tgt_private 	= NULL;
			tran->tran_tgt_init	= megasas_tran_tgt_init;
			tran->tran_tgt_probe	= scsi_hba_probe;
			tran->tran_tgt_free	= (void (*)())NULL;
			tran->tran_init_pkt	= megasas_tran_init_pkt;
			tran->tran_start	= megasas_tran_start;
			tran->tran_abort	= megasas_tran_abort;
			tran->tran_reset	= megasas_tran_reset;
			tran->tran_bus_reset	= megasas_tran_bus_reset;
			tran->tran_getcap	= megasas_tran_getcap;
			tran->tran_setcap	= megasas_tran_setcap;
			tran->tran_destroy_pkt	= megasas_tran_destroy_pkt;
			tran->tran_dmafree	= megasas_tran_dmafree;
			tran->tran_sync_pkt	= megasas_tran_sync_pkt;
			tran->tran_reset_notify	= NULL;
			tran->tran_quiesce	= megasas_tran_quiesce;
			tran->tran_unquiesce	= megasas_tran_unquiesce;

			tran_dma_attr = megasas_generic_dma_attr;
			tran_dma_attr.dma_attr_sgllen = instance->max_num_sge;

			/* Attach this instance of the hba */
			if (scsi_hba_attach_setup(dip, &tran_dma_attr, tran, 0)
			    != DDI_SUCCESS) {
				con_log(CL_ANN, (CE_WARN,
				    "scsi_hba_attach failed\n"));

				goto fail_attach;
			}

			/* create devctl node for cfgadm command */
			if (ddi_create_minor_node(dip, "devctl",
			    S_IFCHR, INST2DEVCTL(instance_no),
			    DDI_NT_SCSI_NEXUS, 0) == DDI_FAILURE) {
				con_log(CL_ANN, (CE_WARN,
				    "megaraid: failed to create devctl node."));

				goto fail_attach;
			}

			create_devctl_node_f = 1;

			/* create scsi node for cfgadm command */
			if (ddi_create_minor_node(dip, "scsi", S_IFCHR,
			    INST2SCSI(instance_no),
			    DDI_NT_SCSI_ATTACHMENT_POINT, 0) ==
			    DDI_FAILURE) {
				con_log(CL_ANN, (CE_WARN,
				    "megaraid: failed to create scsi node."));

				goto fail_attach;
			}

			create_scsi_node_f = 1;

			(void) sprintf(instance->iocnode, "%d:lsirdctl",
			    instance_no);

			/*
			 * Create a node for applications
			 * for issuing ioctl to the driver.
			 */
			if (ddi_create_minor_node(dip, instance->iocnode,
			    S_IFCHR, INST2LSIRDCTL(instance_no),
			    DDI_PSEUDO, 0) == DDI_FAILURE) {
				con_log(CL_ANN, (CE_WARN,
				    "megaraid: failed to create ioctl node."));

				goto fail_attach;
			}

			create_ioc_node_f = 1;

			/* enable interrupt */
			instance->func_ptr->enable_intr(instance);

			/* initiate AEN */
			if (start_mfi_aen(instance)) {
				con_log(CL_ANN, (CE_WARN,
				    "megaraid: failed to initiate AEN."));
				goto fail_initiate_aen;
			}

			con_log(CL_DLEVEL1, (CE_NOTE,
			    "AEN started for instance %d.", instance_no));

			/* Finally! We are on the air.  */
			ddi_report_dev(dip);

			if (megasas_check_acc_handle(instance->regmap_handle) !=
			    DDI_SUCCESS) {
				goto fail_attach;
			}
			if (megasas_check_acc_handle(instance->pci_handle) !=
			    DDI_SUCCESS) {
				goto fail_attach;
			}
			break;
		case DDI_PM_RESUME:
			con_log(CL_ANN, (CE_NOTE,
			    "megasas: DDI_PM_RESUME"));
			break;
		case DDI_RESUME:
			con_log(CL_ANN, (CE_NOTE,
			    "megasas: DDI_RESUME"));
			break;
		default:
			con_log(CL_ANN, (CE_WARN,
			    "megasas: invalid attach cmd=%x", cmd));
			return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);

fail_initiate_aen:
fail_attach:
	if (create_devctl_node_f) {
		ddi_remove_minor_node(dip, "devctl");
	}

	if (create_scsi_node_f) {
		ddi_remove_minor_node(dip, "scsi");
	}

	if (create_ioc_node_f) {
		ddi_remove_minor_node(dip, instance->iocnode);
	}

	if (tran_alloc_f) {
		scsi_hba_tran_free(tran);
	}


	if (added_soft_isr_f) {
		ddi_remove_softintr(instance->soft_intr_id);
	}

	if (added_isr_f) {
		ddi_remove_intr(dip, 0, instance->iblock_cookie);
	}

	megasas_fm_ereport(instance, DDI_FM_DEVICE_NO_RESPONSE);
	ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);

	megasas_fm_fini(instance);

	pci_config_teardown(&instance->pci_handle);

	ddi_soft_state_free(megasas_state, instance_no);

	con_log(CL_ANN, (CE_NOTE,
	    "megasas: return failure from mega_attach\n"));

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
megasas_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,  void *arg, void **resultp)
{
	int	rval;
	int	megasas_minor = getminor((dev_t)arg);

	struct megasas_instance	*instance;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	switch (cmd) {
		case DDI_INFO_DEVT2DEVINFO:
			instance = (struct megasas_instance *)
			    ddi_get_soft_state(megasas_state,
			    MINOR2INST(megasas_minor));

			if (instance == NULL) {
				*resultp = NULL;
				rval = DDI_FAILURE;
			} else {
				*resultp = instance->dip;
				rval = DDI_SUCCESS;
			}
			break;
		case DDI_INFO_DEVT2INSTANCE:
			*resultp = (void *)instance;
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
megasas_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int	instance_no;

	struct megasas_instance	*instance;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	instance_no = ddi_get_instance(dip);

	instance = (struct megasas_instance *)ddi_get_soft_state(megasas_state,
	    instance_no);

	if (!instance) {
		con_log(CL_ANN, (CE_WARN,
		    "megasas:%d could not get instance in detach",
		    instance_no));

		return (DDI_FAILURE);
	}

	con_log(CL_ANN, (CE_NOTE,
	    "megasas%d: detaching device 0x%4x:0x%4x:0x%4x:0x%4x\n",
	    instance_no, instance->vendor_id, instance->device_id,
	    instance->subsysvid, instance->subsysid));

	switch (cmd) {
		case DDI_DETACH:
			con_log(CL_ANN, (CE_NOTE,
			    "megasas_detach: DDI_DETACH\n"));

			if (scsi_hba_detach(dip) != DDI_SUCCESS) {
				con_log(CL_ANN, (CE_WARN,
				    "megasas:%d failed to detach",
				    instance_no));

				return (DDI_FAILURE);
			}

			scsi_hba_tran_free(instance->tran);

			if (abort_aen_cmd(instance, instance->aen_cmd)) {
				con_log(CL_ANN, (CE_WARN, "megasas_detach: "
				    "failed to abort prevous AEN command\n"));

				return (DDI_FAILURE);
			}

			instance->func_ptr->disable_intr(instance);

			if (instance->isr_level == HIGH_LEVEL_INTR) {
				ddi_remove_softintr(instance->soft_intr_id);
			}

			ddi_remove_intr(dip, 0, instance->iblock_cookie);

			free_space_for_mfi(instance);

			megasas_fm_fini(instance);

			pci_config_teardown(&instance->pci_handle);

			kmem_free(instance->func_ptr,
			    sizeof (struct megasas_func_ptr));

			ddi_soft_state_free(megasas_state, instance_no);
			break;
		case DDI_PM_SUSPEND:
			con_log(CL_ANN, (CE_NOTE,
			    "megasas_detach: DDI_PM_SUSPEND\n"));

			break;
		case DDI_SUSPEND:
			con_log(CL_ANN, (CE_NOTE,
			    "megasas_detach: DDI_SUSPEND\n"));

			break;
		default:
			con_log(CL_ANN, (CE_WARN,
			    "invalid detach command:0x%x", cmd));
			return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * ************************************************************************** *
 *                                                                            *
 *             common entry points - for character driver types               *
 *                                                                            *
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
static  int
megasas_open(dev_t *dev, int openflags, int otyp, cred_t *credp)
{
	int	rval = 0;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	/* Check root permissions */
	if (drv_priv(credp) != 0) {
		con_log(CL_ANN, (CE_WARN,
		    "megaraid: Non-root ioctl access tried!"));
		return (EPERM);
	}

	/* Verify we are being opened as a character device */
	if (otyp != OTYP_CHR) {
		con_log(CL_ANN, (CE_WARN,
		    "megaraid: ioctl node must be a char node\n"));
		return (EINVAL);
	}

	if (ddi_get_soft_state(megasas_state, MINOR2INST(getminor(*dev)))
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
static  int
megasas_close(dev_t dev, int openflags, int otyp, cred_t *credp)
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
megasas_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int	rval = 0;

	struct megasas_instance	*instance;
	struct megasas_ioctl	ioctl;
	struct megasas_aen	aen;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	instance = ddi_get_soft_state(megasas_state, MINOR2INST(getminor(dev)));

	if (instance == NULL) {
		/* invalid minor number */
		con_log(CL_ANN, (CE_WARN, "megaraid: adapter not found."));
		return (ENXIO);
	}

	switch ((uint_t)cmd) {
		case MEGASAS_IOCTL_FIRMWARE:
			if (ddi_copyin((void *) arg, &ioctl,
			    sizeof (struct megasas_ioctl), mode)) {
				con_log(CL_ANN, (CE_WARN, "megasas_ioctl: "
				    "ERROR IOCTL copyin"));
				return (EFAULT);
			}

			if (ioctl.control_code == MR_DRIVER_IOCTL_COMMON) {
				rval = handle_drv_ioctl(instance, &ioctl, mode);
			} else {
				rval = handle_mfi_ioctl(instance, &ioctl, mode);
			}

			if (ddi_copyout((void *) &ioctl, (void *)arg,
			    (sizeof (struct megasas_ioctl) - 1), mode)) {
				con_log(CL_ANN, (CE_WARN,
				    "megasas_ioctl: copy_to_user failed\n"));
				rval = 1;
			}

			break;
		case MEGASAS_IOCTL_AEN:
			if (ddi_copyin((void *) arg, &aen,
			    sizeof (struct megasas_aen), mode)) {
				con_log(CL_ANN, (CE_WARN,
				    "megasas_ioctl: ERROR AEN copyin"));
				return (EFAULT);
			}

			rval = handle_mfi_aen(instance, &aen);

			if (ddi_copyout((void *) &aen, (void *)arg,
			    sizeof (struct megasas_aen), mode)) {
				con_log(CL_ANN, (CE_WARN,
				    "megasas_ioctl: copy_to_user failed\n"));
				rval = 1;
			}

			break;
		default:
			rval = scsi_hba_ioctl(dev, cmd, arg,
			    mode, credp, rvalp);

			con_log(CL_DLEVEL1, (CE_NOTE, "megasas_ioctl: "
			    "scsi_hba_ioctl called, ret = %x.", rval));
	}

	return (rval);
}

/*
 * ************************************************************************** *
 *                                                                            *
 *               common entry points - for block driver types                 *
 *                                                                            *
 * ************************************************************************** *
 */
/*
 * reset - TBD
 * @dip:
 * @cmd:
 *
 * TBD
 */
/*ARGSUSED*/
static int
megasas_reset(dev_info_t *dip, ddi_reset_cmd_t cmd)
{
	int	instance_no;

	struct megasas_instance	*instance;

	instance_no = ddi_get_instance(dip);
	instance = (struct megasas_instance *)ddi_get_soft_state
	    (megasas_state, instance_no);

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	if (!instance) {
		con_log(CL_ANN, (CE_WARN,
		    "megaraid:%d could not get adapter in reset",
		    instance_no));
		return (DDI_FAILURE);
	}

	con_log(CL_ANN, (CE_NOTE, "flushing cache for instance %d ..",
	    instance_no));

	flush_cache(instance);

	return (DDI_SUCCESS);
}


/*
 * ************************************************************************** *
 *                                                                            *
 *                          entry points (SCSI HBA)                           *
 *                                                                            *
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
megasas_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
		scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

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
megasas_tran_init_pkt(struct scsi_address *ap, register struct scsi_pkt *pkt,
	struct buf *bp, int cmdlen, int statuslen, int tgtlen,
	int flags, int (*callback)(), caddr_t arg)
{
	struct scsa_cmd	*acmd;
	struct megasas_instance	*instance;
	struct scsi_pkt	*new_pkt;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	instance = ADDR2MEGA(ap);

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
			if (megasas_dma_alloc(instance, pkt, bp, flags,
			    callback) == -1) {
				if (new_pkt) {
					scsi_hba_pkt_free(ap, new_pkt);
				}

				return ((struct scsi_pkt *)NULL);
			}
		} else {
			if (megasas_dma_move(instance, pkt, bp) == -1) {
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
megasas_tran_start(struct scsi_address *ap, register struct scsi_pkt *pkt)
{
	uchar_t 	cmd_done = 0;

	struct megasas_instance	*instance = ADDR2MEGA(ap);
	struct megasas_cmd	*cmd;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d:SCSI CDB[0]=0x%x",
	    __func__, __LINE__, pkt->pkt_cdbp[0]));

	pkt->pkt_reason	= CMD_CMPLT;
	*pkt->pkt_scbp = STATUS_GOOD; /* clear arq scsi_status */

	cmd = build_cmd(instance, ap, pkt, &cmd_done);

	/*
	 * Check if the command is already completed by the mega_build_cmd()
	 * routine. In which case the busy_flag would be clear and scb will be
	 * NULL and appropriate reason provided in pkt_reason field
	 */
	if (cmd_done) {
		if ((pkt->pkt_flags & FLAG_NOINTR) == 0) {
			scsi_hba_pkt_comp(pkt);
		}
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_scbp[0] = STATUS_GOOD;
		pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET
		    | STATE_SENT_CMD;
		return (TRAN_ACCEPT);
	}

	if (cmd == NULL) {
		return (TRAN_BUSY);
	}

	if ((pkt->pkt_flags & FLAG_NOINTR) == 0) {
		if (instance->fw_outstanding > instance->max_fw_cmds) {
			con_log(CL_ANN, (CE_CONT, "megasas:Firmware busy"));
			return_mfi_pkt(instance, cmd);
			return (TRAN_BUSY);
		}

		/* Syncronize the Cmd frame for the controller */
		(void) ddi_dma_sync(cmd->frame_dma_obj.dma_handle, 0, 0,
		    DDI_DMA_SYNC_FORDEV);

		instance->func_ptr->issue_cmd(cmd, instance);

	} else {
		struct megasas_header *hdr = &cmd->frame->hdr;

		cmd->sync_cmd = MEGASAS_TRUE;

		instance->func_ptr-> issue_cmd_in_poll_mode(instance, cmd);

		pkt->pkt_reason		= CMD_CMPLT;
		pkt->pkt_statistics	= 0;
		pkt->pkt_state |= STATE_XFERRED_DATA | STATE_GOT_STATUS;

		switch (hdr->cmd_status) {
		case MFI_STAT_OK:
			pkt->pkt_scbp[0] = STATUS_GOOD;
			break;

		case MFI_STAT_SCSI_DONE_WITH_ERROR:

			pkt->pkt_reason	= CMD_CMPLT;
			pkt->pkt_statistics = 0;

			((struct scsi_status *)pkt->pkt_scbp)->sts_chk = 1;
			break;

		case MFI_STAT_DEVICE_NOT_FOUND:
			pkt->pkt_reason		= CMD_DEV_GONE;
			pkt->pkt_statistics	= STAT_DISCON;
			break;

		default:
			((struct scsi_status *)pkt->pkt_scbp)->sts_busy = 1;
		}

		return_mfi_pkt(instance, cmd);
		(void) megasas_common_check(instance, cmd);

		scsi_hba_pkt_comp(pkt);

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
megasas_tran_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	/* aborting command not supported by H/W */

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
megasas_tran_reset(struct scsi_address *ap, int level)
{
	struct megasas_instance *instance = ADDR2MEGA(ap);

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	if (wait_for_outstanding(instance)) {
		return (DDI_FAILURE);
	} else {
		return (DDI_SUCCESS);
	}
}

/*
 * tran_bus_reset - reset the SCSI bus
 * @dip:
 * @level:
 *
 * The tran_bus_reset() vector in the scsi_hba_tran structure should be
 * initialized during the HBA driver's attach(). The vector should point to
 * an HBA entry point that is to be called when a user initiates a bus reset.
 * Implementation is hardware specific. If the HBA driver cannot reset the
 * SCSI bus without affecting the targets, the driver should fail RESET_BUS
 * or not initialize this vector.
 */
/*ARGSUSED*/
static int
megasas_tran_bus_reset(dev_info_t *dip, int level)
{
	int	instance_no = ddi_get_instance(dip);

	struct megasas_instance	*instance = ddi_get_soft_state(megasas_state,
	    instance_no);

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	if (wait_for_outstanding(instance)) {
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
megasas_tran_getcap(struct scsi_address *ap, char *cap, int whom)
{
	int	rval = 0;

	struct megasas_instance	*instance = ADDR2MEGA(ap);

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	/* we do allow inquiring about capabilities for other targets */
	if (cap == NULL) {
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
		case SCSI_CAP_DMA_MAX:
			/* Limit to 16MB max transfer */
			rval = megasas_max_cap_maxxfer;
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
megasas_tran_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	int		rval = 1;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

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
megasas_tran_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct scsa_cmd *acmd = PKT2CMD(pkt);

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

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
megasas_tran_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
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
megasas_tran_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	/*
	 * following 'ddi_dma_sync()' API call
	 * already called for each I/O in the ISR
	 */
#if 0
	int	i;

	register struct scsa_cmd	*acmd = PKT2CMD(pkt);

	if (acmd->cmd_flags & CFLAG_DMAVALID) {
		(void) ddi_dma_sync(acmd->cmd_dmahandle, acmd->cmd_dma_offset,
		    acmd->cmd_dma_len, (acmd->cmd_flags & CFLAG_DMASEND) ?
		    DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU);
	}
#endif
}

/*ARGSUSED*/
static int
megasas_tran_quiesce(dev_info_t *dip)
{
	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	return (1);
}

/*ARGSUSED*/
static int
megasas_tran_unquiesce(dev_info_t *dip)
{
	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	return (1);
}

/*
 * megasas_isr(caddr_t)
 *
 * The Interrupt Service Routine
 *
 * Collect status for all completed commands and do callback
 *
 */
static uint_t
megasas_isr(struct megasas_instance *instance)
{
	int		need_softintr;
	uint32_t	producer;
	uint32_t	consumer;
	uint32_t	context;

	struct megasas_cmd	*cmd;

	con_log(CL_ANN1, (CE_NOTE, "chkpnt:%s:%d", __func__, __LINE__));

	ASSERT(instance);
	if (!instance->func_ptr->intr_ack(instance)) {
		return (DDI_INTR_UNCLAIMED);
	}

	(void) ddi_dma_sync(instance->mfi_internal_dma_obj.dma_handle,
	    0, 0, DDI_DMA_SYNC_FORCPU);

	if (megasas_check_dma_handle(instance->mfi_internal_dma_obj.dma_handle)
	    != DDI_SUCCESS) {
		megasas_fm_ereport(instance, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);
		return (DDI_INTR_UNCLAIMED);
	}

	producer = *instance->producer;
	consumer = *instance->consumer;

	con_log(CL_ANN1, (CE_CONT, " producer %x consumer %x ",
	    producer, consumer));

	mutex_enter(&instance->completed_pool_mtx);

	while (consumer != producer) {
		context = instance->reply_queue[consumer];
		cmd = instance->cmd_list[context];
		mlist_add_tail(&cmd->list, &instance->completed_pool_list);

		consumer++;
		if (consumer == (instance->max_fw_cmds + 1)) {
			consumer = 0;
		}
	}

	mutex_exit(&instance->completed_pool_mtx);

	*instance->consumer = consumer;
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
		(void) megasas_softintr(instance);
	}

	return (DDI_INTR_CLAIMED);
}


/*
 * ************************************************************************** *
 *                                                                            *
 *                                  libraries                                 *
 *                                                                            *
 * ************************************************************************** *
 */
/*
 * get_mfi_pkt : Get a command from the free pool
 */
static struct megasas_cmd *
get_mfi_pkt(struct megasas_instance *instance)
{
	mlist_t 		*head = &instance->cmd_pool_list;
	struct megasas_cmd	*cmd = NULL;

	mutex_enter(&instance->cmd_pool_mtx);
	ASSERT(mutex_owned(&instance->cmd_pool_mtx));

	if (!mlist_empty(head)) {
		cmd = mlist_entry(head->next, struct megasas_cmd, list);
		mlist_del_init(head->next);
	}
	if (cmd != NULL)
		cmd->pkt = NULL;
	mutex_exit(&instance->cmd_pool_mtx);

	return (cmd);
}

/*
 * return_mfi_pkt : Return a cmd to free command pool
 */
static void
return_mfi_pkt(struct megasas_instance *instance, struct megasas_cmd *cmd)
{
	mutex_enter(&instance->cmd_pool_mtx);
	ASSERT(mutex_owned(&instance->cmd_pool_mtx));

	mlist_add(&cmd->list, &instance->cmd_pool_list);

	mutex_exit(&instance->cmd_pool_mtx);
}

/*
 * destroy_mfi_frame_pool
 */
static void
destroy_mfi_frame_pool(struct megasas_instance *instance)
{
	int		i;
	uint32_t	max_cmd = instance->max_fw_cmds;

	struct megasas_cmd	*cmd;

	/* return all frames to pool */
	for (i = 0; i < max_cmd; i++) {

		cmd = instance->cmd_list[i];

		if (cmd->frame_dma_obj_status == DMA_OBJ_ALLOCATED)
			(void) mega_free_dma_obj(instance, cmd->frame_dma_obj);

		cmd->frame_dma_obj_status  = DMA_OBJ_FREED;
	}

}

/*
 * create_mfi_frame_pool
 */
static int
create_mfi_frame_pool(struct megasas_instance *instance)
{
	int		i = 0;
	int		cookie_cnt;
	uint16_t	max_cmd;
	uint16_t	sge_sz;
	uint32_t	sgl_sz;
	uint32_t	tot_frame_size;

	struct megasas_cmd	*cmd;

	max_cmd = instance->max_fw_cmds;

	sge_sz	= sizeof (struct megasas_sge64);

	/* calculated the number of 64byte frames required for SGL */
	sgl_sz		= sge_sz * instance->max_num_sge;
	tot_frame_size	= sgl_sz + MEGAMFI_FRAME_SIZE + SENSE_LENGTH;

	con_log(CL_DLEVEL3, (CE_NOTE, "create_mfi_frame_pool: "
	    "sgl_sz %x tot_frame_size %x", sgl_sz, tot_frame_size));

	while (i < max_cmd) {
		cmd = instance->cmd_list[i];

		cmd->frame_dma_obj.size	= tot_frame_size;
		cmd->frame_dma_obj.dma_attr = megasas_generic_dma_attr;
		cmd->frame_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		cmd->frame_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
		cmd->frame_dma_obj.dma_attr.dma_attr_sgllen = 1;
		cmd->frame_dma_obj.dma_attr.dma_attr_align = 64;


		cookie_cnt = mega_alloc_dma_obj(instance, &cmd->frame_dma_obj);

		if (cookie_cnt == -1 || cookie_cnt > 1) {
			con_log(CL_ANN, (CE_WARN,
			    "create_mfi_frame_pool: could not alloc."));
			return (DDI_FAILURE);
		}

		bzero(cmd->frame_dma_obj.buffer, tot_frame_size);

		cmd->frame_dma_obj_status = DMA_OBJ_ALLOCATED;
		cmd->frame = (union megasas_frame *)cmd->frame_dma_obj.buffer;
		cmd->frame_phys_addr =
		    cmd->frame_dma_obj.dma_cookie[0].dmac_address;

		cmd->sense = (uint8_t *)(((unsigned long)
		    cmd->frame_dma_obj.buffer) +
		    tot_frame_size - SENSE_LENGTH);
		cmd->sense_phys_addr =
		    cmd->frame_dma_obj.dma_cookie[0].dmac_address +
		    tot_frame_size - SENSE_LENGTH;

		if (!cmd->frame || !cmd->sense) {
			con_log(CL_ANN, (CE_NOTE,
			    "megasas: pci_pool_alloc failed \n"));

			return (-ENOMEM);
		}

		cmd->frame->io.context = cmd->index;
		i++;

		con_log(CL_DLEVEL3, (CE_NOTE, "[%x]-%x",
		    cmd->frame->io.context, cmd->frame_phys_addr));
	}

	return (DDI_SUCCESS);
}

/*
 * free_additional_dma_buffer
 */
static void
free_additional_dma_buffer(struct megasas_instance *instance)
{
	if (instance->mfi_internal_dma_obj.status == DMA_OBJ_ALLOCATED) {
		(void) mega_free_dma_obj(instance,
		    instance->mfi_internal_dma_obj);
		instance->mfi_internal_dma_obj.status = DMA_OBJ_FREED;
	}

	if (instance->mfi_evt_detail_obj.status == DMA_OBJ_ALLOCATED) {
		(void) mega_free_dma_obj(instance,
		    instance->mfi_evt_detail_obj);
		instance->mfi_evt_detail_obj.status = DMA_OBJ_FREED;
	}
}

/*
 * alloc_additional_dma_buffer
 */
static int
alloc_additional_dma_buffer(struct megasas_instance *instance)
{
	uint32_t	reply_q_sz;
	uint32_t	internal_buf_size = PAGESIZE*2;

	/* max cmds plus 1 + producer & consumer */
	reply_q_sz = sizeof (uint32_t) * (instance->max_fw_cmds + 1 + 2);

	instance->mfi_internal_dma_obj.size = internal_buf_size;
	instance->mfi_internal_dma_obj.dma_attr	= megasas_generic_dma_attr;
	instance->mfi_internal_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
	instance->mfi_internal_dma_obj.dma_attr.dma_attr_count_max =
	    0xFFFFFFFFU;
	instance->mfi_internal_dma_obj.dma_attr.dma_attr_sgllen	= 1;

	if (mega_alloc_dma_obj(instance, &instance->mfi_internal_dma_obj)
	    != 1) {
		con_log(CL_ANN, (CE_WARN, "megaraid: could not alloc reply Q"));
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
	    reply_q_sz;
	instance->internal_buf_size = internal_buf_size -
	    (reply_q_sz + 8);

	/* allocate evt_detail */
	instance->mfi_evt_detail_obj.size = sizeof (struct megasas_evt_detail);
	instance->mfi_evt_detail_obj.dma_attr = megasas_generic_dma_attr;
	instance->mfi_evt_detail_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
	instance->mfi_evt_detail_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
	instance->mfi_evt_detail_obj.dma_attr.dma_attr_sgllen = 1;
	instance->mfi_evt_detail_obj.dma_attr.dma_attr_align = 1;

	if (mega_alloc_dma_obj(instance, &instance->mfi_evt_detail_obj) != 1) {
		con_log(CL_ANN, (CE_WARN, "alloc_additional_dma_buffer: "
		    "could not data transfer buffer alloc."));
		return (DDI_FAILURE);
	}

	bzero(instance->mfi_evt_detail_obj.buffer,
	    sizeof (struct megasas_evt_detail));

	instance->mfi_evt_detail_obj.status |= DMA_OBJ_ALLOCATED;

	return (DDI_SUCCESS);
}

/*
 * free_space_for_mfi
 */
static void
free_space_for_mfi(struct megasas_instance *instance)
{
	int		i;
	uint32_t	max_cmd = instance->max_fw_cmds;

	/* already freed */
	if (instance->cmd_list == NULL) {
		return;
	}

	free_additional_dma_buffer(instance);

	/* first free the MFI frame pool */
	destroy_mfi_frame_pool(instance);

	/* free all the commands in the cmd_list */
	for (i = 0; i < instance->max_fw_cmds; i++) {
		kmem_free(instance->cmd_list[i],
		    sizeof (struct megasas_cmd));

		instance->cmd_list[i] = NULL;
	}

	/* free the cmd_list buffer itself */
	kmem_free(instance->cmd_list,
	    sizeof (struct megasas_cmd *) * max_cmd);

	instance->cmd_list = NULL;

	INIT_LIST_HEAD(&instance->cmd_pool_list);
}

/*
 * alloc_space_for_mfi
 */
static int
alloc_space_for_mfi(struct megasas_instance *instance)
{
	int		i;
	uint32_t	max_cmd;
	size_t		sz;

	struct megasas_cmd	*cmd;

	max_cmd = instance->max_fw_cmds;
	sz = sizeof (struct megasas_cmd *) * max_cmd;

	/*
	 * instance->cmd_list is an array of struct megasas_cmd pointers.
	 * Allocate the dynamic array first and then allocate individual
	 * commands.
	 */
	instance->cmd_list = kmem_zalloc(sz, KM_SLEEP);
	ASSERT(instance->cmd_list);

	for (i = 0; i < max_cmd; i++) {
		instance->cmd_list[i] = kmem_zalloc(sizeof (struct megasas_cmd),
		    KM_SLEEP);
		ASSERT(instance->cmd_list[i]);
	}

	INIT_LIST_HEAD(&instance->cmd_pool_list);

	/* add all the commands to command pool (instance->cmd_pool) */
	for (i = 0; i < max_cmd; i++) {
		cmd		= instance->cmd_list[i];
		cmd->index	= i;

		mlist_add_tail(&cmd->list, &instance->cmd_pool_list);
	}

	/* create a frame pool and assign one frame to each cmd */
	if (create_mfi_frame_pool(instance)) {
		con_log(CL_ANN, (CE_NOTE, "error creating frame DMA pool\n"));
		return (DDI_FAILURE);
	}

	/* create a frame pool and assign one frame to each cmd */
	if (alloc_additional_dma_buffer(instance)) {
		con_log(CL_ANN, (CE_NOTE, "error creating frame DMA pool\n"));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * get_ctrl_info
 */
static int
get_ctrl_info(struct megasas_instance *instance,
    struct megasas_ctrl_info *ctrl_info)
{
	int	ret = 0;

	struct megasas_cmd		*cmd;
	struct megasas_dcmd_frame	*dcmd;
	struct megasas_ctrl_info	*ci;

	cmd = get_mfi_pkt(instance);

	if (!cmd) {
		con_log(CL_ANN, (CE_WARN,
		    "Failed to get a cmd for ctrl info\n"));
		return (DDI_FAILURE);
	}

	dcmd = &cmd->frame->dcmd;

	ci = (struct megasas_ctrl_info *)instance->internal_buf;

	if (!ci) {
		con_log(CL_ANN, (CE_WARN,
		    "Failed to alloc mem for ctrl info\n"));
		return_mfi_pkt(instance, cmd);
		return (DDI_FAILURE);
	}

	(void) memset(ci, 0, sizeof (struct megasas_ctrl_info));

	/* for( i = 0; i < DCMD_MBOX_SZ; i++ ) dcmd->mbox.b[i] = 0; */
	(void) memset(dcmd->mbox.b, 0, DCMD_MBOX_SZ);

	dcmd->cmd			= MFI_CMD_OP_DCMD;
	dcmd->cmd_status		= MFI_CMD_STATUS_POLL_MODE;
	dcmd->sge_count			= 1;
	dcmd->flags			= MFI_FRAME_DIR_READ;
	dcmd->timeout			= 0;
	dcmd->data_xfer_len		= sizeof (struct megasas_ctrl_info);
	dcmd->opcode			= MR_DCMD_CTRL_GET_INFO;
	dcmd->sgl.sge32[0].phys_addr	= instance->internal_buf_dmac_add;
	dcmd->sgl.sge32[0].length	= sizeof (struct megasas_ctrl_info);

	cmd->frame_count = 1;

	if (!instance->func_ptr->issue_cmd_in_poll_mode(instance, cmd)) {
		ret = 0;
		(void) memcpy(ctrl_info, ci, sizeof (struct megasas_ctrl_info));
	} else {
		con_log(CL_ANN, (CE_WARN, "get_ctrl_info: Ctrl info failed\n"));
		ret = -1;
	}

	return_mfi_pkt(instance, cmd);
	if (megasas_common_check(instance, cmd) != DDI_SUCCESS) {
		ret = -1;
	}

	return (ret);
}

/*
 * abort_aen_cmd
 */
static int
abort_aen_cmd(struct megasas_instance *instance,
    struct megasas_cmd *cmd_to_abort)
{
	int	ret = 0;

	struct megasas_cmd		*cmd;
	struct megasas_abort_frame	*abort_fr;

	cmd = get_mfi_pkt(instance);

	if (!cmd) {
		con_log(CL_ANN, (CE_WARN,
		    "Failed to get a cmd for ctrl info\n"));
		return (DDI_FAILURE);
	}

	abort_fr = &cmd->frame->abort;

	/* prepare and issue the abort frame */
	abort_fr->cmd = MFI_CMD_OP_ABORT;
	abort_fr->cmd_status = MFI_CMD_STATUS_SYNC_MODE;
	abort_fr->flags = 0;
	abort_fr->abort_context = cmd_to_abort->index;
	abort_fr->abort_mfi_phys_addr_lo = cmd_to_abort->frame_phys_addr;
	abort_fr->abort_mfi_phys_addr_hi = 0;

	instance->aen_cmd->abort_aen = 1;

	cmd->sync_cmd = MEGASAS_TRUE;
	cmd->frame_count = 1;

	if (instance->func_ptr->issue_cmd_in_sync_mode(instance, cmd)) {
		con_log(CL_ANN, (CE_WARN,
		    "abort_aen_cmd: issue_cmd_in_sync_mode failed\n"));
		ret = -1;
	} else {
		ret = 0;
	}

	instance->aen_cmd->abort_aen = 1;
	instance->aen_cmd = 0;

	return_mfi_pkt(instance, cmd);
	(void) megasas_common_check(instance, cmd);

	return (ret);
}

/*
 * init_mfi
 */
static int
init_mfi(struct megasas_instance *instance)
{
	off_t				reglength;
	struct megasas_cmd		*cmd;
	struct megasas_ctrl_info	ctrl_info;
	struct megasas_init_frame	*init_frame;
	struct megasas_init_queue_info	*initq_info;

	if ((ddi_dev_regsize(instance->dip, REGISTER_SET_IO, &reglength)
	    != DDI_SUCCESS) || reglength < MINIMUM_MFI_MEM_SZ) {
		return (DDI_FAILURE);
	}

	if (reglength > DEFAULT_MFI_MEM_SZ) {
		reglength = DEFAULT_MFI_MEM_SZ;
		con_log(CL_DLEVEL1, (CE_NOTE,
		    "mega: register length to map is 0x%lx bytes", reglength));
	}

	if (ddi_regs_map_setup(instance->dip, REGISTER_SET_IO,
	    &instance->regmap, 0, reglength, &endian_attr,
	    &instance->regmap_handle) != DDI_SUCCESS) {
		con_log(CL_ANN, (CE_NOTE,
		    "megaraid: couldn't map control registers"));

		goto fail_mfi_reg_setup;
	}

	/* we expect the FW state to be READY */
	if (mfi_state_transition_to_ready(instance)) {
		con_log(CL_ANN, (CE_WARN, "megaraid: F/W is not ready"));
		goto fail_ready_state;
	}

	/* get various operational parameters from status register */
	instance->max_num_sge =
	    (instance->func_ptr->read_fw_status_reg(instance) &
	    0xFF0000) >> 0x10;
	/*
	 * Reduce the max supported cmds by 1. This is to ensure that the
	 * reply_q_sz (1 more than the max cmd that driver may send)
	 * does not exceed max cmds that the FW can support
	 */
	instance->max_fw_cmds =
	    instance->func_ptr->read_fw_status_reg(instance) & 0xFFFF;
	instance->max_fw_cmds = instance->max_fw_cmds - 1;

	instance->max_num_sge =
	    (instance->max_num_sge > MEGASAS_MAX_SGE_CNT) ?
	    MEGASAS_MAX_SGE_CNT : instance->max_num_sge;

	/* create a pool of commands */
	if (alloc_space_for_mfi(instance))
		goto fail_alloc_fw_space;

	/* disable interrupt for initial preparation */
	instance->func_ptr->disable_intr(instance);

	/*
	 * Prepare a init frame. Note the init frame points to queue info
	 * structure. Each frame has SGL allocated after first 64 bytes. For
	 * this frame - since we don't need any SGL - we use SGL's space as
	 * queue info structure
	 */
	cmd = get_mfi_pkt(instance);

	init_frame = (struct megasas_init_frame *)cmd->frame;
	initq_info = (struct megasas_init_queue_info *)
	    ((unsigned long)init_frame + 64);

	(void) memset(init_frame, 0, MEGAMFI_FRAME_SIZE);
	(void) memset(initq_info, 0, sizeof (struct megasas_init_queue_info));

	initq_info->init_flags = 0;

	initq_info->reply_queue_entries	= instance->max_fw_cmds + 1;

	initq_info->producer_index_phys_addr_hi	= 0;
	initq_info->producer_index_phys_addr_lo =
	    instance->mfi_internal_dma_obj.dma_cookie[0].dmac_address;

	initq_info->consumer_index_phys_addr_hi = 0;
	initq_info->consumer_index_phys_addr_lo =
	    instance->mfi_internal_dma_obj.dma_cookie[0].dmac_address + 4;

	initq_info->reply_queue_start_phys_addr_hi = 0;
	initq_info->reply_queue_start_phys_addr_lo =
	    instance->mfi_internal_dma_obj.dma_cookie[0].dmac_address + 8;

	init_frame->cmd				= MFI_CMD_OP_INIT;
	init_frame->cmd_status			= MFI_CMD_STATUS_POLL_MODE;
	init_frame->flags			= 0;
	init_frame->queue_info_new_phys_addr_lo	=
	    cmd->frame_phys_addr + 64;
	init_frame->queue_info_new_phys_addr_hi	= 0;

	init_frame->data_xfer_len = sizeof (struct megasas_init_queue_info);

	cmd->frame_count = 1;

	/* issue the init frame in polled mode */
	if (instance->func_ptr->issue_cmd_in_poll_mode(instance, cmd)) {
		con_log(CL_ANN, (CE_WARN, "failed to init firmware"));
		goto fail_fw_init;
	}

	return_mfi_pkt(instance, cmd);
	if (megasas_common_check(instance, cmd) != DDI_SUCCESS) {
		goto fail_fw_init;
	}

	/* gather misc FW related information */
	if (!get_ctrl_info(instance, &ctrl_info)) {
		instance->max_sectors_per_req = ctrl_info.max_request_size;
		con_log(CL_ANN1, (CE_NOTE, "product name %s ld present %d",
		    ctrl_info.product_name, ctrl_info.ld_present_count));
	} else {
		instance->max_sectors_per_req = instance->max_num_sge *
		    PAGESIZE / 512;
	}

	if (megasas_check_acc_handle(instance->regmap_handle) != DDI_SUCCESS) {
		goto fail_fw_init;
	}

	return (0);

fail_fw_init:
fail_alloc_fw_space:

	free_space_for_mfi(instance);

fail_ready_state:
	ddi_regs_map_free(&instance->regmap_handle);

fail_mfi_reg_setup:
	return (DDI_FAILURE);
}

/*
 * mfi_state_transition_to_ready	: Move the FW to READY state
 *
 * @reg_set			: MFI register set
 */
static int
mfi_state_transition_to_ready(struct megasas_instance *instance)
{
	int		i;
	uint8_t		max_wait;
	uint32_t	fw_ctrl;
	uint32_t	fw_state;
	uint32_t	cur_state;

	fw_state =
	    instance->func_ptr->read_fw_status_reg(instance) & MFI_STATE_MASK;
	con_log(CL_ANN1, (CE_NOTE,
	    "mfi_state_transition_to_ready:FW state = 0x%x", fw_state));

	while (fw_state != MFI_STATE_READY) {
		con_log(CL_ANN, (CE_NOTE,
		    "mfi_state_transition_to_ready:FW state%x", fw_state));

		switch (fw_state) {
		case MFI_STATE_FAULT:
			con_log(CL_ANN, (CE_NOTE,
			    "megasas: FW in FAULT state!!"));

			return (-ENODEV);
		case MFI_STATE_WAIT_HANDSHAKE:
			/* set the CLR bit in IMR0 */
			con_log(CL_ANN, (CE_NOTE,
			    "megasas: FW waiting for HANDSHAKE"));
			/*
			 * PCI_Hot Plug: MFI F/W requires
			 * (MFI_INIT_CLEAR_HANDSHAKE|MFI_INIT_HOTPLUG)
			 * to be set
			 */
			/* WR_IB_MSG_0(MFI_INIT_CLEAR_HANDSHAKE, instance); */
			WR_IB_DOORBELL(MFI_INIT_CLEAR_HANDSHAKE |
			    MFI_INIT_HOTPLUG, instance);

			max_wait	= 2;
			cur_state	= MFI_STATE_WAIT_HANDSHAKE;
			break;
		case MFI_STATE_BOOT_MESSAGE_PENDING:
			/* set the CLR bit in IMR0 */
			con_log(CL_ANN, (CE_NOTE,
			    "megasas: FW state boot message pending"));
			/*
			 * PCI_Hot Plug: MFI F/W requires
			 * (MFI_INIT_CLEAR_HANDSHAKE|MFI_INIT_HOTPLUG)
			 * to be set
			 */
			WR_IB_DOORBELL(MFI_INIT_HOTPLUG, instance);

			max_wait	= 10;
			cur_state	= MFI_STATE_BOOT_MESSAGE_PENDING;
			break;
		case MFI_STATE_OPERATIONAL:
			/* bring it to READY state; assuming max wait 2 secs */
			instance->func_ptr->disable_intr(instance);
			con_log(CL_ANN1, (CE_NOTE,
			    "megasas: FW in OPERATIONAL state"));
			/*
			 * PCI_Hot Plug: MFI F/W requires
			 * (MFI_INIT_READY | MFI_INIT_MFIMODE | MFI_INIT_ABORT)
			 * to be set
			 */
			/* WR_IB_DOORBELL(MFI_INIT_READY, instance); */
			WR_IB_DOORBELL(MFI_RESET_FLAGS, instance);

			max_wait	= 10;
			cur_state	= MFI_STATE_OPERATIONAL;
			break;
		case MFI_STATE_UNDEFINED:
			/* this state should not last for more than 2 seconds */
			con_log(CL_ANN, (CE_NOTE, "FW state undefined\n"));

			max_wait	= 2;
			cur_state	= MFI_STATE_UNDEFINED;
			break;
		case MFI_STATE_BB_INIT:
			max_wait	= 2;
			cur_state	= MFI_STATE_BB_INIT;
			break;
		case MFI_STATE_FW_INIT:
			max_wait	= 2;
			cur_state	= MFI_STATE_FW_INIT;
			break;
		case MFI_STATE_DEVICE_SCAN:
			max_wait	= 10;
			cur_state	= MFI_STATE_DEVICE_SCAN;
			break;
		default:
			con_log(CL_ANN, (CE_NOTE,
			    "megasas: Unknown state 0x%x\n", fw_state));
			return (-ENODEV);
		}

		/* the cur_state should not last for more than max_wait secs */
		for (i = 0; i < (max_wait * MILLISEC); i++) {
			/* fw_state = RD_OB_MSG_0(instance) & MFI_STATE_MASK; */
			fw_state =
			    instance->func_ptr->read_fw_status_reg(instance) &
			    MFI_STATE_MASK;

			if (fw_state == cur_state) {
				delay(1 * drv_usectohz(MILLISEC));
			} else {
				break;
			}
		}

		/* return error if fw_state hasn't changed after max_wait */
		if (fw_state == cur_state) {
			con_log(CL_ANN, (CE_NOTE,
			    "FW state hasn't changed in %d secs\n", max_wait));
			return (-ENODEV);
		}
	};

	fw_ctrl = RD_IB_DOORBELL(instance);

	con_log(CL_ANN1, (CE_NOTE,
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

	if (megasas_check_acc_handle(instance->regmap_handle) != DDI_SUCCESS) {
		return (-ENODEV);
	}
	return (0);
}

/*
 * get_seq_num
 */
static int
get_seq_num(struct megasas_instance *instance,
    struct megasas_evt_log_info *eli)
{
	int	ret = 0;

	dma_obj_t			dcmd_dma_obj;
	struct megasas_cmd		*cmd;
	struct megasas_dcmd_frame	*dcmd;

	cmd = get_mfi_pkt(instance);

	if (!cmd) {
		cmn_err(CE_WARN, "megasas: failed to get a cmd\n");
		return (-ENOMEM);
	}

	dcmd	= &cmd->frame->dcmd;

	/* allocate the data transfer buffer */
	dcmd_dma_obj.size = sizeof (struct megasas_evt_log_info);
	dcmd_dma_obj.dma_attr = megasas_generic_dma_attr;
	dcmd_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
	dcmd_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
	dcmd_dma_obj.dma_attr.dma_attr_sgllen = 1;
	dcmd_dma_obj.dma_attr.dma_attr_align = 1;

	if (mega_alloc_dma_obj(instance, &dcmd_dma_obj) != 1) {
		con_log(CL_ANN, (CE_WARN,
		    "get_seq_num: could not data transfer buffer alloc."));
		return (DDI_FAILURE);
	}

	(void) memset(dcmd_dma_obj.buffer, 0,
	    sizeof (struct megasas_evt_log_info));

	(void) memset(dcmd->mbox.b, 0, DCMD_MBOX_SZ);

	dcmd->cmd = MFI_CMD_OP_DCMD;
	dcmd->cmd_status = 0;
	dcmd->sge_count	= 1;
	dcmd->flags = MFI_FRAME_DIR_READ;
	dcmd->timeout = 0;
	dcmd->data_xfer_len = sizeof (struct megasas_evt_log_info);
	dcmd->opcode = MR_DCMD_CTRL_EVENT_GET_INFO;
	dcmd->sgl.sge32[0].length = sizeof (struct megasas_evt_log_info);
	dcmd->sgl.sge32[0].phys_addr = dcmd_dma_obj.dma_cookie[0].dmac_address;

	cmd->sync_cmd = MEGASAS_TRUE;
	cmd->frame_count = 1;

	if (instance->func_ptr->issue_cmd_in_sync_mode(instance, cmd)) {
		cmn_err(CE_WARN, "get_seq_num: "
		    "failed to issue MR_DCMD_CTRL_EVENT_GET_INFO\n");
		ret = -1;
	} else {
		/* copy the data back into callers buffer */
		bcopy(dcmd_dma_obj.buffer, eli,
		    sizeof (struct megasas_evt_log_info));
		ret = 0;
	}

	if (mega_free_dma_obj(instance, dcmd_dma_obj) != DDI_SUCCESS)
		ret = -1;

	return_mfi_pkt(instance, cmd);
	if (megasas_common_check(instance, cmd) != DDI_SUCCESS) {
		ret = -1;
	}
	return (ret);
}

/*
 * start_mfi_aen
 */
static int
start_mfi_aen(struct megasas_instance *instance)
{
	int	ret = 0;

	struct megasas_evt_log_info	eli;
	union megasas_evt_class_locale	class_locale;

	/* get the latest sequence number from FW */
	(void) memset(&eli, 0, sizeof (struct megasas_evt_log_info));

	if (get_seq_num(instance, &eli)) {
		cmn_err(CE_WARN, "start_mfi_aen: failed to get seq num\n");
		return (-1);
	}

	/* register AEN with FW for latest sequence number plus 1 */
	class_locale.members.reserved	= 0;
	class_locale.members.locale	= MR_EVT_LOCALE_ALL;
	class_locale.members.class	= MR_EVT_CLASS_CRITICAL;

	ret = register_mfi_aen(instance, eli.newest_seq_num + 1,
	    class_locale.word);

	if (ret) {
		cmn_err(CE_WARN, "start_mfi_aen: aen registration failed\n");
		return (-1);
	}

	return (ret);
}

/*
 * flush_cache
 */
static void
flush_cache(struct megasas_instance *instance)
{
	struct megasas_cmd		*cmd;
	struct megasas_dcmd_frame	*dcmd;

	if (!(cmd = get_mfi_pkt(instance)))
		return;

	dcmd = &cmd->frame->dcmd;

	(void) memset(dcmd->mbox.b, 0, DCMD_MBOX_SZ);

	dcmd->cmd		= MFI_CMD_OP_DCMD;
	dcmd->cmd_status	= 0x0;
	dcmd->sge_count		= 0;
	dcmd->flags		= MFI_FRAME_DIR_NONE;
	dcmd->timeout		= 0;
	dcmd->data_xfer_len	= 0;
	dcmd->opcode		= MR_DCMD_CTRL_CACHE_FLUSH;
	dcmd->mbox.b[0]		= MR_FLUSH_CTRL_CACHE | MR_FLUSH_DISK_CACHE;

	cmd->frame_count = 1;

	if (instance->func_ptr->issue_cmd_in_poll_mode(instance, cmd)) {
		cmn_err(CE_WARN,
		    "flush_cache: failed to issue MFI_DCMD_CTRL_CACHE_FLUSH\n");
	}
	con_log(CL_DLEVEL1, (CE_NOTE, "done"));
	return_mfi_pkt(instance, cmd);
	(void) megasas_common_check(instance, cmd);
}

/*
 * service_mfi_aen-	Completes an AEN command
 * @instance:			Adapter soft state
 * @cmd:			Command to be completed
 *
 */
static void
service_mfi_aen(struct megasas_instance *instance, struct megasas_cmd *cmd)
{
	uint32_t	seq_num;
	struct megasas_evt_detail *evt_detail =
	    (struct megasas_evt_detail *)instance->mfi_evt_detail_obj.buffer;

	cmd->cmd_status = cmd->frame->io.cmd_status;

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
		    "mega%d: Failed to log AEN event", instance_no));
	}

	/* get copy of seq_num and class/locale for re-registration */
	seq_num = evt_detail->seq_num;
	seq_num++;
	(void) memset(instance->mfi_evt_detail_obj.buffer, 0,
	    sizeof (struct megasas_evt_detail));

	cmd->frame->dcmd.cmd_status = 0x0;
	cmd->frame->dcmd.mbox.w[0] = seq_num;

	instance->aen_seq_num = seq_num;

	cmd->frame_count = 1;

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
complete_cmd_in_sync_mode(struct megasas_instance *instance,
    struct megasas_cmd *cmd)
{
	cmd->cmd_status = cmd->frame->io.cmd_status;

	cmd->sync_cmd = MEGASAS_FALSE;

	if (cmd->cmd_status == ENODATA) {
		cmd->cmd_status = 0;
	}

	cv_broadcast(&instance->int_cmd_cv);
}

/*
 * megasas_softintr - The Software ISR
 * @param arg	: HBA soft state
 *
 * called from high-level interrupt if hi-level interrupt are not there,
 * otherwise triggered as a soft interrupt
 */
static uint_t
megasas_softintr(struct megasas_instance *instance)
{
	struct scsi_pkt		*pkt;
	struct scsa_cmd		*acmd;
	struct megasas_cmd	*cmd;
	struct mlist_head	*pos, *next;
	mlist_t			process_list;
	struct megasas_header	*hdr;
	struct scsi_arq_status	*arqstat;

	con_log(CL_ANN1, (CE_CONT, "megasas_softintr called"));

	ASSERT(instance);
	mutex_enter(&instance->completed_pool_mtx);

	if (mlist_empty(&instance->completed_pool_list)) {
		mutex_exit(&instance->completed_pool_mtx);
		return (DDI_INTR_UNCLAIMED);
	}

	instance->softint_running = 1;

	INIT_LIST_HEAD(&process_list);
	mlist_splice(&instance->completed_pool_list, &process_list);
	INIT_LIST_HEAD(&instance->completed_pool_list);

	mutex_exit(&instance->completed_pool_mtx);

	/* perform all callbacks first, before releasing the SCBs */
	mlist_for_each_safe(pos, next, &process_list) {
		cmd = mlist_entry(pos, struct megasas_cmd, list);

		/* syncronize the Cmd frame for the controller */
		(void) ddi_dma_sync(cmd->frame_dma_obj.dma_handle,
		    0, 0, DDI_DMA_SYNC_FORCPU);

		if (megasas_check_dma_handle(cmd->frame_dma_obj.dma_handle) !=
		    DDI_SUCCESS) {
			megasas_fm_ereport(instance, DDI_FM_DEVICE_NO_RESPONSE);
			ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);
			return (DDI_INTR_UNCLAIMED);
		}

		hdr = &cmd->frame->hdr;

		/* remove the internal command from the process list */
		mlist_del_init(&cmd->list);

		switch (hdr->cmd) {
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
			if (cmd->sync_cmd == MEGASAS_TRUE) {
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

			con_log(CL_ANN1, (CE_CONT,
			    "CDB[0] = %x completed for %s: size %lx context %x",
			    pkt->pkt_cdbp[0], ((acmd->islogical) ? "LD" : "PD"),
			    acmd->cmd_dmacount, hdr->context));

			if (pkt->pkt_cdbp[0] == SCMD_INQUIRY) {
				struct scsi_inquiry	*inq;

				if (acmd->cmd_dmacount != 0) {
					bp_mapin(acmd->cmd_buf);
					inq = (struct scsi_inquiry *)
					    acmd->cmd_buf->b_un.b_addr;

					/* don't expose physical drives to OS */
					if (acmd->islogical &&
					    (hdr->cmd_status == MFI_STAT_OK)) {
						display_scsi_inquiry(
						    (caddr_t)inq);
					} else if ((hdr->cmd_status ==
					    MFI_STAT_OK) && inq->inq_dtype ==
					    DTYPE_DIRECT) {

						display_scsi_inquiry(
						    (caddr_t)inq);

						/* for physical disk */
						hdr->cmd_status =
						    MFI_STAT_DEVICE_NOT_FOUND;
					}
				}
			}

			switch (hdr->cmd_status) {
			case MFI_STAT_OK:
				pkt->pkt_scbp[0] = STATUS_GOOD;
				break;
			case MFI_STAT_LD_CC_IN_PROGRESS:
			case MFI_STAT_LD_RECON_IN_PROGRESS:
			    /* SJ - these are not correct way */
				pkt->pkt_scbp[0] = STATUS_GOOD;
				break;
			case MFI_STAT_LD_INIT_IN_PROGRESS:
				con_log(CL_ANN,
				    (CE_WARN, "Initialization in Progress"));
				pkt->pkt_reason	= CMD_TRAN_ERR;

				break;
			case MFI_STAT_SCSI_DONE_WITH_ERROR:
				con_log(CL_ANN1, (CE_CONT, "scsi_done error"));

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

					bcopy(cmd->sense,
					    &(arqstat->sts_sensedata),
					    acmd->cmd_scblen -
					    offsetof(struct scsi_arq_status,
					    sts_sensedata));
				}
				break;
			case MFI_STAT_LD_OFFLINE:
			case MFI_STAT_DEVICE_NOT_FOUND:
				con_log(CL_ANN1, (CE_CONT,
				    "device not found error"));
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

			return_mfi_pkt(instance, cmd);

			(void) megasas_common_check(instance, cmd);

			if (acmd->cmd_dmahandle) {
				if (megasas_check_dma_handle(
				    acmd->cmd_dmahandle) != DDI_SUCCESS) {
					ddi_fm_service_impact(instance->dip,
					    DDI_SERVICE_UNAFFECTED);
					pkt->pkt_reason = CMD_TRAN_ERR;
					pkt->pkt_statistics = 0;
				}
			}

			/* Call the callback routine */
			if ((pkt->pkt_flags & FLAG_NOINTR) == 0) {
				scsi_hba_pkt_comp(pkt);
			}

			break;
		case MFI_CMD_OP_SMP:
		case MFI_CMD_OP_STP:
			complete_cmd_in_sync_mode(instance, cmd);
			break;
		case MFI_CMD_OP_DCMD:
			/* see if got an event notification */
			if (cmd->frame->dcmd.opcode ==
			    MR_DCMD_CTRL_EVENT_WAIT) {
				if ((instance->aen_cmd == cmd) &&
				    (instance->aen_cmd->abort_aen)) {
					con_log(CL_ANN, (CE_WARN,
					    "megasas_softintr: "
					    "aborted_aen returned"));
				} else {
					service_mfi_aen(instance, cmd);

					atomic_add_16(&instance->fw_outstanding,
					    (-1));
				}
			} else {
				complete_cmd_in_sync_mode(instance, cmd);
			}

			break;
		case MFI_CMD_OP_ABORT:
			con_log(CL_ANN, (CE_WARN, "MFI_CMD_OP_ABORT complete"));
			/*
			 * MFI_CMD_OP_ABORT successfully completed
			 * in the synchronous mode
			 */
			complete_cmd_in_sync_mode(instance, cmd);
			break;
		default:
			megasas_fm_ereport(instance, DDI_FM_DEVICE_NO_RESPONSE);
			ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);

			if (cmd->pkt != NULL) {
				pkt = cmd->pkt;
				if ((pkt->pkt_flags & FLAG_NOINTR) == 0) {
					scsi_hba_pkt_comp(pkt);
				}
			}
			con_log(CL_ANN, (CE_WARN, "Cmd type unknown !!"));
			break;
		}
	}

	instance->softint_running = 0;

	return (DDI_INTR_CLAIMED);
}

/*
 * mega_alloc_dma_obj
 *
 * Allocate the memory and other resources for an dma object.
 */
static int
mega_alloc_dma_obj(struct megasas_instance *instance, dma_obj_t *obj)
{
	int	i;
	size_t	alen = 0;
	uint_t	cookie_cnt;
	struct ddi_device_acc_attr	tmp_endian_attr;

	tmp_endian_attr = endian_attr;
	tmp_endian_attr.devacc_attr_access = DDI_DEFAULT_ACC;
	i = ddi_dma_alloc_handle(instance->dip, &obj->dma_attr,
	    DDI_DMA_SLEEP, NULL, &obj->dma_handle);
	if (i != DDI_SUCCESS) {

		switch (i) {
			case DDI_DMA_BADATTR :
				con_log(CL_ANN, (CE_WARN,
				"Failed ddi_dma_alloc_handle- Bad atrib"));
				break;
			case DDI_DMA_NORESOURCES :
				con_log(CL_ANN, (CE_WARN,
				"Failed ddi_dma_alloc_handle- No Resources"));
				break;
			default :
				con_log(CL_ANN, (CE_WARN,
				"Failed ddi_dma_alloc_handle :unknown %d", i));
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

	if (megasas_check_dma_handle(obj->dma_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);
		return (-1);
	}

	if (megasas_check_acc_handle(obj->acc_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_LOST);
		return (-1);
	}

	return (cookie_cnt);
}

/*
 * mega_free_dma_obj(struct megasas_instance *, dma_obj_t)
 *
 * De-allocate the memory and other resources for an dma object, which must
 * have been alloated by a previous call to mega_alloc_dma_obj()
 */
static int
mega_free_dma_obj(struct megasas_instance *instance, dma_obj_t obj)
{

	if (megasas_check_dma_handle(obj.dma_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_UNAFFECTED);
		return (DDI_FAILURE);
	}

	if (megasas_check_acc_handle(obj.acc_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_UNAFFECTED);
		return (DDI_FAILURE);
	}

	(void) ddi_dma_unbind_handle(obj.dma_handle);
	ddi_dma_mem_free(&obj.acc_handle);
	ddi_dma_free_handle(&obj.dma_handle);

	return (DDI_SUCCESS);
}

/*
 * megasas_dma_alloc(instance_t *, struct scsi_pkt *, struct buf *,
 * int, int (*)())
 *
 * Allocate dma resources for a new scsi command
 */
static int
megasas_dma_alloc(struct megasas_instance *instance, struct scsi_pkt *pkt,
    struct buf *bp, int flags, int (*callback)())
{
	int	dma_flags;
	int	(*cb)(caddr_t);
	int	i;

	ddi_dma_attr_t	tmp_dma_attr = megasas_generic_dma_attr;
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

	if ((i = ddi_dma_alloc_handle(instance->dip, &tmp_dma_attr,
	    cb, 0, &acmd->cmd_dmahandle)) != DDI_SUCCESS) {
		switch (i) {
		case DDI_DMA_BADATTR:
			bioerror(bp, EFAULT);
			return (-1);

		case DDI_DMA_NORESOURCES:
			bioerror(bp, 0);
			return (-1);

		default:
			con_log(CL_ANN, (CE_PANIC, "ddi_dma_alloc_handle: "
			    "0x%x impossible\n", i));
			bioerror(bp, EFAULT);
			return (-1);
		}
	}

	i = ddi_dma_buf_bind_handle(acmd->cmd_dmahandle, bp, dma_flags,
	    cb, 0, &acmd->cmd_dmacookies[0], &acmd->cmd_ncookies);

	switch (i) {
	case DDI_DMA_PARTIAL_MAP:
		if ((dma_flags & DDI_DMA_PARTIAL) == 0) {
			con_log(CL_ANN, (CE_PANIC, "ddi_dma_buf_bind_handle: "
			    "DDI_DMA_PARTIAL_MAP impossible\n"));
			goto no_dma_cookies;
		}

		if (ddi_dma_numwin(acmd->cmd_dmahandle, &acmd->cmd_nwin) ==
		    DDI_FAILURE) {
			con_log(CL_ANN, (CE_PANIC, "ddi_dma_numwin failed\n"));
			goto no_dma_cookies;
		}

		if (ddi_dma_getwin(acmd->cmd_dmahandle, acmd->cmd_curwin,
		    &acmd->cmd_dma_offset, &acmd->cmd_dma_len,
		    &acmd->cmd_dmacookies[0], &acmd->cmd_ncookies) ==
		    DDI_FAILURE) {

			con_log(CL_ANN, (CE_PANIC, "ddi_dma_getwin failed\n"));
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

		return (0);
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
		    " DDI_DMA_INUSE impossible\n"));
		break;
	default:
		con_log(CL_ANN, (CE_PANIC, "ddi_dma_buf_bind_handle: "
		    "0x%x impossible\n", i));
		break;
	}

no_dma_cookies:
	ddi_dma_free_handle(&acmd->cmd_dmahandle);
	acmd->cmd_dmahandle = NULL;
	acmd->cmd_flags &= ~CFLAG_DMAVALID;
	return (-1);
}

/*
 * megasas_dma_move(struct megasas_instance *, struct scsi_pkt *, struct buf *)
 *
 * move dma resources to next dma window
 *
 */
static int
megasas_dma_move(struct megasas_instance *instance, struct scsi_pkt *pkt,
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
			return (0);
		}

		/* at last window, cannot move */
		if (++acmd->cmd_curwin >= acmd->cmd_nwin) {
			return (-1);
		}

		if (ddi_dma_getwin(acmd->cmd_dmahandle, acmd->cmd_curwin,
		    &acmd->cmd_dma_offset, &acmd->cmd_dma_len,
		    &acmd->cmd_dmacookies[0], &acmd->cmd_ncookies) ==
		    DDI_FAILURE) {
			return (-1);
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

	return (0);
}

/*
 * build_cmd
 */
static struct megasas_cmd *
build_cmd(struct megasas_instance *instance, struct scsi_address *ap,
    struct scsi_pkt *pkt, uchar_t *cmd_done)
{
	uint16_t	flags = 0;
	uint32_t	i;
	uint32_t 	context;
	uint32_t	sge_bytes;

	struct megasas_cmd		*cmd;
	struct megasas_sge64		*mfi_sgl;
	struct scsa_cmd			*acmd = PKT2CMD(pkt);
	struct megasas_pthru_frame 	*pthru;
	struct megasas_io_frame		*ldio;

	/* find out if this is logical or physical drive command.  */
	acmd->islogical = MEGADRV_IS_LOGICAL(ap);
	acmd->device_id = MAP_DEVICE_ID(instance, ap);
	*cmd_done = 0;

	/* get the command packet */
	if (!(cmd = get_mfi_pkt(instance))) {
		return (NULL);
	}

	cmd->pkt = pkt;
	cmd->cmd = acmd;

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

	flags |= MFI_FRAME_SGL64;

	switch (pkt->pkt_cdbp[0]) {

	/*
	 * case SCMD_SYNCHRONIZE_CACHE:
	 * 	flush_cache(instance);
	 *	return_mfi_pkt(instance, cmd);
	 *	*cmd_done = 1;
	 *
	 *	return (NULL);
	 */

	case SCMD_READ:
	case SCMD_WRITE:
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
		if (acmd->islogical) {
			ldio = (struct megasas_io_frame *)cmd->frame;

			/*
			 * preare the Logical IO frame:
			 * 2nd bit is zero for all read cmds
			 */
			ldio->cmd = (pkt->pkt_cdbp[0] & 0x02) ?
			    MFI_CMD_OP_LD_WRITE : MFI_CMD_OP_LD_READ;
			ldio->cmd_status = 0x0;
			ldio->scsi_status = 0x0;
			ldio->target_id	 = acmd->device_id;
			ldio->timeout = 0;
			ldio->reserved_0 = 0;
			ldio->pad_0 = 0;
			ldio->flags = flags;

			/* Initialize sense Information */
			bzero(cmd->sense, SENSE_LENGTH);
			ldio->sense_len = SENSE_LENGTH;
			ldio->sense_buf_phys_addr_hi = 0;
			ldio->sense_buf_phys_addr_lo = cmd->sense_phys_addr;

			ldio->start_lba_hi = 0;
			ldio->access_byte = (acmd->cmd_cdblen != 6) ?
			    pkt->pkt_cdbp[1] : 0;
			ldio->sge_count = acmd->cmd_cookiecnt;
			mfi_sgl = (struct megasas_sge64	*)&ldio->sgl;

			context = ldio->context;

			if (acmd->cmd_cdblen == CDB_GROUP0) {
				ldio->lba_count	= host_to_le16(
				    (uint16_t)(pkt->pkt_cdbp[4]));

				ldio->start_lba_lo = host_to_le32(
				    ((uint32_t)(pkt->pkt_cdbp[3])) |
				    ((uint32_t)(pkt->pkt_cdbp[2]) << 8) |
				    ((uint32_t)((pkt->pkt_cdbp[1]) & 0x1F)
				    << 16));
			} else if (acmd->cmd_cdblen == CDB_GROUP1) {
				ldio->lba_count = host_to_le16(
				    ((uint16_t)(pkt->pkt_cdbp[8])) |
				    ((uint16_t)(pkt->pkt_cdbp[7]) << 8));

				ldio->start_lba_lo = host_to_le32(
				    ((uint32_t)(pkt->pkt_cdbp[5])) |
				    ((uint32_t)(pkt->pkt_cdbp[4]) << 8) |
				    ((uint32_t)(pkt->pkt_cdbp[3]) << 16) |
				    ((uint32_t)(pkt->pkt_cdbp[2]) << 24));
			} else if (acmd->cmd_cdblen == CDB_GROUP2) {
				ldio->lba_count	 = host_to_le16(
				    ((uint16_t)(pkt->pkt_cdbp[9])) |
				    ((uint16_t)(pkt->pkt_cdbp[8]) << 8) |
				    ((uint16_t)(pkt->pkt_cdbp[7]) << 16) |
				    ((uint16_t)(pkt->pkt_cdbp[6]) << 24));

				ldio->start_lba_lo = host_to_le32(
				    ((uint32_t)(pkt->pkt_cdbp[5])) |
				    ((uint32_t)(pkt->pkt_cdbp[4]) << 8) |
				    ((uint32_t)(pkt->pkt_cdbp[3]) << 16) |
				    ((uint32_t)(pkt->pkt_cdbp[2]) << 24));
			} else if (acmd->cmd_cdblen == CDB_GROUP3) {
				ldio->lba_count = host_to_le16(
				    ((uint16_t)(pkt->pkt_cdbp[13])) |
				    ((uint16_t)(pkt->pkt_cdbp[12]) << 8) |
				    ((uint16_t)(pkt->pkt_cdbp[11]) << 16) |
				    ((uint16_t)(pkt->pkt_cdbp[10]) << 24));

				ldio->start_lba_lo = host_to_le32(
				    ((uint32_t)(pkt->pkt_cdbp[9])) |
				    ((uint32_t)(pkt->pkt_cdbp[8]) << 8) |
				    ((uint32_t)(pkt->pkt_cdbp[7]) << 16) |
				    ((uint32_t)(pkt->pkt_cdbp[6]) << 24));

				ldio->start_lba_lo = host_to_le32(
				    ((uint32_t)(pkt->pkt_cdbp[5])) |
				    ((uint32_t)(pkt->pkt_cdbp[4]) << 8) |
				    ((uint32_t)(pkt->pkt_cdbp[3]) << 16) |
				    ((uint32_t)(pkt->pkt_cdbp[2]) << 24));
			}

			break;
		}
		/* fall through For all non-rd/wr cmds */
	default:
		pthru	= (struct megasas_pthru_frame *)cmd->frame;

		/* prepare the DCDB frame */
		pthru->cmd = (acmd->islogical) ?
		    MFI_CMD_OP_LD_SCSI : MFI_CMD_OP_PD_SCSI;
		pthru->cmd_status	= 0x0;
		pthru->scsi_status	= 0x0;
		pthru->target_id	= acmd->device_id;
		pthru->lun		= 0;
		pthru->cdb_len		= acmd->cmd_cdblen;
		pthru->timeout		= 0;
		pthru->flags		= flags;
		pthru->data_xfer_len	= acmd->cmd_dmacount;
		pthru->sge_count	= acmd->cmd_cookiecnt;
		mfi_sgl			= (struct megasas_sge64 *)&pthru->sgl;

		bzero(cmd->sense, SENSE_LENGTH);
		pthru->sense_len	= SENSE_LENGTH;
		pthru->sense_buf_phys_addr_hi = 0;
		pthru->sense_buf_phys_addr_lo = cmd->sense_phys_addr;

		context = pthru->context;

		bcopy(pkt->pkt_cdbp, pthru->cdb, acmd->cmd_cdblen);

		break;
	}
#ifdef lint
	context = context;
#endif
	/* bzero(mfi_sgl, sizeof (struct megasas_sge64) * MAX_SGL); */

	/* prepare the scatter-gather list for the firmware */
	for (i = 0; i < acmd->cmd_cookiecnt; i++, mfi_sgl++) {
		mfi_sgl->phys_addr = acmd->cmd_dmacookies[i].dmac_laddress;
		mfi_sgl->length    = acmd->cmd_dmacookies[i].dmac_size;
	}

	sge_bytes = sizeof (struct megasas_sge64)*acmd->cmd_cookiecnt;

	cmd->frame_count = (sge_bytes / MEGAMFI_FRAME_SIZE) +
	    ((sge_bytes % MEGAMFI_FRAME_SIZE) ? 1 : 0) + 1;

	if (cmd->frame_count >= 8) {
		cmd->frame_count = 8;
	}

	return (cmd);
}

/*
 * wait_for_outstanding -	Wait for all outstanding cmds
 * @instance:				Adapter soft state
 *
 * This function waits for upto MEGASAS_RESET_WAIT_TIME seconds for FW to
 * complete all its outstanding commands. Returns error if one or more IOs
 * are pending after this time period.
 */
static int
wait_for_outstanding(struct megasas_instance *instance)
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

	ddi_fm_acc_err_clear(instance->regmap_handle, DDI_FME_VERSION);

	return (0);
}

/*
 * issue_mfi_pthru
 */
static int
issue_mfi_pthru(struct megasas_instance *instance, struct megasas_ioctl *ioctl,
    struct megasas_cmd *cmd, int mode)
{
	void		*ubuf;
	uint32_t	kphys_addr = 0;
	uint32_t	xferlen = 0;
	uint_t		model;

	dma_obj_t			pthru_dma_obj;
	struct megasas_pthru_frame	*kpthru;
	struct megasas_pthru_frame	*pthru;

	pthru = &cmd->frame->pthru;
	kpthru = (struct megasas_pthru_frame *)&ioctl->frame[0];

	model = ddi_model_convert_from(mode & FMODELS);
	if (model == DDI_MODEL_ILP32) {
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_pthru: DDI_MODEL_LP32"));

		xferlen	= kpthru->sgl.sge32[0].length;

		/* SJ! - ubuf needs to be virtual address. */
		ubuf	= (void *)(ulong_t)kpthru->sgl.sge32[0].phys_addr;
	} else {
#ifdef _ILP32
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_pthru: DDI_MODEL_LP32"));
		xferlen	= kpthru->sgl.sge32[0].length;
		/* SJ! - ubuf needs to be virtual address. */
		ubuf	= (void *)(ulong_t)kpthru->sgl.sge32[0].phys_addr;
#else
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_pthru: DDI_MODEL_LP64"));
		xferlen	= kpthru->sgl.sge64[0].length;
		/* SJ! - ubuf needs to be virtual address. */
		ubuf	= (void *)(ulong_t)kpthru->sgl.sge64[0].phys_addr;
#endif
	}

	if (xferlen) {
		/* means IOCTL requires DMA */
		/* allocate the data transfer buffer */
		pthru_dma_obj.size = xferlen;
		pthru_dma_obj.dma_attr = megasas_generic_dma_attr;
		pthru_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		pthru_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
		pthru_dma_obj.dma_attr.dma_attr_sgllen = 1;
		pthru_dma_obj.dma_attr.dma_attr_align = 1;

		/* allocate kernel buffer for DMA */
		if (mega_alloc_dma_obj(instance, &pthru_dma_obj) != 1) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_pthru: "
			    "could not data transfer buffer alloc."));
			return (DDI_FAILURE);
		}

		/* If IOCTL requires DMA WRITE, do ddi_copyin IOCTL data copy */
		if (kpthru->flags & MFI_FRAME_DIR_WRITE) {
			if (ddi_copyin(ubuf, (void *)pthru_dma_obj.buffer,
			    xferlen, mode)) {
				con_log(CL_ANN, (CE_WARN, "issue_mfi_pthru: "
				    "copy from user space failed\n"));
				return (1);
			}
		}

		kphys_addr = pthru_dma_obj.dma_cookie[0].dmac_address;
	}

	pthru->cmd		= kpthru->cmd;
	pthru->sense_len	= kpthru->sense_len;
	pthru->cmd_status	= kpthru->cmd_status;
	pthru->scsi_status	= kpthru->scsi_status;
	pthru->target_id	= kpthru->target_id;
	pthru->lun		= kpthru->lun;
	pthru->cdb_len		= kpthru->cdb_len;
	pthru->sge_count	= kpthru->sge_count;
	pthru->timeout		= kpthru->timeout;
	pthru->data_xfer_len	= kpthru->data_xfer_len;

	pthru->sense_buf_phys_addr_hi	= 0;
	/* pthru->sense_buf_phys_addr_lo = cmd->sense_phys_addr; */
	pthru->sense_buf_phys_addr_lo	= 0;

	bcopy((void *)kpthru->cdb, (void *)pthru->cdb, pthru->cdb_len);

	pthru->flags			= kpthru->flags & ~MFI_FRAME_SGL64;
	pthru->sgl.sge32[0].length	= xferlen;
	pthru->sgl.sge32[0].phys_addr	= kphys_addr;

	cmd->sync_cmd = MEGASAS_TRUE;
	cmd->frame_count = 1;

	if (instance->func_ptr->issue_cmd_in_sync_mode(instance, cmd)) {
		con_log(CL_ANN, (CE_WARN,
		    "issue_mfi_pthru: fw_ioctl failed\n"));
	} else {
		if (xferlen && (kpthru->flags & MFI_FRAME_DIR_READ)) {

			if (ddi_copyout(pthru_dma_obj.buffer, ubuf,
			    xferlen, mode)) {
				con_log(CL_ANN, (CE_WARN, "issue_mfi_pthru: "
				    "copy to user space failed\n"));
				return (1);
			}
		}
	}

	kpthru->cmd_status = pthru->cmd_status;
	kpthru->scsi_status = pthru->scsi_status;

	con_log(CL_ANN, (CE_NOTE, "issue_mfi_pthru: cmd_status %x, "
	    "scsi_status %x\n", pthru->cmd_status, pthru->scsi_status));

	if (xferlen) {
		/* free kernel buffer */
		if (mega_free_dma_obj(instance, pthru_dma_obj) != DDI_SUCCESS)
			return (1);
	}

	return (0);
}

/*
 * issue_mfi_dcmd
 */
static int
issue_mfi_dcmd(struct megasas_instance *instance, struct megasas_ioctl *ioctl,
    struct megasas_cmd *cmd, int mode)
{
	void		*ubuf;
	uint32_t	kphys_addr = 0;
	uint32_t	xferlen = 0;
	uint32_t	model;
	dma_obj_t			dcmd_dma_obj;
	struct megasas_dcmd_frame	*kdcmd;
	struct megasas_dcmd_frame	*dcmd;

	dcmd = &cmd->frame->dcmd;
	kdcmd = (struct megasas_dcmd_frame *)&ioctl->frame[0];

	model = ddi_model_convert_from(mode & FMODELS);
	if (model == DDI_MODEL_ILP32) {
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_dcmd: DDI_MODEL_ILP32"));

		xferlen	= kdcmd->sgl.sge32[0].length;

		/* SJ! - ubuf needs to be virtual address. */
		ubuf	= (void *)(ulong_t)kdcmd->sgl.sge32[0].phys_addr;
	}
	else
	{
#ifdef _ILP32
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_dcmd: DDI_MODEL_ILP32"));
		xferlen	= kdcmd->sgl.sge32[0].length;
		/* SJ! - ubuf needs to be virtual address. */
		ubuf	= (void *)(ulong_t)kdcmd->sgl.sge32[0].phys_addr;
#else
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_dcmd: DDI_MODEL_LP64"));
		xferlen	= kdcmd->sgl.sge64[0].length;
		/* SJ! - ubuf needs to be virtual address. */
		ubuf	= (void *)(ulong_t)dcmd->sgl.sge64[0].phys_addr;
#endif
	}
	if (xferlen) {
		/* means IOCTL requires DMA */
		/* allocate the data transfer buffer */
		dcmd_dma_obj.size = xferlen;
		dcmd_dma_obj.dma_attr = megasas_generic_dma_attr;
		dcmd_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		dcmd_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
		dcmd_dma_obj.dma_attr.dma_attr_sgllen = 1;
		dcmd_dma_obj.dma_attr.dma_attr_align = 1;

		/* allocate kernel buffer for DMA */
		if (mega_alloc_dma_obj(instance, &dcmd_dma_obj) != 1) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_dcmd: "
			    "could not data transfer buffer alloc."));
			return (DDI_FAILURE);
		}

		/* If IOCTL requires DMA WRITE, do ddi_copyin IOCTL data copy */
		if (kdcmd->flags & MFI_FRAME_DIR_WRITE) {
			if (ddi_copyin(ubuf, (void *)dcmd_dma_obj.buffer,
			    xferlen, mode)) {
				con_log(CL_ANN, (CE_WARN, "issue_mfi_dcmd: "
				    "copy from user space failed\n"));
				return (1);
			}
		}

		kphys_addr = dcmd_dma_obj.dma_cookie[0].dmac_address;
	}

	dcmd->cmd		= kdcmd->cmd;
	dcmd->cmd_status	= kdcmd->cmd_status;
	dcmd->sge_count		= kdcmd->sge_count;
	dcmd->timeout		= kdcmd->timeout;
	dcmd->data_xfer_len	= kdcmd->data_xfer_len;
	dcmd->opcode		= kdcmd->opcode;

	bcopy((void *)kdcmd->mbox.b, (void *)dcmd->mbox.b, DCMD_MBOX_SZ);

	dcmd->flags			= kdcmd->flags & ~MFI_FRAME_SGL64;
	dcmd->sgl.sge32[0].length	= xferlen;
	dcmd->sgl.sge32[0].phys_addr	= kphys_addr;

	cmd->sync_cmd = MEGASAS_TRUE;
	cmd->frame_count = 1;

	if (instance->func_ptr->issue_cmd_in_sync_mode(instance, cmd)) {
		con_log(CL_ANN, (CE_WARN, "issue_mfi_dcmd: fw_ioctl failed\n"));
	} else {
		if (xferlen && (kdcmd->flags & MFI_FRAME_DIR_READ)) {

			if (ddi_copyout(dcmd_dma_obj.buffer, ubuf,
			    xferlen, mode)) {
				con_log(CL_ANN, (CE_WARN, "issue_mfi_dcmd: "
				    "copy to user space failed\n"));
				return (1);
			}
		}
	}

	kdcmd->cmd_status = dcmd->cmd_status;

	if (xferlen) {
		/* free kernel buffer */
		if (mega_free_dma_obj(instance, dcmd_dma_obj) != DDI_SUCCESS)
			return (1);
	}

	return (0);
}

/*
 * issue_mfi_smp
 */
static int
issue_mfi_smp(struct megasas_instance *instance, struct megasas_ioctl *ioctl,
    struct megasas_cmd *cmd, int mode)
{
	void		*request_ubuf;
	void		*response_ubuf;
	uint32_t	request_xferlen = 0;
	uint32_t	response_xferlen = 0;
	uint_t		model;
	dma_obj_t			request_dma_obj;
	dma_obj_t			response_dma_obj;
	struct megasas_smp_frame	*ksmp;
	struct megasas_smp_frame	*smp;
	struct megasas_sge32		*sge32;
#ifndef _ILP32
	struct megasas_sge64		*sge64;
#endif

	smp = &cmd->frame->smp;
	ksmp = (struct megasas_smp_frame *)&ioctl->frame[0];

	model = ddi_model_convert_from(mode & FMODELS);
	if (model == DDI_MODEL_ILP32) {
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_smp: DDI_MODEL_ILP32"));

		sge32			= &ksmp->sgl[0].sge32[0];
		response_xferlen	= sge32[0].length;
		request_xferlen		= sge32[1].length;
		con_log(CL_ANN, (CE_NOTE, "issue_mfi_smp: "
		    "response_xferlen = %x, request_xferlen = %x",
		    response_xferlen, request_xferlen));

		/* SJ! - ubuf needs to be virtual address. */

		response_ubuf	= (void *)(ulong_t)sge32[0].phys_addr;
		request_ubuf	= (void *)(ulong_t)sge32[1].phys_addr;
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_smp: "
		    "response_ubuf = %p, request_ubuf = %p",
		    response_ubuf, request_ubuf));
	} else {
#ifdef _ILP32
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_smp: DDI_MODEL_ILP32"));

		sge32			= &ksmp->sgl[0].sge32[0];
		response_xferlen	= sge32[0].length;
		request_xferlen		= sge32[1].length;
		con_log(CL_ANN, (CE_NOTE, "issue_mfi_smp: "
		    "response_xferlen = %x, request_xferlen = %x",
		    response_xferlen, request_xferlen));

		/* SJ! - ubuf needs to be virtual address. */

		response_ubuf	= (void *)(ulong_t)sge32[0].phys_addr;
		request_ubuf	= (void *)(ulong_t)sge32[1].phys_addr;
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_smp: "
		    "response_ubuf = %p, request_ubuf = %p",
		    response_ubuf, request_ubuf));
#else
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_smp: DDI_MODEL_LP64"));

		sge64			= &ksmp->sgl[0].sge64[0];
		response_xferlen	= sge64[0].length;
		request_xferlen		= sge64[1].length;

		/* SJ! - ubuf needs to be virtual address. */
		response_ubuf	= (void *)(ulong_t)sge64[0].phys_addr;
		request_ubuf	= (void *)(ulong_t)sge64[1].phys_addr;
#endif
	}
	if (request_xferlen) {
		/* means IOCTL requires DMA */
		/* allocate the data transfer buffer */
		request_dma_obj.size = request_xferlen;
		request_dma_obj.dma_attr = megasas_generic_dma_attr;
		request_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		request_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
		request_dma_obj.dma_attr.dma_attr_sgllen = 1;
		request_dma_obj.dma_attr.dma_attr_align = 1;

		/* allocate kernel buffer for DMA */
		if (mega_alloc_dma_obj(instance, &request_dma_obj) != 1) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_smp: "
			    "could not data transfer buffer alloc."));
			return (DDI_FAILURE);
		}

		/* If IOCTL requires DMA WRITE, do ddi_copyin IOCTL data copy */
		if (ddi_copyin(request_ubuf, (void *) request_dma_obj.buffer,
		    request_xferlen, mode)) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_smp: "
			    "copy from user space failed\n"));
			return (1);
		}
	}

	if (response_xferlen) {
		/* means IOCTL requires DMA */
		/* allocate the data transfer buffer */
		response_dma_obj.size = response_xferlen;
		response_dma_obj.dma_attr = megasas_generic_dma_attr;
		response_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		response_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
		response_dma_obj.dma_attr.dma_attr_sgllen = 1;
		response_dma_obj.dma_attr.dma_attr_align = 1;

		/* allocate kernel buffer for DMA */
		if (mega_alloc_dma_obj(instance, &response_dma_obj) != 1) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_smp: "
			    "could not data transfer buffer alloc."));
			return (DDI_FAILURE);
		}

		/* If IOCTL requires DMA WRITE, do ddi_copyin IOCTL data copy */
		if (ddi_copyin(response_ubuf, (void *) response_dma_obj.buffer,
		    response_xferlen, mode)) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_smp: "
			    "copy from user space failed\n"));
			return (1);
		}
	}

	smp->cmd		= ksmp->cmd;
	smp->cmd_status		= ksmp->cmd_status;
	smp->connection_status	= ksmp->connection_status;
	smp->sge_count		= ksmp->sge_count;
	/* smp->context		= ksmp->context; */
	smp->timeout		= ksmp->timeout;
	smp->data_xfer_len	= ksmp->data_xfer_len;

	bcopy((void *)&ksmp->sas_addr, (void *)&smp->sas_addr,
	    sizeof (uint64_t));

	smp->flags		= ksmp->flags & ~MFI_FRAME_SGL64;

	model = ddi_model_convert_from(mode & FMODELS);
	if (model == DDI_MODEL_ILP32) {
		con_log(CL_ANN1, (CE_NOTE,
		    "handle_drv_ioctl: DDI_MODEL_ILP32"));

		sge32 = &smp->sgl[0].sge32[0];
		sge32[0].length	= response_xferlen;
		sge32[0].phys_addr =
		    response_dma_obj.dma_cookie[0].dmac_address;
		sge32[1].length	= request_xferlen;
		sge32[1].phys_addr =
		    request_dma_obj.dma_cookie[0].dmac_address;
	} else {
#ifdef _ILP32
		con_log(CL_ANN1, (CE_NOTE,
		    "handle_drv_ioctl: DDI_MODEL_ILP32"));
		sge32 = &smp->sgl[0].sge32[0];
		sge32[0].length	 = response_xferlen;
		sge32[0].phys_addr =
		    response_dma_obj.dma_cookie[0].dmac_address;
		sge32[1].length	= request_xferlen;
		sge32[1].phys_addr =
		    request_dma_obj.dma_cookie[0].dmac_address;
#else
		con_log(CL_ANN1, (CE_NOTE,
		    "issue_mfi_smp: DDI_MODEL_LP64"));
		sge64 = &smp->sgl[0].sge64[0];
		sge64[0].length	= response_xferlen;
		sge64[0].phys_addr =
		    response_dma_obj.dma_cookie[0].dmac_address;
		sge64[1].length	= request_xferlen;
		sge64[1].phys_addr =
		    request_dma_obj.dma_cookie[0].dmac_address;
#endif
	}
	con_log(CL_ANN1, (CE_NOTE, "issue_mfi_smp: "
	    "smp->response_xferlen = %d, smp->request_xferlen = %d "
	    "smp->data_xfer_len = %d", sge32[0].length, sge32[1].length,
	    smp->data_xfer_len));

	cmd->sync_cmd = MEGASAS_TRUE;
	cmd->frame_count = 1;

	if (instance->func_ptr->issue_cmd_in_sync_mode(instance, cmd)) {
		con_log(CL_ANN, (CE_WARN,
		    "issue_mfi_smp: fw_ioctl failed\n"));
	} else {
		con_log(CL_ANN1, (CE_NOTE,
		    "issue_mfi_smp: copy to user space\n"));

		if (request_xferlen) {
			if (ddi_copyout(request_dma_obj.buffer, request_ubuf,
			    request_xferlen, mode)) {
				con_log(CL_ANN, (CE_WARN, "issue_mfi_smp: "
				    "copy to user space failed\n"));
				return (1);
			}
		}

		if (response_xferlen) {
			if (ddi_copyout(response_dma_obj.buffer, response_ubuf,
			    response_xferlen, mode)) {
				con_log(CL_ANN, (CE_WARN, "issue_mfi_smp: "
				    "copy to user space failed\n"));
				return (1);
			}
		}
	}

	ksmp->cmd_status = smp->cmd_status;
	con_log(CL_ANN1, (CE_NOTE, "issue_mfi_smp: smp->cmd_status = %d",
	    smp->cmd_status));


	if (request_xferlen) {
		/* free kernel buffer */
		if (mega_free_dma_obj(instance, request_dma_obj) != DDI_SUCCESS)
			return (1);
	}

	if (response_xferlen) {
		/* free kernel buffer */
		if (mega_free_dma_obj(instance, response_dma_obj) !=
		    DDI_SUCCESS)
			return (1);
	}

	return (0);
}

/*
 * issue_mfi_stp
 */
static int
issue_mfi_stp(struct megasas_instance *instance, struct megasas_ioctl *ioctl,
    struct megasas_cmd *cmd, int mode)
{
	void		*fis_ubuf;
	void		*data_ubuf;
	uint32_t	fis_xferlen = 0;
	uint32_t	data_xferlen = 0;
	uint_t		model;
	dma_obj_t			fis_dma_obj;
	dma_obj_t			data_dma_obj;
	struct megasas_stp_frame	*kstp;
	struct megasas_stp_frame	*stp;

	stp = &cmd->frame->stp;
	kstp = (struct megasas_stp_frame *)&ioctl->frame[0];

	model = ddi_model_convert_from(mode & FMODELS);
	if (model == DDI_MODEL_ILP32) {
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_stp: DDI_MODEL_ILP32"));

		fis_xferlen	= kstp->sgl.sge32[0].length;
		data_xferlen	= kstp->sgl.sge32[1].length;

		/* SJ! - ubuf needs to be virtual address. */
		fis_ubuf	= (void *)(ulong_t)kstp->sgl.sge32[0].phys_addr;
		data_ubuf	= (void *)(ulong_t)kstp->sgl.sge32[1].phys_addr;
	}
	else
	{
#ifdef _ILP32
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_stp: DDI_MODEL_ILP32"));

		fis_xferlen	= kstp->sgl.sge32[0].length;
		data_xferlen	= kstp->sgl.sge32[1].length;

		/* SJ! - ubuf needs to be virtual address. */
		fis_ubuf	= (void *)(ulong_t)kstp->sgl.sge32[0].phys_addr;
		data_ubuf	= (void *)(ulong_t)kstp->sgl.sge32[1].phys_addr;
#else
		con_log(CL_ANN1, (CE_NOTE, "issue_mfi_stp: DDI_MODEL_LP64"));

		fis_xferlen	= kstp->sgl.sge64[0].length;
		data_xferlen	= kstp->sgl.sge64[1].length;

		/* SJ! - ubuf needs to be virtual address. */
		fis_ubuf	= (void *)(ulong_t)kstp->sgl.sge64[0].phys_addr;
		data_ubuf	= (void *)(ulong_t)kstp->sgl.sge64[1].phys_addr;
#endif
	}


	if (fis_xferlen) {
		con_log(CL_ANN, (CE_NOTE, "issue_mfi_stp: "
		    "fis_ubuf = %p fis_xferlen = %x", fis_ubuf, fis_xferlen));

		/* means IOCTL requires DMA */
		/* allocate the data transfer buffer */
		fis_dma_obj.size = fis_xferlen;
		fis_dma_obj.dma_attr = megasas_generic_dma_attr;
		fis_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		fis_dma_obj.dma_attr.dma_attr_count_max	= 0xFFFFFFFFU;
		fis_dma_obj.dma_attr.dma_attr_sgllen = 1;
		fis_dma_obj.dma_attr.dma_attr_align = 1;

		/* allocate kernel buffer for DMA */
		if (mega_alloc_dma_obj(instance, &fis_dma_obj) != 1) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_stp: "
			    "could not data transfer buffer alloc."));
			return (DDI_FAILURE);
		}

		/* If IOCTL requires DMA WRITE, do ddi_copyin IOCTL data copy */
		if (ddi_copyin(fis_ubuf, (void *)fis_dma_obj.buffer,
		    fis_xferlen, mode)) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_stp: "
			    "copy from user space failed\n"));
			return (1);
		}
	}

	if (data_xferlen) {
		con_log(CL_ANN, (CE_NOTE, "issue_mfi_stp: data_ubuf = %p "
		    "data_xferlen = %x", data_ubuf, data_xferlen));

		/* means IOCTL requires DMA */
		/* allocate the data transfer buffer */
		data_dma_obj.size = data_xferlen;
		data_dma_obj.dma_attr = megasas_generic_dma_attr;
		data_dma_obj.dma_attr.dma_attr_addr_hi = 0xFFFFFFFFU;
		data_dma_obj.dma_attr.dma_attr_count_max = 0xFFFFFFFFU;
		data_dma_obj.dma_attr.dma_attr_sgllen = 1;
		data_dma_obj.dma_attr.dma_attr_align = 1;

		/* allocate kernel buffer for DMA */
		if (mega_alloc_dma_obj(instance, &data_dma_obj) != 1) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_stp: "
			    "could not data transfer buffer alloc."));
			return (DDI_FAILURE);
		}

		/* If IOCTL requires DMA WRITE, do ddi_copyin IOCTL data copy */
		if (ddi_copyin(data_ubuf, (void *) data_dma_obj.buffer,
		    data_xferlen, mode)) {
			con_log(CL_ANN, (CE_WARN, "issue_mfi_stp: "
			    "copy from user space failed\n"));
			return (1);
		}
	}

	stp->cmd = kstp->cmd;
	stp->cmd_status	= kstp->cmd_status;
	stp->connection_status = kstp->connection_status;
	stp->target_id = kstp->target_id;
	stp->sge_count = kstp->sge_count;
	/* stp->context = kstp->context; */
	stp->timeout = kstp->timeout;
	stp->data_xfer_len = kstp->data_xfer_len;

	bcopy((void *)kstp->fis, (void *)stp->fis, 10);

	stp->flags = kstp->flags & ~MFI_FRAME_SGL64;
	stp->stp_flags = kstp->stp_flags;
	stp->sgl.sge32[0].length = fis_xferlen;
	stp->sgl.sge32[0].phys_addr = fis_dma_obj.dma_cookie[0].dmac_address;
	stp->sgl.sge32[1].length = data_xferlen;
	stp->sgl.sge32[1].phys_addr = data_dma_obj.dma_cookie[0].dmac_address;

	cmd->sync_cmd = MEGASAS_TRUE;
	cmd->frame_count = 1;

	if (instance->func_ptr->issue_cmd_in_sync_mode(instance, cmd)) {
		con_log(CL_ANN, (CE_WARN, "issue_mfi_stp: fw_ioctl failed\n"));
	} else {

		if (fis_xferlen) {
			if (ddi_copyout(fis_dma_obj.buffer, fis_ubuf,
			    fis_xferlen, mode)) {
				con_log(CL_ANN, (CE_WARN, "issue_mfi_stp: "
				    "copy to user space failed\n"));
				return (1);
			}
		}

		if (data_xferlen) {
			if (ddi_copyout(data_dma_obj.buffer, data_ubuf,
			    data_xferlen, mode)) {
				con_log(CL_ANN, (CE_WARN, "issue_mfi_stp: "
				    "copy to user space failed\n"));
				return (1);
			}
		}
	}

	kstp->cmd_status = stp->cmd_status;

	if (fis_xferlen) {
		/* free kernel buffer */
		if (mega_free_dma_obj(instance, fis_dma_obj) != DDI_SUCCESS)
			return (1);
	}

	if (data_xferlen) {
		/* free kernel buffer */
		if (mega_free_dma_obj(instance, data_dma_obj) != DDI_SUCCESS)
			return (1);
	}

	return (0);
}

/*
 * fill_up_drv_ver
 */
static void
fill_up_drv_ver(struct megasas_drv_ver *dv)
{
	(void) memset(dv, 0, sizeof (struct megasas_drv_ver));

	(void) memcpy(dv->signature, "$LSI LOGIC$", strlen("$LSI LOGIC$"));
	(void) memcpy(dv->os_name, "Solaris", strlen("Solaris"));
	(void) memcpy(dv->drv_name, "megaraid_sas", strlen("megaraid_sas"));
	(void) memcpy(dv->drv_ver, MEGASAS_VERSION, strlen(MEGASAS_VERSION));
	(void) memcpy(dv->drv_rel_date, MEGASAS_RELDATE,
	    strlen(MEGASAS_RELDATE));
}

/*
 * handle_drv_ioctl
 */
static int
handle_drv_ioctl(struct megasas_instance *instance, struct megasas_ioctl *ioctl,
    int mode)
{
	int	i;
	int	rval = 0;
	int	*props = NULL;
	void	*ubuf;

	uint8_t		*pci_conf_buf;
	uint32_t	xferlen;
	uint32_t	num_props;
	uint_t		model;
	struct megasas_dcmd_frame	*kdcmd;
	struct megasas_drv_ver		dv;
	struct megasas_pci_information	pi;

	kdcmd = (struct megasas_dcmd_frame *)&ioctl->frame[0];

	model = ddi_model_convert_from(mode & FMODELS);
	if (model == DDI_MODEL_ILP32) {
		con_log(CL_ANN1, (CE_NOTE,
		    "handle_drv_ioctl: DDI_MODEL_ILP32"));

		xferlen	= kdcmd->sgl.sge32[0].length;

		/* SJ! - ubuf needs to be virtual address. */
		ubuf = (void *)(ulong_t)kdcmd->sgl.sge32[0].phys_addr;
	} else {
#ifdef _ILP32
		con_log(CL_ANN1, (CE_NOTE,
		    "handle_drv_ioctl: DDI_MODEL_ILP32"));
		xferlen	= kdcmd->sgl.sge32[0].length;
		/* SJ! - ubuf needs to be virtual address. */
		ubuf = (void *)(ulong_t)kdcmd->sgl.sge32[0].phys_addr;
#else
		con_log(CL_ANN1, (CE_NOTE,
		    "handle_drv_ioctl: DDI_MODEL_LP64"));
		xferlen	= kdcmd->sgl.sge64[0].length;
		/* SJ! - ubuf needs to be virtual address. */
		ubuf = (void *)(ulong_t)kdcmd->sgl.sge64[0].phys_addr;
#endif
	}
	con_log(CL_ANN1, (CE_NOTE, "handle_drv_ioctl: "
	    "dataBuf=%p size=%d bytes", ubuf, xferlen));

	switch (kdcmd->opcode) {
	case MR_DRIVER_IOCTL_DRIVER_VERSION:
		con_log(CL_ANN1, (CE_NOTE, "handle_drv_ioctl: "
		    "MR_DRIVER_IOCTL_DRIVER_VERSION"));

		fill_up_drv_ver(&dv);

		if (ddi_copyout(&dv, ubuf, xferlen, mode)) {
			con_log(CL_ANN, (CE_WARN, "handle_drv_ioctl: "
			    "MR_DRIVER_IOCTL_DRIVER_VERSION : "
			    "copy to user space failed\n"));
			kdcmd->cmd_status = 1;
			rval = 1;
		} else {
			kdcmd->cmd_status = 0;
		}
		break;
	case MR_DRIVER_IOCTL_PCI_INFORMATION:
		con_log(CL_ANN1, (CE_NOTE, "handle_drv_ioctl: "
		    "MR_DRIVER_IOCTL_PCI_INFORMAITON"));

		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, instance->dip,
		    0, "reg", &props, &num_props)) {
			con_log(CL_ANN, (CE_WARN, "handle_drv_ioctl: "
			    "MR_DRIVER_IOCTL_PCI_INFORMATION : "
			    "ddi_prop_look_int_array failed\n"));
			rval = 1;
		} else {

			pi.busNumber = (props[0] >> 16) & 0xFF;
			pi.deviceNumber = (props[0] >> 11) & 0x1f;
			pi.functionNumber = (props[0] >> 8) & 0x7;
			ddi_prop_free((void *)props);
		}

		pci_conf_buf = (uint8_t *)&pi.pciHeaderInfo;

		for (i = 0; i < (sizeof (struct megasas_pci_information) -
		    offsetof(struct megasas_pci_information, pciHeaderInfo));
		    i++) {
			pci_conf_buf[i] =
			    pci_config_get8(instance->pci_handle, i);
		}

		if (ddi_copyout(&pi, ubuf, xferlen, mode)) {
			con_log(CL_ANN, (CE_WARN, "handle_drv_ioctl: "
			    "MR_DRIVER_IOCTL_PCI_INFORMATION : "
			    "copy to user space failed\n"));
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
		rval = 1;
		break;
	}

	return (rval);
}

/*
 * handle_mfi_ioctl
 */
static int
handle_mfi_ioctl(struct megasas_instance *instance, struct megasas_ioctl *ioctl,
    int mode)
{
	int	rval = 0;

	struct megasas_header	*hdr;
	struct megasas_cmd	*cmd;

	cmd = get_mfi_pkt(instance);

	if (!cmd) {
		con_log(CL_ANN, (CE_WARN, "megasas: "
		    "failed to get a cmd packet\n"));
		return (1);
	}

	hdr = (struct megasas_header *)&ioctl->frame[0];

	switch (hdr->cmd) {
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
		    "invalid mfi ioctl hdr->cmd = %d\n", hdr->cmd));
		rval = 1;
		break;
	}


	return_mfi_pkt(instance, cmd);
	if (megasas_common_check(instance, cmd) != DDI_SUCCESS)
		rval = 1;
	return (rval);
}

/*
 * AEN
 */
static int
handle_mfi_aen(struct megasas_instance *instance, struct megasas_aen *aen)
{
	int	rval = 0;

	rval = register_mfi_aen(instance, instance->aen_seq_num,
	    aen->class_locale_word);

	aen->cmd_status = (uint8_t)rval;

	return (rval);
}

static int
register_mfi_aen(struct megasas_instance *instance, uint32_t seq_num,
    uint32_t class_locale_word)
{
	int	ret_val;

	struct megasas_cmd		*cmd;
	struct megasas_dcmd_frame	*dcmd;
	union megasas_evt_class_locale	curr_aen;
	union megasas_evt_class_locale	prev_aen;

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

	curr_aen.word = class_locale_word;

	if (instance->aen_cmd) {
		prev_aen.word = instance->aen_cmd->frame->dcmd.mbox.w[1];

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

			ret_val = abort_aen_cmd(instance, instance->aen_cmd);

			if (ret_val) {
				con_log(CL_ANN, (CE_WARN, "register_mfi_aen: "
				    "failed to abort prevous AEN command\n"));

				return (ret_val);
			}
		}
	} else {
		curr_aen.word = class_locale_word;
	}

	cmd = get_mfi_pkt(instance);

	if (!cmd)
		return (-ENOMEM);

	dcmd = &cmd->frame->dcmd;

	/* for(i = 0; i < DCMD_MBOX_SZ; i++) dcmd->mbox.b[i] = 0; */
	(void) memset(dcmd->mbox.b, 0, DCMD_MBOX_SZ);

	(void) memset(instance->mfi_evt_detail_obj.buffer, 0,
	    sizeof (struct megasas_evt_detail));

	/* Prepare DCMD for aen registration */
	dcmd->cmd = MFI_CMD_OP_DCMD;
	dcmd->cmd_status = 0x0;
	dcmd->sge_count = 1;
	dcmd->flags = MFI_FRAME_DIR_READ;
	dcmd->timeout = 0;
	dcmd->data_xfer_len = sizeof (struct megasas_evt_detail);
	dcmd->opcode = MR_DCMD_CTRL_EVENT_WAIT;
	dcmd->mbox.w[0] = seq_num;
	dcmd->mbox.w[1] = curr_aen.word;
	dcmd->sgl.sge32[0].phys_addr =
	    instance->mfi_evt_detail_obj.dma_cookie[0].dmac_address;
	dcmd->sgl.sge32[0].length = sizeof (struct megasas_evt_detail);

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
	instance->func_ptr->issue_cmd(cmd, instance);

	return (0);
}

static void
display_scsi_inquiry(caddr_t scsi_inq)
{
#define	MAX_SCSI_DEVICE_CODE	14
	int		i;
	char		inquiry_buf[256] = {0};
	int		len;
	const char	*const scsi_device_types[] = {
		"Direct-Access    ",
		"Sequential-Access",
		"Printer          ",
		"Processor        ",
		"WORM             ",
		"CD-ROM           ",
		"Scanner          ",
		"Optical Device   ",
		"Medium Changer   ",
		"Communications   ",
		"Unknown          ",
		"Unknown          ",
		"Unknown          ",
		"Enclosure        ",
	};

	len = 0;

	len += snprintf(inquiry_buf + len, 265 - len, "  Vendor: ");
	for (i = 8; i < 16; i++) {
		len += snprintf(inquiry_buf + len, 265 - len, "%c",
		    scsi_inq[i]);
	}

	len += snprintf(inquiry_buf + len, 265 - len, "  Model: ");

	for (i = 16; i < 32; i++) {
		len += snprintf(inquiry_buf + len, 265 - len, "%c",
		    scsi_inq[i]);
	}

	len += snprintf(inquiry_buf + len, 265 - len, "  Rev: ");

	for (i = 32; i < 36; i++) {
		len += snprintf(inquiry_buf + len, 265 - len, "%c",
		    scsi_inq[i]);
	}

	len += snprintf(inquiry_buf + len, 265 - len, "\n");


	i = scsi_inq[0] & 0x1f;


	len += snprintf(inquiry_buf + len, 265 - len, "  Type:   %s ",
	    i < MAX_SCSI_DEVICE_CODE ? scsi_device_types[i] :
	    "Unknown          ");


	len += snprintf(inquiry_buf + len, 265 - len,
	    "                 ANSI SCSI revision: %02x", scsi_inq[2] & 0x07);

	if ((scsi_inq[2] & 0x07) == 1 && (scsi_inq[3] & 0x0f) == 1) {
		len += snprintf(inquiry_buf + len, 265 - len, " CCS\n");
	} else {
		len += snprintf(inquiry_buf + len, 265 - len, "\n");
	}

	con_log(CL_ANN1, (CE_CONT, inquiry_buf));
}

static int
read_fw_status_reg_xscale(struct megasas_instance *instance)
{
	return ((int)RD_OB_MSG_0(instance));
}

static int
read_fw_status_reg_ppc(struct megasas_instance *instance)
{
	return ((int)RD_OB_SCRATCH_PAD_0(instance));
}

static void
issue_cmd_xscale(struct megasas_cmd *cmd, struct megasas_instance *instance)
{
	atomic_inc_16(&instance->fw_outstanding);

	/* Issue the command to the FW */
	WR_IB_QPORT((host_to_le32(cmd->frame_phys_addr) >> 3) |
	    (cmd->frame_count - 1), instance);
}

static void
issue_cmd_ppc(struct megasas_cmd *cmd, struct megasas_instance *instance)
{
	atomic_inc_16(&instance->fw_outstanding);

	/* Issue the command to the FW */
	WR_IB_QPORT((host_to_le32(cmd->frame_phys_addr)) |
	    (((cmd->frame_count - 1) << 1) | 1), instance);
}

/*
 * issue_cmd_in_sync_mode
 */
static int
issue_cmd_in_sync_mode_xscale(struct megasas_instance *instance,
    struct megasas_cmd *cmd)
{
	int		i;
	uint32_t	msecs = MFI_POLL_TIMEOUT_SECS * (10 * MILLISEC);

	cmd->cmd_status	= ENODATA;

	WR_IB_QPORT((host_to_le32(cmd->frame_phys_addr) >> 3) |
	    (cmd->frame_count - 1), instance);

	mutex_enter(&instance->int_cmd_mtx);

	for (i = 0; i < msecs && (cmd->cmd_status == ENODATA); i++) {
		cv_wait(&instance->int_cmd_cv, &instance->int_cmd_mtx);
	}

	mutex_exit(&instance->int_cmd_mtx);

	if (i < (msecs -1)) {
		return (0);
	} else {
		return (1);
	}
}

static int
issue_cmd_in_sync_mode_ppc(struct megasas_instance *instance,
    struct megasas_cmd *cmd)
{
	int		i;
	uint32_t	msecs = MFI_POLL_TIMEOUT_SECS * (10 * MILLISEC);

	con_log(CL_ANN1, (CE_NOTE, "issue_cmd_in_sync_mode_ppc: called\n"));

	cmd->cmd_status	= ENODATA;

	WR_IB_QPORT((host_to_le32(cmd->frame_phys_addr)) |
	    (((cmd->frame_count - 1) << 1) | 1), instance);

	mutex_enter(&instance->int_cmd_mtx);

	for (i = 0; i < msecs && (cmd->cmd_status == ENODATA); i++) {
		cv_wait(&instance->int_cmd_cv, &instance->int_cmd_mtx);
	}

	mutex_exit(&instance->int_cmd_mtx);

	con_log(CL_ANN1, (CE_NOTE, "issue_cmd_in_sync_mode_ppc: done\n"));

	if (i < (msecs -1)) {
		return (0);
	} else {
		return (1);
	}
}

/*
 * issue_cmd_in_poll_mode
 */
static int
issue_cmd_in_poll_mode_xscale(struct megasas_instance *instance,
    struct megasas_cmd *cmd)
{
	int		i;
	uint32_t	msecs = MFI_POLL_TIMEOUT_SECS * MILLISEC;
	struct megasas_header *frame_hdr;

	frame_hdr = (struct megasas_header *)cmd->frame;
	frame_hdr->cmd_status	= MFI_CMD_STATUS_POLL_MODE;
	frame_hdr->flags 	|= MFI_FRAME_DONT_POST_IN_REPLY_QUEUE;

	/* issue the frame using inbound queue port */
	WR_IB_QPORT((host_to_le32(cmd->frame_phys_addr) >> 3) |
	    (cmd->frame_count - 1), instance);

	/* wait for cmd_status to change from 0xFF */
	for (i = 0; i < msecs && (frame_hdr->cmd_status ==
	    MFI_CMD_STATUS_POLL_MODE); i++) {
		drv_usecwait(MILLISEC); /* wait for 1000 usecs */
	}

	if (frame_hdr->cmd_status == MFI_CMD_STATUS_POLL_MODE) {
		con_log(CL_ANN, (CE_NOTE, "issue_cmd_in_poll_mode: "
		    "cmd polling timed out"));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
issue_cmd_in_poll_mode_ppc(struct megasas_instance *instance,
    struct megasas_cmd *cmd)
{
	int		i;
	uint32_t	msecs = MFI_POLL_TIMEOUT_SECS * MILLISEC;
	struct megasas_header *frame_hdr;

	con_log(CL_ANN1, (CE_NOTE, "issue_cmd_in_poll_mode_ppc: called\n"));

	frame_hdr = (struct megasas_header *)cmd->frame;
	frame_hdr->cmd_status	= MFI_CMD_STATUS_POLL_MODE;
	frame_hdr->flags 	|= MFI_FRAME_DONT_POST_IN_REPLY_QUEUE;

	/* issue the frame using inbound queue port */
	WR_IB_QPORT((host_to_le32(cmd->frame_phys_addr)) |
	    (((cmd->frame_count - 1) << 1) | 1), instance);

	/* wait for cmd_status to change from 0xFF */
	for (i = 0; i < msecs && (frame_hdr->cmd_status ==
	    MFI_CMD_STATUS_POLL_MODE); i++) {
		drv_usecwait(MILLISEC); /* wait for 1000 usecs */
	}

	if (frame_hdr->cmd_status == MFI_CMD_STATUS_POLL_MODE) {
		con_log(CL_ANN, (CE_NOTE, "issue_cmd_in_poll_mode: "
		    "cmd polling timed out"));
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
enable_intr_xscale(struct megasas_instance *instance)
{
	MFI_ENABLE_INTR(instance);
}

static void
enable_intr_ppc(struct megasas_instance *instance)
{
	uint32_t	mask;

	con_log(CL_ANN1, (CE_NOTE, "enable_intr_ppc: called\n"));

	/* WR_OB_DOORBELL_CLEAR(0xFFFFFFFF, instance); */
	WR_OB_DOORBELL_CLEAR(OB_DOORBELL_CLEAR_MASK, instance);

	/*
	 * As 1078DE is same as 1078 chip, the interrupt mask
	 * remains the same.
	 */
	/* WR_OB_INTR_MASK(~0x80000000, instance); */
	WR_OB_INTR_MASK(~(MFI_REPLY_1078_MESSAGE_INTR), instance);

	/* dummy read to force PCI flush */
	mask = RD_OB_INTR_MASK(instance);

	con_log(CL_ANN1, (CE_NOTE, "enable_intr_ppc: "
	    "outbound_intr_mask = 0x%x\n", mask));
}

static void
disable_intr_xscale(struct megasas_instance *instance)
{
	MFI_DISABLE_INTR(instance);
}

static void
disable_intr_ppc(struct megasas_instance *instance)
{
	uint32_t	mask;

	con_log(CL_ANN1, (CE_NOTE, "disable_intr_ppc: called\n"));

	con_log(CL_ANN1, (CE_NOTE, "disable_intr_ppc: before : "
	    "outbound_intr_mask = 0x%x\n", RD_OB_INTR_MASK(instance)));

	/* WR_OB_INTR_MASK(0xFFFFFFFF, instance); */
	WR_OB_INTR_MASK(OB_INTR_MASK, instance);

	con_log(CL_ANN1, (CE_NOTE, "disable_intr_ppc: after : "
	    "outbound_intr_mask = 0x%x\n", RD_OB_INTR_MASK(instance)));

	/* dummy read to force PCI flush */
	mask = RD_OB_INTR_MASK(instance);
#ifdef lint
	mask = mask;
#endif
}

static int
intr_ack_xscale(struct megasas_instance *instance)
{
	uint32_t	status;

	/* check if it is our interrupt */
	status = RD_OB_INTR_STATUS(instance);

	if (!(status & MFI_OB_INTR_STATUS_MASK)) {
		return (DDI_INTR_UNCLAIMED);
	}

	/* clear the interrupt by writing back the same value */
	WR_OB_INTR_STATUS(status, instance);

	return (DDI_INTR_CLAIMED);
}

static int
intr_ack_ppc(struct megasas_instance *instance)
{
	uint32_t	status;

	con_log(CL_ANN1, (CE_NOTE, "intr_ack_ppc: called\n"));

	/* check if it is our interrupt */
	status = RD_OB_INTR_STATUS(instance);

	con_log(CL_ANN1, (CE_NOTE, "intr_ack_ppc: status = 0x%x\n", status));

	/*
	 * As 1078DE is same as 1078 chip, the status field
	 * remains the same.
	 */
	if (!(status & MFI_REPLY_1078_MESSAGE_INTR)) {
		return (DDI_INTR_UNCLAIMED);
	}

	/* clear the interrupt by writing back the same value */
	WR_OB_DOORBELL_CLEAR(status, instance);

	/* dummy READ */
	status = RD_OB_INTR_STATUS(instance);

	con_log(CL_ANN1, (CE_NOTE, "intr_ack_ppc: interrupt cleared\n"));

	return (DDI_INTR_CLAIMED);
}

static int
megasas_common_check(struct megasas_instance *instance,
    struct  megasas_cmd *cmd)
{
	int ret = DDI_SUCCESS;

	if (megasas_check_dma_handle(cmd->frame_dma_obj.dma_handle) !=
	    DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_UNAFFECTED);
		if (cmd->pkt != NULL) {
			cmd->pkt->pkt_reason = CMD_TRAN_ERR;
			cmd->pkt->pkt_statistics = 0;
		}
		ret = DDI_FAILURE;
	}
	if (megasas_check_dma_handle(instance->mfi_internal_dma_obj.dma_handle)
	    != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_UNAFFECTED);
		if (cmd->pkt != NULL) {
			cmd->pkt->pkt_reason = CMD_TRAN_ERR;
			cmd->pkt->pkt_statistics = 0;
		}
		ret = DDI_FAILURE;
	}
	if (megasas_check_dma_handle(instance->mfi_evt_detail_obj.dma_handle) !=
	    DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_UNAFFECTED);
		if (cmd->pkt != NULL) {
			cmd->pkt->pkt_reason = CMD_TRAN_ERR;
			cmd->pkt->pkt_statistics = 0;
		}
		ret = DDI_FAILURE;
	}
	if (megasas_check_acc_handle(instance->regmap_handle) != DDI_SUCCESS) {
		ddi_fm_service_impact(instance->dip, DDI_SERVICE_UNAFFECTED);
		ddi_fm_acc_err_clear(instance->regmap_handle, DDI_FME_VER0);
		if (cmd->pkt != NULL) {
			cmd->pkt->pkt_reason = CMD_TRAN_ERR;
			cmd->pkt->pkt_statistics = 0;
		}
		ret = DDI_FAILURE;
	}

	return (ret);
}

/*ARGSUSED*/
static int
megasas_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	/*
	 * as the driver can always deal with an error in any dma or
	 * access handle, we can just return the fme_status value.
	 */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

static void
megasas_fm_init(struct megasas_instance *instance)
{
	/* Need to change iblock to priority for new MSI intr */
	ddi_iblock_cookie_t fm_ibc;

	/* Only register with IO Fault Services if we have some capability */
	if (instance->fm_capabilities) {
		/* Adjust access and dma attributes for FMA */
		endian_attr.devacc_attr_access = DDI_FLAGERR_ACC;
		megasas_generic_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;

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
			    megasas_fm_error_cb, (void*) instance);
		}
	} else {
		endian_attr.devacc_attr_access = DDI_DEFAULT_ACC;
		megasas_generic_dma_attr.dma_attr_flags = 0;
	}
}

static void
megasas_fm_fini(struct megasas_instance *instance)
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
		megasas_generic_dma_attr.dma_attr_flags = 0;
	}
}

int
megasas_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_fm_error_t de;

	if (handle == NULL) {
		return (DDI_FAILURE);
	}

	ddi_fm_acc_err_get(handle, &de, DDI_FME_VERSION);

	return (de.fme_status);
}

int
megasas_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_fm_error_t de;

	if (handle == NULL) {
		return (DDI_FAILURE);
	}

	ddi_fm_dma_err_get(handle, &de, DDI_FME_VERSION);

	return (de.fme_status);
}

void
megasas_fm_ereport(struct megasas_instance *instance, char *detail)
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
