/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

#include "bnx.h"
#include "bnxgld.h"
#include "bnxhwi.h"
#include "bnxint.h"
#include "bnxtmr.h"
#include "bnxcfg.h"

#define	BNX_PRODUCT_BANNER "QLogic 570x/571x Gigabit Ethernet Driver "\
    BRCMVERSION

#define	BNX_PRODUCT_INFO "QLogic 570x/571x GbE "\
    BRCMVERSION

ddi_device_acc_attr_t bnxAccessAttribBAR = {
	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_STRUCTURE_LE_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC,	/* devacc_attr_dataorder */
	DDI_DEFAULT_ACC		/* devacc_attr_access */
};

ddi_device_acc_attr_t bnxAccessAttribBUF = {
	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC,	/* devacc_attr_dataorder */
	DDI_DEFAULT_ACC		/* devacc_attr_access */
};


/*
 * Name:    bnx_free_system_resources
 *
 * Input:   ptr to device structure
 *
 * Return:  void
 *
 * Description:
 *          This function is called from detach() entry point to free most
 *          resources held by this device instance.
 */
static int
bnx_free_system_resources(um_device_t * const umdevice)
{
	if (umdevice->os_param.active_resc_flag & DRV_RESOURCE_MINOR_NODE) {
		umdevice->os_param.active_resc_flag &= ~DRV_RESOURCE_MINOR_NODE;
#ifdef _USE_FRIENDLY_NAME
		ddi_remove_minor_node(umdevice->os_param.dip,
		    (char *)ddi_driver_name(umdevice->os_param.dip));
#else
		ddi_remove_minor_node(umdevice->os_param.dip,
		    ddi_get_name(umdevice->os_param.dip));
#endif
	}

	if (umdevice->os_param.active_resc_flag & DRV_RESOURCE_TIMER) {
		umdevice->os_param.active_resc_flag &=
		    ~DRV_RESOURCE_TIMER;
		bnx_timer_fini(umdevice);
	}

	if (umdevice->os_param.active_resc_flag & DRV_RESOURCE_GLD_REGISTER) {
		if (bnx_gld_fini(umdevice)) {
			/*
			 * FIXME -- If bnx_gld_fini() fails, we need to
			 * reactivate resources.
			 */
			return (-1);
		}
		umdevice->os_param.active_resc_flag &=
		    ~DRV_RESOURCE_GLD_REGISTER;
	}

	if (umdevice->os_param.active_resc_flag & DRV_RESOURCE_KSTAT) {
		umdevice->os_param.active_resc_flag &= ~DRV_RESOURCE_KSTAT;
		bnx_kstat_fini(umdevice);
	}

	if (umdevice->os_param.active_resc_flag & DRV_RESOURCE_HDWR_REGISTER) {
		umdevice->os_param.active_resc_flag &=
		    ~DRV_RESOURCE_HDWR_REGISTER;
		bnx_hdwr_fini(umdevice);
	}

	if (umdevice->os_param.active_resc_flag & DRV_RESOURCE_MUTEX) {
		umdevice->os_param.active_resc_flag &= ~DRV_RESOURCE_MUTEX;
		mutex_destroy(&umdevice->os_param.ind_mutex);
		mutex_destroy(&umdevice->os_param.phy_mutex);
		mutex_destroy(&umdevice->os_param.rcv_mutex);
	}

	if (umdevice->os_param.active_resc_flag & DRV_RESOURCE_INTR_1) {
		umdevice->os_param.active_resc_flag &= ~DRV_RESOURCE_INTR_1;
		bnxIntrFini(umdevice);
	}

	if (umdevice->os_param.active_resc_flag & DRV_RESOURCE_MAP_REGS) {
		umdevice->os_param.active_resc_flag &= ~DRV_RESOURCE_MAP_REGS;
		ddi_regs_map_free(&umdevice->os_param.reg_acc_handle);
		umdevice->lm_dev.vars.dmaRegAccHandle = NULL;
		umdevice->os_param.reg_acc_handle = NULL;
	}

	if (umdevice->os_param.active_resc_flag & DRV_RESOURCE_PCICFG_MAPPED) {
		umdevice->os_param.active_resc_flag &=
		    ~DRV_RESOURCE_PCICFG_MAPPED;
		pci_config_teardown(&umdevice->os_param.pci_cfg_handle);
	}

	return (0);
}



/*
 * Name:    bnx_attach_attach
 *
 * Input:   ptr to dev_info_t
 *
 * Return:  DDI_SUCCESS or DDI_FAILURE.
 *
 * Description: This is the main code involving all important driver data struct
 *		and device initialization stuff. This function allocates driver
 *		soft state for this instance of the driver,  sets access up
 *		attributes for the device, maps BAR register space, initializes
 *		the hardware, determines interrupt pin, registers interrupt
 *		service routine with the OS and initializes receive/transmit
 *		mutex. After successful completion of above mentioned tasks,
 *		the driver registers with the GLD and creates minor node in
 *		the file system tree for this device.
 */
static int
bnx_attach_attach(um_device_t *umdevice)
{
	int rc;
	int instance;
	unsigned int val;
	int chip_id;
	int device_id;
	int subdevice_id;
	off_t regSize;

	dev_info_t *dip;

	dip = umdevice->os_param.dip;

	umdevice->os_param.active_resc_flag = 0;

	rc = pci_config_setup(umdevice->os_param.dip,
	    &umdevice->os_param.pci_cfg_handle);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s: Failed to setup PCI configuration space accesses.\n",
		    umdevice->dev_name);
		goto error;
	}

	umdevice->os_param.active_resc_flag |= DRV_RESOURCE_PCICFG_MAPPED;

	rc = ddi_dev_regsize(dip, 1, &regSize);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: failed to determine register set size.",
		    umdevice->dev_name);
	}

	/*
	 * Setup device memory mapping so that LM driver can start accessing it.
	 */
	rc = ddi_regs_map_setup(dip,
	    1, /* BAR */
	    &umdevice->os_param.regs_addr,
	    0, /* OFFSET */
	    regSize,
	    &bnxAccessAttribBAR,
	    &umdevice->os_param.reg_acc_handle);
	if (rc != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s: Failed to memory map device.\n",
		    umdevice->dev_name);
		goto error;
	}

	umdevice->os_param.active_resc_flag |= DRV_RESOURCE_MAP_REGS;

	bnx_cfg_msix(umdevice);

	if (bnxIntrInit(umdevice) != 0) {
		goto error;
	}

	umdevice->os_param.active_resc_flag |= DRV_RESOURCE_INTR_1;

	mutex_init(&umdevice->os_param.rcv_mutex, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(umdevice->intrPriority));
	mutex_init(&umdevice->os_param.phy_mutex, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(umdevice->intrPriority));
	mutex_init(&umdevice->os_param.ind_mutex, NULL,
	    MUTEX_DRIVER, DDI_INTR_PRI(umdevice->intrPriority));

	umdevice->os_param.active_resc_flag |= DRV_RESOURCE_MUTEX;

	/*
	 * Call lower module's initialization routines to initialize
	 * hardware and related components within BNX.
	 */
	if (bnx_hdwr_init(umdevice)) {
		goto error;
	}

	umdevice->os_param.active_resc_flag |= DRV_RESOURCE_HDWR_REGISTER;

	if (!bnx_kstat_init(umdevice)) {
		goto error;
	}

	umdevice->os_param.active_resc_flag |= DRV_RESOURCE_KSTAT;

	if (bnx_gld_init(umdevice)) {
		goto error;
	}

	umdevice->os_param.active_resc_flag |= DRV_RESOURCE_GLD_REGISTER;

	bnx_timer_init(umdevice);

	umdevice->os_param.active_resc_flag |= DRV_RESOURCE_TIMER;

	instance = ddi_get_instance(umdevice->os_param.dip);

	/* Create a minor node entry in /devices . */
#ifdef _USE_FRIENDLY_NAME
	rc = ddi_create_minor_node(dip, (char *)ddi_driver_name(dip),
	    S_IFCHR, instance, DDI_PSEUDO, 0);
#else
	rc = ddi_create_minor_node(dip, ddi_get_name(dip),
	    S_IFCHR, instance, DDI_PSEUDO, 0);
#endif
	if (rc == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s: Failed to create device minor node.\n",
		    umdevice->dev_name);
		goto error;
	}

	umdevice->os_param.active_resc_flag |= DRV_RESOURCE_MINOR_NODE;

	ddi_report_dev(dip);

	device_id = pci_config_get16(umdevice->os_param.pci_cfg_handle,
	    0x2);
	subdevice_id = pci_config_get16(umdevice->os_param.pci_cfg_handle,
	    0x2e);

	/*  Dip into PCI config space to determine if we have 5716's */
	if ((device_id == 0x163b) && (subdevice_id == 0x163b)) {
		chip_id = 0x5716;
	} else {
		chip_id = CHIP_NUM(&umdevice->lm_dev) >> 16;
	}

	(void) snprintf(umdevice->version, sizeof (umdevice->version), "%s",
	    BRCMVERSION);

	/* Get firmware version. */
	REG_RD_IND(&umdevice->lm_dev,
	    umdevice->lm_dev.hw_info.shmem_base +
	    OFFSETOF(shmem_region_t, dev_info.bc_rev), &val);
	umdevice->dev_var.fw_ver = (val & 0xFFFF0000) | ((val & 0xFF00) >> 8);

	(void) snprintf(umdevice->versionFW, sizeof (umdevice->versionFW),
	    "0x%x", umdevice->dev_var.fw_ver);

	(void) snprintf(umdevice->chipName, sizeof (umdevice->chipName),
	    "BCM%x", chip_id);

	(void) snprintf(umdevice->intrAlloc, sizeof (umdevice->intrAlloc),
	    "1 %s", (umdevice->intrType == DDI_INTR_TYPE_MSIX) ? "MSIX" :
	    (umdevice->intrType == DDI_INTR_TYPE_MSI)  ? "MSI"  :
	    "Fixed");

	cmn_err(CE_NOTE,
	    "!%s: (%s) BCM%x device with F/W Ver%x is initialized (%s)",
	    umdevice->dev_name, umdevice->version,
	    chip_id, umdevice->dev_var.fw_ver,
	    umdevice->intrAlloc);

	return (0);

error:
	(void) bnx_free_system_resources(umdevice);

	return (-1);
}

/*
 * Name:    bnx_attach
 *
 * Input:   ptr to dev_info_t, command code for the task to be executed
 *
 * Return:  DDI_SUCCESS or DDI_FAILURE.
 *
 * Description:	OS determined module attach entry point.
 */
static int
bnx_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	um_device_t *umdevice;
	int ret_val = DDI_SUCCESS;

	switch (cmd) {
		case DDI_ATTACH:
			umdevice = kmem_zalloc(sizeof (um_device_t),
			    KM_NOSLEEP);
			if (umdevice == NULL) {
				cmn_err(CE_WARN, "%s: Failed to allocate "
				    "device memory.\n", __func__);
				ret_val = DDI_FAILURE;
				break;
			}

			/* Save dev_info_t info in the driver struture. */
			umdevice->os_param.dip = dip;

			/*
			 * Obtain a human-readable name to prepend all our
			 * messages with.
			 */
			umdevice->instance = ddi_get_instance(dip);
			(void) snprintf(umdevice->dev_name,
			    sizeof (umdevice->dev_name), "%s%d", "bnx",
			    umdevice->instance);

			/*
			 * Set driver private pointer to per device structure
			 * ptr.
			 */
			ddi_set_driver_private(dip, (caddr_t)umdevice);

			umdevice->magic = BNX_MAGIC;

			if (bnx_attach_attach(umdevice)) {
				ddi_set_driver_private(dip, (caddr_t)NULL);
				kmem_free(umdevice, sizeof (um_device_t));
				ret_val = DDI_FAILURE;
			}
			break;

		case DDI_RESUME:
			/* Retrieve our device structure. */
			umdevice = ddi_get_driver_private(dip);
			if (umdevice == NULL) {
				ret_val = DDI_FAILURE;
				break;
			}
			break;

		default:
			ret_val = DDI_FAILURE;
			break;
	}

	return (ret_val);
}

/*
 * Name:    bnx_detach
 *
 * Input:   ptr to dev_info_t, command code for the task to be executed
 *
 * Return:  DDI_SUCCESS or DDI_FAILURE.
 *
 * Description:	OS determined module detach entry point.
 */
static int
bnx_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	um_device_t *umdevice;
	int ret_val = DDI_SUCCESS;

	switch (cmd) {
		case DDI_DETACH:
			umdevice = ddi_get_driver_private(dip);
			if (umdevice == NULL) {
				/* Must have failed attach. */
				ret_val = DDI_SUCCESS;
				break;
			}

			/* Sanity check. */
			if (umdevice == NULL) {
				cmn_err(CE_WARN,
				    "%s: Sanity check failed(1).", __func__);
				ret_val = DDI_SUCCESS;
				break;
			}

			/* Sanity check. */
			if (umdevice->os_param.dip != dip) {
				cmn_err(CE_WARN,
				    "%s: Sanity check failed(2).", __func__);
				ret_val = DDI_SUCCESS;
				break;
			}

			/* Another sanity check. */
			if (umdevice->intr_enabled != B_FALSE) {
				cmn_err(CE_WARN, "%s: Detaching a device "
				    "that is currently running!!!\n",
				    umdevice->dev_name);
				ret_val = DDI_FAILURE;
				break;
			}

			if (bnx_free_system_resources(umdevice)) {
				ret_val = DDI_FAILURE;
				break;
			}

			ddi_set_driver_private(dip, (caddr_t)NULL);
			kmem_free(umdevice, sizeof (um_device_t));
			break;

		case DDI_SUSPEND:
			/* Retrieve our device structure. */
			umdevice = ddi_get_driver_private(dip);
			if (umdevice == NULL) {
				ret_val = DDI_FAILURE;
				break;
			}
			break;

		default:
			ret_val = DDI_FAILURE;
			break;
	}

	return (ret_val);
}

/*
 * Name:    bnx_quiesce
 *
 * Input:   ptr to dev_info_t
 *
 * Return:  DDI_SUCCESS or DDI_FAILURE.
 *
 * Description: quiesce(9E) entry point.
 *              This function will make sure no more interrupts and DMA of
 *              the hardware. It is called when the system is single-threaded
 *              at high PIL with preemption disabled. Thus this function should
 *              not be blocked.
 */
static int
bnx_quiesce(dev_info_t *dip)
{
	um_device_t *umdevice;

	umdevice = ddi_get_driver_private(dip);

	/* Sanity check. */
	if (umdevice == NULL || umdevice->os_param.dip != dip) {
		cmn_err(CE_WARN, "%s: Sanity check failed.", __func__);
		return (DDI_FAILURE);
	}

	/* Stop the device from generating any interrupts. */
	lm_disable_int(&(umdevice->lm_dev));

	/* Set RX mask to stop receiving any further packets */
	(void) lm_set_rx_mask(&(umdevice->lm_dev), RX_FILTER_USER_IDX0,
	    LM_RX_MASK_ACCEPT_NONE);

	return (DDI_SUCCESS);
}

DDI_DEFINE_STREAM_OPS(bnx_dev_ops, nulldev, nulldev, bnx_attach, bnx_detach, \
    nodev, NULL, (D_MP | D_64BIT), NULL, bnx_quiesce);

static struct modldrv bnx_modldrv = {
	&mod_driverops,		/* drv_modops */
	BNX_PRODUCT_INFO,	/* drv_linkinfo */
	&bnx_dev_ops		/* drv_dev_ops */
};

static struct modlinkage bnx_modlinkage = {
	MODREV_1,	/* ml_rev */
	&bnx_modldrv,	/* ml_linkage */
	NULL		/* NULL termination */
};

/*
 * Name:        _init
 *
 * Input:       None
 *
 * Return:      SUCCESS or FAILURE.
 *
 * Description: OS determined driver module load entry point.
 */
int
_init(void)
{
	int rc;

	mac_init_ops(&bnx_dev_ops, "bnx");

	/* Install module information with O/S */
	rc = mod_install(&bnx_modlinkage);
	if (rc != 0) {
		cmn_err(CE_WARN, "%s:_init - mod_install returned 0x%x", "bnx",
		    rc);
		return (rc);
	}

	cmn_err(CE_NOTE, "!%s", BNX_PRODUCT_BANNER);

	return (rc);
}



/*
 * Name:        _fini
 *
 * Input:       None
 *
 * Return:      SUCCESS or FAILURE.
 *
 * Description: OS determined driver module unload entry point.
 */
int
_fini(void)
{
	int rc;

	rc = mod_remove(&bnx_modlinkage);

	if (rc == 0) {
		mac_fini_ops(&bnx_dev_ops);
	}

	return (rc);
}

/*
 * Name:        _info
 *
 * Input:       None
 *
 * Return:      SUCCESS or FAILURE.
 *
 * Description: OS determined module info entry point.
 */
int
_info(struct modinfo *modinfop)
{
	int rc;

	rc = mod_info(&bnx_modlinkage, modinfop);

	return (rc);
}
