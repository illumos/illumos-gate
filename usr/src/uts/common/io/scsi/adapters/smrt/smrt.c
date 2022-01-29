/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017, Joyent, Inc.
 */

#include <sys/scsi/adapters/smrt/smrt.h>

static int smrt_attach(dev_info_t *, ddi_attach_cmd_t);
static int smrt_detach(dev_info_t *, ddi_detach_cmd_t);
static int smrt_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static void smrt_cleanup(smrt_t *);
static int smrt_command_comparator(const void *, const void *);

/*
 * Controller soft state.  Each entry is an object of type "smrt_t".
 */
void *smrt_state;

/*
 * DMA attributes template.  Each controller will make a copy of this template
 * with appropriate customisations; e.g., the Scatter/Gather List Length.
 */
static ddi_dma_attr_t smrt_dma_attr_template = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0x0000000000000000,
	.dma_attr_addr_hi =		0xFFFFFFFFFFFFFFFF,
	.dma_attr_count_max =		0x00FFFFFF,
	.dma_attr_align =		0x20,
	.dma_attr_burstsizes =		0x20,
	.dma_attr_minxfer =		DMA_UNIT_8,
	.dma_attr_maxxfer =		0xFFFFFFFF,
	/*
	 * There is some suggestion that at least some, possibly older, Smart
	 * Array controllers cannot tolerate a DMA segment that straddles a 4GB
	 * boundary.
	 */
	.dma_attr_seg =			0xFFFFFFFF,
	.dma_attr_sgllen =		1,
	.dma_attr_granular =		512,
	.dma_attr_flags =		0
};

/*
 * Device memory access attributes for device control registers.
 */
ddi_device_acc_attr_t smrt_dev_attributes = {
	.devacc_attr_version =		DDI_DEVICE_ATTR_V0,
	.devacc_attr_endian_flags =	DDI_STRUCTURE_LE_ACC,
	.devacc_attr_dataorder =	DDI_STRICTORDER_ACC,
	.devacc_attr_access =		0
};

/*
 * Character/Block Operations Structure
 */
static struct cb_ops smrt_cb_ops = {
	.cb_rev =			CB_REV,
	.cb_flag =			D_NEW | D_MP,

	.cb_open =			scsi_hba_open,
	.cb_close =			scsi_hba_close,

	.cb_ioctl =			smrt_ioctl,

	.cb_strategy =			nodev,
	.cb_print =			nodev,
	.cb_dump =			nodev,
	.cb_read =			nodev,
	.cb_write =			nodev,
	.cb_devmap =			nodev,
	.cb_mmap =			nodev,
	.cb_segmap =			nodev,
	.cb_chpoll =			nochpoll,
	.cb_prop_op =			ddi_prop_op,
	.cb_str =			NULL,
	.cb_aread =			nodev,
	.cb_awrite =			nodev
};

/*
 * Device Operations Structure
 */
static struct dev_ops smrt_dev_ops = {
	.devo_rev =			DEVO_REV,
	.devo_refcnt =			0,

	.devo_attach =			smrt_attach,
	.devo_detach =			smrt_detach,

	.devo_cb_ops =			&smrt_cb_ops,

	.devo_getinfo =			nodev,
	.devo_identify =		nulldev,
	.devo_probe =			nulldev,
	.devo_reset =			nodev,
	.devo_bus_ops =			NULL,
	.devo_power =			nodev,
	.devo_quiesce =			nodev
};

/*
 * Linkage structures
 */
static struct modldrv smrt_modldrv = {
	.drv_modops =			&mod_driverops,
	.drv_linkinfo =			"HP Smart Array",
	.drv_dev_ops =			&smrt_dev_ops
};

static struct modlinkage smrt_modlinkage = {
	.ml_rev =			MODREV_1,
	.ml_linkage =			{ &smrt_modldrv, NULL }
};


int
_init()
{
	int r;

	VERIFY0(ddi_soft_state_init(&smrt_state, sizeof (smrt_t), 0));

	if ((r = scsi_hba_init(&smrt_modlinkage)) != 0) {
		goto fail;
	}

	if ((r = mod_install(&smrt_modlinkage)) != 0) {
		scsi_hba_fini(&smrt_modlinkage);
		goto fail;
	}

	return (r);

fail:
	ddi_soft_state_fini(&smrt_state);
	return (r);
}

int
_fini()
{
	int r;

	if ((r = mod_remove(&smrt_modlinkage)) == 0) {
		scsi_hba_fini(&smrt_modlinkage);
		ddi_soft_state_fini(&smrt_state);
	}

	return (r);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&smrt_modlinkage, modinfop));
}

static int
smrt_iport_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	const char *addr;
	dev_info_t *pdip;
	int instance;
	smrt_t *smrt;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * Note, we cannot get to our parent via the tran's tran_hba_private
	 * member.  This pointer is reset to NULL when the scsi_hba_tran_t
	 * structure is duplicated.
	 */
	addr = scsi_hba_iport_unit_address(dip);
	VERIFY(addr != NULL);
	pdip = ddi_get_parent(dip);
	instance = ddi_get_instance(pdip);
	smrt = ddi_get_soft_state(smrt_state, instance);
	VERIFY(smrt != NULL);

	if (strcmp(addr, SMRT_IPORT_VIRT) == 0) {
		if (smrt_logvol_hba_setup(smrt, dip) != DDI_SUCCESS)
			return (DDI_FAILURE);
		smrt->smrt_virt_iport = dip;
	} else if (strcmp(addr, SMRT_IPORT_PHYS) == 0) {
		if (smrt_phys_hba_setup(smrt, dip) != DDI_SUCCESS)
			return (DDI_FAILURE);
		smrt->smrt_phys_iport = dip;
	} else {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
smrt_iport_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	const char *addr;
	scsi_hba_tran_t *tran;
	smrt_t *smrt;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	tran = ddi_get_driver_private(dip);
	VERIFY(tran != NULL);
	smrt = tran->tran_hba_private;
	VERIFY(smrt != NULL);

	addr = scsi_hba_iport_unit_address(dip);
	VERIFY(addr != NULL);

	if (strcmp(addr, SMRT_IPORT_VIRT) == 0) {
		smrt_logvol_hba_teardown(smrt, dip);
		smrt->smrt_virt_iport = NULL;
	} else if (strcmp(addr, SMRT_IPORT_PHYS) == 0) {
		smrt_phys_hba_teardown(smrt, dip);
		smrt->smrt_phys_iport = NULL;
	} else {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
smrt_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	uint32_t instance;
	smrt_t *smrt;
	boolean_t check_for_interrupts = B_FALSE;
	int r;
	char taskq_name[64];

	if (scsi_hba_iport_unit_address(dip) != NULL)
		return (smrt_iport_attach(dip, cmd));

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	/*
	 * Allocate the per-controller soft state object and get
	 * a pointer to it.
	 */
	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(smrt_state, instance) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not allocate soft state");
		return (DDI_FAILURE);
	}
	if ((smrt = ddi_get_soft_state(smrt_state, instance)) == NULL) {
		dev_err(dip, CE_WARN, "could not get soft state");
		ddi_soft_state_free(smrt_state, instance);
		return (DDI_FAILURE);
	}

	/*
	 * Initialise per-controller state object.
	 */
	smrt->smrt_dip = dip;
	smrt->smrt_instance = instance;
	smrt->smrt_next_tag = SMRT_MIN_TAG_NUMBER;
	list_create(&smrt->smrt_commands, sizeof (smrt_command_t),
	    offsetof(smrt_command_t, smcm_link));
	list_create(&smrt->smrt_finishq, sizeof (smrt_command_t),
	    offsetof(smrt_command_t, smcm_link_finish));
	list_create(&smrt->smrt_abortq, sizeof (smrt_command_t),
	    offsetof(smrt_command_t, smcm_link_abort));
	list_create(&smrt->smrt_volumes, sizeof (smrt_volume_t),
	    offsetof(smrt_volume_t, smlv_link));
	list_create(&smrt->smrt_physicals, sizeof (smrt_physical_t),
	    offsetof(smrt_physical_t, smpt_link));
	list_create(&smrt->smrt_targets, sizeof (smrt_target_t),
	    offsetof(smrt_target_t, smtg_link_ctlr));
	avl_create(&smrt->smrt_inflight, smrt_command_comparator,
	    sizeof (smrt_command_t), offsetof(smrt_command_t,
	    smcm_node));
	cv_init(&smrt->smrt_cv_finishq, NULL, CV_DRIVER, NULL);

	smrt->smrt_init_level |= SMRT_INITLEVEL_BASIC;

	/*
	 * Perform basic device setup, including identifying the board, mapping
	 * the I2O registers and the Configuration Table.
	 */
	if (smrt_device_setup(smrt) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "device setup failed");
		goto fail;
	}

	/*
	 * Select a Transport Method (e.g. Simple or Performant) and update
	 * the Configuration Table.  This function also waits for the
	 * controller to become ready.
	 */
	if (smrt_ctlr_init(smrt) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "controller initialisation failed");
		goto fail;
	}

	/*
	 * Each controller may have a different Scatter/Gather Element count.
	 * Configure a per-controller set of DMA attributes with the
	 * appropriate S/G size.
	 */
	VERIFY(smrt->smrt_sg_cnt > 0);
	smrt->smrt_dma_attr = smrt_dma_attr_template;
	smrt->smrt_dma_attr.dma_attr_sgllen = smrt->smrt_sg_cnt;

	/*
	 * Now that we have selected a Transport Method, we can configure
	 * the appropriate interrupt handlers.
	 */
	if (smrt_interrupts_setup(smrt) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "interrupt handler setup failed");
		goto fail;
	}

	/*
	 * Now that we have the correct interrupt priority, we can initialise
	 * the mutex.  This must be done before the interrupt handler is
	 * enabled.
	 */
	mutex_init(&smrt->smrt_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(smrt->smrt_interrupt_pri));
	smrt->smrt_init_level |= SMRT_INITLEVEL_MUTEX;

	/*
	 * From this point forward, the controller is able to accept commands
	 * and (at least by polling) return command submissions.  Setting this
	 * flag allows the rest of the driver to interact with the device.
	 */
	smrt->smrt_status |= SMRT_CTLR_STATUS_RUNNING;

	if (smrt_interrupts_enable(smrt) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "interrupt handler could not be enabled");
		goto fail;
	}

	if (smrt_ctrl_hba_setup(smrt) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "SCSI framework setup failed");
		goto fail;
	}

	/*
	 * Set the appropriate Interrupt Mask Register bits to start
	 * command completion interrupts from the controller.
	 */
	smrt_intr_set(smrt, B_TRUE);
	check_for_interrupts = B_TRUE;

	/*
	 * Register the maintenance routine for periodic execution:
	 */
	smrt->smrt_periodic = ddi_periodic_add(smrt_periodic, smrt,
	    SMRT_PERIODIC_RATE * NANOSEC, DDI_IPL_0);
	smrt->smrt_init_level |= SMRT_INITLEVEL_PERIODIC;

	(void) snprintf(taskq_name, sizeof (taskq_name), "smrt_discover_%u",
	    instance);
	smrt->smrt_discover_taskq = ddi_taskq_create(smrt->smrt_dip, taskq_name,
	    1, TASKQ_DEFAULTPRI, 0);
	if (smrt->smrt_discover_taskq == NULL) {
		dev_err(dip, CE_WARN, "failed to create discovery task queue");
		goto fail;
	}
	smrt->smrt_init_level |= SMRT_INITLEVEL_TASKQ;

	if ((r = smrt_event_init(smrt)) != 0) {
		dev_err(dip, CE_WARN, "could not initialize event subsystem "
		    "(%d)", r);
		goto fail;
	}
	smrt->smrt_init_level |= SMRT_INITLEVEL_ASYNC_EVENT;

	if (scsi_hba_iport_register(dip, SMRT_IPORT_VIRT) != DDI_SUCCESS)
		goto fail;

	if (scsi_hba_iport_register(dip, SMRT_IPORT_PHYS) != DDI_SUCCESS)
		goto fail;

	/*
	 * Announce the attachment of this controller.
	 */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail:
	if (check_for_interrupts) {
		if (smrt->smrt_stats.smrts_claimed_interrupts == 0) {
			dev_err(dip, CE_WARN, "controller did not interrupt "
			    "during attach");
		}
	}
	smrt_cleanup(smrt);
	return (DDI_FAILURE);
}

static int
smrt_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	scsi_hba_tran_t *tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
	smrt_t *smrt = (smrt_t *)tran->tran_hba_private;

	if (scsi_hba_iport_unit_address(dip) != NULL)
		return (smrt_iport_detach(dip, cmd));

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	/*
	 * First, check to make sure that all SCSI framework targets have
	 * detached.
	 */
	mutex_enter(&smrt->smrt_mutex);
	if (!list_is_empty(&smrt->smrt_targets)) {
		mutex_exit(&smrt->smrt_mutex);
		dev_err(smrt->smrt_dip, CE_WARN, "cannot detach; targets still "
		    "using HBA");
		return (DDI_FAILURE);
	}

	if (smrt->smrt_virt_iport != NULL || smrt->smrt_phys_iport != NULL) {
		mutex_exit(&smrt->smrt_mutex);
		dev_err(smrt->smrt_dip, CE_WARN, "cannot detach: iports still "
		    "attached");
		return (DDI_FAILURE);
	}

	/*
	 * Prevent new targets from attaching now:
	 */
	smrt->smrt_status |= SMRT_CTLR_STATUS_DETACHING;
	mutex_exit(&smrt->smrt_mutex);

	/*
	 * Clean up all remaining resources.
	 */
	smrt_cleanup(smrt);

	return (DDI_SUCCESS);
}

static int
smrt_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rval)
{
	int inst = MINOR2INST(getminor(dev));
	int status;

	if (secpolicy_sys_config(credp, B_FALSE) != 0) {
		return (EPERM);
	}

	/*
	 * Ensure that we have a soft state object for this instance.
	 */
	if (ddi_get_soft_state(smrt_state, inst) == NULL) {
		return (ENXIO);
	}

	switch (cmd) {
	default:
		status = scsi_hba_ioctl(dev, cmd, arg, mode, credp, rval);
		break;
	}

	return (status);
}

static void
smrt_cleanup(smrt_t *smrt)
{
	if (smrt->smrt_init_level & SMRT_INITLEVEL_ASYNC_EVENT) {
		smrt_event_fini(smrt);
		smrt->smrt_init_level &= ~SMRT_INITLEVEL_ASYNC_EVENT;
	}

	smrt_interrupts_teardown(smrt);

	if (smrt->smrt_init_level & SMRT_INITLEVEL_TASKQ) {
		ddi_taskq_destroy(smrt->smrt_discover_taskq);
		smrt->smrt_discover_taskq = NULL;
		smrt->smrt_init_level &= ~SMRT_INITLEVEL_TASKQ;
	}

	if (smrt->smrt_init_level & SMRT_INITLEVEL_PERIODIC) {
		ddi_periodic_delete(smrt->smrt_periodic);
		smrt->smrt_init_level &= ~SMRT_INITLEVEL_PERIODIC;
	}

	smrt_ctrl_hba_teardown(smrt);

	smrt_ctlr_teardown(smrt);

	smrt_device_teardown(smrt);

	if (smrt->smrt_init_level & SMRT_INITLEVEL_BASIC) {
		smrt_logvol_teardown(smrt);
		smrt_phys_teardown(smrt);

		cv_destroy(&smrt->smrt_cv_finishq);

		VERIFY(list_is_empty(&smrt->smrt_commands));
		list_destroy(&smrt->smrt_commands);
		list_destroy(&smrt->smrt_finishq);
		list_destroy(&smrt->smrt_abortq);

		VERIFY(list_is_empty(&smrt->smrt_volumes));
		list_destroy(&smrt->smrt_volumes);

		VERIFY(list_is_empty(&smrt->smrt_physicals));
		list_destroy(&smrt->smrt_physicals);

		VERIFY(list_is_empty(&smrt->smrt_targets));
		list_destroy(&smrt->smrt_targets);

		VERIFY(avl_is_empty(&smrt->smrt_inflight));
		avl_destroy(&smrt->smrt_inflight);

		smrt->smrt_init_level &= ~SMRT_INITLEVEL_BASIC;
	}

	if (smrt->smrt_init_level & SMRT_INITLEVEL_MUTEX) {
		mutex_destroy(&smrt->smrt_mutex);

		smrt->smrt_init_level &= ~SMRT_INITLEVEL_MUTEX;
	}

	VERIFY0(smrt->smrt_init_level);

	ddi_soft_state_free(smrt_state, ddi_get_instance(smrt->smrt_dip));
}

/*
 * Comparator for the "smrt_inflight" AVL tree in a "smrt_t".  This AVL tree
 * allows a tag ID to be mapped back to the relevant "smrt_command_t".
 */
static int
smrt_command_comparator(const void *lp, const void *rp)
{
	const smrt_command_t *l = lp;
	const smrt_command_t *r = rp;

	if (l->smcm_tag > r->smcm_tag) {
		return (1);
	} else if (l->smcm_tag < r->smcm_tag) {
		return (-1);
	} else {
		return (0);
	}
}
