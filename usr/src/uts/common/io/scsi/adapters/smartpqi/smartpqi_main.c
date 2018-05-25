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
 * Copyright 2023 Tintri by DDN, Inc. All rights reserved.
 * Copyright 2021 RackTop Systems, Inc.
 */

/*
 * Driver attach/detach routines are found here.
 */

/* ---- Private header files ---- */
#include <smartpqi.h>

void	*pqi_state;

/* ---- Autoconfigure forward declarations ---- */
static int smartpqi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int smartpqi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int smartpqi_quiesce(dev_info_t *dip);

static struct cb_ops smartpqi_cb_ops = {
	.cb_open =		scsi_hba_open,
	.cb_close =		scsi_hba_close,
	.cb_strategy =		nodev,
	.cb_print =		nodev,
	.cb_dump =		nodev,
	.cb_read =		nodev,
	.cb_write =		nodev,
	.cb_ioctl =		scsi_hba_ioctl,
	.cb_devmap =		nodev,
	.cb_mmap =		nodev,
	.cb_segmap =		nodev,
	.cb_chpoll =		nochpoll,
	.cb_prop_op =		ddi_prop_op,
	.cb_str =		NULL,
	.cb_flag =		D_MP,
	.cb_rev =		CB_REV,
	.cb_aread =		nodev,
	.cb_awrite =		nodev
};

static struct dev_ops smartpqi_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,
	.devo_getinfo =		nodev,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_attach =		smartpqi_attach,
	.devo_detach =		smartpqi_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&smartpqi_cb_ops,
	.devo_bus_ops =		NULL,
	.devo_power =		nodev,
	.devo_quiesce =		smartpqi_quiesce
};

static struct modldrv smartpqi_modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		SMARTPQI_MOD_STRING,
	.drv_dev_ops =		&smartpqi_ops
};

static struct modlinkage smartpqi_modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{ &smartpqi_modldrv, NULL }
};

/*
 * This is used for data I/O DMA memory allocation. (full 64-bit DMA
 * physical addresses are supported.)
 *
 * We believe that the device probably doesn't have any limitations,
 * but previous generations of this hardware used a 32-bit DMA counter.
 * Absent better guidance, we choose the same.  (Note that the Linux
 * driver from the vendor imposes no DMA limitations.)
 */
ddi_dma_attr_t smartpqi_dma_attrs = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0x0ull,
	.dma_attr_addr_hi =	0xffffffffffffffffull,
	.dma_attr_count_max =	0x00ffffffull,
	.dma_attr_align =	4096,
	.dma_attr_burstsizes =	0x78,
	.dma_attr_minxfer =	1,
	.dma_attr_maxxfer =	0x00ffffffull,
	.dma_attr_seg =		0xffffffffull,
	.dma_attr_sgllen =	PQI_MAX_SCATTER_GATHER,
	.dma_attr_granular =	512,
	.dma_attr_flags =	0,
};

ddi_device_acc_attr_t smartpqi_dev_attr = {
	DDI_DEVICE_ATTR_V1,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};

int
_init(void)
{
	int	ret;

	if ((ret = ddi_soft_state_init(&pqi_state,
	    sizeof (struct pqi_state), SMARTPQI_INITIAL_SOFT_SPACE)) !=
	    0) {
		return (ret);
	}

	if ((ret = scsi_hba_init(&smartpqi_modlinkage)) != 0) {
		ddi_soft_state_fini(&pqi_state);
		return (ret);
	}

	if ((ret = mod_install(&smartpqi_modlinkage)) != 0) {
		scsi_hba_fini(&smartpqi_modlinkage);
		ddi_soft_state_fini(&pqi_state);
	}

	return (ret);
}

int
_fini(void)
{
	int	ret;

	if ((ret = mod_remove(&smartpqi_modlinkage)) == 0) {
		scsi_hba_fini(&smartpqi_modlinkage);
		ddi_soft_state_fini(&pqi_state);
	}
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&smartpqi_modlinkage, modinfop));
}

static int
smartpqi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;
	pqi_state_t	*s	= NULL;
	int		mem_bar	= IO_SPACE;
	mem_len_pair_t	m;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	/* ---- allocate softc structure ---- */
	if (ddi_soft_state_zalloc(pqi_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if ((s = ddi_get_soft_state(pqi_state, instance)) == NULL)
		goto fail;

	scsi_size_clean(dip);

	s->s_dip = dip;
	s->s_instance = instance;
	s->s_intr_ready = B_FALSE;
	s->s_offline = B_FALSE;
	list_create(&s->s_devnodes, sizeof (struct pqi_device),
	    offsetof(struct pqi_device, pd_list));
	list_create(&s->s_special_device.pd_cmd_list, sizeof (struct pqi_cmd),
	    offsetof(struct pqi_cmd, pc_list));

	/* ---- Initialize mutex used in interrupt handler ---- */
	mutex_init(&s->s_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(s->s_intr_pri));
	mutex_init(&s->s_io_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&s->s_intr_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&s->s_special_device.pd_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&s->s_quiescedvar, NULL, CV_DRIVER, NULL);
	cv_init(&s->s_io_condvar, NULL, CV_DRIVER, NULL);

	m = pqi_alloc_mem_len(256);
	(void) snprintf(m.mem, m.len, "smartpqi_cache%d", instance);
	s->s_cmd_cache = kmem_cache_create(m.mem, sizeof (struct pqi_cmd), 0,
	    pqi_cache_constructor, pqi_cache_destructor, NULL, s, NULL, 0);

	(void) snprintf(m.mem, m.len, "pqi_events_taskq%d", instance);
	s->s_events_taskq = ddi_taskq_create(s->s_dip, m.mem, 1,
	    TASKQ_DEFAULTPRI, 0);
	(void) snprintf(m.mem, m.len, "pqi_complete_taskq%d", instance);
	s->s_complete_taskq = ddi_taskq_create(s->s_dip, m.mem, 4,
	    TASKQ_DEFAULTPRI, 0);
	pqi_free_mem_len(&m);

	s->s_debug_level = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "debug", 0);

	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "disable-mpxio", 0) != 0) {
		s->s_disable_mpxio = B_TRUE;
	}
	if (smartpqi_register_intrs(s) == FALSE) {
		dev_err(s->s_dip, CE_WARN, "unable to register interrupts");
		goto fail;
	}

	s->s_msg_dma_attr = smartpqi_dma_attrs;
	s->s_reg_acc_attr = smartpqi_dev_attr;

	if (ddi_regs_map_setup(dip, mem_bar, (caddr_t *)&s->s_reg, 0,
	    /* sizeof (pqi_ctrl_regs_t) */ 0x8000, &s->s_reg_acc_attr,
	    &s->s_datap) != DDI_SUCCESS) {
		dev_err(s->s_dip, CE_WARN, "map setup failed");
		goto fail;
	}

	if (pqi_check_firmware(s) == B_FALSE) {
		dev_err(s->s_dip, CE_WARN, "firmware issue");
		goto fail;
	}
	if (pqi_prep_full(s) == B_FALSE) {
		goto fail;
	}
	if (smartpqi_register_hba(s) == FALSE) {
		dev_err(s->s_dip, CE_WARN, "unable to register SCSI interface");
		goto fail;
	}
	ddi_report_dev(s->s_dip);

	return (DDI_SUCCESS);

fail:
	(void) smartpqi_detach(s->s_dip, 0);
	return (DDI_FAILURE);
}

static int
smartpqi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd __unused)
{
	int		instance;
	pqi_state_t	*s;
	pqi_device_t	*devp;

	instance = ddi_get_instance(dip);
	if ((s = ddi_get_soft_state(pqi_state, instance)) != NULL) {

		if (s->s_watchdog != 0) {
			(void) untimeout(s->s_watchdog);
			s->s_watchdog = 0;
		}

		if (s->s_error_dma != NULL) {
			pqi_free_single(s, s->s_error_dma);
			s->s_error_dma = NULL;
		}
		if (s->s_adminq_dma != NULL) {
			pqi_free_single(s, s->s_adminq_dma);
			s->s_adminq_dma = NULL;
		}
		if (s->s_queue_dma != NULL) {
			pqi_free_single(s, s->s_queue_dma);
			s->s_queue_dma = NULL;
		}

		/* ---- Safe to always call ---- */
		pqi_free_io_resource(s);

		if (s->s_cmd_cache != NULL) {
			kmem_cache_destroy(s->s_cmd_cache);
			s->s_cmd_cache = NULL;
		}

		if (s->s_events_taskq != NULL) {
			ddi_taskq_destroy(s->s_events_taskq);
			s->s_events_taskq = NULL;
		}
		if (s->s_complete_taskq != NULL) {
			ddi_taskq_destroy(s->s_complete_taskq);
			s->s_complete_taskq = NULL;
		}

		while ((devp = list_head(&s->s_devnodes)) != NULL) {
			/* ---- Better not be any active commands ---- */
			ASSERT(list_is_empty(&devp->pd_cmd_list));

			ddi_devid_free_guid(devp->pd_guid);
			if (devp->pd_pip != NULL)
				(void) mdi_pi_free(devp->pd_pip, 0);
			if (devp->pd_pip_offlined)
				(void) mdi_pi_free(devp->pd_pip_offlined, 0);
			list_destroy(&devp->pd_cmd_list);
			mutex_destroy(&devp->pd_mutex);
			list_remove(&s->s_devnodes, devp);
			kmem_free(devp, sizeof (*devp));
		}
		list_destroy(&s->s_devnodes);
		mutex_destroy(&s->s_mutex);
		mutex_destroy(&s->s_io_mutex);
		mutex_destroy(&s->s_intr_mutex);

		cv_destroy(&s->s_quiescedvar);
		smartpqi_unregister_hba(s);
		smartpqi_unregister_intrs(s);

		if (s->s_time_of_day != 0) {
			(void) untimeout(s->s_time_of_day);
			s->s_time_of_day = 0;
		}

		ddi_soft_state_free(pqi_state, instance);
		ddi_prop_remove_all(dip);
	}

	return (DDI_SUCCESS);
}

static int
smartpqi_quiesce(dev_info_t *dip)
{
	pqi_state_t	*s;
	int		instance;

	/*
	 * ddi_get_soft_state is lock-free, so is safe to call from
	 * quiesce.  Furthermore, pqi_hba_reset uses only the safe
	 * drv_usecwait() and register accesses.
	 */
	instance = ddi_get_instance(dip);
	if ((s = ddi_get_soft_state(pqi_state, instance)) != NULL) {
		if (pqi_hba_reset(s)) {
			return (DDI_SUCCESS);
		}
	}
	/* If we couldn't quiesce for any reason, play it safe and reboot. */
	return (DDI_FAILURE);
}
