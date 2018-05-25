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
 * Copyright 2019 Nexenta Systems, Inc.
 * Copyright 2019 RackTop Systems
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
static int smartpqi_power(dev_info_t *dip, int component, int level);
static int smartpqi_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **results);
static int smartpqi_quiesce(dev_info_t *dip);

/* ---- cb_ops forward declarations ---- */
static int smartpqi_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *credp, int *rval);

static struct cb_ops smartpqi_cb_ops = {
	scsi_hba_open,		/* open */
	scsi_hba_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	smartpqi_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab */
	D_MP,			/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* aread */
	nodev			/* awrite */
};

static struct dev_ops smartpqi_ops = {
	DEVO_REV,		/* dev_rev */
	0,			/* refcnt */
	smartpqi_getinfo,	/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	smartpqi_attach,	/* attach */
	smartpqi_detach,	/* detach */
	nodev,			/* reset */
	&smartpqi_cb_ops,	/* driver operations */
	NULL,			/* bus operations */
	smartpqi_power,		/* power management */
	smartpqi_quiesce,	/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	SMARTPQI_MOD_STRING,
	&smartpqi_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int pqi_do_scan = 0;
int pqi_do_ctrl = 0;
int pqi_offline_target = 0;
int pqi_do_offline = 0;

/*
 * This is used for data I/O DMA memory allocation. (full 64-bit DMA
 * physical addresses are supported.)
 */
ddi_dma_attr_t smartpqi_dma_attrs = {
	DMA_ATTR_V0,		/* attribute layout version		*/
	0x0ull,			/* address low - should be 0 (longlong)	*/
	0xffffffffffffffffull, /* address high - 64-bit max	*/
	0x00666600ull,		/* count max - max DMA object size	*/
	4096,			/* allocation alignment requirements	*/
	0x78,			/* burstsizes - binary encoded values	*/
	1,			/* minxfer - gran. of DMA engine	*/
	0x00666600ull,		/* maxxfer - gran. of DMA engine	*/
	0x00666600ull,		/* max segment size (DMA boundary)	*/
	PQI_MAX_SCATTER_GATHER,	/* scatter/gather list length		*/
	512,			/* granularity - device transfer size	*/
	0			/* flags, set to 0			*/
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
	int	status;

	if ((status = ddi_soft_state_init(&pqi_state,
	    sizeof (struct pqi_state), SMARTPQI_INITIAL_SOFT_SPACE)) !=
	    0) {
		return (status);
	}

	if ((status = scsi_hba_init(&modlinkage)) != 0) {
		ddi_soft_state_fini(&pqi_state);
		return (status);
	}

	if ((status = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&pqi_state);
		scsi_hba_fini(&modlinkage);
	}

	return (status);
}

int
_fini(void)
{
	int	ret;

	if ((ret = mod_remove(&modlinkage)) == 0) {
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini(&pqi_state);
	}
	return (ret);
}

/*
 * The loadable-module _info(9E) entry point
 */
int
_info(struct modinfo *modinfop)
{
	/* CONSTCOND */
	ASSERT(NO_COMPETING_THREADS);

	return (mod_info(&modlinkage, modinfop));
}

/*ARGSUSED*/
static int smartpqi_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **result)
{
	int		rc = DDI_FAILURE;
	pqi_state_t	s;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((s = ddi_get_soft_state(pqi_state, 0)) == NULL)
			break;
		*result = s->s_dip;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		rc = DDI_SUCCESS;
		break;

	default:
		break;
	}
	return (rc);
}

static int
smartpqi_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance;
	pqi_state_t	s	= NULL;
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
	s->s_intr_ready = 0;
	s->s_offline = 0;
	list_create(&s->s_devnodes, sizeof (struct pqi_device),
	    offsetof(struct pqi_device, pd_list));
	list_create(&s->s_mem_check, sizeof (struct mem_check),
	    offsetof(struct mem_check, m_node));

	/* ---- Initialize mutex used in interrupt handler ---- */
	mutex_init(&s->s_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(s->s_intr_pri));
	mutex_init(&s->s_mem_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&s->s_io_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&s->s_intr_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&s->s_quiescedvar, NULL, CV_DRIVER, NULL);
	cv_init(&s->s_io_condvar, NULL, CV_DRIVER, NULL);
	sema_init(&s->s_sync_rqst, 1, NULL, SEMA_DRIVER, NULL);

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
	    "enable-mpxio", 0) != 0) {
		s->s_enable_mpxio = 1;
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
	s->s_mem_timeo = timeout(pqi_mem_check, s, drv_usectohz(5 * MICROSEC));

	return (DDI_SUCCESS);

fail:
	(void) smartpqi_detach(s->s_dip, 0);
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
smartpqi_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	pqi_state_t	s;
	pqi_device_t	devp;

	instance = ddi_get_instance(dip);
	if ((s = ddi_get_soft_state(pqi_state, instance)) != NULL) {
		if (s->s_rescan != NULL) {
			(void) untimeout(s->s_rescan);
			s->s_rescan = NULL;
		}

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
			PQI_FREE(devp, sizeof (*devp));
		}
		list_destroy(&s->s_devnodes);
		mutex_destroy(&s->s_mutex);
		mutex_destroy(&s->s_io_mutex);
		mutex_destroy(&s->s_intr_mutex);

		cv_destroy(&s->s_quiescedvar);
		smartpqi_unregister_hba(s);
		smartpqi_unregister_intrs(s);

		if (s->s_mem_timeo != 0) {
			mutex_enter(&s->s_mem_mutex);
			(void) untimeout(s->s_mem_timeo);
			s->s_mem_timeo = 0;
			mutex_exit(&s->s_mem_mutex);
			mutex_destroy(&s->s_mem_mutex);
		}

		if (s->s_time_of_day != 0) {
			(void) untimeout(s->s_time_of_day);
			s->s_time_of_day = 0;
		}

		ddi_soft_state_free(pqi_state, instance);
		ddi_prop_remove_all(dip);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
smartpqi_power(dev_info_t *dip, int component, int level)
{
	/* We don't register any power components yet. */
	return (DDI_SUCCESS);
}

static int
smartpqi_quiesce(dev_info_t *dip)
{
	pqi_state_t	s;
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

/*ARGSUSED*/
static int
smartpqi_ioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *credp,
    int *rval)
{
	/* Arguably we could just use nodev for the entry point. */
	return (EINVAL);
}
