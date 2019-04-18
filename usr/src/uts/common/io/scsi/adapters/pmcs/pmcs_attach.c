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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <sys/scsi/adapters/pmcs/pmcs.h>

#define	PMCS_DRIVER_VERSION	"pmcs HBA device driver"

static	char	*pmcs_driver_rev = PMCS_DRIVER_VERSION;

/*
 * Non-DDI Compliant stuff
 */
extern char hw_serial[];

/*
 * Global driver data
 */
void *pmcs_softc_state = NULL;
void *pmcs_iport_softstate = NULL;

/*
 * Tracing and Logging info
 */
pmcs_tbuf_t *pmcs_tbuf = NULL;
uint32_t pmcs_tbuf_num_elems = 0;
pmcs_tbuf_t *pmcs_tbuf_ptr;
uint32_t pmcs_tbuf_idx = 0;
boolean_t pmcs_tbuf_wrap = B_FALSE;
kmutex_t pmcs_trace_lock;

/*
 * If pmcs_force_syslog value is non-zero, all messages put in the trace log
 * will also be sent to system log.
 */
int pmcs_force_syslog = 0;
int pmcs_console = 0;

/*
 * External References
 */
extern int ncpus_online;

/*
 * Local static data
 */
static int fwlog_level = 3;
static int physpeed = PHY_LINK_ALL;
static int phymode = PHY_LM_AUTO;
static int block_mask = 0;
static int phymap_stable_usec = 3 * MICROSEC;
static int iportmap_stable_usec = 2 * MICROSEC;
static int iportmap_csync_usec = 20 * MICROSEC;

#ifdef DEBUG
static int debug_mask = 1;
#else
static int debug_mask = 0;
#endif

#ifdef DISABLE_MSIX
static int disable_msix = 1;
#else
static int disable_msix = 0;
#endif

#ifdef DISABLE_MSI
static int disable_msi = 1;
#else
static int disable_msi = 0;
#endif

/*
 * DEBUG: testing: allow detach with an active port:
 *
 * # echo 'detach_driver_unconfig/W 10'		| mdb -kw
 * # echo 'scsi_hba_bus_unconfig_remove/W 1'	| mdb -kw
 * # echo 'pmcs`detach_with_active_port/W 1'	| mdb -kw
 * # modunload -i <pmcs_driver_index>
 */
static int detach_with_active_port = 0;

static uint16_t maxqdepth = 0xfffe;

/*
 * Local prototypes
 */
static int pmcs_attach(dev_info_t *, ddi_attach_cmd_t);
static int pmcs_detach(dev_info_t *, ddi_detach_cmd_t);
static int pmcs_unattach(pmcs_hw_t *);
static int pmcs_iport_unattach(pmcs_iport_t *);
static int pmcs_add_more_chunks(pmcs_hw_t *, unsigned long);
static void pmcs_watchdog(void *);
static int pmcs_setup_intr(pmcs_hw_t *);
static int pmcs_teardown_intr(pmcs_hw_t *);

static uint_t pmcs_nonio_ix(caddr_t, caddr_t);
static uint_t pmcs_general_ix(caddr_t, caddr_t);
static uint_t pmcs_event_ix(caddr_t, caddr_t);
static uint_t pmcs_iodone_ix(caddr_t, caddr_t);
static uint_t pmcs_fatal_ix(caddr_t, caddr_t);
static uint_t pmcs_all_intr(caddr_t, caddr_t);
static int pmcs_quiesce(dev_info_t *dip);
static boolean_t pmcs_fabricate_wwid(pmcs_hw_t *);

static void pmcs_create_all_phy_stats(pmcs_iport_t *);
int pmcs_update_phy_stats(kstat_t *, int);

static void pmcs_fm_fini(pmcs_hw_t *pwp);
static void pmcs_fm_init(pmcs_hw_t *pwp);
static int pmcs_fm_error_cb(dev_info_t *dip,
    ddi_fm_error_t *err, const void *impl_data);

/*
 * Local configuration data
 */
static struct dev_ops pmcs_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt */
	ddi_no_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	pmcs_attach,		/* attach */
	pmcs_detach,		/* detach */
	nodev,			/* reset */
	NULL,			/* driver operations */
	NULL,			/* bus operations */
	ddi_power,		/* power management */
	pmcs_quiesce		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	PMCS_DRIVER_VERSION,
	&pmcs_ops,	/* driver ops */
};
static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

const ddi_dma_attr_t pmcs_dattr = {
	DMA_ATTR_V0,			/* dma_attr version	*/
	0x0000000000000000ull,		/* dma_attr_addr_lo	*/
	0xFFFFFFFFFFFFFFFFull,		/* dma_attr_addr_hi	*/
	0x00000000FFFFFFFFull,		/* dma_attr_count_max	*/
	0x0000000000000001ull,		/* dma_attr_align	*/
	0x00000078,			/* dma_attr_burstsizes	*/
	0x00000001,			/* dma_attr_minxfer	*/
	0x00000000FFFFFFFFull,		/* dma_attr_maxxfer	*/
	0x00000000FFFFFFFFull,		/* dma_attr_seg		*/
	1,				/* dma_attr_sgllen	*/
	512,				/* dma_attr_granular	*/
	0				/* dma_attr_flags	*/
};

static ddi_device_acc_attr_t rattr = {
	DDI_DEVICE_ATTR_V1,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_DEFAULT_ACC
};


/*
 * Attach/Detach functions
 */

int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&pmcs_softc_state, sizeof (pmcs_hw_t), 1);
	if (ret != 0) {
		cmn_err(CE_WARN, "?soft state init failed for pmcs");
		return (ret);
	}

	if ((ret = scsi_hba_init(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "?scsi_hba_init failed for pmcs");
		ddi_soft_state_fini(&pmcs_softc_state);
		return (ret);
	}

	/*
	 * Allocate soft state for iports
	 */
	ret = ddi_soft_state_init(&pmcs_iport_softstate,
	    sizeof (pmcs_iport_t), 2);
	if (ret != 0) {
		cmn_err(CE_WARN, "?iport soft state init failed for pmcs");
		ddi_soft_state_fini(&pmcs_softc_state);
		return (ret);
	}

	ret = mod_install(&modlinkage);
	if (ret != 0) {
		cmn_err(CE_WARN, "?mod_install failed for pmcs (%d)", ret);
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini(&pmcs_iport_softstate);
		ddi_soft_state_fini(&pmcs_softc_state);
		return (ret);
	}

	/* Initialize the global trace lock */
	mutex_init(&pmcs_trace_lock, NULL, MUTEX_DRIVER, NULL);

	return (0);
}

int
_fini(void)
{
	int ret;
	if ((ret = mod_remove(&modlinkage)) != 0) {
		return (ret);
	}
	scsi_hba_fini(&modlinkage);

	/* Free pmcs log buffer and destroy the global lock */
	if (pmcs_tbuf) {
		kmem_free(pmcs_tbuf,
		    pmcs_tbuf_num_elems * sizeof (pmcs_tbuf_t));
		pmcs_tbuf = NULL;
	}
	mutex_destroy(&pmcs_trace_lock);

	ddi_soft_state_fini(&pmcs_iport_softstate);
	ddi_soft_state_fini(&pmcs_softc_state);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
pmcs_iport_attach(dev_info_t *dip)
{
	pmcs_iport_t		*iport;
	pmcs_hw_t		*pwp;
	scsi_hba_tran_t		*tran;
	void			*ua_priv = NULL;
	char			*iport_ua;
	char			*init_port;
	int			hba_inst;
	int			inst;

	hba_inst = ddi_get_instance(ddi_get_parent(dip));
	inst = ddi_get_instance(dip);

	pwp = ddi_get_soft_state(pmcs_softc_state, hba_inst);
	if (pwp == NULL) {
		cmn_err(CE_WARN, "%s: No HBA softstate for instance %d",
		    __func__, inst);
		return (DDI_FAILURE);
	}

	if ((pwp->state == STATE_UNPROBING) || (pwp->state == STATE_DEAD)) {
		return (DDI_FAILURE);
	}

	if ((iport_ua = scsi_hba_iport_unit_address(dip)) == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: invoked with NULL unit address, inst (%d)",
		    __func__, inst);
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(pmcs_iport_softstate, inst) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "Failed to alloc soft state for iport %d", inst);
		return (DDI_FAILURE);
	}

	iport = ddi_get_soft_state(pmcs_iport_softstate, inst);
	if (iport == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "cannot get iport soft state");
		goto iport_attach_fail1;
	}

	mutex_init(&iport->lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(pwp->intr_pri));
	cv_init(&iport->refcnt_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&iport->smp_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&iport->refcnt_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(pwp->intr_pri));
	mutex_init(&iport->smp_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(pwp->intr_pri));

	/* Set some data on the iport handle */
	iport->dip = dip;
	iport->pwp = pwp;

	/* Dup the UA into the iport handle */
	iport->ua = strdup(iport_ua);

	tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
	tran->tran_hba_private = iport;

	list_create(&iport->phys, sizeof (pmcs_phy_t),
	    offsetof(pmcs_phy_t, list_node));

	/*
	 * If our unit address is active in the phymap, configure our
	 * iport's phylist.
	 */
	mutex_enter(&iport->lock);
	ua_priv = sas_phymap_lookup_uapriv(pwp->hss_phymap, iport->ua);
	if (ua_priv) {
		/* Non-NULL private data indicates the unit address is active */
		iport->ua_state = UA_ACTIVE;
		if (pmcs_iport_configure_phys(iport) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
			    "%s: failed to "
			    "configure phys on iport handle (0x%p), "
			    " unit address [%s]", __func__,
			    (void *)iport, iport_ua);
			mutex_exit(&iport->lock);
			goto iport_attach_fail2;
		}
	} else {
		iport->ua_state = UA_INACTIVE;
	}
	mutex_exit(&iport->lock);

	/* Allocate string-based soft state pool for targets */
	iport->tgt_sstate = NULL;
	if (ddi_soft_state_bystr_init(&iport->tgt_sstate,
	    sizeof (pmcs_xscsi_t), PMCS_TGT_SSTATE_SZ) != 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "cannot get iport tgt soft state");
		goto iport_attach_fail2;
	}

	/* Create this iport's target map */
	if (pmcs_iport_tgtmap_create(iport) == B_FALSE) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "Failed to create tgtmap on iport %d", inst);
		goto iport_attach_fail3;
	}

	/* Set up the 'initiator-port' DDI property on this iport */
	init_port = kmem_zalloc(PMCS_MAX_UA_SIZE, KM_SLEEP);
	if (pwp->separate_ports) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: separate ports not supported", __func__);
	} else {
		/* Set initiator-port value to the HBA's base WWN */
		(void) scsi_wwn_to_wwnstr(pwp->sas_wwns[0], 1,
		    init_port);
	}

	mutex_enter(&iport->lock);
	pmcs_smhba_add_iport_prop(iport, DATA_TYPE_STRING,
	    SCSI_ADDR_PROP_INITIATOR_PORT, init_port);
	kmem_free(init_port, PMCS_MAX_UA_SIZE);

	/* Set up a 'num-phys' DDI property for the iport node */
	pmcs_smhba_add_iport_prop(iport, DATA_TYPE_INT32, PMCS_NUM_PHYS,
	    &iport->nphy);
	mutex_exit(&iport->lock);

	/* Create kstats for each of the phys in this port */
	pmcs_create_all_phy_stats(iport);

	/*
	 * Insert this iport handle into our list and set
	 * iports_attached on the HBA node.
	 */
	rw_enter(&pwp->iports_lock, RW_WRITER);
	ASSERT(!list_link_active(&iport->list_node));
	list_insert_tail(&pwp->iports, iport);
	pwp->iports_attached = 1;
	pwp->num_iports++;
	rw_exit(&pwp->iports_lock);

	pmcs_prt(pwp, PMCS_PRT_DEBUG_IPORT, NULL, NULL,
	    "iport%d attached", inst);
	ddi_report_dev(dip);
	return (DDI_SUCCESS);

	/* teardown and fail */
iport_attach_fail3:
	ddi_soft_state_bystr_fini(&iport->tgt_sstate);
iport_attach_fail2:
	list_destroy(&iport->phys);
	strfree(iport->ua);
	mutex_destroy(&iport->refcnt_lock);
	mutex_destroy(&iport->smp_lock);
	cv_destroy(&iport->refcnt_cv);
	cv_destroy(&iport->smp_cv);
	mutex_destroy(&iport->lock);
iport_attach_fail1:
	ddi_soft_state_free(pmcs_iport_softstate, inst);
	return (DDI_FAILURE);
}

static int
pmcs_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	scsi_hba_tran_t *tran;
	char chiprev, *fwsupport, hw_rev[24], fw_rev[24];
	off_t set3size;
	int inst, i;
	int sm_hba = 1;
	int protocol = 0;
	int num_phys = 0;
	pmcs_hw_t *pwp;
	pmcs_phy_t *phyp;
	uint32_t num_threads;
	char buf[64];
	char *fwl_file;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_PM_RESUME:
	case DDI_RESUME:
		tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
		if (!tran) {
			return (DDI_FAILURE);
		}
		/* No DDI_?_RESUME on iport nodes */
		if (scsi_hba_iport_unit_address(dip) != NULL) {
			return (DDI_SUCCESS);
		}
		pwp = TRAN2PMC(tran);
		if (pwp == NULL) {
			return (DDI_FAILURE);
		}

		mutex_enter(&pwp->lock);
		pwp->suspended = 0;
		if (pwp->tq) {
			ddi_taskq_resume(pwp->tq);
		}
		mutex_exit(&pwp->lock);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/*
	 * If this is an iport node, invoke iport attach.
	 */
	if (scsi_hba_iport_unit_address(dip) != NULL) {
		return (pmcs_iport_attach(dip));
	}

	/*
	 * From here on is attach for the HBA node
	 */

#ifdef	DEBUG
	/*
	 * Check to see if this unit is to be disabled.  We can't disable
	 * on a per-iport node.  It's either the entire HBA or nothing.
	 */
	(void) snprintf(buf, sizeof (buf),
	    "disable-instance-%d", ddi_get_instance(dip));
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, buf, 0)) {
		cmn_err(CE_NOTE, "pmcs%d: disabled by configuration",
		    ddi_get_instance(dip));
		return (DDI_FAILURE);
	}
#endif

	/*
	 * Allocate softstate
	 */
	inst = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(pmcs_softc_state, inst) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "pmcs%d: Failed to alloc soft state", inst);
		return (DDI_FAILURE);
	}

	pwp = ddi_get_soft_state(pmcs_softc_state, inst);
	if (pwp == NULL) {
		cmn_err(CE_WARN, "pmcs%d: cannot get soft state", inst);
		ddi_soft_state_free(pmcs_softc_state, inst);
		return (DDI_FAILURE);
	}
	pwp->dip = dip;
	STAILQ_INIT(&pwp->dq);
	STAILQ_INIT(&pwp->cq);
	STAILQ_INIT(&pwp->wf);
	STAILQ_INIT(&pwp->pf);

	/*
	 * Create the list for iports and init its lock.
	 */
	list_create(&pwp->iports, sizeof (pmcs_iport_t),
	    offsetof(pmcs_iport_t, list_node));
	rw_init(&pwp->iports_lock, NULL, RW_DRIVER, NULL);

	pwp->state = STATE_PROBING;

	/*
	 * Get driver.conf properties
	 */
	pwp->debug_mask = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "pmcs-debug-mask",
	    debug_mask);
	pwp->phyid_block_mask = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "pmcs-phyid-block-mask",
	    block_mask);
	pwp->physpeed = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "pmcs-physpeed", physpeed);
	pwp->phymode = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "pmcs-phymode", phymode);
	pwp->fwlog = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "pmcs-fwlog", fwlog_level);
	if (pwp->fwlog > PMCS_FWLOG_MAX) {
		pwp->fwlog = PMCS_FWLOG_MAX;
	}
	if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, 0, "pmcs-fwlogfile",
	    &fwl_file) == DDI_SUCCESS)) {
		if (snprintf(pwp->fwlogfile_aap1, MAXPATHLEN, "%s%d-aap1.0",
		    fwl_file, ddi_get_instance(dip)) > MAXPATHLEN) {
			pwp->fwlogfile_aap1[0] = '\0';
			pwp->fwlogfile_iop[0] = '\0';
		} else if (snprintf(pwp->fwlogfile_iop, MAXPATHLEN,
		    "%s%d-iop.0", fwl_file,
		    ddi_get_instance(dip)) > MAXPATHLEN) {
			pwp->fwlogfile_aap1[0] = '\0';
			pwp->fwlogfile_iop[0] = '\0';
		}
		ddi_prop_free(fwl_file);
	} else {
		pwp->fwlogfile_aap1[0] = '\0';
		pwp->fwlogfile_iop[0] = '\0';
	}

	pwp->open_retry_interval = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "pmcs-open-retry-interval",
	    OPEN_RETRY_INTERVAL_DEF);
	if (pwp->open_retry_interval > OPEN_RETRY_INTERVAL_MAX) {
		pwp->open_retry_interval = OPEN_RETRY_INTERVAL_MAX;
	}

	mutex_enter(&pmcs_trace_lock);
	if (pmcs_tbuf == NULL) {
		/* Allocate trace buffer */
		pmcs_tbuf_num_elems = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "pmcs-tbuf-num-elems",
		    PMCS_TBUF_NUM_ELEMS_DEF);
		if ((pmcs_tbuf_num_elems == DDI_PROP_NOT_FOUND) ||
		    (pmcs_tbuf_num_elems == 0)) {
			pmcs_tbuf_num_elems = PMCS_TBUF_NUM_ELEMS_DEF;
		}

		pmcs_tbuf = kmem_zalloc(pmcs_tbuf_num_elems *
		    sizeof (pmcs_tbuf_t), KM_SLEEP);
		pmcs_tbuf_ptr = pmcs_tbuf;
		pmcs_tbuf_idx = 0;
	}
	mutex_exit(&pmcs_trace_lock);

	if (pwp->fwlog && strlen(pwp->fwlogfile_aap1) > 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: firmware event log files: %s, %s", __func__,
		    pwp->fwlogfile_aap1, pwp->fwlogfile_iop);
		pwp->fwlog_file = 1;
	} else {
		if (pwp->fwlog == 0) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: No firmware event log will be written "
			    "(event log disabled)", __func__);
		} else {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: No firmware event log will be written "
			    "(no filename configured - too long?)", __func__);
		}
		pwp->fwlog_file = 0;
	}

	disable_msix = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "pmcs-disable-msix",
	    disable_msix);
	disable_msi = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "pmcs-disable-msi",
	    disable_msi);
	maxqdepth = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "pmcs-maxqdepth", maxqdepth);
	pwp->fw_force_update = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "pmcs-fw-force-update", 0);
	if (pwp->fw_force_update == 0) {
		pwp->fw_disable_update = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    "pmcs-fw-disable-update", 0);
	}
	pwp->ioq_depth = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "pmcs-num-io-qentries",
	    PMCS_NQENTRY);

	/*
	 * Initialize FMA
	 */
	pwp->dev_acc_attr = pwp->reg_acc_attr = rattr;
	pwp->iqp_dma_attr = pwp->oqp_dma_attr =
	    pwp->regdump_dma_attr = pwp->cip_dma_attr =
	    pwp->fwlog_dma_attr = pmcs_dattr;
	pwp->fm_capabilities = ddi_getprop(DDI_DEV_T_ANY, pwp->dip,
	    DDI_PROP_NOTPROM | DDI_PROP_DONTPASS, "fm-capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);
	pmcs_fm_init(pwp);

	/*
	 * Map registers
	 */
	if (pci_config_setup(dip, &pwp->pci_acc_handle)) {
		pmcs_prt(pwp, PMCS_PRT_WARN, NULL, NULL,
		    "pci config setup failed");
		ddi_soft_state_free(pmcs_softc_state, inst);
		return (DDI_FAILURE);
	}

	/*
	 * Get the size of register set 3.
	 */
	if (ddi_dev_regsize(dip, PMCS_REGSET_3, &set3size) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "unable to get size of register set %d", PMCS_REGSET_3);
		pci_config_teardown(&pwp->pci_acc_handle);
		ddi_soft_state_free(pmcs_softc_state, inst);
		return (DDI_FAILURE);
	}

	/*
	 * Map registers
	 */
	pwp->reg_acc_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;

	if (ddi_regs_map_setup(dip, PMCS_REGSET_0, (caddr_t *)&pwp->msg_regs,
	    0, 0, &pwp->reg_acc_attr, &pwp->msg_acc_handle)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "failed to map Message Unit registers");
		pci_config_teardown(&pwp->pci_acc_handle);
		ddi_soft_state_free(pmcs_softc_state, inst);
		return (DDI_FAILURE);
	}

	if (ddi_regs_map_setup(dip, PMCS_REGSET_1, (caddr_t *)&pwp->top_regs,
	    0, 0, &pwp->reg_acc_attr, &pwp->top_acc_handle)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "failed to map TOP registers");
		ddi_regs_map_free(&pwp->msg_acc_handle);
		pci_config_teardown(&pwp->pci_acc_handle);
		ddi_soft_state_free(pmcs_softc_state, inst);
		return (DDI_FAILURE);
	}

	if (ddi_regs_map_setup(dip, PMCS_REGSET_2, (caddr_t *)&pwp->gsm_regs,
	    0, 0, &pwp->reg_acc_attr, &pwp->gsm_acc_handle)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "failed to map GSM registers");
		ddi_regs_map_free(&pwp->top_acc_handle);
		ddi_regs_map_free(&pwp->msg_acc_handle);
		pci_config_teardown(&pwp->pci_acc_handle);
		ddi_soft_state_free(pmcs_softc_state, inst);
		return (DDI_FAILURE);
	}

	if (ddi_regs_map_setup(dip, PMCS_REGSET_3, (caddr_t *)&pwp->mpi_regs,
	    0, 0, &pwp->reg_acc_attr, &pwp->mpi_acc_handle)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "failed to map MPI registers");
		ddi_regs_map_free(&pwp->top_acc_handle);
		ddi_regs_map_free(&pwp->gsm_acc_handle);
		ddi_regs_map_free(&pwp->msg_acc_handle);
		pci_config_teardown(&pwp->pci_acc_handle);
		ddi_soft_state_free(pmcs_softc_state, inst);
		return (DDI_FAILURE);
	}
	pwp->mpibar =
	    (((5U << 2) + 0x10) << PMCS_MSGU_MPI_BAR_SHIFT) | set3size;

	/*
	 * Make sure we can support this card.
	 */
	pwp->chiprev = pmcs_rd_topunit(pwp, PMCS_DEVICE_REVISION);

	switch (pwp->chiprev) {
	case PMCS_PM8001_REV_A:
	case PMCS_PM8001_REV_B:
		pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL,
		    "Rev A/B Card no longer supported");
		goto failure;
	case PMCS_PM8001_REV_C:
		break;
	default:
		pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL,
		    "Unknown chip revision (%d)", pwp->chiprev);
		goto failure;
	}

	/*
	 * Allocate DMA addressable area for Inbound and Outbound Queue indices
	 * that the chip needs to access plus a space for scratch usage
	 */
	pwp->cip_dma_attr.dma_attr_align = sizeof (uint32_t);
	if (pmcs_dma_setup(pwp, &pwp->cip_dma_attr, &pwp->cip_acchdls,
	    &pwp->cip_handles, ptob(1), (caddr_t *)&pwp->cip,
	    &pwp->ciaddr) == B_FALSE) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "Failed to setup DMA for index/scratch");
		goto failure;
	}

	bzero(pwp->cip, ptob(1));
	pwp->scratch = &pwp->cip[PMCS_INDICES_SIZE];
	pwp->scratch_dma = pwp->ciaddr + PMCS_INDICES_SIZE;

	/*
	 * Allocate DMA S/G list chunks
	 */
	(void) pmcs_add_more_chunks(pwp, ptob(1) * PMCS_MIN_CHUNK_PAGES);

	/*
	 * Allocate a DMA addressable area for the firmware log (if needed)
	 */
	if (pwp->fwlog) {
		/*
		 * Align to event log header and entry size
		 */
		pwp->fwlog_dma_attr.dma_attr_align = 32;
		if (pmcs_dma_setup(pwp, &pwp->fwlog_dma_attr,
		    &pwp->fwlog_acchdl,
		    &pwp->fwlog_hndl, PMCS_FWLOG_SIZE,
		    (caddr_t *)&pwp->fwlogp,
		    &pwp->fwaddr) == B_FALSE) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "Failed to setup DMA for fwlog area");
			pwp->fwlog = 0;
		} else {
			bzero(pwp->fwlogp, PMCS_FWLOG_SIZE);
			pwp->fwlogp_aap1 = (pmcs_fw_event_hdr_t *)pwp->fwlogp;
			pwp->fwlogp_iop = (pmcs_fw_event_hdr_t *)((void *)
			    ((caddr_t)pwp->fwlogp + (PMCS_FWLOG_SIZE / 2)));
		}
	}

	if (pwp->flash_chunk_addr == 0) {
		pwp->regdump_dma_attr.dma_attr_align = PMCS_FLASH_CHUNK_SIZE;
		if (pmcs_dma_setup(pwp, &pwp->regdump_dma_attr,
		    &pwp->regdump_acchdl,
		    &pwp->regdump_hndl, PMCS_FLASH_CHUNK_SIZE,
		    (caddr_t *)&pwp->flash_chunkp, &pwp->flash_chunk_addr) ==
		    B_FALSE) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "Failed to setup DMA for register dump area");
			goto failure;
		}
		bzero(pwp->flash_chunkp, PMCS_FLASH_CHUNK_SIZE);
	}

	/*
	 * More bits of local initialization...
	 */
	pwp->tq = ddi_taskq_create(dip, "_tq", 4, TASKQ_DEFAULTPRI, 0);
	if (pwp->tq == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "unable to create worker taskq");
		goto failure;
	}

	/*
	 * Cache of structures for dealing with I/O completion callbacks.
	 */
	(void) snprintf(buf, sizeof (buf), "pmcs_iocomp_cb_cache%d", inst);
	pwp->iocomp_cb_cache = kmem_cache_create(buf,
	    sizeof (pmcs_iocomp_cb_t), 16, NULL, NULL, NULL, NULL, NULL, 0);

	/*
	 * Cache of PHY structures
	 */
	(void) snprintf(buf, sizeof (buf), "pmcs_phy_cache%d", inst);
	pwp->phy_cache = kmem_cache_create(buf, sizeof (pmcs_phy_t), 8,
	    pmcs_phy_constructor, pmcs_phy_destructor, NULL, (void *)pwp,
	    NULL, 0);

	/*
	 * Allocate space for the I/O completion threads
	 */
	num_threads = ncpus_online;
	if (num_threads > PMCS_MAX_CQ_THREADS) {
		num_threads = PMCS_MAX_CQ_THREADS;
	}

	pwp->cq_info.cq_threads = num_threads;
	pwp->cq_info.cq_thr_info = kmem_zalloc(
	    sizeof (pmcs_cq_thr_info_t) * pwp->cq_info.cq_threads, KM_SLEEP);
	pwp->cq_info.cq_next_disp_thr = 0;
	pwp->cq_info.cq_stop = B_FALSE;

	/*
	 * Set the quantum value in clock ticks for the I/O interrupt
	 * coalescing timer.
	 */
	pwp->io_intr_coal.quantum = drv_usectohz(PMCS_QUANTUM_TIME_USECS);

	/*
	 * We have a delicate dance here. We need to set up
	 * interrupts so we know how to set up some OQC
	 * tables. However, while we're setting up table
	 * access, we may need to flash new firmware and
	 * reset the card, which will take some finessing.
	 */

	/*
	 * Set up interrupts here.
	 */
	switch (pmcs_setup_intr(pwp)) {
	case 0:
		break;
	case EIO:
		pwp->stuck = 1;
		/* FALLTHROUGH */
	default:
		goto failure;
	}

	/*
	 * Set these up now becuase they are used to initialize the OQC tables.
	 *
	 * If we have MSI or MSI-X interrupts set up and we have enough
	 * vectors for each OQ, the Outbound Queue vectors can all be the
	 * same as the appropriate interrupt routine will have been called
	 * and the doorbell register automatically cleared.
	 * This keeps us from having to check the Outbound Doorbell register
	 * when the routines for these interrupts are called.
	 *
	 * If we have Legacy INT-X interrupts set up or we didn't have enough
	 * MSI/MSI-X vectors to uniquely identify each OQ, we point these
	 * vectors to the bits we would like to have set in the Outbound
	 * Doorbell register because pmcs_all_intr will read the doorbell
	 * register to find out why we have an interrupt and write the
	 * corresponding 'clear' bit for that interrupt.
	 */

	switch (pwp->intr_cnt) {
	case 1:
		/*
		 * Only one vector, so we must check all OQs for MSI.  For
		 * INT-X, there's only one vector anyway, so we can just
		 * use the outbound queue bits to keep from having to
		 * check each queue for each interrupt.
		 */
		if (pwp->int_type == PMCS_INT_FIXED) {
			pwp->oqvec[PMCS_OQ_IODONE] = PMCS_OQ_IODONE;
			pwp->oqvec[PMCS_OQ_GENERAL] = PMCS_OQ_GENERAL;
			pwp->oqvec[PMCS_OQ_EVENTS] = PMCS_OQ_EVENTS;
		} else {
			pwp->oqvec[PMCS_OQ_IODONE] = PMCS_OQ_IODONE;
			pwp->oqvec[PMCS_OQ_GENERAL] = PMCS_OQ_IODONE;
			pwp->oqvec[PMCS_OQ_EVENTS] = PMCS_OQ_IODONE;
		}
		break;
	case 2:
		/* With 2, we can at least isolate IODONE */
		pwp->oqvec[PMCS_OQ_IODONE] = PMCS_OQ_IODONE;
		pwp->oqvec[PMCS_OQ_GENERAL] = PMCS_OQ_GENERAL;
		pwp->oqvec[PMCS_OQ_EVENTS] = PMCS_OQ_GENERAL;
		break;
	case 4:
		/* With 4 vectors, everybody gets one */
		pwp->oqvec[PMCS_OQ_IODONE] = PMCS_OQ_IODONE;
		pwp->oqvec[PMCS_OQ_GENERAL] = PMCS_OQ_GENERAL;
		pwp->oqvec[PMCS_OQ_EVENTS] = PMCS_OQ_EVENTS;
		break;
	}

	/*
	 * Do the first part of setup
	 */
	if (pmcs_setup(pwp)) {
		goto failure;
	}
	pmcs_report_fwversion(pwp);

	/*
	 * Now do some additonal allocations based upon information
	 * gathered during MPI setup.
	 */
	pwp->root_phys = kmem_zalloc(pwp->nphy * sizeof (pmcs_phy_t), KM_SLEEP);
	ASSERT(pwp->nphy < SAS2_PHYNUM_MAX);
	phyp = pwp->root_phys;
	for (i = 0; i < pwp->nphy; i++) {
		if (i < pwp->nphy-1) {
			phyp->sibling = (phyp + 1);
		}
		mutex_init(&phyp->phy_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(pwp->intr_pri));
		phyp->phynum = i & SAS2_PHYNUM_MASK;
		pmcs_phy_name(pwp, phyp, phyp->path, sizeof (phyp->path));
		phyp->pwp = pwp;
		phyp->device_id = PMCS_INVALID_DEVICE_ID;
		phyp->portid = PMCS_PHY_INVALID_PORT_ID;
		phyp++;
	}

	pwp->work = kmem_zalloc(pwp->max_cmd * sizeof (pmcwork_t), KM_SLEEP);
	for (i = 0; i < pwp->max_cmd; i++) {
		pmcwork_t *pwrk = &pwp->work[i];
		mutex_init(&pwrk->lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(pwp->intr_pri));
		cv_init(&pwrk->sleep_cv, NULL, CV_DRIVER, NULL);
		STAILQ_INSERT_TAIL(&pwp->wf, pwrk, next);

	}
	pwp->targets = (pmcs_xscsi_t **)
	    kmem_zalloc(pwp->max_dev * sizeof (pmcs_xscsi_t *), KM_SLEEP);

	pwp->iqpt = (pmcs_iqp_trace_t *)
	    kmem_zalloc(sizeof (pmcs_iqp_trace_t), KM_SLEEP);
	pwp->iqpt->head = kmem_zalloc(PMCS_IQP_TRACE_BUFFER_SIZE, KM_SLEEP);
	pwp->iqpt->curpos = pwp->iqpt->head;
	pwp->iqpt->size_left = PMCS_IQP_TRACE_BUFFER_SIZE;

	/*
	 * Start MPI communication.
	 */
	if (pmcs_start_mpi(pwp)) {
		if (pmcs_soft_reset(pwp, B_FALSE)) {
			goto failure;
		}
		pwp->last_reset_reason = PMCS_LAST_RST_ATTACH;
	}

	/*
	 * Do some initial acceptance tests.
	 * This tests interrupts and queues.
	 */
	if (pmcs_echo_test(pwp)) {
		goto failure;
	}

	/* Read VPD - if it exists */
	if (pmcs_get_nvmd(pwp, PMCS_NVMD_VPD, PMCIN_NVMD_VPD, 0, NULL, 0)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: Unable to read VPD: "
		    "attempting to fabricate", __func__);
		/*
		 * When we release, this must goto failure and the call
		 * to pmcs_fabricate_wwid is removed.
		 */
		/* goto failure; */
		if (!pmcs_fabricate_wwid(pwp)) {
			goto failure;
		}
	}

	/*
	 * We're now officially running
	 */
	pwp->state = STATE_RUNNING;

	/*
	 * Check firmware versions and load new firmware
	 * if needed and reset.
	 */
	if (pmcs_firmware_update(pwp)) {
		pmcs_prt(pwp, PMCS_PRT_WARN, NULL, NULL,
		    "%s: Firmware update failed", __func__);
		goto failure;
	}

	/*
	 * Create completion threads.
	 */
	for (i = 0; i < pwp->cq_info.cq_threads; i++) {
		pwp->cq_info.cq_thr_info[i].cq_pwp = pwp;
		pwp->cq_info.cq_thr_info[i].cq_thread =
		    thread_create(NULL, 0, pmcs_scsa_cq_run,
		    &pwp->cq_info.cq_thr_info[i], 0, &p0, TS_RUN, minclsyspri);
	}

	/*
	 * Create one thread to deal with the updating of the interrupt
	 * coalescing timer.
	 */
	pwp->ict_thread = thread_create(NULL, 0, pmcs_check_intr_coal,
	    pwp, 0, &p0, TS_RUN, minclsyspri);

	/*
	 * Kick off the watchdog
	 */
	pwp->wdhandle = timeout(pmcs_watchdog, pwp,
	    drv_usectohz(PMCS_WATCH_INTERVAL));
	/*
	 * Do the SCSI attachment code (before starting phys)
	 */
	if (pmcs_scsa_init(pwp, &pmcs_dattr)) {
		goto failure;
	}
	pwp->hba_attached = 1;

	/* Check all acc & dma handles allocated in attach */
	if (pmcs_check_acc_dma_handle(pwp)) {
		ddi_fm_service_impact(pwp->dip, DDI_SERVICE_LOST);
		goto failure;
	}

	/*
	 * Create the iportmap for this HBA instance
	 */
	if (scsi_hba_iportmap_create(dip, iportmap_csync_usec,
	    iportmap_stable_usec, &pwp->hss_iportmap) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: pmcs%d iportmap_create failed", __func__, inst);
		goto failure;
	}
	ASSERT(pwp->hss_iportmap);

	/*
	 * Create the phymap for this HBA instance
	 */
	if (sas_phymap_create(dip, phymap_stable_usec, PHYMAP_MODE_SIMPLE, NULL,
	    pwp, pmcs_phymap_activate, pmcs_phymap_deactivate,
	    &pwp->hss_phymap) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: pmcs%d phymap_create failed", __func__, inst);
		goto failure;
	}
	ASSERT(pwp->hss_phymap);

	/*
	 * Start the PHYs.
	 */
	if (pmcs_start_phys(pwp)) {
		goto failure;
	}

	/*
	 * From this point on, we can't fail.
	 */
	ddi_report_dev(dip);

	/* SM-HBA */
	pmcs_smhba_add_hba_prop(pwp, DATA_TYPE_INT32, PMCS_SMHBA_SUPPORTED,
	    &sm_hba);

	/* SM-HBA */
	pmcs_smhba_add_hba_prop(pwp, DATA_TYPE_STRING, PMCS_DRV_VERSION,
	    pmcs_driver_rev);

	/* SM-HBA */
	chiprev = 'A' + pwp->chiprev;
	(void) snprintf(hw_rev, 2, "%s", &chiprev);
	pmcs_smhba_add_hba_prop(pwp, DATA_TYPE_STRING, PMCS_HWARE_VERSION,
	    hw_rev);

	/* SM-HBA */
	switch (PMCS_FW_TYPE(pwp)) {
	case PMCS_FW_TYPE_RELEASED:
		fwsupport = "Released";
		break;
	case PMCS_FW_TYPE_DEVELOPMENT:
		fwsupport = "Development";
		break;
	case PMCS_FW_TYPE_ALPHA:
		fwsupport = "Alpha";
		break;
	case PMCS_FW_TYPE_BETA:
		fwsupport = "Beta";
		break;
	default:
		fwsupport = "Special";
		break;
	}
	(void) snprintf(fw_rev, sizeof (fw_rev), "%x.%x.%x %s",
	    PMCS_FW_MAJOR(pwp), PMCS_FW_MINOR(pwp), PMCS_FW_MICRO(pwp),
	    fwsupport);
	pmcs_smhba_add_hba_prop(pwp, DATA_TYPE_STRING, PMCS_FWARE_VERSION,
	    fw_rev);

	/* SM-HBA */
	num_phys = pwp->nphy;
	pmcs_smhba_add_hba_prop(pwp, DATA_TYPE_INT32, PMCS_NUM_PHYS_HBA,
	    &num_phys);

	/* SM-HBA */
	protocol = SAS_SSP_SUPPORT | SAS_SATA_SUPPORT | SAS_SMP_SUPPORT;
	pmcs_smhba_add_hba_prop(pwp, DATA_TYPE_INT32, PMCS_SUPPORTED_PROTOCOL,
	    &protocol);

	/* Receptacle properties (FMA) */
	pwp->recept_labels[0] = PMCS_RECEPT_LABEL_0;
	pwp->recept_pm[0] = PMCS_RECEPT_PM_0;
	pwp->recept_labels[1] = PMCS_RECEPT_LABEL_1;
	pwp->recept_pm[1] = PMCS_RECEPT_PM_1;
	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    SCSI_HBA_PROP_RECEPTACLE_LABEL, &pwp->recept_labels[0],
	    PMCS_NUM_RECEPTACLES) != DDI_PROP_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: failed to create %s property", __func__,
		    "receptacle-label");
	}
	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    SCSI_HBA_PROP_RECEPTACLE_PM, &pwp->recept_pm[0],
	    PMCS_NUM_RECEPTACLES) != DDI_PROP_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: failed to create %s property", __func__,
		    "receptacle-pm");
	}

	return (DDI_SUCCESS);

failure:
	if (pmcs_unattach(pwp)) {
		pwp->stuck = 1;
	}
	return (DDI_FAILURE);
}

int
pmcs_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int inst = ddi_get_instance(dip);
	pmcs_iport_t	*iport = NULL;
	pmcs_hw_t	*pwp = NULL;
	scsi_hba_tran_t	*tran;

	if (scsi_hba_iport_unit_address(dip) != NULL) {
		/* iport node */
		iport = ddi_get_soft_state(pmcs_iport_softstate, inst);
		ASSERT(iport);
		if (iport == NULL) {
			return (DDI_FAILURE);
		}
		pwp = iport->pwp;
	} else {
		/* hba node */
		pwp = (pmcs_hw_t *)ddi_get_soft_state(pmcs_softc_state, inst);
		ASSERT(pwp);
		if (pwp == NULL) {
			return (DDI_FAILURE);
		}
	}
	switch (cmd) {
	case DDI_DETACH:
		if (iport) {
			/* iport detach */
			if (pmcs_iport_unattach(iport)) {
				return (DDI_FAILURE);
			}
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "iport%d detached", inst);
			return (DDI_SUCCESS);
		} else {
			/* HBA detach */
			if (pmcs_unattach(pwp)) {
				return (DDI_FAILURE);
			}
			return (DDI_SUCCESS);
		}

	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
		/* No DDI_SUSPEND on iport nodes */
		if (iport) {
			return (DDI_SUCCESS);
		}

		if (pwp->stuck) {
			return (DDI_FAILURE);
		}
		tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
		if (!tran) {
			return (DDI_FAILURE);
		}

		pwp = TRAN2PMC(tran);
		if (pwp == NULL) {
			return (DDI_FAILURE);
		}
		mutex_enter(&pwp->lock);
		if (pwp->tq) {
			ddi_taskq_suspend(pwp->tq);
		}
		pwp->suspended = 1;
		mutex_exit(&pwp->lock);
		pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "PMC8X6G suspending");
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
pmcs_iport_unattach(pmcs_iport_t *iport)
{
	pmcs_hw_t	*pwp = iport->pwp;

	/*
	 * First, check if there are still any configured targets on this
	 * iport.  If so, we fail detach.
	 */
	if (pmcs_iport_has_targets(pwp, iport)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_IPORT, NULL, NULL,
		    "iport%d detach failure: iport has targets (luns)",
		    ddi_get_instance(iport->dip));
		return (DDI_FAILURE);
	}

	/*
	 * Remove this iport from our list if it is inactive in the phymap.
	 */
	rw_enter(&pwp->iports_lock, RW_WRITER);
	mutex_enter(&iport->lock);

	if ((iport->ua_state == UA_ACTIVE) &&
	    (detach_with_active_port == 0)) {
		mutex_exit(&iport->lock);
		rw_exit(&pwp->iports_lock);
		pmcs_prt(pwp, PMCS_PRT_DEBUG_IPORT, NULL, NULL,
		    "iport%d detach failure: "
		    "iport unit address active in phymap",
		    ddi_get_instance(iport->dip));
		return (DDI_FAILURE);
	}

	/* If it's our only iport, clear iports_attached */
	ASSERT(pwp->num_iports >= 1);
	if (--pwp->num_iports == 0) {
		pwp->iports_attached = 0;
	}

	ASSERT(list_link_active(&iport->list_node));
	list_remove(&pwp->iports, iport);
	rw_exit(&pwp->iports_lock);

	/*
	 * We have removed the iport handle from the HBA's iports list,
	 * there will be no new references to it. Two things must be
	 * guarded against here.  First, we could have PHY up events,
	 * adding themselves to the iport->phys list and grabbing ref's
	 * on our iport handle.  Second, we could have existing references
	 * to this iport handle from a point in time prior to the list
	 * removal above.
	 *
	 * So first, destroy the phys list. Remove any phys that have snuck
	 * in after the phymap deactivate, dropping the refcnt accordingly.
	 * If these PHYs are still up if and when the phymap reactivates
	 * (i.e. when this iport reattaches), we'll populate the list with
	 * them and bump the refcnt back up.
	 */
	pmcs_remove_phy_from_iport(iport, NULL);
	ASSERT(list_is_empty(&iport->phys));
	list_destroy(&iport->phys);
	mutex_exit(&iport->lock);

	/*
	 * Second, wait for any other references to this iport to be
	 * dropped, then continue teardown.
	 */
	mutex_enter(&iport->refcnt_lock);
	while (iport->refcnt != 0) {
		cv_wait(&iport->refcnt_cv, &iport->refcnt_lock);
	}
	mutex_exit(&iport->refcnt_lock);


	/* Destroy the iport target map */
	if (pmcs_iport_tgtmap_destroy(iport) == B_FALSE) {
		return (DDI_FAILURE);
	}

	/* Free the tgt soft state */
	if (iport->tgt_sstate != NULL) {
		ddi_soft_state_bystr_fini(&iport->tgt_sstate);
	}

	/* Free our unit address string */
	strfree(iport->ua);

	/* Finish teardown and free the softstate */
	mutex_destroy(&iport->refcnt_lock);
	mutex_destroy(&iport->smp_lock);
	ASSERT(iport->refcnt == 0);
	cv_destroy(&iport->refcnt_cv);
	cv_destroy(&iport->smp_cv);
	mutex_destroy(&iport->lock);
	ddi_soft_state_free(pmcs_iport_softstate, ddi_get_instance(iport->dip));

	return (DDI_SUCCESS);
}

static int
pmcs_unattach(pmcs_hw_t *pwp)
{
	int i;
	enum pwpstate curstate;
	pmcs_cq_thr_info_t *cqti;

	/*
	 * Tear down the interrupt infrastructure.
	 */
	if (pmcs_teardown_intr(pwp)) {
		pwp->stuck = 1;
	}
	pwp->intr_cnt = 0;

	/*
	 * Grab a lock, if initted, to set state.
	 */
	if (pwp->locks_initted) {
		mutex_enter(&pwp->lock);
		if (pwp->state != STATE_DEAD) {
			pwp->state = STATE_UNPROBING;
		}
		curstate = pwp->state;
		mutex_exit(&pwp->lock);

		/*
		 * Stop the I/O completion threads.
		 */
		mutex_enter(&pwp->cq_lock);
		pwp->cq_info.cq_stop = B_TRUE;
		for (i = 0; i < pwp->cq_info.cq_threads; i++) {
			if (pwp->cq_info.cq_thr_info[i].cq_thread) {
				cqti = &pwp->cq_info.cq_thr_info[i];
				mutex_enter(&cqti->cq_thr_lock);
				cv_signal(&cqti->cq_cv);
				mutex_exit(&cqti->cq_thr_lock);
				mutex_exit(&pwp->cq_lock);
				thread_join(cqti->cq_thread->t_did);
				mutex_enter(&pwp->cq_lock);
			}
		}
		mutex_exit(&pwp->cq_lock);
		kmem_free(pwp->cq_info.cq_thr_info,
		    sizeof (pmcs_cq_thr_info_t) * pwp->cq_info.cq_threads);

		/*
		 * Stop the interrupt coalescing timer thread
		 */
		if (pwp->ict_thread) {
			mutex_enter(&pwp->ict_lock);
			pwp->io_intr_coal.stop_thread = B_TRUE;
			cv_signal(&pwp->ict_cv);
			mutex_exit(&pwp->ict_lock);
			thread_join(pwp->ict_thread->t_did);
		}
	} else {
		if (pwp->state != STATE_DEAD) {
			pwp->state = STATE_UNPROBING;
		}
		curstate = pwp->state;
	}

	/*
	 * Make sure that any pending watchdog won't
	 * be called from this point on out.
	 */
	(void) untimeout(pwp->wdhandle);
	/*
	 * After the above action, the watchdog
	 * timer that starts up the worker task
	 * may trigger but will exit immediately
	 * on triggering.
	 *
	 * Now that this is done, we can destroy
	 * the task queue, which will wait if we're
	 * running something on it.
	 */
	if (pwp->tq) {
		ddi_taskq_destroy(pwp->tq);
		pwp->tq = NULL;
	}

	pmcs_fm_fini(pwp);

	if (pwp->hba_attached) {
		(void) scsi_hba_detach(pwp->dip);
		pwp->hba_attached = 0;
	}

	/*
	 * If the chip hasn't been marked dead, shut it down now
	 * to bring it back to a known state without attempting
	 * a soft reset.
	 */
	if (curstate != STATE_DEAD && pwp->locks_initted) {
		/*
		 * De-register all registered devices
		 */
		pmcs_deregister_devices(pwp, pwp->root_phys);

		/*
		 * Stop all the phys.
		 */
		pmcs_stop_phys(pwp);

		/*
		 * Shut Down Message Passing
		 */
		(void) pmcs_stop_mpi(pwp);

		/*
		 * Reset chip
		 */
		(void) pmcs_soft_reset(pwp, B_FALSE);
		pwp->last_reset_reason = PMCS_LAST_RST_DETACH;
	}

	/*
	 * Turn off interrupts on the chip
	 */
	if (pwp->mpi_acc_handle) {
		pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_MASK, 0xffffffff);
	}

	if (pwp->hss_phymap != NULL) {
		/* Destroy the phymap */
		sas_phymap_destroy(pwp->hss_phymap);
	}

	if (pwp->hss_iportmap != NULL) {
		/* Destroy the iportmap */
		scsi_hba_iportmap_destroy(pwp->hss_iportmap);
	}

	/* Destroy the iports lock and list */
	rw_destroy(&pwp->iports_lock);
	ASSERT(list_is_empty(&pwp->iports));
	list_destroy(&pwp->iports);

	/*
	 * Free DMA handles and associated consistent memory
	 */
	if (pwp->regdump_hndl) {
		if (ddi_dma_unbind_handle(pwp->regdump_hndl) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "Condition check failed "
			    "at %s():%d", __func__, __LINE__);
		}
		ddi_dma_free_handle(&pwp->regdump_hndl);
		ddi_dma_mem_free(&pwp->regdump_acchdl);
		pwp->regdump_hndl = 0;
	}
	if (pwp->fwlog_hndl) {
		if (ddi_dma_unbind_handle(pwp->fwlog_hndl) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "Condition check failed "
			    "at %s():%d", __func__, __LINE__);
		}
		ddi_dma_free_handle(&pwp->fwlog_hndl);
		ddi_dma_mem_free(&pwp->fwlog_acchdl);
		pwp->fwlog_hndl = 0;
	}
	if (pwp->cip_handles) {
		if (ddi_dma_unbind_handle(pwp->cip_handles) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "Condition check failed "
			    "at %s():%d", __func__, __LINE__);
		}
		ddi_dma_free_handle(&pwp->cip_handles);
		ddi_dma_mem_free(&pwp->cip_acchdls);
		pwp->cip_handles = 0;
	}
	for (i = 0; i < PMCS_NOQ; i++) {
		if (pwp->oqp_handles[i]) {
			if (ddi_dma_unbind_handle(pwp->oqp_handles[i]) !=
			    DDI_SUCCESS) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
				    "Condition check failed at %s():%d",
				    __func__, __LINE__);
			}
			ddi_dma_free_handle(&pwp->oqp_handles[i]);
			ddi_dma_mem_free(&pwp->oqp_acchdls[i]);
			pwp->oqp_handles[i] = 0;
		}
	}
	for (i = 0; i < PMCS_NIQ; i++) {
		if (pwp->iqp_handles[i]) {
			if (ddi_dma_unbind_handle(pwp->iqp_handles[i]) !=
			    DDI_SUCCESS) {
				pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
				    "Condition check failed at %s():%d",
				    __func__, __LINE__);
			}
			ddi_dma_free_handle(&pwp->iqp_handles[i]);
			ddi_dma_mem_free(&pwp->iqp_acchdls[i]);
			pwp->iqp_handles[i] = 0;
		}
	}

	pmcs_free_dma_chunklist(pwp);

	/*
	 * Unmap registers and destroy access handles
	 */
	if (pwp->mpi_acc_handle) {
		ddi_regs_map_free(&pwp->mpi_acc_handle);
		pwp->mpi_acc_handle = 0;
	}
	if (pwp->top_acc_handle) {
		ddi_regs_map_free(&pwp->top_acc_handle);
		pwp->top_acc_handle = 0;
	}
	if (pwp->gsm_acc_handle) {
		ddi_regs_map_free(&pwp->gsm_acc_handle);
		pwp->gsm_acc_handle = 0;
	}
	if (pwp->msg_acc_handle) {
		ddi_regs_map_free(&pwp->msg_acc_handle);
		pwp->msg_acc_handle = 0;
	}
	if (pwp->pci_acc_handle) {
		pci_config_teardown(&pwp->pci_acc_handle);
		pwp->pci_acc_handle = 0;
	}

	/*
	 * Do memory allocation cleanup.
	 */
	while (pwp->dma_freelist) {
		pmcs_dmachunk_t *this = pwp->dma_freelist;
		pwp->dma_freelist = this->nxt;
		kmem_free(this, sizeof (pmcs_dmachunk_t));
	}

	/*
	 * Free pools
	 */
	if (pwp->iocomp_cb_cache) {
		kmem_cache_destroy(pwp->iocomp_cb_cache);
	}

	/*
	 * Free all PHYs (at level > 0), then free the cache
	 */
	pmcs_free_all_phys(pwp, pwp->root_phys);
	if (pwp->phy_cache) {
		kmem_cache_destroy(pwp->phy_cache);
	}

	/*
	 * Free root PHYs
	 */
	if (pwp->root_phys) {
		pmcs_phy_t *phyp = pwp->root_phys;
		for (i = 0; i < pwp->nphy; i++) {
			mutex_destroy(&phyp->phy_lock);
			phyp = phyp->sibling;
		}
		kmem_free(pwp->root_phys, pwp->nphy * sizeof (pmcs_phy_t));
		pwp->root_phys = NULL;
		pwp->nphy = 0;
	}

	/* Free the targets list */
	if (pwp->targets) {
		kmem_free(pwp->targets,
		    sizeof (pmcs_xscsi_t *) * pwp->max_dev);
	}

	/*
	 * Free work structures
	 */

	if (pwp->work && pwp->max_cmd) {
		for (i = 0; i < pwp->max_cmd; i++) {
			pmcwork_t *pwrk = &pwp->work[i];
			mutex_destroy(&pwrk->lock);
			cv_destroy(&pwrk->sleep_cv);
		}
		kmem_free(pwp->work, sizeof (pmcwork_t) * pwp->max_cmd);
		pwp->work = NULL;
		pwp->max_cmd = 0;
	}

	/*
	 * Do last property and SCSA cleanup
	 */
	if (pwp->smp_tran) {
		smp_hba_tran_free(pwp->smp_tran);
		pwp->smp_tran = NULL;
	}
	if (pwp->tran) {
		scsi_hba_tran_free(pwp->tran);
		pwp->tran = NULL;
	}
	if (pwp->reset_notify_listf) {
		scsi_hba_reset_notify_tear_down(pwp->reset_notify_listf);
		pwp->reset_notify_listf = NULL;
	}
	ddi_prop_remove_all(pwp->dip);
	if (pwp->stuck) {
		return (-1);
	}

	/* Free register dump area if allocated */
	if (pwp->regdumpp) {
		kmem_free(pwp->regdumpp, PMCS_REG_DUMP_SIZE);
		pwp->regdumpp = NULL;
	}
	if (pwp->iqpt && pwp->iqpt->head) {
		kmem_free(pwp->iqpt->head, PMCS_IQP_TRACE_BUFFER_SIZE);
		pwp->iqpt->head = pwp->iqpt->curpos = NULL;
	}
	if (pwp->iqpt) {
		kmem_free(pwp->iqpt, sizeof (pmcs_iqp_trace_t));
		pwp->iqpt = NULL;
	}

	/* Destroy pwp's lock */
	if (pwp->locks_initted) {
		mutex_destroy(&pwp->lock);
		mutex_destroy(&pwp->dma_lock);
		mutex_destroy(&pwp->axil_lock);
		mutex_destroy(&pwp->cq_lock);
		mutex_destroy(&pwp->config_lock);
		mutex_destroy(&pwp->ict_lock);
		mutex_destroy(&pwp->wfree_lock);
		mutex_destroy(&pwp->pfree_lock);
		mutex_destroy(&pwp->dead_phylist_lock);
#ifdef	DEBUG
		mutex_destroy(&pwp->dbglock);
#endif
		cv_destroy(&pwp->config_cv);
		cv_destroy(&pwp->ict_cv);
		cv_destroy(&pwp->drain_cv);
		pwp->locks_initted = 0;
	}

	ddi_soft_state_free(pmcs_softc_state, ddi_get_instance(pwp->dip));
	return (0);
}

/*
 * quiesce (9E) entry point
 *
 * This function is called when the system is single-threaded at high PIL
 * with preemption disabled. Therefore, the function must not block/wait/sleep.
 *
 * Returns DDI_SUCCESS or DDI_FAILURE.
 *
 */
static int
pmcs_quiesce(dev_info_t *dip)
{
	pmcs_hw_t	*pwp;
	scsi_hba_tran_t	*tran;

	if ((tran = ddi_get_driver_private(dip)) == NULL)
		return (DDI_SUCCESS);

	/* No quiesce necessary on a per-iport basis */
	if (scsi_hba_iport_unit_address(dip) != NULL) {
		return (DDI_SUCCESS);
	}

	if ((pwp = TRAN2PMC(tran)) == NULL)
		return (DDI_SUCCESS);

	/* Stop MPI & Reset chip (no need to re-initialize) */
	(void) pmcs_stop_mpi(pwp);
	(void) pmcs_soft_reset(pwp, B_TRUE);
	pwp->last_reset_reason = PMCS_LAST_RST_QUIESCE;

	return (DDI_SUCCESS);
}

/*
 * Called with xp->statlock and PHY lock and scratch acquired.
 */
static int
pmcs_add_sata_device(pmcs_hw_t *pwp, pmcs_xscsi_t *xp)
{
	ata_identify_t *ati;
	int result, i;
	pmcs_phy_t *pptr;
	uint16_t *a;
	union {
		uint8_t nsa[8];
		uint16_t nsb[4];
	} u;

	/*
	 * Safe defaults - use only if this target is brand new (i.e. doesn't
	 * already have these settings configured)
	 */
	if (xp->capacity == 0) {
		xp->capacity = (uint64_t)-1;
		xp->ca = 1;
		xp->qdepth = 1;
		xp->pio = 1;
	}

	pptr = xp->phy;

	/*
	 * We only try and issue an IDENTIFY for first level
	 * (direct attached) devices. We don't try and
	 * set other quirks here (this will happen later,
	 * if the device is fully configured)
	 */
	if (pptr->level) {
		return (0);
	}

	mutex_exit(&xp->statlock);
	result = pmcs_sata_identify(pwp, pptr);
	mutex_enter(&xp->statlock);

	if (result) {
		return (result);
	}
	ati = pwp->scratch;
	a = &ati->word108;
	for (i = 0; i < 4; i++) {
		u.nsb[i] = ddi_swap16(*a++);
	}

	/*
	 * Check the returned data for being a valid (NAA=5) WWN.
	 * If so, use that and override the SAS address we were
	 * given at Link Up time.
	 */
	if ((u.nsa[0] >> 4) == 5) {
		(void) memcpy(pptr->sas_address, u.nsa, 8);
	}
	pmcs_prt(pwp, PMCS_PRT_DEBUG, pptr, xp,
	    "%s: %s has SAS ADDRESS " SAS_ADDR_FMT,
	    __func__, pptr->path, SAS_ADDR_PRT(pptr->sas_address));
	return (0);
}

/*
 * Called with PHY lock and target statlock held and scratch acquired
 */
static boolean_t
pmcs_add_new_device(pmcs_hw_t *pwp, pmcs_xscsi_t *target)
{
	ASSERT(target != NULL);
	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, target, "%s: target = 0x%p",
	    __func__, (void *) target);

	switch (target->phy->dtype) {
	case SATA:
		if (pmcs_add_sata_device(pwp, target) != 0) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, target->phy,
			    target, "%s: add_sata_device failed for tgt 0x%p",
			    __func__, (void *) target);
			return (B_FALSE);
		}
		break;
	case SAS:
		target->qdepth = maxqdepth;
		break;
	case EXPANDER:
		target->qdepth = 1;
		break;
	}

	target->new = 0;
	target->assigned = 1;
	target->dev_state = PMCS_DEVICE_STATE_OPERATIONAL;
	target->dtype = target->phy->dtype;

	/*
	 * Set the PHY's config stop time to 0.  This is one of the final
	 * stops along the config path, so we're indicating that we
	 * successfully configured the PHY.
	 */
	target->phy->config_stop = 0;

	return (B_TRUE);
}

void
pmcs_worker(void *arg)
{
	pmcs_hw_t *pwp = arg;
	ulong_t work_flags;

	DTRACE_PROBE2(pmcs__worker, ulong_t, pwp->work_flags, boolean_t,
	    pwp->config_changed);

	if (pwp->state != STATE_RUNNING) {
		return;
	}

	work_flags = atomic_swap_ulong(&pwp->work_flags, 0);

	if (work_flags & PMCS_WORK_FLAG_DUMP_REGS) {
		mutex_enter(&pwp->lock);
		pmcs_register_dump_int(pwp);
		mutex_exit(&pwp->lock);
	}

	if (work_flags & PMCS_WORK_FLAG_SAS_HW_ACK) {
		pmcs_ack_events(pwp);
	}

	if (work_flags & PMCS_WORK_FLAG_SPINUP_RELEASE) {
		mutex_enter(&pwp->lock);
		pmcs_spinup_release(pwp, NULL);
		mutex_exit(&pwp->lock);
	}

	if (work_flags & PMCS_WORK_FLAG_SSP_EVT_RECOVERY) {
		pmcs_ssp_event_recovery(pwp);
	}

	if (work_flags & PMCS_WORK_FLAG_DS_ERR_RECOVERY) {
		pmcs_dev_state_recovery(pwp, NULL);
	}

	if (work_flags & PMCS_WORK_FLAG_DEREGISTER_DEV) {
		pmcs_deregister_device_work(pwp, NULL);
	}

	if (work_flags & PMCS_WORK_FLAG_DISCOVER) {
		pmcs_discover(pwp);
	}

	if (work_flags & PMCS_WORK_FLAG_ABORT_HANDLE) {
		if (pmcs_abort_handler(pwp)) {
			SCHEDULE_WORK(pwp, PMCS_WORK_ABORT_HANDLE);
		}
	}

	if (work_flags & PMCS_WORK_FLAG_SATA_RUN) {
		pmcs_sata_work(pwp);
	}

	if (work_flags & PMCS_WORK_FLAG_RUN_QUEUES) {
		pmcs_scsa_wq_run(pwp);
		mutex_enter(&pwp->lock);
		PMCS_CQ_RUN(pwp);
		mutex_exit(&pwp->lock);
	}

	if (work_flags & PMCS_WORK_FLAG_ADD_DMA_CHUNKS) {
		if (pmcs_add_more_chunks(pwp,
		    ptob(1) * PMCS_ADDTL_CHUNK_PAGES)) {
			SCHEDULE_WORK(pwp, PMCS_WORK_ADD_DMA_CHUNKS);
		} else {
			SCHEDULE_WORK(pwp, PMCS_WORK_RUN_QUEUES);
		}
	}
}

static int
pmcs_add_more_chunks(pmcs_hw_t *pwp, unsigned long nsize)
{
	pmcs_dmachunk_t *dc;
	unsigned long dl;
	pmcs_chunk_t	*pchunk = NULL;

	pwp->cip_dma_attr.dma_attr_align = sizeof (uint32_t);

	pchunk = kmem_zalloc(sizeof (pmcs_chunk_t), KM_SLEEP);
	if (pchunk == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "Not enough memory for DMA chunks");
		return (-1);
	}

	if (pmcs_dma_setup(pwp, &pwp->cip_dma_attr, &pchunk->acc_handle,
	    &pchunk->dma_handle, nsize, (caddr_t *)&pchunk->addrp,
	    &pchunk->dma_addr) == B_FALSE) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "Failed to setup DMA for chunks");
		kmem_free(pchunk, sizeof (pmcs_chunk_t));
		return (-1);
	}

	if ((pmcs_check_acc_handle(pchunk->acc_handle) != DDI_SUCCESS) ||
	    (pmcs_check_dma_handle(pchunk->dma_handle) != DDI_SUCCESS)) {
		ddi_fm_service_impact(pwp->dip, DDI_SERVICE_UNAFFECTED);
		return (-1);
	}

	bzero(pchunk->addrp, nsize);
	dc = NULL;
	for (dl = 0; dl < (nsize / PMCS_SGL_CHUNKSZ); dl++) {
		pmcs_dmachunk_t *tmp;
		tmp = kmem_alloc(sizeof (pmcs_dmachunk_t), KM_SLEEP);
		tmp->nxt = dc;
		dc = tmp;
	}
	mutex_enter(&pwp->dma_lock);
	pmcs_idma_chunks(pwp, dc, pchunk, nsize);
	pwp->nchunks++;
	mutex_exit(&pwp->dma_lock);
	return (0);
}

static void
pmcs_check_forward_progress(pmcs_hw_t *pwp)
{
	pmcwork_t	*wrkp;
	uint32_t	*iqp;
	uint32_t	cur_iqci;
	uint32_t	cur_work_idx;
	uint32_t	cur_msgu_tick;
	uint32_t	cur_iop_tick;
	int		i;

	mutex_enter(&pwp->lock);

	if (pwp->state == STATE_IN_RESET) {
		mutex_exit(&pwp->lock);
		return;
	}

	/*
	 * Ensure that inbound work is getting picked up.  First, check to
	 * see if new work has been posted.  If it has, ensure that the
	 * work is moving forward by checking the consumer index and the
	 * last_htag for the work being processed against what we saw last
	 * time.  Note: we use the work structure's 'last_htag' because at
	 * any given moment it could be freed back, thus clearing 'htag'
	 * and setting 'last_htag' (see pmcs_pwork).
	 */
	for (i = 0; i < PMCS_NIQ; i++) {
		cur_iqci = pmcs_rd_iqci(pwp, i);
		iqp = &pwp->iqp[i][cur_iqci * (PMCS_QENTRY_SIZE >> 2)];
		cur_work_idx = PMCS_TAG_INDEX(LE_32(*(iqp+1)));
		wrkp = &pwp->work[cur_work_idx];
		if (cur_iqci == pwp->shadow_iqpi[i]) {
			pwp->last_iqci[i] = cur_iqci;
			pwp->last_htag[i] = wrkp->last_htag;
			continue;
		}
		if ((cur_iqci == pwp->last_iqci[i]) &&
		    (wrkp->last_htag == pwp->last_htag[i])) {
			pmcs_prt(pwp, PMCS_PRT_WARN, NULL, NULL,
			    "Inbound Queue stall detected, issuing reset");
			goto hot_reset;
		}
		pwp->last_iqci[i] = cur_iqci;
		pwp->last_htag[i] = wrkp->last_htag;
	}

	/*
	 * Check heartbeat on both the MSGU and IOP.  It is unlikely that
	 * we'd ever fail here, as the inbound queue monitoring code above
	 * would detect a stall due to either of these elements being
	 * stalled, but we might as well keep an eye on them.
	 */
	cur_msgu_tick = pmcs_rd_gst_tbl(pwp, PMCS_GST_MSGU_TICK);
	if (cur_msgu_tick == pwp->last_msgu_tick) {
		pmcs_prt(pwp, PMCS_PRT_WARN, NULL, NULL,
		    "Stall detected on MSGU, issuing reset");
		goto hot_reset;
	}
	pwp->last_msgu_tick = cur_msgu_tick;

	cur_iop_tick  = pmcs_rd_gst_tbl(pwp, PMCS_GST_IOP_TICK);
	if (cur_iop_tick == pwp->last_iop_tick) {
		pmcs_prt(pwp, PMCS_PRT_WARN, NULL, NULL,
		    "Stall detected on IOP, issuing reset");
		goto hot_reset;
	}
	pwp->last_iop_tick = cur_iop_tick;

	mutex_exit(&pwp->lock);
	return;

hot_reset:
	pwp->state = STATE_DEAD;
	/*
	 * We've detected a stall. Attempt to recover service via hot
	 * reset. In case of failure, pmcs_hot_reset() will handle the
	 * failure and issue any required FM notifications.
	 * See pmcs_subr.c for more details.
	 */
	if (pmcs_hot_reset(pwp)) {
		pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL,
		    "%s: hot reset failure", __func__);
	} else {
		pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL,
		    "%s: hot reset complete", __func__);
		pwp->last_reset_reason = PMCS_LAST_RST_STALL;
	}
	mutex_exit(&pwp->lock);
}

static void
pmcs_check_commands(pmcs_hw_t *pwp)
{
	pmcs_cmd_t *sp;
	size_t amt;
	char path[32];
	pmcwork_t *pwrk;
	pmcs_xscsi_t *target;
	pmcs_phy_t *phyp;
	int rval;

	for (pwrk = pwp->work; pwrk < &pwp->work[pwp->max_cmd]; pwrk++) {
		mutex_enter(&pwrk->lock);

		/*
		 * If the command isn't active, we can't be timing it still.
		 * Active means the tag is not free and the state is "on chip".
		 */
		if (!PMCS_COMMAND_ACTIVE(pwrk)) {
			mutex_exit(&pwrk->lock);
			continue;
		}

		/*
		 * No timer active for this command.
		 */
		if (pwrk->timer == 0) {
			mutex_exit(&pwrk->lock);
			continue;
		}

		/*
		 * Knock off bits for the time interval.
		 */
		if (pwrk->timer >= US2WT(PMCS_WATCH_INTERVAL)) {
			pwrk->timer -= US2WT(PMCS_WATCH_INTERVAL);
		} else {
			pwrk->timer = 0;
		}
		if (pwrk->timer > 0) {
			mutex_exit(&pwrk->lock);
			continue;
		}

		/*
		 * The command has now officially timed out.
		 * Get the path for it. If it doesn't have
		 * a phy pointer any more, it's really dead
		 * and can just be put back on the free list.
		 * There should *not* be any commands associated
		 * with it any more.
		 */
		if (pwrk->phy == NULL) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "dead command with gone phy being recycled");
			ASSERT(pwrk->xp == NULL);
			pmcs_pwork(pwp, pwrk);
			continue;
		}
		amt = sizeof (path);
		amt = min(sizeof (pwrk->phy->path), amt);
		(void) memcpy(path, pwrk->phy->path, amt);

		/*
		 * If this is a non-SCSA command, stop here. Eventually
		 * we might do something with non-SCSA commands here-
		 * but so far their timeout mechanisms are handled in
		 * the WAIT_FOR macro.
		 */
		if (pwrk->xp == NULL) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "%s: non-SCSA cmd tag 0x%x timed out",
			    path, pwrk->htag);
			mutex_exit(&pwrk->lock);
			continue;
		}

		sp = pwrk->arg;
		ASSERT(sp != NULL);

		/*
		 * Mark it as timed out.
		 */
		CMD2PKT(sp)->pkt_reason = CMD_TIMEOUT;
		CMD2PKT(sp)->pkt_statistics |= STAT_TIMEOUT;
#ifdef	DEBUG
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pwrk->phy, pwrk->xp,
		    "%s: SCSA cmd tag 0x%x timed out (state %x) onwire=%d",
		    path, pwrk->htag, pwrk->state, pwrk->onwire);
#else
		pmcs_prt(pwp, PMCS_PRT_DEBUG, pwrk->phy, pwrk->xp,
		    "%s: SCSA cmd tag 0x%x timed out (state %x)",
		    path, pwrk->htag, pwrk->state);
#endif
		/*
		 * Mark the work structure as timed out.
		 */
		pwrk->state = PMCS_WORK_STATE_TIMED_OUT;
		phyp = pwrk->phy;
		target = pwrk->xp;
		ASSERT(target != NULL);
		mutex_exit(&pwrk->lock);

		pmcs_lock_phy(phyp);
		mutex_enter(&target->statlock);

		/*
		 * No point attempting recovery if the device is gone
		 */
		if (target->dev_gone) {
			mutex_exit(&target->statlock);
			pmcs_unlock_phy(phyp);
			pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, target,
			    "%s: tgt(0x%p) is gone. Returning CMD_DEV_GONE "
			    "for htag 0x%08x", __func__,
			    (void *)target, pwrk->htag);
			mutex_enter(&pwrk->lock);
			if (!PMCS_COMMAND_DONE(pwrk)) {
				/* Complete this command here */
				pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, target,
				    "%s: Completing cmd (htag 0x%08x) "
				    "anyway", __func__, pwrk->htag);
				pwrk->dead = 1;
				CMD2PKT(sp)->pkt_reason = CMD_DEV_GONE;
				CMD2PKT(sp)->pkt_state = STATE_GOT_BUS;
				pmcs_complete_work_impl(pwp, pwrk, NULL, 0);
			} else {
				mutex_exit(&pwrk->lock);
			}
			continue;
		}

		mutex_exit(&target->statlock);
		rval = pmcs_abort(pwp, phyp, pwrk->htag, 0, 1);
		if (rval) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, target,
			    "%s: Bad status (%d) on abort of HTAG 0x%08x",
			    __func__, rval, pwrk->htag);
			pmcs_unlock_phy(phyp);
			mutex_enter(&pwrk->lock);
			if (!PMCS_COMMAND_DONE(pwrk)) {
				/* Complete this command here */
				pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, target,
				    "%s: Completing cmd (htag 0x%08x) "
				    "anyway", __func__, pwrk->htag);
				if (target->dev_gone) {
					pwrk->dead = 1;
					CMD2PKT(sp)->pkt_reason = CMD_DEV_GONE;
					CMD2PKT(sp)->pkt_state = STATE_GOT_BUS;
				}
				pmcs_complete_work_impl(pwp, pwrk, NULL, 0);
			} else {
				mutex_exit(&pwrk->lock);
			}
			pmcs_lock_phy(phyp);
			/*
			 * No need to reschedule ABORT if we get any other
			 * status
			 */
			if (rval == ENOMEM) {
				phyp->abort_sent = 0;
				phyp->abort_pending = 1;
				SCHEDULE_WORK(pwp, PMCS_WORK_ABORT_HANDLE);
			}
		}
		pmcs_unlock_phy(phyp);
	}
	/*
	 * Run any completions that may have been queued up.
	 */
	PMCS_CQ_RUN(pwp);
}

static void
pmcs_watchdog(void *arg)
{
	pmcs_hw_t *pwp = arg;

	DTRACE_PROBE2(pmcs__watchdog, ulong_t, pwp->work_flags, boolean_t,
	    pwp->config_changed);

	/*
	 * Check forward progress on the chip
	 */
	if (++pwp->watchdog_count == PMCS_FWD_PROG_TRIGGER) {
		pwp->watchdog_count = 0;
		pmcs_check_forward_progress(pwp);
	}

	/*
	 * Check to see if we need to kick discovery off again
	 */
	mutex_enter(&pwp->config_lock);
	if (pwp->config_restart &&
	    (ddi_get_lbolt() >= pwp->config_restart_time)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "%s: Timer expired for re-enumeration: Start discovery",
		    __func__);
		pwp->config_restart = B_FALSE;
		SCHEDULE_WORK(pwp, PMCS_WORK_DISCOVER);
	}
	mutex_exit(&pwp->config_lock);

	mutex_enter(&pwp->lock);
	if (pwp->state != STATE_RUNNING) {
		mutex_exit(&pwp->lock);
		return;
	}

	if (atomic_cas_ulong(&pwp->work_flags, 0, 0) != 0) {
		if (ddi_taskq_dispatch(pwp->tq, pmcs_worker, pwp,
		    DDI_NOSLEEP) != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "Could not dispatch to worker thread");
		}
	}
	pwp->wdhandle = timeout(pmcs_watchdog, pwp,
	    drv_usectohz(PMCS_WATCH_INTERVAL));

	mutex_exit(&pwp->lock);

	pmcs_check_commands(pwp);
	pmcs_handle_dead_phys(pwp);
}

static int
pmcs_remove_ihandlers(pmcs_hw_t *pwp, int icnt)
{
	int i, r, rslt = 0;
	for (i = 0; i < icnt; i++) {
		r = ddi_intr_remove_handler(pwp->ih_table[i]);
		if (r == DDI_SUCCESS) {
			continue;
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: unable to remove interrupt handler %d", __func__, i);
		rslt = -1;
		break;
	}
	return (rslt);
}

static int
pmcs_disable_intrs(pmcs_hw_t *pwp, int icnt)
{
	if (pwp->intr_cap & DDI_INTR_FLAG_BLOCK) {
		int r = ddi_intr_block_disable(&pwp->ih_table[0],
		    pwp->intr_cnt);
		if (r != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "unable to disable interrupt block");
			return (-1);
		}
	} else {
		int i;
		for (i = 0; i < icnt; i++) {
			if (ddi_intr_disable(pwp->ih_table[i]) == DDI_SUCCESS) {
				continue;
			}
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "unable to disable interrupt %d", i);
			return (-1);
		}
	}
	return (0);
}

static int
pmcs_free_intrs(pmcs_hw_t *pwp, int icnt)
{
	int i;
	for (i = 0; i < icnt; i++) {
		if (ddi_intr_free(pwp->ih_table[i]) == DDI_SUCCESS) {
			continue;
		}
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "unable to free interrupt %d", i);
		return (-1);
	}
	kmem_free(pwp->ih_table, pwp->ih_table_size);
	pwp->ih_table_size = 0;
	return (0);
}

/*
 * Try to set up interrupts of type "type" with a minimum number of interrupts
 * of "min".
 */
static void
pmcs_setup_intr_impl(pmcs_hw_t *pwp, int type, int min)
{
	int rval, avail, count, actual, max;

	rval = ddi_intr_get_nintrs(pwp->dip, type, &count);
	if ((rval != DDI_SUCCESS) || (count < min)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "%s: get_nintrs failed; type: %d rc: %d count: %d min: %d",
		    __func__, type, rval, count, min);
		return;
	}

	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
	    "%s: nintrs = %d for type: %d", __func__, count, type);

	rval = ddi_intr_get_navail(pwp->dip, type, &avail);
	if ((rval != DDI_SUCCESS) || (avail < min)) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "%s: get_navail failed; type: %d rc: %d avail: %d min: %d",
		    __func__, type, rval, avail, min);
		return;
	}

	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
	    "%s: navail = %d for type: %d", __func__, avail, type);

	pwp->ih_table_size = avail * sizeof (ddi_intr_handle_t);
	pwp->ih_table = kmem_alloc(pwp->ih_table_size, KM_SLEEP);

	switch (type) {
	case DDI_INTR_TYPE_MSIX:
		pwp->int_type = PMCS_INT_MSIX;
		max = PMCS_MAX_MSIX;
		break;
	case DDI_INTR_TYPE_MSI:
		pwp->int_type = PMCS_INT_MSI;
		max = PMCS_MAX_MSI;
		break;
	case DDI_INTR_TYPE_FIXED:
	default:
		pwp->int_type = PMCS_INT_FIXED;
		max = PMCS_MAX_FIXED;
		break;
	}

	rval = ddi_intr_alloc(pwp->dip, pwp->ih_table, type, 0, max, &actual,
	    DDI_INTR_ALLOC_NORMAL);
	if (rval != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, NULL, NULL,
		    "%s: ddi_intr_alloc failed; type: %d rc: %d",
		    __func__, type, rval);
		kmem_free(pwp->ih_table, pwp->ih_table_size);
		pwp->ih_table = NULL;
		pwp->ih_table_size = 0;
		pwp->intr_cnt = 0;
		pwp->int_type = PMCS_INT_NONE;
		return;
	}

	pwp->intr_cnt = actual;
}

/*
 * Set up interrupts.
 * We return one of three values:
 *
 * 0 - success
 * EAGAIN - failure to set up interrupts
 * EIO - "" + we're now stuck partly enabled
 *
 * If EIO is returned, we can't unload the driver.
 */
static int
pmcs_setup_intr(pmcs_hw_t *pwp)
{
	int i, r, itypes, oqv_count;
	ddi_intr_handler_t **iv_table;
	size_t iv_table_size;
	uint_t pri;

	if (ddi_intr_get_supported_types(pwp->dip, &itypes) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "cannot get interrupt types");
		return (EAGAIN);
	}

	if (disable_msix) {
		itypes &= ~DDI_INTR_TYPE_MSIX;
	}
	if (disable_msi) {
		itypes &= ~DDI_INTR_TYPE_MSI;
	}

	/*
	 * We won't know what firmware we're running until we call pmcs_setup,
	 * and we can't call pmcs_setup until we establish interrupts.
	 */

	pwp->int_type = PMCS_INT_NONE;

	/*
	 * We want PMCS_MAX_MSIX vectors for MSI-X.  Anything less would be
	 * uncivilized.
	 */
	if (itypes & DDI_INTR_TYPE_MSIX) {
		pmcs_setup_intr_impl(pwp, DDI_INTR_TYPE_MSIX, PMCS_MAX_MSIX);
		if (pwp->int_type == PMCS_INT_MSIX) {
			itypes = 0;
		}
	}

	if (itypes & DDI_INTR_TYPE_MSI) {
		pmcs_setup_intr_impl(pwp, DDI_INTR_TYPE_MSI, 1);
		if (pwp->int_type == PMCS_INT_MSI) {
			itypes = 0;
		}
	}

	if (itypes & DDI_INTR_TYPE_FIXED) {
		pmcs_setup_intr_impl(pwp, DDI_INTR_TYPE_FIXED, 1);
		if (pwp->int_type == PMCS_INT_FIXED) {
			itypes = 0;
		}
	}

	if (pwp->intr_cnt == 0) {
		pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL,
		    "No interrupts available");
		return (EAGAIN);
	}

	iv_table_size = sizeof (ddi_intr_handler_t *) * pwp->intr_cnt;
	iv_table = kmem_alloc(iv_table_size, KM_SLEEP);

	/*
	 * Get iblock cookie and add handlers.
	 */
	switch (pwp->intr_cnt) {
	case 1:
		iv_table[0] = pmcs_all_intr;
		break;
	case 2:
		iv_table[0] = pmcs_iodone_ix;
		iv_table[1] = pmcs_nonio_ix;
		break;
	case 4:
		iv_table[PMCS_MSIX_GENERAL] = pmcs_general_ix;
		iv_table[PMCS_MSIX_IODONE] = pmcs_iodone_ix;
		iv_table[PMCS_MSIX_EVENTS] = pmcs_event_ix;
		iv_table[PMCS_MSIX_FATAL] = pmcs_fatal_ix;
		break;
	default:
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: intr_cnt = %d - unexpected", __func__, pwp->intr_cnt);
		kmem_free(iv_table, iv_table_size);
		return (EAGAIN);
	}

	for (i = 0; i < pwp->intr_cnt; i++) {
		r = ddi_intr_add_handler(pwp->ih_table[i], iv_table[i],
		    (caddr_t)pwp, NULL);
		if (r != DDI_SUCCESS) {
			kmem_free(iv_table, iv_table_size);
			if (pmcs_remove_ihandlers(pwp, i)) {
				return (EIO);
			}
			if (pmcs_free_intrs(pwp, i)) {
				return (EIO);
			}
			pwp->intr_cnt = 0;
			return (EAGAIN);
		}
	}

	kmem_free(iv_table, iv_table_size);

	if (ddi_intr_get_cap(pwp->ih_table[0], &pwp->intr_cap) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "unable to get int capabilities");
		if (pmcs_remove_ihandlers(pwp, pwp->intr_cnt)) {
			return (EIO);
		}
		if (pmcs_free_intrs(pwp, pwp->intr_cnt)) {
			return (EIO);
		}
		pwp->intr_cnt = 0;
		return (EAGAIN);
	}

	if (pwp->intr_cap & DDI_INTR_FLAG_BLOCK) {
		r = ddi_intr_block_enable(&pwp->ih_table[0], pwp->intr_cnt);
		if (r != DDI_SUCCESS) {
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "intr blk enable failed");
			if (pmcs_remove_ihandlers(pwp, pwp->intr_cnt)) {
				return (EIO);
			}
			if (pmcs_free_intrs(pwp, pwp->intr_cnt)) {
				return (EIO);
			}
			pwp->intr_cnt = 0;
			return (EFAULT);
		}
	} else {
		for (i = 0; i < pwp->intr_cnt; i++) {
			r = ddi_intr_enable(pwp->ih_table[i]);
			if (r == DDI_SUCCESS) {
				continue;
			}
			pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
			    "unable to enable interrupt %d", i);
			if (pmcs_disable_intrs(pwp, i)) {
				return (EIO);
			}
			if (pmcs_remove_ihandlers(pwp, pwp->intr_cnt)) {
				return (EIO);
			}
			if (pmcs_free_intrs(pwp, pwp->intr_cnt)) {
				return (EIO);
			}
			pwp->intr_cnt = 0;
			return (EAGAIN);
		}
	}

	/*
	 * Set up locks.
	 */
	if (ddi_intr_get_pri(pwp->ih_table[0], &pri) != DDI_SUCCESS) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "unable to get interrupt priority");
		if (pmcs_disable_intrs(pwp, pwp->intr_cnt)) {
			return (EIO);
		}
		if (pmcs_remove_ihandlers(pwp, pwp->intr_cnt)) {
			return (EIO);
		}
		if (pmcs_free_intrs(pwp, pwp->intr_cnt)) {
			return (EIO);
		}
		pwp->intr_cnt = 0;
		return (EAGAIN);
	}

	pwp->locks_initted = 1;
	pwp->intr_pri = pri;
	mutex_init(&pwp->lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	mutex_init(&pwp->dma_lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	mutex_init(&pwp->axil_lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	mutex_init(&pwp->cq_lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	mutex_init(&pwp->ict_lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	mutex_init(&pwp->config_lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	mutex_init(&pwp->wfree_lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	mutex_init(&pwp->pfree_lock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
	mutex_init(&pwp->dead_phylist_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(pri));
#ifdef	DEBUG
	mutex_init(&pwp->dbglock, NULL, MUTEX_DRIVER, DDI_INTR_PRI(pri));
#endif
	cv_init(&pwp->ict_cv, NULL, CV_DRIVER, NULL);
	cv_init(&pwp->drain_cv, NULL, CV_DRIVER, NULL);
	cv_init(&pwp->config_cv, NULL, CV_DRIVER, NULL);
	for (i = 0; i < PMCS_NIQ; i++) {
		mutex_init(&pwp->iqp_lock[i], NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(pwp->intr_pri));
	}
	for (i = 0; i < pwp->cq_info.cq_threads; i++) {
		mutex_init(&pwp->cq_info.cq_thr_info[i].cq_thr_lock, NULL,
		    MUTEX_DRIVER, DDI_INTR_PRI(pwp->intr_pri));
		cv_init(&pwp->cq_info.cq_thr_info[i].cq_cv, NULL,
		    CV_DRIVER, NULL);
	}

	pmcs_prt(pwp, PMCS_PRT_INFO, NULL, NULL, "%d %s interrup%s configured",
	    pwp->intr_cnt, (pwp->int_type == PMCS_INT_MSIX)? "MSI-X" :
	    ((pwp->int_type == PMCS_INT_MSI)? "MSI" : "INT-X"),
	    pwp->intr_cnt == 1? "t" : "ts");


	/*
	 * Enable Interrupts
	 */
	if (pwp->intr_cnt > PMCS_NOQ) {
		oqv_count = pwp->intr_cnt;
	} else {
		oqv_count = PMCS_NOQ;
	}
	for (pri = 0xffffffff, i = 0; i < oqv_count; i++) {
		pri ^= (1 << i);
	}

	mutex_enter(&pwp->lock);
	pwp->intr_mask = pri;
	pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_MASK, pwp->intr_mask);
	pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_CLEAR, 0xffffffff);
	mutex_exit(&pwp->lock);

	return (0);
}

static int
pmcs_teardown_intr(pmcs_hw_t *pwp)
{
	if (pwp->intr_cnt) {
		if (pmcs_disable_intrs(pwp, pwp->intr_cnt)) {
			return (EIO);
		}
		if (pmcs_remove_ihandlers(pwp, pwp->intr_cnt)) {
			return (EIO);
		}
		if (pmcs_free_intrs(pwp, pwp->intr_cnt)) {
			return (EIO);
		}
		pwp->intr_cnt = 0;
	}
	return (0);
}

static uint_t
pmcs_general_ix(caddr_t arg1, caddr_t arg2)
{
	pmcs_hw_t *pwp = (pmcs_hw_t *)((void *)arg1);
	_NOTE(ARGUNUSED(arg2));
	pmcs_general_intr(pwp);
	return (DDI_INTR_CLAIMED);
}

static uint_t
pmcs_event_ix(caddr_t arg1, caddr_t arg2)
{
	pmcs_hw_t *pwp = (pmcs_hw_t *)((void *)arg1);
	_NOTE(ARGUNUSED(arg2));
	pmcs_event_intr(pwp);
	return (DDI_INTR_CLAIMED);
}

static uint_t
pmcs_iodone_ix(caddr_t arg1, caddr_t arg2)
{
	_NOTE(ARGUNUSED(arg2));
	pmcs_hw_t *pwp = (pmcs_hw_t *)((void *)arg1);

	/*
	 * It's possible that if we just turned interrupt coalescing off
	 * (and thus, re-enabled auto clear for interrupts on the I/O outbound
	 * queue) that there was an interrupt already pending.  We use
	 * io_intr_coal.int_cleared to ensure that we still drop in here and
	 * clear the appropriate interrupt bit one last time.
	 */
	mutex_enter(&pwp->ict_lock);
	if (pwp->io_intr_coal.timer_on ||
	    (pwp->io_intr_coal.int_cleared == B_FALSE)) {
		pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_CLEAR,
		    (1 << PMCS_OQ_IODONE));
		pwp->io_intr_coal.int_cleared = B_TRUE;
	}
	mutex_exit(&pwp->ict_lock);

	pmcs_iodone_intr(pwp);

	return (DDI_INTR_CLAIMED);
}

static uint_t
pmcs_fatal_ix(caddr_t arg1, caddr_t arg2)
{
	pmcs_hw_t *pwp = (pmcs_hw_t *)((void *)arg1);
	_NOTE(ARGUNUSED(arg2));
	pmcs_fatal_handler(pwp);
	return (DDI_INTR_CLAIMED);
}

static uint_t
pmcs_nonio_ix(caddr_t arg1, caddr_t arg2)
{
	_NOTE(ARGUNUSED(arg2));
	pmcs_hw_t *pwp = (void *)arg1;
	uint32_t obdb = pmcs_rd_msgunit(pwp, PMCS_MSGU_OBDB);

	/*
	 * Check for Fatal Interrupts
	 */
	if (obdb & (1 << PMCS_FATAL_INTERRUPT)) {
		pmcs_fatal_handler(pwp);
		return (DDI_INTR_CLAIMED);
	}

	if (obdb & (1 << PMCS_OQ_GENERAL)) {
		pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_CLEAR,
		    (1 << PMCS_OQ_GENERAL));
		pmcs_general_intr(pwp);
		pmcs_event_intr(pwp);
	}

	return (DDI_INTR_CLAIMED);
}

static uint_t
pmcs_all_intr(caddr_t arg1, caddr_t arg2)
{
	_NOTE(ARGUNUSED(arg2));
	pmcs_hw_t *pwp = (void *) arg1;
	uint32_t obdb;
	int handled = 0;

	obdb = pmcs_rd_msgunit(pwp, PMCS_MSGU_OBDB);

	/*
	 * Check for Fatal Interrupts
	 */
	if (obdb & (1 << PMCS_FATAL_INTERRUPT)) {
		pmcs_fatal_handler(pwp);
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * Check for Outbound Queue service needed
	 */
	if (obdb & (1 << PMCS_OQ_IODONE)) {
		pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_CLEAR,
		    (1 << PMCS_OQ_IODONE));
		obdb ^= (1 << PMCS_OQ_IODONE);
		handled++;
		pmcs_iodone_intr(pwp);
	}
	if (obdb & (1 << PMCS_OQ_GENERAL)) {
		pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_CLEAR,
		    (1 << PMCS_OQ_GENERAL));
		obdb ^= (1 << PMCS_OQ_GENERAL);
		handled++;
		pmcs_general_intr(pwp);
	}
	if (obdb & (1 << PMCS_OQ_EVENTS)) {
		pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_CLEAR,
		    (1 << PMCS_OQ_EVENTS));
		obdb ^= (1 << PMCS_OQ_EVENTS);
		handled++;
		pmcs_event_intr(pwp);
	}
	if (obdb) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "interrupt bits not handled (0x%x)", obdb);
		pmcs_wr_msgunit(pwp, PMCS_MSGU_OBDB_CLEAR, obdb);
		handled++;
	}
	if (pwp->int_type == PMCS_INT_MSI) {
		handled++;
	}
	return (handled? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

void
pmcs_fatal_handler(pmcs_hw_t *pwp)
{
	pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL, "Fatal Interrupt caught");

	mutex_enter(&pwp->lock);
	pwp->state = STATE_DEAD;

	/*
	 * Attempt a hot reset. In case of failure, pmcs_hot_reset() will
	 * handle the failure and issue any required FM notifications.
	 * See pmcs_subr.c for more details.
	 */
	if (pmcs_hot_reset(pwp)) {
		pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL,
		    "%s: hot reset failure", __func__);
	} else {
		pmcs_prt(pwp, PMCS_PRT_ERR, NULL, NULL,
		    "%s: hot reset complete", __func__);
		pwp->last_reset_reason = PMCS_LAST_RST_FATAL_ERROR;
	}
	mutex_exit(&pwp->lock);
}

/*
 * Called with PHY lock and target statlock held and scratch acquired.
 */
boolean_t
pmcs_assign_device(pmcs_hw_t *pwp, pmcs_xscsi_t *tgt)
{
	pmcs_phy_t *pptr = tgt->phy;

	switch (pptr->dtype) {
	case SAS:
	case EXPANDER:
		break;
	case SATA:
		tgt->ca = 1;
		break;
	default:
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, tgt,
		    "%s: Target %p has PHY %p with invalid dtype",
		    __func__, (void *)tgt, (void *)pptr);
		return (B_FALSE);
	}

	tgt->new = 1;
	tgt->dev_gone = 0;
	tgt->recover_wait = 0;

	pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, tgt,
	    "%s: config %s vtgt %u for " SAS_ADDR_FMT, __func__,
	    pptr->path, tgt->target_num, SAS_ADDR_PRT(pptr->sas_address));

	if (pmcs_add_new_device(pwp, tgt) != B_TRUE) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, tgt,
		    "%s: Failed for vtgt %u / WWN " SAS_ADDR_FMT, __func__,
		    tgt->target_num, SAS_ADDR_PRT(pptr->sas_address));
		mutex_destroy(&tgt->statlock);
		mutex_destroy(&tgt->wqlock);
		mutex_destroy(&tgt->aqlock);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Called with softstate lock held
 */
void
pmcs_remove_device(pmcs_hw_t *pwp, pmcs_phy_t *pptr)
{
	pmcs_xscsi_t *xp;
	unsigned int vtgt;

	ASSERT(mutex_owned(&pwp->lock));

	for (vtgt = 0; vtgt < pwp->max_dev; vtgt++) {
		xp = pwp->targets[vtgt];
		if (xp == NULL) {
			continue;
		}

		mutex_enter(&xp->statlock);
		if (xp->phy == pptr) {
			if (xp->new) {
				xp->new = 0;
				pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, xp,
				    "cancel config of vtgt %u", vtgt);
			} else {
				pmcs_clear_xp(pwp, xp);
				pmcs_prt(pwp, PMCS_PRT_DEBUG_CONFIG, pptr, xp,
				    "Removed tgt 0x%p vtgt %u",
				    (void *)xp, vtgt);
			}
			mutex_exit(&xp->statlock);
			break;
		}
		mutex_exit(&xp->statlock);
	}
}

void
pmcs_prt_impl(pmcs_hw_t *pwp, pmcs_prt_level_t level,
    pmcs_phy_t *phyp, pmcs_xscsi_t *target, const char *fmt, ...)
{
	va_list	ap;
	int written = 0;
	char *ptr;
	uint32_t elem_size = PMCS_TBUF_ELEM_SIZE - 1;
	boolean_t system_log;
	int system_log_level;
	hrtime_t hrtimestamp;

	switch (level) {
	case PMCS_PRT_DEBUG_DEVEL:
	case PMCS_PRT_DEBUG_DEV_STATE:
	case PMCS_PRT_DEBUG_PHY_LOCKING:
	case PMCS_PRT_DEBUG_SCSI_STATUS:
	case PMCS_PRT_DEBUG_UNDERFLOW:
	case PMCS_PRT_DEBUG_CONFIG:
	case PMCS_PRT_DEBUG_IPORT:
	case PMCS_PRT_DEBUG_MAP:
	case PMCS_PRT_DEBUG3:
	case PMCS_PRT_DEBUG2:
	case PMCS_PRT_DEBUG1:
	case PMCS_PRT_DEBUG:
		system_log = B_FALSE;
		break;
	case PMCS_PRT_INFO:
		system_log = B_TRUE;
		system_log_level = CE_CONT;
		break;
	case PMCS_PRT_WARN:
		system_log = B_TRUE;
		system_log_level = CE_NOTE;
		break;
	case PMCS_PRT_ERR:
		system_log = B_TRUE;
		system_log_level = CE_WARN;
		break;
	default:
		return;
	}

	mutex_enter(&pmcs_trace_lock);
	hrtimestamp = gethrtime();
	gethrestime(&pmcs_tbuf_ptr->timestamp);

	if (pwp->fw_timestamp != 0) {
		/* Calculate the approximate firmware time stamp... */
		pmcs_tbuf_ptr->fw_timestamp = pwp->fw_timestamp +
		    ((hrtimestamp - pwp->hrtimestamp) / PMCS_FWLOG_TIMER_DIV);
	} else {
		pmcs_tbuf_ptr->fw_timestamp = 0;
	}

	ptr = pmcs_tbuf_ptr->buf;

	/*
	 * Store the pertinent PHY and target information if there is any
	 */
	if (target == NULL) {
		pmcs_tbuf_ptr->target_num = PMCS_INVALID_TARGET_NUM;
		pmcs_tbuf_ptr->target_ua[0] = '\0';
	} else {
		pmcs_tbuf_ptr->target_num = target->target_num;
		(void) strncpy(pmcs_tbuf_ptr->target_ua, target->ua,
		    PMCS_TBUF_UA_MAX_SIZE);
	}

	if (phyp == NULL) {
		(void) memset(pmcs_tbuf_ptr->phy_sas_address, 0, 8);
		pmcs_tbuf_ptr->phy_path[0] = '\0';
		pmcs_tbuf_ptr->phy_dtype = NOTHING;
	} else {
		(void) memcpy(pmcs_tbuf_ptr->phy_sas_address,
		    phyp->sas_address, 8);
		(void) strncpy(pmcs_tbuf_ptr->phy_path, phyp->path, 32);
		pmcs_tbuf_ptr->phy_dtype = phyp->dtype;
	}

	written += snprintf(ptr, elem_size, "pmcs%d:%d: ",
	    ddi_get_instance(pwp->dip), level);
	ptr += strlen(ptr);
	va_start(ap, fmt);
	written += vsnprintf(ptr, elem_size - written, fmt, ap);
	va_end(ap);
	if (written > elem_size - 1) {
		/* Indicate truncation */
		pmcs_tbuf_ptr->buf[elem_size - 1] = '+';
	}
	if (++pmcs_tbuf_idx == pmcs_tbuf_num_elems) {
		pmcs_tbuf_ptr = pmcs_tbuf;
		pmcs_tbuf_wrap = B_TRUE;
		pmcs_tbuf_idx = 0;
	} else {
		++pmcs_tbuf_ptr;
	}
	mutex_exit(&pmcs_trace_lock);

	/*
	 * When pmcs_force_syslog in non-zero, everything goes also
	 * to syslog, at CE_CONT level.
	 */
	if (pmcs_force_syslog) {
		system_log = B_TRUE;
		system_log_level = CE_CONT;
	}

	/*
	 * Anything that comes in with PMCS_PRT_INFO, WARN, or ERR also
	 * goes to syslog.
	 */
	if (system_log) {
		char local[196];

		switch (system_log_level) {
		case CE_CONT:
			(void) snprintf(local, sizeof (local), "%sINFO: ",
			    pmcs_console ? "" : "?");
			break;
		case CE_NOTE:
		case CE_WARN:
			local[0] = '\0';
			break;
		default:
			return;
		}

		ptr = local;
		ptr += strlen(local);
		(void) snprintf(ptr, (sizeof (local)) -
		    ((size_t)ptr - (size_t)local), "pmcs%d: ",
		    ddi_get_instance(pwp->dip));
		ptr += strlen(ptr);
		va_start(ap, fmt);
		(void) vsnprintf(ptr,
		    (sizeof (local)) - ((size_t)ptr - (size_t)local), fmt, ap);
		va_end(ap);
		if (level == CE_CONT) {
			(void) strlcat(local, "\n", sizeof (local));
		}
		cmn_err(system_log_level, local);
	}

}

/*
 * pmcs_acquire_scratch
 *
 * If "wait" is true, the caller will wait until it can acquire the scratch.
 * This implies the caller needs to be in a context where spinning for an
 * indeterminate amount of time is acceptable.
 */
int
pmcs_acquire_scratch(pmcs_hw_t *pwp, boolean_t wait)
{
	int rval;

	if (!wait) {
		return (atomic_swap_8(&pwp->scratch_locked, 1));
	}

	/*
	 * Caller will wait for scratch.
	 */
	while ((rval = atomic_swap_8(&pwp->scratch_locked, 1)) != 0) {
		drv_usecwait(100);
	}

	return (rval);
}

void
pmcs_release_scratch(pmcs_hw_t *pwp)
{
	pwp->scratch_locked = 0;
}

/* Called with iport_lock and phy lock held */
void
pmcs_create_one_phy_stats(pmcs_iport_t *iport, pmcs_phy_t *phyp)
{
	sas_phy_stats_t		*ps;
	pmcs_hw_t		*pwp;
	int			ndata;
	char			ks_name[KSTAT_STRLEN];

	ASSERT(mutex_owned(&iport->lock));
	pwp = iport->pwp;
	ASSERT(pwp != NULL);
	ASSERT(mutex_owned(&phyp->phy_lock));

	if (phyp->phy_stats != NULL) {
		/*
		 * Delete existing kstats with name containing
		 * old iport instance# and allow creation of
		 * new kstats with new iport instance# in the name.
		 */
		kstat_delete(phyp->phy_stats);
	}

	ndata = (sizeof (sas_phy_stats_t)/sizeof (kstat_named_t));

	(void) snprintf(ks_name, sizeof (ks_name),
	    "%s.%llx.%d.%d", ddi_driver_name(iport->dip),
	    (longlong_t)pwp->sas_wwns[0],
	    ddi_get_instance(iport->dip), phyp->phynum);

	phyp->phy_stats = kstat_create("pmcs",
	    ddi_get_instance(iport->dip), ks_name, KSTAT_SAS_PHY_CLASS,
	    KSTAT_TYPE_NAMED, ndata, 0);

	if (phyp->phy_stats == NULL) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, phyp, NULL,
		    "%s: Failed to create %s kstats for PHY(0x%p) at %s",
		    __func__, ks_name, (void *)phyp, phyp->path);
		return;
	}

	ps = (sas_phy_stats_t *)phyp->phy_stats->ks_data;

	kstat_named_init(&ps->seconds_since_last_reset,
	    "SecondsSinceLastReset", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&ps->tx_frames,
	    "TxFrames", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&ps->rx_frames,
	    "RxFrames", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&ps->tx_words,
	    "TxWords", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&ps->rx_words,
	    "RxWords", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&ps->invalid_dword_count,
	    "InvalidDwordCount", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&ps->running_disparity_error_count,
	    "RunningDisparityErrorCount", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&ps->loss_of_dword_sync_count,
	    "LossofDwordSyncCount", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&ps->phy_reset_problem_count,
	    "PhyResetProblemCount", KSTAT_DATA_ULONGLONG);

	phyp->phy_stats->ks_private = phyp;
	phyp->phy_stats->ks_update = pmcs_update_phy_stats;
	kstat_install(phyp->phy_stats);
}

static void
pmcs_create_all_phy_stats(pmcs_iport_t *iport)
{
	pmcs_hw_t		*pwp;
	pmcs_phy_t		*phyp;

	ASSERT(iport != NULL);
	pwp = iport->pwp;
	ASSERT(pwp != NULL);

	mutex_enter(&iport->lock);

	for (phyp = list_head(&iport->phys);
	    phyp != NULL;
	    phyp = list_next(&iport->phys, phyp)) {

		mutex_enter(&phyp->phy_lock);
		pmcs_create_one_phy_stats(iport, phyp);
		mutex_exit(&phyp->phy_lock);
	}

	mutex_exit(&iport->lock);
}

int
pmcs_update_phy_stats(kstat_t *ks, int rw)
{
	int		val, ret = DDI_FAILURE;
	pmcs_phy_t	*pptr = (pmcs_phy_t *)ks->ks_private;
	pmcs_hw_t	*pwp = pptr->pwp;
	sas_phy_stats_t	*ps = ks->ks_data;

	_NOTE(ARGUNUSED(rw));
	ASSERT((pptr != NULL) && (pwp != NULL));

	/*
	 * We just want to lock against other invocations of kstat;
	 * we don't need to pmcs_lock_phy() for this.
	 */
	mutex_enter(&pptr->phy_lock);

	/* Get Stats from Chip */
	val = pmcs_get_diag_report(pwp, PMCS_INVALID_DWORD_CNT, pptr->phynum);
	if (val == DDI_FAILURE)
		goto fail;
	ps->invalid_dword_count.value.ull = (unsigned long long)val;

	val = pmcs_get_diag_report(pwp, PMCS_DISPARITY_ERR_CNT, pptr->phynum);
	if (val == DDI_FAILURE)
		goto fail;
	ps->running_disparity_error_count.value.ull = (unsigned long long)val;

	val = pmcs_get_diag_report(pwp, PMCS_LOST_DWORD_SYNC_CNT, pptr->phynum);
	if (val == DDI_FAILURE)
		goto fail;
	ps->loss_of_dword_sync_count.value.ull = (unsigned long long)val;

	val = pmcs_get_diag_report(pwp, PMCS_RESET_FAILED_CNT, pptr->phynum);
	if (val == DDI_FAILURE)
		goto fail;
	ps->phy_reset_problem_count.value.ull = (unsigned long long)val;

	ret = DDI_SUCCESS;
fail:
	mutex_exit(&pptr->phy_lock);
	return (ret);
}

/*ARGSUSED*/
static int
pmcs_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	/*
	 * as the driver can always deal with an error in any dma or
	 * access handle, we can just return the fme_status value.
	 */
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

static void
pmcs_fm_init(pmcs_hw_t *pwp)
{
	ddi_iblock_cookie_t	fm_ibc;

	/* Only register with IO Fault Services if we have some capability */
	if (pwp->fm_capabilities) {
		/* Adjust access and dma attributes for FMA */
		pwp->reg_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;
		pwp->iqp_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		pwp->oqp_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		pwp->cip_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		pwp->fwlog_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;

		/*
		 * Register capabilities with IO Fault Services.
		 */
		ddi_fm_init(pwp->dip, &pwp->fm_capabilities, &fm_ibc);

		/*
		 * Initialize pci ereport capabilities if ereport
		 * capable (should always be.)
		 */
		if (DDI_FM_EREPORT_CAP(pwp->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(pwp->fm_capabilities)) {
			pci_ereport_setup(pwp->dip);
		}

		/*
		 * Register error callback if error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(pwp->fm_capabilities)) {
			ddi_fm_handler_register(pwp->dip,
			    pmcs_fm_error_cb, (void *) pwp);
		}
	}
}

static void
pmcs_fm_fini(pmcs_hw_t *pwp)
{
	/* Only unregister FMA capabilities if registered */
	if (pwp->fm_capabilities) {
		/*
		 * Un-register error callback if error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(pwp->fm_capabilities)) {
			ddi_fm_handler_unregister(pwp->dip);
		}

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(pwp->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(pwp->fm_capabilities)) {
			pci_ereport_teardown(pwp->dip);
		}

		/* Unregister from IO Fault Services */
		ddi_fm_fini(pwp->dip);

		/* Adjust access and dma attributes for FMA */
		pwp->reg_acc_attr.devacc_attr_access = DDI_DEFAULT_ACC;
		pwp->iqp_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		pwp->oqp_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		pwp->cip_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
		pwp->fwlog_dma_attr.dma_attr_flags &= ~DDI_DMA_FLAGERR;
	}
}

static boolean_t
pmcs_fabricate_wwid(pmcs_hw_t *pwp)
{
	char *cp, c;
	uint64_t adr;
	int i;

	cp = &c;
	(void) ddi_strtoul(hw_serial, &cp, 10, (unsigned long *)&adr);

	if (adr == 0) {
		pmcs_prt(pwp, PMCS_PRT_DEBUG, NULL, NULL,
		    "%s: No serial number available to fabricate WWN",
		    __func__);

		adr = (uint64_t)gethrtime();
	}

	adr <<= 8;
	adr |= ((uint64_t)ddi_get_instance(pwp->dip) << 52);
	adr |= (5ULL << 60);

	for (i = 0; i < PMCS_MAX_PORTS; i++) {
		pwp->sas_wwns[i] = adr + i;
	}

	return (B_TRUE);
}
