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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * 1394 mass storage HBA driver
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/byteorder.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/1394/targets/scsa1394/impl.h>
#include <sys/1394/targets/scsa1394/cmd.h>

/* DDI/DKI entry points */
static int	scsa1394_attach(dev_info_t *, ddi_attach_cmd_t);
static int	scsa1394_detach(dev_info_t *, ddi_detach_cmd_t);
static int	scsa1394_power(dev_info_t *, int, int);
static int	scsa1394_cpr_suspend(dev_info_t *);
static void	scsa1394_cpr_resume(dev_info_t *);

/* configuration routines */
static void	scsa1394_cleanup(scsa1394_state_t *, int);
static int	scsa1394_attach_1394(scsa1394_state_t *);
static void	scsa1394_detach_1394(scsa1394_state_t *);
static int	scsa1394_attach_threads(scsa1394_state_t *);
static void	scsa1394_detach_threads(scsa1394_state_t *);
static int	scsa1394_attach_scsa(scsa1394_state_t *);
static void	scsa1394_detach_scsa(scsa1394_state_t *);
static int	scsa1394_create_cmd_cache(scsa1394_state_t *);
static void	scsa1394_destroy_cmd_cache(scsa1394_state_t *);
static int	scsa1394_add_events(scsa1394_state_t *);
static void	scsa1394_remove_events(scsa1394_state_t *);

/* device configuration */
static int	scsa1394_scsi_bus_config(dev_info_t *, uint_t,
		ddi_bus_config_op_t, void *, dev_info_t **);
static int	scsa1394_scsi_bus_unconfig(dev_info_t *, uint_t,
		ddi_bus_config_op_t, void *);
static void	scsa1394_create_children(scsa1394_state_t *);
static void	scsa1394_bus_reset(dev_info_t *, ddi_eventcookie_t, void *,
		void *);
static void	scsa1394_disconnect(dev_info_t *, ddi_eventcookie_t, void *,
		void *);
static void	scsa1394_reconnect(dev_info_t *, ddi_eventcookie_t, void *,
		void *);

/* SCSA HBA entry points */
static int	scsa1394_scsi_tgt_init(dev_info_t *, dev_info_t *,
		scsi_hba_tran_t *, struct scsi_device *);
static void	scsa1394_scsi_tgt_free(dev_info_t *, dev_info_t *,
		scsi_hba_tran_t *, struct scsi_device *);
static int	scsa1394_scsi_tgt_probe(struct scsi_device *, int (*)());
static int	scsa1394_probe_g0_nodata(struct scsi_device *, int (*)(),
		uchar_t, uint_t, uint_t);
static int	scsa1394_probe_tran(struct scsi_pkt *);
static struct scsi_pkt *scsa1394_scsi_init_pkt(struct scsi_address *,
		struct scsi_pkt *, struct buf *, int, int, int, int,
		int (*)(), caddr_t arg);
static void	scsa1394_scsi_destroy_pkt(struct scsi_address *,
		struct scsi_pkt *);
static int	scsa1394_scsi_start(struct scsi_address *, struct scsi_pkt *);
static int	scsa1394_scsi_abort(struct scsi_address *, struct scsi_pkt *);
static int	scsa1394_scsi_reset(struct scsi_address *, int);
static int	scsa1394_scsi_getcap(struct scsi_address *, char *, int);
static int	scsa1394_scsi_setcap(struct scsi_address *, char *, int, int);
static void	scsa1394_scsi_dmafree(struct scsi_address *, struct scsi_pkt *);
static void	scsa1394_scsi_sync_pkt(struct scsi_address *,
		struct scsi_pkt *);

/* pkt resource allocation routines */
static int	scsa1394_cmd_cache_constructor(void *, void *, int);
static void	scsa1394_cmd_cache_destructor(void *, void *);
static int	scsa1394_cmd_ext_alloc(scsa1394_state_t *, scsa1394_cmd_t *,
		int);
static void	scsa1394_cmd_ext_free(scsa1394_state_t *, scsa1394_cmd_t *);
static int	scsa1394_cmd_cdb_dma_alloc(scsa1394_state_t *, scsa1394_cmd_t *,
		int, int (*)(), caddr_t);
static void	scsa1394_cmd_cdb_dma_free(scsa1394_state_t *, scsa1394_cmd_t *);
static int	scsa1394_cmd_buf_dma_alloc(scsa1394_state_t *, scsa1394_cmd_t *,
		int, int (*)(), caddr_t, struct buf *);
static void	scsa1394_cmd_buf_dma_free(scsa1394_state_t *, scsa1394_cmd_t *);
static int	scsa1394_cmd_dmac2seg(scsa1394_state_t *, scsa1394_cmd_t *,
		ddi_dma_cookie_t *, uint_t, int);
static void	scsa1394_cmd_seg_free(scsa1394_state_t *, scsa1394_cmd_t *);
static int	scsa1394_cmd_pt_dma_alloc(scsa1394_state_t *, scsa1394_cmd_t *,
		int (*)(), caddr_t, int);
static void	scsa1394_cmd_pt_dma_free(scsa1394_state_t *, scsa1394_cmd_t *);
static int	scsa1394_cmd_buf_addr_alloc(scsa1394_state_t *,
		scsa1394_cmd_t *);
static void	scsa1394_cmd_buf_addr_free(scsa1394_state_t *,
		scsa1394_cmd_t *);
static int	scsa1394_cmd_buf_dma_move(scsa1394_state_t *, scsa1394_cmd_t *);


/* pkt and data transfer routines */
static void	scsa1394_prepare_pkt(scsa1394_state_t *, struct scsi_pkt *);
static void	scsa1394_cmd_fill_cdb(scsa1394_lun_t *, scsa1394_cmd_t *);
static void	scsa1394_cmd_fill_cdb_rbc(scsa1394_lun_t *, scsa1394_cmd_t *);
static void	scsa1394_cmd_fill_cdb_other(scsa1394_lun_t *, scsa1394_cmd_t *);
static void	scsa1394_cmd_fill_cdb_len(scsa1394_cmd_t *, int);
static void	scsa1394_cmd_fill_cdb_lba(scsa1394_cmd_t *, int);
static void	scsa1394_cmd_fill_12byte_cdb_len(scsa1394_cmd_t *, int);
static void	scsa1394_cmd_fill_read_cd_cdb_len(scsa1394_cmd_t *, int);
static int	scsa1394_cmd_read_cd_blk_size(uchar_t);
static int	scsa1394_cmd_fake_mode_sense(scsa1394_state_t *,
		scsa1394_cmd_t *);
static int	scsa1394_cmd_fake_inquiry(scsa1394_state_t *, scsa1394_cmd_t *);
static int	scsa1394_cmd_fake_comp(scsa1394_state_t *, scsa1394_cmd_t *);
static int	scsa1394_cmd_setup_next_xfer(scsa1394_lun_t *,
		scsa1394_cmd_t *);
static void	scsa1394_cmd_adjust_cdb(scsa1394_lun_t *, scsa1394_cmd_t *);
static void	scsa1394_cmd_status_wrka(scsa1394_lun_t *, scsa1394_cmd_t *);

/* other routines */
static boolean_t scsa1394_is_my_child(dev_info_t *);
static void *	scsa1394_kmem_realloc(void *, int, int, size_t, int);

static void	*scsa1394_statep;
#define	SCSA1394_INST2STATE(inst) (ddi_get_soft_state(scsa1394_statep, inst))

static struct cb_ops scsa1394_cb_ops = {
	nodev,			/* open */
	nodev,			/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	NULL,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* aread */
	nodev			/* awrite */
};

static struct dev_ops scsa1394_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_no_info,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	scsa1394_attach,	/* attach */
	scsa1394_detach,	/* detach */
	nodev,			/* reset */
	&scsa1394_cb_ops,	/* driver operations */
	NULL,			/* bus operations */
	scsa1394_power,		/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv scsa1394_modldrv = {
	&mod_driverops,			/* module type */
	"1394 Mass Storage HBA Driver", /* name of the module */
	&scsa1394_ops,			/* driver ops */
};

static struct modlinkage scsa1394_modlinkage = {
	MODREV_1, (void *)&scsa1394_modldrv, NULL
};

/* tunables */
int scsa1394_bus_config_debug = 0;
int scsa1394_start_stop_fail_max = SCSA1394_START_STOP_FAIL_MAX;
int scsa1394_mode_sense_fail_max = SCSA1394_MODE_SENSE_FAIL_MAX;
int scsa1394_start_stop_timeout_max = SCSA1394_START_STOP_TIMEOUT_MAX;

/* workarounds */
int scsa1394_wrka_rbc2direct = 1;
int scsa1394_wrka_fake_rmb = 0;
int scsa1394_wrka_fake_prin = 1;

int scsa1394_wrka_symbios = 1;
int scsa1394_symbios_page_size = 4 * 1024;	/* must be <= _pagesize */
int scsa1394_symbios_size_max = 512 * 248;	/* multiple of page size */

/*
 *
 * --- DDI/DKI entry points
 *
 */
int
_init(void)
{
	int	ret;

	if (((ret = ddi_soft_state_init(&scsa1394_statep,
	    sizeof (scsa1394_state_t), 1)) != 0)) {
		return (ret);
	}

	if ((ret = scsi_hba_init(&scsa1394_modlinkage)) != 0) {
		ddi_soft_state_fini(&scsa1394_statep);
		return (ret);
	}

	if ((ret = mod_install(&scsa1394_modlinkage)) != 0) {
		scsi_hba_fini(&scsa1394_modlinkage);
		ddi_soft_state_fini(&scsa1394_statep);
		return (ret);
	}

	return (ret);
}

int
_fini(void)
{
	int	ret;

	if ((ret = mod_remove(&scsa1394_modlinkage)) == 0) {
		scsi_hba_fini(&scsa1394_modlinkage);
		ddi_soft_state_fini(&scsa1394_statep);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&scsa1394_modlinkage, modinfop));
}

static int
scsa1394_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	scsa1394_state_t *sp;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		scsa1394_cpr_resume(dip);
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(scsa1394_statep, instance) != 0) {
		return (DDI_FAILURE);
	}
	sp = SCSA1394_INST2STATE(instance);

#ifndef __lock_lint
	sp->s_dip = dip;
	sp->s_instance = instance;
#endif
	mutex_init(&sp->s_mutex, NULL, MUTEX_DRIVER,
	    sp->s_attachinfo.iblock_cookie);
	cv_init(&sp->s_event_cv, NULL, CV_DRIVER, NULL);

	if (scsa1394_attach_1394(sp) != DDI_SUCCESS) {
		scsa1394_cleanup(sp, 1);
		return (DDI_FAILURE);
	}

	if (scsa1394_sbp2_attach(sp) != DDI_SUCCESS) {
		scsa1394_cleanup(sp, 2);
		return (DDI_FAILURE);
	}

	if (scsa1394_attach_threads(sp) != DDI_SUCCESS) {
		scsa1394_cleanup(sp, 3);
		return (DDI_FAILURE);
	}

	if (scsa1394_attach_scsa(sp) != DDI_SUCCESS) {
		scsa1394_cleanup(sp, 4);
		return (DDI_FAILURE);
	}

	if (scsa1394_create_cmd_cache(sp) != DDI_SUCCESS) {
		scsa1394_cleanup(sp, 5);
		return (DDI_FAILURE);
	}

	if (scsa1394_add_events(sp) != DDI_SUCCESS) {
		scsa1394_cleanup(sp, 6);
		return (DDI_FAILURE);
	}

	/* prevent async PM changes until we are done */
	(void) pm_busy_component(dip, 0);

	/* Set power to full on */
	(void) pm_raise_power(dip, 0, PM_LEVEL_D0);

	/* we are done */
	(void) pm_idle_component(dip, 0);

#ifndef __lock_lint
	sp->s_dev_state = SCSA1394_DEV_ONLINE;
#endif

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
scsa1394_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance = ddi_get_instance(dip);
	scsa1394_state_t *sp;

	if ((sp = SCSA1394_INST2STATE(instance)) == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		/* Cycle power state to off and idle  where done/gone */
		(void) pm_lower_power(dip, 0, PM_LEVEL_D3);

		scsa1394_cleanup(sp, SCSA1394_CLEANUP_LEVEL_MAX);
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (scsa1394_cpr_suspend(dip));
	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
scsa1394_power(dev_info_t *dip, int comp, int level)
{
	return (DDI_SUCCESS);
}

/*
 * scsa1394_cpr_suspend
 *	determine if the device's state can be changed to SUSPENDED
 */
/* ARGSUSED */
static int
scsa1394_cpr_suspend(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	scsa1394_state_t *sp;
	int		rval = DDI_FAILURE;

	sp = SCSA1394_INST2STATE(instance);

	ASSERT(sp != NULL);


	mutex_enter(&sp->s_mutex);
	switch (sp->s_dev_state) {
	case SCSA1394_DEV_ONLINE:
	case SCSA1394_DEV_PWRED_DOWN:
	case SCSA1394_DEV_DISCONNECTED:
		sp->s_dev_state = SCSA1394_DEV_SUSPENDED;

		/*  Power down and make device idle */
		(void) pm_lower_power(dip, 0, PM_LEVEL_D3);

		rval = DDI_SUCCESS;
		break;
	case SCSA1394_DEV_SUSPENDED:
	default:
		if (scsa1394_bus_config_debug)
			cmn_err(CE_WARN,
			    "scsa1304_cpr_suspend: Illegal dev state: %d",
			    sp->s_dev_state);

		rval = DDI_SUCCESS;
		break;
	}
	mutex_exit(&sp->s_mutex);

	return (rval);
}

/*
 * scsa2usb_cpr_resume:
 *	restore device's state
 */
static void
scsa1394_cpr_resume(dev_info_t *dip)
{
	int		instance = ddi_get_instance(dip);
	scsa1394_state_t *sp;
	int		i;
	scsa1394_lun_t	*lp;

	sp = SCSA1394_INST2STATE(instance);

	ASSERT(sp != NULL);

	if (sp->s_dev_state != SCSA1394_DEV_SUSPENDED)
		return;

	/*
	 * Go through each lun and reset it to force a reconnect.
	 */
	for (i = 0; i < sp->s_nluns; i++) {
		lp = &sp->s_lun[i];
		if (lp->l_ses != NULL) {  /* Are we loged in? */
			scsa1394_sbp2_req_bus_reset(lp);
			scsa1394_sbp2_req_reconnect(lp);
		}
	}

	/* we are down so let the power get managed */
	(void) pm_idle_component(dip, 0);
}



/*
 *
 * --- configuration routines
 *
 */
static void
scsa1394_cleanup(scsa1394_state_t *sp, int level)
{
	ASSERT((level > 0) && (level <= SCSA1394_CLEANUP_LEVEL_MAX));

	switch (level) {
	default:
		scsa1394_remove_events(sp);
		/* FALLTHRU */
	case 6:
		scsa1394_detach_scsa(sp);
		/* FALLTHRU */
	case 5:
		scsa1394_destroy_cmd_cache(sp);
		/* FALLTHRU */
	case 4:
		scsa1394_detach_threads(sp);
		/* FALLTHRU */
	case 3:
		scsa1394_sbp2_detach(sp);
		/* FALLTHRU */
	case 2:
		scsa1394_detach_1394(sp);
		/* FALLTHRU */
	case 1:
		cv_destroy(&sp->s_event_cv);
		mutex_destroy(&sp->s_mutex);
		ddi_soft_state_free(scsa1394_statep, sp->s_instance);
	}
}

static int
scsa1394_attach_1394(scsa1394_state_t *sp)
{
	int	ret;

	if ((ret = t1394_attach(sp->s_dip, T1394_VERSION_V1, 0,
	    &sp->s_attachinfo, &sp->s_t1394_hdl)) != DDI_SUCCESS) {
		return (ret);
	}

	/* DMA attributes for data buffers */
	sp->s_buf_dma_attr = sp->s_attachinfo.dma_attr;

	/* DMA attributes for page tables */
	sp->s_pt_dma_attr = sp->s_attachinfo.dma_attr;
	sp->s_pt_dma_attr.dma_attr_sgllen = 1;	/* pt must be contiguous */

	if ((ret = t1394_get_targetinfo(sp->s_t1394_hdl, SCSA1394_BUSGEN(sp), 0,
	    &sp->s_targetinfo)) != DDI_SUCCESS) {
		(void) t1394_detach(&sp->s_t1394_hdl, 0);
		return (ret);
	}

	return (DDI_SUCCESS);
}

static void
scsa1394_detach_1394(scsa1394_state_t *sp)
{
	(void) t1394_detach(&sp->s_t1394_hdl, 0);
}

static int
scsa1394_attach_threads(scsa1394_state_t *sp)
{
	char		name[16];
	int		nthr;

	nthr = sp->s_nluns;
	(void) snprintf(name, sizeof (name), "scsa1394%d", sp->s_instance);
	if ((sp->s_taskq = ddi_taskq_create(sp->s_dip, name, nthr,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		return (DDI_FAILURE);
	}

	if (scsa1394_sbp2_threads_init(sp) != DDI_SUCCESS) {
		ddi_taskq_destroy(sp->s_taskq);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
scsa1394_detach_threads(scsa1394_state_t *sp)
{
	scsa1394_sbp2_threads_fini(sp);
	ddi_taskq_destroy(sp->s_taskq);
}

static int
scsa1394_attach_scsa(scsa1394_state_t *sp)
{
	scsi_hba_tran_t	*tran;
	int		ret;

	sp->s_tran = tran = scsi_hba_tran_alloc(sp->s_dip, SCSI_HBA_CANSLEEP);

	tran->tran_hba_private	= sp;
	tran->tran_tgt_private	= NULL;
	tran->tran_tgt_init	= scsa1394_scsi_tgt_init;
	tran->tran_tgt_probe	= scsa1394_scsi_tgt_probe;
	tran->tran_tgt_free	= scsa1394_scsi_tgt_free;
	tran->tran_start	= scsa1394_scsi_start;
	tran->tran_abort	= scsa1394_scsi_abort;
	tran->tran_reset	= scsa1394_scsi_reset;
	tran->tran_getcap	= scsa1394_scsi_getcap;
	tran->tran_setcap	= scsa1394_scsi_setcap;
	tran->tran_init_pkt	= scsa1394_scsi_init_pkt;
	tran->tran_destroy_pkt	= scsa1394_scsi_destroy_pkt;
	tran->tran_dmafree	= scsa1394_scsi_dmafree;
	tran->tran_sync_pkt	= scsa1394_scsi_sync_pkt;
	tran->tran_reset_notify	= NULL;
	tran->tran_get_bus_addr	= NULL;
	tran->tran_get_name	= NULL;
	tran->tran_bus_reset	= NULL;
	tran->tran_quiesce	= NULL;
	tran->tran_unquiesce	= NULL;
	tran->tran_get_eventcookie = NULL;
	tran->tran_add_eventcall = NULL;
	tran->tran_remove_eventcall = NULL;
	tran->tran_post_event	= NULL;
	tran->tran_bus_config	= scsa1394_scsi_bus_config;
	tran->tran_bus_unconfig	= scsa1394_scsi_bus_unconfig;

	if ((ret = scsi_hba_attach_setup(sp->s_dip, &sp->s_attachinfo.dma_attr,
	    tran, 0)) != DDI_SUCCESS) {
		scsi_hba_tran_free(tran);
		return (ret);
	}

	return (DDI_SUCCESS);
}

static void
scsa1394_detach_scsa(scsa1394_state_t *sp)
{
	int	ret;

	ret = scsi_hba_detach(sp->s_dip);
	ASSERT(ret == DDI_SUCCESS);

	scsi_hba_tran_free(sp->s_tran);
}

static int
scsa1394_create_cmd_cache(scsa1394_state_t *sp)
{
	char	name[64];

	(void) sprintf(name, "scsa1394%d_cache", sp->s_instance);
	sp->s_cmd_cache = kmem_cache_create(name,
	    SCSA1394_CMD_SIZE, sizeof (void *),
	    scsa1394_cmd_cache_constructor, scsa1394_cmd_cache_destructor,
	    NULL, (void *)sp, NULL, 0);

	return ((sp->s_cmd_cache == NULL) ? DDI_FAILURE : DDI_SUCCESS);
}

static void
scsa1394_destroy_cmd_cache(scsa1394_state_t *sp)
{
	kmem_cache_destroy(sp->s_cmd_cache);
}

static int
scsa1394_add_events(scsa1394_state_t *sp)
{
	ddi_eventcookie_t	br_evc, rem_evc, ins_evc;

	if (ddi_get_eventcookie(sp->s_dip, DDI_DEVI_BUS_RESET_EVENT,
	    &br_evc) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (ddi_add_event_handler(sp->s_dip, br_evc, scsa1394_bus_reset,
	    sp, &sp->s_reset_cb_id) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (ddi_get_eventcookie(sp->s_dip, DDI_DEVI_REMOVE_EVENT,
	    &rem_evc) != DDI_SUCCESS) {
		(void) ddi_remove_event_handler(sp->s_reset_cb_id);
		return (DDI_FAILURE);
	}
	if (ddi_add_event_handler(sp->s_dip, rem_evc, scsa1394_disconnect,
	    sp, &sp->s_remove_cb_id) != DDI_SUCCESS) {
		(void) ddi_remove_event_handler(sp->s_reset_cb_id);
		return (DDI_FAILURE);
	}

	if (ddi_get_eventcookie(sp->s_dip, DDI_DEVI_INSERT_EVENT,
	    &ins_evc) != DDI_SUCCESS) {
		(void) ddi_remove_event_handler(sp->s_remove_cb_id);
		(void) ddi_remove_event_handler(sp->s_reset_cb_id);
		return (DDI_FAILURE);
	}
	if (ddi_add_event_handler(sp->s_dip, ins_evc, scsa1394_reconnect,
	    sp, &sp->s_insert_cb_id) != DDI_SUCCESS) {
		(void) ddi_remove_event_handler(sp->s_remove_cb_id);
		(void) ddi_remove_event_handler(sp->s_reset_cb_id);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
scsa1394_remove_events(scsa1394_state_t *sp)
{
	ddi_eventcookie_t	evc;

	if (ddi_get_eventcookie(sp->s_dip, DDI_DEVI_INSERT_EVENT,
	    &evc) == DDI_SUCCESS) {
		(void) ddi_remove_event_handler(sp->s_insert_cb_id);
	}

	if (ddi_get_eventcookie(sp->s_dip, DDI_DEVI_REMOVE_EVENT,
	    &evc) == DDI_SUCCESS) {
		(void) ddi_remove_event_handler(sp->s_remove_cb_id);
	}

	if (ddi_get_eventcookie(sp->s_dip, DDI_DEVI_BUS_RESET_EVENT,
	    &evc) == DDI_SUCCESS) {
		(void) ddi_remove_event_handler(sp->s_reset_cb_id);
	}
}

/*
 *
 * --- device configuration
 *
 */
static int
scsa1394_scsi_bus_config(dev_info_t *dip, uint_t flag, ddi_bus_config_op_t op,
    void *arg, dev_info_t **child)
{
	scsa1394_state_t *sp = SCSA1394_INST2STATE(ddi_get_instance(dip));
	int		circ;
	int		ret;

	if (scsa1394_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	ndi_devi_enter(dip, &circ);
	if (DEVI(dip)->devi_child == NULL) {
		scsa1394_create_children(sp);
	}
	ret = ndi_busop_bus_config(dip, flag, op, arg, child, 0);
	ndi_devi_exit(dip, circ);

	return (ret);
}

static int
scsa1394_scsi_bus_unconfig(dev_info_t *dip, uint_t flag, ddi_bus_config_op_t op,
    void *arg)
{
	scsa1394_state_t *sp = SCSA1394_INST2STATE(ddi_get_instance(dip));
	int		circ;
	int		ret;
	uint_t		saved_flag = flag;

	if (scsa1394_bus_config_debug) {
		flag |= NDI_DEVI_DEBUG;
	}

	/*
	 * First offline and if offlining successful, then remove children.
	 */
	if (op == BUS_UNCONFIG_ALL) {
		flag &= ~(NDI_DEVI_REMOVE | NDI_UNCONFIG);
	}

	ndi_devi_enter(dip, &circ);

	ret = ndi_busop_bus_unconfig(dip, flag, op, arg);

	/*
	 * If previous step was successful and not part of modunload daemon,
	 * attempt to remove children.
	 */
	if ((op == BUS_UNCONFIG_ALL) && (ret == NDI_SUCCESS) &&
	    ((flag & NDI_AUTODETACH) == 0)) {
		flag |= NDI_DEVI_REMOVE;
		ret = ndi_busop_bus_unconfig(dip, flag, op, arg);
	}
	ndi_devi_exit(dip, circ);

	if ((ret != NDI_SUCCESS) && (op == BUS_UNCONFIG_ALL) &&
	    ((saved_flag & NDI_DEVI_REMOVE) != 0)) {
		mutex_enter(&sp->s_mutex);
		if (!sp->s_disconnect_warned) {
			cmn_err(CE_WARN, "scsa1394(%d): "
			    "Disconnected device was busy, please reconnect.\n",
			    sp->s_instance);
			sp->s_disconnect_warned = B_TRUE;
		}
		mutex_exit(&sp->s_mutex);
	}

	return (ret);
}

void
scsa1394_dtype2name(int dtype, char **node_name, char **driver_name)
{
	static struct {
		char	*node_name;
		char	*driver_name;
	} dtype2name[] = {
		{ "disk",	"sd" },		/* DTYPE_DIRECT		0x00 */
		{ "tape",	"st" },		/* DTYPE_SEQUENTIAL	0x01 */
		{ "printer",	NULL },		/* DTYPE_PRINTER	0x02 */
		{ "processor",	NULL },		/* DTYPE_PROCESSOR	0x03 */
		{ "worm",	NULL },		/* DTYPE_WORM		0x04 */
		{ "disk",	"sd" },		/* DTYPE_RODIRECT	0x05 */
		{ "scanner",	NULL },		/* DTYPE_SCANNER	0x06 */
		{ "disk",	"sd" },		/* DTYPE_OPTICAL	0x07 */
		{ "changer",	NULL },		/* DTYPE_CHANGER	0x08 */
		{ "comm",	NULL },		/* DTYPE_COMM		0x09 */
		{ "generic",	NULL },		/* DTYPE_???		0x0A */
		{ "generic",	NULL },		/* DTYPE_???		0x0B */
		{ "array_ctrl",	NULL },		/* DTYPE_ARRAY_CTRL	0x0C */
		{ "esi",	"ses" },	/* DTYPE_ESI		0x0D */
		{ "disk",	"sd" }		/* DTYPE_RBC		0x0E */
	};

	if (dtype < NELEM(dtype2name)) {
		*node_name = dtype2name[dtype].node_name;
		*driver_name = dtype2name[dtype].driver_name;
	} else {
		*node_name = "generic";
		*driver_name = NULL;
	}
}

static void
scsa1394_create_children(scsa1394_state_t *sp)
{
	char		name[SCSA1394_COMPAT_MAX][16];
	char		*compatible[SCSA1394_COMPAT_MAX];
	dev_info_t	*cdip;
	int		i;
	int		dtype;
	char		*node_name;
	char		*driver_name;
	int		ret;

	bzero(name, sizeof (name));
	(void) strcpy(name[0], "sd");
	for (i = 0; i < SCSA1394_COMPAT_MAX; i++) {
		compatible[i] = name[i];
	}

	for (i = 0; i < sp->s_nluns; i++) {
		dtype = scsa1394_sbp2_get_lun_type(&sp->s_lun[i]);
		scsa1394_dtype2name(dtype, &node_name, &driver_name);

		ndi_devi_alloc_sleep(sp->s_dip, node_name,
		    (pnode_t)DEVI_SID_NODEID, &cdip);

		ret = ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
		    SCSI_ADDR_PROP_TARGET, 0);
		if (ret != DDI_PROP_SUCCESS) {
			(void) ndi_devi_free(cdip);
			continue;
		}

		ret = ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
		    SCSI_ADDR_PROP_LUN, i);
		if (ret != DDI_PROP_SUCCESS) {
			ddi_prop_remove_all(cdip);
			(void) ndi_devi_free(cdip);
			continue;
		}

		/*
		 * Some devices don't support LOG SENSE, so tell
		 * sd driver not to send this command.
		 */
		ret = ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
		    "pm-capable", 1);
		if (ret != DDI_PROP_SUCCESS) {
			ddi_prop_remove_all(cdip);
			(void) ndi_devi_free(cdip);
			continue;
		}

		ret = ndi_prop_create_boolean(DDI_DEV_T_NONE, cdip,
		    "hotpluggable");
		if (ret != DDI_PROP_SUCCESS) {
			ddi_prop_remove_all(cdip);
			(void) ndi_devi_free(cdip);
			continue;
		}

		if (driver_name) {
			compatible[0] = driver_name;
			ret = ndi_prop_update_string_array(DDI_DEV_T_NONE, cdip,
			    "compatible", (char **)compatible,
			    SCSA1394_COMPAT_MAX);
			if (ret != DDI_PROP_SUCCESS) {
				ddi_prop_remove_all(cdip);
				(void) ndi_devi_free(cdip);
				continue;
			}
		}

		/*
		 * add property "scsa1394" to distinguish from others' children
		 */
		ret = ndi_prop_create_boolean(DDI_DEV_T_NONE, cdip, "scsa1394");
		if (ret != DDI_PROP_SUCCESS) {
			ddi_prop_remove_all(cdip);
			(void) ndi_devi_free(cdip);
			continue;
		}

		(void) ddi_initchild(sp->s_dip, cdip);
	}
}

/*ARGSUSED*/
static void
scsa1394_bus_reset(dev_info_t *dip, ddi_eventcookie_t evc, void *arg,
    void *data)
{
	scsa1394_state_t	*sp = arg;

	if (sp != NULL) {
		mutex_enter(&sp->s_mutex);
		if (sp->s_dev_state == SCSA1394_DEV_DISCONNECTED) {
			mutex_exit(&sp->s_mutex);
			return;
		}
		sp->s_stat.stat_bus_reset_cnt++;
		sp->s_dev_state = SCSA1394_DEV_BUS_RESET;
		sp->s_attachinfo.localinfo = *(t1394_localinfo_t *)data;
		mutex_exit(&sp->s_mutex);

		scsa1394_sbp2_req(sp, 0, SCSA1394_THREQ_BUS_RESET);
	}
}

/*ARGSUSED*/
static void
scsa1394_disconnect(dev_info_t *dip, ddi_eventcookie_t evc, void *arg,
    void *data)
{
	scsa1394_state_t	*sp = arg;
	int			circ;
	dev_info_t		*cdip, *cdip_next;

	if (sp == NULL) {
		return;
	}

	mutex_enter(&sp->s_mutex);
	sp->s_stat.stat_disconnect_cnt++;
	sp->s_dev_state = SCSA1394_DEV_DISCONNECTED;
	mutex_exit(&sp->s_mutex);

	scsa1394_sbp2_disconnect(sp);

	ndi_devi_enter(dip, &circ);
	for (cdip = ddi_get_child(dip); cdip != NULL; cdip = cdip_next) {
		cdip_next = ddi_get_next_sibling(cdip);

		mutex_enter(&DEVI(cdip)->devi_lock);
		DEVI_SET_DEVICE_REMOVED(cdip);
		mutex_exit(&DEVI(cdip)->devi_lock);
	}
	ndi_devi_exit(dip, circ);
}

/*ARGSUSED*/
static void
scsa1394_reconnect(dev_info_t *dip, ddi_eventcookie_t evc, void *arg,
    void *data)
{
	scsa1394_state_t	*sp = arg;
	int			circ;
	dev_info_t		*cdip, *cdip_next;

	if (sp == NULL) {
		return;
	}

	mutex_enter(&sp->s_mutex);
	sp->s_stat.stat_reconnect_cnt++;
	sp->s_attachinfo.localinfo = *(t1394_localinfo_t *)data;
	sp->s_disconnect_warned = B_FALSE;
	mutex_exit(&sp->s_mutex);

	ndi_devi_enter(dip, &circ);
	for (cdip = ddi_get_child(dip); cdip != NULL; cdip = cdip_next) {
		cdip_next = ddi_get_next_sibling(cdip);

		mutex_enter(&DEVI(cdip)->devi_lock);
		DEVI_SET_DEVICE_REINSERTED(cdip);
		mutex_exit(&DEVI(cdip)->devi_lock);
	}
	ndi_devi_exit(dip, circ);

	scsa1394_sbp2_req(sp, 0, SCSA1394_THREQ_RECONNECT);
}

/*
 *
 * --- SCSA entry points
 *
 */
/*ARGSUSED*/
static int
scsa1394_scsi_tgt_init(dev_info_t *dip, dev_info_t *cdip, scsi_hba_tran_t *tran,
    struct scsi_device *sd)
{
	scsa1394_state_t *sp = (scsa1394_state_t *)tran->tran_hba_private;
	int		lun;
	int		plen = sizeof (int);
	int		ret = DDI_FAILURE;

	if (ddi_prop_op(DDI_DEV_T_ANY, cdip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, SCSI_ADDR_PROP_LUN,
	    (caddr_t)&lun, &plen) != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (!scsa1394_is_my_child(cdip)) {
		/*
		 * add property "scsa1394" to distinguish from others' children
		 */
		ret = ndi_prop_create_boolean(DDI_DEV_T_NONE, cdip, "scsa1394");
		if (ret != DDI_PROP_SUCCESS) {
			return (DDI_FAILURE);
		}

		if (scsa1394_dev_is_online(sp)) {
			return (scsa1394_sbp2_login(sp, lun));
		} else {
			return (DDI_FAILURE);
		}
	}

	if ((lun >= sp->s_nluns) || (sp->s_lun[lun].l_cdip != NULL) ||
	    !scsa1394_dev_is_online(sp)) {
		return (DDI_FAILURE);
	}

	if ((ret = scsa1394_sbp2_login(sp, lun)) == DDI_SUCCESS) {
		sp->s_lun[lun].l_cdip = cdip;
	}
	return (ret);
}

/*ARGSUSED*/
static void
scsa1394_scsi_tgt_free(dev_info_t *dip, dev_info_t *cdip, scsi_hba_tran_t *tran,
    struct scsi_device *sd)
{
	scsa1394_state_t *sp = (scsa1394_state_t *)tran->tran_hba_private;
	int		lun;
	int		plen = sizeof (int);

	if (!scsa1394_is_my_child(cdip)) {
		return;
	}

	if (ddi_prop_op(DDI_DEV_T_ANY, cdip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP, SCSI_ADDR_PROP_LUN,
	    (caddr_t)&lun, &plen) != DDI_PROP_SUCCESS) {
		return;
	}

	if ((lun < sp->s_nluns) && (sp->s_lun[lun].l_cdip == cdip)) {
		if (scsa1394_dev_is_online(sp)) {
			scsa1394_sbp2_logout(sp, lun, B_TRUE);
		}
		sp->s_lun[lun].l_cdip = NULL;
	}
}

static int
scsa1394_scsi_tgt_probe(struct scsi_device *sd, int (*waitfunc)())
{
	dev_info_t	*dip = ddi_get_parent(sd->sd_dev);
	scsi_hba_tran_t	*tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
	scsa1394_state_t *sp = (scsa1394_state_t *)tran->tran_hba_private;
	scsa1394_lun_t	*lp;

	if (!scsa1394_dev_is_online(sp)) {
		return (SCSIPROBE_FAILURE);
	}
	lp = &sp->s_lun[sd->sd_address.a_lun];

	if (scsa1394_probe_g0_nodata(sd, waitfunc,
	    SCMD_TEST_UNIT_READY, 0, 0) != SCSIPROBE_EXISTS) {
		lp->l_nosup_tur = B_TRUE;
		(void) scsa1394_sbp2_reset(lp, RESET_LUN, NULL);
	}
	if (scsa1394_probe_g0_nodata(sd, waitfunc,
	    SCMD_START_STOP, 0, 1) != SCSIPROBE_EXISTS) {
		lp->l_nosup_start_stop = B_TRUE;
	}

	/* standard probe issues INQUIRY, which some devices may not support */
	if (scsi_hba_probe(sd, waitfunc) != SCSIPROBE_EXISTS) {
		lp->l_nosup_inquiry = B_TRUE;
		scsa1394_sbp2_fake_inquiry(sp, &lp->l_fake_inq);
		bcopy(&lp->l_fake_inq, sd->sd_inq, SUN_INQSIZE);
#ifndef __lock_lint
		lp->l_rmb_orig = 1;
#endif
	}

	if (scsa1394_wrka_fake_rmb) {
		sd->sd_inq->inq_rmb = 1;
	}

	return (SCSIPROBE_EXISTS);
}

static int
scsa1394_probe_g0_nodata(struct scsi_device *sd, int (*waitfunc)(),
    uchar_t cmd, uint_t addr, uint_t cnt)
{
	struct scsi_pkt	*pkt;
	int		ret = SCSIPROBE_EXISTS;

	pkt = scsi_init_pkt(&sd->sd_address, NULL, NULL, CDB_GROUP0,
	    sizeof (struct scsi_arq_status), 0, PKT_CONSISTENT, waitfunc, NULL);

	if (pkt == NULL) {
		return (SCSIPROBE_NOMEM);
	}

	(void) scsi_setup_cdb((union scsi_cdb *)pkt->pkt_cdbp, cmd, addr, cnt,
	    0);
	((union scsi_cdb *)(pkt)->pkt_cdbp)->scc_lun = sd->sd_address.a_lun;
	pkt->pkt_flags = FLAG_NOINTR;

	if (scsa1394_probe_tran(pkt) < 0) {
		if (pkt->pkt_reason == CMD_INCOMPLETE) {
			ret = SCSIPROBE_NORESP;
		} else if ((pkt->pkt_reason == CMD_TRAN_ERR) &&
		    ((*(pkt->pkt_scbp) & STATUS_MASK) == STATUS_CHECK) &&
		    (pkt->pkt_state & STATE_ARQ_DONE)) {
			ret = SCSIPROBE_EXISTS;
		} else {
			ret = SCSIPROBE_FAILURE;
		}
	}

	scsi_destroy_pkt(pkt);

	return (ret);
}

static int
scsa1394_probe_tran(struct scsi_pkt *pkt)
{
	pkt->pkt_time = SCSA1394_PROBE_TIMEOUT;

	if (scsi_transport(pkt) != TRAN_ACCEPT) {
		return (-1);
	} else if ((pkt->pkt_reason == CMD_INCOMPLETE) &&
	    (pkt->pkt_state == 0)) {
		return (-1);
	} else if (pkt->pkt_reason != CMD_CMPLT) {
		return (-1);
	} else if (((*pkt->pkt_scbp) & STATUS_MASK) == STATUS_BUSY) {
		return (0);
	}
	return (0);
}

/*ARGSUSED*/
static int
scsa1394_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	return (0);
}

static int
scsa1394_scsi_reset(struct scsi_address *ap, int level)
{
	scsa1394_state_t *sp = ADDR2STATE(ap);
	scsa1394_lun_t	*lp;
	int		ret;

	switch (level) {
	case RESET_ALL:
	case RESET_TARGET:
		lp = &sp->s_lun[0];
		break;
	case RESET_LUN:
		lp = &sp->s_lun[ap->a_lun];
		break;
	default:
		return (DDI_FAILURE);
	}

	ret = scsa1394_sbp2_reset(lp, level, NULL);

	return ((ret == SBP2_SUCCESS) ? 1 : 0);
}

/*ARGSUSED*/
static int
scsa1394_scsi_getcap(struct scsi_address *ap, char *cap, int whom)
{
	scsa1394_state_t *sp = ADDR2STATE(ap);
	size_t		dev_bsize_cap;
	int		ret = -1;

	if (!scsa1394_dev_is_online(sp)) {
		return (-1);
	}

	if (cap == NULL) {
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_DMA_MAX:
		ret = sp->s_attachinfo.dma_attr.dma_attr_maxxfer;
		break;
	case SCSI_CAP_SCSI_VERSION:
		ret = SCSI_VERSION_2;
		break;
	case SCSI_CAP_ARQ:
		ret = 1;
		break;
	case SCSI_CAP_UNTAGGED_QING:
		ret = 1;
		break;
	case SCSI_CAP_GEOMETRY:
		dev_bsize_cap = sp->s_totalsec;

		if (sp->s_secsz > DEV_BSIZE) {
			dev_bsize_cap *= sp->s_secsz / DEV_BSIZE;
		} else if (sp->s_secsz < DEV_BSIZE) {
			dev_bsize_cap /= DEV_BSIZE / sp->s_secsz;
		}

		if (dev_bsize_cap < 65536 * 2 * 18) {		/* < ~1GB */
			/* unlabeled floppy, 18k per cylinder */
			ret = ((2 << 16) | 18);
		} else if (dev_bsize_cap < 65536 * 64 * 32) {	/* < 64GB */
			/* 1024k per cylinder */
			ret = ((64 << 16) | 32);
		} else if (dev_bsize_cap < 65536 * 255 * 63) {	/* < ~500GB */
			/* ~8m per cylinder */
			ret = ((255 << 16) | 63);
		} else {					/* .. 8TB */
			/* 64m per cylinder */
			ret = ((512 << 16) | 256);
		}
		break;
	default:
		break;
	}

	return (ret);
}

/*ARGSUSED*/
static int
scsa1394_scsi_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	scsa1394_state_t *sp = ADDR2STATE(ap);
	int		ret = -1;

	if (!scsa1394_dev_is_online(sp)) {
		return (-1);
	}

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_ARQ:
		ret = 1;
		break;
	case SCSI_CAP_DMA_MAX:
	case SCSI_CAP_SCSI_VERSION:
	case SCSI_CAP_UNTAGGED_QING:
		/* supported but not settable */
		ret = 0;
		break;
	case SCSI_CAP_SECTOR_SIZE:
		if (value) {
			sp->s_secsz = value;
		}
		break;
	case SCSI_CAP_TOTAL_SECTORS:
		if (value) {
			sp->s_totalsec = value;
		}
		break;
	default:
		break;
	}

	return (ret);
}

/*ARGSUSED*/
static void
scsa1394_scsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	scsa1394_cmd_t	*cmd = PKT2CMD(pkt);

	if (cmd->sc_flags & SCSA1394_CMD_DMA_BUF_VALID) {
		(void) ddi_dma_sync(cmd->sc_buf_dma_hdl, 0, 0,
		    (cmd->sc_flags & SCSA1394_CMD_READ) ?
		    DDI_DMA_SYNC_FORCPU : DDI_DMA_SYNC_FORDEV);
	}
}

/*
 *
 * --- pkt resource allocation routines
 *
 */
static struct scsi_pkt *
scsa1394_scsi_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
    struct buf *bp, int cmdlen, int statuslen, int tgtlen, int flags,
    int (*callback)(), caddr_t arg)
{
	scsa1394_state_t *sp = ADDR2STATE(ap);
	scsa1394_lun_t	*lp;
	scsa1394_cmd_t	*cmd;
	boolean_t	is_new;	/* new cmd is being allocated */
	int		kf = (callback == SLEEP_FUNC) ? KM_SLEEP : KM_NOSLEEP;

	if (ap->a_lun >= sp->s_nluns) {
		return (NULL);
	}
	lp = &sp->s_lun[ap->a_lun];

	/*
	 * allocate cmd space
	 */
	if (pkt == NULL) {
		is_new = B_TRUE;
		if ((cmd = kmem_cache_alloc(sp->s_cmd_cache, kf)) == NULL) {
			return (NULL);
		}

		/* initialize cmd */
		pkt = &cmd->sc_scsi_pkt;
		pkt->pkt_ha_private	= cmd;
		pkt->pkt_address	= *ap;
		pkt->pkt_private	= cmd->sc_priv;
		pkt->pkt_scbp		= (uchar_t *)&cmd->sc_scb;
		pkt->pkt_cdbp		= (uchar_t *)&cmd->sc_pkt_cdb;
		pkt->pkt_resid		= 0;

		cmd->sc_lun		= lp;
		cmd->sc_pkt		= pkt;
		cmd->sc_cdb_len		= cmdlen;
		cmd->sc_scb_len		= statuslen;
		cmd->sc_priv_len	= tgtlen;

		/* need external space? */
		if ((cmdlen > sizeof (cmd->sc_pkt_cdb)) ||
		    (statuslen > sizeof (cmd->sc_scb)) ||
		    (tgtlen > sizeof (cmd->sc_priv))) {
			if (scsa1394_cmd_ext_alloc(sp, cmd, kf) !=
			    DDI_SUCCESS) {
				kmem_cache_free(sp->s_cmd_cache, cmd);
				lp->l_stat.stat_err_pkt_kmem_alloc++;
				return (NULL);
			}
		}

		/* allocate DMA resources for CDB */
		if (scsa1394_cmd_cdb_dma_alloc(sp, cmd, flags, callback, arg) !=
		    DDI_SUCCESS) {
			scsa1394_scsi_destroy_pkt(ap, pkt);
			return (NULL);
		}
	} else {
		is_new = B_FALSE;
		cmd = PKT2CMD(pkt);
	}

	cmd->sc_flags &= ~SCSA1394_CMD_RDWR;

	/* allocate/move DMA resources for data buffer */
	if ((bp != NULL) && (bp->b_bcount > 0)) {
		if ((cmd->sc_flags & SCSA1394_CMD_DMA_BUF_VALID) == 0) {
			if (scsa1394_cmd_buf_dma_alloc(sp, cmd, flags, callback,
			    arg, bp) != DDI_SUCCESS) {
				if (is_new) {
					scsa1394_scsi_destroy_pkt(ap, pkt);
				}
				return (NULL);
			}
		} else {
			if (scsa1394_cmd_buf_dma_move(sp, cmd) != DDI_SUCCESS) {
				return (NULL);
			}
		}

		ASSERT(cmd->sc_win_len > 0);
		pkt->pkt_resid = bp->b_bcount - cmd->sc_win_len;
	}

	/*
	 * kernel virtual address may be required for certain workarounds
	 * and in case of B_PHYS or B_PAGEIO, bp_mapin() will get it for us
	 */
	if ((bp != NULL) && ((bp->b_flags & (B_PAGEIO | B_PHYS)) != 0) &&
	    (bp->b_bcount < SCSA1394_MAPIN_SIZE_MAX) &&
	    ((cmd->sc_flags & SCSA1394_CMD_DMA_BUF_MAPIN) == 0)) {
		bp_mapin(bp);
		cmd->sc_flags |= SCSA1394_CMD_DMA_BUF_MAPIN;
	}

	return (pkt);
}

static void
scsa1394_scsi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	scsa1394_state_t *sp = ADDR2STATE(ap);
	scsa1394_cmd_t	*cmd = PKT2CMD(pkt);

	if (cmd->sc_flags & SCSA1394_CMD_DMA_BUF_VALID) {
		scsa1394_cmd_buf_dma_free(sp, cmd);
	}
	if (cmd->sc_flags & SCSA1394_CMD_DMA_CDB_VALID) {
		scsa1394_cmd_cdb_dma_free(sp, cmd);
	}
	if (cmd->sc_flags & SCSA1394_CMD_DMA_BUF_MAPIN) {
		bp_mapout(cmd->sc_bp);
		cmd->sc_flags &= ~SCSA1394_CMD_DMA_BUF_MAPIN;
	}
	if (cmd->sc_flags & SCSA1394_CMD_EXT) {
		scsa1394_cmd_ext_free(sp, cmd);
	}

	kmem_cache_free(sp->s_cmd_cache, cmd);
}

static void
scsa1394_scsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	scsa1394_state_t *sp = ADDR2STATE(ap);
	scsa1394_cmd_t	*cmd = PKT2CMD(pkt);

	if (cmd->sc_flags & SCSA1394_CMD_DMA_BUF_VALID) {
		scsa1394_cmd_buf_dma_free(sp, cmd);
	}
	if (cmd->sc_flags & SCSA1394_CMD_DMA_BUF_MAPIN) {
		bp_mapout(cmd->sc_bp);
		cmd->sc_flags &= ~SCSA1394_CMD_DMA_BUF_MAPIN;
	}
}

/*ARGSUSED*/
static int
scsa1394_cmd_cache_constructor(void *buf, void *cdrarg, int kf)
{
	scsa1394_cmd_t	*cmd = buf;

	bzero(buf, SCSA1394_CMD_SIZE);
	cmd->sc_task.ts_drv_priv = cmd;

	return (0);
}

/*ARGSUSED*/
static void
scsa1394_cmd_cache_destructor(void *buf, void *cdrarg)
{
}

/*
 * allocate and deallocate external cmd space (ie. not part of scsa1394_cmd_t)
 * for non-standard length cdb, pkt_private, status areas
 */
static int
scsa1394_cmd_ext_alloc(scsa1394_state_t *sp, scsa1394_cmd_t *cmd, int kf)
{
	struct scsi_pkt	*pkt = cmd->sc_pkt;
	void		*buf;

	if (cmd->sc_cdb_len > sizeof (cmd->sc_pkt_cdb)) {
		if ((buf = kmem_zalloc(cmd->sc_cdb_len, kf)) == NULL) {
			return (DDI_FAILURE);
		}
		pkt->pkt_cdbp = buf;
		cmd->sc_flags |= SCSA1394_CMD_CDB_EXT;
	}

	if (cmd->sc_scb_len > sizeof (cmd->sc_scb)) {
		if ((buf = kmem_zalloc(cmd->sc_scb_len, kf)) == NULL) {
			scsa1394_cmd_ext_free(sp, cmd);
			return (DDI_FAILURE);
		}
		pkt->pkt_scbp = buf;
		cmd->sc_flags |= SCSA1394_CMD_SCB_EXT;
	}

	if (cmd->sc_priv_len > sizeof (cmd->sc_priv)) {
		if ((buf = kmem_zalloc(cmd->sc_priv_len, kf)) == NULL) {
			scsa1394_cmd_ext_free(sp, cmd);
			return (DDI_FAILURE);
		}
		pkt->pkt_private = buf;
		cmd->sc_flags |= SCSA1394_CMD_PRIV_EXT;
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static void
scsa1394_cmd_ext_free(scsa1394_state_t *sp, scsa1394_cmd_t *cmd)
{
	struct scsi_pkt	*pkt = cmd->sc_pkt;

	if (cmd->sc_flags & SCSA1394_CMD_CDB_EXT) {
		kmem_free(pkt->pkt_cdbp, cmd->sc_cdb_len);
	}
	if (cmd->sc_flags & SCSA1394_CMD_SCB_EXT) {
		kmem_free(pkt->pkt_scbp, cmd->sc_scb_len);
	}
	if (cmd->sc_flags & SCSA1394_CMD_PRIV_EXT) {
		kmem_free(pkt->pkt_private, cmd->sc_priv_len);
	}
	cmd->sc_flags &= ~SCSA1394_CMD_EXT;
}

/*ARGSUSED*/
static int
scsa1394_cmd_cdb_dma_alloc(scsa1394_state_t *sp, scsa1394_cmd_t *cmd,
    int flags, int (*callback)(), caddr_t arg)
{
	if (sbp2_task_orb_alloc(cmd->sc_lun->l_lun, &cmd->sc_task,
	    sizeof (scsa1394_cmd_orb_t)) != SBP2_SUCCESS) {
		return (DDI_FAILURE);
	}

	cmd->sc_flags |= SCSA1394_CMD_DMA_CDB_VALID;
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static void
scsa1394_cmd_cdb_dma_free(scsa1394_state_t *sp, scsa1394_cmd_t *cmd)
{
	sbp2_task_orb_free(cmd->sc_lun->l_lun, &cmd->sc_task);
	cmd->sc_flags &= ~SCSA1394_CMD_DMA_CDB_VALID;
}

/*
 * buffer resources
 */
static int
scsa1394_cmd_buf_dma_alloc(scsa1394_state_t *sp, scsa1394_cmd_t *cmd,
    int flags, int (*callback)(), caddr_t arg, struct buf *bp)
{
	scsa1394_lun_t	*lp = cmd->sc_lun;
	int		kf = (callback == SLEEP_FUNC) ? KM_SLEEP : KM_NOSLEEP;
	int		dma_flags;
	ddi_dma_cookie_t dmac;
	uint_t		ccount;
	int		error;
	int		ret;

	cmd->sc_bp = bp;

	if ((ddi_dma_alloc_handle(sp->s_dip, &sp->s_buf_dma_attr, callback,
	    NULL, &cmd->sc_buf_dma_hdl)) != DDI_SUCCESS) {
		bioerror(bp, 0);
		return (DDI_FAILURE);
	}

	cmd->sc_flags &= ~SCSA1394_CMD_RDWR;
	if (bp->b_flags & B_READ) {
		dma_flags = DDI_DMA_READ;
		cmd->sc_flags |= SCSA1394_CMD_READ;
	} else {
		dma_flags = DDI_DMA_WRITE;
		cmd->sc_flags |= SCSA1394_CMD_WRITE;
	}
	if (flags & PKT_CONSISTENT) {
		dma_flags |= DDI_DMA_CONSISTENT;
	}
	if (flags & PKT_DMA_PARTIAL) {
		dma_flags |= DDI_DMA_PARTIAL;
	}

	ret = ddi_dma_buf_bind_handle(cmd->sc_buf_dma_hdl, bp, dma_flags,
	    callback, arg, &dmac, &ccount);

	switch (ret) {
	case DDI_DMA_MAPPED:
		cmd->sc_nwin = 1;
		cmd->sc_curwin = 0;
		cmd->sc_win_offset = 0;
		cmd->sc_win_len = bp->b_bcount;
		break;

	case DDI_DMA_PARTIAL_MAP:
		/* retrieve number of windows and first window cookie */
		cmd->sc_curwin = 0;
		if ((ddi_dma_numwin(cmd->sc_buf_dma_hdl, &cmd->sc_nwin) !=
		    DDI_SUCCESS) ||
		    (ddi_dma_getwin(cmd->sc_buf_dma_hdl, cmd->sc_curwin,
		    &cmd->sc_win_offset, &cmd->sc_win_len, &dmac, &ccount) !=
		    DDI_SUCCESS)) {
			(void) ddi_dma_unbind_handle(cmd->sc_buf_dma_hdl);
			ddi_dma_free_handle(&cmd->sc_buf_dma_hdl);
			return (DDI_FAILURE);
		}
		lp->l_stat.stat_cmd_buf_dma_partial++;
		break;

	case DDI_DMA_NORESOURCES:
		error = 0;
		goto map_error;

	case DDI_DMA_BADATTR:
	case DDI_DMA_NOMAPPING:
		error = EFAULT;
		goto map_error;

	default:
		error = EINVAL;

	map_error:
		bioerror(bp, error);
		lp->l_stat.stat_err_cmd_buf_dbind++;
		ddi_dma_free_handle(&cmd->sc_buf_dma_hdl);
		return (DDI_FAILURE);
	}
	cmd->sc_flags |= SCSA1394_CMD_DMA_BUF_BIND_VALID;

	/*
	 * setup page table if needed
	 */
	if ((ccount == 1) && (dmac.dmac_size <= SBP2_PT_SEGSIZE_MAX) &&
	    (!sp->s_symbios ||
	    (dmac.dmac_size <= scsa1394_symbios_page_size))) {
		cmd->sc_buf_nsegs = 1;
		cmd->sc_buf_seg_mem.ss_len = dmac.dmac_size;
		cmd->sc_buf_seg_mem.ss_daddr = dmac.dmac_address;
		cmd->sc_buf_seg = &cmd->sc_buf_seg_mem;
	} else {
		/* break window into segments */
		if (scsa1394_cmd_dmac2seg(sp, cmd, &dmac, ccount, kf) !=
		    DDI_SUCCESS) {
			scsa1394_cmd_buf_dma_free(sp, cmd);
			bioerror(bp, 0);
			return (DDI_FAILURE);
		}

		/* allocate DMA resources for page table */
		if (scsa1394_cmd_pt_dma_alloc(sp, cmd, callback, arg,
		    cmd->sc_buf_nsegs) != DDI_SUCCESS) {
			scsa1394_cmd_buf_dma_free(sp, cmd);
			bioerror(bp, 0);
			return (DDI_FAILURE);
		}
	}

	/* allocate 1394 addresses for segments */
	if (scsa1394_cmd_buf_addr_alloc(sp, cmd) != DDI_SUCCESS) {
		scsa1394_cmd_buf_dma_free(sp, cmd);
		bioerror(bp, 0);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
scsa1394_cmd_buf_dma_free(scsa1394_state_t *sp, scsa1394_cmd_t *cmd)
{
	scsa1394_cmd_buf_addr_free(sp, cmd);
	if (cmd->sc_flags & SCSA1394_CMD_DMA_BUF_PT_VALID) {
		scsa1394_cmd_pt_dma_free(sp, cmd);
	}
	scsa1394_cmd_seg_free(sp, cmd);
	if (cmd->sc_flags & SCSA1394_CMD_DMA_BUF_BIND_VALID) {
		(void) ddi_dma_unbind_handle(cmd->sc_buf_dma_hdl);
		ddi_dma_free_handle(&cmd->sc_buf_dma_hdl);
	}
	cmd->sc_flags &= ~(SCSA1394_CMD_DMA_BUF_VALID | SCSA1394_CMD_RDWR);
}

/*
 * Break a set DMA cookies into segments suitable for SBP-2 page table.
 * This routine can reuse/reallocate segment array from previous calls.
 */
static int
scsa1394_cmd_dmac2seg(scsa1394_state_t *sp, scsa1394_cmd_t *cmd,
    ddi_dma_cookie_t *dmac, uint_t ccount, int kf)
{
	scsa1394_lun_t	*lp = cmd->sc_lun;
	int		i;
	int		nsegs;
	size_t		segsize_max;
	size_t		dmac_resid;
	uint32_t	dmac_addr;
	scsa1394_cmd_seg_t *seg;

	if (!sp->s_symbios) {
		/*
		 * Number of segments is unknown at this point. Start with
		 * a reasonable estimate and grow it later if needed.
		 */
		nsegs = max(ccount, cmd->sc_win_len / SBP2_PT_SEGSIZE_MAX) * 2;
		segsize_max = SBP2_PT_SEGSIZE_MAX;
	} else {
		/*
		 * For Symbios workaround we know exactly the number of segments
		 * Additional segment may be needed if buffer is not aligned.
		 */
		nsegs =
		    howmany(cmd->sc_win_len, scsa1394_symbios_page_size) + 1;
		segsize_max = scsa1394_symbios_page_size;
	}

	if (nsegs > cmd->sc_buf_nsegs_alloc) {
		if ((cmd->sc_buf_seg = scsa1394_kmem_realloc(cmd->sc_buf_seg,
		    cmd->sc_buf_nsegs_alloc, nsegs,
		    sizeof (scsa1394_cmd_seg_t), kf)) == NULL) {
			cmd->sc_buf_nsegs_alloc = 0;
			return (DDI_FAILURE);
		}
		cmd->sc_buf_nsegs_alloc = nsegs;
	}

	/* each cookie maps into one or more segments */
	cmd->sc_buf_nsegs = 0;
	i = ccount;
	for (;;) {
		dmac_resid = dmac->dmac_size;
		dmac_addr = dmac->dmac_address;
		while (dmac_resid > 0) {
			/* grow array if needed */
			if (cmd->sc_buf_nsegs >= cmd->sc_buf_nsegs_alloc) {
				if ((cmd->sc_buf_seg = scsa1394_kmem_realloc(
				    cmd->sc_buf_seg,
				    cmd->sc_buf_nsegs_alloc,
				    cmd->sc_buf_nsegs_alloc + ccount,
				    sizeof (scsa1394_cmd_seg_t), kf)) == NULL) {
					return (DDI_FAILURE);
				}
				cmd->sc_buf_nsegs_alloc += ccount;
			}

			seg = &cmd->sc_buf_seg[cmd->sc_buf_nsegs];
			seg->ss_len = min(dmac_resid, segsize_max);
			seg->ss_daddr = (uint64_t)dmac_addr;
			dmac_addr += seg->ss_len;
			dmac_resid -= seg->ss_len;
			cmd->sc_buf_nsegs++;
		}
		ASSERT(dmac_resid == 0);

		/* grab next cookie */
		if (--i <= 0) {
			break;
		}
		ddi_dma_nextcookie(cmd->sc_buf_dma_hdl, dmac);
	}

	if (cmd->sc_buf_nsegs > lp->l_stat.stat_cmd_buf_max_nsegs) {
		lp->l_stat.stat_cmd_buf_max_nsegs = cmd->sc_buf_nsegs;
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static void
scsa1394_cmd_seg_free(scsa1394_state_t *sp, scsa1394_cmd_t *cmd)
{
	if (cmd->sc_buf_nsegs_alloc > 0) {
		kmem_free(cmd->sc_buf_seg, cmd->sc_buf_nsegs_alloc *
		    sizeof (scsa1394_cmd_seg_t));
	}
	cmd->sc_buf_seg = NULL;
	cmd->sc_buf_nsegs = 0;
	cmd->sc_buf_nsegs_alloc = 0;
}

static int
scsa1394_cmd_pt_dma_alloc(scsa1394_state_t *sp, scsa1394_cmd_t *cmd,
    int (*callback)(), caddr_t arg, int cnt)
{
	scsa1394_lun_t	*lp = cmd->sc_lun;
	size_t		len, rlen;
	uint_t		ccount;
	t1394_alloc_addr_t aa;
	int		result;

	/* allocate DMA memory for page table */
	if ((ddi_dma_alloc_handle(sp->s_dip, &sp->s_pt_dma_attr,
	    callback, NULL, &cmd->sc_pt_dma_hdl)) != DDI_SUCCESS) {
		lp->l_stat.stat_err_cmd_pt_dmem_alloc++;
		return (DDI_FAILURE);
	}

	cmd->sc_pt_ent_alloc = cnt;
	len = cmd->sc_pt_ent_alloc * SBP2_PT_ENT_SIZE;
	if (ddi_dma_mem_alloc(cmd->sc_pt_dma_hdl, len,
	    &sp->s_attachinfo.acc_attr, DDI_DMA_CONSISTENT, callback, arg,
	    &cmd->sc_pt_kaddr, &rlen, &cmd->sc_pt_acc_hdl) != DDI_SUCCESS) {
		ddi_dma_free_handle(&cmd->sc_pt_dma_hdl);
		lp->l_stat.stat_err_cmd_pt_dmem_alloc++;
		return (DDI_FAILURE);
	}

	if (ddi_dma_addr_bind_handle(cmd->sc_pt_dma_hdl, NULL,
	    cmd->sc_pt_kaddr, len, DDI_DMA_READ | DDI_DMA_CONSISTENT,
	    callback, arg, &cmd->sc_pt_dmac, &ccount) != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&cmd->sc_pt_acc_hdl);
		ddi_dma_free_handle(&cmd->sc_pt_dma_hdl);
		lp->l_stat.stat_err_cmd_pt_dmem_alloc++;
		return (DDI_FAILURE);
	}
	ASSERT(ccount == 1);	/* because dma_attr_sgllen is 1 */

	/* allocate 1394 address for page table */
	aa.aa_type = T1394_ADDR_FIXED;
	aa.aa_length = len;
	aa.aa_address = cmd->sc_pt_dmac.dmac_address;
	aa.aa_evts.recv_read_request = NULL;
	aa.aa_evts.recv_write_request = NULL;
	aa.aa_evts.recv_lock_request = NULL;
	aa.aa_arg = NULL;
	aa.aa_kmem_bufp = NULL;
	aa.aa_enable = T1394_ADDR_RDENBL;
	if (t1394_alloc_addr(sp->s_t1394_hdl, &aa, 0, &result) != DDI_SUCCESS) {
		(void) ddi_dma_unbind_handle(cmd->sc_pt_dma_hdl);
		ddi_dma_mem_free(&cmd->sc_pt_acc_hdl);
		ddi_dma_free_handle(&cmd->sc_pt_dma_hdl);
		lp->l_stat.stat_err_cmd_pt_addr_alloc++;
		return (DDI_FAILURE);
	}
	ASSERT(aa.aa_address != 0);
	cmd->sc_pt_baddr = aa.aa_address;
	cmd->sc_pt_addr_hdl = aa.aa_hdl;

	cmd->sc_flags |= SCSA1394_CMD_DMA_BUF_PT_VALID;

	return (DDI_SUCCESS);
}

static void
scsa1394_cmd_pt_dma_free(scsa1394_state_t *sp, scsa1394_cmd_t *cmd)
{
	(void) ddi_dma_unbind_handle(cmd->sc_pt_dma_hdl);
	ddi_dma_mem_free(&cmd->sc_pt_acc_hdl);
	ddi_dma_free_handle(&cmd->sc_pt_dma_hdl);
	(void) t1394_free_addr(sp->s_t1394_hdl, &cmd->sc_pt_addr_hdl, 0);
	cmd->sc_flags &= ~SCSA1394_CMD_DMA_BUF_PT_VALID;
}

/*
 * allocate 1394 addresses for all buffer segments
 */
static int
scsa1394_cmd_buf_addr_alloc(scsa1394_state_t *sp, scsa1394_cmd_t *cmd)
{
	scsa1394_lun_t	*lp = cmd->sc_lun;
	t1394_alloc_addr_t aa;
	scsa1394_cmd_seg_t *seg;
	int		result;
	int		i;

	aa.aa_type = T1394_ADDR_FIXED;
	aa.aa_evts.recv_read_request = NULL;
	aa.aa_evts.recv_write_request = NULL;
	aa.aa_evts.recv_lock_request = NULL;
	aa.aa_arg = NULL;
	aa.aa_kmem_bufp = NULL;
	if (cmd->sc_flags & SCSA1394_CMD_READ) {
		aa.aa_enable = T1394_ADDR_RDENBL;
	} else {
		aa.aa_enable = T1394_ADDR_WRENBL;
	}

	for (i = 0; i < cmd->sc_buf_nsegs; i++) {
		seg = &cmd->sc_buf_seg[i];

		/* segment bus address */
		aa.aa_length = seg->ss_len;
		aa.aa_address = seg->ss_daddr;

		if (t1394_alloc_addr(sp->s_t1394_hdl, &aa, 0, &result) !=
		    DDI_SUCCESS) {
			lp->l_stat.stat_err_cmd_buf_addr_alloc++;
			return (DDI_FAILURE);
		}
		ASSERT(aa.aa_address != 0);
		seg->ss_baddr = aa.aa_address;
		seg->ss_addr_hdl = aa.aa_hdl;
	}

	cmd->sc_flags |= SCSA1394_CMD_DMA_BUF_ADDR_VALID;

	return (DDI_SUCCESS);
}

static void
scsa1394_cmd_buf_addr_free(scsa1394_state_t *sp, scsa1394_cmd_t *cmd)
{
	int		i;

	for (i = 0; i < cmd->sc_buf_nsegs; i++) {
		if (cmd->sc_buf_seg[i].ss_addr_hdl) {
			(void) t1394_free_addr(sp->s_t1394_hdl,
			    &cmd->sc_buf_seg[i].ss_addr_hdl, 0);
		}
	}
	cmd->sc_flags &= ~SCSA1394_CMD_DMA_BUF_ADDR_VALID;
}

/*
 * move to next DMA window
 */
static int
scsa1394_cmd_buf_dma_move(scsa1394_state_t *sp, scsa1394_cmd_t *cmd)
{
	/* scsa1394_lun_t	*lp = cmd->sc_lun; */
	ddi_dma_cookie_t dmac;
	uint_t		ccount;

	/* for small pkts, leave things where they are (says WDD) */
	if ((cmd->sc_curwin == cmd->sc_nwin) && (cmd->sc_nwin == 1)) {
		return (DDI_SUCCESS);
	}
	if (++cmd->sc_curwin >= cmd->sc_nwin) {
		return (DDI_FAILURE);
	}
	if (ddi_dma_getwin(cmd->sc_buf_dma_hdl, cmd->sc_curwin,
	    &cmd->sc_win_offset, &cmd->sc_win_len, &dmac, &ccount) !=
	    DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	scsa1394_cmd_buf_addr_free(sp, cmd);

	/*
	 * setup page table if needed
	 */
	if ((ccount == 1) && (dmac.dmac_size <= SBP2_PT_SEGSIZE_MAX) &&
	    (!sp->s_symbios ||
	    (dmac.dmac_size <= scsa1394_symbios_page_size))) {
		/* but first, free old resources */
		if (cmd->sc_flags & SCSA1394_CMD_DMA_BUF_PT_VALID) {
			scsa1394_cmd_pt_dma_free(sp, cmd);
		}
		scsa1394_cmd_seg_free(sp, cmd);

		cmd->sc_buf_nsegs = 1;
		cmd->sc_buf_seg_mem.ss_len = dmac.dmac_size;
		cmd->sc_buf_seg_mem.ss_daddr = dmac.dmac_address;
		cmd->sc_buf_seg = &cmd->sc_buf_seg_mem;
	} else {
		/* break window into segments */
		if (scsa1394_cmd_dmac2seg(sp, cmd, &dmac, ccount, KM_NOSLEEP) !=
		    DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		/* allocate DMA resources */
		if (scsa1394_cmd_pt_dma_alloc(sp, cmd, NULL_FUNC, NULL,
		    cmd->sc_buf_nsegs) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}

	/* allocate 1394 addresses for segments */
	if (scsa1394_cmd_buf_addr_alloc(sp, cmd) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 *
 * --- pkt and data transfer routines
 *
 */
static int
scsa1394_scsi_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	scsa1394_state_t *sp = ADDR2STATE(ap);
	scsa1394_cmd_t	*cmd = PKT2CMD(pkt);
	scsa1394_lun_t	*lp = cmd->sc_lun;
	int		ret;

	/*
	 * since we don't support polled I/O, just accept the packet
	 * so the rest of the file systems get synced properly
	 */
	if (ddi_in_panic()) {
		scsa1394_prepare_pkt(sp, pkt);
		return (TRAN_ACCEPT);
	}

	/* polling not supported yet */
	if (pkt->pkt_flags & FLAG_NOINTR) {
		return (TRAN_BADPKT);
	}

	mutex_enter(&sp->s_mutex);
	if (sp->s_dev_state != SCSA1394_DEV_ONLINE) {
		/*
		 * If device is temporarily gone due to bus reset,
		 * return busy to prevent prevent scary console messages.
		 * If permanently gone, leave it to scsa1394_cmd_fake_comp().
		 */
		if (sp->s_dev_state == SCSA1394_DEV_BUS_RESET) {
			mutex_exit(&sp->s_mutex);
			return (TRAN_BUSY);
		}
	}
	mutex_exit(&sp->s_mutex);

	if ((ap->a_lun >= sp->s_nluns) ||
	    (ap->a_lun != pkt->pkt_address.a_lun)) {
		return (TRAN_BADPKT);
	}

	scsa1394_prepare_pkt(sp, pkt);

	/* some commands may require fake completion */
	if ((ret = scsa1394_cmd_fake_comp(sp, cmd)) == DDI_SUCCESS) {
		return (TRAN_ACCEPT);
	}

	scsa1394_cmd_fill_cdb(lp, cmd);

	if (cmd->sc_flags & SCSA1394_CMD_DMA_BUF_PT_VALID) {
		scsa1394_sbp2_seg2pt(lp, cmd);
	}

	scsa1394_sbp2_cmd2orb(lp, cmd);		/* convert into ORB */

	if ((ret = scsa1394_sbp2_start(lp, cmd)) != TRAN_BUSY) {
		scsa1394_sbp2_nudge(lp);
	}

	return (ret);
}

/*ARGSUSED*/
static void
scsa1394_prepare_pkt(scsa1394_state_t *sp, struct scsi_pkt *pkt)
{
	scsa1394_cmd_t	*cmd = PKT2CMD(pkt);

	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state = 0;
	pkt->pkt_statistics = 0;
	*(pkt->pkt_scbp) = STATUS_GOOD;

	if (cmd) {
		cmd->sc_timeout = pkt->pkt_time;

		/* workarounds */
		switch (pkt->pkt_cdbp[0]) {
		/*
		 * sd does START_STOP_UNIT during attach with a 200 sec timeout.
		 * at this time devi_lock is held, prtconf will be stuck.
		 * reduce timeout for the time being.
		 */
		case SCMD_START_STOP:
			cmd->sc_timeout = min(cmd->sc_timeout,
			    scsa1394_start_stop_timeout_max);
			break;
		default:
			break;
		}
	}
}

static void
scsa1394_cmd_fill_cdb(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd)
{
	cmd->sc_cdb_actual_len = cmd->sc_cdb_len;

	mutex_enter(&lp->l_mutex);

	switch (lp->l_dtype_orig) {
	case DTYPE_DIRECT:
	case DTYPE_RODIRECT:
	case DTYPE_OPTICAL:
	case SCSA1394_DTYPE_RBC:
		scsa1394_cmd_fill_cdb_rbc(lp, cmd);
		break;
	default:
		scsa1394_cmd_fill_cdb_other(lp, cmd);
		break;
	}

	mutex_exit(&lp->l_mutex);
}

static void
scsa1394_cmd_fill_cdb_rbc(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd)
{
	scsa1394_state_t *sp = lp->l_sp;
	struct scsi_pkt	*pkt = CMD2PKT(cmd);
	int		lba, opcode;
	struct buf	*bp = cmd->sc_bp;
	size_t		len;
	size_t		blk_size;
	int		sz;

	opcode = pkt->pkt_cdbp[0];
	blk_size  = lp->l_lba_size;

	switch (opcode) {
	case SCMD_READ:
		/* RBC only supports 10-byte read/write */
		lba = SCSA1394_LBA_6BYTE(pkt);
		len = SCSA1394_LEN_6BYTE(pkt);
		opcode = SCMD_READ_G1;
		cmd->sc_cdb_actual_len = CDB_GROUP1;
		break;
	case SCMD_WRITE:
		lba = SCSA1394_LBA_6BYTE(pkt);
		len = SCSA1394_LEN_6BYTE(pkt);
		opcode = SCMD_WRITE_G1;
		cmd->sc_cdb_actual_len = CDB_GROUP1;
		break;
	case SCMD_READ_G1:
	case SCMD_READ_LONG:
		lba = SCSA1394_LBA_10BYTE(pkt);
		len = SCSA1394_LEN_10BYTE(pkt);
		break;
	case SCMD_WRITE_G1:
	case SCMD_WRITE_LONG:
		lba = SCSA1394_LBA_10BYTE(pkt);
		len = SCSA1394_LEN_10BYTE(pkt);
		if ((lp->l_dtype_orig == DTYPE_RODIRECT) &&
		    (bp != NULL) && (len != 0)) {
			sz = SCSA1394_CDRW_BLKSZ(bp->b_bcount, len);
			if (SCSA1394_VALID_CDRW_BLKSZ(sz)) {
				blk_size = sz;
			}
		}
		break;
	case SCMD_READ_CD:
		lba = SCSA1394_LBA_10BYTE(pkt);
		len = SCSA1394_LEN_READ_CD(pkt);
		blk_size = scsa1394_cmd_read_cd_blk_size(pkt->pkt_cdbp[1] >> 2);
		break;
	case SCMD_READ_G5:
		lba = SCSA1394_LBA_12BYTE(pkt);
		len = SCSA1394_LEN_12BYTE(pkt);
		break;
	case SCMD_WRITE_G5:
		lba = SCSA1394_LBA_12BYTE(pkt);
		len = SCSA1394_LEN_12BYTE(pkt);
		break;
	default:
		/* no special mapping for other commands */
		scsa1394_cmd_fill_cdb_other(lp, cmd);
		return;
	}
	cmd->sc_blk_size = blk_size;

	/* limit xfer length for Symbios workaround */
	if (sp->s_symbios && (len * blk_size > scsa1394_symbios_size_max)) {
		cmd->sc_flags |= SCSA1394_CMD_SYMBIOS_BREAKUP;

		cmd->sc_total_blks = cmd->sc_resid_blks = len;

		len = scsa1394_symbios_size_max / blk_size;
	}
	cmd->sc_xfer_blks = len;
	cmd->sc_xfer_bytes = len * blk_size;

	/* finalize new CDB */
	switch (pkt->pkt_cdbp[0]) {
	case SCMD_READ:
	case SCMD_WRITE:
		/*
		 * We rewrite READ/WRITE G0 commands as READ/WRITE G1.
		 * Build new cdb from scatch.
		 * The lba and length fields is updated below.
		 */
		bzero(cmd->sc_cdb, cmd->sc_cdb_actual_len);
		break;
	default:
		/*
		 * Copy the non lba/len fields.
		 * The lba and length fields is updated below.
		 */
		bcopy(pkt->pkt_cdbp, cmd->sc_cdb, cmd->sc_cdb_actual_len);
		break;
	}

	cmd->sc_cdb[0] = (uchar_t)opcode;
	scsa1394_cmd_fill_cdb_lba(cmd, lba);
	switch (opcode) {
	case SCMD_READ_CD:
		scsa1394_cmd_fill_read_cd_cdb_len(cmd, len);
		break;
	case SCMD_WRITE_G5:
	case SCMD_READ_G5:
		scsa1394_cmd_fill_12byte_cdb_len(cmd, len);
		break;
	default:
		scsa1394_cmd_fill_cdb_len(cmd, len);
		break;
	}
}

/*ARGSUSED*/
static void
scsa1394_cmd_fill_cdb_other(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd)
{
	struct scsi_pkt	*pkt = CMD2PKT(cmd);

	cmd->sc_xfer_bytes = cmd->sc_win_len;
	cmd->sc_xfer_blks = cmd->sc_xfer_bytes / lp->l_lba_size;
	cmd->sc_total_blks = cmd->sc_xfer_blks;
	cmd->sc_lba = 0;

	bcopy(pkt->pkt_cdbp, cmd->sc_cdb, cmd->sc_cdb_len);
}

/*
 * fill up parts of CDB
 */
static void
scsa1394_cmd_fill_cdb_len(scsa1394_cmd_t *cmd, int len)
{
	cmd->sc_cdb[7] = len >> 8;
	cmd->sc_cdb[8] = (uchar_t)len;
}

static void
scsa1394_cmd_fill_cdb_lba(scsa1394_cmd_t *cmd, int lba)
{
	cmd->sc_cdb[2] = lba >> 24;
	cmd->sc_cdb[3] = lba >> 16;
	cmd->sc_cdb[4] = lba >> 8;
	cmd->sc_cdb[5] = (uchar_t)lba;
	cmd->sc_lba = lba;
}

static void
scsa1394_cmd_fill_12byte_cdb_len(scsa1394_cmd_t *cmd, int len)
{
	cmd->sc_cdb[6] = len >> 24;
	cmd->sc_cdb[7] = len >> 16;
	cmd->sc_cdb[8] = len >> 8;
	cmd->sc_cdb[9] = (uchar_t)len;
}

static void
scsa1394_cmd_fill_read_cd_cdb_len(scsa1394_cmd_t *cmd, int len)
{
	cmd->sc_cdb[6] = len >> 16;
	cmd->sc_cdb[7] = len >> 8;
	cmd->sc_cdb[8] = (uchar_t)len;
}

/*
 * For SCMD_READ_CD, figure out the block size based on expected sector type.
 * See MMC SCSI Specs section 6.1.15
 */
static int
scsa1394_cmd_read_cd_blk_size(uchar_t expected_sector_type)
{
	int blk_size;

	switch (expected_sector_type) {
	case READ_CD_EST_CDDA:
		blk_size = CDROM_BLK_2352;
		break;
	case READ_CD_EST_MODE2:
		blk_size = CDROM_BLK_2336;
		break;
	case READ_CD_EST_MODE2FORM2:
		blk_size = CDROM_BLK_2324;
		break;
	case READ_CD_EST_MODE2FORM1:
	case READ_CD_EST_ALLTYPE:
	case READ_CD_EST_MODE1:
	default:
		blk_size = CDROM_BLK_2048;
	}

	return (blk_size);
}

/*ARGSUSED*/
static int
scsa1394_cmd_fake_mode_sense(scsa1394_state_t *sp, scsa1394_cmd_t *cmd)
{
	struct scsi_pkt	*pkt = CMD2PKT(cmd);
	struct scsi_arq_status *arqp = (struct scsi_arq_status *)pkt->pkt_scbp;
	struct scsi_extended_sense *esp = &arqp->sts_sensedata;

	*(pkt->pkt_scbp) = STATUS_CHECK;
	*(uint8_t *)&arqp->sts_rqpkt_status = STATUS_GOOD;
	arqp->sts_rqpkt_reason = CMD_CMPLT;
	arqp->sts_rqpkt_resid = 0;
	arqp->sts_rqpkt_state |= STATE_XFERRED_DATA;
	arqp->sts_rqpkt_statistics = 0;

	bzero(esp, sizeof (struct scsi_extended_sense));

	esp->es_class = CLASS_EXTENDED_SENSE;

	esp->es_key = KEY_ILLEGAL_REQUEST;

	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD |
	    STATE_XFERRED_DATA | STATE_GOT_STATUS);

	if (pkt->pkt_comp) {
		(*pkt->pkt_comp)(pkt);
	}
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
scsa1394_cmd_fake_inquiry(scsa1394_state_t *sp, scsa1394_cmd_t *cmd)
{
	scsa1394_lun_t	*lp = cmd->sc_lun;
	struct scsi_pkt	*pkt = CMD2PKT(cmd);
	struct scsi_inquiry *inq;

	/* copy fabricated inquiry data */
	inq = (struct scsi_inquiry *)cmd->sc_bp->b_un.b_addr;
	bcopy(&lp->l_fake_inq, inq, sizeof (struct scsi_inquiry));

	pkt->pkt_resid -= sizeof (struct scsi_inquiry);
	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD |
	    STATE_XFERRED_DATA | STATE_GOT_STATUS);

	if (pkt->pkt_comp) {
		(*pkt->pkt_comp)(pkt);
	}
	return (DDI_SUCCESS);
}

/*
 * If command allows fake completion (without actually being transported),
 * call completion callback and return DDI_SUCCESS.
 * Otherwise return DDI_FAILURE.
 */
static int
scsa1394_cmd_fake_comp(scsa1394_state_t *sp, scsa1394_cmd_t *cmd)
{
	struct scsi_pkt	*pkt = CMD2PKT(cmd);
	scsa1394_lun_t	*lp = cmd->sc_lun;
	int		ret = DDI_SUCCESS;

	/*
	 * agreement with sd in case of device hot removal
	 * is to fake completion with CMD_DEV_GONE
	 */
	mutex_enter(&sp->s_mutex);
	if (sp->s_dev_state != SCSA1394_DEV_ONLINE) {
		mutex_exit(&sp->s_mutex);
		pkt->pkt_reason = CMD_DEV_GONE;
		if (pkt->pkt_comp) {
			(*pkt->pkt_comp)(pkt);
		}
		return (DDI_SUCCESS);
	}
	mutex_exit(&sp->s_mutex);

	mutex_enter(&lp->l_mutex);

	switch (pkt->pkt_cdbp[0]) {
	/*
	 * RBC support for PRIN/PROUT is optional
	 */
	case SCMD_PRIN:
	case SCMD_PROUT:
		if (!scsa1394_wrka_fake_prin) {
			ret = DDI_FAILURE;
		}
		break;
	/*
	 * Some fixed disks don't like doorlock cmd. And they don't need it.
	 */
	case SCMD_DOORLOCK:
		if (lp->l_rmb_orig != 0) {
			ret = DDI_FAILURE;
		}
		break;
	case SCMD_TEST_UNIT_READY:
		if (!lp->l_nosup_tur) {
			ret = DDI_FAILURE;
		}
		break;
	case SCMD_START_STOP:
		if (!lp->l_nosup_start_stop) {
			ret = DDI_FAILURE;
		}
		break;
	case SCMD_INQUIRY:
		if (!lp->l_nosup_inquiry) {
			ret = DDI_FAILURE;
		} else {
			mutex_exit(&lp->l_mutex);
			return (scsa1394_cmd_fake_inquiry(sp, cmd));
		}
		break;
	case SCMD_MODE_SENSE:
		if (!lp->l_mode_sense_fake) {
			ret = DDI_FAILURE;
		} else {
			mutex_exit(&lp->l_mutex);
			return (scsa1394_cmd_fake_mode_sense(sp, cmd));
		}
		break;
	default:
		ret = DDI_FAILURE;
	}

	mutex_exit(&lp->l_mutex);

	if (ret != DDI_SUCCESS) {
		return (ret);
	}

	ASSERT(*(pkt->pkt_scbp) == STATUS_GOOD);
	ASSERT(pkt->pkt_reason == CMD_CMPLT);
	pkt->pkt_state |= (STATE_GOT_BUS | STATE_GOT_TARGET | STATE_SENT_CMD |
	    STATE_XFERRED_DATA | STATE_GOT_STATUS);

	if (pkt->pkt_comp) {
		(*pkt->pkt_comp)(pkt);
	}
	return (DDI_SUCCESS);
}

/*
 * Returns DDI_SUCCESS if next xfer setup successfully, DDI_FAILURE otherwise.
 */
static int
scsa1394_cmd_setup_next_xfer(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd)
{
	struct scsi_pkt		*pkt = CMD2PKT(cmd);

	ASSERT(cmd->sc_flags & SCSA1394_CMD_SYMBIOS_BREAKUP);

	cmd->sc_resid_blks -= cmd->sc_xfer_blks;
	if (cmd->sc_resid_blks <= 0) {
		pkt->pkt_resid = 0;
		return (DDI_FAILURE);
	}

	scsa1394_cmd_adjust_cdb(lp, cmd);

	scsa1394_sbp2_seg2pt(lp, cmd);

	scsa1394_sbp2_cmd2orb(lp, cmd);

	if (scsa1394_sbp2_start(lp, cmd) != TRAN_ACCEPT) {
		pkt->pkt_resid = cmd->sc_resid_blks * cmd->sc_blk_size;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * new lba = current lba + previous xfer len
 */
/*ARGSUSED*/
static void
scsa1394_cmd_adjust_cdb(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd)
{
	int		len;

	ASSERT(cmd->sc_flags & SCSA1394_CMD_SYMBIOS_BREAKUP);

	cmd->sc_lba += cmd->sc_xfer_blks;
	len = cmd->sc_resid_blks;

	/* limit xfer length for Symbios workaround */
	if (len * cmd->sc_blk_size > scsa1394_symbios_size_max) {
		len = scsa1394_symbios_size_max / cmd->sc_blk_size;
	}

	switch (cmd->sc_cdb[0]) {
	case SCMD_READ_CD:
		scsa1394_cmd_fill_read_cd_cdb_len(cmd, len);
		break;
	case SCMD_WRITE_G5:
	case SCMD_READ_G5:
		scsa1394_cmd_fill_12byte_cdb_len(cmd, len);
		break;
	case SCMD_WRITE_G1:
	case SCMD_WRITE_LONG:
	default:
		scsa1394_cmd_fill_cdb_len(cmd, len);
	}

	scsa1394_cmd_fill_cdb_lba(cmd, cmd->sc_lba);

	cmd->sc_xfer_blks = len;
	cmd->sc_xfer_bytes = len * cmd->sc_blk_size;
}

void
scsa1394_cmd_status_proc(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd)
{
	struct scsi_pkt		*pkt = CMD2PKT(cmd);

	/* next iteration of partial xfer? */
	if ((pkt->pkt_reason == CMD_CMPLT) &&
	    (cmd->sc_flags & SCSA1394_CMD_SYMBIOS_BREAKUP)) {
		if (scsa1394_cmd_setup_next_xfer(lp, cmd) == DDI_SUCCESS) {
			return;
		}
	}
	cmd->sc_flags &= ~SCSA1394_CMD_SYMBIOS_BREAKUP;

	/* apply workarounds */
	if (pkt->pkt_reason == CMD_CMPLT) {
		scsa1394_cmd_status_wrka(lp, cmd);
	}

	mutex_enter(&lp->l_mutex);

	/* mode sense workaround */
	if (pkt->pkt_cdbp[0] == SCMD_MODE_SENSE) {
		if (pkt->pkt_reason == CMD_CMPLT) {
			lp->l_mode_sense_fail_cnt = 0;
		} else if (++lp->l_mode_sense_fail_cnt >=
		    scsa1394_mode_sense_fail_max) {
			lp->l_mode_sense_fake = B_TRUE;
		}
	} else {
		lp->l_mode_sense_fail_cnt = 0;
	}

	mutex_exit(&lp->l_mutex);

	if (pkt->pkt_comp) {
		(*pkt->pkt_comp)(pkt);
	}
}

static void
scsa1394_cmd_status_wrka(scsa1394_lun_t *lp, scsa1394_cmd_t *cmd)
{
	struct scsi_pkt	*pkt = CMD2PKT(cmd);

	mutex_enter(&lp->l_mutex);

	switch (pkt->pkt_cdbp[0]) {
	case SCMD_INQUIRY: {
		struct scsi_inquiry *inq;

		inq = (struct scsi_inquiry *)cmd->sc_bp->b_un.b_addr;

		/* change dtype RBC to DIRECT, sd doesn't support RBC */
		lp->l_dtype_orig = inq->inq_dtype;
		if ((inq->inq_dtype == SCSA1394_DTYPE_RBC) &&
		    scsa1394_wrka_rbc2direct) {
			inq->inq_dtype = DTYPE_DIRECT;
		}

		/* force RMB to 1 */
		lp->l_rmb_orig = inq->inq_rmb;
		if (scsa1394_wrka_fake_rmb) {
			inq->inq_rmb = 1;
		}
		break;
	}
	case SCMD_READ_CAPACITY: {
		uint32_t	*capacity_buf;

		capacity_buf = (uint32_t *)cmd->sc_bp->b_un.b_addr;

		if (lp->l_dtype_orig != DTYPE_RODIRECT) {
			lp->l_lba_size = min(BE_32(capacity_buf[1]), DEV_BSIZE);
			if (lp->l_lba_size == 0) {
				cmn_err(CE_WARN, "zero LBA size reported, "
				    "possibly broken device");
				lp->l_lba_size = DEV_BSIZE;
			}
		} else {
			lp->l_lba_size = 2048;
		}
	}
	default:
		break;
	}

	mutex_exit(&lp->l_mutex);
}

/*
 * --- thread management
 *
 * dispatch a thread
 */
int
scsa1394_thr_dispatch(scsa1394_thread_t *thr)
{
	scsa1394_lun_t		*lp = thr->thr_lun;
	scsa1394_state_t	*sp = lp->l_sp;
	int			ret;

	ASSERT(mutex_owned(&lp->l_mutex));
	ASSERT(thr->thr_state == SCSA1394_THR_INIT);

	thr->thr_state = SCSA1394_THR_RUN;

	ret = ddi_taskq_dispatch(sp->s_taskq, thr->thr_func, thr->thr_arg,
	    KM_SLEEP);
	return (ret);
}

/*
 * cancel thread
 */
void
scsa1394_thr_cancel(scsa1394_thread_t *thr)
{
	scsa1394_lun_t		*lp = thr->thr_lun;

	ASSERT(mutex_owned(&lp->l_mutex));

	thr->thr_req |= SCSA1394_THREQ_EXIT;
	cv_signal(&thr->thr_cv);

	/* wait until the thread actually exits */
	do {
		if (cv_wait_sig(&thr->thr_cv, &lp->l_mutex) == 0) {
			break;
		}
	} while (thr->thr_state != SCSA1394_THR_EXIT);
}

/*
 * wake thread
 */
void
scsa1394_thr_wake(scsa1394_thread_t *thr, int req)
{
	scsa1394_lun_t		*lp = thr->thr_lun;

	ASSERT(mutex_owned(&lp->l_mutex));

	thr->thr_req |= req;
	cv_signal(&thr->thr_cv);
}

void
scsa1394_thr_clear_req(scsa1394_thread_t *thr, int mask)
{
	scsa1394_lun_t		*lp = thr->thr_lun;

	mutex_enter(&lp->l_mutex);
	thr->thr_req &= ~mask;
	mutex_exit(&lp->l_mutex);
}

/*
 *
 * --- other routines
 *
 */
static boolean_t
scsa1394_is_my_child(dev_info_t *dip)
{
	return ((dip != NULL) && (ddi_prop_exists(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "scsa1394") == 1));
}

boolean_t
scsa1394_dev_is_online(scsa1394_state_t *sp)
{
	boolean_t	ret;

	mutex_enter(&sp->s_mutex);
	ret = (sp->s_dev_state == SCSA1394_DEV_ONLINE);
	mutex_exit(&sp->s_mutex);

	return (ret);
}

static void *
scsa1394_kmem_realloc(void *old_buf, int old_size, int new_size, size_t elsize,
    int kf)
{
	void	*new_buf;

	new_buf = kmem_zalloc(new_size * elsize, kf);

	if (old_size > 0) {
		if (new_buf != NULL) {
			bcopy(old_buf, new_buf, old_size * elsize);
		}
		kmem_free(old_buf, old_size * elsize);
	}

	return (new_buf);
}
