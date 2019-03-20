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
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */


/*
 * SCSA HBA nexus driver that emulates an HBA connected to SCSI target
 * devices (large disks).
 */

#ifdef DEBUG
#define	EMUL64DEBUG
#endif

#include <sys/scsi/scsi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/types.h>
#include <sys/buf.h>
#include <sys/cpuvar.h>
#include <sys/dklabel.h>

#include <sys/emul64.h>
#include <sys/emul64cmd.h>
#include <sys/emul64var.h>

int emul64_usetaskq	= 1;	/* set to zero for debugging */
int emul64debug		= 0;
#ifdef	EMUL64DEBUG
static int emul64_cdb_debug	= 0;
#include <sys/debug.h>
#endif

/*
 * cb_ops function prototypes
 */
static int emul64_ioctl(dev_t, int cmd, intptr_t arg, int mode,
			cred_t *credp, int *rvalp);

/*
 * dev_ops functions prototypes
 */
static int emul64_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result);
static int emul64_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int emul64_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/*
 * Function prototypes
 *
 * SCSA functions exported by means of the transport table
 */
static int emul64_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
	scsi_hba_tran_t *tran, struct scsi_device *sd);
static int emul64_scsi_start(struct scsi_address *ap, struct scsi_pkt *pkt);
static void emul64_pkt_comp(void *);
static int emul64_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
static int emul64_scsi_reset(struct scsi_address *ap, int level);
static int emul64_scsi_getcap(struct scsi_address *ap, char *cap, int whom);
static int emul64_scsi_setcap(struct scsi_address *ap, char *cap, int value,
    int whom);
static struct scsi_pkt *emul64_scsi_init_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen,
    int tgtlen, int flags, int (*callback)(), caddr_t arg);
static void emul64_scsi_destroy_pkt(struct scsi_address *ap,
					struct scsi_pkt *pkt);
static void emul64_scsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt);
static void emul64_scsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt);
static int emul64_scsi_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg);

/*
 * internal functions
 */
static void emul64_i_initcap(struct emul64 *emul64);

static void emul64_i_log(struct emul64 *emul64, int level, char *fmt, ...);
static int emul64_get_tgtrange(struct emul64 *,
				intptr_t,
				emul64_tgt_t **,
				emul64_tgt_range_t *);
static int emul64_write_off(struct emul64 *,
			    emul64_tgt_t *,
			    emul64_tgt_range_t *);
static int emul64_write_on(struct emul64 *,
				emul64_tgt_t *,
				emul64_tgt_range_t *);
static emul64_nowrite_t *emul64_nowrite_alloc(emul64_range_t *);
static void emul64_nowrite_free(emul64_nowrite_t *);
static emul64_nowrite_t *emul64_find_nowrite(emul64_tgt_t *,
					diskaddr_t start_block,
					size_t blkcnt,
					emul64_rng_overlap_t *overlapp,
					emul64_nowrite_t ***prevp);

extern emul64_tgt_t *find_tgt(struct emul64 *, ushort_t, ushort_t);

#ifdef EMUL64DEBUG
static void emul64_debug_dump_cdb(struct scsi_address *ap,
		struct scsi_pkt *pkt);
#endif


#ifdef	_DDICT
static int	ddi_in_panic(void);
static int	ddi_in_panic() { return (0); }
#ifndef	SCSI_CAP_RESET_NOTIFICATION
#define	SCSI_CAP_RESET_NOTIFICATION		14
#endif
#ifndef	SCSI_RESET_NOTIFY
#define	SCSI_RESET_NOTIFY			0x01
#endif
#ifndef	SCSI_RESET_CANCEL
#define	SCSI_RESET_CANCEL			0x02
#endif
#endif

/*
 * Tunables:
 *
 * emul64_max_task
 *	The taskq facility is used to queue up SCSI start requests on a per
 *	controller basis.  If the maximum number of queued tasks is hit,
 *	taskq_ent_alloc() delays for a second, which adversely impacts our
 *	performance.  This value establishes the maximum number of task
 *	queue entries when taskq_create is called.
 *
 * emul64_task_nthreads
 *	Specifies the number of threads that should be used to process a
 *	controller's task queue.  Our init function sets this to the number
 *	of CPUs on the system, but this can be overridden in emul64.conf.
 */
int emul64_max_task = 16;
int emul64_task_nthreads = 1;

/*
 * Local static data
 */
static void		*emul64_state = NULL;

/*
 * Character/block operations.
 */
static struct cb_ops emul64_cbops = {
	scsi_hba_open,		/* cb_open */
	scsi_hba_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	emul64_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_str */
	D_MP | D_64BIT | D_HOTPLUG, /* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

/*
 * autoconfiguration routines.
 */

static struct dev_ops emul64_ops = {
	DEVO_REV,			/* rev, */
	0,				/* refcnt */
	emul64_info,			/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	emul64_attach,			/* attach */
	emul64_detach,			/* detach */
	nodev,				/* reset */
	&emul64_cbops,			/* char/block ops */
	NULL,				/* bus ops */
	NULL,				/* power */
	ddi_quiesce_not_needed,			/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* module type - driver */
	"emul64 SCSI Host Bus Adapter",	/* module name */
	&emul64_ops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,			/* ml_rev - must be MODREV_1 */
	&modldrv,			/* ml_linkage */
	NULL				/* end of driver linkage */
};

int
_init(void)
{
	int	ret;

	ret = ddi_soft_state_init(&emul64_state, sizeof (struct emul64),
	    EMUL64_INITIAL_SOFT_SPACE);
	if (ret != 0)
		return (ret);

	if ((ret = scsi_hba_init(&modlinkage)) != 0) {
		ddi_soft_state_fini(&emul64_state);
		return (ret);
	}

	/* Set the number of task threads to the number of CPUs */
	if (boot_max_ncpus == -1) {
		emul64_task_nthreads = max_ncpus;
	} else {
		emul64_task_nthreads = boot_max_ncpus;
	}

	emul64_bsd_init();

	ret = mod_install(&modlinkage);
	if (ret != 0) {
		emul64_bsd_fini();
		scsi_hba_fini(&modlinkage);
		ddi_soft_state_fini(&emul64_state);
	}

	return (ret);
}

int
_fini(void)
{
	int	ret;

	if ((ret = mod_remove(&modlinkage)) != 0)
		return (ret);

	emul64_bsd_fini();

	scsi_hba_fini(&modlinkage);

	ddi_soft_state_fini(&emul64_state);

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Given the device number return the devinfo pointer
 * from the scsi_device structure.
 */
/*ARGSUSED*/
static int
emul64_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	struct emul64	*foo;
	int		instance = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		foo = ddi_get_soft_state(emul64_state, instance);
		if (foo != NULL)
			*result = (void *)foo->emul64_dip;
		else {
			*result = NULL;
			return (DDI_FAILURE);
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		break;

	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Attach an instance of an emul64 host adapter.  Allocate data structures,
 * initialize the emul64 and we're on the air.
 */
/*ARGSUSED*/
static int
emul64_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int		mutex_initted = 0;
	struct emul64	*emul64;
	int		instance;
	scsi_hba_tran_t	*tran = NULL;
	ddi_dma_attr_t	tmp_dma_attr;

	emul64_bsd_get_props(dip);

	bzero((void *) &tmp_dma_attr, sizeof (tmp_dma_attr));
	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
		if (!tran) {
			return (DDI_FAILURE);
		}
		emul64 = TRAN2EMUL64(tran);

		return (DDI_SUCCESS);

	default:
		emul64_i_log(NULL, CE_WARN,
		    "emul64%d: Cmd != DDI_ATTACH/DDI_RESUME", instance);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate emul64 data structure.
	 */
	if (ddi_soft_state_zalloc(emul64_state, instance) != DDI_SUCCESS) {
		emul64_i_log(NULL, CE_WARN,
		    "emul64%d: Failed to alloc soft state",
		    instance);
		return (DDI_FAILURE);
	}

	emul64 = (struct emul64 *)ddi_get_soft_state(emul64_state, instance);
	if (emul64 == (struct emul64 *)NULL) {
		emul64_i_log(NULL, CE_WARN, "emul64%d: Bad soft state",
		    instance);
		ddi_soft_state_free(emul64_state, instance);
		return (DDI_FAILURE);
	}


	/*
	 * Allocate a transport structure
	 */
	tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP);
	if (tran == NULL) {
		cmn_err(CE_WARN, "emul64: scsi_hba_tran_alloc failed\n");
		goto fail;
	}

	emul64->emul64_tran			= tran;
	emul64->emul64_dip			= dip;

	tran->tran_hba_private		= emul64;
	tran->tran_tgt_private		= NULL;
	tran->tran_tgt_init		= emul64_tran_tgt_init;
	tran->tran_tgt_probe		= scsi_hba_probe;
	tran->tran_tgt_free		= NULL;

	tran->tran_start		= emul64_scsi_start;
	tran->tran_abort		= emul64_scsi_abort;
	tran->tran_reset		= emul64_scsi_reset;
	tran->tran_getcap		= emul64_scsi_getcap;
	tran->tran_setcap		= emul64_scsi_setcap;
	tran->tran_init_pkt		= emul64_scsi_init_pkt;
	tran->tran_destroy_pkt		= emul64_scsi_destroy_pkt;
	tran->tran_dmafree		= emul64_scsi_dmafree;
	tran->tran_sync_pkt		= emul64_scsi_sync_pkt;
	tran->tran_reset_notify 	= emul64_scsi_reset_notify;

	tmp_dma_attr.dma_attr_minxfer = 0x1;
	tmp_dma_attr.dma_attr_burstsizes = 0x7f;

	/*
	 * Attach this instance of the hba
	 */
	if (scsi_hba_attach_setup(dip, &tmp_dma_attr, tran,
	    0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "emul64: scsi_hba_attach failed\n");
		goto fail;
	}

	emul64->emul64_initiator_id = 2;

	/*
	 * Look up the scsi-options property
	 */
	emul64->emul64_scsi_options =
	    ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "scsi-options",
	    EMUL64_DEFAULT_SCSI_OPTIONS);
	EMUL64_DEBUG(emul64, SCSI_DEBUG, "emul64 scsi-options=%x",
	    emul64->emul64_scsi_options);


	/* mutexes to protect the emul64 request and response queue */
	mutex_init(EMUL64_REQ_MUTEX(emul64), NULL, MUTEX_DRIVER,
	    emul64->emul64_iblock);
	mutex_init(EMUL64_RESP_MUTEX(emul64), NULL, MUTEX_DRIVER,
	    emul64->emul64_iblock);

	mutex_initted = 1;

	EMUL64_MUTEX_ENTER(emul64);

	/*
	 * Initialize the default Target Capabilities and Sync Rates
	 */
	emul64_i_initcap(emul64);

	EMUL64_MUTEX_EXIT(emul64);


	ddi_report_dev(dip);
	emul64->emul64_taskq = taskq_create("emul64_comp",
	    emul64_task_nthreads, MINCLSYSPRI, 1, emul64_max_task, 0);

	return (DDI_SUCCESS);

fail:
	emul64_i_log(NULL, CE_WARN, "emul64%d: Unable to attach", instance);

	if (mutex_initted) {
		mutex_destroy(EMUL64_REQ_MUTEX(emul64));
		mutex_destroy(EMUL64_RESP_MUTEX(emul64));
	}
	if (tran) {
		scsi_hba_tran_free(tran);
	}
	ddi_soft_state_free(emul64_state, instance);
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
emul64_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct emul64	*emul64;
	scsi_hba_tran_t	*tran;
	int		instance = ddi_get_instance(dip);


	/* get transport structure pointer from the dip */
	if (!(tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip))) {
		return (DDI_FAILURE);
	}

	/* get soft state from transport structure */
	emul64 = TRAN2EMUL64(tran);

	if (!emul64) {
		return (DDI_FAILURE);
	}

	EMUL64_DEBUG(emul64, SCSI_DEBUG, "emul64_detach: cmd = %d", cmd);

	switch (cmd) {
	case DDI_DETACH:
		EMUL64_MUTEX_ENTER(emul64);

		taskq_destroy(emul64->emul64_taskq);
		(void) scsi_hba_detach(dip);

		scsi_hba_tran_free(emul64->emul64_tran);


		EMUL64_MUTEX_EXIT(emul64);

		mutex_destroy(EMUL64_REQ_MUTEX(emul64));
		mutex_destroy(EMUL64_RESP_MUTEX(emul64));


		EMUL64_DEBUG(emul64, SCSI_DEBUG, "emul64_detach: done");
		ddi_soft_state_free(emul64_state, instance);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * Function name : emul64_tran_tgt_init
 *
 * Return Values : DDI_SUCCESS if target supported, DDI_FAILURE otherwise
 *
 */
/*ARGSUSED*/
static int
emul64_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
	scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	struct emul64	*emul64;
	emul64_tgt_t	*tgt;
	char		**geo_vidpid = NULL;
	char		*geo, *vidpid;
	uint32_t	*geoip = NULL;
	uint_t		length;
	uint_t		length2;
	lldaddr_t	sector_count;
	char		prop_name[15];
	int		ret = DDI_FAILURE;

	emul64 = TRAN2EMUL64(tran);
	EMUL64_MUTEX_ENTER(emul64);

	/*
	 * We get called for each target driver.conf node, multiple
	 * nodes may map to the same tgt,lun (sd.conf, st.conf, etc).
	 * Check to see if transport to tgt,lun already established.
	 */
	tgt = find_tgt(emul64, sd->sd_address.a_target, sd->sd_address.a_lun);
	if (tgt) {
		ret = DDI_SUCCESS;
		goto out;
	}

	/* see if we have driver.conf specified device for this target,lun */
	(void) snprintf(prop_name, sizeof (prop_name), "targ_%d_%d",
	    sd->sd_address.a_target, sd->sd_address.a_lun);
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, hba_dip,
	    DDI_PROP_DONTPASS, prop_name,
	    &geo_vidpid, &length) != DDI_PROP_SUCCESS)
		goto out;
	if (length < 2) {
		cmn_err(CE_WARN, "emul64: %s property does not have 2 "
		    "elements", prop_name);
		goto out;
	}

	/* pick geometry name and vidpid string from string array */
	geo = *geo_vidpid;
	vidpid = *(geo_vidpid + 1);

	/* lookup geometry property integer array */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, hba_dip, DDI_PROP_DONTPASS,
	    geo, (int **)&geoip, &length2) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "emul64: didn't get prop '%s'", geo);
		goto out;
	}
	if (length2 < 6) {
		cmn_err(CE_WARN, "emul64: property %s does not have 6 "
		    "elements", *geo_vidpid);
		goto out;
	}

	/* allocate and initialize tgt structure for tgt,lun */
	tgt = kmem_zalloc(sizeof (emul64_tgt_t), KM_SLEEP);
	rw_init(&tgt->emul64_tgt_nw_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&tgt->emul64_tgt_blk_lock, NULL, MUTEX_DRIVER, NULL);

	/* create avl for data block storage */
	avl_create(&tgt->emul64_tgt_data, emul64_bsd_blkcompare,
	    sizeof (blklist_t), offsetof(blklist_t, bl_node));

	/* save scsi_address and vidpid */
	bcopy(sd, &tgt->emul64_tgt_saddr, sizeof (struct scsi_address));
	(void) strncpy(tgt->emul64_tgt_inq, vidpid,
	    sizeof (emul64->emul64_tgt->emul64_tgt_inq));

	/*
	 * The high order 4 bytes of the sector count always come first in
	 * emul64.conf.  They are followed by the low order 4 bytes.  Not
	 * all CPU types want them in this order, but laddr_t takes care of
	 * this for us.  We then pick up geometry (ncyl X nheads X nsect).
	 */
	sector_count._p._u	= *(geoip + 0);
	sector_count._p._l	= *(geoip + 1);
	/*
	 * On 32-bit platforms, fix block size if it's greater than the
	 * allowable maximum.
	 */
#if !defined(_LP64)
	if (sector_count._f > DK_MAX_BLOCKS)
		sector_count._f = DK_MAX_BLOCKS;
#endif
	tgt->emul64_tgt_sectors = sector_count._f;
	tgt->emul64_tgt_dtype	= *(geoip + 2);
	tgt->emul64_tgt_ncyls	= *(geoip + 3);
	tgt->emul64_tgt_nheads	= *(geoip + 4);
	tgt->emul64_tgt_nsect	= *(geoip + 5);

	/* insert target structure into list */
	tgt->emul64_tgt_next = emul64->emul64_tgt;
	emul64->emul64_tgt = tgt;
	ret = DDI_SUCCESS;

out:	EMUL64_MUTEX_EXIT(emul64);
	if (geoip)
		ddi_prop_free(geoip);
	if (geo_vidpid)
		ddi_prop_free(geo_vidpid);
	return (ret);
}

/*
 * Function name : emul64_i_initcap
 *
 * Return Values : NONE
 * Description	 : Initializes the default target capabilities and
 *		   Sync Rates.
 *
 * Context	 : Called from the user thread through attach.
 *
 */
static void
emul64_i_initcap(struct emul64 *emul64)
{
	uint16_t	cap, synch;
	int		i;

	cap = 0;
	synch = 0;
	for (i = 0; i < NTARGETS_WIDE; i++) {
		emul64->emul64_cap[i] = cap;
		emul64->emul64_synch[i] = synch;
	}
	EMUL64_DEBUG(emul64, SCSI_DEBUG, "default cap = 0x%x", cap);
}

/*
 * Function name : emul64_scsi_getcap()
 *
 * Return Values : current value of capability, if defined
 *		   -1 if capability is not defined
 * Description	 : returns current capability value
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
static int
emul64_scsi_getcap(struct scsi_address *ap, char *cap, int whom)
{
	struct emul64	*emul64	= ADDR2EMUL64(ap);
	int		rval = 0;

	/*
	 * We don't allow inquiring about capabilities for other targets
	 */
	if (cap == NULL || whom == 0) {
		return (-1);
	}

	EMUL64_MUTEX_ENTER(emul64);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_DMA_MAX:
		rval = 1 << 24; /* Limit to 16MB max transfer */
		break;
	case SCSI_CAP_MSG_OUT:
		rval = 1;
		break;
	case SCSI_CAP_DISCONNECT:
		rval = 1;
		break;
	case SCSI_CAP_SYNCHRONOUS:
		rval = 1;
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
		rval = emul64->emul64_initiator_id;
		break;
	case SCSI_CAP_ARQ:
		rval = 1;
		break;
	case SCSI_CAP_LINKED_CMDS:
		break;
	case SCSI_CAP_RESET_NOTIFICATION:
		rval = 1;
		break;

	default:
		rval = -1;
		break;
	}

	EMUL64_MUTEX_EXIT(emul64);

	return (rval);
}

/*
 * Function name : emul64_scsi_setcap()
 *
 * Return Values : 1 - capability exists and can be set to new value
 *		   0 - capability could not be set to new value
 *		  -1 - no such capability
 *
 * Description	 : sets a capability for a target
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
static int
emul64_scsi_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	struct emul64	*emul64	= ADDR2EMUL64(ap);
	int		rval = 0;

	/*
	 * We don't allow setting capabilities for other targets
	 */
	if (cap == NULL || whom == 0) {
		return (-1);
	}

	EMUL64_MUTEX_ENTER(emul64);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_DMA_MAX:
	case SCSI_CAP_MSG_OUT:
	case SCSI_CAP_PARITY:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_LINKED_CMDS:
	case SCSI_CAP_RESET_NOTIFICATION:
		/*
		 * None of these are settable via
		 * the capability interface.
		 */
		break;
	case SCSI_CAP_DISCONNECT:
		rval = 1;
		break;
	case SCSI_CAP_SYNCHRONOUS:
		rval = 1;
		break;
	case SCSI_CAP_TAGGED_QING:
		rval = 1;
		break;
	case SCSI_CAP_WIDE_XFER:
		rval = 1;
		break;
	case SCSI_CAP_INITIATOR_ID:
		rval = -1;
		break;
	case SCSI_CAP_ARQ:
		rval = 1;
		break;
	case SCSI_CAP_TOTAL_SECTORS:
		emul64->nt_total_sectors[ap->a_target][ap->a_lun] = value;
		rval = TRUE;
		break;
	case SCSI_CAP_SECTOR_SIZE:
		rval = TRUE;
		break;
	default:
		rval = -1;
		break;
	}


	EMUL64_MUTEX_EXIT(emul64);

	return (rval);
}

/*
 * Function name : emul64_scsi_init_pkt
 *
 * Return Values : pointer to scsi_pkt, or NULL
 * Description	 : Called by kernel on behalf of a target driver
 *		   calling scsi_init_pkt(9F).
 *		   Refer to tran_init_pkt(9E) man page
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
/* ARGSUSED */
static struct scsi_pkt *
emul64_scsi_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
	struct buf *bp, int cmdlen, int statuslen, int tgtlen,
	int flags, int (*callback)(), caddr_t arg)
{
	struct emul64		*emul64	= ADDR2EMUL64(ap);
	struct emul64_cmd	*sp;

	ASSERT(callback == NULL_FUNC || callback == SLEEP_FUNC);

	/*
	 * First step of emul64_scsi_init_pkt:  pkt allocation
	 */
	if (pkt == NULL) {
		pkt = scsi_hba_pkt_alloc(emul64->emul64_dip, ap, cmdlen,
		    statuslen,
		    tgtlen, sizeof (struct emul64_cmd), callback, arg);
		if (pkt == NULL) {
			cmn_err(CE_WARN, "emul64_scsi_init_pkt: "
			    "scsi_hba_pkt_alloc failed");
			return (NULL);
		}

		sp = PKT2CMD(pkt);

		/*
		 * Initialize the new pkt - we redundantly initialize
		 * all the fields for illustrative purposes.
		 */
		sp->cmd_pkt		= pkt;
		sp->cmd_flags		= 0;
		sp->cmd_scblen		= statuslen;
		sp->cmd_cdblen		= cmdlen;
		sp->cmd_emul64		= emul64;
		pkt->pkt_address	= *ap;
		pkt->pkt_comp		= (void (*)())NULL;
		pkt->pkt_flags		= 0;
		pkt->pkt_time		= 0;
		pkt->pkt_resid		= 0;
		pkt->pkt_statistics	= 0;
		pkt->pkt_reason		= 0;

	} else {
		sp = PKT2CMD(pkt);
	}

	/*
	 * Second step of emul64_scsi_init_pkt:  dma allocation/move
	 */
	if (bp && bp->b_bcount != 0) {
		if (bp->b_flags & B_READ) {
			sp->cmd_flags &= ~CFLAG_DMASEND;
		} else {
			sp->cmd_flags |= CFLAG_DMASEND;
		}
		bp_mapin(bp);
		sp->cmd_addr = (unsigned char *) bp->b_un.b_addr;
		sp->cmd_count = bp->b_bcount;
		pkt->pkt_resid = 0;
	}

	return (pkt);
}


/*
 * Function name : emul64_scsi_destroy_pkt
 *
 * Return Values : none
 * Description	 : Called by kernel on behalf of a target driver
 *		   calling scsi_destroy_pkt(9F).
 *		   Refer to tran_destroy_pkt(9E) man page
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
static void
emul64_scsi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct emul64_cmd	*sp = PKT2CMD(pkt);

	/*
	 * emul64_scsi_dmafree inline to make things faster
	 */
	if (sp->cmd_flags & CFLAG_DMAVALID) {
		/*
		 * Free the mapping.
		 */
		sp->cmd_flags &= ~CFLAG_DMAVALID;
	}

	/*
	 * Free the pkt
	 */
	scsi_hba_pkt_free(ap, pkt);
}


/*
 * Function name : emul64_scsi_dmafree()
 *
 * Return Values : none
 * Description	 : free dvma resources
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
/*ARGSUSED*/
static void
emul64_scsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
}

/*
 * Function name : emul64_scsi_sync_pkt()
 *
 * Return Values : none
 * Description	 : sync dma
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
/*ARGSUSED*/
static void
emul64_scsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
}

/*
 * routine for reset notification setup, to register or cancel.
 */
static int
emul64_scsi_reset_notify(struct scsi_address *ap, int flag,
void (*callback)(caddr_t), caddr_t arg)
{
	struct emul64				*emul64 = ADDR2EMUL64(ap);
	struct emul64_reset_notify_entry	*p, *beforep;
	int					rval = DDI_FAILURE;

	mutex_enter(EMUL64_REQ_MUTEX(emul64));

	p = emul64->emul64_reset_notify_listf;
	beforep = NULL;

	while (p) {
		if (p->ap == ap)
			break;	/* An entry exists for this target */
		beforep = p;
		p = p->next;
	}

	if ((flag & SCSI_RESET_CANCEL) && (p != NULL)) {
		if (beforep == NULL) {
			emul64->emul64_reset_notify_listf = p->next;
		} else {
			beforep->next = p->next;
		}
		kmem_free((caddr_t)p,
		    sizeof (struct emul64_reset_notify_entry));
		rval = DDI_SUCCESS;

	} else if ((flag & SCSI_RESET_NOTIFY) && (p == NULL)) {
		p = kmem_zalloc(sizeof (struct emul64_reset_notify_entry),
		    KM_SLEEP);
		p->ap = ap;
		p->callback = callback;
		p->arg = arg;
		p->next = emul64->emul64_reset_notify_listf;
		emul64->emul64_reset_notify_listf = p;
		rval = DDI_SUCCESS;
	}

	mutex_exit(EMUL64_REQ_MUTEX(emul64));

	return (rval);
}

/*
 * Function name : emul64_scsi_start()
 *
 * Return Values : TRAN_FATAL_ERROR	- emul64 has been shutdown
 *		   TRAN_BUSY		- request queue is full
 *		   TRAN_ACCEPT		- pkt has been submitted to emul64
 *
 * Description	 : init pkt, start the request
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
static int
emul64_scsi_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct emul64_cmd	*sp	= PKT2CMD(pkt);
	int			rval	= TRAN_ACCEPT;
	struct emul64		*emul64	= ADDR2EMUL64(ap);
	clock_t			cur_lbolt;
	taskqid_t		dispatched;

	ASSERT(mutex_owned(EMUL64_REQ_MUTEX(emul64)) == 0 || ddi_in_panic());
	ASSERT(mutex_owned(EMUL64_RESP_MUTEX(emul64)) == 0 || ddi_in_panic());

	EMUL64_DEBUG2(emul64, SCSI_DEBUG, "emul64_scsi_start %x", sp);

	pkt->pkt_reason = CMD_CMPLT;

#ifdef	EMUL64DEBUG
	if (emul64_cdb_debug) {
		emul64_debug_dump_cdb(ap, pkt);
	}
#endif	/* EMUL64DEBUG */

	/*
	 * calculate deadline from pkt_time
	 * Instead of multiplying by 100 (ie. HZ), we multiply by 128 so
	 * we can shift and at the same time have a 28% grace period
	 * we ignore the rare case of pkt_time == 0 and deal with it
	 * in emul64_i_watch()
	 */
	cur_lbolt = ddi_get_lbolt();
	sp->cmd_deadline = cur_lbolt + (pkt->pkt_time * 128);

	if ((emul64_usetaskq == 0) || (pkt->pkt_flags & FLAG_NOINTR) != 0) {
		emul64_pkt_comp((caddr_t)pkt);
	} else {
		dispatched = TASKQID_INVALID;
		if (emul64_collect_stats) {
			/*
			 * If we are collecting statistics, call
			 * taskq_dispatch in no sleep mode, so that we can
			 * detect if we are exceeding the queue length that
			 * was established in the call to taskq_create in
			 * emul64_attach.  If the no sleep call fails
			 * (returns NULL), the task will be dispatched in
			 * sleep mode below.
			 */
			dispatched = taskq_dispatch(emul64->emul64_taskq,
			    emul64_pkt_comp, (void *)pkt, TQ_NOSLEEP);
			if (dispatched == TASKQID_INVALID) {
				/* Queue was full.  dispatch failed. */
				mutex_enter(&emul64_stats_mutex);
				emul64_taskq_max++;
				mutex_exit(&emul64_stats_mutex);
			}
		}
		if (dispatched == TASKQID_INVALID) {
			(void) taskq_dispatch(emul64->emul64_taskq,
			    emul64_pkt_comp, (void *)pkt, TQ_SLEEP);
		}
	}

done:
	ASSERT(mutex_owned(EMUL64_REQ_MUTEX(emul64)) == 0 || ddi_in_panic());
	ASSERT(mutex_owned(EMUL64_RESP_MUTEX(emul64)) == 0 || ddi_in_panic());

	return (rval);
}

void
emul64_check_cond(struct scsi_pkt *pkt, uchar_t key, uchar_t asc, uchar_t ascq)
{
	struct scsi_arq_status *arq =
	    (struct scsi_arq_status *)pkt->pkt_scbp;

	/* got check, no data transferred and ARQ done */
	arq->sts_status.sts_chk = 1;
	pkt->pkt_state |= STATE_ARQ_DONE;
	pkt->pkt_state &= ~STATE_XFERRED_DATA;

	/* for ARQ */
	arq->sts_rqpkt_reason = CMD_CMPLT;
	arq->sts_rqpkt_resid = 0;
	arq->sts_rqpkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
	    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS;
	arq->sts_sensedata.es_valid = 1;
	arq->sts_sensedata.es_class = 0x7;
	arq->sts_sensedata.es_key = key;
	arq->sts_sensedata.es_add_code = asc;
	arq->sts_sensedata.es_qual_code = ascq;
}

ushort_t
emul64_error_inject(struct scsi_pkt *pkt)
{
	struct emul64_cmd	*sp	= PKT2CMD(pkt);
	emul64_tgt_t		*tgt;
	struct scsi_arq_status *arq =
	    (struct scsi_arq_status *)pkt->pkt_scbp;
	uint_t			max_sense_len;

	EMUL64_MUTEX_ENTER(sp->cmd_emul64);
	tgt = find_tgt(sp->cmd_emul64,
	    pkt->pkt_address.a_target, pkt->pkt_address.a_lun);
	EMUL64_MUTEX_EXIT(sp->cmd_emul64);

	/*
	 * If there is no target, skip the error injection and
	 * let the packet be handled normally.  This would normally
	 * never happen since a_target and a_lun are setup in
	 * emul64_scsi_init_pkt.
	 */
	if (tgt == NULL) {
		return (ERR_INJ_DISABLE);
	}

	if (tgt->emul64_einj_state != ERR_INJ_DISABLE) {
		arq->sts_status = tgt->emul64_einj_scsi_status;
		pkt->pkt_state = tgt->emul64_einj_pkt_state;
		pkt->pkt_reason = tgt->emul64_einj_pkt_reason;

		/*
		 * Calculate available sense buffer length.  We could just
		 * assume sizeof(struct scsi_extended_sense) but hopefully
		 * that limitation will go away soon.
		 */
		max_sense_len = sp->cmd_scblen  -
		    (sizeof (struct scsi_arq_status) -
		    sizeof (struct scsi_extended_sense));
		if (max_sense_len > tgt->emul64_einj_sense_length) {
			max_sense_len = tgt->emul64_einj_sense_length;
		}

		/* for ARQ */
		arq->sts_rqpkt_reason = CMD_CMPLT;
		arq->sts_rqpkt_resid = 0;
		arq->sts_rqpkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS;

		/* Copy sense data */
		if (tgt->emul64_einj_sense_data != 0) {
			bcopy(tgt->emul64_einj_sense_data,
			    (uint8_t *)&arq->sts_sensedata,
			    max_sense_len);
		}
	}

	/* Return current error injection state */
	return (tgt->emul64_einj_state);
}

int
emul64_error_inject_req(struct emul64 *emul64, intptr_t arg)
{
	emul64_tgt_t		*tgt;
	struct emul64_error_inj_data error_inj_req;

	/* Check args */
	if (arg == NULL) {
		return (EINVAL);
	}

	if (ddi_copyin((void *)arg, &error_inj_req,
	    sizeof (error_inj_req), 0) != 0) {
		cmn_err(CE_WARN, "emul64: ioctl - inj copyin failed\n");
		return (EFAULT);
	}

	EMUL64_MUTEX_ENTER(emul64);
	tgt = find_tgt(emul64, error_inj_req.eccd_target,
	    error_inj_req.eccd_lun);
	EMUL64_MUTEX_EXIT(emul64);

	/* Make sure device exists */
	if (tgt == NULL) {
		return (ENODEV);
	}

	/* Free old sense buffer if we have one */
	if (tgt->emul64_einj_sense_data != NULL) {
		ASSERT(tgt->emul64_einj_sense_length != 0);
		kmem_free(tgt->emul64_einj_sense_data,
		    tgt->emul64_einj_sense_length);
		tgt->emul64_einj_sense_data = NULL;
		tgt->emul64_einj_sense_length = 0;
	}

	/*
	 * Now handle error injection request.  If error injection
	 * is requested we will return the sense data provided for
	 * any I/O to this target until told to stop.
	 */
	tgt->emul64_einj_state = error_inj_req.eccd_inj_state;
	tgt->emul64_einj_sense_length = error_inj_req.eccd_sns_dlen;
	tgt->emul64_einj_pkt_state = error_inj_req.eccd_pkt_state;
	tgt->emul64_einj_pkt_reason = error_inj_req.eccd_pkt_reason;
	tgt->emul64_einj_scsi_status = error_inj_req.eccd_scsi_status;
	switch (error_inj_req.eccd_inj_state) {
	case ERR_INJ_ENABLE:
	case ERR_INJ_ENABLE_NODATA:
		if (error_inj_req.eccd_sns_dlen) {
			tgt->emul64_einj_sense_data =
			    kmem_alloc(error_inj_req.eccd_sns_dlen, KM_SLEEP);
			/* Copy sense data */
			if (ddi_copyin((void *)(arg + sizeof (error_inj_req)),
			    tgt->emul64_einj_sense_data,
			    error_inj_req.eccd_sns_dlen, 0) != 0) {
				cmn_err(CE_WARN,
				    "emul64: sense data copy in failed\n");
				return (EFAULT);
			}
		}
		break;
	case ERR_INJ_DISABLE:
	default:
		break;
	}

	return (0);
}

int bsd_scsi_start_stop_unit(struct scsi_pkt *);
int bsd_scsi_test_unit_ready(struct scsi_pkt *);
int bsd_scsi_request_sense(struct scsi_pkt *);
int bsd_scsi_inquiry(struct scsi_pkt *);
int bsd_scsi_format(struct scsi_pkt *);
int bsd_scsi_io(struct scsi_pkt *);
int bsd_scsi_log_sense(struct scsi_pkt *);
int bsd_scsi_mode_sense(struct scsi_pkt *);
int bsd_scsi_mode_select(struct scsi_pkt *);
int bsd_scsi_read_capacity(struct scsi_pkt *);
int bsd_scsi_read_capacity_16(struct scsi_pkt *);
int bsd_scsi_reserve(struct scsi_pkt *);
int bsd_scsi_format(struct scsi_pkt *);
int bsd_scsi_release(struct scsi_pkt *);
int bsd_scsi_read_defect_list(struct scsi_pkt *);
int bsd_scsi_reassign_block(struct scsi_pkt *);
int bsd_freeblkrange(emul64_tgt_t *, emul64_range_t *);

static void
emul64_handle_cmd(struct scsi_pkt *pkt)
{
	if (emul64_error_inject(pkt) == ERR_INJ_ENABLE_NODATA) {
		/*
		 * If error injection is configured to return with
		 * no data return now without handling the command.
		 * This is how normal check conditions work.
		 *
		 * If the error injection state is ERR_INJ_ENABLE
		 * (or if error injection is disabled) continue and
		 * handle the command.  This would be used for
		 * KEY_RECOVERABLE_ERROR type conditions.
		 */
		return;
	}

	switch (pkt->pkt_cdbp[0]) {
	case SCMD_START_STOP:
		(void) bsd_scsi_start_stop_unit(pkt);
		break;
	case SCMD_TEST_UNIT_READY:
		(void) bsd_scsi_test_unit_ready(pkt);
		break;
	case SCMD_REQUEST_SENSE:
		(void) bsd_scsi_request_sense(pkt);
		break;
	case SCMD_INQUIRY:
		(void) bsd_scsi_inquiry(pkt);
		break;
	case SCMD_FORMAT:
		(void) bsd_scsi_format(pkt);
		break;
	case SCMD_READ:
	case SCMD_WRITE:
	case SCMD_READ_G1:
	case SCMD_WRITE_G1:
	case SCMD_READ_G4:
	case SCMD_WRITE_G4:
		(void) bsd_scsi_io(pkt);
		break;
	case SCMD_LOG_SENSE_G1:
		(void) bsd_scsi_log_sense(pkt);
		break;
	case SCMD_MODE_SENSE:
	case SCMD_MODE_SENSE_G1:
		(void) bsd_scsi_mode_sense(pkt);
		break;
	case SCMD_MODE_SELECT:
	case SCMD_MODE_SELECT_G1:
		(void) bsd_scsi_mode_select(pkt);
		break;
	case SCMD_READ_CAPACITY:
		(void) bsd_scsi_read_capacity(pkt);
		break;
	case SCMD_SVC_ACTION_IN_G4:
		if (pkt->pkt_cdbp[1] == SSVC_ACTION_READ_CAPACITY_G4) {
			(void) bsd_scsi_read_capacity_16(pkt);
		} else {
			cmn_err(CE_WARN, "emul64: unrecognized G4 service "
			    "action 0x%x", pkt->pkt_cdbp[1]);
		}
		break;
	case SCMD_RESERVE:
	case SCMD_RESERVE_G1:
		(void) bsd_scsi_reserve(pkt);
		break;
	case SCMD_RELEASE:
	case SCMD_RELEASE_G1:
		(void) bsd_scsi_release(pkt);
		break;
	case SCMD_REASSIGN_BLOCK:
		(void) bsd_scsi_reassign_block(pkt);
		break;
	case SCMD_READ_DEFECT_LIST:
		(void) bsd_scsi_read_defect_list(pkt);
		break;
	case SCMD_PRIN:
	case SCMD_PROUT:
	case SCMD_REPORT_LUNS:
		/* ASC 0x24 INVALID FIELD IN CDB */
		emul64_check_cond(pkt, KEY_ILLEGAL_REQUEST, 0x24, 0x0);
		break;
	default:
		cmn_err(CE_WARN, "emul64: unrecognized "
		    "SCSI cmd 0x%x", pkt->pkt_cdbp[0]);
		emul64_check_cond(pkt, KEY_ILLEGAL_REQUEST, 0x24, 0x0);
		break;
	case SCMD_GET_CONFIGURATION:
	case 0x35:			/* SCMD_SYNCHRONIZE_CACHE */
		/* Don't complain */
		break;
	}
}

static void
emul64_pkt_comp(void * arg)
{
	struct scsi_pkt		*pkt = (struct scsi_pkt *)arg;
	struct emul64_cmd	*sp = PKT2CMD(pkt);
	emul64_tgt_t		*tgt;

	EMUL64_MUTEX_ENTER(sp->cmd_emul64);
	tgt = find_tgt(sp->cmd_emul64,
	    pkt->pkt_address.a_target, pkt->pkt_address.a_lun);
	EMUL64_MUTEX_EXIT(sp->cmd_emul64);
	if (!tgt) {
		pkt->pkt_reason = CMD_TIMEOUT;
		pkt->pkt_state = STATE_GOT_BUS | STATE_SENT_CMD;
		pkt->pkt_statistics = STAT_TIMEOUT;
	} else {
		pkt->pkt_reason = CMD_CMPLT;
		*pkt->pkt_scbp = STATUS_GOOD;
		pkt->pkt_state = STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS;
		pkt->pkt_statistics = 0;
		emul64_handle_cmd(pkt);
	}
	scsi_hba_pkt_comp(pkt);
}

/* ARGSUSED */
static int
emul64_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	return (1);
}

/* ARGSUSED */
static int
emul64_scsi_reset(struct scsi_address *ap, int level)
{
	return (1);
}

static int
emul64_get_tgtrange(struct emul64 *emul64,
		    intptr_t arg,
		    emul64_tgt_t **tgtp,
		    emul64_tgt_range_t *tgtr)
{
	if (ddi_copyin((void *)arg, tgtr, sizeof (*tgtr), 0) != 0) {
		cmn_err(CE_WARN, "emul64: ioctl - copy in failed\n");
		return (EFAULT);
	}
	EMUL64_MUTEX_ENTER(emul64);
	*tgtp = find_tgt(emul64, tgtr->emul64_target, tgtr->emul64_lun);
	EMUL64_MUTEX_EXIT(emul64);
	if (*tgtp == NULL) {
		cmn_err(CE_WARN, "emul64: ioctl - no target for %d,%d on %d",
		    tgtr->emul64_target, tgtr->emul64_lun,
		    ddi_get_instance(emul64->emul64_dip));
		return (ENXIO);
	}
	return (0);
}

static int
emul64_ioctl(dev_t dev,
	int cmd,
	intptr_t arg,
	int mode,
	cred_t *credp,
	int *rvalp)
{
	struct emul64		*emul64;
	int			instance;
	int			rv = 0;
	emul64_tgt_range_t	tgtr;
	emul64_tgt_t		*tgt;

	instance = MINOR2INST(getminor(dev));
	emul64 = (struct emul64 *)ddi_get_soft_state(emul64_state, instance);
	if (emul64 == NULL) {
		cmn_err(CE_WARN, "emul64: ioctl - no softstate for %d\n",
		    getminor(dev));
		return (ENXIO);
	}

	switch (cmd) {
	case EMUL64_WRITE_OFF:
		rv = emul64_get_tgtrange(emul64, arg, &tgt, &tgtr);
		if (rv == 0) {
			rv = emul64_write_off(emul64, tgt, &tgtr);
		}
		break;
	case EMUL64_WRITE_ON:
		rv = emul64_get_tgtrange(emul64, arg, &tgt, &tgtr);
		if (rv == 0) {
			rv = emul64_write_on(emul64, tgt, &tgtr);
		}
		break;
	case EMUL64_ZERO_RANGE:
		rv = emul64_get_tgtrange(emul64, arg, &tgt, &tgtr);
		if (rv == 0) {
			mutex_enter(&tgt->emul64_tgt_blk_lock);
			rv = bsd_freeblkrange(tgt, &tgtr.emul64_blkrange);
			mutex_exit(&tgt->emul64_tgt_blk_lock);
		}
		break;
	case EMUL64_ERROR_INJECT:
		rv = emul64_error_inject_req(emul64, arg);
		break;
	default:
		rv  = scsi_hba_ioctl(dev, cmd, arg, mode, credp, rvalp);
		break;
	}
	return (rv);
}

/* ARGSUSED */
static int
emul64_write_off(struct emul64 *emul64,
	emul64_tgt_t *tgt,
	emul64_tgt_range_t *tgtr)
{
	size_t			blkcnt = tgtr->emul64_blkrange.emul64_blkcnt;
	emul64_nowrite_t	*cur;
	emul64_nowrite_t	*nowrite;
	emul64_rng_overlap_t	overlap = O_NONE;
	emul64_nowrite_t	**prev = NULL;
	diskaddr_t		sb = tgtr->emul64_blkrange.emul64_sb;

	nowrite = emul64_nowrite_alloc(&tgtr->emul64_blkrange);

	/* Find spot in list */
	rw_enter(&tgt->emul64_tgt_nw_lock, RW_WRITER);
	cur = emul64_find_nowrite(tgt, sb, blkcnt, &overlap, &prev);
	if (overlap == O_NONE) {
		/* Insert into list */
		*prev = nowrite;
		nowrite->emul64_nwnext = cur;
	}
	rw_exit(&tgt->emul64_tgt_nw_lock);
	if (overlap == O_NONE) {
		if (emul64_collect_stats) {
			mutex_enter(&emul64_stats_mutex);
			emul64_nowrite_count++;
			mutex_exit(&emul64_stats_mutex);
		}
	} else {
		cmn_err(CE_WARN, "emul64: EMUL64_WRITE_OFF 0x%llx,0x%"
		    PRIx64 "overlaps 0x%llx,0x%" PRIx64 "\n",
		    nowrite->emul64_blocked.emul64_sb,
		    nowrite->emul64_blocked.emul64_blkcnt,
		    cur->emul64_blocked.emul64_sb,
		    cur->emul64_blocked.emul64_blkcnt);
		emul64_nowrite_free(nowrite);
		return (EINVAL);
	}
	return (0);
}

/* ARGSUSED */
static int
emul64_write_on(struct emul64 *emul64,
		emul64_tgt_t *tgt,
		emul64_tgt_range_t *tgtr)
{
	size_t			blkcnt = tgtr->emul64_blkrange.emul64_blkcnt;
	emul64_nowrite_t	*cur;
	emul64_rng_overlap_t	overlap = O_NONE;
	emul64_nowrite_t	**prev = NULL;
	int			rv = 0;
	diskaddr_t		sb = tgtr->emul64_blkrange.emul64_sb;

	/* Find spot in list */
	rw_enter(&tgt->emul64_tgt_nw_lock, RW_WRITER);
	cur = emul64_find_nowrite(tgt, sb, blkcnt, &overlap, &prev);
	if (overlap == O_SAME) {
		/* Remove from list */
		*prev = cur->emul64_nwnext;
	}
	rw_exit(&tgt->emul64_tgt_nw_lock);

	switch (overlap) {
	case O_NONE:
		cmn_err(CE_WARN, "emul64: EMUL64_WRITE_ON 0x%llx,0x%lx "
		    "range not found\n", sb, blkcnt);
		rv = ENXIO;
		break;
	case O_SAME:
		if (emul64_collect_stats) {
			mutex_enter(&emul64_stats_mutex);
			emul64_nowrite_count--;
			mutex_exit(&emul64_stats_mutex);
		}
		emul64_nowrite_free(cur);
		break;
	case O_OVERLAP:
	case O_SUBSET:
		cmn_err(CE_WARN, "emul64: EMUL64_WRITE_ON 0x%llx,0x%lx "
		    "overlaps 0x%llx,0x%" PRIx64 "\n",
		    sb, blkcnt, cur->emul64_blocked.emul64_sb,
		    cur->emul64_blocked.emul64_blkcnt);
		rv = EINVAL;
		break;
	}
	return (rv);
}

static emul64_nowrite_t *
emul64_find_nowrite(emul64_tgt_t *tgt,
		    diskaddr_t sb,
		    size_t blkcnt,
		    emul64_rng_overlap_t *overlap,
		    emul64_nowrite_t ***prevp)
{
	emul64_nowrite_t	*cur;
	emul64_nowrite_t	**prev;

	/* Find spot in list */
	*overlap = O_NONE;
	prev = &tgt->emul64_tgt_nowrite;
	cur = tgt->emul64_tgt_nowrite;
	while (cur != NULL) {
		*overlap = emul64_overlap(&cur->emul64_blocked, sb, blkcnt);
		if (*overlap != O_NONE)
			break;
		prev = &cur->emul64_nwnext;
		cur = cur->emul64_nwnext;
	}

	*prevp = prev;
	return (cur);
}

static emul64_nowrite_t *
emul64_nowrite_alloc(emul64_range_t *range)
{
	emul64_nowrite_t	*nw;

	nw = kmem_zalloc(sizeof (*nw), KM_SLEEP);
	bcopy((void *) range,
	    (void *) &nw->emul64_blocked,
	    sizeof (nw->emul64_blocked));
	return (nw);
}

static void
emul64_nowrite_free(emul64_nowrite_t *nw)
{
	kmem_free((void *) nw, sizeof (*nw));
}

emul64_rng_overlap_t
emul64_overlap(emul64_range_t *rng, diskaddr_t sb, size_t cnt)
{

	if (rng->emul64_sb >= sb + cnt)
		return (O_NONE);
	if (rng->emul64_sb + rng->emul64_blkcnt <= sb)
		return (O_NONE);
	if ((rng->emul64_sb == sb) && (rng->emul64_blkcnt == cnt))
		return (O_SAME);
	if ((sb >= rng->emul64_sb) &&
	    ((sb + cnt) <= (rng->emul64_sb + rng->emul64_blkcnt))) {
		return (O_SUBSET);
	}
	return (O_OVERLAP);
}

#include <sys/varargs.h>

/*
 * Error logging, printing, and debug print routines
 */

/*VARARGS3*/
static void
emul64_i_log(struct emul64 *emul64, int level, char *fmt, ...)
{
	char	buf[256];
	va_list	ap;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	scsi_log(emul64 ? emul64->emul64_dip : NULL,
	    "emul64", level, "%s\n", buf);
}


#ifdef EMUL64DEBUG

static void
emul64_debug_dump_cdb(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	static char	hex[]	= "0123456789abcdef";
	struct emul64	*emul64	= ADDR2EMUL64(ap);
	struct emul64_cmd	*sp	= PKT2CMD(pkt);
	uint8_t		*cdb	= pkt->pkt_cdbp;
	char		buf [256];
	char		*p;
	int		i;

	(void) snprintf(buf, sizeof (buf), "emul64%d: <%d,%d> ",
	    ddi_get_instance(emul64->emul64_dip),
	    ap->a_target, ap->a_lun);

	p = buf + strlen(buf);

	*p++ = '[';
	for (i = 0; i < sp->cmd_cdblen; i++, cdb++) {
		if (i != 0)
			*p++ = ' ';
		*p++ = hex[(*cdb >> 4) & 0x0f];
		*p++ = hex[*cdb & 0x0f];
	}
	*p++ = ']';
	*p++ = '\n';
	*p = 0;

	cmn_err(CE_CONT, buf);
}
#endif	/* EMUL64DEBUG */
