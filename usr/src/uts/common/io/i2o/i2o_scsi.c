/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * I2O SCSI HBA OSM
 *
 * I2O Scsi Host Bus Adapter Operating System Module (OSM)
 * conforms to I2O and converts SCSI pkt information send by
 * the target driver through SCSA to I2O message format and send it
 * down to the IOP.  This driver utilized the I2O messaging framework,
 * i2o_msg. Currently only support on x86.
 *
 */

/*
 * debugging code
 */
#ifdef	DEBUG
#define	I2OHBA_DEBUG
#endif

#ifdef	I2OHBA_DEBUG
int	i2ohbadebugflag = 0;
int	ddi_dma_alloc_hdl = 0;
int	ddi_dma_alloc_mem = 0;
int	ddi_dma_bind_hdl = 0;
int	ddi_dma_unbind = 0;
int	ddi_dma_free_mem = 0;
int	ddi_dma_bind_free = 0;
int	ddi_dma_bufalloc = 0;
int	ddi_dma_buf_bind = 0;
int	ddi_dma_buf_unbind = 0;
int	ddi_dma_buf_free_hdl = 0;
#define	DEBUGF(level, args) \
	{ if (i2ohbadebugflag >= (level)) cmn_err args; }
#else
#define	DEBUGF(leve, args)	/* nothing */
#endif

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/varargs.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/scsi_ctl.h>
#include <sys/scsi/impl/scsi_reset_notify.h>

#include <sys/i2o/i2obscsi.h>
#include <sys/i2o/i2oadptr.h>
#include <sys/i2o/i2omsg.h>
#include <sys/i2o/i2outil.h>

#include "i2o_scsi_var.h"
#include "i2o_scsi_util.h"
#include "i2o_scsi_cmd.h"

/*
 * dev_ops functions prototypes
 */
static int i2ohba_info(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result);
static int i2ohba_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int i2ohba_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/*
 * Function prototypes
 *
 * SCSA functions exported by means of the transport table
 */
static int i2ohba_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
	scsi_hba_tran_t *tran, struct scsi_device *sd);
static int i2ohba_scsi_start(struct scsi_address *ap, struct scsi_pkt *pkt);
static int i2ohba_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt);
static int i2ohba_scsi_reset(struct scsi_address *ap, int level);
static int i2ohba_scsi_getcap(struct scsi_address *ap, char *cap, int whom);
static int i2ohba_scsi_setcap(struct scsi_address *ap, char *cap, int value,
    int whom);
static struct scsi_pkt *i2ohba_scsi_init_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt, struct buf *bp, int cmdlen, int statuslen,
    int tgtlen, int flags, int (*callback)(), caddr_t arg);
static void i2ohba_scsi_destroy_pkt(struct scsi_address *ap,
    struct scsi_pkt *pkt);
static void i2ohba_scsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt);
static void i2ohba_scsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt);
static int i2ohba_scsi_reset_notify(struct scsi_address *ap, int flag,
    void (*callback)(caddr_t), caddr_t arg);

/*
 * i2ohba's complete function for sending the SCSI pkt.
 */
static void i2ohba_callback(i2o_message_frame_t *msg, ddi_acc_handle_t
    acc_handle);


/*
 * Internal Functions
 */
/* tid map to scsi convertion function */
static int i2ohba_i_tid_to_scsi(dev_info_t *dip, struct i2ohba *i2ohba,
    i2o_lct_t *lct_buf, size_t lct_real_size,
    ddi_acc_handle_t lctbuf_dmaacchandle);

/* capability/prop functions */
static void i2ohba_i_updatesync(struct i2ohba *i2ohba, int tgt);
static void i2ohba_i_update_props(struct i2ohba *i2ohba, int tgt);
static void i2ohba_i_update_this_prop(struct i2ohba *i2ohba, char *property,
    int value);
static void i2ohba_i_initcap(struct i2ohba *i2ohba);

/* dma engine funcitons */
static int i2ohba_i_dma_alloc(struct i2ohba *i2ohba, struct scsi_pkt *pkt,
    struct buf *bp, int flags, int (*callback)());
static int i2ohba_i_dma_move(struct i2ohba *i2ohba, struct scsi_pkt *pkt,
    struct buf *bp);

/* timer and recovery functions */
static void i2ohba_i_watch(void *);
static void i2ohba_i_fatal_error(struct i2ohba *i2ohba);
static int i2ohba_i_reset_interface(struct i2ohba *i2ohba, int action);
static int i2ohba_i_reset_abort(struct i2ohba *i2ohba, uint16_t tid, int action,
    struct i2ohba_cmd *cmd);

/* command processing functions */
static void i2ohba_i_polled_cmd_start(struct i2ohba *i2ohba,
    struct i2ohba_cmd *sp);
static void i2ohba_i_req_insert(struct i2ohba *i2ohba, struct i2ohba_cmd *sp);
static void i2ohba_i_req_remove(struct i2ohba *i2ohba, struct i2ohba_cmd *sp);
static void i2ohba_i_pkt_comp(i2o_single_reply_message_frame_t *reply,
    ddi_acc_handle_t acc_handle, struct i2ohba_cmd *sp);
static void i2ohba_i_handle_arq(i2o_scsi_error_reply_message_frame_t *replyerr,
    struct i2ohba_cmd *sp, int aqcount);
static void i2ohba_i_qflush(struct i2ohba *i2ohba, uint16_t start_tgt,
    uint16_t end_tgt);
/*PRINTFLIKE3*/
static void i2ohba_i_log(struct i2ohba *i2ohba, int level, char *fmt, ...);
static void i2ohba_i_print_state(struct i2ohba *i2ohba);

/* utility parameter functions */
static int i2ohba_utilparamset_msg(struct i2ohba *i2ohba, int tgt,
    uint16_t tid, uint16_t group, uint16_t idx, uint16_t value);
static int i2ohba_utilparamget_msg(struct i2ohba *i2ohba, uint16_t tidx,
    char flag);
static void i2ohba_utilmsg_comp(i2o_message_frame_t *msg, ddi_acc_handle_t
    acc_handle);
static int i2ohba_utilclaim_msg(struct i2ohba *i2ohba, uint16_t tid,
    int action);

/*
 * mutex for protecting variables shared by all instances of the driver
 */
static kmutex_t i2ohba_log_mutex;

/*
 * Local static data
 */
static	void *i2ohba_state = NULL;
static	clock_t i2ohba_tick;		/* watch interval in HZ */
static	clock_t i2ohba_watchdog_tick = 15; /* watch interval in sec */
static	int i2ohba_scsi_reset_delay = 3000;
ddi_device_acc_attr_t dev_attr; 	/* dev_attr */
static	char i2ohba_log_buf[256];	/* buffer used in i2ohba_i_log */



/*
 * DMA Attribute for data buffers
 */
static ddi_dma_attr_t i2ohba_dma_attr = {
	DMA_ATTR_VERSION,			/* dma_attr_version */
	0,					/* dma_attr_addr_lo */
	0xffffffffull,				/* dma_attr_addr_hi */
	0x00ffffffull,				/* dma_attr_count_max */
	1,					/* dma_attr_align */
	1,					/* dma_attr_burstsizes */
	1,					/* dma_attr_minxfer */
	0xffffffffull,				/* dma_attr_maxxfer */
	0x00ffffffull,				/* dma_attr_seg */
	I2OHBA_CMD_NSEGS,			/* dma_attr_sgllen */
	512,					/* dma_attr_granular */
	0					/* dma_attr_flags */
};

/*
 * DMA attributes for SGL buffer
 */
static ddi_dma_attr_t i2ohba_dmasgl_attr = {
	DMA_ATTR_VERSION,			/* dma_attr_version */
	0,					/* dma_attr_addr_lo */
	0xffffffffull,				/* dma_attr_addr_hi */
	0x00ffffffull,				/* dma_attr_count_max */
	1,					/* dma_attr_align */
	1,					/* dma_attr_burstsizes */
	1,					/* dma_attr_minxfer */
	0xffffffffull,				/* dma_attr_maxxfer */
	0x00ffffffull,				/* dma_attr_seg */
	0x1,					/* dma_attr_sgllen */
	1,					/* dma_attr_granular */
	0					/* dma_attr_flags */
};

/*
 * Hotplug support
 * Leaf ops (hotplug controls for target devices)
 * XXXLWXXX currently doesn't support any hotpluging
 */

static struct cb_ops i2ohba_cb_ops = {
	nodev,		/* open */
	nodev,		/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	nodev,		/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,	/* prop_op */
	NULL,
	D_NEW | D_MP | D_HOTPLUG
};

/*
 * autoconfiguration routines.
 */

static struct dev_ops i2ohba_ops = {
	DEVO_REV,			/* rev, */
	0,				/* refcnt */
	i2ohba_info,			/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	i2ohba_attach,			/* attach */
	i2ohba_detach,			/* detach */
	nodev,				/* reset */
	&i2ohba_cb_ops,			/* driver operations */
	NULL,				/* bus ops */
	NULL				/* power ops */
};

char _depends_on[] = "misc/scsi misc/i2o_msg";

static struct modldrv modldrv = {
	&mod_driverops,			/* Type of module */
	"I2O SCSI HBA OSM version %I%",	/* module name */
	&i2ohba_ops,			/* driver ops */

};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&i2ohba_state, sizeof (struct i2ohba),
		I2OHBA_INITIAL_SOFT_SPACE);

	if (ret != 0)
		return (ret);

	mutex_init(&i2ohba_log_mutex, NULL, MUTEX_DRIVER, NULL);

	i2ohba_tick = drv_usectohz(i2ohba_watchdog_tick * 1000000);

	if ((ret = scsi_hba_init(&modlinkage)) != 0) {
		mutex_destroy(&i2ohba_log_mutex);
		ddi_soft_state_fini(&i2ohba_state);
		return (ret);
	}

	if ((ret = mod_install(&modlinkage)) != 0) {
		scsi_hba_fini(&modlinkage);
		mutex_destroy(&i2ohba_log_mutex);
		ddi_soft_state_fini(&i2ohba_state);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{

	int ret;

	if ((ret = mod_remove(&modlinkage)) != 0)
		return (ret);

	scsi_hba_fini(&modlinkage);

	mutex_destroy(&i2ohba_log_mutex);
	ddi_soft_state_fini(&i2ohba_state);

	return (ret);
}

/*
 * Given the device number return the devinfo pointer
 * from the scsi_device structure.
 */
/*ARGSUSED*/
static int
i2ohba_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	return (DDI_FAILURE);
}


/*
 * Attach an instance of an i2o hba OSM module.  Allocate data structures,
 * initialize the OSM and send commands to IOP to bring I2O on line.
 */
/*ARGSUSED*/
static int
i2ohba_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	scsi_hba_tran_t *tran = NULL;
	char prop_str[32];
	int i, id, tid2scsi;
	int freecount = 0;
	int ishdlalloc = 0;
	struct i2ohba *i2ohba;
	int instance;
	size_t lct_size, lct_real_size, lct_rlen;
	i2o_lct_t *lct_buf;
	ddi_dma_handle_t	lctbuf_dmahandle;
	ddi_acc_handle_t	lctbuf_dmaacchandle;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:
		dev_attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
		dev_attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
		/* currently for x86 PCI, we'll use little endian */
		dev_attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
		break;

	/* XXXLWXXX  will work on it more */
	case DDI_RESUME:
	case DDI_PM_RESUME:

	default:
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_attach%d: "
		    "cmd != DDI_ATTACH", instance);
		return (DDI_FAILURE);
	}

	/*
	 * I2O comes in at intr level 5
	 */
	if (ddi_intr_hilevel(dip, 0) != 0) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_attach%d: high-level "
		    "interrupt not supported", instance);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate i2ohba data structure.
	 */
	if (ddi_soft_state_zalloc(i2ohba_state, instance) != DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba%d: Failed to alloc"
		    " soft state", instance);
		return (DDI_FAILURE);
	}

	i2ohba = ddi_get_soft_state(i2ohba_state, instance);

	if (i2ohba == (struct i2ohba *)NULL) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba%d: Bad soft state",
		    instance);
		ddi_soft_state_free(i2ohba_state, instance);
		return (DDI_FAILURE);
	}

	/*
	 * save the dip info
	 */
	i2ohba->i2ohba_dip = dip;

	/*
	 * register OSM with message layer
	 */
	if (i2o_msg_osm_register(dip, &i2ohba->i2ohba_iophdl)
	    != DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba%d: Registeration Fail "
		    "with IOP", instance);
		goto cleanup;
	}

	/*
	 * get the LCT from iop
	 */
	if (i2o_msg_get_lct(i2ohba->i2ohba_iophdl, NULL, NULL,
	    &lct_size, NULL) != DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba%d: Can't get LCT SIZE "
		    "info from IOP", instance);
		goto cleanup;
	}

retry:
	/*
	 * first get the size from IOP, then
	 * DMA Allocate it.
	 */
	if (lct_size) {
		if (!ishdlalloc) {
			if (ddi_dma_alloc_handle(dip, &i2ohba_dmasgl_attr,
			    DDI_DMA_SLEEP, NULL, &lctbuf_dmahandle) !=
			    DDI_SUCCESS)
				goto cleanup;
		}
		ishdlalloc = 1;
#ifdef I2OHBA_DEBUG
		ddi_dma_alloc_hdl++;
#endif
		if (ddi_dma_mem_alloc(lctbuf_dmahandle, (size_t)
		    lct_size, &dev_attr, DDI_DMA_STREAMING,
		    DDI_DMA_SLEEP, NULL, (caddr_t *)&lct_buf, &lct_rlen,
		    &lctbuf_dmaacchandle) != DDI_SUCCESS)
			goto cleanup;
#ifdef I2OHBA_DEBUG
		ddi_dma_alloc_mem++;
#endif
		freecount = 1;

	} else {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba%d: Invalid LCT size",
		    instance);
		goto cleanup;
	}

	/*
	 * with the right size buffer, now get the table
	 */
	if (i2o_msg_get_lct(i2ohba->i2ohba_iophdl, lct_buf, lct_size,
		NULL, &lct_real_size) != DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba%d: Getting LCT table "
		    "info failed", instance);
		goto cleanup;
	}

	/*
	 * partial transfer
	 */
	if (lct_real_size > lct_size) {
		ddi_dma_mem_free(&lctbuf_dmaacchandle);
#ifdef I2OHBA_DEBUG
		ddi_dma_free_mem++;
#endif
		lct_size = lct_real_size;
		goto retry;
	}

	/*
	 * Set up TID->SCSI info map, query all unclaimed SCSI devices
	 */
	if (tid2scsi = i2ohba_i_tid_to_scsi(dip, i2ohba, lct_buf,
	    lct_real_size, lctbuf_dmaacchandle)) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba%d: Setup TID to SCSI "
		    "info map failed", instance);
		goto cleanup;
	}

	/* free dma, may be XXLWXX we can keep it for later LCT update */
	freecount = 0;
	ddi_dma_mem_free(&lctbuf_dmaacchandle);
#ifdef I2OHBA_DEBUG
	ddi_dma_free_mem++;
#endif
	ishdlalloc = 0;
	ddi_dma_free_handle(&lctbuf_dmahandle);
#ifdef I2OHBA_DEBUG
	ddi_dma_bind_free++;
#endif

	/*
	 * Allocate a transport structure
	 */
	tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP);

	i2ohba->i2ohba_tran	= tran;
	i2ohba->i2ohba_dip	= dip;

	tran->tran_hba_private	= i2ohba;
	tran->tran_tgt_private	= NULL;
	tran->tran_tgt_init	= i2ohba_tran_tgt_init;
	tran->tran_tgt_probe	= (int (*)())scsi_hba_probe;
	tran->tran_tgt_free	= (void (*)())NULL;

	tran->tran_start	= i2ohba_scsi_start;
	tran->tran_abort	= i2ohba_scsi_abort;
	tran->tran_reset	= i2ohba_scsi_reset;
	tran->tran_getcap	= i2ohba_scsi_getcap;
	tran->tran_setcap	= i2ohba_scsi_setcap;
	tran->tran_init_pkt	= i2ohba_scsi_init_pkt;
	tran->tran_destroy_pkt	= i2ohba_scsi_destroy_pkt;
	tran->tran_dmafree	= i2ohba_scsi_dmafree;
	tran->tran_sync_pkt	= i2ohba_scsi_sync_pkt;
	tran->tran_reset_notify = i2ohba_scsi_reset_notify;
	tran->tran_get_bus_addr	= NULL;
	tran->tran_get_name	= NULL;


	/*
	 * Attach this instance of the hba
	 */
	if (scsi_hba_attach_setup(dip, &i2ohba_dma_attr, tran,
	    0) != DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?scsi_hba_attach failed");
		goto cleanup;
	}

	/*
	 * find scsi host id property
	 */
	id = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
		"scsi-initiator-id", -1);
	if (id != scsi_host_id &&
			(id >= 0 && id < N_I2OHBA_TARGETS_WIDE)) {
		i2ohba->i2ohba_initiator_id = (uint8_t)id;
	} else {
		i2ohba->i2ohba_initiator_id = (uint8_t)scsi_host_id;
	}

	/*
	 * property: look up the scsi-options property
	 */
	i2ohba->i2ohba_scsi_options =
	    ddi_getprop(DDI_DEV_T_ANY, dip, 0, "scsi-options",
	    I2OHBA_DEFAULT_SCSI_OPTIONS);

	/*
	 * property: if target<n>-scsi-options property exists, use it;
	 *		otherwise use the i2o_scsi_options
	 */
	for (i = 0; i < N_I2OHBA_TARGETS_WIDE; i++) {
		(void) sprintf(prop_str, "target%x-scsi-options", i);
		i2ohba->i2ohba_target_scsi_option[i] = ddi_getprop(
		    DDI_DEV_T_ANY, dip, 0, prop_str,
		    i2ohba->i2ohba_scsi_options);

		if (i2ohba->i2ohba_target_scsi_option[i] !=
		    i2ohba->i2ohba_scsi_options) {
			i2ohba_i_log(NULL, CE_CONT,
			    "?i2ohba:target%x-scsi-options=0x%x",
			    i, i2ohba->i2ohba_target_scsi_option[i]);
		}
	}


	i2ohba->i2ohba_scsi_reset_delay =
		ddi_getprop(DDI_DEV_T_ANY, dip, 0, "scsi-reset-delay",
		    i2ohba_scsi_reset_delay);

	if (i2ohba->i2ohba_scsi_reset_delay != i2ohba_scsi_reset_delay) {
		i2ohba_i_log(NULL, CE_CONT,
		    "?i2ohba_scsi-reset-delay=%d",
		    i2ohba->i2ohba_scsi_reset_delay);
	}



	/*
	 * set up watchdog for this i2o
	 */
	i2ohba->i2ohba_timeout_id = timeout(i2ohba_i_watch, (caddr_t)i2ohba,
	    i2ohba_tick);

	/*
	 * initialized I2OHBA request mutex and reset mutex
	 */
	mutex_init(I2OHBA_REQ_MUTEX(i2ohba), NULL, MUTEX_DRIVER, NULL);
	mutex_init(I2OHBA_RESET_MUTEX(i2ohba), NULL, MUTEX_DRIVER, NULL);
	cv_init(I2OHBA_RESET_CV(i2ohba), NULL, CV_DRIVER, NULL);

	I2OHBA_MUTEX_ENTER(i2ohba);
	/*
	 * Initialize the default Target Capabilites and Sync Rates
	 */
	(void) i2ohba_i_initcap(i2ohba);

	/*
	 * reset i2ohba/bus and initialize capabilities
	 * if (i2ohba_i_reset_interface(i2ohba, I2OHBA_FORCE_BUS_RESET)) {
	 *	goto cleanup;
	 * }
	 */
	I2OHBA_MUTEX_EXIT(i2ohba);

	ddi_report_dev(dip);
	i2ohba->i2ohba_throttle = 0;

	DEBUGF(1, (CE_CONT, "i2ohba_attach%d: Succeeded", instance));

	return (DDI_SUCCESS);

cleanup:
	DEBUGF(1, (CE_CONT, "?i2ohba_attach%d: Unable to attach", instance));

	if (tid2scsi) {
		i2o_tid_scsi_ent_t *map = i2ohba->i2ohba_tid_scsi_map;

		/*
		 * if tid_to_scsi has succeeded, then at least
		 * we have the HBA node claimed.
		 */
		(void) i2ohba_utilclaim_msg(i2ohba, i2ohba->i2ohba_tid,
		    I2O_UTIL_CLAIM_RELEASE);

		DEBUGF(1, (CE_CONT, "?Utilunclaim %d", i2ohba->i2ohba_tid));

		for (i = 0; i < N_I2OHBA_TARGETS_WIDE; i++) {
			if (map[i].tid != 0)
				(void) i2ohba_utilclaim_msg(i2ohba,
				    map[i].tid,
				    I2O_UTIL_CLAIM_RELEASE);
		}

	}

	if (freecount) {
		ddi_dma_mem_free(&lctbuf_dmaacchandle);
	}
	if (ishdlalloc) {
		ddi_dma_free_handle(&lctbuf_dmahandle);
	}

	if (i2ohba->i2ohba_timeout_id != 0) {
		i2ohba->i2ohba_shutdown = 1;
		(void) untimeout(i2ohba->i2ohba_timeout_id);
		i2ohba->i2ohba_timeout_id = 0;
	}

	if (tran) {
		scsi_hba_tran_free(tran);
	}

	if (i2ohba->i2ohba_iophdl)
		i2o_msg_osm_unregister(&i2ohba->i2ohba_iophdl);

	ddi_soft_state_free(i2ohba_state, instance);

	return (DDI_FAILURE);
}

/*
 * Function name: i2ohba_i_tid_to_scsi
 *
 * Return Values: -1	Failed
 *		   0	Success
 *
 * Description	: Take in the LCT (logical configuration table), and
 *		  parse it through to find the appropriated SCSI target
 *		  devices that belongs to this HBA.  Then send a
 *		  I2O_UTIL_PARAM_GET message to the target device to
 *		  to get its parameters, ie SCSI ID and build a
 *		  tid-to-scsi.id map.
 */
/*ARGSUSED*/
static int
i2ohba_i_tid_to_scsi(dev_info_t *dip, struct i2ohba *i2ohba,
    i2o_lct_t *lct_buf, size_t lct_real_size,
    ddi_acc_handle_t lctbuf_dmaacchandle)
{
	i2o_tid_scsi_ent_t *map = i2ohba->i2ohba_tid_scsi_map;
	uint_t	tablesize, actualtbl;
	i2o_lct_entry_t	*lctentptr;
	int	i, count, entries = 0, rval = -1;

	/*
	 * translating dev_addr field in the dev_info struct to TID
	 */

	i2ohba->i2ohba_tid = ddi_getprop(DDI_DEV_T_ANY, dip, 0,
		"i2o-device-id", -1);

	/*
	 * scan the table for SCSI bus/devices
	 */
	tablesize = ddi_get16(lctbuf_dmaacchandle, &lct_buf->TableSize);

	if (!tablesize) {
		i2ohba_i_log(NULL, CE_WARN, "?i2o_i_tid_to_scsi: Invalid "
		    "tablesize");
		return (rval);
	}

	/*
	 * lct table size in WORDS
	 */
	actualtbl = (tablesize << 2) - sizeof (i2o_lct_t) +
	    sizeof (i2o_lct_entry_t);

	actualtbl = actualtbl/sizeof (i2o_lct_entry_t);

	/* scan through the table */
	for (count = 0; count < actualtbl; count++) {
		uint16_t userid, parentid = 0;

		lctentptr = &(lct_buf->LCTEntry[count]);
		userid = get_lct_entry_UserTID(lctentptr, lctbuf_dmaacchandle);
		parentid = get_lct_entry_ParentTID(lctentptr,
		    lctbuf_dmaacchandle);

		/* unclaim devices */
		if (userid == 0xFFF) {
			int class;
			uint16_t tid;

			class = get_lct_entry_Class(lctentptr,
			    lctbuf_dmaacchandle);
			tid = get_lct_entry_LocalTID(lctentptr,
			    lctbuf_dmaacchandle);

			/*
			 * search for SCSI Peripheral with Parent ID
			 * as the same as hba's TID and unclaimed devices
			 */

			if ((parentid == i2ohba->i2ohba_tid) &&
			    (class == I2O_CLASS_SCSI_PERIPHERAL)) {
				/* claim it */
				if (i2ohba_utilclaim_msg(i2ohba, tid,
				    I2O_UTIL_CLAIM)) {
					i2ohba_i_log(NULL, CE_WARN,
					    "?i2ohba_i_tid_to_scsi: "
					    "i2ohba_utilclaim_msg failed");
				} else {
					i2ohba_i_log(NULL, CE_CONT,
					    "?utilclaim:"
					    "Tid: 0x%x, SCSI_PERIPHERAL", tid);
					/* claim succeed */
					map[entries].tid = tid;
					entries++;
				}
			}

			/*
			 * find our own bus adapter port and
			 * claim it as well
			 */
			if ((tid == i2ohba->i2ohba_tid) &&
			    (class == I2O_CLASS_BUS_ADAPTER_PORT)) {
				if (i2ohba_utilclaim_msg(i2ohba, tid,
				    I2O_UTIL_CLAIM)) {
					i2ohba_i_log(NULL, CE_WARN,
					    "?i2ohba_i_tid_to_scsi: "
					    "i2ohba_utilclaim_msg failed");
				/*
				 * it is pointless to continue here
				 * because if we can't claim the bus port
				 * then we can't do anything except for
				 * sending utilgetparm and busreset msgs
				 */
					break;
				} else {
					i2ohba_i_log(NULL, CE_CONT,
					    "?utilclaim:"
					    "Tid: 0x%x, BUS_ADAPTER_PORT", tid);
					rval = 0;
				}
			}

		} /* userid == 0xFFF */
	} /* for loop */

	/*
	 * initialized all utilparam message's mutex's
	 */
	for (i = 0; i < N_I2OHBA_TARGETS_WIDE; i++) {
		mutex_init(I2OHBA_UTILPARAM_MUTEX(i2ohba, i), NULL,
		    MUTEX_DRIVER, NULL);
		cv_init(I2OHBA_UTILPARAM_CV(i2ohba, i), NULL,
		    CV_DRIVER, NULL);
	}

	/*
	 * Now allocated parameter for each qualified peripheral
	 */
	for (i = 0; i < entries; i++) {
		/*
		 * call i2ohba_utilparamget_msg to get
		 * parameters
		 */
		rval = i2ohba_utilparamget_msg(i2ohba, i, ALL_UTILPARAMS);
		if (rval) {
			i2ohba_i_log(NULL, CE_WARN, "?i2ohba_i_tid_to_scsi:"
			    " i2ohba_utilparamget_msg failed");
		}

	} /* for loop */

	if (i > 0)
		rval = 0;
	return (rval);

}

/*
 * Function name: i2ohba_utilcliam_msg()
 *
 * Return Values: 0 - success
 *		  -1 - fail to claim the device
 *
 * Description	: send a utilclaim or utilclaim_release msg
 *		  to the device
 *
 * This function is called from i2ohba_i_tid_to_scsi()
 */
static int
i2ohba_utilclaim_msg(struct i2ohba *i2ohba, uint16_t tid, int action)
{
	int			rval = -1;
	i2o_util_claim_message_t	*msgptr;
	i2o_msg_handle_t	msg_handle;
	ddi_acc_handle_t	acc_handle;
	struct i2ohba_util	*sp;

	if (i2o_msg_alloc(i2ohba->i2ohba_iophdl, I2O_MSG_SLEEP, NULL,
	    (void *)&msgptr, &msg_handle, &acc_handle) != DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_utilclaim_msg: "
		    "i2o_msg_alloc failed");
		return (rval);
	}

	/*
	 * construct a i2o_hba_bus_reset_message
	 */
	msgptr->StdMessageFrame.VersionOffset = 0x01;
	msgptr->StdMessageFrame.MsgFlags = 0;
	ddi_put16(acc_handle, &msgptr->StdMessageFrame.MessageSize,
	    sizeof (i2o_util_claim_message_t) >> 2);
	put_msg_TargetAddress(&msgptr->StdMessageFrame, tid, acc_handle);
	put_msg_InitiatorAddress(&msgptr->StdMessageFrame, I2O_OSM_TID,
	    acc_handle);
	put_msg_Function(&msgptr->StdMessageFrame, action, acc_handle);
	ddi_put32(acc_handle,
	    (uint32_t *)&msgptr->StdMessageFrame.InitiatorContext,
	    (uint32_t)i2ohba_utilmsg_comp);
	ddi_put8(acc_handle, &msgptr->ClaimType, I2O_CLAIM_TYPE_PRIMARY_USER);

	/*
	 * allocating synchronized status buffer
	 */
	sp = kmem_alloc(sizeof (struct i2ohba_util), KM_SLEEP);

	ddi_put32(acc_handle, &msgptr->TransactionContext,
	    (uint32_t)(uintptr_t)sp);

	/*
	 * initialized a mutex and cond variable to
	 * send message to IOP, and wait for it to signal back
	 */
	sp->mutex = I2OHBA_UTILPARAM_MUTEX(i2ohba, 0);
	sp->cv = I2OHBA_UTILPARAM_CV(i2ohba, 0);
	mutex_enter(sp->mutex);
	sp->wakeup = UTIL_MSG_SLEEP;
	sp->status = 0;
	(void) i2o_msg_send(i2ohba->i2ohba_iophdl, msgptr, msg_handle);
	while (!sp->wakeup)
		cv_wait(sp->cv, sp->mutex);
	mutex_exit(sp->mutex);

	/*
	 * process reply message
	 */

	switch (sp->status) {
		case I2O_REPLY_STATUS_SUCCESS:
			rval = 0;
			DEBUGF(1, (CE_CONT, "Reset Succeeded"));
			break;
		default:
			i2ohba_i_log(NULL, CE_CONT, "Reset Failed");
			/*
			 * Failed the reset for now,
			 * we can also parse the AdapterStatus
			 * and retry if needed
			 */
			break;
	}

cleanup:
	if (sp)
		kmem_free(sp, sizeof (struct i2ohba_util));
	return (rval);
}

/*
 * i2ohba_utilmsg_comp
 * 	passed the status back to the caller to decided
 *	what to do with the error code.
 */
/*ARGSUSED*/
static void
i2ohba_utilmsg_comp(i2o_message_frame_t *msg, ddi_acc_handle_t acc_handle)
{

	i2o_single_reply_message_frame_t  *reply;
	int	type, reqstatus, detailstatus, adptrstatus;
	struct i2ohba_util	*sp;


	reply = (i2o_single_reply_message_frame_t *)msg;
	sp = (struct i2ohba_util *)(uintptr_t)ddi_get32(acc_handle,
	    &reply->TransactionContext);

	type = get_msg_Function(&reply->StdMessageFrame, acc_handle);

	switch (type) {
	/*
	 * Bus Reset
	 */
	case I2O_HBA_BUS_RESET:
		detailstatus = ddi_get16(acc_handle,
		    &reply->DetailedStatusCode);
		adptrstatus = detailstatus & I2O_SCSI_HBA_DSC_MASK;
		if (adptrstatus != I2O_HBA_DSC_BUS_RESET)
			reqstatus = I2O_REPLY_STATUS_TRANSACTION_ERROR;
		else
			reqstatus = reply->ReqStatus;
		break;

	/*
	 * Utility Class Function
	 */
	case I2O_UTIL_PARAMS_GET:
	case I2O_UTIL_PARAMS_SET:
	case I2O_UTIL_CLAIM:
	case I2O_UTIL_CLAIM_RELEASE:
	/*
	 * Adapter Class Function
	 */
	case I2O_HBA_ADAPTER_RESET:
	case I2O_SCSI_DEVICE_RESET:
		reqstatus = reply->ReqStatus;
		break;

	default:
		DEBUGF(2, (CE_CONT, "Error! Not Supported"));
		return;

	}

	mutex_enter(sp->mutex);
	sp->wakeup = UTIL_MSG_WAKEUP;
	sp->status = reqstatus;
	cv_broadcast(sp->cv);
	mutex_exit(sp->mutex);
}

/*ARGSUSED*/
static int
i2ohba_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{

	struct i2ohba	*i2ohba;
	scsi_hba_tran_t	*tran;
	int		instance = ddi_get_instance(dip);
	int		i;

	switch (cmd) {
	case DDI_DETACH:
	{
		if ((tran = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);

		i2ohba = TRAN2I2OHBA(tran);
		if (!i2ohba) {
			return (DDI_FAILURE);
		}

		if (i2ohba->i2ohba_iophdl)
			i2o_msg_osm_unregister(&i2ohba->i2ohba_iophdl);

		/*
		 * deallocate reset notify callback list
		 */
		scsi_hba_reset_notify_tear_down(
		    i2ohba->i2ohba_reset_notify_listf);

		if (i2ohba->i2ohba_timeout_id != 0) {
			(void) untimeout(i2ohba->i2ohba_timeout_id);
			i2ohba->i2ohba_timeout_id = NULL;
		}

		/*
		 * remove device MT locks
		 */
		mutex_destroy(I2OHBA_REQ_MUTEX(i2ohba));
		mutex_destroy(I2OHBA_RESET_MUTEX(i2ohba));
		cv_destroy(I2OHBA_RESET_CV(i2ohba));

		for (i = 0; i < N_I2OHBA_TARGETS_WIDE; i++) {

			mutex_destroy(I2OHBA_UTILPARAM_MUTEX(i2ohba, i));
			cv_destroy(I2OHBA_UTILPARAM_CV(i2ohba, i));
		}

		/*
		 * remove properties created druing attach()
		 */
		ddi_prop_remove_all(dip);

		/*
		 * Delete the DMA limits, transport vectors and remove the
		 * device links to the scsi_transport layer.
		 *	-- ddi_set_driver_private(dip, NULL)
		 */
		(void) scsi_hba_detach(dip);

		/*
		 * Free the scsi_transport structure for this device.
		 */
		scsi_hba_tran_free(tran);

		i2ohba->i2ohba_dip = (dev_info_t *)NULL;
		i2ohba->i2ohba_tran = (scsi_hba_tran_t *)NULL;

		ddi_soft_state_free(i2ohba_state, instance);
		ddi_remove_minor_node(dip, NULL);

		return (DDI_SUCCESS);
	}
	/* XXXLWXXX */
	case DDI_SUSPEND:
	case DDI_PM_SUSPEND:
	default:
		return (DDI_FAILURE);
	}
}


/*
 * Function name : i2ohba_tran_tgt_init
 *
 * Return Values : DDI_SUCCESS if target supported, DDI_FAILURE otherwise
 *
 */
/*ARGSUSED*/
static int
i2ohba_tran_tgt_init(dev_info_t *hba_dip, dev_info_t *tgt_dip,
	scsi_hba_tran_t *tran, struct scsi_device *sd)
{
	return ((sd->sd_address.a_target < N_I2OHBA_TARGETS_WIDE &&
	    sd->sd_address.a_lun == 0)  ? DDI_SUCCESS :
	    DDI_FAILURE);
}


/*
 * Function name : i2ohba_i_initcap
 *
 * Return Values : NONE
 * Description	 : Initializes the default target capabilites and
 *		   Sync Rates.
 *
 * Context	 : Called from the user thread through attach.
 *
 */
static void
i2ohba_i_initcap(struct i2ohba *i2ohba)
{
	int i, option;
	uint16_t cap, synch;
	uint8_t offset;
	i2o_tid_scsi_ent_t **map = i2ohba->i2ohba_tgt_id_map;

	for (i = 0; i < N_I2OHBA_TARGETS_WIDE; i++) {
		cap = 0;
		synch = 0;
		option = 0;
		offset = 0;

		if (map[i] == NULL)
			continue;

		/*
		 * Check for connect/disconnect
		 */
		if (map[i]->scsi_info_scalar.Flags &
		    I2O_SCSI_ENABLE_DISCONNECT) {
			option |= SCSI_OPTIONS_DR;
			cap |= I2OHBA_CAP_DISCONNECT;
		} else {
			option &= ~SCSI_OPTIONS_DR;
		}

		/*
		 * Check for Wide data
		 */
		if (map[i]->scsi_info_scalar.Flags &
		    I2O_SCSI_DATA_WIDTH_MASK) {
			option |= SCSI_OPTIONS_WIDE;
			cap |= I2OHBA_CAP_WIDE;
		} else {
			option &= ~SCSI_OPTIONS_WIDE;
		}

		/*
		 * Check for synchronization
		 */
		if (map[i]->scsi_info_scalar.Flags &
		    I2O_SCSI_ENABLE_SYNC_NEGOTIATION) {
			option |= SCSI_OPTIONS_SYNC;
			cap |= I2OHBA_CAP_SYNC;
		} else {
			option &= ~SCSI_OPTIONS_SYNC;
		}

		synch = (uint16_t)map[i]->scsi_info_scalar.NegSyncRate;
		offset = (uint8_t)map[i]->scsi_info_scalar.NegOffset;

		/*
		 * Check for tag queuing capability
		 */
		if (map[i]->scsi_info_scalar.QueueDepth) {
			option |= SCSI_OPTIONS_TAG;
			cap |= I2OHBA_CAP_TAG;
		} else {
			option &= ~SCSI_OPTIONS_TAG;
		}

		i2ohba->i2ohba_target_scsi_option[i] = option;
		i2ohba->i2ohba_cap[i] = cap;
		i2ohba->i2ohba_synch[i] = synch;
		i2ohba->i2ohba_offset[i] = offset;
	}
}



/*
 * Function name : i2ohba_scsi_getcap()
 *
 * Return Values : current value of capability, if defined
 *		   -1 if capability is not defined
 *
 * Description	 : returns current capability value
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
static int
i2ohba_scsi_getcap(struct scsi_address *ap, char *cap, int whom)
{
	struct i2ohba	*i2ohba	= ADDR2I2OHBA(ap);
	i2o_tid_scsi_ent_t **map = i2ohba->i2ohba_tgt_id_map;
	uint8_t		tgt	= ap->a_target;
	int		rval	= 0;

	/*
	 * We don't allow inquiring about capabilities for other targets
	 */
	if (cap == NULL || whom == 0 || map[tgt] == NULL) {
		return (-1);
	}

	I2OHBA_MUTEX_ENTER(i2ohba);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_GEOMETRY:
	{ /* left this code from adp driver */
		uint32_t total_sectors, c, h, s, t;
		c = 1024L;
		s = 62L;

		total_sectors = i2ohba->i2ohba_totsec[tgt];

		t = c * s;
		h = total_sectors / t;
		if (total_sectors % t) {
			h ++;
			t = c * h;
			s = total_sectors / t;
			if (total_sectors % t) {
				s++;
				t = h * s;
				c = total_sectors / t;
			}
		}
		if (c == 0) rval = 1;

		rval = ((h << 16) | s);
		break;
	}
	case SCSI_CAP_DMA_MAX:
		rval = 1 << 24; /* Limit to 16MB max transfer */
		break;
	case SCSI_CAP_MSG_OUT:
		rval = 1;
		break;
	case SCSI_CAP_DISCONNECT:
		if ((i2ohba->i2ohba_target_scsi_option[tgt] &
		    SCSI_OPTIONS_DR) == 0) {
			break;
		} else if ((i2ohba->i2ohba_cap[tgt] & I2OHBA_CAP_DISCONNECT)
		    == 0) {
			break;
		}
		rval = 1;
		break;
	case SCSI_CAP_SYNCHRONOUS:
		if ((i2ohba->i2ohba_target_scsi_option[tgt] &
			SCSI_OPTIONS_SYNC) == 0) {
			break;
		} else if ((i2ohba->i2ohba_cap[tgt] & I2OHBA_CAP_SYNC) == 0) {
			break;
		}
		rval = 1;
		break;
	case SCSI_CAP_WIDE_XFER:
		if ((i2ohba->i2ohba_target_scsi_option[tgt] &
			SCSI_OPTIONS_WIDE) == 0) {
			break;
		} else if ((i2ohba->i2ohba_cap[tgt] & I2OHBA_CAP_WIDE) == 0) {
			break;
		}
		rval = 1;
		break;
	case SCSI_CAP_TAGGED_QING:
		if ((i2ohba->i2ohba_target_scsi_option[tgt] &
			SCSI_OPTIONS_DR) == 0 ||
		    (i2ohba->i2ohba_target_scsi_option[tgt] &
			SCSI_OPTIONS_TAG) == 0) {
			break;
		} else if ((i2ohba->i2ohba_cap[tgt] & I2OHBA_CAP_TAG) == 0) {
			break;
		}
		rval = 1;
		break;
	case SCSI_CAP_UNTAGGED_QING:
		rval = 0;
		break;
	case SCSI_CAP_PARITY:
		if (i2ohba->i2ohba_target_scsi_option[tgt] &
			SCSI_OPTIONS_PARITY) {
			rval = 1;
		}
		break;
	case SCSI_CAP_INITIATOR_ID:
		rval = i2ohba->i2ohba_initiator_id;
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

	I2OHBA_MUTEX_EXIT(i2ohba);

	return (rval);
}


/*
 * Function name : i2ohba_scsi_setcap()
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
i2ohba_scsi_setcap(struct scsi_address *ap, char *cap, int value, int whom)
{
	struct i2ohba	*i2ohba	= ADDR2I2OHBA(ap);
	i2o_tid_scsi_ent_t **map = i2ohba->i2ohba_tgt_id_map;
	uint8_t		tgt	= ap->a_target;
	int		update	= 0;
	int		sync	= 0;
	int		rval	= 0;

	/*
	 * We don't allow setting capabilities for other targets
	 * and the targets that are not in this OSM's control
	 */
	if (cap == NULL || whom == 0 || map[tgt] == NULL) {
		return (-1);
	}

	I2OHBA_MUTEX_ENTER(i2ohba);

	switch (scsi_hba_lookup_capstr(cap)) {
	case SCSI_CAP_DMA_MAX:
	case SCSI_CAP_MSG_OUT:
	case SCSI_CAP_PARITY:
	case SCSI_CAP_UNTAGGED_QING:
	case SCSI_CAP_LINKED_CMDS:
	case SCSI_CAP_RESET_NOTIFICATION:
	case SCSI_CAP_GEOMETRY:
		/*
		 * None of these are settable via
		 * the capability interface.
		 */
		break;

	case SCSI_CAP_SECTOR_SIZE:
		if (value) {
			i2ohba->i2ohba_secsz[tgt] = value;
			rval = 1;
		}
		break;

	case SCSI_CAP_TOTAL_SECTORS:
		if (value) {
			i2ohba->i2ohba_totsec[tgt] = value;
			rval = 1;
		}
		break;
	case SCSI_CAP_ARQ:
		if (value) {
			i2ohba->i2ohba_cap[tgt] |= I2OHBA_CAP_AUTOSENSE;
		} else {
			i2ohba->i2ohba_cap[tgt] &= ~I2OHBA_CAP_AUTOSENSE;
		}
		rval = 1;
		break;

	/* disconnect/reconncet either the target supports or doesn't */
	case SCSI_CAP_DISCONNECT:
		if ((i2ohba->i2ohba_target_scsi_option[tgt] &
			SCSI_OPTIONS_DR) == 0) {
			break;
		} else {
			if (value) {
				if ((i2ohba->i2ohba_cap[tgt] &
				    I2OHBA_CAP_DISCONNECT) == 0) {
					if (i2ohba_utilparamset_msg(i2ohba,
					    tgt, map[tgt]->tid,
					    I2O_SCSI_DEVICE_INFO_GROUP_NO, 0x1,
					    I2O_SCSI_ENABLE_DISCONNECT) != 0)
					break;
				i2ohba->i2ohba_cap[tgt] |=
				    I2OHBA_CAP_DISCONNECT;
				}
			} else {
				if ((i2ohba->i2ohba_cap[tgt] &
				    I2OHBA_CAP_DISCONNECT) == 1) {
					if (i2ohba_utilparamset_msg(i2ohba,
					    tgt, map[tgt]->tid,
					    I2O_SCSI_DEVICE_INFO_GROUP_NO, 0x1,
					    I2O_SCSI_DISABLE_DISCONNECT) != 0)
					break;
				i2ohba->i2ohba_cap[tgt] &=
				    ~I2OHBA_CAP_DISCONNECT;
				}
			}
		}
		rval = 1;
		break;

	/* these can be set through UtilParamSet message */
	case SCSI_CAP_SYNCHRONOUS:
		if ((i2ohba->i2ohba_target_scsi_option[tgt] &
			SCSI_OPTIONS_SYNC) == 0) {
			break;
		} else {
			if (value) {
				if ((i2ohba->i2ohba_cap[tgt] &
				    I2OHBA_CAP_SYNC) == 0) {
					if (i2ohba_utilparamset_msg(i2ohba,
					    tgt, map[tgt]->tid,
					    I2O_SCSI_DEVICE_INFO_GROUP_NO, 0x1,
					    I2O_SCSI_ENABLE_SYNC_NEGOTIATION)
					    != 0)
						break;
					/* set sync speed to Max */
					if (i2ohba_utilparamset_msg(i2ohba,
					    tgt, map[tgt]->tid,
					    I2O_SCSI_DEVICE_INFO_GROUP_NO, 0xA,
					    0xFFFF) != 0)
						break;
					/* read the set value */
					if (i2ohba_utilparamget_msg(i2ohba,
					    tgt, SYNC_UTILPARAM) != 0)
						break;
					i2ohba->i2ohba_cap[tgt] |=
					    I2OHBA_CAP_SYNC;
					sync++;
					update++;
				}
			} else {
				if ((i2ohba->i2ohba_cap[tgt] &
				    I2OHBA_CAP_SYNC) == 1) {
					if (i2ohba_utilparamset_msg(i2ohba,
					    tgt, map[tgt]->tid,
					    I2O_SCSI_DEVICE_INFO_GROUP_NO, 0x1,
					    I2O_SCSI_DISABLE_SYNC_NEGOTIATION)
					    != 0)
						break;
					i2ohba->i2ohba_cap[tgt] &=
					    ~I2OHBA_CAP_SYNC;
					update++;
				}
			}
		}
		rval = 1;
		break;
	case SCSI_CAP_TAGGED_QING:
		if ((i2ohba->i2ohba_target_scsi_option[tgt] &
			SCSI_OPTIONS_DR) == 0 ||
		    (i2ohba->i2ohba_target_scsi_option[tgt] &
			SCSI_OPTIONS_TAG) == 0) {
			break;
		} else {
			if (value) {
				if ((i2ohba->i2ohba_cap[tgt] &
				    I2OHBA_CAP_TAG) == 0) {
					if (i2ohba_utilparamset_msg(i2ohba,
					    tgt, map[tgt]->tid,
					    I2O_SCSI_DEVICE_INFO_GROUP_NO, 0x5,
					    0) != 0)
						break;
					i2ohba->i2ohba_cap[tgt] |=
					    I2OHBA_CAP_TAG;
					update++;
				}
			} else {
				if ((i2ohba->i2ohba_cap[tgt] &
				    I2OHBA_CAP_TAG) == 1) {
					if (i2ohba_utilparamset_msg(i2ohba,
					    tgt, map[tgt]->tid,
					    I2O_SCSI_DEVICE_INFO_GROUP_NO, 0x5,
					    (uint16_t)1) != 0)
						break;
					i2ohba->i2ohba_cap[tgt] &=
					    ~I2OHBA_CAP_TAG;
					update++;
				}
			}
		}
		rval = 1;
		break;
	case SCSI_CAP_WIDE_XFER:
		if ((i2ohba->i2ohba_target_scsi_option[tgt] &
			SCSI_OPTIONS_WIDE) == 0) {
			break;
		} else {
			if (value) {
				if ((i2ohba->i2ohba_cap[tgt] &
				    I2OHBA_CAP_WIDE) == 0) {
					if (i2ohba_utilparamset_msg(i2ohba,
					    tgt, map[tgt]->tid,
					    I2O_SCSI_DEVICE_INFO_GROUP_NO, 0x1,
					    I2O_SCSI_DATA_WIDTH_16) != 0)
						break;
					i2ohba->i2ohba_cap[tgt] |=
					    I2OHBA_CAP_WIDE;
					update++;
				}
			} else {
				if ((i2ohba->i2ohba_cap[tgt] &
				    I2OHBA_CAP_WIDE) == 1) {
					if (i2ohba_utilparamset_msg(i2ohba,
					    tgt, map[tgt]->tid,
					    I2O_SCSI_DEVICE_INFO_GROUP_NO, 0x1,
					    I2O_SCSI_DATA_WIDTH_8) != 0)
						break;
					i2ohba->i2ohba_cap[tgt] &=
					    ~I2OHBA_CAP_WIDE;
					update++;
				}
			}
		}
		rval = 1;
		break;
	case SCSI_CAP_INITIATOR_ID:
		if (value < N_I2OHBA_TARGETS_WIDE) {
			if (i2ohba->i2ohba_initiator_id != (uint16_t)value) {
				/*
				 * set Initiator SCSI ID
				 */
				if (i2ohba_utilparamset_msg(i2ohba,
				    i2ohba->i2ohba_initiator_id,
				    i2ohba->i2ohba_tid,
				    I2O_HBA_SCSI_CONTROLLER_INFO_GROUP_NO, 0x4,
				    value) == 0) {
					rval = 1;
					i2ohba->i2ohba_initiator_id = value;
				}
			}
		}
		break;

	default:
		rval = -1;
		break;
	}


	/*
	 * now set flag so latter in i2ohba_i_watch(),
	 * we can set prop_update
	 */
	if ((rval == 1) && (update > 0)) {
		i2ohba->i2ohba_need_prop_update |= 1 << tgt;
		if (sync)
			i2ohba_i_updatesync(i2ohba, tgt);
	}

	I2OHBA_MUTEX_EXIT(i2ohba);

	return (rval);
}

/*
 * Function name : i2ohba_i_updatesync()
 *
 * Return Values : -1 failed
 *		    0 success
 *
 * Description	 : modifies/update target sync mode speed, widexfer,
 *		   and TQ.
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can not be called by interrupt thread
 */
static void
i2ohba_i_updatesync(struct i2ohba *i2ohba, int tgt)
{
	uint16_t	synch;
	uint8_t		offset;
	i2o_tid_scsi_ent_t **map = i2ohba->i2ohba_tgt_id_map;

	if (map[tgt] == NULL)
		return;

	if (map[tgt]->scsi_info_scalar.Flags &
	    I2O_SCSI_ENABLE_SYNC_NEGOTIATION) {
		synch = (uint16_t)map[tgt]->scsi_info_scalar.NegSyncRate;
		offset = (uint8_t)map[tgt]->scsi_info_scalar.NegOffset;

		i2ohba->i2ohba_synch[tgt] = synch;
		i2ohba->i2ohba_offset[tgt] = offset;
	}
}

/*
 * Function name : i2ohba_i_update_props()
 *
 * Description	 : Creates/modifies/removes a target sync mode speed,
 *		   wide, and TQ properties
 *		   If offset is 0 then asynchronous mode is assumed and the
 *		   property is removed, if it existed.
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can not be called by interrupt thread
 */
static void
i2ohba_i_update_props(struct i2ohba *i2ohba, int tgt)
{
	static char	property[32];
	int		xfer_speed = 0;
	int		wide_enabled;
	int		tq_enabled;
	uint16_t	cap;
	uint16_t	synch;
	uint8_t	offset;

	cap = i2ohba->i2ohba_cap[tgt];
	synch = i2ohba->i2ohba_synch[tgt];
	offset = i2ohba->i2ohba_offset[tgt];

	tq_enabled = cap & I2OHBA_CAP_TAG;
	wide_enabled = cap & I2OHBA_CAP_WIDE;

	if (offset && synch) {
		if (wide_enabled) {
			/* double xfer speed if wide has been enabled */
			xfer_speed = ((int)synch  * 2);
		} else {
			xfer_speed = (int)(synch);
		}
	}

	(void) sprintf(property, "target%x-sync-speed", tgt);
	i2ohba_i_update_this_prop(i2ohba, property, xfer_speed);

	(void) sprintf(property, "target%x-wide", tgt);
	i2ohba_i_update_this_prop(i2ohba, property, wide_enabled);

	(void) sprintf(property, "target%x-TQ", tgt);
	i2ohba_i_update_this_prop(i2ohba, property, tq_enabled);
}

/*
 * Update a property's value
 */
static void
i2ohba_i_update_this_prop(struct i2ohba *i2ohba, char *property, int value)
{
	dev_info_t *dip = i2ohba->i2ohba_dip;


	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
	    property, value) != DDI_PROP_SUCCESS) {
		i2ohba_i_log(NULL, CE_CONT, "?i2ohba_i_update_this_prop:"
		    "  can't update %s property to 0x%x",
		    property, value);
	}
}


/*
 * Function name : i2ohba_scsi_init_pkt
 *
 * Return Values : pointer to scsi_pkt, or NULL
 * Description	 : Called by kernel on behalf of a target driver
 *		   calling scsi_init_pkt(9F).
 *		   Refer to tran_init_pkt(9E) man page
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
static struct scsi_pkt *
i2ohba_scsi_init_pkt(struct scsi_address *ap, struct scsi_pkt *pkt,
	struct buf *bp, int cmdlen, int statuslen, int tgtlen,
	int flags, int (*callback)(), caddr_t arg)
{
	struct i2ohba_cmd *sp;
	struct i2ohba	*i2ohba	= ADDR2I2OHBA(ap);
	struct scsi_pkt	*new_pkt;

	ASSERT(callback == NULL_FUNC || callback == SLEEP_FUNC);

	/*
	 * First step of i2ohba_scsi_init_pkt:  pkt allocation
	 */
	if (pkt == NULL) {
		pkt = scsi_hba_pkt_alloc(i2ohba->i2ohba_dip, ap, cmdlen,
		    statuslen, tgtlen, sizeof (struct i2ohba_cmd), callback,
		    arg);

		if (pkt == NULL) {
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
		sp->cmd_cdblen		= (uint8_t)cmdlen;
		sp->cmd_privlen		= tgtlen;
		sp->cmd_dmahandle	= NULL;
		sp->cmd_dmacount	= 0;
		sp->cmd_cookie		= 0;
		pkt->pkt_address	= *ap;
		pkt->pkt_comp		= (void (*)())NULL;
		pkt->pkt_flags		= 0;
		pkt->pkt_time		= 0;
		pkt->pkt_resid		= 0;
		pkt->pkt_statistics	= 0;
		pkt->pkt_reason		= 0;

		new_pkt = pkt;
	} else {
		sp = PKT2CMD(pkt);
		new_pkt = NULL;
	}

	/*
	 * Second step of i2ohba_scsi_init_pkt:  dma allocation/move
	 */
	if (bp && bp->b_bcount != 0) {
		if (sp->cmd_dmahandle == NULL) {
			ASSERT((sp->cmd_flags & CFLAG_DMAVALID) == 0);
			if (i2ohba_i_dma_alloc(i2ohba, pkt, bp,
			    flags, callback) == -1) {
				if (new_pkt) {
					scsi_hba_pkt_free(ap, new_pkt);
				}
				return ((struct scsi_pkt *)NULL);
			}
		} else {
			ASSERT(new_pkt == NULL);
			ASSERT(sp->cmd_flags & CFLAG_DMAVALID);
			if (i2ohba_i_dma_move(i2ohba, pkt, bp) < 0) {
				return ((struct scsi_pkt *)NULL);
			}
		}
		ASSERT(sp->cmd_flags & CFLAG_DMAVALID);
		DEBUGF(3, (CE_CONT, "init: bcount = %lx, resid = %lx",
		    bp->b_bcount, pkt->pkt_resid));
	}

	return (pkt);
}

/*
 * Function name : i2ohba_i_dma_alloc
 *
 * Return Values : 0 if successful, -1 if failure
 * Description	 : allocate DMA resources
 *
 * Context	 : Can only be called from i2ohba_scsi_init_pkt()
 */
static int
i2ohba_i_dma_alloc(struct i2ohba *i2ohba, struct scsi_pkt *pkt,
	struct buf *bp, int flags, int (*callback)())
{
	struct i2ohba_cmd *sp = PKT2CMD(pkt);
	int		dma_flags;
	int		(*cb)(caddr_t);
	int		i;

	ASSERT(callback == NULL_FUNC || callback == SLEEP_FUNC);

	if (bp->b_flags & B_READ) {
		sp->cmd_flags &= ~CFLAG_DMASEND;
		dma_flags = DDI_DMA_READ;
	} else {
		sp->cmd_flags |= CFLAG_DMASEND;
		dma_flags = DDI_DMA_WRITE;
	}

	if (flags & PKT_CONSISTENT) {
		sp->cmd_flags |= CFLAG_CMDIOPB;
		dma_flags |= DDI_DMA_CONSISTENT;
	}

	if (flags & PKT_DMA_PARTIAL) {
		dma_flags |= DDI_DMA_PARTIAL;
	}

	dma_flags |= DDI_DMA_REDZONE;

	cb = (callback == NULL_FUNC) ? DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

	if ((i = ddi_dma_alloc_handle(i2ohba->i2ohba_dip,
	    &i2ohba_dma_attr, cb, NULL, &sp->cmd_dmahandle))
	    != DDI_SUCCESS) {
		switch (i) {
		case DDI_DMA_BADATTR:
			bioerror(bp, EFAULT);
			return (-1);

		case DDI_DMA_NORESOURCES:
			bioerror(bp, 0);
			return (-1);

		default:
			i2ohba_i_log(NULL, CE_WARN,
			    "?ddi_dma_alloc_handle:"
			    " 0x%x impossible", i);
			/*NOTREACHED*/
		}
	}

#ifdef	I2OHBA_DEBUG
	ddi_dma_bufalloc++;
#endif

	i = ddi_dma_buf_bind_handle(sp->cmd_dmahandle, bp, dma_flags,
		cb, NULL, &sp->cmd_dmacookies[0], &sp->cmd_ncookies);
#ifdef	I2OHBA_DEBUG
	ddi_dma_buf_bind++;
#endif

	DEBUGF(3, (CE_CONT, "dma_alloc: cmd_ncookies is %d\n",
	    sp->cmd_ncookies));

	switch (i) {
	case DDI_DMA_PARTIAL_MAP:
		ASSERT(dma_flags & DDI_DMA_PARTIAL);

		if (ddi_dma_numwin(sp->cmd_dmahandle, &sp->cmd_nwin) ==
		    DDI_FAILURE) {
			i2ohba_i_log(NULL, CE_WARN,
			    "?ddi_dma_numwin() failed");
				/*NOTREACHED*/
		}

		if (ddi_dma_getwin(sp->cmd_dmahandle, sp->cmd_curwin,
		    &sp->cmd_dma_offset, &sp->cmd_dma_len,
		    &sp->cmd_dmacookies[0], &sp->cmd_ncookies) ==
		    DDI_FAILURE) {
			i2ohba_i_log(NULL, CE_WARN,
			    "?ddi_dma_getwin() failed");
				/*NOTREACHED*/
		}
		goto get_dma_cookies;

	case DDI_DMA_MAPPED:
		sp->cmd_nwin = 1;
		sp->cmd_dma_len = 0;
		sp->cmd_dma_offset = 0;

get_dma_cookies:
		i = 0;
		sp->cmd_dmacount = 0;
		for (;;) {
			sp->cmd_dmacount += sp->cmd_dmacookies[i++].dmac_size;

			if (i == I2OHBA_CMD_NSEGS || i == sp->cmd_ncookies)
				break;
			ddi_dma_nextcookie(sp->cmd_dmahandle,
				&sp->cmd_dmacookies[i]);
		}

		sp->cmd_cookie = i;
		sp->cmd_cookiecnt = i;

		sp->cmd_flags |= CFLAG_DMAVALID;
		pkt->pkt_resid = bp->b_bcount - sp->cmd_dmacount;

		DEBUGF(3, (CE_CONT, "bcount is %lx, dmacount is %lx,"
			" resid is %lx\n",
			bp->b_bcount, sp->cmd_dmacount, pkt->pkt_resid));

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
		i2ohba_i_log(NULL, CE_WARN, "?ddi_dma_buf_bind_handle:"
			" DDI_DMA_INUSE impossible");
		/*NOTREACHED*/

	default:
		i2ohba_i_log(NULL, CE_WARN, "?ddi_dma_buf_bind_handle:"
			" 0x%x impossible", i);
		/*NOTREACHED*/
	}

	ddi_dma_free_handle(&sp->cmd_dmahandle);
	sp->cmd_dmahandle = NULL;
	sp->cmd_flags &= ~CFLAG_DMAVALID;
	return (-1);
}


/*
 * Function name : i2ohba_i_dma_move
 *
 * Return Values : 0 if successful, -1 if failure
 * Description	 : move DMA resources to next DMA window
 *
 * Context	 : Can only be called from i2ohba_scsi_init_pkt()
 */
/*ARGSUSED*/
static int
i2ohba_i_dma_move(struct i2ohba *i2ohba, struct scsi_pkt *pkt, struct buf *bp)
{
	struct i2ohba_cmd	*sp		= PKT2CMD(pkt);
	int		i;

	ASSERT(sp->cmd_flags & CFLAG_COMPLETED);
	sp->cmd_flags &= ~CFLAG_COMPLETED;

	/*
	 * If there are no more cookies remaining in this window,
	 * must move to the next window first.
	 */
	if (sp->cmd_cookie == sp->cmd_ncookies) {
		/*
		 * 1217340: cmdk reuses pkts incorrectly
		 */
		if (sp->cmd_curwin == sp->cmd_nwin && sp->cmd_nwin == 1)
			return (0);

		/*
		 * At last window, cannot move
		 */
		if (++sp->cmd_curwin >= sp->cmd_nwin)
			return (-1);

		if (ddi_dma_getwin(sp->cmd_dmahandle, sp->cmd_curwin,
		    &sp->cmd_dma_offset, &sp->cmd_dma_len,
		    &sp->cmd_dmacookies[0], &sp->cmd_ncookies) == DDI_FAILURE)
			return (-1);

		sp->cmd_cookie = 0;
	} else {
		/*
		 * Still more cookies in this window - get the next one
		 */
		ddi_dma_nextcookie(sp->cmd_dmahandle, &sp->cmd_dmacookies[0]);
	}

	/*
	 * Get remaining cookies in this window, up to our maximum
	 */
	i = 0;
	for (;;) {
		sp->cmd_dmacount += sp->cmd_dmacookies[i++].dmac_size;
		sp->cmd_cookie++;
		if (i == I2OHBA_CMD_NSEGS || sp->cmd_cookie == sp->cmd_ncookies)
			break;
		ddi_dma_nextcookie(sp->cmd_dmahandle, &sp->cmd_dmacookies[i]);
	}
	sp->cmd_cookiecnt = i;

	pkt->pkt_resid = bp->b_bcount - sp->cmd_dmacount;
	return (0);
}


/*
 * Function name : i2ohba_scsi_destroy_pkt
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
i2ohba_scsi_destroy_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct i2ohba_cmd *sp = PKT2CMD(pkt);
	struct i2ohba	*i2ohba	= ADDR2I2OHBA(ap);
	i2o_tid_scsi_ent_t **map = i2ohba->i2ohba_tgt_id_map;
	uint8_t		tgt	= ap->a_target;

	if (map[tgt] != NULL) {

		/*
		 * i2o_scsi_dmafree inline to make things faster
		 */
		if (sp->cmd_flags & CFLAG_DMAVALID) {
			/*
			 * Free the mapping
			 */
			sp->cmd_flags &= ~CFLAG_DMAVALID;
			if (ddi_dma_unbind_handle(sp->cmd_dmahandle)
				    != DDI_SUCCESS) {
				i2ohba_i_log(NULL, CE_WARN,
				    "?i2ohba_scsi_destroy_pkt: "
				    "ddi_dma_unbind_handle() for dataseg"
				    " failed");
				/*NOTREACHED*/
			}
#ifdef	I2OHBA_DEBUG
			ddi_dma_buf_unbind++;
#endif
			ddi_dma_free_handle(&sp->cmd_dmahandle);
#ifdef	I2OHBA_DEBUG
			ddi_dma_buf_free_hdl++;
#endif
			sp->cmd_dmahandle = NULL;
		}
	}

	/*
	 * Free the pkt
	 */
	scsi_hba_pkt_free(ap, pkt);
}


/*
 * Function name : i2ohba_scsi_dmafree()
 *
 * Return Values : none
 * Description	 : free dvma resources
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
/*ARGSUSED*/
static void
i2ohba_scsi_dmafree(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct i2ohba_cmd *sp = PKT2CMD(pkt);
	struct i2ohba	*i2ohba	= ADDR2I2OHBA(ap);
	i2o_tid_scsi_ent_t **map = i2ohba->i2ohba_tgt_id_map;
	uint8_t		tgt	= ap->a_target;

	if (map[tgt] != NULL) {
		if (sp->cmd_flags & CFLAG_DMAVALID) {
			/*
			 * Free the mapping.
			 */
			sp->cmd_flags &= ~CFLAG_DMAVALID;
			if (ddi_dma_unbind_handle(sp->cmd_dmahandle)
			    != DDI_SUCCESS) {
				i2ohba_i_log(NULL, CE_WARN,
				    "?i2ohba_scsi_dmafree: "
				    "ddi_dma_unbind_handle() for dataseg"
				    " failed");
				/*NOTREACHED*/
			}
#ifdef	I2OHBA_DEBUG
			ddi_dma_buf_unbind++;
#endif
			ddi_dma_free_handle(&sp->cmd_dmahandle);
#ifdef	I2OHBA_DEBUG
			ddi_dma_buf_free_hdl++;
#endif
			sp->cmd_dmahandle = NULL;
		}
	}
}

/*
 * Function name: i2ohba_scsi_sync_pkt()
 *
 * Return Values: none
 * Description	: sync dma
 *
 * Context	: Can be called from different kernel process threads.
 *		  Can be called by interrupt thread.
 */
/*ARGSUSED*/
static void
i2ohba_scsi_sync_pkt(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	int i;
	struct i2ohba_cmd *sp = PKT2CMD(pkt);
	struct i2ohba	*i2ohba	= ADDR2I2OHBA(ap);
	i2o_tid_scsi_ent_t **map = i2ohba->i2ohba_tgt_id_map;
	uint8_t		tgt	= ap->a_target;

	if (map[tgt] != NULL) {
		if (sp->cmd_flags & CFLAG_DMAVALID) {
			i = ddi_dma_sync(sp->cmd_dmahandle, sp->cmd_dma_offset,
				sp->cmd_dma_len,
				(sp->cmd_flags & CFLAG_DMASEND) ?
				DDI_DMA_SYNC_FORDEV : DDI_DMA_SYNC_FORCPU);
			if (i != DDI_SUCCESS) {
				i2ohba_i_log(NULL, CE_WARN,
				    "?i2ohba_scsi_sync_pkt: sync pkt failed");
			}
		}
	}
}


/*
 * routine for reset notification setup, to register or cancel.
 */
static int
i2ohba_scsi_reset_notify(struct scsi_address *ap, int flag,
void (*callback)(caddr_t), caddr_t arg)
{
	struct i2ohba			*i2ohba = ADDR2I2OHBA(ap);
	return (scsi_hba_reset_notify_setup(ap, flag, callback, arg,
	    I2OHBA_REQ_MUTEX(i2ohba), &i2ohba->i2ohba_reset_notify_listf));
}

/*
 * Function name : i2ohba_scsi_start()
 *
 * Return Values : TRAN_FATAL_ERROR	- i2o has been shutdown
 *		   TRAN_BUSY		- request queue is full
 *		   TRAN_ACCEPT		- pkt has been submitted to i2o
 *
 * Description	 : init pkt, start the request
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
static int
i2ohba_scsi_start(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct i2ohba_cmd	*sp	= PKT2CMD(pkt);
	int			rval	= TRAN_ACCEPT;
	struct i2ohba		*i2ohba	= ADDR2I2OHBA(ap);
	dev_info_t		*dip	= (PKT2I2OHBA(pkt))->i2ohba_dip;
	i2o_tid_scsi_ent_t **tgtmap	= i2ohba->i2ohba_tgt_id_map;
	i2o_scsi_scb_execute_message_t	*req;
	i2o_sge_chain_element_t		*sgl;
	i2o_sge_ignore_element_t	*sgl2;
	i2o_msg_handle_t		msg_handle;
	i2o_sge_chain_element_t 	*cpsgl;
	ddi_acc_handle_t		acc_handle;
	clock_t			cur_lbolt;
	uint16_t		tid;
	uint16_t		flags = 0, msgsize;
	int			i, val, bound = 0;
	size_t			sglen;
	uint_t			count;


	ASSERT(I2OHBA_MUTEX_OWNED(i2ohba) == 0 || ddi_in_panic());

	/*
	 * if we have a shutdown, return packet
	 */
	if (i2ohba->i2ohba_shutdown) {
		return (TRAN_FATAL_ERROR);
	}

	if (i2ohba->i2ohba_throttle) {
		return (TRAN_BUSY);
	}
	/*
	 * if the target id is not in our map, don't bother composing
	 * the message, return fail
	 */
	if (tgtmap[TGT(sp)] == NULL) {
		return (TRAN_FATAL_ERROR);
	} else {
		tid = tgtmap[TGT(sp)]->tid;
	}

	i2ohba->i2ohba_counter++;
	if (i2ohba->i2ohba_counter > 64) {
		DEBUGF(1, (CE_CONT, "i2ohba_counter > 64\n"));
		DEBUGF(1, (CE_CONT, "sp = %p\n", (void *)sp));
		i2ohba->i2ohba_counter--;
		return (TRAN_BUSY);
	}

	ASSERT(!(sp->cmd_flags & CFLAG_IN_TRANSPORT));
	sp->cmd_flags = (sp->cmd_flags & ~CFLAG_TRANFLAG) |
			    CFLAG_IN_TRANSPORT;
	pkt->pkt_reason = CMD_CMPLT;

	/*
	 * Set up request in i2ohba_reqhead area so it is ready to
	 * go once we have the request mutex,
	 * The reason we don't allocate the msg buffer in scsi_init_pkt
	 * is that the msg buffer is a resource from the FIFO of the IOP
	 * we don't want to give that ptr around
	 */

	if (i2o_msg_alloc(i2ohba->i2ohba_iophdl, I2O_MSG_DONTWAIT,
	    NULL, (void *)&req, &msg_handle, &acc_handle) != DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_scsi_start: "
		    " i2o_msg_alloc failed");
		sp->cmd_flags = (sp->cmd_flags & ~CFLAG_IN_TRANSPORT);
		pkt->pkt_reason = 0;
		i2ohba->i2ohba_counter--;
		return (TRAN_BUSY);
	}


	/*
	 * Constructed a scsi_scb_execute_message
	 */

	/* StdMessageFrame */
	req->StdMessageFrame.VersionOffset = 0xA1;
	req->StdMessageFrame.MsgFlags = 0;

	if (sp->cmd_flags & CFLAG_DMAVALID) {
		msgsize = ((sizeof (i2o_scsi_scb_execute_message_t) -
		    sizeof (i2o_sg_element_t) +
		    sizeof (i2o_sge_chain_element_t) +
		    sizeof (i2o_sge_ignore_element_t)) >> 2);
	} else {
		msgsize = ((sizeof (i2o_scsi_scb_execute_message_t) -
		    sizeof (i2o_sg_element_t)) >> 2);
	}

	/*
	 * To get actual allocation msg size
	 */
	ASSERT(msgsize <= ddi_get16(acc_handle,
	    &req->StdMessageFrame.MessageSize));

	ddi_put16(acc_handle, &req->StdMessageFrame.MessageSize, msgsize);
	put_msg_TargetAddress(&req->StdMessageFrame, tid, acc_handle);
	put_msg_InitiatorAddress(&req->StdMessageFrame, I2O_OSM_TID,
	    acc_handle);
	put_msg_Function(&req->StdMessageFrame, I2O_SCSI_SCB_EXEC, acc_handle);
	ddi_put32(acc_handle,
	    (uint32_t *)&req->StdMessageFrame.InitiatorContext,
	    (uint32_t)i2ohba_callback);

	/* TransactionContext */
	ddi_put32(acc_handle, &req->TransactionContext,
	    (uint32_t)(uintptr_t)sp);

	/* Set up CDB in the request */

	bzero(req->CDB, I2O_SCSI_CDB_LENGTH);
	if (sp->cmd_cdblen > I2O_SCSI_CDB_LENGTH) {
		req->CDBLength = I2O_SCSI_CDB_LENGTH;
	} else {
		req->CDBLength = sp->cmd_cdblen;
	}
	bcopy(pkt->pkt_cdbp, req->CDB, sp->cmd_cdblen);
	bcopy(pkt->pkt_cdbp, sp->cmd_cdb, sp->cmd_cdblen);

#ifdef I2OHBA_DEBUG
	if (sp->cmd_cdblen == 0x6) {
		DEBUGF(1, (CE_CONT, "%d: %x %x %x %x %x %x\n",
			    sp->cmd_cdblen,
			    pkt->pkt_cdbp[0], pkt->pkt_cdbp[1],
			    pkt->pkt_cdbp[2], pkt->pkt_cdbp[3],
			    pkt->pkt_cdbp[4], pkt->pkt_cdbp[5]));
	} else {
		DEBUGF(1, (CE_CONT, "10: %x %x %x %x %x %x %x %x %x %x\n",
			    pkt->pkt_cdbp[0], pkt->pkt_cdbp[1],
			    pkt->pkt_cdbp[2], pkt->pkt_cdbp[3],
			    pkt->pkt_cdbp[4], pkt->pkt_cdbp[5],
			    pkt->pkt_cdbp[6], pkt->pkt_cdbp[7],
			    pkt->pkt_cdbp[8], pkt->pkt_cdbp[9]));
	}
#endif

	DEBUGF(1, (CE_CONT, "pkt_flags = 0x%x\n", pkt->pkt_flags));
	/* Tag queuing */
	if (pkt->pkt_flags & FLAG_STAG)
		flags |= I2O_SCB_FLAG_SIMPLE_QUEUE_TAG;

	else if (pkt->pkt_flags & FLAG_OTAG)
		flags |= I2O_SCB_FLAG_ORDERED_QUEUE_TAG;

	else if (pkt->pkt_flags & FLAG_HTAG)
		flags |= I2O_SCB_FLAG_HEAD_QUEUE_TAG;

	else if (pkt->pkt_flags & FLAG_ACA)
		flags |= I2O_SCB_FLAG_ACA_QUEUE_TAG;

	if ((pkt->pkt_flags & FLAG_SENSING) ||
	    (i2ohba->i2ohba_cap[TGT(sp)] & I2OHBA_CAP_AUTOSENSE))
		flags |= I2O_SCB_FLAG_SENSE_DATA_IN_MESSAGE;

	/* DISCONNECT enable by default especially with TAGQ */
	if (pkt->pkt_flags & FLAG_NODISCON)
		flags &= ~I2O_SCB_FLAG_ENABLE_DISCONNECT;
	else
		flags |= I2O_SCB_FLAG_ENABLE_DISCONNECT;

	if (sp->cmd_flags & CFLAG_DMASEND) {
		flags |= I2O_SCB_FLAG_XFER_TO_DEVICE;
	} else {
		flags |= I2O_SCB_FLAG_XFER_FROM_DEVICE;
	}

	ddi_put16(acc_handle, &req->SCBFlags, flags);
	DEBUGF(1, (CE_CONT, "SCBflags = 0x%x\n", flags));

	/*
	 * All msg are using chain pointer.
	 * Setup dma transfers data segments.
	 */

	sgl = (i2o_sge_chain_element_t *)&req->SGL;
	sgl2 = (i2o_sge_ignore_element_t *)((caddr_t)sgl +
	    sizeof (i2o_sge_chain_element_t));
	if (sp->cmd_flags & CFLAG_DMAVALID) {

		if (sp->cmd_flags & CFLAG_CMDIOPB) {
			(void) ddi_dma_sync(sp->cmd_dmahandle,
			    sp->cmd_dma_offset, sp->cmd_dma_len,
			    DDI_DMA_SYNC_FORDEV);
		}

		ASSERT(sp->cmd_cookiecnt > 0);

		/* size of the next SGL chain elements list */
		sglen = sp->cmd_cookiecnt * sizeof (i2o_sge_chain_element_t);

		/* flags */
		put_flags_count_Flags(&sgl->FlagsCount,
		    I2O_SGL_FLAGS_CHAIN_POINTER_ELEMENT, acc_handle);

		/*
		 * instead of allocating a chuck of dma
		 * address here like isp driver, the
		 * trade of speed vs managing the free
		 * memory list.  I don't want this
		 * to become kmem_alloc functions.
		 */
		if (ddi_dma_alloc_handle(dip, &i2ohba_dmasgl_attr,
		    DDI_DMA_DONTWAIT, NULL, &sp->sglbuf_dmahandle)
		    != DDI_SUCCESS) {
			i2ohba_i_log(NULL, CE_WARN, "?i2ohba_scsi_start: "
			    "cannot allocate SGL's chain buffer handle");
			goto cleanup;
		}
		bound++;
#ifdef	I2OHBA_DEBUG
		ddi_dma_alloc_hdl++;
#endif

		if (ddi_dma_mem_alloc(sp->sglbuf_dmahandle, (size_t)
		    sglen, &dev_attr, DDI_DMA_STREAMING, DDI_DMA_DONTWAIT,
		    NULL, (caddr_t *)&sp->sglbuf, &sp->sglrlen,
		    &sp->sglbuf_dmaacchandle) != DDI_SUCCESS) {
			i2ohba_i_log(NULL, CE_WARN, "?i2ohba_scsi_start: "
			    "cannot allocate SGL's chain buffer memory");
			goto cleanup;
		}
		bound++;
#ifdef	I2OHBA_DEBUG
		ddi_dma_alloc_mem++;
#endif

		/*
		 * we passed in the sgl real length in transaction
		 * context because we need it to free the dma,
		 * but we set the chain element header with sglen
		 */
		put_flags_count_Count(&sgl->FlagsCount, sglen, acc_handle);

		put_flags_count_Flags(&sgl2->FlagsCount,
		    I2O_SGL_FLAGS_IGNORE_ELEMENT |
		    I2O_SGL_FLAGS_LAST_ELEMENT, acc_handle);

		put_flags_count_Count(&sgl2->FlagsCount, 0x1, acc_handle);

		/* fill in the SGL chain headers */
		sp->cmd_xfercount = 0;
		cpsgl = (i2o_sge_chain_element_t *)sp->sglbuf;

		for (i = 0; i < sp->cmd_cookiecnt; i++, cpsgl++) {

			put_flags_count_Flags(&cpsgl->FlagsCount,
			    I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT,
			    sp->sglbuf_dmaacchandle);

			put_flags_count_Count(&cpsgl->FlagsCount,
			    sp->cmd_dmacookies[i].dmac_size,
			    sp->sglbuf_dmaacchandle);

			ddi_put32(sp->sglbuf_dmaacchandle,
			    &cpsgl->PhysicalAddress,
			    sp->cmd_dmacookies[i].dmac_address);

			sp->cmd_xfercount +=
				sp->cmd_dmacookies[i].dmac_size;
		}

		DEBUGF(3, (CE_CONT, "cookiecnt is %x, ncookie is %x,"
		    "cookie# is %d\n", sp->cmd_cookiecnt, sp->cmd_ncookies,
		    sp->cmd_cookie));
		DEBUGF(3, (CE_CONT, "cmd_xfercount is %lx\n",
		    sp->cmd_xfercount));


		/* mark the last chain pointer header as the last one */

		cpsgl--;
		put_flags_count_Flags(&cpsgl->FlagsCount,
		    I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT |
		    I2O_SGL_FLAGS_LAST_ELEMENT | I2O_SGL_FLAGS_END_OF_BUFFER,
		    sp->sglbuf_dmaacchandle);

		if (ddi_dma_addr_bind_handle(sp->sglbuf_dmahandle, NULL,
		    (caddr_t)sp->sglbuf, sp->sglrlen, DDI_DMA_RDWR |
		    DDI_DMA_STREAMING, DDI_DMA_DONTWAIT, NULL,
		    &sp->sglbuf_dmacookie, &count) != DDI_DMA_MAPPED) {
			i2ohba_i_log(NULL, CE_WARN, "?i2ohba_scsi_start: "
			    "cannot bind SGL's bind handle");
			goto cleanup;
		}
#ifdef	I2OHBA_DEBUG
		ddi_dma_bind_hdl++;
#endif

		DEBUGF(1, (CE_CONT, "start: cmd_dmacount=%lx,"
			    " cmd_xfercount=%lx\n",
			    sp->cmd_dmacount, sp->cmd_xfercount));

		ddi_put32(acc_handle, &req->ByteCount, sp->cmd_xfercount);

		ddi_put32(acc_handle, &sgl->PhysicalAddress,
		    (uint32_t)sp->sglbuf_dmacookie.dmac_address);

	} else {
		ddi_put32(acc_handle, &req->ByteCount, 0);
		put_flags_count_Flags(&sgl->FlagsCount, 0, acc_handle);
		put_flags_count_Count(&sgl->FlagsCount, 0, acc_handle);
		put_flags_count_Flags(&sgl2->FlagsCount, 0, acc_handle);
		put_flags_count_Count(&sgl2->FlagsCount, 0, acc_handle);
	}

	/*
	 * calculate deadline from pkt_time
	 * Instead of multiplying by 100 (ie. HZ), we multiply by 128 so
	 * we can shift and at the same time have a 28% grace period
	 * we ignore the rare case of pkt_time == 0 and deal with it
	 * in i2ohba_i_watch()
	 */
	cur_lbolt = ddi_get_lbolt();
	sp->cmd_deadline = cur_lbolt + (clock_t)(pkt->pkt_time * 256);

	I2OHBA_MUTEX_ENTER(i2ohba);
	(void) i2ohba_i_req_insert(i2ohba, sp);
	I2OHBA_MUTEX_EXIT(i2ohba);
	/*
	 * Start the cmd.  If NO_INTR, must wait for cmd reply/completion.
	 */
	if ((pkt->pkt_flags & FLAG_NOINTR) == 0) {

		/*
		 * need a list (or some sort of queue) so that
		 * when we need to flash the queue, ie: SCSI_BUS_RESET
		 * we'll have a way to do it (link list)
		 */
		val = i2o_msg_send(i2ohba->i2ohba_iophdl, req, msg_handle);
		if (val != DDI_SUCCESS)
			rval = TRAN_BUSY; /* I/O couldnot be started */
	} else {
		val = i2o_msg_send(i2ohba->i2ohba_iophdl, req, msg_handle);
		/*  poll command */
		if (val == DDI_SUCCESS) {
			i2ohba_i_polled_cmd_start(i2ohba, sp);
		} else {
			rval = TRAN_BUSY;
		}
	}
	return (rval);

cleanup:

	if (sp) {
		if (bound) {
			(void) ddi_dma_unbind_handle(sp->sglbuf_dmahandle);
#ifdef I2OHBA_DEBUG
			ddi_dma_unbind++;
#endif
			if (bound > 1) {
				ddi_dma_mem_free(&sp->sglbuf_dmaacchandle);
#ifdef I2OHBA_DEBUG
				ddi_dma_free_mem++;
#endif
			}
			ddi_dma_free_handle(&sp->sglbuf_dmahandle);
#ifdef I2OHBA_DEBUG
			ddi_dma_bind_free++;
#endif
		}

		sp->cmd_flags = (sp->cmd_flags & ~CFLAG_IN_TRANSPORT);
		i2ohba->i2ohba_counter--;
		pkt->pkt_reason = 0;
	}

	/* return MFA to IOP */
	if (req) {
		req->StdMessageFrame.VersionOffset = 0;
		req->StdMessageFrame.MsgFlags = 0;
		ddi_put16(acc_handle, &req->StdMessageFrame.MessageSize, 3);
		put_msg_TargetAddress(&req->StdMessageFrame, 0, acc_handle);
		put_msg_InitiatorAddress(&req->StdMessageFrame, 0, acc_handle);
		put_msg_Function(&req->StdMessageFrame, I2O_UTIL_NOP,
		    acc_handle);
		(void) i2o_msg_send(i2ohba->i2ohba_iophdl, req, msg_handle);
	}

	ASSERT(I2OHBA_MUTEX_OWNED(i2ohba) == 0 || ddi_in_panic());
	return (TRAN_BUSY);
}


/*
 * Function name : i2ohba_i_req_insert()
 *
 * Return Values : void
 *
 * Usage	 : called by i2ohba_scsi_start().
 *
 * Description	 : Insert the i2ohba_cmd into the double
 *		   link list in FIFO fashion.
 *
 * Context	 : called by SCSA frame work.
 */
static void
i2ohba_i_req_insert(struct i2ohba *i2ohba, struct i2ohba_cmd *sp)
{
	struct i2ohba_cmd 	*head = i2ohba->i2ohba_reqhead;

	sp->cmd_forw = head;
	if (head != NULL) {
		i2ohba->i2ohba_reqhead->cmd_backw = sp;
	} else {
		i2ohba->i2ohba_reqtail = sp;
	}
	i2ohba->i2ohba_reqhead = sp;
	sp->cmd_backw = NULL;

}


/*
 * Function name : i2ohba_i_req_remove()
 *
 * Return Values : void
 *
 * Usage	 : called by i2ohba_callback().
 *		   called by i2ohba_scsi_start() if i2o_msg_send()
 *			failed.
 * Description	 : remove a i2ohba_cmd from the double link list
 *
 * Context	 : called by SCSA frame work.
 */
static void
i2ohba_i_req_remove(struct i2ohba *i2ohba, struct i2ohba_cmd *sp)
{
	struct i2ohba_cmd	*tail = i2ohba->i2ohba_reqtail;
	struct i2ohba_cmd	*tmp;

	for (tmp = tail; tmp != NULL; tmp = tmp->cmd_backw) {
		if (tmp == sp) {
			if (tmp->cmd_backw)
				tmp->cmd_backw->cmd_forw = tmp->cmd_forw;
			else
				i2ohba->i2ohba_reqhead = tmp->cmd_forw;

			if (tmp->cmd_forw)
				tmp->cmd_forw->cmd_backw = tmp->cmd_backw;
			else
				i2ohba->i2ohba_reqtail = tmp->cmd_backw;

			tmp->cmd_backw = NULL;
			tmp->cmd_forw  = NULL;
			break;

		}
	}
}

/*
 * Function name : i2ohba_callback()
 *
 * Return Values : None
 *
 * Context:	 : called by interrupt thread.
 */

void
i2ohba_callback(i2o_message_frame_t *msg, ddi_acc_handle_t acc_handle)
{

	i2o_single_reply_message_frame_t	*reply;
	struct i2ohba *i2ohba;
	struct scsi_pkt *pkt;
	struct	i2ohba_cmd *sp;
	uint8_t	reqstatus;

	reply = (i2o_single_reply_message_frame_t *)msg;


	ASSERT(I2O_SCSI_SCB_EXEC == get_msg_Function(
	    &reply->StdMessageFrame, acc_handle));

	sp = (struct i2ohba_cmd *)(uintptr_t)ddi_get32(acc_handle,
	    &reply->TransactionContext);

	ASSERT(sp);

	i2ohba = CMD2I2OHBA(sp);
	I2OHBA_MUTEX_ENTER(i2ohba);
	(void) i2ohba_i_req_remove(i2ohba, sp);
	I2OHBA_MUTEX_EXIT(i2ohba);

	if (sp->cmd_dmahandle) {
		(void) ddi_dma_sync(sp->cmd_dmahandle,
		    sp->cmd_dma_offset, sp->cmd_dma_len,
		    DDI_DMA_SYNC_FORKERNEL);
	}

	reqstatus = ddi_get8(acc_handle, &reply->ReqStatus);
	DEBUGF(1, (CE_CONT, "reqstatus %x\n", reqstatus));
	pkt = CMD2PKT(sp);

	/*
	 * First filter the reqstatus
	 * check for any special errors
	 */
	switch (reqstatus) {

		case I2O_REPLY_STATUS_ERROR_PARTIAL_TRANSFER:
		/*
		 * With paritial transfer, we want to make
		 * sure it is an USCSI cmd
		 */
			if ((pkt->pkt_flags >> 16) == 0)
				pkt->pkt_reason = CMD_TRAN_ERR;

			sp->cmd_flags |= CFLAG_FINISHED;
			i2ohba_i_pkt_comp(reply, acc_handle, sp);

			return;

		case I2O_REPLY_STATUS_SUCCESS:
		/*
		 * With successful completetion, only the ReqStatus
		 * field is set to reflect sucessful completion, the
		 * DetailedStatusCode is set to zero, the TransferCount
		 * field indicates the actual amount of data transferred.
		 * There is no StatusData.
		 */

			sp->cmd_flags |= CFLAG_FINISHED;
			i2ohba_i_pkt_comp(reply, acc_handle, sp);

			return;

		/* XXLWXX Error code handling */
		case I2O_REPLY_STATUS_ABORT_DIRTY:
		case I2O_REPLY_STATUS_ABORT_NO_DATA_TRANSFER:
		case I2O_REPLY_STATUS_ERROR_DIRTY:
		case I2O_REPLY_STATUS_ERROR_NO_DATA_TRANSFER:
		case I2O_REPLY_STATUS_PROCESS_ABORT_DIRTY:
		case I2O_REPLY_STATUS_PROCESS_ABORT_NO_DATA_TRANSFER:
		case I2O_REPLY_STATUS_PROCESS_ABORT_PARTIAL_TRANSFER:
		case I2O_REPLY_STATUS_PROGRESS_REPORT:
		/*
		 * If message has failed due to aborted by hosts,
		 * error in execution, due to system command or reconfig.
		 * failed the request.
		 */
		case I2O_REPLY_STATUS_TRANSACTION_ERROR:
		default:
			pkt->pkt_reason = CMD_TRAN_ERR;
			sp->cmd_flags |= CFLAG_FINISHED;
			i2ohba_i_pkt_comp(reply, acc_handle, sp);
#ifdef I2OHBA_DEBUG
			DEBUGF(1, (CE_CONT,
			    "?i2ohba_callback: Reply Failed"));
#endif
			break;

	}
}

/*
 * Function name : i2ohba_i_pkt_complete()
 *
 * Return Values : none
 *
 * Description	 :
 *		   callback into target driver
 *		   argument is a  NULL-terminated list of packets
 *		   copy over stuff from response packet
 *
 * Context	 : Can be called by interrupt thread.
 */
static void
i2ohba_i_pkt_comp(i2o_single_reply_message_frame_t *reply, ddi_acc_handle_t
    acc_handle, struct i2ohba_cmd *sp)
{
	i2o_scsi_success_reply_message_frame_t	*replysuc;
	i2o_scsi_error_reply_message_frame_t	*replyerr;
	struct i2ohba *i2ohba;
	struct scsi_pkt *pkt;
	uint32_t	transcount;
	uint32_t	autocount;
	uint16_t	adptrstatus;
	uint16_t	detailstat;
	uint16_t	messagesize;
	uint8_t		devstatus;

	i2ohba = CMD2I2OHBA(sp);
	ASSERT(I2OHBA_MUTEX_OWNED(i2ohba) == 0 || ddi_in_panic());

	pkt = CMD2PKT(sp);

	ASSERT(sp->cmd_flags & CFLAG_FINISHED);

	if (sp->cmd_flags & CFLAG_DMAVALID) {
		if (ddi_dma_unbind_handle(sp->sglbuf_dmahandle) !=
		    DDI_SUCCESS) {
			i2ohba_i_log(NULL, CE_WARN, "?i2ohba_scsi_dmafree: "
			    "ddi_dma_unbind_handle() for sglbuf failed");
			/*NOTREACHED*/
		}
#ifdef I2OHBA_DEBUG
		ddi_dma_unbind++;
#endif
		ddi_dma_mem_free(&sp->sglbuf_dmaacchandle);
#ifdef I2OHBA_DEBUG
		ddi_dma_free_mem++;
#endif
		ddi_dma_free_handle(&sp->sglbuf_dmahandle);
#ifdef I2OHBA_DEBUG
		ddi_dma_bind_free++;
#endif
		sp->sglbuf_dmahandle = NULL;
	}

	replysuc = (i2o_scsi_success_reply_message_frame_t *)reply;

	detailstat = ddi_get16(acc_handle, &reply->DetailedStatusCode);
	devstatus = (uint8_t)(detailstat & I2O_SCSI_DEVICE_DSC_MASK);
	/* this is a workaround for 0x3 and 0x9 LSB is being ORed */
		devstatus = devstatus & 0xfe;
	DEBUGF(1, (CE_CONT, "devstatus %x\n", devstatus));
	adptrstatus = detailstat & I2O_SCSI_HBA_DSC_MASK;
	DEBUGF(1, (CE_CONT, "adptrstatus %x\n", adptrstatus));

	transcount = ddi_get32(acc_handle, &replysuc->TransferCount);

	if (detailstat == 0)  {
		pkt->pkt_scbp[0] =
		    (uint8_t)(detailstat & I2O_SCSI_DEVICE_DSC_MASK);
		pkt->pkt_reason = CMD_CMPLT;
		pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA;
		pkt->pkt_statistics = 0;
		pkt->pkt_resid = sp->cmd_xfercount - transcount;
	} else {
		replyerr = (i2o_scsi_error_reply_message_frame_t *)reply;

		/*
		 * devstatus:	SCSI_SUCESS 0, SCSI_CHECK_COND 2,
		 * 		SCSI_BUSY   8, SCSI_RES_CONFLICT 18,
		 *		SCSI_CMD_TERM 22, SCSI_TASK_SET_FULL 28,
		 *		SCSI_ACA_ACTIVE 30
		 */
		messagesize = ddi_get16(acc_handle,
		    &replyerr->StdReplyFrame.StdMessageFrame.MessageSize);

		pkt->pkt_scbp[0] = devstatus;

		if (devstatus == I2O_SCSI_DSC_CHECK_CONDITION) {
			pkt->pkt_reason = CMD_CMPLT;
			pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
			    STATE_SENT_CMD | STATE_XFERRED_DATA;
			pkt->pkt_statistics = 0;
			goto arqchk;
		}

		/* SYM HDM problem, can't recognized USCSI cmd well */
		if ((devstatus == I2O_SCSI_DSC_BUSY) &&
		    (transcount != 0) && ((pkt->pkt_flags >> 16) != 0)) {
			pkt->pkt_reason = CMD_CMPLT;
			pkt->pkt_state |= STATE_GOT_BUS | STATE_GOT_TARGET |
			    STATE_SENT_CMD | STATE_XFERRED_DATA;
			pkt->pkt_statistics = 0;
			pkt->pkt_resid = sp->cmd_xfercount - transcount;
			pkt->pkt_scbp[0] = STATUS_GOOD;
			goto done;
		}


		switch (adptrstatus) {

		case I2O_SCSI_HBA_DSC_AUTOSENSE_FAILED:
			pkt->pkt_reason = CMD_INCOMPLETE;
			pkt->pkt_state |= STATE_ARQ_DONE;
			break;

		/* bus reset */
		case I2O_SCSI_HBA_DSC_SCSI_BUS_RESET:
			pkt->pkt_reason = CMD_RESET;
			pkt->pkt_statistics |= STAT_BUS_RESET;
			/* Do we need to call notify_callback? */
			scsi_hba_reset_notify_callback(
			    I2OHBA_REQ_MUTEX(i2ohba),
			    &i2ohba->i2ohba_reset_notify_listf);
			break;

		/* cmd terminated */
		case I2O_SCSI_HBA_DSC_REQUEST_TERMINATED:
			pkt->pkt_reason = CMD_TERMINATED;

			pkt->pkt_statistics |= STAT_TERMINATED;
			break;

		/* request aborted */
		case I2O_SCSI_HBA_DSC_NO_NEXUS:
			pkt->pkt_reason = CMD_ABORTED;
			pkt->pkt_statistics |= STAT_ABORTED;
			break;

		/* parity error */
		case I2O_SCSI_HBA_DSC_PARITY_ERROR_FAILURE:
			pkt->pkt_reason = CMD_TRAN_ERR;
			pkt->pkt_statistics |= STAT_PERR;
			i2ohba_i_log(NULL, CE_WARN, "?Parity Error");
			break;

		/* data overrun */
		case I2O_SCSI_HBA_DSC_DATA_OVERRUN:
			pkt->pkt_reason = CMD_DATA_OVR;
			pkt->pkt_state |= STATE_GOT_BUS |
			    STATE_GOT_TARGET | STATE_SENT_CMD |
			    STATE_XFERRED_DATA;
			break;

		/* cmd complete with error */
		case I2O_SCSI_HBA_DSC_LUN_ALREADY_ENABLED:
		case I2O_SCSI_HBA_DSC_COMPLETE_WITH_ERROR:
			/* devstatus should be busy/checkcond */
			pkt->pkt_reason = CMD_CMPLT;
			break;

		/* cmd aborted by request or aborted by time */
		case I2O_SCSI_HBA_DSC_REQUEST_ABORTED:
			if (sp->cmd_flags & CFLAG_DELAY_TIMEOUT) {
				pkt->pkt_reason = CMD_TIMEOUT;
				pkt->pkt_statistics |= STAT_TIMEOUT
				    | STAT_ABORTED;
			} else {
				pkt->pkt_reason = CMD_ABORTED;
				pkt->pkt_statistics |= STAT_ABORTED;
			}
			break;

		/* cmd timeout */
		case I2O_SCSI_HBA_DSC_COMMAND_TIMEOUT:
			pkt->pkt_reason = CMD_TIMEOUT;
			pkt->pkt_statistics |= STAT_TIMEOUT;
			break;

		/* CDB received */
		case I2O_SCSI_HBA_DSC_CDB_RECEIVED:
			pkt->pkt_reason = CMD_INCOMPLETE;
			pkt->pkt_state |= STATE_SENT_CMD |
			    STATE_GOT_BUS | STATE_GOT_TARGET |
			    STATE_XFERRED_DATA;
			break;

		/* device reset msg send */
		case I2O_SCSI_HBA_DSC_BDR_MESSAGE_SENT:
			pkt->pkt_reason = CMD_RESET;
			pkt->pkt_statistics |= STAT_DEV_RESET;
			break;

		/* unexpected bus free */
		case I2O_SCSI_HBA_DSC_UNEXPECTED_BUS_FREE:
			pkt->pkt_reason = CMD_UNX_BUS_FREE;
			break;

		/* cmd failed, transport error */
		case I2O_SCSI_HBA_DSC_ADAPTER_BUSY:
		case I2O_SCSI_HBA_DSC_SEQUENCE_FAILURE:
		case I2O_SCSI_HBA_DSC_BUS_BUSY:
		case I2O_SCSI_HBA_DSC_QUEUE_FROZEN:
		case I2O_SCSI_HBA_DSC_UNABLE_TO_ABORT:
		case I2O_SCSI_HBA_DSC_UNABLE_TO_TERMINATE:
		case I2O_SCSI_HBA_DSC_RESOURCE_UNAVAILABLE:
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;

		/* failed command, retry? */
		case I2O_SCSI_HBA_DSC_REQUEST_INVALID:
		case I2O_SCSI_HBA_DSC_PATH_INVALID:
		case I2O_SCSI_HBA_DSC_INVALID_CDB:
		case I2O_SCSI_HBA_DSC_LUN_INVALID:
		case I2O_SCSI_HBA_DSC_SELECTION_TIMEOUT:
			pkt->pkt_state |= STATE_GOT_BUS;
			pkt->pkt_reason = CMD_INCOMPLETE;
			break;

		case I2O_SCSI_HBA_DSC_DEVICE_NOT_PRESENT:
		case I2O_SCSI_HBA_DSC_FUNCTION_UNAVAILABLE:
			pkt->pkt_reason = CMD_INCOMPLETE;
			break;

		/* what? NO adapter! shutdown now! */
		case I2O_SCSI_HBA_DSC_NO_ADAPTER:
			i2ohba->i2ohba_shutdown = 1;
			break;

		case I2O_SCSI_HBA_DSC_SCSI_TID_INVALID:
		case I2O_SCSI_HBA_DSC_SCSI_IID_INVALID:
		default: /* failed cmd, retry */
			pkt->pkt_state |= STATE_GOT_BUS;
			pkt->pkt_reason = CMD_TRAN_ERR;
			break;


		}

		pkt->pkt_resid = sp->cmd_xfercount;

		/*
		 * was there auto request sense info?
		 */
arqchk:		if (messagesize >
		    sizeof (i2o_scsi_success_reply_message_frame_t)) {
			autocount = ddi_get32(acc_handle,
			    &replyerr->AutoSenseTransferCount);

			/* currently uses the DATA_IN_MESSAGE, only 40 bytes */
			if (autocount) {
			    pkt->pkt_state |= STATE_ARQ_DONE;
			    i2ohba_i_handle_arq(replyerr, sp, autocount);
			}
		}

	}


done:	DEBUGF(1, (CE_CONT, "transfer=0x%x, resid=0x%lx\n", transcount,
	    pkt->pkt_resid));

	/*
	 * if data was xferred and this was an IOPB, we need
	 * to do a dma sync
	 */
	if ((sp->cmd_flags & CFLAG_CMDIOPB) &&
	    (pkt->pkt_state & STATE_XFERRED_DATA)) {
		(void) ddi_dma_sync(sp->cmd_dmahandle,
		    sp->cmd_dma_offset, sp->cmd_dma_len,
		    DDI_DMA_SYNC_FORCPU);
	}


	ASSERT(sp->cmd_flags & CFLAG_IN_TRANSPORT);
	ASSERT(sp->cmd_flags & CFLAG_FINISHED);
	ASSERT((sp->cmd_flags & CFLAG_COMPLETED) == 0);

	sp->cmd_flags = ((sp->cmd_flags & ~CFLAG_IN_TRANSPORT) &
			~CFLAG_DELAY_TIMEOUT) | CFLAG_COMPLETED;
	i2ohba->i2ohba_counter--;

	/*
	 * Call packet completion routine if FLAG_NOINTR is not set.
	 * If FLAG_NOINTR is set turning on CFLAG_COMPLETED in line
	 * above will cause busy wait loop in
	 * i2ohba_i_polled_cmd_start() to exit.
	 */
	if (((pkt->pkt_flags & FLAG_NOINTR) == 0) &&
	    pkt->pkt_comp) {
		(*pkt->pkt_comp)(pkt);
	}

	ASSERT(I2OHBA_MUTEX_OWNED(i2ohba) == 0 || ddi_in_panic());
}


/*
 * Function name : i2ohba_i_handle_arq()
 *
 * Description	 : called on an autorequest sense condition, sets up arqstat
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
static void
i2ohba_i_handle_arq(i2o_scsi_error_reply_message_frame_t *replyerr,
    struct i2ohba_cmd *sp, int aqcount)
{
	char status;
	struct scsi_pkt *pkt = CMD2PKT(sp);

	if (sp->cmd_scblen >= sizeof (struct scsi_arq_status)) {
		struct scsi_arq_status *arqstat;

		DEBUGF(1, (CE_CONT, "tgt %d.%d: auto request sense",
		    TGT(sp), LUN(sp)));

		/* clear the pkt_scbp struct */
		arqstat = (struct scsi_arq_status *)(pkt->pkt_scbp);
		status = pkt->pkt_scbp[0];
		bzero(arqstat, sizeof (struct scsi_arq_status));

		/*
		 * I2O does not provide statistics for request sense,
		 * so use same statistics as the original cmd.
		 */
		arqstat->sts_rqpkt_statistics = pkt->pkt_statistics;
		arqstat->sts_rqpkt_state =
		    (STATE_GOT_BUS | STATE_GOT_TARGET |
		    STATE_SENT_CMD | STATE_XFERRED_DATA | STATE_GOT_STATUS);
		if (aqcount < sizeof (struct scsi_extended_sense)) {
			arqstat->sts_rqpkt_resid =
			    sizeof (struct scsi_extended_sense) - aqcount;

		}
		bcopy(replyerr->SenseData,
		    &arqstat->sts_sensedata,
		    (sizeof (struct scsi_extended_sense) <
		    I2O_SCSI_SENSE_DATA_SZ) ?
		    sizeof (struct scsi_extended_sense) :
		    I2O_SCSI_SENSE_DATA_SZ);

		/*
		 * restore status which was wiped out by bzero
		 */
		pkt->pkt_scbp[0] = status;

		DEBUGF(1, (CE_CONT, "arq: %x %x %x %x %x %x %x",
		    replyerr->SenseData[0], replyerr->SenseData[1],
		    replyerr->SenseData[2], replyerr->SenseData[3],
		    replyerr->SenseData[4], replyerr->SenseData[5],
		    replyerr->SenseData[6]));
		return;
	}
	/*
	 * Failed cmd auto sense data; can't copy over ARQ data,
	 */
	DEBUGF(1, (CE_CONT, "Failed cmd, possible sense data"));
	DEBUGF(1, (CE_CONT, "arq: %x %x %x %x %x %x %x",
	    replyerr->SenseData[0], replyerr->SenseData[1],
	    replyerr->SenseData[2], replyerr->SenseData[3],
	    replyerr->SenseData[4], replyerr->SenseData[5],
	    replyerr->SenseData[6]));
}


/*
 * Function name : i2ohba_i_polled_cmd_start()
 *
 * Return Values : TRAN_ACCEPT	if transaction was accepted
 *		   TRAN_BUSY	if I/O could not be started
 *		   TRAN_ACCEPT	if I/O timed out, pkt fields indicate error
 *
 * Description	 : Busy waits for I/O to complete or timeout.
 *		   NOTE: This function returns void because the cmd
 *		   has already started in scsi_start() before this
 *		   function is called. So no need to return rval.
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
static void
i2ohba_i_polled_cmd_start(struct i2ohba *i2ohba, struct i2ohba_cmd *sp)
{
	int delay_loops;
	struct scsi_pkt *pkt = CMD2PKT(sp);

	ASSERT(I2OHBA_MUTEX_OWNED(i2ohba) == 0 || ddi_in_panic());

	/*
	 * set timeout to SCSI_POLL_TIMEOUT for non-polling
	 * commands that do not have this field set
	 */
	if (pkt->pkt_time == 0) {
		pkt->pkt_time = SCSI_POLL_TIMEOUT;
	}

	ASSERT(pkt->pkt_flags & FLAG_NOINTR);

	delay_loops = I2OHBA_TIMEOUT_DELAY(
	    (pkt->pkt_time + (2 * I2OHBA_GRACE)),
	    I2OHBA_NOINTR_POLL_DELAY_TIME);

	/*
	 * busy wait for command to finish
	 * ie. till CFLAG_COMPLETED is set
	 */
	while ((sp->cmd_flags & CFLAG_COMPLETED) == 0) {
		drv_usecwait(I2OHBA_NOINTR_POLL_DELAY_TIME);
		if (--delay_loops <= 0) {

			if ((i2ohba_scsi_reset(&pkt->pkt_address,
			    RESET_TARGET)) == 0) {
				mutex_enter(I2OHBA_REQ_MUTEX(i2ohba));
				i2ohba_i_fatal_error(i2ohba);
				mutex_exit(I2OHBA_REQ_MUTEX(i2ohba));
			}
			pkt->pkt_reason = CMD_TIMEOUT;
			pkt->pkt_statistics |= STAT_BUS_RESET |
			    STAT_TIMEOUT;
			sp->cmd_flags = ((sp->cmd_flags &
			    ~CFLAG_IN_TRANSPORT) & ~CFLAG_DELAY_TIMEOUT)
			    | CFLAG_COMPLETED | CFLAG_FINISHED;
			i2ohba->i2ohba_counter--;
			break;
		}
	}

	ASSERT(I2OHBA_MUTEX_OWNED(i2ohba) == 0 || ddi_in_panic());

}



/*
 * Function name : i2ohba_i_watch()
 *
 * Return Values : none
 * Description	 : I2OHBA deadman timer routine.
 *
 * Given that the i2ohba's request queue is double link list
 * in FIFO fashion, the tail should be pointing at the oldest
 * cmd.  However, each command has different timeout value set
 * by the target driver, if any of them has timeout then we
 * will call fatal_error().
 *
 * A hung i2ohba controller is detected by failure to complete
 * cmds within a timeout interval (including grace period for
 * i2ohba error recovery). All target error recovery is handled
 * directly by the i2ohba.
 *
 * If i2ohba hungs, restart by resetting the i2ohba's HBA/BUS and
 * flushing the double linked list (via i2ohba_i_qflush()).
 *
 * Tagged queueing gives us other headaches since we cannot know
 * exactly when a command starts.  For example, a command with a
 * 2-hour timeout, will cause a second command with a 60-second timeout
 * to be timed-out. We won't worry about it now, but will later
 *
 * Context	 : Can be called by timeout thread.
 */

static void
i2ohba_i_watch(void *arg)
{
	struct i2ohba	*i2ohba		= (struct i2ohba *)arg;
	clock_t		cur_lbolt;
	clock_t		deadline;
	struct i2ohba_cmd	*sp;
	struct scsi_pkt		*pkt;


	if (i2ohba->i2ohba_shutdown) {
		return;
	}

	I2OHBA_MUTEX_ENTER(i2ohba);

	if ((cur_lbolt = ddi_get_lbolt()) != 0) {
		for (sp = i2ohba->i2ohba_reqtail; sp != NULL;
		    sp = sp->cmd_backw) {
			pkt = CMD2PKT(sp);
			deadline = sp->cmd_deadline;
			if ((deadline - cur_lbolt <= 0) && (pkt->pkt_time)) {
				if (!(sp->cmd_flags & CFLAG_DELAY_TIMEOUT)) {
					/* report time out */
					i2ohba_i_log(NULL, CE_CONT,
					    "?i2ohba_i_watch: "
					    "Exend cmd timeout on target %d.%d",
					    TGT(sp), LUN(sp));
					/* reset timeout vaule for delay */
					sp->cmd_deadline = cur_lbolt +
					    (clock_t)(pkt->pkt_time * 192);
					/* set DELAY_TIMEOUT indicator */
					sp->cmd_flags |= CFLAG_DELAY_TIMEOUT;
					/* set throttle on */
					i2ohba->i2ohba_throttle++;
				} else {
					i2ohba_i_req_remove(i2ohba, sp);
					pkt->pkt_reason = CMD_TIMEOUT;
					pkt->pkt_statistics |= STAT_TIMEOUT;
					sp->cmd_flags = ((sp->cmd_flags
					    & ~CFLAG_DELAY_TIMEOUT)
					    & ~CFLAG_IN_TRANSPORT)
					    | CFLAG_COMPLETED | CFLAG_FINISHED;
					i2ohba_i_log(NULL, CE_WARN,
					    "?i2ohba_i_watch: "
					    "Cmd timeout on target %d.%d",
					    TGT(sp), LUN(sp));
					I2OHBA_MUTEX_EXIT(i2ohba);
					if (((pkt->pkt_flags & FLAG_NOINTR)
					    == 0) && pkt->pkt_comp) {
						(*pkt->pkt_comp)(pkt);
					}
					I2OHBA_MUTEX_ENTER(i2ohba);
				}
			}
		}

		DEBUGF(2, (CE_CONT, "?throttle=%d", i2ohba->i2ohba_throttle));
		if ((i2ohba->i2ohba_reqtail == NULL) &&
		    (i2ohba->i2ohba_reqhead == NULL)) {
			i2ohba->i2ohba_throttle = 0;
		}

	}

	if (i2ohba->i2ohba_need_prop_update) {
		int i;

		for (i = 0; i < N_I2OHBA_TARGETS_WIDE; i++) {
			if (i2ohba->i2ohba_need_prop_update & (1 << i)) {
				i2ohba_i_update_props(i2ohba, i);
			}
		}

		i2ohba->i2ohba_need_prop_update = 0;

	}

	/*
	 * Set up next timeout
	 */
	i2ohba->i2ohba_timeout_id = timeout(i2ohba_i_watch, i2ohba,
	    i2ohba_tick);
	I2OHBA_MUTEX_EXIT(i2ohba);
}



/*
 * Function name : i2ohba_i_fatal_error()
 *
 * Return Values :  none
 *
 * Description	 :
 * Isp fatal error recovery:
 * Reset the i2o and flush the active queues and attempt restart.
 * This should only happen in case of a firmware bug or hardware
 * death.  Flushing is from backup queue as I2O cannot be trusted.
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 *		   i2ohba_request_mutex is held.
 */
static void
i2ohba_i_fatal_error(struct i2ohba *i2ohba)
{
	/*
	 * hold off starting new requests by grabbing the request mutex
	 */
	ASSERT(I2OHBA_MUTEX_OWNED(i2ohba));

	/*
	 * If shutdown flag is set than no need to do
	 * fatal error recovery.
	 */
	if (i2ohba->i2ohba_shutdown) {
		return;
	}

	i2ohba_i_log(NULL, CE_WARN, "?i2ohba_i_fatal_error: "
	    "Fatal error, resetting interface");

	i2ohba_i_print_state(i2ohba);

	(void) i2ohba_i_reset_interface(i2ohba, I2OHBA_FORCE_BUS_RESET);

	i2ohba_i_qflush(i2ohba, (uint16_t)0, (uint16_t)N_I2OHBA_TARGETS_WIDE);

	(void) scsi_hba_reset_notify_callback(I2OHBA_REQ_MUTEX(i2ohba),
	    &i2ohba->i2ohba_reset_notify_listf);

	ASSERT(I2OHBA_MUTEX_OWNED(i2ohba));
}


/*
 * Function name : i2ohba_i_qflush()
 *
 * Return Values : none
 * Description	 :
 *	Flush i2ohba queues over range specified
 *	from start_tgt to end_tgt.  Flushing goes from oldest to newest
 *	to preserve some cmd ordering.
 *	This is used for i2o crash recovery as normally i2o takes
 *	care of target or bus problems.
 *
 * Context	 : Can be called from different kernel process threads.
 *			i2ohba_i_fatal_error()
 *			i2ohba_i_reset_interface()
 *		   Can be called by interrupt thread.
 */
static void
i2ohba_i_qflush(struct i2ohba *i2ohba, uint16_t start_tgt, uint16_t end_tgt)
{
	struct i2ohba_cmd *sp;
	struct scsi_pkt   *pkt;

	ASSERT(start_tgt <= end_tgt);
	ASSERT(I2OHBA_MUTEX_OWNED(i2ohba));


	/*
	 * If flushing active queue, start with current free slot
	 * ie. oldest request, to preserve some order.
	 */
	sp = i2ohba->i2ohba_reqtail;
	for (; sp != NULL; sp = i2ohba->i2ohba_reqtail->cmd_backw) {
		if ((TGT(sp) >= start_tgt) && (TGT(sp) <= end_tgt)) {

			pkt = CMD2PKT(sp);
			pkt->pkt_reason = CMD_RESET;
			pkt->pkt_statistics |= STAT_DEV_RESET;
			(void) i2ohba_i_req_remove(i2ohba, sp);
			sp->cmd_flags |= CFLAG_FINISHED;
			sp->cmd_flags = ((sp->cmd_flags & ~CFLAG_IN_TRANSPORT)
			    & ~CFLAG_DELAY_TIMEOUT) | CFLAG_COMPLETED;
			i2ohba->i2ohba_counter--;
			if (((pkt->pkt_flags & FLAG_NOINTR) == 0) &&
			    pkt->pkt_comp) {
				(*pkt->pkt_comp)(pkt);
			}

		}
	}

	ASSERT(I2OHBA_MUTEX_OWNED(i2ohba));
}


/*
 * Function name : i2ohba_scsi_abort()
 *
 * Return Values : 0	- abort failed
 *		   1	- abort succeeded
 * Description	 :
 * SCSA interface routine to abort pkt(s) in progress.
 * Abort the pkt specified or NULL pkt, abort ALL pkts.
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
static int
i2ohba_scsi_abort(struct scsi_address *ap, struct scsi_pkt *pkt)
{
	struct i2ohba *i2ohba = ADDR2I2OHBA(ap);
	struct i2ohba_cmd *sp = PKT2CMD(pkt);
	uint16_t arg, tid;
	int rval = 0;

	ASSERT(mutex_owned(I2OHBA_REQ_MUTEX(i2ohba)) == 0 || ddi_in_panic());

	arg = (uint16_t)ap->a_target;

	if (i2ohba->i2ohba_tgt_id_map[arg] == NULL)
		return (rval);

	tid = i2ohba->i2ohba_tgt_id_map[arg]->tid;

	/*
	 * hold off new requests, we need the req mutex anyway so noone
	 * can access the queue.
	 */
	I2OHBA_MUTEX_ENTER(i2ohba);

	i2ohba_i_log(NULL, CE_CONT, "?i2ohba_scsi_abort: "
	    "aborting pkt 0x%p", (void *)pkt);


	if (pkt) {
		if (i2ohba_i_reset_abort(i2ohba, tid, I2O_SCSI_SCB_ABORT, sp)) {
			I2OHBA_MUTEX_EXIT(i2ohba);
			return (0);
		}
	} else {
		if (i2ohba_i_reset_abort(i2ohba, tid, I2O_SCSI_SCB_ABORT, 0)) {
			I2OHBA_MUTEX_EXIT(i2ohba);
			return (0);
		}
	}

	I2OHBA_MUTEX_EXIT(i2ohba);
	return (1);
}


/*
 * Function name : i2ohba_scsi_reset()
 *
 * Return Values : 0 - reset failed
 *		   1 - reset succeeded
 * Description	 :
 * SCSA interface routine to perform scsi resets on either
 * a specified target or the bus (default).
 *
 * Context	 : Can be called from different kernel process threads.
 *		   Can be called by interrupt thread.
 */
static int
i2ohba_scsi_reset(struct scsi_address *ap, int level)
{
	struct i2ohba *i2ohba = ADDR2I2OHBA(ap);
	uint16_t arg, tid;
	int	rval = 0;

	ASSERT(mutex_owned(I2OHBA_REQ_MUTEX(i2ohba)) == 0 || ddi_in_panic());

	arg = (uint16_t)ap->a_target;

	if (i2ohba->i2ohba_tgt_id_map[arg] == NULL)
		return (rval);

	tid = i2ohba->i2ohba_tgt_id_map[arg]->tid;

	I2OHBA_MUTEX_ENTER(i2ohba);
	/*
	 * hold off new requests, we need the req mutex.
	 */

	if (level == RESET_TARGET) {
		i2ohba_i_log(NULL, CE_CONT,
		    "?i2ohba_scsi_reset: reset target %d", ap->a_target);

		if (i2ohba_i_reset_abort(i2ohba, tid,
		    I2O_SCSI_DEVICE_RESET, 0))  {
			return (rval);
		}
	} else {
		i2ohba_i_log(NULL, CE_CONT, "?i2ohba_scsi_reset: reset bus");

		tid = i2ohba->i2ohba_tid;
		if (i2ohba_i_reset_abort(i2ohba, tid, I2O_HBA_BUS_RESET, 0)) {
			return (rval);
		}
		(void) scsi_hba_reset_notify_callback(
		    I2OHBA_REQ_MUTEX(i2ohba),
		    &i2ohba->i2ohba_reset_notify_listf);
		/* wait for 3 sec after a reset */
		drv_usecwait((clock_t)i2ohba->i2ohba_scsi_reset_delay * 1000);
	}
	I2OHBA_MUTEX_EXIT(i2ohba);
	return (1);
}

/*
 * Function name: i2ohba_i_reset_abort()
 *
 * Return Values: 0 - success
 *		  -1 - fail reset
 *
 * Description	:
 * Reset either the HBA Adpter or Bus Reset
 * This function is called from i2ohba_i_reset_interface()
 *			i2ohba_scsi_abort()
 *			i2ohba_scsi_reset()
 *
 * Context	: Can be called from different kernel process threads.
 *		  Can not be called by interrupt thread because it
 *		  waits on the reply message.
 */
static int
i2ohba_i_reset_abort(struct i2ohba *i2ohba, uint16_t tid, int action,
    struct i2ohba_cmd *cmd)
{
	int			rval = -1;
	i2o_message_frame_t	*msgptr;
	i2o_scsi_scb_abort_message_t	*abortmsg;
	i2o_msg_handle_t	msg_handle;
	ddi_acc_handle_t	acc_handle;
	struct i2ohba_util	*sp;

	if (i2o_msg_alloc(i2ohba->i2ohba_iophdl, I2O_MSG_SLEEP, NULL,
	    (void *)&msgptr, &msg_handle, &acc_handle) != DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_i_reset_abort: "
		    "i2o_msg_alloc failed");
		return (rval);
	}

	if ((action == I2O_SCSI_SCB_ABORT) && (cmd == NULL))
		action = I2O_SCSI_DEVICE_RESET;

	abortmsg = (i2o_scsi_scb_abort_message_t *)msgptr;
	/*
	 * construct a i2o_hba_bus_reset_message
	 */
	abortmsg->StdMessageFrame.VersionOffset = 0x01;
	abortmsg->StdMessageFrame.MsgFlags = 0;
	if (action == I2O_SCSI_SCB_ABORT)
		ddi_put16(acc_handle, &abortmsg->StdMessageFrame.MessageSize,
		    sizeof (i2o_scsi_scb_abort_message_t) >> 2);
	else
		ddi_put16(acc_handle, &abortmsg->StdMessageFrame.MessageSize,
		    sizeof (i2o_scsi_device_reset_message_t) >> 2);
	put_msg_TargetAddress(&abortmsg->StdMessageFrame, tid, acc_handle);
	put_msg_InitiatorAddress(&abortmsg->StdMessageFrame, I2O_OSM_TID,
	    acc_handle);
	put_msg_Function(&abortmsg->StdMessageFrame, action, acc_handle);
	ddi_put32(acc_handle,
	    (uint32_t *)&abortmsg->StdMessageFrame.InitiatorContext,
	    (uint32_t)i2ohba_utilmsg_comp);

	/*
	 * allocating synchronized status buffer
	 */
	sp = kmem_alloc(sizeof (struct i2ohba_util), KM_SLEEP);

	ddi_put32(acc_handle, &abortmsg->TransactionContext,
	    (uint32_t)(uintptr_t)sp);

	if (cmd)
		ddi_put32(acc_handle, &abortmsg->TransactionContextToAbort,
		    (uint32_t)(uintptr_t)cmd);

	/*
	 * initialized a mutex and cond variable to
	 * send message to IOP, and wait for it to signal back
	 */
	sp->mutex = I2OHBA_RESET_MUTEX(i2ohba);
	sp->cv = I2OHBA_RESET_CV(i2ohba);
	mutex_enter(sp->mutex);
	sp->wakeup = UTIL_MSG_SLEEP;
	sp->status = 0;
	(void) i2o_msg_send(i2ohba->i2ohba_iophdl, msgptr, msg_handle);
	while (!sp->wakeup)
		cv_wait(sp->cv, sp->mutex);
	mutex_exit(sp->mutex);

	/*
	 * process reply message
	 */

	switch (sp->status) {
		case I2O_REPLY_STATUS_SUCCESS:
			rval = 0;
			break;
		default:
			/*
			 * Failed the reset for now,
			 * we can also parse the AdapterStatus
			 * and retry if needed
			 */
			break;
	}

cleanup:
	if (sp)
		kmem_free(sp, sizeof (struct i2ohba_util));

	return (rval);
}


/*
 * Function name : i2ohba_i_reset_interface()
 *
 * Return Values : 0 - success
 *		  -1 - hw failure
 *
 * Description	 :
 * Master reset routine for hardware/software.	Resets softc struct,
 * i2ohba; and scsi bus and the scsi adapter.  The works!
 * This function is called from i2ohba_attach with no mutexes held or
 * from i2ohba_i_fatal_error with request mutex held
 *
 * NOTE: it is up to the caller to flush the response queue
 *
 * Context	 : Can be called from different kernel process threads.
 *		   i2ohba_attach() - single thread, no mutex held
 *		   i2ohba_i_fatal_error()
 *		   Can be called by interrupt thread.
 */
static int
i2ohba_i_reset_interface(struct i2ohba *i2ohba, int action)
{
	int		i;
	int		rval = -1;

	/*
	 * Handle reset recovery; reset the bus before we reset the
	 * adapter chip
	 */
	/*
	 * send command Bus Reset
	 */
	DEBUGF(1, (CE_CONT, "Resetting i2o SCSI BUS"));

	if (action == I2OHBA_FORCE_BUS_RESET) {
		if (i2ohba_i_reset_abort(i2ohba, i2ohba->i2ohba_tid,
		    I2O_HBA_BUS_RESET, 0)) {
			i2ohba_i_log(NULL, CE_WARN,
			    "?i2ohba_i_reset_interface: bus reset failed");
			goto cleanup;
		}
		(void) scsi_hba_reset_notify_callback(
		    I2OHBA_REQ_MUTEX(i2ohba),
		    &i2ohba->i2ohba_reset_notify_listf);
		drv_usecwait((clock_t)i2ohba->i2ohba_scsi_reset_delay * 1000);
	}

	/*
	 * Handle resetting i2o host adapter.
	 */
	DEBUGF(1, (CE_CONT, "Resetting i2o SCSI Host Adapter"));

	/*
	 * Reset the i2o host adapter.
	 */
	if (i2ohba_i_reset_abort(i2ohba, i2ohba->i2ohba_tid,
	    I2O_HBA_ADAPTER_RESET, 0)) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_i_reset_interface: "
		    "adapter reset failed");
		goto cleanup;
	}
	drv_usecwait((clock_t)i2ohba->i2ohba_scsi_reset_delay * 1000);


	/*
	 * set Initiator SCSI ID using utilparamset
	 */

/*
 *	DEBUGF(1, (CE_CONT, "Initializing SCSI HBA ID"));
 *
 *	i = i2ohba->i2ohba_initiator_id;
 *	if (i2ohba_utilparamset_msg(i2ohba, 7, i2ohba->i2ohba_tid,
 *	    I2O_HBA_SCSI_CONTROLLER_INFO_GROUP_NO, 0x4, i) != 0) {
 *		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_i_reset_interface: "
 *		    "resetting initiator id failed");
 *		goto cleanup;
 *	}
 *
 */

	/*
	 * Update sync/offset from i2ohba utilparmas to
	 * global per target sync area.
	 */
	DEBUGF(1, (CE_CONT, "Initializing i2ohba capabilities"));

	for (i = 0; i < N_I2OHBA_TARGETS_WIDE; i++) {
		(void) i2ohba_i_updatesync(i2ohba, i);
	}
	rval = 0;

cleanup:
	if (rval) {
		DEBUGF(1, (CE_WARN, "reset interface failed"));
		i2ohba->i2ohba_shutdown = 1;
		DEBUGF(1, (CE_WARN, "interface going offline"));
		i2ohba_i_qflush(i2ohba, (uint16_t)0,
		    (uint16_t)N_I2OHBA_TARGETS_WIDE);
	}

	return (rval);
}



static void
i2ohba_i_print_state(struct i2ohba *i2ohba)
{
	char	buf[128];
	int	i;


	/*
	 * Print out sync scsi info and suppress trailing zero
	 * period and offset entries.
	 */
	if (i2ohba->i2ohba_scsi_options & SCSI_OPTIONS_SYNC) {
		(void) sprintf(buf, "period/offset:");
		for (i = 0; i < N_I2OHBA_TARGETS; i++) {
			(void) sprintf(&buf[strlen(buf)], " %d/%d",
			    i2ohba->i2ohba_synch[i], i2ohba->i2ohba_offset[i]);
		}
		DEBUGF(1, (CE_CONT, buf));
		(void) sprintf(buf, "period/offset:");
		for (i = N_I2OHBA_TARGETS; i < N_I2OHBA_TARGETS_WIDE; i++) {
			(void) sprintf(&buf[strlen(buf)], " %d/%d",
			    i2ohba->i2ohba_synch[i], i2ohba->i2ohba_offset[i]);
		}
		DEBUGF(1, (CE_CONT, buf));
	}
}

/*
 * Function name: i2ohba_utilparamset_msg()
 *
 * Return Values: 0 - success
 *		 -1 - set prarmeter failed
 * Description  : common UtilParamSet function.
 *		  However, only one param at a time. Pass in
 *		  the Tid, GroupNumber, and the FieldIdx, and
 *		  value, then compose the Message frame,
 *		  then send it off through i2o_message_send().
 *
 *	 Message Format:
 *
 *	 Building a param_set message requires:
 *	 Buffer#1 SGL-immediate data (Request)
 *	 1. i2o_param_operations_list_header_t(1W)
 *		u16	OperationCount (1)
 *		u16	Reserved
 *	 2. i2o_param_operation_specific_template_t(2W)
 *		u16	Operation (FIELD_SET)
 *		u16	GroupNumber (group)
 *		u16	FieldCount 0x1
 *		u16	FieldIdx  (idx)
 *		u16	value of idx
 *
 *	 Buffer#2 SGL-Simple addressing (Reply)
 *	 1. i2o_param_results_list_header_t(1W)
 *		u16	ResultCount
 *		u16	Reserved
 *	 2. i2o_param_modify_operation_result_t(9W)
 *		u16	BlockSize
 *		u8	BlockStatus
 *		u8	ErrorInfoSize
 *		...	ErrorInformation
 *
 *
 * Context	: Can be called from i2ohba_i_reset_interface()
 *		  Can be called from i2ohba_i_updatecap() or
 *			i2ohba_scsi_setcap()
 */


static int
i2ohba_utilparamset_msg(struct i2ohba *i2ohba, int tgt, uint16_t tid,
    uint16_t group, uint16_t idx, uint16_t value)
{

	i2o_setparam_t		*msgptr;
	i2o_msg_handle_t	msg_handle;
	ddi_acc_handle_t	acc_handle;
	struct i2ohba_util	*sp = NULL;
	uint_t			count;
	int			rval = -1;
	int			bound = 0;
	uint16_t		allocmsgsize;


	/*
	 * allocate a message frame
	 */
	if (i2o_msg_alloc(i2ohba->i2ohba_iophdl, I2O_MSG_SLEEP,
	    NULL, (void *)&msgptr, &msg_handle, &acc_handle)
	    != DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_utilparamset_msg: "
		    "i2o_msg_alloc failed");
		return (rval);
	}

	/*
	 * To get the actual allocation msg size
	 */
	allocmsgsize = (ddi_get16(acc_handle, &msgptr->MessageSize) << 2);

	if (allocmsgsize < sizeof (i2o_setparam_t)) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_utilparamset_msg: "
		    "msg size alloc is smaller than what setparam needed");
		goto fail;
	}

	/*
	 * Construct a utilparamset message
	 */
	msgptr->VersionOffset = ContextSize32;
	msgptr->MsgFlags = 0;
	ddi_put16(acc_handle, &msgptr->MessageSize,
	    (sizeof (i2o_setparam_t) >> 2));
	put_msg_TargetAddress(msgptr, tid, acc_handle);
	put_msg_InitiatorAddress(msgptr, I2O_OSM_TID, acc_handle);
	put_msg_Function(msgptr, I2O_UTIL_PARAMS_SET, acc_handle);
	ddi_put32(acc_handle, (uint32_t *)&msgptr->InitiatorContext,
	    (uint32_t)i2ohba_utilmsg_comp);

	/*
	 * allocating sychronize status buffer
	 */
	sp = kmem_alloc(sizeof (struct i2ohba_util), KM_SLEEP);

	ddi_put32(acc_handle, &msgptr->TransactionContext,
	    (uint32_t)(uintptr_t)sp);

	/*
	 * First message buffer's SGL and operation parameters
	 */

	/*
	 * Buf1 SGL header:
	 *	Immediate Data for the operation
	 */
	put_flags_count_Flags(&msgptr->FlagsCount1,
	    I2O_SGL_FLAGS_IMMEDIATE_DATA_ELEMENT
	    | I2O_SGL_FLAGS_END_OF_BUFFER, acc_handle);
	put_flags_count_Count(&msgptr->FlagsCount1, ONE_PARAM_BLOCK,
	    acc_handle);

	/*
	 * Fill in the modify operation param for in the sgl1 payload
	 */

	ddi_put16(acc_handle, &msgptr->OperationCount, 1);
	ddi_put16(acc_handle, &msgptr->Operation,
	    I2O_PARAMS_OPERATION_FIELD_SET);
	ddi_put16(acc_handle, &msgptr->GroupNumber, group);
	ddi_put16(acc_handle, &msgptr->FieldCount, 0x1);
	ddi_put16(acc_handle, &msgptr->FieldIdx, idx);
	ddi_put16(acc_handle, &msgptr->Value, value);


	/*
	 * Buf2 SGL header:
	 *	Simple addressing
	 *	1. allocate the buffer for reply msg
	 *	2. setup the SGL header
	 */

	sp->i2ohba_util_buffer = NULL;

	if (ddi_dma_alloc_handle(i2ohba->i2ohba_dip, &i2ohba_dmasgl_attr,
	    DDI_DMA_SLEEP, NULL, &sp->dmahandle) !=
	    DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_utilparam_set: "
		    "cannot alloc dma handle");
		goto fail;
	}
	bound++;
	if (ddi_dma_mem_alloc(sp->dmahandle, (size_t)
	    sizeof (i2o_param_results_list_header_t) + (size_t)
	    sizeof (i2o_param_modify_operation_result_t),
	    &dev_attr, DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
	    (caddr_t *)&sp->i2ohba_util_buffer, &sp->rlen,
	    &sp->dma_acc_handle) != DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_utilparamset_msg: "
		    "cannot allocate param buffer");
		goto fail;
	}
	bound++;
	put_flags_count_Flags(&msgptr->FlagsCount2,
	    I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT |
	    I2O_SGL_FLAGS_END_OF_BUFFER |
	    I2O_SGL_FLAGS_LAST_ELEMENT, acc_handle);

	put_flags_count_Count(&msgptr->FlagsCount2, sp->rlen, acc_handle);


	if (ddi_dma_addr_bind_handle(sp->dmahandle, NULL,
	    sp->i2ohba_util_buffer, (size_t)
	    sizeof (i2o_param_results_list_header_t) + (size_t)
	    sizeof (i2o_param_modify_operation_result_t) + (size_t)
	    sizeof (i2o_scsi_device_info_scalar_t),
	    DDI_DMA_RDWR|DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &sp->dmacookie, &count) != DDI_DMA_MAPPED) {
		/*
		 * currently assume simple
		 * addring with one physical
		 * continuous address buffer.
		 */
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_utilparamset_msg: "
			"cannot bind buffer");
		goto fail;
	}

	ddi_put32(acc_handle, &msgptr->PhysicalAddress,
	    (uint32_t)sp->dmacookie.dmac_address);
	/*
	 * initialized a mutex and condvariable to
	 * send message to IOP, and wait for it
	 * to signal back
	 */
	sp->mutex = I2OHBA_UTILPARAM_MUTEX(i2ohba, tgt);
	sp->cv = I2OHBA_UTILPARAM_CV(i2ohba, tgt);
	mutex_enter(sp->mutex);
	sp->wakeup = UTIL_MSG_SLEEP;
	sp->status = 0;
	(void) i2o_msg_send(i2ohba->i2ohba_iophdl, msgptr, msg_handle);
	while (!sp->wakeup)
		cv_wait(sp->cv, sp->mutex);
	mutex_exit(sp->mutex);

	/* clear msg pointer */
	msgptr = NULL;

	/*
	 * process the data
	 */
	switch (sp->status) {

	i2o_setparam_reply_t  *result;
	uint16_t count;
	uint8_t	 blockstatus, errinfosize;

	case I2O_REPLY_STATUS_SUCCESS:
		/*
		 * since the reply is successful, will check
		 * for the opeation reulsts
		 */
		result = (i2o_setparam_reply_t *)sp->i2ohba_util_buffer;
		count = ddi_get16(sp->dma_acc_handle,
		    &result->ResultCount);
		if (!count) {
			i2ohba_i_log(NULL, CE_WARN,
			    "?i2ohba_utilparamset_msg: No Results");
			break;
		}

		blockstatus = ddi_get8(sp->dma_acc_handle,
		    &result->BlockStatus);

		errinfosize = ddi_get8(sp->dma_acc_handle,
		    &result->ErrorInfoSize);

		if ((blockstatus != 0) || (errinfosize != 0)) {
			i2ohba_i_log(NULL, CE_WARN,
			    "?i2ohba_utilparamset_msg: Error "
			    "occured during Modify Operation");
			/*
			 * retrived errorinfo and possibily retry
			 * XXLWLXX
			 */
			break;
		}
		rval = 0;
		break;

	default:
		rval = -1;
		break;
	}

fail:

	if (sp) {
		if (bound) {
			(void) ddi_dma_unbind_handle(sp->dmahandle);
			if (bound > 1)
				(void) ddi_dma_mem_free(&sp->dma_acc_handle);
			(void) ddi_dma_free_handle(&sp->dmahandle);
		}
		kmem_free(sp, sizeof (struct i2ohba_util));
	}

	/* return MFA to IOP */
	if (msgptr) {
		msgptr->VersionOffset = 0;
		msgptr->MsgFlags = 0;
		ddi_put16(acc_handle, &msgptr->MessageSize, 3);
		put_msg_TargetAddress(msgptr, 0, acc_handle);
		put_msg_InitiatorAddress(msgptr, 0, acc_handle);
		put_msg_Function(msgptr, I2O_UTIL_NOP, acc_handle);
		(void) i2o_msg_send(i2ohba->i2ohba_iophdl, msgptr, msg_handle);
	}
	return (rval);
}

/*
 * Function name: i2ohba_utilparamget_msg()
 *
 * Return Values: 0 - success
 *		 -1 - get prarmeter failed
 *
 * Description  : common UtilParamGet function.
 *		  However, only one param at a time. Pass in
 *		  the Tid, GroupNumber, and the FieldIdx, and
 *		  value, then compose the Message frame,
 *		  then send it off through i2o_message_send().
 *
 *	Message Format:
 *
 *	building a param_get message requires
 *	Buffer#1 SGL-immediate data
 *	1. i2o_param_operations_list_header_t(1W)
 *		u16	OperationCount
 *		u16	Reserved
 *	2. i2o_param_operation_speicific_template_t(2W)
 *		u16	Operation (FIELD_GET)
 *		u16	GroupNumber
 *		u16	FieldCount 0xFFFF
 *		u16	Pad
 *
 *	Buffer#2 SGL-Simple addressing
 *	Reply Message:
 *	1. i2o_param_results_list_header_t(1W)
 *		u16	ResultCount
 *		u16	Reserved
 *	2. i2o_param_read_operation_result_t(9W)
 *		u16	BlockSize
 *		u8	BlockStatus
 *		u8	ErrorInfoSize
 *		...	Total 8W for (ALL_PARAM_BLOCK)
 *		u32	Identifier
 *		u64	LUN
 *		...
 *	OR	Total	9 bytes (ONE_PARAM_BLOCK)
 *		u8	NegOffset
 *		u64	NegSynch
 */

static int
i2ohba_utilparamget_msg(struct i2ohba *i2ohba, uint16_t tidx, char flag)
{

	i2o_tid_scsi_ent_t *map = i2ohba->i2ohba_tid_scsi_map;
	i2o_tid_scsi_ent_t **tgtmap = i2ohba->i2ohba_tgt_id_map;

	i2o_getsyncparam_t	*msgptr;
	i2o_msg_handle_t	msg_handle;
	ddi_acc_handle_t	acc_handle;
	struct i2ohba_util	*sp = NULL;
	uint_t			count;
	uint16_t		allocmsgsize;
	uint16_t		tid;
	int			rval = -1;
	int			bound = 0;

	/*
	 * allocate a message frame
	 */
	if (i2o_msg_alloc(i2ohba->i2ohba_iophdl, I2O_MSG_SLEEP,
	    NULL, (void *)&msgptr, &msg_handle, &acc_handle)
	    != DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_utilparamget_msg: "
		    "i2o_msg_alloc failed");
		return (rval);
	}

	/*
	 * NOTE:
	 * "tidx" is either the entry number for the tid to scsi map
	 * or tidx is the target id, which needs tgt to id map to
	 * find the tid.
	 */
	if (flag == ALL_UTILPARAMS) {
		tid = map[tidx].tid;
	} else {
		tid = tgtmap[tidx]->tid;
	}

	/*
	 * To get the actual allocation msg
	 * size (in WORDS)
	 */
	allocmsgsize = (ddi_get16(acc_handle, &msgptr->MessageSize) << 2);


	/*
	 * Construct a utilparamget message
	 */
	/* msgptr->VersionOffset = ContextSize32; */
	msgptr->VersionOffset = I2O_VERSION_11;
	msgptr->MsgFlags = 0;
	put_msg_TargetAddress(msgptr, tid, acc_handle);
	put_msg_InitiatorAddress(msgptr, I2O_OSM_TID, acc_handle);
	put_msg_Function(msgptr, I2O_UTIL_PARAMS_GET, acc_handle);
	ddi_put32(acc_handle,
	    (uint32_t *)&msgptr->InitiatorContext.initiator_context_32bits,
	    (uint32_t)i2ohba_utilmsg_comp);
	/*
	 * allocating sychroniz status buffer
	 */
	sp = kmem_alloc(sizeof (struct i2ohba_util), KM_SLEEP);

	ddi_put32(acc_handle, &msgptr->TransactionContext,
	    (uint32_t)(uintptr_t)sp);

	/*
	 * Buf1 SGL header:
	 * 	Immediate Data
	 */
	put_flags_count_Flags(&msgptr->FlagsCount1,
	    I2O_SGL_FLAGS_IMMEDIATE_DATA_ELEMENT |
	    I2O_SGL_FLAGS_END_OF_BUFFER, acc_handle);

	/*
	 * Fill in the read operation param for
	 * in the payload
	 */

	ddi_put16(acc_handle, &msgptr->OperationCount, 1);

	ddi_put16(acc_handle, &msgptr->Operation,
	    I2O_PARAMS_OPERATION_FIELD_GET);

	ddi_put16(acc_handle, &msgptr->GroupNumber,
	    I2O_SCSI_DEVICE_INFO_GROUP_NO);

	/*
	 * End of message sending
	 */

	/*
	 * Buf2 SGL header:
	 * 	Simple Addressing
	 *	1. allocating the buffer
	 *	2. set up the SGL header
	 */

	sp->i2ohba_util_buffer = NULL;

	if (ddi_dma_alloc_handle(i2ohba->i2ohba_dip, &i2ohba_dmasgl_attr,
	    DDI_DMA_SLEEP, NULL, &sp->dmahandle) !=
	    DDI_SUCCESS) {
		i2ohba_i_log(NULL, CE_WARN, "?i2ohba_utilparamget_msg: "
		    "cannot alloc dma handle");
		goto fail;
	}
	bound++;
	if (flag == ALL_UTILPARAMS) {

		if (allocmsgsize < sizeof (i2o_getallparam_t))
			return (rval);

		if (ddi_dma_mem_alloc(sp->dmahandle, (size_t)
		    sizeof (i2o_getallparam_reply_t), &dev_attr,
		    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
		    (caddr_t *)&sp->i2ohba_util_buffer, &sp->rlen,
		    &sp->dma_acc_handle) != DDI_SUCCESS) {
			i2ohba_i_log(NULL, CE_WARN,
			    "?i2ohba_utilparamget_msg: "
			    "cannot allocate param buffer");
			goto fail;
		}
		bound++;
		/* StdMessageFrame */
		ddi_put16(acc_handle, &msgptr->MessageSize,
		    (sizeof (i2o_getallparam_t) >> 2));

		/* i2o_sge_immediate_data_element */
		put_flags_count_Count(&msgptr->FlagsCount1, ALL_PARAM_BLOCK,
		    acc_handle);

		/* i2o_param_operation_all_template */
		ddi_put16(acc_handle, &msgptr->FieldCount, 0xFFFF);

		/* i2o_sge_simple_element */
		put_flags_count_Flags(
		    &((i2o_getallparam_t *)msgptr)->FlagsCount2,
		    I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT |
		    I2O_SGL_FLAGS_END_OF_BUFFER |
		    I2O_SGL_FLAGS_LAST_ELEMENT, acc_handle);

		put_flags_count_Count(
		    &((i2o_getallparam_t *)msgptr)->FlagsCount2,
		    sp->rlen, acc_handle);

		if (ddi_dma_addr_bind_handle(sp->dmahandle, NULL,
		    sp->i2ohba_util_buffer, (size_t)
		    sizeof (i2o_getallparam_reply_t),
		    DDI_DMA_READ|DDI_DMA_STREAMING, DDI_DMA_SLEEP,
		    NULL, &sp->dmacookie, &count) != DDI_SUCCESS) {
			/*
			 * currently assume simple
			 * addring with one physical
			 * continuous address buffer.
			 */
			i2ohba_i_log(NULL, CE_WARN,
			    "?i2ohba_utilparamget_msg: "
			    "cannot bind buffer");
			goto fail;
		}

		ddi_put32(acc_handle,
		    &((i2o_getallparam_t *)msgptr)->PhysicalAddress,
		    (uint32_t)sp->dmacookie.dmac_address);

		/*
		 * initialized the target param_mutex and cv.
		 * note: given that we don't have target id
		 * yet, (that is why we are here), we'll just
		 * use target[0]'s mutex & cv.
		 */
		sp->mutex = I2OHBA_UTILPARAM_MUTEX(i2ohba, 0);
		sp->cv = I2OHBA_UTILPARAM_CV(i2ohba, 0);
	} else {
		if (allocmsgsize < sizeof (i2o_getsyncparam_t))
			return (rval);

		if (ddi_dma_mem_alloc(sp->dmahandle, (size_t)
		    sizeof (i2o_getsyncparam_reply_t), &dev_attr,
		    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL,
		    (void *)&sp->i2ohba_util_buffer, &sp->rlen,
		    &sp->dma_acc_handle) != DDI_SUCCESS) {
			i2ohba_i_log(NULL, CE_WARN,
			    "?i2ohba_utilparamget_msg: "
			    "cannot allocate param buffer");
			goto fail;
		}
		bound++;
		/* StdMessageFrame */
		ddi_put16(acc_handle, &msgptr->MessageSize,
		    (sizeof (i2o_getsyncparam_t) >> 2));

		/* i2o_sge_immediate_data_element */
		put_flags_count_Count(&msgptr->FlagsCount1, ONE_PARAM_BLOCK,
		    acc_handle);

		/* i2o_param_operation_specific_template */
		ddi_put16(acc_handle, &msgptr->FieldCount, 0x0002);
		ddi_put16(acc_handle, &msgptr->FieldIdx, 0x000A);
		ddi_put16(acc_handle, &msgptr->FieldIdx, 0x0007);

		/* i2o_sge_simple_element */
		put_flags_count_Flags(&msgptr->FlagsCount2,
		    I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT |
		    I2O_SGL_FLAGS_END_OF_BUFFER |
		    I2O_SGL_FLAGS_LAST_ELEMENT, acc_handle);

		put_flags_count_Count(&msgptr->FlagsCount2, sp->rlen,
		    acc_handle);

		if (ddi_dma_addr_bind_handle(sp->dmahandle, NULL,
		    sp->i2ohba_util_buffer, (size_t)
		    sizeof (i2o_getsyncparam_reply_t),
		    DDI_DMA_RDWR|DDI_DMA_STREAMING, DDI_DMA_SLEEP,
		    NULL, &sp->dmacookie, &count) != DDI_DMA_MAPPED) {
			/*
			 * currently assume simple
			 * addring with one physical
			 * continuous address buffer.
			 */
			i2ohba_i_log(NULL, CE_WARN,
			    "?i2ohba_utilparamget_msg: "
			    "cannot bind buffer");
			goto fail;
		}

		ddi_put32(acc_handle, &msgptr->PhysicalAddress,
		    (uint32_t)sp->dmacookie.dmac_address);

		/*
		 * initialized the target param_mutex and cv
		 * tidx holds the target id number
		 */
		sp->mutex = I2OHBA_UTILPARAM_MUTEX(i2ohba, tidx);
		sp->cv = I2OHBA_UTILPARAM_CV(i2ohba, tidx);
	}

#ifdef	I2OHBA_DEBUG
	DEBUGF(2, (CE_CONT, "\nmsgptr: 0x%p\n", (void *)msgptr));
	DEBUGF(2, (CE_CONT, "msgptr->VersionOffset: %x\n",
	    msgptr->VersionOffset));
	DEBUGF(2, (CE_CONT, "msgptr->MsgFlags: %x\n", msgptr->MsgFlags));
	DEBUGF(2, (CE_CONT, "msgptr->MessageSize: %x\n", ddi_get16(acc_handle,
	    &msgptr->MessageSize)));
	DEBUGF(2, (CE_CONT, "msgptr->TargetAddress: %x\n",
	    get_msg_TargetAddress(msgptr, acc_handle)));
	DEBUGF(2, (CE_CONT, "msgptr->InitiatorAddress: %x\n",
	    get_msg_InitiatorAddress(msgptr, acc_handle)));
	DEBUGF(2, (CE_CONT, "msgptr->Function: %x\n",
	    get_msg_Function(msgptr, acc_handle)));
	DEBUGF(2, (CE_CONT, "msgptr->InitContext: %x\n",
	    ddi_get32(acc_handle,
	    &msgptr->InitiatorContext.initiator_context_32bits)));
	DEBUGF(2, (CE_CONT, "msgptr->TransContext: %x\n",
	    ddi_get32(acc_handle, &msgptr->TransactionContext)));
	DEBUGF(2, (CE_CONT, "msgptr->OperationFlags: Resevered\n"));
	DEBUGF(2, (CE_CONT, "msgptr->FlagsCount1.Flags: %x\n",
	    get_flags_count_Flags(&msgptr->FlagsCount1, acc_handle)));
	DEBUGF(2, (CE_CONT, "msgptr->FlagsCount1.Count: %x\n",
	    get_flags_count_Count(&msgptr->FlagsCount1, acc_handle)));
	DEBUGF(2, (CE_CONT, "msgptr->OperationCount: %x\n",
	    ddi_get16(acc_handle, &msgptr->OperationCount)));
	DEBUGF(2, (CE_CONT, "msgptr->Operation: %x\n",
	    ddi_get16(acc_handle, &msgptr->Operation)));
	DEBUGF(2, (CE_CONT, "msgptr->GroupNumber: %x\n",
	    ddi_get16(acc_handle, &msgptr->GroupNumber)));
	DEBUGF(2, (CE_CONT, "msgptr->FieldCount: %x\n",
	    ddi_get16(acc_handle, &msgptr->FieldCount)));
	DEBUGF(2, (CE_CONT, "msgptr->FlagsCount2.Flags: %x\n",
	    get_flags_count_Flags(&((i2o_getallparam_t *)msgptr)->FlagsCount2,
	    acc_handle)));
	DEBUGF(2, (CE_CONT, "msgptr->FlagsCount2.Count: %x\n",
	    get_flags_count_Count(&((i2o_getallparam_t *)msgptr)->FlagsCount2,
	    acc_handle)));
	DEBUGF(2, (CE_CONT, "msgptr->PhyAddr: %x\n", ddi_get32(acc_handle,
	    &((i2o_getallparam_t *)msgptr)->PhysicalAddress)));
#endif
	/*
	 * initialized a mutex and condvariable to
	 * send message to IOP, and wait for it
	 * to signal back
	 */
	mutex_enter(sp->mutex);
	sp->wakeup = UTIL_MSG_SLEEP;
	sp->status = 0;
	(void) i2o_msg_send(i2ohba->i2ohba_iophdl, msgptr, msg_handle);
	while (!sp->wakeup)
		cv_wait(sp->cv, sp->mutex);
	mutex_exit(sp->mutex);

	msgptr = NULL;

	/*
	 * process the data
	 */
	switch (sp->status) {
	case I2O_REPLY_STATUS_SUCCESS:
		/*
		 * Success:
		 *   0)	read the reply headers XXLWXX
		 *   1) copy buffer over to the map
		 *   2) unbind dma buffer
		 */

		if (sp->i2ohba_util_buffer) {
			uint_t tgtid;

			if (flag == ALL_UTILPARAMS) {
				i2o_getallparam_reply_t *reply;

				reply = (i2o_getallparam_reply_t *)
				    sp->i2ohba_util_buffer;
				map[tidx].scsi_info_scalar.DeviceType =
				    reply->DeviceType;
				DEBUGF(2, (CE_CONT, "/tDeviceType:"
				    " 0x%x", reply->DeviceType));
				map[tidx].scsi_info_scalar.Flags =
				    reply->Flags;
				DEBUGF(2, (CE_CONT, "/tFlags:"
				    " 0x%x", reply->Flags));
				map[tidx].scsi_info_scalar.Identifier =
				    tgtid =
				    ddi_get32(sp->dma_acc_handle,
				    &reply->Identifier);
				DEBUGF(2, (CE_CONT, "/tSCSI Id: 0x%x",
				    tgtid));
				map[tidx].scsi_info_scalar.LunInfo[0] = 0;
				map[tidx].scsi_info_scalar.QueueDepth =
				    ddi_get32(sp->dma_acc_handle,
				    &reply->QueueDepth);
				DEBUGF(2, (CE_CONT, "/tQueueDepth: 0x%x",
				    map[tidx].scsi_info_scalar.QueueDepth));
				map[tidx].scsi_info_scalar.NegOffset =
				    reply->NegOffset;
				DEBUGF(2, (CE_CONT, "/tQueueDepth: 0x%x",
				    reply->NegOffset));
				map[tidx].scsi_info_scalar.NegDataWidth =
				    reply->NegDataWidth;
				DEBUGF(2, (CE_CONT, "/tNegDataWidth: 0x%x",
				    reply->NegDataWidth));
				map[tidx].scsi_info_scalar.NegSyncRate =
				    ddi_get64(sp->dma_acc_handle,
				    &reply->NegSyncRate);
				DEBUGF(2, (CE_CONT, "/tNegSyncRate: 0x%x",
				    (uint32_t)
				    map[tidx].scsi_info_scalar.NegSyncRate));

				tgtmap[tgtid] = &map[tidx];

			} else {
				i2o_getsyncparam_reply_t *reply;

				reply = (i2o_getsyncparam_reply_t *)
				    sp->i2ohba_util_buffer;
				tgtmap[tidx]->scsi_info_scalar.NegSyncRate =
				    ddi_get64(sp->dma_acc_handle,
				    &reply->NegSyncRate);
				DEBUGF(2, (CE_CONT, "/tNegSyncRate: 0x%x",
				    (uint32_t)
				    map[tidx].scsi_info_scalar.NegSyncRate));
				tgtmap[tidx]->scsi_info_scalar.NegOffset =
				    reply->NegOffset;
				DEBUGF(2, (CE_CONT, "/tNegOffset: 0x%x",
				    reply->NegOffset));
			}
		}
		rval = 0;
		break;

	case I2O_REPLY_STATUS_ERROR_NO_DATA_TRANSFER:
	case I2O_REPLY_STATUS_ERROR_PARTIAL_TRANSFER:
	default:
		i2ohba_i_log(NULL, CE_WARN, "?I2O_PARAM_UTIL_GET on "
		    "Target %d failed", tidx);
		break;

	}

fail:

	if (sp) {
		if (bound) {
			(void) ddi_dma_unbind_handle(sp->dmahandle);
			if (bound > 1)
				(void) ddi_dma_mem_free(&sp->dma_acc_handle);
			(void) ddi_dma_free_handle(&sp->dmahandle);

		}
		kmem_free(sp, sizeof (struct i2ohba_util));
	}

	/* return MFA to IOP */
	if (msgptr) {
		msgptr->VersionOffset = 0;
		msgptr->MsgFlags = 0;
		ddi_put16(acc_handle, &msgptr->MessageSize, 3);
		put_msg_TargetAddress(msgptr, 0, acc_handle);
		put_msg_InitiatorAddress(msgptr, 0, acc_handle);
		put_msg_Function(msgptr, I2O_UTIL_NOP, acc_handle);
		(void) i2o_msg_send(i2ohba->i2ohba_iophdl, msgptr, msg_handle);
	}

	return (rval);
}

/*PRINTFLIKE3*/
static void
i2ohba_i_log(struct i2ohba *i2ohba, int level, char *fmt, ...)
{
	dev_info_t *dip;
	va_list ap;

	ASSERT((mutex_owned(&i2ohba_log_mutex)) == 0 || ddi_in_panic());

	if (i2ohba) {
		dip = i2ohba->i2ohba_dip;
	} else {
		dip = 0;
	}

	mutex_enter(&i2ohba_log_mutex);
	va_start(ap, fmt);
	(void) vsprintf(i2ohba_log_buf, fmt, ap);
	va_end(ap);

	if (level == CE_WARN) {
		scsi_log(dip, "i2o_scsi", level, "%s", i2ohba_log_buf);
	} else {
		scsi_log(dip, "i2o_scsi", level, "%s\n", i2ohba_log_buf);
	}
	mutex_exit(&i2ohba_log_mutex);
}
