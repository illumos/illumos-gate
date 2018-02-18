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
 * Enclosure Services Device target driver
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/targets/sesio.h>
#include <sys/scsi/targets/ses.h>



/*
 * Power management defines (should be in a common include file?)
 */
#define	PM_HARDWARE_STATE_PROP		"pm-hardware-state"
#define	PM_NEEDS_SUSPEND_RESUME		"needs-suspend-resume"


/*
 * Global Driver Data
 */
int ses_io_time = SES_IO_TIME;

static int ses_retry_count = SES_RETRY_COUNT * SES_RETRY_MULTIPLIER;

#ifdef	DEBUG
int ses_debug = 0;
#else	/* DEBUG */
#define	ses_debug	0
#endif	/* DEBUG */


/*
 * External Enclosure Functions
 */
extern int ses_softc_init(ses_softc_t *, int);
extern int ses_init_enc(ses_softc_t *);
extern int ses_get_encstat(ses_softc_t *, int);
extern int ses_set_encstat(ses_softc_t *, uchar_t, int);
extern int ses_get_objstat(ses_softc_t *, ses_objarg *, int);
extern int ses_set_objstat(ses_softc_t *, ses_objarg *, int);

extern int safte_softc_init(ses_softc_t *, int);
extern int safte_init_enc(ses_softc_t *);
extern int safte_get_encstat(ses_softc_t *, int);
extern int safte_set_encstat(ses_softc_t *, uchar_t, int);
extern int safte_get_objstat(ses_softc_t *, ses_objarg *, int);
extern int safte_set_objstat(ses_softc_t *, ses_objarg *, int);

extern int sen_softc_init(ses_softc_t *, int);
extern int sen_init_enc(ses_softc_t *);
extern int sen_get_encstat(ses_softc_t *, int);
extern int sen_set_encstat(ses_softc_t *, uchar_t, int);
extern int sen_get_objstat(ses_softc_t *, ses_objarg *, int);
extern int sen_set_objstat(ses_softc_t *, ses_objarg *, int);

/*
 * Local Function prototypes
 */
static int ses_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int ses_probe(dev_info_t *);
static int ses_attach(dev_info_t *, ddi_attach_cmd_t);
static int ses_detach(dev_info_t *, ddi_detach_cmd_t);

static int is_enc_dev(ses_softc_t *, struct scsi_inquiry *, int, enctyp *);
static int ses_doattach(dev_info_t *dip);

static int  ses_open(dev_t *, int, int, cred_t *);
static int  ses_close(dev_t, int, int, cred_t *);
static int  ses_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static encvec vecs[3] = {
{
	ses_softc_init, ses_init_enc, ses_get_encstat,
	ses_set_encstat, ses_get_objstat, ses_set_objstat
},
{
	safte_softc_init, safte_init_enc, safte_get_encstat,
	safte_set_encstat, safte_get_objstat, safte_set_objstat,
},
{
	sen_softc_init, sen_init_enc, sen_get_encstat,
	sen_set_encstat, sen_get_objstat, sen_set_objstat
}
};


/*
 * Local Functions
 */
static int ses_start(struct buf *bp);
static int ses_decode_sense(struct scsi_pkt *pkt, int *err);

static void ses_get_pkt(struct buf *bp, int (*func)(opaque_t));
static void ses_callback(struct scsi_pkt *pkt);
static void ses_restart(void *arg);


/*
 * Local Static Data
 */
#ifndef	D_HOTPLUG
#define	D_HOTPLUG	0
#endif /* D_HOTPLUG */

static struct cb_ops ses_cb_ops = {
	ses_open,			/* open */
	ses_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	ses_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab  */
#if	!defined(CB_REV)
	D_MP | D_NEW | D_HOTPLUG	/* Driver compatibility flag */
#else	/* !defined(CB_REV) */
	D_MP | D_NEW | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* cb_ops version number */
	nodev,				/* aread */
	nodev				/* awrite */
#endif	/* !defined(CB_REV) */
};

static struct dev_ops ses_dev_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ses_info,		/* info */
	nulldev,		/* identify */
	ses_probe,		/* probe */
	ses_attach,		/* attach */
	ses_detach,		/* detach */
	nodev,			/* reset */
	&ses_cb_ops,		/* driver operations */
	(struct bus_ops *)NULL,	/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static void *estate  = NULL;
static const char *Snm = "ses";
static const char *Str = "%s\n";
static const char *efl = "copyin/copyout EFAULT @ line %d";
static const char *fail_msg = "%stransport failed: reason '%s': %s";



/*
 * autoconfiguration routines.
 */

static struct modldrv modldrv = {
	&mod_driverops,
	"SCSI Enclosure Services",
	&ses_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};


int
_init(void)
{
	int status;
	status = ddi_soft_state_init(&estate, sizeof (ses_softc_t), 0);
	if (status == 0) {
		if ((status = mod_install(&modlinkage)) != 0) {
			ddi_soft_state_fini(&estate);
		}
	}
	return (status);
}

int
_fini(void)
{
	int status;
	if ((status = mod_remove(&modlinkage)) != 0) {
		return (status);
	}
	ddi_soft_state_fini(&estate);
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
ses_probe(dev_info_t *dip)
{
	int			err;
	struct scsi_device	*devp;
	enctyp			ep;

	/*
	 * I finally figured out why we return success
	 * on every probe. The devices that we attach to
	 * don't all report as being the same "device type"
	 *
	 * 1) A5x00 -- report as Enclosure Services (0xD) SES
	 * 2) A1000 -- report as Direct Access (0x0) SES
	 *    uses the same target as raid controler.
	 * 3) D1000 -- report as processor (0x3) SAFTE
	 * 3) D240  -- report as processor (0x3) SAFTE
	 *
	 * We also reportedly attach to SEN devices which I
	 * believe reside in a Tobasco tray.  I have never
	 * been able to get one to attach.
	 *
	 */
	if (dip == NULL)
		return (DDI_PROBE_FAILURE);
	/* SES_LOG(NULL, SES_CE_DEBUG1, "ses_probe: OK"); */
	if (ddi_dev_is_sid(dip) == DDI_SUCCESS) {
		return (DDI_PROBE_DONTCARE);
	}

	devp = ddi_get_driver_private(dip);

	/* Legacy: prevent driver.conf specified ses nodes on atapi. */
	if (scsi_ifgetcap(&devp->sd_address, "interconnect-type", -1) ==
	    INTERCONNECT_ATAPI)
		return (DDI_PROBE_FAILURE);

	/*
	 * XXX: Breakage from the x86 folks.
	 */
	if (strcmp(ddi_get_name(ddi_get_parent(dip)), "ata") == 0) {
		return (DDI_PROBE_FAILURE);
	}

	switch (err = scsi_probe(devp, SLEEP_FUNC)) {
	case SCSIPROBE_EXISTS:
		if (is_enc_dev(NULL, devp->sd_inq, SUN_INQSIZE, &ep)) {
			break;
		}
		/* FALLTHROUGH */
	case SCSIPROBE_NORESP:
		scsi_unprobe(devp);
		return (DDI_PROBE_FAILURE);
	default:
		SES_LOG(NULL, SES_CE_DEBUG9,
		    "ses_probe: probe error %d", err);
		scsi_unprobe(devp);
		return (DDI_PROBE_FAILURE);
	}
	scsi_unprobe(devp);
	return (DDI_PROBE_SUCCESS);
}

static int
ses_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int inst, err;
	ses_softc_t *ssc;

	inst = ddi_get_instance(dip);
	switch (cmd) {
	case DDI_ATTACH:
		SES_LOG(NULL, SES_CE_DEBUG9, "ses_attach: DDI_ATTACH ses%d",
		    inst);

		err = ses_doattach(dip);

		if (err == DDI_FAILURE) {
			return (DDI_FAILURE);
		}
		SES_LOG(NULL, SES_CE_DEBUG4,
		    "ses_attach: DDI_ATTACH OK ses%d", inst);
		break;

	case DDI_RESUME:
		if ((ssc = ddi_get_soft_state(estate, inst)) == NULL) {
			return (DDI_FAILURE);
		}
		SES_LOG(ssc, SES_CE_DEBUG1, "ses_attach: DDI_ATTACH ses%d",
		    inst);
		ssc->ses_suspended = 0;
		break;

	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
is_enc_dev(ses_softc_t *ssc, struct scsi_inquiry *inqp, int iqlen, enctyp *ep)
{
	uchar_t dt = (inqp->inq_dtype & DTYPE_MASK);
	uchar_t *iqd = (uchar_t *)inqp;

	if (dt == DTYPE_ESI) {
		if (strncmp(inqp->inq_vid, SEN_ID, SEN_ID_LEN) == 0) {
			SES_LOG(ssc, SES_CE_DEBUG3, "SEN device found");
			*ep = SEN_TYPE;
		} else if (inqp->inq_rdf == RDF_SCSI2) {
			/*
			 * Per SPC4 #6.4.2 Standard Inquiry Data, response
			 * data format (RDF) values of 0 and 1 are Obsolete,
			 * whereas values greater than 2 are Reserved
			 */
			SES_LOG(ssc, SES_CE_DEBUG3, "SES device found");
			*ep = SES_TYPE;
		} else {
			SES_LOG(ssc, SES_CE_DEBUG3, "Pre-SCSI3 SES device");
			*ep = SES_TYPE;
		}
		return (1);
	}
	if ((iqd[6] & 0x40) && inqp->inq_rdf >= RDF_SCSI2) {
		/*
		 * PassThrough Device.
		 */
		*ep = SES_TYPE;
		SES_LOG(ssc, SES_CE_DEBUG3, "Passthru SES device");
		return (1);
	}

	if (iqlen < 47) {
		SES_LOG(ssc, CE_NOTE,
		    "INQUIRY data too short to determine SAF-TE");
		return (0);
	}
	if (strncmp((char *)&iqd[44], "SAF-TE", 4) == 0) {
		*ep = SAFT_TYPE;
		SES_LOG(ssc, SES_CE_DEBUG3, "SAF-TE device found");
		return (1);
	}
	return (0);
}


/*
 * Attach ses device.
 *
 * XXX:  Power management is NOT supported.  A token framework
 *       is provided that will need to be extended assuming we have
 *       ses devices we can power down.  Currently, we don't have any.
 */
static int
ses_doattach(dev_info_t *dip)
{
	int inst, err;
	Scsidevp devp;
	ses_softc_t *ssc;
	enctyp etyp;

	inst = ddi_get_instance(dip);
	/*
	 * Workaround for bug #4154979- for some reason we can
	 * be called with identical instance numbers but for
	 * different dev_info_t-s- all but one are bogus.
	 *
	 * Bad Dog! No Biscuit!
	 *
	 * A quick workaround might be to call ddi_soft_state_zalloc
	 * unconditionally, as the implementation fails these calls
	 * if there's an item already allocated. A more reasonable
	 * and longer term change is to move the allocation past
	 * the probe for the device's existence as most of these
	 * 'bogus' calls are for nonexistent devices.
	 */

	devp  = ddi_get_driver_private(dip);
	devp->sd_dev = dip;

	/*
	 * Determine whether the { i, t, l } we're called
	 * to start is an enclosure services device.
	 */

	/*
	 * Call the scsi_probe routine to see whether
	 * we actually have an Enclosure Services device at
	 * this address.
	 */
	err = scsi_probe(devp, SLEEP_FUNC);
	if (err != SCSIPROBE_EXISTS) {
		SES_LOG(NULL, SES_CE_DEBUG9,
		    "ses_doattach: probe error %d", err);
		scsi_unprobe(devp);
		return (DDI_FAILURE);
	}
	/* Call is_enc_dev() to get the etyp */
	if (!(is_enc_dev(NULL, devp->sd_inq, SUN_INQSIZE, &etyp))) {
		SES_LOG(NULL, CE_WARN,
		    "ses_doattach: ses%d: is_enc_dev failure", inst);
		scsi_unprobe(devp);
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(estate, inst) != DDI_SUCCESS) {
		scsi_unprobe(devp);
		SES_LOG(NULL, CE_NOTE, "ses%d: softalloc fails", inst);
		return (DDI_FAILURE);
	}
	ssc = ddi_get_soft_state(estate, inst);
	if (ssc == NULL) {
		scsi_unprobe(devp);
		SES_LOG(NULL, CE_NOTE, "ses%d: get_soft_state fails", inst);
		return (DDI_FAILURE);
	}
	devp->sd_private = (opaque_t)ssc;
	ssc->ses_devp = devp;
	err = ddi_create_minor_node(dip, "0", S_IFCHR, inst,
	    DDI_NT_SCSI_ENCLOSURE, NULL);
	if (err == DDI_FAILURE) {
		ddi_remove_minor_node(dip, NULL);
		SES_LOG(ssc, CE_NOTE, "minor node creation failed");
		ddi_soft_state_free(estate, inst);
		scsi_unprobe(devp);
		return (DDI_FAILURE);
	}

	ssc->ses_type = etyp;
	ssc->ses_vec = vecs[etyp];

	/* Call SoftC Init Routine A bit later... */

	ssc->ses_rqbp = scsi_alloc_consistent_buf(SES_ROUTE(ssc),
	    NULL, MAX_SENSE_LENGTH, B_READ, SLEEP_FUNC, NULL);
	if (ssc->ses_rqbp != NULL) {
		ssc->ses_rqpkt = scsi_init_pkt(SES_ROUTE(ssc), NULL,
		    ssc->ses_rqbp, CDB_GROUP0, 1, 0, PKT_CONSISTENT,
		    SLEEP_FUNC, NULL);
	}
	if (ssc->ses_rqbp == NULL || ssc->ses_rqpkt == NULL) {
		ddi_remove_minor_node(dip, NULL);
		SES_LOG(ssc, CE_NOTE, "scsi_init_pkt of rqbuf failed");
		if (ssc->ses_rqbp != NULL) {
			scsi_free_consistent_buf(ssc->ses_rqbp);
			ssc->ses_rqbp = NULL;
		}
		ddi_soft_state_free(estate, inst);
		scsi_unprobe(devp);
		return (DDI_FAILURE);
	}
	ssc->ses_rqpkt->pkt_private = (opaque_t)ssc;
	ssc->ses_rqpkt->pkt_address = *(SES_ROUTE(ssc));
	ssc->ses_rqpkt->pkt_comp = ses_callback;
	ssc->ses_rqpkt->pkt_time = ses_io_time;
	ssc->ses_rqpkt->pkt_flags = FLAG_NOPARITY|FLAG_NODISCON|FLAG_SENSING;
	ssc->ses_rqpkt->pkt_cdbp[0] = SCMD_REQUEST_SENSE;
	ssc->ses_rqpkt->pkt_cdbp[1] = 0;
	ssc->ses_rqpkt->pkt_cdbp[2] = 0;
	ssc->ses_rqpkt->pkt_cdbp[3] = 0;
	ssc->ses_rqpkt->pkt_cdbp[4] = MAX_SENSE_LENGTH;
	ssc->ses_rqpkt->pkt_cdbp[5] = 0;

	switch (scsi_ifgetcap(SES_ROUTE(ssc), "auto-rqsense", 1)) {
	case 1:
		/* if already set, don't reset it */
		ssc->ses_arq = 1;
		break;
	case 0:
		/* try and set it */
		ssc->ses_arq = ((scsi_ifsetcap(SES_ROUTE(ssc),
		    "auto-rqsense", 1, 1) == 1) ? 1 : 0);
		break;
	default:
		/* probably undefined, so zero it out */
		ssc->ses_arq = 0;
		break;
	}

	ssc->ses_sbufp = getrbuf(KM_SLEEP);
	cv_init(&ssc->ses_sbufcv, NULL, CV_DRIVER, NULL);

	/*
	 * If the HBA supports wide, tell it to use wide.
	 */
	if (scsi_ifgetcap(SES_ROUTE(ssc), "wide-xfer", 1) != -1) {
		int wd = ((devp->sd_inq->inq_rdf == RDF_SCSI2) &&
		    (devp->sd_inq->inq_wbus16 || devp->sd_inq->inq_wbus32))
		    ? 1 : 0;
		(void) scsi_ifsetcap(SES_ROUTE(ssc), "wide-xfer", wd, 1);
	}

	/*
	 * Now do ssc init of enclosure specifics.
	 * At the same time, check to make sure getrbuf
	 * actually succeeded.
	 */
	if ((*ssc->ses_vec.softc_init)(ssc, 1)) {
		SES_LOG(ssc, SES_CE_DEBUG3, "failed softc init");
		(void) (*ssc->ses_vec.softc_init)(ssc, 0);
		ddi_remove_minor_node(dip, NULL);
		scsi_destroy_pkt(ssc->ses_rqpkt);
		scsi_free_consistent_buf(ssc->ses_rqbp);
		if (ssc->ses_sbufp) {
			freerbuf(ssc->ses_sbufp);
		}
		cv_destroy(&ssc->ses_sbufcv);
		ddi_soft_state_free(estate, inst);
		scsi_unprobe(devp);
		return (DDI_FAILURE);
	}

	/*
	 * create this property so that PM code knows we want
	 * to be suspended at PM time
	 */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    PM_HARDWARE_STATE_PROP, PM_NEEDS_SUSPEND_RESUME);

	/* announce the existence of this device */
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}


/*
 * Detach ses device.
 *
 * XXX:  Power management is NOT supported.  A token framework
 *       is provided that will need to be extended assuming we have
 *       ses devices we can power down.  Currently, we don't have any.
 */
static int
ses_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ses_softc_t *ssc;
	int inst;

	switch (cmd) {
	case DDI_DETACH:
		inst = ddi_get_instance(dip);
		ssc = ddi_get_soft_state(estate, inst);
		if (ssc == NULL) {
			cmn_err(CE_NOTE,
			    "ses%d: DDI_DETACH, no softstate found", inst);
			return (DDI_FAILURE);
		}
		if (ISOPEN(ssc)) {
			return (DDI_FAILURE);
		}

#if		!defined(lint)
		/* LINTED */
		_NOTE(COMPETING_THREADS_NOW);
#endif		/* !defined(lint) */

		if (ssc->ses_vec.softc_init)
			(void) (*ssc->ses_vec.softc_init)(ssc, 0);

#if		!defined(lint)
		_NOTE(NO_COMPETING_THREADS_NOW);
#endif 		/* !defined(lint) */

		(void) scsi_ifsetcap(SES_ROUTE(ssc), "auto-rqsense", 1, 0);
		scsi_destroy_pkt(ssc->ses_rqpkt);
		scsi_free_consistent_buf(ssc->ses_rqbp);
		freerbuf(ssc->ses_sbufp);
		cv_destroy(&ssc->ses_sbufcv);
		ddi_soft_state_free(estate, inst);
		ddi_prop_remove_all(dip);
		ddi_remove_minor_node(dip, NULL);
		scsi_unprobe(ddi_get_driver_private(dip));
		break;

	case DDI_SUSPEND:
		inst = ddi_get_instance(dip);
		if ((ssc = ddi_get_soft_state(estate, inst)) == NULL) {
			cmn_err(CE_NOTE,
			    "ses%d: DDI_SUSPEND, no softstate found", inst);
			return (DDI_FAILURE);
		}

		/*
		 * If driver idle, accept suspend request.
		 * If it's busy, reject it.  This keeps things simple!
		 */
		mutex_enter(SES_MUTEX);
		if (ssc->ses_sbufbsy) {
			mutex_exit(SES_MUTEX);
			return (DDI_FAILURE);
		}
		ssc->ses_suspended = 1;
		mutex_exit(SES_MUTEX);
		break;

	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
ses_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t dev;
	ses_softc_t *ssc;
	int inst, error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		inst = getminor(dev);
		if ((ssc = ddi_get_soft_state(estate, inst)) == NULL) {
			return (DDI_FAILURE);
		}
		*result = (void *) ssc->ses_devp->sd_dev;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		inst = getminor(dev);
		*result = (void *)(uintptr_t)inst;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}


/*
 * Unix Entry Points
 */

/* ARGSUSED */
static int
ses_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	ses_softc_t *ssc;

	if ((ssc = ddi_get_soft_state(estate, getminor(*dev_p))) == NULL) {
		return (ENXIO);
	}

	/*
	 * If the device is powered down, request it's activation.
	 * If it can't be activated, fail open.
	 */
	if (ssc->ses_suspended &&
	    ddi_dev_is_needed(SES_DEVINFO(ssc), 0, 1) != DDI_SUCCESS) {
		return (EIO);
	}

	mutex_enter(SES_MUTEX);
	if (otyp == OTYP_LYR)
		ssc->ses_lyropen++;
	else
		ssc->ses_oflag = 1;

	ssc->ses_present = (ssc->ses_present)? ssc->ses_present: SES_OPENING;
	mutex_exit(SES_MUTEX);
	return (EOK);
}

/*ARGSUSED*/
static int
ses_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	ses_softc_t *ssc;
	if ((ssc = ddi_get_soft_state(estate, getminor(dev))) == NULL) {
		return (ENXIO);
	}

	if (ssc->ses_suspended) {
		(void) ddi_dev_is_needed(SES_DEVINFO(ssc), 0, 1);
	}

	mutex_enter(SES_MUTEX);
	if (otyp == OTYP_LYR)
		ssc->ses_lyropen -= (ssc->ses_lyropen)? 1: 0;
	else
		ssc->ses_oflag = 0;
	mutex_exit(SES_MUTEX);
	return (0);
}


/*ARGSUSED3*/
static int
ses_ioctl(dev_t dev, int cmd, intptr_t arg, int flg, cred_t *cred_p, int *rvalp)
{
	ses_softc_t *ssc;
	ses_object k, *up;
	ses_objarg x;
	uchar_t t;
	uchar_t i;
	int rv = 0;

	if ((ssc = ddi_get_soft_state(estate, getminor(dev))) == NULL ||
	    ssc->ses_present == SES_CLOSED) {
		return (ENXIO);
	}


	switch (cmd) {
	case SESIOC_GETNOBJ:
		if (ddi_copyout(&ssc->ses_nobjects, (void *)arg,
		    sizeof (int), flg)) {
			rv = EFAULT;
			break;
		}
		break;

	case SESIOC_GETOBJMAP:
		up = (ses_object *) arg;
		mutex_enter(SES_MUTEX);
		for (i = 0; i != ssc->ses_nobjects; i++) {
			k.obj_id = i;
			k.subencid = ssc->ses_objmap[i].subenclosure;
			k.elem_type = ssc->ses_objmap[i].enctype;
			if (ddi_copyout(&k, up, sizeof (k), flg)) {
				rv = EFAULT;
				break;
			}
			up++;
		}
		mutex_exit(SES_MUTEX);
		break;

	case SESIOC_INIT:
		if (drv_priv(cred_p) != 0) {
			rv = EPERM;
			break;
		}
		rv = (*ssc->ses_vec.init_enc)(ssc);
		break;

	case SESIOC_GETENCSTAT:
		if ((ssc->ses_encstat & ENCI_SVALID) == 0) {
			rv = (*ssc->ses_vec.get_encstat)(ssc, KM_SLEEP);
			if (rv) {
				break;
			}
		}
		t = ssc->ses_encstat & 0xf;
		if (ddi_copyout(&t, (void *)arg, sizeof (t), flg))
			rv = EFAULT;
		/*
		 * And always invalidate enclosure status on the way out.
		 */
		mutex_enter(SES_MUTEX);
		ssc->ses_encstat &= ~ENCI_SVALID;
		mutex_exit(SES_MUTEX);
		break;

	case SESIOC_SETENCSTAT:
		if (drv_priv(cred_p) != 0) {
			rv = EPERM;
			break;
		}
		if (ddi_copyin((void *)arg, &t, sizeof (t), flg))
			rv = EFAULT;
		else
			rv = (*ssc->ses_vec.set_encstat)(ssc, t, KM_SLEEP);
		mutex_enter(SES_MUTEX);
		ssc->ses_encstat &= ~ENCI_SVALID;
		mutex_exit(SES_MUTEX);
		break;

	case SESIOC_GETOBJSTAT:
		if (ddi_copyin((void *)arg, &x, sizeof (x), flg)) {
			rv = EFAULT;
			break;
		}
		if (x.obj_id >= ssc->ses_nobjects) {
			rv = EINVAL;
			break;
		}
		if ((rv = (*ssc->ses_vec.get_objstat)(ssc, &x, KM_SLEEP)) != 0)
			break;
		if (ddi_copyout(&x, (void *)arg, sizeof (x), flg))
			rv = EFAULT;
		else {
			/*
			 * Now that we no longer poll, svalid never stays true.
			 */
			mutex_enter(SES_MUTEX);
			ssc->ses_objmap[x.obj_id].svalid = 0;
			mutex_exit(SES_MUTEX);
		}
		break;

	case SESIOC_SETOBJSTAT:
		if (drv_priv(cred_p) != 0) {
			rv = EPERM;
			break;
		}
		if (ddi_copyin((void *)arg, &x, sizeof (x), flg)) {
			rv = EFAULT;
			break;
		}
		if (x.obj_id >= ssc->ses_nobjects) {
			rv = EINVAL;
			break;
		}
		rv = (*ssc->ses_vec.set_objstat)(ssc, &x, KM_SLEEP);
		if (rv == 0) {
			mutex_enter(SES_MUTEX);
			ssc->ses_objmap[x.obj_id].svalid = 0;
			mutex_exit(SES_MUTEX);
		}
		break;

	case USCSICMD:
		if (drv_priv(cred_p) != 0) {
			rv = EPERM;
			break;
		}
		rv = ses_uscsi_cmd(ssc, (Uscmd *)arg, flg);
		break;

	default:
		rv = ENOTTY;
		break;
	}
	return (rv);
}


/*
 * Loop on running a kernel based command
 *
 * FIXME:  This routine is not really needed.
 */
int
ses_runcmd(ses_softc_t *ssc, Uscmd *lp)
{
	int e;

	lp->uscsi_status = 0;
	e = ses_uscsi_cmd(ssc, lp, FKIOCTL);

#ifdef	not
	/*
	 * Debug:  Nice cross-check code for verifying consistent status.
	 */
	if (lp->uscsi_status) {
		if (lp->uscsi_status == STATUS_CHECK) {
			SES_LOG(ssc, CE_NOTE, "runcmd<cdb[0]="
			    "0x%x->%s ASC/ASCQ=0x%x/0x%x>",
			    lp->uscsi_cdb[0],
			    scsi_sname(lp->uscsi_rqbuf[2] & 0xf),
			    lp->uscsi_rqbuf[12] & 0xff,
			    lp->uscsi_rqbuf[13] & 0xff);
		} else {
			SES_LOG(ssc, CE_NOTE, "runcmd<cdb[0]="
			    "0x%x -> Status 0x%x", lp->uscsi_cdb[0],
			    lp->uscsi_status);
		}
	}
#endif	/* not */
	return (e);
}


/*
 * Run a scsi command.
 */
int
ses_uscsi_cmd(ses_softc_t *ssc, Uscmd *Uc, int Uf)
{
	Uscmd	*uscmd;
	struct buf	*bp;
	enum uio_seg	uioseg;
	int	err;

	/*
	 * Grab local 'special' buffer
	 */
	mutex_enter(SES_MUTEX);
	while (ssc->ses_sbufbsy) {
		cv_wait(&ssc->ses_sbufcv, &ssc->ses_devp->sd_mutex);
	}
	ssc->ses_sbufbsy = 1;
	mutex_exit(SES_MUTEX);

	/*
	 * If the device is powered down, request it's activation.
	 * This check must be done after setting ses_sbufbsy!
	 */
	if (ssc->ses_suspended &&
	    ddi_dev_is_needed(SES_DEVINFO(ssc), 0, 1) != DDI_SUCCESS) {
		mutex_enter(SES_MUTEX);
		ssc->ses_sbufbsy = 0;
		mutex_exit(SES_MUTEX);
		return (EIO);
	}

	err = scsi_uscsi_alloc_and_copyin((intptr_t)Uc, Uf,
	    SES_ROUTE(ssc), &uscmd);
	if (err != 0) {
		SES_LOG(ssc, SES_CE_DEBUG1, "ses_uscsi_cmd: "
		    "scsi_uscsi_alloc_and_copyin failed\n");
		mutex_enter(SES_MUTEX);
		ssc->ses_sbufbsy = 0;
		cv_signal(&ssc->ses_sbufcv);
		mutex_exit(SES_MUTEX);
		SES_LOG(ssc, SES_CE_DEBUG2, efl, __LINE__);
		return (err);
	}

	/*
	 * Copy the uscsi command related infos to ssc for use in ses_start()
	 * and ses_callback().
	 */
	bcopy(uscmd, &ssc->ses_uscsicmd, sizeof (Uscmd));
	if (uscmd->uscsi_cdb != NULL) {
		bcopy(uscmd->uscsi_cdb, &ssc->ses_srqcdb,
		    (size_t)(uscmd->uscsi_cdblen));
	}
	ssc->ses_uscsicmd.uscsi_status = 0;

	bp = ssc->ses_sbufp;
	bp->av_back = (struct buf *)NULL;
	bp->av_forw = (struct buf *)NULL;
	bp->b_back = (struct buf *)ssc;
	bp->b_edev = NODEV;

	if (uscmd->uscsi_cdb != NULL) {
		if (uscmd->uscsi_cdblen == CDB_GROUP0) {
			SES_LOG(ssc, SES_CE_DEBUG7,
			    "scsi_cmd: %x %x %x %x %x %x",
			    ((char *)uscmd->uscsi_cdb)[0],
			    ((char *)uscmd->uscsi_cdb)[1],
			    ((char *)uscmd->uscsi_cdb)[2],
			    ((char *)uscmd->uscsi_cdb)[3],
			    ((char *)uscmd->uscsi_cdb)[4],
			    ((char *)uscmd->uscsi_cdb)[5]);
		} else {
			SES_LOG(ssc, SES_CE_DEBUG7,
			    "scsi cmd: %x %x %x %x %x %x %x %x %x %x",
			    ((char *)uscmd->uscsi_cdb)[0],
			    ((char *)uscmd->uscsi_cdb)[1],
			    ((char *)uscmd->uscsi_cdb)[2],
			    ((char *)uscmd->uscsi_cdb)[3],
			    ((char *)uscmd->uscsi_cdb)[4],
			    ((char *)uscmd->uscsi_cdb)[5],
			    ((char *)uscmd->uscsi_cdb)[6],
			    ((char *)uscmd->uscsi_cdb)[7],
			    ((char *)uscmd->uscsi_cdb)[8],
			    ((char *)uscmd->uscsi_cdb)[9]);
		}
	}

	uioseg = (Uf & FKIOCTL) ? UIO_SYSSPACE : UIO_USERSPACE;
	err = scsi_uscsi_handle_cmd(NODEV, uioseg, uscmd,
	    ses_start, bp, NULL);

	/*
	 * ses_callback() may set values for ssc->ses_uscsicmd or
	 * ssc->ses_srqsbuf, so copy them back to uscmd.
	 */
	if (uscmd->uscsi_rqbuf != NULL) {
		bcopy(&ssc->ses_srqsbuf, uscmd->uscsi_rqbuf,
		    (size_t)(uscmd->uscsi_rqlen));
		uscmd->uscsi_rqresid = ssc->ses_uscsicmd.uscsi_rqresid;
	}
	uscmd->uscsi_status = ssc->ses_uscsicmd.uscsi_status;

	(void) scsi_uscsi_copyout_and_free((intptr_t)Uc, uscmd);
	mutex_enter(SES_MUTEX);
	ssc->ses_sbufbsy = 0;
	cv_signal(&ssc->ses_sbufcv);
	mutex_exit(SES_MUTEX);

	return (err);
}



/*
 * Command start and done functions.
 */
static int
ses_start(struct buf *bp)
{
	ses_softc_t *ssc = (ses_softc_t *)bp->b_back;

	SES_LOG(ssc, SES_CE_DEBUG9, "ses_start");
	if (!BP_PKT(bp)) {
		/*
		 * Allocate a packet.
		 */
		ses_get_pkt(bp, SLEEP_FUNC);
		if (!BP_PKT(bp)) {
			int err;
			bp->b_resid = bp->b_bcount;
			if (geterror(bp) == 0)
				SET_BP_ERROR(bp, EIO);
			err = geterror(bp);
			biodone(bp);
			return (err);
		}
	}

	/*
	 * Initialize the transfer residue, error code, and retry count.
	 */
	bp->b_resid = 0;
	SET_BP_ERROR(bp, 0);

#if	!defined(lint)
	_NOTE(NO_COMPETING_THREADS_NOW);
#endif 	/* !defined(lint) */
	ssc->ses_retries = ses_retry_count;

#if	!defined(lint)
	/* LINTED */
	_NOTE(COMPETING_THREADS_NOW);
#endif	/* !defined(lint) */

	SES_LOG(ssc, SES_CE_DEBUG9, "ses_start -> scsi_transport");
	switch (scsi_transport(BP_PKT(bp))) {
	case TRAN_ACCEPT:
		return (0);
		/* break; */

	case TRAN_BUSY:
		SES_LOG(ssc, SES_CE_DEBUG2,
		    "ses_start: TRANSPORT BUSY");
		SES_ENABLE_RESTART(SES_RESTART_TIME, BP_PKT(bp));
		return (0);
		/* break; */

	default:
		SES_LOG(ssc, SES_CE_DEBUG2, "TRANSPORT ERROR\n");
		SET_BP_ERROR(bp, EIO);
		scsi_destroy_pkt(BP_PKT(bp));
		SET_BP_PKT(bp, NULL);
		biodone(bp);
		return (EIO);
		/* break; */
	}
}


static void
ses_get_pkt(struct buf *bp, int (*func)())
{
	ses_softc_t *ssc = (ses_softc_t *)bp->b_back;
	Uscmd *scmd = &ssc->ses_uscsicmd;
	struct scsi_pkt *pkt;
	int stat_size = 1;
	int flags = 0;

	if ((scmd->uscsi_flags & USCSI_RQENABLE) && ssc->ses_arq) {
		if (scmd->uscsi_rqlen > SENSE_LENGTH) {
			stat_size = (int)(scmd->uscsi_rqlen) +
			    sizeof (struct scsi_arq_status) -
			    sizeof (struct scsi_extended_sense);
			flags = PKT_XARQ;
		} else {
			stat_size = sizeof (struct scsi_arq_status);
		}
	}

	if (bp->b_bcount) {
		pkt = scsi_init_pkt(SES_ROUTE(ssc), NULL, bp,
		    scmd->uscsi_cdblen, stat_size, 0, flags,
		    func, (caddr_t)ssc);
	} else {
		pkt = scsi_init_pkt(SES_ROUTE(ssc), NULL, NULL,
		    scmd->uscsi_cdblen, stat_size, 0, flags,
		    func, (caddr_t)ssc);
	}
	SET_BP_PKT(bp, pkt);
	if (pkt == (struct scsi_pkt *)NULL)
		return;
	bcopy(scmd->uscsi_cdb, pkt->pkt_cdbp, (size_t)scmd->uscsi_cdblen);

	/* Set an upper bound timeout of ses_io_time if zero is passed in */
	pkt->pkt_time = (scmd->uscsi_timeout == 0) ?
	    ses_io_time : scmd->uscsi_timeout;

	pkt->pkt_comp = ses_callback;
	pkt->pkt_private = (opaque_t)ssc;
}


/*
 * Restart ses command.
 */
static void
ses_restart(void *arg)
{
	struct scsi_pkt *pkt = (struct scsi_pkt *)arg;
	ses_softc_t *ssc = (ses_softc_t *)pkt->pkt_private;
	struct buf *bp = ssc->ses_sbufp;
	SES_LOG(ssc, SES_CE_DEBUG9, "ses_restart");

	ssc->ses_restart_id = NULL;

	switch (scsi_transport(pkt)) {
	case TRAN_ACCEPT:
		SES_LOG(ssc, SES_CE_DEBUG9,
		    "RESTART %d ok", ssc->ses_retries);
		return;
		/* break; */
	case TRAN_BUSY:
		SES_LOG(ssc, SES_CE_DEBUG1,
		    "RESTART %d TRANSPORT BUSY\n", ssc->ses_retries);
		if (ssc->ses_retries > SES_NO_RETRY) {
			ssc->ses_retries -= SES_BUSY_RETRY;
			SES_ENABLE_RESTART(SES_RESTART_TIME, pkt);
			return;
		}
		SET_BP_ERROR(bp, EBUSY);
		break;
	default:
		SET_BP_ERROR(bp, EIO);
		break;
	}
	SES_LOG(ssc, SES_CE_DEBUG1,
	    "RESTART %d TRANSPORT FAILED\n", ssc->ses_retries);

	pkt = (struct scsi_pkt *)bp->av_back;
	scsi_destroy_pkt(pkt);
	bp->b_resid = bp->b_bcount;
	SET_BP_PKT(bp, NULL);
	biodone(bp);
}


/*
 * Command completion processing
 */
#define	HBA_RESET	(STAT_BUS_RESET|STAT_DEV_RESET|STAT_ABORTED)
static void
ses_callback(struct scsi_pkt *pkt)
{
	ses_softc_t *ssc = (ses_softc_t *)pkt->pkt_private;
	struct buf *bp;
	Uscmd *scmd;
	int err;
	char action;

	bp = ssc->ses_sbufp;
	scmd = &ssc->ses_uscsicmd;
	/* SES_LOG(ssc, SES_CE_DEBUG9, "ses_callback"); */

	/*
	 * Optimization: Normal completion.
	 */
	if (pkt->pkt_reason == CMD_CMPLT &&
	    !SCBP_C(pkt) &&
	    !(pkt->pkt_flags & FLAG_SENSING) &&
	    !pkt->pkt_resid) {
		scsi_destroy_pkt(pkt);
		SET_BP_PKT(bp, NULL);
		biodone(bp);
		return;
	}


	/*
	 * Abnormal completion.
	 *
	 * Assume most common error initially.
	 */
	err = EIO;
	action = COMMAND_DONE;
	if (scmd->uscsi_flags & USCSI_DIAGNOSE) {
		ssc->ses_retries = SES_NO_RETRY;
	}

CHECK_PKT:
	if (pkt->pkt_reason != CMD_CMPLT) {
		/* Process transport errors. */
		switch (pkt->pkt_reason) {
		case CMD_TIMEOUT:
			/*
			 * If the transport layer didn't clear the problem,
			 * reset the target.
			 */
			if (! (pkt->pkt_statistics & HBA_RESET)) {
				(void) scsi_reset(&pkt->pkt_address,
				    RESET_TARGET);
			}
			err = ETIMEDOUT;
			break;

		case CMD_INCOMPLETE:
		case CMD_UNX_BUS_FREE:
			/*
			 * No response?  If probing, give up.
			 * Otherwise, keep trying until retries exhausted.
			 * Then lockdown the driver as the device is
			 * unplugged.
			 */
			if (ssc->ses_retries <= SES_NO_RETRY &&
			    !(scmd->uscsi_flags & USCSI_DIAGNOSE)) {
				ssc->ses_present = SES_CLOSED;
			}
			/* Inhibit retries to speed probe/attach. */
			if (ssc->ses_present < SES_OPEN) {
				ssc->ses_retries = SES_NO_RETRY;
			}
			/* SES_CMD_RETRY4(ssc->ses_retries); */
			err = ENXIO;
			break;

		case CMD_DATA_OVR:
			/*
			 * XXX:	Some HBA's (e.g. Adaptec 1740 and
			 *	earlier ISP revs) report a DATA OVERRUN
			 *	error instead of a transfer residue.  So,
			 *	we convert the error and restart.
			 */
			if ((bp->b_bcount - pkt->pkt_resid) > 0) {
				SES_LOG(ssc, SES_CE_DEBUG6,
				    "ignoring overrun");
				pkt->pkt_reason = CMD_CMPLT;
				err = EOK;
				goto CHECK_PKT;
			}
			ssc->ses_retries = SES_NO_RETRY;
			/* err = EIO; */
			break;

		case CMD_DMA_DERR:
			ssc->ses_retries = SES_NO_RETRY;
			err = EFAULT;
			break;

		default:
			/* err = EIO; */
			break;
		}
		if (pkt == ssc->ses_rqpkt) {
			SES_LOG(ssc, CE_WARN, fail_msg,
			    "Request Sense ",
			    scsi_rname(pkt->pkt_reason),
			    (ssc->ses_retries > 0)?
			    "retrying": "giving up");
			pkt = (struct scsi_pkt *)bp->av_back;
			action = QUE_SENSE;
		} else {
			SES_LOG(ssc, CE_WARN, fail_msg,
			    "", scsi_rname(pkt->pkt_reason),
			    (ssc->ses_retries > 0)?
			    "retrying": "giving up");
			action = QUE_COMMAND;
		}
		/* Device exists, allow full error recovery. */
		if (ssc->ses_retries > SES_NO_RETRY) {
			ssc->ses_present = SES_OPEN;
		}


	/*
	 * Process status and sense data errors.
	 */
	} else {
		ssc->ses_present = SES_OPEN;
		action = ses_decode_sense(pkt, &err);
	}


	/*
	 * Initiate error recovery action, as needed.
	 */
	switch (action) {
	case QUE_COMMAND_NOW:
		/* SES_LOG(ssc, SES_CE_DEBUG1, "retrying cmd now"); */
		if (ssc->ses_retries > SES_NO_RETRY) {
			ssc->ses_retries -= SES_CMD_RETRY;
			scmd->uscsi_status = 0;
			if (ssc->ses_arq)
				bzero(pkt->pkt_scbp,
				    sizeof (struct scsi_arq_status));

			if (scsi_transport((struct scsi_pkt *)bp->av_back)
			    != TRAN_ACCEPT) {
				SES_ENABLE_RESTART(SES_RESTART_TIME,
				    (struct scsi_pkt *)bp->av_back);
			}
			return;
		}
		break;

	case QUE_COMMAND:
		SES_LOG(ssc, SES_CE_DEBUG1, "retrying cmd");
		if (ssc->ses_retries > SES_NO_RETRY) {
			clock_t ms_time;

			ms_time =
			    (err == EBUSY)? SES_BUSY_TIME : SES_RESTART_TIME;
			ssc->ses_retries -=
			    (err == EBUSY)? SES_BUSY_RETRY: SES_CMD_RETRY;
			scmd->uscsi_status = 0;
			if (ssc->ses_arq)
				bzero(pkt->pkt_scbp,
				    sizeof (struct scsi_arq_status));

			SES_ENABLE_RESTART(ms_time,
			    (struct scsi_pkt *)bp->av_back);
			return;
		}
		break;

	case QUE_SENSE:
		SES_LOG(ssc, SES_CE_DEBUG1, "retrying sense");
		if (ssc->ses_retries > SES_NO_RETRY) {
			ssc->ses_retries -= SES_SENSE_RETRY;
			scmd->uscsi_status = 0;
			bzero(&ssc->ses_srqsbuf, MAX_SENSE_LENGTH);

			if (scsi_transport(ssc->ses_rqpkt) != TRAN_ACCEPT) {
				SES_ENABLE_RESTART(SES_RESTART_TIME,
				    ssc->ses_rqpkt);
			}
			return;
		}
		break;

	case COMMAND_DONE:
		SES_LOG(ssc, SES_CE_DEBUG4, "cmd done");
		pkt = (struct scsi_pkt *)bp->av_back;
		bp->b_resid = pkt->pkt_resid;
		if (bp->b_resid) {
			SES_LOG(ssc, SES_CE_DEBUG6,
			    "transfer residue %ld(%ld)",
			    bp->b_bcount - bp->b_resid, bp->b_bcount);
		}
		break;
	}
	pkt = (struct scsi_pkt *)bp->av_back;
	if (err) {
		SES_LOG(ssc, SES_CE_DEBUG1, "SES: ERROR %d\n", err);
		SET_BP_ERROR(bp, err);
		bp->b_resid = bp->b_bcount;
	}
	scsi_destroy_pkt(pkt);
	SET_BP_PKT(bp, NULL);
	biodone(bp);
}


/*
 * Check status and sense data and determine recovery.
 */
static int
ses_decode_sense(struct scsi_pkt *pkt, int *err)
{
	ses_softc_t *ssc = (ses_softc_t *)pkt->pkt_private;
	struct	scsi_extended_sense *sense =
	    (struct scsi_extended_sense *)&ssc->ses_srqsbuf;
	Uscmd *scmd = &ssc->ses_uscsicmd;
	char sense_flag = 0;
	uchar_t status = SCBP_C(pkt) & STATUS_MASK;
	char *err_action;
	char action;
	uchar_t rqlen;
	int amt;

	/*
	 * Process manual request sense.
	 * Copy manual request sense to sense buffer.
	 *
	 * This is done if auto request sense is not enabled.
	 * Or the auto request sense failed and the request
	 * sense needs to be retried.
	 */
	if (pkt->pkt_flags & FLAG_SENSING) {
		struct buf *sbp = ssc->ses_rqbp;
		amt = min(MAX_SENSE_LENGTH,
		    sbp->b_bcount - sbp->b_resid);
		rqlen = min((uchar_t)amt, scmd->uscsi_rqlen);
		bcopy(sbp->b_un.b_addr, sense, rqlen);
		scmd->uscsi_rqresid = scmd->uscsi_rqlen - rqlen;
		sense_flag = 1;
	/*
	 * Process auto request sense.
	 * Copy auto request sense to sense buffer.
	 *
	 * If auto request sense failed due to transport error,
	 * retry the command.  Otherwise process the status and
	 * sense data.
	 */
	} else if (ssc->ses_arq && pkt->pkt_state & STATE_ARQ_DONE) {
		struct scsi_arq_status *arq =
		    (struct scsi_arq_status *)(pkt->pkt_scbp);
		uchar_t *arq_status = (uchar_t *)&arq->sts_rqpkt_status;
		if (pkt->pkt_state & STATE_XARQ_DONE) {
			amt = MAX_SENSE_LENGTH - arq->sts_rqpkt_resid;
		} else {
			if (arq->sts_rqpkt_resid > SENSE_LENGTH) {
				amt = MAX_SENSE_LENGTH - arq->sts_rqpkt_resid;
			} else {
				amt = SENSE_LENGTH - arq->sts_rqpkt_resid;
			}
		}

		if (arq->sts_rqpkt_reason != CMD_CMPLT) {
			return (QUE_COMMAND);
		}

		rqlen = min((uchar_t)amt, scmd->uscsi_rqlen);
		bcopy(&arq->sts_sensedata, sense, rqlen);
		scmd->uscsi_status = status;
		scmd->uscsi_rqresid = scmd->uscsi_rqlen - rqlen;
		status = *arq_status & STATUS_MASK;
		pkt->pkt_state &= ~STATE_ARQ_DONE;
		sense_flag = 1;
	}


	/*
	 * Check status of REQUEST SENSE or command.
	 *
	 * If it's not successful, try retrying the original command
	 * and hope that it goes away.  If not, we'll eventually run
	 * out of retries and die.
	 */
	switch (status) {
	case STATUS_GOOD:
	case STATUS_INTERMEDIATE:
	case STATUS_MET:
		/*
		 * If the command status is ok, we're done.
		 * Otherwise, examine the request sense data.
		 */
		if (! sense_flag) {
			*err = EOK;
			return (COMMAND_DONE);
		}
		break;

	case STATUS_CHECK:
		SES_LOG(ssc, SES_CE_DEBUG3, "status decode: check");
		*err = EIO;
		return (QUE_SENSE);
		/* break; */

	case STATUS_BUSY:
		SES_LOG(ssc, SES_CE_DEBUG1, "status decode: busy");
		/* SES_CMD_RETRY2(ssc->ses_retries); */
		*err = EBUSY;
		return (QUE_COMMAND);
		/* break; */

	case STATUS_RESERVATION_CONFLICT:
		SES_LOG(ssc, SES_CE_DEBUG1, "status decode: reserved");
		*err = EACCES;
		return (COMMAND_DONE_ERROR);
		/* break; */

	case STATUS_TERMINATED:
		SES_LOG(ssc, SES_CE_DEBUG1, "status decode: terminated");
		*err = ECANCELED;
		return (COMMAND_DONE_ERROR);
		/* break; */

	default:
		SES_LOG(ssc, SES_CE_DEBUG1, "status 0x%x", status);
		*err = EIO;
		return (QUE_COMMAND);
		/* break; */
	}


	/*
	 * Check REQUEST SENSE error code.
	 *
	 * Either there's no error, a retryable error,
	 * or it's dead.  SES devices aren't very complex.
	 */
	err_action = "retrying";
	switch (sense->es_key) {
	case KEY_RECOVERABLE_ERROR:
		*err = EOK;
		err_action = "recovered";
		action = COMMAND_DONE;
		break;

	case KEY_UNIT_ATTENTION:
		/*
		 * This is common for RAID!
		 */
		/* *err = EIO; */
		SES_CMD_RETRY1(ssc->ses_retries);
		action = QUE_COMMAND_NOW;
		break;

	case KEY_NOT_READY:
	case KEY_NO_SENSE:
		/* *err = EIO; */
		action = QUE_COMMAND;
		break;

	default:
		/* *err = EIO; */
		err_action = "fatal";
		action = COMMAND_DONE_ERROR;
		break;
	}
	SES_LOG(ssc, SES_CE_DEBUG1,
	    "cdb[0]= 0x%x %s,  key=0x%x, ASC/ASCQ=0x%x/0x%x",
	    scmd->uscsi_cdb[0], err_action,
	    sense->es_key, sense->es_add_code, sense->es_qual_code);

#ifdef 	not
	/*
	 * Dump cdb and sense data stat's for manufacturing.
	 */
	if (DEBUGGING_ERR || sd_error_level == SDERR_ALL) {
		auto buf[128];

		p = pkt->pkt_cdbp;
		if ((j = scsi_cdb_size[CDB_GROUPID(*p)]) == 0)
			j = CDB_SIZE;

		/* Print cdb */
		(void) sprintf(buf, "cmd:");
		for (i = 0; i < j; i++) {
			(void) sprintf(&buf[strlen(buf)],
			    hex, (uchar_t)*p++);
		}
		SES_LOG(ssc, SES_CE_DEBUG3, "%s", buf);

		/* Suppress trailing zero's in sense data */
		if (amt > 3) {
			p = (char *)devp->sd_sense + amt;
			for (j = amt; j > 3; j--) {
				if (*(--p))  break;
			}
		} else {
			j = amt;
		}

		/* Print sense data. */
		(void) sprintf(buf, "sense:");
		p = (char *)devp->sd_sense;
		for (i = 0; i < j; i++) {
			(void) sprintf(&buf[strlen(buf)],
			    hex, (uchar_t)*p++);
		}
		SES_LOG(ssc, SES_CE_DEBUG3, "%s", buf);
	}
#endif 	/* not */
	return (action);
}


/*PRINTFLIKE3*/
void
ses_log(ses_softc_t *ssc, int level, const char *fmt, ...)
{
	va_list	ap;
	char buf[256];

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	if (ssc == (ses_softc_t *)NULL) {
		switch (level) {
		case SES_CE_DEBUG1:
			if (ses_debug > 1)
				cmn_err(CE_NOTE, "%s", buf);
			break;
		case SES_CE_DEBUG2:
			if (ses_debug > 2)
				cmn_err(CE_NOTE, "%s", buf);
			break;
		case SES_CE_DEBUG3:
			if (ses_debug > 3)
				cmn_err(CE_NOTE, "%s", buf);
			break;
		case SES_CE_DEBUG4:
			if (ses_debug > 4)
				cmn_err(CE_NOTE, "%s", buf);
			break;
		case SES_CE_DEBUG5:
			if (ses_debug > 5)
				cmn_err(CE_NOTE, "%s", buf);
			break;
		case SES_CE_DEBUG6:
			if (ses_debug > 6)
				cmn_err(CE_NOTE, "%s", buf);
			break;
		case SES_CE_DEBUG7:
			if (ses_debug > 7)
				cmn_err(CE_NOTE, "%s", buf);
			break;
		case SES_CE_DEBUG8:
			if (ses_debug > 8)
				cmn_err(CE_NOTE, "%s", buf);
			break;
		case SES_CE_DEBUG9:
			if (ses_debug > 9)
				cmn_err(CE_NOTE, "%s", buf);
			break;
		case CE_NOTE:
		case CE_WARN:
		case CE_PANIC:
			cmn_err(level, "%s", buf);
			break;
		case SES_CE_DEBUG:
		default:
			cmn_err(CE_NOTE, "%s", buf);
		break;
		}
		return;
	}

	switch (level) {
	case CE_CONT:
	case CE_NOTE:
	case CE_WARN:
	case CE_PANIC:
		scsi_log(SES_DEVINFO(ssc), (char *)Snm, level, Str, buf);
		break;
	case SES_CE_DEBUG1:
		if (ses_debug > 1)
			scsi_log(SES_DEVINFO(ssc), (char *)Snm, SCSI_DEBUG,
			    Str, buf);
		break;
	case SES_CE_DEBUG2:
		if (ses_debug > 2)
			scsi_log(SES_DEVINFO(ssc), (char *)Snm, SCSI_DEBUG,
			    Str, buf);
		break;
	case SES_CE_DEBUG3:
		if (ses_debug > 3)
			scsi_log(SES_DEVINFO(ssc), (char *)Snm, SCSI_DEBUG,
			    Str, buf);
		break;
	case SES_CE_DEBUG4:
		if (ses_debug > 4)
			scsi_log(SES_DEVINFO(ssc), (char *)Snm, SCSI_DEBUG,
			    Str, buf);
		break;
	case SES_CE_DEBUG5:
		if (ses_debug > 5)
			scsi_log(SES_DEVINFO(ssc), (char *)Snm, SCSI_DEBUG,
			    Str, buf);
		break;
	case SES_CE_DEBUG6:
		if (ses_debug > 6)
			scsi_log(SES_DEVINFO(ssc), (char *)Snm, SCSI_DEBUG,
			    Str, buf);
		break;
	case SES_CE_DEBUG7:
		if (ses_debug > 7)
			scsi_log(SES_DEVINFO(ssc), (char *)Snm, SCSI_DEBUG,
			    Str, buf);
		break;
	case SES_CE_DEBUG8:
		if (ses_debug > 8)
			scsi_log(SES_DEVINFO(ssc), (char *)Snm, SCSI_DEBUG,
			    Str, buf);
		break;
	case SES_CE_DEBUG9:
		if (ses_debug > 9)
			scsi_log(SES_DEVINFO(ssc), (char *)Snm, SCSI_DEBUG,
			    Str, buf);
		break;
	case SES_CE_DEBUG:
	default:
		scsi_log(SES_DEVINFO(ssc), (char *)Snm, SCSI_DEBUG, Str, buf);
		break;
	}
}
/*
 * mode: c
 * Local variables:
 * c-indent-level: 8
 * c-brace-imaginary-offset: 0
 * c-brace-offset: -8
 * c-argdecl-indent: 8
 * c-label-offset: -8
 * c-continued-statement-offset: 8
 * c-continued-brace-offset: 0
 * End:
 */
