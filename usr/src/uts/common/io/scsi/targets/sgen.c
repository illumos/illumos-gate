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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright Siemens 1999
 * All rights reserved.
 */


/*
 * sgen - SCSI generic device driver
 *
 * The sgen driver provides user programs access to SCSI devices that
 * are not supported by other drivers by providing the USCSI(7I) interface.
 */

#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/targets/sgendef.h>

/* The name of the driver, established from the module name in _init. */
static	char *sgen_label	= NULL;

#define	DDI_NT_SGEN		"ddi_generic:scsi"

static char *sgen_devtypes[] = {
	"direct",		/* 0x00 -- disks */
	"sequential",		/* 0x01 */
	"printer",		/* 0x02 */
	"processor",		/* 0x03 */
	"worm",			/* 0x04 */
	"rodirect",		/* 0x05 */
	"scanner",		/* 0x06 */
	"optical",		/* 0x07 */
	"changer",		/* 0x08 */
	"comm",			/* 0x09 */
	"prepress1",		/* 0x0a -- reserved for prepress (ASC IT8) */
	"prepress2",		/* 0x0b -- reserved for prepress (ASC IT8) */
	"array_ctrl",		/* 0x0c -- storage array */
	"ses",			/* 0x0d -- enclosure services */
	"rbc",			/* 0x0e -- simplified block */
	"ocrw",			/* 0x0f -- optical card read/write */
	"bridge",		/* 0x10 -- reserved for bridging expanders */
	"type_0x11",		/* 0x11 */
	"type_0x12",		/* 0x12 */
	"type_0x13",		/* 0x13 */
	"type_0x14",		/* 0x14 */
	"type_0x15",		/* 0x15 */
	"type_0x16",		/* 0x16 */
	"type_0x17",		/* 0x17 */
	"type_0x18",		/* 0x18 */
	"type_0x19",		/* 0x19 */
	"type_0x1a",		/* 0x1a */
	"type_0x1b",		/* 0x1b */
	"type_0x1c",		/* 0x1c */
	"type_0x1d",		/* 0x1d */
	"type_0x1e",		/* 0x1e */
	"type_unknown"		/* 0x1f is "no device type" or "unknown" */
};

#define	SGEN_NDEVTYPES ((sizeof (sgen_devtypes) / sizeof (char *)))

#define	SGEN_INQSTRLEN 24
#define	SGEN_VENDID_MAX 8
#define	SGEN_PRODID_MAX 16

#define	FILL_SCSI1_LUN(devp, pkt)					\
	if ((devp)->sd_inq->inq_ansi == 0x1) {				\
		int _lun;						\
		_lun = ddi_prop_get_int(DDI_DEV_T_ANY, (devp)->sd_dev,	\
		    DDI_PROP_DONTPASS, SCSI_ADDR_PROP_LUN, 0);		\
		if (_lun > 0) {						\
			((union scsi_cdb *)(pkt)->pkt_cdbp)->scc_lun =	\
			    _lun;					\
		}							\
	}

#define	SGEN_DO_ERRSTATS(sg_state, x)  \
	if (sg_state->sgen_kstats) { \
		struct sgen_errstats *sp; \
		sp = (struct sgen_errstats *)sg_state->sgen_kstats->ks_data; \
		sp->x.value.ui32++; \
	}

#define	SCBP_C(pkt)	((*(pkt)->pkt_scbp) & STATUS_MASK)

/*
 * Standard entrypoints
 */
static int sgen_attach(dev_info_t *, ddi_attach_cmd_t);
static int sgen_detach(dev_info_t *, ddi_detach_cmd_t);
static int sgen_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int sgen_probe(dev_info_t *);
static int sgen_open(dev_t *, int, int, cred_t *);
static int sgen_close(dev_t, int, int, cred_t *);
static int sgen_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * Configuration routines
 */
static int sgen_do_attach(dev_info_t *);
static int sgen_setup_sense(sgen_state_t *);
static void sgen_create_errstats(sgen_state_t *, int);
static int sgen_do_suspend(dev_info_t *);
static int sgen_do_detach(dev_info_t *);
static void sgen_setup_binddb(dev_info_t *);
static void sgen_cleanup_binddb();

/*
 * Packet transport routines
 */
static int  sgen_uscsi_cmd(dev_t, struct uscsi_cmd *, int);
static int sgen_start(struct buf *);
static int sgen_hold_cmdbuf(sgen_state_t *);
static void sgen_rele_cmdbuf(sgen_state_t *);
static int sgen_make_uscsi_cmd(sgen_state_t *, struct buf *);
static void sgen_restart(void *);
static void sgen_callback(struct scsi_pkt *);
static int sgen_handle_autosense(sgen_state_t *, struct scsi_pkt *);
static int sgen_handle_sense(sgen_state_t *);
static int sgen_handle_incomplete(sgen_state_t *, struct scsi_pkt *);
static int sgen_check_error(sgen_state_t *, struct buf *);
static int sgen_initiate_sense(sgen_state_t *, int);
static int sgen_scsi_transport(struct scsi_pkt *);
static int sgen_tur(dev_t);

/*
 * Logging/debugging routines
 */
static void sgen_log(sgen_state_t  *, int,  const char *, ...);
static int sgen_diag_ok(sgen_state_t *, int);
static void sgen_dump_cdb(sgen_state_t *, const char *, union scsi_cdb *, int);
static void sgen_dump_sense(sgen_state_t *, size_t, uchar_t *);

int sgen_diag = 0;
int sgen_sporadic_failures = 0;
int sgen_force_manual_sense = 0;
struct sgen_binddb sgen_binddb;

static struct cb_ops sgen_cb_ops = {
	sgen_open,			/* open */
	sgen_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	sgen_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab  */
	D_MP | D_NEW | D_HOTPLUG	/* Driver compatibility flag */
};

static struct dev_ops sgen_dev_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	sgen_getinfo,		/* info */
	nodev,			/* identify */
	sgen_probe,		/* probe */
	sgen_attach,		/* attach */
	sgen_detach,		/* detach */
	nodev,			/* reset */
	&sgen_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static void *sgen_soft_state = NULL;

static struct modldrv modldrv = {
	&mod_driverops, "SCSI generic driver", &sgen_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	int err;

	/* establish driver name from module name */
	sgen_label = (char *)mod_modname(&modlinkage);

	sgen_log(NULL, SGEN_DIAG2, "in sgen_init()");
	if ((err = ddi_soft_state_init(&sgen_soft_state,
	    sizeof (sgen_state_t), SGEN_ESTIMATED_NUM_DEVS)) != 0) {
		goto done;
	}

	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&sgen_soft_state);
		goto done;
	}

done:
	sgen_log(NULL, SGEN_DIAG2, "%s sgen_init()", err ? "failed" : "done");
	return (err);
}

int
_fini(void)
{
	int err;
	sgen_log(NULL, SGEN_DIAG2, "in sgen_fini()");

	if ((err = mod_remove(&modlinkage)) != 0) {
		goto done;
	}

	ddi_soft_state_fini(&sgen_soft_state);
	sgen_cleanup_binddb();

done:
	sgen_log(NULL, SGEN_DIAG2, "%s sgen_fini()", err ? "failed" : "done");
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * sgen_typename()
 *	return a device type's name by looking it up in the sgen_devtypes table.
 */
static char *
sgen_typename(uchar_t typeno)
{
	if (typeno >= SGEN_NDEVTYPES)
		return ("type_unknown");
	return (sgen_devtypes[typeno]);
}

/*
 * sgen_typenum()
 *	return a device type's number by looking it up in the sgen_devtypes
 *	table.
 */
static int
sgen_typenum(const char *typename, uchar_t *typenum)
{
	int i;
	for (i = 0; i < SGEN_NDEVTYPES; i++) {
		if (strcasecmp(sgen_devtypes[i], typename) == 0) {
			*typenum = (uchar_t)i;
			return (0);
		}
	}
	return (-1);
}

/*
 * sgen_setup_binddb()
 *	initialize a data structure which stores all of the information about
 *	which devices and device types the driver should bind to.
 */
static void
sgen_setup_binddb(dev_info_t *dip)
{
	char **strs = NULL, *cp, *pcp, *vcp;
	uint_t nelems, pcplen, vcplen, idx;

	ASSERT(sgen_binddb.sdb_init == 0);
	ASSERT(MUTEX_HELD(&sgen_binddb.sdb_lock));

	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-type-config-list", &strs, &nelems) == DDI_PROP_SUCCESS) {
		/*
		 * for each device type specifier make a copy and put it into a
		 * node in the binddb.
		 */
		for (idx = 0; idx < nelems; idx++) {
			sgen_type_node_t *nodep;
			uchar_t devtype;
			cp = strs[idx];
			if (sgen_typenum(cp, &devtype) != 0) {
				sgen_log(NULL, CE_WARN,
				    "unknown device type '%s', "
				    "device unit-address @%s",
				    cp, ddi_get_name_addr(dip));
				continue;
			}
			nodep = kmem_zalloc(sizeof (sgen_type_node_t),
			    KM_SLEEP);
			nodep->node_type = devtype;
			nodep->node_next = sgen_binddb.sdb_type_nodes;
			sgen_binddb.sdb_type_nodes = nodep;

			sgen_log(NULL, SGEN_DIAG2, "found device type "
			    "'%s' in device-type-config-list, "
			    "device unit-address @%s",
			    cp, ddi_get_name_addr(dip));
		}
		ddi_prop_free(strs);
	}

	/*
	 * for each Vendor/Product inquiry pair, build a node and put it
	 * into the the binddb.
	 */
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "inquiry-config-list", &strs, &nelems) == DDI_PROP_SUCCESS) {

		if (nelems % 2 == 1) {
			sgen_log(NULL, CE_WARN, "inquiry-config-list must "
			    "contain Vendor/Product pairs, "
			    "device unit-address @%s",
			    ddi_get_name_addr(dip));
			nelems--;
		}
		for (idx = 0; idx < nelems; idx += 2) {
			sgen_inq_node_t *nodep;
			/*
			 * Grab vendor and product ID.
			 */
			vcp = strs[idx];
			vcplen = strlen(vcp);
			if (vcplen == 0 || vcplen > SGEN_VENDID_MAX) {
				sgen_log(NULL, CE_WARN,
				    "Invalid vendor ID '%s', "
				    "device unit-address @%s",
				    vcp, ddi_get_name_addr(dip));
				continue;
			}

			pcp = strs[idx + 1];
			pcplen = strlen(pcp);
			if (pcplen == 0 || pcplen > SGEN_PRODID_MAX) {
				sgen_log(NULL, CE_WARN,
				    "Invalid product ID '%s', "
				    "device unit-address @%s",
				    pcp, ddi_get_name_addr(dip));
				continue;
			}

			nodep = kmem_zalloc(sizeof (sgen_inq_node_t),
			    KM_SLEEP);
			nodep->node_vendor = kmem_alloc(vcplen + 1, KM_SLEEP);
			(void) strcpy(nodep->node_vendor, vcp);
			nodep->node_product = kmem_alloc(pcplen + 1, KM_SLEEP);
			(void) strcpy(nodep->node_product, pcp);

			nodep->node_next = sgen_binddb.sdb_inq_nodes;
			sgen_binddb.sdb_inq_nodes = nodep;

			sgen_log(NULL, SGEN_DIAG2, "found inquiry string "
			    "'%s' '%s' in device-type-config-list, "
			    "device unit-address @%s",
			    nodep->node_vendor, nodep->node_product,
			    ddi_get_name_addr(dip));
		}
		ddi_prop_free(strs);
	}

	sgen_binddb.sdb_init = 1;
}

/*
 * sgen_cleanup_binddb()
 *	deallocate data structures for binding database.
 */
static void
sgen_cleanup_binddb()
{
	sgen_inq_node_t *inqp, *inqnextp;
	sgen_type_node_t *typep, *typenextp;

	mutex_enter(&sgen_binddb.sdb_lock);
	if (sgen_binddb.sdb_init == 0) {
		mutex_exit(&sgen_binddb.sdb_lock);
		return;
	}

	for (inqp = sgen_binddb.sdb_inq_nodes; inqp != NULL; inqp = inqnextp) {
		inqnextp = inqp->node_next;
		ASSERT(inqp->node_vendor && inqp->node_product);
		kmem_free(inqp->node_vendor,
		    strlen(inqp->node_vendor) + 1);
		kmem_free(inqp->node_product,
		    strlen(inqp->node_product) + 1);
		kmem_free(inqp, sizeof (sgen_inq_node_t));
	}

	for (typep = sgen_binddb.sdb_type_nodes; typep != NULL;
	    typep = typenextp) {
		typenextp = typep->node_next;
		kmem_free(typep, sizeof (sgen_type_node_t));
	}
	mutex_exit(&sgen_binddb.sdb_lock);
}

/*
 * sgen_bind_byinq()
 *	lookup a device in the binding database by its inquiry data.
 */
static int
sgen_bind_byinq(dev_info_t *dip)
{
	sgen_inq_node_t *nodep;
	char vend_str[SGEN_VENDID_MAX+1];
	char prod_str[SGEN_PRODID_MAX+1];
	struct scsi_device *scsidevp;

	scsidevp = ddi_get_driver_private(dip);

	/*
	 * inq_vid and inq_pid are laid out by the protocol in order in the
	 * inquiry structure, and are not delimited by \0.
	 */
	bcopy(scsidevp->sd_inq->inq_vid, vend_str, SGEN_VENDID_MAX);
	vend_str[SGEN_VENDID_MAX] = '\0';
	bcopy(scsidevp->sd_inq->inq_pid, prod_str, SGEN_PRODID_MAX);
	prod_str[SGEN_PRODID_MAX] = '\0';

	for (nodep = sgen_binddb.sdb_inq_nodes; nodep != NULL;
	    nodep = nodep->node_next) {
		/*
		 * Allow the "*" wildcard to match all vendor IDs.
		 */
		if (strcmp(nodep->node_vendor, "*") != 0) {
			if (strncasecmp(nodep->node_vendor, vend_str,
			    strlen(nodep->node_vendor)) != 0) {
				continue;
			}
		}

		/*
		 * Using strncasecmp() with the key length allows substring
		 * matching for product data.
		 */
		if (strncasecmp(nodep->node_product, prod_str,
		    strlen(nodep->node_product)) == 0) {
			return (0);
		}
	}
	return (-1);
}

/*
 * sgen_bind_bytype()
 *	lookup a device type in the binding database; if found, return a
 *	format string corresponding to the string in the .conf file.
 */
static int
sgen_bind_bytype(dev_info_t *dip)
{
	sgen_type_node_t *nodep;
	struct scsi_device *scsidevp;

	scsidevp = ddi_get_driver_private(dip);

	for (nodep = sgen_binddb.sdb_type_nodes; nodep != NULL;
	    nodep = nodep->node_next) {
		if (nodep->node_type == scsidevp->sd_inq->inq_dtype) {
			return (0);
		}
	}
	return (-1);
}

/*
 * sgen_get_binding()
 *	Check to see if the device in question matches the criteria for
 *	sgen to bind.
 *
 *	Either the .conf file must specify a device_type entry which
 *	matches the SCSI device type of this device, or the inquiry
 *	string provided by the device must match an inquiry string specified
 *	in the .conf file.  Inquiry data is matched first.
 */
static int
sgen_get_binding(dev_info_t *dip)
{
	int retval = 0;

	mutex_enter(&sgen_binddb.sdb_lock);
	if (sgen_binddb.sdb_init == 0)
		sgen_setup_binddb(dip);
	mutex_exit(&sgen_binddb.sdb_lock);


	/*
	 * Check device-type-config-list for a match by device type.
	 */
	if (sgen_bind_bytype(dip) == 0)
		goto done;

	/*
	 * Check inquiry-config-list for a match by Vendor/Product ID.
	 */
	if (sgen_bind_byinq(dip) == 0)
		goto done;

	retval = -1;
done:
	return (retval);
}

/*
 * sgen_attach()
 *	attach(9e) entrypoint.
 */
static int
sgen_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int err;

	sgen_log(NULL, SGEN_DIAG2, "in sgen_attach(), device unit-address @%s",
	    ddi_get_name_addr(dip));

	switch (cmd) {
	case DDI_ATTACH:
		err = sgen_do_attach(dip);
		break;
	case DDI_RESUME:
		err = DDI_SUCCESS;
		break;
	case DDI_PM_RESUME:
	default:
		err = DDI_FAILURE;
		break;
	}

done:
	sgen_log(NULL, SGEN_DIAG2, "%s sgen_attach(), device unit-address @%s",
	    err == DDI_SUCCESS ? "done" : "failed", ddi_get_name_addr(dip));
	return (err);
}

/*
 * sgen_do_attach()
 *	handle the nitty details of attach.
 */
static int
sgen_do_attach(dev_info_t *dip)
{
	int instance;
	struct scsi_device *scsidevp;
	sgen_state_t *sg_state;
	uchar_t devtype;
	struct scsi_inquiry *inq;

	instance = ddi_get_instance(dip);

	scsidevp = ddi_get_driver_private(dip);
	ASSERT(scsidevp);

	sgen_log(NULL, SGEN_DIAG2, "sgen_do_attach: instance = %d, "
	    "device unit-address @%s", instance, ddi_get_name_addr(dip));

	/*
	 * Probe the device in order to get its device type to name the minor
	 * node.
	 */
	if (scsi_probe(scsidevp, NULL_FUNC) != SCSIPROBE_EXISTS) {
		scsi_unprobe(scsidevp);
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(sgen_soft_state, instance) != DDI_SUCCESS) {
		sgen_log(NULL, SGEN_DIAG1,
		    "sgen_do_attach: failed to allocate softstate, "
		    "device unit-address @%s", ddi_get_name_addr(dip));
		scsi_unprobe(scsidevp);
		return (DDI_FAILURE);
	}

	inq = scsidevp->sd_inq;		/* valid while device is probed... */
	devtype = inq->inq_dtype;

	sg_state = ddi_get_soft_state(sgen_soft_state, instance);
	sg_state->sgen_scsidev = scsidevp;
	scsidevp->sd_dev = dip;

	/*
	 * Now that sg_state->sgen_scsidev is initialized, it's ok to
	 * call sgen_log with sg_state instead of NULL.
	 */

	/*
	 * If the user specified the sgen_diag property, override the global
	 * sgen_diag setting by setting sg_state's sgen_diag value.  If the
	 * user gave a value out of range, default to '0'.
	 */
	sg_state->sgen_diag = ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "sgen-diag", -1);

	if (sg_state->sgen_diag != -1) {
		if (sg_state->sgen_diag < 0 || sg_state->sgen_diag > 3)
			sg_state->sgen_diag = 0;
	}

	sgen_log(sg_state, SGEN_DIAG2,
	    "sgen_do_attach: sgen_soft_state=0x%p, instance=%d, "
	    "device unit-address @%s",
	    sgen_soft_state, instance, ddi_get_name_addr(dip));

	/*
	 * For simplicity, the minor number == the instance number
	 */
	if (ddi_create_minor_node(dip, sgen_typename(devtype), S_IFCHR,
	    instance, DDI_NT_SGEN, 0) == DDI_FAILURE) {
		scsi_unprobe(scsidevp);
		ddi_prop_remove_all(dip);
		sgen_log(sg_state, SGEN_DIAG1,
		    "sgen_do_attach: minor node creation failed, "
		    "device unit-address @%s", ddi_get_name_addr(dip));
		ddi_soft_state_free(sgen_soft_state, instance);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate the command buffer, then create a condition variable for
	 * managing it; mark the command buffer as free.
	 */
	sg_state->sgen_cmdbuf = getrbuf(KM_SLEEP);
	cv_init(&sg_state->sgen_cmdbuf_cv, NULL, CV_DRIVER, NULL);

	SGEN_CLR_BUSY(sg_state);
	SGEN_CLR_OPEN(sg_state);
	SGEN_CLR_SUSP(sg_state);

	/*
	 * If the hba and the target both support wide xfers, enable them.
	 */
	if (scsi_ifgetcap(&sg_state->sgen_scsiaddr, "wide-xfer", 1) != -1) {
		int wide = 0;
		if ((inq->inq_rdf == RDF_SCSI2) &&
		    (inq->inq_wbus16 || inq->inq_wbus32))
			wide = 1;
		if (scsi_ifsetcap(&sg_state->sgen_scsiaddr, "wide-xfer",
		    wide, 1) == 1) {
			sgen_log(sg_state, SGEN_DIAG1,
			    "sgen_attach: wide xfer %s, "
			    "device unit-address @%s",
			    wide ? "enabled" : "disabled",
			    ddi_get_name_addr(dip));
		}
	}

	/*
	 * This is a little debugging code-- since the codepath for auto-sense
	 * and 'manual' sense is split, toggling this variable will make
	 * sgen act as though the adapter in question can't do auto-sense.
	 */
	if (sgen_force_manual_sense) {
		if (scsi_ifsetcap(&sg_state->sgen_scsiaddr, "auto-rqsense",
		    0, 1) == 1) {
			sg_state->sgen_arq_enabled = 0;
		} else {
			sg_state->sgen_arq_enabled = 1;
		}
	} else {
		/*
		 * Enable autorequest sense, if supported
		 */
		if (scsi_ifgetcap(&sg_state->sgen_scsiaddr,
		    "auto-rqsense", 1) != 1) {
			if (scsi_ifsetcap(&sg_state->sgen_scsiaddr,
			    "auto-rqsense", 1, 1) == 1) {
				sg_state->sgen_arq_enabled = 1;
				sgen_log(sg_state, SGEN_DIAG1,
				    "sgen_attach: auto-request-sense enabled, "
				    "device unit-address @%s",
				    ddi_get_name_addr(dip));
			} else {
				sg_state->sgen_arq_enabled = 0;
				sgen_log(sg_state, SGEN_DIAG1,
				    "sgen_attach: auto-request-sense disabled, "
				    "device unit-address @%s",
				    ddi_get_name_addr(dip));
			}
		} else {
			sg_state->sgen_arq_enabled = 1;	/* already enabled */
			sgen_log(sg_state, SGEN_DIAG1,
			    "sgen_attach: auto-request-sense enabled, "
			    "device unit-address @%s", ddi_get_name_addr(dip));
		}
	}

	/*
	 * Allocate plumbing for manually fetching sense.
	 */
	if (sgen_setup_sense(sg_state) != 0) {
		freerbuf(sg_state->sgen_cmdbuf);
		ddi_prop_remove_all(dip);
		ddi_remove_minor_node(dip, NULL);
		scsi_unprobe(scsidevp);
		sgen_log(sg_state, SGEN_DIAG1,
		    "sgen_do_attach: failed to setup request-sense, "
		    "device unit-address @%s", ddi_get_name_addr(dip));
		ddi_soft_state_free(sgen_soft_state, instance);
		return (DDI_FAILURE);
	}

	sgen_create_errstats(sg_state, instance);

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

/*
 * sgen_setup_sense()
 *	Allocate a request sense packet so that if sgen needs to fetch sense
 *	data for the user, it will have a pkt ready to send.
 */
static int
sgen_setup_sense(sgen_state_t *sg_state)
{
	struct buf *bp;
	struct scsi_pkt *rqpkt;

	if ((bp = scsi_alloc_consistent_buf(&sg_state->sgen_scsiaddr, NULL,
	    MAX_SENSE_LENGTH, B_READ, SLEEP_FUNC, NULL)) == NULL) {
		return (-1);
	}

	if ((rqpkt = scsi_init_pkt(&sg_state->sgen_scsiaddr, NULL, bp,
	    CDB_GROUP0, 1, 0, PKT_CONSISTENT, SLEEP_FUNC, NULL)) == NULL) {
		scsi_free_consistent_buf(bp);
		return (-1);
	}

	/*
	 * Make the results of running a SENSE available by filling out the
	 * sd_sense field of the scsi device (sgen_sense is just an alias).
	 */
	sg_state->sgen_sense = (struct scsi_extended_sense *)bp->b_un.b_addr;

	(void) scsi_setup_cdb((union scsi_cdb *)rqpkt->pkt_cdbp,
	    SCMD_REQUEST_SENSE, 0, MAX_SENSE_LENGTH, 0);
	FILL_SCSI1_LUN(sg_state->sgen_scsidev, rqpkt);

	rqpkt->pkt_comp = sgen_callback;
	rqpkt->pkt_time = SGEN_IO_TIME;
	rqpkt->pkt_flags |= FLAG_SENSING;
	rqpkt->pkt_private = sg_state;

	sg_state->sgen_rqspkt = rqpkt;
	sg_state->sgen_rqsbuf = bp;

	return (0);
}

/*
 * sgen_create_errstats()
 *	create named kstats for tracking occurrence of errors.
 */
static void
sgen_create_errstats(sgen_state_t *sg_state, int instance)
{
	char kstatname[KSTAT_STRLEN];
	struct sgen_errstats *stp;

	(void) snprintf(kstatname, KSTAT_STRLEN, "%s%d,err",
	    sgen_label, instance);
	sg_state->sgen_kstats = kstat_create("sgenerr", instance,
	    kstatname, "device_error", KSTAT_TYPE_NAMED,
	    sizeof (struct sgen_errstats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT);

	if (sg_state->sgen_kstats == NULL)
		return;

	stp = (struct sgen_errstats *)sg_state->sgen_kstats->ks_data;
	kstat_named_init(&stp->sgen_trans_err, "transport_errors",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sgen_restart, "command_restarts",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sgen_incmp_err, "incomplete_commands",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sgen_autosen_rcv, "autosense_occurred",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sgen_autosen_bad, "autosense_undecipherable",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sgen_sense_rcv, "sense_fetches",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sgen_sense_bad, "sense_data_undecipherable",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sgen_recov_err, "recoverable_error",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sgen_nosen_err, "NO_SENSE_sense_key",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->sgen_unrecov_err, "unrecoverable_sense_error",
	    KSTAT_DATA_UINT32);
	sg_state->sgen_kstats->ks_private = sg_state;
	sg_state->sgen_kstats->ks_update = nulldev;
	kstat_install(sg_state->sgen_kstats);
}

/*
 * sgen_detach()
 *	detach(9E) entrypoint
 */
static int
sgen_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	sgen_state_t *sg_state;

	instance = ddi_get_instance(dip);
	sg_state = ddi_get_soft_state(sgen_soft_state, instance);

	sgen_log(sg_state, SGEN_DIAG2, "in sgen_detach(), "
	    "device unit-address @%s", ddi_get_name_addr(dip));

	if (sg_state == NULL) {
		sgen_log(NULL, SGEN_DIAG1,
		    "sgen_detach: failed, no softstate found (%d), "
		    "device unit-address @%s",
		    instance, ddi_get_name_addr(dip));
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		return (sgen_do_detach(dip));
	case DDI_SUSPEND:
		return (sgen_do_suspend(dip));
	case DDI_PM_SUSPEND:
	default:
		return (DDI_FAILURE);
	}
}

/*
 * sgen_do_detach()
 *	detach the driver, tearing down resources.
 */
static int
sgen_do_detach(dev_info_t *dip)
{
	int instance;
	sgen_state_t *sg_state;
	struct scsi_device *devp;

	instance = ddi_get_instance(dip);
	sg_state = ddi_get_soft_state(sgen_soft_state, instance);
	ASSERT(sg_state);

	sgen_log(sg_state, SGEN_DIAG2, "in sgen_do_detach(), "
	    "device unit-address @%s", ddi_get_name_addr(dip));
	devp = ddi_get_driver_private(dip);

	mutex_enter(&sg_state->sgen_mutex);
	if (SGEN_IS_BUSY(sg_state)) {
		mutex_exit(&sg_state->sgen_mutex);
		sgen_log(sg_state, SGEN_DIAG1, "sgen_do_detach: failed because "
		    "device is busy, device unit-address @%s",
		    ddi_get_name_addr(dip));
		return (DDI_FAILURE);
	}
	mutex_exit(&sg_state->sgen_mutex);

	/*
	 * Final approach for detach.  Free data allocated by scsi_probe()
	 * in attach.
	 */
	if (sg_state->sgen_restart_timeid)
		(void) untimeout(sg_state->sgen_restart_timeid);
	sg_state->sgen_restart_timeid = 0;
	scsi_unprobe(devp);

	/*
	 * Free auto-request plumbing.
	 */
	scsi_free_consistent_buf(sg_state->sgen_rqsbuf);
	scsi_destroy_pkt(sg_state->sgen_rqspkt);

	if (sg_state->sgen_kstats) {
		kstat_delete(sg_state->sgen_kstats);
		sg_state->sgen_kstats = NULL;
	}

	/*
	 * Free command buffer and clean up
	 */
	freerbuf(sg_state->sgen_cmdbuf);
	cv_destroy(&sg_state->sgen_cmdbuf_cv);

	sgen_log(sg_state, SGEN_DIAG2, "done sgen_do_detach(), "
	    "device unit-address @%s", ddi_get_name_addr(dip));

	ddi_soft_state_free(sgen_soft_state, instance);
	ddi_prop_remove_all(dip);
	ddi_remove_minor_node(dip, NULL);
	return (DDI_SUCCESS);
}

/*
 * sgen_do_suspend()
 *	suspend the driver.  This sets the "suspend" bit for this target if it
 *	is currently open; once resumed, the suspend bit will cause
 *	subsequent I/Os to fail.  We want user programs to close and
 *	reopen the device to acknowledge that they need to reexamine its
 *	state and do the right thing.
 */
static int
sgen_do_suspend(dev_info_t *dip)
{
	int instance;
	sgen_state_t *sg_state;

	instance = ddi_get_instance(dip);
	sg_state = ddi_get_soft_state(sgen_soft_state, instance);
	ASSERT(sg_state);

	sgen_log(sg_state, SGEN_DIAG2, "in sgen_do_suspend(), "
	    "device unit-address @%s", ddi_get_name_addr(dip));

	if (sg_state->sgen_restart_timeid) {
		(void) untimeout(sg_state->sgen_restart_timeid);
	}
	sg_state->sgen_restart_timeid = 0;

	mutex_enter(&sg_state->sgen_mutex);
	if (SGEN_IS_OPEN(sg_state))
		SGEN_SET_SUSP(sg_state);
	mutex_exit(&sg_state->sgen_mutex);

	sgen_log(sg_state, SGEN_DIAG2, "done sgen_do_suspend(), "
	    "device unit-address @%s", ddi_get_name_addr(dip));
	return (DDI_SUCCESS);
}

/*
 * sgen_getinfo()
 *	getinfo(9e) entrypoint.
 */
/*ARGSUSED*/
static int
sgen_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t dev;
	sgen_state_t *sg_state;
	int instance, error;
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		instance = getminor(dev);
		if ((sg_state = ddi_get_soft_state(sgen_soft_state, instance))
		    == NULL)
			return (DDI_FAILURE);
		*result = (void *) sg_state->sgen_scsidev->sd_dev;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = getminor(dev);
		*result = (void *)(uintptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*
 * sgen_probe()
 *	probe(9e) entrypoint.  sgen *never* returns DDI_PROBE_PARTIAL, in
 *	order to avoid leaving around extra devinfos.  If sgen's binding
 *	rules indicate that it should bind, it returns DDI_PROBE_SUCCESS.
 */
static int
sgen_probe(dev_info_t *dip)
{
	struct scsi_device *scsidevp;
	int instance;
	int rval;

	scsidevp = ddi_get_driver_private(dip);
	instance = ddi_get_instance(dip);
	sgen_log(NULL, SGEN_DIAG2, "in sgen_probe(): instance = %d, "
	    "device unit-address @%s", instance, ddi_get_name_addr(dip));

	if (ddi_dev_is_sid(dip) == DDI_SUCCESS)
		return (DDI_PROBE_DONTCARE);

	if (ddi_get_soft_state(sgen_soft_state, instance) != NULL)
		return (DDI_PROBE_FAILURE);

	mutex_enter(&sgen_binddb.sdb_lock);
	if (sgen_binddb.sdb_init == 0) {
		sgen_setup_binddb(dip);
	}
	mutex_exit(&sgen_binddb.sdb_lock);

	/*
	 * A small optimization: if it's impossible for sgen to bind to
	 * any devices, don't bother probing, just fail.
	 */
	if ((sgen_binddb.sdb_inq_nodes == NULL) &&
	    (sgen_binddb.sdb_type_nodes == NULL)) {
		return (DDI_PROBE_FAILURE);
	}

	if (scsi_probe(scsidevp, NULL_FUNC) == SCSIPROBE_EXISTS) {
		if (sgen_get_binding(dip) == 0) {
			rval = DDI_PROBE_SUCCESS;
		}
	} else {
		rval = DDI_PROBE_FAILURE;
	}
	scsi_unprobe(scsidevp);

	sgen_log(NULL, SGEN_DIAG2, "sgen_probe() %s, device unit-address @%s",
	    rval == DDI_PROBE_SUCCESS ? "succeeded" : "failed",
	    ddi_get_name_addr(dip));
	return (rval);
}

/*
 * sgen_open()
 *	open(9e) entrypoint.  sgen enforces a strict exclusive open policy per
 *	target.
 */
/*ARGSUSED1*/
static int
sgen_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	dev_t dev = *dev_p;
	sgen_state_t *sg_state;
	int instance;

	instance = getminor(dev);

	if ((sg_state = ddi_get_soft_state(sgen_soft_state, instance)) == NULL)
		return (ENXIO);

	sgen_log(sg_state, SGEN_DIAG2, "in sgen_open(): instance = %d",
	    instance);

	mutex_enter(&sg_state->sgen_mutex);

	/*
	 * Don't allow new opens of a suspended device until the last close has
	 * happened.  This is rather simplistic, but keeps the implementation
	 * straightforward.
	 */
	if (SGEN_IS_SUSP(sg_state)) {
		mutex_exit(&sg_state->sgen_mutex);
		return (EIO);
	}

	/*
	 * Enforce exclusive access.
	 */
	if (SGEN_IS_EXCL(sg_state) ||
	    (SGEN_IS_OPEN(sg_state) && (flag & FEXCL))) {
		mutex_exit(&sg_state->sgen_mutex);
		return (EBUSY);
	}

	if (flag & FEXCL)
		SGEN_SET_EXCL(sg_state);

	SGEN_SET_OPEN(sg_state);

	mutex_exit(&sg_state->sgen_mutex);

	return (0);
}

/*
 * sgen_close()
 *	close(9e) entrypoint.
 */
/*ARGSUSED1*/
static int
sgen_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	sgen_state_t *sg_state;
	int instance;

	instance = getminor(dev);

	if ((sg_state = ddi_get_soft_state(sgen_soft_state, instance)) == NULL)
		return (ENXIO);

	sgen_log(sg_state, SGEN_DIAG2, "in sgen_close(): instance = %d",
	    instance);

	mutex_enter(&sg_state->sgen_mutex);
	SGEN_CLR_OPEN(sg_state);
	SGEN_CLR_EXCL(sg_state);
	SGEN_CLR_SUSP(sg_state); /* closing clears the 'I was suspended' bit */
	mutex_exit(&sg_state->sgen_mutex);

	sgen_log(sg_state, SGEN_DIAG2, "done sgen_close()");

	return (0);
}

/*
 * sgen_ioctl()
 *	sgen supports the USCSI(7I) ioctl interface.
 */
/*ARGSUSED4*/
static int
sgen_ioctl(dev_t dev,
    int cmd, intptr_t arg, int flag, cred_t *cred_p, int *rval_p)
{
	int retval = 0;
	sgen_state_t *sg_state;
	int instance;

	instance = getminor(dev);

	if ((sg_state = ddi_get_soft_state(sgen_soft_state, instance)) == NULL)
		return (ENXIO);

	sgen_log(sg_state, SGEN_DIAG2, "in sgen_ioctl(): instance = %d",
	    instance);

	/*
	 * If the driver has been suspended since the last open, fail all
	 * subsequent IO's so that the userland consumer reinitializes state.
	 */
	mutex_enter(&sg_state->sgen_mutex);
	if (SGEN_IS_SUSP(sg_state)) {
		mutex_exit(&sg_state->sgen_mutex);
		sgen_log(sg_state, SGEN_DIAG1, "sgen_ioctl: returning EIO: "
		    "driver instance %d was previously suspended", instance);
		return (EIO);
	}
	mutex_exit(&sg_state->sgen_mutex);

	switch (cmd) {
	case SGEN_IOC_DIAG: {
		if (arg > 3) {
			arg = 0;
		}
		sg_state->sgen_diag = (int)arg;
		retval = 0;
		break;
	}

	case SGEN_IOC_READY: {
		if (sgen_tur(dev) != 0) {
			retval = EIO;
		} else {
			retval = 0;
		}
		break;
	}

	case USCSICMD:
		retval = sgen_uscsi_cmd(dev, (struct uscsi_cmd *)arg, flag);
		break;

	default:
		retval = ENOTTY;
	}

	sgen_log(sg_state, SGEN_DIAG2, "done sgen_ioctl(), returning %d",
	    retval);

	return (retval);
}

/*
 * sgen_uscsi_cmd()
 *	Setup, configuration and teardown for a uscsi(7I) command
 */
/*ARGSUSED*/
static int
sgen_uscsi_cmd(dev_t dev, struct uscsi_cmd *ucmd, int flag)
{
	struct uscsi_cmd	*uscmd;
	struct buf	*bp;
	sgen_state_t	*sg_state;
	enum uio_seg	uioseg;
	int	instance;
	int	flags;
	int	err;

	instance = getminor(dev);

	sg_state = ddi_get_soft_state(sgen_soft_state, instance);
	ASSERT(sg_state);

	sgen_log(sg_state, SGEN_DIAG2, "in sgen_uscsi_cmd(): instance = %d",
	    instance);

	/*
	 * At this point, we start affecting state relevant to the target,
	 * so access needs to be serialized.
	 */
	if (sgen_hold_cmdbuf(sg_state) != 0) {
		sgen_log(sg_state, SGEN_DIAG1, "sgen_uscsi_cmd: interrupted");
		return (EINTR);
	}

	err = scsi_uscsi_alloc_and_copyin((intptr_t)ucmd, flag,
	    &sg_state->sgen_scsiaddr, &uscmd);
	if (err != 0) {
		sgen_rele_cmdbuf(sg_state);
		sgen_log(sg_state, SGEN_DIAG1, "sgen_uscsi_cmd: "
		    "scsi_uscsi_alloc_and_copyin failed\n");
		return (err);
	}

	/*
	 * Clear out undesirable command flags
	 */
	flags = (uscmd->uscsi_flags & ~(USCSI_NOINTR | USCSI_NOPARITY |
	    USCSI_OTAG | USCSI_HTAG | USCSI_HEAD));
	if (flags != uscmd->uscsi_flags) {
		sgen_log(sg_state, SGEN_DIAG1, "sgen_uscsi_cmd: cleared "
		    "unsafe uscsi_flags 0x%x", uscmd->uscsi_flags & ~flags);
		uscmd->uscsi_flags = flags;
	}

	if (uscmd->uscsi_cdb != NULL) {
		sgen_dump_cdb(sg_state, "sgen_uscsi_cmd: ",
		    (union scsi_cdb *)uscmd->uscsi_cdb, uscmd->uscsi_cdblen);
	}

	/*
	 * Stash the sense buffer into sgen_rqs_sen for convenience.
	 */
	sg_state->sgen_rqs_sen = uscmd->uscsi_rqbuf;

	bp = sg_state->sgen_cmdbuf;
	bp->av_back = NULL;
	bp->av_forw = NULL;
	bp->b_private = (struct buf *)uscmd;
	uioseg = (flag & FKIOCTL) ? UIO_SYSSPACE : UIO_USERSPACE;

	err = scsi_uscsi_handle_cmd(dev, uioseg, uscmd, sgen_start, bp, NULL);

	if (sg_state->sgen_cmdpkt != NULL) {
		uscmd->uscsi_status = SCBP_C(sg_state->sgen_cmdpkt);
	} else {
		uscmd->uscsi_status = 0;
	}

	sgen_log(sg_state, SGEN_DIAG3, "sgen_uscsi_cmd: awake from waiting "
	    "for command.  Status is 0x%x", uscmd->uscsi_status);

	if (uscmd->uscsi_rqbuf != NULL) {
		int rqlen = uscmd->uscsi_rqlen - uscmd->uscsi_rqresid;
		sgen_dump_sense(sg_state, rqlen,
		    (uchar_t *)uscmd->uscsi_rqbuf);
	}

	(void) scsi_uscsi_copyout_and_free((intptr_t)ucmd, uscmd);

	if (sg_state->sgen_cmdpkt != NULL) {
		scsi_destroy_pkt(sg_state->sgen_cmdpkt);
		sg_state->sgen_cmdpkt = NULL;
	}

	/*
	 * After this point, we can't touch per-target state.
	 */
	sgen_rele_cmdbuf(sg_state);

	sgen_log(sg_state, SGEN_DIAG2, "done sgen_uscsi_cmd()");

	return (err);
}

/*
 * sgen_hold_cmdbuf()
 *	Acquire a lock on the command buffer for the given target.  Returns
 *	non-zero if interrupted.
 */
static int
sgen_hold_cmdbuf(sgen_state_t *sg_state)
{
	mutex_enter(&sg_state->sgen_mutex);
	while (SGEN_IS_BUSY(sg_state)) {
		if (!cv_wait_sig(&sg_state->sgen_cmdbuf_cv,
		    &sg_state->sgen_mutex)) {
			mutex_exit(&sg_state->sgen_mutex);
			return (-1);
		}
	}
	SGEN_SET_BUSY(sg_state);
	mutex_exit(&sg_state->sgen_mutex);
	return (0);
}

/*
 * sgen_rele_cmdbuf()
 *	release the command buffer for a particular target.
 */
static void
sgen_rele_cmdbuf(sgen_state_t *sg_state)
{
	mutex_enter(&sg_state->sgen_mutex);
	SGEN_CLR_BUSY(sg_state);
	cv_signal(&sg_state->sgen_cmdbuf_cv);
	mutex_exit(&sg_state->sgen_mutex);
}

/*
 * sgen_start()
 *	Transport a uscsi command; this is invoked by physio() or directly
 *	by sgen_uscsi_cmd().
 */
static int
sgen_start(struct buf *bp)
{
	sgen_state_t *sg_state;
	dev_t dev = bp->b_edev;
	int trans_err;

	if ((sg_state = ddi_get_soft_state(sgen_soft_state,
	    getminor(dev))) == NULL) {
		bp->b_resid = bp->b_bcount;
		bioerror(bp, ENXIO);
		biodone(bp);
		return (ENXIO);
	}

	/*
	 * Sanity checks - command should not be complete, no packet should
	 * be allocated, and there ought to be a uscsi cmd in b_private
	 */
	ASSERT(bp == sg_state->sgen_cmdbuf && sg_state->sgen_cmdpkt == NULL);
	ASSERT((bp->b_flags & B_DONE) == 0);
	ASSERT(bp->b_private);
	if (sgen_make_uscsi_cmd(sg_state, bp) != 0) {
		bp->b_resid = bp->b_bcount;
		bioerror(bp, EFAULT);
		biodone(bp);
		return (EFAULT);
	}

	ASSERT(sg_state->sgen_cmdpkt != NULL);

	/*
	 * Clear out the residual and error fields
	 */
	bp->b_resid = 0;
	bp->b_error = 0;

	trans_err = sgen_scsi_transport(sg_state->sgen_cmdpkt);
	switch (trans_err) {
	case TRAN_ACCEPT:
		break;
	case TRAN_BUSY:
		sgen_log(sg_state, SGEN_DIAG2,
		    "sgen_start: scsi_transport() returned TRAN_BUSY");
		sg_state->sgen_restart_timeid = timeout(sgen_restart, sg_state,
		    SGEN_BSY_TIMEOUT);
		break;
	default:
		/*
		 * Indicate there has been an I/O transfer error.
		 * Be done with the command.
		 */
		mutex_enter(&sg_state->sgen_mutex);
		SGEN_DO_ERRSTATS(sg_state, sgen_trans_err);
		mutex_exit(&sg_state->sgen_mutex);
		sgen_log(sg_state, SGEN_DIAG2, "sgen_start: scsi_transport() "
		    "returned %d", trans_err);
		bioerror(bp, EIO);
		biodone(bp);
		return (EIO);
	}
	sgen_log(sg_state, SGEN_DIAG2, "sgen_start: b_flags 0x%x", bp->b_flags);
	return (0);
}

/*
 * sgen_scsi_transport()
 *	a simple scsi_transport() wrapper which can be configured to inject
 *	sporadic errors for testing.
 */
static int
sgen_scsi_transport(struct scsi_pkt *pkt)
{
	int trans_err;
	static int cnt = 0;
	sgen_state_t *sg_state = pkt->pkt_private;

	if (sgen_sporadic_failures == 0) {
		return (scsi_transport(pkt));
	}

	cnt = (cnt * 2416 + 374441) % 1771875;	/* borrowed from kmem.c */
	if (cnt % 40 == 1) {
		sgen_log(sg_state, SGEN_DIAG1, "sgen_scsi_transport: "
		    "injecting sporadic BUSY");
		trans_err = TRAN_BUSY;
	} else if (cnt % 40 == 2) {
		sgen_log(sg_state, SGEN_DIAG1, "sgen_scsi_transport: "
		    "injecting sporadic BADPKT");
		trans_err = TRAN_BADPKT;
	} else {
		/*
		 * Most of the time we take the normal path
		 */
		trans_err = scsi_transport(pkt);
	}
	return (trans_err);
}

/*
 * sgen_make_uscsi_cmd()
 *	Initialize a SCSI packet usable for USCSI.
 */
static int
sgen_make_uscsi_cmd(sgen_state_t *sg_state, struct buf *bp)
{
	struct scsi_pkt	*pkt;
	struct uscsi_cmd *ucmd;
	int stat_size = 1;
	int flags = 0;

	ASSERT(bp);

	sgen_log(sg_state, SGEN_DIAG2, "in sgen_make_uscsi_cmd()");

	ucmd = (struct uscsi_cmd *)bp->b_private;

	if (ucmd->uscsi_flags & USCSI_RQENABLE) {
		if (ucmd->uscsi_rqlen > SENSE_LENGTH) {
			stat_size = (int)(ucmd->uscsi_rqlen) +
			    sizeof (struct scsi_arq_status) -
			    sizeof (struct scsi_extended_sense);
			flags = PKT_XARQ;
		} else {
			stat_size = sizeof (struct scsi_arq_status);
		}
	}

	sgen_log(sg_state, SGEN_DIAG3, "sgen_make_uscsi_cmd: b_bcount = %ld",
	    bp->b_bcount);
	pkt = scsi_init_pkt(&sg_state->sgen_scsiaddr,
	    NULL,			/* in_pkt - null so it'll be alloc'd */
	    bp->b_bcount ? bp : NULL,	/* buf structure for data xfer */
	    ucmd->uscsi_cdblen,		/* cmdlen */
	    stat_size,			/* statuslen */
	    0,				/* privatelen */
	    flags,			/* flags */
	    SLEEP_FUNC,			/* callback */
	    (caddr_t)sg_state);		/* callback_arg */

	if (pkt == NULL) {
		sgen_log(sg_state, SGEN_DIAG2, "failed sgen_make_uscsi_cmd()");
		return (-1);
	}

	pkt->pkt_comp = sgen_callback;
	pkt->pkt_private = sg_state;
	sg_state->sgen_cmdpkt = pkt;

	/*
	 * We *don't* call scsi_setup_cdb here, as is customary, since the
	 * user could specify a command from one group, but pass cdblen
	 * as something totally different.  If cdblen is smaller than expected,
	 * this results in scsi_setup_cdb writing past the end of the cdb.
	 */
	bcopy(ucmd->uscsi_cdb, pkt->pkt_cdbp, ucmd->uscsi_cdblen);
	if (ucmd->uscsi_cdblen >= CDB_GROUP0) {
		FILL_SCSI1_LUN(sg_state->sgen_scsidev, pkt);
	}

	if (ucmd->uscsi_timeout > 0)
		pkt->pkt_time = ucmd->uscsi_timeout;
	else
		pkt->pkt_time = SGEN_IO_TIME;

	/*
	 * Set packet options
	 */
	if (ucmd->uscsi_flags & USCSI_SILENT)
		pkt->pkt_flags |= FLAG_SILENT;
	if (ucmd->uscsi_flags & USCSI_ISOLATE)
		pkt->pkt_flags |= FLAG_ISOLATE;
	if (ucmd->uscsi_flags & USCSI_DIAGNOSE)
		pkt->pkt_flags |= FLAG_DIAGNOSE;
	if (ucmd->uscsi_flags & USCSI_RENEGOT) {
		pkt->pkt_flags |= FLAG_RENEGOTIATE_WIDE_SYNC;
	}

	/* Transfer uscsi information to scsi_pkt */
	(void) scsi_uscsi_pktinit(ucmd, pkt);

	sgen_log(sg_state, SGEN_DIAG2, "done sgen_make_uscsi_cmd()");
	return (0);
}


/*
 * sgen_restart()
 *	sgen_restart() is called after a timeout, when a command has been
 *	postponed due to a TRAN_BUSY response from the HBA.
 */
static void
sgen_restart(void *arg)
{
	sgen_state_t *sg_state = (sgen_state_t *)arg;
	struct scsi_pkt *pkt;
	struct buf *bp;

	sgen_log(sg_state, SGEN_DIAG2, "in sgen_restart()");

	bp = sg_state->sgen_cmdbuf;
	pkt = sg_state->sgen_cmdpkt;
	ASSERT(bp && pkt);

	SGEN_DO_ERRSTATS(sg_state, sgen_restart);

	/*
	 * If the packet is marked with the sensing flag, sgen is off running
	 * a request sense, and *that packet* is what needs to be restarted.
	 */
	if (pkt->pkt_flags & FLAG_SENSING) {
		sgen_log(sg_state, SGEN_DIAG3,
		    "sgen_restart: restarting REQUEST SENSE");
		pkt = sg_state->sgen_rqspkt;
	}

	if (sgen_scsi_transport(pkt) != TRAN_ACCEPT) {
		bp->b_resid = bp->b_bcount;
		bioerror(bp, EIO);
		biodone(bp);
	}
}

/*
 * sgen_callback()
 *	Command completion processing
 *
 *	sgen's completion processing is very pessimistic-- it does not retry
 *	failed commands; instead, it allows the user application to make
 *	decisions about what has gone wrong.
 */
static void
sgen_callback(struct scsi_pkt *pkt)
{
	sgen_state_t *sg_state;
	struct uscsi_cmd *ucmd;
	struct buf *bp;
	int action;

	sg_state = pkt->pkt_private;
	/*
	 * bp should always be the command buffer regardless of whether
	 * this is a command completion or a request-sense completion.
	 * This is because there is no need to biodone() the sense buf
	 * when it completes-- we want to biodone() the actual command buffer!
	 */
	bp = sg_state->sgen_cmdbuf;
	if (pkt->pkt_flags & FLAG_SENSING) {
		ASSERT(pkt == sg_state->sgen_rqspkt);
		sgen_log(sg_state, SGEN_DIAG2,
		    "in sgen_callback() (SENSE completion callback)");
	} else {
		ASSERT(pkt == sg_state->sgen_cmdpkt);
		sgen_log(sg_state, SGEN_DIAG2,
		    "in sgen_callback() (command completion callback)");
	}
	ucmd = (struct uscsi_cmd *)bp->b_private;

	sgen_log(sg_state, SGEN_DIAG3, "sgen_callback: reason=0x%x resid=%ld "
	    "state=0x%x", pkt->pkt_reason, pkt->pkt_resid, pkt->pkt_state);

	/* Transfer scsi_pkt information to uscsi */
	(void) scsi_uscsi_pktfini(pkt, ucmd);

	if (pkt->pkt_reason != CMD_CMPLT) {
		/*
		 * The command did not complete.
		 */
		sgen_log(sg_state, SGEN_DIAG3,
		    "sgen_callback: command did not complete");
		action = sgen_handle_incomplete(sg_state, pkt);
	} else if (sg_state->sgen_arq_enabled &&
	    (pkt->pkt_state & STATE_ARQ_DONE)) {
		/*
		 * The auto-rqsense happened, and the packet has a filled-in
		 * scsi_arq_status structure, pointed to by pkt_scbp.
		 */
		sgen_log(sg_state, SGEN_DIAG3,
		    "sgen_callback: received auto-requested sense");
		action = sgen_handle_autosense(sg_state, pkt);
		ASSERT(action != FETCH_SENSE);
	} else if (pkt->pkt_flags & FLAG_SENSING) {
		/*
		 * sgen was running a REQUEST SENSE. Decode the sense data and
		 * decide what to do next.
		 *
		 * Clear FLAG_SENSING on the original packet for completeness.
		 */
		sgen_log(sg_state, SGEN_DIAG3, "sgen_callback: received sense");
		sg_state->sgen_cmdpkt->pkt_flags &= ~FLAG_SENSING;
		action = sgen_handle_sense(sg_state);
		ASSERT(action != FETCH_SENSE);
	} else {
		/*
		 * Command completed and we're not getting sense. Check for
		 * errors and decide what to do next.
		 */
		sgen_log(sg_state, SGEN_DIAG3,
		    "sgen_callback: command appears complete");
		action = sgen_check_error(sg_state, bp);
	}

	switch (action) {
	case FETCH_SENSE:
		/*
		 * If there is sense to fetch, break out to prevent biodone'ing
		 * until the sense fetch is complete.
		 */
		if (sgen_initiate_sense(sg_state,
		    scsi_pkt_allocated_correctly(pkt) ?
		    pkt->pkt_path_instance : 0) == 0)
			break;
		/*FALLTHROUGH*/
	case COMMAND_DONE_ERROR:
		bp->b_resid = bp->b_bcount;
		bioerror(bp, EIO);
		/*FALLTHROUGH*/
	case COMMAND_DONE:
		biodone(bp);
		break;
	default:
		ASSERT(0);
		break;
	}

	sgen_log(sg_state, SGEN_DIAG2, "done sgen_callback()");
}

/*
 * sgen_initiate_sense()
 *	Send the sgen_rqspkt to the target, thereby requesting sense data.
 */
static int
sgen_initiate_sense(sgen_state_t *sg_state, int path_instance)
{
	/* use same path_instance as command */
	if (scsi_pkt_allocated_correctly(sg_state->sgen_rqspkt))
		sg_state->sgen_rqspkt->pkt_path_instance = path_instance;

	switch (sgen_scsi_transport(sg_state->sgen_rqspkt)) {
	case TRAN_ACCEPT:
		sgen_log(sg_state, SGEN_DIAG3, "sgen_initiate_sense: "
		    "sense fetch transport accepted.");
		return (0);
	case TRAN_BUSY:
		sgen_log(sg_state, SGEN_DIAG2, "sgen_initiate_sense: "
		    "sense fetch transport busy, setting timeout.");
		sg_state->sgen_restart_timeid = timeout(sgen_restart, sg_state,
		    SGEN_BSY_TIMEOUT);
		return (0);
	default:
		sgen_log(sg_state, SGEN_DIAG2, "sgen_initiate_sense: "
		    "sense fetch transport failed or busy.");
		return (-1);
	}
}

/*
 * sgen_handle_incomplete()
 *	sgen is pessimistic, but also careful-- it doesn't try to retry
 *	incomplete commands, but it also doesn't go resetting devices;
 *	it is hard to tell if the device will be tolerant of that sort
 *	of prodding.
 *
 *	This routine has been left as a guide for the future--- the
 *	current administration's hands-off policy may need modification.
 */
/*ARGSUSED*/
static int
sgen_handle_incomplete(sgen_state_t *sg_state, struct scsi_pkt *pkt)
{
	SGEN_DO_ERRSTATS(sg_state, sgen_incmp_err);
	return (COMMAND_DONE_ERROR);
}

/*
 * sgen_handle_autosense()
 *	Deal with SENSE data acquired automatically via the auto-request-sense
 *	facility.
 *
 *	Sgen takes a pessimistic view of things-- it doesn't retry commands,
 *	and unless the device recovered from the problem, this routine returns
 *	COMMAND_DONE_ERROR.
 */
static int
sgen_handle_autosense(sgen_state_t *sg_state, struct scsi_pkt *pkt)
{
	struct scsi_arq_status *arqstat;
	struct uscsi_cmd *ucmd =
	    (struct uscsi_cmd *)sg_state->sgen_cmdbuf->b_private;
	int amt;

	arqstat = (struct scsi_arq_status *)(pkt->pkt_scbp);

	SGEN_DO_ERRSTATS(sg_state, sgen_autosen_rcv);

	if (arqstat->sts_rqpkt_reason != CMD_CMPLT) {
		sgen_log(sg_state, SGEN_DIAG1, "sgen_handle_autosense: ARQ"
		    "failed to complete.");
		SGEN_DO_ERRSTATS(sg_state, sgen_autosen_bad);
		return (COMMAND_DONE_ERROR);
	}

	if (pkt->pkt_state & STATE_XARQ_DONE) {
		amt = MAX_SENSE_LENGTH - arqstat->sts_rqpkt_resid;
	} else {
		if (arqstat->sts_rqpkt_resid > SENSE_LENGTH) {
			amt = MAX_SENSE_LENGTH - arqstat->sts_rqpkt_resid;
		} else {
			amt = SENSE_LENGTH - arqstat->sts_rqpkt_resid;
		}
	}

	if (ucmd->uscsi_flags & USCSI_RQENABLE) {
		ucmd->uscsi_rqstatus = *((char *)&arqstat->sts_rqpkt_status);
		uchar_t rqlen = min((uchar_t)amt, ucmd->uscsi_rqlen);
		ucmd->uscsi_rqresid = ucmd->uscsi_rqlen - rqlen;
		ASSERT(ucmd->uscsi_rqlen && sg_state->sgen_rqs_sen);
		bcopy(&(arqstat->sts_sensedata), sg_state->sgen_rqs_sen, rqlen);
		sgen_log(sg_state, SGEN_DIAG2, "sgen_handle_autosense: "
		    "uscsi_rqstatus=0x%x uscsi_rqresid=%d\n",
		    ucmd->uscsi_rqstatus, ucmd->uscsi_rqresid);
	}

	if (arqstat->sts_rqpkt_status.sts_chk) {
		sgen_log(sg_state, SGEN_DIAG1, "sgen_handle_autosense: got "
		    "check condition on auto request sense!");
		SGEN_DO_ERRSTATS(sg_state, sgen_autosen_bad);
		return (COMMAND_DONE_ERROR);
	}

	if (((arqstat->sts_rqpkt_state & STATE_XFERRED_DATA) == 0) ||
	    (amt == 0)) {
		sgen_log(sg_state, SGEN_DIAG1, "sgen_handle_autosense: got "
		    "auto-sense, but it contains no data!");
		SGEN_DO_ERRSTATS(sg_state, sgen_autosen_bad);
		return (COMMAND_DONE_ERROR);
	}

	/*
	 * Stuff the sense data pointer into sgen_sense for later retrieval
	 */
	sg_state->sgen_sense = &arqstat->sts_sensedata;

	/*
	 * Now, check to see whether we got enough sense data to make any
	 * sense out if it (heh-heh).
	 */
	if (amt < SUN_MIN_SENSE_LENGTH) {
		sgen_log(sg_state, SGEN_DIAG1, "sgen_handle_autosense: not "
		    "enough auto sense data");
		return (COMMAND_DONE_ERROR);
	}

	switch (arqstat->sts_sensedata.es_key) {
	case KEY_RECOVERABLE_ERROR:
		SGEN_DO_ERRSTATS(sg_state, sgen_recov_err);
		break;
	case KEY_NO_SENSE:
		SGEN_DO_ERRSTATS(sg_state, sgen_nosen_err);
		break;
	default:
		SGEN_DO_ERRSTATS(sg_state, sgen_unrecov_err);
		break;
	}

	return (COMMAND_DONE);
}

/*
 * sgen_handle_sense()
 *	Examine sense data that was manually fetched from the target.
 */
static int
sgen_handle_sense(sgen_state_t *sg_state)
{
	struct scsi_pkt *rqpkt = sg_state->sgen_rqspkt;
	struct scsi_status *rqstatus = (struct scsi_status *)rqpkt->pkt_scbp;
	struct uscsi_cmd *ucmd =
	    (struct uscsi_cmd *)sg_state->sgen_cmdbuf->b_private;
	int amt;

	SGEN_DO_ERRSTATS(sg_state, sgen_sense_rcv);

	amt = MAX_SENSE_LENGTH - rqpkt->pkt_resid;

	if (ucmd->uscsi_flags & USCSI_RQENABLE) {
		ucmd->uscsi_rqstatus = *((char *)rqstatus);
		uchar_t rqlen = min((uchar_t)amt, ucmd->uscsi_rqlen);
		ucmd->uscsi_rqresid = ucmd->uscsi_rqlen - rqlen;
		ASSERT(ucmd->uscsi_rqlen && sg_state->sgen_rqs_sen);
		bcopy(sg_state->sgen_sense, sg_state->sgen_rqs_sen, rqlen);
		sgen_log(sg_state, SGEN_DIAG2, "sgen_handle_sense: "
		    "uscsi_rqstatus=0x%x uscsi_rqresid=%d\n",
		    ucmd->uscsi_rqstatus, ucmd->uscsi_rqresid);
	}

	if (rqstatus->sts_busy) {
		sgen_log(sg_state, SGEN_DIAG1, "sgen_handle_sense: got busy "
		    "on request sense");
		SGEN_DO_ERRSTATS(sg_state, sgen_sense_bad);
		return (COMMAND_DONE_ERROR);
	}

	if (rqstatus->sts_chk) {
		sgen_log(sg_state, SGEN_DIAG1, "sgen_handle_sense: got check "
		    "condition on request sense!");
		SGEN_DO_ERRSTATS(sg_state, sgen_sense_bad);
		return (COMMAND_DONE_ERROR);
	}

	if ((rqpkt->pkt_state & STATE_XFERRED_DATA) == 0 || amt == 0) {
		sgen_log(sg_state, SGEN_DIAG1, "sgen_handle_sense: got "
		    "sense, but it contains no data");
		SGEN_DO_ERRSTATS(sg_state, sgen_sense_bad);
		return (COMMAND_DONE_ERROR);
	}

	/*
	 * Now, check to see whether we got enough sense data to make any
	 * sense out if it (heh-heh).
	 */
	if (amt < SUN_MIN_SENSE_LENGTH) {
		sgen_log(sg_state, SGEN_DIAG1, "sgen_handle_sense: not "
		    "enough sense data");
		SGEN_DO_ERRSTATS(sg_state, sgen_sense_bad);
		return (COMMAND_DONE_ERROR);
	}

	/*
	 * Decode the sense data-- this was deposited here for us by the
	 * setup in sgen_do_attach(). (note that sgen_sense is an alias for
	 * the sd_sense field in the scsi_device).
	 */
	sgen_log(sg_state, SGEN_DIAG1, "Sense key is %s [0x%x]",
	    scsi_sname(sg_state->sgen_sense->es_key),
	    sg_state->sgen_sense->es_key);
	switch (sg_state->sgen_sense->es_key) {
	case KEY_RECOVERABLE_ERROR:
		SGEN_DO_ERRSTATS(sg_state, sgen_recov_err);
		break;
	case KEY_NO_SENSE:
		SGEN_DO_ERRSTATS(sg_state, sgen_nosen_err);
		break;
	default:
		SGEN_DO_ERRSTATS(sg_state, sgen_unrecov_err);
		break;
	}

	return (COMMAND_DONE);
}

/*
 * sgen_check_error()
 *	examine the command packet for abnormal completion.
 *
 *	sgen_check_error should only be called at the completion of the
 *	command packet.
 */
static int
sgen_check_error(sgen_state_t *sg_state, struct buf *bp)
{
	struct scsi_pkt *pkt = sg_state->sgen_cmdpkt;
	struct scsi_status *status = (struct scsi_status *)pkt->pkt_scbp;
	struct uscsi_cmd *ucmd =
	    (struct uscsi_cmd *)sg_state->sgen_cmdbuf->b_private;

	if (status->sts_busy) {
		sgen_log(sg_state, SGEN_DIAG1,
		    "sgen_check_error: target is busy");
		return (COMMAND_DONE_ERROR);
	}

	/*
	 * pkt_resid will reflect, at this point, a residual of how many bytes
	 * were not transferred; a non-zero pkt_resid is an error.
	 */
	if (pkt->pkt_resid) {
		bp->b_resid += pkt->pkt_resid;
	}

	if (status->sts_chk) {
		if (ucmd->uscsi_flags & USCSI_RQENABLE) {
			if (sg_state->sgen_arq_enabled) {
				sgen_log(sg_state, SGEN_DIAG1,
				    "sgen_check_error: strange: target "
				    "indicates CHECK CONDITION with auto-sense "
				    "enabled.");
			}
			sgen_log(sg_state, SGEN_DIAG2, "sgen_check_error: "
			    "target ready for sense fetch");
			return (FETCH_SENSE);
		} else {
			sgen_log(sg_state, SGEN_DIAG2, "sgen_check_error: "
			    "target indicates CHECK CONDITION");
		}
	}

	return (COMMAND_DONE);
}

/*
 * sgen_tur()
 *	test if a target is ready to operate by sending it a TUR command.
 */
static int
sgen_tur(dev_t dev)
{
	char cmdblk[CDB_GROUP0];
	struct uscsi_cmd scmd;

	bzero(&scmd, sizeof (scmd));
	scmd.uscsi_bufaddr = 0;
	scmd.uscsi_buflen = 0;
	bzero(cmdblk, CDB_GROUP0);
	cmdblk[0] = (char)SCMD_TEST_UNIT_READY;
	scmd.uscsi_flags = USCSI_DIAGNOSE | USCSI_SILENT | USCSI_WRITE;
	scmd.uscsi_cdb = cmdblk;
	scmd.uscsi_cdblen = CDB_GROUP0;

	return (sgen_uscsi_cmd(dev, &scmd, FKIOCTL));
}

/*
 * sgen_diag_ok()
 *	given an sg_state and a desired diagnostic level, return true if
 *	it is acceptable to output a message.
 */
/*ARGSUSED*/
static int
sgen_diag_ok(sgen_state_t *sg_state, int level)
{
	int diag_lvl;

	switch (level) {
	case CE_WARN:
	case CE_NOTE:
	case CE_CONT:
	case CE_PANIC:
		return (1);
	case SGEN_DIAG1:
	case SGEN_DIAG2:
	case SGEN_DIAG3:
		if (sg_state) {
			/*
			 * Check to see if user overrode the diagnostics level
			 * for this instance (either via SGEN_IOC_DIAG or via
			 * .conf file).  If not, fall back to the global diag
			 * level.
			 */
			if (sg_state->sgen_diag != -1)
				diag_lvl = sg_state->sgen_diag;
			else
				diag_lvl = sgen_diag;
		} else {
			diag_lvl = sgen_diag;
		}
		if (((diag_lvl << 8) | CE_CONT) >= level) {
			return (1);
		} else {
			return (0);
		}
	default:
		return (1);
	}
}

/*PRINTFLIKE3*/
static void
sgen_log(sgen_state_t *sg_state, int level, const char *fmt, ...)
{
	va_list	ap;
	char buf[256];

	if (!sgen_diag_ok(sg_state, level))
		return;

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	switch (level) {
	case CE_NOTE:
	case CE_CONT:
	case CE_WARN:
	case CE_PANIC:
		if (sg_state == (sgen_state_t *)NULL) {
			cmn_err(level, "%s", buf);
		} else {
			scsi_log(sg_state->sgen_devinfo, sgen_label, level,
			    "%s", buf);
		}
		break;
	case SGEN_DIAG1:
	case SGEN_DIAG2:
	case SGEN_DIAG3:
	default:
		if (sg_state == (sgen_state_t *)NULL) {
			scsi_log(NULL, sgen_label, CE_CONT, "%s", buf);
		} else {
			scsi_log(sg_state->sgen_devinfo, sgen_label, CE_CONT,
			    "%s", buf);
		}
	}
}

/*
 * sgen_dump_cdb()
 *	dump out the contents of a cdb.  Take care that 'label' is not too
 *	large, or 'buf' could overflow.
 */
static void
sgen_dump_cdb(sgen_state_t *sg_state, const char *label,
    union scsi_cdb *cdb, int cdblen)
{
	static char hex[] = "0123456789abcdef";
	char *buf, *p;
	size_t nbytes;
	int i;
	uchar_t	*cdbp = (uchar_t *)cdb;

	/*
	 * fastpath-- if we're not able to print out, don't do all of this
	 * extra work.
	 */
	if (!sgen_diag_ok(sg_state, SGEN_DIAG3))
		return;

	/*
	 * 3 characters for each byte (because of the ' '), plus the size of
	 * the label, plus the trailing ']' and the null character.
	 */
	nbytes = 3 * cdblen + strlen(label) + strlen(" CDB = [") + 2;
	buf = kmem_alloc(nbytes, KM_SLEEP);
	(void) sprintf(buf, "%s CDB = [", label);
	p = &buf[strlen(buf)];
	for (i = 0; i < cdblen; i++, cdbp++) {
		if (i > 0)
			*p++ = ' ';
		*p++ = hex[(*cdbp >> 4) & 0x0f];
		*p++ = hex[*cdbp & 0x0f];
	}
	*p++ = ']';
	*p = 0;
	sgen_log(sg_state, SGEN_DIAG3, buf);
	kmem_free(buf, nbytes);
}

static void
sgen_dump_sense(sgen_state_t *sg_state, size_t rqlen, uchar_t *rqbuf)
{
	static char hex[] = "0123456789abcdef";
	char *buf, *p;
	size_t nbytes;
	int i;

	/*
	 * fastpath-- if we're not able to print out, don't do all of this
	 * extra work.
	 */
	if (!sgen_diag_ok(sg_state, SGEN_DIAG3))
		return;

	/*
	 * 3 characters for each byte (because of the ' '), plus the size of
	 * the label, plus the trailing ']' and the null character.
	 */
	nbytes = 3 * rqlen + strlen(" SENSE = [") + 2;
	buf = kmem_alloc(nbytes, KM_SLEEP);
	(void) sprintf(buf, "SENSE = [");
	p = &buf[strlen(buf)];
	for (i = 0; i < rqlen; i++, rqbuf++) {
		if (i > 0)
			*p++ = ' ';
		*p++ = hex[(*rqbuf >> 4) & 0x0f];
		*p++ = hex[*rqbuf & 0x0f];
	}
	*p++ = ']';
	*p = 0;
	sgen_log(sg_state, SGEN_DIAG3, buf);
	kmem_free(buf, nbytes);
}
