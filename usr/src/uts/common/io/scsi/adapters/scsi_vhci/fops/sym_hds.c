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

/* Copyright 2008 Hitachi Ltd. */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This file contains confidential information of other companies
 * and should not be distributed in source form without approval
 * from Sun Legal.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation of "scsi_vhci_f_sym_hds" asymmetric-active-active
 * failover_ops. The device has a preferred(owner)/non-preferred
 * with no action needed to use the non-preferred path. This is really
 * more inline with symmetric device so am using that prefix.
 *
 * This file imports the standard "scsi_vhci_f_sym", but with HDS specific
 * knowledge related to preferred/non-preferred path.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/adapters/scsi_vhci.h>

/* Supported device table entries.  */
char *hds_sym_dev_table[] = {
/*	"                  111111" */
/*	"012345670123456789012345" */
/*	"|-VID--||-----PID------|" */

	"HITACHI DF",
	NULL
};

static int	hds_sym_device_probe(struct scsi_device *,
			struct scsi_inquiry *, void **);
static void	hds_sym_device_unprobe(struct scsi_device *, void *);
static void	hds_sym_init();
static int	hds_sym_get_opinfo(struct scsi_device *sd,
			struct scsi_path_opinfo *opinfo, void *ctpriv);

#ifdef	lint
#define	scsi_vhci_failover_ops	scsi_vhci_failover_ops_f_sym_hds
#endif	/* lint */
/*
 * Use the following for the Asymmetric-Active-Active fops.
 * A different fops may get used for the Symmetric-Active-Active.
 */
struct scsi_failover_ops scsi_vhci_failover_ops = {
	SFO_REV,
	SFO_NAME_SYM "_hds",
	hds_sym_dev_table,
	hds_sym_init,
	hds_sym_device_probe,
	hds_sym_device_unprobe,
	NULL,
	NULL,
	hds_sym_get_opinfo,
	/* The rest of the implementation comes from SFO_NAME_SYM import  */
};

static struct modlmisc modlmisc = {
	&mod_miscops, "f_sym_hds 1.1"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

#define	HDS_MAX_INQ_BUF_SIZE		0xff
#define	HDS_INQ_PAGE_E0			0xe0
#define	HDS_SAA_TYPE			"DF00"
#define	ASYM_ACTIVE_ACTIVE		0
#define	SYM_ACTIVE_ACTIVE		1

extern struct scsi_failover_ops	*vhci_failover_ops_by_name(char *);

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static void
hds_sym_init()
{
	struct scsi_failover_ops	*sfo, *ssfo, clone;

	/* clone SFO_NAME_SYM implementation for most things */
	ssfo = vhci_failover_ops_by_name(SFO_NAME_SYM);
	if (ssfo == NULL) {
		VHCI_DEBUG(4, (CE_NOTE, NULL, "!hds_sym_init: "
		    "can't import " SFO_NAME_SYM "\n"));
		return;
	}
	sfo				= &scsi_vhci_failover_ops;
	clone				= *ssfo;
	clone.sfo_rev			= sfo->sfo_rev;
	clone.sfo_name			= sfo->sfo_name;
	clone.sfo_devices		= sfo->sfo_devices;
	clone.sfo_init			= sfo->sfo_init;
	clone.sfo_device_probe		= sfo->sfo_device_probe;
	clone.sfo_device_unprobe	= sfo->sfo_device_unprobe;
	clone.sfo_path_get_opinfo	= sfo->sfo_path_get_opinfo;
	*sfo				= clone;
}

/* ARGSUSED */
static int
hds_sym_device_probe(struct scsi_device *sd, struct scsi_inquiry *stdinq,
void **ctpriv)
{
	char	**dt;
	char	*dftype;
	unsigned char	len;
	unsigned char	*inq_data = (unsigned char *)stdinq;

	VHCI_DEBUG(6, (CE_NOTE, NULL, "hds_sym_device_probe: vidpid %s\n",
	    stdinq->inq_vid));
	for (dt = hds_sym_dev_table; *dt; dt++) {
		if (strncmp(stdinq->inq_vid, *dt, strlen(*dt)))
			continue;
		len = inq_data[4];
		if (len < 128) {
			vhci_log(CE_NOTE, NULL,
			    "hds_sym_device_probe: vidpid %s len error: %d\n",
			    stdinq->inq_vid, len);
			return (SFO_DEVICE_PROBE_PHCI);
		}
		*ctpriv = kmem_alloc(sizeof (unsigned char), KM_SLEEP);
		dftype = (char *)&inq_data[128];
		if (*dftype == 0) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "hds_sym_device_probe: vidpid %s"
			    " ASYM_ACTIVE_ACTIVE\n", stdinq->inq_vid));
			*((unsigned char *)*ctpriv) = ASYM_ACTIVE_ACTIVE;
			return (SFO_DEVICE_PROBE_VHCI);
		}
		if (strncmp(dftype, HDS_SAA_TYPE, strlen(HDS_SAA_TYPE)) == 0) {
			*((unsigned char *)*ctpriv) = SYM_ACTIVE_ACTIVE;
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "hds_sym_device_probe: vidpid %s"
			    " SYM_ACTIVE_ACTIVE\n", stdinq->inq_vid));
			return (SFO_DEVICE_PROBE_VHCI);
		}
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "hds_sym_device_probe: vidpid %s"
		    " - unknown dftype: %d\n", stdinq->inq_vid, *dftype));
		kmem_free(*ctpriv, sizeof (unsigned char));
		*ctpriv = NULL;
		return (SFO_DEVICE_PROBE_PHCI);

	}
	return (SFO_DEVICE_PROBE_PHCI);
}

/* ARGSUSED */
static void
hds_sym_device_unprobe(struct scsi_device *sd, void *ctpriv)
{
	if (ctpriv != NULL) {
		kmem_free(ctpriv, sizeof (unsigned char));
	}
}


/*
 * Local routine to get inquiry VPD page from the device.
 *
 * return 1 for failure
 * return 0 for success
 */
static int
hds_get_inquiry_vpd_page(struct scsi_device *sd, unsigned char page,
    unsigned char *buf, int size)
{
	int		retval = 0;
	struct buf	*bp;
	struct scsi_pkt	*pkt;
	struct scsi_address	*ap;

	if ((buf == NULL) || (size == 0)) {
		return (1);
	}
	bp = getrbuf(KM_NOSLEEP);
	if (bp == NULL) {
		return (1);
	}
	bp->b_un.b_addr = (char *)buf;
	bp->b_flags = B_READ;
	bp->b_bcount = size;
	bp->b_resid = 0;

	ap = &sd->sd_address;
	pkt = scsi_init_pkt(ap, NULL, bp, CDB_GROUP0,
	    sizeof (struct scsi_arq_status), 0, 0, NULL, NULL);
	if (pkt == NULL) {
		VHCI_DEBUG(4, (CE_WARN, NULL,
		    "hds_get_inquiry_vpd_page:"
		    "Failed to initialize packet"));
		freerbuf(bp);
		return (1);
	}

	/*
	 * Send the inquiry command for page xx to the target.
	 * Data is returned in the buf pointed to by buf.
	 */

	pkt->pkt_cdbp[0] = SCMD_INQUIRY;
	pkt->pkt_cdbp[1] = 0x1;
	pkt->pkt_cdbp[2] = page;
	pkt->pkt_cdbp[4] = (unsigned char)size;
	pkt->pkt_time = 90;
	retval = vhci_do_scsi_cmd(pkt);
	scsi_destroy_pkt(pkt);
	freerbuf(bp);
	return (!retval);

}

/* ARGSUSED */
static int
hds_sym_get_opinfo(struct scsi_device *sd, struct scsi_path_opinfo *opinfo,
    void *ctpriv)
{
	unsigned char	inq_vpd_buf[HDS_MAX_INQ_BUF_SIZE];

	opinfo->opinfo_rev = OPINFO_REV;
	(void) strcpy(opinfo->opinfo_path_attr, "primary");
	opinfo->opinfo_path_state  = SCSI_PATH_ACTIVE;
	opinfo->opinfo_pswtch_best = 0;		/* N/A */
	opinfo->opinfo_pswtch_worst = 0;	/* N/A */
	opinfo->opinfo_xlf_capable = 0;
	opinfo->opinfo_mode = SCSI_NO_FAILOVER;
	ASSERT(ctpriv != NULL);
	if (*((unsigned char *)ctpriv) == SYM_ACTIVE_ACTIVE) {
		VHCI_DEBUG(4, (CE_NOTE, NULL,
		    "hds_get_opinfo: sd(%p): sym_active_active "
		    "preferred bit set ", (void*)sd));
		opinfo->opinfo_preferred = PCLASS_PREFERRED;
		return (0);
	}
	/* check if this is the preferred path */
	if (hds_get_inquiry_vpd_page(sd, HDS_INQ_PAGE_E0, inq_vpd_buf,
	    sizeof (inq_vpd_buf)) != 0) {
		VHCI_DEBUG(4, (CE_WARN, NULL,
		    "hds_get_opinfo: sd(%p):Unable to "
		    "get inquiry Page %x", (void*)sd, HDS_INQ_PAGE_E0));
		return (1);
	}
	if (inq_vpd_buf[4] & 0x80) {
		if (inq_vpd_buf[4] & 0x40) {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "hds_get_opinfo: sd(%p): preferred bit set ",
			    (void*)sd));
			opinfo->opinfo_preferred = PCLASS_PREFERRED;
		} else {
			VHCI_DEBUG(4, (CE_NOTE, NULL,
			    "hds_get_opinfo: sd(%p): non-preferred bit set ",
			    (void*)sd));
			opinfo->opinfo_preferred = PCLASS_NONPREFERRED;
		}
	} else {
		vhci_log(CE_NOTE, NULL,
		    "hds_get_opinfo: sd(%p): "
		    "get inquiry Page %x has invalid P/SVid bit set",
		    (void*)sd, HDS_INQ_PAGE_E0);
		return (1);
	}

	return (0);
}
