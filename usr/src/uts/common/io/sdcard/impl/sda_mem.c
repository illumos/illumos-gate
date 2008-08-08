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
 * Memory target support for SDcard.
 */

#include <sys/types.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/scsi/adapters/blk2scsa.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sdcard/sda.h>
#include <sys/sdcard/sda_impl.h>

static int sda_mem_attach(dev_info_t *, ddi_attach_cmd_t);
static int sda_mem_detach(dev_info_t *, ddi_detach_cmd_t);
static b2s_err_t sda_mem_b2s_errno(sda_err_t);
static boolean_t sda_mem_b2s_request(void *, b2s_request_t *);
static boolean_t sda_mem_b2s_rw(sda_slot_t *, b2s_request_t *);
static void sda_mem_b2s_done(sda_cmd_t *);
static void sda_mem_getstring(uint32_t *, char *, int, int);
static int sda_mem_parse_cid_csd(sda_slot_t *, dev_info_t *);
static int sda_mem_cmd(sda_slot_t *, uint8_t, uint32_t, uint8_t, uint32_t *);


/*
 * To minimize complexity and reduce layering, we implement almost the
 * entire memory card driver (sdcard) here.  The memory card still
 * needs to be a separate driver though, due to the requirement to
 * have both SCSI HBA bus ops and SD bus ops.
 */

/*
 * SCSA layer supplies a cb_ops, but we don't want it, because we
 * don't want to expose a SCSI attachment point.  (Our parent handles
 * the attachment point, the SCSI one would be confusing.)  We have to
 * supply a stubbed out one, to prevent SCSA from trying to create minor
 * nodes on our behalf.
 *
 * Perhaps at some future point we might want to expose a separate set
 * of ioctls for these nodes, but for now we rely on our parent to do
 * all that work.
 */
static struct cb_ops sda_mem_ops = {
	nodev,			/* cb_open */
	nodev,			/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_MP			/* cb_flag */
};

/*
 * Here are the public functions.
 */
void
sda_mem_init(struct modlinkage *modlp)
{
	struct dev_ops *devo;

	devo = ((struct modldrv *)(modlp->ml_linkage[0]))->drv_dev_ops;
	devo->devo_attach = sda_mem_attach;
	devo->devo_detach = sda_mem_detach;

	devo->devo_cb_ops = &sda_mem_ops;

	/* it turns out that this can't ever really fail */
	(void) b2s_mod_init(modlp);
}

void
sda_mem_fini(struct modlinkage *modlp)
{
	b2s_mod_fini(modlp);
}

/*
 * Everything beyond this is private.
 */

int
sda_mem_cmd(sda_slot_t *slot, uint8_t cmd, uint32_t arg, uint8_t rtype,
    uint32_t *resp)
{
	sda_cmd_t	*cmdp;
	int		errno;

	cmdp = sda_cmd_alloc(slot, cmd, arg, rtype, NULL, KM_SLEEP);
	if (cmdp == NULL) {
		return (ENOMEM);
	}
	errno = sda_cmd_exec(slot, cmdp, resp);
	sda_cmd_free(cmdp);

	return (errno);
}

boolean_t
sda_mem_b2s_rw(sda_slot_t *slot, b2s_request_t *reqp)
{
	sda_cmd_t	*cmdp;
	uint64_t	nblks;
	uint64_t	blkno;
	uint16_t	rblen;
	int		rv;
	uint8_t		index;
	uint16_t	flags;

	blkno = reqp->br_lba;
	nblks = reqp->br_nblks;

	switch (reqp->br_cmd) {
	case B2S_CMD_READ:
		if (nblks > 1) {
			index = CMD_READ_MULTI;
			flags = SDA_CMDF_DAT | SDA_CMDF_MEM | SDA_CMDF_READ |
			    SDA_CMDF_AUTO_CMD12;
		} else {
			index = CMD_READ_SINGLE;
			flags = SDA_CMDF_DAT | SDA_CMDF_MEM | SDA_CMDF_READ;
		}
		break;
	case B2S_CMD_WRITE:
		if (nblks > 1) {
			index = CMD_WRITE_MULTI;
			flags = SDA_CMDF_DAT | SDA_CMDF_MEM | SDA_CMDF_WRITE |
			    SDA_CMDF_AUTO_CMD12;
		} else {
			index = CMD_WRITE_SINGLE;
			flags = SDA_CMDF_DAT | SDA_CMDF_MEM | SDA_CMDF_WRITE;
		}
		break;
	default:
		ASSERT(0);
		break;
	}

	cmdp = sda_cmd_alloc(slot, index, blkno << slot->s_bshift,
	    R1, reqp, KM_NOSLEEP);
	if (cmdp == NULL) {
		b2s_request_done(reqp, B2S_ENOMEM, 0);
		return (B_TRUE);
	}

	if (slot->s_host->h_dma != NULL) {
		b2s_request_dma(reqp, &cmdp->sc_ndmac, &cmdp->sc_dmacs);
		cmdp->sc_kvaddr = 0;
	}
	if ((slot->s_caps & SLOT_CAP_NOPIO) == 0) {
		size_t	maplen;
		b2s_request_mapin(reqp, &cmdp->sc_kvaddr, &maplen);
		cmdp->sc_ndmac = 0;
	}

	if (nblks == 0) {
		/*
		 * This is not strictly a failure, but no work to do.
		 * We have to do it late here because we don't want to
		 * by pass the above media readiness checks.
		 */
		rv = B2S_EOK;
		goto failed;
	}
	if (nblks > 0xffff) {
		rv = B2S_EINVAL;
		goto failed;
	}

	rblen = slot->s_blksz;

	if ((blkno + nblks) > slot->s_nblks) {
		rv = B2S_EBLKADDR;
		goto failed;
	}

	cmdp->sc_rtype = R1;
	cmdp->sc_blksz = rblen;
	cmdp->sc_nblks = (uint16_t)nblks;
	cmdp->sc_index = index;
	cmdp->sc_flags = flags;

	sda_cmd_submit(slot, cmdp, sda_mem_b2s_done);
	return (B_TRUE);

failed:
	sda_cmd_free(cmdp);
	b2s_request_done(reqp, rv, 0);
	return (B_TRUE);
}

boolean_t
sda_mem_b2s_format(sda_slot_t *slot, b2s_request_t *reqp)
{
	sda_cmd_t	*cmdp;
	int		rv;


	rv = sda_mem_cmd(slot, CMD_ERASE_START, 0, R1, NULL);
	if (rv != 0) {
		b2s_request_done(reqp, sda_mem_b2s_errno(rv), 0);
		return (B_TRUE);
	}
	rv = sda_mem_cmd(slot, CMD_ERASE_END, slot->s_nblks - 1, R1, NULL);
	if (rv != 0) {
		b2s_request_done(reqp, sda_mem_b2s_errno(rv), 0);
		return (B_TRUE);
	}

	cmdp = sda_cmd_alloc(slot, CMD_ERASE, 0, R1b, reqp, KM_NOSLEEP);
	if (cmdp == NULL) {
		b2s_request_done(reqp, B2S_ENOMEM, 0);
		return (B_TRUE);
	}
	cmdp->sc_flags = SDA_CMDF_DAT | SDA_CMDF_MEM;

	sda_cmd_submit(slot, cmdp, sda_mem_b2s_done);
	return (B_TRUE);
}

b2s_err_t
sda_mem_b2s_errno(sda_err_t errno)
{
	/* the hot path */
	if (errno == SDA_EOK) {
		return (B2S_EOK);
	}

	switch (errno) {
	case SDA_ENOMEM:
		return (B2S_ENOMEM);
	case SDA_ETIME:
		return (B2S_ETIMEDOUT);
	case SDA_EWPROTECT:
		return (B2S_EWPROTECT);
	case SDA_ESUSPENDED:
	case SDA_ENODEV:
		return (B2S_ENOMEDIA);
	case SDA_EFAULT:
	case SDA_ECRC7:
	case SDA_EPROTO:
		return (B2S_EHARDWARE);
	case SDA_ERESET:
		return (B2S_ERESET);
	case SDA_EIO:
	case SDA_ERESID:
	default:
		return (B2S_EIO);
	}
}

void
sda_mem_b2s_done(sda_cmd_t *cmdp)
{
	b2s_request_t	*reqp = sda_cmd_data(cmdp);
	int		errno = sda_cmd_errno(cmdp);

	b2s_request_done(reqp, sda_mem_b2s_errno(errno), cmdp->sc_resid);
	sda_cmd_free(cmdp);
}

boolean_t
sda_mem_b2s_request(void *arg, b2s_request_t *reqp)
{
	sda_slot_t	*slot = arg;
	int		rv;

	switch (reqp->br_cmd) {
	case B2S_CMD_WRITE:
		if ((slot->s_flags & SLOTF_WRITABLE) == 0) {
			rv = B2S_EWPROTECT;
		} else {
			return (sda_mem_b2s_rw(slot, reqp));
		}
		break;

	case B2S_CMD_READ:
		return (sda_mem_b2s_rw(slot, reqp));

	case B2S_CMD_INQUIRY:
		reqp->br_inquiry.inq_vendor = "OSOL";
		reqp->br_inquiry.inq_product =
		    slot->s_flags & SLOTF_MMC ? "MultiMediaCard" :
		    slot->s_flags & SLOTF_SDHC ? "SDHC Memory Card" :
		    "SD Memory Card";
		reqp->br_inquiry.inq_revision = "";
		reqp->br_inquiry.inq_serial = "";
		rv = B2S_EOK;
		break;

	case B2S_CMD_GETMEDIA:
		if (!slot->s_ready) {
			rv = B2S_ENODEV;
		} else {
			reqp->br_media.media_blksz = slot->s_blksz;
			reqp->br_media.media_nblks = slot->s_nblks;
			/* detect read-only cards */
			if (slot->s_flags & SLOTF_WRITABLE) {
				reqp->br_media.media_flags = 0;
			} else {
				reqp->br_media.media_flags =
				    B2S_MEDIA_FLAG_READ_ONLY;
			}
			rv = B2S_EOK;
		}
		break;

	case B2S_CMD_FORMAT:
		return (sda_mem_b2s_format(slot, reqp));

	case B2S_CMD_ABORT:
		sda_slot_mem_reset(slot, SDA_EABORT);
		rv = B2S_EOK;
		break;

	case B2S_CMD_RESET:
		sda_slot_mem_reset(slot, SDA_ERESET);
		rv = B2S_EOK;
		break;

	case B2S_CMD_START:
	case B2S_CMD_STOP:
	case B2S_CMD_SYNC:
		rv = B2S_EOK;
		break;

	case B2S_CMD_LOCK:
	case B2S_CMD_UNLOCK:
	default:
		rv = B2S_ENOTSUP;
		break;
	}

	b2s_request_done(reqp, rv, 0);
	return (B_TRUE);
}

int
sda_mem_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	sda_slot_t		*slot;
	b2s_nexus_t		*nexus;
	b2s_nexus_info_t	nexinfo;
	b2s_leaf_info_t		leafinfo;

	switch (cmd) {
	case DDI_ATTACH:
		if ((slot = ddi_get_parent_data(dip)) == NULL) {
			return (DDI_FAILURE);
		}

		if (sda_mem_parse_cid_csd(slot, dip) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		nexinfo.nexus_version = B2S_VERSION_0;
		nexinfo.nexus_private = slot;
		nexinfo.nexus_dip = dip;
		nexinfo.nexus_dma_attr = slot->s_host->h_dma;
		nexinfo.nexus_request = sda_mem_b2s_request;

		nexus = b2s_alloc_nexus(&nexinfo);
		if (nexus == NULL) {
			return (DDI_FAILURE);
		}

		leafinfo.leaf_target = 0;
		leafinfo.leaf_lun = 0;
		leafinfo.leaf_flags =
		    B2S_LEAF_REMOVABLE | B2S_LEAF_HOTPLUGGABLE;
		leafinfo.leaf_unique_id = slot->s_uuid;

		slot->s_leaf = b2s_attach_leaf(nexus, &leafinfo);
		if (slot->s_leaf == NULL) {
			b2s_free_nexus(nexus);
			return (DDI_FAILURE);
		}

		slot->s_nexus = nexus;
		if (b2s_attach_nexus(nexus) != DDI_SUCCESS) {
			slot->s_nexus = NULL;
			b2s_free_nexus(nexus);
			return (DDI_FAILURE);
		}
		slot->s_nexus = nexus;

		return (DDI_SUCCESS);


	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

int
sda_mem_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	sda_slot_t	*slot;
	b2s_nexus_t	*nexus;

	switch (cmd) {
	case DDI_DETACH:
		if ((slot = ddi_get_parent_data(dip)) == NULL) {
			return (DDI_FAILURE);
		}
		if ((nexus = slot->s_nexus) == NULL) {
			/* nothing to do */
			return (DDI_SUCCESS);
		}
		if (b2s_detach_nexus(nexus) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
		slot->s_nexus = NULL;
		b2s_free_nexus(nexus);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

uint32_t
sda_mem_getbits(uint32_t *resp, int hibit, int len)
{
	uint32_t	val = 0;
	uint32_t	bit;

	for (bit = hibit; len--; bit--) {
		val <<= 1;
		val |= ((resp[bit / 32]) >> (bit % 32)) & 1;
	}
	return (val);
}

void
sda_mem_getstring(uint32_t *resp, char *s, int hibit, int len)
{
	while (len--) {
		*s++ = sda_mem_getbits(resp, hibit, 8);
		hibit -= 8;
	}
	*s = 0;
}

uint32_t
sda_mem_maxclk(sda_slot_t *slot)
{
	static const uint32_t	mult[16] = {
		0, 10, 12, 13, 15, 20, 25, 30, 35, 40, 45, 50, 55, 60, 70, 80
	};

	static const uint32_t	units[8] = {
		10000, 100000, 1000000, 10000000, 0, 0, 0, 0,
	};
	uint8_t			ts;

	ts = sda_mem_getbits(slot->s_rcsd, 103, 8);

	return ((units[ts & 0x7]) * (mult[(ts >> 3) & 0xf]));
}

int
sda_mem_parse_cid_csd(sda_slot_t *slot, dev_info_t *dip)
{
	uint32_t	*rcid;
	uint32_t	*rcsd;
	int		csdver;
	uint16_t	rblen;
	uint16_t	bshift;
	uint32_t	cmult;
	uint32_t	csize;
	char		date[16];
	char		*dtype;

	rcid = slot->s_rcid;
	rcsd = slot->s_rcsd;

	csdver = sda_mem_getbits(rcsd, 127, 2);

	if (slot->s_flags & SLOTF_SDMEM) {
		switch (csdver) {
		case 0:
			csize = sda_mem_getbits(rcsd, 73, 12);
			/* see comment above */
			rblen = (1 << sda_mem_getbits(rcsd, 83, 4));
			cmult = (4 << sda_mem_getbits(rcsd, 49, 3));
			bshift = 9;
			break;
		case 1:
			rblen = 512;
			csize = sda_mem_getbits(rcsd, 69, 22);
			cmult = 1024;
			bshift = 0;
			break;
		default:
			sda_slot_err(slot, "Unknown SD CSD version (%d)",
			    csdver);
			return (DDI_FAILURE);
		}

		dtype = slot->s_flags & SLOTF_SDHC ? "sdhc" : "sdcard";
		slot->s_mfg = sda_mem_getbits(rcid, 127, 8);
		sda_mem_getstring(rcid, slot->s_oem, 119, 2);
		sda_mem_getstring(rcid, slot->s_prod, 103, 5);
		slot->s_majver = sda_mem_getbits(rcid, 63, 4);
		slot->s_minver = sda_mem_getbits(rcid, 59, 4);
		slot->s_serial =  sda_mem_getbits(rcid, 55, 32);
		slot->s_year = sda_mem_getbits(rcid, 19, 8) + 2000;
		slot->s_month = sda_mem_getbits(rcid, 11, 4);

	} else if (slot->s_flags & SLOTF_MMC) {
		if ((csdver < 1) || (csdver > 2)) {
			sda_slot_err(slot, "Unknown MMC CSD version (%d)",
			    csdver);
			return (DDI_FAILURE);
		}

		dtype = "mmc";

		switch (sda_mem_getbits(rcsd, 125, 4)) {
		case 0:	/* MMC 1.0 - 1.2 */
		case 1:	/* MMC 1.4 */
			slot->s_mfg = sda_mem_getbits(rcid, 127, 24);
			slot->s_oem[0] = 0;
			sda_mem_getstring(rcid, slot->s_prod, 103, 7);
			slot->s_majver = sda_mem_getbits(rcid, 47, 4);
			slot->s_minver = sda_mem_getbits(rcid, 43, 4);
			slot->s_serial =  sda_mem_getbits(rcid, 39, 24);
			break;

		case 2:	/* MMC 2.0 - 2.2 */
		case 3:	/* MMC 3.1 - 3.3 */
		case 4:	/* MMC 4.x */
			slot->s_mfg = sda_mem_getbits(rcid, 127, 8);
			sda_mem_getstring(rcid, slot->s_oem, 119, 2);
			sda_mem_getstring(rcid, slot->s_prod, 103, 6);
			slot->s_majver = sda_mem_getbits(rcid, 55, 4);
			slot->s_minver = sda_mem_getbits(rcid, 51, 4);
			slot->s_serial =  sda_mem_getbits(rcid, 47, 32);
			break;

		default:
			/* this error isn't fatal to us */
			sda_slot_err(slot, "Unknown MMCA version (%d)",
			    sda_mem_getbits(rcsd, 125, 4));
			break;
		}

		slot->s_year = sda_mem_getbits(rcid, 11, 4) + 1997;
		slot->s_month = sda_mem_getbits(rcid, 15, 4);

		csize = sda_mem_getbits(rcsd, 73, 12);
		rblen = (1 << sda_mem_getbits(rcsd, 83, 4));
		cmult = (4 << sda_mem_getbits(rcsd, 49, 3));
		bshift = 9;

	} else {

		sda_slot_err(slot, "Card type unknown");
		return (DDI_FAILURE);
	}

	/*
	 * These fields are common to all known MMC/SDcard memory cards.
	 *
	 * The spec requires that block size 512 be supported.
	 * The media may have a different native size, but 512
	 * byte blocks will always work.  This is true for SDcard,
	 * and apparently for MMC as well.
	 */
	rblen = max(rblen, 512);	/* paranoia */
	slot->s_nblks = (csize + 1) * cmult * (rblen / 512);
	slot->s_bshift = bshift;
	slot->s_blksz = 512;

	slot->s_r2w = (1 << sda_mem_getbits(rcsd, 28, 3));
	slot->s_ccc = sda_mem_getbits(rcsd, 95, 12);
	slot->s_perm_wp = sda_mem_getbits(rcsd, 13, 1);
	slot->s_temp_wp = sda_mem_getbits(rcsd, 12, 1);
	slot->s_dsr = sda_mem_getbits(rcsd, 76, 1);

	if (((slot->s_ccc & (1 << 4)) == 0) ||
	    (slot->s_perm_wp != 0) || (slot->s_temp_wp != 0)) {
		slot->s_flags &= ~SLOTF_WRITABLE;
	}
	(void) snprintf(date, sizeof (date), "%02d-%04d",
	    slot->s_month, slot->s_year);

#define	prop_set_int(name, val)		\
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip, name, val)
#define	prop_set_str(name, val)		\
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip, name, val)
#define	prop_set_bool(name, val)	\
	if (val) (void) ddi_prop_create(DDI_DEV_T_NONE, dip, 0, name, NULL, 0)

	prop_set_str("device-type", dtype);
	prop_set_int("mfg-id", slot->s_mfg);
	prop_set_str("product-id", slot->s_prod);
	prop_set_str("oem-id", slot->s_oem);
	prop_set_str("mfg-date", date);

	prop_set_int("block-size", slot->s_blksz);
	prop_set_int("num-blocks", slot->s_nblks);
	prop_set_int("max-freq", slot->s_maxclk);
	prop_set_bool("dsr-implemented", slot->s_dsr);
	prop_set_int("ccc", slot->s_ccc);
	prop_set_bool("perm-wp", slot->s_perm_wp);
	prop_set_bool("temp-wp", slot->s_temp_wp);

#undef	prop_set_int
#undef	prop_set_str
#undef	prop_set_bool

	return (DDI_SUCCESS);
}
