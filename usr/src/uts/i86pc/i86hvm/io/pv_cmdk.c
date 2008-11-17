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

#include <io/xdf_shell.h>

/*
 * We're emulating (and possibly layering on top of) cmdk devices, so xdf
 * disk unit mappings must match up with cmdk disk unit mappings'.
 */
#if !defined(XDF_PSHIFT)
#error "can't find definition for xdf unit mappings - XDF_PSHIFT"
#endif /* XDF_PSHIFT */

#if !defined(CMDK_UNITSHF)
#error "can't find definition for cmdk unit mappings - CMDK_UNITSHF"
#endif /* CMDK_UNITSHF */

#if ((XDF_PSHIFT - CMDK_UNITSHF) != 0)
#error "cmdk and xdf unit mappings don't match."
#endif /* ((XDF_PSHIFT - CMDK_UNITSHF) != 0) */

extern const struct dev_ops	cmdk_ops;
extern void			*cmdk_state;

/*
 * Globals required by xdf_shell.c
 */
const char		*xdfs_c_name = "cmdk";
const char		*xdfs_c_linkinfo = "PV Common Direct Access Disk";
void			**xdfs_c_hvm_ss = &cmdk_state;
const size_t		xdfs_c_hvm_ss_size = sizeof (struct cmdk);
const struct dev_ops	*xdfs_c_hvm_dev_ops = &cmdk_ops;

const xdfs_h2p_map_t xdfs_c_h2p_map[] = {
	/*
	 * The paths mapping here are very specific to xen and qemu.  When a
	 * domU is booted under xen in HVM mode, qemu is normally used to
	 * emulate up to four ide disks.  These disks always have the four
	 * path listed below.  To configure an emulated ide device, the
	 * xen domain configuration file normally has an entry that looks
	 * like this:
	 *	disk = [ 'file:/foo.img,hda,w' ]
	 *
	 * The part we're interested in is the 'hda', which we'll call the
	 * xen disk device name here.  The xen management tools (which parse
	 * the xen domain configuration file and launch qemu) makes the
	 * following assumptions about this value:
	 *	hda == emulated ide disk 0 (ide bus 0, master)
	 *	hdb == emulated ide disk 1 (ide bus 0, slave)
	 *	hdc == emulated ide disk 2 (ide bus 1, master)
	 *	hdd == emulated ide disk 3 (ide bus 1, slave)
	 *
	 * (Uncoincidentally, these xen disk device names actually map to
	 * the /dev filesystem names of ide disk devices in Linux.  So in
	 * Linux /dev/hda is the first ide disk.)  So for the first part of
	 * our mapping we've just hardcoded the cmdk paths that we know
	 * qemu will use.
	 *
	 * To understand the second half of the mapping (ie, the xdf device
	 * that each emulated cmdk device should be mapped two) we need to
	 * know the solaris device node address that will be assigned to
	 * each xdf device.  (The device node address is the decimal
	 * number that comes after the "xdf@" in the device path.)
	 *
	 * So the question becomes, how do we know what the xenstore device
	 * id for emulated disk will be?  Well, it turns out that since the
	 * xen management tools expect the disk device names to be Linux
	 * device names, those same management tools assign each disk a
	 * device id that matches the dev_t of the corresponding device
	 * under Linux.  (Big shocker.)  This xen device name-to-id mapping
	 * is currently all hard coded here:
	 *	xen.hg/tools/python/xen/util/blkif.py`blkdev_name_to_number()
	 *
	 * So looking at the code above we can see the following xen disk
	 * device name to xenstore device id mappings:
	 *	'hda' == 0t768  == ((3  * 256) + (0 * 64))
	 *	'hdb' == 0t832  == ((3  * 256) + (1 * 64))
	 *	'hdc' == 0t5632 == ((22 * 256) + (0 * 64))
	 *	'hdd' == 0t5696 == ((22 * 256) + (1 * 64))
	 */
	{ "/pci@0,0/pci-ide@1,1/ide@0/cmdk@0,0", "/xpvd/xdf@768" },
	{ "/pci@0,0/pci-ide@1,1/ide@0/cmdk@1,0", "/xpvd/xdf@832" },
	{ "/pci@0,0/pci-ide@1,1/ide@1/cmdk@0,0", "/xpvd/xdf@5632" },
	{ "/pci@0,0/pci-ide@1,1/ide@1/cmdk@1,0", "/xpvd/xdf@5696" },
	{ NULL, 0 }
};

/*
 * Private functions
 */
/*
 * xdfs_get_modser() is basically a local copy of
 * cmdk_get_modser() modified to work without the dadk layer.
 * (which the non-pv version of the cmdk driver uses.)
 */
static int
xdfs_get_modser(xdfs_state_t *xsp, int ioccmd, char *buf, int len)
{
	struct scsi_device	*scsi_device;
	opaque_t		ctlobjp;
	dadk_ioc_string_t	strarg;
	char			*s;
	char			ch;
	boolean_t		ret;
	int			i;
	int			tb;

	strarg.is_buf = buf;
	strarg.is_size = len;
	scsi_device = ddi_get_driver_private(xsp->xdfss_dip);
	ctlobjp = scsi_device->sd_address.a_hba_tran;
	if (CTL_IOCTL(ctlobjp,
	    ioccmd, (uintptr_t)&strarg, FNATIVE | FKIOCTL) != 0)
		return (0);

	/*
	 * valid model/serial string must contain a non-zero non-space
	 * trim trailing spaces/NULL
	 */
	ret = B_FALSE;
	s = buf;
	for (i = 0; i < strarg.is_size; i++) {
		ch = *s++;
		if (ch != ' ' && ch != '\0')
			tb = i + 1;
		if (ch != ' ' && ch != '\0' && ch != '0')
			ret = B_TRUE;
	}

	if (ret == B_FALSE)
		return (0);

	return (tb);
}

/*
 * xdfs_devid_modser() is basically a copy of cmdk_devid_modser()
 * that has been modified to use local pv cmdk driver functions.
 *
 * Build a devid from the model and serial number
 * Return DDI_SUCCESS or DDI_FAILURE.
 */
static int
xdfs_devid_modser(xdfs_state_t *xsp)
{
	int	rc = DDI_FAILURE;
	char	*hwid;
	int	modlen;
	int	serlen;

	/*
	 * device ID is a concatenation of model number, '=', serial number.
	 */
	hwid = kmem_alloc(CMDK_HWIDLEN, KM_SLEEP);
	modlen = xdfs_get_modser(xsp, DIOCTL_GETMODEL, hwid, CMDK_HWIDLEN);
	if (modlen == 0)
		goto err;

	hwid[modlen++] = '=';
	serlen = xdfs_get_modser(xsp, DIOCTL_GETSERIAL,
	    hwid + modlen, CMDK_HWIDLEN - modlen);
	if (serlen == 0)
		goto err;

	hwid[modlen + serlen] = 0;

	/* Initialize the device ID, trailing NULL not included */
	rc = ddi_devid_init(xsp->xdfss_dip, DEVID_ATA_SERIAL, modlen + serlen,
	    hwid, (ddi_devid_t *)&xsp->xdfss_tgt_devid);
	if (rc != DDI_SUCCESS)
		goto err;

	kmem_free(hwid, CMDK_HWIDLEN);
	return (DDI_SUCCESS);

err:
	kmem_free(hwid, CMDK_HWIDLEN);
	return (DDI_FAILURE);
}

/*
 * xdfs_devid_read() is basically a local copy of
 * cmdk_devid_read() modified to work without the dadk layer.
 * (which the non-pv version of the cmdk driver uses.)
 *
 * Read a devid from on the first block of the last track of
 * the last cylinder.  Make sure what we read is a valid devid.
 * Return DDI_SUCCESS or DDI_FAILURE.
 */
static int
xdfs_devid_read(xdfs_state_t *xsp)
{
	diskaddr_t	blk;
	struct dk_devid *dkdevidp;
	uint_t		*ip, chksum;
	int		i;

	if (cmlb_get_devid_block(xsp->xdfss_cmlbhandle, &blk, 0) != 0)
		return (DDI_FAILURE);

	dkdevidp = kmem_zalloc(NBPSCTR, KM_SLEEP);
	if (xdfs_lb_rdwr(xsp->xdfss_dip,
	    TG_READ, dkdevidp, blk, NBPSCTR, NULL) != 0)
		goto err;

	/* Validate the revision */
	if ((dkdevidp->dkd_rev_hi != DK_DEVID_REV_MSB) ||
	    (dkdevidp->dkd_rev_lo != DK_DEVID_REV_LSB))
		goto err;

	/* Calculate the checksum */
	chksum = 0;
	ip = (uint_t *)dkdevidp;
	for (i = 0; i < ((NBPSCTR - sizeof (int))/sizeof (int)); i++)
		chksum ^= ip[i];
	if (DKD_GETCHKSUM(dkdevidp) != chksum)
		goto err;

	/* Validate the device id */
	if (ddi_devid_valid((ddi_devid_t)dkdevidp->dkd_devid) != DDI_SUCCESS)
		goto err;

	/* keep a copy of the device id */
	i = ddi_devid_sizeof((ddi_devid_t)dkdevidp->dkd_devid);
	xsp->xdfss_tgt_devid = kmem_alloc(i, KM_SLEEP);
	bcopy(dkdevidp->dkd_devid, xsp->xdfss_tgt_devid, i);
	kmem_free(dkdevidp, NBPSCTR);
	return (DDI_SUCCESS);

err:
	kmem_free(dkdevidp, NBPSCTR);
	return (DDI_FAILURE);
}

/*
 * xdfs_devid_fabricate() is basically a local copy of
 * cmdk_devid_fabricate() modified to work without the dadk layer.
 * (which the non-pv version of the cmdk driver uses.)
 *
 * Create a devid and write it on the first block of the last track of
 * the last cylinder.
 * Return DDI_SUCCESS or DDI_FAILURE.
 */
static int
xdfs_devid_fabricate(xdfs_state_t *xsp)
{
	ddi_devid_t	devid = NULL; /* devid made by ddi_devid_init  */
	struct dk_devid	*dkdevidp = NULL; /* devid struct stored on disk */
	diskaddr_t	blk;
	uint_t		*ip, chksum;
	int		i;

	if (cmlb_get_devid_block(xsp->xdfss_cmlbhandle, &blk, 0) != 0)
		return (DDI_FAILURE);

	if (ddi_devid_init(xsp->xdfss_dip, DEVID_FAB, 0, NULL, &devid) !=
	    DDI_SUCCESS)
		return (DDI_FAILURE);

	/* allocate a buffer */
	dkdevidp = (struct dk_devid *)kmem_zalloc(NBPSCTR, KM_SLEEP);

	/* Fill in the revision */
	dkdevidp->dkd_rev_hi = DK_DEVID_REV_MSB;
	dkdevidp->dkd_rev_lo = DK_DEVID_REV_LSB;

	/* Copy in the device id */
	i = ddi_devid_sizeof(devid);
	if (i > DK_DEVID_SIZE)
		goto err;
	bcopy(devid, dkdevidp->dkd_devid, i);

	/* Calculate the chksum */
	chksum = 0;
	ip = (uint_t *)dkdevidp;
	for (i = 0; i < ((NBPSCTR - sizeof (int))/sizeof (int)); i++)
		chksum ^= ip[i];

	/* Fill in the checksum */
	DKD_FORMCHKSUM(chksum, dkdevidp);

	if (xdfs_lb_rdwr(xsp->xdfss_dip,
	    TG_WRITE, dkdevidp, blk, NBPSCTR, NULL) != 0)
		goto err;

	kmem_free(dkdevidp, NBPSCTR);

	xsp->xdfss_tgt_devid = devid;
	return (DDI_SUCCESS);

err:
	if (dkdevidp != NULL)
		kmem_free(dkdevidp, NBPSCTR);
	if (devid != NULL)
		ddi_devid_free(devid);
	return (DDI_FAILURE);
}

/*
 * xdfs_rwcmd_copyin() is a duplicate of rwcmd_copyin().
 */
static int
xdfs_rwcmd_copyin(struct dadkio_rwcmd *rwcmdp, caddr_t inaddr, int flag)
{
	switch (ddi_model_convert_from(flag)) {
		case DDI_MODEL_ILP32: {
			struct dadkio_rwcmd32 cmd32;

			if (ddi_copyin(inaddr, &cmd32,
			    sizeof (struct dadkio_rwcmd32), flag)) {
				return (EFAULT);
			}

			rwcmdp->cmd = cmd32.cmd;
			rwcmdp->flags = cmd32.flags;
			rwcmdp->blkaddr = (blkaddr_t)cmd32.blkaddr;
			rwcmdp->buflen = cmd32.buflen;
			rwcmdp->bufaddr = (caddr_t)(intptr_t)cmd32.bufaddr;
			/*
			 * Note: we do not convert the 'status' field,
			 * as it should not contain valid data at this
			 * point.
			 */
			bzero(&rwcmdp->status, sizeof (rwcmdp->status));
			break;
		}
		case DDI_MODEL_NONE: {
			if (ddi_copyin(inaddr, rwcmdp,
			    sizeof (struct dadkio_rwcmd), flag)) {
				return (EFAULT);
			}
		}
	}
	return (0);
}

/*
 * xdfs_rwcmd_copyout() is a duplicate of rwcmd_copyout().
 */
static int
xdfs_rwcmd_copyout(struct dadkio_rwcmd *rwcmdp, caddr_t outaddr, int flag)
{
	switch (ddi_model_convert_from(flag)) {
		case DDI_MODEL_ILP32: {
			struct dadkio_rwcmd32 cmd32;

			cmd32.cmd = rwcmdp->cmd;
			cmd32.flags = rwcmdp->flags;
			cmd32.blkaddr = rwcmdp->blkaddr;
			cmd32.buflen = rwcmdp->buflen;
			ASSERT64(((uintptr_t)rwcmdp->bufaddr >> 32) == 0);
			cmd32.bufaddr = (caddr32_t)(uintptr_t)rwcmdp->bufaddr;

			cmd32.status.status = rwcmdp->status.status;
			cmd32.status.resid = rwcmdp->status.resid;
			cmd32.status.failed_blk_is_valid =
			    rwcmdp->status.failed_blk_is_valid;
			cmd32.status.failed_blk = rwcmdp->status.failed_blk;
			cmd32.status.fru_code_is_valid =
			    rwcmdp->status.fru_code_is_valid;
			cmd32.status.fru_code = rwcmdp->status.fru_code;

			bcopy(rwcmdp->status.add_error_info,
			    cmd32.status.add_error_info, DADKIO_ERROR_INFO_LEN);

			if (ddi_copyout(&cmd32, outaddr,
			    sizeof (struct dadkio_rwcmd32), flag))
				return (EFAULT);
			break;
		}
		case DDI_MODEL_NONE: {
			if (ddi_copyout(rwcmdp, outaddr,
			    sizeof (struct dadkio_rwcmd), flag))
			return (EFAULT);
		}
	}
	return (0);
}

static int
xdfs_dioctl_rwcmd(dev_t dev, intptr_t arg, int flag)
{
	struct dadkio_rwcmd	*rwcmdp;
	struct iovec		aiov;
	struct uio		auio;
	struct buf		*bp;
	int			rw, status;

	rwcmdp = kmem_alloc(sizeof (struct dadkio_rwcmd), KM_SLEEP);
	status = xdfs_rwcmd_copyin(rwcmdp, (caddr_t)arg, flag);

	if (status != 0)
		goto out;

	switch (rwcmdp->cmd) {
		case DADKIO_RWCMD_READ:
		case DADKIO_RWCMD_WRITE:
			break;
		default:
			status = EINVAL;
			goto out;
	}

	bzero((caddr_t)&aiov, sizeof (struct iovec));
	aiov.iov_base = rwcmdp->bufaddr;
	aiov.iov_len = rwcmdp->buflen;

	bzero((caddr_t)&auio, sizeof (struct uio));
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = (offset_t)rwcmdp->blkaddr * (offset_t)XB_BSIZE;
	auio.uio_resid = rwcmdp->buflen;
	auio.uio_segflg = (flag & FKIOCTL) ? UIO_SYSSPACE : UIO_USERSPACE;

	/*
	 * Tell the xdf driver that this I/O request is using an absolute
	 * offset.
	 */
	bp = getrbuf(KM_SLEEP);
	bp->b_private = (void *)XB_SLICE_NONE;

	rw = ((rwcmdp->cmd == DADKIO_RWCMD_WRITE) ? B_WRITE : B_READ);
	status = physio(xdfs_strategy, bp, dev, rw, xdfs_minphys, &auio);

	biofini(bp);
	kmem_free(bp, sizeof (buf_t));

	if (status == 0)
		status = xdfs_rwcmd_copyout(rwcmdp, (caddr_t)arg, flag);

out:
	kmem_free(rwcmdp, sizeof (struct dadkio_rwcmd));
	return (status);
}


/*
 * xdf_shell callback functions
 */
/*ARGSUSED*/
int
xdfs_c_ioctl(xdfs_state_t *xsp, dev_t dev, int part,
    int cmd, intptr_t arg, int flag, cred_t *credp, int *rvalp, boolean_t *done)
{
	*done = B_TRUE;
	switch (cmd) {
	default:
		*done = B_FALSE;
		return (0);
	case DKIOCLOCK:
	case DKIOCUNLOCK:
	case FDEJECT:
	case DKIOCEJECT:
	case CDROMEJECT: {
		/* we don't support ejectable devices */
		return (ENOTTY);
	}
	case DKIOCGETWCE:
	case DKIOCSETWCE: {
		/* we don't support write cache get/set */
		return (EIO);
	}
	case DKIOCADDBAD: {
		/*
		 * This is for ata/ide bad block handling.  It is supposed
		 * to cause the driver to re-read the bad block list and
		 * alternate map after it has been updated.  Our driver
		 * will refuse to attach to any disk which has a bad blocks
		 * list defined, so there really isn't much to do here.
		 */
		return (0);
	}
	case DKIOCGETDEF: {
		/*
		 * I can't actually find any code that utilizes this ioctl,
		 * hence we're leaving it explicitly unimplemented.
		 */
		ASSERT("ioctl cmd unsupported by xdf shell: DKIOCGETDEF");
		return (EIO);
	}
	case DIOCTL_RWCMD: {
		/*
		 * This just seems to just be an alternate interface for
		 * reading and writing the disk.  Great, another way to
		 * do the same thing...
		 */
		return (xdfs_dioctl_rwcmd(dev, arg, flag));
	}
	case DKIOCINFO: {
		int		instance = ddi_get_instance(xsp->xdfss_dip);
		dev_info_t	*dip = xsp->xdfss_dip;
		struct dk_cinfo	info;
		int		rv;

		/* Pass on the ioctl request, save the response */
		if ((rv = ldi_ioctl(xsp->xdfss_tgt_lh[part],
		    cmd, (intptr_t)&info, FKIOCTL, credp, rvalp)) != 0)
			return (rv);

		/* Update controller info */
		info.dki_cnum = ddi_get_instance(ddi_get_parent(dip));
		(void) strlcpy(info.dki_cname,
		    ddi_get_name(ddi_get_parent(dip)), sizeof (info.dki_cname));

		/* Update unit info. */
		if (info.dki_ctype == DKC_VBD)
			info.dki_ctype = DKC_DIRECT;
		info.dki_unit = instance;
		(void) strlcpy(info.dki_dname,
		    ddi_driver_name(dip), sizeof (info.dki_dname));
		info.dki_addr = 1;

		if (ddi_copyout(&info, (void *)arg, sizeof (info), flag))
			return (EFAULT);
		return (0);
	}
	} /* switch (cmd) */
	/*NOTREACHED*/
}

/*
 * xdfs_c_devid_setup() is a slightly modified copy of cmdk_devid_setup().
 *
 * Create and register the devid.
 * There are 4 different ways we can get a device id:
 *    1. Already have one - nothing to do
 *    2. Build one from the drive's model and serial numbers
 *    3. Read one from the disk (first sector of last track)
 *    4. Fabricate one and write it on the disk.
 * If any of these succeeds, register the deviceid
 */
void
xdfs_c_devid_setup(xdfs_state_t *xsp)
{
	int	rc;

	/* Try options until one succeeds, or all have failed */

	/* 1. All done if already registered */

	if (xsp->xdfss_tgt_devid != NULL)
		return;

	/* 2. Build a devid from the model and serial number */
	rc = xdfs_devid_modser(xsp);
	if (rc != DDI_SUCCESS) {
		/* 3. Read devid from the disk, if present */
		rc = xdfs_devid_read(xsp);

		/* 4. otherwise make one up and write it on the disk */
		if (rc != DDI_SUCCESS)
			rc = xdfs_devid_fabricate(xsp);
	}

	/* If we managed to get a devid any of the above ways, register it */
	if (rc == DDI_SUCCESS)
		(void) ddi_devid_register(xsp->xdfss_dip, xsp->xdfss_tgt_devid);
}

int
xdfs_c_getpgeom(dev_info_t *dip, cmlb_geom_t *pgeom)
{
	struct scsi_device	*scsi_device;
	struct tgdk_geom	tgdk_geom;
	opaque_t		ctlobjp;
	int			err;

	scsi_device = ddi_get_driver_private(dip);
	ctlobjp = scsi_device->sd_address.a_hba_tran;
	if ((err = CTL_IOCTL(ctlobjp,
	    DIOCTL_GETPHYGEOM, (uintptr_t)&tgdk_geom, FKIOCTL)) != 0)
		return (err);

	/* This driver won't work if this isn't true */
	ASSERT(tgdk_geom.g_secsiz == XB_BSIZE);

	pgeom->g_ncyl = tgdk_geom.g_cyl;
	pgeom->g_acyl = tgdk_geom.g_acyl;
	pgeom->g_nhead = tgdk_geom.g_head;
	pgeom->g_nsect = tgdk_geom.g_sec;
	pgeom->g_secsize = tgdk_geom.g_secsiz;
	pgeom->g_capacity = tgdk_geom.g_cap;
	pgeom->g_intrlv = 1;
	pgeom->g_rpm = 3600;
	return (0);
}

boolean_t
xdfs_c_bb_check(xdfs_state_t *xsp)
{
	struct alts_parttbl	*ap;
	diskaddr_t		nblocks, blk;
	uint32_t		altused, altbase, altlast;
	uint16_t		vtoctag;
	int			alts;

	/* find slice with V_ALTSCTR tag */
	for (alts = 0; alts < NDKMAP; alts++) {

		if (cmlb_partinfo(xsp->xdfss_cmlbhandle, alts,
		    &nblocks, &blk, NULL, &vtoctag, 0) != 0) {
			/* no partition table exists */
			return (B_FALSE);
		}

		if ((vtoctag == V_ALTSCTR) && (nblocks > 1))
			break;
	}
	if (alts >= NDKMAP)
		return (B_FALSE); /* no V_ALTSCTR slice defined */

	/* read in ALTS label block */
	ap = (struct alts_parttbl *)kmem_zalloc(NBPSCTR, KM_SLEEP);
	if (xdfs_lb_rdwr(xsp->xdfss_dip, TG_READ, ap, blk, NBPSCTR, NULL) != 0)
		goto err;

	altused = ap->alts_ent_used;	/* number of BB entries */
	altbase = ap->alts_ent_base;	/* blk offset from begin slice */
	altlast = ap->alts_ent_end;	/* blk offset to last block */

	if ((altused == 0) || (altbase < 1) ||
	    (altbase > altlast) || (altlast >= nblocks))
		goto err;

	/* we found bad block mappins */
	kmem_free(ap, NBPSCTR);
	return (B_TRUE);

err:
	kmem_free(ap, NBPSCTR);
	return (B_FALSE);
}

char *
xdfs_c_cmlb_node_type(xdfs_state_t *xsp)
{
	return (xsp->xdfss_tgt_is_cd ? DDI_NT_CD : DDI_NT_BLOCK);
}

/*ARGSUSED*/
int
xdfs_c_cmlb_alter_behavior(xdfs_state_t *xsp)
{
	return (xsp->xdfss_tgt_is_cd ?
	    0 : CMLB_CREATE_ALTSLICE_VTOC_16_DTYPE_DIRECT);
}

/*ARGSUSED*/
void
xdfs_c_attach(xdfs_state_t *xsp)
{
}
