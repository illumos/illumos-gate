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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/varargs.h>
#include <sys/fs/pc_label.h>

#include <sys/hdio.h>
#include <sys/dkio.h>
#include <sys/dktp/dadkio.h>

#include <sys/dklabel.h>

#include <sys/vtoc.h>


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dktp/cm.h>

#include <sys/dktp/fdisk.h>

#include <sys/pccard.h>
#include <sys/pcmcia/pcata.h>

#define	MIN_SEC_SIZE	512

static int pcata_redo_vtoc(ata_soft_t *softp, buf_t *fdiskbp);
static buf_t *pcata_lblk_alloc(dev_t dev);

/* Check media insertion/ejection status */
static int pcata_check_media(ata_soft_t *rs, enum dkio_state state);

/*
 * Queue a request and call start routine.
 *
 * If the request is not a special buffer request,
 * do validation on it and generate both an absolute
 * block number (which we will leave in b_resid),
 * and a actual block count value (which we will
 * leave in av_back).
 */

int
pcata_strategy(buf_t *bp)
{
	ata_soft_t	*softp;
	ata_unit_t	*unitp;
	void		*instance;
	daddr_t		blkno;
	int		part;
	int		ret;

#ifdef ATA_DEBUG
	if (pcata_debug & DIO)
		cmn_err(CE_CONT, "_strategy\n");
#endif
	bp->b_resid = bp->b_bcount;

	if (pcata_getinfo(NULL, DDI_INFO_DEVT2INSTANCE, (void *)bp->b_edev,
	    &instance) != DDI_SUCCESS) {
		cmn_err(CE_CONT, "_strategy: pcata_getinfo ENODEV\n");
		bioerror(bp, ENODEV);
		biodone(bp);
		return (0);
	}

	if (!(softp = ddi_get_soft_state(pcata_soft,
	    (int)(uintptr_t)instance))) {
		bioerror(bp, ENXIO);
		biodone(bp);
		return (0);
	}

	if (!(CARD_PRESENT_VALID(softp))) {
#ifdef ATA_DEBUG
		if (pcata_debug & DIO)
			cmn_err(CE_CONT, "_strategy card_state = %d bp=%p\n",
				softp->card_state,
				(void *)bp);
#endif
		bioerror(bp, ENXIO);
		biodone(bp);
		return (0);
	}

	if (bp->b_bcount & (NBPSCTR-1)) {
		bioerror(bp, ENXIO);
		biodone(bp);
		return (0);
	}

#ifdef	ATA_DEBUG
	if (pcata_debug & DIO) {
		cmn_err(CE_CONT, "_strategy: bp->b_private = %p\n",
			(void *)bp->b_private);
		cmn_err(CE_CONT, "_strategy %s request for buf: %p\n",
			bp->b_flags & B_READ ? "read" : "write", (void *)bp);
	}
#endif

	mutex_enter(&softp->ata_mutex);

	/*
	 * pointer to structure for physical drive
	 */
	/*
	 * XXX/lcl since we don't traverse a_forw with some bits from minor
	 * (aka the UNIT macro) this means only 1 physical disk
	 * this error occurs everywhere ab_link is used!
	 */
	unitp = softp->ab_link;
	if (!unitp) {
		mutex_exit(&softp->ata_mutex);
		bioerror(bp, ENXIO);
		biodone(bp);
		return (0);
	}

	/*
	 * A normal read/write command.
	 *
	 * If the transfer size would take it past the end of the
	 * partition, trim it down. Also trim it down to a multiple
	 * of the block size.
	 */
	bp->b_flags &= ~(B_DONE|B_ERROR);
	bp->av_forw = NULL;
	blkno = bp->b_blkno;
	part = LPART(bp->b_edev);


	/*
	 * Map block number within partition to absolute
	 * block number.
	 */
#ifdef ATA_DEBUG
	if (pcata_debug & DIO)
		cmn_err(CE_CONT, "_strategy  "
			"%c%d: %s block %ld mapped to %ld dev %lx\n",
			(part > 15 ? 'p' : 's'),
			(part > 15 ? part - 16 : part),
			bp->b_flags & B_READ ? "read" : "write",
			blkno,
			blkno + unitp->lbl.pmap[part].p_start,
			bp->b_edev);
#endif

	/* make sure this partition exists */
	if (unitp->lbl.pmap[part].p_size == 0) {
#ifdef ATA_DEBUG
		cmn_err(CE_CONT, "_strategy:invalid slice part=%d\n", part);
#endif
		mutex_exit(&softp->ata_mutex);
		bioerror(bp, ENXIO);
		biodone(bp);
		return (0);
	}

	/* make sure the I/O begins at a block within the partition */
	if (blkno < 0 || blkno >= unitp->lbl.pmap[part].p_size) {
#ifdef ATA_DEBUG
		cmn_err(CE_CONT, "_strategy:block number out of range\n");
#endif
		mutex_exit(&softp->ata_mutex);
		bioerror(bp, ENXIO);
		biodone(bp);
		return (0);
	}

	/* XXX/lcl check to make sure I/O doesn't go past end of partition */

	/* put block number into b_resid and number of blocks into av_back */
	bp->b_resid = bp->b_bcount;
	bp->av_back = (buf_t *)(ROUNDUP(bp->b_bcount, NBPSCTR) >> SCTRSHFT);

	blkno += unitp->lbl.pmap[part].p_start;

	ret = pcata_start(unitp, bp, blkno);
	mutex_exit(&softp->ata_mutex);

	if (ret != CTL_SEND_SUCCESS) {
		bp->b_resid = bp->b_bcount;
#ifdef ATA_DEBUG
		cmn_err(CE_CONT, "_strategy: ata_start failed bp 0x%p\n",
			(void *)bp);
#endif
		bioerror(bp, EIO);
		biodone(bp);
		return (0);
	}

	/*
	 * If the disk block to be written to is disk block 0, it would
	 * mean the partition table is changing from underneath us
	 * we shoud trap and update the in memory image.
	 * By now the buffer is mapped in and we should be able to
	 * use the contents as the new fdisk partition.
	 */
	if ((bp->b_flags & B_WRITE) && ((bp->b_flags & B_ERROR) != B_ERROR) &&
		blkno == 0) {
		if (pcata_redo_vtoc(softp, bp)) {
			bioerror(bp, EFAULT);
			biodone(bp);
			return (0);
		}
	}

	return (0);
}

/*
 * This routine implements the ioctl calls for the ATA
 */
#define	COPYOUT(a, b, c, f)	\
	ddi_copyout((caddr_t)(a), (caddr_t)(b), sizeof (c), f)
#define	COPYIN(a, b, c, f)	\
	ddi_copyin((caddr_t)(a), (caddr_t)(b), sizeof (c), f)

/* ARGSUSED3 */
int
pcata_ioctl(
	dev_t dev,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cred_p,
	int *rval_p)
{
	uint32_t	data[512 / (sizeof (uint32_t))];
	void		*instance;
	ata_soft_t	*softp;
	ata_unit_t	*unitp;
	struct dk_cinfo *info;
	int		i, status;
	int		err;
	enum dkio_state	state;

#ifdef ATA_DEBUG
	if (pcata_debug & DIO) cmn_err(CE_CONT, "_ioctl\n");
#endif
	if (pcata_getinfo(NULL, DDI_INFO_DEVT2INSTANCE, (void *)dev,
	    &instance) != DDI_SUCCESS)
		return (ENODEV);

	if (!(softp = ddi_get_soft_state(pcata_soft,
	    (int)(uintptr_t)instance))) {
		return (ENXIO);
	}


#ifdef ATA_DEBUG
	if (pcata_debug & DENT) {
		char    *cmdname;

		switch (cmd) {
		case DKIOCINFO:		cmdname = "DKIOCINFO       "; break;
		case DKIOCREMOVABLE:	cmdname = "DKIOCREMOVABLE  "; break;
		case DKIOCGMEDIAINFO:   cmdname = "DKIOCGMEDIAINFO "; break;
		case DKIOCGGEOM:	cmdname = "DKIOCGGEOM      "; break;
		case DKIOCGAPART:	cmdname = "DKIOCGAPART     "; break;
		case DKIOCSAPART:	cmdname = "DKIOCSAPART     "; break;
		case DKIOCGVTOC:	cmdname = "DKIOCGVTOC      "; break;
		case DKIOCSVTOC:	cmdname = "DKIOCSVTOC      "; break;
		case DKIOCG_VIRTGEOM:	cmdname = "DKIOCG_VIRTGEOM "; break;
		case DKIOCG_PHYGEOM:	cmdname = "DKIOCG_PHYGEOM  "; break;
		case DKIOCEJECT:	cmdname = "DKIOCEJECT     *"; break;
		case DKIOCSGEOM:	cmdname = "DKIOCSGEOM     *"; break;
		case DKIOCSTATE:	cmdname = "DKIOCSTATE     *"; break;
		case DKIOCADDBAD:	cmdname = "DKIOCADDBAD    *"; break;
		case DKIOCGETDEF:	cmdname = "DKIOCGETDEF    *"; break;
		case DKIOCPARTINFO:	cmdname = "DKIOCPARTINFO  *"; break;
		case DIOCTL_RWCMD:	cmdname = "DIOCTL_RWCMD    "; break;
		default:		cmdname = "UNKNOWN        *"; break;
		}
		cmn_err(CE_CONT,
			"_ioctl%d: cmd %x(%s) arg %p softp %p\n",
			(int)(uintptr_t)instance, cmd, cmdname, (void *)arg,
			(void *)softp);
	}
#endif

	/*
	 * We should process DKIOCSTATE cmd even if CARD is not PRESENT.
	 * The DKIOCSTATE command should BLOCK if there is no change in state.
	 * Only when softp->state != state the control returns to the caller.
	 * This check is done in pcata_check_media().
	 * There are 3 states for the device.
	 *	DKIO_NONE
	 *	DKIO_INSERTED
	 *	DKIO_EJECTED
	 * The state transitions are as follows
	 * DKIO_NONE-DKIO_INSERTED-DKIO_EJECTED-DKIO_NONE-DKIO_INSERTED...
	 */
	if (cmd == DKIOCSTATE) {
		if (ddi_copyin((caddr_t)arg, (caddr_t)&state,
		    sizeof (state), flag)) {
			return (EFAULT);
		}

		/*
		 * This function is used by the volume management
		 * to check the pcata card state
		 */
		if (err = pcata_check_media(softp, state)) {
			return (err);
		}

		if (ddi_copyout((caddr_t)&softp->media_state,
			(caddr_t)arg, sizeof (softp->media_state), flag)) {
			return (EFAULT);
		}
		return (0);
	}

	if (!(CARD_PRESENT_VALID(softp))) {
		return (ENODEV);
	}


	/*
	 * we can respond to get geom ioctl() only while the driver has
	 * not completed initialization.
	 */
	if ((softp->flags & PCATA_READY) == 0 && cmd != DKIOCG_PHYGEOM) {
		(void) pcata_readywait(softp);
		if (!(softp->flags & PCATA_READY))
			return (EFAULT);
	}

	ASSERT(softp->ab_link);
	unitp = softp->ab_link;
	bzero((caddr_t)data, sizeof (data));

	switch (cmd) {
	case DKIOCGGEOM:
	case DKIOCSGEOM:
	case DKIOCGAPART:
	case DKIOCSAPART:
	case DKIOCGVTOC:
	case DKIOCSVTOC:
		status = 0;
		mutex_enter(&softp->label_mutex);
		status = pcata_lbl_ioctl(dev, cmd, arg, flag);
		mutex_exit(&softp->label_mutex);
		return (status);
	}

	switch (cmd) {

	case DKIOCINFO:

		info = (struct dk_cinfo *)data;
		/*
		 * Controller Information
		 */
		info->dki_ctype = DKC_PCMCIA_ATA;
		info->dki_cnum = ddi_get_instance(softp->dip);
		(void) strcpy(info->dki_cname,
		    ddi_get_name(ddi_get_parent(softp->dip)));

		/*
		 * Unit Information
		 */
		info->dki_unit = ddi_get_instance(softp->dip);
		info->dki_slave = 0;
		(void) strcpy(info->dki_dname, "card");
		info->dki_flags = DKI_FMTVOL;
		info->dki_partition = LPART(dev);
		info->dki_maxtransfer = softp->ab_max_transfer;

		/*
		 * We can't get from here to there yet
		 */
		info->dki_addr = 0;
		info->dki_space = 0;
		info->dki_prio = 0;
		info->dki_vec = 0;

		if (COPYOUT(data, arg, struct dk_cinfo, flag))
			return (EFAULT);
		break;

	case DKIOCG_VIRTGEOM:
	case DKIOCG_PHYGEOM:

		{
		struct dk_geom dkg;
		status = 0;

		bzero((caddr_t)&dkg, sizeof (struct dk_geom));
		mutex_enter(&softp->ata_mutex);
		unitp = softp->ab_link;
		if (unitp != 0) {
			dkg.dkg_ncyl  	= unitp->au_cyl;
			dkg.dkg_acyl  	= unitp->au_acyl;
			dkg.dkg_pcyl  	= unitp->au_cyl+unitp->au_acyl;
			dkg.dkg_nhead 	= unitp->au_hd;
			dkg.dkg_nsect 	= unitp->au_sec;
		} else
			status = EFAULT;
		mutex_exit(&softp->ata_mutex);
		if (status)
			return (EFAULT);

		if (ddi_copyout((caddr_t)&dkg, (caddr_t)arg,
		    sizeof (struct dk_geom), flag))
			return (EFAULT);
		else
			return (0);
		}

	case DKIOCGMEDIAINFO:

		{
		struct dk_minfo media_info;
		int	secsize;

		media_info.dki_media_type = DK_FIXED_DISK;
		/*
		 * atarp_secsize contains the unformatted sector size.
		 * Using this we determine the actual sector size.
		 * sector sizes are a multiple of MIN_SEC_SIZE(512).
		 */
		secsize = softp->ab_rpbp[0]->atarp_secsiz;
		secsize = (((secsize)/MIN_SEC_SIZE) * MIN_SEC_SIZE);
		media_info.dki_lbsize = secsize;
		media_info.dki_capacity = unitp->au_cyl * unitp->au_hd *
		    unitp->au_sec;
		if (ddi_copyout((caddr_t)&media_info, (caddr_t)arg,
		    sizeof (struct dk_minfo), flag))
			return (EFAULT);
		else
			return (0);
		}

	case DKIOCREMOVABLE:

		{
		/*
		 * Supporting volmgt by returning a constant
		 *	since PCMCIA is a removable media.
		 *	Refer to PSARC/1996/004.
		 */
		i = 1;
		if (ddi_copyout((caddr_t)&i, (caddr_t)arg, sizeof (int),
		    flag)) {
			return (EFAULT);
		}
		break;
		}

	case DIOCTL_RWCMD:
		{
		int	rw;
		int	status;
		struct dadkio_rwcmd	rwcmd;
		struct buf		*bp;
		struct iovec		aiov;
		struct uio		auio;

#if defined(_MULTI_DATAMODEL)
		switch (ddi_model_convert_from(flag & FMODELS)) {

		case DDI_MODEL_ILP32: {
			struct dadkio_rwcmd32	rwcmd32;

			if (ddi_copyin((caddr_t)arg, (caddr_t)&rwcmd32,
				sizeof (struct dadkio_rwcmd32), flag)) {
				return (EFAULT);
			}
			rwcmd.cmd = rwcmd32.cmd;
			rwcmd.flags = rwcmd32.flags;
			rwcmd.blkaddr = (daddr_t)rwcmd32.blkaddr;
			rwcmd.buflen = rwcmd32.buflen;
			rwcmd.bufaddr = (caddr_t)(uintptr_t)rwcmd32.bufaddr;
			break;
		}

		case DDI_MODEL_NONE:
			if (ddi_copyin((caddr_t)arg, (caddr_t)&rwcmd,
				sizeof (struct dadkio_rwcmd), flag)) {
				return (EFAULT);
			}
			break;
		}
#else	/*  _MULTI_DATAMODEL */
		if (ddi_copyin((caddr_t)arg, (caddr_t)&rwcmd,
			sizeof (struct dadkio_rwcmd), flag)) {
			return (EFAULT);
		}
#endif	/*  _MULTI_DATAMODEL */

		switch (rwcmd.cmd) {
		case DADKIO_RWCMD_READ:
			rw = B_READ;
			break;
		case DADKIO_RWCMD_WRITE:
			rw = B_WRITE;
			break;
		default:
			return (EINVAL);
		}

		bp		= getrbuf(KM_SLEEP);
		bp->b_back	= (buf_t *)&rwcmd;	/* ioctl packet */
		bp->b_private	= (void *)0xBEE;

		bzero((caddr_t)&aiov, sizeof (struct iovec));
		aiov.iov_base	= rwcmd.bufaddr;
		aiov.iov_len	= rwcmd.buflen;

		bzero((caddr_t)&auio, sizeof (struct uio));
		auio.uio_iov	= &aiov;
		auio.uio_iovcnt	= 1;
		auio.uio_resid	= rwcmd.buflen;
		auio.uio_segflg	= flag & FKIOCTL ? UIO_SYSSPACE : UIO_USERSPACE;

		status = physio(pcata_strategy, bp, dev, rw, pcata_min, &auio);

		freerbuf(bp);

		return (status);
		}

	case DKIOCEJECT:
		/*
		 * Since we do not have hardware support for ejecting
		 * a pcata card, we must not support the generic eject
		 * ioctl (DKIOCEJECT) which is used for eject(1) command
		 * because it leads the user to expect behavior that is
		 * not present.
		 */
		return (ENOSYS);

	case HDKIOCSCMD:
	case HDKIOCGDIAG:
		break;
	default:
		return (ENOTTY);
	}
	return (0);
}

int
pcata_lbl_ioctl(dev_t dev, int cmd, intptr_t arg, int flag)
{
	uint32_t data[512 / (sizeof (uint32_t))];
	void *instance;
	ata_soft_t *softp;
	ata_unit_t *unitp;
	int i;
	struct vtoc vtoc;

	if (pcata_getinfo(NULL, DDI_INFO_DEVT2INSTANCE, (void *)dev,
	    &instance) != DDI_SUCCESS)
		return (ENODEV);

	if (!(softp = ddi_get_soft_state(pcata_soft,
	    (int)(uintptr_t)instance))) {
		return (ENXIO);
	}

	if (!(CARD_PRESENT_VALID(softp))) {
		return (ENODEV);
	}

	ASSERT(softp->ab_link);
	bzero((caddr_t)data, sizeof (data));
	unitp    = softp->ab_link;

	switch (cmd) {
	case DKIOCGGEOM:
	case DKIOCGAPART:
	case DKIOCGVTOC:
		if (pcata_update_vtoc(softp, dev))
			return (EFAULT);
	}

	switch (cmd) {
	case DKIOCGGEOM:
		{
		struct dk_geom up;

		pcdsklbl_dgtoug(&up, &unitp->lbl.ondsklbl);
		if (COPYOUT(&up, arg, struct dk_geom, flag)) {
			return (EFAULT);
		}
		break;
		}

	case DKIOCSGEOM:
		i = sizeof (struct dk_geom);
		if (ddi_copyin((caddr_t)arg, (caddr_t)data, i, flag))
			return (EFAULT);
		pcdsklbl_ugtodg((struct dk_geom *)data, &unitp->lbl.ondsklbl);
		break;

	case DKIOCGAPART:
		/*
		 * Return the map for all logical partitions.
		 */
#if defined(_MULTI_DATAMODEL)
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct dk_map32 dk_map32[NDKMAP];
			int	i;

			for (i = 0; i < NDKMAP; i++) {
				dk_map32[i].dkl_cylno =
					unitp->lbl.un_map[i].dkl_cylno;
				dk_map32[i].dkl_nblk =
					unitp->lbl.un_map[i].dkl_nblk;
			}
			i = NDKMAP * sizeof (struct dk_map32);
			if (ddi_copyout(dk_map32, (caddr_t)arg, i, flag))
				return (EFAULT);
			break;
		}

		case DDI_MODEL_NONE:
			i = NDKMAP * sizeof (struct dk_map);
			if (ddi_copyout((caddr_t)unitp->lbl.un_map,
			    (caddr_t)arg, i, flag))
				return (EFAULT);
			break;
		}

#else	/*  _MULTI_DATAMODEL */
		i = NDKMAP * sizeof (struct dk_map);
		if (ddi_copyout((caddr_t)unitp->lbl.un_map,
		    (caddr_t)arg, i, flag))
			return (EFAULT);
#endif	/*  _MULTI_DATAMODEL */
		break;

	case DKIOCSAPART:
		/*
		 * Set the map for all logical partitions.
		 */
#if defined(_MULTI_DATAMODEL)
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct dk_map32 dk_map32[NDKMAP];
			int	i;

			i = NDKMAP * sizeof (struct dk_map32);
			if (ddi_copyin((caddr_t)arg, dk_map32, i, flag))
				return (EFAULT);
			for (i = 0; i < NDKMAP; i++) {
				unitp->lbl.un_map[i].dkl_cylno =
					dk_map32[i].dkl_cylno;
				unitp->lbl.un_map[i].dkl_nblk =
					dk_map32[i].dkl_nblk;
			}
			i = NDKMAP * sizeof (struct dk_map32);
			break;
		}

		case DDI_MODEL_NONE:
			i = NDKMAP * sizeof (struct dk_map);
			if (ddi_copyout((caddr_t)unitp->lbl.un_map,
			    (caddr_t)arg, i, flag))
				return (EFAULT);
			break;
		}
		break;
#else	/*  _MULTI_DATAMODEL */
		i = NDKMAP * sizeof (struct dk_map);
		if (ddi_copyin((caddr_t)arg, (caddr_t)data, i, flag))
			return (EFAULT);
		bcopy((caddr_t)data, (caddr_t)unitp->lbl.un_map, i);
		break;
#endif	/*  _MULTI_DATAMODEL */

	case DKIOCGVTOC:
#if defined(_MULTI_DATAMODEL)
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct vtoc32 vtoc32;

			pcdsklbl_ondsklabel_to_vtoc(&unitp->lbl, &vtoc);
			vtoctovtoc32(vtoc, vtoc32);
			if (ddi_copyout(&vtoc32, (caddr_t)arg,
			    sizeof (struct vtoc32), flag))
				return (EFAULT);
			break;
		}

		case DDI_MODEL_NONE:
			pcdsklbl_ondsklabel_to_vtoc(&unitp->lbl, &vtoc);
			if (ddi_copyout((caddr_t)&vtoc, (caddr_t)arg,
			    sizeof (struct vtoc), flag))
				return (EFAULT);
			break;
		}
		return (0);
#else	/*  _MULTI_DATAMODEL */
		pcdsklbl_ondsklabel_to_vtoc(&unitp->lbl, &vtoc);
		if (ddi_copyout((caddr_t)&vtoc, (caddr_t)arg,
		    sizeof (struct vtoc), flag))
			return (EFAULT);
		return (0);
#endif	/*  _MULTI_DATAMODEL */

	case DKIOCSVTOC:
#if defined(_MULTI_DATAMODEL)
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct vtoc32 vtoc32;

			if (ddi_copyin((caddr_t)arg, &vtoc32,
			    sizeof (struct vtoc32), flag))
				return (EFAULT);
			vtoc32tovtoc(vtoc32, vtoc);

			if (pcata_write_dskvtoc(softp, dev, &unitp->lbl, &vtoc))
				return (EFAULT);
			break;
		}

		case DDI_MODEL_NONE:
			if (ddi_copyin((caddr_t)arg, (caddr_t)&vtoc,
			    sizeof (struct vtoc), flag))
				return (EFAULT);

			if (pcata_write_dskvtoc(softp, dev, &unitp->lbl, &vtoc))
				return (EFAULT);

			break;
		}
#else	/*  _MULTI_DATAMODEL */
		if (ddi_copyin((caddr_t)arg, (caddr_t)&vtoc,
		    sizeof (struct vtoc), flag))
			return (EFAULT);

		if (pcata_write_dskvtoc(softp, dev, &unitp->lbl, &vtoc))
			return (EFAULT);

		break;
#endif	/*  _MULTI_DATAMODEL */
	}
	return (0);
}

/* ARGSUSED */
int
pcata_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	register dev_t dev = *dev_p;
	ata_soft_t *softp;
	void	*instance;
	int	i;

#ifdef ATA_DEBUG
	if (pcata_debug & DIO)
		cmn_err(CE_CONT, "_open: "
		    "dev_p=%p dev=%x flag=%x otyp=%x cred_p=%p\n",
		    (void *)dev_p, (int)dev, flag, otyp, (void *)cred_p);
#endif
	if (pcata_getinfo(NULL, DDI_INFO_DEVT2INSTANCE, (void *) *dev_p,
	    &instance) != DDI_SUCCESS)
		return (ENODEV);

	softp = ddi_get_soft_state(pcata_soft, (int)(uintptr_t)instance);

	/*
	 * open and getinfo may be called before attach completes
	 */
	for (i = 0; i < 300; i++) {
		if (softp->flags & PCATA_READY)
			break;
		drv_usecwait(10000);
	}
	if (!pcata_readywait(softp))
		return (ENXIO);

#ifdef ATA_DEBUG
	if (pcata_debug & DIO)
		cmn_err(CE_CONT,
		    "_open: part=%d blk_open=%x chr_open=%x lyr_open=%d\n",
		    LPART(dev), softp->blk_open, softp->chr_open,
		    softp->lyr_open[LPART(dev)]);
#endif

	mutex_enter(&(softp)->ata_mutex);
	/*
	 * Only honor FEXCL.  If a regular open or a layered open
	 * is still outstanding on the device, the exclusive open
	 * must fail.
	 */
	if (flag & FEXCL) {
		if ((softp->chr_open & (1 << LPART(dev))) ||
		    (softp->blk_open & (1 << LPART(dev))) ||
		    (softp->lyr_open[LPART(dev)])) {
			mutex_exit(&(softp)->ata_mutex);
			return (EAGAIN);
		}
	}

	switch (otyp) {
		case OTYP_BLK:
			softp->blk_open |= (1 << LPART(dev));
			break;
		case OTYP_CHR:
			softp->chr_open |= (1 << LPART(dev));
			break;
		case OTYP_LYR:
			softp->lyr_open[LPART(dev)]++;
			break;
		default:
			mutex_exit(&(softp)->ata_mutex);
			return (EINVAL);
	}

	mutex_exit(&(softp)->ata_mutex);

	return (0);
}



/* ARGSUSED */
int
pcata_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	ata_soft_t *softp;
	int	i;
	int	lyr_count = 0;
	void	*instance;

#ifdef ATA_DEBUG
	if (pcata_debug & DIO)
		cmn_err(CE_CONT, "_close: dev=%x flag=%x otyp=%x cred_p=%p\n",
		    (int)dev, flag, otyp, (void *)cred_p);
#endif

	if (pcata_getinfo(NULL, DDI_INFO_DEVT2INSTANCE, (void *) dev,
	    &instance) != DDI_SUCCESS)
		return (ENODEV);

	softp = ddi_get_soft_state(pcata_soft, (int)(uintptr_t)instance);

#ifdef ATA_DEBUG
	if (pcata_debug & DIO)
		cmn_err(CE_CONT,
		    "_close: part=%d blk_open=%x chr_open=%x lyr_open=%d\n",
		    LPART(dev), softp->blk_open, softp->chr_open,
		    softp->lyr_open[LPART(dev)]);
#endif


	mutex_enter(&(softp)->ata_mutex);

	switch (otyp) {
		case OTYP_BLK:
			softp->blk_open &= ~(1 << LPART(dev));
			break;
		case OTYP_CHR:
			softp->chr_open &= ~(1 << LPART(dev));
			break;
		case OTYP_LYR:
			softp->lyr_open[LPART(dev)]--;
			break;
			default:
			mutex_exit(&(softp)->ata_mutex);
			return (EINVAL);
	}

	if ((softp->blk_open) || (softp->chr_open)) {
		/* not done yet */
		mutex_exit(&(softp)->ata_mutex);
		return (0);
	} else {
		for (i = 0; i < LPART(dev); i++) {
			if (softp->lyr_open[LPART(dev)] != 0)
				lyr_count++;
		}

		if (lyr_count) {
			/* not done yet */
			mutex_exit(&(softp)->ata_mutex);
			return (0);
		}
	}

	if (softp->ejected_while_mounted)
		softp->ejected_while_mounted = 0;

	mutex_exit(&(softp)->ata_mutex);

	return (0);
}

static int
pcata_redo_vtoc(ata_soft_t *softp, buf_t *fdiskbp)
{
	struct dk_geom	dkg;
	ata_unit_t	*unitp;
	buf_t		*bp;
	int		status;
	dev_t		dev;


	unitp = softp->ab_link;
	if (!unitp)
		return (EFAULT);

	/* given any maj/min convert to fdisk partition 0 */
	dev = makedevice(getmajor(fdiskbp->b_edev),
		PCATA_SETMINOR(softp->sn, FDISK_OFFSET));

	if ((bp = pcata_lblk_alloc(dev)) == NULL)
		return (EFAULT);

	bcopy(fdiskbp->b_un.b_addr, bp->b_un.b_addr, NBPSCTR);

	bzero((caddr_t)&dkg, sizeof (struct dk_geom));
	dkg.dkg_ncyl  	= unitp->au_cyl;
	dkg.dkg_nhead 	= unitp->au_hd;
	dkg.dkg_nsect 	= unitp->au_sec;

	status = pcfdisk_parse(bp, unitp);

	/* release buffer allocated by getrbuf */
	kmem_free(bp->b_un.b_addr, NBPSCTR);
	freerbuf(bp);

	if (status == DDI_FAILURE)
		return (EFAULT);
	return (0);
}

/*
 *
 */
int
pcata_update_vtoc(ata_soft_t *softp, dev_t dev)
{
	ata_unit_t	*unitp;
	buf_t		*bp;
	int		status;

	unitp = softp->ab_link;
	if (!unitp)
		return (EFAULT);

	/* given any maj/min convert to fdisk partition 0 */
	dev = makedevice(getmajor(dev),
		PCATA_SETMINOR(softp->sn, FDISK_OFFSET));

	if ((bp = pcata_lblk_alloc(dev)) == NULL)
		return (EFAULT);

	/*
	 * The dev is passed here for use later by the dsklbl_rdvtoc()
	 * and pcata_dsklbl_read_label() to check for card present before
	 * calling biowait.
	 */
	status = pcfdisk_read(bp, unitp);

	/* release buffer allocated by getrbuf */
	kmem_free(bp->b_un.b_addr, NBPSCTR);
	freerbuf(bp);

	if (status == DDI_FAILURE)
		return (EFAULT);
	return (0);
}

static buf_t *
pcata_lblk_alloc(dev_t dev)
{
	buf_t *bp;
	char	*secbuf;

	/* allocate memory to hold disk label */
	secbuf = kmem_zalloc(NBPSCTR, KM_SLEEP);
	if (!secbuf)
		return (NULL);

	/* allocate a buf_t to manage the disk label block */
	bp = getrbuf(KM_SLEEP);
	if (!bp) {
		kmem_free(secbuf, NBPSCTR);
		return (NULL);
	}

	/* initialize the buf_t */
	bp->b_edev = dev;
	bp->b_dev  = cmpdev(dev);
	bp->b_flags |= B_BUSY;
	bp->b_resid = 0;
	bp->b_bcount = NBPSCTR;
	bp->b_un.b_addr = (caddr_t)secbuf;

	return (bp);
}


int
pcata_write_dskvtoc(ata_soft_t *softp, dev_t dev, dsk_label_t *lblp,
		struct vtoc *vtocp)
{
	buf_t *bp;
	int	status;

	dev = makedevice(getmajor(dev),
		PCATA_SETMINOR(softp->sn, FDISK_OFFSET));

	if ((bp = pcata_lblk_alloc(dev)) == NULL)
		return (EFAULT);

#ifdef ATA_DEBUG
	cmn_err(CE_CONT, "_write_dskvtoc: edev = %lx dev = %x\n",
		bp->b_edev,
		bp->b_dev);
#endif


	bp->b_edev = dev; /* used by probe_for_card() */
	status = pcdsklbl_wrvtoc(lblp, vtocp, bp);

	/* release buffer allocated by getrbuf */
	kmem_free(bp->b_un.b_addr, NBPSCTR);
	freerbuf(bp);

	return (status);
}
/*
 *  Check media insertion/ejection status
 */
static int
pcata_check_media(ata_soft_t *rs, enum dkio_state state)
{
	int		err;
	get_status_t	get_status;


	mutex_enter(&rs->ata_mutex);

	/*
	 * Do a CS call to see if the card is present
	 */
	if ((err = csx_GetStatus(rs->client_handle, &get_status))
	    != CS_SUCCESS) {
		error2text_t cft;

		mutex_exit(&rs->ata_mutex);

		cft.item = err;
		(void) csx_Error2Text(&cft);
		cmn_err(CE_CONT, "pcata_check_media: socket %d "
		    "GetStatus failed %s (0x%x)\n",
		    rs->sn, cft.text, err);
		return (ENXIO);
	}

	/* Register rs->media_state */
	if ((get_status.CardState & CS_EVENT_CARD_INSERTION)) {
		rs->media_state = DKIO_INSERTED;
	} else {
		if (state == DKIO_NONE) {
			rs->media_state = DKIO_NONE;
		} else {
			rs->media_state = DKIO_EJECTED;
		}
	}


	/*
	 * XXXX - In order not to modify the volume management
	 *	we have to follow the current SCSI CDROM model
	 *	for checking media state (broken way, sigh!)
	 *		start with state = DKIO_NONE
	 *		wait until mediastate = DKIO_INSERTED
	 *		wait until mediastate = DKIO_EJECTED
	 *		if DKIOCSTATE ioctl() is called second time
	 *		with state = DKIO_EJECTED,
	 *		   return state = DKIO_NONE
	 *		restart with state = DKIO_NONE
	 *
	 */
	if (state != DKIO_NONE) {
		if (rs->ejected_media_flag &&
		    (rs->media_state == DKIO_EJECTED)) {
			rs->media_state = DKIO_NONE;
			rs->ejected_media_flag = 0;
			mutex_exit(&rs->ata_mutex);
			return (0);
		}
	}

#ifdef	ATA_DEBUG
	if (pcata_debug & DVOLD) {
	    cmn_err(CE_CONT, "pcata_check_media: socket %d \n"
		"\tWaiting state change: rs->media_state %d state %d\n"
		"\tDKIO_NONE %d DKIO_EJECTED %d DKIO_INSERTED %d\n",
		rs->sn, rs->media_state, state,
		DKIO_NONE, DKIO_EJECTED, DKIO_INSERTED);
	}
#endif

	/*
	 * wait for Card Detect Change Interrupt handler
	 * see either pcata_card_insertion/pcata_card_removal
	 * for cv_broadcast
	 */
	while (rs->media_state == state) {
		rs->checkmedia_flag++;
		if (cv_wait_sig(&rs->condvar_mediastate,
		    &rs->ata_mutex) == 0) {
			mutex_exit(&rs->ata_mutex);
			return (EINTR);
		}
	}

#ifdef	ATA_DEBUG
	if (pcata_debug & DVOLD) {
		cmn_err(CE_CONT, "pcata_check_media: socket %d \n"
		    "\tAfter state change: rs->media_state %d state %d\n"
		    "\tDKIO_NONE %d DKIO_EJECTED %d DKIO_INSERTED %d\n",
		    rs->sn, rs->media_state, state,
		    DKIO_NONE, DKIO_EJECTED, DKIO_INSERTED);
	}
#endif

	if (state != DKIO_NONE) {
		if (!rs->ejected_media_flag &&
		    (rs->media_state == DKIO_EJECTED)) {
			rs->ejected_media_flag++;
		}
	}

	mutex_exit(&rs->ata_mutex);

	return (0);
}

int
pcata_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int mod_flags, char *name, caddr_t valuep, int *lengthp)
{
	int		instance = ddi_get_instance(dip);
	ata_soft_t	*softp;
	ata_unit_t	*unitp;
	uint64_t	nblocks64;

	/*
	 * Our dynamic properties are all device specific and size oriented.
	 * Requests issued under conditions where size is valid are passed
	 * to ddi_prop_op_nblocks with the size information, otherwise the
	 * request is passed to ddi_prop_op.
	 */
	softp = ddi_get_soft_state(pcata_soft, instance);
	if ((dev == DDI_DEV_T_ANY) || (softp == NULL) ||
	    !(CARD_PRESENT_VALID(softp)) ||
	    ((unitp = softp->ab_link) == NULL)) {
		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));
	} else {
		/* get nblocks value */
		nblocks64 = (ulong_t)unitp->lbl.pmap[LPART(dev)].p_size;

		return (ddi_prop_op_nblocks(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp, nblocks64));
	}
}
