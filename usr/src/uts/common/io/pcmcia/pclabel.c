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

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/scsi/scsi.h>

#include <sys/fdio.h>

#include <sys/errno.h>
#include <sys/open.h>
#include <sys/debug.h>
#include <sys/varargs.h>
#include <sys/fs/pc_label.h>

#include <sys/hdio.h>
#include <sys/dkio.h>

#include <sys/dklabel.h>

#include <sys/vtoc.h>


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dktp/cm.h>

#include <sys/dktp/fdisk.h>

#include <sys/pctypes.h>


/* Future WORK */
/* Card Services header files should be removed.  When pcata.h is split  */

#include <sys/cis.h>
#include <sys/cis_handlers.h>
#include <sys/cs_types.h>
#include <sys/cs.h>

#include <sys/fs/pc_label.h>

#include <sys/pctypes.h>
#include <sys/pcmcia/pcata.h>

static	int	pcdsklbl_chk(struct dk_label *, unsigned short *);
static	void	pcdsklbl_preplb(ata_unit_t *unitp);
static	int	pcdsklbl_rdvtoc(ata_unit_t *unitp, buf_t *bp);

/*
 * accepts pointer to buffer containing the on-disk label data
 *	data could be VTOC8 or VTOC16
 *	data could be in a struct buf or in lbl
 *
 * verifies magic numbers in label and checksum
 *
 * if the parameter pointing to the checksum points to a location
 * within the label, this routine will generate the checksum
 */
static int
pcdsklbl_chk(struct dk_label *lbp, unsigned short *cksum)
{
	short	*sp;
	short	count;
	unsigned short	sum;

	/*
	 * Check magic number of the label
	 */
	if (lbp->dkl_magic != DKL_MAGIC) {
#ifdef ATA_DEBUG
		if (pcata_debug & DLBL) {
			cmn_err(CE_CONT, "pcdsklbl_chk: "
				"magic: 0x%x not MAGIC:0x%x\n",
				lbp->dkl_magic,
				DKL_MAGIC);
		}
#endif
		return (DDI_FAILURE);
	}
	if (lbp->dkl_vtoc.v_sanity != VTOC_SANE) {
#ifdef ATA_DEBUG
		if (pcata_debug & DLBL) {
			cmn_err(CE_CONT, "pcdsklbl_chk: "
				"sanity: 0x%x not SANE:0x%x\n",
				lbp->dkl_vtoc.v_sanity,
				VTOC_SANE);
		}
#endif
		return (DDI_FAILURE);
	}
	if (lbp->dkl_vtoc.v_version != V_VERSION) {
#ifdef ATA_DEBUG
		if (pcata_debug & DLBL) {
			cmn_err(CE_CONT, "pcdsklbl_chk: "
				"version: 0x%x not 0x%x\n",
				lbp->dkl_vtoc.v_version,
				V_VERSION);
		}
#endif
		return (DDI_FAILURE);
	}

	/*
	 * Check the checksum of the label
	 */
	sp = (short *)lbp;
	sum = 0;
	count = sizeof (struct dk_label) / sizeof (short);
	while (count--)  {
		sum ^= *sp++;
	}

	*cksum = sum;
	if (sum)
		return (DDI_FAILURE);
	return (DDI_SUCCESS);
}

void
pcinit_pmap(ata_unit_t *unitp)
{
	dsk_label_t		*lblp = &unitp->lbl;
	struct partition	*pmapp = lblp->pmap;
	uint32_t		disksize;	/* maximum block number */

	/*
	 * clear pmap (all 20 slices)
	 */
	bzero((caddr_t)pmapp, sizeof (struct partition) * NUM_PARTS);

	/*
	 * calc total blocks on device
	 */
	disksize = (unitp->au_cyl + unitp->au_acyl)
		 * unitp->au_hd * unitp->au_sec;

	/*
	 * The whole disk is represented here (this is the p0 partition.)
	 */
	pmapp[FDISK_OFFSET].p_tag	= 0;
	pmapp[FDISK_OFFSET].p_flag	= V_UNMNT;
	pmapp[FDISK_OFFSET].p_start	= 0;
	pmapp[FDISK_OFFSET].p_size	= disksize;

	lblp->fdiskpresent	= 0;		/* NO MBR fdisk record */
	lblp->uidx		= FDISK_OFFSET; /* NO unix fdisk partition */
}

/*
 * read sector 0 of the disk and call fdisk parse
 */
int
pcfdisk_read(buf_t *bp, ata_unit_t *unitp)
{
	int		ret;

	/*
	 * read fdisk sector (device block 0)
	 */
	bp->b_bcount = 1 * DEV_BSIZE;
	bp->b_flags = B_READ;
	bp->b_blkno = 0;

	(void) pcata_strategy(bp);
	if (biowait(bp))
		return (DDI_FAILURE);

	ret = pcfdisk_parse(bp, unitp);
	return (ret);
}

/*
 * We have this wonderful scenario
 * where there exists two different kinds of labeling schemes,
 * the x86/ppc vs. Sparc
 *
 * Procedurely we do the following
 *	clear pmap[s0-s15,p0-p5]
 *	set pmap[p0] to entire disk
 *	set uidx = p0
 *
 *	read disk block 0 and check for fdisk record
 *	if (fdisk record exists) {
 *		set pmap[p1-p4]
 *		if (Solaris partiton exists) {
 *			set uidx to px
 *		}
 *	}
 *
 *	if (fdisk record does not exist OR a Solaris partiton exists) {
 *		read disk block 1 of pmap[uidx] and check for VTOC
 *		if (VTOC exists) {
 *			set pmap[s0-s15] from vtoc
 *		}
 *		set pmap[s2] to entire Solaris partition
 *	}
 *
 *	for s0 to s15
 *		add start address of pmap[uidx] to pmap [s0-s15]
 *		(do not change incore vtoc record)
 */

int
pcfdisk_parse(buf_t *bp, ata_unit_t *unitp)
{
	dsk_label_t		*lblp = &unitp->lbl;
	struct partition	*pmapp = lblp->pmap;
	struct mboot		*mbp;
	struct ipart		*fdp;
	int			i;
	struct ipart		fdisk[FD_NUMPART];


	/* check to see if valid fdisk record exists */
	mbp = (struct mboot *)bp->b_un.b_addr;
#ifdef ATA_DEBUG
	if (pcata_debug & DLBL)
		cmn_err(CE_CONT, "pcfdisk_parse "
			"fdisk signature=%04x  MBB_MAGIC=%04x\n",
			ltohs(mbp->signature),
			MBB_MAGIC);
#endif
	if (ltohs(mbp->signature) == MBB_MAGIC) {

		/* fdisk record exists */
		lblp->fdiskpresent = 1;

		/* copy fdisk table so it is aligned on 4 byte boundry */
		fdp = fdisk;
		bcopy((caddr_t)&(mbp->parts[0]), (caddr_t)fdp, sizeof (fdisk));

		for (i = 1; i <= FD_NUMPART; i++, fdp++) {
			int	num, rel;

#ifdef ATA_DEBUG
			if (pcata_debug & DLBL)
				cmn_err(CE_CONT, "%d sy=%02x rel=%7d num=%7d\n",
					i,
					fdp->systid,
					ltohi(fdp->relsect),
					ltohi(fdp->numsect));
#endif

			/*
			 * make sure numbers are reasonable
			 * XXX/lcl partitions can still overlap
			 * XXX/lcl in fdisk.h,  num and rel are signed
			 */
			rel = ltohi(fdp->relsect);
			num = ltohi(fdp->numsect);

			if (fdp->systid == 0 ||
					rel < 0 ||
					num <= 0 ||
					rel+num > pmapp[FDISK_OFFSET].p_size) {
				continue;
			}

			pmapp[i+FDISK_OFFSET].p_tag  = fdp->systid;
			pmapp[i+FDISK_OFFSET].p_flag = 0;
			pmapp[i+FDISK_OFFSET].p_start = rel;
			pmapp[i+FDISK_OFFSET].p_size = num;
			if (fdp->systid == SUNIXOS || fdp->systid == SUNIXOS2) {
				if (lblp->uidx == FDISK_OFFSET)
					lblp->uidx = i+FDISK_OFFSET;
				else if (fdp->bootid == ACTIVE)
					lblp->uidx = i+FDISK_OFFSET;
			}
		}
	}

	/*
	 * Partitions p0 - p4 are established correctly
	 * now check for Solaris vtoc
	 */

	/*
	 * if there is no MBR (fdisk label)
	 * or there is an FDISK label which defines a Solaris partition
	 * then call rdvtoc.
	 *
	 * note: if fdisk does exist, but does not define a Solaris partiton
	 *	s0-s15 are set to zero length
	 */
	if (!lblp->fdiskpresent || lblp->uidx != FDISK_OFFSET) {
		/* failures leave pmap in the correct state, so we don't care */
		(void) pcdsklbl_rdvtoc(unitp, bp);
	}

#ifdef ATA_DEBUG
	if (pcata_debug & DLBL) {
		cmn_err(CE_CONT, "DEFINED PARTITIONS\n");
		for (i = 0; i <= NUM_PARTS; i++)
			if (pmapp[i].p_size > 0)
				cmn_err(CE_CONT, "s%2d  beg=%6ld  siz=%ld\n",
					i,
					pmapp[i].p_start,
					pmapp[i].p_size);
	}
#endif

	return (DDI_SUCCESS);
}

static int
pcdsklbl_rdvtoc(ata_unit_t *unitp, buf_t *bp)
{
	dsk_label_t	*lblp	= &unitp->lbl;
	struct dk_label *lbp;			/* points to data in buf_t */
	unsigned short	sum;
	int		i;

	/*
	 * read the label from the uidx partition (p0-p4)
	 */
	bp->b_bcount = 1 * DEV_BSIZE;
	bp->b_flags = B_READ;
	bp->b_blkno = lblp->pmap[lblp->uidx].p_start+VTOC_OFFSET;
	(void) pcata_strategy(bp);
	if (biowait(bp)) {
		return (DDI_FAILURE);
	}

	lbp = (struct dk_label *)bp->b_un.b_addr;
	if (!lbp) {
		return (DDI_FAILURE);
	}

	/*
	 * check label
	 */
	if (pcdsklbl_chk(lbp, &sum) == DDI_SUCCESS) {

		/*
		 * record label information
		 * copy the data from the buf_t memory to the lblp memory
		 */
		bcopy((caddr_t)lbp, (caddr_t)&lblp->ondsklbl, sizeof (*lbp));
	} else {
#ifdef	ATA_DEBUG
		if (pcata_debug & DLBL)
			cmn_err(CE_CONT, "vtoc label has invalid checksum\n");
#endif
		/*
		 * Since there is no valid vtoc and there should be
		 * create one based on the solaris partition (possibly p0)
		 */
		pcdsklbl_preplb(unitp);
	}

	/*
	 * adjust the lbp to point to data in the lbl structures
	 * rather than the data in the buf_t structure
	 * this is where the data was left by either the bcopy or preplb
	 */
	lbp = &lblp->ondsklbl;

#if defined(_SUNOS_VTOC_16)
	bcopy((caddr_t)&lbp->dkl_vtoc.v_part,
		(caddr_t)lblp->pmap, sizeof (lbp->dkl_vtoc.v_part));
#elif defined(_SUNOS_VTOC_8)
	for (i = 0; i < NDKMAP; i++) {
		/*
		 * convert SUNOS (VTOC8) info
		 */
		lblp->pmap[i].p_tag   = lbp->dkl_vtoc.v_part[i].p_tag;
		lblp->pmap[i].p_flag  = lbp->dkl_vtoc.v_part[i].p_flag;
		lblp->pmap[i].p_start = lbp->dkl_map[i].dkl_cylno *
			lblp->ondsklbl.dkl_nhead * lblp->ondsklbl.dkl_nsect;
		lblp->pmap[i].p_size  = lbp->dkl_map[i].dkl_nblk;
	}
#else
#error No VTOC format defined.
#endif

	/*
	 * adjust the offsets of slices 0-15 or 0-7 by the base of the uidx
	 */
	for (i = 0; i < NDKMAP; i++) {
		/*
		 * Initialize logical partition info when VTOC is read.
		 */
#if defined(_SUNOS_VTOC_8)
		lblp->un_map[i].dkl_cylno =  lbp->dkl_map[i].dkl_cylno;
		lblp->un_map[i].dkl_nblk =  lbp->dkl_map[i].dkl_nblk;
#endif
		lblp->pmap[i].p_start += lblp->pmap[lblp->uidx].p_start;
	}

	return (DDI_SUCCESS);
}

/*
 * Using the disk size information in unit and the partition data (p0-p4)
 *	construct a default device label
 *	Note - all offsets for slices 0-15 are zero based
 *	(do not include the offset of the partition which defines s2)
 *
 * There is a number of cases we have to worry about:
 *
 *   1) There is an fdisk partition but no Solaris partition.
 *	In this case the s2 slice size is zero since a valid
 *	Solaris partition must be present for us to decide the
 *	the size of the Solaris partition.
 *
 *   2)	There is an fdisk parition and a Solaris partition.
 *	We got here because the Solaris partition was not labeled
 *	or the label has been corrupted, declare the entire Solaris
 *	parition as the s2 slice
 *
 *   3) There is no fdisk partition.
 *	We have to declare the entire disk as the s2 slice,
 *	with some room for the fdisk partition (I think)
 */
static void
pcdsklbl_preplb(ata_unit_t *unitp)
{
	dsk_label_t	*lblp	= &unitp->lbl;
	struct dk_label	*odlp	= &lblp->ondsklbl;	/* on disk label */
	int		s2size;
	int		nspc;

	/* sectors per cylinder */
	nspc				= unitp->au_hd * unitp->au_sec;

	bzero((caddr_t)odlp, sizeof (struct dk_label));

	odlp->dkl_vtoc.v_nparts		= V_NUMPAR;
	odlp->dkl_vtoc.v_sanity		= VTOC_SANE;
	odlp->dkl_vtoc.v_version	= V_VERSION;

	odlp->dkl_pcyl			= lblp->pmap[lblp->uidx].p_size / nspc;
	odlp->dkl_acyl			= 2;
	odlp->dkl_ncyl			= odlp->dkl_pcyl - odlp->dkl_acyl;

	odlp->dkl_nhead			= unitp->au_hd;
	odlp->dkl_nsect			= unitp->au_sec;

	odlp->dkl_rpm			= 3600;

	odlp->dkl_intrlv		= 1;
	odlp->dkl_apc			= 0;
	odlp->dkl_magic			= DKL_MAGIC;

	/*
	 * set size of s2 from uidx
	 */
	s2size				= lblp->pmap[lblp->uidx].p_size;

#if defined(_SUNOS_VTOC_16)
	/*
	 * If this is x86/PowerPC format label
	 */

	odlp->dkl_vtoc.v_sectorsz	= NBPSCTR;

	/* Add full disk slice as slice 2 to the disk */
	odlp->dkl_vtoc.v_part[USLICE_WHOLE].p_start	= 0;
	odlp->dkl_vtoc.v_part[USLICE_WHOLE].p_size	= s2size;
	odlp->dkl_vtoc.v_part[USLICE_WHOLE].p_tag	= V_BACKUP;
	odlp->dkl_vtoc.v_part[USLICE_WHOLE].p_flag	= V_UNMNT;

	/* Boot slice */
	odlp->dkl_vtoc.v_part[8].p_start	= 0;
	odlp->dkl_vtoc.v_part[8].p_size		= nspc;
	odlp->dkl_vtoc.v_part[8].p_tag		= V_BOOT;
	odlp->dkl_vtoc.v_part[8].p_flag		= V_UNMNT;

	(void) sprintf(odlp->dkl_vtoc.v_asciilabel,
		    "DEFAULT cyl %d alt %d hd %d sec %d",
			odlp->dkl_ncyl,
			odlp->dkl_acyl,
			odlp->dkl_nhead,
			odlp->dkl_nsect);
#elif defined(_SUNOS_VTOC_8)

	/* Add full disk slice as slice 2 to the disk */
	odlp->dkl_map[USLICE_WHOLE].dkl_cylno	= 0;
	odlp->dkl_map[USLICE_WHOLE].dkl_nblk	= s2size;

	(void) sprintf(odlp->dkl_asciilabel,
		    "DEFAULT cyl %d alt %d hd %d sec %d",
			odlp->dkl_ncyl,
			odlp->dkl_acyl,
			odlp->dkl_nhead,
			odlp->dkl_nsect);
#else
#error No VTOC format defined.
#endif

	/*
	 * an on-disk label has been constructed above
	 * call pcdsklbl_chk with the 2nd parm pointing into the label
	 * will generate a correct checksum in the label
	 */
	(void) pcdsklbl_chk(&lblp->ondsklbl, &(lblp->ondsklbl.dkl_cksum));
}

int
pcdsklbl_wrvtoc(dsk_label_t *lblp, struct vtoc *vtocp, buf_t *bp)
{
	register struct dk_label *lbp, *dp;
	int	status;
	int	backup_block;
	int	count;

	/*
	 * Data is originated from vtoc. One copy of the data is stored in
	 * lblp->ondsklbl. This is what we think of as the copy of the lable
	 * on this held in memory. The other copy (to the lbp) is to be
	 * written out to the disk.
	 */
	dp = &lblp->ondsklbl;

	bp->b_bcount = 1 * DEV_BSIZE;
	bp->b_flags = B_WRITE;

	lbp = (struct dk_label *)bp->b_un.b_addr;

	pcdsklbl_vtoc_to_ondsklabel(lblp, vtocp);
	*lbp = lblp->ondsklbl;

	/*
	 * check label
	 */
	bp->b_blkno = lblp->pmap[lblp->uidx].p_start + VTOC_OFFSET;

#ifdef ATA_DEBUG
	if (pcata_debug & DLBL)
		cmn_err(CE_NOTE, "dsklbl_wrvtoc:  calling strategy \n");
#endif
	(void) pcata_strategy(bp);
	status = biowait(bp);

	if (status != 0 || dp->dkl_acyl == 0)
		return (status);

	/*
	 * DO backup copies of vtoc
	 */

	backup_block = ((dp->dkl_ncyl + dp->dkl_acyl - 1) *
			(dp->dkl_nhead * dp->dkl_nsect)) +
			((dp->dkl_nhead - 1) * dp->dkl_nsect) + 1;

	bcopy((caddr_t)&(lblp->ondsklbl), (caddr_t)lbp, sizeof (*lbp));
	for (count = 1; count < 6; count++) {

		bp->b_blkno = lblp->pmap[lblp->uidx].p_start+backup_block;

		/* issue read */
		(void) pcata_strategy(bp);
		if (biowait(bp))
			return (bp->b_error);

		backup_block += 2;
	}
	return (0);
}



void
pcdsklbl_ondsklabel_to_vtoc(dsk_label_t *lblp, struct vtoc *vtocp)
{

#if defined(_SUNOS_VTOC_16)
	bcopy((caddr_t)&lblp->ondsklbl.dkl_vtoc, (caddr_t)vtocp,
		sizeof (*vtocp));
#elif defined(_SUNOS_VTOC_8)
	int i;
	uint32_t nblks;
	struct dk_map2 *lpart;
#ifdef _SYSCALL32
	struct dk_map32 *lmap;
#else
	struct dk_map	*lmap;
#endif
	struct partition *vpart;
	/*
	 * Data is originated from vtoc. One copy of the data is stored in
	 * lblp->ondsklbl. This is what we think of as the copy of the label
	 * on the disk held in memory. The other copy (to the lbp) is to be
	 * written out to the disk.
	 */

	/*
	 * Put appropriate vtoc structure fields into the disk label
	 *
	 */
	bcopy((caddr_t)(lblp->ondsklbl.dkl_vtoc.v_bootinfo),
		(caddr_t)vtocp->v_bootinfo, sizeof (vtocp->v_bootinfo));

	/* For now may want to add the sectorsz field to the generic structur */
	vtocp->v_sectorsz = NBPSCTR;	/* sector size in bytes */

	vtocp->v_sanity = lblp->ondsklbl.dkl_vtoc.v_sanity;
	vtocp->v_version = lblp->ondsklbl.dkl_vtoc.v_version;

	bcopy((caddr_t)lblp->ondsklbl.dkl_vtoc.v_volume,
		(caddr_t)vtocp->v_volume, LEN_DKL_VVOL);

	vtocp->v_nparts = lblp->ondsklbl.dkl_vtoc.v_nparts;

	bcopy((caddr_t)lblp->ondsklbl.dkl_vtoc.v_reserved,
		(caddr_t)vtocp->v_reserved, sizeof (vtocp->v_reserved));

	/*
	 * Note the conversion from starting sector number
	 * to starting cylinder number.
	 */
	/* Bug Check this		*/
	nblks = lblp->ondsklbl.dkl_nsect * lblp->ondsklbl.dkl_nhead;

	lmap = lblp->ondsklbl.dkl_map;
	lpart = (struct dk_map2 *)lblp->ondsklbl.dkl_vtoc.v_part;
	vpart = vtocp->v_part;

	for (i = 0; i < (int)vtocp->v_nparts; i++) {
		vpart->p_tag = lpart->p_tag;
		vpart->p_flag = lpart->p_flag;
		vpart->p_start = lmap->dkl_cylno * nblks;
		vpart->p_size = lmap->dkl_nblk;

		lmap++;
		lpart++;
		vpart++;
	}

	bcopy((caddr_t)lblp->ondsklbl.dkl_vtoc.v_timestamp,
		(caddr_t)vtocp->timestamp, sizeof (vtocp->timestamp));

	bcopy((caddr_t)lblp->ondsklbl.dkl_asciilabel,
		(caddr_t)vtocp->v_asciilabel,
		LEN_DKL_ASCII);

#else
#error No VTOC format defined.
#endif
}

void
pcdsklbl_vtoc_to_ondsklabel(dsk_label_t *lblp, struct vtoc *vtocp)
{
#if defined(_SUNOS_VTOC_16)
	bcopy((caddr_t)vtocp, (caddr_t)&(lblp->ondsklbl.dkl_vtoc),
							sizeof (*vtocp));
#elif defined(_SUNOS_VTOC_8)
	/*
	 * Put appropriate vtoc structure fields into the disk label
	 *
	 */
	{
	int i;
	uint32_t nblks;
	struct dk_map2 *lpart;
#ifdef _SYSCALL32
	struct dk_map32 *lmap;
#else
	struct dk_map	*lmap;
#endif
	struct partition *vpart;
	register struct dk_label *dp;

	/*
	 * Data is originated from vtoc. One copy of the data is stored in
	 * lblp->ondsklbl. This is what we think of as the copy of the label
	 * on this disk held in memory.
	 */

	dp = &lblp->ondsklbl;

	bcopy((caddr_t)vtocp->v_bootinfo,
		(caddr_t)(lblp->ondsklbl.dkl_vtoc.v_bootinfo),
		sizeof (vtocp->v_bootinfo));

	lblp->ondsklbl.dkl_vtoc.v_sanity = vtocp->v_sanity;
	lblp->ondsklbl.dkl_vtoc.v_version = vtocp->v_version;

	bcopy((caddr_t)vtocp->v_volume,
		(caddr_t)lblp->ondsklbl.dkl_vtoc.v_volume,
		LEN_DKL_VVOL);

	lblp->ondsklbl.dkl_vtoc.v_nparts = vtocp->v_nparts;

	bcopy((caddr_t)vtocp->v_reserved,
		(caddr_t)lblp->ondsklbl.dkl_vtoc.v_reserved,
		sizeof (vtocp->v_reserved));

	/*
	 * Note the conversion from starting sector number
	 * to starting cylinder number.
	 */
	nblks = dp->dkl_nsect * dp->dkl_nhead;
	lmap = lblp->ondsklbl.dkl_map;
	lpart = (struct dk_map2 *)lblp->ondsklbl.dkl_vtoc.v_part;
	vpart = vtocp->v_part;

	for (i = 0; i < (int)vtocp->v_nparts; i++) {
		lpart->p_tag  = vpart->p_tag;
		lpart->p_flag = vpart->p_flag;
		lmap->dkl_cylno = vpart->p_start / nblks;
		lmap->dkl_nblk = vpart->p_size;

		lmap++;
		lpart++;
		vpart++;
	}

	bcopy((caddr_t)vtocp->timestamp,
		(caddr_t)lblp->ondsklbl.dkl_vtoc.v_timestamp,
		sizeof (vtocp->timestamp));

	bcopy((caddr_t)vtocp->v_asciilabel,
		(caddr_t)lblp->ondsklbl.dkl_asciilabel,
		LEN_DKL_ASCII);

	}
#else
#error No VTOC format defined.
#endif

	lblp->ondsklbl.dkl_cksum = 0;
	(void) pcdsklbl_chk(&lblp->ondsklbl, &(lblp->ondsklbl.dkl_cksum));
}

void
pcdsklbl_dgtoug(struct dk_geom *up, struct dk_label *dp)
{

#ifdef ATA_DEBUG
	cmn_err(CE_CONT, "pcdsklbl_dgtoug:  pcyl = %d ncyl = %d acyl = %d"
		" head= %d sect = %d intrlv = %d \n",
		dp->dkl_pcyl,
		dp->dkl_ncyl,
		dp->dkl_acyl,
		dp->dkl_nhead,
		dp->dkl_nsect,
		dp->dkl_intrlv);
#endif

	up->dkg_pcyl   = dp->dkl_pcyl;
	up->dkg_ncyl   = dp->dkl_ncyl;
	up->dkg_acyl   = dp->dkl_acyl;
#if !defined(__sparc)
	up->dkg_bcyl   = dp->dkl_bcyl;
#endif
	up->dkg_nhead  = dp->dkl_nhead;
	up->dkg_nsect  = dp->dkl_nsect;
	up->dkg_intrlv = dp->dkl_intrlv;
	up->dkg_apc    = dp->dkl_apc;
	up->dkg_rpm    = dp->dkl_rpm;
	up->dkg_write_reinstruct = dp->dkl_write_reinstruct;
	up->dkg_read_reinstruct  = dp->dkl_read_reinstruct;
}




void
pcdsklbl_ugtodg(struct dk_geom *up, struct dk_label *dp)
{
	dp->dkl_pcyl   = up->dkg_pcyl;
	dp->dkl_ncyl   = up->dkg_ncyl;
	dp->dkl_acyl   = up->dkg_acyl;
#if !defined(__sparc)
	dp->dkl_bcyl   = up->dkg_bcyl;
#endif
	dp->dkl_nhead  = up->dkg_nhead;
	dp->dkl_nsect  = up->dkg_nsect;
	dp->dkl_intrlv = up->dkg_intrlv;
	dp->dkl_apc    = up->dkg_apc;
	dp->dkl_rpm    = up->dkg_rpm;
	dp->dkl_write_reinstruct = up->dkg_write_reinstruct;
	dp->dkl_read_reinstruct  = up->dkg_read_reinstruct;
}
