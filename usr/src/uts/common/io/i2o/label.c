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
#include <sys/stat.h>

#include <sys/fdio.h>

#include <sys/errno.h>
#include <sys/open.h>
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

#include <sys/dktp/fdisk.h>


#include <sys/fs/pc_label.h>

#include <sys/i2o/i2omsg.h>
#include "i2o_bs.h"


static int	dsklbl_chk(struct dk_label *, unsigned short *);
static void 	dsklbl_preplb(dsk_label_t *, dev_t, struct cb_ops *, int);
static void 	dsklbl_convert_lbl_to_pmap(struct dk_label *, dsk_label_t *);
static void 	dsklbl_savelb(struct dk_label *, dsk_label_t *);
static int 	dsklbl_rdvtoc(dsk_label_t *, struct buf *, struct cb_ops *);
char		*partition_type(unsigned char);
void		dsklbl_read_label(struct buf *, dsk_label_t *, struct cb_ops *,
					struct dk_geom *, int);
void		dsklbl_mprint(struct partition *);
int 		dsklbl_wrvtoc(dsk_label_t *, struct vtoc *, struct buf *,
					struct cb_ops *);
void		dsklbl_ondsklabel_to_vtoc(dsk_label_t *, struct vtoc *);
void    	dsklbl_vtoc_to_ondsklabel(dsk_label_t *, struct vtoc *);
void 		dsklbl_dgtoug(struct dk_geom *, struct dk_label *);
void 		dsklbl_ugtodg(struct dk_geom *, struct dk_label *);

#ifdef	DLBL_DEBUG
int label_debug = 1;

#define	DEBUGF(flag, args) \
	{ if (label_debug & (flag)) cmn_err args; }
#else
#define	DEBUGF(level, args)	/* nothing */
#endif

static int
dsklbl_chk(struct dk_label *lbp, unsigned short *cksum)
{
	short 	*sp;
	short 	count;
	unsigned short	sum;

	/*
	 * Check magic number of the label
	 */
	if (lbp->dkl_magic != DKL_MAGIC) {
		DEBUGF(1, (CE_CONT, "?dsklbl_chk: magic: %x not MAGIC:"
				"%x\n", lbp->dkl_magic, DKL_MAGIC));
		return (DDI_FAILURE);
	}
	if (lbp->dkl_vtoc.v_sanity != VTOC_SANE) {
		DEBUGF(1, (CE_CONT, "?dsklbl_chk:sanity: %x not SANE:"
				"%x\n", lbp->dkl_vtoc.v_sanity, VTOC_SANE));
		return (DDI_FAILURE);
	}
	if (lbp->dkl_vtoc.v_version != V_VERSION) {
		DEBUGF(1, (CE_CONT, "?dsklbl_chk:version: %x not %x\n",
				lbp->dkl_vtoc.v_version, V_VERSION));
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

/*
 * We have this wonderful scenario where there exists two different kind
 * of labeling scheme the x86/ppc vs. Sparc they are sufficiently different
 * (read broken) that it justifies having two completely different preplb
 * routines.
 */

static void
dsklbl_preplb(dsk_label_t *lblp, dev_t dev, struct cb_ops *dev_ops, int type)
{
	long	disksize;
	struct dk_geom dkg;
	int	rval;
	int	s2size;


	DEBUGF(1, (CE_CONT, "?dlbl_preplb(%x, %x)\n", lblp, dev));

	bzero(&dkg, sizeof (struct dk_geom));
	bzero(&lblp->ondsklbl, sizeof (struct dk_label));

	(*dev_ops->cb_ioctl)(dev, DKIOCG_PHYGEOM,
			(uintptr_t)&dkg, FKIOCTL, (cred_t *)0, &rval);


#if defined(_SUNOS_VTOC_16)
	lblp->ondsklbl.dkl_pcyl = lblp->pmap[FDISK_OFFSET+lblp->uidx].p_size /
					(dkg.dkg_nhead * dkg.dkg_nsect);

	DEBUGF(1, (CE_CONT, "?dsklbl_preplb(p_size = %d, nhead = %d"
	    "nsect = %d)\n",
	    (lblp->pmap[FDISK_OFFSET+lblp->uidx].p_size), dkg.dkg_nhead,
	    dkg.dkg_nsect));

#elif defined(_SUNOS_VTOC_8)
	lblp->ondsklbl.dkl_pcyl = (unsigned short)(lblp->pmap[FDISK_OFFSET+
					lblp->uidx].p_size /
					(long)(dkg.dkg_nhead * dkg.dkg_nsect));
#endif



	lblp->ondsklbl.dkl_acyl = 2;
	lblp->ondsklbl.dkl_ncyl = lblp->ondsklbl.dkl_pcyl -
					lblp->ondsklbl.dkl_acyl;

	/* or can use the size saved in ata_data (consider generic case */
	disksize = lblp->ondsklbl.dkl_ncyl * dkg.dkg_nhead * dkg.dkg_nsect;


	lblp->ondsklbl.dkl_intrlv	= 1;
	lblp->ondsklbl.dkl_apc	= 0;
	lblp->ondsklbl.dkl_vtoc.v_nparts = V_NUMPAR;
	lblp->ondsklbl.dkl_magic	= DKL_MAGIC;

	lblp->ondsklbl.dkl_vtoc.v_sanity = VTOC_SANE;
	lblp->ondsklbl.dkl_vtoc.v_version = V_VERSION;


	/*
	 * Set up the p0 partition
	 */
	lblp->pmap[FPART_WHOLE+FDISK_OFFSET].p_start = 0;
	lblp->pmap[FPART_WHOLE+FDISK_OFFSET].p_size  = disksize;
	lblp->pmap[FPART_WHOLE+FDISK_OFFSET].p_flag  = V_UNMNT;



	/* NEEDS WORK add support for SPARC for CD  */
	/*
	 * If CD-ROM, special-case:
	 *  - lie about head/sect/cyl to get at every block on the disk
	 *  - add full disk as slices 0 and 2 to the label
	 */

	if (type == DKC_CDROM) {
		/*
		 * Not heads * sectors * cyls, but the whole thing
		 * This applies later, to s2, as well.
		 */


		lblp->ondsklbl.dkl_nhead = 1;
		lblp->ondsklbl.dkl_nsect = 1;

		/* NEEDS WORK get it from IOP probably not SD uses it too */
		lblp->ondsklbl.dkl_rpm	= 200;

#if defined(_SUNOS_VTOC_16)

		lblp->ondsklbl.dkl_vtoc.v_part[USLICE_WHOLE].p_start = 0;
		lblp->ondsklbl.dkl_vtoc.v_part[USLICE_WHOLE].p_size  = disksize;
		lblp->ondsklbl.dkl_vtoc.v_part[USLICE_WHOLE].p_tag = V_BACKUP;
		lblp->ondsklbl.dkl_vtoc.v_part[USLICE_WHOLE].p_flag = V_UNMNT;

		lblp->ondsklbl.dkl_vtoc.v_part[0].p_start = 0;
		lblp->ondsklbl.dkl_vtoc.v_part[0].p_size  = disksize;
		lblp->ondsklbl.dkl_vtoc.v_part[0].p_tag = V_BACKUP;
		lblp->ondsklbl.dkl_vtoc.v_part[0].p_flag = V_UNMNT;


#elif defined(_SUNOS_VTOC_8)

		/* Add full disk slice as slice 2 to the disk */

		lblp->ondsklbl.dkl_map[USLICE_WHOLE].dkl_cylno = 0;
		lblp->ondsklbl.dkl_map[USLICE_WHOLE].dkl_nblk  = disksize;

		lblp->ondsklbl.dkl_map[0].dkl_cylno = 0;
		lblp->ondsklbl.dkl_map[USLICE_WHOLE].dkl_nblk  = disksize;



#else
#error No VTOC format defined.
#endif
	} else {

	/* NONE CD case */


	lblp->ondsklbl.dkl_nhead = dkg.dkg_nhead;
	lblp->ondsklbl.dkl_nsect = dkg.dkg_nsect;

	lblp->ondsklbl.dkl_rpm	= 3600;

	/* Add boot disk slice as slice 8 to the disk */


	/*
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

	if (lblp->fdiskpresent) {
		if (lblp->uidx == 0) {		/* FDISK - Solaris (1 above) */
			s2size = 0;
		} else {			/* FDISK + Solaris (2 above) */
			s2size = lblp->pmap[lblp->uidx+FDISK_OFFSET].p_size;
		}
	} else {				/* No FDISK	(3 above) */
		s2size = disksize;
	}
#if defined(_SUNOS_VTOC_16)
	/*
	 * If this is x86/PowerPC format label
	 */

	lblp->ondsklbl.dkl_vtoc.v_sectorsz = NBPSCTR;

	/* Add full disk slice as slice 2 to the disk */

	lblp->ondsklbl.dkl_vtoc.v_part[USLICE_WHOLE].p_start = 0;
	lblp->ondsklbl.dkl_vtoc.v_part[USLICE_WHOLE].p_size  = s2size;
	lblp->ondsklbl.dkl_vtoc.v_part[USLICE_WHOLE].p_tag = V_BACKUP;
	lblp->ondsklbl.dkl_vtoc.v_part[USLICE_WHOLE].p_flag = V_UNMNT;

	lblp->ondsklbl.dkl_vtoc.v_part[8].p_start = 0;
	lblp->ondsklbl.dkl_vtoc.v_part[8].p_size  =
					dkg.dkg_nhead * dkg.dkg_nsect;
	lblp->ondsklbl.dkl_vtoc.v_part[8].p_tag = V_BOOT;
	lblp->ondsklbl.dkl_vtoc.v_part[8].p_flag = V_UNMNT;

	/* For now this is not a requirenment		    */
	/* Add Alternates disk slice as slice 9 to the disk */

	lblp->ondsklbl.dkl_vtoc.v_part[9].p_start =
					dkg.dkg_nhead * dkg.dkg_nsect;
	lblp->ondsklbl.dkl_vtoc.v_part[9].p_size  =
					2 * dkg.dkg_nhead * dkg.dkg_nsect;
	lblp->ondsklbl.dkl_vtoc.v_part[9].p_tag = V_ALTSCTR;
	lblp->ondsklbl.dkl_vtoc.v_part[9].p_flag = 0;

	(void) sprintf(lblp->ondsklbl.dkl_vtoc.v_asciilabel,
		    "DEFAULT cyl %d alt %d hd %d sec %d",
			lblp->ondsklbl.dkl_ncyl,
			lblp->ondsklbl.dkl_acyl,
			lblp->ondsklbl.dkl_nhead,
			lblp->ondsklbl.dkl_nsect);
#elif defined(_SUNOS_VTOC_8)

	/* Add full disk slice as slice 2 to the disk */

	lblp->ondsklbl.dkl_map[USLICE_WHOLE].dkl_cylno = 0;
	lblp->ondsklbl.dkl_map[USLICE_WHOLE].dkl_nblk  = s2size;

	(void) sprintf(lblp->ondsklbl.dkl_asciilabel,
		    "DEFAULT cyl %d alt %d hd %d sec %d",
			lblp->ondsklbl.dkl_ncyl,
			lblp->ondsklbl.dkl_acyl,
			lblp->ondsklbl.dkl_nhead,
			lblp->ondsklbl.dkl_nsect);
#else
#error No VTOC format defined.
#endif



	}

	(void) dsklbl_chk(&lblp->ondsklbl, &(lblp->ondsklbl.dkl_cksum));
	/*
	 * now that an on disk label is manufactured, convert so
	 * that we start using right away
	 * is this the right thing to do, we also need a mutex
	 * to protext it.
	 *
	 * dsklbl_convert_lbl_to_pmap(&lblp->ondsklbl, lblp);
	 *
	 */

}

static void
dsklbl_convert_lbl_to_pmap(struct dk_label *lbp, dsk_label_t *lblp)
{
	int	i;
#if defined(_SUNOS_VTOC_16)
	bcopy((caddr_t)&lbp->dkl_vtoc.v_part,
		(caddr_t)lblp->pmap, sizeof (lbp->dkl_vtoc.v_part));
#elif defined(_SUNOS_VTOC_8)
	for (i = 0; i < NDKMAP; i++) {
		lblp->pmap[i].p_tag   = lbp->dkl_vtoc.v_part[i].p_tag;
		lblp->pmap[i].p_flag  = lbp->dkl_vtoc.v_part[i].p_flag;
		lblp->pmap[i].p_start = lbp->dkl_map[i].dkl_cylno *
			lblp->ondsklbl.dkl_nhead * lblp->ondsklbl.dkl_nsect;
		lblp->pmap[i].p_size  = lbp->dkl_map[i].dkl_nblk;
	}
#else
#error No VTOC format defined.
#endif
	for (i = 0; i < NDKMAP; i++) {
		lblp->pmap[i].p_start +=
				lblp->pmap[lblp->uidx+FDISK_OFFSET].p_start;
	}
}

static void
dsklbl_savelb(struct dk_label *lbp, dsk_label_t *lblp)
{
	/*
	 * save the disk label in memory
	 */

	bcopy((caddr_t)lbp, (caddr_t)&lblp->ondsklbl, sizeof (*lbp));

	dsklbl_convert_lbl_to_pmap(lbp, lblp);
#ifdef	DLBL_DEBUG
	dsklbl_mprint(lblp->pmap);
#endif
}

static int
dsklbl_rdvtoc(dsk_label_t *lblp, struct buf *bp, struct cb_ops *dev_ops)
{
	struct dk_label *lbp;
	unsigned short	sum;

	/*
	 * read the label
	 */
	DEBUGF(1, (CE_CONT, "?dsklbl_rdvtoc(%x, %x)\n", lblp, bp));
	bp->b_bcount = 1 * DEV_BSIZE;
	bp->b_flags = B_READ;
	bp->b_blkno = lblp->pmap[FDISK_OFFSET+lblp->uidx].p_start+VTOC_OFFSET;

	(*dev_ops->cb_strategy)(bp);
	(void) biowait(bp);


	lbp = (struct dk_label *)bp->b_un.b_addr;

	/*
	 * check label
	 */
	if ((!lbp) || (dsklbl_chk(lbp, &sum) == DDI_FAILURE)) {
		DEBUGF(1, (CE_CONT,
			"?label does not have a valid checksum\n"));
		return (DDI_FAILURE);
	}
	/*
	 * record label information
	 */
	dsklbl_savelb(lbp, lblp);
	lblp->vtocread = 1;

	return (DDI_SUCCESS);
}


struct {
	unsigned char	id;
	char		*name;
} partitionname[] = {
	{ 0x01, "DOS 12-bit FAT" },
	{ 0x02, "XENIX /" },
	{ 0x03, "XENIX /usr" },
	{ 0x04, "DOS 16-bit FAT <32M" },
	{ 0x05, "DOS Extended Partition" },
	{ 0x06, "DOS 16-bit FAT >=32M" },
	{ 0x07, "OS/2 IFS (e.g., HPFS) or NTFS or QNX2.x or Advanced UNIX" },
	{ 0x08, "AIX boot or SplitDrive" },
	{ 0x09, "AIX data or Coherent" },
	{ 0x0a, "OS/2 Boot Manager" },
	{ 0x0e, "DOS 16-bit FAT, CHS-mapped" },
	{ 0x0f, "Extended partition, CHS-mapped" },
	{ 0x10, "OPUS" },
	{ 0x11, "OS/2 BM: Hidden DOS 12-bit FAT" },
	{ 0x12, "Compaq config partition" },
	{ 0x14, "OS/2 BM: Hidden DOS 16-bit FAT <32M" },
	{ 0x16, "OS/2 BM: Hidden DOS 16-bit FAT >=32M" },
	{ 0x17, "OS/2 BM: Hidden IFS (e.g., HPFS)" },
	{ 0x18, "AST Windows swapfile" },
	{ 0x24, "NEC DOS" },
	{ 0x3c, "PartitionMagic recovery partition" },
	{ 0x40, "Venix 80286" },
	{ 0x41, "Linux/MINIX (sharing disk with DRDOS)" },
	{ 0x42, "Linux swap (sharing disk with DRDOS) or SFS" },
	{ 0x43, "Linux native (sharing disk with DRDOS)" },
	{ 0x50, "OnTrack DM RO" },
	{ 0x51, "OnTrack DM RW (DM6 Aux1) or Novell" },
	{ 0x52, "CP/M or Microport SysV/AT" },
	{ 0x53, "DM6 Aux3" },
	{ 0x54, "DM6" },
	{ 0x55, "EZ-Drive" },
	{ 0x56, "Golden Bow VFeature Partitioned Volume." },
	{ 0x5C, "Priam EDisk" },
	{ 0x61, "SpeedStor" },
	{ 0x63, "Unix System V (SCO, ISC UNIX, UnixWare, ...)" },
	{ 0x64, "Novell Netware 2.xx" },
	{ 0x65, "Novell Netware 3.xx or 4.xx" },
	{ 0x70, "DiskSecure Multi-Boot" },
	{ 0x75, "PC/IX" },
	{ 0x77, "QNX4.x" },
	{ 0x78, "QNX4.x 2nd part" },
	{ 0x79, "QNX4.x 3rd part" },
	{ 0x80, "MINIX until 1.4a" },
	{ 0x81, "MINIX since 1.4b, early Linux, Mitac dmgr" },
	{ 0x82, "Solaris" },
	{ 0x83, "Linux native" },
	{ 0x84, "OS/2 hidden C: drive" },
	{ 0x85, "Linux extended partition" },
	{ 0x86, "NTFS volume set??" },
	{ 0x87, "NTFS volume set??" },
	{ 0x93, "Amoeba" },
	{ 0x94, "Amoeba bad track table" },
	{ 0xa0, "IBM Thinkpad hibernation partition" },
	{ 0xa5, "BSD/386, 386BSD, NetBSD, FreeBSD" },
	{ 0xa7, "NEXTSTEP" },
	{ 0xb7, "BSDI fs" },
	{ 0xb8, "BSDI swap" },
	{ 0xc1, "DRDOS/sec (FAT-12)" },
	{ 0xc4, "DRDOS/sec (FAT-16, < 32M)" },
	{ 0xc6, "DRDOS/sec (FAT-16, >= 32M)" },
	{ 0xc7, "Syrinx" },
	{ 0xdb, "Concurrent CP/M or Concurrent DOS or CTOS" },
	{ 0xe1, "DOS access or SpeedStor 12-bit FAT extended partition" },
	{ 0xe3, "DOS R/O or SpeedStor" },
	{ 0xe4, "SpeedStor 16-bit FAT extended partition < 1024 cyl." },
	{ 0xf1, "SpeedStor" },
	{ 0xf2, "DOS 3.3+ secondary" },
	{ 0xf4, "SpeedStor large partition" },
	{ 0xfe, "SpeedStor >1024 cyl. or LANstep" },
	{ 0xff, "Xenix Bad Block Table" }
};

char *
partition_type(unsigned char systid)
{
	int	i;

	for (i = 0; i < sizeof (partitionname)/sizeof (partitionname[0]); i++)
		if (partitionname[i].id == systid)
			return (partitionname[i].name);

	return ("Unknown");
}

int
parse_fdisk_lbl(struct buf *bp, dsk_label_t *lblp, struct cb_ops *dev_ops,
			struct dk_geom *dkg, int type)
{
	struct mboot	*mbp;
	struct ipart	*fdp;
	int		i, uidx;
	struct ipart fdisk[FD_NUMPART];

	/*
	 * The whole disk is represented here (this is the p0 partition.)
	 */
	lblp->pmap[FPART_WHOLE+FDISK_OFFSET].p_start = 0;
	lblp->pmap[FPART_WHOLE+FDISK_OFFSET].p_size  =
		dkg->dkg_ncyl * dkg->dkg_nhead * dkg->dkg_nsect;
	lblp->pmap[FPART_WHOLE+FDISK_OFFSET].p_flag  = V_UNMNT;

	mbp = (struct mboot *)bp->b_un.b_addr;

	if (!mbp || ltohs(mbp->signature) != MBB_MAGIC) {

		DEBUGF(1, (CE_CONT,
			"?lbl 0x%x does not have an fdisk table.\n",
			bp->b_edev));
#ifdef DLBL_DEBUG
		if (mbp)
			DEBUGF(1, (CE_CONT, "?lbl "
				"expteced magic: 0x%x got 0x%x\n",
				MBB_MAGIC, ltohs(mbp->signature)));
#endif
		DEBUGF(1, (CE_CONT,
			"parse_label: b_edev %x "
			"b_dev = %x\n",
			bp->b_edev, bp->b_dev));

		lblp->fdiskpresent = 0;
		lblp->uidx = 0;
		if (dsklbl_rdvtoc(lblp, bp, dev_ops) == DDI_FAILURE) {
			bp->b_dev = cmpdev(bp->b_edev);
			dsklbl_preplb(lblp, bp->b_edev, dev_ops, type);
		}
		return (DDI_SUCCESS);
	}
	/*
	 * The fdisk table does not begin on a 4-byte boundary within
	 * the master boot record; so, we need to recopy its contents to
	 * another data structure to avoid an alignment exception.
	 * This is not necessary for x86, but it avoids ifdefs
	 */
	fdp = fdisk;
	bcopy((caddr_t)&(mbp->parts[0]), (caddr_t)fdp, sizeof (fdisk));

	DEBUGF(1, (CE_CONT,
	"?---------------------- Partition Table -----------------\n"));
	DEBUGF(1, (CE_CONT, "?index    relsect  numsect  type\n"));
	DEBUGF(1, (CE_CONT,
	"?-------  -------  -------  -----------------------------\n"));

	for (uidx = 0, i = 1; i <= FD_NUMPART; i++, fdp++)  {
		if (!fdp->numsect) {
			lblp->pmap[i+FDISK_OFFSET].p_flag  = V_INVALID;
			continue;
		}
		lblp->pmap[i+FDISK_OFFSET].p_start = ltohi(fdp->relsect);
		lblp->pmap[i+FDISK_OFFSET].p_size  = ltohi(fdp->numsect);
		DEBUGF(1, (CE_CONT, "?%7d  %7d  %7d  %4x (%s)\n", i,
			ltohi(fdp->relsect),
			ltohi(fdp->numsect),
			fdp->systid, partition_type(fdp->systid)));
		if (fdp->systid == SUNIXOS || fdp->systid == SUNIXOS2) {
			if (uidx == 0)
				uidx = i;
			else if (fdp->bootid == ACTIVE)
				uidx = i;
		}
	}

	lblp->fdiskpresent = 1;
	lblp->uidx = uidx;
	if (dsklbl_rdvtoc(lblp, bp, dev_ops) == DDI_FAILURE) {
		bp->b_dev = cmpdev(bp->b_edev);
		dsklbl_preplb(lblp, bp->b_edev, dev_ops, type);

	}
	return (DDI_SUCCESS);
}

void
dsklbl_read_label(struct buf *bp, dsk_label_t *lblp, struct cb_ops *dev_ops,
			struct dk_geom *dkg, int type)
{
	/*
	 * read the label
	 */

	bp->b_bcount = 1 * DEV_BSIZE;
	bp->b_flags = B_READ;
	bp->b_blkno = 0;
	(*dev_ops->cb_strategy)(bp);
	(void) biowait(bp);
	(void) parse_fdisk_lbl(bp, lblp, dev_ops, dkg, type);
}

#ifdef	DLBL_DEBUG
void
dsklbl_mprint(struct partition *pp)
{
	int i;

	cmn_err(CE_CONT, "?----- UNIX slices -----\n");
	cmn_err(CE_CONT, "?slice  start   size\n");
	cmn_err(CE_CONT, "?-----  ------  --------\n");
	for (i = 0; i < NDKMAP; i++, pp++) {
		if (pp->p_size) {
			cmn_err(CE_CONT, "?%5d  %6x  %x\n", i, pp->p_start,
				pp->p_size);
		}
	}
}
#endif


int
dsklbl_wrvtoc(dsk_label_t *lblp, struct vtoc *vtocp, struct buf *bp,
		struct cb_ops *dev_ops)
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
	bp->b_flags = B_WRITE | B_BUSY;

	lbp = (struct dk_label *)bp->b_un.b_addr;

	dsklbl_vtoc_to_ondsklabel(lblp, vtocp);
	*lbp = lblp->ondsklbl;

	/*
	 * check label
	 */
	if (lblp->uidx)
		bp->b_blkno = lblp->pmap[FDISK_OFFSET+lblp->uidx].p_start;
	else
		bp->b_blkno = 0;
	bp->b_blkno += VTOC_OFFSET;


	(*dev_ops->cb_strategy)(bp);
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

		bp->b_blkno =
		lblp->pmap[FDISK_OFFSET+lblp->uidx].p_start+backup_block;
		bp->b_flags = B_WRITE | B_BUSY;

		(*dev_ops->cb_strategy)(bp);
		(void) biowait(bp);

		backup_block += 2;
	}
	return (0);
}



void
dsklbl_ondsklabel_to_vtoc(dsk_label_t *lblp, struct vtoc *vtocp)
{
#if defined(_SUNOS_VTOC_16)
	bcopy((caddr_t)&lblp->ondsklbl.dkl_vtoc, (caddr_t)vtocp,
		sizeof (*vtocp));
#elif defined(_SUNOS_VTOC_8)
	int i;
	long nblks;
	struct dk_map2 *lpart;
	struct dk_map	*lmap;
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
	vtocp->v_sectorsz = NBPSCTR; 	/* sector size in bytes */

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
dsklbl_vtoc_to_ondsklabel(dsk_label_t *lblp, struct vtoc *vtocp)
{
#if defined(_SUNOS_VTOC_16)
	bcopy((caddr_t)vtocp, (caddr_t)&(lblp->ondsklbl.dkl_vtoc),
							sizeof (*vtocp));
#elif defined(_SUNOS_VTOC_8)
	/*
	 * Put appropriate vtoc structure fields into the disk label
	 *
	 */
	int i;
	long nblks;
	struct dk_map2 *lpart;
	struct dk_map	*lmap;
	struct partition *vpart;
	register struct dk_label *dp;

	/*
	 * Data is originated from vtoc. One copy of the data is stored in
	 * lblp->ondsklbl. This is what we think of as the copy of the label
	 * on this disk held in memory. The other copy (to the lbp) is to be
	 * written out to the disk.
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

#else
#error No VTOC format defined.
#endif

	lblp->ondsklbl.dkl_cksum = 0;
	(void) dsklbl_chk(&lblp->ondsklbl, &(lblp->ondsklbl.dkl_cksum));
}

void
dsklbl_dgtoug(struct dk_geom *up, struct dk_label *dp)
{
	DEBUGF(1, (CE_CONT, "?dsklbl_dgtoug:  pcyl = %d ncyl = %d acyl = %d\n",
		dp->dkl_pcyl, dp->dkl_ncyl, dp->dkl_acyl));

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
dsklbl_ugtodg(struct dk_geom *up, struct dk_label *dp)
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
