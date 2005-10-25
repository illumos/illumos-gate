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

/*
 * Sun Disk Label routines.
 */

#include <sys/dktp/cm.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/file.h>
#include <sys/dktp/dadkio.h>

#include <sys/dktp/fdisk.h>

#include <sys/dktp/bbh.h>
#include <sys/dktp/tgdk.h>
#include <sys/dktp/dklb.h>
#include <sys/dktp/snlb.h>

#include <sys/scsi/generic/inquiry.h>

/*
 * Local Function Prototypes
 */
static int  snlb_rdvtoc(struct sn_label *snlbp);
static int  snlb_wrvtoc(struct sn_label *snlbp, struct vtoc32 *vtocp);
static int  snlb_chk(struct dk_label *lbp, unsigned short *sum);
static void snlb_savelb(register struct dk_label *lbp, struct sn_label *snlbp);
static void snlb_preplb(struct sn_label *snlbp, int uidx);
static void snlb_getgeom(struct sn_label *snlbp);
static void snlb_chgmap(struct sn_label *snlbp, struct dk_map *map);
static void snlb_getmap(struct sn_label *snlbp, struct dk_map *map);
static int  snlb_get_altsctr(struct sn_label *snlbp);
static int  snlb_bsearch(struct alts_ent *buf, int cnt, daddr_t key);
static void snlb_setalts_idx(struct sn_label *snlbp);
static void snlb_free_alts(struct sn_label *snlbp);
static void snlb_dgtoug(struct dk_geom *up, struct dk_label *dp);
static void snlb_ugtodg(struct dk_geom *up, struct dk_label *dp);

static int  snlb_init(opaque_t bbh_data, opaque_t dkobjp, void *lkarg);
static int  snlb_free(struct dklb_obj *lbobjp);
static int  snlb_has_max_chs_vals(struct ipart *fdp);
static int  snlb_open(opaque_t bbh_data, dev_t dev, dev_info_t *dip);
static int  snlb_ioctl(opaque_t bbh_data, int cmd, intptr_t arg, int flag,
    cred_t *cred_p, int *rval_p);
static void snlb_partinfo(opaque_t bbh_data, daddr_t *lblksrt, long *lblkcnt,
    int part);
static void snlb_setup_devid(struct sn_label *snlbp,
    boolean_t have_unix_partition);
static int  snlb_make_devid_from_serial(struct sn_label *snlbp);
static int  snlb_read_devid(struct sn_label *snlbp);
static int  snlb_write_devid(struct sn_label *snlbp);
static int  snlb_fabricate_devid(struct sn_label *snlbp);
static daddr_t snlb_compute_devid_block(struct sn_label *snlbp);
static int  snlb_get_ioctl_string(struct sn_label *snlbp, int ioccmd, char *buf,
    int len);

struct 	dklb_objops snlb_ops = {
	snlb_init,
	snlb_free,
	snlb_open,
	snlb_ioctl,
	snlb_partinfo,
	0, 0
};

static opaque_t snlb_bbh_gethandle(opaque_t bbh_data, struct buf *bp);
static bbh_cookie_t snlb_bbh_htoc(opaque_t bbh_data, opaque_t handle);
static void snlb_bbh_freehandle(opaque_t bbh_data, opaque_t handle);

static struct bbh_objops snlb_bbh_ops = {
	nulldev,
	nulldev,
	snlb_bbh_gethandle,
	snlb_bbh_htoc,
	snlb_bbh_freehandle,
	0, 0
};

/*
 * Local static data
 */
#ifdef	SNLB_DEBUG
#define	DENT	0x0001
#define	DERR	0x0002
#define	DIO	0x0004
#define	DXALT	0x0008
#define	DXDEVID	0x0010
int	snlb_debug = DERR|DIO|DXDEVID;
#endif	/* SNLB_DEBUG */

/*
 * This is the driver loadable module wrapper.
 */

#include <sys/modctl.h>

static struct modlmisc modlmisc = {
	&mod_miscops,	/* Type of module */
	"Solaris Disk Label Object %I%"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
#ifdef SNLB_DEBUG
	if (snlb_debug & DENT)
		PRF("snlb_fini: call\n");
#endif
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

#ifdef SNLB_DEBUG
void
snlb_mprint(struct dkl_partition *pp)
{
	int i;

	if (snlb_debug & DIO) {
		for (i = 0; i < SNDKMAP; i++, pp++) {
			if (pp->p_size) {
				PRF("DISK PART[%d]: start= 0x%x size= 0x%x\n",
				    i, pp->p_start, pp->p_size);
			}
		}
	}
}
#endif

struct dklb_obj *
snlb_create()
{
	struct	dklb_obj *lbobjp;
	struct	sn_label *snlbp;

	lbobjp = kmem_zalloc((sizeof (*lbobjp) + sizeof (*snlbp)), KM_SLEEP);

	snlbp = (struct sn_label *)(lbobjp + 1);
	lbobjp->lb_data = (opaque_t)snlbp;
	lbobjp->lb_ops = (struct dklb_objops *)&snlb_ops;
	lbobjp->lb_ext = &(lbobjp->lb_extblk);
	snlbp->s_extp = &(lbobjp->lb_extblk);
	return (lbobjp);
}

static int
snlb_init(opaque_t bbh_data, opaque_t dkobjp, void *lkarg)
{
	struct sn_label *snlbp = (struct sn_label *)bbh_data;

	snlbp->s_dkobjp = (opaque_t)dkobjp;
	snlbp->s_extp->lb_numpart = 2*SNDKMAP;

	mutex_init(&snlbp->s_mutex, NULL, MUTEX_DRIVER, lkarg);
	rw_init(&snlbp->s_rw_mutex, NULL, RW_DRIVER, lkarg);
	return (DDI_SUCCESS);
}

static int
snlb_free(struct dklb_obj *lbobjp)
{
	struct sn_label *snlbp;

	snlbp = (struct sn_label *)(lbobjp->lb_data);

	ddi_devid_unregister(snlbp->s_dip);
	if (snlbp->s_devid != NULL) {
		ddi_devid_free(snlbp->s_devid);
		snlbp->s_devid = NULL;
	}

	if (snlbp->s_dkobjp) {
		mutex_destroy(&snlbp->s_mutex);
		rw_destroy(&snlbp->s_rw_mutex);
	}

	/* free the alt sector map data */
	snlb_free_alts(snlbp);

	if (snlbp->s_dkobjp)
		TGDK_CLEANUP(snlbp->s_dkobjp);

	kmem_free(lbobjp, (sizeof (*lbobjp)+sizeof (*snlbp)));
	return (DDI_SUCCESS);
}

/*
 * snlb_reopen:
 * The actual work of "opening" the disk label driver is done here.
 * Called from snlb_open and from snlb_ioctl when the disk label and
 * vtoc need to be re-read.
 * Always called with snlbp->s_mutex held.
 */

static int
snlb_reopen(struct sn_label *snlbp)
{
	struct sn_lbdata *sdp;
	struct ipart	*fdp;
	tgdk_iob_handle	handle;
	struct mboot	*mbp;
	int		i;
	int		uidx;
	int		lba;

	ASSERT(MUTEX_HELD(&snlbp->s_mutex));
	sdp = (struct sn_lbdata *)&(snlbp->s_data);

	rw_enter(&snlbp->s_rw_mutex, RW_WRITER);
	/* free the old alt sector map data */
	snlb_free_alts(snlbp);
	/* clear the stale label info */
	bzero((caddr_t)sdp, sizeof (struct sn_lbdata));
	rw_exit(&snlbp->s_rw_mutex);

	/* let the slice representing the whole disk to become valid */
	snlb_getgeom(snlbp);	/* initialize the geometry value */
	sdp->s_fpart[SNFPART_WHOLE].p_start = 0;
	sdp->s_fpart[SNFPART_WHOLE].p_size  = sdp->s_capacity;

	/* assume no fdisk, thus UNIX fdisk partition start at 0 */
	sdp->s_ustart = 0;

	/* read the label */
	handle = TGDK_IOB_ALLOC(snlbp->s_dkobjp, PCFDISK, NBPSCTR, KM_SLEEP);
	if (!handle)
		return (DDI_FAILURE);
	mbp = (struct mboot *)TGDK_IOB_RD(snlbp->s_dkobjp, handle);

	/*
	 * Check for lba support before verifying sig; sig might not be
	 * there, say on a blank disk, but the max_chs mark may still
	 * be present
	 * First, check for lba-access-ok on root node (searching to prom).
	 */

	lba = 0;
	if (ddi_getprop(DDI_DEV_T_ANY, ddi_root_node(), 0,
	    "lba-access-ok", 0) != 0) {
		lba = 1;
	} else {
		if (mbp) {
			fdp = (struct ipart *)&(mbp->parts[0]);
			for (i = 1; i <= FD_NUMPART; i++, fdp++)
				lba = (lba || snlb_has_max_chs_vals(fdp));
		}
	}

	/*
	 * Next, look for 'no-bef-lba-access' prop on parent.
	 * Its presence means the realmode driver doesn't support
	 * LBA, so the target driver shouldn't advertise it as ok.
	 * This should be a temporary condition; one day all
	 * BEFs should support the LBA access functions.
	 */

	if (lba && (ddi_getprop(DDI_DEV_T_ANY, ddi_get_parent(snlbp->s_dip),
	    DDI_PROP_DONTPASS, "no-bef-lba-access", 0) != 0)) {
		/* BEF doesn't support LBA; don't advertise it as ok */
		lba = 0;
	}

	if (lba) {
		if (ddi_getprop(snlbp->s_dev, snlbp->s_dip, DDI_PROP_DONTPASS,
		    "lba-access-ok", 0) == 0) {
			/* not found; create it */
			if (ddi_prop_create(snlbp->s_dev,
			    snlbp->s_dip, 0, "lba-access-ok",
			    (caddr_t)NULL, 0) != DDI_PROP_SUCCESS) {
				cmn_err(CE_CONT,
				    "?snlb: Can't create lba property "
				    "for instance %d\n",
				    ddi_get_instance(snlbp->s_dip));
			}
		}
	}

	/* check label */
	if (!mbp || mbp->signature != MBB_MAGIC) {
		/* DOS label missing - go for vtoc in block 1 */
		TGDK_IOB_FREE(snlbp->s_dkobjp, handle);
		if (snlb_rdvtoc(snlbp) == DDI_FAILURE)
			snlb_preplb(snlbp, 0);
		snlb_setup_devid(snlbp, B_TRUE);
		return (DDI_SUCCESS);
	}

	/* have a DOS label - use it */
	fdp = (struct ipart *)&(mbp->parts[0]);

	/* look for a Solaris partition in the DOS mboot record */
	uidx = -1;
	for (i = 1; i <= FD_NUMPART; i++, fdp++)  {
		if (!fdp->numsect)
			continue;
		sdp->s_fpart[i].p_start = fdp->relsect;
		sdp->s_fpart[i].p_size  = fdp->numsect;

		if (fdp->systid == SUNIXOS || fdp->systid == SUNIXOS2) {
			if (uidx == -1)
				uidx = i;
			else if (fdp->bootid == ACTIVE)
				uidx = i;
		}
	}

	TGDK_IOB_FREE(snlbp->s_dkobjp, handle);

	if (uidx == -1) {
		/* no UNIX partition, can't slice */
		snlb_setup_devid(snlbp, B_FALSE);
		return (DDI_SUCCESS);
	}

#ifdef SNLB_DEBUG
	if (snlb_debug & DIO) {
		PRF("snlb_reopen: FDISK partitions\n");
		snlb_mprint((struct dkl_partition *)sdp->s_fpart);
	}
#endif

	/* have a solaris partition - get vtoc from it */
	sdp->s_ustart   = sdp->s_fpart[uidx].p_start;
	sdp->s_capacity = sdp->s_fpart[uidx].p_size;
	if (snlb_rdvtoc(snlbp) == DDI_FAILURE)
		snlb_preplb(snlbp, uidx);

	snlb_setup_devid(snlbp, B_TRUE);
	return (DDI_SUCCESS);
}

/* max CHS values, as they are encoded into bytes, for 1022/254/63 */
#define	LBA_MAX_SECT	(63 | ((1022 & 0x300) >> 2))
#define	LBA_MAX_CYL	(1022 & 0xFF)
#define	LBA_MAX_HEAD	(254)

static int
snlb_has_max_chs_vals(struct ipart *fdp)
{
	return (fdp->begcyl == LBA_MAX_CYL &&
	    fdp->beghead == LBA_MAX_HEAD &&
	    fdp->begsect == LBA_MAX_SECT &&
	    fdp->endcyl == LBA_MAX_CYL &&
	    fdp->endhead == LBA_MAX_HEAD &&
	    fdp->endsect == LBA_MAX_SECT);
}

static int
snlb_open(opaque_t bbh_data, dev_t dev, dev_info_t *dip)
{
	int	rc;
	struct sn_label *snlbp = (struct sn_label *)bbh_data;

	snlbp->s_dev = dev;
	snlbp->s_dip = dip;
	mutex_enter(&snlbp->s_mutex);
	rc = snlb_reopen(snlbp);
	mutex_exit(&snlbp->s_mutex);
	return (rc);
}

static void
snlb_preplb(struct sn_label *snlbp, int uidx)
{
	struct	sn_lbdata *sdp = (struct  sn_lbdata *)&snlbp->s_data;
	struct	tgdk_geom phyg;
	struct	scsi_inquiry *inqp;
	long	disksize;

	TGDK_GETPHYGEOM(snlbp->s_dkobjp, &phyg);

	sdp->s_dklb.dkl_pcyl = sdp->s_fpart[uidx].p_size /
	    (phyg.g_head * phyg.g_sec);
	sdp->s_dklb.dkl_acyl = 2;
	sdp->s_dklb.dkl_ncyl = sdp->s_dklb.dkl_pcyl - sdp->s_dklb.dkl_acyl;
	disksize = sdp->s_dklb.dkl_ncyl * (phyg.g_head * phyg.g_sec);

	/*
	 * If CD-ROM, special-case:
	 *  - lie about head/sect/cyl to get at every block on the disk
	 *  - add full disk as slices 0 and 2 to the label
	 */

	if (TGDK_INQUIRY(snlbp->s_dkobjp, (opaque_t *)&inqp) == DDI_SUCCESS &&
	    (inqp->inq_dtype & DTYPE_MASK) == DTYPE_RODIRECT) {

		/*
		 * Not heads * sectors * cyls, but the whole thing
		 * This applies later, to s2, as well.
		 */
		disksize = sdp->s_capacity;

		sdp->s_dklb.dkl_nhead = 1;
		sdp->s_dklb.dkl_nsect = 1;
		sdp->s_dklb.dkl_rpm = 200;

		sdp->s_dklb.dkl_vtoc.v_part[0].p_start = 0;
		sdp->s_dklb.dkl_vtoc.v_part[0].p_size  = disksize;
		sdp->s_dklb.dkl_vtoc.v_part[0].p_tag = V_BACKUP;
		sdp->s_dklb.dkl_vtoc.v_part[0].p_flag = V_UNMNT;
	} else {
		/* non-CD-ROM disks */
		sdp->s_dklb.dkl_nhead 	= phyg.g_head;
		sdp->s_dklb.dkl_nsect 	= phyg.g_sec;

		sdp->s_dklb.dkl_rpm	= 3600;
		sdp->s_dklb.dkl_vtoc.v_sectorsz	= NBPSCTR;

		/* Add boot disk slice as slice 8 to the disk */

		sdp->s_dklb.dkl_vtoc.v_part[8].p_start = 0;
		sdp->s_dklb.dkl_vtoc.v_part[8].p_size  =
						phyg.g_head * phyg.g_sec;
		sdp->s_dklb.dkl_vtoc.v_part[8].p_tag = V_BOOT;
		sdp->s_dklb.dkl_vtoc.v_part[8].p_flag = V_UNMNT;

		/* Add Alternates disk slice as slice 9 to the disk */

		sdp->s_dklb.dkl_vtoc.v_part[9].p_start =
		    phyg.g_head * phyg.g_sec;
		sdp->s_dklb.dkl_vtoc.v_part[9].p_size  =
		    2 * phyg.g_head * phyg.g_sec;
		sdp->s_dklb.dkl_vtoc.v_part[9].p_tag = V_ALTSCTR;
		sdp->s_dklb.dkl_vtoc.v_part[9].p_flag = 0;
	}

	sdp->s_dklb.dkl_intrlv	= 1;
	sdp->s_dklb.dkl_apc	= 0;
	sdp->s_dklb.dkl_vtoc.v_nparts = V_NUMPAR;
	sdp->s_dklb.dkl_magic	= DKL_MAGIC;

	/* Add full disk slice as slice 2 to the disk */

	sdp->s_dklb.dkl_vtoc.v_part[SNUSLICE_WHOLE].p_start = 0;
	sdp->s_dklb.dkl_vtoc.v_part[SNUSLICE_WHOLE].p_size  = disksize;
	sdp->s_dklb.dkl_vtoc.v_part[SNUSLICE_WHOLE].p_tag = V_BACKUP;
	sdp->s_dklb.dkl_vtoc.v_part[SNUSLICE_WHOLE].p_flag = V_UNMNT;

	sdp->s_dklb.dkl_vtoc.v_sanity = VTOC_SANE;
	sdp->s_dklb.dkl_vtoc.v_version = V_VERSION;


	(void) sprintf(sdp->s_dklb.dkl_vtoc.v_asciilabel,
		    "DEFAULT cyl %d alt %d hd %d sec %d",
			sdp->s_dklb.dkl_ncyl,
			sdp->s_dklb.dkl_acyl,
			sdp->s_dklb.dkl_nhead,
			sdp->s_dklb.dkl_nsect);
	(void) snlb_chk(&sdp->s_dklb, &(sdp->s_dklb.dkl_cksum));

#ifdef SNLB_DEBUG
	if (snlb_debug & DIO) {
		PRF("snlb_preplb:cyl= %d acyl= %d nhd=%d nsect= %d cap= 0x%x\n",
			sdp->s_dklb.dkl_ncyl,
			sdp->s_dklb.dkl_acyl,
			sdp->s_dklb.dkl_nhead,
			sdp->s_dklb.dkl_nsect, sdp->s_capacity);

		PRF("snlb_preplb: UNIX slices\n");
		snlb_mprint(sdp->s_dklb.dkl_vtoc.v_part);
	}
#endif
}

static int
snlb_rdvtoc(struct sn_label *snlbp)
{
	struct dk_label *lbp;
	tgdk_iob_handle	handle;
	struct	sn_lbdata *sdp = (struct  sn_lbdata *)&(snlbp->s_data);
	unsigned short	sum;
	struct	bbh_obj *bbhobjp;

	/* read the label */
	handle = TGDK_IOB_ALLOC(snlbp->s_dkobjp, sdp->s_ustart+SNVTOC, NBPSCTR,
	    KM_SLEEP);
	if (!handle)
		return (DDI_FAILURE);
	lbp = (struct dk_label *)TGDK_IOB_RD(snlbp->s_dkobjp, handle);

	/* check label */
	if ((!lbp) || (snlb_chk(lbp, &sum) == DDI_FAILURE)) {
		TGDK_IOB_FREE(snlbp->s_dkobjp, handle);
		return (DDI_FAILURE);
	}

	/* record label information */
	snlb_savelb(lbp, snlbp);

	TGDK_IOB_FREE(snlbp->s_dkobjp, handle);

	/* get alternate sector partition map */
	if (snlb_get_altsctr(snlbp) == DDI_SUCCESS) {
		bbhobjp = &(snlbp->s_bbh);
		bbhobjp->bbh_data = (opaque_t)snlbp;
		bbhobjp->bbh_ops  = &snlb_bbh_ops;
		TGDK_SET_BBHOBJ(snlbp->s_dkobjp, bbhobjp);
	}

	snlbp->s_extp->lb_flag |= DKLB_VALLB;
	return (DDI_SUCCESS);
}

static int
snlb_chk(struct dk_label *lbp, unsigned short *cksum)
{
	short 	*sp;
	short 	count;
	unsigned short	sum;

	/*  Check magic number of the label */
	if ((lbp->dkl_magic != DKL_MAGIC) ||
	    (((struct dk_vtoc *)lbp)->v_sanity != VTOC_SANE) ||
	    (((struct dk_vtoc *)lbp)->v_version != V_VERSION))
		return (DDI_FAILURE);

	/* Check the checksum of the label */
	sp = (short *)lbp;
	sum = 0;
	count = sizeof (struct dk_label) / sizeof (short);
	while (count--)  {
		sum ^= *sp++;
	}

	*cksum = sum;

	return (sum ? DDI_FAILURE : DDI_SUCCESS);
}

static void
snlb_savelb(struct dk_label *lbp, struct sn_label *snlbp)
{
	struct	sn_lbdata *sdp;

	sdp = (struct  sn_lbdata *)&(snlbp->s_data);
	/* save the disk label in memory */
	bcopy((caddr_t)lbp, (caddr_t)&(sdp->s_dklb), sizeof (*lbp));

#ifdef SNLB_DEBUG
	if (snlb_debug & DIO) {
		PRF("snlb_savelb:cyl= %d acyl= %d nhd=%d nsect= %d cap= 0x%x\n",
			sdp->s_dklb.dkl_ncyl,
			sdp->s_dklb.dkl_acyl,
			sdp->s_dklb.dkl_nhead,
			sdp->s_dklb.dkl_nsect, sdp->s_capacity);

		PRF("snlb_savelb: UNIX slices\n");
		snlb_mprint(sdp->s_dklb.dkl_vtoc.v_part);
	}
#endif
}

static void
snlb_getgeom(struct sn_label *snlbp)
{
	struct	sn_lbdata *sdp = (struct  sn_lbdata *)&snlbp->s_data;
	struct	tgdk_geom lg;

	TGDK_GETGEOM(snlbp->s_dkobjp, &lg);
	sdp->s_dklb.dkl_ncyl  	= lg.g_cyl;
	sdp->s_dklb.dkl_acyl  	= (ushort_t)lg.g_acyl;
	sdp->s_dklb.dkl_pcyl  	= lg.g_cyl + lg.g_acyl;
	sdp->s_dklb.dkl_nhead 	= lg.g_head;
	sdp->s_dklb.dkl_nsect 	= lg.g_sec;
	sdp->s_dklb.dkl_vtoc.v_sectorsz	= (ushort_t)lg.g_secsiz;
	sdp->s_capacity		= lg.g_cap;
}

static void
snlb_ugtodg(struct dk_geom *up, struct dk_label *dp)
{
	dp->dkl_pcyl   = up->dkg_pcyl;
	dp->dkl_ncyl   = up->dkg_ncyl;
	dp->dkl_acyl   = up->dkg_acyl;
	dp->dkl_bcyl   = up->dkg_bcyl;
	dp->dkl_nhead  = up->dkg_nhead;
	dp->dkl_nsect  = up->dkg_nsect;
	dp->dkl_intrlv = up->dkg_intrlv;
	dp->dkl_apc    = up->dkg_apc;
	dp->dkl_rpm    = up->dkg_rpm;
	dp->dkl_write_reinstruct = up->dkg_write_reinstruct;
	dp->dkl_read_reinstruct  = up->dkg_read_reinstruct;
}

static void
snlb_dgtoug(struct dk_geom *up, struct dk_label *dp)
{
	up->dkg_pcyl   = dp->dkl_pcyl;
	up->dkg_ncyl   = dp->dkl_ncyl;
	up->dkg_acyl   = dp->dkl_acyl;
	up->dkg_bcyl   = dp->dkl_bcyl;
	up->dkg_nhead  = dp->dkl_nhead;
	up->dkg_nsect  = dp->dkl_nsect;
	up->dkg_intrlv = dp->dkl_intrlv;
	up->dkg_apc    = dp->dkl_apc;
	up->dkg_rpm    = dp->dkl_rpm;
	up->dkg_write_reinstruct = dp->dkl_write_reinstruct;
	up->dkg_read_reinstruct  = dp->dkl_read_reinstruct;
}

/*ARGSUSED4*/
static int
snlb_ioctl(opaque_t bbh_data, int cmd, intptr_t arg, int flag,
	cred_t *cred_p, int *rval_p)
{
	struct	sn_lbdata *sdp;
	int	argsiz;
	caddr_t	data[NBPSCTR];
	int	status = ENOTTY;
	struct	sn_label *snlbp = (struct sn_label *)bbh_data;
	struct	vtoc vtoc;

	sdp = (struct  sn_lbdata *)&snlbp->s_data;
	switch (cmd) {
	case DKIOCGVTOC:
		mutex_enter(&snlbp->s_mutex);

		/* re-read the vtoc from disk */
		if (snlb_reopen(snlbp) == DDI_FAILURE) {
			mutex_exit(&snlbp->s_mutex);
			return (ENXIO);
		}

		bcopy(&sdp->s_dklb.dkl_vtoc, data,
		    sizeof (sdp->s_dklb.dkl_vtoc));
		mutex_exit(&snlbp->s_mutex);

		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
			if (ddi_copyout(&data[0], (void *)arg,
			    sizeof (struct vtoc32), flag))
				return (EFAULT);
			break;
		case DDI_MODEL_NONE:
			vtoc32tovtoc((*(struct vtoc32 *)data), vtoc);
			if (ddi_copyout(&vtoc, (void *)arg,
			    sizeof (struct vtoc), flag))
				return (EFAULT);
			break;
		}
		return (0);

	case DKIOCSVTOC:
		/*
		 * Get the vtoc from the caller, write it onto the disk
		 */
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
			if (ddi_copyin((const void *)arg, data,
			    sizeof (struct vtoc32), flag))
				return (EFAULT);
			break;

		case DDI_MODEL_NONE:
			if (ddi_copyin((const void *)arg, &vtoc,
			    sizeof (vtoc), flag))
				return (EFAULT);
			vtoctovtoc32(vtoc, (*(struct vtoc32 *)data));
			break;
		}

		mutex_enter(&snlbp->s_mutex);
		status = snlb_wrvtoc(snlbp, (struct vtoc32 *)data);
		/*
		 * If already have a devid, write it on the disk
		 * If we don't, create one and write it.
		 */
		if (snlbp->s_devid != NULL &&
		    (snlbp->s_flags & SNLB_FABID)) {
			if (snlb_write_devid(snlbp) != DDI_SUCCESS) {
				ddi_devid_free(snlbp->s_devid);
				snlbp->s_devid = NULL;
			}
		} else {
			snlb_setup_devid(snlbp, B_TRUE);
		}
		mutex_exit(&snlbp->s_mutex);
		break;

	case DKIOCG_PHYGEOM:
		{
		struct dk_geom dkg;
		struct tgdk_geom *phygp;

		phygp = (struct tgdk_geom *)data;
		TGDK_GETPHYGEOM(snlbp->s_dkobjp, phygp);

		argsiz = sizeof (struct dk_geom);
		bzero((caddr_t)&dkg, argsiz);
		dkg.dkg_ncyl  	= phygp->g_cyl;
		dkg.dkg_acyl  	= phygp->g_acyl;
		dkg.dkg_pcyl  	= phygp->g_cyl + phygp->g_acyl;
		dkg.dkg_nhead 	= phygp->g_head;
		dkg.dkg_nsect 	= phygp->g_sec;
		if (ddi_copyout((caddr_t)&dkg, (caddr_t)arg, argsiz, flag))
			return (EFAULT);
		else
			return (0);
		}

	case DKIOCG_VIRTGEOM:
		{
		struct dk_geom dkg;
		struct tgdk_geom *loggp;

		loggp = (struct tgdk_geom *)data;
		TGDK_GETGEOM(snlbp->s_dkobjp, loggp);

		/*
		 * If the controller returned us something that doesn't
		 * really fit into an Int 13/function 8 geometry
		 * result, just fail the ioctl.  See PSARC 1998/313.
		 */

		if ((loggp->g_cyl + loggp->g_acyl) > 1024)
			return (EINVAL);

		argsiz = sizeof (struct dk_geom);
		bzero((caddr_t)&dkg, argsiz);
		dkg.dkg_ncyl  	= loggp->g_cyl;
		dkg.dkg_acyl  	= loggp->g_acyl;
		dkg.dkg_pcyl  	= loggp->g_cyl + loggp->g_acyl;
		dkg.dkg_nhead 	= loggp->g_head;
		dkg.dkg_nsect 	= loggp->g_sec;
		if (ddi_copyout((caddr_t)&dkg, (caddr_t)arg, argsiz, flag))
			return (EFAULT);
		else
			return (0);
		}

	/* Return the geometry of the specified unit. */
	case DKIOCGGEOM:
		mutex_enter(&snlbp->s_mutex);

		/* re-read the vtoc from disk */
		if (snlb_reopen(snlbp) == DDI_FAILURE) {
			mutex_exit(&snlbp->s_mutex);
			return (ENXIO);
		}

		snlb_dgtoug((struct dk_geom *)data, &(sdp->s_dklb));
		mutex_exit(&snlbp->s_mutex);

		if (ddi_copyout((caddr_t)data, (caddr_t)arg,
		    sizeof (struct dk_geom), flag))
			return (EFAULT);
		else
			return (0);

	/* Set the geometry of the specified unit. */
	case DKIOCSGEOM:
		if (ddi_copyin((caddr_t)arg, (caddr_t)data,
		    sizeof (struct dk_geom), flag))
			return (EFAULT);

		mutex_enter(&snlbp->s_mutex);
		snlb_ugtodg((struct dk_geom *)data, &(sdp->s_dklb));
		mutex_exit(&snlbp->s_mutex);
		return (0);

	case DKIOCGAPART:
		mutex_enter(&snlbp->s_mutex);

		/* re-read the vtoc from disk */
		if (snlb_reopen(snlbp) == DDI_FAILURE) {
			mutex_exit(&snlbp->s_mutex);
			return (ENXIO);
		}
		snlb_getmap(snlbp, (struct dk_map *)data);
		mutex_exit(&snlbp->s_mutex);

		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct dk_map32	dk_map32[SNDKMAP];
			struct dk_map	*dk_map;
			int		i;

			dk_map = (struct dk_map *)data;
			for (i = 0; i < SNDKMAP; i++, dk_map++) {
				dk_map32[i].dkl_cylno =
				    (daddr32_t)dk_map->dkl_cylno;
				dk_map32[i].dkl_nblk =
				    (daddr32_t)dk_map->dkl_nblk;
			}
			if (ddi_copyout(&dk_map32[0], (caddr_t)arg,
			    SNDKMAP * sizeof (struct dk_map32), flag))
				return (EFAULT);
			break;
		}

		case DDI_MODEL_NONE:
			if (ddi_copyout(data, (caddr_t)arg,
			    SNDKMAP * sizeof (struct dk_map), flag))
				return (EFAULT);
		}
		return (0);

	case DKIOCSAPART:
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32: {
			struct dk_map32	dk_map32[SNDKMAP];
			struct dk_map	*dk_map;
			int		i;

			if (ddi_copyin((caddr_t)arg, (caddr_t)&dk_map32,
			    SNDKMAP * sizeof (struct dk_map32), flag))
				return (EFAULT);

			dk_map = (struct dk_map *)data;
			for (i = 0; i < SNDKMAP; i++, dk_map++) {
				dk_map->dkl_cylno = dk_map32[i].dkl_cylno;
				dk_map->dkl_nblk = dk_map32[i].dkl_nblk;
			}
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyin((caddr_t)arg, (caddr_t)data,
			    SNDKMAP * sizeof (struct dk_map), flag))
				return (EFAULT);
		}
		mutex_enter(&snlbp->s_mutex);
		snlb_chgmap(snlbp, (struct dk_map *)data);
		mutex_exit(&snlbp->s_mutex);
		return (0);

	case DKIOCADDBAD:
		/* snlb_get_altsctr(snlbp); */
		mutex_enter(&snlbp->s_mutex);
		/* re-read the vtoc from disk */
		if (snlb_reopen(snlbp) == DDI_FAILURE) {
			mutex_exit(&snlbp->s_mutex);
			return (ENXIO);
		}
		mutex_exit(&snlbp->s_mutex);
		return (0);

	default:
		break;
	}
	return (status);
}

static void
snlb_getmap(struct sn_label *snlbp, struct dk_map *map)
{
	struct	dkl_partition *pp;
	int 	i;
	int	spc;
	struct	 sn_lbdata *sdp;

	sdp = (struct  sn_lbdata *)&(snlbp->s_data);
	spc = sdp->s_dklb.dkl_nhead * sdp->s_dklb.dkl_nsect;

	pp = sdp->s_dklb.dkl_vtoc.v_part;
	for (i = 0; i < SNDKMAP; i++, pp++) {
		map[i].dkl_cylno = pp->p_start / spc;
		map[i].dkl_nblk  = (daddr_t)pp->p_size;
	}

#ifdef SNLB_DEBUG
	PRF("snlb_getmap: UNIX slices\n");
	snlb_mprint(sdp->s_dklb.dkl_vtoc.v_part);
#endif
}

static void
snlb_chgmap(struct sn_label *snlbp, struct dk_map *map)
{
	struct	dkl_partition *pp;
	int 	i;
	int	spc;
	struct	 sn_lbdata *sdp;

	sdp = (struct  sn_lbdata *)&(snlbp->s_data);
	spc = sdp->s_dklb.dkl_nhead * sdp->s_dklb.dkl_nsect;

	pp = sdp->s_dklb.dkl_vtoc.v_part;
	for (i = 0; i < SNDKMAP; i++, pp++) {
		pp->p_start = map[i].dkl_cylno * spc;
		pp->p_size  = (long)map[i].dkl_nblk;
	}

#ifdef SNLB_DEBUG
	snlb_mprint(sdp->s_dklb.dkl_vtoc.v_part);
#endif
}

static int
snlb_wrvtoc(struct sn_label *snlbp, struct vtoc32 *vtocp)
{
	struct dk_label *lbp, *dp;
	tgdk_iob_handle	handle;
	struct	sn_lbdata *sdp;
	int	status;
	int	backup_block;
	int	count;

	sdp = (struct sn_lbdata *)&(snlbp->s_data);
	dp = &sdp->s_dklb;
	handle = TGDK_IOB_ALLOC(snlbp->s_dkobjp, sdp->s_ustart+SNVTOC, NBPSCTR,
	    KM_SLEEP);
	if (!handle)
		return (ENOMEM);
	lbp = (struct dk_label *)TGDK_IOB_HTOC(snlbp->s_dkobjp, handle);
	bzero(lbp, NBPSCTR);

	lbp->dkl_pcyl   = dp->dkl_pcyl;
	lbp->dkl_ncyl   = dp->dkl_ncyl;
	lbp->dkl_acyl   = dp->dkl_acyl;
	lbp->dkl_bcyl   = dp->dkl_bcyl;
	lbp->dkl_nhead  = dp->dkl_nhead;
	lbp->dkl_nsect  = dp->dkl_nsect;
	lbp->dkl_intrlv = dp->dkl_intrlv;
	lbp->dkl_skew   = dp->dkl_skew;
	lbp->dkl_apc    = dp->dkl_apc;
	lbp->dkl_rpm    = dp->dkl_rpm;
	lbp->dkl_write_reinstruct = dp->dkl_write_reinstruct;
	lbp->dkl_read_reinstruct  = dp->dkl_read_reinstruct;
	lbp->dkl_magic = DKL_MAGIC;
	bcopy(vtocp, &lbp->dkl_vtoc, sizeof (*vtocp));

	/* check label */
	lbp->dkl_cksum = 0;
	(void) snlb_chk(lbp, &(lbp->dkl_cksum));

	lbp = (struct dk_label *)TGDK_IOB_WR(snlbp->s_dkobjp, handle);
	if (lbp) {
		bcopy(lbp, &(sdp->s_dklb), sizeof (*lbp));
		snlbp->s_extp->lb_flag |= DKLB_VALLB;
		status = 0;
	} else {
		status = EIO;
	}
	TGDK_IOB_FREE(snlbp->s_dkobjp, handle);

	if (status != 0 || dp->dkl_acyl == 0)
		return (status);

	/* DO backup copies of vtoc */
	backup_block = ((dp->dkl_ncyl + dp->dkl_acyl - 1) *
	    (dp->dkl_nhead * dp->dkl_nsect)) +
	    ((dp->dkl_nhead - 1) * dp->dkl_nsect) + 1;

	for (count = 1; count < 6; count++) {
		handle = TGDK_IOB_ALLOC(snlbp->s_dkobjp,
		    sdp->s_ustart+backup_block, NBPSCTR, KM_SLEEP);
		if (!handle)
			return (ENOMEM);
		lbp = (struct dk_label *)TGDK_IOB_HTOC(snlbp->s_dkobjp,
		    handle);

		bcopy(&sdp->s_dklb, lbp, sizeof (*lbp));

		lbp = (struct dk_label *)TGDK_IOB_WR(snlbp->s_dkobjp, handle);

		TGDK_IOB_FREE(snlbp->s_dkobjp, handle);

		if (!lbp)
			return (EIO);

		backup_block += 2;
	}

	return (0);
}

static void
snlb_partinfo(opaque_t bbh_data, daddr_t *lblksrt, long *lblkcnt, int part)
{
	struct sn_lbdata *sdp;
	struct sn_label *snlbp = (struct sn_label *)bbh_data;

	sdp = (struct sn_lbdata *)&snlbp->s_data;

	mutex_enter(&snlbp->s_mutex);
	if (part < SNDKMAP) {
		struct dkl_partition *pp;

		pp = &(sdp->s_dklb.dkl_vtoc.v_part[part]);
		*lblksrt = (daddr_t)(pp->p_start + sdp->s_ustart);
		*lblkcnt = (long)pp->p_size;
	} else {
		struct partition *pp;

		pp = &(sdp->s_fpart[part-SNDKMAP]);
		*lblksrt = (daddr_t)pp->p_start;
		*lblkcnt = (long)pp->p_size;
	}

	mutex_exit(&snlbp->s_mutex);
}

static void
snlb_free_alts(struct sn_label *snlbp)
{
	if (snlbp->s_data.s_hdl_enttbl) {
		TGDK_IOB_FREE(snlbp->s_dkobjp, snlbp->s_data.s_hdl_enttbl);
		kmem_free(snlbp->s_data.s_alts_altcount, (SNDKMAP *
		    (sizeof (long) + sizeof (struct alts_ent *))));
		snlbp->s_data.s_hdl_enttbl = NULL;
	}
}

static int
snlb_get_altsctr(struct sn_label *snlbp)
{
	tgdk_iob_handle 	hdl_altspart;
	tgdk_iob_handle 	hdl_enttbl;
	struct	dkl_partition 	*pp;
	struct	alts_parttbl	*ap;
	struct	alts_ent	*enttblp;
	int			i;
	daddr_t			ustart;
	long			alts_ent_used;

	pp = snlbp->s_data.s_dklb.dkl_vtoc.v_part;
	for (i = 0; i < SNDKMAP; i++, pp++) {
		if (pp->p_tag == V_ALTSCTR)
			break;
	}
	if (i >= SNDKMAP)
		return (DDI_FAILURE);

	ustart = snlbp->s_data.s_ustart;
	hdl_altspart = TGDK_IOB_ALLOC(snlbp->s_dkobjp, (ustart + pp->p_start),
				NBPSCTR, KM_SLEEP);
	if (!hdl_altspart)
		return (DDI_FAILURE);
	ap = (struct alts_parttbl *)TGDK_IOB_RD(snlbp->s_dkobjp, hdl_altspart);
	if (!ap || (ap->alts_sanity != ALTS_SANITY)) {
		TGDK_IOB_FREE(snlbp->s_dkobjp, hdl_altspart);
		return (DDI_FAILURE);
	}

	hdl_enttbl = TGDK_IOB_ALLOC(snlbp->s_dkobjp,
	    (ustart + pp->p_start + ap->alts_ent_base),
	    (ap->alts_ent_end - ap->alts_ent_base + 1) << SCTRSHFT, KM_SLEEP);

	alts_ent_used = ap->alts_ent_used;
	TGDK_IOB_FREE(snlbp->s_dkobjp, hdl_altspart);

	if (!hdl_enttbl)
		return (DDI_FAILURE);
	enttblp = (struct alts_ent *)TGDK_IOB_RD(snlbp->s_dkobjp, hdl_enttbl);
	if (!enttblp) {
		TGDK_IOB_FREE(snlbp->s_dkobjp, hdl_enttbl);
		return (DDI_FAILURE);
	}

	/*
	 * If we bail out before this point, the old alternate map, if it
	 * ever existed, is still intact.
	 * Now its time to destroy the old map and create a new one.
	 */
	rw_enter(&snlbp->s_rw_mutex, RW_WRITER);
	if (snlbp->s_data.s_alts_altcount == NULL) {
		snlbp->s_data.s_alts_altcount = kmem_alloc(SNDKMAP *
		    (sizeof (long) + sizeof (struct alts_ent *)), KM_SLEEP);
	}
	snlbp->s_data.s_alts_firstalt =
	    (struct alts_ent **)(snlbp->s_data.s_alts_altcount + SNDKMAP);

	snlbp->s_data.s_hdl_enttbl = hdl_enttbl;
	snlbp->s_data.s_alts_enttbl = enttblp;
	snlbp->s_data.s_alts_entused = alts_ent_used;

	snlb_setalts_idx(snlbp);
	rw_exit(&snlbp->s_rw_mutex);
	return (DDI_SUCCESS);
}

static void
snlb_setalts_idx(struct sn_label *snlbp)
{
	struct	dkl_partition 	*pp;
	struct	alts_ent	*entp;
	struct	sn_lbdata	*sdp;
	daddr_t	 ustart;
	daddr_t	 lastsec;
	int	 i, j;

	pp = snlbp->s_data.s_dklb.dkl_vtoc.v_part;
	sdp = &snlbp->s_data;
	ustart = sdp->s_ustart;
	entp = sdp->s_alts_enttbl;
	for (i = 0; i < SNDKMAP; i++) {
		sdp->s_alts_altcount[i] = 0;
		sdp->s_alts_firstalt[i] = NULL;

		if (pp[i].p_size == 0)
			continue;
		if (i == SNUSLICE_WHOLE) {
			sdp->s_alts_altcount[i] = sdp->s_alts_entused;
			sdp->s_alts_firstalt[i] = sdp->s_alts_enttbl;
			continue;
		}

		lastsec = ustart + pp[i].p_start + pp[i].p_size - 1;
		for (j = 0; j < sdp->s_alts_entused; j++) {

			/*
			 * if bad sector cluster is less than partition range
			 * then skip
			 */
			if ((entp[j].bad_start < pp[i].p_start) &&
			    (entp[j].bad_end   < pp[i].p_start))
				continue;
			/*
			 * if bad sector cluster passed the end of the
			 * partition then stop
			 */
			if (entp[j].bad_start > lastsec)
				break;
			if (!sdp->s_alts_firstalt[i]) {
				sdp->s_alts_firstalt[i] =
				    (struct alts_ent *)&entp[j];
			}
			sdp->s_alts_altcount[i]++;
		}
	}
}

/*ARGSUSED*/
static bbh_cookie_t
snlb_bbh_htoc(opaque_t bbh_data, opaque_t handle)
{
	struct	bbh_handle *hp;
	bbh_cookie_t ckp;

	hp = (struct  bbh_handle *)handle;
	ckp = hp->h_cktab + hp->h_idx;
	hp->h_idx++;
	return (ckp);
}

/*ARGSUSED*/
static void
snlb_bbh_freehandle(opaque_t bbh_data, opaque_t handle)
{
	struct	bbh_handle *hp;

	hp = (struct  bbh_handle *)handle;
	kmem_free(handle, (sizeof (struct bbh_handle) +
	    (hp->h_totck * (sizeof (struct bbh_cookie)))));
}


/*
 *	snlb_bbh_gethandle remaps the bad sectors to alternates.
 *	There are 7 different cases when the comparison is made
 *	between the bad sector cluster and the disk section.
 *
 *	bad sector cluster	gggggggggggbbbbbbbggggggggggg
 *	case 1:			   ddddd
 *	case 2:				   -d-----
 *	case 3:					     ddddd
 *	case 4:			         dddddddddddd
 *	case 5:			      ddddddd-----
 *	case 6:			           ---ddddddd
 *	case 7:			           ddddddd
 *
 *	where:  g = good sector,	b = bad sector
 *		d = sector in disk section
 *		- = disk section may be extended to cover those disk area
 */

static opaque_t
snlb_bbh_gethandle(opaque_t bbh_data, struct buf *bp)
{
	struct	sn_label *snlbp = (struct sn_label *)bbh_data;
	struct	sn_lbdata *sdp;
	struct	bbh_handle *hp;
	struct	bbh_cookie *ckp;
	struct	alts_ent *altp;
	long	alts_used;
	long	part = SNLB_PART(bp->b_edev);
	daddr_t	lastsec;
	long	d_count;
	int	i;
	int	idx;
	int	cnt;

	if (part >= V_NUMPAR)
		return (NULL);
	rw_enter(&snlbp->s_rw_mutex, RW_READER);
	sdp = &snlbp->s_data;
	if (!sdp->s_hdl_enttbl || !(alts_used = sdp->s_alts_altcount[part])) {
		rw_exit(&snlbp->s_rw_mutex);
		return (NULL);
	}
	altp = sdp->s_alts_firstalt[part];

	/*
	 * binary search for the largest bad sector index in the alternate
	 * entry table which overlaps or larger than the starting d_sec
	 */
	i = snlb_bsearch(altp, alts_used, GET_BP_SEC(bp));
	/* if starting sector is > the largest bad sector, return */
	if (i == -1) {
		rw_exit(&snlbp->s_rw_mutex);
		return (NULL);
	}
	/* i is the starting index.  Set altp to the starting entry addr */
	altp += i;

	d_count = bp->b_bcount >> SCTRSHFT;
	lastsec = GET_BP_SEC(bp) + d_count - 1;

	/* calculate the number of bad sectors */
	for (idx = i, cnt = 0; idx < alts_used; idx++, altp++, cnt++) {
		if (lastsec < altp->bad_start)
			break;
	}

	if (!cnt) {
		rw_exit(&snlbp->s_rw_mutex);
		return (NULL);
	}

	/* calculate the maximum number of reserved cookies */
	cnt <<= 1;
	cnt++;

	/* allocate the handle */
	hp = (struct bbh_handle *)kmem_zalloc((sizeof (*hp) +
	    (cnt * sizeof (*ckp))), KM_SLEEP);

	hp->h_idx = 0;
	hp->h_totck = cnt;
	ckp = hp->h_cktab = (struct bbh_cookie *)(hp + 1);
	ckp[0].ck_sector = GET_BP_SEC(bp);
	ckp[0].ck_seclen = d_count;

	altp = sdp->s_alts_firstalt[part];
	altp += i;
	for (idx = 0; i < alts_used; i++, altp++) {
		/* CASE 1: */
		if (lastsec < altp->bad_start)
			break;

		/* CASE 3: */
		if (ckp[idx].ck_sector > altp->bad_end)
			continue;

		/* CASE 2 and 7: */
		if ((ckp[idx].ck_sector >= altp->bad_start) &&
		    (lastsec <= altp->bad_end)) {
#ifdef SNLB_DEBUG
			if (snlb_debug & DXALT) {
				printf("snlb_bbh_gethandle: CASE 2 & 7 \n");
			}
#endif
			ckp[idx].ck_sector = altp->good_start +
			    ckp[idx].ck_sector - altp->bad_start;
			break;
		}

		/* at least one bad sector in our section.  break it. */
		/* CASE 5: */
		if ((lastsec >= altp->bad_start) &&
			    (lastsec <= altp->bad_end)) {
#ifdef SNLB_DEBUG
			if (snlb_debug & DXALT) {
				printf("snlb_bbh_gethandle: CASE 5 \n");
			}
#endif
			ckp[idx+1].ck_seclen = lastsec - altp->bad_start + 1;
			ckp[idx].ck_seclen -= ckp[idx+1].ck_seclen;
			ckp[idx+1].ck_sector = altp->good_start;
			break;
		}
		/* CASE 6: */
		if ((ckp[idx].ck_sector <= altp->bad_end) &&
		    (ckp[idx].ck_sector >= altp->bad_start)) {
#ifdef SNLB_DEBUG
			if (snlb_debug & DXALT) {
				printf("snlb_bbh_gethandle: CASE 6 \n");
			}
#endif
			ckp[idx+1].ck_seclen = ckp[idx].ck_seclen;
			ckp[idx].ck_seclen = altp->bad_end -
			    ckp[idx].ck_sector + 1;
			ckp[idx+1].ck_seclen -= ckp[idx].ck_seclen;
			ckp[idx].ck_sector = altp->good_start +
			    ckp[idx].ck_sector - altp->bad_start;
			idx++;
			ckp[idx].ck_sector = altp->bad_end + 1;
			continue;	/* check rest of section */
		}

		/* CASE 4: */
#ifdef SNLB_DEBUG
		if (snlb_debug & DXALT) {
			printf("snlb_bbh_gethandle: CASE 4\n");
		}
#endif
		ckp[idx].ck_seclen = altp->bad_start - ckp[idx].ck_sector;
		ckp[idx+1].ck_sector = altp->good_start;
		ckp[idx+1].ck_seclen = altp->bad_end - altp->bad_start + 1;
		idx += 2;
		ckp[idx].ck_sector = altp->bad_end + 1;
		ckp[idx].ck_seclen = lastsec - altp->bad_end;
	}

#ifdef SNLB_DEBUG
	if (snlb_debug & DXALT) {
		for (i = 0; i < hp->h_totck && ckp[i].ck_seclen; i++) {
			PRF("snlb_bbh_gethandle: [%d]", i);
			PRF(" sector= %d count= %d \n",
			    ckp[i].ck_sector, ckp[i].ck_seclen);
		}
	}
#endif
	rw_exit(&snlbp->s_rw_mutex);
	return ((opaque_t)hp);
}

static int
snlb_bsearch(struct alts_ent *buf, int cnt, daddr_t key)
{
	int	i;
	int	ind;
	int	interval;
	int	mystatus = -1;

	if (!cnt)
		return (mystatus);

	ind = 1; /* compiler complains about possible uninitialized var	*/
	for (i = 1; i <= cnt; i <<= 1)
		ind = i;

	for (interval = ind; interval; ) {
		if ((key >= buf[ind-1].bad_start) &&
		    (key <= buf[ind-1].bad_end)) {
			return (ind-1);
		} else {
			interval >>= 1;
			if (key < buf[ind-1].bad_start) {
				/* record the largest bad sector index */
				mystatus = ind-1;
				if (!interval)
					break;
				ind = ind - interval;
			} else {
				/*
				 * if key is larger than the last element
				 * then break
				 */
				if ((ind == cnt) || !interval)
					break;
				if ((ind+interval) <= cnt)
					ind += interval;
			}
		}
	}
	return (mystatus);
}


/*
 * Create (if necessary) and register the devid.
 * There are 4 different ways we can get a device id:
 *    1. Already have one - nothing to do
 *    2. Build one from the drive's model and serial numbers
 *    3. Read one from the disk (first sector of last track)
 *    4. Fabricate one and write it on the disk.
 * If any of these succeeds, register the deviceid
 * Must be holding snlbp->s_mutex when this routine is called.
 */

void
snlb_setup_devid(struct sn_label *snlbp, boolean_t have_unix_partition)
{
	int	rc;

	/* Try options until one succeeds, or all have failed */

	/* 1. All done if already registered */
	if (snlbp->s_devid != NULL)
		return;

	/* 2. Build a devid from the model and serial number, if present */
	rc = snlb_make_devid_from_serial(snlbp);
	if (rc != DDI_SUCCESS) {
		/* Can't read or write the devid if no unix partition */
		if (!have_unix_partition)
			return;

		/* 3. Read devid from the disk, if present */
		rc = snlb_read_devid(snlbp);

		/* 4. otherwise make one up and write it on the disk */
		if (rc != DDI_SUCCESS)
			rc = snlb_fabricate_devid(snlbp);
	}

	/* If we managed to get a devid any of the above ways, register it */
	if (rc == DDI_SUCCESS)
		(void) ddi_devid_register(snlbp->s_dip, snlbp->s_devid);

}

/*
 * Test for a valid model or serial number. Assume that a valid representation
 * contains at least one character that is neither a space, 0 digit, or NULL.
 * Trim trailing blanks and NULLS from returned length.
 */
static void
snlb_validate_model_serial(char *str, int *retlen, int totallen)
{
	char		ch;
	boolean_t	ret = B_FALSE;
	int		i;
	int		tb;

	for (i = 0, tb = 0; i < totallen; i++) {
		ch = *str++;
		if ((ch != ' ') && (ch != '\0') && (ch != '0'))
			ret = B_TRUE;
		if ((ch == ' ') || (ch == '\0'))
			tb++;
		else
			tb = 0;
	}

	if (ret == B_TRUE) {
		/* Atleast one non 0 or blank character. */
		*retlen = totallen - tb;
	} else {
		*retlen = 0;
	}
}


/*
 * Build a devid from the model and serial number, if present
 * Return DDI_SUCCESS or DDI_FAILURE.
 */
static int
snlb_make_devid_from_serial(struct sn_label *snlbp)
{
	int	rc = DDI_SUCCESS;
	char	*hwid;
	char	*model = NULL;
	int	amodel_len;
	int	model_len;
	char	*serno = NULL;
	int	aserno_len;
	int	serno_len;
	int	total_len;

	/*
	 * Initialize the model and serial number information.
	 * First make the ioctl calls to get the required lengths,
	 * then allocate and make ioctl calls to get the information.
	 */
	amodel_len = snlb_get_ioctl_string(snlbp, DIOCTL_GETMODEL, NULL, 0);
	model = kmem_alloc(amodel_len + 1, KM_SLEEP);
	(void) snlb_get_ioctl_string(snlbp, DIOCTL_GETMODEL, model,
	    amodel_len + 1);
	aserno_len = snlb_get_ioctl_string(snlbp, DIOCTL_GETSERIAL, NULL, 0);
	serno = kmem_alloc(aserno_len + 1, KM_SLEEP);
	(void) snlb_get_ioctl_string(snlbp, DIOCTL_GETSERIAL, serno,
	    aserno_len + 1);

	/* Verify the model and serial number */
	snlb_validate_model_serial(model, &model_len, amodel_len);
	if (model_len == 0) {
		rc = DDI_FAILURE;
		goto out;
	}
	snlb_validate_model_serial(serno, &serno_len, aserno_len);
	if (serno_len == 0) {
		rc = DDI_FAILURE;
		goto out;
	}

	/*
	 * The device ID will be concatenation of the model number,
	 * the '=' separator, the serial number. Allocate
	 * the string and concatenate the components.
	 */
	total_len = model_len + 1 + serno_len;
	hwid = kmem_alloc(total_len, KM_SLEEP);
	bcopy((caddr_t)model, (caddr_t)hwid, model_len);
	bcopy((caddr_t)"=", (caddr_t)&hwid[model_len], 1);
	bcopy((caddr_t)serno, (caddr_t)&hwid[model_len + 1], serno_len);

	/* Initialize the device ID, trailing NULL not included */
	rc = ddi_devid_init(snlbp->s_dip, DEVID_ATA_SERIAL, total_len,
	    hwid, (ddi_devid_t *)&snlbp->s_devid);

	/* Free the allocated string */
	kmem_free(hwid, total_len);

	if (rc == DDI_SUCCESS)
		snlbp->s_flags |= SNLB_HWID;

out:	if (model)
		kmem_free(model, amodel_len + 1);
	if (serno)
		kmem_free(serno, aserno_len + 1);
	return (rc);
}

/*
 * Read a devid from on the first block of the last track of
 * the last cylinder.  Make sure what we read is a valid devid.
 * Return DDI_SUCCESS or DDI_FAILURE.
 */
static int
snlb_read_devid(struct sn_label *snlbp)
{
	daddr_t	blk;
	struct dk_devid *dkdevidp;
	uint_t *ip;
	int chksum;
	int i, sz;
	tgdk_iob_handle	handle;

	blk = snlb_compute_devid_block(snlbp);
	if (blk < 0)
		return (DDI_FAILURE);

	/* read the devid */
	handle = TGDK_IOB_ALLOC(snlbp->s_dkobjp, blk, NBPSCTR, KM_SLEEP);
	if (!handle)
		return (DDI_FAILURE);
	dkdevidp = (struct dk_devid *)TGDK_IOB_RD(snlbp->s_dkobjp, handle);

	if (dkdevidp == NULL) {
		TGDK_IOB_FREE(snlbp->s_dkobjp, handle);
		return (DDI_FAILURE);
	}

	/* Validate the revision */
	if ((dkdevidp->dkd_rev_hi != DK_DEVID_REV_MSB) ||
	    (dkdevidp->dkd_rev_lo != DK_DEVID_REV_LSB)) {
		TGDK_IOB_FREE(snlbp->s_dkobjp, handle);
		return (DDI_FAILURE);
	}

	/* Calculate the checksum */
	chksum = 0;
	ip = (uint_t *)dkdevidp;
	for (i = 0; i < ((NBPSCTR - sizeof (int))/sizeof (int)); i++)
		chksum ^= ip[i];

	/* Compare the checksums */
	if (DKD_GETCHKSUM(dkdevidp) != chksum) {
		TGDK_IOB_FREE(snlbp->s_dkobjp, handle);
		return (DDI_FAILURE);
	}

	/* Validate the device id */
	if (ddi_devid_valid((ddi_devid_t)dkdevidp->dkd_devid) != DDI_SUCCESS) {
		TGDK_IOB_FREE(snlbp->s_dkobjp, handle);
		return (DDI_FAILURE);
	}

	/* keep a copy of the device id */
	sz = ddi_devid_sizeof((ddi_devid_t)dkdevidp->dkd_devid);
	snlbp->s_devid = kmem_alloc(sz, KM_SLEEP);
	bcopy(dkdevidp->dkd_devid, snlbp->s_devid, sz);

	TGDK_IOB_FREE(snlbp->s_dkobjp, handle);
	snlbp->s_flags |= SNLB_FABID;
	return (DDI_SUCCESS);
}

/*
 * Write a devid on the first block of the last track of the last cylinder.
 * Return DDI_SUCCESS or DDI_FAILURE.
 * Must be holding snlbp->s_mutex when this routine is called.
 */
static int
snlb_write_devid(struct sn_label *snlbp)
{
	daddr_t		blk;
	tgdk_iob_handle	handle;
	struct dk_devid	*dkdevidp;
	uint_t	*ip, chksum;
	int	i;

	blk = snlb_compute_devid_block(snlbp);
	if (blk < 0)
		return (DDI_FAILURE);

	handle = TGDK_IOB_ALLOC(snlbp->s_dkobjp, blk, NBPSCTR, KM_SLEEP);
	if (!handle)
		return (DDI_FAILURE);

	/* Locate the buffer */
	dkdevidp = (struct dk_devid *)TGDK_IOB_HTOC(snlbp->s_dkobjp, handle);

	/* Fill in the revision */
	dkdevidp->dkd_rev_hi = DK_DEVID_REV_MSB;
	dkdevidp->dkd_rev_lo = DK_DEVID_REV_LSB;

	/* Copy in the device id */
	bcopy(snlbp->s_devid, dkdevidp->dkd_devid, DK_DEVID_SIZE);

	/* Calculate the chksum */
	chksum = 0;
	ip = (uint_t *)dkdevidp;
	for (i = 0; i < ((NBPSCTR - sizeof (int))/sizeof (int)); i++)
		chksum ^= ip[i];

	/* Fill in the checksum */
	DKD_FORMCHKSUM(chksum, dkdevidp);

/*	write the devid							*/
	(void) TGDK_IOB_WR(snlbp->s_dkobjp, handle);

	TGDK_IOB_FREE(snlbp->s_dkobjp, handle);
	return (DDI_SUCCESS);
}

/*
 * Create a devid and write it on the first block of the last track of
 * the last cylinder.
 * Return DDI_SUCCESS or DDI_FAILURE.
 * Must be holding snlbp->s_mutex when this routine is called.
 */
static int
snlb_fabricate_devid(struct sn_label *snlbp)
{
	ddi_devid_t	devid;	/* temporary until success */
	daddr_t		blk;
	tgdk_iob_handle	handle;
	struct dk_devid	*dkdevidp;
	caddr_t	outp;
	uint_t	*ip, chksum;
	int	i;
	int	rc;

	rc = ddi_devid_init(snlbp->s_dip, DEVID_FAB, 0, NULL, &devid);
	if (rc != DDI_SUCCESS)
		return (rc);

	blk = snlb_compute_devid_block(snlbp);
	if (blk < 0)
		return (DDI_FAILURE);

	handle = TGDK_IOB_ALLOC(snlbp->s_dkobjp, blk, NBPSCTR, KM_SLEEP);
	if (!handle)
		return (DDI_FAILURE);

	/* Locate the buffer */
	dkdevidp = (struct dk_devid *)TGDK_IOB_HTOC(snlbp->s_dkobjp, handle);

	/* Fill in the revision */
	dkdevidp->dkd_rev_hi = DK_DEVID_REV_MSB;
	dkdevidp->dkd_rev_lo = DK_DEVID_REV_LSB;

	/* Copy in the device id */
	bcopy(devid, dkdevidp->dkd_devid, DK_DEVID_SIZE);

	/* Calculate the chksum */
	chksum = 0;
	ip = (uint_t *)dkdevidp;
	for (i = 0; i < ((NBPSCTR - sizeof (int))/sizeof (int)); i++)
		chksum ^= ip[i];

	/* Fill in the checksum */
	DKD_FORMCHKSUM(chksum, dkdevidp);

/*	write the devid							*/
	outp = TGDK_IOB_WR(snlbp->s_dkobjp, handle);

	TGDK_IOB_FREE(snlbp->s_dkobjp, handle);
	if (outp != (caddr_t)dkdevidp) {
		ddi_devid_free(devid);
		return (DDI_FAILURE);
	}

	snlbp->s_devid = devid;
	snlbp->s_flags |= SNLB_FABID;
	return (DDI_SUCCESS);
}

/*
 * Compute the block number where the devid is (to be) stored
 * on the disk.  Return block number, or -1 if can't compute.
 * The "rw" string is for debugging printfs only.
 * Must be holding snlbp->s_mutex when this routine is called.
 */

static daddr_t
snlb_compute_devid_block(struct sn_label *snlbp)
{
	struct sn_lbdata *sdp = (struct  sn_lbdata *)&snlbp->s_data;
	daddr_t		spc, blk, head, cyl;

	ASSERT(MUTEX_HELD(&snlbp->s_mutex));

	if (sdp->s_dklb.dkl_acyl < 2)
		return (-1);

/*	Next to last cylinder is used */
	cyl = sdp->s_dklb.dkl_ncyl + sdp->s_dklb.dkl_acyl - 2;
	spc = sdp->s_dklb.dkl_nhead * sdp->s_dklb.dkl_nsect;
	head = sdp->s_dklb.dkl_nhead -1;
	blk = (cyl *(spc - sdp->s_dklb.dkl_apc)) +
		(head *sdp->s_dklb.dkl_nsect) + 1;

#ifdef SNLB_DEBUG
	if (snlb_debug & DXDEVID) {
		PRF("devid: start %d, capacity %d, devid block %d\n",
		    sdp->s_ustart, sdp->s_capacity, blk);
	}
#endif

	return (blk);
}


/*
 * Make an ioctl call to get a string from the actual disk driver.
 * This routine serves two purposes:
 *   1. Called with a NULL buf argument to get the length required to
 *      hold the string
 *   2. Called with a buffer to get the string
 */

static int
snlb_get_ioctl_string(struct sn_label *snlbp, int ioccmd, char *buf, int len)
{
	dadk_ioc_string_t strarg;
	char fakebuf[2];
	int dummyrval;

	if (buf != NULL) {
		strarg.is_buf = buf;
		strarg.is_size = len;
	} else {
		strarg.is_buf = fakebuf;
		strarg.is_size = sizeof (fakebuf);
	}

	TGDK_IOCTL(snlbp->s_dkobjp, snlbp->s_dev, ioccmd, (uintptr_t)&strarg,
	    FNATIVE | FKIOCTL, NULL, &dummyrval);

	return (strarg.is_size);
}
