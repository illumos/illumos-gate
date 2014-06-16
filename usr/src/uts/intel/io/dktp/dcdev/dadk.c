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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Direct Attached Disk
 */

#include <sys/file.h>
#include <sys/scsi/scsi.h>
#include <sys/var.h>
#include <sys/proc.h>
#include <sys/dktp/cm.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/policy.h>
#include <sys/priv.h>

#include <sys/dktp/dadev.h>
#include <sys/dktp/fctypes.h>
#include <sys/dktp/flowctrl.h>
#include <sys/dktp/tgcom.h>
#include <sys/dktp/tgdk.h>
#include <sys/dktp/bbh.h>
#include <sys/dktp/dadkio.h>
#include <sys/dktp/dadk.h>
#include <sys/cdio.h>

/*
 * Local Function Prototypes
 */
static void dadk_restart(void *pktp);
static void dadk_pktcb(struct cmpkt *pktp);
static void dadk_iodone(struct buf *bp);
static void dadk_polldone(struct buf *bp);
static void dadk_setcap(struct dadk *dadkp);
static void dadk_create_errstats(struct dadk *dadkp, int instance);
static void dadk_destroy_errstats(struct dadk *dadkp);

static int dadk_chkerr(struct cmpkt *pktp);
static int dadk_ioprep(struct dadk *dadkp, struct cmpkt *pktp);
static int dadk_iosetup(struct dadk *dadkp, struct cmpkt *pktp);
static int dadk_ioretry(struct cmpkt *pktp, int action);

static struct cmpkt *dadk_pktprep(struct dadk *dadkp, struct cmpkt *in_pktp,
    struct buf *bp, void (*cb_func)(struct buf *), int (*func)(caddr_t),
    caddr_t arg);

static int  dadk_pkt(opaque_t com_data, struct buf *bp, int (*func)(caddr_t),
    caddr_t arg);
static void dadk_transport(opaque_t com_data, struct buf *bp);
static int dadk_ctl_ioctl(struct dadk *, uint32_t, uintptr_t, int);

struct tgcom_objops dadk_com_ops = {
	nodev,
	nodev,
	dadk_pkt,
	dadk_transport,
	0, 0
};

/*
 * architecture dependent allocation restrictions for dadk_iob_alloc(). For
 * x86, we'll set dma_attr_addr_hi to dadk_max_phys_addr and dma_attr_sgllen
 * to dadk_sgl_size during _init().
 */
#if defined(__sparc)
static ddi_dma_attr_t dadk_alloc_attr = {
	DMA_ATTR_V0,	/* version number */
	0x0,		/* lowest usable address */
	0xFFFFFFFFull,	/* high DMA address range */
	0xFFFFFFFFull,	/* DMA counter register */
	1,		/* DMA address alignment */
	1,		/* DMA burstsizes */
	1,		/* min effective DMA size */
	0xFFFFFFFFull,	/* max DMA xfer size */
	0xFFFFFFFFull,	/* segment boundary */
	1,		/* s/g list length */
	512,		/* granularity of device */
	0,		/* DMA transfer flags */
};
#elif defined(__x86)
static ddi_dma_attr_t dadk_alloc_attr = {
	DMA_ATTR_V0,	/* version number */
	0x0,		/* lowest usable address */
	0x0,		/* high DMA address range [set in _init()] */
	0xFFFFull,	/* DMA counter register */
	512,		/* DMA address alignment */
	1,		/* DMA burstsizes */
	1,		/* min effective DMA size */
	0xFFFFFFFFull,	/* max DMA xfer size */
	0xFFFFFFFFull,	/* segment boundary */
	0,		/* s/g list length [set in _init()] */
	512,		/* granularity of device */
	0,		/* DMA transfer flags */
};

uint64_t dadk_max_phys_addr = 0xFFFFFFFFull;
int dadk_sgl_size = 0xFF;
#endif

static int dadk_rmb_ioctl(struct dadk *dadkp, int cmd, intptr_t arg, int flags,
    int silent);
static void dadk_rmb_iodone(struct buf *bp);

static int dadk_dk_buf_setup(struct dadk *dadkp, opaque_t *cmdp,
    dev_t dev, enum uio_seg dataspace, int rw);
static void dadk_dk(struct dadk *dadkp, struct dadkio_rwcmd *scmdp,
    struct buf *bp);
static void dadkmin(struct buf *bp);
static int dadk_dk_strategy(struct buf *bp);
static void dadk_recorderr(struct cmpkt *pktp, struct dadkio_rwcmd *rwcmdp);

struct tgdk_objops dadk_ops = {
	dadk_init,
	dadk_free,
	dadk_probe,
	dadk_attach,
	dadk_open,
	dadk_close,
	dadk_ioctl,
	dadk_strategy,
	dadk_setgeom,
	dadk_getgeom,
	dadk_iob_alloc,
	dadk_iob_free,
	dadk_iob_htoc,
	dadk_iob_xfer,
	dadk_dump,
	dadk_getphygeom,
	dadk_set_bbhobj,
	dadk_check_media,
	dadk_inquiry,
	dadk_cleanup,
	0
};

/*
 * Local static data
 */

#ifdef	DADK_DEBUG
#define	DENT	0x0001
#define	DERR	0x0002
#define	DIO	0x0004
#define	DGEOM	0x0010
#define	DSTATE  0x0020
static	int	dadk_debug = DGEOM;

#endif	/* DADK_DEBUG */

static int dadk_check_media_time = 3000000;	/* 3 Second State Check */
static int dadk_dk_maxphys = 0x80000;

static char	*dadk_cmds[] = {
	"\000Unknown",			/* unknown 		*/
	"\001read sector",		/* DCMD_READ 1		*/
	"\002write sector",		/* DCMD_WRITE 2		*/
	"\003format track",		/* DCMD_FMTTRK 3	*/
	"\004format whole drive",	/* DCMD_FMTDRV 4	*/
	"\005recalibrate",		/* DCMD_RECAL  5	*/
	"\006seek sector",		/* DCMD_SEEK   6	*/
	"\007read verify",		/* DCMD_RDVER  7	*/
	"\010read defect list",		/* DCMD_GETDEF 8	*/
	"\011lock door",		/* DCMD_LOCK   9	*/
	"\012unlock door",		/* DCMD_UNLOCK 10	*/
	"\013start motor",		/* DCMD_START_MOTOR 11	*/
	"\014stop motor",		/* DCMD_STOP_MOTOR 12	*/
	"\015eject",			/* DCMD_EJECT  13	*/
	"\016update geometry",		/* DCMD_UPDATE_GEOM  14	*/
	"\017get state",		/* DCMD_GET_STATE  15	*/
	"\020cdrom pause",		/* DCMD_PAUSE  16	*/
	"\021cdrom resume",		/* DCMD_RESUME  17	*/
	"\022cdrom play track index",	/* DCMD_PLAYTRKIND  18	*/
	"\023cdrom play msf",		/* DCMD_PLAYMSF  19	*/
	"\024cdrom sub channel",	/* DCMD_SUBCHNL  20	*/
	"\025cdrom read mode 1",	/* DCMD_READMODE1  21	*/
	"\026cdrom read toc header",	/* DCMD_READTOCHDR  22	*/
	"\027cdrom read toc entry",	/* DCMD_READTOCENT  23	*/
	"\030cdrom read offset",	/* DCMD_READOFFSET  24	*/
	"\031cdrom read mode 2",	/* DCMD_READMODE2  25	*/
	"\032cdrom volume control",	/* DCMD_VOLCTRL  26	*/
	"\033flush cache",		/* DCMD_FLUSH_CACHE  27	*/
	NULL
};

static char *dadk_sense[] = {
	"\000Success",			/* DERR_SUCCESS		*/
	"\001address mark not found",	/* DERR_AMNF		*/
	"\002track 0 not found",	/* DERR_TKONF		*/
	"\003aborted command",		/* DERR_ABORT		*/
	"\004write fault",		/* DERR_DWF		*/
	"\005ID not found",		/* DERR_IDNF		*/
	"\006drive busy",		/* DERR_BUSY		*/
	"\007uncorrectable data error",	/* DERR_UNC		*/
	"\010bad block detected",	/* DERR_BBK		*/
	"\011invalid command",		/* DERR_INVCDB		*/
	"\012device hard error",	/* DERR_HARD		*/
	"\013illegal length indicated", /* DERR_ILI		*/
	"\014end of media",		/* DERR_EOM		*/
	"\015media change requested",	/* DERR_MCR		*/
	"\016recovered from error",	/* DERR_RECOVER		*/
	"\017device not ready",		/* DERR_NOTREADY	*/
	"\020medium error",		/* DERR_MEDIUM		*/
	"\021hardware error",		/* DERR_HW		*/
	"\022illegal request",		/* DERR_ILL		*/
	"\023unit attention",		/* DERR_UNIT_ATTN	*/
	"\024data protection",		/* DERR_DATA_PROT	*/
	"\025miscompare",		/* DERR_MISCOMPARE	*/
	"\026ICRC error during UDMA",	/* DERR_ICRC		*/
	"\027reserved",			/* DERR_RESV		*/
	NULL
};

static char *dadk_name = "Disk";

/*
 *	This is the loadable module wrapper
 */
#include <sys/modctl.h>

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,	/* Type of module */
	"Direct Attached Disk"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
#ifdef DADK_DEBUG
	if (dadk_debug & DENT)
		PRF("dadk_init: call\n");
#endif

#if defined(__x86)
	/* set the max physical address for iob allocs on x86 */
	dadk_alloc_attr.dma_attr_addr_hi = dadk_max_phys_addr;

	/*
	 * set the sgllen for iob allocs on x86. If this is set less than
	 * the number of pages the buffer will take (taking into account
	 * alignment), it would force the allocator to try and allocate
	 * contiguous pages.
	 */
	dadk_alloc_attr.dma_attr_sgllen = dadk_sgl_size;
#endif

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
#ifdef DADK_DEBUG
	if (dadk_debug & DENT)
		PRF("dadk_fini: call\n");
#endif

	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

struct tgdk_obj *
dadk_create()
{
	struct tgdk_obj *dkobjp;
	struct dadk *dadkp;

	dkobjp = kmem_zalloc((sizeof (*dkobjp) + sizeof (*dadkp)), KM_NOSLEEP);
	if (!dkobjp)
		return (NULL);
	dadkp = (struct dadk *)(dkobjp+1);

	dkobjp->tg_ops  = (struct  tgdk_objops *)&dadk_ops;
	dkobjp->tg_data = (opaque_t)dadkp;
	dkobjp->tg_ext = &(dkobjp->tg_extblk);
	dadkp->dad_extp = &(dkobjp->tg_extblk);

#ifdef DADK_DEBUG
	if (dadk_debug & DENT)
		PRF("dadk_create: tgdkobjp= 0x%x dadkp= 0x%x\n", dkobjp, dadkp);
#endif
	return (dkobjp);
}

int
dadk_init(opaque_t objp, opaque_t devp, opaque_t flcobjp, opaque_t queobjp,
	opaque_t bbhobjp, void *lkarg)
{
	struct dadk *dadkp = (struct dadk *)objp;
	struct scsi_device *sdevp = (struct scsi_device *)devp;

	dadkp->dad_sd = devp;
	dadkp->dad_ctlobjp = (opaque_t)sdevp->sd_address.a_hba_tran;
	sdevp->sd_private = (caddr_t)dadkp;

	/* initialize the communication object */
	dadkp->dad_com.com_data = (opaque_t)dadkp;
	dadkp->dad_com.com_ops  = &dadk_com_ops;

	dadkp->dad_bbhobjp = bbhobjp;
	BBH_INIT(bbhobjp);

	dadkp->dad_flcobjp = flcobjp;
	mutex_init(&dadkp->dad_cmd_mutex, NULL, MUTEX_DRIVER, NULL);
	dadkp->dad_cmd_count = 0;
	return (FLC_INIT(flcobjp, &(dadkp->dad_com), queobjp, lkarg));
}

int
dadk_free(struct tgdk_obj *dkobjp)
{
	TGDK_CLEANUP(dkobjp);
	kmem_free(dkobjp, (sizeof (*dkobjp) + sizeof (struct dadk)));

	return (DDI_SUCCESS);
}

void
dadk_cleanup(struct tgdk_obj *dkobjp)
{
	struct dadk *dadkp;

	dadkp = (struct dadk *)(dkobjp->tg_data);
	if (dadkp->dad_sd)
		dadkp->dad_sd->sd_private = NULL;
	if (dadkp->dad_bbhobjp) {
		BBH_FREE(dadkp->dad_bbhobjp);
		dadkp->dad_bbhobjp = NULL;
	}
	if (dadkp->dad_flcobjp) {
		FLC_FREE(dadkp->dad_flcobjp);
		dadkp->dad_flcobjp = NULL;
	}
	mutex_destroy(&dadkp->dad_cmd_mutex);
}

/* ARGSUSED */
int
dadk_probe(opaque_t objp, int kmsflg)
{
	struct dadk *dadkp = (struct dadk *)objp;
	struct scsi_device *devp;
	char   name[80];

	devp = dadkp->dad_sd;
	if (!devp->sd_inq || (devp->sd_inq->inq_dtype == DTYPE_NOTPRESENT) ||
	    (devp->sd_inq->inq_dtype == DTYPE_UNKNOWN)) {
		return (DDI_PROBE_FAILURE);
	}

	switch (devp->sd_inq->inq_dtype) {
		case DTYPE_DIRECT:
			dadkp->dad_ctype = DKC_DIRECT;
			dadkp->dad_extp->tg_nodetype = DDI_NT_BLOCK;
			dadkp->dad_extp->tg_ctype = DKC_DIRECT;
			break;
		case DTYPE_RODIRECT: /* eg cdrom */
			dadkp->dad_ctype = DKC_CDROM;
			dadkp->dad_extp->tg_rdonly = 1;
			dadkp->dad_rdonly = 1;
			dadkp->dad_cdrom = 1;
			dadkp->dad_extp->tg_nodetype = DDI_NT_CD;
			dadkp->dad_extp->tg_ctype = DKC_CDROM;
			break;
		case DTYPE_WORM:
		case DTYPE_OPTICAL:
		default:
			return (DDI_PROBE_FAILURE);
	}

	dadkp->dad_extp->tg_rmb = dadkp->dad_rmb = devp->sd_inq->inq_rmb;

	dadkp->dad_secshf = SCTRSHFT;
	dadkp->dad_blkshf = 0;

	/* display the device name */
	(void) strcpy(name, "Vendor '");
	gda_inqfill((caddr_t)devp->sd_inq->inq_vid, 8, &name[strlen(name)]);
	(void) strcat(name, "' Product '");
	gda_inqfill((caddr_t)devp->sd_inq->inq_pid, 16, &name[strlen(name)]);
	(void) strcat(name, "'");
	gda_log(devp->sd_dev, dadk_name, CE_NOTE, "!<%s>\n", name);

	return (DDI_PROBE_SUCCESS);
}


/* ARGSUSED */
int
dadk_attach(opaque_t objp)
{
	return (DDI_SUCCESS);
}

int
dadk_set_bbhobj(opaque_t objp, opaque_t bbhobjp)
{
	struct dadk *dadkp = (struct dadk *)objp;
	/* free the old bbh object */
	if (dadkp->dad_bbhobjp)
		BBH_FREE(dadkp->dad_bbhobjp);

	/* initialize the new bbh object */
	dadkp->dad_bbhobjp = bbhobjp;
	BBH_INIT(bbhobjp);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
int
dadk_open(opaque_t objp, int flag)
{
	struct dadk *dadkp = (struct dadk *)objp;
	int error;
	int wce;

	if (!dadkp->dad_rmb) {
		if (dadkp->dad_phyg.g_cap) {
			FLC_START_KSTAT(dadkp->dad_flcobjp, "disk",
			    ddi_get_instance(CTL_DIP_DEV(dadkp->dad_ctlobjp)));
			return (DDI_SUCCESS);
		}
	} else {
		mutex_enter(&dadkp->dad_mutex);
		dadkp->dad_iostate = DKIO_NONE;
		cv_broadcast(&dadkp->dad_state_cv);
		mutex_exit(&dadkp->dad_mutex);

		if (dadk_rmb_ioctl(dadkp, DCMD_START_MOTOR, 0, 0,
		    DADK_SILENT) ||
		    dadk_rmb_ioctl(dadkp, DCMD_LOCK, 0, 0, DADK_SILENT) ||
		    dadk_rmb_ioctl(dadkp, DCMD_UPDATE_GEOM, 0, 0,
		    DADK_SILENT)) {
			return (DDI_FAILURE);
		}

		mutex_enter(&dadkp->dad_mutex);
		dadkp->dad_iostate = DKIO_INSERTED;
		cv_broadcast(&dadkp->dad_state_cv);
		mutex_exit(&dadkp->dad_mutex);
	}

	/*
	 * get write cache enable state
	 * If there is an error, must assume that write cache
	 * is enabled.
	 * NOTE: Since there is currently no Solaris mechanism to
	 * change the state of the Write Cache Enable feature,
	 * this code just checks the value of the WCE bit
	 * obtained at device init time.  If a mechanism
	 * is added to the driver to change WCE, dad_wce
	 * must be updated appropriately.
	 */
	error = dadk_ctl_ioctl(dadkp, DIOCTL_GETWCE,
	    (uintptr_t)&wce, FKIOCTL | FNATIVE);
	mutex_enter(&dadkp->dad_mutex);
	dadkp->dad_wce = (error != 0) || (wce != 0);
	mutex_exit(&dadkp->dad_mutex);

	/* logical disk geometry */
	(void) dadk_ctl_ioctl(dadkp, DIOCTL_GETGEOM,
	    (uintptr_t)&dadkp->dad_logg, FKIOCTL | FNATIVE);
	if (dadkp->dad_logg.g_cap == 0)
		return (DDI_FAILURE);

	/* get physical disk geometry */
	(void) dadk_ctl_ioctl(dadkp, DIOCTL_GETPHYGEOM,
	    (uintptr_t)&dadkp->dad_phyg, FKIOCTL | FNATIVE);
	if (dadkp->dad_phyg.g_cap == 0)
		return (DDI_FAILURE);

	dadk_setcap(dadkp);

	dadk_create_errstats(dadkp,
	    ddi_get_instance(CTL_DIP_DEV(dadkp->dad_ctlobjp)));

	/* start profiling */
	FLC_START_KSTAT(dadkp->dad_flcobjp, "disk",
	    ddi_get_instance(CTL_DIP_DEV(dadkp->dad_ctlobjp)));

	return (DDI_SUCCESS);
}

static void
dadk_setcap(struct dadk *dadkp)
{
	int	 totsize;
	int	 i;

	totsize = dadkp->dad_phyg.g_secsiz;

	if (totsize == 0) {
		if (dadkp->dad_cdrom) {
			totsize = 2048;
		} else {
			totsize = NBPSCTR;
		}
	} else {
		/* Round down sector size to multiple of 512B */
		totsize &= ~(NBPSCTR-1);
	}
	dadkp->dad_phyg.g_secsiz = totsize;

	/* set sec,block shift factor - (512->0, 1024->1, 2048->2, etc.) */
	totsize >>= SCTRSHFT;
	for (i = 0; totsize != 1; i++, totsize >>= 1)
		;
	dadkp->dad_blkshf = i;
	dadkp->dad_secshf = i + SCTRSHFT;
}


static void
dadk_create_errstats(struct dadk *dadkp, int instance)
{
	dadk_errstats_t *dep;
	char kstatname[KSTAT_STRLEN];
	dadk_ioc_string_t dadk_ioc_string;

	if (dadkp->dad_errstats)
		return;

	(void) sprintf(kstatname, "cmdk%d,error", instance);
	dadkp->dad_errstats = kstat_create("cmdkerror", instance,
	    kstatname, "device_error", KSTAT_TYPE_NAMED,
	    sizeof (dadk_errstats_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT);

	if (!dadkp->dad_errstats)
		return;

	dep = (dadk_errstats_t *)dadkp->dad_errstats->ks_data;

	kstat_named_init(&dep->dadk_softerrs,
	    "Soft Errors", KSTAT_DATA_UINT32);
	kstat_named_init(&dep->dadk_harderrs,
	    "Hard Errors", KSTAT_DATA_UINT32);
	kstat_named_init(&dep->dadk_transerrs,
	    "Transport Errors", KSTAT_DATA_UINT32);
	kstat_named_init(&dep->dadk_model,
	    "Model", KSTAT_DATA_CHAR);
	kstat_named_init(&dep->dadk_revision,
	    "Revision", KSTAT_DATA_CHAR);
	kstat_named_init(&dep->dadk_serial,
	    "Serial No", KSTAT_DATA_CHAR);
	kstat_named_init(&dep->dadk_capacity,
	    "Size", KSTAT_DATA_ULONGLONG);
	kstat_named_init(&dep->dadk_rq_media_err,
	    "Media Error", KSTAT_DATA_UINT32);
	kstat_named_init(&dep->dadk_rq_ntrdy_err,
	    "Device Not Ready", KSTAT_DATA_UINT32);
	kstat_named_init(&dep->dadk_rq_nodev_err,
	    "No Device", KSTAT_DATA_UINT32);
	kstat_named_init(&dep->dadk_rq_recov_err,
	    "Recoverable", KSTAT_DATA_UINT32);
	kstat_named_init(&dep->dadk_rq_illrq_err,
	    "Illegal Request", KSTAT_DATA_UINT32);

	dadkp->dad_errstats->ks_private = dep;
	dadkp->dad_errstats->ks_update = nulldev;
	kstat_install(dadkp->dad_errstats);

	/* get model */
	dep->dadk_model.value.c[0] = 0;
	dadk_ioc_string.is_buf = &dep->dadk_model.value.c[0];
	dadk_ioc_string.is_size = sizeof (dep->dadk_model.value.c);
	(void) dadk_ctl_ioctl(dadkp, DIOCTL_GETMODEL,
	    (uintptr_t)&dadk_ioc_string, FKIOCTL | FNATIVE);

	/* get serial */
	dep->dadk_serial.value.c[0] = 0;
	dadk_ioc_string.is_buf = &dep->dadk_serial.value.c[0];
	dadk_ioc_string.is_size = sizeof (dep->dadk_serial.value.c);
	(void) dadk_ctl_ioctl(dadkp, DIOCTL_GETSERIAL,
	    (uintptr_t)&dadk_ioc_string, FKIOCTL | FNATIVE);

	/* Get revision */
	dep->dadk_revision.value.c[0] = 0;

	/* Get capacity */

	dep->dadk_capacity.value.ui64 =
	    (uint64_t)dadkp->dad_logg.g_cap *
	    (uint64_t)dadkp->dad_logg.g_secsiz;
}


int
dadk_close(opaque_t objp)
{
	struct dadk *dadkp = (struct dadk *)objp;

	if (dadkp->dad_rmb) {
		(void) dadk_rmb_ioctl(dadkp, DCMD_STOP_MOTOR, 0, 0,
		    DADK_SILENT);
		(void) dadk_rmb_ioctl(dadkp, DCMD_UNLOCK, 0, 0, DADK_SILENT);
	}
	FLC_STOP_KSTAT(dadkp->dad_flcobjp);

	dadk_destroy_errstats(dadkp);

	return (DDI_SUCCESS);
}

static void
dadk_destroy_errstats(struct dadk *dadkp)
{
	if (!dadkp->dad_errstats)
		return;

	kstat_delete(dadkp->dad_errstats);
	dadkp->dad_errstats = NULL;
}


int
dadk_strategy(opaque_t objp, struct buf *bp)
{
	struct dadk *dadkp = (struct dadk *)objp;

	if (dadkp->dad_rdonly && !(bp->b_flags & B_READ)) {
		bioerror(bp, EROFS);
		return (DDI_FAILURE);
	}

	if (bp->b_bcount & (dadkp->DAD_SECSIZ-1)) {
		bioerror(bp, ENXIO);
		return (DDI_FAILURE);
	}

	SET_BP_SEC(bp, (LBLK2SEC(GET_BP_SEC(bp), dadkp->dad_blkshf)));
	mutex_enter(&dadkp->dad_cmd_mutex);
	dadkp->dad_cmd_count++;
	mutex_exit(&dadkp->dad_cmd_mutex);
	FLC_ENQUE(dadkp->dad_flcobjp, bp);

	return (DDI_SUCCESS);
}

int
dadk_dump(opaque_t objp, struct buf *bp)
{
	struct dadk *dadkp = (struct dadk *)objp;
	struct cmpkt *pktp;

	if (dadkp->dad_rdonly) {
		bioerror(bp, EROFS);
		return (DDI_FAILURE);
	}

	if (bp->b_bcount & (dadkp->DAD_SECSIZ-1)) {
		bioerror(bp, ENXIO);
		return (DDI_FAILURE);
	}

	SET_BP_SEC(bp, (LBLK2SEC(GET_BP_SEC(bp), dadkp->dad_blkshf)));

	pktp = dadk_pktprep(dadkp, NULL, bp, dadk_polldone, NULL, NULL);
	if (!pktp) {
		cmn_err(CE_WARN, "no resources for dumping");
		bioerror(bp, EIO);
		return (DDI_FAILURE);
	}
	pktp->cp_flags |= CPF_NOINTR;

	(void) dadk_ioprep(dadkp, pktp);
	dadk_transport(dadkp, bp);
	pktp->cp_byteleft -= pktp->cp_bytexfer;

	while (geterror(bp) == 0 && pktp->cp_byteleft != 0) {
		(void) dadk_iosetup(dadkp, pktp);
		dadk_transport(dadkp, bp);
		pktp->cp_byteleft -= pktp->cp_bytexfer;
	}

	if (pktp->cp_private)
		BBH_FREEHANDLE(dadkp->dad_bbhobjp, pktp->cp_private);
	gda_free(dadkp->dad_ctlobjp, pktp, NULL);
	return (DDI_SUCCESS);
}

/* ARGSUSED  */
int
dadk_ioctl(opaque_t objp, dev_t dev, int cmd, intptr_t arg, int flag,
	cred_t *cred_p, int *rval_p)
{
	struct dadk *dadkp = (struct dadk *)objp;

	switch (cmd) {
	case DKIOCGETDEF:
		{
		struct buf	*bp;
		int		err, head;
		unsigned char	*secbuf;
		STRUCT_DECL(defect_header, adh);

		STRUCT_INIT(adh, flag & FMODELS);

		/*
		 * copyin header ....
		 * yields head number and buffer address
		 */
		if (ddi_copyin((caddr_t)arg, STRUCT_BUF(adh), STRUCT_SIZE(adh),
		    flag))
			return (EFAULT);
		head = STRUCT_FGET(adh, head);
		if (head < 0 || head >= dadkp->dad_phyg.g_head)
			return (ENXIO);
		secbuf = kmem_zalloc(NBPSCTR, KM_SLEEP);
		if (!secbuf)
			return (ENOMEM);
		bp = getrbuf(KM_SLEEP);
		if (!bp) {
			kmem_free(secbuf, NBPSCTR);
			return (ENOMEM);
		}

		bp->b_edev = dev;
		bp->b_dev  = cmpdev(dev);
		bp->b_flags = B_BUSY;
		bp->b_resid = 0;
		bp->b_bcount = NBPSCTR;
		bp->b_un.b_addr = (caddr_t)secbuf;
		bp->b_blkno = head; /* I had to put it somwhere! */
		bp->b_forw = (struct buf *)dadkp;
		bp->b_back = (struct buf *)DCMD_GETDEF;

		mutex_enter(&dadkp->dad_cmd_mutex);
		dadkp->dad_cmd_count++;
		mutex_exit(&dadkp->dad_cmd_mutex);
		FLC_ENQUE(dadkp->dad_flcobjp, bp);
		err = biowait(bp);
		if (!err) {
			if (ddi_copyout((caddr_t)secbuf,
			    STRUCT_FGETP(adh, buffer), NBPSCTR, flag))
				err = ENXIO;
		}
		kmem_free(secbuf, NBPSCTR);
		freerbuf(bp);
		return (err);
		}
	case DIOCTL_RWCMD:
		{
		struct dadkio_rwcmd *rwcmdp;
		int status, rw;

		/*
		 * copied in by cmdk and, if necessary, converted to the
		 * correct datamodel
		 */
		rwcmdp = (struct dadkio_rwcmd *)(intptr_t)arg;

		/*
		 * handle the complex cases here; we pass these
		 * through to the driver, which will queue them and
		 * handle the requests asynchronously.  The simpler
		 * cases ,which can return immediately, fail here, and
		 * the request reverts to the dadk_ioctl routine, while
		 *  will reroute them directly to the ata driver.
		 */
		switch (rwcmdp->cmd) {
			case DADKIO_RWCMD_READ :
				/*FALLTHROUGH*/
			case DADKIO_RWCMD_WRITE:
				rw = ((rwcmdp->cmd == DADKIO_RWCMD_WRITE) ?
				    B_WRITE : B_READ);
				status = dadk_dk_buf_setup(dadkp,
				    (opaque_t)rwcmdp, dev, ((flag &FKIOCTL) ?
				    UIO_SYSSPACE : UIO_USERSPACE), rw);
				return (status);
			default:
				return (EINVAL);
			}
		}
	case DKIOC_UPDATEFW:

		/*
		 * Require PRIV_ALL privilege to invoke DKIOC_UPDATEFW
		 * to protect the firmware update from malicious use
		 */
		if (PRIV_POLICY(cred_p, PRIV_ALL, B_FALSE, EPERM, NULL) != 0)
			return (EPERM);
		else
			return (dadk_ctl_ioctl(dadkp, cmd, arg, flag));

	case DKIOCFLUSHWRITECACHE:
		{
			struct buf *bp;
			int err = 0;
			struct dk_callback *dkc = (struct dk_callback *)arg;
			struct cmpkt *pktp;
			int is_sync = 1;

			mutex_enter(&dadkp->dad_mutex);
			if (dadkp->dad_noflush || !  dadkp->dad_wce) {
				err = dadkp->dad_noflush ? ENOTSUP : 0;
				mutex_exit(&dadkp->dad_mutex);
				/*
				 * If a callback was requested: a
				 * callback will always be done if the
				 * caller saw the DKIOCFLUSHWRITECACHE
				 * ioctl return 0, and never done if the
				 * caller saw the ioctl return an error.
				 */
				if ((flag & FKIOCTL) && dkc != NULL &&
				    dkc->dkc_callback != NULL) {
					(*dkc->dkc_callback)(dkc->dkc_cookie,
					    err);
					/*
					 * Did callback and reported error.
					 * Since we did a callback, ioctl
					 * should return 0.
					 */
					err = 0;
				}
				return (err);
			}
			mutex_exit(&dadkp->dad_mutex);

			bp = getrbuf(KM_SLEEP);

			bp->b_edev = dev;
			bp->b_dev  = cmpdev(dev);
			bp->b_flags = B_BUSY;
			bp->b_resid = 0;
			bp->b_bcount = 0;
			SET_BP_SEC(bp, 0);

			if ((flag & FKIOCTL) && dkc != NULL &&
			    dkc->dkc_callback != NULL) {
				struct dk_callback *dkc2 =
				    (struct dk_callback *)kmem_zalloc(
				    sizeof (struct dk_callback), KM_SLEEP);

				bcopy(dkc, dkc2, sizeof (*dkc2));
				bp->b_private = dkc2;
				bp->b_iodone = dadk_flushdone;
				is_sync = 0;
			}

			/*
			 * Setup command pkt
			 * dadk_pktprep() can't fail since DDI_DMA_SLEEP set
			 */
			pktp = dadk_pktprep(dadkp, NULL, bp,
			    dadk_iodone, DDI_DMA_SLEEP, NULL);

			pktp->cp_time = DADK_FLUSH_CACHE_TIME;

			*((char *)(pktp->cp_cdbp)) = DCMD_FLUSH_CACHE;
			pktp->cp_byteleft = 0;
			pktp->cp_private = NULL;
			pktp->cp_secleft = 0;
			pktp->cp_srtsec = -1;
			pktp->cp_bytexfer = 0;

			CTL_IOSETUP(dadkp->dad_ctlobjp, pktp);

			mutex_enter(&dadkp->dad_cmd_mutex);
			dadkp->dad_cmd_count++;
			mutex_exit(&dadkp->dad_cmd_mutex);
			FLC_ENQUE(dadkp->dad_flcobjp, bp);

			if (is_sync) {
				err = biowait(bp);
				freerbuf(bp);
			}
			return (err);
		}
	default:
		if (!dadkp->dad_rmb)
			return (dadk_ctl_ioctl(dadkp, cmd, arg, flag));
	}

	switch (cmd) {
	case CDROMSTOP:
		return (dadk_rmb_ioctl(dadkp, DCMD_STOP_MOTOR, 0,
		    0, DADK_SILENT));
	case CDROMSTART:
		return (dadk_rmb_ioctl(dadkp, DCMD_START_MOTOR, 0,
		    0, DADK_SILENT));
	case DKIOCLOCK:
		return (dadk_rmb_ioctl(dadkp, DCMD_LOCK, 0, 0, DADK_SILENT));
	case DKIOCUNLOCK:
		return (dadk_rmb_ioctl(dadkp, DCMD_UNLOCK, 0, 0, DADK_SILENT));
	case DKIOCEJECT:
	case CDROMEJECT:
		{
			int ret;

			if (ret = dadk_rmb_ioctl(dadkp, DCMD_UNLOCK, 0, 0,
			    DADK_SILENT)) {
				return (ret);
			}
			if (ret = dadk_rmb_ioctl(dadkp, DCMD_EJECT, 0, 0,
			    DADK_SILENT)) {
				return (ret);
			}
			mutex_enter(&dadkp->dad_mutex);
			dadkp->dad_iostate = DKIO_EJECTED;
			cv_broadcast(&dadkp->dad_state_cv);
			mutex_exit(&dadkp->dad_mutex);

			return (0);

		}
	default:
		return (ENOTTY);
	/*
	 * cdrom audio commands
	 */
	case CDROMPAUSE:
		cmd = DCMD_PAUSE;
		break;
	case CDROMRESUME:
		cmd = DCMD_RESUME;
		break;
	case CDROMPLAYMSF:
		cmd = DCMD_PLAYMSF;
		break;
	case CDROMPLAYTRKIND:
		cmd = DCMD_PLAYTRKIND;
		break;
	case CDROMREADTOCHDR:
		cmd = DCMD_READTOCHDR;
		break;
	case CDROMREADTOCENTRY:
		cmd = DCMD_READTOCENT;
		break;
	case CDROMVOLCTRL:
		cmd = DCMD_VOLCTRL;
		break;
	case CDROMSUBCHNL:
		cmd = DCMD_SUBCHNL;
		break;
	case CDROMREADMODE2:
		cmd = DCMD_READMODE2;
		break;
	case CDROMREADMODE1:
		cmd = DCMD_READMODE1;
		break;
	case CDROMREADOFFSET:
		cmd = DCMD_READOFFSET;
		break;
	}
	return (dadk_rmb_ioctl(dadkp, cmd, arg, flag, 0));
}

int
dadk_flushdone(struct buf *bp)
{
	struct dk_callback *dkc = bp->b_private;

	ASSERT(dkc != NULL && dkc->dkc_callback != NULL);

	(*dkc->dkc_callback)(dkc->dkc_cookie, geterror(bp));

	kmem_free(dkc, sizeof (*dkc));
	freerbuf(bp);
	return (0);
}

int
dadk_getphygeom(opaque_t objp, struct tgdk_geom *dkgeom_p)
{
	struct dadk *dadkp = (struct dadk *)objp;

	bcopy((caddr_t)&dadkp->dad_phyg, (caddr_t)dkgeom_p,
	    sizeof (struct tgdk_geom));
	return (DDI_SUCCESS);
}

int
dadk_getgeom(opaque_t objp, struct tgdk_geom *dkgeom_p)
{
	struct dadk *dadkp = (struct dadk *)objp;
	bcopy((caddr_t)&dadkp->dad_logg, (caddr_t)dkgeom_p,
	    sizeof (struct tgdk_geom));
	return (DDI_SUCCESS);
}

int
dadk_setgeom(opaque_t objp, struct tgdk_geom *dkgeom_p)
{
	struct dadk *dadkp = (struct dadk *)objp;

	dadkp->dad_logg.g_cyl = dkgeom_p->g_cyl;
	dadkp->dad_logg.g_head = dkgeom_p->g_head;
	dadkp->dad_logg.g_sec = dkgeom_p->g_sec;
	dadkp->dad_logg.g_cap = dkgeom_p->g_cap;
	return (DDI_SUCCESS);
}


tgdk_iob_handle
dadk_iob_alloc(opaque_t objp, daddr_t blkno, ssize_t xfer, int kmsflg)
{
	struct dadk *dadkp = (struct dadk *)objp;
	struct buf *bp;
	struct tgdk_iob *iobp;
	size_t rlen;

	iobp = kmem_zalloc(sizeof (*iobp), kmsflg);
	if (iobp == NULL)
		return (NULL);
	if ((bp = getrbuf(kmsflg)) == NULL) {
		kmem_free(iobp, sizeof (*iobp));
		return (NULL);
	}

	iobp->b_psec  = LBLK2SEC(blkno, dadkp->dad_blkshf);
	iobp->b_pbyteoff = (blkno & ((1<<dadkp->dad_blkshf) - 1)) << SCTRSHFT;
	iobp->b_pbytecnt = ((iobp->b_pbyteoff + xfer + dadkp->DAD_SECSIZ - 1)
	    >> dadkp->dad_secshf) << dadkp->dad_secshf;

	bp->b_un.b_addr = 0;
	/*
	 * use i_ddi_mem_alloc() for now until we have an interface to allocate
	 * memory for DMA which doesn't require a DMA handle.
	 */
	if (i_ddi_mem_alloc((dadkp->dad_sd)->sd_dev, &dadk_alloc_attr,
	    (size_t)iobp->b_pbytecnt, ((kmsflg == KM_SLEEP) ? 1 : 0), 0, NULL,
	    &bp->b_un.b_addr, &rlen, NULL) != DDI_SUCCESS) {
		freerbuf(bp);
		kmem_free(iobp, sizeof (*iobp));
		return (NULL);
	}
	iobp->b_flag |= IOB_BPALLOC | IOB_BPBUFALLOC;
	iobp->b_bp = bp;
	iobp->b_lblk = blkno;
	iobp->b_xfer = xfer;
	iobp->b_lblk = blkno;
	iobp->b_xfer = xfer;
	return (iobp);
}

/* ARGSUSED */
int
dadk_iob_free(opaque_t objp, struct tgdk_iob *iobp)
{
	struct buf *bp;

	if (iobp) {
		if (iobp->b_bp && (iobp->b_flag & IOB_BPALLOC)) {
			bp = iobp->b_bp;
			if (bp->b_un.b_addr && (iobp->b_flag & IOB_BPBUFALLOC))
				i_ddi_mem_free((caddr_t)bp->b_un.b_addr, NULL);
			freerbuf(bp);
		}
		kmem_free(iobp, sizeof (*iobp));
	}
	return (DDI_SUCCESS);
}

/* ARGSUSED */
caddr_t
dadk_iob_htoc(opaque_t objp, struct tgdk_iob *iobp)
{
	return (iobp->b_bp->b_un.b_addr+iobp->b_pbyteoff);
}


caddr_t
dadk_iob_xfer(opaque_t objp, struct tgdk_iob *iobp, int rw)
{
	struct dadk	*dadkp = (struct dadk *)objp;
	struct buf	*bp;
	int		err;

	bp = iobp->b_bp;
	if (dadkp->dad_rdonly && !(rw & B_READ)) {
		bioerror(bp, EROFS);
		return (NULL);
	}

	bp->b_flags |= (B_BUSY | rw);
	bp->b_bcount = iobp->b_pbytecnt;
	SET_BP_SEC(bp, iobp->b_psec);
	bp->av_back = (struct buf *)0;
	bp->b_resid = 0;

	/* call flow control */
	mutex_enter(&dadkp->dad_cmd_mutex);
	dadkp->dad_cmd_count++;
	mutex_exit(&dadkp->dad_cmd_mutex);
	FLC_ENQUE(dadkp->dad_flcobjp, bp);
	err = biowait(bp);

	bp->b_bcount = iobp->b_xfer;
	bp->b_flags &= ~(B_DONE|B_BUSY);

	if (err)
		return (NULL);

	return (bp->b_un.b_addr+iobp->b_pbyteoff);
}

static void
dadk_transport(opaque_t com_data, struct buf *bp)
{
	struct dadk *dadkp = (struct dadk *)com_data;

	if (CTL_TRANSPORT(dadkp->dad_ctlobjp, GDA_BP_PKT(bp)) ==
	    CTL_SEND_SUCCESS)
		return;
	dadk_restart((void*)GDA_BP_PKT(bp));
}

static int
dadk_pkt(opaque_t com_data, struct buf *bp, int (*func)(caddr_t), caddr_t arg)
{
	struct cmpkt *pktp;
	struct dadk *dadkp = (struct dadk *)com_data;

	if (GDA_BP_PKT(bp))
		return (DDI_SUCCESS);

	pktp = dadk_pktprep(dadkp, NULL, bp, dadk_iodone, func, arg);
	if (!pktp)
		return (DDI_FAILURE);

	return (dadk_ioprep(dadkp, pktp));
}

/*
 * Read, Write preparation
 */
static int
dadk_ioprep(struct dadk *dadkp, struct cmpkt *pktp)
{
	struct buf *bp;

	bp = pktp->cp_bp;
	if (bp->b_forw == (struct buf *)dadkp)
		*((char *)(pktp->cp_cdbp)) = (char)(intptr_t)bp->b_back;

	else if (bp->b_flags & B_READ)
		*((char *)(pktp->cp_cdbp)) = DCMD_READ;
	else
		*((char *)(pktp->cp_cdbp)) = DCMD_WRITE;
	pktp->cp_byteleft = bp->b_bcount;

	/* setup the bad block list handle */
	pktp->cp_private = BBH_GETHANDLE(dadkp->dad_bbhobjp, bp);
	return (dadk_iosetup(dadkp, pktp));
}

static int
dadk_iosetup(struct dadk *dadkp, struct cmpkt *pktp)
{
	struct buf	*bp;
	bbh_cookie_t	bbhckp;
	int		seccnt;

	seccnt = pktp->cp_bytexfer >> dadkp->dad_secshf;
	pktp->cp_secleft -= seccnt;

	if (pktp->cp_secleft) {
		pktp->cp_srtsec += seccnt;
	} else {
		/* get the first cookie from the bad block list */
		if (!pktp->cp_private) {
			bp = pktp->cp_bp;
			pktp->cp_srtsec  = GET_BP_SEC(bp);
			pktp->cp_secleft = (bp->b_bcount >> dadkp->dad_secshf);
		} else {
			bbhckp = BBH_HTOC(dadkp->dad_bbhobjp,
			    pktp->cp_private);
			pktp->cp_srtsec = BBH_GETCK_SECTOR(dadkp->dad_bbhobjp,
			    bbhckp);
			pktp->cp_secleft = BBH_GETCK_SECLEN(dadkp->dad_bbhobjp,
			    bbhckp);
		}
	}

	pktp->cp_bytexfer = pktp->cp_secleft << dadkp->dad_secshf;

	if (CTL_IOSETUP(dadkp->dad_ctlobjp, pktp)) {
		return (DDI_SUCCESS);
	} else {
		return (DDI_FAILURE);
	}




}

static struct cmpkt *
dadk_pktprep(struct dadk *dadkp, struct cmpkt *in_pktp, struct buf *bp,
    void (*cb_func)(struct buf *), int (*func)(caddr_t), caddr_t arg)
{
	struct cmpkt *pktp;

	pktp = gda_pktprep(dadkp->dad_ctlobjp, in_pktp, (opaque_t)bp, func,
	    arg);

	if (pktp) {
		pktp->cp_callback = dadk_pktcb;
		pktp->cp_time = DADK_IO_TIME;
		pktp->cp_flags = 0;
		pktp->cp_iodone = cb_func;
		pktp->cp_dev_private = (opaque_t)dadkp;

	}

	return (pktp);
}


static void
dadk_restart(void *vpktp)
{
	struct cmpkt *pktp = (struct cmpkt *)vpktp;

	if (dadk_ioretry(pktp, QUE_COMMAND) == JUST_RETURN)
		return;
	pktp->cp_iodone(pktp->cp_bp);
}

static int
dadk_ioretry(struct cmpkt *pktp, int action)
{
	struct buf *bp;
	struct dadk *dadkp = PKT2DADK(pktp);

	switch (action) {
	case QUE_COMMAND:
		if (pktp->cp_retry++ < DADK_RETRY_COUNT) {
			CTL_IOSETUP(dadkp->dad_ctlobjp, pktp);
			if (CTL_TRANSPORT(dadkp->dad_ctlobjp, pktp) ==
			    CTL_SEND_SUCCESS) {
				return (JUST_RETURN);
			}
			gda_log(dadkp->dad_sd->sd_dev, dadk_name,
			    CE_WARN, "transport of command fails\n");
		} else
			gda_log(dadkp->dad_sd->sd_dev,
			    dadk_name, CE_WARN,
			    "exceeds maximum number of retries\n");
		bioerror(pktp->cp_bp, ENXIO);
		/*FALLTHROUGH*/
	case COMMAND_DONE_ERROR:
		bp = pktp->cp_bp;
		bp->b_resid += pktp->cp_byteleft - pktp->cp_bytexfer +
		    pktp->cp_resid;
		if (geterror(bp) == 0) {
			if ((*((char *)(pktp->cp_cdbp)) == DCMD_FLUSH_CACHE) &&
			    (pktp->cp_dev_private == (opaque_t)dadkp) &&
			    ((int)(*(char *)pktp->cp_scbp) == DERR_ABORT)) {
				/*
				 * Flag "unimplemented" responses for
				 * DCMD_FLUSH_CACHE as ENOTSUP
				 */
				bioerror(bp, ENOTSUP);
				mutex_enter(&dadkp->dad_mutex);
				dadkp->dad_noflush = 1;
				mutex_exit(&dadkp->dad_mutex);
			} else {
				bioerror(bp, EIO);
			}
		}
		/*FALLTHROUGH*/
	case COMMAND_DONE:
	default:
		return (COMMAND_DONE);
	}
}


static void
dadk_pktcb(struct cmpkt *pktp)
{
	int action;
	struct dadkio_rwcmd *rwcmdp;

	rwcmdp = (struct dadkio_rwcmd *)pktp->cp_passthru;  /* ioctl packet */

	if (pktp->cp_reason == CPS_SUCCESS) {
		if (rwcmdp && (rwcmdp != (opaque_t)DADK_SILENT))
			rwcmdp->status.status = DADKIO_STAT_NO_ERROR;
		pktp->cp_iodone(pktp->cp_bp);
		return;
	}

	if (rwcmdp && (rwcmdp != (opaque_t)DADK_SILENT)) {
		if (pktp->cp_reason == CPS_CHKERR)
			dadk_recorderr(pktp, rwcmdp);
		dadk_iodone(pktp->cp_bp);
		return;
	}

	if (pktp->cp_reason == CPS_CHKERR)
		action = dadk_chkerr(pktp);
	else
		action = COMMAND_DONE_ERROR;

	if (action == JUST_RETURN)
		return;

	/*
	 * If we are panicking don't retry the command
	 * just fail it so we can go down completing all
	 * of the buffers.
	 */
	if (ddi_in_panic() && action == QUE_COMMAND)
		action = COMMAND_DONE_ERROR;

	if (action != COMMAND_DONE) {
		if ((dadk_ioretry(pktp, action)) == JUST_RETURN)
			return;
	}
	pktp->cp_iodone(pktp->cp_bp);
}



static struct dadkio_derr dadk_errtab[] = {
	{COMMAND_DONE, GDA_INFORMATIONAL},	/*  0 DERR_SUCCESS	*/
	{QUE_COMMAND, GDA_FATAL},		/*  1 DERR_AMNF		*/
	{QUE_COMMAND, GDA_FATAL},		/*  2 DERR_TKONF	*/
	{COMMAND_DONE_ERROR, GDA_INFORMATIONAL}, /* 3 DERR_ABORT	*/
	{QUE_COMMAND, GDA_RETRYABLE},		/*  4 DERR_DWF		*/
	{QUE_COMMAND, GDA_FATAL},		/*  5 DERR_IDNF		*/
	{JUST_RETURN, GDA_INFORMATIONAL},	/*  6 DERR_BUSY		*/
	{QUE_COMMAND, GDA_FATAL},		/*  7 DERR_UNC		*/
	{QUE_COMMAND, GDA_RETRYABLE},		/*  8 DERR_BBK		*/
	{COMMAND_DONE_ERROR, GDA_FATAL},	/*  9 DERR_INVCDB	*/
	{COMMAND_DONE_ERROR, GDA_FATAL},	/* 10 DERR_HARD		*/
	{COMMAND_DONE_ERROR, GDA_FATAL},	/* 11 DERR_ILI		*/
	{COMMAND_DONE_ERROR, GDA_FATAL},	/* 12 DERR_EOM		*/
	{COMMAND_DONE, GDA_INFORMATIONAL},	/* 13 DERR_MCR		*/
	{COMMAND_DONE, GDA_INFORMATIONAL},	/* 14 DERR_RECOVER	*/
	{COMMAND_DONE_ERROR, GDA_FATAL},	/* 15 DERR_NOTREADY	*/
	{QUE_COMMAND, GDA_RETRYABLE},		/* 16 DERR_MEDIUM	*/
	{COMMAND_DONE_ERROR, GDA_FATAL},	/* 17 DERR_HW		*/
	{COMMAND_DONE, GDA_FATAL},		/* 18 DERR_ILL		*/
	{COMMAND_DONE, GDA_FATAL},		/* 19 DERR_UNIT_ATTN	*/
	{COMMAND_DONE_ERROR, GDA_FATAL},	/* 20 DERR_DATA_PROT	*/
	{COMMAND_DONE_ERROR, GDA_FATAL},	/* 21 DERR_MISCOMPARE	*/
	{QUE_COMMAND, GDA_RETRYABLE},		/* 22 DERR_ICRC		*/
	{COMMAND_DONE_ERROR, GDA_FATAL},	/* 23 DERR_RESV		*/
};

static int
dadk_chkerr(struct cmpkt *pktp)
{
	daddr_t err_blkno;
	struct dadk *dadkp = PKT2DADK(pktp);
	dadk_errstats_t *dep;
	int scb = *(char *)pktp->cp_scbp;

	if (scb == DERR_SUCCESS) {
		if (pktp->cp_retry != 0 && dadkp->dad_errstats != NULL) {
			dep = (dadk_errstats_t *)
			    dadkp->dad_errstats->ks_data;
			dep->dadk_rq_recov_err.value.ui32++;
		}
		return (COMMAND_DONE);
	}

	if (pktp->cp_retry) {
		err_blkno = pktp->cp_srtsec + ((pktp->cp_bytexfer -
		    pktp->cp_resid) >> dadkp->dad_secshf);
	} else
		err_blkno = -1;

	if (dadkp->dad_errstats != NULL) {
		dep = (dadk_errstats_t *)dadkp->dad_errstats->ks_data;

		switch (dadk_errtab[scb].d_severity) {
			case GDA_RETRYABLE:
				dep->dadk_softerrs.value.ui32++;
				break;

			case GDA_FATAL:
				dep->dadk_harderrs.value.ui32++;
				break;

			default:
				break;
		}

		switch (scb) {
			case DERR_INVCDB:
			case DERR_ILI:
			case DERR_EOM:
			case DERR_HW:
			case DERR_ICRC:
				dep->dadk_transerrs.value.ui32++;
				break;

			case DERR_AMNF:
			case DERR_TKONF:
			case DERR_DWF:
			case DERR_BBK:
			case DERR_UNC:
			case DERR_HARD:
			case DERR_MEDIUM:
			case DERR_DATA_PROT:
			case DERR_MISCOMP:
				dep->dadk_rq_media_err.value.ui32++;
				break;

			case DERR_NOTREADY:
				dep->dadk_rq_ntrdy_err.value.ui32++;
				break;

			case DERR_IDNF:
			case DERR_UNIT_ATTN:
				dep->dadk_rq_nodev_err.value.ui32++;
				break;

			case DERR_ILL:
			case DERR_RESV:
				dep->dadk_rq_illrq_err.value.ui32++;
				break;

			default:
				break;
		}
	}

	/* if attempting to read a sector from a cdrom audio disk */
	if ((dadkp->dad_cdrom) &&
	    (*((char *)(pktp->cp_cdbp)) == DCMD_READ) &&
	    (scb == DERR_ILL)) {
		return (COMMAND_DONE);
	}
	if (pktp->cp_passthru == NULL) {
		gda_errmsg(dadkp->dad_sd, pktp, dadk_name,
		    dadk_errtab[scb].d_severity, pktp->cp_srtsec,
		    err_blkno, dadk_cmds, dadk_sense);
	}

	if (scb == DERR_BUSY) {
		(void) timeout(dadk_restart, (void *)pktp, DADK_BSY_TIMEOUT);
	}

	return (dadk_errtab[scb].d_action);
}

static void
dadk_recorderr(struct cmpkt *pktp, struct dadkio_rwcmd *rwcmdp)
{
	struct dadk *dadkp;
	int scb;

	dadkp = PKT2DADK(pktp);
	scb = (int)(*(char *)pktp->cp_scbp);


	rwcmdp->status.failed_blk = rwcmdp->blkaddr +
	    ((pktp->cp_bytexfer - pktp->cp_resid) >> dadkp->dad_secshf);

	rwcmdp->status.resid = pktp->cp_bp->b_resid +
	    pktp->cp_byteleft - pktp->cp_bytexfer + pktp->cp_resid;
	switch ((int)(* (char *)pktp->cp_scbp)) {
	case DERR_AMNF:
	case DERR_ABORT:
		rwcmdp->status.status = DADKIO_STAT_ILLEGAL_REQUEST;
		break;
	case DERR_DWF:
	case DERR_IDNF:
		rwcmdp->status.status = DADKIO_STAT_ILLEGAL_ADDRESS;
		break;
	case DERR_TKONF:
	case DERR_UNC:
	case DERR_BBK:
		rwcmdp->status.status = DADKIO_STAT_MEDIUM_ERROR;
		rwcmdp->status.failed_blk_is_valid = 1;
		rwcmdp->status.resid = 0;
		break;
	case DERR_BUSY:
		rwcmdp->status.status = DADKIO_STAT_NOT_READY;
		break;
	case DERR_INVCDB:
	case DERR_HARD:
		rwcmdp->status.status = DADKIO_STAT_HARDWARE_ERROR;
		break;
	case DERR_ICRC:
	default:
		rwcmdp->status.status = DADKIO_STAT_NOT_SUPPORTED;
	}

	if (rwcmdp->flags & DADKIO_FLAG_SILENT)
		return;
	gda_errmsg(dadkp->dad_sd, pktp, dadk_name, dadk_errtab[scb].d_severity,
	    rwcmdp->blkaddr, rwcmdp->status.failed_blk,
	    dadk_cmds, dadk_sense);
}

/*ARGSUSED*/
static void
dadk_polldone(struct buf *bp)
{
	struct cmpkt *pktp;
	struct dadk *dadkp;

	pktp  = GDA_BP_PKT(bp);
	dadkp = PKT2DADK(pktp);
	mutex_enter(&dadkp->dad_cmd_mutex);
	dadkp->dad_cmd_count--;
	mutex_exit(&dadkp->dad_cmd_mutex);
}

static void
dadk_iodone(struct buf *bp)
{
	struct cmpkt *pktp;
	struct dadk *dadkp;

	pktp  = GDA_BP_PKT(bp);
	dadkp = PKT2DADK(pktp);

	/* check for all iodone */
	pktp->cp_byteleft -= pktp->cp_bytexfer;
	if (geterror(bp) == 0 && pktp->cp_byteleft != 0) {
		pktp->cp_retry = 0;
		(void) dadk_iosetup(dadkp, pktp);


	/* 	transport the next one */
		if (CTL_TRANSPORT(dadkp->dad_ctlobjp, pktp) == CTL_SEND_SUCCESS)
			return;
		if ((dadk_ioretry(pktp, QUE_COMMAND)) == JUST_RETURN)
			return;
	}

	/* start next one */
	FLC_DEQUE(dadkp->dad_flcobjp, bp);

	/* free pkt */
	if (pktp->cp_private)
		BBH_FREEHANDLE(dadkp->dad_bbhobjp, pktp->cp_private);
	gda_free(dadkp->dad_ctlobjp, pktp, NULL);
	mutex_enter(&dadkp->dad_cmd_mutex);
	dadkp->dad_cmd_count--;
	mutex_exit(&dadkp->dad_cmd_mutex);
	biodone(bp);
}

int
dadk_check_media(opaque_t objp, int *state)
{
	struct dadk *dadkp = (struct dadk *)objp;

	if (!dadkp->dad_rmb) {
		return (ENXIO);
	}
#ifdef DADK_DEBUG
	if (dadk_debug & DSTATE)
		PRF("dadk_check_media: user state %x disk state %x\n",
		    *state, dadkp->dad_iostate);
#endif
	/*
	 * If state already changed just return
	 */
	if (*state != dadkp->dad_iostate) {
		*state = dadkp->dad_iostate;
		return (0);
	}

	/*
	 * Startup polling on thread state
	 */
	mutex_enter(&dadkp->dad_mutex);
	if (dadkp->dad_thread_cnt == 0) {
		/*
		 * One thread per removable dadk device
		 */
		(void) thread_create(NULL, 0, dadk_watch_thread, dadkp, 0, &p0,
		    TS_RUN, v.v_maxsyspri - 2);
	}
	dadkp->dad_thread_cnt++;

	/*
	 * Wait for state to change
	 */
	do {
		if (cv_wait_sig(&dadkp->dad_state_cv, &dadkp->dad_mutex) == 0) {
			dadkp->dad_thread_cnt--;
			mutex_exit(&dadkp->dad_mutex);
			return (EINTR);
		}
	} while (*state == dadkp->dad_iostate);
	*state = dadkp->dad_iostate;
	dadkp->dad_thread_cnt--;
	mutex_exit(&dadkp->dad_mutex);
	return (0);
}


#define	MEDIA_ACCESS_DELAY 2000000

static void
dadk_watch_thread(struct dadk *dadkp)
{
	enum dkio_state state;
	int interval;

	interval = drv_usectohz(dadk_check_media_time);

	do {
		if (dadk_rmb_ioctl(dadkp, DCMD_GET_STATE, (intptr_t)&state, 0,
		    DADK_SILENT)) {
			/*
			 * Assume state remained the same
			 */
			state = dadkp->dad_iostate;
		}

		/*
		 * now signal the waiting thread if this is *not* the
		 * specified state;
		 * delay the signal if the state is DKIO_INSERTED
		 * to allow the target to recover
		 */
		if (state != dadkp->dad_iostate) {

			dadkp->dad_iostate = state;
			if (state == DKIO_INSERTED) {
				/*
				 * delay the signal to give the drive a chance
				 * to do what it apparently needs to do
				 */
				(void) timeout((void(*)(void *))cv_broadcast,
				    (void *)&dadkp->dad_state_cv,
				    drv_usectohz((clock_t)MEDIA_ACCESS_DELAY));
			} else {
				cv_broadcast(&dadkp->dad_state_cv);
			}
		}
		delay(interval);
	} while (dadkp->dad_thread_cnt);
}

int
dadk_inquiry(opaque_t objp, opaque_t *inqpp)
{
	struct dadk *dadkp = (struct dadk *)objp;
	struct scsi_inquiry **sinqpp = (struct scsi_inquiry **)inqpp;

	if (dadkp && dadkp->dad_sd && dadkp->dad_sd->sd_inq) {
		*sinqpp = dadkp->dad_sd->sd_inq;
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

static int
dadk_rmb_ioctl(struct dadk *dadkp, int cmd, intptr_t arg, int flags, int silent)

{
	struct buf *bp;
	int err;
	struct cmpkt *pktp;

	if ((bp = getrbuf(KM_SLEEP)) == NULL) {
		return (ENOMEM);
	}
	pktp = dadk_pktprep(dadkp, NULL, bp, dadk_rmb_iodone, NULL, NULL);
	if (!pktp) {
		freerbuf(bp);
		return (ENOMEM);
	}
	bp->b_back  = (struct buf *)arg;
	bp->b_forw  = (struct buf *)dadkp->dad_flcobjp;
	pktp->cp_passthru = (opaque_t)(intptr_t)silent;

	err = dadk_ctl_ioctl(dadkp, cmd, (uintptr_t)pktp, flags);
	freerbuf(bp);
	gda_free(dadkp->dad_ctlobjp, pktp, NULL);
	return (err);


}

static void
dadk_rmb_iodone(struct buf *bp)
{
	struct cmpkt *pktp;
	struct dadk *dadkp;

	pktp  = GDA_BP_PKT(bp);
	dadkp = PKT2DADK(pktp);

	bp->b_flags &= ~(B_DONE|B_BUSY);

	/* Start next one */
	FLC_DEQUE(dadkp->dad_flcobjp, bp);

	mutex_enter(&dadkp->dad_cmd_mutex);
	dadkp->dad_cmd_count--;
	mutex_exit(&dadkp->dad_cmd_mutex);
	biodone(bp);
}

static int
dadk_dk_buf_setup(struct dadk *dadkp, opaque_t *cmdp, dev_t dev,
	enum uio_seg dataspace, int rw)
{
	struct dadkio_rwcmd *rwcmdp = (struct dadkio_rwcmd *)cmdp;
	struct buf	*bp;
	struct iovec	aiov;
	struct uio	auio;
	struct uio	*uio = &auio;
	int		status;

	bp = getrbuf(KM_SLEEP);

	bp->av_forw = bp->b_forw = (struct buf *)dadkp;
	bp->b_back  = (struct buf *)rwcmdp;	/* ioctl packet */

	bzero((caddr_t)&auio, sizeof (struct uio));
	bzero((caddr_t)&aiov, sizeof (struct iovec));
	aiov.iov_base = rwcmdp->bufaddr;
	aiov.iov_len = rwcmdp->buflen;
	uio->uio_iov = &aiov;

	uio->uio_iovcnt = 1;
	uio->uio_resid = rwcmdp->buflen;
	uio->uio_segflg = dataspace;

	/* Let physio do the rest... */
	status = physio(dadk_dk_strategy, bp, dev, rw, dadkmin, uio);

	freerbuf(bp);
	return (status);

}

/* Do not let a user gendisk request get too big or */
/* else we could use to many resources.		    */

static void
dadkmin(struct buf *bp)
{
	if (bp->b_bcount > dadk_dk_maxphys)
		bp->b_bcount = dadk_dk_maxphys;
}

static int
dadk_dk_strategy(struct buf *bp)
{
	dadk_dk((struct dadk *)bp->av_forw, (struct dadkio_rwcmd *)bp->b_back,
	    bp);
	return (0);
}

static void
dadk_dk(struct dadk *dadkp, struct dadkio_rwcmd *rwcmdp, struct buf *bp)
{
	struct  cmpkt *pktp;

	pktp = dadk_pktprep(dadkp, NULL, bp, dadk_iodone, NULL, NULL);
	if (!pktp) {
		bioerror(bp, ENOMEM);
		biodone(bp);
		return;
	}

	pktp->cp_passthru = rwcmdp;

	(void) dadk_ioprep(dadkp, pktp);

	mutex_enter(&dadkp->dad_cmd_mutex);
	dadkp->dad_cmd_count++;
	mutex_exit(&dadkp->dad_cmd_mutex);
	FLC_ENQUE(dadkp->dad_flcobjp, bp);
}

/*
 * There is no existing way to notify cmdk module
 * when the command completed, so add this function
 * to calculate how many on-going commands.
 */
int
dadk_getcmds(opaque_t objp)
{
	struct dadk *dadkp = (struct dadk *)objp;
	int count;

	mutex_enter(&dadkp->dad_cmd_mutex);
	count = dadkp->dad_cmd_count;
	mutex_exit(&dadkp->dad_cmd_mutex);
	return (count);
}

/*
 * this function was used to calc the cmd for CTL_IOCTL
 */
static int
dadk_ctl_ioctl(struct dadk *dadkp, uint32_t cmd, uintptr_t arg, int flag)
{
	int error;
	mutex_enter(&dadkp->dad_cmd_mutex);
	dadkp->dad_cmd_count++;
	mutex_exit(&dadkp->dad_cmd_mutex);
	error = CTL_IOCTL(dadkp->dad_ctlobjp, cmd, arg, flag);
	mutex_enter(&dadkp->dad_cmd_mutex);
	dadkp->dad_cmd_count--;
	mutex_exit(&dadkp->dad_cmd_mutex);
	return (error);
}
