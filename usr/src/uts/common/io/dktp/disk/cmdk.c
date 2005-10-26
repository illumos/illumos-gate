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

#include <sys/scsi/scsi.h>
#include <sys/dktp/cm.h>
#include <sys/dktp/quetypes.h>
#include <sys/dktp/queue.h>
#include <sys/dktp/fctypes.h>
#include <sys/dktp/flowctrl.h>
#include <sys/dktp/cmdev.h>
#include <sys/dkio.h>
#include <sys/dktp/tgdk.h>
#include <sys/dktp/dadk.h>
#include <sys/dktp/bbh.h>

#include <sys/dktp/cmdk.h>
#include <sys/stat.h>
#include <sys/vtoc.h>
#include <sys/file.h>
#include <sys/dktp/dadkio.h>
#include <sys/dktp/dklb.h>
#include <sys/aio_req.h>

/*
 * Local Static Data
 */
#ifdef CMDK_DEBUG
#define	DENT	0x0001
#define	DIO	0x0002

static	int	cmdk_debug = DIO;
#endif

#ifndef	TRUE
#define	TRUE	1
#endif

#ifndef	FALSE
#define	FALSE	0
#endif

/*
 * NDKMAP is the base number for accessing the fdisk partitions.
 * c?d?p0 --> cmdk@?,?:q
 */
#define	PARTITION0_INDEX	(NDKMAP + 0)

#define	DKTP_DATA		(dkp->dk_tgobjp)->tg_data
#define	DKTP_EXT		(dkp->dk_tgobjp)->tg_ext

static void *cmdk_state;

/*
 * the cmdk_attach_mutex protects cmdk_max_instance in multi-threaded
 * attach situations
 */
static kmutex_t cmdk_attach_mutex;
static int cmdk_max_instance = 0;

/*
 * Panic dumpsys state
 * There is only a single flag that is not mutex locked since
 * the system is prevented from thread switching and cmdk_dump
 * will only be called in a single threaded operation.
 */
static int	cmdk_indump;

static struct driver_minor_data {
	char    *name;
	int	minor;
	int	type;
} cmdk_minor_data[] = {
	{"a", 0, S_IFBLK},
	{"b", 1, S_IFBLK},
	{"c", 2, S_IFBLK},
	{"d", 3, S_IFBLK},
	{"e", 4, S_IFBLK},
	{"f", 5, S_IFBLK},
	{"g", 6, S_IFBLK},
	{"h", 7, S_IFBLK},
	{"i", 8, S_IFBLK},
	{"j", 9, S_IFBLK},
	{"k", 10, S_IFBLK},
	{"l", 11, S_IFBLK},
	{"m", 12, S_IFBLK},
	{"n", 13, S_IFBLK},
	{"o", 14, S_IFBLK},
	{"p", 15, S_IFBLK},
	{"q", 16, S_IFBLK},
	{"r", 17, S_IFBLK},
	{"s", 18, S_IFBLK},
	{"t", 19, S_IFBLK},
	{"u", 20, S_IFBLK},
	{"a,raw", 0, S_IFCHR},
	{"b,raw", 1, S_IFCHR},
	{"c,raw", 2, S_IFCHR},
	{"d,raw", 3, S_IFCHR},
	{"e,raw", 4, S_IFCHR},
	{"f,raw", 5, S_IFCHR},
	{"g,raw", 6, S_IFCHR},
	{"h,raw", 7, S_IFCHR},
	{"i,raw", 8, S_IFCHR},
	{"j,raw", 9, S_IFCHR},
	{"k,raw", 10, S_IFCHR},
	{"l,raw", 11, S_IFCHR},
	{"m,raw", 12, S_IFCHR},
	{"n,raw", 13, S_IFCHR},
	{"o,raw", 14, S_IFCHR},
	{"p,raw", 15, S_IFCHR},
	{"q,raw", 16, S_IFCHR},
	{"r,raw", 17, S_IFCHR},
	{"s,raw", 18, S_IFCHR},
	{"t,raw", 19, S_IFCHR},
	{"u,raw", 20, S_IFCHR},
	{0}
};

/*
 * Local Function Prototypes
 */
static int cmdk_reopen(struct cmdk *dkp);
static int cmdk_create_obj(dev_info_t *dip, struct cmdk *dkp);
static void cmdk_destroy_obj(dev_info_t *dip, struct cmdk *dkp);
static int cmdk_create_lbobj(dev_info_t *dip, struct cmdk *dkp);
static void cmdk_destroy_lbobj(dev_info_t *dip, struct cmdk *dkp, int unload);
static void cmdkmin(struct buf *bp);
static int cmdkrw(dev_t dev, struct uio *uio, int flag);
static int cmdkarw(dev_t dev, struct aio_req *aio, int flag);
static int cmdk_part_info(struct cmdk *dkp, int force, daddr_t *startp,
    long *countp, int part);
static void cmdk_part_info_init(struct cmdk *dkp);
static void cmdk_part_info_fini(struct cmdk *dkp);

#ifdef	NOT_USED
static void cmdk_devstatus(struct cmdk *dkp);
#endif	/* NOT_USED */

/*
 * Bad Block Handling Functions Prototypes
 */
static opaque_t cmdk_bbh_gethandle(opaque_t bbh_data, struct buf *bp);
static bbh_cookie_t cmdk_bbh_htoc(opaque_t bbh_data, opaque_t handle);
static void cmdk_bbh_freehandle(opaque_t bbh_data, opaque_t handle);

static struct bbh_objops cmdk_bbh_ops = {
	nulldev,
	nulldev,
	cmdk_bbh_gethandle,
	cmdk_bbh_htoc,
	cmdk_bbh_freehandle,
	0, 0
};

static struct bbh_obj cmdk_bbh_obj = {
	NULL,
	&cmdk_bbh_ops
};

static int cmdkopen(dev_t *dev_p, int flag, int otyp, cred_t *credp);
static int cmdkclose(dev_t dev, int flag, int otyp, cred_t *credp);
static int cmdkstrategy(struct buf *bp);
static int cmdkdump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk);
static int cmdkioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int cmdkread(dev_t dev, struct uio *uio, cred_t *credp);
static int cmdkwrite(dev_t dev, struct uio *uio, cred_t *credp);
static int cmdk_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int mod_flags, char *name, caddr_t valuep, int *lengthp);
static int cmdkaread(dev_t dev, struct aio_req *aio, cred_t *credp);
static int cmdkawrite(dev_t dev, struct aio_req *aio, cred_t *credp);

/*
 * Configuration Data
 */

/*
 * Device driver ops vector
 */

static struct cb_ops cmdk_cb_ops = {
	cmdkopen, 		/* open */
	cmdkclose, 		/* close */
	cmdkstrategy, 		/* strategy */
	nodev, 			/* print */
	cmdkdump, 		/* dump */
	cmdkread, 		/* read */
	cmdkwrite, 		/* write */
	cmdkioctl, 		/* ioctl */
	nodev, 			/* devmap */
	nodev, 			/* mmap */
	nodev, 			/* segmap */
	nochpoll, 		/* poll */
	cmdk_prop_op, 		/* cb_prop_op */
	0, 			/* streamtab  */
	D_64BIT | D_MP | D_NEW,	/* Driver comaptibility flag */
	CB_REV,			/* cb_rev */
	cmdkaread,		/* async read */
	cmdkawrite		/* async write */
};

static int cmdkinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result);
static int cmdkprobe(dev_info_t *dip);
static int cmdkattach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int cmdkdetach(dev_info_t *dip, ddi_detach_cmd_t cmd);

struct dev_ops cmdk_ops = {
	DEVO_REV, 		/* devo_rev, */
	0, 			/* refcnt  */
	cmdkinfo,		/* info */
	nulldev, 		/* identify */
	cmdkprobe, 		/* probe */
	cmdkattach, 		/* attach */
	cmdkdetach,		/* detach */
	nodev, 			/* reset */
	&cmdk_cb_ops, 		/* driver operations */
	(struct bus_ops *)0	/* bus operations */
};

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops, 	/* Type of module. This one is a driver */
	"Common Direct Access Disk %I%",
	&cmdk_ops, 				/* driver ops 		*/
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	int 	rval;

	if (rval = ddi_soft_state_init(&cmdk_state, sizeof (struct cmdk), 7))
		return (rval);

	mutex_init(&cmdk_attach_mutex, NULL, MUTEX_DRIVER, NULL);
	if ((rval = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&cmdk_attach_mutex);
		ddi_soft_state_fini(&cmdk_state);
	}
	return (rval);
}

int
_fini(void)
{
	return (EBUSY);

	/*
	 * This has been commented out until cmdk is a true
	 * unloadable module. Right now x86's are panicking on
	 * a diskless reconfig boot.
	 */

#if 0 	/* bugid 1186679 */
	int	rval;

	rval = mod_remove(&modlinkage);
	if (rval != 0)
		return (rval);

	mutex_destroy(&cmdk_attach_mutex);
	ddi_soft_state_fini(&cmdk_state);

	return (0);
#endif
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*	pseudo BBH functions						*/
/*ARGSUSED*/
static opaque_t
cmdk_bbh_gethandle(opaque_t bbh_data, struct buf *bp)
{
	return (NULL);
}

/*ARGSUSED*/
static bbh_cookie_t
cmdk_bbh_htoc(opaque_t bbh_data, opaque_t handle)
{
	return (NULL);
}

/*ARGSUSED*/
static void
cmdk_bbh_freehandle(opaque_t bbh_data, opaque_t handle)
{
}

/*
 * Autoconfiguration Routines
 */
static int
cmdkprobe(dev_info_t *dip)
{
	int 	instance;
	int	status;
	struct	cmdk	*dkp;

	instance = ddi_get_instance(dip);

	if (ddi_get_soft_state(cmdk_state, instance))
		return (DDI_PROBE_PARTIAL);

	if ((ddi_soft_state_zalloc(cmdk_state, instance) != DDI_SUCCESS) ||
	    ((dkp = ddi_get_soft_state(cmdk_state, instance)) == NULL))
		return (DDI_PROBE_PARTIAL);

	dkp->dk_dip = dip;

	/* for property create inside DKLB_*() */
	dkp->dk_dev = makedevice(ddi_driver_major(dip),
	    ddi_get_instance(dip) << CMDK_UNITSHF);

	if (cmdk_create_obj(dip, dkp) != DDI_SUCCESS) {
		ddi_soft_state_free(cmdk_state, instance);
		return (DDI_PROBE_PARTIAL);
	}

	status = dadk_probe(DKTP_DATA, KM_NOSLEEP);
	if (status != DDI_PROBE_SUCCESS) {
		cmdk_destroy_obj(dip, dkp);
		ddi_soft_state_free(cmdk_state, instance);
		return (status);
	}

	sema_init(&dkp->dk_semoclose, 1, NULL, SEMA_DRIVER, NULL);

#ifdef CMDK_DEBUG
	if (cmdk_debug & DENT)
		PRF("cmdkprobe: instance= %d name= `%s`\n",
		    instance, ddi_get_name_addr(dip));
#endif
	return (status);
}

static int
cmdkattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int 	instance;
	long	start, count;
	struct 	driver_minor_data *dmdp;
	struct	cmdk *dkp;
	char 	*node_type;
	char	name[48];

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)))
		return (DDI_FAILURE);

	/* dadk_attach is an empty function that only returns SUCCESS */
	(void) dadk_attach(DKTP_DATA);

	node_type = DKTP_EXT->tg_nodetype;
	for (dmdp = cmdk_minor_data; dmdp->name != NULL; dmdp++) {
		minor_t minor_num = (instance << CMDK_UNITSHF) | dmdp->minor;

		(void) sprintf(name, "%s", dmdp->name);
		if (ddi_create_minor_node(dip, name, dmdp->type, minor_num,
		    node_type, NULL) == DDI_FAILURE) {

			cmdk_destroy_obj(dip, dkp);

			sema_destroy(&dkp->dk_semoclose);
			ddi_soft_state_free(cmdk_state, instance);

			ddi_remove_minor_node(dip, NULL);
			ddi_prop_remove_all(dip);
			return (DDI_FAILURE);
		}
	}
	mutex_enter(&cmdk_attach_mutex);
	if (instance > cmdk_max_instance)
		cmdk_max_instance = instance;
	mutex_exit(&cmdk_attach_mutex);

	/*
	 * Add a zero-length attribute to tell the world we support
	 * kernel ioctls (for layered drivers)
	 */
	(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0);
	ddi_report_dev(dip);

	cmdk_part_info_init(dkp);

	/* Need to open the label and register devid early */
	(void) cmdk_part_info(dkp, TRUE, &start, &count, PARTITION0_INDEX);

	return (DDI_SUCCESS);
}


static int
cmdkdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct cmdk	*dkp;
	int 		instance;
	int		max_instance;

	if (cmd != DDI_DETACH) {
#ifdef CMDK_DEBUG
		if (cmdk_debug & DIO) {
			PRF("cmdkdetach: cmd = %d unknown\n", cmd);
		}
#endif
		return (DDI_FAILURE);
	}

	mutex_enter(&cmdk_attach_mutex);
	max_instance = cmdk_max_instance;
	mutex_exit(&cmdk_attach_mutex);

	for (instance = 0; instance < max_instance; instance++) {
		dkp = ddi_get_soft_state(cmdk_state, instance);
		if (!dkp)
			continue;
		if (dkp->dk_flag & CMDK_OPEN)
			return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)))
		return (DDI_SUCCESS);

	/*
	 * The cmdk_part_info call at the end of cmdkattach may have
	 * caused cmdk_reopen to do a TGDK_OPEN, make sure we close on
	 * detach for case when cmdkopen/cmdkclose never occurs.
	 */
	if (dkp->dk_flag & CMDK_TGDK_OPEN) {
		dkp->dk_flag &= ~CMDK_TGDK_OPEN;
		(void) dadk_close(DKTP_DATA);
	}

	cmdk_part_info_fini(dkp);
	cmdk_destroy_lbobj(dip, dkp, 1);
	cmdk_destroy_obj(dip, dkp);

	sema_destroy(&dkp->dk_semoclose);
	ddi_soft_state_free(cmdk_state, instance);

	ddi_prop_remove_all(dip);
	ddi_remove_minor_node(dip, NULL);
	return (DDI_SUCCESS);
}

static int
cmdkinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t		dev = (dev_t)arg;
	int 		instance;
	struct	cmdk	*dkp;

#ifdef lint
	dip = dip;	/* no one ever uses this */
#endif

#ifdef CMDK_DEBUG
	if (cmdk_debug & DENT)
		PRF("cmdkinfo: call\n");
#endif
	instance = CMDKUNIT(dev);

	switch (infocmd) {
		case DDI_INFO_DEVT2DEVINFO:
			if (!(dkp = ddi_get_soft_state(cmdk_state, instance)))
				return (DDI_FAILURE);
			*result = (void *) dkp->dk_dip;
			break;
		case DDI_INFO_DEVT2INSTANCE:
			*result = (void *)(intptr_t)instance;
			break;
		default:
			return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
cmdk_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
	int		instance = ddi_get_instance(dip);
	struct	cmdk	*dkp;
	long		lblocks;
	uint64_t	nblocks64;
	daddr_t		p_lblksrt;

#ifdef CMDK_DEBUG
	if (cmdk_debug & DENT)
		PRF("cmdk_prop_op: call\n");
#endif

	/*
	 * Our dynamic properties are all device specific and size oriented.
	 * Requests issued under conditions where size is valid are passed
	 * to ddi_prop_op_nblocks with the size information, otherwise the
	 * request is passed to ddi_prop_op. Size depends on valid label.
	 */
	dkp = ddi_get_soft_state(cmdk_state, instance);
	if ((dev == DDI_DEV_T_ANY) || (dkp == NULL) ||
	    !(dkp->dk_flag & CMDK_VALID_LABEL)) {
pass:		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));
	} else {
		/* force re-read of MBR and label and partition info */
		if (!cmdk_part_info(dkp, TRUE, &p_lblksrt,
		    &lblocks, CMDKPART(dev)))
			goto pass;

		/* get nblocks value */
		nblocks64 = (ulong_t)lblocks;
		return (ddi_prop_op_nblocks(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp, nblocks64));
	}
}

/*
 * dump routine
 */
static int
cmdkdump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	int 		instance;
	struct	cmdk	*dkp;
	daddr_t		p_lblksrt;
	long		p_lblkcnt;
	struct	buf	local;
	struct	buf	*bp;

#ifdef CMDK_DEBUG
	if (cmdk_debug & DENT)
		PRF("cmdkdump: call\n");
#endif
	instance = CMDKUNIT(dev);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)) || (blkno < 0))
		return (ENXIO);

	DKLB_PARTINFO(dkp->dk_lbobjp, &p_lblksrt, &p_lblkcnt, CMDKPART(dev));

	if ((blkno+nblk) > p_lblkcnt)
		return (EINVAL);

	cmdk_indump = 1;	/* Tell disk targets we are panic dumpping */

	bp = &local;
	bzero(bp, sizeof (*bp));
	bp->b_flags = B_BUSY;
	bp->b_un.b_addr = addr;
	bp->b_bcount = nblk << SCTRSHFT;
	SET_BP_SEC(bp, (p_lblksrt + blkno));

	(void) dadk_dump(DKTP_DATA, bp);
	return (bp->b_error);
}

/*
 * Copy in the dadkio_rwcmd according to the user's data model.  If needed,
 * convert it for our internal use.
 */
static int
rwcmd_copyin(struct dadkio_rwcmd *rwcmdp, caddr_t inaddr, int flag)
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
			rwcmdp->blkaddr = (daddr_t)cmd32.blkaddr;
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
 * If necessary, convert the internal rwcmdp and status to the appropriate
 * data model and copy it out to the user.
 */
static int
rwcmd_copyout(struct dadkio_rwcmd *rwcmdp, caddr_t outaddr, int flag)
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

/*
 * ioctl routine
 */
static int
cmdkioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *credp,
	int *rvalp)
{
	int 		instance;
	struct scsi_device *devp;
	struct cmdk	*dkp;
	char 		data[NBPSCTR];

	instance = CMDKUNIT(dev);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)))
		return (ENXIO);

	bzero(data, sizeof (data));

	switch (cmd) {

	case DKIOCGMEDIAINFO: {
		struct dk_minfo	media_info;
		struct  tgdk_geom phyg;

		(void) dadk_getphygeom(DKTP_DATA, &phyg);

		media_info.dki_lbsize = phyg.g_secsiz;
		media_info.dki_capacity = phyg.g_cap;
		media_info.dki_media_type = DK_FIXED_DISK;

		if (ddi_copyout(&media_info, (void *)arg,
		    sizeof (struct dk_minfo), flag)) {
			return (EFAULT);
		} else {
			return (0);
		}
	}

	case DKIOCINFO: {
		struct dk_cinfo *info = (struct dk_cinfo *)data;

		/* controller information */
		info->dki_ctype = DKTP_EXT->tg_ctype;
		info->dki_cnum = ddi_get_instance(ddi_get_parent(dkp->dk_dip));
		(void) strcpy(info->dki_cname,
		    ddi_get_name(ddi_get_parent(dkp->dk_dip)));

		/* Unit Information */
		info->dki_unit = ddi_get_instance(dkp->dk_dip);
		devp = ddi_get_driver_private(dkp->dk_dip);
		info->dki_slave = (CMDEV_TARG(devp)<<3) | CMDEV_LUN(devp);
		(void) strcpy(info->dki_dname, ddi_driver_name(dkp->dk_dip));
		info->dki_flags = DKI_FMTVOL;
		info->dki_partition = CMDKPART(dev);

		info->dki_maxtransfer = maxphys / DEV_BSIZE;
		info->dki_addr = 1;
		info->dki_space = 0;
		info->dki_prio = 0;
		info->dki_vec = 0;

		if (ddi_copyout(data, (void *)arg, sizeof (*info), flag))
			return (EFAULT);
		else
			return (0);
	}

	case DKIOCPARTINFO: {
		daddr_t	start;
		long len;
		STRUCT_DECL(part_info, p);

		/*
		 * force re-read of MBR and label and partition info
		 */
		if (!cmdk_part_info(dkp, TRUE, &start, &len, CMDKPART(dev)))
			return (ENXIO);

		if (len > INT_MAX)
			return (EOVERFLOW);

		STRUCT_INIT(p, flag & FMODELS);
		STRUCT_FSET(p, p_start, start);
		STRUCT_FSET(p, p_length, (int)len);
		if (ddi_copyout(STRUCT_BUF(p), (caddr_t)arg, STRUCT_SIZE(p),
		    flag))
			return (EFAULT);
		return (0);
	}

	case DKIOCSTATE: {
		int	state;
		int	rval;
		int 	part;
		daddr_t	p_lblksrt;
		long	p_lblkcnt;

		if (ddi_copyin((void *)arg, &state, sizeof (int), flag))
			return (EFAULT);

		/* dadk_check_media blocks until state changes */
		if (rval = dadk_check_media(DKTP_DATA, &state))
			return (rval);

		if (state == DKIO_INSERTED) {
			part = CMDKPART(dev);
			/*
			 * force re-read of MBR and label and partition info
			 */
			if (!cmdk_part_info(dkp, TRUE, &p_lblksrt, &p_lblkcnt,
			    part))
				return (ENXIO);

			if (part < 0 || p_lblkcnt <= 0)
				return (ENXIO);
		}

		if (ddi_copyout(&state, (caddr_t)arg, sizeof (int), flag))
			return (EFAULT);

		return (0);
	}

	/*
	 * is media removable?
	 */
	case DKIOCREMOVABLE: {
		int i;

		i = (DKTP_EXT->tg_rmb) ? 1 : 0;

		if (ddi_copyout(&i, (caddr_t)arg, sizeof (int), flag))
			return (EFAULT);

		return (0);
	}

	case DKIOCG_PHYGEOM:
	case DKIOCG_VIRTGEOM:
	case DKIOCGGEOM:
	case DKIOCSGEOM:
	case DKIOCSVTOC:
	case DKIOCGVTOC:
	case DKIOCGAPART:
	case DKIOCSAPART:
	case DKIOCADDBAD:

		/* If we don't have a label obj we can't call its ioctl */
		if (!dkp->dk_lbobjp)
			return (EIO);

		return (DKLB_IOCTL(dkp->dk_lbobjp, cmd, arg, flag,
			credp, rvalp));

	case DIOCTL_RWCMD: {
		struct	dadkio_rwcmd *rwcmdp;
		int	status;

		rwcmdp = kmem_alloc(sizeof (struct dadkio_rwcmd), KM_SLEEP);

		status = rwcmd_copyin(rwcmdp, (caddr_t)arg, flag);

		if (status == 0) {
			bzero(&(rwcmdp->status), sizeof (struct dadkio_status));
			status = dadk_ioctl(DKTP_DATA,
			    dev,
			    cmd,
			    (uintptr_t)rwcmdp,
			    flag,
			    credp,
			    rvalp);
		}
		if (status == 0)
			status = rwcmd_copyout(rwcmdp, (caddr_t)arg, flag);

		kmem_free(rwcmdp, sizeof (struct dadkio_rwcmd));
		return (status);
	}

	default:
		return (dadk_ioctl(DKTP_DATA,
		    dev,
		    cmd,
		    arg,
		    flag,
		    credp,
		    rvalp));
	}
}

/*ARGSUSED1*/
static int
cmdkclose(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int		part;
	ulong_t		partbit;
	int 		instance;
	struct cmdk	*dkp;
	int		i;

	instance = CMDKUNIT(dev);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)) ||
	    (otyp >= OTYPCNT))
		return (ENXIO);

	sema_p(&dkp->dk_semoclose);

	/* check for device has been opened */
	if (!(dkp->dk_flag & CMDK_OPEN)) {
		sema_v(&dkp->dk_semoclose);
		return (ENXIO);
	}

	part = CMDKPART(dev);
	if (part < 0) {
		sema_v(&dkp->dk_semoclose);
		return (ENXIO);
	}
	partbit = 1 << part;

	/* account for close */
	if (otyp == OTYP_LYR) {
		if (dkp->dk_open.dk_lyr[part])
			dkp->dk_open.dk_lyr[part]--;
	} else
		dkp->dk_open.dk_reg[otyp] &= ~partbit;
	dkp->dk_open.dk_exl &= ~partbit;

	/* check for last close */
	for (i = 0; i < OTYPCNT; i++) {
		if (dkp->dk_open.dk_reg[i])
			break;
	}
	if (i >= OTYPCNT) {
		for (i = 0; i < CMDK_MAXPART; i++) {
			if (dkp->dk_open.dk_lyr[i])
				break;
		}
		if (i >= CMDK_MAXPART) {
			/* OK, last close */
			(void) dadk_close(DKTP_DATA);
			dkp->dk_flag &=
			    ~(CMDK_OPEN | CMDK_TGDK_OPEN | CMDK_VALID_LABEL);
		}
	}

	sema_v(&dkp->dk_semoclose);
	return (DDI_SUCCESS);
}

/*ARGSUSED3*/
static int
cmdkopen(dev_t *dev_p, int flag, int otyp, cred_t *credp)
{
	dev_t		dev = *dev_p;
	int 		part;
	ulong_t		partbit;
	int 		instance;
	struct	cmdk	*dkp;
	daddr_t		p_lblksrt;
	long		p_lblkcnt;
	int		i;

	instance = CMDKUNIT(dev);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)))
		return (ENXIO);

	if (otyp >= OTYPCNT)
		return (EINVAL);

	if ((part = CMDKPART(dev)) < 0)
		return (ENXIO);

	sema_p(&dkp->dk_semoclose);

	/* re-do the target open */
	if (cmdk_part_info(dkp, TRUE, &p_lblksrt, &p_lblkcnt, part)) {
		if (p_lblkcnt <= 0 &&
		    ((flag & (FNDELAY|FNONBLOCK)) == 0 || otyp != OTYP_CHR)) {
			sema_v(&dkp->dk_semoclose);
			return (ENXIO);
		}
	} else {
		/* fail if not doing non block open */
		if ((flag & (FNONBLOCK|FNDELAY)) == 0) {
			sema_v(&dkp->dk_semoclose);
			return (ENXIO);
		}
	}
	if (DKTP_EXT->tg_rdonly && (flag & FWRITE)) {
		sema_v(&dkp->dk_semoclose);
		return (EROFS);
	}

	partbit = 1 << part;

	/* check for part already opend exclusively */
	if (dkp->dk_open.dk_exl & partbit)
		goto excl_open_fail;

	/* check if we can establish exclusive open */
	if (flag & FEXCL) {
		if (dkp->dk_open.dk_lyr[part])
			goto excl_open_fail;
		for (i = 0; i < OTYPCNT; i++) {
			if (dkp->dk_open.dk_reg[i] & partbit)
				goto excl_open_fail;
		}
	}

	/* open will succeed, acount for open */
	dkp->dk_flag |= CMDK_OPEN;
	if (otyp == OTYP_LYR)
		dkp->dk_open.dk_lyr[part]++;
	else
		dkp->dk_open.dk_reg[otyp] |= partbit;
	if (flag & FEXCL)
		dkp->dk_open.dk_exl |= partbit;

	sema_v(&dkp->dk_semoclose);
	return (DDI_SUCCESS);

excl_open_fail:
	sema_v(&dkp->dk_semoclose);
	return (EBUSY);
}

static int
cmdk_reopen(struct cmdk *dkp)
{
	/* open the target disk	 */
	if (dadk_open(DKTP_DATA, 0) != DDI_SUCCESS)
		return (FALSE);

	/* mark as having opened target */
	dkp->dk_flag |= CMDK_TGDK_OPEN;

	/* check for valid label object */
	if (!dkp->dk_lbobjp)
		if (cmdk_create_lbobj(dkp->dk_dip, dkp) != DDI_SUCCESS)
			return (FALSE);

	/* reset back to pseudo bbh */
	(void) dadk_set_bbhobj(DKTP_DATA, &cmdk_bbh_obj);

	/* search for proper disk label object */
	(void) DKLB_OPEN(dkp->dk_lbobjp, dkp->dk_dev, dkp->dk_dip);

	dkp->dk_flag |= CMDK_VALID_LABEL;
	return (TRUE);
}

/*
 * read routine
 */
/*ARGSUSED2*/
static int
cmdkread(dev_t dev, struct uio *uio, cred_t *credp)
{
	return (cmdkrw(dev, uio, B_READ));
}

/*
 * async read routine
 */
/*ARGSUSED2*/
static int
cmdkaread(dev_t dev, struct aio_req *aio, cred_t *credp)
{
	return (cmdkarw(dev, aio, B_READ));
}

/*
 * write routine
 */
/*ARGSUSED2*/
static int
cmdkwrite(dev_t dev, struct uio *uio, cred_t *credp)
{
	return (cmdkrw(dev, uio, B_WRITE));
}

/*
 * async write routine
 */
/*ARGSUSED2*/
static int
cmdkawrite(dev_t dev, struct aio_req *aio, cred_t *credp)
{
	return (cmdkarw(dev, aio, B_WRITE));
}

static void
cmdkmin(struct buf *bp)
{
	if (bp->b_bcount > DK_MAXRECSIZE)
		bp->b_bcount = DK_MAXRECSIZE;
}

static int
cmdkrw(dev_t dev, struct uio *uio, int flag)
{
	return (physio(cmdkstrategy, (struct buf *)0, dev, flag, cmdkmin, uio));
}

static int
cmdkarw(dev_t dev, struct aio_req *aio, int flag)
{
	return (aphysio(cmdkstrategy, anocancel, dev, flag, cmdkmin, aio));
}

/*
 * strategy routine
 */
static int
cmdkstrategy(struct buf *bp)
{
	int 		instance;
	struct	cmdk 	*dkp;
	long		d_cnt;
	daddr_t		p_lblksrt;
	long		p_lblkcnt;

	instance = CMDKUNIT(bp->b_edev);
	if (cmdk_indump || !(dkp = ddi_get_soft_state(cmdk_state, instance)) ||
	    (dkblock(bp) < 0)) {
		bp->b_resid = bp->b_bcount;
		SETBPERR(bp, ENXIO);
		biodone(bp);
		return (0);
	}

	bp->b_flags &= ~(B_DONE|B_ERROR);
	bp->b_resid = 0;
	bp->av_back = NULL;

	/*
	 * only re-read the vtoc if necessary (force == FALSE)
	 */
	if (!cmdk_part_info(dkp, FALSE, &p_lblksrt, &p_lblkcnt,
	    CMDKPART(bp->b_edev))) {
		SETBPERR(bp, ENXIO);
	}

	if ((bp->b_bcount & (NBPSCTR-1)) || (dkblock(bp) > p_lblkcnt))
		SETBPERR(bp, ENXIO);

	if ((bp->b_flags & B_ERROR) || (dkblock(bp) == p_lblkcnt)) {
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}

	d_cnt = bp->b_bcount >> SCTRSHFT;
	if ((dkblock(bp) + d_cnt) > p_lblkcnt) {
		bp->b_resid = ((dkblock(bp) + d_cnt) - p_lblkcnt) << SCTRSHFT;
		bp->b_bcount -= bp->b_resid;
	}

	SET_BP_SEC(bp, (p_lblksrt + dkblock(bp)));
	if (dadk_strategy(DKTP_DATA, bp) != DDI_SUCCESS) {
		bp->b_resid += bp->b_bcount;
		biodone(bp);
	}
	return (0);
}

static int
cmdk_create_obj(dev_info_t *dip, struct cmdk *dkp)
{
	struct scsi_device *devp;
	opaque_t	queobjp = NULL;
	opaque_t	flcobjp = NULL;
	char		que_keyvalp[64];
	int		que_keylen;
	char		flc_keyvalp[64];
	int		flc_keylen;

	que_keylen = sizeof (que_keyvalp);
	if (ddi_prop_op(DDI_DEV_T_NONE, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_CANSLEEP, "queue", que_keyvalp, &que_keylen) !=
	    DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "cmdk_create_obj: queue property undefined");
		return (DDI_FAILURE);
	}
	que_keyvalp[que_keylen] = (char)0;

	if (strcmp(que_keyvalp, "qfifo") == 0) {
		queobjp = (opaque_t)qfifo_create();
	} else if (strcmp(que_keyvalp, "qsort") == 0) {
		queobjp = (opaque_t)qsort_create();
	} else {
		return (DDI_FAILURE);
	}

	flc_keylen = sizeof (flc_keyvalp);
	if (ddi_prop_op(DDI_DEV_T_NONE, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_CANSLEEP, "flow_control", flc_keyvalp, &flc_keylen) !=
	    DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "cmdk_create_obj: flow-control property undefined");
		return (DDI_FAILURE);
	}

	flc_keyvalp[flc_keylen] = (char)0;

	if (strcmp(flc_keyvalp, "dsngl") == 0) {
		flcobjp = (opaque_t)dsngl_create();
	} else if (strcmp(flc_keyvalp, "dmult") == 0) {
		flcobjp = (opaque_t)dmult_create();
	} else {
		return (DDI_FAILURE);
	}

	dkp->dk_tgobjp = (opaque_t)dadk_create();

	devp = ddi_get_driver_private(dip);

	(void) dadk_init(DKTP_DATA, devp, flcobjp, queobjp, &cmdk_bbh_obj,
	    NULL);

	return (DDI_SUCCESS);
}

static void
cmdk_destroy_obj(dev_info_t *dip, struct cmdk *dkp)
{
	char		que_keyvalp[64];
	int		que_keylen;
	char		flc_keyvalp[64];
	int		flc_keylen;

	(void) dadk_free(DKTP_DATA);
	DKTP_DATA = NULL;

	que_keylen = sizeof (que_keyvalp);
	if (ddi_prop_op(DDI_DEV_T_NONE, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_CANSLEEP, "queue", que_keyvalp, &que_keylen) !=
	    DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "cmdk_destroy_obj: queue property undefined");
		return;
	}
	que_keyvalp[que_keylen] = (char)0;

	flc_keylen = sizeof (flc_keyvalp);
	if (ddi_prop_op(DDI_DEV_T_NONE, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_CANSLEEP, "flow_control", flc_keyvalp, &flc_keylen) !=
	    DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		    "cmdk_destroy_obj: flow-control property undefined");
		return;
	}
	flc_keyvalp[flc_keylen] = (char)0;
}

/*ARGSUSED*/
static int
cmdk_create_lbobj(dev_info_t *dip, struct cmdk *dkp)
{
	dkp->dk_lbobjp = (opaque_t)snlb_create();
	if (!(dkp->dk_lbobjp)) {
		cmn_err(CE_WARN,
		    "cmdk_create_lbobj: ERROR creating disklabel %s",
		    "snlb");
		return (DDI_FAILURE);
	}

	DKLB_INIT(dkp->dk_lbobjp, dkp->dk_tgobjp, NULL);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static void
cmdk_destroy_lbobj(dev_info_t *dip, struct cmdk *dkp, int unload)
{
	if (!dkp->dk_lbobjp)
		return;

	DKLB_FREE(dkp->dk_lbobjp);
	dkp->dk_lbobjp = 0;
}


/*
 * cmdk_part_info()
 *
 *	Make the device valid if possible. The dk_pinfo_lock is only
 *	held for very short periods so that there's very little
 *	contention with the cmdk_devstatus() function which can
 *	be called from interrupt context.
 *
 *	This function implements a simple state machine which looks
 *	like this:
 *
 *
 *	   +---------------------------------+
 *         |				     |
 *	   +--> invalid --> busy --> valid --+
 *			     ^|
 *			     |v
 *			    busy2
 *
 *	This function can change the state from invalid to busy, or from
 *	busy2 to busy, or from busy to valid.
 *
 *	The cmdk_devstatus() function can change the state from valid
 *	to invalid or from busy to busy2.
 *
 */


static int
cmdk_part_info(struct cmdk *dkp, int force, daddr_t *startp, long *countp,
		int part)
{
	/*
	 * The dk_pinfo_state variable (and by implication the partition
	 * info) is always protected by the dk_pinfo_lock mutex.
	 */
	mutex_enter(&dkp->dk_pinfo_lock);

	for (;;) {
		switch (dkp->dk_pinfo_state) {

		case CMDK_PARTINFO_VALID:
			/* it's already valid */
			if (!force) {
				goto done;
			}
		/*FALLTHROUGH*/

		case CMDK_PARTINFO_INVALID:
			/*
			 * It's invalid or we're being forced to reread
			 */
			goto reopen;

		case CMDK_PARTINFO_BUSY:
		case CMDK_PARTINFO_BUSY2:
			/*
			 * Some other thread has already called
			 * cmdk_reopen(), wait for it to complete and then
			 * start over from the top.
			 */
			cv_wait(&dkp->dk_pinfo_cv, &dkp->dk_pinfo_lock);
		}
	}

reopen:
	/*
	 * ASSERT: only one thread at a time can possibly reach this point
	 * and invoke cmdk_reopen()
	 */
	dkp->dk_pinfo_state = CMDK_PARTINFO_BUSY;

	for (;;)  {
		int	rc;

		/*
		 * drop the mutex while in cmdk_reopen() because
		 * it may take a long time to return
		 */
		mutex_exit(&dkp->dk_pinfo_lock);
		rc = cmdk_reopen(dkp);
		mutex_enter(&dkp->dk_pinfo_lock);

		if (rc == FALSE) {
			/*
			 * bailout, probably due to no device,
			 * or invalid label
			 */
			goto error;
		}

		switch (dkp->dk_pinfo_state) {

		case CMDK_PARTINFO_BUSY:
			dkp->dk_pinfo_state = CMDK_PARTINFO_VALID;
			cv_broadcast(&dkp->dk_pinfo_cv);
			goto done;

		case CMDK_PARTINFO_BUSY2:
			/*
			 * device status changed by cmdk_devstatus(),
			 * redo the reopen
			 */
			dkp->dk_pinfo_state = CMDK_PARTINFO_BUSY;
			break;
		}
	}


done:
	/*
	 * finished cmdk_reopen() without any device status change
	 */
	DKLB_PARTINFO(dkp->dk_lbobjp, startp, countp, part);
	mutex_exit(&dkp->dk_pinfo_lock);
	return (TRUE);

error:
	dkp->dk_pinfo_state = CMDK_PARTINFO_INVALID;
	cv_broadcast(&dkp->dk_pinfo_cv);
	mutex_exit(&dkp->dk_pinfo_lock);
	return (FALSE);
}

#ifdef	NOT_USED
static void
cmdk_devstatus(struct cmdk *dkp)
{
	mutex_enter(&dkp->dk_pinfo_lock);
	switch (dkp->dk_pinfo_state) {

	case CMDK_PARTINFO_VALID:
		dkp->dk_pinfo_state = CMDK_PARTINFO_INVALID;
		break;

	case CMDK_PARTINFO_INVALID:
		break;

	case CMDK_PARTINFO_BUSY:
		dkp->dk_pinfo_state = CMDK_PARTINFO_BUSY2;
		break;

	case CMDK_PARTINFO_BUSY2:
		break;
	}
	mutex_exit(&dkp->dk_pinfo_lock);
}
#endif	/* NOT_USED */


/*
 * initialize the state for cmdk_part_info()
 */
static void
cmdk_part_info_init(struct cmdk *dkp)
{
	mutex_init(&dkp->dk_pinfo_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&dkp->dk_pinfo_cv, NULL, CV_DRIVER, NULL);
	dkp->dk_pinfo_state = CMDK_PARTINFO_INVALID;
}

static void
cmdk_part_info_fini(struct cmdk *dkp)
{
	mutex_destroy(&dkp->dk_pinfo_lock);
	cv_destroy(&dkp->dk_pinfo_cv);
}
