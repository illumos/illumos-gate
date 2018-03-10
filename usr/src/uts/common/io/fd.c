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
 * Floppy Disk driver
 */

/*
 * Set CMOS feature:
 *	CMOS_CONF_MEM:	CMOS memory contains configuration info
 */
#define	CMOS_CONF_MEM

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/autoconf.h>
#include <sys/vtoc.h>
#include <sys/dkio.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kstat.h>
#include <sys/kmem.h>
#include <sys/ddidmareq.h>
#include <sys/fdio.h>
#include <sys/fdc.h>
#include <sys/fd_debug.h>
#include <sys/fdmedia.h>
#include <sys/debug.h>
#include <sys/modctl.h>

/*
 * Local Function Prototypes
 */
static int fd_unit_is_open(struct fdisk *);
static int fdgetlabel(struct fcu_obj *, int);
static void fdstart(struct fcu_obj *);
static int fd_build_label_vtoc(struct fcu_obj *, struct fdisk *,
    struct vtoc *, struct dk_label *);
static void fd_build_user_vtoc(struct fcu_obj *, struct fdisk *,
    struct vtoc *);
static int fd_rawioctl(struct fcu_obj *, int, caddr_t, int);
static void fd_media_watch(void *);

static int fd_open(dev_t *, int, int, cred_t *);
static int fd_close(dev_t, int, int, cred_t *);
static int fd_strategy(struct buf *);
static int fd_read(dev_t, struct uio *, cred_t *);
static int fd_write(dev_t, struct uio *, cred_t *);
static int fd_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int fd_prop_op(dev_t, dev_info_t *, ddi_prop_op_t, int, char *,
    caddr_t, int *);
static int fd_check_media(dev_t dev, enum dkio_state state);
static int fd_get_media_info(struct fcu_obj *fjp, caddr_t buf, int flag);

static struct cb_ops fd_cb_ops = {
	fd_open,		/* open */
	fd_close,		/* close */
	fd_strategy,		/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	fd_read,		/* read */
	fd_write,		/* write */
	fd_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	fd_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static int fd_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int fd_probe(dev_info_t *);
static int fd_attach(dev_info_t *, ddi_attach_cmd_t);
static int fd_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops fd_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	fd_getinfo,		/* getinfo */
	nulldev,		/* identify */
	fd_probe,		/* probe */
	fd_attach,		/* attach */
	fd_detach,		/* detach */
	nodev,			/* reset */
	&fd_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};


/*
 * static data
 */
static void *fd_state_head;		/* opaque handle top of state structs */
static int fd_check_media_time = 5000000;	/* 5 second state check */

/*
 * error handling
 *
 * for debugging,
 *		set fderrlevel to 1
 *		set fderrmask  to 224  or 644
 */
#ifdef DEBUG
static uint_t fderrmask = FDEM_ALL;
#endif
static int fderrlevel = 5;

#define	KIOSP	KSTAT_IO_PTR(fdp->d_iostat)

static struct driver_minor_data {
	char	*name;
	int	minor;
	int	type;
} fd_minor [] = {
	{ "a", 0, S_IFBLK},
	{ "b", 1, S_IFBLK},
	{ "c", 2, S_IFBLK},
	{ "a,raw", 0, S_IFCHR},
	{ "b,raw", 1, S_IFCHR},
	{ "c,raw", 2, S_IFCHR},
	{0}
};

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"Floppy Disk driver",	/* Name of the module. */
	&fd_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};


int
_init(void)
{
	int retval;

	if ((retval = ddi_soft_state_init(&fd_state_head,
	    sizeof (struct fdisk) + sizeof (struct fd_drive) +
	    sizeof (struct fd_char) + sizeof (struct fdattr), 0)) != 0)
		return (retval);

	if ((retval = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&fd_state_head);
	return (retval);
}

int
_fini(void)
{
	int retval;

	if ((retval = mod_remove(&modlinkage)) != 0)
		return (retval);
	ddi_soft_state_fini(&fd_state_head);
	return (retval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static int
fd_getdrive(dev_t dev, struct fcu_obj **fjpp, struct fdisk **fdpp)
{
	if (fdpp) {
		*fdpp = ddi_get_soft_state(fd_state_head, DRIVE(dev));
		if (*fdpp && fjpp) {
			*fjpp = (*fdpp)->d_obj;
			if (*fjpp)
				return ((*fjpp)->fj_unit);
		}
	}
	return (-1);
}

/*ARGSUSED*/
static int
fd_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	dev_t dev = (dev_t)arg;
	struct fcu_obj *fjp = NULL;
	struct fdisk *fdp = NULL;
	int rval;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		(void) fd_getdrive(dev, &fjp, &fdp);
		/*
		 * Ignoring return value because success is checked by
		 * verifying fjp and fdp and returned unit value is not used.
		 */
		if (fjp && fdp) {
			*result = fjp->fj_dip;
			rval = DDI_SUCCESS;
		} else
			rval = DDI_FAILURE;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)DRIVE(dev);
		rval = DDI_SUCCESS;
		break;
	default:
		rval = DDI_FAILURE;
	}
	return (rval);
}

#ifdef CMOS_CONF_MEM
#define	CMOS_ADDR	0x70
#define	CMOS_DATA	0x71
#define	CMOS_FDRV	0x10
#endif	/* CMOS_CONF_MEM */

static int
fd_probe(dev_info_t *dip)
{
#ifdef CMOS_CONF_MEM
	int cmos;
	int drive_type;
#endif	/* CMOS_CONF_MEM */
	int debug[2];
	int drive_size;
	int len;
	int unit_num;
	char density[8];

	len = sizeof (debug);
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS, "debug", (caddr_t)debug, &len) ==
	    DDI_PROP_SUCCESS) {
		fderrlevel = debug[0];
#ifdef DEBUG
		fderrmask = (uint_t)debug[1];
#endif
	}
	len = sizeof (unit_num);
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_DONTPASS, "unit", (caddr_t)&unit_num, &len) !=
	    DDI_PROP_SUCCESS) {
		FDERRPRINT(FDEP_L3, FDEM_ATTA,
		    (CE_WARN, "fd_probe failed: dip %p", (void *)dip));
		return (DDI_PROBE_FAILURE);
	}

#ifdef CMOS_CONF_MEM
	/* get the cmos memory values quick and dirty */
	outb(CMOS_ADDR, CMOS_FDRV);
	cmos = drive_type = (int)inb(CMOS_DATA);
#endif	/* CMOS_CONF_MEM */

	switch (unit_num) {
#ifdef CMOS_CONF_MEM
	case 0:
		drive_type = drive_type >> 4;
		/* FALLTHROUGH */
	case 1:
		if (cmos && (drive_type & 0x0F)) {
			break;
		}
		/*
		 * Some enhanced floppy-disk controller adaptor cards
		 * require NO drives defined in the CMOS configuration
		 * memory.
		 * So fall through
		 */
#endif	/* CMOS_CONF_MEM */
	default:		/* need to check conf file */
		len = sizeof (density);
		if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
		    DDI_PROP_DONTPASS, "density", (caddr_t)&density, &len) !=
		    DDI_PROP_SUCCESS) {
			FDERRPRINT(FDEP_L3, FDEM_ATTA,
			    (CE_WARN,
			    "fd_probe failed density: dip %p unit %d",
			    (void *)dip, unit_num));
			return (DDI_PROBE_FAILURE);
		}
		len = sizeof (drive_size);
		if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
		    DDI_PROP_DONTPASS, "size", (caddr_t)&drive_size, &len) !=
		    DDI_PROP_SUCCESS) {
			FDERRPRINT(FDEP_L3, FDEM_ATTA,
			    (CE_WARN, "fd_probe failed size: dip %p unit %d",
			    (void *)dip, unit_num));
			return (DDI_PROBE_FAILURE);
		}
	}
	FDERRPRINT(FDEP_L3, FDEM_ATTA,
	    (CE_WARN, "fd_probe dip %p unit %d", (void *)dip, unit_num));
	return (DDI_PROBE_SUCCESS);
}


/* ARGSUSED */
static int
fd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct fcu_obj *fjp;
	struct fdisk *fdp;
	struct driver_minor_data *dmdp;
	int mode_3D;
	int drive_num, drive_size, drive_type;
#ifdef CMOS_CONF_MEM
	int cmos;
#endif	/* CMOS_CONF_MEM */
	int len, sig_minor;
	int unit_num;
	char density[8];
	char name[MAXNAMELEN];

	switch (cmd) {
	case DDI_ATTACH:
		len = sizeof (unit_num);
		if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
		    DDI_PROP_DONTPASS, "unit", (caddr_t)&unit_num, &len) !=
		    DDI_PROP_SUCCESS) {
			FDERRPRINT(FDEP_L3, FDEM_ATTA,
			    (CE_WARN, "fd_attach failed: dip %p", (void *)dip));
			return (DDI_FAILURE);
		}

#ifdef CMOS_CONF_MEM
		outb(CMOS_ADDR, CMOS_FDRV);
		cmos = drive_type = (int)inb(CMOS_DATA);
#endif	/* CMOS_CONF_MEM */

		switch (unit_num) {
#ifdef CMOS_CONF_MEM
		case 0:
			drive_type = drive_type >> 4;
			/* FALLTHROUGH */
		case 1:
			drive_type = drive_type & 0x0F;
			if (cmos)
				break;
			/*
			 * Some enhanced floppy-disk controller adaptor cards
			 * require NO drives defined in the CMOS configuration
			 * memory.
			 * So fall through
			 */
#endif	/* CMOS_CONF_MEM */
		default:		/* need to check .conf file */
			drive_type = 0;
			len = sizeof (density);
			if (ddi_prop_op(DDI_DEV_T_ANY, dip,
			    PROP_LEN_AND_VAL_BUF, DDI_PROP_DONTPASS, "density",
			    (caddr_t)&density, &len) != DDI_PROP_SUCCESS)
				density[0] = '\0';
			len = sizeof (drive_size);
			if (ddi_prop_op(DDI_DEV_T_ANY, dip,
			    PROP_LEN_AND_VAL_BUF, DDI_PROP_DONTPASS, "size",
			    (caddr_t)&drive_size, &len) != DDI_PROP_SUCCESS)
				drive_size = 0;
			if (strcmp(density, "DSDD") == 0) {
				if (drive_size == 5)
					drive_type = 1;
				else if (drive_size == 3)
					drive_type = 3;
			} else if (strcmp(density, "DSHD") == 0) {
				if (drive_size == 5)
					drive_type = 2;
				else if (drive_size == 3)
					drive_type = 4;
			} else if (strcmp(density, "DSED") == 0 &&
			    drive_size == 3) {
				drive_type = 6;
			}
			break;
		}
		if (drive_type == 0) {
			FDERRPRINT(FDEP_L3, FDEM_ATTA,
			    (CE_WARN, "fd_attach failed type: dip %p unit %d",
			    (void *)dip, unit_num));
			return (DDI_FAILURE);
		}

		drive_num = ddi_get_instance(dip);
		if (ddi_soft_state_zalloc(fd_state_head, drive_num) != 0)
			return (DDI_FAILURE);
		fdp = ddi_get_soft_state(fd_state_head, drive_num);
		fjp = fdp->d_obj = ddi_get_driver_private(dip);

		mutex_init(&fjp->fj_lock, NULL, MUTEX_DRIVER, *fjp->fj_iblock);
		sema_init(&fdp->d_ocsem, 1, NULL, SEMA_DRIVER, NULL);

		fjp->fj_drive = (struct fd_drive *)(fdp + 1);
		fjp->fj_chars = (struct fd_char *)(fjp->fj_drive + 1);
		fjp->fj_attr = (struct fdattr *)(fjp->fj_chars + 1);

		/*
		 * set default floppy drive characteristics & geometry
		 */
		switch (drive_type) {	/* assume doubled sided */
		case 2:			/* 5.25 high density */
			*fjp->fj_drive = dfd_525HD;
			fdp->d_media = 1<<FMT_5H | 1<<FMT_5D9 | 1<<FMT_5D8 |
			    1<<FMT_5D4 | 1<<FMT_5D16;
			fdp->d_deffdtype = fdp->d_curfdtype = FMT_5H;
			break;
		case 4:			/* 3.5 high density */
			*fjp->fj_drive = dfd_350HD;
			fdp->d_media = 1<<FMT_3H | 1<<FMT_3I | 1<<FMT_3D;
			len = sizeof (mode_3D);
			if (ddi_prop_op(DDI_DEV_T_ANY, dip,
			    PROP_LEN_AND_VAL_BUF, DDI_PROP_DONTPASS, "mode_3D",
			    (caddr_t)&mode_3D, &len) != DDI_PROP_SUCCESS)
				mode_3D = 0;
			if (mode_3D && (fjp->fj_fdc->c_flags & FCFLG_3DMODE))
				/*
				 * 3D mode should be enabled only if a dual-
				 * speed 3.5" high-density drive and a
				 * supported floppy controller are installed.
				 */
				fdp->d_media |= 1 << FMT_3M;
			fdp->d_deffdtype = fdp->d_curfdtype = FMT_3H;
			break;
		case 1:			/* 5.25 double density */
			*fjp->fj_drive = dfd_525DD;
			fdp->d_media = 1<<FMT_5D9 | 1<<FMT_5D8 | 1<<FMT_5D4 |
			    1<<FMT_5D16;
			fdp->d_deffdtype = fdp->d_curfdtype = FMT_5D9;
			break;
		case 3:			/* 3.5 double density */
			*fjp->fj_drive = dfd_350HD;
			fdp->d_media = 1<<FMT_3D;
			fdp->d_deffdtype = fdp->d_curfdtype = FMT_3D;
			break;
		case 5:			/* 3.5 extended density */
		case 6:
		case 7:
			*fjp->fj_drive = dfd_350ED;
			fdp->d_media = 1<<FMT_3E | 1<<FMT_3H | 1<<FMT_3I |
			    1<<FMT_3D;
			fdp->d_deffdtype = fdp->d_curfdtype = FMT_3E;
			break;
		case 0:			/* no drive defined */
		default:
			goto no_attach;
		}
		*fjp->fj_chars = *defchar[fdp->d_deffdtype];
		*fjp->fj_attr = fdtypes[fdp->d_deffdtype];
		bcopy(fdparts[fdp->d_deffdtype], fdp->d_part,
		    sizeof (struct partition) * NDKMAP);
		fjp->fj_rotspd = fdtypes[fdp->d_deffdtype].fda_rotatespd;

		sig_minor = drive_num << 3;
		for (dmdp = fd_minor; dmdp->name != NULL; dmdp++) {
			if (ddi_create_minor_node(dip, dmdp->name, dmdp->type,
			    sig_minor | dmdp->minor, DDI_NT_FD, NULL)
			    == DDI_FAILURE) {
				ddi_remove_minor_node(dip, NULL);
				goto no_attach;
			}
		}

		FDERRPRINT(FDEP_L3, FDEM_ATTA,
		    (CE_WARN, "fd_attach: dip %p unit %d",
		    (void *)dip, unit_num));
		(void) sprintf(name, "fd%d", drive_num);
		fdp->d_iostat = kstat_create("fd", drive_num, name, "disk",
		    KSTAT_TYPE_IO, 1, KSTAT_FLAG_PERSISTENT);
		if (fdp->d_iostat) {
			fdp->d_iostat->ks_lock = &fjp->fj_lock;
			kstat_install(fdp->d_iostat);
		}

		fjp->fj_data = (caddr_t)fdp;
		fjp->fj_flags |= FUNIT_DRVATCH;

		/*
		 * Add a zero-length attribute to tell the world we support
		 * kernel ioctls (for layered drivers)
		 */
		(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
		    DDI_KERNEL_IOCTL, NULL, 0);

		/*
		 * We want to get suspend/resume events, so that we can
		 * refuse to suspend when pcfs is mounted.
		 */
		(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "pm-hardware-state", "needs-suspend-resume");

		/*
		 * Ignoring return value because, for passed arguments, only
		 * DDI_SUCCESS is returned.
		 */
		ddi_report_dev(dip);
		return (DDI_SUCCESS);

	case DDI_RESUME:
		/* nothing for us to do */
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
no_attach:
	fjp->fj_drive = NULL;
	fjp->fj_chars = NULL;
	fjp->fj_attr = NULL;
	mutex_destroy(&fjp->fj_lock);
	sema_destroy(&fdp->d_ocsem);
	ddi_soft_state_free(fd_state_head, drive_num);
	FDERRPRINT(FDEP_L3, FDEM_ATTA,
	    (CE_WARN, "fd_attach failed: dip %p unit %d",
	    (void *)dip, unit_num));
	return (DDI_FAILURE);
}


/* ARGSUSED */
static int
fd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct fcu_obj *fjp;
	struct fdisk *fdp;
	int drive_num;
	int rval = DDI_SUCCESS;

	FDERRPRINT(FDEP_L3, FDEM_ATTA, (CE_WARN, "fd_detach dip %p",
	    (void *)dip));

	drive_num = ddi_get_instance(dip);
	if (!(fdp = ddi_get_soft_state(fd_state_head, drive_num)))
		return (rval);

	switch (cmd) {
	case DDI_DETACH:
		if (fd_unit_is_open(fdp)) {
			rval = DDI_FAILURE;
			break;
		}
		kstat_delete(fdp->d_iostat);
		fdp->d_iostat = NULL;
		fjp = (struct fcu_obj *)fdp->d_obj;
		fjp->fj_flags &= ~FUNIT_DRVATCH;
		fjp->fj_data = NULL;
		fjp->fj_drive = NULL;
		fjp->fj_chars = NULL;
		fjp->fj_attr = NULL;
		ddi_prop_remove_all(dip);
		mutex_destroy(&fjp->fj_lock);
		sema_destroy(&fdp->d_ocsem);
		ddi_soft_state_free(fd_state_head, drive_num);
		break;

	case DDI_SUSPEND:
		/*
		 * Bad, bad, bad things will happen if someone
		 * *changes* the disk in the drive while it is mounted
		 * and the system is suspended.  We have no way to
		 * detect that.  (Undetected filesystem corruption.
		 * Its akin to changing the boot disk while the system
		 * is suspended.  Don't do it!)
		 *
		 * So we refuse to suspend if there is a mounted filesystem.
		 * (We guess this by looking for a block open.  Character
		 * opens are fine.)  This limits some of the usability of
		 * suspend/resume, but it certainly avoids this
		 * potential filesystem corruption from pilot error.
		 * Given the decreasing popularity of floppy media, we
		 * don't see this as much of a limitation.
		 */
		if (fdp->d_regopen[OTYP_BLK]) {
			cmn_err(CE_NOTE,
			    "Unable to suspend while floppy is in use.");
			rval = DDI_FAILURE;
		}
		break;

	default:
		rval = DDI_FAILURE;
		break;
	}
	return (rval);
}


static int
fd_part_is_open(struct fdisk *fdp, int part)
{
	int i;

	for (i = 0; i < (OTYPCNT - 1); i++)
		if (fdp->d_regopen[i] & (1 << part))
			return (1);
	return (0);
}

static int
fd_unit_is_open(struct fdisk *fdp)
{
	int i;

	for (i = 0; i < NDKMAP; i++)
		if (fdp->d_lyropen[i])
			return (1);
	for (i = 0; i < (OTYPCNT - 1); i++)
		if (fdp->d_regopen[i])
			return (1);
	return (0);
}

/*ARGSUSED*/
static int
fd_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	struct fcu_obj *fjp = NULL;
	struct fdisk *fdp = NULL;
	struct partition *pp;
	dev_t dev;
	int part, unit;
	int part_is_open;
	int rval;
	uint_t pbit;

	dev = *devp;
	unit = fd_getdrive(dev, &fjp, &fdp);
	if (!fjp || !fdp)
		return (ENXIO);
	part = PARTITION(dev);
	pbit = 1 << part;
	pp = &fdp->d_part[part];

	/*
	 * Serialize opens/closes
	 */
	sema_p(&fdp->d_ocsem);
	FDERRPRINT(FDEP_L1, FDEM_OPEN,
	    (CE_CONT, "fd_open: fd%d part %d flag %x otype %x\n", DRIVE(dev),
	    part, flag, otyp));

	/*
	 * Check for previous exclusive open, or trying to exclusive open
	 * An "exclusive open" on any partition is not guaranteed to
	 * protect against opens on another partition that overlaps it.
	 */
	if (otyp == OTYP_LYR) {
		part_is_open = (fdp->d_lyropen[part] != 0);
	} else {
		part_is_open = fd_part_is_open(fdp, part);
	}
	if ((fdp->d_exclmask & pbit) || ((flag & FEXCL) && part_is_open)) {
		FDERRPRINT(FDEP_L0, FDEM_OPEN, (CE_CONT,
		    "fd_open: exclparts %lx openparts %lx lyrcnt %lx pbit %x\n",
		    fdp->d_exclmask, fdp->d_regopen[otyp], fdp->d_lyropen[part],
		    pbit));
		sema_v(&fdp->d_ocsem);
		return (EBUSY);
	}

	/*
	 * Ensure that drive is recalibrated on first open of new diskette.
	 */
	fjp->fj_ops->fco_select(fjp, unit, 1);
	if (fjp->fj_ops->fco_getchng(fjp, unit) != 0) {
		if (fjp->fj_ops->fco_rcseek(fjp, unit, -1, 0)) {
			FDERRPRINT(FDEP_L2, FDEM_OPEN,
			    (CE_NOTE, "fd_open fd%d: not ready", DRIVE(dev)));
			fjp->fj_ops->fco_select(fjp, unit, 0);
			sema_v(&fdp->d_ocsem);
			return (ENXIO);
		}
		fjp->fj_flags &= ~(FUNIT_LABELOK | FUNIT_UNLABELED);
	}
	if (flag & (FNDELAY | FNONBLOCK)) {
		/* don't attempt access, just return successfully */
		fjp->fj_ops->fco_select(fjp, unit, 0);
		goto out;
	}

	/*
	 * auto-sense the density/format of the diskette
	 */
	rval = fdgetlabel(fjp, unit);
	fjp->fj_ops->fco_select(fjp, unit, 0);
	if (rval) {
		/* didn't find label (couldn't read anything) */
		FDERRPRINT(FDEP_L2, FDEM_OPEN,
		    (CE_NOTE, "fd%d: drive not ready", DRIVE(dev)));
		sema_v(&fdp->d_ocsem);
		return (EIO);
	}
	/* check partition */
	if (pp->p_size == 0) {
		sema_v(&fdp->d_ocsem);
		return (ENXIO);
	}
	/*
	 * if opening for writing, check write protect on diskette
	 */
	if ((flag & FWRITE) && (fdp->d_obj->fj_flags & FUNIT_WPROT)) {
		sema_v(&fdp->d_ocsem);
		return (EROFS);
	}

out:
	/*
	 * mark open as having succeeded
	 */
	if (flag & FEXCL)
		fdp->d_exclmask |= pbit;
	if (otyp == OTYP_LYR)
		fdp->d_lyropen[part]++;
	else
		fdp->d_regopen[otyp] |= 1 << part;

	sema_v(&fdp->d_ocsem);
	return (0);
}

/*
 * fdgetlabel - read the SunOS label off the diskette
 *	if it can read a valid label it does so, else it will use a
 *	default.  If it can`t read the diskette - that is an error.
 *
 * RETURNS: 0 for ok - meaning that it could at least read the device,
 *	!0 for error XXX TBD NYD error codes
 */
static int
fdgetlabel(struct fcu_obj *fjp, int unit)
{
	struct dk_label *label;
	struct fdisk *fdp;
	char *newlabel;
	short *sp;
	short count;
	short xsum;
	int tries, try_this;
	uint_t nexttype;
	int rval;
	short oldlvl;
	int i;

	FDERRPRINT(FDEP_L0, FDEM_GETL,
	    (CE_CONT, "fdgetlabel fd unit %d\n", unit));
	fdp = (struct fdisk *)fjp->fj_data;
	fjp->fj_flags &= ~(FUNIT_UNLABELED);

	/*
	 * get some space to play with the label
	 */
	label = kmem_zalloc(sizeof (struct dk_label), KM_SLEEP);
	FDERRPRINT(FDEP_L0, FDEM_GETL, (CE_CONT,
	    "fdgetlabel fd unit %d kmem_zalloc: ptr = %p, size = %lx\n",
	    unit, (void *)label, (size_t)sizeof (struct dk_label)));

	/*
	 * read block 0 (0/0/1) to find the label
	 * (disk is potentially not present or unformatted)
	 */
	/* noerrprint since this is a private cmd */
	oldlvl = fderrlevel;
	fderrlevel = FDEP_LMAX;
	/*
	 * try different characteristics (ie densities)
	 *
	 * if fdp->d_curfdtype is -1 then the current characteristics
	 * were set by ioctl and need to try it as well as everything
	 * in the table
	 */
	nexttype = fdp->d_deffdtype;
	try_this = 1;		/* always try the current characteristics */

	for (tries = nfdtypes; tries; tries--) {
		if (try_this) {
			fjp->fj_flags &= ~FUNIT_CHAROK;

			/* try reading last sector of cyl 1, head 0 */
			if (!(rval = fjp->fj_ops->fco_rw(fjp, unit,
			    FDREAD, 1, 0, fjp->fj_chars->fdc_secptrack,
			    (caddr_t)label,
			    sizeof (struct dk_label))) &&
			    /* and last sector plus 1 of cylinder 1 */
			    fjp->fj_ops->fco_rw(fjp, unit, FDREAD, 1,
			    0, fjp->fj_chars->fdc_secptrack + 1,
			    (caddr_t)label,
			    sizeof (struct dk_label)) &&
			    /* and label sector on cylinder 0 */
			    !(rval = fjp->fj_ops->fco_rw(fjp, unit,
			    FDREAD, 0, 0, 1, (caddr_t)label,
			    sizeof (struct dk_label))))
				break;
			if (rval == ENXIO)
				break;
		}
		/*
		 * try the next entry in the characteristics tbl
		 */
		fdp->d_curfdtype = (signed char)nexttype;
		nexttype = (nexttype + 1) % nfdtypes;
		if ((1 << fdp->d_curfdtype) & fdp->d_media) {
			*fjp->fj_chars = *defchar[fdp->d_curfdtype];
			*fjp->fj_attr = fdtypes[fdp->d_curfdtype];
			bcopy(fdparts[fdp->d_curfdtype], fdp->d_part,
			    sizeof (struct partition) * NDKMAP);
			/*
			 * check for a double_density diskette
			 * in a high_density 5.25" drive
			 */
			if (fjp->fj_chars->fdc_transfer_rate == 250 &&
			    fjp->fj_rotspd > fjp->fj_attr->fda_rotatespd) {
				/*
				 * yes - adjust transfer rate since we don't
				 * know if we have a 5.25" dual-speed drive
				 */
				fjp->fj_attr->fda_rotatespd = 360;
				fjp->fj_chars->fdc_transfer_rate = 300;
				fjp->fj_chars->fdc_medium = 5;
			}
			if ((2 * fjp->fj_chars->fdc_ncyl) ==
			    defchar[fdp->d_deffdtype]->fdc_ncyl) {
				/* yes - adjust steps per cylinder */
				fjp->fj_chars->fdc_steps = 2;
			} else
				fjp->fj_chars->fdc_steps = 1;
			try_this = 1;
		} else
			try_this = 0;
	}
	fderrlevel = oldlvl;	/* print errors again */

	if (rval) {
		fdp->d_curfdtype = fdp->d_deffdtype;
		goto out;			/* couldn't read anything */
	}

	FDERRPRINT(FDEP_L0, FDEM_GETL,
	    (CE_CONT,
	    "fdgetlabel fd unit=%d ncyl=%d nsct=%d step=%d rpm=%d intlv=%d\n",
	    unit, fjp->fj_chars->fdc_ncyl, fjp->fj_chars->fdc_secptrack,
	    fjp->fj_chars->fdc_steps, fjp->fj_attr->fda_rotatespd,
	    fjp->fj_attr->fda_intrlv));

	/*
	 * _something_ was read  -  look for unixtype label
	 */
	if (label->dkl_magic != DKL_MAGIC ||
	    label->dkl_vtoc.v_sanity != VTOC_SANE) {
		/* not a label - no magic number */
		goto nolabel;	/* no errors, but no label */
	}

	count = sizeof (struct dk_label) / sizeof (short);
	sp = (short *)label;
	xsum = 0;
	while (count--)
		xsum ^= *sp++;	/* should add up to 0 */
	if (xsum) {
		/* not a label - checksum didn't compute */
		goto nolabel;	/* no errors, but no label */
	}

	/*
	 * the SunOS label overrides current diskette characteristics
	 */
	fjp->fj_chars->fdc_ncyl = label->dkl_pcyl;
	fjp->fj_chars->fdc_nhead = label->dkl_nhead;
	fjp->fj_chars->fdc_secptrack = (label->dkl_nsect * DEV_BSIZE) /
	    fjp->fj_chars->fdc_sec_size;
	if (defchar[fdp->d_deffdtype]->fdc_ncyl == 2 * fjp->fj_chars->fdc_ncyl)
		fjp->fj_chars->fdc_steps = 2;
	else
		fjp->fj_chars->fdc_steps = 1;

	fjp->fj_attr->fda_rotatespd = label->dkl_rpm;
	fjp->fj_attr->fda_intrlv = label->dkl_intrlv;

	fdp->d_vtoc_version = label->dkl_vtoc.v_version;
	bcopy(label->dkl_vtoc.v_volume, fdp->d_vtoc_volume, LEN_DKL_VVOL);
	bcopy(label->dkl_vtoc.v_asciilabel,
	    fdp->d_vtoc_asciilabel, LEN_DKL_ASCII);
	/*
	 * logical partitions
	 */
	for (i = 0; i < NDKMAP; i++) {
		fdp->d_part[i].p_tag = label->dkl_vtoc.v_part[i].p_tag;
		fdp->d_part[i].p_flag = label->dkl_vtoc.v_part[i].p_flag;
		fdp->d_part[i].p_start = label->dkl_vtoc.v_part[i].p_start;
		fdp->d_part[i].p_size = label->dkl_vtoc.v_part[i].p_size;

		fdp->d_vtoc_timestamp[i] = label->dkl_vtoc.timestamp[i];
	}

	fjp->fj_flags |= FUNIT_LABELOK;
	goto out;

nolabel:
	/*
	 * if not found, fill in label info from default (mark default used)
	 */
	if (fdp->d_media & (1<<FMT_3D))
		newlabel = deflabel_35;
	else /* if (fdp->d_media & (1<<FMT_5D9)) */
		newlabel = deflabel_525;
	bzero(fdp->d_vtoc_volume, LEN_DKL_VVOL);
	(void) sprintf(fdp->d_vtoc_asciilabel, newlabel,
	    fjp->fj_chars->fdc_ncyl, fjp->fj_chars->fdc_nhead,
	    fjp->fj_chars->fdc_secptrack);
	fjp->fj_flags |= FUNIT_UNLABELED;

out:
	kmem_free(label, sizeof (struct dk_label));
	return (rval);
}


/*ARGSUSED*/
static int
fd_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	struct fcu_obj *fjp = NULL;
	struct fdisk *fdp = NULL;
	int part, part_is_closed;

#ifdef DEBUG
	int unit;
#define	DEBUG_ASSIGN	unit=
#else
#define	DEBUG_ASSIGN	(void)
#endif

	DEBUG_ASSIGN fd_getdrive(dev, &fjp, &fdp);
	/*
	 * Ignoring return in non DEBUG mode because success is checked by
	 * verifying fjp and fdp and returned unit value is not used.
	 */
	if (!fjp || !fdp)
		return (ENXIO);
	part = PARTITION(dev);

	sema_p(&fdp->d_ocsem);
	FDERRPRINT(FDEP_L1, FDEM_CLOS,
	    (CE_CONT, "fd_close: fd unit %d part %d otype %x\n",
	    unit, part, otyp));

	if (otyp == OTYP_LYR) {
		if (fdp->d_lyropen[part])
			fdp->d_lyropen[part]--;
		part_is_closed = (fdp->d_lyropen[part] == 0);
	} else {
		fdp->d_regopen[otyp] &= ~(1<<part);
		part_is_closed = 1;
	}
	if (part_is_closed) {
		if (part == 2 && fdp->d_exclmask&(1<<part))
			fdp->d_exclmask = 0;
		else
			fdp->d_exclmask &= ~(1<<part);
		FDERRPRINT(FDEP_L0, FDEM_CLOS,
		    (CE_CONT,
		    "fd_close: exclparts %lx openparts %lx lyrcnt %lx\n",
		    fdp->d_exclmask, fdp->d_regopen[otyp],
		    fdp->d_lyropen[part]));

		if (fd_unit_is_open(fdp) == 0)
			fdp->d_obj->fj_flags &= ~FUNIT_CHANGED;
	}
	sema_v(&fdp->d_ocsem);
	return (0);
}

/* ARGSUSED */
static int
fd_read(dev_t dev, struct uio *uio, cred_t *cred_p)
{
	return (physio(fd_strategy, NULL, dev, B_READ, minphys, uio));
}

/* ARGSUSED */
static int
fd_write(dev_t dev, struct uio *uio, cred_t *cred_p)
{
	return (physio(fd_strategy, NULL, dev, B_WRITE, minphys, uio));
}

/*
 * fd_strategy
 *	checks operation, hangs buf struct off fdcntlr, calls fdstart
 *	if not already busy.  Note that if we call start, then the operation
 *	will already be done on return (start sleeps).
 */
static int
fd_strategy(struct buf *bp)
{
	struct fcu_obj *fjp;
	struct fdisk *fdp;
	struct partition *pp;

	FDERRPRINT(FDEP_L1, FDEM_STRA,
	    (CE_CONT, "fd_strategy: bp = 0x%p, dev = 0x%lx\n",
	    (void *)bp, bp->b_edev));

	(void) fd_getdrive(bp->b_edev, &fjp, &fdp);

	/*
	 * Ignoring return because device exist.
	 * Returned unit value is not used.
	 */
	pp = &fdp->d_part[PARTITION(bp->b_edev)];

	if (fjp->fj_chars->fdc_sec_size > NBPSCTR && (bp->b_blkno & 1))  {
		FDERRPRINT(FDEP_L3, FDEM_STRA,
		    (CE_WARN, "fd%d: block %ld is not start of sector!",
		    DRIVE(bp->b_edev), (long)bp->b_blkno));
		bp->b_error = EINVAL;
		goto bad;
	}

	if ((bp->b_blkno > pp->p_size)) {
		FDERRPRINT(FDEP_L3, FDEM_STRA,
		    (CE_WARN, "fd%d: block %ld is past the end! (nblk=%ld)",
		    DRIVE(bp->b_edev), (long)bp->b_blkno, pp->p_size));
		bp->b_error = ENOSPC;
		goto bad;
	}

	/* if at end of file, skip out now */
	if (bp->b_blkno == pp->p_size) {
		if ((bp->b_flags & B_READ) == 0) {
			/* a write needs to get an error! */
			bp->b_error = ENOSPC;
			goto bad;
		}
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}

	/* if operation not a multiple of sector size, is error! */
	if (bp->b_bcount % fjp->fj_chars->fdc_sec_size)  {
		FDERRPRINT(FDEP_L3, FDEM_STRA,
		    (CE_WARN, "fd%d: count %ld must be a multiple of %d",
		    DRIVE(bp->b_edev), bp->b_bcount,
		    fjp->fj_chars->fdc_sec_size));
		bp->b_error = EINVAL;
		goto bad;
	}

	/*
	 * Put the buf request in the drive's queue, FIFO.
	 */
	bp->av_forw = 0;
	mutex_enter(&fjp->fj_lock);
	if (fdp->d_iostat)
		kstat_waitq_enter(KIOSP);
	if (fdp->d_actf)
		fdp->d_actl->av_forw = bp;
	else
		fdp->d_actf = bp;
	fdp->d_actl = bp;
	if (!(fjp->fj_flags & FUNIT_BUSY)) {
		fdstart(fjp);
	}
	mutex_exit(&fjp->fj_lock);
	return (0);

bad:
	bp->b_resid = bp->b_bcount;
	bp->b_flags |= B_ERROR;
	biodone(bp);
	return (0);
}

/*
 * fdstart
 *	called from fd_strategy() or from fdXXXX() to setup and
 *	start operations of read or write only (using buf structs).
 *	Because the chip doesn't handle crossing cylinder boundaries on
 *	the fly, this takes care of those boundary conditions.  Note that
 *	it sleeps until the operation is done *within fdstart* - so that
 *	when fdstart returns, the operation is already done.
 */
static void
fdstart(struct fcu_obj *fjp)
{
	struct buf *bp;
	struct fdisk *fdp = (struct fdisk *)fjp->fj_data;
	struct fd_char *chp;
	struct partition *pp;
	uint_t ptend;
	uint_t bincyl;		/* (the number of the desired) block in cyl. */
	uint_t blk, len, tlen;
	uint_t secpcyl;		/* number of sectors per cylinder */
	int cyl, head, sect;
	int sctrshft, unit;
	caddr_t	addr;

	ASSERT(MUTEX_HELD(&fjp->fj_lock));
	fjp->fj_flags |= FUNIT_BUSY;

	while ((bp = fdp->d_actf) != NULL) {
		fdp->d_actf = bp->av_forw;
		fdp->d_current = bp;
		if (fdp->d_iostat) {
			kstat_waitq_to_runq(KIOSP);
		}
		mutex_exit(&fjp->fj_lock);

		FDERRPRINT(FDEP_L0, FDEM_STRT,
		    (CE_CONT, "fdstart: bp=0x%p blkno=0x%lx bcount=0x%lx\n",
		    (void *)bp, (long)bp->b_blkno, bp->b_bcount));
		bp->b_flags &= ~B_ERROR;
		bp->b_error = 0;
		bp->b_resid = bp->b_bcount;	/* init resid */

		ASSERT(DRIVE(bp->b_edev) == ddi_get_instance(fjp->fj_dip));
		unit = fjp->fj_unit;
		fjp->fj_ops->fco_select(fjp, unit, 1);

		bp_mapin(bp);			/* map in buffers */

		pp = &fdp->d_part[PARTITION(bp->b_edev)];
		/* starting blk adjusted for the partition */
		blk = bp->b_blkno + pp->p_start;
		ptend = pp->p_start + pp->p_size;   /* end of the partition */

		chp = fjp->fj_chars;
		secpcyl = chp->fdc_nhead * chp->fdc_secptrack;
		switch (chp->fdc_sec_size) {
		/* convert logical block numbers to sector numbers */
		case 1024:
			sctrshft = SCTRSHFT + 1;
			blk >>= 1;
			ptend >>= 1;
			break;
		default:
		case NBPSCTR:
			sctrshft = SCTRSHFT;
			break;
		case 256:
			sctrshft = SCTRSHFT - 1;
			blk <<= 1;
			ptend <<= 1;
			break;
		}

		/*
		 * If off the end, limit to actual amount that
		 * can be transferred.
		 */
		if ((blk + (bp->b_bcount >> sctrshft)) > ptend)
			/* to end of partition */
			len = (ptend - blk) << sctrshft;
		else
			len = bp->b_bcount;
		addr = bp->b_un.b_addr;		/* data buffer address */

		/*
		 * now we have the real start blk, addr and len for xfer op
		 */
		while (len != 0) {
			/* start cyl of req */
			cyl = blk / secpcyl;
			bincyl = blk % secpcyl;
			/* start head of req */
			head = bincyl / chp->fdc_secptrack;
			/* start sector of req */
			sect = (bincyl % chp->fdc_secptrack) + 1;
			/*
			 * If the desired block and length will go beyond the
			 * cylinder end, then limit it to the cylinder end.
			 */
			if (bp->b_flags & B_READ) {
				if (len > ((secpcyl - bincyl) << sctrshft))
					tlen = (secpcyl - bincyl) << sctrshft;
				else
					tlen = len;
			} else {
				if (len >
				    ((chp->fdc_secptrack - sect + 1) <<
				    sctrshft))
					tlen =
					    (chp->fdc_secptrack - sect + 1) <<
					    sctrshft;
				else
					tlen = len;
			}

			FDERRPRINT(FDEP_L0, FDEM_STRT, (CE_CONT,
			    "  blk 0x%x addr 0x%p len 0x%x "
			    "cyl %d head %d sec %d\n  resid 0x%lx, tlen %d\n",
			    blk, (void *)addr, len, cyl, head, sect,
			    bp->b_resid, tlen));

			/*
			 * (try to) do the operation - failure returns an errno
			 */
			bp->b_error = fjp->fj_ops->fco_rw(fjp, unit,
			    bp->b_flags & B_READ, cyl, head, sect, addr, tlen);
			if (bp->b_error != 0) {
				FDERRPRINT(FDEP_L3, FDEM_STRT, (CE_WARN,
				    "fdstart: bad exec of bp: 0x%p, err=%d",
				    (void *)bp, bp->b_error));
				bp->b_flags |= B_ERROR;
				break;
			}
			blk += tlen >> sctrshft;
			len -= tlen;
			addr += tlen;
			bp->b_resid -= tlen;
		}
		FDERRPRINT(FDEP_L0, FDEM_STRT,
		    (CE_CONT, "fdstart done: b_resid %lu, b_count %lu\n",
		    bp->b_resid, bp->b_bcount));
		if (fdp->d_iostat) {
			if (bp->b_flags & B_READ) {
				KIOSP->reads++;
				KIOSP->nread += (bp->b_bcount - bp->b_resid);
			} else {
				KIOSP->writes++;
				KIOSP->nwritten += (bp->b_bcount - bp->b_resid);
			}
			kstat_runq_exit(KIOSP);
		}
		bp_mapout(bp);
		biodone(bp);

		fjp->fj_ops->fco_select(fjp, unit, 0);
		mutex_enter(&fjp->fj_lock);
		fdp->d_current = 0;
	}
	fjp->fj_flags ^= FUNIT_BUSY;
}

/* ARGSUSED */
static int
fd_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cred_p,
	int *rval_p)
{
	union {
		struct dk_cinfo dki;
		struct dk_geom dkg;
		struct dk_allmap dka;
		struct fd_char fdchar;
		struct fd_drive drvchar;
		int	temp;
	} cpy;
	struct vtoc vtoc;
	struct fcu_obj *fjp = NULL;
	struct fdisk *fdp = NULL;
	struct dk_map *dmp;
	struct dk_label *label;
	int nblks, part, unit;
	int rval = 0;
	enum dkio_state state;

	unit = fd_getdrive(dev, &fjp, &fdp);
	if (!fjp || !fdp)
		return (ENXIO);

	FDERRPRINT(FDEP_L1, FDEM_IOCT,
	    (CE_CONT, "fd_ioctl fd unit %d: cmd %x, arg %lx\n",
	    unit, cmd, arg));

	switch (cmd) {
	case DKIOCINFO:
		fjp->fj_ops->fco_dkinfo(fjp, &cpy.dki);
		cpy.dki.dki_cnum = FDCTLR(fjp->fj_unit);
		cpy.dki.dki_unit = FDUNIT(fjp->fj_unit);
		cpy.dki.dki_partition = PARTITION(dev);
		if (ddi_copyout(&cpy.dki, (void *)arg, sizeof (cpy.dki), flag))
			rval = EFAULT;
		break;

	case DKIOCG_PHYGEOM:
	case DKIOCG_VIRTGEOM:
		cpy.dkg.dkg_nsect = fjp->fj_chars->fdc_secptrack;
		goto get_geom;
	case DKIOCGGEOM:
		if (fjp->fj_flags & FUNIT_LABELOK)
			cpy.dkg.dkg_nsect = (fjp->fj_chars->fdc_secptrack *
			    fjp->fj_chars->fdc_sec_size) / DEV_BSIZE;
		else
			cpy.dkg.dkg_nsect = fjp->fj_chars->fdc_secptrack;
get_geom:
		cpy.dkg.dkg_pcyl = fjp->fj_chars->fdc_ncyl;
		cpy.dkg.dkg_ncyl = fjp->fj_chars->fdc_ncyl;
		cpy.dkg.dkg_nhead = fjp->fj_chars->fdc_nhead;
		cpy.dkg.dkg_intrlv = fjp->fj_attr->fda_intrlv;
		cpy.dkg.dkg_rpm = fjp->fj_attr->fda_rotatespd;
		cpy.dkg.dkg_read_reinstruct =
		    (int)(cpy.dkg.dkg_nsect * cpy.dkg.dkg_rpm * 4) / 60000;
		cpy.dkg.dkg_write_reinstruct = cpy.dkg.dkg_read_reinstruct;
		if (ddi_copyout(&cpy.dkg, (void *)arg, sizeof (cpy.dkg), flag))
			rval = EFAULT;
		break;

	case DKIOCSGEOM:
		if (ddi_copyin((void *)arg, &cpy.dkg,
		    sizeof (struct dk_geom), flag)) {
			rval = EFAULT;
			break;
		}
		mutex_enter(&fjp->fj_lock);
		fjp->fj_chars->fdc_ncyl = cpy.dkg.dkg_ncyl;
		fjp->fj_chars->fdc_nhead = cpy.dkg.dkg_nhead;
		fjp->fj_chars->fdc_secptrack = cpy.dkg.dkg_nsect;
		fjp->fj_attr->fda_intrlv = cpy.dkg.dkg_intrlv;
		fjp->fj_attr->fda_rotatespd = cpy.dkg.dkg_rpm;
		fdp->d_curfdtype = -1;
		mutex_exit(&fjp->fj_lock);
		break;

	/*
	 * return the map of all logical partitions
	 */
	case DKIOCGAPART:
		/*
		 * Note the conversion from starting sector number
		 * to starting cylinder number.
		 * Return error if division results in a remainder.
		 */
		nblks = fjp->fj_chars->fdc_nhead * fjp->fj_chars->fdc_secptrack;

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			struct dk_allmap32 dka32;

			for (part = 0; part < NDKMAP; part++) {
				if ((fdp->d_part[part].p_start % nblks) != 0)
					return (EINVAL);
				dka32.dka_map[part].dkl_cylno =
				    fdp->d_part[part].p_start / nblks;
				dka32.dka_map[part].dkl_nblk =
				    fdp->d_part[part].p_size;
			}

			if (ddi_copyout(&dka32, (void *)arg,
			    sizeof (struct dk_allmap32), flag))
				rval = EFAULT;

			break;
		}
		case DDI_MODEL_NONE:

#endif /* _MULTI_DATAMODEL */

			dmp = (struct dk_map *)&cpy.dka;
			for (part = 0; part < NDKMAP; part++) {
				if ((fdp->d_part[part].p_start % nblks) != 0)
					return (EINVAL);
				dmp->dkl_cylno =
				    fdp->d_part[part].p_start / nblks;
				dmp->dkl_nblk = fdp->d_part[part].p_size;
				dmp++;
			}

			if (ddi_copyout(&cpy.dka, (void *)arg,
			    sizeof (struct dk_allmap), flag))
				rval = EFAULT;
#ifdef _MULTI_DATAMODEL
			break;

		}
#endif /* _MULTI_DATAMODEL */

		break;

	/*
	 * Set the map of all logical partitions
	 */
	case DKIOCSAPART:

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			struct dk_allmap32 dka32;

			if (ddi_copyin((void *)arg, &dka32,
			    sizeof (dka32), flag)) {
				rval = EFAULT;
				break;
			}
			for (part = 0; part < NDKMAP; part++) {
				cpy.dka.dka_map[part].dkl_cylno =
				    dka32.dka_map[part].dkl_cylno;
				cpy.dka.dka_map[part].dkl_nblk =
				    dka32.dka_map[part].dkl_nblk;
			}
			break;
		}
		case DDI_MODEL_NONE:

#endif /* _MULTI_DATAMODEL */
		if (ddi_copyin((void *)arg, &cpy.dka, sizeof (cpy.dka), flag))
			rval = EFAULT;
#ifdef _MULTI_DATAMODEL

			break;
		}
#endif /* _MULTI_DATAMODEL */

		if (rval != 0)
			break;

		dmp = (struct dk_map *)&cpy.dka;
		nblks = fjp->fj_chars->fdc_nhead *
		    fjp->fj_chars->fdc_secptrack;
		mutex_enter(&fjp->fj_lock);
		/*
		 * Note the conversion from starting cylinder number
		 * to starting sector number.
		 */
		for (part = 0; part < NDKMAP; part++) {
			fdp->d_part[part].p_start = dmp->dkl_cylno *
			    nblks;
			fdp->d_part[part].p_size = dmp->dkl_nblk;
			dmp++;
		}
		mutex_exit(&fjp->fj_lock);

		break;

	case DKIOCGVTOC:
		mutex_enter(&fjp->fj_lock);

		/*
		 * Exit if the diskette has no label.
		 * Also, get the label to make sure the correct one is
		 * being used since the diskette may have changed
		 */
		fjp->fj_ops->fco_select(fjp, unit, 1);
		rval = fdgetlabel(fjp, unit);
		fjp->fj_ops->fco_select(fjp, unit, 0);
		if (rval) {
			mutex_exit(&fjp->fj_lock);
			rval = EINVAL;
			break;
		}

		fd_build_user_vtoc(fjp, fdp, &vtoc);
		mutex_exit(&fjp->fj_lock);

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			struct vtoc32	vtoc32;

			vtoctovtoc32(vtoc, vtoc32);

			if (ddi_copyout(&vtoc32, (void *)arg,
			    sizeof (vtoc32), flag))
				rval = EFAULT;

			break;
		}
		case DDI_MODEL_NONE:

#endif /* _MULTI_DATAMODEL */
			if (ddi_copyout(&vtoc, (void *)arg,
			    sizeof (vtoc), flag))
				rval = EFAULT;
#ifdef _MULTI_DATAMODEL
			break;
		}
#endif /* _MULTI_DATAMODEL */

		break;

	case DKIOCSVTOC:

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			struct vtoc32	vtoc32;

			if (ddi_copyin((void *)arg, &vtoc32,
			    sizeof (vtoc32), flag)) {
				rval = EFAULT;
				break;
			}

			vtoc32tovtoc(vtoc32, vtoc);

			break;
		}
		case DDI_MODEL_NONE:

#endif /* _MULTI_DATAMODEL */
			if (ddi_copyin((void *)arg, &vtoc, sizeof (vtoc), flag))
				rval = EFAULT;
#ifdef _MULTI_DATAMODEL
			break;
		}
#endif /* _MULTI_DATAMODEL */

		if (rval != 0)
			break;


		label = kmem_zalloc(sizeof (struct dk_label), KM_SLEEP);

		mutex_enter(&fjp->fj_lock);

		if ((rval = fd_build_label_vtoc(fjp, fdp, &vtoc, label)) == 0) {
			fjp->fj_ops->fco_select(fjp, unit, 1);
			rval = fjp->fj_ops->fco_rw(fjp, unit, FDWRITE,
			    0, 0, 1, (caddr_t)label, sizeof (struct dk_label));
			fjp->fj_ops->fco_select(fjp, unit, 0);
		}
		mutex_exit(&fjp->fj_lock);
		kmem_free(label, sizeof (struct dk_label));
		break;

	case DKIOCSTATE:
		FDERRPRINT(FDEP_L1, FDEM_IOCT,
		    (CE_CONT, "fd_ioctl fd unit %d: DKIOCSTATE\n", unit));

		if (ddi_copyin((void *)arg, &state, sizeof (int), flag)) {
			rval = EFAULT;
			break;
		}

		rval = fd_check_media(dev, state);

		if (ddi_copyout(&fdp->d_media_state, (void *)arg,
		    sizeof (int), flag))
			rval = EFAULT;
		break;

	case FDIOGCHAR:
		if (ddi_copyout(fjp->fj_chars, (void *)arg,
		    sizeof (struct fd_char), flag))
			rval = EFAULT;
		break;

	case FDIOSCHAR:
		if (ddi_copyin((void *)arg, &cpy.fdchar,
		    sizeof (struct fd_char), flag)) {
			rval = EFAULT;
			break;
		}
		switch (cpy.fdchar.fdc_transfer_rate) {
		case 417:
			if ((fdp->d_media & (1 << FMT_3M)) == 0) {
				cmn_err(CE_CONT,
				    "fdioschar:Medium density not supported\n");
				rval = EINVAL;
				break;
			}
			mutex_enter(&fjp->fj_lock);
			fjp->fj_attr->fda_rotatespd = 360;
			mutex_exit(&fjp->fj_lock);
			/* cpy.fdchar.fdc_transfer_rate = 500; */
			/* FALLTHROUGH */
		case 1000:
		case 500:
		case 300:
		case 250:
			mutex_enter(&fjp->fj_lock);
			*(fjp->fj_chars) = cpy.fdchar;
			fdp->d_curfdtype = -1;
			fjp->fj_flags &= ~FUNIT_CHAROK;
			mutex_exit(&fjp->fj_lock);

			break;

		default:
			FDERRPRINT(FDEP_L4, FDEM_IOCT,
			    (CE_WARN, "fd_ioctl fd unit %d: FDIOSCHAR odd "
			    "xfer rate %dkbs",
			    unit, cpy.fdchar.fdc_transfer_rate));
			rval = EINVAL;
			break;
		}
		break;

	/*
	 * set all characteristics and geometry to the defaults
	 */
	case FDDEFGEOCHAR:
		mutex_enter(&fjp->fj_lock);
		fdp->d_curfdtype = fdp->d_deffdtype;
		*fjp->fj_chars = *defchar[fdp->d_curfdtype];
		*fjp->fj_attr = fdtypes[fdp->d_curfdtype];
		bcopy(fdparts[fdp->d_curfdtype],
		    fdp->d_part, sizeof (struct partition) * NDKMAP);
		fjp->fj_flags &= ~FUNIT_CHAROK;
		mutex_exit(&fjp->fj_lock);
		break;

	case FDEJECT:  /* eject disk */
	case DKIOCEJECT:
		fjp->fj_flags &= ~(FUNIT_LABELOK | FUNIT_UNLABELED);
		rval = ENOSYS;
		break;

	case FDGETCHANGE: /* disk changed */
		if (ddi_copyin((void *)arg, &cpy.temp, sizeof (int), flag)) {
			rval = EFAULT;
			break;
		}
		mutex_enter(&fjp->fj_lock);
		fjp->fj_ops->fco_select(fjp, unit, 1);

		if (fjp->fj_flags & FUNIT_CHANGED)
			cpy.temp |= FDGC_HISTORY;
		else
			cpy.temp &= ~FDGC_HISTORY;
		fjp->fj_flags &= ~FUNIT_CHANGED;

		if (fjp->fj_ops->fco_getchng(fjp, unit)) {
			cpy.temp |= FDGC_DETECTED;
			fjp->fj_ops->fco_resetchng(fjp, unit);
			/*
			 * check diskette again only if it was removed
			 */
			if (fjp->fj_ops->fco_getchng(fjp, unit)) {
				/*
				 * no diskette is present
				 */
				cpy.temp |= FDGC_CURRENT;
				if (fjp->fj_flags & FUNIT_CHGDET)
					/*
					 * again no diskette; not a new change
					 */
					cpy.temp ^= FDGC_DETECTED;
				else
					fjp->fj_flags |= FUNIT_CHGDET;
			} else {
				/*
				 * a new diskette is present
				 */
				cpy.temp &= ~FDGC_CURRENT;
				fjp->fj_flags &= ~FUNIT_CHGDET;
			}
		} else {
			cpy.temp &= ~(FDGC_DETECTED | FDGC_CURRENT);
			fjp->fj_flags &= ~FUNIT_CHGDET;
		}
		/*
		 * also get state of write protection
		 */
		if (fjp->fj_flags & FUNIT_WPROT) {
			cpy.temp |= FDGC_CURWPROT;
		} else {
			cpy.temp &= ~FDGC_CURWPROT;
		}
		fjp->fj_ops->fco_select(fjp, unit, 0);
		mutex_exit(&fjp->fj_lock);

		if (ddi_copyout(&cpy.temp, (void *)arg, sizeof (int), flag))
			rval = EFAULT;
		break;

	case FDGETDRIVECHAR:
		if (ddi_copyout(fjp->fj_drive, (void *)arg,
		    sizeof (struct fd_drive), flag))
			rval = EFAULT;
		break;

	case FDSETDRIVECHAR:
		if (ddi_copyin((void *)arg, &cpy.drvchar,
		    sizeof (struct fd_drive), flag)) {
			rval = EFAULT;
			break;
		}
		mutex_enter(&fjp->fj_lock);
		*(fjp->fj_drive) = cpy.drvchar;
		fdp->d_curfdtype = -1;
		fjp->fj_flags &= ~FUNIT_CHAROK;
		mutex_exit(&fjp->fj_lock);
		break;

	case DKIOCREMOVABLE: {
		int	i = 1;

		/* no brainer: floppies are always removable */
		if (ddi_copyout(&i, (void *)arg, sizeof (int), flag)) {
			rval = EFAULT;
		}
		break;
	}

	case DKIOCGMEDIAINFO:
		rval = fd_get_media_info(fjp, (caddr_t)arg, flag);
		break;

	case FDIOCMD:
	{
		struct fd_cmd fc;
		int cyl, head, spc, spt;

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			struct fd_cmd32 fc32;

			if (ddi_copyin((void *)arg, &fc32,
			    sizeof (fc32), flag)) {
				rval = EFAULT;
				break;
			}

			fc.fdc_cmd = fc32.fdc_cmd;
			fc.fdc_flags = fc32.fdc_flags;
			fc.fdc_blkno = fc32.fdc_blkno;
			fc.fdc_secnt = fc32.fdc_secnt;
			fc.fdc_bufaddr = (caddr_t)(uintptr_t)fc32.fdc_bufaddr;
			fc.fdc_buflen = fc32.fdc_buflen;

			break;
		}
		case DDI_MODEL_NONE:

#endif /* _MULTI_DATAMODEL */

			if (ddi_copyin((void *)arg, &fc, sizeof (fc), flag)) {
				rval = EFAULT;
				break;
			}
#ifdef _MULTI_DATAMODEL
			break;
		}
#endif /* _MULTI_DATAMODEL */

		if (rval != 0)
			break;

	if (fc.fdc_cmd == FDCMD_READ || fc.fdc_cmd == FDCMD_WRITE) {
			auto struct iovec aiov;
			auto struct uio auio;
			struct uio *uio = &auio;

			spc = (fc.fdc_cmd == FDCMD_READ)? B_READ: B_WRITE;

			bzero(&auio, sizeof (struct uio));
			bzero(&aiov, sizeof (struct iovec));
			aiov.iov_base = fc.fdc_bufaddr;
			aiov.iov_len = (uint_t)fc.fdc_secnt *
			    fjp->fj_chars->fdc_sec_size;
			uio->uio_iov = &aiov;

			uio->uio_iovcnt = 1;
			uio->uio_resid = aiov.iov_len;
			uio->uio_segflg = UIO_USERSPACE;

			rval = physio(fd_strategy, (struct buf *)0, dev,
			    spc, minphys, uio);
			break;
		} else if (fc.fdc_cmd == FDCMD_FORMAT_TRACK) {
			spt = fjp->fj_chars->fdc_secptrack;	/* sec/trk */
			spc = fjp->fj_chars->fdc_nhead * spt;	/* sec/cyl */
			cyl = fc.fdc_blkno / spc;
			head = (fc.fdc_blkno % spc) / spt;
			if ((cyl | head) == 0)
				fjp->fj_flags &=
				    ~(FUNIT_LABELOK | FUNIT_UNLABELED);

			FDERRPRINT(FDEP_L0, FDEM_FORM,
			    (CE_CONT, "fd_format cyl %d, hd %d\n", cyl, head));
			fjp->fj_ops->fco_select(fjp, unit, 1);
			rval = fjp->fj_ops->fco_format(fjp, unit, cyl, head,
			    (int)fc.fdc_flags);
			fjp->fj_ops->fco_select(fjp, unit, 0);

			break;
		}
		FDERRPRINT(FDEP_L4, FDEM_IOCT,
		    (CE_WARN, "fd_ioctl fd unit %d: FDIOCSCMD not yet complete",
		    unit));
		rval = EINVAL;
		break;
	}

	case FDRAW:
		rval = fd_rawioctl(fjp, unit, (caddr_t)arg, flag);
		break;

	default:
		FDERRPRINT(FDEP_L4, FDEM_IOCT,
		    (CE_WARN, "fd_ioctl fd unit %d: invalid ioctl 0x%x",
		    unit, cmd));
		rval = ENOTTY;
		break;
	}
	return (rval);
}

static void
fd_build_user_vtoc(struct fcu_obj *fjp, struct fdisk *fdp, struct vtoc *vtocp)
{
	struct partition *vpart;
	int	i;
	int	xblk;

	/*
	 * Return vtoc structure fields in the provided VTOC area, addressed
	 * by *vtocp.
	 *
	 */
	bzero(vtocp, sizeof (struct vtoc));

	bcopy(fdp->d_vtoc_bootinfo,
	    vtocp->v_bootinfo, sizeof (vtocp->v_bootinfo));

	vtocp->v_sanity = VTOC_SANE;
	vtocp->v_version = fdp->d_vtoc_version;
	bcopy(fdp->d_vtoc_volume, vtocp->v_volume, LEN_DKL_VVOL);
	if (fjp->fj_flags & FUNIT_LABELOK) {
		vtocp->v_sectorsz = DEV_BSIZE;
		xblk = 1;
	} else {
		vtocp->v_sectorsz = fjp->fj_chars->fdc_sec_size;
		xblk = vtocp->v_sectorsz / DEV_BSIZE;
	}
	vtocp->v_nparts = 3;	/* <= NDKMAP;	*/

	/*
	 * Copy partitioning information.
	 */
	bcopy(fdp->d_part, vtocp->v_part, sizeof (struct partition) * NDKMAP);
	for (i = NDKMAP, vpart = vtocp->v_part; i && (xblk > 1); i--, vpart++) {
		/* correct partition info if sector size > 512 bytes */
		vpart->p_start /= xblk;
		vpart->p_size /= xblk;
	}

	bcopy(fdp->d_vtoc_timestamp,
	    vtocp->timestamp, sizeof (fdp->d_vtoc_timestamp));
	bcopy(fdp->d_vtoc_asciilabel, vtocp->v_asciilabel, LEN_DKL_ASCII);
}


static int
fd_build_label_vtoc(struct fcu_obj *fjp, struct fdisk *fdp, struct vtoc *vtocp,
    struct dk_label *labelp)
{
	struct partition *vpart;
	int	i;
	int	nblks;
	int	ncyl;
	ushort_t sum, *sp;


	/*
	 * Sanity-check the vtoc
	 */
	if (vtocp->v_sanity != VTOC_SANE ||
	    vtocp->v_nparts > NDKMAP || vtocp->v_nparts <= 0) {
		FDERRPRINT(FDEP_L3, FDEM_IOCT,
		    (CE_WARN, "fd_build_label:  sanity check on vtoc failed"));
		return (EINVAL);
	}

	/*
	 * before copying the vtoc, the partition information in it should be
	 * checked against the information the driver already has on the
	 * diskette.
	 */

	nblks = (fjp->fj_chars->fdc_nhead * fjp->fj_chars->fdc_secptrack *
	    fjp->fj_chars->fdc_sec_size) / DEV_BSIZE;
	if (nblks == 0 || fjp->fj_chars->fdc_ncyl == 0)
		return (EFAULT);
	vpart = vtocp->v_part;

	/*
	 * Check the partition information in the vtoc.  The starting sectors
	 * must lie along cylinder boundaries. (NDKMAP entries are checked
	 * to ensure that the unused entries are set to 0 if vtoc->v_nparts
	 * is less than NDKMAP)
	 */
	for (i = NDKMAP; i; i--) {
		if ((vpart->p_start % nblks) != 0) {
			return (EINVAL);
		}
		ncyl = vpart->p_start / nblks;
		ncyl += vpart->p_size / nblks;
		if ((vpart->p_size % nblks) != 0)
			ncyl++;
		if (ncyl > (long)fjp->fj_chars->fdc_ncyl) {
			return (EINVAL);
		}
		vpart++;
	}


	bcopy(vtocp->v_bootinfo, fdp->d_vtoc_bootinfo,
	    sizeof (vtocp->v_bootinfo));
	fdp->d_vtoc_version = vtocp->v_version;
	bcopy(vtocp->v_volume, fdp->d_vtoc_volume, LEN_DKL_VVOL);

	/*
	 * Copy partitioning information.
	 */
	bcopy(vtocp->v_part, fdp->d_part, sizeof (struct partition) * NDKMAP);
	bcopy(vtocp->timestamp, fdp->d_vtoc_timestamp,
	    sizeof (fdp->d_vtoc_timestamp));
	bcopy(vtocp->v_asciilabel, fdp->d_vtoc_asciilabel, LEN_DKL_ASCII);

	/*
	 * construct the diskette label in supplied buffer
	 */

	/* Put appropriate vtoc structure fields into the disk label */
	labelp->dkl_vtoc.v_bootinfo[0] = (uint32_t)vtocp->v_bootinfo[0];
	labelp->dkl_vtoc.v_bootinfo[1] = (uint32_t)vtocp->v_bootinfo[1];
	labelp->dkl_vtoc.v_bootinfo[2] = (uint32_t)vtocp->v_bootinfo[2];

	labelp->dkl_vtoc.v_sanity = vtocp->v_sanity;
	labelp->dkl_vtoc.v_version = vtocp->v_version;

	bcopy(vtocp->v_volume, labelp->dkl_vtoc.v_volume, LEN_DKL_VVOL);

	labelp->dkl_vtoc.v_nparts = vtocp->v_nparts;

	bcopy(vtocp->v_reserved, labelp->dkl_vtoc.v_reserved,
	    sizeof (labelp->dkl_vtoc.v_reserved));

	for (i = 0; i < (int)vtocp->v_nparts; i++) {
		labelp->dkl_vtoc.v_part[i].p_tag  = vtocp->v_part[i].p_tag;
		labelp->dkl_vtoc.v_part[i].p_flag  = vtocp->v_part[i].p_flag;
		labelp->dkl_vtoc.v_part[i].p_start  = vtocp->v_part[i].p_start;
		labelp->dkl_vtoc.v_part[i].p_size  = vtocp->v_part[i].p_size;
	}

	for (i = 0; i < NDKMAP; i++) {
		labelp->dkl_vtoc.v_timestamp[i] = vtocp->timestamp[i];
	}
	bcopy(vtocp->v_asciilabel, labelp->dkl_asciilabel, LEN_DKL_ASCII);


	labelp->dkl_pcyl = fjp->fj_chars->fdc_ncyl;
	labelp->dkl_ncyl = fjp->fj_chars->fdc_ncyl;
	labelp->dkl_nhead = fjp->fj_chars->fdc_nhead;
	/*
	 * The fdc_secptrack field of the fd_char structure is the number
	 * of sectors per track where the sectors are fdc_sec_size.
	 * The dkl_nsect field of the dk_label structure is the number of
	 * DEV_BSIZE (512) byte sectors per track.
	 */
	labelp->dkl_nsect = (fjp->fj_chars->fdc_secptrack *
	    fjp->fj_chars->fdc_sec_size) / DEV_BSIZE;
	labelp->dkl_intrlv = fjp->fj_attr->fda_intrlv;
	labelp->dkl_rpm = fjp->fj_attr->fda_rotatespd;
	labelp->dkl_read_reinstruct =
	    (int)(labelp->dkl_nsect * labelp->dkl_rpm * 4) / 60000;
	labelp->dkl_write_reinstruct = labelp->dkl_read_reinstruct;

	labelp->dkl_magic = DKL_MAGIC;

	sum = 0;
	labelp->dkl_cksum = 0;
	sp = (ushort_t *)labelp;
	while (sp < &(labelp->dkl_cksum)) {
		sum ^= *sp++;
	}
	labelp->dkl_cksum = sum;

	return (0);
}

static int
fd_rawioctl(struct fcu_obj *fjp, int unit, caddr_t arg, int mode)
{
	struct fd_raw fdr;
	char *arg_result = NULL;
	int flag = B_READ;
	int rval = 0;
	caddr_t	uaddr;
	uint_t ucount;

	FDERRPRINT(FDEP_L1, FDEM_RAWI,
	    (CE_CONT, "fd_rawioctl: cmd[0]=0x%x\n", fdr.fdr_cmd[0]));

	if (fjp->fj_chars->fdc_medium != 3 && fjp->fj_chars->fdc_medium != 5) {
		cmn_err(CE_CONT, "fd_rawioctl: Medium density not supported\n");
		return (ENXIO);
	}

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(mode & FMODELS)) {
	case DDI_MODEL_ILP32:
	{
		struct fd_raw32 fdr32;

		if (ddi_copyin(arg, &fdr32, sizeof (fdr32), mode))
			return (EFAULT);

		bcopy(fdr32.fdr_cmd, fdr.fdr_cmd, sizeof (fdr.fdr_cmd));
		fdr.fdr_cnum = fdr32.fdr_cnum;
		fdr.fdr_nbytes = fdr32.fdr_nbytes;
		fdr.fdr_addr = (caddr_t)(uintptr_t)fdr32.fdr_addr;
		arg_result = ((struct fd_raw32 *)arg)->fdr_result;

		break;
	}
	case DDI_MODEL_NONE:
#endif /* ! _MULTI_DATAMODEL */

		if (ddi_copyin(arg, &fdr, sizeof (fdr), mode))
			return (EFAULT);

		arg_result = ((struct fd_raw *)arg)->fdr_result;

#ifdef _MULTI_DATAMODEL
		break;
	}
#endif /* _MULTI_DATAMODEL */



	/*
	 * copy user address & nbytes from raw_req so that we can
	 * put kernel address in req structure
	 */
	uaddr = fdr.fdr_addr;
	ucount = (uint_t)fdr.fdr_nbytes;
	unit &= 3;

	switch (fdr.fdr_cmd[0] & 0x0f) {

	case FDRAW_FORMAT:
		ucount += 16;
		fdr.fdr_addr = kmem_zalloc(ucount, KM_SLEEP);
		if (ddi_copyin(uaddr, fdr.fdr_addr,
		    (size_t)fdr.fdr_nbytes, mode)) {
			kmem_free(fdr.fdr_addr, ucount);
			return (EFAULT);
		}
		if ((*fdr.fdr_addr | fdr.fdr_addr[1]) == 0)
			fjp->fj_flags &= ~(FUNIT_LABELOK | FUNIT_UNLABELED);
		flag = B_WRITE;
		fdr.fdr_cmd[1] = (fdr.fdr_cmd[1] & ~3) | unit;
		break;

	case FDRAW_WRCMD:
	case FDRAW_WRITEDEL:
		flag = B_WRITE;
		/* FALLTHROUGH */
	case FDRAW_RDCMD:
	case FDRAW_READDEL:
	case FDRAW_READTRACK:
		if (ucount) {
			/*
			 * In SunOS 4.X, we used to as_fault things in.
			 * We really cannot do this in 5.0/SVr4. Unless
			 * someone really believes that speed is of the
			 * essence here, it is just much simpler to do
			 * this in kernel space and use copyin/copyout.
			 */
			fdr.fdr_addr = kmem_alloc((size_t)ucount, KM_SLEEP);
			if (flag == B_WRITE) {
				if (ddi_copyin(uaddr, fdr.fdr_addr, ucount,
				    mode)) {
					kmem_free(fdr.fdr_addr, ucount);
					return (EFAULT);
				}
			}
		} else
			return (EINVAL);
		fdr.fdr_cmd[1] = (fdr.fdr_cmd[1] & ~3) | unit;
		break;

	case FDRAW_READID:
	case FDRAW_REZERO:
	case FDRAW_SEEK:
	case FDRAW_SENSE_DRV:
		ucount = 0;
		fdr.fdr_cmd[1] = (fdr.fdr_cmd[1] & ~3) | unit;
		break;

	case FDRAW_SPECIFY:
		fdr.fdr_cmd[2] &= 0xfe;	/* keep NoDMA bit clear */
		/* FALLTHROUGH */
	case FDRAW_SENSE_INT:
		ucount = 0;
		break;

	default:
		return (EINVAL);
	}

	/*
	 * Note that we ignore any error returns from controller
	 * This is the way the driver has been, and it may be
	 * that the raw ioctl senders simply don't want to
	 * see any errors returned in this fashion.
	 */

	fjp->fj_ops->fco_select(fjp, unit, 1);
	rval = fjp->fj_ops->fco_rwioctl(fjp, unit, (caddr_t)&fdr);

	if (ucount && flag == B_READ && rval == 0) {
		if (ddi_copyout(fdr.fdr_addr, uaddr, ucount, mode)) {
			rval = EFAULT;
		}
	}
	if (ddi_copyout(fdr.fdr_result, arg_result, sizeof (fdr.fdr_cmd), mode))
		rval = EFAULT;

	fjp->fj_ops->fco_select(fjp, unit, 0);
	if (ucount)
		kmem_free(fdr.fdr_addr, ucount);

	return (rval);
}

/*
 * property operation routine.  return the number of blocks for the partition
 * in question or forward the request to the property facilities.
 */
static int
fd_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
	struct fcu_obj	*fjp = NULL;
	struct fdisk	*fdp = NULL;
	uint64_t	nblocks64;

	FDERRPRINT(FDEP_L1, FDEM_PROP,
	    (CE_CONT, "fd_prop_op: dip %p %s\n", (void *)dip, name));

	/*
	 * Our dynamic properties are all device specific and size oriented.
	 * Requests issued under conditions where size is valid are passed
	 * to ddi_prop_op_nblocks with the size information, otherwise the
	 * request is passed to ddi_prop_op.
	 */
	if (dev == DDI_DEV_T_ANY) {
pass:  		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));
	} else {
		/*
		 * Ignoring return value because success is checked by
		 * verifying fjp and fdp and returned unit value is not used.
		 */
		(void) fd_getdrive(dev, &fjp, &fdp);
		if (!fjp || !fdp)
			goto pass;

		/* get nblocks value */
		nblocks64 = (ulong_t)fdp->d_part[PARTITION(dev)].p_size;

		return (ddi_prop_op_nblocks(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp, nblocks64));
	}
}

static void
fd_media_watch(void *arg)
{
	struct fcu_obj *fjp;
	struct fdisk *fdp;

#ifdef DEBUG
	int	unit;
#define	DEBUG_ASSIGN	unit=
#else
#define	DEBUG_ASSIGN	(void)
#endif
	DEBUG_ASSIGN fd_getdrive((dev_t)arg, &fjp, &fdp);
	/*
	 * Ignoring return in non DEBUG mode because device exist.
	 * Returned unit value is not used.
	 */

	FDERRPRINT(FDEP_L0, FDEM_IOCT,
	    (CE_CONT, "fd_media_watch unit %d\n", unit));

	/*
	 * fd_get_media_state() cannot be called from this timeout function
	 * because the  floppy drive has to be selected first, and that could
	 * force this function to sleep (while waiting for the select
	 * semaphore).
	 * Instead, just wakeup up driver.
	 */
	mutex_enter(&fjp->fj_lock);
	cv_broadcast(&fdp->d_statecv);
	mutex_exit(&fjp->fj_lock);
}

enum dkio_state
fd_get_media_state(struct fcu_obj *fjp, int unit)
{
	enum dkio_state state;

	if (fjp->fj_ops->fco_getchng(fjp, unit)) {
		/* recheck disk only if DSKCHG "high" */
		fjp->fj_ops->fco_resetchng(fjp, unit);
		if (fjp->fj_ops->fco_getchng(fjp, unit)) {
			if (fjp->fj_flags & FUNIT_CHGDET) {
				/*
				 * again no diskette; not a new change
				 */
				state = DKIO_NONE;
			} else {
				/*
				 * a new change; diskette was ejected
				 */
				fjp->fj_flags |= FUNIT_CHGDET;
				state = DKIO_EJECTED;
			}
		} else {
			fjp->fj_flags &= ~FUNIT_CHGDET;
			state = DKIO_INSERTED;
		}
	} else {
		fjp->fj_flags &= ~FUNIT_CHGDET;
		state = DKIO_INSERTED;
	}
	FDERRPRINT(FDEP_L0, FDEM_IOCT,
	    (CE_CONT, "fd_get_media_state unit %d: state %x\n", unit, state));
	return (state);
}

static int
fd_check_media(dev_t dev, enum dkio_state state)
{
	struct fcu_obj *fjp;
	struct fdisk *fdp;
	int	unit;
	int	err;

	unit = fd_getdrive(dev, &fjp, &fdp);

	mutex_enter(&fjp->fj_lock);

	fjp->fj_ops->fco_select(fjp, unit, 1);
	fdp->d_media_state = fd_get_media_state(fjp, unit);
	fdp->d_media_timeout = drv_usectohz(fd_check_media_time);

	while (fdp->d_media_state == state) {
		/* release the controller and drive */
		fjp->fj_ops->fco_select(fjp, unit, 0);

		/* turn on timer */
		fdp->d_media_timeout_id = timeout(fd_media_watch,
		    (void *)dev, fdp->d_media_timeout);

		if (cv_wait_sig(&fdp->d_statecv, &fjp->fj_lock) == 0) {
			fdp->d_media_timeout = 0;
			mutex_exit(&fjp->fj_lock);
			return (EINTR);
		}
		fjp->fj_ops->fco_select(fjp, unit, 1);
		fdp->d_media_state = fd_get_media_state(fjp, unit);
	}

	if (fdp->d_media_state == DKIO_INSERTED) {
		err = fdgetlabel(fjp, unit);
		if (err) {
			fjp->fj_ops->fco_select(fjp, unit, 0);
			mutex_exit(&fjp->fj_lock);
			return (EIO);
		}
	}
	fjp->fj_ops->fco_select(fjp, unit, 0);
	mutex_exit(&fjp->fj_lock);
	return (0);
}

/*
 * fd_get_media_info :
 * 	Collects medium information for
 *	DKIOCGMEDIAINFO ioctl.
 */

static int
fd_get_media_info(struct fcu_obj *fjp, caddr_t buf, int flag)
{
	struct dk_minfo media_info;
	int err = 0;

	media_info.dki_media_type = DK_FLOPPY;
	media_info.dki_lbsize = fjp->fj_chars->fdc_sec_size;
	media_info.dki_capacity = fjp->fj_chars->fdc_ncyl *
	    fjp->fj_chars->fdc_secptrack * fjp->fj_chars->fdc_nhead;

	if (ddi_copyout(&media_info, buf, sizeof (struct dk_minfo), flag))
		err = EFAULT;
	return (err);
}
