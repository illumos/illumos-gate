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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

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
#include <sys/dktp/altsctr.h>
#include <sys/dktp/cmdk.h>

#include <sys/stat.h>
#include <sys/vtoc.h>
#include <sys/file.h>
#include <sys/dktp/dadkio.h>
#include <sys/aio_req.h>

#include <sys/cmlb.h>

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

void *cmdk_state;

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

/*
 * Local Function Prototypes
 */
static int cmdk_create_obj(dev_info_t *dip, struct cmdk *dkp);
static void cmdk_destroy_obj(dev_info_t *dip, struct cmdk *dkp);
static void cmdkmin(struct buf *bp);
static int cmdkrw(dev_t dev, struct uio *uio, int flag);
static int cmdkarw(dev_t dev, struct aio_req *aio, int flag);

/*
 * Bad Block Handling Functions Prototypes
 */
static void cmdk_bbh_reopen(struct cmdk *dkp);
static opaque_t cmdk_bbh_gethandle(opaque_t bbh_data, struct buf *bp);
static bbh_cookie_t cmdk_bbh_htoc(opaque_t bbh_data, opaque_t handle);
static void cmdk_bbh_freehandle(opaque_t bbh_data, opaque_t handle);
static void cmdk_bbh_close(struct cmdk *dkp);
static void cmdk_bbh_setalts_idx(struct cmdk *dkp);
static int cmdk_bbh_bsearch(struct alts_ent *buf, int cnt, daddr32_t key);

static struct bbh_objops cmdk_bbh_ops = {
	nulldev,
	nulldev,
	cmdk_bbh_gethandle,
	cmdk_bbh_htoc,
	cmdk_bbh_freehandle,
	0, 0
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

static void cmdk_setup_pm(dev_info_t *dip, struct cmdk *dkp);
static int cmdkresume(dev_info_t *dip);
static int cmdksuspend(dev_info_t *dip);
static int cmdkpower(dev_info_t *dip, int component, int level);

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
	(struct bus_ops *)0,	/* bus operations */
	cmdkpower,		/* power */
	ddi_quiesce_not_needed,	/* quiesce */
};

/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

#ifndef XPV_HVM_DRIVER
static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module. This one is a driver */
	"Common Direct Access Disk",
	&cmdk_ops,				/* driver ops 		*/
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};


#else /* XPV_HVM_DRIVER */
static struct modlmisc modlmisc = {
	&mod_miscops,		/* Type of module. This one is a misc */
	"HVM Common Direct Access Disk",
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

#endif /* XPV_HVM_DRIVER */

/* Function prototypes for cmlb callbacks */

static int cmdk_lb_rdwr(dev_info_t *dip, uchar_t cmd, void *bufaddr,
    diskaddr_t start, size_t length, void *tg_cookie);

static int cmdk_lb_getinfo(dev_info_t *dip, int cmd,  void *arg,
    void *tg_cookie);

static void cmdk_devid_setup(struct cmdk *dkp);
static int cmdk_devid_modser(struct cmdk *dkp);
static int cmdk_get_modser(struct cmdk *dkp, int ioccmd, char *buf, int len);
static int cmdk_devid_fabricate(struct cmdk *dkp);
static int cmdk_devid_read(struct cmdk *dkp);

static cmlb_tg_ops_t cmdk_lb_ops = {
	TG_DK_OPS_VERSION_1,
	cmdk_lb_rdwr,
	cmdk_lb_getinfo
};

static boolean_t
cmdk_isopen(struct cmdk *dkp, dev_t dev)
{
	int		part, otyp;
	ulong_t		partbit;

	ASSERT(MUTEX_HELD((&dkp->dk_mutex)));

	part = CMDKPART(dev);
	partbit = 1 << part;

	/* account for close */
	if (dkp->dk_open_lyr[part] != 0)
		return (B_TRUE);
	for (otyp = 0; otyp < OTYPCNT; otyp++)
		if (dkp->dk_open_reg[otyp] & partbit)
			return (B_TRUE);
	return (B_FALSE);
}

int
_init(void)
{
	int 	rval;

#ifndef XPV_HVM_DRIVER
	if (rval = ddi_soft_state_init(&cmdk_state, sizeof (struct cmdk), 7))
		return (rval);
#endif /* !XPV_HVM_DRIVER */

	mutex_init(&cmdk_attach_mutex, NULL, MUTEX_DRIVER, NULL);
	if ((rval = mod_install(&modlinkage)) != 0) {
		mutex_destroy(&cmdk_attach_mutex);
#ifndef XPV_HVM_DRIVER
		ddi_soft_state_fini(&cmdk_state);
#endif /* !XPV_HVM_DRIVER */
	}
	return (rval);
}

int
_fini(void)
{
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
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

#ifndef XPV_HVM_DRIVER
	if (ddi_get_soft_state(cmdk_state, instance))
		return (DDI_PROBE_PARTIAL);

	if (ddi_soft_state_zalloc(cmdk_state, instance) != DDI_SUCCESS)
		return (DDI_PROBE_PARTIAL);
#endif /* !XPV_HVM_DRIVER */

	if ((dkp = ddi_get_soft_state(cmdk_state, instance)) == NULL)
		return (DDI_PROBE_PARTIAL);

	mutex_init(&dkp->dk_mutex, NULL, MUTEX_DRIVER, NULL);
	rw_init(&dkp->dk_bbh_mutex, NULL, RW_DRIVER, NULL);
	dkp->dk_dip = dip;
	mutex_enter(&dkp->dk_mutex);

	dkp->dk_dev = makedevice(ddi_driver_major(dip),
	    ddi_get_instance(dip) << CMDK_UNITSHF);

	/* linkage to dadk and strategy */
	if (cmdk_create_obj(dip, dkp) != DDI_SUCCESS) {
		mutex_exit(&dkp->dk_mutex);
		mutex_destroy(&dkp->dk_mutex);
		rw_destroy(&dkp->dk_bbh_mutex);
#ifndef XPV_HVM_DRIVER
		ddi_soft_state_free(cmdk_state, instance);
#endif /* !XPV_HVM_DRIVER */
		return (DDI_PROBE_PARTIAL);
	}

	status = dadk_probe(DKTP_DATA, KM_NOSLEEP);
	if (status != DDI_PROBE_SUCCESS) {
		cmdk_destroy_obj(dip, dkp);	/* dadk/strategy linkage  */
		mutex_exit(&dkp->dk_mutex);
		mutex_destroy(&dkp->dk_mutex);
		rw_destroy(&dkp->dk_bbh_mutex);
#ifndef XPV_HVM_DRIVER
		ddi_soft_state_free(cmdk_state, instance);
#endif /* !XPV_HVM_DRIVER */
		return (status);
	}

	mutex_exit(&dkp->dk_mutex);
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
	int 		instance;
	struct		cmdk *dkp;
	char 		*node_type;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (cmdkresume(dip));
	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)))
		return (DDI_FAILURE);

	dkp->dk_pm_level = CMDK_SPINDLE_UNINIT;
	mutex_init(&dkp->dk_mutex, NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&dkp->dk_mutex);

	/* dadk_attach is an empty function that only returns SUCCESS */
	(void) dadk_attach(DKTP_DATA);

	node_type = (DKTP_EXT->tg_nodetype);

	/*
	 * this open allows cmlb to read the device
	 * and determine the label types
	 * so that cmlb can create minor nodes for device
	 */

	/* open the target disk	 */
	if (dadk_open(DKTP_DATA, 0) != DDI_SUCCESS)
		goto fail2;

#ifdef _ILP32
	{
		struct  tgdk_geom phyg;
		(void) dadk_getphygeom(DKTP_DATA, &phyg);
		if ((phyg.g_cap - 1) > DK_MAX_BLOCKS) {
			(void) dadk_close(DKTP_DATA);
			goto fail2;
		}
	}
#endif


	/* mark as having opened target */
	dkp->dk_flag |= CMDK_TGDK_OPEN;

	cmlb_alloc_handle((cmlb_handle_t *)&dkp->dk_cmlbhandle);

	if (cmlb_attach(dip,
	    &cmdk_lb_ops,
	    DTYPE_DIRECT,		/* device_type */
	    B_FALSE,			/* removable */
	    B_FALSE,			/* hot pluggable XXX */
	    node_type,
	    CMLB_CREATE_ALTSLICE_VTOC_16_DTYPE_DIRECT,	/* alter_behaviour */
	    dkp->dk_cmlbhandle,
	    0) != 0)
		goto fail1;

	/* Calling validate will create minor nodes according to disk label */
	(void) cmlb_validate(dkp->dk_cmlbhandle, 0, 0);

	/* set bbh (Bad Block Handling) */
	cmdk_bbh_reopen(dkp);

	/* setup devid string */
	cmdk_devid_setup(dkp);

	mutex_enter(&cmdk_attach_mutex);
	if (instance > cmdk_max_instance)
		cmdk_max_instance = instance;
	mutex_exit(&cmdk_attach_mutex);

	mutex_exit(&dkp->dk_mutex);

	/*
	 * Add a zero-length attribute to tell the world we support
	 * kernel ioctls (for layered drivers)
	 */
	(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0);
	ddi_report_dev(dip);

	/*
	 * Initialize power management
	 */
	mutex_init(&dkp->dk_pm_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&dkp->dk_suspend_cv,   NULL, CV_DRIVER, NULL);
	cmdk_setup_pm(dip, dkp);

	return (DDI_SUCCESS);

fail1:
	cmlb_free_handle(&dkp->dk_cmlbhandle);
	(void) dadk_close(DKTP_DATA);
fail2:
	cmdk_destroy_obj(dip, dkp);
	rw_destroy(&dkp->dk_bbh_mutex);
	mutex_exit(&dkp->dk_mutex);
	mutex_destroy(&dkp->dk_mutex);
#ifndef XPV_HVM_DRIVER
	ddi_soft_state_free(cmdk_state, instance);
#endif /* !XPV_HVM_DRIVER */
	return (DDI_FAILURE);
}


static int
cmdkdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct cmdk	*dkp;
	int 		instance;
	int		max_instance;

	switch (cmd) {
	case DDI_DETACH:
		/* return (DDI_FAILURE); */
		break;
	case DDI_SUSPEND:
		return (cmdksuspend(dip));
	default:
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

	/* check if any instance of driver is open */
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

	mutex_enter(&dkp->dk_mutex);

	/*
	 * The cmdk_part_info call at the end of cmdkattach may have
	 * caused cmdk_reopen to do a TGDK_OPEN, make sure we close on
	 * detach for case when cmdkopen/cmdkclose never occurs.
	 */
	if (dkp->dk_flag & CMDK_TGDK_OPEN) {
		dkp->dk_flag &= ~CMDK_TGDK_OPEN;
		(void) dadk_close(DKTP_DATA);
	}

	cmlb_detach(dkp->dk_cmlbhandle, 0);
	cmlb_free_handle(&dkp->dk_cmlbhandle);
	ddi_prop_remove_all(dip);

	cmdk_destroy_obj(dip, dkp);	/* dadk/strategy linkage  */

	/*
	 * free the devid structure if allocated before
	 */
	if (dkp->dk_devid) {
		ddi_devid_free(dkp->dk_devid);
		dkp->dk_devid = NULL;
	}

	mutex_exit(&dkp->dk_mutex);
	mutex_destroy(&dkp->dk_mutex);
	rw_destroy(&dkp->dk_bbh_mutex);
	mutex_destroy(&dkp->dk_pm_mutex);
	cv_destroy(&dkp->dk_suspend_cv);
#ifndef XPV_HVM_DRIVER
	ddi_soft_state_free(cmdk_state, instance);
#endif /* !XPV_HVM_DRIVER */

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

/*
 * Initialize the power management components
 */
static void
cmdk_setup_pm(dev_info_t *dip, struct cmdk *dkp)
{
	char *pm_comp[] = { "NAME=cmdk", "0=off", "1=on", NULL };

	/*
	 * Since the cmdk device does not the 'reg' property,
	 * cpr will not call its DDI_SUSPEND/DDI_RESUME entries.
	 * The following code is to tell cpr that this device
	 * DOES need to be suspended and resumed.
	 */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "pm-hardware-state", "needs-suspend-resume");

	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "pm-components", pm_comp, 3) == DDI_PROP_SUCCESS) {
		if (pm_raise_power(dip, 0, CMDK_SPINDLE_ON) == DDI_SUCCESS) {
			mutex_enter(&dkp->dk_pm_mutex);
			dkp->dk_pm_level = CMDK_SPINDLE_ON;
			dkp->dk_pm_is_enabled = 1;
			mutex_exit(&dkp->dk_pm_mutex);
		} else {
			mutex_enter(&dkp->dk_pm_mutex);
			dkp->dk_pm_level = CMDK_SPINDLE_OFF;
			dkp->dk_pm_is_enabled = 0;
			mutex_exit(&dkp->dk_pm_mutex);
		}
	} else {
		mutex_enter(&dkp->dk_pm_mutex);
		dkp->dk_pm_level = CMDK_SPINDLE_UNINIT;
		dkp->dk_pm_is_enabled = 0;
		mutex_exit(&dkp->dk_pm_mutex);
	}
}

/*
 * suspend routine, it will be run when get the command
 * DDI_SUSPEND at detach(9E) from system power management
 */
static int
cmdksuspend(dev_info_t *dip)
{
	struct cmdk	*dkp;
	int		instance;
	clock_t		count = 0;

	instance = ddi_get_instance(dip);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)))
		return (DDI_FAILURE);
	mutex_enter(&dkp->dk_mutex);
	if (dkp->dk_flag & CMDK_SUSPEND) {
		mutex_exit(&dkp->dk_mutex);
		return (DDI_SUCCESS);
	}
	dkp->dk_flag |= CMDK_SUSPEND;

	/* need to wait a while */
	while (dadk_getcmds(DKTP_DATA) != 0) {
		delay(drv_usectohz(1000000));
		if (count > 60) {
			dkp->dk_flag &= ~CMDK_SUSPEND;
			cv_broadcast(&dkp->dk_suspend_cv);
			mutex_exit(&dkp->dk_mutex);
			return (DDI_FAILURE);
		}
		count++;
	}
	mutex_exit(&dkp->dk_mutex);
	return (DDI_SUCCESS);
}

/*
 * resume routine, it will be run when get the command
 * DDI_RESUME at attach(9E) from system power management
 */
static int
cmdkresume(dev_info_t *dip)
{
	struct cmdk	*dkp;
	int		instance;

	instance = ddi_get_instance(dip);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)))
		return (DDI_FAILURE);
	mutex_enter(&dkp->dk_mutex);
	if (!(dkp->dk_flag & CMDK_SUSPEND)) {
		mutex_exit(&dkp->dk_mutex);
		return (DDI_FAILURE);
	}
	dkp->dk_pm_level = CMDK_SPINDLE_ON;
	dkp->dk_flag &= ~CMDK_SUSPEND;
	cv_broadcast(&dkp->dk_suspend_cv);
	mutex_exit(&dkp->dk_mutex);
	return (DDI_SUCCESS);

}

/*
 * power management entry point, it was used to
 * change power management component.
 * Actually, the real hard drive suspend/resume
 * was handled in ata, so this function is not
 * doing any real work other than verifying that
 * the disk is idle.
 */
static int
cmdkpower(dev_info_t *dip, int component, int level)
{
	struct cmdk	*dkp;
	int		instance;

	instance = ddi_get_instance(dip);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)) ||
	    component != 0 || level > CMDK_SPINDLE_ON ||
	    level < CMDK_SPINDLE_OFF) {
		return (DDI_FAILURE);
	}

	mutex_enter(&dkp->dk_pm_mutex);
	if (dkp->dk_pm_is_enabled && dkp->dk_pm_level == level) {
		mutex_exit(&dkp->dk_pm_mutex);
		return (DDI_SUCCESS);
	}
	mutex_exit(&dkp->dk_pm_mutex);

	if ((level == CMDK_SPINDLE_OFF) &&
	    (dadk_getcmds(DKTP_DATA) != 0)) {
		return (DDI_FAILURE);
	}

	mutex_enter(&dkp->dk_pm_mutex);
	dkp->dk_pm_level = level;
	mutex_exit(&dkp->dk_pm_mutex);
	return (DDI_SUCCESS);
}

static int
cmdk_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
	struct	cmdk	*dkp;

#ifdef CMDK_DEBUG
	if (cmdk_debug & DENT)
		PRF("cmdk_prop_op: call\n");
#endif

	dkp = ddi_get_soft_state(cmdk_state, ddi_get_instance(dip));
	if (dkp == NULL)
		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));

	return (cmlb_prop_op(dkp->dk_cmlbhandle,
	    dev, dip, prop_op, mod_flags, name, valuep, lengthp,
	    CMDKPART(dev), NULL));
}

/*
 * dump routine
 */
static int
cmdkdump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	int 		instance;
	struct	cmdk	*dkp;
	diskaddr_t	p_lblksrt;
	diskaddr_t	p_lblkcnt;
	struct	buf	local;
	struct	buf	*bp;

#ifdef CMDK_DEBUG
	if (cmdk_debug & DENT)
		PRF("cmdkdump: call\n");
#endif
	instance = CMDKUNIT(dev);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)) || (blkno < 0))
		return (ENXIO);

	if (cmlb_partinfo(
	    dkp->dk_cmlbhandle,
	    CMDKPART(dev),
	    &p_lblkcnt,
	    &p_lblksrt,
	    NULL,
	    NULL,
	    0)) {
		return (ENXIO);
	}

	if ((blkno+nblk) > p_lblkcnt)
		return (EINVAL);

	cmdk_indump = 1;	/* Tell disk targets we are panic dumpping */

	bp = &local;
	bzero(bp, sizeof (*bp));
	bp->b_flags = B_BUSY;
	bp->b_un.b_addr = addr;
	bp->b_bcount = nblk << SCTRSHFT;
	SET_BP_SEC(bp, ((ulong_t)(p_lblksrt + blkno)));

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
cmdkioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *credp, int *rvalp)
{
	int 		instance;
	struct scsi_device *devp;
	struct cmdk	*dkp;
	char 		data[NBPSCTR];

	instance = CMDKUNIT(dev);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)))
		return (ENXIO);

	mutex_enter(&dkp->dk_mutex);
	while (dkp->dk_flag & CMDK_SUSPEND) {
		cv_wait(&dkp->dk_suspend_cv, &dkp->dk_mutex);
	}
	mutex_exit(&dkp->dk_mutex);

	bzero(data, sizeof (data));

	switch (cmd) {

	case DKIOCGMEDIAINFO: {
		struct dk_minfo	media_info;
		struct  tgdk_geom phyg;

		/* dadk_getphygeom always returns success */
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
		info->dki_ctype = (DKTP_EXT->tg_ctype);
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

	case DKIOCSTATE: {
		int	state;
		int	rval;
		diskaddr_t	p_lblksrt;
		diskaddr_t	p_lblkcnt;

		if (ddi_copyin((void *)arg, &state, sizeof (int), flag))
			return (EFAULT);

		/* dadk_check_media blocks until state changes */
		if (rval = dadk_check_media(DKTP_DATA, &state))
			return (rval);

		if (state == DKIO_INSERTED) {

			if (cmlb_validate(dkp->dk_cmlbhandle, 0, 0) != 0)
				return (ENXIO);

			if (cmlb_partinfo(dkp->dk_cmlbhandle, CMDKPART(dev),
			    &p_lblkcnt, &p_lblksrt, NULL, NULL, 0))
				return (ENXIO);

			if (p_lblkcnt <= 0)
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

	case DKIOCADDBAD:
		/*
		 * This is not an update mechanism to add bad blocks
		 * to the bad block structures stored on disk.
		 *
		 * addbadsec(1M) will update the bad block data on disk
		 * and use this ioctl to force the driver to re-initialize
		 * the list of bad blocks in the driver.
		 */

		/* start BBH */
		cmdk_bbh_reopen(dkp);
		return (0);

	case DKIOCG_PHYGEOM:
	case DKIOCG_VIRTGEOM:
	case DKIOCGGEOM:
	case DKIOCSGEOM:
	case DKIOCGAPART:
	case DKIOCSAPART:
	case DKIOCGVTOC:
	case DKIOCSVTOC:
	case DKIOCPARTINFO:
	case DKIOCGEXTVTOC:
	case DKIOCSEXTVTOC:
	case DKIOCEXTPARTINFO:
	case DKIOCGMBOOT:
	case DKIOCSMBOOT:
	case DKIOCGETEFI:
	case DKIOCSETEFI:
	case DKIOCPARTITION:
	case DKIOCSETEXTPART:
	{
		int rc;

		rc = cmlb_ioctl(dkp->dk_cmlbhandle, dev, cmd, arg, flag,
		    credp, rvalp, 0);
		if (cmd == DKIOCSVTOC || cmd == DKIOCSEXTVTOC)
			cmdk_devid_setup(dkp);
		return (rc);
	}

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
	int		lastclose = 1;
	int		i;

	instance = CMDKUNIT(dev);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)) ||
	    (otyp >= OTYPCNT))
		return (ENXIO);

	mutex_enter(&dkp->dk_mutex);

	/* check if device has been opened */
	ASSERT(cmdk_isopen(dkp, dev));
	if (!(dkp->dk_flag & CMDK_OPEN)) {
		mutex_exit(&dkp->dk_mutex);
		return (ENXIO);
	}

	while (dkp->dk_flag & CMDK_SUSPEND) {
		cv_wait(&dkp->dk_suspend_cv, &dkp->dk_mutex);
	}

	part = CMDKPART(dev);
	partbit = 1 << part;

	/* account for close */
	if (otyp == OTYP_LYR) {
		ASSERT(dkp->dk_open_lyr[part] > 0);
		if (dkp->dk_open_lyr[part])
			dkp->dk_open_lyr[part]--;
	} else {
		ASSERT((dkp->dk_open_reg[otyp] & partbit) != 0);
		dkp->dk_open_reg[otyp] &= ~partbit;
	}
	dkp->dk_open_exl &= ~partbit;

	for (i = 0; i < CMDK_MAXPART; i++)
		if (dkp->dk_open_lyr[i] != 0) {
			lastclose = 0;
			break;
		}

	if (lastclose)
		for (i = 0; i < OTYPCNT; i++)
			if (dkp->dk_open_reg[i] != 0) {
				lastclose = 0;
				break;
			}

	mutex_exit(&dkp->dk_mutex);

	if (lastclose)
		cmlb_invalidate(dkp->dk_cmlbhandle, 0);

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
	diskaddr_t	p_lblksrt;
	diskaddr_t	p_lblkcnt;
	int		i;
	int		nodelay;

	instance = CMDKUNIT(dev);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)))
		return (ENXIO);

	if (otyp >= OTYPCNT)
		return (EINVAL);

	mutex_enter(&dkp->dk_mutex);
	while (dkp->dk_flag & CMDK_SUSPEND) {
		cv_wait(&dkp->dk_suspend_cv, &dkp->dk_mutex);
	}
	mutex_exit(&dkp->dk_mutex);

	part = CMDKPART(dev);
	partbit = 1 << part;
	nodelay = (flag & (FNDELAY | FNONBLOCK));

	mutex_enter(&dkp->dk_mutex);

	if (cmlb_validate(dkp->dk_cmlbhandle, 0, 0) != 0) {

		/* fail if not doing non block open */
		if (!nodelay) {
			mutex_exit(&dkp->dk_mutex);
			return (ENXIO);
		}
	} else if (cmlb_partinfo(dkp->dk_cmlbhandle, part, &p_lblkcnt,
	    &p_lblksrt, NULL, NULL, 0) == 0) {

		if (p_lblkcnt <= 0 && (!nodelay || otyp != OTYP_CHR)) {
			mutex_exit(&dkp->dk_mutex);
			return (ENXIO);
		}
	} else {
		/* fail if not doing non block open */
		if (!nodelay) {
			mutex_exit(&dkp->dk_mutex);
			return (ENXIO);
		}
	}

	if ((DKTP_EXT->tg_rdonly) && (flag & FWRITE)) {
		mutex_exit(&dkp->dk_mutex);
		return (EROFS);
	}

	/* check for part already opend exclusively */
	if (dkp->dk_open_exl & partbit)
		goto excl_open_fail;

	/* check if we can establish exclusive open */
	if (flag & FEXCL) {
		if (dkp->dk_open_lyr[part])
			goto excl_open_fail;
		for (i = 0; i < OTYPCNT; i++) {
			if (dkp->dk_open_reg[i] & partbit)
				goto excl_open_fail;
		}
	}

	/* open will succeed, account for open */
	dkp->dk_flag |= CMDK_OPEN;
	if (otyp == OTYP_LYR)
		dkp->dk_open_lyr[part]++;
	else
		dkp->dk_open_reg[otyp] |= partbit;
	if (flag & FEXCL)
		dkp->dk_open_exl |= partbit;

	mutex_exit(&dkp->dk_mutex);
	return (DDI_SUCCESS);

excl_open_fail:
	mutex_exit(&dkp->dk_mutex);
	return (EBUSY);
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
	int 		instance;
	struct	cmdk	*dkp;

	instance = CMDKUNIT(dev);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)))
		return (ENXIO);

	mutex_enter(&dkp->dk_mutex);
	while (dkp->dk_flag & CMDK_SUSPEND) {
		cv_wait(&dkp->dk_suspend_cv, &dkp->dk_mutex);
	}
	mutex_exit(&dkp->dk_mutex);

	return (physio(cmdkstrategy, (struct buf *)0, dev, flag, cmdkmin, uio));
}

static int
cmdkarw(dev_t dev, struct aio_req *aio, int flag)
{
	int 		instance;
	struct	cmdk	*dkp;

	instance = CMDKUNIT(dev);
	if (!(dkp = ddi_get_soft_state(cmdk_state, instance)))
		return (ENXIO);

	mutex_enter(&dkp->dk_mutex);
	while (dkp->dk_flag & CMDK_SUSPEND) {
		cv_wait(&dkp->dk_suspend_cv, &dkp->dk_mutex);
	}
	mutex_exit(&dkp->dk_mutex);

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
	diskaddr_t	p_lblksrt;
	diskaddr_t	p_lblkcnt;

	instance = CMDKUNIT(bp->b_edev);
	if (cmdk_indump || !(dkp = ddi_get_soft_state(cmdk_state, instance)) ||
	    (dkblock(bp) < 0)) {
		bp->b_resid = bp->b_bcount;
		SETBPERR(bp, ENXIO);
		biodone(bp);
		return (0);
	}

	mutex_enter(&dkp->dk_mutex);
	ASSERT(cmdk_isopen(dkp, bp->b_edev));
	while (dkp->dk_flag & CMDK_SUSPEND) {
		cv_wait(&dkp->dk_suspend_cv, &dkp->dk_mutex);
	}
	mutex_exit(&dkp->dk_mutex);

	bp->b_flags &= ~(B_DONE|B_ERROR);
	bp->b_resid = 0;
	bp->av_back = NULL;

	/*
	 * only re-read the vtoc if necessary (force == FALSE)
	 */
	if (cmlb_partinfo(dkp->dk_cmlbhandle, CMDKPART(bp->b_edev),
	    &p_lblkcnt, &p_lblksrt, NULL, NULL, 0)) {
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

	SET_BP_SEC(bp, ((ulong_t)(p_lblksrt + dkblock(bp))));
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

	ASSERT(mutex_owned(&dkp->dk_mutex));

	/* Create linkage to queueing routines based on property */
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

	/* Create linkage to dequeueing routines based on property */
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

	/* populate bbh_obj object stored in dkp */
	dkp->dk_bbh_obj.bbh_data = dkp;
	dkp->dk_bbh_obj.bbh_ops = &cmdk_bbh_ops;

	/* create linkage to dadk */
	dkp->dk_tgobjp = (opaque_t)dadk_create();

	devp = ddi_get_driver_private(dip);
	(void) dadk_init(DKTP_DATA, devp, flcobjp, queobjp, &dkp->dk_bbh_obj,
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

	ASSERT(mutex_owned(&dkp->dk_mutex));

	(void) dadk_free((dkp->dk_tgobjp));
	dkp->dk_tgobjp = NULL;

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
/*ARGSUSED5*/
static int
cmdk_lb_rdwr(dev_info_t *dip, uchar_t cmd, void *bufaddr,
    diskaddr_t start, size_t count, void *tg_cookie)
{
	struct cmdk	*dkp;
	opaque_t	handle;
	int		rc = 0;
	char		*bufa;
	size_t		buflen;

	dkp = ddi_get_soft_state(cmdk_state, ddi_get_instance(dip));
	if (dkp == NULL)
		return (ENXIO);

	if (cmd != TG_READ && cmd != TG_WRITE)
		return (EINVAL);

	/* buflen must be multiple of 512 */
	buflen = (count + NBPSCTR - 1) & -NBPSCTR;
	handle = dadk_iob_alloc(DKTP_DATA, start, buflen, KM_SLEEP);
	if (!handle)
		return (ENOMEM);

	if (cmd == TG_READ) {
		bufa = dadk_iob_xfer(DKTP_DATA, handle, B_READ);
		if (!bufa)
			rc = EIO;
		else
			bcopy(bufa, bufaddr, count);
	} else {
		bufa = dadk_iob_htoc(DKTP_DATA, handle);
		bcopy(bufaddr, bufa, count);
		bufa = dadk_iob_xfer(DKTP_DATA, handle, B_WRITE);
		if (!bufa)
			rc = EIO;
	}
	(void) dadk_iob_free(DKTP_DATA, handle);

	return (rc);
}

/*ARGSUSED3*/
static int
cmdk_lb_getinfo(dev_info_t *dip, int cmd, void *arg, void *tg_cookie)
{

	struct cmdk		*dkp;
	struct tgdk_geom	phyg;


	dkp = ddi_get_soft_state(cmdk_state, ddi_get_instance(dip));
	if (dkp == NULL)
		return (ENXIO);

	switch (cmd) {
	case TG_GETPHYGEOM: {
		cmlb_geom_t *phygeomp = (cmlb_geom_t *)arg;

		/* dadk_getphygeom always returns success */
		(void) dadk_getphygeom(DKTP_DATA, &phyg);

		phygeomp->g_capacity	= phyg.g_cap;
		phygeomp->g_nsect	= phyg.g_sec;
		phygeomp->g_nhead	= phyg.g_head;
		phygeomp->g_acyl	= phyg.g_acyl;
		phygeomp->g_ncyl	= phyg.g_cyl;
		phygeomp->g_secsize	= phyg.g_secsiz;
		phygeomp->g_intrlv	= 1;
		phygeomp->g_rpm		= 3600;

		return (0);
	}

	case TG_GETVIRTGEOM: {
		cmlb_geom_t *virtgeomp = (cmlb_geom_t *)arg;
		diskaddr_t		capacity;

		(void) dadk_getgeom(DKTP_DATA, &phyg);
		capacity = phyg.g_cap;

		/*
		 * If the controller returned us something that doesn't
		 * really fit into an Int 13/function 8 geometry
		 * result, just fail the ioctl.  See PSARC 1998/313.
		 */
		if (capacity < 0 || capacity >= 63 * 254 * 1024)
			return (EINVAL);

		virtgeomp->g_capacity	= capacity;
		virtgeomp->g_nsect	= 63;
		virtgeomp->g_nhead	= 254;
		virtgeomp->g_ncyl	= capacity / (63 * 254);
		virtgeomp->g_acyl	= 0;
		virtgeomp->g_secsize	= 512;
		virtgeomp->g_intrlv	= 1;
		virtgeomp->g_rpm	= 3600;

		return (0);
	}

	case TG_GETCAPACITY:
	case TG_GETBLOCKSIZE:
	{

		/* dadk_getphygeom always returns success */
		(void) dadk_getphygeom(DKTP_DATA, &phyg);
		if (cmd == TG_GETCAPACITY)
			*(diskaddr_t *)arg = phyg.g_cap;
		else
			*(uint32_t *)arg = (uint32_t)phyg.g_secsiz;

		return (0);
	}

	case TG_GETATTR: {
		tg_attribute_t *tgattribute = (tg_attribute_t *)arg;
		if ((DKTP_EXT->tg_rdonly))
			tgattribute->media_is_writable = FALSE;
		else
			tgattribute->media_is_writable = TRUE;
		tgattribute->media_is_rotational = TRUE;

		return (0);
	}

	default:
		return (ENOTTY);
	}
}





/*
 * Create and register the devid.
 * There are 4 different ways we can get a device id:
 *    1. Already have one - nothing to do
 *    2. Build one from the drive's model and serial numbers
 *    3. Read one from the disk (first sector of last track)
 *    4. Fabricate one and write it on the disk.
 * If any of these succeeds, register the deviceid
 */
static void
cmdk_devid_setup(struct cmdk *dkp)
{
	int	rc;

	/* Try options until one succeeds, or all have failed */

	/* 1. All done if already registered */
	if (dkp->dk_devid != NULL)
		return;

	/* 2. Build a devid from the model and serial number */
	rc = cmdk_devid_modser(dkp);
	if (rc != DDI_SUCCESS) {
		/* 3. Read devid from the disk, if present */
		rc = cmdk_devid_read(dkp);

		/* 4. otherwise make one up and write it on the disk */
		if (rc != DDI_SUCCESS)
			rc = cmdk_devid_fabricate(dkp);
	}

	/* If we managed to get a devid any of the above ways, register it */
	if (rc == DDI_SUCCESS)
		(void) ddi_devid_register(dkp->dk_dip, dkp->dk_devid);

}

/*
 * Build a devid from the model and serial number
 * Return DDI_SUCCESS or DDI_FAILURE.
 */
static int
cmdk_devid_modser(struct cmdk *dkp)
{
	int	rc = DDI_FAILURE;
	char	*hwid;
	int	modlen;
	int	serlen;

	/*
	 * device ID is a concatenation of model number, '=', serial number.
	 */
	hwid = kmem_alloc(CMDK_HWIDLEN, KM_SLEEP);
	modlen = cmdk_get_modser(dkp, DIOCTL_GETMODEL, hwid, CMDK_HWIDLEN);
	if (modlen == 0) {
		rc = DDI_FAILURE;
		goto err;
	}
	hwid[modlen++] = '=';
	serlen = cmdk_get_modser(dkp, DIOCTL_GETSERIAL,
	    hwid + modlen, CMDK_HWIDLEN - modlen);
	if (serlen == 0) {
		rc = DDI_FAILURE;
		goto err;
	}
	hwid[modlen + serlen] = 0;

	/* Initialize the device ID, trailing NULL not included */
	rc = ddi_devid_init(dkp->dk_dip, DEVID_ATA_SERIAL, modlen + serlen,
	    hwid, &dkp->dk_devid);
	if (rc != DDI_SUCCESS) {
		rc = DDI_FAILURE;
		goto err;
	}

	rc = DDI_SUCCESS;

err:
	kmem_free(hwid, CMDK_HWIDLEN);
	return (rc);
}

static int
cmdk_get_modser(struct cmdk *dkp, int ioccmd, char *buf, int len)
{
	dadk_ioc_string_t strarg;
	int		rval;
	char		*s;
	char		ch;
	boolean_t	ret;
	int		i;
	int		tb;

	strarg.is_buf = buf;
	strarg.is_size = len;
	if (dadk_ioctl(DKTP_DATA,
	    dkp->dk_dev,
	    ioccmd,
	    (uintptr_t)&strarg,
	    FNATIVE | FKIOCTL,
	    NULL,
	    &rval) != 0)
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
 * Read a devid from on the first block of the last track of
 * the last cylinder.  Make sure what we read is a valid devid.
 * Return DDI_SUCCESS or DDI_FAILURE.
 */
static int
cmdk_devid_read(struct cmdk *dkp)
{
	diskaddr_t	blk;
	struct dk_devid *dkdevidp;
	uint_t		*ip;
	int		chksum;
	int		i, sz;
	tgdk_iob_handle	handle = NULL;
	int		rc = DDI_FAILURE;

	if (cmlb_get_devid_block(dkp->dk_cmlbhandle, &blk, 0))
		goto err;

	/* read the devid */
	handle = dadk_iob_alloc(DKTP_DATA, blk, NBPSCTR, KM_SLEEP);
	if (handle == NULL)
		goto err;

	dkdevidp = (struct dk_devid *)dadk_iob_xfer(DKTP_DATA, handle, B_READ);
	if (dkdevidp == NULL)
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
	sz = ddi_devid_sizeof((ddi_devid_t)dkdevidp->dkd_devid);
	dkp->dk_devid = kmem_alloc(sz, KM_SLEEP);
	bcopy(dkdevidp->dkd_devid, dkp->dk_devid, sz);

	rc = DDI_SUCCESS;

err:
	if (handle != NULL)
		(void) dadk_iob_free(DKTP_DATA, handle);
	return (rc);
}

/*
 * Create a devid and write it on the first block of the last track of
 * the last cylinder.
 * Return DDI_SUCCESS or DDI_FAILURE.
 */
static int
cmdk_devid_fabricate(struct cmdk *dkp)
{
	ddi_devid_t	devid = NULL;	/* devid made by ddi_devid_init  */
	struct dk_devid	*dkdevidp;	/* devid struct stored on disk */
	diskaddr_t	blk;
	tgdk_iob_handle	handle = NULL;
	uint_t		*ip, chksum;
	int		i;
	int		rc = DDI_FAILURE;

	if (ddi_devid_init(dkp->dk_dip, DEVID_FAB, 0, NULL, &devid) !=
	    DDI_SUCCESS)
		goto err;

	if (cmlb_get_devid_block(dkp->dk_cmlbhandle, &blk, 0)) {
		/* no device id block address */
		goto err;
	}

	handle = dadk_iob_alloc(DKTP_DATA, blk, NBPSCTR, KM_SLEEP);
	if (!handle)
		goto err;

	/* Locate the buffer */
	dkdevidp = (struct dk_devid *)dadk_iob_htoc(DKTP_DATA, handle);

	/* Fill in the revision */
	bzero(dkdevidp, NBPSCTR);
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

	/* write the devid */
	(void) dadk_iob_xfer(DKTP_DATA, handle, B_WRITE);

	dkp->dk_devid = devid;

	rc = DDI_SUCCESS;

err:
	if (handle != NULL)
		(void) dadk_iob_free(DKTP_DATA, handle);

	if (rc != DDI_SUCCESS && devid != NULL)
		ddi_devid_free(devid);

	return (rc);
}

static void
cmdk_bbh_free_alts(struct cmdk *dkp)
{
	if (dkp->dk_alts_hdl) {
		(void) dadk_iob_free(DKTP_DATA, dkp->dk_alts_hdl);
		kmem_free(dkp->dk_slc_cnt,
		    NDKMAP * (sizeof (uint32_t) + sizeof (struct alts_ent *)));
		dkp->dk_alts_hdl = NULL;
	}
}

static void
cmdk_bbh_reopen(struct cmdk *dkp)
{
	tgdk_iob_handle 	handle = NULL;
	diskaddr_t		slcb, slcn, slce;
	struct	alts_parttbl	*ap;
	struct	alts_ent	*enttblp;
	uint32_t		altused;
	uint32_t		altbase;
	uint32_t		altlast;
	int			alts;
	uint16_t		vtoctag;
	int			i, j;

	/* find slice with V_ALTSCTR tag */
	for (alts = 0; alts < NDKMAP; alts++) {
		if (cmlb_partinfo(
		    dkp->dk_cmlbhandle,
		    alts,
		    &slcn,
		    &slcb,
		    NULL,
		    &vtoctag,
		    0)) {
			goto empty;	/* no partition table exists */
		}

		if (vtoctag == V_ALTSCTR && slcn > 1)
			break;
	}
	if (alts >= NDKMAP) {
		goto empty;	/* no V_ALTSCTR slice defined */
	}

	/* read in ALTS label block */
	handle = dadk_iob_alloc(DKTP_DATA, slcb, NBPSCTR, KM_SLEEP);
	if (!handle) {
		goto empty;
	}

	ap = (struct alts_parttbl *)dadk_iob_xfer(DKTP_DATA, handle, B_READ);
	if (!ap || (ap->alts_sanity != ALTS_SANITY)) {
		goto empty;
	}

	altused = ap->alts_ent_used;	/* number of BB entries */
	altbase = ap->alts_ent_base;	/* blk offset from begin slice */
	altlast = ap->alts_ent_end;	/* blk offset to last block */
	/* ((altused * sizeof (struct alts_ent) + NBPSCTR - 1) & ~NBPSCTR) */

	if (altused == 0 ||
	    altbase < 1 ||
	    altbase > altlast ||
	    altlast >= slcn) {
		goto empty;
	}
	(void) dadk_iob_free(DKTP_DATA, handle);

	/* read in ALTS remapping table */
	handle = dadk_iob_alloc(DKTP_DATA,
	    slcb + altbase,
	    (altlast - altbase + 1) << SCTRSHFT, KM_SLEEP);
	if (!handle) {
		goto empty;
	}

	enttblp = (struct alts_ent *)dadk_iob_xfer(DKTP_DATA, handle, B_READ);
	if (!enttblp) {
		goto empty;
	}

	rw_enter(&dkp->dk_bbh_mutex, RW_WRITER);

	/* allocate space for dk_slc_cnt and dk_slc_ent tables */
	if (dkp->dk_slc_cnt == NULL) {
		dkp->dk_slc_cnt = kmem_alloc(NDKMAP *
		    (sizeof (long) + sizeof (struct alts_ent *)), KM_SLEEP);
	}
	dkp->dk_slc_ent = (struct alts_ent **)(dkp->dk_slc_cnt + NDKMAP);

	/* free previous BB table (if any) */
	if (dkp->dk_alts_hdl) {
		(void) dadk_iob_free(DKTP_DATA, dkp->dk_alts_hdl);
		dkp->dk_alts_hdl = NULL;
		dkp->dk_altused = 0;
	}

	/* save linkage to new BB table */
	dkp->dk_alts_hdl = handle;
	dkp->dk_altused = altused;

	/*
	 * build indexes to BB table by slice
	 * effectively we have
	 *	struct alts_ent *enttblp[altused];
	 *
	 *	uint32_t	dk_slc_cnt[NDKMAP];
	 *	struct alts_ent *dk_slc_ent[NDKMAP];
	 */
	for (i = 0; i < NDKMAP; i++) {
		if (cmlb_partinfo(
		    dkp->dk_cmlbhandle,
		    i,
		    &slcn,
		    &slcb,
		    NULL,
		    NULL,
		    0)) {
			goto empty1;
		}

		dkp->dk_slc_cnt[i] = 0;
		if (slcn == 0)
			continue;	/* slice is not allocated */

		/* last block in slice */
		slce = slcb + slcn - 1;

		/* find first remap entry in after beginnning of slice */
		for (j = 0; j < altused; j++) {
			if (enttblp[j].bad_start + enttblp[j].bad_end >= slcb)
				break;
		}
		dkp->dk_slc_ent[i] = enttblp + j;

		/* count remap entrys until end of slice */
		for (; j < altused && enttblp[j].bad_start <= slce; j++) {
			dkp->dk_slc_cnt[i] += 1;
		}
	}

	rw_exit(&dkp->dk_bbh_mutex);
	return;

empty:
	rw_enter(&dkp->dk_bbh_mutex, RW_WRITER);
empty1:
	if (handle && handle != dkp->dk_alts_hdl)
		(void) dadk_iob_free(DKTP_DATA, handle);

	if (dkp->dk_alts_hdl) {
		(void) dadk_iob_free(DKTP_DATA, dkp->dk_alts_hdl);
		dkp->dk_alts_hdl = NULL;
	}

	rw_exit(&dkp->dk_bbh_mutex);
}

/*ARGSUSED*/
static bbh_cookie_t
cmdk_bbh_htoc(opaque_t bbh_data, opaque_t handle)
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
cmdk_bbh_freehandle(opaque_t bbh_data, opaque_t handle)
{
	struct	bbh_handle *hp;

	hp = (struct  bbh_handle *)handle;
	kmem_free(handle, (sizeof (struct bbh_handle) +
	    (hp->h_totck * (sizeof (struct bbh_cookie)))));
}


/*
 *	cmdk_bbh_gethandle remaps the bad sectors to alternates.
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
cmdk_bbh_gethandle(opaque_t bbh_data, struct buf *bp)
{
	struct cmdk		*dkp = (struct cmdk *)bbh_data;
	struct bbh_handle	*hp;
	struct bbh_cookie	*ckp;
	struct alts_ent		*altp;
	uint32_t		alts_used;
	uint32_t		part = CMDKPART(bp->b_edev);
	daddr32_t		lastsec;
	long			d_count;
	int			i;
	int			idx;
	int			cnt;

	if (part >= V_NUMPAR)
		return (NULL);

	/*
	 * This if statement is atomic and it will succeed
	 * if there are no bad blocks (almost always)
	 *
	 * so this if is performed outside of the rw_enter for speed
	 * and then repeated inside the rw_enter for safety
	 */
	if (!dkp->dk_alts_hdl) {
		return (NULL);
	}

	rw_enter(&dkp->dk_bbh_mutex, RW_READER);

	if (dkp->dk_alts_hdl == NULL) {
		rw_exit(&dkp->dk_bbh_mutex);
		return (NULL);
	}

	alts_used = dkp->dk_slc_cnt[part];
	if (alts_used == 0) {
		rw_exit(&dkp->dk_bbh_mutex);
		return (NULL);
	}
	altp = dkp->dk_slc_ent[part];

	/*
	 * binary search for the largest bad sector index in the alternate
	 * entry table which overlaps or larger than the starting d_sec
	 */
	i = cmdk_bbh_bsearch(altp, alts_used, GET_BP_SEC(bp));
	/* if starting sector is > the largest bad sector, return */
	if (i == -1) {
		rw_exit(&dkp->dk_bbh_mutex);
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
		rw_exit(&dkp->dk_bbh_mutex);
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

	altp = dkp->dk_slc_ent[part];
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
			ckp[idx].ck_sector = altp->good_start +
			    ckp[idx].ck_sector - altp->bad_start;
			break;
		}

		/* at least one bad sector in our section.  break it. */
		/* CASE 5: */
		if ((lastsec >= altp->bad_start) &&
		    (lastsec <= altp->bad_end)) {
			ckp[idx+1].ck_seclen = lastsec - altp->bad_start + 1;
			ckp[idx].ck_seclen -= ckp[idx+1].ck_seclen;
			ckp[idx+1].ck_sector = altp->good_start;
			break;
		}
		/* CASE 6: */
		if ((ckp[idx].ck_sector <= altp->bad_end) &&
		    (ckp[idx].ck_sector >= altp->bad_start)) {
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
		ckp[idx].ck_seclen = altp->bad_start - ckp[idx].ck_sector;
		ckp[idx+1].ck_sector = altp->good_start;
		ckp[idx+1].ck_seclen = altp->bad_end - altp->bad_start + 1;
		idx += 2;
		ckp[idx].ck_sector = altp->bad_end + 1;
		ckp[idx].ck_seclen = lastsec - altp->bad_end;
	}

	rw_exit(&dkp->dk_bbh_mutex);
	return ((opaque_t)hp);
}

static int
cmdk_bbh_bsearch(struct alts_ent *buf, int cnt, daddr32_t key)
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
