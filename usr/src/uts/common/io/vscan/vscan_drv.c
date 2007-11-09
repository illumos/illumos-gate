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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/time.h>
#include <sys/varargs.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/vnode.h>
#include <fs/fs_subr.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/disp.h>
#include <sys/vscan.h>
#include <sys/policy.h>
#include <sys/sdt.h>

#define	VS_DRV_NODENAME_LEN	16


/*
 * Instance States: VS_INIT (initial state), VS_OPEN, VS_READING
 *
 * Instance 0 controls the state of the driver: vscan_drv_connected.
 *   vscan_drv_state[0] should NOT be used.
 * Actions:
 * open:	VS_INIT->VS_OPEN, otherwise ERROR
 * close:	any->VS_INIT
 * read:	VS_OPEN->VS_READING, otherwise ERROR
 */
typedef enum {
	VS_INIT,
	VS_OPEN,
	VS_READING
} vscan_drv_state_t;

static vscan_drv_state_t vscan_drv_state[VS_DRV_MAX_FILES + 1];
static boolean_t vscan_drv_connected = B_FALSE; /* vscand daemon connected */

static dev_info_t *vscan_drv_dip;
static kmutex_t vscan_drv_mutex;

/*
 * DDI entry points.
 */
static int vscan_drv_attach(dev_info_t *, ddi_attach_cmd_t);
static int vscan_drv_detach(dev_info_t *, ddi_detach_cmd_t);
static int vscan_drv_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int vscan_drv_open(dev_t *, int, int, cred_t *);
static int vscan_drv_close(dev_t, int, int, cred_t *);
static int vscan_drv_read(dev_t, struct uio *, cred_t *);
static int vscan_drv_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static boolean_t vscan_drv_in_use();


/*
 * module linkage info for the kernel
 */

static struct cb_ops cbops = {
	vscan_drv_open,		/* cb_open */
	vscan_drv_close,	/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	vscan_drv_read,		/* cb_read */
	nodev,			/* cb_write */
	vscan_drv_ioctl,	/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_streamtab */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops devops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	vscan_drv_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	vscan_drv_attach,	/* devo_attach */
	vscan_drv_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&cbops,			/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* drv_modops */
	"virus scanning",	/* drv_linkinfo */
	&devops,
};

static struct modlinkage modlinkage = {

	MODREV_1,	/* revision of the module, must be: MODREV_1	*/
	&modldrv,	/* ptr to linkage structures			*/
	NULL,
};


/*
 * _init
 */
int
_init(void)
{
	int rc;

	mutex_init(&vscan_drv_mutex, NULL, MUTEX_DRIVER, NULL);

	if (vscan_door_init() != 0) {
		mutex_destroy(&vscan_drv_mutex);
		return (DDI_FAILURE);
	}

	if (vscan_svc_init() != 0) {
		vscan_door_fini();
		mutex_destroy(&vscan_drv_mutex);
		return (DDI_FAILURE);
	}

	(void) memset(&vscan_drv_state, 0, sizeof (vscan_drv_state));

	if ((rc  = mod_install(&modlinkage)) != 0) {
		vscan_door_fini();
		vscan_svc_fini();
		mutex_destroy(&vscan_drv_mutex);
	}

	return (rc);
}


/*
 * _info
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * _fini
 */
int
_fini(void)
{
	int rc;

	if (vscan_drv_in_use())
		return (EBUSY);

	if ((rc = mod_remove(&modlinkage)) == 0) {
		vscan_door_fini();
		vscan_svc_fini();
		mutex_destroy(&vscan_drv_mutex);
	}

	return (rc);
}


/*
 * DDI entry points.
 */

/*
 * vscan_drv_getinfo
 */
/* ARGSUSED */
static int
vscan_drv_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	ulong_t inst = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = vscan_drv_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)inst;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}


/*
 * vscan_drv_attach
 */
static int
vscan_drv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int i;
	char name[VS_DRV_NODENAME_LEN];

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_get_instance(dip) != 0)
		return (DDI_FAILURE);

	vscan_drv_dip = dip;

	/* create the minor nodes */
	for (i = 0; i <= VS_DRV_MAX_FILES; i++) {
		(void) snprintf(name, VS_DRV_NODENAME_LEN, "vscan%d", i);
		if (ddi_create_minor_node(dip, name, S_IFCHR, i,
		    DDI_PSEUDO, 0) != DDI_SUCCESS) {
			ddi_remove_minor_node(dip, NULL);
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * vscan_drv_detach
 */
static int
vscan_drv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	if (ddi_get_instance(dip) != 0)
		return (DDI_FAILURE);

	if (vscan_drv_in_use())
		return (DDI_FAILURE);

	vscan_drv_dip = NULL;
	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}


/*
 * vscan_drv_in_use
 */
static boolean_t
vscan_drv_in_use()
{
	if (vscan_drv_connected)
		return (B_TRUE);
	else
		return (vscan_svc_in_use());
}


/*
 * vscan_drv_open
 * if inst == 0, this is vscand initializing.
 * Otherwise, open the file associated with inst.
 */
/* ARGSUSED */
static int
vscan_drv_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int rc;
	int inst = getminor(*devp);

	if ((inst < 0) || (inst > VS_DRV_MAX_FILES))
		return (EINVAL);

	/* check if caller has privilege for virus scanning */
	if ((rc = secpolicy_vscan(credp)) != 0) {
		DTRACE_PROBE1(vscan__priv, int, rc);
		return (EPERM);
	}

	mutex_enter(&vscan_drv_mutex);
	if (inst == 0) {
		if (vscan_drv_connected) {
			mutex_exit(&vscan_drv_mutex);
			return (EINVAL);
		}
		vscan_drv_connected = B_TRUE;
	} else {
		if ((!vscan_drv_connected) ||
		    (vscan_drv_state[inst] != VS_INIT)) {
				mutex_exit(&vscan_drv_mutex);
				return (EINVAL);
		}
		vscan_drv_state[inst] = VS_OPEN;
	}
	mutex_exit(&vscan_drv_mutex);

	return (0);
}


/*
 * vscan_drv_close
 * if inst == 0, this is vscand detaching
 * Otherwise close the file associated with inst
 */
/* ARGSUSED */
static int
vscan_drv_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int i, inst = getminor(dev);

	if ((inst < 0) || (inst > VS_DRV_MAX_FILES))
		return (EINVAL);

	mutex_enter(&vscan_drv_mutex);
	if (inst == 0) {
		for (i = 1; i <= VS_DRV_MAX_FILES; i++)
			vscan_drv_state[i] = VS_INIT;

		vscan_drv_connected = B_FALSE;
		vscan_svc_enable(B_FALSE);
		vscan_door_close();
	} else {
		vscan_drv_state[inst] = VS_INIT;
	}
	mutex_exit(&vscan_drv_mutex);

	return (0);
}


/*
 * vscan_drv_read
 */
/* ARGSUSED */
static int
vscan_drv_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int rc;
	int inst = getminor(dev);
	vnode_t *vp;

	if ((inst <= 0) || (inst > VS_DRV_MAX_FILES))
		return (EINVAL);

	mutex_enter(&vscan_drv_mutex);
	if ((!vscan_drv_connected) || (vscan_drv_state[inst] != VS_OPEN)) {
		mutex_exit(&vscan_drv_mutex);
		return (EINVAL);
	}
	vscan_drv_state[inst] = VS_READING;
	mutex_exit(&vscan_drv_mutex);

	if ((vp = vscan_svc_get_vnode(inst)) == NULL)
		return (EINVAL);

	(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, NULL);
	rc = VOP_READ(vp, uiop, 0, kcred, NULL);
	VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);

	mutex_enter(&vscan_drv_mutex);
	if (vscan_drv_state[inst] == VS_READING)
		vscan_drv_state[inst] = VS_OPEN;
	mutex_exit(&vscan_drv_mutex);

	return (rc);
}


/*
 * vscan_drv_ioctl
 */
/* ARGSUSED */
static int
vscan_drv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
	cred_t *credp, int *rvalp)
{
	int inst = getminor(dev);
	vs_config_t conf;

	if (inst != 0)
		return (EINVAL);

	switch (cmd) {
	case VS_DRV_IOCTL_ENABLE:
		mutex_enter(&vscan_drv_mutex);
		if ((!vscan_drv_connected) ||
		    (vscan_door_open((int)arg) != 0)) {
			mutex_exit(&vscan_drv_mutex);
			return (EINVAL);
		}
		vscan_svc_enable(B_TRUE);
		mutex_exit(&vscan_drv_mutex);
		break;
	case VS_DRV_IOCTL_DISABLE:
		vscan_svc_enable(B_FALSE);
		break;
	case VS_DRV_IOCTL_CONFIG:
		if (ddi_copyin((void *)arg, &conf,
		    sizeof (vs_config_t), 0) == -1)
			return (EFAULT);
		if (vscan_svc_configure(&conf) == -1)
			return (EINVAL);
		break;
	default:
		return (ENOTTY);
	}

	return (0);
}
