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
static boolean_t vscan_drv_nodes[VS_DRV_MAX_FILES + 1];
static boolean_t vscan_drv_connected = B_FALSE; /* vscand daemon connected */

static dev_info_t *vscan_drv_dip;
static kmutex_t vscan_drv_mutex;
static kcondvar_t vscan_drv_cv; /* wait for daemon reconnect */

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

static boolean_t vscan_drv_in_use(void);
static void vscan_drv_delayed_disable(void);


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
	(void) memset(&vscan_drv_nodes, 0, sizeof (vscan_drv_nodes));

	if ((rc  = mod_install(&modlinkage)) != 0) {
		vscan_door_fini();
		vscan_svc_fini();
		mutex_destroy(&vscan_drv_mutex);
	}

	cv_init(&vscan_drv_cv, NULL, CV_DEFAULT, NULL);
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
		cv_destroy(&vscan_drv_cv);
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
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_get_instance(dip) != 0)
		return (DDI_FAILURE);

	vscan_drv_dip = dip;

	/* create minor node 0 for daemon-driver synchronization */
	if (vscan_drv_create_node(0) == B_FALSE)
		return (DDI_FAILURE);

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

	/* remove all minor nodes */
	vscan_drv_dip = NULL;
	ddi_remove_minor_node(dip, NULL);
	(void) memset(&vscan_drv_nodes, 0, sizeof (vscan_drv_nodes));

	return (DDI_SUCCESS);
}


/*
 * vscan_drv_in_use
 *
 * If vscand is connected (vscan_drv_connected == B_TRUE) the
 * vscan driver is obviously in use. Otherwise invoke
 * vscan_svc_in_use() to determine if the driver is in use,
 * even though the daemon has disconnected.
 * For example, there may be requests not yet complete, or
 * the driver may still be enabled waiting for the daemon to
 * reconnect.
 * Used to determine whether the driver can be unloaded.
 */
static boolean_t
vscan_drv_in_use()
{
	boolean_t in_use;

	mutex_enter(&vscan_drv_mutex);
	in_use = vscan_drv_connected;
	mutex_exit(&vscan_drv_mutex);

	if (in_use == B_FALSE)
		in_use = vscan_svc_in_use();

	return (in_use);
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
		/* wake any pending delayed disable */
		cv_signal(&vscan_drv_cv);
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
		if (vscan_svc_is_enabled()) {
			if (thread_create(NULL, 0, vscan_drv_delayed_disable,
			    0, 0, &p0, TS_RUN, minclsyspri) == NULL) {
				vscan_svc_enable();
			}
		}
		vscan_door_close();
	} else {
		vscan_drv_state[inst] = VS_INIT;
	}
	mutex_exit(&vscan_drv_mutex);

	return (0);
}


/*
 * vscan_drv_delayed_disable
 *
 * Invoked from vscan_drv_close if the daemon disconnects
 * without first sending disable (e.g. daemon crashed).
 * Delays for VS_DAEMON_WAIT_SEC before disabling, to allow
 * the daemon to reconnect. During this time, scan requests
 * will be processed locally (see vscan_svc.c)
 */
static void
vscan_drv_delayed_disable(void)
{
	clock_t timeout = lbolt + SEC_TO_TICK(VS_DAEMON_WAIT_SEC);

	mutex_enter(&vscan_drv_mutex);
	(void) cv_timedwait(&vscan_drv_cv, &vscan_drv_mutex, timeout);

	if (vscan_drv_connected) {
		DTRACE_PROBE(vscan__reconnect);
	} else {
		vscan_svc_disable();
	}
	mutex_exit(&vscan_drv_mutex);
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
		vscan_svc_enable();
		mutex_exit(&vscan_drv_mutex);
		break;
	case VS_DRV_IOCTL_DISABLE:
		vscan_svc_disable();
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


/*
 * vscan_drv_create_node
 *
 * Create minor node with which vscan daemon will communicate
 * to access a file. Invoked from vscan_svc before scan request
 * sent up to daemon.
 * Minor node 0 is reserved for daemon-driver synchronization
 * and is created during attach.
 * All minor nodes are removed during detach.
 */
boolean_t
vscan_drv_create_node(int idx)
{
	char name[VS_DRV_NODENAME_LEN];
	boolean_t *pnode, rc;

	mutex_enter(&vscan_drv_mutex);

	pnode = &vscan_drv_nodes[idx];
	if (*pnode == B_FALSE) {
		(void) snprintf(name, VS_DRV_NODENAME_LEN, "vscan%d", idx);
		if (ddi_create_minor_node(vscan_drv_dip, name,
		    S_IFCHR, idx, DDI_PSEUDO, 0) == DDI_SUCCESS) {
			*pnode = B_TRUE;
		}
		DTRACE_PROBE2(vscan__minor__node, int, idx, int, *pnode);
	}

	rc = *pnode;
	mutex_exit(&vscan_drv_mutex);

	return (rc);
}
