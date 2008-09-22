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


/* seconds to wait for daemon to reconnect before disabling */
#define	VS_DAEMON_WAIT_SEC	60

/* length of minor node name - vscan%d */
#define	VS_NODENAME_LEN		16

/* global variables - tunable via /etc/system */
uint32_t vs_reconnect_timeout = VS_DAEMON_WAIT_SEC;
extern uint32_t vs_nodes_max;	/* max in-progress scan requests */

/*
 * vscan_drv_state
 *
 * Operations on instance 0 represent vscand initiated state
 * transition events:
 * open(0) - vscand connect
 * close(0) - vscan disconnect
 * enable(0) - vscand enable (ready to hand requests)
 * disable(0) - vscand disable (shutting down)
 *
 *   +------------------------+
 *   | VS_DRV_UNCONFIG        |
 *   +------------------------+
 *      |           ^
 *      | attach    | detach
 *      v           |
 *   +------------------------+
 *   | VS_DRV_IDLE            |<------|
 *   +------------------------+       |
 *      |           ^                 |
 *      | open(0)   | close(0)        |
 *      v           |                 |
 *   +------------------------+       |
 *   | VS_DRV_CONNECTED       |<-|    |
 *   +------------------------+  |    |
 *      |           ^            |    |
 *      | enable(0) | disable(0) |    |
 *      v           |            |    |
 *   +------------------------+  |    |
 *   | VS_DRV_ENABLED         |  |    |
 *   +------------------------+  |    |
 *      |                        |    |
 *      | close(0)            open(0) |
 *      v                        |    |
 *   +------------------------+  |    | timeout
 *   | VS_DRV_DELAYED_DISABLE | --    |
 *   +------------------------+	------|
 *
 */
typedef enum {
	VS_DRV_UNCONFIG,
	VS_DRV_IDLE,
	VS_DRV_CONNECTED,
	VS_DRV_ENABLED,
	VS_DRV_DELAYED_DISABLE
} vscan_drv_state_t;
static vscan_drv_state_t vscan_drv_state = VS_DRV_UNCONFIG;


/*
 * vscan_drv_inst_state
 *
 * Instance 0 controls the state of the driver: vscan_drv_state.
 * vscan_drv_inst_state[0] should NOT be used.
 *
 * vscan_drv_inst_state[n] represents the state of driver
 * instance n, used by vscand to access file data for the
 * scan request with index n in vscan_svc_reqs.
 * Minor nodes are created as required then all are destroyed
 * during driver detach.
 *
 *   +------------------------+
 *   | VS_DRV_INST_UNCONFIG   |
 *   +------------------------+
 *      |                 ^
 *      | create_node(n)  | detach
 *      v                 |
 *   +------------------------+
 *   | VS_DRV_INST_INIT       |<-|
 *   +------------------------+  |
 *      |                        |
 *      | open(n)                |
 *      v                        |
 *   +------------------------+  |
 *   | VS_DRV_INST_OPEN       |--|
 *   +------------------------+  |
 *      |                        |
 *      | read(n)                |
 *      v                        | close(n)
 *   +------------------------+  |
 *   | VS_DRV_INST_READING    |--|
 *   +------------------------+
 */
typedef enum {
	VS_DRV_INST_UNCONFIG = 0, /* minor node not created */
	VS_DRV_INST_INIT,
	VS_DRV_INST_OPEN,
	VS_DRV_INST_READING
} vscan_drv_inst_state_t;

static vscan_drv_inst_state_t *vscan_drv_inst_state;
static int vscan_drv_inst_state_sz;

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
	ddi_quiesce_not_needed,		/* devo_quiesce */
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

	vscan_drv_inst_state_sz =
	    sizeof (vscan_drv_inst_state_t) * (vs_nodes_max + 1);

	if (vscan_door_init() != 0)
		return (DDI_FAILURE);

	if (vscan_svc_init() != 0) {
		vscan_door_fini();
		return (DDI_FAILURE);
	}

	mutex_init(&vscan_drv_mutex, NULL, MUTEX_DRIVER, NULL);
	vscan_drv_inst_state = kmem_zalloc(vscan_drv_inst_state_sz, KM_SLEEP);

	cv_init(&vscan_drv_cv, NULL, CV_DEFAULT, NULL);

	if ((rc  = mod_install(&modlinkage)) != 0) {
		vscan_door_fini();
		vscan_svc_fini();
		kmem_free(vscan_drv_inst_state, vscan_drv_inst_state_sz);
		cv_destroy(&vscan_drv_cv);
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
		kmem_free(vscan_drv_inst_state, vscan_drv_inst_state_sz);
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

	vscan_drv_state = VS_DRV_IDLE;
	return (DDI_SUCCESS);
}


/*
 * vscan_drv_detach
 */
static int
vscan_drv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int i;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	if (ddi_get_instance(dip) != 0)
		return (DDI_FAILURE);

	if (vscan_drv_in_use())
		return (DDI_FAILURE);

	/* remove all minor nodes */
	vscan_drv_dip = NULL;
	ddi_remove_minor_node(dip, NULL);
	for (i = 0; i <= vs_nodes_max; i++)
		vscan_drv_inst_state[i] = VS_DRV_INST_UNCONFIG;

	vscan_drv_state = VS_DRV_UNCONFIG;
	return (DDI_SUCCESS);
}


/*
 * vscan_drv_in_use
 *
 * If the driver state is not IDLE or UNCONFIG then the
 * driver is in use. Otherwise, check the service interface
 * (vscan_svc) to see if it is still in use - for example
 * there there may be requests still in progress.
 */
static boolean_t
vscan_drv_in_use()
{
	boolean_t in_use = B_FALSE;

	mutex_enter(&vscan_drv_mutex);
	if ((vscan_drv_state != VS_DRV_IDLE) &&
	    (vscan_drv_state != VS_DRV_UNCONFIG)) {
		in_use = B_TRUE;
	}
	mutex_exit(&vscan_drv_mutex);

	if (in_use)
		return (B_TRUE);
	else
		return (vscan_svc_in_use());
}


/*
 * vscan_drv_open
 *
 * If inst == 0, this is vscand initializing.
 * If the driver is in DELAYED_DISABLE, ie vscand previously
 * disconnected without a clean shutdown and the driver is
 * waiting for a period to allow vscand to reconnect, signal
 * vscan_drv_cv to cancel the delayed disable.
 *
 * If inst != 0, open the file associated with inst.
 */
/* ARGSUSED */
static int
vscan_drv_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int rc;
	int inst = getminor(*devp);

	if ((inst < 0) || (inst > vs_nodes_max))
		return (EINVAL);

	/* check if caller has privilege for virus scanning */
	if ((rc = secpolicy_vscan(credp)) != 0) {
		DTRACE_PROBE1(vscan__priv, int, rc);
		return (EPERM);
	}

	mutex_enter(&vscan_drv_mutex);
	if (inst == 0) {
		switch (vscan_drv_state) {
		case VS_DRV_IDLE:
			vscan_drv_state = VS_DRV_CONNECTED;
			break;
		case VS_DRV_DELAYED_DISABLE:
			cv_signal(&vscan_drv_cv);
			vscan_drv_state = VS_DRV_CONNECTED;
			break;
		default:
			DTRACE_PROBE1(vscan__drv__state__violation,
			    int, vscan_drv_state);
			mutex_exit(&vscan_drv_mutex);
			return (EINVAL);
		}
	} else {
		if ((vscan_drv_state != VS_DRV_ENABLED) ||
		    (vscan_drv_inst_state[inst] != VS_DRV_INST_INIT)) {
			mutex_exit(&vscan_drv_mutex);
			return (EINVAL);
		}
		vscan_drv_inst_state[inst] = VS_DRV_INST_OPEN;
	}
	mutex_exit(&vscan_drv_mutex);

	return (0);
}


/*
 * vscan_drv_close
 *
 * If inst == 0, this is vscand detaching.
 * If the driver is in ENABLED state vscand has terminated without
 * a clean shutdown (nod DISABLE received). Enter DELAYED_DISABLE
 * state and initiate a delayed disable to allow vscand time to
 * reconnect.
 *
 * If inst != 0, close the file associated with inst
 */
/* ARGSUSED */
static int
vscan_drv_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int i, inst = getminor(dev);

	if ((inst < 0) || (inst > vs_nodes_max))
		return (EINVAL);

	mutex_enter(&vscan_drv_mutex);
	if (inst != 0) {
		vscan_drv_inst_state[inst] = VS_DRV_INST_INIT;
		mutex_exit(&vscan_drv_mutex);
		return (0);
	}

	/* instance 0 - daemon disconnect */
	if ((vscan_drv_state != VS_DRV_CONNECTED) &&
	    (vscan_drv_state != VS_DRV_ENABLED)) {
		DTRACE_PROBE1(vscan__drv__state__violation,
		    int, vscan_drv_state);
		mutex_exit(&vscan_drv_mutex);
		return (EINVAL);
	}

	for (i = 1; i <= vs_nodes_max; i++) {
		if (vscan_drv_inst_state[i] != VS_DRV_INST_UNCONFIG)
			vscan_drv_inst_state[i] = VS_DRV_INST_INIT;
	}

	if (vscan_drv_state == VS_DRV_CONNECTED) {
		vscan_drv_state = VS_DRV_IDLE;
	} else { /* VS_DRV_ENABLED */
		cmn_err(CE_WARN, "Detected vscand exit without clean shutdown");
		if (thread_create(NULL, 0, vscan_drv_delayed_disable,
		    0, 0, &p0, TS_RUN, minclsyspri) == NULL) {
			vscan_svc_disable();
			vscan_drv_state = VS_DRV_IDLE;
		} else {
			vscan_drv_state = VS_DRV_DELAYED_DISABLE;
		}
	}
	mutex_exit(&vscan_drv_mutex);

	vscan_svc_scan_abort();
	vscan_door_close();
	return (0);
}


/*
 * vscan_drv_delayed_disable
 *
 * Invoked from vscan_drv_close if the daemon disconnects
 * without first sending disable (e.g. daemon crashed).
 * Delays for vs_reconnect_timeout before disabling, to allow
 * the daemon to reconnect. During this time, scan requests
 * will be processed locally (see vscan_svc.c)
 */
static void
vscan_drv_delayed_disable(void)
{
	clock_t timeout = lbolt + SEC_TO_TICK(vs_reconnect_timeout);

	mutex_enter(&vscan_drv_mutex);
	(void) cv_timedwait(&vscan_drv_cv, &vscan_drv_mutex, timeout);

	if (vscan_drv_state == VS_DRV_DELAYED_DISABLE) {
		vscan_svc_disable();
		vscan_drv_state = VS_DRV_IDLE;
	} else {
		DTRACE_PROBE(vscan__reconnect);
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

	if ((inst <= 0) || (inst > vs_nodes_max))
		return (EINVAL);

	mutex_enter(&vscan_drv_mutex);
	if ((vscan_drv_state != VS_DRV_ENABLED) ||
	    (vscan_drv_inst_state[inst] != VS_DRV_INST_OPEN)) {
		mutex_exit(&vscan_drv_mutex);
		return (EINVAL);
	}
	vscan_drv_inst_state[inst] = VS_DRV_INST_READING;
	mutex_exit(&vscan_drv_mutex);

	if ((vp = vscan_svc_get_vnode(inst)) == NULL)
		return (EINVAL);

	(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, NULL);
	rc = VOP_READ(vp, uiop, 0, kcred, NULL);
	VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);

	mutex_enter(&vscan_drv_mutex);
	if (vscan_drv_inst_state[inst] == VS_DRV_INST_READING)
		vscan_drv_inst_state[inst] = VS_DRV_INST_OPEN;
	mutex_exit(&vscan_drv_mutex);

	return (rc);
}


/*
 * vscan_drv_ioctl
 *
 * Process ioctls from vscand:
 * VS_IOCTL_ENABLE - vscand is ready to handle scan requests,
 *    enable VFS interface.
 * VS_IOCTL_DISABLE - vscand is shutting down, disable VFS interface
 * VS_IOCTL_RESULT - scan response data
 * VS_IOCTL_CONFIG - configuration data from vscand
 * VS_IOCTL_MAX_REQ - provide the max request idx to vscand,
 *    to allow vscand to set appropriate resource allocation limits
 */
/* ARGSUSED */
static int
vscan_drv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
	cred_t *credp, int *rvalp)
{
	int inst = getminor(dev);
	vs_config_t conf;
	vs_scan_rsp_t rsp;

	if (inst != 0)
		return (EINVAL);

	switch (cmd) {
	case VS_IOCTL_ENABLE:
		mutex_enter(&vscan_drv_mutex);
		if (vscan_drv_state != VS_DRV_CONNECTED) {
			DTRACE_PROBE1(vscan__drv__state__violation,
			    int, vscan_drv_state);
			mutex_exit(&vscan_drv_mutex);
			return (EINVAL);
		}
		if ((vscan_door_open((int)arg) != 0) ||
		    (vscan_svc_enable() != 0)) {
			mutex_exit(&vscan_drv_mutex);
			return (EINVAL);
		}
		vscan_drv_state = VS_DRV_ENABLED;
		mutex_exit(&vscan_drv_mutex);
		break;

	case VS_IOCTL_DISABLE:
		mutex_enter(&vscan_drv_mutex);
		if (vscan_drv_state != VS_DRV_ENABLED) {
			DTRACE_PROBE1(vscan__drv__state__violation,
			    int, vscan_drv_state);
			mutex_exit(&vscan_drv_mutex);
			return (EINVAL);
		}
		vscan_svc_disable();
		vscan_drv_state = VS_DRV_CONNECTED;
		mutex_exit(&vscan_drv_mutex);
		break;

	case VS_IOCTL_RESULT:
		if (ddi_copyin((void *)arg, &rsp,
		    sizeof (vs_scan_rsp_t), 0) == -1)
			return (EFAULT);
		else
			vscan_svc_scan_result(&rsp);
		break;

	case VS_IOCTL_CONFIG:
		if (ddi_copyin((void *)arg, &conf,
		    sizeof (vs_config_t), 0) == -1)
			return (EFAULT);
		if (vscan_svc_configure(&conf) == -1)
			return (EINVAL);
		break;

	case VS_IOCTL_MAX_REQ:
		if (ddi_copyout(&vs_nodes_max, (void *)arg,
		    sizeof (uint32_t), 0) == -1)
			return (EFAULT);
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
	char name[VS_NODENAME_LEN];
	boolean_t rc = B_TRUE;

	mutex_enter(&vscan_drv_mutex);

	if (vscan_drv_inst_state[idx] == VS_DRV_INST_UNCONFIG) {
		(void) snprintf(name, VS_NODENAME_LEN, "vscan%d", idx);
		if (ddi_create_minor_node(vscan_drv_dip, name,
		    S_IFCHR, idx, DDI_PSEUDO, 0) == DDI_SUCCESS) {
			vscan_drv_inst_state[idx] = VS_DRV_INST_INIT;
		} else {
			rc = B_FALSE;
		}
		DTRACE_PROBE2(vscan__minor__node, int, idx, int, rc);
	}

	mutex_exit(&vscan_drv_mutex);

	return (rc);
}
