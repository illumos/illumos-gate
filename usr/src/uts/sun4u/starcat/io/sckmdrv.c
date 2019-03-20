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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Starcat IPSec Key Management Driver.
 *
 * This driver runs on a Starcat Domain. It processes requests received
 * from the System Controller (SC) from IOSRAM, passes these requests
 * to the sckmd daemon by means of an open/close/ioctl interface, and
 * sends corresponding status information back to the SC.
 *
 * Requests received from the SC consist of IPsec security associations
 * (SAs) needed to secure the communication between SC and Domain daemons
 * communicating using the Management Network (MAN).
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/modctl.h>
#include <sys/disp.h>
#include <sys/async.h>
#include <sys/mboxsc.h>
#include <sys/sckm_msg.h>
#include <sys/sckm_io.h>
#include <sys/taskq.h>
#include <sys/note.h>

#ifdef DEBUG
static uint_t sckm_debug_flags = 0x0;
#define	SCKM_DEBUG0(f, s) if ((f)& sckm_debug_flags) \
	cmn_err(CE_CONT, s)
#define	SCKM_DEBUG1(f, s, a) if ((f)& sckm_debug_flags) \
	cmn_err(CE_CONT, s, a)
#define	SCKM_DEBUG2(f, s, a, b) if ((f)& sckm_debug_flags) \
	cmn_err(CE_CONT, s, a, b)
#define	SCKM_DEBUG3(f, s, a, b, c) if ((f)& sckm_debug_flags) \
	cmn_err(CE_CONT, s, a, b, c)
#define	SCKM_DEBUG4(f, s, a, b, c, d) if ((f)& sckm_debug_flags) \
	cmn_err(CE_CONT, s, a, b, c, d)
#define	SCKM_DEBUG5(f, s, a, b, c, d, e) if ((f)& sckm_debug_flags) \
	cmn_err(CE_CONT, s, a, b, c, d, e)
#define	SCKM_DEBUG6(f, s, a, b, c, d, e, ff) if ((f)& sckm_debug_flags) \
	cmn_err(CE_CONT, s, a, b, c, d, e, ff)
#else
#define	SCKM_DEBUG0(f, s)
#define	SCKM_DEBUG1(f, s, a)
#define	SCKM_DEBUG2(f, s, a, b)
#define	SCKM_DEBUG3(f, s, a, b, c)
#define	SCKM_DEBUG4(f, s, a, b, c, d)
#define	SCKM_DEBUG5(f, s, a, b, c, d, e)
#define	SCKM_DEBUG6(f, s, a, b, c, d, e, ff)
#endif /* DEBUG */

#define	D_INIT		0x00000001	/* _init/_fini/_info */
#define	D_ATTACH	0x00000002	/* attach/detach */
#define	D_OPEN		0x00000008	/* open/close */
#define	D_IOCTL		0x00010000	/* ioctl */
#define	D_TASK		0x00100000	/* mailbox task processing */
#define	D_CALLBACK	0x00200000	/* mailbox callback */

static int sckm_open(dev_t *, int, int, struct cred *);
static int sckm_close(dev_t, int, int, struct cred *);
static int sckm_ioctl(dev_t, int, intptr_t, int, struct cred *, int *);

static struct cb_ops sckm_cb_ops = {
	sckm_open,		/* open */
	sckm_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	sckm_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static int sckm_attach(dev_info_t *, ddi_attach_cmd_t);
static int sckm_detach(dev_info_t *, ddi_detach_cmd_t);
static int sckm_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

static struct dev_ops sckm_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	sckm_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sckm_attach,		/* attach */
	sckm_detach,		/* detach */
	nodev,			/* reset */
	&sckm_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* no bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Key Management Driver",
	&sckm_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * Private definitions.
 */
#define	SCKM_DEF_GETMSG_TIMEOUT 60	/* in seconds */
#define	SCKM_DAEMON_TIMEOUT	4000000	/* in microseconds */
#define	SCKM_NUM_TASKQ		2	/* # of task queue entries */

/*
 * For processing mailbox layer events.
 */
static kmutex_t sckm_task_mutex;
static kmutex_t sckm_taskq_ptr_mutex;
static clock_t sckm_getmsg_timeout = SCKM_DEF_GETMSG_TIMEOUT*1000;
static taskq_t *sckm_taskq = NULL;
static sckm_mbox_req_hdr_t *req_data = NULL;
static sckm_mbox_rep_hdr_t *rep_data = NULL;


/*
 * For synchronization with key management daemon.
 */
static kmutex_t sckm_umutex;
static kcondvar_t sckm_udata_cv;	/* daemon waits on data */
static kcondvar_t sckm_cons_cv;		/* wait for daemon to consume data */
static boolean_t sckm_udata_req = B_FALSE; /* data available for daemon */
static sckm_ioctl_getreq_t sckm_udata;	/* request for daemon */
static sckm_ioctl_status_t sckm_udata_status; /* status from daemon */

/*
 * Other misc private variables.
 */
static dev_info_t *sckm_devi = NULL;
static boolean_t sckm_oflag = B_FALSE;

/*
 * Private functions prototypes.
 */
static void sckm_mbox_callback(void);
static void sckm_mbox_task(void *arg);
static void sckm_process_msg(uint32_t cmd, uint64_t transid,
    uint32_t len, sckm_mbox_req_hdr_t *req_data,
    sckm_mbox_rep_hdr_t *rep_data);


int
_init(void)
{
	mboxsc_timeout_range_t timeout_range;
	int ret;

	SCKM_DEBUG0(D_INIT, "in _init");

	/*
	 * Initialize outgoing mailbox (KDSC)
	 */
	if ((ret = mboxsc_init(KEY_KDSC, MBOXSC_MBOX_OUT, NULL)) != 0) {
		cmn_err(CE_WARN, "failed initializing outgoing mailbox "
		    "(%d)", ret);
		return (ret);
	}

	/*
	 * Initialize incoming mailbox (SCKD)
	 */
	if ((ret = mboxsc_init(KEY_SCKD, MBOXSC_MBOX_IN,
	    sckm_mbox_callback)) != 0) {
		cmn_err(CE_WARN, "failed initializing incoming mailbox "
		    "(%d)\n", ret);
		(void) mboxsc_fini(KEY_KDSC);
		return (ret);
	}

	if ((ret = mboxsc_ctrl(KEY_SCKD, MBOXSC_CMD_GETMSG_TIMEOUT_RANGE,
	    (void *)&timeout_range)) != 0) {
		(void) mboxsc_fini(KEY_SCKD);
		(void) mboxsc_fini(KEY_KDSC);
		return (ret);
	}

	if (sckm_getmsg_timeout < timeout_range.min_timeout) {
		sckm_getmsg_timeout = timeout_range.min_timeout;
		cmn_err(CE_WARN, "resetting getmsg timeout to %lx",
		    sckm_getmsg_timeout);
	}

	if (sckm_getmsg_timeout > timeout_range.max_timeout) {
		sckm_getmsg_timeout = timeout_range.max_timeout;
		cmn_err(CE_WARN, "resetting getmsg timeout to %lx",
		    sckm_getmsg_timeout);
	}

	if ((ret = mod_install(&modlinkage)) != 0) {
		(void) mboxsc_fini(KEY_KDSC);
		(void) mboxsc_fini(KEY_SCKD);
		return (ret);
	}

	/*
	 * Initialize variables needed for synchronization with daemon.
	 */
	sckm_udata.buf = kmem_alloc(SCKM_SCKD_MAXDATA, KM_SLEEP);
	req_data = (sckm_mbox_req_hdr_t *)kmem_alloc(SCKM_SCKD_MAXDATA,
	    KM_SLEEP);
	rep_data = (sckm_mbox_rep_hdr_t *)kmem_alloc(SCKM_KDSC_MAXDATA,
	    KM_SLEEP);

	if ((sckm_udata.buf == NULL) || (req_data == NULL) ||
	    (rep_data == NULL)) {
		cmn_err(CE_WARN, "not enough memory during _init");

		/* free what was successfully allocated */
		if (sckm_udata.buf != NULL)
			kmem_free(sckm_udata.buf, SCKM_SCKD_MAXDATA);
		if (req_data != NULL)
			kmem_free(req_data, SCKM_SCKD_MAXDATA);
		if (rep_data != NULL)
			kmem_free(rep_data, SCKM_KDSC_MAXDATA);
		sckm_udata.buf = NULL;
		req_data = NULL;
		rep_data = NULL;

		/* uninitialize mailboxes, remove module, and return error */
		(void) mboxsc_fini(KEY_KDSC);
		(void) mboxsc_fini(KEY_SCKD);
		(void) mod_remove(&modlinkage);
		return (-1);
	}

	cv_init(&sckm_udata_cv, NULL, CV_DRIVER, NULL);
	cv_init(&sckm_cons_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&sckm_umutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Create mutex for task processing, protection of taskq
	 * pointer, and create taskq.
	 */
	mutex_init(&sckm_task_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&sckm_taskq_ptr_mutex, NULL, MUTEX_DRIVER, NULL);
	sckm_taskq = taskq_create("sckm_taskq", 1, minclsyspri,
	    SCKM_NUM_TASKQ, SCKM_NUM_TASKQ, TASKQ_PREPOPULATE);

	SCKM_DEBUG1(D_INIT, "out _init ret=%d\n", ret);
	return (ret);
}

int
_fini(void)
{
	int ret;

	SCKM_DEBUG0(D_INIT, "in _fini");

	if ((ret = mod_remove(&modlinkage)) != 0) {
		return (ret);
	}

	/*
	 * Wait for scheduled tasks to complete, then destroy task queue.
	 */
	mutex_enter(&sckm_taskq_ptr_mutex);
	if (sckm_taskq != NULL) {
		taskq_destroy(sckm_taskq);
		sckm_taskq = NULL;
	}
	mutex_exit(&sckm_taskq_ptr_mutex);

	/*
	 * Terminate incoming and outgoing IOSRAM mailboxes
	 */
	(void) mboxsc_fini(KEY_KDSC);
	(void) mboxsc_fini(KEY_SCKD);

	/*
	 * Destroy module synchronization objects and free memory
	 */
	mutex_destroy(&sckm_task_mutex);
	mutex_destroy(&sckm_taskq_ptr_mutex);
	mutex_destroy(&sckm_umutex);
	cv_destroy(&sckm_cons_cv);

	if (sckm_udata.buf != NULL) {
		kmem_free(sckm_udata.buf, SCKM_SCKD_MAXDATA);
		sckm_udata.buf = NULL;
	}
	if (rep_data != NULL) {
		kmem_free(rep_data, SCKM_KDSC_MAXDATA);
		rep_data = NULL;
	}
	if (req_data != NULL) {
		kmem_free(req_data, SCKM_SCKD_MAXDATA);
		req_data = NULL;
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	SCKM_DEBUG0(D_INIT, "in _info");
	return (mod_info(&modlinkage, modinfop));
}

static int
sckm_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	SCKM_DEBUG1(D_ATTACH, "in sckm_attach, cmd=%d", cmd);

	switch (cmd) {
	case DDI_ATTACH:
		SCKM_DEBUG0(D_ATTACH, "sckm_attach: DDI_ATTACH");
		if (ddi_create_minor_node(devi, "sckmdrv", S_IFCHR,
		    0, NULL, NULL) == DDI_FAILURE) {
			cmn_err(CE_WARN, "ddi_create_minor_node failed");
			ddi_remove_minor_node(devi, NULL);
			return (DDI_FAILURE);
		}
		sckm_devi = devi;
		break;
	case DDI_SUSPEND:
		SCKM_DEBUG0(D_ATTACH, "sckm_attach: DDI_SUSPEND");
		break;
	default:
		cmn_err(CE_WARN, "sckm_attach: bad cmd %d\n", cmd);
		return (DDI_FAILURE);
	}

	SCKM_DEBUG0(D_ATTACH, "out sckm_attach (DDI_SUCCESS)");
	return (DDI_SUCCESS);
}

static int
sckm_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	SCKM_DEBUG1(D_ATTACH, "in sckm_detach, cmd=%d", cmd);

	switch (cmd) {
	case DDI_DETACH:
		SCKM_DEBUG0(D_ATTACH, "sckm_detach: DDI_DETACH");
		ddi_remove_minor_node(devi, NULL);
		break;
	case DDI_SUSPEND:
		SCKM_DEBUG0(D_ATTACH, "sckm_detach: DDI_DETACH");
		break;
	default:
		cmn_err(CE_WARN, "sckm_detach: bad cmd %d\n", cmd);
		return (DDI_FAILURE);
	}

	SCKM_DEBUG0(D_ATTACH, "out sckm_detach (DDI_SUCCESS)");
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
sckm_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int rv;

	SCKM_DEBUG1(D_ATTACH, "in sckm_info, infocmd=%d", infocmd);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)sckm_devi;
		rv = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		rv = DDI_SUCCESS;
		break;
	default:
		rv = DDI_FAILURE;
	}

	SCKM_DEBUG1(D_ATTACH, "out sckm_info, rv=%d", rv);
	return (rv);
}

/*ARGSUSED*/
static int
sckm_open(dev_t *devp, int flag, int otyp, struct cred *cred)
{
	SCKM_DEBUG0(D_OPEN, "in sckm_open");

	/* check credentials of calling process */
	if (drv_priv(cred)) {
		SCKM_DEBUG0(D_OPEN, "sckm_open: attempt by non-root proc");
		return (EPERM);
	}

	/* enforce exclusive access */
	mutex_enter(&sckm_umutex);
	if (sckm_oflag == B_TRUE) {
		SCKM_DEBUG0(D_OPEN, "sckm_open: already open");
		mutex_exit(&sckm_umutex);
		return (EBUSY);
	}
	sckm_oflag = B_TRUE;
	mutex_exit(&sckm_umutex);

	SCKM_DEBUG0(D_OPEN, "sckm_open: succcess");
	return (0);
}

/*ARGSUSED*/
static int
sckm_close(dev_t dev, int flag, int otyp, struct cred *cred)
{
	SCKM_DEBUG0(D_OPEN, "in sckm_close");

	mutex_enter(&sckm_umutex);
	sckm_oflag = B_FALSE;
	mutex_exit(&sckm_umutex);

	return (0);
}


static int
sckm_copyin_ioctl_getreq(intptr_t userarg, sckm_ioctl_getreq_t *driverarg,
    int flag)
{
#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		sckm_ioctl_getreq32_t driverarg32;
		if (ddi_copyin((caddr_t)userarg, &driverarg32,
		    sizeof (sckm_ioctl_getreq32_t), flag)) {
			return (EFAULT);
		}
		driverarg->transid = driverarg32.transid;
		driverarg->type = driverarg32.type;
		driverarg->buf = (caddr_t)(uintptr_t)driverarg32.buf;
		driverarg->buf_len = driverarg32.buf_len;
		break;
	}
	case DDI_MODEL_NONE: {
		if (ddi_copyin((caddr_t)userarg, &driverarg,
		    sizeof (sckm_ioctl_getreq_t), flag)) {
			return (EFAULT);
		}
		break;
	}
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin((caddr_t)userarg, &driverarg,
	    sizeof (sckm_ioctl_getreq_t), flag)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */
	return (0);
}


static int
sckm_copyout_ioctl_getreq(sckm_ioctl_getreq_t *driverarg, intptr_t userarg,
    int flag)
{
#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		sckm_ioctl_getreq32_t driverarg32;
		driverarg32.transid = driverarg->transid;
		driverarg32.type = driverarg->type;
		driverarg32.buf = (caddr32_t)(uintptr_t)driverarg->buf;
		driverarg32.buf_len = driverarg->buf_len;
		if (ddi_copyout(&driverarg32, (caddr_t)userarg,
		    sizeof (sckm_ioctl_getreq32_t), flag)) {
			return (EFAULT);
		}
		break;
	}
	case DDI_MODEL_NONE:
		if (ddi_copyout(driverarg, (caddr_t)userarg,
		    sizeof (sckm_ioctl_getreq_t), flag)) {
			return (EFAULT);
		}
		break;
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyout(driverarg, (caddr_t)userarg,
	    sizeof (sckm_ioctl_getreq_t), flag)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */
	return (0);
}


/*ARGSUSED*/
static int
sckm_ioctl(dev_t dev, int cmd, intptr_t data, int flag,
    cred_t *cred, int *rvalp)
{
	int rval = 0;

	SCKM_DEBUG0(D_IOCTL, "in sckm_ioctl");

	switch (cmd) {
	case SCKM_IOCTL_GETREQ: {
		sckm_ioctl_getreq_t arg;

		SCKM_DEBUG0(D_IOCTL, "sckm_ioctl: got SCKM_IOCTL_GETREQ");
		if (sckm_copyin_ioctl_getreq(data, &arg, flag)) {
			return (EFAULT);
		}

		/* sanity check argument */
		if (arg.buf_len < SCKM_SCKD_MAXDATA) {
			SCKM_DEBUG2(D_IOCTL, "sckm_ioctl: usr buffer too "
			    "small (%d < %d)", arg.buf_len, SCKM_SCKD_MAXDATA);
			return (ENOSPC);
		}

		mutex_enter(&sckm_umutex);

		/* wait for request from SC */
		while (!sckm_udata_req) {
			SCKM_DEBUG0(D_IOCTL, "sckm_ioctl: waiting for msg");
			if (cv_wait_sig(&sckm_udata_cv, &sckm_umutex) == 0) {
				mutex_exit(&sckm_umutex);
				return (EINTR);
			}
		}
		SCKM_DEBUG1(D_IOCTL, "sckm_ioctl: msg available "
		    "transid = 0x%lx", sckm_udata.transid);

		arg.transid = sckm_udata.transid;
		arg.type = sckm_udata.type;
		if (ddi_copyout(sckm_udata.buf, arg.buf,
		    sckm_udata.buf_len, flag)) {
			mutex_exit(&sckm_umutex);
			return (EFAULT);
		}
		arg.buf_len = sckm_udata.buf_len;

		mutex_exit(&sckm_umutex);
		if (sckm_copyout_ioctl_getreq(&arg, data, flag)) {
			return (EFAULT);
		}
		break;
	}
	case SCKM_IOCTL_STATUS: {
		sckm_ioctl_status_t arg;
		SCKM_DEBUG0(D_IOCTL, "sckm_ioctl: got SCKM_IOCTL_STATUS");
		if (ddi_copyin((caddr_t)data, &arg,
		    sizeof (sckm_ioctl_status_t), flag)) {
			cmn_err(CE_WARN, "sckm_ioctl: ddi_copyin failed");
			return (EFAULT);
		}
		SCKM_DEBUG3(D_IOCTL, "sckm_ioctl: arg transid=0x%lx, "
		    "status=%d, sadb_msg_errno=%d", arg.transid, arg.status,
		    arg.sadb_msg_errno);

		mutex_enter(&sckm_umutex);

		/* fail if no status is expected, or if it does not match */
		if (!sckm_udata_req || sckm_udata.transid != arg.transid) {
			mutex_exit(&sckm_umutex);
			return (EINVAL);
		}

		/* update status information for event handler */
		bcopy(&arg, &sckm_udata_status, sizeof (sckm_ioctl_status_t));

		/* signal event handler that request has been processed */
		SCKM_DEBUG0(D_IOCTL, "sckm_ioctl: signaling event handler"
		    " that data has been processed");
		cv_signal(&sckm_cons_cv);
		sckm_udata_req = B_FALSE;

		mutex_exit(&sckm_umutex);
		break;
	}
	default:
		SCKM_DEBUG0(D_IOCTL, "sckm_ioctl: unknown command");
		rval = EINVAL;
	}

	SCKM_DEBUG1(D_IOCTL, "out sckm_ioctl, rval=%d", rval);
	return (rval);
}


/*
 * sckm_mbox_callback
 *
 * Callback routine registered with the IOSRAM mailbox protocol driver.
 * Invoked when a message is received on the mailbox.
 */
static void
sckm_mbox_callback(void)
{
	SCKM_DEBUG0(D_CALLBACK, "in sckm_mbox_callback()");

	mutex_enter(&sckm_taskq_ptr_mutex);

	if (sckm_taskq == NULL) {
		mutex_exit(&sckm_taskq_ptr_mutex);
		return;
	}

	if (taskq_dispatch(sckm_taskq, sckm_mbox_task, NULL, KM_NOSLEEP) ==
	    TASKQID_INVALID) {
		/*
		 * Too many tasks already pending. Do not queue a new
		 * request.
		 */
		SCKM_DEBUG0(D_CALLBACK, "failed dispatching task");
	}

	mutex_exit(&sckm_taskq_ptr_mutex);

	SCKM_DEBUG0(D_CALLBACK, "out sckm_mbox_callback()");
}


/*
 * sckm_mbox_task
 *
 * Dispatched on taskq from the IOSRAM mailbox callback
 * sckm_mbox_callback when a message is received on the incoming
 * mailbox.
 */
static void
sckm_mbox_task(void *ignored)
{
        _NOTE(ARGUNUSED(ignored))
	uint32_t type, cmd, length;
	uint64_t transid;
	int rval;

	SCKM_DEBUG0(D_TASK, "in sckm_mbox_task\n");

	mutex_enter(&sckm_task_mutex);

	if (req_data == NULL || rep_data == NULL) {
		SCKM_DEBUG0(D_TASK, "sckm_mbox_task: no buffers");
		mutex_exit(&sckm_task_mutex);
		return;
	}

	/*
	 * Get mailbox message.
	 */

	type = MBOXSC_MSG_REQUEST;
	length = SCKM_SCKD_MAXDATA;
	cmd = 0;
	transid = 0;

	SCKM_DEBUG0(D_TASK, "sckm_mbox_task: "
	    "calling mboxsc_getmsg()\n");
	rval = mboxsc_getmsg(KEY_SCKD, &type, &cmd, &transid,
	    &length, req_data, sckm_getmsg_timeout);

	if (rval != 0) {
		SCKM_DEBUG1(D_TASK, "sckm_mbox_task: "
		    "mboxsc_getmsg() failed (%d)\n", rval);
		mutex_exit(&sckm_task_mutex);
		return;
	}

	SCKM_DEBUG4(D_TASK, "sckm_mbox_task: "
	    "type=0x%x cmd=0x%x length=%d transid=0x%lx\n",
	    type, cmd, length, transid);

	/* check message length */
	if (length < sizeof (sckm_mbox_req_hdr_t)) {
		/* protocol error, drop message */
		SCKM_DEBUG2(D_TASK, "received short "
		    "message of length %d, min %lu",
		    length, sizeof (sckm_mbox_req_hdr_t));
		mutex_exit(&sckm_task_mutex);
		return;
	}

	/* check version of message received */
	if (req_data->sckm_version != SCKM_PROTOCOL_VERSION) {
		SCKM_DEBUG2(D_TASK, "received protocol "
		    "version %d, expected %d",
		    req_data->sckm_version, SCKM_PROTOCOL_VERSION);
		/*
		 * Send reply with SCKM_SADB_ERR_VERSION error
		 * so that SC can adopt correct protocol version
		 * for this domain.
		 */
		rep_data->sckm_version = SCKM_PROTOCOL_VERSION;
		rep_data->status = SCKM_ERR_VERSION;

		rval = mboxsc_putmsg(KEY_KDSC, MBOXSC_MSG_REPLY,
		    cmd, &transid, sizeof (sckm_mbox_rep_hdr_t),
		    rep_data, MBOXSC_PUTMSG_DEF_TIMEOUT);

		if (rval != 0) {
			SCKM_DEBUG1(D_TASK, "sckm_mbox_task: "
			    "mboxsc_putmsg() failed (%d)\n", rval);
			mutex_exit(&sckm_task_mutex);
			return;
		}
	}

	/* process message */
	sckm_process_msg(cmd, transid, length,
	    req_data, rep_data);

	mutex_exit(&sckm_task_mutex);
}

/*
 * sckm_process_msg
 *
 * Process a message received from the SC. Invoked by sckm_event_task().
 */
static void
sckm_process_msg(uint32_t cmd, uint64_t transid,
    uint32_t len, sckm_mbox_req_hdr_t *req_data,
    sckm_mbox_rep_hdr_t *rep_data)
{
	int rv;

	mutex_enter(&sckm_umutex);

	switch (cmd) {
	case SCKM_MSG_SADB: {
		int sadb_msglen;

		sadb_msglen = len-sizeof (sckm_mbox_req_hdr_t);
		SCKM_DEBUG1(D_TASK, "received SCKM_MSG_SADB len=%d",
		    sadb_msglen);

		/* sanity check request */
		if (len-sizeof (sckm_mbox_req_hdr_t) <= 0) {
			SCKM_DEBUG0(D_TASK, "bad SADB message, "
			    "zero length");
			/*
			 * SADB message is too short, send corresponding
			 * error message to SC.
			 */
			rep_data->sckm_version = SCKM_PROTOCOL_VERSION;
			rep_data->status = SCKM_ERR_SADB_MSG;

			if ((rv = mboxsc_putmsg(KEY_KDSC, MBOXSC_MSG_REPLY,
			    cmd, &transid, sizeof (sckm_mbox_rep_hdr_t),
			    rep_data, MBOXSC_PUTMSG_DEF_TIMEOUT)) != 0) {
				SCKM_DEBUG1(D_TASK, "sckm_mbox_task: "
				    "mboxsc_putmsg() failed (%d)\n", rv);
			}
			mutex_exit(&sckm_umutex);
			return;
		}

		/* initialize request for daemon */
		sckm_udata.transid = transid;
		sckm_udata.type = SCKM_IOCTL_REQ_SADB;
		sckm_udata.buf_len = len-sizeof (sckm_mbox_req_hdr_t);
		bcopy(req_data+1, sckm_udata.buf, sckm_udata.buf_len);

		break;
	}
	default:
		cmn_err(CE_WARN, "unknown cmd %x received from SC", cmd);
		/*
		 * Received unknown command from SC. Send corresponding
		 * error message to SC.
		 */
		rep_data->sckm_version = SCKM_PROTOCOL_VERSION;
		rep_data->status = SCKM_ERR_BAD_CMD;

		if ((rv = mboxsc_putmsg(KEY_KDSC, MBOXSC_MSG_REPLY,
		    cmd, &transid, sizeof (sckm_mbox_rep_hdr_t),
		    rep_data, MBOXSC_PUTMSG_DEF_TIMEOUT)) != 0) {
			SCKM_DEBUG1(D_TASK, "sckm_mbox_task: "
			    "mboxsc_putmsg() failed (%d)\n", rv);
		}
		mutex_exit(&sckm_umutex);
		return;
	}

	/*
	 * At this point, we know that the request is valid, so pass
	 * the request to the daemon.
	 */
	SCKM_DEBUG0(D_TASK, "waking up daemon");
	sckm_udata_req = B_TRUE;
	cv_signal(&sckm_udata_cv);

	/* wait for daemon to process request */
	if (cv_reltimedwait(&sckm_cons_cv, &sckm_umutex,
	    drv_usectohz(SCKM_DAEMON_TIMEOUT), TR_CLOCK_TICK) == -1) {
		/*
		 * Daemon did not process the data, report this
		 * error to the SC.
		 */
		SCKM_DEBUG0(D_TASK, "daemon timeout!!");
		rep_data->sckm_version = SCKM_PROTOCOL_VERSION;
		rep_data->status = SCKM_ERR_DAEMON;
	} else {
		/* Daemon processed data, return status to SC */
		SCKM_DEBUG0(D_TASK, "daemon processed data");
		rep_data->sckm_version = SCKM_PROTOCOL_VERSION;
		switch (sckm_udata_status.status) {
		case SCKM_IOCTL_STAT_SUCCESS:
			SCKM_DEBUG0(D_TASK, "daemon returned success");
			rep_data->status = SCKM_SUCCESS;
			break;
		case SCKM_IOCTL_STAT_ERR_PFKEY:
			SCKM_DEBUG1(D_TASK, "daemon returned PF_KEY "
			    "error, errno=%d",
			    sckm_udata_status.sadb_msg_errno);
			rep_data->status = SCKM_ERR_SADB_PFKEY;
			rep_data->sadb_msg_errno =
			    sckm_udata_status.sadb_msg_errno;
			break;
		case SCKM_IOCTL_STAT_ERR_REQ:
			SCKM_DEBUG0(D_TASK, "daemon returned "
			    "bad request");
			rep_data->status = SCKM_ERR_DAEMON;
			break;
		case SCKM_IOCTL_STAT_ERR_VERSION:
			SCKM_DEBUG0(D_TASK, "PF_KEY version not "
			    "supported");
			rep_data->status = SCKM_ERR_SADB_VERSION;
			rep_data->sadb_msg_version =
			    sckm_udata_status.sadb_msg_version;
			break;
		case SCKM_IOCTL_STAT_ERR_TIMEOUT:
			SCKM_DEBUG0(D_TASK, "no response received "
			    "from key engine");
			rep_data->status = SCKM_ERR_SADB_TIMEOUT;
			break;
		case SCKM_IOCTL_STAT_ERR_OTHER:
			SCKM_DEBUG0(D_TASK, "daemon encountered "
			    "an error");
			rep_data->status = SCKM_ERR_DAEMON;
			break;
		case SCKM_IOCTL_STAT_ERR_SADB_TYPE:
			SCKM_DEBUG0(D_TASK, "daemon returned bad "
			    "SADB message type");
			rep_data->status = SCKM_ERR_SADB_BAD_TYPE;
			break;
		default:
			cmn_err(CE_WARN, "SCKM daemon returned "
			    "invalid status %d", sckm_udata_status.status);
			rep_data->status = SCKM_ERR_DAEMON;
		}
	}

	/* send reply back to SC */
	if ((rv = mboxsc_putmsg(KEY_KDSC, MBOXSC_MSG_REPLY,
	    cmd, &transid, sizeof (sckm_mbox_rep_hdr_t),
	    rep_data, MBOXSC_PUTMSG_DEF_TIMEOUT)) != 0) {
		SCKM_DEBUG1(D_TASK, "failed sending reply to SC (%d)", rv);
	} else {
		SCKM_DEBUG0(D_TASK, "reply sent to SC");
	}

	sckm_udata_req = B_FALSE;
	mutex_exit(&sckm_umutex);
}
