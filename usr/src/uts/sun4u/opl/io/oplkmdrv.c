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
 * OPL IPSec Key Management Driver.
 *
 * This driver runs on a OPL Domain. It processes requests received
 * from the OPL Service Processor (SP) via mailbox message. It passes
 * these requests to the sckmd daemon by means of an /ioctl interface.
 *
 * Requests received from the SP consist of IPsec security associations
 * (SAs) needed to secure the communication between SC and Domain daemons
 * communicating using DSCP.
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
#include <sys/note.h>
#include <sys/byteorder.h>
#include <sys/sdt.h>

#include <sys/scfd/scfdscpif.h>
#include <sys/oplkm_msg.h>
#include <sys/sckm_io.h>
#include <sys/oplkm.h>

#define	OKM_NODENAME	"oplkmdrv"		/* Node name */
#define	OKM_TARGET_ID	0			/* Target ID */
#define	OKM_SM_TOUT	5000			/* small timeout (5msec) */
#define	OKM_LG_TOUT	50000			/* large timeout (50msec) */
#define	OKM_MB_TOUT	10000000		/* Mailbox timeout (10sec) */

okms_t okms_global;				/* Global instance structure */

#ifdef DEBUG
uint32_t okm_debug = DBG_WARN;
#endif

/*
 * Prototypes for the module related functions.
 */
int okm_attach(dev_info_t *devi, ddi_attach_cmd_t cmd);
int okm_detach(dev_info_t *devi, ddi_detach_cmd_t cmd);
int okm_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result);
int okm_open(dev_t *devp, int flag, int otyp, struct cred *cred);
int okm_close(dev_t dev, int flag, int otyp, struct cred *cred);
int okm_ioctl(dev_t dev, int cmd, intptr_t data, int flag,
		cred_t *cred, int *rvalp);

/*
 * Prototypes for the internal functions.
 */
int okm_get_req(okms_t *okmsp, sckm_ioctl_getreq_t *ireqp,
    intptr_t data, int flag);
int okm_process_req(okms_t *okmsp, okm_req_hdr_t *reqp, uint32_t len,
    sckm_ioctl_getreq_t *ireqp, intptr_t data, int flag);
int okm_process_status(okms_t *okmsp, sckm_ioctl_status_t *ireply);
void okm_event_handler(scf_event_t event, void *arg);
int okm_send_reply(okms_t *okmsp, uint32_t transid, uint32_t status,
    uint32_t sadb_err, uint32_t sadb_ver);
int block_until_ready(okms_t *okmsp);
static int okm_copyin_ioctl_getreq(intptr_t userarg,
    sckm_ioctl_getreq_t *driverarg, int flag);
static int okm_copyout_ioctl_getreq(sckm_ioctl_getreq_t *driverarg,
    intptr_t userarg, int flag);
static void okm_cleanup(okms_t *okmsp);
static int okm_mbox_init(okms_t *okmsp);
static void okm_mbox_fini(okms_t *okmsp);
static clock_t okm_timeout_val(int error);


struct cb_ops okm_cb_ops = {
	okm_open,		/* open */
	okm_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	okm_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

struct dev_ops okm_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	okm_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	okm_attach,		/* attach */
	okm_detach,		/* detach */
	nodev,			/* reset */
	&okm_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* no bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

struct modldrv modldrv = {
	&mod_driverops,
	"OPL Key Management Driver",
	&okm_ops,
};

struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};


/*
 * _init - Module's init routine.
 */
int
_init(void)
{
	int ret;

	if ((ret = mod_install(&modlinkage)) != 0) {
		cmn_err(CE_WARN, "mod_install failed, error = %d", ret);
	}
	return (ret);
}

/*
 * _fini - Module's fini routine.
 */
int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&modlinkage)) != 0) {
		return (ret);
	}
	return (ret);
}

/*
 * _info - Module's info routine.
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * okm_attach - Module's attach routine.
 *
 * Description:	Initializes the modules state structure and create
 *		the minor device node.
 */
int
okm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance;
	okms_t *okmsp = &okms_global;

	instance = ddi_get_instance(dip);

	/* Only one instance is supported.  */
	if (instance != 0) {
		return (DDI_FAILURE);
	}

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	okmsp->km_dip = dip;
	okmsp->km_major = ddi_driver_major(dip);
	okmsp->km_inst = instance;

	/*
	 * Get an interrupt block cookie corresponding to the
	 * interrupt priority of the event handler.
	 * Assert that the event priority is not redefined to
	 * some other priority.
	 */
	/* LINTED */
	ASSERT(SCF_EVENT_PRI == DDI_SOFTINT_LOW);
	if (ddi_get_soft_iblock_cookie(dip, SCF_EVENT_PRI,
	    &okmsp->km_ibcookie) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ddi_get_soft_iblock_cookie failed.");
		return (DDI_FAILURE);
	}
	mutex_init(&okmsp->km_lock, NULL, MUTEX_DRIVER,
	    (void *)okmsp->km_ibcookie);
	okmsp->km_clean |= OKM_CLEAN_LOCK;
	cv_init(&okmsp->km_wait, NULL, CV_DRIVER, NULL);
	okmsp->km_clean |= OKM_CLEAN_CV;

	/*
	 * set clean_node ahead as remove_node has to be called even
	 * if create node fails.
	 */
	okmsp->km_clean |= OKM_CLEAN_NODE;
	if (ddi_create_minor_node(dip, OKM_NODENAME, S_IFCHR,
	    instance, NULL, 0) == DDI_FAILURE) {
		cmn_err(CE_WARN, "Device node creation failed");
		okm_cleanup(okmsp);
		return (DDI_FAILURE);
	}

	ddi_set_driver_private(dip, (caddr_t)okmsp);
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

/*
 * okm_detach - Module's detach routine.
 *
 * Description:	Cleans up the module's state structures and any other
 *		relevant data.
 */
int
okm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	okms_t *okmsp;

	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if ((okmsp = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	mutex_enter(&okmsp->km_lock);
	/*
	 * Check if the mailbox is still in use.
	 */
	if (okmsp->km_state & OKM_MB_INITED) {
		mutex_exit(&okmsp->km_lock);
		cmn_err(CE_WARN, "Detach failure: Mailbox in use");
		return (DDI_FAILURE);
	}
	mutex_exit(&okmsp->km_lock);
	okm_cleanup(okmsp);
	ddi_set_driver_private(dip, NULL);
	return (DDI_SUCCESS);
}

/*
 * okm_info - Module's info routine.
 */
/* ARGSUSED */
int
okm_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	okms_t	*okmsp = &okms_global;
	minor_t	minor;
	int	ret = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		/*
		 * We have the case here where the minor number
		 * is the same as the instance number. So, just
		 * make sure we have the right minor node in our
		 * global state. If we don't, set the result to NULL.
		 */
		minor = getminor((dev_t)arg);
		if (okmsp->km_inst != minor) {
			*result = NULL;
		} else {
			*result = okmsp->km_dip;
			ret = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		minor = getminor((dev_t)arg);
		*result = (void *)(uintptr_t)minor;
		ret = DDI_SUCCESS;

	default:
		break;
	}
	return (ret);
}

/*
 * okm_open - Device open routine.
 *
 * Description:	Initializes the mailbox and waits until the mailbox
 *		gets connected. Only one open at a time is supported.
 */
/*ARGSUSED*/
int
okm_open(dev_t *devp, int flag, int otyp, struct cred *cred)
{
	okms_t *okmsp = &okms_global;
	int ret = 0;

	DPRINTF(DBG_DRV, ("okm_open: called\n"));
	mutex_enter(&okmsp->km_lock);
	if (okmsp->km_state & OKM_OPENED) {
		/* Only one open supported */
		mutex_exit(&okmsp->km_lock);
		DPRINTF(DBG_WARN, ("okm_open: already opened\n"));
		return (EBUSY);
	}
	okmsp->km_state |= OKM_OPENED;
	ret = block_until_ready(okmsp);
	if (ret != 0) {
		okmsp->km_state &= ~OKM_OPENED;
	}
	mutex_exit(&okmsp->km_lock);
	DPRINTF(DBG_DRV, ("okm_open: ret=%d\n", ret));
	return (ret);
}

/*
 * block_until_ready - Function to wait until the mailbox is ready to use.
 *
 * Description:	It initializes the mailbox and waits for the mailbox
 *		state to transition to connected.
 */
int
block_until_ready(okms_t *okmsp)
{
	int ret = 0;

	DPRINTF(DBG_DRV, ("block_until_ready: called\n"));
	ASSERT(MUTEX_HELD(&okmsp->km_lock));

	if (okmsp->km_state & OKM_MB_DISC) {
		DPRINTF(DBG_DRV, ("block_until_ready: closing the mailbox\n"));
		okm_mbox_fini(okmsp);
	}
	if (okmsp->km_state & OKM_MB_CONN) {
		DPRINTF(DBG_DRV, ("block_until_ready: mailbox connected\n"));
		return (0);
	}
	/*
	 * Initialize mailbox.
	 */
	if ((ret = okm_mbox_init(okmsp)) != 0) {
		DPRINTF(DBG_MBOX,
		    ("block_until_ready: mailbox init failed ret=%d\n", ret));
		return (ret);
	}
	DPRINTF(DBG_DRV, ("block_until_ready: ret=%d", ret));
	return (ret);
}

/*
 * okm_close - Device close routine.
 *
 * Description: Closes the mailbox.
 */
/*ARGSUSED*/
int
okm_close(dev_t dev, int flag, int otyp, struct cred *cred)
{
	okms_t *okmsp = &okms_global;

	DPRINTF(DBG_DRV, ("okm_close: called\n"));
	/* Close the lower layer first */
	mutex_enter(&okmsp->km_lock);
	okm_mbox_fini(okmsp);
	okmsp->km_state = 0;
	mutex_exit(&okmsp->km_lock);
	return (0);
}


/*
 * okm_ioctl - Device ioctl routine.
 *
 * Description:	Processes ioctls from the daemon.
 */
/*ARGSUSED*/
int
okm_ioctl(dev_t dev, int cmd, intptr_t data, int flag, cred_t *cred, int *rvalp)
{
	okms_t *okmsp = &okms_global;
	sckm_ioctl_getreq_t ireq;
	sckm_ioctl_status_t istatus;
	int ret = 0;

	switch (cmd) {
	case SCKM_IOCTL_GETREQ:

		DPRINTF(DBG_DRV, ("okm_ioctl: GETREQ\n"));
		if (okm_copyin_ioctl_getreq(data, &ireq, flag)) {
			return (EFAULT);
		}

		ret = okm_get_req(okmsp, &ireq, data, flag);
		DPRINTF(DBG_DRV, ("okm_ioctl: GETREQ ret=%d\n", ret));
		break;

	case SCKM_IOCTL_STATUS:

		DPRINTF(DBG_DRV, ("okm_ioctl: STATUS\n"));
		if (ddi_copyin((caddr_t)data, &istatus,
		    sizeof (sckm_ioctl_status_t), flag)) {
			return (EFAULT);
		}
		ret = okm_process_status(okmsp, &istatus);
		DPRINTF(DBG_DRV, ("okm_ioctl: STATUS ret=%d\n", ret));
		break;

	default:
		DPRINTF(DBG_DRV, ("okm_ioctl: UNKNOWN ioctl\n"));
		ret = EINVAL;
	}
	return (ret);
}

/*
 * okm_get_req - Get a request from the mailbox.
 *
 * Description:	It blocks until a message is received, then processes
 *		the message and returns it to the requestor.
 */
int
okm_get_req(okms_t *okmsp, sckm_ioctl_getreq_t *ireqp, intptr_t data, int flag)
{
	okm_req_hdr_t *reqp;
	caddr_t msgbuf;
	uint32_t len;
	int ret;

	DPRINTF(DBG_DRV, ("okm_getreq: called\n"));
	mutex_enter(&okmsp->km_lock);
	if ((ret = block_until_ready(okmsp)) != 0) {
		mutex_exit(&okmsp->km_lock);
		DPRINTF(DBG_WARN, ("okm_getreq: failed ret=%d\n", ret));
		return (ret);
	}

	if (okmsp->km_reqp != NULL) {
		DPRINTF(DBG_DRV, ("okm_getreq: req cached\n"));
		reqp = okmsp->km_reqp;
		len = okmsp->km_reqlen;
		okmsp->km_reqp = NULL;
		okmsp->km_reqlen = 0;
	} else {
retry:
		while (OKM_MBOX_READY(okmsp) &&
		    ((ret = scf_mb_canget(okmsp->km_target,
		    okmsp->km_key, &len)) != 0)) {
			if (ret != ENOMSG) {
				DPRINTF(DBG_WARN, ("okm_getreq: Unknown "
				    "mbox failure=%d\n", ret));
				mutex_exit(&okmsp->km_lock);
				return (EIO);
			}
			DPRINTF(DBG_MBOX, ("okm_getreq: waiting for mesg\n"));
			if (cv_wait_sig(&okmsp->km_wait,
			    &okmsp->km_lock) <= 0) {
				mutex_exit(&okmsp->km_lock);
				DPRINTF(DBG_DRV, ("okm_getreq:interrupted\n"));
				return (EINTR);
			}
		}
		if (!OKM_MBOX_READY(okmsp)) {
			mutex_exit(&okmsp->km_lock);
			DPRINTF(DBG_WARN, ("okm_getreq: mailbox not ready\n"));
			return (EIO);
		}
		ASSERT(len != 0);
		msgbuf = kmem_alloc(len, KM_SLEEP);
		okmsp->km_sg_rcv.msc_dptr = msgbuf;
		okmsp->km_sg_rcv.msc_len = len;

		DPRINTF(DBG_MBOX, ("okm_getreq: getmsg\n"));
		ret = scf_mb_getmsg(okmsp->km_target, okmsp->km_key, len, 1,
		    &okmsp->km_sg_rcv, 0);
		if (ret == ENOMSG || ret == EMSGSIZE) {
			kmem_free(msgbuf, len);
			DPRINTF(DBG_MBOX, ("okm_getreq: nomsg ret=%d\n", ret));
			goto retry;
		} else if (ret != 0) {
			kmem_free(msgbuf, len);
			mutex_exit(&okmsp->km_lock);
			DPRINTF(DBG_WARN,
			    ("okm_getreq: Unknown mbox failure=%d\n", ret));
			return (EIO);
		}

		/* check message length */
		if (len < sizeof (okm_req_hdr_t)) {
			/* protocol error, drop message */
			kmem_free(msgbuf, len);
			mutex_exit(&okmsp->km_lock);
			DPRINTF(DBG_WARN, ("okm_getreq: Bad message\n"));
			return (EBADMSG);
		}

		reqp = (okm_req_hdr_t *)msgbuf;
		reqp->krq_version = ntohl(reqp->krq_version);
		reqp->krq_transid = ntohl(reqp->krq_transid);
		reqp->krq_cmd = ntohl(reqp->krq_cmd);
		reqp->krq_reserved = ntohl(reqp->krq_reserved);

		/* check version of the message received */
		if (reqp->krq_version != OKM_PROTOCOL_VERSION) {
			(void) okm_send_reply(okmsp, reqp->krq_transid,
			    OKM_ERR_VERSION, 0, 0);
			kmem_free(msgbuf, len);
			mutex_exit(&okmsp->km_lock);
			DPRINTF(DBG_WARN, ("okm_getreq: Unknown version=%d\n",
			    reqp->krq_version));
			return (EBADMSG);
		}
	}

	/* process message */
	ret = okm_process_req(okmsp, reqp, len, ireqp, data, flag);
	if (okmsp->km_reqp == NULL) {
		/*
		 * The message is not saved, so free the buffer.
		 */
		kmem_free(reqp, len);
	}
	mutex_exit(&okmsp->km_lock);
	DPRINTF(DBG_DRV, ("okm_getreq: ret=%d\n", ret));
	return (ret);
}


/*
 * okm_process_req - Process the request.
 *
 * Description:	Validate the request and then give the request to the
 *		daemon.
 */
int
okm_process_req(okms_t *okmsp, okm_req_hdr_t *reqp, uint32_t len,
    sckm_ioctl_getreq_t *ireqp, intptr_t data, int flag)
{
	void *req_datap = (void *)(((char *)reqp) + sizeof (okm_req_hdr_t));
	int sadb_msglen = len - sizeof (okm_req_hdr_t);

	DPRINTF(DBG_DRV, ("okm_process_req: called\n"));
	DUMP_REQ(reqp, len);

	switch (reqp->krq_cmd) {
	case OKM_MSG_SADB:
		/* sanity check request */
		if (sadb_msglen <= 0) {
			(void) okm_send_reply(okmsp, reqp->krq_transid,
			    OKM_ERR_SADB_MSG, 0, 0);
			DPRINTF(DBG_WARN, ("okm_process_req: bad message\n"));
			return (EBADMSG);
		}

		/*
		 * Save the message, prior to giving it to the daemon.
		 */
		okmsp->km_reqp = reqp;
		okmsp->km_reqlen = len;

		if (ireqp->buf_len < len) {
			DPRINTF(DBG_WARN,
			    ("okm_process_req: not enough space\n"));
			return (ENOSPC);
		}

		ireqp->transid = reqp->krq_transid;
		ireqp->type = SCKM_IOCTL_REQ_SADB;
		if (ddi_copyout(req_datap, ireqp->buf, sadb_msglen, flag)) {
			DPRINTF(DBG_WARN,
			    ("okm_process_req: copyout failed\n"));
			return (EFAULT);
		}
		ireqp->buf_len = sadb_msglen;
		if (okm_copyout_ioctl_getreq(ireqp, data, flag)) {
			DPRINTF(DBG_WARN,
			    ("okm_process_req: copyout failed\n"));
			return (EFAULT);
		}
		break;

	default:
		cmn_err(CE_WARN, "Unknown cmd 0x%x received", reqp->krq_cmd);
		/*
		 * Received an unknown command, send corresponding
		 * error message.
		 */
		(void) okm_send_reply(okmsp, reqp->krq_transid,
		    OKM_ERR_BAD_CMD, 0, 0);
		return (EBADMSG);
	}
	DPRINTF(DBG_DRV, ("okm_process_req: ret=0\n"));
	return (0);
}

/*
 * okm_process_status - Process the status from the daemon.
 *
 * Description:	Processes the status received from the daemon and sends
 *		corresponding message to the SP.
 */
int
okm_process_status(okms_t *okmsp, sckm_ioctl_status_t *ireply)
{
	uint32_t status;
	uint32_t sadb_msg_errno = 0;
	uint32_t sadb_msg_version = 0;
	okm_req_hdr_t *reqp = okmsp->km_reqp;
	int ret;

	DPRINTF(DBG_DRV, ("okm_process_status: called\n"));
	mutex_enter(&okmsp->km_lock);
	if ((ret = block_until_ready(okmsp)) != 0) {
		mutex_exit(&okmsp->km_lock);
		DPRINTF(DBG_WARN,
		    ("okm_process_status: Unknown failure=%d\n", ret));
		return (ret);
	}

	/* fail if no status is expected, or if it does not match */
	if (!okmsp->km_reqp || (reqp->krq_transid != ireply->transid)) {
		mutex_exit(&okmsp->km_lock);
		DPRINTF(DBG_WARN,
		    ("okm_process_status: req/transid mismatch\n"));
		return (EINVAL);
	}

	switch (ireply->status) {
	case SCKM_IOCTL_STAT_SUCCESS:
		DPRINTF(DBG_DRV, ("okm_process_status: SUCCESS\n"));
		status = OKM_SUCCESS;
		break;
	case SCKM_IOCTL_STAT_ERR_PFKEY:
		DPRINTF(DBG_DRV, ("okm_process_status: PFKEY ERROR\n"));
		status = OKM_ERR_SADB_PFKEY;
		sadb_msg_errno = ireply->sadb_msg_errno;
		break;
	case SCKM_IOCTL_STAT_ERR_REQ:
		DPRINTF(DBG_DRV, ("okm_process_status: REQ ERROR\n"));
		status = OKM_ERR_DAEMON;
		break;
	case SCKM_IOCTL_STAT_ERR_VERSION:
		DPRINTF(DBG_DRV, ("okm_process_status: SADB VERSION ERROR\n"));
		status = OKM_ERR_SADB_VERSION;
		sadb_msg_version = ireply->sadb_msg_version;
		break;
	case SCKM_IOCTL_STAT_ERR_TIMEOUT:
		DPRINTF(DBG_DRV, ("okm_process_status: TIMEOUT ERR\n"));
		status = OKM_ERR_SADB_TIMEOUT;
		break;
	case SCKM_IOCTL_STAT_ERR_OTHER:
		DPRINTF(DBG_DRV, ("okm_process_status: OTHER ERR\n"));
		status = OKM_ERR_DAEMON;
		break;
	case SCKM_IOCTL_STAT_ERR_SADB_TYPE:
		DPRINTF(DBG_DRV, ("okm_process_status: SADB TYPE ERR\n"));
		status = OKM_ERR_SADB_BAD_TYPE;
		break;
	default:
		cmn_err(CE_WARN, "SCKM daemon returned invalid status %d\n",
		    ireply->status);
		status = OKM_ERR_DAEMON;
	}
	ret = okm_send_reply(okmsp, ireply->transid, status,
	    sadb_msg_errno, sadb_msg_version);
	/*
	 * Clean up the cached request now.
	 */
	if (ret == 0) {
		kmem_free(okmsp->km_reqp, okmsp->km_reqlen);
		okmsp->km_reqp = NULL;
		okmsp->km_reqlen = 0;
	}
	mutex_exit(&okmsp->km_lock);
	DPRINTF(DBG_DRV, ("okm_process_status: ret=%d\n", ret));
	return (ret);
}

/*
 * okm_copyin_ioctl_getreq - copy-in the ioctl request from the daemon.
 */

static int
okm_copyin_ioctl_getreq(intptr_t userarg, sckm_ioctl_getreq_t *driverarg,
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


/*
 * okm_copyout_ioctl_getreq - copy-out the request to the daemon.
 */
static int
okm_copyout_ioctl_getreq(sckm_ioctl_getreq_t *driverarg, intptr_t userarg,
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

/*
 * okm_cleanup - Cleanup routine.
 */
static void
okm_cleanup(okms_t *okmsp)
{

	ASSERT(okmsp != NULL);
	if (okmsp->km_clean & OKM_CLEAN_NODE) {
		ddi_remove_minor_node(okmsp->km_dip, NULL);
	}
	if (okmsp->km_clean & OKM_CLEAN_LOCK)
		mutex_destroy(&okmsp->km_lock);
	if (okmsp->km_clean & OKM_CLEAN_CV)
		cv_destroy(&okmsp->km_wait);
	if (okmsp->km_reqp != NULL) {
		kmem_free(okmsp->km_reqp, okmsp->km_reqlen);
		okmsp->km_reqp = NULL;
		okmsp->km_reqlen = 0;
	}
	ddi_set_driver_private(okmsp->km_dip, NULL);
}

/*
 * okm_mbox_init - Mailbox specific initialization.
 */
static int
okm_mbox_init(okms_t *okmsp)
{
	int ret;
	clock_t tout;

	ASSERT(MUTEX_HELD(&okmsp->km_lock));
	okmsp->km_target = OKM_TARGET_ID;
	okmsp->km_key = DKMD_KEY;
	okmsp->km_state &= ~OKM_MB_INITED;

	/* Iterate until mailbox gets connected */
	while (!(okmsp->km_state & OKM_MB_CONN)) {
		DPRINTF(DBG_MBOX, ("okm_mbox_init: calling mb_init\n"));
		ret = scf_mb_init(okmsp->km_target, okmsp->km_key,
		    okm_event_handler, (void *)okmsp);
		DPRINTF(DBG_MBOX, ("okm_mbox_init: mb_init ret=%d\n", ret));

		if (ret != 0) {
			DPRINTF(DBG_MBOX,
			    ("okm_mbox_init: failed ret =%d\n", ret));
			DTRACE_PROBE1(okm_mbox_fail, int, ret);
		} else {
			okmsp->km_state |= OKM_MB_INITED;

			/* Block until the mailbox is ready to communicate. */
			while (!(okmsp->km_state &
			    (OKM_MB_CONN | OKM_MB_DISC))) {

				if (cv_wait_sig(&okmsp->km_wait,
				    &okmsp->km_lock) <= 0) {
					/* interrupted */
					ret = EINTR;
					break;
				}
			}
		}

		if ((ret != 0) || (okmsp->km_state & OKM_MB_DISC)) {

			if (okmsp->km_state & OKM_MB_INITED) {
				(void) scf_mb_fini(okmsp->km_target,
				    okmsp->km_key);
			}
			if (okmsp->km_state & OKM_MB_DISC) {
				DPRINTF(DBG_WARN,
				    ("okm_mbox_init: mbox DISC_ERROR\n"));
				DTRACE_PROBE1(okm_mbox_fail,
				    int, OKM_MB_DISC);
			}

			okmsp->km_state &= ~(OKM_MB_INITED | OKM_MB_DISC |
			    OKM_MB_CONN);

			if (ret == EINTR) {
				return (ret);
			}

			/*
			 * If there was failure, then wait for
			 * OKM_MB_TOUT secs and retry again.
			 */

			DPRINTF(DBG_MBOX, ("okm_mbox_init: waiting...\n"));
			tout = drv_usectohz(OKM_MB_TOUT);
			ret = cv_reltimedwait_sig(&okmsp->km_wait,
			    &okmsp->km_lock, tout, TR_CLOCK_TICK);
			if (ret == 0) {
				/* if interrupted, return immediately. */
				DPRINTF(DBG_MBOX,
				    ("okm_mbox_init: interrupted\n"));
				return (EINTR);
			}
		}
	}

	ret = scf_mb_ctrl(okmsp->km_target, okmsp->km_key,
	    SCF_MBOP_MAXMSGSIZE, &okmsp->km_maxsz);

	/*
	 * The max msg size should be at least the size of reply
	 * we need to send.
	 */
	if ((ret == 0) && (okmsp->km_maxsz < sizeof (okm_rep_hdr_t))) {
		cmn_err(CE_WARN, "Max message size expected >= %ld "
		    "but found %d\n", sizeof (okm_rep_hdr_t), okmsp->km_maxsz);
		ret = EIO;
	}
	if (ret != 0) {
		okmsp->km_state &= ~OKM_MB_INITED;
		(void) scf_mb_fini(okmsp->km_target, okmsp->km_key);
	}
	DPRINTF(DBG_MBOX, ("okm_mbox_init: mb_init ret=%d\n", ret));
	return (ret);
}

/*
 * okm_mbox_fini - Mailbox de-initialization.
 */
static void
okm_mbox_fini(okms_t *okmsp)
{
	int ret = 0;

	ASSERT(MUTEX_HELD(&okmsp->km_lock));
	if (okmsp->km_state & OKM_MB_INITED) {
		DPRINTF(DBG_MBOX, ("okm_mbox_fini: calling mb_fini\n"));
		ret = scf_mb_fini(okmsp->km_target, okmsp->km_key);
		DPRINTF(DBG_MBOX, ("okm_mbox_fini: mb_fini ret=%d\n", ret));
		if (ret != 0) {
			cmn_err(CE_WARN,
			    "Failed to close the Mailbox error=%d", ret);
		}
		okmsp->km_state &= ~(OKM_MB_INITED | OKM_MB_CONN | OKM_MB_DISC);
	}
}

/*
 * okm_event_handler - Mailbox event handler.
 *
 * Description:	Implements a state machine to handle all the mailbox
 *		events. For each event, it sets the appropriate state
 *		flag and wakes up the threads waiting for that event.
 */
void
okm_event_handler(scf_event_t event, void *arg)
{
	okms_t *okmsp = (okms_t *)arg;

	DPRINTF(DBG_MBOX, ("okm_event_handler: called\n"));
	ASSERT(okmsp != NULL);
	mutex_enter(&okmsp->km_lock);
	if (!(okmsp->km_state & OKM_MB_INITED)) {
		/*
		 * Ignore all events if the state flag indicates that the
		 * mailbox not initialized, this may happen during the close.
		 */
		mutex_exit(&okmsp->km_lock);
		DPRINTF(DBG_MBOX,
		    ("okm_event_handler: event=0x%X - mailbox not inited \n",
		    event));
		return;
	}
	switch (event) {
	case SCF_MB_CONN_OK:
		DPRINTF(DBG_MBOX, ("okm_event_handler: Event CONN_OK\n"));
		/*
		 * Now the mailbox is ready to use, lets wake up
		 * any one waiting for this event.
		 */
		okmsp->km_state |= OKM_MB_CONN;
		cv_broadcast(&okmsp->km_wait);
		break;

	case SCF_MB_MSG_DATA:
		DPRINTF(DBG_MBOX, ("okm_event_handler: Event MSG_DATA\n"));
		/*
		 * A message is available in the mailbox,
		 * wakeup if any one is ready to read the message.
		 */
		if (OKM_MBOX_READY(okmsp)) {
			cv_broadcast(&okmsp->km_wait);
		}
		break;

	case SCF_MB_SPACE:
		DPRINTF(DBG_MBOX, ("okm_event_handler: Event MB_SPACE\n"));
		/*
		 * Now the mailbox is ready to transmit, lets
		 * wakeup if any one is waiting to write.
		 */
		if (OKM_MBOX_READY(okmsp)) {
			cv_broadcast(&okmsp->km_wait);
		}
		break;
	case SCF_MB_DISC_ERROR:
		DPRINTF(DBG_MBOX, ("okm_event_handler: Event DISC_ERROR\n"));
		okmsp->km_state &= ~OKM_MB_CONN;
		okmsp->km_state |= OKM_MB_DISC;
		cv_broadcast(&okmsp->km_wait);
		break;
	default:
		cmn_err(CE_WARN, "Unexpected event received\n");
	}
	mutex_exit(&okmsp->km_lock);
}

/*
 * okm_send_reply - Send a mailbox reply message.
 */
int
okm_send_reply(okms_t *okmsp, uint32_t transid,
    uint32_t status, uint32_t sadb_err, uint32_t sadb_ver)
{
	okm_rep_hdr_t reply;
	int ret = EIO;

	DPRINTF(DBG_DRV, ("okm_send_reply: called\n"));
	ASSERT(MUTEX_HELD(&okmsp->km_lock));
	reply.krp_version = htonl(OKM_PROTOCOL_VERSION);
	reply.krp_transid = htonl(transid);
	reply.krp_status = htonl(status);
	reply.krp_sadb_errno = htonl(sadb_err);
	reply.krp_sadb_version = htonl(sadb_ver);
	okmsp->km_sg_tx.msc_dptr = (caddr_t)&reply;
	okmsp->km_sg_tx.msc_len = sizeof (reply);
	DUMP_REPLY(&reply);

	while (OKM_MBOX_READY(okmsp)) {
		DPRINTF(DBG_MBOX, ("okm_send_reply: sending reply\n"));
		ret = scf_mb_putmsg(okmsp->km_target, okmsp->km_key,
		    sizeof (reply), 1, &okmsp->km_sg_tx, 0);
		DPRINTF(DBG_MBOX, ("okm_send_reply: putmsg ret=%d\n", ret));
		if (ret == EBUSY || ret == ENOSPC) {
			/* mailbox is busy, poll/retry */
			if (cv_timedwait_sig(&okmsp->km_wait,
			    &okmsp->km_lock, okm_timeout_val(ret)) == 0) {
				/* interrupted */
				ret = EINTR;
				DPRINTF(DBG_DRV,
				    ("okm_send_reply: interrupted\n"));
				break;
			}
		} else {
			break;
		}
	}
	DPRINTF(DBG_DRV, ("okm_send_reply: ret=%d\n", ret));
	return (ret);
}

/*
 * okm_timeout_val -- Return appropriate timeout value.
 *
 * A small timeout value is returned for EBUSY as the mailbox busy
 * condition may go away sooner and we are expected to poll.
 *
 * A larger timeout value is returned for ENOSPC case, as the condition
 * depends on the peer to release buffer space.
 * NOTE: there will also be an event(SCF_MB_SPACE) but a timeout is
 * used for reliability purposes.
 */
static clock_t
okm_timeout_val(int error)
{
	clock_t tval;

	ASSERT(error == EBUSY || error == ENOSPC);

	if (error == EBUSY) {
		tval = OKM_SM_TOUT;
	} else {
		tval = OKM_LG_TOUT;
	}
	return (drv_usectohz(tval));
}

#ifdef DEBUG
static void
okm_print_req(okm_req_hdr_t *reqp, uint32_t len)
{
	uint8_t *datap = (uint8_t *)(((char *)reqp) + sizeof (okm_req_hdr_t));
	int msglen = len - sizeof (okm_req_hdr_t);
	int i, j;
#define	BYTES_PER_LINE	20
	char bytestr[BYTES_PER_LINE * 3 + 1];

	if (!(okm_debug & DBG_MESG))
		return;
	printf("OKM: Request  ver=%d transid=%d cmd=%s\n",
	    reqp->krq_version, reqp->krq_transid,
	    ((reqp->krq_cmd == OKM_MSG_SADB) ? "MSG_SADB" : "UNKNOWN"));
	for (i = 0; i < msglen; ) {
		for (j = 0; (j < BYTES_PER_LINE) && (i < msglen); j++, i++) {
			(void) sprintf(&bytestr[j * 3], "%02X ", datap[i]);
		}
		if (j != 0) {
			printf("\t%s\n", bytestr);
		}
	}
}

static void
okm_print_rep(okm_rep_hdr_t *repp)
{
	if (!(okm_debug & DBG_MESG))
		return;
	printf("OKM: Reply Ver=%d Transid=%d Status=%d ",
	    repp->krp_version, repp->krp_transid, repp->krp_status);
	printf("Sadb_errno=%d Sadb_ver=%d\n", repp->krp_sadb_errno,
	    repp->krp_sadb_version);
}
#endif
