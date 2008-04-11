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

/*
 * IPMI: front-end to BMC access
 */

#include <sys/types.h>
#include <sys/stropts.h>
#include <sys/note.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/devops.h>
#include <sys/dditypes.h>
#include <sys/stream.h>
#include <sys/modctl.h>
#include <sys/varargs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/policy.h>
#include <sys/sysmacros.h>
#include <sys/atomic.h>
#include <sys/bmc_intf.h>
#include <sys/bmc_cmd.h>

#include "bmc_fe.h"

static boolean_t bmc_command_requires_privilege(uint8_t, uint8_t);
static void bmc_send_syserror(queue_t *q, uint8_t err);
static mblk_t *bmc_process_msg(queue_t *q, mblk_t *mp, boolean_t *intr);
static mblk_t *bmc_build_msg(uint8_t type, uint32_t mid, ...);

int bmc_debug = 0;

#define	BMC_NUM_CMDS	256

typedef struct bmc_clone {
	ipmi_state_t	*ipmip;		/* IPMI state */
	dev_t		dev;		/* maj/min for this clone */
} bmc_clone_t;

#define	BMC_CLONE(x)	((bmc_clone_t *)(x))

static void *ipmi_state;
static bmc_clone_t *bmc_clones;
static int bmc_nclones;


/*ARGSUSED*/
static void
bmc_mioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk		*iocp = (struct iocblk *)mp->b_rptr;
	mblk_t			*mptr;
	ipmi_state_t *ipmip = BMC_CLONE(q->q_ptr)->ipmip;
	ipmi_dev_t *devp = &ipmip->ipmi_dev_ext;
	bmc_reqrsp_t *intfp;
	uint8_t *methodp;
	unsigned char ack_type = M_IOCNAK;

	dprintf(BMC_DEBUG_LEVEL_4, "IOCTL  enter");

	/* mptr points to the the data the user passed down */
	mptr = mp->b_cont;

	/* Consolidate multiple mblk_t's used to build this message */
	if (mptr) {
		dprintf(BMC_DEBUG_LEVEL_4, "mptr: %p", (void *)mptr);
		if (pullupmsg(mptr, -1) == 0) {
			dprintf(BMC_DEBUG_LEVEL_4, "pullupmsg failure");
			iocp->ioc_error = EINVAL;
			goto mioctl_exit;
		}

		intfp = (bmc_reqrsp_t *)mptr->b_rptr;
	}

	/* Make sure that the user passed in something */
	if (intfp == NULL) {
		dprintf(BMC_DEBUG_LEVEL_4, "No data passed with M_IOCTL");
		iocp->ioc_error = EINVAL;
		goto mioctl_exit;
	}

	/* Don't allow transparent ioctls */
	if (iocp->ioc_count == TRANSPARENT) {
		dprintf(BMC_DEBUG_LEVEL_4, "TRANSPARENT ioctls not allowed");
		iocp->ioc_error = EINVAL;
		goto mioctl_exit;
	}

	if (devp == NULL) {
		dprintf(BMC_DEBUG_LEVEL_4, "deviceExt is NULL");
		iocp->ioc_error = EINVAL;
		goto mioctl_exit;
	}


	dprintf(BMC_DEBUG_LEVEL_4, "IOCTL cmd 0x%x count 0x%lx",
	    iocp->ioc_cmd, (ulong_t)iocp->ioc_count);

	switch (iocp->ioc_cmd) {

	case IOCTL_IPMI_KCS_ACTION:	/* DEPRECATED */
					/* legacy from x86 /dev/bmc */
	case IOCTL_IPMI_INTERFACE_METHOD:
		/*
		 * If the user has provided at least enough space to hold
		 * the interface type, then return it.  Otherwise, bail
		 * out with an error.
		 */
		if (iocp->ioc_count >= sizeof (uint8_t)) {

			/* All future accesses should be via putmsg/getmsg */
			methodp = (uint8_t *)mptr->b_rptr;
			*methodp = BMC_PUTMSG_METHOD;
			ack_type = M_IOCACK;
			iocp->ioc_rval = 0;
			iocp->ioc_count = 1;
		} else {
			dprintf(BMC_DEBUG_LEVEL_3,
			    "IOCTL_IPMI_INTERFACE_METHOD: Not enough data"
			    " supplied to ioctl");
			iocp->ioc_error = ENOSPC;
		}

		break;

	default:
		iocp->ioc_error = EINVAL;
		break;
	}

mioctl_exit:
	mp->b_datap->db_type = ack_type;
	qreply(q, mp);
}

static int
bmc_wput(queue_t *q, mblk_t *mp)
{
	dprintf(BMC_DEBUG_LEVEL_4, "bmc_wput  enter");
	/* We're expecting a message with data here */
	ASSERT(mp != NULL);
	ASSERT(mp->b_datap != NULL);

	switch (mp->b_datap->db_type) {

	case M_DATA:
		/* Queue for later processing */
		if (!putq(q, mp)) {
			dprintf(BMC_DEBUG_LEVEL_2, "putq(M_DATA) failed!");
			freemsg(mp);
		}
		break;

	case M_IOCTL:
		/* Process the I_STR ioctl() from user land */
		bmc_mioctl(q, mp);
		break;

	case M_FLUSH:
		/*
		 * Flush processing is a requirement of streams drivers and
		 * modules.
		 *
		 * The bmc driver does not use the read queue, so M_FLUSH
		 * handling consists of passing a read flush message back
		 * up the read side of the queue to any modules that may
		 * be residing above it as well as clearing the write queue,
		 * if requested.
		 *
		 */
		if (*mp->b_rptr & FLUSHW) {
			dprintf(BMC_DEBUG_LEVEL_2, "Flush write queue");
			flushq(q, FLUSHALL);
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR) {
			dprintf(BMC_DEBUG_LEVEL_2, "Flush read queue");
			qreply(q, mp);
		} else
			/* No read processing required.  Throw away message */
			freemsg(mp);
		break;

	default:
		dprintf(BMC_DEBUG_LEVEL_2,
		    "Message not understood.  Ignoring. db_type = %d",
		    mp->b_datap->db_type);
		freemsg(mp);
		break;
	}

	return (0);

}

/*
 * Write-size queue processing
 *
 * Process data messages and perform BMC operations as directed.
 */
static int
bmc_wsrv(queue_t *q)
{
	mblk_t *mp;
	queue_t *rq = RD(q);
	boolean_t intr;

	while (mp = getq(q)) {
		/* We only queued M_DATA messages */
		ASSERT(mp->b_datap->db_type == M_DATA);

		/*
		 * If we wouldn't be able to put a message upstream, hold
		 * off on processing this message and but it back on our
		 * write queue.  We'll get scheduled later and check the
		 * state of our upstream partner at that time.
		 */
		if (!canputnext(rq)) {
			/* If putbq fails, free the message */
			if (!putbq(q, mp))
				freemsg(mp);
			break;
		}

		/*
		 * Process this message.  Any replies will not reuse
		 * mp, so discard it after the message is processed.
		 */
		mp = bmc_process_msg(q, mp, &intr);
		freemsg(mp);
		if (intr) {
			bmc_send_syserror(RD(q), EINTR);
			break;
		}
	}
	return (0);
}


/*ARGSUSED*/
static int
bmc_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	int instance = getminor(*devp);
	ipmi_state_t *ipmip;
	int c;

	if (sflag) {
		/* Clone open NOT supported here */
		return (ENXIO);
	}

	if ((ipmip = ddi_get_soft_state(ipmi_state, instance)) == NULL) {
		return (ENXIO);
	}

	/*
	 * Locate and reserve a clone structure.  We skip clone 0 as that is
	 * the real minor number, and we assign a new minor to each clone.
	 */
	for (c = 0; c < bmc_nclones; c++) {
		if (casptr(&bmc_clones[c].ipmip, NULL, ipmip) == NULL) {
			break;
		}
	}

	if (c >= bmc_nclones)
		return (EAGAIN);

	*devp = bmc_clones[c].dev = makedevice(getemajor(*devp), c + 1);

	/* Init q data pointers */
	q->q_ptr = WR(q)->q_ptr = &bmc_clones[c];

	qprocson(q);	/* Turn on the q */
	return (0);
}

/*ARGSUSED*/
static int
bmc_close(queue_t *q, int flag, cred_t *credp)
{
	bmc_clones[getminor(BMC_CLONE(q->q_ptr)->dev) - 1].ipmip = NULL;

	qprocsoff(q);	/* Turn the q off */
	return (0);
}

static int
bmc_getbmcversions(ipmi_state_t *ipmip, boolean_t can_intr, boolean_t *intr)
{
	bmc_req_t req;
	bmc_rsp_t rsp;

	bzero(&req, sizeof (bmc_req_t));
	bzero(&rsp, sizeof (bmc_rsp_t));

	req.fn = BMC_NETFN_APP;
	req.cmd = BMC_GET_DEVICE_ID;

	rsp.fn = BMC_NETFN_APP;
	rsp.cmd = BMC_GET_DEVICE_ID;
	rsp.datalength = RECV_MAX_PAYLOAD_SIZE;


	if (do_vc2bmc(&ipmip->ipmi_dev_ext, &req, &rsp, can_intr, intr)
	    == BMC_SUCCESS) {

		/* check for the version */
		if (rsp.ccode != 0) {
			goto getbmcversions_error;
		}

		if (rsp.data[4] == BMC_IPMI_15_VER) {
			dprintf(BMC_DEBUG_LEVEL_3, "F/W Version: %x.%x",
			    (rsp.data[2] & 0x7F), rsp.data[3]);
		}

		return (BMC_SUCCESS);
	}

getbmcversions_error:

	if (*intr)
		dprintf(BMC_DEBUG_LEVEL_2, "getbmcversion interrupted");
	else
		dprintf(BMC_DEBUG_LEVEL_2, "getbmcversion failed");

	return (BMC_FAILURE);
}

static int
bmc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	ipmi_state_t *ipmip;
	boolean_t intr = B_FALSE;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_soft_state_zalloc(ipmi_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if ((ipmip = ddi_get_soft_state(ipmi_state, instance)) == NULL) {
		ddi_soft_state_free(ipmi_state, instance);
		return (DDI_FAILURE);
	}

	ipmip->ipmi_dip = dip;

	mutex_init(&ipmip->ipmi_dev_ext.if_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ipmip->ipmi_dev_ext.if_cv, NULL, CV_DEFAULT, NULL);
	ipmip->ipmi_dev_ext.if_busy = B_FALSE;

	/* LDI initialization */
	if (vc_init(dip) != BMC_SUCCESS) {
		goto cleanup_on_fail;
	}

	/* Try twice to get the BMC version */
	if (bmc_getbmcversions(ipmip, B_FALSE, &intr) == BMC_FAILURE) {
		if (bmc_getbmcversions(ipmip, B_FALSE, &intr) == BMC_FAILURE) {
			goto cleanup_on_fail;
		}
	}

	if ((ddi_create_minor_node(dip, BMC_NODENAME, S_IFCHR,
	    BMC_MINOR, DDI_PSEUDO, 0)) != DDI_SUCCESS) {
		ddi_remove_minor_node(dip, NULL);
		goto cleanup_on_fail;
	}

	ddi_report_dev(dip);
	return (DDI_SUCCESS);

cleanup_on_fail:
	(void) vc_uninit();
	cv_destroy(&ipmip->ipmi_dev_ext.if_cv);
	mutex_destroy(&ipmip->ipmi_dev_ext.if_mutex);
	ddi_soft_state_free(ipmi_state, instance);

	return (DDI_FAILURE);
}

static int
bmc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	ipmi_state_t *ipmip;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	(void) vc_uninit();

	instance = ddi_get_instance(dip);

	ddi_remove_minor_node(dip, NULL);

	if ((ipmip = ddi_get_soft_state(ipmi_state, instance)) != NULL) {
		cv_destroy(&ipmip->ipmi_dev_ext.if_cv);
		mutex_destroy(&ipmip->ipmi_dev_ext.if_mutex);
	}
	ddi_soft_state_free(ipmi_state, ddi_get_instance(dip));

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
bmc_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error, instance = getminor((dev_t)arg);
	ipmi_state_t *ipmip = ddi_get_soft_state(ipmi_state, instance);

	if (ipmip == NULL)
		return (DDI_FAILURE);

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (ipmip->ipmi_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *)ipmip->ipmi_dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)instance;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}

	return (error);
}

/*PRINTFLIKE2*/
void
dprintf(int d, const char *format, ...)
{
#ifdef DEBUG
	if (d <= bmc_debug) {
		va_list ap;
		va_start(ap, format);
		vcmn_err(d < BMC_DEBUG_LEVEL_2 ? CE_WARN : CE_CONT, format, ap);
		va_end(ap);
	}
#endif
}

static boolean_t
bmc_command_requires_privilege(uint8_t command, uint8_t netFn)
{

	bmc_command_priv_level_t *command_listp;
	int i;

	/*
	 * BMC commands are grouped by function (netFn).
	 * The commands implemented within each function
	 * group are tabulated, together with their associated
	 * privilege level in the bmc_netfn* arrays.
	 *
	 * Currently two privilege levels are defined:
	 *    BMC_REQ_NORM permits global access to this command
	 *    BMC_REQ_PRIV permits privileged (sys_admin) access
	 *    to this command.
	 *
	 * bmc_command_requires_privilege() returns B_FALSE in the case
	 * that global access is permitted and B_TRUE in the case
	 * that sys_admin privileges are required.
	 *
	 * Future IPMI implementations may add further function
	 * groups and further commands to existing function groups.
	 * In the case that an unknown function group is specified,
	 * and in the case that an unknown command within an existing
	 * function group is specified, B_TRUE is returned.
	 */

	switch (netFn) {

	case BMC_NETFN_CHASSIS:
		command_listp = bmc_netfn_chassis;
		break;

	case BMC_NETFN_BRIDGE:
		command_listp = bmc_netfn_bridge;
		break;

	case BMC_NETFN_SE:
		command_listp = bmc_netfn_se;
		break;

	case BMC_NETFN_APP:
		command_listp = bmc_netfn_app;
		break;

	case BMC_NETFN_STORAGE:
		command_listp = bmc_netfn_storage;
		break;

	case BMC_NETFN_TRANSPORT:
		command_listp = bmc_netfn_transport;
		break;

	default:
		return (B_TRUE); /* Unknown function group */
	}

	for (i = 0; command_listp[i].req_level != BMC_END_OF_LIST; i++) {
		if (command_listp[i].command == command)
			return (command_listp[i].req_level == BMC_REQ_PRIV);
	}

	return (B_TRUE); /* Unknown command */
}

/*
 * Send an error code upstream
 * Used to signal system-related errors to the stream head
 * Use sparingly, as sending an M_ERROR wakes up all processes
 * sleeping on system calls to this device and is semi-permanent.
 *
 * q: an upward-facing queue (read-side)
 */
static void
bmc_send_syserror(queue_t *q, uint8_t err)
{
	mblk_t *bp;

	if ((bp = allocb(1, BPRI_HI)) != NULL) {

		bp->b_datap->db_type = M_ERROR;
		*bp->b_wptr++ = err;

		putnext(q, bp);
	}
}

/*
 * Process a message sent from the user.
 *
 * q passed in is the WRITE side.
 */
static mblk_t *
bmc_process_msg(queue_t *q, mblk_t *mp, boolean_t *intr)
{
	ipmi_state_t *ipmip = BMC_CLONE(q->q_ptr)->ipmip;
	bmc_msg_t *msg;
	bmc_req_t *request;
	bmc_rsp_t *response;
	int response_allocsz;
	mblk_t *reply_msg = NULL;
	int msgsize;
	mblk_t *origmp = mp;

	ASSERT(mp->b_datap->db_type == M_DATA);

	dprintf(BMC_DEBUG_LEVEL_4, "bmc_process_msg  enter");

	/* Construct contiguous message so we can access its fields below */
	dprintf(BMC_DEBUG_LEVEL_4, "mp = %p", (void *)mp);
	if ((mp = msgpullup(origmp, -1)) == NULL) {
		dprintf(BMC_DEBUG_LEVEL_4, "msgpullup failure");
		bmc_send_syserror(RD(q), ENOSR);
		return (origmp);
	}

	/* Done with the original message; the pulled-up message is in mp */
	freemsg(origmp);

	msgsize = msgdsize(mp);
	msg = (bmc_msg_t *)mp->b_rptr;

	/* The message must be at LEAST as large as a bmc_msg_t */
	if (msgsize < sizeof (bmc_msg_t)) {
		dprintf(BMC_DEBUG_LEVEL_4, "Message is smaller than min msg"
		    " size (size was %d, must be at least %lu)", msgsize,
		    (ulong_t)sizeof (bmc_msg_t));

		reply_msg = bmc_build_msg(BMC_MSG_ERROR, BMC_UNKNOWN_MSG_ID,
		    EINVAL);
		ASSERT(reply_msg != NULL);

		/* Invalid message -- send an error upstream and return */
		qreply(q, reply_msg);
		return (mp);
	}

	*intr = B_FALSE;

	switch (msg->m_type) {

	case BMC_MSG_REQUEST:
		/*
		 * Calculate the payload size (the size of the request
		 * structure embedded in the bmc_msg_t request) by subtracting
		 * the size of all members of the bmc_msg_t except for the
		 * msg field (which is overlayed with the bmc_req_t).
		 */
		msgsize -= offsetof(bmc_msg_t, msg);

		request = (bmc_req_t *)&msg->msg[0];

		/* Perform some sanity checks on the size of the message */
		if (msgsize < sizeof (bmc_req_t) || msgsize <
		    (offsetof(bmc_req_t, data) + request->datalength)) {
			dprintf(BMC_DEBUG_LEVEL_4, "Malformed message, msg "
			    " size=%lu, payload size=%d, expected size=%lu",
			    (ulong_t)msgdsize(mp), msgsize,
			    (ulong_t)((msgsize < sizeof (bmc_req_t)) ?
			    sizeof (bmc_req_t) :
			    (offsetof(bmc_req_t, data) +
			    request->datalength)));
			/* Send a message to signal an error */
			reply_msg = bmc_build_msg(BMC_MSG_ERROR, msg->m_id,
			    EINVAL);
			break;
		}

		/* Does the command number look OK? */
		if (request->cmd >= (BMC_NUM_CMDS - 1)) {
			reply_msg = bmc_build_msg(BMC_MSG_RESPONSE,
			    msg->m_id, request->fn, request->lun,
			    request->cmd, BMC_IPMI_INVALID_COMMAND,
			    0, NULL);
			break;
		}

		/*
		 * Command number's good.  Does the messages have a NULL
		 * cred attached to its first data block, or does this
		 * command require privileges the user doesn't have?
		 *
		 * (This implies that should any STREAMS modules be pushed
		 * between the stream head and this driver, it must preserve
		 * the cred added to the original message so that this driver
		 * can do the appropriate permissions checks).
		 */
		if ((DB_CRED(mp) == NULL) ||
		    (bmc_command_requires_privilege(request->cmd,
		    request->fn) && secpolicy_sys_config(DB_CRED(mp),
		    B_FALSE) != 0)) {
			reply_msg = bmc_build_msg(BMC_MSG_ERROR, msg->m_id,
			    EACCES);
			break;
		}

		dprintf(BMC_DEBUG_LEVEL_2,
		    "MSG  type 0x%x subcmd 0x%x req_len 0x%x",
		    msg->m_type, request->cmd, request->datalength);

		/* Allocate enough space for the largest response possible */
		response_allocsz = bmc_vc_max_response_payload_size() +
		    offsetof(bmc_rsp_t, data);
		response = (bmc_rsp_t *)kmem_zalloc(response_allocsz, KM_SLEEP);
		response->datalength = bmc_vc_max_response_payload_size();

		/*
		 * If an error occurs during the processing of the command,
		 * the cause of the error is recorded in the response, so
		 * ignore the return value and send the response upstream.
		 */
		(void) do_vc2bmc(&ipmip->ipmi_dev_ext, request, response,
		    B_TRUE, intr);

		if (!*intr) {
			reply_msg = bmc_build_msg(BMC_MSG_RESPONSE, msg->m_id,
			    response->fn, response->lun, response->cmd,
			    response->ccode, response->datalength,
			    (uint8_t *)response->data);

			dprintf(BMC_DEBUG_LEVEL_2,
			    "MSG DONE subcmd 0x%x req_len 0x%x rsp_len 0x%x "
			    "code 0x%x",
			    request->cmd,
			    request->datalength,
			    response->datalength,
			    response->ccode);
		}

		kmem_free(response, response_allocsz);

		break;

	default:
		reply_msg = bmc_build_msg(BMC_MSG_ERROR, msg->m_id, EINVAL);
		break;
	}

	ASSERT(*intr || reply_msg != NULL);

	if (!*intr) {
		/* Send the reply upstream */
		qreply(q, reply_msg);
	}
	return (mp);
}

static mblk_t *
bmc_build_msg(uint8_t mtype, uint32_t mid, ...)
{
	mblk_t *mp = NULL;
	bmc_msg_t *msg = NULL;
	va_list ap;
	bmc_rsp_t *rsp;
	bmc_rsp_t *response;
	uint8_t *datap;
	size_t msgsz = 0;

	va_start(ap, mid);

	switch (mtype) {
	case BMC_MSG_ERROR:
		/*
		 * Build an error message.  The second parameter is the
		 * message ID, and the third is the error code.
		 */
		msgsz = sizeof (bmc_msg_t);
		mp = allocb(msgsz, BPRI_MED);
		if (mp == NULL)
			break;
		msg = (bmc_msg_t *)mp->b_wptr;
		/* First byte of msg is the error code */
		msg->msg[0] = va_arg(ap, uint_t);
		break;

	case BMC_MSG_RESPONSE:
		rsp = kmem_alloc(sizeof (bmc_rsp_t), KM_SLEEP);
		rsp->fn = va_arg(ap, uint_t);
		rsp->lun = va_arg(ap, uint_t);
		rsp->cmd = va_arg(ap, uint_t);
		rsp->ccode = va_arg(ap, uint_t);
		rsp->datalength = va_arg(ap, uint_t);
		datap = va_arg(ap, uint8_t *);


		/*
		 * Total message size is (# of bytes before the msg field
		 * in the bmc_msg_t field) + the full size of the bmc_rsp_t
		 * structure, including all non-data members + size of the
		 * data array (variable).
		 */
		msgsz = offsetof(bmc_msg_t, msg) + offsetof(bmc_rsp_t, data) +
		    rsp->datalength;

		mp = allocb(msgsz, BPRI_MED);
		if (mp == NULL)
			break;

		msg = (bmc_msg_t *)mp->b_wptr;
		response = (bmc_rsp_t *)&msg->msg[0];
		response->fn = rsp->fn;
		response->lun = rsp->lun;
		response->cmd = rsp->cmd;
		response->ccode = rsp->ccode;
		response->datalength = rsp->datalength;
		if (response->datalength != 0 && datap != 0)
			bcopy(datap, response->data, response->datalength);

		kmem_free(rsp, sizeof (bmc_rsp_t));
		break;

	default:
		dprintf(BMC_DEBUG_LEVEL_2,
		    "bmc_build_msg: unknown message type 0x%x!",
		    mtype);
		break;
	}

	if (msg != NULL) {
		msg->m_type = mtype;
		msg->m_id = mid;
	}

	if (mp != NULL)
		mp->b_wptr += msgsz;

	ASSERT(mp == NULL || mp->b_wptr <= mp->b_datap->db_lim);

	va_end(ap);

	return (mp);
}

static struct module_info bmc_minfo = {
	0xabcd,				/* module id number */
	"IPMI bmc driver %I%",		/* module name */
	0,				/* min packet size */
	INFPSZ,				/* max packet size */
	1024,				/* hi water mark */
	512				/* low water mark */
};

static struct qinit bmc_rinit = {
	NULL,				/* put procedure */
	NULL,				/* service procedure */
	bmc_open,			/* open() procedure */
	bmc_close,			/* close() procedure */
	NULL,				/* reserved */
	&bmc_minfo,			/* module information pointer */
	NULL				/* module stats pointer */
};

static struct qinit bmc_winit = {
	bmc_wput,			/* put procedure */
	bmc_wsrv,			/* service procedure */
	NULL,				/* open() not used on write side */
	NULL,				/* close() not used on write side */
	NULL,				/* reserved */
	&bmc_minfo,			/* module information pointer */
	NULL				/* module state pointer */
};

struct streamtab bmc_str_info = {
	&bmc_rinit,
	&bmc_winit,
	NULL,
	NULL
};

DDI_DEFINE_STREAM_OPS(				\
	bmc_ops,				\
	nulldev,				\
	nulldev,				\
	bmc_attach,				\
	bmc_detach,				\
	nodev,					\
	bmc_getinfo,				\
	D_MP | D_NEW,				\
	&bmc_str_info				\
);

static struct modldrv modldrv = {
	&mod_driverops, "BMC driver %I%", &bmc_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&ipmi_state,
	    sizeof (ipmi_state_t), 0)) != 0)
		return (error);

	if (bmc_nclones <= 0)
		bmc_nclones = maxusers;

	bmc_clones = kmem_zalloc(sizeof (bmc_clone_t) * bmc_nclones, KM_SLEEP);

	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&ipmi_state);
		kmem_free(bmc_clones, sizeof (bmc_clone_t) * bmc_nclones);
	}

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&ipmi_state);
		kmem_free(bmc_clones, sizeof (bmc_clone_t) * bmc_nclones);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
