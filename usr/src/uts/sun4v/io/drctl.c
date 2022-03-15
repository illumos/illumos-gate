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
 * DR control module for LDoms
 */

#include <sys/sysmacros.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/stat.h>
#include <sys/door.h>
#include <sys/open.h>
#include <sys/note.h>
#include <sys/ldoms.h>
#include <sys/dr_util.h>
#include <sys/drctl.h>
#include <sys/drctl_impl.h>


static int drctl_attach(dev_info_t *, ddi_attach_cmd_t);
static int drctl_detach(dev_info_t *, ddi_detach_cmd_t);
static int drctl_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);

static int drctl_open(dev_t *, int, int, cred_t *);
static int drctl_close(dev_t, int, int, cred_t *);
static int drctl_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static void *pack_message(int, int, int, void *, size_t *, size_t *);
static int send_message(void *, size_t, drctl_resp_t **, size_t *);


/*
 * Configuration data structures
 */
static struct cb_ops drctl_cb_ops = {
	drctl_open,		/* open */
	drctl_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	drctl_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streamtab */
	D_MP | D_NEW,		/* driver compatibility flag */
	CB_REV,			/* cb_ops revision */
	nodev,			/* async read */
	nodev			/* async write */
};


static struct dev_ops drctl_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	drctl_getinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	drctl_attach,		/* attach */
	drctl_detach,		/* detach */
	nodev,			/* reset */
	&drctl_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* type of module - driver */
	"DR Control pseudo driver",
	&drctl_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};


/*
 * Locking strategy
 *
 * One of the reasons for this module's existence is to serialize
 * DR requests which might be coming from different sources.  Only
 * one operation is allowed to be in progress at any given time.
 *
 * A single lock word (the 'drc_busy' element below) is NULL
 * when there is no operation in progress.  When a client of this
 * module initiates an operation it grabs the mutex 'drc_lock' in
 * order to examine the lock word ('drc_busy').  If no other
 * operation is in progress, the lock word will be NULL.  If so,
 * a cookie which uniquely identifies the requestor is stored in
 * the lock word, and the mutex is released.  Attempts by other
 * clients to initiate an operation will fail.
 *
 * When the lock-holding client's operation is completed, the
 * client will call a "finalize" function in this module, providing
 * the cookie passed with the original request.  Since the cookie
 * matches, the operation will succeed and the lock word will be
 * cleared.  At this point, an new operation may be initiated.
 */

/*
 * Driver private data
 */
static struct drctl_unit {
	kmutex_t		drc_lock;	/* global driver lock */
	dev_info_t		*drc_dip;	/* dev_info pointer */
	kcondvar_t		drc_busy_cv;	/* block for !busy */
	drctl_cookie_t		drc_busy;	/* NULL if free else a unique */
						/* identifier for caller */
	int			drc_cmd;	/* the cmd underway (or -1) */
	int			drc_flags;	/* saved flag from above cmd */
	int			drc_inst;	/* our single instance */
	uint_t			drc_state;	/* driver state */
} drctl_state;

static struct drctl_unit *drctlp = &drctl_state;

int
_init(void)
{
	int rv;

	drctlp->drc_inst = -1;
	mutex_init(&drctlp->drc_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&drctlp->drc_busy_cv, NULL, CV_DRIVER, NULL);

	if ((rv = mod_install(&modlinkage)) != 0)
		mutex_destroy(&drctlp->drc_lock);

	return (rv);
}


int
_fini(void)
{
	int rv;

	if ((rv = mod_remove(&modlinkage)) != 0)
		return (rv);
	cv_destroy(&drctlp->drc_busy_cv);
	mutex_destroy(&drctlp->drc_lock);
	return (0);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * Do the attach work
 */
static int
drctl_do_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	_NOTE(ARGUNUSED(cmd))

	char *str = "drctl_do_attach";
	int retval = DDI_SUCCESS;

	if (drctlp->drc_inst != -1) {
		cmn_err(CE_WARN, "%s: an instance is already attached!", str);
		return (DDI_FAILURE);
	}
	drctlp->drc_inst = ddi_get_instance(dip);

	retval = ddi_create_minor_node(dip, "drctl", S_IFCHR,
	    drctlp->drc_inst, DDI_PSEUDO, 0);
	if (retval != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: can't create minor node", str);
		drctlp->drc_inst = -1;
		return (retval);
	}

	drctlp->drc_dip = dip;
	ddi_report_dev(dip);

	return (retval);
}


static int
drctl_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		return (drctl_do_attach(dip, cmd));

	default:
		return (DDI_FAILURE);
	}
}


/* ARGSUSED */
static int
drctl_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		drctlp->drc_inst = -1;
		ddi_remove_minor_node(dip, "drctl");
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
drctl_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	_NOTE(ARGUNUSED(dip, cmd, arg, resultp))

	return (0);
}

static int
drctl_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	_NOTE(ARGUNUSED(devp, flag, cred_p))

	if (otyp != OTYP_CHR)
		return (EINVAL);

	return (0);
}

static int
drctl_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	_NOTE(ARGUNUSED(dev, flag, otyp, cred_p))

	return (0);
}

/*
 * Create a reponse structure which includes an array of drctl_rsrc_t
 * structures in which each status element is set to the 'status'
 * arg.  There is no error text, so set the 'offset' elements to 0.
 */
static drctl_resp_t *
drctl_generate_resp(drctl_rsrc_t *res,
    int count, size_t *rsize, drctl_status_t status)
{
	int		i;
	size_t		size;
	drctl_rsrc_t	*rsrc;
	drctl_resp_t	*resp;

	size = offsetof(drctl_resp_t, resp_resources) + (count * sizeof (*res));
	resp  = kmem_alloc(size, KM_SLEEP);
	DR_DBG_KMEM("%s: alloc addr %p size %ld\n",
	    __func__, (void *)resp, size);

	resp->resp_type = DRCTL_RESP_OK;
	rsrc = resp->resp_resources;

	bcopy(res, rsrc, count * sizeof (*res));

	for (i = 0; i < count; i++) {
		rsrc[i].status = status;
		rsrc[i].offset = 0;
	}

	*rsize = size;

	return (resp);
}

/*
 * Generate an error response message.
 */
static drctl_resp_t *
drctl_generate_err_resp(char *msg, size_t *size)
{
	drctl_resp_t	*resp;

	ASSERT(msg != NULL);
	ASSERT(size != NULL);

	*size = offsetof(drctl_resp_t, resp_err_msg) + strlen(msg) + 1;
	resp = kmem_alloc(*size, KM_SLEEP);
	DR_DBG_KMEM("%s: alloc addr %p size %ld\n",
	    __func__, (void *)resp, *size);

	resp->resp_type = DRCTL_RESP_ERR;
	(void) strcpy(resp->resp_err_msg, msg);

	return (resp);
}

/*
 * Since response comes from userland, verify that it is at least the
 * minimum size based on the size of the original request.  Verify
 * that any offsets to error strings are within the string area of
 * the response and, force the string area to be null-terminated.
 */
static int
verify_response(int cmd,
    int count, drctl_resp_t *resp, size_t sent_len, size_t resp_len)
{
	drctl_rsrc_t *rsrc = resp->resp_resources;
	size_t rcvd_len = resp_len - (offsetof(drctl_resp_t, resp_resources));
	int is_cpu = 0;
	int i;

	switch (cmd) {
	case DRCTL_CPU_CONFIG_REQUEST:
	case DRCTL_CPU_UNCONFIG_REQUEST:
		if (rcvd_len < sent_len)
			return (EIO);
		is_cpu = 1;
		break;
	case DRCTL_IO_UNCONFIG_REQUEST:
	case DRCTL_IO_CONFIG_REQUEST:
		if (count != 1)
			return (EIO);
		break;
	case DRCTL_MEM_CONFIG_REQUEST:
	case DRCTL_MEM_UNCONFIG_REQUEST:
		break;
	default:
		return (EIO);
	}

	for (i = 0; i < count; i++)
		if ((rsrc[i].offset > 0) &&
		    /* string can't be inside the bounds of original request */
		    (((rsrc[i].offset < sent_len) && is_cpu) ||
		    /* string must start inside the message */
		    (rsrc[i].offset >= rcvd_len)))
			return (EIO);

	/* If there are any strings, terminate the string area. */
	if (rcvd_len > sent_len)
		*((char *)rsrc + rcvd_len - 1) = '\0';

	return (0);
}

static int
drctl_config_common(int cmd, int flags, drctl_rsrc_t *res,
    int count, drctl_resp_t **rbuf, size_t *rsize, size_t *rq_size)
{
	int	rv = 0;
	size_t	size;
	char	*bufp;

	switch (cmd) {
	case DRCTL_CPU_CONFIG_REQUEST:
	case DRCTL_CPU_CONFIG_NOTIFY:
	case DRCTL_CPU_UNCONFIG_REQUEST:
	case DRCTL_CPU_UNCONFIG_NOTIFY:
	case DRCTL_IO_UNCONFIG_REQUEST:
	case DRCTL_IO_UNCONFIG_NOTIFY:
	case DRCTL_IO_CONFIG_REQUEST:
	case DRCTL_IO_CONFIG_NOTIFY:
	case DRCTL_MEM_CONFIG_REQUEST:
	case DRCTL_MEM_CONFIG_NOTIFY:
	case DRCTL_MEM_UNCONFIG_REQUEST:
	case DRCTL_MEM_UNCONFIG_NOTIFY:
		rv = 0;
		break;
	default:
		rv = ENOTSUP;
		break;
	}

	if (rv != 0) {
		DR_DBG_CTL("%s: invalid cmd %d\n", __func__, cmd);
		return (rv);
	}

	/*
	 * If the operation is a FORCE, we don't send a message to
	 * the daemon.  But, the upstream clients still expect a
	 * response, so generate a response with all ops 'allowed'.
	 */
	if (flags == DRCTL_FLAG_FORCE) {
		if (rbuf != NULL)
			*rbuf = drctl_generate_resp(res,
			    count, rsize, DRCTL_STATUS_ALLOW);
		return (0);
	}

	bufp = pack_message(cmd, flags, count, (void *)res, &size, rq_size);
	DR_DBG_CTL("%s: from pack_message, bufp = %p size %ld\n",
	    __func__, (void *)bufp, size);

	if (bufp == NULL || size == 0)
		return (EINVAL);

	return (send_message(bufp, size, rbuf, rsize));
}

/*
 * Prepare for a reconfig operation.
 */
int
drctl_config_init(int cmd, int flags, drctl_rsrc_t *res,
    int count, drctl_resp_t **rbuf, size_t *rsize, drctl_cookie_t ck)
{
	static char inval_msg[] = "Invalid command format received.\n";
	static char unsup_msg[] = "Unsuppported command received.\n";
	static char unk_msg  [] = "Failure reason unknown.\n";
	static char rsp_msg  [] = "Invalid response from "
	    "reconfiguration daemon.\n";
	static char drd_msg  [] = "Cannot communicate with reconfiguration "
	    "daemon (drd) in target domain.\n"
	    "drd(8) SMF service may not be enabled.\n";
	static char busy_msg [] = "Busy executing earlier command; "
	    "please try again later.\n";
	size_t rq_size;
	char *ermsg;
	int rv;

	if (ck == 0) {
		*rbuf = drctl_generate_err_resp(inval_msg, rsize);

		return (EINVAL);
	}

	mutex_enter(&drctlp->drc_lock);
	if (drctlp->drc_busy != NULL) {
		mutex_exit(&drctlp->drc_lock);
		*rbuf = drctl_generate_err_resp(busy_msg, rsize);

		return (EBUSY);
	}

	DR_DBG_CTL("%s: cmd %d flags %d res %p count %d\n",
	    __func__, cmd, flags, (void *)res, count);

	/* Mark the link busy.  Below we will fill in the actual cookie. */
	drctlp->drc_busy = (drctl_cookie_t)-1;
	mutex_exit(&drctlp->drc_lock);

	rv = drctl_config_common(cmd, flags, res, count, rbuf, rsize, &rq_size);
	if (rv == 0) {
		/*
		 * If the upcall to the daemon returned successfully, we
		 * still need to validate the format of the returned msg.
		 */
		if ((rv = verify_response(cmd,
		    count, *rbuf, rq_size, *rsize)) != 0) {
			DR_DBG_KMEM("%s: free addr %p size %ld\n",
			    __func__, (void *)*rbuf, *rsize);
			kmem_free(*rbuf, *rsize);
			*rbuf = drctl_generate_err_resp(rsp_msg, rsize);
			drctlp->drc_busy = NULL;
			cv_broadcast(&drctlp->drc_busy_cv);
		} else { /* message format is valid */
			drctlp->drc_busy = ck;
			drctlp->drc_cmd = cmd;
			drctlp->drc_flags = flags;
		}
	} else {
		switch (rv) {
		case ENOTSUP:
			ermsg = unsup_msg;
			break;
		case EIO:
			ermsg = drd_msg;
			break;
		default:
			ermsg = unk_msg;
			break;
		}

		*rbuf = drctl_generate_err_resp(ermsg, rsize);

		drctlp->drc_cmd = -1;
		drctlp->drc_flags = 0;
		drctlp->drc_busy = NULL;
		cv_broadcast(&drctlp->drc_busy_cv);
	}
	return (rv);
}

/*
 * Complete a reconfig operation.
 */
int
drctl_config_fini(drctl_cookie_t ck, drctl_rsrc_t *res, int count)
{
	int rv;
	int notify_cmd;
	int flags;
	size_t rq_size;

	mutex_enter(&drctlp->drc_lock);
	if (drctlp->drc_busy != ck) {
		mutex_exit(&drctlp->drc_lock);
		return (EBUSY);
	}
	mutex_exit(&drctlp->drc_lock);

	flags = drctlp->drc_flags;
	/*
	 * Flip the saved _REQUEST command to its corresponding
	 * _NOTIFY command.
	 */
	switch (drctlp->drc_cmd) {
	case DRCTL_CPU_CONFIG_REQUEST:
		notify_cmd = DRCTL_CPU_CONFIG_NOTIFY;
		break;

	case DRCTL_CPU_UNCONFIG_REQUEST:
		notify_cmd = DRCTL_CPU_UNCONFIG_NOTIFY;
		break;

	case DRCTL_IO_UNCONFIG_REQUEST:
		notify_cmd = DRCTL_IO_UNCONFIG_NOTIFY;
		break;

	case DRCTL_IO_CONFIG_REQUEST:
		notify_cmd = DRCTL_IO_CONFIG_NOTIFY;
		break;

	case DRCTL_MEM_CONFIG_REQUEST:
		notify_cmd = DRCTL_MEM_CONFIG_NOTIFY;
		break;

	case DRCTL_MEM_UNCONFIG_REQUEST:
		notify_cmd = DRCTL_MEM_UNCONFIG_NOTIFY;
		break;

	default:
		/* none of the above should have been accepted in _init */
		ASSERT(0);
		cmn_err(CE_CONT,
		    "drctl_config_fini: bad cmd %d\n", drctlp->drc_cmd);
		rv = EINVAL;
		goto done;
	}

	rv = drctl_config_common(notify_cmd,
	    flags, res, count, NULL, 0, &rq_size);

done:
		drctlp->drc_cmd = -1;
		drctlp->drc_flags = 0;
		drctlp->drc_busy = NULL;
		cv_broadcast(&drctlp->drc_busy_cv);
		return (rv);
}

static int
drctl_ioctl(dev_t dev,
    int cmd, intptr_t arg, int mode, cred_t *cred_p, int *rval_p)
{
	_NOTE(ARGUNUSED(dev, mode, cred_p, rval_p))

	int rv;

	switch (cmd) {
	case DRCTL_IOCTL_CONNECT_SERVER:
		rv = i_drctl_ioctl(cmd, arg);
		break;
	default:
		rv = ENOTSUP;
	}

	*rval_p = (rv == 0) ? 0 : -1;

	return (rv);
}

/*
 * Accept a preformatted request from caller and send a message to
 * the daemon.  A pointer to the daemon's response buffer is passed
 * back in obufp, its size in osize.
 */
static int
send_message(void *msg, size_t size, drctl_resp_t **obufp, size_t *osize)
{
	drctl_resp_t *bufp;
	drctl_rsrc_t *rsrcs;
	size_t rsrcs_size;
	int rv;

	rv = i_drctl_send(msg, size, (void **)&rsrcs, &rsrcs_size);

	if ((rv == 0) && ((rsrcs == NULL) ||(rsrcs_size == 0)))
		rv = EINVAL;

	if (rv == 0) {
		if (obufp != NULL) {
			ASSERT(osize != NULL);

			*osize =
			    offsetof(drctl_resp_t, resp_resources) + rsrcs_size;
			bufp =
			    kmem_alloc(*osize, KM_SLEEP);
			DR_DBG_KMEM("%s: alloc addr %p size %ld\n",
			    __func__, (void *)bufp, *osize);
			bufp->resp_type = DRCTL_RESP_OK;
			bcopy(rsrcs, bufp->resp_resources, rsrcs_size);
			*obufp = bufp;
		}

		DR_DBG_KMEM("%s: free addr %p size %ld\n",
		    __func__, (void *)rsrcs, rsrcs_size);
		kmem_free(rsrcs, rsrcs_size);
	}

	DR_DBG_KMEM("%s:free addr %p size %ld\n", __func__, msg, size);
	kmem_free(msg, size);

	return (rv);
}

static void *
pack_message(int cmd,
    int flags, int count, void *data, size_t *osize, size_t *data_size)
{
	drd_msg_t *msgp = NULL;
	size_t hdr_size = offsetof(drd_msg_t, data);

	switch (cmd) {
	case DRCTL_CPU_CONFIG_REQUEST:
	case DRCTL_CPU_CONFIG_NOTIFY:
	case DRCTL_CPU_UNCONFIG_REQUEST:
	case DRCTL_CPU_UNCONFIG_NOTIFY:
		*data_size = count * sizeof (drctl_rsrc_t);
		break;
	case DRCTL_MEM_CONFIG_REQUEST:
	case DRCTL_MEM_CONFIG_NOTIFY:
	case DRCTL_MEM_UNCONFIG_REQUEST:
	case DRCTL_MEM_UNCONFIG_NOTIFY:
		*data_size = count * sizeof (drctl_rsrc_t);
		break;
	case DRCTL_IO_CONFIG_REQUEST:
	case DRCTL_IO_CONFIG_NOTIFY:
	case DRCTL_IO_UNCONFIG_REQUEST:
	case DRCTL_IO_UNCONFIG_NOTIFY:
		*data_size = sizeof (drctl_rsrc_t) +
		    strlen(((drctl_rsrc_t *)data)->res_dev_path);
		break;
	default:
		cmn_err(CE_WARN,
		    "drctl: pack_message received invalid cmd %d", cmd);
		break;
	}

	if (data_size) {
		*osize = hdr_size + *data_size;
		msgp = kmem_alloc(*osize, KM_SLEEP);
		DR_DBG_KMEM("%s: alloc addr %p size %ld\n",
		    __func__, (void *)msgp, *osize);
		msgp->cmd = cmd;
		msgp->count = count;
		msgp->flags = flags;
		bcopy(data, msgp->data, *data_size);
	}

	return (msgp);
}

/*
 * Depending on the should_block argument, either wait for ongoing DR
 * operations to finish and then block subsequent operations, or if a DR
 * operation is already in progress, return EBUSY immediately without
 * blocking subsequent DR operations.
 */
static int
drctl_block_conditional(boolean_t should_block)
{
	mutex_enter(&drctlp->drc_lock);
	/* If DR in progress and should_block is false, return */
	if (!should_block && drctlp->drc_busy != NULL) {
		mutex_exit(&drctlp->drc_lock);
		return (EBUSY);
	}

	/* Wait for any in progress DR operation to complete */
	while (drctlp->drc_busy != NULL)
		(void) cv_wait_sig(&drctlp->drc_busy_cv, &drctlp->drc_lock);

	/* Mark the link busy */
	drctlp->drc_busy = (drctl_cookie_t)-1;
	drctlp->drc_cmd = DRCTL_DRC_BLOCK;
	drctlp->drc_flags = 0;
	mutex_exit(&drctlp->drc_lock);
	return (0);
}

/*
 * Wait for ongoing DR operations to finish, block subsequent operations.
 */
void
drctl_block(void)
{
	(void) drctl_block_conditional(B_TRUE);
}

/*
 * If a DR operation is already in progress, return EBUSY immediately
 * without blocking subsequent DR operations.
 */
int
drctl_tryblock(void)
{
	return (drctl_block_conditional(B_FALSE));
}

/*
 * Unblock DR operations
 */
void
drctl_unblock(void)
{
	/* Mark the link free */
	mutex_enter(&drctlp->drc_lock);
	drctlp->drc_cmd = -1;
	drctlp->drc_flags = 0;
	drctlp->drc_busy = NULL;
	cv_broadcast(&drctlp->drc_busy_cv);
	mutex_exit(&drctlp->drc_lock);
}
