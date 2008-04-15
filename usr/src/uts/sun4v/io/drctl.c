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

static void *pack_message(int, int, int, void *, size_t *);
static int send_message(void *, size_t, void **, size_t *);


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
};

static struct modldrv modldrv = {
	&mod_driverops,		/* type of module - driver */
	"DR Control pseudo driver v%I%",
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
 * This driver guarantees that if drctl_config_init returns 0,
 * a valid response buffer will be passed back to the caller.  This
 * routine can be used to generate that response in cases where the
 * upcall has not resulted in a response message from userland.
 */
static drctl_rsrc_t *
drctl_generate_resp(drctl_rsrc_t *res,
    int count, size_t *rsize, drctl_status_t status)
{
	int		idx;
	size_t		size;
	drctl_rsrc_t	*rbuf;

	size = count * sizeof (*res);
	rbuf  = kmem_alloc(size, KM_SLEEP);

	bcopy(res, rbuf, size);

	for (idx = 0; idx < count; idx++) {
		rbuf[idx].status = status;
		rbuf[idx].offset = 0;
	}

	*rsize = size;
	return (rbuf);
}

static int
drctl_config_common(int cmd, int flags, drctl_rsrc_t *res,
    int count, drctl_rsrc_t **rbuf, size_t *rsize)
{
	int	rv = 0;
	size_t	size;
	char	*bufp;
	static const char me[] = "drctl_config_common";

	switch (cmd) {
	case DRCTL_CPU_CONFIG_REQUEST:
	case DRCTL_CPU_CONFIG_NOTIFY:
	case DRCTL_CPU_UNCONFIG_REQUEST:
	case DRCTL_CPU_UNCONFIG_NOTIFY:
	case DRCTL_IO_UNCONFIG_REQUEST:
	case DRCTL_IO_UNCONFIG_NOTIFY:
	case DRCTL_IO_CONFIG_REQUEST:
	case DRCTL_IO_CONFIG_NOTIFY:
		rv = 0;
		break;
	case DRCTL_MEM_CONFIG_REQUEST:
	case DRCTL_MEM_CONFIG_NOTIFY:
	case DRCTL_MEM_UNCONFIG_REQUEST:
	case DRCTL_MEM_UNCONFIG_NOTIFY:
		rv = ENOTSUP;
		break;
	}

	if (rv != 0) {
		DR_DBG_CTL("%s: invalid cmd %d\n", me, cmd);
		return (rv);
	}

	/*
	 * If the operation is a FORCE, we don't send a message to
	 * the daemon.  But, the upstream clients still expect a
	 * response, so generate a response with all ops 'allowed'.
	 */
	if (flags == DRCTL_FLAG_FORCE) {
		if (rbuf != NULL) {
			*rbuf = drctl_generate_resp(res, count, &size,
			    DRCTL_STATUS_ALLOW);
			*rsize = size;
		}
		return (0);
	}

	bufp = pack_message(cmd, flags, count, (void *)res, &size);
	DR_DBG_CTL("%s: from pack_message, bufp = %p size %ld\n",
	    me, (void *)bufp, size);
	if (bufp == NULL || size == 0)
		return (EIO);

	rv = send_message(bufp, size, (void **)rbuf, rsize);

	/*
	 * For failure, as part of our contract with the caller,
	 * generate a response message, but mark all proposed
	 * changes as 'denied'.
	 */
	if (rv != 0 && rbuf != NULL) {
		*rbuf = drctl_generate_resp(res, count, &size,
		    DRCTL_STATUS_DENY);
		*rsize = size;
	}

	return (rv);
}

/*
 * Since the response comes from userland, make sure it is
 * at least the minimum size and, if it contains error
 * strings, that the string area is null-terminated.
 */
static int
verify_response(int count, drctl_rsrc_t *resp, size_t size)
{
	int idx;
	int need_terminator = 0;
	static const char me[] = "verify_response";

	if (resp == NULL || size < count * sizeof (*resp)) {
		DR_DBG_CTL("%s: BAD size - count %d size %ld\n",
		    me, count, size);
		return (EIO);
	}

	for (idx = 0; idx < count; idx++) {

		if (resp[idx].offset != 0)
			need_terminator++;
	}

	if (need_terminator && *((caddr_t)(resp) + size - 1) != '\0') {
		DR_DBG_CTL("%s: unterm. strings: resp %p size %ld char %d\n",
		    me, (void *)resp, size, *((caddr_t)(resp) + size - 1));
		/* Don't fail the transaction, but don't advertise strings */
		for (idx = 0; idx < count; idx++)
			resp[idx].offset = 0;
	}

	return (0);
}


/*
 * Prepare for a reconfig operation.
 */
int
drctl_config_init(int cmd, int flags, drctl_rsrc_t *res,
    int count, drctl_rsrc_t **rbuf, size_t *rsize, drctl_cookie_t ck)
{
	static char me[] = "drctl_config_init";
	int idx;
	int rv;

	if (ck == 0)
		return (EINVAL);

	mutex_enter(&drctlp->drc_lock);

	if (drctlp->drc_busy != NULL) {
		mutex_exit(&drctlp->drc_lock);
		return (EBUSY);
	}

	DR_DBG_CTL("%s: cmd %d flags %d res %p count %d\n",
	    me, cmd, flags, (void *)res, count);

	/* Mark the link busy.  Below we will fill in the actual cookie. */
	drctlp->drc_busy = (drctl_cookie_t)-1;
	mutex_exit(&drctlp->drc_lock);

	if ((rv = drctl_config_common(cmd,
	    flags, res, count, rbuf, rsize)) == 0 &&
	    verify_response(count, *rbuf, *rsize) == 0) {
		drctlp->drc_busy = ck;
		drctlp->drc_cmd = cmd;
		drctlp->drc_flags = flags;

		/*
		 * If there wasn't a valid response msg passed back,
		 * create a response with each resource op denied.
		 */
		if (*rbuf == NULL || *rsize == 0) {
			drctl_rsrc_t *bp = *rbuf;

			*rsize = count * sizeof (*bp);
			bp = kmem_zalloc(*rsize, KM_SLEEP);
			bcopy(res, bp, *rsize);

			for (idx = 0; idx < count; idx++) {
				bp[idx].status = DRCTL_STATUS_DENY;
				bp[idx].offset = 0;
			}
		}
	} else {
		drctlp->drc_cmd = -1;
		drctlp->drc_flags = 0;
		drctlp->drc_busy = NULL;
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
	case DRCTL_MEM_CONFIG_NOTIFY:
	case DRCTL_MEM_UNCONFIG_REQUEST:
	case DRCTL_MEM_UNCONFIG_NOTIFY:
	default:
		/* none of the above should have been accepted in _init */
		ASSERT(0);
		cmn_err(CE_CONT,
		    "drctl_config_fini: bad cmd %d\n", drctlp->drc_cmd);
		rv = EINVAL;
		goto done;
	}

	rv = drctl_config_common(notify_cmd, flags, res, count, NULL, 0);

done:
	drctlp->drc_cmd = -1;
	drctlp->drc_flags = 0;
	drctlp->drc_busy = NULL;

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
send_message(void *msg, size_t size, void **obufp, size_t *osize)
{
	int rv;

	rv = i_drctl_send(msg, size, obufp, osize);

	kmem_free(msg, size);

	return (rv);
}

static void *
pack_message(int cmd, int flags, int count, void *data, size_t *osize)
{
	drd_msg_t *msgp = NULL;
	size_t hdr_size = offsetof(drd_msg_t, data);
	size_t data_size = 0;

	switch (cmd) {
	case DRCTL_CPU_CONFIG_REQUEST:
	case DRCTL_CPU_CONFIG_NOTIFY:
	case DRCTL_CPU_UNCONFIG_REQUEST:
	case DRCTL_CPU_UNCONFIG_NOTIFY:
		data_size = count * sizeof (drctl_rsrc_t);
		break;
	case DRCTL_IO_CONFIG_REQUEST:
	case DRCTL_IO_CONFIG_NOTIFY:
	case DRCTL_IO_UNCONFIG_REQUEST:
	case DRCTL_IO_UNCONFIG_NOTIFY:
		data_size = sizeof (drctl_rsrc_t) +
		    strlen(((drctl_rsrc_t *)data)->res_dev_path);
		break;
	default:
		cmn_err(CE_WARN,
		    "drctl: pack_message received invalid cmd %d", cmd);
		break;
	}

	if (data_size) {
		*osize = hdr_size + data_size;
		msgp = kmem_alloc(*osize, KM_SLEEP);
		msgp->cmd = cmd;
		msgp->count = count;
		msgp->flags = flags;
		bcopy(data, msgp->data, data_size);
	}

	return (msgp);
}
