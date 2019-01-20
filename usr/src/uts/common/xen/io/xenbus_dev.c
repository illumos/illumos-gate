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
 * xenbus_dev.c
 *
 * Driver giving user-space access to the kernel's xenbus connection
 * to xenstore.
 *
 * Copyright (c) 2005, Christian Limpach
 * Copyright (c) 2005, Rusty Russell, IBM Corporation
 *
 * This file may be distributed separately from the Linux kernel, or
 * incorporated into other software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */


#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/uio.h>
#include <sys/list.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/condvar.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/policy.h>

#ifdef XPV_HVM_DRIVER
#include <public/io/xenbus.h>
#include <public/io/xs_wire.h>
#include <sys/xpv_support.h>
#endif
#include <sys/hypervisor.h>
#include <xen/sys/xenbus.h>
#include <xen/sys/xenbus_comms.h>
#include <xen/sys/xenbus_impl.h>
#include <xen/public/io/xs_wire.h>

#ifdef DEBUG
#define	XENBUSDRV_DBPRINT(fmt) { if (xenbusdrv_debug) cmn_err fmt; }
#else
#define	XENBUSDRV_DBPRINT(fmt)
#endif /* ifdef DEBUG */

/* Some handy macros */
#define	XENBUSDRV_MASK_READ_IDX(idx)	((idx) & (PAGESIZE - 1))
#define	XENBUSDRV_MINOR2INST(minor)	((int)(minor))
#define	XENBUSDRV_NCLONES		256
#define	XENBUSDRV_INST2SOFTS(instance)	\
	((xenbus_dev_t *)ddi_get_soft_state(xenbusdrv_statep, (instance)))

static int xenbusdrv_debug = 0;
static int xenbusdrv_clone_tab[XENBUSDRV_NCLONES];
static dev_info_t *xenbusdrv_dip;
static kmutex_t xenbusdrv_clone_tab_mutex;

struct xenbus_dev_transaction {
	list_t list;
	xenbus_transaction_t handle;
};

/* Soft state data structure for xenbus driver */
struct xenbus_dev_data {
	dev_info_t *dip;

	/* In-progress transaction. */
	list_t transactions;

	/* Partial request. */
	unsigned int len;
	union {
		struct xsd_sockmsg msg;
		char buffer[MMU_PAGESIZE];
	} u;

	/* Response queue. */
	char read_buffer[MMU_PAGESIZE];
	unsigned int read_cons, read_prod;
	kcondvar_t read_cv;
	kmutex_t read_mutex;
	int xenstore_inst;
};
typedef struct xenbus_dev_data xenbus_dev_t;
static void *xenbusdrv_statep;

static int xenbusdrv_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int xenbusdrv_attach(dev_info_t *, ddi_attach_cmd_t);
static int xenbusdrv_detach(dev_info_t *, ddi_detach_cmd_t);
static int xenbusdrv_open(dev_t *, int, int, cred_t *);
static int xenbusdrv_close(dev_t, int, int, cred_t *);
static int xenbusdrv_read(dev_t, struct uio *, cred_t *);
static int xenbusdrv_write(dev_t, struct uio *, cred_t *);
static int xenbusdrv_devmap(dev_t, devmap_cookie_t, offset_t, size_t, size_t *,
    uint_t);
static int xenbusdrv_segmap(dev_t, off_t, ddi_as_handle_t, caddr_t *, off_t,
    uint_t, uint_t, uint_t, cred_t *);
static int xenbusdrv_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int xenbusdrv_queue_reply(xenbus_dev_t *, const struct xsd_sockmsg *,
    const char *);

/* Solaris driver framework */

static struct cb_ops xenbusdrv_cb_ops = {
	xenbusdrv_open,			/* cb_open */
	xenbusdrv_close,		/* cb_close */
	nodev,				/* cb_strategy */
	nodev,				/* cb_print */
	nodev,				/* cb_dump */
	xenbusdrv_read,			/* cb_read */
	xenbusdrv_write,		/* cb_write */
	xenbusdrv_ioctl,		/* cb_ioctl */
	xenbusdrv_devmap,		/* cb_devmap */
	NULL,				/* cb_mmap */
	xenbusdrv_segmap,		/* cb_segmap */
	nochpoll,			/* cb_chpoll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* cb_stream */
	D_DEVMAP | D_NEW | D_MP,	/* cb_flag */
	CB_REV
};

static struct dev_ops xenbusdrv_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	xenbusdrv_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	xenbusdrv_attach,	/* devo_attach */
	xenbusdrv_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&xenbusdrv_cb_ops,	/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"virtual bus driver",	/* Name of the module. */
	&xenbusdrv_dev_ops	/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int e;

	e = ddi_soft_state_init(&xenbusdrv_statep, sizeof (xenbus_dev_t), 1);
	if (e)
		return (e);

	e = mod_install(&modlinkage);
	if (e)
		ddi_soft_state_fini(&xenbusdrv_statep);

	return (e);
}

int
_fini(void)
{
	int e;

	e = mod_remove(&modlinkage);
	if (e)
		return (e);

	ddi_soft_state_fini(&xenbusdrv_statep);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
xenbusdrv_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	dev_t	dev = (dev_t)arg;
	minor_t	minor = getminor(dev);
	int	retval;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (minor != 0 || xenbusdrv_dip == NULL) {
			*result = (void *)NULL;
			retval = DDI_FAILURE;
		} else {
			*result = (void *)xenbusdrv_dip;
			retval = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		retval = DDI_SUCCESS;
		break;
	default:
		retval = DDI_FAILURE;
	}
	return (retval);
}

static int
xenbusdrv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	error;
	int	unit = ddi_get_instance(dip);


	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		cmn_err(CE_WARN, "xenbus_attach: unknown cmd 0x%x\n", cmd);
		return (DDI_FAILURE);
	}

	/* DDI_ATTACH */

	/*
	 * only one instance - but we clone using the open routine
	 */
	if (ddi_get_instance(dip) > 0)
		return (DDI_FAILURE);

	mutex_init(&xenbusdrv_clone_tab_mutex, NULL, MUTEX_DRIVER,
	    NULL);

	error = ddi_create_minor_node(dip, "xenbus", S_IFCHR, unit,
	    DDI_PSEUDO, 0);
	if (error != DDI_SUCCESS)
		goto fail;

	/*
	 * save dip for getinfo
	 */
	xenbusdrv_dip = dip;
	ddi_report_dev(dip);

#ifndef XPV_HVM_DRIVER
	if (DOMAIN_IS_INITDOMAIN(xen_info))
		xs_dom0_init();
#endif

	return (DDI_SUCCESS);

fail:
	(void) xenbusdrv_detach(dip, DDI_DETACH);
	return (error);
}

static int
xenbusdrv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	/*
	 * again, only one instance
	 */
	if (ddi_get_instance(dip) > 0)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_DETACH:
		ddi_remove_minor_node(dip, NULL);
		mutex_destroy(&xenbusdrv_clone_tab_mutex);
		xenbusdrv_dip = NULL;
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		cmn_err(CE_WARN, "xenbus_detach: unknown cmd 0x%x\n", cmd);
		return (DDI_FAILURE);
	}
}

/* ARGSUSED */
static int
xenbusdrv_open(dev_t *devp, int flag, int otyp, cred_t *cr)
{
	xenbus_dev_t *xbs;
	minor_t minor = getminor(*devp);

	if (otyp == OTYP_BLK)
		return (ENXIO);

	/*
	 * only allow open on minor = 0 - the clone device
	 */
	if (minor != 0)
		return (ENXIO);

	/*
	 * find a free slot and grab it
	 */
	mutex_enter(&xenbusdrv_clone_tab_mutex);
	for (minor = 1; minor < XENBUSDRV_NCLONES; minor++) {
		if (xenbusdrv_clone_tab[minor] == 0) {
			xenbusdrv_clone_tab[minor] = 1;
			break;
		}
	}
	mutex_exit(&xenbusdrv_clone_tab_mutex);
	if (minor == XENBUSDRV_NCLONES)
		return (EAGAIN);

	/* Allocate softstate structure */
	if (ddi_soft_state_zalloc(xenbusdrv_statep,
	    XENBUSDRV_MINOR2INST(minor)) != DDI_SUCCESS) {
		mutex_enter(&xenbusdrv_clone_tab_mutex);
		xenbusdrv_clone_tab[minor] = 0;
		mutex_exit(&xenbusdrv_clone_tab_mutex);
		return (EAGAIN);
	}
	xbs = XENBUSDRV_INST2SOFTS(XENBUSDRV_MINOR2INST(minor));

	/* ... and init it */
	xbs->dip = xenbusdrv_dip;
	mutex_init(&xbs->read_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&xbs->read_cv, NULL, CV_DEFAULT, NULL);
	list_create(&xbs->transactions, sizeof (struct xenbus_dev_transaction),
	    offsetof(struct xenbus_dev_transaction, list));

	/* clone driver */
	*devp = makedevice(getmajor(*devp), minor);
	XENBUSDRV_DBPRINT((CE_NOTE, "Xenbus drv open succeeded, minor=%d",
	    minor));

	return (0);
}

/* ARGSUSED */
static int
xenbusdrv_close(dev_t dev, int flag, int otyp, struct cred *cr)
{
	xenbus_dev_t *xbs;
	minor_t minor = getminor(dev);
	struct xenbus_dev_transaction *trans;

	xbs = XENBUSDRV_INST2SOFTS(XENBUSDRV_MINOR2INST(minor));
	if (xbs == NULL)
		return (ENXIO);

#ifdef notyet
	/*
	 * XXPV - would like to be able to notify xenstore down here, but
	 * as the daemon is currently written, it doesn't leave the device
	 * open after initial setup, so we have no way of knowing if it has
	 * gone away.
	 */
	if (xbs->xenstore_inst)
		xs_notify_xenstore_down();
#endif
	/* free pending transaction */
	while (trans = (struct xenbus_dev_transaction *)
	    list_head(&xbs->transactions)) {
		(void) xenbus_transaction_end(trans->handle, 1);
		list_remove(&xbs->transactions, (void *)trans);
		kmem_free(trans, sizeof (*trans));
	}

	mutex_destroy(&xbs->read_mutex);
	cv_destroy(&xbs->read_cv);
	ddi_soft_state_free(xenbusdrv_statep, XENBUSDRV_MINOR2INST(minor));

	/*
	 * free clone tab slot
	 */
	mutex_enter(&xenbusdrv_clone_tab_mutex);
	xenbusdrv_clone_tab[minor] = 0;
	mutex_exit(&xenbusdrv_clone_tab_mutex);

	XENBUSDRV_DBPRINT((CE_NOTE, "Xenbus drv close succeeded, minor=%d",
	    minor));

	return (0);
}

/* ARGSUSED */
static int
xenbusdrv_read(dev_t dev, struct uio *uiop, cred_t *cr)
{
	xenbus_dev_t *xbs;
	size_t len;
	int res, ret;
	int idx;

	XENBUSDRV_DBPRINT((CE_NOTE, "xenbusdrv_read called"));

	if (secpolicy_xvm_control(cr))
		return (EPERM);

	xbs = XENBUSDRV_INST2SOFTS(XENBUSDRV_MINOR2INST(getminor(dev)));

	mutex_enter(&xbs->read_mutex);

	/* check if we have something to read */
	while (xbs->read_prod == xbs->read_cons) {
		if (cv_wait_sig(&xbs->read_cv, &xbs->read_mutex) == 0) {
			mutex_exit(&xbs->read_mutex);
			return (EINTR);
		}
	}

	idx = XENBUSDRV_MASK_READ_IDX(xbs->read_cons);
	res = uiop->uio_resid;

	len = xbs->read_prod - xbs->read_cons;

	if (len > (sizeof (xbs->read_buffer) - idx))
		len = sizeof (xbs->read_buffer) - idx;
	if (len > res)
		len = res;

	ret = uiomove(xbs->read_buffer + idx, len, UIO_READ, uiop);
	xbs->read_cons += res - uiop->uio_resid;
	mutex_exit(&xbs->read_mutex);

	return (ret);
}

/*
 * prepare data for xenbusdrv_read()
 */
static int
xenbusdrv_queue_reply(xenbus_dev_t *xbs, const struct xsd_sockmsg *msg,
    const char *reply)
{
	int i;
	int remaining;

	XENBUSDRV_DBPRINT((CE_NOTE, "xenbusdrv_queue_reply called"));

	mutex_enter(&xbs->read_mutex);

	remaining = sizeof (xbs->read_buffer) -
	    (xbs->read_prod - xbs->read_cons);

	if (sizeof (*msg) + msg->len > remaining) {
		mutex_exit(&xbs->read_mutex);
		return (EOVERFLOW);
	}

	for (i = 0; i < sizeof (*msg); i++, xbs->read_prod++) {
		xbs->read_buffer[XENBUSDRV_MASK_READ_IDX(xbs->read_prod)] =
		    ((char *)msg)[i];
	}

	for (i = 0; i < msg->len; i++, xbs->read_prod++) {
		xbs->read_buffer[XENBUSDRV_MASK_READ_IDX(xbs->read_prod)] =
		    reply[i];
	}

	cv_broadcast(&xbs->read_cv);

	mutex_exit(&xbs->read_mutex);

	XENBUSDRV_DBPRINT((CE_NOTE, "xenbusdrv_queue_reply exited"));

	return (0);
}

/* ARGSUSED */
static int
xenbusdrv_write(dev_t dev, struct uio *uiop, cred_t *cr)
{
	xenbus_dev_t *xbs;
	struct xenbus_dev_transaction *trans;
	void *reply;
	size_t len;
	int rc = 0;

	XENBUSDRV_DBPRINT((CE_NOTE, "xenbusdrv_write called"));

	if (secpolicy_xvm_control(cr))
		return (EPERM);

	xbs = XENBUSDRV_INST2SOFTS(XENBUSDRV_MINOR2INST(getminor(dev)));
	len = uiop->uio_resid;

	if ((len + xbs->len) > sizeof (xbs->u.buffer)) {
		XENBUSDRV_DBPRINT((CE_WARN, "Request is too big"));
		rc = EINVAL;
		goto out;
	}

	if (uiomove(xbs->u.buffer + xbs->len, len, UIO_WRITE, uiop) != 0) {
		XENBUSDRV_DBPRINT((CE_WARN, "Uiomove failed"));
		rc = EFAULT;
		goto out;
	}

	xbs->len += len;

	if (xbs->len < (sizeof (xbs->u.msg)) ||
	    xbs->len < (sizeof (xbs->u.msg) + xbs->u.msg.len)) {
		XENBUSDRV_DBPRINT((CE_NOTE, "Partial request"));
		return (0);
	}

	switch (xbs->u.msg.type) {
	case XS_TRANSACTION_START:
	case XS_TRANSACTION_END:
	case XS_DIRECTORY:
	case XS_READ:
	case XS_GET_PERMS:
	case XS_RELEASE:
	case XS_GET_DOMAIN_PATH:
	case XS_WRITE:
	case XS_MKDIR:
	case XS_RM:
	case XS_SET_PERMS:
		/* send the request to xenstore and get feedback */
		rc = xenbus_dev_request_and_reply(&xbs->u.msg, &reply);
		if (rc) {
			XENBUSDRV_DBPRINT((CE_WARN,
			    "xenbus_dev_request_and_reply failed"));
			goto out;
		}

		/* handle transaction start/end */
		if (xbs->u.msg.type == XS_TRANSACTION_START) {
			trans = kmem_alloc(sizeof (*trans), KM_SLEEP);
			(void) ddi_strtoul((char *)reply, NULL, 0,
			    (unsigned long *)&trans->handle);
			list_insert_tail(&xbs->transactions, (void *)trans);
		} else if (xbs->u.msg.type == XS_TRANSACTION_END) {
			/* try to find out the ending transaction */
			for (trans = (struct xenbus_dev_transaction *)
			    list_head(&xbs->transactions); trans;
			    trans = (struct xenbus_dev_transaction *)
			    list_next(&xbs->transactions, (void *)trans))
				if (trans->handle ==
				    (xenbus_transaction_t)
				    xbs->u.msg.tx_id)
					break;
			ASSERT(trans);
			/* free it, if we find it */
			list_remove(&xbs->transactions, (void *)trans);
			kmem_free(trans, sizeof (*trans));
		}

		/* prepare data for xenbusdrv_read() to get */
		rc = xenbusdrv_queue_reply(xbs, &xbs->u.msg, reply);

		kmem_free(reply, xbs->u.msg.len + 1);
		break;
	default:
		rc = EINVAL;
	}

out:
	xbs->len = 0;
	return (rc);
}

/*ARGSUSED*/
static int
xenbusdrv_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model)
{
	xenbus_dev_t *xbs;
	int err;

	xbs = XENBUSDRV_INST2SOFTS(XENBUSDRV_MINOR2INST(getminor(dev)));

	if (off != 0 || len != PAGESIZE)
		return (-1);

	if (!DOMAIN_IS_INITDOMAIN(xen_info))
		return (-1);

	err = devmap_umem_setup(dhp, xbs->dip, NULL, xb_xenstore_cookie(),
	    0, PAGESIZE, PROT_READ | PROT_WRITE | PROT_USER, 0, NULL);

	if (err)
		return (err);

	*maplen = PAGESIZE;

	return (0);
}

static int
xenbusdrv_segmap(dev_t dev, off_t off, ddi_as_handle_t as, caddr_t *addrp,
    off_t len, uint_t prot, uint_t maxprot, uint_t flags, cred_t *cr)
{

	if (secpolicy_xvm_control(cr))
		return (EPERM);

	return (ddi_devmap_segmap(dev, off, as, addrp, len, prot,
	    maxprot, flags, cr));
}

/*ARGSUSED*/
static int
xenbusdrv_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cr,
    int *rvalp)
{
	xenbus_dev_t *xbs;

	if (secpolicy_xvm_control(cr))
		return (EPERM);

	xbs = XENBUSDRV_INST2SOFTS(XENBUSDRV_MINOR2INST(getminor(dev)));
	switch (cmd) {
	case IOCTL_XENBUS_XENSTORE_EVTCHN:
		*rvalp = xen_info->store_evtchn;
		break;
	case IOCTL_XENBUS_NOTIFY_UP:
		xs_notify_xenstore_up();
		xbs->xenstore_inst = 1;
		break;
	default:
		return (EINVAL);
	}

	return (0);
}
