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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * sun4v domain services PRI driver
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ds.h>
#include <sys/hypervisor_api.h>
#include <sys/machsystm.h>
#include <sys/sysmacros.h>
#include <sys/hsvc.h>
#include <sys/bitmap.h>
#include <sys/ds_pri.h>

static uint_t ds_pri_debug = 0;
#define	DS_PRI_DBG	if (ds_pri_debug) printf

#define	DS_PRI_NAME	"ds_pri"

#define	TEST_HARNESS
#ifdef TEST_HARNESS
#define	DS_PRI_MAX_PRI_SIZE	(64 * 1024)

#define	DSIOC_TEST_REG	97
#define	DSIOC_TEST_UNREG	98
#define	DSIOC_TEST_DATA	99

struct ds_pri_test_data {
	size_t		size;
	void		*data;
};

struct ds_pri_test_data32 {
	size32_t	size;
	caddr32_t	data;
};
#endif /* TEST_HARNESS */

typedef	enum {
	DS_PRI_REQUEST	= 0,
	DS_PRI_DATA	= 1,
	DS_PRI_UPDATE	= 2
} ds_pri_msg_type_t;

typedef	struct {
	struct {
		uint64_t	seq_num;
		uint64_t	type;
	} hdr;
	uint8_t		data[1];
} ds_pri_msg_t;

/*
 * The following are bit field flags. No service implies no DS PRI and
 * no outstanding request.
 */
typedef enum {
	DS_PRI_NO_SERVICE = 0x0,
	DS_PRI_HAS_SERVICE = 0x1,
	DS_PRI_REQUESTED = 0x2,
	DS_PRI_HAS_PRI = 0x4
} ds_pri_flags_t;

struct ds_pri_state {
	dev_info_t	*dip;
	int		instance;

	kmutex_t	lock;
	kcondvar_t	cv;

	/* PRI/DS */
	ds_pri_flags_t	state;
	uint64_t	gencount;
	ds_svc_hdl_t	ds_pri_handle;
	void		*ds_pri;
	size_t		ds_pri_len;
	uint64_t	req_id;
	uint64_t	last_req_id;
	int		num_opens;
};

typedef struct ds_pri_state ds_pri_state_t;

static void *ds_pri_statep;

static void request_pri(ds_pri_state_t *sp);
static uint64_t ds_get_hv_pri(ds_pri_state_t *sp);

static int ds_pri_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int ds_pri_attach(dev_info_t *, ddi_attach_cmd_t);
static int ds_pri_detach(dev_info_t *, ddi_detach_cmd_t);
static int ds_pri_open(dev_t *, int, int, cred_t *);
static int ds_pri_close(dev_t, int, int, cred_t *);
static int ds_pri_read(dev_t, struct uio *, cred_t *);
static int ds_pri_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * DS Callbacks
 */
static void ds_pri_reg_handler(ds_cb_arg_t, ds_ver_t *, ds_svc_hdl_t);
static void ds_pri_unreg_handler(ds_cb_arg_t arg);
static void ds_pri_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen);

/*
 * PRI DS capability registration
 */

static ds_ver_t ds_pri_ver_1_0 = { 1, 0 };

static ds_capability_t ds_pri_cap = {
	"pri",
	&ds_pri_ver_1_0,
	1
};

/*
 * PRI DS Client callback vector
 */
static ds_clnt_ops_t ds_pri_ops = {
	ds_pri_reg_handler,	/* ds_reg_cb */
	ds_pri_unreg_handler,	/* ds_unreg_cb */
	ds_pri_data_handler,	/* ds_data_cb */
	NULL			/* cb_arg */
};

/*
 * DS PRI driver Ops Vector
 */
static struct cb_ops ds_pri_cb_ops = {
	ds_pri_open,		/* cb_open */
	ds_pri_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	ds_pri_read,		/* cb_read */
	nodev,			/* cb_write */
	ds_pri_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	(struct streamtab *)NULL, /* cb_str */
	D_MP | D_64BIT,		/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops ds_pri_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	ds_pri_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	ds_pri_attach,		/* devo_attach */
	ds_pri_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&ds_pri_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	nulldev,		/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Domain Services PRI Driver",
	&ds_pri_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

static boolean_t hsvc_pboot_available = B_FALSE;
static hsvc_info_t pboot_hsvc = {
	HSVC_REV_1, NULL, HSVC_GROUP_PBOOT, 1, 0, NULL
};

int
_init(void)
{
	int retval;
	uint64_t	hsvc_pboot_minor;
	uint64_t	status;

	status = hsvc_register(&pboot_hsvc, &hsvc_pboot_minor);
	if (status == H_EOK) {
		hsvc_pboot_available = B_TRUE;
	} else {
		DS_PRI_DBG("hypervisor services not negotiated "
		    "for group number: 0x%lx errorno: 0x%lx\n",
		    pboot_hsvc.hsvc_group, status);
	}

	retval = ddi_soft_state_init(&ds_pri_statep,
	    sizeof (ds_pri_state_t), 0);
	if (retval != 0)
		return (retval);

	retval = mod_install(&modlinkage);
	if (retval != 0) {
		ddi_soft_state_fini(&ds_pri_statep);
		return (retval);
	}

	return (retval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


int
_fini(void)
{
	int retval;

	if ((retval = mod_remove(&modlinkage)) != 0)
		return (retval);

	ddi_soft_state_fini(&ds_pri_statep);

	if (hsvc_pboot_available)
		(void) hsvc_unregister(&pboot_hsvc);

	return (retval);
}


/*ARGSUSED*/
static int
ds_pri_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	ds_pri_state_t *sp;
	int retval = DDI_FAILURE;

	ASSERT(resultp != NULL);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		sp = ddi_get_soft_state(ds_pri_statep, getminor((dev_t)arg));
		if (sp != NULL) {
			*resultp = sp->dip;
			retval = DDI_SUCCESS;
		} else
			*resultp = NULL;
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)getminor((dev_t)arg);
		retval = DDI_SUCCESS;
		break;

	default:
		break;
	}

	return (retval);
}


static int
ds_pri_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance;
	ds_pri_state_t *sp;
	int rv;
	uint64_t status;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(ds_pri_statep, instance) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s@%d: Unable to allocate state",
		    DS_PRI_NAME, instance);
		return (DDI_FAILURE);
	}
	sp = ddi_get_soft_state(ds_pri_statep, instance);

	mutex_init(&sp->lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sp->cv, NULL, CV_DEFAULT, NULL);

	if (ddi_create_minor_node(dip, DS_PRI_NAME, S_IFCHR, instance,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s@%d: Unable to create minor node",
		    DS_PRI_NAME, instance);
		goto fail;
	}

	if (ds_pri_ops.cb_arg != NULL)
		goto fail;
	ds_pri_ops.cb_arg = dip;

	sp->state = DS_PRI_NO_SERVICE;

	/* Until the service registers the handle is invalid */
	sp->ds_pri_handle = DS_INVALID_HDL;

	sp->ds_pri = NULL;
	sp->ds_pri_len = 0;
	sp->req_id = 0;
	sp->num_opens = 0;

	/*
	 * See if we can get the static hv pri data. Static pri data
	 * is only available for privileged domains.
	 */
	if (hsvc_pboot_available) {
		if ((status = ds_get_hv_pri(sp)) != 0) {
			cmn_err(CE_NOTE, "ds_get_hv_pri failed: 0x%lx", status);
		}
	}

	if ((rv = ds_cap_init(&ds_pri_cap, &ds_pri_ops)) != 0) {
		cmn_err(CE_NOTE, "ds_cap_init failed: %d", rv);
		goto fail;
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail:
	if (sp->ds_pri)
		kmem_free(sp->ds_pri, sp->ds_pri_len);
	ddi_remove_minor_node(dip, NULL);
	cv_destroy(&sp->cv);
	mutex_destroy(&sp->lock);
	ddi_soft_state_free(ds_pri_statep, instance);
	return (DDI_FAILURE);

}


/*ARGSUSED*/
static int
ds_pri_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ds_pri_state_t *sp;
	int instance;
	int rv;

	instance = ddi_get_instance(dip);
	sp = ddi_get_soft_state(ds_pri_statep, instance);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* This really shouldn't fail - but check anyway */
	if ((rv = ds_cap_fini(&ds_pri_cap)) != 0) {
		cmn_err(CE_WARN, "ds_cap_fini failed: %d", rv);
	}

	if (sp != NULL && sp->ds_pri_len != 0)
		kmem_free(sp->ds_pri, sp->ds_pri_len);

	ds_pri_ops.cb_arg = NULL;

	ddi_remove_minor_node(dip, NULL);
	cv_destroy(&sp->cv);
	mutex_destroy(&sp->lock);
	ddi_soft_state_free(ds_pri_statep, instance);

	return (DDI_SUCCESS);
}


/*ARGSUSED*/
static int
ds_pri_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	ds_pri_state_t *sp;
	int instance;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	instance = getminor(*devp);
	sp = ddi_get_soft_state(ds_pri_statep, instance);
	if (sp == NULL)
		return (ENXIO);

	mutex_enter(&sp->lock);

	/*
	 * Proceed if we have PRI data (possibly obtained from
	 * static HV PRI or last pushed DS PRI data update).
	 * If no PRI data and we have no DS PRI service then this
	 * means that PRI DS has never called the registration callback.
	 * A while loop is necessary as we might have been woken up
	 * prematurely, e.g., due to a debugger or "pstack" etc.
	 * Wait here and the callback will signal us when it has completed
	 * its work.
	 */
	if (!(sp->state & DS_PRI_HAS_PRI)) {
		while (!(sp->state & DS_PRI_HAS_SERVICE)) {
			if (cv_wait_sig(&sp->cv, &sp->lock) == 0) {
				mutex_exit(&sp->lock);
				return (EINTR);
			}
		}
	}

	sp->num_opens++;
	mutex_exit(&sp->lock);

	DS_PRI_DBG("ds_pri_open: state = 0x%x\n", sp->state);

	return (0);
}


/*ARGSUSED*/
static int
ds_pri_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	int instance;
	ds_pri_state_t *sp;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	DS_PRI_DBG("ds_pri_close\n");

	instance = getminor(dev);
	if ((sp = ddi_get_soft_state(ds_pri_statep, instance)) == NULL)
		return (ENXIO);

	mutex_enter(&sp->lock);
	if (!(sp->state & DS_PRI_HAS_SERVICE)) {
		mutex_exit(&sp->lock);
		return (0);
	}

	if (--sp->num_opens > 0) {
		mutex_exit(&sp->lock);
		return (0);
	}

	sp->state &= ~DS_PRI_REQUESTED;
	mutex_exit(&sp->lock);
	return (0);
}


/*ARGSUSED*/
static int
ds_pri_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	ds_pri_state_t *sp;
	int instance;
	size_t len;
	int retval;
	caddr_t tmpbufp;
	offset_t off = uiop->uio_offset;

	instance = getminor(dev);
	if ((sp = ddi_get_soft_state(ds_pri_statep, instance)) == NULL)
		return (ENXIO);

	len = uiop->uio_resid;

	if (len == 0)
		return (0);

	mutex_enter(&sp->lock);

	DS_PRI_DBG("ds_pri_read: state = 0x%x\n", sp->state);

	/* block or bail if there is no current PRI */
	if (!(sp->state & DS_PRI_HAS_PRI)) {
		DS_PRI_DBG("ds_pri_read: no PRI held\n");

		if (uiop->uio_fmode & (FNDELAY | FNONBLOCK)) {
			mutex_exit(&sp->lock);
			return (EAGAIN);
		}

		while (!(sp->state & DS_PRI_HAS_PRI)) {
			DS_PRI_DBG("ds_pri_read: state = 0x%x\n", sp->state);
			request_pri(sp);
			if (cv_wait_sig(&sp->cv, &sp->lock) == 0) {
				mutex_exit(&sp->lock);
				return (EINTR);
			}
		}
	}

	if (len > sp->ds_pri_len)
		len = sp->ds_pri_len;

	if (len == 0) {
		mutex_exit(&sp->lock);
		return (0);
	}

	/*
	 * We're supposed to move the data out to userland, but
	 * that can suspend because of page faults etc., and meanwhile
	 * other parts of this driver want to update the PRI buffer ...
	 * we could hold the data buffer locked with a flag etc.,
	 * but that's still a lock ... a simpler mechanism - if not quite
	 * as performance efficient is to simply clone here the part of
	 * the buffer we care about and then the original can be released
	 * for further updates while the uiomove continues.
	 */

	tmpbufp = kmem_alloc(len, KM_SLEEP);
	bcopy(((caddr_t)sp->ds_pri), tmpbufp, len);
	mutex_exit(&sp->lock);

	retval = uiomove(tmpbufp, len, UIO_READ, uiop);

	kmem_free(tmpbufp, len);

	/*
	 * restore uio_offset after uiomove since the driver
	 * does not support the concept of position.
	 */
	uiop->uio_offset = off;

	return (retval);
}


/*ARGSUSED*/
static int
ds_pri_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	ds_pri_state_t *sp;
	int instance;

	instance = getminor(dev);
	if ((sp = ddi_get_soft_state(ds_pri_statep, instance)) == NULL)
		return (ENXIO);

	switch (cmd) {
	case DSPRI_GETINFO: {
		struct dspri_info info;

		if (!(mode & FREAD))
			return (EACCES);

		/*
		 * We are not guaranteed that ddi_copyout(9F) will read
		 * atomically anything larger than a byte.  Therefore we
		 * must duplicate the size before copying it out to the user.
		 */
		mutex_enter(&sp->lock);

loop:;
		if (sp->state & DS_PRI_HAS_PRI) {
			/* If we have a PRI simply return the info */
			info.size = sp->ds_pri_len;
			info.token = sp->gencount;
		} else
		if (!(sp->state & DS_PRI_HAS_SERVICE)) {
			/* If we have no service return a nil response */
			info.size = 0;
			info.token = 0;
		} else {
			request_pri(sp);
			/* wait for something & check again */
			if (cv_wait_sig(&sp->cv, &sp->lock) == 0) {
				mutex_exit(&sp->lock);
				return (EINTR);
			}
			goto loop;
		}
		DS_PRI_DBG("ds_pri_ioctl: DSPRI_GETINFO sz=0x%lx tok=0x%lx\n",
		    info.size, info.token);
		mutex_exit(&sp->lock);

		if (ddi_copyout(&info, (void *)arg, sizeof (info), mode) != 0)
			return (EFAULT);
		break;
	}

	case DSPRI_WAIT: {
		uint64_t gencount;

		if (ddi_copyin((void *)arg, &gencount, sizeof (gencount),
		    mode) != 0)
			return (EFAULT);

		mutex_enter(&sp->lock);

		DS_PRI_DBG("ds_pri_ioctl: DSPRI_WAIT gen=0x%lx sp->gen=0x%lx\n",
		    gencount, sp->gencount);

		while ((sp->state & DS_PRI_HAS_PRI) == 0 ||
		    gencount == sp->gencount) {
			if ((sp->state & DS_PRI_HAS_PRI) == 0)
				request_pri(sp);
			if (cv_wait_sig(&sp->cv, &sp->lock) == 0) {
				mutex_exit(&sp->lock);
				return (EINTR);
			}
		}
		mutex_exit(&sp->lock);
		break;
	}

	default:
		return (ENOTTY);
	}
	return (0);
}


	/* assumes sp->lock is held when called */
static void
request_pri(ds_pri_state_t *sp)
{
	ds_pri_msg_t reqmsg;

	ASSERT(MUTEX_HELD(&sp->lock));

	/* If a request is already pending we're done */
	if (!(sp->state & DS_PRI_HAS_SERVICE))
		return;
	if (sp->state & DS_PRI_REQUESTED)
		return;

	/* If we have an old PRI - remove it */
	if (sp->state & DS_PRI_HAS_PRI) {
		ASSERT(sp->ds_pri_len != 0);
		ASSERT(sp->ds_pri != NULL);

		/* remove the old data if we have an outstanding request */
		kmem_free(sp->ds_pri, sp->ds_pri_len);
		sp->ds_pri_len = 0;
		sp->ds_pri = NULL;
		sp->state &= ~DS_PRI_HAS_PRI;
	} else {
		ASSERT(sp->ds_pri == NULL);
		ASSERT(sp->ds_pri_len == 0);
	}

	reqmsg.hdr.seq_num = ++(sp->req_id);
	reqmsg.hdr.type = DS_PRI_REQUEST;

	DS_PRI_DBG("request_pri: request id 0x%lx\n", sp->req_id);

		/*
		 * Request consists of header only.
		 * We don't care about fail status for ds_send;
		 * if it does fail we will get an unregister callback
		 * from the DS framework and we handle the state change
		 * there.
		 */
	(void) ds_cap_send(sp->ds_pri_handle, &reqmsg, sizeof (reqmsg.hdr));

	sp->state |= DS_PRI_REQUESTED;
	sp->last_req_id = sp->req_id;
}

/*
 * DS Callbacks
 */
/*ARGSUSED*/
static void
ds_pri_reg_handler(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl)
{
	dev_info_t *dip = arg;
	ds_pri_state_t *sp;
	int instance;

	instance = ddi_get_instance(dip);
	if ((sp = ddi_get_soft_state(ds_pri_statep, instance)) == NULL)
		return;

	DS_PRI_DBG("ds_pri_reg_handler: registering handle 0x%lx for version "
	    "0x%x:0x%x\n", (uint64_t)hdl, ver->major, ver->minor);

	/* When the domain service comes up automatically update the state */
	mutex_enter(&sp->lock);

	ASSERT(sp->ds_pri_handle == DS_INVALID_HDL);
	sp->ds_pri_handle = hdl;

	ASSERT(!(sp->state & DS_PRI_HAS_SERVICE));
	sp->state |= DS_PRI_HAS_SERVICE;

	/*
	 * Cannot request a PRI here, because the reg handler cannot
	 * do a DS send operation - we take care of this later.
	 * Static hv pri data might be available.
	 */

	/* Wake up anyone waiting in open() */
	cv_broadcast(&sp->cv);

	mutex_exit(&sp->lock);
}


static void
ds_pri_unreg_handler(ds_cb_arg_t arg)
{
	dev_info_t *dip = arg;
	ds_pri_state_t *sp;
	int instance;

	instance = ddi_get_instance(dip);
	if ((sp = ddi_get_soft_state(ds_pri_statep, instance)) == NULL)
		return;

	DS_PRI_DBG("ds_pri_unreg_handler: un-registering ds_pri service\n");

	mutex_enter(&sp->lock);

	/*
	 * Note that if the service goes offline, we don't
	 * free up the current PRI data at hand. It is assumed
	 * that PRI DS service will only push new update when
	 * it comes online. We mark the state to indicate no
	 * DS PRI service is available. The current PRI data if
	 * available is provided to the consumers.
	 */
	sp->ds_pri_handle = DS_INVALID_HDL;
	sp->state &= ~DS_PRI_HAS_SERVICE;

	mutex_exit(&sp->lock);
}


static void
ds_pri_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	dev_info_t *dip = arg;
	ds_pri_state_t *sp;
	int instance;
	void *data;
	ds_pri_msg_t	*msgp;
	size_t	pri_size;

	msgp = (ds_pri_msg_t *)buf;

	/* make sure the header is at least valid */
	if (buflen < sizeof (msgp->hdr))
		return;

	DS_PRI_DBG("ds_pri_data_handler: msg buf len 0x%lx : type 0x%lx, "
	    "seqn 0x%lx\n", buflen, msgp->hdr.type, msgp->hdr.seq_num);

	instance = ddi_get_instance(dip);
	if ((sp = ddi_get_soft_state(ds_pri_statep, instance)) == NULL)
		return;

	mutex_enter(&sp->lock);

	ASSERT(sp->state & DS_PRI_HAS_SERVICE);

	switch (msgp->hdr.type) {
	case DS_PRI_DATA:	/* in response to a request from us */
		break;
	case DS_PRI_UPDATE:	/* aynch notification */
			/* our default response to this is to request the PRI */
		/* simply issue a request for the new PRI */
		request_pri(sp);
		goto done;
	default:	/* ignore garbage or unknown message types */
		goto done;
	}

	/*
	 * If there is no pending PRI request, then we've received a
	 * bogus data message ... so ignore it.
	 */

	if (!(sp->state & DS_PRI_REQUESTED)) {
		cmn_err(CE_WARN, "Received DS pri data without request");
		goto done;
	}

	/* response to a request therefore old PRI must be gone */
	ASSERT(!(sp->state & DS_PRI_HAS_PRI));
	ASSERT(sp->ds_pri_len == 0);
	ASSERT(sp->ds_pri == NULL);

	/* response seq_num should match our request seq_num */
	if (msgp->hdr.seq_num != sp->last_req_id) {
		cmn_err(CE_WARN, "Received DS pri data out of sequence with "
		    "request");
		goto done;
	}

	pri_size = buflen - sizeof (msgp->hdr);
	if (pri_size == 0) {
		cmn_err(CE_WARN, "Received DS pri data of size 0");
		goto done;
	}
	data = kmem_alloc(pri_size, KM_SLEEP);
	sp->ds_pri = data;
	sp->ds_pri_len = pri_size;
	bcopy(msgp->data, data, sp->ds_pri_len);
	sp->state &= ~DS_PRI_REQUESTED;
	sp->state |= DS_PRI_HAS_PRI;

	sp->gencount++;
	cv_broadcast(&sp->cv);

done:;
	mutex_exit(&sp->lock);
}

/*
 * Routine to get static PRI data from the Hypervisor.
 * If successful, this PRI data is the last known PRI
 * data generated since the last poweron reset.
 */
static uint64_t
ds_get_hv_pri(ds_pri_state_t *sp)
{
	uint64_t	status;
	uint64_t	pri_size;
	uint64_t	buf_size;
	uint64_t	buf_pa;
	caddr_t		buf_va = NULL;
	caddr_t		pri_data;

	/*
	 * Get pri buffer size by calling hcall with buffer size 0.
	 */
	pri_size = 0LL;
	status = hv_mach_pri((uint64_t)0, &pri_size);
	if (status == H_ENOTSUPPORTED || status == H_ENOACCESS) {
		/*
		 * hv_mach_pri() is not supported on a guest domain.
		 * Unregister pboot API group to prevent failures.
		 */
		(void) hsvc_unregister(&pboot_hsvc);
		hsvc_pboot_available = B_FALSE;
		DS_PRI_DBG("ds_get_hv_pri: hv_mach_pri service is not "
		    "available. errorno: 0x%lx\n", status);
		return (0);
	} else if (pri_size == 0) {
		return (1);
	} else {
		DS_PRI_DBG("ds_get_hv_pri: hv_mach_pri pri size: 0x%lx\n",
		    pri_size);
	}

	/*
	 * contig_mem_alloc requires size to be a power of 2.
	 * Increase size to next power of 2 if necessary.
	 */
	if (!ISP2(pri_size))
		buf_size = 1 << highbit(pri_size);
	DS_PRI_DBG("ds_get_hv_pri: buf_size = 0x%lx\n", buf_size);

	buf_va = contig_mem_alloc(buf_size);
	if (buf_va == NULL)
		return (1);

	buf_pa = va_to_pa(buf_va);
	DS_PRI_DBG("ds_get_hv_pri: buf_pa 0x%lx\n", buf_pa);
	status = hv_mach_pri(buf_pa, &pri_size);
	DS_PRI_DBG("ds_get_hv_pri: hv_mach_pri status = 0x%lx\n", status);

	if (status == H_EOK) {
		pri_data = kmem_alloc(pri_size, KM_SLEEP);
		sp->ds_pri = pri_data;
		sp->ds_pri_len = pri_size;
		bcopy(buf_va, pri_data, sp->ds_pri_len);
		sp->state |= DS_PRI_HAS_PRI;
		sp->gencount++;
	}

	contig_mem_free(buf_va, buf_size);

	return (status);
}
