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
 * sun4v domain services SNMP driver
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
#include <sys/ds_snmp.h>

#define	DS_SNMP_NAME		"ds_snmp"
#define	DS_SNMP_MAX_OPENS	256
#define	DS_BITS_IN_UINT64	64
#define	DS_MINOR_POOL_SZ	(DS_SNMP_MAX_OPENS / DS_BITS_IN_UINT64)
#define	DS_SNMP_MINOR_SHIFT	56
#define	DS_SNMP_DBG		if (ds_snmp_debug) printf

typedef	struct {
	uint64_t	seq_num;
	uint64_t	type;
} ds_snmp_msg_t;

typedef	enum {
	DS_SNMP_REQUEST	= 0,
	DS_SNMP_REPLY	= 1,
	DS_SNMP_ERROR = 2
} ds_snmp_msg_type_t;

typedef enum {
	DS_SNMP_READY = 0x0,
	DS_SNMP_REQUESTED = 0x1,
	DS_SNMP_DATA_AVL = 0x2,
	DS_SNMP_DATA_ERR = 0x3
} ds_snmp_flags_t;

/*
 * The single mutex 'lock' protects all the SNMP/DS variables in the state
 * structure.
 *
 * The condition variable 'state_cv' helps serialize write() calls for a
 * single descriptor. When write() is called, it sets a flag to indicate
 * that an SNMP request has been made to the agent. No more write()'s on
 * the same open descriptor will be allowed until this flag is cleared via
 * a matching read(), where the requested packet is consumed on arrival.
 * Read() then wakes up any waiters blocked in write() for sending the next
 * SNMP request to the agent.
 */
typedef struct ds_snmp_state {
	dev_info_t	*dip;
	int		instance;
	dev_t		dev;

	/* SNMP/DS */
	kmutex_t	lock;
	kcondvar_t	state_cv;
	ds_snmp_flags_t	state;
	void		*data;
	size_t		data_len;
	uint64_t	req_id;
	uint64_t	last_req_id;
	uint64_t	gencount;
	boolean_t	sc_reset;
} ds_snmp_state_t;


static uint_t		ds_snmp_debug = 0;
static void		*ds_snmp_statep = NULL;
static int		ds_snmp_instance = -1;
static dev_info_t	*ds_snmp_devi = NULL;

/*
 * The ds_snmp_lock mutex protects the following data global to the
 * driver.
 *
 * The ds_snmp_service_cv condition variable is used to resolve the
 * potential race between the registration of snmp service via a
 * ds_cap_init() in attach(), the acknowledgement of this registration
 * at a later time in ds_snmp_reg_handler(), and a possible open() at
 * a time inbetween. The ds_snmp_has_service and ds_snmp_handle are
 * used to indicate whether the registration acknowledgement has happened
 * or not.
 *
 * The ds_snmp_minor_pool[] is a bitmask to allocate and keep track of
 * minor numbers dynamically.
 */
static kmutex_t		ds_snmp_lock;
static kcondvar_t	ds_snmp_service_cv;
static int		ds_snmp_has_service = B_FALSE;
static ds_svc_hdl_t	ds_snmp_handle = DS_INVALID_HDL;
static uint64_t		ds_snmp_minor_pool[DS_MINOR_POOL_SZ];	/* bitmask */
static int		ds_snmp_num_opens = 0;

static int ds_snmp_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int ds_snmp_attach(dev_info_t *, ddi_attach_cmd_t);
static int ds_snmp_detach(dev_info_t *, ddi_detach_cmd_t);
static int ds_snmp_open(dev_t *, int, int, cred_t *);
static int ds_snmp_close(dev_t, int, int, cred_t *);
static int ds_snmp_read(dev_t, struct uio *, cred_t *);
static int ds_snmp_write(dev_t, struct uio *, cred_t *);
static int ds_snmp_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * DS Callbacks
 */
static void ds_snmp_reg_handler(ds_cb_arg_t, ds_ver_t *, ds_svc_hdl_t);
static void ds_snmp_unreg_handler(ds_cb_arg_t arg);
static void ds_snmp_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen);

/*
 * SNMP DS capability registration
 */
static ds_ver_t ds_snmp_ver_1_0 = { 1, 0 };
static ds_capability_t ds_snmp_cap = {
	"snmp",
	&ds_snmp_ver_1_0,
	1
};

/*
 * SNMP DS Client callback vector
 */
static ds_clnt_ops_t ds_snmp_ops = {
	ds_snmp_reg_handler,	/* ds_reg_cb */
	ds_snmp_unreg_handler,	/* ds_unreg_cb */
	ds_snmp_data_handler,	/* ds_data_cb */
	NULL			/* cb_arg */
};

/*
 * DS SNMP driver Ops Vector
 */
static struct cb_ops ds_snmp_cb_ops = {
	ds_snmp_open,		/* cb_open */
	ds_snmp_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	ds_snmp_read,		/* cb_read */
	ds_snmp_write,		/* cb_write */
	ds_snmp_ioctl,		/* cb_ioctl */
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

static struct dev_ops ds_snmp_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	ds_snmp_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	ds_snmp_attach,		/* devo_attach */
	ds_snmp_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&ds_snmp_cb_ops,	/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	nulldev			/* devo_power */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Domain Services SNMP Driver 1.0",
	&ds_snmp_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int retval;

	mutex_init(&ds_snmp_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ds_snmp_service_cv, NULL, CV_DRIVER, NULL);

	retval = ddi_soft_state_init(&ds_snmp_statep,
	    sizeof (ds_snmp_state_t), DS_SNMP_MAX_OPENS);
	if (retval != 0) {
		cv_destroy(&ds_snmp_service_cv);
		mutex_destroy(&ds_snmp_lock);
		return (retval);
	}

	retval = mod_install(&modlinkage);
	if (retval != 0) {
		ddi_soft_state_fini(&ds_snmp_statep);
		cv_destroy(&ds_snmp_service_cv);
		mutex_destroy(&ds_snmp_lock);
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

	ddi_soft_state_fini(&ds_snmp_statep);

	cv_destroy(&ds_snmp_service_cv);
	mutex_destroy(&ds_snmp_lock);

	return (retval);
}

/*ARGSUSED*/
static int
ds_snmp_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	ds_snmp_state_t *sp;
	int retval = DDI_FAILURE;

	ASSERT(resultp != NULL);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		sp = ddi_get_soft_state(ds_snmp_statep, getminor((dev_t)arg));
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
	}

	return (retval);
}

static int
ds_snmp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	rv;

	switch (cmd) {
	case DDI_ATTACH:
		if (ds_snmp_instance != -1)
			return (DDI_FAILURE);
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	ds_snmp_instance = ddi_get_instance(dip);
	if (ddi_create_minor_node(dip, DS_SNMP_NAME, S_IFCHR, ds_snmp_instance,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s@%d: Unable to create minor node",
		    DS_SNMP_NAME, ds_snmp_instance);
		return (DDI_FAILURE);
	}

	bzero(ds_snmp_minor_pool, DS_MINOR_POOL_SZ * sizeof (uint64_t));

	ds_snmp_ops.cb_arg = dip;
	if ((rv = ds_cap_init(&ds_snmp_cap, &ds_snmp_ops)) != 0) {
		cmn_err(CE_NOTE, "ds_cap_init failed: %d", rv);
		ddi_remove_minor_node(dip, NULL);
		ds_snmp_instance = -1;
		return (DDI_FAILURE);
	}

	ds_snmp_devi = dip;
	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
ds_snmp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		if (ds_snmp_instance == -1)
			return (DDI_FAILURE);
		break;

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	(void) ds_cap_fini(&ds_snmp_cap);

	ddi_remove_minor_node(ds_snmp_devi, NULL);
	bzero(ds_snmp_minor_pool, DS_MINOR_POOL_SZ * sizeof (uint64_t));

	ds_snmp_instance = -1;
	ds_snmp_devi = NULL;

	return (DDI_SUCCESS);
}

static minor_t
ds_snmp_get_minor(void)
{
	uint64_t	val;
	int		i, ndx;
	minor_t		minor;

	mutex_enter(&ds_snmp_lock);
	for (ndx = 0; ndx < DS_MINOR_POOL_SZ; ndx++) {
		val = ds_snmp_minor_pool[ndx];
		for (i = 0; i < DS_BITS_IN_UINT64; i++) {
			if ((val & 0x1) == 0) {
				ds_snmp_minor_pool[ndx] |= ((uint64_t)1 << i);
				ds_snmp_num_opens++;
				mutex_exit(&ds_snmp_lock);

				minor = ndx * DS_BITS_IN_UINT64 + i + 1;

				return (minor);
			}
			val >>= 1;
		}
	}
	mutex_exit(&ds_snmp_lock);

	return (0);
}

static void
ds_snmp_rel_minor(minor_t minor)
{
	int	i, ndx;

	ndx = (minor - 1) / DS_BITS_IN_UINT64;
	i = (minor - 1) % DS_BITS_IN_UINT64;

	ASSERT(ndx < DS_MINOR_POOL_SZ);

	mutex_enter(&ds_snmp_lock);

	ds_snmp_num_opens--;
	ds_snmp_minor_pool[ndx] &= ~((uint64_t)1 << i);

	mutex_exit(&ds_snmp_lock);
}

static boolean_t
ds_snmp_is_open(minor_t minor)
{
	uint64_t	val;
	int		i, ndx;

	ndx = (minor - 1) / DS_BITS_IN_UINT64;
	i = (minor - 1) % DS_BITS_IN_UINT64;

	val = ((uint64_t)1 << i);
	if (ds_snmp_minor_pool[ndx] & val)
		return (B_TRUE);
	else
		return (B_FALSE);
}

static int
ds_snmp_create_state(dev_t *devp)
{
	major_t	major;
	minor_t	minor;
	ds_snmp_state_t	*sp;

	if ((minor = ds_snmp_get_minor()) == 0)
		return (EMFILE);

	if (ddi_soft_state_zalloc(ds_snmp_statep, minor) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s@%d: Unable to allocate state",
		    DS_SNMP_NAME, minor);
		ds_snmp_rel_minor(minor);
		return (ENOMEM);
	}

	sp = ddi_get_soft_state(ds_snmp_statep, minor);
	if (devp != NULL)
		major = getemajor(*devp);
	else
		major = ddi_driver_major(ds_snmp_devi);

	sp->dev = makedevice(major, minor);
	if (devp != NULL)
		*devp = sp->dev;

	sp->instance = minor;
	sp->data = NULL;
	sp->data_len = 0;
	sp->req_id = 0;
	sp->last_req_id = 0;
	sp->state = DS_SNMP_READY;
	sp->sc_reset = B_FALSE;

	mutex_init(&sp->lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sp->state_cv, NULL, CV_DRIVER, NULL);

	return (0);
}

static int
ds_snmp_destroy_state(dev_t dev)
{
	ds_snmp_state_t	*sp;
	minor_t	minor;

	minor = getminor(dev);

	if ((sp = ddi_get_soft_state(ds_snmp_statep, minor)) == NULL)
		return (ENXIO);

	ASSERT(sp->instance == minor);

	/*
	 * If the app has not exited cleanly, the data may not have been
	 * read/memory freed, hence take care of that here
	 */
	if (sp->data) {
		kmem_free(sp->data, sp->data_len);
	}
	cv_destroy(&sp->state_cv);
	mutex_destroy(&sp->lock);

	ddi_soft_state_free(ds_snmp_statep, minor);
	ds_snmp_rel_minor(minor);

	return (0);
}

/*ARGSUSED*/
static int
ds_snmp_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{

	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (ds_snmp_instance == -1)
		return (ENXIO);

	/*
	 * Avoid possible race condition - ds service may not be there yet
	 */
	mutex_enter(&ds_snmp_lock);
	while (ds_snmp_has_service == B_FALSE) {
		if (cv_wait_sig(&ds_snmp_service_cv, &ds_snmp_lock) == 0) {
			mutex_exit(&ds_snmp_lock);
			return (EINTR);
		}
	}
	mutex_exit(&ds_snmp_lock);

	return (ds_snmp_create_state(devp));
}


/*ARGSUSED*/
static int
ds_snmp_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (ds_snmp_instance == -1)
		return (ENXIO);

	if (ds_snmp_handle == DS_INVALID_HDL)
		return (EIO);

	return (ds_snmp_destroy_state(dev));
}

/*ARGSUSED*/
static int
ds_snmp_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	ds_snmp_state_t *sp;
	minor_t	minor;
	size_t len;
	int retval;
	caddr_t tmpbufp = (caddr_t)NULL;

	/*
	 * Given that now we can have sc resets happening at any
	 * time, it is possible that it happened since the last time
	 * we issued a read, write or ioctl.  If so, we need to wait
	 * for the unreg-reg pair to complete before we can do
	 * anything.
	 */
	mutex_enter(&ds_snmp_lock);
	while (ds_snmp_has_service == B_FALSE) {
		DS_SNMP_DBG("ds_snmp_read: waiting for service\n");
		if (cv_wait_sig(&ds_snmp_service_cv, &ds_snmp_lock) == 0) {
			mutex_exit(&ds_snmp_lock);
			return (EINTR);
		}
	}
	mutex_exit(&ds_snmp_lock);

	if ((len = uiop->uio_resid) == 0)
		return (0);

	minor = getminor(dev);
	if ((sp = ddi_get_soft_state(ds_snmp_statep, minor)) == NULL)
		return (ENXIO);

	mutex_enter(&sp->lock);

	if (sp->sc_reset == B_TRUE) {
		mutex_exit(&sp->lock);
		return (ECANCELED);
	}

	/*
	 * Block or bail if there is no SNMP data
	 */
	if (sp->state != DS_SNMP_DATA_AVL && sp->state != DS_SNMP_DATA_ERR) {
		DS_SNMP_DBG("ds_snmp_read: no SNMP data\n");
		if (uiop->uio_fmode & (FNDELAY | FNONBLOCK)) {
			mutex_exit(&sp->lock);
			return (EAGAIN);
		}
		while (sp->state != DS_SNMP_DATA_AVL &&
		    sp->state != DS_SNMP_DATA_ERR) {
			if (cv_wait_sig(&sp->state_cv, &sp->lock) == 0) {
				mutex_exit(&sp->lock);
				return (EINTR);
			}
		}
	}

	/*
	 * If there has been an error, it could be because the agent
	 * returned failure and there is no data to read, or an ldc-reset
	 * has happened.  Figure out which and return appropriate
	 * error to the caller.
	 */
	if (sp->state == DS_SNMP_DATA_ERR) {
		if (sp->sc_reset == B_TRUE) {
			mutex_exit(&sp->lock);
			DS_SNMP_DBG("ds_snmp_read: sc got reset, "
			    "returning ECANCELED\n");
			return (ECANCELED);
		} else {
			sp->state = DS_SNMP_READY;
			cv_broadcast(&sp->state_cv);
			mutex_exit(&sp->lock);
			DS_SNMP_DBG("ds_snmp_read: data error, "
			    "returning EIO\n");
			return (EIO);
		}
	}

	if (len > sp->data_len)
		len = sp->data_len;

	tmpbufp = kmem_alloc(len, KM_SLEEP);

	bcopy(sp->data, (void *)tmpbufp, len);
	kmem_free(sp->data, sp->data_len);
	sp->data = (caddr_t)NULL;
	sp->data_len = 0;

	/*
	 * SNMP data has been consumed, wake up anyone waiting to send
	 */
	sp->state = DS_SNMP_READY;
	cv_broadcast(&sp->state_cv);

	mutex_exit(&sp->lock);

	retval = uiomove(tmpbufp, len, UIO_READ, uiop);
	kmem_free(tmpbufp, len);

	return (retval);
}

/*ARGSUSED*/
static int
ds_snmp_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	ds_snmp_state_t *sp;
	ds_snmp_msg_t hdr;
	minor_t minor;
	size_t len;
	caddr_t tmpbufp;

	/*
	 * Check if there was an sc reset; if yes, wait until we have the
	 * service back again.
	 */
	mutex_enter(&ds_snmp_lock);
	while (ds_snmp_has_service == B_FALSE) {
		DS_SNMP_DBG("ds_snmp_write: waiting for service\n");
		if (cv_wait_sig(&ds_snmp_service_cv, &ds_snmp_lock) == 0) {
			mutex_exit(&ds_snmp_lock);
			return (EINTR);
		}
	}
	mutex_exit(&ds_snmp_lock);

	minor = getminor(dev);
	if ((sp = ddi_get_soft_state(ds_snmp_statep, minor)) == NULL)
		return (ENXIO);

	len = uiop->uio_resid + sizeof (ds_snmp_msg_t);
	tmpbufp = kmem_alloc(len, KM_SLEEP);

	if (uiomove(tmpbufp + sizeof (ds_snmp_msg_t),
	    len - sizeof (ds_snmp_msg_t), UIO_WRITE, uiop) != 0) {
		kmem_free(tmpbufp, len);
		return (EIO);
	}

	mutex_enter(&sp->lock);

	if (sp->sc_reset == B_TRUE) {
		mutex_exit(&sp->lock);
		kmem_free(tmpbufp, len);
		DS_SNMP_DBG("ds_snmp_write: sc_reset is TRUE, "
		    "returning ECANCELD\n");
		return (ECANCELED);
	}

	/*
	 * wait if earlier transaction is not yet completed
	 */
	while (sp->state != DS_SNMP_READY) {
		if (cv_wait_sig(&sp->state_cv, &sp->lock) == 0) {
			mutex_exit(&sp->lock);
			kmem_free(tmpbufp, len);
			return (EINTR);
		}
		/*
		 * Normally, only a reader would ever wake us up. But if we
		 * did get signalled with an ERROR, it could only mean there
		 * was an sc reset and there's no point waiting; we need to
		 * fail this write().
		 */
		if (sp->state == DS_SNMP_DATA_ERR && sp->sc_reset == B_TRUE) {
			DS_SNMP_DBG("ds_snmp_write: woke up with an sc_reset, "
			    "returning ECANCELED\n");
			mutex_exit(&sp->lock);
			kmem_free(tmpbufp, len);
			return (ECANCELED);
		}
	}

	if (sp->req_id == (((uint64_t)1 << DS_SNMP_MINOR_SHIFT) - 1))
		sp->req_id = 0; /* Reset */

	hdr.seq_num = ((uint64_t)minor << DS_SNMP_MINOR_SHIFT) | sp->req_id;
	sp->last_req_id = hdr.seq_num;
	(sp->req_id)++;

	/*
	 * Set state to SNMP_REQUESTED, but don't wakeup anyone yet
	 */
	sp->state = DS_SNMP_REQUESTED;

	mutex_exit(&sp->lock);

	hdr.type = DS_SNMP_REQUEST;
	bcopy((void *)&hdr, (void *)tmpbufp, sizeof (hdr));

	/*
	 * If the service went away since the time we entered this
	 * routine and now, tough luck. Just ignore the current
	 * write() and return.
	 */
	mutex_enter(&ds_snmp_lock);
	if (ds_snmp_has_service == B_FALSE) {
		DS_SNMP_DBG("ds_snmp_write: service went away, aborting "
		    "write, returning ECANCELED\n");
		mutex_exit(&ds_snmp_lock);
		kmem_free(tmpbufp, len);
		return (ECANCELED);
	}
	DS_SNMP_DBG("ds_snmp_write: ds_cap_send(0x%lx, %lu) called.\n",
	    ds_snmp_handle, len);
	(void) ds_cap_send(ds_snmp_handle, tmpbufp, len);
	mutex_exit(&ds_snmp_lock);

	kmem_free(tmpbufp, len);

	return (0);
}

/*ARGSUSED*/
static int
ds_snmp_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	ds_snmp_state_t *sp;
	struct dssnmp_info info;
	minor_t	minor;

	/*
	 * Check if there was an sc reset; if yes, wait until we have the
	 * service back again.
	 */
	mutex_enter(&ds_snmp_lock);
	while (ds_snmp_has_service == B_FALSE) {
		DS_SNMP_DBG("ds_snmp_ioctl: waiting for service\n");
		if (cv_wait_sig(&ds_snmp_service_cv, &ds_snmp_lock) == 0) {
			mutex_exit(&ds_snmp_lock);
			return (EINTR);
		}
	}
	mutex_exit(&ds_snmp_lock);

	DS_SNMP_DBG("ds_snmp_ioctl: hdl=0x%lx\n", ds_snmp_handle);

	minor = getminor(dev);
	if ((sp = ddi_get_soft_state(ds_snmp_statep, minor)) == NULL)
		return (ENXIO);

	if (!(mode & FREAD))
		return (EACCES);

	switch (cmd) {
	case DSSNMP_GETINFO:
		mutex_enter(&sp->lock);

		if (sp->sc_reset == B_TRUE) {
			mutex_exit(&sp->lock);
			DS_SNMP_DBG("ds_snmp_ioctl: returning ECANCELED\n");
			return (ECANCELED);
		}

		while (sp->state != DS_SNMP_DATA_AVL &&
		    sp->state != DS_SNMP_DATA_ERR) {
			DS_SNMP_DBG("ds_snmp_ioctl: state=%d, sc_reset=%d, "
			    "waiting for data\n", sp->state, sp->sc_reset);
			if (cv_wait_sig(&sp->state_cv, &sp->lock) == 0) {
				sp->state = DS_SNMP_READY;
				mutex_exit(&sp->lock);
				return (EINTR);
			}
		}
		DS_SNMP_DBG("ds_snmp_ioctl: state=%d, sc_reset=%d, "
		    "out of wait!\n", sp->state, sp->sc_reset);

		/*
		 * If there has been an error, it could be because the
		 * agent returned failure and there is no data to read,
		 * or an ldc-reset has happened.  Figure out which and
		 * return appropriate error to the caller.
		 */
		if (sp->state == DS_SNMP_DATA_ERR) {
			if (sp->sc_reset == B_TRUE) {
				mutex_exit(&sp->lock);
				DS_SNMP_DBG("ds_snmp_ioctl: sc_reset=TRUE "
				    "returning ECANCELED\n");
				return (ECANCELED);
			} else {
				sp->state = DS_SNMP_READY;
				cv_broadcast(&sp->state_cv);
				mutex_exit(&sp->lock);
				DS_SNMP_DBG("ds_snmp_ioctl: sc_reset=FALSE "
				    "returning EIO\n");
				return (EIO);
			}
		}

		info.size = sp->data_len;
		info.token = sp->gencount;

		mutex_exit(&sp->lock);

		if (ddi_copyout(&info, (void *)arg, sizeof (info), mode) != 0)
			return (EFAULT);
		break;

	case DSSNMP_CLRLNKRESET:
		mutex_enter(&sp->lock);

		DS_SNMP_DBG("ds_snmp_ioctl: DSSNMP_CLRLNKRESET\n");
		DS_SNMP_DBG("ds_snmp_ioctl: sc_reset=%d\n", sp->sc_reset);

		if (sp->sc_reset == B_TRUE) {
			if (sp->data) {
				DS_SNMP_DBG("ds_snmp_ioctl: data=%p, len=%lu\n",
				    sp->data, sp->data_len);
				kmem_free(sp->data, sp->data_len);
			}
			sp->data = NULL;
			sp->data_len = 0;
			sp->state = DS_SNMP_READY;
			sp->req_id = 0;
			sp->last_req_id = 0;
			sp->sc_reset = B_FALSE;
		}
		mutex_exit(&sp->lock);
		break;

	default:
		return (ENOTTY);
	}

	return (0);
}

/*
 * DS Callbacks
 */
/*ARGSUSED*/
static void
ds_snmp_reg_handler(ds_cb_arg_t arg, ds_ver_t *ver, ds_svc_hdl_t hdl)
{
	DS_SNMP_DBG("ds_snmp_reg_handler: registering handle 0x%lx for version "
	    "0x%x:0x%x\n", (uint64_t)hdl, ver->major, ver->minor);

	mutex_enter(&ds_snmp_lock);

	ASSERT(ds_snmp_handle == DS_INVALID_HDL);

	ds_snmp_handle = hdl;
	ds_snmp_has_service = B_TRUE;

	cv_broadcast(&ds_snmp_service_cv);

	mutex_exit(&ds_snmp_lock);

}

/*ARGSUSED*/
static void
ds_snmp_unreg_handler(ds_cb_arg_t arg)
{
	minor_t minor;
	ds_snmp_state_t *sp;

	DS_SNMP_DBG("ds_snmp_unreg_handler: un-registering ds_snmp service\n");

	mutex_enter(&ds_snmp_lock);

	if (ds_snmp_num_opens) {
		DS_SNMP_DBG("ds_snmp_unreg_handler: %d opens, sc reset!\n",
		    ds_snmp_num_opens);
		for (minor = 1; minor <= DS_SNMP_MAX_OPENS; minor++) {
			if (ds_snmp_is_open(minor)) {
				DS_SNMP_DBG("ds_snmp_unreg_handler: minor %d "
				    "open\n", minor);
				sp = ddi_get_soft_state(ds_snmp_statep, minor);
				if (sp == NULL)
					continue;

				/*
				 * Set the sc_reset flag and break any waiters
				 * out of their existing reads/writes/ioctls.
				 */
				DS_SNMP_DBG("ds_snmp_unreg_hdlr: about to "
				    "signal waiters\n");
				mutex_enter(&sp->lock);
				sp->sc_reset = B_TRUE;
				sp->state = DS_SNMP_DATA_ERR;
				cv_broadcast(&sp->state_cv);
				mutex_exit(&sp->lock);
			}
		}
	}

	ds_snmp_handle = DS_INVALID_HDL;
	ds_snmp_has_service = B_FALSE;

	DS_SNMP_DBG("ds_snmp_unreg_handler: handle invalidated\n");

	mutex_exit(&ds_snmp_lock);
}

/*ARGSUSED*/
static void
ds_snmp_data_handler(ds_cb_arg_t arg, void *buf, size_t buflen)
{
	ds_snmp_state_t *sp;
	ds_snmp_msg_t   hdr;
	size_t  	snmp_size;
	minor_t 	minor;

	/*
	 * Make sure the header is at least valid
	 */
	if (buflen < sizeof (hdr)) {
		cmn_err(CE_WARN,
		"ds_snmp_data_handler: buflen <%lu> too small", buflen);
		return;
	}

	ASSERT(buf != NULL);
	bcopy(buf, (void *)&hdr, sizeof (hdr));

	DS_SNMP_DBG("ds_snmp_data_handler: msg buf len 0x%lx : type 0x%lx, "
	    "seqn 0x%lx\n", buflen, hdr.type, hdr.seq_num);

	minor = (int)(hdr.seq_num >> DS_SNMP_MINOR_SHIFT);
	if ((sp = ddi_get_soft_state(ds_snmp_statep, minor)) == NULL)
		return;

	mutex_enter(&sp->lock);

	/*
	 * If there is no pending SNMP request, then we've received
	 * bogus data or an SNMP trap or the reader was interrupted.
	 * Since we don't yet support SNMP traps, ignore it.
	 */
	if (sp->state != DS_SNMP_REQUESTED) {
		DS_SNMP_DBG("Received SNMP data without request");
		mutex_exit(&sp->lock);
		return;
	}

	/*
	 * Response to a request therefore old SNMP must've been consumed
	 */
	ASSERT(sp->data_len == 0);
	ASSERT(sp->data == NULL);

	/*
	 * Response seq_num should match our request seq_num
	 */
	if (hdr.seq_num != sp->last_req_id) {
		cmn_err(CE_WARN, "Received DS snmp data out of sequence with "
		    "request");
		mutex_exit(&sp->lock);
		return;
	}

	if (hdr.type == DS_SNMP_ERROR) {
		sp->state = DS_SNMP_DATA_ERR;
		DS_SNMP_DBG("ds_snmp_data_handler: hdr.type = DS_SNMP_ERROR\n");
	} else {
		snmp_size = buflen - sizeof (ds_snmp_msg_t);
		sp->data = kmem_alloc(snmp_size, KM_SLEEP);
		sp->data_len = snmp_size;
		sp->state = DS_SNMP_DATA_AVL;

		bcopy((caddr_t)buf + sizeof (ds_snmp_msg_t),
		    sp->data, sp->data_len);
	}

	sp->gencount++;

	/*
	 * Wake up any readers waiting for data
	 */
	cv_broadcast(&sp->state_cv);
	mutex_exit(&sp->lock);
}
