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


#include <sys/time.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>

#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/callb.h>
#include <sys/disp.h>
#include <sys/strlog.h>
#include <sys/file.h>

#include <sys/uadmin.h>
#include <sys/machsystm.h>
#include <sys/hypervisor_api.h>
#include <sys/hsvc.h>
#include <sys/glvc.h>

/*
 * Global Variables - can be patched from Solaris
 * ==============================================
 */

/* bit defination in virtual device register */
#define	GLVC_REG_RECV		0x0001
#define	GLVC_REG_RECV_ENA	0x0002
#define	GLVC_REG_SEND		0x0004
#define	GLVC_REG_SEND_ENA	0x0008
#define	GLVC_REG_ERR		0x8000

/*
 * For interrupt mode
 */
#define	GLVC_MODE_NONE		0
#define	GLVC_POLLING_MODE	1
#define	GLVC_INTR_MODE		2

/*
 * For open
 */
#define	GLVC_NO_OPEN		0
#define	GLVC_OPEN		1
#define	GLVC_EXCL_OPEN		2

/*
 * For timeout polling, in microsecond.
 */
#define	GLVC_TIMEOUT_POLL	5000000		/* Timeout in intr mode */
#define	GLVC_POLLMODE_POLL	500000		/* Interval in polling mode */

/*
 * For debug printing
 */
#define	_PRINTF			printf
#define	DPRINTF(args)		if (glvc_debug) _PRINTF args;

/*
 * Driver entry points
 */
static int	glvc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	glvc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int	glvc_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p);
static int	glvc_close(dev_t dev, int flag, int otyp, cred_t *cred_p);
static int	glvc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *cred_p, int *rval_p);
static int	glvc_read(dev_t dev, struct uio *uiop, cred_t *credp);
static int	glvc_write(dev_t dev, struct uio *uiop, cred_t *credp);

static struct cb_ops glvc_cb_ops = {
	glvc_open,	/* open */
	glvc_close,	/* close */
	nodev,		/* strategy() */
	nodev,		/* print() */
	nodev,		/* dump() */
	glvc_read,	/* read() */
	glvc_write,	/* write() */
	glvc_ioctl,	/* ioctl() */
	nodev,		/* devmap() */
	nodev,		/* mmap() */
	ddi_segmap,	/* segmap() */
	nochpoll,	/* poll() */
	ddi_prop_op,    /* prop_op() */
	NULL,		/* cb_str */
	D_NEW | D_MP	/* cb_flag */
};


static struct dev_ops glvc_ops = {
	DEVO_REV,
	0,			/* ref count */
	ddi_getinfo_1to1,	/* getinfo() */
	nulldev,		/* identify() */
	nulldev,		/* probe() */
	glvc_attach,		/* attach() */
	glvc_detach,		/* detach */
	nodev,			/* reset */
	&glvc_cb_ops,		/* pointer to cb_ops structure */
	(struct bus_ops *)NULL,
	nulldev,		/* power() */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Loadable module support.
 */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,			/* Type of module. This is a driver */
	"Sun4v virtual channel driver",	/* Name of the module */
	&glvc_ops			/* pointer to the dev_ops structure */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

typedef struct glvc_soft_state {
	dev_info_t *dip;	/* dev info of myself */
	uint64_t s_id;		/* service id for this node */
	uint64_t mtu;		/* max transmit unit size */
	uint64_t flag;		/* flag register */
	kmutex_t open_mutex;	/* protect open_state flag */
	uint8_t open_state;	/* no-open, open or open exclusively */
	kmutex_t recv_mutex;
	kmutex_t send_complete_mutex;
	uint8_t send_complete_flag;	/* 1 = send completed */
	uint8_t intr_mode;	/* 1 = polling mode, 2 = interrupt mode */
	clock_t polling_interval;
	ddi_softintr_t poll_mode_softint_id;
	kcondvar_t recv_cv;
	kcondvar_t send_complete_cv;
	kmutex_t statusreg_mutex;	/* Protects status register */
	char *mb_recv_buf;
	char *mb_send_buf;
	uint64_t mb_recv_buf_pa;
	uint64_t mb_send_buf_pa;
} glvc_soft_state_t;

/*
 * Hypervisor VSC api versioning information for glvc driver.
 */
static uint64_t	glvc_vsc_min_ver; /* Negotiated VSC API minor version */
static uint_t glvc_vsc_users = 0; /* VSC API users */
static kmutex_t glvc_vsc_users_mutex;	/* Mutex to protect user count */

static hsvc_info_t glvc_hsvc = {
	HSVC_REV_1, NULL, HSVC_GROUP_VSC, GLVC_VSC_MAJOR_VER,
	GLVC_VSC_MINOR_VER, "glvc"
};

/*
 * Module Variables
 * ================
 */

/*
 * functions local to this driver.
 */
static int	glvc_add_intr_handlers(dev_info_t *dip);
static int	glvc_remove_intr_handlers(dev_info_t *dip);
static uint_t	glvc_intr(caddr_t arg);
static int	glvc_peek(glvc_soft_state_t *softsp,
    glvc_xport_msg_peek_t *msg_peek);
static uint_t	glvc_soft_intr(caddr_t arg);
static int	glvc_emap_h2s(uint64_t hv_errcode);
static int	glvc_ioctl_opt_op(glvc_soft_state_t *softsp,
    intptr_t arg, int mode);

/*
 * Driver globals
 */
static void *glvc_ssp; /* pointer to driver soft state */

static uint_t glvc_debug = 0;

int
_init(void)
{
	int	error = 0;

	if ((error = ddi_soft_state_init(&glvc_ssp,
	    sizeof (glvc_soft_state_t), 1)) != 0)
		return (error);

	/*
	 * Initialize the mutex for global data structure
	 */
	mutex_init(&glvc_vsc_users_mutex, NULL, MUTEX_DRIVER, NULL);

	error = mod_install(&modlinkage);

	return (error);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


int
_fini(void)
{
	int	error = 0;

	error = mod_remove(&modlinkage);
	if (error)
		return (error);

	mutex_destroy(&glvc_vsc_users_mutex);

	ddi_soft_state_fini(&glvc_ssp);
	return (0);
}


static int
glvc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	int			err;
	glvc_soft_state_t	*softsp;

	switch (cmd) {
	case DDI_ATTACH:
		instance = ddi_get_instance(dip);

		/*
		 * Negotiate the API version for VSC hypervisor services.
		 */
		mutex_enter(&glvc_vsc_users_mutex);
		if (glvc_vsc_users == 0 &&
		    (err = hsvc_register(&glvc_hsvc, &glvc_vsc_min_ver))
		    != 0) {
			cmn_err(CE_WARN, "%s: cannot negotiate hypervisor "
			    "services group: 0x%lx major: 0x%lx minor: 0x%lx "
			    "errno: %d\n", glvc_hsvc.hsvc_modname,
			    glvc_hsvc.hsvc_group, glvc_hsvc.hsvc_major,
			    glvc_hsvc.hsvc_minor, err);

			mutex_exit(&glvc_vsc_users_mutex);
			return (DDI_FAILURE);
		} else {
			glvc_vsc_users++;
			mutex_exit(&glvc_vsc_users_mutex);
		}

		DPRINTF(("Glvc instance %d negotiated VSC API version, "
		    " major 0x%lx minor 0x%lx\n",
		    instance, glvc_hsvc.hsvc_major, glvc_vsc_min_ver));

		if (ddi_soft_state_zalloc(glvc_ssp, instance)
		    != DDI_SUCCESS) {
			mutex_enter(&glvc_vsc_users_mutex);
			if (--glvc_vsc_users == 0)
				(void) hsvc_unregister(&glvc_hsvc);
			mutex_exit(&glvc_vsc_users_mutex);
			return (DDI_FAILURE);
		}

		softsp = ddi_get_soft_state(glvc_ssp, instance);

		/* Set the dip in the soft state */
		softsp->dip = dip;

		softsp->open_state = GLVC_NO_OPEN;
		softsp->send_complete_flag = 1;

		glvc_debug = (uint64_t)ddi_getprop(DDI_DEV_T_ANY,
		    softsp->dip, DDI_PROP_DONTPASS, "glvc_debug", glvc_debug);

		if ((softsp->s_id = (uint64_t)ddi_getprop(DDI_DEV_T_ANY,
		    softsp->dip, DDI_PROP_DONTPASS, "channel#", -1))
		    == -1) {
			cmn_err(CE_WARN, "Failed to get channel#");
			goto bad;
		}

		if ((softsp->mtu = (uint64_t)ddi_getprop(DDI_DEV_T_ANY,
		    softsp->dip, DDI_PROP_DONTPASS, "mtu", -1))
		    <= 0) {
			cmn_err(CE_WARN, "Failed to get mtu");
			goto bad;
		}

		softsp->mb_recv_buf =
		    (char *)kmem_zalloc(softsp->mtu, KM_NOSLEEP);
		if (softsp->mb_recv_buf == NULL) {
			cmn_err(CE_WARN, "Failed to alloc mem for recv buf");
			goto bad;
		}
		softsp->mb_recv_buf_pa =
		    va_to_pa((caddr_t)softsp->mb_recv_buf);

		softsp->mb_send_buf =
		    (char *)kmem_zalloc(softsp->mtu, KM_NOSLEEP);
		if (softsp->mb_send_buf == NULL) {
			kmem_free(softsp->mb_recv_buf, softsp->mtu);
			cmn_err(CE_WARN, "Failed to alloc mem for send buf");
			goto bad;
		}
		softsp->mb_send_buf_pa =
		    va_to_pa((caddr_t)softsp->mb_send_buf);

		err = ddi_create_minor_node(dip, "glvc", S_IFCHR,
		    instance, DDI_PSEUDO, 0);
		if (err != DDI_SUCCESS) {
			kmem_free(softsp->mb_recv_buf, softsp->mtu);
			kmem_free(softsp->mb_send_buf, softsp->mtu);
			cmn_err(CE_WARN, "Failed to create minor node");
			goto bad;
		}

		mutex_init(&(softsp->open_mutex), NULL, MUTEX_DRIVER, NULL);
		mutex_init(&(softsp->recv_mutex), NULL, MUTEX_DRIVER, NULL);
		mutex_init(&(softsp->send_complete_mutex), NULL,
		    MUTEX_DRIVER, NULL);
		mutex_init(&(softsp->statusreg_mutex), NULL,
		    MUTEX_DRIVER, NULL);
		cv_init(&(softsp->recv_cv), NULL, CV_DRIVER, NULL);
		cv_init(&(softsp->send_complete_cv), NULL, CV_DRIVER, NULL);

		/*
		 * Add the handlers which watch for unsolicited messages
		 * and post event to Sysevent Framework.
		 */
		err = glvc_add_intr_handlers(dip);
		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to add intr handler");
			kmem_free(softsp->mb_recv_buf, softsp->mtu);
			kmem_free(softsp->mb_send_buf, softsp->mtu);
			ddi_remove_minor_node(dip, NULL);
			goto bad1;
		}

		/*
		 * Trigger soft interrupt to start polling device if
		 * we are in the polling mode
		 */
		if (softsp->intr_mode == GLVC_POLLING_MODE)
			ddi_trigger_softintr(softsp->poll_mode_softint_id);

		ddi_report_dev(dip);

		DPRINTF(("glvc instance %d, s_id %lu,"
		    "mtu %lu attached\n", instance, softsp->s_id,
		    softsp->mtu));

		return (DDI_SUCCESS);
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

bad1:
	cv_destroy(&(softsp->send_complete_cv));
	cv_destroy(&(softsp->recv_cv));
	mutex_destroy(&(softsp->open_mutex));
	mutex_destroy(&(softsp->send_complete_mutex));
	mutex_destroy(&(softsp->recv_mutex));
	mutex_destroy(&(softsp->statusreg_mutex));

bad:
	mutex_enter(&glvc_vsc_users_mutex);
	if (--glvc_vsc_users == 0)
		(void) hsvc_unregister(&glvc_hsvc);
	mutex_exit(&glvc_vsc_users_mutex);
	cmn_err(CE_WARN, "glvc: attach failed for instance %d\n", instance);
	ddi_soft_state_free(glvc_ssp, instance);
	return (DDI_FAILURE);
}


static int
glvc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int	instance;
	int	err;
	glvc_soft_state_t	*softsp;


	switch (cmd) {
	case DDI_DETACH:
		instance = ddi_get_instance(dip);

		softsp = ddi_get_soft_state(glvc_ssp, instance);

		cv_destroy(&(softsp->send_complete_cv));
		cv_destroy(&(softsp->recv_cv));
		mutex_destroy(&(softsp->open_mutex));
		mutex_destroy(&(softsp->statusreg_mutex));
		mutex_destroy(&(softsp->send_complete_mutex));
		mutex_destroy(&(softsp->recv_mutex));

		kmem_free(softsp->mb_recv_buf, softsp->mtu);
		kmem_free(softsp->mb_send_buf, softsp->mtu);

		err = glvc_remove_intr_handlers(dip);

		if (err != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to remove event handlers");
			return (DDI_FAILURE);
		}

		ddi_remove_minor_node(dip, NULL);

		ddi_soft_state_free(glvc_ssp, instance);

		mutex_enter(&glvc_vsc_users_mutex);
		if (--glvc_vsc_users == 0)
			(void) hsvc_unregister(&glvc_hsvc);
		mutex_exit(&glvc_vsc_users_mutex);

		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
glvc_add_intr_handlers(dev_info_t *dip)
{
	int	instance;
	glvc_soft_state_t	*softsp;
	int	err = DDI_FAILURE;
	uint64_t polling_interval;

	instance = ddi_get_instance(dip);
	softsp = ddi_get_soft_state(glvc_ssp, instance);

	if ((uint64_t)ddi_getprop(DDI_DEV_T_ANY, softsp->dip,
	    DDI_PROP_DONTPASS, "flags", -1) != -1) {
		err = ddi_add_intr(dip, 0, NULL, NULL, glvc_intr,
		    (caddr_t)softsp);
		if (err != DDI_SUCCESS)
			cmn_err(CE_NOTE, "glvc, instance %d"
			    " ddi_add_intr() failed, using"
			    " polling mode", instance);
	}

	if (err == DDI_SUCCESS) {
		softsp->intr_mode = GLVC_INTR_MODE;
		polling_interval = (uint64_t)ddi_getprop(DDI_DEV_T_ANY,
		    softsp->dip, DDI_PROP_DONTPASS, "intrmode_poll",
		    GLVC_TIMEOUT_POLL);
		DPRINTF(("glvc instance %d polling_interval = %lu\n",
		    instance, polling_interval));
		softsp->polling_interval = drv_usectohz(polling_interval);
	} else {
		DPRINTF(("glvc, instance %d  intr support not found, "
		    "err = %d , use polling mode", instance, err));
		softsp->intr_mode = GLVC_POLLING_MODE;
		polling_interval =
		    (uint64_t)ddi_getprop(DDI_DEV_T_ANY,
		    softsp->dip, DDI_PROP_DONTPASS, "pollmode_poll",
		    GLVC_POLLMODE_POLL);
		DPRINTF(("glvc instance %d polling_interval = %lu\n",
		    instance, polling_interval));
		softsp->polling_interval =
		    drv_usectohz(polling_interval);
	}

	/* Now enable interrupt bits in the status register */
	if (softsp->intr_mode == GLVC_INTR_MODE) {
		err = hv_service_setstatus(softsp->s_id,
		    GLVC_REG_RECV_ENA|GLVC_REG_SEND_ENA);
		if (err != H_EOK) {
			cmn_err(CE_NOTE, "glvc instance %d"
			    " cannot enable receive interrupt\n",
			    instance);
			return (DDI_FAILURE);
		}
	}


	err = ddi_add_softintr(dip, DDI_SOFTINT_LOW,
	    &softsp->poll_mode_softint_id, NULL, NULL,
	    glvc_soft_intr, (caddr_t)softsp);

	return (err);
}

static int
glvc_remove_intr_handlers(dev_info_t *dip)
{
	int	instance;
	glvc_soft_state_t	*softsp;

	instance = ddi_get_instance(dip);
	softsp = ddi_get_soft_state(glvc_ssp, instance);

	if (softsp->intr_mode ==  GLVC_INTR_MODE)
		ddi_remove_intr(dip, 0, NULL);

	ddi_remove_softintr(softsp->poll_mode_softint_id);

	softsp->intr_mode = GLVC_MODE_NONE;
	softsp->polling_interval = 0;

	return (DDI_SUCCESS);
}

static uint_t
glvc_soft_intr(caddr_t arg)
{
	/*
	 * Call the interrupt handle routine to check the register
	 * status.
	 */
	(uint_t)glvc_intr(arg);

	return (DDI_INTR_CLAIMED);
}

/*ARGSUSED*/
static int
glvc_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	int error = 0;
	int instance;
	glvc_soft_state_t *softsp;

	instance = getminor(*dev_p);

	softsp = ddi_get_soft_state(glvc_ssp, instance);

	mutex_enter(&softsp->open_mutex);

	switch (softsp->open_state) {
	case GLVC_NO_OPEN:
		if (flag & FEXCL)
			softsp->open_state = GLVC_EXCL_OPEN;
		else
			softsp->open_state = GLVC_OPEN;
		break;

	case GLVC_OPEN:
		if (flag & FEXCL)
			error = EBUSY;
		break;

	case GLVC_EXCL_OPEN:
		error = EBUSY;
		break;

	default:
		/* Should not happen */
		cmn_err(CE_WARN, "glvc_open: bad open state %d.",
		    softsp->open_state);
		error = ENXIO;
		break;
	}

	mutex_exit(&softsp->open_mutex);

	return (error);
}

/*ARGSUSED*/
static int
glvc_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	glvc_soft_state_t *softsp;
	int instance;
	int error = 0;

	instance = getminor(dev);

	softsp = ddi_get_soft_state(glvc_ssp, instance);

	mutex_enter(&softsp->open_mutex);
	if (softsp->open_state == GLVC_NO_OPEN) {
		cmn_err(CE_WARN,
		    "glvc_close: device already closed");
		error = ENXIO;
	} else {
		softsp->open_state = GLVC_NO_OPEN;
	}
	mutex_exit(&softsp->open_mutex);

	return (error);
}

/*ARGSUSED*/
static int
glvc_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	glvc_soft_state_t *softsp;
	int instance;
	int rv, error = DDI_SUCCESS;
	uint64_t hverr, recv_count = 0;
	uint64_t status_reg;

	instance = getminor(dev);

	softsp = ddi_get_soft_state(glvc_ssp, instance);

	mutex_enter(&softsp->recv_mutex);

	hverr = hv_service_getstatus(softsp->s_id, &status_reg);
	DPRINTF(("glvc_read: err = %ld, getstatus = 0x%lx",
	    hverr, status_reg));


	/*
	 * If no data available, we wait till we get some.
	 * Notice we still holding the recv_mutex lock at this
	 * point.
	 */
	while (hverr == H_EOK && (status_reg & GLVC_REG_RECV) !=
	    GLVC_REG_RECV) {
		rv =  cv_reltimedwait_sig(&softsp->recv_cv,
		    &softsp->recv_mutex, softsp->polling_interval,
		    TR_CLOCK_TICK);
		if (rv == 0) {
			/*
			 * We got interrupted.
			 */
			mutex_exit(&softsp->recv_mutex);
			return (EINTR);
		}
		if (rv == -1) {
			/*
			 * Timeout wait, trigger a soft intr in case
			 * we miss an interrupt or in polling mode.
			 */
			ddi_trigger_softintr(softsp->poll_mode_softint_id);
		}
		hverr = hv_service_getstatus(softsp->s_id, &status_reg);
		DPRINTF(("glvc_read: err = %ld, getstatus = 0x%lx",
		    hverr, status_reg));
	}

	/* Read data into kernel buffer */
	hverr = hv_service_recv(softsp->s_id, softsp->mb_recv_buf_pa,
	    softsp->mtu, &recv_count);

	DPRINTF(("Instance %d glvc_read returns error = %ld, recv_count = %lu",
	    instance, hverr, recv_count));

	if (hverr == H_EOK) {
		if (uiop->uio_resid < recv_count) {
			DPRINTF(("Instance %d, glvc_read user buffer "
			    "size(%lu) smaller than number of bytes "
			    "received(%lu).", instance, uiop->uio_resid,
			    recv_count));
			mutex_exit(&softsp->recv_mutex);
			return (EINVAL);
		}
		/* move data from kernel to user space */
		error = uiomove(softsp->mb_recv_buf, recv_count,
		    UIO_READ, uiop);
	} else {
		error = glvc_emap_h2s(hverr);
	}

	/* Clear the RECV data interrupt bit on device register */
	if (hv_service_clrstatus(softsp->s_id, GLVC_REG_RECV) != H_EOK) {
		cmn_err(CE_WARN, "glvc_read clear status reg failed");
	}

	/* Set RECV interrupt enable bit so we can receive interrupt */
	if (softsp->intr_mode == GLVC_INTR_MODE)
		if (hv_service_setstatus(softsp->s_id, GLVC_REG_RECV_ENA)
		    != H_EOK) {
			cmn_err(CE_WARN, "glvc_read set status reg failed");
		}

	mutex_exit(&softsp->recv_mutex);

	return (error);
}

/*ARGSUSED*/
static int
glvc_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	glvc_soft_state_t *softsp;
	int instance;
	int rv, error = DDI_SUCCESS;
	uint64_t hverr, send_count = 0;

	instance = getminor(dev);

	softsp = ddi_get_soft_state(glvc_ssp, instance);

	if (uiop->uio_resid > softsp->mtu)
		return (EINVAL);

	send_count = uiop->uio_resid;
	DPRINTF(("instance %d glvc_write: request to send %lu bytes",
	    instance, send_count));

	mutex_enter(&softsp->send_complete_mutex);
	while (softsp->send_complete_flag == 0) {
		rv = cv_reltimedwait_sig(&softsp->send_complete_cv,
		    &softsp->send_complete_mutex, softsp->polling_interval,
		    TR_CLOCK_TICK);
		if (rv == 0) {
			/*
			 * We got interrupted.
			 */
			mutex_exit(&softsp->send_complete_mutex);
			return (EINTR);
		}
		if (rv == -1) {
			/*
			 * Timeout wait, trigger a soft intr in case
			 * we miss an interrupt or in polling mode.
			 */
			ddi_trigger_softintr(softsp->poll_mode_softint_id);
		}
	}

	/* move data from to user to kernel space */
	error = uiomove(softsp->mb_send_buf, send_count,
	    UIO_WRITE, uiop);

	if (error == 0) {
		hverr = hv_service_send(softsp->s_id,
		    softsp->mb_send_buf_pa, send_count, &send_count);
		error = glvc_emap_h2s(hverr);
	}

	DPRINTF(("instance %d glvc_write write check error = %d,"
	    " send_count = %lu", instance, error, send_count));

	softsp->send_complete_flag = 0;

	mutex_exit(&softsp->send_complete_mutex);

	return (error);
}

/*
 * Interrupt handler
 */
static uint_t
glvc_intr(caddr_t arg)
{
	glvc_soft_state_t *softsp = (glvc_soft_state_t *)arg;
	uint64_t status_reg;
	int error = DDI_INTR_UNCLAIMED;
	uint64_t hverr = H_EOK;
	uint64_t clr_bits = 0;

	mutex_enter(&softsp->recv_mutex);
	mutex_enter(&softsp->send_complete_mutex);
	hverr = hv_service_getstatus(softsp->s_id, &status_reg);
	DPRINTF(("glvc_intr: err = %ld, getstatus = 0x%lx",
	    hverr, status_reg));

	/*
	 * Clear SEND_COMPLETE bit and disable RECV interrupt
	 */
	if (status_reg & GLVC_REG_SEND)
		clr_bits |= GLVC_REG_SEND;
	if ((softsp->intr_mode == GLVC_INTR_MODE) &&
	    (status_reg & GLVC_REG_RECV))
		clr_bits |= GLVC_REG_RECV_ENA;

	if ((hverr = hv_service_clrstatus(softsp->s_id, clr_bits))
	    != H_EOK) {
		cmn_err(CE_WARN, "glvc_intr clear status reg failed"
		    "error = %ld", hverr);
		mutex_exit(&softsp->send_complete_mutex);
		mutex_exit(&softsp->recv_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	if (status_reg & GLVC_REG_RECV) {
		cv_broadcast(&softsp->recv_cv);
		error = DDI_INTR_CLAIMED;
	}

	if (status_reg & GLVC_REG_SEND) {
		softsp->send_complete_flag = 1;
		cv_broadcast(&softsp->send_complete_cv);
		error = DDI_INTR_CLAIMED;
	}

	mutex_exit(&softsp->send_complete_mutex);
	mutex_exit(&softsp->recv_mutex);

	return (error);
}

/*
 * Peek to see if there is data received. If no data available,
 * we sleep wait. If there is data, read from hypervisor and copy
 * to ioctl buffer. We don't clear the receive data interrupt bit.
 */
static int
glvc_peek(glvc_soft_state_t *softsp, glvc_xport_msg_peek_t *msg_peek)
{
	int rv, error = 0;
	uint64_t hverr = H_EOK;
	uint64_t recv_count = 0;
	uint64_t status_reg;

	mutex_enter(&softsp->recv_mutex);

	hverr = hv_service_getstatus(softsp->s_id, &status_reg);
	DPRINTF(("glvc_peek: err = %ld, getstatus = 0x%lx",
	    hverr, status_reg));

	/*
	 * If no data available, we wait till we get some.
	 * Notice we still holding the recv_mutex lock at
	 * this point.
	 */
	while (hverr == H_EOK && (status_reg & GLVC_REG_RECV) !=
	    GLVC_REG_RECV) {
		rv = cv_reltimedwait_sig(&softsp->recv_cv,
		    &softsp->recv_mutex, softsp->polling_interval,
		    TR_CLOCK_TICK);
		if (rv == 0) {
			/*
			 * We got interrupted.
			 */
			mutex_exit(&softsp->recv_mutex);
			return (EINTR);
		}
		if (rv == -1) {
			/*
			 * Timeout wait, trigger a soft intr in case
			 * we miss an interrupt or in polling mode.
			 */
			ddi_trigger_softintr(softsp->poll_mode_softint_id);
		}
		hverr = hv_service_getstatus(softsp->s_id, &status_reg);
		DPRINTF(("glvc_peek: err = %ld, getstatus = 0x%lx",
		    hverr, status_reg));
	}

	/* Read data into kernel buffer */
	hverr = hv_service_recv(softsp->s_id, softsp->mb_recv_buf_pa,
	    softsp->mtu, &recv_count);
	DPRINTF(("glvc_peek recv data, error = %ld, recv_count = %lu",
	    hverr, recv_count));

	if (hverr == H_EOK && recv_count > 0) {
		(void *) memcpy(msg_peek->buf,
		    softsp->mb_recv_buf, recv_count);
		msg_peek->buflen = recv_count;
	} else {
		error = glvc_emap_h2s(hverr);
	}

	mutex_exit(&softsp->recv_mutex);

	return (error);
}

static int
glvc_ioctl_opt_op(glvc_soft_state_t *softsp, intptr_t arg, int mode)
{
	glvc_xport_opt_op_t glvc_xport_cmd;
	uint64_t status_reg;
	int retval = 0;
	uint64_t hverr;

	if (ddi_copyin((caddr_t)arg, (caddr_t)&glvc_xport_cmd,
	    sizeof (glvc_xport_opt_op_t), mode) != 0) {
		return (EFAULT);
	}

	switch (glvc_xport_cmd.opt_sel) {
	case GLVC_XPORT_OPT_MTU_SZ:
		if (glvc_xport_cmd.op_sel == GLVC_XPORT_OPT_GET) {
			glvc_xport_cmd.opt_val = softsp->mtu;
			retval = ddi_copyout((caddr_t)&glvc_xport_cmd,
			    (caddr_t)arg, sizeof (glvc_xport_opt_op_t),
			    mode);
		} else
			retval = ENOTSUP;

		break;

	case GLVC_XPORT_OPT_REG_STATUS:
		if (glvc_xport_cmd.op_sel == GLVC_XPORT_OPT_GET) {
			mutex_enter(&softsp->statusreg_mutex);
			hverr = hv_service_getstatus(softsp->s_id, &status_reg);
			mutex_exit(&softsp->statusreg_mutex);
			if (hverr == H_EOK) {
				glvc_xport_cmd.opt_val = (uint32_t)status_reg;
				retval = ddi_copyout((caddr_t)&glvc_xport_cmd,
				    (caddr_t)arg, sizeof (glvc_xport_opt_op_t),
				    mode);
			} else {
				retval = EIO;
			}
		} else {
			retval = ENOTSUP;
		}

		break;

	default:
		retval = ENOTSUP;
		break;
	}

	return (retval);
}


/*ARGSUSED*/
static int
glvc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
    int *rval_p)
{
	glvc_soft_state_t *softsp;
	int instance = getminor(dev);
	glvc_xport_msg_peek_t glvc_peek_msg, msg_peek_cmd;
	glvc_xport_msg_peek32_t msg_peek_cmd32;

	int retval = 0;

	softsp = ddi_get_soft_state(glvc_ssp, instance);

	switch (cmd) {
	case GLVC_XPORT_IOCTL_OPT_OP:
		retval = glvc_ioctl_opt_op(softsp, arg, mode);
		break;

	case GLVC_XPORT_IOCTL_DATA_PEEK:
		glvc_peek_msg.buf =
		    (char *)kmem_zalloc(softsp->mtu, KM_NOSLEEP);
		if (glvc_peek_msg.buf == NULL)
			return (EBUSY);
		retval = glvc_peek(softsp, &glvc_peek_msg);
		if (retval == 0) {
			switch (ddi_model_convert_from(mode)) {
			case DDI_MODEL_ILP32:
				if (ddi_copyin((caddr_t)arg,
				    (caddr_t)&msg_peek_cmd32,
				    sizeof (glvc_xport_msg_peek32_t),
				    mode) == -1) {
					retval = EFAULT;
					break;
				}

				if (msg_peek_cmd32.buflen32 == 0) {
					retval = EINVAL;
					break;
				}

				if (msg_peek_cmd32.buflen32 >
				    glvc_peek_msg.buflen)
					msg_peek_cmd32.buflen32 =
					    glvc_peek_msg.buflen;

				if (ddi_copyout((caddr_t)glvc_peek_msg.buf,
				    (caddr_t)(uintptr_t)msg_peek_cmd32.buf32,
				    msg_peek_cmd32.buflen32, mode) == -1) {
					retval = EFAULT;
					break;
				}

				if (ddi_copyout((caddr_t)&msg_peek_cmd32,
				    (caddr_t)arg,
				    sizeof (glvc_xport_msg_peek32_t), mode)
				    == -1)
					retval = EFAULT;
				break;

			case DDI_MODEL_NONE:
				if (ddi_copyin((caddr_t)arg,
				    (caddr_t)&msg_peek_cmd,
				    sizeof (glvc_xport_msg_peek_t), mode) == -1)
					retval = EFAULT;

				if (msg_peek_cmd.buflen == 0) {
					retval = EINVAL;
					break;
				}

				if (msg_peek_cmd.buflen > glvc_peek_msg.buflen)
					msg_peek_cmd.buflen =
					    glvc_peek_msg.buflen;

				if (ddi_copyout((caddr_t)glvc_peek_msg.buf,
				    (caddr_t)msg_peek_cmd.buf,
				    msg_peek_cmd.buflen, mode) == -1) {
					retval = EFAULT;
					break;
				}

				if (ddi_copyout((caddr_t)&msg_peek_cmd,
				    (caddr_t)arg,
				    sizeof (glvc_xport_msg_peek_t), mode) == -1)
					retval = EFAULT;
				break;

			default:
				retval = EFAULT;
				break;
			}
		}
		kmem_free(glvc_peek_msg.buf, softsp->mtu);
		break;

	default:
		retval = ENOTSUP;
		break;
	}
	return (retval);
}

/*
 * Map hypervisor error code to solaris. Only
 * H_EOK, H_EINVA, H_EWOULDBLOCK and H_EIO are meaningful
 * to this device. All other error codes are mapped to EIO.
 */
static int
glvc_emap_h2s(uint64_t hv_errcode)
{
	int s_errcode;

	switch (hv_errcode) {
	case H_EOK:
		s_errcode = 0;
		break;

	case H_EINVAL:
		s_errcode = EINVAL;
		break;

	case H_EWOULDBLOCK:
		s_errcode = EWOULDBLOCK;
		break;

	case H_EIO:
		s_errcode = EIO;
		break;

	default:
		/* should not happen */
		DPRINTF(("Unexpected device error code %ld received, "
		    "mapped to EIO", hv_errcode));
		s_errcode = EIO;
		break;
	}

	return (s_errcode);
}
