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
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/rmc_comm_dp.h>
#include <sys/rmc_comm_dp_boot.h>
#include <sys/rmc_comm_drvintf.h>
#include <sys/cyclic.h>
#include <sys/rmc_comm.h>
#include <sys/machsystm.h>
#include <sys/file.h>
#include <sys/rmcadm.h>

/*
 * functions local to this driver.
 */
static int	rmcadm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp);
static int	rmcadm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	rmcadm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int	rmcadm_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p);
static int	rmcadm_close(dev_t dev, int flag, int otyp, cred_t *cred_p);
static int	rmcadm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *cred_p, int *rval_p);

/*
 * Driver entry points
 */
static struct cb_ops rmcadm_cb_ops = {
	rmcadm_open,	/* open */
	rmcadm_close,	/* close */
	nodev,		/* strategy() */
	nodev,		/* print() */
	nodev,		/* dump() */
	nodev,		/* read() */
	nodev,		/* write() */
	rmcadm_ioctl,	/* ioctl() */
	nodev,		/* devmap() */
	nodev,		/* mmap() */
	ddi_segmap,	/* segmap() */
	nochpoll,	/* poll() */
	ddi_prop_op,    /* prop_op() */
	NULL,		/* cb_str */
	D_NEW | D_MP	/* cb_flag */
};


static struct dev_ops rmcadm_ops = {
	DEVO_REV,
	0,			/* ref count */
	rmcadm_getinfo,		/* getinfo() */
	nulldev,		/* identify() */
	nulldev,		/* probe() */
	rmcadm_attach,		/* attach() */
	rmcadm_detach,		/* detach */
	nodev,			/* reset */
	&rmcadm_cb_ops,		/* pointer to cb_ops structure */
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
	"rmcadm control driver",	/* Name of the module */
	&rmcadm_ops			/* pointer to the dev_ops structure */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

static dev_info_t		*rmcadm_dip = NULL;

extern void pmugpio_reset();

/*
 * Utilities...
 */

/*
 * to return the errno from the rmc_comm error status
 */
int
rmcadm_get_errno(int status)
{
	int retval = EIO;

	/* errors from RMC */
	switch (status) {
		case RCENOSOFTSTATE:
			/* invalid/NULL soft state structure */
			retval = EIO;
			break;
		case RCENODATALINK:
			/* data protocol not available (down) */
			retval = EIO;
			break;
		case RCENOMEM:
			/* memory problems */
			retval = ENOMEM;
			break;
		case RCECANTRESEND:
			/* resend failed */
			retval = EIO;
			break;
		case RCEMAXRETRIES:
			/* reply not received - retries exceeded */
			retval = EINTR;
			break;
		case RCETIMEOUT:
			/* reply not received - command has timed out */
			retval = EINTR;
			break;
		case RCEINVCMD:
			/* data protocol cmd not supported */
			retval = ENOTSUP;
			break;
		case RCEINVARG:
			/* invalid argument(s) */
			retval = ENOTSUP;
			break;
		case RCEGENERIC:
			/* generic error */
			retval = EIO;
			break;
		default:
			retval = EIO;
			break;
	}
	return (retval);
}

int
_init(void)
{
	int	error = 0;

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
	return (error);
}


/* ARGSUSED */
static int
rmcadm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	minor_t m = getminor((dev_t)arg);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((m != 0) || (rmcadm_dip == NULL)) {
			*resultp = NULL;
			return (DDI_FAILURE);
		}
		*resultp = rmcadm_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)m;
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}


static int
rmcadm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int			instance;
	int			err;

	switch (cmd) {
	case DDI_ATTACH:
		/*
		 * only allow one instance
		 */
		instance = ddi_get_instance(dip);
		if (instance != 0)
			return (DDI_FAILURE);

		err = ddi_create_minor_node(dip, "rmcadm", S_IFCHR,
		    instance, DDI_PSEUDO, 0);
		if (err != DDI_SUCCESS)
			return (DDI_FAILURE);

		/*
		 * Register with rmc_comm to prevent it being detached
		 */
		err = rmc_comm_register();
		if (err != DDI_SUCCESS) {
			ddi_remove_minor_node(dip, NULL);
			return (DDI_FAILURE);
		}

		/* Remember the dev info */
		rmcadm_dip = dip;

		ddi_report_dev(dip);
		return (DDI_SUCCESS);
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}


static int
rmcadm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int	instance;

	switch (cmd) {
	case DDI_DETACH:
		instance = ddi_get_instance(dip);
		if (instance != 0)
			return (DDI_FAILURE);

		rmcadm_dip = NULL;
		ddi_remove_minor_node(dip, NULL);
		rmc_comm_unregister();
		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
rmcadm_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	int error = 0;
	int instance = getminor(*dev_p);

	if (instance != 0)
		return (ENXIO);

	if ((error = drv_priv(cred_p)) != 0) {
		cmn_err(CE_WARN, "rmcadm: inst %d drv_priv failed",
		    instance);
		return (error);
	}
	return (error);
}

/*ARGSUSED*/
static int
rmcadm_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
rmcadm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
    int *rval_p)
{
	int				instance = getminor(dev);
	int				retval = 0;
	rmcadm_request_response_t	rr;
	rmcadm_send_srecord_bp_t	ssbp;
	rmc_comm_msg_t			rmc_req, *rmc_reqp = &rmc_req;
	rmc_comm_msg_t			rmc_resp, *rmc_respp = &rmc_resp;
	caddr_t				user_req_buf;
	caddr_t				user_data_buf;
	caddr_t				user_resp_buf;

	if (instance != 0)
		return (ENXIO);

	switch (cmd) {

	case RMCADM_REQUEST_RESPONSE:
	case RMCADM_REQUEST_RESPONSE_BP:

		/*
		 * first copy in the request_response structure
		 */
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			rmcadm_request_response32_t	rr32;

			if (ddi_copyin((caddr_t)arg, (caddr_t)&rr32,
			    sizeof (rr32), mode)) {
				return (EFAULT);
			}
			rr.req.msg_type = rr32.req.msg_type;
			rr.req.msg_len = rr32.req.msg_len;
			rr.req.msg_bytes = rr32.req.msg_bytes;
			rr.req.msg_buf = (caddr_t)(uintptr_t)rr32.req.msg_buf;
			rr.resp.msg_type = rr32.resp.msg_type;
			rr.resp.msg_len = rr32.resp.msg_len;
			rr.resp.msg_bytes = rr32.resp.msg_bytes;
			rr.resp.msg_buf = (caddr_t)(uintptr_t)rr32.resp.msg_buf;
			rr.wait_time = rr32.wait_time;
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyin((caddr_t)arg, (caddr_t)&rr,
			    sizeof (rr), mode)) {
				return (EFAULT);
			}
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyin((caddr_t)arg, (caddr_t)&rr,
		    sizeof (rr), mode) != 0) {
			return (EFAULT);
		}
#endif /* _MULTI_DATAMODEL */

		/*
		 * save the user request buffer pointer
		 */
		user_req_buf = rr.req.msg_buf;

		if (user_req_buf != NULL) {
			/*
			 * copy in the request data
			 */
			rr.req.msg_buf = kmem_alloc(rr.req.msg_len, KM_SLEEP);

			if (ddi_copyin(user_req_buf, rr.req.msg_buf,
			    rr.req.msg_len, mode) != 0) {

				kmem_free(rr.req.msg_buf, rr.req.msg_len);
				rr.req.msg_buf = user_req_buf;
				return (EFAULT);
			}
		} else {
			if (rr.req.msg_len > 0)
				/*
				 * msg_len should be 0 if buffer is NULL!
				 */
				return (EINVAL);
		}

		/*
		 * save the user request buffer pointer
		 */
		user_resp_buf = rr.resp.msg_buf;
		if (user_resp_buf != NULL) {
			rr.resp.msg_buf = kmem_alloc(rr.resp.msg_len, KM_SLEEP);
		}

		/*
		 * send the request (or BP request) via the rmc_comm driver
		 */
		rmc_reqp->msg_type = rr.req.msg_type;
		rmc_reqp->msg_buf = rr.req.msg_buf;
		rmc_reqp->msg_len = rr.req.msg_len;
		rmc_reqp->msg_bytes = rr.req.msg_bytes;

		if (cmd == RMCADM_REQUEST_RESPONSE) {

			/*
			 * check if response is expected. If so, fill in
			 * the response data structure
			 */
			if (rr.resp.msg_type != DP_NULL_MSG) {

				rmc_respp->msg_type = rr.resp.msg_type;
				rmc_respp->msg_buf = rr.resp.msg_buf;
				rmc_respp->msg_len = rr.resp.msg_len;
				rmc_respp->msg_bytes = rr.resp.msg_bytes;

			} else {

				rmc_respp = (rmc_comm_msg_t *)NULL;
			}

			rr.status = rmc_comm_request_response(
			    rmc_reqp, rmc_respp, rr.wait_time);

		} else { /* RMCADM_REQUEST_RESPONSE_BP */

			/*
			 * check if a BP message is expected back. If so,
			 * fill in the response data structure
			 */
			if (rr.resp.msg_buf != NULL) {

				rmc_respp->msg_type = rr.resp.msg_type;
				rmc_respp->msg_buf = rr.resp.msg_buf;
				rmc_respp->msg_len = rr.resp.msg_len;
				rmc_respp->msg_bytes = rr.resp.msg_bytes;

			} else {

				rmc_respp = (rmc_comm_msg_t *)NULL;
			}

			rr.status = rmc_comm_request_response_bp(
			    rmc_reqp, rmc_respp, rr.wait_time);
		}

		/*
		 * if a response was expected, copy back the (actual) number
		 * of bytes of the response returned by the
		 * rmc_comm_request_response function (msg_bytes field)
		 */
		if (rmc_respp != NULL) {
			rr.resp.msg_bytes = rmc_respp->msg_bytes;
		}

		if (rr.status != RCNOERR) {

			retval = rmcadm_get_errno(rr.status);

		} else if (user_resp_buf != NULL) {
			/*
			 * copy out the user response buffer
			 */
			if (ddi_copyout(rr.resp.msg_buf, user_resp_buf,
			    rr.resp.msg_bytes, mode) != 0) {
				retval = EFAULT;
			}
		}

		/*
		 * now copy out the updated request_response structure
		 */
		if (rr.req.msg_buf)
			kmem_free(rr.req.msg_buf, rr.req.msg_len);
		if (rr.resp.msg_buf)
			kmem_free(rr.resp.msg_buf, rr.resp.msg_len);

		rr.req.msg_buf = user_req_buf;
		rr.resp.msg_buf = user_resp_buf;

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			rmcadm_request_response32_t	rr32;

			rr32.req.msg_type = rr.req.msg_type;
			rr32.req.msg_len = rr.req.msg_len;
			rr32.req.msg_bytes = rr.req.msg_bytes;
			rr32.req.msg_buf = (caddr32_t)(uintptr_t)rr.req.msg_buf;
			rr32.resp.msg_type = rr.resp.msg_type;
			rr32.resp.msg_len = rr.resp.msg_len;
			rr32.resp.msg_bytes = rr.resp.msg_bytes;
			rr32.resp.msg_buf =
			    (caddr32_t)(uintptr_t)rr.resp.msg_buf;
			rr32.wait_time = rr.wait_time;
			rr32.status = rr.status;
			if (ddi_copyout((caddr_t)&rr32, (caddr_t)arg,
			    sizeof (rr32), mode)) {
				return (EFAULT);
			}
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyout((caddr_t)&rr, (caddr_t)arg,
			    sizeof (rr), mode))
				return (EFAULT);
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyout((caddr_t)&rr, (caddr_t)arg, sizeof (rr),
		    mode) != 0)
			return (EFAULT);
#endif /* _MULTI_DATAMODEL */
		break;


	case RMCADM_SEND_SRECORD_BP:

		/*
		 * first copy in the request_response structure
		 */
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			rmcadm_send_srecord_bp32_t	ssbp32;

			if (ddi_copyin((caddr_t)arg, (caddr_t)&ssbp32,
			    sizeof (ssbp32), mode)) {
				return (EFAULT);
			}
			ssbp.data_len = ssbp32.data_len;
			ssbp.data_buf = (caddr_t)(uintptr_t)ssbp32.data_buf;
			ssbp.resp_bp.msg_type = ssbp32.resp_bp.msg_type;
			ssbp.resp_bp.msg_len = ssbp32.resp_bp.msg_len;
			ssbp.resp_bp.msg_bytes = ssbp32.resp_bp.msg_bytes;
			ssbp.resp_bp.msg_buf =
			    (caddr_t)(uintptr_t)ssbp32.resp_bp.msg_buf;
			ssbp.wait_time = ssbp32.wait_time;
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyin((caddr_t)arg, (caddr_t)&ssbp,
			    sizeof (ssbp), mode))
				return (EFAULT);
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyin((caddr_t)arg, (caddr_t)&ssbp,
		    sizeof (ssbp), mode) != 0)
			return (EFAULT);
#endif /* _MULTI_DATAMODEL */

		/*
		 * save the user data buffer pointer
		 */
		user_data_buf = ssbp.data_buf;

		if (user_data_buf != NULL) {
			/*
			 * copy in the srecord data
			 */
			ssbp.data_buf = kmem_alloc(ssbp.data_len, KM_SLEEP);

			if (ddi_copyin(user_data_buf, ssbp.data_buf,
			    ssbp.data_len, mode) != 0) {

				kmem_free(ssbp.data_buf, ssbp.data_len);
				ssbp.data_buf = user_data_buf;
				return (EFAULT);
			}
		} else {
			return (EINVAL);	/* request can't be NULL! */
		}

		/*
		 * save the user request buffer pointer
		 */
		user_resp_buf = ssbp.resp_bp.msg_buf;
		if (user_resp_buf != NULL) {
			ssbp.resp_bp.msg_buf =
			    kmem_alloc(ssbp.resp_bp.msg_len, KM_SLEEP);
		} else {

			kmem_free(ssbp.data_buf, ssbp.data_len);
			return (EINVAL);
		}

		/*
		 * send the srecord via the rmc_comm driver and get the reply
		 * back (BP message)
		 */

		rmc_respp->msg_type = ssbp.resp_bp.msg_type;
		rmc_respp->msg_buf = ssbp.resp_bp.msg_buf;
		rmc_respp->msg_len = ssbp.resp_bp.msg_len;
		rmc_respp->msg_bytes = ssbp.resp_bp.msg_bytes;

		ssbp.status = rmc_comm_send_srecord_bp(ssbp.data_buf,
		    ssbp.data_len, rmc_respp, ssbp.wait_time);

		/*
		 * copy back the actual size of the returned message
		 */
		ssbp.resp_bp.msg_bytes = rmc_respp->msg_bytes;

		if (ssbp.status != RCNOERR) {
			retval = rmcadm_get_errno(ssbp.status);

		} else if (user_resp_buf != NULL) {
			/*
			 * copy out the user BP response buffer
			 */
			if (ddi_copyout(ssbp.resp_bp.msg_buf, user_resp_buf,
			    ssbp.resp_bp.msg_bytes, mode) != 0) {
				retval = EFAULT;
			}
		}

		/*
		 * now copy out the updated request_response structure
		 */
		if (ssbp.data_buf)
			kmem_free(ssbp.data_buf, ssbp.data_len);
		if (ssbp.resp_bp.msg_buf)
			kmem_free(ssbp.resp_bp.msg_buf, ssbp.resp_bp.msg_len);

		ssbp.data_buf = user_data_buf;
		ssbp.resp_bp.msg_buf = user_resp_buf;

#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			/*
			 * For use when a 32 bit app makes a call into a
			 * 64 bit ioctl
			 */
			rmcadm_send_srecord_bp32_t	ssbp32;

			ssbp32.data_len = ssbp.data_len;
			ssbp32.data_buf = (caddr32_t)(uintptr_t)ssbp.data_buf;
			ssbp32.resp_bp.msg_type = ssbp.resp_bp.msg_type;
			ssbp32.resp_bp.msg_len = ssbp.resp_bp.msg_len;
			ssbp32.resp_bp.msg_bytes = ssbp.resp_bp.msg_bytes;
			ssbp32.resp_bp.msg_buf =
			    (caddr32_t)(uintptr_t)ssbp.resp_bp.msg_buf;
			ssbp32.wait_time = ssbp.wait_time;

			if (ddi_copyout((caddr_t)&ssbp32, (caddr_t)arg,
			    sizeof (ssbp32), mode)) {
				return (EFAULT);
			}
			break;
		}
		case DDI_MODEL_NONE:
			if (ddi_copyout((caddr_t)&ssbp, (caddr_t)arg,
			    sizeof (ssbp), mode))
				return (EFAULT);
			break;
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyout((caddr_t)&ssbp, (caddr_t)arg, sizeof (ssbp),
		    mode) != 0)
			return (EFAULT);
#endif /* _MULTI_DATAMODEL */
		break;


	case RMCADM_RESET_SP:
		pmugpio_reset();
		retval = 0;
		break;
	default:
		retval = ENOTSUP;
		break;
	}
	return (retval);
}
