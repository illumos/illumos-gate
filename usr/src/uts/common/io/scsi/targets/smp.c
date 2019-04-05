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
 * SMP - Serial Management Protocol Device Driver
 *
 * The SMP driver provides user programs access to SAS Serial Management
 * Protocol devices by providing ioctl interface.
 */

#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/targets/smp.h>
#include <sys/sdt.h>

/*
 * Standard entrypoints
 */
static int smp_attach(dev_info_t *, ddi_attach_cmd_t);
static int smp_detach(dev_info_t *, ddi_detach_cmd_t);
static int smp_open(dev_t *, int, int, cred_t *);
static int smp_close(dev_t, int, int, cred_t *);
static int smp_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * Configuration routines
 */
static int smp_do_attach(dev_info_t *);
static int smp_do_detach(dev_info_t *);

/*
 * Command handle routing
 */
static int smp_handle_func(dev_t, intptr_t, int, cred_t *, int *);

/*
 * Logging/debugging routines
 */
static void smp_log(smp_state_t  *, int,  const char *, ...);

int smp_retry_times	= SMP_DEFAULT_RETRY_TIMES;
int smp_retry_delay	= 10000;	/* 10msec */
int smp_delay_cmd	= 1;		/* 1usec */
int smp_single_command	= 1;		/* one command at a time */

static int smp_retry_recovered	= 0;	/* retry recovery counter */
static int smp_retry_failed	= 0;	/* retry failed counter */
static int smp_failed		= 0;

static struct cb_ops smp_cb_ops = {
	smp_open,			/* open */
	smp_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	smp_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab  */
	D_MP | D_NEW | D_HOTPLUG	/* Driver compatibility flag */
};

static struct dev_ops smp_dev_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	ddi_getinfo_1to1,	/* info */
	nulldev,		/* identify */
	NULL,			/* probe */
	smp_attach,		/* attach */
	smp_detach,		/* detach */
	nodev,			/* reset */
	&smp_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static void *smp_soft_state = NULL;

static struct modldrv modldrv = {
	&mod_driverops, "smp device driver", &smp_dev_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	int err;

	if ((err = ddi_soft_state_init(&smp_soft_state,
	    sizeof (smp_state_t), SMP_ESTIMATED_NUM_DEVS)) != 0) {
		return (err);
	}

	if ((err = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&smp_soft_state);
	}

	return (err);
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&smp_soft_state);
	}

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * smp_attach()
 *	attach(9e) entrypoint.
 */
static int
smp_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int err;

	switch (cmd) {
	case DDI_ATTACH:
		err = smp_do_attach(dip);
		break;
	case DDI_RESUME:
		err = DDI_SUCCESS;
		break;
	default:
		err = DDI_FAILURE;
		break;
	}

	if (err != DDI_SUCCESS) {
		smp_log(NULL, CE_NOTE, "!smp_attach(), "
		    "device unit-address @%s failed",
		    ddi_get_name_addr(dip));
	}
	return (err);
}

/*
 * smp_do_attach()
 *	handle the nitty details of attach.
 */
static int
smp_do_attach(dev_info_t *dip)
{
	int			instance;
	struct smp_device	*smp_sd;
	uchar_t			*srmir = NULL;
	uint_t			srmirlen = 0;
	ddi_devid_t		devid = NULL;
	smp_state_t		*smp_state;

	instance = ddi_get_instance(dip);
	smp_sd = ddi_get_driver_private(dip);
	ASSERT(smp_sd != NULL);

	DTRACE_PROBE2(smp__attach__detach, int, instance, char *,
	    ddi_get_name_addr(dip));

	/* make sure device is there, and establish srmir identity property */
	if (smp_probe(smp_sd) != DDI_PROBE_SUCCESS) {
		smp_log(NULL, CE_NOTE,
		    "!smp_do_attach: failed smp_probe, "
		    "device unit-address @%s", ddi_get_name_addr(dip));
		return (DDI_FAILURE);
	}

	/* if we have not already registered a devid, then do so now  */
	if (ddi_devid_get(dip, &devid) != DDI_SUCCESS) {
		/* get the srmir identity information for use in devid */
		(void) ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    SMP_PROP_REPORT_MANUFACTURER, &srmir, &srmirlen);

		/* Convert smp unit-address and srmir into devid */
		if (ddi_devid_smp_encode(DEVID_SMP_ENCODE_VERSION_LATEST,
		    (char *)ddi_driver_name(dip), ddi_get_name_addr(dip),
		    srmir, srmirlen, &devid) == DDI_SUCCESS) {
			/* register the devid */
			(void) ddi_devid_register(dip, devid);
		}
		ddi_prop_free(srmir);
	}

	/* We don't need the devid for our own operation, so free now. */
	if (devid)
		ddi_devid_free(devid);

	/* we are now done with srmir identity property defined by smp_probe */
	(void) ndi_prop_remove(DDI_DEV_T_NONE,
	    dip, SMP_PROP_REPORT_MANUFACTURER);

	if (ddi_soft_state_zalloc(smp_soft_state, instance) != DDI_SUCCESS) {
		smp_log(NULL, CE_NOTE,
		    "!smp_do_attach: failed to allocate softstate, "
		    "device unit-address @%s", ddi_get_name_addr(dip));
		return (DDI_FAILURE);
	}

	smp_state = ddi_get_soft_state(smp_soft_state, instance);
	smp_state->smp_sd = smp_sd;

	/*
	 * For simplicity, the minor number == the instance number
	 */
	if (ddi_create_minor_node(dip, "smp", S_IFCHR,
	    instance, DDI_NT_SMP, 0) == DDI_FAILURE) {
		smp_log(smp_state, CE_NOTE,
		    "!smp_do_attach: minor node creation failed, "
		    "device unit-address @%s", ddi_get_name_addr(dip));
		ddi_soft_state_free(smp_soft_state, instance);
		return (DDI_FAILURE);
	}

	mutex_init(&smp_state->smp_mutex, NULL, MUTEX_DRIVER, NULL);
	smp_state->smp_open_flag = SMP_CLOSED;

	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

/*
 * smp_detach()
 *	detach(9E) entrypoint
 */
static int
smp_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	smp_state_t *smp_state;

	instance = ddi_get_instance(dip);
	smp_state = ddi_get_soft_state(smp_soft_state, instance);

	if (smp_state == NULL) {
		smp_log(NULL, CE_NOTE,
		    "!smp_detach: failed, no softstate found (%d), "
		    "device unit-address @%s",
		    instance, ddi_get_name_addr(dip));
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_DETACH:
		return (smp_do_detach(dip));
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

/*
 * smp_do_detach()
 *	detach the driver, tearing down resources.
 */
static int
smp_do_detach(dev_info_t *dip)
{
	int instance;
	smp_state_t *smp_state;

	instance = ddi_get_instance(dip);
	smp_state = ddi_get_soft_state(smp_soft_state, instance);

	DTRACE_PROBE2(smp__attach__detach, int, instance, char *,
	    ddi_get_name_addr(dip));

	mutex_destroy(&smp_state->smp_mutex);
	ddi_soft_state_free(smp_soft_state, instance);
	ddi_remove_minor_node(dip, NULL);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
smp_open(dev_t *dev_p, int flag, int otyp, cred_t *cred_p)
{
	smp_state_t *smp_state;
	int instance;
	int rv = 0;

	instance = getminor(*dev_p);
	if ((smp_state = ddi_get_soft_state(smp_soft_state, instance))
	    == NULL) {
		return (ENXIO);
	}

	mutex_enter(&smp_state->smp_mutex);
	if (flag & FEXCL) {
		if (smp_state->smp_open_flag != SMP_CLOSED) {
			rv = EBUSY;
		} else {
			smp_state->smp_open_flag = SMP_EXOPENED;
		}
	} else {
		if (smp_state->smp_open_flag == SMP_EXOPENED) {
			rv = EBUSY;
		} else {
			smp_state->smp_open_flag = SMP_SOPENED;
		}
	}
	mutex_exit(&smp_state->smp_mutex);

	return (rv);
}

/*ARGSUSED*/
static int
smp_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	smp_state_t *smp_state;
	int instance;
	int rv = 0;

	instance = getminor(dev);
	if ((smp_state = ddi_get_soft_state(smp_soft_state, instance))
	    == NULL) {
		return (ENXIO);
	}

	mutex_enter(&smp_state->smp_mutex);
	if (smp_state->smp_open_flag == SMP_CLOSED) {
		smp_log(smp_state, CE_NOTE, "!smp device is already in close");
	} else {
		smp_state->smp_open_flag = SMP_CLOSED;
	}
	mutex_exit(&smp_state->smp_mutex);
	return (rv);
}

/*ARGSUSED*/
static int
smp_handle_func(dev_t dev,
    intptr_t arg, int flag, cred_t *cred_p, int *rval_p)
{
	usmp_cmd_t usmp_cmd_data, *usmp_cmd = &usmp_cmd_data;
	smp_pkt_t smp_pkt_data, *smp_pkt = &smp_pkt_data;
	smp_state_t *smp_state;
	int instance, retrycount;
	cred_t *cr;
	uint64_t cmd_flags = 0;
	int rval = 0;

#ifdef	_MULTI_DATAMODEL
	usmp_cmd32_t usmp_cmd32_data, *usmp_cmd32 = &usmp_cmd32_data;
#endif

	/* require PRIV_SYS_DEVICES privilege */
	cr = ddi_get_cred();
	if ((drv_priv(cred_p) != 0) && (drv_priv(cr) != 0)) {
		return (EPERM);
	}

	bzero(smp_pkt, sizeof (smp_pkt_t));

	instance = getminor(dev);
	if ((smp_state = ddi_get_soft_state(smp_soft_state, instance))
	    == NULL) {
		return (ENXIO);
	}

#ifdef	_MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)arg, usmp_cmd32, sizeof (usmp_cmd32_t),
		    flag)) {
			return (EFAULT);
		}

		usmp_cmd32tousmp_cmd(usmp_cmd32, usmp_cmd);
		break;
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, usmp_cmd, sizeof (usmp_cmd_t),
		    flag)) {
			return (EFAULT);
		}
		break;
	}
#else  /* ! _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, usmp_cmd, sizeof (usmp_cmd_t), flag)) {
		return (EFAULT);
	}
#endif	/* _MULTI_DATAMODEL */

	if ((usmp_cmd->usmp_reqsize < SMP_MIN_REQUEST_SIZE) ||
	    (usmp_cmd->usmp_reqsize > SMP_MAX_REQUEST_SIZE) ||
	    (usmp_cmd->usmp_rspsize < SMP_MIN_RESPONSE_SIZE) ||
	    (usmp_cmd->usmp_rspsize > SMP_MAX_RESPONSE_SIZE)) {
		rval = EINVAL;
		goto done;
	}

	smp_pkt->smp_pkt_reqsize = usmp_cmd->usmp_reqsize;
	smp_pkt->smp_pkt_rspsize = usmp_cmd->usmp_rspsize;

	/* allocate memory space for smp request and response frame in kernel */
	smp_pkt->smp_pkt_req = kmem_zalloc((size_t)usmp_cmd->usmp_reqsize,
	    KM_SLEEP);
	cmd_flags |= SMP_FLAG_REQBUF;

	smp_pkt->smp_pkt_rsp = kmem_zalloc((size_t)usmp_cmd->usmp_rspsize,
	    KM_SLEEP);
	cmd_flags |= SMP_FLAG_RSPBUF;

	/* copy smp request frame to kernel space */
	if (ddi_copyin(usmp_cmd->usmp_req, smp_pkt->smp_pkt_req,
	    (size_t)usmp_cmd->usmp_reqsize, flag) != 0) {
		rval = EFAULT;
		goto done;
	}

	DTRACE_PROBE1(smp__transport__start, caddr_t, smp_pkt->smp_pkt_req);

	smp_pkt->smp_pkt_address = &smp_state->smp_sd->smp_sd_address;
	if (usmp_cmd->usmp_timeout <= 0) {
		smp_pkt->smp_pkt_timeout = SMP_DEFAULT_TIMEOUT;
	} else {
		smp_pkt->smp_pkt_timeout = usmp_cmd->usmp_timeout;
	}

	/* call smp_transport entry and send smp_pkt to HBA driver */
	cmd_flags |= SMP_FLAG_XFER;
	for (retrycount = 0; retrycount <= smp_retry_times; retrycount++) {

		/*
		 * To improve transport reliability, only allow one command
		 * outstanding at a time in smp_transport().
		 *
		 * NOTE: Some expanders have issues with heavy smp load.
		 */
		if (smp_single_command) {
			mutex_enter(&smp_state->smp_mutex);
			while (smp_state->smp_busy)
				cv_wait(&smp_state->smp_cv,
				    &smp_state->smp_mutex);
			smp_state->smp_busy = 1;
			mutex_exit(&smp_state->smp_mutex);
		}

		/* Let the transport know if more retries are possible. */
		smp_pkt->smp_pkt_will_retry =
		    (retrycount < smp_retry_times) ? 1 : 0;

		smp_pkt->smp_pkt_reason = 0;
		rval = smp_transport(smp_pkt);	/* put on the wire */

		if (smp_delay_cmd)
			delay(drv_usectohz(smp_delay_cmd));

		if (smp_single_command) {
			mutex_enter(&smp_state->smp_mutex);
			smp_state->smp_busy = 0;
			cv_signal(&smp_state->smp_cv);
			mutex_exit(&smp_state->smp_mutex);
		}

		if (rval == DDI_SUCCESS) {
			if (retrycount)
				smp_retry_recovered++;
			rval = 0;
			break;
		}

		switch (smp_pkt->smp_pkt_reason) {
		case EAGAIN:
			if (retrycount < smp_retry_times) {
				bzero(smp_pkt->smp_pkt_rsp,
				    (size_t)usmp_cmd->usmp_rspsize);
				if (smp_retry_delay)
					delay(drv_usectohz(smp_retry_delay));
				continue;
			} else {
				smp_retry_failed++;
				smp_log(smp_state, CE_NOTE,
				    "!smp_transport failed, smp_pkt_reason %d",
				    smp_pkt->smp_pkt_reason);
				rval = smp_pkt->smp_pkt_reason;
				goto copyout;
			}
		default:
			smp_log(smp_state, CE_NOTE,
			    "!smp_transport failed, smp_pkt_reason %d",
			    smp_pkt->smp_pkt_reason);
			rval = smp_pkt->smp_pkt_reason;
			goto copyout;
		}
	}

copyout:
	/* copy out smp response to user process */
	if (ddi_copyout(smp_pkt->smp_pkt_rsp, usmp_cmd->usmp_rsp,
	    (size_t)usmp_cmd->usmp_rspsize, flag) != 0) {
		rval = EFAULT;
	}

done:
	if ((cmd_flags & SMP_FLAG_XFER) != 0) {
		DTRACE_PROBE2(smp__transport__done, caddr_t,
		    smp_pkt->smp_pkt_rsp, uchar_t, smp_pkt->smp_pkt_reason);
	}
	if ((cmd_flags & SMP_FLAG_REQBUF) != 0) {
		kmem_free(smp_pkt->smp_pkt_req, smp_pkt->smp_pkt_reqsize);
	}
	if ((cmd_flags & SMP_FLAG_RSPBUF) != 0) {
		kmem_free(smp_pkt->smp_pkt_rsp, smp_pkt->smp_pkt_rspsize);
	}

	if (rval)
		smp_failed++;
	return (rval);
}

/*ARGSUSED*/
static int
smp_ioctl(dev_t dev,
    int cmd, intptr_t arg, int flag, cred_t *cred_p, int *rval_p)
{
	int rval = 0;

	switch (cmd) {
	case USMPFUNC:
		/*
		 * The response payload is valid only if return value is 0
		 * or EOVERFLOW.
		 */
		rval = smp_handle_func(dev, arg, flag, cred_p, rval_p);
		break;
	default:
		rval = EINVAL;
	}
	return (rval);
}

static void
smp_log(smp_state_t *smp_state, int level, const char *fmt, ...)
{
	va_list	ap;
	char buf[256];
	dev_info_t *dip;

	if (smp_state == (smp_state_t *)NULL) {
		dip = NULL;
	} else {
		dip = smp_state->smp_sd->smp_sd_dev;
	}

	va_start(ap, fmt);
	(void) vsnprintf(buf, sizeof (buf), fmt, ap);
	va_end(ap);

	scsi_log(dip, "smp", level, "%s", buf);
}
