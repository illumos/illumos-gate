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
 * Copyright (C) 4Front Technologies 1996-2008.
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/list.h>
#include <sys/mkdev.h>
#include <sys/conf.h>
#include <sys/note.h>
#include <sys/atomic.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "audio_impl.h"

/*
 * Audio DDI glue implementation.
 */

/*
 * The audio module is itself a pseudo driver, as it contains the
 * logic to support un-associated nodes.  (Think generic /dev/mixer
 * and /dev/sndstat used by OSS.)
 */
static int
audio_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	audio_dev_t	*adev;

	/* pseudo devices don't need S/R support */
	if ((cmd != DDI_ATTACH) || (dip == NULL)) {
		return (DDI_FAILURE);
	}

	if (ddi_get_instance(dip) != 0) {
		return (DDI_FAILURE);
	}

	/* this can't fail */
	adev = audio_dev_alloc(dip, 0);
	adev->d_flags = DEV_SNDSTAT_CAP;
	audio_dev_set_description(adev, "Audio Common Code");
	audio_dev_set_version(adev, "pseudo");
	ddi_set_driver_private(dip, adev);

	/* look up our properties! */

	if (audio_dev_register(adev) != DDI_SUCCESS) {
		audio_dev_free(adev);
		return (DDI_FAILURE);
	}

	ddi_report_dev(dip);

	return (DDI_SUCCESS);
}

static int
audio_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	audio_dev_t	*adev;

	/* pseudo devices don't need S/R support */
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (dip == NULL) {
		return (DDI_FAILURE);
	}

	if ((adev = ddi_get_driver_private(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	if (audio_dev_unregister(adev) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	audio_dev_free(adev);

	return (DDI_SUCCESS);
}

static int
audio_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resp)
{
	dip = NULL;

	if (getminor((dev_t)arg) & AUDIO_MN_CLONE_MASK) {
		audio_client_t *c;
		c = auclnt_hold_by_devt((dev_t)arg);
		if (c != NULL) {
			dip = c->c_dev->d_dip;
			auclnt_release(c);
		}
	} else {
		audio_dev_t	*adev;
		if ((adev = auimpl_dev_hold_by_devt((dev_t)arg)) != NULL) {
			dip = adev->d_dip;
			auimpl_dev_release(adev);
		}
	}

	if (dip == NULL) {
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resp = dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resp = (void *)(uintptr_t)ddi_get_instance(dip);
		break;
	default:
		*resp = NULL;
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
audio_open(dev_t *devp, int oflag, int otyp, cred_t *credp)
{
	int			rv;
	audio_client_t		*c;

	if (otyp == OTYP_BLK) {
		return (ENXIO);
	}

	if ((c = auimpl_client_create(*devp)) == NULL) {
		audio_dev_warn(NULL, "client create failed");
		return (ENXIO);
	}

	c->c_omode = oflag;
	c->c_pid = ddi_get_pid();
	c->c_cred = credp;

	/*
	 * Call client/personality specific open handler.  Note that
	 * we "insist" that there is an open.  The personality layer
	 * will initialize/allocate any engines required.
	 *
	 * Hmm... do we need to pass in the cred?
	 */
	if ((rv = c->c_open(c, oflag)) != 0) {
		audio_dev_warn(c->c_dev, "open failed (rv %d)", rv);
		auimpl_client_destroy(c);
		return (rv);
	}

	/* we do device cloning! */
	*devp = makedevice(c->c_major, c->c_minor);

	/* now we can receive upcalls */
	auimpl_client_activate(c);

	atomic_inc_uint(&c->c_dev->d_serial);

	return (0);
}

static int
audio_stropen(queue_t *rq, dev_t *devp, int oflag, int sflag, cred_t *credp)
{
	int			rv;
	audio_client_t		*c;

	if (sflag != 0) {
		/* no direct clone or module opens */
		return (ENXIO);
	}

	/*
	 * Make sure its a STREAMS personality - only legacy Sun API uses
	 * STREAMS.
	 */
	switch (AUDIO_MN_TYPE_MASK & getminor(*devp)) {
	case AUDIO_MINOR_DEVAUDIO:
	case AUDIO_MINOR_DEVAUDIOCTL:
		break;
	default:
		return (ENOSTR);
	}

	if ((c = auimpl_client_create(*devp)) == NULL) {
		audio_dev_warn(NULL, "client create failed");
		return (ENXIO);
	}

	rq->q_ptr = WR(rq)->q_ptr = c;
	c->c_omode = oflag;
	c->c_pid = ddi_get_pid();
	c->c_cred = credp;
	c->c_rq = rq;
	c->c_wq = WR(rq);

	/*
	 * Call client/personality specific open handler.  Note that
	 * we "insist" that there is an open.  The personality layer
	 * will initialize/allocate any engines required.
	 *
	 * Hmm... do we need to pass in the cred?
	 */
	if ((rv = c->c_open(c, oflag)) != 0) {
		audio_dev_warn(c->c_dev, "open failed (rv %d)", rv);
		auimpl_client_destroy(c);
		return (rv);
	}

	/* we do device cloning! */
	*devp = makedevice(c->c_major, c->c_minor);

	qprocson(rq);

	/* now we can receive upcalls */
	auimpl_client_activate(c);

	atomic_inc_uint(&c->c_dev->d_serial);

	return (0);
}

static int
audio_strclose(queue_t *rq, int flag, cred_t *credp)
{
	audio_client_t	*c;
	audio_dev_t	*d;
	int		rv;

	_NOTE(ARGUNUSED(flag));
	_NOTE(ARGUNUSED(credp));

	if ((c = rq->q_ptr) == NULL) {
		return (ENXIO);
	}
	if (ddi_can_receive_sig() || (ddi_get_pid() == 0)) {
		rv = auclnt_drain(c);
	}

	/* make sure we won't get any upcalls */
	auimpl_client_deactivate(c);

	/*
	 * Pick up any data sitting around in input buffers.  This
	 * avoids leaving record data stuck in queues.
	 */
	if (c->c_istream.s_engine != NULL)
		auimpl_input_callback(c->c_istream.s_engine);

	/* get a local hold on the device */
	d = c->c_dev;
	auimpl_dev_hold(c->c_dev);

	/* Turn off queue processing... */
	qprocsoff(rq);

	/* Call personality specific close handler */
	c->c_close(c);

	auimpl_client_destroy(c);

	/* notify peers that a change has occurred */
	atomic_inc_uint(&d->d_serial);

	/* now we can drop the release we had on the device */
	auimpl_dev_release(d);

	return (rv);
}

static int
audio_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	audio_client_t	*c;
	audio_dev_t	*d;

	_NOTE(ARGUNUSED(flag));
	_NOTE(ARGUNUSED(credp));
	_NOTE(ARGUNUSED(otyp));

	if ((c = auclnt_hold_by_devt(dev)) == NULL) {
		audio_dev_warn(NULL, "close on bogus devt %x,%x",
		    getmajor(dev), getminor(dev));
		return (ENXIO);
	}

	/* we don't want any upcalls anymore */
	auimpl_client_deactivate(c);

	/*
	 * Pick up any data sitting around in input buffers.  This
	 * avoids leaving record data stuck in queues.
	 */
	if (c->c_istream.s_engine != NULL)
		auimpl_input_callback(c->c_istream.s_engine);

	/* get a local hold on the device */
	d = c->c_dev;
	auimpl_dev_hold(c->c_dev);

	/*
	 * NB: This must be done before c->c_close, since it calls
	 * auclnt_close which will block waiting for the refence count
	 * to drop to zero.
	 */
	auclnt_release(c);

	/* Call personality specific close handler */
	c->c_close(c);

	auimpl_client_destroy(c);

	/* notify peers that a change has occurred */
	atomic_inc_uint(&d->d_serial);

	/* now we can drop the release we had on the device */
	auimpl_dev_release(d);

	return (0);
}

static int
audio_write(dev_t dev, struct uio *uio, cred_t *credp)
{
	audio_client_t *c;
	int rv;

	if ((c = auclnt_hold_by_devt(dev)) == NULL) {
		return (ENXIO);
	}
	if ((rv = auclnt_serialize(c)) == 0) {
		rv = (c->c_write == NULL) ? ENXIO : c->c_write(c, uio, credp);
		auclnt_unserialize(c);
	}
	auclnt_release(c);

	return (rv);
}

static int
audio_read(dev_t dev, struct uio *uio, cred_t *credp)
{
	audio_client_t *c;
	int rv;

	if ((c = auclnt_hold_by_devt(dev)) == NULL) {
		return (ENXIO);
	}
	if ((rv = auclnt_serialize(c)) == 0) {
		rv = (c->c_read == NULL) ? ENXIO : c->c_read(c, uio, credp);
		auclnt_unserialize(c);
	}
	auclnt_release(c);

	return (rv);
}

static int
audio_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	audio_client_t *c;
	int rv;

	if ((c = auclnt_hold_by_devt(dev)) == NULL) {
		return (ENXIO);
	}
	rv = (c->c_ioctl == NULL) ? ENXIO : c->c_ioctl(c, cmd, arg, mode,
	    credp, rvalp);
	auclnt_release(c);

	return (rv);
}

static int
audio_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	audio_client_t *c;
	int rv;

	if ((c = auclnt_hold_by_devt(dev)) == NULL) {
		return (ENXIO);
	}
	rv = (c->c_chpoll == NULL) ?
	    ENXIO :
	    c->c_chpoll(c, events, anyyet, reventsp, phpp);
	auclnt_release(c);

	return (rv);
}

static int
audio_wput(queue_t *wq, mblk_t *mp)
{
	audio_client_t	*c;

	c = wq->q_ptr;
	if (c->c_wput) {
		c->c_wput(c, mp);
	} else {
		freemsg(mp);
	}
	return (0);
}

static int
audio_wsrv(queue_t *wq)
{
	audio_client_t	*c;

	c = wq->q_ptr;
	if (c->c_wsrv) {
		c->c_wsrv(c);
	} else {
		flushq(wq, FLUSHALL);
	}
	return (0);
}

static int
audio_rsrv(queue_t *rq)
{
	audio_client_t	*c;

	c = rq->q_ptr;
	if (c->c_rsrv) {
		c->c_rsrv(c);
	} else {
		flushq(rq, FLUSHALL);
	}
	return (0);
}


static struct dev_ops audio_dev_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	NULL,			/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	audio_attach,		/* attach */
	audio_detach,		/* detach */
	nodev,			/* reset */
	NULL,			/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Audio Framework",
	&audio_dev_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,			/* MODREV_1 indicated by manual */
	&modldrv,
	NULL
};

struct audio_ops_helper {
	struct cb_ops		cbops;	/* NB: must be first */
	struct streamtab	strtab;
	struct qinit		rqinit;
	struct qinit		wqinit;
	struct module_info	minfo;
	char			name[MODMAXNAMELEN+1];
};

void
audio_init_ops(struct dev_ops *devops, const char *name)
{
	struct audio_ops_helper	*helper;

	helper = kmem_zalloc(sizeof (*helper), KM_SLEEP);

	(void) strlcpy(helper->name, name, sizeof (helper->name));

	helper->minfo.mi_idnum = 0;	/* only for strlog(1M) */
	helper->minfo.mi_idname = helper->name;
	helper->minfo.mi_minpsz = 0;
	helper->minfo.mi_maxpsz = 8192;
	helper->minfo.mi_hiwat = 65536;
	helper->minfo.mi_lowat = 32768;

	helper->wqinit.qi_putp = audio_wput;
	helper->wqinit.qi_srvp = audio_wsrv;
	helper->wqinit.qi_qopen = NULL;
	helper->wqinit.qi_qclose = NULL;
	helper->wqinit.qi_qadmin = NULL;
	helper->wqinit.qi_minfo = &helper->minfo;
	helper->wqinit.qi_mstat = NULL;

	helper->rqinit.qi_putp = putq;
	helper->rqinit.qi_srvp = audio_rsrv;
	helper->rqinit.qi_qopen = audio_stropen;
	helper->rqinit.qi_qclose = audio_strclose;
	helper->rqinit.qi_qadmin = NULL;
	helper->rqinit.qi_minfo = &helper->minfo;
	helper->rqinit.qi_mstat = NULL;

	helper->strtab.st_rdinit = &helper->rqinit;
	helper->strtab.st_wrinit = &helper->wqinit;
	helper->strtab.st_muxrinit = NULL;
	helper->strtab.st_muxwinit = NULL;

	helper->cbops.cb_open = audio_open;
	helper->cbops.cb_close = audio_close;
	helper->cbops.cb_strategy = nodev;
	helper->cbops.cb_print = nodev;
	helper->cbops.cb_dump = nodev;
	helper->cbops.cb_read = audio_read;
	helper->cbops.cb_write = audio_write;
	helper->cbops.cb_ioctl = audio_ioctl;
	helper->cbops.cb_devmap = nodev;
	helper->cbops.cb_mmap = nodev;
	helper->cbops.cb_segmap = nodev;
	helper->cbops.cb_chpoll = audio_chpoll;
	helper->cbops.cb_prop_op = ddi_prop_op;
	helper->cbops.cb_str = &helper->strtab;
	helper->cbops.cb_flag = D_MP | D_64BIT;
	helper->cbops.cb_rev = CB_REV;
	helper->cbops.cb_aread = nodev;
	helper->cbops.cb_awrite = nodev;

	devops->devo_cb_ops = &helper->cbops;
	devops->devo_getinfo = audio_getinfo;
}

void
audio_fini_ops(struct dev_ops *devops)
{
	kmem_free(devops->devo_cb_ops, sizeof (struct audio_ops_helper));
	devops->devo_cb_ops = NULL;
	devops->devo_getinfo = NULL;
}

void
auimpl_dev_vwarn(audio_dev_t *dev, const char *fmt, va_list va)
{
	char	buf[256];

	if (dev != NULL) {
		(void) snprintf(buf, sizeof (buf), "%s#%d: %s",
		    ddi_driver_name(dev->d_dip), ddi_get_instance(dev->d_dip),
		    fmt);
	} else {
		(void) snprintf(buf, sizeof (buf), "audio: %s", fmt);
	}

	vcmn_err(CE_WARN, buf, va);
}


void
audio_dev_warn(audio_dev_t *dev, const char *fmt, ...)
{
	va_list	va;

	va_start(va, fmt);
	auimpl_dev_vwarn(dev, fmt, va);
	va_end(va);
}

/*
 * _init, _info, and _fini DDI glue.
 */
int
_init(void)
{
	int	rv;

	auimpl_client_init();
	auimpl_dev_init();
	auimpl_sun_init();
	auimpl_oss_init();

	audio_init_ops(&audio_dev_ops, "audio");

	if ((rv = mod_install(&modlinkage)) != 0) {
		audio_fini_ops(&audio_dev_ops);
		auimpl_dev_fini();
		auimpl_client_fini();
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int rv;

	if ((rv = mod_remove(&modlinkage)) != 0)
		return (rv);

	auimpl_dev_fini();
	auimpl_client_fini();

	return (rv);
}
