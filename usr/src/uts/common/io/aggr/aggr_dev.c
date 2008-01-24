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
 * IEEE 802.3ad Link Aggregation.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/list.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/stat.h>

#include <sys/dld_impl.h>
#include <sys/aggr.h>
#include <sys/aggr_impl.h>
#include <inet/common.h>

/* module description */
#define	AGGR_LINKINFO	"Link Aggregation MAC"
#define	AGGR_DRIVER_NAME	"aggr"

/* device info ptr, only one for instance 0 */
dev_info_t *aggr_dip = NULL;

static int aggr_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int aggr_attach(dev_info_t *, ddi_attach_cmd_t);
static int aggr_detach(dev_info_t *, ddi_detach_cmd_t);
static int aggr_open(queue_t *, dev_t *, int, int, cred_t *);
static int aggr_close(queue_t *);
static void aggr_wput(queue_t *, mblk_t *);

/*
 * mi_hiwat is set to 1 because of the flow control mechanism implemented
 * in dld. refer to the comments in dld_str.c for details.
 */
static struct module_info aggr_module_info = {
	0,
	AGGR_DRIVER_NAME,
	0,
	INFPSZ,
	1,
	0
};

static struct qinit aggr_r_qinit = {	/* read queues */
	NULL,
	NULL,
	aggr_open,
	aggr_close,
	NULL,
	&aggr_module_info
};

static struct qinit aggr_w_qinit = {	/* write queues */
	(pfi_t)dld_wput,
	(pfi_t)dld_wsrv,
	NULL,
	NULL,
	NULL,
	&aggr_module_info
};

/*
 * Entry points for aggr control node
 */
static struct qinit aggr_w_ctl_qinit = {
	(pfi_t)aggr_wput,
	NULL,
	NULL,
	NULL,
	NULL,
	&aggr_module_info
};

static struct streamtab aggr_streamtab = {
	&aggr_r_qinit,
	&aggr_w_qinit
};

DDI_DEFINE_STREAM_OPS(aggr_dev_ops, nulldev, nulldev, aggr_attach, aggr_detach,
    nodev, aggr_getinfo, D_MP, &aggr_streamtab);

static struct modldrv aggr_modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	AGGR_LINKINFO,		/* short description */
	&aggr_dev_ops		/* driver specific ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&aggr_modldrv,
	NULL
};


int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
aggr_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	if (q->q_ptr != NULL)
		return (EBUSY);

	if (getminor(*devp) == AGGR_MINOR_CTL) {
		dld_str_t	*dsp;

		dsp = dld_str_create(q, DLD_CONTROL, getmajor(*devp),
		    DL_STYLE1);
		if (dsp == NULL)
			return (ENOSR);

		/*
		 * The ioctl handling callback to process control ioctl
		 * messages; see comments above dld_ioctl() for details.
		 */
		dsp->ds_ioctl = aggr_ioctl;

		/*
		 * The aggr control node uses its own set of entry points.
		 */
		WR(q)->q_qinfo = &aggr_w_ctl_qinit;
		*devp = makedevice(getmajor(*devp), dsp->ds_minor);
		qprocson(q);
		return (0);
	}
	return (dld_open(q, devp, flag, sflag, credp));
}

static int
aggr_close(queue_t *q)
{
	dld_str_t	*dsp = q->q_ptr;

	if (dsp->ds_type == DLD_CONTROL) {
		qprocsoff(q);
		dld_finish_pending_task(dsp);
		dsp->ds_ioctl = NULL;
		dld_str_destroy(dsp);
		return (0);
	}
	return (dld_close(q));
}

static void
aggr_wput(queue_t *q, mblk_t *mp)
{
	if (DB_TYPE(mp) == M_IOCTL)
		dld_ioctl(q, mp);
	else
		freemsg(mp);
}

/*ARGSUSED*/
static int
aggr_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = aggr_dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
aggr_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		if (ddi_get_instance(dip) != 0) {
			/* we only allow instance 0 to attach */
			return (DDI_FAILURE);
		}

		/* create minor node for control interface */
		if (ddi_create_minor_node(dip, AGGR_DEVNAME_CTL, S_IFCHR,
		    AGGR_MINOR_CTL, DDI_PSEUDO, 0) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		aggr_dip = dip;
		aggr_port_init();
		aggr_grp_init();
		aggr_lacp_init();
		return (DDI_SUCCESS);

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
aggr_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		if (aggr_grp_count() > 0)
			return (DDI_FAILURE);

		aggr_dip = NULL;
		ddi_remove_minor_node(dip, AGGR_DEVNAME_CTL);
		aggr_port_fini();
		aggr_grp_fini();
		aggr_lacp_fini();
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}
