/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Data-Link Driver
 */

#include	<sys/types.h>
#include	<sys/stream.h>
#include	<sys/conf.h>
#include	<sys/stat.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/dlpi.h>
#include	<sys/modctl.h>
#include	<sys/kmem.h>
#include	<inet/common.h>

#include	<sys/dls.h>
#include	<sys/dld.h>
#include	<sys/dld_impl.h>

static void	drv_init(void);
static int	drv_fini(void);

static int	drv_getinfo(dev_info_t	*, ddi_info_cmd_t, void *, void **);
static int	drv_attach(dev_info_t *, ddi_attach_cmd_t);
static int	drv_detach(dev_info_t *, ddi_detach_cmd_t);

static int	drv_open(queue_t *, dev_t *, int, int, cred_t *);
static int	drv_close(queue_t *);

static void	drv_uw_put(queue_t *, mblk_t *);
static void	drv_uw_srv(queue_t *);

dev_info_t	*dld_dip;		/* dev_info_t for the driver */
uint32_t	dld_opt;		/* Global options */
boolean_t	dld_open;		/* Flag to note that the control */
					/* node is open */
boolean_t	dld_aul = B_TRUE;	/* Set to B_FALSE to prevent driver */
					/* unloading */

static kmutex_t	drv_lock;		/* Needs no initialization */

static	struct	module_info	drv_info = {
	0,			/* mi_idnum */
	DLD_DRIVER_NAME,	/* mi_idname */
	0,			/* mi_minpsz */
	(64 * 1024),		/* mi_maxpsz */
	1,			/* mi_hiwat */
	0			/* mi_lowat */
};

static	struct qinit		drv_ur_init = {
	NULL,			/* qi_putp */
	NULL,			/* qi_srvp */
	drv_open,		/* qi_qopen */
	drv_close,		/* qi_qclose */
	NULL,			/* qi_qadmin */
	&drv_info,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static	struct qinit		drv_uw_init = {
	(pfi_t)drv_uw_put,	/* qi_putp */
	(pfi_t)drv_uw_srv,	/* qi_srvp */
	NULL,			/* qi_qopen */
	NULL,			/* qi_qclose */
	NULL,			/* qi_qadmin */
	&drv_info,		/* qi_minfo */
	NULL			/* qi_mstat */
};

static	struct streamtab	drv_stream = {
	&drv_ur_init,		/* st_rdinit */
	&drv_uw_init,		/* st_wrinit */
	NULL,			/* st_muxrinit */
	NULL			/* st_muxwinit */
};

DDI_DEFINE_STREAM_OPS(drv_ops, nulldev, nulldev, drv_attach, drv_detach,
    nodev, drv_getinfo, D_MP | D_MTQPAIR | D_MTPUTSHARED, &drv_stream);

/*
 * Module linkage information for the kernel.
 */

extern	struct mod_ops		mod_driverops;

static	struct modldrv		drv_modldrv = {
	&mod_driverops,
	DLD_INFO,
	&drv_ops
};

static	struct modlinkage	drv_modlinkage = {
	MODREV_1,
	&drv_modldrv,
	NULL
};

int
_init(void)
{
	int	err;

	if ((err = mod_install(&drv_modlinkage)) != 0)
		return (err);

#ifdef	DEBUG
	cmn_err(CE_NOTE, "!%s loaded", DLD_INFO);
#endif	/* DEBUG */

	return (0);
}

int
_fini(void)
{
	int	err;

	if (!dld_aul)
		return (ENOTSUP);

	if ((err = mod_remove(&drv_modlinkage)) != 0)
		return (err);

#ifdef	DEBUG
	cmn_err(CE_NOTE, "!%s unloaded", DLD_INFO);
#endif	/* DEBUG */

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&drv_modlinkage, modinfop));
}


/*
 * Initialize compoment modules.
 */
static void
drv_init(void)
{
	dld_minor_init();
	dld_node_init();
	dld_str_init();
	dld_ppa_init();
}

static int
drv_fini(void)
{
	int	err;

	if ((err = dld_ppa_fini()) != 0)
		return (err);

	err = dld_str_fini();
	ASSERT(err == 0);

	err = dld_node_fini();
	ASSERT(err == 0);

	err = dld_minor_fini();
	ASSERT(err == 0);

	return (0);
}

/*
 * devo_getinfo: getinfo(9e)
 */
/*ARGSUSED*/
static int
drv_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resp)
{
	if (dld_dip == NULL)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*resp = (void *)0;
		break;
	case DDI_INFO_DEVT2DEVINFO:
		*resp = (void *)dld_dip;
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Check properties to set options. (See dld.h for property definitions).
 */
static void
drv_set_opt(dev_info_t *dip)
{
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    DLD_PROP_NO_STYLE1, 0) != 0) {
#ifdef	DEBUG
		cmn_err(CE_NOTE, "%s: ON", DLD_PROP_NO_STYLE1);
#endif	/* DEBUG */
		dld_opt |= DLD_OPT_NO_STYLE1;
	}

	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    DLD_PROP_NO_FASTPATH, 0) != 0) {
#ifdef	DEBUG
		cmn_err(CE_NOTE, "%s: ON", DLD_PROP_NO_FASTPATH);
#endif	/* DEBUG */
		dld_opt |= DLD_OPT_NO_FASTPATH;
	}

	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    DLD_PROP_NO_POLL, 0) != 0) {
#ifdef	DEBUG
		cmn_err(CE_NOTE, "%s: ON", DLD_PROP_NO_POLL);
#endif	/* DEBUG */
		dld_opt |= DLD_OPT_NO_POLL;
	}

	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    DLD_PROP_NO_ZEROCOPY, 0) != 0) {
#ifdef	DEBUG
		cmn_err(CE_NOTE, "%s: ON", DLD_PROP_NO_ZEROCOPY);
#endif	/* DEBUG */
		dld_opt |= DLD_OPT_NO_ZEROCOPY;
	}
}

/*
 * devo_attach: attach(9e)
 */
static int
drv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	ASSERT(ddi_get_instance(dip) == 0);

	drv_init();
	drv_set_opt(dip);

	/*
	 * Create control node. DLPI provider nodes will be created on demand.
	 */
	if (ddi_create_minor_node(dip, DLD_CONTROL_MINOR_NAME, S_IFCHR,
	    DLD_CONTROL_MINOR, DDI_PSEUDO, 0) != DDI_SUCCESS)
		return (DDI_FAILURE);

	dld_dip = dip;

	/*
	 * Log the fact that the driver is now attached.
	 */
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

/*
 * devo_detach: detach(9e)
 */
static int
drv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	if (drv_fini() != 0)
		return (DDI_FAILURE);

	ASSERT(dld_dip == dip);

	/*
	 * Remove the control node.
	 */
	ddi_remove_minor_node(dip, DLD_CONTROL_MINOR_NAME);
	dld_dip = NULL;

	return (DDI_SUCCESS);
}

/*
 * qi_qopen: open(9e)
 */
/*ARGSUSED*/
static int
drv_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	dld_str_t	*dsp;
	dld_node_t	*dnp;
	dld_ppa_t	*dpp;
	minor_t		minor;
	int		err;

	ASSERT(sflag != MODOPEN);

	/*
	 * This is a cloning driver and therefore each queue should only
	 * ever get opened once.
	 */
	ASSERT(rq->q_ptr == NULL);
	if (rq->q_ptr != NULL)
		return (EBUSY);

	/*
	 * Grab the minor number of the dev_t that was opened. Because this
	 * is a cloning driver this will be distinct from the actual minor
	 * of the dev_t handed back.
	 */
	minor = getminor(*devp);

	/*
	 * Create a new dld_str_t for the stream. This will grab a new minor
	 * number that will be handed back in the cloned dev_t.
	 */
	dsp = dld_str_create(rq);

	if (minor != DLD_CONTROL_MINOR) {
		/*
		 * This is not the control node, so look up the DLPI
		 * provider node that is being opened.
		 */
		if ((dnp = dld_node_find(minor)) == NULL) {
			err = ENODEV;
			goto failed;
		}

		dsp->ds_dnp = dnp;
		dsp->ds_type = DLD_DLPI;

		ASSERT(dsp->ds_dlstate == DL_UNATTACHED);
		if (dnp->dn_style == DL_STYLE1) {
			/*
			 * This is a style 1 provider node so we have a
			 * non-ambiguous PPA.
			 */
			dpp = dld_node_ppa_find(dnp, -1);

			if ((err = dld_str_attach(dsp, dpp)) != 0)
				goto failed;
			dsp->ds_dlstate = DL_UNBOUND;
		}
	} else {
		/*
		 * This is the control node. It is exclusive-access so
		 * verify that it is not already open.
		 */
		mutex_enter(&drv_lock);
		if (dld_open) {
			err = EBUSY;
			mutex_exit(&drv_lock);
			goto failed;
		}

		dld_open = B_TRUE;
		mutex_exit(&drv_lock);

		dsp->ds_type = DLD_CONTROL;
	}

	/*
	 * Enable the queue srv(9e) routine.
	 */
	qprocson(rq);

	/*
	 * Construct a cloned dev_t to hand back.
	 */
	*devp = makedevice(getmajor(*devp), dsp->ds_minor);
	return (0);

failed:
	dld_str_destroy(dsp);
	return (err);
}

/*
 * qi_qclose: close(9e)
 */
static int
drv_close(queue_t *rq)
{
	dld_str_t	*dsp;

	dsp = rq->q_ptr;
	ASSERT(dsp != NULL);

	/*
	 * Disable the queue srv(9e) routine.
	 */
	qprocsoff(rq);

	if (dsp->ds_type != DLD_CONTROL) {
		/*
		 * This stream was open to a provider node. Check to see
		 * if it has been cleanly shut down.
		 */
		if (dsp->ds_dlstate != DL_UNATTACHED) {
			/*
			 * The stream is either open to a style 1 provider or
			 * this is not clean shutdown. Detach from the PPA.
			 * (This is still ok even in the style 1 case).
			 */
			dld_str_detach(dsp);
			dsp->ds_dlstate = DL_UNATTACHED;
		}
	} else {
		/*
		 * This stream was open to the control node. Clear the flag
		 * to allow another stream access.
		 */
		ASSERT(dld_open);
		dld_open = B_FALSE;
	}

	dld_str_destroy(dsp);
	return (0);
}

/*
 * qi_qputp: put(9e)
 */
static void
drv_uw_put(queue_t *wq, mblk_t *mp)
{
	dld_str_t	*dsp;

	dsp = wq->q_ptr;
	ASSERT(dsp != NULL);

	/*
	 * Call the put(9e) processor.
	 */
	dld_str_put(dsp, mp);
}

/*
 * qi_srvp: srv(9e)
 */
static void
drv_uw_srv(queue_t *wq)
{
	mblk_t		*mp = NULL;
	mblk_t		*p;
	mblk_t		**pp;
	dld_str_t	*dsp;

	dsp = wq->q_ptr;
	ASSERT(dsp != NULL);

	/*
	 * Loop round and pull a chain of messages from the queue.
	 */
	for (pp = &mp; (p = getq(wq)) != NULL; pp = &(p->b_next))
		*pp = p;

	/*
	 * If there was nothing on the queue then there's nothing to do.
	 */
	if (mp == NULL)
		return;

	/*
	 * Call the srv(9e) processor.
	 */
	dld_str_srv(dsp, mp);
}
