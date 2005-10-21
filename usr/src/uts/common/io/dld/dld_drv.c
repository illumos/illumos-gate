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

#include	<sys/conf.h>
#include	<sys/mkdev.h>
#include	<sys/modctl.h>
#include	<sys/stat.h>
#include	<sys/strsun.h>
#include	<sys/dld.h>
#include	<sys/dld_impl.h>
#include	<sys/dls_impl.h>
#include	<inet/common.h>

/*
 * dld control node state, one per open control node session.
 */
typedef struct dld_ctl_str_s {
	minor_t cs_minor;
	queue_t *cs_wq;
} dld_ctl_str_t;

static void	drv_init(void);
static int	drv_fini(void);

static int	drv_getinfo(dev_info_t	*, ddi_info_cmd_t, void *, void **);
static int	drv_attach(dev_info_t *, ddi_attach_cmd_t);
static int	drv_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * The following entry points are private to dld and are used for control
 * operations only. The entry points exported to mac drivers are defined
 * in dld_str.c. Refer to the comment on top of dld_str.c for details.
 */
static int	drv_open(queue_t *, dev_t *, int, int, cred_t *);
static int	drv_close(queue_t *);

static void	drv_uw_put(queue_t *, mblk_t *);
static void	drv_uw_srv(queue_t *);

dev_info_t	*dld_dip;		/* dev_info_t for the driver */
uint32_t	dld_opt = 0;		/* Global options */
static vmem_t	*dld_ctl_vmem;		/* for control minor numbers */

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
    nodev, drv_getinfo, D_MP, &drv_stream);

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

	drv_init();

	if ((err = mod_install(&drv_modlinkage)) != 0)
		return (err);

	return (0);
}

int
_fini(void)
{
	int	err;

	if ((err = mod_remove(&drv_modlinkage)) != 0)
		return (err);

	if (drv_fini() != 0) {
		(void) mod_install(&drv_modlinkage);
		return (DDI_FAILURE);
	}

	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&drv_modlinkage, modinfop));
}


/*
 * Initialize component modules.
 */
static void
drv_init(void)
{
	dld_ctl_vmem = vmem_create("dld_ctl", (void *)1, MAXMIN, 1,
	    NULL, NULL, NULL, 1, VM_SLEEP | VMC_IDENTIFIER);
	dld_str_init();
}

static int
drv_fini(void)
{
	int	err;

	if ((err = dld_str_fini()) != 0)
		return (err);

	vmem_destroy(dld_ctl_vmem);
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
	    DLD_PROP_NO_FASTPATH, 0) != 0) {
		dld_opt |= DLD_OPT_NO_FASTPATH;
	}

	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    DLD_PROP_NO_POLL, 0) != 0) {
		dld_opt |= DLD_OPT_NO_POLL;
	}

	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    DLD_PROP_NO_ZEROCOPY, 0) != 0) {
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

	ASSERT(dld_dip == dip);

	/*
	 * Remove the control node.
	 */
	ddi_remove_minor_node(dip, DLD_CONTROL_MINOR_NAME);
	dld_dip = NULL;

	return (DDI_SUCCESS);
}

/*
 * dld control node open procedure.
 */
/*ARGSUSED*/
static int
drv_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	dld_ctl_str_t	*ctls;
	minor_t		minor;
	queue_t *oq =	OTHERQ(rq);

	if (sflag == MODOPEN)
		return (ENOTSUP);

	/*
	 * This is a cloning driver and therefore each queue should only
	 * ever get opened once.
	 */
	if (rq->q_ptr != NULL)
		return (EBUSY);

	minor = (minor_t)(uintptr_t)vmem_alloc(dld_ctl_vmem, 1, VM_NOSLEEP);
	if (minor == 0)
		return (ENOMEM);

	ctls = kmem_zalloc(sizeof (dld_ctl_str_t), KM_NOSLEEP);
	if (ctls == NULL) {
		vmem_free(dld_ctl_vmem, (void *)(uintptr_t)minor, 1);
		return (ENOMEM);
	}

	ctls->cs_minor = minor;
	ctls->cs_wq = WR(rq);

	rq->q_ptr = ctls;
	oq->q_ptr = ctls;

	/*
	 * Enable the queue srv(9e) routine.
	 */
	qprocson(rq);

	/*
	 * Construct a cloned dev_t to hand back.
	 */
	*devp = makedevice(getmajor(*devp), ctls->cs_minor);
	return (0);
}

/*
 * dld control node close procedure.
 */
static int
drv_close(queue_t *rq)
{
	dld_ctl_str_t	*ctls;

	ctls = rq->q_ptr;
	ASSERT(ctls != NULL);

	/*
	 * Disable the queue srv(9e) routine.
	 */
	qprocsoff(rq);

	vmem_free(dld_ctl_vmem, (void *)(uintptr_t)ctls->cs_minor, 1);

	kmem_free(ctls, sizeof (dld_ctl_str_t));

	return (0);
}

/*
 * DLDIOCATTR
 */
static void
drv_ioc_attr(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_attr_t *diap;
	dls_vlan_t	*dvp = NULL;
	dls_link_t	*dlp = NULL;
	int		err;
	queue_t		*q = ctls->cs_wq;

	if ((err = miocpullup(mp, sizeof (dld_ioc_attr_t))) != 0)
		goto failed;

	diap = (dld_ioc_attr_t *)mp->b_cont->b_rptr;
	diap->dia_name[IFNAMSIZ - 1] = '\0';

	if (dls_vlan_hold(diap->dia_name, &dvp, B_FALSE) != 0) {
		err = ENOENT;
		goto failed;
	}

	dlp = dvp->dv_dlp;
	(void) strlcpy(diap->dia_dev, dlp->dl_dev, MAXNAMELEN);
	diap->dia_port = dlp->dl_port;
	diap->dia_vid = dvp->dv_id;
	diap->dia_max_sdu = dlp->dl_mip->mi_sdu_max;

	dls_vlan_rele(dvp);
	miocack(q, mp, sizeof (dld_ioc_attr_t), 0);
	return;

failed:
	ASSERT(err != 0);
	if (err == ENOENT) {
		char	devname[MAXNAMELEN];
		uint_t	instance;
		major_t	major;

		/*
		 * Try to detect if the specified device is gldv3
		 * and return ENODEV if it is not.
		 */
		if (ddi_parse(diap->dia_name, devname, &instance) == 0 &&
		    (major = ddi_name_to_major(devname)) != (major_t)-1 &&
		    !GLDV3_DRV(major))
			err = ENODEV;
	}
	miocnak(q, mp, 0, err);
}


/*
 * DLDIOCVLAN
 */
typedef struct dld_ioc_vlan_state {
	uint_t		bytes_left;
	dld_ioc_vlan_t	*divp;
	dld_vlan_info_t	*vlanp;
} dld_ioc_vlan_state_t;

static int
drv_ioc_vlan_info(dls_vlan_t *dvp, void *arg)
{
	dld_ioc_vlan_state_t	*statep = arg;

	/*
	 * passed buffer space is limited to 65536 bytes. So
	 * copy only the vlans associated with the passed link.
	 */
	if (strcmp(dvp->dv_dlp->dl_dev, statep->divp->div_name) == 0 &&
	    dvp->dv_dlp->dl_port == statep->divp->div_port &&
	    dvp->dv_id != 0) {
		if (statep->bytes_left < sizeof (dld_vlan_info_t))
			return (ENOSPC);

		(void) strlcpy(statep->vlanp->dvi_name,
		    dvp->dv_name, IFNAMSIZ);
		statep->divp->div_count++;
		statep->bytes_left -= sizeof (dld_vlan_info_t);
		statep->vlanp += 1;
	}
	return (0);
}

static void
drv_ioc_vlan(dld_ctl_str_t *ctls, mblk_t *mp)
{
	dld_ioc_vlan_t		*divp;
	dld_ioc_vlan_state_t	state;
	int			err = EINVAL;
	queue_t			*q = ctls->cs_wq;
	mblk_t			*bp;

	if ((err = miocpullup(mp, sizeof (dld_ioc_vlan_t))) != 0)
		goto failed;

	if ((bp = msgpullup(mp->b_cont, -1)) == NULL)
		goto failed;

	freemsg(mp->b_cont);
	mp->b_cont = bp;
	divp = (dld_ioc_vlan_t *)bp->b_rptr;
	divp->div_count = 0;
	state.bytes_left = MBLKL(bp) - sizeof (dld_ioc_vlan_t);
	state.divp = divp;
	state.vlanp = (dld_vlan_info_t *)(divp + 1);

	err = dls_vlan_walk(drv_ioc_vlan_info, &state);
	if (err != 0)
		goto failed;

	miocack(q, mp, sizeof (dld_ioc_vlan_t) +
	    state.divp->div_count * sizeof (dld_vlan_info_t), 0);
	return;

failed:
	ASSERT(err != 0);
	miocnak(q, mp, 0, err);
}


/*
 * Process an IOCTL message received by the control node.
 */
static void
drv_ioc(dld_ctl_str_t *ctls, mblk_t *mp)
{
	uint_t	cmd;

	cmd = ((struct iocblk *)mp->b_rptr)->ioc_cmd;
	switch (cmd) {
	case DLDIOCATTR:
		drv_ioc_attr(ctls, mp);
		return;
	case DLDIOCVLAN:
		drv_ioc_vlan(ctls, mp);
		return;
	default:
		miocnak(ctls->cs_wq, mp, 0, ENOTSUP);
		return;
	}
}

/*
 * Write side put routine of the dld control node.
 */
static void
drv_uw_put(queue_t *q, mblk_t *mp)
{
	dld_ctl_str_t *ctls = q->q_ptr;

	switch (mp->b_datap->db_type) {
	case M_IOCTL:
		drv_ioc(ctls, mp);
		break;
	default:
		freemsg(mp);
		break;
	}
}

/*
 * Write-side service procedure.
 */
void
drv_uw_srv(queue_t *q)
{
	mblk_t *mp;

	while (mp = getq(q))
		drv_uw_put(q, mp);
}
