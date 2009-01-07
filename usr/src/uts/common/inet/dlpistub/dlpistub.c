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
 * DLPI stub driver; currently supports VNI and IPMP stub devices.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dlpi.h>
#include <sys/stat.h>
#include <sys/strsun.h>
#include <sys/stropts.h>
#include <sys/types.h>
#include <sys/id_space.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/mkdev.h>
#include <sys/sdt.h>

#include "dlpistub_impl.h"

static id_space_t *ds_minors;
static dev_info_t *ds_dip;

/*
 * DL_INFO_ACK template.
 */
static dl_info_ack_t ds_infoack = {
	DL_INFO_ACK,	/* dl_primitive */
	0,		/* dl_max_sdu */
	0,		/* dl_min_sdu */
	0,		/* dl_addr_length */
	0,		/* dl_mac_type */
	0,		/* dl_reserved */
	0,		/* dl_current_state */
	0,		/* dl_sap_length */
	DL_CLDLS,	/* dl_service_mode */
	0,		/* dl_qos_length */
	0,		/* dl_qos_offset */
	0,		/* dl_qos_range_length */
	0,		/* dl_qos_range_offset */
	DL_STYLE2,	/* dl_provider_style */
	0,		/* dl_addr_offset */
	DL_VERSION_2,	/* dl_version */
	0,		/* dl_brdcst_addr_length */
	0,		/* dl_brdcst_addr_offset */
	0		/* dl_growth */
};

static int
ds_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_create_minor_node(dip, "vni", S_IFCHR, DS_MINOR_VNI,
	    DDI_PSEUDO, 0) == DDI_FAILURE ||
	    ddi_create_minor_node(dip, "ipmpstub", S_IFCHR, DS_MINOR_IPMP,
	    DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(dip, NULL);
		cmn_err(CE_NOTE, "ds_attach: cannot create minor nodes");
		return (DDI_FAILURE);
	}

	ds_dip = dip;
	ds_minors = id_space_create("ds_minors", DS_MINOR_START, MAXMIN32);
	return (DDI_SUCCESS);
}

static int
ds_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	id_space_destroy(ds_minors);
	ds_minors = NULL;
	ASSERT(dip == ds_dip);
	ddi_remove_minor_node(dip, NULL);
	ds_dip = NULL;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
ds_devinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2DEVINFO:
		if (ds_dip != NULL) {
			*result = ds_dip;
			error = DDI_SUCCESS;
		}
		break;
	}
	return (error);
}

/* ARGSUSED */
static int
ds_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	int type;
	dlpistub_t *dsp;

	if (sflag == CLONEOPEN || sflag == MODOPEN)
		return (EINVAL);

	if (q->q_ptr != NULL)
		return (0);

	switch (getminor(*devp)) {
	case DS_MINOR_VNI:
		type = SUNW_DL_VNI;
		break;
	case DS_MINOR_IPMP:
		type = SUNW_DL_IPMP;
		break;
	default:
		return (ENXIO);
	}

	dsp = kmem_zalloc(sizeof (dlpistub_t), KM_SLEEP);
	dsp->ds_type = type;
	dsp->ds_minor = (minor_t)id_alloc(ds_minors);
	dsp->ds_state = DL_UNATTACHED;
	*devp = makedevice(getmajor(*devp), dsp->ds_minor);
	q->q_ptr = WR(q)->q_ptr = dsp;
	qprocson(q);

	return (0);
}

/* ARGSUSED */
static int
ds_close(queue_t *q, int flag, cred_t *credp)
{
	dlpistub_t	*dsp = q->q_ptr;

	qprocsoff(q);
	q->q_ptr = WR(q)->q_ptr = NULL;

	id_free(ds_minors, dsp->ds_minor);
	kmem_free(dsp, sizeof (dlpistub_t));

	return (0);
}

static int
ds_badprim(queue_t *q, mblk_t *mp, t_scalar_t prim)
{
	dlerrorack(q, mp, prim, DL_BADPRIM, 0);
	return (0);
}

static int
ds_outstate(queue_t *q, mblk_t *mp, t_scalar_t prim)
{
	dlerrorack(q, mp, prim, DL_OUTSTATE, 0);
	return (0);
}

static int
ds_wput(queue_t *q, mblk_t *mp)
{
	union DL_primitives	*dlp;
	dl_info_ack_t		*dlip;
	dlpistub_t		*dsp = q->q_ptr;
	t_scalar_t		prim;

	switch (DB_TYPE(mp)) {
	case M_PROTO:
	case M_PCPROTO:
		if (MBLKL(mp) < sizeof (t_scalar_t)) {
			dlerrorack(q, mp, DL_PRIM_INVAL, DL_UNSUPPORTED, 0);
			return (0);
		}

		dlp = (void *)mp->b_rptr;
		prim = dlp->dl_primitive;
		switch (prim) {
		case DL_ATTACH_REQ:
			if (MBLKL(mp) < DL_ATTACH_REQ_SIZE)
				return (ds_badprim(q, mp, prim));

			if (dsp->ds_state != DL_UNATTACHED)
				return (ds_outstate(q, mp, prim));

			dsp->ds_state = DL_UNBOUND;
			dlokack(q, mp, DL_ATTACH_REQ);
			break;

		case DL_BIND_REQ:
			if (MBLKL(mp) < DL_BIND_REQ_SIZE)
				return (ds_badprim(q, mp, prim));

			if (dsp->ds_state != DL_UNBOUND)
				return (ds_outstate(q, mp, prim));

			dsp->ds_state = DL_IDLE;
			dlbindack(q, mp, dlp->bind_req.dl_sap, NULL, 0, 0, 0);
			break;

		case DL_INFO_REQ:
			if (MBLKL(mp) < DL_INFO_REQ_SIZE)
				return (ds_badprim(q, mp, prim));

			mp = mexchange(q, mp, sizeof (dl_info_ack_t),
			    M_PCPROTO, DL_INFO_ACK);
			if (mp != NULL) {
				dlip = (void *)mp->b_rptr;
				*dlip = ds_infoack;
				dlip->dl_mac_type = dsp->ds_type;
				dlip->dl_current_state = dsp->ds_state;
				qreply(q, mp);
			}
			break;

		case DL_PHYS_ADDR_REQ:
			if (MBLKL(mp) < DL_PHYS_ADDR_REQ_SIZE)
				return (ds_badprim(q, mp, prim));

			dlphysaddrack(q, mp, NULL, 0);
			break;

		case DL_UNBIND_REQ:
			if (MBLKL(mp) < DL_UNBIND_REQ_SIZE)
				return (ds_badprim(q, mp, prim));

			if (dsp->ds_state != DL_IDLE)
				return (ds_outstate(q, mp, prim));

			dsp->ds_state = DL_UNBOUND;
			dlokack(q, mp, DL_UNBIND_REQ);
			break;

		case DL_DETACH_REQ:
			if (MBLKL(mp) < DL_DETACH_REQ_SIZE)
				return (ds_badprim(q, mp, prim));

			if (dsp->ds_state != DL_UNBOUND)
				return (ds_outstate(q, mp, prim));

			dsp->ds_state = DL_UNATTACHED;
			dlokack(q, mp, DL_DETACH_REQ);
			break;

		case DL_UNITDATA_REQ:
			DTRACE_PROBE2(dlpistub__data, dlpistub_t *, dsp,
			    mblk_t *, mp);
			freemsg(mp);
			break;

		default:
			dlerrorack(q, mp, prim, DL_UNSUPPORTED, 0);
		}
		break;

	case M_IOCTL:
		miocnak(q, mp, 0, EINVAL);
		break;

	case M_FLUSH:
		*mp->b_rptr &= ~FLUSHW;
		if (*mp->b_rptr & FLUSHR)
			qreply(q, mp);
		else
			freemsg(mp);
		break;
	default:
		freemsg(mp);
		break;
	}

	return (0);
}

static struct module_info ds_minfo = {
	DS_IDNUM,	/* mi_idnum */
	"dlpistub",	/* mi_idname */
	0,		/* mi_minpsz */
	INFPSZ,		/* mi_maxpsz */
	0,		/* mi_hiwat */
	0,		/* mi_lowat */
};

static struct qinit ds_rinit = {
	NULL,		/* qi_putp */
	NULL,		/* qi_srvp */
	ds_open,	/* qi_qopen */
	ds_close,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&ds_minfo,	/* qi_minfo */
};

static struct qinit ds_winit = {
	ds_wput,	/* qi_putp */
	NULL,		/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&ds_minfo,	/* qi_minfo */
};

static struct streamtab ds_info = {
	&ds_rinit,	/* st_rdinit */
	&ds_winit	/* st_wrinit */
};

DDI_DEFINE_STREAM_OPS(ds_ops, nulldev, nulldev, ds_attach, ds_detach,
    nodev, ds_devinfo, D_MP|D_MTPERMOD, &ds_info, ddi_quiesce_not_supported);

static struct modldrv modldrv = {
	&mod_driverops,
	"DLPI stub driver",
	&ds_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
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
