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


#include "vni_impl.h"
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dlpi.h>
#include <sys/stat.h>
#include <sys/ethernet.h>
#include <sys/strsun.h>
#include <sys/stropts.h>

static int vniopen(queue_t *, dev_t *, int, int, cred_t *);
static int vniclose(queue_t *, int, cred_t *);
static int vniwput(queue_t *, mblk_t *);
static int vniattach(dev_info_t *, ddi_attach_cmd_t);
static int vnidetach(dev_info_t *, ddi_detach_cmd_t);

static struct module_info minfo = {
	VNIIDNUM,	/* mi_idnum */
	VNINAME,	/* mi_idname */
	VNIMINPSZ,	/* mi_minpsz */
	VNIMAXPSZ,	/* mi_maxpsz */
	VNIHIWAT,	/* mi_hiwat */
	VNILOWAT	/* mi_lowat */
};

static struct qinit vnirinit = {
	NULL,		/* qi_putp */
	NULL,		/* qi_srvp */
	vniopen,	/* qi_qopen */
	vniclose,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&minfo,		/* qi_minfo */
	NULL		/* qi_mstat */
};

static struct qinit vniwinit = {
	vniwput,	/* qi_putp */
	NULL,		/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&minfo,		/* qi_minfo */
	NULL		/* qi_mstat */
};

static struct streamtab vni_info = {
	&vnirinit,	/* st_rdinit */
	&vniwinit,	/* st_wrinit */
	NULL,		/* st_muxrinit */
	NULL		/* st_muxwrinit */
};

DDI_DEFINE_STREAM_OPS(vni_ops, nulldev, nulldev, vniattach, \
    vnidetach, nodev, nodev, VNIFLAGS, &vni_info, ddi_quiesce_not_supported);

static struct modldrv modldrv = {
	&mod_driverops,
	"Virtual network interface",
	&vni_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

static vni_str_t *vni_strlist_head;

/*
 * DL_INFO_ACK template for VNI pseudo interface.
 */
static  dl_info_ack_t dlvni_infoack = {
	DL_INFO_ACK,	/* dl_primitive */
	0,		/* dl_max_sdu */
	0,		/* dl_min_sdu */
	0,		/* dl_addr_length */
	SUNW_DL_VNI,	/* dl_mac_type */
	0,		/* dl_reserved */
	0,		/* dl_current_state */
	0,		/* dl_sap_length */
	DL_CLDLS,	/* dl_service_mode */
	0,		/* dl_qos_length */
	0,		/* dl_qos_offset */
	0,		/* dl_range_length */
	0,		/* dl_range_offset */
	DL_STYLE2,	/* dl_provider_style */
	0,		/* dl_addr_offset */
	DL_VERSION_2,	/* dl_version */
	0,		/* dl_brdcst_addr_length */
	0,		/* dl_brdcst_addr_offset */
	0		/* dl_growth */
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
vniattach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		cmn_err(CE_NOTE, "vniattach failure: cmd != DDI_ATTACH\n");
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, VNINAME, S_IFCHR,
	    ddi_get_instance(devi), DDI_PSEUDO, CLONE_DEV) ==
	    DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		cmn_err(CE_NOTE, "vniattach failure: ddi_create_minor_node\n");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
vnidetach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ddi_remove_minor_node(devi, NULL);
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
vniopen(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	vni_str_t	*stp, *prevstp;
	minor_t		minordev = 0;

	if (sflag != CLONEOPEN)
		return (EINVAL);

	prevstp = NULL;

	for (stp = vni_strlist_head; stp != NULL; stp = stp->st_next) {
		if (minordev < stp->st_minor)
			break;
		minordev++;
		prevstp = stp;
	}

	stp = kmem_zalloc(sizeof (vni_str_t), KM_SLEEP);

	*devp = makedevice(getmajor(*devp), minordev);

	stp->st_minor = minordev;
	stp->st_state = DL_UNATTACHED;
	stp->st_next = NULL;

	q->q_ptr = stp;
	WR(q)->q_ptr = stp;

	if (prevstp != NULL) {
		stp->st_next = prevstp->st_next;
		prevstp->st_next = stp;
	} else {
		stp->st_next = vni_strlist_head;
		vni_strlist_head = stp;
	}

	qprocson(q);
	return (0);
}

/* ARGSUSED */
static int
vniclose(queue_t *q, int flag, cred_t *credp)
{
	vni_str_t *stp, **prevstpp;

	qprocsoff(q);
	stp = (vni_str_t *)q->q_ptr;
	stp->st_state = DL_UNATTACHED;

	/* Unlink the per-stream entry from the list and free it */
	stp = vni_strlist_head;
	prevstpp = &vni_strlist_head;

	for (; stp != NULL; stp = stp->st_next) {
		if (stp == (vni_str_t *)q->q_ptr)
			break;
		prevstpp = &stp->st_next;
	}

	ASSERT(stp != NULL);

	*prevstpp = stp->st_next;

	kmem_free(stp, sizeof (vni_str_t));

	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

static int
vniwput(queue_t *q, mblk_t *mp)
{
	union DL_primitives	*dlp;
	vni_str_t		*stp;
	dl_info_ack_t		*dlip;
	t_scalar_t		prim;

	stp = q->q_ptr;

	switch ((mp)->b_datap->db_type) {
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
			if (MBLKL(mp) < DL_ATTACH_REQ_SIZE) {
				dlerrorack(q, mp, DL_ATTACH_REQ, DL_BADPRIM, 0);
				return (0);
			}
			if (stp->st_state != DL_UNATTACHED) {
				dlerrorack(q, mp, DL_ATTACH_REQ, DL_OUTSTATE,
				    0);
				return (0);
			}
			stp->st_ppa = dlp->attach_req.dl_ppa;
			stp->st_state = DL_UNBOUND;
			dlokack(q, mp, DL_ATTACH_REQ);
			break;
		case DL_BIND_REQ:
			if (MBLKL(mp) < DL_BIND_REQ_SIZE) {
				dlerrorack(q, mp, DL_BIND_REQ, DL_BADPRIM, 0);
				return (0);
			}
			if (stp->st_state != DL_UNBOUND) {
				dlerrorack(q, mp, DL_BIND_REQ, DL_OUTSTATE, 0);
				return (0);
			}
			stp->st_state = DL_IDLE;
			dlbindack(q, mp, dlp->bind_req.dl_sap, NULL, 0, 0, 0);
			break;
		case DL_INFO_REQ:
			if (MBLKL(mp) < DL_INFO_REQ_SIZE) {
				dlerrorack(q, mp, DL_INFO_REQ, DL_BADPRIM, 0);
				return (0);
			}
			if ((mp = mexchange(q, mp, sizeof (dl_info_ack_t),
			    M_PCPROTO, DL_INFO_ACK)) == NULL) {
				return (0);
			}
			dlip = (void *)mp->b_rptr;
			*dlip = dlvni_infoack;
			dlip->dl_current_state = stp->st_state;
			qreply(q, mp);
			break;
		case DL_PHYS_ADDR_REQ:
			if (MBLKL(mp) < DL_PHYS_ADDR_REQ_SIZE) {
				dlerrorack(q, mp, DL_PHYS_ADDR_REQ, DL_BADPRIM,
				    0);
				return (0);
			}
			dlphysaddrack(q, mp, NULL, 0);
			break;
		case DL_UNBIND_REQ:
			if (MBLKL(mp) < DL_UNBIND_REQ_SIZE) {
				dlerrorack(q, mp, DL_UNBIND_REQ, DL_BADPRIM, 0);
				return (0);
			}
			if (stp->st_state != DL_IDLE) {
				dlerrorack(q, mp, DL_UNBIND_REQ, DL_OUTSTATE,
				    0);
				return (0);
			}
			/* Nothing to flush. But DLPI spec says to; so do it */
			flushq(q, FLUSHALL);
			flushq(RD(q), FLUSHALL);
			stp->st_state = DL_UNBOUND;
			dlokack(q, mp, DL_UNBIND_REQ);
			break;
		case DL_DETACH_REQ:
			if (MBLKL(mp) < DL_DETACH_REQ_SIZE) {
				dlerrorack(q, mp, DL_DETACH_REQ, DL_BADPRIM, 0);
				return (0);
			}
			if (stp->st_state != DL_UNBOUND) {
				dlerrorack(q, mp, DL_DETACH_REQ, DL_OUTSTATE,
				    0);
				return (0);
			}
			stp->st_state = DL_UNATTACHED;
			dlokack(q, mp, DL_DETACH_REQ);
			break;
		default:
			dlerrorack(q, mp, prim, DL_UNSUPPORTED, 0);
		}
		break;
	case M_IOCTL:
		/*
		 * No ioctl's currently supported. Need to have the NAK since
		 * ifconfig calls SIOCGTUNPARAM during the end of plumb
		 */
		miocnak(q, mp, 0, EINVAL);
		break;
	case M_FLUSH:
		/* Really nothing to flush since no msgs enqueued */
		if (*mp->b_rptr & FLUSHR) {
			qreply(q, mp);
		} else {
			freemsg(mp);
		}
		break;
	default:
		freemsg(mp);
		break;
	}
	return (0);
}
