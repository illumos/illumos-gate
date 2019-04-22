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
 * av1394 isochronous module
 */
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/av/iec61883.h>
#include <sys/1394/targets/av1394/av1394_impl.h>

/* configuration routines */
static int	av1394_isoch_create_minor_node(av1394_inst_t *);
static void	av1394_isoch_remove_minor_node(av1394_inst_t *);
static void	av1394_isoch_cleanup(av1394_inst_t *, int);
av1394_isoch_seg_t *av1394_isoch_find_seg(av1394_inst_t *, offset_t, size_t);
static int	av1394_isoch_autorecv_init(av1394_inst_t *, av1394_ic_t **);
static int	av1394_isoch_autoxmit_init(av1394_inst_t *, av1394_ic_t **,
		struct uio *);

/* ioctls */
static int	av1394_ioctl_isoch_init(av1394_inst_t *, void *, int);
static av1394_ic_t *av1394_ioctl_isoch_handle2ic(av1394_inst_t *, void *);
static int	av1394_ioctl_isoch_fini(av1394_inst_t *, void *, int);
static int	av1394_ioctl_start(av1394_inst_t *, void *, int);
static int	av1394_ioctl_stop(av1394_inst_t *, void *, int);
static int	av1394_ioctl_recv(av1394_inst_t *, void *, int);
static int	av1394_ioctl_xmit(av1394_inst_t *, void *, int);

static uint_t av1394_isoch_softintr(caddr_t);

static struct devmap_callback_ctl av1394_isoch_devmap_ops = {
	DEVMAP_OPS_REV,		/* rev */
	NULL,			/* map */
	NULL,			/* access */
	NULL,			/* dup */
	NULL,			/* unmap */
};

/* tunables */
int av1394_rate_n_dv_ntsc = 246;
int av1394_rate_d_dv_ntsc = 3840;
int av1394_rate_n_dv_pal = 1;
int av1394_rate_d_dv_pal = 16;

int av1394_isoch_autorecv_nframes = 50;
int av1394_isoch_autorecv_framesz = 250;
int av1394_isoch_autoxmit_nframes = 50;
int av1394_isoch_autoxmit_framesz = 250;

#define	AV1394_TNF_ENTER(func)	\
	TNF_PROBE_0_DEBUG(func##_enter, AV1394_TNF_ISOCH_STACK, "");

#define	AV1394_TNF_EXIT(func)	\
	TNF_PROBE_0_DEBUG(func##_exit, AV1394_TNF_ISOCH_STACK, "");

int
av1394_isoch_attach(av1394_inst_t *avp)
{
	av1394_isoch_t	*ip = &avp->av_i;
	ddi_iblock_cookie_t ibc = avp->av_attachinfo.iblock_cookie;

	AV1394_TNF_ENTER(av1394_isoch_attach);

	mutex_init(&ip->i_mutex, NULL, MUTEX_DRIVER, ibc);

	mutex_enter(&ip->i_mutex);
	if (av1394_isoch_create_minor_node(avp) != DDI_SUCCESS) {
		mutex_exit(&ip->i_mutex);
		av1394_isoch_cleanup(avp, 1);
		AV1394_TNF_EXIT(av1394_isoch_attach);
		return (DDI_FAILURE);
	}

	if (ddi_add_softintr(avp->av_dip, DDI_SOFTINT_LOW, &ip->i_softintr_id,
	    0, 0, av1394_isoch_softintr, (caddr_t)avp) != DDI_SUCCESS) {
		mutex_exit(&ip->i_mutex);
		av1394_isoch_cleanup(avp, 2);
		AV1394_TNF_EXIT(av1394_isoch_attach);
		return (DDI_FAILURE);
	}

	if (av1394_cmp_init(avp) != DDI_SUCCESS) {
		mutex_exit(&ip->i_mutex);
		av1394_isoch_cleanup(avp, 3);
		AV1394_TNF_EXIT(av1394_isoch_attach);
		return (DDI_FAILURE);
	}

	av1394_as_init(&ip->i_mmap_as);
	mutex_exit(&ip->i_mutex);

	AV1394_TNF_EXIT(av1394_isoch_attach);
	return (DDI_SUCCESS);
}

void
av1394_isoch_detach(av1394_inst_t *avp)
{
	AV1394_TNF_ENTER(av1394_isoch_detach);

	av1394_isoch_cleanup(avp, AV1394_CLEANUP_LEVEL_MAX);

	AV1394_TNF_EXIT(av1394_isoch_detach);
}

int
av1394_isoch_cpr_suspend(av1394_inst_t *avp)
{
	av1394_isoch_t	*ip = &avp->av_i;
	av1394_ic_t	*icp;
	int		i;
	int		ret = DDI_SUCCESS;

	AV1394_TNF_ENTER(av1394_isoch_cpr_suspend);

	/*
	 * suspend only if there are no active channels
	 */
	mutex_enter(&ip->i_mutex);
	for (i = 0; (i < NELEM(ip->i_ic)) && (ret == DDI_SUCCESS); i++) {
		icp = ip->i_ic[i];
		if (icp) {
			mutex_enter(&icp->ic_mutex);
			if (icp->ic_state != AV1394_IC_IDLE) {
				ret = DDI_FAILURE;
			}
			mutex_exit(&icp->ic_mutex);
		}
	}
	mutex_exit(&ip->i_mutex);

	AV1394_TNF_EXIT(av1394_isoch_cpr_suspend);
	return (ret);
}

/*ARGSUSED*/
int
av1394_isoch_close(av1394_inst_t *avp, int flag)
{
	int	ret;

	AV1394_TNF_ENTER(av1394_isoch_close);

	ret = av1394_ic_close(avp, flag);
	av1394_cmp_close(avp);

	AV1394_TNF_EXIT(av1394_isoch_close);
	return (ret);
}

int
av1394_isoch_read(av1394_inst_t *avp, struct uio *uiop)
{
	av1394_ic_t	*icp;
	int		ret;

	AV1394_TNF_ENTER(av1394_isoch_read);

	/* use broadcast channel */
	icp = avp->av_i.i_ic[63];
	if (icp == NULL) {
		if ((ret = av1394_isoch_autorecv_init(avp, &icp)) != 0) {
			AV1394_TNF_EXIT(av1394_isoch_read);
			return (ret);
		}
	} else if (icp->ic_dir != AV1394_IR) {
		/* channel already used for xmit */
		return (EBUSY);
	}

	if ((ret = av1394_ir_start(icp)) == 0) {
		ret = av1394_ir_read(icp, uiop);
	}

	AV1394_TNF_EXIT(av1394_isoch_read);
	return (ret);
}

int
av1394_isoch_write(av1394_inst_t *avp, struct uio *uiop)
{
	av1394_ic_t	*icp;
	int		ret;

	AV1394_TNF_ENTER(av1394_isoch_write);

	/* use broadcast channel */
	icp = avp->av_i.i_ic[63];
	if (icp == NULL) {
		if ((ret = av1394_isoch_autoxmit_init(avp, &icp, uiop)) != 0) {
			AV1394_TNF_EXIT(av1394_isoch_write);
			return (ret);
		}
	} else if (icp->ic_dir != AV1394_IT) {
		/* channel already used for recv */
		AV1394_TNF_EXIT(av1394_isoch_write);
		return (EBUSY);
	}

	ret = av1394_it_write(icp, uiop);

	AV1394_TNF_EXIT(av1394_isoch_write);
	return (ret);
}

/*ARGSUSED*/
int
av1394_isoch_ioctl(av1394_inst_t *avp, int cmd, intptr_t arg, int mode,
    int *rvalp)
{
	int		ret = EINVAL;

	switch (cmd) {
	case IEC61883_ISOCH_INIT:
		ret = av1394_ioctl_isoch_init(avp, (void *)arg, mode);
		break;
	case IEC61883_ISOCH_FINI:
		ret = av1394_ioctl_isoch_fini(avp, (void *)arg, mode);
		break;
	case IEC61883_START:
		ret = av1394_ioctl_start(avp, (void *)arg, mode);
		break;
	case IEC61883_STOP:
		ret = av1394_ioctl_stop(avp, (void *)arg, mode);
		break;
	case IEC61883_RECV:
		ret = av1394_ioctl_recv(avp, (void *)arg, mode);
		break;
	case IEC61883_XMIT:
		ret = av1394_ioctl_xmit(avp, (void *)arg, mode);
		break;
	case IEC61883_PLUG_INIT:
		ret = av1394_ioctl_plug_init(avp, (void *)arg, mode);
		break;
	case IEC61883_PLUG_FINI:
		ret = av1394_ioctl_plug_fini(avp, (void *)arg, mode);
		break;
	case IEC61883_PLUG_REG_READ:
		ret = av1394_ioctl_plug_reg_read(avp, (void *)arg, mode);
		break;
	case IEC61883_PLUG_REG_CAS:
		ret = av1394_ioctl_plug_reg_cas(avp, (void *)arg, mode);
		break;
	}

	return (ret);
}

/*ARGSUSED*/
int
av1394_isoch_devmap(av1394_inst_t *avp, devmap_cookie_t dhp, offset_t off,
    size_t len, size_t *maplen, uint_t model)
{
	av1394_isoch_seg_t *isp;

	AV1394_TNF_ENTER(av1394_isoch_devmap);

	*maplen = 0;

	/* find segment */
	isp = av1394_isoch_find_seg(avp, off, ptob(btopr(len)));
	if (isp == NULL) {
		AV1394_TNF_EXIT(av1394_isoch_devmap);
		return (EINVAL);
	}

	/* map segment */
	if (devmap_umem_setup(dhp, avp->av_dip, &av1394_isoch_devmap_ops,
	    isp->is_umem_cookie, 0, isp->is_umem_size, PROT_ALL, 0,
	    &avp->av_attachinfo.acc_attr) != 0) {
		TNF_PROBE_0(av1394_isoch_devmap_error_umem_setup,
		    AV1394_TNF_ISOCH_ERROR, "");
		AV1394_TNF_EXIT(av1394_isoch_devmap);
		return (EINVAL);
	}
	*maplen = isp->is_umem_size;

	AV1394_TNF_EXIT(av1394_isoch_devmap);
	return (0);
}

/*
 *
 * --- configuration routines
 *
 * av1394_isoch_create_minor_node()
 *    Create isoch minor node
 */
static int
av1394_isoch_create_minor_node(av1394_inst_t *avp)
{
	int	ret;

	ret = ddi_create_minor_node(avp->av_dip, "isoch",
	    S_IFCHR, AV1394_ISOCH_INST2MINOR(avp->av_instance),
	    DDI_NT_AV_ISOCH, 0);
	if (ret != DDI_SUCCESS) {
		TNF_PROBE_0(av1394_isoch_create_minor_node_error,
		    AV1394_TNF_ISOCH_ERROR, "");
	}
	return (ret);
}

/*
 * av1394_isoch_remove_minor_node()
 *    Remove isoch minor node
 */
static void
av1394_isoch_remove_minor_node(av1394_inst_t *avp)
{
	ddi_remove_minor_node(avp->av_dip, "isoch");
}

/*
 * av1394_isoch_cleanup()
 *    Cleanup after attach
 */
static void
av1394_isoch_cleanup(av1394_inst_t *avp, int level)
{
	av1394_isoch_t	*ip = &avp->av_i;

	ASSERT((level > 0) && (level <= AV1394_CLEANUP_LEVEL_MAX));

	switch (level) {
	default:
		mutex_enter(&ip->i_mutex);
		av1394_as_fini(&ip->i_mmap_as);
		av1394_cmp_fini(avp);
		mutex_exit(&ip->i_mutex);
		/* FALLTHRU */
	case 3:
		ddi_remove_softintr(ip->i_softintr_id);
		/* FALLTHRU */
	case 2:
		av1394_isoch_remove_minor_node(avp);
		/* FALLTHRU */
	case 1:
		mutex_destroy(&ip->i_mutex);
	}
}

/*
 * av1394_isoch_find_seg()
 *    Given an offset and size, find a matching av1394_isoch_seg_t structure.
 */
av1394_isoch_seg_t *
av1394_isoch_find_seg(av1394_inst_t *avp, offset_t off, size_t len)
{
	av1394_isoch_t	*ip = &avp->av_i;
	av1394_ic_t	*icp;
	av1394_isoch_pool_t *pool;
	av1394_isoch_seg_t *isp;
	offset_t	segoff;
	int		i;

	/* find channel from within this range */
	for (i = 0; i < NELEM(ip->i_ic); i++) {
		icp = ip->i_ic[i];
		if (icp == NULL) {
			continue;
		}
		if ((off >= icp->ic_mmap_off) &&
		    (off + len <= icp->ic_mmap_off + icp->ic_mmap_sz)) {
			off -= icp->ic_mmap_off;	/* convert to base */
			break;
		}
		icp = NULL;
	}
	if (icp == NULL) {
		TNF_PROBE_0(av1394_isoch_find_seg_error_nochan,
		    AV1394_TNF_ISOCH_ERROR, "");
		return (NULL);
	}

	/* find a segment */
	pool = (icp->ic_dir == AV1394_IR) ?
	    &icp->ic_ir.ir_data_pool : &icp->ic_it.it_data_pool;
	for (segoff = 0, i = 0; i < pool->ip_nsegs; i++) {
		isp = &pool->ip_seg[i];
		if (off == segoff) {
			break;
		}
		segoff += isp->is_umem_size;
		isp = NULL;
	}
	if (isp == NULL) {
		TNF_PROBE_0(av1394_isoch_find_seg_error_noseg,
		    AV1394_TNF_ISOCH_ERROR, "");
		return (NULL);
	}

	/* only whole segments can be mapped */
	if (len != isp->is_umem_size) {
		TNF_PROBE_0(av1394_isoch_devmap_error_whole,
		    AV1394_TNF_ISOCH_ERROR, "");
		return (NULL);
	}
	return (isp);
}

/*
 * initialize default channel for data receipt
 */
static int
av1394_isoch_autorecv_init(av1394_inst_t *avp, av1394_ic_t **icpp)
{
	iec61883_isoch_init_t ii;
	int		ret = 0;

	AV1394_TNF_ENTER(av1394_isoch_autorecv_init);

	bzero(&ii, sizeof (ii));
	ii.ii_version = IEC61883_V1_0;
	ii.ii_pkt_size = 512;
	ii.ii_frame_size = av1394_isoch_autorecv_framesz;
	ii.ii_frame_cnt = av1394_isoch_autorecv_nframes;
	ii.ii_direction = IEC61883_DIR_RECV;
	ii.ii_bus_speed = IEC61883_S100;
	ii.ii_channel = (1ULL << 63);

	ret = av1394_ic_init(avp, &ii, icpp);

	AV1394_TNF_EXIT(av1394_isoch_autorecv_init);
	return (ret);
}

/*
 * initialize default channel for data xmit
 */
static int
av1394_isoch_autoxmit_init(av1394_inst_t *avp, av1394_ic_t **icpp,
    struct uio *uiop)
{
	av1394_isoch_autoxmit_t *axp = &avp->av_i.i_autoxmit;
	iec61883_isoch_init_t ii;
	uint_t		fmt, dbs, fn, f5060, stype;	/* CIP fields */
	int		ret = 0;

	AV1394_TNF_ENTER(av1394_isoch_autoxmit_init);

	/* copyin the first CIP header */
	axp->ax_copy_ciph = B_FALSE;
	if (uiop->uio_resid < AV1394_CIPSZ) {
		TNF_PROBE_0_DEBUG(av1394_isoch_autoxmit_init_error_cipsz,
		    AV1394_TNF_ISOCH_ERROR, "");
		return (EINVAL);
	}
	ret = uiomove(axp->ax_ciph, AV1394_CIPSZ, UIO_WRITE, uiop);
	if (ret != 0) {
		return (ret);
	}
	axp->ax_copy_ciph = B_TRUE;

	/* parse CIP header */
	dbs = axp->ax_ciph[1];
	fn = (axp->ax_ciph[2] >> 6) & 0x3;
	fmt = axp->ax_ciph[4] & 0x3F;
	stype = (axp->ax_ciph[5] >> 2) & 0x1F;

	/* fill out the init structure */
	bzero(&ii, sizeof (ii));
	ii.ii_version = IEC61883_V1_0;
	ii.ii_frame_cnt = av1394_isoch_autoxmit_nframes;
	ii.ii_direction = IEC61883_DIR_XMIT;
	ii.ii_bus_speed = IEC61883_S100;
	ii.ii_channel = (1ULL << 63);
	ii.ii_dbs = dbs;
	ii.ii_fn = fn;

	if ((fmt == 0) && (dbs == 0x78) && (fn == 0) && (stype == 0)) {
		/* either DV-NTSC or DV-PAL */
		ii.ii_pkt_size = 488;
		ii.ii_ts_mode = IEC61883_TS_SYT;
		f5060 = axp->ax_ciph[5] & 0x80;
		if (f5060 == 0) {
			axp->ax_fmt = AV1394_ISOCH_AUTOXMIT_DV_NTSC;
			ii.ii_frame_size = AV1394_DV_NTSC_FRAMESZ;
			ii.ii_rate_n = av1394_rate_n_dv_ntsc;
			ii.ii_rate_d = av1394_rate_d_dv_ntsc;
		} else {
			axp->ax_fmt = AV1394_ISOCH_AUTOXMIT_DV_PAL;
			ii.ii_frame_size = AV1394_DV_PAL_FRAMESZ;
			ii.ii_rate_n = av1394_rate_n_dv_pal;
			ii.ii_rate_d = av1394_rate_d_dv_pal;
		}
	} else {
		/* raw stream */
		axp->ax_fmt = AV1394_ISOCH_AUTOXMIT_UNKNOWN;
		ii.ii_pkt_size = 512;
		ii.ii_frame_size = av1394_isoch_autoxmit_framesz;
		ii.ii_ts_mode = IEC61883_TS_NONE;
	}

	ret = av1394_ic_init(avp, &ii, icpp);

	AV1394_TNF_EXIT(av1394_isoch_autoxmit_init);
	return (ret);
}


/*
 *
 * --- ioctls
 *	these routines are generally responsible for copyin/out of arguments
 *	and passing control to the actual implementation.
 *
 */
static int
av1394_ioctl_isoch_init(av1394_inst_t *avp, void *arg, int mode)
{
	iec61883_isoch_init_t	ii;
#ifdef _MULTI_DATAMODEL
	iec61883_isoch_init32_t	ii32;
#endif
	av1394_ic_t		*icp;
	int			ret;

	AV1394_TNF_ENTER(av1394_ioctl_isoch_init);

	if (ddi_copyin(arg, &ii, sizeof (ii), mode) != 0) {
		AV1394_TNF_EXIT(av1394_ioctl_isoch_init);
		return (EFAULT);
	}

	ret = av1394_ic_init(avp, &ii, &icp);

	if (ret != 0) {
		AV1394_TNF_EXIT(av1394_ioctl_isoch_init);
#ifdef _MULTI_DATAMODEL
		if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
			bcopy(&ii, &ii32, sizeof (ii32));
			ii32.ii_error = ii.ii_error;
			(void) ddi_copyout(&ii32, arg, sizeof (ii32), mode);
		} else
#endif
		(void) ddi_copyout(&ii, arg, sizeof (ii), mode);
		return (ret);
	}

#ifdef _MULTI_DATAMODEL
	/* fixup 32-bit deviations */
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		bcopy(&ii, &ii32, sizeof (ii32));
		ii32.ii_mmap_off = ii.ii_mmap_off;
		ii32.ii_rchannel = ii.ii_rchannel;
		ii32.ii_error = ii.ii_error;
		ret = ddi_copyout(&ii32, arg, sizeof (ii32), mode);
	} else
#endif
	ret = ddi_copyout(&ii, arg, sizeof (ii), mode);
	if (ret != 0) {
		AV1394_TNF_EXIT(av1394_ioctl_isoch_init);
		return (ENOMEM);
	}

	AV1394_TNF_EXIT(av1394_ioctl_isoch_init);
	return (ret);
}

static av1394_ic_t *
av1394_ioctl_isoch_handle2ic(av1394_inst_t *avp, void *arg)
{
	int		num = (int)(intptr_t)arg;
	av1394_isoch_t	*ip = &avp->av_i;

	if (num >= (sizeof (ip->i_ic) / sizeof (av1394_ic_t))) {
		TNF_PROBE_0(av1394_ioctl_isoch_handle2ic_error_range,
		    AV1394_TNF_ISOCH_ERROR, "");
		return (NULL);
	}
	if (ip->i_ic[num] == NULL) {
		TNF_PROBE_0(av1394_ioctl_isoch_handle2ic_error_null,
		    AV1394_TNF_ISOCH_ERROR, "");
	}
	return (ip->i_ic[num]);
}

/*ARGSUSED*/
static int
av1394_ioctl_isoch_fini(av1394_inst_t *avp, void *arg, int mode)
{
	av1394_ic_t	*icp;

	AV1394_TNF_ENTER(av1394_ioctl_isoch_fini);

	if ((icp = av1394_ioctl_isoch_handle2ic(avp, arg)) != NULL) {
		av1394_ic_fini(icp);
	}

	AV1394_TNF_EXIT(av1394_ioctl_isoch_fini);
	return (0);
}

/*ARGSUSED*/
static int
av1394_ioctl_start(av1394_inst_t *avp, void *arg, int mode)
{
	av1394_ic_t	*icp;
	int		ret = EINVAL;

	AV1394_TNF_ENTER(av1394_ioctl_start);

	if ((icp = av1394_ioctl_isoch_handle2ic(avp, arg)) != NULL) {
		ret = av1394_ic_start(icp);
	}

	AV1394_TNF_EXIT(av1394_ioctl_start);
	return (ret);
}

/*ARGSUSED*/
static int
av1394_ioctl_stop(av1394_inst_t *avp, void *arg, int mode)
{
	av1394_ic_t	*icp;
	int		ret = EINVAL;

	AV1394_TNF_ENTER(av1394_ioctl_stop);

	if ((icp = av1394_ioctl_isoch_handle2ic(avp, arg)) != NULL) {
		ret = av1394_ic_stop(icp);
	}

	AV1394_TNF_EXIT(av1394_ioctl_stop);
	return (ret);
}

static int
av1394_ioctl_recv(av1394_inst_t *avp, void *arg, int mode)
{
	av1394_isoch_t	*ip = &avp->av_i;
	av1394_ic_t	*icp;
	iec61883_recv_t	recv;
	int		num;
	int		ret = EINVAL;

	/* copyin the structure and get channel pointer */
	if (ddi_copyin(arg, &recv, sizeof (recv), mode) != 0) {
		return (EFAULT);
	}
	num = recv.rx_handle;
	if (num >= (sizeof (ip->i_ic) / sizeof (av1394_ic_t))) {
		TNF_PROBE_0(av1394_ioctl_recv_error_range,
		    AV1394_TNF_ISOCH_ERROR, "");
		return (EINVAL);
	}
	icp = ip->i_ic[num];
	if (icp == NULL) {
		TNF_PROBE_0(av1394_ioctl_recv_error_null,
		    AV1394_TNF_ISOCH_ERROR, "");
	}

	/* now call the actual handler */
	if (icp->ic_dir != AV1394_IR) {
		ret = EINVAL;
	} else {
		ret = av1394_ir_recv(icp, &recv);
	}

	/* copyout the result */
	if (ret == 0) {
		if (ddi_copyout(&recv, arg, sizeof (recv), mode) != 0) {
			return (EFAULT);
		}
	}

	return (ret);
}

static int
av1394_ioctl_xmit(av1394_inst_t *avp, void *arg, int mode)
{
	av1394_isoch_t	*ip = &avp->av_i;
	av1394_ic_t	*icp;
	iec61883_xmit_t	xmit;
	int		num;
	int		ret = EINVAL;

	/* copyin the structure and get channel pointer */
	if (ddi_copyin(arg, &xmit, sizeof (xmit), mode) != 0) {
		return (EFAULT);
	}
	num = xmit.tx_handle;
	if (num >= (sizeof (ip->i_ic) / sizeof (av1394_ic_t))) {
		TNF_PROBE_0(av1394_ioctl_xmit_error_range,
		    AV1394_TNF_ISOCH_ERROR, "");
		return (EINVAL);
	}
	icp = ip->i_ic[num];
	if (icp == NULL) {
		TNF_PROBE_0(av1394_ioctl_xmit_error_null,
		    AV1394_TNF_ISOCH_ERROR, "");
	}

	/* now call the actual handler */
	if (icp->ic_dir != AV1394_IT) {
		ret = EINVAL;
	} else {
		ret = av1394_it_xmit(icp, &xmit);
	}

	/* copyout the result */
	if (ret == 0) {
		if (ddi_copyout(&xmit, arg, sizeof (xmit), mode) != 0) {
			return (EFAULT);
		}
	}

	return (ret);
}

static uint_t
av1394_isoch_softintr(caddr_t arg)
{
	av1394_inst_t	*avp = (av1394_inst_t *)arg;
	av1394_isoch_t	*ip = &avp->av_i;
	int		i;
	uint64_t	ch;
	av1394_ic_t	*icp;

	mutex_enter(&ip->i_mutex);
	do {
		for (i = 63, ch = (1ULL << 63);
		    (i > 0) && (ip->i_softintr_ch != 0);
		    i--, ch >>= 1) {
			if ((ip->i_softintr_ch & ch) == 0) {
				continue;
			}
			ip->i_softintr_ch &= ~ch;
			icp = ip->i_ic[i];
			if (icp == NULL) {
				continue;
			}

			mutex_exit(&ip->i_mutex);
			mutex_enter(&icp->ic_mutex);
			if (icp->ic_preq & AV1394_PREQ_IR_OVERFLOW) {
				icp->ic_preq &= ~AV1394_PREQ_IR_OVERFLOW;
				av1394_ir_overflow(icp);
			}
			if (icp->ic_preq & AV1394_PREQ_IT_UNDERRUN) {
				icp->ic_preq &= ~AV1394_PREQ_IT_UNDERRUN;
				av1394_it_underrun(icp);
			}
			mutex_exit(&icp->ic_mutex);
			mutex_enter(&ip->i_mutex);
		}
	} while (ip->i_softintr_ch != 0);
	mutex_exit(&ip->i_mutex);

	return (DDI_INTR_CLAIMED);
}
