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
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * routines common to isoch receive and isoch transmit
 */
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/bitmap.h>
#include <sys/av/iec61883.h>
#include <sys/1394/targets/av1394/av1394_impl.h>

/* configuration routines */
static void	av1394_ic_cleanup(av1394_ic_t *icp, int level);
static int	av1394_ic_validate_init_params(iec61883_isoch_init_t *ii);
static void	av1394_ic_set_params(av1394_inst_t *avp,
		iec61883_isoch_init_t *ii, av1394_ic_t *icp, int num);
static int	av1394_ic_alloc_channel(av1394_ic_t *icp, uint64_t mask, int *);
static void	av1394_ic_free_channel(av1394_ic_t *icp);

/* callbacks */
static void	av1394_ic_rsrc_fail(t1394_isoch_single_handle_t t1394_sii_hdl,
		opaque_t arg, t1394_isoch_rsrc_error_t fail_args);

uint64_t	av1394_ic_bitreverse(uint64_t);
boolean_t	av1394_ic_onebit(uint64_t);

#define	AV1394_TNF_ENTER(func)	\
	TNF_PROBE_0_DEBUG(func##_enter, AV1394_TNF_ISOCH_STACK, "");

#define	AV1394_TNF_EXIT(func)	\
	TNF_PROBE_0_DEBUG(func##_exit, AV1394_TNF_ISOCH_STACK, "");

/* tunables */
extern int av1394_rate_n_dv_ntsc;
extern int av1394_rate_d_dv_ntsc;
extern int av1394_rate_n_dv_pal;
extern int av1394_rate_d_dv_pal;

/*ARGSUSED*/
int
av1394_ic_close(av1394_inst_t *avp, int flags)
{
	av1394_isoch_t	*ip = &avp->av_i;
	av1394_ic_t	*icp;
	int		i;

	AV1394_TNF_ENTER(av1394_ic_close);

	/* cleanup channels in case application didn't */
	for (i = 0; i < NELEM(ip->i_ic); i++) {
		icp = ip->i_ic[i];
		if (icp != NULL) {
			(void) av1394_ic_stop(icp);
			av1394_ic_fini(icp);
		}
	}

	AV1394_TNF_EXIT(av1394_ic_close);
	return (0);
}

/*
 * av1394_ic_init()
 *    Channel allocation and initialization.
 */
int
av1394_ic_init(av1394_inst_t *avp, iec61883_isoch_init_t *ii,
		av1394_ic_t **icpp)
{
	av1394_isoch_t		*ip = &avp->av_i;
	av1394_ic_t		*icp = NULL;
	int			num;
	av1394_isoch_pool_t	*pool;
	uint64_t		mask;	/* channel mask */
	int			ret;
	ddi_iblock_cookie_t	ibc = avp->av_attachinfo.iblock_cookie;

	AV1394_TNF_ENTER(av1394_ic_init);

	ii->ii_frame_rcnt = 0;
	ii->ii_rchannel = 0;
	ii->ii_error = 0;

	if ((ret = av1394_ic_validate_init_params(ii)) != 0) {
		AV1394_TNF_EXIT(av1394_ic_init);
		return (ret);
	}

	/* allocate channel structure */
	icp = kmem_zalloc(sizeof (av1394_ic_t), KM_SLEEP);

	mutex_init(&icp->ic_mutex, NULL, MUTEX_DRIVER, ibc);
	cv_init(&icp->ic_xfer_cv, NULL, CV_DRIVER, NULL);

	av1394_ic_set_params(avp, ii, icp, -1);

	/* allocate isoch channel and bandwidth, except for broadcast */
	if (ii->ii_channel == (1ULL << 63)) {
		num = 63;
	} else if (ii->ii_flags & IEC61883_PRIV_ISOCH_NOALLOC) {
		num = lowbit(ii->ii_channel) - 1;
	} else {
		mask = av1394_ic_bitreverse(ii->ii_channel);
		ret = av1394_ic_alloc_channel(icp, mask, &num);
		if (ret != DDI_SUCCESS) {
			ii->ii_error = IEC61883_ERR_NOCHANNEL;
			av1394_ic_cleanup(icp, 1);
			AV1394_TNF_EXIT(av1394_ic_init);
			return (EINVAL);
		}
	}
	ASSERT((num >= 0) && (num < 64));

	mutex_enter(&icp->ic_mutex);
	icp->ic_num = num;
	mutex_exit(&icp->ic_mutex);

	mutex_enter(&ip->i_mutex);
	if (ip->i_ic[num] != NULL) {
		mutex_exit(&ip->i_mutex);
		ii->ii_error = IEC61883_ERR_NOCHANNEL;
		av1394_ic_cleanup(icp, 2);
		TNF_PROBE_0(av1394_ic_init_error_chan_used,
		    AV1394_TNF_ISOCH_ERROR, "");
		AV1394_TNF_EXIT(av1394_ic_init);
		return (EINVAL);
	}
	ip->i_ic[num] = icp;
	mutex_exit(&ip->i_mutex);

	/* do direction specific initialization */
	if (icp->ic_dir == AV1394_IR) {
		ret = av1394_ir_init(icp, &ii->ii_error);
		pool = &icp->ic_ir.ir_data_pool;
	} else {
		ret = av1394_it_init(icp, &ii->ii_error);
		pool = &icp->ic_it.it_data_pool;
	}

	if (ret != 0) {
		av1394_ic_cleanup(icp, 3);
		AV1394_TNF_EXIT(av1394_ic_init);
		return (ret);
	}

	/* allocate mmap space */
	mutex_enter(&ip->i_mutex);
	mutex_enter(&icp->ic_mutex);
	icp->ic_mmap_sz = pool->ip_umem_size;
	icp->ic_mmap_off = av1394_as_alloc(&ip->i_mmap_as, icp->ic_mmap_sz);

	icp->ic_state = AV1394_IC_IDLE;

	*icpp = icp;
	ii->ii_handle = icp->ic_num;
	ii->ii_frame_rcnt = icp->ic_nframes;
	ii->ii_mmap_off = icp->ic_mmap_off;
	ii->ii_rchannel = icp->ic_num;
	mutex_exit(&icp->ic_mutex);
	mutex_exit(&ip->i_mutex);

	TNF_PROBE_2_DEBUG(av1394_ic_init, AV1394_TNF_ISOCH, "",
	    tnf_string, msg, "channel allocated", tnf_int, num, icp->ic_num);

	AV1394_TNF_EXIT(av1394_ic_init);
	return (0);
}

void
av1394_ic_fini(av1394_ic_t *icp)
{
	AV1394_TNF_ENTER(av1394_ic_fini);

	av1394_ic_cleanup(icp, AV1394_CLEANUP_LEVEL_MAX);

	AV1394_TNF_EXIT(av1394_ic_fini);
}

/*
 *
 * --- configuration routines
 *
 */
static void
av1394_ic_cleanup(av1394_ic_t *icp, int level)
{
	av1394_inst_t	*avp = icp->ic_avp;
	av1394_isoch_t	*ip = &avp->av_i;

	ASSERT((level > 0) && (level <= AV1394_CLEANUP_LEVEL_MAX));

	switch (level) {
	default:
		if (icp->ic_dir == AV1394_IR) {
			av1394_ir_fini(icp);
		} else {
			av1394_it_fini(icp);
		}
		/* FALLTHRU */
	case 3:
		mutex_enter(&ip->i_mutex);
		av1394_as_free(&ip->i_mmap_as, icp->ic_mmap_off);
		ip->i_ic[icp->ic_num] = NULL;
		mutex_exit(&ip->i_mutex);
		/* FALLTHRU */
	case 2:
		av1394_ic_free_channel(icp);
		/* FALLTHRU */
	case 1:
		cv_destroy(&icp->ic_xfer_cv);
		mutex_destroy(&icp->ic_mutex);
		kmem_free(icp, sizeof (av1394_ic_t));
	}
}

static int
av1394_ic_validate_init_params(iec61883_isoch_init_t *ii)
{
	int	framesz;

	ii->ii_error = 0;
	if ((IEC61883_IMPL_VER_MAJOR(ii->ii_version) !=
	    IEC61883_IMPL_VER_MAJOR(AV1394_IEC61883_VER)) ||
	    (IEC61883_IMPL_VER_MINOR(ii->ii_version) >
	    IEC61883_IMPL_VER_MINOR(AV1394_IEC61883_VER))) {
		TNF_PROBE_0(av1394_ic_validate_init_params_ver_error,
		    AV1394_TNF_ISOCH_ERROR, "");
		ii->ii_error = IEC61883_ERR_VERSION;
		return (EINVAL);
	}
	if ((ii->ii_pkt_size % 4) || (ii->ii_pkt_size > 512)) {
		TNF_PROBE_0(av1394_ic_validate_init_params_pktsz_error,
		    AV1394_TNF_ISOCH_ERROR, "");
		ii->ii_error = IEC61883_ERR_PKT_SIZE;
		return (EINVAL);
	}
	framesz = ii->ii_frame_size * ii->ii_pkt_size;
	if (framesz > AV1394_IC_FRAME_SIZE_MAX) {
		TNF_PROBE_0(av1394_ic_validate_init_params_frsz_error,
		    AV1394_TNF_ISOCH_ERROR, "");
		ii->ii_error = IEC61883_ERR_NOMEM;
		return (EINVAL);
	}
	if ((ii->ii_direction != IEC61883_DIR_RECV) &&
	    (ii->ii_direction != IEC61883_DIR_XMIT)) {
		TNF_PROBE_0(av1394_ic_validate_init_params_dir_error,
		    AV1394_TNF_ISOCH_ERROR, "");
		ii->ii_error = IEC61883_ERR_INVAL;
		return (EINVAL);
	}
	if (((ii->ii_direction == IEC61883_DIR_RECV) &&
	    (ii->ii_frame_cnt < AV1394_IR_NFRAMES_MIN)) ||
	    ((ii->ii_direction == IEC61883_DIR_XMIT) &&
	    (ii->ii_frame_cnt < AV1394_IT_NFRAMES_MIN))) {
		TNF_PROBE_0(av1394_ic_validate_init_params_frcnt_error,
		    AV1394_TNF_ISOCH_ERROR, "");
		ii->ii_error = IEC61883_ERR_INVAL;
		return (EINVAL);
	}
	if ((ii->ii_bus_speed != IEC61883_S100) &&
	    (ii->ii_bus_speed != IEC61883_S200) &&
	    (ii->ii_bus_speed != IEC61883_S400)) {
		TNF_PROBE_0(av1394_ic_validate_init_params_speed_error,
		    AV1394_TNF_ISOCH_ERROR, "");
		ii->ii_error = IEC61883_ERR_INVAL;
		return (EINVAL);
	}
	if (ii->ii_channel == 0) {
		TNF_PROBE_0(av1394_ic_validate_init_params_chan_error,
		    AV1394_TNF_ISOCH_ERROR, "");
		ii->ii_error = IEC61883_ERR_INVAL;
		return (EINVAL);
	}
	if ((ii->ii_flags & IEC61883_PRIV_ISOCH_NOALLOC) &&
	    !av1394_ic_onebit(ii->ii_channel)) {
		TNF_PROBE_0(av1394_ic_validate_init_params_chan_onebit_error,
		    AV1394_TNF_ISOCH_ERROR, "");
		ii->ii_error = IEC61883_ERR_INVAL;
		return (EINVAL);
	}
	/* the rest are xmit only */
	if (ii->ii_direction == IEC61883_DIR_RECV) {
		return (0);
	}
	if (((ii->ii_rate_d != 0) ||
	    (ii->ii_rate_n != IEC61883_RATE_N_DV_NTSC) &&
	    (ii->ii_rate_n != IEC61883_RATE_N_DV_PAL)) &&
	    ((ii->ii_rate_d <= 0) || (ii->ii_rate_n < 0) ||
	    ((ii->ii_rate_n != 0) && (ii->ii_rate_d / ii->ii_rate_n < 2)))) {
		TNF_PROBE_0(av1394_ic_validate_init_params_rate_error,
		    AV1394_TNF_ISOCH_ERROR, "");
		ii->ii_error = IEC61883_ERR_INVAL;
		return (EINVAL);
	}
	if (AV1394_TS_MODE_GET_OFF(ii->ii_ts_mode) +
	    AV1394_TS_MODE_GET_SIZE(ii->ii_ts_mode) > ii->ii_pkt_size) {
		TNF_PROBE_0(av1394_ic_validate_init_params_ts_error,
		    AV1394_TNF_ISOCH_ERROR, "");
		ii->ii_error = IEC61883_ERR_INVAL;
		return (EINVAL);
	}
	return (0);
}

static void
av1394_ic_set_params(av1394_inst_t *avp, iec61883_isoch_init_t *ii,
		av1394_ic_t *icp, int num)
{
	av1394_ic_param_t	*cp = &icp->ic_param;

	mutex_enter(&icp->ic_mutex);
	icp->ic_avp = avp;
	icp->ic_num = num;
	icp->ic_dir = (ii->ii_direction == IEC61883_DIR_RECV) ?
	    AV1394_IR : AV1394_IT;
	icp->ic_pktsz = ii->ii_pkt_size;
	icp->ic_npkts = ii->ii_frame_size;
	icp->ic_framesz = icp->ic_pktsz * icp->ic_npkts;
	icp->ic_nframes = ii->ii_frame_cnt;
	cp->cp_bus_speed = ii->ii_bus_speed;
	cp->cp_dbs = ii->ii_dbs;
	cp->cp_fn = ii->ii_fn;
	if (icp->ic_dir == AV1394_IT) {
		if (ii->ii_rate_d == 0) {
			switch (ii->ii_rate_n) {
			case IEC61883_RATE_N_DV_NTSC:
				cp->cp_n = av1394_rate_n_dv_ntsc;
				cp->cp_d = av1394_rate_d_dv_ntsc;
				break;
			case IEC61883_RATE_N_DV_PAL:
				cp->cp_n = av1394_rate_n_dv_pal;
				cp->cp_d = av1394_rate_d_dv_pal;
				break;
			default:
				ASSERT(0);	/* can't happen */
			}
		} else {
			cp->cp_n = ii->ii_rate_n;
			cp->cp_d = ii->ii_rate_d;
		}
	}
	cp->cp_ts_mode = ii->ii_ts_mode;
	mutex_exit(&icp->ic_mutex);
}

static int
av1394_ic_alloc_channel(av1394_ic_t *icp, uint64_t mask, int *num)
{
	av1394_inst_t	*avp = icp->ic_avp;
	int		ret, result;
	t1394_isoch_singleinfo_t sii;
	t1394_isoch_single_out_t so;

	/* allocate isoch channel */
	sii.si_channel_mask	= mask;
	sii.si_bandwidth	= icp->ic_pktsz;
	sii.rsrc_fail_target	= av1394_ic_rsrc_fail;
	sii.single_evt_arg	= icp;
	sii.si_speed		= icp->ic_param.cp_bus_speed;

	ret = t1394_alloc_isoch_single(avp->av_t1394_hdl, &sii, 0, &so,
	    &icp->ic_sii_hdl, &result);
	if (ret != DDI_SUCCESS) {
		TNF_PROBE_1(av1394_ic_alloc_channel_error,
		    AV1394_TNF_ISOCH_ERROR, "", tnf_int, result, result);
	} else {
		*num = so.channel_num;
	}
	return (ret);
}

static void
av1394_ic_free_channel(av1394_ic_t *icp)
{
	av1394_inst_t	*avp = icp->ic_avp;

	if (icp->ic_sii_hdl != NULL) {
		t1394_free_isoch_single(avp->av_t1394_hdl, &icp->ic_sii_hdl, 0);
	}
}

/*
 *
 * --- memory allocation and mapping routines
 *
 * av1394_ic_alloc_pool()
 *    Allocate isoch pool for at least 'mincnt' and at most 'cnt' frames
 *    'framesz' bytes each. The strategy is to allocate segments of reasonably
 *    large size, to avoid fragmentation and use resources efficiently in case
 *    of a large number of very small frames.
 *
 *    Another problem is that RECV/SEND_BUF IXL commands can address limited
 *    amount of buffer space (AV1394_IXL_BUFSZ_MAX), and if segment size and
 *    buffer size are not aligned, it can make much harder to build IXL chains.
 *    To simplify things, segments shall always contain full frames.
 *
 *    Function returns number of frames the resulting pool can hold.
 */
int
av1394_ic_alloc_pool(av1394_isoch_pool_t *pool, size_t framesz, int cnt,
	int mincnt)
{
	av1394_isoch_seg_t *seg;
	int		fps;		/* frames per segment */
	int		nsegs;
	size_t		totalsz, segsz;
	int		i;
	int		ret;

	AV1394_TNF_ENTER(av1394_ic_alloc_pool);

	totalsz = framesz * cnt;
	ASSERT(totalsz > 0);

	/* request should be reasonable */
	if (btopr(totalsz) > physmem / AV1394_MEM_MAX_PERCENT) {
		TNF_PROBE_0(av1394_ic_alloc_pool_error_physmem,
		    AV1394_TNF_ISOCH_ERROR, "");
		AV1394_TNF_EXIT(av1394_ic_alloc_pool);
		return (0);
	}

	/* calculate segment size and number of segments */
	segsz = framesz;
	nsegs = cnt;
	if (framesz < AV1394_IXL_BUFSZ_MAX / 2) {
		fps = AV1394_IXL_BUFSZ_MAX / framesz;
		segsz = framesz * fps;
		nsegs = totalsz / segsz;
		if ((totalsz % segsz) != 0)
			nsegs++;	/* remainder in non-full segment */
	}
	ASSERT(segsz * nsegs >= totalsz);

	/* allocate segment array */
	pool->ip_alloc_size = nsegs * sizeof (av1394_isoch_seg_t);
	pool->ip_seg = kmem_zalloc(pool->ip_alloc_size, KM_SLEEP);

	/* allocate page-aligned user-mappable memory for each segment */
	pool->ip_nsegs = 0;
	pool->ip_size = 0;
	pool->ip_umem_size = 0;
	for (i = 0; i < nsegs; i++) {
		seg = &pool->ip_seg[i];

		seg->is_umem_size = ptob(btopr(segsz));
		seg->is_kaddr = ddi_umem_alloc(seg->is_umem_size,
		    DDI_UMEM_SLEEP, &seg->is_umem_cookie);
		if (seg->is_kaddr == NULL) {
			TNF_PROBE_0(av1394_ic_alloc_pool_error_umem_alloc,
			    AV1394_TNF_ISOCH_ERROR, "");
			break;
		}
		seg->is_size = segsz;

		pool->ip_size += seg->is_size;
		pool->ip_umem_size += seg->is_umem_size;
		pool->ip_nsegs++;
	}

	/* number of frames the pool can hold */
	ret = pool->ip_size / framesz;
	if (ret < mincnt) {
		TNF_PROBE_0(av1394_ic_alloc_pool_error_mincnt,
		    AV1394_TNF_ISOCH_ERROR, "");
		av1394_ic_free_pool(pool);
		ret = 0;
	}

	AV1394_TNF_EXIT(av1394_ic_alloc_pool);
	return (ret);
}

void
av1394_ic_free_pool(av1394_isoch_pool_t *pool)
{
	int	i;

	AV1394_TNF_ENTER(av1394_ic_free_pool);

	if (pool->ip_seg != NULL) {
		for (i = 0; i < pool->ip_nsegs; i++) {
			ddi_umem_free(pool->ip_seg[i].is_umem_cookie);
		}
		kmem_free(pool->ip_seg, pool->ip_alloc_size);
		pool->ip_seg = NULL;
	}

	AV1394_TNF_EXIT(av1394_ic_free_pool);
}

int
av1394_ic_dma_setup(av1394_ic_t *icp, av1394_isoch_pool_t *pool)
{
	av1394_inst_t		*avp = icp->ic_avp;
	av1394_isoch_seg_t	*isp;
	uint_t			dma_dir;
	int			ret;
	int			i;
	int			j;

	AV1394_TNF_ENTER(av1394_ic_dma_setup);

	dma_dir = (icp->ic_dir == AV1394_IR) ? DDI_DMA_READ : DDI_DMA_WRITE;
	/*
	 * Alloc and bind a DMA handle for each segment.
	 * Note that we need packet size alignment, but since ddi_umem_alloc'ed
	 * memory is page-aligned and our packets are less than page size (yet)
	 * we don't need to do anything special here.
	 */
	for (i = 0; i < pool->ip_nsegs; i++) {
		isp = &pool->ip_seg[i];

		ret = ddi_dma_alloc_handle(avp->av_dip,
		    &avp->av_attachinfo.dma_attr, DDI_DMA_DONTWAIT, NULL,
		    &isp->is_dma_hdl);
		if (ret != DDI_SUCCESS) {
			TNF_PROBE_0(av1394_ic_dma_setup_error_alloc_hdl,
			    AV1394_TNF_ISOCH_ERROR, "");
			av1394_ic_dma_cleanup(icp, pool);
			AV1394_TNF_EXIT(av1394_ic_dma_setup);
			return (ret);
		}

		ret = ddi_dma_addr_bind_handle(isp->is_dma_hdl, NULL,
		    isp->is_kaddr, isp->is_size,
		    dma_dir | DDI_DMA_CONSISTENT, DDI_DMA_DONTWAIT, NULL,
		    &isp->is_dma_cookie[0], &isp->is_dma_ncookies);

		if (ret != DDI_DMA_MAPPED) {
			TNF_PROBE_0(av1394_ic_dma_setup_error_bind_hdl,
			    AV1394_TNF_ISOCH_ERROR, "");
			av1394_ic_dma_cleanup(icp, pool);
			AV1394_TNF_EXIT(av1394_ic_dma_setup);
			return (DDI_FAILURE);
		}

		if (isp->is_dma_ncookies > COOKIES) {
			TNF_PROBE_0(av1394_ic_dma_setup_error_ncookies,
			    AV1394_TNF_ISOCH_ERROR, "");
			av1394_ic_dma_cleanup(icp, pool);
			AV1394_TNF_EXIT(av1394_ic_dma_setup);
			return (DDI_FAILURE);
		}

		for (j = 1; j < isp->is_dma_ncookies; ++j)
			ddi_dma_nextcookie(isp->is_dma_hdl,
			    &isp->is_dma_cookie[j]);
	}

	AV1394_TNF_EXIT(av1394_ic_dma_setup);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
void
av1394_ic_dma_cleanup(av1394_ic_t *icp, av1394_isoch_pool_t *pool)
{
	av1394_isoch_seg_t	*seg;
	int			i;

	AV1394_TNF_ENTER(av1394_ic_dma_cleanup);

	for (i = 0; i < pool->ip_nsegs; i++) {
		seg = &pool->ip_seg[i];
		if (seg->is_dma_hdl != NULL) {
			if (seg->is_dma_ncookies > 0) {
				(void) ddi_dma_unbind_handle(seg->is_dma_hdl);
			}
			ddi_dma_free_handle(&seg->is_dma_hdl);
		}
	}

	AV1394_TNF_EXIT(av1394_ic_dma_cleanup);
}

/*
 * sync frames for CPU access
 */
void
av1394_ic_dma_sync_frames(av1394_ic_t *icp, int idx, int cnt,
		av1394_isoch_pool_t *pool, uint_t type)
{
	int	fps;		/* frames per segment */
	int	nsegs;		/* number of segments for indicated frames */
	int	seg;		/* index of segment to sync */

	fps = icp->ic_nframes / pool->ip_nsegs;

	nsegs = (cnt / fps) + 1;

	seg = idx / fps;

	for (;;) {
		(void) ddi_dma_sync(pool->ip_seg[seg].is_dma_hdl, 0,
		    icp->ic_framesz, type);

		--nsegs;
		if (nsegs == 0)
			break;

		++seg;
		if (seg == pool->ip_nsegs)
			seg = 0;	/* wrap segment index */
	}
}

/*
 *
 * --- transfer
 *
 */
int
av1394_ic_start(av1394_ic_t *icp)
{
	if (icp->ic_dir == AV1394_IR) {
		return (av1394_ir_start(icp));
	} else {
		return (av1394_it_start(icp));
	}
}

int
av1394_ic_stop(av1394_ic_t *icp)
{
	if (icp->ic_dir == AV1394_IR) {
		return (av1394_ir_stop(icp));
	} else {
		return (av1394_it_stop(icp));
	}
}

/*
 *
 * --- callbacks
 *
 */
/*ARGSUSED*/
static void
av1394_ic_rsrc_fail(t1394_isoch_single_handle_t t1394_sii_hdl, opaque_t arg,
		t1394_isoch_rsrc_error_t fail_args)
{
	AV1394_TNF_ENTER(av1394_ic_rsrc_fail);

	/* XXX this could be handled more gracefully */
	cmn_err(CE_CONT, "av1394: can't reallocate isochronous resources"
	    " after bus reset\n");

	AV1394_TNF_EXIT(av1394_ic_rsrc_fail);
}

/*
 *
 * --- misc
 *
 *
 * av1394_ic_ixl_seg_decomp()
 *    Calculate the best decomposition of a segment into buffers.
 *    Return number of buffers, buffer and tail buffer sizes.
 *
 *    We are looking to divide a segment evenly into equally-sized or almost
 *    equally-sized buffers. Maximum buffer size is AV1394_IXL_BUFSZ_MAX.
 *    Algorithm:
 *	1. If segment size divides evenly by maximum size, terminate.
 *	2. n = number of maximum-size buffers than fits into the segment.
 *	3. Divide the segment by n+1, calculate buffer size and tail
 *	   (remainder) size.
 *	4. If the tail can be appended to the last buffer and the resulting
 *	   buffer is still less than maximum size, terminate.
 *	5. Repeat steps 3-5 for n+2, n+3, ... until division is too small.
 *
 *    Since all sizes are packet-aligned, we scale them down (divide by
 *    packet size) in the beginning, do all calculations and scale them up
 *    in the end.
 */
int
av1394_ic_ixl_seg_decomp(size_t segsz, size_t pktsz, size_t *bufszp,
	size_t *tailszp)
{
	size_t	nbufs, bufsz, tailsz;
	size_t	maxsz = AV1394_IXL_BUFSZ_MAX;

	ASSERT(segsz >= maxsz);
	ASSERT(segsz % pktsz == 0);

	if (segsz % maxsz == 0) {
		*tailszp = *bufszp = maxsz;
		return (segsz / *bufszp - 1);
	}

	maxsz /= pktsz;
	segsz /= pktsz;

	nbufs = segsz / maxsz;
	do {
		nbufs++;
		bufsz = segsz / nbufs;
		tailsz = bufsz + (segsz - bufsz * nbufs);
	} while ((tailsz > maxsz) && ((segsz / (nbufs + 1)) > 1));
	nbufs--;

	*bufszp = bufsz * pktsz;
	*tailszp = tailsz * pktsz;
	return (nbufs);
}

void
av1394_ic_ixl_dump(ixl1394_command_t *cmd)
{
	ixl1394_callback_t	*cb;
	ixl1394_jump_t		*jmp;
	ixl1394_xfer_buf_t	*buf;
	ixl1394_xfer_pkt_t	*pkt;

	while (cmd) {
		switch (cmd->ixl_opcode) {
		case IXL1394_OP_LABEL:
			cmn_err(CE_CONT, "%p: LABEL\n", (void *)cmd);
			break;
		case IXL1394_OP_RECV_BUF:
		case IXL1394_OP_RECV_BUF_U:
			buf = (ixl1394_xfer_buf_t *)cmd;
			cmn_err(CE_CONT, "%p: RECV_BUF addr=%p size=%d "
			    "pkt_size=%d\n", (void *)cmd, (void *)buf->mem_bufp,
			    buf->size, buf->pkt_size);
			break;
		case IXL1394_OP_SEND_BUF:
		case IXL1394_OP_SEND_BUF_U:
			buf = (ixl1394_xfer_buf_t *)cmd;
			cmn_err(CE_CONT, "%p: SEND_BUF addr=%p size=%d "
			    "pkt_size=%d\n", (void *)cmd, (void *)buf->mem_bufp,
			    buf->size, buf->pkt_size);
			break;
		case IXL1394_OP_SEND_PKT_ST:
			pkt = (ixl1394_xfer_pkt_t *)cmd;
			cmn_err(CE_CONT, "%p: SEND_PKT_ST addr=%p size=%d\n",
			    (void *)cmd, (void *)pkt->mem_bufp, pkt->size);
			break;
		case IXL1394_OP_CALLBACK:
		case IXL1394_OP_CALLBACK_U:
			cb = (ixl1394_callback_t *)cmd;
			cmn_err(CE_CONT, "%p: CALLBACK %p\n", (void *)cmd,
			    (void *)cb->callback);
			break;
		case IXL1394_OP_JUMP:
			jmp = (ixl1394_jump_t *)cmd;
			cmn_err(CE_CONT, "%p: JUMP %p\n", (void *)cmd,
			    (void *)jmp->label);
			break;
		case IXL1394_OP_JUMP_U:
			jmp = (ixl1394_jump_t *)cmd;
			cmn_err(CE_CONT, "%p: JUMP_U %p\n", (void *)cmd,
			    (void *)jmp->label);
			break;
		case IXL1394_OP_STORE_TIMESTAMP:
			cmn_err(CE_CONT, "%p: STORE_TIMESTAMP\n", (void *)cmd);
			break;
		default:
			cmn_err(CE_CONT, "%p: other\n", (void *)cmd);
		}
		cmd = cmd->next_ixlp;
	}
}

/*
 * trigger a soft interrupt, if not already, for a given channel and type
 */
void
av1394_ic_trigger_softintr(av1394_ic_t *icp, int num, int preq)
{
	av1394_isoch_t	*ip = &icp->ic_avp->av_i;
	uint64_t	chmask = (1ULL << num);

	if (((ip->i_softintr_ch & chmask) == 0) ||
	    ((icp->ic_preq & preq) == 0)) {
		ip->i_softintr_ch |= chmask;
		icp->ic_preq |= preq;
		ddi_trigger_softintr(ip->i_softintr_id);
	}
}

/*
 * reverse bits in a 64-bit word
 */
uint64_t
av1394_ic_bitreverse(uint64_t x)
{
	x = (((x >> 1) & 0x5555555555555555) | ((x & 0x5555555555555555) << 1));
	x = (((x >> 2) & 0x3333333333333333) | ((x & 0x3333333333333333) << 2));
	x = (((x >> 4) & 0x0f0f0f0f0f0f0f0f) | ((x & 0x0f0f0f0f0f0f0f0f) << 4));
	x = (((x >> 8) & 0x00ff00ff00ff00ff) | ((x & 0x00ff00ff00ff00ff) << 8));
	x = (((x >> 16) & 0x0000ffff0000ffff) |
	    ((x & 0x0000ffff0000ffff) << 16));

	return ((x >> 32) | (x << 32));
}

/*
 * return B_TRUE if a 64-bit value has only one bit set to 1
 */
boolean_t
av1394_ic_onebit(uint64_t i)
{
	return (((~i + 1) | ~i) == 0xFFFFFFFFFFFFFFFF);
}
