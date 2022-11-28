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
 * av1394 isochronous transmit module
 */
#include <sys/1394/targets/av1394/av1394_impl.h>

static int	av1394_it_start_common(av1394_ic_t *);

/* configuration routines */
static void	av1394_it_cleanup(av1394_ic_t *, int);
static int	av1394_it_bld_ixl(av1394_ic_t *);
static void	av1394_it_destroy_ixl(av1394_ic_t *);
static int	av1394_it_ixl_bld_data(av1394_ic_t *);
static void	av1394_it_ixl_destroy_data(av1394_ic_t *);
static av1394_it_ixl_buf_t *av1394_it_ixl_bld_buf(av1394_ic_t *, int, int,
		off_t, int, int);
static void	av1394_it_ixl_complete_buf(av1394_it_ixl_buf_t *,
		av1394_it_ixl_empty_cip_t *);
static void	av1394_it_ixl_complete_buf2(av1394_it_ixl_buf_t *,
		av1394_it_ixl_buf_t *);
static av1394_it_ixl_empty_cip_t *av1394_it_ixl_bld_empty_cip(av1394_ic_t *,
		int);
static void	av1394_it_ixl_complete_empty_cip(av1394_it_ixl_empty_cip_t *,
		av1394_it_ixl_buf_t *);
static void	av1394_it_ixl_bld_begin(av1394_ic_t *);
static void	av1394_it_ixl_begin_update_pkts(av1394_ic_t *,
		av1394_it_ixl_buf_t *);
static int	av1394_it_alloc_isoch_dma(av1394_ic_t *);
static void	av1394_it_free_isoch_dma(av1394_ic_t *);
static void	av1394_it_dma_sync_frames(av1394_ic_t *, int, int);

/* callbacks */
static void	av1394_it_ixl_begin_cb(opaque_t, struct ixl1394_callback *);
static void	av1394_it_ixl_buf_cb(opaque_t, struct ixl1394_callback *);
static void	av1394_it_ixl_eof_cb(av1394_it_ixl_buf_t *bp);
static int	av1394_it_underrun_resume(av1394_ic_t *);
static void	av1394_it_dma_stopped_cb(t1394_isoch_dma_handle_t,
		opaque_t, id1394_isoch_dma_stopped_t);

/* data transfer routines */
static int	av1394_it_add_frames(av1394_ic_t *, int, int);
static int	av1394_it_wait_frames(av1394_ic_t *, int *, int *, int *);

static void	av1394_it_update_frame_syt(av1394_ic_t *, int, int, uint16_t);
static uint16_t	av1394_it_ts_cyc2syt(uint16_t);
static uint16_t	av1394_it_ts_syt_inc(uint16_t, uint16_t);

static void	av1394_it_kcopyin(av1394_ic_t *, void *, size_t);
static int	av1394_it_copyin(av1394_ic_t *, struct uio *, int *, int);
static boolean_t av1394_it_is_dv_frame_start(caddr_t);
static void	av1394_it_reset_frame_syt(av1394_ic_t *, int);

/* tunables */
int av1394_it_hiwat_sub = 2;
int av1394_it_lowat = 3;
int av1394_it_start_thre = 3;	/* xmit start threshold */
int av1394_it_syt_off = 3;	/* SYT offset in cycles */
int av1394_it_dump_ixl = 0;

int
av1394_it_init(av1394_ic_t *icp, int *error)
{
	av1394_it_t	*itp = &icp->ic_it;
	av1394_isoch_pool_t *pool = &itp->it_data_pool;
	int		nframes;

	nframes = av1394_ic_alloc_pool(pool, icp->ic_framesz, icp->ic_nframes,
	    AV1394_IT_NFRAMES_MIN);
	if (nframes == 0) {
		*error = IEC61883_ERR_NOMEM;
		return (EINVAL);
	}
	mutex_enter(&icp->ic_mutex);
	icp->ic_nframes = nframes;
	itp->it_hiwat = nframes - av1394_it_hiwat_sub;
	itp->it_lowat = av1394_it_lowat;
	itp->it_start_thre = av1394_it_start_thre;
	itp->it_nempty = icp->ic_nframes;
	itp->it_last_full = icp->ic_nframes - 1;

	if (av1394_ic_dma_setup(icp, pool) != DDI_SUCCESS) {
		mutex_exit(&icp->ic_mutex);
		*error = IEC61883_ERR_NOMEM;
		av1394_it_cleanup(icp, 1);
		return (EINVAL);
	}

	if (av1394_it_bld_ixl(icp) != DDI_SUCCESS) {
		mutex_exit(&icp->ic_mutex);
		*error = IEC61883_ERR_NOMEM;
		av1394_it_cleanup(icp, 2);
		return (EINVAL);
	}
	mutex_exit(&icp->ic_mutex);

	if (av1394_it_alloc_isoch_dma(icp) != DDI_SUCCESS) {
		*error = IEC61883_ERR_NOMEM;
		av1394_it_cleanup(icp, 3);
		return (EINVAL);
	}

	return (0);
}

void
av1394_it_fini(av1394_ic_t *icp)
{
	av1394_it_cleanup(icp, AV1394_CLEANUP_LEVEL_MAX);
}

int
av1394_it_start(av1394_ic_t *icp)
{
	av1394_it_t	*itp = &icp->ic_it;
	int		ret = 0;

	mutex_enter(&icp->ic_mutex);
	ASSERT(icp->ic_state == AV1394_IC_IDLE);

	/* should be enough full frames to be able to start */
	if (itp->it_nfull >= itp->it_start_thre) {
		ret = av1394_it_start_common(icp);
	}
	mutex_exit(&icp->ic_mutex);

	return (ret);
}

static int
av1394_it_start_common(av1394_ic_t *icp)
{
	av1394_inst_t	*avp = icp->ic_avp;
	id1394_isoch_dma_ctrlinfo_t idma_ctrlinfo = { 0 };
	int		result;
	int		err;
	int		ret = 0;

	ASSERT(icp->ic_state == AV1394_IC_IDLE);

	err = t1394_start_isoch_dma(avp->av_t1394_hdl, icp->ic_isoch_hdl,
	    &idma_ctrlinfo, 0, &result);
	if (err == DDI_SUCCESS) {
		icp->ic_state = AV1394_IC_DMA;
	} else {
		ret = EIO;
	}

	return (ret);
}


int
av1394_it_stop(av1394_ic_t *icp)
{
	av1394_inst_t	*avp = icp->ic_avp;
	av1394_it_t	*itp = &icp->ic_it;

	mutex_enter(&icp->ic_mutex);
	if (icp->ic_state != AV1394_IC_IDLE) {
		mutex_exit(&icp->ic_mutex);
		t1394_stop_isoch_dma(avp->av_t1394_hdl, icp->ic_isoch_hdl, 0);
		mutex_enter(&icp->ic_mutex);

		icp->ic_state = AV1394_IC_IDLE;
		itp->it_nempty = icp->ic_nframes;
		itp->it_first_empty = 0;
		itp->it_last_full = icp->ic_nframes - 1;
		itp->it_nfull = 0;
	}
	mutex_exit(&icp->ic_mutex);

	return (0);
}

int
av1394_it_xmit(av1394_ic_t *icp, iec61883_xmit_t *xmit)
{
	av1394_it_t	*itp = &icp->ic_it;
	int		ret = 0;
	int		idx, cnt;

	idx = xmit->tx_xfer.xf_full_idx;
	cnt = xmit->tx_xfer.xf_full_cnt;

	mutex_enter(&icp->ic_mutex);
	/* check arguments */
	if ((idx < 0) || (cnt < 0) || (cnt > itp->it_nempty)) {
		mutex_exit(&icp->ic_mutex);
		return (EINVAL);
	}

	/* add full frames to the pool */
	if (cnt > 0) {
		if ((ret = av1394_it_add_frames(icp, idx, cnt)) != 0) {
			mutex_exit(&icp->ic_mutex);
			return (ret);
		}
	}

	if ((icp->ic_state == AV1394_IC_IDLE) &&
	    (itp->it_nfull >= itp->it_start_thre)) {
		if ((ret = av1394_it_start_common(icp)) != 0) {
			mutex_exit(&icp->ic_mutex);
			return (ret);
		}
	}

	/* wait for new empty frames */
	ret = av1394_it_wait_frames(icp, &xmit->tx_xfer.xf_empty_idx,
	    &xmit->tx_xfer.xf_empty_cnt, &xmit->tx_miss_cnt);
	mutex_exit(&icp->ic_mutex);

	return (ret);
}

int
av1394_it_write(av1394_ic_t *icp, struct uio *uiop)
{
	av1394_inst_t	*avp = icp->ic_avp;
	av1394_it_t	*itp = &icp->ic_it;
	av1394_isoch_autoxmit_t *axp = &avp->av_i.i_autoxmit;
	int		dv;
	int		ret = 0;
	int		full_cnt;
	int		miss_cnt;

	mutex_enter(&icp->ic_mutex);
	dv = (axp->ax_fmt & AV1394_ISOCH_AUTOXMIT_DV);

	while (uiop->uio_resid > 0) {
		/* must have at least one empty frame */
		if (itp->it_write_cnt == 0) {
			ret = av1394_it_wait_frames(icp, &itp->it_write_idx,
			    &itp->it_write_cnt, &miss_cnt);
			if (ret != 0) {
				break;
			}
		}

		/* copyin as much data as we can */
		if (axp->ax_copy_ciph) {
			ASSERT(itp->it_write_off == 0);
			av1394_it_kcopyin(icp, axp->ax_ciph, AV1394_CIPSZ);
			axp->ax_copy_ciph = B_FALSE;
		}
		if ((ret = av1394_it_copyin(icp, uiop, &full_cnt, dv)) != 0) {
			break;
		}

		/* add full frames to the pool */
		if (full_cnt > 0) {
			ret = av1394_it_add_frames(icp,
			    itp->it_write_idx, full_cnt);
			if (ret != 0) {
				break;
			}
			itp->it_write_idx += full_cnt;
			itp->it_write_idx %= icp->ic_nframes;
		}

		/* start xfer if not already */
		if ((icp->ic_state == AV1394_IC_IDLE) &&
		    (itp->it_nfull >= itp->it_start_thre)) {
			if ((ret = av1394_it_start_common(icp)) != 0) {
				mutex_exit(&icp->ic_mutex);
				return (ret);
			}
		}
	}
	mutex_exit(&icp->ic_mutex);

	return (ret);
}

/*
 *
 * --- configuration routines
 *
 */
static void
av1394_it_cleanup(av1394_ic_t *icp, int level)
{
	av1394_isoch_pool_t *pool = &icp->ic_it.it_data_pool;

	ASSERT((level > 0) && (level <= AV1394_CLEANUP_LEVEL_MAX));

	switch (level) {
	default:
		av1394_it_free_isoch_dma(icp);
		/* FALLTHRU */
	case 3:
		av1394_it_destroy_ixl(icp);
		/* FALLTHRU */
	case 2:
		av1394_ic_dma_cleanup(icp, pool);
		/* FALLTHRU */
	case 1:
		av1394_ic_free_pool(pool);
		/* FALLTHRU */
	}
}

/*
 * av1394_it_bld_ixl()
 *    Build an IXL chain out of several blocks.
 */
static int
av1394_it_bld_ixl(av1394_ic_t *icp)
{
	av1394_it_t	*itp = &icp->ic_it;
	int		ret;

	/* data block */
	if ((ret = av1394_it_ixl_bld_data(icp)) != DDI_SUCCESS) {
		return (ret);
	}

	/* begin block */
	if (icp->ic_param.cp_ts_mode != IEC61883_TS_NONE) {
		av1394_it_ixl_bld_begin(icp);

		itp->it_ixlp = (ixl1394_command_t *)&itp->it_ixl_begin;
	} else {
		itp->it_ixlp = (ixl1394_command_t *)
		    &((av1394_it_ixl_buf_t *)itp->it_ixl_data)->tb_label;
	}

	if (av1394_it_dump_ixl) {
		av1394_ic_ixl_dump(itp->it_ixlp);
	}

	return (ret);
}

static void
av1394_it_destroy_ixl(av1394_ic_t *icp)
{
	av1394_it_t	*itp = &icp->ic_it;

	av1394_it_ixl_destroy_data(icp);
	itp->it_ixlp = NULL;
}

/*
 * build data transmit part of the IXL chain
 */
static int
av1394_it_ixl_bld_data(av1394_ic_t *icp)
{
	av1394_it_t		*itp = &icp->ic_it;
	av1394_isoch_pool_t	*pool = &itp->it_data_pool;
	int			total = 0;	/* # of pkts in the chain */
	int			nfull = 0;	/* # of full CIPs in a series */
	int			framenum = -1;	/* frame number */
	int			bufsz_max;	/* max buffer size in pkts */
	int			segnum = 0;	/* current segment number */
	int			segsz;		/* segment size in pkts */
	off_t			segoff = 0;	/* segment offset in pkts */
	av1394_it_ixl_empty_cip_t *ep = NULL;	/* last empty CIP */
	av1394_it_ixl_buf_t	*bp = NULL;	/* last data buffer */
	av1394_it_ixl_buf_t	*prevbp = NULL;
	int			a, n, d;	/* N/D algorithm variables */
	int			type, ptype;	/* current and prev CIP type */
	int			tb_flags;

	itp->it_frame_info = kmem_zalloc(icp->ic_nframes *
	    sizeof (av1394_it_frame_info_t), KM_SLEEP);

	bufsz_max = AV1394_IXL_BUFSZ_MAX / icp->ic_pktsz;
	n = icp->ic_param.cp_n;
	d = icp->ic_param.cp_d;
	/*
	 * following assert guarantees no more than one empty CIP in a row,
	 * i.e. empty CIPs account for <=50% of all packets.
	 * this should be ensured by ioctl argument validation.
	 */
	ASSERT((n == 0) || (d / n > 1));
	/*
	 * build the chain. it is hard to precalculate amount of memory
	 * needed for the entire chain, so we simply allocate as we go.
	 */
	ptype = AV1394_CIP_EMPTY;
	segsz = pool->ip_seg[0].is_size / icp->ic_pktsz;
	a = n;
	while (total < icp->ic_nframes * icp->ic_npkts) {
		/* insert empty CIPs using N/D algorithm */
		a += n;
		if (a > d) {
			a -= d;
			type = AV1394_CIP_EMPTY;
		} else {
			type = AV1394_CIP_FULL;
			nfull++;
		}

		/*
		 * merge series of full packets into single SEND_BUF commands.
		 * a series can be terminated by:
		 *  - an empty CIP;
		 *  - series buffer size reached maximum;
		 *  - end of isoch segment;
		 *  - end of frame (which is always at the end of segment);
		 */
		if (((type == AV1394_CIP_EMPTY) || (segoff + nfull == segsz) ||
		    (nfull == bufsz_max)) && (nfull > 0)) {

			/* build buffer block */
			prevbp = bp;
			tb_flags = 0;
			if (type == AV1394_CIP_EMPTY) {
				tb_flags |= AV1394_IT_IXL_BUF_NEXT_EMPTY;
			}
			if (total % icp->ic_npkts == 0) {
				tb_flags |= AV1394_IT_IXL_BUF_SOF;
				framenum++;
			}
			if ((total + nfull) % icp->ic_npkts == 0) {
				tb_flags |= AV1394_IT_IXL_BUF_EOF;
			}
			bp = av1394_it_ixl_bld_buf(icp, nfull, segnum, segoff,
			    tb_flags, framenum);

			if (itp->it_ixl_data == NULL) {
				itp->it_ixl_data = &bp->tb_common;
			}

			/* complete previous empty CIP or a buffer */
			if (ep) {
				av1394_it_ixl_complete_empty_cip(ep, bp);
				ep = NULL;
			} else if (prevbp) {
				av1394_it_ixl_complete_buf2(prevbp, bp);
			}

			/* if current segment is used up, pick next one */
			segoff += nfull;
			if (segoff == segsz) {
				if (++segnum < pool->ip_nsegs) {
					segsz = pool->ip_seg[segnum].is_size /
					    icp->ic_pktsz;
				}
				segoff = 0;
			}

			total += nfull;
			nfull = 0;
		}
		/* insert an empty packet if needed */
		if (type == AV1394_CIP_EMPTY) {
			ep = av1394_it_ixl_bld_empty_cip(icp, framenum);
			av1394_it_ixl_complete_buf(bp, ep);
		}
		ptype = type;
	}
	ASSERT(nfull == 0);

	/* last packet must be an empty CIP, except when n == 0 */
	if (n != 0) {
		if (ptype != AV1394_CIP_EMPTY) {
			ep = av1394_it_ixl_bld_empty_cip(icp, framenum);
			av1394_it_ixl_complete_buf(bp, ep);
		}
		av1394_it_ixl_complete_empty_cip(ep,
		    (av1394_it_ixl_buf_t *)itp->it_ixl_data);
		ep->te_jump.next_ixlp = NULL;
		ep->te_common.tc_next = NULL;
	} else {
		bp->tb_jump.label = (ixl1394_command_t *)
		    &(((av1394_it_ixl_buf_t *)itp->it_ixl_data)->tb_label);
	}

	return (DDI_SUCCESS);
}

static void
av1394_it_ixl_destroy_data(av1394_ic_t *icp)
{
	av1394_it_t		*itp = &icp->ic_it;
	av1394_it_ixl_common_t	*cmd, *cmd_next;

	for (cmd = itp->it_ixl_data; cmd != NULL; cmd = cmd_next) {
		cmd_next = cmd->tc_next;
		kmem_free(cmd, cmd->tc_size);
	}
	itp->it_ixl_data = NULL;

	kmem_free(itp->it_frame_info,
	    icp->ic_nframes * sizeof (av1394_it_frame_info_t));
}

static av1394_it_ixl_buf_t *
av1394_it_ixl_bld_buf(av1394_ic_t *icp, int cnt, int segnum, off_t off,
		int flags, int framenum)
{
	av1394_it_t		*itp = &icp->ic_it;
	av1394_isoch_seg_t	*isp = &itp->it_data_pool.ip_seg[segnum];
	av1394_it_ixl_buf_t	*bp;
	int			pktsz = icp->ic_pktsz;

	bp = kmem_zalloc(sizeof (av1394_it_ixl_buf_t), KM_SLEEP);
	bp->tb_common.tc_size = sizeof (av1394_it_ixl_buf_t);
	/* tc_next later */
	bp->tb_flags = flags;
	bp->tb_framenum = framenum;
	bp->tb_icp = icp;

	bp->tb_label.ixl_opcode = IXL1394_OP_LABEL;
	bp->tb_label.next_ixlp = (ixl1394_command_t *)&bp->tb_buf;

	bp->tb_buf.ixl_opcode = IXL1394_OP_SEND_BUF;
	bp->tb_buf.pkt_size = pktsz;
	bp->tb_buf.size = cnt * pktsz;
	bp->tb_buf.ixl_buf._dmac_ll =
	    isp->is_dma_cookie[0].dmac_laddress + off * pktsz;
	bp->tb_buf.mem_bufp = isp->is_kaddr + off * pktsz;

	if (flags & AV1394_IT_IXL_BUF_EOF) {
		bp->tb_buf.next_ixlp = (ixl1394_command_t *)&bp->tb_store_ts;

		bp->tb_store_ts.ixl_opcode = IXL1394_OP_STORE_TIMESTAMP;
		bp->tb_store_ts.next_ixlp = (ixl1394_command_t *)&bp->tb_cb;

		bp->tb_cb.ixl_opcode = IXL1394_OP_CALLBACK;
		bp->tb_cb.callback = av1394_it_ixl_buf_cb;
		bp->tb_cb.callback_arg = bp;
		bp->tb_cb.next_ixlp = (ixl1394_command_t *)&bp->tb_jump;

		bp->tb_jump.ixl_opcode = IXL1394_OP_JUMP_U;
	} else {
		bp->tb_buf.next_ixlp = (ixl1394_command_t *)&bp->tb_jump;

		bp->tb_jump.ixl_opcode = IXL1394_OP_JUMP;
	}
	/*
	 * jump label and next_ixlp later.
	 * unset fields will be set in av1394_it_ixl_complete_buf()
	 *
	 * save additional frame info
	 */
	if (flags & AV1394_IT_IXL_BUF_SOF) {
		itp->it_frame_info[framenum].fi_first_buf = bp;
		itp->it_frame_info[framenum].fi_ts_off = bp->tb_buf.mem_bufp +
		    AV1394_TS_MODE_GET_OFF(icp->ic_param.cp_ts_mode);
	} else if (flags & AV1394_IT_IXL_BUF_EOF) {
		itp->it_frame_info[framenum].fi_last_buf = bp;
	}
	itp->it_frame_info[framenum].fi_ncycs += cnt;

	return (bp);
}

static void
av1394_it_ixl_complete_buf(av1394_it_ixl_buf_t *bp,
	av1394_it_ixl_empty_cip_t *ep)
{
	bp->tb_common.tc_next = &ep->te_common;
	bp->tb_jump.label = bp->tb_jump.next_ixlp =
	    (ixl1394_command_t *)&ep->te_label;
}

static void
av1394_it_ixl_complete_buf2(av1394_it_ixl_buf_t *bp,
	av1394_it_ixl_buf_t *nextbp)
{
	bp->tb_common.tc_next = &nextbp->tb_common;
	bp->tb_jump.label = bp->tb_jump.next_ixlp =
	    (ixl1394_command_t *)&nextbp->tb_label;
}

static av1394_it_ixl_empty_cip_t *
av1394_it_ixl_bld_empty_cip(av1394_ic_t *icp, int framenum)
{
	av1394_it_t	*itp = &icp->ic_it;
	av1394_it_ixl_empty_cip_t *ep;

	ep = kmem_zalloc(sizeof (av1394_it_ixl_empty_cip_t), KM_SLEEP);
	ep->te_common.tc_size = sizeof (av1394_it_ixl_empty_cip_t);
	/* tc_next later */

	ep->te_label.ixl_opcode = IXL1394_OP_LABEL;
	ep->te_label.next_ixlp = (ixl1394_command_t *)&ep->te_pkt;

	ep->te_pkt.ixl_opcode = IXL1394_OP_SEND_PKT_ST;
	ep->te_pkt.size = AV1394_CIPSZ;
	/* ixl_buf and mem_bufp later */
	ep->te_pkt.next_ixlp = (ixl1394_command_t *)&ep->te_jump;

	ep->te_jump.ixl_opcode = IXL1394_OP_JUMP;
	/*
	 * label and next_ixlp later.
	 * unset fields will be set in av1394_it_ixl_complete_empty_cip()
	 */

	itp->it_frame_info[framenum].fi_ncycs++;

	return (ep);
}

/*
 * empty CIP packet contains CIP header of the next packet,
 * so we just point to the same address as the next packet's header
 */
static void
av1394_it_ixl_complete_empty_cip(av1394_it_ixl_empty_cip_t *ep,
	av1394_it_ixl_buf_t *bp)
{
	ep->te_common.tc_next = &bp->tb_common;

	ep->te_pkt.ixl_buf._dmac_ll = bp->tb_buf.ixl_buf._dmac_ll;
	ep->te_pkt.mem_bufp = bp->tb_buf.mem_bufp;

	ep->te_jump.label = ep->te_jump.next_ixlp =
	    (ixl1394_command_t *)&bp->tb_label;
}

static void
av1394_it_ixl_bld_begin(av1394_ic_t *icp)
{
	av1394_it_t		*itp = &icp->ic_it;
	av1394_it_ixl_buf_t	*bp = (av1394_it_ixl_buf_t *)itp->it_ixl_data;
	av1394_it_ixl_begin_t	*bep = &itp->it_ixl_begin;
	int			i;

	bep->be_label.ixl_opcode = IXL1394_OP_LABEL;
	bep->be_label.next_ixlp = (ixl1394_command_t *)&bep->be_empty_pre;

	bep->be_empty_pre.ixl_opcode = IXL1394_OP_SEND_PKT_ST;
	bep->be_empty_pre.size = AV1394_CIPSZ;
	bep->be_empty_pre.ixl_buf._dmac_ll = bp->tb_buf.ixl_buf._dmac_ll;
	bep->be_empty_pre.mem_bufp = bp->tb_buf.mem_bufp;
	bep->be_empty_pre.next_ixlp = (ixl1394_command_t *)&bep->be_store_ts;

	bep->be_store_ts.ixl_opcode = IXL1394_OP_STORE_TIMESTAMP;
	bep->be_store_ts.next_ixlp = (ixl1394_command_t *)&bep->be_cb;

	bep->be_cb.ixl_opcode = IXL1394_OP_CALLBACK;
	bep->be_cb.callback = av1394_it_ixl_begin_cb;
	bep->be_cb.callback_arg = &bep->be_store_ts.timestamp;
	bep->be_cb.next_ixlp = (ixl1394_command_t *)&bep->be_empty_post[0];

	for (i = 0; i < AV1394_IT_IXL_BEGIN_NPOST; i++) {
		bep->be_empty_post[i].ixl_opcode = IXL1394_OP_SEND_PKT_ST;
		bep->be_empty_post[i].size = AV1394_CIPSZ;
		bep->be_empty_post[i].ixl_buf._dmac_ll =
		    bp->tb_buf.ixl_buf._dmac_ll;
		bep->be_empty_post[i].mem_bufp = bp->tb_buf.mem_bufp;
		bep->be_empty_post[i].next_ixlp =
		    (ixl1394_command_t *)&bep->be_empty_post[i + 1];
	}
	bep->be_empty_post[AV1394_IT_IXL_BEGIN_NPOST - 1].next_ixlp =
	    (ixl1394_command_t *)&bep->be_jump;

	bep->be_jump.ixl_opcode = IXL1394_OP_JUMP_U;
	bep->be_jump.label = (ixl1394_command_t *)&bp->tb_label;
	bep->be_jump.next_ixlp = (ixl1394_command_t *)&bp->tb_label;
}

static void
av1394_it_ixl_begin_update_pkts(av1394_ic_t *icp, av1394_it_ixl_buf_t *bp)
{
	av1394_it_t		*itp = &icp->ic_it;
	av1394_it_ixl_begin_t	*bep = &itp->it_ixl_begin;
	int			i;

	for (i = 0; i < AV1394_IT_IXL_BEGIN_NPOST; i++) {
		bep->be_empty_post[i].ixl_buf._dmac_ll =
		    bp->tb_buf.ixl_buf._dmac_ll;
		bep->be_empty_post[i].mem_bufp = bp->tb_buf.mem_bufp;
	}
}

static int
av1394_it_alloc_isoch_dma(av1394_ic_t *icp)
{
	av1394_inst_t		*avp = icp->ic_avp;
	av1394_it_t		*itp = &icp->ic_it;
	id1394_isoch_dmainfo_t	di;
	int			result;
	int			ret;

	di.ixlp = itp->it_ixlp;
	di.channel_num = icp->ic_num;
	di.idma_options = ID1394_TALK;
	di.it_speed = icp->ic_param.cp_bus_speed;
	/*
	 * XXX this should really be IXL1394_SKIP_TO_NEXT,
	 * but it can't be used yet due to the Framework bug
	 */
	di.it_default_skip = IXL1394_SKIP_TO_SELF;
	di.default_tag = 1;
	di.default_sync = 0;
	di.global_callback_arg = icp;
	di.isoch_dma_stopped = av1394_it_dma_stopped_cb;
	di.idma_evt_arg = icp;

	ret = t1394_alloc_isoch_dma(avp->av_t1394_hdl, &di, 0,
	    &icp->ic_isoch_hdl, &result);

	return (ret);
}

static void
av1394_it_free_isoch_dma(av1394_ic_t *icp)
{
	av1394_inst_t		*avp = icp->ic_avp;

	t1394_free_isoch_dma(avp->av_t1394_hdl, 0, &icp->ic_isoch_hdl);
}

static void
av1394_it_dma_sync_frames(av1394_ic_t *icp, int idx, int cnt)
{
	av1394_ic_dma_sync_frames(icp, idx, cnt,
	    &icp->ic_it.it_data_pool, DDI_DMA_SYNC_FORDEV);
}

/*
 *
 * --- callbacks
 *
 */
static void
av1394_it_ixl_begin_cb(opaque_t arg, struct ixl1394_callback *cb)
{
	av1394_ic_t	*icp = arg;
	av1394_it_t	*itp = &icp->ic_it;
	uint16_t	*cycp = cb->callback_arg; /* cycle timestamp pointer */
	uint16_t	syt;
	int		first;

	mutex_enter(&icp->ic_mutex);
	/* save initial timestamp value */
	itp->it_ts_init.ts_syt = av1394_it_ts_cyc2syt(*cycp);

	/*
	 * update frame timestamps if needed
	 */
	if ((itp->it_nfull <= 0) ||
	    (AV1394_TS_MODE_GET_SIZE(icp->ic_param.cp_ts_mode) == 0)) {
		mutex_exit(&icp->ic_mutex);
		return;
	}
	ASSERT(itp->it_nfull <= icp->ic_nframes);

	syt = av1394_it_ts_syt_inc(itp->it_ts_init.ts_syt,
	    AV1394_IT_IXL_BEGIN_NPOST + av1394_it_syt_off);
	first = (itp->it_last_full + icp->ic_nframes - itp->it_nfull + 1) %
	    icp->ic_nframes;
	av1394_it_update_frame_syt(icp, first, itp->it_nfull, syt);
	mutex_exit(&icp->ic_mutex);
}

/*ARGSUSED*/
static void
av1394_it_ixl_buf_cb(opaque_t arg, struct ixl1394_callback *cb)
{
	av1394_it_ixl_buf_t	*bp = cb->callback_arg;

	if (bp->tb_flags & AV1394_IT_IXL_BUF_EOF) {
		av1394_it_ixl_eof_cb(bp);
	}
}

static void
av1394_it_ixl_eof_cb(av1394_it_ixl_buf_t *bp)
{
	av1394_ic_t	*icp = bp->tb_icp;
	av1394_isoch_t	*ip = &icp->ic_avp->av_i;
	av1394_it_t	*itp = &icp->ic_it;

	mutex_enter(&ip->i_mutex);
	mutex_enter(&icp->ic_mutex);
	if (itp->it_nempty < icp->ic_nframes) {
		itp->it_nempty++;
		itp->it_nfull--;
		cv_signal(&icp->ic_xfer_cv);
	}

	if ((itp->it_nempty >= itp->it_hiwat) &&
	    (icp->ic_state == AV1394_IC_DMA)) {
		av1394_ic_trigger_softintr(icp, icp->ic_num,
		    AV1394_PREQ_IT_UNDERRUN);
	}
	mutex_exit(&icp->ic_mutex);
	mutex_exit(&ip->i_mutex);
}

void
av1394_it_underrun(av1394_ic_t *icp)
{
	av1394_it_t		*itp = &icp->ic_it;
	av1394_inst_t		*avp = icp->ic_avp;
	int			idx;
	ixl1394_jump_t		*old_jmp;
	ixl1394_jump_t		new_jmp;
	id1394_isoch_dma_updateinfo_t update_info;
	int			err;
	int			result;

	/*
	 * update the last full frame's jump to NULL
	 */
	idx = (itp->it_first_empty + icp->ic_nframes - 1) % icp->ic_nframes;

	old_jmp = &itp->it_frame_info[idx].fi_last_buf->tb_jump;
	itp->it_saved_label = old_jmp->label;

	new_jmp.ixl_opcode = IXL1394_OP_JUMP_U;
	new_jmp.label = NULL;
	new_jmp.next_ixlp = NULL;

	update_info.orig_ixlp = (ixl1394_command_t *)old_jmp;
	update_info.temp_ixlp = (ixl1394_command_t *)&new_jmp;
	update_info.ixl_count = 1;

	mutex_exit(&icp->ic_mutex);
	err = t1394_update_isoch_dma(avp->av_t1394_hdl,
	    icp->ic_isoch_hdl, &update_info, 0, &result);
	mutex_enter(&icp->ic_mutex);

	if (err == DDI_SUCCESS) {
		itp->it_underrun_idx = idx;
		icp->ic_state = AV1394_IC_SUSPENDED;
		cv_signal(&icp->ic_xfer_cv);
	}
}

/*
 * resume from the underrun condition
 */
static int
av1394_it_underrun_resume(av1394_ic_t *icp)
{
	av1394_it_t		*itp = &icp->ic_it;
	av1394_inst_t		*avp = icp->ic_avp;
	av1394_it_ixl_buf_t	*bp;
	int			idx;
	ixl1394_jump_t		*old_jmp;
	ixl1394_jump_t		new_jmp;
	id1394_isoch_dma_updateinfo_t update_info;
	int			err;
	int			result;

	/*
	 * resuming the transfer it a lot like starting the transfer:
	 * first the IXL begin block needs to be executed, then the rest
	 * of the IXL chain. The following dynamic updates are needed:
	 *
	 *  1. update the begin block to jump to the first empty frame;
	 *  2. restore the original jump label which we previously
	 *    changed to jump to the underrun block;
	 *
	 * update #1
	 *   start by updating the begin block with a new buffer address
	 */
	idx = (itp->it_underrun_idx + 1) % icp->ic_nframes;
	bp = itp->it_frame_info[idx].fi_first_buf;
	av1394_it_ixl_begin_update_pkts(icp, bp);

	old_jmp = &itp->it_ixl_begin.be_jump;

	new_jmp.ixl_opcode = IXL1394_OP_JUMP_U;
	new_jmp.label = (ixl1394_command_t *)&bp->tb_label;
	new_jmp.next_ixlp = NULL;

	update_info.orig_ixlp = (ixl1394_command_t *)old_jmp;
	update_info.temp_ixlp = (ixl1394_command_t *)&new_jmp;
	update_info.ixl_count = 1;

	mutex_exit(&icp->ic_mutex);
	err = t1394_update_isoch_dma(avp->av_t1394_hdl,
	    icp->ic_isoch_hdl, &update_info, 0, &result);
	mutex_enter(&icp->ic_mutex);

	if (err != DDI_SUCCESS) {
		return (EIO);
	}

	/*
	 * update #2
	 */
	bp = itp->it_frame_info[itp->it_underrun_idx].fi_last_buf;
	old_jmp = &bp->tb_jump;

	new_jmp.ixl_opcode = IXL1394_OP_JUMP_U;
	new_jmp.label = itp->it_saved_label;
	new_jmp.next_ixlp = NULL;

	update_info.orig_ixlp = (ixl1394_command_t *)old_jmp;
	update_info.temp_ixlp = (ixl1394_command_t *)&new_jmp;
	update_info.ixl_count = 1;

	mutex_exit(&icp->ic_mutex);
	err = t1394_update_isoch_dma(avp->av_t1394_hdl,
	    icp->ic_isoch_hdl, &update_info, 0, &result);
	mutex_enter(&icp->ic_mutex);

	if (err != DDI_SUCCESS) {
		return (EIO);
	}

	icp->ic_state = AV1394_IC_DMA;

	return (0);
}

/*ARGSUSED*/
static void
av1394_it_dma_stopped_cb(t1394_isoch_dma_handle_t t1394_idma_hdl,
	opaque_t idma_evt_arg, id1394_isoch_dma_stopped_t status)
{
	av1394_ic_t	*icp = idma_evt_arg;

	mutex_enter(&icp->ic_mutex);
	icp->ic_state = AV1394_IC_IDLE;
	mutex_exit(&icp->ic_mutex);
}


/*
 *
 * --- data transfer routines
 *
 * av1394_it_add_frames()
 *    Add full frames to the pool.
 */
static int
av1394_it_add_frames(av1394_ic_t *icp, int idx, int cnt)
{
	av1394_it_t	*itp = &icp->ic_it;
	av1394_it_frame_info_t *fip;
	int		prev_full = itp->it_last_full;
	uint16_t	syt;
	int		ret = 0;

	/* can only add to tail */
	if (idx != ((itp->it_last_full + 1) % icp->ic_nframes)) {
		return (EINVAL);
	}

	/* turn empty frames into full ones */
	itp->it_nempty -= cnt;
	itp->it_first_empty = (itp->it_first_empty + cnt) % icp->ic_nframes;
	itp->it_nfull += cnt;
	itp->it_last_full = (itp->it_last_full + cnt) % icp->ic_nframes;
	ASSERT((itp->it_nempty >= 0) && (itp->it_nfull <= icp->ic_nframes));

	/*
	 * update frame timestamps if needed
	 */
	if (AV1394_TS_MODE_GET_SIZE(icp->ic_param.cp_ts_mode) > 0) {
		ASSERT(prev_full >= 0);
		fip = &itp->it_frame_info[prev_full];
		syt = *(uint16_t *)fip->fi_ts_off;
		syt = av1394_it_ts_syt_inc(syt, fip->fi_ncycs);
		av1394_it_update_frame_syt(icp, idx, cnt, syt);
	}

	av1394_it_dma_sync_frames(icp, idx, cnt);

	/* if suspended due to overrun, check if we can resume */
	if ((icp->ic_state == AV1394_IC_SUSPENDED) &&
	    (itp->it_nempty >= itp->it_lowat)) {
		ret = av1394_it_underrun_resume(icp);
	}

	return (ret);
}

/*
 * wait for empty frames
 */
static int
av1394_it_wait_frames(av1394_ic_t *icp, int *idx, int *cnt, int *nlost)
{
	av1394_it_t	*itp = &icp->ic_it;
	int		ret = 0;

	while ((itp->it_nempty == 0) && (icp->ic_state == AV1394_IC_DMA)) {
		if (cv_wait_sig(&icp->ic_xfer_cv, &icp->ic_mutex) <= 0) {
			ret = EINTR;
			break;
		}
	}

	if (itp->it_nempty > 0) {
		*idx = itp->it_first_empty;
		*cnt = itp->it_nempty;
		*nlost = 0;
		ret = 0;
	}
	return (ret);
}

/*
 * update frame timestamps for a range of frames
 */
static void
av1394_it_update_frame_syt(av1394_ic_t *icp, int first, int cnt, uint16_t syt)
{
	av1394_it_t	*itp = &icp->ic_it;
	int		i;
	int		j = first;	/* frame number */

	for (i = cnt; i > 0; i--) {
		*(uint16_t *)itp->it_frame_info[j].fi_ts_off = syt;
		syt = av1394_it_ts_syt_inc(syt, itp->it_frame_info[j].fi_ncycs);
		j = (j + 1) % icp->ic_nframes;
	}
}

/*
 * convert cycle timestamp into SYT timestamp:
 *
 * Cycle timer:          cycleSeconds         cycleCount     cycleOffset
 *                   31_30_29_28_27_26_25  24___15_14_13_12  11________0
 * Cycle timestamp:              |------------------------|
 * SYT timestamp:                               |----------------------|
 */
static uint16_t
av1394_it_ts_cyc2syt(uint16_t cyc)
{
	return (((cyc & 0xF) << 12) + 0x800);
}

/*
 * increment SYT by a number of cycles
 */
static uint16_t
av1394_it_ts_syt_inc(uint16_t syt, uint16_t ncycs)
{
	return (syt + (ncycs << 12));
}

/*
 * copyin from the kernel buffer
 */
static void
av1394_it_kcopyin(av1394_ic_t *icp, void *buf, size_t len)
{
	av1394_it_t	*itp = &icp->ic_it;
	av1394_isoch_seg_t *seg = itp->it_data_pool.ip_seg;

	ASSERT(itp->it_write_off + len < icp->ic_framesz);

	bcopy(buf, seg[itp->it_write_idx].is_kaddr + itp->it_write_off, len);
	itp->it_write_off += len;
}

/*
 * copyin from the user buffer
 */
static int
av1394_it_copyin(av1394_ic_t *icp, struct uio *uiop, int *full_cnt, int dv)
{
	av1394_it_t	*itp = &icp->ic_it;
	av1394_isoch_seg_t *seg = itp->it_data_pool.ip_seg;
	int		idx = itp->it_write_idx;
	int		framesz = icp->ic_framesz;
	size_t		len, frame_resid, start_resid;
	caddr_t		kaddr, kaddr_end;
	int		ret = 0;

	*full_cnt = 0;

	while ((uiop->uio_resid > 0) && (itp->it_write_cnt > 0)) {
		kaddr = seg[idx].is_kaddr + itp->it_write_off;
		frame_resid = framesz - itp->it_write_off;
		len = min(uiop->uio_resid, frame_resid);

		mutex_exit(&icp->ic_mutex);
		ret = uiomove(kaddr, len, UIO_WRITE, uiop);
		mutex_enter(&icp->ic_mutex);
		if (ret != 0) {
			break;
		}

		itp->it_write_off += len;
		if ((itp->it_write_off == framesz) && dv) {
			/*
			 * for DV formats, make sure we got a frame start.
			 * this is to ensure correct timestamping
			 */
			kaddr = seg[idx].is_kaddr;
			kaddr_end = kaddr + framesz;
			while (!av1394_it_is_dv_frame_start(kaddr)) {
				kaddr += icp->ic_pktsz;
				if (kaddr == kaddr_end) {
					break;
				}
			}
			start_resid = kaddr_end - kaddr;
			if (start_resid != framesz) {
				bcopy(kaddr, seg[idx].is_kaddr, start_resid);
				itp->it_write_off = start_resid;
			}
		}
		if (itp->it_write_off == framesz) {
			/* for DV formats, reset frame's SYT fields */
			if (dv) {
				av1394_it_reset_frame_syt(icp, idx);
			}
			itp->it_write_off = 0;
			itp->it_write_cnt--;
			idx = (idx + 1) % icp->ic_nframes;
			(*full_cnt)++;
		}
	}

	return (ret);
}

/*
 * check if a packet starts a new DV frame
 */
static boolean_t
av1394_it_is_dv_frame_start(caddr_t kaddr)
{
	uint8_t *p = (uint8_t *)kaddr + 8;
	/*
	 * in the DIF block ID data, which immediately follows CIP header,
	 * SCT, Dseq and DBN fields should be zero (Ref: IEC 61834-2, Fig. 66)
	 */
	return (((p[0] & 0xE0) == 0) && ((p[1] & 0xF0) == 0) && (p[2] == 0));
}

/*
 * reset all frame's SYT fields
 */
static void
av1394_it_reset_frame_syt(av1394_ic_t *icp, int idx)
{
	caddr_t		kaddr = icp->ic_it.it_data_pool.ip_seg[idx].is_kaddr;
	caddr_t		kaddr_end = kaddr + icp->ic_framesz;

	kaddr += 6;
	while (kaddr < kaddr_end) {
		*(uint16_t *)kaddr = 0xFFFF;
		kaddr += icp->ic_pktsz;
	}
}
