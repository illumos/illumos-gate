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
 * av1394 isochronous receive module
 */
#include <sys/1394/targets/av1394/av1394_impl.h>

/* configuration routines */
static void	av1394_ir_cleanup(av1394_ic_t *, int);
static int	av1394_ir_build_ixl(av1394_ic_t *);
static void	av1394_ir_ixl_label_init(av1394_ir_ixl_data_t *,
		ixl1394_command_t *);
static void	av1394_ir_ixl_buf_init(av1394_ic_t *, ixl1394_xfer_buf_t *,
		av1394_isoch_seg_t *, off_t, uint64_t, uint16_t,
		ixl1394_command_t *);
static void	av1394_ir_ixl_cb_init(av1394_ic_t *, av1394_ir_ixl_data_t *,
		int);
static void	av1394_ir_ixl_jump_init(av1394_ic_t *, av1394_ir_ixl_data_t *,
		int);
static void	av1394_ir_destroy_ixl(av1394_ic_t *);
static int	av1394_ir_alloc_isoch_dma(av1394_ic_t *);
static void	av1394_ir_free_isoch_dma(av1394_ic_t *);
static void	av1394_ir_dma_sync_frames(av1394_ic_t *, int, int);

/* callbacks */
static void	av1394_ir_ixl_frame_cb(opaque_t, struct ixl1394_callback *);
static void	av1394_ir_overflow_resume(av1394_ic_t *icp);
static void	av1394_ir_dma_stopped_cb(t1394_isoch_dma_handle_t,
		opaque_t, id1394_isoch_dma_stopped_t);

/* data transfer routines */
static int	av1394_ir_add_frames(av1394_ic_t *, int, int);
static int	av1394_ir_wait_frames(av1394_ic_t *, int *, int *);
static int	av1394_ir_copyout(av1394_ic_t *, struct uio *, int *);
static void	av1394_ir_zero_pkts(av1394_ic_t *, int, int);

/* value complementary to hi & lo watermarks (modulo number of frames) */
int av1394_ir_hiwat_sub = 2;
int av1394_ir_lowat_sub = 3;
int av1394_ir_dump_ixl = 0;

int
av1394_ir_init(av1394_ic_t *icp, int *error)
{
	av1394_ir_t	*irp = &icp->ic_ir;
	av1394_isoch_pool_t *pool = &irp->ir_data_pool;
	int		nframes;

	nframes = av1394_ic_alloc_pool(pool, icp->ic_framesz, icp->ic_nframes,
	    AV1394_IR_NFRAMES_MIN);
	if (nframes == 0) {
		*error = IEC61883_ERR_NOMEM;
		return (EINVAL);
	}
	mutex_enter(&icp->ic_mutex);
	icp->ic_nframes = nframes;
	irp->ir_hiwat = nframes - av1394_ir_hiwat_sub;
	irp->ir_lowat = nframes - av1394_ir_lowat_sub;

	if (av1394_ic_dma_setup(icp, pool) != DDI_SUCCESS) {
		mutex_exit(&icp->ic_mutex);
		*error = IEC61883_ERR_NOMEM;
		av1394_ir_cleanup(icp, 1);
		return (EINVAL);
	}

	if (av1394_ir_build_ixl(icp) != DDI_SUCCESS) {
		mutex_exit(&icp->ic_mutex);
		*error = IEC61883_ERR_NOMEM;
		av1394_ir_cleanup(icp, 2);
		return (EINVAL);
	}
	mutex_exit(&icp->ic_mutex);

	if (av1394_ir_alloc_isoch_dma(icp) != DDI_SUCCESS) {
		*error = IEC61883_ERR_NOMEM;
		av1394_ir_cleanup(icp, 3);
		return (EINVAL);
	}

	return (0);
}

void
av1394_ir_fini(av1394_ic_t *icp)
{
	av1394_ir_cleanup(icp, AV1394_CLEANUP_LEVEL_MAX);
}

int
av1394_ir_start(av1394_ic_t *icp)
{
	av1394_inst_t	*avp = icp->ic_avp;
	av1394_ir_t	*irp = &icp->ic_ir;
	id1394_isoch_dma_ctrlinfo_t idma_ctrlinfo = { 0 };
	int		result;
	int		err;
	int		ret = 0;

	mutex_enter(&icp->ic_mutex);
	if (icp->ic_state != AV1394_IC_IDLE) {
		mutex_exit(&icp->ic_mutex);
		return (0);
	}

	irp->ir_first_full = 0;
	irp->ir_last_empty = icp->ic_nframes - 1;
	irp->ir_nfull = 0;
	irp->ir_nempty = icp->ic_nframes;
	irp->ir_read_cnt = 0;
	mutex_exit(&icp->ic_mutex);

	err = t1394_start_isoch_dma(avp->av_t1394_hdl, icp->ic_isoch_hdl,
	    &idma_ctrlinfo, 0, &result);
	if (err == DDI_SUCCESS) {
		mutex_enter(&icp->ic_mutex);
		icp->ic_state = AV1394_IC_DMA;
		mutex_exit(&icp->ic_mutex);
	} else {
		ret = EIO;
	}

	return (ret);
}

int
av1394_ir_stop(av1394_ic_t *icp)
{
	av1394_inst_t	*avp = icp->ic_avp;

	mutex_enter(&icp->ic_mutex);
	if (icp->ic_state != AV1394_IC_IDLE) {
		mutex_exit(&icp->ic_mutex);
		t1394_stop_isoch_dma(avp->av_t1394_hdl, icp->ic_isoch_hdl, 0);
		mutex_enter(&icp->ic_mutex);
		icp->ic_state = AV1394_IC_IDLE;
	}
	mutex_exit(&icp->ic_mutex);

	return (0);
}

int
av1394_ir_recv(av1394_ic_t *icp, iec61883_recv_t *recv)
{
	int		ret = 0;
	int		idx, cnt;

	idx = recv->rx_xfer.xf_empty_idx;
	cnt = recv->rx_xfer.xf_empty_cnt;

	/* check arguments */
	if ((idx < 0) || (idx >= icp->ic_nframes) ||
	    (cnt < 0) || (cnt > icp->ic_nframes)) {
		return (EINVAL);
	}

	mutex_enter(&icp->ic_mutex);
	if (cnt > 0) {
		/* add empty frames to the pool */
		if ((ret = av1394_ir_add_frames(icp, idx, cnt)) != 0) {
			mutex_exit(&icp->ic_mutex);
			return (ret);
		}
	}

	/* wait for new frames to arrive */
	ret = av1394_ir_wait_frames(icp,
	    &recv->rx_xfer.xf_full_idx, &recv->rx_xfer.xf_full_cnt);
	mutex_exit(&icp->ic_mutex);

	return (ret);
}

int
av1394_ir_read(av1394_ic_t *icp, struct uio *uiop)
{
	av1394_ir_t	*irp = &icp->ic_ir;
	int		ret = 0;
	int		empty_cnt;

	mutex_enter(&icp->ic_mutex);
	while (uiop->uio_resid) {
		/* wait for full frames, if necessary */
		if (irp->ir_read_cnt == 0) {
			irp->ir_read_off = 0;
			ret = av1394_ir_wait_frames(icp,
			    &irp->ir_read_idx, &irp->ir_read_cnt);
			if (ret != 0) {
				mutex_exit(&icp->ic_mutex);
				return (ret);
			}
		}

		/* copyout the data */
		ret = av1394_ir_copyout(icp, uiop, &empty_cnt);

		/* return freed frames to the pool */
		if (empty_cnt > 0) {
			av1394_ir_zero_pkts(icp, irp->ir_read_idx, empty_cnt);
			ret = av1394_ir_add_frames(icp, irp->ir_read_idx,
			    empty_cnt);
			irp->ir_read_idx += empty_cnt;
			irp->ir_read_idx %= icp->ic_nframes;
			irp->ir_read_cnt -= empty_cnt;
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
av1394_ir_cleanup(av1394_ic_t *icp, int level)
{
	av1394_isoch_pool_t *pool = &icp->ic_ir.ir_data_pool;

	ASSERT((level > 0) && (level <= AV1394_CLEANUP_LEVEL_MAX));

	switch (level) {
	default:
		av1394_ir_free_isoch_dma(icp);
		/* FALLTHRU */
	case 3:
		av1394_ir_destroy_ixl(icp);
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
 * av1394_ir_build_ixl()
 *    Build an IXL chain to receive CIP data. The smallest instance of data
 *    that can be received is a packet, typically 512 bytes. Frames consist
 *    of a number of packets, typically 250-300. Packet size, frame size and
 *    number of frames allocated are set by a user process. The received data
 *    made available to the user process in full frames, hence there an IXL
 *    callback at the end of each frame. A sequence of IXL commands that
 *    receives one frame is further referred to as an IXL data block.
 *
 *    During normal operation, frames are in a circular list and IXL chain
 *    does not change. When the user process does not keep up with the
 *    data flow and there are too few empty frames left, the jump following
 *    last empty frame is dynamically updated to point to NULL -- otherwise
 *    the first full frame would be overwritten. When IXL execution reaches
 *    the nulled jump, it just waits until the driver updates it again or
 *    stops the transfer. Once a user process frees up enough frames, the
 *    jump is restored and transfer continues. User process will be able to
 *    detect dropped packets using continuity conters embedded in the data.
 *
 *    Because RECV_BUF buffer size is limited to AV1394_IXL_BUFSZ_MAX, and due
 *    to isoch pool segmentaion, the number of RECV_BUF commands per IXL data
 *    block depends on frame size. Also, to simplify calculations, we consider
 *    a sequence of RECV_BUF commands to consist of two parts: zero or more
 *    equal-sized RECV_BUF commands followed by one "tail" REC_BUF command,
 *    whose size may not be equal to others.
 *
 *    Schematically the IXL chain looks like this:
 *
 *    ...
 *    LABEL N;
 *    RECV_BUF(buf)
 *    ...
 *    RECV_BUF(tail)
 *    CALLBACK(frame done);
 *    JUMP_U(LABEL (N+1)%nframes or NULL);
 *    ...
 */
static int
av1394_ir_build_ixl(av1394_ic_t *icp)
{
	av1394_ir_t		*irp = &icp->ic_ir;
	av1394_isoch_pool_t	*pool = &irp->ir_data_pool;
	int			i;	/* segment index */
	int			j;
	int			fi;	/* frame index */
	int			bi;	/* buffer index */

	/* allocate space for IXL data blocks */
	irp->ir_ixl_data = kmem_zalloc(icp->ic_nframes *
	    sizeof (av1394_ir_ixl_data_t), KM_SLEEP);

	/*
	 * We have a bunch of segments, and each is divided into cookies.  We
	 * need to cover the segments with RECV_BUFs such that they
	 *   - don't span cookies
	 *   - don't span frames
	 *   - are at most AV1394_IXL_BUFSZ_MAX
	 *
	 * The straightforward algorithm is to start from the beginning, find
	 * the next lowest frame or cookie boundary, and either make a buf for
	 * it if it is smaller than AV1394_IXL_BUFSZ_MAX, or make multiple
	 * bufs for it as with av1394_ic_ixl_seg_decomp().  And repeat.
	 */

	irp->ir_ixl_nbufs = 0;
	for (i = 0; i < pool->ip_nsegs; ++i) {
		av1394_isoch_seg_t *isp = &pool->ip_seg[i];
		size_t dummy1, dummy2;

		uint_t off = 0;
		uint_t end;

		uint_t frame_end = icp->ic_framesz;
		int ci = 0;
		uint_t cookie_end = isp->is_dma_cookie[ci].dmac_size;

		for (;;) {
			end = min(frame_end, cookie_end);

			if (end - off <= AV1394_IXL_BUFSZ_MAX) {
				++irp->ir_ixl_nbufs;
			} else {
				irp->ir_ixl_nbufs += av1394_ic_ixl_seg_decomp(
				    end - off, icp->ic_pktsz, &dummy1, &dummy2);
				/* count the tail buffer */
				++irp->ir_ixl_nbufs;
			}

			off = end;
			if (off >= isp->is_size)
				break;

			if (off == frame_end)
				frame_end += icp->ic_framesz;
			if (off == cookie_end) {
				++ci;
				cookie_end += isp->is_dma_cookie[ci].dmac_size;
			}
		}
	}

	irp->ir_ixl_buf = kmem_zalloc(irp->ir_ixl_nbufs *
	    sizeof (ixl1394_xfer_buf_t), KM_SLEEP);


	fi = 0;
	bi = 0;

	for (i = 0; i < pool->ip_nsegs; ++i) {
		av1394_isoch_seg_t *isp = &pool->ip_seg[i];

		uint_t off = 0;		/* offset into segment */
		uint_t end;
		uint_t coff = 0;	/* offset into cookie */


		uint_t frame_end = icp->ic_framesz;
		int ci = 0;
		uint_t cookie_end = isp->is_dma_cookie[ci].dmac_size;

		ixl1394_command_t *nextp;

		av1394_ir_ixl_label_init(&irp->ir_ixl_data[fi],
		    (ixl1394_command_t *)&irp->ir_ixl_buf[bi]);

		for (;;) {
			end = min(frame_end, cookie_end);

			if (end == frame_end)
				nextp = (ixl1394_command_t *)
				    &irp->ir_ixl_data[fi].rd_cb;
			else
				nextp = (ixl1394_command_t *)
				    &irp->ir_ixl_buf[bi + 1];

			if (end - off <= AV1394_IXL_BUFSZ_MAX) {
				av1394_ir_ixl_buf_init(icp,
				    &irp->ir_ixl_buf[bi], isp, off,
				    isp->is_dma_cookie[ci].dmac_laddress + coff,
				    end - off, nextp);
				coff += end - off;
				off = end;
				++bi;
			} else {
				size_t reg, tail;
				uint_t nbufs;

				nbufs = av1394_ic_ixl_seg_decomp(end - off,
				    icp->ic_pktsz, &reg, &tail);

				for (j = 0; j < nbufs; ++j) {
					av1394_ir_ixl_buf_init(icp,
					    &irp->ir_ixl_buf[bi], isp, off,
					    isp->is_dma_cookie[ci].
					    dmac_laddress + coff, reg,
					    (ixl1394_command_t *)
					    &irp->ir_ixl_buf[bi + 1]);
					++bi;
					off += reg;
					coff += reg;
				}

				av1394_ir_ixl_buf_init(icp,
				    &irp->ir_ixl_buf[bi], isp, off,
				    isp->is_dma_cookie[ci].dmac_laddress + coff,
				    tail, nextp);
				++bi;
				off += tail;
				coff += tail;
			}

			ASSERT((off == frame_end) || (off == cookie_end));

			if (off >= isp->is_size)
				break;

			if (off == frame_end) {
				av1394_ir_ixl_cb_init(icp,
				    &irp->ir_ixl_data[fi], fi);
				av1394_ir_ixl_jump_init(icp,
				    &irp->ir_ixl_data[fi], fi);
				++fi;
				frame_end += icp->ic_framesz;
				av1394_ir_ixl_label_init(&irp->ir_ixl_data[fi],
				    (ixl1394_command_t *)&irp->ir_ixl_buf[bi]);
			}

			if (off == cookie_end) {
				++ci;
				cookie_end += isp->is_dma_cookie[ci].dmac_size;
				coff = 0;
			}
		}

		av1394_ir_ixl_cb_init(icp, &irp->ir_ixl_data[fi], fi);
		av1394_ir_ixl_jump_init(icp, &irp->ir_ixl_data[fi], fi);
		++fi;
	}

	ASSERT(fi == icp->ic_nframes);
	ASSERT(bi == irp->ir_ixl_nbufs);

	irp->ir_ixlp = (ixl1394_command_t *)irp->ir_ixl_data;

	if (av1394_ir_dump_ixl) {
		av1394_ic_ixl_dump(irp->ir_ixlp);
	}

	return (DDI_SUCCESS);
}

static void
av1394_ir_ixl_label_init(av1394_ir_ixl_data_t *dp, ixl1394_command_t *nextp)
{
	dp->rd_label.ixl_opcode = IXL1394_OP_LABEL;
	dp->rd_label.next_ixlp	= nextp;
}

static void
av1394_ir_ixl_buf_init(av1394_ic_t *icp, ixl1394_xfer_buf_t *buf,
	av1394_isoch_seg_t *isp, off_t offset, uint64_t addr, uint16_t size,
	ixl1394_command_t *nextp)
{
	buf->ixl_opcode = IXL1394_OP_RECV_BUF;
	buf->size = size;
	buf->pkt_size = icp->ic_pktsz;
	buf->ixl_buf._dmac_ll = addr;
	buf->mem_bufp = isp->is_kaddr + offset;
	buf->next_ixlp = nextp;
}

/*ARGSUSED*/
static void
av1394_ir_ixl_cb_init(av1394_ic_t *icp, av1394_ir_ixl_data_t *dp, int i)
{
	dp->rd_cb.ixl_opcode = IXL1394_OP_CALLBACK;
	dp->rd_cb.callback = av1394_ir_ixl_frame_cb;
	dp->rd_cb.callback_arg = (void *)(intptr_t)i;
	dp->rd_cb.next_ixlp = (ixl1394_command_t *)&dp->rd_jump;
}

static void
av1394_ir_ixl_jump_init(av1394_ic_t *icp, av1394_ir_ixl_data_t *dp, int i)
{
	av1394_ir_t	*irp = &icp->ic_ir;
	int		next_idx;
	ixl1394_command_t *jump_cmd;

	next_idx = (i + 1) % icp->ic_nframes;
	jump_cmd = (ixl1394_command_t *)&irp->ir_ixl_data[next_idx];

	dp->rd_jump.ixl_opcode	= IXL1394_OP_JUMP_U;
	dp->rd_jump.label = jump_cmd;
	dp->rd_jump.next_ixlp = (next_idx != 0) ? jump_cmd : NULL;
}

static void
av1394_ir_destroy_ixl(av1394_ic_t *icp)
{
	av1394_ir_t		*irp = &icp->ic_ir;

	mutex_enter(&icp->ic_mutex);
	kmem_free(irp->ir_ixl_buf,
	    irp->ir_ixl_nbufs * sizeof (ixl1394_xfer_buf_t));
	kmem_free(irp->ir_ixl_data,
	    icp->ic_nframes * sizeof (av1394_ir_ixl_data_t));

	irp->ir_ixlp = NULL;
	irp->ir_ixl_buf = NULL;
	irp->ir_ixl_data = NULL;
	mutex_exit(&icp->ic_mutex);
}

static int
av1394_ir_alloc_isoch_dma(av1394_ic_t *icp)
{
	av1394_inst_t		*avp = icp->ic_avp;
	av1394_ir_t		*irp = &icp->ic_ir;
	id1394_isoch_dmainfo_t	di;
	int			result;
	int			ret;

	di.ixlp = irp->ir_ixlp;
	di.channel_num = icp->ic_num;
	di.global_callback_arg = icp;
	di.idma_options = ID1394_LISTEN_PKT_MODE;
	di.isoch_dma_stopped = av1394_ir_dma_stopped_cb;
	di.idma_evt_arg = icp;

	ret = t1394_alloc_isoch_dma(avp->av_t1394_hdl, &di, 0,
	    &icp->ic_isoch_hdl, &result);

	return (ret);
}

static void
av1394_ir_free_isoch_dma(av1394_ic_t *icp)
{
	av1394_inst_t		*avp = icp->ic_avp;

	t1394_free_isoch_dma(avp->av_t1394_hdl, 0, &icp->ic_isoch_hdl);
}

static void
av1394_ir_dma_sync_frames(av1394_ic_t *icp, int idx, int cnt)
{
	av1394_ic_dma_sync_frames(icp, idx, cnt,
	    &icp->ic_ir.ir_data_pool, DDI_DMA_SYNC_FORCPU);
}

/*
 *
 * --- callbacks
 *
 */
/*ARGSUSED*/
static void
av1394_ir_ixl_frame_cb(opaque_t arg, struct ixl1394_callback *cb)
{
	av1394_ic_t	*icp = arg;
	av1394_isoch_t	*ip = &icp->ic_avp->av_i;
	av1394_ir_t	*irp = &icp->ic_ir;

	mutex_enter(&ip->i_mutex);
	mutex_enter(&icp->ic_mutex);
	if (irp->ir_nfull < icp->ic_nframes) {
		irp->ir_nfull++;
		irp->ir_nempty--;
		cv_broadcast(&icp->ic_xfer_cv);

		/*
		 * signal the overflow condition early, so we get enough
		 * time to handle it before old data is overwritten
		 */
		if (irp->ir_nfull >= irp->ir_hiwat) {
			av1394_ic_trigger_softintr(icp, icp->ic_num,
			    AV1394_PREQ_IR_OVERFLOW);
		}
	}
	mutex_exit(&icp->ic_mutex);
	mutex_exit(&ip->i_mutex);
}

/*
 * received data overflow
 */
void
av1394_ir_overflow(av1394_ic_t *icp)
{
	av1394_inst_t	*avp = icp->ic_avp;
	av1394_ir_t	*irp = &icp->ic_ir;
	int		idx;
	ixl1394_jump_t	*old_jmp;
	ixl1394_jump_t	new_jmp;
	id1394_isoch_dma_updateinfo_t update_info;
	int		err;
	int		result;

	/*
	 * in the circular IXL chain overflow means overwriting the least
	 * recent data. to avoid that, we suspend the transfer by NULL'ing
	 * the last IXL block until the user process frees up some frames.
	 */
	idx = irp->ir_last_empty;

	old_jmp = &irp->ir_ixl_data[idx].rd_jump;

	new_jmp.ixl_opcode = IXL1394_OP_JUMP_U;
	new_jmp.label = NULL;
	new_jmp.next_ixlp = NULL;

	update_info.orig_ixlp = (ixl1394_command_t *)old_jmp;
	update_info.temp_ixlp = (ixl1394_command_t *)&new_jmp;
	update_info.ixl_count = 1;

	mutex_exit(&icp->ic_mutex);
	err = t1394_update_isoch_dma(avp->av_t1394_hdl, icp->ic_isoch_hdl,
	    &update_info, 0, &result);
	mutex_enter(&icp->ic_mutex);

	if (err == DDI_SUCCESS) {
		irp->ir_overflow_idx = idx;
		icp->ic_state = AV1394_IC_SUSPENDED;
	}
}

/*
 * restore from overflow condition
 */
static void
av1394_ir_overflow_resume(av1394_ic_t *icp)
{
	av1394_inst_t	*avp = icp->ic_avp;
	av1394_ir_t	*irp = &icp->ic_ir;
	int		idx, next_idx;
	ixl1394_jump_t	*old_jmp;
	ixl1394_jump_t	new_jmp;
	id1394_isoch_dma_updateinfo_t update_info;
	int		err;
	int		result;

	/*
	 * restore the jump command we NULL'ed in av1394_ir_overflow()
	 */
	idx = irp->ir_overflow_idx;
	next_idx = (idx + 1) % icp->ic_nframes;

	old_jmp = &irp->ir_ixl_data[idx].rd_jump;

	new_jmp.ixl_opcode = IXL1394_OP_JUMP_U;
	new_jmp.label = (ixl1394_command_t *)&irp->ir_ixl_data[next_idx];
	new_jmp.next_ixlp = NULL;

	update_info.orig_ixlp = (ixl1394_command_t *)old_jmp;
	update_info.temp_ixlp = (ixl1394_command_t *)&new_jmp;
	update_info.ixl_count = 1;

	mutex_exit(&icp->ic_mutex);
	err = t1394_update_isoch_dma(avp->av_t1394_hdl,
	    icp->ic_isoch_hdl, &update_info, 0, &result);
	mutex_enter(&icp->ic_mutex);

	if (err == DDI_SUCCESS) {
		icp->ic_state = AV1394_IC_DMA;
	}
}

/*ARGSUSED*/
static void
av1394_ir_dma_stopped_cb(t1394_isoch_dma_handle_t t1394_idma_hdl,
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
 * av1394_ir_add_frames()
 *    Add empty frames to the pool.
 */
static int
av1394_ir_add_frames(av1394_ic_t *icp, int idx, int cnt)
{
	av1394_ir_t	*irp = &icp->ic_ir;

	/* can only add to the tail */
	if (idx != ((irp->ir_last_empty + 1) % icp->ic_nframes)) {
		return (EINVAL);
	}

	/* turn full frames into empty ones */
	irp->ir_nfull -= cnt;
	irp->ir_first_full = (irp->ir_first_full + cnt) % icp->ic_nframes;
	irp->ir_nempty += cnt;
	irp->ir_last_empty = (irp->ir_last_empty + cnt) % icp->ic_nframes;
	ASSERT((irp->ir_nfull >= 0) && (irp->ir_nempty <= icp->ic_nframes));

	/* if suspended due to overflow, check if iwe can resume */
	if ((icp->ic_state == AV1394_IC_SUSPENDED) &&
	    (irp->ir_nempty >= irp->ir_lowat)) {
		av1394_ir_overflow_resume(icp);
	}

	return (0);
}

static int
av1394_ir_wait_frames(av1394_ic_t *icp, int *idx, int *cnt)
{
	av1394_ir_t	*irp = &icp->ic_ir;
	int		ret = 0;

	while (irp->ir_nfull == 0) {
		if (cv_wait_sig(&icp->ic_xfer_cv, &icp->ic_mutex) <= 0) {
			ret = EINTR;
			break;
		}
	}
	if (irp->ir_nfull > 0) {
		*idx = irp->ir_first_full;
		*cnt = irp->ir_nfull;
		av1394_ir_dma_sync_frames(icp, *idx, *cnt);
		ret = 0;
	}
	return (ret);
}

/*
 * copyout the data, adjust to data format and remove empty CIPs if possible
 */
static int
av1394_ir_copyout(av1394_ic_t *icp, struct uio *uiop, int *empty_cnt)
{
	av1394_ir_t	*irp = &icp->ic_ir;
	av1394_isoch_seg_t *seg = irp->ir_data_pool.ip_seg;
	int		idx = irp->ir_read_idx;
	int		cnt = irp->ir_read_cnt;
	int		pktsz = icp->ic_pktsz;
	int		bs;		/* data block size */
	caddr_t		kaddr_begin, kaddr;
	int		pkt_off;	/* offset into current packet */
	int		len;
	int		frame_resid;	/* bytes left in the current frame */
	int		ret = 0;

	*empty_cnt = 0;

	/* DBS -> block size */
	bs = *(uchar_t *)(seg[idx].is_kaddr + 1) * 4 + AV1394_CIPSZ;
	if ((bs > pktsz) || (bs < AV1394_CIPSZ + 8)) {
		bs = pktsz;
	}

	while ((cnt > 0) && (uiop->uio_resid > 0) && (ret == 0)) {
		kaddr = kaddr_begin = seg[idx].is_kaddr + irp->ir_read_off;
		frame_resid = icp->ic_framesz - irp->ir_read_off;

		mutex_exit(&icp->ic_mutex);
		/* copyout data blocks, skipping empty CIPs */
		while ((uiop->uio_resid > 0) && (frame_resid > 0)) {
			pkt_off = (uintptr_t)kaddr % pktsz;
			/*
			 * a quadlet following CIP header can't be zero
			 * unless in an empty packet
			 */
			if ((pkt_off == 0) &&
			    (*(uint32_t *)(kaddr + AV1394_CIPSZ) == 0)) {
				kaddr += pktsz;
				frame_resid -= pktsz;
				continue;
			}

			len = bs - pkt_off;
			if (len > uiop->uio_resid) {
				len = uiop->uio_resid;
			}
			if (len > frame_resid) {
				len = frame_resid;
			}
			if ((ret = uiomove(kaddr, len, UIO_READ, uiop)) != 0) {
				break;
			}

			if (pkt_off + len == bs) {
				kaddr += pktsz - pkt_off;
				frame_resid -= pktsz - pkt_off;
			} else {
				kaddr += len;
				frame_resid -= len;
			}
		}
		mutex_enter(&icp->ic_mutex);

		if (frame_resid > 0) {
			irp->ir_read_off = kaddr - kaddr_begin;
		} else {
			irp->ir_read_off = 0;
			idx = (idx + 1) % icp->ic_nframes;
			cnt--;
			(*empty_cnt)++;
		}
	}

	return (ret);
}

/*
 * zero a quadlet in each packet so we can recognize empty CIPs
 */
static void
av1394_ir_zero_pkts(av1394_ic_t *icp, int idx, int cnt)
{
	av1394_ir_t	*irp = &icp->ic_ir;
	av1394_isoch_seg_t *seg = irp->ir_data_pool.ip_seg;
	caddr_t		kaddr, kaddr_end;
	int		pktsz = icp->ic_pktsz;
	int		i;

	for (i = cnt; i > 0; i--) {
		kaddr = seg[idx].is_kaddr + AV1394_CIPSZ;
		kaddr_end = seg[idx].is_kaddr + icp->ic_framesz;
		do {
			*(uint32_t *)kaddr = 0;
			kaddr += pktsz;
		} while (kaddr < kaddr_end);

		idx = (idx + 1) % icp->ic_nframes;
	}
}
