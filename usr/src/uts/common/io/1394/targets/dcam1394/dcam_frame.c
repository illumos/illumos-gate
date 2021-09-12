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

/*
 * dcam_frame.c
 *
 * dcam1394 driver.  Support for video frame access.
 */

#include <sys/int_limits.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/1394/targets/dcam1394/dcam.h>
#include <sys/1394/targets/dcam1394/dcam_frame.h>
#include <sys/dcam/dcam1394_io.h>

#include <sys/1394/targets/dcam1394/dcam_reg.h>

static void dcam_free_resources(dcam_state_t *);

typedef struct dcam_mode_info_s {
	int bytes_per_pkt;
	int pkts_per_frame;
} dcam_mode_info_t;

/*
 * packets per frame
 *
 * 30fps
 *  mode_0 1/2h, 60q,  240b
 *  mode_1 1h,  160q,  640
 *  mode_2 2h,  480q, 1920
 *  mode_3 2h,  640q, 2560
 *  mode_4 2h,  960q, 3840
 *  mode_5 2h,  320q, 1280
 *
 * 15fps
 *  mode_0 1/4h, 30q,  120
 *  mode_1 1/2h, 80q,  320
 *  mode_2 1h,  240q,  960
 *  mode_3 1h,  320q, 1280
 *  mode_4 1h,  480q, 1920
 *  mode_5 1h,  160q,  640
 *
 * 7.5fps
 *  mode_0 1/8h,  15q,  60
 *  mode_1 1/4h,  40q, 160
 *  mode_2 1/2h, 120q, 480
 *  mode_3 1/2h, 160q, 640
 *  mode_4 1/2h, 240q, 960
 *  mode_5 1/2h,  80q, 320
 *
 * 3.75fps
 *  mode_0 x
 *  mode_1 1/8h,  20q,  80
 *  mode_2 1/4h,  60q, 240
 *  mode_3 1/4h,  80q, 320
 *  mode_4 1/4h, 120q, 480
 *  mode_5 1/4h,  40q, 160
 *
 * 60fps
 *  mode_5 4H, 640q, 2560
 *
 */

/* indexed by vid mode, frame rate */
static int g_bytes_per_packet[6][5] = {

	/* fps:			3.75	7.5	15	30	60 */
	/* vid mode 0 */	-1,	60,	120,	240,	-1,
	/* vid mode 1 */	80,	160,	320,	640,	-1,
	/* vid mode 2 */	240,	480,	960,	1920,	-1,
	/* vid mode 3 */	320,	640,	1280,	2560,	-1,
	/* vid mode 4 */	480,	960,	1920,	3840,	-1,
	/* vid mode 5 */	160,	320,	640,	1280,	2560
};

/* indexed by vid mode */
static int g_bytes_per_frame[6] = {
    57600,
    153600,
    460800,
    614400,
    921600,
    307200
};


static
void dcam_rsrc_fail(t1394_isoch_single_handle_t	t1394_single_hdl,
    opaque_t single_evt_arg, t1394_isoch_rsrc_error_t fail_args);

/*
 * dcam1394_ioctl_frame_rcv_start
 */
int
dcam1394_ioctl_frame_rcv_start(dcam_state_t *softc_p)
{
	if (!(softc_p->flags & DCAM1394_FLAG_FRAME_RCV_INIT)) {

		if (dcam_frame_rcv_init(softc_p, softc_p->cur_vid_mode,
		    softc_p->cur_frame_rate, softc_p->cur_ring_buff_capacity)) {

			dcam_free_resources(softc_p);
			return (1);
		}

		softc_p->flags |= DCAM1394_FLAG_FRAME_RCV_INIT;
	}

	if (dcam_frame_rcv_start(softc_p)) {
		return (1);
	}

	return (0);
}


/*
 * dcam_frame_rcv_init
 */
int
dcam_frame_rcv_init(dcam_state_t *softc_p, int vid_mode, int frame_rate,
    int ring_buff_capacity)
{
	int16_t			bytes_per_pkt;	/* # pkt bytes + overhead */
	int			bytes_per_frame;
	size_t			frame;
	int			cookie;
	int			failure;
	id1394_isoch_dmainfo_t	isoch_args;	/* for alloc isoch call */
	ixl1394_command_t	*last_ixlp;	/* last ixl in chain, */
						/* used for appending ixls */
	ixl1394_command_t	*new_ixl_cmdp;	/* new ixl command */
	ixl1394_set_syncwait_t	*new_ixl_sswp;	/* new ixl set syncwait */
	ixl1394_xfer_pkt_t	*new_ixl_xfpp;	/* new ixl xfer packet */
	ixl1394_xfer_buf_t	*new_ixl_xfbp;	/* new ixl xfer buffer */
	ixl1394_callback_t	*new_ixl_cbp;	/* new ixl callback */
	ixl1394_jump_t		*new_ixl_jmpp;	/* new ixl jump */
	int32_t			result;		/* errno from alloc_isoch_dma */
	buff_info_t		*buff_info_p;
	dcam1394_reg_io_t	reg_io;
	uint_t			data;
	size_t			num_bytes, num_bytes_left;
	size_t			num_xfer_cmds, xfer_cmd;
	size_t			max_ixl_buff_size;
	uint64_t		ixl_buff_kaddr;
	caddr_t			ixl_buff_vaddr;

	bytes_per_pkt = g_bytes_per_packet[vid_mode][frame_rate];
	if (bytes_per_pkt == -1) {
		return (1);
	}

	bytes_per_frame = g_bytes_per_frame[vid_mode];

	if ((softc_p->ring_buff_p = ring_buff_create(softc_p,
	    (size_t)ring_buff_capacity, (size_t)bytes_per_frame)) == NULL) {
		return (1);
	}

	softc_p->ring_buff_p->read_ptr_pos[0] = 0;

	/* allocate isoch channel */
	softc_p->sii.si_channel_mask	= 0xFFFF000000000000;
	softc_p->sii.si_bandwidth	= bytes_per_pkt;
	softc_p->sii.rsrc_fail_target	= dcam_rsrc_fail;
	softc_p->sii.single_evt_arg	= softc_p;
	softc_p->sii.si_speed		= softc_p->targetinfo.current_max_speed;

	if (t1394_alloc_isoch_single(softc_p->sl_handle,
	    &softc_p->sii, 0, &softc_p->sii_output_args, &softc_p->sii_hdl,
	    &failure) != DDI_SUCCESS) {
		return (1);
	}

	/*
	 * At this point, all buffer memory has been allocated and
	 * mapped, and is tracked on a linear linked list.  Now need to
	 * build the IXL.  Done on a frame-by-frame basis.  Could
	 * theoretically have been done at the same time as the mem alloc
	 * above, but hey, no need to be so fancy here.
	 *
	 * ixl buff size is bound by SHRT_MAX and needs to
	 * be a multiple of packet size
	 */
	max_ixl_buff_size = (SHRT_MAX / bytes_per_pkt) * bytes_per_pkt;

	/* for each frame build frame's ixl list */
	for (frame = 0; frame < softc_p->ring_buff_p->num_buffs; frame++) {

		buff_info_p = &(softc_p->ring_buff_p->buff_info_array_p[frame]);

		/*
		 * if this is the 1st frame, put a IXL label at the top so a
		 * loop can be created later
		 */
		if (frame == 0) {
			new_ixl_cmdp = kmem_zalloc(
					sizeof (ixl1394_label_t), KM_SLEEP);
			softc_p->ixlp = new_ixl_cmdp;

			new_ixl_cmdp->ixl_opcode = IXL1394_OP_LABEL;

			last_ixlp = softc_p->ixlp;
		}

		/* add wait-for-sync IXL command */
		new_ixl_sswp = kmem_zalloc(
				sizeof (ixl1394_set_syncwait_t), KM_SLEEP);

		new_ixl_sswp->ixl_opcode = IXL1394_OP_SET_SYNCWAIT;

		last_ixlp->next_ixlp = (ixl1394_command_t *)new_ixl_sswp;
		last_ixlp = (ixl1394_command_t *)new_ixl_sswp;

		/* add in each dma cookie */
		for (cookie = 0; cookie < buff_info_p->dma_cookie_count;
		    cookie++) {

			num_xfer_cmds = min(bytes_per_frame,
			    buff_info_p->dma_cookie.dmac_size) /
			    max_ixl_buff_size;

			if (min(bytes_per_frame,
			    buff_info_p->dma_cookie.dmac_size) %
			    max_ixl_buff_size) {
				num_xfer_cmds++;
			}

			num_bytes_left = min(bytes_per_frame,
			    buff_info_p->dma_cookie.dmac_size);

			ixl_buff_kaddr =
			    buff_info_p->dma_cookie.dmac_laddress;

			ixl_buff_vaddr = buff_info_p->kaddr_p;

			for (xfer_cmd = 0; xfer_cmd < (num_xfer_cmds + 1);
			    xfer_cmd++) {
				num_bytes = min(num_bytes_left,
				    max_ixl_buff_size);

				if (xfer_cmd == 0) {
					new_ixl_xfpp =
					    kmem_zalloc(
						sizeof (ixl1394_xfer_pkt_t),
						KM_SLEEP);

					new_ixl_xfpp->ixl_opcode =
					    IXL1394_OP_RECV_PKT_ST;

					new_ixl_xfpp->ixl_buf._dmac_ll =
					    ixl_buff_kaddr;
					new_ixl_xfpp->size =
					    (uint16_t)bytes_per_pkt;
					new_ixl_xfpp->mem_bufp =
					    ixl_buff_vaddr;

					last_ixlp->next_ixlp =
					    (ixl1394_command_t *)new_ixl_xfpp;
					last_ixlp =
					    (ixl1394_command_t *)new_ixl_xfpp;

					num_bytes_left -= bytes_per_pkt;
					ixl_buff_kaddr += bytes_per_pkt;
					ixl_buff_vaddr += bytes_per_pkt;

					continue;
				}

				/* allocate & init an IXL transfer command. */
				new_ixl_xfbp =
				    kmem_zalloc(sizeof (ixl1394_xfer_buf_t),
					    KM_SLEEP);

				new_ixl_xfbp->ixl_opcode = IXL1394_OP_RECV_BUF;

				new_ixl_xfbp->ixl_buf._dmac_ll =
				    ixl_buff_kaddr;
				new_ixl_xfbp->size = (uint16_t)num_bytes;
				new_ixl_xfbp->pkt_size = bytes_per_pkt;
				new_ixl_xfbp->mem_bufp = ixl_buff_vaddr;

				last_ixlp->next_ixlp =
				    (ixl1394_command_t *)new_ixl_xfbp;
				last_ixlp =
				    (ixl1394_command_t *)new_ixl_xfbp;

				num_bytes_left -= num_bytes;
				ixl_buff_kaddr += num_bytes;
				ixl_buff_vaddr += num_bytes;
			}

			if (cookie > 0) {
				ddi_dma_nextcookie(buff_info_p->dma_handle,
				    &(buff_info_p->dma_cookie));
			}

		}

		/*
		 * at this point, have finished a frame.  put in a callback
		 */
		new_ixl_cbp = kmem_zalloc(
				sizeof (ixl1394_callback_t), KM_SLEEP);

		new_ixl_cbp->ixl_opcode	= IXL1394_OP_CALLBACK;

		new_ixl_cbp->callback = &dcam_frame_is_done;
		new_ixl_cbp->callback_arg = NULL;

		last_ixlp->next_ixlp = (ixl1394_command_t *)new_ixl_cbp;
		last_ixlp = (ixl1394_command_t *)new_ixl_cbp;
	}

	/*
	 * for the final touch, put an IXL jump at the end to jump to the
	 * label at the top
	 */
	new_ixl_jmpp = kmem_zalloc(sizeof (ixl1394_jump_t), KM_SLEEP);

	new_ixl_jmpp->ixl_opcode = IXL1394_OP_JUMP;

	new_ixl_jmpp->label = softc_p->ixlp;

	last_ixlp->next_ixlp = (ixl1394_command_t *)new_ixl_jmpp;

	/* don't need this, but it's neater */
	last_ixlp = (ixl1394_command_t *)new_ixl_jmpp;

	/* call fwim routine to alloc an isoch resource */
	isoch_args.ixlp		= softc_p->ixlp;
	isoch_args.channel_num	= softc_p->sii_output_args.channel_num;

	/* other misc args.  note speed doesn't matter for isoch receive */
	isoch_args.idma_options		= ID1394_LISTEN_PKT_MODE;
	isoch_args.default_tag		= 0;
	isoch_args.default_sync		= 1;
	isoch_args.global_callback_arg	= softc_p;

	/* set the ISO channel number */
	data = (softc_p->sii_output_args.channel_num & 0xF) << 28;

	/* set the ISO speed */
	data |= (softc_p->targetinfo.current_max_speed << 24);

	reg_io.offs = DCAM1394_REG_OFFS_CUR_ISO_CHANNEL;
	reg_io.val  = data;

	if (dcam_reg_write(softc_p, &reg_io)) {
		return (1);
	}

	result = 1234;

	if (t1394_alloc_isoch_dma(softc_p->sl_handle, &isoch_args, 0,
	    &softc_p->isoch_handle, &result) != DDI_SUCCESS) {
		return (1);
	}

	return (0);
}


/*
 * dcam_frame_rcv_fini
 */
int
dcam_frame_rcv_fini(dcam_state_t *softc_p)
{
	t1394_free_isoch_dma(softc_p->sl_handle, 0, &softc_p->isoch_handle);

	softc_p->isoch_handle = NULL;

	t1394_free_isoch_single(softc_p->sl_handle, &softc_p->sii_hdl, 0);

	return (0);
}


/*
 * dcam_frame_rcv_start
 */
int
dcam_frame_rcv_start(dcam_state_t *softc_p)
{
	id1394_isoch_dma_ctrlinfo_t	idma_ctrlinfo; /* currently not used */
	int32_t				result;
	dcam1394_reg_io_t		reg_io;

	if ((t1394_start_isoch_dma(softc_p->sl_handle, softc_p->isoch_handle,
	    &idma_ctrlinfo, 0, &result)) != DDI_SUCCESS) {
		return (1);
	}

	reg_io.offs = DCAM1394_REG_OFFS_ISO_EN;
	reg_io.val  = 0x80000000;

	if (dcam_reg_write(softc_p, &reg_io)) {
		return (1);
	}

	softc_p->flags |= DCAM1394_FLAG_FRAME_RCVING;

	return (0);
}


/*
 * dcam_frame_rcv_stop
 */
int
dcam_frame_rcv_stop(dcam_state_t *softc_p)
{
	dcam1394_reg_io_t reg_io;

	/* if resources have already been cleared, nothing to do */
	if (!(softc_p->flags & DCAM1394_FLAG_FRAME_RCV_INIT)) {
		return (0);
	}

	reg_io.offs = DCAM1394_REG_OFFS_ISO_EN;
	reg_io.val  = 0;

	(void) dcam_reg_write(softc_p, &reg_io);

	t1394_stop_isoch_dma(softc_p->sl_handle, softc_p->isoch_handle, 0);
	t1394_free_isoch_dma(softc_p->sl_handle, 0, &softc_p->isoch_handle);
	t1394_free_isoch_single(softc_p->sl_handle, &softc_p->sii_hdl, 0);

	dcam_free_resources(softc_p);

	return (0);
}


void
dcam_free_resources(dcam_state_t *softc_p)
{
	ixl1394_command_t *ptr;
	ixl1394_command_t *tmp;

	/*
	 *  The following fixes a memory leak.  See bug #4423667.
	 *  The original code  only released memory for the first  frame.
	 */

	/* free ixl opcode resources */
	ptr = softc_p->ixlp;

	while (ptr != NULL) {
		tmp = ptr;
		ptr = ptr->next_ixlp;

		switch (tmp->ixl_opcode) {
			case IXL1394_OP_LABEL:
				kmem_free(tmp, sizeof (ixl1394_label_t));
			break;

			case IXL1394_OP_SET_SYNCWAIT:
				kmem_free(tmp, sizeof (ixl1394_set_syncwait_t));
			break;

			case IXL1394_OP_RECV_PKT_ST:
				kmem_free(tmp, sizeof (ixl1394_xfer_pkt_t));
			break;

			case IXL1394_OP_RECV_BUF:
				kmem_free(tmp, sizeof (ixl1394_xfer_buf_t));
			break;

			case IXL1394_OP_CALLBACK:
				kmem_free(tmp, sizeof (ixl1394_callback_t));
			break;

			case IXL1394_OP_JUMP:
				kmem_free(tmp, sizeof (ixl1394_jump_t));
			break;
		}
	}

	/*
	 * free ring buff and indicate that the resources have been cleared
	 */
	ring_buff_free(softc_p, softc_p->ring_buff_p);

	softc_p->flags &= ~DCAM1394_FLAG_FRAME_RCV_INIT;
	softc_p->ixlp = NULL;
}


/*
 * dcam_frame_is_done
 *
 * This routine is called after DMA engine has stored a single received
 * frame in ring buffer position pointed to by write pointer; this
 * routine marks the frame's vid mode, timestamp, and sequence number
 *
 * Store received frame in ring buffer position pointed to by write pointer.
 * Increment write pointer.  If write pointer is pointing to the same
 * position as read pointer, increment read pointer.
 *
 * If device driver is processing a user process's read() request
 * invalidate the read() request processing operation.
 *
 */

/* ARGSUSED */
void
dcam_frame_is_done(void *ssp, ixl1394_callback_t *ixlp)
{
	dcam_state_t	*softc_p;
	int		 num_read_ptrs;
	int		 read_ptr_id;
	int		 vid_mode;
	size_t		 write_ptr_pos;
	ring_buff_t	*ring_buff_p;
	unsigned int	 seq_num;

	/*
	 * Store received frame in ring buffer position pointed to by
	 * write pointer (this routine is called after DMA engine has
	 * stored a single received frame in ring buffer position pointed
	 * to by write pointer; this routine marks the frame's vid mode,
	 * timestamp, and sequence number)
	 */

	if ((softc_p = (dcam_state_t *)ssp) == NULL) {
		return;
	}

	if ((ring_buff_p = softc_p->ring_buff_p) == NULL) {
		return;
	}

	mutex_enter(&softc_p->dcam_frame_is_done_mutex);

	write_ptr_pos = ring_buff_write_ptr_pos_get(ring_buff_p);

	/* mark vid mode */
	vid_mode =
	    softc_p->
		param_attr[DCAM1394_PARAM_VID_MODE][DCAM1394_SUBPARAM_NONE];
	ring_buff_p->buff_info_array_p[write_ptr_pos].vid_mode = vid_mode;


	/* update sequence counter overflow in param_status */
	if (softc_p->seq_count == 0xffffffff)
		softc_p->param_status |=
		    DCAM1394_STATUS_FRAME_SEQ_NUM_COUNT_OVERFLOW;


	/* mark frame's sequence number */
	ring_buff_p->buff_info_array_p[write_ptr_pos].seq_num =
	    softc_p->seq_count++;

	seq_num = ring_buff_p->buff_info_array_p[write_ptr_pos].seq_num;


	/* mark frame's timestamp */
	ring_buff_p->buff_info_array_p[write_ptr_pos].timestamp = gethrtime();


	/* increment write pointer */
	ring_buff_write_ptr_incr(ring_buff_p);

	num_read_ptrs = 1;

	for (read_ptr_id = 0; read_ptr_id < num_read_ptrs; read_ptr_id++) {

		/*
		 * if write pointer is pointing to the same position as
		 * read pointer
		 */

		if ((ring_buff_write_ptr_pos_get(ring_buff_p) ==
		    ring_buff_read_ptr_pos_get(ring_buff_p, read_ptr_id)) &&
		    (seq_num != 0)) {

			/* increment read pointer */
			ring_buff_read_ptr_incr(ring_buff_p, read_ptr_id);

			/*
			 * if device driver is processing a user
			 * process's read() request
			 */
			if (softc_p->reader_flags[read_ptr_id] &
			    DCAM1394_FLAG_READ_REQ_PROC) {

				/*
				 * invalidate the read() request processing
				 * operation
				 */
				softc_p->reader_flags[read_ptr_id] |=
				    DCAM1394_FLAG_READ_REQ_INVALID;
			}

			/* inform user app that we have lost one frame */
			softc_p->param_status |=
			    DCAM1394_STATUS_RING_BUFF_LOST_FRAME;
		}
	}

	/* inform user app that we have received one frame */
	softc_p->param_status |= DCAM1394_STATUS_FRAME_RCV_DONE;

	mutex_exit(&softc_p->dcam_frame_is_done_mutex);
}


/* ARGSUSED */
static void
dcam_rsrc_fail(t1394_isoch_single_handle_t t1394_single_hdl,
    opaque_t single_evt_arg, t1394_isoch_rsrc_error_t fail_args)
{
	cmn_err(CE_NOTE, "dcam_rsrc_fail(): unable to re-alloc resources\n");
}
