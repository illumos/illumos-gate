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

/* Copyright 2015 QLogic Corporation */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver source file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2015 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#include <ql_apps.h>
#include <ql_api.h>
#include <ql_debug.h>
#include <ql_iocb.h>
#include <ql_isr.h>
#include <ql_nx.h>
#include <ql_xioctl.h>
#include <ql_fm.h>


/*
 * Local Function Prototypes.
 */
static int ql_req_pkt(ql_adapter_state_t *, ql_request_q_t *, request_t **);
static void ql_isp_cmd(ql_adapter_state_t *, ql_request_q_t *);
static void ql_continuation_iocb(ql_adapter_state_t *, ql_request_q_t *,
    ddi_dma_cookie_t *, uint16_t, boolean_t);
static void ql_isp24xx_rcvbuf(ql_adapter_state_t *);
static void ql_cmd_24xx_type_6_iocb(ql_adapter_state_t *, ql_request_q_t *,
    ql_srb_t *, void *);

/*
 * ql_start_iocb
 *	The start IOCB is responsible for building request packets
 *	on request ring and modifying ISP input pointer.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	sp:	srb structure pointer.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_start_iocb(ql_adapter_state_t *vha, ql_srb_t *sp)
{
	ql_link_t		*link;
	ql_request_q_t		*req_q;
	request_t		*pkt;
	uint64_t		*ptr64;
	uint32_t		cnt;
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(ha, "started\n");

	/* Acquire ring lock. */
	REQUEST_RING_LOCK(ha);

	if (sp != NULL) {
		/*
		 * If the pending queue is not empty maintain order
		 * by puting this srb at the tail and geting the head.
		 */
		if ((link = ha->pending_cmds.first) != NULL) {
			ql_add_link_b(&ha->pending_cmds, &sp->cmd);
			/* Remove command from pending command queue */
			sp = link->base_address;
			ql_remove_link(&ha->pending_cmds, &sp->cmd);
		}
	} else {
		/* Get command from pending command queue if not empty. */
		if ((link = ha->pending_cmds.first) == NULL) {
			/* Release ring specific lock */
			REQUEST_RING_UNLOCK(ha);
			QL_PRINT_3(ha, "empty done\n");
			return;
		}
		/* Remove command from pending command queue */
		sp = link->base_address;
		ql_remove_link(&ha->pending_cmds, &sp->cmd);
	}

	/* start this request and as many others as possible */
	for (;;) {
		if (ha->req_q[1] != NULL && sp->rsp_q_number != 0) {
			req_q = ha->req_q[1];
		} else {
			req_q = ha->req_q[0];
		}

		if (req_q->req_q_cnt < sp->req_cnt) {
			/* Calculate number of free request entries. */
			if (ha->flags & QUEUE_SHADOW_PTRS) {
				(void) ddi_dma_sync(req_q->req_ring.dma_handle,
				    (off_t)req_q->req_out_shadow_ofst,
				    SHADOW_ENTRY_SIZE, DDI_DMA_SYNC_FORCPU);
				cnt = ddi_get32(req_q->req_ring.acc_handle,
				    req_q->req_out_shadow_ptr);
			} else if (ha->flags & MULTI_QUEUE) {
				cnt = RD16_MBAR_REG(ha, req_q->mbar_req_out);
			} else {
				cnt = RD16_IO_REG(ha, req_out);
			}
			if (req_q->req_ring_index < cnt) {
				req_q->req_q_cnt = (uint16_t)
				    (cnt - req_q->req_ring_index);
			} else {
				req_q->req_q_cnt =
				    (uint16_t)(req_q->req_entry_cnt -
				    (req_q->req_ring_index - cnt));
			}
			if (req_q->req_q_cnt != 0) {
				req_q->req_q_cnt--;
			}

			/*
			 * If no room in request ring put this srb at
			 * the head of the pending queue and exit.
			 */
			if (req_q->req_q_cnt < sp->req_cnt) {
				QL_PRINT_8(ha, "request ring full,"
				    " req_q_cnt=%d, req_ring_index=%d\n",
				    req_q->req_q_cnt, req_q->req_ring_index);
				ql_add_link_t(&ha->pending_cmds, &sp->cmd);
				break;
			}
		}

		/* Check for room in outstanding command list. */
		for (cnt = 1; cnt < ha->osc_max_cnt; cnt++) {
			ha->osc_index++;
			if (ha->osc_index == ha->osc_max_cnt) {
				ha->osc_index = 1;
			}
			if (ha->outstanding_cmds[ha->osc_index] == NULL) {
				break;
			}
		}
		/*
		 * If no room in outstanding array put this srb at
		 * the head of the pending queue and exit.
		 */
		if (cnt == ha->osc_max_cnt) {
			QL_PRINT_8(ha, "no room in outstanding array\n");
			ql_add_link_t(&ha->pending_cmds, &sp->cmd);
			break;
		}

		/* nothing to stop us now. */
		ha->outstanding_cmds[ha->osc_index] = sp;
		/* create and save a unique response identifier in the srb */
		sp->handle = ha->adapter_stats->ncmds << OSC_INDEX_SHIFT |
		    ha->osc_index;
		req_q->req_q_cnt = (uint16_t)(req_q->req_q_cnt - sp->req_cnt);

		/* build the iocb in the request ring */
		pkt = req_q->req_ring_ptr;
		sp->request_ring_ptr = pkt;
		sp->req_q_number = req_q->req_q_number;
		sp->flags |= SRB_IN_TOKEN_ARRAY;

		/* Zero out packet. */
		ptr64 = (uint64_t *)pkt;
		*ptr64++ = 0; *ptr64++ = 0;
		*ptr64++ = 0; *ptr64++ = 0;
		*ptr64++ = 0; *ptr64++ = 0;
		*ptr64++ = 0; *ptr64 = 0;

		/* Setup IOCB common data. */
		pkt->entry_count = (uint8_t)sp->req_cnt;
		if (ha->req_q[1] != NULL && sp->rsp_q_number != 0) {
			pkt->entry_status = sp->rsp_q_number;
		}
		pkt->sys_define = (uint8_t)req_q->req_ring_index;

		/* mark the iocb with the response identifier */
		ddi_put32(req_q->req_ring.acc_handle, &pkt->handle,
		    (uint32_t)sp->handle);

		/* Setup IOCB unique data. */
		(sp->iocb)(vha, req_q, sp, pkt);

		sp->flags |= SRB_ISP_STARTED;

		QL_PRINT_5(ha, "req packet, sp=%p\n", (void *)sp);
		QL_DUMP_5((uint8_t *)pkt, 8, REQUEST_ENTRY_SIZE);

		/* Sync DMA buffer. */
		(void) ddi_dma_sync(req_q->req_ring.dma_handle,
		    (off_t)(req_q->req_ring_index * REQUEST_ENTRY_SIZE),
		    (size_t)REQUEST_ENTRY_SIZE, DDI_DMA_SYNC_FORDEV);

		/* Adjust ring index. */
		req_q->req_ring_index++;
		if (req_q->req_ring_index == REQUEST_ENTRY_CNT) {
			req_q->req_ring_index = 0;
			req_q->req_ring_ptr = req_q->req_ring.bp;
		} else {
			req_q->req_ring_ptr++;
		}

		/* Reset watchdog timer */
		sp->wdg_q_time = sp->init_wdg_q_time;

		/*
		 * Send it by setting the new ring index in the ISP Request
		 * Ring In Pointer register.  This is the mechanism
		 * used to notify the isp that a new iocb has been
		 * placed on the request ring.
		 */
		if (ha->flags & MULTI_QUEUE) {
			WR16_MBAR_REG(ha, req_q->mbar_req_in,
			    req_q->req_ring_index);
		} else if (CFG_IST(ha, CFG_CTRL_82XX)) {
			ql_8021_wr_req_in(ha, req_q->req_ring_index);
		} else {
			WRT16_IO_REG(ha, req_in, req_q->req_ring_index);
		}

		/* Update outstanding command count statistic. */
		ha->adapter_stats->ncmds++;

		/* if there is a pending command, try to start it. */
		if ((link = ha->pending_cmds.first) == NULL) {
			break;
		}

		/* Remove command from pending command queue */
		sp = link->base_address;
		ql_remove_link(&ha->pending_cmds, &sp->cmd);
	}

	if (qlc_fm_check_acc_handle(ha, ha->dev_handle)
	    != DDI_FM_OK) {
		qlc_fm_report_err_impact(ha,
		    QL_FM_EREPORT_ACC_HANDLE_CHECK);
	}

	/* Release ring specific lock */
	REQUEST_RING_UNLOCK(ha);

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_req_pkt
 *	Function is responsible for locking ring and
 *	getting a zeroed out request packet.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	req_q:	request queue structure pointer.
 *	pkt:	address for packet pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static int
ql_req_pkt(ql_adapter_state_t *vha, ql_request_q_t *req_q, request_t **pktp)
{
	uint16_t		cnt;
	uint64_t		*ptr64;
	uint32_t		timer;
	int			rval = QL_FUNCTION_TIMEOUT;
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(ha, "started\n");

	/* Wait for 30 seconds for slot. */
	for (timer = 30000; timer != 0; timer--) {
		/* Acquire ring lock. */
		REQUEST_RING_LOCK(ha);

		if (req_q->req_q_cnt == 0) {
			/* Calculate number of free request entries. */
			if (ha->flags & QUEUE_SHADOW_PTRS) {
				(void) ddi_dma_sync(req_q->req_ring.dma_handle,
				    (off_t)req_q->req_out_shadow_ofst,
				    SHADOW_ENTRY_SIZE, DDI_DMA_SYNC_FORCPU);
				cnt = ddi_get32(req_q->req_ring.acc_handle,
				    req_q->req_out_shadow_ptr);
			} else if (ha->flags & MULTI_QUEUE) {
				cnt = RD16_MBAR_REG(ha, req_q->mbar_req_out);
			} else {
				cnt = RD16_IO_REG(ha, req_out);
			}
			if (req_q->req_ring_index < cnt) {
				req_q->req_q_cnt = (uint16_t)
				    (cnt - req_q->req_ring_index);
			} else {
				req_q->req_q_cnt = (uint16_t)
				    (REQUEST_ENTRY_CNT -
				    (req_q->req_ring_index - cnt));
			}
			if (req_q->req_q_cnt != 0) {
				req_q->req_q_cnt--;
			}
		}

		/* Found empty request ring slot? */
		if (req_q->req_q_cnt != 0) {
			req_q->req_q_cnt--;
			*pktp = req_q->req_ring_ptr;

			/* Zero out packet. */
			ptr64 = (uint64_t *)req_q->req_ring_ptr;
			*ptr64++ = 0; *ptr64++ = 0;
			*ptr64++ = 0; *ptr64++ = 0;
			*ptr64++ = 0; *ptr64++ = 0;
			*ptr64++ = 0; *ptr64 = 0;

			/* Setup IOCB common data. */
			req_q->req_ring_ptr->entry_count = 1;
			req_q->req_ring_ptr->sys_define =
			    (uint8_t)req_q->req_ring_index;
			ddi_put32(req_q->req_ring.acc_handle,
			    &req_q->req_ring_ptr->handle,
			    (uint32_t)QL_FCA_BRAND);

			rval = QL_SUCCESS;

			break;
		}

		/* Release request queue lock. */
		REQUEST_RING_UNLOCK(ha);

		drv_usecwait(MILLISEC);

		/* Check for pending interrupts. */
		/*
		 * XXX protect interrupt routine from calling itself.
		 * Need to revisit this routine. So far we never
		 * hit this case as req slot was available
		 */
		if ((!(curthread->t_flag & T_INTR_THREAD)) &&
		    INTERRUPT_PENDING(ha)) {
			(void) ql_isr((caddr_t)ha);
			INTR_LOCK(ha);
			ha->intr_claimed = TRUE;
			INTR_UNLOCK(ha);
		}
	}

	if (rval != QL_SUCCESS) {
		ql_awaken_task_daemon(ha, NULL, ISP_ABORT_NEEDED, 0);
		EL(ha, "failed, rval = %xh, isp_abort_needed\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_isp_cmd
 *	Function is responsible for modifying ISP input pointer.
 *	This action notifies the isp that a new request has been
 *	added to the request ring.
 *
 *	Releases ring lock.
 *
 * Input:
 *	vha:	adapter state pointer.
 *	req_q:	request queue structure pointer.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_isp_cmd(ql_adapter_state_t *vha, ql_request_q_t *req_q)
{
	ql_adapter_state_t	*ha = vha->pha;

	QL_PRINT_3(ha, "started\n");

	QL_PRINT_5(ha, "req packet:\n");
	QL_DUMP_5((uint8_t *)req_q->req_ring_ptr, 8, REQUEST_ENTRY_SIZE);

	/* Sync DMA buffer. */
	(void) ddi_dma_sync(req_q->req_ring.dma_handle,
	    (off_t)(req_q->req_ring_index * REQUEST_ENTRY_SIZE),
	    (size_t)REQUEST_ENTRY_SIZE, DDI_DMA_SYNC_FORDEV);

	/* Adjust ring index. */
	req_q->req_ring_index++;
	if (req_q->req_ring_index == REQUEST_ENTRY_CNT) {
		req_q->req_ring_index = 0;
		req_q->req_ring_ptr = req_q->req_ring.bp;
	} else {
		req_q->req_ring_ptr++;
	}

	/* Set chip new ring index. */
	if (ha->flags & MULTI_QUEUE) {
		WR16_MBAR_REG(ha, req_q->mbar_req_in,
		    req_q->req_ring_index);
	} else if (CFG_IST(ha, CFG_CTRL_82XX)) {
		ql_8021_wr_req_in(ha, req_q->req_ring_index);
	} else {
		WRT16_IO_REG(ha, req_in, req_q->req_ring_index);
	}

	/* Release ring lock. */
	REQUEST_RING_UNLOCK(ha);

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_command_iocb
 *	Setup of command IOCB.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	req_q:	request queue structure pointer.
 *	sp:	srb structure pointer.
 *	arg:	request queue packet.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_command_iocb(ql_adapter_state_t *ha, ql_request_q_t *req_q, ql_srb_t *sp,
    void *arg)
{
	ddi_dma_cookie_t	*cp;
	uint32_t		*ptr32, cnt;
	uint16_t		seg_cnt;
	fcp_cmd_t		*fcp = sp->fcp;
	ql_tgt_t		*tq = sp->lun_queue->target_queue;
	cmd_entry_t		*pkt = arg;
	cmd_3_entry_t		*pkt3 = arg;

	QL_PRINT_3(ha, "started\n");

	/* Set LUN number */
	pkt->lun_l = LSB(sp->lun_queue->lun_no);
	pkt->lun_h = MSB(sp->lun_queue->lun_no);

	/* Set target ID */
	if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
		pkt->target_l = LSB(tq->loop_id);
		pkt->target_h = MSB(tq->loop_id);
	} else {
		pkt->target_h = LSB(tq->loop_id);
	}

	/* Set tag queue control flags */
	if (fcp->fcp_cntl.cntl_qtype == FCP_QTYPE_HEAD_OF_Q) {
		pkt->control_flags_l = (uint8_t)
		    (pkt->control_flags_l | CF_HTAG);
	} else if (fcp->fcp_cntl.cntl_qtype == FCP_QTYPE_ORDERED) {
		pkt->control_flags_l = (uint8_t)
		    (pkt->control_flags_l | CF_OTAG);
	/* else if (fcp->fcp_cntl.cntl_qtype == FCP_QTYPE_SIMPLE) */
	} else {
		pkt->control_flags_l = (uint8_t)
		    (pkt->control_flags_l | CF_STAG);
	}

	/* Set ISP command timeout. */
	ddi_put16(req_q->req_ring.acc_handle, &pkt->timeout, sp->isp_timeout);

	/* Load SCSI CDB */
	ddi_rep_put8(req_q->req_ring.acc_handle, fcp->fcp_cdb,
	    pkt->scsi_cdb, MAX_CMDSZ, DDI_DEV_AUTOINCR);

	if (fcp->fcp_data_len == 0) {
		QL_PRINT_3(ha, "done\n");
		pkt->entry_type = IOCB_CMD_TYPE_2;
		ha->xioctl->IOControlRequests++;
		return;
	}

	/*
	 * Set transfer direction. Load Data segments.
	 */
	if (fcp->fcp_cntl.cntl_write_data) {
		pkt->control_flags_l = (uint8_t)
		    (pkt->control_flags_l | CF_DATA_OUT);
		ha->xioctl->IOOutputRequests++;
		ha->xioctl->IOOutputByteCnt += fcp->fcp_data_len;
	} else if (fcp->fcp_cntl.cntl_read_data) {
		pkt->control_flags_l = (uint8_t)
		    (pkt->control_flags_l | CF_DATA_IN);
		ha->xioctl->IOInputRequests++;
		ha->xioctl->IOInputByteCnt += fcp->fcp_data_len;
	}

	/* Set data segment count. */
	seg_cnt = (uint16_t)sp->pkt->pkt_data_cookie_cnt;
	ddi_put16(req_q->req_ring.acc_handle, &pkt->dseg_count, seg_cnt);

	/* Load total byte count. */
	ddi_put32(req_q->req_ring.acc_handle, &pkt->byte_count,
	    fcp->fcp_data_len);

	/* Load command data segment. */
	cp = sp->pkt->pkt_data_cookie;

	if (CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)) {
		pkt3->entry_type = IOCB_CMD_TYPE_3;
		cnt = CMD_TYPE_3_DATA_SEGMENTS;

		ptr32 = (uint32_t *)&pkt3->dseg;
		while (cnt && seg_cnt) {
			ddi_put32(req_q->req_ring.acc_handle, ptr32++,
			    cp->dmac_address);
			ddi_put32(req_q->req_ring.acc_handle, ptr32++,
			    cp->dmac_notused);
			ddi_put32(req_q->req_ring.acc_handle, ptr32++,
			    (uint32_t)cp->dmac_size);
			seg_cnt--;
			cnt--;
			cp++;
		}
	} else {
		pkt->entry_type = IOCB_CMD_TYPE_2;
		cnt = CMD_TYPE_2_DATA_SEGMENTS;

		ptr32 = (uint32_t *)&pkt->dseg;
		while (cnt && seg_cnt) {
			ddi_put32(req_q->req_ring.acc_handle, ptr32++,
			    cp->dmac_address);
			ddi_put32(req_q->req_ring.acc_handle, ptr32++,
			    (uint32_t)cp->dmac_size);
			seg_cnt--;
			cnt--;
			cp++;
		}
	}

	/*
	 * Build continuation packets.
	 */
	if (seg_cnt) {
		ql_continuation_iocb(ha, req_q, cp, seg_cnt,
		    (boolean_t)(CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)));
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_continuation_iocb
 *	Setup of continuation IOCB.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	req_q:		request queue structure pointer.
 *	cp:		cookie list pointer.
 *	seg_cnt:	number of segments.
 *	addr64:		64 bit addresses.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_continuation_iocb(ql_adapter_state_t *ha, ql_request_q_t *req_q,
    ddi_dma_cookie_t *cp, uint16_t seg_cnt, boolean_t addr64)
{
	cont_entry_t		*pkt;
	cont_type_1_entry_t	*pkt1;
	uint64_t		*ptr64;
	uint32_t		*ptr32, cnt;

	QL_PRINT_3(ha, "started\n");

	/*
	 * Build continuation packets.
	 */
	while (seg_cnt) {
		/* Sync DMA buffer. */
		(void) ddi_dma_sync(req_q->req_ring.dma_handle,
		    (off_t)(req_q->req_ring_index * REQUEST_ENTRY_SIZE),
		    REQUEST_ENTRY_SIZE, DDI_DMA_SYNC_FORDEV);

		/* Adjust ring pointer, and deal with wrap. */
		req_q->req_ring_index++;
		if (req_q->req_ring_index == REQUEST_ENTRY_CNT) {
			req_q->req_ring_index = 0;
			req_q->req_ring_ptr = req_q->req_ring.bp;
		} else {
			req_q->req_ring_ptr++;
		}
		pkt = (cont_entry_t *)req_q->req_ring_ptr;
		pkt1 = (cont_type_1_entry_t *)req_q->req_ring_ptr;

		/* Zero out packet. */
		ptr64 = (uint64_t *)pkt;
		*ptr64++ = 0; *ptr64++ = 0;
		*ptr64++ = 0; *ptr64++ = 0;
		*ptr64++ = 0; *ptr64++ = 0;
		*ptr64++ = 0; *ptr64 = 0;

		/*
		 * Build continuation packet.
		 */
		pkt->entry_count = 1;
		pkt->sys_define = (uint8_t)req_q->req_ring_index;
		if (addr64) {
			pkt1->entry_type = CONTINUATION_TYPE_1;
			cnt = CONT_TYPE_1_DATA_SEGMENTS;
			ptr32 = (uint32_t *)&pkt1->dseg;
			while (cnt && seg_cnt) {
				ddi_put32(req_q->req_ring.acc_handle, ptr32++,
				    cp->dmac_address);
				ddi_put32(req_q->req_ring.acc_handle, ptr32++,
				    cp->dmac_notused);
				ddi_put32(req_q->req_ring.acc_handle, ptr32++,
				    (uint32_t)cp->dmac_size);
				seg_cnt--;
				cnt--;
				cp++;
			}
		} else {
			pkt->entry_type = CONTINUATION_TYPE_0;
			cnt = CONT_TYPE_0_DATA_SEGMENTS;
			ptr32 = (uint32_t *)&pkt->dseg;
			while (cnt && seg_cnt) {
				ddi_put32(req_q->req_ring.acc_handle, ptr32++,
				    cp->dmac_address);
				ddi_put32(req_q->req_ring.acc_handle, ptr32++,
				    (uint32_t)cp->dmac_size);
				seg_cnt--;
				cnt--;
				cp++;
			}
		}

		QL_PRINT_5(ha, "packet:\n");
		QL_DUMP_5((uint8_t *)pkt, 8, REQUEST_ENTRY_SIZE);
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_command_24xx_iocb
 *	Setup of ISP24xx command IOCB.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	req_q:	request queue structure pointer.
 *	sp:	srb structure pointer.
 *	arg:	request queue packet.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_command_24xx_iocb(ql_adapter_state_t *ha, ql_request_q_t *req_q,
    ql_srb_t *sp, void *arg)
{
	ddi_dma_cookie_t	*cp;
	uint32_t		*ptr32, cnt;
	uint16_t		seg_cnt;
	fcp_cmd_t		*fcp = sp->fcp;
	ql_tgt_t		*tq = sp->lun_queue->target_queue;
	cmd7_24xx_entry_t	*pkt = arg;
	ql_adapter_state_t	*pha = ha->pha;
	fcp_ent_addr_t		*fcp_ent_addr;

	QL_PRINT_3(ha, "started\n");

	if (fcp->fcp_data_len != 0 && sp->sg_dma.dma_handle != NULL &&
	    sp->pkt->pkt_data_cookie_cnt > 1) {
		ql_cmd_24xx_type_6_iocb(ha, req_q, sp, arg);
		QL_PRINT_3(ha, "cmd6 exit\n");
		return;
	}

	pkt->entry_type = IOCB_CMD_TYPE_7;

	/* Set LUN number */
	fcp_ent_addr = (fcp_ent_addr_t *)&sp->lun_queue->lun_addr;
	pkt->fcp_lun[2] = lobyte(fcp_ent_addr->ent_addr_0);
	pkt->fcp_lun[3] = hibyte(fcp_ent_addr->ent_addr_0);
	pkt->fcp_lun[0] = lobyte(fcp_ent_addr->ent_addr_1);
	pkt->fcp_lun[1] = hibyte(fcp_ent_addr->ent_addr_1);
	pkt->fcp_lun[6] = lobyte(fcp_ent_addr->ent_addr_2);
	pkt->fcp_lun[7] = hibyte(fcp_ent_addr->ent_addr_2);
	pkt->fcp_lun[4] = lobyte(fcp_ent_addr->ent_addr_3);
	pkt->fcp_lun[5] = hibyte(fcp_ent_addr->ent_addr_3);

	/* Set N_port handle */
	ddi_put16(req_q->req_ring.acc_handle, &pkt->n_port_hdl, tq->loop_id);

	/* Set target ID */
	pkt->target_id[0] = tq->d_id.b.al_pa;
	pkt->target_id[1] = tq->d_id.b.area;
	pkt->target_id[2] = tq->d_id.b.domain;

	pkt->vp_index = ha->vp_index;

	/* Set ISP command timeout. */
	if (sp->isp_timeout < 0x1999) {
		ddi_put16(req_q->req_ring.acc_handle, &pkt->timeout,
		    sp->isp_timeout);
	}

	/* Load SCSI CDB */
	ddi_rep_put8(req_q->req_ring.acc_handle, fcp->fcp_cdb, pkt->scsi_cdb,
	    MAX_CMDSZ, DDI_DEV_AUTOINCR);
	for (cnt = 0; cnt < MAX_CMDSZ; cnt += 4) {
		ql_chg_endian((uint8_t *)&pkt->scsi_cdb + cnt, 4);
	}

	/*
	 * Set tag queue control flags
	 * Note:
	 *	Cannot copy fcp->fcp_cntl.cntl_qtype directly,
	 *	problem with x86 in 32bit kernel mode
	 */
	switch (fcp->fcp_cntl.cntl_qtype) {
	case FCP_QTYPE_SIMPLE:
		pkt->task = TA_STAG;
		break;
	case FCP_QTYPE_HEAD_OF_Q:
		pkt->task = TA_HTAG;
		break;
	case FCP_QTYPE_ORDERED:
		pkt->task = TA_OTAG;
		break;
	case FCP_QTYPE_ACA_Q_TAG:
		pkt->task = TA_ACA;
		break;
	case FCP_QTYPE_UNTAGGED:
		pkt->task = TA_UNTAGGED;
		break;
	default:
		break;
	}

	if (fcp->fcp_data_len == 0) {
		QL_PRINT_3(ha, "done\n");
		pha->xioctl->IOControlRequests++;
		return;
	}

	/* Set transfer direction. */
	if (fcp->fcp_cntl.cntl_write_data) {
		pkt->control_flags = CF_WR;
		pha->xioctl->IOOutputRequests++;
		pha->xioctl->IOOutputByteCnt += fcp->fcp_data_len;
	} else if (fcp->fcp_cntl.cntl_read_data) {
		pkt->control_flags = CF_RD;
		pha->xioctl->IOInputRequests++;
		pha->xioctl->IOInputByteCnt += fcp->fcp_data_len;
	}

	/* Set data segment count. */
	seg_cnt = (uint16_t)sp->pkt->pkt_data_cookie_cnt;
	ddi_put16(req_q->req_ring.acc_handle, &pkt->dseg_count, seg_cnt);

	/* Load total byte count. */
	ddi_put32(req_q->req_ring.acc_handle, &pkt->total_byte_count,
	    fcp->fcp_data_len);

	/* Load command data segment. */
	ptr32 = (uint32_t *)&pkt->dseg;
	cp = sp->pkt->pkt_data_cookie;
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, cp->dmac_address);
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, cp->dmac_notused);
	ddi_put32(req_q->req_ring.acc_handle, ptr32, (uint32_t)cp->dmac_size);
	seg_cnt--;
	cp++;

	/*
	 * Build continuation packets.
	 */
	if (seg_cnt) {
		ql_continuation_iocb(pha, req_q, cp, seg_cnt, B_TRUE);
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_cmd_24xx_type_6_iocb
 *	Setup of ISP24xx command type 6 IOCB.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	req_q:	request queue structure pointer.
 *	sp:	srb structure pointer.
 *	arg:	request queue packet.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_cmd_24xx_type_6_iocb(ql_adapter_state_t *ha, ql_request_q_t *req_q,
    ql_srb_t *sp, void *arg)
{
	uint64_t		addr;
	ddi_dma_cookie_t	*cp;
	uint32_t		*ptr32;
	uint16_t		seg_cnt;
	fcp_cmd_t		*fcp = sp->fcp;
	ql_tgt_t		*tq = sp->lun_queue->target_queue;
	cmd6_24xx_entry_t	*pkt = arg;
	ql_adapter_state_t	*pha = ha->pha;
	dma_mem_t		*cmem = &sp->sg_dma;
	cmd6_2400_dma_t		*cdma = cmem->bp;
	fcp_ent_addr_t		*fcp_ent_addr;

	QL_PRINT_3(ha, "started\n");

	pkt->entry_type = IOCB_CMD_TYPE_6;

	bzero(cdma, sizeof (cmd6_2400_dma_t));

	/* Set LUN number */
	fcp_ent_addr = (fcp_ent_addr_t *)&sp->lun_queue->lun_addr;
	pkt->fcp_lun[2] = cdma->cmd.fcp_lun[2] =
	    lobyte(fcp_ent_addr->ent_addr_0);
	pkt->fcp_lun[3] = cdma->cmd.fcp_lun[3] =
	    hibyte(fcp_ent_addr->ent_addr_0);
	pkt->fcp_lun[0] = cdma->cmd.fcp_lun[0] =
	    lobyte(fcp_ent_addr->ent_addr_1);
	pkt->fcp_lun[1] = cdma->cmd.fcp_lun[1] =
	    hibyte(fcp_ent_addr->ent_addr_1);
	pkt->fcp_lun[6] = cdma->cmd.fcp_lun[6] =
	    lobyte(fcp_ent_addr->ent_addr_2);
	pkt->fcp_lun[7] = cdma->cmd.fcp_lun[7] =
	    hibyte(fcp_ent_addr->ent_addr_2);
	pkt->fcp_lun[4] = cdma->cmd.fcp_lun[4] =
	    lobyte(fcp_ent_addr->ent_addr_3);
	pkt->fcp_lun[5] = cdma->cmd.fcp_lun[5] =
	    hibyte(fcp_ent_addr->ent_addr_3);

	/* Set N_port handle */
	ddi_put16(req_q->req_ring.acc_handle, &pkt->n_port_hdl, tq->loop_id);

	/* Set target ID */
	pkt->target_id[0] = tq->d_id.b.al_pa;
	pkt->target_id[1] = tq->d_id.b.area;
	pkt->target_id[2] = tq->d_id.b.domain;

	pkt->vp_index = ha->vp_index;

	/* Set ISP command timeout. */
	if (sp->isp_timeout < 0x1999) {
		ddi_put16(req_q->req_ring.acc_handle, &pkt->timeout,
		    sp->isp_timeout);
	}

	/* Load SCSI CDB */
	ddi_rep_put8(cmem->acc_handle, fcp->fcp_cdb, cdma->cmd.scsi_cdb,
	    MAX_CMDSZ, DDI_DEV_AUTOINCR);

	/*
	 * Set tag queue control flags
	 * Note:
	 *	Cannot copy fcp->fcp_cntl.cntl_qtype directly,
	 *	problem with x86 in 32bit kernel mode
	 */
	switch (fcp->fcp_cntl.cntl_qtype) {
	case FCP_QTYPE_SIMPLE:
		cdma->cmd.task = TA_STAG;
		break;
	case FCP_QTYPE_HEAD_OF_Q:
		cdma->cmd.task = TA_HTAG;
		break;
	case FCP_QTYPE_ORDERED:
		cdma->cmd.task = TA_OTAG;
		break;
	case FCP_QTYPE_ACA_Q_TAG:
		cdma->cmd.task = TA_ACA;
		break;
	case FCP_QTYPE_UNTAGGED:
		cdma->cmd.task = TA_UNTAGGED;
		break;
	default:
		break;
	}

	/*
	 * FCP_CMND Payload Data Segment
	 */
	cp = cmem->cookies;
	ddi_put16(req_q->req_ring.acc_handle, &pkt->cmnd_length,
	    sizeof (fcp_cmnd_t));
	ddi_put32(req_q->req_ring.acc_handle, &pkt->cmnd_address[0],
	    cp->dmac_address);
	ddi_put32(req_q->req_ring.acc_handle, &pkt->cmnd_address[1],
	    cp->dmac_notused);

	/* Set transfer direction. */
	if (fcp->fcp_cntl.cntl_write_data) {
		pkt->control_flags = (uint8_t)(CF_DSD_PTR | CF_WR);
		cdma->cmd.control_flags = CF_WR;
		pha->xioctl->IOOutputRequests++;
		pha->xioctl->IOOutputByteCnt += fcp->fcp_data_len;
	} else if (fcp->fcp_cntl.cntl_read_data) {
		pkt->control_flags = (uint8_t)(CF_DSD_PTR | CF_RD);
		cdma->cmd.control_flags = CF_RD;
		pha->xioctl->IOInputRequests++;
		pha->xioctl->IOInputByteCnt += fcp->fcp_data_len;
	}

	/*
	 * FCP_DATA Data Segment Descriptor.
	 */
	addr = cp->dmac_laddress + sizeof (fcp_cmnd_t);
	ddi_put32(req_q->req_ring.acc_handle, &pkt->dseg.address[0], LSD(addr));
	ddi_put32(req_q->req_ring.acc_handle, &pkt->dseg.address[1], MSD(addr));

	/* Set data segment count. */
	seg_cnt = (uint16_t)sp->pkt->pkt_data_cookie_cnt;
	ddi_put16(req_q->req_ring.acc_handle, &pkt->dseg_count, seg_cnt);
	ddi_put32(req_q->req_ring.acc_handle, &pkt->dseg.length,
	    seg_cnt * 12 + 12);

	/* Load total byte count. */
	ddi_put32(req_q->req_ring.acc_handle, &pkt->total_byte_count,
	    fcp->fcp_data_len);
	ddi_put32(cmem->acc_handle, &cdma->cmd.dl, (uint32_t)fcp->fcp_data_len);
	ql_chg_endian((uint8_t *)&cdma->cmd.dl, 4);

	/* Load command data segments. */
	ptr32 = (uint32_t *)cdma->cookie_list;
	cp = sp->pkt->pkt_data_cookie;
	while (seg_cnt--) {
		ddi_put32(cmem->acc_handle, ptr32++, cp->dmac_address);
		ddi_put32(cmem->acc_handle, ptr32++, cp->dmac_notused);
		ddi_put32(cmem->acc_handle, ptr32++, (uint32_t)cp->dmac_size);
		cp++;
	}

	/* Sync DMA buffer. */
	(void) ddi_dma_sync(cmem->dma_handle, 0, 0, DDI_DMA_SYNC_FORDEV);

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_marker
 *	Function issues marker IOCB.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	loop_id:	device loop ID
 *	lq:		LUN queue pointer.
 *	type:		marker modifier
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
int
ql_marker(ql_adapter_state_t *ha, uint16_t loop_id, ql_lun_t *lq,
    uint8_t type)
{
	mrk_entry_t	*pkt;
	int		rval;
	ql_request_q_t	*req_q = ha->req_q[0];
	fcp_ent_addr_t	*fcp_ent_addr;

	QL_PRINT_3(ha, "started\n");

	rval = ql_req_pkt(ha, req_q, (request_t **)&pkt);
	if (rval == QL_SUCCESS) {
		pkt->entry_type = MARKER_TYPE;

		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			marker_24xx_entry_t	*pkt24 =
			    (marker_24xx_entry_t *)pkt;

			pkt24->modifier = type;

			/* Set LUN number */
			if (lq) {
				fcp_ent_addr = (fcp_ent_addr_t *)&lq->lun_addr;
				pkt24->fcp_lun[2] =
				    lobyte(fcp_ent_addr->ent_addr_0);
				pkt24->fcp_lun[3] =
				    hibyte(fcp_ent_addr->ent_addr_0);
				pkt24->fcp_lun[0] =
				    lobyte(fcp_ent_addr->ent_addr_1);
				pkt24->fcp_lun[1] =
				    hibyte(fcp_ent_addr->ent_addr_1);
				pkt24->fcp_lun[6] =
				    lobyte(fcp_ent_addr->ent_addr_2);
				pkt24->fcp_lun[7] =
				    hibyte(fcp_ent_addr->ent_addr_2);
				pkt24->fcp_lun[4] =
				    lobyte(fcp_ent_addr->ent_addr_3);
				pkt24->fcp_lun[5] =
				    hibyte(fcp_ent_addr->ent_addr_3);
			}

			pkt24->vp_index = ha->vp_index;

			/* Set N_port handle */
			ddi_put16(req_q->req_ring.acc_handle,
			    &pkt24->n_port_hdl, loop_id);

		} else {
			pkt->modifier = type;

			if (lq) {
				pkt->lun_l = LSB(lq->lun_no);
				pkt->lun_h = MSB(lq->lun_no);
			}

			if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
				pkt->target_l = LSB(loop_id);
				pkt->target_h = MSB(loop_id);
			} else {
				pkt->target_h = LSB(loop_id);
			}
		}

		/* Issue command to ISP */
		ql_isp_cmd(ha, req_q);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_ms_iocb
 *	Setup of name/management server IOCB.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	req_q:	request queue structure pointer.
 *	sp:	srb structure pointer.
 *	arg:	request queue packet.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_ms_iocb(ql_adapter_state_t *ha, ql_request_q_t *req_q, ql_srb_t *sp,
    void *arg)
{
	ddi_dma_cookie_t	*cp;
	uint32_t		*ptr32;
	uint16_t		seg_cnt;
	ql_tgt_t		*tq = sp->lun_queue->target_queue;
	ms_entry_t		*pkt = arg;

	QL_PRINT_3(ha, "started\n");
	QL_DUMP_3(sp->pkt->pkt_cmd, 8, sp->pkt->pkt_cmdlen);
	/*
	 * Build command packet.
	 */
	pkt->entry_type = MS_TYPE;

	/* Set loop ID */
	if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
		pkt->loop_id_l = LSB(tq->loop_id);
		pkt->loop_id_h = MSB(tq->loop_id);
	} else {
		pkt->loop_id_h = LSB(tq->loop_id);
	}

	/* Set ISP command timeout. */
	ddi_put16(req_q->req_ring.acc_handle, &pkt->timeout, sp->isp_timeout);

	/* Set cmd data segment count. */
	pkt->cmd_dseg_count_l = 1;

	/* Set total data segment count */
	seg_cnt = (uint16_t)(sp->pkt->pkt_resp_cookie_cnt + 1);
	ddi_put16(req_q->req_ring.acc_handle, &pkt->total_dseg_count, seg_cnt);

	/* Load ct cmd byte count. */
	ddi_put32(req_q->req_ring.acc_handle, &pkt->cmd_byte_count,
	    (uint32_t)sp->pkt->pkt_cmdlen);

	/* Load ct rsp byte count. */
	ddi_put32(req_q->req_ring.acc_handle, &pkt->resp_byte_count,
	    (uint32_t)sp->pkt->pkt_rsplen);

	/* Load MS command data segments. */
	ptr32 = (uint32_t *)&pkt->dseg;
	cp = sp->pkt->pkt_cmd_cookie;
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, cp->dmac_address);
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, cp->dmac_notused);
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, (uint32_t)cp->dmac_size);
	seg_cnt--;

	/* Load MS response entry data segments. */
	cp = sp->pkt->pkt_resp_cookie;
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, cp->dmac_address);
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, cp->dmac_notused);
	ddi_put32(req_q->req_ring.acc_handle, ptr32, (uint32_t)cp->dmac_size);
	seg_cnt--;
	cp++;

	/*
	 * Build continuation packets.
	 */
	if (seg_cnt) {
		ql_continuation_iocb(ha, req_q, cp, seg_cnt, B_TRUE);
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_ms_24xx_iocb
 *	Setup of name/management server IOCB.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	req_q:	request queue structure pointer.
 *	sp:	srb structure pointer.
 *	arg:	request queue packet.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_ms_24xx_iocb(ql_adapter_state_t *ha, ql_request_q_t *req_q, ql_srb_t *sp,
    void *arg)
{
	ddi_dma_cookie_t	*cp;
	uint32_t		*ptr32;
	uint16_t		seg_cnt;
	ql_tgt_t		*tq = sp->lun_queue->target_queue;
	ct_passthru_entry_t	*pkt = arg;
	ql_adapter_state_t	*pha = ha->pha;

	QL_PRINT_3(ha, "started\n");
	QL_DUMP_3(sp->pkt->pkt_cmd, 8, sp->pkt->pkt_cmdlen);
	/*
	 * Build command packet.
	 */
	pkt->entry_type = CT_PASSTHRU_TYPE;

	/* Set loop ID */
	ddi_put16(req_q->req_ring.acc_handle, &pkt->n_port_hdl, tq->loop_id);

	pkt->vp_index = ha->vp_index;

	/* Set ISP command timeout. */
	if (sp->isp_timeout < 0x1999) {
		ddi_put16(req_q->req_ring.acc_handle, &pkt->timeout,
		    sp->isp_timeout);
	}

	/* Set cmd/response data segment counts. */
	ddi_put16(req_q->req_ring.acc_handle, &pkt->cmd_dseg_count, 1);
	seg_cnt = (uint16_t)sp->pkt->pkt_resp_cookie_cnt;
	ddi_put16(req_q->req_ring.acc_handle, &pkt->resp_dseg_count, seg_cnt);

	/* Load ct cmd byte count. */
	ddi_put32(req_q->req_ring.acc_handle, &pkt->cmd_byte_count,
	    (uint32_t)sp->pkt->pkt_cmdlen);

	/* Load ct rsp byte count. */
	ddi_put32(req_q->req_ring.acc_handle, &pkt->resp_byte_count,
	    (uint32_t)sp->pkt->pkt_rsplen);

	/* Load MS command entry data segments. */
	ptr32 = (uint32_t *)&pkt->dseg;
	cp = sp->pkt->pkt_cmd_cookie;
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, cp->dmac_address);
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, cp->dmac_notused);
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, (uint32_t)cp->dmac_size);

	/* Load MS response entry data segments. */
	cp = sp->pkt->pkt_resp_cookie;
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, cp->dmac_address);
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, cp->dmac_notused);
	ddi_put32(req_q->req_ring.acc_handle, ptr32, (uint32_t)cp->dmac_size);
	seg_cnt--;
	cp++;

	/*
	 * Build continuation packets.
	 */
	if (seg_cnt) {
		ql_continuation_iocb(pha, req_q, cp, seg_cnt, B_TRUE);
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_ip_iocb
 *	Setup of IP IOCB.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	req_q:	request queue structure pointer.
 *	sp:	srb structure pointer.
 *	arg:	request queue packet.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_ip_iocb(ql_adapter_state_t *ha, ql_request_q_t *req_q, ql_srb_t *sp,
    void *arg)
{
	ddi_dma_cookie_t	*cp;
	uint32_t		*ptr32, cnt;
	uint16_t		seg_cnt;
	ql_tgt_t		*tq = sp->lun_queue->target_queue;
	ip_entry_t		*pkt = arg;
	ip_a64_entry_t		*pkt64 = arg;

	QL_PRINT_3(ha, "started\n");

	/* Set loop ID */
	if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
		pkt->loop_id_l = LSB(tq->loop_id);
		pkt->loop_id_h = MSB(tq->loop_id);
	} else {
		pkt->loop_id_h = LSB(tq->loop_id);
	}

	/* Set control flags */
	pkt->control_flags_l = BIT_6;
	if (sp->pkt->pkt_tran_flags & FC_TRAN_HI_PRIORITY) {
		pkt->control_flags_h = BIT_7;
	}

	/* Set ISP command timeout. */
	ddi_put16(req_q->req_ring.acc_handle, &pkt->timeout, sp->isp_timeout);

	/* Set data segment count. */
	seg_cnt = (uint16_t)sp->pkt->pkt_cmd_cookie_cnt;
	/* Load total byte count. */
	ddi_put32(req_q->req_ring.acc_handle, &pkt->byte_count,
	    (uint32_t)sp->pkt->pkt_cmdlen);
	ddi_put16(req_q->req_ring.acc_handle, &pkt->dseg_count, seg_cnt);

	/*
	 * Build command packet.
	 */

	/* Load command entry data segments. */
	cp = sp->pkt->pkt_cmd_cookie;

	if (CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)) {
		pkt64->entry_type = IP_A64_TYPE;
		cnt = IP_A64_DATA_SEGMENTS;
		ptr32 = (uint32_t *)&pkt64->dseg;
		while (cnt && seg_cnt) {
			ddi_put32(req_q->req_ring.acc_handle, ptr32++,
			    cp->dmac_address);
			ddi_put32(req_q->req_ring.acc_handle, ptr32++,
			    cp->dmac_notused);
			ddi_put32(req_q->req_ring.acc_handle, ptr32++,
			    (uint32_t)cp->dmac_size);
			seg_cnt--;
			cnt--;
			cp++;
		}
	} else {
		pkt->entry_type = IP_TYPE;
		cnt = IP_DATA_SEGMENTS;
		ptr32 = (uint32_t *)&pkt->dseg;
		while (cnt && seg_cnt) {
			ddi_put32(req_q->req_ring.acc_handle, ptr32++,
			    cp->dmac_address);
			ddi_put32(req_q->req_ring.acc_handle, ptr32++,
			    (uint32_t)cp->dmac_size);
			seg_cnt--;
			cnt--;
			cp++;
		}
	}

	/*
	 * Build continuation packets.
	 */
	if (seg_cnt) {
		ql_continuation_iocb(ha, req_q, cp, seg_cnt,
		    (boolean_t)(CFG_IST(ha, CFG_ENABLE_64BIT_ADDRESSING)));
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_ip_24xx_iocb
 *	Setup of IP IOCB for ISP24xx.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	req_q:	request queue structure pointer.
 *	sp:	srb structure pointer.
 *	arg:	request queue packet.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_ip_24xx_iocb(ql_adapter_state_t *ha, ql_request_q_t *req_q, ql_srb_t *sp,
    void *arg)
{
	ddi_dma_cookie_t	*cp;
	uint32_t		*ptr32;
	uint16_t		seg_cnt;
	ql_tgt_t		*tq = sp->lun_queue->target_queue;
	ip_cmd_entry_t		*pkt = arg;

	pkt->entry_type = IP_CMD_TYPE;

	QL_PRINT_3(ha, "started\n");

	/* Set N_port handle */
	ddi_put16(req_q->req_ring.acc_handle, &pkt->hdl_status, tq->loop_id);

	/* Set ISP command timeout. */
	if (sp->isp_timeout < 0x1999) {
		ddi_put16(req_q->req_ring.acc_handle, &pkt->timeout_hdl,
		    sp->isp_timeout);
	}

	/* Set data segment count. */
	seg_cnt = (uint16_t)sp->pkt->pkt_cmd_cookie_cnt;
	/* Load total byte count. */
	ddi_put32(req_q->req_ring.acc_handle, &pkt->byte_count,
	    (uint32_t)sp->pkt->pkt_cmdlen);
	ddi_put16(req_q->req_ring.acc_handle, &pkt->dseg_count, seg_cnt);

	/* Set control flags */
	ddi_put16(req_q->req_ring.acc_handle, &pkt->control_flags,
	    (uint16_t)(BIT_0));

	/* Set frame header control flags */
	ddi_put16(req_q->req_ring.acc_handle, &pkt->frame_hdr_cntrl_flgs,
	    (uint16_t)(IPCF_LAST_SEQ | IPCF_FIRST_SEQ));

	/* Load command data segment. */
	ptr32 = (uint32_t *)&pkt->dseg;
	cp = sp->pkt->pkt_cmd_cookie;
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, cp->dmac_address);
	ddi_put32(req_q->req_ring.acc_handle, ptr32++, cp->dmac_notused);
	ddi_put32(req_q->req_ring.acc_handle, ptr32, (uint32_t)cp->dmac_size);
	seg_cnt--;
	cp++;

	/*
	 * Build continuation packets.
	 */
	if (seg_cnt) {
		ql_continuation_iocb(ha, req_q, cp, seg_cnt, B_TRUE);
	}

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_isp_rcvbuf
 *	Locates free buffers and places it on the receive buffer queue.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
void
ql_isp_rcvbuf(ql_adapter_state_t *ha)
{
	rcvbuf_t	*container;
	uint16_t	rcv_q_cnt;
	uint16_t	index = 0;
	uint16_t	index1 = 1;
	int		debounce_count = QL_MAX_DEBOUNCE;
	ql_srb_t	*sp;
	fc_unsol_buf_t	*ubp;
	int		ring_updated = FALSE;

	if (CFG_IST(ha, CFG_CTRL_24XX)) {
		ql_isp24xx_rcvbuf(ha);
		return;
	}

	QL_PRINT_3(ha, "started\n");

	/* Acquire adapter state lock. */
	ADAPTER_STATE_LOCK(ha);

	/* Calculate number of free receive buffer entries. */
	index = RD16_IO_REG(ha, mailbox_out[8]);
	do {
		index1 = RD16_IO_REG(ha, mailbox_out[8]);
		if (index1 == index) {
			break;
		} else {
			index = index1;
		}
	} while (debounce_count--);

	if (debounce_count < 0) {
		/* This should never happen */
		EL(ha, "max mb8 debounce retries exceeded\n");
	}

	rcv_q_cnt = (uint16_t)(ha->rcvbuf_ring_index < index ?
	    index - ha->rcvbuf_ring_index : RCVBUF_CONTAINER_CNT -
	    (ha->rcvbuf_ring_index - index));

	if (rcv_q_cnt == RCVBUF_CONTAINER_CNT) {
		rcv_q_cnt--;
	}

	/* Load all free buffers in ISP receive buffer ring. */
	index = 0;
	while (rcv_q_cnt > (uint16_t)0 && index < QL_UB_LIMIT) {
		/* Locate a buffer to give. */
		QL_UB_LOCK(ha);
		while (index < QL_UB_LIMIT) {
			ubp = ha->ub_array[index];
			if (ubp != NULL) {
				sp = ubp->ub_fca_private;
				if ((sp->ub_type == FC_TYPE_IS8802_SNAP) &&
				    (ha->flags & IP_INITIALIZED) &&
				    (sp->flags & SRB_UB_IN_FCA) &&
				    (!(sp->flags & (SRB_UB_IN_ISP |
				    SRB_UB_FREE_REQUESTED | SRB_UB_CALLBACK |
				    SRB_UB_ACQUIRED)))) {
					sp->flags |= SRB_UB_IN_ISP;
					break;
				}
			}
			index++;
		}

		if (index < QL_UB_LIMIT) {
			rcv_q_cnt--;
			index++;
			container = ha->rcvbuf_ring_ptr;

			/*
			 * Build container.
			 */
			ddi_put32(ha->rcv_ring.acc_handle,
			    (uint32_t *)(void *)&container->bufp[0],
			    sp->ub_buffer.cookie.dmac_address);

			ddi_put32(ha->rcv_ring.acc_handle,
			    (uint32_t *)(void *)&container->bufp[1],
			    sp->ub_buffer.cookie.dmac_notused);

			ddi_put16(ha->rcv_ring.acc_handle, &container->handle,
			    LSW(sp->handle));

			ha->ub_outcnt++;

			/* Adjust ring index. */
			ha->rcvbuf_ring_index++;
			if (ha->rcvbuf_ring_index == RCVBUF_CONTAINER_CNT) {
				ha->rcvbuf_ring_index = 0;
				ha->rcvbuf_ring_ptr = ha->rcv_ring.bp;
			} else {
				ha->rcvbuf_ring_ptr++;
			}

			ring_updated = TRUE;
		}
		QL_UB_UNLOCK(ha);
	}

	if (ring_updated) {
		/* Sync queue. */
		(void) ddi_dma_sync(ha->rcv_ring.dma_handle, 0,
		    (size_t)RCVBUF_QUEUE_SIZE, DDI_DMA_SYNC_FORDEV);

		/* Set chip new ring index. */
		WRT16_IO_REG(ha, mailbox_in[8], ha->rcvbuf_ring_index);
	}

	/* Release adapter state lock. */
	ADAPTER_STATE_UNLOCK(ha);

	QL_PRINT_3(ha, "done\n");
}

/*
 * ql_isp24xx_rcvbuf
 *	Locates free buffers and send it to adapter.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_isp24xx_rcvbuf(ql_adapter_state_t *ha)
{
	rcvbuf_t		*container;
	uint16_t		index;
	ql_srb_t		*sp;
	fc_unsol_buf_t		*ubp;
	int			rval;
	ip_buf_pool_entry_t	*pkt = NULL;
	ql_request_q_t		*req_q = ha->req_q[0];

	QL_PRINT_3(ha, "started\n");

	for (;;) {
		/* Locate a buffer to give. */
		QL_UB_LOCK(ha);
		for (index = 0; index < QL_UB_LIMIT; index++) {
			ubp = ha->ub_array[index];
			if (ubp != NULL) {
				sp = ubp->ub_fca_private;
				if ((sp->ub_type == FC_TYPE_IS8802_SNAP) &&
				    (ha->flags & IP_INITIALIZED) &&
				    (sp->flags & SRB_UB_IN_FCA) &&
				    (!(sp->flags & (SRB_UB_IN_ISP |
				    SRB_UB_FREE_REQUESTED | SRB_UB_CALLBACK |
				    SRB_UB_ACQUIRED)))) {
					ha->ub_outcnt++;
					sp->flags |= SRB_UB_IN_ISP;
					break;
				}
			}
		}
		QL_UB_UNLOCK(ha);
		if (index == QL_UB_LIMIT) {
			break;
		}

		/* Get IOCB packet for buffers. */
		if (pkt == NULL) {
			rval = ql_req_pkt(ha, req_q, (request_t **)&pkt);
			if (rval != QL_SUCCESS) {
				EL(ha, "failed, ql_req_pkt=%x\n", rval);
				QL_UB_LOCK(ha);
				ha->ub_outcnt--;
				sp->flags &= ~SRB_UB_IN_ISP;
				QL_UB_UNLOCK(ha);
				break;
			}
			pkt->entry_type = IP_BUF_POOL_TYPE;
			container = &pkt->buffers[0];
		}

		/*
		 * Build container.
		 */
		ddi_put32(req_q->req_ring.acc_handle, &container->bufp[0],
		    sp->ub_buffer.cookie.dmac_address);
		ddi_put32(req_q->req_ring.acc_handle, &container->bufp[1],
		    sp->ub_buffer.cookie.dmac_notused);
		ddi_put16(req_q->req_ring.acc_handle, &container->handle,
		    LSW(sp->handle));

		pkt->buffer_count++;
		container++;

		if (pkt->buffer_count == IP_POOL_BUFFERS) {
			ql_isp_cmd(ha, req_q);
			pkt = NULL;
		}
	}

	if (pkt != NULL) {
		ql_isp_cmd(ha, req_q);
	}

	QL_PRINT_3(ha, "done\n");
}
