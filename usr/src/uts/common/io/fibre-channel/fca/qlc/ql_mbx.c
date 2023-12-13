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
 * Copyright (c) 2008, 2011, Oracle and/or its affiliates. All rights reserved.
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
#include <ql_mbx.h>
#include <ql_nx.h>
#include <ql_xioctl.h>

/*
 * Local data
 */

/*
 * Local prototypes
 */
static int ql_mailbox_command(ql_adapter_state_t *, mbx_cmd_t *);
static int ql_task_mgmt_iocb(ql_adapter_state_t *, ql_tgt_t *, uint64_t,
    uint32_t, uint16_t);
static int ql_abort_cmd_iocb(ql_adapter_state_t *, ql_srb_t *);
static int ql_setup_mbox_dma_transfer(ql_adapter_state_t *, dma_mem_t *,
    caddr_t, uint32_t);
static int ql_setup_mbox_dma_resources(ql_adapter_state_t *, dma_mem_t *,
    uint32_t);
static void ql_setup_mbox_dma_data(dma_mem_t *, caddr_t);
static void ql_get_mbox_dma_data(dma_mem_t *, caddr_t);
static int ql_init_req_q(ql_adapter_state_t *, ql_request_q_t *, uint16_t);
static int ql_init_rsp_q(ql_adapter_state_t *, ql_response_q_t *, uint16_t);
/*
 * ql_mailbox_command
 *	Issue mailbox command and waits for completion.
 *
 * Input:
 *	ha = adapter state pointer.
 *	mcp = mailbox command parameter structure pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_mailbox_command(ql_adapter_state_t *vha, mbx_cmd_t *mcp)
{
	uint16_t		cnt;
	uint32_t		data;
	clock_t			timer, cv_stat;
	int			rval;
	uint32_t		set_flags = 0;
	uint32_t		reset_flags = 0;
	ql_adapter_state_t	*ha = vha->pha;
	int			mbx_cmd = mcp->mb[0];

	QL_PRINT_3(ha, "started, cmd=%xh\n", mbx_cmd);

	/* Acquire mailbox register lock. */
	MBX_REGISTER_LOCK(ha);

	/* Check for mailbox available, if not wait for signal. */
	while (ha->mailbox_flags & MBX_BUSY_FLG) {
		if (ha->task_daemon_flags & TASK_DAEMON_POWERING_DOWN) {
			EL(vha, "powerdown availability cmd=%xh\n", mcp->mb[0]);
			MBX_REGISTER_UNLOCK(ha);
			return (QL_LOCK_TIMEOUT);
		}
		ha->mailbox_flags = (uint8_t)
		    (ha->mailbox_flags | MBX_WANT_FLG);

		/* Set timeout after command that is running. */
		timer = ha->mailbox_flags & MBX_BUSY_FLG ?
		    (mcp->timeout + 20) : 2;
		timer = timer * drv_usectohz(1000000);
		cv_stat = cv_reltimedwait_sig(&ha->cv_mbx_wait,
		    &ha->pha->mbx_mutex, timer, TR_CLOCK_TICK);
		if (cv_stat == -1 || cv_stat == 0) {
			/*
			 * The timeout time 'timer' was
			 * reached without the condition
			 * being signaled.
			 */
			ha->mailbox_flags = (uint8_t)(ha->mailbox_flags &
			    ~MBX_WANT_FLG);
			cv_broadcast(&ha->cv_mbx_wait);

			/* Release mailbox register lock. */
			MBX_REGISTER_UNLOCK(ha);

			if (cv_stat == 0) {
				EL(vha, "waiting for availability aborted, "
				    "cmd=%xh\n", mcp->mb[0]);
				return (QL_ABORTED);
			}
			EL(vha, "failed availability cmd=%xh\n", mcp->mb[0]);
			return (QL_LOCK_TIMEOUT);
		}
	}

	ha->mailbox_flags = (uint8_t)(ha->mailbox_flags | MBX_BUSY_FLG);

	/* Structure pointer for return mailbox registers. */
	ha->mcp = mcp;

	/* Load mailbox registers. */
	data = mcp->out_mb;
	for (cnt = 0; cnt < ha->reg_off->mbox_cnt && data; cnt++) {
		if (data & MBX_0) {
			WRT16_IO_REG(ha, mailbox_in[cnt], mcp->mb[cnt]);
		}
		data >>= 1;
	}

	/* Issue set host interrupt command. */
	ha->mailbox_flags = (uint8_t)(ha->mailbox_flags & ~MBX_INTERRUPT);
	if (CFG_IST(ha, CFG_CTRL_82XX)) {
		WRT32_IO_REG(ha, nx_host_int, NX_MBX_CMD);
	} else if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		WRT32_IO_REG(ha, hccr, HC24_SET_HOST_INT);
	} else {
		WRT16_IO_REG(ha, hccr, HC_SET_HOST_INT);
	}

	/* Wait for command to complete. */
	if (ha->flags & INTERRUPTS_ENABLED &&
	    !(ha->task_daemon_flags & TASK_DAEMON_POWERING_DOWN) &&
	    !ddi_in_panic()) {
		timer = mcp->timeout * drv_usectohz(1000000);
		while (!(ha->mailbox_flags & (MBX_INTERRUPT | MBX_ABORT)) &&
		    !(ha->task_daemon_flags & ISP_ABORT_NEEDED)) {

			if (cv_reltimedwait(&ha->cv_mbx_intr,
			    &ha->pha->mbx_mutex, timer, TR_CLOCK_TICK) == -1) {
				/*
				 * The timeout time 'timer' was
				 * reached without the condition
				 * being signaled.
				 */
				EL(vha, "reltimedwait expired cmd=%xh\n",
				    mcp->mb[0]);
				MBX_REGISTER_UNLOCK(ha);
				while (INTERRUPT_PENDING(ha)) {
					(void) ql_isr((caddr_t)ha);
					INTR_LOCK(ha);
					ha->intr_claimed = B_TRUE;
					INTR_UNLOCK(ha);
				}
				MBX_REGISTER_LOCK(ha);
				break;
			}
		}
	} else {
		/* Release mailbox register lock. */
		MBX_REGISTER_UNLOCK(ha);

		/* Acquire interrupt lock. */
		for (timer = mcp->timeout * 100; timer; timer--) {
			/* Check for pending interrupts. */
			while (INTERRUPT_PENDING(ha)) {
				(void) ql_isr((caddr_t)ha);
				INTR_LOCK(ha);
				ha->intr_claimed = B_TRUE;
				INTR_UNLOCK(ha);
				if (ha->mailbox_flags &
				    (MBX_INTERRUPT | MBX_ABORT) ||
				    ha->task_daemon_flags & ISP_ABORT_NEEDED) {
					break;
				}
			}
			if (ha->mailbox_flags & (MBX_INTERRUPT | MBX_ABORT) ||
			    ha->task_daemon_flags & ISP_ABORT_NEEDED) {
				break;
			} else if (!ddi_in_panic() && timer % 101 == 0) {
				delay(drv_usectohz(10000));
			} else {
				drv_usecwait(10000);
			}
		}

		/* Acquire mailbox register lock. */
		MBX_REGISTER_LOCK(ha);
	}

	/* Mailbox command timeout? */
	if (ha->task_daemon_flags & ISP_ABORT_NEEDED ||
	    ha->mailbox_flags & MBX_ABORT) {
		rval = QL_ABORTED;
	} else if ((ha->mailbox_flags & MBX_INTERRUPT) == 0) {
		if (!CFG_IST(ha, CFG_CTRL_82XX)) {
			if (CFG_IST(ha, CFG_DUMP_MAILBOX_TIMEOUT)) {
				(void) ql_binary_fw_dump(ha, FALSE);
			}
			EL(vha, "command timeout, isp_abort_needed\n");
			set_flags |= ISP_ABORT_NEEDED;
		}
		rval = QL_FUNCTION_TIMEOUT;
	} else {
		ha->mailbox_flags = (uint8_t)
		    (ha->mailbox_flags & ~MBX_INTERRUPT);
		/*
		 * This is the expected completion path so
		 * return the actual mbx cmd completion status.
		 */
		rval = mcp->mb[0];
	}

	/*
	 * Clear outbound to risc mailbox registers per spec. The exception
	 * is on 2200 mailbox 4 and 5 affect the req and resp que indexes
	 * so avoid writing them.
	 */
	if (CFG_IST(ha, CFG_CTRL_22XX)) {
		data = ((mcp->out_mb & ~(MBX_4 | MBX_5)) >> 1);
	} else {
		data = (mcp->out_mb >> 1);
	}
	for (cnt = 1; cnt < ha->reg_off->mbox_cnt && data; cnt++) {
		if (data & MBX_0) {
			WRT16_IO_REG(ha, mailbox_in[cnt], (uint16_t)0);
		}
		data >>= 1;
	}

	/* Reset busy status. */
	ha->mailbox_flags = (uint8_t)(ha->mailbox_flags &
	    ~(MBX_BUSY_FLG | MBX_ABORT));
	ha->mcp = NULL;

	/* If thread is waiting for mailbox go signal it to start. */
	if (ha->mailbox_flags & MBX_WANT_FLG) {
		ha->mailbox_flags = (uint8_t)(ha->mailbox_flags &
		    ~MBX_WANT_FLG);
		cv_broadcast(&ha->cv_mbx_wait);
	}

	/* Release mailbox register lock. */
	MBX_REGISTER_UNLOCK(ha);

	if (set_flags != 0 || reset_flags != 0) {
		ql_awaken_task_daemon(ha, NULL, set_flags, reset_flags);
	}

	if (rval != QL_SUCCESS) {
		EL(vha, "%s failed, rval=%xh, mcp->mb[0]=%xh\n",
		    mbx_cmd_text(mbx_cmd), rval, mcp->mb[0]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_setup_mbox_dma_resources
 *	Prepare the data for a mailbox dma transfer.
 *
 * Input:
 *	ha = adapter state pointer.
 *	mem_desc = descriptor to contain the dma resource information.
 *	data = pointer to the data.
 *	size = size of the data in bytes.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_setup_mbox_dma_transfer(ql_adapter_state_t *ha, dma_mem_t *mem_desc,
    caddr_t data, uint32_t size)
{
	int rval = QL_SUCCESS;

	if ((rval = ql_setup_mbox_dma_resources(ha, mem_desc, size)) ==
	    QL_SUCCESS) {
		ql_setup_mbox_dma_data(mem_desc, data);
	} else {
		EL(ha, "failed, setup_mbox_dma_transfer: %xh\n", rval);
	}

	return (rval);
}

/*
 * ql_setup_mbox_dma_resources
 *	Prepare a dma buffer.
 *
 * Input:
 *	ha = adapter state pointer.
 *	mem_desc = descriptor to contain the dma resource information.
 *	data = pointer to the data.
 *	size = size of the data in bytes.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
static int
ql_setup_mbox_dma_resources(ql_adapter_state_t *ha, dma_mem_t *mem_desc,
    uint32_t size)
{
	int	rval = QL_SUCCESS;

	if ((rval = ql_get_dma_mem(ha, mem_desc, size, LITTLE_ENDIAN_DMA,
	    QL_DMA_RING_ALIGN)) != QL_SUCCESS) {
		EL(ha, "failed, ql_get_dma_mem FC_NOMEM\n");
		rval = QL_MEMORY_ALLOC_FAILED;
	}

	return (rval);
}

/*
 * ql_setup_mbox_dma_data
 *	Move data to the dma buffer.
 *
 * Input:
 *	mem_desc = descriptor to contain the dma resource information.
 *	data = pointer to the data.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static void
ql_setup_mbox_dma_data(dma_mem_t *mem_desc, caddr_t data)
{
	/* Copy out going data to DMA buffer. */
	ddi_rep_put8(mem_desc->acc_handle, (uint8_t *)data,
	    (uint8_t *)mem_desc->bp, mem_desc->size, DDI_DEV_AUTOINCR);

	/* Sync DMA buffer. */
	(void) ddi_dma_sync(mem_desc->dma_handle, 0, mem_desc->size,
	    DDI_DMA_SYNC_FORDEV);
}

/*
 * ql_get_mbox_dma_data
 *	Recover data from the dma buffer.
 *
 * Input:
 *	mem_desc = descriptor to contain the dma resource information.
 *	data = pointer to the data.
 *
 * Returns:
 *
 * Context:
 *	Kernel context.
 */
static void
ql_get_mbox_dma_data(dma_mem_t *mem_desc, caddr_t data)
{
	/* Sync in coming DMA buffer. */
	(void) ddi_dma_sync(mem_desc->dma_handle, 0, mem_desc->size,
	    DDI_DMA_SYNC_FORKERNEL);
	/* Copy in coming DMA data. */
	ddi_rep_get8(mem_desc->acc_handle, (uint8_t *)data,
	    (uint8_t *)mem_desc->bp, mem_desc->size, DDI_DEV_AUTOINCR);
}

/*
 * ql_initialize_ip
 *	Initialize IP receive buffer queue.
 *
 * Input:
 *	ha = adapter state pointer.
 *	ha->ip_init_ctrl_blk = setup for transmit.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_initialize_ip(ql_adapter_state_t *ha)
{
	ql_link_t	*link;
	ql_tgt_t	*tq;
	uint16_t	index;
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if (!CFG_IST(ha, CFG_FCIP_SUPPORT) || ha->vp_index != 0) {
		ha->flags &= ~IP_INITIALIZED;
		EL(ha, "HBA does not support IP\n");
		return (QL_FUNCTION_FAILED);
	}

	ha->rcvbuf_ring_ptr = ha->rcv_ring.bp;
	ha->rcvbuf_ring_index = 0;

	/* Reset all sequence counts. */
	for (index = 0; index < DEVICE_HEAD_LIST_SIZE; index++) {
		for (link = ha->dev[index].first; link != NULL;
		    link = link->next) {
			tq = link->base_address;
			tq->ub_total_seg_cnt = 0;
		}
	}

	rval = ql_setup_mbox_dma_transfer(ha, &mem_desc,
	    (caddr_t)&ha->ip_init_ctrl_blk, sizeof (ql_comb_ip_init_cb_t));
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, setup_mbox_dma_transfer: %xh\n", rval);
		return (rval);
	}

	mcp->mb[0] = MBC_INITIALIZE_IP;
	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[8] = 0;
	mcp->out_mb = MBX_8|MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
	mcp->in_mb = MBX_8|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	ql_free_dma_resource(ha, &mem_desc);

	if (rval == QL_SUCCESS) {
		ADAPTER_STATE_LOCK(ha);
		ha->flags |= IP_INITIALIZED;
		ADAPTER_STATE_UNLOCK(ha);
		QL_PRINT_3(ha, "done\n");
	} else {
		ha->flags &= ~IP_INITIALIZED;
		EL(ha, "failed, rval = %xh\n", rval);
	}
	return (rval);
}

/*
 * ql_shutdown_ip
 *	Disconnects firmware IP from system buffers.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_shutdown_ip(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;
	fc_unsol_buf_t	*ubp;
	ql_srb_t	*sp;
	uint16_t	index;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_UNLOAD_IP;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	ADAPTER_STATE_LOCK(ha);
	QL_UB_LOCK(ha);
	/* Return all unsolicited buffers that ISP-IP has. */
	for (index = 0; index < QL_UB_LIMIT; index++) {
		ubp = ha->ub_array[index];
		if (ubp != NULL) {
			sp = ubp->ub_fca_private;
			sp->flags &= ~SRB_UB_IN_ISP;
		}
	}

	ha->ub_outcnt = 0;
	QL_UB_UNLOCK(ha);
	ha->flags &= ~IP_INITIALIZED;
	ADAPTER_STATE_UNLOCK(ha);

	if (rval == QL_SUCCESS) {
		/* EMPTY - no need to check return value of MBC_SHUTDOWN_IP */
		QL_PRINT_3(ha, "done\n");
	} else {
		EL(ha, "failed, rval = %xh\n", rval);
	}
	return (rval);
}

/*
 * ql_online_selftest
 *	Issue online self test mailbox command.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_online_selftest(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_ONLINE_SELF_TEST;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0 | MBX_1 | MBX_2 | MBX_3;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh, mb1=%xh, mb2=%xh, mb3=%xh\n",
		    rval, mcp->mb[1], mcp->mb[2], mcp->mb[3]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_loop_back
 *	Issue diagnostic loop back frame mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	findex:	FCF index.
 *	lb:	loop back parameter structure pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
#ifndef apps_64bit
int
ql_loop_back(ql_adapter_state_t *ha, uint16_t findex, lbp_t *lb,
    uint32_t h_xmit, uint32_t h_rcv)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_DIAGNOSTIC_LOOP_BACK;
	mcp->mb[1] = lb->options;
	mcp->mb[2] = findex;
	mcp->mb[6] = LSW(h_rcv);
	mcp->mb[7] = MSW(h_rcv);
	mcp->mb[10] = LSW(lb->transfer_count);
	mcp->mb[11] = MSW(lb->transfer_count);
	mcp->mb[12] = lb->transfer_segment_count;
	mcp->mb[13] = lb->receive_segment_count;
	mcp->mb[14] = LSW(lb->transfer_data_address);
	mcp->mb[15] = MSW(lb->transfer_data_address);
	mcp->mb[16] = LSW(lb->receive_data_address);
	mcp->mb[17] = MSW(lb->receive_data_address);
	mcp->mb[18] = LSW(lb->iteration_count);
	mcp->mb[19] = MSW(lb->iteration_count);
	mcp->mb[20] = LSW(h_xmit);
	mcp->mb[21] = MSW(h_xmit);
	mcp->out_mb = MBX_21|MBX_20|MBX_19|MBX_18|MBX_17|MBX_16|MBX_15|
	    MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_7|MBX_6|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_19|MBX_18|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->timeout = lb->iteration_count / 300;

	if (mcp->timeout < MAILBOX_TOV) {
		mcp->timeout = MAILBOX_TOV;
	}

	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh, mb1=%xh, mb2=%xh, mb3=%xh\n",
		    rval, mcp->mb[1], mcp->mb[2], mcp->mb[3]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}
#else
int
ql_loop_back(ql_adapter_state_t *ha, uint16_t findex, lbp_t *lb)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_DIAGNOSTIC_LOOP_BACK;
	mcp->mb[1] = lb->options;
	mcp->mb[2] = findex;
	mcp->mb[6] = LSW(h_rcv);
	mcp->mb[7] = MSW(h_rcv);
	mcp->mb[6] = LSW(MSD(lb->receive_data_address));
	mcp->mb[7] = MSW(MSD(lb->receive_data_address));
	mcp->mb[10] = LSW(lb->transfer_count);
	mcp->mb[11] = MSW(lb->transfer_count);
	mcp->mb[12] = lb->transfer_segment_count;
	mcp->mb[13] = lb->receive_segment_count;
	mcp->mb[14] = LSW(lb->transfer_data_address);
	mcp->mb[15] = MSW(lb->transfer_data_address);
	mcp->mb[14] = LSW(LSD(lb->transfer_data_address));
	mcp->mb[15] = MSW(LSD(lb->transfer_data_address));
	mcp->mb[16] = LSW(lb->receive_data_address);
	mcp->mb[17] = MSW(lb->receive_data_address);
	mcp->mb[16] = LSW(LSD(lb->receive_data_address));
	mcp->mb[17] = MSW(LSD(lb->receive_data_address));
	mcp->mb[18] = LSW(lb->iteration_count);
	mcp->mb[19] = MSW(lb->iteration_count);
	mcp->mb[20] = LSW(h_xmit);
	mcp->mb[21] = MSW(h_xmit);
	mcp->mb[20] = LSW(MSD(lb->transfer_data_address));
	mcp->mb[21] = MSW(MSD(lb->transfer_data_address));
	mcp->out_mb = MBX_21|MBX_20|MBX_19|MBX_18|MBX_17|MBX_16|MBX_15|
	    MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_7|MBX_6|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_19|MBX_18|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->timeout = lb->iteration_count / 300;

	if (mcp->timeout < MAILBOX_TOV) {
		mcp->timeout = MAILBOX_TOV;
	}

	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}
#endif

/*
 * ql_echo
 *	Issue an ELS echo using the user specified data to a user specified
 *	destination
 *
 * Input:
 *	ha:		adapter state pointer.
 *	findex:		FCF index.
 *	echo_pt:	echo parameter structure pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_echo(ql_adapter_state_t *ha, uint16_t findex, echo_t *echo_pt)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_ECHO;			/* ECHO command */
	mcp->mb[1] = echo_pt->options;		/* command options; 64 bit */
						/* addressing (bit 6) and */
						/* real echo (bit 15 */
	mcp->mb[2] = findex;

	/*
	 * I know this looks strange, using a field labled "not used"
	 * The way the ddi_dma_cookie_t structure/union is defined
	 * is a union of one 64 bit entity with an array of two 32
	 * bit enititys.  Since we have routines to convert 32 bit
	 * entities into 16 bit entities it is easier to use
	 * both 32 bit union members then the one 64 bit union
	 * member
	 */
	if (echo_pt->options & BIT_6) {
		/* 64 bit addressing */
		/* Receive data dest add in system memory bits 47-32 */
		mcp->mb[6] = LSW(echo_pt->receive_data_address.dmac_notused);

		/* Receive data dest add in system memory bits 63-48 */
		mcp->mb[7] = MSW(echo_pt->receive_data_address.dmac_notused);

		/* Transmit data source address in system memory bits 47-32 */
		mcp->mb[20] = LSW(echo_pt->transfer_data_address.dmac_notused);

		/* Transmit data source address in system memory bits 63-48 */
		mcp->mb[21] = MSW(echo_pt->transfer_data_address.dmac_notused);
	}

	/* transfer count bits 15-0 */
	mcp->mb[10] = LSW(echo_pt->transfer_count);

	/* Transmit data source address in system memory bits 15-0 */
	mcp->mb[14] = LSW(echo_pt->transfer_data_address.dmac_address);

	/*  Transmit data source address in system memory bits 31-16 */
	mcp->mb[15] = MSW(echo_pt->transfer_data_address.dmac_address);

	/* Receive data destination address in system memory bits 15-0 */
	mcp->mb[16] = LSW(echo_pt->receive_data_address.dmac_address);

	/*  Receive data destination address in system memory bits 31-16 */
	mcp->mb[17] = MSW(echo_pt->receive_data_address.dmac_address);

	mcp->out_mb = MBX_21|MBX_20|MBX_17|MBX_16|MBX_15|MBX_14|MBX_10|
	    MBX_7|MBX_6|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_3|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;

	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_send_change_request
 *	Issue send change request mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	fmt:	Registration format.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_send_change_request(ql_adapter_state_t *ha, uint16_t fmt)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_SEND_CHANGE_REQUEST;
	mcp->mb[1] = fmt;
	mcp->out_mb = MBX_1|MBX_0;
	if (ha->flags & VP_ENABLED) {
		mcp->mb[9] = ha->vp_index;
		mcp->out_mb |= MBX_9;
	}
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_send_lfa
 *	Send a Loop Fabric Address mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	lfa:	LFA command structure pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_send_lfa(ql_adapter_state_t *ha, lfa_cmd_t *lfa)
{
	int		rval;
	uint16_t	size;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	/* LFA_CB sz = 4 16bit words subcommand + 10 16bit words header. */
	size = (uint16_t)((lfa->subcommand_length[0] + 10) << 1);

	rval = ql_setup_mbox_dma_transfer(ha, &mem_desc, (caddr_t)lfa, size);
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, setup_mbox_dma_transfer: %xh\n", rval);
		return (rval);
	}

	mcp->mb[0] = MBC_SEND_LFA_COMMAND;
	mcp->mb[1] = (uint16_t)(size >> 1);
	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->in_mb = MBX_0;
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	if (ha->flags & VP_ENABLED) {
		mcp->mb[9] = ha->vp_index;
		mcp->out_mb |= MBX_9;
	}
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	ql_free_dma_resource(ha, &mem_desc);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_clear_aca
 *	Issue clear ACA mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	lq:	LUN queue pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_clear_aca(ql_adapter_state_t *ha, ql_tgt_t *tq, ql_lun_t *lq)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		rval = ql_task_mgmt_iocb(ha, tq, lq->lun_addr,
		    CF_CLEAR_ACA, 0);
	} else {
		mcp->mb[0] = MBC_CLEAR_ACA;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
		}
		mcp->mb[2] = lq->lun_no;
		mcp->out_mb = MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	(void) ql_marker(ha, tq->loop_id, lq, MK_SYNC_ID);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_target_reset
 *	Issue target reset mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	delay:	seconds.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_target_reset(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t delay)
{
	ql_link_t	*link;
	ql_srb_t	*sp;
	uint16_t	index;
	int		rval = QL_SUCCESS;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	ql_requeue_pending_cmds(ha, tq);
	INTR_LOCK(ha);
	for (index = 1; index < ha->pha->osc_max_cnt; index++) {
		if ((sp = ha->pha->outstanding_cmds[index]) != NULL &&
		    sp->lun_queue != NULL &&
		    sp->lun_queue->target_queue == tq) {
			sp->flags |= SRB_ABORTING;
		}
	}
	INTR_UNLOCK(ha);

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		/* queue = NULL, all targets. */
		if (tq == NULL) {
			for (index = 0; index < DEVICE_HEAD_LIST_SIZE;
			    index++) {
				for (link = ha->dev[index].first; link !=
				    NULL; link = link->next) {
					tq = link->base_address;
					if (!VALID_DEVICE_ID(ha,
					    tq->loop_id)) {
						continue;
					}

					if (CFG_IST(ha, CFG_FAST_TIMEOUT)) {
						rval = ql_task_mgmt_iocb(ha,
						    tq, 0, CF_DO_NOT_SEND |
						    CF_TARGET_RESET, delay);
					} else {
						rval = ql_task_mgmt_iocb(ha,
						    tq, 0, CF_TARGET_RESET,
						    delay);
					}

					if (rval != QL_SUCCESS) {
						break;
					}
				}

				if (link != NULL) {
					break;
				}
			}
			tq = NULL;
		} else {

			if (CFG_IST(ha, CFG_FAST_TIMEOUT)) {
				rval = ql_task_mgmt_iocb(ha, tq, 0,
				    CF_TARGET_RESET | CF_DO_NOT_SEND, delay);
			} else {
				rval = ql_task_mgmt_iocb(ha, tq, 0,
				    CF_TARGET_RESET, delay);
			}
		}
	} else {
		/* queue = NULL, all targets. */
		if (tq == NULL) {
			mcp->mb[0] = MBC_RESET;
			mcp->mb[1] = delay;
			mcp->out_mb = MBX_1|MBX_0;
		} else {
			mcp->mb[0] = MBC_TARGET_RESET;
			if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
				mcp->mb[1] = tq->loop_id;
			} else {
				mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
			}
			mcp->mb[2] = delay;
			mcp->out_mb = MBX_2|MBX_1|MBX_0;
		}
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	tq == NULL ? (void) ql_marker(ha, 0, 0, MK_SYNC_ALL) :
	    (void) ql_marker(ha, tq->loop_id, 0, MK_SYNC_ID);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_abort_target
 *	Issue abort target mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	delay:	in seconds.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_abort_target(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t delay)
{
	ql_srb_t	*sp;
	uint16_t	index;
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	ql_requeue_pending_cmds(ha, tq);
	INTR_LOCK(ha);
	for (index = 1; index < ha->pha->osc_max_cnt; index++) {
		if ((sp = ha->pha->outstanding_cmds[index]) != NULL &&
		    sp->lun_queue != NULL &&
		    sp->lun_queue->target_queue == tq) {
			sp->flags |= SRB_ABORTING;
		}
	}
	INTR_UNLOCK(ha);

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		rval = ql_task_mgmt_iocb(ha, tq, 0,
		    CF_DO_NOT_SEND | CF_TARGET_RESET, delay);
	} else {
		mcp->mb[0] = MBC_ABORT_TARGET;
		/* Don't send Task Mgt */
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
			mcp->mb[10] = BIT_0;
			mcp->out_mb = MBX_10|MBX_2|MBX_1|MBX_0;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8 | BIT_0);
			mcp->out_mb = MBX_2|MBX_1|MBX_0;
		}
		mcp->mb[2] = delay;
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	(void) ql_marker(ha, tq->loop_id, 0, MK_SYNC_ID);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_lun_reset
 *	Issue LUN reset task management mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	lq:	LUN queue pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_lun_reset(ql_adapter_state_t *ha, ql_tgt_t *tq, ql_lun_t *lq)
{
	ql_srb_t	*sp;
	uint16_t	index;
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	ql_requeue_pending_cmds(ha, tq);
	INTR_LOCK(ha);
	for (index = 1; index < ha->pha->osc_max_cnt; index++) {
		if ((sp = ha->pha->outstanding_cmds[index]) != NULL &&
		    sp->lun_queue != NULL &&
		    sp->lun_queue->target_queue == tq &&
		    sp->lun_queue == lq) {
			sp->flags |= SRB_ABORTING;
		}
	}
	INTR_UNLOCK(ha);

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		rval = ql_task_mgmt_iocb(ha, tq, lq->lun_addr,
		    CF_LUN_RESET, 0);
	} else {
		mcp->mb[0] = MBC_LUN_RESET;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
		}
		mcp->mb[2] = lq->lun_no;
		mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	(void) ql_marker(ha, tq->loop_id, lq, MK_SYNC_ID);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_clear_task_set
 *	Issue clear task set mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	lq:	LUN queue pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_clear_task_set(ql_adapter_state_t *ha, ql_tgt_t *tq, ql_lun_t *lq)
{
	ql_srb_t	*sp;
	uint16_t	index;
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	ql_requeue_pending_cmds(ha, tq);
	INTR_LOCK(ha);
	for (index = 1; index < ha->pha->osc_max_cnt; index++) {
		if ((sp = ha->pha->outstanding_cmds[index]) != NULL &&
		    sp->lun_queue != NULL &&
		    sp->lun_queue->target_queue == tq &&
		    sp->lun_queue == lq) {
			sp->flags |= SRB_ABORTING;
		}
	}
	INTR_UNLOCK(ha);

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		rval = ql_task_mgmt_iocb(ha, tq, lq->lun_addr,
		    CF_CLEAR_TASK_SET, 0);
	} else {
		mcp->mb[0] = MBC_CLEAR_TASK_SET;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
		}
		mcp->mb[2] = lq->lun_no;
		mcp->out_mb = MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	(void) ql_marker(ha, tq->loop_id, lq, MK_SYNC_ID);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_abort_task_set
 *	Issue abort task set mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	lq:	LUN queue pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_abort_task_set(ql_adapter_state_t *ha, ql_tgt_t *tq, ql_lun_t *lq)
{
	ql_srb_t	*sp;
	uint16_t	index;
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	ql_requeue_pending_cmds(ha, tq);
	INTR_LOCK(ha);
	for (index = 1; index < ha->pha->osc_max_cnt; index++) {
		if ((sp = ha->pha->outstanding_cmds[index]) != NULL &&
		    sp->lun_queue != NULL &&
		    sp->lun_queue->target_queue == tq &&
		    sp->lun_queue == lq) {
			sp->flags |= SRB_ABORTING;
		}
	}
	INTR_UNLOCK(ha);

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		rval = ql_task_mgmt_iocb(ha, tq, lq->lun_addr,
		    CF_ABORT_TASK_SET, 0);
	} else {
		mcp->mb[0] = MBC_ABORT_TASK_SET;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
		}
		mcp->mb[2] = lq->lun_no;
		mcp->out_mb = MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	(void) ql_marker(ha, tq->loop_id, lq, MK_SYNC_ID);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_task_mgmt_iocb
 *	Function issues task management IOCB.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	tq:		target queue pointer.
 *	lun_addr:	LUN.
 *	flags:		control flags.
 *	delay:		seconds.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context
 */
static int
ql_task_mgmt_iocb(ql_adapter_state_t *ha, ql_tgt_t *tq, uint64_t lun_addr,
    uint32_t flags, uint16_t delay)
{
	ql_mbx_iocb_t	*pkt;
	int		rval;
	uint32_t	pkt_size;
	fcp_ent_addr_t	*fcp_ent_addr;

	QL_PRINT_3(ha, "started\n");

	pkt_size = sizeof (ql_mbx_iocb_t);
	pkt = kmem_zalloc(pkt_size, KM_SLEEP);
	if (pkt == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (QL_MEMORY_ALLOC_FAILED);
	}

	pkt->mgmt.entry_type = TASK_MGMT_TYPE;
	pkt->mgmt.entry_count = 1;

	pkt->mgmt.n_port_hdl = (uint16_t)LE_16(tq->loop_id);
	pkt->mgmt.delay = (uint16_t)LE_16(delay);
	pkt->mgmt.timeout = LE_16(MAILBOX_TOV);

	fcp_ent_addr = (fcp_ent_addr_t *)&lun_addr;
	pkt->mgmt.fcp_lun[2] = lobyte(fcp_ent_addr->ent_addr_0);
	pkt->mgmt.fcp_lun[3] = hibyte(fcp_ent_addr->ent_addr_0);
	pkt->mgmt.fcp_lun[0] = lobyte(fcp_ent_addr->ent_addr_1);
	pkt->mgmt.fcp_lun[1] = hibyte(fcp_ent_addr->ent_addr_1);
	pkt->mgmt.fcp_lun[6] = lobyte(fcp_ent_addr->ent_addr_2);
	pkt->mgmt.fcp_lun[7] = hibyte(fcp_ent_addr->ent_addr_2);
	pkt->mgmt.fcp_lun[4] = lobyte(fcp_ent_addr->ent_addr_3);
	pkt->mgmt.fcp_lun[5] = hibyte(fcp_ent_addr->ent_addr_3);

	pkt->mgmt.control_flags = LE_32(flags);
	pkt->mgmt.target_id[0] = tq->d_id.b.al_pa;
	pkt->mgmt.target_id[1] = tq->d_id.b.area;
	pkt->mgmt.target_id[2] = tq->d_id.b.domain;
	pkt->mgmt.vp_index = ha->vp_index;

	rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt, pkt_size);
	if (rval == QL_SUCCESS && (pkt->sts24.entry_status & 0x3c) != 0) {
		EL(ha, "failed, entry_status=%xh, d_id=%xh\n",
		    pkt->sts24.entry_status, tq->d_id.b24);
		rval = QL_FUNCTION_PARAMETER_ERROR;
	}

	LITTLE_ENDIAN_16(&pkt->sts24.comp_status);

	if (rval == QL_SUCCESS && pkt->sts24.comp_status != CS_COMPLETE) {
		EL(ha, "failed, comp_status=%xh, d_id=%xh\n",
		    pkt->sts24.comp_status, tq->d_id.b24);
		rval = QL_FUNCTION_FAILED;
	}

	kmem_free(pkt, pkt_size);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_loop_port_bypass
 *	Issue loop port bypass mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_loop_port_bypass(ql_adapter_state_t *ha, ql_tgt_t *tq)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_LOOP_PORT_BYPASS;

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		mcp->mb[1] = tq->d_id.b.al_pa;
	} else if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
		mcp->mb[1] = tq->loop_id;
	} else {
		mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
	}

	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_loop_port_enable
 *	Issue loop port enable mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_loop_port_enable(ql_adapter_state_t *ha, ql_tgt_t *tq)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_LOOP_PORT_ENABLE;

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		mcp->mb[1] = tq->d_id.b.al_pa;
	} else if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
		mcp->mb[1] = tq->loop_id;
	} else {
		mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
	}
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_login_lport
 *	Issue login loop port mailbox command.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	tq:		target queue pointer.
 *	loop_id:	FC loop id.
 *	opt:		options.
 *			LLF_NONE, LLF_PLOGI
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_login_lport(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t loop_id,
    uint16_t opt)
{
	int		rval;
	uint16_t	flags;
	ql_mbx_data_t	mr;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started, d_id=%xh, loop_id=%xh\n",
	    ha->instance, tq->d_id.b24, loop_id);

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		flags = CF_CMD_PLOGI;
		if ((opt & LLF_PLOGI) == 0) {
			flags = (uint16_t)(flags | CFO_COND_PLOGI);
		}
		rval = ql_log_iocb(ha, tq, loop_id, flags, &mr);
	} else {
		mcp->mb[0] = MBC_LOGIN_LOOP_PORT;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = loop_id;
		} else {
			mcp->mb[1] = (uint16_t)(loop_id << 8);
		}
		mcp->mb[2] = opt;
		mcp->out_mb = MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "d_id=%xh, loop_id=%xh, failed=%xh\n", tq->d_id.b24,
		    loop_id, rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_login_fport
 *	Issue login fabric port mailbox command.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	tq:		target queue pointer.
 *	loop_id:	FC loop id.
 *	opt:		options.
 *			LFF_NONE, LFF_NO_PLOGI, LFF_NO_PRLI
 *	mr:		pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_login_fport(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t loop_id,
    uint16_t opt, ql_mbx_data_t *mr)
{
	int		rval;
	uint16_t	flags;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started, d_id=%xh, loop_id=%xh\n",
	    ha->instance, tq->d_id.b24, loop_id);

	if ((tq->d_id.b24 & QL_PORT_ID_MASK) == FS_MANAGEMENT_SERVER) {
		opt = (uint16_t)(opt | LFF_NO_PRLI);
	}

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		flags = CF_CMD_PLOGI;
		if (opt & LFF_NO_PLOGI) {
			flags = (uint16_t)(flags | CFO_COND_PLOGI);
		}
		if (opt & LFF_NO_PRLI) {
			flags = (uint16_t)(flags | CFO_SKIP_PRLI);
		}
		rval = ql_log_iocb(ha, tq, loop_id, flags, mr);
	} else {
		mcp->mb[0] = MBC_LOGIN_FABRIC_PORT;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = loop_id;
			mcp->mb[10] = opt;
			mcp->out_mb = MBX_10|MBX_3|MBX_2|MBX_1|MBX_0;
		} else {
			mcp->mb[1] = (uint16_t)(loop_id << 8 | opt);
			mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
		}
		mcp->mb[2] = MSW(tq->d_id.b24);
		mcp->mb[3] = LSW(tq->d_id.b24);
		mcp->in_mb = MBX_7|MBX_6|MBX_2|MBX_1|MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);

		/* Return mailbox data. */
		if (mr != NULL) {
			mr->mb[0] = mcp->mb[0];
			mr->mb[1] = mcp->mb[1];
			mr->mb[2] = mcp->mb[2];
			mr->mb[6] = mcp->mb[6];
			mr->mb[7] = mcp->mb[7];
		}
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "d_id=%xh, loop_id=%xh, failed=%xh, mb1=%02xh, "
		    "mb2=%04x\n", tq->d_id.b24, loop_id, rval,
		    mr != NULL ? mr->mb[1] : mcp->mb[1],
		    mr != NULL ? mr->mb[2] : mcp->mb[2]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_logout_fabric_port
 *	Issue logout fabric port mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_logout_fabric_port(ql_adapter_state_t *ha, ql_tgt_t *tq)
{
	int		rval;
	uint16_t	flag;
	ql_mbx_data_t	mr;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started, loop_id=%xh d_id=%xh\n",
	    tq->loop_id, tq->d_id.b24);

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		if ((ha->topology & QL_N_PORT) &&
		    (tq->loop_id != 0x7fe) &&
		    (tq->loop_id != 0x7ff)) {
			flag = (uint16_t)(CFO_IMPLICIT_LOGO |
			    CF_CMD_LOGO | CFO_FREE_N_PORT_HANDLE);

			rval = ql_log_iocb(ha, tq, tq->loop_id, flag, &mr);
		} else {
			flag = (uint16_t)(RESERVED_LOOP_ID(ha, tq->loop_id) ?
			    CFO_EXPLICIT_LOGO | CF_CMD_LOGO |
			    CFO_FREE_N_PORT_HANDLE :
			    CFO_IMPLICIT_LOGO | CF_CMD_LOGO |
			    CFO_FREE_N_PORT_HANDLE);

			rval = ql_log_iocb(ha, tq, tq->loop_id, flag, &mr);
		}

		if (rval == QL_SUCCESS) {
			EL(ha, "tq=%ph, loop_id=%xh, d_id=%xh, flag=%xh\n",
			    tq, tq->loop_id, tq->d_id.b24, flag);
		}
	} else {
		flag = (uint16_t)(RESERVED_LOOP_ID(ha, tq->loop_id) ? 1 : 0);
		mcp->mb[0] = MBC_LOGOUT_FABRIC_PORT;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
			mcp->mb[10] = flag;
			mcp->out_mb = MBX_10|MBX_1|MBX_0;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8 | flag);
			mcp->out_mb = MBX_1|MBX_0;
		}
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval=%xh, d_id=%xh, loop_id=%xh\n", rval,
		    tq->d_id.b24, tq->loop_id);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_log_iocb
 *	Function issues login/logout IOCB.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	tq:		target queue pointer.
 *	loop_id:	FC Loop ID.
 *	flags:		control flags.
 *	mr:		pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_log_iocb(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t loop_id,
    uint16_t flags, ql_mbx_data_t *mr)
{
	ql_mbx_iocb_t	*pkt;
	int		rval;
	uint32_t	pkt_size;

	QL_PRINT_3(ha, "started\n");

	pkt_size = sizeof (ql_mbx_iocb_t);
	pkt = kmem_zalloc(pkt_size, KM_SLEEP);
	if (pkt == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (QL_MEMORY_ALLOC_FAILED);
	}

	pkt->log.entry_type = LOG_TYPE;
	pkt->log.entry_count = 1;
	pkt->log.n_port_hdl = (uint16_t)LE_16(loop_id);
	pkt->log.control_flags = (uint16_t)LE_16(flags);
	pkt->log.port_id[0] = tq->d_id.b.al_pa;
	pkt->log.port_id[1] = tq->d_id.b.area;
	pkt->log.port_id[2] = tq->d_id.b.domain;
	pkt->log.vp_index = ha->vp_index;

	rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt, pkt_size);
	if (rval == QL_SUCCESS && (pkt->log.entry_status & 0x3c) != 0) {
		EL(ha, "failed, entry_status=%xh, d_id=%xh\n",
		    pkt->log.entry_status, tq->d_id.b24);
		rval = QL_FUNCTION_PARAMETER_ERROR;
	}

	if (rval == QL_SUCCESS) {
		if (pkt->log.rsp_size == 0xB) {
			LITTLE_ENDIAN_32(&pkt->log.io_param[5]);
			tq->cmn_features = MSW(pkt->log.io_param[5]);
			LITTLE_ENDIAN_32(&pkt->log.io_param[6]);
			tq->conc_sequences = MSW(pkt->log.io_param[6]);
			tq->relative_offset = LSW(pkt->log.io_param[6]);
			LITTLE_ENDIAN_32(&pkt->log.io_param[9]);
			tq->class3_recipient_ctl = MSW(pkt->log.io_param[9]);
			tq->class3_conc_sequences = LSW(pkt->log.io_param[9]);
			LITTLE_ENDIAN_32(&pkt->log.io_param[10]);
			tq->class3_open_sequences_per_exch =
			    MSW(pkt->log.io_param[10]);
			tq->prli_payload_length = 0x14;
		}
		if (mr != NULL) {
			LITTLE_ENDIAN_16(&pkt->log.status);
			LITTLE_ENDIAN_32(&pkt->log.io_param[0]);
			LITTLE_ENDIAN_32(&pkt->log.io_param[1]);

			if (pkt->log.status != CS_COMPLETE) {
				EL(ha, "failed, status=%xh, iop0=%xh, iop1="
				    "%xh\n", pkt->log.status,
				    pkt->log.io_param[0],
				    pkt->log.io_param[1]);

				switch (pkt->log.io_param[0]) {
				case CS0_NO_LINK:
				case CS0_FIRMWARE_NOT_READY:
					mr->mb[0] = MBS_COMMAND_ERROR;
					mr->mb[1] = 1;
					break;
				case CS0_NO_IOCB:
				case CS0_NO_PCB_ALLOCATED:
					mr->mb[0] = MBS_COMMAND_ERROR;
					mr->mb[1] = 2;
					break;
				case CS0_NO_EXCH_CTRL_BLK:
					mr->mb[0] = MBS_COMMAND_ERROR;
					mr->mb[1] = 3;
					break;
				case CS0_COMMAND_FAILED:
					mr->mb[0] = MBS_COMMAND_ERROR;
					mr->mb[1] = 4;
					switch (LSB(pkt->log.io_param[1])) {
					case CS1_PLOGI_RESPONSE_FAILED:
						mr->mb[2] = 3;
						break;
					case CS1_PRLI_FAILED:
						mr->mb[2] = 4;
						break;
					case CS1_PRLI_RESPONSE_FAILED:
						mr->mb[2] = 5;
						break;
					case CS1_COMMAND_LOGGED_OUT:
						mr->mb[2] = 7;
						break;
					case CS1_PLOGI_FAILED:
					default:
						EL(ha, "log iop1 = %xh\n",
						    LSB(pkt->log.io_param[1]))
						mr->mb[2] = 2;
						break;
					}
					break;
				case CS0_PORT_NOT_LOGGED_IN:
					mr->mb[0] = MBS_COMMAND_ERROR;
					mr->mb[1] = 4;
					mr->mb[2] = 7;
					break;
				case CS0_NO_FLOGI_ACC:
				case CS0_NO_FABRIC_PRESENT:
					mr->mb[0] = MBS_COMMAND_ERROR;
					mr->mb[1] = 5;
					break;
				case CS0_ELS_REJECT_RECEIVED:
					mr->mb[0] = MBS_COMMAND_ERROR;
					mr->mb[1] = 0xd;
					break;
				case CS0_PORT_ID_USED:
					mr->mb[0] = MBS_PORT_ID_USED;
					mr->mb[1] = LSW(pkt->log.io_param[1]);
					break;
				case CS0_N_PORT_HANDLE_USED:
					mr->mb[0] = MBS_LOOP_ID_USED;
					mr->mb[1] = MSW(pkt->log.io_param[1]);
					mr->mb[2] = LSW(pkt->log.io_param[1]);
					break;
				case CS0_NO_N_PORT_HANDLE_AVAILABLE:
					mr->mb[0] = MBS_ALL_IDS_IN_USE;
					break;
				case CS0_CMD_PARAMETER_ERROR:
				default:
					EL(ha, "pkt->log iop[0]=%xh\n",
					    pkt->log.io_param[0]);
					mr->mb[0] =
					    MBS_COMMAND_PARAMETER_ERROR;
					break;
				}
			} else {
				QL_PRINT_3(ha, "status=%xh\n", pkt->log.status);

				mr->mb[0] = MBS_COMMAND_COMPLETE;
				mr->mb[1] = (uint16_t)
				    (pkt->log.io_param[0] & BIT_4 ? 0 : BIT_0);
				if (pkt->log.io_param[0] & BIT_8) {
					mr->mb[1] = (uint16_t)
					    (mr->mb[1] | BIT_1);
				}
			}
			rval = mr->mb[0];
		}

	}

	kmem_free(pkt, pkt_size);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval=%xh, d_id=%xh loop_id=%xh\n",
		    rval, tq->d_id.b24, loop_id);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_port_database
 *	Issue get port database mailbox command
 *	and copy context to device queue.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	opt:	options.
 *		PDF_NONE, PDF_PLOGI, PDF_ADISC
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_port_database(ql_adapter_state_t *ha, ql_tgt_t *tq, uint8_t opt)
{
	int			rval;
	dma_mem_t		mem_desc;
	mbx_cmd_t		mc = {0};
	mbx_cmd_t		*mcp = &mc;
	port_database_23_t	*pd23;

	QL_PRINT_3(ha, "started\n");

	pd23 = (port_database_23_t *)kmem_zalloc(PORT_DATABASE_SIZE, KM_SLEEP);
	if (pd23 == NULL) {
		rval = QL_MEMORY_ALLOC_FAILED;
		EL(ha, "failed, rval = %xh\n", rval);
		return (rval);
	}

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
	    PORT_DATABASE_SIZE)) != QL_SUCCESS) {
		return (QL_MEMORY_ALLOC_FAILED);
	}

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		mcp->mb[0] = MBC_GET_PORT_DATABASE;
		mcp->mb[1] = tq->loop_id;
		mcp->mb[4] = CHAR_TO_SHORT(tq->d_id.b.al_pa, tq->d_id.b.area);
		mcp->mb[5] = (uint16_t)tq->d_id.b.domain;
		mcp->mb[9] = ha->vp_index;
		mcp->mb[10] = (uint16_t)(opt | PDF_ADISC);
		mcp->out_mb = MBX_10|MBX_9|MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|
		    MBX_2|MBX_1|MBX_0;
	} else {
		mcp->mb[0] = (uint16_t)(opt == PDF_NONE ?
		    MBC_GET_PORT_DATABASE : MBC_ENHANCED_GET_PORT_DATABASE);
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
			mcp->mb[10] = opt;
			mcp->out_mb = MBX_10|MBX_7|MBX_6|MBX_3|
			    MBX_2|MBX_1|MBX_0;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8 | opt);
			mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
		}
	}

	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ql_get_mbox_dma_data(&mem_desc, (caddr_t)pd23);
	}

	ql_free_dma_resource(ha, &mem_desc);

	if (rval == QL_SUCCESS) {
		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			port_database_24_t *pd24 = (port_database_24_t *)pd23;

			tq->master_state = pd24->current_login_state;
			tq->slave_state = pd24->last_stable_login_state;
			if (PD_PORT_LOGIN(tq)) {
				/* Names are big endian. */
				bcopy((void *)&pd24->port_name[0],
				    (void *)&tq->port_name[0], 8);
				bcopy((void *)&pd24->node_name[0],
				    (void *)&tq->node_name[0], 8);
				tq->hard_addr.b.al_pa = pd24->hard_address[2];
				tq->hard_addr.b.area = pd24->hard_address[1];
				tq->hard_addr.b.domain = pd24->hard_address[0];
				tq->class3_rcv_data_size =
				    pd24->receive_data_size;
				LITTLE_ENDIAN_16(&tq->class3_rcv_data_size);
				tq->prli_svc_param_word_0 =
				    pd24->PRLI_service_parameter_word_0;
				LITTLE_ENDIAN_16(&tq->prli_svc_param_word_0);
				tq->prli_svc_param_word_3 =
				    pd24->PRLI_service_parameter_word_3;
				LITTLE_ENDIAN_16(&tq->prli_svc_param_word_3);
			}
		} else {
			tq->master_state = pd23->master_state;
			tq->slave_state = pd23->slave_state;
			if (PD_PORT_LOGIN(tq)) {
				/* Names are big endian. */
				bcopy((void *)&pd23->port_name[0],
				    (void *)&tq->port_name[0], 8);
				bcopy((void *)&pd23->node_name[0],
				    (void *)&tq->node_name[0], 8);
				tq->hard_addr.b.al_pa = pd23->hard_address[2];
				tq->hard_addr.b.area = pd23->hard_address[1];
				tq->hard_addr.b.domain = pd23->hard_address[0];
				tq->cmn_features = pd23->common_features;
				LITTLE_ENDIAN_16(&tq->cmn_features);
				tq->conc_sequences =
				    pd23->total_concurrent_sequences;
				LITTLE_ENDIAN_16(&tq->conc_sequences);
				tq->relative_offset =
				    pd23->RO_by_information_category;
				LITTLE_ENDIAN_16(&tq->relative_offset);
				tq->class3_recipient_ctl = pd23->recipient;
				LITTLE_ENDIAN_16(&tq->class3_recipient_ctl);
				tq->class3_rcv_data_size =
				    pd23->receive_data_size;
				LITTLE_ENDIAN_16(&tq->class3_rcv_data_size);
				tq->class3_conc_sequences =
				    pd23->concurrent_sequences;
				LITTLE_ENDIAN_16(&tq->class3_conc_sequences);
				tq->class3_open_sequences_per_exch =
				    pd23->open_sequences_per_exchange;
				LITTLE_ENDIAN_16(
				    &tq->class3_open_sequences_per_exch);
				tq->prli_payload_length =
				    pd23->PRLI_payload_length;
				LITTLE_ENDIAN_16(&tq->prli_payload_length);
				tq->prli_svc_param_word_0 =
				    pd23->PRLI_service_parameter_word_0;
				LITTLE_ENDIAN_16(&tq->prli_svc_param_word_0);
				tq->prli_svc_param_word_3 =
				    pd23->PRLI_service_parameter_word_3;
				LITTLE_ENDIAN_16(&tq->prli_svc_param_word_3);
			}
		}

		if (!PD_PORT_LOGIN(tq)) {
			EL(ha, "d_id=%xh, loop_id=%xh, not logged in "
			    "master=%xh, slave=%xh\n", tq->d_id.b24,
			    tq->loop_id, tq->master_state, tq->slave_state);
			rval = QL_NOT_LOGGED_IN;
		} else {
			tq->flags = tq->prli_svc_param_word_3 &
			    PRLI_W3_TARGET_FUNCTION ?
			    tq->flags & ~TQF_INITIATOR_DEVICE :
			    tq->flags | TQF_INITIATOR_DEVICE;

			if ((tq->flags & TQF_INITIATOR_DEVICE) == 0) {
				tq->flags = tq->prli_svc_param_word_3 &
				    PRLI_W3_RETRY ?
				    tq->flags | TQF_TAPE_DEVICE :
				    tq->flags & ~TQF_TAPE_DEVICE;
			} else {
				tq->flags &= ~TQF_TAPE_DEVICE;
			}
		}
	}

	kmem_free(pd23, PORT_DATABASE_SIZE);

	/*
	 * log the trace in any cases other than QL_SUCCESS.
	 */
	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval=%xh, d_id=%xh, loop_id=%xh\n",
		    rval, tq->d_id.b24, tq->loop_id);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_loop_position_map
 *	Issue get loop position map mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	size:	size of data buffer.
 *	bufp:	data pointer for DMA data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_loop_position_map(ql_adapter_state_t *ha, size_t size, caddr_t bufp)
{
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
	    (uint32_t)size)) != QL_SUCCESS) {
		EL(ha, "setup_mbox_dma_resources failed: %xh\n", rval);
		return (QL_MEMORY_ALLOC_FAILED);
	}

	mcp->mb[0] = MBC_GET_FC_AL_POSITION_MAP;
	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ql_get_mbox_dma_data(&mem_desc, bufp);
	}

	ql_free_dma_resource(ha, &mem_desc);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_set_rnid_params
 *	Issue set RNID parameters mailbox command.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	size:		size of data buffer.
 *	bufp:		data pointer for DMA data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_set_rnid_params(ql_adapter_state_t *ha, size_t size, caddr_t bufp)
{
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if ((rval = ql_setup_mbox_dma_transfer(ha, &mem_desc, bufp,
	    (uint32_t)size)) != QL_SUCCESS) {
		EL(ha, "failed, setup_mbox_dma_transfer: %x\n", rval);
		return (rval);
	}

	mcp->mb[0] = MBC_SET_PARAMETERS;
	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	ql_free_dma_resource(ha, &mem_desc);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_send_rnid_els
 *	Issue a send node identfication data mailbox command.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	loop_id:	FC loop id.
 *	opt:		options.
 *	size:		size of data buffer.
 *	bufp:		data pointer for DMA data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_send_rnid_els(ql_adapter_state_t *ha, uint16_t loop_id, uint8_t opt,
    size_t size, caddr_t bufp)
{
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
	    (uint32_t)size)) != QL_SUCCESS) {
		return (QL_MEMORY_ALLOC_FAILED);
	}

	mcp->mb[0] = MBC_SEND_RNID_ELS;
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		mcp->mb[1] = loop_id;
		mcp->mb[9] = ha->vp_index;
		mcp->mb[10] = opt;
		mcp->out_mb = MBX_10|MBX_9|MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	} else if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
		mcp->mb[1] = loop_id;
		mcp->mb[10] = opt;
		mcp->out_mb = MBX_10|MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	} else {
		mcp->mb[1] = (uint16_t)(loop_id << 8 | opt);
		mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	}
	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ql_get_mbox_dma_data(&mem_desc, bufp);
	}

	ql_free_dma_resource(ha, &mem_desc);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_rnid_params
 *	Issue get RNID parameters mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	size:	size of data buffer.
 *	bufp:	data pointer for DMA data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_rnid_params(ql_adapter_state_t *ha, size_t size, caddr_t bufp)
{
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
	    (uint32_t)size)) != QL_SUCCESS) {
		return (QL_MEMORY_ALLOC_FAILED);
	}

	mcp->mb[0] = MBC_GET_PARAMETERS;
	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ql_get_mbox_dma_data(&mem_desc, bufp);
	}

	ql_free_dma_resource(ha, &mem_desc);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_link_status
 *	Issue get link status mailbox command.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	loop_id:	FC loop id or n_port_hdl.
 *	size:		size of data buffer.
 *	bufp:		data pointer for DMA data.
 *	port_no:	port number to query.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_link_status(ql_adapter_state_t *ha, uint16_t loop_id, size_t size,
    caddr_t bufp, uint8_t port_no)
{
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;
	int		rval = QL_SUCCESS;
	int		retry = 0;

	QL_PRINT_3(ha, "started\n");

	do {
		if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
		    (uint32_t)size)) != QL_SUCCESS) {
			EL(ha, "setup_mbox_dma_resources failed: %xh\n", rval);
			return (QL_MEMORY_ALLOC_FAILED);
		}

		mcp->mb[0] = MBC_GET_LINK_STATUS;
		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			if (loop_id == ha->loop_id) {
				mcp->mb[0] = MBC_GET_STATUS_COUNTS;
				mcp->mb[8] = (uint16_t)(size >> 2);
				mcp->out_mb = MBX_10|MBX_8;
			} else {
				mcp->mb[1] = loop_id;
				mcp->mb[4] = port_no;
				mcp->mb[10] = (uint16_t)(retry ? BIT_3 : 0);
				mcp->out_mb = MBX_10|MBX_4;
			}
		} else {
			if (retry) {
				port_no = (uint8_t)(port_no | BIT_3);
			}
			if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
				mcp->mb[1] = loop_id;
				mcp->mb[10] = port_no;
				mcp->out_mb = MBX_10;
			} else {
				mcp->mb[1] = (uint16_t)((loop_id << 8) |
				    port_no);
				mcp->out_mb = 0;
			}
		}
		mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
		mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
		mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
		mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
		mcp->in_mb = MBX_1|MBX_0;
		mcp->out_mb |= MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
		mcp->timeout = MAILBOX_TOV;

		rval = ql_mailbox_command(ha, mcp);

		if (rval == QL_SUCCESS) {
			ql_get_mbox_dma_data(&mem_desc, bufp);
		}

		ql_free_dma_resource(ha, &mem_desc);

		if (rval != QL_SUCCESS) {
			EL(ha, "failed=%xh, mbx1=%xh\n", rval, mcp->mb[1]);
		}

		/*
		 * Some of the devices want d_id in the payload,
		 * strictly as per standard. Let's retry.
		 */

	} while (rval == QL_COMMAND_ERROR && !retry++);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, mbx1=%xh\n", rval, mcp->mb[1]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_status_counts
 *	Issue get adapter link status counts mailbox command.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	loop_id:	FC loop id or n_port_hdl.
 *	size:		size of data buffer.
 *	bufp:		data pointer for DMA data.
 *	port_no:	port number to query.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_status_counts(ql_adapter_state_t *ha, uint16_t loop_id, size_t size,
    caddr_t bufp, uint8_t port_no)
{
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;
	int		rval = QL_SUCCESS;

	QL_PRINT_3(ha, "started\n");

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
	    (uint32_t)size)) != QL_SUCCESS) {
		EL(ha, "setup_mbox_dma_resources failed: %x\n", rval);
		return (QL_MEMORY_ALLOC_FAILED);
	}

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		mcp->mb[0] = MBC_GET_STATUS_COUNTS;
		mcp->mb[8] = (uint16_t)(size / 4);
		mcp->out_mb = MBX_10|MBX_8;
	} else {
		mcp->mb[0] = MBC_GET_LINK_STATUS;

		/* allows reporting when link is down */
		if (CFG_IST(ha, CFG_CTRL_22XX) == 0) {
			port_no = (uint8_t)(port_no | BIT_6);
		}

		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = loop_id;
			mcp->mb[10] = port_no;
			mcp->out_mb = MBX_10|MBX_1;
		} else {
			mcp->mb[1] = (uint16_t)((loop_id << 8) |
			    port_no);
			mcp->out_mb = MBX_1;
		}
	}
	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->out_mb |= MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ql_get_mbox_dma_data(&mem_desc, bufp);
	}

	ql_free_dma_resource(ha, &mem_desc);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, mbx1=%xh, mbx2=%xh\n", rval,
		    mcp->mb[1], mcp->mb[2]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_reset_link_status
 *	Issue Reset Link Error Status mailbox command
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_reset_link_status(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_RESET_LINK_STATUS;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_loop_reset
 *	Issue loop reset.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_loop_reset(ql_adapter_state_t *ha)
{
	int	rval;

	QL_PRINT_3(ha, "started\n");

	if (CFG_IST(ha, CFG_ENABLE_LIP_RESET)) {
		rval = ql_lip_reset(ha, 0xff);
	} else if (CFG_IST(ha, CFG_ENABLE_FULL_LIP_LOGIN)) {
		rval = ql_full_login_lip(ha);
	} else if (CFG_IST(ha, CFG_ENABLE_TARGET_RESET)) {
		rval = ql_target_reset(ha, NULL, ha->loop_reset_delay);
	} else {
		rval = ql_initiate_lip(ha);
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
 * ql_initiate_lip
 *	Initiate LIP mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_initiate_lip(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if (CFG_IST(ha, CFG_FCOE_SUPPORT)) {
		ql_toggle_loop_state(ha);
		QL_PRINT_3(ha, "8081 done\n");
		return (QL_SUCCESS);
	}
	if (CFG_IST(ha, CFG_FC_TYPE_2)) {
		mcp->mb[0] = MBC_LIP_FULL_LOGIN;
		mcp->mb[1] = BIT_4;
		mcp->mb[3] = ha->loop_reset_delay;
		mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	} else {
		mcp->mb[0] = MBC_INITIATE_LIP;
		mcp->out_mb = MBX_0;
	}
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_full_login_lip
 *	Issue full login LIP mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_full_login_lip(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if (CFG_IST(ha, CFG_FCOE_SUPPORT)) {
		ql_toggle_loop_state(ha);
		QL_PRINT_3(ha, "8081 done\n");
		return (QL_SUCCESS);
	}
	mcp->mb[0] = MBC_LIP_FULL_LOGIN;
	if (CFG_IST(ha, CFG_FC_TYPE_2)) {
		mcp->mb[1] = BIT_3;
	}
	mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done");
	}

	return (rval);
}

/*
 * ql_lip_reset
 *	Issue lip reset to a port.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	loop_id:	FC loop id.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_lip_reset(ql_adapter_state_t *ha, uint16_t loop_id)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if (CFG_IST(ha, CFG_FCOE_SUPPORT)) {
		ql_toggle_loop_state(ha);
		QL_PRINT_3(ha, "8081 done\n");
		return (QL_SUCCESS);
	}

	if (CFG_IST(ha, CFG_FC_TYPE_2)) {
		mcp->mb[0] = MBC_LIP_FULL_LOGIN;
		mcp->mb[1] = BIT_6;
		mcp->mb[3] = ha->loop_reset_delay;
		mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	} else {
		mcp->mb[0] = MBC_LIP_RESET;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = loop_id;
			mcp->out_mb = MBX_10|MBX_3|MBX_2|MBX_1|MBX_0;
		} else {
			mcp->mb[1] = (uint16_t)(loop_id << 8);
			mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
		}
		mcp->mb[2] = ha->loop_reset_delay;
	}
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_abort_command
 *	Abort command aborts a specified IOCB.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	sp:	SRB structure pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_abort_command(ql_adapter_state_t *ha, ql_srb_t *sp)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;
	ql_tgt_t	*tq = sp->lun_queue->target_queue;

	QL_PRINT_3(ha, "started\n");

	sp->flags |= SRB_ABORTING;
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		rval = ql_abort_cmd_iocb(ha, sp);
	} else {
		mcp->mb[0] = MBC_ABORT_COMMAND_IOCB;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
		}
		mcp->mb[2] = LSW(sp->handle);
		mcp->mb[3] = MSW(sp->handle);
		mcp->mb[6] = (uint16_t)(sp->flags & SRB_FCP_CMD_PKT ?
		    sp->lun_queue->lun_no : 0);
		mcp->out_mb = MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh, handle=%xh\n", rval,
		    tq->d_id.b24, sp->handle);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_abort_cmd_iocb
 *	Function issues abort command IOCB.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	sp:	SRB structure pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static int
ql_abort_cmd_iocb(ql_adapter_state_t *ha, ql_srb_t *sp)
{
	ql_mbx_iocb_t	*pkt;
	int		rval;
	uint32_t	pkt_size;
	uint16_t	comp_status;
	ql_tgt_t	*tq = sp->lun_queue->target_queue;

	QL_PRINT_3(ha, "started\n");

	pkt_size = sizeof (ql_mbx_iocb_t);
	if ((pkt = kmem_zalloc(pkt_size, KM_SLEEP)) == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (QL_MEMORY_ALLOC_FAILED);
	}

	pkt->abo.entry_type = ABORT_CMD_TYPE;
	pkt->abo.entry_count = 1;
	pkt->abo.n_port_hdl = (uint16_t)LE_16(tq->loop_id);
	if (!CFG_IST(ha, CFG_CTRL_82XX)) {
		pkt->abo.options = AF_NO_ABTS;
	}
	pkt->abo.cmd_handle = LE_32(sp->handle);
	pkt->abo.target_id[0] = tq->d_id.b.al_pa;
	pkt->abo.target_id[1] = tq->d_id.b.area;
	pkt->abo.target_id[2] = tq->d_id.b.domain;
	pkt->abo.vp_index = ha->vp_index;

	rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt, pkt_size);

	if (rval == QL_SUCCESS) {
		if ((pkt->abo.entry_status & 0x3c) != 0) {
			EL(ha, "failed, entry_status=%xh, d_id=%xh\n",
			    pkt->abo.entry_status, tq->d_id.b24);
			rval = QL_FUNCTION_PARAMETER_ERROR;
		} else {
			comp_status = (uint16_t)LE_16(pkt->abo.n_port_hdl);
			if (comp_status != CS_COMPLETE) {
				EL(ha, "failed, comp_status=%xh, d_id=%xh\n",
				    comp_status, tq->d_id.b24);
				rval = QL_FUNCTION_FAILED;
			}
		}
	}

	kmem_free(pkt, pkt_size);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_verify_checksum
 *	Verify loaded RISC firmware.
 *
 * Input:
 *	ha = adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_verify_checksum(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_VERIFY_CHECKSUM;
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		mcp->mb[1] = MSW(ha->risc_fw[0].addr);
		mcp->mb[2] = LSW(ha->risc_fw[0].addr);
	} else {
		mcp->mb[1] = LSW(ha->risc_fw[0].addr);
	}
	mcp->out_mb = MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_id_list
 *	Get d_id and loop ID list.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	data pointer for DMA data.
 *	size:	size of data buffer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_id_list(ql_adapter_state_t *ha, caddr_t bp, uint32_t size,
    ql_mbx_data_t *mr)
{
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
	    (uint32_t)size)) != QL_SUCCESS) {
		EL(ha, "setup_mbox_dma_resources failed: %xh\n", rval);
		return (QL_MEMORY_ALLOC_FAILED);
	}

	mcp->mb[0] = MBC_GET_ID_LIST;
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
		mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
		mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
		mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
		mcp->mb[8] = (uint16_t)size;
		mcp->mb[9] = ha->vp_index;
		mcp->out_mb = MBX_9|MBX_8|MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
	} else {
		mcp->mb[1] = MSW(LSD(mem_desc.cookie.dmac_laddress));
		mcp->mb[2] = LSW(LSD(mem_desc.cookie.dmac_laddress));
		mcp->mb[3] = MSW(MSD(mem_desc.cookie.dmac_laddress));
		mcp->mb[6] = LSW(MSD(mem_desc.cookie.dmac_laddress));
		mcp->out_mb = MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	}
	mcp->in_mb = MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ql_get_mbox_dma_data(&mem_desc, bp);
	}

	ql_free_dma_resource(ha, &mem_desc);

	/* Return mailbox data. */
	if (mr != NULL) {
		mr->mb[0] = mcp->mb[0];
		mr->mb[1] = mcp->mb[1];
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
 * ql_wrt_risc_ram
 *	Load RISC RAM.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	risc_address:	risc ram word address.
 *	bp:		DMA pointer.
 *	word_count:	16/32bit word count.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_wrt_risc_ram(ql_adapter_state_t *ha, uint32_t risc_address, uint64_t bp,
    uint32_t word_count)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[1] = LSW(risc_address);
	mcp->mb[2] = MSW(LSD(bp));
	mcp->mb[3] = LSW(LSD(bp));
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		mcp->mb[0] = MBC_LOAD_RAM_EXTENDED;
		mcp->mb[4] = MSW(word_count);
		mcp->mb[5] = LSW(word_count);
		mcp->mb[8] = MSW(risc_address);
		mcp->out_mb = MBX_0_THRU_8;
	} else {
		mcp->mb[0] = MBC_LOAD_RISC_RAM;
		mcp->mb[4] = LSW(word_count);
		mcp->out_mb = MBX_7|MBX_6|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	}
	mcp->mb[6] = MSW(MSD(bp));
	mcp->mb[7] = LSW(MSD(bp));
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_rd_risc_ram
 *	Get RISC RAM.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	risc_address:	risc ram word address.
 *	bp:		direct data pointer.
 *	word_count:	16/32bit word count.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_rd_risc_ram(ql_adapter_state_t *ha, uint32_t risc_address, uint64_t bp,
    uint32_t word_count)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		mcp->mb[0] = MBC_DUMP_RAM_EXTENDED;
		mcp->mb[1] = LSW(risc_address);
		mcp->mb[2] = MSW(LSD(bp));
		mcp->mb[3] = LSW(LSD(bp));
		mcp->mb[4] = MSW(word_count);
		mcp->mb[5] = LSW(word_count);
		mcp->mb[6] = MSW(MSD(bp));
		mcp->mb[7] = LSW(MSD(bp));
		mcp->mb[8] = MSW(risc_address);
		mcp->out_mb = MBX_8|MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|
		    MBX_0;
	} else {
		mcp->mb[0] = MBC_DUMP_RAM;	/* doesn't support 64bit addr */
		mcp->mb[1] = LSW(risc_address);
		mcp->mb[2] = MSW(LSD(bp));
		mcp->mb[3] = LSW(LSD(bp));
		mcp->mb[4] = LSW(word_count);
		mcp->out_mb = MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	}
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_wrt_risc_ram_word
 *	Write RISC RAM word.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	risc_address:	risc ram word address.
 *	data:		data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_wrt_risc_ram_word(ql_adapter_state_t *ha, uint32_t risc_address,
    uint32_t data)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_WRITE_RAM_EXTENDED;
	mcp->mb[1] = LSW(risc_address);
	mcp->mb[2] = LSW(data);
	mcp->mb[3] = MSW(data);
	mcp->mb[8] = MSW(risc_address);
	mcp->out_mb = MBX_8|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;

	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_rd_risc_ram_word
 *	Read RISC RAM word.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	risc_address:	risc ram word address.
 *	data:		data pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_rd_risc_ram_word(ql_adapter_state_t *ha, uint32_t risc_address,
    uint32_t *data)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_READ_RAM_EXTENDED;
	mcp->mb[1] = LSW(risc_address);
	mcp->mb[8] = MSW(risc_address);
	mcp->out_mb = MBX_8|MBX_1|MBX_0;
	mcp->in_mb = MBX_3|MBX_2|MBX_0;
	mcp->timeout = MAILBOX_TOV;

	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		*data = mcp->mb[2];
		if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
			*data |= mcp->mb[3] << 16;
		}
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_issue_mbx_iocb
 *	Issue IOCB using mailbox command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	buffer pointer.
 *	size:	buffer size.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_issue_mbx_iocb(ql_adapter_state_t *ha, caddr_t bp, uint32_t size)
{
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if ((rval = ql_setup_mbox_dma_transfer(ha, &mem_desc, bp, size)) !=
	    QL_SUCCESS) {
		EL(ha, "setup_mbox_dma_transfer failed: %x\n", rval);
		return (rval);
	}

	mcp->mb[0] = MBC_EXECUTE_IOCB;
	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->out_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV + 5;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ql_get_mbox_dma_data(&mem_desc, bp);
	}

	ql_free_dma_resource(ha, &mem_desc);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, mbx1=%xh\n", rval, mcp->mb[1]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_mbx_wrap_test
 *	Mailbox register wrap test.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for in/out mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_mbx_wrap_test(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started cfg=0x%llx\n", ha->cfg_flags);

	mcp->mb[0] = MBC_MAILBOX_REGISTER_TEST;
	if (mr == NULL) {
		mcp->mb[1] = 0xAAAA;
		mcp->mb[2] = 0x5555;
		mcp->mb[3] = 0xAA55;
		mcp->mb[4] = 0x55AA;
		mcp->mb[5] = 0xA5A5;
		mcp->mb[6] = 0x5A5A;
		mcp->mb[7] = 0x2525;
	} else {
		mcp->mb[1] = mr->mb[1];
		mcp->mb[2] = mr->mb[2];
		mcp->mb[3] = mr->mb[3];
		mcp->mb[4] = mr->mb[4];
		mcp->mb[5] = mr->mb[5];
		mcp->mb[6] = mr->mb[6];
		mcp->mb[7] = mr->mb[7];
	}
	mcp->out_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);
	if (rval == QL_SUCCESS) {
		if (mr == NULL) {
			if (mcp->mb[1] != 0xAAAA || mcp->mb[2] != 0x5555 ||
			    mcp->mb[3] != 0xAA55 || mcp->mb[4] != 0x55AA) {
				rval = QL_FUNCTION_FAILED;
			}
			if (mcp->mb[5] != 0xA5A5 || mcp->mb[6] != 0x5A5A ||
			    mcp->mb[7] != 0x2525) {
				rval = QL_FUNCTION_FAILED;
			}
		} else {
			if (mcp->mb[1] != mr->mb[1] ||
			    mcp->mb[2] != mr->mb[2] ||
			    mcp->mb[3] != mr->mb[3] ||
			    mcp->mb[4] != mr->mb[4]) {
				rval = QL_FUNCTION_FAILED;
			}
			if (mcp->mb[5] != mr->mb[5] ||
			    mcp->mb[6] != mr->mb[6] ||
			    mcp->mb[7] != mr->mb[7]) {
				rval = QL_FUNCTION_FAILED;
			}
		}
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_execute_fw
 *	Start adapter firmware.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_execute_fw(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if (CFG_IST(ha, CFG_CTRL_82XX)) {
		return (QL_SUCCESS);
	}

	mcp->mb[0] = MBC_EXECUTE_FIRMWARE;
	if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		mcp->mb[1] = MSW(ha->risc_fw[0].addr);
		mcp->mb[2] = LSW(ha->risc_fw[0].addr);
	} else {
		mcp->mb[1] = LSW(ha->risc_fw[0].addr);
	}
	if (CFG_IST(ha, CFG_LR_SUPPORT)) {
		mcp->mb[4] = BIT_0;
	}
	mcp->out_mb = MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (CFG_IST(ha, CFG_CTRL_22XX)) {
		rval = QL_SUCCESS;
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_firmware_option
 *	 Get Firmware Options Mailbox Command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_firmware_option(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_GET_FIRMWARE_OPTIONS;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	if (mr != NULL) {
		mr->mb[0] = mcp->mb[0];
		mr->mb[1] = mcp->mb[1];
		mr->mb[2] = mcp->mb[2];
		mr->mb[3] = mcp->mb[3];
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_9(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_set_firmware_option
 *	 Set Firmware Options Mailbox Command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_set_firmware_option(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if (mr != NULL) {
		mcp->mb[0] = MBC_SET_FIRMWARE_OPTIONS;
		mcp->mb[1] = mr->mb[1];
		mcp->mb[2] = mr->mb[2];
		mcp->mb[3] = mr->mb[3];
		mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	} else {
		rval = QL_FUNCTION_PARAMETER_ERROR;
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_init_firmware
 *	 Initialize firmware mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	ha->init_ctrl_blk = setup for transmit.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_init_firmware(ql_adapter_state_t *ha)
{
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if (ha->flags & MULTI_QUEUE) {
		WR32_MBAR_REG(ha, ha->req_q[0]->mbar_req_in, 0);
		WR32_MBAR_REG(ha, ha->rsp_queues[0]->mbar_rsp_out, 0);
	} else if (CFG_IST(ha, CFG_CTRL_82XX)) {
		ql_8021_wr_req_in(ha, 0);
		WRT32_IO_REG(ha, req_out, 0);
		WRT32_IO_REG(ha, resp_in, 0);
		WRT32_IO_REG(ha, resp_out, 0);
	} else if (CFG_IST(ha, CFG_ISP_FW_TYPE_2)) {
		WRT32_IO_REG(ha, req_in, 0);
		WRT32_IO_REG(ha, resp_out, 0);
		WRT32_IO_REG(ha, pri_req_in, 0);
		WRT32_IO_REG(ha, atio_req_out, 0);
	} else {
		WRT16_IO_REG(ha, req_in, 0);
		WRT16_IO_REG(ha, resp_out, 0);
	}
	if (ha->req_q[0]->req_out_shadow_ptr) {
		*ha->req_q[0]->req_out_shadow_ptr = 0;
	}
	if (ha->rsp_queues[0]->rsp_in_shadow_ptr) {
		*ha->rsp_queues[0]->rsp_in_shadow_ptr = 0;
	}

	if ((rval = ql_setup_mbox_dma_transfer(ha, &mem_desc,
	    (caddr_t)&ha->init_ctrl_blk, sizeof (ql_comb_init_cb_t))) !=
	    QL_SUCCESS) {
		EL(ha, "dma setup failed=%xh\n", rval);
		return (rval);
	}

	mcp->mb[0] = (uint16_t)(ha->flags & VP_ENABLED ?
	    MBC_INITIALIZE_MULTI_ID_FW : MBC_INITIALIZE_FIRMWARE);

	if (CFG_IST(ha, CFG_SBUS_CARD)) {
		mcp->mb[1] = (uint16_t)(CFG_IST(ha, CFG_CTRL_22XX) ?
		    0x204c : 0x52);
	}

	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	if (CFG_IST(ha, CFG_FCOE_SUPPORT)) {
		uint64_t		ofst, addr;
		ql_init_24xx_cb_t	*icb = (ql_init_24xx_cb_t *)
		    &ha->init_ctrl_blk.cb24;

		mcp->mb[0] = MBC_INITIALIZE_MULTI_ID_FW;
		if (icb->ext_blk.version[0] | icb->ext_blk.version[1]) {
			ofst = (uintptr_t)&icb->ext_blk - (uintptr_t)icb;
			addr = mem_desc.cookie.dmac_laddress + ofst;
			mcp->mb[10] = MSW(LSD(addr));
			mcp->mb[11] = LSW(LSD(addr));
			mcp->mb[12] = MSW(MSD(addr));
			mcp->mb[13] = LSW(MSD(addr));
			mcp->mb[14] = sizeof (ql_ext_icb_8100_t);
			mcp->mb[1] = BIT_0;
		}
		mcp->out_mb = MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_7|MBX_6|
		    MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	} else {
		mcp->out_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	}
	mcp->in_mb = MBX_5|MBX_4|MBX_2|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ha->sfp_stat = mcp->mb[2];
		if (CFG_IST(ha, CFG_CTRL_82XX)) {
			(void) ql_8021_get_md_template(ha);
		} else {
			uint16_t	i, opt;

			opt = ha->flags & NO_INTR_HANDSHAKE ?
			    IMO_NONE : IMO_INTERRUPT_HANDSHAKE;
			if (ha->flags & QUEUE_SHADOW_PTRS) {
				opt |= IMO_QUEUE_POINTER_SHADOWING;
			}
			/* Initialize ha multi-response-queue request queue */
			if (ha->rsp_queues_cnt > 1) {
				rval = ql_init_req_q(ha, ha->req_q[1], opt);
				if (rval != QL_SUCCESS) {
					EL(ha, "ql_init_req_q=%xh\n", rval);
					return (rval);
				}
			}
			/* Initialize multi-response queues */
			for (i = 1; i < ha->rsp_queues_cnt; i++) {
				rval = ql_init_rsp_q(ha, ha->rsp_queues[i],
				    opt);
				if (rval != QL_SUCCESS) {
					EL(ha, "ql_init_rsp_q=%xh\n", rval);
					return (rval);
				}
			}
		}
	}
	ql_free_dma_resource(ha, &mem_desc);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_firmware_state
 *	Get adapter firmware state.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_firmware_state(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_GET_FIRMWARE_STATE;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0_THRU_6;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	ha->fw_state[0] = mcp->mb[0];
	ha->fw_state[1] = mcp->mb[1];
	ha->fw_state[2] = mcp->mb[2];
	ha->fw_state[3] = mcp->mb[3];
	ha->fw_state[4] = mcp->mb[4];
	ha->fw_state[5] = mcp->mb[5];
	ha->fw_state[6] = mcp->mb[6];

	/* Return mailbox data. */
	if (mr != NULL) {
		mr->mb[1] = mcp->mb[1];
		mr->mb[2] = mcp->mb[2];
		mr->mb[3] = mcp->mb[3];
		mr->mb[4] = mcp->mb[4];
		mr->mb[5] = mcp->mb[5];
		mr->mb[6] = mcp->mb[6];
	}

	ha->sfp_stat = mcp->mb[2];

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_adapter_id
 *	Get adapter ID and topology.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_adapter_id(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		i, rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_GET_ID;
	if (ha->flags & VP_ENABLED) {
		mcp->mb[9] = ha->vp_index;
	}
	mcp->out_mb = MBX_9|MBX_0;
	mcp->in_mb = MBX_0_THRU_19;
	mcp->timeout = MAILBOX_TOV;

	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	if (mr != NULL) {
		for (i = 0; i < 20; i++) {
			mr->mb[i] = mcp->mb[i];
		}
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_fw_version
 *	Get firmware version.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_fw_version(ql_adapter_state_t *ha, ql_mbx_data_t *mr, uint16_t timeout)
{
	int		rval, i;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_ABOUT_FIRMWARE;
	mcp->out_mb = MBX_0;
	if (CFG_IST(ha, CFG_CTRL_83XX)) {
		mcp->in_mb = MBX_0_THRU_17;
	} else if (CFG_IST(ha, CFG_CTRL_27XX)) {
		mcp->in_mb = MBX_0_THRU_25;
	} else {
		mcp->in_mb = MBX_0_THRU_13;
	}
	mcp->timeout = timeout;
	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	if (mr != NULL) {
		for (i = 0; i < ha->reg_off->mbox_cnt && mcp->in_mb; i++) {
			if (mcp->in_mb & MBX_0) {
				mr->mb[i] = mcp->mb[i];
			}
			mcp->in_mb >>= 1;
		}
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_data_rate
 *	 Issue data rate Mailbox Command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_data_rate(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if (mr != NULL) {
		mcp->mb[0] = MBC_DATA_RATE;
		mcp->mb[1] = mr->mb[1];
		mcp->mb[2] = mr->mb[2];
		mcp->out_mb = MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_3|MBX_2|MBX_1|MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);

		/* Return mailbox data. */
		mr->mb[1] = mcp->mb[1];
		mr->mb[2] = mcp->mb[2];
		mr->mb[3] = mcp->mb[3];
	} else {
		rval = QL_FUNCTION_PARAMETER_ERROR;
	}

	ha->sfp_stat = mcp->mb[2];

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_Diag_Loopback
 *	Issue Reset Link Status mailbox command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	buffer pointer.
 *	size:	buffer size.
 *	opt:	command options.
 *	it_cnt:	iteration count.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_diag_loopback(ql_adapter_state_t *ha, caddr_t bp, uint32_t size,
    uint16_t opt, uint32_t it_cnt, ql_mbx_data_t *mr)
{
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if ((rval = ql_setup_mbox_dma_transfer(ha, &mem_desc, bp, size)) !=
	    QL_SUCCESS) {
		EL(ha, "setup_mbox_dma_transfer failed: %x\n", rval);
		return (rval);
	}

	mcp->mb[0] = MBC_DIAGNOSTIC_LOOP_BACK;
	mcp->mb[1] = opt;
	mcp->mb[2] = ha->fcoe_fcf_idx;
	mcp->mb[6] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[10] = LSW(size);
	mcp->mb[11] = MSW(size);
	mcp->mb[14] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[15] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[16] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[17] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[18] = LSW(it_cnt);
	mcp->mb[19] = MSW(it_cnt);
	mcp->mb[20] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[21] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->out_mb = MBX_21|MBX_20|MBX_19|MBX_18|MBX_17|MBX_16|MBX_15|
	    MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_7|MBX_6|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_19|MBX_18|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->timeout = it_cnt / 300;
	if (mcp->timeout < MAILBOX_TOV) {
		mcp->timeout = MAILBOX_TOV;
	}
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ql_get_mbox_dma_data(&mem_desc, bp);
	}

	ql_free_dma_resource(ha, &mem_desc);

	/* Return mailbox data. */
	if (mr != NULL) {
		mr->mb[0] = mcp->mb[0];
		mr->mb[1] = mcp->mb[1];
		mr->mb[2] = mcp->mb[2];
		mr->mb[3] = mcp->mb[3];
		mr->mb[18] = mcp->mb[18];
		mr->mb[19] = mcp->mb[19];
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, mb1=%xh\n", rval, mcp->mb[1]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_diag_echo
 *	Issue Diag echo mailbox command.  Valid for qla23xx HBA's.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	bp:	buffer pointer.
 *	size:	buffer size.
 *	opt:	command options.
 *	mr:	pointer to mailbox status.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_diag_echo(ql_adapter_state_t *ha, caddr_t bp, uint32_t size, uint16_t opt,
    ql_mbx_data_t *mr)
{
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if ((rval = ql_setup_mbox_dma_transfer(ha, &mem_desc, bp, size)) !=
	    QL_SUCCESS) {
		EL(ha, "setup_mbox_dma_transfer failed: %x\n", rval);
		return (rval);
	}

	mcp->mb[0] = MBC_ECHO;
	mcp->mb[1] = opt;
	mcp->mb[2] = ha->fcoe_fcf_idx;
	mcp->mb[6] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[10] = LSW(size);
	mcp->mb[14] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[15] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[16] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[17] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[20] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[21] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->out_mb = MBX_21|MBX_20|MBX_17|MBX_16|MBX_15|
	    MBX_14|MBX_10|MBX_7|MBX_6|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ql_get_mbox_dma_data(&mem_desc, bp);
	}

	ql_free_dma_resource(ha, &mem_desc);

	if (mr != NULL) {
		mr->mb[0] = mcp->mb[0];
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, mb1=%xh\n", rval,
		    mcp->mb[1]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_diag_beacon
 *      Enable/Disable beaconing via mailbox command.
 *
 * Input:
 *      ha:     adapter state pointer.
 *      mr:     pointer to mailbox in/out parameters.
 *
 * Returns:
 *      ql local function return status code.
 *
 * Context:
 *      Kernel context.
 */
int
ql_diag_beacon(ql_adapter_state_t *ha, int cmd, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	mcp->mb[0] = MBC_SET_LED_CONFIG;
	if (cmd == QL_BEACON_ENABLE) {
		mcp->mb[7] = 0xE;
	} else if (cmd == QL_BEACON_DISABLE) {
		mcp->mb[7] = 0xD;
	} else {
		return (EIO);
	}
	mcp->out_mb = MBX_7|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;

	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	if (mr != NULL) {
		mr->mb[0] = mcp->mb[0];
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	}

	return (rval);
}


/*
 * ql_serdes_param
 *	Set/Get serdes transmit parameters mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer to mailbox in/out parameters.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_serdes_param(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_SERDES_TRANSMIT_PARAMETERS;
	mcp->mb[1] = mr->mb[1];
	mcp->mb[2] = mr->mb[2];
	mcp->mb[3] = mr->mb[3];
	mcp->mb[4] = mr->mb[4];
	mcp->out_mb = MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_4|MBX_3|MBX_2|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	mr->mb[0] = mcp->mb[0];
	mr->mb[2] = mcp->mb[2];
	mr->mb[3] = mcp->mb[3];
	mr->mb[4] = mcp->mb[4];

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_timeout_parameters
 *	Issue get timeout parameters mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer to mailbox in/out parameters.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_timeout_parameters(ql_adapter_state_t *ha, uint16_t *tov)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_GET_TIMEOUT_PARAMETERS;
	mcp->mb[1] = ha->fcoe_fcf_idx;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_3|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);
	if (rval == QL_SUCCESS) {
		/* Get 2 * R_A_TOV in seconds */
		if (CFG_IST(ha, CFG_CTRL_22XX) || mcp->mb[3] == 0) {
			*tov = R_A_TOV_DEFAULT;
		} else {
			*tov = (uint16_t)(mcp->mb[3] / 10);
			if (mcp->mb[3] % 10 != 0) {
				*tov = (uint16_t)(*tov + 1);
			}
			/*
			 * Adjust value to prevent driver timeout at the same
			 * time as device.
			 */
			*tov = (uint16_t)(*tov + 5);
		}
	} else {
		*tov = R_A_TOV_DEFAULT;
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_stop_firmware
 *	 Issue stop firmware Mailbox Command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_stop_firmware(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_STOP_FIRMWARE;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = 2;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_read_sfp
 *	Issue Read SFP Mailbox command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mem:	pointer to dma memory object for command.
 *	dev:	Device address (A0h or A2h).
 *	addr:	Data address on SFP EEPROM (0-255).
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_read_sfp(ql_adapter_state_t *ha, dma_mem_t *mem, uint16_t dev,
    uint16_t addr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_READ_SFP;
	mcp->mb[1] = dev;
	mcp->mb[2] = MSW(mem->cookies->dmac_address);
	mcp->mb[3] = LSW(mem->cookies->dmac_address);
	mcp->mb[6] = MSW(mem->cookies->dmac_notused);
	mcp->mb[7] = LSW(mem->cookies->dmac_notused);
	mcp->mb[8] = LSW(mem->size);
	mcp->mb[9] = addr;
	mcp->out_mb = MBX_10|MBX_9|MBX_8|MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	(void) ddi_dma_sync(mem->dma_handle, 0, mem->size,
	    DDI_DMA_SYNC_FORKERNEL);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_iidma_rate
 *	Issue get/set iidma rate command
 *
 * Input:
 *	ha:		adapter state pointer.
 *	loop_id:	n-port handle to set/get iidma rate.
 *	idma_rate:	Pointer to iidma rate.
 *	option:		iidma firmware option (set or get data).
 *				0 --> Get iidma rate
 *				1 --> Set iidma rate
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_iidma_rate(ql_adapter_state_t *ha, uint16_t loop_id, uint32_t *idma_rate,
    uint32_t option)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_PORT_PARAM;
	mcp->mb[1] = loop_id;
	mcp->mb[2] = (uint16_t)option;
	mcp->out_mb = MBX_0|MBX_1|MBX_2;
	mcp->in_mb = MBX_0|MBX_1;

	if (option & BIT_0) {
		mcp->mb[3] = (uint16_t)*idma_rate;
		mcp->out_mb |= MBX_3;
	} else {
		mcp->in_mb |= MBX_3;
	}

	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, mb1=%xh\n", rval, mcp->mb[1]);
	} else {
		if (option == 0) {
			*idma_rate = mcp->mb[3];
		}

		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_set_xmit_parms
 *	Set transmit parameters
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_set_xmit_parms(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_XMIT_PARM;
	mcp->mb[1] = BIT_1;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_fw_etrace
 *	Firmware extended tracing.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mem:	pointer to dma memory object for command.
 *	opt:	options and opcode.
 *	mr:	pointer to mailbox in/out parameters.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_fw_etrace(ql_adapter_state_t *ha, dma_mem_t *mem, uint16_t opt,
    ql_mbx_data_t *mr)
{
	int		rval = QL_SUCCESS;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;
	uint16_t	op_code;
	uint64_t	time;

	QL_PRINT_3(ha, "started\n");

	/* currently no supported options */
	op_code = (uint16_t)(opt & ~0xFF00);

	mcp->mb[0] = MBC_TRACE_CONTROL;
	mcp->mb[1] = op_code;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;

	switch (op_code) {
	case FTO_INSERT_TIME_STAMP:

		(void) drv_getparm(TIME, &time);

		EL(ha, "insert time: %x %xh\n", MSD(time), LSD(time));

		mcp->mb[2] = LSW(LSD(time));
		mcp->mb[3] = MSW(LSD(time));
		mcp->mb[4] = LSW(MSD(time));
		mcp->mb[5] = MSW(MSD(time));
		mcp->out_mb = MBX_0_THRU_5;
		break;

	case FTO_FCE_TRACE_ENABLE:
		/* Firmware Fibre Channel Event Trace Buffer */
		mcp->mb[2] = LSW(mem->cookies->dmac_address);
		mcp->mb[3] = MSW(mem->cookies->dmac_address);
		mcp->mb[4] = LSW(mem->cookies->dmac_notused);
		mcp->mb[5] = MSW(mem->cookies->dmac_notused);
		mcp->mb[6] = (uint16_t)(mem->size / 0x4000);	/* 16kb blks */
		mcp->mb[8] = (uint16_t)ha->fwfcetraceopt;
		mcp->mb[9] = FTO_FCEMAXTRACEBUF;
		mcp->mb[10] = FTO_FCEMAXTRACEBUF;
		mcp->out_mb = MBX_0_THRU_10;
		break;

	case FTO_EXT_TRACE_ENABLE:
		/* Firmware Extended Trace Buffer */
		mcp->mb[2] = LSW(mem->cookies->dmac_address);
		mcp->mb[3] = MSW(mem->cookies->dmac_address);
		mcp->mb[4] = LSW(mem->cookies->dmac_notused);
		mcp->mb[5] = MSW(mem->cookies->dmac_notused);
		mcp->mb[6] = (uint16_t)(mem->size / 0x4000);	/* 16kb blks */
		mcp->out_mb = MBX_0_THRU_7;
		break;

	case FTO_FCE_TRACE_DISABLE:
		/* also causes ISP25xx to flush its internal FCE buffer. */
		mcp->mb[2] = BIT_0;
		mcp->out_mb = MBX_0_THRU_2;
		break;

	case FTO_EXT_TRACE_DISABLE:
		/* just sending the opcode disables it */
		break;

	default:
		EL(ha, "invalid option: %xh\n", opt);
		rval = QL_PARAMETER_ERROR;
		break;
	}

	if (rval == QL_SUCCESS) {
		rval = ql_mailbox_command(ha, mcp);
	}

	/* Return mailbox data. */
	if (mr != NULL) {
		mr->mb[0] = mcp->mb[0];
		mr->mb[1] = mcp->mb[1];
		mr->mb[2] = mcp->mb[2];
		mr->mb[3] = mcp->mb[3];
		mr->mb[4] = mcp->mb[4];
		mr->mb[5] = mcp->mb[5];
		mr->mb[6] = mcp->mb[6];
		mr->mb[7] = mcp->mb[7];
		mr->mb[8] = mcp->mb[8];
		mr->mb[9] = mcp->mb[9];
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_reset_menlo
 *	 Reset Menlo Mailbox Command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer to mailbox in/out parameters.
 *	opt:	options.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_reset_menlo(ql_adapter_state_t *ha, ql_mbx_data_t *mr, uint16_t opt)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_RESET_MENLO;
	mcp->mb[1] = opt;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	if (mr != NULL) {
		mr->mb[0] = mcp->mb[0];
		mr->mb[1] = mcp->mb[1];
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_restart_mpi
 *	The Restart MPI Firmware Mailbox Command will reset the MPI RISC,
 *	reload MPI firmware from Flash, and execute the firmware.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_restart_mpi(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_RESTART_MPI;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	if (rval != QL_SUCCESS) {
		EL(ha, "status=%xh, mbx1=%xh\n", rval, mcp->mb[1]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_idc_request
 *	Inter-Driver Communication Request.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_idc_request(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_IDC_REQUEST;
	mcp->mb[1] = mr->mb[1];
	mcp->mb[2] = mr->mb[2];
	mcp->mb[3] = mr->mb[3];
	mcp->mb[4] = mr->mb[4];
	mcp->mb[5] = mr->mb[5];
	mcp->mb[6] = mr->mb[6];
	mcp->mb[7] = mr->mb[7];
	mcp->out_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_2|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		mr->mb[2] = mcp->mb[2];
		QL_PRINT_3(ha, "done\n");
	} else {
		EL(ha, "status=%xh, mbx2=%xh\n", rval, mcp->mb[2]);
	}

	return (rval);
}

/*
 * ql_idc_ack
 *	Inter-Driver Communication Acknowledgement.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_idc_ack(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_IDC_ACK;
	mcp->mb[1] = ha->idc_mb[1];
	mcp->mb[2] = ha->idc_mb[2];
	mcp->mb[3] = ha->idc_mb[3];
	mcp->mb[4] = ha->idc_mb[4];
	mcp->mb[5] = ha->idc_mb[5];
	mcp->mb[6] = ha->idc_mb[6];
	mcp->mb[7] = ha->idc_mb[7];
	mcp->out_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	QL_PRINT_3(ha, "done\n");

	return (rval);
}

/*
 * ql_idc_time_extend
 *	Inter-Driver Communication Time Extend
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_idc_time_extend(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_IDC_TIME_EXTEND;
	mcp->mb[1] = ha->idc_mb[1];
	mcp->mb[2] = ha->idc_mb[2];
	mcp->mb[3] = ha->idc_mb[3];
	mcp->mb[4] = ha->idc_mb[4];
	mcp->mb[5] = ha->idc_mb[5];
	mcp->mb[6] = ha->idc_mb[6];
	mcp->mb[7] = ha->idc_mb[7];
	mcp->out_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	QL_PRINT_3(ha, "done\n");

	return (rval);
}

/*
 * ql_port_reset
 *	The Port Reset for the external 10G port associated with this function.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_port_reset(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_PORT_RESET;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	QL_PRINT_3(ha, "done\n");

	return (rval);
}

/*
 * ql_set_port_config
 *	The Set Port Configuration command sets the configuration for the
 *	external 10G port associated with this function.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_set_port_config(ql_adapter_state_t *ha, ql_mbx_data_t *mrp)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_SET_PORT_CONFIG;
	mcp->mb[1] = mrp->mb[1];
	mcp->mb[2] = mrp->mb[2];
	mcp->mb[3] = mrp->mb[3];
	mcp->mb[4] = mrp->mb[4];
	mcp->out_mb = MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	QL_PRINT_3(ha, "done\n");

	return (rval);
}

/*
 * ql_get_port_config
 *	The Get Port Configuration command retrieves the current configuration
 *	for the external 10G port associated with this function.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_port_config(ql_adapter_state_t *ha, ql_mbx_data_t *mrp)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_GET_PORT_CONFIG;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		if (mrp != NULL) {
			mrp->mb[1] = mcp->mb[1];
			mrp->mb[2] = mcp->mb[2];
			mrp->mb[3] = mcp->mb[3];
			mrp->mb[4] = mcp->mb[4];
		}
		QL_PRINT_3(ha, "done\n");
	} else {
		EL(ha, "status=%xh, mbx1=%xh, mbx2=%xh, mbx3=%xh, mbx4=%xh\n",
		    rval, mcp->mb[1], mcp->mb[2], mcp->mb[3], mcp->mb[4]);
	}

	return (rval);
}

/*
 * ql_flash_access
 *	The Get Port Configuration command retrieves the current configuration
 *	for the external 10G port associated with this function
 *
 * Input:
 *	ha:	adapter state pointer.
 *	cmd:	command.
 *	start:	32bit word address.
 *	end:	32bit word address.
 *	dp:	32bit word pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_flash_access(ql_adapter_state_t *ha, uint16_t cmd, uint32_t start,
    uint32_t end, uint32_t *dp)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started, cmd=%xh\n", cmd);

	mcp->mb[0] = MBC_FLASH_ACCESS;
	mcp->mb[1] = cmd;
	mcp->mb[2] = LSW(start);
	mcp->mb[3] = MSW(start);
	mcp->mb[4] = LSW(end);
	mcp->mb[5] = MSW(end);

	mcp->out_mb = MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0_THRU_4;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "cmd=%xh, status=%xh, mbx1=%xh, mbx2=%xh, mbx3=%xh, "
		    "mbx4=%xh\n", cmd, rval, mcp->mb[1], mcp->mb[2],
		    mcp->mb[3], mcp->mb[4]);
	} else {
		if (dp != NULL) {
			*dp = (uint32_t)mcp->mb[1];
		}
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_xgmac_stats
 *	Issue et XGMAC Statistics Mailbox command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	size:	size of data buffer.
 *	bufp:	data pointer for DMA data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_xgmac_stats(ql_adapter_state_t *ha, size_t size, caddr_t bufp)
{
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
	    (uint32_t)size)) != QL_SUCCESS) {
		EL(ha, "setup_mbox_dma_resources failed: %xh\n", rval);
		return (QL_MEMORY_ALLOC_FAILED);
	}

	mcp->mb[0] = MBC_GET_XGMAC_STATS;
	mcp->mb[2] = MSW(mem_desc.cookie.dmac_address);
	mcp->mb[3] = LSW(mem_desc.cookie.dmac_address);
	mcp->mb[6] = MSW(mem_desc.cookie.dmac_notused);
	mcp->mb[7] = LSW(mem_desc.cookie.dmac_notused);
	mcp->mb[8] = (uint16_t)(size >> 2);
	mcp->out_mb = MBX_8|MBX_7|MBX_6|MBX_3|MBX_2|MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ql_get_mbox_dma_data(&mem_desc, bufp);
	}
	ql_free_dma_resource(ha, &mem_desc);

	if (rval != QL_SUCCESS) {
		EL(ha, "status=%xh, mbx1=%xh, mbx2=%xh\n", rval, mcp->mb[1],
		    mcp->mb[2]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_dcbx_params
 *	Issue get DCBX parameters mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	size:	size of data buffer.
 *	bufp:	data pointer for DMA data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_dcbx_params(ql_adapter_state_t *ha, uint32_t size, caddr_t bufp)
{
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc, size)) !=
	    QL_SUCCESS) {
		EL(ha, "failed=%xh\n", QL_MEMORY_ALLOC_FAILED);
		return (QL_MEMORY_ALLOC_FAILED);
	}

	mcp->mb[0] = MBC_GET_DCBX_PARAMS;
	mcp->mb[1] = 0;	/* Return all DCBX paramters */
	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[8] = (uint16_t)size;
	mcp->out_mb = MBX_8|MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ql_get_mbox_dma_data(&mem_desc, bufp);
	}

	ql_free_dma_resource(ha, &mem_desc);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}
/*
 * ql_get_fcf_list
 *	Issue get FCF list mailbox command.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	fcf_list:	pointer to ql_fcf_list_desc_t
 *	bufp:		data pointer for DMA data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */

int
ql_get_fcf_list_mbx(ql_adapter_state_t *ha, ql_fcf_list_desc_t *fcf_list,
    caddr_t bufp)
{
	int		rval;
	dma_mem_t	mem_desc;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
	    fcf_list->buffer_size)) !=
	    QL_SUCCESS) {
		EL(ha, "failed=%xh\n", QL_MEMORY_ALLOC_FAILED);
		return (QL_MEMORY_ALLOC_FAILED);
	}

	mcp->mb[0] = MBC_GET_FCF_LIST;
	mcp->mb[1] = fcf_list->options;
	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[8] = (uint16_t)fcf_list->buffer_size;
	mcp->mb[9] = fcf_list->fcf_index;
	mcp->out_mb = MBX_9|MBX_8|MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ql_get_mbox_dma_data(&mem_desc, bufp);
		fcf_list->buffer_size = (uint16_t)mcp->mb[1];
	}

	ql_free_dma_resource(ha, &mem_desc);

	if (rval != QL_SUCCESS) {
		EL(ha, "status=%xh, mbx1=%xh, mbx2=%xh\n", rval, mcp->mb[1],
		    mcp->mb[2]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_resource_cnts
 *	Issue get Resourse Count mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */

int
ql_get_resource_cnts(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_GET_RESOURCE_COUNTS;
	mcp->out_mb = MBX_9|MBX_1|MBX_0;
	mcp->in_mb = MBX_12|MBX_11|MBX_10|MBX_7|MBX_6|
	    MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	if (mr != NULL) {
		mr->mb[1] = mcp->mb[1];
		mr->mb[2] = mcp->mb[2];
		mr->mb[3] = mcp->mb[3];
		mr->mb[6] = mcp->mb[6];
		mr->mb[7] = mcp->mb[7];
		mr->mb[10] = mcp->mb[10];
		mr->mb[11] = mcp->mb[11];
		mr->mb[12] = mcp->mb[12];
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_toggle_interrupt
 *	 Issue Toggle Interrupt Mailbox Command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	opt:	0 = disable, 1 = enable.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_toggle_interrupt(ql_adapter_state_t *ha, uint16_t opt)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_TOGGLE_INTERRUPT;
	mcp->mb[1] = opt;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = 2;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_get_md_template
 *	Issue request mini-dump template Mailbox command
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mem:	pointer to dma memory object for command.
 *	mr:	pointer for return mailboxes.
 *	ofst:	template offset.
 *	opt:	request command code.
 *		GTO_TEMPLATE_SIZE	= Request Template Size.
 *		GTO_TEMPLATE		= Request Template.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_md_template(ql_adapter_state_t *ha, dma_mem_t *mem, ql_mbx_data_t *mr,
    uint32_t ofst, uint16_t opt)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_GET_MD_TEMPLATE;
	mcp->mb[2] = opt;
	if (mem != NULL) {
		mcp->mb[4] = LSW(mem->cookies->dmac_address);
		mcp->mb[5] = MSW(mem->cookies->dmac_address);
		mcp->mb[6] = LSW(mem->cookies->dmac_notused);
		mcp->mb[7] = MSW(mem->cookies->dmac_notused);
		mcp->mb[8] = LSW(mem->size);
		mcp->mb[9] = MSW(mem->size);
	}
	if (ofst != 0) {
		mcp->mb[10] = LSW(ofst);
		mcp->mb[11] = MSW(ofst);
	}
	mcp->out_mb = MBX_11|MBX_10|MBX_9|MBX_8|MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|
	    MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_15|MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_9|MBX_8|
	    MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	if (mr != NULL) {
		mr->mb[0] = mcp->mb[0];
		mr->mb[1] = mcp->mb[1];
		mr->mb[2] = mcp->mb[2];
		mr->mb[3] = mcp->mb[3];
		mr->mb[4] = mcp->mb[4];
		mr->mb[5] = mcp->mb[5];
		mr->mb[6] = mcp->mb[6];
		mr->mb[7] = mcp->mb[7];
		mr->mb[8] = mcp->mb[8];
		mr->mb[9] = mcp->mb[9];
		mr->mb[10] = mcp->mb[10];
		mr->mb[11] = mcp->mb[11];
		mr->mb[12] = mcp->mb[12];
		mr->mb[13] = mcp->mb[13];
		mr->mb[12] = mcp->mb[14];
		mr->mb[13] = mcp->mb[15];
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_init_req_q
 *	 Initialize request queue.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	req_q:	request queue structure pointer.
 *	opt:	Initialize Multiple Queue mailbox command options.
 *
 * Returns:
 *	ql driver local function return status codes
 *
 * Context:
 *	Kernel context.
 */
static int
ql_init_req_q(ql_adapter_state_t *ha, ql_request_q_t *req_q, uint16_t opt)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started, req_q_number=%d\n", req_q->req_q_number);

	if (!(opt & IMO_QOS_UPDATE)) {
		req_q->req_ring_ptr = req_q->req_ring.bp;
		req_q->req_ring_index = 0;
		req_q->req_q_cnt = (uint16_t)(req_q->req_entry_cnt - 1);
		WR32_MBAR_REG(ha, req_q->mbar_req_in, 0);
		if (req_q->req_out_shadow_ptr) {
			*req_q->req_out_shadow_ptr = 0;
		}
	}

	mcp->mb[0] = MBC_INIT_MULTIPLE_QUEUE;
	mcp->mb[1] = (uint16_t)(opt | IMO_QUEUE_NOT_ASSOCIATED);
	mcp->mb[2] = MSW(LSD(req_q->req_ring.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(req_q->req_ring.cookie.dmac_laddress));
	mcp->mb[4] = req_q->req_q_number;
	mcp->mb[5] = req_q->req_entry_cnt;
	mcp->mb[6] = MSW(MSD(req_q->req_ring.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(req_q->req_ring.cookie.dmac_laddress));
	mcp->mb[11] = ha->vp_index;
	mcp->mb[12] = 0;
	mcp->mb[14] = 1;
	mcp->out_mb = MBX_0_THRU_14;
	mcp->in_mb = MBX_0_THRU_1;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "status=%xh, mbx1=%xh\n", rval, mcp->mb[1]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_init_rsp_q
 *	 Initialize response queue.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	rsp_q:	response queue structure pointer.
 *	opt:	Initialize Multiple Queue mailbox command options.
 *
 * Returns:
 *	ql driver local function return status codes
 *
 * Context:
 *	Kernel context.
 */
static int
ql_init_rsp_q(ql_adapter_state_t *ha, ql_response_q_t *rsp_q, uint16_t opt)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started, rsp_q_number=%d\n", rsp_q->rsp_q_number);

	if (!(opt & IMO_DELETE_Q)) {
		rsp_q->rsp_ring_ptr = rsp_q->rsp_ring.bp;
		rsp_q->rsp_ring_index = 0;
		WR32_MBAR_REG(ha, rsp_q->mbar_rsp_out, 0);
		if (rsp_q->rsp_in_shadow_ptr) {
			*rsp_q->rsp_in_shadow_ptr = 0;
		}
	}

	mcp->mb[0] = MBC_INIT_MULTIPLE_QUEUE;
	mcp->mb[1] = (uint16_t)(opt | IMO_QUEUE_NOT_ASSOCIATED |
	    IMO_RESPONSE_Q_SERVICE);
	mcp->mb[2] = MSW(LSD(rsp_q->rsp_ring.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(rsp_q->rsp_ring.cookie.dmac_laddress));
	mcp->mb[4] = rsp_q->rsp_q_number;
	mcp->mb[5] = rsp_q->rsp_entry_cnt;
	mcp->mb[6] = MSW(MSD(rsp_q->rsp_ring.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(rsp_q->rsp_ring.cookie.dmac_laddress));
	mcp->mb[14] = rsp_q->msi_x_vector;
	mcp->out_mb = MBX_0_THRU_14;
	mcp->in_mb = MBX_0_THRU_1;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "status=%xh, mbx1=%xh\n", rval, mcp->mb[1]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_load_flash_image
 *	Load Flash Firmware.
 *
 * Input:
 *	ha:	adapter state pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_load_flash_image(ql_adapter_state_t *ha)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_LOAD_FLASH_IMAGE;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval=%xh, mbx1=%xh, mbx2=%xh\n",
		    rval, mcp->mb[1], mcp->mb[2]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_set_led_config
 *	Set LED Configuration.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_set_led_config(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_SET_LED_CONFIG;
	mcp->mb[1] = mr->mb[1];
	mcp->mb[2] = mr->mb[2];
	mcp->mb[3] = mr->mb[3];
	mcp->mb[4] = mr->mb[4];
	mcp->mb[5] = mr->mb[5];
	mcp->mb[6] = mr->mb[6];
	mcp->out_mb = MBX_0_THRU_6;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}
/*
 * ql_get_led_config
 *	Get LED Configuration.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_led_config(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_GET_LED_CONFIG;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0_THRU_6;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return config data. */
	if (mr != NULL) {
		mr->mb[1] = mcp->mb[1];
		mr->mb[2] = mcp->mb[2];
		mr->mb[3] = mcp->mb[3];
		mr->mb[4] = mcp->mb[4];
		mr->mb[5] = mcp->mb[5];
		mr->mb[6] = mcp->mb[6];
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_led_config
 *	Set/Get Fibre Channel LED Configuration command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	opt:	Options.
 *	led0:	LED 0 configuration.
 *	led1:	LED 1 configuration.
 *	led2:	LED 2 configuration.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	qlc local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_led_config(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int			rval = QL_SUCCESS;
	mbx_cmd_t		mc = {0};
	mbx_cmd_t		*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_FC_LED_CONFIG;
	mcp->mb[1] = mr->mb[1];
	mcp->mb[2] = mr->mb[2];
	mcp->mb[3] = mr->mb[3];
	mcp->mb[4] = mr->mb[4];
	mcp->out_mb = MBX_0_THRU_4;
	mcp->in_mb = MBX_0_THRU_4;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	mr->mb[0] = mcp->mb[0];
	mr->mb[1] = mcp->mb[1];
	mr->mb[2] = mcp->mb[2];
	mr->mb[3] = mcp->mb[3];
	mr->mb[4] = mcp->mb[4];

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval=%xh, mbx1=%xh\n", rval, mcp->mb[1]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_write_remote_reg
 *	Writes a register within another function.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	addr:	address.
 *	data:	data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_write_remote_reg(ql_adapter_state_t *ha, uint32_t addr, uint32_t data)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_10(ha, "started, addr=%xh, data=%xh\n", addr, data);

	mcp->mb[0] = MBC_WRITE_REMOTE_REG;
	mcp->mb[1] = LSW(addr);
	mcp->mb[2] = MSW(addr);
	mcp->mb[3] = LSW(data);
	mcp->mb[4] = MSW(data);
	mcp->out_mb = MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, mbx1=%xh, addr=%xh, data=%xh\n", rval,
		    mcp->mb[1], addr, data);
	} else {
		/*EMPTY*/
		QL_PRINT_10(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_read_remote_reg
 *	Read a register within another function.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	addr:	address.
 *	data:	data pointer.
 *
 * Returns:
 *	qlc local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_read_remote_reg(ql_adapter_state_t *ha, uint32_t addr, uint32_t *dp)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_10(ha, "started, addr=%xh\n", addr);

	mcp->mb[0] = MBC_READ_REMOTE_REG;
	mcp->mb[1] = LSW(addr);
	mcp->mb[2] = MSW(addr);
	mcp->out_mb = MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_4|MBX_3|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, mbx1=%xh, addr=%xh\n", rval, mcp->mb[1],
		    addr);
	} else {
		*dp = SHORT_TO_LONG(mcp->mb[3], mcp->mb[4]);
		QL_PRINT_10(ha, "done, addr=%xh, data=%xh\n", addr, *dp);
	}
	return (rval);
}

/*
 * ql_get_temp
 *	Issue get temperature mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_get_temp(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_GET_PARAMETERS;
	mcp->mb[1] = READ_ASIC_TEMP << 8;
	mcp->out_mb = MBX_0_THRU_1;
	mcp->in_mb = MBX_0_THRU_1;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return config data. */
	if (mr != NULL) {
		mr->mb[1] = mcp->mb[1];
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval=%xh, mbx1=%xh\n", rval, mcp->mb[1]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}
	return (rval);
}

/*
 * ql_write_serdes
 *	Issue write FC serdes register mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_write_serdes(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_WRITE_SERDES_REG;
	mcp->mb[1] = mr->mb[1];
	mcp->mb[2] = mr->mb[2];
	mcp->mb[3] = mr->mb[3];
	mcp->mb[4] = mr->mb[4];
	mcp->mb[5] = mr->mb[5];
	mcp->mb[6] = mr->mb[6];
	mcp->out_mb = MBX_0_THRU_6;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}

/*
 * ql_read_serdes
 *	Issue read FC serdes register mailbox command.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	mr:	pointer for mailbox data.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_read_serdes(ql_adapter_state_t *ha, ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(ha, "started\n");

	mcp->mb[0] = MBC_READ_SERDES_REG;
	mcp->mb[1] = mr->mb[1];
	mcp->mb[2] = mr->mb[2];
	mcp->mb[3] = mr->mb[3];
	mcp->mb[4] = mr->mb[4];
	mcp->mb[5] = mr->mb[5];
	mcp->mb[6] = mr->mb[6];
	mcp->out_mb = MBX_0_THRU_6;
	mcp->in_mb = MBX_0_THRU_6;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	mr->mb[0] = mcp->mb[0];
	mr->mb[1] = mcp->mb[1];
	mr->mb[2] = mcp->mb[2];
	mr->mb[3] = mcp->mb[3];
	mr->mb[4] = mcp->mb[4];
	mr->mb[4] = mcp->mb[5];
	mr->mb[4] = mcp->mb[6];

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval=%xh", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(ha, "done\n");
	}

	return (rval);
}
