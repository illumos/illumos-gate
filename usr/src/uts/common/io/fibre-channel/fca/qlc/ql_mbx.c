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

/* Copyright 2008 QLogic Corporation */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"Copyright 2008 QLogic Corporation; ql_mbx.c"

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver source file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2008 QLOGIC CORPORATION		**
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
#include <ql_xioctl.h>

/*
 * Local data
 */

/*
 * Local prototypes
 */
static int ql_mailbox_command(ql_adapter_state_t *, mbx_cmd_t *);
static int ql_task_mgmt_iocb(ql_adapter_state_t *, ql_tgt_t *, uint16_t,
    uint32_t, uint16_t);
static int ql_abort_cmd_iocb(ql_adapter_state_t *, ql_srb_t *);
static int ql_setup_mbox_dma_transfer(ql_adapter_state_t *, dma_mem_t *,
    caddr_t, uint32_t);
static int ql_setup_mbox_dma_resources(ql_adapter_state_t *, dma_mem_t *,
    uint32_t);
static void ql_setup_mbox_dma_data(dma_mem_t *, caddr_t);
static void ql_get_mbox_dma_data(dma_mem_t *, caddr_t);

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

	ASSERT(!MUTEX_HELD(&ha->mutex));

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Acquire mailbox register lock. */
	MBX_REGISTER_LOCK(ha);

	/* Check for mailbox available, if not wait for signal. */
	while (ha->mailbox_flags & MBX_BUSY_FLG) {
		ha->mailbox_flags = (uint8_t)
		    (ha->mailbox_flags | MBX_WANT_FLG);

		if (ha->task_daemon_flags & TASK_DAEMON_POWERING_DOWN) {
			EL(vha, "failed availability cmd=%xh\n", mcp->mb[0]);
			MBX_REGISTER_UNLOCK(ha);
			return (QL_LOCK_TIMEOUT);
		}

		/* Set timeout after command that is running. */
		timer = ddi_get_lbolt();
		timer += (mcp->timeout + 20) * drv_usectohz(1000000);
		cv_stat = cv_timedwait_sig(&ha->cv_mbx_wait,
		    &ha->mbx_mutex, timer);
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
			WRT16_IO_REG(ha, mailbox[cnt], mcp->mb[cnt]);
		}
		data >>= 1;
	}

	/* Issue set host interrupt command. */
	ha->mailbox_flags = (uint8_t)(ha->mailbox_flags & ~MBX_INTERRUPT);
	CFG_IST(ha, CFG_CTRL_2425) ?
	    WRT32_IO_REG(ha, hccr, HC24_SET_HOST_INT) :
	    WRT16_IO_REG(ha, hccr, HC_SET_HOST_INT);

	/* Wait for command to complete. */
	if (ha->flags & INTERRUPTS_ENABLED &&
	    !(ha->task_daemon_flags & (TASK_THREAD_CALLED |
	    TASK_DAEMON_POWERING_DOWN)) &&
	    !ddi_in_panic()) {
		while (!(ha->mailbox_flags & (MBX_INTERRUPT | MBX_ABORT)) &&
		    !(ha->task_daemon_flags & ISP_ABORT_NEEDED)) {

			/* 30 seconds from now */
			timer = ddi_get_lbolt();
			timer += mcp->timeout * drv_usectohz(1000000);
			if (cv_timedwait(&ha->cv_mbx_intr, &ha->mbx_mutex,
			    timer) == -1) {
				/*
				 * The timeout time 'timer' was
				 * reached without the condition
				 * being signaled.
				 */
				break;
			}
		}
	} else {
		/* Release mailbox register lock. */
		MBX_REGISTER_UNLOCK(ha);

		/* Acquire interrupt lock. */
		for (timer = mcp->timeout * 100; timer; timer--) {
			/* Check for pending interrupts. */
			while (RD16_IO_REG(ha, istatus) & RISC_INT) {
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
		if (CFG_IST(ha, CFG_DUMP_MAILBOX_TIMEOUT)) {
			(void) ql_binary_fw_dump(ha, FALSE);
		}
		EL(vha, "command timeout, isp_abort_needed\n");
		set_flags |= ISP_ABORT_NEEDED;
		rval = QL_FUNCTION_TIMEOUT;
	} else {
		ha->mailbox_flags = (uint8_t)
		    (ha->mailbox_flags & ~MBX_INTERRUPT);

		rval = mcp->mb[0];
	}

	/* reset outbound to risc mailbox registers. */
	data = (mcp->out_mb >> 1);
	for (cnt = 1; cnt < ha->reg_off->mbox_cnt && data; cnt++) {
		if (data & MBX_0) {
			WRT16_IO_REG(ha, mailbox[cnt], (uint16_t)0);
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
		EL(vha, "failed, rval=%xh, mcp->mb[0]=%xh\n", rval,
		    mcp->mb[0]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
	    MEM_RING_ALIGN)) != QL_SUCCESS) {
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, (CFG_CTRL_6322 | CFG_CTRL_25XX)) ||
	    ha->vp_index != 0) {
		ha->flags &= ~IP_INITIALIZED;
		EL(ha, "HBA does not support IP\n");
		return (QL_FUNCTION_FAILED);
	}

	ha->rcvbuf_ring_ptr = ha->rcvbuf_ring_bp;
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}
	return (rval);
}

/*
 * ql_loop_back
 *	Issue diagnostic loop back frame mailbox command.
 *
 * Input:
 *	ha = adapter state pointer.
 *	lb = loop back parameter structure pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
#ifndef apps_64bit
int
ql_loop_back(ql_adapter_state_t *ha, lbp_t *lb, uint32_t h_xmit,
    uint32_t h_rcv)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_DIAGNOSTIC_LOOP_BACK;
	mcp->mb[1] = lb->options;
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
	    MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_7|MBX_6|MBX_1|MBX_0;
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}
#else
int
ql_loop_back(ql_adapter_state_t *ha, lbp_t *lb)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_DIAGNOSTIC_LOOP_BACK;
	mcp->mb[1] = lb->options;
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
	    MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_7|MBX_6|MBX_1|MBX_0;
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
 *	echo_pt:	echo parameter structure pointer.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_echo(ql_adapter_state_t *ha, echo_t *echo_pt)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_ECHO;			/* ECHO command */
	mcp->mb[1] = echo_pt->options;		/* command options; 64 bit */
						/* addressing (bit 6) and */
						/* real echo (bit 15 */

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
	} else {
		mcp->mb[6] = 0;		/* bits 63-48 */
		mcp->mb[7] = 0;		/* bits 47-32 */
		mcp->mb[20] = 0;	/* bits 63-48 */
		mcp->mb[21] = 0;	/* bits 47-32 */
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
	    MBX_7|MBX_6|MBX_1|MBX_0;
	mcp->in_mb = MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;

	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
 *	lun:	LUN.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_clear_aca(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t lun)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
		rval = ql_task_mgmt_iocb(ha, tq, lun, CF_CLEAR_ACA, 0);
	} else {
		mcp->mb[0] = MBC_CLEAR_ACA;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
		}
		mcp->mb[2] = lun;
		mcp->out_mb = MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	(void) ql_marker(ha, tq->loop_id, lun, MK_SYNC_ID);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
	uint16_t	index;
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
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
					rval = ql_task_mgmt_iocb(ha, tq, 0,
					    CF_TARGET_RESET, delay);

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
			rval = ql_task_mgmt_iocb(ha, tq, 0, CF_TARGET_RESET,
			    delay);
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
 *	qla2x00 local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_abort_target(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t delay)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
 *	lun:	LUN.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_lun_reset(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t lun)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
		rval = ql_task_mgmt_iocb(ha, tq, lun, CF_LUN_RESET, 0);
	} else {
		mcp->mb[0] = MBC_LUN_RESET;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
		}
		mcp->mb[2] = lun;
		mcp->mb[3] = 0;
		mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	(void) ql_marker(ha, tq->loop_id, lun, MK_SYNC_ID);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
 *	lun:	LUN.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_clear_task_set(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t lun)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
		rval = ql_task_mgmt_iocb(ha, tq, lun, CF_CLEAR_TASK_SET, 0);
	} else {
		mcp->mb[0] = MBC_CLEAR_TASK_SET;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
		}
		mcp->mb[2] = lun;
		mcp->out_mb = MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	(void) ql_marker(ha, tq->loop_id, lun, MK_SYNC_ID);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
 *	lun:	LUN.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_abort_task_set(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t lun)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
		rval = ql_task_mgmt_iocb(ha, tq, lun, CF_ABORT_TASK_SET, 0);
	} else {
		mcp->mb[0] = MBC_ABORT_TASK_SET;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
		}
		mcp->mb[2] = lun;
		mcp->out_mb = MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	(void) ql_marker(ha, tq->loop_id, lun, MK_SYNC_ID);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}

/*
 * ql_task_mgmt_iocb
 *	Function issues task management IOCB.
 *
 * Input:
 *	ha:	adapter state pointer.
 *	tq:	target queue pointer.
 *	lun:	LUN.
 *	flags:	control flags.
 *	delay:	seconds.
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context
 */
static int
ql_task_mgmt_iocb(ql_adapter_state_t *ha, ql_tgt_t *tq, uint16_t lun,
    uint32_t flags, uint16_t delay)
{
	ql_mbx_iocb_t	*pkt;
	int		rval;
	uint32_t	pkt_size;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
	pkt->mgmt.fcp_lun[2] = LSB(lun);
	pkt->mgmt.fcp_lun[3] = MSB(lun);
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_LOOP_PORT_BYPASS;

	if (CFG_IST(ha, CFG_CTRL_2425)) {
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_LOOP_PORT_ENABLE;

	if (CFG_IST(ha, CFG_CTRL_2425)) {
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started, d_id=%xh, loop_id=%xh\n",
	    ha->instance, tq->d_id.b24, loop_id);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started, d_id=%xh, loop_id=%xh\n",
	    ha->instance, tq->d_id.b24, loop_id);

	if ((tq->d_id.b24 & 0xffffff) == 0xfffffa) {
		opt = (uint16_t)(opt | LFF_NO_PRLI);
	}

	if (CFG_IST(ha, CFG_CTRL_2425)) {
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
		    "mb2=%04x\n", tq->d_id.b24, loop_id, rval, mr->mb[1],
		    mr->mb[2]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
	ql_mbx_data_t	mr;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
		rval = ql_log_iocb(ha, tq, tq->loop_id, CFO_IMPLICIT_LOGO |
		    CF_CMD_LOGO | CFO_FREE_N_PORT_HANDLE, &mr);
	} else {
		mcp->mb[0] = MBC_LOGOUT_FABRIC_PORT;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = tq->loop_id;
			mcp->mb[10] = 0;
			mcp->out_mb = MBX_10|MBX_1|MBX_0;
		} else {
			mcp->mb[1] = (uint16_t)(tq->loop_id << 8);
			mcp->out_mb = MBX_1|MBX_0;
		}
		mcp->in_mb = MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "d_id=%xh, loop_id=%xh, failed=%xh\n", rval,
		    tq->d_id.b24, tq->loop_id);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
				QL_PRINT_3(CE_CONT, "(%d): status=%xh\n",
				    ha->instance, pkt->log.status);

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
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	ASSERT(!MUTEX_HELD(&ha->mutex));

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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

	if (CFG_IST(ha, CFG_CTRL_2425)) {
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
		if (CFG_IST(ha, CFG_CTRL_2425)) {
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
			rval = QL_FUNCTION_FAILED;
		} else {
			tq->flags = tq->prli_svc_param_word_3 & BIT_4 ?
			    tq->flags & ~TQF_INITIATOR_DEVICE :
			    tq->flags | TQF_INITIATOR_DEVICE;

			if ((tq->flags & TQF_INITIATOR_DEVICE) == 0) {
				tq->flags = tq->prli_svc_param_word_3 & BIT_8 ?
				    tq->flags | TQF_TAPE_DEVICE :
				    tq->flags & ~TQF_TAPE_DEVICE;
			} else {
				tq->flags &= ~TQF_TAPE_DEVICE;
			}
		}
	}

	kmem_free(pd23, PORT_DATABASE_SIZE);

	if (rval != QL_SUCCESS) {
		EL(ha, "d_id=%xh, loop_id=%xh, failed=%xh\n", tq->d_id.b24,
		    tq->loop_id, rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if ((rval = ql_setup_mbox_dma_transfer(ha, &mem_desc, bufp,
	    (uint32_t)size)) != QL_SUCCESS) {
		EL(ha, "failed, setup_mbox_dma_transfer: %x\n", rval);
		return (rval);
	}

	mcp->mb[0] = MBC_SET_PARAMETERS;
	mcp->mb[1] = 0;
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	bzero((caddr_t)mcp, sizeof (mbx_cmd_t));

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
	    (uint32_t)size)) != QL_SUCCESS) {
		return (QL_MEMORY_ALLOC_FAILED);
	}

	mcp->mb[0] = MBC_SEND_RNID_ELS;
	if (CFG_IST(ha, CFG_CTRL_2425)) {
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
	    (uint32_t)size)) != QL_SUCCESS) {
		return (QL_MEMORY_ALLOC_FAILED);
	}

	mcp->mb[0] = MBC_GET_PARAMETERS;
	mcp->mb[1] = 0;
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	do {
		if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
		    (uint32_t)size)) != QL_SUCCESS) {
			EL(ha, "setup_mbox_dma_resources failed: %xh\n", rval);
			return (QL_MEMORY_ALLOC_FAILED);
		}

		mcp->mb[0] = MBC_GET_LINK_STATUS;
		if (CFG_IST(ha, CFG_CTRL_2425)) {
			if (loop_id == ha->loop_id) {
				mcp->mb[0] = MBC_GET_STATUS_COUNTS;
				mcp->mb[8] = (uint16_t)(size >> 2);
				mcp->mb[10] = 0;
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
	    (uint32_t)size)) != QL_SUCCESS) {
		EL(ha, "setup_mbox_dma_resources failed: %x\n", rval);
		return (QL_MEMORY_ALLOC_FAILED);
	}

	if (CFG_IST(ha, CFG_CTRL_2425)) {
		mcp->mb[0] = MBC_GET_STATUS_COUNTS;
		mcp->mb[8] = (uint16_t)(size / 4);
		mcp->mb[10] = 0;
		mcp->out_mb = MBX_10|MBX_8;
	} else {
		mcp->mb[0] = MBC_GET_LINK_STATUS;

		/* allows reporting when link is down */
		if (CFG_IST(ha, CFG_CTRL_2200) == 0) {
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): entered\n", ha->instance);

	mcp->mb[0] = MBC_RESET_LINK_STATUS;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
		mcp->mb[0] = MBC_LIP_FULL_LOGIN;
		mcp->mb[1] = BIT_4;
		mcp->mb[2] = 0;
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_LIP_FULL_LOGIN;
	mcp->mb[1] = (uint16_t)(CFG_IST(ha, CFG_CTRL_2425) ? BIT_3 : 0);
	mcp->mb[2] = 0;
	mcp->mb[3] = 0;
	mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
		mcp->mb[0] = MBC_LIP_FULL_LOGIN;
		mcp->mb[1] = BIT_6;
		mcp->mb[2] = 0;
		mcp->mb[3] = ha->loop_reset_delay;
		mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	} else {
		mcp->mb[0] = MBC_LIP_RESET;
		if (CFG_IST(ha, CFG_EXT_FW_INTERFACE)) {
			mcp->mb[1] = loop_id;
			mcp->mb[10] = 0;
			mcp->out_mb = MBX_10|MBX_3|MBX_2|MBX_1|MBX_0;
		} else {
			mcp->mb[1] = (uint16_t)(loop_id << 8);
			mcp->out_mb = MBX_3|MBX_2|MBX_1|MBX_0;
		}
		mcp->mb[2] = ha->loop_reset_delay;
		mcp->mb[3] = 0;
	}
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	pkt_size = sizeof (ql_mbx_iocb_t);
	if ((pkt = kmem_zalloc(pkt_size, KM_SLEEP)) == NULL) {
		EL(ha, "failed, kmem_zalloc\n");
		return (QL_MEMORY_ALLOC_FAILED);
	}

	pkt->abo.entry_type = ABORT_CMD_TYPE;
	pkt->abo.entry_count = 1;
	pkt->abo.n_port_hdl = (uint16_t)LE_16(tq->loop_id);
	pkt->abo.options = AF_NO_ABTS;
	pkt->abo.cmd_handle = LE_32(sp->handle);
	pkt->abo.target_id[0] = tq->d_id.b.al_pa;
	pkt->abo.target_id[1] = tq->d_id.b.area;
	pkt->abo.target_id[2] = tq->d_id.b.domain;
	pkt->abo.vp_index = ha->vp_index;

	rval = ql_issue_mbx_iocb(ha, (caddr_t)pkt, pkt_size);

	if (rval == QL_SUCCESS && (pkt->abo.entry_status  & 0x3c) != 0) {
		EL(ha, "failed, entry_status=%xh, d_id=%xh\n",
		    pkt->abo.entry_status, tq->d_id.b24);
		rval = QL_FUNCTION_PARAMETER_ERROR;
	}

	comp_status = (uint16_t)LE_16(pkt->abo.n_port_hdl);
	if (rval == QL_SUCCESS && comp_status != CS_COMPLETE) {
		EL(ha, "failed, comp_status=%xh, d_id=%xh\n",
		    comp_status, tq->d_id.b24);
		rval = QL_FUNCTION_FAILED;
	}

	kmem_free(pkt, pkt_size);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh, d_id=%xh\n", rval, tq->d_id.b24);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_VERIFY_CHECKSUM;
	if (CFG_IST(ha, CFG_CTRL_2425)) {
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if ((rval = ql_setup_mbox_dma_resources(ha, &mem_desc,
	    (uint32_t)size)) != QL_SUCCESS) {
		EL(ha, "setup_mbox_dma_resources failed: %xh\n", rval);
		return (QL_MEMORY_ALLOC_FAILED);
	}

	mcp->mb[0] = MBC_GET_ID_LIST;
	if (CFG_IST(ha, CFG_CTRL_2425)) {
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
		mcp->mb[0] = MBC_LOAD_RAM_EXTENDED;
		mcp->mb[4] = MSW(word_count);
		mcp->mb[5] = LSW(word_count);
		mcp->mb[6] = MSW(MSD(bp));
		mcp->mb[7] = LSW(MSD(bp));
		mcp->mb[8] = MSW(risc_address);
		mcp->out_mb = MBX_8|MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|
		    MBX_0;
	} else {
		mcp->mb[0] = MBC_LOAD_RAM;
		mcp->mb[4] = LSW(word_count);
		mcp->out_mb = MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	}
	mcp->mb[1] = LSW(risc_address);
	mcp->mb[2] = MSW(LSD(bp));
	mcp->mb[3] = LSW(LSD(bp));
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;

	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed, rval = %xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);


	if ((rval = ql_setup_mbox_dma_transfer(ha, &mem_desc, bp, size)) !=
	    QL_SUCCESS) {
		EL(ha, "setup_mbox_dma_transfer failed: %x\n", rval);
		return (rval);
	}

	mcp->mb[0] = MBC_EXECUTE_IOCB;
	mcp->mb[1] = 0;
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (mr != NULL) {
		mcp->mb[0] = MBC_MAILBOX_REGISTER_TEST;
		mcp->mb[1] = mr->mb[1];
		mcp->mb[2] = mr->mb[2];
		mcp->mb[3] = mr->mb[3];
		mcp->mb[4] = mr->mb[4];
		mcp->mb[5] = mr->mb[5];
		mcp->mb[6] = mr->mb[6];
		mcp->mb[7] = mr->mb[7];
		mcp->out_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);
		if (rval == QL_SUCCESS) {
			mr->mb[1] = mcp->mb[1];
			mr->mb[2] = mcp->mb[2];
			mr->mb[3] = mcp->mb[3];
			mr->mb[4] = mcp->mb[4];
			mr->mb[5] = mcp->mb[5];
			mr->mb[6] = mcp->mb[6];
			mr->mb[7] = mcp->mb[7];
		}
	} else {
		rval = QL_FUNCTION_PARAMETER_ERROR;
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
 *	qla2x00 local function return status code.
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_EXECUTE_FIRMWARE;
	if (CFG_IST(ha, CFG_CTRL_2425)) {
		mcp->mb[1] = MSW(ha->risc_fw[0].addr);
		mcp->mb[2] = LSW(ha->risc_fw[0].addr);
	} else {
		mcp->mb[1] = LSW(ha->risc_fw[0].addr);
		mcp->mb[2] = 0;
	}
	mcp->mb[3] = 0;
	mcp->mb[4] = 0;
	mcp->out_mb = MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (CFG_IST(ha, CFG_CTRL_2200)) {
		rval = QL_SUCCESS;
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
		QL_PRINT_9(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
		WRT32_IO_REG(ha, req_in, 0);
		WRT32_IO_REG(ha, resp_out, 0);
		WRT32_IO_REG(ha, pri_req_in, 0);
		WRT32_IO_REG(ha, atio_req_out, 0);
	} else {
		WRT16_IO_REG(ha, req_in, 0);
		WRT16_IO_REG(ha, resp_out, 0);
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
		mcp->mb[1] = (uint16_t)(CFG_IST(ha, CFG_CTRL_2200) ?
		    0x204c : 0x52);
	} else {
		mcp->mb[1] = 0;
	}

	mcp->mb[2] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[3] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[4] = 0;
	mcp->mb[5] = 0;
	mcp->mb[6] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->out_mb = MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->in_mb = MBX_0|MBX_2;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval == QL_SUCCESS) {
		ha->sfp_stat = mcp->mb[2];
	}
	ql_free_dma_resource(ha, &mem_desc);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_GET_FIRMWARE_STATE;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	if (mr != NULL) {
		mr->mb[1] = mcp->mb[1];
		mr->mb[2] = mcp->mb[2];
		mr->mb[3] = mcp->mb[3];
	}

	ha->sfp_stat = mcp->mb[2];

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_GET_ID;
	mcp->out_mb = MBX_0;
	if (ha->flags & VP_ENABLED) {
		mcp->mb[9] = ha->vp_index;
		mcp->out_mb |= MBX_9;
	}
	mcp->in_mb = MBX_7|MBX_6|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
	if (mr != NULL) {
		mr->mb[1] = mcp->mb[1];
		mr->mb[1] = (uint16_t)(CFG_IST(ha, CFG_CTRL_2425) ?
		    0xffff : mcp->mb[1]);
		mr->mb[2] = mcp->mb[2];
		mr->mb[3] = mcp->mb[3];
		mr->mb[6] = mcp->mb[6];
		mr->mb[7] = mcp->mb[7];
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
ql_get_fw_version(ql_adapter_state_t *ha,  ql_mbx_data_t *mr)
{
	int		rval;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_ABOUT_FIRMWARE;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_6|MBX_5|MBX_4|MBX_3|MBX_2|MBX_1|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	/* Return mailbox data. */
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (mr != NULL) {
		mcp->mb[0] = MBC_DATA_RATE;
		mcp->mb[1] = mr->mb[1];
		mcp->mb[2] = mr->mb[2];
		mcp->out_mb = MBX_2|MBX_1|MBX_0;
		mcp->in_mb = MBX_2|MBX_1|MBX_0;
		mcp->timeout = MAILBOX_TOV;
		rval = ql_mailbox_command(ha, mcp);

		/* Return mailbox data. */
		mr->mb[1] = mcp->mb[1];
		mr->mb[2] = mcp->mb[2];
	} else {
		rval = QL_FUNCTION_PARAMETER_ERROR;
	}

	ha->sfp_stat = mcp->mb[2];

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);


	if ((rval = ql_setup_mbox_dma_transfer(ha, &mem_desc, bp, size)) !=
	    QL_SUCCESS) {
		EL(ha, "setup_mbox_dma_transfer failed: %x\n", rval);
		return (rval);
	}

	mcp->mb[0] = MBC_DIAGNOSTIC_LOOP_BACK;
	mcp->mb[1] = opt;
	mcp->mb[2] = 0;
	mcp->mb[3] = 0;
	mcp->mb[6] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[7] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[10] = LSW(size);
	mcp->mb[11] = MSW(size);
	mcp->mb[12] = 0;
	mcp->mb[13] = 0;
	mcp->mb[14] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[15] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[16] = LSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[17] = MSW(LSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[18] = LSW(it_cnt);
	mcp->mb[19] = MSW(it_cnt);
	mcp->mb[20] = LSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->mb[21] = MSW(MSD(mem_desc.cookie.dmac_laddress));
	mcp->out_mb = MBX_21|MBX_20|MBX_19|MBX_18|MBX_17|MBX_16|MBX_15|
	    MBX_14|MBX_13|MBX_12|MBX_11|MBX_10|MBX_3|MBX_2|MBX_1|MBX_0;
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
		EL(ha, "failed=%xh, mb1=%xh\n", rval,
		    mcp->mb[1]);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if ((rval = ql_setup_mbox_dma_transfer(ha, &mem_desc, bp, size)) !=
	    QL_SUCCESS) {
		EL(ha, "setup_mbox_dma_transfer failed: %x\n", rval);
		return (rval);
	}

	mcp->mb[0] = MBC_ECHO;
	mcp->mb[1] = opt;
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
	    MBX_14|MBX_10|MBX_7|MBX_6|MBX_1|MBX_0;
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
	if (mr != NULL) {
		mr->mb[0] = mcp->mb[0];
		mr->mb[2] = mcp->mb[2];
		mr->mb[3] = mcp->mb[3];
		mr->mb[4] = mcp->mb[4];
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_GET_TIMEOUT_PARAMETERS;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_3|MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);
	if (rval == QL_SUCCESS) {
		/* Get 2 * R_A_TOV in seconds */
		if (CFG_IST(ha, CFG_CTRL_2200) || mcp->mb[3] == 0) {
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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	mcp->mb[0] = MBC_STOP_FIRMWARE;
	mcp->out_mb = MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;
	rval = ql_mailbox_command(ha, mcp);

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
 *	addr:	Data address on SFP EEPROM (0–255).
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

	QL_PRINT_3(CE_CONT, "(%d): entered\n", ha->instance);

	mcp->mb[0] = MBC_READ_SFP;
	mcp->mb[1] = dev;
	mcp->mb[2] = MSW(mem->cookies->dmac_address);
	mcp->mb[3] = LSW(mem->cookies->dmac_address);
	mcp->mb[6] = MSW(mem->cookies->dmac_notused);
	mcp->mb[7] = LSW(mem->cookies->dmac_notused);
	mcp->mb[8] = LSW(mem->size);
	mcp->mb[9] = addr;
	mcp->mb[10] = 0;
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
		QL_PRINT_3(CE_CONT, "(%d): exiting\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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

		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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
 *	opt:	options.
 *		FTO_EXTENABLE
 *		FTO_EXTDISABLE
 *		FTO_FCEENABLE
 *		FTO_FCEDISABLE
 *
 * Returns:
 *	ql local function return status code.
 *
 * Context:
 *	Kernel context.
 */
int
ql_fw_etrace(ql_adapter_state_t *ha, dma_mem_t *mem, uint16_t opt)
{
	int		rval = QL_SUCCESS;
	mbx_cmd_t	mc = {0};
	mbx_cmd_t	*mcp = &mc;

	QL_PRINT_3(CE_CONT, "(%d): entered\n", ha->instance);

	mcp->mb[0] = MBC_TRACE_CONTROL;
	mcp->mb[1] = opt;
	mcp->out_mb = MBX_1|MBX_0;
	mcp->in_mb = MBX_0;
	mcp->timeout = MAILBOX_TOV;

	switch (opt) {
	case FTO_FCEENABLE:
	case FTO_EXTENABLE:
		mcp->mb[2] = LSW(mem->cookies->dmac_address);
		mcp->mb[3] = MSW(mem->cookies->dmac_address);
		mcp->mb[4] = LSW(mem->cookies->dmac_notused);
		mcp->mb[5] = MSW(mem->cookies->dmac_notused);
		mcp->mb[6] = (uint16_t)(mem->size / 0x4000);	/* 16kb blks */
		mcp->mb[7] = 0;
		mcp->out_mb |= MBX_7|MBX_6|MBX_5|MBX_4|MBX_3|MBX_2;
		if (opt == FTO_FCEENABLE) {
			mcp->mb[8] = (uint16_t)ha->fwfcetraceopt;
			mcp->mb[9] = FTO_FCEMAXTRACEBUF;
			mcp->mb[10] = FTO_FCEMAXTRACEBUF;
			mcp->out_mb |= MBX_10|MBX_9|MBX_8;
		}
		break;

	case FTO_FCEDISABLE:
		mcp->mb[2] = BIT_0;
		mcp->out_mb = MBX_2;
		break;

	case FTO_EXTDISABLE:
		break;

	default:
		EL(ha, "invalid option: %xh\n", opt);
		rval = QL_PARAMETER_ERROR;
		break;
	}

	if (rval == QL_SUCCESS) {
		rval = ql_mailbox_command(ha, mcp);
	}

	if (rval != QL_SUCCESS) {
		EL(ha, "failed=%xh\n", rval);
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
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

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

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
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
	}

	return (rval);
}
