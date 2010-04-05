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
 * Copyright 2010 QLogic Corporation. All rights reserved.
 */

#include <qlge.h>

static int ql_async_event_parser(qlge_t *, mbx_data_t *);

/*
 * Wait upto timeout seconds for Processor Interrupt
 * if timeout is 0, then wait for default waittime
 */
static int
ql_poll_processor_intr(qlge_t *qlge, uint8_t timeout)
{
	int rtn_val = DDI_SUCCESS;

	if (ql_wait_reg_bit(qlge, REG_STATUS, STS_PI, BIT_SET, timeout)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Polling for processor interrupt failed.");
		rtn_val = DDI_FAILURE;
	}
	return (rtn_val);
}

/*
 * Wait for mailbox Processor Register Ready
 */
static int
ql_wait_processor_addr_reg_ready(qlge_t *qlge)
{
	int rtn_val = DDI_SUCCESS;

	if (ql_wait_reg_bit(qlge, REG_PROCESSOR_ADDR,
	    PROCESSOR_ADDRESS_RDY, BIT_SET, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "Wait for processor address register ready timeout.");
		rtn_val = DDI_FAILURE;
	}
	return (rtn_val);
}

/*
 * Read and write MPI registers using the indirect register interface
 * Assume all the locks&semaphore have been acquired
 */
int
ql_write_processor_data(qlge_t *qlge, uint32_t addr, uint32_t data)
{
	int rtn_val = DDI_FAILURE;

	/* wait for processor address register ready */
	if (ql_wait_processor_addr_reg_ready(qlge) == DDI_FAILURE)
		goto out;
	/* write the data to the data reg */
	ql_write_reg(qlge, REG_PROCESSOR_DATA, data);
	/* trigger the write */
	ql_write_reg(qlge, REG_PROCESSOR_ADDR, addr);
	/* wait for register to come ready */
	if (ql_wait_processor_addr_reg_ready(qlge) == DDI_FAILURE)
		goto out;

	rtn_val = DDI_SUCCESS;

out:
	return (rtn_val);

}

/*
 * Read from processor register
 */
int
ql_read_processor_data(qlge_t *qlge, uint32_t addr, uint32_t *data)
{
	int rtn_val = DDI_FAILURE;

	/* enable read operation */
	addr |= PROCESSOR_ADDRESS_READ;
	/* wait for processor address register ready */
	if (ql_wait_processor_addr_reg_ready(qlge) == DDI_FAILURE)
		goto out;

	/* Write read address, wait for data ready in Data register */
	ql_write_reg(qlge, REG_PROCESSOR_ADDR, addr);
	/* wait for data ready */
	if (ql_wait_processor_addr_reg_ready(qlge) == DDI_FAILURE)
		goto out;
	/* read data */
	*data = ql_read_reg(qlge, REG_PROCESSOR_DATA);

	rtn_val = DDI_SUCCESS;

out:
	return (rtn_val);

}

/*
 * Read "count" number of outgoing Mailbox register starting
 * from mailbox #0 if count is 0 then read all mailboxes
 */
static int
ql_read_mailbox_cmd(qlge_t *qlge, mbx_data_t *mbx_buf, uint32_t count)
{
	int rtn_val = DDI_FAILURE;
	uint32_t reg_status;
	uint32_t addr;
	int i;

	if (ql_sem_spinlock(qlge, QL_PROCESSOR_SEM_MASK) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s(%d) get QL_PROCESSOR_SEM_MASK time out error",
		    __func__, qlge->instance);
		return (DDI_FAILURE);
	}

	if (qlge->func_number == qlge->fn0_net)
		addr = FUNC_0_OUT_MAILBOX_0_REG_OFFSET;
	else
		addr = FUNC_1_OUT_MAILBOX_0_REG_OFFSET;

	if (count == 0)
		count = NUM_MAILBOX_REGS;
	for (i = 0; i < count; i++) {
		if (ql_read_processor_data(qlge, addr, &reg_status)
		    == DDI_FAILURE)
			goto out;
		QL_PRINT(DBG_MBX, ("%s(%d) mailbox %d value 0x%x\n",
		    __func__, qlge->instance, i, reg_status));
		mbx_buf->mb[i] = reg_status;
		addr ++;
	}

	rtn_val = DDI_SUCCESS;

out:
	ql_sem_unlock(qlge, QL_PROCESSOR_SEM_MASK);

	return (rtn_val);

}

/*
 * Write mail box command (upto 16) to MPI Firmware
 */
int
ql_issue_mailbox_cmd(qlge_t *qlge, mbx_cmd_t *mbx_cmd)
{
	int rtn_val = DDI_FAILURE;
	uint32_t addr;
	int i;
	/*
	 * Get semaphore to access Processor Address and
	 * Processor Data Registers
	 */
	if (ql_sem_spinlock(qlge, QL_PROCESSOR_SEM_MASK) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	/* ensure no overwriting current command */
	if (ql_wait_reg_bit(qlge, REG_HOST_CMD_STATUS,
	    HOST_TO_MPI_INTR_NOT_DONE, BIT_RESET, 0) != DDI_SUCCESS) {
		goto out;
	}

	if (qlge->func_number == qlge->fn0_net)
		addr = FUNC_0_IN_MAILBOX_0_REG_OFFSET;
	else
		addr = FUNC_1_IN_MAILBOX_0_REG_OFFSET;

	/* wait for mailbox registers to be ready to access */
	if (ql_wait_processor_addr_reg_ready(qlge) == DDI_FAILURE)
		goto out;

	/* issue mailbox command one by one */
	for (i = 0; i < NUM_MAILBOX_REGS; i++) {
		/* write sending cmd to mailbox data register */
		ql_write_reg(qlge, REG_PROCESSOR_DATA, mbx_cmd->mb[i]);
		/* write mailbox address to address register */
		ql_write_reg(qlge, REG_PROCESSOR_ADDR, addr);
		QL_PRINT(DBG_MBX, ("%s(%d) write %x to mailbox(%x) addr %x \n",
		    __func__, qlge->instance, mbx_cmd->mb[i], i, addr));
		addr++;
		/*
		 * wait for mailbox cmd to be written before
		 * next write can start
		 */
		if (ql_wait_processor_addr_reg_ready(qlge) == DDI_FAILURE)
			goto out;
	}
	/* inform MPI that new mailbox commands are available */
	ql_write_reg(qlge, REG_HOST_CMD_STATUS, HOST_CMD_SET_RISC_INTR);
	rtn_val = DDI_SUCCESS;
out:
	ql_sem_unlock(qlge, QL_PROCESSOR_SEM_MASK);
	return (rtn_val);
}

/*
 * Send mail box command (upto 16) to MPI Firmware
 * and polling for MPI mailbox completion response when
 * interrupt is not enabled.
 * The MBX_LOCK mutexe should have been held and released
 * externally
 */
int
ql_issue_mailbox_cmd_and_poll_rsp(qlge_t *qlge, mbx_cmd_t *mbx_cmd,
    mbx_data_t *p_results)
{
	int rtn_val = DDI_FAILURE;
	boolean_t done;
	int max_wait;

	if (mbx_cmd == NULL)
		goto err;

	rtn_val = ql_issue_mailbox_cmd(qlge, mbx_cmd);
	if (rtn_val != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d) ql_issue_mailbox_cmd failed",
		    __func__, qlge->instance);
		goto err;
	}
	done = B_FALSE;
	max_wait = 5; /* wait upto 5 PI interrupt */
	/* delay for the processor interrupt is received */
	while ((done != B_TRUE) && (max_wait--)) {
		/* wait up to 5s for PI interrupt */
		if (ql_poll_processor_intr(qlge, (uint8_t)mbx_cmd->timeout)
		    == DDI_SUCCESS) {
			QL_PRINT(DBG_MBX, ("%s(%d) PI Intr received",
			    __func__, qlge->instance));
			(void) ql_read_mailbox_cmd(qlge, p_results, 0);
			/*
			 * Sometimes, the incoming messages is not what we are
			 * waiting for, ie. async events, then, continue to
			 * wait. If it is the result * of previous mailbox
			 * command, then Done. No matter what, send
			 * HOST_CMD_CLEAR_RISC_TO_HOST_INTR to clear each
			 * PI interrupt
			 */
			if (ql_async_event_parser(qlge, p_results) == B_FALSE) {
				/*
				 * we get what we are waiting for,
				 * clear the interrupt
				 */
				rtn_val = DDI_SUCCESS;
				done = B_TRUE;
			} else {
				/*EMPTY*/
				QL_PRINT(DBG_MBX,
				    ("%s(%d) result ignored, not we wait for\n",
				    __func__, qlge->instance));
			}
			ql_write_reg(qlge, REG_HOST_CMD_STATUS,
			    HOST_CMD_CLEAR_RISC_TO_HOST_INTR);
		} else { /* timeout */
			done = B_TRUE;
		}
		rtn_val = DDI_SUCCESS;
	}
err:
	return (rtn_val);
}
/*
 * Send mail box command (upto 16) to MPI Firmware
 * and wait for MPI mailbox completion response which
 * is saved in interrupt. Thus, this function can only
 * be used after interrupt is enabled.
 * Must hold MBX mutex before calling this function
 */
static int
ql_issue_mailbox_cmd_and_wait_rsp(qlge_t *qlge, mbx_cmd_t *mbx_cmd)
{
	int rtn_val = DDI_FAILURE;
	clock_t timer;
	int i;
	int done = 0;

	if (mbx_cmd == NULL)
		goto err;

	ASSERT(mutex_owned(&qlge->mbx_mutex));

	/* if interrupts are not enabled, poll when results are available */
	if (!(qlge->flags & INTERRUPTS_ENABLED)) {
		rtn_val = ql_issue_mailbox_cmd_and_poll_rsp(qlge, mbx_cmd,
		    &qlge->received_mbx_cmds);
		if (rtn_val == DDI_SUCCESS) {
			for (i = 0; i < NUM_MAILBOX_REGS; i++)
				mbx_cmd->mb[i] = qlge->received_mbx_cmds.mb[i];
		}
	} else {
		rtn_val = ql_issue_mailbox_cmd(qlge, mbx_cmd);
		if (rtn_val != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s(%d) ql_issue_mailbox_cmd failed",
			    __func__, qlge->instance);
			goto err;
		}
		qlge->mbx_wait_completion = 1;
		while (!done && qlge->mbx_wait_completion && !ddi_in_panic()) {
			/* default 5 seconds from now to timeout */
			timer = ddi_get_lbolt();
			if (mbx_cmd->timeout) {
				timer +=
				    mbx_cmd->timeout * drv_usectohz(1000000);
			} else {
				timer += 5 * drv_usectohz(1000000);
			}
			if (cv_timedwait(&qlge->cv_mbx_intr, &qlge->mbx_mutex,
			    timer) == -1) {
				/*
				 * The timeout time 'timer' was
				 * reached or expired without the condition
				 * being signaled.
				 */
				cmn_err(CE_WARN, "%s(%d) Wait for Mailbox cmd "
				    "complete timeout.",
				    __func__, qlge->instance);
				rtn_val = DDI_FAILURE;
				done = 1;
			} else {
				QL_PRINT(DBG_MBX,
				    ("%s(%d) mailbox completion signal received"
				    " \n", __func__, qlge->instance));
				for (i = 0; i < NUM_MAILBOX_REGS; i++) {
					mbx_cmd->mb[i] =
					    qlge->received_mbx_cmds.mb[i];
				}
				rtn_val = DDI_SUCCESS;
				done = 1;
			}
		}
	}
err:
	return (rtn_val);
}

/*
 * Inteprete incoming asynchronous events
 */
static int
ql_async_event_parser(qlge_t *qlge, mbx_data_t *mbx_cmds)
{
	uint32_t link_status, cmd;
	uint8_t link_speed;
	uint8_t link_type;
	boolean_t proc_done = B_TRUE;
	mbx_cmd_t reply_cmd = {0};
	boolean_t fatal_error = B_FALSE;

	switch (mbx_cmds->mb[0]) {
	case MBA_IDC_INTERMEDIATE_COMPLETE /* 1000h */:
		QL_PRINT(DBG_MBX, ("%s(%d):"
		    "MBA_IDC_INTERMEDIATE_COMPLETE received\n",
		    __func__, qlge->instance));
		break;
	case MBA_SYSTEM_ERR /* 8002h */:
		cmn_err(CE_WARN, "%s(%d): MBA_SYSTEM_ERR received",
		    __func__, qlge->instance);
		cmn_err(CE_WARN, "%s(%d): File id %x, Line # %x,"
		    "Firmware Ver# %x",
		    __func__, qlge->instance, mbx_cmds->mb[1],
		    mbx_cmds->mb[2], mbx_cmds->mb[3]);
		fatal_error = B_TRUE;
		(void) ql_8xxx_binary_core_dump(qlge, &qlge->ql_mpi_coredump);
		break;
	case MBA_LINK_UP /* 8011h */:
		QL_PRINT(DBG_MBX, ("%s(%d): MBA_LINK_UP received\n",
		    __func__, qlge->instance));
		link_status = mbx_cmds->mb[1];
		QL_PRINT(DBG_MBX, ("%s(%d): Link Status %x \n",
		    __func__, qlge->instance, link_status));
		link_speed = (uint8_t)((link_status >> 3) & 0x07);

		if (link_speed == 0) {
			qlge->speed = SPEED_100;
			QL_PRINT(DBG_MBX, ("%s(%d):Link speed 100M\n",
			    __func__, qlge->instance));
		} else if (link_speed == 1) {
			qlge->speed = SPEED_1000;
			QL_PRINT(DBG_MBX, ("%s(%d):Link speed 1G\n",
			    __func__, qlge->instance));
		} else if (link_speed == 2) {
			qlge->speed = SPEED_10G;
			QL_PRINT(DBG_MBX, ("%s(%d):Link speed 10G\n",
			    __func__, qlge->instance));
			}

		qlge->link_type = link_type = (uint8_t)(link_status & 0x07);

		if (link_type == XFI_NETWORK_INTERFACE) {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d):Link type XFI_NETWORK_INTERFACE\n",
			    __func__, qlge->instance));
		} else if (link_type == XAUI_NETWORK_INTERFACE) {
			/* EMPTY */
			QL_PRINT(DBG_MBX, ("%s(%d):Link type"
			    "XAUI_NETWORK_INTERFACE\n",
			    __func__, qlge->instance));
		} else if (link_type == XFI_BACKPLANE_INTERFACE) {
			/* EMPTY */
			QL_PRINT(DBG_MBX, ("%s(%d):Link type"
			    "XFI_BACKPLANE_INTERFACE\n",
			    __func__, qlge->instance));
		} else if (link_type == XAUI_BACKPLANE_INTERFACE) {
			/* EMPTY */
			QL_PRINT(DBG_MBX, ("%s(%d):Link type "
			    "XAUI_BACKPLANE_INTERFACE\n",
			    __func__, qlge->instance));
		} else if (link_type == EXT_10GBASE_T_PHY) {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d):Link type EXT_10GBASE_T_PHY\n",
			    __func__, qlge->instance));
		} else if (link_type == EXT_EXT_EDC_PHY) {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d):Link type EXT_EXT_EDC_PHY\n",
			    __func__, qlge->instance));
		} else {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d):unknown Link type \n",
			    __func__, qlge->instance));
		}
		cmn_err(CE_NOTE, "qlge(%d) mpi link up! speed %dMbps\n",
		    qlge->instance, qlge->speed);
		/*
		 * start timer if not started to delay some time then
		 * check if link is really up or down
		 */
		ql_restart_timer(qlge);

		break;
	case MBA_LINK_DOWN /* 8012h */:
		QL_PRINT(DBG_MBX,
		    ("%s(%d): MBA_LINK_DOWN received\n",
		    __func__, qlge->instance));

		link_status = mbx_cmds->mb[1];

		QL_PRINT(DBG_MBX, ("%s(%d): Link Status %x \n",
		    __func__, qlge->instance, link_status));
		if (link_status & 0x1) {
			/* EMPTY */
			QL_PRINT(DBG_MBX, ("%s(%d): Loss of signal \n",
			    __func__, qlge->instance));
		}
		if (link_status & 0x2) {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d): Auto-Negotiation Failed \n",
			    __func__, qlge->instance));
		}
		if (link_status & 0x4) {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d): XTI-Training Failed \n",
			    __func__, qlge->instance));
		}

		cmn_err(CE_NOTE, "qlge(%d) mpi link down!\n", qlge->instance);
		ql_restart_timer(qlge);
		break;
	case MBA_IDC_COMPLETE /* 8100h */:

		QL_PRINT(DBG_MBX,
		    ("%s(%d): MBA_IDC_COMPLETE received\n",
		    __func__, qlge->instance));
		cmd = mbx_cmds->mb[1];
		if (cmd == MBC_STOP_FIRMWARE) {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d): STOP_FIRMWARE event completed\n",
			    __func__, qlge->instance));
		} else if (cmd == MBC_IDC_REQUEST) {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d): IDC_REQUEST event completed\n",
			    __func__, qlge->instance));
		} else if (cmd == MBC_PORT_RESET) {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d): PORT_RESET event completed\n",
			    __func__, qlge->instance));
		} else if (cmd == MBC_SET_PORT_CONFIG) {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d): SET_PORT_CONFIG event "
			    "completed\n", __func__, qlge->instance));
		} else {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d): unknown IDC completion request"
			    " event %x %x\n", __func__, qlge->instance,
			    mbx_cmds->mb[1], mbx_cmds->mb[2]));
		}
		proc_done = B_FALSE;
		break;

	case MBA_IDC_REQUEST_NOTIFICATION /* 8101h */:
		QL_PRINT(DBG_MBX,
		    ("%s(%d): MBA_IDC_REQUEST_NOTIFICATION "
		    "received\n", __func__, qlge->instance));
		cmd = mbx_cmds->mb[1];
		if (cmd == MBC_STOP_FIRMWARE) {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d): STOP_FIRMWARE notification"
			    " received\n", __func__, qlge->instance));
		} else if (cmd == MBC_IDC_REQUEST) {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d): IDC_REQUEST notification "
			    "received\n", __func__, qlge->instance));
		} else if (cmd == MBC_PORT_RESET) {
			/* EMPTY */
			QL_PRINT(DBG_MBX, ("%s(%d): PORT_RESET "
			    "notification received\n",
			    __func__, qlge->instance));
		} else if (cmd == MBC_SET_PORT_CONFIG) {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d): SET_PORT_CONFIG notification "
			    "received\n", __func__, qlge->instance));
		} else {
			/* EMPTY */
			QL_PRINT(DBG_MBX, ("%s(%d): "
			    "unknown request received %x %x\n",
			    __func__, qlge->instance, mbx_cmds->mb[1],
			    mbx_cmds->mb[2]));
		}
		reply_cmd.mb[0] = MBC_IDC_ACK;
		reply_cmd.mb[1] = mbx_cmds->mb[1];
		reply_cmd.mb[2] = mbx_cmds->mb[2];
		reply_cmd.mb[3] = mbx_cmds->mb[3];
		reply_cmd.mb[4] = mbx_cmds->mb[4];
		if (ql_issue_mailbox_cmd(qlge, &reply_cmd)
		    != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "%s(%d) send IDC Ack failed.",
			    __func__, qlge->instance);
		}
		/*
		 * verify if the incoming outbound mailbox value is what
		 * we just sent
		 */
		if (mbx_cmds->mb[0] == MBS_COMMAND_COMPLETE) {
			/* 0x4000 */
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d): IDC Ack sent success.\n",
			    __func__, qlge->instance));
			} else {
			/* EMPTY */
			QL_PRINT(DBG_MBX,
			    ("%s(%d): IDC Ack reply error %x %x %x.\n",
			    __func__, qlge->instance, mbx_cmds->mb[0],
			    mbx_cmds->mb[1], mbx_cmds->mb[2]));
			}
		break;
	case MBA_IDC_TIME_EXTENDED /* 8102 */:
		QL_PRINT(DBG_MBX,
		    ("%s(%d): MBA_IDC_TIME_EXTENDED received\n",
		    __func__, qlge->instance));
		break;
	case MBA_DCBX_CONFIG_CHANGE /* 8110 */:
		QL_PRINT(DBG_MBX,
		    ("%s(%d): MBA_DCBX_CONFIG_CHANGE received\n",
		    __func__, qlge->instance));
		break;
	case MBA_NOTIFICATION_LOST /* 8120 */:
		QL_PRINT(DBG_MBX,
		    ("%s(%d): MBA_NOTIFICATION_LOST received\n",
		    __func__, qlge->instance));
		break;
	case MBA_SFT_TRANSCEIVER_INSERTION /* 8130 */:
		QL_PRINT(DBG_MBX,
		    ("%s(%d): MBA_SFT_TRANSCEIVER_INSERTION "
		    "received\n", __func__, qlge->instance));
		break;
	case MBA_SFT_TRANSCEIVER_REMOVAL /* 8140 */:
		QL_PRINT(DBG_MBX,
		    ("%s(%d): MBA_SFT_TRANSCEIVER_REMOVAL "
		    "received\n", __func__, qlge->instance));
		break;
	case MBA_FIRMWARE_INIT_COMPLETE /* 8400 */:
		QL_PRINT(DBG_MBX,
		    ("%s(%d): MBA_FIRMWARE_INIT_COMPLETE "
		    "received\n", __func__, qlge->instance));
		QL_PRINT(DBG_MBX,
		    ("%s(%d): mbx[1] %x, mbx[2] %x\n", __func__,
		    qlge->instance, mbx_cmds->mb[1], mbx_cmds->mb[2]));
		qlge->fw_init_complete = B_TRUE;
		qlge->fw_version_info.major_version =
		    LSB(MSW(mbx_cmds->mb[1]));
		qlge->fw_version_info.minor_version =
		    MSB(LSW(mbx_cmds->mb[1]));
		qlge->fw_version_info.sub_minor_version =
		    LSB(LSW(mbx_cmds->mb[1]));
		qlge->phy_version_info.major_version =
		    LSB(MSW(mbx_cmds->mb[2]));
		qlge->phy_version_info.minor_version =
		    MSB(LSW(mbx_cmds->mb[2]));
		qlge->phy_version_info.sub_minor_version =
		    LSB(LSW(mbx_cmds->mb[2]));
		break;
	case MBA_FIRMWARE_INIT_FAILED /* 8401 */:
		cmn_err(CE_WARN, "%s(%d):"
		    "ASYNC_EVENT_FIRMWARE_INIT_FAILURE "
		    "received:  mbx[1] %x, mbx[2] %x",
		    __func__, qlge->instance,
		    mbx_cmds->mb[1], mbx_cmds->mb[2]);
		fatal_error = B_TRUE;
		break;
	default:
		if (mbx_cmds->mb[0] > 0x8000) {
			cmn_err(CE_WARN, "%s(%d): "
			    "Unknown Async event received: mbx[0] %x ,"
			    "mbx[1] %x; mbx[2] %x",
			    __func__, qlge->instance,
			    mbx_cmds->mb[0], mbx_cmds->mb[1],
			    mbx_cmds->mb[2]);
			proc_done = B_TRUE;
		} else {
			proc_done = B_FALSE;
		}
		break;
	}
	if (fatal_error) {
		if (qlge->fm_enable) {
			ql_fm_ereport(qlge, DDI_FM_DEVICE_NO_RESPONSE);
			ddi_fm_service_impact(qlge->dip, DDI_SERVICE_LOST);
			atomic_or_32(&qlge->flags, ADAPTER_ERROR);
		}
	}
	return (proc_done);
}


/*
 * MPI Interrupt handler
 * Caller must have MBX_LOCK
 */
void
ql_do_mpi_intr(qlge_t *qlge)
{
	/*
	 * we just need to read first few mailboxes that this adapter's MPI
	 * will write response to.
	 */
	mutex_enter(&qlge->mbx_mutex);

	(void) ql_read_mailbox_cmd(qlge, &qlge->received_mbx_cmds,
	    qlge->max_read_mbx);

	/*
	 * process PI interrupt as async events, if not done,
	 * then pass to mailbox processing
	 */
	if (ql_async_event_parser(qlge, &qlge->received_mbx_cmds) == B_FALSE) {
		QL_PRINT(DBG_MBX, ("%s(%d) mailbox completion interrupt\n",
		    __func__, qlge->instance));
		/*
		 * If another thread is waiting for the mail box
		 * completion event to occur
		 */
		if (qlge->mbx_wait_completion == 1) {
			qlge->mbx_wait_completion = 0;
			cv_broadcast(&qlge->cv_mbx_intr);
			QL_PRINT(DBG_MBX,
			    ("%s(%d) mailbox completion signaled \n",
			    __func__, qlge->instance));
		}
	}
	/* inform MPI Firmware to clear the interrupt */
	ql_write_reg(qlge, REG_HOST_CMD_STATUS,
	    HOST_CMD_CLEAR_RISC_TO_HOST_INTR /* 0x0A */);
	mutex_exit(&qlge->mbx_mutex);
	ql_enable_completion_interrupt(qlge, 0); /* MPI is on irq 0 */
}

/*
 * Test if mailbox communication works
 * This is used when Interrupt is not enabled
 */
int
ql_mbx_test(qlge_t *qlge)
{
	mbx_cmd_t mbx_cmds;
	mbx_data_t mbx_results;
	int i, test_ok = 1;
	int rtn_val = DDI_FAILURE;

	for (i = 0; i < NUM_MAILBOX_REGS; i++)
		mbx_cmds.mb[i] = i;

	mbx_cmds.mb[0] = MBC_MAILBOX_REGISTER_TEST; /* 0x06 */
	if (ql_issue_mailbox_cmd(qlge, &mbx_cmds) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d) ql_issue_mailbox_cmd timeout.",
		    __func__, qlge->instance);
		goto out;
	}

	/* delay for the processor interrupt is received */
	if (ql_poll_processor_intr(qlge, (uint8_t)mbx_cmds.timeout)
	    == DDI_SUCCESS) {
		QL_PRINT(DBG_MBX, ("%s(%d) PI Intr received",
		    __func__, qlge->instance));
		(void) ql_read_mailbox_cmd(qlge, &mbx_results, 0);

		ql_write_reg(qlge, REG_HOST_CMD_STATUS,
		    HOST_CMD_CLEAR_RISC_TO_HOST_INTR);

		if (mbx_results.mb[0] != MBS_COMMAND_COMPLETE /* 0x4000 */) {
			test_ok = 0;
		} else {
			for (i = 1; i < NUM_MAILBOX_REGS; i++) {
				if (mbx_results.mb[i] != i) {
					test_ok = 0;
					break;
				}
			}
		}
		if (test_ok) {
			rtn_val = DDI_SUCCESS;
		} else {
			cmn_err(CE_WARN, "%s(%d) mailbox test failed!",
			    __func__, qlge->instance);
		}
	} else {
		cmn_err(CE_WARN, "%s(%d) mailbox testing error: "
		    "PI Intr not received ", __func__, qlge->instance);
	}
out:
	return (rtn_val);
}

/*
 * ql_mbx_test2
 * Test if mailbox communication works
 * This is used when Interrupt is enabled
 * mailbox cmd:0x06h
 */
int
ql_mbx_test2(qlge_t *qlge)
{
	mbx_cmd_t mbx_cmds = {0};
	int i, test_ok = 1;
	int rtn_val = DDI_FAILURE;

	for (i = 0; i < NUM_MAILBOX_REGS; i++)
		mbx_cmds.mb[i] = i;

	mbx_cmds.mb[0] = MBC_MAILBOX_REGISTER_TEST; /* 0x06 */
	if (ql_issue_mailbox_cmd_and_wait_rsp(qlge, &mbx_cmds) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s(%d) ql_issue_mailbox_cmd_and_wait_rsp failed.",
		    __func__, qlge->instance);
		goto out;
	}

	/* verify if the incoming outbound mailbox value is what we just sent */
	if (mbx_cmds.mb[0] != MBS_COMMAND_COMPLETE /* 0x4000 */) {
		test_ok = 0;
	} else {
		for (i = 1; i < qlge->max_read_mbx; i++) {
			if (mbx_cmds.mb[i] != i) {
				test_ok = 0;
				break;
			}
		}
	}
	if (test_ok) {
		rtn_val = DDI_SUCCESS;
	} else {
		cmn_err(CE_WARN, "%s(%d) mailbox test failed!",
		    __func__, qlge->instance);
	}
out:
	if ((rtn_val != DDI_SUCCESS) && qlge->fm_enable) {
		ql_fm_ereport(qlge, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(qlge->dip, DDI_SERVICE_DEGRADED);
	}
	return (rtn_val);
}

/*
 * ql_get_fw_state
 * Get fw state.
 * mailbox cmd:0x69h
 */
int
ql_get_fw_state(qlge_t *qlge, uint32_t *fw_state_ptr)
{
	int rtn_val = DDI_FAILURE;
	mbx_cmd_t mbx_cmds = {0};

	mbx_cmds.mb[0] = MBC_GET_FIRMWARE_STATE;

	if (ql_issue_mailbox_cmd_and_wait_rsp(qlge, &mbx_cmds)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d) ql_issue_mailbox_cmd_and_wait_rsp"
		    " failed.", __func__, qlge->instance);
		goto out;
	}
	/* verify if the transaction is completed successful */
	if (mbx_cmds.mb[0] != MBS_COMMAND_COMPLETE /* 0x4000 */) {
		cmn_err(CE_WARN, "%s(%d) failed, 0x%x",
		    __func__, qlge->instance, mbx_cmds.mb[0]);
	} else {
		/* EMPTY */
		QL_PRINT(DBG_MBX, ("firmware state: 0x%x\n", mbx_cmds.mb[1]));
	}
	if (fw_state_ptr != NULL)
		*fw_state_ptr = mbx_cmds.mb[1];
	rtn_val = DDI_SUCCESS;
out:
	if ((rtn_val != DDI_SUCCESS) && qlge->fm_enable) {
		ql_fm_ereport(qlge, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(qlge->dip, DDI_SERVICE_DEGRADED);
	}
	return (rtn_val);
}

/*
 * ql_set_IDC_Req
 * Send a IDC Request to firmware to notify all functions
 * or any specific functions on the same port
 * mailbox cmd:0x100h
 */
int
ql_set_IDC_Req(qlge_t *qlge, uint8_t dest_functions, uint8_t timeout)
{
	int rtn_val = DDI_FAILURE;
	mbx_cmd_t mbx_cmds = {0};

	mbx_cmds.mb[0] = MBC_IDC_REQUEST /* 0x100 */;
	mbx_cmds.mb[1] = (timeout<<8) | qlge->func_number;

	switch (dest_functions) {
	case IDC_REQ_DEST_FUNC_ALL:
		mbx_cmds.mb[1] |= IDC_REQ_ALL_DEST_FUNC_MASK;
		mbx_cmds.mb[2] = 0;
		break;
	case IDC_REQ_DEST_FUNC_0:
		mbx_cmds.mb[2] = IDC_REQ_DEST_FUNC_0_MASK;
		break;
	case IDC_REQ_DEST_FUNC_1:
		mbx_cmds.mb[2] = IDC_REQ_DEST_FUNC_1_MASK;
		break;
	case IDC_REQ_DEST_FUNC_2:
		mbx_cmds.mb[2] = IDC_REQ_DEST_FUNC_2_MASK;
		break;
	case IDC_REQ_DEST_FUNC_3:
		mbx_cmds.mb[2] = IDC_REQ_DEST_FUNC_3_MASK;
		break;
	default:
		cmn_err(CE_WARN, "Wrong dest functions %x",
		    dest_functions);
	}

	if (ql_issue_mailbox_cmd_and_wait_rsp(qlge, &mbx_cmds) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s(%d) ql_issue_mailbox_cmd_and_wait_rsp failed.",
		    __func__, qlge->instance);
		goto out;
	}
	/* verify if the transaction is completed successful */
	if (mbx_cmds.mb[0] == MBA_IDC_INTERMEDIATE_COMPLETE /* 0x1000 */) {
		QL_PRINT(DBG_MBX, ("%s(%d) mbx1: 0x%x, mbx2: 0x%x\n",
		    __func__, qlge->instance, mbx_cmds.mb[1], mbx_cmds.mb[2]));
		rtn_val = DDI_SUCCESS;
	} else if (mbx_cmds.mb[0] == MBS_COMMAND_COMPLETE /* 0x4000 */) {
		QL_PRINT(DBG_MBX, ("%s(%d) cmd sent succesfully 0x%x\n",
		    __func__, qlge->instance));
		rtn_val = DDI_SUCCESS;
	} else if (mbx_cmds.mb[0] == MBS_COMMAND_ERROR /* 0x4005 */) {
		cmn_err(CE_WARN, "%s(%d) failed: COMMAND_ERROR",
		    __func__, qlge->instance);
	} else if (mbx_cmds.mb[0] == MBS_COMMAND_PARAMETER_ERROR /* 0x4006 */) {
		cmn_err(CE_WARN, "%s(%d) failed: COMMAND_PARAMETER_ERROR",
		    __func__, qlge->instance);
	} else {
		cmn_err(CE_WARN, "%s(%d) unknow result: mbx[0]: 0x%x; mbx[1]:"
		    " 0x%x; mbx[2]: 0x%x", __func__, qlge->instance,
		    mbx_cmds.mb[0], mbx_cmds.mb[1], mbx_cmds.mb[2]);
	}

out:
	if ((rtn_val != DDI_SUCCESS) && qlge->fm_enable) {
		ql_fm_ereport(qlge, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(qlge->dip, DDI_SERVICE_DEGRADED);
	}
return (rtn_val);
}

/*
 * ql_set_mpi_port_config
 * Send new port configuration.to mpi
 * mailbox cmd:0x122h
 */
int
ql_set_mpi_port_config(qlge_t *qlge, port_cfg_info_t new_cfg)
{
	int rtn_val = DDI_FAILURE;
	mbx_cmd_t mbx_cmds = {0};

	mbx_cmds.mb[0] = MBC_SET_PORT_CONFIG /* 0x122 */;
	mbx_cmds.mb[1] = new_cfg.link_cfg;
	mbx_cmds.mb[2] = new_cfg.max_frame_size;

	if (ql_issue_mailbox_cmd_and_wait_rsp(qlge, &mbx_cmds) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d) ql_issue_mailbox_cmd_and_wait_rsp"
		    " failed.", __func__, qlge->instance);
		goto out;
	}
	/* verify if the transaction is completed successful */
	if ((mbx_cmds.mb[0] != MBS_COMMAND_COMPLETE /* 0x4000 */) &&
	    (mbx_cmds.mb[0] != MBA_IDC_COMPLETE /* 0x8100 */)) {
		cmn_err(CE_WARN, "set port config (%d) failed, 0x%x",
		    qlge->instance, mbx_cmds.mb[0]);
	} else
		rtn_val = DDI_SUCCESS;
out:
	if ((rtn_val != DDI_SUCCESS) && qlge->fm_enable) {
		ql_fm_ereport(qlge, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(qlge->dip, DDI_SERVICE_DEGRADED);
	}
	return (rtn_val);
}

int
ql_set_pause_mode(qlge_t *qlge)
{
	uint32_t pause_bit_mask = 0x60;	/* bit 5-6 */

	/* clear pause bits */
	qlge->port_cfg_info.link_cfg &= ~pause_bit_mask;

	/* set new pause mode */
	if (qlge->pause == PAUSE_MODE_STANDARD)
		qlge->port_cfg_info.link_cfg |= STD_PAUSE;
	else if (qlge->pause == PAUSE_MODE_PER_PRIORITY)
		qlge->port_cfg_info.link_cfg |= PP_PAUSE;

	return (ql_set_mpi_port_config(qlge, qlge->port_cfg_info));
}

int
ql_set_loop_back_mode(qlge_t *qlge)
{
	uint32_t loop_back_bit_mask = 0x0e; /* bit 1-3 */

	/* clear loop back bits */
	qlge->port_cfg_info.link_cfg &= ~loop_back_bit_mask;
	/* loop back cfg: bit1-3 */
	if (qlge->loop_back_mode == QLGE_LOOP_INTERNAL_PARALLEL)
		qlge->port_cfg_info.link_cfg |= LOOP_INTERNAL_PARALLEL;
	else if (qlge->loop_back_mode == QLGE_LOOP_INTERNAL_SERIAL)
		qlge->port_cfg_info.link_cfg |= LOOP_INTERNAL_SERIAL;

	return (ql_set_mpi_port_config(qlge, qlge->port_cfg_info));

}
/*
 * ql_get_port_cfg
 * Get port configuration.
 * mailbox cmd:0x123h
 */
int
ql_get_port_cfg(qlge_t *qlge)
{
	int rtn_val = DDI_FAILURE;
	mbx_cmd_t mbx_cmds = {0};

	mbx_cmds.mb[0] = MBC_GET_PORT_CONFIG /* 0x123 */;
	if (ql_issue_mailbox_cmd_and_wait_rsp(qlge, &mbx_cmds) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d) ql_issue_mailbox_cmd_and_wait_rsp"
		    " failed.", __func__, qlge->instance);
		goto out;
	}
	/* verify if the transaction is completed successfully */
	if (mbx_cmds.mb[0] != MBS_COMMAND_COMPLETE /* 0x4000 */) {
		cmn_err(CE_WARN, "get port config (%d) failed, 0x%x",
		    qlge->instance, mbx_cmds.mb[0]);
	} else { /* verify frame size */
		if ((mbx_cmds.mb[2] == NORMAL_FRAME_SIZE) ||
		    (mbx_cmds.mb[2] == JUMBO_FRAME_SIZE)) {
			qlge->port_cfg_info.link_cfg = mbx_cmds.mb[1];
			qlge->port_cfg_info.max_frame_size = mbx_cmds.mb[2];
			QL_PRINT(DBG_MBX, ("link_cfg: 0x%x, max_frame_size:"
			    " %d bytes\n", mbx_cmds.mb[1], mbx_cmds.mb[2]));
			rtn_val = DDI_SUCCESS;
		} else {
			cmn_err(CE_WARN, "bad link_cfg: 0x%x, max_frame_size:"
			    " %d bytes", mbx_cmds.mb[1], mbx_cmds.mb[2]);
		}
	}
out:
	if ((rtn_val != DDI_SUCCESS) && qlge->fm_enable) {
		ql_fm_ereport(qlge, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(qlge->dip, DDI_SERVICE_DEGRADED);
	}
	return (rtn_val);
}

/*
 * qlge_get_link_status
 * Get link status.
 * mailbox cmd:0x124h
 */
int
qlge_get_link_status(qlge_t *qlge,
    struct qlnic_link_status_info *link_status_ptr)
{
	int rtn_val = DDI_FAILURE;
	mbx_cmd_t mbx_cmds = {0};

	mbx_cmds.mb[0] = MBC_GET_LINK_STATUS /* 0x124 */;

	if (ql_issue_mailbox_cmd_and_wait_rsp(qlge, &mbx_cmds)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s(%d) ql_issue_mailbox_cmd_and_wait_rsp failed.",
		    __func__, qlge->instance);
		goto out;
	}
	/* verify if the transaction is completed successful */
	if (mbx_cmds.mb[0] != MBS_COMMAND_COMPLETE /* 0x4000 */) {
		cmn_err(CE_WARN, "get link status(%d) failed, 0x%x",
		    qlge->instance, mbx_cmds.mb[0]);
	} else {
		/* EMPTY */
		QL_PRINT(DBG_MBX,
		    ("link status: status1 : 0x%x, status2 : 0x%x, "
		    "status3 : 0x%x\n",
		    mbx_cmds.mb[1], mbx_cmds.mb[2], mbx_cmds.mb[3]));
	}
	if (link_status_ptr != NULL) {
		link_status_ptr->link_status_info = mbx_cmds.mb[1];
		link_status_ptr->additional_info = mbx_cmds.mb[2];
		link_status_ptr->network_hw_info = mbx_cmds.mb[3];
		link_status_ptr->dcbx_frame_counters_info = mbx_cmds.mb[4];
		link_status_ptr->change_counters_info = mbx_cmds.mb[5];
	}
	rtn_val = DDI_SUCCESS;
out:
	if ((rtn_val != DDI_SUCCESS) && qlge->fm_enable) {
		ql_fm_ereport(qlge, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(qlge->dip, DDI_SERVICE_DEGRADED);
	}
	return (rtn_val);
}

/*
 * ql_get_firmware_version
 * Get firmware version.
 */
int
ql_get_firmware_version(qlge_t *qlge,
    struct qlnic_mpi_version_info *mpi_version_ptr)
{
	int rtn_val = DDI_FAILURE;
	mbx_cmd_t mbx_cmds = {0};

	mbx_cmds.mb[0] = MBC_ABOUT_FIRMWARE /* 0x08 */;

	if (ql_issue_mailbox_cmd_and_wait_rsp(qlge, &mbx_cmds)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "%s(%d) ql_issue_mailbox_cmd_and_wait_rsp failed.",
		    __func__, qlge->instance);
		goto out;
	}

	/* verify if the transaction is completed successful */
	if (mbx_cmds.mb[0] != MBS_COMMAND_COMPLETE /* 0x4000 */) {
		cmn_err(CE_WARN, "get firmware version(%d) failed, 0x%x",
		    qlge->instance, mbx_cmds.mb[0]);
	} else {
		qlge->fw_version_info.major_version =
		    LSB(MSW(mbx_cmds.mb[1]));
		qlge->fw_version_info.minor_version =
		    MSB(LSW(mbx_cmds.mb[1]));
		qlge->fw_version_info.sub_minor_version =
		    LSB(LSW(mbx_cmds.mb[1]));
		qlge->phy_version_info.major_version =
		    LSB(MSW(mbx_cmds.mb[2]));
		qlge->phy_version_info.minor_version =
		    MSB(LSW(mbx_cmds.mb[2]));
		qlge->phy_version_info.sub_minor_version =
		    LSB(LSW(mbx_cmds.mb[2]));
#ifdef QLGE_LOAD_UNLOAD
		cmn_err(CE_NOTE, "firmware version: %d.%d.%d\n",
		    qlge->fw_version_info.major_version,
		    qlge->fw_version_info.minor_version,
		    qlge->fw_version_info.sub_minor_version);
#endif
		if (mpi_version_ptr != NULL) {
			mpi_version_ptr->fw_version =
			    (qlge->fw_version_info.major_version<<16)
			    |(qlge->fw_version_info.minor_version<<8)
			    |(qlge->fw_version_info.sub_minor_version);
			mpi_version_ptr->phy_version =
			    (qlge->phy_version_info.major_version<<16)
			    |(qlge->phy_version_info.minor_version<<8)
			    |(qlge->phy_version_info.sub_minor_version);
		}
	}
	rtn_val = DDI_SUCCESS;
out:
	if ((rtn_val != DDI_SUCCESS) && qlge->fm_enable) {
		ql_fm_ereport(qlge, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(qlge->dip, DDI_SERVICE_DEGRADED);
	}
	return (rtn_val);
}

/*
 * Trigger a system error event
 */
int
ql_trigger_system_error_event(qlge_t *qlge)
{
	mbx_cmd_t mbx_cmds = {0};
	int rtn_val = DDI_FAILURE;

	mbx_cmds.mb[0] = MBC_GENERATE_SYS_ERROR; /* 0x2A */
	if (ql_issue_mailbox_cmd(qlge, &mbx_cmds) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s(%d) ql_issue_mailbox_cmd timeout.",
		    __func__, qlge->instance);
		goto out;
	}
	rtn_val = DDI_SUCCESS;
out:
	return (rtn_val);
}

/*
 * Reset the MPI RISC Processor
 */
int
ql_reset_mpi_risc(qlge_t *qlge)
{
	int rtn_val = DDI_FAILURE;

	/* Reset the MPI Processor */
	ql_write_reg(qlge, REG_HOST_CMD_STATUS, HOST_CMD_SET_RISC_RESET);
	if (ql_wait_reg_bit(qlge, REG_HOST_CMD_STATUS, RISC_RESET,
	    BIT_SET, 0) != DDI_SUCCESS) {
		(void) ql_read_reg(qlge, REG_HOST_CMD_STATUS);
		goto out;
	}
	ql_write_reg(qlge, REG_HOST_CMD_STATUS, HOST_CMD_CLEAR_RISC_RESET);
	rtn_val = DDI_SUCCESS;
out:
	return (rtn_val);
}

int
ql_read_risc_ram(qlge_t *qlge, uint32_t risc_address, uint64_t bp,
    uint32_t word_count)
{
	int rval = DDI_FAILURE;
	mbx_cmd_t mc = {0};
	mbx_cmd_t *mcp = &mc;
	mbx_data_t mbx_results;

	QL_PRINT(DBG_MBX, ("%s(%d): read risc addr:0x%x,"
	    "phys_addr %x,%x words\n", __func__, qlge->instance,
	    risc_address, bp, word_count));
	if (CFG_IST(qlge, CFG_CHIP_8100)) {
		mcp->mb[0] = MBC_DUMP_RISC_RAM /* 0x0C */;
		mcp->mb[1] = LSW(risc_address);
		mcp->mb[2] = MSW(LSD(bp));
		mcp->mb[3] = LSW(LSD(bp));
		mcp->mb[4] = MSW(word_count);
		mcp->mb[5] = LSW(word_count);
		mcp->mb[6] = MSW(MSD(bp));
		mcp->mb[7] = LSW(MSD(bp));
		mcp->mb[8] = MSW(risc_address);
	}
	mcp->timeout = 10 /* MAILBOX_TOV */;

	if (ql_issue_mailbox_cmd_and_poll_rsp(qlge, mcp, &mbx_results)
	    != DDI_SUCCESS) {
		goto out;
	} else {
		QL_PRINT(DBG_MBX, ("%s(%d) PI Intr received",
		    __func__, qlge->instance));
		if (mbx_results.mb[0] == MBS_COMMAND_COMPLETE /* 0x4000 */) {
			QL_PRINT(DBG_MBX, ("%s(%d): success\n",
			    __func__, qlge->instance));
			rval = DDI_SUCCESS;
		} else {
			cmn_err(CE_WARN, "read_risc_ram(%d): failed, status %x",
			    qlge->instance, mbx_results.mb[0]);
		}
	}
out:
	return (rval);
}
