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

#pragma ident	"Copyright 2008 QLogic Corporation; ql_isr.c"

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
#include <ql_init.h>
#include <ql_mbx.h>
#include <ql_xioctl.h>

/*
 * Local Function Prototypes.
 */
static void ql_spurious_intr(ql_adapter_state_t *, int);
static void ql_mbx_completion(ql_adapter_state_t *, uint16_t, uint32_t *,
    uint32_t *, int);
static void ql_async_event(ql_adapter_state_t *, uint32_t, ql_head_t *,
    uint32_t *, uint32_t *, int);
static void ql_fast_fcp_post(ql_srb_t *);
static void ql_response_pkt(ql_adapter_state_t *, ql_head_t *, uint32_t *,
    uint32_t *, int);
static void ql_error_entry(ql_adapter_state_t *, response_t *, ql_head_t *,
    uint32_t *, uint32_t *);
static int ql_status_entry(ql_adapter_state_t *, sts_entry_t *, ql_head_t *,
    uint32_t *, uint32_t *);
static int ql_24xx_status_entry(ql_adapter_state_t *, sts_24xx_entry_t *,
    ql_head_t *, uint32_t *, uint32_t *);
static int ql_status_error(ql_adapter_state_t *, ql_srb_t *, sts_entry_t *,
    ql_head_t *, uint32_t *, uint32_t *);
static void ql_status_cont_entry(ql_adapter_state_t *, sts_cont_entry_t *,
    ql_head_t *, uint32_t *, uint32_t *);
static void ql_immediate_notify_entry(ql_adapter_state_t *,
    immediate_notify_entry_t *, ql_head_t *, uint32_t *, uint32_t *);
static void ql_notify_acknowledge_entry(ql_adapter_state_t *,
    notify_acknowledge_entry_t *, ql_head_t *, uint32_t *, uint32_t *);
static void ql_accept_target_io_entry(ql_adapter_state_t *,
    atio_entry_t *, ql_head_t *, uint32_t *, uint32_t *);
static void ql_continue_target_io_entry(ql_adapter_state_t *,
    ctio_entry_t *, ql_head_t *, uint32_t *, uint32_t *);
static void ql_ip_entry(ql_adapter_state_t *, ip_entry_t *, ql_head_t *,
    uint32_t *, uint32_t *);
static void ql_ip_rcv_entry(ql_adapter_state_t *, ip_rcv_entry_t *,
    ql_head_t *, uint32_t *, uint32_t *);
static void ql_ip_rcv_cont_entry(ql_adapter_state_t *,
    ip_rcv_cont_entry_t *, ql_head_t *, uint32_t *, uint32_t *);
static void ql_ip_24xx_rcv_entry(ql_adapter_state_t *, ip_rcv_24xx_entry_t *,
    ql_head_t *, uint32_t *, uint32_t *);
static void ql_ms_entry(ql_adapter_state_t *, ms_entry_t *, ql_head_t *,
    uint32_t *, uint32_t *);
static void ql_report_id_entry(ql_adapter_state_t *, report_id_1_t *,
    ql_head_t *, uint32_t *, uint32_t *);

/* TODO: temporary define until defined in LV */
#ifndef FC_STATE_8GBIT_SPEED
#define	FC_STATE_8GBIT_SPEED		0x0700	/* 8 Gbit/sec */
#endif

/*
 * ql_isr
 *	Process all INTX intr types.
 *
 * Input:
 *	arg1:	adapter state pointer.
 *
 * Returns:
 *	DDI_INTR_CLAIMED or DDI_INTR_UNCLAIMED
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
uint_t
ql_isr(caddr_t arg1)
{
	return (ql_isr_aif(arg1, 0));
}

/*
 * ql_isr_default
 *	Process unknown/unvectored intr types
 *
 * Input:
 *	arg1:	adapter state pointer.
 *	arg2:	interrupt vector.
 *
 * Returns:
 *	DDI_INTR_CLAIMED or DDI_INTR_UNCLAIMED
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
uint_t
ql_isr_default(caddr_t arg1, caddr_t arg2)
{
	ql_adapter_state_t	*ha = (void *)arg1;

	EL(ha, "isr_default called: idx=%x\n", arg2);
	return (ql_isr_aif(arg1, arg2));
}

/*
 * ql_isr_aif
 *	Process mailbox and I/O command completions.
 *
 * Input:
 *	arg:	adapter state pointer.
 *	intvec:	interrupt vector.
 *
 * Returns:
 *	DDI_INTR_CLAIMED or DDI_INTR_UNCLAIMED
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
uint_t
ql_isr_aif(caddr_t arg, caddr_t intvec)
{
	uint16_t		mbx;
	uint32_t		stat;
	ql_adapter_state_t	*ha = (void *)arg;
	uint32_t		set_flags = 0;
	uint32_t		reset_flags = 0;
	ql_head_t		isr_done_q = {NULL, NULL};
	uint_t			rval = DDI_INTR_UNCLAIMED;
	int			spurious_intr = 0;
	boolean_t		intr = B_FALSE, daemon = B_FALSE;
	int			intr_loop = 4;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	QL_PM_LOCK(ha);
	if (ha->power_level != PM_LEVEL_D0) {
		/*
		 * Looks like we are about to go down soon, exit early.
		 */
		QL_PM_UNLOCK(ha);
		QL_PRINT_3(CE_CONT, "(%d): power down exit\n", ha->instance);
		return (DDI_INTR_UNCLAIMED);
	}
	ha->busy++;
	QL_PM_UNLOCK(ha);

	/* Acquire interrupt lock. */
	INTR_LOCK(ha);

	if (CFG_IST(ha, CFG_CTRL_2200)) {
		while (RD16_IO_REG(ha, istatus) & RISC_INT) {
			/* Reset idle timer. */
			ha->idle_timer = 0;
			rval = DDI_INTR_CLAIMED;
			if (intr_loop) {
				intr_loop--;
			}

			/* Special Fast Post 2200. */
			stat = 0;
			if (ha->task_daemon_flags & FIRMWARE_LOADED &&
			    ha->flags & ONLINE) {
				ql_srb_t	*sp;

				mbx = RD16_IO_REG(ha, mailbox[23]);

				if ((mbx & 3) == MBX23_SCSI_COMPLETION) {
					/* Release mailbox registers. */
					WRT16_IO_REG(ha, semaphore, 0);

					if (intr_loop) {
						WRT16_IO_REG(ha, hccr,
						    HC_CLR_RISC_INT);
					}

					/* Get handle. */
					mbx >>= 4;
					stat = mbx & OSC_INDEX_MASK;

					/* Validate handle. */
					sp = stat < MAX_OUTSTANDING_COMMANDS ?
					    ha->outstanding_cmds[stat] : NULL;

					if (sp != NULL && (sp->handle & 0xfff)
					    == mbx) {
						ha->outstanding_cmds[stat] =
						    NULL;
						sp->handle = 0;
						sp->flags &=
						    ~SRB_IN_TOKEN_ARRAY;

						/* Set completed status. */
						sp->flags |= SRB_ISP_COMPLETED;

						/* Set completion status */
						sp->pkt->pkt_reason =
						    CS_COMPLETE;

						ql_fast_fcp_post(sp);
					} else if (mbx !=
					    (QL_FCA_BRAND & 0xfff)) {
						if (sp == NULL) {
							EL(ha, "unknown IOCB"
							    " handle=%xh\n",
							    mbx);
						} else {
							EL(ha, "mismatch IOCB"
							    " handle pkt=%xh, "
							    "sp=%xh\n", mbx,
							    sp->handle & 0xfff);
						}

						(void) ql_binary_fw_dump(ha,
						    FALSE);

						if (!(ha->task_daemon_flags &
						    (ISP_ABORT_NEEDED |
						    ABORT_ISP_ACTIVE))) {
							EL(ha, "ISP Invalid "
							    "handle, "
							    "isp_abort_needed"
							    "\n");
							set_flags |=
							    ISP_ABORT_NEEDED;
						}
					}
				}
			}

			if (stat == 0) {
				/* Check for mailbox interrupt. */
				mbx = RD16_IO_REG(ha, semaphore);
				if (mbx & BIT_0) {
					/* Release mailbox registers. */
					WRT16_IO_REG(ha, semaphore, 0);

					/* Get mailbox data. */
					mbx = RD16_IO_REG(ha, mailbox[0]);
					if (mbx > 0x3fff && mbx < 0x8000) {
						ql_mbx_completion(ha, mbx,
						    &set_flags, &reset_flags,
						    intr_loop);
					} else if (mbx > 0x7fff &&
					    mbx < 0xc000) {
						ql_async_event(ha, mbx,
						    &isr_done_q, &set_flags,
						    &reset_flags, intr_loop);
					} else {
						EL(ha, "UNKNOWN interrupt "
						    "type\n");
						intr = B_TRUE;
					}
				} else {
					ha->isp_rsp_index = RD16_IO_REG(ha,
					    resp_in);

					if (ha->isp_rsp_index !=
					    ha->rsp_ring_index) {
						ql_response_pkt(ha,
						    &isr_done_q, &set_flags,
						    &reset_flags, intr_loop);
					} else if (++spurious_intr ==
					    MAX_SPURIOUS_INTR) {
						/*
						 * Process excessive
						 * spurious intrrupts
						 */
						ql_spurious_intr(ha,
						    intr_loop);
						EL(ha, "excessive spurious "
						    "interrupts, "
						    "isp_abort_needed\n");
						set_flags |= ISP_ABORT_NEEDED;
					} else {
						intr = B_TRUE;
					}
				}
			}

			/* Clear RISC interrupt */
			if (intr || intr_loop == 0) {
				intr = B_FALSE;
				WRT16_IO_REG(ha, hccr, HC_CLR_RISC_INT);
			}

			if (set_flags != 0 || reset_flags != 0) {
				TASK_DAEMON_LOCK(ha);
				ha->task_daemon_flags |= set_flags;
				ha->task_daemon_flags &= ~reset_flags;
				TASK_DAEMON_UNLOCK(ha);
				set_flags = 0;
				reset_flags = 0;
				daemon = B_TRUE;
			}
		}
	} else {
		while ((stat = RD32_IO_REG(ha, intr_info_lo)) & BIT_15) {
			mbx = MSW(stat);

			/* Reset idle timer. */
			ha->idle_timer = 0;
			rval = DDI_INTR_CLAIMED;
			if (intr_loop) {
				intr_loop--;
			}

			switch (stat & 0x1ff) {
			case ROM_MBX_SUCCESS:
			case ROM_MBX_ERR:
				ql_mbx_completion(ha, mbx, &set_flags,
				    &reset_flags, intr_loop);

				/* Release mailbox registers. */
				if ((CFG_IST(ha, CFG_CTRL_2425)) == 0) {
					WRT16_IO_REG(ha, semaphore, 0);
				}
				break;

			case MBX_SUCCESS:
			case MBX_ERR:
				/* Sun FW, Release mailbox registers. */
				if ((CFG_IST(ha, CFG_CTRL_2425)) == 0) {
					WRT16_IO_REG(ha, semaphore, 0);
				}
				ql_mbx_completion(ha, mbx, &set_flags,
				    &reset_flags, intr_loop);
				break;

			case ASYNC_EVENT:
				/* Sun FW, Release mailbox registers. */
				if ((CFG_IST(ha, CFG_CTRL_2425)) == 0) {
					WRT16_IO_REG(ha, semaphore, 0);
				}
				ql_async_event(ha, (uint32_t)mbx, &isr_done_q,
				    &set_flags, &reset_flags, intr_loop);
				break;

			case RESP_UPDATE:
				if (mbx != ha->rsp_ring_index) {
					ha->isp_rsp_index = mbx;
					ql_response_pkt(ha, &isr_done_q,
					    &set_flags, &reset_flags,
					    intr_loop);
				} else if (++spurious_intr ==
				    MAX_SPURIOUS_INTR) {
					/* Process excessive spurious intr. */
					ql_spurious_intr(ha, intr_loop);
					EL(ha, "excessive spurious "
					    "interrupts, isp_abort_needed\n");
					set_flags |= ISP_ABORT_NEEDED;
				} else {
					intr = B_TRUE;
				}
				break;

			case SCSI_FAST_POST_16:
				stat = (stat & 0xffff0000) | MBA_CMPLT_1_16BIT;
				ql_async_event(ha, stat, &isr_done_q,
				    &set_flags, &reset_flags, intr_loop);
				break;

			case SCSI_FAST_POST_32:
				stat = (stat & 0xffff0000) | MBA_CMPLT_1_32BIT;
				ql_async_event(ha, stat, &isr_done_q,
				    &set_flags, &reset_flags, intr_loop);
				break;

			case CTIO_FAST_POST:
				stat = (stat & 0xffff0000) |
				    MBA_CTIO_COMPLETION;
				ql_async_event(ha, stat, &isr_done_q,
				    &set_flags, &reset_flags, intr_loop);
				break;

			case IP_FAST_POST_XMT:
				stat = (stat & 0xffff0000) | MBA_IP_COMPLETION;
				ql_async_event(ha, stat, &isr_done_q,
				    &set_flags, &reset_flags, intr_loop);
				break;

			case IP_FAST_POST_RCV:
				stat = (stat & 0xffff0000) | MBA_IP_RECEIVE;
				ql_async_event(ha, stat, &isr_done_q,
				    &set_flags, &reset_flags, intr_loop);
				break;

			case IP_FAST_POST_BRD:
				stat = (stat & 0xffff0000) | MBA_IP_BROADCAST;
				ql_async_event(ha, stat, &isr_done_q,
				    &set_flags, &reset_flags, intr_loop);
				break;

			case IP_FAST_POST_RCV_ALN:
				stat = (stat & 0xffff0000) |
				    MBA_IP_HDR_DATA_SPLIT;
				ql_async_event(ha, stat, &isr_done_q,
				    &set_flags, &reset_flags, intr_loop);
				break;

			case ATIO_UPDATE:
				EL(ha, "unsupported ATIO queue update"
				    " interrupt, status=%xh\n", stat);
				intr = B_TRUE;
				break;

			case ATIO_RESP_UPDATE:
				EL(ha, "unsupported ATIO response queue "
				    "update interrupt, status=%xh\n", stat);
				intr = B_TRUE;
				break;

			default:
				mbx = RD16_IO_REG(ha, hccr);
				if (stat & BIT_8 ||
				    mbx & (BIT_15 | BIT_13 | BIT_11 | BIT_8)) {

					ADAPTER_STATE_LOCK(ha);
					ha->flags |= PARITY_ERROR;
					ADAPTER_STATE_UNLOCK(ha);

					if (ha->parity_pause_errors == 0 ||
					    ha->parity_hccr_err != mbx ||
					    ha->parity_stat_err != stat) {
						cmn_err(CE_WARN, "qlc(%d): "
						    "isr, Internal Parity/"
						    "Pause Error - hccr=%xh, "
						    "stat=%xh, count=%d",
						    ha->instance, mbx, stat,
						    ha->parity_pause_errors);
						ha->parity_hccr_err = mbx;
						ha->parity_stat_err = stat;
					}

					EL(ha, "parity/pause error, "
					    "isp_abort_needed\n");

					if (ql_binary_fw_dump(ha, FALSE) !=
					    QL_SUCCESS) {
						/* Reset ISP chip. */
						ql_reset_chip(ha);
					}

					if (ha->parity_pause_errors == 0) {
						(void) ql_flash_errlog(ha,
						    FLASH_ERRLOG_PARITY_ERR, 0,
						    MSW(stat), LSW(stat));
					}

					if (ha->parity_pause_errors <
					    0xffffffff) {
						ha->parity_pause_errors++;
					}

					set_flags |= ISP_ABORT_NEEDED;

					/* Disable ISP interrupts. */
					WRT16_IO_REG(ha, ictrl, 0);
					ADAPTER_STATE_LOCK(ha);
					ha->flags &= ~INTERRUPTS_ENABLED;
					ADAPTER_STATE_UNLOCK(ha);
				} else {
					EL(ha, "UNKNOWN interrupt status=%xh,"
					    " hccr=%xh\n", stat, mbx);
				}
				intr = B_TRUE;
				break;
			}

			/* Clear RISC interrupt */
			if (intr || intr_loop == 0) {
				intr = B_FALSE;
				CFG_IST(ha, CFG_CTRL_2425) ?
				    WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT) :
				    WRT16_IO_REG(ha, hccr, HC_CLR_RISC_INT);
			}

			if (set_flags != 0 || reset_flags != 0) {
				TASK_DAEMON_LOCK(ha);
				ha->task_daemon_flags |= set_flags;
				ha->task_daemon_flags &= ~reset_flags;
				TASK_DAEMON_UNLOCK(ha);
				set_flags = 0;
				reset_flags = 0;
				daemon = B_TRUE;
			}

			if (ha->flags & PARITY_ERROR) {
				EL(ha, "parity/pause exit\n");
				mbx = RD16_IO_REG(ha, hccr); /* PCI posting */
				break;
			}
		}
	}

	/* Process claimed interrupts during polls. */
	if (rval == DDI_INTR_UNCLAIMED && ha->intr_claimed == B_TRUE) {
		ha->intr_claimed = B_FALSE;
		rval = DDI_INTR_CLAIMED;
	}

	/* Release interrupt lock. */
	INTR_UNLOCK(ha);

	if (daemon) {
		ql_awaken_task_daemon(ha, NULL, 0, 0);
	}

	if (isr_done_q.first != NULL) {
		ql_done(isr_done_q.first);
	}

	if (rval == DDI_INTR_CLAIMED) {
		QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
		ha->xioctl->TotalInterrupts++;
	} else {
		/*EMPTY*/
		QL_PRINT_3(CE_CONT, "(%d): interrupt not claimed\n",
		    ha->instance);
	}

	QL_PM_LOCK(ha);
	ha->busy--;
	QL_PM_UNLOCK(ha);

	return (rval);
}

/*
 * ql_spurious_intr
 *	Inform Solaris of spurious interrupts.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	intr_clr:	early interrupt clear
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_spurious_intr(ql_adapter_state_t *ha, int intr_clr)
{
	ddi_devstate_t	state;

	EL(ha, "Spurious interrupt\n");

	/* Disable ISP interrupts. */
	WRT16_IO_REG(ha, ictrl, 0);
	ADAPTER_STATE_LOCK(ha);
	ha->flags &= ~INTERRUPTS_ENABLED;
	ADAPTER_STATE_UNLOCK(ha);

	/* Clear RISC interrupt */
	if (intr_clr) {
		CFG_IST(ha, CFG_CTRL_2425) ?
		    WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT) :
		    WRT16_IO_REG(ha, hccr, HC_CLR_RISC_INT);
	}

	state = ddi_get_devstate(ha->dip);
	if (state == DDI_DEVSTATE_UP) {
		/*EMPTY*/
		ddi_dev_report_fault(ha->dip, DDI_SERVICE_DEGRADED,
		    DDI_DEVICE_FAULT, "spurious interrupts");
	}
}

/*
 * ql_mbx_completion
 *	Processes mailbox completions.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	mb0:		Mailbox 0 contents.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *	intr_clr:	early interrupt clear
 *
 * Context:
 *	Interrupt context.
 */
/* ARGSUSED */
static void
ql_mbx_completion(ql_adapter_state_t *ha, uint16_t mb0, uint32_t *set_flags,
    uint32_t *reset_flags, int intr_clr)
{
	uint32_t	index;
	uint16_t	cnt;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Load return mailbox registers. */
	MBX_REGISTER_LOCK(ha);

	if (ha->mcp != NULL) {
		ha->mcp->mb[0] = mb0;
		index = ha->mcp->in_mb & ~MBX_0;

		for (cnt = 1; cnt < MAX_MBOX_COUNT && index != 0; cnt++) {
			index >>= 1;
			if (index & MBX_0) {
				ha->mcp->mb[cnt] = RD16_IO_REG(ha,
				    mailbox[cnt]);
			}
		}

	} else {
		EL(ha, "mcp == NULL\n");
	}

	if (intr_clr) {
		/* Clear RISC interrupt. */
		CFG_IST(ha, CFG_CTRL_2425) ?
		    WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT) :
		    WRT16_IO_REG(ha, hccr, HC_CLR_RISC_INT);
	}

	ha->mailbox_flags = (uint8_t)(ha->mailbox_flags | MBX_INTERRUPT);
	if (ha->flags & INTERRUPTS_ENABLED) {
		cv_broadcast(&ha->cv_mbx_intr);
	}

	MBX_REGISTER_UNLOCK(ha);

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_async_event
 *	Processes asynchronous events.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	mbx:		Mailbox 0 register.
 *	done_q:		head pointer to done queue.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *	intr_clr:	early interrupt clear
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_async_event(ql_adapter_state_t *ha, uint32_t mbx, ql_head_t *done_q,
    uint32_t *set_flags, uint32_t *reset_flags, int intr_clr)
{
	uint32_t		handle;
	uint32_t		index;
	uint16_t		cnt;
	uint16_t		mb[MAX_MBOX_COUNT];
	ql_srb_t		*sp;
	port_id_t		s_id;
	ql_tgt_t		*tq;
	boolean_t		intr = B_TRUE;
	ql_adapter_state_t	*vha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Setup to process fast completion. */
	mb[0] = LSW(mbx);
	switch (mb[0]) {
	case MBA_SCSI_COMPLETION:
		handle = SHORT_TO_LONG(RD16_IO_REG(ha, mailbox[1]),
		    RD16_IO_REG(ha, mailbox[2]));
		break;

	case MBA_CMPLT_1_16BIT:
		handle = MSW(mbx);
		mb[0] = MBA_SCSI_COMPLETION;
		break;

	case MBA_CMPLT_1_32BIT:
		handle = SHORT_TO_LONG(MSW(mbx), RD16_IO_REG(ha, mailbox[2]));
		mb[0] = MBA_SCSI_COMPLETION;
		break;

	case MBA_CTIO_COMPLETION:
	case MBA_IP_COMPLETION:
		handle = CFG_IST(ha, CFG_CTRL_2200) ? SHORT_TO_LONG(
		    RD16_IO_REG(ha, mailbox[1]), RD16_IO_REG(ha, mailbox[2])) :
		    SHORT_TO_LONG(MSW(mbx), RD16_IO_REG(ha, mailbox[2]));
		mb[0] = MBA_SCSI_COMPLETION;
		break;

	default:
		break;
	}

	/* Handle asynchronous event */
	switch (mb[0]) {
	case MBA_SCSI_COMPLETION:
		QL_PRINT_5(CE_CONT, "(%d): Fast post completion\n",
		    ha->instance);

		if (intr_clr) {
			/* Clear RISC interrupt */
			CFG_IST(ha, CFG_CTRL_2425) ?
			    WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT) :
			    WRT16_IO_REG(ha, hccr, HC_CLR_RISC_INT);
			intr = B_FALSE;
		}

		if ((ha->flags & ONLINE) == 0) {
			break;
		}

		/* Get handle. */
		index = handle & OSC_INDEX_MASK;

		/* Validate handle. */
		sp = index < MAX_OUTSTANDING_COMMANDS ?
		    ha->outstanding_cmds[index] : NULL;

		if (sp != NULL && sp->handle == handle) {
			ha->outstanding_cmds[index] = NULL;
			sp->handle = 0;
			sp->flags &= ~SRB_IN_TOKEN_ARRAY;

			/* Set completed status. */
			sp->flags |= SRB_ISP_COMPLETED;

			/* Set completion status */
			sp->pkt->pkt_reason = CS_COMPLETE;

			if (!(sp->flags & SRB_FCP_CMD_PKT)) {
				/* Place block on done queue */
				ql_add_link_b(done_q, &sp->cmd);
			} else {
				ql_fast_fcp_post(sp);
			}
		} else if (handle != QL_FCA_BRAND) {
			if (sp == NULL) {
				EL(ha, "%xh unknown IOCB handle=%xh\n",
				    mb[0], handle);
			} else {
				EL(ha, "%xh mismatch IOCB handle pkt=%xh, "
				    "sp=%xh\n", mb[0], handle, sp->handle);
			}

			EL(ha, "%xh Fast post, mbx1=%xh, mbx2=%xh, mbx3=%xh,"
			    "mbx6=%xh, mbx7=%xh\n", mb[0],
			    RD16_IO_REG(ha, mailbox[1]),
			    RD16_IO_REG(ha, mailbox[2]),
			    RD16_IO_REG(ha, mailbox[3]),
			    RD16_IO_REG(ha, mailbox[6]),
			    RD16_IO_REG(ha, mailbox[7]));

			(void) ql_binary_fw_dump(ha, FALSE);

			if (!(ha->task_daemon_flags &
			    (ISP_ABORT_NEEDED | ABORT_ISP_ACTIVE))) {
				EL(ha, "%xh ISP Invalid handle, "
				    "isp_abort_needed\n", mb[0]);
				*set_flags |= ISP_ABORT_NEEDED;
			}
		}
		break;

	case MBA_RESET:		/* Reset */
		EL(ha, "%xh Reset received\n", mb[0]);
		*set_flags |= RESET_MARKER_NEEDED;
		break;

	case MBA_SYSTEM_ERR:		/* System Error */
		mb[1] = RD16_IO_REG(ha, mailbox[1]);
		mb[2] = RD16_IO_REG(ha, mailbox[2]);
		mb[3] = RD16_IO_REG(ha, mailbox[3]);

		EL(ha, "%xh ISP System Error, isp_abort_needed\n mbx1=%xh, "
		    "mbx2=%xh, mbx3=%xh, mbx4=%xh, mbx5=%xh, mbx6=%xh,\n "
		    "mbx7=%xh, mbx8=%xh, mbx9=%xh, mbx10=%xh, mbx11=%xh, "
		    "mbx12=%xh,\n", mb[0], mb[1], mb[2], mb[3],
		    RD16_IO_REG(ha, mailbox[4]), RD16_IO_REG(ha, mailbox[5]),
		    RD16_IO_REG(ha, mailbox[6]), RD16_IO_REG(ha, mailbox[7]),
		    RD16_IO_REG(ha, mailbox[8]), RD16_IO_REG(ha, mailbox[9]),
		    RD16_IO_REG(ha, mailbox[10]), RD16_IO_REG(ha, mailbox[11]),
		    RD16_IO_REG(ha, mailbox[12]));

		EL(ha, "%xh ISP System Error, isp_abort_needed\n mbx13=%xh, "
		    "mbx14=%xh, mbx15=%xh, mbx16=%xh, mbx17=%xh, mbx18=%xh,\n"
		    "mbx19=%xh, mbx20=%xh, mbx21=%xh, mbx22=%xh, mbx23=%xh\n",
		    mb[0], RD16_IO_REG(ha, mailbox[13]),
		    RD16_IO_REG(ha, mailbox[14]), RD16_IO_REG(ha, mailbox[15]),
		    RD16_IO_REG(ha, mailbox[16]), RD16_IO_REG(ha, mailbox[17]),
		    RD16_IO_REG(ha, mailbox[18]), RD16_IO_REG(ha, mailbox[19]),
		    RD16_IO_REG(ha, mailbox[20]), RD16_IO_REG(ha, mailbox[21]),
		    RD16_IO_REG(ha, mailbox[22]),
		    RD16_IO_REG(ha, mailbox[23]));

		if (ha->reg_off->mbox_cnt > 24) {
			EL(ha, "%xh ISP System Error, mbx24=%xh, mbx25=%xh, "
			    "mbx26=%xh,\n mbx27=%xh, mbx28=%xh, mbx29=%xh, "
			    "mbx30=%xh, mbx31=%xh\n", mb[0],
			    RD16_IO_REG(ha, mailbox[24]),
			    RD16_IO_REG(ha, mailbox[25]),
			    RD16_IO_REG(ha, mailbox[26]),
			    RD16_IO_REG(ha, mailbox[27]),
			    RD16_IO_REG(ha, mailbox[28]),
			    RD16_IO_REG(ha, mailbox[29]),
			    RD16_IO_REG(ha, mailbox[30]),
			    RD16_IO_REG(ha, mailbox[31]));
		}

		(void) ql_binary_fw_dump(ha, FALSE);

		(void) ql_flash_errlog(ha, FLASH_ERRLOG_AEN_8002, mb[1],
		    mb[2], mb[3]);

		*set_flags |= ISP_ABORT_NEEDED;
		ha->xioctl->ControllerErrorCount++;
		break;

	case MBA_REQ_TRANSFER_ERR:  /* Request Transfer Error */
		EL(ha, "%xh Request Transfer Error received, "
		    "isp_abort_needed\n", mb[0]);

		(void) ql_flash_errlog(ha, FLASH_ERRLOG_AEN_8003,
		    RD16_IO_REG(ha, mailbox[1]), RD16_IO_REG(ha, mailbox[2]),
		    RD16_IO_REG(ha, mailbox[3]));

		*set_flags |= ISP_ABORT_NEEDED;
		ha->xioctl->ControllerErrorCount++;
		break;

	case MBA_RSP_TRANSFER_ERR:  /* Response Xfer Err */
		EL(ha, "%xh Response Transfer Error received,"
		    " isp_abort_needed\n", mb[0]);

		(void) ql_flash_errlog(ha, FLASH_ERRLOG_AEN_8004,
		    RD16_IO_REG(ha, mailbox[1]), RD16_IO_REG(ha, mailbox[2]),
		    RD16_IO_REG(ha, mailbox[3]));

		*set_flags |= ISP_ABORT_NEEDED;
		ha->xioctl->ControllerErrorCount++;
		break;

	case MBA_WAKEUP_THRES: /* Request Queue Wake-up */
		EL(ha, "%xh Request Queue Wake-up received\n",
		    mb[0]);
		break;

	case MBA_MENLO_ALERT:	/* Menlo Alert Notification */
		mb[1] = RD16_IO_REG(ha, mailbox[1]);
		mb[2] = RD16_IO_REG(ha, mailbox[2]);
		mb[3] = RD16_IO_REG(ha, mailbox[3]);

		EL(ha, "%xh Menlo Alert Notification received, mbx1=%xh,"
		    " mbx2=%xh, mbx3=%xh\n", mb[0], mb[1], mb[2], mb[3]);

		switch (mb[1]) {
		case MLA_LOGIN_OPERATIONAL_FW:
			ADAPTER_STATE_LOCK(ha);
			ha->flags |= MENLO_LOGIN_OPERATIONAL;
			ADAPTER_STATE_UNLOCK(ha);
			break;
		case MLA_PANIC_RECOVERY:
		case MLA_LOGIN_DIAGNOSTIC_FW:
		case MLA_LOGIN_GOLDEN_FW:
		case MLA_REJECT_RESPONSE:
		default:
			break;
		}
		break;

	case MBA_LIP_F8:	/* Received a LIP F8. */
	case MBA_LIP_RESET:	/* LIP reset occurred. */
	case MBA_LIP_OCCURRED:	/* Loop Initialization Procedure */
		EL(ha, "%xh LIP received\n", mb[0]);

		ADAPTER_STATE_LOCK(ha);
		ha->flags &= ~POINT_TO_POINT;
		ADAPTER_STATE_UNLOCK(ha);

		if (!(ha->task_daemon_flags & LOOP_DOWN)) {
			*set_flags |= LOOP_DOWN;
		}
		ql_port_state(ha, FC_STATE_OFFLINE,
		    FC_STATE_CHANGE | COMMAND_WAIT_NEEDED | LOOP_DOWN);

		if (ha->loop_down_timer == LOOP_DOWN_TIMER_OFF) {
			ha->loop_down_timer = LOOP_DOWN_TIMER_START;
		}

		ha->adapter_stats->lip_count++;

		/* Update AEN queue. */
		ha->xioctl->TotalLipResets++;
		if (ha->xioctl->flags & QL_AEN_TRACKING_ENABLE) {
			ql_enqueue_aen(ha, mb[0], NULL);
		}
		break;

	case MBA_LOOP_UP:
		if (CFG_IST(ha, (CFG_CTRL_2300|CFG_CTRL_6322|CFG_CTRL_2425))) {
			mb[1] = RD16_IO_REG(ha, mailbox[1]);
			if (mb[1] == 0) {		/* 1GB */
				ha->state = FC_PORT_STATE_MASK(
				    ha->state) | FC_STATE_1GBIT_SPEED;
				index = 1;
			} else if (mb[1] == 1) {	/* 2GB */
				ha->state = FC_PORT_STATE_MASK(
				    ha->state) | FC_STATE_2GBIT_SPEED;
				index = 2;
			} else if (mb[1] == 3) {	/* 4GB */
				ha->state = FC_PORT_STATE_MASK(
				    ha->state) | FC_STATE_4GBIT_SPEED;
				index = 4;
			} else if (mb[1] == 4) {	/* 8GB */
				ha->state = FC_PORT_STATE_MASK(
				    ha->state) | FC_STATE_8GBIT_SPEED;
				index = 8;
			} else {
				ha->state = FC_PORT_STATE_MASK(
				    ha->state);
				index = 0;
			}
		} else {
			ha->state = FC_PORT_STATE_MASK(ha->state) |
			    FC_STATE_FULL_SPEED;
			index = 1;
		}

		for (vha = ha; vha != NULL; vha = vha->vp_next) {
			vha->state = FC_PORT_STATE_MASK(vha->state) |
			    FC_PORT_SPEED_MASK(ha->state);
		}
		EL(ha, "%d GB %xh Loop Up received\n", index, mb[0]);

		/* Update AEN queue. */
		if (ha->xioctl->flags & QL_AEN_TRACKING_ENABLE) {
			ql_enqueue_aen(ha, mb[0], NULL);
		}
		break;

	case MBA_LOOP_DOWN:
		EL(ha, "%xh Loop Down received, mbx1=%xh, mbx2=%xh, "
		    "mbx3=%xh\n", mb[0], RD16_IO_REG(ha, mailbox[1]),
		    RD16_IO_REG(ha, mailbox[2]), RD16_IO_REG(ha, mailbox[3]));

		if (!(ha->task_daemon_flags & LOOP_DOWN)) {
			*set_flags |= LOOP_DOWN;
		}
		ql_port_state(ha, FC_STATE_OFFLINE,
		    FC_STATE_CHANGE | COMMAND_WAIT_NEEDED | LOOP_DOWN);

		if (ha->loop_down_timer == LOOP_DOWN_TIMER_OFF) {
			ha->loop_down_timer = LOOP_DOWN_TIMER_START;
		}

		if (CFG_IST(ha, CFG_CTRL_25XX)) {
			ha->sfp_stat = RD16_IO_REG(ha, mailbox[2]);
		}

		/* Update AEN queue. */
		if (ha->xioctl->flags & QL_AEN_TRACKING_ENABLE) {
			ql_enqueue_aen(ha, mb[0], NULL);
		}
		break;

	case MBA_PORT_UPDATE:
		mb[1] = RD16_IO_REG(ha, mailbox[1]);
		mb[2] = RD16_IO_REG(ha, mailbox[2]);
		mb[3] = (uint16_t)(ha->flags & VP_ENABLED ?
		    RD16_IO_REG(ha, mailbox[3]) : 0);

		/* Locate port state structure. */
		for (vha = ha; vha != NULL; vha = vha->vp_next) {
			if (vha->vp_index == LSB(mb[3])) {
				break;
			}
		}

		if (vha == NULL) {
			break;
		}

		if (FC_PORT_STATE_MASK(vha->state) != FC_STATE_OFFLINE ||
		    (CFG_IST(ha, CFG_CTRL_2425) && (mb[1] != 0xffff ||
		    mb[2] != 6 || mb[3] != 0))) {
			EL(ha, "%xh Port Database Update, Login/Logout "
			    "received, mbx1=%xh, mbx2=%xh, mbx3=%xh\n",
			    mb[0], mb[1], mb[2], mb[3]);
		} else {
			EL(ha, "%xh Port Database Update received, mbx1=%xh,"
			    " mbx2=%xh, mbx3=%xh\n", mb[0], mb[1], mb[2],
			    mb[3]);
			*set_flags |= LOOP_RESYNC_NEEDED;
			*set_flags &= ~LOOP_DOWN;
			*reset_flags |= LOOP_DOWN;
			*reset_flags &= ~LOOP_RESYNC_NEEDED;
			vha->loop_down_timer = LOOP_DOWN_TIMER_OFF;
			TASK_DAEMON_LOCK(ha);
			vha->task_daemon_flags |= LOOP_RESYNC_NEEDED;
			vha->task_daemon_flags &= ~LOOP_DOWN;
			TASK_DAEMON_UNLOCK(ha);
			ADAPTER_STATE_LOCK(ha);
			vha->flags &= ~COMMAND_ABORT_TIMEOUT;
			ADAPTER_STATE_UNLOCK(ha);
		}

		/* Update AEN queue. */
		if (ha->xioctl->flags & QL_AEN_TRACKING_ENABLE) {
			ql_enqueue_aen(ha, mb[0], NULL);
		}
		break;

	case MBA_RSCN_UPDATE:
		mb[1] = RD16_IO_REG(ha, mailbox[1]);
		mb[2] = RD16_IO_REG(ha, mailbox[2]);
		mb[3] = (uint16_t)(ha->flags & VP_ENABLED ?
		    RD16_IO_REG(ha, mailbox[3]) : 0);

		/* Locate port state structure. */
		for (vha = ha; vha != NULL; vha = vha->vp_next) {
			if (vha->vp_index == LSB(mb[3])) {
				break;
			}
		}

		if (vha == NULL) {
			break;
		}

		if (LSB(mb[1]) == vha->d_id.b.domain &&
		    MSB(mb[2]) == vha->d_id.b.area &&
		    LSB(mb[2]) == vha->d_id.b.al_pa) {
			EL(ha, "%xh RSCN match adapter, mbx1=%xh, mbx2=%xh, "
			    "mbx3=%xh\n", mb[0], mb[1], mb[2], mb[3]);
		} else {
			EL(ha, "%xh RSCN received, mbx1=%xh, mbx2=%xh, "
			    "mbx3=%xh\n", mb[0], mb[1], mb[2], mb[3]);
			if (FC_PORT_STATE_MASK(vha->state) !=
			    FC_STATE_OFFLINE) {
				ql_rcv_rscn_els(vha, &mb[0], done_q);
				TASK_DAEMON_LOCK(ha);
				vha->task_daemon_flags |= RSCN_UPDATE_NEEDED;
				TASK_DAEMON_UNLOCK(ha);
				*set_flags |= RSCN_UPDATE_NEEDED;
			}
		}

		/* Update AEN queue. */
		if (ha->xioctl->flags & QL_AEN_TRACKING_ENABLE) {
			ql_enqueue_aen(ha, mb[0], NULL);
		}
		break;

	case MBA_LIP_ERROR:	/* Loop initialization errors. */
		EL(ha, "%xh LIP error received, mbx1=%xh\n", mb[0],
		    RD16_IO_REG(ha, mailbox[1]));
		break;

	case MBA_IP_RECEIVE:
	case MBA_IP_BROADCAST:
		mb[1] = RD16_IO_REG(ha, mailbox[1]);
		mb[2] = RD16_IO_REG(ha, mailbox[2]);
		mb[3] = RD16_IO_REG(ha, mailbox[3]);

		EL(ha, "%xh IP packet/broadcast received, mbx1=%xh, "
		    "mbx2=%xh, mbx3=%xh\n", mb[0], mb[1], mb[2], mb[3]);

		/* Locate device queue. */
		s_id.b.al_pa = LSB(mb[2]);
		s_id.b.area = MSB(mb[2]);
		s_id.b.domain = LSB(mb[1]);
		if ((tq = ql_d_id_to_queue(ha, s_id)) == NULL) {
			EL(ha, "Unknown IP device=%xh\n", s_id.b24);
			break;
		}

		cnt = (uint16_t)(CFG_IST(ha, CFG_CTRL_2425) ?
		    CHAR_TO_SHORT(ha->ip_init_ctrl_blk.cb24.buf_size[0],
		    ha->ip_init_ctrl_blk.cb24.buf_size[1]) :
		    CHAR_TO_SHORT(ha->ip_init_ctrl_blk.cb.buf_size[0],
		    ha->ip_init_ctrl_blk.cb.buf_size[1]));

		tq->ub_sequence_length = mb[3];
		tq->ub_total_seg_cnt = (uint8_t)(mb[3] / cnt);
		if (mb[3] % cnt) {
			tq->ub_total_seg_cnt++;
		}
		cnt = (uint16_t)(tq->ub_total_seg_cnt + 10);

		for (index = 10; index < ha->reg_off->mbox_cnt && index < cnt;
		    index++) {
			mb[index] = RD16_IO_REG(ha, mailbox[index]);
		}

		tq->ub_seq_id = ++ha->ub_seq_id;
		tq->ub_seq_cnt = 0;
		tq->ub_frame_ro = 0;
		tq->ub_loop_id = (uint16_t)(mb[0] == MBA_IP_BROADCAST ?
		    (CFG_IST(ha, CFG_CTRL_2425) ? BROADCAST_24XX_HDL :
		    IP_BROADCAST_LOOP_ID) : tq->loop_id);
		ha->rcv_dev_q = tq;

		for (cnt = 10; cnt < ha->reg_off->mbox_cnt &&
		    tq->ub_seq_cnt < tq->ub_total_seg_cnt; cnt++) {
			if (ql_ub_frame_hdr(ha, tq, mb[cnt], done_q) !=
			    QL_SUCCESS) {
				EL(ha, "ql_ub_frame_hdr failed, "
				    "isp_abort_needed\n");
				*set_flags |= ISP_ABORT_NEEDED;
				break;
			}
		}
		break;

	case MBA_IP_LOW_WATER_MARK:
	case MBA_IP_RCV_BUFFER_EMPTY:
		EL(ha, "%xh IP low water mark / RCV buffer empty received\n",
		    mb[0]);
		*set_flags |= NEED_UNSOLICITED_BUFFERS;
		break;

	case MBA_IP_HDR_DATA_SPLIT:
		EL(ha, "%xh IP HDR data split received\n", mb[0]);
		break;

	case MBA_POINT_TO_POINT:
		EL(ha, "%xh Point to Point Mode received\n", mb[0]);
		ADAPTER_STATE_LOCK(ha);
		ha->flags |= POINT_TO_POINT;
		ADAPTER_STATE_UNLOCK(ha);

		if (!(ha->task_daemon_flags & LOOP_DOWN)) {
			*set_flags |= LOOP_DOWN;
		}
		ql_port_state(ha, FC_STATE_OFFLINE,
		    FC_STATE_CHANGE | COMMAND_WAIT_NEEDED | LOOP_DOWN);

		if (ha->loop_down_timer == LOOP_DOWN_TIMER_OFF) {
			ha->loop_down_timer = LOOP_DOWN_TIMER_START;
		}
		break;

	case MBA_CHG_IN_CONNECTION:
		mb[1] = RD16_IO_REG(ha, mailbox[1]);
		if (mb[1] == 2) {
			EL(ha, "%xh Change In Connection received, "
			    "mbx1=%xh\n",  mb[0], mb[1]);
			ADAPTER_STATE_LOCK(ha);
			ha->flags &= ~POINT_TO_POINT;
			ADAPTER_STATE_UNLOCK(ha);
			if (ha->topology & QL_N_PORT) {
				ha->topology = (uint8_t)(ha->topology &
				    ~QL_N_PORT);
				ha->topology = (uint8_t)(ha->topology |
				    QL_NL_PORT);
			}
		} else {
			EL(ha, "%xh Change In Connection received, "
			    "mbx1=%xh, isp_abort_needed\n", mb[0], mb[1]);
			*set_flags |= ISP_ABORT_NEEDED;
		}
		break;

	case MBA_ZIO_UPDATE:
		EL(ha, "%xh ZIO response received\n", mb[0]);

		ha->isp_rsp_index = RD16_IO_REG(ha, resp_in);
		ql_response_pkt(ha, done_q, set_flags, reset_flags, intr_clr);
		intr = B_FALSE;
		break;

	case MBA_PORT_BYPASS_CHANGED:
		EL(ha, "%xh Port Bypass Changed received, mbx1=%xh\n",
		    mb[0], RD16_IO_REG(ha, mailbox[1]));
		/*
		 * Event generated when there is a transition on
		 * port bypass of crystal+.
		 * Mailbox 1:	Bit 0 - External.
		 *		Bit 2 - Internal.
		 * When the bit is 0, the port is bypassed.
		 *
		 * For now we will generate a LIP for all cases.
		 */
		*set_flags |= HANDLE_PORT_BYPASS_CHANGE;
		break;

	case MBA_RECEIVE_ERROR:
		EL(ha, "%xh Receive Error received, mbx1=%xh, mbx2=%xh\n",
		    mb[0], RD16_IO_REG(ha, mailbox[1]),
		    RD16_IO_REG(ha, mailbox[2]));
		break;

	case MBA_LS_RJT_SENT:
		EL(ha, "%xh LS_RJT Response Sent ELS=%xh\n", mb[0],
		    RD16_IO_REG(ha, mailbox[1]));
		break;

	case MBA_FW_RESTART_COMP:
		EL(ha, "%xh firmware restart complete received mb1=%xh\n",
		    mb[0], RD16_IO_REG(ha, mailbox[1]));
		break;

	default:
		EL(ha, "%xh UNKNOWN event received, mbx1=%xh, mbx2=%xh, "
		    "mbx3=%xh\n", mb[0], RD16_IO_REG(ha, mailbox[1]),
		    RD16_IO_REG(ha, mailbox[2]), RD16_IO_REG(ha, mailbox[3]));
		break;
	}

	/* Clear RISC interrupt */
	if (intr && intr_clr) {
		CFG_IST(ha, CFG_CTRL_2425) ?
		    WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT) :
		    WRT16_IO_REG(ha, hccr, HC_CLR_RISC_INT);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_fast_fcp_post
 *	Fast path for good SCSI I/O completion.
 *
 * Input:
 *	sp:	SRB pointer.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_fast_fcp_post(ql_srb_t *sp)
{
	ql_adapter_state_t	*ha = sp->ha;
	ql_lun_t		*lq = sp->lun_queue;
	ql_tgt_t		*tq = lq->target_queue;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	ASSERT(sp->flags & SRB_FCP_CMD_PKT && ha &&
	    sp->pkt->pkt_reason == CS_COMPLETE);

	/* Acquire device queue lock. */
	DEVICE_QUEUE_LOCK(tq);

	/* Decrement outstanding commands on device. */
	if (tq->outcnt != 0) {
		tq->outcnt--;
	}

	if (sp->flags & SRB_FCP_CMD_PKT) {
		if (sp->fcp->fcp_cntl.cntl_qtype == FCP_QTYPE_UNTAGGED) {
			/*
			 * Clear the flag for this LUN so that
			 * untagged commands can be submitted
			 * for it.
			 */
			lq->flags &= ~LQF_UNTAGGED_PENDING;
		}

		if (lq->lun_outcnt != 0) {
			lq->lun_outcnt--;
		}
	}

	/* Reset port down retry count on good completion. */
	tq->port_down_retry_count = ha->port_down_retry_count;
	tq->qfull_retry_count = ha->qfull_retry_count;

	/* Remove command from watchdog queue. */
	if (sp->flags & SRB_WATCHDOG_ENABLED) {
		ql_remove_link(&tq->wdg, &sp->wdg);
		sp->flags &= ~SRB_WATCHDOG_ENABLED;
	}

	if (lq->cmd.first != NULL) {
		ql_next(ha, lq);
	} else {
		/* Release LU queue specific lock. */
		DEVICE_QUEUE_UNLOCK(tq);
		if (ha->pha->pending_cmds.first != NULL) {
			ql_start_iocb(ha, NULL);
		}
	}

	/* Sync buffers if required.  */
	if (sp->flags & SRB_MS_PKT) {
		(void) ddi_dma_sync(sp->pkt->pkt_resp_dma, 0, 0,
		    DDI_DMA_SYNC_FORCPU);
	}

	/* Map ISP completion codes. */
	sp->pkt->pkt_expln = FC_EXPLN_NONE;
	sp->pkt->pkt_action = FC_ACTION_RETRYABLE;
	sp->pkt->pkt_state = FC_PKT_SUCCESS;

	/* Now call the pkt completion callback */
	if (sp->flags & SRB_POLL) {
		sp->flags &= ~SRB_POLL;
	} else if (sp->pkt->pkt_comp) {
		INTR_UNLOCK(ha);
		(*sp->pkt->pkt_comp)(sp->pkt);
		INTR_LOCK(ha);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_response_pkt
 *	Processes response entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	done_q:		head pointer to done queue.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *	intr_clr:	early interrupt clear
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
static void
ql_response_pkt(ql_adapter_state_t *ha, ql_head_t *done_q, uint32_t *set_flags,
    uint32_t *reset_flags, int intr_clr)
{
	response_t	*pkt;
	uint32_t	dma_sync_size_1 = 0;
	uint32_t	dma_sync_size_2 = 0;
	int		status = 0;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Clear RISC interrupt */
	if (intr_clr) {
		CFG_IST(ha, CFG_CTRL_2425) ?
		    WRT32_IO_REG(ha, hccr, HC24_CLR_RISC_INT) :
		    WRT16_IO_REG(ha, hccr, HC_CLR_RISC_INT);
	}

	if (ha->isp_rsp_index >= RESPONSE_ENTRY_CNT) {
		EL(ha, "index error = %xh, isp_abort_needed",
		    ha->isp_rsp_index);
		*set_flags |= ISP_ABORT_NEEDED;
		return;
	}

	if ((ha->flags & ONLINE) == 0) {
		QL_PRINT_3(CE_CONT, "(%d): not onlne, done\n", ha->instance);
		return;
	}

	/* Calculate size of response queue entries to sync. */
	if (ha->isp_rsp_index > ha->rsp_ring_index) {
		dma_sync_size_1 = (uint32_t)
		    ((uint32_t)(ha->isp_rsp_index - ha->rsp_ring_index) *
		    RESPONSE_ENTRY_SIZE);
	} else if (ha->isp_rsp_index == 0) {
		dma_sync_size_1 = (uint32_t)
		    ((uint32_t)(RESPONSE_ENTRY_CNT - ha->rsp_ring_index) *
		    RESPONSE_ENTRY_SIZE);
	} else {
		/* Responses wrap around the Q */
		dma_sync_size_1 = (uint32_t)
		    ((uint32_t)(RESPONSE_ENTRY_CNT - ha->rsp_ring_index) *
		    RESPONSE_ENTRY_SIZE);
		dma_sync_size_2 = (uint32_t)
		    (ha->isp_rsp_index * RESPONSE_ENTRY_SIZE);
	}

	/* Sync DMA buffer. */
	(void) ddi_dma_sync(ha->hba_buf.dma_handle,
	    (off_t)(ha->rsp_ring_index * RESPONSE_ENTRY_SIZE +
	    RESPONSE_Q_BUFFER_OFFSET), dma_sync_size_1,
	    DDI_DMA_SYNC_FORKERNEL);
	if (dma_sync_size_2) {
		(void) ddi_dma_sync(ha->hba_buf.dma_handle,
		    RESPONSE_Q_BUFFER_OFFSET, dma_sync_size_2,
		    DDI_DMA_SYNC_FORKERNEL);
	}

	while (ha->rsp_ring_index != ha->isp_rsp_index) {
		pkt = ha->response_ring_ptr;

		QL_PRINT_5(CE_CONT, "(%d): ha->rsp_rg_idx=%xh, mbx[5]=%xh\n",
		    ha->instance, ha->rsp_ring_index, ha->isp_rsp_index);
		QL_DUMP_5((uint8_t *)ha->response_ring_ptr, 8,
		    RESPONSE_ENTRY_SIZE);

		/* Adjust ring index. */
		ha->rsp_ring_index++;
		if (ha->rsp_ring_index == RESPONSE_ENTRY_CNT) {
			ha->rsp_ring_index = 0;
			ha->response_ring_ptr = ha->response_ring_bp;
		} else {
			ha->response_ring_ptr++;
		}

		/* Process packet. */
		if (ha->status_srb != NULL && pkt->entry_type !=
		    STATUS_CONT_TYPE) {
			ql_add_link_b(done_q, &ha->status_srb->cmd);
			ha->status_srb = NULL;
		}

		pkt->entry_status = (uint8_t)(CFG_IST(ha, CFG_CTRL_2425) ?
		    pkt->entry_status & 0x3c : pkt->entry_status & 0x7e);

		if (pkt->entry_status != 0) {
			ql_error_entry(ha, pkt, done_q, set_flags,
			    reset_flags);
		} else {
			switch (pkt->entry_type) {
			case STATUS_TYPE:
				status |= CFG_IST(ha, CFG_CTRL_2425) ?
				    ql_24xx_status_entry(ha,
				    (sts_24xx_entry_t *)pkt, done_q, set_flags,
				    reset_flags) :
				    ql_status_entry(ha, (sts_entry_t *)pkt,
				    done_q, set_flags, reset_flags);
				break;

			case STATUS_CONT_TYPE:
				ql_status_cont_entry(ha,
				    (sts_cont_entry_t *)pkt, done_q, set_flags,
				    reset_flags);
				break;

			case IMMEDIATE_NOTIFY_TYPE:
				if (CFG_IST(ha, CFG_ENABLE_TARGET_MODE)) {
					ql_immediate_notify_entry(ha,
					    (immediate_notify_entry_t *)pkt,
					    done_q, set_flags, reset_flags);
				}
				break;

			case NOTIFY_ACKNOWLEDGE_TYPE:
				if (CFG_IST(ha, CFG_ENABLE_TARGET_MODE)) {
					ql_notify_acknowledge_entry(ha,
					    (notify_acknowledge_entry_t *)pkt,
					    done_q, set_flags, reset_flags);
				}
				break;

			case ATIO_TYPE:
				if (CFG_IST(ha, CFG_ENABLE_TARGET_MODE)) {
					ql_accept_target_io_entry(ha,
					    (atio_entry_t *)pkt, done_q,
					    set_flags, reset_flags);
				}
				break;

			case CTIO_TYPE_2:
			case CTIO_TYPE_3:
				if (CFG_IST(ha, CFG_ENABLE_TARGET_MODE)) {
					ql_continue_target_io_entry(ha,
					    (ctio_entry_t *)pkt, done_q,
					    set_flags, reset_flags);
				}
				break;

			case IP_TYPE:
			case IP_A64_TYPE:
			case IP_CMD_TYPE:
				ql_ip_entry(ha, (ip_entry_t *)pkt, done_q,
				    set_flags, reset_flags);
				break;
			case IP_RECEIVE_TYPE:
				ql_ip_rcv_entry(ha,
				    (ip_rcv_entry_t *)pkt, done_q, set_flags,
				    reset_flags);
				break;
			case IP_RECEIVE_CONT_TYPE:
				ql_ip_rcv_cont_entry(ha,
				    (ip_rcv_cont_entry_t *)pkt,	done_q,
				    set_flags, reset_flags);
				break;
			case IP_24XX_RECEIVE_TYPE:
				ql_ip_24xx_rcv_entry(ha,
				    (ip_rcv_24xx_entry_t *)pkt, done_q,
				    set_flags, reset_flags);
				break;
			case MS_TYPE:
				ql_ms_entry(ha, (ms_entry_t *)pkt, done_q,
				    set_flags, reset_flags);
				break;
			case REPORT_ID_TYPE:
				ql_report_id_entry(ha, (report_id_1_t *)pkt,
				    done_q, set_flags, reset_flags);
				break;
			case IP_BUF_POOL_TYPE:
			case MARKER_TYPE:
			case VP_MODIFY_TYPE:
			case VP_CONTROL_TYPE:
				break;
			default:
				EL(ha, "Unknown IOCB entry type=%xh\n",
				    pkt->entry_type);
				break;
			}
		}
	}

	/* Inform RISC of processed responses. */
	WRT16_IO_REG(ha, resp_out, ha->rsp_ring_index);

	/* RESET packet received delay for possible async event. */
	if (status & BIT_0) {
		drv_usecwait(500000);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_error_entry
 *	Processes error entry.
 *
 * Input:
 *	ha = adapter state pointer.
 *	pkt = entry pointer.
 *	done_q = head pointer to done queue.
 *	set_flags = task daemon flags to set.
 *	reset_flags = task daemon flags to reset.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_error_entry(ql_adapter_state_t *ha, response_t *pkt, ql_head_t *done_q,
    uint32_t *set_flags, uint32_t *reset_flags)
{
	ql_srb_t	*sp;
	uint32_t	index, cnt;

	if (pkt->entry_type == INVALID_ENTRY_TYPE) {
		EL(ha, "Aborted command\n");
		return;
	}

	QL_PRINT_2(CE_CONT, "(%d): started, packet:\n", ha->instance);
	QL_DUMP_2((uint8_t *)pkt, 8, RESPONSE_ENTRY_SIZE);

	if (pkt->entry_status & BIT_6) {
		EL(ha, "Request Queue DMA error\n");
	} else if (pkt->entry_status & BIT_5) {
		EL(ha, "Invalid Entry Order\n");
	} else if (pkt->entry_status & BIT_4) {
		EL(ha, "Invalid Entry Count\n");
	} else if (pkt->entry_status & BIT_3) {
		EL(ha, "Invalid Entry Parameter\n");
	} else if (pkt->entry_status & BIT_2) {
		EL(ha, "Invalid Entry Type\n");
	} else if (pkt->entry_status & BIT_1) {
		EL(ha, "Busy\n");
	} else {
		EL(ha, "UNKNOWN flag = %xh error\n", pkt->entry_status);
	}

	/* Get handle. */
	cnt = ddi_get32(ha->hba_buf.acc_handle, &pkt->handle);
	index = cnt & OSC_INDEX_MASK;

	/* Validate handle. */
	sp = index < MAX_OUTSTANDING_COMMANDS ? ha->outstanding_cmds[index] :
	    NULL;

	if (sp != NULL && sp->handle == cnt) {
		ha->outstanding_cmds[index] = NULL;
		sp->handle = 0;
		sp->flags &= ~SRB_IN_TOKEN_ARRAY;

		/* Bad payload or header */
		if (pkt->entry_status & (BIT_5 + BIT_4 + BIT_3 + BIT_2)) {
			/* Bad payload or header, set error status. */
			sp->pkt->pkt_reason = CS_BAD_PAYLOAD;
		} else if (pkt->entry_status & BIT_1) /* FULL flag */ {
			sp->pkt->pkt_reason = CS_QUEUE_FULL;
		} else {
			/* Set error status. */
			sp->pkt->pkt_reason = CS_UNKNOWN;
		}

		/* Set completed status. */
		sp->flags |= SRB_ISP_COMPLETED;

		/* Place command on done queue. */
		ql_add_link_b(done_q, &sp->cmd);

	} else {
		if (sp == NULL) {
			EL(ha, "unknown IOCB handle=%xh\n", cnt);
		} else {
			EL(ha, "mismatch IOCB handle pkt=%xh, sp=%xh\n",
			    cnt, sp->handle);
		}

		(void) ql_binary_fw_dump(ha, FALSE);

		if (!(ha->task_daemon_flags & (ISP_ABORT_NEEDED |
		    ABORT_ISP_ACTIVE))) {
			EL(ha, "ISP Invalid handle, isp_abort_needed\n");
			*set_flags |= ISP_ABORT_NEEDED;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_status_entry
 *	Processes received ISP2200-2300 status entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Returns:
 *	BIT_0 = CS_RESET status received.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static int
ql_status_entry(ql_adapter_state_t *ha, sts_entry_t *pkt,
    ql_head_t *done_q, uint32_t *set_flags, uint32_t *reset_flags)
{
	ql_srb_t		*sp;
	uint32_t		index, cnt;
	uint16_t		comp_status;
	int			rval = 0;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Get handle. */
	cnt = ddi_get32(ha->hba_buf.acc_handle, &pkt->handle);
	index = cnt & OSC_INDEX_MASK;

	/* Validate handle. */
	sp = index < MAX_OUTSTANDING_COMMANDS ? ha->outstanding_cmds[index] :
	    NULL;

	if (sp != NULL && sp->handle == cnt) {
		comp_status = (uint16_t)ddi_get16(ha->hba_buf.acc_handle,
		    &pkt->comp_status);

		/*
		 * We dont care about SCSI QFULLs.
		 */
		if (comp_status == CS_QUEUE_FULL) {
			EL(ha, "CS_QUEUE_FULL, d_id=%xh, lun=%xh\n",
			    sp->lun_queue->target_queue->d_id.b24,
			    sp->lun_queue->lun_no);
			comp_status = CS_COMPLETE;
		}

		/*
		 * 2300 firmware marks completion status as data underrun
		 * for scsi qfulls. Make it transport complete.
		 */
		if ((CFG_IST(ha, (CFG_CTRL_2300 | CFG_CTRL_6322))) &&
		    (comp_status == CS_DATA_UNDERRUN) &&
		    (pkt->scsi_status_l != 0)) {
			comp_status = CS_COMPLETE;
		}

		/*
		 * Workaround T3 issue where we do not get any data xferred
		 * but get back a good status.
		 */
		if ((pkt->state_flags_h & SF_XFERRED_DATA) == 0 &&
		    comp_status == CS_COMPLETE &&
		    pkt->scsi_status_l == 0 &&
		    (pkt->scsi_status_h & FCP_RSP_MASK) == 0 &&
		    pkt->residual_length == 0 &&
		    sp->fcp &&
		    sp->fcp->fcp_data_len != 0 &&
		    (pkt->state_flags_l & (SF_DATA_OUT | SF_DATA_IN)) ==
		    SF_DATA_OUT) {
			comp_status = CS_ABORTED;
		}

		if (sp->flags & SRB_MS_PKT) {
			/*
			 * Ideally it should never be true. But there
			 * is a bug in FW which upon receiving invalid
			 * parameters in MS IOCB returns it as
			 * status entry and not as ms entry type.
			 */
			ql_ms_entry(ha, (ms_entry_t *)pkt, done_q,
			    set_flags, reset_flags);
			QL_PRINT_3(CE_CONT, "(%d): ql_ms_entry done\n",
			    ha->instance);
			return (0);
		}

		ha->outstanding_cmds[index] = NULL;
		sp->handle = 0;
		sp->flags &= ~SRB_IN_TOKEN_ARRAY;

		/*
		 * Fast path to good SCSI I/O completion
		 */
		if ((comp_status == CS_COMPLETE) &
		    (!pkt->scsi_status_l) &
		    (!(pkt->scsi_status_h & FCP_RSP_MASK))) {
			/* Set completed status. */
			sp->flags |= SRB_ISP_COMPLETED;
			sp->pkt->pkt_reason = comp_status;
			ql_fast_fcp_post(sp);
			QL_PRINT_3(CE_CONT, "(%d): ql_fast_fcp_post done\n",
			    ha->instance);
			return (0);
		}
		rval = ql_status_error(ha, sp, pkt, done_q, set_flags,
		    reset_flags);
	} else {
		if (sp == NULL) {
			EL(ha, "unknown IOCB handle=%xh\n", cnt);
		} else {
			EL(ha, "mismatch IOCB handle pkt=%xh, sp=%xh\n",
			    cnt, sp->handle);
		}

		(void) ql_binary_fw_dump(ha, FALSE);

		if (!(ha->task_daemon_flags & (ISP_ABORT_NEEDED |
		    ABORT_ISP_ACTIVE))) {
			EL(ha, "ISP Invalid handle, isp_abort_needed\n");
			*set_flags |= ISP_ABORT_NEEDED;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_24xx_status_entry
 *	Processes received ISP24xx status entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Returns:
 *	BIT_0 = CS_RESET status received.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static int
ql_24xx_status_entry(ql_adapter_state_t *ha, sts_24xx_entry_t *pkt,
    ql_head_t *done_q, uint32_t *set_flags, uint32_t *reset_flags)
{
	ql_srb_t		*sp;
	uint32_t		index, cnt;
	uint16_t		comp_status;
	int			rval = 0;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Get handle. */
	cnt = ddi_get32(ha->hba_buf.acc_handle, &pkt->handle);
	index = cnt & OSC_INDEX_MASK;

	/* Validate handle. */
	sp = index < MAX_OUTSTANDING_COMMANDS ? ha->outstanding_cmds[index] :
	    NULL;

	if (sp != NULL && sp->handle == cnt) {
		comp_status = (uint16_t)ddi_get16(ha->hba_buf.acc_handle,
		    &pkt->comp_status);

		/*
		 * We dont care about SCSI QFULLs.
		 */
		if (comp_status == CS_QUEUE_FULL) {
			EL(sp->ha, "CS_QUEUE_FULL, d_id=%xh, lun=%xh\n",
			    sp->lun_queue->target_queue->d_id.b24,
			    sp->lun_queue->lun_no);
			comp_status = CS_COMPLETE;
		}

		/*
		 * 2300 firmware marks completion status as data underrun
		 * for scsi qfulls. Make it transport complete.
		 */
		if ((comp_status == CS_DATA_UNDERRUN) &&
		    (pkt->scsi_status_l != 0)) {
			comp_status = CS_COMPLETE;
		}

		/*
		 * Workaround T3 issue where we do not get any data xferred
		 * but get back a good status.
		 */
		if (comp_status == CS_COMPLETE &&
		    pkt->scsi_status_l == 0 &&
		    (pkt->scsi_status_h & FCP_RSP_MASK) == 0 &&
		    pkt->residual_length != 0 &&
		    sp->fcp &&
		    sp->fcp->fcp_data_len != 0 &&
		    sp->fcp->fcp_cntl.cntl_write_data) {
			comp_status = CS_ABORTED;
		}

		if (sp->flags & SRB_MS_PKT) {
			/*
			 * Ideally it should never be true. But there
			 * is a bug in FW which upon receiving invalid
			 * parameters in MS IOCB returns it as
			 * status entry and not as ms entry type.
			 */
			ql_ms_entry(ha, (ms_entry_t *)pkt, done_q,
			    set_flags, reset_flags);
			QL_PRINT_3(CE_CONT, "(%d): ql_ms_entry done\n",
			    ha->instance);
			return (0);
		}

		ha->outstanding_cmds[index] = NULL;
		sp->handle = 0;
		sp->flags &= ~SRB_IN_TOKEN_ARRAY;

		/*
		 * Fast path to good SCSI I/O completion
		 */
		if ((comp_status == CS_COMPLETE) &
		    (!pkt->scsi_status_l) &
		    (!(pkt->scsi_status_h & FCP_RSP_MASK))) {
			/* Set completed status. */
			sp->flags |= SRB_ISP_COMPLETED;
			sp->pkt->pkt_reason = comp_status;
			ql_fast_fcp_post(sp);
			QL_PRINT_3(CE_CONT, "(%d): ql_fast_fcp_post done\n",
			    ha->instance);
			return (0);
		}
		rval = ql_status_error(ha, sp, (sts_entry_t *)pkt, done_q,
		    set_flags, reset_flags);
	} else {
		if (sp == NULL) {
			EL(ha, "unknown IOCB handle=%xh\n", cnt);
		} else {
			EL(sp->ha, "mismatch IOCB handle pkt=%xh, sp=%xh\n",
			    cnt, sp->handle);
		}

		(void) ql_binary_fw_dump(ha, FALSE);

		if (!(ha->task_daemon_flags & (ISP_ABORT_NEEDED |
		    ABORT_ISP_ACTIVE))) {
			EL(ha, "ISP Invalid handle, isp_abort_needed\n");
			*set_flags |= ISP_ABORT_NEEDED;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_status_error
 *	Processes received ISP status entry error.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	sp:		SRB pointer.
 *	pkt:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Returns:
 *	BIT_0 = CS_RESET status received.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static int
ql_status_error(ql_adapter_state_t *ha, ql_srb_t *sp, sts_entry_t *pkt23,
    ql_head_t *done_q, uint32_t *set_flags, uint32_t *reset_flags)
{
	uint32_t		sense_sz = 0;
	uint32_t		cnt;
	ql_tgt_t		*tq;
	fcp_rsp_t		*fcpr;
	struct fcp_rsp_info	*rsp;
	int			rval = 0;

	struct {
		uint8_t		*rsp_info;
		uint8_t		*req_sense_data;
		uint32_t	residual_length;
		uint32_t	fcp_residual_length;
		uint32_t	rsp_info_length;
		uint32_t	req_sense_length;
		uint16_t	comp_status;
		uint8_t		state_flags_l;
		uint8_t		state_flags_h;
		uint8_t		scsi_status_l;
		uint8_t		scsi_status_h;
	} sts;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (CFG_IST(ha, CFG_CTRL_2425)) {
		sts_24xx_entry_t *pkt24 = (sts_24xx_entry_t *)pkt23;

		/* Setup status. */
		sts.comp_status = (uint16_t)ddi_get16(ha->hba_buf.acc_handle,
		    &pkt24->comp_status);
		sts.scsi_status_l = pkt24->scsi_status_l;
		sts.scsi_status_h = pkt24->scsi_status_h;

		/* Setup firmware residuals. */
		sts.residual_length = sts.comp_status == CS_DATA_UNDERRUN ?
		    ddi_get32(ha->hba_buf.acc_handle,
		    (uint32_t *)&pkt24->residual_length) : 0;

		/* Setup FCP residuals. */
		sts.fcp_residual_length = sts.scsi_status_h &
		    (FCP_RESID_UNDER | FCP_RESID_OVER) ?
		    ddi_get32(ha->hba_buf.acc_handle,
		    (uint32_t *)&pkt24->fcp_rsp_residual_count) : 0;

		if ((sts.comp_status == CS_DATA_UNDERRUN) &&
		    (sts.scsi_status_h & FCP_RESID_UNDER) &&
		    (sts.residual_length != pkt24->fcp_rsp_residual_count)) {

			EL(sp->ha, "mismatch resid's: fw=%xh, pkt=%xh\n",
			    sts.residual_length,
			    pkt24->fcp_rsp_residual_count);
			sts.scsi_status_h = (uint8_t)
			    (sts.scsi_status_h & ~FCP_RESID_UNDER);
		}

		/* Setup state flags. */
		sts.state_flags_l = pkt24->state_flags_l;
		sts.state_flags_h = pkt24->state_flags_h;

		if (sp->fcp->fcp_data_len &&
		    (sts.comp_status != CS_DATA_UNDERRUN ||
		    sts.residual_length != sp->fcp->fcp_data_len)) {
			sts.state_flags_h = (uint8_t)
			    (sts.state_flags_h | SF_GOT_BUS |
			    SF_GOT_TARGET | SF_SENT_CMD |
			    SF_XFERRED_DATA | SF_GOT_STATUS);
		} else {
			sts.state_flags_h = (uint8_t)
			    (sts.state_flags_h | SF_GOT_BUS |
			    SF_GOT_TARGET | SF_SENT_CMD |
			    SF_GOT_STATUS);
		}
		if (sp->fcp->fcp_cntl.cntl_write_data) {
			sts.state_flags_l = (uint8_t)
			    (sts.state_flags_l | SF_DATA_OUT);
		} else if (sp->fcp->fcp_cntl.cntl_read_data) {
			sts.state_flags_l = (uint8_t)
			    (sts.state_flags_l | SF_DATA_IN);
		}
		if (sp->fcp->fcp_cntl.cntl_qtype == FCP_QTYPE_HEAD_OF_Q) {
			sts.state_flags_l = (uint8_t)
			    (sts.state_flags_l | SF_HEAD_OF_Q);
		} else if (sp->fcp->fcp_cntl.cntl_qtype == FCP_QTYPE_ORDERED) {
			sts.state_flags_l = (uint8_t)
			    (sts.state_flags_l | SF_ORDERED_Q);
		} else if (sp->fcp->fcp_cntl.cntl_qtype == FCP_QTYPE_SIMPLE) {
			sts.state_flags_l = (uint8_t)
			    (sts.state_flags_l | SF_SIMPLE_Q);
		}

		/* Setup FCP response info. */
		sts.rsp_info = &pkt24->rsp_sense_data[0];
		if ((sts.scsi_status_h & FCP_RSP_LEN_VALID) != 0) {
			sts.rsp_info_length = ddi_get32(ha->hba_buf.acc_handle,
			    (uint32_t *)&pkt24->fcp_rsp_data_length);
			if (sts.rsp_info_length >
			    sizeof (struct fcp_rsp_info)) {
				sts.rsp_info_length =
				    sizeof (struct fcp_rsp_info);
			}
			for (cnt = 0; cnt < sts.rsp_info_length; cnt += 4) {
				ql_chg_endian(sts.rsp_info + cnt, 4);
			}
		} else {
			sts.rsp_info_length = 0;
		}

		/* Setup sense data. */
		sts.req_sense_data =
		    &pkt24->rsp_sense_data[sts.rsp_info_length];
		if (sts.scsi_status_h & FCP_SNS_LEN_VALID) {
			sts.req_sense_length =
			    ddi_get32(ha->hba_buf.acc_handle,
			    (uint32_t *)&pkt24->fcp_sense_length);
			sts.state_flags_h = (uint8_t)
			    (sts.state_flags_h | SF_ARQ_DONE);
			sense_sz = (uint32_t)
			    (((uintptr_t)pkt24 + sizeof (sts_24xx_entry_t)) -
			    (uintptr_t)sts.req_sense_data);
			for (cnt = 0; cnt < sense_sz; cnt += 4) {
				ql_chg_endian(sts.req_sense_data + cnt, 4);
			}
		} else {
			sts.req_sense_length = 0;
		}
	} else {
		/* Setup status. */
		sts.comp_status = (uint16_t)ddi_get16(
		    ha->hba_buf.acc_handle, &pkt23->comp_status);
		sts.scsi_status_l = pkt23->scsi_status_l;
		sts.scsi_status_h = pkt23->scsi_status_h;

		/* Setup firmware residuals. */
		sts.residual_length = sts.comp_status == CS_DATA_UNDERRUN ?
		    ddi_get32(ha->hba_buf.acc_handle,
		    (uint32_t *)&pkt23->residual_length) : 0;

		/* Setup FCP residuals. */
		sts.fcp_residual_length = sts.scsi_status_h &
		    (FCP_RESID_UNDER | FCP_RESID_OVER) ?
		    sts.residual_length : 0;

		/* Setup state flags. */
		sts.state_flags_l = pkt23->state_flags_l;
		sts.state_flags_h = pkt23->state_flags_h;

		/* Setup FCP response info. */
		sts.rsp_info = &pkt23->rsp_info[0];
		if ((sts.scsi_status_h & FCP_RSP_LEN_VALID) != 0) {
			sts.rsp_info_length = ddi_get16(
			    ha->hba_buf.acc_handle,
			    (uint16_t *)&pkt23->rsp_info_length);
			if (sts.rsp_info_length >
			    sizeof (struct fcp_rsp_info)) {
				sts.rsp_info_length =
				    sizeof (struct fcp_rsp_info);
			}
		} else {
			sts.rsp_info_length = 0;
		}

		/* Setup sense data. */
		sts.req_sense_data = &pkt23->req_sense_data[0];
		sts.req_sense_length = sts.scsi_status_h & FCP_SNS_LEN_VALID ?
		    ddi_get16(ha->hba_buf.acc_handle,
		    (uint16_t *)&pkt23->req_sense_length) : 0;
	}

	bzero(sp->pkt->pkt_resp, sp->pkt->pkt_rsplen);

	fcpr = (fcp_rsp_t *)sp->pkt->pkt_resp;
	rsp = (struct fcp_rsp_info *)(sp->pkt->pkt_resp +
	    sizeof (fcp_rsp_t));

	tq = sp->lun_queue->target_queue;

	fcpr->fcp_u.fcp_status.scsi_status = sts.scsi_status_l;
	if (sts.scsi_status_h & FCP_RSP_LEN_VALID) {
		fcpr->fcp_u.fcp_status.rsp_len_set = 1;
	}
	if (sts.scsi_status_h & FCP_SNS_LEN_VALID) {
		fcpr->fcp_u.fcp_status.sense_len_set = 1;
	}
	if (sts.scsi_status_h & FCP_RESID_OVER) {
		fcpr->fcp_u.fcp_status.resid_over = 1;
	}
	if (sts.scsi_status_h & FCP_RESID_UNDER) {
		fcpr->fcp_u.fcp_status.resid_under = 1;
	}
	fcpr->fcp_u.fcp_status.reserved_1 = 0;

	/* Set ISP completion status */
	sp->pkt->pkt_reason = sts.comp_status;

	/* Update statistics. */
	if ((sts.scsi_status_h & FCP_RSP_LEN_VALID) &&
	    (sp->pkt->pkt_rsplen > sizeof (fcp_rsp_t))) {

		sense_sz = sp->pkt->pkt_rsplen - (uint32_t)sizeof (fcp_rsp_t);
		if (sense_sz > sts.rsp_info_length) {
			sense_sz = sts.rsp_info_length;
		}

		/* copy response information data. */
		if (sense_sz) {
			ddi_rep_get8(ha->hba_buf.acc_handle, (uint8_t *)rsp,
			    sts.rsp_info, sense_sz, DDI_DEV_AUTOINCR);
		}
		fcpr->fcp_response_len = sense_sz;

		rsp = (struct fcp_rsp_info *)((caddr_t)rsp +
		    fcpr->fcp_response_len);

		switch (*(sts.rsp_info + 3)) {
		case FCP_NO_FAILURE:
			break;
		case FCP_DL_LEN_MISMATCH:
			ha->adapter_stats->d_stats[lobyte(
			    tq->loop_id)].dl_len_mismatches++;
			break;
		case FCP_CMND_INVALID:
			break;
		case FCP_DATA_RO_MISMATCH:
			ha->adapter_stats->d_stats[lobyte(
			    tq->loop_id)].data_ro_mismatches++;
			break;
		case FCP_TASK_MGMT_NOT_SUPPTD:
			break;
		case FCP_TASK_MGMT_FAILED:
			ha->adapter_stats->d_stats[lobyte(
			    tq->loop_id)].task_mgmt_failures++;
			break;
		default:
			break;
		}
	} else {
		/*
		 * EL(sp->ha, "scsi_h=%xh, pkt_rsplen=%xh\n",
		 *   sts.scsi_status_h, sp->pkt->pkt_rsplen);
		 */
		fcpr->fcp_response_len = 0;
	}

	/* Set reset status received. */
	if (sts.comp_status == CS_RESET && LOOP_READY(ha)) {
		rval |= BIT_0;
	}

	if (!(tq->flags & TQF_TAPE_DEVICE) &&
	    (!(CFG_IST(ha, CFG_ENABLE_LINK_DOWN_REPORTING)) ||
	    ha->loop_down_abort_time < LOOP_DOWN_TIMER_START) &&
	    ha->task_daemon_flags & LOOP_DOWN) {
		EL(sp->ha, "Loop Not Ready Retry, d_id=%xh, lun=%xh\n",
		    tq->d_id.b24, sp->lun_queue->lun_no);

		/* Set retry status. */
		sp->flags |= SRB_RETRY;
	} else if (!(tq->flags & TQF_TAPE_DEVICE) &&
	    tq->port_down_retry_count != 0 &&
	    (sts.comp_status == CS_INCOMPLETE ||
	    sts.comp_status == CS_PORT_UNAVAILABLE ||
	    sts.comp_status == CS_PORT_LOGGED_OUT ||
	    sts.comp_status == CS_PORT_CONFIG_CHG ||
	    sts.comp_status == CS_PORT_BUSY)) {
		EL(sp->ha, "Port Down Retry=%xh, d_id=%xh, lun=%xh, count=%d"
		    "\n", sts.comp_status, tq->d_id.b24, sp->lun_queue->lun_no,
		    tq->port_down_retry_count);

		/* Set retry status. */
		sp->flags |= SRB_RETRY;

		if ((tq->flags & TQF_QUEUE_SUSPENDED) == 0) {
			/* Acquire device queue lock. */
			DEVICE_QUEUE_LOCK(tq);

			tq->flags |= TQF_QUEUE_SUSPENDED;

			/* Decrement port down count. */
			if (CFG_IST(ha, CFG_ENABLE_LINK_DOWN_REPORTING)) {
				tq->port_down_retry_count--;
			}

			DEVICE_QUEUE_UNLOCK(tq);

			if ((ha->task_daemon_flags & ABORT_ISP_ACTIVE)
			    == 0 &&
			    (sts.comp_status == CS_PORT_LOGGED_OUT ||
			    sts.comp_status == CS_PORT_UNAVAILABLE)) {
				sp->ha->adapter_stats->d_stats[lobyte(
				    tq->loop_id)].logouts_recvd++;
				ql_send_logo(sp->ha, tq, done_q);
			}

			ADAPTER_STATE_LOCK(ha);
			if (ha->port_retry_timer == 0) {
				if ((ha->port_retry_timer =
				    ha->port_down_retry_delay) == 0) {
					*set_flags |=
					    PORT_RETRY_NEEDED;
				}
			}
			ADAPTER_STATE_UNLOCK(ha);
		}
	} else if (!(tq->flags & TQF_TAPE_DEVICE) &&
	    (sts.comp_status == CS_RESET ||
	    (sts.comp_status == CS_QUEUE_FULL && tq->qfull_retry_count != 0) ||
	    (sts.comp_status == CS_ABORTED && !(sp->flags & SRB_ABORTING)))) {
		if (sts.comp_status == CS_RESET) {
			EL(sp->ha, "Reset Retry, d_id=%xh, lun=%xh\n",
			    tq->d_id.b24, sp->lun_queue->lun_no);
		} else if (sts.comp_status == CS_QUEUE_FULL) {
			EL(sp->ha, "Queue Full Retry, d_id=%xh, lun=%xh, "
			    "cnt=%d\n", tq->d_id.b24, sp->lun_queue->lun_no,
			    tq->qfull_retry_count);
			if ((tq->flags & TQF_QUEUE_SUSPENDED) == 0) {
				tq->flags |= TQF_QUEUE_SUSPENDED;

				tq->qfull_retry_count--;

				ADAPTER_STATE_LOCK(ha);
				if (ha->port_retry_timer == 0) {
					if ((ha->port_retry_timer =
					    ha->qfull_retry_delay) ==
					    0) {
						*set_flags |=
						    PORT_RETRY_NEEDED;
					}
				}
				ADAPTER_STATE_UNLOCK(ha);
			}
		} else {
			EL(sp->ha, "Abort Retry, d_id=%xh, lun=%xh\n",
			    tq->d_id.b24, sp->lun_queue->lun_no);
		}

		/* Set retry status. */
		sp->flags |= SRB_RETRY;
	} else {
		fcpr->fcp_resid =
		    sts.fcp_residual_length > sp->fcp->fcp_data_len ?
		    sp->fcp->fcp_data_len : sts.fcp_residual_length;

		if ((sts.comp_status == CS_DATA_UNDERRUN) &&
		    (sts.scsi_status_h & FCP_RESID_UNDER) == 0) {

			if (sts.scsi_status_l == STATUS_CHECK) {
				sp->pkt->pkt_reason = CS_COMPLETE;
			} else {
				EL(ha, "transport error - "
				    "underrun & invalid resid\n");
				EL(ha, "ssh=%xh, ssl=%xh\n",
				    sts.scsi_status_h, sts.scsi_status_l);
				sp->pkt->pkt_reason = CS_FCP_RESPONSE_ERROR;
			}
		}

		/* Ignore firmware underrun error. */
		if (sts.comp_status == CS_DATA_UNDERRUN &&
		    (sts.scsi_status_h & FCP_RESID_UNDER ||
		    (sts.scsi_status_l != STATUS_CHECK &&
		    sts.scsi_status_l != STATUS_GOOD))) {
			sp->pkt->pkt_reason = CS_COMPLETE;
		}

		if (sp->pkt->pkt_reason != CS_COMPLETE) {
			ha->xioctl->DeviceErrorCount++;
			EL(sp->ha, "Cmplt status err = %xh, d_id=%xh, lun=%xh"
			    "\n", sts.comp_status, tq->d_id.b24,
			    sp->lun_queue->lun_no);
		}

		/* Set target request sense data. */
		if (sts.scsi_status_l == STATUS_CHECK) {
			if (sts.scsi_status_h & FCP_SNS_LEN_VALID) {

				if (sp->pkt->pkt_reason == CS_COMPLETE &&
				    sts.req_sense_data[2] != KEY_NO_SENSE &&
				    sts.req_sense_data[2] !=
				    KEY_UNIT_ATTENTION) {
					ha->xioctl->DeviceErrorCount++;
				}

				sense_sz = sts.req_sense_length;

				/* Insure data does not exceed buf. */
				if (sp->pkt->pkt_rsplen <=
				    (uint32_t)sizeof (fcp_rsp_t) +
				    fcpr->fcp_response_len) {
					sp->request_sense_length = 0;
				} else {
					sp->request_sense_length = (uint32_t)
					    (sp->pkt->pkt_rsplen -
					    sizeof (fcp_rsp_t) -
					    fcpr->fcp_response_len);
				}

				if (sense_sz <
				    sp->request_sense_length) {
					sp->request_sense_length =
					    sense_sz;
				}

				sp->request_sense_ptr = (caddr_t)rsp;

				sense_sz = (uint32_t)
				    (((uintptr_t)pkt23 +
				    sizeof (sts_entry_t)) -
				    (uintptr_t)sts.req_sense_data);
				if (sp->request_sense_length <
				    sense_sz) {
					sense_sz =
					    sp->request_sense_length;
				}

				fcpr->fcp_sense_len = sense_sz;

				/* Move sense data. */
				ddi_rep_get8(ha->hba_buf.acc_handle,
				    (uint8_t *)sp->request_sense_ptr,
				    sts.req_sense_data,
				    (size_t)sense_sz,
				    DDI_DEV_AUTOINCR);

				sp->request_sense_ptr += sense_sz;
				sp->request_sense_length -= sense_sz;
				if (sp->request_sense_length != 0) {
					ha->status_srb = sp;
				}
			}

			if (sense_sz != 0) {
				EL(sp->ha, "check condition sense data, "
				    "d_id=%xh, lun=%xh\n%2xh%3xh%3xh%3xh"
				    "%3xh%3xh%3xh%3xh%3xh%3xh%3xh%3xh%3xh"
				    "%3xh%3xh%3xh%3xh%3xh\n", tq->d_id.b24,
				    sp->lun_queue->lun_no,
				    sts.req_sense_data[0],
				    sts.req_sense_data[1],
				    sts.req_sense_data[2],
				    sts.req_sense_data[3],
				    sts.req_sense_data[4],
				    sts.req_sense_data[5],
				    sts.req_sense_data[6],
				    sts.req_sense_data[7],
				    sts.req_sense_data[8],
				    sts.req_sense_data[9],
				    sts.req_sense_data[10],
				    sts.req_sense_data[11],
				    sts.req_sense_data[12],
				    sts.req_sense_data[13],
				    sts.req_sense_data[14],
				    sts.req_sense_data[15],
				    sts.req_sense_data[16],
				    sts.req_sense_data[17]);
			} else {
				EL(sp->ha, "check condition, d_id=%xh, lun=%xh"
				    "\n", tq->d_id.b24, sp->lun_queue->lun_no);
			}
		}
	}

	/* Set completed status. */
	sp->flags |= SRB_ISP_COMPLETED;

	/* Place command on done queue. */
	if (ha->status_srb == NULL) {
		ql_add_link_b(done_q, &sp->cmd);
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);

	return (rval);
}

/*
 * ql_status_cont_entry
 *	Processes status continuation entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_status_cont_entry(ql_adapter_state_t *ha, sts_cont_entry_t *pkt,
    ql_head_t *done_q, uint32_t *set_flags, uint32_t *reset_flags)
{
	uint32_t	sense_sz, index;
	ql_srb_t	*sp = ha->status_srb;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if (sp != NULL && sp->request_sense_length) {
		if (sp->request_sense_length > sizeof (pkt->req_sense_data)) {
			sense_sz = sizeof (pkt->req_sense_data);
		} else {
			sense_sz = sp->request_sense_length;
		}

		if (CFG_IST(ha, CFG_CTRL_2425)) {
			for (index = 0; index < sense_sz; index += 4) {
				ql_chg_endian((uint8_t *)
				    &pkt->req_sense_data[0] + index, 4);
			}
		}

		/* Move sense data. */
		ddi_rep_get8(ha->hba_buf.acc_handle,
		    (uint8_t *)sp->request_sense_ptr,
		    (uint8_t *)&pkt->req_sense_data[0], (size_t)sense_sz,
		    DDI_DEV_AUTOINCR);

		sp->request_sense_ptr += sense_sz;
		sp->request_sense_length -= sense_sz;

		/* Place command on done queue. */
		if (sp->request_sense_length == 0) {
			ql_add_link_b(done_q, &sp->cmd);
			ha->status_srb = NULL;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_immediate_notify_entry
 *	Processes immediate notify entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_immediate_notify_entry(ql_adapter_state_t *ha,
    immediate_notify_entry_t *pkt, ql_head_t *done_q, uint32_t *set_flags,
    uint32_t *reset_flags)
{
	notify_acknowledge_entry_t *nack;
	ql_srb_t		*sp;
	fcp_cmd_t		*fcp;
	tgt_cmd_t		*cmd, *nackcmd;
	ql_tgt_t		*tq;
	fc_unsol_buf_t		*ubp = NULL;
	int			use_ubuffer;
	uint16_t		loop_id;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	cmd = (tgt_cmd_t *)kmem_zalloc(sizeof (tgt_cmd_t), KM_NOSLEEP);
	if (cmd != NULL) {
		cmd->cmd.base_address = cmd;

		/* Save command context. */
		cmd->type = pkt->entry_type;
		cmd->initiator_id_l = pkt->initiator_id_l;
		cmd->initiator_id_h = pkt->initiator_id_h;
		cmd->rx_id = (uint16_t)ddi_get16(ha->hba_buf.acc_handle,
		    &pkt->sequence_id);
		cmd->status = (uint16_t)ddi_get16(ha->hba_buf.acc_handle,
		    &pkt->status);
		cmd->task_flags_l = pkt->task_flags_l;
		cmd->task_flags_h = pkt->task_flags_h;

		/*
		 * TODO: flushing in case of pkt_status_l of 0x34
		 * needs to be handled properly.
		 */

		EL(ha, "status = %xh\n", cmd->status);

		/*
		 * For immediate notify situations that need attention,
		 * we attempt to put the command in the array of notify
		 * acknowledge slots for future handling.  A LIP RESET
		 * always gets slot 0, since we have to ensure that there's
		 * always a slot available and we can't do any other
		 * processsing if a LIP RESET is pending.
		 *
		 * Otherwise, immediate notifies take the next open slot.
		 */
		use_ubuffer = 0;
		nackcmd = NULL;
		mutex_enter(&ha->ql_nack_mtx);
		switch (cmd->status) {
		case 0x0E:
			if (ha->ql_nack != NULL) {
				/*
				 * We're in the sticky situation of receiving
				 * LIP reset while one is pending.  What appears
				 * to work is to drop the old request and
				 * replace it with the new.  We send a NACK
				 * for the old to replenish the IOCB.
				 */
				nackcmd = ha->ql_nack;
			}
			ha->ql_nack = cmd;
			break;
		case 0x20:
		case 0x29:
		case 0x36:
			/* If this isn't NULL, a LIP RESET is outstanding */
			if (ha->ql_nack == NULL) {
				use_ubuffer++;
			}
			break;
		default:
			EL(ha, "unknown status=%xh\n",
			    cmd->status);
			break;
		}
		mutex_exit(&ha->ql_nack_mtx);

		if (use_ubuffer) {
			/*
			 * Get an unsolicited buffer to send the message up in
			 */

			/* Locate a buffer to use. */
			loop_id = (uint16_t)
			    (CFG_IST(ha, CFG_EXT_FW_INTERFACE) ?
			    CHAR_TO_SHORT(pkt->initiator_id_l,
			    pkt->initiator_id_h) : pkt->initiator_id_h);
			if ((tq = ql_loop_id_to_queue(ha, loop_id)) != NULL) {
				ubp = ql_get_unsolicited_buffer(ha,
				    FC_TYPE_SCSI_FCP);
			}
			if (ubp != NULL) {
				ubp->ub_resp_flags = FC_UB_FCP_CDB_FLAG;
				ubp->ub_resp_token = tq;
				sp = ubp->ub_fca_private;

				fcp = (fcp_cmd_t *)ubp->ub_buffer;

				/* Set header. */
				ubp->ub_frame.d_id = ha->d_id.b24;
				/* Set 0x06 for R_CTL_COMMAND */
				ubp->ub_frame.r_ctl = R_CTL_COMMAND;
				ubp->ub_frame.s_id = tq->d_id.b24;
				ubp->ub_frame.rsvd = 0;
				ubp->ub_frame.f_ctl = F_CTL_FIRST_SEQ |
				    F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
				ubp->ub_frame.type = FC_TYPE_SCSI_FCP;
				ubp->ub_frame.seq_cnt = 0;
				ubp->ub_frame.df_ctl = 0;
				ubp->ub_frame.seq_id = 0;
				ubp->ub_frame.rx_id = cmd->rx_id;
				ubp->ub_frame.ox_id = (uint16_t)ddi_get16(
				    ha->hba_buf.acc_handle, &pkt->ox_id);
				ubp->ub_frame.ro = 0;

				/* Set command in buffer. */
				bzero((void *)fcp, sizeof (fcp_cmd_t));

				lobyte(fcp->fcp_ent_addr.ent_addr_0) =
				    pkt->lun_l;
				hibyte(fcp->fcp_ent_addr.ent_addr_0) =
				    pkt->lun_h;

				switch (cmd->status) {
				case 0x29:
					ubp->ub_resp_flags = (uint16_t)
					    (ubp->ub_resp_flags |
					    FC_UB_FCP_PORT_LOGOUT);
					break;
				case 0x20:
					ubp->ub_resp_flags = (uint16_t)
					    (ubp->ub_resp_flags |
					    FC_UB_FCP_ABORT_TASK);
					break;
				case 0x36:
					if (pkt->task_flags_h & BIT_7) {
						fcp->fcp_cntl.cntl_kill_tsk =
						    1;
					}
					if (pkt->task_flags_h & BIT_6) {
						fcp->fcp_cntl.cntl_clr_aca = 1;
					}
					if (pkt->task_flags_h & BIT_5) {
						fcp->fcp_cntl.cntl_reset_tgt =
						    1;
					}
					if (pkt->task_flags_h & BIT_4) {
						fcp->fcp_cntl.cntl_reset_lun =
						    1;
					}
					if (pkt->task_flags_h & BIT_2) {
						fcp->fcp_cntl.cntl_clr_tsk = 1;
					}
					if (pkt->task_flags_h & BIT_1) {
						fcp->fcp_cntl.cntl_abort_tsk =
						    1;
					}
					break;
				default:
					EL(ha, "default, no action\n");
					break;
				}

				QL_UB_LOCK(ha);
				sp->flags |= SRB_UB_CALLBACK | SRB_UB_FCP;
				QL_UB_UNLOCK(ha);
				QL_PRINT_3(CE_CONT, "(%d): Sent Up status = "
				    "%xh\n", ha->instance, cmd->status);
				ql_add_link_b(done_q, &sp->cmd);
			}
		}

		if (nackcmd) {
			if (ql_req_pkt(ha, (request_t **)&nack) ==
			    QL_SUCCESS) {

				ql_notify_acknowledge_iocb(ha, nackcmd, nack);

				nack->flags_l = 0;
				QL_PRINT_3(CE_CONT, "(%d): send clear "
				    "notify_ack: status=%xh, flag=%xh\n",
				    ha->instance, ddi_get16(
				    ha->hba_buf.acc_handle, &nack->status),
				    nack->flags_l);

				/* Issue command to ISP */
				ql_isp_cmd(ha);
			}
			kmem_free(nackcmd, sizeof (tgt_cmd_t));
		}

		/*
		 * ql_nack can only be non-NULL if we got a LIP RESET and
		 * are processing it.  In that case, we don't want to send
		 * a notify acknowledge right now.
		 */
		if (cmd->status != 0x0E) {
			if (ql_req_pkt(ha, (request_t **)&nack) ==
			    QL_SUCCESS) {
				ql_notify_acknowledge_iocb(ha, cmd, nack);

				EL(ha, "send notify_ack: status=%xh "
				    "flag=%xh\n", cmd->status, nack->flags_l);

				/* Issue command to ISP */
				ql_isp_cmd(ha);
			}
			kmem_free(cmd, sizeof (tgt_cmd_t));
		} else {
			ql_awaken_task_daemon(ha, NULL,
			    LIP_RESET_PENDING, 0);
		}
	}
	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_notify_acknowledge_entry
 *	Processes notify acknowledge entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_notify_acknowledge_entry(ql_adapter_state_t *ha,
    notify_acknowledge_entry_t *pkt, ql_head_t *done_q, uint32_t *set_flags,
    uint32_t *reset_flags)
{
	ql_srb_t	*sp;
	uint32_t	index, cnt;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Get handle. */
	cnt = ddi_get32(ha->hba_buf.acc_handle, &pkt->handle);
	index = cnt & OSC_INDEX_MASK;

	/* Validate handle. */
	sp = index < MAX_OUTSTANDING_COMMANDS ? ha->outstanding_cmds[index] :
	    NULL;

	if (sp != NULL && sp->handle == cnt) {
		ha->outstanding_cmds[index] = NULL;
		sp->handle = 0;
		sp->flags &= ~SRB_IN_TOKEN_ARRAY;

		/* Set completion status */
		sp->pkt->pkt_reason = ddi_get16(ha->hba_buf.acc_handle,
		    &pkt->status) == 1 ? CS_COMPLETE : CS_PORT_UNAVAILABLE;

		/* Set completed status. */
		sp->flags |= SRB_ISP_COMPLETED;

		/* Place command on done queue. */
		ql_add_link_b(done_q, &sp->cmd);

	} else if (cnt != QL_FCA_BRAND) {
		if (sp == NULL) {
			EL(ha, "unknown IOCB handle=%xh\n", cnt);
		} else {
			EL(ha, "mismatch IOCB handle pkt=%xh, sp=%xh\n",
			    cnt, sp->handle);
		}

		(void) ql_binary_fw_dump(ha, FALSE);

		if (!(ha->task_daemon_flags & (ISP_ABORT_NEEDED |
		    ABORT_ISP_ACTIVE))) {
			EL(ha, "ISP Invalid handle, isp_abort_needed\n");
			*set_flags |= ISP_ABORT_NEEDED;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_accept_target_io_entry
 *	Processes accept target I/O entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_accept_target_io_entry(ql_adapter_state_t *ha, atio_entry_t *pkt,
    ql_head_t *done_q, uint32_t *set_flags, uint32_t *reset_flags)
{
	ctio_entry_t	*ctio;
	atio_entry_t	*atio;
	ql_srb_t	*sp;
	fcp_cmd_t	*fcp;
	ql_tgt_t	*tq;
	uint16_t	loop_id;
	fc_unsol_buf_t	*ubp = NULL;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Locate a buffer to use. */
	loop_id = (uint16_t)(CFG_IST(ha, CFG_EXT_FW_INTERFACE) ?
	    CHAR_TO_SHORT(pkt->initiator_id_l, pkt->initiator_id_h) :
	    pkt->initiator_id_h);
	if ((tq = ql_loop_id_to_queue(ha, loop_id)) != NULL) {
		ubp = ql_get_unsolicited_buffer(ha,
		    FC_TYPE_SCSI_FCP);
	}
	if (ubp != NULL) {
		ubp->ub_resp_flags = FC_UB_FCP_CDB_FLAG;
		ubp->ub_resp_token = tq;
		sp = ubp->ub_fca_private;
		fcp = (fcp_cmd_t *)ubp->ub_buffer;

		/* Set header. */
		ubp->ub_frame.d_id = ha->d_id.b24;
		ubp->ub_frame.r_ctl = R_CTL_COMMAND;
		ubp->ub_frame.s_id = tq->d_id.b24;
		ubp->ub_frame.rsvd = 0;
		ubp->ub_frame.f_ctl = F_CTL_FIRST_SEQ |
		    F_CTL_END_SEQ | F_CTL_SEQ_INITIATIVE;
		ubp->ub_frame.type = FC_TYPE_SCSI_FCP;
		ubp->ub_frame.seq_cnt = 0;
		ubp->ub_frame.df_ctl = 0;
		ubp->ub_frame.seq_id = 0;
		ubp->ub_frame.rx_id = (uint16_t)ddi_get16(
		    ha->hba_buf.acc_handle, &pkt->rx_id);
		ubp->ub_frame.ox_id = (uint16_t)ddi_get16(
		    ha->hba_buf.acc_handle, &pkt->ox_id);
		ubp->ub_frame.ro = 0;

		/* Set command in buffer. */

		bzero((void *)fcp, sizeof (fcp_cmd_t));

		lobyte(fcp->fcp_ent_addr.ent_addr_0) = pkt->lun_l;
		hibyte(fcp->fcp_ent_addr.ent_addr_0) = pkt->lun_h;

		fcp->fcp_cntl.cntl_qtype = pkt->task_codes;

		if (pkt->execution_codes & BIT_1)
			fcp->fcp_cntl.cntl_read_data = 1;
		if (pkt->execution_codes & BIT_0)
			fcp->fcp_cntl.cntl_write_data = 1;

		ddi_rep_put8(ha->hba_buf.acc_handle, (uint8_t *)&pkt->cdb[0],
		    (uint8_t *)&fcp->fcp_cdb[0], FCP_CDB_SIZE,
		    DDI_DEV_AUTOINCR);

		fcp->fcp_data_len = (int)ddi_get32(
		    ha->hba_buf.acc_handle, (uint32_t *)&pkt->data_length);
		QL_UB_LOCK(ha);
		sp->flags |= SRB_UB_CALLBACK | SRB_UB_FCP;
		QL_UB_UNLOCK(ha);
		ql_add_link_b(done_q, &sp->cmd);
	}

	/* If command not sent to transport layer. */
	if (ubp == NULL) {

		if (ql_req_pkt(ha, (request_t **)&ctio) == QL_SUCCESS) {
			ctio->entry_type = CTIO_TYPE_2;
			ctio->initiator_id_l = pkt->initiator_id_l;
			ctio->initiator_id_h = pkt->initiator_id_h;
			ddi_put16(ha->hba_buf.acc_handle, &ctio->rx_id,
			    (uint16_t)ddi_get16(ha->hba_buf.acc_handle,
			    &pkt->rx_id));
			ctio->flags_l = BIT_7 | BIT_6;
			ctio->flags_h = BIT_7 | BIT_1 | BIT_0;
			ctio->timeout = 0xffff;
			ctio->type.s0_32bit.scsi_status_l = STATUS_BUSY;

			/* Issue command to ISP */
			ql_isp_cmd(ha);
		}
	} else {
		if (ql_req_pkt(ha, (request_t **)&atio) == QL_SUCCESS) {
			atio->entry_type = ATIO_TYPE;
			atio->initiator_id_l = pkt->initiator_id_l;
			atio->initiator_id_h = pkt->initiator_id_h;
			ddi_put16(ha->hba_buf.acc_handle, &atio->rx_id,
			    (uint16_t)ddi_get16(ha->hba_buf.acc_handle,
			    &pkt->rx_id));
			atio->lun_l = pkt->lun_l;
			atio->lun_h = pkt->lun_h;

			/* Issue command to ISP */
			ql_isp_cmd(ha);
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_continue_target_io_entry
 *	Processes continue target IO entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_continue_target_io_entry(ql_adapter_state_t *ha, ctio_entry_t *pkt,
    ql_head_t *done_q, uint32_t *set_flags, uint32_t *reset_flags)
{
	ql_srb_t	*sp;
	uint32_t	index, cnt;
	uint16_t	status;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Get handle. */
	cnt = ddi_get32(ha->hba_buf.acc_handle, &pkt->handle);
	index = cnt & OSC_INDEX_MASK;

	/* Validate handle. */
	sp = index < MAX_OUTSTANDING_COMMANDS ? ha->outstanding_cmds[index] :
	    NULL;

	if (sp != NULL && sp->handle == cnt) {
		ha->outstanding_cmds[index] = NULL;
		sp->handle = 0;
		sp->flags &= ~SRB_IN_TOKEN_ARRAY;

		/* Set completion status */
		status = (uint16_t)ddi_get16(ha->hba_buf.acc_handle,
		    &pkt->status);

		switch (status) {
		case 1:
			sp->pkt->pkt_reason = CS_COMPLETE;
			break;
		case 2:
			sp->pkt->pkt_reason = CS_ABORTED;
			break;
		case 9:
			sp->pkt->pkt_reason = CS_DATA_OVERRUN;
			break;
		case 0xa:
		case 0xb:
			sp->pkt->pkt_reason = CS_TIMEOUT;
			break;
		case 0xe:
		case 0x17:
			sp->pkt->pkt_reason = CS_RESET;
			break;
		case 0x10:
			sp->pkt->pkt_reason = CS_DMA_ERROR;
			break;
		case 0x15:
		case 0x28:
		case 0x29:
		case 0x2A:
			sp->pkt->pkt_reason = status;
			break;
		default:
			sp->pkt->pkt_reason = CS_PORT_UNAVAILABLE;
			break;
		}

		/* Set completed status. */
		sp->flags |= SRB_ISP_COMPLETED;

		/* Place command on done queue. */
		ql_add_link_b(done_q, &sp->cmd);

	} else if (cnt != QL_FCA_BRAND) {
		if (sp == NULL) {
			EL(ha, "unknown IOCB handle=%xh\n", cnt);
		} else {
			EL(ha, "mismatch IOCB handle pkt=%xh, sp=%xh\n",
			    cnt, sp->handle);
		}

		(void) ql_binary_fw_dump(ha, FALSE);

		if (!(ha->task_daemon_flags & (ISP_ABORT_NEEDED |
		    ABORT_ISP_ACTIVE))) {
			EL(ha, "ISP Invalid handle, isp_abort_needed\n");
			*set_flags |= ISP_ABORT_NEEDED;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_ip_entry
 *	Processes received ISP IP entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_ip_entry(ql_adapter_state_t *ha, ip_entry_t *pkt23, ql_head_t *done_q,
    uint32_t *set_flags, uint32_t *reset_flags)
{
	ql_srb_t	*sp;
	uint32_t	index, cnt;
	ql_tgt_t	*tq;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Get handle. */
	cnt = ddi_get32(ha->hba_buf.acc_handle, &pkt23->handle);
	index = cnt & OSC_INDEX_MASK;

	/* Validate handle. */
	sp = index < MAX_OUTSTANDING_COMMANDS ? ha->outstanding_cmds[index] :
	    NULL;

	if (sp != NULL && sp->handle == cnt) {
		ha->outstanding_cmds[index] = NULL;
		sp->handle = 0;
		sp->flags &= ~SRB_IN_TOKEN_ARRAY;
		tq = sp->lun_queue->target_queue;

		/* Set ISP completion status */
		if (CFG_IST(ha, CFG_CTRL_2425)) {
			ip_cmd_entry_t	*pkt24 = (ip_cmd_entry_t *)pkt23;

			sp->pkt->pkt_reason = ddi_get16(
			    ha->hba_buf.acc_handle, &pkt24->hdl_status);
		} else {
			sp->pkt->pkt_reason = ddi_get16(
			    ha->hba_buf.acc_handle, &pkt23->comp_status);
		}

		if (ha->task_daemon_flags & LOOP_DOWN) {
			EL(ha, "Loop Not Ready Retry, d_id=%xh\n",
			    tq->d_id.b24);

			/* Set retry status. */
			sp->flags |= SRB_RETRY;

		} else if (tq->port_down_retry_count &&
		    (sp->pkt->pkt_reason == CS_INCOMPLETE ||
		    sp->pkt->pkt_reason == CS_PORT_UNAVAILABLE ||
		    sp->pkt->pkt_reason == CS_PORT_LOGGED_OUT ||
		    sp->pkt->pkt_reason == CS_PORT_CONFIG_CHG ||
		    sp->pkt->pkt_reason == CS_PORT_BUSY)) {
			EL(ha, "Port Down Retry=%xh, d_id=%xh, count=%d\n",
			    sp->pkt->pkt_reason, tq->d_id.b24,
			    tq->port_down_retry_count);

			/* Set retry status. */
			sp->flags |= SRB_RETRY;

			if (sp->pkt->pkt_reason == CS_PORT_LOGGED_OUT ||
			    sp->pkt->pkt_reason == CS_PORT_UNAVAILABLE) {
				ha->adapter_stats->d_stats[lobyte(
				    tq->loop_id)].logouts_recvd++;
				ql_send_logo(ha, tq, done_q);
			}

			/* Acquire device queue lock. */
			DEVICE_QUEUE_LOCK(tq);

			if ((tq->flags & TQF_QUEUE_SUSPENDED) == 0) {
				tq->flags |= TQF_QUEUE_SUSPENDED;

				tq->port_down_retry_count--;

				ADAPTER_STATE_LOCK(ha);
				if (ha->port_retry_timer == 0) {
					if ((ha->port_retry_timer =
					    ha->port_down_retry_delay) == 0) {
						*set_flags |=
						    PORT_RETRY_NEEDED;
					}
				}
				ADAPTER_STATE_UNLOCK(ha);
			}

			/* Release device queue specific lock. */
			DEVICE_QUEUE_UNLOCK(tq);

		} else if (sp->pkt->pkt_reason == CS_RESET) {
			EL(ha, "Reset Retry, d_id=%xh\n", tq->d_id.b24);

			/* Set retry status. */
			sp->flags |= SRB_RETRY;
		} else {
			if (sp->pkt->pkt_reason != CS_COMPLETE) {
				EL(ha, "Cmplt status err=%xh, d_id=%xh\n",
				    sp->pkt->pkt_reason, tq->d_id.b24);
			}
		}

		/* Set completed status. */
		sp->flags |= SRB_ISP_COMPLETED;

		ql_add_link_b(done_q, &sp->cmd);

	} else {
		if (sp == NULL) {
			EL(ha, "unknown IOCB handle=%xh\n", cnt);
		} else {
			EL(ha, "mismatch IOCB handle pkt=%xh, sp=%xh\n",
			    cnt, sp->handle);
		}

		(void) ql_binary_fw_dump(ha, FALSE);

		if (!(ha->task_daemon_flags & (ISP_ABORT_NEEDED |
		    ABORT_ISP_ACTIVE))) {
			EL(ha, "ISP Invalid handle, isp_abort_needed\n");
			*set_flags |= ISP_ABORT_NEEDED;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_ip_rcv_entry
 *	Processes received ISP IP buffers entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_ip_rcv_entry(ql_adapter_state_t *ha, ip_rcv_entry_t *pkt,
    ql_head_t *done_q, uint32_t *set_flags, uint32_t *reset_flags)
{
	port_id_t	s_id;
	uint16_t	index;
	uint8_t		cnt;
	ql_tgt_t	*tq;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Locate device queue. */
	s_id.b.al_pa = pkt->s_id[0];
	s_id.b.area = pkt->s_id[1];
	s_id.b.domain = pkt->s_id[2];
	if ((tq = ql_d_id_to_queue(ha, s_id)) == NULL) {
		EL(ha, "Unknown IP device ID=%xh\n", s_id.b24);
		return;
	}

	tq->ub_sequence_length = (uint16_t)ddi_get16(ha->hba_buf.acc_handle,
	    &pkt->seq_length);
	tq->ub_total_seg_cnt = pkt->segment_count;
	tq->ub_seq_id = ++ha->ub_seq_id;
	tq->ub_seq_cnt = 0;
	tq->ub_frame_ro = 0;
	tq->ub_loop_id = pkt->loop_id;
	ha->rcv_dev_q = tq;

	for (cnt = 0; cnt < IP_RCVBUF_HANDLES && tq->ub_seq_cnt <
	    tq->ub_total_seg_cnt; cnt++) {

		index = (uint16_t)ddi_get16(ha->hba_buf.acc_handle,
		    &pkt->buffer_handle[cnt]);

		if (ql_ub_frame_hdr(ha, tq, index, done_q) != QL_SUCCESS) {
			EL(ha, "ql_ub_frame_hdr failed, isp_abort_needed\n");
			*set_flags |= ISP_ABORT_NEEDED;
			break;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_ip_rcv_cont_entry
 *	Processes received ISP IP buffers continuation entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_ip_rcv_cont_entry(ql_adapter_state_t *ha, ip_rcv_cont_entry_t *pkt,
    ql_head_t *done_q, uint32_t *set_flags, uint32_t *reset_flags)
{
	uint16_t	index;
	uint8_t		cnt;
	ql_tgt_t	*tq;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	if ((tq = ha->rcv_dev_q) == NULL) {
		EL(ha, "No IP receive device\n");
		return;
	}

	for (cnt = 0; cnt < IP_RCVBUF_CONT_HANDLES &&
	    tq->ub_seq_cnt < tq->ub_total_seg_cnt; cnt++) {

		index = (uint16_t)ddi_get16(ha->hba_buf.acc_handle,
		    &pkt->buffer_handle[cnt]);

		if (ql_ub_frame_hdr(ha, tq, index, done_q) != QL_SUCCESS) {
			EL(ha, "ql_ub_frame_hdr failed, isp_abort_needed\n");
			*set_flags |= ISP_ABORT_NEEDED;
			break;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ip_rcv_24xx_entry_t
 *	Processes received ISP24xx IP buffers entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_ip_24xx_rcv_entry(ql_adapter_state_t *ha, ip_rcv_24xx_entry_t *pkt,
    ql_head_t *done_q, uint32_t *set_flags, uint32_t *reset_flags)
{
	port_id_t	s_id;
	uint16_t	index;
	uint8_t		cnt;
	ql_tgt_t	*tq;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Locate device queue. */
	s_id.b.al_pa = pkt->s_id[0];
	s_id.b.area = pkt->s_id[1];
	s_id.b.domain = pkt->s_id[2];
	if ((tq = ql_d_id_to_queue(ha, s_id)) == NULL) {
		EL(ha, "Unknown IP device ID=%xh\n", s_id.b24);
		return;
	}

	if (tq->ub_total_seg_cnt == 0) {
		tq->ub_sequence_length = (uint16_t)ddi_get16(
		    ha->hba_buf.acc_handle, &pkt->seq_length);
		tq->ub_total_seg_cnt = pkt->segment_count;
		tq->ub_seq_id = ++ha->ub_seq_id;
		tq->ub_seq_cnt = 0;
		tq->ub_frame_ro = 0;
		tq->ub_loop_id = (uint16_t)ddi_get16(
		    ha->hba_buf.acc_handle, &pkt->n_port_hdl);
	}

	for (cnt = 0; cnt < IP_24XX_RCVBUF_HANDLES && tq->ub_seq_cnt <
	    tq->ub_total_seg_cnt; cnt++) {

		index = (uint16_t)ddi_get16(ha->hba_buf.acc_handle,
		    &pkt->buffer_handle[cnt]);

		if (ql_ub_frame_hdr(ha, tq, index, done_q) != QL_SUCCESS) {
			EL(ha, "ql_ub_frame_hdr failed, isp_abort_needed\n");
			*set_flags |= ISP_ABORT_NEEDED;
			break;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_ms_entry
 *	Processes received Name/Management/CT Pass-Through entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt23:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_ms_entry(ql_adapter_state_t *ha, ms_entry_t *pkt23, ql_head_t *done_q,
    uint32_t *set_flags, uint32_t *reset_flags)
{
	ql_srb_t		*sp;
	uint32_t		index, cnt;
	ql_tgt_t		*tq;
	ct_passthru_entry_t	*pkt24 = (ct_passthru_entry_t *)pkt23;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	/* Get handle. */
	cnt = ddi_get32(ha->hba_buf.acc_handle, &pkt23->handle);
	index = cnt & OSC_INDEX_MASK;

	/* Validate handle. */
	sp = index < MAX_OUTSTANDING_COMMANDS ? ha->outstanding_cmds[index] :
	    NULL;

	if (sp != NULL && sp->handle == cnt) {
		if (!(sp->flags & SRB_MS_PKT)) {
			EL(ha, "Not SRB_MS_PKT flags=%xh, isp_abort_needed",
			    sp->flags);
			*set_flags |= ISP_ABORT_NEEDED;
			return;
		}

		ha->outstanding_cmds[index] = NULL;
		sp->handle = 0;
		sp->flags &= ~SRB_IN_TOKEN_ARRAY;
		tq = sp->lun_queue->target_queue;

		/* Set ISP completion status */
		if (CFG_IST(ha, CFG_CTRL_2425)) {
			sp->pkt->pkt_reason = ddi_get16(
			    ha->hba_buf.acc_handle, &pkt24->status);
		} else {
			sp->pkt->pkt_reason = ddi_get16(
			    ha->hba_buf.acc_handle, &pkt23->comp_status);
		}

		if (sp->pkt->pkt_reason == CS_RESOUCE_UNAVAILABLE &&
		    sp->retry_count) {
			EL(ha, "Resouce Unavailable Retry = %d\n",
			    sp->retry_count);

			/* Set retry status. */
			sp->retry_count--;
			sp->flags |= SRB_RETRY;

			/* Acquire device queue lock. */
			DEVICE_QUEUE_LOCK(tq);

			if (!(tq->flags & TQF_QUEUE_SUSPENDED)) {
				tq->flags |= TQF_QUEUE_SUSPENDED;

				ADAPTER_STATE_LOCK(ha);
				if (ha->port_retry_timer == 0) {
					ha->port_retry_timer = 2;
				}
				ADAPTER_STATE_UNLOCK(ha);
			}

			/* Release device queue specific lock. */
			DEVICE_QUEUE_UNLOCK(tq);

		} else if (tq->port_down_retry_count &&
		    (sp->pkt->pkt_reason == CS_PORT_CONFIG_CHG ||
		    sp->pkt->pkt_reason == CS_PORT_BUSY)) {
			EL(ha, "Port Down Retry\n");

			/* Set retry status. */
			sp->flags |= SRB_RETRY;

			/* Acquire device queue lock. */
			DEVICE_QUEUE_LOCK(tq);

			if ((tq->flags & TQF_QUEUE_SUSPENDED) == 0) {
				tq->flags |= TQF_QUEUE_SUSPENDED;

				tq->port_down_retry_count--;

				ADAPTER_STATE_LOCK(ha);
				if (ha->port_retry_timer == 0) {
					if ((ha->port_retry_timer =
					    ha->port_down_retry_delay) == 0) {
						*set_flags |=
						    PORT_RETRY_NEEDED;
					}
				}
				ADAPTER_STATE_UNLOCK(ha);
			}

			/* Release device queue specific lock. */
			DEVICE_QUEUE_UNLOCK(tq);

		} else if (sp->pkt->pkt_reason == CS_RESET) {
			EL(ha, "Reset Retry\n");

			/* Set retry status. */
			sp->flags |= SRB_RETRY;

		} else if (CFG_IST(ha, CFG_CTRL_2425) &&
		    sp->pkt->pkt_reason == CS_DATA_UNDERRUN) {
			cnt = ddi_get32(ha->hba_buf.acc_handle,
			    &pkt24->resp_byte_count);
			if (cnt < sizeof (fc_ct_header_t)) {
				EL(ha, "Data underrrun\n");
			} else {
				sp->pkt->pkt_reason = CS_COMPLETE;
			}

		} else if (sp->pkt->pkt_reason != CS_COMPLETE) {
			EL(ha, "status err=%xh\n", sp->pkt->pkt_reason);
		}

		if (sp->pkt->pkt_reason == CS_COMPLETE) {
			/*EMPTY*/
			QL_PRINT_3(CE_CONT, "(%d): resp\n", ha->instance);
			QL_DUMP_3(sp->pkt->pkt_resp, 8, sp->pkt->pkt_rsplen);
		}

		/* For nameserver restore command, management change header. */
		if ((sp->flags & SRB_RETRY) == 0) {
			tq->d_id.b24 == 0xfffffc ?
			    ql_cthdr_endian(sp->pkt->pkt_cmd_acc,
			    sp->pkt->pkt_cmd, B_TRUE) :
			    ql_cthdr_endian(sp->pkt->pkt_resp_acc,
			    sp->pkt->pkt_resp, B_TRUE);
		}

		/* Set completed status. */
		sp->flags |= SRB_ISP_COMPLETED;

		/* Place command on done queue. */
		ql_add_link_b(done_q, &sp->cmd);

	} else {
		if (sp == NULL) {
			EL(ha, "unknown IOCB handle=%xh\n", cnt);
		} else {
			EL(ha, "mismatch IOCB handle pkt=%xh, sp=%xh\n",
			    cnt, sp->handle);
		}

		(void) ql_binary_fw_dump(ha, FALSE);

		if (!(ha->task_daemon_flags & (ISP_ABORT_NEEDED |
		    ABORT_ISP_ACTIVE))) {
			EL(ha, "ISP Invalid handle, isp_abort_needed\n");
			*set_flags |= ISP_ABORT_NEEDED;
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}

/*
 * ql_report_id_entry
 *	Processes received Name/Management/CT Pass-Through entry.
 *
 * Input:
 *	ha:		adapter state pointer.
 *	pkt23:		entry pointer.
 *	done_q:		done queue pointer.
 *	set_flags:	task daemon flags to set.
 *	reset_flags:	task daemon flags to reset.
 *
 * Context:
 *	Interrupt or Kernel context, no mailbox commands allowed.
 */
/* ARGSUSED */
static void
ql_report_id_entry(ql_adapter_state_t *ha, report_id_1_t *pkt,
    ql_head_t *done_q, uint32_t *set_flags, uint32_t *reset_flags)
{
	ql_adapter_state_t	*vha;

	QL_PRINT_3(CE_CONT, "(%d): started\n", ha->instance);

	EL(ha, "format=%d, vp=%d, status=%d\n",
	    pkt->format, pkt->vp_index, pkt->status);

	if (pkt->format == 1) {
		/* Locate port state structure. */
		for (vha = ha; vha != NULL; vha = vha->vp_next) {
			if (vha->vp_index == pkt->vp_index) {
				break;
			}
		}
		if (vha != NULL && (pkt->status == CS_COMPLETE ||
		    pkt->status == CS_PORT_ID_CHANGE)) {
			*set_flags |= LOOP_RESYNC_NEEDED;
			*reset_flags &= ~LOOP_RESYNC_NEEDED;
			vha->loop_down_timer = LOOP_DOWN_TIMER_OFF;
			TASK_DAEMON_LOCK(ha);
			vha->task_daemon_flags |= LOOP_RESYNC_NEEDED;
			vha->task_daemon_flags &= ~LOOP_DOWN;
			TASK_DAEMON_UNLOCK(ha);
		}
	}

	QL_PRINT_3(CE_CONT, "(%d): done\n", ha->instance);
}
