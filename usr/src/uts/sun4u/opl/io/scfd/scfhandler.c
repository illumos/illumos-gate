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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/ksynch.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scfd/scfparam.h>

/*
 * Function list
 */
uint_t	scf_intr(caddr_t arg);
int	scf_intr_cmdcmp(scf_state_t *statep);
void	scf_intr_cmdcmp_driver(scf_state_t *statep, struct scf_cmd *scfcmdp);
int	scf_intr_dsens(struct scf_cmd *scfcmdp, scf_int_reason_t *int_rp,
	int len);
void	scf_status_change(scf_state_t *statep);
void	scf_next_cmd_check(scf_state_t *statep);
void	scf_next_rxdata_get(void);
void	scf_online_wait_tout(void);
void	scf_cmdbusy_tout(void);
void	scf_cmdend_tout(void);
void	scf_report_send_wait_tout(void);
void	scf_alivecheck_intr(scf_state_t *statep);
void	scf_path_change(scf_state_t *statep);
void	scf_halt(uint_t mode);
void	scf_panic_callb(int code);
void	scf_shutdown_callb(int code);
uint_t	scf_softintr(caddr_t arg);
void	scf_cmdwait_status_set(void);

/*
 * External function
 */
extern	void	scf_dscp_start(uint32_t factor);
extern	void	scf_dscp_stop(uint32_t factor);
extern	void	scf_dscp_intr(scf_state_t *state);
extern	void	scf_dscp_callback(void);

extern	void	do_shutdown(void);


/*
 * scf_intr()
 *
 * Description: Interrupt handler entry processing.
 *
 */
uint_t
scf_intr(caddr_t arg)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_intr() "
	scf_state_t		*statep = (void *)arg;
	int			path_change = 0;
	uint_t			ret = DDI_INTR_CLAIMED;
	timeout_id_t		save_tmids[SCF_TIMERCD_MAX];
	int			tm_stop_cnt;

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");
	SC_DBG_DRV_TRACE(TC_INTR|TC_IN, __LINE__, &arg, sizeof (caddr_t));

	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	/* Path status check */
	if (scf_check_state(statep) == PATH_STAT_EMPTY) {
		SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__, "intr    ", 8);
		goto END_intr;
	}

	/* PANIC exec status */
	if (scf_panic_exec_flag) {
		/* SCF interrupt disable(CR) */
		SCF_P_DDI_PUT16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->CONTROL, CONTROL_DISABLE);
		/* Register read sync */
		scf_rs16 = SCF_P_DDI_GET16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->CONTROL);

		/* SCF Status register interrupt(STR) : clear */
		SCF_P_DDI_PUT16(statep->scf_regs_handle,
			&statep->scf_regs->STATUS, 0xffff);

		/* SCF Status extended register(STExR) : interrupt clear */
		SCF_P_DDI_PUT32(statep->scf_regs_handle,
			&statep->scf_regs->STATUS_ExR, 0xffffffff);

		/* DSCP buffer status register(DSR) : interrupt clear */
		SCF_P_DDI_PUT8(statep->scf_regs_handle,
			&statep->scf_regs->DSR, 0xff);

		/* SCF interrupt status register(ISR) : interrupt clear */
		SCF_P_DDI_PUT16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST,
			(INT_ST_PATHCHGIE | CONTROL_ALIVEINE));
		scf_rs16 = SCF_P_DDI_GET16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST);
		goto END_intr;
	}

	/* Check hard error after or interrupt disable status */
	if ((statep->scf_herr & HERR_EXEC) ||
		(!(statep->resource_flag & S_DID_REGENB))) {
		SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__, "intr    ", 8);

		/* Interrupt disable */
		scf_forbid_intr(statep);

		/* SCF Status register interrupt(STR) : clear */
		SCF_DDI_PUT16(statep, statep->scf_regs_handle,
			&statep->scf_regs->STATUS, 0xffff);

		/* SCF Status extended register(STExR) : interrupt clear */
		SCF_DDI_PUT32(statep, statep->scf_regs_handle,
			&statep->scf_regs->STATUS_ExR, 0xffffffff);

		/* DSCP buffer status register(DSR) : interrupt clear */
		SCF_DDI_PUT8(statep, statep->scf_regs_handle,
			&statep->scf_regs->DSR, 0xff);

		/* SCF interrupt status register(ISR) : interrupt clear */
		SCF_DDI_PUT16(statep, statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST,
			(INT_ST_PATHCHGIE | CONTROL_ALIVEINE));
		scf_rs16 = SCF_DDI_GET16(statep, statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST);
		goto END_intr;
	}

	/* Get SCF interrupt register */
	statep->reg_int_st = SCF_DDI_GET16(statep, statep->scf_regs_c_handle,
		&statep->scf_regs_c->INT_ST);
	SC_DBG_DRV_TRACE(TC_R_INT_ST, __LINE__, &statep->reg_int_st,
		sizeof (statep->reg_int_st));

	/* SCF interrupt register interrupt clear */
	SCF_DDI_PUT16(statep, statep->scf_regs_c_handle,
		&statep->scf_regs_c->INT_ST, statep->reg_int_st);
	SC_DBG_DRV_TRACE(TC_W_INT_ST, __LINE__, &statep->reg_int_st,
		sizeof (statep->reg_int_st));
	/* Register read sync */
	scf_rs16 = SCF_DDI_GET16(statep, statep->scf_regs_c_handle,
		&statep->scf_regs_c->INT_ST);

	SCF_DBG_TEST_INTR(statep);

	SCFDBGMSG1(SCF_DBGFLAG_REG, "ISR = 0x%04x", statep->reg_int_st);

	/* Get SCF status register */
	statep->reg_status = SCF_DDI_GET16(statep,
		statep->scf_regs_handle, &statep->scf_regs->STATUS);
	SC_DBG_DRV_TRACE(TC_R_STATUS, __LINE__, &statep->reg_status,
		sizeof (statep->reg_status));

	/* Get SCF status extended register */
	statep->reg_status_exr = SCF_DDI_GET32(statep,
		statep->scf_regs_handle, &statep->scf_regs->STATUS_ExR);
	SC_DBG_DRV_TRACE(TC_R_STATUS_ExR, __LINE__, &statep->reg_status_exr,
		sizeof (statep->reg_status_exr));

	/* Get SCF command register */
	statep->reg_command = SCF_DDI_GET16(statep,
		statep->scf_regs_handle, &statep->scf_regs->COMMAND);
	SC_DBG_DRV_TRACE(TC_R_COMMAND, __LINE__, &statep->reg_command,
		sizeof (statep->reg_command));

	/* Get SCF command extended register */
	statep->reg_command_exr = SCF_DDI_GET8(statep, statep->scf_regs_handle,
		&statep->scf_regs->COMMAND_ExR);
	SC_DBG_DRV_TRACE(TC_R_COMMAND_ExR, __LINE__, &statep->reg_command_exr,
		sizeof (statep->reg_command_exr));

	SCF_DBG_TEST_INTR_SCFINT(statep);

	/* SRAM trace */
	SCF_SRAM_TRACE(statep, DTC_INT);

	/* Check SCF path change interrupt */
	if (statep->reg_int_st & CONTROL_PATHCHGIE) {
		/* Check interrupt SCF path */
		if ((statep != scf_comtbl.scf_exec_p) &&
			(statep != scf_comtbl.scf_path_p)) {
			path_change = 1;
			goto END_intr;
		}
	}

	/* Check Alive Interrupt */
	if (statep->reg_int_st & INT_ST_ALIVEINT) {
		/* Check interrupt SCF path */
		if ((statep == scf_comtbl.scf_exec_p) ||
			(statep == scf_comtbl.scf_path_p)) {
			/* Alive check interrupt */
			scf_alivecheck_intr(statep);
		} else {
			/* not active SCF path */
			SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
				"intr    ", 8);
			/* Alive interrupt disable */
			scf_alivecheck_stop(statep);
		}
	}

	/* Check SCF interrupt */
	if (statep->reg_int_st & INT_ST_SCFINT) {
		SC_DBG_DRV_TRACE(TC_RSTS, __LINE__, &statep->reg_command,
			TC_INFO_SIZE);

		SCFDBGMSG2(SCF_DBGFLAG_REG, "STR = 0x%04x STExR = 0x%08x",
			statep->reg_status, statep->reg_status_exr);

		/* Check active SCF path */
		if ((statep == scf_comtbl.scf_exec_p) ||
			(statep == scf_comtbl.scf_path_p)) {

			/* Mode changed bit valid */
			if ((statep->reg_status & STATUS_MODE_CHANGED) ||
				(statep->reg_status & STATUS_CMD_COMPLETE)) {
				/* Check secure mode status */
				if ((statep->reg_status & STATUS_SECURE_MODE) ==
					STATUS_MODE_LOCK) {
					/* Mode status LOCK */
					scf_dm_secure_mode = SCF_STAT_MODE_LOCK;
					if (((scf_comtbl.scf_mode_sw &
						STATUS_SECURE_MODE) !=
						STATUS_MODE_LOCK) &&
						(scf_comtbl.alive_running ==
						SCF_ALIVE_START)) {
						/* Alive check start */
						scf_comtbl.scf_alive_event_sub =
							EVENT_SUB_ALST_WAIT;
					}
				} else {
					scf_dm_secure_mode =
						SCF_STAT_MODE_UNLOCK;
				}
				scf_comtbl.scf_mode_sw =
					(statep->reg_status &
					(STATUS_BOOT_MODE |
					STATUS_SECURE_MODE));
			}

			/* Check command complete */
			if ((scf_comtbl.scf_cmd_exec_flag) &&
				(statep->reg_status & STATUS_CMD_COMPLETE)) {
				/* SCF command complete processing */
				path_change = scf_intr_cmdcmp(statep);
				if (path_change) {
					goto END_intr;
				}
			}
		} else {
			/* SCF Status register interrupt clear */
			SCF_DDI_PUT16(statep, statep->scf_regs_handle,
				&statep->scf_regs->STATUS, statep->reg_status);
			SC_DBG_DRV_TRACE(TC_W_STATUS, __LINE__,
				&statep->reg_status,
				sizeof (statep->reg_status));
			/* Register read sync */
			scf_rs16 = SCF_DDI_GET16(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->STATUS);

			/* SCF Status extended register interrupt clear */
			SCF_DDI_PUT32(statep, statep->scf_regs_handle,
				&statep->scf_regs->STATUS_ExR,
				statep->reg_status_exr);
			SC_DBG_DRV_TRACE(TC_W_STATUS_ExR, __LINE__,
				&statep->reg_status_exr,
				sizeof (statep->reg_status_exr));
			/* Register read sync */
			scf_rs32 = SCF_DDI_GET32(statep,
				statep->scf_regs_handle,
				&statep->scf_regs->STATUS_ExR);
			goto END_intr;
		}

		/* Check SCF status change */
		if (statep->reg_status_exr & STATUS_SCF_STATUS_CHANGE) {
			/* SCF status change processing */
			scf_status_change(statep);
		}

		/* SCF Status register interrupt clear */
		SCF_DDI_PUT16(statep, statep->scf_regs_handle,
			&statep->scf_regs->STATUS, statep->reg_status);
		SC_DBG_DRV_TRACE(TC_W_STATUS, __LINE__, &statep->reg_status,
			sizeof (statep->reg_status));
		/* Register read sync */
		scf_rs16 = SCF_DDI_GET16(statep, statep->scf_regs_handle,
			&statep->scf_regs->STATUS);

		/* SCF Status extended register interrupt clear */
		SCF_DDI_PUT32(statep, statep->scf_regs_handle,
			&statep->scf_regs->STATUS_ExR, statep->reg_status_exr);
		SC_DBG_DRV_TRACE(TC_W_STATUS_ExR, __LINE__,
			&statep->reg_status_exr,
			sizeof (statep->reg_status_exr));
		/* Register read sync */
		scf_rs32 = SCF_DDI_GET32(statep, statep->scf_regs_handle,
			&statep->scf_regs->STATUS_ExR);

		/* SHUTDOWN/POFF/EVENT/ALIVE save */
		if (statep->reg_status &
			(STATUS_SHUTDOWN | STATUS_POFF | STATUS_EVENT)) {
			scf_comtbl.scf_event_flag |= (statep->reg_status &
				(STATUS_SHUTDOWN | STATUS_POFF | STATUS_EVENT));
		}

		/* POWER_FAILURE save */
		if (statep->reg_status_exr & STATUS_POWER_FAILURE) {
			scf_comtbl.scf_event_flag |= STATUS_SHUTDOWN;
		}

		/* Check next receive data timer exec */
		if (scf_timer_check(SCF_TIMERCD_NEXTRECV) ==
			SCF_TIMER_NOT_EXEC) {
			/* Next command send check */
			scf_next_cmd_check(statep);
		}
	}

	/* Check next command send */
	if ((scf_comtbl.scf_cmd_exec_flag == 0) &&
		(scf_comtbl.cmd_busy_wait != 0)) {
		scf_comtbl.cmd_busy_wait = 0;
		/* Signal to command wait */
		cv_signal(&scf_comtbl.cmdwait_cv);
		SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__, &scf_comtbl.cmdwait_cv,
			sizeof (kcondvar_t));
	}

	/* Check DSCP Communication Buffer Interrupt */
	if (statep->reg_int_st & INT_ST_IDBCINT) {
		/* Check interrupt SCF path */
		if ((statep == scf_comtbl.scf_exec_p) ||
			(statep == scf_comtbl.scf_path_p)) {
			scf_dscp_intr(statep);
		} else {
			/* not active SCF path */
			SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
				"intr    ", 8);
			/* DSCP buffer status register interrupt clear */
			SCF_DDI_PUT8(statep, statep->scf_regs_handle,
				&statep->scf_regs->DSR, 0xff);
			/* Register read sync */
			scf_rs8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
				&statep->scf_regs->DSR);
		}
	}

	if ((statep->reg_int_st & INT_ST_ALL) == 0) {
		/* Unclamed counter up */
		scf_comtbl.scf_unclamed_cnt++;

		/* Get control register */
		statep->reg_control = SCF_DDI_GET16(statep,
			statep->scf_regs_c_handle,
			&statep->scf_regs_c->CONTROL);
		SC_DBG_DRV_TRACE(TC_R_CONTROL, __LINE__, &statep->reg_control,
			sizeof (statep->reg_control));
		scf_comtbl.scf_unclamed.CONTROL = statep->reg_control;

		scf_comtbl.scf_unclamed.INT_ST = statep->reg_int_st;

		/* Get SCF command register */
		statep->reg_command = SCF_DDI_GET16(statep,
			statep->scf_regs_handle, &statep->scf_regs->COMMAND);
		SC_DBG_DRV_TRACE(TC_R_COMMAND, __LINE__, &statep->reg_command,
			sizeof (statep->reg_command));
		scf_comtbl.scf_unclamed.COMMAND = statep->reg_command;

		/* Get SCF status register */
		statep->reg_status = SCF_DDI_GET16(statep,
			statep->scf_regs_handle, &statep->scf_regs->STATUS);
		SC_DBG_DRV_TRACE(TC_R_STATUS, __LINE__, &statep->reg_status,
			sizeof (statep->reg_status));
		scf_comtbl.scf_unclamed.STATUS = statep->reg_status;

		/* Get SCF status extended register */
		statep->reg_status_exr = SCF_DDI_GET32(statep,
			statep->scf_regs_handle, &statep->scf_regs->STATUS_ExR);
		SC_DBG_DRV_TRACE(TC_R_STATUS_ExR, __LINE__,
			&statep->reg_status_exr,
			sizeof (statep->reg_status_exr));
		scf_comtbl.scf_unclamed.STATUS_ExR = statep->reg_status_exr;

		/* Get DSR register */
		statep->reg_dsr = SCF_DDI_GET8(statep, statep->scf_regs_handle,
			&statep->scf_regs->DSR);
		SC_DBG_DRV_TRACE(TC_R_DSR, __LINE__, &statep->reg_dsr,
			sizeof (statep->reg_dsr));
		scf_comtbl.scf_unclamed.DSR = statep->reg_dsr;
	}

/*
 * END_intr
 */
	END_intr:

	/* Check SCF path change */
	if (path_change) {
		scf_path_change(statep);
	}

	/* Collect the timers which need to be stopped */
	tm_stop_cnt = scf_timer_stop_collect(save_tmids, SCF_TIMERCD_MAX);

	/* Unlock driver mutex */
	mutex_exit(&scf_comtbl.all_mutex);

	/* Timer stop */
	if (tm_stop_cnt != 0) {
		scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
	}

	SC_DBG_DRV_TRACE(TC_INTR|TC_OUT, __LINE__, &ret, sizeof (uint_t));
	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_intr_cmdcmp()
 *
 * Description: SCF command complete processing.
 *
 */
int
scf_intr_cmdcmp(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_intr_cmdcmp() "
	struct scf_cmd		*scfcmdp;
	uint8_t			sum;
	uint32_t		sum4;
	uint8_t			*wk_in_p8;
	uint32_t		*wk_in_p32;
	uint8_t			*wk_in_p;
	uint8_t			*wk_out_p;
	uint_t			wkleng;
	uint_t			wkleng2;
	uint_t			rcount;
	uint_t			rxbuff_cnt;
	uint_t			rxbuff_flag = 0;
	char			sumerr_msg[16];
	int			info_size;
	int			ii;
	int			ret = 0;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	if (scf_comtbl.scf_exec_cmd_id) {
		/* SCF command start for ioctl */
		scfcmdp = scf_comtbl.scf_cmdp;
	} else {
		/* SCF command start for interrupt */
		scfcmdp = &scf_comtbl.scf_cmd_intr;
	}
	scfcmdp->stat0 = (statep->reg_status & STATUS_CMD_RTN_CODE) >> 4;
	scfcmdp->status = statep->reg_status;

	scf_timer_stop(SCF_TIMERCD_CMDEND);
	scf_comtbl.scf_cmd_exec_flag = 0;
	statep->cmd_to_rcnt = 0;

	statep->reg_rdata[0] = SCF_DDI_GET32(statep, statep->scf_regs_handle,
		&statep->scf_regs->RDATA0);
	statep->reg_rdata[1] = SCF_DDI_GET32(statep, statep->scf_regs_handle,
		&statep->scf_regs->RDATA1);
	SC_DBG_DRV_TRACE(TC_R_RDATA0, __LINE__, & statep->reg_rdata[0],
		sizeof (statep->reg_rdata[0]) + sizeof (statep->reg_rdata[1]));
	statep->reg_rdata[2] = SCF_DDI_GET32(statep, statep->scf_regs_handle,
		&statep->scf_regs->RDATA2);
	statep->reg_rdata[3] = SCF_DDI_GET32(statep, statep->scf_regs_handle,
		&statep->scf_regs->RDATA3);
	SC_DBG_DRV_TRACE(TC_R_RDATA2, __LINE__, &statep->reg_rdata[2],
		sizeof (statep->reg_rdata[2]) + sizeof (statep->reg_rdata[3]));

	SCF_DBG_TEST_INTR_CMDEND(statep);

	SCFDBGMSG1(SCF_DBGFLAG_SYS, "command complete status = 0x%04x",
		scfcmdp->stat0);
	SCFDBGMSG4(SCF_DBGFLAG_REG, "RxDR = 0x%08x 0x%08x 0x%08x 0x%08x",
		statep->reg_rdata[0], statep->reg_rdata[1],
		statep->reg_rdata[2], statep->reg_rdata[3]);

	/* SRAM trace */
	SCF_SRAM_TRACE(statep, DTC_RECVDATA);

	SCF_DBG_XSCF_SET_STATUS

	/* Check command return value */
	switch (scfcmdp->stat0) {
	case NORMAL_END:
		/* Norman end */
		statep->tesum_rcnt = 0;

		SCF_DBG_XSCF_SET_LENGTH

		/* Make Rx register sum */
		sum = SCF_MAGICNUMBER_S;
		wk_in_p8 = (uint8_t *)&statep->reg_rdata[0];
		for (ii = 0; ii < SCF_S_CNT_15; ii++, wk_in_p8++) {
			sum += *wk_in_p8;
		}

		SCF_DBG_MAKE_RXSUM(sum, *wk_in_p8);

		/* Check Rx register sum */
		if (sum != *wk_in_p8) {
			SCFDBGMSG2(SCF_DBGFLAG_SYS,
				"Rx sum failure 0x%02x 0x%02x", sum, *wk_in_p8);
			SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
				"intr    ", 8);
			scfcmdp->stat0 = SCF_STAT0_RDATA_SUM;
			strcpy(&sumerr_msg[0], "SCF device");
			statep->resum_rcnt++;
			goto CHECK_rxsum_start;
		}

		if (scfcmdp->flag == SCF_USE_SLBUF) {
			/*
			 * SCF_USE_SLBUF
			 */
			scfcmdp->rbufleng = statep->reg_rdata[0];
			if (scfcmdp->rbufleng > SCF_L_CNT_MAX) {
				/* Invalid receive data length */
				SCFDBGMSG1(SCF_DBGFLAG_SYS,
					"Invalid receive data length = 0x%08x",
					scfcmdp->rbufleng);
				SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
					"intr    ", 8);
				scfcmdp->stat0 = SCF_STAT0_RDATA_SUM;
				strcpy(&sumerr_msg[0], "SRAM");
				statep->resum_rcnt++;
				goto CHECK_rxsum_start;
			}

			if (scfcmdp->rbufleng == 0) {
				statep->resum_rcnt = 0;
				goto CHECK_rxsum_start;
			}
			/* Check receive data division mode */
			if ((scf_comtbl.scf_exec_cmd_id) &&
				(scfcmdp->rbufleng > scf_rxbuff_max_size)) {
				scf_comtbl.scf_rem_rxbuff_size =
					scfcmdp->rbufleng - scf_rxbuff_max_size;
				rxbuff_cnt = scf_rxbuff_max_size;
				rxbuff_flag = 1;
			} else {
				rxbuff_cnt = scfcmdp->rbufleng;
				rxbuff_flag = 0;
			}

			/* Receive data copy */
			wk_in_p = (uint8_t *)&statep->scf_sys_sram->DATA[0];
			wk_out_p = (uint8_t *)&scfcmdp->rbuf[0];
			for (ii = 0; ii < rxbuff_cnt;
				ii++, wk_in_p++, wk_out_p++) {
				*wk_out_p = SCF_DDI_GET8(statep,
					statep->scf_sys_sram_handle, wk_in_p);
			}

			/* SRAM trace */
			if (rxbuff_cnt > scf_sram_trace_data_size) {
				rcount = scf_sram_trace_data_size;
			} else {
				rcount = rxbuff_cnt;
			}
			wk_in_p = (uint8_t *)scfcmdp->rbuf;
			info_size = sizeof (statep->memo_scf_drvtrc.INFO);
			while (rcount != 0) {
				bzero((void *)&statep->memo_scf_drvtrc.INFO[0],
					info_size);
				wk_out_p = &statep->memo_scf_drvtrc.INFO[0];
				if (rcount > info_size) {
					wkleng = info_size;
				} else {
					wkleng = rcount;
				}
				rcount -= wkleng;
				bcopy(wk_in_p, wk_out_p, wkleng);
				SCF_SRAM_TRACE(statep, DTC_RECVDATA_SRAM);
				wk_in_p += wkleng;
			}

			/* Check receive data division mode */
			if (rxbuff_flag != 0) {
				goto CHECK_rxsum_start;
			}

			/* Make SRAM data sum */
			sum4 = SCF_MAGICNUMBER_L;
			wkleng2 = scfcmdp->rbufleng;
			wkleng = scfcmdp->rbufleng / 4;
			wk_in_p32 = (void *)scfcmdp->rbuf;
			for (ii = 0; ii < wkleng; ii++, wk_in_p32++) {
				sum4 += *wk_in_p32;
			}
			if ((wkleng2 % 4) == 3) {
				sum4 += ((scfcmdp->rbuf[wkleng2 - 3] << 24) |
					(scfcmdp->rbuf[wkleng2 - 2] << 16) |
					(scfcmdp->rbuf[wkleng2 - 1] <<  8));

			} else if ((wkleng2 % 4) == 2) {
				sum4 += ((scfcmdp->rbuf[wkleng2 - 2] << 24) |
					(scfcmdp->rbuf[wkleng2 - 1] << 16));
			} else if ((wkleng2 % 4) == 1) {
				sum4 += (scfcmdp->rbuf[wkleng2 - 1] << 24);
			}

			SCF_DBG_MAKE_RXSUM_L(sum4, statep->reg_rdata[2]);

			/* Check SRAM data sum */
			if (sum4 == statep->reg_rdata[2]) {
				statep->resum_rcnt = 0;
			} else {
				SCFDBGMSG2(SCF_DBGFLAG_SYS,
					"Rx sum failure 0x%08x 0x%08x",
					sum4, statep->reg_rdata[2]);
				SC_DBG_DRV_TRACE(TC_INTR|TC_ERR,
					__LINE__, "intr    ", 8);
				scfcmdp->stat0 = SCF_STAT0_RDATA_SUM;
				strcpy(&sumerr_msg[0], "SRAM");
				statep->resum_rcnt++;
			}
		} else {
			if ((scfcmdp->flag == SCF_USE_SSBUF) ||
				(scfcmdp->flag == SCF_USE_LSBUF)) {
				/*
				 * SCF_USE_SSBUF/SCF_USE_LSBUF
				 */
				if (scfcmdp->rcount < SCF_S_CNT_16) {
					wkleng = scfcmdp->rcount;
				} else {
					wkleng = SCF_S_CNT_16;
				}
				scfcmdp->rbufleng = wkleng;
				if (wkleng != 0) {
					/* Receive data copy */
					bcopy((void *)&statep->reg_rdata[0],
						(void *)scfcmdp->rbuf, wkleng);
				}
			} else {
				/*
				 * SCF_USE_S_BUF/SCF_USE_L_BUF
				 */
				scfcmdp->rbufleng = 0;
			}
			statep->resum_rcnt = 0;
		}

/*
 * CHECK_rxsum_start
 */
	CHECK_rxsum_start:

		/* Check Rx sum re-try out */
		if ((scfcmdp->stat0 == SCF_STAT0_RDATA_SUM) &&
			(statep->resum_rcnt > scf_resum_rcnt)) {
			/* SRAM trace */
			SCF_SRAM_TRACE(statep, DTC_RSUMERR);

			SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
				"intr    ", 8);
			cmn_err(CE_WARN,
				"%s,Failed the receive data SUM of %s. "
				"SCF command = 0x%02x%02x\n",
					&statep->pathname[0], &sumerr_msg[0],
					scfcmdp->subcmd, scfcmdp->cmd);
			statep->scf_herr |= HERR_RESUM;
			ret = 1;
			goto END_intr_cmdcmp;
		}
		break;

	case INTERFACE:
		/* Interface error */
		SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__, "intr    ", 8);

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_INTERFACE);

		statep->tesum_rcnt++;
		/* Check interface error re-try out */
		if (statep->tesum_rcnt > scf_tesum_rcnt) {
			cmn_err(CE_WARN,
				"%s,Detected the interface error by XSCF. "
				"SCF command = 0x%02x%02x\n",
					&statep->pathname[0], scfcmdp->subcmd,
					scfcmdp->cmd);
			statep->scf_herr |= HERR_TESUM;
			ret = 1;
			goto END_intr_cmdcmp;
		}
		break;

	case BUF_FUL:
		/* Buff full */
		SC_DBG_DRV_TRACE(TC_INTR|TC_MSG, __LINE__, "intr    ", 8);

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_RCI_BUF_FUL);

		break;

	case RCI_BUSY:
		/* RCI busy */
		SC_DBG_DRV_TRACE(TC_INTR|TC_MSG, __LINE__, "intr    ", 8);

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_RCI_BUSY);

		break;

	case E_NOT_SUPPORT:
		/* Not support command/sub command */
		SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__, "intr    ", 8);

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_E_NOT_SUPPORT);

		cmn_err(CE_WARN,
			"%s,Detected the not support command by XSCF. "
			"SCF command = 0x%02x%02x\n",
				&statep->pathname[0], scfcmdp->subcmd,
				scfcmdp->cmd);
		break;

	case E_PARAM:
		/* Parameter error */

		/* Check command is SB configuration change */
		if ((scfcmdp->cmd == CMD_DR) && (scfcmdp->subcmd ==
			SUB_SB_CONF_CHG)) {
			scfcmdp->rbufleng = SCF_S_CNT_16;
			/* Receive data copy */
			if (scfcmdp->rcount < SCF_S_CNT_16) {
				wkleng = scfcmdp->rcount;
			} else {
				wkleng = SCF_S_CNT_16;
			}
			if (wkleng != 0) {
				bcopy((void *)&statep->reg_rdata[0],
					(void *)scfcmdp->rbuf, wkleng);
			}
		} else {
			SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
				"intr    ", 8);

			/* SRAM trace */
			SCF_SRAM_TRACE(statep, DTC_E_PARAM);

			cmn_err(CE_WARN,
				"%s,Detected the invalid parameter by XSCF. "
				"SCF command = 0x%02x%02x\n",
					&statep->pathname[0], scfcmdp->subcmd,
					scfcmdp->cmd);
		}
		break;

	case E_RCI_ACCESS:
		/* RCI access error */
		SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__, "intr    ", 8);

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_E_RCI_ACCESS);

		cmn_err(CE_WARN,
			"%s,RCI access error occurred in XSCF. "
			"SCF command = 0x%02x%02x\n",
				&statep->pathname[0], scfcmdp->subcmd,
				scfcmdp->cmd);
		break;

	case E_SCFC_NOPATH:
		/* No SCFC path */
		SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__, "intr    ", 8);

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_E_SCFC_PATH);

		if (scf_comtbl.scf_exec_p) {
			scf_chg_scf(scf_comtbl.scf_exec_p, PATH_STAT_ACTIVE);
			scf_comtbl.scf_path_p = scf_comtbl.scf_exec_p;
			scf_comtbl.scf_exec_p = 0;
		}
		scf_comtbl.scf_pchg_event_sub = EVENT_SUB_PCHG_WAIT;
		break;

	case RCI_NS:
		/* Not support RCI */
		SC_DBG_DRV_TRACE(TC_INTR|TC_MSG, __LINE__, "intr    ", 8);
		cmn_err(CE_WARN,
			"%s,Cannot use RCI interface. "
			"SCF command = 0x%02x%02x\n",
				&statep->pathname[0], scfcmdp->subcmd,
				scfcmdp->cmd);
		break;

	default:
		SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__, "intr    ", 8);

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_ERRRTN | scfcmdp->stat0);

		cmn_err(CE_WARN,
			"%s,Invalid status value was notified from XSCF. "
			"SCF command = 0x%02x%02x, Status value = 0x%04x\n",
				&statep->pathname[0], scfcmdp->subcmd,
				scfcmdp->cmd, scfcmdp->status);
		scfcmdp->stat0 = E_NOT_SUPPORT;
		break;
	}

	/* Check SCF command start for interrupt */
	if (scf_comtbl.scf_exec_cmd_id == 0) {
		/* SCF command start for interrupt processing */
		scf_intr_cmdcmp_driver(statep, scfcmdp);
	} else {
		/* Check ioctl command end wait */
		if (scf_comtbl.cmd_end_wait != 0) {
			/* Check command return value */
			switch (scfcmdp->stat0) {
			case NORMAL_END:
			case BUF_FUL:
			case RCI_BUSY:
			case E_NOT_SUPPORT:
			case E_PARAM:
			case E_RCI_ACCESS:
			case RCI_NS:
				if ((scfcmdp->stat0 == NORMAL_END) &&
					(scfcmdp->cmd == CMD_ALIVE_CHECK)) {
					if (scfcmdp->subcmd ==
						SUB_ALIVE_START) {
						scf_alivecheck_start(statep);
					} else {
						scf_alivecheck_stop(statep);
					}
				}
				if ((scfcmdp->stat0 == NORMAL_END) &&
					(rxbuff_flag)) {
					break;
				}

				scf_comtbl.cmd_end_wait = 0;
				/* Signal to command end wait */
				cv_signal(&scf_comtbl.cmdend_cv);
				SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
					&scf_comtbl.cmdend_cv,
					sizeof (kcondvar_t));
				break;

			default:
				/* INTERFACE */
				/* E_SCFC_NOPATH */
				/* Rx DATA SUM ERROR */

				/* Set command retry send flag */
				scf_comtbl.scf_cmd_resend_req |= RESEND_IOCTL;
				break;
			}
		}
	}

	/* Check receive data division mode */
	if (rxbuff_flag == 1) {
		/* Next receive data timer start */
		scf_timer_start(SCF_TIMERCD_NEXTRECV);
		scf_comtbl.scf_cmd_exec_flag = 1;
	}

/*
 * END_intr_cmdcmp
 */
	END_intr_cmdcmp:

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_intr_cmdcmp_driver()
 *
 * Description: SCF command complete. start for interrupt processing.
 *
 */
void
scf_intr_cmdcmp_driver(scf_state_t *statep, struct scf_cmd *scfcmdp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_intr_cmdcmp_driver() "
	int			shutdown_flag = 0;
	int			poff_flag;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Check command code */
	switch (scfcmdp->cmd) {
	case CMD_SCFI_PATH:		/* SCF Path change command */
		/* Check command return value */
		if (scfcmdp->stat0 != NORMAL_END) {
			scf_comtbl.scf_pchg_event_sub = EVENT_SUB_PCHG_WAIT;

			/* Set command retry send flag */
			scf_comtbl.scf_cmd_resend_req |= RESEND_PCHG;
			break;
		}

		/* Check SCF path change status */
		if (scf_comtbl.scf_path_p != NULL) {
			scf_chg_scf(scf_comtbl.scf_path_p, PATH_STAT_ACTIVE);
			scf_comtbl.scf_exec_p = scf_comtbl.scf_path_p;
			scf_comtbl.scf_path_p = NULL;
			/* FMEMA interface */
			scf_avail_cmd_reg_vaddr =
				(caddr_t)&statep->scf_regs->COMMAND;

			scf_comtbl.path_change_rcnt = 0;
		}

		/* Check Alive check exec */
		if (scf_comtbl.alive_running == SCF_ALIVE_START) {
			scf_comtbl.scf_alive_event_sub = EVENT_SUB_ALST_WAIT;
		} else {
			scf_comtbl.scf_alive_event_sub = EVENT_SUB_NONE;
			if (scf_comtbl.suspend_wait == 1) {
				scf_comtbl.suspend_wait = 0;
				scf_comtbl.scf_suspend_sendstop = 1;
				cv_signal(&scf_comtbl.suspend_wait_cv);
				SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
					&scf_comtbl.suspend_wait_cv,
					sizeof (kcondvar_t));
			}
		}
		scf_comtbl.scf_pchg_event_sub = EVENT_SUB_NONE;

		scf_comtbl.scf_event_flag |= STATUS_EVENT;

		SCF_DBG_NO_INT_REASON;

		/* DSCP interface start */
		scf_dscp_start(FACTOR_PATH_CHG);
		break;

	case CMD_PART_POW_CTR:	/* power control command */
		/* Check command return value */
		if (scfcmdp->stat0 != NORMAL_END) {
			switch (scfcmdp->stat0) {
			case BUF_FUL:
			case RCI_BUSY:
			case E_NOT_SUPPORT:
			case E_PARAM:
			case E_RCI_ACCESS:
			case RCI_NS:
				scf_comtbl.scf_poff_event_sub = EVENT_SUB_NONE;
				break;

			default:
				/* INTERFACE */
				/* E_SCFC_NOPATH */
				/* Rx DATA SUM ERROR */
				scf_comtbl.scf_poff_event_sub =
					EVENT_SUB_POFF_WAIT;

				/* Set command retry send flag */
				scf_comtbl.scf_cmd_resend_req |= RESEND_POFF;
				break;
			}
			break;
		}

		poff_flag = 0;
		scf_comtbl.scf_poff_id =
			(uchar_t)((statep->reg_rdata[0] &
			0xFF000000) >> 24);

		SCF_DBG_TEST_INTR_POFF;

		if (scf_comtbl.scf_poff_id == POFF_ID_PANEL) {
			/* PANEL */
			if ((scf_comtbl.scf_mode_sw & STATUS_SECURE_MODE) !=
				STATUS_MODE_LOCK) {
				/* Not LOCK */
				SC_DBG_DRV_TRACE(TC_INTR, __LINE__,
					"intr    ", 8);
				if (scf_comtbl.scf_shutdownreason == 0) {
					poff_flag = 1;
					scf_comtbl.scf_shutdownreason =
						REASON_XSCFPOFF;
				}
				cmn_err(CE_NOTE,
					"%s: System shutdown by panel "
					"request.\n", scf_driver_name);
			}
		} else if ((scf_comtbl.scf_poff_id & POFF_ID_MASK) ==
			POFF_ID_RCI) {
			/* RCI */
			SC_DBG_DRV_TRACE(TC_INTR, __LINE__, "intr    ", 8);
			if (scf_comtbl.scf_shutdownreason == 0) {
				poff_flag = 1;
				scf_comtbl.scf_shutdownreason = REASON_RCIPOFF;
			}
			cmn_err(CE_NOTE,
				"%s: System shutdown from RCI.\n",
				scf_driver_name);
		} else if (scf_comtbl.scf_poff_id == POFF_ID_XSCF) {
			/* XSCF */
			SC_DBG_DRV_TRACE(TC_INTR, __LINE__, "intr    ", 8);
			if (scf_comtbl.scf_shutdownreason == 0) {
				poff_flag = 1;
				scf_comtbl.scf_shutdownreason = REASON_XSCFPOFF;
			}
			cmn_err(CE_NOTE,
				"%s: System shutdown by XSCF "
				"request.\n", scf_driver_name);
		}

		if (poff_flag) {
			cmn_err(CE_CONT,
				"%s: Shutdown was executed.\n",
				scf_driver_name);
			/* System shutdown start */
			do_shutdown();
		}

		scf_comtbl.scf_poff_event_sub = EVENT_SUB_NONE;
		break;

	case CMD_INT_REASON:		/* Event information command */
		/* Check command return value */
		if ((scfcmdp->stat0 != NORMAL_END) &&
			(scfcmdp->stat0 != SCF_STAT0_RDATA_SUM)) {
			switch (scfcmdp->stat0) {
			case BUF_FUL:
			case RCI_BUSY:
			case E_NOT_SUPPORT:
			case E_PARAM:
			case E_RCI_ACCESS:
			case RCI_NS:
				scf_comtbl.scf_shut_event_sub = EVENT_SUB_NONE;
				break;

			default:
				/* INTERFACE */
				/* E_SCFC_NORATH */
				if (scf_comtbl.scf_shut_event_sub ==
					EVENT_SUB_SHUT_EXEC) {
					scf_comtbl.scf_shut_event_sub =
						EVENT_SUB_SHUT_WAIT;
				} else {
					scf_comtbl.scf_shut_event_sub =
						EVENT_SUB_WAIT;
				}

				/* Set command retry send flag */
				scf_comtbl.scf_cmd_resend_req |= RESEND_SHUT;
				break;
			}
			break;
		}

		/* Check factor detail disp */
		if ((scfcmdp->stat0 == SCF_STAT0_RDATA_SUM) &&
			(scfcmdp->subcmd == SUB_INT_REASON_DISP)) {
			/* Send detail re-disp */
			scf_comtbl.int_reason_retry = 1;
			if (scf_comtbl.scf_shut_event_sub ==
				EVENT_SUB_SHUT_EXEC) {
				scf_comtbl.scf_shut_event_sub =
					EVENT_SUB_SHUT_WAIT;
			} else {
				scf_comtbl.scf_shut_event_sub = EVENT_SUB_WAIT;
			}
			break;
		}

		if (scfcmdp->stat0 == NORMAL_END) {

			SCF_DBG_TEST_DSENS(scfcmdp, (void *)scfcmdp->rbuf,
				(int)scfcmdp->rbufleng);

			scf_comtbl.int_reason_retry = 0;
			/*
			 * Event interrupt factor check
			 * processing
			 */
			shutdown_flag = scf_intr_dsens(scfcmdp,
				(void *)scfcmdp->rbuf, (int)scfcmdp->rbufleng);
		} else {
			if (scf_comtbl.scf_shut_event_sub ==
				EVENT_SUB_SHUT_EXEC) {
				shutdown_flag = DEV_SENSE_SHUTDOWN;
			}
		}
		if (shutdown_flag == DEV_SENSE_SHUTDOWN) {
			cmn_err(CE_CONT,
				"%s: Shutdown was executed.\n",
				scf_driver_name);
			/* System shutdown start */
			do_shutdown();
		}
		scf_comtbl.scf_shut_event_sub = EVENT_SUB_NONE;
		break;

	case CMD_ALIVE_CHECK:		/* Alive check command */
		/* Check command return value */
		switch (scfcmdp->stat0) {
		case NORMAL_END:
		case BUF_FUL:
		case RCI_BUSY:
		case E_NOT_SUPPORT:
		case E_PARAM:
		case E_SCFC_NOPATH:
		case E_RCI_ACCESS:
		case RCI_NS:
			if (scfcmdp->stat0 == NORMAL_END) {
				if (scfcmdp->subcmd == SUB_ALIVE_START) {
					scf_alivecheck_start(statep);
				} else {
					scf_alivecheck_stop(statep);
				}
			}

			if ((scf_comtbl.scf_alive_event_sub ==
				EVENT_SUB_ALSP_EXEC) &&
				(scf_comtbl.suspend_wait)) {
				/* Signal to suspend wait */
				scf_comtbl.suspend_wait = 0;
				scf_comtbl.scf_suspend_sendstop = 1;
				cv_signal(&scf_comtbl.suspend_wait_cv);
				SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
					&scf_comtbl.suspend_wait_cv,
					sizeof (kcondvar_t));
			}
			if ((scf_comtbl.scf_alive_event_sub ==
				EVENT_SUB_ALST_EXEC) ||
				(scf_comtbl.scf_alive_event_sub ==
				EVENT_SUB_ALSP_EXEC)) {
				scf_comtbl.scf_alive_event_sub = EVENT_SUB_NONE;
			}
			break;

		default:
			/* INTERFACE */
			/* Rx DATA SUM ERROR */
			if (scf_comtbl.alive_running == SCF_ALIVE_START) {
				scf_comtbl.scf_alive_event_sub =
					EVENT_SUB_ALST_WAIT;
			} else {
				scf_comtbl.scf_alive_event_sub =
					EVENT_SUB_ALSP_WAIT;
			}

			/* Set command retry send flag */
			if ((scfcmdp->subcmd == SUB_ALIVE_START) &&
				(scf_comtbl.scf_alive_event_sub ==
				EVENT_SUB_ALST_WAIT)) {
				scf_comtbl.scf_cmd_resend_req |= RESEND_ALST;
			} else if ((scfcmdp->subcmd == SUB_ALIVE_STOP) &&
				(scf_comtbl.scf_alive_event_sub ==
				EVENT_SUB_ALSP_WAIT)) {
				scf_comtbl.scf_cmd_resend_req |= RESEND_ALSP;
			}
			break;
		}
		break;

	case CMD_REPORT:		/* Report command */
		/* Check command return value */
		switch (scfcmdp->stat0) {
		case NORMAL_END:
		case BUF_FUL:
		case RCI_BUSY:
		case E_NOT_SUPPORT:
		case E_PARAM:
		case E_SCFC_NOPATH:
		case E_RCI_ACCESS:
		case RCI_NS:
			if ((scfcmdp->stat0 == NORMAL_END) &&
				(scf_comtbl.alive_running == SCF_ALIVE_START)) {
				/* Check Alive check exec */
				scf_comtbl.scf_alive_event_sub =
					EVENT_SUB_ALST_WAIT;
			}

			if ((scf_comtbl.scf_report_event_sub ==
				EVENT_SUB_REPORT_RUN_EXEC) ||
				(scf_comtbl.scf_report_event_sub ==
				EVENT_SUB_REPORT_SHOT_EXEC)) {
				scf_comtbl.scf_report_event_sub =
					EVENT_SUB_NONE;
			}

			if (scfcmdp->stat0 == BUF_FUL) {
				if (scf_comtbl.report_buf_ful_rcnt !=
					scf_buf_ful_rcnt) {
					scf_comtbl.report_buf_ful_rcnt++;
					scf_timer_start(SCF_TIMERCD_BUF_FUL);
				} else {
					scf_comtbl.report_buf_ful_rcnt = 0;
				}
			} else {
				scf_comtbl.report_buf_ful_rcnt = 0;
			}

			if (scfcmdp->stat0 == RCI_BUSY) {
				if (scf_comtbl.report_rci_busy_rcnt !=
					scf_rci_busy_rcnt) {
					scf_comtbl.report_rci_busy_rcnt++;
					scf_timer_start(SCF_TIMERCD_RCI_BUSY);
				} else {
					scf_comtbl.report_rci_busy_rcnt = 0;
				}
			} else {
				scf_comtbl.report_rci_busy_rcnt = 0;
			}
			break;

		default:
			/* INTERFACE */
			/* Rx DATA SUM ERROR */
			if (scf_comtbl.scf_report_event_sub ==
				EVENT_SUB_REPORT_RUN_EXEC) {
				scf_comtbl.scf_report_event_sub =
					EVENT_SUB_REPORT_RUN_WAIT;

			/* Set command retry send flag */
				scf_comtbl.scf_cmd_resend_req |=
					RESEND_REPORT_RUN;
			} else {
				scf_comtbl.scf_report_event_sub =
					EVENT_SUB_REPORT_SHUT_WAIT;

			/* Set command retry send flag */
				scf_comtbl.scf_cmd_resend_req |=
					RESEND_REPORT_SHUT;
			}
			break;
		}
		break;

	case CMD_DOMAIN_INFO:		/* Domain info command */
		/* Check command return value */
		if (scfcmdp->stat0 != NORMAL_END) {
			switch (scfcmdp->stat0) {
			case BUF_FUL:
			case RCI_BUSY:
			case E_NOT_SUPPORT:
			case E_PARAM:
			case E_RCI_ACCESS:
			case RCI_NS:
				scf_comtbl.scf_domain_event_sub =
					EVENT_SUB_NONE;
				break;

			default:
				/* INTERFACE */
				/* E_SCFC_NOPATH */
				/* Rx DATA SUM ERROR */
				scf_comtbl.scf_domain_event_sub =
					EVENT_SUB_DOMAIN_WAIT;

				/* Set command retry send flag */
				scf_comtbl.scf_cmd_resend_req |= RESEND_DOMAIN;
				break;
			}
			break;
		}

		/* Set XSCF version */
		scf_xscf_comif_version = (ushort_t)(statep->reg_rdata[3] >> 8);

		scf_comtbl.scf_domain_event_sub = EVENT_SUB_NONE;
		break;
	}

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * scf_intr_dsens()
 *
 * Description: Event factor check processing.
 *
 */
/* ARGSUSED */
int
scf_intr_dsens(struct scf_cmd *scfcmdp, scf_int_reason_t *int_rp, int len)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_intr_dsens() "
	scf_int_reason_t	*rbuf;
	uchar_t			category_code;
	uchar_t			sub_status;
	uchar_t			category_type;
	time_t			timestamp;
	int			ret = 0;
	int			ent = 0;
	int			getevent_flag;
	int			max_ent;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	rbuf = int_rp;
	max_ent = len / SCF_INT_REASON_SIZE;
	if (max_ent > 4) {
		max_ent = 4;
	}

	/* entry count loop */
	while ((rbuf->b[4]) && (ent < max_ent)) {
		/* Save last event */
		bcopy((void *)&rbuf->b[0], (void *)&scf_comtbl.last_event[0],
			SCF_INT_REASON_SIZE);

		/* Check SCFIOCEVENTLIST */
		getevent_flag = scf_push_getevent(&rbuf->b[0]);
		if (getevent_flag == 0) {
			/* wake up waiting thread */
			cv_signal(&scf_comtbl.getevent_cv);
			SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
				&scf_comtbl.getevent_cv, sizeof (kcondvar_t));
		}

		/* get category code of the sense */
		category_code = rbuf->b[4] & (~DEV_SENSE_SHUTDOWN);
		sub_status = rbuf->b[4];
		category_type = rbuf->b[6];
		SC_DBG_DRV_TRACE(TC_DSENS, __LINE__, &rbuf->b[0], 8);
		SC_DBG_DRV_TRACE(TC_DSENS, __LINE__, &rbuf->b[8], 8);
		SCFDBGMSG4(SCF_DBGFLAG_REG,
			"SENSE = 0x%08x  0x%08x 0x%08x 0x%08x",
			rbuf->four_bytes_access[0], rbuf->four_bytes_access[1],
			rbuf->four_bytes_access[2], rbuf->four_bytes_access[3]);

		switch (category_code) {
		case DEV_SENSE_FANUNIT:
			/* fan unit failure */
			SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
				"intr_dse", 8);

			if (category_type == DEV_SENSE_ATTR_OWN) {
				cmn_err(CE_WARN,
					"%s: fan unit failure"
					", sub status = 0x%02x\n",
						scf_driver_name, sub_status);
				if ((sub_status & DEV_SENSE_SHUTDOWN) &&
					(scf_comtbl.scf_shutdownreason == 0)) {
					scf_comtbl.scf_shutdownreason =
						REASON_SHUTDOWN_FAN;
					ret = DEV_SENSE_SHUTDOWN;
				}
			} else {
				cmn_err(CE_WARN,
					"%s: fan unit failure on "
					"RCI(addr = 0x%08x)"
					", FAN#%d, sub status = 0x%02x,\n"
					"sense info ="
					" 0x%02x 0x%02x 0x%02x 0x%02x"
					" 0x%02x 0x%02x 0x%02x 0x%02x\n",
						scf_driver_name,
						rbuf->four_bytes_access[0],
						rbuf->b[9], sub_status,
						rbuf->b[0], rbuf->b[1],
						rbuf->b[2], rbuf->b[3],
						rbuf->b[8], rbuf->b[9],
						rbuf->b[10], rbuf->b[11]);
			}
			break;

		case DEV_SENSE_PWRUNIT:
			/* power unit failure */
			SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
				"intr_dse", 8);

			if (category_type == DEV_SENSE_ATTR_OWN) {
				cmn_err(CE_WARN,
					"%s: power supply unit failure"
					", sub status = 0x%02x\n",
						scf_driver_name, sub_status);
				if ((sub_status & DEV_SENSE_SHUTDOWN) &&
					(scf_comtbl.scf_shutdownreason == 0)) {
					scf_comtbl.scf_shutdownreason =
						REASON_SHUTDOWN_PSU;
					ret = DEV_SENSE_SHUTDOWN;
				}
			} else {
				cmn_err(CE_WARN,
					"%s: power supply unit failure on "
					"RCI(addr = 0x%08x)"
					", FEP#%d, sub status = 0x%02x,\n"
					"sense info ="
					" 0x%02x 0x%02x 0x%02x 0x%02x"
					" 0x%02x 0x%02x 0x%02x 0x%02x\n",
						scf_driver_name,
						rbuf->four_bytes_access[0],
						rbuf->b[11],
						sub_status,
						rbuf->b[0], rbuf->b[1],
						rbuf->b[2], rbuf->b[3],
						rbuf->b[8], rbuf->b[9],
						rbuf->b[10], rbuf->b[11]);
			}
			break;

		case DEV_SENSE_UPS:
			/* UPS failure */
			SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
				"intr_dse", 8);

			if (category_type != DEV_SENSE_ATTR_OWN) {
				break;
			}

			switch (rbuf->b[8] & DEV_SENSE_UPS_MASK) {
			case DEV_SENSE_UPS_LOWBAT:
				SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
					"intr_dse", 8);
				cmn_err(CE_WARN,
					"%s: UPS low battery"
					" was detected, sub status = 0x%02x\n",
						scf_driver_name, sub_status);
				break;

			default:
				SC_DBG_DRV_TRACE(TC_INTR|TC_ERR,
					__LINE__, "intr_dse", 8);
				cmn_err(CE_WARN,
					"%s: UPS failure"
					" was detected, sub status = 0x%02x\n",
						scf_driver_name, sub_status);
				break;
			}
			if ((sub_status & DEV_SENSE_SHUTDOWN) &&
				(scf_comtbl.scf_shutdownreason == 0)) {
				scf_comtbl.scf_shutdownreason =
					REASON_SHUTDOWN_UPS;
				ret = DEV_SENSE_SHUTDOWN;
			}
			break;

		case DEV_SENSE_THERMAL:
			/* thermal failure */
			SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
				"intr_dse", 8);

			if (category_type == DEV_SENSE_ATTR_OWN) {
				cmn_err(CE_WARN,
					"%s: thermal alarm"
					", sub status = 0x%02x\n",
						scf_driver_name, sub_status);
				if ((sub_status & DEV_SENSE_SHUTDOWN) &&
					(scf_comtbl.scf_shutdownreason == 0)) {
					scf_comtbl.scf_shutdownreason =
						REASON_SHUTDOWN_THERMAL;
					ret = DEV_SENSE_SHUTDOWN;
				}
			} else {
				cmn_err(CE_WARN,
					"%s: thermal alarm on "
					"RCI(addr = 0x%08x)"
					", SENSOR#%d, sub status = 0x%02x,\n"
					"sense info ="
					" 0x%02x 0x%02x 0x%02x 0x%02x"
					" 0x%02x 0x%02x 0x%02x 0x%02x\n",
						scf_driver_name,
						rbuf->four_bytes_access[0],
						rbuf->b[9], sub_status,
						rbuf->b[0], rbuf->b[1],
						rbuf->b[2], rbuf->b[3],
						rbuf->b[8], rbuf->b[9],
						rbuf->b[10], rbuf->b[11]);
			}
			break;

		case DEV_SENSE_PWRSR:
			/* power stop */
			SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
				"intr_dse", 8);

			if (category_type != DEV_SENSE_ATTR_OWN) {
				break;
			}

			SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
				"intr_dse", 8);
			cmn_err(CE_WARN,
				"%s: Input power down was detected. "
				"UPS is activated"
				", sub status = 0x%02x\n",
					scf_driver_name, sub_status);
			if (sub_status & DEV_SENSE_SHUTDOWN) {
				if (scf_comtbl.shutdown_start_reported == 0) {
					scf_comtbl.poff_factor =
						SCF_POFF_FACTOR_PFAIL;
				}
				if (scf_comtbl.scf_shutdownreason == 0) {
					scf_comtbl.scf_shutdownreason =
						REASON_SHUTDOWN_UPS;
					ret = DEV_SENSE_SHUTDOWN;
				}
			}
			break;

		case DEV_SENSE_NODE:
			/* node error */
			SC_DBG_DRV_TRACE(TC_INTR|TC_ERR, __LINE__,
				"intr_dse", 8);

			if (category_type == DEV_SENSE_ATTR_OWN) {
				break;
			}

			cmn_err(CE_WARN,
				"%s: node error on RCI(addr = 0x%08x)"
				", sub status = 0x%02x,\n"
				"sense info ="
				" 0x%02x 0x%02x 0x%02x 0x%02x"
				" 0x%02x 0x%02x 0x%02x 0x%02x\n",
					scf_driver_name,
					rbuf->four_bytes_access[0],
					sub_status,
					rbuf->b[0], rbuf->b[1],
					rbuf->b[2], rbuf->b[3],
					rbuf->b[8], rbuf->b[9],
					rbuf->b[10], rbuf->b[11]);
			if (rbuf->b[9] == DEV_SENSE_NODE_STCKTO) {
				scf_comtbl.rcidown_event_flag = 1;
				scf_comtbl.scfreport_rcidown.rci_addr =
					rbuf->four_bytes_access[0];
				scf_comtbl.scfreport_rcidown.report_sense[0] =
					REPORT_STAT_RCIDWN;
				scf_comtbl.scfreport_rcidown.report_sense[1] =
					rbuf->b[9];
				scf_comtbl.scfreport_rcidown.report_sense[2] =
					rbuf->b[10];
				scf_comtbl.scfreport_rcidown.report_sense[3] =
					rbuf->b[11];
				scf_comtbl.scfreport_rcidown.timestamp =
					ddi_get_time();
				/* wake up waiting thread */
				cv_signal(&scf_comtbl.rsense_cv);
				SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
					&scf_comtbl.rsense_cv,
					sizeof (kcondvar_t));
			}
			break;

		case DEV_SENSE_SYS_REPORT:
			/* system status report */
			timestamp = ddi_get_time();
			(void) scf_push_reportsense(rbuf->four_bytes_access[0],
				&rbuf->b[8], timestamp);
			/* wake up waiting thread */
			cv_signal(&scf_comtbl.rsense_cv);
			SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
				&scf_comtbl.rsense_cv, sizeof (kcondvar_t));
			break;

		case DEV_SENSE_PANIC_REQ:
			/* panic request */
			cmn_err(CE_PANIC,
				"%s: panic request from RCI(addr = 0x%08x)\n",
				scf_driver_name,
				rbuf->four_bytes_access[0]);
			break;

		case DEV_SENSE_IONODESTAT:
			/* I/O node status */
			if (category_type == DEV_SENSE_ATTR_OWN) {
				break;
			}

			cmn_err(CE_NOTE,
				"%s: I/O node status sense from "
				"RCI(addr = 0x%08x), "
				"sub status = 0x%02x,\n"
				"sense info = 0x%02x 0x%02x 0x%02x 0x%02x"
				" 0x%02x 0x%02x 0x%02x 0x%02x\n",
					scf_driver_name,
					rbuf->four_bytes_access[0],
					sub_status,
					rbuf->b[0], rbuf->b[1],
					rbuf->b[2], rbuf->b[3],
					rbuf->b[8], rbuf->b[9],
					rbuf->b[10], rbuf->b[11]);
			break;

		case DEV_SENSE_STATUS_RPT:
			/* Deveice status print */
			if (scf_comtbl.rdctrl_end_wait) {
				/* rdctrl devsense? (for SCFIOCRDCTRL) */
				/* keep devsense info */
				scf_comtbl.rdctrl_sense_category_code =
					category_code;
				bcopy((void *)&rbuf->b[0],
					(void *)&scf_comtbl.rdctrl_sense[0],
					SCF_INT_REASON_SIZE);
				cv_signal(&scf_comtbl.rdcsense_cv);
				SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
					&scf_comtbl.rdcsense_cv,
					sizeof (kcondvar_t));
			}
			break;

		default:
			/* Devive status print */
			if (((category_code & 0xf0) == DEV_SENSE_RCI_PATH40) &&
				(scf_comtbl.rdctrl_end_wait)) {
				/* rdctrl devsense (for SCFIOCRDCTRL) */
				/* keep devsense info */
				scf_comtbl.rdctrl_sense_category_code =
					category_code;
				bcopy((void *)&rbuf->b[0],
					(void *)&scf_comtbl.rdctrl_sense[0],
					SCF_INT_REASON_SIZE);
				cv_signal(&scf_comtbl.rdcsense_cv);
				SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
					&scf_comtbl.rdcsense_cv,
					sizeof (kcondvar_t));
			}
			break;

		}

/*
 * NEXT_intr_dsens
 */
	NEXT_intr_dsens:

		rbuf = (void *)((char *)rbuf + SCF_INT_REASON_SIZE);
		ent++;
	}

	SCFDBGMSG1(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_status_change()
 *
 * Description: SCF status change processing.
 *
 */
void
scf_status_change(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_status_change() "
	uint8_t			scf_unit;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Check SCF status */
	if ((statep->reg_status_exr & STATUS_SCF_STATUS) == STATUS_SCF_ONLINE) {
		/*
		 * SCF online
		 */
		if (scf_comtbl.scf_status == SCF_STATUS_OFFLINE) {
			cmn_err(CE_NOTE, "%s: SCF online.\n", scf_driver_name);
		}
		scf_comtbl.scf_status = SCF_STATUS_ONLINE;

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_ONLINE);

		/* Check online wait timer exec */
		if (scf_timer_check(SCF_TIMERCD_ONLINE) == SCF_TIMER_NOT_EXEC) {
			/* DCSP interface re-start */
			scf_dscp_stop(FACTOR_OFFLINE);
			scf_dscp_start(FACTOR_ONLINE);
		} else {
			/* DCSP interface start */
			scf_dscp_start(FACTOR_ONLINE);

			/* SCF online timer stop */
			scf_timer_stop(SCF_TIMERCD_ONLINE);

			/* Check SCF command exec */
			if (scf_comtbl.scf_cmd_exec_flag) {
				/* Set command wait status */
				scf_cmdwait_status_set();
				scf_comtbl.scf_cmd_exec_flag = 0;
			}

			scf_comtbl.scf_domain_event_sub = EVENT_SUB_DOMAIN_WAIT;

			/* Check Alive check exec */
			if (scf_comtbl.alive_running == SCF_ALIVE_START) {
				scf_comtbl.scf_alive_event_sub =
					EVENT_SUB_ALST_WAIT;
			}
		}
	} else {
		/*
		 * SCF offline
		 */
		if (scf_comtbl.scf_status != SCF_STATUS_OFFLINE) {
			if (statep->reg_status_exr & STATUS_SCF_NO) {
				scf_unit = 1;
			} else {
				scf_unit = 0;
			}
			cmn_err(CE_WARN,
				"%s: SCF went to offline mode. unit=%d",
				scf_driver_name, scf_unit);
		}
		scf_comtbl.scf_status = SCF_STATUS_OFFLINE;

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_OFFLINE);

		/* Check online wait timer exec */
		if (scf_timer_check(SCF_TIMERCD_ONLINE) == SCF_TIMER_NOT_EXEC) {
			/* DCSP interface stop */
			scf_dscp_stop(FACTOR_OFFLINE);

			statep->online_to_rcnt = 0;
			/* SCF online timer start */
			scf_timer_start(SCF_TIMERCD_ONLINE);
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * scf_next_cmd_check()
 *
 * Description: Next command send and check processing.
 *
 */
void
scf_next_cmd_check(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_next_cmd_check() "
	struct scf_cmd		*scfcmdp = &scf_comtbl.scf_cmd_intr;
	int			offline_ret;
	int			cmdbusy_ret;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Check suspend send stop */
	if (scf_comtbl.scf_suspend_sendstop) {
		goto END_next_cmd_check;
	}

	if ((scf_comtbl.scf_path_p == NULL) &&
		(scf_comtbl.scf_pchg_event_sub == EVENT_SUB_PCHG_WAIT)) {
		scf_chg_scf(statep, PATH_STAT_ACTIVE);
		scf_comtbl.scf_path_p = statep;
	}

	if (scf_comtbl.scf_cmd_exec_flag == 0) {
		/* send comannd for interrupt */
		offline_ret = scf_offline_check(statep, FLAG_ON);
		cmdbusy_ret = scf_cmdbusy_check(statep);

		if ((offline_ret != SCF_PATH_ONLINE) ||
			(cmdbusy_ret != SCF_COMMAND_READY)) {
			goto END_next_cmd_check;
		}
	}

	/* Check SCF Path change request */
	if ((scf_comtbl.scf_cmd_exec_flag == 0) &&
		(scf_comtbl.scf_pchg_event_sub == EVENT_SUB_PCHG_WAIT)) {
		/* Send SCF Path change command */
		scfcmdp->cmd = CMD_SCFI_PATH;
		scfcmdp->subcmd = SUB_CMD_PATH;
		bzero((void *)&scf_comtbl.scf_sbuf[0], SCF_S_CNT_16);
		scf_comtbl.scf_sbuf[0] = CMD_PATH_TYPE_SCFD;
		scfcmdp->sbuf = &scf_comtbl.scf_sbuf[0];
		scfcmdp->scount = SCF_S_CNT_15;
		scfcmdp->rcount = 0;
		scfcmdp->flag = SCF_USE_S_BUF;
		if ((scf_comtbl.scf_cmd_resend_req & RESEND_PCHG) != 0) {
			scf_comtbl.scf_cmd_resend_flag = 1;
			scf_comtbl.scf_cmd_resend_req &= ~RESEND_PCHG;
		}
		scf_i_send_cmd(scfcmdp, statep);
		scf_comtbl.scf_pchg_event_sub = EVENT_SUB_PCHG_EXEC;
	}

	if (scf_comtbl.scf_cmd_exec_flag == 0) {
		/* Check shutdown event information request */
		if ((scf_comtbl.scf_shut_event_sub == EVENT_SUB_NONE) &&
			(scf_comtbl.scf_event_flag & STATUS_SHUTDOWN)) {
			scf_comtbl.scf_event_flag &=
				(~(STATUS_SHUTDOWN | STATUS_EVENT));
			scf_comtbl.scf_shut_event_sub = EVENT_SUB_SHUT_WAIT;
		}
		if (scf_comtbl.scf_shut_event_sub == EVENT_SUB_SHUT_WAIT) {
			/* Send event information command */
			scfcmdp->cmd = CMD_INT_REASON;
			if (scf_comtbl.int_reason_retry == 0) {
				scfcmdp->subcmd = SUB_INT_REASON_DISP;
			} else {
				scfcmdp->subcmd = SUB_INT_REASON_RETRY;
			}
			scfcmdp->scount = 0;
			scfcmdp->rbuf = &scf_comtbl.scf_rbuf[0];
			scfcmdp->rcount = SCF_INT_CNT_MAX;
			scfcmdp->flag = SCF_USE_SLBUF;
			if ((scf_comtbl.scf_cmd_resend_req & RESEND_SHUT) !=
				0) {
				scf_comtbl.scf_cmd_resend_flag = 1;
				scf_comtbl.scf_cmd_resend_req &= ~RESEND_SHUT;
			}
			scf_i_send_cmd(scfcmdp, statep);
			scf_comtbl.scf_shut_event_sub = EVENT_SUB_SHUT_EXEC;
		}
	}

	if (scf_comtbl.scf_cmd_exec_flag == 0) {
		/* Check power off factor request */
		if ((scf_comtbl.scf_poff_event_sub == EVENT_SUB_NONE) &&
			(scf_comtbl.scf_event_flag & STATUS_POFF)) {
			scf_comtbl.scf_event_flag &= (~STATUS_POFF);
			scf_comtbl.scf_poff_event_sub = EVENT_SUB_POFF_WAIT;
		}
		if (scf_comtbl.scf_poff_event_sub == EVENT_SUB_POFF_WAIT) {
			/* Send power off factor command */
			scfcmdp->cmd = CMD_PART_POW_CTR;
			scfcmdp->subcmd = SUB_POFFID;
			scfcmdp->scount = 0;
			scfcmdp->rbuf = &scf_comtbl.scf_rbuf[0];
			scfcmdp->rcount = SCF_S_CNT_15;
			scfcmdp->flag = SCF_USE_SSBUF;
			if ((scf_comtbl.scf_cmd_resend_req & RESEND_POFF) !=
				0) {
				scf_comtbl.scf_cmd_resend_flag = 1;
				scf_comtbl.scf_cmd_resend_req &= ~RESEND_POFF;
			}
			scf_i_send_cmd(scfcmdp, statep);
			scf_comtbl.scf_poff_event_sub = EVENT_SUB_POFF_EXEC;
		}
	}

	if (scf_comtbl.scf_cmd_exec_flag == 0) {
		/* Check event information request */
		if ((scf_comtbl.scf_shut_event_sub == EVENT_SUB_NONE) &&
			(scf_comtbl.scf_event_flag & STATUS_EVENT)) {
			scf_comtbl.scf_event_flag &= (~STATUS_EVENT);
			scf_comtbl.scf_shut_event_sub = EVENT_SUB_WAIT;
		}
		if (scf_comtbl.scf_shut_event_sub == EVENT_SUB_WAIT) {
			/* Send event information command */
			scfcmdp->cmd = CMD_INT_REASON;
			if (scf_comtbl.int_reason_retry == 0) {
				scfcmdp->subcmd = SUB_INT_REASON_DISP;
			} else {
				scfcmdp->subcmd = SUB_INT_REASON_RETRY;
			}
			scfcmdp->scount = 0;
			scfcmdp->rbuf = &scf_comtbl.scf_rbuf[0];
			scfcmdp->rcount = SCF_INT_CNT_MAX;
			scfcmdp->flag = SCF_USE_SLBUF;
			if ((scf_comtbl.scf_cmd_resend_req & RESEND_SHUT) !=
				0) {
				scf_comtbl.scf_cmd_resend_flag = 1;
				scf_comtbl.scf_cmd_resend_req &= ~RESEND_SHUT;
			}
			scf_i_send_cmd(scfcmdp, statep);
			scf_comtbl.scf_shut_event_sub = EVENT_SUB_EXEC;
		}
	}

	if ((scf_comtbl.scf_cmd_exec_flag == 0) &&
		((scf_timer_check(SCF_TIMERCD_BUF_FUL) ==
		SCF_TIMER_NOT_EXEC) &&
		(scf_timer_check(SCF_TIMERCD_RCI_BUSY) ==
		SCF_TIMER_NOT_EXEC))) {
		/* Check report request */
		if (scf_comtbl.scf_report_event_sub ==
			EVENT_SUB_REPORT_RUN_WAIT) {
			/* Send report(System running) command */
			scfcmdp->cmd = CMD_REPORT;
			scfcmdp->subcmd = SUB_SYSTEM_STATUS_RPT;
			bzero((void *)&scf_comtbl.scf_sbuf[0], SCF_S_CNT_16);
			scf_comtbl.scf_sbuf[0] = REPORT_STAT_SYSTEM_RUNNING;
			scf_comtbl.scf_sbuf[1] = 0;
			scf_comtbl.scf_sbuf[2] = 0;
			scf_comtbl.scf_sbuf[3] = 0;
			scfcmdp->sbuf = &scf_comtbl.scf_sbuf[0];
			scfcmdp->scount = SCF_S_CNT_15;
			scfcmdp->rcount = 0;
			scfcmdp->flag = SCF_USE_S_BUF;
			if ((scf_comtbl.scf_cmd_resend_req &
				RESEND_REPORT_RUN) != 0) {
				scf_comtbl.scf_cmd_resend_flag = 1;
				scf_comtbl.scf_cmd_resend_req &=
					~RESEND_REPORT_RUN;
			}
			scf_i_send_cmd(scfcmdp, statep);
			scf_comtbl.scf_report_event_sub =
				EVENT_SUB_REPORT_RUN_EXEC;
			scf_comtbl.scf_last_report = SCF_SYSTEM_RUNNING;
		} else if (scf_comtbl.scf_report_event_sub ==
			EVENT_SUB_REPORT_SHUT_WAIT) {
			/* Send report(Shutdown start) command */
			scfcmdp->cmd = CMD_REPORT;
			scfcmdp->subcmd = SUB_SYSTEM_STATUS_RPT;
			bzero((void *)&scf_comtbl.scf_sbuf[0],
				SCF_S_CNT_16);
			scf_comtbl.scf_sbuf[0] =
				REPORT_STAT_SHUTDOWN_START;
			scf_comtbl.scf_sbuf[1] =
				scf_poff_factor[scf_comtbl.poff_factor][0];
			scf_comtbl.scf_sbuf[2] =
				scf_poff_factor[scf_comtbl.poff_factor][1];
			scf_comtbl.scf_sbuf[3] =
				scf_poff_factor[scf_comtbl.poff_factor][2];
			scfcmdp->sbuf = &scf_comtbl.scf_sbuf[0];
			scfcmdp->scount = SCF_S_CNT_15;
			scfcmdp->rcount = 0;
			scfcmdp->flag = SCF_USE_S_BUF;
			if ((scf_comtbl.scf_cmd_resend_req &
				RESEND_REPORT_SHUT) != 0) {
				scf_comtbl.scf_cmd_resend_flag = 1;
				scf_comtbl.scf_cmd_resend_req &=
					~RESEND_REPORT_SHUT;
			}
			scf_i_send_cmd(scfcmdp, statep);
			scf_comtbl.scf_report_event_sub =
				EVENT_SUB_REPORT_SHOT_EXEC;
			scf_comtbl.scf_last_report = SCF_SHUTDOWN_START;
			scf_comtbl.shutdown_start_reported = 1;
		}
	}

	if ((scf_comtbl.scf_cmd_exec_flag == 0) &&
		(scf_comtbl.scf_domain_event_sub == EVENT_SUB_DOMAIN_WAIT)) {
		/* Send Option disp command */
		scfcmdp->cmd = CMD_DOMAIN_INFO;
		scfcmdp->subcmd = SUB_OPTION_DISP;
		bzero((void *)&scf_comtbl.scf_sbuf[0], SCF_S_CNT_16);
		scf_comtbl.scf_sbuf[13] =
			(uchar_t)(scf_scfd_comif_version >> 8);
		scf_comtbl.scf_sbuf[14] = (uchar_t)scf_scfd_comif_version;
		scfcmdp->sbuf = &scf_comtbl.scf_sbuf[0];
		scfcmdp->scount = SCF_S_CNT_15;
		scfcmdp->rbuf = &scf_comtbl.scf_rbuf[0];
		scfcmdp->rcount = SCF_S_CNT_15;
		scfcmdp->flag = SCF_USE_SSBUF;
		if ((scf_comtbl.scf_cmd_resend_req & RESEND_DOMAIN) != 0) {
			scf_comtbl.scf_cmd_resend_flag = 1;
			scf_comtbl.scf_cmd_resend_req &= ~RESEND_DOMAIN;
		}
		scf_i_send_cmd(scfcmdp, statep);
		scf_comtbl.scf_domain_event_sub = EVENT_SUB_DOMAIN_EXEC;
	}

	if (scf_comtbl.scf_cmd_exec_flag == 0) {
		/* Check alive check request */
		if (scf_comtbl.scf_alive_event_sub == EVENT_SUB_ALST_WAIT) {
			/* Send alive check start command */
			scfcmdp->cmd = CMD_ALIVE_CHECK;
			scfcmdp->subcmd = SUB_ALIVE_START;
			bzero((void *)&scf_comtbl.scf_sbuf[0], SCF_S_CNT_16);
			scf_comtbl.scf_sbuf[0] = scf_alive_watch_code;
			scf_comtbl.scf_sbuf[1] = scf_alive_phase_code;
			scf_alive_phase_code++;
			scf_comtbl.scf_sbuf[2] = scf_alive_interval_time;
			scf_comtbl.scf_sbuf[3] = scf_alive_monitor_time;
			scf_comtbl.scf_sbuf[4] =
				(uchar_t)(scf_alive_panic_time >> 8);
			scf_comtbl.scf_sbuf[5] =
				(uchar_t)(scf_alive_panic_time);
			scfcmdp->sbuf = &scf_comtbl.scf_sbuf[0];
			scfcmdp->scount = SCF_S_CNT_15;
			scfcmdp->rcount = 0;
			scfcmdp->flag = SCF_USE_S_BUF;
			if ((scf_comtbl.scf_cmd_resend_req & RESEND_ALST) !=
				0) {
				scf_comtbl.scf_cmd_resend_flag = 1;
				scf_comtbl.scf_cmd_resend_req &= ~RESEND_ALST;
			}
			scf_i_send_cmd(scfcmdp, statep);
			scf_comtbl.scf_alive_event_sub = EVENT_SUB_ALST_EXEC;
		} else if (scf_comtbl.scf_alive_event_sub ==
			EVENT_SUB_ALSP_WAIT) {
			/* Send alive check stop command */
			scfcmdp->cmd = CMD_ALIVE_CHECK;
			scfcmdp->subcmd = SUB_ALIVE_STOP;
			scfcmdp->scount = 0;
			scfcmdp->rcount = 0;
			scfcmdp->flag = SCF_USE_S_BUF;
			if ((scf_comtbl.scf_cmd_resend_req & RESEND_ALSP) !=
				0) {
				scf_comtbl.scf_cmd_resend_flag = 1;
				scf_comtbl.scf_cmd_resend_req &= ~RESEND_ALSP;
			}
			scf_i_send_cmd(scfcmdp, statep);
			scf_comtbl.scf_alive_event_sub = EVENT_SUB_ALSP_EXEC;
		}
	}

	/* Check send wait */
	if ((scf_comtbl.scf_cmd_exec_flag == 0) && (scf_comtbl.cmd_end_wait)) {
		if ((scf_comtbl.scf_cmd_resend_req & RESEND_IOCTL) != 0) {
			scf_comtbl.scf_cmd_resend_flag = 1;
			scf_comtbl.scf_cmd_resend_req &= ~RESEND_IOCTL;
		}
		scf_i_send_cmd(scf_comtbl.scf_cmdp, statep);

		scf_comtbl.scf_exec_cmd_id = 1;
	}

	/* Signal to command wait */
	if ((scf_comtbl.scf_cmd_exec_flag == 0) &&
		(scf_comtbl.cmd_busy_wait != 0)) {
		scf_comtbl.cmd_busy_wait = 0;
		cv_signal(&scf_comtbl.cmdwait_cv);
		SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__, &scf_comtbl.cmdwait_cv,
			sizeof (kcondvar_t));
	}

/*
 * END_next_cmd_check
 */
	END_next_cmd_check:

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * scf_next_rxdata_get()
 *
 * Description: Next receive data Read processing.
 *
 */
void
scf_next_rxdata_get(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_next_rxdata_get() "
	scf_state_t		*statep;
	struct scf_cmd		*scfcmdp;
	uint32_t		sum4;
	uint8_t			*wk_in_p;
	uint8_t			*wk_out_p;
	uint32_t		*wk_in_p32;
	uint_t			wk_leng;
	uint_t			rxbuff_cnt;
	uint_t			rxbuff_offset;
	int			path_ret;
	int			ii;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Check command send exec */
	if (scf_comtbl.scf_cmd_exec_flag == 0) {
		goto END_next_rxdata_get;
	}

	/* Get SCF path status */
	path_ret = scf_path_check(&statep);
	/* Check SCF path status */
	if (path_ret != SCF_PATH_ONLINE) {
		goto END_next_rxdata_get;
	}

	/* Check remainder receive data size */
	if (scf_comtbl.scf_rem_rxbuff_size == 0) {
		goto END_next_rxdata_get;
	}


	scfcmdp = scf_comtbl.scf_cmdp;
	rxbuff_offset = scfcmdp->rbufleng - scf_comtbl.scf_rem_rxbuff_size;
	if (scf_comtbl.scf_rem_rxbuff_size > scf_rxbuff_max_size) {
		rxbuff_cnt = scf_rxbuff_max_size;
	} else {
		rxbuff_cnt = scf_comtbl.scf_rem_rxbuff_size;
	}
	scf_comtbl.scf_rem_rxbuff_size -= rxbuff_cnt;

	/* Receive data copy */
	wk_in_p = (uint8_t *)&statep->scf_sys_sram->DATA[rxbuff_offset];
	wk_out_p = (uint8_t *)&scfcmdp->rbuf[rxbuff_offset];
	for (ii = 0; ii < rxbuff_cnt; ii++, wk_in_p++, wk_out_p++) {
		*wk_out_p = SCF_DDI_GET8(statep, statep->scf_sys_sram_handle,
			wk_in_p);
	}

	/* Check remainder receive data size */
	if (scf_comtbl.scf_rem_rxbuff_size != 0) {
		/* Next receive data timer start */
		scf_timer_start(SCF_TIMERCD_NEXTRECV);
		goto END_next_rxdata_get;
	}

	/* Remainder receive data end */
	scf_comtbl.scf_cmd_exec_flag = 0;

	/* Make SRAM data sum */
	sum4 = SCF_MAGICNUMBER_L;
	wk_leng = scfcmdp->rbufleng / 4;
	wk_in_p32 = (void *)scfcmdp->rbuf;
	for (ii = 0; ii < wk_leng; ii++, wk_in_p32++) {
		sum4 += *wk_in_p32;
	}
	if ((scfcmdp->rbufleng % 4) == 3) {
		sum4 += ((scfcmdp->rbuf[scfcmdp->rbufleng - 3] << 24) |
			(scfcmdp->rbuf[scfcmdp->rbufleng - 2] << 16) |
			(scfcmdp->rbuf[scfcmdp->rbufleng - 1] <<  8));
	} else if ((scfcmdp->rbufleng % 4) == 2) {
		sum4 += ((scfcmdp->rbuf[scfcmdp->rbufleng - 2] << 24) |
			(scfcmdp->rbuf[scfcmdp->rbufleng - 1] << 16));
	} else if ((scfcmdp->rbufleng % 4) == 1) {
		sum4 += (scfcmdp->rbuf[scfcmdp->rbufleng - 1] << 24);
	}

	SCF_DBG_MAKE_RXSUM_L(sum4, statep->reg_rdata[2]);

	/* Check SRAM data sum */
	if (sum4 == statep->reg_rdata[2]) {
		statep->resum_rcnt = 0;

		scf_comtbl.cmd_end_wait = 0;
		/* Signal to command end wait */
		cv_signal(&scf_comtbl.cmdend_cv);
		SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__, &scf_comtbl.cmdend_cv,
			sizeof (kcondvar_t));

		/* Next command send check */
		scf_next_cmd_check(statep);
	} else {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "next_rx ", 8);
		scfcmdp->stat0 = SCF_STAT0_RDATA_SUM;
		statep->resum_rcnt++;

		/* Check Rx sum re-try out */
		if (statep->resum_rcnt > scf_resum_rcnt) {
			/* SRAM trace */
			SCF_SRAM_TRACE(statep, DTC_RSUMERR);

			SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "next_rx ", 8);
			cmn_err(CE_WARN,
				"%s,Failed the receive data SUM of "
				"SRAM. SCF command =0x%02x%02x\n",
					&statep->pathname[0],
					scfcmdp->subcmd, scfcmdp->cmd);
			statep->scf_herr |= HERR_RESUM;
			scf_path_change(statep);
		} else {
			/* Set command wait status */
			scf_cmdwait_status_set();

			scf_comtbl.scf_cmd_exec_flag = 0;

			/* Next command send check */
			scf_next_cmd_check(statep);
		}
	}

/*
 * END_next_rxdata_get
 */
	END_next_rxdata_get:

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * scf_online_wait_tout()
 *
 * Description: SCF online monitor timeout processing.
 *
 */
void
scf_online_wait_tout(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_online_wait_tout() "
	scf_state_t		*statep = NULL;
	scf_state_t		*wkstatep = NULL;
	scf_state_t		*wait_top_statep = NULL;
	int			online_flag = 0;
	int			ii;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Get SCF path status */
	statep = scf_comtbl.scf_exec_p;
	if (statep == NULL) {
		statep = scf_comtbl.scf_path_p;
	}
	/* Check SCF path status */
	if (statep == NULL) {
		goto END_online_wait_tout;
	}

	SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "onlin_to", 8);
	/* Get SCF status extended register */
	statep->reg_status_exr = SCF_DDI_GET32(statep,
		statep->scf_regs_handle, &statep->scf_regs->STATUS_ExR);
	SC_DBG_DRV_TRACE(TC_R_STATUS_ExR, __LINE__,
		&statep->reg_status_exr, sizeof (statep->reg_status_exr));

	/* Check SCF status */
	if ((statep->reg_status_exr & STATUS_SCF_STATUS) == STATUS_SCF_ONLINE) {
		/*
		 * SCF online
		 */
		SCFDBGMSG(SCF_DBGFLAG_SYS, "SCF path online");
		if (scf_comtbl.scf_status == SCF_STATUS_OFFLINE) {
			cmn_err(CE_NOTE, "%s: SCF online.\n", scf_driver_name);
		}
		scf_comtbl.scf_status = SCF_STATUS_ONLINE;

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_ONLINE);

		/* DCSP interface start */
		scf_dscp_start(FACTOR_ONLINE);

		/* Check Alive check exec */
		if (scf_comtbl.alive_running == SCF_ALIVE_START) {
			scf_comtbl.scf_alive_event_sub = EVENT_SUB_ALST_WAIT;
		}

		/* Check command send exec */
		if (scf_comtbl.scf_cmd_exec_flag) {
			/* Set command wait status */
			scf_cmdwait_status_set();
			scf_comtbl.scf_cmd_exec_flag = 0;
		}

		scf_comtbl.scf_domain_event_sub = EVENT_SUB_DOMAIN_WAIT;

		/* Next command send check */
		scf_next_cmd_check(statep);

		/* Check next command send */
		if (scf_comtbl.cmd_busy_wait != 0) {
			scf_comtbl.cmd_busy_wait = 0;
			/* Signal to command wait */
			cv_signal(&scf_comtbl.cmdwait_cv);
			SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
				&scf_comtbl.cmdwait_cv, sizeof (kcondvar_t));
		}
	} else {
		/*
		 * SCF offline
		 */

		/* Check standby path */
		if ((wkstatep = scf_comtbl.scf_wait_p) != NULL) {
			wait_top_statep = wkstatep;
			for (ii = 0; ii < scf_path_change_max; ii++) {
				/* Get SCF status extended register */
				wkstatep->reg_status_exr =
					SCF_DDI_GET32(wkstatep,
					wkstatep->scf_regs_handle,
					&wkstatep->scf_regs->STATUS_ExR);
				SC_DBG_DRV_TRACE(TC_R_STATUS_ExR, __LINE__,
					&wkstatep->reg_status_exr,
					sizeof (wkstatep->reg_status_exr));

				/* Check SCF status */
				if ((wkstatep->reg_status_exr &
					STATUS_SCF_STATUS) ==
					STATUS_SCF_ONLINE) {
					/* SCF path change process */
						online_flag = 1;
						scf_path_change(wkstatep);
					break;
				}

				/* SCF path change */
				scf_comtbl.scf_wait_p = wkstatep->next;
				scf_chg_scf(wkstatep, PATH_STAT_STANDBY);

				/* Check standby path */
				wkstatep = scf_comtbl.scf_wait_p;
				if (wkstatep == NULL) {
					/* Not change path */
					break;
				}
				if (wkstatep != wait_top_statep) {
					/* Next SCF path */
					continue;
				} else {
					/* Not change path */
					break;
				}
			}
		}

		if (online_flag != 0) {
			goto END_online_wait_tout;
		}

		scf_comtbl.scf_status = SCF_STATUS_OFFLINE;

		statep->online_to_rcnt++;

		/* Check re-try out */
		if (statep->online_to_rcnt <= scf_online_wait_rcnt) {
			/* SCF online timer start */
			scf_timer_start(SCF_TIMERCD_ONLINE);
			goto END_online_wait_tout;
		}

		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "onlin_to", 8);

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_ONLINETO);

		scf_comtbl.scf_cmd_exec_flag = 0;

		/* Timer stop */
		scf_timer_stop(SCF_TIMERCD_CMDBUSY);
		scf_timer_stop(SCF_TIMERCD_CMDEND);
		scf_timer_stop(SCF_TIMERCD_ONLINE);
		scf_timer_stop(SCF_TIMERCD_NEXTRECV);
		scf_timer_stop(SCF_TIMERCD_BUF_FUL);
		scf_timer_stop(SCF_TIMERCD_RCI_BUSY);

		if (scf_comtbl.suspend_wait) {
			/* Signal to suspend wait */
			scf_comtbl.suspend_wait = 0;
			scf_comtbl.scf_suspend_sendstop = 1;
			cv_signal(&scf_comtbl.suspend_wait_cv);
			SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
				&scf_comtbl.suspend_wait_cv,
				sizeof (kcondvar_t));
		}
		if (scf_comtbl.cmd_end_wait != 0) {
			/* Signal to command end wait */
			scf_comtbl.cmd_end_wait = 0;
			scf_comtbl.scf_cmdp->stat0 = SCF_STAT0_NOT_PATH;
			cv_signal(&scf_comtbl.cmdend_cv);
			SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
				&scf_comtbl.cmdend_cv,
				sizeof (kcondvar_t));
		}
		if (scf_comtbl.cmd_busy_wait != 0) {
			/* Signal to command wait */
			scf_comtbl.cmd_busy_wait = 0;
			cv_signal(&scf_comtbl.cmdwait_cv);
			SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
				&scf_comtbl.cmdwait_cv,
				sizeof (kcondvar_t));
		}

		/* DCSP interface stop */
		scf_dscp_stop(FACTOR_PATH_STOP);
	}

/*
 * END_online_wait_tout
 */
	END_online_wait_tout:

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * scf_cmdbusy_tout()
 *
 * Description: SCF command busy monitor timeout processing.
 *
 */
void
scf_cmdbusy_tout(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_cmdbusy_tout() "
	scf_state_t		*statep;
	int			path_ret;
	uint8_t			wk_int8;
	uint16_t		wk_int16;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Get SCF path status */
	path_ret = scf_path_check(&statep);
	/* Check SCF path status */
	if ((path_ret != SCF_PATH_ONLINE) && (path_ret != SCF_PATH_CHANGE)) {
		goto END_cmdbusy_tout;
	}

	SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "cmdbusy ", 8);

	/* SRAM trace */
	SCF_SRAM_TRACE(statep, DTC_CMDBUSYTO);

	/* Get SCF command register */
	wk_int16 = SCF_DDI_GET16(statep, statep->scf_regs_handle,
		&statep->scf_regs->COMMAND);
	SC_DBG_DRV_TRACE(TC_R_COMMAND, __LINE__, &wk_int16, sizeof (wk_int16));
	wk_int8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
		&statep->scf_regs->COMMAND_ExR);
	SC_DBG_DRV_TRACE(TC_R_COMMAND_ExR, __LINE__, &wk_int8,
		sizeof (wk_int8));

	/* Check busy flag */
	if (((wk_int16 & COMMAND_BUSY) == 0x0000) &&
		((wk_int8 & COMMAND_ExR_BUSY) == 0x00)) {
		SCFDBGMSG(SCF_DBGFLAG_SYS, "SCF command ready");
		/* Next command send check */
		scf_next_cmd_check(statep);
	} else {
		statep->devbusy_to_rcnt++;

		/* Check re-try out */
		if (statep->devbusy_to_rcnt <= scf_devbusy_wait_rcnt) {
			/* SCF online timer start */
			scf_timer_start(SCF_TIMERCD_CMDBUSY);
			goto END_cmdbusy_tout;
		}

		if ((wk_int16 & COMMAND_BUSY) != 0x0000) {
			SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "cmdbusy ", 8);
			cmn_err(CE_WARN,
				"%s,Busy state of SCF command is "
				"not released.\n", &statep->pathname[0]);
		} else {
			SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "cmdbusy ", 8);
			cmn_err(CE_WARN,
				"%s,Busy state of XSCF is not released.\n",
				&statep->pathname[0]);
		}
		statep->scf_herr |= HERR_BUSY_RTO;
		scf_path_change(statep);
	}

/*
 * END_cmdbusy_tout
 */
	END_cmdbusy_tout:

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}

/*
 * scf_cmdend_tout()
 *
 * Description: SCF command complete monitor timeout processing.
 *
 */
void
scf_cmdend_tout(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_cmdend_tout() "
	scf_state_t		*statep;
	int			path_ret;
	struct scf_cmd		*scfcmdp;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Get SCF path status */
	path_ret = scf_path_check(&statep);
	/* Check SCF path status */
	if ((path_ret != SCF_PATH_ONLINE) && (path_ret != SCF_PATH_CHANGE)) {
		goto END_cmdend_tout;
	}

	SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "cmd_to  ", 8);

	/* SRAM trace */
	SCF_SRAM_TRACE(statep, DTC_CMDTO);

	/* error memo */
	scf_comtbl.memo_cmd_to_cnt++;
	statep->memo_cmd_to_cnt++;

	if (scf_comtbl.scf_exec_cmd_id) {
		/* Comand send for ioctl */
		scfcmdp = scf_comtbl.scf_cmdp;
	} else {
		/* Comand send for interrupt */
		scfcmdp = &scf_comtbl.scf_cmd_intr;
	}

	statep->cmd_to_rcnt++;

	/* Check re-try out */
	if (statep->cmd_to_rcnt <= scf_cmd_to_rcnt) {
		/* Set command wait status */
		scf_cmdwait_status_set();

		scf_comtbl.scf_cmd_exec_flag = 0;

		/* Next command send check */
		scf_next_cmd_check(statep);
	} else {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "cmd_to  ", 8);
		cmn_err(CE_WARN,
			"%s,SCF command timeout occurred. "
			"SCF command = 0x%02x%02x\n",
				&statep->pathname[0],
				scfcmdp->subcmd, scfcmdp->cmd);
		statep->scf_herr |= HERR_CMD_RTO;
		scf_path_change(statep);
	}

/*
 * END_cmdend_tout
 */
	END_cmdend_tout:

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * scf_report_send_wait_tout()
 *
 * Description: Report command send wait timeout processing.
 *
 */
void
scf_report_send_wait_tout(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_report_send_wait_tout() "
	scf_state_t		*statep;
	int			next_send = 0;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Get SCF path status */
	(void) scf_path_check(&statep);
	/* Check SCF path status */
	if (statep != NULL) {
		/* Last send report send */
		if (scf_comtbl.scf_last_report == SCF_SYSTEM_RUNNING) {
			scf_comtbl.scf_report_event_sub =
				EVENT_SUB_REPORT_RUN_WAIT;
			next_send = 1;
		} else if (scf_comtbl.scf_last_report ==
			EVENT_SUB_REPORT_SHOT_EXEC) {
			scf_comtbl.scf_report_event_sub =
				EVENT_SUB_REPORT_SHUT_WAIT;
			next_send = 1;
		}
		if (next_send) {
			/* Next command send check */
			scf_next_cmd_check(statep);
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * scf_alivecheck_intr()
 *
 * Description: Alive check timeout interrupt processing.
 *
 */
void
scf_alivecheck_intr(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_alivecheck_intr() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Check alive check exec */
	if (scf_comtbl.alive_running == SCF_ALIVE_START) {
		scf_comtbl.scf_alive_int_count--;

		if (scf_comtbl.scf_alive_int_count == 0) {
			/* Alive check register set */
			statep->reg_acr = scf_acr_phase_code | ACR_ALIVE_INT;
			SCF_DDI_PUT8(statep, statep->scf_regs_handle,
				&statep->scf_regs->ACR, statep->reg_acr);
			SC_DBG_DRV_TRACE(TC_W_ACR, __LINE__, &statep->reg_acr,
				sizeof (statep->reg_acr));
			/* Register read sync */
			scf_rs8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
				&statep->scf_regs->ACR);

			SCFDBGMSG1(SCF_DBGFLAG_REG, "ACR = 0x%02x",
				statep->reg_acr);

			scf_acr_phase_code++;
			scf_comtbl.scf_alive_int_count =
				scf_alive_interval_time / 3;
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * scf_path_change()
 *
 * Description: SCF pass change processing.
 *
 */
void
scf_path_change(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_path_change() "
	scf_state_t		*wkstatep;
	scf_state_t		*act_statep = NULL;
	uint_t			path_change = 0;
	uint_t			halt_flag = 0;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	if (statep->scf_herr != 0) {
		act_statep = statep;

		statep->scf_herr |= HERR_EXEC;

		/* Interrupt disable */
		scf_forbid_intr(statep);

		/* Change statep */
		if (scf_comtbl.scf_path_p == statep) {
			scf_comtbl.scf_path_p = NULL;
			path_change = FACTOR_PATH_HALT;
		} else if (scf_comtbl.scf_exec_p == statep) {
			scf_comtbl.scf_exec_p = NULL;
			path_change = FACTOR_PATH_HALT;
		} else {
			if ((statep->path_status == PATH_STAT_STANDBY) ||
				(statep->path_status == PATH_STAT_STOP)) {
				scf_del_queue(statep);
			}
		}
		if ((statep->path_status == PATH_STAT_ACTIVE) ||
			(statep->path_status == PATH_STAT_STANDBY) ||
			(statep->path_status == PATH_STAT_STOP)) {
			scf_chg_scf(statep, PATH_STAT_FAIL);
		}
	} else {
		/* SCF path change interrupt or SCF online wait timeout */
		if (scf_comtbl.scf_exec_p != NULL) {
			act_statep = scf_comtbl.scf_exec_p;
		} else if (scf_comtbl.scf_path_p != NULL) {
			act_statep = scf_comtbl.scf_path_p;
		}
		if ((act_statep != NULL) && (scf_comtbl.scf_wait_p != NULL)) {
			/* Interrupt disable */
			scf_forbid_intr(act_statep);
			/* Interrupt enable */
			scf_permit_intr(act_statep, 1);

			scf_comtbl.scf_exec_p = NULL;
			scf_comtbl.scf_path_p = NULL;
			path_change = FACTOR_PATH_STOP;

			scf_chg_scf(act_statep, PATH_STAT_STANDBY);
		}
	}

	if (path_change) {
		/* FMEMA interface */
		scf_avail_cmd_reg_vaddr = NULL;

		/* Check standby path */
		if ((wkstatep = scf_comtbl.scf_wait_p) != NULL) {
			if (path_change == FACTOR_PATH_HALT) {
				/* Check SCF path change retry */
				if (scf_comtbl.path_change_rcnt <
					scf_path_change_max) {
					scf_comtbl.path_change_rcnt++;
				} else {
					/* SCF path change retry over */
					halt_flag = FACTOR_PATH_HALT;
				}
			}
		} else {
			/* Not change path */
			halt_flag = FACTOR_PATH_HALT;
		}

		if (halt_flag == 0) {
			if (wkstatep != act_statep) {
				cmn_err(CE_CONT,
					"%s: SCFC path changed. (%s --> %s)\n",
					scf_driver_name,
					&act_statep->pathname[0],
					&wkstatep->pathname[0]);
			}

			/* Timer stop */
			scf_timer_stop(SCF_TIMERCD_CMDBUSY);
			scf_timer_stop(SCF_TIMERCD_CMDEND);
			scf_timer_stop(SCF_TIMERCD_ONLINE);
			scf_timer_stop(SCF_TIMERCD_NEXTRECV);

			/* Set command wait status */
			scf_cmdwait_status_set();

			scf_comtbl.scf_alive_event_sub = EVENT_SUB_NONE;
			scf_comtbl.scf_cmd_exec_flag = 0;
			/* Send path change */
			scf_comtbl.scf_wait_p = wkstatep->next;
			scf_comtbl.scf_pchg_event_sub = EVENT_SUB_PCHG_WAIT;
			scf_next_cmd_check(wkstatep);

			/* DCSP interface stop */
			scf_dscp_stop(FACTOR_PATH_CHG);
		}
	}

	if (halt_flag) {
		SC_DBG_DRV_TRACE(TC_ERR, __LINE__, "path_chg", 8);

		scf_comtbl.path_change_rcnt = 0;

		scf_comtbl.scf_cmd_exec_flag = 0;

		/* Timer stop */
		scf_timer_stop(SCF_TIMERCD_CMDBUSY);
		scf_timer_stop(SCF_TIMERCD_CMDEND);
		scf_timer_stop(SCF_TIMERCD_ONLINE);
		scf_timer_stop(SCF_TIMERCD_NEXTRECV);
		scf_timer_stop(SCF_TIMERCD_BUF_FUL);
		scf_timer_stop(SCF_TIMERCD_RCI_BUSY);

		if (scf_comtbl.suspend_wait) {
			/* Signal to suspend wait */
			scf_comtbl.suspend_wait = 0;
			scf_comtbl.scf_suspend_sendstop = 1;
			cv_signal(&scf_comtbl.suspend_wait_cv);
			SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
				&scf_comtbl.suspend_wait_cv,
				sizeof (kcondvar_t));
		}
		if (scf_comtbl.cmd_end_wait != 0) {
			/* Signal to command end wait */
			scf_comtbl.cmd_end_wait = 0;
			scf_comtbl.scf_cmdp->stat0 = SCF_STAT0_NOT_PATH;
			cv_signal(&scf_comtbl.cmdend_cv);
			SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
				&scf_comtbl.cmdend_cv, sizeof (kcondvar_t));
		}
		if (scf_comtbl.cmd_busy_wait != 0) {
			/* Signal to command wait */
			scf_comtbl.cmd_busy_wait = 0;
			cv_signal(&scf_comtbl.cmdwait_cv);
			SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
				&scf_comtbl.cmdwait_cv, sizeof (kcondvar_t));
		}

		/* DCSP interface stop */
		scf_dscp_stop(halt_flag);

		if (halt_flag == FACTOR_PATH_HALT) {
			/* Not change path(SCF HALT) */

			/* FMEMA interface */
			scf_avail_cmd_reg_vaddr = NULL;

			cmn_err(CE_WARN,
				"%s: SCF HALT was detected.\n",
				scf_driver_name);

			/* SCF HALT after processing */
			scf_halt(scf_halt_proc_mode);
		}

	}

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * scf_halt()
 *
 * Description: SCFHALT shutdown/panic processing.
 *
 */
void
scf_halt(uint_t mode)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_halt() "
	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__, &mode, sizeof (mode));

	switch (mode) {
	case HALTPROC_SHUTDOWN:
		cmn_err(CE_CONT,
			"%s: Shutdown was executed.\n",
			scf_driver_name);
		/* System shutdown start */
		if (scf_comtbl.scf_shutdownreason == 0) {
			scf_comtbl.scf_shutdownreason = REASON_SHUTDOWN_HALT;
			do_shutdown();
		}
		break;

	case HALTPROC_PANIC:
		/* System panic */
		cmn_err(CE_PANIC,
			"%s: Executed panic by SCF HALT.\n",
			scf_driver_name);
		break;

	default:
		break;
	}

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}


/*
 * scf_panic_callb()
 *
 * Description: Panic entry processing.
 *
 */
/* ARGSUSED */
void
scf_panic_callb(int code)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_panic_callb() "
	scf_state_t		*statep;
	scf_state_t		*save__exec_p;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;
	unsigned short		status;
	int			counter;
	int			report_succeeded = 0;
	int			path_flag = 0;
	int			path_counter = 0;
	int			report_counter = 0;
	int			ii = 0;
	int			new_report = 0;

	SCFDBGMSG1(SCF_DBGFLAG_FOCK, SCF_FUNC_NAME ": start code = %d",
		code);
	SCF_PANIC_TRACE(__LINE__);

	/* Check panic after */
	if (scf_panic_reported) {
		SCF_PANIC_TRACE(__LINE__);
		return;
	}

	/* Check double panic */
	if (scf_panic_exec_flag) {
		SCF_PANIC_TRACE(__LINE__);
		return;
	}

	/* Check shutdown exec */
	if (scf_comtbl.scf_shutdown_exec_flag) {
		SCF_PANIC_TRACE(__LINE__);
		return;
	}

	/* Set panic exec flag */
	scf_panic_exec_flag = 1;

	save__exec_p = scf_comtbl.scf_exec_p;
	/* wait */
	drv_usecwait(SCF_MIL2MICRO(scf_panic_exec_wait_time));

	if ((statep = scf_comtbl.scf_exec_p) != NULL) {
		/* Exec SCF path interrupt disable */
		/* SCF interrupt disable(CR) */
		SCF_P_DDI_PUT16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->CONTROL, CONTROL_DISABLE);
		/* Register read sync */
		status = SCF_P_DDI_GET16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->CONTROL);

		/* SCF Status register interrupt(STR) : clear */
		SCF_P_DDI_PUT16(statep->scf_regs_handle,
			&statep->scf_regs->STATUS, 0xffff);

		/* SCF Status extended register(STExR) : interrupt clear */
		SCF_P_DDI_PUT32(statep->scf_regs_handle,
			&statep->scf_regs->STATUS_ExR, 0xffffffff);

		/* DSCP buffer status register(DSR) : interrupt clear */
		SCF_P_DDI_PUT8(statep->scf_regs_handle,
			&statep->scf_regs->DSR, 0xff);

		/* SCF interrupt status register(ISR) : interrupt clear */
		SCF_P_DDI_PUT16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST,
			(INT_ST_PATHCHGIE | CONTROL_ALIVEINE));
		status = SCF_P_DDI_GET16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST);
	}

	if ((statep = scf_comtbl.scf_path_p) != NULL) {
		/* Path change SCF path interrupt disable */
		/* SCF interrupt disable(CR) */
		SCF_P_DDI_PUT16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->CONTROL, CONTROL_DISABLE);
		/* Register read sync */
		status = SCF_P_DDI_GET16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->CONTROL);

		/* SCF Status register interrupt(STR) : clear */
		SCF_P_DDI_PUT16(statep->scf_regs_handle,
			&statep->scf_regs->STATUS, 0xffff);

		/* SCF Status extended register(STExR) : interrupt clear */
		SCF_P_DDI_PUT32(statep->scf_regs_handle,
			&statep->scf_regs->STATUS_ExR, 0xffffffff);

		/* DSCP buffer status register(DSR) : interrupt clear */
		SCF_P_DDI_PUT8(statep->scf_regs_handle,
			&statep->scf_regs->DSR, 0xff);

		/* SCF interrupt status register(ISR) : interrupt clear */
		SCF_P_DDI_PUT16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST,
			(INT_ST_PATHCHGIE | CONTROL_ALIVEINE));
		status = SCF_P_DDI_GET16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST);
	}

	statep = scf_comtbl.scf_wait_p;
	while (statep != NULL) {	/* Standby SCF path interrupt disable */
		/* SCF interrupt disable(CR) */
		SCF_P_DDI_PUT16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->CONTROL, CONTROL_DISABLE);
		/* Register read sync */
		status = SCF_P_DDI_GET16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->CONTROL);

		/* SCF Status register interrupt(STR) : clear */
		SCF_P_DDI_PUT16(statep->scf_regs_handle,
			&statep->scf_regs->STATUS, 0xffff);

		/* SCF Status extended register(STExR) : interrupt clear */
		SCF_P_DDI_PUT32(statep->scf_regs_handle,
			&statep->scf_regs->STATUS_ExR, 0xffffffff);

		/* DSCP buffer status register(DSR) : interrupt clear */
		SCF_P_DDI_PUT8(statep->scf_regs_handle,
			&statep->scf_regs->DSR, 0xff);

		/* SCF interrupt status register(ISR) : interrupt clear */
		SCF_P_DDI_PUT16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST,
			(INT_ST_PATHCHGIE | CONTROL_ALIVEINE));
		status = SCF_P_DDI_GET16(statep->scf_regs_c_handle,
			&statep->scf_regs_c->INT_ST);

		statep = statep->next;
	}

	status = 0;

	/* Check comand exec */
	if (scf_comtbl.scf_cmd_exec_flag == 0) {
		statep = scf_comtbl.scf_exec_p;
		if (statep == NULL) {
			statep = scf_comtbl.scf_path_p;
			if (statep == NULL) {
				statep = scf_comtbl.scf_wait_p;
				if (statep == NULL) {
					/* Not use SCF path */
					SCF_PANIC_TRACE(__LINE__);
					goto END_scf_panic_callb;
				}
				path_flag = 1;
			}
		}
		goto START_scf_panic;
	}

	statep = scf_comtbl.scf_exec_p;
	if (statep == NULL) {
		statep = scf_comtbl.scf_path_p;
		if (statep == NULL) {
			statep = scf_comtbl.scf_wait_p;
			if (statep == NULL) {
				SCF_PANIC_TRACE(__LINE__);
				goto END_scf_panic_callb;
			}
			/* wait */
			drv_usecwait(SCF_MIL2MICRO((scf_cmdend_wait_time_panic *
				scf_cmdend_wait_rcnt_panic)));
			path_flag = 1;
		}
	}
	if (path_flag == 0) {
		for (ii = 0; ii < scf_cmdend_wait_rcnt_panic; ii++) {
			/* wait */
			drv_usecwait
			(SCF_MIL2MICRO(scf_cmdend_wait_time_panic));

			/* Get SCF status register */
			status = SCF_P_DDI_GET16(statep->scf_regs_handle,
				&statep->scf_regs->STATUS);
			scf_panic_trc_status = status;

			if (status & STATUS_CMD_COMPLETE) {
				/* Command complete */
				break;
			}
		}
		SCF_P_DDI_PUT16(statep->scf_regs_handle,
			&statep->scf_regs->STATUS, 0xffff);
	}

/*
 * START_scf_panic
 */
	START_scf_panic:

	counter = scf_panic_report_maxretry;
	do {
/*
 * START_scf_panic_loop
 */
	START_scf_panic_loop:

		/* Check SCF path change */
		if (path_flag == 0) {
			goto START_report_send;
		}

		scf_cmd.cmd = CMD_SCFI_PATH;
		scf_cmd.subcmd = SUB_CMD_PATH;
		bzero((void *)&sbuf.b[0], SCF_S_CNT_16);
		sbuf.b[0] = REPORT_STAT_PANIC;
		scf_cmd.scount = CMD_PATH_TYPE_SCFD;
		scf_cmd.sbuf = &sbuf.b[0];
		scf_cmd.rcount = 0;
		scf_cmd.flag = SCF_USE_S_BUF;
		scf_p_send_cmd(&scf_cmd, statep);

		/* Check command complete */
		for (ii = 0; ii < scf_cmdend_wait_rcnt_panic; ii++) {
			/* wait */
			drv_usecwait(SCF_MIL2MICRO(scf_cmdend_wait_time_panic));

			/* Get SCF status register */
			status = SCF_P_DDI_GET16(statep->scf_regs_handle,
				&statep->scf_regs->STATUS);
			scf_panic_trc_status = status;

			if (status & STATUS_CMD_COMPLETE) {
				/* Command complete */
				break;
			}
		}
		SCF_P_DDI_PUT16(statep->scf_regs_handle,
			&statep->scf_regs->STATUS, 0xffff);

		if (ii == scf_cmdend_wait_rcnt_panic) {
			/* Not command complete */
			if (path_counter < 1) {
				path_counter++;
				goto START_scf_panic_loop;
			}
			SCF_PANIC_TRACE(__LINE__);
			goto END_scf_panic_callb;
		}
		switch ((status & STATUS_CMD_RTN_CODE) >> 4) {
		case NORMAL_END:
			counter = scf_panic_report_maxretry;
			path_flag = 0;
			report_counter = 0;
			break;
		default:
			if (path_counter < 1) {
				path_flag = 1;
				path_counter++;
				goto START_scf_panic_loop;
			}
			SCF_PANIC_TRACE(__LINE__);
			goto END_scf_panic_callb;
		}

/*
 * START_report_send
 */
	START_report_send:

		if (new_report) {
			/* new report panic */
			scf_cmd.cmd = CMD_REPORT;
			scf_cmd.subcmd = SUB_SYSTEM_STATUS_RPT_NOPATH;
		} else {
			/* report panic */
			scf_cmd.cmd = CMD_REPORT;
			scf_cmd.subcmd = SUB_SYSTEM_STATUS_RPT;
		}
		bzero((void *)&sbuf.b[0], SCF_S_CNT_16);
		sbuf.b[0] = REPORT_STAT_PANIC;
		scf_cmd.scount = SCF_S_CNT_15;
		scf_cmd.sbuf = &sbuf.b[0];
		scf_cmd.rcount = 0;
		scf_cmd.flag = SCF_USE_S_BUF;
		scf_p_send_cmd(&scf_cmd, statep);
		scf_panic_exec_flag2 = 1;

		/* Check command complete */
		for (ii = 0; ii < scf_cmdend_wait_rcnt_panic; ii++) {
			/* wait */
			drv_usecwait(SCF_MIL2MICRO(scf_cmdend_wait_time_panic));

			/* Get SCF status register */
			status = SCF_P_DDI_GET16(statep->scf_regs_handle,
				&statep->scf_regs->STATUS);
			scf_panic_trc_status = status;

			if (status & STATUS_CMD_COMPLETE) {
				/* Command complete */
				break;
			}
		}
		SCF_P_DDI_PUT16(statep->scf_regs_handle,
			&statep->scf_regs->STATUS, 0xffff);

		if (ii == scf_cmdend_wait_rcnt_panic) {
			/* Not command complete */
			if (report_counter < 1) {
				report_counter++;
				goto START_scf_panic_loop;
			}
			SCF_PANIC_TRACE(__LINE__);
			goto END_scf_panic_callb;
		}

		switch ((status & STATUS_CMD_RTN_CODE) >> 4) {
		case NORMAL_END:
			/* command success */
			report_succeeded = 1;
			SCF_PANIC_TRACE(__LINE__);
			goto END_scf_panic_callb;

		case BUF_FUL:
			counter--;
			if (counter > 0) {
				drv_usecwait(SCF_MIL2MICRO(scf_buf_ful_rtime));
			}
			break;

		case RCI_BUSY:
			counter--;
			if (counter > 0) {
				drv_usecwait(SCF_MIL2MICRO(scf_rci_busy_rtime));
			}
			break;

		case INTERFACE:
			counter--;
			break;

		case E_SCFC_NOPATH:
			if (new_report == 0) {
				path_flag = 1;
				path_counter = 0;
				goto START_scf_panic_loop;
			}

		default:
			/* E_NOT_SUPPORT */
			/* E_PARAM */
			/* E_RCI_ACCESS */
			/* RCI_NS */
			goto END_scf_panic_callb;
		}

	} while (counter > 0);

/*
 * END_scf_panic_callb
 */
	END_scf_panic_callb:

	scf_comtbl.scf_exec_p = save__exec_p;
	if (report_succeeded) {
		SCF_PANIC_TRACE(__LINE__);
		scf_panic_reported = 1;
	} else {
		SCF_PANIC_TRACE(__LINE__);
		cmn_err(CE_WARN, "%s: cannot report PANIC.\n", scf_driver_name);
	}

	SCFDBGMSG(SCF_DBGFLAG_FOCK, SCF_FUNC_NAME ": end");
}


/*
 * scf_shutdown_callb()
 *
 * Description: Shutdown entry processing.
 *
 */
/* ARGSUSED */
void
scf_shutdown_callb(int code)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_shutdown_callb() "
	scf_state_t		*statep;
	int			ret;
	struct scf_cmd		scf_cmd;
	scf_short_buffer_t	sbuf;

	SCFDBGMSG1(SCF_DBGFLAG_FOCK, SCF_FUNC_NAME ": start code = %d",
		code);

	mutex_enter(&scf_comtbl.all_mutex);

	/* Check panic exec or shutdown exec */
	if ((scf_panic_exec_flag) || (scf_comtbl.scf_shutdown_exec_flag)) {
		SCFDBGMSG(SCF_DBGFLAG_SYS, "After Panic or shutdown");
		goto END_scf_shutdown_callb99;
	}

	scf_comtbl.scf_shutdown_exec_flag = 1;

	/* SCF command transmit sync stop */
	ret = scf_make_send_cmd(&scf_cmd, SCF_USE_STOP);
	if (ret != 0) {
		SC_DBG_DRV_TRACE(TC_SHUTDOWN|TC_ERR, __LINE__, "i_ioctl ", 8);
		goto END_scf_shutdown_callb;
	}

	scf_comtbl.shutdown_start_reported = 1;

	bzero((void *)&sbuf.b[0], SCF_S_CNT_16);
	sbuf.b[0] = REPORT_STAT_SHUTDOWN_START;
	sbuf.b[1] = scf_poff_factor[scf_comtbl.poff_factor][0];
	sbuf.b[2] = scf_poff_factor[scf_comtbl.poff_factor][1];
	sbuf.b[3] = scf_poff_factor[scf_comtbl.poff_factor][2];
	scf_cmd.cmd = CMD_REPORT;
	scf_cmd.subcmd = SUB_SYSTEM_STATUS_RPT_NOPATH;
	scf_cmd.scount = SCF_S_CNT_15;
	scf_cmd.sbuf = &sbuf.b[0];
	scf_cmd.rcount = 0;
	scf_cmd.flag = (SCF_USE_S_BUF | SCF_USE_SP);
	scf_comtbl.scf_last_report = SCF_SHUTDOWN_START;

	ret = scf_send_cmd_check_bufful(&scf_cmd);
	if (ret != 0) {
		SC_DBG_DRV_TRACE(TC_SHUTDOWN|TC_ERR, __LINE__, "shutdown", 8);
		goto END_scf_shutdown_callb;
	}
	/* SCF command send sync re-stop */
	ret = scf_make_send_cmd(&scf_cmd, SCF_USE_STOP);
	if (ret != 0) {
		SC_DBG_DRV_TRACE(TC_SHUTDOWN|TC_ERR, __LINE__, "shutdown", 8);
		goto END_scf_shutdown_callb;
	}

	/* Check alive check exec */
	if (scf_comtbl.alive_running == SCF_ALIVE_START) {
		scf_cmd.cmd = CMD_ALIVE_CHECK;
		scf_cmd.subcmd = SUB_ALIVE_STOP;
		scf_cmd.scount = 0;
		scf_cmd.rcount = 0;
		scf_cmd.flag = (SCF_USE_S_BUF | SCF_USE_SP);
		ret = scf_send_cmd_check_bufful(&scf_cmd);
		scf_comtbl.alive_running = SCF_ALIVE_STOP;
		if (ret != 0) {
			SC_DBG_DRV_TRACE(TC_SHUTDOWN|TC_ERR, __LINE__,
				"shutdown", 8);
			goto END_scf_shutdown_callb;
		}
		/* SCF command send sync re-stop */
		ret = scf_make_send_cmd(&scf_cmd, SCF_USE_STOP);
	}

/*
 * END_scf_shutdown_callb
 */
END_scf_shutdown_callb:

	if ((statep = scf_comtbl.scf_exec_p) == NULL) {
		statep = scf_comtbl.scf_path_p;
	}
	scf_comtbl.scf_exec_p = 0;
	scf_comtbl.scf_path_p = 0;
	if (statep) {
		/* Exec device interrupt disable */
		scf_forbid_intr(statep);
		scf_chg_scf(statep, PATH_STAT_STOP);
	}

	while (scf_comtbl.scf_wait_p) {
		/* Standby device interrupt disable */
		statep = scf_comtbl.scf_wait_p;
		scf_comtbl.scf_wait_p = statep->next;
		scf_forbid_intr(statep);
		scf_chg_scf(statep, PATH_STAT_STOP);
	}

	/* SCF command send sync start */
	(void) scf_make_send_cmd(&scf_cmd, SCF_USE_START);

	/* DCSP interface stop */
	scf_dscp_stop(FACTOR_PATH_STOP);

/*
 * END_scf_shutdown_callb99
 */
END_scf_shutdown_callb99:

	mutex_exit(&scf_comtbl.all_mutex);

	SCFDBGMSG(SCF_DBGFLAG_FOCK, SCF_FUNC_NAME ": end");
}


/*
 * scf_softintr()
 *
 * Description: Soft interrupt entry processing. (for DSCP callback)
 *
 */
/* ARGSUSED */
uint_t
scf_softintr(caddr_t arg)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_softintr() "
	uint_t			ret = DDI_INTR_CLAIMED;

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	mutex_enter(&scf_comtbl.si_mutex);
	if (scf_comtbl.scf_softintr_dscp_kicked == FLAG_ON) {
		/* Lock driver mutex */
		mutex_enter(&scf_comtbl.all_mutex);

		/* Check panic exec and shutdown exec */
		if ((scf_panic_exec_flag == 0) &&
			(scf_comtbl.scf_shutdown_exec_flag == 0)) {
			scf_dscp_callback();
		}

		/* Unlock driver mutex */
		mutex_exit(&scf_comtbl.all_mutex);

		scf_comtbl.scf_softintr_dscp_kicked = FLAG_OFF;
	}
	mutex_exit(&scf_comtbl.si_mutex);

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
	return (ret);
}


/*
 * scf_cmdwait_status_set()
 *
 * Description: Check and setting command status.
 *
 */
void
scf_cmdwait_status_set(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_cmdwait_status_set() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": start");

	/* Set command wait status */
	if (scf_comtbl.scf_pchg_event_sub == EVENT_SUB_PCHG_EXEC) {
		scf_comtbl.scf_pchg_event_sub = EVENT_SUB_PCHG_WAIT;

		/* Set command retry send flag */
		scf_comtbl.scf_cmd_resend_req |= RESEND_PCHG;
	}

	if (scf_comtbl.scf_poff_event_sub == EVENT_SUB_POFF_EXEC) {
		scf_comtbl.scf_poff_event_sub = EVENT_SUB_POFF_WAIT;

		/* Set command retry send flag */
		scf_comtbl.scf_cmd_resend_req |= RESEND_POFF;
	}

	switch (scf_comtbl.scf_shut_event_sub) {
	case EVENT_SUB_SHUT_EXEC:
		scf_comtbl.scf_shut_event_sub = EVENT_SUB_SHUT_WAIT;

		/* Set command retry send flag */
		scf_comtbl.scf_cmd_resend_req |= RESEND_SHUT;
		break;

	case EVENT_SUB_EXEC:
		scf_comtbl.scf_shut_event_sub = EVENT_SUB_WAIT;

		/* Set command retry send flag */
		scf_comtbl.scf_cmd_resend_req |= RESEND_SHUT;
		break;

	default:
		break;
	}

	switch (scf_comtbl.scf_alive_event_sub) {
	case EVENT_SUB_ALST_EXEC:
		scf_comtbl.scf_alive_event_sub = EVENT_SUB_ALST_WAIT;

		/* Set command retry send flag */
		scf_comtbl.scf_cmd_resend_req |= RESEND_ALST;
		break;

	case EVENT_SUB_ALSP_EXEC:
		scf_comtbl.scf_alive_event_sub = EVENT_SUB_ALSP_WAIT;

		/* Set command retry send flag */
		scf_comtbl.scf_cmd_resend_req |= RESEND_ALSP;
		break;

	default:
		break;
	}

	switch (scf_comtbl.scf_report_event_sub) {
	case EVENT_SUB_REPORT_RUN_EXEC:
		scf_comtbl.scf_report_event_sub = EVENT_SUB_REPORT_RUN_WAIT;

		/* Set command retry send flag */
		scf_comtbl.scf_cmd_resend_req |= RESEND_REPORT_RUN;
		break;

	case EVENT_SUB_REPORT_SHOT_EXEC:
		scf_comtbl.scf_report_event_sub = EVENT_SUB_REPORT_SHUT_WAIT;

		/* Set command retry send flag */
		scf_comtbl.scf_cmd_resend_req |= RESEND_REPORT_SHUT;
		break;

	default:
		break;
	}

	/* Set command wait status */
	if (scf_comtbl.scf_domain_event_sub == EVENT_SUB_DOMAIN_EXEC) {
		scf_comtbl.scf_domain_event_sub = EVENT_SUB_DOMAIN_WAIT;

		/* Set command retry send flag */
		scf_comtbl.scf_cmd_resend_req |= RESEND_DOMAIN;
	}

	if (scf_comtbl.scf_cmd_exec_flag) {
		if (scf_comtbl.cmd_end_wait) {
			/* Set command retry send flag */
			scf_comtbl.scf_cmd_resend_req |= RESEND_IOCTL;
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_SYS, SCF_FUNC_NAME ": end");
}
