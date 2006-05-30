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
#include <sys/scfd/scfdscp.h>

/*
 * Timer control table and control flag
 */
static int	scf_timer_stop_flag = FLAG_OFF;	/* Timer stop flag */
scf_timer_t	scf_timer[SCF_TIMERCD_MAX];	/* Timer contorol table */

/*
 * Timer value
 */
	/* SCF command busy watch timer */
int	scf_devbusy_wait_time	= SCF_TIMER_VALUE_DEVBUSY;
	/* SCF command completion watch timer */
int	scf_cmdend_wait_time	= SCF_TIMER_VALUE_CMDEND;
	/* SCF online watch timer */
int	scf_online_wait_time	= SCF_TIMER_VALUE_ONLINE;
	/* Next receive wait timer */
int	scf_rxbuff_wait_time	= SCF_TIMER_VALUE_NEXTRCV;
	/* DSCP interface TxACK watch timer */
int	scf_dscp_ack_wait_time	= SCF_TIMER_VALUE_DSCP_ACK;
	/* DSCP interface TxEND watch timer */
int	scf_dscp_end_wait_time	= SCF_TIMER_VALUE_DSCP_END;
	/* DSCP interface busy watch timer */
int	scf_dscp_txbusy_time	= SCF_TIMER_VALUE_DSCP_BUSY;
	/* DSCP interface callback timer */
int	scf_dscp_callback_time	= SCF_TIMER_VALUE_DSCP_CALLBACK;
	/* DSCP INIT_REQ retry timer */
int	scf_dscp_init_time	= SCF_TIMER_VALUE_DSCP_INIT;

/*
 * Function list
 */
void	scf_timer_init(void);
void	scf_timer_start(int tmcd);
void	scf_timer_stop(int tmcd);
void	scf_timer_all_stop(void);
int	scf_timer_check(int tmcd);
uint32_t	scf_timer_value_get(int tmcd);
void	scf_tout(void *arg);
int	scf_timer_stop_collect(timeout_id_t *tmids, int size);
void	scf_timer_untimeout(timeout_id_t *tmids, int size);

/*
 * External function
 */
extern void	scf_cmdbusy_tout(void);
extern void	scf_cmdend_tout(void);
extern void	scf_online_wait_tout(void);
extern void	scf_next_rxdata_get(void);
extern void	scf_dscp_ack_tout(void);
extern void	scf_dscp_end_tout(void);
extern void	scf_dscp_busy_tout(void);
extern void	scf_dscp_callback_tout(void);
extern void	scf_report_send_wait_tout(void);
extern void	scf_dscp_init_tout(uint8_t id);

/*
 * scf_timer_init()
 *
 * Description: Timer initialization processing.
 *
 */
void
scf_timer_init(void)
{
#define	SCF_FUNC_NAME		"scf_timer_init() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": start");

	/* Set timer code and timer value */
	scf_timer[SCF_TIMERCD_CMDBUSY].value = scf_devbusy_wait_time;
	scf_timer[SCF_TIMERCD_CMDBUSY].tbl[0].code = SCF_TIMERCD_CMDBUSY;
	scf_timer[SCF_TIMERCD_CMDBUSY].tbl[1].code = SCF_TIMERCD_CMDBUSY;

	scf_timer[SCF_TIMERCD_CMDEND].value = scf_cmdend_wait_time;
	scf_timer[SCF_TIMERCD_CMDEND].tbl[0].code = SCF_TIMERCD_CMDEND;
	scf_timer[SCF_TIMERCD_CMDEND].tbl[1].code = SCF_TIMERCD_CMDEND;

	scf_timer[SCF_TIMERCD_ONLINE].value = scf_online_wait_time;
	scf_timer[SCF_TIMERCD_ONLINE].tbl[0].code = SCF_TIMERCD_ONLINE;
	scf_timer[SCF_TIMERCD_ONLINE].tbl[1].code = SCF_TIMERCD_ONLINE;

	scf_timer[SCF_TIMERCD_NEXTRECV].value = scf_rxbuff_wait_time;
	scf_timer[SCF_TIMERCD_NEXTRECV].tbl[0].code = SCF_TIMERCD_NEXTRECV;
	scf_timer[SCF_TIMERCD_NEXTRECV].tbl[1].code = SCF_TIMERCD_NEXTRECV;

	scf_timer[SCF_TIMERCD_DSCP_ACK].value = scf_dscp_ack_wait_time;
	scf_timer[SCF_TIMERCD_DSCP_ACK].tbl[0].code = SCF_TIMERCD_DSCP_ACK;
	scf_timer[SCF_TIMERCD_DSCP_ACK].tbl[1].code = SCF_TIMERCD_DSCP_ACK;

	scf_timer[SCF_TIMERCD_DSCP_END].value = scf_dscp_end_wait_time;
	scf_timer[SCF_TIMERCD_DSCP_END].tbl[0].code = SCF_TIMERCD_DSCP_END;
	scf_timer[SCF_TIMERCD_DSCP_END].tbl[1].code = SCF_TIMERCD_DSCP_END;

	scf_timer[SCF_TIMERCD_DSCP_BUSY].value = scf_dscp_txbusy_time;
	scf_timer[SCF_TIMERCD_DSCP_BUSY].tbl[0].code = SCF_TIMERCD_DSCP_BUSY;
	scf_timer[SCF_TIMERCD_DSCP_BUSY].tbl[1].code = SCF_TIMERCD_DSCP_BUSY;

	scf_timer[SCF_TIMERCD_DSCP_CALLBACK].value = scf_dscp_callback_time;
	scf_timer[SCF_TIMERCD_DSCP_CALLBACK].tbl[0].code =
		SCF_TIMERCD_DSCP_CALLBACK;
	scf_timer[SCF_TIMERCD_DSCP_CALLBACK].tbl[1].code =
		SCF_TIMERCD_DSCP_CALLBACK;

	scf_timer[SCF_TIMERCD_BUF_FUL].value = scf_buf_ful_rtime;
	scf_timer[SCF_TIMERCD_BUF_FUL].tbl[0].code = SCF_TIMERCD_BUF_FUL;
	scf_timer[SCF_TIMERCD_BUF_FUL].tbl[1].code = SCF_TIMERCD_BUF_FUL;

	scf_timer[SCF_TIMERCD_RCI_BUSY].value = scf_rci_busy_rtime;
	scf_timer[SCF_TIMERCD_RCI_BUSY].tbl[0].code = SCF_TIMERCD_RCI_BUSY;
	scf_timer[SCF_TIMERCD_RCI_BUSY].tbl[1].code = SCF_TIMERCD_RCI_BUSY;

	scf_timer[SCF_TIMERCD_DSCP_INIT].value = scf_dscp_init_time;
	scf_timer[SCF_TIMERCD_DSCP_INIT].tbl[0].code = SCF_TIMERCD_DSCP_INIT;
	scf_timer[SCF_TIMERCD_DSCP_INIT].tbl[1].code = SCF_TIMERCD_DSCP_INIT;

	scf_timer[SCF_TIMERCD_DKMD_INIT].value = scf_dscp_init_time;
	scf_timer[SCF_TIMERCD_DKMD_INIT].tbl[0].code = SCF_TIMERCD_DKMD_INIT;
	scf_timer[SCF_TIMERCD_DKMD_INIT].tbl[1].code = SCF_TIMERCD_DKMD_INIT;

	SCFDBGMSG(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": end");
}


/*
 * scf_timer_start()
 *
 * Description: Timer start subroutine.
 *
 */
void
scf_timer_start(int tmcd)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_timer_start() "
	scf_timer_t		*tm_p;		/* Timer table address */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": start tmcd = %d", tmcd);

	/* Check timer code */
	if (tmcd >= SCF_TIMERCD_MAX) {
		goto END_timer_start;
	}

	/* Get timer table address */
	tm_p = &scf_timer[tmcd];

	/* Check timer value and timer start flag */
	if ((tm_p->value == 0) || (tm_p->start == FLAG_ON)) {
		goto END_timer_start;
	}

	/* Check timer stop flag */
	if (tm_p->stop == FLAG_OFF) {
		/*
		 * Timer start and judgment
		 */
		/* Change timer table side */
		tm_p->side = (tm_p->side == 0) ? 1 : 0;

		/* timer start */
		tm_p->tbl[tm_p->side].id = timeout(scf_tout,
			&tm_p->tbl[tm_p->side],
			drv_usectohz(SCF_MIL2MICRO(tm_p->value)));

		/* Timer start flag ON */
		tm_p->start = FLAG_ON;

		SC_DBG_DRV_TRACE(TC_T_START, __LINE__, &tmcd, sizeof (tmcd));
		SCFDBGMSG(SCF_DBGFLAG_TIMER, "timeout() call");
	} else {
		/*
		 * Timer restart and judgment
		 */
		SCFDBGMSG(SCF_DBGFLAG_TIMER, "timer restart");

		/* Check current table timer use */
		if (tm_p->tbl[tm_p->side].id != 0) {
			/* Change timer table side */
			tm_p->side = (tm_p->side == 0) ? 1 : 0;
		}

		/* Timer start and restart flag ON */
		tm_p->start = FLAG_ON;
		tm_p->restart = FLAG_ON;
	}

/*
 * END_timer_start
 */
	END_timer_start:

	SCFDBGMSG(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": end");
}


/*
 * scf_timer_stop()
 *
 * Description: Timer stop subroutine.
 *
 */
void
scf_timer_stop(int tmcd)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_timer_stop() "
	scf_timer_t		*tm_p;		/* Timer table address */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": start tmcd = %d", tmcd);

	/* Check timer code */
	if (tmcd < SCF_TIMERCD_MAX) {
		/* Get timer table address */
		tm_p = &scf_timer[tmcd];

		/* Check timer start flag */
		if (tm_p->start == FLAG_ON) {
			/*
			 * Timer start and judgment
			 */

			/* Timer start and restart flag OFF */
			tm_p->start = FLAG_OFF;
			tm_p->restart = FLAG_OFF;

			/* Timer stop flag ON */
			tm_p->stop = FLAG_ON;
			scf_timer_stop_flag = FLAG_ON;
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": end");
}


/*
 * scf_timer_all_stop()
 *
 * Description: Timer all stop subroutine.
 *
 */
void
scf_timer_all_stop(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_timer_all_stop() "
	int			tm_cd;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": start");

	for (tm_cd = 0; tm_cd < SCF_TIMERCD_MAX; tm_cd++) {
		scf_timer_stop(tm_cd);
	}

	SCFDBGMSG(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": end");
}


/*
 * scf_timer_check()
 *
 * Description: Timer status check subroutine.
 *
 */
int
scf_timer_check(int tmcd)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_timer_check() "
	scf_timer_t		*tm_p;		/* Timer table address */
	int			ret = SCF_TIMER_NOT_EXEC; /* Return value */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": start tmcd = %d", tmcd);

	/* Check timer code */
	if (tmcd < SCF_TIMERCD_MAX) {
		/* Get timer table address */
		tm_p = &scf_timer[tmcd];

		/* Check timer start flag */
		if (tm_p->start == FLAG_ON) {
			/* Timer exec state */
			ret = SCF_TIMER_EXEC;
		}
	}

	SCFDBGMSG1(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_timer_value_get()
 *
 * Description: Timer value get subroutine.
 *
 */
uint32_t
scf_timer_value_get(int tmcd)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_timer_value_get() "
	uint32_t		ret = 0;	/* Return value */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": start tmcd = %d", tmcd);

	/* Check timer code */
	if (tmcd < SCF_TIMERCD_MAX) {
		/* Set timer value */
		ret = scf_timer[tmcd].value;
	}

	SCFDBGMSG1(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_tout()
 *
 * Description: Timeout main processing.
 *
 */
void
scf_tout(void *arg)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_tout() "
	scf_timer_tbl_t		*tm_tblp = (scf_timer_tbl_t *)arg;
	scf_timer_t		*tm_p;		/* Timer table address */
	timeout_id_t		save_tmids[SCF_TIMERCD_MAX];
	int			tm_stop_cnt;

	SCFDBGMSG1(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": start tmcd = %d",
		tm_tblp->code);

	SC_DBG_DRV_TRACE(TC_T_TOUT | TC_IN, __LINE__, &tm_tblp->code,
		sizeof (tm_tblp->code));

	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	/* Get timer table address */
	tm_p = &scf_timer[tm_tblp->code];

	/* Check timer exec state */
	if ((tm_p->start == FLAG_ON) && (tm_tblp->id != 0) &&
		(tm_p->stop == FLAG_OFF)) {
		/* Timer flag OFF and timer id clear */
		tm_p->start = FLAG_OFF;
		tm_tblp->id = 0;

		/* Check timer code */
		switch (tm_tblp->code) {
		case SCF_TIMERCD_CMDBUSY:
			/* SCF command busy watch timeout */
			scf_cmdbusy_tout();
			break;

		case SCF_TIMERCD_CMDEND:
			/* SCF command completion watch timeout */
			scf_cmdend_tout();
			break;

		case SCF_TIMERCD_ONLINE:
			/* SCF online watch timeout */
			scf_online_wait_tout();
			break;

		case SCF_TIMERCD_NEXTRECV:
			/* Next receive wait timeout */
			scf_next_rxdata_get();
			break;

		case SCF_TIMERCD_DSCP_ACK:
			/* DSCP interface TxACK watch timeout */
			scf_dscp_ack_tout();
			break;

		case SCF_TIMERCD_DSCP_END:
			/* DSCP interface TxEND watch timeout */
			scf_dscp_end_tout();
			break;

		case SCF_TIMERCD_DSCP_BUSY:
			/* DSCP interface busy watch timeout */
			scf_dscp_busy_tout();
			break;

		case SCF_TIMERCD_DSCP_CALLBACK:
			/* DSCP interface callback timeout */
			scf_dscp_callback_tout();
			break;

		case SCF_TIMERCD_BUF_FUL:
			/* SCF command BUF_FUL timeout */
		case SCF_TIMERCD_RCI_BUSY:
			/* SCF command RCI_BUSY timeout */
			scf_report_send_wait_tout();
			break;

		case SCF_TIMERCD_DSCP_INIT:
			/* DSCP INIT_REQ retry timeout */
			scf_dscp_init_tout(MBIF_DSCP);
			break;

		case SCF_TIMERCD_DKMD_INIT:
			/* DKMD INIT_REQ retry timeout */
			scf_dscp_init_tout(MBIF_DKMD);
			break;

		default:
			/* NOP */
			break;
		}
	} else {
		/* Timer flag OFF and timer id clear */
		tm_p->stop = FLAG_OFF;
		tm_tblp->id = 0;

		/* Check timer restart flag */
		if (tm_p->restart == FLAG_ON) {
			/*
			 * Timer start and judgment
			 */
			/* timer start */
			tm_p->tbl[tm_p->side].id = timeout(scf_tout,
				&tm_p->tbl[tm_p->side],
				drv_usectohz(SCF_MIL2MICRO(tm_p->value)));

			/* Timer start flag is already ON */

			/* Timer restart flag OFF */
			tm_p->restart = FLAG_OFF;

			SC_DBG_DRV_TRACE(TC_T_START, __LINE__, &tm_tblp->code,
				sizeof (tm_tblp->code));
			SCFDBGMSG(SCF_DBGFLAG_TIMER, "timeout() call");
		}
	}

	/* Collect the timers which need to be stopped */
	tm_stop_cnt = scf_timer_stop_collect(save_tmids, SCF_TIMERCD_MAX);

	/* Unlock driver mutex */
	mutex_exit(&scf_comtbl.all_mutex);

	/* Timer stop */
	if (tm_stop_cnt != 0) {
		scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
	}

	SC_DBG_DRV_TRACE(TC_T_TOUT | TC_OUT, __LINE__, NULL, 0);
	SCFDBGMSG(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": end");
}


/*
 * scf_timer_stop_collect()
 *
 * Description:  Collect the timers which need to be stopped.
 *
 */
int
scf_timer_stop_collect(timeout_id_t *tmids, int size)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_timer_stop_collect() "
	scf_timer_t		*tm_p;	/* Timer table address */
	int			ii;		/* Working value : counter */
	int			tm_stop_cnt = 0; /* Timer stop counter */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": start");

	/* Clear save timer table */
	bzero((caddr_t)tmids, (sizeof (timeout_id_t) * size));

	/* Check timer stop factor */
	if (scf_timer_stop_flag == FLAG_OFF) {
		goto END_timer_stop_collect;
	}

	/* Timer stop flag OFF */
	scf_timer_stop_flag = FLAG_OFF;

	/* Get timer table address */
	tm_p = &scf_timer[0];

	/* Check all timer table */
	for (ii = 0; ii < size; ii++, tm_p++) {
		/* Check timer stop flag */
		if (tm_p->stop == FLAG_ON) {
			/* Timer stop flag OFF */
			tm_p->stop = FLAG_OFF;

			/* Check timer side 0 table timer use */
			if (tm_p->tbl[0].id != 0) {
				/* Save stop timer id */
				tmids[tm_stop_cnt++] = tm_p->tbl[0].id;

				/* Timer id clear */
				tm_p->tbl[0].id = 0;

				SC_DBG_DRV_TRACE(TC_T_STOP, __LINE__, &ii,
					sizeof (ii));
			}

			/* Check timer side 1 table timer use */
			if (tm_p->tbl[1].id != 0) {
				/* Save stop timer id */
				tmids[tm_stop_cnt++] = tm_p->tbl[1].id;

				/* Timer id clear */
				tm_p->tbl[1].id = 0;

				SC_DBG_DRV_TRACE(TC_T_STOP, __LINE__, &ii,
					sizeof (ii));
			}
		}
		/* Check timer restart flag */
		if (tm_p->restart == FLAG_ON) {
			/*
			 * Timer start and judgment
			 */

			/* timer start */
			tm_p->tbl[tm_p->side].id = timeout(scf_tout,
				&tm_p->tbl[tm_p->side],
				drv_usectohz(SCF_MIL2MICRO(tm_p->value)));

			/* Timer start flag ON */
			tm_p->restart = FLAG_OFF;

			SC_DBG_DRV_TRACE(TC_T_START, __LINE__, &ii,
				sizeof (ii));
		}
	}

/*
 * END_timer_stop_collect
 */
	END_timer_stop_collect:

	SCFDBGMSG1(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": end tm_stop_cnt = %d",
		tm_stop_cnt);
	return (tm_stop_cnt);
}


/*
 * scf_timer_untimeout()
 *
 * Description: Timer stop subroutine.
 *
 */
void
scf_timer_untimeout(timeout_id_t *tmids, int size)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_timer_untimeout() "
	int			ii;		/* Working value : counter */

	SCFDBGMSG(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": start");

	/* Save timer id stop */
	for (ii = 0; ii < size; ii++) {
		if (tmids[ii] != 0) {
			(void) untimeout(tmids[ii]);
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_TIMER, SCF_FUNC_NAME ": end");
}
