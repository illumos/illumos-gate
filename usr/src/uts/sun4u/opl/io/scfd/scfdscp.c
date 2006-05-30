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
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scfd/scfparam.h>
#include <sys/scfd/scfdscp.h>

/*
 * DSCP control table
 */
scf_dscp_comtbl_t scf_dscp_comtbl;	/* DSCP control table */

mkey_t 	scf_dscp_mkey_search[] = {
	DSCP_KEY,			/* DSCP mailbox interface key */
	DKMD_KEY			/* DKMD mailbox interface key */
					/* Add mailbox key */
};

/*
 * SCF driver system control intafece function
 */
void	scf_dscp_init(void);
void	scf_dscp_fini(void);
void	scf_dscp_start(uint32_t factor);
void	scf_dscp_stop(uint32_t factor);
void	scf_dscp_intr(scf_state_t *statep);

/*
 * Timeout function : from SCF driver timer contorol function
 */
void	scf_dscp_ack_tout(void);
void	scf_dscp_end_tout(void);
void	scf_dscp_busy_tout(void);
void	scf_dscp_callback_tout(void);
void	scf_dscp_callback(void);
void	scf_dscp_init_tout(uint8_t id);

/*
 * Interrupt function : from scf_dscp_intr()
 */
void	scf_dscp_txack_recv(scf_state_t *statep);
void	scf_dscp_txend_recv(scf_state_t *statep);
void	scf_dscp_rxreq_recv(scf_state_t *statep);

/*
 * Main and Tx/Rx interface function
 */
void	scf_dscp_txend_notice(scf_dscp_main_t *mainp);
void	scf_dscp_txrelbusy_notice(scf_dscp_main_t *mainp);
void	scf_dscp_rxreq_notice(scf_dscp_main_t *mainp);
void	scf_dscp_rxdata_notice(scf_dscp_main_t *mainp);

/*
 * Tx subroutine function
 */
void	scf_dscp_send_matrix(void);
void	scf_dscp_txreq_send(scf_state_t *statep, scf_dscp_dsc_t *dsc_p);

/*
 * Rx subroutine function
 */
void	scf_dscp_recv_matrix(void);
void	scf_dscp_rxack_send(scf_state_t *statep);
void	scf_dscp_rxend_send(scf_state_t *statep, scf_dscp_dsc_t *dsc_p);

/*
 * subroutine function
 */
void	scf_dscp_dscbuff_free_all(void);
void	scf_dscp_txdscbuff_free(scf_dscp_main_t *mainp);
void	scf_dscp_rxdscbuff_free(scf_dscp_main_t *mainp);
void	scf_dscp_rdata_free(scf_dscp_main_t *mainp);
void	scf_dscp_event_queue(scf_dscp_main_t *mainp, scf_event_t mevent);
void	scf_dscp_event_queue_free(scf_dscp_main_t *mainp);
scf_dscp_main_t	*scf_dscp_mkey2mainp(mkey_t mkey);
scf_dscp_main_t	*scf_dscp_id2mainp(uint8_t id);
uint16_t	scf_dscp_sram_get(void);
void	scf_dscp_sram_free(uint16_t offset);


/*
 * DSCP Driver interface function
 */

/*
 * scf_mb_init()
 *
 * Description: Initialize the mailbox and register a callback for receiving
 *		events related to the specified mailbox.
 * Arguments:
 *
 * target_id	- The target_id of the peer. It must be 0 on a Domain.
 * mkey		- mailbox key
 * event_handler- handler to be called for all events related
 *		  to a mailbox. It should be called back with
 *		  the event type and the registered argument.
 *
 * arg		- A callback argument to be passed back to the
 *		  event_handler.
 *
 * Return Values: returns 0 on success, otherwise any meaningful errno
 *		  values are returned, some of the notable error values
 *		  are given below.
 * EINVAL	- Invalid values.
 * EEXIST	- Already OPEN.
 * EIO		- DSCP I/F path not available.
 */
int
scf_mb_init(target_id_t target_id, mkey_t mkey,
	void (*event_handler) (scf_event_t mevent, void *arg), void *arg)
{
#define	SCF_FUNC_NAME		"scf_mb_init() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */
	int			path_ret; /* SCF path status return value */
	int			ret = 0;	/* Return value */
	timeout_id_t		save_tmids[SCF_TIMERCD_MAX];
	int			tm_stop_cnt;

	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start mkey = 0x%08x",
		mkey);
	SC_DBG_DRV_TRACE(TC_MB_INIT | TC_IN, __LINE__, &mkey, sizeof (mkey));

	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	/* Check target_id */
	if (target_id != 0) {
		/* Invalid "target_id" */
		SC_DBG_DRV_TRACE(TC_MB_INIT | TC_ERRCD, __LINE__, &target_id,
			sizeof (target_id));
		ret = EINVAL;
		goto END_mb_init;
	}

	/* Get main table address from "mkey" */
	mainp = scf_dscp_mkey2mainp(mkey);

	/* Check mainp address */
	if (mainp == NULL) {
		/* Invalid "mkey" */
		SC_DBG_DRV_TRACE(TC_MB_INIT | TC_ERRCD, __LINE__, &mkey,
			sizeof (mkey));
		ret = EINVAL;
		goto END_mb_init;
	}

	/* Check "event_handler" address */
	if (event_handler == NULL) {
		/* Invalid "event_handler" */
		SC_DBG_DRV_TRACE(TC_MB_INIT | TC_ERRCD, __LINE__,
			&event_handler, sizeof (event_handler));
		ret = EINVAL;
		goto END_mb_init;
	}

	/* Get SCF path status */
	path_ret = scf_path_check(NULL);

	/* Check SCF path status */
	if (path_ret == SCF_PATH_HALT) {
		/* SCF path status is halt */
		SC_DBG_DRV_TRACE(TC_MB_INIT | TC_ERRCD, __LINE__, &path_ret,
			sizeof (path_ret));
		ret = EIO;
		goto END_mb_init;
	}

	/* Check main status */
	if (mainp->status != SCF_ST_IDLE) {
		/* Main status != A0 */
		SC_DBG_DRV_TRACE(TC_MB_INIT | TC_ERRCD, __LINE__,
			&mainp->status, sizeof (mainp->status));
		ret = EEXIST;
		goto END_mb_init;
	}

	/* Initialize flag */
	mainp->conn_chk_flag = FLAG_OFF;
	mainp->putmsg_busy_flag = FLAG_OFF;

	/* Get TxDSC address */
	dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_put];

	/* Make Tx descriptor : INIT_REQ */
	dsc_p->dinfo.base.c_flag = DSC_FLAG_DEFAULT;
	dsc_p->dinfo.base.offset = DSC_OFFSET_NOTHING;
	dsc_p->dinfo.base.length = 0;
	dsc_p->dinfo.base.dscp_datap = NULL;
	dsc_p->dinfo.bdcr.id = mainp->id & DSC_CNTL_MASK_ID;
	dsc_p->dinfo.bdcr.code = DSC_CNTL_INIT_REQ;

	/* Update Tx descriptor offset */
	if (scf_dscp_comtbl.tx_put == scf_dscp_comtbl.tx_last) {
		scf_dscp_comtbl.tx_put = scf_dscp_comtbl.tx_first;
	} else {
		scf_dscp_comtbl.tx_put++;
	}

	/* Update Tx descriptor count */
	scf_dscp_comtbl.tx_dsc_count++;

	/* Change TxDSC status (SB2) */
	SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_TXREQ_SEND_WAIT);

	/* Call send matrix */
	scf_dscp_send_matrix();

	/* Change main status (B0) */
	SCF_SET_STATUS(mainp, SCF_ST_EST_TXEND_RECV_WAIT);

	/* Save parameter */
	mainp->event_handler = event_handler;
	mainp->arg = arg;
	mainp->target_id = target_id;
	mainp->mkey = mkey;

/*
 * END_mb_init
 */
	END_mb_init:

	/* Collect the timers which need to be stopped */
	tm_stop_cnt = scf_timer_stop_collect(save_tmids, SCF_TIMERCD_MAX);

	/* Unlock driver mutex */
	mutex_exit(&scf_comtbl.all_mutex);

	/* Timer stop */
	if (tm_stop_cnt != 0) {
		scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
	}

	SC_DBG_DRV_TRACE(TC_MB_INIT | TC_OUT, __LINE__, &ret, sizeof (ret));
	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_mb_fini()
 *
 * Description: Cleanup the mailbox and unregister an event_handler,
 *		if it is registered.
 *
 * target_id	- The target_id of the peer. It must be 0 on a Domain.
 * mkey		- mailbox key
 *
 * Return Values: returns 0 on success, otherwise any meaningful errno
 *		  values are returned, some of the notable error values
 *		  are given below.
 * EINVAL	- Invalid values.
 * EBADF	- Specified target_id is not OPEN.
 */
int
scf_mb_fini(target_id_t target_id, mkey_t mkey)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_mb_fini() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */
	int			path_ret; /* SCF path status return value */
	int			ret = 0;	/* Return value */
	timeout_id_t		save_tmids[SCF_TIMERCD_MAX];
	int			tm_stop_cnt;

	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start mkey = 0x%08x",
		mkey);
	SC_DBG_DRV_TRACE(TC_MB_FINI | TC_IN, __LINE__, &mkey, sizeof (mkey));

	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	/* Check target_id */
	if (target_id != 0) {
		/* Invalid "target_id" */
		SC_DBG_DRV_TRACE(TC_MB_FINI | TC_ERRCD, __LINE__, &target_id,
			sizeof (target_id));
		ret = EINVAL;
		goto END_mb_fini;
	}

	/* Get main table address from "mkey" */
	mainp = scf_dscp_mkey2mainp(mkey);

	/* Check mainp address */
	if (mainp == NULL) {
		/* Invalid "mkey" */
		SC_DBG_DRV_TRACE(TC_MB_FINI | TC_ERRCD, __LINE__, &mkey,
			sizeof (mkey));
		ret = EINVAL;
		goto END_mb_fini;
	}

	/* Get SCF path status */
	path_ret = scf_path_check(NULL);

	/* Check SCF path status */
	if (path_ret == SCF_PATH_HALT) {
		/* SCF path status is halt */
		if (mainp->status != SCF_ST_IDLE) {
			/* TxDSC buffer release */
			scf_dscp_txdscbuff_free(mainp);

			/* RxDSC buffer release */
			scf_dscp_rxdscbuff_free(mainp);

			/* All queing event release */
			scf_dscp_event_queue_free(mainp);

			/* All receive buffer release */
			scf_dscp_rdata_free(mainp);

			/* event_handler and arg NULL */
			mainp->event_handler = NULL;
			mainp->arg = NULL;

			/* Change main status (A0) */
			SCF_SET_STATUS(mainp, SCF_ST_IDLE);
		}
		goto END_mb_fini;
	}

	/* Check main status */
	switch (mainp->status) {
	case SCF_ST_EST_TXEND_RECV_WAIT:	/* Main status (B0) */
	case SCF_ST_ESTABLISHED:		/* Main status (C0) */
		/* Get TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_put];

		/* Make Tx descriptor : FINI_REQ */
		dsc_p->dinfo.base.c_flag = DSC_FLAG_DEFAULT;
		dsc_p->dinfo.base.offset = DSC_OFFSET_NOTHING;
		dsc_p->dinfo.base.length = 0;
		dsc_p->dinfo.base.dscp_datap = NULL;
		dsc_p->dinfo.bdcr.id = mainp->id & DSC_CNTL_MASK_ID;
		dsc_p->dinfo.bdcr.code = DSC_CNTL_FINI_REQ;

		/* Update Tx descriptor offset */
		if (scf_dscp_comtbl.tx_put == scf_dscp_comtbl.tx_last) {
			scf_dscp_comtbl.tx_put = scf_dscp_comtbl.tx_first;
		} else {
			scf_dscp_comtbl.tx_put++;
		}

		/* Update Tx descriptor count */
		scf_dscp_comtbl.tx_dsc_count++;

		/* Change TxDSC status (SB2) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_TXREQ_SEND_WAIT);

		/* Call send matrix */
		scf_dscp_send_matrix();

		/* Change main status (D0) */
		SCF_SET_STATUS(mainp, SCF_ST_CLOSE_TXEND_RECV_WAIT);

		/* INIT_REQ retry timer stop */
		scf_timer_stop(mainp->timer_code);

		/* TxEND(FINI) receive wait */
		SC_DBG_DRV_TRACE(TC_W_SIG, __LINE__, &mainp->fini_cv,
			sizeof (kcondvar_t));
		mainp->fini_wait_flag = FLAG_ON;
		while (mainp->fini_wait_flag == FLAG_ON) {
			cv_wait(&mainp->fini_cv, &scf_comtbl.all_mutex);
		}

		/* TxDSC buffer release */
		scf_dscp_txdscbuff_free(mainp);

		/* RxDSC buffer release */
		scf_dscp_rxdscbuff_free(mainp);

		/* All queing event release */
		scf_dscp_event_queue_free(mainp);

		/* All receive buffer release */
		scf_dscp_rdata_free(mainp);

		/* event_handler and arg NULL */
		mainp->event_handler = NULL;
		mainp->arg = NULL;

		/* Change main status (A0) */
		SCF_SET_STATUS(mainp, SCF_ST_IDLE);
		break;

	case SCF_ST_EST_FINI_WAIT:		/* Main status (C1) */
		/* TxDSC buffer release */
		scf_dscp_txdscbuff_free(mainp);

		/* RxDSC buffer release */
		scf_dscp_rxdscbuff_free(mainp);

		/* All queing event release */
		scf_dscp_event_queue_free(mainp);

		/* All receive buffer release */
		scf_dscp_rdata_free(mainp);

		/* event_handler and arg NULL */
		mainp->event_handler = NULL;
		mainp->arg = NULL;

		/* Change main status (A0) */
		SCF_SET_STATUS(mainp, SCF_ST_IDLE);
		break;

	case SCF_ST_IDLE:			/* Main status (A0) */
		/* Main status == A0 is NOP */
		break;

	default:
		/* Not open */
		SC_DBG_DRV_TRACE(TC_MB_FINI | TC_ERRCD, __LINE__,
			&mainp->status, TC_INFO_SIZE);
		ret = EBADF;
		break;
	}

/*
 * END_mb_fini
 */
	END_mb_fini:

	/* Collect the timers which need to be stopped */
	tm_stop_cnt = scf_timer_stop_collect(save_tmids, SCF_TIMERCD_MAX);

	/* Unlock driver mutex */
	mutex_exit(&scf_comtbl.all_mutex);

	/* Timer stop */
	if (tm_stop_cnt != 0) {
		scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
	}

	SC_DBG_DRV_TRACE(TC_MB_FINI | TC_OUT, __LINE__, &ret, sizeof (ret));
	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_mb_putmsg()
 *
 * Description: Send a message via the mailbox identified by mkey. The message
 *		need to	be sent either completely or none. That is, no partial
 *		messages should be sent.
 *
 *		If a 0 timeout value is specified, then it should act as
 *		a non-blocking interface, that is, it should either send
 *		the message immediately or return appropriate error.
 *		If a timeout value is specified, then it can blocked
 *		until either the message is sent successfully or timedout.
 *
 * Arguments:
 *
 * target_id	- The target_id of the peer. It must be 0 on a Domain.
 * mkey		- Unique key corresponding to a mailbox.
 * data_len	- Total length of the data to be sent.
 * num_sg	- Number of scatter/gather elements in the argument sgp.
 * sgp		- Scatter/gather list pointer.
 * timeout	- timeout value in milliseconds. If 0 specified, no waiting
 *		  is required.
 *
 * Return Values: returns 0 on success, otherwise any meaningful errno
 *		  values are returned, some of the notable error values
 *		  are given below.
 *
 * EINVAL	- Invalid values.
 * EBADF	- Specified target_id is not OPEN.
 * EBUSY	- Driver is BUSY.
 * ENOSPC	- Not enough space to send the message.
 * EIO		- DSCP I/F path not available.
 */
/* ARGSUSED */
int
scf_mb_putmsg(target_id_t target_id, mkey_t mkey, uint32_t data_len,
	uint32_t num_sg, mscat_gath_t *sgp, clock_t timeout)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_mb_putmsg() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	scf_dscp_dsc_t		*dsc_p;		/* Current TxDSC address */
	caddr_t			wkaddr;	/* Working value : buffer address */
	uint32_t		wkleng = 0;	/* Working value : length */
	uint32_t		wkoffset; /* Working value : Tx SRAM offset */
	int			ii;		/* Working value : counter */
	int			path_ret; /* SCF path status return value */
	int			ret = 0;	/* Return value */
	timeout_id_t		save_tmids[SCF_TIMERCD_MAX];
	int			tm_stop_cnt;

	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start mkey = 0x%08x",
		mkey);
	SC_DBG_DRV_TRACE(TC_MB_PUTMSG | TC_IN, __LINE__, &mkey, sizeof (mkey));

	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	/* Check target_id */
	if (target_id != 0) {
		/* Invalid "target_id" */
		SC_DBG_DRV_TRACE(TC_MB_PUTMSG | TC_ERRCD, __LINE__, &target_id,
			sizeof (target_id));
		ret = EINVAL;
		goto END_mb_putmsg;
	}

	/* Get main table address from "mkey" */
	mainp = scf_dscp_mkey2mainp(mkey);

	/* Check mainp address */
	if (mainp == NULL) {
		/* Invalid "mkey" */
		SC_DBG_DRV_TRACE(TC_MB_PUTMSG | TC_ERRCD, __LINE__, &mkey,
			sizeof (mkey));
		ret = EINVAL;
		goto END_mb_putmsg;
	}

	/* Get SCF path status */
	path_ret = scf_path_check(NULL);

	/* Check SCF path status */
	if (path_ret == SCF_PATH_HALT) {
		/* SCF path status halt */
		SC_DBG_DRV_TRACE(TC_MB_PUTMSG | TC_ERRCD, __LINE__, &path_ret,
			sizeof (path_ret));
		ret = EIO;
		goto END_mb_putmsg;
	}

	/* Check main status */
	switch (mainp->status) {
	case SCF_ST_ESTABLISHED:		/* Main status (C0) */
		/* Check "data_len" is "maxdatalen" */
		if (data_len > scf_dscp_comtbl.maxdatalen) {
			/* Invalid "data_len" */
			SC_DBG_DRV_TRACE(TC_MB_PUTMSG | TC_ERRCD, __LINE__,
				&data_len, sizeof (data_len));
			ret = EINVAL;
			goto END_mb_putmsg;
		}

		/* Check "data_len" is 0 */
		if (data_len == 0) {
			goto END_mb_putmsg;
		}

		/*
		 * Check "num_sg" is not 0, and "sgp" is not NULL
		 */
		if ((num_sg == 0) || (sgp == NULL)) {
			/* Invalid "num_sg" or "sgp" */
			SC_DBG_DRV_TRACE(TC_MB_PUTMSG | TC_ERRCD, __LINE__,
				&num_sg, sizeof (num_sg));
			ret = EINVAL;
			goto END_mb_putmsg;
		}

		/* Get total data length : "num_sg" */
		for (ii = 0; ii < num_sg; ii++) {
			if ((sgp[ii].msc_len == 0) ||
				(sgp[ii].msc_dptr != NULL)) {
				/*
				 * Add total data length
				 */
				wkleng += sgp[ii].msc_len;
			} else {
				/* Invalid "sgp" */
				SC_DBG_DRV_TRACE(TC_MB_PUTMSG | TC_ERRCD,
					__LINE__, &ii, sizeof (ii));
				ret = EINVAL;
				goto END_mb_putmsg;
			}
		}

		/*
		 * Check "data_len" and "wkleng"
		 */
		if (data_len != wkleng) {
			/* Invalid "data_len" */
			SC_DBG_DRV_TRACE(TC_MB_PUTMSG | TC_ERRCD, __LINE__,
				&data_len, sizeof (data_len));
			ret = EINVAL;
			goto END_mb_putmsg;
		}

		/*
		 * Check Tx SRAM space
		 */
		if (scf_dscp_comtbl.tx_dsc_count >=
			scf_dscp_comtbl.txdsc_busycount) {
			/* No space of Tx SRAM */
			SC_DBG_DRV_TRACE(TC_MB_PUTMSG | TC_ERRCD, __LINE__,
				&scf_dscp_comtbl.tx_dsc_count,
				sizeof (scf_dscp_comtbl.tx_dsc_count));

			/* putmsg ENOSPC counter up */
			mainp->memo_putmsg_enospc_cnt++;

			mainp->putmsg_busy_flag = FLAG_ON;
			ret = ENOSPC;
			goto END_mb_putmsg;
		}

		/* Tx buffer allocation */
		wkaddr = (caddr_t)kmem_zalloc(wkleng, KM_SLEEP);

		/* Get Tx SRAM offset */
		wkoffset = scf_dscp_sram_get();
		/* Check Tx SRAM offset */
		if (wkoffset == TX_SRAM_GET_ERROR) {
			/* Tx SRAM offset failure */
			SC_DBG_DRV_TRACE(TC_MB_PUTMSG | TC_ERRCD, __LINE__,
				&wkoffset, sizeof (wkoffset));

			/* Send data release */
			kmem_free(wkaddr, wkleng);

			/* putmsg busy counter up */
			mainp->memo_putmsg_busy_cnt++;

			ret = EBUSY;
			goto END_mb_putmsg;
		}

		/* Get TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_put];

		/* Make Tx descriptor : DATA_REQ */
		dsc_p->dinfo.base.c_flag = DSC_FLAG_DEFAULT;
		dsc_p->dinfo.base.offset = (uint16_t)wkoffset;
		dsc_p->dinfo.base.length = wkleng;
		dsc_p->dinfo.base.dscp_datap = wkaddr;
		dsc_p->dinfo.bdcr.id = mainp->id & DSC_CNTL_MASK_ID;
		dsc_p->dinfo.bdcr.code = DSC_CNTL_DATA_REQ;

		/* Data copy to Tx buffer */
		for (ii = 0; ii < num_sg; ii++) {
			if (sgp[ii].msc_len != 0) {
				bcopy(sgp[ii].msc_dptr, wkaddr,
					sgp[ii].msc_len);
				wkaddr += sgp[ii].msc_len;
			}
		}

		/* Update Tx descriptor offset */
		if (scf_dscp_comtbl.tx_put == scf_dscp_comtbl.tx_last) {
			scf_dscp_comtbl.tx_put = scf_dscp_comtbl.tx_first;
		} else {
			scf_dscp_comtbl.tx_put++;
		}

		/* Update Tx descriptor count */
		scf_dscp_comtbl.tx_dsc_count++;

		/* Change TxDSC status (SB0) */
		SCF_SET_DSC_STATUS(dsc_p,
			SCF_TX_ST_SRAM_TRANS_WAIT);

		/* Call send matrix */
		scf_dscp_send_matrix();

		/* Tx DATA_REQ counter */
		mainp->memo_tx_data_req_cnt++;
		break;

	case SCF_ST_EST_FINI_WAIT:		/* Main status (C1) */
		/* Main status == C1 is NOP */
		break;

	default:
		/* Not open */
		SC_DBG_DRV_TRACE(TC_MB_PUTMSG | TC_ERRCD, __LINE__,
			&mainp->status, TC_INFO_SIZE);
		ret = EBADF;
		break;
	}

/*
 * END_mb_putmsg
 */
	END_mb_putmsg:

	/* Collect the timers which need to be stopped */
	tm_stop_cnt = scf_timer_stop_collect(save_tmids, SCF_TIMERCD_MAX);

	/* Unlock driver mutex */
	mutex_exit(&scf_comtbl.all_mutex);

	/* Timer stop */
	if (tm_stop_cnt != 0) {
		scf_timer_untimeout(save_tmids, SCF_TIMERCD_MAX);
	}

	SC_DBG_DRV_TRACE(TC_MB_PUTMSG | TC_OUT, __LINE__, &ret, sizeof (ret));
	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_mb_canget()
 *
 * Description:	Checks if a message received in the specified mailbox.
 *		If there is a message received, then the length of the
 *		message is passed via the argument data_lenp. Otherwise,
 *		return an appropriate error value.
 *
 * Arguments:
 *
 * target_id	- The target_id of the peer. It must be 0 on a Domain.
 * mkey		- Unique key corresponding to a mailbox.
 * data_lenp	- A pointer to uint32_t, in which the size of the message
 *			is returned.
 *
 * Return Values: returns 0 if a message is present, otherwise an appropriate
 *		  errno value is returned.
 *
 * EINVAL	- Invalid values.
 * EBADF	- Specified target_id is not OPEN.
 * ENOMSG	- No message available.
 * EIO		- DSCP I/F path not available.
 */
int
scf_mb_canget(target_id_t target_id, mkey_t mkey, uint32_t *data_lenp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_mb_canget() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	scf_rdata_que_t		*rdt_p;	/* Current receive data queue address */
	int			path_ret; /* SCF path status return value */
	int			ret = 0;	/* Return value */

	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start mkey = 0x%08x",
		mkey);
	SC_DBG_DRV_TRACE(TC_MB_CANGET | TC_IN, __LINE__, &mkey, sizeof (mkey));
	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	/* Check target_id */
	if (target_id != 0) {
		/* Invalid "target_id" */
		SC_DBG_DRV_TRACE(TC_MB_CANGET | TC_ERRCD, __LINE__, &target_id,
			sizeof (target_id));
		ret = EINVAL;
		goto END_mb_canget;
	}

	/* Get main table address from "mkey" */
	mainp = scf_dscp_mkey2mainp(mkey);

	/* Check mainp address */
	if (mainp == NULL) {
		/* Invalid "mkey" */
		SC_DBG_DRV_TRACE(TC_MB_CANGET | TC_ERRCD, __LINE__, &mkey,
			sizeof (mkey));
		ret = EINVAL;
		goto END_mb_canget;
	}

	/* Get SCF path status */
	path_ret = scf_path_check(NULL);

	/* Check SCF path status */
	if (path_ret == SCF_PATH_HALT) {
		/* SCF path status halt */
		SC_DBG_DRV_TRACE(TC_MB_CANGET | TC_ERRCD, __LINE__, &path_ret,
			sizeof (path_ret));
		ret = EIO;
		goto END_mb_canget;
	}

	/* Check main status */
	switch (mainp->status) {
	case SCF_ST_ESTABLISHED:		/* Main status (C0) */
	case SCF_ST_EST_FINI_WAIT:		/* Main status (C1) */
		/* Check "data_lenp" address */
		if (data_lenp == NULL) {
			/* Invalid "data_lenp" */
			SC_DBG_DRV_TRACE(TC_MB_CANGET | TC_ERRCD, __LINE__,
				&data_lenp, sizeof (data_lenp));

			ret = EINVAL;
			goto END_mb_canget;
		}

		/* Check receive data count */
		if (mainp->rd_count != 0) {
			/* Set receive data length */
			rdt_p = &mainp->rd_datap[mainp->rd_get];
			*data_lenp = rdt_p->length;
		} else {
			/* Set receive data length is 0 : No messages */
			SC_DBG_DRV_TRACE(TC_MB_CANGET, __LINE__,
				&mainp->rd_count,
				sizeof (mainp->rd_count));
			*data_lenp = 0;
			ret = ENOMSG;
		}
		break;

	default:
		/* Not open */
		SC_DBG_DRV_TRACE(TC_MB_CANGET | TC_ERRCD, __LINE__,
			&mainp->status, TC_INFO_SIZE);
		ret = EBADF;
		break;
	}

/*
 * END_mb_canget
 */
	END_mb_canget:

	/* Unlock driver mutex */
	mutex_exit(&scf_comtbl.all_mutex);

	SC_DBG_DRV_TRACE(TC_MB_CANGET | TC_OUT, __LINE__, &ret, sizeof (ret));
	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_mb_getmsg()
 *
 * Description: Get a message from the specified mailbox. A message need to
 *		be received either completely or none, that is, no partial
 *		messages should be received.
 *
 *		If a 0 timeout value is specified, then it should act as a
 *		non-blocking interface, that is, it should either return
 *		a  message from the mailbox or return appropriate error.
 *		If a timeout value is specified, then it can blocked
 *		until either the message is received successfully or timedout.
 *
 * Arguments:
 *
 * target_id	- The target_id of the peer. It must be 0 on a Domain.
 * mkey		- Unique key corresponding to a mailbox.
 * data_len	- Total length of data buffers passed via scatter/gather list.
 * num_sg	- Number of scatter/gather elements in the argument sgp.
 * sgp		- Scatter/gather list pointer.
 * timeout	- timeout value in milliseconds. If 0 specified, no waiting
 *		  is required.
 *
 * Return Values: returns 0 on success, otherwise any meaningful errno
 *		  values are returned, some of the notable error values
 *		  are given below.
 *
 * EINVAL	- Invalid values.
 * EBADF	- Specified target_id is not OPEN.
 * EMSGSIZE	- Specified receive data size unmatched.
 * ENOMSG	- No message available.
 * EIO		- DSCP I/F path not available.
 */
/* ARGSUSED */
int
scf_mb_getmsg(target_id_t target_id, mkey_t mkey, uint32_t data_len,
	uint32_t num_sg, mscat_gath_t *sgp, clock_t timeout)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_mb_getmsg() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	scf_rdata_que_t		*rdt_p;	/* Current receive data queue address */
	caddr_t			wkaddr;	/* Working value : buffer address */
	uint32_t		wkleng = 0;	/* Working value : length */
	int			ii;		/* Working value : counter */
	int			path_ret; /* SCF path status return value */
	int			ret = 0;	/* Return value */

	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start mkey = 0x%08x",
		mkey);
	SC_DBG_DRV_TRACE(TC_MB_GETMSG | TC_IN, __LINE__, &mkey, sizeof (mkey));
	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	/* Check target_id */
	if (target_id != 0) {
		/* Invalid "target_id" */
		SC_DBG_DRV_TRACE(TC_MB_GETMSG | TC_ERRCD, __LINE__, &target_id,
			sizeof (target_id));
		ret = EINVAL;
		goto END_mb_getmsg;
	}

	/* Get main table address from "mkey" */
	mainp = scf_dscp_mkey2mainp(mkey);

	/* Check mainp address */
	if (mainp == NULL) {
		/* Invalid "mkey" */
		SC_DBG_DRV_TRACE(TC_MB_GETMSG | TC_ERRCD, __LINE__, &mkey,
			sizeof (mkey));
		ret = EINVAL;
		goto END_mb_getmsg;
	}

	/* Get SCF path status */
	path_ret = scf_path_check(NULL);

	/* Check SCF path status */
	if (path_ret == SCF_PATH_HALT) {
		/* SCF path status halt */
		SC_DBG_DRV_TRACE(TC_MB_GETMSG | TC_ERRCD, __LINE__, &path_ret,
			sizeof (path_ret));
		ret = EIO;
		goto END_mb_getmsg;
	}

	switch (mainp->status) {
	case SCF_ST_ESTABLISHED:		/* Main status (C0) */
	case SCF_ST_EST_FINI_WAIT:		/* Main status (C1) */
		/* Check "data_len" */
		if ((data_len == 0) ||
			(data_len > scf_dscp_comtbl.maxdatalen)) {
			/* Unmatched "data_len" */
			SC_DBG_DRV_TRACE(TC_MB_GETMSG | TC_ERRCD, __LINE__,
				&data_len, sizeof (data_len));
			ret = EMSGSIZE;
			goto END_mb_getmsg;
		}

		/* Is num_sg and sgp valid? */
		if ((num_sg == 0) || (sgp == NULL)) {
			/* Invalid "num_sg" or "sgp" */
			SC_DBG_DRV_TRACE(TC_MB_GETMSG | TC_ERRCD,
				__LINE__, &num_sg, sizeof (num_sg));
			ret = EINVAL;
			goto END_mb_getmsg;
		}
		/* Is there receive data? */
		if (mainp->rd_count == 0) {
			/* No message */
			SC_DBG_DRV_TRACE(TC_MB_GETMSG, __LINE__,
				&mainp->rd_count,
				sizeof (mainp->rd_count));
			ret = ENOMSG;
			goto END_mb_getmsg;
		}

		/* Get total data length : "num_sg" */
		for (ii = 0; ii < num_sg; ii++) {
			if ((sgp[ii].msc_len == 0) ||
				(sgp[ii].msc_dptr != NULL)) {
				/*
				 * Add total data length
				 */
				wkleng += sgp[ii].msc_len;
			} else {
				/* Invalid "sgp" */
				SC_DBG_DRV_TRACE(TC_MB_GETMSG | TC_ERRCD,
					__LINE__, &sgp, sizeof (sgp));
				ret = EINVAL;
				goto END_mb_getmsg;
			}
		}
		/* Check "data_len" and "wkleng" */
		if (data_len != wkleng) {
			/* Unmatched "data_len" */
			SC_DBG_DRV_TRACE(TC_MB_GETMSG | TC_ERRCD, __LINE__,
				&data_len, sizeof (data_len));
			ret = EMSGSIZE;
			goto END_mb_getmsg;
		}

		/* Get receive data queue address */
		rdt_p = &mainp->rd_datap[mainp->rd_get];

		/* Check "data_len" and receive data length */
		if (data_len != rdt_p->length) {
			/* Unmatched data_len */
			SC_DBG_DRV_TRACE(TC_MB_GETMSG | TC_ERRCD,
				__LINE__, &data_len, sizeof (data_len));
			ret = EMSGSIZE;
			goto END_mb_getmsg;
		}

		/* Data copy to "sgp" */
		wkaddr = rdt_p->rdatap;
		for (ii = 0; ii < num_sg; ii++) {
			if (sgp[ii].msc_len != 0) {
				bcopy(wkaddr, sgp[ii].msc_dptr,
					sgp[ii].msc_len);
				wkaddr += sgp[ii].msc_len;
			}
		}
		/* Receve data release */
		kmem_free(rdt_p->rdatap, rdt_p->length);
		rdt_p->rdatap = NULL;

		/* Update receive data queue */
		if (mainp->rd_get == mainp->rd_last) {
			mainp->rd_get = mainp->rd_first;
		} else {
			mainp->rd_get++;
		}

		/* Update receive data queue count */
		mainp->rd_count--;
		break;

	default:
		/* Not open */
		SC_DBG_DRV_TRACE(TC_MB_GETMSG | TC_ERRCD, __LINE__,
			&mainp->status, TC_INFO_SIZE);
		ret = EBADF;
		break;
	}

/*
 * END_mb_getmsg
 */
	END_mb_getmsg:

	/* Unlock driver mutex */
	mutex_exit(&scf_comtbl.all_mutex);

	SC_DBG_DRV_TRACE(TC_MB_GETMSG | TC_OUT, __LINE__, &ret, sizeof (ret));
	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_mb_flush()
 *
 * Description: Flush messages from a specified mailbox.
 *
 * Arguments:
 *
 * target_id	- The target_id of the peer. It must be 0 on a Domain.
 * mkey		- Unique key corresponding to a mailbox.
 * flush_type	- Specifies what type of flush is desired.
 *
 * Return Values: returns 0 on success, otherwise any meaningful errno
 *		  values are returned.
 * EINVAL	- Invalid values.
 * EBADF	- Specified target_id is not OPEN.
 */
int
scf_mb_flush(target_id_t target_id, mkey_t mkey, mflush_type_t flush_type)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_mb_flush() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	int			ret = 0;	/* Return value */

	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start mkey = 0x%08x",
		mkey);
	SC_DBG_DRV_TRACE(TC_MB_FLUSH | TC_IN, __LINE__, &mkey, sizeof (mkey));

	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	/* Check target_id */
	if (target_id != 0) {
		/* Invalid "target_id" */
		SC_DBG_DRV_TRACE(TC_MB_FLUSH | TC_ERRCD, __LINE__, &target_id,
			sizeof (target_id));
		ret = EINVAL;
		goto END_mb_flush;
	}

	/* Get main table address from "mkey" */
	mainp = scf_dscp_mkey2mainp(mkey);

	/* Check mainp address */
	if (mainp == NULL) {
		/* Invalid "mkey" */
		SC_DBG_DRV_TRACE(TC_MB_FLUSH | TC_ERRCD, __LINE__, &mkey,
			sizeof (mkey));
		ret = EINVAL;
		goto END_mb_flush;
	}

	switch (mainp->status) {
	case SCF_ST_EST_TXEND_RECV_WAIT: /* Main status (B0) */
	case SCF_ST_ESTABLISHED:	/* Main status (C0) */
	case SCF_ST_EST_FINI_WAIT:	/* Main status (C1) */
		switch (flush_type) {
		case MB_FLUSH_SEND:
		case MB_FLUSH_RECEIVE:
		case MB_FLUSH_ALL:
			if (flush_type != MB_FLUSH_RECEIVE) {
				/* TxDSC buffer release */
				scf_dscp_txdscbuff_free(mainp);
			}
			if (flush_type != MB_FLUSH_SEND) {
				/* RxDSC buffer release */
				scf_dscp_rxdscbuff_free(mainp);

				/* All queing event release */
				scf_dscp_event_queue_free(mainp);

				/* All receive buffer release */
				scf_dscp_rdata_free(mainp);
			}
			break;

		default:

			/* Invalid "flush_type" */
			SC_DBG_DRV_TRACE(TC_MB_FLUSH | TC_ERRCD, __LINE__,
				&flush_type, sizeof (flush_type));
			ret = EINVAL;
			break;
		}
		break;

	default:
		/* Not open */
		SC_DBG_DRV_TRACE(TC_MB_FLUSH | TC_ERRCD, __LINE__,
			&mainp->status, TC_INFO_SIZE);
		ret = EBADF;
		break;
	}

/*
 * END_mb_flush
 */
	END_mb_flush:

	/* Unlock driver mutex */
	mutex_exit(&scf_comtbl.all_mutex);

	SC_DBG_DRV_TRACE(TC_MB_FLUSH | TC_OUT, __LINE__, &ret, sizeof (ret));
	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * scf_mb_ctrl()
 *
 * Description: This interface provides a way to obtain any specific
 *		properties of a mailbox, such as maximum size of the
 *		message which could be transmitted/received etc.
 *
 * Arguments:
 *
 * target_id	- The target_id of the peer. It must be 0 on a Domain.
 * mkey		- Unique key corresponding to a mailbox.
 * op		- an operation.
 * arg		- argument specific to the operation.
 *
 * Return Values: returns 0 on success, otherwise any meaningful errno
 *		  values are returned.
 *
 * EINVAL	- Invalid values.
 * EBADF	- Specified target_id is not OPEN.
 * ENOTSUP	- Not supported.
 */
int
scf_mb_ctrl(target_id_t target_id, mkey_t mkey, uint32_t op, void *arg)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_mb_ctrl() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	uint32_t		*wkarg;		/* Working value : arg */
	int			ret = 0;	/* Return value */

	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start mkey = 0x%08x",
		mkey);
	SC_DBG_DRV_TRACE(TC_MB_CTRL | TC_IN, __LINE__, &mkey, sizeof (mkey));

	/* Lock driver mutex */
	mutex_enter(&scf_comtbl.all_mutex);

	/* Check target_id */
	if (target_id != 0) {
		/* Invalid "target_id" */
		SC_DBG_DRV_TRACE(TC_MB_CTRL | TC_ERRCD, __LINE__, &target_id,
			sizeof (target_id));
		ret = EINVAL;
		goto END_mb_ctrl;
	}

	/* Get main table address from "mkey" */
	mainp = scf_dscp_mkey2mainp(mkey);

	/* Check mainp address */
	if (mainp == NULL) {
		/* Invalid "mkey" */
		SC_DBG_DRV_TRACE(TC_MB_CTRL | TC_ERRCD, __LINE__, &mkey,
			sizeof (mkey));
		ret = EINVAL;
		goto END_mb_ctrl;
	}

	switch (mainp->status) {
	case SCF_ST_EST_TXEND_RECV_WAIT: /* Main status (B0) */
	case SCF_ST_ESTABLISHED:	/* Main status (C0) */
	case SCF_ST_EST_FINI_WAIT:	/* Main status (C1) */
		/* Check "arg" address */
		if (arg == NULL) {
			/* Invalid "arg" */
			SC_DBG_DRV_TRACE(TC_MB_CTRL | TC_ERRCD, __LINE__,
				&arg, sizeof (arg));
			ret = EINVAL;
			goto END_mb_ctrl;
		}

		/* Check "op" */
		switch (op) {
		case SCF_MBOP_MAXMSGSIZE:
			/*
			 * Notifies max send/receive
			 * data size
			 */
			SC_DBG_DRV_TRACE(TC_MB_CTRL, __LINE__,
				&scf_dscp_comtbl.maxdatalen,
				sizeof (scf_dscp_comtbl.maxdatalen));

			/* Setsend/receive data size */
			wkarg = (uint32_t *)arg;
			*wkarg = scf_dscp_comtbl.maxdatalen;
			break;

		default:
			/* Not support  */
			SC_DBG_DRV_TRACE(TC_MB_CTRL, __LINE__, &op,
				sizeof (op));
			ret = ENOTSUP;
			break;
		}
		break;

	default:
		/* Not open */
		SC_DBG_DRV_TRACE(TC_MB_CTRL | TC_ERRCD,
			__LINE__, &mainp->status, TC_INFO_SIZE);
		ret = EBADF;
		break;
	}

/*
 * END_mb_ctrl
 */
	END_mb_ctrl:

	/* Unlock driver mutex */
	mutex_exit(&scf_comtbl.all_mutex);

	SC_DBG_DRV_TRACE(TC_MB_CTRL | TC_OUT, __LINE__, &ret, sizeof (ret));
	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end return = %d", ret);
	return (ret);
}


/*
 * SCF driver system control intafece function
 */

/*
 * scf_dscp_init()
 *
 * Description: DSCP control area initialization processing.
 *
 */
void
scf_dscp_init(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_init() "
	scf_dscp_main_t		*mainp = NULL;	/* Main table address */
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */
	scf_tx_sram_t		*sram_p;	/* Tx SRAM address */
	int			ii;		/* Working value : counter */
	int			jj;		/* Working value : counter */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/*
	 * DSCP common table initialization
	 */
	/* Set size value */
	scf_dscp_comtbl.maxdatalen = SCF_MB_MAXDATALEN;
	scf_dscp_comtbl.total_buffsize = SCF_TOTAL_BUFFSIZE;
	scf_dscp_comtbl.txbuffsize = SCF_TXBUFFSIZE;
	scf_dscp_comtbl.rxbuffsize = SCF_RXBUFFSIZE;

	/* Set max count */
	scf_dscp_comtbl.txsram_maxcount = SCF_TX_SRAM_MAXCOUNT;
	scf_dscp_comtbl.rxsram_maxcount = SCF_RX_SRAM_MAXCOUNT;
	scf_dscp_comtbl.txdsc_maxcount = SCF_TXDSC_MAXCOUNT;
	scf_dscp_comtbl.rxdsc_maxcount = SCF_RXDSC_MAXCOUNT;
	scf_dscp_comtbl.txdsc_busycount = SCF_TXDSC_BUSYCOUNT;
	scf_dscp_comtbl.rxdsc_busycount = SCF_RXDSC_BUSYCOUNT;

	/* Set re-try max count */
	scf_dscp_comtbl.tx_ackto_maxretry_cnt = SCF_TX_ACKTO_MAXRETRAYCOUNT;
	scf_dscp_comtbl.tx_endto_maxretry_cnt = SCF_TX_ENDTO_MAXRETRAYCOUNT;
	scf_dscp_comtbl.tx_busy_maxretry_cnt = SCF_TX_BUSY_MAXRETRAYCOUNT;
	scf_dscp_comtbl.tx_interface_maxretry_cnt = SCF_TX_IF_MAXRETRAYCOUNT;
	scf_dscp_comtbl.tx_nak_maxretry_cnt = SCF_TX_NAK_MAXRETRAYCOUNT;
	scf_dscp_comtbl.tx_notsup_maxretry_cnt = SCF_TX_NOTSUP_MAXRETRAYCOUNT;
	scf_dscp_comtbl.tx_prmerr_maxretry_cnt = SCF_TX_PRMERR_MAXRETRAYCOUNT;
	scf_dscp_comtbl.tx_seqerr_maxretry_cnt = SCF_TX_SEQERR_MAXRETRAYCOUNT;
	scf_dscp_comtbl.tx_other_maxretry_cnt = SCF_TX_OTHER_MAXRETRAYCOUNT;
	scf_dscp_comtbl.tx_send_maxretry_cnt = SCF_TX_SEND_MAXRETRAYCOUNT;

	/* TxDSC/RxDSC table allocation */
	scf_dscp_comtbl.tx_dscsize =
		sizeof (scf_dscp_dsc_t) * (scf_dscp_comtbl.txdsc_maxcount +
		SCF_TXDSC_LOCALCOUNT);
	scf_dscp_comtbl.tx_dscp =
		(scf_dscp_dsc_t *)kmem_zalloc(scf_dscp_comtbl.tx_dscsize,
		KM_SLEEP);

	scf_dscp_comtbl.rx_dscsize =
		sizeof (scf_dscp_dsc_t) * (scf_dscp_comtbl.rxdsc_maxcount);
	scf_dscp_comtbl.rx_dscp =
		(scf_dscp_dsc_t *)kmem_zalloc(scf_dscp_comtbl.rx_dscsize,
		KM_SLEEP);

	/* Tx SRAM table allocation */
	scf_dscp_comtbl.tx_sramsize =
		sizeof (scf_tx_sram_t) * scf_dscp_comtbl.txsram_maxcount;
	scf_dscp_comtbl.tx_sramp =
		(scf_tx_sram_t *)kmem_zalloc(scf_dscp_comtbl.tx_sramsize,
		KM_SLEEP);

	/*
	 * TxDSC table initialization
	 */
	/* Get TxDSC table address */
	dsc_p = scf_dscp_comtbl.tx_dscp;
	for (ii = 0; ii < scf_dscp_comtbl.txdsc_maxcount; ii++, dsc_p++) {
		/* Init SRAM offset */
		dsc_p->dinfo.base.offset = DSC_OFFSET_NOTHING;
	}

	/* Set Tx offset */
	scf_dscp_comtbl.tx_first = 0;
	scf_dscp_comtbl.tx_last =
		(uint16_t)(scf_dscp_comtbl.txdsc_maxcount - 1);
	scf_dscp_comtbl.tx_put = 0;
	scf_dscp_comtbl.tx_get = 0;
	scf_dscp_comtbl.tx_local = (uint16_t)scf_dscp_comtbl.txdsc_maxcount;
	scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_local].dinfo.base.offset =
		DSC_OFFSET_NOTHING;

	/*
	 * Tx STAM offset initialization
	 */
	/* Get Tx SRAM table address */
	sram_p = scf_dscp_comtbl.tx_sramp;
	for (ii = 0; ii < scf_dscp_comtbl.txsram_maxcount; ii++, sram_p++) {
		/* Init SRAM offset */
		sram_p->offset =
			(uint16_t)(scf_dscp_comtbl.txbuffsize * ii /
			DSC_OFFSET_CONVERT);
	}

	/* Set Tx SRAM offset */
	scf_dscp_comtbl.tx_sram_first = 0;
	scf_dscp_comtbl.tx_sram_last = (scf_dscp_comtbl.txsram_maxcount - 1);
	scf_dscp_comtbl.tx_sram_put = 0;

	/*
	 * RxDSC table initialization
	 */
	/* Set Rx offset */
	scf_dscp_comtbl.rx_first = 0;
	scf_dscp_comtbl.rx_last =
		(uint16_t)(scf_dscp_comtbl.rxdsc_maxcount - 1);
	scf_dscp_comtbl.rx_put = 0;
	scf_dscp_comtbl.rx_get = 0;

	/*
	 * Main table initialization
	 */
	/* Get Top main table address */
	mainp = &scf_dscp_comtbl.scf_dscp_main[0];

	/* Check main table */
	for (ii = 0; ii < MBIF_MAX; ii++, mainp++) {
		/* Set table id */
		mainp->id = ii & DSC_CNTL_MASK_ID;

		/* Set event/recive queue max count */
		mainp->ev_maxcount = SCF_MB_EVQUE_MAXCOUNT;
		mainp->rd_maxcount = SCF_RDQUE_MAXCOUNT;
		mainp->rd_busycount = SCF_RDQUE_BUSYCOUNT;

		/* Set fint() condition variable */
		cv_init(&mainp->fini_cv, NULL, CV_DRIVER, NULL);
		mainp->cv_init_flag = FLAG_ON;

		/* event/receive data queue table allocation */
		mainp->ev_quesize =
			sizeof (scf_event_que_t) * mainp->ev_maxcount;
		mainp->ev_quep =
			(scf_event_que_t *)kmem_zalloc(mainp->ev_quesize,
			KM_SLEEP);
		mainp->rd_datasize =
			sizeof (scf_rdata_que_t) * mainp->ev_maxcount;
		mainp->rd_datap =
			(scf_rdata_que_t *)kmem_zalloc(mainp->rd_datasize,
			KM_SLEEP);

		/* Event queue initialization */
		for (jj = 0; jj < mainp->ev_maxcount; jj++) {
			mainp->ev_quep[jj].mevent = (scf_event_t)(-1);
		}
		mainp->ev_first = 0;
		mainp->ev_last = (uint16_t)(mainp->ev_maxcount - 1);
		mainp->ev_put = 0;
		mainp->ev_get = 0;

		/* Receive data queue initialization */
		mainp->rd_first = 0;
		mainp->rd_last = (uint16_t)(mainp->rd_maxcount - 1);
		mainp->rd_put = 0;
		mainp->rd_get = 0;

		/* Set DSCP INIT_REQ retry timer code */
		if (mainp->id == MBIF_DSCP) {
			mainp->timer_code = SCF_TIMERCD_DSCP_INIT;
		} else {
			mainp->timer_code = SCF_TIMERCD_DKMD_INIT;
		}
	}

	/* Initialize success flag ON */
	scf_dscp_comtbl.dscp_init_flag = FLAG_ON;

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_fini()
 *
 * Description: DSCP control area release processing.
 *
 */
void
scf_dscp_fini(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_fini() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	int			ii;		/* Working value : counter */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/*
	 * Main table resources release
	 */
	/* Get Top main table address */
	mainp = &scf_dscp_comtbl.scf_dscp_main[0];

	/* Check main table */
	for (ii = 0; ii < MBIF_MAX; ii++, mainp++) {
		/* All receive buffer release */
		scf_dscp_rdata_free(mainp);

		/* Check fint() condition variable */
		if (mainp->cv_init_flag == FLAG_ON) {
			/* Destroy fint() condition variable */
			cv_destroy(&mainp->fini_cv);
			mainp->cv_init_flag = FLAG_OFF;
		}

		/* Check event queue table allocation */
		if (mainp->ev_quep != NULL) {
			/* Event queue table release */
			kmem_free(mainp->ev_quep, mainp->ev_quesize);
			mainp->ev_quep = NULL;
		}

		/* Check receive data table queue allocation */
		if (mainp->rd_datap != NULL) {
			/* Receive data queue table release */
			kmem_free(mainp->rd_datap, mainp->rd_datasize);
			mainp->rd_datap = NULL;
		}
	}

	/*
	 * DSCP common table resources release
	 */
	/* All timer stop */
	scf_timer_stop(SCF_TIMERCD_DSCP_ACK);
	scf_timer_stop(SCF_TIMERCD_DSCP_END);
	scf_timer_stop(SCF_TIMERCD_DSCP_CALLBACK);
	scf_timer_stop(SCF_TIMERCD_DSCP_BUSY);
	scf_timer_stop(SCF_TIMERCD_DSCP_INIT);
	scf_timer_stop(SCF_TIMERCD_DKMD_INIT);

	/* All DSC buffer release */
	scf_dscp_dscbuff_free_all();

	/* Check TxDSC table allocation */
	if (scf_dscp_comtbl.tx_dscp != NULL) {
		/* TxDSC table release */
		kmem_free(scf_dscp_comtbl.tx_dscp,
			scf_dscp_comtbl.tx_dscsize);
		scf_dscp_comtbl.tx_dscp = NULL;
	}

	/* Check RxDSC table allocation */
	if (scf_dscp_comtbl.rx_dscp != NULL) {
		/* RxDSC table release */
		kmem_free(scf_dscp_comtbl.rx_dscp,
			scf_dscp_comtbl.rx_dscsize);
		scf_dscp_comtbl.rx_dscp = NULL;
	}

	/* Check Tx SRAM table allocation */
	if (scf_dscp_comtbl.tx_sramp != NULL) {
		/* Tx SRAM table release */
		kmem_free(scf_dscp_comtbl.tx_sramp,
			scf_dscp_comtbl.tx_sramsize);
		scf_dscp_comtbl.tx_sramp = NULL;
	}

	/* Initialize success flag ON */
	scf_dscp_comtbl.dscp_init_flag = FLAG_OFF;

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_start()
 *
 * Description: DSCP interface start processing.
 *
 */
void
scf_dscp_start(uint32_t factor)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_start() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */
	int			ii;		/* Working value : counter */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start factor = 0x%08x",
		factor);

	/* Check local control data flag */
	if (scf_dscp_comtbl.tx_local_use_flag == FLAG_ON) {
		/* Get local data TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_local];

		/* Change TxDSC status (SA0) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_IDLE);

		/* TxREQ send exec flag OFF */
		scf_dscp_comtbl.tx_exec_flag = FLAG_OFF;
	}

	/* Check pending send TxDSC */
	if (scf_dscp_comtbl.tx_dsc_count != 0) {
		/* Get TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_get];

		/* Check TxDSC status */
		switch (dsc_p->status) {
		case SCF_TX_ST_TXREQ_SEND_WAIT:		/* TxDSC status (SB2) */
			/* Check send data length */
			if (dsc_p->dinfo.base.length != 0) {
				/* Try again SRAM transfer */

				/* Change TxDSC status (SB0) */
				SCF_SET_DSC_STATUS(dsc_p,
					SCF_TX_ST_SRAM_TRANS_WAIT);
			}
			break;

		case SCF_TX_ST_TXACK_RECV_WAIT:		/* TxDSC status (SC0) */
		case SCF_TX_ST_TXEND_RECV_WAIT:		/* TxDSC status (SC1) */
			/* Try again TxREQ send */

			/* Change TxDSC status (SB2) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_TXREQ_SEND_WAIT);
			break;

		default:
			/* TxDSC status != SB2 or SC0 or SC1 is NOP */
			break;
		}
	}

	/* Check pending RxDSC */
	while (scf_dscp_comtbl.rx_dsc_count != 0) {
		/* Get RxDSC address */
		dsc_p = &scf_dscp_comtbl.rx_dscp[scf_dscp_comtbl.rx_get];

		/* Check receive data */
		if (dsc_p->dinfo.base.dscp_datap != NULL) {
			/* Receive data release */
			kmem_free(dsc_p->dinfo.base.dscp_datap,
				dsc_p->dinfo.base.length);
			dsc_p->dinfo.base.dscp_datap = NULL;
		}

		/* Change RxDSC status (RA0) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_IDLE);

		/* Update Rx descriptor offset */
		if (scf_dscp_comtbl.rx_get == scf_dscp_comtbl.rx_last) {
			scf_dscp_comtbl.rx_get = scf_dscp_comtbl.rx_first;
		} else {
			scf_dscp_comtbl.rx_get++;
		}

		/* Update Rx descriptor count */
		scf_dscp_comtbl.rx_dsc_count--;

		/* RxREQ receive exec flag OFF */
		scf_dscp_comtbl.rx_exec_flag = FLAG_OFF;
	}

	/* Check SCF path change */
	if (factor == FACTOR_PATH_CHG) {
		/* Tx re-try counter initialization */
		scf_dscp_comtbl.tx_ackto_retry_cnt = 0;
		scf_dscp_comtbl.tx_endto_retry_cnt = 0;

		scf_dscp_comtbl.tx_busy_retry_cnt = 0;
		scf_dscp_comtbl.tx_interface_retry_cnt = 0;
		scf_dscp_comtbl.tx_nak_retry_cnt = 0;
		scf_dscp_comtbl.tx_notsuop_retry_cnt = 0;
		scf_dscp_comtbl.tx_prmerr_retry_cnt = 0;
		scf_dscp_comtbl.tx_seqerr_retry_cnt = 0;
		scf_dscp_comtbl.tx_other_retry_cnt = 0;
		scf_dscp_comtbl.tx_send_retry_cnt = 0;

		/*
		 * SCF path change flag ON :
		 * local control data send(DSCP_PATH)
		 */
		scf_dscp_comtbl.dscp_path_flag = FLAG_ON;
	} else {
		/* SCF online processing */

		/* Get Top main table address */
		mainp = &scf_dscp_comtbl.scf_dscp_main[0];

		/* Check main table */
		for (ii = 0; ii < MBIF_MAX; ii++, mainp++) {
			/* Check main status */
			switch (mainp->status) {
			case SCF_ST_EST_TXEND_RECV_WAIT: /* Main status (B0) */
			case SCF_ST_ESTABLISHED:	/* Main status (C0) */
				/*
				 * Connect check flag ON :
				 * local control data send(CONN_CHK)
				 */
				mainp->conn_chk_flag = FLAG_ON;
				break;

			default:
				/* Connect check flag OFF */
				mainp->conn_chk_flag = FLAG_OFF;
				break;
			}
		}
	}

	/* Call send matrix */
	scf_dscp_send_matrix();

	/* Call receive matrix */
	scf_dscp_recv_matrix();

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_stop()
 *
 * Description: DSCP interface stop processing.
 *
 */
void
scf_dscp_stop(uint32_t factor)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_stop() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	int			ii;		/* Working value : counter */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start factor = 0x%08x",
		factor);

	/* Check stop factor */
	if ((factor == FACTOR_PATH_HALT) || (factor == FACTOR_PATH_STOP)) {
		/* memo counter up */
		scf_dscp_comtbl.scf_stop_memo_cnt++;

		/* Get Top main table address */
		mainp = &scf_dscp_comtbl.scf_dscp_main[0];

		/* Check main table */
		for (ii = 0; ii < MBIF_MAX; ii++, mainp++) {
			/* Check main status */
			switch (mainp->status) {
			case SCF_ST_EST_TXEND_RECV_WAIT: /* Main status (B0) */
			case SCF_ST_ESTABLISHED:	/* Main status (C0) */
				/* SCF_MB_DISC_ERROR event queuing */
				scf_dscp_event_queue(mainp, SCF_MB_DISC_ERROR);

				/* Change main status (C1) */
				SCF_SET_STATUS(mainp, SCF_ST_EST_FINI_WAIT);

				break;

			case SCF_ST_CLOSE_TXEND_RECV_WAIT:
				/* Main status (D0) */
				/* Signal to fini() wait */
				mainp->fini_wait_flag = FLAG_OFF;
				cv_signal(&mainp->fini_cv);
				SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__,
					&mainp->fini_cv, sizeof (kcondvar_t));
				break;

			default:
				/* Main status != B0 or C0 or D0 is NOP */
				break;
			}
		}
	}

	/* Tx timer stop */
	scf_timer_stop(SCF_TIMERCD_DSCP_ACK);
	scf_timer_stop(SCF_TIMERCD_DSCP_END);
	scf_timer_stop(SCF_TIMERCD_DSCP_BUSY);

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_intr()
 *
 * Description: The corresponding function is called according to the
 * interruption factor from SCF.
 *
 */
void
scf_dscp_intr(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_intr() "
	/* Working value : Interrupt check flag */
	int			interrupt = FLAG_OFF;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Get DSR register */
	statep->reg_dsr = SCF_DDI_GET8(statep, statep->scf_regs_handle,
		&statep->scf_regs->DSR);
	SC_DBG_DRV_TRACE(TC_R_DSR, __LINE__, &statep->reg_dsr,
		sizeof (statep->reg_dsr));

	/* DSR register interrupt clear */
	SCF_DDI_PUT8(statep, statep->scf_regs_handle, &statep->scf_regs->DSR,
		statep->reg_dsr);
	SC_DBG_DRV_TRACE(TC_W_DSR, __LINE__, &statep->reg_dsr,
		sizeof (statep->reg_dsr));

	/* Regster read sync */
	scf_rs8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
		&statep->scf_regs->DSR);

	SCF_DBG_TEST_INTR_DSCP_DSR(statep);

	SCFDBGMSG1(SCF_DBGFLAG_REG, "DSR = 0x%02x", statep->reg_dsr);

	if ((statep->reg_dsr & DSR_TxACK) != 0) {	/* TxACK interrupt */
		SCFDBGMSG(SCF_DBGFLAG_DSCP, "TxACK interrupt");

		interrupt = FLAG_ON;

		SC_DBG_DRV_TRACE(TC_TxACK, __LINE__, NULL, 0);

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_DSCP_TXACK);

		/* Call TxACK interrupt processing */
		scf_dscp_txack_recv(statep);
	}

	if ((statep->reg_dsr & DSR_TxEND) != 0) {	/* TxEND interrupt */
		SCFDBGMSG(SCF_DBGFLAG_DSCP, "TxEND interrupt");

		interrupt = FLAG_ON;

		/* Get TxDSR register */
		statep->reg_txdsr_c_flag =
			SCF_DDI_GET16(statep, statep->scf_regs_handle,
			&statep->scf_regs->TxDSR_C_FLAG);
		SC_DBG_DRV_TRACE(TC_R_TxDSR_C_FLAG, __LINE__,
			&statep->reg_txdsr_c_flag,
			sizeof (statep->reg_txdsr_c_flag));

		statep->reg_txdsr_c_offset =
			SCF_DDI_GET16(statep, statep->scf_regs_handle,
			&statep->scf_regs->TxDSR_OFFSET);
		SC_DBG_DRV_TRACE(TC_R_TxDSR_OFFSET, __LINE__,
			&statep->reg_txdsr_c_offset,
			sizeof (statep->reg_txdsr_c_offset));

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_DSCP_TXEND);

		SCF_DBG_TEST_INTR_DSCP_RXTX(statep, DSR_TxEND);

		SC_DBG_DRV_TRACE(TC_TxEND, __LINE__,
			&statep->reg_txdsr_c_flag, 4);

		SCFDBGMSG2(SCF_DBGFLAG_REG, "TxDSR = 0x%04x 0x%04x",
			statep->reg_txdsr_c_flag, statep->reg_txdsr_c_offset);

		/* Call TxEND interrupt processing */
		scf_dscp_txend_recv(statep);
	}

	if ((statep->reg_dsr & DSR_RxREQ) != 0) {	/* RxREQ interrupt */
		SCFDBGMSG(SCF_DBGFLAG_DSCP, "RxREQ interrupt");

		interrupt = FLAG_ON;
		/* Get RxDCR register */
		statep->reg_rxdcr_c_flag =
			SCF_DDI_GET16(statep, statep->scf_regs_handle,
			&statep->scf_regs->RxDCR_C_FLAG);
		SC_DBG_DRV_TRACE(TC_R_RxDCR_C_FLAG, __LINE__,
			&statep->reg_rxdcr_c_flag,
			sizeof (statep->reg_rxdcr_c_flag));

		statep->reg_rxdcr_c_offset =
			SCF_DDI_GET16(statep, statep->scf_regs_handle,
			&statep->scf_regs->RxDCR_OFFSET);
		SC_DBG_DRV_TRACE(TC_R_RxDCR_OFFSET, __LINE__,
			&statep->reg_rxdcr_c_offset,
			sizeof (statep->reg_rxdcr_c_offset));

		statep->reg_rxdcr_c_length =
			SCF_DDI_GET32(statep, statep->scf_regs_handle,
			&statep->scf_regs->RxDCR_LENGTH);
		SC_DBG_DRV_TRACE(TC_R_RxDCR_LENGTH, __LINE__,
			&statep->reg_rxdcr_c_length,
			sizeof (statep->reg_rxdcr_c_length));

		/* SRAM trace */
		SCF_SRAM_TRACE(statep, DTC_DSCP_RXREQ);

		SCF_DBG_TEST_INTR_DSCP_RXTX(statep, statep->reg_dsr);

		SC_DBG_DRV_TRACE(TC_RxREQ, __LINE__,
			&statep->reg_rxdcr_c_flag, 8);

		SCFDBGMSG3(SCF_DBGFLAG_REG, "RxDCR = 0x%04x 0x%04x 0x%08x",
			statep->reg_rxdcr_c_flag, statep->reg_rxdcr_c_offset,
			statep->reg_rxdcr_c_length);

		/* Call RxRERQ interrupt processing */
		scf_dscp_rxreq_recv(statep);
	}

	if (interrupt == FLAG_OFF) {
		SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__, &statep->reg_dsr,
			sizeof (statep->reg_dsr));
		statep->no_int_dsr_cnt++;
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * Timeout function : from SCF driver timer contorol function
 */

/*
 * scf_dscp_ack_tout()
 *
 * Description: TxACK reception surveillance timeout processing is performed.
 *		SCF path change factor.
 *
 */
void
scf_dscp_ack_tout(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_ack_tout() "
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */
	scf_state_t		*statep;	/* Soft state pointer */
	int			path_ret; /* SCF path status return value */
	uchar_t			cmd;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Check TxREQ send exec */
	if (scf_dscp_comtbl.tx_exec_flag == FLAG_OFF) {
		goto END_dscp_ack_tout;
	}

	/* memo counter up */
	scf_dscp_comtbl.tx_ackto_memo_cnt++;

	/* TxREQ send exec flag OFF */
	scf_dscp_comtbl.tx_exec_flag = FLAG_OFF;

	/* Check local control data flag */
	if (scf_dscp_comtbl.tx_local_use_flag == FLAG_OFF) {
		/* Get TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_get];
	} else {
		/* Get local data TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_local];
	}

	/* Check TxDSC status */
	if (dsc_p->status == SCF_TX_ST_TXACK_RECV_WAIT) {
		/* TxDSC status (SC0) */
		/* Check re-try counter */
		if ((scf_dscp_comtbl.tx_ackto_retry_cnt <
			scf_dscp_comtbl.tx_ackto_maxretry_cnt) &&
				(scf_dscp_comtbl.tx_send_retry_cnt <
				scf_dscp_comtbl.tx_send_maxretry_cnt)) {
			/* re-try count up */
			scf_dscp_comtbl.tx_ackto_retry_cnt++;
			scf_dscp_comtbl.tx_send_retry_cnt++;

			/* Change TxDSC status (SB2) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_TXREQ_SEND_WAIT);

			/* Call send matrix */
			scf_dscp_send_matrix();
		} else {
			/* TxACK re-try timeout error */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__,
				&scf_dscp_comtbl.tx_ackto_retry_cnt,
				sizeof (scf_dscp_comtbl.tx_ackto_retry_cnt));

			/* Get SCF path status */
			path_ret = scf_path_check(&statep);

			/* Check SCF path status */
			if (path_ret == SCF_PATH_ONLINE) {
				cmd = (uchar_t)(dsc_p->dinfo.base.c_flag >> 8);
				cmn_err(CE_WARN,
					"%s,DSCP ack response timeout "
					"occurred. "
					"DSCP command = 0x%02x\n",
						&statep->pathname[0], cmd);

				/* SRAM trace */
				SCF_SRAM_TRACE(statep, DTC_DSCP_ACKTO);

				/* SCF path change */
				statep->scf_herr |= HERR_DSCP_ACKTO;
				scf_path_change(statep);
			}
		}
	}

/*
 * END_dscp_ack_tout
 */
	END_dscp_ack_tout:

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_end_tout()
 *
 * Description: TxEND reception surveillance timeout processing is performed.
 *		SCF path change factor.
 *
 */
void
scf_dscp_end_tout(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_end_tout() "
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */
	scf_state_t		*statep;	/* Soft state pointer */
	int			path_ret; /* SCF path status return value */
	uchar_t			cmd;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Check TxREQ send exec */
	if (scf_dscp_comtbl.tx_exec_flag == FLAG_OFF) {
		goto END_dscp_end_tout;
	}

	/* memo counter up */
	scf_dscp_comtbl.tx_endto_memo_cnt++;

	/* TxREQ send exec flag OFF */
	scf_dscp_comtbl.tx_exec_flag = FLAG_OFF;

	/* Check local control data flag */
	if (scf_dscp_comtbl.tx_local_use_flag == FLAG_OFF) {
		/* Get TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_get];
	} else {
		/* Get local data TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_local];
	}

	/* Check TxDSC status */
	if (dsc_p->status == SCF_TX_ST_TXEND_RECV_WAIT) {
		/* TxDSC status (SC1) */
		/* Check re-try counter */
		if ((scf_dscp_comtbl.tx_endto_retry_cnt <
			scf_dscp_comtbl.tx_endto_maxretry_cnt) &&
				(scf_dscp_comtbl.tx_send_retry_cnt <
				scf_dscp_comtbl.tx_send_maxretry_cnt)) {
			/* re-try count up */
			scf_dscp_comtbl.tx_endto_retry_cnt++;
			scf_dscp_comtbl.tx_send_retry_cnt++;

			/* Change TxDSC status (SB2) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_TXREQ_SEND_WAIT);

			/* Call send matrix */
			scf_dscp_send_matrix();
		} else {
			/* TxEND re-try timeout error */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__,
				&scf_dscp_comtbl.tx_endto_retry_cnt,
				sizeof (scf_dscp_comtbl.tx_endto_retry_cnt));

			/* Get SCF path status */
			path_ret = scf_path_check(&statep);

			/* Check SCF path status */
			if (path_ret == SCF_PATH_ONLINE) {
				cmd = (uchar_t)(dsc_p->dinfo.base.c_flag >> 8);
				cmn_err(CE_WARN,
					"%s,DSCP end response timeout "
					"occurred. "
					"DSCP command = 0x%02x\n",
						&statep->pathname[0], cmd);

				/* SRAM trace */
				SCF_SRAM_TRACE(statep, DTC_DSCP_ENDTO);

				/* SCF path change */
				statep->scf_herr |= HERR_DSCP_ENDTO;
				scf_path_change(statep);
			}
		}
	}

/*
 * END_dscp_end_tout
 */
	END_dscp_end_tout:

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_busy_tout()
 *
 * Description: Busy timeout performs TxREQ transmission again.
 *
 */
void
scf_dscp_busy_tout(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_busy_tout() "
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Check pending send TxDSC or local control TxDSC */
	if ((scf_dscp_comtbl.tx_dsc_count == 0) &&
		(scf_dscp_comtbl.tx_local_use_flag == FLAG_OFF)) {
		goto END_dscp_busy_tout;
	}

	/* Check local control data flag */
	if (scf_dscp_comtbl.tx_local_use_flag == FLAG_OFF) {
		/* Get TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_get];
	} else {
		/* Get local data TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_local];
	}

	/* Check TxDSC status */
	if (dsc_p->status == SCF_TX_ST_TXREQ_SEND_WAIT) {
		/* TxDSC status (SB2) */
		/* Call send matrix */
		scf_dscp_send_matrix();
	}

/*
 * END_dscp_busy_tout
 */
	END_dscp_busy_tout:

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_callback_tout()
 *
 * Description: Callbak timeout performs soft interrupt again.
 *
 */
void
scf_dscp_callback_tout(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_callback_tout() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Soft interrupt : call scf_dscp_callback() */
	if (mutex_tryenter(&scf_comtbl.si_mutex) != 0) {
		scf_comtbl.scf_softintr_dscp_kicked = FLAG_ON;
		ddi_trigger_softintr(scf_comtbl.scf_softintr_id);
		mutex_exit(&scf_comtbl.si_mutex);
	}

	/* Callback timer start */
	scf_timer_start(SCF_TIMERCD_DSCP_CALLBACK);

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_init_tout()
 *
 * Description: INIT_REQ retry timeout performs TxREQ transmission again.
 *
 */
void
scf_dscp_init_tout(uint8_t id)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_init_tout() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Get main table address */
	mainp = scf_dscp_id2mainp(id);

	/* Get TxDSC address */
	dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_put];

	/* Make Tx descriptor : INIT_REQ */
	dsc_p->dinfo.base.c_flag = DSC_FLAG_DEFAULT;
	dsc_p->dinfo.base.offset = DSC_OFFSET_NOTHING;
	dsc_p->dinfo.base.length = 0;
	dsc_p->dinfo.base.dscp_datap = NULL;
	dsc_p->dinfo.bdcr.id = mainp->id & DSC_CNTL_MASK_ID;
	dsc_p->dinfo.bdcr.code = DSC_CNTL_INIT_REQ;

	/* Update Tx descriptor offset */
	if (scf_dscp_comtbl.tx_put == scf_dscp_comtbl.tx_last) {
		scf_dscp_comtbl.tx_put = scf_dscp_comtbl.tx_first;
	} else {
		scf_dscp_comtbl.tx_put++;
	}

	/* Update Tx descriptor count */
	scf_dscp_comtbl.tx_dsc_count++;

	/* Change TxDSC status (SB2) */
	SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_TXREQ_SEND_WAIT);

	/* Call send matrix */
	scf_dscp_send_matrix();

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_callback()
 *
 * Description: Event queue is taken out and a callback entry is called.
 *
 */
void
scf_dscp_callback(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_callback() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	/* Working value : event_handler */
	void			(*wkevent_handler)(scf_event_t, void *);
	scf_event_t		wkmevent;	/* Working value : mevent */
	void			*wkarg;		/* Working value : arg */
	/* Working value : next event processing check flag */
	int			event_flag = FLAG_OFF;
	int			ii;		/* Working value : counter */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Check callback entry exec flag */
	if (scf_dscp_comtbl.callback_exec_flag == FLAG_ON) {
		goto END_dscp_callback;
	}

	/* Set callback entry exec flag */
	scf_dscp_comtbl.callback_exec_flag = FLAG_ON;

/*
 * CALLBACK_START
 */
	CALLBACK_START:

	/* Get Top main table address */
	mainp = &scf_dscp_comtbl.scf_dscp_main[0];
	/* Check all main table */
	for (ii = 0; ii < MBIF_MAX; ii++, mainp++) {
		/* Check event count */
		if (mainp->ev_count != 0) {
			/* Next event processing flag ON */
			event_flag = FLAG_ON;

			/* Get event info */
			wkmevent = mainp->ev_quep[mainp->ev_get].mevent;

			/* Update event queue offset */
			if (mainp->ev_get == mainp->ev_last) {
				mainp->ev_get = mainp->ev_first;
			} else {
				mainp->ev_get++;
			}

			/* Update event queue count */
			mainp->ev_count--;

			/* Get callback enntry and arg */
			wkevent_handler = mainp->event_handler;
			wkarg = mainp->arg;

			/* Check event_handler address */
			if (wkevent_handler != NULL) {
				/* Check main status */
				switch (mainp->status) {
				case SCF_ST_ESTABLISHED:
					/* Main status (C0) */
				case SCF_ST_EST_FINI_WAIT:
					/* Main status (C1) */

					/* Unlock driver mutex */
					mutex_exit(&scf_comtbl.all_mutex);

					/* Call event handler */
					wkevent_handler(wkmevent, wkarg);

					SC_DBG_DRV_TRACE(TC_MB_CALLBACK,
						__LINE__, &wkmevent,
						sizeof (wkmevent));
					SCFDBGMSG1(SCF_DBGFLAG_DSCP,
						"DSCP callback mevent = %d",
						wkmevent);

					/* Lock driver mutex */
					mutex_enter(&scf_comtbl.all_mutex);
					break;

				default:
					/*
					 * Main status != C0 or C1 is NOP
					 */
					break;
				}
			}
		}
	}

	/* Check next event processing */
	if (event_flag == FLAG_ON) {
		event_flag = FLAG_OFF;
		goto CALLBACK_START;
	}

	/* Clear callback entry exec flag */
	scf_dscp_comtbl.callback_exec_flag = FLAG_OFF;

/*
 * END_dscp_callback
 */
	END_dscp_callback:

	/* CALLBACK timer stop */
	scf_timer_stop(SCF_TIMERCD_DSCP_CALLBACK);

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}



/*
 * Interrupt function : from scf_dscp_intr()
 */

/*
 * scf_dscp_txack_recv()
 *
 * Description: TxACK reception processing is performed.
 *
 */
/* ARGSUSED */
void
scf_dscp_txack_recv(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_txack_recv() "
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Check TxREQ send exec */
	if (scf_dscp_comtbl.tx_exec_flag == FLAG_OFF) {
		goto END_dscp_txack_recv;
	}

	/* Check local control data flag */
	if (scf_dscp_comtbl.tx_local_use_flag == FLAG_OFF) {
		/* Get TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_get];
	} else {
		/* Get local data TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_local];
	}

	/* Check TxDSC status */
	if (dsc_p->status == SCF_TX_ST_TXACK_RECV_WAIT) {
		/* TxDSC status (SC0) */
		/* Error counter initialization */
		scf_dscp_comtbl.tx_ackto_retry_cnt = 0;

		/* TxACK timer stop */
		scf_timer_stop(SCF_TIMERCD_DSCP_ACK);

		/* TxEND timer start */
		scf_timer_start(SCF_TIMERCD_DSCP_END);

		/* Change TxDSC status (SC1) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_TXEND_RECV_WAIT);
	}

/*
 * END_dscp_txack_recv
 */
	END_dscp_txack_recv:

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_txend_recv()
 *
 * Description: TxEND reception is received and processing is carried out by
 * completion information.
 *
 */
void
scf_dscp_txend_recv(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_txend_recv() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */
	scf_dscreg_t		wk_dsc;		/* Work TxDSC */
	/* Working value : TxDSC release check flag */
	int			norel_txdsc = FLAG_OFF;
	/* Working value : SCF path change flag */
	int			path_change = FLAG_OFF;
	int			ii;		/* Working value : counter */
	uchar_t			cmd;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Check TxREQ send exec */
	if (scf_dscp_comtbl.tx_exec_flag == FLAG_OFF) {
		goto END_dscp_txend_recv;
	}

	/* Check local control data flag */
	if (scf_dscp_comtbl.tx_local_use_flag == FLAG_OFF) {
		/* Get TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_get];
	} else {
		/* Get local data TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_local];
	}

	/* Save TxDSR status information in TxDSC */
	wk_dsc.base.c_flag = statep->reg_txdsr_c_flag;
	dsc_p->dinfo.bdsr.status = wk_dsc.bdsr.status;
	SCFDBGMSG1(SCF_DBGFLAG_DSCP, "TxEND status = 0x%02x",
		dsc_p->dinfo.bdsr.status);

	/* Check TxREQ offset and TxEND offset */
	if (dsc_p->dinfo.base.offset != statep->reg_txdsr_c_offset) {
		goto END_dscp_txend_recv;
	}

	/* TxACK and TxEND timer stop */
	scf_timer_stop(SCF_TIMERCD_DSCP_ACK);
	scf_timer_stop(SCF_TIMERCD_DSCP_END);

	/* Get main table address from "id" */
	mainp = scf_dscp_id2mainp(dsc_p->dinfo.bdcr.id);

	/*
	 * Check mainp address or local control data(DSCP_PATH)
	 */
	if ((mainp == NULL) &&
		(dsc_p->dinfo.bdcr.id != DSC_CNTL_LOCAL)) {
		goto END_dscp_txend_recv;
	}

	cmd = (uchar_t)(dsc_p->dinfo.base.c_flag >> 8);

	/* Check TxDSC status */
	switch (dsc_p->status) {
	case SCF_TX_ST_TXACK_RECV_WAIT:
		/* TxDSC status (SC0) */
	case SCF_TX_ST_TXEND_RECV_WAIT:
		/* TxDSC status (SC1) */
		/* Check TxREQ end status */
		switch (dsc_p->dinfo.bdsr.status) {
		case DSC_STATUS_NORMAL:		/* Normal end */
			/* Error counter initialization */
			scf_dscp_comtbl.tx_ackto_retry_cnt = 0;
			scf_dscp_comtbl.tx_endto_retry_cnt = 0;
			scf_dscp_comtbl.tx_busy_retry_cnt = 0;
			scf_dscp_comtbl.tx_interface_retry_cnt = 0;
			scf_dscp_comtbl.tx_nak_retry_cnt = 0;
			scf_dscp_comtbl.tx_notsuop_retry_cnt = 0;
			scf_dscp_comtbl.tx_prmerr_retry_cnt = 0;
			scf_dscp_comtbl.tx_seqerr_retry_cnt = 0;
			scf_dscp_comtbl.tx_other_retry_cnt = 0;
			scf_dscp_comtbl.tx_send_retry_cnt = 0;

			/* Check local control data(DSCP_PATH) */
			if (dsc_p->dinfo.bdcr.id != DSC_CNTL_LOCAL) {
				/* TxEND notice to main matrix */
				scf_dscp_txend_notice(mainp);
			}
			break;

		case DSC_STATUS_BUF_BUSY:	/* Buffer busy */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__,
				&dsc_p->dinfo.base.c_flag, TC_INFO_SIZE);

			/* memo counter up */
			scf_dscp_comtbl.tx_busy_memo_cnt++;

			/* TxREQ code check */
			if (dsc_p->dinfo.bdcr.code == DSC_CNTL_INIT_REQ) {
				/* Check main status */
				if (mainp->status ==
					SCF_ST_EST_TXEND_RECV_WAIT) {
					/* INIT_REQ retry timer start */
					scf_timer_start(mainp->timer_code);
				}
				break;
			}

			/* Check re-try counter */
			if ((scf_dscp_comtbl.tx_busy_retry_cnt <
				scf_dscp_comtbl.tx_busy_maxretry_cnt) &&
					(scf_dscp_comtbl.tx_send_retry_cnt <
					scf_dscp_comtbl.tx_send_maxretry_cnt)) {
				/* re-try count up */
				scf_dscp_comtbl.tx_busy_retry_cnt++;
				scf_dscp_comtbl.tx_send_retry_cnt++;

				/* TxREQ busy timer start */
				scf_timer_start(SCF_TIMERCD_DSCP_BUSY);

				/* Change TxDSC status (SB2) */
				SCF_SET_DSC_STATUS(dsc_p,
					SCF_TX_ST_TXREQ_SEND_WAIT);

				/* TxDSC not release */
				norel_txdsc = FLAG_ON;
			} else {
				/* Buffer busy end re-try error */
				cmn_err(CE_WARN,
					"%s,Buffer busy occurred in XSCF. "
					"DSCP command = 0x%02x\n",
						&statep->pathname[0], cmd);

				/* Check local control data(DSCP_PATH) */
				if (dsc_p->dinfo.bdcr.id != DSC_CNTL_LOCAL) {
					/* TxEND notice to main matrix */
					scf_dscp_txend_notice(mainp);
				} else {
					/* DSCP path change send flag ON */
					scf_dscp_comtbl.dscp_path_flag =
						FLAG_ON;
				}
			}
			break;

		case DSC_STATUS_INTERFACE:	/* Interface error */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__,
				&dsc_p->dinfo.base.c_flag, TC_INFO_SIZE);

			/* memo counter up */
			scf_dscp_comtbl.tx_interface_memo_cnt++;

			/* Check re-try counter */
			if ((scf_dscp_comtbl.tx_interface_retry_cnt <
				scf_dscp_comtbl.tx_interface_maxretry_cnt) &&
					(scf_dscp_comtbl.tx_send_retry_cnt <
					scf_dscp_comtbl.tx_send_maxretry_cnt)) {
				/* re-try count up */
				scf_dscp_comtbl.tx_interface_retry_cnt++;
				scf_dscp_comtbl.tx_send_retry_cnt++;

				/* Change TxDSC status (SB2) */
				SCF_SET_DSC_STATUS(dsc_p,
					SCF_TX_ST_TXREQ_SEND_WAIT);

				/* TxDSC not release */
				norel_txdsc = FLAG_ON;
			} else {
				/* Interface error end re-try error */
				cmn_err(CE_WARN,
					"%s,Detected the interface error by "
					"XSCF. DSCP command = 0x%02x\n",
						&statep->pathname[0], cmd);

				/* Set hard error flag */
				statep->scf_herr |= HERR_DSCP_INTERFACE;

				/* SCF path change flag ON */
				path_change = FLAG_ON;
			}
			break;

		case DSC_STATUS_CONN_NAK:	/* Connection refusal */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__,
				&dsc_p->dinfo.base.c_flag, TC_INFO_SIZE);

			/* memo counter up */
			scf_dscp_comtbl.tx_nak_memo_cnt++;

			/* TxREQ code check */
			if (dsc_p->dinfo.bdcr.code == DSC_CNTL_INIT_REQ) {
				/* Check main status */
				if (mainp->status ==
					SCF_ST_EST_TXEND_RECV_WAIT) {
					/* INIT_REQ retry timer start */
					scf_timer_start(mainp->timer_code);
				}
				break;
			}

			/* Check re-try counter */
			if ((scf_dscp_comtbl.tx_nak_retry_cnt <
				scf_dscp_comtbl.tx_nak_maxretry_cnt) &&
					(scf_dscp_comtbl.tx_send_retry_cnt <
					scf_dscp_comtbl.tx_send_maxretry_cnt)) {
				/* re-try count up */
				scf_dscp_comtbl.tx_nak_retry_cnt++;
				scf_dscp_comtbl.tx_send_retry_cnt++;

				/* Change TxDSC status (SB2) */
				SCF_SET_DSC_STATUS(dsc_p,
					SCF_TX_ST_TXREQ_SEND_WAIT);

				/* TxDSC not release */
				norel_txdsc = FLAG_ON;
			} else {
				/* Connection refusal end re-try error */

				/* Check local control data(DSCP_PATH) */
				if (dsc_p->dinfo.bdcr.id != DSC_CNTL_LOCAL) {
					/* TxEND notice to main matrix */
					scf_dscp_txend_notice(mainp);
				} else {
					/* Set hard error flag */
					statep->scf_herr |= HERR_DSCP_INTERFACE;

					/* SCF path change flag ON */
					path_change = FLAG_ON;
				}
			}
			break;

		case DSC_STATUS_E_NOT_SUPPORT:	/* Not support */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__,
				&dsc_p->dinfo.base.c_flag, TC_INFO_SIZE);

			/* memo counter up */
			scf_dscp_comtbl.tx_notsuop_memo_cnt++;

			/* Check re-try counter */
			if ((scf_dscp_comtbl.tx_notsuop_retry_cnt <
				scf_dscp_comtbl.tx_notsup_maxretry_cnt) &&
					(scf_dscp_comtbl.tx_send_retry_cnt <
					scf_dscp_comtbl.tx_send_maxretry_cnt)) {
				/* re-try count up */
				scf_dscp_comtbl.tx_notsuop_retry_cnt++;
				scf_dscp_comtbl.tx_send_retry_cnt++;

				/* Change TxDSC status (SB2) */
				SCF_SET_DSC_STATUS(dsc_p,
					SCF_TX_ST_TXREQ_SEND_WAIT);

				/* TxDSC not release */
				norel_txdsc = FLAG_ON;
			} else {
				/* Not support end re-try error */
				cmn_err(CE_WARN,
					"%s,Detected the not support command "
					"by XSCF. DSCP command = 0x%02x\n",
						&statep->pathname[0], cmd);

				/* Check local control data(DSCP_PATH) */
				if (dsc_p->dinfo.bdcr.id != DSC_CNTL_LOCAL) {
					/* TxEND notice to main matrix */
					scf_dscp_txend_notice(mainp);
				} else {
					/* DSCP path change send flag ON */
					scf_dscp_comtbl.dscp_path_flag =
						FLAG_ON;
				}
			}
			break;

		case DSC_STATUS_E_PARAM:	/* Parameter error */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__,
				&dsc_p->dinfo.base.c_flag, TC_INFO_SIZE);

			/* memo counter up */
			scf_dscp_comtbl.tx_prmerr_memo_cnt++;

			/* Check re-try counter */
			if ((scf_dscp_comtbl.tx_prmerr_retry_cnt <
				scf_dscp_comtbl.tx_prmerr_maxretry_cnt) &&
					(scf_dscp_comtbl.tx_send_retry_cnt <
					scf_dscp_comtbl.tx_send_maxretry_cnt)) {
				/* re-try count up */
				scf_dscp_comtbl.tx_prmerr_retry_cnt++;
				scf_dscp_comtbl.tx_send_retry_cnt++;

				/* Change TxDSC status (SB2) */
				SCF_SET_DSC_STATUS(dsc_p,
					SCF_TX_ST_TXREQ_SEND_WAIT);

				/* TxDSC not release */
				norel_txdsc = FLAG_ON;
			} else {
				/* Parameter error end re-try error */
				cmn_err(CE_WARN,
					"%s,Detected the invalid parameter by "
					"XSCF. DSCP command = 0x%02x\n",
						&statep->pathname[0], cmd);

				/* Check local control data(DSCP_PATH) */
				if (dsc_p->dinfo.bdcr.id != DSC_CNTL_LOCAL) {
					/* TxEND notice to main matrix */
					scf_dscp_txend_notice(mainp);
				} else {
					/* DSCP path change send flag ON */
					scf_dscp_comtbl.dscp_path_flag =
						FLAG_ON;
				}
			}
			break;

		case DSC_STATUS_E_SEQUENCE:	/* Sequence error */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__,
				&dsc_p->dinfo.base.c_flag, TC_INFO_SIZE);

			/* memo counter up */
			scf_dscp_comtbl.tx_seqerr_memo_cnt++;

			/* Check re-try counter */
			if ((scf_dscp_comtbl.tx_seqerr_retry_cnt <
				scf_dscp_comtbl.tx_seqerr_maxretry_cnt) &&
					(scf_dscp_comtbl.tx_send_retry_cnt <
					scf_dscp_comtbl.tx_send_maxretry_cnt)) {
				/* re-try count up */
				scf_dscp_comtbl.tx_seqerr_retry_cnt++;
				scf_dscp_comtbl.tx_send_retry_cnt++;

				/* Change TxDSC status (SB2) */
				SCF_SET_DSC_STATUS(dsc_p,
					SCF_TX_ST_TXREQ_SEND_WAIT);

				/* TxDSC not release */
				norel_txdsc = FLAG_ON;
			} else {
				/* Sequence error end re-try error */
				cmn_err(CE_WARN,
					"%s,Detected the sequence error by "
					"XSCF. DSCP command = 0x%02x\n",
						&statep->pathname[0], cmd);

				/* Check local control data(DSCP_PATH) */
				if (dsc_p->dinfo.bdcr.id != DSC_CNTL_LOCAL) {
					/* TxEND notice to main matrix */
					scf_dscp_txend_notice(mainp);
				} else {
					/* DSCP path change send flag ON */
					scf_dscp_comtbl.dscp_path_flag =
						FLAG_ON;
				}
			}
			break;

		default:			/* Other status */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__,
				&dsc_p->dinfo.base.c_flag, TC_INFO_SIZE);

			/* memo counter up */
			scf_dscp_comtbl.tx_other_memo_cnt++;

			/* Check re-try counter */
			if ((scf_dscp_comtbl.tx_other_retry_cnt <
				scf_dscp_comtbl.tx_other_maxretry_cnt) &&
					(scf_dscp_comtbl.tx_send_retry_cnt <
					scf_dscp_comtbl.tx_send_maxretry_cnt)) {
				/* re-try count up */
				scf_dscp_comtbl.tx_other_retry_cnt++;
				scf_dscp_comtbl.tx_send_retry_cnt++;

				/* Change TxDSC status (SB2) */
				SCF_SET_DSC_STATUS(dsc_p,
					SCF_TX_ST_TXREQ_SEND_WAIT);

				/* TxDSC not release */
				norel_txdsc = FLAG_ON;
			} else {
				/* Other error end re-try error */
				cmn_err(CE_WARN,
					"%s,Invalid status value was notified "
					"from XSCF. DSCP command = 0x%02x, "
					"Status value = 0x%02x\n",
						&statep->pathname[0], cmd,
						(uchar_t)
						dsc_p->dinfo.base.c_flag);

				/* Check local control data(DSCP_PATH) */
				if (dsc_p->dinfo.bdcr.id != DSC_CNTL_LOCAL) {
					/* TxEND notice to main matrix */
					scf_dscp_txend_notice(mainp);
				} else {
					/* DSCP path change send flag ON */
					scf_dscp_comtbl.dscp_path_flag =
						FLAG_ON;
				}
			}
			break;
		}
		break;

	default:
		/* TxDSC status != SC0 or SC1 is NOP */
		break;
	}

	/* Check TxDSC not release */
	if (norel_txdsc == FLAG_OFF) {
		/* Check send data */
		if (dsc_p->dinfo.base.dscp_datap != NULL) {
			/* Send data release */
			kmem_free(dsc_p->dinfo.base.dscp_datap,
				dsc_p->dinfo.base.length);
			dsc_p->dinfo.base.dscp_datap = NULL;
		}

		/* Check SRAM data */
		if (dsc_p->dinfo.base.offset != DSC_OFFSET_NOTHING) {
			/* Send SRAM data release */
			scf_dscp_sram_free(dsc_p->dinfo.base.offset);
			dsc_p->dinfo.base.offset = DSC_OFFSET_NOTHING;
		}

		/* Change TxDSC status (SA0) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_IDLE);

		/* Check use local control TxDSC flag */
		if (scf_dscp_comtbl.tx_local_use_flag == FLAG_OFF) {
			/* Update Tx descriptor offset */
			if (scf_dscp_comtbl.tx_get == scf_dscp_comtbl.tx_last) {
				scf_dscp_comtbl.tx_get =
					scf_dscp_comtbl.tx_first;
			} else {
				scf_dscp_comtbl.tx_get++;
			}

			/* Update Tx descriptor count */
			scf_dscp_comtbl.tx_dsc_count--;

			/* Get Top main table address */
			mainp = &scf_dscp_comtbl.scf_dscp_main[0];
			/* Check main table */
			for (ii = 0; ii < MBIF_MAX; ii++, mainp++) {
				/* Check putmsg busy release */
				if ((mainp->putmsg_busy_flag == FLAG_ON) &&
					(scf_dscp_comtbl.tx_dsc_count <
					scf_dscp_comtbl.txdsc_busycount)) {
					/* putmsg busy flag OFF */
					mainp->putmsg_busy_flag = FLAG_OFF;

					/* TxREL_BUSY notice to main matrix */
					scf_dscp_txrelbusy_notice(mainp);
				}
			}
		} else {
			/* Initialize use local control TxDSC flag */
			scf_dscp_comtbl.tx_local_use_flag = FLAG_OFF;

			/* DSCP path change send flag OFF */
			scf_dscp_comtbl.dscp_path_flag = FLAG_OFF;
		}
	}
	/* TxREQ send exec flag OFF */
	scf_dscp_comtbl.tx_exec_flag = FLAG_OFF;

	/* Check SCF path change flag */
	if (path_change == FLAG_OFF) {
		/* Call send matrix */
		scf_dscp_send_matrix();
	} else {
		/* SCF path change */
		scf_path_change(statep);
	}

/*
 * END_dscp_txend_recv
 */
	END_dscp_txend_recv:

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_rxreq_recv()
 *
 * Description: TxREQ reception notifies to a main control matrix.
 *
 */
void
scf_dscp_rxreq_recv(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_rxreq_recv() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	scf_dscp_dsc_t		*dsc_p;		/* RxDSC address */
	uint16_t		offset_low;	/* Working value : offset */
	uint16_t		offset_hight;	/* Working value : offset */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Check pending RxDSC */
	if (scf_dscp_comtbl.rx_dsc_count == 0) {
		/* Get RxDSC address */
		dsc_p = &scf_dscp_comtbl.rx_dscp[scf_dscp_comtbl.rx_put];

		/* Save RxDCR information in RxDSC */
		dsc_p->dinfo.base.c_flag = statep->reg_rxdcr_c_flag;
		dsc_p->dinfo.base.offset = statep->reg_rxdcr_c_offset;
		dsc_p->dinfo.base.length = statep->reg_rxdcr_c_length;
		dsc_p->dinfo.bdsr.status = DSC_STATUS_NORMAL;
		dsc_p->dinfo.base.dscp_datap = NULL;

		/* Update Rx descriptor offset */
		if (scf_dscp_comtbl.rx_put == scf_dscp_comtbl.rx_last) {
			scf_dscp_comtbl.rx_put = scf_dscp_comtbl.rx_first;
		} else {
			scf_dscp_comtbl.rx_put++;
		}

		/* Update Rx descriptor count */
		scf_dscp_comtbl.rx_dsc_count++;

		/* RxREQ receive exec flag ON */
		scf_dscp_comtbl.rx_exec_flag = FLAG_ON;

		/* Get main table address from "id" */
		mainp = scf_dscp_id2mainp(dsc_p->dinfo.bdcr.id);

		offset_low = (uint16_t)(scf_dscp_comtbl.txbuffsize *
			scf_dscp_comtbl.txsram_maxcount / DSC_OFFSET_CONVERT);

		SCF_DBG_MAKE_LOOPBACK(offset_low);

		offset_hight =
			(uint16_t)(offset_low + scf_dscp_comtbl.rxbuffsize *
			scf_dscp_comtbl.rxsram_maxcount / DSC_OFFSET_CONVERT);

		/* Check mainp address and offset */
		if ((mainp != NULL) &&
			(((dsc_p->dinfo.base.offset >= offset_low) &&
			(dsc_p->dinfo.base.offset < offset_hight)) ||
			((dsc_p->dinfo.base.offset == DSC_OFFSET_NOTHING) &&
			(dsc_p->dinfo.bdcr.code != DSC_CNTL_DATA_REQ)))) {
			/* RxREQ notice to main matrix */
			scf_dscp_rxreq_notice(mainp);
		} else {
			/* Invalid "id" or "offset" */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__,
				&dsc_p->dinfo.base.c_flag, TC_INFO_SIZE);
			SCFDBGMSG(SCF_DBGFLAG_DSCP, "Invalid id or offset");

			/* Set end status : Parameter error */
			dsc_p->dinfo.bdsr.status = DSC_STATUS_E_PARAM;

			/* Change RxDSC status (RB3) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_RXEND_SEND_WAIT);

			/* Call receive matrix */
			scf_dscp_recv_matrix();
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * Main and Tx/Rx interface function
 */

/*
 * scf_dscp_txend_notice()
 *
 * Description: The TxEND reception is notified of by Tx matrix and handle it
 * with data code.
 *
 */
void
scf_dscp_txend_notice(scf_dscp_main_t *mainp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_txend_notice() "
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Check local control data flag */
	if (scf_dscp_comtbl.tx_local_use_flag == FLAG_OFF) {
		/* Get TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_get];
	} else {
		/* Get local data TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_local];
	}

	/* TxREQ code check */
	switch (dsc_p->dinfo.bdcr.code) {
	case DSC_CNTL_INIT_REQ:				/* INIT_REQ */
		/* Check main status */
		if (mainp->status == SCF_ST_EST_TXEND_RECV_WAIT) {
			/* Main status (B0) */
			/* Check end status */
			if (dsc_p->dinfo.bdsr.status == DSC_STATUS_NORMAL) {
				/* SCF_MB_CONN_OK event queuing */
				scf_dscp_event_queue(mainp, SCF_MB_CONN_OK);

				/* Change main status (C0) */
				SCF_SET_STATUS(mainp, SCF_ST_ESTABLISHED);
			} else {
				/* Not normal end status */

				/* SCF_MB_DISC_ERROR event queuing */
				scf_dscp_event_queue(mainp, SCF_MB_DISC_ERROR);

				/* Change main status (C1) */
				SCF_SET_STATUS(mainp, SCF_ST_EST_FINI_WAIT);
			}
		}
		break;

	case DSC_CNTL_FINI_REQ:				/* FINI_REQ */
		/* Check main status */
		if (mainp->status == SCF_ST_CLOSE_TXEND_RECV_WAIT) {
			/* Main status (D0) */
			/* Signal to fini() wait */
			mainp->fini_wait_flag = FLAG_OFF;
			cv_signal(&mainp->fini_cv);
			SC_DBG_DRV_TRACE(TC_SIGNAL, __LINE__, &mainp->fini_cv,
				sizeof (kcondvar_t));
		}
		break;

	case DSC_CNTL_CONN_CHK:				/* CONN_CHK */
		/* Check main status */
		switch (mainp->status) {
		case SCF_ST_EST_TXEND_RECV_WAIT:	/* Main status (B0) */
		case SCF_ST_ESTABLISHED:		/* Main status (C0) */
			/* CONN_CHK flag OFF */
			mainp->conn_chk_flag = FLAG_OFF;
			/* Check end status */
			if (dsc_p->dinfo.bdsr.status != DSC_STATUS_NORMAL) {
				/* SCF_MB_DISC_ERROR event queuing */
				scf_dscp_event_queue(mainp, SCF_MB_DISC_ERROR);

				/* Change main status (C1) */
				SCF_SET_STATUS(mainp, SCF_ST_EST_FINI_WAIT);
			}
			break;

		default:
			/* Main status != B0 or C0 is NOP */
			break;
		}
		break;

	case DSC_CNTL_DATA_REQ:				/* DATA_REQ */
		/* Tx DATA_REQ ok counter up */
		mainp->memo_tx_data_req_ok_cnt++;
		break;

	default:
		/* Undefine TxREQ code is NOP */
		break;
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_txrelbusy_notice()
 *
 * Description: Tx busy release is notified of by Tx matrix and perform event
 * queue processing.
 *
 */
void
scf_dscp_txrelbusy_notice(scf_dscp_main_t *mainp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_txrelbusy_notice() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Check main status */
	if (mainp->status == SCF_ST_ESTABLISHED) {	/* Main status (C0) */
		/* SCF_MB_SPACE event queuing */
		scf_dscp_event_queue(mainp, SCF_MB_SPACE);
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_rxreq_notice()
 *
 * Description: The RxREQ reception is notified of by Rx matrix and handle it
 * with data code.
 *
 */
void
scf_dscp_rxreq_notice(scf_dscp_main_t *mainp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_rxreq_notice() "
	scf_dscp_dsc_t		*dsc_p;		/* RxDSC address */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Get RxDSC address */
	dsc_p = &scf_dscp_comtbl.rx_dscp[scf_dscp_comtbl.rx_get];

	/* RxREQ code check */
	switch (dsc_p->dinfo.bdcr.code) {
	case DSC_CNTL_INIT_REQ:				/* INIT_REQ */
		/* Set end status : Not support */
		dsc_p->dinfo.bdsr.status = DSC_STATUS_E_NOT_SUPPORT;

		/* Change RxDSC status (RB3) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_RXEND_SEND_WAIT);

		/* Call receive matrix */
		scf_dscp_recv_matrix();
		break;

	case DSC_CNTL_FINI_REQ:				/* FINI_REQ */
		/* Check main status */
		switch (mainp->status) {
		case SCF_ST_EST_TXEND_RECV_WAIT:	/* Main status (B0) */
		case SCF_ST_ESTABLISHED:		/* Main status (C0) */
			/* SCF_MB_DISC_ERROR event queuing */
			scf_dscp_event_queue(mainp, SCF_MB_DISC_ERROR);

			/* Change main status (C1) */
			SCF_SET_STATUS(mainp, SCF_ST_EST_FINI_WAIT);
			break;

		default:
			/* Main status != B0 or C0 is NOP */
			break;
		}

		/* Set end status : Normal end */
		dsc_p->dinfo.bdsr.status = DSC_STATUS_NORMAL;

		/* Change RxDSC status (RB3) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_RXEND_SEND_WAIT);

		/* Call receive matrix */
		scf_dscp_recv_matrix();
		break;

	case DSC_CNTL_DATA_REQ:				/* DATA_REQ */
		/* Rx DATA_REQ counter up */
		mainp->memo_rx_data_req_cnt++;

		/* Check receive data length */
		if (dsc_p->dinfo.base.length <= scf_dscp_comtbl.maxdatalen) {
			/* Check receive data queue space */
			if (mainp->rd_count < mainp->rd_busycount) {
				/* Set end status : Normal end */
				dsc_p->dinfo.bdsr.status = DSC_STATUS_NORMAL;

				/* Check main status */
				if (mainp->status == SCF_ST_ESTABLISHED) {
					/* Main status (C0) */
					/* Change RxDSC status (RB0) */
					SCF_SET_DSC_STATUS(dsc_p,
						SCF_RX_ST_RXACK_SEND_WAIT);
				} else {
					/* Change RxDSC status (RB3) */
					SCF_SET_DSC_STATUS(dsc_p,
						SCF_RX_ST_RXEND_SEND_WAIT);
				}
			} else {
				/* No space of receive data queue */

				/* Set end status : Buffer busy */
				dsc_p->dinfo.bdsr.status = DSC_STATUS_BUF_BUSY;

				/* Change RxDSC status (RB3) */
				SCF_SET_DSC_STATUS(dsc_p,
					SCF_RX_ST_RXEND_SEND_WAIT);
			}
		} else {
			/* Invalid deta length */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__,
				&dsc_p->dinfo.base.length,
				sizeof (dsc_p->dinfo.base.length));

			/* Set end status : Parameter error */
			dsc_p->dinfo.bdsr.status = DSC_STATUS_E_PARAM;

			/* Change RxDSC status (RB3) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_RXEND_SEND_WAIT);
		}

		/* Call receive matrix */
		scf_dscp_recv_matrix();
		break;

	case DSC_CNTL_CONN_CHK:				/* CONN_CHK */
		/* Check main status */
		if (mainp->status == SCF_ST_ESTABLISHED) {
			/* Main status (C0) */
			/* Set end status : Normal end */
			dsc_p->dinfo.bdsr.status = DSC_STATUS_NORMAL;
		} else {
			/* Set end status : Connection refusal */
			dsc_p->dinfo.bdsr.status = DSC_STATUS_CONN_NAK;
		}

		/* Change RxDSC status (RB3) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_RXEND_SEND_WAIT);

		/* Call receive matrix */
		scf_dscp_recv_matrix();
		break;

	default:
		/* Invalid RxREQ code */
		SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__, &dsc_p->dinfo.base.c_flag,
			TC_INFO_SIZE);

		/* Set end status : Parameter error */
		dsc_p->dinfo.bdsr.status = DSC_STATUS_E_PARAM;

		/* Change RxDSC status (RB3) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_RXEND_SEND_WAIT);

		/* Call receive matrix */
		scf_dscp_recv_matrix();
		break;
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_rxdata_notice()
 *
 * Description: It is notified from a Rx control matrix, the received data are
 * read from SRAM,
 *		and the notice of a receive data event is performed.
 *
 */
void
scf_dscp_rxdata_notice(scf_dscp_main_t *mainp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_rxdata_notice() "
	scf_dscp_dsc_t		*dsc_p;		/* RxDSC address */
	scf_rdata_que_t		*rdt_p;		/* Receive data queue address */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Get RxDSC address */
	dsc_p = &scf_dscp_comtbl.rx_dscp[scf_dscp_comtbl.rx_get];

	/* Check main status */
	switch (mainp->status) {
	case SCF_ST_ESTABLISHED:			/* Main status (C0) */
	case SCF_ST_EST_FINI_WAIT:			/* Main status (C1) */
		/* Check receive data queue space */
		if (mainp->rd_count < mainp->rd_busycount) {
			/* Receive data queing */
			rdt_p = &mainp->rd_datap[mainp->rd_put];
			rdt_p->rdatap = dsc_p->dinfo.base.dscp_datap;
			dsc_p->dinfo.base.dscp_datap = NULL;
			rdt_p->length = dsc_p->dinfo.base.length;

			/* Update receive data queue offset */
			if (mainp->rd_put == mainp->rd_last) {
				mainp->rd_put = mainp->rd_first;
			} else {
				mainp->rd_put++;
			}

			/* Update receive data queue count */
			mainp->rd_count++;

			/* SCF_MB_MSG_DATA event queuing */
			scf_dscp_event_queue(mainp, SCF_MB_MSG_DATA);

			/* Rx DATA_REQ ok counter up */
			mainp->memo_rx_data_req_ok_cnt++;
		} else {
			/* No space of receive data queue */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__, &mainp->rd_count,
				sizeof (mainp->rd_count));
			SCFDBGMSG(SCF_DBGFLAG_DSCP,
				"No space of receive data queue");

			/* Check receive data */
			if (dsc_p->dinfo.base.dscp_datap != NULL) {
				/* Receive data release  */
				kmem_free(dsc_p->dinfo.base.dscp_datap,
					dsc_p->dinfo.base.length);
				dsc_p->dinfo.base.dscp_datap = NULL;
			}

			/* Set end status : Buffer busy */
			dsc_p->dinfo.bdsr.status = DSC_STATUS_BUF_BUSY;

			/* Change RxDSC status (RB3) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_RXEND_SEND_WAIT);
		}
		break;

	case SCF_ST_CLOSE_TXEND_RECV_WAIT:		/* Main status (D0) */
		/* Check receive data */
		if (dsc_p->dinfo.base.dscp_datap != NULL) {
			/* Receive data release  */
			kmem_free(dsc_p->dinfo.base.dscp_datap,
				dsc_p->dinfo.base.length);
			dsc_p->dinfo.base.dscp_datap = NULL;
		}

		/* Set end status : Normal end */
		dsc_p->dinfo.bdsr.status = DSC_STATUS_NORMAL;

		/* Change RxDSC status (RB3) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_RXEND_SEND_WAIT);
		break;

	default:
		SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__, &mainp->status,
			TC_INFO_SIZE);
		SCFDBGMSG(SCF_DBGFLAG_DSCP, "Sequence error");

		/* Check receive data */
		if (dsc_p->dinfo.base.dscp_datap != NULL) {
			/* Receive data release  */
			kmem_free(dsc_p->dinfo.base.dscp_datap,
				dsc_p->dinfo.base.length);
			dsc_p->dinfo.base.dscp_datap = NULL;
		}

		/* Set end status : Sequence error */
		dsc_p->dinfo.bdsr.status = DSC_STATUS_E_SEQUENCE;

		/* Change RxDSC status (RB3) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_RXEND_SEND_WAIT);
		break;
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * Tx subroutine function
 */

/*
 * scf_dscp_send_matrix()
 *
 * Description: The Request to Send by a Tx descriptor state is performed.
 *
 */
void
scf_dscp_send_matrix(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_send_matrix() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */
	scf_state_t		*statep;	/* Soft state pointer */
	uint8_t			*wk_in_p; /* Working value : input address */
	uint8_t			*wk_out_p; /* Working value : output address */
	/*  Working value : next processing check flag */
	int			next_send_req = FLAG_OFF;
	int			path_ret; /* SCF path status return value */
	int			timer_ret;	/* Timer check return value */
	int			ii;		/* Working value : counter */
	uint16_t		tx_local = scf_dscp_comtbl.tx_local;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	SCF_DBG_MAKE_NO_DSCP_PATH(scf_dscp_comtbl.dscp_path_flag);

/*
 * SEND_MATRIX_START
 */
	SEND_MATRIX_START:

	/* Check use local control TxDSC send */
	if ((scf_dscp_comtbl.tx_local_use_flag == FLAG_OFF) &&
		/* Check DSCP path change data send */
		(scf_dscp_comtbl.dscp_path_flag == FLAG_ON)) {
		/* Set use local control TxDSC flag */
		scf_dscp_comtbl.tx_local_use_flag = FLAG_ON;

		/* Get local data TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[tx_local];

		/* Make Tx descriptor : DSCP_PATH */
		dsc_p->dinfo.base.c_flag = DSC_FLAG_DEFAULT;
		dsc_p->dinfo.base.offset = DSC_OFFSET_NOTHING;
		dsc_p->dinfo.base.length = 0;
		dsc_p->dinfo.base.dscp_datap = NULL;
		dsc_p->dinfo.bdcr.id = DSC_CNTL_LOCAL;
		dsc_p->dinfo.bdcr.code = DSC_CNTL_DSCP_PATH;

		/* Change TxDSC status (SB2) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_TXREQ_SEND_WAIT);
	} else if ((scf_dscp_comtbl.tx_local_use_flag == FLAG_OFF) &&
		(scf_dscp_comtbl.dscp_path_flag == FLAG_OFF)) {
		/* Initialize use local control TxDSC flag */
		scf_dscp_comtbl.tx_local_use_flag = FLAG_OFF;

		/* Get TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[scf_dscp_comtbl.tx_get];

		/* Get top main table address */
		mainp = &scf_dscp_comtbl.scf_dscp_main[0];
		for (ii = 0; ii < MBIF_MAX; ii++, mainp++) {
			/*
			 * Check DSCP connect data send and not local
			 * control TxDSC send
			 */
			if ((mainp->conn_chk_flag == FLAG_OFF) ||
				(scf_dscp_comtbl.tx_local_use_flag ==
				FLAG_ON)) {
				break;
			}
			/* Check main status */
			switch (mainp->status) {
			case SCF_ST_EST_TXEND_RECV_WAIT:
				/* Main status (B0) */
			case SCF_ST_ESTABLISHED:
				/* Main status (C0) */
				/*
				 * Set use local control TxDSC flag
				 */
				scf_dscp_comtbl.tx_local_use_flag = FLAG_ON;

				/*
				 * Get local data TxDSC address
				 */
				dsc_p = &scf_dscp_comtbl.tx_dscp[tx_local];

				/*
				 * Make Tx descriptor : CONN_CHK
				 */
				dsc_p->dinfo.base.c_flag = DSC_FLAG_DEFAULT;
				dsc_p->dinfo.base.offset = DSC_OFFSET_NOTHING;
				dsc_p->dinfo.base.length = 0;
				dsc_p->dinfo.base.dscp_datap = NULL;
				dsc_p->dinfo.bdcr.id = mainp->id & 0x0f;
				dsc_p->dinfo.bdcr.code = DSC_CNTL_CONN_CHK;

				/* Change TxDSC status (SB2) */
				SCF_SET_DSC_STATUS(dsc_p,
					SCF_TX_ST_TXREQ_SEND_WAIT);
				break;

			default:
				/*
				 * Clear DSCP connect check flag
				 */
				mainp->conn_chk_flag = FLAG_OFF;
				break;
			}
		}
	} else {
		/* Get local data TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[tx_local];
	}

	/* Check pending send TxDSC or local control TxDSC */
	if ((scf_dscp_comtbl.tx_dsc_count == 0) &&
		(scf_dscp_comtbl.tx_local_use_flag == FLAG_OFF)) {
		goto END_dscp_send_matrix;
	}

	/* Get SCF path status */
	path_ret = scf_path_check(&statep);
	/* Check TxDSC status */
	switch (dsc_p->status) {
	case SCF_TX_ST_IDLE:		/* TxDSC status (SA0) */
		/* TxDSC status == SA0 is next processing */
		if (scf_dscp_comtbl.tx_local_use_flag == FLAG_OFF) {
			/* Update Tx descriptor offset */
			if (scf_dscp_comtbl.tx_get == scf_dscp_comtbl.tx_last) {
				scf_dscp_comtbl.tx_get =
					scf_dscp_comtbl.tx_first;
			} else {
				scf_dscp_comtbl.tx_get++;
			}

			/* Update Tx descriptor count */
			scf_dscp_comtbl.tx_dsc_count--;
		} else {
			/* Initialize use local control TxDSC flag */
			scf_dscp_comtbl.tx_local_use_flag = FLAG_OFF;
		}

		/* Next processing flag ON */
		next_send_req = FLAG_ON;
		break;

	case SCF_TX_ST_SRAM_TRANS_WAIT:		/* TxDSC status (SB0) */
		/* Check SCF path status */
		if (path_ret != SCF_PATH_ONLINE) {
			break;
		}
		/* Data copy to SRAM */
		ii = dsc_p->dinfo.base.offset * DSC_OFFSET_CONVERT;
		wk_in_p = (uint8_t *)dsc_p->dinfo.base.dscp_datap;
		wk_out_p = (uint8_t *)&statep->scf_dscp_sram->DATA[ii];
		for (ii = 0; ii < dsc_p->dinfo.base.length;
			ii++, wk_in_p++, wk_out_p++) {
			SCF_DDI_PUT8(statep, statep->scf_dscp_sram_handle,
				wk_out_p, *wk_in_p);
		}

		/* Change TxDSC status (SB2) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_TXREQ_SEND_WAIT);

		/* Next processing flag ON */
		next_send_req = FLAG_ON;
		break;

	case SCF_TX_ST_TXREQ_SEND_WAIT:		/* TxDSC status (SB2) */
		/* Get timer status */
		timer_ret = scf_timer_check(SCF_TIMERCD_DSCP_BUSY);
		/* Check TxREQ busy timer exec */
		if (timer_ret == SCF_TIMER_EXEC) {
			break;
		}
		/* Check SCF path status */
		if (path_ret != SCF_PATH_ONLINE) {
			break;
		}
		/* Check TxREQ send exec */
		if (scf_dscp_comtbl.tx_exec_flag == FLAG_OFF) {
			/* TxREQ send */
			scf_dscp_txreq_send(statep, dsc_p);

			/* Check send data length */
			if (dsc_p->dinfo.base.length != 0) {
				/* TxACK timer start */
				scf_timer_start(SCF_TIMERCD_DSCP_ACK);

				/*
				 * Change TxDSC status (SC0)
				 */
				SCF_SET_DSC_STATUS(dsc_p,
					SCF_TX_ST_TXACK_RECV_WAIT);
			} else {
				/* TxEND timer start */
				scf_timer_start(SCF_TIMERCD_DSCP_END);

				/*
				 * Change TxDSC status (SC1)
				 */
				SCF_SET_DSC_STATUS(dsc_p,
					SCF_TX_ST_TXEND_RECV_WAIT);
			}
		}
		break;

	default:
		/* TxDSC status != SA0 or SB0 or SB2 is NOP */
		break;
	}

	/* Check next send processing */
	if (next_send_req == FLAG_ON) {
		next_send_req = FLAG_OFF;
		goto SEND_MATRIX_START;
	}

/*
 * END_dscp_send_matrix
 */
	END_dscp_send_matrix:

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_txreq_send()
 *
 * Description: TxREQ is transmitted by hard access.
 *
 */
void
scf_dscp_txreq_send(scf_state_t *statep, scf_dscp_dsc_t *dsc_p)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_txreq_send() "
	uint8_t			*wk_in_p; /* Working value : input address */
	uint8_t			*wk_out_p; /* Working value : output address */
	uint32_t		wkleng;		/* Working value : length */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Set control flag */
	dsc_p->dinfo.bdsr.status = 0;
	dsc_p->dinfo.base.c_flag |= DSC_FLAG_DEFAULT;

	/* Write TxDCR register */
	statep->reg_txdcr_c_flag = dsc_p->dinfo.base.c_flag;
	SCF_DDI_PUT16(statep, statep->scf_regs_handle,
		&statep->scf_regs->TxDCR_C_FLAG, statep->reg_txdcr_c_flag);
	SC_DBG_DRV_TRACE(TC_W_TxDCR_C_FLAG, __LINE__,
		&statep->reg_txdcr_c_flag, sizeof (statep->reg_txdcr_c_flag));

	statep->reg_txdcr_c_offset = dsc_p->dinfo.base.offset;
	SCF_DDI_PUT16(statep, statep->scf_regs_handle,
		&statep->scf_regs->TxDCR_OFFSET, statep->reg_txdcr_c_offset);
	SC_DBG_DRV_TRACE(TC_W_TxDCR_OFFSET, __LINE__,
		&statep->reg_txdcr_c_offset,
		sizeof (statep->reg_txdcr_c_offset));

	statep->reg_txdcr_c_length = dsc_p->dinfo.base.length;
	SCF_DDI_PUT32(statep, statep->scf_regs_handle,
		&statep->scf_regs->TxDCR_LENGTH, statep->reg_txdcr_c_length);
	SC_DBG_DRV_TRACE(TC_W_TxDCR_LENGTH, __LINE__,
		&statep->reg_txdcr_c_length,
		sizeof (statep->reg_txdcr_c_length));

	/* Write DCR register : TxREQ interrupt */
	statep->reg_dcr = DCR_TxREQ;
	SCF_DDI_PUT8(statep, statep->scf_regs_handle,
		&statep->scf_regs->DCR, statep->reg_dcr);
	SC_DBG_DRV_TRACE(TC_W_DCR, __LINE__, &statep->reg_dcr,
		sizeof (statep->reg_dcr));

	/* Register read sync */
	scf_rs8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
		&statep->scf_regs->DCR);

	SC_DBG_DRV_TRACE(TC_TxREQ, __LINE__, &statep->reg_txdcr_c_flag, 8);

	SCFDBGMSG1(SCF_DBGFLAG_REG, "DCR = 0x%02x", statep->reg_dcr);
	SCFDBGMSG3(SCF_DBGFLAG_REG, "TxDCR = 0x%04x 0x%04x 0x%08x",
		statep->reg_txdcr_c_flag, statep->reg_txdcr_c_offset,
		statep->reg_txdcr_c_length);

	/* TxREQ send exec flag ON */
	scf_dscp_comtbl.tx_exec_flag = FLAG_ON;

	/* SRAM trace */
	SCF_SRAM_TRACE(statep, DTC_DSCP_TXREQ);
	if (dsc_p->dinfo.base.length != 0) {
		wk_in_p = (uint8_t *)dsc_p->dinfo.base.dscp_datap;
		wk_out_p = (uint8_t *)&statep->memo_scf_drvtrc.INFO[0];
		if (dsc_p->dinfo.base.length >
			sizeof (statep->memo_scf_drvtrc.INFO)) {
			wkleng = sizeof (statep->memo_scf_drvtrc.INFO);
		} else {
			wkleng = dsc_p->dinfo.base.length;
		}
		bcopy(wk_in_p, wk_out_p, wkleng);
		SCF_SRAM_TRACE(statep, DTC_DSCP_SENDDATA);
	}

	SCF_DBG_TEST_TXREQ_SEND(statep, dsc_p);

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * Rx subroutine function
 */

/*
 * scf_dscp_recv_matrix()
 *
 * Description: TxREQ received performs the corresponding response request.
 *
 */
void
scf_dscp_recv_matrix(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_recv_matrix() "
	scf_dscp_main_t		*mainp;		/* Main table address */
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */
	scf_state_t		*statep;	/* Soft state pointer */
	caddr_t			wkaddr;	/* Working value : buffer address */
	uint8_t			*wk_in_p; /* Working value : input address */
	uint8_t			*wk_out_p; /* Working value : output address */
	uint32_t		wkleng;		/* Working value : length */
	uint32_t		info_size;
	/* Working value : next receive processing check flag */
	int			next_resp_req = FLAG_OFF;
	int			path_ret; /* SCF path status return value */
	int			ii;		/* Working value : counter */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

/*
 * RECV_MATRIX_START
 */
	RECV_MATRIX_START:

	/* Check pending RxDSC */
	if (scf_dscp_comtbl.rx_dsc_count == 0) {
		goto END_dscp_recv_matrix;
	}

	/* Get RxDSC address */
	dsc_p = &scf_dscp_comtbl.rx_dscp[scf_dscp_comtbl.rx_get];

	/* Get SCF path status */
	path_ret = scf_path_check(&statep);

	/* Check RxDSC status */
	switch (dsc_p->status) {
	case SCF_RX_ST_RXACK_SEND_WAIT:		/* RxDSC status (RB0) */
		/* Check SCF path status */
		if (path_ret != SCF_PATH_ONLINE) {
			break;
		}
		/* Check receive data length */
		if (dsc_p->dinfo.base.length != 0) {
			/* Rx buffer allocation */
			wkaddr = (caddr_t)kmem_zalloc(dsc_p->dinfo.base.length,
				KM_NOSLEEP);

			/* Set Rx buffer address */
			dsc_p->dinfo.base.dscp_datap = wkaddr;

			/* RxACK send */
			scf_dscp_rxack_send(statep);

			/* Change RxDSC status (RB1) */
			SCF_SET_DSC_STATUS(dsc_p,
				SCF_RX_ST_SRAM_TRANS_WAIT);
		} else {
			/* Change RxDSC status (RB3) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_RXEND_SEND_WAIT);
			break;
		}
		/* Next receive processing flag ON */
		next_resp_req = FLAG_ON;

		break;

	case SCF_RX_ST_SRAM_TRANS_WAIT:		/* RxDSC status (RB1) */
		/* Check SCF path status */
		if (path_ret != SCF_PATH_ONLINE) {
			break;
		}
		/* Get main table address from "id" */
		mainp = scf_dscp_id2mainp(dsc_p->dinfo.bdcr.id);

		/* Check mainp address */
		if (mainp != NULL) {
			/* Data copy from SRAM */
			ii = dsc_p->dinfo.base.offset * DSC_OFFSET_CONVERT;
			wk_in_p = &statep->scf_dscp_sram->DATA[ii];
			wk_out_p = (uint8_t *)dsc_p->dinfo.base.dscp_datap;
			for (ii = 0; ii < dsc_p->dinfo.base.length; ii++,
				wk_in_p++, wk_out_p++) {
				*wk_out_p = SCF_DDI_GET8(statep,
					statep->scf_dscp_sram_handle, wk_in_p);
			}

			/* Set end status : Normal end */
			dsc_p->dinfo.bdsr.status = DSC_STATUS_NORMAL;

			/* Change RxDSC status (RB3) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_RXEND_SEND_WAIT);

			/* STAM trace */
			info_size = sizeof (statep->memo_scf_drvtrc.INFO);
			if (dsc_p->dinfo.base.length != 0) {
				wk_in_p =
					(uint8_t *)dsc_p->dinfo.base.dscp_datap;
				wk_out_p = &statep->memo_scf_drvtrc.INFO[0];
				if (dsc_p->dinfo.base.length > info_size) {
					wkleng = info_size;
				} else {
					wkleng = dsc_p->dinfo.base.length;
				}
				bcopy(wk_in_p, wk_out_p, wkleng);
				SCF_SRAM_TRACE(statep, DTC_DSCP_RECVDATA);
			}

			/* Receive data notice to main matrix */
			scf_dscp_rxdata_notice(mainp);
		} else {
			/* Invalid "id" */
			SC_DBG_DRV_TRACE(TC_ERRCD, __LINE__,
				&dsc_p->dinfo.base.c_flag, TC_INFO_SIZE);
			SCFDBGMSG(SCF_DBGFLAG_DSCP, "Invalid id");

			/* Set end status : Parameter error */
			dsc_p->dinfo.bdsr.status = DSC_STATUS_E_PARAM;

			/* Change RxDSC status (RB3) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_RXEND_SEND_WAIT);
		}

		/* Next receive processing flag ON */
		next_resp_req = FLAG_ON;
		break;

	case SCF_RX_ST_RXEND_SEND_WAIT:		/* RxDSC status (RB3) */
		/* Is SCF path online? */
		if (path_ret != SCF_PATH_ONLINE) {
			break;
		}
		/* RxEND send */
		scf_dscp_rxend_send(statep, dsc_p);

		/* Change RxDSC status (RA0) */
		SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_IDLE);

		/* Update Rx descriptor offset */
		if (scf_dscp_comtbl.rx_get == scf_dscp_comtbl.rx_last) {
			scf_dscp_comtbl.rx_get = scf_dscp_comtbl.rx_first;
		} else {
			scf_dscp_comtbl.rx_get++;
		}

		/* Update Rx descriptor count */
		scf_dscp_comtbl.rx_dsc_count--;

		/* RxREQ receive exec flag OFF */
		scf_dscp_comtbl.rx_exec_flag = FLAG_OFF;
		break;

	default:
		/* RxDSC status == RA0 is NOP */
		break;
	}

	/* Check next receive processing */
	if (next_resp_req == FLAG_ON) {
		next_resp_req = FLAG_OFF;
		goto RECV_MATRIX_START;
	}

/*
 * END_dscp_recv_matrix
 */
	END_dscp_recv_matrix:

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_rxack_send()
 *
 * Description: RxACK is transmitted by hard access.
 *
 */
void
scf_dscp_rxack_send(scf_state_t *statep)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_rxack_send() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Write DCR register : RxACK interrupt */
	statep->reg_dcr = DCR_RxACK;
	SCF_DDI_PUT8(statep, statep->scf_regs_handle,
		&statep->scf_regs->DCR, statep->reg_dcr);
	SC_DBG_DRV_TRACE(TC_W_DCR, __LINE__, &statep->reg_dcr,
		sizeof (statep->reg_dcr));

	/* Register read sync */
	scf_rs8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
		&statep->scf_regs->DCR);

	SC_DBG_DRV_TRACE(TC_RxACK, __LINE__, NULL, 0);

	SCFDBGMSG1(SCF_DBGFLAG_REG, "DCR = 0x%02x", statep->reg_dcr);

	/* SRAM trace */
	SCF_SRAM_TRACE(statep, DTC_DSCP_RXACK);

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_rxend_send()
 *
 * Description: RxEND is transmitted by hard access.
 *
 */
void
scf_dscp_rxend_send(scf_state_t *statep, scf_dscp_dsc_t *dsc_p)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_rxend_send() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Write RxDSR register */
	statep->reg_rxdsr_c_flag = dsc_p->dinfo.base.c_flag;
	SCF_DDI_PUT16(statep, statep->scf_regs_handle,
		&statep->scf_regs->RxDSR_C_FLAG, statep->reg_rxdsr_c_flag);
	SC_DBG_DRV_TRACE(TC_W_RxDSR_C_FLAG, __LINE__, &statep->reg_rxdsr_c_flag,
		sizeof (statep->reg_rxdsr_c_flag));

	statep->reg_rxdsr_c_offset = dsc_p->dinfo.base.offset;
	SCF_DDI_PUT16(statep, statep->scf_regs_handle,
		&statep->scf_regs->RxDSR_OFFSET, statep->reg_rxdsr_c_offset);
	SC_DBG_DRV_TRACE(TC_W_RxDSR_OFFSET, __LINE__,
		&statep->reg_rxdsr_c_offset,
		sizeof (statep->reg_rxdsr_c_offset));

	/* Write DCR register : RxEND interrupt */
	statep->reg_dcr = DCR_RxEND;
	SCF_DDI_PUT8(statep, statep->scf_regs_handle,
		&statep->scf_regs->DCR, statep->reg_dcr);
	SC_DBG_DRV_TRACE(TC_W_DCR, __LINE__, &statep->reg_dcr,
		sizeof (statep->reg_dcr));

	/* Register read sync */
	scf_rs8 = SCF_DDI_GET8(statep, statep->scf_regs_handle,
		&statep->scf_regs->DCR);

	SC_DBG_DRV_TRACE(TC_RxEND, __LINE__, &statep->reg_rxdsr_c_flag, 4);

	SCFDBGMSG1(SCF_DBGFLAG_REG, "DCR = 0x%02x", statep->reg_dcr);
	SCFDBGMSG2(SCF_DBGFLAG_REG, "RxDSR = 0x%04x 0x%04x",
		statep->reg_rxdsr_c_flag, statep->reg_rxdsr_c_offset);

	/* SRAM trace */
	SCF_SRAM_TRACE(statep, DTC_DSCP_RXEND);

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * subroutine function
 */

/*
 * scf_dscp_dscbuff_free_all()
 *
 * Description: All descripter buffer release processing.
 *
 */
void
scf_dscp_dscbuff_free_all(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_dscbuff_free_all() "
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */
	int			ii;		/* Working value : counter */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Get TxDSC address */
	dsc_p = scf_dscp_comtbl.tx_dscp;

	if (dsc_p != NULL) {
		/* Check TxDSC */
		for (ii = 0; ii < scf_dscp_comtbl.txdsc_maxcount; ii++,
			dsc_p++) {
			/* Check TxDSC status */
			if (dsc_p->status == SCF_TX_ST_IDLE) {
				continue;
			}
			/* TxDSC status not (SA0) */
			/* Check send data */
			if (dsc_p->dinfo.base.dscp_datap != NULL) {
				/* Send data release */
				kmem_free(dsc_p->dinfo.base.dscp_datap,
					dsc_p->dinfo.base.length);
				dsc_p->dinfo.base.dscp_datap = NULL;
			}

			/* Check SRAM data */
			if (dsc_p->dinfo.base.offset != DSC_OFFSET_NOTHING) {
				/* Send SRAM data release */
				scf_dscp_sram_free(dsc_p->dinfo.base.offset);
				dsc_p->dinfo.base.offset = DSC_OFFSET_NOTHING;
			}

			/* Change TxDSC status (SA0) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_IDLE);
		}

		/* Tx flag initialization */
		scf_dscp_comtbl.tx_exec_flag = FLAG_OFF;
		scf_dscp_comtbl.dscp_path_flag = FLAG_OFF;
		scf_dscp_comtbl.tx_local_use_flag = FLAG_OFF;

		/* TxDSC counter/offset initialization */
		scf_dscp_comtbl.tx_get = scf_dscp_comtbl.tx_put;
		scf_dscp_comtbl.tx_dsc_count = 0;

		/* Tx re-try counter initialization */
		scf_dscp_comtbl.tx_ackto_retry_cnt = 0;
		scf_dscp_comtbl.tx_endto_retry_cnt = 0;

		scf_dscp_comtbl.tx_busy_retry_cnt = 0;
		scf_dscp_comtbl.tx_interface_retry_cnt = 0;
		scf_dscp_comtbl.tx_nak_retry_cnt = 0;
		scf_dscp_comtbl.tx_notsuop_retry_cnt = 0;
		scf_dscp_comtbl.tx_prmerr_retry_cnt = 0;
		scf_dscp_comtbl.tx_seqerr_retry_cnt = 0;
		scf_dscp_comtbl.tx_other_retry_cnt = 0;
		scf_dscp_comtbl.tx_send_retry_cnt = 0;
	}

	/* Get RxDSC address */
	dsc_p = scf_dscp_comtbl.rx_dscp;

	if (dsc_p != NULL) {
		/* Check RxDSC */
		for (ii = 0; ii < scf_dscp_comtbl.rxdsc_maxcount; ii++,
			dsc_p++) {
			/* Check RxDSC status */
			if (dsc_p->status == SCF_RX_ST_IDLE) {
				continue;
			}
			/* RxDSC status not (RA0) */
			/* Check receive data */
			if (dsc_p->dinfo.base.dscp_datap != NULL) {
				/* Receive data release */
				kmem_free(dsc_p->dinfo.base.dscp_datap,
					dsc_p->dinfo.base.length);
				dsc_p->dinfo.base.dscp_datap = NULL;
			}

			/* Change RxDSC status (RA0) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_IDLE);
		}

		/* Rx flag initialization */
		scf_dscp_comtbl.rx_exec_flag = FLAG_OFF;

		/* RxDSC counter/offset initialization */
		scf_dscp_comtbl.rx_get = scf_dscp_comtbl.rx_put;
		scf_dscp_comtbl.rx_dsc_count = 0;
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_txdscbuff_free()
 *
 * Description: Tx descripter buffer release processing.
 *
 */
void
scf_dscp_txdscbuff_free(scf_dscp_main_t *mainp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_txdscbuff_free() "
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */
	uint16_t		wkget;		/* Working value : get offset */
	int			ii;		/* Working value : counter */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Get TxDSC offser */
	wkget = scf_dscp_comtbl.tx_get;

	/* Check TxDSC */
	for (ii = 0; ii < scf_dscp_comtbl.tx_dsc_count; ii++) {
		/* Get TxDSC address */
		dsc_p = &scf_dscp_comtbl.tx_dscp[wkget];

		/* Update Tx descriptor offset */
		if (wkget == scf_dscp_comtbl.tx_last) {
			wkget = scf_dscp_comtbl.tx_first;
		} else {
			wkget++;
		}

		/* Check main use data */
		if (mainp->id != dsc_p->dinfo.bdcr.id) {
			continue;
		}
		/* Check TxDSC status */
		switch (dsc_p->status) {
		case SCF_TX_ST_SRAM_TRANS_WAIT:
			/* TxDSC status not (SB0) */
		case SCF_TX_ST_TXREQ_SEND_WAIT:
			/* TxDSC status not (SB2) */
			/* Check send data */
			if (dsc_p->dinfo.base.dscp_datap != NULL) {
				/* Send data release */
				kmem_free(dsc_p->dinfo.base.dscp_datap,
					dsc_p->dinfo.base.length);
				dsc_p->dinfo.base.dscp_datap = NULL;
			}

			/* Check SRAM data */
			if (dsc_p->dinfo.base.offset != DSC_OFFSET_NOTHING) {
				/* Send SRAM data release */
				scf_dscp_sram_free(dsc_p->dinfo.base.offset);
				dsc_p->dinfo.base.offset = DSC_OFFSET_NOTHING;
			}

			/* Change TxDSC status (SA0) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_TX_ST_IDLE);
			break;

		default:
			/* TxDSC status != SB0 or SB2 is NOP */
			break;
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_rxdscbuff_free()
 *
 * Description: Rx descripter buffer release processing.
 *
 */
void
scf_dscp_rxdscbuff_free(scf_dscp_main_t *mainp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_rxdscbuff_free() "
	scf_dscp_dsc_t		*dsc_p;		/* TxDSC address */
	uint16_t		wkget;		/* Working value : get offset */
	int			ii;		/* Working value : counter */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Get RxDSC offser */
	wkget = scf_dscp_comtbl.rx_get;

	/* Check RxDSC */
	for (ii = 0; ii < scf_dscp_comtbl.rx_dsc_count; ii++) {
		/* Get RxDSC address */
		dsc_p = &scf_dscp_comtbl.rx_dscp[wkget];

		/* Update Rx descriptor offset */
		if (wkget == scf_dscp_comtbl.rx_last) {
			wkget = scf_dscp_comtbl.rx_first;
		} else {
			wkget++;
		}

		/* Check main use data */
		if (mainp->id != dsc_p->dinfo.bdcr.id) {
			continue;
		}
		/* Check RxDSC status */
		if (dsc_p->status != SCF_RX_ST_IDLE) {
			/* TxDSC status not (RA0) */
			/* Check receive data */
			if (dsc_p->dinfo.base.dscp_datap != NULL) {
				/* Receive data release */
				kmem_free(dsc_p->dinfo.base.dscp_datap,
					dsc_p->dinfo.base.length);
				dsc_p->dinfo.base.dscp_datap = NULL;
			}

			/* Change RxDSC status (RA0) */
			SCF_SET_DSC_STATUS(dsc_p, SCF_RX_ST_IDLE);

			/* Rx flag initialization */
			scf_dscp_comtbl.rx_exec_flag = FLAG_OFF;

			/* RxDSC counter/offset initialization */
			scf_dscp_comtbl.rx_get = scf_dscp_comtbl.rx_put;
			scf_dscp_comtbl.rx_dsc_count = 0;
			break;
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_rdata_free()
 *
 * Description: All receive data buffer release processing.
 *
 */
void
scf_dscp_rdata_free(scf_dscp_main_t *mainp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_rdata_free() "
	/* Current receive data queue address */
	scf_rdata_que_t		*rdt_p;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	while (mainp->rd_count != 0) {
		/* Get receive data queue address */
		rdt_p = &mainp->rd_datap[mainp->rd_get];

		/* Check receive data buffer */
		if (rdt_p->rdatap != NULL) {
			/* Receve data release */
			kmem_free(rdt_p->rdatap, rdt_p->length);
			rdt_p->rdatap = NULL;
		}

		/* Update receive data queue */
		if (mainp->rd_get == mainp->rd_last) {
			mainp->rd_get = mainp->rd_first;
		} else {
			mainp->rd_get++;
		}

		/* Update receive data queue count */
		mainp->rd_count--;
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_event_queue()
 *
 * Description: Event queueing processing.
 *
 */
void
scf_dscp_event_queue(scf_dscp_main_t *mainp, scf_event_t mevent)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_event_queue() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Check DISC ERROR event */
	if (mevent == SCF_MB_DISC_ERROR) {
		/* INIT_REQ retry timer stop */
		scf_timer_stop(mainp->timer_code);

		/* TxDSC buffer release */
		scf_dscp_txdscbuff_free(mainp);

		/* RxDSC buffer release */
		scf_dscp_rxdscbuff_free(mainp);

		/* All queing event release */
		scf_dscp_event_queue_free(mainp);

		/* All receive buffer release */
		scf_dscp_rdata_free(mainp);
	}

	/* Event queing */
	mainp->ev_quep[mainp->ev_put].mevent = mevent;

	/* Update event queue offset */
	if (mainp->ev_put == mainp->ev_last) {
		mainp->ev_put = mainp->ev_first;
	} else {
		mainp->ev_put++;
	}

	/* Update event queue count */
	mainp->ev_count++;

	/* Soft interrupt : call scf_dscp_callback() */
	if (mutex_tryenter(&scf_comtbl.si_mutex) != 0) {
		scf_comtbl.scf_softintr_dscp_kicked = FLAG_ON;
		ddi_trigger_softintr(scf_comtbl.scf_softintr_id);
		mutex_exit(&scf_comtbl.si_mutex);
	}

	/* Callback timer start */
	scf_timer_start(SCF_TIMERCD_DSCP_CALLBACK);

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_event_queue_free()
 *
 * Description: Event queue release processing.
 *
 */
void
scf_dscp_event_queue_free(scf_dscp_main_t *mainp)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_event_queue_free() "

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* All queing event release */
	mainp->ev_get = mainp->ev_put;
	mainp->ev_count = 0;

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}


/*
 * scf_dscp_mkey2mainp()
 *
 * Description: Get MAIN control table address processing by mkey.
 *
 */
scf_dscp_main_t *
scf_dscp_mkey2mainp(mkey_t mkey)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_mkey2mainp() "
	/* Return value : Main table address */
	scf_dscp_main_t		*mainp = NULL;
	int			ii;		/* Working value : counter */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	for (ii = 0; ii < MBIF_MAX; ii++) {
		/* Check "mkey" at search table */
		if (mkey == scf_dscp_mkey_search[ii]) {
			/* Set mainp address */
			mainp = &scf_dscp_comtbl.scf_dscp_main[ii];
			break;
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
	return (mainp);
}


/*
 * scf_dscp_id2mainp()
 *
 * Description: Get MAIN control table address processing by id.
 *
 */
scf_dscp_main_t *
scf_dscp_id2mainp(uint8_t id)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_id2mainp() "
	/* Return value : Main table address */
	scf_dscp_main_t		*mainp = NULL;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Check "id" */
	if (id < MBIF_MAX) {
		/* Set mainp address */
		mainp = &scf_dscp_comtbl.scf_dscp_main[id];
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
	return (mainp);
}


/*
 * scf_dscp_sram_get()
 *
 * Description: Tx SRAM alloc processing.
 *
 */
uint16_t
scf_dscp_sram_get(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_sram_get() "
	scf_tx_sram_t		*sram_p;	/* Tx SRAM table address */
	int			ii;		/* Working value : counter */
	/* Return value : Tx SRAM offset */
	uint16_t		offset = TX_SRAM_GET_ERROR;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start");

	/* Check Tx SRAM space */
	if (scf_dscp_comtbl.tx_sram_count >=
		scf_dscp_comtbl.txsram_maxcount) {
		goto END_dscp_sram_get;
	}

	/* Check all Tx SRAM table */
	for (ii = 0; ii < scf_dscp_comtbl.txsram_maxcount; ii++) {
		/* Get Tx SRAM table address */
		sram_p = &scf_dscp_comtbl.tx_sramp[scf_dscp_comtbl.tx_sram_put];

		/* Update Tx SRAM offset */
		if (scf_dscp_comtbl.tx_sram_put ==
			scf_dscp_comtbl.tx_sram_last) {
			scf_dscp_comtbl.tx_sram_put =
				scf_dscp_comtbl.tx_sram_first;
		} else {
			scf_dscp_comtbl.tx_sram_put++;
		}

		/* Check Tx SRAM use */
		if (sram_p->use_flag == FLAG_OFF) {
			/* Tx SRAM use flag ON */
			sram_p->use_flag = FLAG_ON;

			/* Get Tx SRAM offset */
			offset = sram_p->offset;

			/* Update Tx SRAM count */
			scf_dscp_comtbl.tx_sram_count++;
			break;
		}
	}

/*
 * END_dscp_sram_get
 */
	END_dscp_sram_get:

	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end offset = 0x%04x",
		offset);
	return (offset);
}


/*
 * scf_dscp_sram_free()
 *
 * Description: Tx SRAM release processing
 *
 */
void
scf_dscp_sram_free(uint16_t offset)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_dscp_sram_free() "
	scf_tx_sram_t		*sram_p;	/* Tx SRAM table address */
	uint16_t		wkget;		/* Working value : get offset */

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG1(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": start offset = 0x%04x",
		offset);

	/* "offset" to Tx SRAM get offset */
	wkget = (uint16_t)(offset
	/ (scf_dscp_comtbl.txbuffsize / DSC_OFFSET_CONVERT));

	/* Check Tx SRAM get offset */
	if (wkget < scf_dscp_comtbl.txsram_maxcount) {
		/* Get Tx SRAM table address */
		sram_p = &scf_dscp_comtbl.tx_sramp[wkget];

		/* Check "offset" */
		if (offset == sram_p->offset) {
			/* Tx SRAM use flag OFF */
			sram_p->use_flag = FLAG_OFF;

			/* Update Tx SRAM count */
			scf_dscp_comtbl.tx_sram_count--;
		}
	}

	SCFDBGMSG(SCF_DBGFLAG_DSCP, SCF_FUNC_NAME ": end");
}
