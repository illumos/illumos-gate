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
 * provide the interface to the layered drivers (send request/receive
 * response to the RMC
 *
 */

/*
 *  Header files
 */
#include <sys/conf.h>
#include <sys/callb.h>
#include <sys/cyclic.h>
#include <sys/membar.h>
#include <sys/modctl.h>
#include <sys/strlog.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/types.h>
#include <sys/disp.h>
#include <sys/rmc_comm_dp.h>
#include <sys/rmc_comm_dp_boot.h>
#include <sys/rmc_comm_drvintf.h>
#include <sys/rmc_comm.h>

void dp_reset(struct rmc_comm_state *, uint8_t, boolean_t, boolean_t);
void dp_wake_up_waiter(struct rmc_comm_state *, uint8_t);

static int rmc_comm_send_req_resp(struct rmc_comm_state *rcs,
    rmc_comm_msg_t *request, rmc_comm_msg_t *response, uint32_t wait_time);
static int rmc_comm_wait_bp_reply(struct rmc_comm_state *,
    rmc_comm_dp_state_t *, dp_req_resp_t *, clock_t);
static void rmc_comm_wait_enable_to_send(struct rmc_comm_state *,
    rmc_comm_dp_state_t *);
static void rmc_comm_wake_up_next(struct rmc_comm_state *);
static void rmc_comm_send_pend_req(caddr_t arg);
static int rmc_comm_dreq_thread_start(struct rmc_comm_state *rcs);
static void rmc_comm_dreq_thread_kill(struct rmc_comm_state *rcs);

/*
 * leaf driver to use this function to send a request to the remote side (RMC)
 * and wait for a reply
 */
int
rmc_comm_request_response(rmc_comm_msg_t *request,
    rmc_comm_msg_t *response, uint32_t wait_time)
{
	struct rmc_comm_state	*rcs;
	int err;

	/*
	 * get the soft state struct (instance 0)
	 */
	if ((rcs = rmc_comm_getstate(NULL, 0,
	    "rmc_comm_request_response")) == NULL)
		return (RCENOSOFTSTATE);

	do {
		err = rmc_comm_send_req_resp(rcs, request, response, wait_time);
	} while (err == RCEGENERIC);
	return (err);
}

/*
 * leaf driver to use this function to send a request to the remote side (RMC)
 * without waiting for a reply. If flag is RMC_COMM_DREQ_URGENT, the request
 * message is sent once-off (an eventual pending request is aborted). This
 * flag must only be used when try to send a request in critical condition
 * (while the system is shutting down for instance and the CPU signature
 * has to be sent). Otherwise, the request is stored in a temporary location
 * and delivered by a thread.
 */
int
rmc_comm_request_nowait(rmc_comm_msg_t *request, uint8_t flag)
{
	struct rmc_comm_state		*rcs;
	rmc_comm_dp_state_t		*dps;
	rmc_comm_drvintf_state_t	*dis;
	dp_message_t			req;
	int				err = RCNOERR;
	uint8_t				flags = 0;

	/*
	 * get the soft state struct (instance 0)
	 */
	if ((rcs = rmc_comm_getstate(NULL, 0,
	    "rmc_comm_request_response")) == NULL)
		return (RCENOSOFTSTATE);

	/*
	 * just a sanity check...
	 */
	if (request == NULL) {
		DPRINTF(rcs, DAPI, (CE_CONT, "reqnowait, invalid args\n"));
		return (RCEINVARG);
	}

	if (!IS_NUMBERED_MSG(request->msg_type)) {
		DPRINTF(rcs, DAPI, (CE_CONT,
		    "reqnowait, ctrl msg not allowed! req type=%x\n",
		    request->msg_type));
		return (RCEINVARG);
	}

	if (flag == RMC_COMM_DREQ_URGENT) {
		/*
		 * Send this request with high priority i.e. abort eventual
		 * request/response pending sessions.
		 */

		dps = &rcs->dp_state;

		DPRINTF(rcs, DAPI, (CE_CONT, "going to send request=%x (URG)\n",
		    request->msg_type));

		/*
		 * Handle the case where we are called during panic
		 * processing.  If that occurs, then another thread in
		 * rmc_comm might have been idled by panic() while
		 * holding dp_mutex.  As a result, do not unconditionally
		 * grab dp_mutex.
		 */
		if (ddi_in_panic() != 0) {
			if (mutex_tryenter(dps->dp_mutex) == 0) {
				return (RCENODATALINK);
			}
		} else {
			mutex_enter(dps->dp_mutex);
		}

		/*
		 * send the request only if the protocol data link is up.
		 * it is pointless to send it in the other case.
		 */
		if (dps->data_link_ok) {

			/*
			 * clean up an eventual pending request/response session
			 * (save its current status)
			 */
			if (dps->pending_request) {
				flags = dps->req_resp.flags;
				rmc_comm_dp_mcleanup(rcs);
			}

			/*
			 * send the request message
			 */
			req.msg_type = request->msg_type;
			req.msg_buf = (uint8_t *)request->msg_buf;
			req.msg_msglen = (uint16_t)request->msg_len;

			DPRINTF(rcs, DAPI, (CE_CONT, "send request=%x (URG)\n",
			    request->msg_type));

			err = rmc_comm_dp_msend(rcs, &req);

			/*
			 * wait for fifos to drain
			 */
			rmc_comm_serdev_drain(rcs);

			/*
			 * clean up the current session
			 */
			rmc_comm_dp_mcleanup(rcs);

			/*
			 * abort an old session (if any)
			 */
			if (dps->pending_request) {
				dps->req_resp.flags = flags;
				dp_wake_up_waiter(rcs, MSG_ERROR);
			}
		}

		mutex_exit(dps->dp_mutex);

	} else {

		/*
		 * Get an 'independent' thread (rmc_comm_send_pend_req)
		 * to send this request (since the calling thread does not
		 * want to wait). Copy the request in the drvintf state
		 * structure and signal the thread.
		 */

		dis = &rcs->drvi_state;

		mutex_enter(dis->dreq_mutex);

		if (dis->dreq_state == RMC_COMM_DREQ_ST_WAIT) {

			DPRINTF(rcs, DAPI, (CE_CONT, "get to send request=%x\n",
			    request->msg_type));

			/*
			 * copy the request in a temporary location
			 * (drvinf_state structure) and signal the thread
			 * that a request message has to be delivered
			 */

			if (request->msg_len < DP_MAX_MSGLEN) {
				dis->dreq_request.msg_type = request->msg_type;
				dis->dreq_request.msg_len = request->msg_len;
				dis->dreq_request.msg_buf =
				    dis->dreq_request_buf;
				bcopy(request->msg_buf,
				    dis->dreq_request.msg_buf,
				    request->msg_len);

				dis->dreq_state = RMC_COMM_DREQ_ST_PROCESS;
				cv_signal(dis->dreq_sig_cv);

			} else {
				/*
				 * not enough space to hold the request
				 */
				err = RCEREPTOOBIG;
			}
		} else {

			DPRINTF(rcs, DAPI, (CE_CONT, "cannot get to send "
			    "request=%x (busy)\n", request->msg_type));

			/*
			 * only one request per time can be processed.
			 * the thread is either busy (RMC_COMM_DREQ_ST_PROCESS)
			 * or terminating (RMC_COMM_DREQ_ST_EXIT)
			 */
			err = RCEGENERIC;
		}

		mutex_exit(dis->dreq_mutex);
	}

	return (err);
}

/*
 * Function used to send a request and (eventually) wait for a response.
 * It can be called from a leaf driver (via rmc_comm_request_response) or
 * from the thread in charge of sending 'no-wait' requests
 * (rmc_comm_send_pend_req).
 */
static int
rmc_comm_send_req_resp(struct rmc_comm_state *rcs, rmc_comm_msg_t *request,
    rmc_comm_msg_t *response, uint32_t wait_time)
{
	rmc_comm_dp_state_t	*dps;
	dp_req_resp_t		*drr;
	dp_message_t		*exp_resp;
	dp_message_t		req;
	clock_t			resend_clockt, delta;
	clock_t			stop_clockt;
	int			err;


	/*
	 * just a sanity check...
	 */
	if (request == NULL) {
		DPRINTF(rcs, DAPI, (CE_CONT, "reqresp, invalid args\n"));
		return (RCEINVARG);
	}

	/*
	 * drivers cannot send control messages at all. They are meant to
	 * be used at low level only.
	 */
	if (!IS_NUMBERED_MSG(request->msg_type)) {
		DPRINTF(rcs, DAPI, (CE_CONT,
		    "reqresp, ctrl msg not allowed! req type=%x\n",
		    request->msg_type));
		return (RCEINVARG);
	}

	dps = &rcs->dp_state;
	drr = &dps->req_resp;
	exp_resp = &drr->response;

	/*
	 * Handle the case where we are called during panic
	 * processing.  If that occurs, then another thread in
	 * rmc_comm might have been idled by panic() while
	 * holding dp_mutex.  As a result, do not unconditionally
	 * grab dp_mutex.
	 */
	if (ddi_in_panic() != 0) {
		if (mutex_tryenter(dps->dp_mutex) == 0) {
			return (RCENODATALINK);
		}
	} else {
		mutex_enter(dps->dp_mutex);
	}

	/*
	 * if the data link set up is suspended, just return.
	 * the only time that this can happen is during firmware download
	 * (see rmc_comm_request_response_bp). Basically, the data link is
	 * down and the timer for setting up the data link is not running.
	 */
	if (!dps->data_link_ok &&
	    dps->timer_link_setup == (timeout_id_t)0) {

		mutex_exit(dps->dp_mutex);
		return (RCENODATALINK);
	}

	DPRINTF(rcs, DAPI, (CE_CONT, "pending request=%d, req type=%x\n",
	    dps->pending_request, request->msg_type));

	rmc_comm_wait_enable_to_send(rcs, dps);

	/*
	 * We now have control of the RMC.
	 * Place a lower limit on the shortest amount of time to be
	 * waited before timing out while communicating with the RMC
	 */
	if (wait_time < DP_MIN_TIMEOUT)
		wait_time = DP_MIN_TIMEOUT;

	stop_clockt = ddi_get_lbolt() + drv_usectohz(wait_time * 1000);

	/*
	 * initialization of the request/response data structure
	 */
	drr->flags = 0;
	drr->error_status = 0;

	/*
	 * set the 'expected reply' buffer: get the buffer already allocated
	 * for the response (if a reply is expected!)
	 */
	if (response != NULL) {
		exp_resp->msg_type = response->msg_type;
		exp_resp->msg_buf = (uint8_t *)response->msg_buf;
		exp_resp->msg_msglen = response->msg_bytes;
		exp_resp->msg_bufsiz = response->msg_len;
	} else {
		exp_resp->msg_type = DP_NULL_MSG;
		exp_resp->msg_buf = NULL;
		exp_resp->msg_bufsiz = 0;
		exp_resp->msg_msglen = 0;
	}

	/*
	 * send the request message
	 */
	req.msg_type = request->msg_type;
	req.msg_buf = (uint8_t *)request->msg_buf;
	req.msg_msglen = request->msg_len;

	/*
	 * send the message and wait for the reply or ACKnowledgment
	 * re-send the message if reply/ACK is not received in the
	 * timeframe defined
	 */
	DPRINTF(rcs, DAPI, (CE_CONT, "send request=%x\n", request->msg_type));

	delta = drv_usectohz(TX_RETRY_TIME * 1000);

	while ((err = rmc_comm_dp_msend(rcs, &req)) == RCNOERR) {

		resend_clockt = ddi_get_lbolt() + delta;

		/*
		 * wait for a reply or an acknowledgement
		 */
		(void) cv_reltimedwait(drr->cv_wait_reply, dps->dp_mutex,
		    delta, TR_CLOCK_TICK);

		DPRINTF(rcs, DAPI, (CE_CONT,
		    "reqresp send status: flags=%02x req=%x resp=%x tick=%ld\n",
		    drr->flags, request->msg_type,
		    response ? response->msg_type : -1,
		    stop_clockt - resend_clockt));

		/*
		 * Check for error condition first
		 * Then, check if the command has been replied/ACKed
		 * Then, check if it has timeout and if there is any
		 * time left to resend the message.
		 */
		if ((drr->flags & MSG_ERROR) != 0) {
			if (drr->error_status == 0) {
				err = RCEGENERIC;
			} else {
				err = drr->error_status;
			}
			break;

		} else if (response != NULL &&
		    (drr->flags & MSG_REPLY_RXED) != 0) {
			/*
			 * yes! here is the reply
			 */

			/*
			 * get the actual length of the msg
			 * a negative value means that the reply message
			 * was too big for the receiver buffer
			 */
			response->msg_bytes = exp_resp->msg_msglen;
			if (response->msg_bytes < 0)
				err = RCEREPTOOBIG;
			else
				err = RCNOERR;
			break;

		} else if (response == NULL && (drr->flags & MSG_ACKED) != 0) {
			/*
			 * yes! message has been acknowledged
			 */

			err = RCNOERR;
			break;

		} else if ((stop_clockt - resend_clockt) <= 0) {
			/*
			 * no more time left. set the error code,
			 * exit the loop
			 */

			err = RCETIMEOUT;
			break;
		}
	}

	rmc_comm_dp_mcleanup(rcs);

	rmc_comm_wake_up_next(rcs);

	mutex_exit(dps->dp_mutex);

	DPRINTF(rcs, DAPI, (CE_CONT, "reqresp end: err=%d, request=%x\n",
	    err, request->msg_type));

	return (err);
}

/*
 * Function used to send a BP (Boot Prom) message and get the reply.
 * BP protocol is provided only to support firmware download.
 *
 * This function will look for the following key BP protocol commands:
 * BP_OBP_BOOTINIT: the data link is brought down so that request/response
 * sessions cannot be started. The reason why is that this command will cause
 * RMC fw to jump to the boot monitor (BOOTMON_FLASH) and data protocol is not
 * operational. In this context, RMC fw will only be using the BP protocol.
 * BP_OBP_RESET: data link setup timer is resumed. This command cause the RMC
 * to reboot and hence become operational.
 */
int
rmc_comm_request_response_bp(rmc_comm_msg_t *request_bp,
    rmc_comm_msg_t *response_bp, uint32_t wait_time)
{
	struct rmc_comm_state	*rcs;
	rmc_comm_dp_state_t	*dps;
	dp_req_resp_t		*drr;
	dp_message_t		*resp_bp;
	bp_msg_t		*bp_msg;
	clock_t			stop_clockt;
	int			err = RCNOERR;
	boolean_t		bootinit_sent = 0;

	/*
	 * get the soft state struct (instance 0)
	 */
	if ((rcs = rmc_comm_getstate(NULL, 0,
	    "rmc_comm_request_response_bp")) == NULL)
		return (RCENOSOFTSTATE);

	/*
	 * sanity check: request_bp buffer must always be provided
	 */
	if (request_bp == NULL) {
		DPRINTF(rcs, DAPI, (CE_CONT, "reqresp_bp, invalid args\n"));
		return (RCEINVARG);
	}

	bp_msg = (bp_msg_t *)request_bp->msg_buf;

	DPRINTF(rcs, DAPI, (CE_CONT, "send request_bp=%x\n", bp_msg->cmd));

	/*
	 * only BP message can be sent
	 */
	if (!IS_BOOT_MSG(bp_msg->cmd)) {
		DPRINTF(rcs, DAPI, (CE_CONT,
		    "reqresp_bp, only BP msg are allowed! type=%x\n",
		    bp_msg->cmd));
		return (RCEINVARG);
	}

	dps = &rcs->dp_state;
	drr = &dps->req_resp;
	resp_bp = &drr->response;

	mutex_enter(dps->dp_mutex);

	rmc_comm_wait_enable_to_send(rcs, dps);

	/*
	 * Now, before sending the message, just check what it is being sent
	 * and take action accordingly.
	 *
	 * is it BP_OBP_BOOTINIT or BP_OBP_RESET command?
	 */
	if (bp_msg->cmd == BP_OBP_BOOTINIT) {

		/*
		 * bring down the protocol data link
		 * (must be done before aborting a request/response session)
		 */
		dps->data_link_ok = 0;
		dps->timer_link_setup = (timeout_id_t)0;

		bootinit_sent = 1;

	} else if (bp_msg->cmd == BP_OBP_RESET) {

		/*
		 * restart the data link set up timer. RMC is coming up...
		 */

		dp_reset(rcs, INITIAL_SEQID, 0, 1);
	}

	/*
	 * initialization of the request/response data structure
	 */
	drr->flags = 0;
	drr->error_status = 0;

	/*
	 * set the reply buffer: get the buffer already allocated
	 * for the response
	 */
	if (response_bp != NULL) {
		DPRINTF(rcs, DAPI, (CE_CONT, "expect BP reply. len=%d\n",
		    response_bp->msg_len));

		resp_bp->msg_buf = (uint8_t *)response_bp->msg_buf;
		resp_bp->msg_bufsiz = (uint16_t)response_bp->msg_len;
	}

	/*
	 * send the BP message and wait for the reply
	 */

	rmc_comm_bp_msend(rcs, bp_msg);

	if (response_bp != NULL) {

		/*
		 * place a lower limit on the shortest amount of time to be
		 * waited before timing out while communicating with the RMC
		 */
		if (wait_time < DP_MIN_TIMEOUT)
			wait_time = DP_MIN_TIMEOUT;

		stop_clockt = ddi_get_lbolt() + drv_usectohz(wait_time * 1000);

		if ((err = rmc_comm_wait_bp_reply(rcs, dps, drr,
		    stop_clockt)) == RCNOERR) {

			/*
			 * get the actual length of the msg
			 * a negative value means that the reply message
			 * was too big for the receiver buffer
			 */
			response_bp->msg_bytes = resp_bp->msg_msglen;
			if (response_bp->msg_bytes < 0) {
				err = RCEREPTOOBIG;

			} else if (bootinit_sent) {

				/*
				 * BOOTINIT cmd may fail. In this is the case,
				 * the RMC is still operational. Hence, we
				 * try (once) to set up the data link
				 * protocol.
				 */
				bp_msg = (bp_msg_t *)response_bp->msg_buf;

				if (bp_msg->cmd == BP_RSC_BOOTFAIL &&
				    bp_msg->dat1 == BP_DAT1_REJECTED) {
					(void) rmc_comm_dp_ctlsend(rcs,
					    DP_CTL_START);
				}
			}
		}
	}

	rmc_comm_dp_mcleanup(rcs);

	rmc_comm_wake_up_next(rcs);

	mutex_exit(dps->dp_mutex);

	return (err);
}


/*
 * to register for an asynchronous (via soft interrupt) notification
 * of a message from the remote side (RMC)
 */
int
rmc_comm_reg_intr(uint8_t msg_type, rmc_comm_intrfunc_t intr_handler,
    rmc_comm_msg_t *msgbuf, uint_t *state, kmutex_t *lock)
{
	struct rmc_comm_state	*rcs;
	dp_msg_intr_t		*msgintr;
	int			 err = RCNOERR;

	if ((rcs = rmc_comm_getstate(NULL, 0, "rmc_comm_reg_intr")) == NULL)
		return (RCENOSOFTSTATE);

	mutex_enter(rcs->dp_state.dp_mutex);

	msgintr = &rcs->dp_state.msg_intr;

	/*
	 * lock is required. If it is not defined, the
	 * interrupt handler routine cannot be registered.
	 */
	if (lock == NULL) {
		mutex_exit(rcs->dp_state.dp_mutex);
		return (RCEINVARG);
	}

	/*
	 * only one interrupt handler can be registered.
	 */
	if (msgintr->intr_handler == NULL) {

		if (ddi_add_softintr(rcs->dip, DDI_SOFTINT_HIGH,
		    &msgintr->intr_id, NULL, NULL, intr_handler,
		    (caddr_t)msgbuf) == DDI_SUCCESS) {

			msgintr->intr_handler = intr_handler;
			msgintr->intr_lock = lock;
			msgintr->intr_state = state;
			msgintr->intr_msg_type = msg_type;
			msgintr->intr_arg = (caddr_t)msgbuf;
		} else {
			err = RCECANTREGINTR;
		}
	} else {
		err = RCEALREADYREG;
	}

	mutex_exit(rcs->dp_state.dp_mutex);

	return (err);
}

/*
 * To unregister for asynchronous notifications
 */
int
rmc_comm_unreg_intr(uint8_t msg_type, rmc_comm_intrfunc_t intr_handler)
{
	struct rmc_comm_state	*rcs;
	dp_msg_intr_t		*msgintr;
	int			 err = RCNOERR;

	if ((rcs = rmc_comm_getstate(NULL, 0, "rmc_comm_unreg_intr")) == NULL)
		return (RCENOSOFTSTATE);

	mutex_enter(rcs->dp_state.dp_mutex);

	msgintr = &rcs->dp_state.msg_intr;

	if (msgintr->intr_handler != NULL &&
	    msgintr->intr_msg_type == msg_type &&
	    msgintr->intr_handler == intr_handler) {

		ddi_remove_softintr(msgintr->intr_id);
		msgintr->intr_handler = NULL;
		msgintr->intr_id = 0;
		msgintr->intr_msg_type = 0;
		msgintr->intr_arg = NULL;
		msgintr->intr_lock = NULL;
		msgintr->intr_state = NULL;
	} else {
		err = RCEGENERIC;
	}

	mutex_exit(rcs->dp_state.dp_mutex);

	return (err);
}

/*
 * To send raw data (firmware s-records) down to the RMC.
 * It is provided only to support firmware download.
 */
int
rmc_comm_send_srecord_bp(caddr_t buf, int buflen,
    rmc_comm_msg_t *response_bp, uint32_t wait_time)
{
	struct rmc_comm_state	*rcs;
	rmc_comm_dp_state_t	*dps;
	dp_req_resp_t		*drr;
	dp_message_t		*resp_bp;
	clock_t			stop_clockt;
	int			err;

	/*
	 * get the soft state struct (instance 0)
	 */
	if ((rcs = rmc_comm_getstate(NULL, 0,
	    "rmc_comm_request_response_bp")) == NULL)
		return (RCENOSOFTSTATE);

	/*
	 * sanity check: response_bp buffer must always be provided
	 */
	if (buf == NULL || response_bp == NULL) {
		DPRINTF(rcs, DAPI, (CE_CONT, "send_srecord_bp,invalid args\n"));
		return (RCEINVARG);
	}

	DPRINTF(rcs, DAPI, (CE_CONT, "send_srecord_bp, buflen=%d\n", buflen));

	dps = &rcs->dp_state;
	drr = &dps->req_resp;
	resp_bp = &drr->response;

	mutex_enter(dps->dp_mutex);

	rmc_comm_wait_enable_to_send(rcs, dps);

	/*
	 * initialization of the request/response data structure
	 */
	drr->flags = 0;
	drr->error_status = 0;

	/*
	 * set the reply buffer: get the buffer already allocated
	 * for the response
	 */
	resp_bp->msg_buf = (uint8_t *)response_bp->msg_buf;
	resp_bp->msg_bufsiz = (uint16_t)response_bp->msg_len;

	/*
	 * send raw data (s-record) and wait for the reply (BP message)
	 */

	rmc_comm_bp_srecsend(rcs, (char *)buf, buflen);

	/*
	 * place a lower limit on the shortest amount of time to be
	 * waited before timing out while communicating with the RMC
	 */
	if (wait_time < DP_MIN_TIMEOUT)
		wait_time = DP_MIN_TIMEOUT;

	stop_clockt = ddi_get_lbolt() + drv_usectohz(wait_time * 1000);

	if ((err = rmc_comm_wait_bp_reply(rcs, dps, drr,
	    stop_clockt)) == RCNOERR) {
		/*
		 * get the actual length of the msg
		 * a negative value means that the reply message
		 * was too big for the receiver buffer
		 */
		response_bp->msg_bytes = resp_bp->msg_msglen;
		if (response_bp->msg_bytes < 0) {
			err = RCEREPTOOBIG;
		}
	}

	rmc_comm_dp_mcleanup(rcs);

	rmc_comm_wake_up_next(rcs);

	mutex_exit(dps->dp_mutex);

	return (err);
}

/*
 * To wait for (any) BP message to be received.
 * (dp_mutex must be held)
 */
static int
rmc_comm_wait_bp_reply(struct rmc_comm_state *rcs, rmc_comm_dp_state_t *dps,
    dp_req_resp_t *drr, clock_t stop_clockt)
{
	clock_t clockleft = 1;
	int err = RCNOERR;

	clockleft = cv_timedwait(drr->cv_wait_reply, dps->dp_mutex,
	    stop_clockt);


	DPRINTF(rcs, DAPI, (CE_CONT,
	    "reqresp_bp, send: flags=%02x, clktick left=%ld\n",
	    drr->flags, clockleft));

	/*
	 * Check for error condition first.
	 * Then, check if it has timeout.
	 * Then, check if the command has been replied.
	 */
	if ((drr->flags & MSG_ERROR) != 0) {

		err = RCEGENERIC;

	} else if (clockleft <= 0) {
		/*
		 * timeout
		 */

		err = RCETIMEOUT;

	} else if ((drr->flags & MSG_RXED_BP) == 0) {

		err = RCEGENERIC;
	}

	return (err);
}

/*
 * Wait for the pending_request flag to be cleared and acquire it for our
 * own use. The caller is then allowed to start a new request/response
 * session with the RMC.
 * Note that all send-receive actions to the RMC include a time-out, so
 * the pending-request must eventually go away - even if the RMC is down.
 * Hence there is no need to timeout the wait action of this function.
 * (dp_mutex must be held on entry).
 */
static void
rmc_comm_wait_enable_to_send(struct rmc_comm_state *rcs,
    rmc_comm_dp_state_t *dps)
{
	DPRINTF(rcs, DAPI, (CE_CONT, "pending request=%d\n",
	    dps->pending_request));

	/*
	 * A new message can actually grab the lock before the thread
	 * that has just been signaled.  Therefore, we need to double
	 * check to make sure that pending_request is not already set
	 * after we wake up.
	 *
	 * Potentially this could mean starvation for certain unfortunate
	 * threads that keep getting woken up and putting back to sleep.
	 * But the window of such contention is very small to begin with.
	 */

	while (dps->pending_request) {
		/*
		 * just 'sit and wait' until there are no pending requests
		 */

		cv_wait(dps->cv_ok_to_send, dps->dp_mutex);
	}

	/*
	 * now a request/response can be started. Set the flag so that nobody
	 * else will be able to send anything.
	 */
	dps->pending_request = 1;
}

/*
 * To wake up one of the threads (if any) waiting for starting a
 * request/response session.
 * (dp_mutex must be held)
 */
static void
rmc_comm_wake_up_next(struct rmc_comm_state *rcs)
{
	/*
	 * wake up eventual waiting threads...
	 */

	rcs->dp_state.pending_request = 0;
	cv_signal(rcs->dp_state.cv_ok_to_send);
}


/*
 * thread which delivers pending request message to the rmc. Some leaf drivers
 * cannot afford to wait for a request to be replied/ACKed. Hence, a request
 * message is stored temporarily in the state structure and this thread
 * gets woken up to deliver it.
 */
static void
rmc_comm_send_pend_req(caddr_t arg)
{
	struct rmc_comm_state		*rcs;
	rmc_comm_drvintf_state_t	*dis;
	callb_cpr_t			cprinfo;

	if (arg == NULL) {
		thread_exit();
		/* NOTREACHED */
	}

	rcs = (struct rmc_comm_state *)arg;
	dis = &rcs->drvi_state;

	CALLB_CPR_INIT(&cprinfo, dis->dreq_mutex, callb_generic_cpr,
	    "rmc_comm_send_pend_req");

	mutex_enter(dis->dreq_mutex);

	if (dis->dreq_state <= RMC_COMM_DREQ_ST_READY)
		dis->dreq_state = RMC_COMM_DREQ_ST_WAIT;

	for (;;) {

		/*
		 * Wait for someone to tell me to continue.
		 */
		while (dis->dreq_state == RMC_COMM_DREQ_ST_WAIT) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(dis->dreq_sig_cv, dis->dreq_mutex);
			CALLB_CPR_SAFE_END(&cprinfo, dis->dreq_mutex);
		}

		/* RMC_COMM_DREQ_ST_EXIT implies signal by _detach(). */
		if (dis->dreq_state == RMC_COMM_DREQ_ST_EXIT) {
			dis->dreq_state = RMC_COMM_DREQ_ST_NOTSTARTED;
			dis->dreq_tid = 0;

			/* dis->dreq_mutex is held at this point! */
			CALLB_CPR_EXIT(&cprinfo);

			thread_exit();
			/* NOTREACHED */
		}

		ASSERT(dis->dreq_state == RMC_COMM_DREQ_ST_PROCESS);
		mutex_exit(dis->dreq_mutex);

		/*
		 * deliver the request (and wait...)
		 */
		while (rmc_comm_send_req_resp(rcs, &dis->dreq_request, NULL,
		    RMC_COMM_DREQ_DEFAULT_TIME) == RCEGENERIC) {
		}

		mutex_enter(dis->dreq_mutex);
		if (dis->dreq_state != RMC_COMM_DREQ_ST_EXIT)
			dis->dreq_state = RMC_COMM_DREQ_ST_WAIT;
	}
}

/*
 * start thread to deal with pending requests to be delivered asynchronously
 * (i.e. leaf driver do not have to/cannot wait for a reply/ACk of a request)
 */
static int
rmc_comm_dreq_thread_start(struct rmc_comm_state *rcs)
{
	rmc_comm_drvintf_state_t *dis = &rcs->drvi_state;
	int err = 0;
	kthread_t *tp;

	mutex_enter(dis->dreq_mutex);

	if (dis->dreq_state == RMC_COMM_DREQ_ST_NOTSTARTED) {

		tp = thread_create(NULL, 0, rmc_comm_send_pend_req,
		    (caddr_t)rcs, 0, &p0, TS_RUN, maxclsyspri);
		dis->dreq_state = RMC_COMM_DREQ_ST_READY;
		dis->dreq_tid = tp->t_did;
	}

	mutex_exit(dis->dreq_mutex);

	return (err);
}

/*
 * stop the thread (to deliver pending request messages)
 */
static void
rmc_comm_dreq_thread_kill(struct rmc_comm_state *rcs)
{
	rmc_comm_drvintf_state_t *dis = &rcs->drvi_state;
	kt_did_t tid;

	mutex_enter(dis->dreq_mutex);
	tid = dis->dreq_tid;
	if (tid != 0) {
		dis->dreq_state = RMC_COMM_DREQ_ST_EXIT;
		dis->dreq_tid = 0;
		cv_signal(dis->dreq_sig_cv);
	}
	mutex_exit(dis->dreq_mutex);

	/*
	 * Wait for rmc_comm_send_pend_req() to finish
	 */
	if (tid != 0)
		thread_join(tid);
}

/*
 * init function - start thread to deal with pending requests (no-wait requests)
 */
int
rmc_comm_drvintf_init(struct rmc_comm_state *rcs)
{
	int err = 0;

	DPRINTF(rcs, DGEN, (CE_CONT, "rmc_comm_drvintf_init\n"));
	rcs->drvi_state.dreq_state = RMC_COMM_DREQ_ST_NOTSTARTED;
	rcs->drvi_state.dreq_tid = 0;

	mutex_init(rcs->drvi_state.dreq_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(rcs->drvi_state.dreq_sig_cv, NULL, CV_DRIVER, NULL);

	err = rmc_comm_dreq_thread_start(rcs);
	if (err != 0) {
		cv_destroy(rcs->drvi_state.dreq_sig_cv);
		mutex_destroy(rcs->drvi_state.dreq_mutex);
	}

	DPRINTF(rcs, DGEN, (CE_CONT, "thread started? err=%d\n", err));

	return (err);
}

/*
 * fini function - kill thread to deal with pending requests (no-wait requests)
 */
void
rmc_comm_drvintf_fini(struct rmc_comm_state *rcs)
{
	DPRINTF(rcs, DGEN, (CE_CONT, "rmc_comm_drvintf_fini:stop thread\n"));

	rmc_comm_dreq_thread_kill(rcs);

	DPRINTF(rcs, DGEN, (CE_CONT, "rmc_comm_drvintf_fini:destroy Mx/CVs\n"));

	cv_destroy(rcs->drvi_state.dreq_sig_cv);
	mutex_destroy(rcs->drvi_state.dreq_mutex);
}
