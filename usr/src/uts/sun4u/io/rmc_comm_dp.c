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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * implementation of the transport layer protocol (known as librsc protocol):
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Header files
 */

#include <sys/conf.h>
#include <sys/cyclic.h>
#include <sys/membar.h>
#include <sys/modctl.h>
#include <sys/strlog.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/types.h>
#include <sys/rmc_comm_dp.h>
#include <sys/rmc_comm_dp_boot.h>
#include <sys/rmc_comm_drvintf.h>
#include <sys/rmc_comm.h>

#ifdef DEBUG_ERROR_INJECTION

#define	ERRI_RX_SEQ_NUMBER	1
#define	ERRI_ACK_MSG		2
#define	ERRI_CRC_HEADER		3
#define	ERRI_CRC_MSG		4
#define	ERRI_SEND_CTL_STACK	5
#define	ERRI_SEND_CTL_START	6

#define	ERRI_CTL_RX_SEQ_NUMBER	7
#define	ERRI_CTL_CRC_HEADER	8

int	erri_test_number = 0;
int	erri_test_intrvl = 0;
int	erri_test_repeat = 0;
int	erri_test_count = 0;

int erri_test_simulate_srec_sec(struct rmc_comm_state *, char *, int);

#endif


/* static functions */

static void dp_link_setup_tohandler(void *);
static void dp_delay_ack_tohandler(void *);
static uint8_t *dp_get_buffer(struct rmc_comm_state *, uint8_t);
static void dp_release_buffer(struct rmc_comm_state *, uint8_t);
static void dp_init_buffers(struct rmc_comm_state *);
static void dp_got_full_hdr(struct rmc_comm_state *, dp_packet_t *);
static void dp_got_bp_msg(struct rmc_comm_state *, dp_packet_t *);
static void dp_got_full_msg(struct rmc_comm_state *, dp_packet_t *);
static void dp_tx_handle_ack(struct rmc_comm_state *, uint16_t);
static void dp_tx_handle_nak(struct rmc_comm_state *, uint16_t);
static void dp_send_packet(struct rmc_comm_state *, uchar_t *);
static void dp_enable_data_link(struct rmc_comm_state *);
static int dp_get_msglen(struct rmc_comm_state *, uint8_t *);
static uint16_t dp_calc_crc16(uint8_t *, int);
void dp_wake_up_waiter(struct rmc_comm_state *, uint8_t);
void dp_reset(struct rmc_comm_state *, uint8_t, boolean_t, boolean_t);

/*
 * utilities...
 */

/*
 *  init rx/tx buffer pool
 */
static void
dp_init_buffers(struct rmc_comm_state *rcs)
{
	int i;
	dp_buffer_t *dbuf = rcs->dp_state.dp_buffers;

	for (i = 0; i < DP_BUFFER_COUNT; i++)
		dbuf[i].in_use = 0;
}

/*
 *  get tx/rx buffer
 */
static uint8_t *
dp_get_buffer(struct rmc_comm_state *rcs, uint8_t type)
{
	dp_buffer_t *dbuf = rcs->dp_state.dp_buffers;

	ASSERT(MUTEX_HELD(rcs->dp_state.dp_mutex));

	if ((type != DP_TX_BUFFER && type != DP_RX_BUFFER) ||
		dbuf[type].in_use) {

		DPRINTF(rcs, DMEM,
			(CE_CONT, "get buffer err. type=%d, in_use=%d\n",
			type, dbuf[type].in_use));

		return (NULL);
	}

	DPRINTF(rcs, DMEM, (CE_CONT, "get buffer type=%d\n", type));

	dbuf[type].in_use = 1;

	return (dbuf[type].buf);
}

/*
 * release tx/rx buffer
 */
static void
dp_release_buffer(struct rmc_comm_state *rcs, uint8_t type)
{
	dp_buffer_t *dbuf = rcs->dp_state.dp_buffers;

	ASSERT(MUTEX_HELD(rcs->dp_state.dp_mutex));

	if (type != DP_TX_BUFFER && type != DP_RX_BUFFER) {
		DPRINTF(rcs, DMEM,
			(CE_CONT, "free buffer err. type=%d, in_use=%d\n",
			type, dbuf[type].in_use));
		return;
	}
	DPRINTF(rcs, DMEM, (CE_CONT, "free buffer type=%d\n", type));

	dbuf[type].in_use = 0;
}

/*
 * setup data link timeout handler
 * (called without having the dp_mutex)
 */
static void
dp_link_setup_tohandler(void *arg)
{
	struct rmc_comm_state *rcs = (struct rmc_comm_state *)arg;
	rmc_comm_dp_state_t *dps = &rcs->dp_state;

	DPRINTF(rcs, DPRO, (CE_CONT, "t/o setup data link\n"));

	/*
	 * check if timer has actually been cancelled
	 */
	mutex_enter(dps->dp_mutex);
	if (dps->timer_link_setup != (timeout_id_t)0) {

		/*
		 * send CTL:start to the remote side to set up the data link
		 */
		(void) rmc_comm_dp_ctlsend(rcs, DP_CTL_START);

		dps->timer_link_setup = timeout(dp_link_setup_tohandler,
		    (void *) rcs, drv_usectohz(RETRY_DP_SETUP * 1000));
	}
	mutex_exit(dps->dp_mutex);
}

/*
 * delay acknowledgment of a received message timeout handler
 * (called without having the dp_mutex)
 */
static void
dp_delay_ack_tohandler(void *arg)
{
	struct rmc_comm_state *rcs = (struct rmc_comm_state *)arg;
	rmc_comm_dp_state_t *dps = &rcs->dp_state;

#ifdef DEBUG_ERROR_INJECTION

	if (erri_test_number == ERRI_ACK_MSG &&
	    erri_test_repeat >= 0 &&
	    erri_test_count++ > 0 && !(erri_test_count % erri_test_intrvl)) {

		/*
		 * DON'T ACK THE MESSAGE - BE SILENT!
		 */

		if (erri_test_repeat == 0)
			erri_test_repeat--; /* will not repeat the test */

		dps->timer_delay_ack = (timeout_id_t)0;
		return;
	}

#endif

	/*
	 * check if timer has actually been cancelled
	 */
	mutex_enter(dps->dp_mutex);
	if (dps->timer_delay_ack != (timeout_id_t)0) {
		/*
		 * ACK the message
		 */
		(void) rmc_comm_dp_ctlsend(rcs, DP_CTL_ACK);
		dps->timer_delay_ack = (timeout_id_t)0;
	}
	mutex_exit(dps->dp_mutex);
}

/*
 * Enable data link protocol:
 *  stop data link setup timer
 *  set data_link_ok flag
 * (must already have the dp_mutex)
 */
static void
dp_enable_data_link(struct rmc_comm_state *rcs)
{
	rmc_comm_dp_state_t	*dps = &rcs->dp_state;
	timeout_id_t		 timer_id;

	ASSERT(MUTEX_HELD(dps->dp_mutex));

	dps->data_link_ok = 1;

	timer_id = dps->timer_link_setup;
	dps->timer_link_setup = (timeout_id_t)0;
	if (timer_id != (timeout_id_t)0) {

		mutex_exit(dps->dp_mutex);
		(void) untimeout(timer_id);
		mutex_enter(dps->dp_mutex);
	}
}

/*
 * CRC calculation routine.
 */
static uint16_t
dp_calc_crc16(uint8_t *buf, int len)
{
	extern uint16_t crctab16[];
	uint16_t crc;

	crc = 0;
	while (len--) {
		crc = (crc >> 8) ^ crctab16[(crc ^ *buf++) & 0xFF];
	}
	return (crc);
}

/*
 * Reset the data protocol
 * (dp_mutex must be held)
 */
void
dp_reset(struct rmc_comm_state *rcs, uint8_t rx_seqid,
    boolean_t flush_tx, boolean_t restart_data_link)
{
	rmc_comm_dp_state_t *dps = &rcs->dp_state;

	ASSERT(MUTEX_HELD(dps->dp_mutex));

	DPRINTF(rcs, DPRO, (CE_CONT,
	    "reset proto: rxsid=%d, flushtx=%d, restartdp=%d\n",
	    rx_seqid, flush_tx, restart_data_link));

	DPRINTF(rcs, DGEN, (CE_CONT,
	    "stats: reset=%d nak=%d start=%d stack=%d retries=%d crcerr=%d\n",
	    dps->reset_cnt, dps->nak_cnt, dps->start_cnt, dps->stack_cnt,
	    dps->retries_cnt, dps->crcerr_cnt));

	dps->last_rx_seqid = rx_seqid;
	dps->reset_cnt++;

	/*
	 * Flush pending tx message.
	 */
	if (flush_tx) {
		dps->last_tx_seqid = INITIAL_SEQID;
		dps->last_rx_ack = rx_seqid;

		/*
		 * if there is any pending request/response session
		 * then just abort it.
		 */
		dp_wake_up_waiter(rcs, MSG_ERROR);
	}

	/*
	 * restart data link, but only if the data link set up timer is
	 * not already running.
	 */
	if (restart_data_link && dps->timer_link_setup == (timeout_id_t)0) {

		dps->data_link_ok = 0;

		/*
		 * set up the data protocol link
		 */
		(void) rmc_comm_dp_ctlsend(rcs, DP_CTL_START);
		dps->timer_link_setup = timeout(dp_link_setup_tohandler,
		    (void *)rcs, drv_usectohz(RETRY_DP_SETUP * 1000));
	}
}

/*
 * Handles acknowledgment of a message previously sent OR a heartbeat command
 * (CTL_RESPOND).
 */
static void
dp_tx_handle_ack(struct rmc_comm_state *rcs, uint16_t rxnum)
{
	rmc_comm_dp_state_t	*dps = &rcs->dp_state;
	dp_req_resp_t		*drr = &dps->req_resp;

	ASSERT(MUTEX_HELD(dps->dp_mutex));

	DPRINTF(rcs, DPRO, (CE_CONT, "handle ACK, rxnum=%03d\n", rxnum));

	dps->last_rx_ack = rxnum;
	if ((drr->flags & MSG_SENT) == 0) {
		/*
		 * no pending messages, so nothing to do
		 */
		return;
	}

	if (rxnum == dps->last_tx_seqid) {
		/*
		 * message was sent and acknowledged successfully
		 * set flag and signal the waiting task if it is not
		 * expecting a reply back
		 */
		drr->flags |= MSG_ACKED;
		if (drr->response.msg_type == DP_NULL_MSG) {
			dp_wake_up_waiter(rcs, MSG_ACKED);
		}
	}
}

/*
 * Handles NAK
 */
static void
dp_tx_handle_nak(struct rmc_comm_state *rcs, uint16_t rxnum)
{
	rmc_comm_dp_state_t	*dps = &rcs->dp_state;
	dp_req_resp_t		*drr = &dps->req_resp;

	ASSERT(MUTEX_HELD(dps->dp_mutex));

	DPRINTF(rcs, DPRO, (CE_CONT, "handle NAK, rxnum=%03d\n", rxnum));

	if ((drr->flags & MSG_SENT) == 0) {
		/*
		 * no pending messages, so nothing to do
		 */
		return;
	}

	/*
	 * since one message per time can be sent, it is assumed that the
	 * message being NAKed is just the one that has been sent.
	 */
	dps->nak_cnt++;

	dp_wake_up_waiter(rcs, MSG_NAKED);
}

/*
 * Got a full header. Check header CRC and get the length of the packet
 */
static void
dp_got_full_hdr(struct rmc_comm_state *rcs, dp_packet_t *pkt)
{
	/*
	 * Got the full header.  Call up to the logical layer to see
	 * how big of a buffer I need for this message.  If the size
	 * is < sizeof (dp_msg_t), then there is something wrong with
	 * this message - drop it.  If the size is equal, then hand it
	 * up right now. If the size is too big - drop it. otherwise we must
	 * receive the body of the message.
	 */

	pkt->full_length = dp_get_msglen(rcs, pkt->buf);

	DPRINTF(rcs, DPKT, (CE_CONT, "got header msglen=%d\n",
	    pkt->full_length));

	if ((pkt->full_length < 0) ||
	    (pkt->full_length < sizeof (dp_header_t)) ||
	    (pkt->full_length > DP_BUFFER_SIZE)) {
		/*
		 * not a valid message: either message too big or too small
		 */
		dp_release_buffer(rcs, DP_RX_BUFFER);
		pkt->buf = NULL;

		pkt->rx_state = WAITING_FOR_SYNC;

	} else if (pkt->full_length == sizeof (dp_header_t)) {
		/*
		 * process message: it is basically a control message
		 * (no data being carried)
		 */
		rmc_comm_dp_mrecv(rcs, pkt->buf);

		dp_release_buffer(rcs, DP_RX_BUFFER);
		pkt->buf = NULL;

		pkt->rx_state = WAITING_FOR_SYNC;
	} else {
		pkt->rx_state = RECEIVING_BODY;
	}
}

/*
 * Got a BP (boot prom) message. Usually, BP messages are received when
 * the firmware goes into boot monitor mode (where only BP protocol is used).
 * This just happens during firmware download. There should not be any other
 * case where a BP message is received.
 */
static void
dp_got_bp_msg(struct rmc_comm_state *rcs, dp_packet_t *pkt)
{
	bp_msg_t		*msgp = (bp_msg_t *)pkt->buf;
	rmc_comm_dp_state_t	*dps = &rcs->dp_state;
	dp_req_resp_t		*drr = &dps->req_resp;
	int			datalen = sizeof (bp_msg_t);

	ASSERT(MUTEX_HELD(dps->dp_mutex));

	/*
	 * ignore BP message, if it is not expected
	 */
	if ((drr->flags & MSG_SENT_BP) != 0) {

		DPRINTF(rcs, DPRO, (CE_CONT, "got bp msg: %02x %02x %02x\n",
		    msgp->cmd, msgp->dat1, msgp->dat2));

		/*
		 * A boot prom (BP) msg has been sent. Here is the
		 * 'expected' reply
		 */

		/*
		 * check that the recv buffer is big enough (just in case).
		 */
		if (datalen <= drr->response.msg_bufsiz) {
			bcopy(pkt->buf, drr->response.msg_buf, datalen);
			drr->response.msg_msglen = datalen;
			dp_wake_up_waiter(rcs, MSG_RXED_BP);
		} else {
			drr->response.msg_msglen = -1;
			dp_wake_up_waiter(rcs, MSG_RXED_BP);
		}
	}

	/* Return the buffer to the pool and wait for the next msg. */
	dp_release_buffer(rcs, DP_RX_BUFFER);
	pkt->buf = NULL;
	pkt->rx_state = WAITING_FOR_SYNC;
}

/*
 * Got a complete message, check CRC and pass it on to the upper layer (message
 * processing)
 */
static void
dp_got_full_msg(struct rmc_comm_state *rcs, dp_packet_t *pkt)
{
	uint16_t	 crc;
	int		 msglen;

	DPRINTF(rcs, DPKT, (CE_CONT, "got full msg\n"));

	/*
	 * check message CRC
	 */

	msglen = pkt->full_length - sizeof (dp_header_t) - sizeof (crc);

	bcopy(pkt->buf + (pkt->full_length - sizeof (crc)), &crc, sizeof (crc));

	if (crc == dp_calc_crc16(pkt->buf + sizeof (dp_header_t), msglen)) {
		/*
		 * CRC is ok, process this message
		 */
		DPRINTF(rcs, DPKT, (CE_CONT, "got 'good' msg\n"));

		rmc_comm_dp_mrecv(rcs, pkt->buf);
	} else {
		DPRINTF(rcs, DPKT, (CE_CONT, "CRC error (msg)\n"));
		rcs->dp_state.crcerr_cnt++;
	}

	dp_release_buffer(rcs, DP_RX_BUFFER);
	pkt->buf = NULL;

	pkt->rx_state = WAITING_FOR_SYNC;
}

/*
 * Check the checksum of the header & return the length field.  If the
 * checksum check fails, then return -1.
 */
static int
dp_get_msglen(struct rmc_comm_state *rcs, uint8_t *buf)
{
	dp_header_t 	*dp_msgp;
	uint16_t	 crc;

	dp_msgp = (dp_header_t *)buf;

	crc = dp_calc_crc16(buf + sizeof (dp_msgp->pad), sizeof (dp_header_t) -
	    sizeof (dp_msgp->crc) - sizeof (dp_msgp->pad));

	if (dp_msgp->crc == crc) {
		return (dp_msgp->length + sizeof (dp_msgp->pad));
	} else {
		DPRINTF(rcs, DPKT, (CE_CONT, "CRC error (header)\n"));
		rcs->dp_state.crcerr_cnt++;
		return (-1);
	}
}

/*
 * to send a protocol packet to the remote side. it handles escaping SYNC
 * and ESC chars
 */
static void
dp_send_packet(struct rmc_comm_state *rcs, uchar_t *buf)
{
	char syncbuf[2];
	dp_header_t *dp_msgp = (dp_header_t *)buf;
	int total, cur;

	/* First, send out two SYNC characters. */
	syncbuf[0] = syncbuf[1] = (char)SYNC_CHAR;
	rmc_comm_serdev_send(rcs, syncbuf, 2);

	total = dp_msgp->length;
	buf = buf + sizeof (dp_msgp->pad);

	while (total > 0) {
		cur = 0;

		/* Count up characters that don't need ESC'ing. */
		while ((cur < total) &&
		    (buf[cur] != ESC_CHAR) &&
		    (buf[cur] != SYNC_CHAR)) {
			cur++;
		}

		/* Send characters that don't need escaping, if any. */
		if (cur > 0) {
			rmc_comm_serdev_send(rcs, (char *)buf, cur);
			total -= cur;
			buf += cur;
		}

		/*
		 * If total > 0 at this point, we need to send an
		 * ESC'd character.  Send as many as there are.
		 */
		while ((total > 0) &&
		    ((*buf == SYNC_CHAR) || (*buf == ESC_CHAR))) {
			syncbuf[0] = (char)ESC_CHAR;
			syncbuf[1] = *buf;
			rmc_comm_serdev_send(rcs, syncbuf, 2);
			buf++;
			total--;
		}
	}
}

/*
 * to wake a thread waiting for a reply/ACK/error status for a request/response
 * session.
 */
void
dp_wake_up_waiter(struct rmc_comm_state *rcs, uint8_t flags)
{
	dp_req_resp_t *drr = &rcs->dp_state.req_resp;

	ASSERT(MUTEX_HELD(rcs->dp_state.dp_mutex));

	DPRINTF(rcs, DGEN, (CE_CONT, "wake up? %x, set %x\n",
	    (drr->flags & (MSG_SENT | MSG_SENT_BP)) != 0, flags));

	if ((drr->flags & (MSG_SENT | MSG_SENT_BP)) != 0) {
		drr->flags |= flags;
		cv_signal(drr->cv_wait_reply);
	}
}

/*
 * initialization of the data protocol (called from the attach routine)
 */
void
rmc_comm_dp_init(struct rmc_comm_state *rcs)
{
	rmc_comm_dp_state_t *dps = &rcs->dp_state;
	dp_packet_t *pkt = &dps->dp_packet;

	DPRINTF(rcs, DGEN, (CE_CONT, "rmc_comm_dp_init\n"));

	/*
	 * initialize data structure:
	 */
	bzero((void *) dps, sizeof (rmc_comm_dp_state_t));

	/*
	 * initialize packet receive handler state
	 */

	pkt->rx_state = WAITING_FOR_SYNC;

	/*
	 * cv variables initialization
	 * (dp_mutex has been already created during the serial device
	 * initialization)
	 */
	cv_init(dps->cv_ok_to_send, NULL, CV_DRIVER, NULL);
	cv_init(dps->req_resp.cv_wait_reply, NULL, CV_DRIVER, NULL);

	mutex_enter(dps->dp_mutex);

	dp_init_buffers(rcs);

	/*
	 * initialize the data protocol (reset sequence numbers, etc.)
	 */
	dps->last_tx_seqid = INITIAL_SEQID;
	dps->last_rx_seqid = dps->last_rx_ack = INITIAL_SEQID;

	/*
	 * start timer to 'delay' the set up of the data protocol link
	 */
	dps->timer_link_setup = timeout(dp_link_setup_tohandler,
	    (void *)rcs, drv_usectohz(DELAY_DP_SETUP * 1000));

	mutex_exit(dps->dp_mutex);

#ifdef DEBUG_ERROR_INJECTION

	erri_test_number = ddi_prop_get_int(DDI_DEV_T_ANY, rcs->dip,
	    DDI_PROP_DONTPASS, "test-no", 0);
	erri_test_intrvl = ddi_prop_get_int(DDI_DEV_T_ANY, rcs->dip,
	    DDI_PROP_DONTPASS, "test-interval", 0);
	erri_test_repeat = ddi_prop_get_int(DDI_DEV_T_ANY, rcs->dip,
	    DDI_PROP_DONTPASS, "test-repeat", 0);

	erri_test_count = 0;


	cmn_err(CE_CONT, "error injection test: no=%d, intrvl=%d, rep=%d\n",
	    erri_test_number, erri_test_intrvl, erri_test_repeat);
#endif

}

/*
 * termination of the data protocol (called from the detach routine)
 */
void
rmc_comm_dp_fini(struct rmc_comm_state *rcs)
{
	rmc_comm_dp_state_t *dps = &rcs->dp_state;
	timeout_id_t	 tid_delay_ack;
	timeout_id_t	 tid_link_setup;

	DPRINTF(rcs, DGEN, (CE_CONT,
	    "stats: reset=%d nak=%d start=%d stack=%d retries=%d crcerr=%d\n",
	    dps->reset_cnt, dps->nak_cnt, dps->start_cnt, dps->stack_cnt,
	    dps->retries_cnt, dps->crcerr_cnt));

	/*
	 * if any timer is running, must be terminated here!
	 */
	mutex_enter(dps->dp_mutex);
	tid_delay_ack = dps->timer_link_setup;
	tid_link_setup = dps->timer_delay_ack;
	dps->timer_link_setup = (timeout_id_t)0;
	dps->timer_delay_ack = (timeout_id_t)0;
	mutex_exit(dps->dp_mutex);

	if (tid_delay_ack)
		(void) untimeout(tid_delay_ack);

	if (tid_link_setup)
		(void) untimeout(tid_link_setup);

	/*
	 * cv variables termination
	 */
	cv_destroy(dps->cv_ok_to_send);
	cv_destroy(dps->req_resp.cv_wait_reply);
}

/*
 * This is the low-level receiver handler. It's job is to find a complete
 * message from the incoming data stream, and once it finds one to pass it
 * on to the upper layer (message processing).
 * (it must have the dp_mutex)
 */
void
rmc_comm_dp_drecv(struct rmc_comm_state *rcs, uint8_t *buf, int buflen)
{
	rmc_comm_dp_state_t 	*dps = &rcs->dp_state;
	dp_packet_t 		*pkt = &dps->dp_packet;
	uint8_t			 quit;
	int			 count;
	int			 max;

	ASSERT(MUTEX_HELD(dps->dp_mutex));

	pkt->inbuf = buf;
	pkt->inbuflen = buflen;

	DPRINTF(rcs, DPKT, (CE_CONT, "drecv len=%d\n", buflen));

	while (pkt->inbuflen > 0) {
		switch (pkt->rx_state) {

		case WAITING_FOR_SYNC:
			while ((pkt->inbuflen > 0) &&
			    (*pkt->inbuf != SYNC_CHAR) &&
			    (*pkt->inbuf != ESC_CHAR)) {

				DPRINTF(rcs, DPKT,
				    (CE_CONT, "not SYNC: %02x\n",
				    (uchar_t)(*pkt->inbuf)));

				pkt->inbuf++;
				pkt->inbuflen--;
			}

			if (pkt->inbuflen > 0) {
				if (*pkt->inbuf == SYNC_CHAR)
					pkt->rx_state = WAITING_FOR_HDR;
				else if (*pkt->inbuf == ESC_CHAR)
					pkt->rx_state = WAITING_FOR_SYNC_ESC;
			}
			break;

		case WAITING_FOR_SYNC_ESC:
			pkt->inbuf++;
			pkt->inbuflen--;
			pkt->rx_state = WAITING_FOR_SYNC;
			break;

		case WAITING_FOR_HDR:
			while ((pkt->inbuflen > 0) &&
			    (*pkt->inbuf == SYNC_CHAR)) {
				pkt->inbuf++;
				pkt->inbuflen--;
			}

			if (pkt->inbuflen <= 0)
				break;

			if (*pkt->inbuf == ESC_CHAR) {
				/*
				 * ESC as first char of header?
				 * Impossible - start over!
				 */
				pkt->rx_state = WAITING_FOR_SYNC;
				pkt->inbuf++;
				pkt->inbuflen--;
				break;
			}

			/* Get a buffer for this message. */
			pkt->buf = dp_get_buffer(rcs, DP_RX_BUFFER);
			if (pkt->buf == NULL) {
				/* Out of buffers - drop this msg. */
				pkt->rx_state = WAITING_FOR_SYNC;
				break;
			}
			DPRINTF(rcs, DPKT, (CE_CONT, "drecv first char %x\n",
			    (uchar_t)*pkt->inbuf));

			pkt->buf[1] = *pkt->inbuf;
			pkt->bufpos = 2;
			pkt->rx_state = RECEIVING_HDR;

			pkt->inbuf++;
			pkt->inbuflen--;
			break;

		case RECEIVING_HDR:
			quit = 0;
			while ((pkt->inbuflen > 0) &&
			    (*pkt->inbuf != SYNC_CHAR) &&
			    (*pkt->inbuf != ESC_CHAR)) {
				pkt->buf[pkt->bufpos++] = *pkt->inbuf;
				pkt->inbuf++;
				pkt->inbuflen--;
				if (pkt->bufpos >= sizeof (dp_header_t)) {
					dp_got_full_hdr(rcs, pkt);
					quit = 1;
					break;
				} else if ((pkt->bufpos >= sizeof (bp_msg_t)) &&
				    (IS_BOOT_MSG(pkt->buf[1]))) {
					dp_got_bp_msg(rcs, pkt);
					quit = 1;
					break;
				}
			}

			if (quit)
				break;

			if (pkt->inbuflen > 0) {
				/* Must have gotten an ESC_CHAR or SYNC_CHAR. */
				if (*pkt->inbuf == SYNC_CHAR) {

					DPRINTF(rcs, DPKT,
						(CE_CONT, "drecv sync in hdr, "
						"bufpos=%d\n", pkt->bufpos));

					dp_release_buffer(rcs, DP_RX_BUFFER);
					pkt->buf = NULL;
					pkt->rx_state = WAITING_FOR_HDR;
				} else {
					pkt->rx_state = RECEIVING_HDR_ESC;
				}
				pkt->inbuf++;
				pkt->inbuflen--;
			}
			break;

		case RECEIVING_HDR_ESC:
			pkt->buf[pkt->bufpos++] = *pkt->inbuf;
			pkt->inbuf++;
			pkt->inbuflen--;
			if (pkt->bufpos >= sizeof (dp_header_t)) {
				dp_got_full_hdr(rcs, pkt);
			} else if ((pkt->bufpos >= sizeof (bp_msg_t)) &&
			    (IS_BOOT_MSG(pkt->buf[1]))) {
				dp_got_bp_msg(rcs, pkt);
			} else {
				pkt->rx_state = RECEIVING_HDR;
			}
			break;

		case RECEIVING_BODY:
			max = pkt->full_length - pkt->bufpos;
			if (max > pkt->inbuflen)
				max = pkt->inbuflen;

			for (count = 0; count < max; count++)
				if ((pkt->inbuf[count] == SYNC_CHAR) ||
				    (pkt->inbuf[count] == ESC_CHAR))
					break;

			if (count > 0) {
				bcopy(pkt->inbuf, pkt->buf + pkt->bufpos,
				    count);
				pkt->inbuf += count;
				pkt->inbuflen -= count;
				pkt->bufpos += count;

				if (pkt->bufpos >= pkt->full_length) {
					dp_got_full_msg(rcs, pkt);
					break;
				}
			}

			if (count < max) {
				/* Must have gotten an ESC_CHAR or SYNC_CHAR. */
				if (*pkt->inbuf == SYNC_CHAR) {
					dp_release_buffer(rcs, DP_RX_BUFFER);
					pkt->buf = NULL;
					pkt->rx_state = WAITING_FOR_HDR;
				} else {
					pkt->rx_state = RECEIVING_BODY_ESC;
				}
				pkt->inbuf++;
				pkt->inbuflen--;
			}
			break;

		case RECEIVING_BODY_ESC:
			pkt->buf[pkt->bufpos] = *pkt->inbuf;
			pkt->inbuf++;
			pkt->inbuflen--;
			pkt->bufpos++;
			if (pkt->bufpos >= pkt->full_length) {
				dp_got_full_msg(rcs, pkt);
			} else {
				pkt->rx_state = RECEIVING_BODY;
			}
			break;
		}
	}
}

/*
 * Handle an incoming message. CRCs have been already checked so message
 * is good. check if sequence numbers are ok.
 * Handles: control message, asynchronous notification, reply to requests
 * and notify the leaf driver of those events.
 * (it must have the dp_mutex)
 */
void
rmc_comm_dp_mrecv(struct rmc_comm_state *rcs, uint8_t *buf)
{
	rmc_comm_dp_state_t *dps = &rcs->dp_state;
	dp_header_t *dp_msgp;
	uint8_t *datap;
	int datalen;
	dp_msg_intr_t *dmi = &dps->msg_intr;
	dp_req_resp_t *drr = &dps->req_resp;

	ASSERT(MUTEX_HELD(dps->dp_mutex));

	dp_msgp = (dp_header_t *)buf;

	datalen = dp_msgp->length -
	    (sizeof (dp_header_t) - sizeof (dp_msgp->pad));

	if (datalen > 0) {
		datalen = datalen - sizeof (uint16_t); /* don't count msg CRC */
		datap = buf + sizeof (dp_header_t);
	} else {
		datap = NULL;
	}

	DPRINTF(rcs, DPRO, (CE_CONT,
	    "[t%03dr%03d] mrecv msgtype: %02x, len=%d\n",
	    dp_msgp->txnum, dp_msgp->rxnum, dp_msgp->type, datalen));

	/*
	 * Handle control messages first
	 */
	if (IS_UNNUMBERED_MSG(dp_msgp->type)) {
		switch (dp_msgp->type) {
		case DP_CTL_START:
			/*
			 * CTL:start
			 * Re-init protocol processing.
			 * Enable data link
			 * Stop data link setup timer if running
			 */
			DPRINTF(rcs, DPRO, (CE_CONT, "mrecv data link ok\n"));

			dp_reset(rcs, dp_msgp->txnum, 1, 0);

			dp_wake_up_waiter(rcs, 0);

			/* Send CTL:stack message. */
			(void) rmc_comm_dp_ctlsend(rcs, DP_CTL_STACK);

			dps->start_cnt++;

			dp_enable_data_link(rcs);

			break;

		case DP_CTL_STACK:
			/*
			 * CTL:stack
			 * Enable data link
			 * Stop data link setup timer if running
			 */
			DPRINTF(rcs, DPRO, (CE_CONT, "mrecv data link ok\n"));

			dp_reset(rcs, dp_msgp->txnum, 0, 0);

			dp_wake_up_waiter(rcs, 0);

			dps->stack_cnt++;

			dp_enable_data_link(rcs);
			break;

		case DP_CTL_RESPOND:
			/*
			 * CTL:respond (heartbeat)
			 * Send a CTL:ack.
			 */
			if (dps->data_link_ok) {
				(void) rmc_comm_dp_ctlsend(rcs, DP_CTL_ACK);
			}
			break;

		case DP_CTL_ACK:
			/*
			 * CTL:ack
			 * Call a transmit-side routine to handle it.
			 */
			dp_tx_handle_ack(rcs, dp_msgp->rxnum);
			break;

		case DP_CTL_NAK:
			/*
			 * CTL:nak
			 * Call a transmit-side routine to handle it.
			 */
			dp_tx_handle_nak(rcs, dp_msgp->rxnum);
			break;

		default:
			/* Drop message. */
			DPRINTF(rcs, DPRO,
			    (CE_CONT, "mrecv unknown ctrlmsg\n"));
			break;
		}
		return;
	}

	/*
	 * Before processing the received message (NUMBERED), check that the
	 * data link protocol is up. If not, ignore this message
	 */
	if (!dps->data_link_ok) {
		DPRINTF(rcs, DPRO, (CE_CONT, "mrecv drop msg: no data link\n"));
		return;
	}

	/*
	 * we received a message (NUMBERED) and data link is ok.
	 * First, instead of ACKing this message now, we delay it. The reason
	 * why is that a message can be sent (from this side) in the meantime
	 * and it can ACK the received message (it will spare us to send
	 * the ACK message across the wire).
	 */

	/*
	 * Handle acknowledgements even if this is a duplicate message.
	 */
	if (dps->timer_delay_ack == (timeout_id_t)0) {
		dps->timer_delay_ack = timeout(dp_delay_ack_tohandler,
		    (void *) rcs, drv_usectohz(TX_RETRY_TIME/2 * 1000));
		DPRINTF(rcs, DGEN, (CE_CONT, "mrecv start ack t/o %p\n",
		    dps->timer_delay_ack));
	}
	dp_tx_handle_ack(rcs, dp_msgp->rxnum);

	if (dp_msgp->txnum != NEXT_SEQID(dps->last_rx_seqid)) {
		/* Duplicate message - free it up & return. */
		DPRINTF(rcs, DPRO, (CE_CONT, "mrecv dup msg txnum=%03d\n",
		    dp_msgp->txnum));
		return;
	}
	dps->last_rx_seqid = dp_msgp->txnum;

#ifdef DEBUG_ERROR_INJECTION

	if ((erri_test_number == ERRI_SEND_CTL_STACK ||
	    erri_test_number == ERRI_SEND_CTL_START) &&
	    erri_test_repeat >= 0 &&
	    erri_test_count++ > 0 && !(erri_test_count % erri_test_intrvl)) {

		if (erri_test_number == ERRI_SEND_CTL_STACK) {
			(void) rmc_comm_dp_ctlsend(rcs, DP_CTL_STACK);

		} else if (erri_test_number == ERRI_SEND_CTL_START) {
			(void) rmc_comm_dp_ctlsend(rcs, DP_CTL_START);

		}
		if (erri_test_repeat == 0)
			erri_test_repeat--; /* will not repeat the test */
	}

#endif

	/*
	 * At this point, we know this is a good message.  We've
	 * checked checksums, message types, and sequence id's.
	 */

	/*
	 * First, check if a driver has register for this message
	 * Second, check if this message is a reply to a request
	 * Third, check to see if ALOM is telling us it doesn't
	 * know about the command code.
	 */

	if (dmi->intr_handler != NULL &&
	    dmi->intr_msg_type == dp_msgp->type) {

		rmc_comm_msg_t 	*msgi = (rmc_comm_msg_t *)dmi->intr_arg;

		DPRINTF(rcs, DPRO, (CE_CONT,
		    "mrecv process async msg len=%d, max=%d\n",
		    datalen, msgi->msg_len));
		/*
		 * process asynchronous notification only if the registered
		 * driver is not currently processing any other notification
		 */
		mutex_enter(dmi->intr_lock);
		if (dmi->intr_state == NULL ||
		    (dmi->intr_state != NULL &&
		    *(dmi->intr_state) == RMC_COMM_INTR_IDLE)) {
			/*
			 * check that the buffer is big enough. do not want to
			 * cross boundaries here..
			 */
			if (datalen <= msgi->msg_len) {
				bcopy(datap, msgi->msg_buf, datalen);
				msgi->msg_bytes = datalen;

			} else {
				msgi->msg_bytes = -1;
			}
			/*
			 * trigger soft intr. in any case.
			 * if message is too big, at least, the leaf driver
			 * will be notified (bytes returned will be -1)
			 */
			ddi_trigger_softintr(dmi->intr_id);
		}
		mutex_exit(dmi->intr_lock);

	} else if ((drr->flags & MSG_SENT) != 0 &&
	    drr->response.msg_type == dp_msgp->type) {

		DPRINTF(rcs, DPRO, (CE_CONT,
		    "mrecv process reply len=%d, max=%d\n",
		    datalen, drr->response.msg_bufsiz));

		/*
		 * check that the recv buffer is big enough.
		 */
		if (datalen <= drr->response.msg_bufsiz) {
			bcopy(datap, drr->response.msg_buf, datalen);
			drr->response.msg_msglen = datalen;
			dp_wake_up_waiter(rcs, MSG_REPLY_RXED);
		} else {
			drr->response.msg_msglen = -1;
			dp_wake_up_waiter(rcs, MSG_REPLY_RXED);
		}
	} else if (dp_msgp->type == DP_INVCMD &&
	    (drr->flags & MSG_SENT) != 0 &&
	    ((dp_invcmd_t *)datap)->inv_type == drr->request.msg_type) {
		drr->error_status = RCEINVCMD;
		dp_wake_up_waiter(rcs, MSG_ERROR);
	}
}

/*
 * to send a control message (unnumbered message)
 * (it must have the dp_mutex)
 */
int
rmc_comm_dp_ctlsend(struct rmc_comm_state *rcs, uint8_t type)
{
	dp_message_t ctlmsg;
	int err = RCNOERR;

	ctlmsg.msg_type = type;
	ctlmsg.msg_buf = NULL;
	ctlmsg.msg_msglen = 0;

	err = rmc_comm_dp_msend(rcs, &ctlmsg);

	return (err);
}

/*
 * to send data to the remote party.
 *
 * NUMBERED messages carry payload data of variable size. A buffer is allocated
 * dynamically for the trasmission of data. NUMBERED message trasmission
 * data status is stored in the dp_state request_response data structure.
 * This because: data sent must be acknowledged, trasmission can be re-tried,
 * upper layer has to know the state/result of the trasmission. Upper layer has
 * to: initialize the data struct, send data (this function), read result,
 * clean up the data struct.
 *
 * UNUMBERED data are just only control command which do not carry any payload
 * A local buffer is used (ctlbuf) instead. UNNUMBERED message are transient
 * data which is sent once and not re-tried. It does not use the
 * request_response data structure
 *
 * (it must have the dp_mutex)
 */
int
rmc_comm_dp_msend(struct rmc_comm_state *rcs, dp_message_t *req)
{
	rmc_comm_dp_state_t 	*dps = &rcs->dp_state;
	dp_req_resp_t		*drr = &dps->req_resp;
	dp_message_t		*pkt;
	dp_header_t		*dp_msgp;
	dp_message_t		 ctl;
	dp_header_t		 ctlbuf;
	uint16_t		 data_crc;
	timeout_id_t		 timer_delay_ack = 0;
	char			 first_time = 0;

	ASSERT(MUTEX_HELD(dps->dp_mutex));

	DPRINTF(rcs, DPRO, (CE_CONT, "msend msgtype=%02x\n", req->msg_type));

	if (IS_NUMBERED_MSG(req->msg_type)) {
		/*
		 * if there was an error, just return the error.
		 * Otherwise if the message was already acknowledged
		 * (NUMBERED message) then, there is no need to (re)send it.
		 * just wait for an expected reply (hence, do not return an
		 * error)
		 */
		if ((drr->flags & MSG_ERROR) != 0) {

			DPRINTF(rcs, DPRO, (CE_CONT,
			    "msg send error flag=%02x\n", drr->flags));
			return (RCEGENERIC);

		} else if ((drr->flags & MSG_ACKED) != 0) {

			DPRINTF(rcs, DPRO, (CE_CONT,
			    "msg already ACKed flag=%02x\n", drr->flags));
			return (RCNOERR);

		} else if ((drr->flags & MSG_SENT) == 0) {

			first_time = 1;
		}

		/*
		 * everything is ok. Now check that the data protocol is up
		 * and running: messages cannot be sent if the link is down.
		 */
		if (!dps->data_link_ok) {
			DPRINTF(rcs, DPRO, (CE_CONT,
			    "msend: can't send msg - no data link\n"));

			/*
			 * do not return error, since it can be retried
			 * later (hoping that the data link will come
			 * up, in the meantime)
			 */
			return (RCNOERR);

		}
	} else {
		first_time = 1;
	}

	/*
	 * if the message has never been sent (and, hence, it is the first
	 * time), then prepare the protocol packet: allocate a buffer,
	 * create the message header, copy the message body into the buffer and
	 * calculate CRCs
	 */
	if (first_time) {

		if (IS_NUMBERED_MSG(req->msg_type)) {

			drr->retries_left = TX_RETRIES;

			/*
			 * Check length of the message.
			 */
			if (req->msg_msglen > DP_MAX_MSGLEN) {
				DPRINTF(rcs, DPRO,
				    (CE_CONT, "msend err: msg too big\n"));
				return (RCEINVARG);
			}

			pkt = &drr->request;

			/*
			 * check that the message buffer is not already
			 * in use (race condition). If so, return error
			 */
			if (pkt->msg_buf != NULL) {
				DPRINTF(rcs, DPRO, (CE_CONT,
				    "msend err: buf already in use\n"));
				return (RCENOMEM);
			}

			/*
			 * allocate a buffer for the protocol packet
			 */
			if ((pkt->msg_buf = dp_get_buffer(rcs,
			    DP_TX_BUFFER)) == NULL) {
				DPRINTF(rcs, DPRO, (CE_CONT,
				    "msend err: no mem\n"));
				return (RCENOMEM);
			}
			pkt->msg_bufsiz = DP_BUFFER_SIZE;

			/*
			 * increment tx sequence number if sending a NUMBERED
			 * message
			 */
			dps->last_tx_seqid = NEXT_SEQID(dps->last_tx_seqid);
		} else {
			/*
			 * UNUMBERED messages (or control messages) do not
			 * carry any data and, hence, have a 'small' fixed size
			 * (the size of the header). In this case,
			 * a 'local' buffer (ctlbuf) is used.
			 */
			pkt = &ctl;
			pkt->msg_buf = (uint8_t *)&ctlbuf;
			pkt->msg_bufsiz = sizeof (dp_header_t);
		}

#ifdef DEBUG_ERROR_INJECTION

		if (((erri_test_number == ERRI_RX_SEQ_NUMBER &&
		    IS_NUMBERED_MSG(req->msg_type)) ||
		    (erri_test_number == ERRI_CTL_RX_SEQ_NUMBER &&
		    IS_UNNUMBERED_MSG(req->msg_type))) &&
		    erri_test_repeat >= 0 &&
		    erri_test_count++ > 0 &&
		    !(erri_test_count % erri_test_intrvl)) {

			dps->last_rx_seqid--;

			if (erri_test_repeat == 0)
				erri_test_repeat--; /* will not repeat it */
		}
#endif

		/*
		 * create the protocol packet
		 */
		pkt->msg_type = req->msg_type;

		/*
		 * length of the packet (including pad bytes)
		 */
		pkt->msg_msglen = req->msg_msglen + sizeof (dp_header_t);

		/*
		 * message header:
		 *  set the message type
		 *  set the length of the message (excluding pad bytes)
		 *  set tx/rx sequence numbers
		 *  calculate CRC
		 */
		dp_msgp = (dp_header_t *)pkt->msg_buf;
		dp_msgp->type = pkt->msg_type;

		if (req->msg_msglen == 0)
			dp_msgp->length = pkt->msg_msglen -
			    sizeof (dp_msgp->pad);
		else
			dp_msgp->length = sizeof (data_crc) +
			    pkt->msg_msglen - sizeof (dp_msgp->pad);

		dp_msgp->txnum = dps->last_tx_seqid;
		dp_msgp->rxnum = dps->last_rx_seqid;

		dp_msgp->crc = dp_calc_crc16(pkt->msg_buf +
		    sizeof (dp_msgp->pad), sizeof (dp_header_t) -
		    sizeof (dp_msgp->crc) - sizeof (dp_msgp->pad));

#ifdef DEBUG_ERROR_INJECTION

		if (((erri_test_number == ERRI_CRC_HEADER &&
		    IS_NUMBERED_MSG(pkt->msg_type)) ||
		    (erri_test_number == ERRI_CTL_CRC_HEADER &&
		    IS_UNNUMBERED_MSG(pkt->msg_type))) &&
		    erri_test_repeat >= 0 &&
		    erri_test_count++ > 0 &&
		    !(erri_test_count % erri_test_intrvl)) {

			dp_msgp->crc = dp_msgp->crc/2;
			if (erri_test_repeat == 0)
				erri_test_repeat--; /* will not repeat it */
		}
#endif

		/*
		 * copy message body (if present) into the buffer
		 * and calculate message CRC
		 */
		if (req->msg_msglen > 0) {
			bcopy(req->msg_buf, pkt->msg_buf + sizeof (dp_header_t),
			    req->msg_msglen);
			data_crc = dp_calc_crc16(pkt->msg_buf +
			    sizeof (dp_header_t),
			    req->msg_msglen);

#ifdef DEBUG_ERROR_INJECTION

			if (erri_test_number == ERRI_CRC_MSG &&
			    erri_test_repeat >= 0 &&
			    erri_test_count++ > 0 &&
			    !(erri_test_count % erri_test_intrvl)) {

				data_crc = data_crc/2;
				if (erri_test_repeat == 0)
					erri_test_repeat--;
			}
#endif
			bcopy((void *) &data_crc,
			    pkt->msg_buf + (sizeof (dp_header_t) +
			    req->msg_msglen),
			    sizeof (data_crc));
		}
	} else {
		/*
		 * message has already been sent (and packetized).
		 * get the message packet from the request/response
		 * data structure
		 */
		pkt = &drr->request;
		dp_msgp = (dp_header_t *)pkt->msg_buf;
		dps->retries_cnt++;
	}

	/*
	 *  NUMBERED messages
	 */
	if (IS_NUMBERED_MSG(pkt->msg_type)) {

		/*
		 * check that we have not exceeded the maximum number of
		 * retries
		 */
		if (drr->retries_left-- <= 0) {

			drr->flags |= MSG_ERROR; /* set error flag */

			/*
			 * restart the data protocol link
			 */
			dp_reset(rcs, INITIAL_SEQID, 0, 1);

			return (RCEMAXRETRIES);
		}

		if (dps->timer_delay_ack != (timeout_id_t)0) {
			/*
			 * Cancel any pending acknowledgements - we're
			 * going to send a message which will include
			 * an acknowledgement.
			 */
			timer_delay_ack = dps->timer_delay_ack;

			/*
			 * the timer is actually removed at the end of this
			 * function since I need to release the dp_mutex.
			 * Instead I clear the timer variable so that the
			 * timeout callback will not do any processing in the
			 * meantime.
			 */
			dps->timer_delay_ack = 0;
		}

		drr->flags |= MSG_SENT;
	}

	/*
	 * set rx sequence number (as we might have received a message in the
	 * meantime). tx sequence number to be the same (we can only send one
	 * message per time)
	 */
	if (dp_msgp->rxnum != dps->last_rx_seqid) {

		dp_msgp->rxnum = dps->last_rx_seqid;

		/*
		 * re-calculate CRC (header)
		 */
		dp_msgp->crc = dp_calc_crc16(pkt->msg_buf +
		    sizeof (dp_msgp->pad), sizeof (dp_header_t) -
		    sizeof (dp_msgp->crc) - sizeof (dp_msgp->pad));
	}

	DPRINTF(rcs, DPRO, (CE_CONT, "[t%03dr%03d] msend msgtype=%02x\n",
	    dp_msgp->txnum, dp_msgp->rxnum, dp_msgp->type));

	/*
	 * send this message
	 */

	dp_send_packet(rcs, pkt->msg_buf);

	/*
	 * remove delay ack timer (if any is running)
	 * Note that the dp_mutex must be released before calling
	 * untimeout. Otherwise we may have a deadlock situation.
	 */
	if (timer_delay_ack != 0) {
		DPRINTF(rcs, DGEN, (CE_CONT, "msend remove ack timer %p\n",
		    timer_delay_ack));
		mutex_exit(dps->dp_mutex);
		(void) untimeout(timer_delay_ack);
		mutex_enter(dps->dp_mutex);
	}

	return (RCNOERR);
}

/*
 * to send a boot protocol message
 * (this is to support the firmware download feature)
 */
void
rmc_comm_bp_msend(struct rmc_comm_state *rcs, bp_msg_t *bp_msg)
{
	char syncbuf[2];

	ASSERT(MUTEX_HELD(rcs->dp_state.dp_mutex));

	DPRINTF(rcs, DPRO, (CE_CONT, "send bp msg: %02x %02x %02x\n",
	    bp_msg->cmd, bp_msg->dat1, bp_msg->dat2));

	rcs->dp_state.req_resp.flags |= MSG_SENT_BP;

	/* First, send out two SYNC characters. */
	syncbuf[0] = syncbuf[1] = (char)SYNC_CHAR;
	rmc_comm_serdev_send(rcs, syncbuf, 2);

	/* Next, send the BP message. */
	rmc_comm_serdev_send(rcs, (char *)&bp_msg->cmd,
	    sizeof (bp_msg_t) - sizeof (bp_msg->pad));
}

/*
 * to send a fw s-record
 * (this is to support the firmware download feature)
 */
void
rmc_comm_bp_srecsend(struct rmc_comm_state *rcs, char *buf, int buflen)
{
	ASSERT(MUTEX_HELD(rcs->dp_state.dp_mutex));

	rcs->dp_state.req_resp.flags |= MSG_SENT_BP;

	rmc_comm_serdev_send(rcs, buf, buflen);
}

/*
 * clean up a request/response session
 * (it must have the dp_mutex)
 */

void
rmc_comm_dp_mcleanup(struct rmc_comm_state *rcs)
{
	rmc_comm_dp_state_t *dps = &rcs->dp_state;
	dp_req_resp_t *drr = &dps->req_resp;
	dp_message_t *req = &drr->request;
	dp_message_t *resp = &drr->response;

	ASSERT(MUTEX_HELD(dps->dp_mutex));

	DPRINTF(rcs, DGEN, (CE_CONT, "msg cleanup\n"));

	/*
	 * 'release' memory
	 * memory is only 'dynamically allocated for NUMBERED messages
	 */
	if (req->msg_buf != NULL)
		dp_release_buffer(rcs, DP_TX_BUFFER);

	drr->flags = 0;
	drr->error_status = 0;

	req->msg_type = DP_NULL_MSG;
	req->msg_buf = NULL;
	req->msg_msglen = 0;
	req->msg_bufsiz = 0;
	resp->msg_type = DP_NULL_MSG;
	resp->msg_buf = NULL;
	resp->msg_msglen = 0;
	resp->msg_bufsiz = 0;
}
