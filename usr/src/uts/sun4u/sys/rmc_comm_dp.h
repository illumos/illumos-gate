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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_RMC_COMM_DP_H
#define	_SYS_RMC_COMM_DP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/rmc_comm_lproto.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * buffer size (used for tx/rx operations)
 */
#define	DP_BUFFER_SIZE	2048

/*
 * Number of tx/rx buffers. there are 2 (static) buffers: receive buffer and
 * send buffer. These buffers are basically used by the protocol to packetize
 * a message to be sent OR to collect data received from the serial device.
 * Currently, we just need two for send and receive operations respectively
 * since there is only one request/response session per time (i.e. a new
 * session is not started until the previous one has not finished)
 */
#define	DP_BUFFER_COUNT		2

#define	DP_TX_BUFFER		0
#define	DP_RX_BUFFER		1

/*
 * Tx/Rx buffers.
 */
typedef struct dp_buffer {
	boolean_t in_use;
	uint8_t buf[DP_BUFFER_SIZE];
} dp_buffer_t;

/*
 * Data structure used to collect data from the serial device and to
 * assemble protocol packets
 */

/*
 * The possible states the message receiver can be in:
 */
#define	WAITING_FOR_SYNC	0
#define	WAITING_FOR_SYNC_ESC	1
#define	WAITING_FOR_HDR		2
#define	RECEIVING_HDR		3
#define	RECEIVING_HDR_ESC	4
#define	RECEIVING_BODY		5
#define	RECEIVING_BODY_ESC	6
#define	N_RX_STATES		7

/*
 * This is the structure passed between the message receiver state routines.
 * It keeps track of all the state of a message that is in the process of
 * being received.
 */
typedef struct dp_packet {
	uint8_t rx_state;	/* Current state of receive engine. */
	uint8_t *inbuf;		/* Input characters to be processed. */
	int16_t inbuflen;	/* Number of input characters. */
	uint8_t *buf;		/* Buffer used to receive current message. */
	int16_t bufpos;		/* Position in buffer. */
	int16_t full_length;	/* Full length of this message. */
} dp_packet_t;


/*
 * message data structure used to send/receive data
 */
typedef struct dp_message {

	uint8_t   msg_type;	/* message type */
	uint8_t  *msg_buf;	/* message buffer */
	uint16_t  msg_bufsiz;	/* size of the buffer */
	int16_t   msg_msglen;	/* message length */

} dp_message_t;

/*
 * structure used by the protocol to send (and, eventually re-send...)
 * messages to the remote side. It keeps the status of the data transfer
 * (message sent, reply received, etc.). It is also used to match
 * request/response
 */

typedef struct dp_req_resp {

	uint8_t		flags;		/* status of the data transfer */

#define	MSG_ERROR 	0x01
#define	MSG_SENT 	0x02
#define	MSG_ACKED 	0x04
#define	MSG_REPLY_RXED	0x08
#define	MSG_NAKED	0x10
#define	MSG_RESET	0x20
#define	MSG_SENT_BP	0x40
#define	MSG_RXED_BP	0x80

	int		error_status;   /* error code */

	uint8_t		retries_left;   /* number of retries left */

	kcondvar_t  	cv_wait_reply[1];	/* cv variable used to signal */
						/* threads waiting for a */
						/* reply */

	dp_message_t	request;	/* request buffer */

	dp_message_t	response;	/* response buffer */

} dp_req_resp_t;


/*
 * interrupt handler prototype (asynchronous messages notification)
 */
typedef uint_t (*rmc_comm_intrfunc_t)(caddr_t);

/*
 * data structure used to deal with asynchronous notification (requests)
 * from the remote side
 */
typedef struct dp_msg_intr {

	rmc_comm_intrfunc_t	intr_handler;	/* interrupt handler */

	ddi_softintr_t		intr_id;	/* soft intr. id */

	uint8_t			intr_msg_type;	/* message type */

	caddr_t			intr_arg;	/* message buffer containing */
						/* the expected message type */

	kmutex_t		*intr_lock;	/* for state flag below */
	uint_t			*intr_state;	/* interrupt handler state */

} dp_msg_intr_t;

/*
 * data protocol structure
 */

typedef struct rmc_comm_dp_state {

	/*
	 * data protcol mutex (initialized using <dp_iblk>)
	 */
	kmutex_t		dp_mutex[1];
	ddi_iblock_cookie_t	dp_iblk;

	boolean_t	data_link_ok;	/* tells whether the data link has */
					/* has been established */

	boolean_t	pending_request;	/* tells if a request is */
						/* already being processed */

	uint8_t		last_tx_seqid;	/* sequence ID of last message */
					/* transmitted */
	uint8_t		last_rx_seqid;  /* sequence ID of last message */
					/* received */
	uint8_t		last_rx_ack;    /* last message acknowledged by */
					/* remote side */

	timeout_id_t	timer_link_setup;	/* timer used to set up the */
						/* data link at regular */
						/* intervals when the link is */
						/* down */
	timeout_id_t	timer_delay_ack;	/* timer used to wait a 'bit' */
						/* before acknowledging a */
						/* received message. In the */
						/* meantime a request can be */
						/* sent from this side and, */
						/* hence, acnowledge that */
						/* message */

	kcondvar_t	cv_ok_to_send[1];	/* cv variable used to wait */
						/* until it is possible to */
						/* send the request (no */
						/* pending request */

	dp_packet_t	dp_packet;		/* used to assemble protocol */
						/* packet from data received */
						/* from the serial device */

	dp_req_resp_t	req_resp;		/* request/response data */
						/* structure */

	dp_msg_intr_t	msg_intr;		/* messages for which layered */
						/* drivers have registered */
						/* for an async notification */
						/* (soft.intr.) */

	dp_buffer_t	dp_buffers[DP_BUFFER_COUNT]; /* protocol buffer  */
						/* pool used for    */
						/* tx/rx operations */

	/* statistical information */

	uint16_t	reset_cnt;
	uint16_t	nak_cnt;
	uint16_t	start_cnt;
	uint16_t	stack_cnt;
	uint16_t	retries_cnt;
	uint16_t	crcerr_cnt;

} rmc_comm_dp_state_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RMC_COMM_DP_H */
