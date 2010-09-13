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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_RMC_COMM_DRVINTF_H
#define	_SYS_RMC_COMM_DRVINTF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/rmc_comm_hproto.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * this struct is used by client programs to request message services:
 */
typedef struct rmc_comm_msg {

	uint8_t	msg_type;	/* message type */
	int16_t	msg_len;	/* size of the message buffer */
	int16_t	msg_bytes;	/* number of bytes returned */
	caddr_t	msg_buf;	/* message buffer */

} rmc_comm_msg_t;


/* list of error codes for RMC comm */

#define	RCNOERR		(0)	/* cmd sent, reply/ACK received */
#define	RCENOSOFTSTATE	(-1)	/* invalid/NULL soft state structure */
#define	RCENODATALINK	(-2)	/* data link down */
#define	RCENOMEM	(-3)	/* no memory */
#define	RCECANTRESEND	(-4)	/* resend failed */
#define	RCEMAXRETRIES	(-5)	/* maximum number of retries exceeded */
#define	RCETIMEOUT	(-6)	/* timeout error */
#define	RCEINVCMD	(-7)	/* invalid data protocol command */
#define	RCEINVARG	(-8)	/* invalid argument(s) */
#define	RCECANTREGINTR	(-9)	/* interrupt handler registration failure */
#define	RCEALREADYREG	(-10)	/* interrupt handler already registered */
#define	RCEREPTOOBIG	(-11)	/* reply message too big */
#define	RCEGENERIC	(-15)	/* generic error */

/*
 * possible value for the 'state' variable provided by the driver
 * (registration for an asynchronous message notification -
 * see rmc_comm_reg_intr). The state variable tells whether the driver
 * interrupt handler is currently processing an asynchronous notification or
 * not.
 */

#define	RMC_COMM_INTR_IDLE	0x01
#define	RMC_COMM_INTR_RUNNING	0x02


/*
 * structure used to store a request (only one per time!) that is delivered
 * later. Some leaf driver (TOD for instance) cannot wait for the completion
 * of the trasmission of a request message so they calls a specific interface
 * (rmc_comm_request_nowait) which stores the request in this structure and
 * signals a thread to deliver the request asynchronously.
 */
typedef struct rmc_comm_drvintf_state {

	kt_did_t	dreq_tid;
	kmutex_t	dreq_mutex[1];
	kcondvar_t	dreq_sig_cv[1];
	uint8_t		dreq_state;
	rmc_comm_msg_t	dreq_request;
	char		dreq_request_buf[ DP_MAX_MSGLEN ];

} rmc_comm_drvintf_state_t;

/*
 * possible value for dreq_state field
 */
enum rmc_comm_dreq_state {
	RMC_COMM_DREQ_ST_NOTSTARTED = 0,
	RMC_COMM_DREQ_ST_READY,
	RMC_COMM_DREQ_ST_WAIT,
	RMC_COMM_DREQ_ST_PROCESS,
	RMC_COMM_DREQ_ST_EXIT
};

/*
 * default timeout value for requests sent from the thread
 */
#define	RMC_COMM_DREQ_DEFAULT_TIME	10000

/*
 * flag which tells if a request has to be sent even if a pending request is
 * in process. This flag must only be used when trying to send a request in
 * critical condition (while the system is shutting down for instance and the
 * CPU signature has to be sent). Otherwise, the request is stored in a
 * temporary location and delivered by a thread.
 */

#define	RMC_COMM_DREQ_URGENT		0x01


/* function prototypes (interface to the drivers) */

int rmc_comm_request_response(rmc_comm_msg_t *, rmc_comm_msg_t *, uint32_t);
int rmc_comm_request_nowait(rmc_comm_msg_t *, uint8_t);
int rmc_comm_request_response_bp(rmc_comm_msg_t *, rmc_comm_msg_t *, uint32_t);
int rmc_comm_reg_intr(uint8_t, rmc_comm_intrfunc_t, rmc_comm_msg_t *, uint_t *,
			kmutex_t *);
int rmc_comm_unreg_intr(uint8_t, rmc_comm_intrfunc_t);
int rmc_comm_send_srecord_bp(caddr_t, int, rmc_comm_msg_t *, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RMC_COMM_DRVINTF_H */
