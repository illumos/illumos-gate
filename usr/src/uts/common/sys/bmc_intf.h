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
 */

#ifndef _BMC_INTF_H
#define	_BMC_INTF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	BMC_SUCCESS		0x0
#define	BMC_FAILURE		0x1

#define	BMC_NETFN_CHASSIS		0x0
#define	BMC_NETFN_BRIDGE		0x2
#define	BMC_NETFN_SE			0x4
#define	BMC_NETFN_APP			0x6
#define	BMC_NETFN_FIRMWARE		0x8
#define	BMC_NETFN_STORAGE		0xa
#define	BMC_NETFN_TRANSPORT		0xc

#define	SEND_MAX_PAYLOAD_SIZE		34	/* MAX payload */
#define	RECV_MAX_PAYLOAD_SIZE		33	/* MAX payload */
#define	BMC_MIN_RESPONSE_SIZE		3
#define	BMC_MIN_REQUEST_SIZE		2
#define	BMC_MAX_RESPONSE_SIZE   (BMC_MIN_RESPONSE_SIZE + RECV_MAX_PAYLOAD_SIZE)
#define	BMC_MAX_REQUEST_SIZE	(BMC_MIN_REQUEST_SIZE + BMC_MAX_RESPONSE_SIZE)

#define	BUF_SIZE 256
#define	MAX_BUF_SIZE			256

/*
 * Useful macros
 */
#define	FORM_NETFNLUN(net, lun)	((((net) << 2) | ((lun) & 0x3)))
#define	GET_NETFN(netfn)	(((netfn) >> 2) & 0x3f)
#define	GET_LUN(netfn)		(netfn & 0x3)
#define	RESP_NETFN(nflun)	((nflun) | 1)
#define	ISREQUEST(nl)		(((nl) & 1) == 0)	/* test for request */
#define	ISRESPONSE(nl)		(((nl) & 1) == 1)	/* test for response */


/* for checking BMC specific stuff */
#define	BMC_GET_DEVICE_ID		0x1	/* GET DEVICE ID COMMAND */
#define	BMC_IPMI_15_VER		0x51	/* IPMI 1.5 definion */

/* BMC Completion Code and OEM Completion Code */
#define	BMC_IPMI_UNSPECIFIC_ERROR	0xFF	/* Unspecific Error */
#define	BMC_IPMI_INVALID_COMMAND	0xC1	/* Invalid Command */
#define	BMC_IPMI_COMMAND_TIMEOUT	0xC3	/* Command Timeout */
#define	BMC_IPMI_DATA_LENGTH_EXCEED	0xC8	/* DataLength exceeded limit */
#define	BMC_IPMI_OEM_FAILURE_SENDBMC	0x7E	/* Cannot send BMC req */


#define	IOCTL_IPMI_KCS_ACTION		0x01
#define	IOCTL_IPMI_INTERFACE_METHOD	0x02

/* Interface methods returned from IOCTL_IPMI_INTERFACE_METHOD ioctl: */

#define	BMC_IOCTL_METHOD		0	/* Not returned from ioctl, */
						/* but can be used by	*/
						/* applications that want to */
						/* compare against an	*/
						/* alternative method.	*/
#define	BMC_PUTMSG_METHOD		1

/*
 * bmc_req_t is the data structure to send
 * request packet from applications to the driver
 * module.
 *
 * the request pkt is mainly for KCS-interface-BMC
 * messages. Since the system interface is session-less
 * connections, the packet won't have any session
 * information.
 *
 * the data payload will be 2 bytes less than max
 * BMC supported packet size.
 * the address of the responder is always BMC and so
 * rsSa field is not required.
 */
typedef struct bmc_req {
	uint8_t fn;			/* netFn for command */
	uint8_t lun;			/* logical unit on responder */
	uint8_t cmd;			/* command */
	uint8_t datalength;		/* length of following data */
	uint8_t data[SEND_MAX_PAYLOAD_SIZE]; /* request data */
} bmc_req_t;

/*
 * bmc_rsp_t is the data structure to send
 * respond packet from applications to the driver
 * module.
 *
 * the respond pkt is mainly for KCS-interface-BMC
 * messages. Since the system interface is session-less
 * connections, the packet won't have any session
 * information.
 *
 * the data payload will be 2 bytes less than max
 * BMC supported packet size.
 */
typedef struct bmc_rsp {
	uint8_t	fn;			/* netFn for command */
	uint8_t	lun;			/* logical unit on responder */
	uint8_t	cmd;			/* command */
	uint8_t	ccode;			/* completion code */
	uint8_t	datalength;		/* Length */
	uint8_t	data[RECV_MAX_PAYLOAD_SIZE]; /* response */
} bmc_rsp_t;

/*
 * the data structure for synchronous operation via ioctl (DEPRECATED)
 */
typedef struct bmc_reqrsp {
	bmc_req_t	req;			/* request half */
	bmc_rsp_t	rsp;			/* response half */
} bmc_reqrsp_t;


/*
 * The new way of communicating with the bmc driver is to use putmsg() to
 * send a message of a particular type.  Replies from the driver also have this
 * form, and will require the user to process the type field before examining
 * the rest of the reply.
 *
 * The only change that must be observed when using the request and response
 * structures defined above is as follows:
 * when sending messages to the bmc driver, the data portion is now variable
 * (the caller must allocate enough space to store the all structure members,
 * plus enough space to cover the amount of data in the request), e.g.:
 *
 * bmc_msg_t *msg = malloc(offsetof(bmc_msg_t, msg) + sizeof(bmc_req_t) + 10);
 *
 * The amount allocated for the message is (# of bytes before the msg field) +
 * the size of a bmc_req_t (which includes SEND_MAX_PAYLOAD_SIZE
 * bytes in the data field), plus an additional 10 bytes for the data
 * field (so the data field would occupy (SEND_MAX_PAYLOAD_SIZE + 10)
 * bytes).  The datalength member must reflect the amount of data in the
 * request's data field (as was required when using the ioctl interface).
 */
typedef struct bmc_msg {
	uint8_t		m_type;		/* Message type (see below) */
	uint32_t	m_id;		/* Message ID */
	uint8_t		reserved[32];
	uint8_t		msg[1];		/* Variable length message data */
} bmc_msg_t;


/*
 * An error response passed back from the bmc driver will have its m_id
 * field set to BMC_UNKNOWN_MSG_ID if a message is sent to it that is not
 * at least as large as a bmc_msg_t.
 */
#define	BMC_UNKNOWN_MSG_ID	~((uint32_t)0)


/*
 * Possible values for the m_type field in bmc_msg_t:
 */
#define	BMC_MSG_REQUEST		1	/* BMC request (as above, sent to the */
					/* driver by the user), bmc_msg.msg */
					/* begins with the bmc_req_t	*/
					/* structure.			*/
#define	BMC_MSG_RESPONSE	2	/* BMC response (sent by the driver) */
					/* bmc_msg.msg begins with the	*/
					/* bmc_rsp_t structure.		*/
#define	BMC_MSG_ERROR		3	/* Error while processing a user msg */
					/* msg[0] is the error code	*/
					/* (interpret as an errno value) */

#ifdef	__cplusplus
}
#endif

#endif /* _BMC_INTF_H */
