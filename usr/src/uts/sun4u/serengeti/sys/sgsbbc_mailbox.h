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

#ifndef	_SYS_SGSBBC_MAILBOX_H
#define	_SYS_SGSBBC_MAILBOX_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sgsbbc.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Message types - one per client!
 */
#define	SBBC_BROADCAST_MSG		0x0
#define	OBP_MBOX			0x1
#define	DR_MBOX				0x2
#define	WILDCAT_RSM_MBOX		0x3
#define	SG_ENV				0x4	/* environmental data */
#define	CPCI_MBOX			0x5
#define	INFO_MBOX			0x6	/* for passing info to the SC */
#define	SGFRU_MBOX			0x7	/* FRUID messages */
#define	MBOX_EVENT_GENERIC		0x8
#define	MBOX_EVENT_KEY_SWITCH		0x9
#define	MBOX_EVENT_PANIC_SHUTDOWN	0xb
#define	MBOX_EVENT_ENV			0xc
#define	MBOX_EVENT_CPCI_ENUM		0xd
#define	LW8_MBOX			0xe
#define	MBOX_EVENT_LW8			0xf
#define	MBOX_EVENT_DP_ERROR		0x10	/* datapath error */
#define	MBOX_EVENT_DP_FAULT		0x11	/* datapath fault */

#ifdef	DEBUG
#define	DBG_MBOX		0x1f	/* debug messages */
#endif	/* DEBUG */

/*
 * INFO_MBOX message sub-types
 */
#define	INFO_MBOX_NODENAME	0x6000	/* for passing nodename to SC */
#define	INFO_MBOX_ERROR_NOTICE	0x6001	/* for logging ECC errors to SC */
#define	INFO_MBOX_ERROR_ECC	0x6003	/* updated interface for logging */
					/* ECC errors to SC */
#define	INFO_MBOX_ERROR_INDICT	0x6004	/* for logging ECC indictments to SC */
#define	INFO_MBOX_ECC		0x6005	/* new interface for logging */
#define	INFO_MBOX_ECC_CAP	0x6006	/* capability message */

/*
 * Message status values returned by the SC to the various mailbox clients.
 *
 * These values need to be kept in sync with MailboxProtocol.java
 * in the SCAPP source code.
 */
#define	SG_MBOX_STATUS_SUCCESS				0
#define	SG_MBOX_STATUS_COMMAND_FAILURE			(-1)
#define	SG_MBOX_STATUS_HARDWARE_FAILURE			(-2)
#define	SG_MBOX_STATUS_ILLEGAL_PARAMETER		(-3)
#define	SG_MBOX_STATUS_BOARD_ACCESS_DENIED		(-4)
#define	SG_MBOX_STATUS_STALE_CONTENTS			(-5)
#define	SG_MBOX_STATUS_STALE_OBJECT			(-6)
#define	SG_MBOX_STATUS_NO_SEPROM_SPACE			(-7)
#define	SG_MBOX_STATUS_NO_MEMORY			(-8)
#define	SG_MBOX_STATUS_NOT_SUPPORTED			(-9)
#define	SG_MBOX_STATUS_ILLEGAL_NODE			(-10)
#define	SG_MBOX_STATUS_ILLEGAL_SLOT			(-11)


/*
 * Time out values in seconds.
 *
 * These definitions should not be used directly except by the
 * sbbc_mbox_xxx_timeout variables. All clients should then use
 * these variables to allow running kernels to modify wait times.
 */
#define	MBOX_MIN_TIMEOUT	1	/* min time to wait before timeout */
#define	MBOX_DEFAULT_TIMEOUT	30	/* suggested wait time */

/*
 * Timeout variables
 */
extern int	sbbc_mbox_min_timeout;		/* minimum wait time */
extern int	sbbc_mbox_default_timeout;	/* suggested wait time */


/*
 * Message type consists of two parts
 * type - client ID
 * sub_type - client defined message type
 */
typedef struct {
	uint16_t	sub_type;
	uint16_t	type;
} sbbc_msg_type_t;

/*
 * this struct is used by client programs to request
 * mailbox message services
 */
typedef struct sbbc_msg {
	sbbc_msg_type_t	msg_type;	/* message type */
	int	msg_status;		/* message return value */
	int	msg_len;		/* size of message buffer */
	int	msg_bytes;		/* number of bytes returned */
	caddr_t	msg_buf;		/* message buffer */
	int32_t	msg_data[2];		/* for junk mail */
} sbbc_msg_t;

/*
 * This data structure is used for queueing up ECC event mailbox
 * messages through the SBBC taskq.
 */

typedef struct sbbc_ecc_mbox {
	sbbc_msg_t	ecc_req;	/* request */
	sbbc_msg_t	ecc_resp;	/* response */
	int		ecc_log_error;	/* Log errors to /var/adm/messages */
} sbbc_ecc_mbox_t;

/*
 * ECC event mailbox taskq parameters
 */
#define	ECC_MBOX_TASKQ_MIN	2	/* minimum number of jobs */
#define	ECC_MBOX_TASKQ_MAX	512	/* maximum number of jobs */

/*
 * These are used to throttle error messages that may appear if
 * the attempt to enqueue an ECC event message to the SC fails.
 * If set to N > 0, then only every Nth message will be output.
 * Set to 0 or 1 to disable this throttling and allow all error
 * messages to appear.
 *
 * ECC_MBOX_TASKQ_ERR_THROTTLE is the default value for
 * sbbc_ecc_mbox_err_throttle, which may be overridden in
 * /etc/system or at run time via debugger.
 */
#define	ECC_MBOX_TASKQ_ERR_THROTTLE	64
extern int	sbbc_ecc_mbox_err_throttle;

extern int	sbbc_mbox_reg_intr(uint32_t, sbbc_intrfunc_t,
		sbbc_msg_t *, uint_t *, kmutex_t *);
extern int	sbbc_mbox_unreg_intr(uint32_t, sbbc_intrfunc_t);
extern int	sbbc_mbox_request_response(sbbc_msg_t *,
		sbbc_msg_t *, time_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SGSBBC_MAILBOX_H */
