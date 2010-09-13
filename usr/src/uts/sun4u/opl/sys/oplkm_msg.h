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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_OPLKM_MSG_H
#define	_SYS_OPLKM_MSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This header file describes the format of the mailbox messages
 * exchanged between the OPL key management driver on a OPL Domain
 * and the OPL Service Processor.
 */


/*
 * Request message header.
 */
typedef struct okm_req_hdr {
	uint32_t krq_version;		/* Protocol version */
	uint32_t krq_transid;		/* Transaction ID */
	uint32_t krq_cmd;		/* Request */
	uint32_t krq_reserved;		/* Reserved */
} okm_req_hdr_t;

/*
 * Reply message header.
 */
typedef struct okm_rep_hdr {
	uint32_t krp_version;		/* protocol version */
	uint32_t krp_transid;		/* Transaction ID */
	uint32_t krp_status;		/* Status */
	uint32_t krp_sadb_errno;	/* PF_KEY errno, if applicable */
	uint32_t krp_sadb_version;	/* PF_KEY version, if applicable */
} okm_rep_hdr_t;

/*
 * Version of this current protocol.
 */
#define	OKM_PROTOCOL_VERSION	1


/*
 * Message types.
 */
#define	OKM_MSG_SADB		0x1	/* SADB message from SP */

/*
 * Values for sckm_msg_rep_hdr status field.
 */
#define	OKM_SUCCESS		0x0	/* Operation succeeded */
#define	OKM_ERR_VERSION		0x1	/* Unexpected version */
#define	OKM_ERR_SADB_PFKEY	0x2	/* PF_KEY returned an error */
#define	OKM_ERR_SADB_MSG	0x3	/* bad SADB msg detect by driver */
#define	OKM_ERR_DAEMON		0x4	/* Error communicating with daemon */
#define	OKM_ERR_BAD_CMD		0x5	/* unknown command */
#define	OKM_ERR_SADB_VERSION	0x6	/* bad SADB version */
#define	OKM_ERR_SADB_TIMEOUT	0x7	/* no response from key engine */
#define	OKM_ERR_SADB_BAD_TYPE	0x8	/* bad SADB msg type */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_OPLKM_MSG_H */
