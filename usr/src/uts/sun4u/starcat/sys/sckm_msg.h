/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

#ifndef	_SYS_SCKM_MSG_H
#define	_SYS_SCKM_MSG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This header file describes the format of the IOSRAM mailbox messages
 * exchanged between the sckmr driver on a Starcat Domain and the
 * Starcat System Controller.
 */

#include <sys/types.h>

/*
 * MBOXSC_MSG_EVENT or MBOXSC_MSG_REQUEST message header.
 */
typedef struct sckm_mbox_req_hdr {
	uint32_t sckm_version;		/* protocol version */
	uint32_t reserved;
} sckm_mbox_req_hdr_t;

/*
 * MBOXSC_MSG_REPLY message header
 */
typedef struct sckm_mbox_rep_hdr {
	uint32_t sckm_version;		/* protocol version */
	uint32_t status;		/* error code */
	uint32_t sadb_msg_errno;	/* PF_KEY errno, if applicable */
	uint32_t sadb_msg_version;	/* PF_KEY version, if applicable */
} sckm_mbox_rep_hdr_t;

/*
 * Version of this current protocol.
 */
#define	SCKM_PROTOCOL_VERSION	1

/*
 * Keys for SC to Domain and Domain to SC mailboxes
 */
#define	KEY_SCKD	0x53434b44	/* SC to Domain mailbox */
#define	KEY_KDSC	0x4b445343	/* Domain to SC mailbox */

/*
 * Max data size, in bytes, for IOSRAM mailboxes
 */
#define	SCKM_SCKD_MAXDATA	1024
#define	SCKM_KDSC_MAXDATA	1024

/*
 * Message types.
 */
#define	SCKM_MSG_SADB		0x1	/* SADB message		SC<->D */

/*
 * Values for sckm_msg_rep_hdr status field.
 */
#define	SCKM_SUCCESS		0x0	/* Operation succeeded */
#define	SCKM_ERR_VERSION	0x1	/* Unexpected version */
#define	SCKM_ERR_SADB_PFKEY	0x2	/* PF_KEY returned an error */
#define	SCKM_ERR_SADB_MSG	0x3	/* bad SADB msg detect by driver */
#define	SCKM_ERR_DAEMON		0x4	/* Error communicating with daemon */
#define	SCKM_ERR_BAD_CMD	0x5	/* unknown command */
#define	SCKM_ERR_SADB_VERSION	0x6	/* bad SADB version */
#define	SCKM_ERR_SADB_TIMEOUT	0x7	/* no response from key engine */
#define	SCKM_ERR_SADB_BAD_TYPE	0x8	/* bad SADB msg type */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SCKM_MSG_H */
