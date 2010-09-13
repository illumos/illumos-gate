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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SMC_IF_H
#define	_SYS_SMC_IF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	_SCIOC	('s' << 8)

/*
 * SMC Driver IOCTL
 */
#define	SCIOC_MSG_SPEC		(_SCIOC | 0x04)
#define	SCIOC_RESERVE_SEQN	(_SCIOC | 0x05)
#define	SCIOC_FREE_SEQN		(_SCIOC | 0x06)
#define	SCIOC_SEND_SYNC_CMD	(_SCIOC | 0x07)

/*
 * IOCTLs to facilitate debugging
 */
#define	SCIOC_ECHO_ON_REQ	(_SCIOC | 0x08)
#define	SCIOC_ECHO_OFF_REQ	(_SCIOC | 0x09)

/*
 * A response message can be sent from any application
 * to simulate a condition of watchdog expiry or receiving
 * async messages
 */
#define	SCIOC_ASYNC_SIM		(_SCIOC | 0x0A)

#define	SC_SUCCESS	0
#define	SC_FAILURE	1

/*
 * structure definitions
 */
typedef struct {
	uint8_t	msg_id;
	uint8_t	cmd;
	uint8_t	len;
} sc_reqhdr_t;

typedef struct {
	uint8_t	msg_id;
	uint8_t	cmd;		/* Will be 0 is non-SMC response, e.g. wdog */
	uint8_t	len;		/* Length of message, including header */
	uint8_t	cc;			/* if non-SMC, contains MSG type */
} sc_rsphdr_t;

#define	SC_SEND_HEADER	(sizeof (sc_reqhdr_t))
#define	SC_RECV_HEADER	(sizeof (sc_rsphdr_t))

#define	SC_MSG_MAX_SIZE	0x3E
#define	SC_SEND_DSIZE	(SC_MSG_MAX_SIZE - SC_SEND_HEADER)
#define	SC_RECV_DSIZE	(SC_MSG_MAX_SIZE - SC_RECV_HEADER)

#define	SMC_CMD_FAILED	-1

typedef enum {
	SC_ATTR_SHARED,
	SC_ATTR_EXCLUSIVE,
	SC_ATTR_CLEAR,
	SC_ATTR_CLEARALL
} sc_cmd_attr_t;

#define	MAX_CMDS	16

typedef struct {
	uint8_t attribute;
	uint8_t args[MAX_CMDS];
} sc_cmdspec_t;

#define	SC_CMDSPEC_ATTR(CMDSPEC)	((CMDSPEC).attribute)
#define	SC_CMDSPEC_ARGS(CMDSPEC)	((CMDSPEC).args)

/*
 * Entire SMC Request Message sent down-stream
 */
typedef struct {
	sc_reqhdr_t hdr;
	uchar_t		data[SC_SEND_DSIZE];
} sc_reqmsg_t;

/*
 * Entire SMC Response Message forwarded up-stream
 */
typedef struct {
	sc_rsphdr_t 	hdr;
	uchar_t			data[SC_RECV_DSIZE];
} sc_rspmsg_t;

#define	SC_MSG_HDR(msg)		((msg)->hdr)

#define	SC_SEND_DLENGTH(msg)	(SC_MSG_HDR(msg).len)
#define	SC_RECV_DLENGTH(msg)	(SC_MSG_HDR(msg).len)

#define	SC_MSG_ID(msg)		(SC_MSG_HDR(msg).msg_id)
#define	SC_MSG_CMD(msg)		(SC_MSG_HDR(msg).cmd)
#define	SC_MSG_LEN(msg)		(SC_MSG_HDR(msg).len)
#define	SC_MSG_CC(msg)		(SC_MSG_HDR(msg).cc)
#define	SC_MSG_DATA(msg)	((msg)->data)

/*
 * IPMB sequence number request structure. Application can
 * reserve a block of sequence numbers for communicating
 * with each destination
 */
#define	SC_SEQ_SZ	16
typedef struct {
	uint8_t	d_addr;	/* Destination micro-controller addr */
	int8_t	n_seqn;	/* Number of seq# requested, max 16, -1 => free all */
	uint8_t	seq_numbers[SC_SEQ_SZ];	/* Placeholder for seq# */
} sc_seqdesc_t;

#define	SC_SEQN_DADDR(SEQDESC)		((SEQDESC).d_addr)
#define	SC_SEQN_COUNT(SEQDESC)		((SEQDESC).n_seqn)
#define	SC_SEQN_NUMBERS(SEQDESC)	((SEQDESC).seq_numbers)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SMC_IF_H */
