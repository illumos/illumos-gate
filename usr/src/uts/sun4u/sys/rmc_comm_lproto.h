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

#ifndef	_SYS_RMC_COMM_LPROTO_H
#define	_SYS_RMC_COMM_LPROTO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	SYNC_CHAR	0x80
#define	ESC_CHAR	0x81

/* Maximum message length */

#define	DP_MAX_MSGLEN	1024

/*
 * Tunables.
 */

/* Number of times a transmitted message will be retried. */
#define	TX_RETRIES	10

/* Amount of time between transmit retries in ms, currently 500ms. */
#define	TX_RETRY_TIME	500L

/* minimum waiting time for a reply (milliseconds) */
#define	DP_MIN_TIMEOUT	200L

/*
 * timeout (in ms) for (re)trying to establish the protocol data link
 */
#define	DELAY_DP_SETUP		10
#define	RETRY_DP_SETUP		5000

/*
 * Data protocol message structure.  Note that this is the in-memory
 * version; when a data protocol message is transmitted it goes
 * through a translation to assist the receiving side in determining
 * message boundaries robustly.
 */
typedef struct dp_header {

	uint8_t  pad;		/* This pad byte is never transmitted nor */
				/* received, it is solely to make the */
				/* structure elements line up in memory. */
	uint8_t  type;		/* The message type-see below for valid types */
	uint16_t length;	/* Length of the whole message. */
	uint8_t  txnum;		/* Sequence number of this message. */
	uint8_t  rxnum;		/* Highest sequence number received. */
				/* (AKA piggy-backed acknowledgement). */
	uint16_t crc;		/* CRC-16 Checksum of header. */

} dp_header_t;

/*
 * Macros for dealing with sequence id's.
 */

/* Given a sequence id, calculate the next one. */
#define	NEXT_SEQID(a)		(((a) + 1) % 0x100)

/* Given a sequence id, calculate the previous one. */
#define	PREV_SEQID(a)		(((a) == 0) ? 0xff : (a)-1)

/* Do these sequence ID's follow each other? */
#define	IS_NEXT_SEQID(a, b)	((b) == NEXT_SEQID(a))

/* What to initialize sequence ID counters to. */
#define	INITIAL_SEQID		0xFF

/*
 * Macros for interpreting message types.
 */
#define	IS_NUMBERED_MSG(t)	(((t) & 0x80) == 0x00)
#define	IS_UNNUMBERED_MSG(t)	(((t) & 0xC0) == 0x80)
#define	IS_BOOT_MSG(t)		(((t) & 0xE0) == 0xC0)

/*
 * Un-numbered messages.
 */

#define	DP_CTL_START		0x88

#define	DP_CTL_STACK		0x89

#define	DP_CTL_RESPOND		0x8A

#define	DP_CTL_ACK		0x8B

#define	DP_CTL_NAK		0x8C

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RMC_COMM_LPROTO_H */
