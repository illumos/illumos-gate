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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MBOXSC_IMPL_H
#define	_MBOXSC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains implementation details for the mboxsc API that need to
 * be shared amongst all implementations, but should be hidden from clients.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Version number of the current Mailbox Protocol implementation.  This must
 * be updated whenever a new version of the Protocol is implemented.
 */
#define	MBOXSC_PROTOCOL_VERSION	1

/*
 * Mailbox message header and checksum.
 */
typedef struct {
	uint32_t	msg_version;
	uint32_t	msg_type;
	uint32_t	msg_cmd;
	uint32_t	msg_length;
	uint64_t	msg_transid;
} mboxsc_msghdr_t;

typedef uint32_t	mboxsc_chksum_t;

/*
 * Constants for various aspects of the protocol.
 */
#define	MBOXSC_MSGHDR_SIZE	(sizeof (mboxsc_msghdr_t))
#define	MBOXSC_CHKSUM_SIZE	(sizeof (mboxsc_chksum_t))
#define	MBOXSC_PROTOCOL_SIZE	(MBOXSC_MSGHDR_SIZE + MBOXSC_CHKSUM_SIZE)
#define	MBOXSC_MSGHDR_OFFSET	(0)
#define	MBOXSC_DATA_OFFSET	MBOXSC_MSGHDR_SIZE

/*
 * Timeouts used for various mboxsc operations.  All timeouts are provided
 * in microseconds.
 * XXX - Aside from the conversion factors, these values are currently
 *       somewhat arbitrary, and may need significant modification.
 */
#define	MBOXSC_USECS_PER_SECOND		(1000000L)
#define	MBOXSC_USECS_PER_MSEC		(1000L)

/*
 * The amount of time to sleep before retrying an IOSRAM operation that failed
 * because a tunnel switch was in progress.
 * Current value: 0.125 seconds
 */
#define	MBOXSC_EAGAIN_POLL_USECS	(MBOXSC_USECS_PER_SECOND / 8)

/*
 * The interval at which the data_valid flag should be polled for a change in
 * status after sending a message.
 * Current value: 0.010 seconds
 */
#define	MBOXSC_PUTMSG_POLL_USECS	(MBOXSC_USECS_PER_SECOND / 100)

/*
 * The polling rates for acquisition of the hardware lock used to synchronize
 * data_valid flag access.
 * Current values: 0.025 seconds
 */
#define	MBOXSC_HWLOCK_POLL_USECS 	(MBOXSC_USECS_PER_SECOND / 40)

/*
 * Minimum, default, and maximum times for mboxsc_putmsg to spend trying to send
 * a message before giving up.
 * Current value: 0.050, 10, and 1800 seconds, respectively
 *                1800 seconds (30 minutes) is a few minutes shy of the maximum
 *                value of a clock_t in units of microseconds.
 */
#define	MBOXSC_PUTMSG_MIN_TIMEOUT_USECS	(MBOXSC_USECS_PER_SECOND / 20)
#define	MBOXSC_PUTMSG_DEF_TIMEOUT_USECS	(MBOXSC_USECS_PER_SECOND * 10)
#define	MBOXSC_PUTMSG_MAX_TIMEOUT_USECS	(MBOXSC_USECS_PER_SECOND * 60 * 30)

#define	MBOXSC_PUTMSG_MIN_TIMEOUT_MSECS \
	(MBOXSC_PUTMSG_MIN_TIMEOUT_USECS / MBOXSC_USECS_PER_MSEC)
#define	MBOXSC_PUTMSG_DEF_TIMEOUT_MSECS \
	(MBOXSC_PUTMSG_DEF_TIMEOUT_USECS / MBOXSC_USECS_PER_MSEC)
#define	MBOXSC_PUTMSG_MAX_TIMEOUT_MSECS \
	(MBOXSC_PUTMSG_MAX_TIMEOUT_USECS / MBOXSC_USECS_PER_MSEC)

/*
 * Minimum and maximum times for mboxsc_getmsg to spend trying to receive a
 * message before giving up.
 * Current value: 0 and 1800 seconds, respectively
 *                1800 seconds (30 minutes) is a few minutes shy of the maximum
 *                value of a clock_t in units of microseconds.
 */
#define	MBOXSC_GETMSG_MIN_TIMEOUT_USECS (MBOXSC_USECS_PER_SECOND * 0)
#define	MBOXSC_GETMSG_MAX_TIMEOUT_USECS (MBOXSC_USECS_PER_SECOND * 60 * 30)

#define	MBOXSC_GETMSG_MIN_TIMEOUT_MSECS \
	(MBOXSC_GETMSG_MIN_TIMEOUT_USECS / MBOXSC_USECS_PER_MSEC)
#define	MBOXSC_GETMSG_MAX_TIMEOUT_MSECS \
	(MBOXSC_GETMSG_MAX_TIMEOUT_USECS / MBOXSC_USECS_PER_MSEC)

#ifdef __cplusplus
}
#endif

#endif /* _MBOXSC_IMPL_H */
