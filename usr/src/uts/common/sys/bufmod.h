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
 * Copyright (c) 1991, 1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_BUFMOD_H
#define	_SYS_BUFMOD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/types32.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions for the STREAMS Buffering module.
 *
 * The module gathers incoming (read-side) messages together into
 * "chunks" and passes completed chunks up to the next module in
 * line.  The gathering process is controlled by two ioctl-settable
 * parameters:
 *
 * timeout	The maximum delay after passing the previous chunk
 *		upward before passing the current one up, even if the
 *		chunk isn't full.  If the timeout value passed in is
 *		a null pointer, the timeout is infinite (as in the
 *		select system call); this is the default.
 * chunksize	The maximum size of a chunk of accumulated messages,
 *		unless a single message exceeds the chunksize, in
 *		which case it's passed up in a chunk containing only
 *		that message.  Note that a given message's size includes
 *		the length of any leading M_PROTO blocks it may have.
 *
 * There is one important side-effect: setting the timeout to zero
 * (polling) will force the chunksize to zero, regardless of its
 * previous setting.
 */

/*
 * Ioctls.
 */
#define	SBIOC	('B' << 8)
#define	SBIOCSTIME	(SBIOC|1)	/* set timeout info */
#define	SBIOCGTIME	(SBIOC|2)	/* get timeout info */
#define	SBIOCCTIME	(SBIOC|3)	/* clear timeout */
#define	SBIOCSCHUNK	(SBIOC|4)	/* set chunksize */
#define	SBIOCGCHUNK	(SBIOC|5)	/* get chunksize */
#define	SBIOCSSNAP	(SBIOC|6)	/* set snapshot length */
#define	SBIOCGSNAP	(SBIOC|7)	/* get snapshot length */
#define	SBIOCSFLAGS	(SBIOC|8)	/* set buffering modes */
#define	SBIOCGFLAGS	(SBIOC|9)	/* get buffering modes */

/*
 * Default chunk size.
 */
#define	SB_DFLT_CHUNK	8192	/* arbitrary */

/*
 * buffering flags
 */

#define	SB_SEND_ON_WRITE	1	/* return buffered read data on write */
#define	SB_NO_HEADER		2	/* don't add header structure to data */
#define	SB_NO_PROTO_CVT		4	/* don't convert proto to data */
#define	SB_DEFER_CHUNK		8	/* fast response time buffering */
#define	SB_NO_DROPS		16	/* Don't drop messages */

/*
 * buffering state
 */
#define	SB_FRCVD	1	/* first message in time window received */

/*
 * When adding a given message to an accumulating chunk, the module
 * first converts any leading M_PROTO data block to M_DATA.
 * It then constructs an sb_hdr (defined below), prepends it to
 * the message, and pads the result out to force its length to a
 * multiple of a machine-dependent alignment size guaranteed to be
 * at least sizeof (ulong_t).  It then adds the padded message to the
 * chunk.
 *
 * sb_origlen is the original length of the message after the M_PROTO => M_DATA
 * conversion, but before truncating or adding the header.
 *
 * sb_msglen is the length of the message after truncation, but before
 * adding the header.
 *
 * sb_totlen is the length of the message after truncation, and including
 * both the header itself and the trailing padding bytes.
 *
 * sb_drops is the cumulative number of messages dropped by the module
 * due to stream read-side flow control or resource exhaustion.
 *
 * sb_timestamp is the packet arrival time expressed as a 'struct timeval'.
 */

struct sb_hdr {
	uint_t	sbh_origlen;
	uint_t	sbh_msglen;
	uint_t	sbh_totlen;
	uint_t	sbh_drops;
#if defined(_LP64) || defined(_I32LPx)
	struct	timeval32 sbh_timestamp;
#else
	struct	timeval sbh_timestamp;
#endif /* !_LP64 */
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_BUFMOD_H */
