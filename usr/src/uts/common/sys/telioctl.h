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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_TELIOCTL_H
#define	_SYS_TELIOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Ioctl's to control telnet protocol module
 * (See also, logindmux.h LOGDMX_IOC_QEXCHANGE)
 *
 * TEL_IOC_ENABLE: Allow processing, and forward normal data messages.  This
 * resumes processing after telmod receives a protocol sequence which it does
 * not process itself.  If data is attached to this ioctl, telmod inserts it
 * at the head of the read queue.
 *
 * TEL_IOC_MODE: Establish the mode for data processing.  Currently binary
 * input and output are the only modes supported.
 *
 * TEL_IOC_GETBLK: When telmod is not enabled, this ioctl requests that
 * the next input message from the network to be processed is forwarded
 * through the mux to the daemon.
 */
#define	TELIOC			('n' << 8)
#define	TEL_IOC_ENABLE		(TELIOC|2)
#define	TEL_IOC_MODE		(TELIOC|3)
#define	TEL_IOC_GETBLK		(TELIOC|4)

/*
 * Bits for indicating binary input (from the net) and output (to the net).
 */
#define	TEL_BINARY_IN	1
#define	TEL_BINARY_OUT	2

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TELIOCTL_H */
