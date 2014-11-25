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
 * Copyright 2006 Sun Microsystems, Inc.	All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_LX_POLL_H
#define	_SYS_LX_POLL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * These events are identical between Linux and Solaris
 */
#define	LX_POLLIN	0x001
#define	LX_POLLPRI	0x002
#define	LX_POLLOUT	0x004
#define	LX_POLLERR	0x008
#define	LX_POLLHUP	0x010
#define	LX_POLLNVAL	0x020
#define	LX_POLLRDNORM	0x040
#define	LX_POLLRDBAND	0x080

#define	LX_POLL_COMMON_EVENTS (LX_POLLIN | LX_POLLPRI | LX_POLLOUT |	\
	LX_POLLERR | LX_POLLHUP | LX_POLLNVAL | LX_POLLRDNORM | LX_POLLRDBAND)

/*
 * These events differ between Linux and Solaris
 */
#define	LX_POLLWRNORM	0x0100
#define	LX_POLLWRBAND	0x0200
#define	LX_POLLRDHUP	0x2000


#define	LX_POLL_SUPPORTED_EVENTS	\
	(LX_POLL_COMMON_EVENTS | LX_POLLWRNORM | LX_POLLWRBAND | LX_POLLRDHUP)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_POLL_H */
