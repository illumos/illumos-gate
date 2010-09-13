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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _XCALWD_H
#define	_XCALWD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Excalibur fan control failsafe timer
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Private ioctls for PICL environment plug-in to enable the watchdog
 */
#define	XCALWD_IOCTL	(('X' << 16) | ('W' << 8))
#define	XCALWD_STARTWATCHDOG	(XCALWD_IOCTL | 1)
#define	XCALWD_STOPWATCHDOG	(XCALWD_IOCTL | 2)
#define	XCALWD_KEEPALIVE	(XCALWD_IOCTL | 3)
#define	XCALWD_GETSTATE		(XCALWD_IOCTL | 4)

#ifdef __cplusplus
}
#endif

#endif /* _XCALWD_H */
