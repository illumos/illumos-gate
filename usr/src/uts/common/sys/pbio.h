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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_PBIO_H
#define	_SYS_PBIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Supported ioctls
 */
#define	PBIOC			('p' << 8)
#define	PB_BEGIN_MONITOR	(PBIOC | 1)
#define	PB_END_MONITOR		(PBIOC | 2)
#define	PB_CREATE_BUTTON_EVENT	(PBIOC | 3)	/* used by test suite */
#define	PB_GET_EVENTS		(PBIOC | 4)

/*
 * Supported events
 */
#define	PB_BUTTON_PRESS		0x1

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PBIO_H */
