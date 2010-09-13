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
 * Copyright (c) 1989-1996, 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 *  ff.h - Failfast device driver header file.
 */

#ifndef	_FF_H
#define	_FF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Supported ioctl calls.
 */
#define	FAILFAST_BASE		('f' << 8)

#define	FAILFAST_ARM		(FAILFAST_BASE|1)
#define	FAILFAST_DISARM		(FAILFAST_BASE|2)
#define	FAILFAST_DEBUG_MODE	(FAILFAST_BASE|3)
#define	FAILFAST_HALT_MODE	(FAILFAST_BASE|4)
#define	FAILFAST_PANIC_MODE	(FAILFAST_BASE|5)
#define	FAILFAST_SETNAME	(FAILFAST_BASE|6)

#ifdef __cplusplus
}
#endif

#endif	/* !_FF_H */
