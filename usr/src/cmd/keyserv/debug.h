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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KEYSERV_DEBUG_H
#define	_KEYSERV_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * #define	DEBUG
 */

#ifdef DEBUG
typedef enum {
	KEYSERV_DEBUG0 = 1,
	KEYSERV_DEBUG1,
	KEYSERV_DEBUG,
	KEYSERV_INFO,
	KEYSERV_PANIC
} debug_level;

extern int debugging;

#define	debug(x, y) (test_debug(x, __FILE__, __LINE__) && real_debug ## y)
#else
#define	debug(x, y)
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _KEYSERV_DEBUG_H */
