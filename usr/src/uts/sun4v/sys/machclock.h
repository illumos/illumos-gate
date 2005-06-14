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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MACHCLOCK_H
#define	_SYS_MACHCLOCK_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Sun4v processors come up with NPT cleared and there is no need to
 * clear it again. Also, clearing of the NPT cannot be done atomically
 * on a CMT processor.
 */
#define	CLEARTICKNPT

#if defined(CPU_MODULE)

/*
 * Constants used to convert hi-res timestamps into nanoseconds
 * (see <sys/clock.h> file for more information)
 */

/*
 * At least 62.5 MHz, for faster %tick-based systems.
 */
#define	NSEC_SHIFT	4
#define	VTRACE_SHIFT	4

#endif /* CPU_MODULE */

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_MACHCLOCK_H */
