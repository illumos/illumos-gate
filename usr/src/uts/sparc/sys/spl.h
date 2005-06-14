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
 * Copyright 1986,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SPL_H
#define	_SYS_SPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* from SunOS psl.h 1.2 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * v9 spl and ipl are identical since pil is a separate register.
 */
#define	ipltospl(n)	(n)
#define	spltoipl(n)	(n)

/*
 * Hardware spl levels
 * XXX - This is a hack for softcall to block all i/o interrupts.
 * XXX - SPL5 and SPL3 are hacks for the latest zs code.
 * it should be replace by the appropriate interrupt class info.
 */
#define	SPL8    15
#define	SPL7    13
#define	SPL5    12
#define	SPLTTY  SPL5
#define	SPL3    6

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SPL_H */
