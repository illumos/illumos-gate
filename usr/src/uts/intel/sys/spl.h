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
 * Copyright (c) 1992-1993,1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_SPL_H
#define	_SYS_SPL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * on x86 platform these are identity functions
 */
#define	ipltospl(n)	(n)
#define	spltoipl(n)	(n)

/*
 * Hardware spl levels
 * it should be replace by the appropriate interrupt class info.
 */
#define	SPL8    15
#define	SPL7    13

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SPL_H */
