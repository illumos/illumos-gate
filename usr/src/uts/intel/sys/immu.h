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
 * Copyright (c) 1990-1997,1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_IMMU_H
#define	_SYS_IMMU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * XXX - following stuff from 3b2 immu.h.  this really belongs elsewhere.
 */

/*
 * The following variables describe the memory managed by
 * the kernel.  This includes all memory above the kernel
 * itself.
 */

extern pgcnt_t	maxmem;		/* Maximum available free memory. */
extern pgcnt_t	freemem;	/* Current free memory. */
extern pgcnt_t	availrmem;	/* Available resident (not	*/
				/* swapable) memory in pages.	*/

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IMMU_H */
