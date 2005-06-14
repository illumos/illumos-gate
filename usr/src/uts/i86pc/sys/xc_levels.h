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
 * Copyright (c) 1991-1993, Sun Microsystems,  Inc.
 */

#ifndef _SYS_XC_LEVELS_H
#define	_SYS_XC_LEVELS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Index for xc_mboxes at each level */
#define	X_CALL_LOPRI	0
#define	X_CALL_MEDPRI	1
#define	X_CALL_HIPRI	2
#define	X_CALL_LEVELS	(X_CALL_HIPRI - X_CALL_LOPRI + 1)

/* PIL associated with each x-call level */
#define	XC_CPUPOKE_PIL	11	/* cpu poke priority x-calls */
#define	XC_LO_PIL	1	/* low priority x-calls */
#define	XC_MED_PIL	13	/* medium priority x-calls */
#define	XC_HI_PIL	15	/* high priority x-calls */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_XC_LEVELS_H */
