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
 * Copyright (c) 1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_STRMDEP_H
#define	_SYS_STRMDEP_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains all machine-dependent declarations
 * in STREAMS.
 */

/*
 * Copy data from one data buffer to another.
 * The addresses must be word aligned - if not, use bcopy!
 */
#define	strbcpy(s, d, c)	bcopy(s, d, c)

/*
 * save the address of the calling function on the 3b2 to
 * enable tracking of who is allocating message blocks
 */
#define	saveaddr(funcp)

/*
 * macro to check pointer alignment
 * (true if alignment is sufficient for worst case)
 */
#define	str_aligned(X)	(((ulong_t)(X) & (sizeof (long) - 1)) == 0)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_STRMDEP_H */
