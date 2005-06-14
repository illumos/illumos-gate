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
 * Copyright (c) 1991-1997 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_CONDVAR_IMPL_H
#define	_SYS_CONDVAR_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Implementation-private definitions for condition variables
 */

#ifndef	_ASM
#include <sys/types.h>
#include <sys/thread.h>
#endif	/* _ASM */

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

/*
 * Condtion variables.
 */

typedef struct _condvar_impl {
	ushort_t	cv_waiters;
} condvar_impl_t;

#define	CV_HAS_WAITERS(cvp)	(((condvar_impl_t *)(cvp))->cv_waiters != 0)

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CONDVAR_IMPL_H */
