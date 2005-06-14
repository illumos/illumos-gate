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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DEVID_IMPL_H
#define	_DEVID_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	TRUE
#define	TRUE 1
#endif	/* TRUE */

#ifndef	FALSE
#define	FALSE 0
#endif	/* FALSE */

/*
 * Macros to make kernel and library code identical.
 *
 * NOTE: to get ddi_ entrypoints to show up in cscope, DEVID_FUNC
 * is NOT used in function definitions.
 */
#ifdef	_KERNEL
#include <sys/kmem.h>
#include <sys/sunddi.h>

#define	DEVID_MALLOC(n)		kmem_alloc(n, KM_SLEEP)
#define	DEVID_FREE(x, n)	kmem_free(x, n)
#define	DEVID_FUNC(x)		ddi_##x
#define	DEVID_ASSERT(x)		ASSERT(x)
#define	DEVID_SUCCESS		DDI_SUCCESS
#define	DEVID_FAILURE		DDI_FAILURE
#define	DEVID_RETRY		DDI_NOT_WELL_FORMED
#define	DEVID_RET_VALID		DDI_SUCCESS
#define	DEVID_RET_INVALID	DDI_FAILURE
#else	/* !_KERNEL */
#include <stdlib.h>
#include <strings.h>
#include <devid.h>

#define	DEVID_MALLOC(n)		malloc(n)
#define	DEVID_FREE(x, n)	free(x)
#define	DEVID_FUNC(x)		x
#define	DEVID_ASSERT(x)
#define	DEVID_SUCCESS		0
#define	DEVID_FAILURE		-1
#define	DEVID_RETRY		-2
#define	DEVID_RET_VALID		1
#define	DEVID_RET_INVALID	0
#endif  /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _DEVID_IMPL_H */
