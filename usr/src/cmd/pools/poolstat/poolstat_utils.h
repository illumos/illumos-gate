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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_POOLSTAT_UTILS_H
#define	_POOLSTAT_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	REALLOC(p, nbytes) Realloc((p), (nbytes))
#define	ZALLOC(nbytes) Zalloc((nbytes))

#define	FREE(p) ((void) (free((p)), (p) = 0))
#define	NEW0(p) ((p) = ZALLOC((long)sizeof (*(p))))

extern void *Zalloc(size_t);
extern void *Realloc(void *, size_t);
extern void Free(void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _POOLSTAT_UTILS_H */
