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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_TOPO_ALLOC_H
#define	_TOPO_ALLOC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <topo_module.h>
#include <libnvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern void *topo_alloc(size_t, int);
extern void *topo_zalloc(size_t, int);
extern void topo_free(void *, size_t);
extern void *topo_nv_alloc(nv_alloc_t *, size_t);
extern void topo_nv_free(nv_alloc_t *, void *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_ALLOC_H */
