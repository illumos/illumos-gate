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
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Rpc additions to <sys/types.h>
 */

#ifndef	__rpc_types_h
#define	__rpc_types_h

#define	bool_t	int
#define	enum_t	int
#define	__dontcare__	-1

#ifndef	FALSE
#	define	FALSE	(0)
#endif

#ifndef	TRUE
#	define	TRUE	(1)
#endif

#ifndef	NULL
#	define	NULL 0
#endif

#ifndef	KERNEL
#include <malloc.h>
#define	mem_alloc(bsize)	malloc(bsize)
#define	mem_free(ptr, bsize)	free(ptr)
#else
extern char *kmem_alloc();
#define	mem_alloc(bsize)	kmem_alloc((u_int)bsize)
#define	mem_free(ptr, bsize)	kmem_free((caddr_t)(ptr), (u_int)(bsize))
#endif

#include <sys/types.h>
#include <sys/time.h>

#endif	/* !__rpc_types_h */
