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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#ifndef _RPC_TYPES_H
#define	_RPC_TYPES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Rpc additions to <sys/types.h>
 */
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int bool_t;
typedef int enum_t;

/*
 * The ulonglong_t type was introduced to workaround an rpcgen bug
 * that has been fixed, this next typedef will be removed in a future release.
 * Do *NOT* use!
 */
typedef u_longlong_t ulonglong_t;

#if defined(_LP64) || defined(_I32LPx)
typedef	uint32_t rpcprog_t;
typedef	uint32_t rpcvers_t;
typedef	uint32_t rpcproc_t;
typedef uint32_t rpcprot_t;
typedef uint32_t rpcport_t;
typedef int32_t rpc_inline_t;
#else
typedef	unsigned long rpcprog_t;
typedef	unsigned long rpcvers_t;
typedef	unsigned long rpcproc_t;
typedef unsigned long rpcprot_t;
typedef unsigned long rpcport_t;
typedef long rpc_inline_t;
#endif


#define	__dontcare__	-1

#ifndef	FALSE
#define	FALSE	(0)
#endif

#ifndef	TRUE
#define	TRUE	(1)
#endif

#ifndef	NULL
#define	NULL	0
#endif

#ifndef	_KERNEL
#define	mem_alloc(bsize)	malloc(bsize)
#define	mem_free(ptr, bsize)	free(ptr)
#else
#include <sys/kmem.h>		/* XXX */

#define	mem_alloc(bsize)	kmem_alloc(bsize, KM_SLEEP)
#define	mem_free(ptr, bsize)	kmem_free(ptr, bsize)

extern const char *rpc_tpiprim2name(uint_t prim);
extern const char *rpc_tpierr2name(uint_t err);

#if defined(DEBUG) && !defined(RPCDEBUG)
#define	RPCDEBUG
#endif

#ifdef RPCDEBUG
extern uint_t	rpclog;

#define	RPCLOG(A, B, C)	\
	((void)((rpclog) && (rpclog & (A)) && (printf((B), (C)), TRUE)))
#define	RPCLOG0(A, B)	\
	((void)((rpclog) && (rpclog & (A)) && (printf(B), TRUE)))
#else
#define		RPCLOG(A, B, C)
#define		RPCLOG0(A, B)
#endif

#endif

/* messaging stuff. */
#ifndef _KERNEL
#ifdef __STDC__
extern const char __nsl_dom[];
#else
extern char __nsl_dom[];
#endif
#endif

#ifdef __cplusplus
}
#endif

#include <sys/time.h>

#endif	/* _RPC_TYPES_H */
