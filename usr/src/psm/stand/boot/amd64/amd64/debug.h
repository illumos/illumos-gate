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

#ifndef	_AMD64_DEBUG_H
#define	_AMD64_DEBUG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/varargs.h>
#include <sys/promif.h>
#include <sys/debug.h>

extern int amd64_debug;
extern int amd64_pt_debug;
extern uint_t bop_trace;

#define	dprintf	if (amd64_debug) printf

#define	AMD64_TRACE_BOP_IO	1
#define	AMD64_TRACE_BOP_VM	2
#define	AMD64_TRACE_BOP_PROP	4
#define	AMD64_TRACE_BOP_1275	8
#define	AMD64_TRACE_BOP_BIOS	16

#ifdef	__cplusplus
}
#endif

#endif	/* _AMD64_DEBUG_H */
