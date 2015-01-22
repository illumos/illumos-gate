/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.	All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc
 */

#ifndef _SYS_LX_THREAD_H
#define	_SYS_LX_THREAD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <thread.h>

typedef struct lx_tsd {
#if defined(_ILP32)
	/* 32-bit thread-specific Linux %gs value */
	uintptr_t	lxtsd_gs;
#else
	/* 64-bit thread-specific Linux %fsbase value */
	uintptr_t	lxtsd_fsbase;
#endif
	int		lxtsd_exit;
	int		lxtsd_exit_status;
	ucontext_t	lxtsd_exit_context;
} lx_tsd_t;

extern thread_key_t	lx_tsd_key;

extern void		lx_swap_gs(long, long *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_THREAD_H */
