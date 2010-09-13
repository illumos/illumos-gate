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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SYSTRACE_H
#define	_SYS_SYSTRACE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dtrace.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

typedef struct systrace_sysent {
	dtrace_id_t	stsy_entry;
	dtrace_id_t	stsy_return;
	int64_t		(*stsy_underlying)();
} systrace_sysent_t;

extern systrace_sysent_t *systrace_sysent;
extern systrace_sysent_t *systrace_sysent32;

extern void (*systrace_probe)(dtrace_id_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t, uintptr_t);
extern void systrace_stub(dtrace_id_t, uintptr_t, uintptr_t,
    uintptr_t, uintptr_t, uintptr_t, uintptr_t);

extern int64_t dtrace_systrace_syscall(uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5);

#ifdef _SYSCALL32_IMPL
extern int64_t dtrace_systrace_syscall32(uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5);
#endif

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SYSTRACE_H */
