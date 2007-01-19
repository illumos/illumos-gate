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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KAIF_H
#define	_KAIF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _ASM
#include <sys/kdi.h>
#include <sys/types.h>
#include <sys/segments.h>
#include <sys/kdi_machimpl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef kdi_cpusave_t kaif_cpusave_t;

#define	KAIF_CPU_STATE_NONE		KDI_CPU_STATE_NONE
#define	KAIF_CPU_STATE_MASTER		KDI_CPU_STATE_MASTER
#define	KAIF_CPU_STATE_SLAVE		KDI_CPU_STATE_SLAVE

#ifndef _ASM

extern kdi_cpusave_t *kaif_cpusave;
extern int kaif_ncpusave;
extern int kaif_master_cpuid;

extern int kaif_trap_switch;

extern void kaif_trap_set_debugger(void);
extern void kaif_trap_set_saved(kdi_cpusave_t *);

extern uintptr_t kaif_invoke(uintptr_t, uint_t, const uintptr_t[]);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _KAIF_H */
