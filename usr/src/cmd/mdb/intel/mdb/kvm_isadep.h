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

#ifndef	_KVM_ISADEP_H
#define	_KVM_ISADEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_modapi.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern int kt_cpustack(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int kt_cpuregs(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int kt_regs(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int kt_kvmregs(mdb_tgt_t *, uint_t, mdb_tgt_gregset_t *);
extern void kt_regs_to_kregs(struct regs *, mdb_tgt_gregset_t *);

extern int kt_putareg(mdb_tgt_t *, mdb_tgt_tid_t, const char *, mdb_tgt_reg_t);
extern int kt_getareg(mdb_tgt_t *, mdb_tgt_tid_t,
    const char *, mdb_tgt_reg_t *);

extern int kt_stack(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int kt_stackv(uintptr_t, uint_t, int, const mdb_arg_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _KVM_ISADEP_H */
