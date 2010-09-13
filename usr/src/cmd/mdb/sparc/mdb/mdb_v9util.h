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

#ifndef _MDB_V9UTIL_H
#define	_MDB_V9UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mdb/mdb_kreg.h>
#include <mdb/mdb_target_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	PC_FAKE		-1UL	/* illegal pc value unequal 0 */

typedef uint32_t mdb_instr_t;

extern const mdb_tgt_regdesc_t mdb_sparcv9_kregs[];

extern void mdb_v9printregs(const mdb_tgt_gregset_t *);
extern int mdb_kvm_v9stack_iter(mdb_tgt_t *, const mdb_tgt_gregset_t *,
    mdb_tgt_stack_f *, void *);

extern int mdb_kvm_v9frame(void *, uintptr_t, uint_t, const long *,
    const mdb_tgt_gregset_t *);
extern int mdb_kvm_v9framev(void *, uintptr_t, uint_t, const long *,
    const mdb_tgt_gregset_t *);
extern int mdb_kvm_v9framer(void *, uintptr_t, uint_t, const long *,
    const mdb_tgt_gregset_t *);

#ifdef __cplusplus
}
#endif

#endif /* _MDB_V9UTIL_H */
