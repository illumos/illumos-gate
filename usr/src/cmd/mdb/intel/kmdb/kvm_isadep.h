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
 *
 * Copyright 2018 Joyent, Inc.
 */

#ifndef _KVM_ISADEP_H
#define	_KVM_ISADEP_H

#ifdef __cplusplus
extern "C" {
#endif

extern uintptr_t kmt_invoke(uintptr_t, uint_t, const uintptr_t *);

extern void kmt_in(void *, size_t, uintptr_t);
extern void kmt_out(void *, size_t, uintptr_t);

extern int kmt_in_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int kmt_out_dcmd(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int kmt_rdmsr(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int kmt_wrmsr(uintptr_t, uint_t, int, const mdb_arg_t *);

extern int kmt_rdpcicfg(uintptr_t, uint_t, int, const mdb_arg_t *);
extern int kmt_wrpcicfg(uintptr_t, uint_t, int, const mdb_arg_t *);

#ifdef __cplusplus
}
#endif

#endif /* _KVM_ISADEP_H */
