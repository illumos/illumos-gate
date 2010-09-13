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

#ifndef _KVM_CPU_IMPL_H
#define	_KVM_CPU_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kmdb/kvm_cpu.h>
#include <mdb/mdb_target.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct kmt_cpu_ops {
	void (*kco_destroy)(kmt_cpu_t *);
	const char *(*kco_name)(kmt_cpu_t *);
	int (*kco_step_branch)(kmt_cpu_t *, mdb_tgt_t *);
} kmt_cpu_ops_t;

struct kmt_cpu {
	kmt_cpu_ops_t *kmt_cpu_ops;	/* Pointer to ops vector */
	void *kmt_cpu_data;		/* Private storage */
};

typedef kmt_cpu_t *kmt_cpu_ctor_f(mdb_tgt_t *);

#if defined(__i386) || defined(__amd64)
extern kmt_cpu_ctor_f kmt_cpu_amd_create;
extern kmt_cpu_ctor_f kmt_cpu_p4_create;
#if defined(__i386)
extern kmt_cpu_ctor_f kmt_cpu_p6_create;
#endif	/* __i386 */
#endif	/* __i386 || __amd64 */

#ifdef __cplusplus
}
#endif

#endif /* _KVM_CPU_IMPL_H */
