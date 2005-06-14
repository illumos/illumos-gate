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

#ifndef _KVM_CPU_H
#define	_KVM_CPU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * CPU-specific target implementation
 *
 * Each CPU provides a set of debugging facilities.  We have per-CPU "modules",
 * each of which exposes a kmt_cpu_t.  When initialized, these modules will
 * install dcmds, walkers, and the like in order to allow the user to take
 * advantage of features specific to the CPU being used.
 */

#include <mdb/mdb_target.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct kmt_cpu kmt_cpu_t;

extern kmt_cpu_t *kmt_cpu_create(mdb_tgt_t *);
extern void kmt_cpu_destroy(kmt_cpu_t *);

extern const char *kmt_cpu_name(kmt_cpu_t *);

#if defined(__i386) || defined(__amd64)
extern int kmt_cpu_step_branch(mdb_tgt_t *, kmt_cpu_t *);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _KVM_CPU_H */
