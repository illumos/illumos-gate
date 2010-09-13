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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * CPU-specific target implementation
 *
 * Each CPU provides a set of debugging facilities.  We have per-CPU "modules",
 * each of which exposes a kmt_cpu_t.  When initialized, these modules will
 * install dcmds, walkers, and the like in order to allow the user to take
 * advantage of features specific to the CPU being used.
 */

#include <kmdb/kmdb_kdi.h>
#include <kmdb/kvm_cpu_impl.h>
#include <mdb/mdb_target.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

static kmt_cpu_ctor_f *const kmt_cpu_ctors[] = {
#if defined(__i386) || defined(__amd64)
	kmt_cpu_amd_create,
	kmt_cpu_p4_create,
#if defined(__i386)
	kmt_cpu_p6_create,
#endif	/* __i386 */
#endif	/* __i386 || __amd64 */
	NULL
};

kmt_cpu_t *
kmt_cpu_create(mdb_tgt_t *t)
{
	kmt_cpu_t *cpu;
	int retry = 0;
	int i;

	for (i = 0; kmt_cpu_ctors[i] != NULL; i++) {
		if ((cpu = kmt_cpu_ctors[i](t)) != NULL)
			return (cpu);
		else if (errno == EAGAIN)
			retry = 1;
	}

	if (retry)
		(void) set_errno(EAGAIN);

	return (NULL);
}

void
kmt_cpu_destroy(kmt_cpu_t *cpu)
{
	if (cpu != NULL)
		cpu->kmt_cpu_ops->kco_destroy(cpu);
}

int
kmt_cpu_step_branch(mdb_tgt_t *t, kmt_cpu_t *cpu)
{
	if (cpu == NULL || cpu->kmt_cpu_ops->kco_step_branch == NULL)
		return (set_errno(EMDB_TGTHWNOTSUP));

	return (cpu->kmt_cpu_ops->kco_step_branch(cpu, t));
}

const char *
kmt_cpu_name(kmt_cpu_t *cpu)
{
	if (cpu == NULL)
		return ("none");
	else
		return (cpu->kmt_cpu_ops->kco_name(cpu));
}
