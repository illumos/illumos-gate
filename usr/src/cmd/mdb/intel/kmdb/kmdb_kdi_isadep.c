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

#include <sys/types.h>
#include <sys/kdi_impl.h>
#include <sys/segments.h>
#include <sys/cpuvar.h>

#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_umem.h>
#include <kmdb/kmdb_dpi.h>
#include <kmdb/kmdb_kdi_impl.h>
#include <mdb/mdb.h>

void (**kmdb_kdi_shutdownp)(int, int);

int
kmdb_kdi_xc_initialized(void)
{
	return (mdb.m_kdi->mkdi_xc_initialized());
}

/*ARGSUSED*/
void
kmdb_kdi_stop_other_cpus(int my_cpuid, void (*slave_saver)(void))
{
	/* Stop other CPUs if there are CPUs to stop */
	if (mdb.m_kdi->mkdi_xc_initialized())
		mdb.m_kdi->mkdi_xc_others(my_cpuid, slave_saver);
}

void
kmdb_kdi_cpu_iter(void (*iter)(struct cpu *, uint_t), uint_t arg)
{
	mdb.m_kdi->mkdi_cpu_iter(iter, arg);
}

uintptr_t
kmdb_kdi_get_userlimit(void)
{
	return (mdb.m_kdi->mkdi_get_userlimit());
}

void
kmdb_kdi_idt_init_gate(gate_desc_t *gate, void (*hdlr)(void), uint_t dpl,
    int useboot)
{
	mdb.m_kdi->mkdi_idt_init_gate(gate, hdlr, dpl, useboot);
}

void
kmdb_kdi_idt_read(gate_desc_t *idt, gate_desc_t *gatep, uint_t vec)
{
	mdb.m_kdi->mkdi_idt_read(idt, gatep, vec);
}

void
kmdb_kdi_idt_write(gate_desc_t *idt, gate_desc_t *gate, uint_t vec)
{
	mdb.m_kdi->mkdi_idt_write(idt, gate, vec);
}

gate_desc_t *
kmdb_kdi_cpu2idt(cpu_t *cp)
{
	return (mdb.m_kdi->mkdi_cpu2idt(cp));
}

int
kmdb_kdi_get_cpuinfo(uint_t *vendorp, uint_t *familyp, uint_t *modelp)
{
	int err;

	if ((err = mdb.m_kdi->mkdi_get_cpuinfo(vendorp, familyp, modelp)) != 0)
		return (set_errno(err));

	return (0);
}

/*ARGSUSED*/
void
kdi_cpu_init(void)
{
}

/*ARGSUSED1*/
void
kmdb_kdi_init_isadep(kdi_t *kdi, kmdb_auxv_t *kav)
{
	kmdb_kdi_shutdownp = kdi->mkdi_shutdownp;
}
