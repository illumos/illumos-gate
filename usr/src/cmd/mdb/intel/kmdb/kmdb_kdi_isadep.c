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

#include <sys/types.h>
#include <sys/kdi_impl.h>
#include <sys/segments.h>
#include <sys/cpuvar.h>

#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_umem.h>
#include <kmdb/kmdb_dpi.h>
#include <mdb/mdb.h>

/*ARGSUSED*/
void
kmdb_kdi_stop_slaves(int my_cpuid, int doxc)
{
	/* Stop other CPUs if there are CPUs to stop */
	mdb.m_kdi->mkdi_stop_slaves(my_cpuid, doxc);
}

void
kmdb_kdi_start_slaves(void)
{
	mdb.m_kdi->mkdi_start_slaves();
}

void
kmdb_kdi_slave_wait(void)
{
	mdb.m_kdi->mkdi_slave_wait();
}

uintptr_t
kmdb_kdi_get_userlimit(void)
{
	return (mdb.m_kdi->mkdi_get_userlimit());
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
kmdb_kdi_init_isadep(kdi_t *kdi, kmdb_auxv_t *kav)
{
}

void
kmdb_kdi_activate(kdi_main_t main, kdi_cpusave_t *cpusave, int ncpusave)
{
	mdb.m_kdi->mkdi_activate(main, cpusave, ncpusave);
}

void
kmdb_kdi_deactivate(void)
{
	mdb.m_kdi->mkdi_deactivate();
}

void
kmdb_kdi_idt_switch(kdi_cpusave_t *cpusave)
{
	mdb.m_kdi->mkdi_idt_switch(cpusave);
}

void
kmdb_kdi_update_drreg(kdi_drreg_t *drreg)
{
	mdb.m_kdi->mkdi_update_drreg(drreg);
}

void
kmdb_kdi_memrange_add(caddr_t base, size_t len)
{
	mdb.m_kdi->mkdi_memrange_add(base, len);
}

void
kmdb_kdi_reboot(void)
{
	mdb.m_kdi->mkdi_reboot();
}
