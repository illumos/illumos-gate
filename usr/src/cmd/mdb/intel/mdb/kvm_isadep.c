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
/*
 * Copyright (c) 2012, Joyent, Inc.  All rights reserved.
 */

/*
 * Libkvm Kernel Target Intel component
 *
 * This file provides the Intel-dependent portion of the libkvm kernel target.
 * For more details on the implementation refer to mdb_kvm.c.
 */

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb_errno.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_kvm.h>
#include <mdb/mdb_ks.h>
#include <mdb/mdb.h>
#include <mdb/kvm_isadep.h>

#include <sys/cpuvar.h>
#include <sys/privmregs.h>

int
kt_getareg(mdb_tgt_t *t, mdb_tgt_tid_t tid,
    const char *rname, mdb_tgt_reg_t *rp)
{
	const mdb_tgt_regdesc_t *rdp;
	kt_data_t *kt = t->t_data;

	if (tid != kt->k_tid)
		return (set_errno(EMDB_NOREGS));

	for (rdp = kt->k_rds; rdp->rd_name != NULL; rdp++) {
		if (strcmp(rname, rdp->rd_name) == 0) {
			*rp = kt->k_regs->kregs[rdp->rd_num];
			if (rdp->rd_flags & MDB_TGT_R_32)
				*rp &= 0xffffffffULL;
			else if (rdp->rd_flags & MDB_TGT_R_16)
				*rp &= 0xffffULL;
			else if (rdp->rd_flags & MDB_TGT_R_8H)
				*rp = (*rp & 0xff00ULL) >> 8;
			else if (rdp->rd_flags & MDB_TGT_R_8L)
				*rp &= 0xffULL;
			return (0);
		}
	}

	return (set_errno(EMDB_BADREG));
}

int
kt_putareg(mdb_tgt_t *t, mdb_tgt_tid_t tid, const char *rname, mdb_tgt_reg_t r)
{
	const mdb_tgt_regdesc_t *rdp;
	kt_data_t *kt = t->t_data;

	if (tid != kt->k_tid)
		return (set_errno(EMDB_NOREGS));

	for (rdp = kt->k_rds; rdp->rd_name != NULL; rdp++) {
		if (strcmp(rname, rdp->rd_name) == 0) {
			if (rdp->rd_flags & MDB_TGT_R_32)
				r &= 0xffffffffULL;
			else if (rdp->rd_flags & MDB_TGT_R_16)
				r &= 0xffffULL;
			else if (rdp->rd_flags & MDB_TGT_R_8H)
				r = (r & 0xffULL) << 8;
			else if (rdp->rd_flags & MDB_TGT_R_8L)
				r &= 0xffULL;

			kt->k_regs->kregs[rdp->rd_num] = (kreg_t)r;
			return (0);
		}
	}

	return (set_errno(EMDB_BADREG));
}

int
kt_kvmregs(mdb_tgt_t *t, uint_t cpuid, mdb_tgt_gregset_t *kregs)
{
	kt_data_t *kt = t->t_data;
	privmregs_t mregs;
	int ret;

	if ((ret = kt->k_kb_ops->kb_getmregs(kt->k_cookie, cpuid, &mregs)) != 0)
		return (ret);

	kt_regs_to_kregs(&mregs.pm_gregs, kregs);
	return (0);
}

static int
kt_cpu2cpuid(uintptr_t cpup)
{
	cpu_t cpu;

	if (mdb_vread(&cpu, sizeof (cpu_t), cpup) != sizeof (cpu_t))
		return (-1);

	return (cpu.cpu_id);
}

int
kt_cpustack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_gregset_t regs;
	intptr_t cpuid = 0;
	uint_t verbose = 0;
	int i;

	if (flags & DCMD_ADDRSPEC) {
		if ((cpuid = kt_cpu2cpuid(addr)) < 0) {
			(void) set_errno(EMDB_NOMAP);
			mdb_warn("failed to find cpuid for cpu at %p", addr);
			return (DCMD_ERR);
		}
		flags &= ~DCMD_ADDRSPEC;
	}


	i = mdb_getopts(argc, argv,
	    'c', MDB_OPT_UINTPTR, &cpuid,
	    'v', MDB_OPT_SETBITS, 1, &verbose,
	    NULL);

	argc -= i;
	argv += i;

	if (kt_kvmregs(t, cpuid, &regs) != 0) {
		mdb_warn("failed to get regs for cpu %d\n", cpuid);
		return (DCMD_ERR);
	}

	/*
	 * Tell the stack walker that we have regs.
	 */
	flags |= DCMD_ADDRSPEC;
	addr = regs.kregs[KREG_FP];

	if (verbose)
		return (kt_stackv(addr, flags, argc, argv));
	else
		return (kt_stack(addr, flags, argc, argv));
}

/*ARGSUSED*/
int
kt_cpuregs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_tgt_t *t = mdb.m_target;
	mdb_tgt_gregset_t regs;
	intptr_t cpuid = 0;
	int i;

	if (flags & DCMD_ADDRSPEC) {
		if (argc != 0)
			return (DCMD_USAGE);
		if ((cpuid = kt_cpu2cpuid(addr)) < 0) {
			(void) set_errno(EMDB_NOMAP);
			mdb_warn("failed to find cpuid for cpu at %p", addr);
			return (DCMD_ERR);
		}
	}


	i = mdb_getopts(argc, argv,
	    'c', MDB_OPT_UINTPTR, &cpuid,
	    NULL);

	argc -= i;
	argv += i;

	if (argc != 0)
		return (DCMD_USAGE);

	if (kt_kvmregs(t, cpuid, &regs) != 0) {
		mdb_warn("failed to get regs for cpu %d\n", cpuid);
		return (DCMD_ERR);
	}

	return (kt_regs((uintptr_t)&regs, flags, argc, argv));
}
