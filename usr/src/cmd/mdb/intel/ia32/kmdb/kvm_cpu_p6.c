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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This plugin supports debugging functionality unique to Intel processors based
 * on the P6 core (Pentium Pro, Pentium II, and Pentium III).  It does not
 * support the Pentium M processor, which uses a P4-style branch trace stack.
 * The Pentium M is supported by the P4 plugin.
 */

#include <kmdb/kvm_cpu_impl.h>
#include <kmdb/kmdb_dpi.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kvm.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

#include <sys/x86_archext.h>

typedef struct kmt_cpu_p6 {
	uint64_t p6_debugctl;
} kmt_cpu_p6_t;

/*
 * The debugctl value in this struct needs to outlive the destruction of the
 * kmt_cpu_t.  It needs to be around for the final exit from the debugger so
 * we can do the final write of the debugctl MSR.
 */
static kmt_cpu_p6_t kmt_cpu_p6;

static void
kmt_p6_branch(uint_t cpuid, const char *label, uint_t msr)
{
	char buf[BUFSIZ];
	uintptr_t addr;

	addr = (uintptr_t)kmdb_dpi_msr_get_by_cpu(cpuid, msr);

	mdb_printf("%s: %p %A\n", label, addr, addr);

	if (mdb_dis_ins2str(mdb.m_disasm, mdb.m_target,
	    MDB_TGT_AS_VIRT, buf, sizeof (buf), addr) != addr)
		mdb_printf("%*s  %s\n", strlen(label), "", buf);
}

/*ARGSUSED*/
static int
kmt_p6_branches(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	intptr_t cpuid = DPI_MASTER_CPUID;

	if (mdb_getopts(argc, argv,
	    'c', MDB_OPT_UINTPTR, &cpuid,
	    NULL) != argc)
		return (DCMD_USAGE);

	kmt_p6_branch(cpuid, "LastBranchToIP     ", MSR_LBR_TO);
	kmt_p6_branch(cpuid, "LastBranchFromIP   ", MSR_LBR_FROM);
	kmt_p6_branch(cpuid, "LastExceptionToIP  ", MSR_LEX_TO);
	kmt_p6_branch(cpuid, "LastExceptionFromIP", MSR_LEX_FROM);

	return (0);
}

/*
 * MSRs that we want to track.  These will be read each time the debugger is
 * entered.
 */
static const kdi_msr_t kmt_p6_msr[] = {
	{ MSR_DEBUGCTL,	KDI_MSR_CLEARENTRY },
	{ MSR_DEBUGCTL,	KDI_MSR_WRITEDELAY, &kmt_cpu_p6.p6_debugctl },
	{ MSR_LBR_TO,	KDI_MSR_READ },
	{ MSR_LBR_FROM,	KDI_MSR_READ },
	{ MSR_LEX_TO,	KDI_MSR_READ },
	{ MSR_LEX_FROM,	KDI_MSR_READ },
	{ NULL }
};

/*ARGSUSED*/
static void
kmt_p6_destroy(kmt_cpu_t *cpu)
{
	/* Leave LBR on */

	mdb_free(cpu, sizeof (kmt_cpu_t));
}

/*ARGSUSED*/
static const char *
kmt_p6_name(kmt_cpu_t *cpu)
{
	return ("Intel P6 family (Pentium Pro, Pentium II, Pentium III)");
}

/*ARGSUSED*/
static void
kmt_p6_btf_clear(mdb_tgt_t *t, int id, void *arg)
{
	kmt_cpu_p6_t *p6 = arg;
	kreg_t efl;

	p6->p6_debugctl &= ~DEBUGCTL_BTF;

	(void) kmdb_dpi_get_register("eflags", &efl);
	efl &= ~(1 << KREG_EFLAGS_TF_SHIFT);
	(void) kmdb_dpi_set_register("eflags", efl);
}

/* Enable branch stepping, to be disabled on the next debugger entry */
static int
kmt_p6_step_branch(kmt_cpu_t *cpu, mdb_tgt_t *t)
{
	kmt_cpu_p6_t *p6 = cpu->kmt_cpu_data;
	kreg_t efl;

	(void) kmdb_dpi_get_register("eflags", &efl);
	(void) kmdb_dpi_set_register("eflags",
	    (efl | (1 << KREG_EFLAGS_TF_SHIFT)));

	p6->p6_debugctl |= DEBUGCTL_BTF;

	return (mdb_tgt_add_fault(t, KMT_TRAP_ALL,
	    MDB_TGT_SPEC_HIDDEN | MDB_TGT_SPEC_TEMPORARY,
	    kmt_p6_btf_clear, p6));
}

static kmt_cpu_ops_t kmt_p6_ops = {
	kmt_p6_destroy,
	kmt_p6_name,
	kmt_p6_step_branch
};

static const mdb_dcmd_t kmt_p6_dcmds[] = {
	{ "branches", NULL, "describe the recently-taken branches",
	    kmt_p6_branches },
	{ NULL }
};

/* See 07/04 AP-485 Intel Processor Identification and the CPUID Instruction */
#define	KMT_CPU_FAMILY_P6	0x6
#define	KMT_CPU_MODEL_PM_9	0x9	/* Pentium M, model 9 */
#define	KMT_CPU_MODEL_PM_D	0xd	/* Pentium M, model d */

kmt_cpu_t *
kmt_cpu_p6_create(mdb_tgt_t *t)
{
	uint_t vendor, family, model;
	kmt_cpu_t *cpu;

	if (kmdb_kdi_get_cpuinfo(&vendor, &family, &model) < 0)
		return (NULL); /* errno is set for us */

	if (vendor != X86_VENDOR_Intel || family != KMT_CPU_FAMILY_P6 ||
	    model == KMT_CPU_MODEL_PM_9 || model == KMT_CPU_MODEL_PM_D) {
		(void) set_errno(ENOTSUP);
		return (NULL);
	}

	cpu = mdb_zalloc(sizeof (kmt_cpu_t), UM_SLEEP);
	cpu->kmt_cpu_ops = &kmt_p6_ops;
	cpu->kmt_cpu_data = &kmt_cpu_p6;

	kmdb_dpi_msr_add(kmt_p6_msr);

	kmt_cpu_p6.p6_debugctl = DEBUGCTL_LBR; /* enable LBR on resume */

	(void) mdb_tgt_register_dcmds(t, kmt_p6_dcmds, MDB_MOD_FORCE);

	return (cpu);
}
