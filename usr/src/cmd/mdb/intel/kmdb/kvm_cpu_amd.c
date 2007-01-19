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
 * Debugging functionality unique to 64-bit AMD processors.
 */

#include <kmdb/kvm_cpu_impl.h>
#include <kmdb/kmdb_dpi.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kvm.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

#include <sys/x86_archext.h>

typedef struct kmt_cpu_amd {
	uint64_t amd_debugctl;		/* value for debugctl MSR */
	const kdi_msr_t *amd_msrs;	/* MSR r/w list */
	uint_t amd_family;		/* CPUID family */
	uint_t amd_model;		/* CPUID model */
} kmt_cpu_amd_t;

/*
 * The debugctl value in this struct needs to outlive the destruction of the
 * kmt_cpu_t.  It needs to be around for the final exit from the debugger so
 * we can do the final write of the debugctl MSR.
 */
static kmt_cpu_amd_t kmt_cpu_amd;

static void
kmt_amd_branch(uint_t cpuid, const char *label, uint_t msr)
{
	char buf[BUFSIZ];
	uintptr_t addr;

	addr = (uintptr_t)kmdb_dpi_msr_get_by_cpu(cpuid, msr);

	mdb_printf("%s: %p %A\n", label, addr, addr);

	if (mdb_dis_ins2str(mdb.m_disasm, mdb.m_target,
	    MDB_TGT_AS_VIRT, buf, sizeof (buf), addr) != addr)
		mdb_printf("%*s  %s\n", strlen(label), "", buf);
}

/*
 * MSRs for AMD processors with simple branch tracing facilities.  We'll use
 * this array if we can access listed LBR/LEX MSRs.
 */
static const kdi_msr_t kmt_amd_msrs[] = {
	{ MSR_DEBUGCTL,	KDI_MSR_CLEARENTRY },
	{ MSR_DEBUGCTL,	KDI_MSR_WRITEDELAY, &kmt_cpu_amd.amd_debugctl },
	{ MSR_LBR_TO,	KDI_MSR_READ },
	{ MSR_LBR_FROM,	KDI_MSR_READ },
	{ MSR_LEX_TO,	KDI_MSR_READ },
	{ MSR_LEX_FROM,	KDI_MSR_READ },
	{ NULL }
};

/*
 * Fallback MSR list for use if we can't read the LBR/LEX MSRs.
 */
static const kdi_msr_t kmt_amdunk_msrs[] = {
	{ MSR_DEBUGCTL,	KDI_MSR_CLEARENTRY },
	{ MSR_DEBUGCTL,	KDI_MSR_WRITEDELAY, &kmt_cpu_amd.amd_debugctl },
	{ NULL }
};

/*ARGSUSED*/
static void
kmt_amd_destroy(kmt_cpu_t *cpu)
{
	/* Leave LBR on */

	mdb_free(cpu, sizeof (kmt_cpu_t));
}

/*ARGSUSED*/
static const char *
kmt_amd_name(kmt_cpu_t *cpu)
{
	return ("AMD");
}

/*ARGSUSED*/
static void
kmt_amd_btf_clear(mdb_tgt_t *t, int id, void *arg)
{
	kmt_cpu_amd_t *amd = arg;
	kreg_t efl;

	amd->amd_debugctl &= ~DEBUGCTL_BTF;

	(void) kmdb_dpi_get_register("rflags", &efl);
	efl &= ~(1 << KREG_EFLAGS_TF_SHIFT);
	(void) kmdb_dpi_set_register("rflags", efl);
}

/* Enable branch stepping, to be disabled on the next debugger entry */
static int
kmt_amd_step_branch(kmt_cpu_t *cpu, mdb_tgt_t *t)
{
	kmt_cpu_amd_t *amd = cpu->kmt_cpu_data;
	kreg_t efl;

	(void) kmdb_dpi_get_register("rflags", &efl);
	(void) kmdb_dpi_set_register("rflags",
	    (efl | (1 << KREG_EFLAGS_TF_SHIFT)));

	amd->amd_debugctl |= DEBUGCTL_BTF;

	return (mdb_tgt_add_fault(t, KMT_TRAP_ALL,
	    MDB_TGT_SPEC_HIDDEN | MDB_TGT_SPEC_TEMPORARY,
	    kmt_amd_btf_clear, amd));
}

static kmt_cpu_ops_t kmt_amd_ops = {
	kmt_amd_destroy,
	kmt_amd_name,
	kmt_amd_step_branch
};

/*ARGSUSED*/
static int
kmt_amd_branches(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	intptr_t cpuid = DPI_MASTER_CPUID;

	if (kmt_cpu_amd.amd_msrs == kmt_amdunk_msrs) {
		warn("branch tracing unavailable on unknown AMD CPU "
		    "(id: %x/%x)\n", kmt_cpu_amd.amd_family,
		    kmt_cpu_amd.amd_model);
		return (DCMD_ERR);
	}

	if (mdb_getopts(argc, argv,
	    'c', MDB_OPT_UINTPTR, &cpuid,
	    NULL) != argc)
		return (DCMD_USAGE);

	kmt_amd_branch(cpuid, "LastBranchToIP     ", MSR_LBR_TO);
	kmt_amd_branch(cpuid, "LastBranchFromIP   ", MSR_LBR_FROM);
	kmt_amd_branch(cpuid, "LastExceptionToIP  ", MSR_LEX_TO);
	kmt_amd_branch(cpuid, "LastExceptionFromIP", MSR_LEX_FROM);

	return (0);
}

static const mdb_dcmd_t kmt_amd_dcmds[] = {
	{ "branches", NULL, "describe the recently-taken branches",
	    kmt_amd_branches },
	{ NULL }
};

kmt_cpu_t *
kmt_cpu_amd_create(mdb_tgt_t *t)
{
	uint_t vendor, family, model;
	kmt_cpu_t *cpu;

	if (kmdb_kdi_get_cpuinfo(&vendor, &family, &model) < 0)
		return (NULL); /* errno is set for us */

	if (vendor != X86_VENDOR_AMD) {
		(void) set_errno(ENOTSUP);
		return (NULL);
	}

	kmt_cpu_amd.amd_family = family;
	kmt_cpu_amd.amd_model = model;
	kmt_cpu_amd.amd_msrs = kmt_amdunk_msrs;
	kmt_cpu_amd.amd_debugctl = DEBUGCTL_LBR; /* Enable LBR on resume */

	cpu = mdb_zalloc(sizeof (kmt_cpu_t), UM_SLEEP);
	cpu->kmt_cpu_ops = &kmt_amd_ops;
	cpu->kmt_cpu_data = &kmt_cpu_amd;

	/*
	 * Use the LBR/LEX MSRs if this CPU supports them.
	 */
	if (kmt_msr_validate(kmt_amd_msrs))
		kmt_cpu_amd.amd_msrs = kmt_amd_msrs;

	(void) mdb_tgt_register_dcmds(t, kmt_amd_dcmds, MDB_MOD_FORCE);
	kmdb_dpi_msr_add(kmt_cpu_amd.amd_msrs);

	return (cpu);
}
