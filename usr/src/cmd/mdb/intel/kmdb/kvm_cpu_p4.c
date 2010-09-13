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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This plugin supports debugging functionality unique to Intel processors based
 * on the NetBurst (P4) microarchitecture.  It also supports the Pentium M, a
 * processor which uses the P6 family code but provides a P4-style branch
 * tracing stack.
 */

#include <kmdb/kvm_cpu_impl.h>
#include <kmdb/kmdb_dpi.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kvm.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb.h>

#include <sys/x86_archext.h>

/*
 * As of this writing, Intel has three different flavors of branch stack.
 * They're essentially the same, but the MSR addresses, stack size, and access
 * methods differ.  We've got one kmt_p4_flavor_t for each type of branch
 * stack.
 */
typedef struct kmt_p4_flavor {
	const char *p4f_name;			/* name for CPU support */
	const kdi_msr_t *p4f_msrs;		/* MSR r/w list */
	int (*p4f_branches)(const struct kmt_p4_flavor *, uint_t,
	    intptr_t, int);			/* dumper for CPU branch stk */
	uint_t p4f_msr_tos;			/* branch stk index MSR */
	uint_t p4f_lbrstk_from_base;		/* low "from" branch stk MSR */
	uint_t p4f_lbrstk_to_base;		/* low "to" branch stk MSR */
	size_t p4f_lbrstk_num;			/* number of entries in stk */
} kmt_p4_flavor_t;

typedef struct kmt_cpu_p4 {
	uint64_t p4_debugctl;			/* value for debugctl MSR */
	const kmt_p4_flavor_t *p4_flavor;	/* parameters for this proc */
	uint_t p4_model;			/* CPUID model */
} kmt_cpu_p4_t;

/* See 07/04 AP-485 Intel Processor Identification and the CPUID Instruction */
#define	KMT_CPU_FAMILY_P6	0x6	/* For this plugin, the Pentium M */
#define	KMT_CPU_FAMILY_P4	0xf	/* "Netburst" CPUs (P4s) */
#define	KMT_CPU_MODEL_PM_9	0x9	/* Pentium M, model 9 */
#define	KMT_CPU_MODEL_PM_D	0xd	/* Pentium M, model d */


static kmt_cpu_p4_t kmt_cpu_p4;

static void
kmt_p4_branch(uintptr_t from, uintptr_t to, int verbose)
{
	if (verbose) {
		uintptr_t addr = mdb_dis_previns(mdb.m_disasm, mdb.m_target,
		    MDB_TGT_AS_VIRT, from, 3);

		mdb_printf("%<b>%-39a %-39a%</b>\n", from, to);

		while (addr <= from) {
			char buf[80];
			uintptr_t next;
			char *c;

			if ((next = mdb_dis_ins2str(mdb.m_disasm, mdb.m_target,
			    MDB_TGT_AS_VIRT, buf, sizeof (buf), addr)) == addr)
				(void) strcpy(buf, "???");

			for (c = buf + strlen(buf) - 1;
			    c > buf && (*c == ' ' || *c == '\t');
			    c--)
			;

			if (*c == '>') {
				while (c > buf && *c != '<')
					c--;

				if (*c == '<')
					*c = '\0';
			}

			if (addr == from) {
				mdb_printf("\t%<b>%-#32a%8T%s%</b>\n",
				    addr, buf);
			} else {
				mdb_printf("\t%-#32a%8T%s\n", addr, buf);
			}

			if (next == addr)
				break;

			addr = next;
		}
		mdb_printf("\n");
	} else {
		mdb_printf("%-39a %-39a\n", from, to);
	}
}

#ifndef __amd64
static int
kmt_p4_branches_unified(const kmt_p4_flavor_t *p4f, uint_t tos, intptr_t cpuid,
    int verbose)
{
	uint_t cur;
	int i;

	for (cur = tos, i = 0; i < p4f->p4f_lbrstk_num;
	    i++, cur = (cur + p4f->p4f_lbrstk_num - 1) % p4f->p4f_lbrstk_num) {
		uint64_t rec = kmdb_dpi_msr_get_by_cpu(cpuid,
		    p4f->p4f_lbrstk_from_base + cur);

		kmt_p4_branch((rec & 0xffffffff), rec >> 32, verbose);
	}

	return (0);
}
#endif	/* !__amd64 */

static int
kmt_p4_branches_split(const kmt_p4_flavor_t *p4f, uint_t tos, intptr_t cpuid,
    int verbose)
{
	uint_t cur;
	int i;

	for (cur = tos, i = 0; i < p4f->p4f_lbrstk_num;
	    i++, cur = (cur + p4f->p4f_lbrstk_num - 1) % p4f->p4f_lbrstk_num) {
		uintptr_t from = (uintptr_t)kmdb_dpi_msr_get_by_cpu(cpuid,
		    p4f->p4f_lbrstk_from_base + cur);
		uintptr_t to = (uintptr_t)kmdb_dpi_msr_get_by_cpu(cpuid,
		    p4f->p4f_lbrstk_to_base + cur);

		kmt_p4_branch(from, to, verbose);
	}

	return (0);
}

#ifndef __amd64
static const kdi_msr_t kmt_p4orig_msrs[] = {
	{ MSR_DEBUGCTL,		KDI_MSR_CLEARENTRY },
	{ MSR_DEBUGCTL,		KDI_MSR_WRITEDELAY, &kmt_cpu_p4.p4_debugctl },
	{ MSR_P4_LBSTK_TOS,	KDI_MSR_READ },
	{ MSR_P4_LBSTK_0,	KDI_MSR_READ },
	{ MSR_P4_LBSTK_1,	KDI_MSR_READ },
	{ MSR_P4_LBSTK_2,	KDI_MSR_READ },
	{ MSR_P4_LBSTK_3,	KDI_MSR_READ },
	{ NULL }
};

static const kmt_p4_flavor_t kmt_p4_original = {
	"Intel Pentium 4 (pre-Prescott)",
	kmt_p4orig_msrs, kmt_p4_branches_unified, MSR_P4_LBSTK_TOS,
	MSR_P4_LBSTK_0, MSR_P4_LBSTK_0, 4
};

static const kdi_msr_t kmt_p6m_msrs[] = {
	{ MSR_DEBUGCTL,		KDI_MSR_CLEARENTRY },
	{ MSR_DEBUGCTL,		KDI_MSR_WRITEDELAY, &kmt_cpu_p4.p4_debugctl },
	{ MSR_P6M_LBSTK_TOS,	KDI_MSR_READ },
	{ MSR_P6M_LBSTK_0,	KDI_MSR_READ },
	{ MSR_P6M_LBSTK_1,	KDI_MSR_READ },
	{ MSR_P6M_LBSTK_2,	KDI_MSR_READ },
	{ MSR_P6M_LBSTK_3,	KDI_MSR_READ },
	{ MSR_P6M_LBSTK_4,	KDI_MSR_READ },
	{ MSR_P6M_LBSTK_5,	KDI_MSR_READ },
	{ MSR_P6M_LBSTK_6,	KDI_MSR_READ },
	{ MSR_P6M_LBSTK_7,	KDI_MSR_READ },
	{ NULL }
};

static const kmt_p4_flavor_t kmt_p6_m = {
	"Intel Pentium M",
	kmt_p6m_msrs, kmt_p4_branches_unified, MSR_P6M_LBSTK_TOS,
	MSR_P6M_LBSTK_0, MSR_P6M_LBSTK_0, 8
};
#endif	/* __amd64 */

static const kdi_msr_t kmt_prp4_msrs[] = {
	{ MSR_DEBUGCTL,		KDI_MSR_CLEARENTRY },
	{ MSR_DEBUGCTL,		KDI_MSR_WRITEDELAY, &kmt_cpu_p4.p4_debugctl },
	{ MSR_PRP4_LBSTK_TOS,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_0, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_1, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_2, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_3, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_4, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_5, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_6, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_7, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_8, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_9, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_10, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_11, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_12, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_13, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_14, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_FROM_15, KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_0,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_1,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_2,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_3,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_4,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_5,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_6,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_7,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_8,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_9,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_10,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_11,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_12,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_13,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_14,	KDI_MSR_READ },
	{ MSR_PRP4_LBSTK_TO_15,	KDI_MSR_READ },
	{ NULL }
};

static const kmt_p4_flavor_t kmt_p4_prescott = {
	"Intel Pentium 4 (Prescott)",
	kmt_prp4_msrs, kmt_p4_branches_split, MSR_PRP4_LBSTK_TOS,
	MSR_PRP4_LBSTK_FROM_0, MSR_PRP4_LBSTK_TO_0, 16
};

static const kdi_msr_t kmt_p4unk_msrs[] = {
	{ MSR_DEBUGCTL,		KDI_MSR_CLEARENTRY },
	{ MSR_DEBUGCTL,		KDI_MSR_WRITEDELAY, &kmt_cpu_p4.p4_debugctl },
	{ NULL }
};

static const kmt_p4_flavor_t kmt_p4_unknown = {
	"Unrecognized Intel Pentium 4",
	kmt_p4unk_msrs, NULL, 0,
	0, 0, 0
};

/*ARGSUSED*/
static void
kmt_p4_destroy(kmt_cpu_t *cpu)
{
	/* Leave LBR on */

	mdb_free(cpu, sizeof (kmt_cpu_t));
}

/*ARGSUSED*/
static const char *
kmt_p4_name(kmt_cpu_t *cpu)
{
	return (kmt_cpu_p4.p4_flavor->p4f_name);
}

/*ARGSUSED*/
static void
kmt_p4_btf_clear(mdb_tgt_t *t, int id, void *arg)
{
	kmt_cpu_p4_t *p4 = arg;
	kreg_t efl;

	p4->p4_debugctl &= ~DEBUGCTL_BTF;

	(void) kmdb_dpi_get_register("eflags", &efl);
	efl &= ~(1 << KREG_EFLAGS_TF_SHIFT);
	(void) kmdb_dpi_set_register("eflags", efl);
}

static int
kmt_p4_step_branch(kmt_cpu_t *cpu, mdb_tgt_t *t)
{
	kmt_cpu_p4_t *p4 = cpu->kmt_cpu_data;
	kreg_t efl;

	(void) kmdb_dpi_get_register("eflags", &efl);
	(void) kmdb_dpi_set_register("eflags",
	    (efl | (1 << KREG_EFLAGS_TF_SHIFT)));

	p4->p4_debugctl |= DEBUGCTL_BTF;

	return (mdb_tgt_add_fault(t, KMT_TRAP_ALL,
	    MDB_TGT_SPEC_HIDDEN | MDB_TGT_SPEC_TEMPORARY,
	    kmt_p4_btf_clear, p4));
}

static kmt_cpu_ops_t kmt_p4_ops = {
	kmt_p4_destroy,
	kmt_p4_name,
	kmt_p4_step_branch
};

/*ARGSUSED*/
static int
kmt_p4_branches(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	const kmt_p4_flavor_t *p4f = kmt_cpu_p4.p4_flavor;
	intptr_t cpuid = DPI_MASTER_CPUID;
	uint_t tos;
	int verbose = FALSE;

	if (p4f->p4f_branches == NULL) {
		warn("branch tracing unavailable on unknown P4 CPU "
		    "(model %x)\n", kmt_cpu_p4.p4_model);
		return (DCMD_ERR);
	}

	if (mdb_getopts(argc, argv,
	    'c', MDB_OPT_UINTPTR, &cpuid,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose,
	    NULL) != argc)
		return (DCMD_USAGE);

	ASSERT(!(p4f->p4f_lbrstk_num & (p4f->p4f_lbrstk_num - 1)));

	tos = (uintptr_t)kmdb_dpi_msr_get_by_cpu(cpuid, p4f->p4f_msr_tos);
	tos &= p4f->p4f_lbrstk_num - 1;

	mdb_printf("%<u>%-39s %-39s%</u>\n", "FROM", "TO");

	return (p4f->p4f_branches(p4f, tos, cpuid, verbose));
}

static const mdb_dcmd_t kmt_p4_dcmds[] = {
	{ "branches", NULL, "describe the recently-taken branches",
	    kmt_p4_branches },
	{ NULL }
};

/*ARGSUSED*/
const kmt_p4_flavor_t *
cpu2flavor(uint_t vendor, uint_t family, uint_t model)
{
	if (vendor != X86_VENDOR_Intel)
		return (NULL);

#ifndef __amd64
	if (family == KMT_CPU_FAMILY_P6) {
		if (model == KMT_CPU_MODEL_PM_9 || model == KMT_CPU_MODEL_PM_D)
			return (&kmt_p6_m);
		else
			return (NULL);
	}

	if (family == KMT_CPU_FAMILY_P4 && model < 3)
		return (&kmt_p4_original);
#endif	/* !__amd64 */

	if (family == KMT_CPU_FAMILY_P4) {
		/*
		 * If this is a model 3, then we've got a Prescott.  On the
		 * other hand, this could be the future, and Intel could have
		 * released a whizzy new processor.  Users shouldn't have to
		 * wait for us to patch the debugger for each new P4 model,
		 * so we'll try to use this CPU as a Prescott.  In the past,
		 * when Intel has changed the branch stack, they've done it by
		 * moving the MSRs, returning #gp's for the old ones.  Our
		 * Prescott check will therefore be an attempt to read the
		 * Prescott MSRs.  This attempt should fail if Intel has changed
		 * the branch stack again.
		 */
		if (kmt_msr_validate(kmt_prp4_msrs))
			return (&kmt_p4_prescott);
		else
			return (&kmt_p4_unknown);
	}

	return (NULL);
}

kmt_cpu_t *
kmt_cpu_p4_create(mdb_tgt_t *t)
{
	uint_t vendor, family, model;
	kmt_cpu_t *cpu;

	if (kmdb_kdi_get_cpuinfo(&vendor, &family, &model) < 0)
		return (NULL); /* errno is set for us */

	if ((kmt_cpu_p4.p4_flavor = cpu2flavor(vendor, family, model)) ==
	    NULL) {
		(void) set_errno(ENOTSUP);
		return (NULL);
	}

	kmt_cpu_p4.p4_model = model;
	kmt_cpu_p4.p4_debugctl = DEBUGCTL_LBR; /* enable LBR on resume */

	cpu = mdb_zalloc(sizeof (kmt_cpu_t), UM_SLEEP);
	cpu->kmt_cpu_ops = &kmt_p4_ops;
	cpu->kmt_cpu_data = &kmt_cpu_p4;

	kmdb_dpi_msr_add(kmt_cpu_p4.p4_flavor->p4f_msrs);
	(void) mdb_tgt_register_dcmds(t, kmt_p4_dcmds, MDB_MOD_FORCE);

	return (cpu);
}
