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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Libkvm Kernel Target SPARC v9 component
 *
 * This file provides the ISA-dependent portion of the libkvm kernel target.
 * For more details on the implementation refer to mdb_kvm.c.  The SPARC v9
 * ISA code is actually compiled into *both* the sparcv7 and sparcv9 MDB
 * binaries because we need to deal with the sparcv9 CPU registers when
 * debugging a 32-bit crash dump from a kernel running on a sparcv9 CPU.
 */

#ifndef __sparcv9cpu
#define	__sparcv9cpu
#endif

#include <sys/types.h>
#include <sys/machtypes.h>
#include <sys/regset.h>
#include <sys/frame.h>
#include <sys/stack.h>
#include <sys/sysmacros.h>
#include <sys/panic.h>
#include <strings.h>

#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_disasm.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_conf.h>
#include <mdb/mdb_kreg_impl.h>
#include <mdb/mdb_v9util.h>
#include <mdb/mdb_kvm.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb.h>

#ifndef STACK_BIAS
#define	STACK_BIAS	0
#endif

static int
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
			return (0);
		}
	}

	return (set_errno(EMDB_BADREG));
}

static int
kt_putareg(mdb_tgt_t *t, mdb_tgt_tid_t tid, const char *rname, mdb_tgt_reg_t r)
{
	const mdb_tgt_regdesc_t *rdp;
	kt_data_t *kt = t->t_data;

	if (tid != kt->k_tid)
		return (set_errno(EMDB_NOREGS));

	for (rdp = kt->k_rds; rdp->rd_name != NULL; rdp++) {
		if (strcmp(rname, rdp->rd_name) == 0) {
			kt->k_regs->kregs[rdp->rd_num] = r;
			return (0);
		}
	}

	return (set_errno(EMDB_BADREG));
}

	/*
	 * - If we got a pc, invoke the call back function starting
	 *   with gsp.
	 * - If we got a saved pc (%i7), invoke the call back function
	 *   starting with the first register window.
	 * - If we got neither a pc nor a saved pc, invoke the call back
	 *   function starting with the second register window.
	 */

/*ARGSUSED*/
static int
kt_regs(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	mdb_v9printregs((const mdb_tgt_gregset_t *)addr);
	return (DCMD_OK);
}

static int
kt_stack_common(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv, mdb_tgt_stack_f *func, kreg_t saved_pc)
{
	kt_data_t *kt = mdb.m_target->t_data;
	void *arg = (void *)(uintptr_t)mdb.m_nargs;
	mdb_tgt_gregset_t gregs, *grp;

	if (flags & DCMD_ADDRSPEC) {
		bzero(&gregs, sizeof (gregs));
		gregs.kregs[KREG_FP] = addr;
		gregs.kregs[KREG_I7] = saved_pc;
		grp = &gregs;
	} else
		grp = kt->k_regs;

	if (argc != 0) {
		if (argv->a_type == MDB_TYPE_CHAR || argc > 1)
			return (DCMD_USAGE);

		if (argv->a_type == MDB_TYPE_STRING)
			arg = (void *)(uintptr_t)(uint_t)
			    mdb_strtoull(argv->a_un.a_str);
		else
			arg = (void *)(uintptr_t)(uint_t)argv->a_un.a_val;
	}

	(void) mdb_kvm_v9stack_iter(mdb.m_target, grp, func, arg);
	return (DCMD_OK);
}

static int
kt_stack(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (kt_stack_common(addr, flags, argc, argv, mdb_kvm_v9frame, 0));
}

static int
kt_stackv(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (kt_stack_common(addr, flags, argc, argv, mdb_kvm_v9framev, 0));
}

static int
kt_stackr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	/*
	 * Force printing of first register window by setting the
	 * saved pc (%i7) to PC_FAKE.
	 */
	return (kt_stack_common(addr, flags, argc, argv, mdb_kvm_v9framer,
	    PC_FAKE));
}

/*ARGSUSED*/
static int
kt_notsup(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	errno = EMDB_TGTNOTSUP;
	return (DCMD_ERR);
}

const mdb_tgt_ops_t kt_sparcv9_ops = {
	kt_setflags,				/* t_setflags */
	kt_setcontext,				/* t_setcontext */
	kt_activate,				/* t_activate */
	kt_deactivate,				/* t_deactivate */
	(void (*)()) mdb_tgt_nop,		/* t_periodic */
	kt_destroy,				/* t_destroy */
	kt_name,				/* t_name */
	(const char *(*)()) mdb_conf_isa,	/* t_isa */
	kt_platform,				/* t_platform */
	kt_uname,				/* t_uname */
	kt_dmodel,				/* t_dmodel */
	kt_aread,				/* t_aread */
	kt_awrite,				/* t_awrite */
	kt_vread,				/* t_vread */
	kt_vwrite,				/* t_vwrite */
	kt_pread,				/* t_pread */
	kt_pwrite,				/* t_pwrite */
	kt_fread,				/* t_fread */
	kt_fwrite,				/* t_fwrite */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_ioread */
	(ssize_t (*)()) mdb_tgt_notsup,		/* t_iowrite */
	kt_vtop,				/* t_vtop */
	kt_lookup_by_name,			/* t_lookup_by_name */
	kt_lookup_by_addr,			/* t_lookup_by_addr */
	kt_symbol_iter,				/* t_symbol_iter */
	kt_mapping_iter,			/* t_mapping_iter */
	kt_object_iter,				/* t_object_iter */
	kt_addr_to_map,				/* t_addr_to_map */
	kt_name_to_map,				/* t_name_to_map */
	kt_addr_to_ctf,				/* t_addr_to_ctf */
	kt_name_to_ctf,				/* t_name_to_ctf */
	kt_status,				/* t_status */
	(int (*)()) mdb_tgt_notsup,		/* t_run */
	(int (*)()) mdb_tgt_notsup,		/* t_step */
	(int (*)()) mdb_tgt_notsup,		/* t_step_out */
	(int (*)()) mdb_tgt_notsup,		/* t_next */
	(int (*)()) mdb_tgt_notsup,		/* t_cont */
	(int (*)()) mdb_tgt_notsup,		/* t_signal */
	(int (*)()) mdb_tgt_null,		/* t_add_vbrkpt */
	(int (*)()) mdb_tgt_null,		/* t_add_sbrkpt */
	(int (*)()) mdb_tgt_null,		/* t_add_pwapt */
	(int (*)()) mdb_tgt_null,		/* t_add_iowapt */
	(int (*)()) mdb_tgt_null,		/* t_add_vwapt */
	(int (*)()) mdb_tgt_null,		/* t_add_sysenter */
	(int (*)()) mdb_tgt_null,		/* t_add_sysexit */
	(int (*)()) mdb_tgt_null,		/* t_add_signal */
	(int (*)()) mdb_tgt_null,		/* t_add_fault */
	kt_getareg,				/* t_getareg */
	kt_putareg,				/* t_putareg */
	mdb_kvm_v9stack_iter,			/* t_stack_iter */
	(int (*)()) mdb_tgt_notsup		/* t_auxv */
};

void
kt_sparcv9_init(mdb_tgt_t *t)
{
	kt_data_t *kt = t->t_data;

	struct rwindow rwin;
	panic_data_t pd;
	label_t label;
	kreg_t *kregs;

	uint64_t tick;
	uint32_t pil;

	/*
	 * Initialize the machine-dependent parts of the kernel target
	 * structure.  Once this is complete and we fill in the ops
	 * vector, the target is now fully constructed and we can use
	 * the target API itself to perform the rest of our initialization.
	 */
	kt->k_rds = mdb_sparcv9_kregs;
	kt->k_regs = mdb_zalloc(sizeof (mdb_tgt_gregset_t), UM_SLEEP);
	kt->k_regsize = sizeof (mdb_tgt_gregset_t);
	kt->k_dcmd_regs = kt_regs;
	kt->k_dcmd_stack = kt_stack;
	kt->k_dcmd_stackv = kt_stackv;
	kt->k_dcmd_stackr = kt_stackr;
	kt->k_dcmd_cpustack = kt_notsup;
	kt->k_dcmd_cpuregs = kt_notsup;

	t->t_ops = &kt_sparcv9_ops;
	kregs = kt->k_regs->kregs;

	(void) mdb_dis_select("v9plus");

	/*
	 * Don't attempt to load any thread or register information if
	 * we're examining the live operating system.
	 */
	if (strcmp(kt->k_symfile, "/dev/ksyms") == 0)
		return;

	/*
	 * If the panicbuf symbol is present and we can consume a panicbuf
	 * header of the appropriate version from this address, then
	 * we can initialize our current register set based on its contents:
	 */
	if (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &pd, sizeof (pd),
	    MDB_TGT_OBJ_EXEC, "panicbuf") == sizeof (pd) &&
	    pd.pd_version == PANICBUFVERS) {

		size_t pd_size = MIN(PANICBUFSIZE, pd.pd_msgoff);
		panic_data_t *pdp = mdb_zalloc(pd_size, UM_SLEEP);
		uint_t i, n;

		(void) mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, pdp, pd_size,
		    MDB_TGT_OBJ_EXEC, "panicbuf");

		n = (pd_size - (sizeof (panic_data_t) -
		    sizeof (panic_nv_t))) / sizeof (panic_nv_t);

		for (i = 0; i < n; i++) {
			const char *name = pdp->pd_nvdata[i].pnv_name;
			uint64_t value = pdp->pd_nvdata[i].pnv_value;

			if (strcmp(name, "tstate") == 0) {
				kregs[KREG_CCR] = KREG_TSTATE_CCR(value);
				kregs[KREG_ASI] = KREG_TSTATE_ASI(value);
				kregs[KREG_PSTATE] = KREG_TSTATE_PSTATE(value);
				kregs[KREG_CWP] = KREG_TSTATE_CWP(value);
			} else
				(void) kt_putareg(t, kt->k_tid, name, value);
		}

		mdb_free(pdp, pd_size);
	}

	/*
	 * Prior to the re-structuring of panicbuf, our only register data
	 * was the panic_regs label_t, into which a setjmp() was performed.
	 */
	if (kregs[KREG_PC] == 0 && kregs[KREG_SP] == 0 &&
	    mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &label, sizeof (label),
	    MDB_TGT_OBJ_EXEC, "panic_regs") == sizeof (label)) {

		kregs[KREG_PC] = label.val[0];
		kregs[KREG_SP] = label.val[1];
	}

	/*
	 * If we can read a saved register window from the stack at %sp,
	 * we can also fill in the locals and inputs.
	 */
	if (kregs[KREG_SP] != 0 && mdb_tgt_vread(t, &rwin, sizeof (rwin),
	    kregs[KREG_SP] + STACK_BIAS) == sizeof (rwin)) {

		kregs[KREG_L0] = rwin.rw_local[0];
		kregs[KREG_L1] = rwin.rw_local[1];
		kregs[KREG_L2] = rwin.rw_local[2];
		kregs[KREG_L3] = rwin.rw_local[3];
		kregs[KREG_L4] = rwin.rw_local[4];
		kregs[KREG_L5] = rwin.rw_local[5];
		kregs[KREG_L6] = rwin.rw_local[6];
		kregs[KREG_L7] = rwin.rw_local[7];

		kregs[KREG_I0] = rwin.rw_in[0];
		kregs[KREG_I1] = rwin.rw_in[1];
		kregs[KREG_I2] = rwin.rw_in[2];
		kregs[KREG_I3] = rwin.rw_in[3];
		kregs[KREG_I4] = rwin.rw_in[4];
		kregs[KREG_I5] = rwin.rw_in[5];
		kregs[KREG_I6] = rwin.rw_in[6];
		kregs[KREG_I7] = rwin.rw_in[7];

	} else if (kregs[KREG_SP] != 0) {
		warn("failed to read rwindow at %p -- current "
		    "frame inputs will be unavailable\n",
		    (void *)(uintptr_t)(kregs[KREG_SP] + STACK_BIAS));
	}

	/*
	 * The panic_ipl variable records the IPL of the panic CPU,
	 * which on sparcv9 is the %pil register's value.
	 */
	if (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &pil, sizeof (pil),
	    MDB_TGT_OBJ_EXEC, "panic_ipl") == sizeof (pil))
		kregs[KREG_PIL] = pil;

	/*
	 * The panic_tick variable records %tick at the approximate
	 * time of the panic in a DEBUG kernel.
	 */
	if (mdb_tgt_readsym(t, MDB_TGT_AS_VIRT, &tick, sizeof (tick),
	    MDB_TGT_OBJ_EXEC, "panic_tick") == sizeof (tick))
		kregs[KREG_TICK] = tick;
}
