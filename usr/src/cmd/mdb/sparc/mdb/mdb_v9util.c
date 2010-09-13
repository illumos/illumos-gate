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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines common to the kvm target and the kmdb target that manipulate
 * registers.  This includes register dumps, registers as named variables,
 * and stack traces.
 */

#include <sys/types.h>
#include <sys/stack.h>
#include <sys/regset.h>

#ifndef	__sparcv9cpu
#define	__sparcv9cpu
#endif

#include <mdb/mdb_debug.h>
#include <mdb/mdb_modapi.h>
#include <mdb/mdb_v9util.h>
#include <mdb/mdb_target_impl.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

#include <mdb/mdb_kreg_impl.h>

/*
 * We also define an array of register names and their corresponding
 * array indices.  This is used by the getareg and putareg entry points,
 * and also by our register variable discipline.
 */
const mdb_tgt_regdesc_t mdb_sparcv9_kregs[] = {
	{ "g0", KREG_G0, MDB_TGT_R_EXPORT },
	{ "g1", KREG_G1, MDB_TGT_R_EXPORT },
	{ "g2", KREG_G2, MDB_TGT_R_EXPORT },
	{ "g3", KREG_G3, MDB_TGT_R_EXPORT },
	{ "g4", KREG_G4, MDB_TGT_R_EXPORT },
	{ "g5", KREG_G5, MDB_TGT_R_EXPORT },
	{ "g6", KREG_G6, MDB_TGT_R_EXPORT },
	{ "g7", KREG_G7, MDB_TGT_R_EXPORT },
	{ "o0", KREG_O0, MDB_TGT_R_EXPORT },
	{ "o1", KREG_O1, MDB_TGT_R_EXPORT },
	{ "o2", KREG_O2, MDB_TGT_R_EXPORT },
	{ "o3", KREG_O3, MDB_TGT_R_EXPORT },
	{ "o4", KREG_O4, MDB_TGT_R_EXPORT },
	{ "o5", KREG_O5, MDB_TGT_R_EXPORT },
	{ "o6", KREG_O6, MDB_TGT_R_EXPORT },
	{ "o7", KREG_O7, MDB_TGT_R_EXPORT },
	{ "l0", KREG_L0, MDB_TGT_R_EXPORT },
	{ "l1", KREG_L1, MDB_TGT_R_EXPORT },
	{ "l2", KREG_L2, MDB_TGT_R_EXPORT },
	{ "l3", KREG_L3, MDB_TGT_R_EXPORT },
	{ "l4", KREG_L4, MDB_TGT_R_EXPORT },
	{ "l5", KREG_L5, MDB_TGT_R_EXPORT },
	{ "l6", KREG_L6, MDB_TGT_R_EXPORT },
	{ "l7", KREG_L7, MDB_TGT_R_EXPORT },
	{ "i0", KREG_I0, MDB_TGT_R_EXPORT },
	{ "i1", KREG_I1, MDB_TGT_R_EXPORT },
	{ "i2", KREG_I2, MDB_TGT_R_EXPORT },
	{ "i3", KREG_I3, MDB_TGT_R_EXPORT },
	{ "i4", KREG_I4, MDB_TGT_R_EXPORT },
	{ "i5", KREG_I5, MDB_TGT_R_EXPORT },
	{ "i6", KREG_I6, MDB_TGT_R_EXPORT },
	{ "i7", KREG_I7, MDB_TGT_R_EXPORT },
	{ "ccr", KREG_CCR, MDB_TGT_R_EXPORT },
	{ "pc", KREG_PC, MDB_TGT_R_EXPORT },
	{ "npc", KREG_NPC, MDB_TGT_R_EXPORT },
	{ "y", KREG_Y, 0 },
	{ "asi", KREG_ASI, MDB_TGT_R_EXPORT },
	{ "fprs", KREG_FPRS, MDB_TGT_R_EXPORT },
	{ "tick", KREG_TICK, MDB_TGT_R_EXPORT },
	{ "stick", KREG_STICK, MDB_TGT_R_EXPORT },
	{ "pstate", KREG_PSTATE, MDB_TGT_R_PRIV | MDB_TGT_R_EXPORT },
	{ "tl", KREG_TL, MDB_TGT_R_PRIV | MDB_TGT_R_EXPORT },
	{ "tt", KREG_TT, MDB_TGT_R_PRIV | MDB_TGT_R_EXPORT },
	{ "pil", KREG_PIL, MDB_TGT_R_PRIV | MDB_TGT_R_EXPORT },
	{ "tba", KREG_TBA, MDB_TGT_R_PRIV | MDB_TGT_R_EXPORT },
	{ "ver", KREG_VER, MDB_TGT_R_PRIV | MDB_TGT_R_EXPORT },
	{ "cwp", KREG_CWP, MDB_TGT_R_PRIV | MDB_TGT_R_EXPORT },
	{ "cansave", KREG_CANSAVE, MDB_TGT_R_PRIV },
	{ "canrestore", KREG_CANRESTORE, MDB_TGT_R_PRIV },
	{ "otherwin", KREG_OTHERWIN, MDB_TGT_R_PRIV },
	{ "wstate", KREG_WSTATE, MDB_TGT_R_PRIV },
	{ "cleanwin", KREG_CLEANWIN, MDB_TGT_R_PRIV },
	{ "sp", KREG_SP, MDB_TGT_R_EXPORT | MDB_TGT_R_ALIAS },
	{ "fp", KREG_FP, MDB_TGT_R_EXPORT | MDB_TGT_R_ALIAS },
	{ NULL, 0, 0 }
};

static const char *
pstate_mm_to_str(kreg_t pstate)
{
	if (KREG_PSTATE_MM_TSO(pstate))
		return ("TSO");

	if (KREG_PSTATE_MM_PSO(pstate))
		return ("PSO");

	if (KREG_PSTATE_MM_RMO(pstate))
		return ("RMO");

	return ("???");
}

void
mdb_v9printregs(const mdb_tgt_gregset_t *gregs)
{
	const kreg_t *kregs = gregs->kregs;

#define	GETREG2(x) ((uintptr_t)kregs[(x)]), ((uintptr_t)kregs[(x)])

	mdb_printf("%%g0 = 0x%0?p %15A %%l0 = 0x%0?p %A\n",
	    GETREG2(KREG_G0), GETREG2(KREG_L0));

	mdb_printf("%%g1 = 0x%0?p %15A %%l1 = 0x%0?p %A\n",
	    GETREG2(KREG_G1), GETREG2(KREG_L1));

	mdb_printf("%%g2 = 0x%0?p %15A %%l2 = 0x%0?p %A\n",
	    GETREG2(KREG_G2), GETREG2(KREG_L2));

	mdb_printf("%%g3 = 0x%0?p %15A %%l3 = 0x%0?p %A\n",
	    GETREG2(KREG_G3), GETREG2(KREG_L3));

	mdb_printf("%%g4 = 0x%0?p %15A %%l4 = 0x%0?p %A\n",
	    GETREG2(KREG_G4), GETREG2(KREG_L4));

	mdb_printf("%%g5 = 0x%0?p %15A %%l5 = 0x%0?p %A\n",
	    GETREG2(KREG_G5), GETREG2(KREG_L5));

	mdb_printf("%%g6 = 0x%0?p %15A %%l6 = 0x%0?p %A\n",
	    GETREG2(KREG_G6), GETREG2(KREG_L6));

	mdb_printf("%%g7 = 0x%0?p %15A %%l7 = 0x%0?p %A\n\n",
	    GETREG2(KREG_G7), GETREG2(KREG_L7));

	mdb_printf("%%o0 = 0x%0?p %15A %%i0 = 0x%0?p %A\n",
	    GETREG2(KREG_O0), GETREG2(KREG_I0));

	mdb_printf("%%o1 = 0x%0?p %15A %%i1 = 0x%0?p %A\n",
	    GETREG2(KREG_O1), GETREG2(KREG_I1));

	mdb_printf("%%o2 = 0x%0?p %15A %%i2 = 0x%0?p %A\n",
	    GETREG2(KREG_O2), GETREG2(KREG_I2));

	mdb_printf("%%o3 = 0x%0?p %15A %%i3 = 0x%0?p %A\n",
	    GETREG2(KREG_O3), GETREG2(KREG_I3));

	mdb_printf("%%o4 = 0x%0?p %15A %%i4 = 0x%0?p %A\n",
	    GETREG2(KREG_O4), GETREG2(KREG_I4));

	mdb_printf("%%o5 = 0x%0?p %15A %%i5 = 0x%0?p %A\n",
	    GETREG2(KREG_O5), GETREG2(KREG_I5));

	mdb_printf("%%o6 = 0x%0?p %15A %%i6 = 0x%0?p %A\n",
	    GETREG2(KREG_O6), GETREG2(KREG_I6));

	mdb_printf("%%o7 = 0x%0?p %15A %%i7 = 0x%0?p %A\n\n",
	    GETREG2(KREG_O7), GETREG2(KREG_I7));

	mdb_printf(" %%ccr = 0x%02llx "
	    "xcc=%c%c%c%c icc=%c%c%c%c\n", kregs[KREG_CCR],
	    (kregs[KREG_CCR] & KREG_CCR_XCC_N_MASK) ? 'N' : 'n',
	    (kregs[KREG_CCR] & KREG_CCR_XCC_Z_MASK) ? 'Z' : 'z',
	    (kregs[KREG_CCR] & KREG_CCR_XCC_V_MASK) ? 'V' : 'v',
	    (kregs[KREG_CCR] & KREG_CCR_XCC_C_MASK) ? 'C' : 'c',
	    (kregs[KREG_CCR] & KREG_CCR_ICC_N_MASK) ? 'N' : 'n',
	    (kregs[KREG_CCR] & KREG_CCR_ICC_Z_MASK) ? 'Z' : 'z',
	    (kregs[KREG_CCR] & KREG_CCR_ICC_V_MASK) ? 'V' : 'v',
	    (kregs[KREG_CCR] & KREG_CCR_ICC_C_MASK) ? 'C' : 'c');

	mdb_printf("%%fprs = 0x%02llx "
	    "fef=%llu du=%llu dl=%llu\n", kregs[KREG_FPRS],
	    (kregs[KREG_FPRS] & KREG_FPRS_FEF_MASK) >> KREG_FPRS_FEF_SHIFT,
	    (kregs[KREG_FPRS] & KREG_FPRS_DU_MASK) >> KREG_FPRS_DU_SHIFT,
	    (kregs[KREG_FPRS] & KREG_FPRS_DL_MASK) >> KREG_FPRS_DL_SHIFT);

	mdb_printf(" %%asi = 0x%02llx\n", kregs[KREG_ASI]);
	mdb_printf("   %%y = 0x%0?p\n", (uintptr_t)kregs[KREG_Y]);

	mdb_printf("  %%pc = 0x%0?p %A\n", GETREG2(KREG_PC));
	mdb_printf(" %%npc = 0x%0?p %A\n", GETREG2(KREG_NPC));

#if STACK_BIAS != 0
	mdb_printf("  %%sp = 0x%0?p unbiased=0x%0?p\n",
	    (uintptr_t)kregs[KREG_SP], (uintptr_t)kregs[KREG_SP] + STACK_BIAS);
#else
	mdb_printf("  %%sp = 0x%0?p\n", (uintptr_t)kregs[KREG_SP]);
#endif
	mdb_printf("  %%fp = 0x%0?p\n\n", (uintptr_t)kregs[KREG_FP]);

	mdb_printf("  %%tick = 0x%016llx\n", kregs[KREG_TICK]);
	if (gregs->kreg_flags & MDB_V9GREG_F_STICK_VALID)
		mdb_printf(" %%stick = 0x%016llx\n", kregs[KREG_STICK]);
	mdb_printf("   %%tba = 0x%016llx\n", kregs[KREG_TBA]);
	mdb_printf("    %%tt = 0x%01llx\n", kregs[KREG_TT]);
	mdb_printf("    %%tl = 0x%01llx\n", kregs[KREG_TL]);
	mdb_printf("   %%pil = 0x%01llx\n", kregs[KREG_PIL]);

	mdb_printf("%%pstate = 0x%03llx cle=%llu tle=%llu mm=%s"
	    " red=%llu pef=%llu am=%llu priv=%llu ie=%llu ag=%llu\n\n",
	    kregs[KREG_PSTATE],
	    (kregs[KREG_PSTATE] & KREG_PSTATE_CLE_MASK) >>
	    KREG_PSTATE_CLE_SHIFT,
	    (kregs[KREG_PSTATE] & KREG_PSTATE_TLE_MASK) >>
	    KREG_PSTATE_TLE_SHIFT, pstate_mm_to_str(kregs[KREG_PSTATE]),
	    (kregs[KREG_PSTATE] & KREG_PSTATE_RED_MASK) >>
	    KREG_PSTATE_RED_SHIFT,
	    (kregs[KREG_PSTATE] & KREG_PSTATE_PEF_MASK) >>
	    KREG_PSTATE_PEF_SHIFT,
	    (kregs[KREG_PSTATE] & KREG_PSTATE_AM_MASK) >> KREG_PSTATE_AM_SHIFT,
	    (kregs[KREG_PSTATE] & KREG_PSTATE_PRIV_MASK) >>
	    KREG_PSTATE_PRIV_SHIFT,
	    (kregs[KREG_PSTATE] & KREG_PSTATE_IE_MASK) >> KREG_PSTATE_IE_SHIFT,
	    (kregs[KREG_PSTATE] & KREG_PSTATE_AG_MASK) >> KREG_PSTATE_AG_SHIFT);

	mdb_printf("       %%cwp = 0x%02llx  %%cansave = 0x%02llx\n",
	    kregs[KREG_CWP], kregs[KREG_CANSAVE]);

	mdb_printf("%%canrestore = 0x%02llx %%otherwin = 0x%02llx\n",
	    kregs[KREG_CANRESTORE], kregs[KREG_OTHERWIN]);

	mdb_printf("    %%wstate = 0x%02llx %%cleanwin = 0x%02llx\n",
	    kregs[KREG_WSTATE], kregs[KREG_CLEANWIN]);
}

int
mdb_kvm_v9stack_iter(mdb_tgt_t *t, const mdb_tgt_gregset_t *gsp,
    mdb_tgt_stack_f *func, void *arg)
{
	mdb_tgt_gregset_t gregs;
	kreg_t *kregs = &gregs.kregs[0];
	int got_pc = (gsp->kregs[KREG_PC] != 0);

	struct rwindow rwin;
	uintptr_t sp;
	long argv[6];
	int i;

	/*
	 * - If we got a pc, invoke the call back function starting
	 *   with gsp.
	 * - If we got a saved pc (%i7), invoke the call back function
	 *   starting with the first register window.
	 * - If we got neither a pc nor a saved pc, invoke the call back
	 *   function starting with the second register window.
	 */

	bcopy(gsp, &gregs, sizeof (gregs));

	for (;;) {
		for (i = 0; i < 6; i++)
			argv[i] = kregs[KREG_I0 + i];

		if (got_pc && func(arg, kregs[KREG_PC], 6, argv, &gregs) != 0)
			break;

		kregs[KREG_PC] = kregs[KREG_I7];
		kregs[KREG_NPC] = kregs[KREG_PC] + 4;

		bcopy(&kregs[KREG_I0], &kregs[KREG_O0], 8 * sizeof (kreg_t));
		got_pc |= (kregs[KREG_PC] != 0);

		if ((sp = kregs[KREG_FP] + STACK_BIAS) == STACK_BIAS || sp == 0)
			break; /* Stop if we're at the end of the stack */

		if (sp & (STACK_ALIGN - 1))
			return (set_errno(EMDB_STKALIGN));

		if (mdb_tgt_vread(t, &rwin, sizeof (rwin), sp) != sizeof (rwin))
			return (-1); /* Failed to read frame */

		for (i = 0; i < 8; i++)
			kregs[KREG_L0 + i] = (uintptr_t)rwin.rw_local[i];
		for (i = 0; i < 8; i++)
			kregs[KREG_I0 + i] = (uintptr_t)rwin.rw_in[i];
	}

	return (0);
}

/*ARGSUSED*/
int
mdb_kvm_v9frame(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs)
{
	argc = MIN(argc, (uint_t)(uintptr_t)arglim);
	mdb_printf("%a(", pc);

	if (argc != 0) {
		mdb_printf("%lr", *argv++);
		for (argc--; argc != 0; argc--)
			mdb_printf(", %lr", *argv++);
	}

	mdb_printf(")\n");
	return (0);
}

int
mdb_kvm_v9framev(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs)
{
	argc = MIN(argc, (uint_t)(uintptr_t)arglim);
	mdb_printf("%0?llr %a(", gregs->kregs[KREG_SP], pc);

	if (argc != 0) {
		mdb_printf("%lr", *argv++);
		for (argc--; argc != 0; argc--)
			mdb_printf(", %lr", *argv++);
	}

	mdb_printf(")\n");
	return (0);
}

int
mdb_kvm_v9framer(void *arglim, uintptr_t pc, uint_t argc, const long *argv,
    const mdb_tgt_gregset_t *gregs)
{
	char buf[BUFSIZ];
	const kreg_t *kregs = &gregs->kregs[0];

	argc = MIN(argc, (uint_t)(uintptr_t)arglim);

	if (pc == PC_FAKE)
		mdb_printf("%<b>%0?llr% %s%</b>(", kregs[KREG_SP], "?");
	else
		mdb_printf("%<b>%0?llr% %a%</b>(", kregs[KREG_SP], pc);

	if (argc != 0) {
		mdb_printf("%lr", *argv++);
		for (argc--; argc != 0; argc--)
			mdb_printf(", %lr", *argv++);
	}

	mdb_printf(")\n");

	(void) mdb_inc_indent(2);

	mdb_printf("%%l0-%%l3: %?lr %?lr %?lr %?lr\n",
	    kregs[KREG_L0], kregs[KREG_L1], kregs[KREG_L2], kregs[KREG_L3]);

	mdb_printf("%%l4-%%l7: %?lr %?lr %?lr %?lr\n",
	    kregs[KREG_L4], kregs[KREG_L5], kregs[KREG_L6], kregs[KREG_L7]);

	if (kregs[KREG_FP] != 0 && (kregs[KREG_FP] + STACK_BIAS) != 0)
		if (mdb_dis_ins2str(mdb.m_disasm, mdb.m_target, MDB_TGT_AS_VIRT,
		    buf, sizeof (buf), kregs[KREG_I7]) != kregs[KREG_I7])
			mdb_printf("%-#25a%s\n", kregs[KREG_I7], buf);

	(void) mdb_dec_indent(2);
	mdb_printf("\n");

	return (0);
}
