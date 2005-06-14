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
 * SPARC-specific portions of the debugger fault routines
 */

#include <sys/types.h>
#include <sys/stack.h>
#include <sys/frame.h>
#include <sys/machtrap.h>
#include <sys/machasi.h>
#include <sys/sun4asi.h>
#include <sys/intreg.h>
#include <sys/mmu.h>

#include <kmdb/kmdb_asmutil.h>
#include <kmdb/kmdb_fault.h>
#include <mdb/mdb_io.h>
#include <mdb/mdb.h>

#define	MAX_STACK_FRAMES	30

static void
print_frame(uintptr_t sp, uintptr_t pc, int fnum, int safe)
{
	if (safe) {
		mdb_iob_printf(mdb.m_err, "    [%2d] %?p %?p()\n",
		    fnum, sp, pc);
	} else {
		mdb_iob_printf(mdb.m_err, "    [%2d] %?p %a()\n",
		    fnum, sp, pc);
	}
}

static int
valid_frame(struct frame *fr)
{
	uintptr_t addr = (uintptr_t)fr;

	if (!(addr - (uintptr_t)mdb.m_dseg < mdb.m_dsegsz)) {
		mdb_iob_printf(mdb.m_err, "    frame (%p) outside of "
		    "debugger segment\n", addr);
		return (0);
	}

	if (addr & (STACK_ALIGN - 1)) {
		mdb_iob_printf(mdb.m_err, "    mis-aligned frame (%p)\n", fr);
		return (0);
	}

	return (1);
}

static void
print_stack(kreg_t sp, int safe)
{
	struct frame *fr = (struct frame *)(sp + STACK_BIAS);
	struct frame *nfr;
	int frnum = 1;

	while (fr != NULL && valid_frame(fr) && fr->fr_savpc != 0 &&
	    frnum <= MAX_STACK_FRAMES) {
		print_frame((uintptr_t)fr - STACK_BIAS, fr->fr_savpc, frnum++,
		    safe);

		nfr = (struct frame *)
		    ((uintptr_t)fr->fr_savfp + STACK_BIAS);

		if ((uintptr_t)nfr == STACK_BIAS)
			break;

		if ((uintptr_t)nfr < (uintptr_t)fr) {
			mdb_iob_printf(mdb.m_err,
			    "    fp (%p) < sp (%p)\n", nfr, fr);
			break;
		}

		fr = nfr;
	}
}

void
kmdb_print_stack(void)
{
	print_stack(get_fp(), FALSE); /* show sym names */
}

void
kmdb_fault_display(kreg_t tt, kreg_t pc, kreg_t sp, int safe)
{
	mdb_iob_printf(mdb.m_err, "    tt: %p, sp: %p, pc: %p", tt, sp, pc);
	if (!safe)
		mdb_iob_printf(mdb.m_err, " %A", pc);
	mdb_iob_printf(mdb.m_err, "\n");

	switch (tt) {
	case T_FAST_DATA_MMU_MISS: {
#ifdef sun4v
#else /* sun4v */
		uint64_t dsfar = rdasi(ASI_DMMU, MMU_SFAR);
		const char *fmt = safe ? "%s%p\n" : "%s%a\n";
		mdb_iob_printf(mdb.m_err, fmt, "\tDSFAR now: ", dsfar);
#endif /* sun4v */
		break;
	}
	case T_VECTORED_INT:
#ifdef sun4v
#else /* sun4v */
		mdb_iob_printf(mdb.m_err,
		    "\tIRDR now: 0: %lx, 1: %lx, 2: %lx\n",
		    (ulong_t)rdasi(ASI_INTR_RECEIVE, IRDR_0),
		    (ulong_t)rdasi(ASI_INTR_RECEIVE, IRDR_1),
		    (ulong_t)rdasi(ASI_INTR_RECEIVE, IRDR_2));
#endif /* sun4v */
		break;
	}

	mdb_iob_printf(mdb.m_err, "\n");

	if (mdb.m_dseg == NULL || mdb.m_dsegsz == 0) {
		mdb_iob_printf(mdb.m_err,
		    "\t*** Stack trace omitted because debugger segment size\n"
		    "\t*** and/or length not set.\n");
		return;
	}

	if (!(sp - (uintptr_t)mdb.m_dseg < mdb.m_dsegsz)) {
		mdb_iob_printf(mdb.m_err,
		    "\t*** Stack trace omitted because sp (%p) isn't in the\n"
		    "\t*** debugger segment.\n", sp);
		return;
	}

	flush_windows();

	print_stack(sp, safe);
}
