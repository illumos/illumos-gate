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
 * Intel-specific portions of the debugger fault routines
 */

#include <sys/types.h>
#include <sys/stack.h>
#include <sys/frame.h>

#include <kmdb/kmdb_fault.h>
#include <kmdb/kmdb_asmutil.h>
#include <mdb/mdb_kreg.h>
#include <mdb/mdb.h>

#define	MAX_STACK_FRAMES	30

static void
print_frame(uintptr_t pc, int fnum, int safe)
{
	if (safe) {
		/*
		 * We exploded the first time around, so we want to try again,
		 * this time without symbol names
		 */
		mdb_iob_printf(mdb.m_err, "    [%2d] %?p()\n", fnum, pc);
	} else {
		mdb_iob_printf(mdb.m_err, "    [%2d] %?p %A()\n", fnum, pc, pc);
	}
}

static int
valid_frame(struct frame *fr)
{
	uintptr_t addr = (uintptr_t)fr;

	if (addr & (STACK_ALIGN - 1)) {
		mdb_iob_printf(mdb.m_err, "    mis-aligned frame (%p)\n", fr);
		return (0);
	}

	return (1);
}

static void
print_stack(kreg_t sp, int safe)
{
	struct frame *fr = (struct frame *)sp;
	int frnum = 1;

	while (fr != NULL && valid_frame(fr) && fr->fr_savpc != 0 &&
	    frnum < MAX_STACK_FRAMES) {
		print_frame(fr->fr_savpc, frnum, safe);

		fr = (struct frame *)fr->fr_savfp;
		frnum++;
	}
}

void
kmdb_print_stack(void)
{
	print_stack(get_fp(), FALSE); /* show sym names */
}

void
kmdb_fault_display(kreg_t trapno, kreg_t pc, kreg_t sp, int safe)
{
	mdb_iob_printf(mdb.m_err, "    trapno: %d, sp: %p, pc: %p", trapno,
	    sp, pc);
	if (!safe)
		mdb_iob_printf(mdb.m_err, " %A", pc);
	mdb_iob_printf(mdb.m_err, "\n\n");

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

	/*
	 * We were on a kmdb stack when we took this fault.  We're going to
	 * assume that there's nothing weird on the stack, and that, therefore,
	 * we can use a simple algorithm to dump it.
	 */

	print_stack(sp, safe);
}
