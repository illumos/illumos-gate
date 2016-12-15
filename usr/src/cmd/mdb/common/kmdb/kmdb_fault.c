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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Handling of unintentional faults (i.e. bugs) in the debugger.
 */

#include <stdlib.h>

#include <kmdb/kmdb_fault.h>
#include <kmdb/kmdb_promif.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_dpi.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_kreg.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb.h>

void
kmdb_fault(kreg_t tt, kreg_t pc, kreg_t sp, int cpuid)
{
	int debug_self_confirm = 0;
	volatile int try;
	jmp_buf pcb, *old;
	char c;

	/* Make absolutely sure */
	kmdb_kdi_system_claim();

	try = 1;
	if (setjmp(pcb) != 0) {
		if (++try == 2) {
			mdb_iob_printf(mdb.m_err,
			    "\n*** First stack trace attempt failed.  "
			    "Trying safe mode.\n\n");

			kmdb_fault_display(tt, pc, sp, 1);
		} else {
			mdb_iob_printf(mdb.m_err,
			    "\n*** Unable to print stack trace.\n");
		}

	} else {
		old = kmdb_dpi_set_fault_hdlr(&pcb);

		mdb_iob_printf(mdb.m_err, "\n*** Debugger Fault (CPU %d)\n\n",
		    cpuid);
		kmdb_fault_display(tt, pc, sp, 0);
	}

	kmdb_dpi_restore_fault_hdlr(old);

	if (mdb.m_term != NULL) {
		for (;;) {
			mdb_iob_printf(mdb.m_err, "\n%s: "
#if defined(__sparc)
#ifndef sun4v
			    "(o)bp, "
#endif /* sun4v */
			    "(p)anic"
#else
			    "reboo(t)"
#endif
			    ", or (d)ebug with self? ", mdb.m_pname);
			mdb_iob_flush(mdb.m_err);

			if (IOP_READ(mdb.m_term, &c, sizeof (c)) != sizeof (c))
				goto fault_obp;

			mdb_iob_printf(mdb.m_err, "\n");

			switch (c) {
#ifdef __sparc
			case 'p':
				kmdb_dpi_kernpanic(cpuid);
				/*NOTREACHED*/
				continue;
#endif

#ifndef sun4v
			case 'o':
			case 'O':
#endif /* sun4v */
			case 't':
			case 'T':
				kmdb_dpi_enter_mon();
				continue;

			case 'd':
			case 'D':
				/*
				 * Debug self - get confirmation, because they
				 * can't go back to their running system if
				 * they choose this one.
				 */
				if (debug_self_confirm == 0) {
					mdb_iob_printf(mdb.m_err,
					    "NOTE: You will not be able to "
					    "resume your system if you "
					    "choose this option.\nPlease "
					    "select 'd' again to confirm.\n");
					debug_self_confirm = 1;
					continue;
				}

				kmdb_dpi_set_state(DPI_STATE_LOST, 0);
				return;
			}
		}
	}

fault_obp:
	exit(1);
	/*NOTREACHED*/
}
