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

/*
 * Intel-specific portions of the DPI
 */

#include <sys/types.h>
#include <sys/trap.h>

#include <kmdb/kmdb_dpi_impl.h>
#include <kmdb/kmdb_fault.h>
#include <kmdb/kmdb_kdi.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_kreg.h>
#include <mdb/mdb.h>

void
kmdb_dpi_handle_fault(kreg_t trapno, kreg_t pc, kreg_t sp, int cpuid)
{
	kmdb_kdi_system_claim();

	mdb_dprintf(MDB_DBG_DPI, "\ndpi_handle_fault: trapno %u, pc 0x%0?p, "
	    "sp 0x%0?p\n", (int)trapno, pc, sp);

	switch (trapno) {
	case T_GPFLT:
		errno = EACCES;
	default:
		errno = EMDB_NOMAP;
	}

	if (kmdb_dpi_fault_pcb != NULL) {
		longjmp(*kmdb_dpi_fault_pcb, 1);
		/*NOTREACHED*/
	}

	/* Debugger fault */
	kmdb_fault(trapno, pc, sp, cpuid);
}

/*ARGSUSED*/
int
kmdb_dpi_get_register(const char *regname, kreg_t *kregp)
{
	return (mdb.m_dpi->dpo_get_register(regname, kregp));
}

/*ARGSUSED*/
int
kmdb_dpi_set_register(const char *regname, kreg_t kreg)
{
	return (mdb.m_dpi->dpo_set_register(regname, kreg));
}

/*
 * Continue/resume handling.  If the target calls kmdb_dpi_resume(), it
 * expects that the world will be resumed, and that the call will return
 * when the world has stopped again.
 *
 * For support, we have resume_return(), which is called from main() when
 * the continuation has completed (when the world has stopped again).
 * set_resume_exit() tells where to jump to actually restart the world.
 *
 * CAUTION: This routine may be called *after* mdb_destroy.
 */
void
kmdb_dpi_resume_common(int cmd)
{
	kreg_t pc, trapno;

	ASSERT(kmdb_dpi_resume_requested == 0);

	if (setjmp(kmdb_dpi_resume_pcb) == 0) {
		(void) kmdb_dpi_get_register("pc", &pc);
		mdb_dprintf(MDB_DBG_PROC, "Resume requested, pc is %p\n",
		    (void *)pc);

		if (cmd != KMDB_DPI_CMD_RESUME_UNLOAD)
			kmdb_dpi_resume_requested = 1;

		longjmp(kmdb_dpi_entry_pcb, cmd);
		/*NOTREACHED*/

	} else {
		(void) kmdb_dpi_get_register("pc", &pc);
		(void) kmdb_dpi_get_register("trapno", &trapno);
		mdb_dprintf(MDB_DBG_PROC, "Back from resume, pc: %p, "
		    "trapno: %u\n", (void *)pc, (int)trapno);

		kmdb_dpi_resume_requested = 0;

		switch (trapno) {
		case T_BPTFLT:
			kmdb_dpi_set_state(DPI_STATE_FAULTED,
			    DPI_STATE_WHY_BKPT);
			break;
		case T_DBGENTR:
			kmdb_dpi_set_state(DPI_STATE_STOPPED, 0);
			break;
		default:
			kmdb_dpi_set_state(DPI_STATE_FAULTED,
			    DPI_STATE_WHY_TRAP);
			break;
		}
	}

	mdb_dprintf(MDB_DBG_PROC, "returning from resume\n");
}

void
kmdb_dpi_reboot(void)
{
	/*
	 * We're going to skip all of the niceties we employ in resume_common,
	 * as we don't plan to ever return.
	 */
	longjmp(kmdb_dpi_entry_pcb, KMDB_DPI_CMD_REBOOT);
}
