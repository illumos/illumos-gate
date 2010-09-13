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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * SPARC-specific portions of the DPI
 */

#include <sys/types.h>
#include <sys/mmu.h>
#include <sys/trap.h>
#include <sys/machtrap.h>

#include <kmdb/kmdb_dpi_impl.h>
#include <kmdb/kmdb_asmutil.h>
#include <kmdb/kmdb_promif.h>
#include <kmdb/kmdb_fault.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_kreg.h>
#include <mdb/mdb.h>

void
kmdb_dpi_handle_fault(kreg_t tt, kreg_t tpc, kreg_t tnpc, kreg_t sp, int cpuid)
{
	mdb_dprintf(MDB_DBG_DPI, "\ndpi_handle_fault: tt 0x%01lx, tpc 0x%0?p, "
	    "tnpc 0x%0?p, sp 0x%0?p, fault_pcb 0x%0?p\n", tt, tpc, tnpc, sp,
	    kmdb_dpi_fault_pcb);

	switch (tt) {
	case FAST_PROT_TT:
		errno = EACCES;
		break;
	case T_DATA_ERROR:
		errno = EIO;
		break;
#ifdef sun4v
	case T_DATA_MMU_MISS:
#endif /* sun4v */
	case FAST_DMMU_MISS_TT:
	default:
		errno = EMDB_NOMAP;
	}

	if (kmdb_dpi_fault_pcb != NULL) {
		longjmp(*kmdb_dpi_fault_pcb, 1);
		/*NOTREACHED*/
	}

	/* Debugger fault */
	kmdb_fault(tt, tpc, sp, cpuid);
}

int
kmdb_dpi_get_register(const char *regname, kreg_t *kregp)
{
	return (mdb.m_dpi->dpo_get_register(regname, kregp));
}

int
kmdb_dpi_set_register(const char *regname, kreg_t kreg)
{
	return (mdb.m_dpi->dpo_set_register(regname, kreg));
}

int
kmdb_dpi_get_rwin(int cpuid, int win, struct rwindow *rwin)
{
	return (mdb.m_dpi->dpo_get_rwin(cpuid, win, rwin));
}

int
kmdb_dpi_get_nwin(int cpuid)
{
	return (mdb.m_dpi->dpo_get_nwin(cpuid));
}

void
kmdb_dpi_kernpanic(int cpuid)
{
	mdb.m_dpi->dpo_kernpanic(cpuid);
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
	kreg_t pc, tt;

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
		(void) kmdb_dpi_get_register("tt", &tt);
		mdb_dprintf(MDB_DBG_PROC, "Back from resume, pc: %p, tt: %lx\n",
		    (void *)pc, tt);

		kmdb_dpi_resume_requested = 0;

		switch (tt) {
		case T_PA_WATCHPOINT:
			kmdb_dpi_set_state(DPI_STATE_FAULTED,
			    DPI_STATE_WHY_P_WAPT);
			break;
		case T_VA_WATCHPOINT:
			kmdb_dpi_set_state(DPI_STATE_FAULTED,
			    DPI_STATE_WHY_V_WAPT);
			break;
		case ST_KMDB_BREAKPOINT|T_SOFTWARE_TRAP:
		case ST_MON_BREAKPOINT|T_SOFTWARE_TRAP: /* Shouldn't happen */
			kmdb_dpi_set_state(DPI_STATE_FAULTED,
			    DPI_STATE_WHY_BKPT);
			break;
		case ST_KMDB_TRAP|T_SOFTWARE_TRAP:
			kmdb_dpi_set_state(DPI_STATE_STOPPED, 0);
			break;
		default:
			kmdb_dpi_set_state(DPI_STATE_FAULTED,
			    DPI_STATE_WHY_TRAP);
			break;
		}
	}
}
