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
 * genconst generates datamodel-independent constants.  Such constants
 * are enum values and constants defined via preprocessor macros.
 * Under no circumstances should this program generate structure size
 * or structure member offset information, those belong in offsets.in.
 */

#ifndef	_GENASSYM
#define	_GENASSYM
#endif

/*
 * This user program uses the kernel header files and the kernel prototype
 * for "exit" isn't appropriate for programs linked against libc so exit
 * is mapped to kern_exit by the preprocessor and an appropriate exit
 * prototype is provided after the header files are included.
 */
#define	exit	kern_exit

#include <sys/types.h>
#include <sys/param.h>
#include <sys/elf_notes.h>
#include <sys/systm.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/file.h>
#include <sys/msacct.h>

#include <sys/cpu.h>
#include <sys/cpuvar.h>
#include <sys/psr_compat.h>
#include <sys/avintr.h>
#include <sys/dtrace.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>

#undef	exit		/* unhide exit, see comment above */
extern void exit(int);

/*
 * Proactively discourage anyone from referring to structures or
 * member offsets in this program.
 */
#define	struct	struct...
#define	OFFSET	OFFSET...

int
main(int argc, char *argv[])
{
	printf("#define\tSSLEEP 0x%x\n", SSLEEP);
	printf("#define\tSRUN 0x%x\n", SRUN);
	printf("#define\tSONPROC 0x%x\n", SONPROC);

	printf("#define\tT_INTR_THREAD %d\n", T_INTR_THREAD);
	printf("#define\tTP_MSACCT 0x%x\n", TP_MSACCT);
	printf("#define\tTP_WATCHPT 0x%x\n", TP_WATCHPT);
	printf("#define\tTS_FREE 0x%x\n", TS_FREE);
	printf("#define\tTS_ZOMB 0x%x\n", TS_ZOMB);
	printf("#define\tTS_ONPROC 0x%x\n", TS_ONPROC);
	printf("#define\tNSYSCALL %d\n", NSYSCALL);

	printf("#define\tSE_64RVAL 0x%x\n", SE_64RVAL);
	printf("#define\tSE_32RVAL1 0x%x\n", SE_32RVAL1);
	printf("#define\tSE_32RVAL2 0x%x\n", SE_32RVAL2);

	printf("#define\tCACHE_PAC 0x%x\n", CACHE_PAC);
	printf("#define\tCACHE_VAC 0x%x\n", CACHE_VAC);
	printf("#define\tCACHE_WRITEBACK 0x%x\n", CACHE_WRITEBACK);

	printf("#define\tS_READ 0x%x\n", S_READ);
	printf("#define\tS_WRITE 0x%x\n", S_WRITE);
	printf("#define\tS_EXEC 0x%x\n", S_EXEC);
	printf("#define\tS_OTHER 0x%x\n", S_OTHER);

	printf("#define\tLWP_USER 0x%x\n", LWP_USER);
	printf("#define\tLWP_SYS 0x%x\n", LWP_SYS);

	printf("#define\tLMS_USER 0x%x\n", LMS_USER);
	printf("#define\tLMS_SYSTEM 0x%x\n", LMS_SYSTEM);

	printf("#define\tPSR_PIL_BIT %d\n", bit(PSR_PIL));

	printf("#define\tELF_NOTE_SOLARIS \"%s\"\n", ELF_NOTE_SOLARIS);
	printf("#define\tELF_NOTE_PAGESIZE_HINT %d\n", ELF_NOTE_PAGESIZE_HINT);

	printf("#define\tAV_INT_SPURIOUS %d\n", AV_INT_SPURIOUS);

	printf("#define\tCPU_ENABLE %d\n", CPU_ENABLE);
	printf("#define\tCPU_READY %d\n", CPU_READY);
	printf("#define\tCPU_QUIESCED %d\n", CPU_QUIESCED);
	printf("#define\tCPU_INTRSTAT_LOW_PIL_OFFSET %d\n", (LOCK_LEVEL + 1) *
	    sizeof (uint64_t) * 2);

	printf("#define\tCPU_DTRACE_NOFAULT 0x%x\n", CPU_DTRACE_NOFAULT);
	printf("#define\tCPU_DTRACE_BADADDR 0x%x\n", CPU_DTRACE_BADADDR);

	printf("#define\tDMP_NOSYNC\t0x%x\n", DMP_NOSYNC);

	printf("#define\tRW_WRITER\t0x%x\n", RW_WRITER);
	printf("#define\tRW_READER\t0x%x\n", RW_READER);

	printf("#define\tSQ_EXCL 0x%x\n", SQ_EXCL);
	printf("#define\tSQ_BLOCKED 0x%x\n", SQ_BLOCKED);
	printf("#define\tSQ_FROZEN 0x%x\n", SQ_FROZEN);
	printf("#define\tSQ_WRITER 0x%x\n", SQ_WRITER);
	printf("#define\tSQ_QUEUED 0x%x\n", SQ_QUEUED);
	printf("#define\tSQ_WANTWAKEUP 0x%x\n", SQ_WANTWAKEUP);
	printf("#define\tSQ_WANTEXWAKEUP 0x%x\n", SQ_WANTEXWAKEUP);
	printf("#define\tSQ_CIPUT 0x%x\n", SQ_CIPUT);
	printf("#define\tSQ_TYPEMASK 0x%x\n", SQ_TYPEMASK);
	printf("#define\tSQ_GOAWAY 0x%x\n", SQ_GOAWAY);
	printf("#define\tSQ_STAYAWAY 0x%x\n", SQ_STAYAWAY);
	printf("#define\tSQ_PERMOD 0x%x\n", SQ_PERMOD);

	printf("#define\tFKIOCTL\t0x%x\n", FKIOCTL);
	printf("#define\tLOCK_MASK\t0xff000000\n");

	printf("#define\tDDI_DEV_NO_AUTOINCR %d\n", DDI_DEV_NO_AUTOINCR);
	printf("#define\tDDI_DEV_AUTOINCR %d\n", DDI_DEV_AUTOINCR);

	printf("#define\tDTRACE_IDSIZE %d\n", sizeof (dtrace_id_t));

	printf("#define\tMODS_NOUNLOAD 0x%x\n", MODS_NOUNLOAD);
	printf("#define\tMODS_WEAK 0x%x\n", MODS_WEAK);
	printf("#define\tMODS_INSTALLED 0x%x\n", MODS_INSTALLED);

	printf("#define\tKPREEMPT_SYNC %d\n", KPREEMPT_SYNC);
	exit(0);
}

int
bit(long mask)
{
	int i;

	for (i = 0; i < sizeof (mask) * NBBY; i++) {
		if (mask & 1)
			return (i);
		mask >>= 1;
	}

	exit(1);
}
