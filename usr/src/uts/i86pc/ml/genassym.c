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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_GENASSYM
#define	_GENASSYM
#endif

#define	exit	kern_exit

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/elf_notes.h>
#include <sys/thread.h>
#include <sys/rwlock.h>
#include <sys/proc.h>
#include <sys/cpuvar.h>
#include <sys/clock.h>
#include <sys/trap.h>
#include <sys/modctl.h>
#include <sys/traptrace.h>
#include <vm/seg.h>
#include <sys/avintr.h>
#include <sys/pic.h>
#include <sys/pit.h>
#include <sys/fp.h>
#include <sys/disp.h>
#include <sys/archsystm.h>
#include <sys/x86_archext.h>
#include <sys/sunddi.h>
#include <sys/mach_mmu.h>

#if defined(__xpv)
#include <sys/hypervisor.h>
#endif

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
	printf("#define\tT_AST 0x%x\n", T_AST);

	printf("#define\tLOCK_LEVEL 0x%x\n", LOCK_LEVEL);
	printf("#define\tCLOCK_LEVEL 0x%x\n", CLOCK_LEVEL);
	printf("#define\tDISP_LEVEL 0x%x\n", DISP_LEVEL);
	printf("#define\tPIL_MAX 0x%x\n", PIL_MAX);
	printf("#define\tHIGH_LEVELS 0x%x\n", HIGH_LEVELS);
	printf("#define\tCPU_INTR_ACTV_HIGH_LEVEL_MASK 0x%x\n",
	    CPU_INTR_ACTV_HIGH_LEVEL_MASK);

	printf("#define\tPIC_NSEOI 0x%x\n", PIC_NSEOI);
	printf("#define\tPIC_SEOI_LVL7 0x%x\n", PIC_SEOI_LVL7);

	printf("#define\tNANOSEC 0x%llx\n", NANOSEC);
	printf("#define\tADJ_SHIFT 0x%x\n", ADJ_SHIFT);

	printf("#define\tSSLEEP 0x%x\n", SSLEEP);
	printf("#define\tSRUN 0x%x\n", SRUN);
	printf("#define\tSONPROC 0x%x\n", SONPROC);

	printf("#define\tT_INTR_THREAD 0x%x\n", T_INTR_THREAD);
	printf("#define\tFREE_THREAD 0x%x\n", TS_FREE);
	printf("#define\tTS_FREE 0x%x\n", TS_FREE);
	printf("#define\tTS_ZOMB 0x%x\n", TS_ZOMB);
	printf("#define\tTP_MSACCT 0x%x\n", TP_MSACCT);
	printf("#define\tTP_WATCHPT 0x%x\n", TP_WATCHPT);
	printf("#define\tONPROC_THREAD 0x%x\n", TS_ONPROC);

	printf("#define\tS_READ 0x%x\n", (int)S_READ);
	printf("#define\tS_WRITE 0x%x\n", (int)S_WRITE);
	printf("#define\tS_EXEC 0x%x\n", (int)S_EXEC);
	printf("#define\tS_OTHER 0x%x\n", (int)S_OTHER);

	printf("#define\tNORMALRETURN 0x%x\n", (int)NORMALRETURN);
	printf("#define\tLWP_USER 0x%x\n", LWP_USER);
	printf("#define\tLWP_SYS 0x%x\n", LWP_SYS);
	printf("#define\tLMS_USER 0x%x\n", LMS_USER);
	printf("#define\tLMS_SYSTEM 0x%x\n", LMS_SYSTEM);

	printf("#define\tSSE_MXCSR_EFLAGS 0x%x\n", SSE_MXCSR_EFLAGS);

	printf("#define\tFP_487 0x%x\n", FP_487);
	printf("#define\tFP_486 0x%x\n", FP_486);
	printf("#define\tFPU_CW_INIT 0x%x\n", FPU_CW_INIT);
	printf("#define\tFPU_EN 0x%x\n", FPU_EN);
	printf("#define\tFPU_VALID 0x%x\n", FPU_VALID);

	printf("#define\tFP_NO 0x%x\n", FP_NO);
	printf("#define\tFP_SW 0x%x\n", FP_SW);
	printf("#define\tFP_HW 0x%x\n", FP_HW);
	printf("#define\tFP_287 0x%x\n", FP_287);
	printf("#define\tFP_387 0x%x\n", FP_387);
	printf("#define\t__FP_SSE 0x%x\n", __FP_SSE);

	printf("#define\tFP_FNSAVE 0x%x\n", FP_FNSAVE);
	printf("#define\tFP_FXSAVE 0x%x\n", FP_FXSAVE);
	printf("#define\tFP_XSAVE 0x%x\n", FP_XSAVE);

	printf("#define\tAV_INT_SPURIOUS 0x%x\n", AV_INT_SPURIOUS);

	printf("#define\tCPU_READY 0x%x\n", CPU_READY);
	printf("#define\tCPU_QUIESCED 0x%x\n", CPU_QUIESCED);

	printf("#define\tMCMD_PORT 0x%x\n", MCMD_PORT);
	printf("#define\tSCMD_PORT 0x%x\n", SCMD_PORT);
	printf("#define\tMIMR_PORT 0x%x\n", MIMR_PORT);
	printf("#define\tSIMR_PORT 0x%x\n", SIMR_PORT);

	printf("#define\tDMP_NOSYNC 0x%x\n", DMP_NOSYNC);

	printf("#define\tRW_WRITER\t0x%x\n", RW_WRITER);
	printf("#define\tRW_READER\t0x%x\n", RW_READER);

	printf("#define\tNSYSCALL 0x%x\n", NSYSCALL);

	printf("#define\tSE_32RVAL1 0x%x\n", SE_32RVAL1);
	printf("#define\tSE_32RVAL2 0x%x\n", SE_32RVAL2);
	printf("#define\tSE_64RVAL 0x%x\n", SE_64RVAL);

	printf("#define\tMAXSYSARGS 0x%x\n", MAXSYSARGS);

	/* Hack value just to allow clock to be kicked */
	printf("#define\tNSEC_PER_CLOCK_TICK 0x%llx\n", NANOSEC / 100);

	printf("#define\tNSEC_PER_COUNTER_TICK 0x%llx\n", NANOSEC / PIT_HZ);

	printf("#define\tPITCTR0_PORT 0x%x\n", PITCTR0_PORT);
	printf("#define\tPITCTL_PORT 0x%x\n", PITCTL_PORT);
	printf("#define\tPIT_COUNTDOWN 0x%x\n",
	    PIT_C0 | PIT_LOADMODE | PIT_NDIVMODE);

	printf("#define\tNBPW 0x%x\n", NBPW);

	printf("#define\tDDI_ACCATTR_IO_SPACE 0x%x\n", DDI_ACCATTR_IO_SPACE);
	printf("#define\tDDI_ACCATTR_DIRECT 0x%x\n", DDI_ACCATTR_DIRECT);
	printf("#define\tDDI_ACCATTR_CPU_VADDR 0x%x\n", DDI_ACCATTR_CPU_VADDR);
	printf("#define\tDDI_DEV_AUTOINCR 0x%x\n", DDI_DEV_AUTOINCR);

	printf("#define\tMMU_STD_PAGESIZE 0x%x\n", (uint_t)MMU_STD_PAGESIZE);
	printf("#define\tMMU_STD_PAGEMASK 0x%x\n", (uint_t)MMU_STD_PAGEMASK);
	printf("#define\tFOUR_MEG 0x%x\n", (uint_t)FOUR_MEG);

	printf("#define\tTRAPTR_NENT 0x%x\n", TRAPTR_NENT);

	printf("#define\tCPU_DTRACE_NOFAULT 0x%x\n", CPU_DTRACE_NOFAULT);
	printf("#define\tCPU_DTRACE_BADADDR 0x%x\n", CPU_DTRACE_BADADDR);
	printf("#define\tCPU_DTRACE_ILLOP 0x%x\n", CPU_DTRACE_ILLOP);

	printf("#define\tMODS_NOUNLOAD 0x%x\n", MODS_NOUNLOAD);
	printf("#define\tMODS_WEAK 0x%x\n", MODS_WEAK);
	printf("#define\tMODS_INSTALLED 0x%x\n", MODS_INSTALLED);

	printf("#define\tKPREEMPT_SYNC 0x%x\n", KPREEMPT_SYNC);

#if defined(__xpv)
	printf("#define\tSHUTDOWN_reboot 0x%x\n", SHUTDOWN_reboot);
	printf("#define\tSCHEDOP_block 0x%x\n", SCHEDOP_block);
	printf("#define\tVGCF_IN_KERNEL 0x%x\n", VGCF_IN_KERNEL);
#endif
	return (0);
}
