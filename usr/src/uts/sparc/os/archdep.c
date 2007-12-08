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
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/types.h>
#include <sys/vmparam.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/signal.h>
#include <sys/stack.h>
#include <sys/frame.h>
#include <sys/proc.h>
#include <sys/ucontext.h>
#include <sys/siginfo.h>
#include <sys/cpuvar.h>
#include <sys/asm_linkage.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/bootconf.h>
#include <sys/archsystm.h>
#include <sys/fpu/fpusystm.h>
#include <sys/auxv.h>
#include <sys/debug.h>
#include <sys/elf.h>
#include <sys/elf_SPARC.h>
#include <sys/cmn_err.h>
#include <sys/spl.h>
#include <sys/privregs.h>
#include <sys/kobj.h>
#include <sys/modctl.h>
#include <sys/reboot.h>
#include <sys/time.h>
#include <sys/panic.h>
#include <vm/seg_kmem.h>
#include <vm/page.h>
#include <sys/machpcb.h>

extern struct bootops *bootops;

/*
 * Workaround for broken FDDI driver (remove when 4289172 is fixed)
 */
short cputype = 0x80;

extern int getpcstack_top(pc_t *pcstack, int limit, uintptr_t *lastfp,
    pc_t *lastpc);

/*
 * Get a pc-only stacktrace.  Used for kmem_alloc() buffer ownership tracking.
 * Returns MIN(current stack depth, pcstack_limit).
 */
int
getpcstack(pc_t *pcstack, int pcstack_limit)
{
	struct frame *fp, *minfp, *stacktop;
	uintptr_t nextfp;
	pc_t nextpc;
	int depth;
	int on_intr;
	pc_t pcswin[MAXWIN];
	int npcwin = MIN(MAXWIN, pcstack_limit);

	if ((on_intr = CPU_ON_INTR(CPU)) != 0)
		stacktop = (struct frame *)(CPU->cpu_intr_stack + SA(MINFRAME));
	else
		stacktop = (struct frame *)curthread->t_stk;

	minfp = (struct frame *)((uintptr_t)getfp() + STACK_BIAS);

	/*
	 * getpcstack_top() processes the frames still in register windows,
	 * fills nextfp and nextpc with our starting point, and returns
	 * the number of frames it wrote into pcstack.
	 *
	 * Since we cannot afford to take a relocation trap while we are
	 * messing with register windows, we pass getpcstack_top() a buffer
	 * on our stack and then copy the result out to the pcstack buffer
	 * provided by the caller.  The size of this buffer is the maximum
	 * supported number of SPARC register windows; however we ASSERT
	 * that it returns fewer than that, since it will skip the current
	 * frame.
	 */
	npcwin = getpcstack_top(pcswin, npcwin, &nextfp, &nextpc);
	ASSERT(npcwin >= 0 && npcwin < MAXWIN && npcwin <= pcstack_limit);
	for (depth = 0; depth < npcwin; depth++) {
		pcstack[depth] = pcswin[depth];
	}

	fp = (struct frame *)(nextfp + STACK_BIAS);

	while (depth < pcstack_limit) {
		if (fp <= minfp || fp >= stacktop) {
			if (on_intr) {
				/*
				 * Hop from interrupt stack to thread stack.
				 */
				stacktop = (struct frame *)curthread->t_stk;
				minfp = (struct frame *)curthread->t_stkbase;
				on_intr = 0;
				continue;
			}
			break;
		}

		pcstack[depth++] = nextpc;
		minfp = fp;

		nextpc = (pc_t)fp->fr_savpc;
		fp = (struct frame *)((uintptr_t)fp->fr_savfp + STACK_BIAS);
	}

	return (depth);
}

/*
 * The following ELF header fields are defined as processor-specific
 * in the SPARC V8 ABI:
 *
 *	e_ident[EI_DATA]	encoding of the processor-specific
 *				data in the object file
 *	e_machine		processor identification
 *	e_flags			processor-specific flags associated
 *				with the file
 */

/*
 * The value of at_flags reflects a platform's cpu module support.
 * at_flags is used to check for allowing a binary to execute and
 * is passed as the value of the AT_FLAGS auxiliary vector.
 */
int at_flags = 0;

/*
 * Check the processor-specific fields of an ELF header.
 *
 * returns 1 if the fields are valid, 0 otherwise
 */
int
elfheadcheck(
	unsigned char e_data,
	Elf32_Half e_machine,
	Elf32_Word e_flags)
{
	Elf32_Word needed_flags;
	int supported_flags;

	if (e_data != ELFDATA2MSB)
		return (0);

	switch (e_machine) {
	case EM_SPARC:
		if (e_flags == 0)
			return (1);
		else
			return (0);
	case EM_SPARCV9:
		/*
		 * Check that ELF flags are set to supported SPARC V9 flags
		 */
		needed_flags = e_flags & EF_SPARC_EXT_MASK;
		supported_flags = at_flags & ~EF_SPARC_32PLUS;

		if (needed_flags & ~supported_flags)
			return (0);
		else
			return (1);
	case EM_SPARC32PLUS:
		if ((e_flags & EF_SPARC_32PLUS) != 0 &&
		    ((e_flags & ~at_flags) & EF_SPARC_32PLUS_MASK) == 0)
			return (1);
		else
			return (0);
	default:
		return (0);
	}
}

uint_t auxv_hwcap_include = 0;	/* patch to enable unrecognized features */
uint_t auxv_hwcap_exclude = 0;	/* patch for broken cpus, debugging */
#if defined(_SYSCALL32_IMPL)
uint_t auxv_hwcap32_include = 0;	/* ditto for 32-bit apps */
uint_t auxv_hwcap32_exclude = 0;	/* ditto for 32-bit apps */
#endif

uint_t cpu_hwcap_flags = 0;	/* set by cpu-dependent code */

/*
 * Gather information about the processor and place it into auxv_hwcap
 * so that it can be exported to the linker via the aux vector.
 *
 * We use this seemingly complicated mechanism so that we can ensure
 * that /etc/system can be used to override what the system can or
 * cannot discover for itself.
 */
void
bind_hwcap(void)
{
	auxv_hwcap = (auxv_hwcap_include | cpu_hwcap_flags) &
	    ~auxv_hwcap_exclude;

	if (auxv_hwcap_include || auxv_hwcap_exclude)
		cmn_err(CE_CONT, "?user ABI extensions: %b\n",
		    auxv_hwcap, FMT_AV_SPARC);

#if defined(_SYSCALL32_IMPL)
	/*
	 * These are now a compatibility artifact; all supported SPARC CPUs
	 * are V9-capable (and thus support v8plus) and fully implement
	 * {s,u}mul and {s,u}div.
	 */
	cpu_hwcap_flags |= AV_SPARC_MUL32 | AV_SPARC_DIV32 | AV_SPARC_V8PLUS;

	auxv_hwcap32 = (auxv_hwcap32_include | cpu_hwcap_flags) &
	    ~auxv_hwcap32_exclude;

	if (auxv_hwcap32_include || auxv_hwcap32_exclude)
		cmn_err(CE_CONT, "?32-bit user ABI extensions: %b\n",
		    auxv_hwcap32, FMT_AV_SPARC);
#endif
}

int
__ipltospl(int ipl)
{
	return (ipltospl(ipl));
}

/*
 * Print a stack backtrace using the specified stack pointer.  We delay two
 * seconds before continuing, unless this is the panic traceback.  Note
 * that the frame for the starting stack pointer value is omitted because
 * the corresponding %pc is not known.
 */
void
traceback(caddr_t sp)
{
	struct frame *fp = (struct frame *)(sp + STACK_BIAS);
	struct frame *nextfp, *minfp, *stacktop;
	int on_intr;

	cpu_t *cpu;

	flush_windows();

	if (!panicstr)
		printf("traceback: %%sp = %p\n", (void *)sp);

	/*
	 * If we are panicking, the high-level interrupt information in
	 * CPU was overwritten.  panic_cpu has the correct values.
	 */
	kpreempt_disable();			/* prevent migration */

	cpu = (panicstr && CPU->cpu_id == panic_cpu.cpu_id)? &panic_cpu : CPU;

	if ((on_intr = CPU_ON_INTR(cpu)) != 0)
		stacktop = (struct frame *)(cpu->cpu_intr_stack + SA(MINFRAME));
	else
		stacktop = (struct frame *)curthread->t_stk;

	kpreempt_enable();

	minfp = fp;

	while ((uintptr_t)fp >= KERNELBASE) {
		uintptr_t pc = (uintptr_t)fp->fr_savpc;
		ulong_t off;
		char *sym;

		nextfp = (struct frame *)((uintptr_t)fp->fr_savfp + STACK_BIAS);
		if (nextfp <= minfp || nextfp >= stacktop) {
			if (on_intr) {
				/*
				 * Hop from interrupt stack to thread stack.
				 */
				stacktop = (struct frame *)curthread->t_stk;
				minfp = (struct frame *)curthread->t_stkbase;
				on_intr = 0;
				continue;
			}
			break; /* we're outside of the expected range */
		}

		if ((uintptr_t)nextfp & (STACK_ALIGN - 1)) {
			printf("  >> mis-aligned %%fp = %p\n", (void *)nextfp);
			break;
		}

		if ((sym = kobj_getsymname(pc, &off)) != NULL) {
			printf("%016lx %s:%s+%lx "
			    "(%lx, %lx, %lx, %lx, %lx, %lx)\n", (ulong_t)nextfp,
			    mod_containing_pc((caddr_t)pc), sym, off,
			    nextfp->fr_arg[0], nextfp->fr_arg[1],
			    nextfp->fr_arg[2], nextfp->fr_arg[3],
			    nextfp->fr_arg[4], nextfp->fr_arg[5]);
		} else {
			printf("%016lx %p (%lx, %lx, %lx, %lx, %lx, %lx)\n",
			    (ulong_t)nextfp, (void *)pc,
			    nextfp->fr_arg[0], nextfp->fr_arg[1],
			    nextfp->fr_arg[2], nextfp->fr_arg[3],
			    nextfp->fr_arg[4], nextfp->fr_arg[5]);
		}

		printf("  %%l0-3: %016lx %016lx %016lx %016lx\n"
		    "  %%l4-7: %016lx %016lx %016lx %016lx\n",
		    nextfp->fr_local[0], nextfp->fr_local[1],
		    nextfp->fr_local[2], nextfp->fr_local[3],
		    nextfp->fr_local[4], nextfp->fr_local[5],
		    nextfp->fr_local[6], nextfp->fr_local[7]);

		fp = nextfp;
		minfp = fp;
	}

	if (!panicstr) {
		printf("end of traceback\n");
		DELAY(2 * MICROSEC);
	}
}

/*
 * Generate a stack backtrace from a saved register set.
 */
void
traceregs(struct regs *rp)
{
	traceback((caddr_t)rp->r_sp);
}

void
exec_set_sp(size_t stksize)
{
	klwp_t *lwp = ttolwp(curthread);

	lwp->lwp_pcb.pcb_xregstat = XREGNONE;
	if (curproc->p_model == DATAMODEL_NATIVE)
		stksize += sizeof (struct rwindow) + STACK_BIAS;
	else
		stksize += sizeof (struct rwindow32);
	lwptoregs(lwp)->r_sp = (uintptr_t)curproc->p_usrstack - stksize;
}

/*
 * Allocate a region of virtual address space, unmapped.
 *
 * When a hard-redzone (firewall) is in effect, redzone violations are
 * caught by the hardware the instant they happen because the first byte
 * past the logical end of a firewalled buffer lies at the start of an
 * unmapped page.  This firewalling is accomplished by bumping up the
 * requested address allocation, effectively removing an additional page
 * beyond the original request from the available virtual memory arena.
 * However, the size of the allocation passed to boot, in boot_alloc(),
 * doesn't reflect this additional page and fragmentation of the OBP
 * "virtual-memory" "available" lists property occurs.  Calling
 * prom_claim_virt() for the firewall page avoids this fragmentation.
 */
void *
boot_virt_alloc(void *addr, size_t size)
{
	return (BOP_ALLOC_VIRT((caddr_t)addr, size));
}


/*ARGSUSED*/
int
xcopyin_nta(const void *uaddr, void *kaddr, size_t count, int dummy)
{
	return (xcopyin(uaddr, kaddr, count));
}
/*ARGSUSED*/
int
xcopyout_nta(const void *kaddr, void *uaddr, size_t count, int dummy)
{
	return (xcopyout(kaddr, uaddr, count));
}
/*ARGSUSED*/
int
kcopy_nta(const void *from, void *to, size_t count, int dummy)
{
	return (kcopy(from, to, count));
}
