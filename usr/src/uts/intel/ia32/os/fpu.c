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
 * Copyright (c) 2018, Joyent, Inc.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T   */
/*		All Rights Reserved				*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation		*/
/*		All Rights Reserved				*/

/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/psw.h>
#include <sys/trap.h>
#include <sys/fault.h>
#include <sys/systm.h>
#include <sys/user.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/pcb.h>
#include <sys/lwp.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/disp.h>
#include <sys/fp.h>
#include <sys/siginfo.h>
#include <sys/archsystm.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/x86_archext.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>

/*
 * FPU Management Overview
 * -----------------------
 *
 * The x86 FPU has evolved substantially since its days as the x87 coprocessor;
 * however, many aspects of its life as a coprocessor are still around in x86.
 *
 * Today, when we refer to the 'FPU', we don't just mean the original x87 FPU.
 * While that state still exists, there is much more that is covered by the FPU.
 * Today, this includes not just traditional FPU state, but also supervisor only
 * state. The following state is currently managed and covered logically by the
 * idea of the FPU registers:
 *
 *    o Traditional x87 FPU
 *    o Vector Registers (%xmm, %ymm, %zmm)
 *    o Memory Protection Extensions (MPX) Bounds Registers
 *    o Protected Key Rights Registers (PKRU)
 *    o Processor Trace data
 *
 * The rest of this covers how the FPU is managed and controlled, how state is
 * saved and restored between threads, interactions with hypervisors, and other
 * information exported to user land through aux vectors. A lot of background
 * information is here to synthesize major parts of the Intel SDM, but
 * unfortunately, it is not a replacement for reading it.
 *
 * FPU Control Registers
 * ---------------------
 *
 * Because the x87 FPU began its life as a co-processor and the FPU was
 * optional there are several bits that show up in %cr0 that we have to
 * manipulate when dealing with the FPU. These are:
 *
 *   o CR0.ET	The 'extension type' bit. This was used originally to indicate
 *		that the FPU co-processor was present. Now it is forced on for
 *		compatibility. This is often used to verify whether or not the
 *		FPU is present.
 *
 *   o CR0.NE	The 'native error' bit. Used to indicate that native error
 *		mode should be enabled. This indicates that we should take traps
 *		on FPU errors. The OS enables this early in boot.
 *
 *   o CR0.MP	The 'Monitor Coprocessor' bit. Used to control whether or not
 *		wait/fwait instructions generate a #NM if CR0.TS is set.
 *
 *   o CR0.EM	The 'Emulation' bit. This is used to cause floating point
 *		operations (x87 through SSE4) to trap with a #UD so they can be
 *		emulated. The system never sets this bit, but makes sure it is
 *		clear on processor start up.
 *
 *   o CR0.TS	The 'Task Switched' bit. When this is turned on, a floating
 *		point operation will generate a #NM. An fwait will as well,
 *		depending on the value in CR0.MP.
 *
 * Our general policy is that CR0.ET, CR0.NE, and CR0.MP are always set by
 * the system. Similarly CR0.EM is always unset by the system. CR0.TS has a more
 * complicated role. Historically it has been used to allow running systems to
 * restore the FPU registers lazily. This will be discussed in greater depth
 * later on.
 *
 * %cr4 is also used as part of the FPU control. Specifically we need to worry
 * about the following bits in the system:
 *
 *   o CR4.OSFXSR	This bit is used to indicate that the OS understands and
 *			supports the execution of the fxsave and fxrstor
 *			instructions. This bit is required to be set to enable
 *			the use of the SSE->SSE4 instructions.
 *
 *   o CR4.OSXMMEXCPT	This bit is used to indicate that the OS can understand
 *			and take a SIMD floating point exception (#XM). This bit
 *			is always enabled by the system.
 *
 *   o CR4.OSXSAVE	This bit is used to indicate that the OS understands and
 *			supports the execution of the xsave and xrstor family of
 *			instructions. This bit is required to use any of the AVX
 *			and newer feature sets.
 *
 * Because all supported processors are 64-bit, they'll always support the XMM
 * extensions and we will enable both CR4.OXFXSR and CR4.OSXMMEXCPT in boot.
 * CR4.OSXSAVE will be enabled and used whenever xsave is reported in cpuid.
 *
 * %xcr0 is used to manage the behavior of the xsave feature set and is only
 * present on the system if xsave is supported. %xcr0 is read and written to
 * through by the xgetbv and xsetbv instructions. This register is present
 * whenever the xsave feature set is supported. Each bit in %xcr0 refers to a
 * different component of the xsave state and controls whether or not that
 * information is saved and restored. For newer feature sets like AVX and MPX,
 * it also controls whether or not the corresponding instructions can be
 * executed (much like CR0.OSFXSR does for the SSE feature sets).
 *
 * Everything in %xcr0 is around features available to users. There is also the
 * IA32_XSS MSR which is used to control supervisor-only features that are still
 * part of the xsave state. Bits that can be set in %xcr0 are reserved in
 * IA32_XSS and vice versa. This is an important property that is particularly
 * relevant to how the xsave instructions operate.
 *
 * Save Mechanisms
 * ---------------
 *
 * When switching between running threads the FPU state needs to be saved and
 * restored by the OS. If this state was not saved, users would rightfully
 * complain about corrupt state. There are three mechanisms that exist on the
 * processor for saving and restoring these state images:
 *
 *   o fsave
 *   o fxsave
 *   o xsave
 *
 * fsave saves and restores only the x87 FPU and is the oldest of these
 * mechanisms. This mechanism is never used in the kernel today because we are
 * always running on systems that support fxsave.
 *
 * The fxsave and fxrstor mechanism allows the x87 FPU and the SSE register
 * state to be saved and restored to and from a struct fxsave_state. This is the
 * default mechanism that is used to save and restore the FPU on amd64. An
 * important aspect of fxsave that was different from the original i386 fsave
 * mechanism is that the restoring of FPU state with pending exceptions will not
 * generate an exception, it will be deferred to the next use of the FPU.
 *
 * The final and by far the most complex mechanism is that of the xsave set.
 * xsave allows for saving and restoring all of the traditional x86 pieces (x87
 * and SSE), while allowing for extensions that will save the %ymm, %zmm, etc.
 * registers.
 *
 * Data is saved and restored into and out of a struct xsave_state. The first
 * part of the struct xsave_state is equivalent to the struct fxsave_state.
 * After that, there is a header which is used to describe the remaining
 * portions of the state. The header is a 64-byte value of which the first two
 * uint64_t values are defined and the rest are reserved and must be zero. The
 * first uint64_t is the xstate_bv member. This describes which values in the
 * xsave_state are actually valid and present. This is updated on a save and
 * used on restore. The second member is the xcomp_bv member. Its last bit
 * determines whether or not a compressed version of the structure is used.
 *
 * When the uncompressed structure is used (currently the only format we
 * support), then each state component is at a fixed offset in the structure,
 * even if it is not being used. For example, if you only saved the AVX related
 * state, but did not save the MPX related state, the offset would not change
 * for any component. With the compressed format, components that aren't used
 * are all elided (though the x87 and SSE state are always there).
 *
 * Unlike fxsave which saves all state, the xsave family does not always save
 * and restore all the state that could be covered by the xsave_state. The
 * instructions all take an argument which is a mask of what to consider. This
 * is the same mask that will be used in the xstate_bv vector and it is also the
 * same values that are present in %xcr0 and IA32_XSS. Though IA32_XSS is only
 * considered with the xsaves and xrstors instructions.
 *
 * When a save or restore is requested, a bitwise and is performed between the
 * requested bits and those that have been enabled in %xcr0. Only the bits that
 * match that are then saved or restored. Others will be silently ignored by
 * the processor. This idea is used often in the OS. We will always request that
 * we save and restore all of the state, but only those portions that are
 * actually enabled in %xcr0 will be touched.
 *
 * If a feature has been asked to be restored that is not set in the xstate_bv
 * feature vector of the save state, then it will be set to its initial state by
 * the processor (usually zeros). Also, when asked to save state, the processor
 * may not write out data that is in its initial state as an optimization. This
 * optimization only applies to saving data and not to restoring data.
 *
 * There are a few different variants of the xsave and xrstor instruction. They
 * are:
 *
 *   o xsave	This is the original save instruction. It will save all of the
 *		requested data in the xsave state structure. It only saves data
 *		in the uncompressed (xcomp_bv[63] is zero) format. It may be
 *		executed at all privilege levels.
 *
 *   o xrstor	This is the original restore instruction. It will restore all of
 *		the requested data. The xrstor function can handle both the
 *		compressed and uncompressed formats. It may be executed at all
 *		privilege levels.
 *
 *   o xsaveopt	This is a variant of the xsave instruction that employs
 *		optimizations to try and only write out state that has been
 *		modified since the last time an xrstor instruction was called.
 *		The processor tracks a tuple of information about the last
 *		xrstor and tries to ensure that the same buffer is being used
 *		when this optimization is being used. However, because of the
 *		way that it tracks the xrstor buffer based on the address of it,
 *		it is not suitable for use if that buffer can be easily reused.
 *		The most common case is trying to save data to the stack in
 *		rtld. It may be executed at all privilege levels.
 *
 *   o xsavec	This is a variant of the xsave instruction that writes out the
 *		compressed form of the xsave_state. Otherwise it behaves as
 *		xsave. It may be executed at all privilege levels.
 *
 *   o xsaves	This is a variant of the xsave instruction. It is similar to
 *		xsavec in that it always writes the compressed form of the
 *		buffer. Unlike all the other forms, this instruction looks at
 *		both the user (%xcr0) and supervisor (IA32_XSS MSR) to determine
 *		what to save and restore. xsaves also implements the same
 *		optimization that xsaveopt does around modified pieces. User
 *		land may not execute the instruction.
 *
 *   o xrstors	This is a variant of the xrstor instruction. Similar to xsaves
 *		it can save and restore both the user and privileged states.
 *		Unlike xrstor it can only operate on the compressed form.
 *		User land may not execute the instruction.
 *
 * Based on all of these, the kernel has a precedence for what it will use.
 * Basically, xsaves (not supported) is preferred to xsaveopt, which is
 * preferred to xsave. A similar scheme is used when informing rtld (more later)
 * about what it should use. xsavec is preferred to xsave. xsaveopt is not
 * recommended due to the modified optimization not being appropriate for this
 * use.
 *
 * Finally, there is one last gotcha with the xsave state. Importantly some AMD
 * processors did not always save and restore some of the FPU exception state in
 * some cases like Intel did. In those cases the OS will make up for this fact
 * itself.
 *
 * FPU Initialization
 * ------------------
 *
 * One difference with the FPU registers is that not all threads have FPU state,
 * only those that have an lwp. Generally this means kernel threads, which all
 * share p0 and its lwp, do not have FPU state. Though there are definitely
 * exceptions such as kcfpoold. In the rest of this discussion we'll use thread
 * and lwp interchangeably, just think of thread meaning a thread that has a
 * lwp.
 *
 * Each lwp has its FPU state allocated in its pcb (process control block). The
 * actual storage comes from the fpsave_cachep kmem cache. This cache is sized
 * dynamically at start up based on the save mechanism that we're using and the
 * amount of memory required for it. This is dynamic because the xsave_state
 * size varies based on the supported feature set.
 *
 * The hardware side of the FPU is initialized early in boot before we mount the
 * root file system. This is effectively done in fpu_probe(). This is where we
 * make the final decision about what the save and restore mechanisms we should
 * use are, create the fpsave_cachep kmem cache, and initialize a number of
 * function pointers that use save and restoring logic.
 *
 * The thread/lwp side is a a little more involved. There are two different
 * things that we need to concern ourselves with. The first is how the FPU
 * resources are allocated and the second is how the FPU state is initialized
 * for a given lwp.
 *
 * We allocate the FPU save state from our kmem cache as part of lwp_fp_init().
 * This is always called unconditionally by the system as part of creating an
 * LWP.
 *
 * There are three different initialization paths that we deal with. The first
 * is when we are executing a new process. As part of exec all of the register
 * state is reset. The exec case is particularly important because init is born
 * like Athena, sprouting from the head of the kernel, without any true parent
 * to fork from. The second is used whenever we fork or create a new lwp.  The
 * third is to deal with special lwps like the agent lwp.
 *
 * During exec, we will call fp_exec() which will initialize and set up the FPU
 * state for the process. That will fill in the initial state for the FPU and
 * also set that state in the FPU itself. As part of fp_exec() we also install a
 * thread context operations vector that takes care of dealing with the saving
 * and restoring of the FPU. These context handlers will also be called whenever
 * an lwp is created or forked. In those cases, to initialize the FPU we will
 * call fp_new_lwp(). Like fp_exec(), fp_new_lwp() will install a context
 * operations vector for the new thread.
 *
 * Next we'll end up in the context operation fp_new_lwp(). This saves the
 * current thread's state, initializes the new thread's state, and copies over
 * the relevant parts of the originating thread's state. It's as this point that
 * we also install the FPU context operations into the new thread, which ensures
 * that all future threads that are descendants of the current one get the
 * thread context operations (unless they call exec).
 *
 * To deal with some things like the agent lwp, we double check the state of the
 * FPU in sys_rtt_common() to make sure that it has been enabled before
 * returning to user land. In general, this path should be rare, but it's useful
 * for the odd lwp here and there.
 *
 * The FPU state will remain valid most of the time. There are times that
 * the state will be rewritten. For example in restorecontext, due to /proc, or
 * the lwp calls exec(). Whether the context is being freed or we are resetting
 * the state, we will call fp_free() to disable the FPU and our context.
 *
 * Finally, when the lwp is destroyed, it will actually destroy and free the FPU
 * state by calling fp_lwp_cleanup().
 *
 * Kernel FPU Multiplexing
 * -----------------------
 *
 * Just as the kernel has to maintain all of the general purpose registers when
 * switching between scheduled threads, the same is true of the FPU registers.
 *
 * When a thread has FPU state, it also has a set of context operations
 * installed. These context operations take care of making sure that the FPU is
 * properly saved and restored during a context switch (fpsave_ctxt and
 * fprestore_ctxt respectively). This means that the current implementation of
 * the FPU is 'eager', when a thread is running the CPU will have its FPU state
 * loaded. While this is always true when executing in userland, there are a few
 * cases where this is not true in the kernel.
 *
 * This was not always the case. Traditionally on x86 a 'lazy' FPU restore was
 * employed. This meant that the FPU would be saved on a context switch and the
 * CR0.TS bit would be set. When a thread next tried to use the FPU, it would
 * then take a #NM trap, at which point we would restore the FPU from the save
 * area and return to user land. Given the frequency of use of the FPU alone by
 * libc, there's no point returning to user land just to trap again.
 *
 * There are a few cases though where the FPU state may need to be changed for a
 * thread on its behalf. The most notable cases are in the case of processes
 * using /proc, restorecontext, forking, etc. In all of these cases the kernel
 * will force a threads FPU state to be saved into the PCB through the fp_save()
 * function. Whenever the FPU is saved, then the FPU_VALID flag is set on the
 * pcb. This indicates that the save state holds currently valid data. As a side
 * effect of this, CR0.TS will be set. To make sure that all of the state is
 * updated before returning to user land, in these cases, we set a flag on the
 * PCB that says the FPU needs to be updated. This will make sure that we take
 * the slow path out of a system call to fix things up for the thread. Due to
 * the fact that this is a rather rare case, effectively setting the equivalent
 * of t_postsys is acceptable.
 *
 * CR0.TS will be set after a save occurs and cleared when a restore occurs.
 * Generally this means it will be cleared immediately by the new thread that is
 * running in a context switch. However, this isn't the case for kernel threads.
 * They currently operate with CR0.TS set as no kernel state is restored for
 * them. This means that using the FPU will cause a #NM and panic.
 *
 * The FPU_VALID flag on the currently executing thread's pcb is meant to track
 * what the value of CR0.TS should be. If it is set, then CR0.TS will be set.
 * However, because we eagerly restore, the only time that CR0.TS should be set
 * for a non-kernel thread is during operations where it will be cleared before
 * returning to user land and importantly, the only data that is in it is its
 * own.
 *
 * FPU Exceptions
 * --------------
 *
 * Certain operations can cause the kernel to take traps due to FPU activity.
 * Generally these events will cause a user process to receive a SIGFPU and if
 * the kernel receives it in kernel context, we will die. Traditionally the #NM
 * (Device Not Available / No Math) exception generated by CR0.TS would have
 * caused us to restore the FPU. Now it is a fatal event regardless of whether
 * or not user land causes it.
 *
 * While there are some cases where the kernel uses the FPU, it is up to the
 * kernel to use the FPU in a way such that it cannot receive a trap or to use
 * the appropriate trap protection mechanisms.
 *
 * Hypervisors
 * -----------
 *
 * When providing support for hypervisors things are a little bit more
 * complicated because the FPU is not virtualized at all. This means that they
 * need to save and restore the FPU and %xcr0 across entry and exit to the
 * guest. To facilitate this, we provide a series of APIs in <sys/hma.h>. These
 * allow us to use the full native state to make sure that we are always saving
 * and restoring the full FPU that the host sees, even when the guest is using a
 * subset.
 *
 * One tricky aspect of this is that the guest may be using a subset of %xcr0
 * and therefore changing our %xcr0 on the fly. It is vital that when we're
 * saving and restoring the FPU that we always use the largest %xcr0 contents
 * otherwise we will end up leaving behind data in it.
 *
 * ELF PLT Support
 * ---------------
 *
 * rtld has to preserve a subset of the FPU when it is saving and restoring
 * registers due to the amd64 SYS V ABI. See cmd/sgs/rtld/amd64/boot_elf.s for
 * more information. As a result, we set up an aux vector that contains
 * information about what save and restore mechanisms it should be using and
 * the sizing thereof based on what the kernel supports. This is passed down in
 * a series of aux vectors SUN_AT_FPTYPE and SUN_AT_FPSIZE. This information is
 * initialized in fpu_subr.c.
 */

kmem_cache_t *fpsave_cachep;

/* Legacy fxsave layout + xsave header + ymm */
#define	AVX_XSAVE_SIZE		(512 + 64 + 256)

/*
 * Various sanity checks.
 */
CTASSERT(sizeof (struct fxsave_state) == 512);
CTASSERT(sizeof (struct fnsave_state) == 108);
CTASSERT((offsetof(struct fxsave_state, fx_xmm[0]) & 0xf) == 0);
CTASSERT(sizeof (struct xsave_state) >= AVX_XSAVE_SIZE);

/*
 * Initial kfpu state for SSE/SSE2 used by fpinit()
 */
const struct fxsave_state sse_initial = {
	FPU_CW_INIT,	/* fx_fcw */
	0,		/* fx_fsw */
	0,		/* fx_fctw */
	0,		/* fx_fop */
#if defined(__amd64)
	0,		/* fx_rip */
	0,		/* fx_rdp */
#else
	0,		/* fx_eip */
	0,		/* fx_cs */
	0,		/* __fx_ign0 */
	0,		/* fx_dp */
	0,		/* fx_ds */
	0,		/* __fx_ign1 */
#endif /* __amd64 */
	SSE_MXCSR_INIT	/* fx_mxcsr */
	/* rest of structure is zero */
};

/*
 * Initial kfpu state for AVX used by fpinit()
 */
const struct xsave_state avx_initial = {
	/*
	 * The definition below needs to be identical with sse_initial
	 * defined above.
	 */
	{
		FPU_CW_INIT,	/* fx_fcw */
		0,		/* fx_fsw */
		0,		/* fx_fctw */
		0,		/* fx_fop */
#if defined(__amd64)
		0,		/* fx_rip */
		0,		/* fx_rdp */
#else
		0,		/* fx_eip */
		0,		/* fx_cs */
		0,		/* __fx_ign0 */
		0,		/* fx_dp */
		0,		/* fx_ds */
		0,		/* __fx_ign1 */
#endif /* __amd64 */
		SSE_MXCSR_INIT	/* fx_mxcsr */
		/* rest of structure is zero */
	},
	/*
	 * bit0 = 1 for XSTATE_BV to indicate that legacy fields are valid,
	 * and CPU should initialize XMM/YMM.
	 */
	1,
	0	/* xs_xcomp_bv */
	/* rest of structure is zero */
};

/*
 * mxcsr_mask value (possibly reset in fpu_probe); used to avoid
 * the #gp exception caused by setting unsupported bits in the
 * MXCSR register
 */
uint32_t sse_mxcsr_mask = SSE_MXCSR_MASK_DEFAULT;

/*
 * Initial kfpu state for x87 used by fpinit()
 */
const struct fnsave_state x87_initial = {
	FPU_CW_INIT,	/* f_fcw */
	0,		/* __f_ign0 */
	0,		/* f_fsw */
	0,		/* __f_ign1 */
	0xffff,		/* f_ftw */
	/* rest of structure is zero */
};

/*
 * This vector is patched to xsave_ctxt() if we discover we have an
 * XSAVE-capable chip in fpu_probe.
 */
void (*fpsave_ctxt)(void *) = fpxsave_ctxt;
void (*fprestore_ctxt)(void *) = fpxrestore_ctxt;

/*
 * This function pointer is changed to xsaveopt if the CPU is xsaveopt capable.
 */
void (*xsavep)(struct xsave_state *, uint64_t) = xsave;

static int fpe_sicode(uint_t);
static int fpe_simd_sicode(uint_t);

/*
 * Copy the state of parent lwp's floating point context into the new lwp.
 * Invoked for both fork() and lwp_create().
 *
 * Note that we inherit -only- the control state (e.g. exception masks,
 * rounding, precision control, etc.); the FPU registers are otherwise
 * reset to their initial state.
 */
static void
fp_new_lwp(kthread_id_t t, kthread_id_t ct)
{
	struct fpu_ctx *fp;		/* parent fpu context */
	struct fpu_ctx *cfp;		/* new fpu context */
	struct fxsave_state *fx, *cfx;
	struct xsave_state *cxs;

	ASSERT(fp_kind != FP_NO);

	fp = &t->t_lwp->lwp_pcb.pcb_fpu;
	cfp = &ct->t_lwp->lwp_pcb.pcb_fpu;

	/*
	 * If the parent FPU state is still in the FPU hw then save it;
	 * conveniently, fp_save() already does this for us nicely.
	 */
	fp_save(fp);

	cfp->fpu_flags = FPU_EN | FPU_VALID;
	cfp->fpu_regs.kfpu_status = 0;
	cfp->fpu_regs.kfpu_xstatus = 0;

	/*
	 * Make sure that the child's FPU is cleaned up and made ready for user
	 * land.
	 */
	PCB_SET_UPDATE_FPU(&ct->t_lwp->lwp_pcb);

	switch (fp_save_mech) {
	case FP_FXSAVE:
		fx = fp->fpu_regs.kfpu_u.kfpu_fx;
		cfx = cfp->fpu_regs.kfpu_u.kfpu_fx;
		bcopy(&sse_initial, cfx, sizeof (*cfx));
		cfx->fx_mxcsr = fx->fx_mxcsr & ~SSE_MXCSR_EFLAGS;
		cfx->fx_fcw = fx->fx_fcw;
		break;

	case FP_XSAVE:
		cfp->fpu_xsave_mask = fp->fpu_xsave_mask;

		VERIFY(fp->fpu_regs.kfpu_u.kfpu_xs != NULL);

		fx = &fp->fpu_regs.kfpu_u.kfpu_xs->xs_fxsave;
		cxs = cfp->fpu_regs.kfpu_u.kfpu_xs;
		cfx = &cxs->xs_fxsave;

		bcopy(&avx_initial, cxs, sizeof (*cxs));
		cfx->fx_mxcsr = fx->fx_mxcsr & ~SSE_MXCSR_EFLAGS;
		cfx->fx_fcw = fx->fx_fcw;
		cxs->xs_xstate_bv |= (get_xcr(XFEATURE_ENABLED_MASK) &
		    XFEATURE_FP_INITIAL);
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}

	/*
	 * Mark that both the parent and child need to have the FPU cleaned up
	 * before returning to user land.
	 */

	installctx(ct, cfp, fpsave_ctxt, fprestore_ctxt, fp_new_lwp,
	    fp_new_lwp, NULL, fp_free);
}

/*
 * Free any state associated with floating point context.
 * Fp_free can be called in three cases:
 * 1) from reaper -> thread_free -> freectx-> fp_free
 *	fp context belongs to a thread on deathrow
 *	nothing to do,  thread will never be resumed
 *	thread calling ctxfree is reaper
 *
 * 2) from exec -> freectx -> fp_free
 *	fp context belongs to the current thread
 *	must disable fpu, thread calling ctxfree is curthread
 *
 * 3) from restorecontext -> setfpregs -> fp_free
 *	we have a modified context in the memory (lwp->pcb_fpu)
 *	disable fpu and release the fp context for the CPU
 *
 */
/*ARGSUSED*/
void
fp_free(struct fpu_ctx *fp, int isexec)
{
	ASSERT(fp_kind != FP_NO);

	if (fp->fpu_flags & FPU_VALID)
		return;

	kpreempt_disable();
	/*
	 * We want to do fpsave rather than fpdisable so that we can
	 * keep the fpu_flags as FPU_VALID tracking the CR0_TS bit
	 */
	fp->fpu_flags |= FPU_VALID;
	/* If for current thread disable FP to track FPU_VALID */
	if (curthread->t_lwp && fp == &curthread->t_lwp->lwp_pcb.pcb_fpu) {
		/* Clear errors if any to prevent frstor from complaining */
		(void) fperr_reset();
		if (fp_kind & __FP_SSE)
			(void) fpxerr_reset();
		fpdisable();
	}
	kpreempt_enable();
}

/*
 * Store the floating point state and disable the floating point unit.
 */
void
fp_save(struct fpu_ctx *fp)
{
	ASSERT(fp_kind != FP_NO);

	kpreempt_disable();
	if (!fp || fp->fpu_flags & FPU_VALID) {
		kpreempt_enable();
		return;
	}
	ASSERT(curthread->t_lwp && fp == &curthread->t_lwp->lwp_pcb.pcb_fpu);

	switch (fp_save_mech) {
	case FP_FXSAVE:
		fpxsave(fp->fpu_regs.kfpu_u.kfpu_fx);
		break;

	case FP_XSAVE:
		xsavep(fp->fpu_regs.kfpu_u.kfpu_xs, fp->fpu_xsave_mask);
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}

	fp->fpu_flags |= FPU_VALID;

	/*
	 * We save the FPU as part of forking, execing, modifications via /proc,
	 * restorecontext, etc. As such, we need to make sure that we return to
	 * userland with valid state in the FPU. If we're context switched out
	 * before we hit sys_rtt_common() we'll end up having restored the FPU
	 * as part of the context ops operations. The restore logic always makes
	 * sure that FPU_VALID is set before doing a restore so we don't restore
	 * it a second time.
	 */
	PCB_SET_UPDATE_FPU(&curthread->t_lwp->lwp_pcb);

	kpreempt_enable();
}

/*
 * Restore the FPU context for the thread:
 * The possibilities are:
 *	1. No active FPU context: Load the new context into the FPU hw
 *	   and enable the FPU.
 */
void
fp_restore(struct fpu_ctx *fp)
{
	switch (fp_save_mech) {
	case FP_FXSAVE:
		fpxrestore(fp->fpu_regs.kfpu_u.kfpu_fx);
		break;

	case FP_XSAVE:
		xrestore(fp->fpu_regs.kfpu_u.kfpu_xs, fp->fpu_xsave_mask);
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}

	fp->fpu_flags &= ~FPU_VALID;
}

/*
 * Reset the FPU such that it is in a valid state for a new thread that is
 * coming out of exec. The FPU will be in a usable state at this point. At this
 * point we know that the FPU state has already been allocated and if this
 * wasn't an init process, then it will have had fp_free() previously called.
 */
void
fp_exec(void)
{
	struct fpu_ctx *fp = &ttolwp(curthread)->lwp_pcb.pcb_fpu;

	if (fp_save_mech == FP_XSAVE) {
		fp->fpu_xsave_mask = XFEATURE_FP_ALL;
	}

	/*
	 * Make sure that we're not preempted in the middle of initializing the
	 * FPU on CPU.
	 */
	kpreempt_disable();
	installctx(curthread, fp, fpsave_ctxt, fprestore_ctxt, fp_new_lwp,
	    fp_new_lwp, NULL, fp_free);
	fpinit();
	fp->fpu_flags = FPU_EN;
	kpreempt_enable();
}


/*
 * Seeds the initial state for the current thread.  The possibilities are:
 *      1. Another process has modified the FPU state before we have done any
 *         initialization: Load the FPU state from the LWP state.
 *      2. The FPU state has not been externally modified:  Load a clean state.
 */
void
fp_seed(void)
{
	struct fpu_ctx *fp = &ttolwp(curthread)->lwp_pcb.pcb_fpu;

	ASSERT(curthread->t_preempt >= 1);
	ASSERT((fp->fpu_flags & FPU_EN) == 0);

	/*
	 * Always initialize a new context and initialize the hardware.
	 */
	if (fp_save_mech == FP_XSAVE) {
		fp->fpu_xsave_mask = XFEATURE_FP_ALL;
	}

	installctx(curthread, fp, fpsave_ctxt, fprestore_ctxt, fp_new_lwp,
	    fp_new_lwp, NULL, fp_free);
	fpinit();

	/*
	 * If FPU_VALID is set, it means someone has modified registers via
	 * /proc.  In this case, restore the current lwp's state.
	 */
	if (fp->fpu_flags & FPU_VALID)
		fp_restore(fp);

	ASSERT((fp->fpu_flags & FPU_VALID) == 0);
	fp->fpu_flags = FPU_EN;
}

/*
 * When using xsave/xrstor, these three functions are used by the lwp code to
 * manage the memory for the xsave area.
 */
void
fp_lwp_init(struct _klwp *lwp)
{
	struct fpu_ctx *fp = &lwp->lwp_pcb.pcb_fpu;

	/*
	 * We keep a copy of the pointer in lwp_fpu so that we can restore the
	 * value in forklwp() after we duplicate the parent's LWP state.
	 */
	lwp->lwp_fpu = fp->fpu_regs.kfpu_u.kfpu_generic =
	    kmem_cache_alloc(fpsave_cachep, KM_SLEEP);

	if (fp_save_mech == FP_XSAVE) {
		/*
		 *
		 * We bzero since the fpinit() code path will only
		 * partially initialize the xsave area using avx_inital.
		 */
		ASSERT(cpuid_get_xsave_size() >= sizeof (struct xsave_state));
		bzero(fp->fpu_regs.kfpu_u.kfpu_xs, cpuid_get_xsave_size());
	}
}

void
fp_lwp_cleanup(struct _klwp *lwp)
{
	struct fpu_ctx *fp = &lwp->lwp_pcb.pcb_fpu;

	if (fp->fpu_regs.kfpu_u.kfpu_generic != NULL) {
		kmem_cache_free(fpsave_cachep,
		    fp->fpu_regs.kfpu_u.kfpu_generic);
		lwp->lwp_fpu = fp->fpu_regs.kfpu_u.kfpu_generic = NULL;
	}
}

/*
 * Called during the process of forklwp(). The kfpu_u pointer will have been
 * overwritten while copying the parent's LWP structure. We have a valid copy
 * stashed in the child's lwp_fpu which we use to restore the correct value.
 */
void
fp_lwp_dup(struct _klwp *lwp)
{
	void *xp = lwp->lwp_fpu;
	size_t sz;

	switch (fp_save_mech) {
	case FP_FXSAVE:
		sz = sizeof (struct fxsave_state);
		break;
	case FP_XSAVE:
		sz = cpuid_get_xsave_size();
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}

	/* copy the parent's values into the new lwp's struct */
	bcopy(lwp->lwp_pcb.pcb_fpu.fpu_regs.kfpu_u.kfpu_generic, xp, sz);
	/* now restore the pointer */
	lwp->lwp_pcb.pcb_fpu.fpu_regs.kfpu_u.kfpu_generic = xp;
}

/*
 * Handle a processor extension error fault
 * Returns non zero for error.
 */

/*ARGSUSED*/
int
fpexterrflt(struct regs *rp)
{
	uint32_t fpcw, fpsw;
	fpu_ctx_t *fp = &ttolwp(curthread)->lwp_pcb.pcb_fpu;

	ASSERT(fp_kind != FP_NO);

	/*
	 * Now we can enable the interrupts.
	 * (NOTE: x87 fp exceptions come thru interrupt gate)
	 */
	sti();

	if (!fpu_exists)
		return (FPE_FLTINV);

	/*
	 * Do an unconditional save of the FP state.  If it's dirty (TS=0),
	 * it'll be saved into the fpu context area passed in (that of the
	 * current thread).  If it's not dirty (it may not be, due to
	 * an intervening save due to a context switch between the sti(),
	 * above and here, then it's safe to just use the stored values in
	 * the context save area to determine the cause of the fault.
	 */
	fp_save(fp);

	/* clear exception flags in saved state, as if by fnclex */
	switch (fp_save_mech) {
	case FP_FXSAVE:
		fpsw = fp->fpu_regs.kfpu_u.kfpu_fx->fx_fsw;
		fpcw = fp->fpu_regs.kfpu_u.kfpu_fx->fx_fcw;
		fp->fpu_regs.kfpu_u.kfpu_fx->fx_fsw &= ~FPS_SW_EFLAGS;
		break;

	case FP_XSAVE:
		fpsw = fp->fpu_regs.kfpu_u.kfpu_xs->xs_fxsave.fx_fsw;
		fpcw = fp->fpu_regs.kfpu_u.kfpu_xs->xs_fxsave.fx_fcw;
		fp->fpu_regs.kfpu_u.kfpu_xs->xs_fxsave.fx_fsw &= ~FPS_SW_EFLAGS;
		/*
		 * Always set LEGACY_FP as it may have been cleared by XSAVE
		 * instruction
		 */
		fp->fpu_regs.kfpu_u.kfpu_xs->xs_xstate_bv |= XFEATURE_LEGACY_FP;
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}

	fp->fpu_regs.kfpu_status = fpsw;

	if ((fpsw & FPS_ES) == 0)
		return (0);		/* No exception */

	/*
	 * "and" the exception flags with the complement of the mask
	 * bits to determine which exception occurred
	 */
	return (fpe_sicode(fpsw & ~fpcw & 0x3f));
}

/*
 * Handle an SSE/SSE2 precise exception.
 * Returns a non-zero sicode for error.
 */
/*ARGSUSED*/
int
fpsimderrflt(struct regs *rp)
{
	uint32_t mxcsr, xmask;
	fpu_ctx_t *fp = &ttolwp(curthread)->lwp_pcb.pcb_fpu;

	ASSERT(fp_kind & __FP_SSE);

	/*
	 * NOTE: Interrupts are disabled during execution of this
	 * function.  They are enabled by the caller in trap.c.
	 */

	/*
	 * The only way we could have gotten here if there is no FP unit
	 * is via a user executing an INT $19 instruction, so there is
	 * no fault in that case.
	 */
	if (!fpu_exists)
		return (0);

	/*
	 * Do an unconditional save of the FP state.  If it's dirty (TS=0),
	 * it'll be saved into the fpu context area passed in (that of the
	 * current thread).  If it's not dirty, then it's safe to just use
	 * the stored values in the context save area to determine the
	 * cause of the fault.
	 */
	fp_save(fp);		/* save the FPU state */

	if (fp_save_mech == FP_XSAVE) {
		mxcsr = fp->fpu_regs.kfpu_u.kfpu_xs->xs_fxsave.fx_mxcsr;
		fp->fpu_regs.kfpu_status =
		    fp->fpu_regs.kfpu_u.kfpu_xs->xs_fxsave.fx_fsw;
	} else {
		mxcsr = fp->fpu_regs.kfpu_u.kfpu_fx->fx_mxcsr;
		fp->fpu_regs.kfpu_status = fp->fpu_regs.kfpu_u.kfpu_fx->fx_fsw;
	}
	fp->fpu_regs.kfpu_xstatus = mxcsr;

	/*
	 * compute the mask that determines which conditions can cause
	 * a #xm exception, and use this to clean the status bits so that
	 * we can identify the true cause of this one.
	 */
	xmask = (mxcsr >> 7) & SSE_MXCSR_EFLAGS;
	return (fpe_simd_sicode((mxcsr & SSE_MXCSR_EFLAGS) & ~xmask));
}

/*
 * In the unlikely event that someone is relying on this subcode being
 * FPE_FLTILL for denormalize exceptions, it can always be patched back
 * again to restore old behaviour.
 */
int fpe_fltden = FPE_FLTDEN;

/*
 * Map from the FPU status word to the FP exception si_code.
 */
static int
fpe_sicode(uint_t sw)
{
	if (sw & FPS_IE)
		return (FPE_FLTINV);
	if (sw & FPS_ZE)
		return (FPE_FLTDIV);
	if (sw & FPS_DE)
		return (fpe_fltden);
	if (sw & FPS_OE)
		return (FPE_FLTOVF);
	if (sw & FPS_UE)
		return (FPE_FLTUND);
	if (sw & FPS_PE)
		return (FPE_FLTRES);
	return (FPE_FLTINV);	/* default si_code for other exceptions */
}

/*
 * Map from the SSE status word to the FP exception si_code.
 */
static int
fpe_simd_sicode(uint_t sw)
{
	if (sw & SSE_IE)
		return (FPE_FLTINV);
	if (sw & SSE_ZE)
		return (FPE_FLTDIV);
	if (sw & SSE_DE)
		return (FPE_FLTDEN);
	if (sw & SSE_OE)
		return (FPE_FLTOVF);
	if (sw & SSE_UE)
		return (FPE_FLTUND);
	if (sw & SSE_PE)
		return (FPE_FLTRES);
	return (FPE_FLTINV);	/* default si_code for other exceptions */
}

/*
 * This routine is invoked as part of libc's __fpstart implementation
 * via sysi86(2).
 *
 * It may be called -before- any context has been assigned in which case
 * we try and avoid touching the hardware.  Or it may be invoked well
 * after the context has been assigned and fiddled with, in which case
 * just tweak it directly.
 */
void
fpsetcw(uint16_t fcw, uint32_t mxcsr)
{
	struct fpu_ctx *fp = &curthread->t_lwp->lwp_pcb.pcb_fpu;
	struct fxsave_state *fx;

	if (!fpu_exists || fp_kind == FP_NO)
		return;

	if ((fp->fpu_flags & FPU_EN) == 0) {
		if (fcw == FPU_CW_INIT && mxcsr == SSE_MXCSR_INIT) {
			/*
			 * Common case.  Floating point unit not yet
			 * enabled, and kernel already intends to initialize
			 * the hardware the way the caller wants.
			 */
			return;
		}
		/*
		 * Hmm.  Userland wants a different default.
		 * Do a fake "first trap" to establish the context, then
		 * handle as if we already had a context before we came in.
		 */
		kpreempt_disable();
		fp_seed();
		kpreempt_enable();
	}

	/*
	 * Ensure that the current hardware state is flushed back to the
	 * pcb, then modify that copy.  Next use of the fp will
	 * restore the context.
	 */
	fp_save(fp);

	switch (fp_save_mech) {
	case FP_FXSAVE:
		fx = fp->fpu_regs.kfpu_u.kfpu_fx;
		fx->fx_fcw = fcw;
		fx->fx_mxcsr = sse_mxcsr_mask & mxcsr;
		break;

	case FP_XSAVE:
		fx = &fp->fpu_regs.kfpu_u.kfpu_xs->xs_fxsave;
		fx->fx_fcw = fcw;
		fx->fx_mxcsr = sse_mxcsr_mask & mxcsr;
		/*
		 * Always set LEGACY_FP as it may have been cleared by XSAVE
		 * instruction
		 */
		fp->fpu_regs.kfpu_u.kfpu_xs->xs_xstate_bv |= XFEATURE_LEGACY_FP;
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}
}
