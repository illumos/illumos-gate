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
 * Copyright 2021 Joyent, Inc.
 * Copyright 2021 RackTop Systems, Inc.
 * Copyright 2023 Oxide Computer Company
 * Copyright 2025 Edgecast Cloud LLC.
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
#include <sys/kfpu.h>
#include <sys/stdbool.h>
#include <sys/stdalign.h>
#include <sys/procfs_isa.h>
#include <sys/sunddi.h>

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
 * idea of the FPU registers and more generally is called the Extended Processor
 * States:
 *
 *    o Traditional x87 FPU
 *    o Vector Registers (%xmm, %ymm, %zmm)
 *    o Memory Protection Extensions (MPX) Bounds Registers
 *    o Protected Key Rights Registers (PKRU)
 *    o Processor Trace data
 *    o Control-Flow Enforcement state
 *    o Hardware Duty Cycle
 *    o Hardware P-states
 *
 * The rest of this covers how the FPU is managed and controlled, how state is
 * saved and restored between threads, interactions with hypervisors, and other
 * information exported to userland through aux vectors. A lot of background
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
 * returning to userland. In general, this path should be rare, but it's useful
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
 * area and return to userland. Given the frequency of use of the FPU alone by
 * libc, there's no point returning to userland just to trap again.
 *
 * There are a few cases though where the FPU state may need to be changed for a
 * thread on its behalf. The most notable cases are in the case of processes
 * using /proc, restorecontext, forking, etc. In all of these cases the kernel
 * will force a threads FPU state to be saved into the PCB through the fp_save()
 * function. Whenever the FPU is saved, then the FPU_VALID flag is set on the
 * pcb. This indicates that the save state holds currently valid data. As a side
 * effect of this, CR0.TS will be set. To make sure that all of the state is
 * updated before returning to userland, in these cases, we set a flag on the
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
 * returning to userland and importantly, the only data that is in it is its
 * own.
 *
 * Kernel FPU Usage
 * ----------------
 *
 * Traditionally the kernel never used the FPU since it had no need for
 * floating point operations. However, modern FPU hardware supports a variety
 * of SIMD extensions which can speed up code such as parity calculations or
 * encryption.
 *
 * To allow the kernel to take advantage of these features, the
 * kernel_fpu_begin() and kernel_fpu_end() functions should be wrapped
 * around any usage of the FPU by the kernel to ensure that user-level context
 * is properly saved/restored, as well as to properly setup the FPU for use by
 * the kernel. There are a variety of ways this wrapping can be used, as
 * discussed in this section below.
 *
 * When kernel_fpu_begin() and kernel_fpu_end() are used for extended
 * operations, the kernel_fpu_alloc() function should be used to allocate a
 * kfpu_state_t structure that is used to save/restore the thread's kernel FPU
 * state. This structure is not tied to any thread. That is, different threads
 * can reuse the same kfpu_state_t structure, although not concurrently. A
 * kfpu_state_t structure is freed by the kernel_fpu_free() function.
 *
 * In some cases, the kernel may need to use the FPU for a short operation
 * without the overhead to manage a kfpu_state_t structure and without
 * allowing for a context switch off the FPU. In this case the KFPU_NO_STATE
 * bit can be set in the kernel_fpu_begin() and kernel_fpu_end() flags
 * parameter. This indicates that there is no kfpu_state_t. When used this way,
 * kernel preemption should be disabled by the caller (kpreempt_disable) before
 * calling kernel_fpu_begin(), and re-enabled after calling kernel_fpu_end().
 * For this usage, it is important to limit the kernel's FPU use to short
 * operations. The tradeoff between using the FPU without a kfpu_state_t
 * structure vs. the overhead of allowing a context switch while using the FPU
 * should be carefully considered on a case by case basis.
 *
 * In other cases, kernel threads have an LWP, but never execute in user space.
 * In this situation, the LWP's pcb_fpu area can be used to save/restore the
 * kernel's FPU state if the thread is context switched, instead of having to
 * allocate and manage a kfpu_state_t structure. The KFPU_USE_LWP bit in the
 * kernel_fpu_begin() and kernel_fpu_end() flags parameter is used to
 * enable this behavior. It is the caller's responsibility to ensure that this
 * is only used for a kernel thread which never executes in user space.
 *
 * FPU Exceptions
 * --------------
 *
 * Certain operations can cause the kernel to take traps due to FPU activity.
 * Generally these events will cause a user process to receive a SIGFPU and if
 * the kernel receives it in kernel context, we will die. Traditionally the #NM
 * (Device Not Available / No Math) exception generated by CR0.TS would have
 * caused us to restore the FPU. Now it is a fatal event regardless of whether
 * or not userland causes it.
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
 *
 * Signal Handling and the ucontext_t
 * ----------------------------------
 *
 * One of the many gifts that signals give us is the twofold fact that when a
 * signal occurs, the signal handler is allowed to change the CPU's state
 * arbitrarily and when the signal handler is done executing, we must restore it
 * back to the original state. However, the second part of this is that the
 * signal handler is actually allowed to modify the state that the thread will
 * return to! To create this facade, the kernel will create a full ucontext_t
 * state, effectively calling getcontext(2) on the thread's behalf, and a
 * pointer to that is given to the signal handler (the void * argument for the
 * sa_sigaction function pointer in sigaction(2)). When libc is done with a
 * signal, it will call setcontext(2) with that same ucontext_t.
 *
 * Now, the ucontext_t has a fixed ABI for both ILP32 and LP64 environments and
 * it's often declared on the stack itself, with the signal handler spilling all
 * this state to the stack. The ucontext_t machine portion was broken into the
 * general purpose and floating point registers. In 64-bit code, the floating
 * point registers were mostly the same as the results of the fxsave instruction
 * (i.e. struct fxsave_state). While the 64-bit kernel still uses the equivalent
 * starting point for information, it is transformed into a different shape to
 * deal with the history of the 32-bit SYS V ABI.
 *
 * While this worked, if you're reading this, you're aware that the x86 FPU and
 * extended register states didn't stop at the initial 16 128-bit %xmm
 * registers. Since then we have added 256-bit %ymm, 512-bit %zmm, and the %k
 * opmask registers. None of these fit inside the standard ucontext_t; however,
 * they must all be preserved and restored across a signal. While the various
 * x86 platform-specific ABIs all suggest that these registers are not preserved
 * across a function call, receiving a signal is not a function call and must be
 * thought of like a process receiving an interrupt. In other words, this
 * extended state must be preserved.
 *
 * To facilitate this, we have extended the ucontext_t structure with an
 * additional flag, UC_XSAVE, which indicates that the traditional padding
 * member, uc_xsave, actually is a pointer to the extended state. While this is
 * accessible outside of a signal handling context through the combination of
 * ucontext_alloc(3C) and getcontext_extd(2), our design around saving this
 * state is focused on signal handling. Signal handling spills all this state to
 * the stack and if we cannot spill the entire state to the stack then our
 * inability to deliver the signal results in the process being killed! While
 * there are separate efforts to ensure that the signal stack sizing that is
 * used for the minimum and maximum signal sizes are sufficient, we still need
 * to do our part to minimize the likelihood here.
 *
 * In designing this, we make the following observations which have helped us
 * focus our design:
 *
 *   o While the start of an xsave area is the traditional 512-byte fxsave XMM
 *     region, we already have that in the fpregs. Thus there is no reason to
 *     duplicate it. This not only saves 512 bytes of additional stack space,
 *     but it also means we don't have to ask which of the version of it to take
 *     if they were to differ.
 *
 *   o Many applications out there aren't necessarily using the extended vectors
 *     and even when we do make libc and others take advantage of it, it will
 *     behoove us to ensure that they are put back into their initial state
 *     after use. This leads us to expect that in a number of cases, the actual
 *     extended register state will be in its initial state.
 *
 *   o While the signal handler does allow contents to be modified, we are
 *     starting with making the interface private and thus allowing us to excise
 *     components that are in their initial state.
 *
 *   o There are similarities to what we want to create with the compressed
 *     xsave format; however, because we don't always have support for the
 *     compressed format, we can't just arbitrarily say let's do a compressed
 *     save to the user stack.
 *
 *   o Because we are not handing this state directly to and from hardware, we
 *     don't need to meet some of the constraints of the compressed xsave format
 *     around wanting alignment for the initial save or additional components.
 *
 * All of the above lead us to our own unique format for this data. When the
 * UC_XSAVE flag is set in the ucontext_t, the uc_xsave member points to a
 * uc_xsave_t structure which has a magic version number, a 32-bit length of the
 * overall structure, and the 64-bit state bit-vector to represent which
 * components are valid. Following this 8-byte header, each component that is
 * present in the bit vector is immediately written out in roughly ascending bit
 * order (the order is determined based on the order of the fpu_xsave_info
 * array).
 *
 * This makes the rough logic that we have here when taking a signal and writing
 * out this state as:
 *
 *   1. Ensure that the FPU is saved and that the contents of the pcb save area
 *      are valid. That is, call fp_save() if the state is not already flagged
 *      with FPU_VALID.
 *
 *   2. Copy the bit-vector from the save area and remove the XFEATURE_LEGACY_FP
 *      and XFEATURE_SSE bits as these will be placed in the xsave area.
 *
 *   3. Initialize the uc_xsave_t by setting our version field, initializing the
 *      length to the length of the current structure, and then setting the
 *      modified bit vector above.
 *
 *   4. Walk each remaining bit of the bit-vector. For each set bit, copy out
 *      its extended state starting at the current length in the header and then
 *      increase the header size by that length.
 *
 *   5. Finally write out the final uc_xsave_t structure.
 *
 * The above process is also used when someone manually calls getcontext_extd(2)
 * to get this state. The main difference between the two is which copyout
 * function we use. This deserves some explanation. Our main starting point for
 * all the logic here is fpu_signal_copyout(). It takes a copyfunc that allows
 * the signal handling context to operate with a different copyout than we
 * normally use in say getcontext_extd(2).
 *
 * When we've received a signal, we're at the intersection of several different
 * gotchas. Normal copyout (or ddi_copyout()) will trigger watchpoints. That is,
 * the watchpoints effectively set a copyout override function (t_copyops) that
 * we end up vectoring to rather than a normal copyout. This allows the data to
 * be modified and for the watchpoint to fire. While this is all well and good
 * normally, it is problematic if we are trying to handle a signal. The signal
 * deliver logic, sendsig(), goes through and disables the watchpoint for the
 * region of the stack that we are copying out to. However, disabling
 * watchpoints is not sufficient, we also need to use the copyout_noerr
 * variants.
 *
 * These variants also require the use of on_fault() and no_fault() for error
 * handling. While it is tempting to try and on_fault() the entire
 * fpu_signal_copyout() operation, that is actually fraught for a few reasons.
 * The first is that we don't want to disable faults during the entire operation
 * as if the kernel messes up we will treat that as a user error. That isn't
 * theoretical and happened during development. The second and perhaps more
 * important issue is that correctly bounding the on_fault() / no_fault() means
 * being careful about state. For example, kernel pre-emption is often disabled
 * during parts of these operations, but it needs to be re-enabled when we're
 * done. This would require tracking in some volatile variable that this had
 * been enabled and disabled and tracking that.
 *
 * Instead, this is why fpu_signal_copyout() takes a copy out function as an
 * argument. When we're in signal handling context, the function will use
 * coypout_noerr() and wrap it in the appropriate on_fault() mechanisms.
 *
 * RESTORING STATE
 *
 * Copying out our current state is the easier half of this problem. When the
 * kernel is done with a signal it calls setcontext(2) with the ucontext_t we
 * assembled for it as described above. setcontext(2) isn't just used for
 * returning from signals.
 *
 * The process for this goes in two steps. The first step is to copy in,
 * validate, and transform the ucontext_t UC_XSAVE that we created above into an
 * equivalent xsave format that we can use the appropriate xrstor function on.
 * This first phase is implemented in fpu_signal_copyin(). Once that is done, we
 * come back through a second phase that is driven out of restorecontext() and
 * is implemented in fpu_set_xsave().
 *
 * Let's start by discussing the second part of this, which is more
 * straightforward. In particular, the second phase assumes that all of the
 * validation and error handling has been done by the first phase. This means
 * here, we have a buffer that is already the appropriate size
 * (cpuid_get_xsave_size()) and all we need to do is make sure that we can
 * replace the actual save state with the current one.
 *
 * The only piece of shenanigans we have to do is around the kernel provided
 * notion of 'status' and 'xstatus', which are cached versions of the x87 and
 * SSE exception vectors. These are part of the fpregset ABI and therefore we
 * need to propagate them from the temporary storage that part 1 sets up in the
 * ignored region of the fxsave data. We use that because it is not persisted by
 * the CPU, so clobbering it is generally alright.
 *
 * Once that is done, we simply note that we need a PCB update to occur to
 * refresh the FPU state before we return to userland. Given that someone has
 * called setcontext(2), this was always going to happen because we have to
 * update segment registers and related, so this isn't so bad. With that, let's
 * move onto the more nuanced part (1).
 *
 * When we're handling a setcontext(2) we have, in userland, a data structure
 * that should match one we serialized out, though we cannot assume that a user
 * has not modified it either accidentally or maliciously. Our goal is to set up
 * the appropriate xsave state that can be passed to the CPU's xrstor. The first
 * problem we have to deal with is where do we actually put this state?
 *
 * While not many programs actually call setcontext(2) of their own volition,
 * this is going to get hit every time we take a signal. The first thought was
 * to re-use the existing thread's save area; however, that's a bit challenging
 * for a few reasons. In particular, we would need to ensure that we don't go
 * off-CPU for any reason, which we cannot assume with a copyin from a user
 * address space. In particular, it is trivial for us to hit a case where the
 * stack has been paged out for some reason, which eschews that path.
 *
 * Instead, whenever a thread first calls setcontext(2), generally from signal
 * context, we will at that time allocate another entry from the 'fpsave_cachep'
 * kmem cache, giving us a buffer of the appropriate space to handle this. Once
 * this buffer has been allocated, we leave it assigned to the thread's pcb and
 * only tear it down when the thread itself finally exits. We reason that a
 * thread that takes a signal once is either going to have the process exit
 * shortly thereafter or is much more likely to take a signal again in the
 * future. Many daemons and other processes set things up so signals are
 * dispatched via one location, masking signals in other thread, using
 * sigsuspend(2), signalfd(3C), or something similar.
 *
 * With this buffer in hand, we begin our task of reassembling state. Note, all
 * of this is conditional on UC_XSAVE being set in the uc_flags member of the
 * ucontext_t. If it is not set, then we assume that there is no extended state
 * and will use the traditional path of setting the fpregset_t into the system
 * via setfpregs().
 *
 * We first will copyin and validate the uc_xsave_t. In particular, we need to
 * make sure the version makes sense, that the xsave component bit-vector
 * doesn't have anything unexpected and more importantly unsupported in it, and
 * that the addresses we've been given are within the user address space. At
 * this point we can walk through our table of implemented bits and process
 * them.
 *
 * For most components in here, the processing is straightforward. We continue
 * walking our cursor and copy data into the kernel and place it in the
 * appropriate place in our xsave state. If a xsave state component bit-vector
 * isn't set, then we must ensure that we have the item in the initial state,
 * which for everything other than the x87/SSE state is the memory being zeroed.
 *
 * The most unique case in the copyin state is that of the x87/SSE state. You
 * might recall that we didn't copy it out explicitly as part of the uc_xsave_t,
 * but instead have opted to use the single definition in the fpregset_t. Thus
 * here, we copy it out of the fpregset_t, which the kernel has helpfully
 * already unified into the 64-bit fxsave version prior to calling us, and
 * install that into the save area we're building up.
 *
 * As part of this, there are two important pieces to be aware of. The first is
 * that because the fpregset_t has both the status and xstatus members
 * mentioned earlier, we temporarily copy them to the software-usable ignored
 * areas of the fxsave state so we can corral this extra state into part (2)
 * without needing to allocate additional space. The second piece is that when
 * we're done processing this we explicitly remove the UC_FPU flag that would
 * tell the kernel to proceed with updating that region. The problem is that
 * that goes directly into the pcb's save area and not to the intermediate
 * buffer as it uses the same entry point as /proc, mainly setfpregs().
 *
 * We don't do much validation of the actual contents of the registers that are
 * being set with the exception of ensuring that no reserved bits of the mxcsr
 * are used. This is not as strict as /proc, but failure here means the process
 * is likely going to die (returning from setcontext() in a signal handler is
 * fatal).
 *
 * /proc xregs
 * -----------
 *
 * Observability of the state of the extended registers is important for
 * understanding the system. While on the surface this is similar to signal
 * handling, it is crucially different in a number of ways:
 *
 *   o In signal handling, we're trying to conserve every byte of stack that we
 *     can.
 *   o The /proc xregs file will end up in core files, which means that we need
 *     a way of knowing what components are present and not present in it,
 *     because this will vary from CPU to CPU due to the addition of
 *     architectural features. For example, some CPUs support AVX-512, but
 *     others do not.
 *
 *   o The signal handling structure (uc_xsave_t) is private and we're not
 *     trying to have software modify it, on the other hand, the /proc
 *     interfaces that we support we do want software to be able to interrogate
 *     and manipulate. These need to be something that we can introduce
 *     additional components into and make other changes that still allow it to
 *     work.
 *
 * The x86 xregs format is documented in proc(5). The short form is that the
 * prxregset_hdr_t has a number of information entries, which are of the type
 * prxregset_info_t. Each of the information headers has a type, size, and
 * offset which indicate where to find the additional data.
 *
 * Each entry is described as one of the entries in the fpu_xsave_info[]. These
 * items either are a 1:1 correspondence with a xsave related feature (e.g.
 * there is one entry for each of the three AVX-512 components) or it is
 * something synthetic that we provide as additional information such as the
 * PRX_INFO_XCR, which is a way of getting information about the system such as
 * what is enabled in %xcr0 out there.
 *
 * Unlike signal handling, we are given the buffer to place everything that
 * needs to be written out. This is partially the design of the /proc APIs. That
 * is, we will always assemble everything into the entire buffer that /proc asks
 * us to, and then it will use as much or as little of it as is required.
 * Similarly, when setting things, we don't have to worry about copying in
 * information in the same way as signal handling does, because /proc takes care
 * of it and always hands us a full buffer. Sizing that is a little nuanced, but
 * is all handled in prmachdep.c.
 *
 * When someone performs a read of the xregs and thus is asking us for the
 * current state, there is a little bit of nuance that we need to deal with.
 * The first, is whether or not the FPU is enabled and the second is if the FPU
 * is enabled, whether a given component is noted as being in its initial state.
 * This basically gives us three possible states for a given component:
 *
 *   1. FPU_EN is not set and FPU_VALID is not set. This means we need to take
 *      the illumos FPU default for an item. More on that in a moment.
 *   2. The saved xsave state indicates that the bit for a given component is
 *      zero -- specifically the xsh_xstate_bv member of the struct xsave_state.
 *      In this case, we must take the CPU's default for an item. This is
 *      usually the same as illumos, but not always.
 *   3. The saved xsave state indicates that a given component's state bit is
 *      valid. The simplest of our cases. We can just take what we have from the
 *      xsave state.
 *
 * The CPU's default state for most components other than the x87/SSE state is
 * to have it be zeroed. This is what we treat as our default state as well. The
 * primary difference is in the initialization of the x87/SSE state. The SYS V
 * ABI requires that we enable a different floating point control word then the
 * hardware default. This means that when we're dealing with case (1) for
 * x87/SSE we have to be more careful than the other components. Thankfully for
 * everything else this is just keeping it zeroed.
 *
 * A reasonable question would be why not just skip components that aren't
 * marked as present. There are a few reasons we take a different approach and
 * always include them. Both of these are to make lives simpler for consumers.
 * In the first case, when someone is performing a read and wants to reassemble
 * and answer the question of 'what is the value of %ymm0 or %zmm15', they have
 * to combine multiple disparate parts. If one knows that the data we put into
 * there is always valid and represents what is in hardware and doesn't have to
 * keep track of what are the defaults in different circumstances, then that
 * greatly simplifies consumers lives. It also helps us for core files and other
 * observability cases because the answer to what is the operating system's
 * default may change over time.
 *
 * Similarly, including all the possible structures means that we have
 * simplified writes. Writes are always setting the full state of a thread,
 * meaning that if someone wants to modify only a single register they must do a
 * read, modify, and write. By including everything that they might need, it
 * makes it easier for consumers to do this and not have to cons up the whole
 * structure on their own.
 *
 * When we're setting state, things change around a little bit. We have a few
 * constraints that are laid out in proc(5). In particular, we require that the
 * PRX_INFO_XSAVE component always be present to tell us which other components
 * we expect to be here and which ones we don't. We also are much stricter about
 * writes in several ways. Of all the components, the PRX_INFO_XCR is read-only
 * and may not be modified by a calling process. In addition, when we have
 * 32-bit applications which have reserved registers in the %ymm, %zmm, etc.
 * components, if they are being written to and have modifications, then we will
 * indicate an error there.
 *
 * Because we are given the entire buffer from userland and don't need to have
 * an intermediate place to copy it in, we will validate the entire thing in
 * advance. Once it has been validated and we consider it legal, then we will
 * translate each entry into its corresponding entry in pcb's normal floating
 * point state. This is different from signal handling mostly because of the
 * fact that we are not using copyin, and once we get to this point, there is
 * no more validation, so we don't have the same concerns around blocking while
 * pre-emption is disabled.
 *
 * The Wrinkle with fpregs
 * -----------------------
 *
 * When we instead turn our attention to the fpregs, whether we're gathering
 * them as part of the ucontext_t or as part of /proc, there are a few
 * complications that we need to be aware of when we're operating on a kernel
 * that is using xsave as the save mechanism. When we're using fxsave as the
 * save mechanism, the CPU will always save the entire 512-byte fxsave region.
 * The fpregs ABI that the kernel expects is basically this structure itself,
 * which is transformed into a 32-bit compatible form in archdep.c.
 *
 * But xsave makes this much more complex and has historically been a source of
 * bugs in the system. In particular, unlike fxsave, xsave has its component bit
 * vector that is written out to indicate validity. This means that blindly
 * copying the fxsave area without checking those bits will lead us to do the
 * wrong thing. The XMM state flag mostly covers the 16 128-bit %xmm registers,
 * while the x87 legacy fp flag covers the rest of the state. This is all good,
 * aside from the MCXSR.
 *
 * One of the more complicated pieces of xsave state management is correctly
 * answering the question of when the MXCSR is written out to xsave_state. In
 * practice, this is rather convoluted and varies. If either the XMM or AVX
 * feature bits are set then the CPU will write out the MXCSR and its mask
 * register into the traditional fxsave state region. This behavior is dependent
 * on the type of save function that we use. xsave and xsaveopt will look at the
 * AVX feature bit; however, xsavec does not and only considers the SSE feature
 * bit. This means that when we're retrieving things, we need to check both of
 * those bits to determine if we should use the initial state or the value
 * written out.
 *
 * When we come to someone trying to set the fpregs through /proc, the main
 * question we have is what happens to the extended registers. We have opted to
 * implement and document it such that a write to the fpregs only impacts the
 * fpregs. Put differently, we will save the FPU state with fp_save() ahead of
 * copying the data into the save area, set the state bits for x87 and XMM
 * state, and then set the FPU to be restored. All in all, this basically means
 * that writing to fpregs does not touch any of the %ymm, %zmm, or other state
 * that we might have present.
 *
 * Forward Looking: Adding Intel AMX Support
 * -----------------------------------------
 *
 * Nothing can stop the march of features being added into the FPU. One of the
 * larger chunks that we will need to wrangle with is Intel's Advanced Matrix
 * Extensions (AMX), which add a large chunk of xsave state to each process.
 * While things like AVX and AVX-512 have been enabled by default, the broader
 * OS community has not been wanting to do this for AMX ,because of the size of
 * the state which exceeds 8 KiB. While the signal handling state went out of
 * its way to minimize the size it wrote to the stack, if this is used, it would
 * need to be preserved.
 *
 * To deal with this reality and the fact that folks don't really want to
 * enable it by default for all purposes when its use will be quite special
 * purpose, Intel has also added a MSR around extended feature disable or xfd.
 * This is what we represent in the PRX_INFO_XCR prx_xfd member. Our starting
 * assumption, and the reason that so much of the /proc and signal logic ensures
 * that we have the thread and process around, taking as an example the unused
 * process argument in fpu_proc_xregs_info(), is that we will follow suit and
 * default to having support disabled, but that a process will be able to opt
 * into it, which will result in several different assumptions around signal
 * stack sizing and cause us to reallocate and extend the pcb's FPU save state.
 *
 * The following is a list of items to pay attention to for future folks who
 * work on this:
 *
 *   o We will want to confirm whether other systems have opted to make this
 *     process-wide or thread-wide. Assuming process-wide, we will need to do a
 *     hold of all lwps while making a change. The interface for that probably
 *     doesn't want to be /proc, as a process probably doesn't want to write to
 *     its own control file. Changing it for another process could be done
 *     through the agent-lwp.
 *   o Opting into this should probably be a one-way street.
 *   o Opting into this will need to evaluate all threads and in particular
 *     stack sizes to confirm they adhere to the new minimum.
 *   o We will need to make sure that setting and clearing the xfd MSR is part
 *     of the FPU context ops and something we set by default on every CPU.
 *   o We will need to add a new interface to allow opting into this feature.
 *   o We will need to ensure that all subsequently created signal stacks adhere
 *     to a required minimum size that we communicate through libc.
 *   o We will need to make sure that both rtld and libc no longer rely on a
 *     static value of the AT_SUN_FPSIZE, but rather realize that this can be
 *     dynamic. At that time, we should evaluate if we can get away with not
 *     needing to save this for rtld, even though signal handlers should assume
 *     they will.
 *   o The various components (because there is more than one) will want to be
 *     added to the fpu_xsave_info[]. Consulting the processes's xfd will be
 *     required and probably require logic changes.
 *
 * The above is not exhaustive. We'll probably have some other issues and fun
 * while doing this.
 */

/*
 * The kind of FPU we advertise to rtld so it knows what to do when working
 * through the PLT.
 */
int fp_elf = AT_386_FPINFO_FXSAVE;

/*
 * Mechanism to save FPU state.
 */
int fp_save_mech = FP_FXSAVE;

/*
 * See section 10.5.1 in the Intel 64 and IA-32 Architectures Software
 * Developer's Manual, Volume 1.
 */
#define	FXSAVE_ALIGN	16

/*
 * See section 13.4 in the Intel 64 and IA-32 Architectures Software
 * Developer's Manual, Volume 1.
 */
#define	XSAVE_ALIGN	64

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
 * Basic architectural alignment information.
 */
#define	FPU_ALIGN_XMM	16
#define	FPU_ALIGN_YMM	32
#define	FPU_ALIGN_ZMM	64

/*
 * This structure is the x86 implementation of the kernel FPU that is defined in
 * uts/common/sys/kfpu.h.
 */

typedef enum kfpu_flags {
	/*
	 * This indicates that the save state has initial FPU data.
	 */
	KFPU_F_INITIALIZED = 0x01
} kfpu_flags_t;

struct kfpu_state {
	fpu_ctx_t	kfpu_ctx;
	kfpu_flags_t	kfpu_flags;
	kthread_t	*kfpu_curthread;
};

/*
 * Initial kfpu state for SSE/SSE2 used by fpinit()
 */
const struct fxsave_state sse_initial = {
	FPU_CW_INIT,	/* fx_fcw */
	0,		/* fx_fsw */
	0,		/* fx_fctw */
	0,		/* fx_fop */
	0,		/* fx_rip */
	0,		/* fx_rdp */
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
	.xs_fxsave = {
		.fx_fcw = FPU_CW_INIT,
		.fx_mxcsr = SSE_MXCSR_INIT,
	},
	.xs_header = {
		/*
		 * bit0 = 1 for XSTATE_BV to indicate that legacy fields are
		 * valid, and CPU should initialize XMM/YMM.
		 */
		.xsh_xstate_bv = 1,
		.xsh_xcomp_bv = 0,
	},
};

/*
 * mxcsr_mask value (possibly reset in fpu_probe); used to avoid
 * the #gp exception caused by setting unsupported bits in the
 * MXCSR register
 */
uint32_t sse_mxcsr_mask = SSE_MXCSR_MASK_DEFAULT;

/*
 * This vector is patched to xsave_ctxt() or xsaveopt_ctxt() if we discover we
 * have an XSAVE-capable chip in fpu_probe.
 */
void (*fpsave_ctxt)(void *) = fpxsave_ctxt;
void (*fprestore_ctxt)(void *) = fpxrestore_ctxt;

/*
 * This function pointer is changed to xsaveopt if the CPU is xsaveopt capable.
 */
void (*xsavep)(struct xsave_state *, uint64_t) = xsave;

static int fpe_sicode(uint_t);
static int fpe_simd_sicode(uint_t);
static void fp_new_lwp(void *, void *);
static void fp_free_ctx(void *, int);

static struct ctxop *
fp_ctxop_allocate(struct fpu_ctx *fp)
{
	const struct ctxop_template tpl = {
		.ct_rev		= CTXOP_TPL_REV,
		.ct_save	= fpsave_ctxt,
		.ct_restore	= fprestore_ctxt,
		.ct_fork	= fp_new_lwp,
		.ct_lwp_create	= fp_new_lwp,
		.ct_free	= fp_free_ctx,
	};
	return (ctxop_allocate(&tpl, fp));
}

/*
 * Copy the state of parent lwp's floating point context into the new lwp.
 * Invoked for both fork() and lwp_create().
 *
 * Note that we inherit -only- the control state (e.g. exception masks,
 * rounding, precision control, etc.); the FPU registers are otherwise
 * reset to their initial state.
 */
static void
fp_new_lwp(void *parent, void *child)
{
	kthread_id_t t = parent, ct = child;
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
		cxs->xs_header.xsh_xstate_bv |=
		    (get_xcr(XFEATURE_ENABLED_MASK) & XFEATURE_FP_INITIAL);
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}

	/*
	 * Mark that both the parent and child need to have the FPU cleaned up
	 * before returning to userland.
	 */

	ctxop_attach(ct, fp_ctxop_allocate(cfp));
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
void
fp_free(struct fpu_ctx *fp)
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
 * Wrapper for freectx to make the types line up for fp_free()
 */
static void
fp_free_ctx(void *arg, int isexec __unused)
{
	fp_free((struct fpu_ctx *)arg);
}

/*
 * Store the floating point state and disable the floating point unit.
 */
void
fp_save(struct fpu_ctx *fp)
{
	ASSERT(fp_kind != FP_NO);

	kpreempt_disable();
	if (!fp || fp->fpu_flags & FPU_VALID ||
	    (fp->fpu_flags & FPU_EN) == 0) {
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

	struct ctxop *ctx = fp_ctxop_allocate(fp);
	/*
	 * Make sure that we're not preempted in the middle of initializing the
	 * FPU on CPU.
	 */
	kpreempt_disable();
	ctxop_attach(curthread, ctx);
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

	ctxop_attach(curthread, fp_ctxop_allocate(fp));
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
fp_lwp_init(klwp_t *lwp)
{
	struct fpu_ctx *fp = &lwp->lwp_pcb.pcb_fpu;

	/*
	 * We keep a copy of the pointer in lwp_fpu so that we can restore the
	 * value in forklwp() after we duplicate the parent's LWP state.
	 */
	lwp->lwp_fpu = fp->fpu_regs.kfpu_u.kfpu_generic =
	    kmem_cache_alloc(fpsave_cachep, KM_SLEEP);
	fp->fpu_signal = NULL;

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
fp_lwp_cleanup(klwp_t *lwp)
{
	struct fpu_ctx *fp = &lwp->lwp_pcb.pcb_fpu;

	if (fp->fpu_regs.kfpu_u.kfpu_generic != NULL) {
		kmem_cache_free(fpsave_cachep,
		    fp->fpu_regs.kfpu_u.kfpu_generic);
		lwp->lwp_fpu = fp->fpu_regs.kfpu_u.kfpu_generic = NULL;
	}

	if (fp->fpu_signal != NULL) {
		kmem_cache_free(fpsave_cachep, fp->fpu_signal);
		fp->fpu_signal = NULL;
	}
}

/*
 * Called during the process of forklwp(). The kfpu_u pointer will have been
 * overwritten while copying the parent's LWP structure. We have a valid copy
 * stashed in the child's lwp_fpu which we use to restore the correct value.
 */
void
fp_lwp_dup(klwp_t *lwp)
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
	/* Ensure that we don't inherit our parent's signal state */
	lwp->lwp_pcb.pcb_fpu.fpu_signal = NULL;
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
		fp->fpu_regs.kfpu_u.kfpu_xs->xs_header.xsh_xstate_bv |=
		    XFEATURE_LEGACY_FP;
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
		fp->fpu_regs.kfpu_u.kfpu_xs->xs_header.xsh_xstate_bv |=
		    XFEATURE_LEGACY_FP;
		break;
	default:
		panic("Invalid fp_save_mech");
		/*NOTREACHED*/
	}
}

static void
kernel_fpu_fpstate_init(kfpu_state_t *kfpu)
{
	struct xsave_state *xs;

	switch (fp_save_mech) {
	case FP_FXSAVE:
		bcopy(&sse_initial, kfpu->kfpu_ctx.fpu_regs.kfpu_u.kfpu_fx,
		    sizeof (struct fxsave_state));
		kfpu->kfpu_ctx.fpu_xsave_mask = 0;
		break;
	case FP_XSAVE:
		xs = kfpu->kfpu_ctx.fpu_regs.kfpu_u.kfpu_xs;
		bzero(xs, cpuid_get_xsave_size());
		bcopy(&avx_initial, xs, sizeof (*xs));
		xs->xs_header.xsh_xstate_bv = XFEATURE_LEGACY_FP | XFEATURE_SSE;
		kfpu->kfpu_ctx.fpu_xsave_mask = XFEATURE_FP_ALL;
		break;
	default:
		panic("invalid fp_save_mech");
	}

	/*
	 * Set the corresponding flags that the system expects on the FPU state
	 * to indicate that this is our state. The FPU_EN flag is required to
	 * indicate that FPU usage is allowed. The FPU_KERN flag is explicitly
	 * not set below as it represents that this state is being suppressed
	 * by the kernel.
	 */
	kfpu->kfpu_ctx.fpu_flags = FPU_EN | FPU_VALID;
	kfpu->kfpu_flags |= KFPU_F_INITIALIZED;
}

kfpu_state_t *
kernel_fpu_alloc(int kmflags)
{
	kfpu_state_t *kfpu;

	if ((kfpu = kmem_zalloc(sizeof (kfpu_state_t), kmflags)) == NULL) {
		return (NULL);
	}

	kfpu->kfpu_ctx.fpu_regs.kfpu_u.kfpu_generic =
	    kmem_cache_alloc(fpsave_cachep, kmflags);
	if (kfpu->kfpu_ctx.fpu_regs.kfpu_u.kfpu_generic == NULL) {
		kmem_free(kfpu, sizeof (kfpu_state_t));
		return (NULL);
	}

	kernel_fpu_fpstate_init(kfpu);

	return (kfpu);
}

void
kernel_fpu_free(kfpu_state_t *kfpu)
{
	kmem_cache_free(fpsave_cachep,
	    kfpu->kfpu_ctx.fpu_regs.kfpu_u.kfpu_generic);
	kmem_free(kfpu, sizeof (kfpu_state_t));
}

static void
kernel_fpu_ctx_save(void *arg)
{
	kfpu_state_t *kfpu = arg;
	fpu_ctx_t *pf;

	if (kfpu == NULL) {
		/*
		 * A NULL kfpu implies this is a kernel thread with an LWP and
		 * no user-level FPU usage. Use the lwp fpu save area.
		 */
		pf = &curthread->t_lwp->lwp_pcb.pcb_fpu;

		ASSERT(curthread->t_procp->p_flag & SSYS);
		ASSERT3U(pf->fpu_flags & FPU_VALID, ==, 0);

		fp_save(pf);
	} else {
		pf = &kfpu->kfpu_ctx;

		ASSERT3P(kfpu->kfpu_curthread, ==, curthread);
		ASSERT3U(pf->fpu_flags & FPU_VALID, ==, 0);

		/*
		 * Note, we can't use fp_save because it assumes that we're
		 * saving to the thread's PCB and not somewhere else. Because
		 * this is a different FPU context, we instead have to do this
		 * ourselves.
		 */
		switch (fp_save_mech) {
		case FP_FXSAVE:
			fpxsave(pf->fpu_regs.kfpu_u.kfpu_fx);
			break;
		case FP_XSAVE:
			xsavep(pf->fpu_regs.kfpu_u.kfpu_xs, pf->fpu_xsave_mask);
			break;
		default:
			panic("Invalid fp_save_mech");
		}

		/*
		 * Because we have saved context here, our save state is no
		 * longer valid and therefore needs to be reinitialized.
		 */
		kfpu->kfpu_flags &= ~KFPU_F_INITIALIZED;
	}

	pf->fpu_flags |= FPU_VALID;

	/*
	 * Clear KFPU flag. This allows swtch to check for improper kernel
	 * usage of the FPU (i.e. switching to a new thread while the old
	 * thread was in the kernel and using the FPU, but did not perform a
	 * context save).
	 */
	curthread->t_flag &= ~T_KFPU;
}

static void
kernel_fpu_ctx_restore(void *arg)
{
	kfpu_state_t *kfpu = arg;
	fpu_ctx_t *pf;

	if (kfpu == NULL) {
		/*
		 * A NULL kfpu implies this is a kernel thread with an LWP and
		 * no user-level FPU usage. Use the lwp fpu save area.
		 */
		pf = &curthread->t_lwp->lwp_pcb.pcb_fpu;

		ASSERT(curthread->t_procp->p_flag & SSYS);
		ASSERT3U(pf->fpu_flags & FPU_VALID, !=, 0);
	} else {
		pf = &kfpu->kfpu_ctx;

		ASSERT3P(kfpu->kfpu_curthread, ==, curthread);
		ASSERT3U(pf->fpu_flags & FPU_VALID, !=, 0);
	}

	fp_restore(pf);
	curthread->t_flag |= T_KFPU;
}

/*
 * Validate that the thread is not switching off-cpu while actively using the
 * FPU within the kernel.
 */
void
kernel_fpu_no_swtch(void)
{
	if ((curthread->t_flag & T_KFPU) != 0) {
		panic("curthread swtch-ing while the kernel is using the FPU");
	}
}

static const struct ctxop_template kfpu_ctxop_tpl = {
	.ct_rev		= CTXOP_TPL_REV,
	.ct_save	= kernel_fpu_ctx_save,
	.ct_restore	= kernel_fpu_ctx_restore,
};

void
kernel_fpu_begin(kfpu_state_t *kfpu, uint_t flags)
{
	klwp_t *pl = curthread->t_lwp;
	struct ctxop *ctx;

	if ((curthread->t_flag & T_KFPU) != 0) {
		panic("curthread attempting to nest kernel FPU states");
	}

	/* KFPU_USE_LWP and KFPU_NO_STATE are mutually exclusive. */
	ASSERT((flags & (KFPU_USE_LWP | KFPU_NO_STATE)) !=
	    (KFPU_USE_LWP | KFPU_NO_STATE));

	if ((flags & KFPU_NO_STATE) == KFPU_NO_STATE) {
		/*
		 * Since we don't have a kfpu_state or usable lwp pcb_fpu to
		 * hold our kernel FPU context, we depend on the caller doing
		 * kpreempt_disable for the duration of our FPU usage. This
		 * should only be done for very short periods of time.
		 */
		ASSERT(curthread->t_preempt > 0);
		ASSERT(kfpu == NULL);

		if (pl != NULL) {
			/*
			 * We might have already saved once so FPU_VALID could
			 * be set. This is handled in fp_save.
			 */
			fp_save(&pl->lwp_pcb.pcb_fpu);
			pl->lwp_pcb.pcb_fpu.fpu_flags |= FPU_KERNEL;
		}

		curthread->t_flag |= T_KFPU;

		/* Always restore the fpu to the initial state. */
		fpinit();

		return;
	}

	/*
	 * We either have a kfpu, or are using the LWP pcb_fpu for context ops.
	 */

	if ((flags & KFPU_USE_LWP) == 0) {
		if (kfpu->kfpu_curthread != NULL)
			panic("attempting to reuse kernel FPU state at %p when "
			    "another thread already is using", kfpu);

		if ((kfpu->kfpu_flags & KFPU_F_INITIALIZED) == 0)
			kernel_fpu_fpstate_init(kfpu);

		kfpu->kfpu_curthread = curthread;
	}

	/*
	 * Not all threads may have an active LWP. If they do and we're not
	 * going to re-use the LWP, then we should go ahead and save the state.
	 * We must also note that the fpu is now being used by the kernel and
	 * therefore we do not want to manage the fpu state via the user-level
	 * thread's context handlers.
	 *
	 * We might have already saved once (due to a prior use of the kernel
	 * FPU or another code path) so FPU_VALID could be set. This is handled
	 * by fp_save, as is the FPU_EN check.
	 */
	ctx = ctxop_allocate(&kfpu_ctxop_tpl, kfpu);
	kpreempt_disable();
	if (pl != NULL) {
		if ((flags & KFPU_USE_LWP) == 0)
			fp_save(&pl->lwp_pcb.pcb_fpu);
		pl->lwp_pcb.pcb_fpu.fpu_flags |= FPU_KERNEL;
	}

	/*
	 * Set the context operations for kernel FPU usage.  Because kernel FPU
	 * setup and ctxop attachment needs to happen under the protection of
	 * kpreempt_disable(), we allocate the ctxop outside the guard so its
	 * sleeping allocation will not cause a voluntary swtch().  This allows
	 * the rest of the initialization to proceed, ensuring valid state for
	 * the ctxop handlers.
	 */
	ctxop_attach(curthread, ctx);
	curthread->t_flag |= T_KFPU;

	if ((flags & KFPU_USE_LWP) == KFPU_USE_LWP) {
		/*
		 * For pure kernel threads with an LWP, we can use the LWP's
		 * pcb_fpu to save/restore context.
		 */
		fpu_ctx_t *pf = &pl->lwp_pcb.pcb_fpu;

		VERIFY(curthread->t_procp->p_flag & SSYS);
		VERIFY(kfpu == NULL);
		ASSERT((pf->fpu_flags & FPU_EN) == 0);

		/* Always restore the fpu to the initial state. */
		if (fp_save_mech == FP_XSAVE)
			pf->fpu_xsave_mask = XFEATURE_FP_ALL;
		fpinit();
		pf->fpu_flags = FPU_EN | FPU_KERNEL;
	} else {
		/* initialize the kfpu state */
		kernel_fpu_ctx_restore(kfpu);
	}
	kpreempt_enable();
}

void
kernel_fpu_end(kfpu_state_t *kfpu, uint_t flags)
{
	if ((curthread->t_flag & T_KFPU) == 0) {
		panic("curthread attempting to clear kernel FPU state "
		    "without using it");
	}

	/*
	 * General comments on why the rest of this function is structured the
	 * way it is. Be aware that there is a lot of subtlety here.
	 *
	 * If a user-level thread ever uses the fpu while in the kernel, then
	 * we cannot call fpdisable since that does STTS. That will set the
	 * ts bit in %cr0 which will cause an exception if anything touches the
	 * fpu. However, the user-level context switch handler (fpsave_ctxt)
	 * needs to access the fpu to save the registers into the pcb.
	 * fpsave_ctxt relies on CLTS having been done to clear the ts bit in
	 * fprestore_ctxt when the thread context switched onto the CPU.
	 *
	 * Calling fpdisable only effects the current CPU's %cr0 register.
	 *
	 * During ctxop_remove and kpreempt_enable, we can voluntarily context
	 * switch, so the CPU we were on when we entered this function might
	 * not be the same one we're on when we return from ctxop_remove or end
	 * the function. Note there can be user-level context switch handlers
	 * still installed if this is a user-level thread.
	 *
	 * We also must be careful in the unlikely chance we're running in an
	 * interrupt thread, since we can't leave the CPU's %cr0 TS state set
	 * incorrectly for the "real" thread to resume on this CPU.
	 */

	if ((flags & KFPU_NO_STATE) == 0) {
		kpreempt_disable();
	} else {
		ASSERT(curthread->t_preempt > 0);
	}

	curthread->t_flag &= ~T_KFPU;

	/*
	 * When we are ending things, we explicitly don't save the current
	 * kernel FPU state back to the temporary state. The kfpu API is not
	 * intended to be a permanent save location.
	 *
	 * If this is a user-level thread and we were to context switch
	 * before returning to user-land, fpsave_ctxt will be a no-op since we
	 * already saved the user-level FPU state the first time we run
	 * kernel_fpu_begin (i.e. we won't save the bad kernel fpu state over
	 * the user-level fpu state). The fpsave_ctxt functions only save if
	 * FPU_VALID is not already set. fp_save also set PCB_SET_UPDATE_FPU so
	 * fprestore_ctxt will be done in sys_rtt_common when the thread
	 * finally returns to user-land.
	 */

	if ((curthread->t_procp->p_flag & SSYS) != 0 &&
	    curthread->t_intr == NULL) {
		/*
		 * A kernel thread which is not an interrupt thread, so we
		 * STTS now.
		 */
		fpdisable();
	}

	if ((flags & KFPU_NO_STATE) == 0) {
		ctxop_remove(curthread, &kfpu_ctxop_tpl, kfpu);

		if (kfpu != NULL) {
			if (kfpu->kfpu_curthread != curthread) {
				panic("attempting to end kernel FPU state "
				    "for %p, but active thread is not "
				    "curthread", kfpu);
			} else {
				kfpu->kfpu_curthread = NULL;
			}
		}

		kpreempt_enable();
	}

	if (curthread->t_lwp != NULL) {
		uint_t f;

		if (flags & KFPU_USE_LWP) {
			f = FPU_EN | FPU_KERNEL;
		} else {
			f = FPU_KERNEL;
		}
		curthread->t_lwp->lwp_pcb.pcb_fpu.fpu_flags &= ~f;
	}
}

void
fpu_save_cache_init(void)
{
	switch (fp_save_mech) {
	case FP_FXSAVE:
		fpsave_cachep = kmem_cache_create("fxsave_cache",
		    sizeof (struct fxsave_state), FXSAVE_ALIGN,
		    NULL, NULL, NULL, NULL, NULL, 0);
		break;
	case FP_XSAVE:
		fpsave_cachep = kmem_cache_create("xsave_cache",
		    cpuid_get_xsave_size(), XSAVE_ALIGN,
		    NULL, NULL, NULL, NULL, NULL, 0);
		break;
	default:
		panic("Invalid fp_save_mech");
	}
}

/*
 * Fill in FPU information that is required by exec.
 */
void
fpu_auxv_info(int *typep, size_t *lenp)
{
	*typep = fp_elf;
	switch (fp_save_mech) {
	case FP_FXSAVE:
		*lenp = sizeof (struct fxsave_state);
		break;
	case FP_XSAVE:
		*lenp = cpuid_get_xsave_size();
		break;
	default:
		*lenp = 0;
		break;
	}
}

/*
 * This function exists to transform an xsave_state into an fxsave_state. The
 * way that we have to do this is nuanced. We assume that callers have already
 * handled FPU_EN and thus we only need to consider the xsave_state and its
 * component vector itself. This results in the following cases that we need to
 * consider:
 *
 *   o Neither the x87 / XMM state bits are set. We use the hardware default and
 *     need to ensure to copy the xsave header.
 *   o Both x87 / XMM state bits are set. We can copy everything.
 *   o Only the x87 bit is set. We need to copy the x87 state but make the XMM
 *     state be in the initial case.
 *   o Only the XMM bit is set. The reverse of the above case.
 *
 * The illumos and hardware defaults in 'sse_initial' and 'avx_initial' are
 * generally the same; however, the default floating point control word is
 * different.
 *
 * Finally, we have the complication of the MXCSR and MCXSR_MASK registers.
 * Because we are using xsave and xsaveopt in the kernel right now and not
 * xsavec, the hardware may write out the MXCSR and MXCSR_MASK registers if the
 * XFEATURE_AVX bit is set. Therefore if we don't have the XMM bit set but AVX
 * is set, we must also come back and copy out the MXCSR register. Sorry, we
 * don't make the rules.
 */
static void
fpu_xsave_to_fxsave(const struct xsave_state *xsave, struct fxsave_state *fx)
{
	const uint64_t comps = xsave->xs_header.xsh_xstate_bv;

	switch (comps & (XFEATURE_LEGACY_FP | XFEATURE_SSE)) {
	case XFEATURE_LEGACY_FP | XFEATURE_SSE:
		bcopy(xsave, fx, sizeof (*fx));
		return;
	case XFEATURE_LEGACY_FP:
		bcopy(xsave, fx, offsetof(struct fxsave_state, fx_xmm));
		fx->fx_mxcsr = SSE_MXCSR_INIT;
		fx->fx_mxcsr_mask = 0;
		break;
	case XFEATURE_SSE:
		bcopy(&sse_initial, fx, offsetof(struct fxsave_state,
		    fx_mxcsr));

		fx->fx_fcw = FPU_CW_INIT_HW;
		fx->fx_mxcsr = xsave->xs_fxsave.fx_mxcsr;
		fx->fx_mxcsr_mask = xsave->xs_fxsave.fx_mxcsr_mask;
		bcopy(xsave->xs_fxsave.fx_xmm, fx->fx_xmm, sizeof (fx->fx_xmm));
		break;
	default:
		bcopy(&sse_initial, fx, sizeof (*fx));
		fx->fx_fcw = FPU_CW_INIT_HW;
		break;
	}

	/*
	 * Account for the AVX causing MXCSR to be valid.
	 */
	if ((xsave->xs_header.xsh_xstate_bv & XFEATURE_AVX) != 0 &&
	    (xsave->xs_header.xsh_xstate_bv & XFEATURE_SSE) == 0) {
		fx->fx_mxcsr = xsave->xs_fxsave.fx_mxcsr;
		fx->fx_mxcsr_mask = xsave->xs_fxsave.fx_mxcsr_mask;
	}
}

/*
 * This function is designed to answer the question of are we using any xsave
 * family of instructions in context switch and therefore we have this state.
 * This should still remain true if we are using xsavec or xsaves in the kernel
 * in the future.
 */
boolean_t
fpu_xsave_enabled(void)
{
	return (fp_save_mech == FP_XSAVE);
}

/*
 * The following structure is used to track and manage the programmatic
 * construction of /proc and signal stack spilling of xsave information. All
 * known xsave types that the kernel supports must be included here.
 */
typedef struct xsave_proc_info {
	/*
	 * This matches the /proc xregs type that this data represents. This s
	 * used for /proc only.
	 */
	uint32_t xi_type;
	/*
	 * This indicates the size of the /proc data that we're operating on.
	 * This is only used for /proc.
	 */
	size_t	xi_size;
	/*
	 * This indicates the alignment that we want to have for the member when
	 * we're writing out. This is not used when setting data. This is only
	 * used for /proc.
	 */
	size_t	xi_align;
	/*
	 * This indicates whether this member must always be considered or not.
	 * This is used in both /proc and context/signal handling.
	 */
	bool	xi_always;
	/*
	 * This contains the corresponding bits in the xsave bit vector that
	 * corresponds to this entry. This is used for both /proc and
	 * context/signal handling.
	 */
	uint64_t xi_bits;
	/*
	 * The xi_fill function pointer is used to write out the /proc regset
	 * data (e.g. when a user reads xregs). This is only used for the /proc
	 * handling. The xi_valid function pointer is used instead to validate a
	 * given set of data that we've read in, while the xi_set pointer is
	 * used to actually transform the data in the underlying fpu save area.
	 */
	void	(*xi_fill)(const fpu_ctx_t *, const struct xsave_proc_info *,
	    void *);
	bool	(*xi_valid)(model_t, const void *);
	void	(*xi_set)(fpu_ctx_t *, const struct xsave_proc_info *,
	    uint64_t, const void *);
	/*
	 * The xi_signal_in and xi_signal_out function pointers are used for
	 * extended context and signal handling information. They are used when
	 * reading in data from a ucontext_t and writing it out respectively.
	 * These are only used for context/signal handling.
	 */
	int	(*xi_signal_in)(const struct xsave_proc_info *,
	    const ucontext_t *, const uc_xsave_t *, void *, uintptr_t *,
	    const uintptr_t);
	int	(*xi_signal_out)(const struct xsave_proc_info *, fpu_copyout_f,
	    uc_xsave_t *, const void *fpup, uintptr_t);
} xsave_proc_info_t;

static bool
fpu_proc_xregs_initial_state(const fpu_ctx_t *fpu, uint64_t feats)
{
	const struct xsave_state *xs = fpu->fpu_regs.kfpu_u.kfpu_xs;

	if ((fpu->fpu_flags & (FPU_EN | FPU_VALID)) == 0) {
		return (true);
	}

	return ((xs->xs_header.xsh_xstate_bv & feats) == 0);
}

static void
fpu_proc_xregs_xcr_fill(const fpu_ctx_t *fpu, const xsave_proc_info_t *info,
    void *datap)
{
	prxregset_xcr_t *xcr = datap;

	xcr->prx_xcr_xcr0 = xsave_bv_all;
}

/*
 * Unlike other instruction portions, we treat the xsave header and the legacy
 * XMM section together as both are somewhat tied at the instruction hip. Unlike
 * the when dealing with other xsave regions like the ymm and zmm components,
 * the initial state here is much more nuanced as it has to match what we actual
 * do in the OS and depends on the components that are present.
 */
static void
fpu_proc_xregs_xsave_fill(const fpu_ctx_t *fpu, const xsave_proc_info_t *info,
    void *datap)
{
	prxregset_xsave_t *prxsave = datap;
	const struct xsave_state *xsave = fpu->fpu_regs.kfpu_u.kfpu_xs;
	size_t hdr_off;

	/*
	 * In the x87/XMM case, the no device vs. initial state is different
	 * because the initial state case still wants us to copy the real xsave
	 * header. It's also worth calling out that the actual illumos default
	 * fxsave state is not the same as what Intel documents. The main
	 * difference is in what the x87 FPU control word is. This results in
	 * the following different cases that we need to think about:
	 *
	 *   o FPU_EN is not set. So we use the illumos default.
	 */
	if ((fpu->fpu_flags & FPU_EN) == 0) {
		bcopy(&avx_initial, prxsave, sizeof (*prxsave));
		return;
	}

	/*
	 * Convert all the fxsave region while taking into account the validity
	 * of the xsave bits. The prxregset_xsave_t structure is the same as the
	 * xsave structure in our ABI and Intel designed the xsave header to
	 * begin with the 512-bit fxsave structure.
	 */
	fpu_xsave_to_fxsave(xsave, (struct fxsave_state *)prxsave);

	/*
	 * Now that we've dealt with the x87 and XMM state, take care of the
	 * header.
	 */
	hdr_off = offsetof(prxregset_xsave_t, prx_xsh_xstate_bv);
	bcopy((const void *)((uintptr_t)xsave + hdr_off),
	    (void *)((uintptr_t)prxsave + hdr_off),
	    sizeof (struct xsave_header));
}

static void
fpu_proc_xregs_std_fill(const fpu_ctx_t *fpu, const xsave_proc_info_t *info,
    void *datap)
{
	if (!fpu_proc_xregs_initial_state(fpu, info->xi_bits)) {
		size_t size, off;
		const void *xsave_off;

		cpuid_get_xsave_info(info->xi_bits, &size, &off);
		ASSERT3U(size, ==, info->xi_size);
		xsave_off = (void *)((uintptr_t)fpu->fpu_regs.kfpu_u.kfpu_xs +
		    off);
		bcopy(xsave_off, datap, info->xi_size);
	}
}

/*
 * Users are not allowed to actually set the xcr information this way. However,
 * to make it easier for someone to just do a read, modify, write, of the xregs
 * data, if it is identical, then we will accept it (and do nothing).
 */
static bool
fpu_proc_xregs_xcr_valid(model_t model, const void *datap)
{
	const prxregset_xcr_t *xcr = datap;

	return (xcr->prx_xcr_xcr0 == xsave_bv_all && xcr->prx_xcr_xfd == 0 &&
	    xcr->prx_xcr_pad[0] == 0 && xcr->prx_xcr_pad[1] == 0);
}

/*
 * To match traditional /proc semantics, we do not error if reserved bits of
 * MXCSR are set, they will be masked off when writing data. We do not allow
 * someone to indicate that they are asking for compressed xsave data, hence the
 * check that prx_xsh_comp_bv is zero. Separately, in fpu_proc_xregs_set() we
 * check that each component that was indicated in the xstate_bv is actually
 * present.
 */
static bool
fpu_proc_xregs_xsave_valid(model_t model, const void *datap)
{
	const prxregset_xsave_t *xsave = datap;
	uint64_t rsvd[6] = { 0 };

	if (bcmp(rsvd, xsave->prx_xsh_reserved, sizeof (rsvd)) != 0 ||
	    xsave->prx_xsh_xcomp_bv != 0) {
		return (false);
	}

	if ((xsave->prx_xsh_xstate_bv & ~xsave_bv_all) != 0) {
		return (false);
	}

	return (true);
}

/*
 * The YMM, ZMM, and Hi-ZMM registers are all valid when in an LP64 environment
 * on x86; however, when operating in ILP32, subsets are reserved. We require
 * that all reserved portions are set to zero.
 */
static bool
fpu_proc_xregs_ymm_valid(model_t model, const void *datap)
{
	upad128_t ymm_zero[8];
	const prxregset_ymm_t *ymm = datap;

	if (model == DATAMODEL_LP64) {
		return (true);
	}

	bzero(&ymm_zero, sizeof (ymm_zero));
	return (bcmp(&ymm->prx_ymm[8], &ymm_zero, sizeof (ymm_zero)) == 0);
}

static bool
fpu_proc_xregs_zmm_valid(model_t model, const void *datap)
{
	upad256_t zmm_zero[8];
	const prxregset_zmm_t *zmm = datap;

	if (model == DATAMODEL_LP64) {
		return (true);
	}

	bzero(&zmm_zero, sizeof (zmm_zero));
	return (bcmp(&zmm->prx_zmm[8], &zmm_zero, sizeof (zmm_zero)) == 0);
}

static bool
fpu_proc_xregs_hi_zmm_valid(model_t model, const void *datap)
{
	prxregset_hi_zmm_t hi_zmm_zero;
	const prxregset_hi_zmm_t *hi_zmm = datap;

	if (model == DATAMODEL_LP64) {
		return (true);
	}

	bzero(&hi_zmm_zero, sizeof (hi_zmm_zero));
	return (bcmp(hi_zmm, &hi_zmm_zero, sizeof (hi_zmm_zero)) == 0);
}

/*
 * The xsave state consists of the first 512 bytes of the XMM state and then the
 * xsave header itself. Because of the xsave header, this structure is marked
 * with xi_always, so we must always process and consider it.
 *
 * Semantically if either of the bits around SSE / x87 is set, then we will copy
 * the entire thing. This may mean that we end up copying a region that is not
 * valid into the save area; however, that should be OK as we still have the
 * specific bit flags that indicate what we should consider or not.
 *
 * There is one additional wrinkle we need to consider and honor here. The CPU
 * will load the MXCSR values if the AVX bit is set in an xrstor regardless of
 * anything else. So if this is set and we do not have a valid x87/XMM bits
 * set then we will set the MXCSR to its default state in case the processor
 * tries to load it. For reference see:
 *
 *   o Intel SDM Volume 1: 13.8.1 Standard Form of XRSTOR
 *   o AMD64 Volume 2: Section 11.5.9 MXCSR State Management
 *
 * Note, the behavior around this changes depending on whether using the
 * compressed xrstor or not. We are not, but it's worth being aware of. We do
 * not worry about MXCSR_MASK because the instructions ignore it.
 */
static void
fpu_proc_xregs_xsave_set(fpu_ctx_t *fpu, const xsave_proc_info_t *info,
    uint64_t xsave_bv, const void *datap)
{
	const struct xsave_state *src_xs = datap;
	struct xsave_state *targ_xs = fpu->fpu_regs.kfpu_u.kfpu_xs;

	if ((xsave_bv & info->xi_bits) != 0) {
		bcopy(&src_xs->xs_fxsave, &targ_xs->xs_fxsave,
		    sizeof (struct fxsave_state));
	} else if ((xsave_bv & XFEATURE_AVX) != 0) {
		targ_xs->xs_fxsave.fx_mxcsr = SSE_MXCSR_INIT;
	}

	bcopy(&src_xs->xs_header, &targ_xs->xs_header,
	    sizeof (struct xsave_header));
	targ_xs->xs_fxsave.fx_mxcsr &= sse_mxcsr_mask;
}

static void
fpu_proc_xregs_std_set(fpu_ctx_t *fpu, const xsave_proc_info_t *info,
    uint64_t xsave_bv, const void *datap)
{
	size_t size, off;
	void *xsave_off;

	cpuid_get_xsave_info(info->xi_bits, &size, &off);
	xsave_off = (void *)((uintptr_t)fpu->fpu_regs.kfpu_u.kfpu_xs +
	    off);
	bcopy(datap, xsave_off, size);
}

/*
 * Dealing with XMM data is a little more annoying in signal context. If UC_FPU
 * is set, the ucontext_t's fpregset_t contains a copy of the XMM region. That
 * must take priority over an XMM region that showed up in the uc_xsave_t data.
 * In the signal copyout code we do not save XMM region in the uc_xsave_t or set
 * it as a present component because of it being kept in the fpregset_t. Because
 * of this behavior, if we find the XMM (or x87) state bits present, we treat
 * that as an error.
 *
 * The system has always gone through and cleaned up the reserved bits in the
 * fxsave state when someone calls setcontext(). Therefore we need to do the
 * same thing which is why you see the masking of the mxcsr below.
 *
 * Finally, there is one last wrinkle here that we need to consider. The
 * fpregset_t has two private words which cache the status/exception
 * information. Therefore, we well...  cheat. Intel has left bytes 464 (0x1d0)
 * through 511 (0x1ff) available for us to do what we want. So we will pass this
 * through that for the moment to help us pass this state around without too
 * much extra allocation.
 */
static int
fpu_signal_copyin_xmm(const xsave_proc_info_t *info, const ucontext_t *kuc,
    const uc_xsave_t *ucx, void *fpup, uintptr_t *udatap,
    const uintptr_t max_udata)
{
	struct xsave_state *xsave = fpup;

	if ((ucx->ucx_bv & info->xi_bits) != 0) {
		return (EINVAL);
	}

	if ((kuc->uc_flags & UC_FPU) != 0) {
		bcopy(&kuc->uc_mcontext.fpregs, &xsave->xs_fxsave,
		    sizeof (struct fxsave_state));
		xsave->xs_fxsave.__fx_ign2[3]._l[0] =
		    kuc->uc_mcontext.fpregs.fp_reg_set.fpchip_state.status;
		xsave->xs_fxsave.__fx_ign2[3]._l[1] =
		    kuc->uc_mcontext.fpregs.fp_reg_set.fpchip_state.xstatus;
		xsave->xs_fxsave.fx_mxcsr &= sse_mxcsr_mask;
		xsave->xs_header.xsh_xstate_bv |= info->xi_bits;
	}

	return (0);
}

static int
fpu_signal_copyin_std(const xsave_proc_info_t *info, const ucontext_t *kuc,
    const uc_xsave_t *ucx, void *fpup, uintptr_t *udatap,
    const uintptr_t max_udata)
{
	size_t len, xsave_off;
	void *copy_to;
	struct xsave_state *xsave = fpup;

	cpuid_get_xsave_info(info->xi_bits, &len, &xsave_off);
	if (*udatap + len > max_udata) {
		return (EOVERFLOW);
	}

	copy_to = (void *)((uintptr_t)fpup + xsave_off);
	if (ddi_copyin((void *)*udatap, copy_to, len, 0) != 0) {
		return (EFAULT);
	}

	xsave->xs_header.xsh_xstate_bv |= info->xi_bits;
	*udatap = *udatap + len;

	return (0);
}

static int
fpu_signal_copyout_std(const xsave_proc_info_t *info, fpu_copyout_f copyfunc,
    uc_xsave_t *ucx, const void *fpup, uintptr_t udatap)
{
	size_t len, xsave_off;
	const void *copy_from;
	void *copy_to;
	int ret;

	cpuid_get_xsave_info(info->xi_bits, &len, &xsave_off);
	copy_from = (void *)(uintptr_t)fpup + xsave_off;
	copy_to = (void *)(udatap + ucx->ucx_len);

	ret = copyfunc(copy_from, copy_to, len);
	if (ret != 0) {
		return (ret);
	}

	ucx->ucx_len += len;
	ucx->ucx_bv |= info->xi_bits;
	return (0);
}

/*
 * This table contains information about the extended FPU states and synthetic
 * information we create for /proc, the ucontext_t, and signal handling. The
 * definition of the xsave_proc_info_t describes how each member is used.
 *
 * In general, this table is expected to be in the order of the xsave data
 * structure itself. Synthetic elements that we create can go anywhere and new
 * ones should be inserted at the end. This structure is walked in order to
 * produce the /proc and signal handling logic, so changing the order is
 * meaningful for those and should not be done lightly.
 */
static const xsave_proc_info_t fpu_xsave_info[] = { {
	.xi_type = PRX_INFO_XCR,
	.xi_size = sizeof (prxregset_xcr_t),
	.xi_align = alignof (prxregset_xcr_t),
	.xi_always = true,
	.xi_bits = 0,
	.xi_fill = fpu_proc_xregs_xcr_fill,
	.xi_valid = fpu_proc_xregs_xcr_valid
}, {
	/*
	 * The XSAVE entry covers both the xsave header and the %xmm registers.
	 * Note, there is no signal copyout information for the %xmm registers
	 * because it is expected that that data is already in the fpregset_t.
	 */
	.xi_type = PRX_INFO_XSAVE,
	.xi_size = sizeof (prxregset_xsave_t),
	.xi_align = FPU_ALIGN_XMM,
	.xi_always = true,
	.xi_bits = XFEATURE_LEGACY_FP | XFEATURE_SSE,
	.xi_fill = fpu_proc_xregs_xsave_fill,
	.xi_set = fpu_proc_xregs_xsave_set,
	.xi_valid = fpu_proc_xregs_xsave_valid,
	.xi_signal_in = fpu_signal_copyin_xmm
}, {
	.xi_type = PRX_INFO_YMM,
	.xi_size = sizeof (prxregset_ymm_t),
	.xi_align = FPU_ALIGN_YMM,
	.xi_always = false,
	.xi_bits = XFEATURE_AVX,
	.xi_fill = fpu_proc_xregs_std_fill,
	.xi_set = fpu_proc_xregs_std_set,
	.xi_signal_in = fpu_signal_copyin_std,
	.xi_valid = fpu_proc_xregs_ymm_valid,
	.xi_signal_out = fpu_signal_copyout_std
}, {
	/*
	 * There is no /proc validation function for the mask registers because
	 * they are the same in ILP32 / LP64 and there is nothing for us to
	 * actually validate.
	 */
	.xi_type = PRX_INFO_OPMASK,
	.xi_size = sizeof (prxregset_opmask_t),
	.xi_align = alignof (prxregset_opmask_t),
	.xi_always = false,
	.xi_bits = XFEATURE_AVX512_OPMASK,
	.xi_fill = fpu_proc_xregs_std_fill,
	.xi_set = fpu_proc_xregs_std_set,
	.xi_signal_in = fpu_signal_copyin_std,
	.xi_signal_out = fpu_signal_copyout_std
}, {
	.xi_type = PRX_INFO_ZMM,
	.xi_size = sizeof (prxregset_zmm_t),
	.xi_align = FPU_ALIGN_ZMM,
	.xi_always = false,
	.xi_bits = XFEATURE_AVX512_ZMM,
	.xi_fill = fpu_proc_xregs_std_fill,
	.xi_set = fpu_proc_xregs_std_set,
	.xi_valid = fpu_proc_xregs_zmm_valid,
	.xi_signal_in = fpu_signal_copyin_std,
	.xi_signal_out = fpu_signal_copyout_std
}, {
	.xi_type = PRX_INFO_HI_ZMM,
	.xi_size = sizeof (prxregset_hi_zmm_t),
	.xi_align = FPU_ALIGN_ZMM,
	.xi_always = false,
	.xi_bits = XFEATURE_AVX512_HI_ZMM,
	.xi_fill = fpu_proc_xregs_std_fill,
	.xi_set = fpu_proc_xregs_std_set,
	.xi_valid = fpu_proc_xregs_hi_zmm_valid,
	.xi_signal_in = fpu_signal_copyin_std,
	.xi_signal_out = fpu_signal_copyout_std
} };

static bool
fpu_proc_xregs_include(const xsave_proc_info_t *infop)
{
	return (infop->xi_always || (xsave_bv_all & infop->xi_bits) != 0);
}

void
fpu_proc_xregs_info(struct proc *p __unused, uint32_t *ninfop, uint32_t *sizep,
    uint32_t *dstart)
{
	size_t ret = sizeof (prxregset_hdr_t);
	uint32_t ninfo = 0;

	ASSERT(fpu_xsave_enabled());

	/*
	 * Right now the set of flags that are enabled in the FPU is global.
	 * That is, while the pcb's fcpu_ctx_t has the fpu_xsave_mask, the
	 * actual things that might show up and we care about are all about what
	 * is set up in %xcr0 which is stored in the global xsave_bv_all. If we
	 * move to per-process FPU enablement which is likely to come with AMX,
	 * then this will need the proc_t to look at, hence why we've set things
	 * up with the unused variable above.
	 *
	 * We take two passes through the array. The first is just to count up
	 * how many informational entries we need.
	 */
	for (size_t i = 0; i < ARRAY_SIZE(fpu_xsave_info); i++) {
		if (!fpu_proc_xregs_include(&fpu_xsave_info[i]))
			continue;
		ninfo++;
	}

	ASSERT3U(ninfo, >, 0);
	ret += sizeof (prxregset_info_t) * ninfo;

	for (size_t i = 0; i < ARRAY_SIZE(fpu_xsave_info); i++) {
		size_t curphase;
		if (!fpu_proc_xregs_include(&fpu_xsave_info[i]))
			continue;

		curphase = ret % fpu_xsave_info[i].xi_align;
		if (ret < fpu_xsave_info[i].xi_align) {
			ret = fpu_xsave_info[i].xi_align;
		} else if (curphase != 0) {
			ret += curphase;
		}

		if (i == 0 && dstart != NULL) {
			*dstart = ret;
		}

		ret += fpu_xsave_info[i].xi_size;
	}

	VERIFY3U(ret, <=, UINT32_MAX);
	if (sizep != NULL) {
		*sizep = ret;
	}

	if (ninfop != NULL) {
		*ninfop = ninfo;
	}
}

/*
 * This function supports /proc. Because /proc does not have a process locked
 * while processing a PCSXREG, this tries to establish an upper bound that we
 * will validate later in fpu_proc_xregs_set(). We basically say that if you
 * take the maximum xsave size and add 1 KiB that is a good enough approximation
 * for the maximum size. The 1 KiB is us basically trying to rationalize the
 * overhead of our structures that we're adding right, while being cognisant of
 * differing alignments and the fact that the full xsave size is in some cases
 * (when supervisor states or features we don't support are present) going to be
 * larger than we would need for this.
 */
size_t
fpu_proc_xregs_max_size(void)
{
	VERIFY(fpu_xsave_enabled());
	return (cpuid_get_xsave_size() + 0x1000);
}

/*
 * This functions supports /proc. In particular, it's meant to perform the
 * following:
 *
 *  o Potentially save the current thread's registers.
 *  o Write out the x86 xsave /proc xregs format data from the xsave data we
 *    actually have. Note, this can be a little weird for cases where the FPU is
 *    not actually enabled, which happens for system processes.
 */
void
fpu_proc_xregs_get(klwp_t *lwp, void *buf)
{
	uint32_t size, ninfo, curinfo, dstart;
	fpu_ctx_t *fpu = &lwp->lwp_pcb.pcb_fpu;
	prxregset_hdr_t *hdr = buf;

	ASSERT(fpu_xsave_enabled());
	fpu_proc_xregs_info(lwp->lwp_procp, &ninfo, &size, &dstart);

	/*
	 * Before we get going, defensively zero out all the data buffer so that
	 * the rest of the fill functions can assume a specific base.
	 */
	bzero(buf, size);

	kpreempt_disable();
	if ((fpu->fpu_flags & (FPU_EN | FPU_VALID)) == FPU_EN) {
		/*
		 * This case suggests that thread in question doesn't have a
		 * valid FPU save state which should only happen when it is on
		 * CPU. If this is the case, we must ensure that we save the
		 * current FPU state before proceeding. We also sanity check
		 * several things here before doing this as using /proc on
		 * yourself is always exciting. fp_save() will ensure that the
		 * thread is flagged to go back to being an eager FPU before
		 * returning back to userland.
		 */
		VERIFY3P(curthread, ==, lwptot(lwp));
		VERIFY0(lwptot(lwp)->t_flag & T_KFPU);
		fp_save(fpu);
	}
	kpreempt_enable();

	hdr->pr_type = PR_TYPE_XSAVE;
	hdr->pr_size = size;
	hdr->pr_flags = hdr->pr_pad[0] = hdr->pr_pad[1] = hdr->pr_pad[2] =
	    hdr->pr_pad[3] = 0;
	hdr->pr_ninfo = ninfo;

	curinfo = 0;
	for (size_t i = 0; i < ARRAY_SIZE(fpu_xsave_info); i++) {
		void *startp;
		uint32_t phase;

		if (!fpu_proc_xregs_include(&fpu_xsave_info[i]))
			continue;

		phase = dstart % fpu_xsave_info[i].xi_align;
		if (dstart < fpu_xsave_info[i].xi_align) {
			ASSERT3U(i, !=, 0);
			dstart = fpu_xsave_info[i].xi_align;
		} else if (phase != 0) {
			ASSERT3U(i, !=, 0);
			dstart += phase;
		}

		hdr->pr_info[curinfo].pri_type = fpu_xsave_info[i].xi_type;
		hdr->pr_info[curinfo].pri_flags = 0;
		hdr->pr_info[curinfo].pri_size = fpu_xsave_info[i].xi_size;
		hdr->pr_info[curinfo].pri_offset = dstart;

		startp = (void *)((uintptr_t)buf + dstart);
		fpu_xsave_info[i].xi_fill(fpu, &fpu_xsave_info[i], startp);
		dstart += fpu_xsave_info[i].xi_size;
		ASSERT3U(curinfo, <=, ninfo);
		curinfo++;
	}
}

/*
 * We have been asked to set the data in the FPU for a given thread. Our
 * prmachdep code has already validated that the raw semantics of the data that
 * we have are valid (that is the appropriate sizes, offsets, and flags). We now
 * apply additional checking here:
 *
 *   o The xsave structure is present and only valid bits are set.
 *   o If the xsave component bit-vector is set, we have the corresponding proc
 *     info item.
 *   o Read-only items are ignored if and only if they actually match what we
 *     gave the user mostly as a courtesy to simplify things here.
 *   o ILP32 processes which can't support many of the regions are allowed to
 *     have the items here (as we likely gave them to them), but they must be
 *     zero if they are set.
 *
 * We take a first pass through all the data, validating it makes sense for the
 * FPU. Only after that point do we ensure that we have the FPU data in question
 * and then we clobber all the FPU data. Part of the semantics of setting this
 * is that we're setting the entire extended FPU.
 */
int
fpu_proc_xregs_set(klwp_t *lwp, void *buf)
{
	prxregset_hdr_t *prx = buf;
	model_t model = lwp_getdatamodel(lwp);
	uint64_t bv_found = 0;
	const prxregset_xsave_t *xsave = NULL;
	fpu_ctx_t *fpu = &lwp->lwp_pcb.pcb_fpu;

	VERIFY(fpu_xsave_enabled());

	/*
	 * First, walk each note info header that we have from the user and
	 * proceed to validate it. The prmachdep code has already validated that
	 * the size, type, and offset information is valid, but it has not
	 * validated the semantic contents of this or if someone is trying to
	 * write something they shouldn't.
	 *
	 * While we walk this, we keep track of where the xsave header is. We
	 * also track all of the bits that we have found along the way so we can
	 * match up and ensure that everything that was set has a corresponding
	 * bit in the xsave bitmap. If we have something in the xsave bitmap,
	 * but not its corresponding data, then that is an error. However, we
	 * allow folks to write data regions without the bit set in the xsave
	 * data to make the read, modify, write process simpler.
	 */
	for (uint32_t i = 0; i < prx->pr_ninfo; i++) {
		const prxregset_info_t *info = &prx->pr_info[i];
		bool found = false;

		for (size_t pt = 0; pt < ARRAY_SIZE(fpu_xsave_info); pt++) {
			void *data;
			if (info->pri_type != fpu_xsave_info[pt].xi_type)
				continue;

			found = true;
			data = (void *)((uintptr_t)buf + info->pri_offset);
			if (fpu_xsave_info[pt].xi_valid != NULL &&
			    !fpu_xsave_info[pt].xi_valid(model, data)) {
				return (EINVAL);
			}

			if (info->pri_type == PRX_INFO_XSAVE) {
				xsave = data;
			}
			bv_found |= fpu_xsave_info[pt].xi_bits;
			break;
		}

		if (!found) {
			return (EINVAL);
		}
	}

	/*
	 * No xsave data, no dice.
	 */
	if (xsave == NULL) {
		return (EINVAL);
	}

	/*
	 * If anything is set in the xsave header that was not found as we
	 * walked structures, then that is an error. The opposite is not true as
	 * discussed above.
	 */
	if ((xsave->prx_xsh_xstate_bv & ~bv_found) != 0) {
		return (EINVAL);
	}

	/*
	 * At this point, we consider all the data actually valid. Now we must
	 * set up this information in the save area. If this is our own lwp, we
	 * must disable it first. Otherwise, we expect that it is already valid.
	 * To try to sanitize this, we will defensively zero the entire region
	 * as we are setting everything that will result in here.
	 */
	kpreempt_disable();
	if ((fpu->fpu_flags & (FPU_EN | FPU_VALID)) == FPU_EN) {
		/*
		 * This case suggests that thread in question doesn't have a
		 * valid FPU save state which should only happen when it is on
		 * CPU. If this is the case, we explicitly disable the FPU, but
		 * do not save it before proceeding. We also sanity check
		 * several things here before doing this as using /proc on
		 * yourself is always exciting. Unlike fp_save(), fp_free() does
		 * not signal that an update is required, so we unconditionally
		 * set that for all threads.
		 */
		VERIFY3P(curthread, ==, lwptot(lwp));
		VERIFY0(lwptot(lwp)->t_flag & T_KFPU);
		fp_free(fpu);
	}
	PCB_SET_UPDATE_FPU(&lwp->lwp_pcb);
	bzero(lwp->lwp_pcb.pcb_fpu.fpu_regs.kfpu_u.kfpu_generic,
	    cpuid_get_xsave_size());

	for (uint32_t i = 0; i < prx->pr_ninfo; i++) {
		const prxregset_info_t *info = &prx->pr_info[i];
		bool found = false;

		for (size_t pt = 0; pt < ARRAY_SIZE(fpu_xsave_info); pt++) {
			const void *data;
			if (info->pri_type != fpu_xsave_info[pt].xi_type)
				continue;

			/*
			 * Check if we have a set function and if we should
			 * include this. We may not if this is something like
			 * PRX_INFO_XCR which is read-only.
			 *
			 * We may not include a given entry as it may not have
			 * been set in the actual xsave state that we have been
			 * asked to restore, in which case to not break the
			 * xsaveopt logic, we must leave it in its initial
			 * state, e.g. zeroed (generally). XMM data initial
			 * state is not zeroed, but is marked with xi_always to
			 * help account for this.
			 */
			found = true;
			if (fpu_xsave_info[pt].xi_set == NULL)
				break;
			if (!fpu_xsave_info[pt].xi_always &&
			    (xsave->prx_xsh_xstate_bv &
			    fpu_xsave_info[pt].xi_bits) !=
			    fpu_xsave_info[pt].xi_bits) {
				break;
			}

			data = (void *)((uintptr_t)buf + info->pri_offset);
			fpu_xsave_info[pt].xi_set(fpu, &fpu_xsave_info[pt],
			    xsave->prx_xsh_xstate_bv, data);
		}

		VERIFY(found);
	}
	kpreempt_enable();

	return (0);
}

/*
 * To be included in the signal copyout logic we must have a copy function and
 * the bit in question must be included. Note, we don't consult xi_always here
 * as that is really part of what is always present for xsave logic and
 * therefore isn't really pertinent here because of our custom format. See the
 * big theory statement for more info.
 */
static bool
fpu_signal_include(const xsave_proc_info_t *infop, uint64_t xs_bv)
{
	return ((infop->xi_bits & xs_bv) == infop->xi_bits &&
	    infop->xi_signal_out != NULL);
}

/*
 * We need to fill out the xsave related data into the ucontext_t that we've
 * been given. We should have a valid user pointer at this point in the uc_xsave
 * member. This is much simpler than the copyin that we have. Here are the
 * current assumptions:
 *
 *   o This is being called for the current thread. This is not meant to operate
 *     on an arbitrary thread's state.
 *   o We cannot assume whether the FPU is valid in the pcb or not. While most
 *     callers will have just called getfpregs() which saved the state, don't
 *     assume that.
 *   o We assume that the user address has the requisite required space for this
 *     to be copied out.
 *   o We assume that copyfunc() will ensure we are not copying into a kernel
 *     address.
 *
 * For more information on the format of the data, see the 'Signal Handling and
 * the ucontext_t' portion of the big theory statement. We copy out all the
 * constituent parts and then come back and write out the actual final header
 * information.
 */
int
fpu_signal_copyout(klwp_t *lwp, uintptr_t uaddr, fpu_copyout_f copyfunc)
{
	struct fpu_ctx *fpu = &lwp->lwp_pcb.pcb_fpu;
	uint64_t xs_bv;
	uc_xsave_t ucx;
	int ret;

	VERIFY3P(curthread, ==, lwptot(lwp));
	VERIFY0(lwptot(lwp)->t_flag & T_KFPU);
	VERIFY3U(fpu->fpu_flags & FPU_EN, ==, FPU_EN);

	if (!fpu_xsave_enabled()) {
		return (ENOTSUP);
	}

	/*
	 * Unlike when we're dealing with /proc, we can unconditionally call
	 * fp_save() because this is always called in the context where the lwp
	 * we're operating on is always the one on CPU (which is what fp_save()
	 * asserts).
	 */
	fp_save(fpu);

	bzero(&ucx, sizeof (ucx));
	ucx.ucx_vers = UC_XSAVE_VERS;
	ucx.ucx_len += sizeof (uc_xsave_t);

	xs_bv = fpu->fpu_regs.kfpu_u.kfpu_xs->xs_header.xsh_xstate_bv;
	for (size_t i = 0; i < ARRAY_SIZE(fpu_xsave_info); i++) {
		const xsave_proc_info_t *info = &fpu_xsave_info[i];

		if (!fpu_signal_include(&fpu_xsave_info[i], xs_bv))
			continue;
		ret = info->xi_signal_out(info, copyfunc, &ucx,
		    lwp->lwp_pcb.pcb_fpu.fpu_regs.kfpu_u.kfpu_generic,
		    uaddr);
		if (ret != 0) {
			kpreempt_enable();
			return (ret);
		}
	}

	/*
	 * Now that everything has been copied out, we should have an accurate
	 * value in the uc_xsave_t header and we can copy that out at the start
	 * of the user data.
	 */
	ret = copyfunc(&ucx, (void *)uaddr, sizeof (ucx));
	return (ret);
}

/*
 * Here we've been given a ucontext_t which potentially has a user pointer to
 * xsave state that we've copied out previously. In this case we need to do the
 * following, assuming UC_XSAVE is present:
 *
 *   o Copy in our header and validate it.
 *   o Allocate an fpu context to use as a holding ground for all this data.
 *   o If UC_FPU is set, override the xsave structure with the saved XMM state,
 *     clear UC_FPU, and make sure that the correct xsave_bv bits are set.
 *
 * Currently we always allocate the additional state as a holding ground for the
 * FPU. What we're copying in may not be valid and we don't want to clobber the
 * existing FPU state or deal with merging it until we believe it's reasonable
 * enough. The proc_t is here to set us up for when we have per-process settings
 * in the extended feature disable MSRs.
 */
int
fpu_signal_copyin(klwp_t *lwp, ucontext_t *kuc)
{
	uc_xsave_t ucx;
	uint64_t bv;
	uintptr_t data, max_data;
	void *fpu;
	proc_t *p = lwp->lwp_procp;
	size_t ksize;

	/*
	 * Because this has been opaque filler and the kernel has never
	 * historically looked at it, we don't really care about the uc_xsave
	 * pointer being garbage in the case that the flag is not set. While
	 * this isn't perhaps the most sporting choice in some cases, this is on
	 * the other hand, pragmatic.
	 */
	if ((kuc->uc_flags & UC_XSAVE) != 0) {
		if (kuc->uc_xsave == 0) {
			return (EINVAL);
		}

		if (!fpu_xsave_enabled()) {
			return (ENOTSUP);
		}
	} else {
		return (0);
	}

	if (ddi_copyin((const void *)kuc->uc_xsave, &ucx, sizeof (ucx), 0) !=
	    0) {
		return (EFAULT);
	}

	ksize = cpuid_get_xsave_size();
	if (ucx.ucx_vers != UC_XSAVE_VERS || ucx.ucx_len < sizeof (ucx) ||
	    ucx.ucx_len > ksize ||
	    (ucx.ucx_bv & ~xsave_bv_all) != 0 ||
	    (uintptr_t)p->p_as->a_userlimit - ucx.ucx_len <
	    (uintptr_t)kuc->uc_xsave) {
		return (EINVAL);
	}

	/*
	 * OK, our goal right now is to recreate a valid xsave_state structure
	 * that we'll ultimately end up having to merge with our existing one in
	 * the FPU save state. The reason we describe this as a merge is to help
	 * future us when we want to retain supervisor state which will never be
	 * part of userland signal state. The design of the userland signal
	 * state is basically to compress it as much as we can. This is done for
	 * two reasons:
	 *
	 *   1) We currently consider this a private interface.
	 *   2) We really want to minimize the actual amount of stack space we
	 *	use as much as possible. Most applications aren't using AVX-512
	 *	right now, so doing our own compression style is worthwhile. If
	 *	libc adopts AVX-512 routines, we may want to change this.
	 *
	 * On the allocation below, our assumption is that if a thread has taken
	 * a signal, then it is likely to take a signal again in the future (or
	 * be shortly headed to its demise). As such, when that happens we will
	 * leave the allocated signal stack around for the process. Most
	 * applications don't allow all threads to take signals, so this should
	 * hopefully help amortize the cost of the allocation.
	 */
	max_data = (uintptr_t)kuc->uc_xsave + ucx.ucx_len;
	data = (uintptr_t)kuc->uc_xsave + sizeof (ucx);
	bv = ucx.ucx_bv;
	if (lwp->lwp_pcb.pcb_fpu.fpu_signal == NULL) {
		lwp->lwp_pcb.pcb_fpu.fpu_signal =
		    kmem_cache_alloc(fpsave_cachep, KM_SLEEP);
	}
	fpu = lwp->lwp_pcb.pcb_fpu.fpu_signal;

	/*
	 * Unconditionally initialize the memory we get in here to ensure that
	 * it is in a reasonable state for ourselves. This ensures that unused
	 * regions are mostly left in their initial state (the main exception
	 * here is the x87/XMM state, but that should be OK). We don't fill in
	 * the initial xsave state as we expect that to happen as part of our
	 * processing.
	 */
	bzero(fpu, ksize);

	for (size_t i = 0; i < ARRAY_SIZE(fpu_xsave_info); i++) {
		int ret;
		const xsave_proc_info_t *info = &fpu_xsave_info[i];
		if (!info->xi_always && (info->xi_bits & bv) == 0)
			continue;
		bv &= ~info->xi_bits;

		if (info->xi_signal_in == NULL)
			continue;
		ret = info->xi_signal_in(info, kuc, &ucx, fpu, &data, max_data);
		if (ret != 0) {
			return (ret);
		}
	}
	ASSERT0(bv);

	/*
	 * As described in the big theory statement section 'Signal Handling and
	 * the ucontext_t', we always remove UC_FPU from here as we've taken
	 * care of reassembling it ourselves.
	 */
	kuc->uc_flags &= ~UC_FPU;
	kuc->uc_xsave = (uintptr_t)fpu;

	return (0);
}

/*
 * This determines the size of the signal stack that we need for our custom form
 * of the xsave state.
 */
size_t
fpu_signal_size(klwp_t *lwp)
{
	struct fpu_ctx *fpu = &lwp->lwp_pcb.pcb_fpu;
	size_t len = sizeof (uc_xsave_t);
	uint64_t xs_bv;

	VERIFY3P(curthread, ==, lwptot(lwp));
	VERIFY0(lwptot(lwp)->t_flag & T_KFPU);
	VERIFY3U(fpu->fpu_flags & FPU_EN, ==, FPU_EN);

	if (!fpu_xsave_enabled()) {
		return (0);
	}

	kpreempt_disable();
	if ((fpu->fpu_flags & (FPU_EN | FPU_VALID)) == FPU_EN) {
		fp_save(fpu);
	}

	xs_bv = fpu->fpu_regs.kfpu_u.kfpu_xs->xs_header.xsh_xstate_bv;
	for (size_t i = 0; i < ARRAY_SIZE(fpu_xsave_info); i++) {
		size_t comp_size;

		if (!fpu_signal_include(&fpu_xsave_info[i], xs_bv))
			continue;

		cpuid_get_xsave_info(fpu_xsave_info[i].xi_bits, &comp_size,
		    NULL);
		len += comp_size;
	}

	kpreempt_enable();
	return (len);
}

/*
 * This function is used in service of restorecontext() to set the specified
 * thread's extended FPU state to the passed in data. Our assumptions at this
 * point from the system are:
 *
 *   o Someone has already verified that the actual xsave header is correct.
 *   o Any traditional XMM state that causes a #gp has been clamped.
 *   o That data is basically the correct sized xsave state structure. Right now
 *     that means it is not compressed and follows the CPUID-based rules for
 *     constructing and laying out data.
 *   o That the lwp argument refers to the current thread.
 *
 * Our primary purpose here is to merge the current FPU state with what exists
 * here. Right now, "merge", strictly speaking is just "replace". We can get
 * away with just replacing everything because all we currently save are user
 * states. If we start saving kernel states in here, this will get more nuanced
 * and we will need to be more careful about how we store data here.
 */
void
fpu_set_xsave(klwp_t *lwp, const void *data)
{
	struct fpu_ctx *fpu = &lwp->lwp_pcb.pcb_fpu;
	uint32_t status, xstatus;
	struct xsave_state *dst_xsave;

	VERIFY(fpu_xsave_enabled());
	VERIFY3P(curthread, ==, lwptot(lwp));
	VERIFY0(lwptot(lwp)->t_flag & T_KFPU);
	ASSERT3U(fpu->fpu_flags & FPU_EN, ==, FPU_EN);

	/*
	 * We use fp_save() here rather than a stock fpdisable() so we can
	 * attempt to honor our invariants that when the thread state has been
	 * saved, the valid flag is set, even though we're going to be
	 * overwriting it shortly. If we just called fpdisable() then we would
	 * basically be asking for trouble.
	 *
	 * Because we are modifying the state here and we don't want the system
	 * to end up in an odd state, we are being a little paranoid and
	 * disabling preemption across this operation. In particular, once the
	 * state is properly tagged with FPU_VALID, there should be no other way
	 * that this thread can return to userland and get cleared out because
	 * we're resetting its context; however, we let paranoia win out.
	 */
	kpreempt_disable();
	if ((fpu->fpu_flags & (FPU_EN | FPU_VALID)) == FPU_EN) {
		fp_save(fpu);
	}

	bcopy(data, lwp->lwp_pcb.pcb_fpu.fpu_regs.kfpu_u.kfpu_generic,
	    cpuid_get_xsave_size());
	dst_xsave = lwp->lwp_pcb.pcb_fpu.fpu_regs.kfpu_u.kfpu_generic;
	status = dst_xsave->xs_fxsave.__fx_ign2[3]._l[0];
	xstatus = dst_xsave->xs_fxsave.__fx_ign2[3]._l[1];
	dst_xsave->xs_fxsave.__fx_ign2[3]._l[0] = 0;
	dst_xsave->xs_fxsave.__fx_ign2[3]._l[1] = 0;

	/*
	 * These two status words are information that the kernel itself uses to
	 * track additional information and is part of the traditional fpregset,
	 * but is not part of our xregs information. Because we are setting this
	 * state, we leave it up to the rest of the kernel to determine whether
	 * this came from an fpregset_t or is being reset to the default of 0.
	 */
	fpu->fpu_regs.kfpu_status = status;
	fpu->fpu_regs.kfpu_xstatus = xstatus;

	fpu->fpu_flags |= FPU_VALID;
	PCB_SET_UPDATE_FPU(&lwp->lwp_pcb);
	kpreempt_enable();
}

/*
 * Convert the current FPU state to the traditional fpregset_t. In the 64-bit
 * kernel, this is just an fxsave_state with additional values for the status
 * and xstatus members.
 *
 * This has the same nuance as the xregs cases discussed above, but is simpler
 * in that we only need to handle the fxsave state, but more complicated because
 * we need to check our save mechanism.
 */
void
fpu_get_fpregset(klwp_t *lwp, fpregset_t *fp)
{
	struct fpu_ctx *fpu = &lwp->lwp_pcb.pcb_fpu;

	kpreempt_disable();
	fp->fp_reg_set.fpchip_state.status = fpu->fpu_regs.kfpu_status;
	fp->fp_reg_set.fpchip_state.xstatus = fpu->fpu_regs.kfpu_xstatus;

	if ((fpu->fpu_flags & (FPU_EN | FPU_VALID)) == FPU_EN) {
		/*
		 * If we're requesting the fpregs of a thread that isn't
		 * currently valid and isn't the one that we're executing, then
		 * we consider getting this information to be a best-effort and
		 * we will not stop the thread in question to serialize it,
		 * which means possibly getting stale data. This is the
		 * traditional semantics that the system has used to service
		 * this for /proc.
		 */
		if (curthread == lwptot(lwp)) {
			VERIFY0(lwptot(lwp)->t_flag & T_KFPU);
			fp_save(fpu);
		}
	}

	/*
	 * If the FPU is not enabled and the state isn't valid (due to someone
	 * else setting it), just copy the initial state.
	 */
	if ((fpu->fpu_flags & (FPU_EN | FPU_VALID)) == 0) {
		bcopy(&sse_initial, fp, sizeof (sse_initial));
		kpreempt_enable();
		return;
	}

	/*
	 * Given that we have an enabled FPU, we must look at the type of FPU
	 * save mechanism to clean this up. In particular, while we can just
	 * copy the save area with FXSAVE, with XSAVE we must carefully copy
	 * only the bits that are valid and reset the rest to their default
	 * state.
	 */
	switch (fp_save_mech) {
	case FP_FXSAVE:
		bcopy(fpu->fpu_regs.kfpu_u.kfpu_fx, fp,
		    sizeof (struct fxsave_state));
		break;
	case FP_XSAVE:
		fpu_xsave_to_fxsave(fpu->fpu_regs.kfpu_u.kfpu_xs,
		    (struct fxsave_state *)fp);
		break;
	default:
		panic("Invalid fp_save_mech");
	}

	kpreempt_enable();
}

/*
 * This is a request to set the ABI fpregset_t into our actual hardware state.
 * In the 64-bit kernel the first 512 bytes of the fpregset_t is the same as the
 * 512-byte fxsave area.
 */
void
fpu_set_fpregset(klwp_t *lwp, const fpregset_t *fp)
{
	struct fpu_ctx *fpu = &lwp->lwp_pcb.pcb_fpu;

	kpreempt_disable();
	if ((fpu->fpu_flags & (FPU_EN | FPU_VALID)) == FPU_EN) {
		/*
		 * We always save the entire FPU. This is required if we're
		 * using xsave. If we're using fxsave, we could skip the
		 * 512-byte write and instead just disable the FPU since we'd be
		 * replacing it all. For now we don't bother with more
		 * conditional logic.
		 */
		VERIFY3P(curthread, ==, lwptot(lwp));
		VERIFY0(lwptot(lwp)->t_flag & T_KFPU);
		fp_save(fpu);
	}

	fpu->fpu_regs.kfpu_xstatus = fp->fp_reg_set.fpchip_state.xstatus;
	fpu->fpu_regs.kfpu_status = fp->fp_reg_set.fpchip_state.status;
	switch (fp_save_mech) {
	case FP_FXSAVE:
		bcopy(fp, fpu->fpu_regs.kfpu_u.kfpu_fx,
		    sizeof (struct fxsave_state));
		break;
	case FP_XSAVE:
		bcopy(fp, fpu->fpu_regs.kfpu_u.kfpu_xs,
		    sizeof (struct fxsave_state));
		fpu->fpu_regs.kfpu_u.kfpu_xs->xs_header.xsh_xstate_bv |=
		    XFEATURE_LEGACY_FP | XFEATURE_SSE;
		break;
	default:
		panic("Invalid fp_save_mech");
	}

	fpu->fpu_flags |= FPU_VALID;
	PCB_SET_UPDATE_FPU(&lwp->lwp_pcb);
	kpreempt_enable();
}
