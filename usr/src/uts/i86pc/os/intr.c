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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018 Joyent, Inc.  All rights reserverd.
 */

/*
 * To understand the present state of interrupt handling on i86pc, we must
 * first consider the history of interrupt controllers and our way of handling
 * interrupts.
 *
 * History of Interrupt Controllers on i86pc
 * -----------------------------------------
 *
 *    Intel 8259 and 8259A
 *
 * The first interrupt controller that attained widespread use on i86pc was
 * the Intel 8259(A) Programmable Interrupt Controller that first saw use with
 * the 8086. It took up to 8 interrupt sources and combined them into one
 * output wire. Up to 8 8259s could be slaved together providing up to 64 IRQs.
 * With the switch to the 8259A, level mode interrupts became possible. For a
 * long time on i86pc the 8259A was the only way to handle interrupts and it
 * had its own set of quirks. The 8259A and its corresponding interval timer
 * the 8254 are programmed using outb and inb instructions.
 *
 *    Intel Advanced Programmable Interrupt Controller (APIC)
 *
 * Starting around the time of the introduction of the P6 family
 * microarchitecture (i686) Intel introduced a new interrupt controller.
 * Instead of having the series of slaved 8259A devices, Intel opted to outfit
 * each processor with a Local APIC (lapic) and to outfit the system with at
 * least one, but potentially more, I/O APICs (ioapic). The lapics and ioapics
 * initially communicated over a dedicated bus, but this has since been
 * replaced. Each physical core and even hyperthread currently contains its
 * own local apic, which is not shared. There are a few exceptions for
 * hyperthreads, but that does not usually concern us.
 *
 * Instead of talking directly to 8259 for status, sending End Of Interrupt
 * (EOI), etc. a microprocessor now communicates directly to the lapic. This
 * also allows for each microprocessor to be able to have independent controls.
 * The programming method is different from the 8259. Consumers map the lapic
 * registers into uncacheable memory to read and manipulate the state.
 *
 * The number of addressable interrupt vectors was increased to 256. However
 * vectors 0-31 are reserved for the processor exception handling, leaving the
 * remaining vectors for general use. In addition to hardware generated
 * interrupts, the lapic provides a way for generating inter-processor
 * interrupts (IPI) which are the basis for CPU cross calls and CPU pokes.
 *
 * AMD ended up implementing the Intel APIC architecture in lieu of their work
 * with Cyrix.
 *
 *    Intel x2apic
 *
 * The x2apic is an extension to the lapic which started showing up around the
 * same time as the Sandy Bridge chipsets. It provides a new programming mode
 * as well as new features. The goal of the x2apic is to solve a few problems
 * with the previous generation of lapic and the x2apic is backwards compatible
 * with the previous programming and model. The only downsides to using the
 * backwards compatibility is that you are not able to take advantage of the new
 * x2apic features.
 *
 *    o The APIC ID is increased from an 8-bit value to a 32-bit value. This
 *    increases the maximum number of addressable physical processors beyond
 *    256. This new ID is assembled in a similar manner as the information that
 *    is obtainable by the extended cpuid topology leaves.
 *
 *    o A new means of generating IPIs was introduced.
 *
 *    o Instead of memory mapping the registers, the x2apic only allows for
 *    programming it through a series of wrmsrs. This has important semantic
 *    side effects. Recall that the registers were previously all mapped to
 *    uncachable memory which meant that all operations to the local apic were
 *    serializing instructions. With the switch to using wrmsrs this has been
 *    relaxed and these operations can no longer be assumed to be serializing
 *    instructions.
 *
 * Note for the rest of this we are only going to concern ourselves with the
 * apic and x2apic which practically all of i86pc has been using now for
 * quite some time.
 *
 * Interrupt Priority Levels
 * -------------------------
 *
 * On i86pc systems there are a total of fifteen interrupt priority levels
 * (ipls) which range from 1-15. Level 0 is for normal processing and
 * non-interrupt processing. To manipulate these values the family of spl
 * functions (which date back to UNIX on the PDP-11) are used. Specifically,
 * splr() to raise the priority level and splx() to lower it. One should not
 * generally call setspl() directly.
 *
 * Both i86pc and the supported SPARC platforms honor the same conventions for
 * the meaning behind these IPLs. The most important IPL is the platform's
 * LOCK_LEVEL (0xa on i86pc). If a thread is above LOCK_LEVEL it _must_ not
 * sleep on any synchronization object. The only allowed synchronization
 * primitive is a mutex that has been specifically initialized to be a spin
 * lock (see mutex_init(9F)). Another important level is DISP_LEVEL (0xb on
 * i86pc). You must be at DISP_LEVEL if you want to control the dispatcher.
 * The XC_HI_PIL is the highest level (0xf) and is used during cross-calls.
 *
 * Each interrupt that is registered in the system fires at a specific IPL.
 * Generally most interrupts fire below LOCK_LEVEL.
 *
 * PSM Drivers
 * -----------
 *
 * We currently have three sets of PSM (platform specific module) drivers
 * available. uppc, pcplusmp, and apix. uppc (uni-processor PC) is the original
 * driver that interacts with the 8259A and 8254. In general, it is not used
 * anymore given the prevalence of the apic.
 *
 * The system prefers to use the apix driver over the pcplusmp driver. The apix
 * driver requires HW support for an x2apic. If there is no x2apic HW, apix
 * will not be used. In general we prefer using the apix driver over the
 * pcplusmp driver because it gives us much more flexibility with respect to
 * interrupts. In the apix driver each local apic has its own independent set
 * of  interrupts, whereas the pcplusmp driver only has a single global set of
 * interrupts. This is why pcplusmp only supports a finite number of interrupts
 * per IPL -- generally 16, often less. The apix driver supports using either
 * the x2apic or the local apic programing modes. The programming mode does not
 * change the number of interrupts available, just the number of processors
 * that we can address. For the apix driver, the x2apic mode is enabled if the
 * system supports interrupt re-mapping, otherwise the module manages the
 * x2apic in local mode.
 *
 * When there is no x2apic present, we default back to the pcplusmp PSM driver.
 * In general, this is not problematic unless you have more than 256
 * processors in the machine or you do not have enough interrupts available.
 *
 * Controlling Interrupt Generation on i86pc
 * -----------------------------------------
 *
 * There are two different ways to manipulate which interrupts will be
 * generated on i86pc. Each offers different degrees of control.
 *
 * The first is through the flags register (eflags and rflags on i386 and amd64
 * respectively). The IF bit determines whether or not interrupts are enabled
 * or disabled. This is manipulated in one of several ways. The most common way
 * is through the cli and sti instructions. These clear the IF flag and set it,
 * respectively, for the current processor. The other common way is through the
 * use of the intr_clear and intr_restore functions.
 *
 * Assuming interrupts are not blocked by the IF flag, then the second form is
 * through the Processor-Priority Register (PPR). The PPR is used to determine
 * whether or not a pending interrupt should be delivered. If the ipl of the
 * new interrupt is higher than the current value in the PPR, then the lapic
 * will either deliver it immediately (if interrupts are not in progress) or it
 * will deliver it once the current interrupt processing has issued an EOI. The
 * highest unmasked interrupt will be the one delivered.
 *
 * The PPR register is based upon the max of the following two registers in the
 * lapic, the TPR register (also known as CR8 on amd64) that can be used to
 * mask interrupt levels, and the current vector. Because the pcplusmp module
 * always sets TPR appropriately early in the do_interrupt path, we can usually
 * just think that the PPR is the TPR. The pcplusmp module also issues an EOI
 * once it has set the TPR, so higher priority interrupts can come in while
 * we're servicing a lower priority interrupt.
 *
 * Handling Interrupts
 * -------------------
 *
 * Interrupts can be broken down into three categories based on priority and
 * source:
 *
 *   o High level interrupts
 *   o Low level hardware interrupts
 *   o Low level software interrupts
 *
 *   High Level Interrupts
 *
 * High level interrupts encompasses both hardware-sourced and software-sourced
 * interrupts. Examples of high level hardware interrupts include the serial
 * console. High level software-sourced interrupts are still delivered through
 * the local apic through IPIs. This is primarily cross calls.
 *
 * When a high level interrupt comes in, we will raise the SPL and then pin the
 * current lwp to the processor. We will use its lwp, but our own interrupt
 * stack and process the high level interrupt in-situ. These handlers are
 * designed to be very short in nature and cannot go to sleep, only block on a
 * spin lock. If the interrupt has a lot of work to do, it must generate a
 * low-priority software interrupt that will be processed later.
 *
 *   Low level hardware interrupts
 *
 * Low level hardware interrupts start off like their high-level cousins. The
 * current CPU contains a number of kernel threads (kthread_t) that can be used
 * to process low level interrupts. These are shared between both low level
 * hardware and software interrupts. Note that while we run with our
 * kthread_t, we borrow the pinned threads lwp_t until such a time as we hit a
 * synchronization object. If we hit one and need to sleep, then the scheduler
 * will instead create the rest of what we need.
 *
 *   Low level software interrupts
 *
 * Low level software interrupts are handled in a similar way as hardware
 * interrupts, but the notification vector is different. Each CPU has a bitmask
 * of pending software interrupts. We can notify a CPU to process software
 * interrupts through a specific trap vector as well as through several
 * checks that are performed throughout the code. These checks will look at
 * processing software interrupts as we lower our spl.
 *
 * We attempt to process the highest pending software interrupt that we can
 * which is greater than our current IPL. If none currently exist, then we move
 * on. We process a software interrupt in a similar fashion to a hardware
 * interrupt.
 *
 * Traditional Interrupt Flow
 * --------------------------
 *
 * The following diagram tracks the flow of the traditional uppc and pcplusmp
 * interrupt handlers. The apix driver has its own version of do_interrupt().
 * We come into the interrupt handler with all interrupts masked by the IF
 * flag. This is because we set up the handler using an interrupt-gate, which
 * is defined architecturally to have cleared the IF flag for us.
 *
 * +--------------+    +----------------+    +-----------+
 * | _interrupt() |--->| do_interrupt() |--->| *setlvl() |
 * +--------------+    +----------------+    +-----------+
 *                       |      |     |
 *                       |      |     |
 *              low-level|      |     | softint
 *                HW int |      |     +---------------------------------------+
 * +--------------+      |      |                                             |
 * | intr_thread_ |<-----+      | hi-level int                                |
 * | prolog()     |             |    +----------+                             |
 * +--------------+             +--->| hilevel_ |      Not on intr stack      |
 *       |                           | intr_    |-----------------+           |
 *       |                           | prolog() |                 |           |
 * +------------+                    +----------+                 |           |
 * | switch_sp_ |                        | On intr                v           |
 * | and_call() |                        | Stack          +------------+      |
 * +------------+                        |                | switch_sp_ |      |
 *       |                               v                | and_call() |      |
 *       v                             +-----------+      +------------+      |
 * +-----------+                       | dispatch_ |             |            |
 * | dispatch_ |   +-------------------| hilevel() |<------------+            |
 * | hardint() |   |                   +-----------+                          |
 * +-----------+   |                                                          |
 *       |         v                                                          |
 *       |     +-----+  +----------------------+  +-----+  hi-level           |
 *       +---->| sti |->| av_dispatch_autovect |->| cli |---------+           |
 *             +-----+  +----------------------+  +-----+         |           |
 *                                |                |              |           |
 *                                v                |              |           |
 *                         +----------+            |              |           |
 *                         | for each |            |              |           |
 *                         | handler  |            |              |           |
 *                         |  *intr() |            |              v           |
 * +--------------+        +----------+            |      +----------------+  |
 * | intr_thread_ |                      low-level |      | hilevel_intr_  |  |
 * | epilog()     |<-------------------------------+      | epilog()       |  |
 * +--------------+                                       +----------------+  |
 *   |       |                                                   |            |
 *   |       +----------------------v      v---------------------+            |
 *   |                           +------------+                               |
 *   |   +---------------------->| *setlvlx() |                               |
 *   |   |                       +------------+                               |
 *   |   |                              |                                     |
 *   |   |                              v                                     |
 *   |   |      +--------+     +------------------+      +-------------+      |
 *   |   |      | return |<----| softint pending? |----->| dosoftint() |<-----+
 *   |   |      +--------+  no +------------------+ yes  +-------------+
 *   |   |           ^                                      |     |
 *   |   |           |  softint pil too low                 |     |
 *   |   |           +--------------------------------------+     |
 *   |   |                                                        v
 *   |   |    +-----------+      +------------+          +-----------+
 *   |   |    | dispatch_ |<-----| switch_sp_ |<---------| *setspl() |
 *   |   |    | softint() |      | and_call() |          +-----------+
 *   |   |    +-----------+      +------------+
 *   |   |        |
 *   |   |        v
 *   |   |      +-----+  +----------------------+  +-----+  +------------+
 *   |   |      | sti |->| av_dispatch_autovect |->| cli |->| dosoftint_ |
 *   |   |      +-----+  +----------------------+  +-----+  | epilog()   |
 *   |   |                                                  +------------+
 *   |   |                                                    |     |
 *   |   +----------------------------------------------------+     |
 *   v                                                              |
 * +-----------+                                                    |
 * | interrupt |                                                    |
 * | thread    |<---------------------------------------------------+
 * | blocked   |
 * +-----------+
 *      |
 *      v
 *  +----------------+  +------------+  +-----------+  +-------+  +---------+
 *  | set_base_spl() |->| *setlvlx() |->| splhigh() |->| sti() |->| swtch() |
 *  +----------------+  +------------+  +-----------+  +-------+  +---------+
 *
 *    Calls made on Interrupt Stacks and Epilogue routines
 *
 * We use the switch_sp_and_call() assembly routine to switch our sp to the
 * interrupt stacks and then call the appropriate dispatch function. In the
 * case of interrupts which may block, softints and hardints, we always ensure
 * that we are still on the interrupt thread when we call the epilog routine.
 * This is not just important, it's necessary. If the interrupt thread blocked,
 * we won't return from our switch_sp_and_call() function and instead we'll go
 * through and set ourselves up to swtch() directly.
 *
 * New Interrupt Flow
 * ------------------
 *
 * The apix module has its own interrupt path. This is done for various
 * reasons. The first is that rather than having global interrupt vectors, we
 * now have per-cpu vectors.
 *
 * The other substantial change is that the apix design does not use the TPR to
 * mask interrupts below the current level. In fact, except for one special
 * case, it does not use the TPR at all. Instead, it only uses the IF flag
 * (cli/sti) to either block all interrupts or allow any interrupts to come in.
 * The design is such that when interrupts are allowed to come in, if we are
 * currently servicing a higher priority interupt, the new interrupt is treated
 * as pending and serviced later. Specifically, in the pcplusmp module's
 * apic_intr_enter() the code masks interrupts at or below the current
 * IPL using the TPR before sending EOI, whereas the apix module's
 * apix_intr_enter() simply sends EOI.
 *
 * The one special case where the apix code uses the TPR is when it calls
 * through the apic_reg_ops function pointer apic_write_task_reg in
 * apix_init_intr() to initially mask all levels and then finally to enable all
 * levels.
 *
 * Recall that we come into the interrupt handler with all interrupts masked
 * by the IF flag. This is because we set up the handler using an
 * interrupt-gate which is defined architecturally to have cleared the IF flag
 * for us.
 *
 * +--------------+    +---------------------+
 * | _interrupt() |--->| apix_do_interrupt() |
 * +--------------+    +---------------------+
 *                               |
 *                hard int? +----+--------+ softint?
 *                          |             | (but no low-level looping)
 *                   +-----------+        |
 *                   | *setlvl() |        |
 * +---------+       +-----------+        +----------------------------------+
 * |apix_add_|    check IPL |                                                |
 * |pending_ |<-------------+------+----------------------+                  |
 * |hardint()|        low-level int|          hi-level int|                  |
 * +---------+                     v                      v                  |
 *     | check IPL       +-----------------+     +---------------+           |
 *  +--+-----+           | apix_intr_      |     | apix_hilevel_ |           |
 *  |        |           | thread_prolog() |     | intr_prolog() |           |
 *  |      return        +-----------------+     +---------------+           |
 *  |                         |                    | On intr                 |
 *  |                   +------------+             | stack?  +------------+  |
 *  |                   | switch_sp_ |             +---------| switch_sp_ |  |
 *  |                   | and_call() |             |         | and_call() |  |
 *  |                   +------------+             |         +------------+  |
 *  |                         |                    |          |              |
 *  |                   +----------------+     +----------------+            |
 *  |                   | apix_dispatch_ |     | apix_dispatch_ |            |
 *  |                   | lowlevel()     |     | hilevel()      |            |
 *  |                   +----------------+     +----------------+            |
 *  |                                |             |                         |
 *  |                                v             v                         |
 *  |                       +-------------------------+                      |
 *  |                       |apix_dispatch_by_vector()|----+                 |
 *  |                       +-------------------------+    |                 |
 *  |               !XC_HI_PIL|         |         |        |                 |
 *  |                       +---+   +-------+   +---+      |                 |
 *  |                       |sti|   |*intr()|   |cli|      |                 |
 *  |                       +---+   +-------+   +---+      |  hi-level?      |
 *  |                          +---------------------------+----+            |
 *  |                          v                low-level?      v            |
 *  |                  +----------------+               +----------------+   |
 *  |                  | apix_intr_     |               | apix_hilevel_  |   |
 *  |                  | thread_epilog()|               | intr_epilog()  |   |
 *  |                  +----------------+               +----------------+   |
 *  |                          |                                |            |
 *  |        v-----------------+--------------------------------+            |
 *  |  +------------+                                                        |
 *  |  | *setlvlx() |   +----------------------------------------------------+
 *  |  +------------+   |
 *  |      |            |            +--------------------------------+ low
 *  v      v     v------+            v                                | level
 * +------------------+      +------------------+      +-----------+  | pending?
 * | apix_do_pending_ |----->| apix_do_pending_ |----->| apix_do_  |--+
 * | hilevel()        |      | hardint()        |      | softint() |  |
 * +------------------+      +------------------+      +-----------+    return
 *     |                       |                         |
 *     | while pending         | while pending           | while pending
 *     | hi-level              | low-level               | softint
 *     |                       |                         |
 *  +---------------+        +-----------------+       +-----------------+
 *  | apix_hilevel_ |        | apix_intr_      |       | apix_do_        |
 *  | intr_prolog() |        | thread_prolog() |       | softint_prolog()|
 *  +---------------+        +-----------------+       +-----------------+
 *     | On intr                       |                      |
 *     | stack? +------------+    +------------+        +------------+
 *     +--------| switch_sp_ |    | switch_sp_ |        | switch_sp_ |
 *     |        | and_call() |    | and_call() |        | and_call() |
 *     |        +------------+    +------------+        +------------+
 *     |           |                   |                      |
 *  +------------------+   +------------------+   +------------------------+
 *  | apix_dispatch_   |   | apix_dispatch_   |   | apix_dispatch_softint()|
 *  | pending_hilevel()|   | pending_hardint()|   +------------------------+
 *  +------------------+   +------------------+      |    |      |      |
 *    |         |           |         |              |    |      |      |
 *    | +----------------+  | +----------------+     |    |      |      |
 *    | | apix_hilevel_  |  | | apix_intr_     |     |    |      |      |
 *    | | intr_epilog()  |  | | thread_epilog()|     |    |      |      |
 *    | +----------------+  | +----------------+     |    |      |      |
 *    |         |           |       |                |    |      |      |
 *    |   +------------+    |  +----------+   +------+    |      |      |
 *    |   | *setlvlx() |    |  |*setlvlx()|   |           |      |      |
 *    |   +------------+    |  +----------+   |   +----------+   |   +---------+
 *    |                     |               +---+ |av_       | +---+ |apix_do_ |
 * +---------------------------------+      |sti| |dispatch_ | |cli| |softint_ |
 * | apix_dispatch_pending_autovect()|      +---+ |softvect()| +---+ |epilog() |
 * +---------------------------------+            +----------+       +---------+
 *  |!XC_HI_PIL  |       |         |                    |
 * +---+  +-------+    +---+  +----------+          +-------+
 * |sti|  |*intr()|    |cli|  |apix_post_|          |*intr()|
 * +---+  +-------+    +---+  |hardint() |          +-------+
 *                            +----------+
 */

#include <sys/cpuvar.h>
#include <sys/cpu_event.h>
#include <sys/regset.h>
#include <sys/psw.h>
#include <sys/types.h>
#include <sys/thread.h>
#include <sys/systm.h>
#include <sys/segments.h>
#include <sys/pcb.h>
#include <sys/trap.h>
#include <sys/ftrace.h>
#include <sys/traptrace.h>
#include <sys/clock.h>
#include <sys/panic.h>
#include <sys/disp.h>
#include <vm/seg_kp.h>
#include <sys/stack.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/kstat.h>
#include <sys/smp_impldefs.h>
#include <sys/pool_pset.h>
#include <sys/zone.h>
#include <sys/bitmap.h>
#include <sys/archsystm.h>
#include <sys/machsystm.h>
#include <sys/ontrap.h>
#include <sys/x86_archext.h>
#include <sys/promif.h>
#include <vm/hat_i86.h>
#if defined(__xpv)
#include <sys/hypervisor.h>
#endif

#if defined(__amd64) && !defined(__xpv)
/* If this fails, then the padding numbers in machcpuvar.h are wrong. */
CTASSERT((offsetof(cpu_t, cpu_m) + offsetof(struct machcpu, mcpu_pad))
    < MMU_PAGESIZE);
CTASSERT((offsetof(cpu_t, cpu_m) + offsetof(struct machcpu, mcpu_kpti))
    >= MMU_PAGESIZE);
CTASSERT((offsetof(cpu_t, cpu_m) + offsetof(struct machcpu, mcpu_kpti_dbg))
    < 2 * MMU_PAGESIZE);
CTASSERT((offsetof(cpu_t, cpu_m) + offsetof(struct machcpu, mcpu_pad2))
    < 2 * MMU_PAGESIZE);
CTASSERT(((sizeof (struct kpti_frame)) & 0xF) == 0);
CTASSERT(((offsetof(cpu_t, cpu_m) + offsetof(struct machcpu, mcpu_kpti_dbg))
    & 0xF) == 0);
CTASSERT((offsetof(struct kpti_frame, kf_tr_rsp) & 0xF) == 0);
#endif

#if defined(__xpv) && defined(DEBUG)

/*
 * This panic message is intended as an aid to interrupt debugging.
 *
 * The associated assertion tests the condition of enabling
 * events when events are already enabled.  The implication
 * being that whatever code the programmer thought was
 * protected by having events disabled until the second
 * enable happened really wasn't protected at all ..
 */

int stistipanic = 1;	/* controls the debug panic check */
const char *stistimsg = "stisti";
ulong_t laststi[NCPU];

/*
 * This variable tracks the last place events were disabled on each cpu
 * it assists in debugging when asserts that interrupts are enabled trip.
 */
ulong_t lastcli[NCPU];

#endif

void do_interrupt(struct regs *rp, trap_trace_rec_t *ttp);

void (*do_interrupt_common)(struct regs *, trap_trace_rec_t *) = do_interrupt;
uintptr_t (*get_intr_handler)(int, short) = NULL;

/*
 * Set cpu's base SPL level to the highest active interrupt level
 */
void
set_base_spl(void)
{
	struct cpu *cpu = CPU;
	uint16_t active = (uint16_t)cpu->cpu_intr_actv;

	cpu->cpu_base_spl = active == 0 ? 0 : bsrw_insn(active);
}

/*
 * Do all the work necessary to set up the cpu and thread structures
 * to dispatch a high-level interrupt.
 *
 * Returns 0 if we're -not- already on the high-level interrupt stack,
 * (and *must* switch to it), non-zero if we are already on that stack.
 *
 * Called with interrupts masked.
 * The 'pil' is already set to the appropriate level for rp->r_trapno.
 */
static int
hilevel_intr_prolog(struct cpu *cpu, uint_t pil, uint_t oldpil, struct regs *rp)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	uint_t mask;
	hrtime_t intrtime;
	hrtime_t now = tsc_read();

	ASSERT(pil > LOCK_LEVEL);

	if (pil == CBE_HIGH_PIL) {
		cpu->cpu_profile_pil = oldpil;
		if (USERMODE(rp->r_cs)) {
			cpu->cpu_profile_pc = 0;
			cpu->cpu_profile_upc = rp->r_pc;
			cpu->cpu_cpcprofile_pc = 0;
			cpu->cpu_cpcprofile_upc = rp->r_pc;
		} else {
			cpu->cpu_profile_pc = rp->r_pc;
			cpu->cpu_profile_upc = 0;
			cpu->cpu_cpcprofile_pc = rp->r_pc;
			cpu->cpu_cpcprofile_upc = 0;
		}
	}

	mask = cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK;
	if (mask != 0) {
		int nestpil;

		/*
		 * We have interrupted another high-level interrupt.
		 * Load starting timestamp, compute interval, update
		 * cumulative counter.
		 */
		nestpil = bsrw_insn((uint16_t)mask);
		ASSERT(nestpil < pil);
		intrtime = now -
		    mcpu->pil_high_start[nestpil - (LOCK_LEVEL + 1)];
		mcpu->intrstat[nestpil][0] += intrtime;
		cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
		/*
		 * Another high-level interrupt is active below this one, so
		 * there is no need to check for an interrupt thread.  That
		 * will be done by the lowest priority high-level interrupt
		 * active.
		 */
	} else {
		kthread_t *t = cpu->cpu_thread;

		/*
		 * See if we are interrupting a low-level interrupt thread.
		 * If so, account for its time slice only if its time stamp
		 * is non-zero.
		 */
		if ((t->t_flag & T_INTR_THREAD) != 0 && t->t_intr_start != 0) {
			intrtime = now - t->t_intr_start;
			mcpu->intrstat[t->t_pil][0] += intrtime;
			cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
			t->t_intr_start = 0;
		}
	}

	/*
	 * Store starting timestamp in CPU structure for this PIL.
	 */
	mcpu->pil_high_start[pil - (LOCK_LEVEL + 1)] = now;

	ASSERT((cpu->cpu_intr_actv & (1 << pil)) == 0);

	if (pil == 15) {
		/*
		 * To support reentrant level 15 interrupts, we maintain a
		 * recursion count in the top half of cpu_intr_actv.  Only
		 * when this count hits zero do we clear the PIL 15 bit from
		 * the lower half of cpu_intr_actv.
		 */
		uint16_t *refcntp = (uint16_t *)&cpu->cpu_intr_actv + 1;
		(*refcntp)++;
	}

	mask = cpu->cpu_intr_actv;

	cpu->cpu_intr_actv |= (1 << pil);

	return (mask & CPU_INTR_ACTV_HIGH_LEVEL_MASK);
}

/*
 * Does most of the work of returning from a high level interrupt.
 *
 * Returns 0 if there are no more high level interrupts (in which
 * case we must switch back to the interrupted thread stack) or
 * non-zero if there are more (in which case we should stay on it).
 *
 * Called with interrupts masked
 */
static int
hilevel_intr_epilog(struct cpu *cpu, uint_t pil, uint_t oldpil, uint_t vecnum)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	uint_t mask;
	hrtime_t intrtime;
	hrtime_t now = tsc_read();

	ASSERT(mcpu->mcpu_pri == pil);

	cpu->cpu_stats.sys.intr[pil - 1]++;

	ASSERT(cpu->cpu_intr_actv & (1 << pil));

	if (pil == 15) {
		/*
		 * To support reentrant level 15 interrupts, we maintain a
		 * recursion count in the top half of cpu_intr_actv.  Only
		 * when this count hits zero do we clear the PIL 15 bit from
		 * the lower half of cpu_intr_actv.
		 */
		uint16_t *refcntp = (uint16_t *)&cpu->cpu_intr_actv + 1;

		ASSERT(*refcntp > 0);

		if (--(*refcntp) == 0)
			cpu->cpu_intr_actv &= ~(1 << pil);
	} else {
		cpu->cpu_intr_actv &= ~(1 << pil);
	}

	ASSERT(mcpu->pil_high_start[pil - (LOCK_LEVEL + 1)] != 0);

	intrtime = now - mcpu->pil_high_start[pil - (LOCK_LEVEL + 1)];
	mcpu->intrstat[pil][0] += intrtime;
	cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;

	/*
	 * Check for lower-pil nested high-level interrupt beneath
	 * current one.  If so, place a starting timestamp in its
	 * pil_high_start entry.
	 */
	mask = cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK;
	if (mask != 0) {
		int nestpil;

		/*
		 * find PIL of nested interrupt
		 */
		nestpil = bsrw_insn((uint16_t)mask);
		ASSERT(nestpil < pil);
		mcpu->pil_high_start[nestpil - (LOCK_LEVEL + 1)] = now;
		/*
		 * (Another high-level interrupt is active below this one,
		 * so there is no need to check for an interrupt
		 * thread.  That will be done by the lowest priority
		 * high-level interrupt active.)
		 */
	} else {
		/*
		 * Check to see if there is a low-level interrupt active.
		 * If so, place a starting timestamp in the thread
		 * structure.
		 */
		kthread_t *t = cpu->cpu_thread;

		if (t->t_flag & T_INTR_THREAD)
			t->t_intr_start = now;
	}

	mcpu->mcpu_pri = oldpil;
	(void) (*setlvlx)(oldpil, vecnum);

	return (cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK);
}

/*
 * Set up the cpu, thread and interrupt thread structures for
 * executing an interrupt thread.  The new stack pointer of the
 * interrupt thread (which *must* be switched to) is returned.
 */
static caddr_t
intr_thread_prolog(struct cpu *cpu, caddr_t stackptr, uint_t pil)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	kthread_t *t, *volatile it;
	hrtime_t now = tsc_read();

	ASSERT(pil > 0);
	ASSERT((cpu->cpu_intr_actv & (1 << pil)) == 0);
	cpu->cpu_intr_actv |= (1 << pil);

	/*
	 * Get set to run an interrupt thread.
	 * There should always be an interrupt thread, since we
	 * allocate one for each level on each CPU.
	 *
	 * t_intr_start could be zero due to cpu_intr_swtch_enter.
	 */
	t = cpu->cpu_thread;
	if ((t->t_flag & T_INTR_THREAD) && t->t_intr_start != 0) {
		hrtime_t intrtime = now - t->t_intr_start;
		mcpu->intrstat[t->t_pil][0] += intrtime;
		cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
		t->t_intr_start = 0;
	}

	ASSERT(SA((uintptr_t)stackptr) == (uintptr_t)stackptr);

	t->t_sp = (uintptr_t)stackptr;	/* mark stack in curthread for resume */

	/*
	 * unlink the interrupt thread off the cpu
	 *
	 * Note that the code in kcpc_overflow_intr -relies- on the
	 * ordering of events here - in particular that t->t_lwp of
	 * the interrupt thread is set to the pinned thread *before*
	 * curthread is changed.
	 */
	it = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it->t_link;
	it->t_intr = t;
	it->t_lwp = t->t_lwp;

	/*
	 * (threads on the interrupt thread free list could have state
	 * preset to TS_ONPROC, but it helps in debugging if
	 * they're TS_FREE.)
	 */
	it->t_state = TS_ONPROC;

	cpu->cpu_thread = it;		/* new curthread on this cpu */
	it->t_pil = (uchar_t)pil;
	it->t_pri = intr_pri + (pri_t)pil;
	it->t_intr_start = now;

	return (it->t_stk);
}


#ifdef DEBUG
int intr_thread_cnt;
#endif

/*
 * Called with interrupts disabled
 */
static void
intr_thread_epilog(struct cpu *cpu, uint_t vec, uint_t oldpil)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	kthread_t *t;
	kthread_t *it = cpu->cpu_thread;	/* curthread */
	uint_t pil, basespl;
	hrtime_t intrtime;
	hrtime_t now = tsc_read();

	pil = it->t_pil;
	cpu->cpu_stats.sys.intr[pil - 1]++;

	ASSERT(it->t_intr_start != 0);
	intrtime = now - it->t_intr_start;
	mcpu->intrstat[pil][0] += intrtime;
	cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;

	ASSERT(cpu->cpu_intr_actv & (1 << pil));
	cpu->cpu_intr_actv &= ~(1 << pil);

	/*
	 * If there is still an interrupted thread underneath this one
	 * then the interrupt was never blocked and the return is
	 * fairly simple.  Otherwise it isn't.
	 */
	if ((t = it->t_intr) == NULL) {
		/*
		 * The interrupted thread is no longer pinned underneath
		 * the interrupt thread.  This means the interrupt must
		 * have blocked, and the interrupted thread has been
		 * unpinned, and has probably been running around the
		 * system for a while.
		 *
		 * Since there is no longer a thread under this one, put
		 * this interrupt thread back on the CPU's free list and
		 * resume the idle thread which will dispatch the next
		 * thread to run.
		 */
#ifdef DEBUG
		intr_thread_cnt++;
#endif
		cpu->cpu_stats.sys.intrblk++;
		/*
		 * Set CPU's base SPL based on active interrupts bitmask
		 */
		set_base_spl();
		basespl = cpu->cpu_base_spl;
		mcpu->mcpu_pri = basespl;
		(*setlvlx)(basespl, vec);
		(void) splhigh();
		sti();
		it->t_state = TS_FREE;
		/*
		 * Return interrupt thread to pool
		 */
		it->t_link = cpu->cpu_intr_thread;
		cpu->cpu_intr_thread = it;
		swtch();
		panic("intr_thread_epilog: swtch returned");
		/*NOTREACHED*/
	}

	/*
	 * Return interrupt thread to the pool
	 */
	it->t_link = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it;
	it->t_state = TS_FREE;

	basespl = cpu->cpu_base_spl;
	pil = MAX(oldpil, basespl);
	mcpu->mcpu_pri = pil;
	(*setlvlx)(pil, vec);
	t->t_intr_start = now;
	cpu->cpu_thread = t;
}

/*
 * intr_get_time() is a resource for interrupt handlers to determine how
 * much time has been spent handling the current interrupt. Such a function
 * is needed because higher level interrupts can arrive during the
 * processing of an interrupt.  intr_get_time() only returns time spent in the
 * current interrupt handler.
 *
 * The caller must be calling from an interrupt handler running at a pil
 * below or at lock level. Timings are not provided for high-level
 * interrupts.
 *
 * The first time intr_get_time() is called while handling an interrupt,
 * it returns the time since the interrupt handler was invoked. Subsequent
 * calls will return the time since the prior call to intr_get_time(). Time
 * is returned as ticks. Use scalehrtimef() to convert ticks to nsec.
 *
 * Theory Of Intrstat[][]:
 *
 * uint64_t intrstat[pil][0..1] is an array indexed by pil level, with two
 * uint64_ts per pil.
 *
 * intrstat[pil][0] is a cumulative count of the number of ticks spent
 * handling all interrupts at the specified pil on this CPU. It is
 * exported via kstats to the user.
 *
 * intrstat[pil][1] is always a count of ticks less than or equal to the
 * value in [0]. The difference between [1] and [0] is the value returned
 * by a call to intr_get_time(). At the start of interrupt processing,
 * [0] and [1] will be equal (or nearly so). As the interrupt consumes
 * time, [0] will increase, but [1] will remain the same. A call to
 * intr_get_time() will return the difference, then update [1] to be the
 * same as [0]. Future calls will return the time since the last call.
 * Finally, when the interrupt completes, [1] is updated to the same as [0].
 *
 * Implementation:
 *
 * intr_get_time() works much like a higher level interrupt arriving. It
 * "checkpoints" the timing information by incrementing intrstat[pil][0]
 * to include elapsed running time, and by setting t_intr_start to rdtsc.
 * It then sets the return value to intrstat[pil][0] - intrstat[pil][1],
 * and updates intrstat[pil][1] to be the same as the new value of
 * intrstat[pil][0].
 *
 * In the normal handling of interrupts, after an interrupt handler returns
 * and the code in intr_thread() updates intrstat[pil][0], it then sets
 * intrstat[pil][1] to the new value of intrstat[pil][0]. When [0] == [1],
 * the timings are reset, i.e. intr_get_time() will return [0] - [1] which
 * is 0.
 *
 * Whenever interrupts arrive on a CPU which is handling a lower pil
 * interrupt, they update the lower pil's [0] to show time spent in the
 * handler that they've interrupted. This results in a growing discrepancy
 * between [0] and [1], which is returned the next time intr_get_time() is
 * called. Time spent in the higher-pil interrupt will not be returned in
 * the next intr_get_time() call from the original interrupt, because
 * the higher-pil interrupt's time is accumulated in intrstat[higherpil][].
 */
uint64_t
intr_get_time(void)
{
	struct cpu *cpu;
	struct machcpu *mcpu;
	kthread_t *t;
	uint64_t time, delta, ret;
	uint_t pil;

	cli();
	cpu = CPU;
	mcpu = &cpu->cpu_m;
	t = cpu->cpu_thread;
	pil = t->t_pil;
	ASSERT((cpu->cpu_intr_actv & CPU_INTR_ACTV_HIGH_LEVEL_MASK) == 0);
	ASSERT(t->t_flag & T_INTR_THREAD);
	ASSERT(pil != 0);
	ASSERT(t->t_intr_start != 0);

	time = tsc_read();
	delta = time - t->t_intr_start;
	t->t_intr_start = time;

	time = mcpu->intrstat[pil][0] + delta;
	ret = time - mcpu->intrstat[pil][1];
	mcpu->intrstat[pil][0] = time;
	mcpu->intrstat[pil][1] = time;
	cpu->cpu_intracct[cpu->cpu_mstate] += delta;

	sti();
	return (ret);
}

static caddr_t
dosoftint_prolog(
	struct cpu *cpu,
	caddr_t stackptr,
	uint32_t st_pending,
	uint_t oldpil)
{
	kthread_t *t, *volatile it;
	struct machcpu *mcpu = &cpu->cpu_m;
	uint_t pil;
	hrtime_t now;

top:
	ASSERT(st_pending == mcpu->mcpu_softinfo.st_pending);

	pil = bsrw_insn((uint16_t)st_pending);
	if (pil <= oldpil || pil <= cpu->cpu_base_spl)
		return (0);

	/*
	 * XX64	Sigh.
	 *
	 * This is a transliteration of the i386 assembler code for
	 * soft interrupts.  One question is "why does this need
	 * to be atomic?"  One possible race is -other- processors
	 * posting soft interrupts to us in set_pending() i.e. the
	 * CPU might get preempted just after the address computation,
	 * but just before the atomic transaction, so another CPU would
	 * actually set the original CPU's st_pending bit.  However,
	 * it looks like it would be simpler to disable preemption there.
	 * Are there other races for which preemption control doesn't work?
	 *
	 * The i386 assembler version -also- checks to see if the bit
	 * being cleared was actually set; if it wasn't, it rechecks
	 * for more.  This seems a bit strange, as the only code that
	 * ever clears the bit is -this- code running with interrupts
	 * disabled on -this- CPU.  This code would probably be cheaper:
	 *
	 * atomic_and_32((uint32_t *)&mcpu->mcpu_softinfo.st_pending,
	 *   ~(1 << pil));
	 *
	 * and t->t_preempt--/++ around set_pending() even cheaper,
	 * but at this point, correctness is critical, so we slavishly
	 * emulate the i386 port.
	 */
	if (atomic_btr32((uint32_t *)
	    &mcpu->mcpu_softinfo.st_pending, pil) == 0) {
		st_pending = mcpu->mcpu_softinfo.st_pending;
		goto top;
	}

	mcpu->mcpu_pri = pil;
	(*setspl)(pil);

	now = tsc_read();

	/*
	 * Get set to run interrupt thread.
	 * There should always be an interrupt thread since we
	 * allocate one for each level on the CPU.
	 */
	it = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it->t_link;

	/* t_intr_start could be zero due to cpu_intr_swtch_enter. */
	t = cpu->cpu_thread;
	if ((t->t_flag & T_INTR_THREAD) && t->t_intr_start != 0) {
		hrtime_t intrtime = now - t->t_intr_start;
		mcpu->intrstat[pil][0] += intrtime;
		cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;
		t->t_intr_start = 0;
	}

	/*
	 * Note that the code in kcpc_overflow_intr -relies- on the
	 * ordering of events here - in particular that t->t_lwp of
	 * the interrupt thread is set to the pinned thread *before*
	 * curthread is changed.
	 */
	it->t_lwp = t->t_lwp;
	it->t_state = TS_ONPROC;

	/*
	 * Push interrupted thread onto list from new thread.
	 * Set the new thread as the current one.
	 * Set interrupted thread's T_SP because if it is the idle thread,
	 * resume() may use that stack between threads.
	 */

	ASSERT(SA((uintptr_t)stackptr) == (uintptr_t)stackptr);
	t->t_sp = (uintptr_t)stackptr;

	it->t_intr = t;
	cpu->cpu_thread = it;

	/*
	 * Set bit for this pil in CPU's interrupt active bitmask.
	 */
	ASSERT((cpu->cpu_intr_actv & (1 << pil)) == 0);
	cpu->cpu_intr_actv |= (1 << pil);

	/*
	 * Initialize thread priority level from intr_pri
	 */
	it->t_pil = (uchar_t)pil;
	it->t_pri = (pri_t)pil + intr_pri;
	it->t_intr_start = now;

	return (it->t_stk);
}

static void
dosoftint_epilog(struct cpu *cpu, uint_t oldpil)
{
	struct machcpu *mcpu = &cpu->cpu_m;
	kthread_t *t, *it;
	uint_t pil, basespl;
	hrtime_t intrtime;
	hrtime_t now = tsc_read();

	it = cpu->cpu_thread;
	pil = it->t_pil;

	cpu->cpu_stats.sys.intr[pil - 1]++;

	ASSERT(cpu->cpu_intr_actv & (1 << pil));
	cpu->cpu_intr_actv &= ~(1 << pil);
	intrtime = now - it->t_intr_start;
	mcpu->intrstat[pil][0] += intrtime;
	cpu->cpu_intracct[cpu->cpu_mstate] += intrtime;

	/*
	 * If there is still an interrupted thread underneath this one
	 * then the interrupt was never blocked and the return is
	 * fairly simple.  Otherwise it isn't.
	 */
	if ((t = it->t_intr) == NULL) {
		/*
		 * Put thread back on the interrupt thread list.
		 * This was an interrupt thread, so set CPU's base SPL.
		 */
		set_base_spl();
		it->t_state = TS_FREE;
		it->t_link = cpu->cpu_intr_thread;
		cpu->cpu_intr_thread = it;
		(void) splhigh();
		sti();
		swtch();
		/*NOTREACHED*/
		panic("dosoftint_epilog: swtch returned");
	}
	it->t_link = cpu->cpu_intr_thread;
	cpu->cpu_intr_thread = it;
	it->t_state = TS_FREE;
	cpu->cpu_thread = t;
	if (t->t_flag & T_INTR_THREAD)
		t->t_intr_start = now;
	basespl = cpu->cpu_base_spl;
	pil = MAX(oldpil, basespl);
	mcpu->mcpu_pri = pil;
	(*setspl)(pil);
}


/*
 * Make the interrupted thread 'to' be runnable.
 *
 * Since t->t_sp has already been saved, t->t_pc is all
 * that needs to be set in this function.
 *
 * Returns the interrupt level of the interrupt thread.
 */
int
intr_passivate(
	kthread_t *it,		/* interrupt thread */
	kthread_t *t)		/* interrupted thread */
{
	extern void _sys_rtt();

	ASSERT(it->t_flag & T_INTR_THREAD);
	ASSERT(SA(t->t_sp) == t->t_sp);

	t->t_pc = (uintptr_t)_sys_rtt;
	return (it->t_pil);
}

/*
 * Create interrupt kstats for this CPU.
 */
void
cpu_create_intrstat(cpu_t *cp)
{
	int		i;
	kstat_t		*intr_ksp;
	kstat_named_t	*knp;
	char		name[KSTAT_STRLEN];
	zoneid_t	zoneid;

	ASSERT(MUTEX_HELD(&cpu_lock));

	if (pool_pset_enabled())
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = ALL_ZONES;

	intr_ksp = kstat_create_zone("cpu", cp->cpu_id, "intrstat", "misc",
	    KSTAT_TYPE_NAMED, PIL_MAX * 2, NULL, zoneid);

	/*
	 * Initialize each PIL's named kstat
	 */
	if (intr_ksp != NULL) {
		intr_ksp->ks_update = cpu_kstat_intrstat_update;
		knp = (kstat_named_t *)intr_ksp->ks_data;
		intr_ksp->ks_private = cp;
		for (i = 0; i < PIL_MAX; i++) {
			(void) snprintf(name, KSTAT_STRLEN, "level-%d-time",
			    i + 1);
			kstat_named_init(&knp[i * 2], name, KSTAT_DATA_UINT64);
			(void) snprintf(name, KSTAT_STRLEN, "level-%d-count",
			    i + 1);
			kstat_named_init(&knp[(i * 2) + 1], name,
			    KSTAT_DATA_UINT64);
		}
		kstat_install(intr_ksp);
	}
}

/*
 * Delete interrupt kstats for this CPU.
 */
void
cpu_delete_intrstat(cpu_t *cp)
{
	kstat_delete_byname_zone("cpu", cp->cpu_id, "intrstat", ALL_ZONES);
}

/*
 * Convert interrupt statistics from CPU ticks to nanoseconds and
 * update kstat.
 */
int
cpu_kstat_intrstat_update(kstat_t *ksp, int rw)
{
	kstat_named_t	*knp = ksp->ks_data;
	cpu_t		*cpup = (cpu_t *)ksp->ks_private;
	int		i;
	hrtime_t	hrt;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	for (i = 0; i < PIL_MAX; i++) {
		hrt = (hrtime_t)cpup->cpu_m.intrstat[i + 1][0];
		scalehrtimef(&hrt);
		knp[i * 2].value.ui64 = (uint64_t)hrt;
		knp[(i * 2) + 1].value.ui64 = cpup->cpu_stats.sys.intr[i];
	}

	return (0);
}

/*
 * An interrupt thread is ending a time slice, so compute the interval it
 * ran for and update the statistic for its PIL.
 */
void
cpu_intr_swtch_enter(kthread_id_t t)
{
	uint64_t	interval;
	uint64_t	start;
	cpu_t		*cpu;

	ASSERT((t->t_flag & T_INTR_THREAD) != 0);
	ASSERT(t->t_pil > 0 && t->t_pil <= LOCK_LEVEL);

	/*
	 * We could be here with a zero timestamp. This could happen if:
	 * an interrupt thread which no longer has a pinned thread underneath
	 * it (i.e. it blocked at some point in its past) has finished running
	 * its handler. intr_thread() updated the interrupt statistic for its
	 * PIL and zeroed its timestamp. Since there was no pinned thread to
	 * return to, swtch() gets called and we end up here.
	 *
	 * Note that we use atomic ops below (atomic_cas_64 and
	 * atomic_add_64), which we don't use in the functions above,
	 * because we're not called with interrupts blocked, but the
	 * epilog/prolog functions are.
	 */
	if (t->t_intr_start) {
		do {
			start = t->t_intr_start;
			interval = tsc_read() - start;
		} while (atomic_cas_64(&t->t_intr_start, start, 0) != start);
		cpu = CPU;
		cpu->cpu_m.intrstat[t->t_pil][0] += interval;

		atomic_add_64((uint64_t *)&cpu->cpu_intracct[cpu->cpu_mstate],
		    interval);
	} else
		ASSERT(t->t_intr == NULL);
}

/*
 * An interrupt thread is returning from swtch(). Place a starting timestamp
 * in its thread structure.
 */
void
cpu_intr_swtch_exit(kthread_id_t t)
{
	uint64_t ts;

	ASSERT((t->t_flag & T_INTR_THREAD) != 0);
	ASSERT(t->t_pil > 0 && t->t_pil <= LOCK_LEVEL);

	do {
		ts = t->t_intr_start;
	} while (atomic_cas_64(&t->t_intr_start, ts, tsc_read()) != ts);
}

/*
 * Dispatch a hilevel interrupt (one above LOCK_LEVEL)
 */
/*ARGSUSED*/
static void
dispatch_hilevel(uint_t vector, uint_t arg2)
{
	sti();
	av_dispatch_autovect(vector);
	cli();
}

/*
 * Dispatch a soft interrupt
 */
/*ARGSUSED*/
static void
dispatch_softint(uint_t oldpil, uint_t arg2)
{
	struct cpu *cpu = CPU;

	sti();
	av_dispatch_softvect((int)cpu->cpu_thread->t_pil);
	cli();

	/*
	 * Must run softint_epilog() on the interrupt thread stack, since
	 * there may not be a return from it if the interrupt thread blocked.
	 */
	dosoftint_epilog(cpu, oldpil);
}

/*
 * Dispatch a normal interrupt
 */
static void
dispatch_hardint(uint_t vector, uint_t oldipl)
{
	struct cpu *cpu = CPU;

	sti();
	av_dispatch_autovect(vector);
	cli();

	/*
	 * Must run intr_thread_epilog() on the interrupt thread stack, since
	 * there may not be a return from it if the interrupt thread blocked.
	 */
	intr_thread_epilog(cpu, vector, oldipl);
}

/*
 * Deliver any softints the current interrupt priority allows.
 * Called with interrupts disabled.
 */
void
dosoftint(struct regs *regs)
{
	struct cpu *cpu = CPU;
	int oldipl;
	caddr_t newsp;

	while (cpu->cpu_softinfo.st_pending) {
		oldipl = cpu->cpu_pri;
		newsp = dosoftint_prolog(cpu, (caddr_t)regs,
		    cpu->cpu_softinfo.st_pending, oldipl);
		/*
		 * If returned stack pointer is NULL, priority is too high
		 * to run any of the pending softints now.
		 * Break out and they will be run later.
		 */
		if (newsp == NULL)
			break;
		switch_sp_and_call(newsp, dispatch_softint, oldipl, 0);
	}
}

/*
 * Interrupt service routine, called with interrupts disabled.
 */
/*ARGSUSED*/
void
do_interrupt(struct regs *rp, trap_trace_rec_t *ttp)
{
	struct cpu *cpu = CPU;
	int newipl, oldipl = cpu->cpu_pri;
	uint_t vector;
	caddr_t newsp;

#ifdef TRAPTRACE
	ttp->ttr_marker = TT_INTERRUPT;
	ttp->ttr_ipl = 0xff;
	ttp->ttr_pri = oldipl;
	ttp->ttr_spl = cpu->cpu_base_spl;
	ttp->ttr_vector = 0xff;
#endif	/* TRAPTRACE */

	cpu_idle_exit(CPU_IDLE_CB_FLAG_INTR);

	++*(uint16_t *)&cpu->cpu_m.mcpu_istamp;

	/*
	 * If it's a softint go do it now.
	 */
	if (rp->r_trapno == T_SOFTINT) {
		dosoftint(rp);
		ASSERT(!interrupts_enabled());
		return;
	}

	/*
	 * Raise the interrupt priority.
	 */
	newipl = (*setlvl)(oldipl, (int *)&rp->r_trapno);
#ifdef TRAPTRACE
	ttp->ttr_ipl = newipl;
#endif	/* TRAPTRACE */

	/*
	 * Bail if it is a spurious interrupt
	 */
	if (newipl == -1)
		return;
	cpu->cpu_pri = newipl;
	vector = rp->r_trapno;
#ifdef TRAPTRACE
	ttp->ttr_vector = vector;
#endif	/* TRAPTRACE */
	if (newipl > LOCK_LEVEL) {
		/*
		 * High priority interrupts run on this cpu's interrupt stack.
		 */
		if (hilevel_intr_prolog(cpu, newipl, oldipl, rp) == 0) {
			newsp = cpu->cpu_intr_stack;
			switch_sp_and_call(newsp, dispatch_hilevel, vector, 0);
		} else { /* already on the interrupt stack */
			dispatch_hilevel(vector, 0);
		}
		(void) hilevel_intr_epilog(cpu, newipl, oldipl, vector);
	} else {
		/*
		 * Run this interrupt in a separate thread.
		 */
		newsp = intr_thread_prolog(cpu, (caddr_t)rp, newipl);
		switch_sp_and_call(newsp, dispatch_hardint, vector, oldipl);
	}

#if !defined(__xpv)
	/*
	 * Deliver any pending soft interrupts.
	 */
	if (cpu->cpu_softinfo.st_pending)
		dosoftint(rp);
#endif	/* !__xpv */
}


/*
 * Common tasks always done by _sys_rtt, called with interrupts disabled.
 * Returns 1 if returning to userland, 0 if returning to system mode.
 */
int
sys_rtt_common(struct regs *rp)
{
	kthread_t *tp;
	extern void mutex_exit_critical_start();
	extern long mutex_exit_critical_size;
	extern void mutex_owner_running_critical_start();
	extern long mutex_owner_running_critical_size;

loop:

	/*
	 * Check if returning to user
	 */
	tp = CPU->cpu_thread;
	if (USERMODE(rp->r_cs)) {
		/*
		 * Check if AST pending.
		 */
		if (tp->t_astflag) {
			/*
			 * Let trap() handle the AST
			 */
			sti();
			rp->r_trapno = T_AST;
			trap(rp, (caddr_t)0, CPU->cpu_id);
			cli();
			goto loop;
		}

#if defined(__amd64)
		/*
		 * We are done if segment registers do not need updating.
		 */
		if (tp->t_lwp->lwp_pcb.pcb_rupdate == 0)
			return (1);

		if (update_sregs(rp, tp->t_lwp)) {
			/*
			 * 1 or more of the selectors is bad.
			 * Deliver a SIGSEGV.
			 */
			proc_t *p = ttoproc(tp);

			sti();
			mutex_enter(&p->p_lock);
			tp->t_lwp->lwp_cursig = SIGSEGV;
			mutex_exit(&p->p_lock);
			psig();
			tp->t_sig_check = 1;
			cli();
		}
		tp->t_lwp->lwp_pcb.pcb_rupdate = 0;

#endif	/* __amd64 */
		return (1);
	}

#if !defined(__xpv)
	/*
	 * Assert that we're not trying to return into the syscall return
	 * trampolines. Things will go baaaaad if we try to do that.
	 *
	 * Note that none of these run with interrupts on, so this should
	 * never happen (even in the sysexit case the STI doesn't take effect
	 * until after sysexit finishes).
	 */
	extern void tr_sysc_ret_start();
	extern void tr_sysc_ret_end();
	ASSERT(!(rp->r_pc >= (uintptr_t)tr_sysc_ret_start &&
	    rp->r_pc <= (uintptr_t)tr_sysc_ret_end));
#endif

	/*
	 * Here if we are returning to supervisor mode.
	 * Check for a kernel preemption request.
	 */
	if (CPU->cpu_kprunrun && (rp->r_ps & PS_IE)) {

		/*
		 * Do nothing if already in kpreempt
		 */
		if (!tp->t_preempt_lk) {
			tp->t_preempt_lk = 1;
			sti();
			kpreempt(1); /* asynchronous kpreempt call */
			cli();
			tp->t_preempt_lk = 0;
		}
	}

	/*
	 * If we interrupted the mutex_exit() critical region we must
	 * reset the PC back to the beginning to prevent missed wakeups
	 * See the comments in mutex_exit() for details.
	 */
	if ((uintptr_t)rp->r_pc - (uintptr_t)mutex_exit_critical_start <
	    mutex_exit_critical_size) {
		rp->r_pc = (greg_t)mutex_exit_critical_start;
	}

	/*
	 * If we interrupted the mutex_owner_running() critical region we
	 * must reset the PC back to the beginning to prevent dereferencing
	 * of a freed thread pointer. See the comments in mutex_owner_running
	 * for details.
	 */
	if ((uintptr_t)rp->r_pc -
	    (uintptr_t)mutex_owner_running_critical_start <
	    mutex_owner_running_critical_size) {
		rp->r_pc = (greg_t)mutex_owner_running_critical_start;
	}

	return (0);
}

void
send_dirint(int cpuid, int int_level)
{
	(*send_dirintf)(cpuid, int_level);
}

#define	IS_FAKE_SOFTINT(flag, newpri)		\
	(((flag) & PS_IE) &&				\
	    (((*get_pending_spl)() > (newpri)) ||	\
	    bsrw_insn((uint16_t)cpu->cpu_softinfo.st_pending) > (newpri)))

/*
 * do_splx routine, takes new ipl to set
 * returns the old ipl.
 * We are careful not to set priority lower than CPU->cpu_base_pri,
 * even though it seems we're raising the priority, it could be set
 * higher at any time by an interrupt routine, so we must block interrupts
 * and look at CPU->cpu_base_pri
 */
int
do_splx(int newpri)
{
	ulong_t	flag;
	cpu_t	*cpu;
	int	curpri, basepri;

	flag = intr_clear();
	cpu = CPU; /* ints are disabled, now safe to cache cpu ptr */
	curpri = cpu->cpu_m.mcpu_pri;
	basepri = cpu->cpu_base_spl;
	if (newpri < basepri)
		newpri = basepri;
	cpu->cpu_m.mcpu_pri = newpri;
	(*setspl)(newpri);
	/*
	 * If we are going to reenable interrupts see if new priority level
	 * allows pending softint delivery.
	 */
	if (IS_FAKE_SOFTINT(flag, newpri))
		fakesoftint();
	ASSERT(!interrupts_enabled());
	intr_restore(flag);
	return (curpri);
}

/*
 * Common spl raise routine, takes new ipl to set
 * returns the old ipl, will not lower ipl.
 */
int
splr(int newpri)
{
	ulong_t	flag;
	cpu_t	*cpu;
	int	curpri, basepri;

	flag = intr_clear();
	cpu = CPU; /* ints are disabled, now safe to cache cpu ptr */
	curpri = cpu->cpu_m.mcpu_pri;
	/*
	 * Only do something if new priority is larger
	 */
	if (newpri > curpri) {
		basepri = cpu->cpu_base_spl;
		if (newpri < basepri)
			newpri = basepri;
		cpu->cpu_m.mcpu_pri = newpri;
		(*setspl)(newpri);
		/*
		 * See if new priority level allows pending softint delivery
		 */
		if (IS_FAKE_SOFTINT(flag, newpri))
			fakesoftint();
	}
	intr_restore(flag);
	return (curpri);
}

int
getpil(void)
{
	return (CPU->cpu_m.mcpu_pri);
}

int
spl_xcall(void)
{
	return (splr(ipltospl(XCALL_PIL)));
}

int
interrupts_enabled(void)
{
	ulong_t	flag;

	flag = getflags();
	return ((flag & PS_IE) == PS_IE);
}

#ifdef DEBUG
void
assert_ints_enabled(void)
{
	ASSERT(!interrupts_unleashed || interrupts_enabled());
}
#endif	/* DEBUG */
