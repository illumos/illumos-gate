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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/cpu_module.h>
#include <vm/hat_sfmmu.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/vm_dep.h>
#include <sys/machsystm.h>
#include <sys/machasi.h>
#include <sys/sysmacros.h>
#include <sys/callb.h>
#include <sys/archsystm.h>
#include <sys/trapstat.h>
#ifdef sun4v
#include <sys/hypervisor_api.h>
#endif
#ifndef sun4v
#include <sys/pghw.h>
#endif

/* BEGIN CSTYLED */
/*
 * trapstat:  Trap Statistics through Dynamic Trap Table Interposition
 * -------------------------------------------------------------------
 *
 * Motivation and Overview
 *
 * Despite being a fundamental indicator of system behavior, there has
 * historically been very little insight provided into the frequency and cost
 * of machine-specific traps.  The lack of insight has been especially acute
 * on UltraSPARC microprocessors:  because these microprocessors handle TLB
 * misses as software traps, the frequency and duration of traps play a
 * decisive role in the performance of the memory system.  As applications have
 * increasingly outstripped TLB reach, this has become increasingly true.
 *
 * Part of the difficulty of observing trap behavior is that the trap handlers
 * are so frequently called (e.g. millions of times per second) that any
 * permanently enabled instrumentation would induce an unacceptable performance
 * degradation.  Thus, it is a constraint on any trap observability
 * infrastructure that it have no probe effect when not explicitly enabled.
 *
 * The basic idea, then, is to create an interposing trap table in which each
 * entry increments a per-trap, in-memory counter and then jumps to the actual,
 * underlying trap table entry.  To enable trapstat, we atomically write to the
 * trap base address (%tba) register to point to our interposing trap table.
 * (Note that per-CPU statistics fall out by creating a different trap table
 * for each CPU.)
 *
 * Implementation Details
 *
 * While the idea is straight-forward, a nuance of SPARC V9 slightly
 * complicates the implementation.  Unlike its predecessors, SPARC V9 supports
 * the notion of nested traps.  The trap level is kept in the TL register:
 * during normal operation it is 0; when a trap is taken, the TL register is
 * incremented by 1.  To aid system software, SPARC V9 breaks the trap table
 * into two halves:  the lower half contains the trap handlers for traps taken
 * when TL is 0; the upper half contains the trap handlers for traps taken
 * when TL is greater than 0.  Each half is further subdivided into two
 * subsequent halves:  the lower half contains the trap handlers for traps
 * other than those induced by the trap instruction (Tcc variants); the upper
 * half contains the trap handlers for traps induced by the trap instruction.
 * This gives a total of four ranges, with each range containing 256 traps:
 *
 *       +--------------------------------+- 3ff
 *       |                                |   .
 *       |     Trap instruction, TL>0     |   .
 *       |                                |   .
 *       |- - - - - - - - - - - - - - - - +- 300
 *       |- - - - - - - - - - - - - - - - +- 2ff
 *       |                                |   .
 *       |   Non-trap instruction, TL>0   |   .
 *       |                                |   .
 *       |- - - - - - - - - - - - - - - - +- 200
 *       |- - - - - - - - - - - - - - - - +- 1ff
 *       |                                |   .
 *       |     Trap instruction, TL=0     |   .
 *       |                                |   .
 *       |- - - - - - - - - - - - - - - - +- 100
 *       |- - - - - - - - - - - - - - - - +- 0ff
 *       |                                |   .
 *       |   Non-trap instruction, TL=0   |   .
 *       |                                |   .
 *       +--------------------------------+- 000
 *
 *
 * Solaris, however, doesn't have reason to support trap instructions when
 * TL>0 (only privileged code may execute at TL>0; not supporting this only
 * constrains our own implementation).  The trap table actually looks like:
 *
 *       +--------------------------------+- 2ff
 *       |                                |   .
 *       |   Non-trap instruction, TL>0   |   .
 *       |                                |   .
 *       |- - - - - - - - - - - - - - - - +- 200
 *       |- - - - - - - - - - - - - - - - +- 1ff
 *       |                                |   .
 *       |     Trap instruction, TL=0     |   .
 *       |                                |   .
 *       |- - - - - - - - - - - - - - - - +- 100
 *       |- - - - - - - - - - - - - - - - +- 0ff
 *       |                                |   .
 *       |   Non-trap instruction, TL=0   |   .
 *       |                                |   .
 *       +--------------------------------+- 000
 *
 * Putatively to aid system software, SPARC V9 has the notion of multiple
 * sets of global registers.  UltraSPARC defines four sets of global
 * registers:
 *
 *    Normal Globals
 *    Alternate Globals (AGs)
 *    MMU Globals (MGs)
 *    Interrupt Globals (IGs)
 *
 * The set of globals in use is controlled by bits in PSTATE; when TL is 0
 * (and PSTATE has not been otherwise explicitly modified), the Normal Globals
 * are in use.  When a trap is issued, PSTATE is modified to point to a set of
 * globals corresponding to the trap type.  Most traps correspond to the
 * Alternate Globals, with a minority corresponding to the MMU Globals, and
 * only the interrupt-vector trap (vector 0x60) corresponding to the Interrupt
 * Globals.  (The complete mapping can be found in the UltraSPARC I&II User's
 * Manual.)
 *
 * Note that the sets of globals are per trap _type_, not per trap _level_.
 * Thus, when executing a TL>0 trap handler, one may not have registers
 * available (for example, both trap-instruction traps and spill traps execute
 * on the alternate globals; if a trap-instruction trap induces a window spill,
 * the window spill handler has no available globals).  For trapstat, this is
 * problematic:  a register is required to transfer control from one arbitrary
 * location (in the interposing trap table) to another (in the actual trap
 * table).
 *
 * We solve this problem by exploiting the trap table's location at the bottom
 * of valid kernel memory (i.e. at KERNELBASE).  We locate the interposing trap
 * tables just below KERNELBASE -- thereby allowing us to use a branch-always
 * instruction (ba) instead of a jump instruction (jmp) to transfer control
 * from the TL>0 entries in the interposing trap table to the TL>0 entries in
 * the actual trap table.  (N.B. while this allows trap table interposition to
 * work, it necessarily limits trapstat to only recording information about
 * TL=0 traps -- there is no way to increment a counter without using a
 * register.)  Diagrammatically:
 *
 *  Actual trap table:
 *
 *       +--------------------------------+- 2ff
 *       |                                |   .
 *       |   Non-trap instruction, TL>0   |   .   <-----------------------+
 *       |                                |   .   <-----------------------|-+
 *       |- - - - - - - - - - - - - - - - +- 200  <-----------------------|-|-+
 *       |- - - - - - - - - - - - - - - - +- 1ff                          | | |
 *       |                                |   .                           | | |
 *       |     Trap instruction, TL=0     |   .   <-----------------+     | | |
 *       |                                |   .   <-----------------|-+   | | |
 *       |- - - - - - - - - - - - - - - - +- 100  <-----------------|-|-+ | | |
 *       |- - - - - - - - - - - - - - - - +- 0ff                    | | | | | |
 *       |                                |   .                     | | | | | |
 *       |   Non-trap instruction, TL=0   |   .   <-----------+     | | | | | |
 *       |                                |   .   <-----------|-+   | | | | | |
 *       +--------------------------------+- 000  <-----------|-|-+ | | | | | |
 *        KERNELBASE                                          | | | | | | | | |
 *                                                            | | | | | | | | |
 *                                                            | | | | | | | | |
 *  Interposing trap table:                                   | | | | | | | | |
 *                                                            | | | | | | | | |
 *       +--------------------------------+- 2ff              | | | | | | | | |
 *       |  ...                           |   .               | | | | | | | | |
 *       |  ...                           |   .               | | | | | | | | |
 *       |  ...                           |   .               | | | | | | | | |
 *       |- - - - - - - - - - - - - - - - +- 203              | | | | | | | | |
 *       |  ba,a                          |      -------------|-|-|-|-|-|-+ | |
 *       |- - - - - - - - - - - - - - - - +- 202              | | | | | |   | |
 *       |  ba,a                          |      -------------|-|-|-|-|-|---+ |
 *       |- - - - - - - - - - - - - - - - +- 201              | | | | | |     |
 *       |  ba,a                          |      -------------|-|-|-|-|-|-----+
 *       |- - - - - - - - - - - - - - - - +- 200              | | | | | |
 *       |  ...                           |   .               | | | | | |
 *       |  ...                           |   .               | | | | | |
 *       |  ...                           |   .               | | | | | |
 *       |- - - - - - - - - - - - - - - - +- 103              | | | | | |
 *       |  (Increment counter)           |                   | | | | | |
 *       |  ba,a                          |      -------------------+ | |
 *       |- - - - - - - - - - - - - - - - +- 102              | | |   | |
 *       |  (Increment counter)           |                   | | |   | |
 *       |  ba,a                          |      ---------------------+ |
 *       |- - - - - - - - - - - - - - - - +- 101              | | |     |
 *       |  (Increment counter)           |                   | | |     |
 *       |  ba,a                          |      -----------------------+
 *       |- - - - - - - - - - - - - - - - +- 100              | | |
 *       |  ...                           |   .               | | |
 *       |  ...                           |   .               | | |
 *       |  ...                           |   .               | | |
 *       |- - - - - - - - - - - - - - - - +- 003              | | |
 *       |  (Increment counter)           |                   | | |
 *       |  ba,a                          |      -------------+ | |
 *       |- - - - - - - - - - - - - - - - +- 002                | |
 *       |  (Increment counter)           |                     | |
 *       |  ba,a                          |      ---------------+ |
 *       |- - - - - - - - - - - - - - - - +- 001                  |
 *       |  (Increment counter)           |                       |
 *       |  ba,a                          |      -----------------+
 *       +--------------------------------+- 000
 *        KERNELBASE - tstat_total_size
 *
 * tstat_total_size is the number of pages required for each trap table.  It
 * must be true that KERNELBASE - tstat_total_size is less than the maximum
 * branch displacement; if each CPU were to consume a disjoint virtual range
 * below KERNELBASE for its trap table, we could support at most
 * (maximum_branch_displacement / tstat_total_size) CPUs.  The maximum branch
 * displacement for Bicc variants is just under eight megabytes, and (because
 * the %tba must be 32K aligned), tstat_total_size must be at least 32K; if
 * each CPU were to consume a disjoint virtual range, we would have an
 * unacceptably low upper bound of 256 CPUs.
 *
 * While there are tricks that one could use to address this constraint (e.g.,
 * creating trampolines every maximum_branch_displacement bytes), we instead
 * solve this by not permitting each CPU to consume a disjoint virtual range.
 * Rather, we have each CPU's interposing trap table use the _same_ virtual
 * range, but we back the trap tables with disjoint physical memory.  Normally,
 * such one-to-many virtual-to-physical mappings are illegal; this is
 * permissible here only because the pages for the interposing trap table are
 * necessarily locked in the TLB.  (The CPUs thus never have the opportunity to
 * discover that they have conflicting translations.)
 *
 * On CMT architectures in which CPUs can share MMUs, the above trick will not
 * work: two CPUs that share an MMU cannot have the same virtual address map
 * to disjoint physical pages.  On these architectures, any CPUs sharing the
 * same MMU must consume a disjoint 32K virtual address range -- limiting the
 * number of CPUs sharing an MMU on these architectures to 256 due to the
 * branch displacement limitation described above.  On the sun4v architecture,
 * there is a further limitation: a guest may not have more than eight locked
 * TLB entries per MMU.  To allow operation under this restriction, the
 * interposing trap table and the trap statistics are each accessed through
 * a single 4M TLB entry.  This limits the footprint to two locked entries
 * (one for the I-TLB and one for the D-TLB), but further restricts the number
 * of CPUs to 128 per MMU.  However, support for more than 128 CPUs can easily
 * be added via a hybrid scheme, where the same 4M virtual address is used
 * on different MMUs.
 *
 * On sun4v architecture, we cannot use the hybrid scheme as the architecture
 * imposes additional restriction on the number of permanent mappings per
 * guest and it is illegal to use the same virtual address to map different
 * TTEs on different MMUs. Instead, we increase the number of supported CPUs
 * by reducing the virtual address space requirements per CPU via shared
 * interposing trap table as follows:
 *
 *                                          Offset (within 4MB page)
 *       +------------------------------------+- 0x400000
 *       |  CPU 1015 trap statistics (4KB)    |   .
 *       |- - - - - - - - - - - - - - - - - - +- 0x3ff000
 *       |                                    |
 *       |   ...                              |
 *       |                                    |
 *       |- - - - - - - - - - - - - - - - - - +- 0x00a000
 *       |  CPU 1 trap statistics (4KB)       |   .
 *       |- - - - - - - - - - - - - - - - - - +- 0x009000
 *       |  CPU 0 trap statistics (4KB)       |   .
 *       |- - - - - - - - - - - - - - - - - - +- 0x008000
 *       |  Shared trap handler continuation  |   .
 *       |- - - - - - - - - - - - - - - - - - +- 0x006000
 *       |  Non-trap instruction, TL>0        |   .
 *       |- - - - - - - - - - - - - - - - - - +- 0x004000
 *       |  Trap instruction, TL=0            |   .
 *       |- - - - - - - - - - - - - - - - - - +- 0x002000
 *       |  Non-trap instruction, TL=0        |   .
 *       +------------------------------------+- 0x000000
 *
 * Note that each CPU has its own 4K space for its trap statistics but
 * shares the same interposing trap handlers.  Interposing trap handlers
 * use the CPU ID to determine the location of per CPU trap statistics
 * area dynamically. This increases the interposing trap handler overhead,
 * but is acceptable as it allows us to support up to 1016 CPUs with one
 * 4MB page on sun4v architecture. Support for additional CPUs can be
 * added with another 4MB page to 2040 cpus (or 3064 cpus with 2 additional
 * 4MB pages). With additional 4MB pages, we cannot use displacement branch
 * (ba instruction) and we have to use jmp instruction instead. Note that
 * with sun4v, globals are nested (not per-trap type as in sun4u), so it is
 * ok to use additional global reg to do jmp. This option is not available in
 * sun4u which mandates the usage of displacement branches since no global reg
 * is available at TL>1
 *
 * TLB Statistics
 *
 * Because TLB misses are an important component of system performance, we wish
 * to know much more about these traps than simply the number received.
 * Specifically, we wish to know:
 *
 *  (a)	The amount of time spent executing the TLB miss handler
 *  (b)	TLB misses versus TSB misses
 *  (c) Kernel-level misses versus user-level misses
 *  (d) Misses per pagesize
 *
 * TLB Statistics: Time Spent Executing
 *
 * To accurately determine the amount of time spent executing the TLB miss
 * handler, one must get a timestamp on trap entry and trap exit, subtract the
 * latter from the former, and add the result to an accumulating count.
 * Consider flow of control during normal TLB miss processing (where "ldx
 * [%g2], %g2" is an arbitrary TLB-missing instruction):
 *
 * + - - - - - - - -+
 * :                :
 * : ldx [%g2], %g2 :<-------------------------------------------------------+
 * :                :              Return from trap:                         |
 * + - - - - - - - -+                TL <- TL - 1 (0)                        |
 *	  |                          %pc <- TSTATE[TL].TPC (address of load) |
 *	  | TLB miss:                                                        |
 *        |   TL <- TL + 1 (1)                                               |
 *        |   %pc <- TLB-miss-trap-handler                                   |
 *        |                                                                  |
 *        v                                                                  |
 * + - - - - - - - - - - - - - - - +                                         |
 * :                               :                                         |
 * : Lookup VA in TSB              :                                         |
 * : If (hit)                      :                                         |
 * :     Fill TLB                  :                                         |
 * : Else                          :                                         |
 * :     Lookup VA (hme hash table :                                         |
 * :                or segkpm)     :                                         |
 * :     Fill TLB                  :                                         |
 * : Endif                         :                                         |
 * : Issue "retry"  ---------------------------------------------------------+
 * :                               :
 * + - - - - - - - - - - - - - - - +
 *  TLB-miss-trap-handler
 *
 *
 * As the above diagram indicates, interposing on the trap table allows one
 * only to determine a timestamp on trap _entry_:  when the TLB miss handler
 * has completed filling the TLB, a "retry" will be issued, and control will
 * transfer immediately back to the missing %pc.
 *
 * To obtain a timestamp on trap exit, we must then somehow interpose between
 * the "retry" and the subsequent control transfer to the TLB-missing
 * instruction.  To do this, we _push_ a trap level.  The basic idea is to
 * spoof a TLB miss by raising TL, setting the %tpc to be within text
 * controlled by trapstat (the "TLB return entry") and branching to the
 * underlying TLB miss handler.  When the TLB miss handler issues its "retry",
 * control will transfer not to the TLB-missing instruction, but rather to the
 * TLB return entry.  This code can then obtain a timestamp, and issue its own
 * "retry" -- thereby correctly returning to the TLB-missing instruction.
 * Here is the above TLB miss flow control diagram modified to reflect
 * trapstat's operation:
 *
 * + - - - - - - - -+
 * :                :
 * : ldx [%g2], %g2 :<-------------------------------------------------------+
 * :                :             Return from trap:                          |
 * + - - - - - - - -+               TL <- TL - 1 (0)                         |
 *	  |                         %pc <- TSTATE[TL].TPC (address of load)  |
 *	  | TLB miss:                                                        |
 *        |   TL <- TL + 1 (1)                                               |
 *        |   %pc <- TLB-miss-trap-handler (trapstat)                        |
 *        |                                                                  |
 *        v                                    TLB-return-entry (trapstat)   |
 * + - - - - - - - - - - - - - - - - - - +    + - - - - - - - - - - - - - +  |
 * :                                     :    :                           :  |
 * : Record timestamp                    :    : Record timestamp          :  |
 * : TL <- 2                             :    : Take timestamp difference :  |
 * : TSTATE[1].TPC <- TLB-return-entry   :    : Add to running total      :  |
 * : ba,a TLB-miss-trap-handler -----------+  : Issue "retry"  --------------+
 * :                                     : |  :                           :
 * + - - - - - - - - - - - - - - - - - - + |  + - - - - - - - - - - - - - +
 *  TLB-miss-trap-handler	           |                  ^
 *  (trapstat)                             |                  |
 *                                         |                  |
 *                                         |                  |
 *                 +-----------------------+                  |
 *                 |                                          |
 *                 |                                          |
 *                 v                                          |
 * + - - - - - - - - - - - - - - - +                          |
 * :                               :                          |
 * : Lookup VA in TSB              :                          |
 * : If (hit)                      :                          |
 * :     Fill TLB                  :                          |
 * : Else                          :                          |
 * :     Lookup VA (hme hash table :                          |
 * :                or segkpm)     :                          |
 * :     Fill TLB                  :                          |
 * : Endif                         :                          |
 * : Issue "retry"  ------------------------------------------+
 * :                               : Return from trap:
 * + - - - - - - - - - - - - - - - +   TL <- TL - 1 (1)
 *  TLB-miss-trap-handler              %pc <- TSTATE[TL].TPC (TLB-return-entry)
 *
 *
 * A final subterfuge is required to complete our artifice:  if we miss in
 * the TLB, the TSB _and_ the subsequent hash or segkpm lookup (that is, if
 * there is no valid translation for the TLB-missing address), common system
 * software will need to accurately determine the %tpc as part of its page
 * fault handling. We therefore modify the kernel to check the %tpc in this
 * case: if the %tpc falls within the VA range controlled by trapstat and
 * the TL is 2, TL is simply lowered back to 1 (this check is implemented
 * by the TSTAT_CHECK_TL1 macro).  Lowering TL to 1 has the effect of
 * discarding the state pushed by trapstat.
 *
 * TLB Statistics: TLB Misses versus TSB Misses
 *
 * Distinguishing TLB misses from TSB misses requires further interposition
 * on the TLB miss handler:  we cannot know a priori or a posteriori if a
 * given VA will or has hit in the TSB.
 *
 * We achieve this distinction by adding a second TLB return entry almost
 * identical to the first -- differing only in the address to which it
 * stores its results.  We then modify the TLB miss handlers of the kernel
 * such that they check the %tpc when they determine that a TLB miss has
 * subsequently missed in the TSB:  if the %tpc lies within trapstat's VA
 * range and TL is 2 (that is, if trapstat is running), the TLB miss handler
 * _increments_ the %tpc by the size of the TLB return entry.  The ensuing
 * "retry" will thus transfer control to the second TLB return entry, and
 * the time spent in the handler will be accumulated in a memory location
 * specific to TSB misses.
 *
 * N.B.:  To minimize the amount of knowledge the kernel must have of trapstat,
 * we do not allow the kernel to hard-code the size of the TLB return entry.
 * Rather, the actual tsbmiss handler executes a known instruction at the
 * corresponding tsbmiss patch points (see the tstat_tsbmiss_patch_table) with
 * the %tpc in %g7:  when trapstat is not running, these points contain the
 * harmless TSTAT_TSBMISS_INSTR instruction ("add %g7, 0, %g7"). Before
 * running, trapstat modifies the instructions at these patch points such
 * that the simm13 equals the size of the TLB return entry.
 *
 * TLB Statistics: Kernel-level Misses versus User-level Misses
 *
 * Differentiating user-level misses from kernel-level misses employs a
 * similar technique, but is simplified by the ability to distinguish a
 * user-level miss from a kernel-level miss a priori by reading the context
 * register:  we implement kernel-/user-level differentiation by again doubling
 * the number of TLB return entries, and setting the %tpc to the appropriate
 * TLB return entry in trapstat's TLB miss handler.  Together with the doubling
 * of entries required for TLB-miss/TSB-miss differentiation, this yields a
 * total of four TLB return entries:
 *
 *	Level		TSB hit?	Structure member
 *	------------------------------------------------------------
 *	Kernel		Yes		tstat_tlbret_t.ttlbr_ktlb
 *	Kernel		No		tstat_tlbret_t.ttlbr_ktsb
 *	User		Yes		tstat_tlbret_t.ttlbr_utlb
 *	User		No		tstat_tlbret_t.ttlbr_utsb
 *
 * TLB Statistics: Misses per Pagesize
 *
 * As with the TLB-/TSB-miss differentiation, we have no way of determining
 * pagesize a priori.  This is therefore implemented by mandating a new rule:
 * whenever the kernel fills the TLB in its TLB miss handler, the TTE
 * corresponding to the TLB-missing VA must be in %g5 when the handler
 * executes its "retry".  This allows the TLB return entry to determine
 * pagesize by simply looking at the pagesize field in the TTE stored in
 * %g5.
 *
 * TLB Statistics: Probe Effect
 *
 * As one might imagine, gathering TLB statistics by pushing a trap level
 * induces significant probe effect.  To account for this probe effect,
 * trapstat attempts to observe it by executing a code sequence with a known
 * number of TLB misses both before and after interposing on the trap table.
 * This allows trapstat to determine a per-trap probe effect which can then be
 * factored into the "%tim" fields of the trapstat command.
 *
 * Note that on sun4v platforms, TLB misses are normally handled by the
 * hypervisor or the hardware TSB walker. Thus no fast MMU miss information
 * is reported for normal operation. However, when trapstat is invoked
 * with -t or -T option to collect detailed TLB statistics, kernel takes
 * over TLB miss handling. This results in significantly more overhead
 * and TLB statistics may not be as accurate as on sun4u platforms.
 * On some processors, hypervisor or hardware may provide a low overhead
 * interface to collect TSB hit statistics. This support is exposed via
 * a well defined CPU module interface (cpu_trapstat_conf to enable this
 * interface and cpu_trapstat_data to get detailed TSB hit statistics).
 * In this scenario, TSB miss statistics is collected by intercepting the
 * IMMU_miss and DMMU_miss traps using above mentioned trap interposition
 * approach.
 *
 * Locking
 *
 * The implementation uses two locks:  tstat_lock (a local lock) and the global
 * cpu_lock.  tstat_lock is used to assure trapstat's consistency in the
 * presence of multithreaded /dev/trapstat consumers (while as of this writing
 * the only consumer of /dev/trapstat is single threaded, it is obviously
 * necessary to correctly support multithreaded access).  cpu_lock is held
 * whenever CPUs are being manipulated directly, to prevent them from
 * disappearing in the process.  Because trapstat's DR callback
 * (trapstat_cpu_setup()) must grab tstat_lock and is called with cpu_lock
 * held, the lock ordering is necessarily cpu_lock before tstat_lock.
 *
 */
/* END CSTYLED */

static dev_info_t	*tstat_devi;	/* saved in xxattach() for xxinfo() */
static int		tstat_open;	/* set if driver is open */
static kmutex_t		tstat_lock;	/* serialize access */
static vmem_t		*tstat_arena;	/* arena for TLB-locked pages */
static tstat_percpu_t	*tstat_percpu;	/* per-CPU data */
static int		tstat_running;	/* set if trapstat is running */
static tstat_data_t	*tstat_buffer;	/* staging buffer for outgoing data */
static int		tstat_options;	/* bit-wise indication of options */
static int		*tstat_enabled;	/* map of enabled trap entries */
static int		tstat_tsbmiss_patched; /* tsbmiss patch flag */
static callb_id_t	tstat_cprcb;	/* CPR callback */
static char		*tstat_probe_area; /* VA range used for probe effect */
static caddr_t		tstat_probe_phys; /* physical to back above VA */
static hrtime_t		tstat_probe_time; /* time spent on probe effect */
static hrtime_t		tstat_probe_before[TSTAT_PROBE_NLAPS];
static hrtime_t		tstat_probe_after[TSTAT_PROBE_NLAPS];
static uint_t		tstat_pgszs;		/* # of kernel page sizes */
static uint_t		tstat_user_pgszs;	/* # of user page sizes */

/*
 * sizeof tstat_data_t + pgsz data for the kernel.  For simplicity's sake, when
 * we collect data, we do it based upon szc, but when we report data back to
 * userland, we have to do it based upon the userszc which may not match.
 * So, these two variables are for internal use and exported use respectively.
 */
static size_t		tstat_data_t_size;
static size_t		tstat_data_t_exported_size;

#ifndef sun4v

static size_t		tstat_data_pages;  /* number of pages of tstat data */
static size_t		tstat_data_size;   /* tstat data size in bytes */
static size_t		tstat_total_pages; /* #data pages + #instr pages */
static size_t		tstat_total_size;  /* tstat data size + instr size */

#else /* sun4v */

static caddr_t		tstat_va[TSTAT_NUM4M_LIMIT]; /* VAs of 4MB pages */
static pfn_t		tstat_pfn[TSTAT_NUM4M_LIMIT]; /* PFNs of 4MB pages */
static boolean_t	tstat_fast_tlbstat = B_FALSE;
static int		tstat_traptab_initialized;
static int		tstat_perm_mapping_failed;
static int		tstat_hv_nopanic;
static int		tstat_num4m_mapping;

#endif /* sun4v */

/*
 * In the above block comment, see "TLB Statistics: TLB Misses versus
 * TSB Misses" for an explanation of the tsbmiss patch points.
 */
extern uint32_t		tsbmiss_trapstat_patch_point;
extern uint32_t		tsbmiss_trapstat_patch_point_kpm;
extern uint32_t		tsbmiss_trapstat_patch_point_kpm_small;

/*
 * Trapstat tsbmiss patch table
 */
tstat_tsbmiss_patch_entry_t tstat_tsbmiss_patch_table[] = {
	{(uint32_t *)&tsbmiss_trapstat_patch_point, 0},
	{(uint32_t *)&tsbmiss_trapstat_patch_point_kpm, 0},
	{(uint32_t *)&tsbmiss_trapstat_patch_point_kpm_small, 0},
	{(uint32_t *)NULL, 0}
};

/*
 * We define some general SPARC-specific constants to allow more readable
 * relocations.
 */
#define	NOP	0x01000000
#define	HI22(v) ((uint32_t)(v) >> 10)
#define	LO10(v) ((uint32_t)(v) & 0x3ff)
#define	LO12(v) ((uint32_t)(v) & 0xfff)
#define	DISP22(from, to) \
	((((uintptr_t)(to) - (uintptr_t)(from)) >> 2) & 0x3fffff)
#define	ASI(asi)	((asi) << 5)

/*
 * The interposing trap table must be locked in the I-TLB, and any data
 * referred to in the interposing trap handler must be locked in the D-TLB.
 * This function locks these pages in the appropriate TLBs by creating TTEs
 * from whole cloth, and manually loading them into the TLB.  This function is
 * called from cross call context.
 *
 * On sun4v platforms, we use 4M page size mappings to minimize the number
 * of locked down entries (i.e. permanent mappings). Each CPU uses a
 * reserved portion of that 4M page for its TBA and data.
 */
static void
trapstat_load_tlb(void)
{
	int i;
#ifdef sun4v
	uint64_t ret;
#endif
	tte_t tte;
	tstat_percpu_t *tcpu = &tstat_percpu[CPU->cpu_id];
	caddr_t va = tcpu->tcpu_vabase;

	ASSERT(tcpu->tcpu_flags & TSTAT_CPU_ALLOCATED);
	ASSERT(!(tcpu->tcpu_flags & TSTAT_CPU_ENABLED));

#ifndef sun4v
	for (i = 0; i < tstat_total_pages; i++, va += MMU_PAGESIZE) {
		tte.tte_inthi = TTE_VALID_INT | TTE_SZ_INT(TTE8K) |
		    TTE_PFN_INTHI(tcpu->tcpu_pfn[i]);
		if (i < TSTAT_INSTR_PAGES) {
			tte.tte_intlo = TTE_PFN_INTLO(tcpu->tcpu_pfn[i]) |
			    TTE_LCK_INT | TTE_CP_INT | TTE_PRIV_INT;
			sfmmu_itlb_ld_kva(va, &tte);
		} else {
			tte.tte_intlo = TTE_PFN_INTLO(tcpu->tcpu_pfn[i]) |
			    TTE_LCK_INT | TTE_CP_INT | TTE_CV_INT |
			    TTE_PRIV_INT | TTE_HWWR_INT;
			sfmmu_dtlb_ld_kva(va, &tte);
		}
	}
#else /* sun4v */
	for (i = 0; i < tstat_num4m_mapping; i++) {
		tte.tte_inthi = TTE_VALID_INT | TTE_PFN_INTHI(tstat_pfn[i]);
		tte.tte_intlo = TTE_PFN_INTLO(tstat_pfn[i]) | TTE_CP_INT |
		    TTE_CV_INT | TTE_PRIV_INT | TTE_HWWR_INT |
		    TTE_SZ_INTLO(TTE4M);
		ret = hv_mmu_map_perm_addr(va, KCONTEXT, *(uint64_t *)&tte,
		    MAP_ITLB | MAP_DTLB);

		if (ret != H_EOK) {
			if (tstat_hv_nopanic) {
				int j;
				/*
				 * The first attempt to create perm mapping
				 * failed. The guest might have exhausted its
				 * perm mapping limit. We don't panic on first
				 * try.
				 */
				tstat_perm_mapping_failed = 1;
				va = tcpu->tcpu_vabase;
				for (j = 0; j < i; j++) {
					(void) hv_mmu_unmap_perm_addr(va,
					    KCONTEXT, MAP_ITLB | MAP_DTLB);
					va += MMU_PAGESIZE4M;
				}
				break;
			}
			/*
			 * We failed on subsequent cpus trying to
			 * create the same perm mappings. This
			 * should not happen. Panic here.
			 */
			cmn_err(CE_PANIC, "trapstat: cannot create "
			    "perm mappings for cpu %d "
			    "(error: 0x%lx)", CPU->cpu_id, ret);
		}
		va += MMU_PAGESIZE4M;
	}
#endif /* sun4v */
}

/*
 * As mentioned in the "TLB Statistics: TLB Misses versus TSB Misses" section
 * of the block comment, TLB misses are differentiated from TSB misses in
 * part by hot-patching the instructions at the tsbmiss patch points (see
 * tstat_tsbmiss_patch_table). This routine is used both to initially patch
 * the instructions, and to patch them back to their original values upon
 * restoring the original trap table.
 */
static void
trapstat_hotpatch()
{
	uint32_t instr;
	uint32_t simm13;
	tstat_tsbmiss_patch_entry_t *ep;

	ASSERT(MUTEX_HELD(&tstat_lock));

	if (!(tstat_options & TSTAT_OPT_TLBDATA))
		return;

	if (!tstat_tsbmiss_patched) {
		/*
		 * We haven't patched the TSB paths; do so now.
		 */
		/*CONSTCOND*/
		ASSERT(offsetof(tstat_tlbret_t, ttlbr_ktsb) -
		    offsetof(tstat_tlbret_t, ttlbr_ktlb) ==
		    offsetof(tstat_tlbret_t, ttlbr_utsb) -
		    offsetof(tstat_tlbret_t, ttlbr_utlb));

		simm13 = offsetof(tstat_tlbret_t, ttlbr_ktsb) -
		    offsetof(tstat_tlbret_t, ttlbr_ktlb);

		for (ep = tstat_tsbmiss_patch_table; ep->tpe_addr; ep++) {
			ASSERT(ep->tpe_instr == 0);
			instr = ep->tpe_instr = *ep->tpe_addr;

			/*
			 * Assert that the instruction we're about to patch is
			 * "add %g7, 0, %g7" (0x8e01e000).
			 */
			ASSERT(instr == TSTAT_TSBMISS_INSTR);

			instr |= simm13;
			hot_patch_kernel_text((caddr_t)ep->tpe_addr,
			    instr, sizeof (instr));
		}

		tstat_tsbmiss_patched = 1;

	} else {
		/*
		 * Remove patches from the TSB paths.
		 */
		for (ep = tstat_tsbmiss_patch_table; ep->tpe_addr; ep++) {
			ASSERT(ep->tpe_instr == TSTAT_TSBMISS_INSTR);
			hot_patch_kernel_text((caddr_t)ep->tpe_addr,
			    ep->tpe_instr, sizeof (instr));
			ep->tpe_instr = 0;
		}

		tstat_tsbmiss_patched = 0;
	}
}

/*
 * This is the routine executed to clock the performance of the trap table,
 * executed both before and after interposing on the trap table to attempt to
 * determine probe effect.  The probe effect is used to adjust the "%tim"
 * fields of trapstat's -t and -T output; we only use TLB misses to clock the
 * trap table.  We execute the inner loop (which is designed to exceed the
 * TLB's reach) nlaps times, taking the best time as our time (thereby
 * factoring out the effects of interrupts, cache misses or other perturbing
 * events.
 */
static hrtime_t
trapstat_probe_laps(int nlaps, hrtime_t *buf)
{
	int i, j = 0;
	hrtime_t ts, best = INT64_MAX;

	while (nlaps--) {
		ts = rdtick();

		for (i = 0; i < TSTAT_PROBE_SIZE; i += MMU_PAGESIZE)
			*((volatile char *)&tstat_probe_area[i]);

		if ((ts = rdtick() - ts) < best)
			best = ts;
		buf[j++] = ts;
	}

	return (best);
}

/*
 * This routine determines the probe effect by calling trapstat_probe_laps()
 * both without and with the interposing trap table.  Note that this is
 * called from a cross call on the desired CPU, and that it is called on
 * every CPU (this is necessary because the probe effect may differ from
 * one CPU to another).
 */
static void
trapstat_probe()
{
	tstat_percpu_t *tcpu = &tstat_percpu[CPU->cpu_id];
	hrtime_t before, after;

	if (!(tcpu->tcpu_flags & TSTAT_CPU_SELECTED))
		return;

	if (tstat_probe_area == NULL || (tstat_options & TSTAT_OPT_NOGO))
		return;

	/*
	 * We very much expect the %tba to be KERNELBASE; this is a
	 * precautionary measure to assure that trapstat doesn't melt the
	 * machine should the %tba point unexpectedly elsewhere.
	 */
	if (get_tba() != (caddr_t)KERNELBASE)
		return;

	/*
	 * Preserve this CPU's data before destroying it by enabling the
	 * interposing trap table.  We can safely use tstat_buffer because
	 * the caller of the trapstat_probe() cross call is holding tstat_lock.
	 */
#ifdef sun4v
	bcopy(tcpu->tcpu_data, tstat_buffer, TSTAT_DATA_SIZE);
#else
	bcopy(tcpu->tcpu_data, tstat_buffer, tstat_data_t_size);
#endif

	tstat_probe_time = gethrtime();

	before = trapstat_probe_laps(TSTAT_PROBE_NLAPS, tstat_probe_before);
	(void) set_tba(tcpu->tcpu_ibase);

	after = trapstat_probe_laps(TSTAT_PROBE_NLAPS, tstat_probe_after);
	(void) set_tba((caddr_t)KERNELBASE);

	tstat_probe_time = gethrtime() - tstat_probe_time;

#ifdef sun4v
	bcopy(tstat_buffer, tcpu->tcpu_data, TSTAT_DATA_SIZE);
	tcpu->tcpu_tdata_peffect = (after - before) / TSTAT_PROBE_NPAGES;
#else
	bcopy(tstat_buffer, tcpu->tcpu_data, tstat_data_t_size);
	tcpu->tcpu_data->tdata_peffect = (after - before) / TSTAT_PROBE_NPAGES;
#endif
}

static void
trapstat_probe_alloc()
{
	pfn_t pfn;
	caddr_t va;
	int i;

	ASSERT(MUTEX_HELD(&tstat_lock));
	ASSERT(tstat_probe_area == NULL);
	ASSERT(tstat_probe_phys == NULL);

	if (!(tstat_options & TSTAT_OPT_TLBDATA))
		return;

	/*
	 * Grab some virtual from the heap arena.
	 */
	tstat_probe_area = vmem_alloc(heap_arena, TSTAT_PROBE_SIZE, VM_SLEEP);
	va = tstat_probe_area;

	/*
	 * Grab a single physical page.
	 */
	tstat_probe_phys = vmem_alloc(tstat_arena, MMU_PAGESIZE, VM_SLEEP);
	pfn = hat_getpfnum(kas.a_hat, tstat_probe_phys);

	/*
	 * Now set the translation for every page in our virtual range
	 * to be our allocated physical page.
	 */
	for (i = 0; i < TSTAT_PROBE_NPAGES; i++) {
		hat_devload(kas.a_hat, va, MMU_PAGESIZE, pfn, PROT_READ,
		    HAT_LOAD_NOCONSIST | HAT_LOAD_LOCK);
		va += MMU_PAGESIZE;
	}
}

static void
trapstat_probe_free()
{
	caddr_t va;
	int i;

	ASSERT(MUTEX_HELD(&tstat_lock));

	if ((va = tstat_probe_area) == NULL)
		return;

	for (i = 0; i < TSTAT_PROBE_NPAGES; i++) {
		hat_unload(kas.a_hat, va, MMU_PAGESIZE, HAT_UNLOAD_UNLOCK);
		va += MMU_PAGESIZE;
	}

	vmem_free(tstat_arena, tstat_probe_phys, MMU_PAGESIZE);
	vmem_free(heap_arena, tstat_probe_area, TSTAT_PROBE_SIZE);

	tstat_probe_phys = NULL;
	tstat_probe_area = NULL;
}

/*
 * This routine actually enables a CPU by setting its %tba to be the
 * CPU's interposing trap table.  It is called out of cross call context.
 */
static void
trapstat_enable()
{
	tstat_percpu_t *tcpu = &tstat_percpu[CPU->cpu_id];

	if (!(tcpu->tcpu_flags & TSTAT_CPU_SELECTED))
		return;

	ASSERT(tcpu->tcpu_flags & TSTAT_CPU_ALLOCATED);
	ASSERT(!(tcpu->tcpu_flags & TSTAT_CPU_ENABLED));

	if (get_tba() != (caddr_t)KERNELBASE)
		return;

	if (!(tstat_options & TSTAT_OPT_NOGO))
		(void) set_tba(tcpu->tcpu_ibase);
	tcpu->tcpu_flags |= TSTAT_CPU_ENABLED;
#ifdef sun4v
	if ((tstat_options & TSTAT_OPT_TLBDATA) &&
	    !(tstat_options & TSTAT_OPT_NOGO)) {
		if (tstat_fast_tlbstat) {
			/*
			 * Invoke processor specific interface to enable
			 * collection of TSB hit statistics.
			 */
			(void) cpu_trapstat_conf(CPU_TSTATCONF_ENABLE);
		} else {
			/*
			 * Collect TLB miss statistics by taking over
			 * TLB miss handling from the hypervisor. This
			 * is done by telling the hypervisor that there
			 * is no TSB configured. Also set TSTAT_TLB_STATS
			 * flag so that no user TSB is configured during
			 * context switch time.
			 */
			cpu_t *cp = CPU;

			cp->cpu_m.cpu_tstat_flags |= TSTAT_TLB_STATS;
			(void) hv_set_ctx0(0, 0);
			(void) hv_set_ctxnon0(0, 0);
		}
	}
#endif
}

/*
 * This routine disables a CPU (vis a vis trapstat) by setting its %tba to be
 * the actual, underlying trap table.  It is called out of cross call context.
 */
static void
trapstat_disable()
{
	tstat_percpu_t *tcpu = &tstat_percpu[CPU->cpu_id];

	if (!(tcpu->tcpu_flags & TSTAT_CPU_ENABLED))
		return;

	ASSERT(tcpu->tcpu_flags & TSTAT_CPU_SELECTED);
	ASSERT(tcpu->tcpu_flags & TSTAT_CPU_ALLOCATED);

	if (!(tstat_options & TSTAT_OPT_NOGO))
		(void) set_tba((caddr_t)KERNELBASE);

	tcpu->tcpu_flags &= ~TSTAT_CPU_ENABLED;

#ifdef sun4v
	if ((tstat_options & TSTAT_OPT_TLBDATA) &&
	    !(tstat_options & TSTAT_OPT_NOGO)) {
		if (tstat_fast_tlbstat) {
			/*
			 * Invoke processor specific interface to disable
			 * collection of TSB hit statistics on each processor.
			 */
			(void) cpu_trapstat_conf(CPU_TSTATCONF_DISABLE);
		} else {
			/*
			 * As part of collecting TLB miss statistics, we took
			 * over TLB miss handling from the hypervisor by
			 * telling the hypervisor that NO TSB is configured.
			 * We need to restore that by communicating proper
			 * kernel/user TSB information so that TLB misses
			 * can be handled by the hypervisor or the hardware
			 * more efficiently.
			 *
			 * We restore kernel TSB information right away.
			 * However, to minimize any locking dependency, we
			 * don't restore user TSB information right away.
			 * Instead, we simply clear the TSTAT_TLB_STATS flag
			 * so that the user TSB information is automatically
			 * restored on next context switch.
			 *
			 * Note that the call to restore kernel TSB information
			 * will normally not fail, unless wrong information is
			 * passed here. In that scenario, system will still
			 * continue to function properly with the exception of
			 * kernel handling all the TLB misses.
			 */
			struct hv_tsb_block *hvbp = &ksfmmup->sfmmu_hvblock;
			cpu_t *cp = CPU;

			cp->cpu_m.cpu_tstat_flags &= ~TSTAT_TLB_STATS;
			(void) hv_set_ctx0(hvbp->hv_tsb_info_cnt,
			    hvbp->hv_tsb_info_pa);
		}
	}
#endif
}

/*
 * We use %tick as the time base when recording the time spent executing
 * the trap handler.  %tick, however, is not necessarily kept in sync
 * across CPUs (indeed, different CPUs may have different %tick frequencies).
 * We therefore cross call onto a CPU to get a snapshot of its data to
 * copy out; this is the routine executed out of that cross call.
 */
static void
trapstat_snapshot()
{
	tstat_percpu_t *tcpu = &tstat_percpu[CPU->cpu_id];
	tstat_data_t *data = tcpu->tcpu_data;

	ASSERT(tcpu->tcpu_flags & TSTAT_CPU_SELECTED);
	ASSERT(tcpu->tcpu_flags & TSTAT_CPU_ALLOCATED);
	ASSERT(tcpu->tcpu_flags & TSTAT_CPU_ENABLED);

#ifndef sun4v
	data->tdata_snapts = gethrtime();
	data->tdata_snaptick = rdtick();
	bcopy(data, tstat_buffer, tstat_data_t_size);
#else
	/*
	 * For sun4v, in order to conserve space in the limited
	 * per-cpu 4K buffer, we derive certain info somewhere else and
	 * copy them directly into the tstat_buffer output.
	 * Note that we either are collecting tlb stats or
	 * regular trapstats but never both.
	 */
	tstat_buffer->tdata_cpuid = CPU->cpu_id;
	tstat_buffer->tdata_peffect = tcpu->tcpu_tdata_peffect;
	tstat_buffer->tdata_snapts = gethrtime();
	tstat_buffer->tdata_snaptick = rdtick();

	if (tstat_options & TSTAT_OPT_TLBDATA) {
		/* Copy tlb/tsb stats collected in the per-cpu trapdata */
		tstat_tdata_t *tdata = (tstat_tdata_t *)data;
		bcopy(&tdata->tdata_pgsz[0],
		    &tstat_buffer->tdata_pgsz[0],
		    tstat_pgszs * sizeof (tstat_pgszdata_t));

		/*
		 * Invoke processor specific interface to collect TLB stats
		 * on each processor if enabled.
		 */
		if (tstat_fast_tlbstat) {
			cpu_trapstat_data((void *) tstat_buffer->tdata_pgsz,
			    tstat_pgszs);
		}
	} else {
		/*
		 * Normal trapstat collection.
		 * Copy all the 4K data area into tstat_buffer tdata_trap
		 * area.
		 */
		bcopy(data, &tstat_buffer->tdata_traps[0], TSTAT_DATA_SIZE);
	}
#endif /* sun4v */
}

/*
 * The TSTAT_RETENT_* constants define offsets in the TLB return entry.
 * They are used only in trapstat_tlbretent() (below) and #undef'd
 * immediately afterwards.  Any change to "retent" in trapstat_tlbretent()
 * will likely require changes to these constants.
 */

#ifndef sun4v
#define	TSTAT_RETENT_STATHI	1
#define	TSTAT_RETENT_STATLO	2
#define	TSTAT_RETENT_SHIFT	11
#define	TSTAT_RETENT_COUNT_LD	13
#define	TSTAT_RETENT_COUNT_ST	15
#define	TSTAT_RETENT_TMPTSHI	16
#define	TSTAT_RETENT_TMPTSLO	17
#define	TSTAT_RETENT_TIME_LD	19
#define	TSTAT_RETENT_TIME_ST	21
#else /* sun4v */
#define	TSTAT_RETENT_TDATASHFT	2
#define	TSTAT_RETENT_STATHI	4
#define	TSTAT_RETENT_STATLO	6
#define	TSTAT_RETENT_SHIFT	9
#define	TSTAT_RETENT_COUNT_LD	11
#define	TSTAT_RETENT_COUNT_ST	13
#define	TSTAT_RETENT_TMPTSHI	14
#define	TSTAT_RETENT_TMPTSLO	16
#define	TSTAT_RETENT_TIME_LD	18
#define	TSTAT_RETENT_TIME_ST	20
#endif /* sun4v */

static void
trapstat_tlbretent(tstat_percpu_t *tcpu, tstat_tlbretent_t *ret,
    tstat_missdata_t *data)
{
	uint32_t *ent = ret->ttlbrent_instr, shift;
	uintptr_t base;
#ifndef sun4v
	uintptr_t tmptick = TSTAT_DATA_OFFS(tcpu, tdata_tmptick);
#else
	uintptr_t tmptick = TSTAT_CPU0_TLBDATA_OFFS(tcpu, tdata_tmptick);
#endif

	/*
	 * This is the entry executed upon return from the TLB/TSB miss
	 * handler (i.e. the code interpositioned between the "retry" and
	 * the actual return to the TLB-missing instruction).  Detail on its
	 * theory of operation can be found in the "TLB Statistics" section
	 * of the block comment.  Note that we expect the TTE just loaded
	 * into the TLB to be in %g5; all other globals are available as
	 * scratch.  Finally, note that the page size information in sun4v is
	 * located in the lower bits of the TTE -- requiring us to have a
	 * different return entry on sun4v.
	 */
	static const uint32_t retent[TSTAT_TLBRET_NINSTR] = {
#ifndef sun4v
	    0x87410000,		/* rd    %tick, %g3			*/
	    0x03000000,		/* sethi %hi(stat), %g1			*/
	    0x82106000,		/* or    %g1, %lo(stat), %g1		*/
	    0x89297001,		/* sllx  %g5, 1, %g4			*/
	    0x8931303e,		/* srlx  %g4, 62, %g4			*/
	    0x8531702e,		/* srlx  %g5, 46, %g2			*/
	    0x8408a004,		/* and   %g2, 4, %g2			*/
	    0x88110002,		/* or    %g4, %g2, %g4			*/
	    0x80a12005,		/* cmp   %g4, 5				*/
	    0x34400002,		/* bg,a,pn %icc, +8			*/
	    0x88102004,		/* mov   4, %g4				*/
	    0x89292000,		/* sll   %g4, shift, %g4		*/
	    0x82004004,		/* add   %g1, %g4, %g1			*/
	    0xc4586000,		/* ldx   [%g1 + tmiss_count], %g2	*/
	    0x8400a001,		/* add   %g2, 1, %g2			*/
	    0xc4706000,		/* stx   %g2, [%g1 + tmiss_count]	*/
	    0x0d000000,		/* sethi %hi(tdata_tmptick), %g6	*/
	    0xc459a000,		/* ldx   [%g6 + %lo(tdata_tmptick)], %g2 */
	    0x8620c002,		/* sub   %g3, %g2, %g3			*/
	    0xc4586000,		/* ldx   [%g1 + tmiss_time], %g2	*/
	    0x84008003,		/* add   %g2, %g3, %g2			*/
	    0xc4706000,		/* stx   %g2, [%g1 + tmiss_time]	*/
	    0x83f00000		/* retry				*/
#else /* sun4v */
	    0x82102008,		/* mov   SCRATCHPAD_CPUID, %g1		*/
	    0xced84400,		/* ldxa  [%g1]ASI_SCRATCHPAD, %g7	*/
	    0x8f29f000,		/* sllx  %g7, TSTAT_DATA_SHIFT, %g7	*/
	    0x87410000,		/* rd    %tick, %g3			*/
	    0x03000000,		/* sethi %hi(stat), %g1			*/
	    0x82004007,		/* add   %g1, %g7, %g1			*/
	    0x82106000,		/* or    %g1, %lo(stat), %g1		*/
	    0x8929703d,		/* sllx  %g5, 61, %g4			*/
	    0x8931303d,		/* srlx  %g4, 61, %g4			*/
	    0x89292000,		/* sll   %g4, shift, %g4		*/
	    0x82004004,		/* add   %g1, %g4, %g1			*/
	    0xc4586000,		/* ldx   [%g1 + tmiss_count], %g2	*/
	    0x8400a001,		/* add   %g2, 1, %g2			*/
	    0xc4706000,		/* stx   %g2, [%g1 + tmiss_count]	*/
	    0x0d000000,		/* sethi %hi(tdata_tmptick), %g6	*/
	    0x8c018007,		/* add   %g6, %g7, %g6			*/
	    0xc459a000,		/* ldx   [%g6 + %lo(tdata_tmptick)], %g2 */
	    0x8620c002,		/* sub   %g3, %g2, %g3			*/
	    0xc4586000,		/* ldx   [%g1 + tmiss_time], %g2	*/
	    0x84008003,		/* add   %g2, %g3, %g2			*/
	    0xc4706000,		/* stx   %g2, [%g1 + tmiss_time]	*/
	    0x83f00000		/* retry				*/
#endif /* sun4v */
	};

	ASSERT(MUTEX_HELD(&tstat_lock));
	/*CONSTCOND*/
	ASSERT(offsetof(tstat_missdata_t, tmiss_count) <= LO10(-1));
	/*CONSTCOND*/
	ASSERT(offsetof(tstat_missdata_t, tmiss_time) <= LO10(-1));
	/*CONSTCOND*/
	ASSERT(!((sizeof (tstat_pgszdata_t) - 1) & sizeof (tstat_pgszdata_t)));

	for (shift = 1; (1 << shift) != sizeof (tstat_pgszdata_t); shift++)
		continue;

	base = (uintptr_t)tcpu->tcpu_ibase + TSTAT_INSTR_SIZE +
	    ((uintptr_t)data - (uintptr_t)tcpu->tcpu_data);

	bcopy(retent, ent, sizeof (retent));

#if defined(sun4v)
	ent[TSTAT_RETENT_TDATASHFT] |= LO10((uintptr_t)TSTAT_DATA_SHIFT);
#endif
	ent[TSTAT_RETENT_STATHI] |= HI22(base);
	ent[TSTAT_RETENT_STATLO] |= LO10(base);
	ent[TSTAT_RETENT_SHIFT] |= shift;
	/* LINTED E_EXPR_NULL_EFFECT */
	ent[TSTAT_RETENT_COUNT_LD] |= offsetof(tstat_missdata_t, tmiss_count);
	/* LINTED E_EXPR_NULL_EFFECT */
	ent[TSTAT_RETENT_COUNT_ST] |= offsetof(tstat_missdata_t, tmiss_count);
	ent[TSTAT_RETENT_TMPTSHI] |= HI22(tmptick);
	ent[TSTAT_RETENT_TMPTSLO] |= LO10(tmptick);
	ent[TSTAT_RETENT_TIME_LD] |= offsetof(tstat_missdata_t, tmiss_time);
	ent[TSTAT_RETENT_TIME_ST] |= offsetof(tstat_missdata_t, tmiss_time);
}

#if defined(sun4v)
#undef TSTAT_RETENT_TDATASHFT
#endif
#undef TSTAT_RETENT_STATHI
#undef TSTAT_RETENT_STATLO
#undef TSTAT_RETENT_SHIFT
#undef TSTAT_RETENT_COUNT_LD
#undef TSTAT_RETENT_COUNT_ST
#undef TSTAT_RETENT_TMPTSHI
#undef TSTAT_RETENT_TMPTSLO
#undef TSTAT_RETENT_TIME_LD
#undef TSTAT_RETENT_TIME_ST

/*
 * The TSTAT_TLBENT_* constants define offsets in the TLB entry.  They are
 * used only in trapstat_tlbent() (below) and #undef'd immediately afterwards.
 * Any change to "tlbent" in trapstat_tlbent() will likely require changes
 * to these constants.
 */

#ifndef sun4v
#define	TSTAT_TLBENT_STATHI	0
#define	TSTAT_TLBENT_STATLO_LD	1
#define	TSTAT_TLBENT_STATLO_ST	3
#define	TSTAT_TLBENT_MMUASI	15
#define	TSTAT_TLBENT_TPCHI	18
#define	TSTAT_TLBENT_TPCLO_USER	19
#define	TSTAT_TLBENT_TPCLO_KERN	21
#define	TSTAT_TLBENT_TSHI	25
#define	TSTAT_TLBENT_TSLO	27
#define	TSTAT_TLBENT_BA		28
#else /* sun4v */
#define	TSTAT_TLBENT_TDATASHFT	2
#define	TSTAT_TLBENT_STATHI	3
#define	TSTAT_TLBENT_STATLO_LD	5
#define	TSTAT_TLBENT_STATLO_ST	7
#define	TSTAT_TLBENT_TAGTARGET	23
#define	TSTAT_TLBENT_TPCHI	25
#define	TSTAT_TLBENT_TPCLO_USER	26
#define	TSTAT_TLBENT_TPCLO_KERN	28
#define	TSTAT_TLBENT_TSHI	32
#define	TSTAT_TLBENT_TSLO	35
#define	TSTAT_TLBENT_ADDRHI	36
#define	TSTAT_TLBENT_ADDRLO	37
#endif /* sun4v */

static void
trapstat_tlbent(tstat_percpu_t *tcpu, int entno)
{
	uint32_t *ent;
	uintptr_t orig, va;
#ifndef sun4v
	uintptr_t baoffs;
	int itlb = entno == TSTAT_ENT_ITLBMISS;
	uint32_t asi = itlb ? ASI(ASI_IMMU) : ASI(ASI_DMMU);
#else
	int itlb = (entno == TSTAT_ENT_IMMUMISS || entno == TSTAT_ENT_ITLBMISS);
	uint32_t tagtarget_off = itlb ? MMFSA_I_CTX : MMFSA_D_CTX;
	uint32_t *tent;			/* MMU trap vector entry */
	uintptr_t tentva;		/* MMU trap vector entry va */
	static const uint32_t mmumiss[TSTAT_ENT_NINSTR] = {
	    0x30800000,			/* ba,a addr */
	    NOP, NOP, NOP, NOP, NOP, NOP, NOP
	};
#endif
	int entoffs = entno << TSTAT_ENT_SHIFT;
	uintptr_t tmptick, stat, tpc, utpc;
	tstat_pgszdata_t *data;
	tstat_tlbdata_t *udata, *kdata;
	tstat_tlbret_t *ret;

#ifdef sun4v
	data = &((tstat_tdata_t *)tcpu->tcpu_data)->tdata_pgsz[0];
#else
	data = &tcpu->tcpu_data->tdata_pgsz[0];
#endif /* sun4v */

	/*
	 * When trapstat is run with TLB statistics, this is the entry for
	 * both I- and D-TLB misses; this code performs trap level pushing,
	 * as described in the "TLB Statistics" section of the block comment.
	 * This code is executing at TL 1; %tstate[0] contains the saved
	 * state at the time of the TLB miss.  Pushing trap level 1 (and thus
	 * raising TL to 2) requires us to fill in %tstate[1] with our %pstate,
	 * %cwp and %asi.  We leave %tt unchanged, and we set %tpc and %tnpc to
	 * the appropriate TLB return entry (based on the context of the miss).
	 * Finally, we sample %tick, and stash it in the tdata_tmptick member
	 * the per-CPU tstat_data structure.  tdata_tmptick will be used in
	 * the TLB return entry to determine the amount of time spent in the
	 * TLB miss handler.
	 *
	 * Note that on sun4v platforms, we must obtain the context information
	 * from the MMU fault status area. (The base address of this MMU fault
	 * status area is kept in the scratchpad register 0.)
	 */
	static const uint32_t tlbent[] = {
#ifndef sun4v
	    0x03000000,			/* sethi %hi(stat), %g1		*/
	    0xc4586000,			/* ldx   [%g1 + %lo(stat)], %g2	*/
	    0x8400a001,			/* add   %g2, 1, %g2		*/
	    0xc4706000,			/* stx   %g2, [%g1 + %lo(stat)]	*/
	    0x85524000,			/* rdpr  %cwp, %g2		*/
	    0x87518000,			/* rdpr  %pstate, %g3		*/
	    0x8728f008,			/* sllx  %g3, 8, %g3		*/
	    0x84108003,			/* or    %g2, %g3, %g2		*/
	    0x8740c000,			/* rd    %asi, %g3		*/
	    0x8728f018,			/* sllx  %g3, 24, %g3		*/
	    0x84108003,			/* or    %g2, %g3, %g2		*/
	    0x8350c000,			/* rdpr  %tt, %g1		*/
	    0x8f902002,			/* wrpr  %g0, 2, %tl		*/
	    0x85908000,			/* wrpr  %g2, %g0, %tstate	*/
	    0x87904000,			/* wrpr  %g1, %g0, %tt		*/
	    0xc2d80000,			/* ldxa  [%g0]ASI_MMU, %g1	*/
	    0x83307030,			/* srlx  %g1, CTXSHIFT, %g1	*/
	    0x02c04004,			/* brz,pn %g1, .+0x10		*/
	    0x03000000,			/* sethi %hi(new_tpc), %g1	*/
	    0x82106000,			/* or    %g1, %lo(new_tpc), %g1	*/
	    0x30800002,			/* ba,a  .+0x8			*/
	    0x82106000,			/* or    %g1, %lo(new_tpc), %g1	*/
	    0x81904000,			/* wrpr  %g1, %g0, %tpc		*/
	    0x82006004,			/* add   %g1, 4, %g1		*/
	    0x83904000,			/* wrpr  %g1, %g0, %tnpc	*/
	    0x03000000,			/* sethi %hi(tmptick), %g1	*/
	    0x85410000,			/* rd    %tick, %g2		*/
	    0xc4706000,			/* stx   %g2, [%g1 + %lo(tmptick)] */
	    0x30800000,			/* ba,a  addr			*/
	    NOP, NOP, NOP
#else /* sun4v */
	    0x82102008,			/* mov SCRATCHPAD_CPUID, %g1	*/
	    0xc8d84400,			/* ldxa [%g1]ASI_SCRATCHPAD, %g4 */
	    0x89293000,			/* sllx %g4, TSTAT_DATA_SHIFT, %g4 */
	    0x03000000,			/* sethi %hi(stat), %g1		*/
	    0x82004004,			/* add %g1, %g4, %g1		*/
	    0xc4586000,			/* ldx   [%g1 + %lo(stat)], %g2	*/
	    0x8400a001,			/* add   %g2, 1, %g2		*/
	    0xc4706000,			/* stx   %g2, [%g1 + %lo(stat)]	*/
	    0x85524000,			/* rdpr  %cwp, %g2		*/
	    0x87518000,			/* rdpr  %pstate, %g3		*/
	    0x8728f008,			/* sllx  %g3, 8, %g3		*/
	    0x84108003,			/* or    %g2, %g3, %g2		*/
	    0x8740c000,			/* rd    %asi, %g3		*/
	    0x8728f018,			/* sllx  %g3, 24, %g3		*/
	    0x83540000,			/* rdpr  %gl, %g1		*/
	    0x83287028,			/* sllx  %g1, 40, %g1		*/
	    0x86104003,			/* or    %g1, %g3, %g3		*/
	    0x84108003,			/* or    %g2, %g3, %g2		*/
	    0x8350c000,			/* rdpr  %tt, %g1		*/
	    0x8f902002,			/* wrpr  %g0, 2, %tl		*/
	    0x85908000,			/* wrpr  %g2, %g0, %tstate	*/
	    0x87904000,			/* wrpr  %g1, %g0, %tt		*/
	    0xc2d80400,			/* ldxa  [%g0]ASI_SCRATCHPAD, %g1 */
	    0xc2586000,			/* ldx  [%g1 + MMFSA_?_CTX], %g1 */
	    0x02c04004,			/* brz,pn %g1, .+0x10		*/
	    0x03000000,			/* sethi %hi(new_tpc), %g1	*/
	    0x82106000,			/* or    %g1, %lo(new_tpc), %g1	*/
	    0x30800002,			/* ba,a  .+0x8			*/
	    0x82106000,			/* or    %g1, %lo(new_tpc), %g1	*/
	    0x81904000,			/* wrpr  %g1, %g0, %tpc		*/
	    0x82006004,			/* add   %g1, 4, %g1		*/
	    0x83904000,			/* wrpr  %g1, %g0, %tnpc	*/
	    0x03000000,			/* sethi %hi(tmptick), %g1	*/
	    0x82004004,			/* add %g1, %g4, %g1		*/
	    0x85410000,			/* rd    %tick, %g2		*/
	    0xc4706000,			/* stx   %g2, [%g1 + %lo(tmptick)] */
	    0x05000000,			/* sethi %hi(addr), %g2		*/
	    0x8410a000,			/* or %g2, %lo(addr), %g2	*/
	    0x81c08000,			/* jmp %g2			*/
	    NOP,
#endif /* sun4v */
	};

	ASSERT(MUTEX_HELD(&tstat_lock));
#ifndef sun4v
	ASSERT(entno == TSTAT_ENT_ITLBMISS || entno == TSTAT_ENT_DTLBMISS);

	stat = TSTAT_DATA_OFFS(tcpu, tdata_traps) + entoffs;
	tmptick = TSTAT_DATA_OFFS(tcpu, tdata_tmptick);
#else /* sun4v */
	ASSERT(entno == TSTAT_ENT_ITLBMISS || entno == TSTAT_ENT_DTLBMISS ||
	    entno == TSTAT_ENT_IMMUMISS || entno == TSTAT_ENT_DMMUMISS);

	stat = TSTAT_CPU0_TLBDATA_OFFS(tcpu, tdata_traps[entno]);
	tmptick = TSTAT_CPU0_TLBDATA_OFFS(tcpu, tdata_tmptick);
#endif /* sun4v */

	if (itlb) {
		ret = &tcpu->tcpu_instr->tinst_itlbret;
		udata = &data->tpgsz_user.tmode_itlb;
		kdata = &data->tpgsz_kernel.tmode_itlb;
		tpc = TSTAT_INSTR_OFFS(tcpu, tinst_itlbret.ttlbr_ktlb);
	} else {
		ret = &tcpu->tcpu_instr->tinst_dtlbret;
		udata = &data->tpgsz_user.tmode_dtlb;
		kdata = &data->tpgsz_kernel.tmode_dtlb;
		tpc = TSTAT_INSTR_OFFS(tcpu, tinst_dtlbret.ttlbr_ktlb);
	}

	utpc = tpc + offsetof(tstat_tlbret_t, ttlbr_utlb) -
	    offsetof(tstat_tlbret_t, ttlbr_ktlb);

	ASSERT(HI22(tpc) == HI22(utpc));

	ent = (uint32_t *)((uintptr_t)tcpu->tcpu_instr + entoffs);
	orig = KERNELBASE + entoffs;
	va = (uintptr_t)tcpu->tcpu_ibase + entoffs;

#ifdef sun4v
	/*
	 * Because of lack of space, interposing tlbent trap handler
	 * for TLB and MMU miss traps cannot be placed in-line. Instead,
	 * we copy it to the space set aside for shared trap handlers
	 * continuation in the interposing trap table and invoke it by
	 * placing a branch in the trap table itself.
	 */
	tent = ent;		/* trap vector entry */
	tentva = va;		/* trap vector entry va */

	if (itlb) {
		ent = (uint32_t *)((uintptr_t)
		    &tcpu->tcpu_instr->tinst_immumiss);
		va = TSTAT_INSTR_OFFS(tcpu, tinst_immumiss);
	} else {
		ent = (uint32_t *)((uintptr_t)
		    &tcpu->tcpu_instr->tinst_dmmumiss);
		va = TSTAT_INSTR_OFFS(tcpu, tinst_dmmumiss);
	}
	bcopy(mmumiss, tent, sizeof (mmumiss));
	tent[0] |= DISP22(tentva, va);
#endif /* sun4v */

	bcopy(tlbent, ent, sizeof (tlbent));

#if defined(sun4v)
	ent[TSTAT_TLBENT_TDATASHFT] |= LO10((uintptr_t)TSTAT_DATA_SHIFT);
#endif
	ent[TSTAT_TLBENT_STATHI] |= HI22(stat);
	ent[TSTAT_TLBENT_STATLO_LD] |= LO10(stat);
	ent[TSTAT_TLBENT_STATLO_ST] |= LO10(stat);
#ifndef sun4v
	ent[TSTAT_TLBENT_MMUASI] |= asi;
#else
	ent[TSTAT_TLBENT_TAGTARGET] |= tagtarget_off;
#endif
	ent[TSTAT_TLBENT_TPCHI] |= HI22(tpc);
	ent[TSTAT_TLBENT_TPCLO_USER] |= LO10(utpc);
	ent[TSTAT_TLBENT_TPCLO_KERN] |= LO10(tpc);
	ent[TSTAT_TLBENT_TSHI] |= HI22(tmptick);
	ent[TSTAT_TLBENT_TSLO] |= LO10(tmptick);
#ifndef	sun4v
	baoffs = TSTAT_TLBENT_BA * sizeof (uint32_t);
	ent[TSTAT_TLBENT_BA] |= DISP22(va + baoffs, orig);
#else
	ent[TSTAT_TLBENT_ADDRHI] |= HI22(orig);
	ent[TSTAT_TLBENT_ADDRLO] |= LO10(orig);
#endif /* sun4v */

	/*
	 * And now set up the TLB return entries.
	 */
	trapstat_tlbretent(tcpu, &ret->ttlbr_ktlb, &kdata->ttlb_tlb);
	trapstat_tlbretent(tcpu, &ret->ttlbr_ktsb, &kdata->ttlb_tsb);
	trapstat_tlbretent(tcpu, &ret->ttlbr_utlb, &udata->ttlb_tlb);
	trapstat_tlbretent(tcpu, &ret->ttlbr_utsb, &udata->ttlb_tsb);
}

#if defined(sun4v)
#undef TSTAT_TLBENT_TDATASHFT
#endif
#undef TSTAT_TLBENT_STATHI
#undef TSTAT_TLBENT_STATLO_LD
#undef TSTAT_TLBENT_STATLO_ST
#ifndef sun4v
#undef TSTAT_TLBENT_MMUASI
#else
#undef TSTAT_TLBENT_TAGTARGET
#endif
#undef TSTAT_TLBENT_TPCHI
#undef TSTAT_TLBENT_TPCLO_USER
#undef TSTAT_TLBENT_TPCLO_KERN
#undef TSTAT_TLBENT_TSHI
#undef TSTAT_TLBENT_TSLO
#undef TSTAT_TLBENT_BA

/*
 * The TSTAT_ENABLED_* constants define offsets in the enabled entry; the
 * TSTAT_DISABLED_BA constant defines an offset in the disabled entry.  Both
 * sets of constants are used only in trapstat_make_traptab() (below) and
 * #undef'd immediately afterwards.  Any change to "enabled" or "disabled"
 * in trapstat_make_traptab() will likely require changes to these constants.
 */
#ifndef sun4v
#define	TSTAT_ENABLED_STATHI	0
#define	TSTAT_ENABLED_STATLO_LD	1
#define	TSTAT_ENABLED_STATLO_ST 3
#define	TSTAT_ENABLED_BA	4
#define	TSTAT_DISABLED_BA	0

static void
trapstat_make_traptab(tstat_percpu_t *tcpu)
{
	uint32_t *ent;
	uint64_t *stat;
	uintptr_t orig, va, en_baoffs, dis_baoffs;
	int nent;

	/*
	 * This is the entry in the interposing trap table for enabled trap
	 * table entries.  It loads a counter, increments it and stores it
	 * back before branching to the actual trap table entry.
	 */
	static const uint32_t enabled[TSTAT_ENT_NINSTR] = {
	    0x03000000,			/* sethi %hi(stat), %g1		*/
	    0xc4586000,			/* ldx   [%g1 + %lo(stat)], %g2	*/
	    0x8400a001,			/* add   %g2, 1, %g2		*/
	    0xc4706000,			/* stx   %g2, [%g1 + %lo(stat)]	*/
	    0x30800000,			/* ba,a addr			*/
	    NOP, NOP, NOP
	};

	/*
	 * This is the entry in the interposing trap table for disabled trap
	 * table entries.  It simply branches to the actual, underlying trap
	 * table entry.  As explained in the "Implementation Details" section
	 * of the block comment, all TL>0 traps _must_ use the disabled entry;
	 * additional entries may be explicitly disabled through the use
	 * of TSTATIOC_ENTRY/TSTATIOC_NOENTRY.
	 */
	static const uint32_t disabled[TSTAT_ENT_NINSTR] = {
	    0x30800000,			/* ba,a addr			*/
	    NOP, NOP, NOP, NOP, NOP, NOP, NOP,
	};

	ASSERT(MUTEX_HELD(&tstat_lock));

	ent = tcpu->tcpu_instr->tinst_traptab;
	stat = (uint64_t *)TSTAT_DATA_OFFS(tcpu, tdata_traps);
	orig = KERNELBASE;
	va = (uintptr_t)tcpu->tcpu_ibase;
	en_baoffs = TSTAT_ENABLED_BA * sizeof (uint32_t);
	dis_baoffs = TSTAT_DISABLED_BA * sizeof (uint32_t);

	for (nent = 0; nent < TSTAT_TOTAL_NENT; nent++) {
		if (tstat_enabled[nent]) {
			bcopy(enabled, ent, sizeof (enabled));
			ent[TSTAT_ENABLED_STATHI] |= HI22((uintptr_t)stat);
			ent[TSTAT_ENABLED_STATLO_LD] |= LO10((uintptr_t)stat);
			ent[TSTAT_ENABLED_STATLO_ST] |= LO10((uintptr_t)stat);
			ent[TSTAT_ENABLED_BA] |= DISP22(va + en_baoffs, orig);
		} else {
			bcopy(disabled, ent, sizeof (disabled));
			ent[TSTAT_DISABLED_BA] |= DISP22(va + dis_baoffs, orig);
		}

		stat++;
		orig += sizeof (enabled);
		ent += sizeof (enabled) / sizeof (*ent);
		va += sizeof (enabled);
	}
}

#undef TSTAT_ENABLED_STATHI
#undef TSTAT_ENABLED_STATLO_LD
#undef TSTAT_ENABLED_STATLO_ST
#undef TSTAT_ENABLED_BA
#undef TSTAT_DISABLED_BA

#else /* sun4v */

#define	TSTAT_ENABLED_STATHI	0
#define	TSTAT_ENABLED_STATLO	1
#define	TSTAT_ENABLED_ADDRHI	2
#define	TSTAT_ENABLED_ADDRLO	3
#define	TSTAT_ENABLED_CONTBA	6
#define	TSTAT_ENABLED_TDATASHFT	7
#define	TSTAT_DISABLED_ADDRHI	0
#define	TSTAT_DISABLED_ADDRLO	1

static void
trapstat_make_traptab(tstat_percpu_t *tcpu)
{
	uint32_t *ent;
	uint64_t *stat;
	uintptr_t orig, va, en_baoffs;
	uintptr_t tstat_cont_va;
	int nent;

	/*
	 * This is the entry in the interposing trap table for enabled trap
	 * table entries.  It loads a counter, increments it and stores it
	 * back before branching to the actual trap table entry.
	 *
	 * All CPUs share the same interposing trap entry to count the
	 * number of traps. Note that the trap counter is kept in per CPU
	 * trap statistics area. Its address is obtained dynamically by
	 * adding the offset of that CPU's trap statistics area from CPU 0
	 * (i.e. cpu_id * TSTAT_DATA_SIZE) to the address of the CPU 0
	 * trap counter already coded in the interposing trap entry itself.
	 *
	 * Since this interposing code sequence to count traps takes more
	 * than 8 instructions, it's split in two parts as follows:
	 *
	 *   tstat_trapcnt:
	 *	sethi %hi(stat), %g1
	 *	or    %g1, %lo[stat), %g1	! %g1 = CPU0 trap counter addr
	 *	sethi %hi(addr), %g2
	 *	or    %g2, %lo(addr), %g2	! %g2 = real trap handler addr
	 *	mov   ASI_SCRATCHPAD_CPUID, %g3
	 *	ldxa [%g3]ASI_SCRATCHPAD, %g3	! %g3 = CPU ID
	 *	ba tstat_trapcnt_cont		! branch to tstat_trapcnt_cont
	 *	sllx %g3, TSTAT_DATA_SHIFT, %g3	! %g3 = CPU trapstat data offset
	 *
	 *   tstat_trapcnt_cont:
	 *	ldx [%g1 + %g3], %g4		! get counter value
	 *	add %g4, 1, %g4			! increment value
	 *	jmp %g2				! jump to original trap handler
	 *	stx %g4, [%g1 + %g3]		! store counter value
	 *
	 * First part, i.e. tstat_trapcnt, is per trap and is kept in-line in
	 * the interposing trap table. However, the tstat_trapcnt_cont code
	 * sequence is shared by all traps and is kept right after the
	 * the interposing trap table.
	 */
	static const uint32_t enabled[TSTAT_ENT_NINSTR] = {
	    0x03000000,			/* sethi %hi(stat), %g1		*/
	    0x82106000,			/* or   %g1, %lo[stat), %g1	*/
	    0x05000000,			/* sethi %hi(addr), %g2		*/
	    0x8410a000,			/* or   %g2, %lo(addr), %g2	*/
	    0x86102008,			/* mov	ASI_SCRATCHPAD_CPUID, %g3 */
	    0xc6d8c400,			/* ldxa [%g3]ASI_SCRATCHPAD, %g3 */
	    0x10800000,			/* ba enabled_cont		*/
	    0x8728f000			/* sllx %g3, TSTAT_DATA_SHIFT, %g3 */
	};

	static const uint32_t enabled_cont[TSTAT_ENT_NINSTR] = {
	    0xc8584003,			/* ldx [%g1 + %g3], %g4		*/
	    0x88012001,			/* add %g4, 1, %g4		*/
	    0x81c08000,			/* jmp %g2			*/
	    0xc8704003,			/* stx %g4, [%g1 + %g3]		*/
	    NOP, NOP, NOP, NOP
	};

	/*
	 * This is the entry in the interposing trap table for disabled trap
	 * table entries.  It simply "jmp" to the actual, underlying trap
	 * table entry.  As explained in the "Implementation Details" section
	 * of the block comment, all TL>0 traps _must_ use the disabled entry;
	 * additional entries may be explicitly disabled through the use
	 * of TSTATIOC_ENTRY/TSTATIOC_NOENTRY.
	 */
	static const uint32_t disabled[TSTAT_ENT_NINSTR] = {
	    0x05000000,			/* sethi %hi(addr), %g2		*/
	    0x8410a000,			/* or %g2, %lo(addr), %g2	*/
	    0x81c08000,			/* jmp %g2			*/
	    NOP, NOP, NOP, NOP, NOP,
	};

	ASSERT(MUTEX_HELD(&tstat_lock));
	ent = tcpu->tcpu_instr->tinst_traptab;
	stat = (uint64_t *)TSTAT_CPU0_DATA_OFFS(tcpu, tdata_traps);
	orig = KERNELBASE;
	va = (uintptr_t)tcpu->tcpu_ibase;
	en_baoffs = TSTAT_ENABLED_CONTBA * sizeof (uint32_t);
	tstat_cont_va = TSTAT_INSTR_OFFS(tcpu, tinst_trapcnt);

	for (nent = 0; nent < TSTAT_TOTAL_NENT; nent++) {
		/*
		 * If TSTAT_OPT_TLBDATA option is enabled (-t or -T option)
		 * we make sure only TSTAT_TLB_NENT traps can be enabled.
		 * Note that this logic is somewhat moot since trapstat
		 * cmd actually use TSTATIOC_NOENTRY ioctl to disable all
		 * traps when performing Tlb stats collection.
		 */
		if ((!(tstat_options & TSTAT_OPT_TLBDATA) ||
		    nent < TSTAT_TLB_NENT) && tstat_enabled[nent]) {
			bcopy(enabled, ent, sizeof (enabled));
			ent[TSTAT_ENABLED_STATHI] |= HI22((uintptr_t)stat);
			ent[TSTAT_ENABLED_STATLO] |= LO10((uintptr_t)stat);
			ent[TSTAT_ENABLED_ADDRHI] |= HI22((uintptr_t)orig);
			ent[TSTAT_ENABLED_ADDRLO] |= LO10((uintptr_t)orig);
			ent[TSTAT_ENABLED_CONTBA] |=
			    DISP22(va + en_baoffs, tstat_cont_va);
			ent[TSTAT_ENABLED_TDATASHFT] |=
			    LO10((uintptr_t)TSTAT_DATA_SHIFT);
		} else {
			bcopy(disabled, ent, sizeof (disabled));
			ent[TSTAT_DISABLED_ADDRHI] |= HI22((uintptr_t)orig);
			ent[TSTAT_DISABLED_ADDRLO] |= LO10((uintptr_t)orig);
		}

		stat++;
		orig += sizeof (enabled);
		ent += sizeof (enabled) / sizeof (*ent);
		va += sizeof (enabled);
	}
	bcopy(enabled_cont, (uint32_t *)tcpu->tcpu_instr->tinst_trapcnt,
	    sizeof (enabled_cont));
}

#undef	TSTAT_ENABLED_TDATASHFT
#undef	TSTAT_ENABLED_STATHI
#undef	TSTAT_ENABLED_STATLO
#undef	TSTAT_ENABLED_ADDRHI
#undef	TSTAT_ENABLED_ADDRLO
#undef	TSTAT_ENABLED_CONTBA
#undef	TSTAT_DISABLED_BA

#endif /* sun4v */

#ifndef sun4v
/*
 * See Section A.6 in SPARC v9 Manual.
 * max branch = 4*((2^21)-1) = 8388604
 */
#define	MAX_BICC_BRANCH_DISPLACEMENT (4 * ((1 << 21) - 1))
#endif

static void
trapstat_setup(processorid_t cpu)
{
	tstat_percpu_t *tcpu = &tstat_percpu[cpu];
#ifndef sun4v
	int i;
	caddr_t va;
	pfn_t *pfn;
	cpu_t *cp;
	uint_t strand_idx;
	size_t tstat_offset;
#else
	uint64_t offset;
#endif

	ASSERT(tcpu->tcpu_pfn == NULL);
	ASSERT(tcpu->tcpu_instr == NULL);
	ASSERT(tcpu->tcpu_data == NULL);
	ASSERT(tcpu->tcpu_flags & TSTAT_CPU_SELECTED);
	ASSERT(!(tcpu->tcpu_flags & TSTAT_CPU_ALLOCATED));
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(MUTEX_HELD(&tstat_lock));

#ifndef sun4v
	/*
	 * The lower fifteen bits of the %tba are always read as zero; we must
	 * align our instruction base address appropriately.
	 */
	tstat_offset = tstat_total_size;

	cp = cpu_get(cpu);
	ASSERT(cp != NULL);
	if ((strand_idx = cpu ^ pg_plat_hw_instance_id(cp, PGHW_IPIPE)) != 0) {
		/*
		 * On sun4u platforms with multiple CPUs sharing the MMU
		 * (Olympus-C has 2 strands per core), each CPU uses a
		 * disjoint trap table.  The indexing is based on the
		 * strand id, which is obtained by XOR'ing the cpuid with
		 * the coreid.
		 */
		tstat_offset += tstat_total_size * strand_idx;

		/*
		 * Offset must be less than the maximum PC-relative branch
		 * displacement for Bicc variants.  See the Implementation
		 * Details comment.
		 */
		ASSERT(tstat_offset <= MAX_BICC_BRANCH_DISPLACEMENT);
	}

	tcpu->tcpu_ibase = (caddr_t)((KERNELBASE - tstat_offset)
	    & TSTAT_TBA_MASK);
	tcpu->tcpu_dbase = tcpu->tcpu_ibase + TSTAT_INSTR_SIZE;
	tcpu->tcpu_vabase = tcpu->tcpu_ibase;

	tcpu->tcpu_pfn = vmem_alloc(tstat_arena, tstat_total_pages, VM_SLEEP);
	bzero(tcpu->tcpu_pfn, tstat_total_pages);
	pfn = tcpu->tcpu_pfn;

	tcpu->tcpu_instr = vmem_alloc(tstat_arena, TSTAT_INSTR_SIZE, VM_SLEEP);

	va = (caddr_t)tcpu->tcpu_instr;
	for (i = 0; i < TSTAT_INSTR_PAGES; i++, va += MMU_PAGESIZE)
		*pfn++ = hat_getpfnum(kas.a_hat, va);

	/*
	 * We must be sure that the pages that we will use to examine the data
	 * have the same virtual color as the pages to which the data is being
	 * recorded, hence the alignment and phase constraints on the
	 * allocation.
	 */
	tcpu->tcpu_data = vmem_xalloc(tstat_arena, tstat_data_size,
	    shm_alignment, (uintptr_t)tcpu->tcpu_dbase & (shm_alignment - 1),
	    0, 0, NULL, VM_SLEEP);
	bzero(tcpu->tcpu_data, tstat_data_size);
	tcpu->tcpu_data->tdata_cpuid = cpu;

	va = (caddr_t)tcpu->tcpu_data;
	for (i = 0; i < tstat_data_pages; i++, va += MMU_PAGESIZE)
		*pfn++ = hat_getpfnum(kas.a_hat, va);

	/*
	 * Now that we have all of the instruction and data pages allocated,
	 * make the trap table from scratch.
	 */
	trapstat_make_traptab(tcpu);

	if (tstat_options & TSTAT_OPT_TLBDATA) {
		/*
		 * TLB Statistics have been specified; set up the I- and D-TLB
		 * entries and corresponding TLB return entries.
		 */
		trapstat_tlbent(tcpu, TSTAT_ENT_ITLBMISS);
		trapstat_tlbent(tcpu, TSTAT_ENT_DTLBMISS);
	}

#else /* sun4v */

	/*
	 * The lower fifteen bits of the %tba are always read as zero; hence
	 * it must be aligned at least on 512K boundary.
	 */
	tcpu->tcpu_vabase = (caddr_t)(KERNELBASE -
	    MMU_PAGESIZE4M * tstat_num4m_mapping);
	tcpu->tcpu_ibase = tcpu->tcpu_vabase;
	tcpu->tcpu_dbase = tcpu->tcpu_ibase + TSTAT_INSTR_SIZE +
	    cpu * TSTAT_DATA_SIZE;

	tcpu->tcpu_pfn = &tstat_pfn[0];
	tcpu->tcpu_instr = (tstat_instr_t *)tstat_va[0];

	offset = TSTAT_INSTR_SIZE + cpu * TSTAT_DATA_SIZE;
	tcpu->tcpu_data = (tstat_data_t *)(tstat_va[offset >> MMU_PAGESHIFT4M] +
	    (offset & MMU_PAGEOFFSET4M));
	bzero(tcpu->tcpu_data, TSTAT_DATA_SIZE);

	/*
	 * Now that we have all of the instruction and data pages allocated,
	 * make the trap table from scratch. It should be done only once
	 * as it is shared by all CPUs.
	 */
	if (!tstat_traptab_initialized)
		trapstat_make_traptab(tcpu);

	if (tstat_options & TSTAT_OPT_TLBDATA) {
		/*
		 * TLB Statistics have been specified; set up the I- and D-TLB
		 * entries and corresponding TLB return entries.
		 */
		if (!tstat_traptab_initialized) {
			if (tstat_fast_tlbstat) {
				trapstat_tlbent(tcpu, TSTAT_ENT_IMMUMISS);
				trapstat_tlbent(tcpu, TSTAT_ENT_DMMUMISS);
			} else {
				trapstat_tlbent(tcpu, TSTAT_ENT_ITLBMISS);
				trapstat_tlbent(tcpu, TSTAT_ENT_DTLBMISS);
			}
		}
	}
	tstat_traptab_initialized = 1;
#endif /* sun4v */

	tcpu->tcpu_flags |= TSTAT_CPU_ALLOCATED;

	/*
	 * Finally, get the target CPU to load the locked pages into its TLBs.
	 */
	xc_one(cpu, (xcfunc_t *)trapstat_load_tlb, 0, 0);
}

static void
trapstat_teardown(processorid_t cpu)
{
	tstat_percpu_t *tcpu = &tstat_percpu[cpu];
	int i;
	caddr_t va = tcpu->tcpu_vabase;

	ASSERT(tcpu->tcpu_pfn != NULL);
	ASSERT(tcpu->tcpu_instr != NULL);
	ASSERT(tcpu->tcpu_data != NULL);
	ASSERT(tcpu->tcpu_flags & TSTAT_CPU_SELECTED);
	ASSERT(tcpu->tcpu_flags & TSTAT_CPU_ALLOCATED);
	ASSERT(!(tcpu->tcpu_flags & TSTAT_CPU_ENABLED));
	ASSERT(MUTEX_HELD(&cpu_lock));
	ASSERT(MUTEX_HELD(&tstat_lock));

#ifndef sun4v
	vmem_free(tstat_arena, tcpu->tcpu_pfn, tstat_total_pages);
	vmem_free(tstat_arena, tcpu->tcpu_instr, TSTAT_INSTR_SIZE);
	vmem_free(tstat_arena, tcpu->tcpu_data, tstat_data_size);

	for (i = 0; i < tstat_total_pages; i++, va += MMU_PAGESIZE) {
		xt_one(cpu, vtag_flushpage_tl1, (uint64_t)va,
		    (uint64_t)ksfmmup);
	}
#else
	for (i = 0; i < tstat_num4m_mapping; i++) {
		xt_one(cpu, vtag_unmap_perm_tl1, (uint64_t)va, KCONTEXT);
		va += MMU_PAGESIZE4M;
	}
#endif

	tcpu->tcpu_pfn = NULL;
	tcpu->tcpu_instr = NULL;
	tcpu->tcpu_data = NULL;
	tcpu->tcpu_flags &= ~TSTAT_CPU_ALLOCATED;
}

static int
trapstat_go()
{
	cpu_t *cp;
#ifdef sun4v
	int i;
#endif /* sun4v */

	mutex_enter(&cpu_lock);
	mutex_enter(&tstat_lock);

	if (tstat_running) {
		mutex_exit(&tstat_lock);
		mutex_exit(&cpu_lock);
		return (EBUSY);
	}

#ifdef sun4v
	/*
	 * Compute the actual number of 4MB mappings
	 * we need based on the guest's ncpu_guest_max value.
	 * Note that earlier at compiled time, we did establish
	 * and check against the sun4v solaris arch limit
	 * (TSTAT_NUM4M_LIMIT) which is based on NCPU.
	 */
	tstat_num4m_mapping = TSTAT_NUM4M_MACRO(ncpu_guest_max);
	ASSERT(tstat_num4m_mapping <= TSTAT_NUM4M_LIMIT);

	/*
	 * Allocate large pages to hold interposing tables.
	 */
	for (i = 0; i < tstat_num4m_mapping; i++) {
		tstat_va[i] = contig_mem_alloc(MMU_PAGESIZE4M);
		tstat_pfn[i] = va_to_pfn(tstat_va[i]);
		if (tstat_pfn[i] == PFN_INVALID) {
			int j;
			for (j = 0; j < i; j++) {
				contig_mem_free(tstat_va[j], MMU_PAGESIZE4M);
			}
			mutex_exit(&tstat_lock);
			mutex_exit(&cpu_lock);
			return (EAGAIN);
		}
	}


	/*
	 * For detailed TLB statistics, invoke CPU specific interface
	 * to see if it supports a low overhead interface to collect
	 * TSB hit statistics. If so, make set tstat_fast_tlbstat flag
	 * to reflect that.
	 */
	if (tstat_options & TSTAT_OPT_TLBDATA) {
		int error;

		tstat_fast_tlbstat = B_FALSE;
		error = cpu_trapstat_conf(CPU_TSTATCONF_INIT);
		if (error == 0)
			tstat_fast_tlbstat = B_TRUE;
		else if (error != ENOTSUP) {
			for (i = 0; i < tstat_num4m_mapping; i++) {
				contig_mem_free(tstat_va[i], MMU_PAGESIZE4M);
			}
			mutex_exit(&tstat_lock);
			mutex_exit(&cpu_lock);
			return (error);
		}
	}

	tstat_hv_nopanic = 1;
	tstat_perm_mapping_failed = 0;
#endif /* sun4v */

	/*
	 * First, perform any necessary hot patching.
	 */
	trapstat_hotpatch();

	/*
	 * Allocate the resources we'll need to measure probe effect.
	 */
	trapstat_probe_alloc();

	cp = cpu_list;
	do {
		if (!(tstat_percpu[cp->cpu_id].tcpu_flags & TSTAT_CPU_SELECTED))
			continue;

		trapstat_setup(cp->cpu_id);

		/*
		 * Note that due to trapstat_probe()'s use of global data,
		 * we determine the probe effect on each CPU serially instead
		 * of in parallel with an xc_all().
		 */
		xc_one(cp->cpu_id, (xcfunc_t *)trapstat_probe, 0, 0);

#ifdef sun4v
		/*
		 * Check to see if the first cpu's attempt to create
		 * the perm mappings failed. This might happen if the
		 * guest somehow exhausted all its limited perm mappings.
		 * Note that we only check this once for the first
		 * attempt since it shouldn't fail for subsequent cpus
		 * mapping the same TTEs if the first attempt was successful.
		 */
		if (tstat_hv_nopanic && tstat_perm_mapping_failed) {
			tstat_percpu_t *tcpu = &tstat_percpu[cp->cpu_id];
			for (i = 0; i < tstat_num4m_mapping; i++) {
				contig_mem_free(tstat_va[i], MMU_PAGESIZE4M);
			}

			/*
			 * Do clean up before returning.
			 * Cleanup is manageable since we
			 * only need to do it for the first cpu
			 * iteration that failed.
			 */
			trapstat_probe_free();
			trapstat_hotpatch();
			tcpu->tcpu_pfn = NULL;
			tcpu->tcpu_instr = NULL;
			tcpu->tcpu_data = NULL;
			tcpu->tcpu_flags &= ~TSTAT_CPU_ALLOCATED;
			mutex_exit(&tstat_lock);
			mutex_exit(&cpu_lock);
			return (EAGAIN);
		}
		tstat_hv_nopanic = 0;
#endif /* sun4v */

	} while ((cp = cp->cpu_next) != cpu_list);

	xc_all((xcfunc_t *)trapstat_enable, 0, 0);

	trapstat_probe_free();
	tstat_running = 1;
	mutex_exit(&tstat_lock);
	mutex_exit(&cpu_lock);

	return (0);
}

static int
trapstat_stop()
{
	int i;

	mutex_enter(&cpu_lock);
	mutex_enter(&tstat_lock);
	if (!tstat_running) {
		mutex_exit(&tstat_lock);
		mutex_exit(&cpu_lock);
		return (ENXIO);
	}

	xc_all((xcfunc_t *)trapstat_disable, 0, 0);

	for (i = 0; i <= max_cpuid; i++) {
		if (tstat_percpu[i].tcpu_flags & TSTAT_CPU_ALLOCATED)
			trapstat_teardown(i);
	}

#ifdef sun4v
	tstat_traptab_initialized = 0;
	if (tstat_options & TSTAT_OPT_TLBDATA)
		(void) cpu_trapstat_conf(CPU_TSTATCONF_FINI);
	for (i = 0; i < tstat_num4m_mapping; i++)
		contig_mem_free(tstat_va[i], MMU_PAGESIZE4M);
#endif
	trapstat_hotpatch();
	tstat_running = 0;
	mutex_exit(&tstat_lock);
	mutex_exit(&cpu_lock);

	return (0);
}

/*
 * This is trapstat's DR CPU configuration callback.  It's called (with
 * cpu_lock held) to unconfigure a newly powered-off CPU, or to configure a
 * powered-off CPU that is to be brought into the system.  We need only take
 * action in the unconfigure case:  because a powered-off CPU will have its
 * trap table restored to KERNELBASE if it is ever powered back on, we must
 * update the flags to reflect that trapstat is no longer enabled on the
 * powered-off CPU.  Note that this means that a TSTAT_CPU_ENABLED CPU that
 * is unconfigured/powered off and later powered back on/reconfigured will
 * _not_ be re-TSTAT_CPU_ENABLED.
 */
static int
trapstat_cpu_setup(cpu_setup_t what, processorid_t cpu)
{
	tstat_percpu_t *tcpu = &tstat_percpu[cpu];

	ASSERT(MUTEX_HELD(&cpu_lock));
	mutex_enter(&tstat_lock);

	if (!tstat_running) {
		mutex_exit(&tstat_lock);
		return (0);
	}

	switch (what) {
	case CPU_CONFIG:
		ASSERT(!(tcpu->tcpu_flags & TSTAT_CPU_ENABLED));
		break;

	case CPU_UNCONFIG:
		if (tcpu->tcpu_flags & TSTAT_CPU_ENABLED) {
			tcpu->tcpu_flags &= ~TSTAT_CPU_ENABLED;
#ifdef	sun4v
			/*
			 * A power-off, causes the cpu mondo queues to be
			 * unconfigured on sun4v. Since we can't teardown
			 * trapstat's mappings on the cpu that is going away,
			 * we simply mark it as not allocated. This will
			 * prevent a teardown on a cpu with the same cpu id
			 * that might have been added while trapstat is running.
			 */
			if (tcpu->tcpu_flags & TSTAT_CPU_ALLOCATED) {
				tcpu->tcpu_pfn = NULL;
				tcpu->tcpu_instr = NULL;
				tcpu->tcpu_data = NULL;
				tcpu->tcpu_flags &= ~TSTAT_CPU_ALLOCATED;
			}
#endif
		}
		break;

	default:
		break;
	}

	mutex_exit(&tstat_lock);
	return (0);
}

/*
 * This is called before a CPR suspend and after a CPR resume.  We don't have
 * anything to do before a suspend, but after a restart we must restore the
 * trap table to be our interposing trap table.  However, we don't actually
 * know whether or not the CPUs have been powered off -- this routine may be
 * called while restoring from a failed CPR suspend.  We thus run through each
 * TSTAT_CPU_ENABLED CPU, and explicitly destroy and reestablish its
 * interposing trap table.  This assures that our state is correct regardless
 * of whether or not the CPU has been newly powered on.
 */
/*ARGSUSED*/
static boolean_t
trapstat_cpr(void *arg, int code)
{
	cpu_t *cp;

	if (code == CB_CODE_CPR_CHKPT)
		return (B_TRUE);

	ASSERT(code == CB_CODE_CPR_RESUME);

	mutex_enter(&cpu_lock);
	mutex_enter(&tstat_lock);

	if (!tstat_running) {
		mutex_exit(&tstat_lock);
		mutex_exit(&cpu_lock);
		return (B_TRUE);
	}

	cp = cpu_list;
	do {
		tstat_percpu_t *tcpu = &tstat_percpu[cp->cpu_id];

		if (!(tcpu->tcpu_flags & TSTAT_CPU_ENABLED))
			continue;

		ASSERT(tcpu->tcpu_flags & TSTAT_CPU_SELECTED);
		ASSERT(tcpu->tcpu_flags & TSTAT_CPU_ALLOCATED);

		xc_one(cp->cpu_id, (xcfunc_t *)trapstat_disable, 0, 0);
		ASSERT(!(tcpu->tcpu_flags & TSTAT_CPU_ENABLED));

		/*
		 * Preserve this CPU's data in tstat_buffer and rip down its
		 * interposing trap table.
		 */
#ifdef sun4v
		bcopy(tcpu->tcpu_data, tstat_buffer, TSTAT_DATA_SIZE);
#else
		bcopy(tcpu->tcpu_data, tstat_buffer, tstat_data_t_size);
#endif /* sun4v */
		trapstat_teardown(cp->cpu_id);
		ASSERT(!(tcpu->tcpu_flags & TSTAT_CPU_ALLOCATED));

		/*
		 * Reestablish the interposing trap table and restore the old
		 * data.
		 */
		trapstat_setup(cp->cpu_id);
		ASSERT(tcpu->tcpu_flags & TSTAT_CPU_ALLOCATED);
#ifdef sun4v
		bcopy(tstat_buffer, tcpu->tcpu_data, TSTAT_DATA_SIZE);
#else
		bcopy(tstat_buffer, tcpu->tcpu_data, tstat_data_t_size);
#endif /* sun4v */

		xc_one(cp->cpu_id, (xcfunc_t *)trapstat_enable, 0, 0);
	} while ((cp = cp->cpu_next) != cpu_list);

	mutex_exit(&tstat_lock);
	mutex_exit(&cpu_lock);

	return (B_TRUE);
}

/*ARGSUSED*/
static int
trapstat_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	int i;

	mutex_enter(&cpu_lock);
	mutex_enter(&tstat_lock);
	if (tstat_open != 0) {
		mutex_exit(&tstat_lock);
		mutex_exit(&cpu_lock);
		return (EBUSY);
	}

	/*
	 * Register this in open() rather than in attach() to prevent deadlock
	 * with DR code. During attach, I/O device tree locks are grabbed
	 * before trapstat_attach() is invoked - registering in attach
	 * will result in the lock order: device tree lock, cpu_lock.
	 * DR code however requires that cpu_lock be acquired before
	 * device tree locks.
	 */
	ASSERT(!tstat_running);
	register_cpu_setup_func((cpu_setup_func_t *)trapstat_cpu_setup, NULL);

	/*
	 * Clear all options.  And until specific CPUs are specified, we'll
	 * mark all CPUs as selected.
	 */
	tstat_options = 0;

	for (i = 0; i <= max_cpuid; i++)
		tstat_percpu[i].tcpu_flags |= TSTAT_CPU_SELECTED;

	/*
	 * By default, all traps at TL=0 are enabled.  Traps at TL>0 must
	 * be disabled.
	 */
	for (i = 0; i < TSTAT_TOTAL_NENT; i++)
		tstat_enabled[i] = i < TSTAT_NENT ? 1 : 0;

	tstat_open = 1;
	mutex_exit(&tstat_lock);
	mutex_exit(&cpu_lock);

	return (0);
}

/*ARGSUSED*/
static int
trapstat_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	(void) trapstat_stop();

	ASSERT(!tstat_running);

	mutex_enter(&cpu_lock);
	unregister_cpu_setup_func((cpu_setup_func_t *)trapstat_cpu_setup, NULL);
	mutex_exit(&cpu_lock);

	tstat_open = 0;
	return (DDI_SUCCESS);
}

static int
trapstat_option(int option)
{
	mutex_enter(&tstat_lock);

	if (tstat_running) {
		mutex_exit(&tstat_lock);
		return (EBUSY);
	}

	tstat_options |= option;
	mutex_exit(&tstat_lock);

	return (0);
}

/*ARGSUSED*/
static int
trapstat_ioctl(dev_t dev, int cmd, intptr_t arg, int md, cred_t *crd, int *rval)
{
	int i, j, out;
	size_t dsize;

	switch (cmd) {
	case TSTATIOC_GO:
		return (trapstat_go());

	case TSTATIOC_NOGO:
		return (trapstat_option(TSTAT_OPT_NOGO));

	case TSTATIOC_STOP:
		return (trapstat_stop());

	case TSTATIOC_CPU:
		if (arg < 0 || arg > max_cpuid)
			return (EINVAL);
		/*FALLTHROUGH*/

	case TSTATIOC_NOCPU:
		mutex_enter(&tstat_lock);

		if (tstat_running) {
			mutex_exit(&tstat_lock);
			return (EBUSY);
		}

		/*
		 * If this is the first CPU to be specified (or if we are
		 * being asked to explicitly de-select CPUs), disable all CPUs.
		 */
		if (!(tstat_options & TSTAT_OPT_CPU) || cmd == TSTATIOC_NOCPU) {
			tstat_options |= TSTAT_OPT_CPU;

			for (i = 0; i <= max_cpuid; i++) {
				tstat_percpu_t *tcpu = &tstat_percpu[i];

				ASSERT(cmd == TSTATIOC_NOCPU ||
				    (tcpu->tcpu_flags & TSTAT_CPU_SELECTED));
				tcpu->tcpu_flags &= ~TSTAT_CPU_SELECTED;
			}
		}

		if (cmd == TSTATIOC_CPU)
			tstat_percpu[arg].tcpu_flags |= TSTAT_CPU_SELECTED;

		mutex_exit(&tstat_lock);

		return (0);

	case TSTATIOC_ENTRY:
		mutex_enter(&tstat_lock);

		if (tstat_running) {
			mutex_exit(&tstat_lock);
			return (EBUSY);
		}

		if (arg >= TSTAT_NENT || arg < 0) {
			mutex_exit(&tstat_lock);
			return (EINVAL);
		}

		if (!(tstat_options & TSTAT_OPT_ENTRY)) {
			/*
			 * If this is the first entry that we are explicitly
			 * enabling, explicitly disable every TL=0 entry.
			 */
			for (i = 0; i < TSTAT_NENT; i++)
				tstat_enabled[i] = 0;

			tstat_options |= TSTAT_OPT_ENTRY;
		}

		tstat_enabled[arg] = 1;
		mutex_exit(&tstat_lock);
		return (0);

	case TSTATIOC_NOENTRY:
		mutex_enter(&tstat_lock);

		if (tstat_running) {
			mutex_exit(&tstat_lock);
			return (EBUSY);
		}

		for (i = 0; i < TSTAT_NENT; i++)
			tstat_enabled[i] = 0;

		mutex_exit(&tstat_lock);
		return (0);

	case TSTATIOC_READ:
		mutex_enter(&tstat_lock);

		if (tstat_options & TSTAT_OPT_TLBDATA) {
			dsize = tstat_data_t_exported_size;
		} else {
			dsize = sizeof (tstat_data_t);
		}

		for (i = 0, out = 0; i <= max_cpuid; i++) {
			tstat_percpu_t *tcpu = &tstat_percpu[i];

			if (!(tcpu->tcpu_flags & TSTAT_CPU_ENABLED))
				continue;

			ASSERT(tcpu->tcpu_flags & TSTAT_CPU_SELECTED);
			ASSERT(tcpu->tcpu_flags & TSTAT_CPU_ALLOCATED);

			tstat_buffer->tdata_cpuid = -1;
			xc_one(i, (xcfunc_t *)trapstat_snapshot, 0, 0);

			if (tstat_buffer->tdata_cpuid == -1) {
				/*
				 * This CPU is not currently responding to
				 * cross calls; we have caught it while it is
				 * being unconfigured.  We'll drop tstat_lock
				 * and pick up and drop cpu_lock.  By the
				 * time we acquire cpu_lock, the DR operation
				 * will appear consistent and we can assert
				 * that trapstat_cpu_setup() has cleared
				 * TSTAT_CPU_ENABLED.
				 */
				mutex_exit(&tstat_lock);
				mutex_enter(&cpu_lock);
				mutex_exit(&cpu_lock);
				mutex_enter(&tstat_lock);
				ASSERT(!(tcpu->tcpu_flags & TSTAT_CPU_ENABLED));
				continue;
			}

			/*
			 * Need to compensate for the difference between page
			 * sizes exported to users and page sizes available
			 * within the kernel.
			 */
			if ((tstat_options & TSTAT_OPT_TLBDATA) &&
			    (tstat_pgszs != tstat_user_pgszs)) {
				tstat_pgszdata_t *tp;
				uint_t szc;

				tp = &tstat_buffer->tdata_pgsz[0];
				for (j = 0; j < tstat_user_pgszs; j++) {
					if ((szc = USERSZC_2_SZC(j)) != j) {
						bcopy(&tp[szc], &tp[j],
						    sizeof (tstat_pgszdata_t));
					}
				}
			}

			if (copyout(tstat_buffer, (void *)arg, dsize) != 0) {
				mutex_exit(&tstat_lock);
				return (EFAULT);
			}

			out++;
			arg += dsize;
		}

		if (out != max_cpuid + 1) {
			processorid_t cpuid = -1;
			arg += offsetof(tstat_data_t, tdata_cpuid);

			if (copyout(&cpuid, (void *)arg, sizeof (cpuid)) != 0) {
				mutex_exit(&tstat_lock);
				return (EFAULT);
			}
		}

		mutex_exit(&tstat_lock);

		return (0);

	case TSTATIOC_TLBDATA:
		return (trapstat_option(TSTAT_OPT_TLBDATA));

	default:
		break;
	}

	return (ENOTTY);
}

/*ARGSUSED*/
static int
trapstat_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)tstat_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

static int
trapstat_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(devi, "trapstat", S_IFCHR,
	    0, DDI_PSEUDO, 0) == DDI_FAILURE) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}

	ddi_report_dev(devi);
	tstat_devi = devi;

	tstat_pgszs = page_num_pagesizes();
	tstat_user_pgszs = page_num_user_pagesizes(0);
	tstat_data_t_size = sizeof (tstat_data_t) +
	    (tstat_pgszs - 1) * sizeof (tstat_pgszdata_t);
	tstat_data_t_exported_size = sizeof (tstat_data_t) +
	    (tstat_user_pgszs - 1) * sizeof (tstat_pgszdata_t);
#ifndef sun4v
	tstat_data_pages = (tstat_data_t_size >> MMU_PAGESHIFT) + 1;
	tstat_total_pages = TSTAT_INSTR_PAGES + tstat_data_pages;
	tstat_data_size = tstat_data_pages * MMU_PAGESIZE;
	tstat_total_size = TSTAT_INSTR_SIZE + tstat_data_size;
#else
	/*
	 * For sun4v, the tstat_data_t_size reflect the tstat_buffer
	 * output size based on tstat_data_t structure. For tlbstats
	 * collection, we use the internal tstat_tdata_t structure
	 * to collect the tlbstats for the pages. Therefore we
	 * need to adjust the size for the assertion.
	 */
	ASSERT((tstat_data_t_size - sizeof (tstat_data_t) +
	    sizeof (tstat_tdata_t)) <= TSTAT_DATA_SIZE);
#endif

	tstat_percpu = kmem_zalloc((max_cpuid + 1) *
	    sizeof (tstat_percpu_t), KM_SLEEP);

	/*
	 * Create our own arena backed by segkmem to assure a source of
	 * MMU_PAGESIZE-aligned allocations.  We allocate out of the
	 * heap32_arena to assure that we can address the allocated memory with
	 * a single sethi/simm13 pair in the interposing trap table entries.
	 */
	tstat_arena = vmem_create("trapstat", NULL, 0, MMU_PAGESIZE,
	    segkmem_alloc_permanent, segkmem_free, heap32_arena, 0, VM_SLEEP);

	tstat_enabled = kmem_alloc(TSTAT_TOTAL_NENT * sizeof (int), KM_SLEEP);
	tstat_buffer = kmem_alloc(tstat_data_t_size, KM_SLEEP);

	/*
	 * CB_CL_CPR_POST_USER is the class that executes from cpr_resume()
	 * after user threads can be restarted.  By executing in this class,
	 * we are assured of the availability of system services needed to
	 * resume trapstat (specifically, we are assured that all CPUs are
	 * restarted and responding to cross calls).
	 */
	tstat_cprcb =
	    callb_add(trapstat_cpr, NULL, CB_CL_CPR_POST_USER, "trapstat");

	return (DDI_SUCCESS);
}

static int
trapstat_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int rval;

	ASSERT(devi == tstat_devi);

	switch (cmd) {
	case DDI_DETACH:
		break;

	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	ASSERT(!tstat_running);

	rval = callb_delete(tstat_cprcb);
	ASSERT(rval == 0);

	kmem_free(tstat_buffer, tstat_data_t_size);
	kmem_free(tstat_enabled, TSTAT_TOTAL_NENT * sizeof (int));
	vmem_destroy(tstat_arena);
	kmem_free(tstat_percpu, (max_cpuid + 1) * sizeof (tstat_percpu_t));
	ddi_remove_minor_node(devi, NULL);

	return (DDI_SUCCESS);
}

/*
 * Configuration data structures
 */
static struct cb_ops trapstat_cb_ops = {
	trapstat_open,		/* open */
	trapstat_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	trapstat_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab */
	D_MP | D_NEW		/* Driver compatibility flag */
};

static struct dev_ops trapstat_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt */
	trapstat_info,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	trapstat_attach,	/* attach */
	trapstat_detach,	/* detach */
	nulldev,		/* reset */
	&trapstat_cb_ops,	/* cb_ops */
	(struct bus_ops *)0,	/* bus_ops */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"Trap Statistics 1.1",	/* name of module */
	&trapstat_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
