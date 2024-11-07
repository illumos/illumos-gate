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
 *
 * Copyright 2024 Oxide Computer Company
 */

/*
 * AMD-specific CPU power management support.
 *
 * And, a brief history of AMD CPU power management. Or, "Why you care about CPU
 * power management even when you are not worried about a few watts from the
 * wall." This history is intended to provide lodestones for this domain, but is
 * not a fully comprehensive AMD power management feature chronology.
 *
 * In the early 2000s, AMD shipped a feature called PowerNow! in the K6 era -
 * K6-2E+ and K6-III+ cores, according to "AMD PowerNow! Technology Dynamically
 * Manages Power and Performance", publication number 24404A. This feature
 * allowed operating systems to control power and performance settings in a way
 * that is very similar to ACPI P-states. That is, selectable core voltage and
 * frequency levels, with default "power-saver" and "high-performance" modes
 * that are reflective of Pmin and Pmax on a 2024-era AMD processor.
 *
 * With Thuban and Zosma parts later in the K10 era, AMD extended power and
 * frequency management with the "Turbo Core" feature. They talk about this in
 * more detail in blogs about the Bulldozer architecture, though many materials
 * are now dead links. Exactly how Turbo Core is informed and managed is less
 * discussed, or at least I have been unable to find good technical material on
 * the topic, but we can draw some inferences from what *is* discussed with
 * those Bulldozer cores:
 * * introduces the notion of boosting all cores beyond a "base frequency"
 * * introduces the notion of boosting further with only half or fewer cores
 * active
 * * introduces the notion of power-governed turbo boost
 *
 * Somewhere in the K10 era, AMD also introduced C-state support, allowing cores
 * to be put into low-power idle states when not used. Some articles from
 * reviewers and system integrators around this time indicate that setting the
 * "C-state mode to C6" is "required to get the highest Turbo Core frequencies."
 *
 * As the AMD 15h BIOS and Kernel Developers Guide (BKDG) is clear to note, AMD
 * C-states do not directly correspond to ACPI C-states. But when an ACPI
 * low-power C-state is entered, the CPU's low-power implementation is one of
 * these AMD C-states, and C6 is the lowest-power of them.
 *
 * Further, note that in the Bulldozer era, CPUs were in the range of 4-8 cores,
 * so "half or fewer cores" means "2-4 active cores."
 *
 * At this point and onwards, for some families of AMD parts, best single-core
 * performance can only be achieved if an operating system parks idle CPU cores
 * in the lowest-power states - AMD's C6, aka ACPI C3.
 *
 * Boosting beyond a base clock, in a AMD-defined and approved manner,
 * potentially on all cores, has since also been branded as "AMD Core
 * Performance Boost." This is the name you can find this behavior known as in
 * Zen and later parts.
 *
 * Zen included a more expansive power management approach, "Precision Boost."
 * "Precision Boost" is where we see start to see power management more
 * explicitly *managed* - core clocks and voltages are decided by some software
 * running on the new System Management Unit (SMU). Correspondingly, exactly
 * what voltage/termperature/power inputs will produce what operational outcomes
 * from the processor become less and less clearly documented.
 *
 * For example, a (Zen 1) Ryzen 7 1700 part is labeled as 3.0GHz base clock,
 * with up to 3.8GHz boost clock. This 800MHz gamut is the purview of the SMU
 * implementing "Precision Boost."
 *
 * In practice, later AMD marketing material implies that Precision Boost
 * retained "Turbo Core" behavior that peak boost frequences are only attainable
 * when one or two cores are actually active. Additionally, even if all cores
 * are loaded, Precision Boost provides some amount of boost if thermal and
 * power headroom allows.
 *
 * Taking the above Ryzen 7 1700 part as an example, the "base clock" of 3.0 GHz
 * is relatively unlikely to be an actual operational frequency of the part.
 * Either a core will be off (as in AMD-defined C1 or C6), on in a low-power
 * P-state (the processor's minimum operational frequency, probably P1 or
 * whatever Pmin the part supports), or on in a high-power P-state (P0). In the
 * high-power P-state, if "boost above base clock" feature is enabled, a core
 * will probably be some hundreds of MHz above its requested clock speed!
 *
 * Further, somewhere around the Zen architecture AMD introduced the "Extended
 * Frequency Range" (XFR) feature, which allows the processor to clock
 * 100-150MHz (depending on SKU) higher than "max turbo." This is still
 * constrained by the silicon, power, and thermal limits indicated by a
 * combination of fused values set at fabrication time, platform firmware, and
 * potentially user customization (if firmware allows). Specifics here are
 * still slim pickings.
 *
 * Forum-goers in 2018 would discuss their Ryzen 7 1700s having a clock speed of
 * 3.1-3.2GHz under all-core load, going up to 3.7GHz under one- or two-core
 * loads. All frequency selection in this range is up to the SMU, potentially
 * capped by BIOS or OS-provided parameters.
 *
 * As of Zen 5, the latest development here is "Precision Boost 2", which began
 * shipping with Zen 2. This seems to be an upgrade of the power/frequency
 * selection regime used by the SMU - instead of "all-core" and "low-core"
 * turbos, the processor measures its utilization of system-specific paramters
 * such as package temperature and power draw. Exactly how frequency choices are
 * made at this point appears to be a black box, other than blanket statements
 * like "the processor will pick the highest permissible frequency given its
 * operating environment."
 *
 * An interesting detail in the marketing material and slide decks surrounding
 * the introduction of Precision Boost 2.0 is an implicit confirmation that
 * Precision Boost did maintain a strict "all-core" and "low-core" pair of
 * frequencies. This comes from the marketing statement that Precision Boost 2.0
 * has done away with those concepts from previous generations, instead
 * providing a "linear scaling" of frequencies under increasing load levels.
 *
 * This brings us to 2024; empirically the above blanket statements are only
 * correct given the operating system managing CPU cores in a way roughly
 * commensurate with how AMD would expect an operating system to manage them.
 *
 * This is especially dramatic on AMD's server parts - Naples, Rome, Milan, and
 * onward - where with all cores in high-power C-states, but possibly low-power
 * P-states, still prevent individual cores from boosting closer to a part's
 * Fmax. The difference between a peak clock without C-state management, and
 * peak clock with C-state management, can be as much as 20% of a part's Fmax.
 * This has also been seen on Threadripper systems. But the impact of C-state
 * management seems much less dramatic on "desktop" parts; a 7950x without
 * C-state management can see individual cores clocking to 5.4 GHz or above,
 * much closer to its rated Fmax of 5.75 GHz.
 *
 * From empirical measurement, the difference here appears to be an undocumented
 * "all-core" turbo that the part limits itself to if all cores are in C0, even
 * if they are in C0 but in Pmax and stopped in hlt/mwait idle - the actual
 * power draw differences between these states may be small, but simply being
 * powered seems to trip some threshold.
 *
 * One conclusion from all this is that across the board, C-state management can
 * have a surprising relationship to performance. Unfortunately, the direct
 * relationships are undocumented. We are entirely dependent on ACPI-provided
 * latency information to decide if C-state transitions are profitable given
 * instantaneous workloads and performance needs.
 *
 * Finally, CPPC (Collaborative Processor Performance Control) is a feature
 * that currently seems to be more oriented towards desktop enthusiast parts,
 * but stretches the above even further. CPPC includes an abstract "performance
 * scale" a processor supports, where the operating system requests some factor
 * along this scale based on workloads it must run. CPPC also introduces the
 * idea of "Preferred Cores", where at manufacturing time individual cores in a
 * die are fused with information indicating how highly they can be driven.
 * This is reportedly reflected as higher peak clocks under load, lower voltage
 * (and less power) at intermediate clocks.
 *
 * It would be nice, in the limit of time, to find if a given processor supports
 * CPPC, collect its preferred cores, and prefer scheduling tasks on those cores
 * if they are not already busy. This extends somewhat beyond simply managing
 * power states of loaded cores.
 */

#include <sys/x86_archext.h>
#include <sys/cpu_acpi.h>
#include <sys/cpu_idle.h>
#include <sys/pwrnow.h>

boolean_t
cpupm_amd_init(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);

	/* AMD or Hygon? */
	if (x86_vendor != X86_VENDOR_AMD &&
	    x86_vendor != X86_VENDOR_HYGON)
		return (B_FALSE);

	/*
	 * If we support PowerNow! on this processor, then set the
	 * correct cma_ops for the processor.
	 */
	mach_state->ms_pstate.cma_ops = pwrnow_supported() ?
	    &pwrnow_ops : NULL;

	/*
	 * AMD systems may support C-states, so optimistically set cma_ops to
	 * drive C-states. If the system does not *actually* support C-states,
	 * ACPI tables will not include _CST objects and `cpus_init` will fail.
	 * This, in turn, will cause `cpupm_init` to reset idle handling to not
	 * use C-states including clearing `ms_cstate.cma_ops`.
	 */
	mach_state->ms_cstate.cma_ops = &cpu_idle_ops;

	return (B_TRUE);
}
