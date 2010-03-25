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
/*
 * Copyright (c) 2009-2010, Intel Corporation.
 * All rights reserved.
 */

#include <sys/x86_archext.h>
#include <sys/machsystm.h>
#include <sys/x_call.h>
#include <sys/stat.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/cpu_acpi.h>
#include <sys/cpu_idle.h>
#include <sys/cpupm.h>
#include <sys/cpu_event.h>
#include <sys/hpet.h>
#include <sys/archsystm.h>
#include <vm/hat_i86.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>
#include <sys/callb.h>

#define	CSTATE_USING_HPET		1
#define	CSTATE_USING_LAT		2

#define	CPU_IDLE_STOP_TIMEOUT		1000

extern void cpu_idle_adaptive(void);
extern uint32_t cpupm_next_cstate(cma_c_state_t *cs_data,
    cpu_acpi_cstate_t *cstates, uint32_t cs_count, hrtime_t start);

static int cpu_idle_init(cpu_t *);
static void cpu_idle_fini(cpu_t *);
static void cpu_idle_stop(cpu_t *);
static boolean_t cpu_deep_idle_callb(void *arg, int code);
static boolean_t cpu_idle_cpr_callb(void *arg, int code);
static void acpi_cpu_cstate(cpu_acpi_cstate_t *cstate);

static boolean_t cstate_use_timer(hrtime_t *lapic_expire, int timer);

/*
 * the flag of always-running local APIC timer.
 * the flag of HPET Timer use in deep cstate.
 */
static boolean_t cpu_cstate_arat = B_FALSE;
static boolean_t cpu_cstate_hpet = B_FALSE;

/*
 * Interfaces for modules implementing Intel's deep c-state.
 */
cpupm_state_ops_t cpu_idle_ops = {
	"Generic ACPI C-state Support",
	cpu_idle_init,
	cpu_idle_fini,
	NULL,
	cpu_idle_stop
};

static kmutex_t		cpu_idle_callb_mutex;
static callb_id_t	cpu_deep_idle_callb_id;
static callb_id_t	cpu_idle_cpr_callb_id;
static uint_t		cpu_idle_cfg_state;

static kmutex_t cpu_idle_mutex;

cpu_idle_kstat_t cpu_idle_kstat = {
	{ "address_space_id",	KSTAT_DATA_STRING },
	{ "latency",		KSTAT_DATA_UINT32 },
	{ "power",		KSTAT_DATA_UINT32 },
};

/*
 * kstat update function of the c-state info
 */
static int
cpu_idle_kstat_update(kstat_t *ksp, int flag)
{
	cpu_acpi_cstate_t *cstate = ksp->ks_private;

	if (flag == KSTAT_WRITE) {
		return (EACCES);
	}

	if (cstate->cs_addrspace_id == ACPI_ADR_SPACE_FIXED_HARDWARE) {
		kstat_named_setstr(&cpu_idle_kstat.addr_space_id,
		"FFixedHW");
	} else if (cstate->cs_addrspace_id == ACPI_ADR_SPACE_SYSTEM_IO) {
		kstat_named_setstr(&cpu_idle_kstat.addr_space_id,
		"SystemIO");
	} else {
		kstat_named_setstr(&cpu_idle_kstat.addr_space_id,
		"Unsupported");
	}

	cpu_idle_kstat.cs_latency.value.ui32 = cstate->cs_latency;
	cpu_idle_kstat.cs_power.value.ui32 = cstate->cs_power;

	return (0);
}

/*
 * Used during configuration callbacks to manage implementation specific
 * details of the hardware timer used during Deep C-state.
 */
boolean_t
cstate_timer_callback(int code)
{
	if (cpu_cstate_arat) {
		return (B_TRUE);
	} else if (cpu_cstate_hpet) {
		return (hpet.callback(code));
	}
	return (B_FALSE);
}

/*
 * Some Local APIC Timers do not work during Deep C-states.
 * The Deep C-state idle function uses this function to ensure it is using a
 * hardware timer that works during Deep C-states.  This function also
 * switches the timer back to the LACPI Timer after Deep C-state.
 */
static boolean_t
cstate_use_timer(hrtime_t *lapic_expire, int timer)
{
	if (cpu_cstate_arat)
		return (B_TRUE);

	/*
	 * We have to return B_FALSE if no arat or hpet support
	 */
	if (!cpu_cstate_hpet)
		return (B_FALSE);

	switch (timer) {
	case CSTATE_USING_HPET:
		return (hpet.use_hpet_timer(lapic_expire));
	case CSTATE_USING_LAT:
		hpet.use_lapic_timer(*lapic_expire);
		return (B_TRUE);
	default:
		return (B_FALSE);
	}
}

/*
 * c-state wakeup function.
 * Similar to cpu_wakeup and cpu_wakeup_mwait except this function deals
 * with CPUs asleep in MWAIT, HLT, or ACPI Deep C-State.
 */
void
cstate_wakeup(cpu_t *cp, int bound)
{
	struct machcpu	*mcpu = &(cp->cpu_m);
	volatile uint32_t *mcpu_mwait = mcpu->mcpu_mwait;
	cpupart_t	*cpu_part;
	uint_t		cpu_found;
	processorid_t	cpu_sid;

	cpu_part = cp->cpu_part;
	cpu_sid = cp->cpu_seqid;
	/*
	 * Clear the halted bit for that CPU since it will be woken up
	 * in a moment.
	 */
	if (bitset_in_set(&cpu_part->cp_haltset, cpu_sid)) {
		/*
		 * Clear the halted bit for that CPU since it will be
		 * poked in a moment.
		 */
		bitset_atomic_del(&cpu_part->cp_haltset, cpu_sid);

		/*
		 * We may find the current CPU present in the halted cpuset
		 * if we're in the context of an interrupt that occurred
		 * before we had a chance to clear our bit in cpu_idle().
		 * Waking ourself is obviously unnecessary, since if
		 * we're here, we're not halted.
		 */
		if (cp != CPU) {
			/*
			 * Use correct wakeup mechanism
			 */
			if ((mcpu_mwait != NULL) &&
			    (*mcpu_mwait == MWAIT_HALTED))
				MWAIT_WAKEUP(cp);
			else
				poke_cpu(cp->cpu_id);
		}
		return;
	} else {
		/*
		 * This cpu isn't halted, but it's idle or undergoing a
		 * context switch. No need to awaken anyone else.
		 */
		if (cp->cpu_thread == cp->cpu_idle_thread ||
		    cp->cpu_disp_flags & CPU_DISP_DONTSTEAL)
			return;
	}

	/*
	 * No need to wake up other CPUs if the thread we just enqueued
	 * is bound.
	 */
	if (bound)
		return;


	/*
	 * See if there's any other halted CPUs. If there are, then
	 * select one, and awaken it.
	 * It's possible that after we find a CPU, somebody else
	 * will awaken it before we get the chance.
	 * In that case, look again.
	 */
	do {
		cpu_found = bitset_find(&cpu_part->cp_haltset);
		if (cpu_found == (uint_t)-1)
			return;

	} while (bitset_atomic_test_and_del(&cpu_part->cp_haltset,
	    cpu_found) < 0);

	/*
	 * Must use correct wakeup mechanism to avoid lost wakeup of
	 * alternate cpu.
	 */
	if (cpu_found != CPU->cpu_seqid) {
		mcpu_mwait = cpu_seq[cpu_found]->cpu_m.mcpu_mwait;
		if ((mcpu_mwait != NULL) && (*mcpu_mwait == MWAIT_HALTED))
			MWAIT_WAKEUP(cpu_seq[cpu_found]);
		else
			poke_cpu(cpu_seq[cpu_found]->cpu_id);
	}
}

/*
 * Function called by CPU idle notification framework to check whether CPU
 * has been awakened. It will be called with interrupt disabled.
 * If CPU has been awakened, call cpu_idle_exit() to notify CPU idle
 * notification framework.
 */
static void
acpi_cpu_mwait_check_wakeup(void *arg)
{
	volatile uint32_t *mcpu_mwait = (volatile uint32_t *)arg;

	ASSERT(arg != NULL);
	if (*mcpu_mwait != MWAIT_HALTED) {
		/*
		 * CPU has been awakened, notify CPU idle notification system.
		 */
		cpu_idle_exit(CPU_IDLE_CB_FLAG_IDLE);
	} else {
		/*
		 * Toggle interrupt flag to detect pending interrupts.
		 * If interrupt happened, do_interrupt() will notify CPU idle
		 * notification framework so no need to call cpu_idle_exit()
		 * here.
		 */
		sti();
		SMT_PAUSE();
		cli();
	}
}

static void
acpi_cpu_mwait_ipi_check_wakeup(void *arg)
{
	volatile uint32_t *mcpu_mwait = (volatile uint32_t *)arg;

	ASSERT(arg != NULL);
	if (*mcpu_mwait != MWAIT_WAKEUP_IPI) {
		/*
		 * CPU has been awakened, notify CPU idle notification system.
		 */
		cpu_idle_exit(CPU_IDLE_CB_FLAG_IDLE);
	} else {
		/*
		 * Toggle interrupt flag to detect pending interrupts.
		 * If interrupt happened, do_interrupt() will notify CPU idle
		 * notification framework so no need to call cpu_idle_exit()
		 * here.
		 */
		sti();
		SMT_PAUSE();
		cli();
	}
}

/*ARGSUSED*/
static void
acpi_cpu_check_wakeup(void *arg)
{
	/*
	 * Toggle interrupt flag to detect pending interrupts.
	 * If interrupt happened, do_interrupt() will notify CPU idle
	 * notification framework so no need to call cpu_idle_exit() here.
	 */
	sti();
	SMT_PAUSE();
	cli();
}

/*
 * enter deep c-state handler
 */
static void
acpi_cpu_cstate(cpu_acpi_cstate_t *cstate)
{
	volatile uint32_t	*mcpu_mwait = CPU->cpu_m.mcpu_mwait;
	cpu_t			*cpup = CPU;
	processorid_t		cpu_sid = cpup->cpu_seqid;
	cpupart_t		*cp = cpup->cpu_part;
	hrtime_t		lapic_expire;
	uint8_t			type = cstate->cs_addrspace_id;
	uint32_t		cs_type = cstate->cs_type;
	int			hset_update = 1;
	boolean_t		using_timer;
	cpu_idle_check_wakeup_t check_func = &acpi_cpu_check_wakeup;

	/*
	 * Set our mcpu_mwait here, so we can tell if anyone tries to
	 * wake us between now and when we call mwait.  No other cpu will
	 * attempt to set our mcpu_mwait until we add ourself to the haltset.
	 */
	if (mcpu_mwait) {
		if (type == ACPI_ADR_SPACE_SYSTEM_IO) {
			*mcpu_mwait = MWAIT_WAKEUP_IPI;
			check_func = &acpi_cpu_mwait_ipi_check_wakeup;
		} else {
			*mcpu_mwait = MWAIT_HALTED;
			check_func = &acpi_cpu_mwait_check_wakeup;
		}
	}

	/*
	 * If this CPU is online, and there are multiple CPUs
	 * in the system, then we should note our halting
	 * by adding ourselves to the partition's halted CPU
	 * bitmap. This allows other CPUs to find/awaken us when
	 * work becomes available.
	 */
	if (cpup->cpu_flags & CPU_OFFLINE || ncpus == 1)
		hset_update = 0;

	/*
	 * Add ourselves to the partition's halted CPUs bitmask
	 * and set our HALTED flag, if necessary.
	 *
	 * When a thread becomes runnable, it is placed on the queue
	 * and then the halted cpuset is checked to determine who
	 * (if anyone) should be awakened. We therefore need to first
	 * add ourselves to the halted cpuset, and and then check if there
	 * is any work available.
	 *
	 * Note that memory barriers after updating the HALTED flag
	 * are not necessary since an atomic operation (updating the bitmap)
	 * immediately follows. On x86 the atomic operation acts as a
	 * memory barrier for the update of cpu_disp_flags.
	 */
	if (hset_update) {
		cpup->cpu_disp_flags |= CPU_DISP_HALTED;
		bitset_atomic_add(&cp->cp_haltset, cpu_sid);
	}

	/*
	 * Check to make sure there's really nothing to do.
	 * Work destined for this CPU may become available after
	 * this check. We'll be notified through the clearing of our
	 * bit in the halted CPU bitmask, and a write to our mcpu_mwait.
	 *
	 * disp_anywork() checks disp_nrunnable, so we do not have to later.
	 */
	if (disp_anywork()) {
		if (hset_update) {
			cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
			bitset_atomic_del(&cp->cp_haltset, cpu_sid);
		}
		return;
	}

	/*
	 * We're on our way to being halted.
	 *
	 * The local APIC timer can stop in ACPI C2 and deeper c-states.
	 * Try to program the HPET hardware to substitute for this CPU's
	 * LAPIC timer.
	 * cstate_use_timer() could disable the LAPIC Timer.  Make sure
	 * to start the LAPIC Timer again before leaving this function.
	 *
	 * Disable interrupts here so we will awaken immediately after halting
	 * if someone tries to poke us between now and the time we actually
	 * halt.
	 */
	cli();
	using_timer = cstate_use_timer(&lapic_expire, CSTATE_USING_HPET);

	/*
	 * We check for the presence of our bit after disabling interrupts.
	 * If it's cleared, we'll return. If the bit is cleared after
	 * we check then the cstate_wakeup() will pop us out of the halted
	 * state.
	 *
	 * This means that the ordering of the cstate_wakeup() and the clearing
	 * of the bit by cpu_wakeup is important.
	 * cpu_wakeup() must clear our mc_haltset bit, and then call
	 * cstate_wakeup().
	 * acpi_cpu_cstate() must disable interrupts, then check for the bit.
	 */
	if (hset_update && bitset_in_set(&cp->cp_haltset, cpu_sid) == 0) {
		(void) cstate_use_timer(&lapic_expire,
		    CSTATE_USING_LAT);
		sti();
		cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
		return;
	}

	/*
	 * The check for anything locally runnable is here for performance
	 * and isn't needed for correctness. disp_nrunnable ought to be
	 * in our cache still, so it's inexpensive to check, and if there
	 * is anything runnable we won't have to wait for the poke.
	 */
	if (cpup->cpu_disp->disp_nrunnable != 0) {
		(void) cstate_use_timer(&lapic_expire,
		    CSTATE_USING_LAT);
		sti();
		if (hset_update) {
			cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
			bitset_atomic_del(&cp->cp_haltset, cpu_sid);
		}
		return;
	}

	if (using_timer == B_FALSE) {

		(void) cstate_use_timer(&lapic_expire,
		    CSTATE_USING_LAT);
		sti();

		/*
		 * We are currently unable to program the HPET to act as this
		 * CPU's proxy LAPIC timer.  This CPU cannot enter C2 or deeper
		 * because no timer is set to wake it up while its LAPIC timer
		 * stalls in deep C-States.
		 * Enter C1 instead.
		 *
		 * cstate_wake_cpu() will wake this CPU with an IPI which
		 * works with MWAIT.
		 */
		i86_monitor(mcpu_mwait, 0, 0);
		if ((*mcpu_mwait & ~MWAIT_WAKEUP_IPI) == MWAIT_HALTED) {
			if (cpu_idle_enter(IDLE_STATE_C1, 0,
			    check_func, (void *)mcpu_mwait) == 0) {
				if ((*mcpu_mwait & ~MWAIT_WAKEUP_IPI) ==
				    MWAIT_HALTED) {
					i86_mwait(0, 0);
				}
				cpu_idle_exit(CPU_IDLE_CB_FLAG_IDLE);
			}
		}

		/*
		 * We're no longer halted
		 */
		if (hset_update) {
			cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
			bitset_atomic_del(&cp->cp_haltset, cpu_sid);
		}
		return;
	}

	if (type == ACPI_ADR_SPACE_FIXED_HARDWARE) {
		/*
		 * We're on our way to being halted.
		 * To avoid a lost wakeup, arm the monitor before checking
		 * if another cpu wrote to mcpu_mwait to wake us up.
		 */
		i86_monitor(mcpu_mwait, 0, 0);
		if (*mcpu_mwait == MWAIT_HALTED) {
			if (cpu_idle_enter((uint_t)cs_type, 0,
			    check_func, (void *)mcpu_mwait) == 0) {
				if (*mcpu_mwait == MWAIT_HALTED) {
					i86_mwait(cstate->cs_address, 1);
				}
				cpu_idle_exit(CPU_IDLE_CB_FLAG_IDLE);
			}
		}
	} else if (type == ACPI_ADR_SPACE_SYSTEM_IO) {
		uint32_t value;
		ACPI_TABLE_FADT *gbl_FADT;

		if (*mcpu_mwait == MWAIT_WAKEUP_IPI) {
			if (cpu_idle_enter((uint_t)cs_type, 0,
			    check_func, (void *)mcpu_mwait) == 0) {
				if (*mcpu_mwait == MWAIT_WAKEUP_IPI) {
					(void) cpu_acpi_read_port(
					    cstate->cs_address, &value, 8);
					acpica_get_global_FADT(&gbl_FADT);
					(void) cpu_acpi_read_port(
					    gbl_FADT->XPmTimerBlock.Address,
					    &value, 32);
				}
				cpu_idle_exit(CPU_IDLE_CB_FLAG_IDLE);
			}
		}
	}

	/*
	 * The LAPIC timer may have stopped in deep c-state.
	 * Reprogram this CPU's LAPIC here before enabling interrupts.
	 */
	(void) cstate_use_timer(&lapic_expire, CSTATE_USING_LAT);
	sti();

	/*
	 * We're no longer halted
	 */
	if (hset_update) {
		cpup->cpu_disp_flags &= ~CPU_DISP_HALTED;
		bitset_atomic_del(&cp->cp_haltset, cpu_sid);
	}
}

/*
 * Idle the present CPU, deep c-state is supported
 */
void
cpu_acpi_idle(void)
{
	cpu_t *cp = CPU;
	cpu_acpi_handle_t handle;
	cma_c_state_t *cs_data;
	cpu_acpi_cstate_t *cstates;
	hrtime_t start, end;
	int cpu_max_cstates;
	uint32_t cs_indx;
	uint16_t cs_type;

	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	handle = mach_state->ms_acpi_handle;
	ASSERT(CPU_ACPI_CSTATES(handle) != NULL);

	cs_data = mach_state->ms_cstate.cma_state.cstate;
	cstates = (cpu_acpi_cstate_t *)CPU_ACPI_CSTATES(handle);
	ASSERT(cstates != NULL);
	cpu_max_cstates = cpu_acpi_get_max_cstates(handle);
	if (cpu_max_cstates > CPU_MAX_CSTATES)
		cpu_max_cstates = CPU_MAX_CSTATES;
	if (cpu_max_cstates == 1) {	/* no ACPI c-state data */
		(*non_deep_idle_cpu)();
		return;
	}

	start = gethrtime_unscaled();

	cs_indx = cpupm_next_cstate(cs_data, cstates, cpu_max_cstates, start);

	cs_type = cstates[cs_indx].cs_type;

	switch (cs_type) {
	default:
		/* FALLTHROUGH */
	case CPU_ACPI_C1:
		(*non_deep_idle_cpu)();
		break;

	case CPU_ACPI_C2:
		acpi_cpu_cstate(&cstates[cs_indx]);
		break;

	case CPU_ACPI_C3:
		/*
		 * All supported Intel processors maintain cache coherency
		 * during C3.  Currently when entering C3 processors flush
		 * core caches to higher level shared cache. The shared cache
		 * maintains state and supports probes during C3.
		 * Consequently there is no need to handle cache coherency
		 * and Bus Master activity here with the cache flush, BM_RLD
		 * bit, BM_STS bit, nor PM2_CNT.ARB_DIS mechanisms described
		 * in section 8.1.4 of the ACPI Specification 4.0.
		 */
		acpi_cpu_cstate(&cstates[cs_indx]);
		break;
	}

	end = gethrtime_unscaled();

	/*
	 * Update statistics
	 */
	cpupm_wakeup_cstate_data(cs_data, end);
}

boolean_t
cpu_deep_cstates_supported(void)
{
	extern int	idle_cpu_no_deep_c;

	if (idle_cpu_no_deep_c)
		return (B_FALSE);

	if (!cpuid_deep_cstates_supported())
		return (B_FALSE);

	if (cpuid_arat_supported()) {
		cpu_cstate_arat = B_TRUE;
		return (B_TRUE);
	}

	if ((hpet.supported == HPET_FULL_SUPPORT) &&
	    hpet.install_proxy()) {
		cpu_cstate_hpet = B_TRUE;
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Validate that this processor supports deep cstate and if so,
 * get the c-state data from ACPI and cache it.
 */
static int
cpu_idle_init(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;
	cpu_acpi_cstate_t *cstate;
	char name[KSTAT_STRLEN];
	int cpu_max_cstates, i;
	int ret;

	/*
	 * Cache the C-state specific ACPI data.
	 */
	if ((ret = cpu_acpi_cache_cstate_data(handle)) != 0) {
		if (ret < 0)
			cmn_err(CE_NOTE,
			    "!Support for CPU deep idle states is being "
			    "disabled due to errors parsing ACPI C-state "
			    "objects exported by BIOS.");
		cpu_idle_fini(cp);
		return (-1);
	}

	cstate = (cpu_acpi_cstate_t *)CPU_ACPI_CSTATES(handle);

	cpu_max_cstates = cpu_acpi_get_max_cstates(handle);

	for (i = CPU_ACPI_C1; i <= cpu_max_cstates; i++) {
		(void) snprintf(name, KSTAT_STRLEN - 1, "c%d", cstate->cs_type);
		/*
		 * Allocate, initialize and install cstate kstat
		 */
		cstate->cs_ksp = kstat_create("cstate", cp->cpu_id,
		    name, "misc",
		    KSTAT_TYPE_NAMED,
		    sizeof (cpu_idle_kstat) / sizeof (kstat_named_t),
		    KSTAT_FLAG_VIRTUAL);

		if (cstate->cs_ksp == NULL) {
			cmn_err(CE_NOTE, "kstat_create(c_state) fail");
		} else {
			cstate->cs_ksp->ks_data = &cpu_idle_kstat;
			cstate->cs_ksp->ks_lock = &cpu_idle_mutex;
			cstate->cs_ksp->ks_update = cpu_idle_kstat_update;
			cstate->cs_ksp->ks_data_size += MAXNAMELEN;
			cstate->cs_ksp->ks_private = cstate;
			kstat_install(cstate->cs_ksp);
		}
		cstate++;
	}

	cpupm_alloc_domains(cp, CPUPM_C_STATES);
	cpupm_alloc_ms_cstate(cp);

	if (cpu_deep_cstates_supported()) {
		uint32_t value;

		mutex_enter(&cpu_idle_callb_mutex);
		if (cpu_deep_idle_callb_id == (callb_id_t)0)
			cpu_deep_idle_callb_id = callb_add(&cpu_deep_idle_callb,
			    (void *)NULL, CB_CL_CPU_DEEP_IDLE, "cpu_deep_idle");
		if (cpu_idle_cpr_callb_id == (callb_id_t)0)
			cpu_idle_cpr_callb_id = callb_add(&cpu_idle_cpr_callb,
			    (void *)NULL, CB_CL_CPR_PM, "cpu_idle_cpr");
		mutex_exit(&cpu_idle_callb_mutex);


		/*
		 * All supported CPUs (Nehalem and later) will remain in C3
		 * during Bus Master activity.
		 * All CPUs set ACPI_BITREG_BUS_MASTER_RLD to 0 here if it
		 * is not already 0 before enabling Deeper C-states.
		 */
		cpu_acpi_get_register(ACPI_BITREG_BUS_MASTER_RLD, &value);
		if (value & 1)
			cpu_acpi_set_register(ACPI_BITREG_BUS_MASTER_RLD, 0);
	}

	return (0);
}

/*
 * Free resources allocated by cpu_idle_init().
 */
static void
cpu_idle_fini(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;
	cpu_acpi_cstate_t *cstate;
	uint_t	cpu_max_cstates, i;

	/*
	 * idle cpu points back to the generic one
	 */
	idle_cpu = cp->cpu_m.mcpu_idle_cpu = non_deep_idle_cpu;
	disp_enq_thread = non_deep_idle_disp_enq_thread;

	cstate = (cpu_acpi_cstate_t *)CPU_ACPI_CSTATES(handle);
	if (cstate) {
		cpu_max_cstates = cpu_acpi_get_max_cstates(handle);

		for (i = CPU_ACPI_C1; i <= cpu_max_cstates; i++) {
			if (cstate->cs_ksp != NULL)
				kstat_delete(cstate->cs_ksp);
			cstate++;
		}
	}

	cpupm_free_ms_cstate(cp);
	cpupm_free_domains(&cpupm_cstate_domains);
	cpu_acpi_free_cstate_data(handle);

	mutex_enter(&cpu_idle_callb_mutex);
	if (cpu_deep_idle_callb_id != (callb_id_t)0) {
		(void) callb_delete(cpu_deep_idle_callb_id);
		cpu_deep_idle_callb_id = (callb_id_t)0;
	}
	if (cpu_idle_cpr_callb_id != (callb_id_t)0) {
		(void) callb_delete(cpu_idle_cpr_callb_id);
		cpu_idle_cpr_callb_id = (callb_id_t)0;
	}
	mutex_exit(&cpu_idle_callb_mutex);
}

/*
 * This function is introduced here to solve a race condition
 * between the master and the slave to touch c-state data structure.
 * After the slave calls this idle function to switch to the non
 * deep idle function, the master can go on to reclaim the resource.
 */
static void
cpu_idle_stop_sync(void)
{
	/* switch to the non deep idle function */
	CPU->cpu_m.mcpu_idle_cpu = non_deep_idle_cpu;
}

static void
cpu_idle_stop(cpu_t *cp)
{
	cpupm_mach_state_t *mach_state =
	    (cpupm_mach_state_t *)(cp->cpu_m.mcpu_pm_mach_state);
	cpu_acpi_handle_t handle = mach_state->ms_acpi_handle;
	cpu_acpi_cstate_t *cstate;
	uint_t cpu_max_cstates, i = 0;

	mutex_enter(&cpu_idle_callb_mutex);
	if (idle_cpu == cpu_idle_adaptive) {
		/*
		 * invoke the slave to call synchronous idle function.
		 */
		cp->cpu_m.mcpu_idle_cpu = cpu_idle_stop_sync;
		poke_cpu(cp->cpu_id);

		/*
		 * wait until the slave switchs to non deep idle function,
		 * so that the master is safe to go on to reclaim the resource.
		 */
		while (cp->cpu_m.mcpu_idle_cpu != non_deep_idle_cpu) {
			drv_usecwait(10);
			if ((++i % CPU_IDLE_STOP_TIMEOUT) == 0)
				cmn_err(CE_NOTE, "!cpu_idle_stop: the slave"
				    " idle stop timeout");
		}
	}
	mutex_exit(&cpu_idle_callb_mutex);

	cstate = (cpu_acpi_cstate_t *)CPU_ACPI_CSTATES(handle);
	if (cstate) {
		cpu_max_cstates = cpu_acpi_get_max_cstates(handle);

		for (i = CPU_ACPI_C1; i <= cpu_max_cstates; i++) {
			if (cstate->cs_ksp != NULL)
				kstat_delete(cstate->cs_ksp);
			cstate++;
		}
	}
	cpupm_free_ms_cstate(cp);
	cpupm_remove_domains(cp, CPUPM_C_STATES, &cpupm_cstate_domains);
	cpu_acpi_free_cstate_data(handle);
}

/*ARGSUSED*/
static boolean_t
cpu_deep_idle_callb(void *arg, int code)
{
	boolean_t rslt = B_TRUE;

	mutex_enter(&cpu_idle_callb_mutex);
	switch (code) {
	case PM_DEFAULT_CPU_DEEP_IDLE:
		/*
		 * Default policy is same as enable
		 */
		/*FALLTHROUGH*/
	case PM_ENABLE_CPU_DEEP_IDLE:
		if ((cpu_idle_cfg_state & CPU_IDLE_DEEP_CFG) == 0)
			break;

		if (cstate_timer_callback(PM_ENABLE_CPU_DEEP_IDLE)) {
			disp_enq_thread = cstate_wakeup;
			idle_cpu = cpu_idle_adaptive;
			cpu_idle_cfg_state &= ~CPU_IDLE_DEEP_CFG;
		} else {
			rslt = B_FALSE;
		}
		break;

	case PM_DISABLE_CPU_DEEP_IDLE:
		if (cpu_idle_cfg_state & CPU_IDLE_DEEP_CFG)
			break;

		idle_cpu = non_deep_idle_cpu;
		if (cstate_timer_callback(PM_DISABLE_CPU_DEEP_IDLE)) {
			disp_enq_thread = non_deep_idle_disp_enq_thread;
			cpu_idle_cfg_state |= CPU_IDLE_DEEP_CFG;
		}
		break;

	default:
		cmn_err(CE_NOTE, "!cpu deep_idle_callb: invalid code %d\n",
		    code);
		break;
	}
	mutex_exit(&cpu_idle_callb_mutex);
	return (rslt);
}

/*ARGSUSED*/
static boolean_t
cpu_idle_cpr_callb(void *arg, int code)
{
	boolean_t rslt = B_TRUE;

	mutex_enter(&cpu_idle_callb_mutex);
	switch (code) {
	case CB_CODE_CPR_RESUME:
		if (cstate_timer_callback(CB_CODE_CPR_RESUME)) {
			/*
			 * Do not enable dispatcher hooks if disabled by user.
			 */
			if (cpu_idle_cfg_state & CPU_IDLE_DEEP_CFG)
				break;

			disp_enq_thread = cstate_wakeup;
			idle_cpu = cpu_idle_adaptive;
		} else {
			rslt = B_FALSE;
		}
		break;

	case CB_CODE_CPR_CHKPT:
		idle_cpu = non_deep_idle_cpu;
		disp_enq_thread = non_deep_idle_disp_enq_thread;
		(void) cstate_timer_callback(CB_CODE_CPR_CHKPT);
		break;

	default:
		cmn_err(CE_NOTE, "!cpudvr cpr_callb: invalid code %d\n", code);
		break;
	}
	mutex_exit(&cpu_idle_callb_mutex);
	return (rslt);
}

/*
 * handle _CST notification
 */
void
cpuidle_cstate_instance(cpu_t *cp)
{
#ifndef	__xpv
	cpupm_mach_state_t	*mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	cpu_acpi_handle_t	handle;
	struct machcpu		*mcpu;
	cpuset_t 		dom_cpu_set;
	kmutex_t		*pm_lock;
	int			result = 0;
	processorid_t		cpu_id;

	if (mach_state == NULL) {
		return;
	}

	ASSERT(mach_state->ms_cstate.cma_domain != NULL);
	dom_cpu_set = mach_state->ms_cstate.cma_domain->pm_cpus;
	pm_lock = &mach_state->ms_cstate.cma_domain->pm_lock;

	/*
	 * Do for all the CPU's in the domain
	 */
	mutex_enter(pm_lock);
	do {
		CPUSET_FIND(dom_cpu_set, cpu_id);
		if (cpu_id == CPUSET_NOTINSET)
			break;

		ASSERT(cpu_id >= 0 && cpu_id < NCPU);
		cp = cpu[cpu_id];
		mach_state = (cpupm_mach_state_t *)
		    cp->cpu_m.mcpu_pm_mach_state;
		if (!(mach_state->ms_caps & CPUPM_C_STATES)) {
			mutex_exit(pm_lock);
			return;
		}
		handle = mach_state->ms_acpi_handle;
		ASSERT(handle != NULL);

		/*
		 * re-evaluate cstate object
		 */
		if (cpu_acpi_cache_cstate_data(handle) != 0) {
			cmn_err(CE_WARN, "Cannot re-evaluate the cpu c-state"
			    " object Instance: %d", cpu_id);
		}
		mcpu = &(cp->cpu_m);
		mcpu->max_cstates = cpu_acpi_get_max_cstates(handle);
		if (mcpu->max_cstates > CPU_ACPI_C1) {
			(void) cstate_timer_callback(
			    CST_EVENT_MULTIPLE_CSTATES);
			disp_enq_thread = cstate_wakeup;
			cp->cpu_m.mcpu_idle_cpu = cpu_acpi_idle;
		} else if (mcpu->max_cstates == CPU_ACPI_C1) {
			disp_enq_thread = non_deep_idle_disp_enq_thread;
			cp->cpu_m.mcpu_idle_cpu = non_deep_idle_cpu;
			(void) cstate_timer_callback(CST_EVENT_ONE_CSTATE);
		}

		CPUSET_ATOMIC_XDEL(dom_cpu_set, cpu_id, result);
	} while (result < 0);
	mutex_exit(pm_lock);
#endif
}

/*
 * handle the number or the type of available processor power states change
 */
void
cpuidle_manage_cstates(void *ctx)
{
	cpu_t			*cp = ctx;
	cpupm_mach_state_t	*mach_state =
	    (cpupm_mach_state_t *)cp->cpu_m.mcpu_pm_mach_state;
	boolean_t		is_ready;

	if (mach_state == NULL) {
		return;
	}

	/*
	 * We currently refuse to power manage if the CPU is not ready to
	 * take cross calls (cross calls fail silently if CPU is not ready
	 * for it).
	 *
	 * Additionally, for x86 platforms we cannot power manage an instance,
	 * until it has been initialized.
	 */
	is_ready = (cp->cpu_flags & CPU_READY) && cpupm_cstate_ready(cp);
	if (!is_ready)
		return;

	cpuidle_cstate_instance(cp);
}
