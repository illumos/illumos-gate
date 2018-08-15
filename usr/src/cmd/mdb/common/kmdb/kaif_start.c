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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * The main CPU-control loops, used to control masters and slaves.
 */

#include <sys/types.h>

#include <kmdb/kaif.h>
#include <kmdb/kaif_start.h>
#include <kmdb/kmdb_asmutil.h>
#include <kmdb/kmdb_dpi_impl.h>
#include <kmdb/kmdb_kdi.h>

#define	KAIF_SLAVE_CMD_SPIN	0
#define	KAIF_SLAVE_CMD_SWITCH	1
#define	KAIF_SLAVE_CMD_RESUME	2
#define	KAIF_SLAVE_CMD_FLUSH	3
#define	KAIF_SLAVE_CMD_REBOOT	4
#if defined(__sparc)
#define	KAIF_SLAVE_CMD_ACK	5
#endif


/*
 * Used to synchronize attempts to set kaif_master_cpuid.  kaif_master_cpuid may
 * be read without kaif_master_lock, and may be written by the current master
 * CPU.
 */
int kaif_master_cpuid = KAIF_MASTER_CPUID_UNSET;
static uintptr_t kaif_master_lock = 0;

/*
 * Used to ensure that all CPUs leave the debugger together. kaif_loop_lock must
 * be held to write kaif_looping, but need not be held to read it.
 */
static volatile uint_t kaif_looping;
static uintptr_t kaif_loop_lock;

static volatile int kaif_slave_cmd;
static volatile int kaif_slave_tgt;	/* target cpuid for CMD_SWITCH */

static void
kaif_lock_enter(uintptr_t *lock)
{
	while (cas(lock, 0, 1) != 0)
		continue;
	membar_producer();
}

static void
kaif_lock_exit(uintptr_t *lock)
{
	*lock = 0;
	membar_producer();
}

static void
kaif_start_slaves(int cmd)
{
	kaif_slave_cmd = cmd;
	kmdb_kdi_start_slaves();
}

static int
kaif_master_loop(kaif_cpusave_t *cpusave)
{
	int notflushed, i;

#if defined(__sparc)
	kaif_prom_rearm();
#endif
	kaif_trap_set_debugger();

	/*
	 * If we re-entered due to a ::switch, we need to tell the slave CPUs
	 * to sleep again.
	 */
	kmdb_kdi_stop_slaves(cpusave->krs_cpu_id, 0);

master_loop:
	switch (kmdb_dpi_reenter()) {
	case KMDB_DPI_CMD_SWITCH_CPU:
		/*
		 * We assume that the target CPU is a valid slave.  There's no
		 * easy way to complain here, so we'll assume that the caller
		 * has done the proper checking.
		 */
		if (kmdb_dpi_switch_target == cpusave->krs_cpu_id)
			break;

		kaif_slave_tgt = kaif_master_cpuid = kmdb_dpi_switch_target;
		cpusave->krs_cpu_state = KAIF_CPU_STATE_SLAVE;
		membar_producer();

		/*
		 * Switch back to the saved trap table before we switch CPUs --
		 * we need to make sure that only one CPU is on the debugger's
		 * table at a time.
		 */
		kaif_trap_set_saved(cpusave);

		kaif_start_slaves(KAIF_SLAVE_CMD_SWITCH);

		/* The new master is now awake */
		return (KAIF_CPU_CMD_SWITCH);

	case KMDB_DPI_CMD_RESUME_ALL:
	case KMDB_DPI_CMD_RESUME_UNLOAD:
		/*
		 * Resume everyone, clean up for next entry.
		 */
		kaif_master_cpuid = KAIF_MASTER_CPUID_UNSET;
		membar_producer();
		kaif_start_slaves(KAIF_SLAVE_CMD_RESUME);

		if (kmdb_dpi_work_required())
			kmdb_dpi_wrintr_fire();

		kaif_trap_set_saved(cpusave);

		return (KAIF_CPU_CMD_RESUME);

	case KMDB_DPI_CMD_RESUME_MASTER:
		/*
		 * Single-CPU resume, which is performed on the debugger's
		 * trap table (so no need to switch back).
		 */
		return (KAIF_CPU_CMD_RESUME_MASTER);

	case KMDB_DPI_CMD_FLUSH_CACHES:
		kaif_start_slaves(KAIF_SLAVE_CMD_FLUSH);

		/*
		 * Wait for the other cpus to finish flushing their caches.
		 */
		do {
			notflushed = 0;
			for (i = 0; i < kaif_ncpusave; i++) {
				kaif_cpusave_t *save = &kaif_cpusave[i];

				if (save->krs_cpu_state ==
				    KAIF_CPU_STATE_SLAVE &&
				    !save->krs_cpu_flushed) {
					notflushed++;
					break;
				}
			}
		} while (notflushed > 0);

		kaif_slave_cmd = KAIF_SLAVE_CMD_SPIN;
		break;

#if defined(__i386) || defined(__amd64)
	case KMDB_DPI_CMD_REBOOT:
		/*
		 * Reboot must be initiated by CPU 0.  I could ask why, but I'm
		 * afraid that I don't want to know the answer.
		 */
		if (cpusave->krs_cpu_id == 0)
			kmdb_kdi_reboot();

		kaif_start_slaves(KAIF_SLAVE_CMD_REBOOT);

		/*
		 * Spin forever, waiting for CPU 0 (apparently a slave) to
		 * reboot the system.
		 */
		for (;;)
			continue;

		/*NOTREACHED*/
		break;
#endif
	}

	goto master_loop;
}

static int
kaif_slave_loop(kaif_cpusave_t *cpusave)
{
	int slavecmd, rv;

#if defined(__sparc)
	/*
	 * If the user elects to drop to OBP from the debugger, some OBP
	 * implementations will cross-call the slaves.  We have to turn
	 * IE back on so we can receive the cross-calls.  If we don't,
	 * some OBP implementations will wait forever.
	 */
	interrupts_on();
#endif

	/* Wait for duty to call */
	for (;;) {
		slavecmd = kaif_slave_cmd;

		if (slavecmd == KAIF_SLAVE_CMD_SWITCH &&
		    kaif_slave_tgt == cpusave->krs_cpu_id) {
			kaif_slave_cmd = KAIF_SLAVE_CMD_SPIN;
			cpusave->krs_cpu_state = KAIF_CPU_STATE_MASTER;
			rv = KAIF_CPU_CMD_SWITCH;
			break;

		} else if (slavecmd == KAIF_SLAVE_CMD_FLUSH) {
			kmdb_kdi_flush_caches();
			cpusave->krs_cpu_flushed = 1;
			continue;

#if defined(__i386) || defined(__amd64)
		} else if (slavecmd == KAIF_SLAVE_CMD_REBOOT &&
		    cpusave->krs_cpu_id == 0) {
			rv = 0;
			kmdb_kdi_reboot();
			break;
#endif

		} else if (slavecmd == KAIF_SLAVE_CMD_RESUME) {
			rv = KAIF_CPU_CMD_RESUME;
			break;
#if defined(__sparc)
		} else if (slavecmd == KAIF_SLAVE_CMD_ACK) {
			cpusave->krs_cpu_acked = 1;
		} else if (cpusave->krs_cpu_acked &&
		    slavecmd == KAIF_SLAVE_CMD_SPIN) {
			cpusave->krs_cpu_acked = 0;
#endif
		}

		kmdb_kdi_slave_wait();
	}

#if defined(__sparc)
	interrupts_off();
#endif

	return (rv);
}

static void
kaif_select_master(kaif_cpusave_t *cpusave)
{
	kaif_lock_enter(&kaif_master_lock);

	if (kaif_master_cpuid == KAIF_MASTER_CPUID_UNSET) {
		/* This is the master. */
		kaif_master_cpuid = cpusave->krs_cpu_id;
		cpusave->krs_cpu_state = KAIF_CPU_STATE_MASTER;
		kaif_slave_cmd = KAIF_SLAVE_CMD_SPIN;

		membar_producer();

		kmdb_kdi_stop_slaves(cpusave->krs_cpu_id, 1);
	} else {
		/* The master was already chosen - go be a slave */
		cpusave->krs_cpu_state = KAIF_CPU_STATE_SLAVE;
		membar_producer();
	}

	kaif_lock_exit(&kaif_master_lock);
}

int
kaif_main_loop(kaif_cpusave_t *cpusave)
{
	int cmd;

	if (kaif_master_cpuid == KAIF_MASTER_CPUID_UNSET) {

		/*
		 * Special case: Unload requested before first debugger entry.
		 * Don't stop the world, as there's nothing to clean up that
		 * can't be handled by the running kernel.
		 */
		if (!kmdb_dpi_resume_requested &&
		    kmdb_kdi_get_unload_request()) {
			cpusave->krs_cpu_state = KAIF_CPU_STATE_NONE;
			return (KAIF_CPU_CMD_RESUME);
		}

		/*
		 * We're a slave with no master, so just resume.  This can
		 * happen if, prior to this, two CPUs both raced through
		 * kdi_cmnint() - for example, a breakpoint on a frequently
		 * called function.  The loser will be redirected to the slave
		 * loop; note that the event itself is lost at this point.
		 *
		 * The winner will then cross-call that slave, but it won't
		 * actually be received until the slave returns to the kernel
		 * and enables interrupts.  We'll then come back in via
		 * kdi_slave_entry() and hit this path.
		 */
		if (cpusave->krs_cpu_state == KAIF_CPU_STATE_SLAVE) {
			cpusave->krs_cpu_state = KAIF_CPU_STATE_NONE;
			return (KAIF_CPU_CMD_RESUME);
		}

		kaif_select_master(cpusave);

#ifdef __sparc
		if (kaif_master_cpuid == cpusave->krs_cpu_id) {
			/*
			 * Everyone has arrived, so we can disarm the post-PROM
			 * entry point.
			 */
			*kaif_promexitarmp = 0;
			membar_producer();
		}
#endif
	} else if (kaif_master_cpuid == cpusave->krs_cpu_id) {
		cpusave->krs_cpu_state = KAIF_CPU_STATE_MASTER;
	} else {
		cpusave->krs_cpu_state = KAIF_CPU_STATE_SLAVE;
	}

	cpusave->krs_cpu_flushed = 0;

	kaif_lock_enter(&kaif_loop_lock);
	kaif_looping++;
	kaif_lock_exit(&kaif_loop_lock);

	/*
	 * We know who the master and slaves are, so now they can go off
	 * to their respective loops.
	 */
	do {
		if (kaif_master_cpuid == cpusave->krs_cpu_id)
			cmd = kaif_master_loop(cpusave);
		else
			cmd = kaif_slave_loop(cpusave);
	} while (cmd == KAIF_CPU_CMD_SWITCH);

	kaif_lock_enter(&kaif_loop_lock);
	kaif_looping--;
	kaif_lock_exit(&kaif_loop_lock);

	cpusave->krs_cpu_state = KAIF_CPU_STATE_NONE;

	if (cmd == KAIF_CPU_CMD_RESUME) {
		/*
		 * By this point, the master has directed the slaves to resume,
		 * and everyone is making their way to this point.  We're going
		 * to block here until all CPUs leave the master and slave
		 * loops.  When all have arrived, we'll turn them all loose.
		 * This barrier is required for two reasons:
		 *
		 * 1. There exists a race condition whereby a CPU could reenter
		 *    the debugger while another CPU is still in the slave loop
		 *    from this debugger entry.  This usually happens when the
		 *    current master releases the slaves, and makes it back to
		 *    the world before the slaves notice the release.  The
		 *    former master then triggers a debugger entry, and attempts
		 *    to stop the slaves for this entry before they've even
		 *    resumed from the last one.  When the slaves arrive here,
		 *    they'll have re-disabled interrupts, and will thus ignore
		 *    cross-calls until they finish resuming.
		 *
		 * 2. At the time of this writing, there exists a SPARC bug that
		 *    causes an apparently unsolicited interrupt vector trap
		 *    from OBP to one of the slaves.  This wouldn't normally be
		 *    a problem but for the fact that the cross-called CPU
		 *    encounters some sort of failure while in OBP.  OBP
		 *    recovers by executing the debugger-hook word, which sends
		 *    the slave back into the debugger, triggering a debugger
		 *    fault.  This problem seems to only happen during resume,
		 *    the result being that all CPUs save for the cross-called
		 *    one make it back into the world, while the cross-called
		 *    one is stuck at the debugger fault prompt.  Leave the
		 *    world in that state too long, and you'll get a mondo
		 *    timeout panic.  If we hold everyone here, we can give the
		 *    the user a chance to trigger a panic for further analysis.
		 *    To trigger the bug, "pool_unlock:b :c" and "while : ; do
		 *    psrset -p ; done".
		 *
		 * When the second item is fixed, the barrier can move into
		 * kaif_select_master(), immediately prior to the setting of
		 * kaif_master_cpuid.
		 */
		while (kaif_looping != 0)
			continue;
	}

	return (cmd);
}


#if defined(__sparc)

static int slave_loop_barrier_failures = 0;	/* for debug */

/*
 * There exist a race condition observed by some
 * platforms where the kmdb master cpu exits to OBP via
 * prom_enter_mon (e.g. "$q" command) and then later re-enter
 * kmdb (typing "go") while the slaves are still proceeding
 * from the OBP idle-loop back to the kmdb slave loop. The
 * problem arises when the master cpu now back in kmdb proceed
 * to re-enter OBP (e.g. doing a prom_read() from the kmdb main
 * loop) while the slaves are still trying to get out of (the
 * previous trip in) OBP into the safety of the kmdb slave loop.
 * This routine forces the slaves to explicitly acknowledge
 * that they are back in the slave loop. The master cpu can
 * call this routine to ensure that all slave cpus are back
 * in the slave loop before proceeding.
 */
void
kaif_slave_loop_barrier(void)
{
	extern void kdi_usecwait(clock_t);
	int i;
	int not_acked;
	int timeout_count = 0;

	kaif_start_slaves(KAIF_SLAVE_CMD_ACK);

	/*
	 * Wait for slave cpus to explicitly acknowledge
	 * that they are spinning in the slave loop.
	 */
	do {
		not_acked = 0;
		for (i = 0; i < kaif_ncpusave; i++) {
			kaif_cpusave_t *save = &kaif_cpusave[i];

			if (save->krs_cpu_state ==
			    KAIF_CPU_STATE_SLAVE &&
			    !save->krs_cpu_acked) {
				not_acked++;
				break;
			}
		}

		if (not_acked == 0)
			break;

		/*
		 * Play it safe and do a timeout delay.
		 * We will do at most kaif_ncpusave delays before
		 * bailing out of this barrier.
		 */
		kdi_usecwait(200);

	} while (++timeout_count < kaif_ncpusave);

	if (not_acked > 0)
		/*
		 * we cannot establish a barrier with all
		 * the slave cpus coming back from OBP
		 * Record this fact for future debugging
		 */
		slave_loop_barrier_failures++;

	kaif_slave_cmd = KAIF_SLAVE_CMD_SPIN;
}
#endif
