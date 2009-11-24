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

#include <sys/mutex.h>
#include <sys/cpuvar.h>
#include <sys/cyclic.h>
#include <sys/disp.h>
#include <sys/ddi.h>
#include <sys/wdt.h>
#include <sys/callb.h>
#include <sys/cmn_err.h>
#include <sys/hypervisor_api.h>
#include <sys/membar.h>
#include <sys/x_call.h>
#include <sys/promif.h>
#include <sys/systm.h>
#include <sys/mach_descrip.h>
#include <sys/cpu_module.h>
#include <sys/pg.h>
#include <sys/lgrp.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/cpupart.h>
#include <sys/hsvc.h>

/*
 * Sun4v OS Suspend
 *
 * Provides a means to suspend a sun4v guest domain by pausing CPUs and then
 * calling into the HV to initiate a suspension. Suspension is sequenced
 * externally by calling suspend_pre, suspend_start, and suspend_post.
 * suspend_pre and suspend_post are meant to perform any special operations
 * that should be done before or after a suspend/resume operation. e.g.,
 * callbacks to cluster software to disable heartbeat monitoring before the
 * system is suspended. suspend_start prepares kernel services to be suspended
 * and then suspends the domain by calling hv_guest_suspend.
 *
 * Special Handling for %tick and %stick Registers
 *
 * After a suspend/resume operation, the %tick and %stick registers may have
 * jumped forwards or backwards. The delta is assumed to be consistent across
 * all CPUs, within the negligible level of %tick and %stick variation
 * acceptable on a cold boot. In order to maintain increasing %tick and %stick
 * counter values without exposing large positive or negative jumps to kernel
 * or user code, a %tick and %stick offset is used. Kernel reads of these
 * counters return the sum of the hardware register counter and offset
 * variable. After a suspend/resume operation, user reads of %tick or %stick
 * are emulated. Suspend code enables emulation by setting the
 * %{tick,stick}.NPT fields which trigger a privileged instruction access
 * trap whenever the registers are read from user mode. If emulation has been
 * enabled, the trap handler emulates the instruction. Emulation is only
 * enabled during a successful suspend/resume operation. When emulation is
 * enabled, CPUs that are DR'd into the system will have their
 * %{tick,stick}.NPT bits set to 1 as well.
 */

extern u_longlong_t gettick(void);	/* returns %stick */
extern uint64_t gettick_counter(void);	/* returns %tick */
extern uint64_t gettick_npt(void);
extern uint64_t getstick_npt(void);
extern int mach_descrip_update(void);
extern cpuset_t cpu_ready_set;
extern uint64_t native_tick_offset;
extern uint64_t native_stick_offset;

/*
 * Global Sun Cluster pre/post callbacks.
 */
const char *(*cl_suspend_error_decode)(int);
int (*cl_suspend_pre_callback)(void);
int (*cl_suspend_post_callback)(void);
#define	SC_PRE_FAIL_STR_FMT	"Sun Cluster pre-suspend failure: %d"
#define	SC_POST_FAIL_STR_FMT	"Sun Cluster post-suspend failure: %d"
#define	SC_FAIL_STR_MAX		256

/*
 * The minimum major and minor version of the HSVC_GROUP_CORE API group
 * required in order to use OS suspend.
 */
#define	SUSPEND_CORE_MAJOR	1
#define	SUSPEND_CORE_MINOR	2

/*
 * By default, sun4v OS suspend is supported if the required HV version
 * is present. suspend_disabled should be set on platforms that do not
 * allow OS suspend regardless of whether or not the HV supports it.
 * It can also be set in /etc/system.
 */
static int suspend_disabled = 0;

/*
 * Controls whether or not user-land tick and stick register emulation
 * will be enabled following a successful suspend operation.
 */
static int enable_user_tick_stick_emulation = 1;

/*
 * Indicates whether or not tick and stick emulation is currently active.
 * After a successful suspend operation, if emulation is enabled, this
 * variable is set to B_TRUE. Global scope to allow emulation code to
 * check if emulation is active.
 */
boolean_t tick_stick_emulation_active = B_FALSE;

/*
 * Controls whether or not MD information is refreshed after a
 * successful suspend and resume. When non-zero, after a successful
 * suspend and resume, the MD will be downloaded, cpunodes updated,
 * and processor grouping information recalculated.
 */
static int suspend_update_cpu_mappings = 1;

/*
 * DBG and DBG_PROM() macro.
 */
#ifdef	DEBUG

static int suspend_debug_flag = 0;

#define	DBG_PROM		\
if (suspend_debug_flag)		\
	prom_printf

#define	DBG			\
if (suspend_debug_flag)		\
	suspend_debug

static void
suspend_debug(const char *fmt, ...)
{
	char	buf[512];
	va_list	ap;

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	cmn_err(CE_NOTE, "%s", buf);
}

#else /* DEBUG */

#define	DBG_PROM
#define	DBG

#endif /* DEBUG */

/*
 * Return true if the HV supports OS suspend and if suspend has not been
 * disabled on this platform.
 */
boolean_t
suspend_supported(void)
{
	uint64_t major, minor;

	if (suspend_disabled)
		return (B_FALSE);

	if (hsvc_version(HSVC_GROUP_CORE, &major, &minor) != 0)
		return (B_FALSE);

	return ((major == SUSPEND_CORE_MAJOR && minor >= SUSPEND_CORE_MINOR) ||
	    (major > SUSPEND_CORE_MAJOR));
}

/*
 * Given a source tick and stick value, set the tick and stick offsets such
 * that the (current physical register value + offset == source value).
 */
static void
set_tick_offsets(uint64_t source_tick, uint64_t source_stick)
{
	uint64_t target_tick;
	uint64_t target_stick;

	native_tick_offset = 0;
	native_stick_offset = 0;

	target_tick = gettick_counter();	/* returns %tick */
	target_stick = gettick();		/* returns %stick */

	native_tick_offset = source_tick - target_tick;
	native_stick_offset = source_stick - target_stick;
}

/*
 * Set the {tick,stick}.NPT field to 1 on this CPU.
 */
static void
enable_tick_stick_npt(void)
{
	hv_stick_set_npt(1);
	hv_tick_set_npt(1);
}

/*
 * Synchronize a CPU's {tick,stick}.NPT fields with the current state
 * of the system. This is used when a CPU is DR'd into the system.
 */
void
suspend_sync_tick_stick_npt(void)
{
	if (tick_stick_emulation_active) {
		DBG("enabling {%%tick/%%stick}.NPT on CPU 0x%x", CPU->cpu_id);
		hv_stick_set_npt(1);
		hv_tick_set_npt(1);
	} else {
		ASSERT(gettick_npt() == 0);
		ASSERT(getstick_npt() == 0);
	}
}

/*
 * Obtain an updated MD from the hypervisor and update cpunodes, CPU HW
 * sharing data structures, and processor groups.
 */
static void
update_cpu_mappings(void)
{
	md_t		*mdp;
	processorid_t	id;
	cpu_t		*cp;
	int		rv;
	cpu_pg_t	*pgps[NCPU];

	/* Download the latest MD */
	if ((rv = mach_descrip_update()) != 0) {
		DBG("suspend: mach_descrip_update error: %d", rv);
		return;
	}

	if ((mdp = md_get_handle()) == NULL) {
		DBG("suspend: md_get_handle failed");
		return;
	}

	DBG("suspend: updating CPU mappings");

	mutex_enter(&cpu_lock);

	setup_chip_mappings(mdp);
	setup_exec_unit_mappings(mdp);
	for (id = 0; id < NCPU; id++) {
		if ((cp = cpu_get(id)) == NULL)
			continue;
		cpu_map_exec_units(cp);
	}

	/*
	 * Re-calculate processor groups.
	 *
	 * First tear down all PG information before adding any new PG
	 * information derived from the MD we just downloaded. We must
	 * call pg_cpu_inactive and pg_cpu_active with CPUs paused and
	 * we want to minimize the number of times pause_cpus is called.
	 * Inactivating all CPUs would leave PGs without any active CPUs,
	 * so while CPUs are paused, call pg_cpu_inactive and swap in the
	 * bootstrap PG structure saving the original PG structure to be
	 * fini'd afterwards. This prevents the dispatcher from encountering
	 * PGs in which all CPUs are inactive.
	 */
	pause_cpus(NULL);
	for (id = 0; id < NCPU; id++) {
		if ((cp = cpu_get(id)) == NULL)
			continue;
		pg_cpu_inactive(cp);
		pgps[id] = cp->cpu_pg;
		pg_cpu_bootstrap(cp);
	}
	start_cpus();

	/*
	 * pg_cpu_fini* and pg_cpu_init* must be called while CPUs are
	 * not paused. Use two separate loops here so that we do not
	 * initialize PG data for CPUs until all the old PG data structures
	 * are torn down.
	 */
	for (id = 0; id < NCPU; id++) {
		if ((cp = cpu_get(id)) == NULL)
			continue;
		pg_cpu_fini(cp, pgps[id]);
	}

	/*
	 * Initialize PG data for each CPU, but leave the bootstrapped
	 * PG structure in place to avoid running with any PGs containing
	 * nothing but inactive CPUs.
	 */
	for (id = 0; id < NCPU; id++) {
		if ((cp = cpu_get(id)) == NULL)
			continue;
		pgps[id] = pg_cpu_init(cp, B_TRUE);
	}

	/*
	 * Now that PG data has been initialized for all CPUs in the
	 * system, replace the bootstrapped PG structure with the
	 * initialized PG structure and call pg_cpu_active for each CPU.
	 */
	pause_cpus(NULL);
	for (id = 0; id < NCPU; id++) {
		if ((cp = cpu_get(id)) == NULL)
			continue;
		cp->cpu_pg = pgps[id];
		pg_cpu_active(cp);
	}
	start_cpus();

	mutex_exit(&cpu_lock);

	(void) md_fini_handle(mdp);
}

/*
 * Wrapper for the Sun Cluster error decoding function.
 */
static int
cluster_error_decode(int error, char *error_reason, size_t max_reason_len)
{
	const char	*decoded;
	size_t		decoded_len;

	ASSERT(error_reason != NULL);
	ASSERT(max_reason_len > 0);

	max_reason_len = MIN(max_reason_len, SC_FAIL_STR_MAX);

	if (cl_suspend_error_decode == NULL)
		return (-1);

	if ((decoded = (*cl_suspend_error_decode)(error)) == NULL)
		return (-1);

	/* Get number of non-NULL bytes */
	if ((decoded_len = strnlen(decoded, max_reason_len - 1)) == 0)
		return (-1);

	bcopy(decoded, error_reason, decoded_len);

	/*
	 * The error string returned from cl_suspend_error_decode
	 * should be NULL-terminated, but set the terminator here
	 * because we only copied non-NULL bytes. If the decoded
	 * string was not NULL-terminated, this guarantees that
	 * error_reason will be.
	 */
	error_reason[decoded_len] = '\0';

	return (0);
}

/*
 * Wrapper for the Sun Cluster pre-suspend callback.
 */
static int
cluster_pre_wrapper(char *error_reason, size_t max_reason_len)
{
	int rv = 0;

	if (cl_suspend_pre_callback != NULL) {
		rv = (*cl_suspend_pre_callback)();
		DBG("suspend: cl_suspend_pre_callback returned %d", rv);
		if (rv != 0 && error_reason != NULL && max_reason_len > 0) {
			if (cluster_error_decode(rv, error_reason,
			    max_reason_len)) {
				(void) snprintf(error_reason, max_reason_len,
				    SC_PRE_FAIL_STR_FMT, rv);
			}
		}
	}

	return (rv);
}

/*
 * Wrapper for the Sun Cluster post-suspend callback.
 */
static int
cluster_post_wrapper(char *error_reason, size_t max_reason_len)
{
	int rv = 0;

	if (cl_suspend_post_callback != NULL) {
		rv = (*cl_suspend_post_callback)();
		DBG("suspend: cl_suspend_post_callback returned %d", rv);
		if (rv != 0 && error_reason != NULL && max_reason_len > 0) {
			if (cluster_error_decode(rv, error_reason,
			    max_reason_len)) {
				(void) snprintf(error_reason,
				    max_reason_len, SC_POST_FAIL_STR_FMT, rv);
			}
		}
	}

	return (rv);
}

/*
 * Execute pre-suspend callbacks preparing the system for a suspend operation.
 * Returns zero on success, non-zero on failure. Sets the recovered argument
 * to indicate whether or not callbacks could be undone in the event of a
 * failure--if callbacks were successfully undone, *recovered is set to B_TRUE,
 * otherwise *recovered is set to B_FALSE. Must be called successfully before
 * suspend_start can be called. Callers should first call suspend_support to
 * determine if OS suspend is supported.
 */
int
suspend_pre(char *error_reason, size_t max_reason_len, boolean_t *recovered)
{
	int rv;

	ASSERT(recovered != NULL);

	/*
	 * Return an error if suspend_pre is erreoneously called
	 * when OS suspend is not supported.
	 */
	ASSERT(suspend_supported());
	if (!suspend_supported()) {
		DBG("suspend: suspend_pre called without suspend support");
		*recovered = B_TRUE;
		return (ENOTSUP);
	}
	DBG("suspend: %s", __func__);

	rv = cluster_pre_wrapper(error_reason, max_reason_len);

	/*
	 * At present, only one pre-suspend operation exists.
	 * If it fails, no recovery needs to be done.
	 */
	if (rv != 0 && recovered != NULL)
		*recovered = B_TRUE;

	return (rv);
}

/*
 * Execute post-suspend callbacks. Returns zero on success, non-zero on
 * failure. Must be called after suspend_start is called, regardless of
 * whether or not suspend_start is successful.
 */
int
suspend_post(char *error_reason, size_t max_reason_len)
{
	ASSERT(suspend_supported());
	DBG("suspend: %s", __func__);
	return (cluster_post_wrapper(error_reason, max_reason_len));
}

/*
 * Suspends the OS by pausing CPUs and calling into the HV to initiate
 * the suspend. When the HV routine hv_guest_suspend returns, the system
 * will be resumed. Must be called after a successful call to suspend_pre.
 * suspend_post must be called after suspend_start, whether or not
 * suspend_start returns an error.
 */
/*ARGSUSED*/
int
suspend_start(char *error_reason, size_t max_reason_len)
{
	uint64_t	source_tick;
	uint64_t	source_stick;
	uint64_t	rv;
	timestruc_t	source_tod;
	int		spl;

	ASSERT(suspend_supported());
	DBG("suspend: %s", __func__);

	mutex_enter(&cpu_lock);

	/* Suspend the watchdog */
	watchdog_suspend();

	/* Record the TOD */
	mutex_enter(&tod_lock);
	source_tod = tod_get();
	mutex_exit(&tod_lock);

	/* Pause all other CPUs */
	pause_cpus(NULL);
	DBG_PROM("suspend: CPUs paused\n");

	/* Suspend cyclics and disable interrupts */
	cyclic_suspend();
	DBG_PROM("suspend: cyclics suspended\n");
	spl = spl8();

	source_tick = gettick_counter();
	source_stick = gettick();
	DBG_PROM("suspend: source_tick: 0x%lx\n", source_tick);
	DBG_PROM("suspend: source_stick: 0x%lx\n", source_stick);

	/*
	 * Call into the HV to initiate the suspend.
	 * hv_guest_suspend() returns after the guest has been
	 * resumed or if the suspend operation failed or was
	 * cancelled. After a successful suspend, the %tick and
	 * %stick registers may have changed by an amount that is
	 * not proportional to the amount of time that has passed.
	 * They may have jumped forwards or backwards. This jump
	 * must be uniform across all CPUs and we operate under
	 * the assumption that it is (maintaining two global offset
	 * variables--one for %tick and one for %stick.)
	 */
	DBG_PROM("suspend: suspending... \n");
	rv = hv_guest_suspend();
	if (rv != 0) {
		splx(spl);
		cyclic_resume();
		start_cpus();
		watchdog_resume();
		mutex_exit(&cpu_lock);
		DBG("suspend: failed, rv: %ld\n", rv);
		return (rv);
	}

	/* Update the global tick and stick offsets */
	set_tick_offsets(source_tick, source_stick);

	/* Ensure new offsets are globally visible before resuming CPUs */
	membar_sync();

	/* Enable interrupts */
	splx(spl);

	/* Set the {%tick,%stick}.NPT bits on all CPUs */
	if (enable_user_tick_stick_emulation) {
		xc_all((xcfunc_t *)enable_tick_stick_npt, NULL, NULL);
		xt_sync(cpu_ready_set);
		ASSERT(gettick_npt() != 0);
		ASSERT(getstick_npt() != 0);
	}

	/* If emulation is enabled, but not currently active, enable it */
	if (enable_user_tick_stick_emulation && !tick_stick_emulation_active) {
		tick_stick_emulation_active = B_TRUE;
	}

	/* Resume cyclics, unpause CPUs */
	cyclic_resume();
	start_cpus();

	/* Set the TOD */
	mutex_enter(&tod_lock);
	tod_set(source_tod);
	mutex_exit(&tod_lock);

	/* Re-enable the watchdog */
	watchdog_resume();

	mutex_exit(&cpu_lock);

	/* Get new MD, update CPU mappings/relationships */
	if (suspend_update_cpu_mappings)
		update_cpu_mappings();

	DBG("suspend: target tick: 0x%lx", gettick_counter());
	DBG("suspend: target stick: 0x%llx", gettick());
	DBG("suspend: user %%tick/%%stick emulation is %d",
	    tick_stick_emulation_active);
	DBG("suspend: finished");

	return (0);
}
