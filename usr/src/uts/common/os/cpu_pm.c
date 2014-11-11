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

#include <sys/cpu_pm.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/sdt.h>

/*
 * Solaris Event Based CPU Power Manager
 *
 * This file implements platform independent event based CPU power management.
 * When CPUs are configured into the system, the CMT scheduling subsystem will
 * query the platform to determine if the CPU belongs to any power management
 * domains. That is, sets of CPUs that share power management states.
 *
 * Active Power Management domains represent a group of CPUs across which the
 * Operating System can request speed changes (which may in turn result
 * in voltage changes). This allows the operating system to trade off
 * performance for power savings.
 *
 * Idle Power Management domains can enter power savings states when they are
 * unutilized. These states allow the Operating System to trade off power
 * for performance (in the form of latency to transition from the idle state
 * to an active one).
 *
 * For each active and idle power domain the CMT subsystem instantiates, a
 * cpupm_domain_t structure is created. As the dispatcher schedules threads
 * to run on the system's CPUs, it will also track the utilization of the
 * enumerated power domains. Significant changes in utilization will result
 * in the dispatcher sending the power manager events that relate to the
 * utilization of the power domain. The power manager recieves the events,
 * and in the context of the policy objectives in force, may decide to request
 * the domain's power/performance state be changed.
 *
 * Under the "elastic" CPUPM policy, when the utilization rises, the CPU power
 * manager will request the CPUs in the domain run at their fastest (and most
 * power consuming) state. When the domain becomes idle (utilization at zero),
 * the power manager will request that the CPUs run at a speed that saves the
 * most power.
 *
 * The advantage of this scheme, is that the CPU power manager working with the
 * dispatcher can be extremely responsive to changes in utilization. Optimizing
 * for performance in the presence of utilization, and power savings in the
 * presence of idleness. Such close collaboration with the dispatcher has other
 * benefits that will play out in the form of more sophisticated power /
 * performance policy in the near future.
 *
 * Avoiding state thrashing in the presence of transient periods of utilization
 * and idleness while still being responsive to non-transient periods is key.
 * The power manager implements a "governor" that is used to throttle
 * state transitions when a significant amount of transient idle or transient
 * work is detected.
 *
 * Kernel background activity (e.g. taskq threads) are by far the most common
 * form of transient utilization. Ungoverned in the face of this utililzation,
 * hundreds of state transitions per second would result on an idle system.
 *
 * Transient idleness is common when a thread briefly yields the CPU to
 * wait for an event elsewhere in the system. Where the idle period is short
 * enough, the overhead associated with making the state transition doesn't
 * justify the power savings.
 *
 * The following is the state machine for the governor implemented by
 * cpupm_utilization_event():
 *
 *         ----->---tw---->-----
 *        /                     \
 *      (I)-<-ti-<-     -<-ntw-<(W)
 *       |         \   /         |
 *       \          \ /          /
 *        >-nti/rm->(D)--->-tw->-
 * Key:
 *
 * States
 * - (D): Default (ungoverned)
 * - (W): Transient work governed
 * - (I): Transient idle governed
 * State Transitions
 * - tw: transient work
 * - ti: transient idleness
 * - ntw: non-transient work
 * - nti: non-transient idleness
 * - rm: thread remain event
 */

static cpupm_domain_t *cpupm_domains = NULL;

/*
 * Uninitialized state of CPU power management is disabled
 */
cpupm_policy_t cpupm_policy = CPUPM_POLICY_DISABLED;

/*
 * Periods of utilization lasting less than this time interval are characterized
 * as transient. State changes associated with transient work are considered
 * to be mispredicted. That is, it's not worth raising and lower power states
 * where the utilization lasts for less than this interval.
 */
hrtime_t cpupm_tw_predict_interval;

/*
 * Periods of idleness lasting less than this time interval are characterized
 * as transient. State changes associated with transient idle are considered
 * to be mispredicted. That is, it's not worth lowering and raising power
 * states where the idleness lasts for less than this interval.
 */
hrtime_t cpupm_ti_predict_interval;

/*
 * Number of mispredictions after which future transitions will be governed.
 */
int cpupm_mispredict_thresh = 4;

/*
 * Likewise, the number of mispredicted governed transitions after which the
 * governor will be removed.
 */
int cpupm_mispredict_gov_thresh = 4;

/*
 * The transient work and transient idle prediction intervals are specified
 * here. Tuning them higher will result in the transient work, and transient
 * idle governors being used more aggresively, which limits the frequency of
 * state transitions at the expense of performance and power savings,
 * respectively. The intervals are specified in nanoseconds.
 */
/*
 * 400 usec
 */
#define	CPUPM_DEFAULT_TI_INTERVAL	400000
/*
 * 400 usec
 */
#define	CPUPM_DEFAULT_TW_INTERVAL	400000

hrtime_t cpupm_ti_gov_interval = CPUPM_DEFAULT_TI_INTERVAL;
hrtime_t cpupm_tw_gov_interval = CPUPM_DEFAULT_TW_INTERVAL;


static void	cpupm_governor_initialize(void);
static void	cpupm_state_change_global(cpupm_dtype_t, cpupm_state_name_t);

cpupm_policy_t
cpupm_get_policy(void)
{
	return (cpupm_policy);
}

int
cpupm_set_policy(cpupm_policy_t new_policy)
{
	static int	gov_init = 0;
	int		result = 0;

	mutex_enter(&cpu_lock);
	if (new_policy == cpupm_policy) {
		mutex_exit(&cpu_lock);
		return (result);
	}

	/*
	 * Pausing CPUs causes a high priority thread to be scheduled
	 * on all other CPUs (besides the current one). This locks out
	 * other CPUs from making CPUPM state transitions.
	 */
	switch (new_policy) {
	case CPUPM_POLICY_DISABLED:
		pause_cpus(NULL, NULL);
		cpupm_policy = CPUPM_POLICY_DISABLED;
		start_cpus();

		result = cmt_pad_disable(PGHW_POW_ACTIVE);

		/*
		 * Once PAD has been enabled, it should always be possible
		 * to disable it.
		 */
		ASSERT(result == 0);

		/*
		 * Bring all the active power domains to the maximum
		 * performance state.
		 */
		cpupm_state_change_global(CPUPM_DTYPE_ACTIVE,
		    CPUPM_STATE_MAX_PERF);

		break;
	case CPUPM_POLICY_ELASTIC:

		result = cmt_pad_enable(PGHW_POW_ACTIVE);
		if (result < 0) {
			/*
			 * Failed to enable PAD across the active power
			 * domains, which may well be because none were
			 * enumerated.
			 */
			break;
		}

		/*
		 * Initialize the governor parameters the first time through.
		 */
		if (gov_init == 0) {
			cpupm_governor_initialize();
			gov_init = 1;
		}

		pause_cpus(NULL, NULL);
		cpupm_policy = CPUPM_POLICY_ELASTIC;
		start_cpus();

		break;
	default:
		cmn_err(CE_WARN, "Attempt to set unknown CPUPM policy %d\n",
		    new_policy);
		ASSERT(0);
		break;
	}
	mutex_exit(&cpu_lock);

	return (result);
}

/*
 * Look for an existing power domain
 */
static cpupm_domain_t *
cpupm_domain_find(id_t id, cpupm_dtype_t type)
{
	ASSERT(MUTEX_HELD(&cpu_lock));

	cpupm_domain_t *dom;

	dom = cpupm_domains;
	while (dom != NULL) {
		if (id == dom->cpd_id && type == dom->cpd_type)
			return (dom);
		dom = dom->cpd_next;
	}
	return (NULL);
}

/*
 * Create a new domain
 */
static cpupm_domain_t *
cpupm_domain_create(id_t id, cpupm_dtype_t type)
{
	cpupm_domain_t *dom;

	ASSERT(MUTEX_HELD(&cpu_lock));

	dom = kmem_zalloc(sizeof (cpupm_domain_t), KM_SLEEP);
	dom->cpd_id = id;
	dom->cpd_type = type;

	/* Link into the known domain list */
	dom->cpd_next = cpupm_domains;
	cpupm_domains = dom;

	return (dom);
}

static void
cpupm_domain_state_enum(struct cpu *cp, cpupm_domain_t *dom)
{
	/*
	 * In the envent we're enumerating because the domain's state
	 * configuration has changed, toss any existing states.
	 */
	if (dom->cpd_nstates > 0) {
		kmem_free(dom->cpd_states,
		    sizeof (cpupm_state_t) * dom->cpd_nstates);
		dom->cpd_nstates = 0;
	}

	/*
	 * Query to determine the number of states, allocate storage
	 * large enough to hold the state information, and pass it back
	 * to the platform driver to complete the enumeration.
	 */
	dom->cpd_nstates = cpupm_plat_state_enumerate(cp, dom->cpd_type, NULL);

	if (dom->cpd_nstates == 0)
		return;

	dom->cpd_states =
	    kmem_zalloc(dom->cpd_nstates * sizeof (cpupm_state_t), KM_SLEEP);
	(void) cpupm_plat_state_enumerate(cp, dom->cpd_type, dom->cpd_states);
}

/*
 * Initialize the specified type of power domain on behalf of the CPU
 */
cpupm_domain_t *
cpupm_domain_init(struct cpu *cp, cpupm_dtype_t type)
{
	cpupm_domain_t	*dom;
	id_t		did;

	ASSERT(MUTEX_HELD(&cpu_lock));

	/*
	 * Instantiate the domain if it doesn't already exist
	 * and enumerate its power states.
	 */
	did = cpupm_domain_id(cp, type);
	dom = cpupm_domain_find(did, type);
	if (dom == NULL) {
		dom = cpupm_domain_create(did, type);
		cpupm_domain_state_enum(cp, dom);
	}

	/*
	 * Named state initialization
	 */
	if (type == CPUPM_DTYPE_ACTIVE) {
		/*
		 * For active power domains, the highest performance
		 * state is defined as first state returned from
		 * the domain enumeration.
		 */
		dom->cpd_named_states[CPUPM_STATE_MAX_PERF] =
		    &dom->cpd_states[0];
		dom->cpd_named_states[CPUPM_STATE_LOW_POWER] =
		    &dom->cpd_states[dom->cpd_nstates - 1];

		/*
		 * Begin by assuming CPU is running at the max perf state.
		 */
		dom->cpd_state = dom->cpd_named_states[CPUPM_STATE_MAX_PERF];
	}

	return (dom);
}

/*
 * Return the id associated with the given type of domain
 * to which cp belongs
 */
id_t
cpupm_domain_id(struct cpu *cp, cpupm_dtype_t type)
{
	return (cpupm_plat_domain_id(cp, type));
}

/*
 * Initiate a state change for the specified domain on behalf of cp
 */
int
cpupm_change_state(struct cpu *cp, cpupm_domain_t *dom, cpupm_state_t *state)
{
	if (cpupm_plat_change_state(cp, state) < 0)
		return (-1);

	DTRACE_PROBE2(cpupm__change__state,
	    cpupm_domain_t *, dom,
	    cpupm_state_t *, state);

	dom->cpd_state = state;
	return (0);
}

/*
 * Interface into the CPU power manager to indicate a significant change
 * in utilization of the specified active power domain
 */
void
cpupm_utilization_event(struct cpu *cp, hrtime_t now, cpupm_domain_t *dom,
			    cpupm_util_event_t event)
{
	cpupm_state_t	*new_state = NULL;
	hrtime_t	last;

	if (cpupm_policy == CPUPM_POLICY_DISABLED) {
		return;
	}

	/*
	 * What follows is a simple elastic power state management policy.
	 *
	 * If the utilization has become non-zero, and the domain was
	 * previously at it's lowest power state, then transition it
	 * to the highest state in the spirit of "race to idle".
	 *
	 * If the utilization has dropped to zero, then transition the
	 * domain to its lowest power state.
	 *
	 * Statistics are maintained to implement a governor to reduce state
	 * transitions resulting from either transient work, or periods of
	 * transient idleness on the domain.
	 */
	switch (event) {
	case CPUPM_DOM_REMAIN_BUSY:

		/*
		 * We've received an event that the domain is running a thread
		 * that's made it to the end of it's time slice. If we are at
		 * low power, then raise it. If the transient work governor
		 * is engaged, then remove it.
		 */
		if (dom->cpd_state ==
		    dom->cpd_named_states[CPUPM_STATE_LOW_POWER]) {
			new_state =
			    dom->cpd_named_states[CPUPM_STATE_MAX_PERF];
			if (dom->cpd_governor == CPUPM_GOV_TRANS_WORK) {
				dom->cpd_governor = CPUPM_GOV_DISENGAGED;
				dom->cpd_tw = 0;
			}
		}
		break;

	case CPUPM_DOM_BUSY_FROM_IDLE:
		last = dom->cpd_last_lower;
		dom->cpd_last_raise = now;

		DTRACE_PROBE3(cpupm__raise__req,
		    cpupm_domain_t *, dom,
		    hrtime_t, last,
		    hrtime_t, now);

		if (dom->cpd_state ==
		    dom->cpd_named_states[CPUPM_STATE_LOW_POWER]) {

			/*
			 * There's non-zero utilization, and the domain is
			 * running in the lower power state. Before we
			 * consider raising power, check if the preceeding
			 * idle period was transient in duration.
			 *
			 * If the domain is already transient work governed,
			 * then we don't bother maintaining transient idle
			 * statistics, as the presence of enough transient work
			 * can also make the domain frequently transiently idle.
			 * In this case, we still want to remain transient work
			 * governed.
			 */
			if (dom->cpd_governor == CPUPM_GOV_DISENGAGED) {
				if ((now - last) < cpupm_ti_predict_interval) {
					/*
					 * We're raising the domain power and
					 * we *just* lowered it. Consider
					 * this a mispredicted power state
					 * transition due to a transient
					 * idle period.
					 */
					if (++dom->cpd_ti >=
					    cpupm_mispredict_thresh) {
						/*
						 * There's enough transient
						 * idle transitions to
						 * justify governing future
						 * lowering requests.
						 */
						dom->cpd_governor =
						    CPUPM_GOV_TRANS_IDLE;
						dom->cpd_ti = 0;
						DTRACE_PROBE1(
						    cpupm__ti__governed,
						    cpupm_domain_t *, dom);
					}
				} else {
					/*
					 * We correctly predicted the last
					 * lowering.
					 */
					dom->cpd_ti = 0;
				}
			}
			if (dom->cpd_governor == CPUPM_GOV_TRANS_WORK) {
				/*
				 * Raise requests are governed due to
				 * transient work.
				 */
				DTRACE_PROBE1(cpupm__raise__governed,
				    cpupm_domain_t *, dom);

				return;
			}
			/*
			 * Prepare to transition to the higher power state
			 */
			new_state = dom->cpd_named_states[CPUPM_STATE_MAX_PERF];

		} else if (dom->cpd_state ==
		    dom->cpd_named_states[CPUPM_STATE_MAX_PERF]) {

			/*
			 * Utilization is non-zero, and we're already running
			 * in the higher power state. Take this opportunity to
			 * perform some book keeping if the last lowering
			 * request was governed.
			 */
			if (dom->cpd_governor == CPUPM_GOV_TRANS_IDLE) {

				if ((now - last) >= cpupm_ti_predict_interval) {
					/*
					 * The domain is transient idle
					 * governed, and we mispredicted
					 * governing the last lowering request.
					 */
					if (++dom->cpd_ti >=
					    cpupm_mispredict_gov_thresh) {
						/*
						 * There's enough non-transient
						 * idle periods to justify
						 * removing the governor.
						 */
						dom->cpd_governor =
						    CPUPM_GOV_DISENGAGED;
						dom->cpd_ti = 0;
						DTRACE_PROBE1(
						    cpupm__ti__ungoverned,
						    cpupm_domain_t *, dom);
					}
				} else {
					/*
					 * Correctly predicted governing the
					 * last lowering request.
					 */
					dom->cpd_ti = 0;
				}
			}
		}
		break;

	case CPUPM_DOM_IDLE_FROM_BUSY:
		last = dom->cpd_last_raise;
		dom->cpd_last_lower = now;

		DTRACE_PROBE3(cpupm__lower__req,
		    cpupm_domain_t *, dom,
		    hrtime_t, last,
		    hrtime_t, now);

		if (dom->cpd_state ==
		    dom->cpd_named_states[CPUPM_STATE_MAX_PERF]) {

			/*
			 * The domain is idle, and is running in the highest
			 * performance state. Before we consider lowering power,
			 * perform some book keeping for the transient work
			 * governor.
			 */
			if (dom->cpd_governor == CPUPM_GOV_DISENGAGED) {
				if ((now - last) < cpupm_tw_predict_interval) {
					/*
					 * We're lowering the domain power and
					 * we *just* raised it. Consider the
					 * last raise mispredicted due to
					 * transient work.
					 */
					if (++dom->cpd_tw >=
					    cpupm_mispredict_thresh) {
						/*
						 * There's enough transient work
						 * transitions to justify
						 * governing future raise
						 * requests.
						 */
						dom->cpd_governor =
						    CPUPM_GOV_TRANS_WORK;
						dom->cpd_tw = 0;
						DTRACE_PROBE1(
						    cpupm__tw__governed,
						    cpupm_domain_t *, dom);
					}
				} else {
					/*
					 * We correctly predicted during the
					 * last raise.
					 */
					dom->cpd_tw = 0;
				}
			}
			if (dom->cpd_governor == CPUPM_GOV_TRANS_IDLE) {
				/*
				 * Lowering requests are governed due to
				 * transient idleness.
				 */
				DTRACE_PROBE1(cpupm__lowering__governed,
				    cpupm_domain_t *, dom);

				return;
			}

			/*
			 * Prepare to transition to a lower power state.
			 */
			new_state =
			    dom->cpd_named_states[CPUPM_STATE_LOW_POWER];

		} else if (dom->cpd_state ==
		    dom->cpd_named_states[CPUPM_STATE_LOW_POWER]) {

			/*
			 * The domain is idle, and we're already running in
			 * the lower power state. Take this opportunity to
			 * perform some book keeping if the last raising
			 * request was governed.
			 */
			if (dom->cpd_governor == CPUPM_GOV_TRANS_WORK) {
				if ((now - last) >= cpupm_tw_predict_interval) {
					/*
					 * The domain is transient work
					 * governed, and we mispredicted
					 * governing the last raising request.
					 */
					if (++dom->cpd_tw >=
					    cpupm_mispredict_gov_thresh) {
						/*
						 * There's enough non-transient
						 * work to justify removing
						 * the governor.
						 */
						dom->cpd_governor =
						    CPUPM_GOV_DISENGAGED;
						dom->cpd_tw = 0;
						DTRACE_PROBE1(
						    cpupm__tw__ungoverned,
						    cpupm_domain_t *, dom);
					}
				} else {
					/*
					 * We correctly predicted governing
					 * the last raise.
					 */
					dom->cpd_tw = 0;
				}
			}
		}
		break;
	}
	/*
	 * Change the power state
	 * Not much currently done if this doesn't succeed
	 */
	if (new_state)
		(void) cpupm_change_state(cp, dom, new_state);
}


/*
 * Interface called by platforms to dynamically change the
 * MAX performance cpupm state
 */
void
cpupm_redefine_max_activepwr_state(struct cpu *cp, int max_perf_level)
{
	cpupm_domain_t	*dom;
	id_t		did;
	cpupm_dtype_t	type = CPUPM_DTYPE_ACTIVE;
	boolean_t	change_state = B_FALSE;
	cpupm_state_t	*new_state = NULL;

	did = cpupm_domain_id(cp, type);
	if (MUTEX_HELD(&cpu_lock)) {
		dom = cpupm_domain_find(did, type);
	} else {
		mutex_enter(&cpu_lock);
		dom = cpupm_domain_find(did, type);
		mutex_exit(&cpu_lock);
	}

	/*
	 * Can use a lock to avoid changing the power state of the cpu when
	 * CPUPM_STATE_MAX_PERF is getting changed.
	 * Since the occurance of events to change MAX_PERF is not frequent,
	 * it may not be a good idea to overburden with locks. In the worst
	 * case, for one cycle the power may not get changed to the required
	 * level
	 */
	if (dom != NULL) {
		if (dom->cpd_state ==
		    dom->cpd_named_states[CPUPM_STATE_MAX_PERF]) {
			change_state = B_TRUE;
		}

		/*
		 * If an out of range level is passed, use the lowest supported
		 * speed.
		 */
		if (max_perf_level >= dom->cpd_nstates &&
		    dom->cpd_nstates > 1) {
			max_perf_level = dom->cpd_nstates - 1;
		}

		dom->cpd_named_states[CPUPM_STATE_MAX_PERF] =
		    &dom->cpd_states[max_perf_level];

		/*
		 * If the current state is MAX_PERF, change the current state
		 * to the new MAX_PERF
		 */
		if (change_state) {
			new_state =
			    dom->cpd_named_states[CPUPM_STATE_MAX_PERF];
			if (new_state) {
				(void) cpupm_change_state(cp, dom, new_state);
			}
		}
	}
}

/*
 * Initialize the parameters for the transience governor state machine
 */
static void
cpupm_governor_initialize(void)
{
	/*
	 * The default prediction intervals are specified in nanoseconds.
	 * Convert these to the equivalent in unscaled hrtime, which is the
	 * format of the timestamps passed to cpupm_utilization_event()
	 */
	cpupm_ti_predict_interval = unscalehrtime(cpupm_ti_gov_interval);
	cpupm_tw_predict_interval = unscalehrtime(cpupm_tw_gov_interval);
}

/*
 * Initiate a state change in all CPUPM domain instances of the specified type
 */
static void
cpupm_state_change_global(cpupm_dtype_t type, cpupm_state_name_t state)
{
	cpu_t		*cp;
	pg_cmt_t	*pwr_pg;
	cpupm_domain_t	*dom;
	group_t		*hwset;
	group_iter_t	giter;
	pg_cpu_itr_t	cpu_iter;
	pghw_type_t	hw;

	ASSERT(MUTEX_HELD(&cpu_lock));

	switch (type) {
	case CPUPM_DTYPE_ACTIVE:
		hw = PGHW_POW_ACTIVE;
		break;
	default:
		/*
		 * Power domain types other than "active" unsupported.
		 */
		ASSERT(type == CPUPM_DTYPE_ACTIVE);
		return;
	}

	if ((hwset = pghw_set_lookup(hw)) == NULL)
		return;

	/*
	 * Iterate over the power domains
	 */
	group_iter_init(&giter);
	while ((pwr_pg = group_iterate(hwset, &giter)) != NULL) {

		dom = (cpupm_domain_t *)pwr_pg->cmt_pg.pghw_handle;

		/*
		 * Iterate over the CPUs in each domain
		 */
		PG_CPU_ITR_INIT(pwr_pg, cpu_iter);
		while ((cp = pg_cpu_next(&cpu_iter)) != NULL) {
			(void) cpupm_change_state(cp, dom,
			    dom->cpd_named_states[state]);
		}
	}
}
