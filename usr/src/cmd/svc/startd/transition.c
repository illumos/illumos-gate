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
 * Copyright 2016 RackTop Systems.
 */


/*
 * transition.c - Graph State Machine
 *
 * The graph state machine is implemented here, with a typical approach
 * of a function per state.  Separating the implementation allows more
 * clarity into the actions taken on notification of state change, as well
 * as a place for future expansion including hooks for configurable actions.
 * All functions are called with dgraph_lock held.
 *
 * The start action for this state machine is not explicit.  The states
 * (ONLINE and DEGRADED) which need to know when they're entering the state
 * due to a daemon restart implement this understanding by checking for
 * transition from uninitialized.  In the future, this would likely be better
 * as an explicit start action instead of relying on an overloaded transition.
 *
 * All gt_enter functions use the same set of return codes.
 *    0              success
 *    ECONNABORTED   repository connection aborted
 */

#include "startd.h"

static int
gt_running(restarter_instance_state_t state)
{
	if (state == RESTARTER_STATE_ONLINE ||
	    state == RESTARTER_STATE_DEGRADED)
		return (1);

	return (0);
}

static int
gt_enter_uninit(scf_handle_t *h, graph_vertex_t *v,
    restarter_instance_state_t old_state, restarter_error_t rerr)
{
	int err;
	scf_instance_t *inst;

	/* Initialize instance by refreshing it. */

	err = libscf_fmri_get_instance(h, v->gv_name, &inst);
	switch (err) {
	case 0:
		break;

	case ECONNABORTED:
		return (ECONNABORTED);

	case ENOENT:
		return (0);

	case EINVAL:
	case ENOTSUP:
	default:
		bad_error("libscf_fmri_get_instance", err);
	}

	err = refresh_vertex(v, inst);
	if (err == 0)
		graph_enable_by_vertex(v, v->gv_flags & GV_ENABLED, 0);

	scf_instance_destroy(inst);

	/* If the service was running, propagate a stop event. */
	if (gt_running(old_state)) {
		log_framework(LOG_DEBUG, "Propagating stop of %s.\n",
		    v->gv_name);

		graph_transition_propagate(v, PROPAGATE_STOP, rerr);
	}

	graph_transition_sulogin(RESTARTER_STATE_UNINIT, old_state);
	return (0);
}

/* ARGSUSED */
static int
gt_enter_maint(scf_handle_t *h, graph_vertex_t *v,
    restarter_instance_state_t old_state, restarter_error_t rerr)
{
	int to_offline = v->gv_flags & GV_TOOFFLINE;

	/*
	 * If the service was running, propagate a stop event.  If the
	 * service was not running the maintenance transition may satisfy
	 * optional dependencies and should be propagated to determine
	 * whether new dependents are satisfiable.
	 * Instances that transition to maintenance and have the GV_TOOFFLINE
	 * flag are special because they can expose new subtree leaves so
	 * propagate the offline to the instance dependencies.
	 */

	/* instance transitioning to maintenance is considered disabled */
	v->gv_flags &= ~GV_TODISABLE;
	v->gv_flags &= ~GV_TOOFFLINE;

	if (gt_running(old_state)) {
		/*
		 * Handle state change during instance disabling.
		 * Propagate offline to the new exposed leaves.
		 */
		if (to_offline) {
			log_framework(LOG_DEBUG, "%s removed from subtree\n",
			    v->gv_name);

			graph_offline_subtree_leaves(v, (void *)h);
		}

		log_framework(LOG_DEBUG, "Propagating maintenance (stop) of "
		    "%s.\n", v->gv_name);

		graph_transition_propagate(v, PROPAGATE_STOP, rerr);

		/*
		 * The maintenance transition may satisfy optional_all/restart
		 * dependencies and should be propagated to determine
		 * whether new dependents are satisfiable.
		 */
		graph_transition_propagate(v, PROPAGATE_SAT, rerr);
	} else {
		log_framework(LOG_DEBUG, "Propagating maintenance of %s.\n",
		    v->gv_name);

		graph_transition_propagate(v, PROPAGATE_SAT, rerr);
	}

	graph_transition_sulogin(RESTARTER_STATE_MAINT, old_state);
	return (0);
}

/* ARGSUSED */
static int
gt_enter_offline(scf_handle_t *h, graph_vertex_t *v,
    restarter_instance_state_t old_state, restarter_error_t rerr)
{
	int to_offline = v->gv_flags & GV_TOOFFLINE;
	int to_disable = v->gv_flags & GV_TODISABLE;

	v->gv_flags &= ~GV_TOOFFLINE;

	/*
	 * If the instance should be enabled, see if we can start it.
	 * Otherwise send a disable command.
	 * If a instance has the GV_TOOFFLINE flag set then it must
	 * remains offline until the disable process completes.
	 */
	if (v->gv_flags & GV_ENABLED) {
		if (to_offline == 0 && to_disable == 0)
			graph_start_if_satisfied(v);
	} else {
		if (gt_running(old_state) && v->gv_post_disable_f)
			v->gv_post_disable_f();

		vertex_send_event(v, RESTARTER_EVENT_TYPE_DISABLE);
	}

	/*
	 * If the service was running, propagate a stop event.  If the
	 * service was not running the offline transition may satisfy
	 * optional dependencies and should be propagated to determine
	 * whether new dependents are satisfiable.
	 * Instances that transition to offline and have the GV_TOOFFLINE flag
	 * are special because they can expose new subtree leaves so propagate
	 * the offline to the instance dependencies.
	 */
	if (gt_running(old_state)) {
		/*
		 * Handle state change during instance disabling.
		 * Propagate offline to the new exposed leaves.
		 */
		if (to_offline) {
			log_framework(LOG_DEBUG, "%s removed from subtree\n",
			    v->gv_name);

			graph_offline_subtree_leaves(v, (void *)h);
		}

		log_framework(LOG_DEBUG, "Propagating stop of %s.\n",
		    v->gv_name);

		graph_transition_propagate(v, PROPAGATE_STOP, rerr);

		/*
		 * The offline transition may satisfy require_any/restart
		 * dependencies and should be propagated to determine
		 * whether new dependents are satisfiable.
		 */
		graph_transition_propagate(v, PROPAGATE_SAT, rerr);
	} else {
		log_framework(LOG_DEBUG, "Propagating offline of %s.\n",
		    v->gv_name);

		graph_transition_propagate(v, PROPAGATE_SAT, rerr);
	}

	graph_transition_sulogin(RESTARTER_STATE_OFFLINE, old_state);
	return (0);
}

/* ARGSUSED */
static int
gt_enter_disabled(scf_handle_t *h, graph_vertex_t *v,
    restarter_instance_state_t old_state, restarter_error_t rerr)
{
	int to_offline = v->gv_flags & GV_TOOFFLINE;

	v->gv_flags &= ~GV_TODISABLE;
	v->gv_flags &= ~GV_TOOFFLINE;

	/*
	 * If the instance should be disabled, no problem.  Otherwise,
	 * send an enable command, which should result in the instance
	 * moving to OFFLINE unless the instance is part of a subtree
	 * (non root) and in this case the result is unpredictable.
	 */
	if (v->gv_flags & GV_ENABLED) {
		vertex_send_event(v, RESTARTER_EVENT_TYPE_ENABLE);
	} else if (gt_running(old_state) && v->gv_post_disable_f) {
		v->gv_post_disable_f();
	}

	/*
	 * If the service was running, propagate this as a stop.  If the
	 * service was not running the disabled transition may satisfy
	 * optional dependencies and should be propagated to determine
	 * whether new dependents are satisfiable.
	 */
	if (gt_running(old_state)) {
		/*
		 * We need to propagate the offline to new exposed leaves in
		 * case we've just disabled an instance that was part of a
		 * subtree.
		 */
		if (to_offline) {
			log_framework(LOG_DEBUG, "%s removed from subtree\n",
			    v->gv_name);

			/*
			 * Handle state change during instance disabling.
			 * Propagate offline to the new exposed leaves.
			 */
			graph_offline_subtree_leaves(v, (void *)h);
		}


		log_framework(LOG_DEBUG, "Propagating stop of %s.\n",
		    v->gv_name);

		graph_transition_propagate(v, PROPAGATE_STOP, rerr);

		/*
		 * The disable transition may satisfy optional_all/restart
		 * dependencies and should be propagated to determine
		 * whether new dependents are satisfiable.
		 */
		graph_transition_propagate(v, PROPAGATE_SAT, rerr);
	} else {
		log_framework(LOG_DEBUG, "Propagating disable of %s.\n",
		    v->gv_name);

		graph_transition_propagate(v, PROPAGATE_SAT, rerr);
	}

	graph_transition_sulogin(RESTARTER_STATE_DISABLED, old_state);
	return (0);
}

static int
gt_internal_online_or_degraded(scf_handle_t *h, graph_vertex_t *v,
    restarter_instance_state_t old_state, restarter_error_t rerr)
{
	int r;

	/*
	 * If the instance has just come up, update the start
	 * snapshot.
	 */
	if (gt_running(old_state) == 0) {
		/*
		 * Don't fire if we're just recovering state
		 * after a restart.
		 */
		if (old_state != RESTARTER_STATE_UNINIT &&
		    v->gv_post_online_f)
			v->gv_post_online_f();

		r = libscf_snapshots_poststart(h, v->gv_name, B_TRUE);
		switch (r) {
		case 0:
		case ENOENT:
			/*
			 * If ENOENT, the instance must have been
			 * deleted.  Pretend we were successful since
			 * we should get a delete event later.
			 */
			break;

		case ECONNABORTED:
			return (ECONNABORTED);

		case EACCES:
		case ENOTSUP:
		default:
			bad_error("libscf_snapshots_poststart", r);
		}
	}

	if (!(v->gv_flags & GV_ENABLED)) {
		vertex_send_event(v, RESTARTER_EVENT_TYPE_DISABLE);
	} else if (v->gv_flags & GV_TOOFFLINE) {
		/*
		 * If the vertex has the GV_TOOFFLINE flag set then that's
		 * because the instance was transitioning from offline to
		 * online and the reverse disable algorithm doesn't offline
		 * those instances because it was already appearing offline.
		 * So do it now.
		 */
		offline_vertex(v);
	}

	if (gt_running(old_state) == 0) {
		log_framework(LOG_DEBUG, "Propagating start of %s.\n",
		    v->gv_name);

		graph_transition_propagate(v, PROPAGATE_START, rerr);
	} else if (rerr == RERR_REFRESH) {
		/* For refresh we'll get a message sans state change */

		log_framework(LOG_DEBUG, "Propagating refresh of %s.\n",
		    v->gv_name);

		graph_transition_propagate(v, PROPAGATE_STOP, rerr);
	}

	return (0);
}

static int
gt_enter_online(scf_handle_t *h, graph_vertex_t *v,
    restarter_instance_state_t old_state, restarter_error_t rerr)
{
	int r;

	r = gt_internal_online_or_degraded(h, v, old_state, rerr);
	if (r != 0)
		return (r);

	graph_transition_sulogin(RESTARTER_STATE_ONLINE, old_state);
	return (0);
}

static int
gt_enter_degraded(scf_handle_t *h, graph_vertex_t *v,
    restarter_instance_state_t old_state, restarter_error_t rerr)
{
	int r;

	r = gt_internal_online_or_degraded(h, v, old_state, rerr);
	if (r != 0)
		return (r);

	graph_transition_sulogin(RESTARTER_STATE_DEGRADED, old_state);
	return (0);
}

/*
 * gt_transition() implements the state transition for the graph
 * state machine.  It can return:
 *    0              success
 *    ECONNABORTED   repository connection aborted
 *
 * v->gv_state should be set to the state we're transitioning to before
 * calling this function.
 */
int
gt_transition(scf_handle_t *h, graph_vertex_t *v, restarter_error_t rerr,
    restarter_instance_state_t old_state)
{
	int err;
	int lost_repository = 0;

	/*
	 * If there's a common set of work to be done on exit from the
	 * old_state, include it as a separate set of functions here.  For
	 * now there's no such work, so there are no gt_exit functions.
	 */

	err = vertex_subgraph_dependencies_shutdown(h, v, old_state);
	switch (err) {
	case 0:
		break;

	case ECONNABORTED:
		lost_repository = 1;
		break;

	default:
		bad_error("vertex_subgraph_dependencies_shutdown", err);
	}

	/*
	 * Now call the appropriate gt_enter function for the new state.
	 */
	switch (v->gv_state) {
	case RESTARTER_STATE_UNINIT:
		err = gt_enter_uninit(h, v, old_state, rerr);
		break;

	case RESTARTER_STATE_DISABLED:
		err = gt_enter_disabled(h, v, old_state, rerr);
		break;

	case RESTARTER_STATE_OFFLINE:
		err = gt_enter_offline(h, v, old_state, rerr);
		break;

	case RESTARTER_STATE_ONLINE:
		err = gt_enter_online(h, v, old_state, rerr);
		break;

	case RESTARTER_STATE_DEGRADED:
		err = gt_enter_degraded(h, v, old_state, rerr);
		break;

	case RESTARTER_STATE_MAINT:
		err = gt_enter_maint(h, v, old_state, rerr);
		break;

	default:
		/* Shouldn't be in an invalid state. */
#ifndef NDEBUG
		uu_warn("%s:%d: Invalid state %d.\n", __FILE__, __LINE__,
		    v->gv_state);
#endif
		abort();
	}

	switch (err) {
	case 0:
		break;

	case ECONNABORTED:
		lost_repository = 1;
		break;

	default:
#ifndef NDEBUG
		uu_warn("%s:%d: "
		    "gt_enter_%s() failed with unexpected error %d.\n",
		    __FILE__, __LINE__, instance_state_str[v->gv_state], err);
#endif
		abort();
	}

	return (lost_repository ? ECONNABORTED : 0);
}
