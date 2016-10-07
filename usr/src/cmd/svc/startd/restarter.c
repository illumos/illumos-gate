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
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 */

/*
 * restarter.c - service manipulation
 *
 * This component manages services whose restarter is svc.startd, the standard
 * restarter.  It translates restarter protocol events from the graph engine
 * into actions on processes, as a delegated restarter would do.
 *
 * The master restarter manages a number of always-running threads:
 *   - restarter event thread: events from the graph engine
 *   - timeout thread: thread to fire queued timeouts
 *   - contract thread: thread to handle contract events
 *   - wait thread: thread to handle wait-based services
 *
 * The other threads are created as-needed:
 *   - per-instance method threads
 *   - per-instance event processing threads
 *
 * The interaction of all threads must result in the following conditions
 * being satisfied (on a per-instance basis):
 *   - restarter events must be processed in order
 *   - method execution must be serialized
 *   - instance delete must be held until outstanding methods are complete
 *   - contract events shouldn't be processed while a method is running
 *   - timeouts should fire even when a method is running
 *
 * Service instances are represented by restarter_inst_t's and are kept in the
 * instance_list list.
 *
 * Service States
 *   The current state of a service instance is kept in
 *   restarter_inst_t->ri_i.i_state.  If transition to a new state could take
 *   some time, then before we effect the transition we set
 *   restarter_inst_t->ri_i.i_next_state to the target state, and afterwards we
 *   rotate i_next_state to i_state and set i_next_state to
 *   RESTARTER_STATE_NONE.  So usually i_next_state is _NONE when ri_lock is not
 *   held.  The exception is when we launch methods, which are done with
 *   a separate thread.  To keep any other threads from grabbing ri_lock before
 *   method_thread() does, we set ri_method_thread to the thread id of the
 *   method thread, and when it is nonzero any thread with a different thread id
 *   waits on ri_method_cv.
 *
 * Method execution is serialized by blocking on ri_method_cv in
 * inst_lookup_by_id() and waiting for a 0 value of ri_method_thread.  This
 * also prevents the instance structure from being deleted until all
 * outstanding operations such as method_thread() have finished.
 *
 * Lock ordering:
 *
 * dgraph_lock [can be held when taking:]
 *   utmpx_lock
 *   dictionary->dict_lock
 *   st->st_load_lock
 *   wait_info_lock
 *   ru->restarter_update_lock
 *     restarter_queue->rpeq_lock
 *   instance_list.ril_lock
 *     inst->ri_lock
 *   st->st_configd_live_lock
 *
 * instance_list.ril_lock
 *   graph_queue->gpeq_lock
 *   gu->gu_lock
 *   st->st_configd_live_lock
 *   dictionary->dict_lock
 *   inst->ri_lock
 *     graph_queue->gpeq_lock
 *     gu->gu_lock
 *     tu->tu_lock
 *     tq->tq_lock
 *     inst->ri_queue_lock
 *       wait_info_lock
 *       bp->cb_lock
 *     utmpx_lock
 *
 * single_user_thread_lock
 *   wait_info_lock
 *   utmpx_lock
 *
 * gu_freeze_lock
 *
 * logbuf_mutex nests inside pretty much everything.
 */

#include <sys/contract/process.h>
#include <sys/ctfs.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <libintl.h>
#include <librestart.h>
#include <librestart_priv.h>
#include <libuutil.h>
#include <limits.h>
#include <poll.h>
#include <port.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>

#include "startd.h"
#include "protocol.h"

static uu_list_pool_t *restarter_instance_pool;
static restarter_instance_list_t instance_list;

static uu_list_pool_t *restarter_queue_pool;

#define	WT_SVC_ERR_THROTTLE	1	/* 1 sec delay for erroring wait svc */

/*
 * Function used to reset the restart times for an instance, when
 * an administrative task comes along and essentially makes the times
 * in this array ineffective.
 */
static void
reset_start_times(restarter_inst_t *inst)
{
	inst->ri_start_index = 0;
	bzero(inst->ri_start_time, sizeof (inst->ri_start_time));
}

/*ARGSUSED*/
static int
restarter_instance_compare(const void *lc_arg, const void *rc_arg,
    void *private)
{
	int lc_id = ((const restarter_inst_t *)lc_arg)->ri_id;
	int rc_id = *(int *)rc_arg;

	if (lc_id > rc_id)
		return (1);
	if (lc_id < rc_id)
		return (-1);
	return (0);
}

static restarter_inst_t *
inst_lookup_by_name(const char *name)
{
	int id;

	id = dict_lookup_byname(name);
	if (id == -1)
		return (NULL);

	return (inst_lookup_by_id(id));
}

restarter_inst_t *
inst_lookup_by_id(int id)
{
	restarter_inst_t *inst;

	MUTEX_LOCK(&instance_list.ril_lock);
	inst = uu_list_find(instance_list.ril_instance_list, &id, NULL, NULL);
	if (inst != NULL)
		MUTEX_LOCK(&inst->ri_lock);
	MUTEX_UNLOCK(&instance_list.ril_lock);

	if (inst != NULL) {
		while (inst->ri_method_thread != 0 &&
		    !pthread_equal(inst->ri_method_thread, pthread_self())) {
			++inst->ri_method_waiters;
			(void) pthread_cond_wait(&inst->ri_method_cv,
			    &inst->ri_lock);
			assert(inst->ri_method_waiters > 0);
			--inst->ri_method_waiters;
		}
	}

	return (inst);
}

static restarter_inst_t *
inst_lookup_queue(const char *name)
{
	int id;
	restarter_inst_t *inst;

	id = dict_lookup_byname(name);
	if (id == -1)
		return (NULL);

	MUTEX_LOCK(&instance_list.ril_lock);
	inst = uu_list_find(instance_list.ril_instance_list, &id, NULL, NULL);
	if (inst != NULL)
		MUTEX_LOCK(&inst->ri_queue_lock);
	MUTEX_UNLOCK(&instance_list.ril_lock);

	return (inst);
}

const char *
service_style(int flags)
{
	switch (flags & RINST_STYLE_MASK) {
	case RINST_CONTRACT:	return ("contract");
	case RINST_TRANSIENT:	return ("transient");
	case RINST_WAIT:	return ("wait");

	default:
#ifndef NDEBUG
		uu_warn("%s:%d: Bad flags 0x%x.\n", __FILE__, __LINE__, flags);
#endif
		abort();
		/* NOTREACHED */
	}
}

/*
 * Fails with ECONNABORTED or ECANCELED.
 */
static int
check_contract(restarter_inst_t *inst, boolean_t primary,
    scf_instance_t *scf_inst)
{
	ctid_t *ctidp;
	int fd, r;

	ctidp = primary ? &inst->ri_i.i_primary_ctid :
	    &inst->ri_i.i_transient_ctid;

	assert(*ctidp >= 1);

	fd = contract_open(*ctidp, NULL, "status", O_RDONLY);
	if (fd >= 0) {
		r = close(fd);
		assert(r == 0);
		return (0);
	}

	r = restarter_remove_contract(scf_inst, *ctidp, primary ?
	    RESTARTER_CONTRACT_PRIMARY : RESTARTER_CONTRACT_TRANSIENT);
	switch (r) {
	case 0:
	case ECONNABORTED:
	case ECANCELED:
		*ctidp = 0;
		return (r);

	case ENOMEM:
		uu_die("Out of memory\n");
		/* NOTREACHED */

	case EPERM:
		uu_die("Insufficient privilege.\n");
		/* NOTREACHED */

	case EACCES:
		uu_die("Repository backend access denied.\n");
		/* NOTREACHED */

	case EROFS:
		log_error(LOG_INFO, "Could not remove unusable contract id %ld "
		    "for %s from repository.\n", *ctidp, inst->ri_i.i_fmri);
		return (0);

	case EINVAL:
	case EBADF:
	default:
		assert(0);
		abort();
		/* NOTREACHED */
	}
}

static int stop_instance(scf_handle_t *, restarter_inst_t *, stop_cause_t);

/*
 * int restarter_insert_inst(scf_handle_t *, char *)
 *   If the inst is already in the restarter list, return its id.  If the inst
 *   is not in the restarter list, initialize a restarter_inst_t, initialize its
 *   states, insert it into the list, and return 0.
 *
 *   Fails with
 *     ENOENT - name is not in the repository
 */
static int
restarter_insert_inst(scf_handle_t *h, const char *name)
{
	int id, r;
	restarter_inst_t *inst;
	uu_list_index_t idx;
	scf_service_t *scf_svc;
	scf_instance_t *scf_inst;
	scf_snapshot_t *snap = NULL;
	scf_propertygroup_t *pg;
	char *svc_name, *inst_name;
	char logfilebuf[PATH_MAX];
	char *c;
	boolean_t do_commit_states;
	restarter_instance_state_t state, next_state;
	protocol_states_t *ps;
	pid_t start_pid;
	restarter_str_t reason = restarter_str_insert_in_graph;

	MUTEX_LOCK(&instance_list.ril_lock);

	/*
	 * We don't use inst_lookup_by_name() here because we want the lookup
	 * & insert to be atomic.
	 */
	id = dict_lookup_byname(name);
	if (id != -1) {
		inst = uu_list_find(instance_list.ril_instance_list, &id, NULL,
		    &idx);
		if (inst != NULL) {
			MUTEX_UNLOCK(&instance_list.ril_lock);
			return (0);
		}
	}

	/* Allocate an instance */
	inst = startd_zalloc(sizeof (restarter_inst_t));
	inst->ri_utmpx_prefix = startd_alloc(max_scf_value_size);
	inst->ri_utmpx_prefix[0] = '\0';

	inst->ri_i.i_fmri = startd_alloc(strlen(name) + 1);
	(void) strcpy((char *)inst->ri_i.i_fmri, name);

	inst->ri_queue = startd_list_create(restarter_queue_pool, inst, 0);

	/*
	 * id shouldn't be -1 since we use the same dictionary as graph.c, but
	 * just in case.
	 */
	inst->ri_id = (id != -1 ? id : dict_insert(name));

	special_online_hooks_get(name, &inst->ri_pre_online_hook,
	    &inst->ri_post_online_hook, &inst->ri_post_offline_hook);

	scf_svc = safe_scf_service_create(h);
	scf_inst = safe_scf_instance_create(h);
	pg = safe_scf_pg_create(h);
	svc_name = startd_alloc(max_scf_name_size);
	inst_name = startd_alloc(max_scf_name_size);

rep_retry:
	if (snap != NULL)
		scf_snapshot_destroy(snap);
	if (inst->ri_logstem != NULL)
		startd_free(inst->ri_logstem, PATH_MAX);
	if (inst->ri_common_name != NULL)
		free(inst->ri_common_name);
	if (inst->ri_C_common_name != NULL)
		free(inst->ri_C_common_name);
	snap = NULL;
	inst->ri_logstem = NULL;
	inst->ri_common_name = NULL;
	inst->ri_C_common_name = NULL;

	if (scf_handle_decode_fmri(h, name, NULL, scf_svc, scf_inst, NULL,
	    NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			libscf_handle_rebind(h);
			goto rep_retry;

		case SCF_ERROR_NOT_FOUND:
			goto deleted;
		}

		uu_die("Can't decode FMRI %s: %s\n", name,
		    scf_strerror(scf_error()));
	}

	/*
	 * If there's no running snapshot, then we execute using the editing
	 * snapshot.  Pending snapshots will be taken later.
	 */
	snap = libscf_get_running_snapshot(scf_inst);

	if ((scf_service_get_name(scf_svc, svc_name, max_scf_name_size) < 0) ||
	    (scf_instance_get_name(scf_inst, inst_name, max_scf_name_size) <
	    0)) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_SET:
			break;

		case SCF_ERROR_CONNECTION_BROKEN:
			libscf_handle_rebind(h);
			goto rep_retry;

		default:
			assert(0);
			abort();
		}

		goto deleted;
	}

	(void) snprintf(logfilebuf, PATH_MAX, "%s:%s", svc_name, inst_name);
	for (c = logfilebuf; *c != '\0'; c++)
		if (*c == '/')
			*c = '-';

	inst->ri_logstem = startd_alloc(PATH_MAX);
	(void) snprintf(inst->ri_logstem, PATH_MAX, "%s%s", logfilebuf,
	    LOG_SUFFIX);

	/*
	 * If the restarter group is missing, use uninit/none.  Otherwise,
	 * we're probably being restarted & don't want to mess up the states
	 * that are there.
	 */
	state = RESTARTER_STATE_UNINIT;
	next_state = RESTARTER_STATE_NONE;

	r = scf_instance_get_pg(scf_inst, SCF_PG_RESTARTER, pg);
	if (r != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			libscf_handle_rebind(h);
			goto rep_retry;

		case SCF_ERROR_NOT_SET:
			goto deleted;

		case SCF_ERROR_NOT_FOUND:
			/*
			 * This shouldn't happen since the graph engine should
			 * have initialized the state to uninitialized/none if
			 * there was no restarter pg.  In case somebody
			 * deleted it, though....
			 */
			do_commit_states = B_TRUE;
			break;

		default:
			assert(0);
			abort();
		}
	} else {
		r = libscf_read_states(pg, &state, &next_state);
		if (r != 0) {
			do_commit_states = B_TRUE;
		} else {
			if (next_state != RESTARTER_STATE_NONE) {
				/*
				 * Force next_state to _NONE since we
				 * don't look for method processes.
				 */
				next_state = RESTARTER_STATE_NONE;
				do_commit_states = B_TRUE;
			} else {
				/*
				 * The reason for transition will depend on
				 * state.
				 */
				if (st->st_initial == 0)
					reason = restarter_str_startd_restart;
				else if (state == RESTARTER_STATE_MAINT)
					reason = restarter_str_bad_repo_state;
				/*
				 * Inform the restarter of our state without
				 * changing the STIME in the repository.
				 */
				ps = startd_alloc(sizeof (*ps));
				inst->ri_i.i_state = ps->ps_state = state;
				inst->ri_i.i_next_state = ps->ps_state_next =
				    next_state;
				ps->ps_reason = reason;

				graph_protocol_send_event(inst->ri_i.i_fmri,
				    GRAPH_UPDATE_STATE_CHANGE, ps);

				do_commit_states = B_FALSE;
			}
		}
	}

	switch (libscf_get_startd_properties(scf_inst, snap, &inst->ri_flags,
	    &inst->ri_utmpx_prefix)) {
	case 0:
		break;

	case ECONNABORTED:
		libscf_handle_rebind(h);
		goto rep_retry;

	case ECANCELED:
		goto deleted;

	case ENOENT:
		/*
		 * This is odd, because the graph engine should have required
		 * the general property group.  So we'll just use default
		 * flags in anticipation of the graph engine sending us
		 * REMOVE_INSTANCE when it finds out that the general property
		 * group has been deleted.
		 */
		inst->ri_flags = RINST_CONTRACT;
		break;

	default:
		assert(0);
		abort();
	}

	r = libscf_get_template_values(scf_inst, snap,
	    &inst->ri_common_name, &inst->ri_C_common_name);

	/*
	 * Copy our names to smaller buffers to reduce our memory footprint.
	 */
	if (inst->ri_common_name != NULL) {
		char *tmp = safe_strdup(inst->ri_common_name);
		startd_free(inst->ri_common_name, max_scf_value_size);
		inst->ri_common_name = tmp;
	}

	if (inst->ri_C_common_name != NULL) {
		char *tmp = safe_strdup(inst->ri_C_common_name);
		startd_free(inst->ri_C_common_name, max_scf_value_size);
		inst->ri_C_common_name = tmp;
	}

	switch (r) {
	case 0:
		break;

	case ECONNABORTED:
		libscf_handle_rebind(h);
		goto rep_retry;

	case ECANCELED:
		goto deleted;

	case ECHILD:
	case ENOENT:
		break;

	default:
		assert(0);
		abort();
	}

	switch (libscf_read_method_ids(h, scf_inst, inst->ri_i.i_fmri,
	    &inst->ri_i.i_primary_ctid, &inst->ri_i.i_transient_ctid,
	    &start_pid)) {
	case 0:
		break;

	case ECONNABORTED:
		libscf_handle_rebind(h);
		goto rep_retry;

	case ECANCELED:
		goto deleted;

	default:
		assert(0);
		abort();
	}

	if (inst->ri_i.i_primary_ctid >= 1) {
		contract_hash_store(inst->ri_i.i_primary_ctid, inst->ri_id);

		switch (check_contract(inst, B_TRUE, scf_inst)) {
		case 0:
			break;

		case ECONNABORTED:
			libscf_handle_rebind(h);
			goto rep_retry;

		case ECANCELED:
			goto deleted;

		default:
			assert(0);
			abort();
		}
	}

	if (inst->ri_i.i_transient_ctid >= 1) {
		switch (check_contract(inst, B_FALSE, scf_inst)) {
		case 0:
			break;

		case ECONNABORTED:
			libscf_handle_rebind(h);
			goto rep_retry;

		case ECANCELED:
			goto deleted;

		default:
			assert(0);
			abort();
		}
	}

	/* No more failures we live through, so add it to the list. */
	(void) pthread_mutex_init(&inst->ri_lock, &mutex_attrs);
	(void) pthread_mutex_init(&inst->ri_queue_lock, &mutex_attrs);
	MUTEX_LOCK(&inst->ri_lock);
	MUTEX_LOCK(&inst->ri_queue_lock);

	(void) pthread_cond_init(&inst->ri_method_cv, NULL);

	uu_list_node_init(inst, &inst->ri_link, restarter_instance_pool);
	uu_list_insert(instance_list.ril_instance_list, inst, idx);
	MUTEX_UNLOCK(&instance_list.ril_lock);

	if (start_pid != -1 &&
	    (inst->ri_flags & RINST_STYLE_MASK) == RINST_WAIT) {
		int ret;
		ret = wait_register(start_pid, inst->ri_i.i_fmri, 0, 1);
		if (ret == -1) {
			/*
			 * Implication:  if we can't reregister the
			 * instance, we will start another one.  Two
			 * instances may or may not result in a resource
			 * conflict.
			 */
			log_error(LOG_WARNING,
			    "%s: couldn't reregister %ld for wait\n",
			    inst->ri_i.i_fmri, start_pid);
		} else if (ret == 1) {
			/*
			 * Leading PID has exited.
			 */
			(void) stop_instance(h, inst, RSTOP_EXIT);
		}
	}


	scf_pg_destroy(pg);

	if (do_commit_states)
		(void) restarter_instance_update_states(h, inst, state,
		    next_state, RERR_NONE, reason);

	log_framework(LOG_DEBUG, "%s is a %s-style service\n", name,
	    service_style(inst->ri_flags));

	MUTEX_UNLOCK(&inst->ri_queue_lock);
	MUTEX_UNLOCK(&inst->ri_lock);

	startd_free(svc_name, max_scf_name_size);
	startd_free(inst_name, max_scf_name_size);
	scf_snapshot_destroy(snap);
	scf_instance_destroy(scf_inst);
	scf_service_destroy(scf_svc);

	log_framework(LOG_DEBUG, "%s: inserted instance into restarter list\n",
	    name);

	return (0);

deleted:
	MUTEX_UNLOCK(&instance_list.ril_lock);
	startd_free(inst_name, max_scf_name_size);
	startd_free(svc_name, max_scf_name_size);
	if (snap != NULL)
		scf_snapshot_destroy(snap);
	scf_pg_destroy(pg);
	scf_instance_destroy(scf_inst);
	scf_service_destroy(scf_svc);
	startd_free((void *)inst->ri_i.i_fmri, strlen(inst->ri_i.i_fmri) + 1);
	uu_list_destroy(inst->ri_queue);
	if (inst->ri_logstem != NULL)
		startd_free(inst->ri_logstem, PATH_MAX);
	if (inst->ri_common_name != NULL)
		free(inst->ri_common_name);
	if (inst->ri_C_common_name != NULL)
		free(inst->ri_C_common_name);
	startd_free(inst->ri_utmpx_prefix, max_scf_value_size);
	startd_free(inst, sizeof (restarter_inst_t));
	return (ENOENT);
}

static void
restarter_delete_inst(restarter_inst_t *ri)
{
	int id;
	restarter_inst_t *rip;
	void *cookie = NULL;
	restarter_instance_qentry_t *e;

	assert(MUTEX_HELD(&ri->ri_lock));

	/*
	 * Must drop the instance lock so we can pick up the instance_list
	 * lock & remove the instance.
	 */
	id = ri->ri_id;
	MUTEX_UNLOCK(&ri->ri_lock);

	MUTEX_LOCK(&instance_list.ril_lock);

	rip = uu_list_find(instance_list.ril_instance_list, &id, NULL, NULL);
	if (rip == NULL) {
		MUTEX_UNLOCK(&instance_list.ril_lock);
		return;
	}

	assert(ri == rip);

	uu_list_remove(instance_list.ril_instance_list, ri);

	log_framework(LOG_DEBUG, "%s: deleted instance from restarter list\n",
	    ri->ri_i.i_fmri);

	MUTEX_UNLOCK(&instance_list.ril_lock);

	/*
	 * We can lock the instance without holding the instance_list lock
	 * since we removed the instance from the list.
	 */
	MUTEX_LOCK(&ri->ri_lock);
	MUTEX_LOCK(&ri->ri_queue_lock);

	if (ri->ri_i.i_primary_ctid >= 1)
		contract_hash_remove(ri->ri_i.i_primary_ctid);

	while (ri->ri_method_thread != 0 || ri->ri_method_waiters > 0)
		(void) pthread_cond_wait(&ri->ri_method_cv, &ri->ri_lock);

	while ((e = uu_list_teardown(ri->ri_queue, &cookie)) != NULL)
		startd_free(e, sizeof (*e));
	uu_list_destroy(ri->ri_queue);

	startd_free((void *)ri->ri_i.i_fmri, strlen(ri->ri_i.i_fmri) + 1);
	startd_free(ri->ri_logstem, PATH_MAX);
	if (ri->ri_common_name != NULL)
		free(ri->ri_common_name);
	if (ri->ri_C_common_name != NULL)
		free(ri->ri_C_common_name);
	startd_free(ri->ri_utmpx_prefix, max_scf_value_size);
	(void) pthread_mutex_destroy(&ri->ri_lock);
	(void) pthread_mutex_destroy(&ri->ri_queue_lock);
	startd_free(ri, sizeof (restarter_inst_t));
}

/*
 * instance_is_wait_style()
 *
 *   Returns 1 if the given instance is a "wait-style" service instance.
 */
int
instance_is_wait_style(restarter_inst_t *inst)
{
	assert(MUTEX_HELD(&inst->ri_lock));
	return ((inst->ri_flags & RINST_STYLE_MASK) == RINST_WAIT);
}

/*
 * instance_is_transient_style()
 *
 *   Returns 1 if the given instance is a transient service instance.
 */
int
instance_is_transient_style(restarter_inst_t *inst)
{
	assert(MUTEX_HELD(&inst->ri_lock));
	return ((inst->ri_flags & RINST_STYLE_MASK) == RINST_TRANSIENT);
}

/*
 * instance_in_transition()
 * Returns 1 if instance is in transition, 0 if not
 */
int
instance_in_transition(restarter_inst_t *inst)
{
	assert(MUTEX_HELD(&inst->ri_lock));
	if (inst->ri_i.i_next_state == RESTARTER_STATE_NONE)
		return (0);
	return (1);
}

/*
 * returns 1 if instance is already started, 0 if not
 */
static int
instance_started(restarter_inst_t *inst)
{
	int ret;

	assert(MUTEX_HELD(&inst->ri_lock));

	if (inst->ri_i.i_state == RESTARTER_STATE_ONLINE ||
	    inst->ri_i.i_state == RESTARTER_STATE_DEGRADED)
		ret = 1;
	else
		ret = 0;

	return (ret);
}

/*
 * Returns
 *   0 - success
 *   ECONNRESET - success, but h was rebound
 */
int
restarter_instance_update_states(scf_handle_t *h, restarter_inst_t *ri,
    restarter_instance_state_t new_state,
    restarter_instance_state_t new_state_next, restarter_error_t err,
    restarter_str_t reason)
{
	protocol_states_t *states;
	int e;
	uint_t retry_count = 0, msecs = ALLOC_DELAY;
	boolean_t rebound = B_FALSE;
	int prev_state_online;
	int state_online;

	assert(MUTEX_HELD(&ri->ri_lock));

	prev_state_online = instance_started(ri);

retry:
	e = _restarter_commit_states(h, &ri->ri_i, new_state, new_state_next,
	    restarter_get_str_short(reason));
	switch (e) {
	case 0:
		break;

	case ENOMEM:
		++retry_count;
		if (retry_count < ALLOC_RETRY) {
			(void) poll(NULL, 0, msecs);
			msecs *= ALLOC_DELAY_MULT;
			goto retry;
		}

		/* Like startd_alloc(). */
		uu_die("Insufficient memory.\n");
		/* NOTREACHED */

	case ECONNABORTED:
		libscf_handle_rebind(h);
		rebound = B_TRUE;
		goto retry;

	case EPERM:
	case EACCES:
	case EROFS:
		log_error(LOG_NOTICE, "Could not commit state change for %s "
		    "to repository: %s.\n", ri->ri_i.i_fmri, strerror(e));
		/* FALLTHROUGH */

	case ENOENT:
		ri->ri_i.i_state = new_state;
		ri->ri_i.i_next_state = new_state_next;
		break;

	case EINVAL:
	default:
		bad_error("_restarter_commit_states", e);
	}

	states = startd_alloc(sizeof (protocol_states_t));
	states->ps_state = new_state;
	states->ps_state_next = new_state_next;
	states->ps_err = err;
	states->ps_reason = reason;
	graph_protocol_send_event(ri->ri_i.i_fmri, GRAPH_UPDATE_STATE_CHANGE,
	    (void *)states);

	state_online = instance_started(ri);

	if (prev_state_online && !state_online)
		ri->ri_post_offline_hook();
	else if (!prev_state_online && state_online)
		ri->ri_post_online_hook();

	return (rebound ? ECONNRESET : 0);
}

void
restarter_mark_pending_snapshot(const char *fmri, uint_t flag)
{
	restarter_inst_t *inst;

	assert(flag == RINST_RETAKE_RUNNING || flag == RINST_RETAKE_START);

	inst = inst_lookup_by_name(fmri);
	if (inst == NULL)
		return;

	inst->ri_flags |= flag;

	MUTEX_UNLOCK(&inst->ri_lock);
}

static void
restarter_take_pending_snapshots(scf_handle_t *h)
{
	restarter_inst_t *inst;
	int r;

	MUTEX_LOCK(&instance_list.ril_lock);

	for (inst = uu_list_first(instance_list.ril_instance_list);
	    inst != NULL;
	    inst = uu_list_next(instance_list.ril_instance_list, inst)) {
		const char *fmri;
		scf_instance_t *sinst = NULL;

		MUTEX_LOCK(&inst->ri_lock);

		/*
		 * This is where we'd check inst->ri_method_thread and if it
		 * were nonzero we'd wait in anticipation of another thread
		 * executing a method for inst.  Doing so with the instance_list
		 * locked, though, leads to deadlock.  Since taking a snapshot
		 * during that window won't hurt anything, we'll just continue.
		 */

		fmri = inst->ri_i.i_fmri;

		if (inst->ri_flags & RINST_RETAKE_RUNNING) {
			scf_snapshot_t *rsnap;

			(void) libscf_fmri_get_instance(h, fmri, &sinst);

			rsnap = libscf_get_or_make_running_snapshot(sinst,
			    fmri, B_FALSE);

			scf_instance_destroy(sinst);

			if (rsnap != NULL)
				inst->ri_flags &= ~RINST_RETAKE_RUNNING;

			scf_snapshot_destroy(rsnap);
		}

		if (inst->ri_flags & RINST_RETAKE_START) {
			switch (r = libscf_snapshots_poststart(h, fmri,
			    B_FALSE)) {
			case 0:
			case ENOENT:
				inst->ri_flags &= ~RINST_RETAKE_START;
				break;

			case ECONNABORTED:
				break;

			case EACCES:
			default:
				bad_error("libscf_snapshots_poststart", r);
			}
		}

		MUTEX_UNLOCK(&inst->ri_lock);
	}

	MUTEX_UNLOCK(&instance_list.ril_lock);
}

/* ARGSUSED */
void *
restarter_post_fsminimal_thread(void *unused)
{
	scf_handle_t *h;
	int r;

	h = libscf_handle_create_bound_loop();

	for (;;) {
		r = libscf_create_self(h);
		if (r == 0)
			break;

		assert(r == ECONNABORTED);
		libscf_handle_rebind(h);
	}

	restarter_take_pending_snapshots(h);

	(void) scf_handle_unbind(h);
	scf_handle_destroy(h);

	return (NULL);
}

/*
 * int stop_instance()
 *
 *   Stop the instance identified by the instance given as the second argument,
 *   for the cause stated.
 *
 *   Returns
 *     0 - success
 *     -1 - inst is in transition
 */
static int
stop_instance(scf_handle_t *local_handle, restarter_inst_t *inst,
    stop_cause_t cause)
{
	fork_info_t *info;
	const char *cp;
	int err;
	restarter_error_t re;
	restarter_str_t	reason;
	restarter_instance_state_t new_state;

	assert(MUTEX_HELD(&inst->ri_lock));
	assert(inst->ri_method_thread == 0);

	switch (cause) {
	case RSTOP_EXIT:
		re = RERR_RESTART;
		reason = restarter_str_ct_ev_exit;
		cp = "all processes in service exited";
		break;
	case RSTOP_ERR_CFG:
		re = RERR_FAULT;
		reason = restarter_str_method_failed;
		cp = "service exited with a configuration error";
		break;
	case RSTOP_ERR_EXIT:
		re = RERR_RESTART;
		reason = restarter_str_ct_ev_exit;
		cp = "service exited with an error";
		break;
	case RSTOP_CORE:
		re = RERR_FAULT;
		reason = restarter_str_ct_ev_core;
		cp = "process dumped core";
		break;
	case RSTOP_SIGNAL:
		re = RERR_FAULT;
		reason = restarter_str_ct_ev_signal;
		cp = "process received fatal signal from outside the service";
		break;
	case RSTOP_HWERR:
		re = RERR_FAULT;
		reason = restarter_str_ct_ev_hwerr;
		cp = "process killed due to uncorrectable hardware error";
		break;
	case RSTOP_DEPENDENCY:
		re = RERR_RESTART;
		reason = restarter_str_dependency_activity;
		cp = "dependency activity requires stop";
		break;
	case RSTOP_DISABLE:
		re = RERR_RESTART;
		reason = restarter_str_disable_request;
		cp = "service disabled";
		break;
	case RSTOP_RESTART:
		re = RERR_RESTART;
		reason = restarter_str_restart_request;
		cp = "service restarting";
		break;
	default:
#ifndef NDEBUG
		(void) fprintf(stderr, "Unknown cause %d at %s:%d.\n",
		    cause, __FILE__, __LINE__);
#endif
		abort();
	}

	/* Services in the disabled and maintenance state are ignored */
	if (inst->ri_i.i_state == RESTARTER_STATE_MAINT ||
	    inst->ri_i.i_state == RESTARTER_STATE_DISABLED) {
		log_framework(LOG_DEBUG,
		    "%s: stop_instance -> is maint/disabled\n",
		    inst->ri_i.i_fmri);
		return (0);
	}

	/* Already stopped instances are left alone */
	if (instance_started(inst) == 0) {
		log_framework(LOG_DEBUG, "Restarter: %s is already stopped.\n",
		    inst->ri_i.i_fmri);
		return (0);
	}

	if (instance_in_transition(inst)) {
		/* requeue event by returning -1 */
		log_framework(LOG_DEBUG,
		    "Restarter: Not stopping %s, in transition.\n",
		    inst->ri_i.i_fmri);
		return (-1);
	}

	log_instance(inst, B_TRUE, "Stopping because %s.", cp);

	log_framework(re == RERR_FAULT ? LOG_INFO : LOG_DEBUG,
	    "%s: Instance stopping because %s.\n", inst->ri_i.i_fmri, cp);

	if (instance_is_wait_style(inst) &&
	    (cause == RSTOP_EXIT ||
	    cause == RSTOP_ERR_CFG ||
	    cause == RSTOP_ERR_EXIT)) {
		/*
		 * No need to stop instance, as child has exited; remove
		 * contract and move the instance to the offline state.
		 */
		switch (err = restarter_instance_update_states(local_handle,
		    inst, inst->ri_i.i_state, RESTARTER_STATE_OFFLINE, re,
		    reason)) {
		case 0:
		case ECONNRESET:
			break;

		default:
			bad_error("restarter_instance_update_states", err);
		}

		if (cause == RSTOP_ERR_EXIT) {
			/*
			 * The RSTOP_ERR_EXIT cause is set via the
			 * wait_thread -> wait_remove code path when we have
			 * a "wait" style svc that exited with an error. If
			 * the svc is failing too quickly, we throttle it so
			 * that we don't restart it more than once/second.
			 * Since we know we're running in the wait thread its
			 * ok to throttle it right here.
			 */
			(void) update_fault_count(inst, FAULT_COUNT_INCR);
			if (method_rate_critical(inst)) {
				log_instance(inst, B_TRUE, "Failing too "
				    "quickly, throttling.");
				(void) sleep(WT_SVC_ERR_THROTTLE);
			}
		} else {
			(void) update_fault_count(inst, FAULT_COUNT_RESET);
			reset_start_times(inst);
		}

		if (inst->ri_i.i_primary_ctid != 0) {
			inst->ri_m_inst =
			    safe_scf_instance_create(local_handle);
			inst->ri_mi_deleted = B_FALSE;

			libscf_reget_instance(inst);
			method_remove_contract(inst, B_TRUE, B_TRUE);

			scf_instance_destroy(inst->ri_m_inst);
			inst->ri_m_inst = NULL;
		}

		switch (err = restarter_instance_update_states(local_handle,
		    inst, inst->ri_i.i_next_state, RESTARTER_STATE_NONE, re,
		    reason)) {
		case 0:
		case ECONNRESET:
			break;

		default:
			bad_error("restarter_instance_update_states", err);
		}

		if (cause != RSTOP_ERR_CFG)
			return (0);
	} else if (instance_is_wait_style(inst) && re == RERR_RESTART) {
		/*
		 * Stopping a wait service through means other than the pid
		 * exiting should keep wait_thread() from restarting the
		 * service, by removing it from the wait list.
		 * We cannot remove it right now otherwise the process will
		 * end up <defunct> so mark it to be ignored.
		 */
		wait_ignore_by_fmri(inst->ri_i.i_fmri);
	}

	/*
	 * There are some configuration errors which we cannot detect until we
	 * try to run the method.  For example, see exec_method() where the
	 * restarter_set_method_context() call can return SMF_EXIT_ERR_CONFIG
	 * in several cases. If this happens for a "wait-style" svc,
	 * wait_remove() sets the cause as RSTOP_ERR_CFG so that we can detect
	 * the configuration error and go into maintenance, even though it is
	 * a "wait-style" svc.
	 */
	if (cause == RSTOP_ERR_CFG)
		new_state = RESTARTER_STATE_MAINT;
	else
		new_state = inst->ri_i.i_enabled ?
		    RESTARTER_STATE_OFFLINE : RESTARTER_STATE_DISABLED;

	switch (err = restarter_instance_update_states(local_handle, inst,
	    inst->ri_i.i_state, new_state, RERR_NONE, reason)) {
	case 0:
	case ECONNRESET:
		break;

	default:
		bad_error("restarter_instance_update_states", err);
	}

	info = startd_zalloc(sizeof (fork_info_t));

	info->sf_id = inst->ri_id;
	info->sf_method_type = METHOD_STOP;
	info->sf_event_type = re;
	info->sf_reason = reason;
	inst->ri_method_thread = startd_thread_create(method_thread, info);

	return (0);
}

/*
 * Returns
 *   ENOENT - fmri is not in instance_list
 *   0 - success
 *   ECONNRESET - success, though handle was rebound
 *   -1 - instance is in transition
 */
int
stop_instance_fmri(scf_handle_t *h, const char *fmri, uint_t flags)
{
	restarter_inst_t *rip;
	int r;

	rip = inst_lookup_by_name(fmri);
	if (rip == NULL)
		return (ENOENT);

	r = stop_instance(h, rip, flags);

	MUTEX_UNLOCK(&rip->ri_lock);

	return (r);
}

static void
unmaintain_instance(scf_handle_t *h, restarter_inst_t *rip,
    unmaint_cause_t cause)
{
	ctid_t ctid;
	scf_instance_t *inst;
	int r;
	uint_t tries = 0, msecs = ALLOC_DELAY;
	const char *cp;
	restarter_str_t	reason;

	assert(MUTEX_HELD(&rip->ri_lock));

	if (rip->ri_i.i_state != RESTARTER_STATE_MAINT) {
		log_error(LOG_DEBUG, "Restarter: "
		    "Ignoring maintenance off command because %s is not in the "
		    "maintenance state.\n", rip->ri_i.i_fmri);
		return;
	}

	switch (cause) {
	case RUNMAINT_CLEAR:
		cp = "clear requested";
		reason = restarter_str_clear_request;
		break;
	case RUNMAINT_DISABLE:
		cp = "disable requested";
		reason = restarter_str_disable_request;
		break;
	default:
#ifndef NDEBUG
		(void) fprintf(stderr, "Uncaught case for %d at %s:%d.\n",
		    cause, __FILE__, __LINE__);
#endif
		abort();
	}

	log_instance(rip, B_TRUE, "Leaving maintenance because %s.",
	    cp);
	log_framework(LOG_DEBUG, "%s: Instance leaving maintenance because "
	    "%s.\n", rip->ri_i.i_fmri, cp);

	(void) restarter_instance_update_states(h, rip, RESTARTER_STATE_UNINIT,
	    RESTARTER_STATE_NONE, RERR_RESTART, reason);

	/*
	 * If we did ADMIN_MAINT_ON_IMMEDIATE, then there might still be
	 * a primary contract.
	 */
	if (rip->ri_i.i_primary_ctid == 0)
		return;

	ctid = rip->ri_i.i_primary_ctid;
	contract_abandon(ctid);
	rip->ri_i.i_primary_ctid = 0;

rep_retry:
	switch (r = libscf_fmri_get_instance(h, rip->ri_i.i_fmri, &inst)) {
	case 0:
		break;

	case ECONNABORTED:
		libscf_handle_rebind(h);
		goto rep_retry;

	case ENOENT:
		/* Must have been deleted. */
		return;

	case EINVAL:
	case ENOTSUP:
	default:
		bad_error("libscf_handle_rebind", r);
	}

again:
	r = restarter_remove_contract(inst, ctid, RESTARTER_CONTRACT_PRIMARY);
	switch (r) {
	case 0:
		break;

	case ENOMEM:
		++tries;
		if (tries < ALLOC_RETRY) {
			(void) poll(NULL, 0, msecs);
			msecs *= ALLOC_DELAY_MULT;
			goto again;
		}

		uu_die("Insufficient memory.\n");
		/* NOTREACHED */

	case ECONNABORTED:
		scf_instance_destroy(inst);
		libscf_handle_rebind(h);
		goto rep_retry;

	case ECANCELED:
		break;

	case EPERM:
	case EACCES:
	case EROFS:
		log_error(LOG_INFO,
		    "Could not remove contract id %lu for %s (%s).\n", ctid,
		    rip->ri_i.i_fmri, strerror(r));
		break;

	case EINVAL:
	case EBADF:
	default:
		bad_error("restarter_remove_contract", r);
	}

	scf_instance_destroy(inst);
}

/*
 * enable_inst()
 *   Set inst->ri_i.i_enabled.  Expects 'e' to be _ENABLE, _DISABLE, or
 *   _ADMIN_DISABLE.  If the event is _ENABLE and inst is uninitialized or
 *   disabled, move it to offline.  If the event is _DISABLE or
 *   _ADMIN_DISABLE, make sure inst will move to disabled.
 *
 *   Returns
 *     0 - success
 *     ECONNRESET - h was rebound
 */
static int
enable_inst(scf_handle_t *h, restarter_inst_t *inst,
    restarter_instance_qentry_t *riq)
{
	restarter_instance_state_t state;
	restarter_event_type_t e = riq->riq_type;
	restarter_str_t reason = restarter_str_per_configuration;
	int r;

	assert(MUTEX_HELD(&inst->ri_lock));
	assert(e == RESTARTER_EVENT_TYPE_ADMIN_DISABLE ||
	    e == RESTARTER_EVENT_TYPE_DISABLE ||
	    e == RESTARTER_EVENT_TYPE_ENABLE);
	assert(instance_in_transition(inst) == 0);

	state = inst->ri_i.i_state;

	if (e == RESTARTER_EVENT_TYPE_ENABLE) {
		inst->ri_i.i_enabled = 1;

		if (state == RESTARTER_STATE_UNINIT ||
		    state == RESTARTER_STATE_DISABLED) {
			/*
			 * B_FALSE: Don't log an error if the log_instance()
			 * fails because it will fail on the miniroot before
			 * install-discovery runs.
			 */
			log_instance(inst, B_FALSE, "Enabled.");
			log_framework(LOG_DEBUG, "%s: Instance enabled.\n",
			    inst->ri_i.i_fmri);

			/*
			 * If we are coming from DISABLED, it was obviously an
			 * enable request. If we are coming from UNINIT, it may
			 * have been a sevice in MAINT that was cleared.
			 */
			if (riq->riq_reason == restarter_str_clear_request)
				reason = restarter_str_clear_request;
			else if (state == RESTARTER_STATE_DISABLED)
				reason = restarter_str_enable_request;
			(void) restarter_instance_update_states(h, inst,
			    RESTARTER_STATE_OFFLINE, RESTARTER_STATE_NONE,
			    RERR_NONE, reason);
		} else {
			log_framework(LOG_DEBUG, "Restarter: "
			    "Not changing state of %s for enable command.\n",
			    inst->ri_i.i_fmri);
		}
	} else {
		inst->ri_i.i_enabled = 0;

		switch (state) {
		case RESTARTER_STATE_ONLINE:
		case RESTARTER_STATE_DEGRADED:
			r = stop_instance(h, inst, RSTOP_DISABLE);
			return (r == ECONNRESET ? 0 : r);

		case RESTARTER_STATE_OFFLINE:
		case RESTARTER_STATE_UNINIT:
			if (inst->ri_i.i_primary_ctid != 0) {
				inst->ri_m_inst = safe_scf_instance_create(h);
				inst->ri_mi_deleted = B_FALSE;

				libscf_reget_instance(inst);
				method_remove_contract(inst, B_TRUE, B_TRUE);

				scf_instance_destroy(inst->ri_m_inst);
			}
			/* B_FALSE: See log_instance(..., "Enabled."); above */
			log_instance(inst, B_FALSE, "Disabled.");
			log_framework(LOG_DEBUG, "%s: Instance disabled.\n",
			    inst->ri_i.i_fmri);

			/*
			 * If we are coming from OFFLINE, it was obviously a
			 * disable request. But if we are coming from
			 * UNINIT, it may have been a disable request for a
			 * service in MAINT.
			 */
			if (riq->riq_reason == restarter_str_disable_request ||
			    state == RESTARTER_STATE_OFFLINE)
				reason = restarter_str_disable_request;
			(void) restarter_instance_update_states(h, inst,
			    RESTARTER_STATE_DISABLED, RESTARTER_STATE_NONE,
			    RERR_RESTART, reason);
			return (0);

		case RESTARTER_STATE_DISABLED:
			break;

		case RESTARTER_STATE_MAINT:
			/*
			 * We only want to pull the instance out of maintenance
			 * if the disable is on adminstrative request.  The
			 * graph engine sends _DISABLE events whenever a
			 * service isn't in the disabled state, and we don't
			 * want to pull the service out of maintenance if,
			 * for example, it is there due to a dependency cycle.
			 */
			if (e == RESTARTER_EVENT_TYPE_ADMIN_DISABLE)
				unmaintain_instance(h, inst, RUNMAINT_DISABLE);
			break;

		default:
#ifndef NDEBUG
			(void) fprintf(stderr, "Restarter instance %s has "
			    "unknown state %d.\n", inst->ri_i.i_fmri, state);
#endif
			abort();
		}
	}

	return (0);
}

static void
start_instance(scf_handle_t *local_handle, restarter_inst_t *inst,
    int32_t reason)
{
	fork_info_t *info;
	restarter_str_t	new_reason;

	assert(MUTEX_HELD(&inst->ri_lock));
	assert(instance_in_transition(inst) == 0);
	assert(inst->ri_method_thread == 0);

	log_framework(LOG_DEBUG, "%s: trying to start instance\n",
	    inst->ri_i.i_fmri);

	/*
	 * We want to keep the original reason for restarts and clear actions
	 */
	switch (reason) {
	case restarter_str_restart_request:
	case restarter_str_clear_request:
		new_reason = reason;
		break;
	default:
		new_reason = restarter_str_dependencies_satisfied;
	}

	/* Services in the disabled and maintenance state are ignored */
	if (inst->ri_i.i_state == RESTARTER_STATE_MAINT ||
	    inst->ri_i.i_state == RESTARTER_STATE_DISABLED ||
	    inst->ri_i.i_enabled == 0) {
		log_framework(LOG_DEBUG,
		    "%s: start_instance -> is maint/disabled\n",
		    inst->ri_i.i_fmri);
		return;
	}

	/* Already started instances are left alone */
	if (instance_started(inst) == 1) {
		log_framework(LOG_DEBUG,
		    "%s: start_instance -> is already started\n",
		    inst->ri_i.i_fmri);
		return;
	}

	log_framework(LOG_DEBUG, "%s: starting instance.\n", inst->ri_i.i_fmri);

	(void) restarter_instance_update_states(local_handle, inst,
	    inst->ri_i.i_state, RESTARTER_STATE_ONLINE, RERR_NONE, new_reason);

	info = startd_zalloc(sizeof (fork_info_t));

	info->sf_id = inst->ri_id;
	info->sf_method_type = METHOD_START;
	info->sf_event_type = RERR_NONE;
	info->sf_reason = new_reason;
	inst->ri_method_thread = startd_thread_create(method_thread, info);
}

static int
event_from_tty(scf_handle_t *h, restarter_inst_t *rip)
{
	scf_instance_t *inst;
	int ret = 0;

	if (libscf_fmri_get_instance(h, rip->ri_i.i_fmri, &inst))
		return (-1);

	ret = restarter_inst_ractions_from_tty(inst);

	scf_instance_destroy(inst);
	return (ret);
}

static boolean_t
restart_dump(scf_handle_t *h, restarter_inst_t *rip)
{
	scf_instance_t *inst;
	boolean_t ret = B_FALSE;

	if (libscf_fmri_get_instance(h, rip->ri_i.i_fmri, &inst))
		return (-1);

	if (restarter_inst_dump(inst) == 1)
		ret = B_TRUE;

	scf_instance_destroy(inst);
	return (ret);
}

static void
maintain_instance(scf_handle_t *h, restarter_inst_t *rip, int immediate,
    restarter_str_t reason)
{
	fork_info_t *info;
	scf_instance_t *scf_inst = NULL;

	assert(MUTEX_HELD(&rip->ri_lock));
	assert(reason != restarter_str_none);
	assert(rip->ri_method_thread == 0);

	log_instance(rip, B_TRUE, "Stopping for maintenance due to %s.",
	    restarter_get_str_short(reason));
	log_framework(LOG_DEBUG, "%s: stopping for maintenance due to %s.\n",
	    rip->ri_i.i_fmri, restarter_get_str_short(reason));

	/* Services in the maintenance state are ignored */
	if (rip->ri_i.i_state == RESTARTER_STATE_MAINT) {
		log_framework(LOG_DEBUG,
		    "%s: maintain_instance -> is already in maintenance\n",
		    rip->ri_i.i_fmri);
		return;
	}

	/*
	 * If reason state is restarter_str_service_request and
	 * restarter_actions/auxiliary_fmri property is set with a valid fmri,
	 * copy the fmri to restarter/auxiliary_fmri so svcs -x can use.
	 */
	if (reason == restarter_str_service_request &&
	    libscf_fmri_get_instance(h, rip->ri_i.i_fmri, &scf_inst) == 0) {
		if (restarter_inst_validate_ractions_aux_fmri(scf_inst) == 0) {
			if (restarter_inst_set_aux_fmri(scf_inst))
				log_framework(LOG_DEBUG, "%s: "
				    "restarter_inst_set_aux_fmri failed: ",
				    rip->ri_i.i_fmri);
		} else {
			log_framework(LOG_DEBUG, "%s: "
			    "restarter_inst_validate_ractions_aux_fmri "
			    "failed: ", rip->ri_i.i_fmri);

			if (restarter_inst_reset_aux_fmri(scf_inst))
				log_framework(LOG_DEBUG, "%s: "
				    "restarter_inst_reset_aux_fmri failed: ",
				    rip->ri_i.i_fmri);
		}
		scf_instance_destroy(scf_inst);
	}

	if (immediate || !instance_started(rip)) {
		if (rip->ri_i.i_primary_ctid != 0) {
			rip->ri_m_inst = safe_scf_instance_create(h);
			rip->ri_mi_deleted = B_FALSE;

			libscf_reget_instance(rip);
			method_remove_contract(rip, B_TRUE, B_TRUE);

			scf_instance_destroy(rip->ri_m_inst);
		}

		(void) restarter_instance_update_states(h, rip,
		    RESTARTER_STATE_MAINT, RESTARTER_STATE_NONE, RERR_RESTART,
		    reason);
		return;
	}

	(void) restarter_instance_update_states(h, rip, rip->ri_i.i_state,
	    RESTARTER_STATE_MAINT, RERR_NONE, reason);

	log_transition(rip, MAINT_REQUESTED);

	info = startd_zalloc(sizeof (*info));
	info->sf_id = rip->ri_id;
	info->sf_method_type = METHOD_STOP;
	info->sf_event_type = RERR_RESTART;
	info->sf_reason = reason;
	rip->ri_method_thread = startd_thread_create(method_thread, info);
}

static void
refresh_instance(scf_handle_t *h, restarter_inst_t *rip)
{
	scf_instance_t *inst;
	scf_snapshot_t *snap;
	fork_info_t *info;
	int r;

	assert(MUTEX_HELD(&rip->ri_lock));

	log_instance(rip, B_TRUE, "Rereading configuration.");
	log_framework(LOG_DEBUG, "%s: rereading configuration.\n",
	    rip->ri_i.i_fmri);

rep_retry:
	r = libscf_fmri_get_instance(h, rip->ri_i.i_fmri, &inst);
	switch (r) {
	case 0:
		break;

	case ECONNABORTED:
		libscf_handle_rebind(h);
		goto rep_retry;

	case ENOENT:
		/* Must have been deleted. */
		return;

	case EINVAL:
	case ENOTSUP:
	default:
		bad_error("libscf_fmri_get_instance", r);
	}

	snap = libscf_get_running_snapshot(inst);

	r = libscf_get_startd_properties(inst, snap, &rip->ri_flags,
	    &rip->ri_utmpx_prefix);
	switch (r) {
	case 0:
		log_framework(LOG_DEBUG, "%s is a %s-style service\n",
		    rip->ri_i.i_fmri, service_style(rip->ri_flags));
		break;

	case ECONNABORTED:
		scf_instance_destroy(inst);
		scf_snapshot_destroy(snap);
		libscf_handle_rebind(h);
		goto rep_retry;

	case ECANCELED:
	case ENOENT:
		/* Succeed in anticipation of REMOVE_INSTANCE. */
		break;

	default:
		bad_error("libscf_get_startd_properties", r);
	}

	if (instance_started(rip)) {
		/* Refresh does not change the state. */
		(void) restarter_instance_update_states(h, rip,
		    rip->ri_i.i_state, rip->ri_i.i_state, RERR_NONE,
		    restarter_str_refresh);

		info = startd_zalloc(sizeof (*info));
		info->sf_id = rip->ri_id;
		info->sf_method_type = METHOD_REFRESH;
		info->sf_event_type = RERR_REFRESH;
		info->sf_reason = NULL;

		assert(rip->ri_method_thread == 0);
		rip->ri_method_thread =
		    startd_thread_create(method_thread, info);
	}

	scf_snapshot_destroy(snap);
	scf_instance_destroy(inst);
}

const char *event_names[] = { "INVALID", "ADD_INSTANCE", "REMOVE_INSTANCE",
	"ENABLE", "DISABLE", "ADMIN_DEGRADED", "ADMIN_REFRESH",
	"ADMIN_RESTART", "ADMIN_MAINT_OFF", "ADMIN_MAINT_ON",
	"ADMIN_MAINT_ON_IMMEDIATE", "STOP", "START", "DEPENDENCY_CYCLE",
	"INVALID_DEPENDENCY", "ADMIN_DISABLE", "STOP_RESET"
};

/*
 * void *restarter_process_events()
 *
 *   Called in a separate thread to process the events on an instance's
 *   queue.  Empties the queue completely, and tries to keep the thread
 *   around for a little while after the queue is empty to save on
 *   startup costs.
 */
static void *
restarter_process_events(void *arg)
{
	scf_handle_t *h;
	restarter_instance_qentry_t *event;
	restarter_inst_t *rip;
	char *fmri = (char *)arg;
	struct timespec to;

	assert(fmri != NULL);

	h = libscf_handle_create_bound_loop();

	/* grab the queue lock */
	rip = inst_lookup_queue(fmri);
	if (rip == NULL)
		goto out;

again:

	while ((event = uu_list_first(rip->ri_queue)) != NULL) {
		restarter_inst_t *inst;

		/* drop the queue lock */
		MUTEX_UNLOCK(&rip->ri_queue_lock);

		/*
		 * Grab the inst lock -- this waits until any outstanding
		 * method finishes running.
		 */
		inst = inst_lookup_by_name(fmri);
		if (inst == NULL) {
			/* Getting deleted in the middle isn't an error. */
			goto cont;
		}

		assert(instance_in_transition(inst) == 0);

		/* process the event */
		switch (event->riq_type) {
		case RESTARTER_EVENT_TYPE_ENABLE:
		case RESTARTER_EVENT_TYPE_DISABLE:
			(void) enable_inst(h, inst, event);
			break;

		case RESTARTER_EVENT_TYPE_ADMIN_DISABLE:
			if (enable_inst(h, inst, event) == 0)
				reset_start_times(inst);
			break;

		case RESTARTER_EVENT_TYPE_REMOVE_INSTANCE:
			restarter_delete_inst(inst);
			inst = NULL;
			goto cont;

		case RESTARTER_EVENT_TYPE_STOP_RESET:
			reset_start_times(inst);
			/* FALLTHROUGH */
		case RESTARTER_EVENT_TYPE_STOP:
			(void) stop_instance(h, inst, RSTOP_DEPENDENCY);
			break;

		case RESTARTER_EVENT_TYPE_START:
			start_instance(h, inst, event->riq_reason);
			break;

		case RESTARTER_EVENT_TYPE_DEPENDENCY_CYCLE:
			maintain_instance(h, inst, 0,
			    restarter_str_dependency_cycle);
			break;

		case RESTARTER_EVENT_TYPE_INVALID_DEPENDENCY:
			maintain_instance(h, inst, 0,
			    restarter_str_invalid_dependency);
			break;

		case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON:
			if (event_from_tty(h, inst) == 0)
				maintain_instance(h, inst, 0,
				    restarter_str_service_request);
			else
				maintain_instance(h, inst, 0,
				    restarter_str_administrative_request);
			break;

		case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON_IMMEDIATE:
			if (event_from_tty(h, inst) == 0)
				maintain_instance(h, inst, 1,
				    restarter_str_service_request);
			else
				maintain_instance(h, inst, 1,
				    restarter_str_administrative_request);
			break;

		case RESTARTER_EVENT_TYPE_ADMIN_MAINT_OFF:
			unmaintain_instance(h, inst, RUNMAINT_CLEAR);
			reset_start_times(inst);
			break;

		case RESTARTER_EVENT_TYPE_ADMIN_REFRESH:
			refresh_instance(h, inst);
			break;

		case RESTARTER_EVENT_TYPE_ADMIN_DEGRADED:
			log_framework(LOG_WARNING, "Restarter: "
			    "%s command (for %s) unimplemented.\n",
			    event_names[event->riq_type], inst->ri_i.i_fmri);
			break;

		case RESTARTER_EVENT_TYPE_ADMIN_RESTART:
			if (!instance_started(inst)) {
				log_framework(LOG_DEBUG, "Restarter: "
				    "Not restarting %s; not running.\n",
				    inst->ri_i.i_fmri);
			} else {
				/*
				 * Stop the instance.  If it can be restarted,
				 * the graph engine will send a new event.
				 */
				if (restart_dump(h, inst)) {
					(void) contract_kill(
					    inst->ri_i.i_primary_ctid, SIGABRT,
					    inst->ri_i.i_fmri);
				} else if (stop_instance(h, inst,
				    RSTOP_RESTART) == 0) {
					reset_start_times(inst);
				}
			}
			break;

		case RESTARTER_EVENT_TYPE_ADD_INSTANCE:
		default:
#ifndef NDEBUG
			uu_warn("%s:%d: Bad restarter event %d.  "
			    "Aborting.\n", __FILE__, __LINE__, event->riq_type);
#endif
			abort();
		}

		assert(inst != NULL);
		MUTEX_UNLOCK(&inst->ri_lock);

cont:
		/* grab the queue lock */
		rip = inst_lookup_queue(fmri);
		if (rip == NULL)
			goto out;

		/* delete the event */
		uu_list_remove(rip->ri_queue, event);
		startd_free(event, sizeof (restarter_instance_qentry_t));
	}

	assert(rip != NULL);

	/*
	 * Try to preserve the thread for a little while for future use.
	 */
	to.tv_sec = 3;
	to.tv_nsec = 0;
	(void) pthread_cond_reltimedwait_np(&rip->ri_queue_cv,
	    &rip->ri_queue_lock, &to);

	if (uu_list_first(rip->ri_queue) != NULL)
		goto again;

	rip->ri_queue_thread = 0;
	MUTEX_UNLOCK(&rip->ri_queue_lock);

out:
	(void) scf_handle_unbind(h);
	scf_handle_destroy(h);
	free(fmri);
	return (NULL);
}

static int
is_admin_event(restarter_event_type_t t) {

	switch (t) {
	case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON:
	case RESTARTER_EVENT_TYPE_ADMIN_MAINT_ON_IMMEDIATE:
	case RESTARTER_EVENT_TYPE_ADMIN_MAINT_OFF:
	case RESTARTER_EVENT_TYPE_ADMIN_REFRESH:
	case RESTARTER_EVENT_TYPE_ADMIN_DEGRADED:
	case RESTARTER_EVENT_TYPE_ADMIN_RESTART:
		return (1);
	default:
		return (0);
	}
}

static void
restarter_queue_event(restarter_inst_t *ri, restarter_protocol_event_t *e)
{
	restarter_instance_qentry_t *qe;
	int r;

	assert(MUTEX_HELD(&ri->ri_queue_lock));
	assert(!MUTEX_HELD(&ri->ri_lock));

	qe = startd_zalloc(sizeof (restarter_instance_qentry_t));
	qe->riq_type = e->rpe_type;
	qe->riq_reason = e->rpe_reason;

	uu_list_node_init(qe, &qe->riq_link, restarter_queue_pool);
	r = uu_list_insert_before(ri->ri_queue, NULL, qe);
	assert(r == 0);
}

/*
 * void *restarter_event_thread()
 *
 *  Handle incoming graph events by placing them on a per-instance
 *  queue.  We can't lock the main part of the instance structure, so
 *  just modify the seprarately locked event queue portion.
 */
/*ARGSUSED*/
static void *
restarter_event_thread(void *unused)
{
	scf_handle_t *h;

	/*
	 * This is a new thread, and thus, gets its own handle
	 * to the repository.
	 */
	h = libscf_handle_create_bound_loop();

	MUTEX_LOCK(&ru->restarter_update_lock);

	/*CONSTCOND*/
	while (1) {
		restarter_protocol_event_t *e;

		while (ru->restarter_update_wakeup == 0)
			(void) pthread_cond_wait(&ru->restarter_update_cv,
			    &ru->restarter_update_lock);

		ru->restarter_update_wakeup = 0;

		while ((e = restarter_event_dequeue()) != NULL) {
			restarter_inst_t *rip;
			char *fmri;

			MUTEX_UNLOCK(&ru->restarter_update_lock);

			/*
			 * ADD_INSTANCE is special: there's likely no
			 * instance structure yet, so we need to handle the
			 * addition synchronously.
			 */
			switch (e->rpe_type) {
			case RESTARTER_EVENT_TYPE_ADD_INSTANCE:
				if (restarter_insert_inst(h, e->rpe_inst) != 0)
					log_error(LOG_INFO, "Restarter: "
					    "Could not add %s.\n", e->rpe_inst);

				MUTEX_LOCK(&st->st_load_lock);
				if (--st->st_load_instances == 0)
					(void) pthread_cond_broadcast(
					    &st->st_load_cv);
				MUTEX_UNLOCK(&st->st_load_lock);

				goto nolookup;
			}

			/*
			 * Lookup the instance, locking only the event queue.
			 * Can't grab ri_lock here because it might be held
			 * by a long-running method.
			 */
			rip = inst_lookup_queue(e->rpe_inst);
			if (rip == NULL) {
				log_error(LOG_INFO, "Restarter: "
				    "Ignoring %s command for unknown service "
				    "%s.\n", event_names[e->rpe_type],
				    e->rpe_inst);
				goto nolookup;
			}

			/* Keep ADMIN events from filling up the queue. */
			if (is_admin_event(e->rpe_type) &&
			    uu_list_numnodes(rip->ri_queue) >
			    RINST_QUEUE_THRESHOLD) {
				MUTEX_UNLOCK(&rip->ri_queue_lock);
				log_instance(rip, B_TRUE, "Instance event "
				    "queue overflow.  Dropping administrative "
				    "request.");
				log_framework(LOG_DEBUG, "%s: Instance event "
				    "queue overflow.  Dropping administrative "
				    "request.\n", rip->ri_i.i_fmri);
				goto nolookup;
			}

			/* Now add the event to the instance queue. */
			restarter_queue_event(rip, e);

			if (rip->ri_queue_thread == 0) {
				/*
				 * Start a thread if one isn't already
				 * running.
				 */
				fmri = safe_strdup(e->rpe_inst);
				rip->ri_queue_thread =  startd_thread_create(
				    restarter_process_events, (void *)fmri);
			} else {
				/*
				 * Signal the existing thread that there's
				 * a new event.
				 */
				(void) pthread_cond_broadcast(
				    &rip->ri_queue_cv);
			}

			MUTEX_UNLOCK(&rip->ri_queue_lock);
nolookup:
			restarter_event_release(e);

			MUTEX_LOCK(&ru->restarter_update_lock);
		}
	}

	/*
	 * Unreachable for now -- there's currently no graceful cleanup
	 * called on exit().
	 */
	(void) scf_handle_unbind(h);
	scf_handle_destroy(h);
	return (NULL);
}

static restarter_inst_t *
contract_to_inst(ctid_t ctid)
{
	restarter_inst_t *inst;
	int id;

	id = lookup_inst_by_contract(ctid);
	if (id == -1)
		return (NULL);

	inst = inst_lookup_by_id(id);
	if (inst != NULL) {
		/*
		 * Since ri_lock isn't held by the contract id lookup, this
		 * instance may have been restarted and now be in a new
		 * contract, making the old contract no longer valid for this
		 * instance.
		 */
		if (ctid != inst->ri_i.i_primary_ctid) {
			MUTEX_UNLOCK(&inst->ri_lock);
			inst = NULL;
		}
	}
	return (inst);
}

/*
 * void contract_action()
 *   Take action on contract events.
 */
static void
contract_action(scf_handle_t *h, restarter_inst_t *inst, ctid_t id,
    uint32_t type)
{
	const char *fmri = inst->ri_i.i_fmri;

	assert(MUTEX_HELD(&inst->ri_lock));

	/*
	 * If startd has stopped this contract, there is no need to
	 * stop it again.
	 */
	if (inst->ri_i.i_primary_ctid > 0 &&
	    inst->ri_i.i_primary_ctid_stopped)
		return;

	if ((type & (CT_PR_EV_EMPTY | CT_PR_EV_CORE | CT_PR_EV_SIGNAL
	    | CT_PR_EV_HWERR)) == 0) {
		/*
		 * There shouldn't be other events, since that's not how we set
		 * the terms. Thus, just log an error and drive on.
		 */
		log_framework(LOG_NOTICE,
		    "%s: contract %ld received unexpected critical event "
		    "(%d)\n", fmri, id, type);
		return;
	}

	assert(instance_in_transition(inst) == 0);

	if (instance_is_wait_style(inst)) {
		/*
		 * We ignore all events; if they impact the
		 * process we're monitoring, then the
		 * wait_thread will stop the instance.
		 */
		log_framework(LOG_DEBUG,
		    "%s: ignoring contract event on wait-style service\n",
		    fmri);
	} else {
		/*
		 * A CT_PR_EV_EMPTY event is an RSTOP_EXIT request.
		 */
		switch (type) {
		case CT_PR_EV_EMPTY:
			(void) stop_instance(h, inst, RSTOP_EXIT);
			break;
		case CT_PR_EV_CORE:
			(void) stop_instance(h, inst, RSTOP_CORE);
			break;
		case CT_PR_EV_SIGNAL:
			(void) stop_instance(h, inst, RSTOP_SIGNAL);
			break;
		case CT_PR_EV_HWERR:
			(void) stop_instance(h, inst, RSTOP_HWERR);
			break;
		}
	}
}

/*
 * void *restarter_contract_event_thread(void *)
 *   Listens to the process contract bundle for critical events, taking action
 *   on events from contracts we know we are responsible for.
 */
/*ARGSUSED*/
static void *
restarter_contracts_event_thread(void *unused)
{
	int fd, err;
	scf_handle_t *local_handle;

	/*
	 * Await graph load completion.  That is, stop here, until we've scanned
	 * the repository for contract - instance associations.
	 */
	MUTEX_LOCK(&st->st_load_lock);
	while (!(st->st_load_complete && st->st_load_instances == 0))
		(void) pthread_cond_wait(&st->st_load_cv, &st->st_load_lock);
	MUTEX_UNLOCK(&st->st_load_lock);

	/*
	 * This is a new thread, and thus, gets its own handle
	 * to the repository.
	 */
	if ((local_handle = libscf_handle_create_bound(SCF_VERSION)) == NULL)
		uu_die("Unable to bind a new repository handle: %s\n",
		    scf_strerror(scf_error()));

	fd = open64(CTFS_ROOT "/process/pbundle", O_RDONLY);
	if (fd == -1)
		uu_die("process bundle open failed");

	/*
	 * Make sure we get all events (including those generated by configd
	 * before this thread was started).
	 */
	err = ct_event_reset(fd);
	assert(err == 0);

	for (;;) {
		int efd, sfd;
		ct_evthdl_t ev;
		uint32_t type;
		ctevid_t evid;
		ct_stathdl_t status;
		ctid_t ctid;
		restarter_inst_t *inst;
		uint64_t cookie;

		if (err = ct_event_read_critical(fd, &ev)) {
			log_error(LOG_WARNING,
			    "Error reading next contract event: %s",
			    strerror(err));
			continue;
		}

		evid = ct_event_get_evid(ev);
		ctid = ct_event_get_ctid(ev);
		type = ct_event_get_type(ev);

		/* Fetch cookie. */
		if ((sfd = contract_open(ctid, "process", "status", O_RDONLY))
		    < 0) {
			ct_event_free(ev);
			continue;
		}

		if (err = ct_status_read(sfd, CTD_COMMON, &status)) {
			log_framework(LOG_WARNING, "Could not get status for "
			    "contract %ld: %s\n", ctid, strerror(err));

			startd_close(sfd);
			ct_event_free(ev);
			continue;
		}

		cookie = ct_status_get_cookie(status);

		log_framework(LOG_DEBUG, "Received event %d for ctid %ld "
		    "cookie %lld\n", type, ctid, cookie);

		ct_status_free(status);

		startd_close(sfd);

		/*
		 * svc.configd(1M) restart handling performed by the
		 * fork_configd_thread.  We don't acknowledge, as that thread
		 * will do so.
		 */
		if (cookie == CONFIGD_COOKIE) {
			ct_event_free(ev);
			continue;
		}

		inst = NULL;
		if (storing_contract != 0 &&
		    (inst = contract_to_inst(ctid)) == NULL) {
			/*
			 * This can happen for two reasons:
			 * - method_run() has not yet stored the
			 *    the contract into the internal hash table.
			 * - we receive an EMPTY event for an abandoned
			 *    contract.
			 * If there is any contract in the process of
			 * being stored into the hash table then re-read
			 * the event later.
			 */
			log_framework(LOG_DEBUG,
			    "Reset event %d for unknown "
			    "contract id %ld\n", type, ctid);

			/* don't go too fast */
			(void) poll(NULL, 0, 100);

			(void) ct_event_reset(fd);
			ct_event_free(ev);
			continue;
		}

		/*
		 * Do not call contract_to_inst() again if first
		 * call succeeded.
		 */
		if (inst == NULL)
			inst = contract_to_inst(ctid);
		if (inst == NULL) {
			/*
			 * This can happen if we receive an EMPTY
			 * event for an abandoned contract.
			 */
			log_framework(LOG_DEBUG,
			    "Received event %d for unknown contract id "
			    "%ld\n", type, ctid);
		} else {
			log_framework(LOG_DEBUG,
			    "Received event %d for contract id "
			    "%ld (%s)\n", type, ctid,
			    inst->ri_i.i_fmri);

			contract_action(local_handle, inst, ctid, type);

			MUTEX_UNLOCK(&inst->ri_lock);
		}

		efd = contract_open(ct_event_get_ctid(ev), "process", "ctl",
		    O_WRONLY);
		if (efd != -1) {
			(void) ct_ctl_ack(efd, evid);
			startd_close(efd);
		}

		ct_event_free(ev);

	}

	/*NOTREACHED*/
	return (NULL);
}

/*
 * Timeout queue, processed by restarter_timeouts_event_thread().
 */
timeout_queue_t *timeouts;
static uu_list_pool_t *timeout_pool;

typedef struct timeout_update {
	pthread_mutex_t		tu_lock;
	pthread_cond_t		tu_cv;
	int			tu_wakeup;
} timeout_update_t;

timeout_update_t *tu;

static const char *timeout_ovr_svcs[] = {
	"svc:/system/manifest-import:default",
	"svc:/network/initial:default",
	"svc:/network/service:default",
	"svc:/system/rmtmpfiles:default",
	"svc:/network/loopback:default",
	"svc:/network/physical:default",
	"svc:/system/device/local:default",
	"svc:/system/filesystem/usr:default",
	"svc:/system/filesystem/minimal:default",
	"svc:/system/filesystem/local:default",
	NULL
};

int
is_timeout_ovr(restarter_inst_t *inst)
{
	int i;

	for (i = 0; timeout_ovr_svcs[i] != NULL; ++i) {
		if (strcmp(inst->ri_i.i_fmri, timeout_ovr_svcs[i]) == 0) {
			log_instance(inst, B_TRUE, "Timeout override by "
			    "svc.startd.  Using infinite timeout.");
			return (1);
		}
	}

	return (0);
}

/*ARGSUSED*/
static int
timeout_compare(const void *lc_arg, const void *rc_arg, void *private)
{
	hrtime_t t1 = ((const timeout_entry_t *)lc_arg)->te_timeout;
	hrtime_t t2 = ((const timeout_entry_t *)rc_arg)->te_timeout;

	if (t1 > t2)
		return (1);
	else if (t1 < t2)
		return (-1);
	return (0);
}

void
timeout_init()
{
	timeouts = startd_zalloc(sizeof (timeout_queue_t));

	(void) pthread_mutex_init(&timeouts->tq_lock, &mutex_attrs);

	timeout_pool = startd_list_pool_create("timeouts",
	    sizeof (timeout_entry_t), offsetof(timeout_entry_t, te_link),
	    timeout_compare, UU_LIST_POOL_DEBUG);
	assert(timeout_pool != NULL);

	timeouts->tq_list = startd_list_create(timeout_pool,
	    timeouts, UU_LIST_SORTED);
	assert(timeouts->tq_list != NULL);

	tu = startd_zalloc(sizeof (timeout_update_t));
	(void) pthread_cond_init(&tu->tu_cv, NULL);
	(void) pthread_mutex_init(&tu->tu_lock, &mutex_attrs);
}

void
timeout_insert(restarter_inst_t *inst, ctid_t cid, uint64_t timeout_sec)
{
	hrtime_t now, timeout;
	timeout_entry_t *entry;
	uu_list_index_t idx;

	assert(MUTEX_HELD(&inst->ri_lock));

	now = gethrtime();

	/*
	 * If we overflow LLONG_MAX, we're never timing out anyways, so
	 * just return.
	 */
	if (timeout_sec >= (LLONG_MAX - now) / 1000000000LL) {
		log_instance(inst, B_TRUE, "timeout_seconds too large, "
		    "treating as infinite.");
		return;
	}

	/* hrtime is in nanoseconds. Convert timeout_sec. */
	timeout = now + (timeout_sec * 1000000000LL);

	entry = startd_alloc(sizeof (timeout_entry_t));
	entry->te_timeout = timeout;
	entry->te_ctid = cid;
	entry->te_fmri = safe_strdup(inst->ri_i.i_fmri);
	entry->te_logstem = safe_strdup(inst->ri_logstem);
	entry->te_fired = 0;
	/* Insert the calculated timeout time onto the queue. */
	MUTEX_LOCK(&timeouts->tq_lock);
	(void) uu_list_find(timeouts->tq_list, entry, NULL, &idx);
	uu_list_node_init(entry, &entry->te_link, timeout_pool);
	uu_list_insert(timeouts->tq_list, entry, idx);
	MUTEX_UNLOCK(&timeouts->tq_lock);

	assert(inst->ri_timeout == NULL);
	inst->ri_timeout = entry;

	MUTEX_LOCK(&tu->tu_lock);
	tu->tu_wakeup = 1;
	(void) pthread_cond_broadcast(&tu->tu_cv);
	MUTEX_UNLOCK(&tu->tu_lock);
}


void
timeout_remove(restarter_inst_t *inst, ctid_t cid)
{
	assert(MUTEX_HELD(&inst->ri_lock));

	if (inst->ri_timeout == NULL)
		return;

	assert(inst->ri_timeout->te_ctid == cid);

	MUTEX_LOCK(&timeouts->tq_lock);
	uu_list_remove(timeouts->tq_list, inst->ri_timeout);
	MUTEX_UNLOCK(&timeouts->tq_lock);

	free(inst->ri_timeout->te_fmri);
	free(inst->ri_timeout->te_logstem);
	startd_free(inst->ri_timeout, sizeof (timeout_entry_t));
	inst->ri_timeout = NULL;
}

static int
timeout_now()
{
	timeout_entry_t *e;
	hrtime_t now;
	int ret;

	now = gethrtime();

	/*
	 * Walk through the (sorted) timeouts list.  While the timeout
	 * at the head of the list is <= the current time, kill the
	 * method.
	 */
	MUTEX_LOCK(&timeouts->tq_lock);

	for (e = uu_list_first(timeouts->tq_list);
	    e != NULL && e->te_timeout <= now;
	    e = uu_list_next(timeouts->tq_list, e)) {
		log_framework(LOG_WARNING, "%s: Method or service exit timed "
		    "out.  Killing contract %ld.\n", e->te_fmri, e->te_ctid);
		log_instance_fmri(e->te_fmri, e->te_logstem, B_TRUE,
		    "Method or service exit timed out.  Killing contract %ld.",
		    e->te_ctid);
		e->te_fired = 1;
		(void) contract_kill(e->te_ctid, SIGKILL, e->te_fmri);
	}

	if (uu_list_numnodes(timeouts->tq_list) > 0)
		ret = 0;
	else
		ret = -1;

	MUTEX_UNLOCK(&timeouts->tq_lock);

	return (ret);
}

/*
 * void *restarter_timeouts_event_thread(void *)
 *   Responsible for monitoring the method timeouts.  This thread must
 *   be started before any methods are called.
 */
/*ARGSUSED*/
static void *
restarter_timeouts_event_thread(void *unused)
{
	/*
	 * Timeouts are entered on a priority queue, which is processed by
	 * this thread.  As timeouts are specified in seconds, we'll do
	 * the necessary processing every second, as long as the queue
	 * is not empty.
	 */

	/*CONSTCOND*/
	while (1) {
		/*
		 * As long as the timeout list isn't empty, process it
		 * every second.
		 */
		if (timeout_now() == 0) {
			(void) sleep(1);
			continue;
		}

		/* The list is empty, wait until we have more timeouts. */
		MUTEX_LOCK(&tu->tu_lock);

		while (tu->tu_wakeup == 0)
			(void) pthread_cond_wait(&tu->tu_cv, &tu->tu_lock);

		tu->tu_wakeup = 0;
		MUTEX_UNLOCK(&tu->tu_lock);
	}

	return (NULL);
}

void
restarter_start()
{
	(void) startd_thread_create(restarter_timeouts_event_thread, NULL);
	(void) startd_thread_create(restarter_event_thread, NULL);
	(void) startd_thread_create(restarter_contracts_event_thread, NULL);
	(void) startd_thread_create(wait_thread, NULL);
}


void
restarter_init()
{
	restarter_instance_pool = startd_list_pool_create("restarter_instances",
	    sizeof (restarter_inst_t), offsetof(restarter_inst_t,
	    ri_link), restarter_instance_compare, UU_LIST_POOL_DEBUG);
	(void) memset(&instance_list, 0, sizeof (instance_list));

	(void) pthread_mutex_init(&instance_list.ril_lock, &mutex_attrs);
	instance_list.ril_instance_list = startd_list_create(
	    restarter_instance_pool, &instance_list, UU_LIST_SORTED);

	restarter_queue_pool = startd_list_pool_create(
	    "restarter_instance_queue", sizeof (restarter_instance_qentry_t),
	    offsetof(restarter_instance_qentry_t,  riq_link), NULL,
	    UU_LIST_POOL_DEBUG);

	contract_list_pool = startd_list_pool_create(
	    "contract_list", sizeof (contract_entry_t),
	    offsetof(contract_entry_t,  ce_link), NULL,
	    UU_LIST_POOL_DEBUG);
	contract_hash_init();

	log_framework(LOG_DEBUG, "Initialized restarter\n");
}
