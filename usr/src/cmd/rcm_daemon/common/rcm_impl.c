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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <librcm_impl.h>
#include "rcm_impl.h"

static int query(char **, int, const char *, int, pid_t, uint_t, timespec_t *,
    int, rcm_info_t **, int *);
static void cancel_query(int, const char *, pid_t, uint_t, int);

/*
 * The following ops are invoked when modules initiate librcm calls which
 * require daemon processing. Cascaded RCM operations must come through
 * this path.
 */
librcm_ops_t rcm_ops = {
	add_resource_client,
	remove_resource_client,
	get_resource_info,
	process_resource_suspend,
	notify_resource_resume,
	process_resource_offline,
	notify_resource_online,
	notify_resource_remove,
	request_capacity_change,
	notify_capacity_change,
	notify_resource_event,
	get_resource_state
};

/*
 * Process a request or a notification on a subtree
 */
/*ARGSUSED2*/
static int
common_resource_op(int cmd, char *rsrcname, pid_t pid, uint_t flag, int seq_num,
    timespec_t *interval, nvlist_t *nvl, rcm_info_t **info)
{
	int error;
	rsrc_node_t *node;
	tree_walk_arg_t arg;

	/*
	 * Find the node (root of subtree) in the resource tree, invoke
	 * appropriate callbacks for all clients hanging off the subtree,
	 * and mark the subtree with the appropriate state.
	 *
	 * NOTE: It's possible the node doesn't exist, which means no RCM
	 * consumer registered for the resource. In this case we silently
	 * succeed.
	 */
	error = rsrc_node_find(rsrcname, 0, &node);
	if ((error == RCM_SUCCESS) && (node != NULL)) {
		arg.flag = flag;
		arg.info = info;
		arg.seq_num = seq_num;
		arg.interval = interval;
		arg.nvl = nvl;
		arg.cmd = cmd;

		if ((cmd == CMD_NOTIFY_CHANGE) ||
		    (cmd == CMD_REQUEST_CHANGE) ||
		    (cmd == CMD_EVENT)) {
			error = rsrc_client_action_list(node->users, cmd, &arg);
		} else {
			error = rsrc_tree_action(node, cmd, &arg);
		}
	} else if ((error == RCM_SUCCESS) && (flag & RCM_RETIRE_REQUEST)) {
		/*
		 * No matching node, so no client. This means there
		 * is no constraint (RCM wise) on this retire. Return
		 * RCM_NO_CONSTRAINT to indicate this
		 */
		rcm_log_message(RCM_TRACE1, "No client. Returning "
		    "RCM_NO_CONSTRAINT: %s\n", rsrcname);
		error = RCM_NO_CONSTRAINT;
	}

	return (error);
}

/*
 * When a resource is removed, notify all clients who registered for this
 * particular resource.
 */
int
notify_resource_remove(char **rsrcnames, pid_t pid, uint_t flag, int seq_num,
    rcm_info_t **info)
{
	int i;
	int error;
	int retval = RCM_SUCCESS;

	for (i = 0; rsrcnames[i] != NULL; i++) {

		rcm_log_message(RCM_TRACE2,
		    "notify_resource_remove(%s, %ld, 0x%x, %d)\n", rsrcnames[i],
		    pid, flag, seq_num);

		/*
		 * Mark state as issuing removal notification. Return failure
		 * if no DR request for this node exists.
		 */
		error = dr_req_update(rsrcnames[i], pid, flag,
		    RCM_STATE_REMOVING, seq_num, info);
		if (error != RCM_SUCCESS) {
			retval = error;
			continue;
		}

		error = common_resource_op(CMD_REMOVE, rsrcnames[i], pid, flag,
		    seq_num, NULL, NULL, info);

		/*
		 * delete the request entry from DR list
		 */
		dr_req_remove(rsrcnames[i], flag);

		if (error != RCM_SUCCESS)
			retval = error;
	}

	return (retval);
}

/*
 * Notify users that a resource has been resumed
 */
int
notify_resource_resume(char **rsrcnames, pid_t pid, uint_t flag, int seq_num,
    rcm_info_t **info)
{
	int i;
	int error;
	rcm_info_t *state_info;
	rcm_info_tuple_t *state_tuple;
	int retval = RCM_SUCCESS;

	for (i = 0; rsrcnames[i] != NULL; i++) {

		state_info = NULL;
		state_tuple = NULL;

		/* Check resource state (was resource actually suspended?) */
		if (get_resource_state(rsrcnames[i], pid, &state_info) ||
		    ((state_tuple = rcm_info_next(state_info, NULL)) == NULL) ||
		    (rcm_info_state(state_tuple) == RCM_STATE_SUSPEND))
			flag |= RCM_SUSPENDED;
		if (state_info)
			rcm_free_info(state_info);

		rcm_log_message(RCM_TRACE2,
		    "notify_resource_resume(%s, %ld, 0x%x, %d)\n",
		    rsrcnames[i], pid, flag, seq_num);

		/*
		 * Mark state as sending resumption notifications
		 */
		error = dr_req_update(rsrcnames[i], pid, flag,
		    RCM_STATE_RESUMING, seq_num, info);
		if (error != RCM_SUCCESS) {
			retval = error;
			continue;
		}

		error = common_resource_op(CMD_RESUME, rsrcnames[i], pid, flag,
		    seq_num, NULL, NULL, info);

		dr_req_remove(rsrcnames[i], flag);

		if (error != RCM_SUCCESS)
			retval = error;
	}

	return (retval);
}

/*
 * Notify users that an offlined device is again available
 */
int
notify_resource_online(char **rsrcnames, pid_t pid, uint_t flag, int seq_num,
    rcm_info_t **info)
{
	int i;
	int error;
	int retval = RCM_SUCCESS;

	for (i = 0; rsrcnames[i] != NULL; i++) {

		rcm_log_message(RCM_TRACE2,
		    "notify_resource_online(%s, %ld, 0x%x, %d)\n",
		    rsrcnames[i], pid, flag, seq_num);

		/*
		 * Mark state as sending onlining notifications
		 */
		error = dr_req_update(rsrcnames[i], pid, flag,
		    RCM_STATE_ONLINING, seq_num, info);
		if (error != RCM_SUCCESS) {
			retval = error;
			continue;
		}

		error = common_resource_op(CMD_ONLINE, rsrcnames[i], pid, flag,
		    seq_num, NULL, NULL, info);

		dr_req_remove(rsrcnames[i], flag);

		if (error != RCM_SUCCESS)
			retval = error;
	}

	return (retval);
}

/*
 * For offline and suspend, need to get the logic correct here. There are
 * several cases:
 *
 * 1. It is a door call and RCM_QUERY is not set:
 *	run a QUERY; if that succeeds, run the operation.
 *
 * 2. It is a door call and RCM_QUERY is set:
 *	run the QUERY only.
 *
 * 3. It is not a door call:
 *	run the call, but look at the flag to see if the
 *	lock should be kept.
 */

/*
 * Request permission to suspend a resource
 */
int
process_resource_suspend(char **rsrcnames, pid_t pid, uint_t flag, int seq_num,
    timespec_t *interval, rcm_info_t **info)
{
	int i;
	int error = RCM_SUCCESS;
	int is_doorcall = ((seq_num & SEQ_NUM_MASK) == 0);

	/*
	 * Query the operation first.  The return value of the query indicates
	 * if the operation should proceed and be implemented.
	 */
	if (query(rsrcnames, CMD_SUSPEND, "suspend", RCM_STATE_SUSPEND_QUERYING,
	    pid, flag, interval, seq_num, info, &error) == 0) {
		return (error);
	}

	/*
	 * Implement the operation.
	 */
	for (i = 0; rsrcnames[i] != NULL; i++) {

		/* Update the lock from a query state to the suspending state */
		if ((error = dr_req_update(rsrcnames[i], pid, flag,
		    RCM_STATE_SUSPENDING, seq_num, info)) != RCM_SUCCESS) {

			rcm_log_message(RCM_DEBUG,
			    "suspend %s denied with error %d\n", rsrcnames[i],
			    error);

			/*
			 * When called from a module, don't return EAGAIN.
			 * This is to avoid recursion if module always retries.
			 */
			if (!is_doorcall && error == EAGAIN) {
				return (RCM_CONFLICT);
			}

			return (error);
		}

		/* Actually suspend the resource */
		error = common_resource_op(CMD_SUSPEND, rsrcnames[i], pid,
		    flag, seq_num, interval, NULL, info);
		if (error != RCM_SUCCESS) {
			(void) dr_req_update(rsrcnames[i], pid, flag,
			    RCM_STATE_SUSPEND_FAIL, seq_num, info);
			rcm_log_message(RCM_DEBUG,
			    "suspend tree failed for %s\n", rsrcnames[i]);
			return (error);
		}

		rcm_log_message(RCM_TRACE3, "suspend tree succeeded for %s\n",
		    rsrcnames[i]);

		/* Update the lock for the successful suspend */
		(void) dr_req_update(rsrcnames[i], pid, flag,
		    RCM_STATE_SUSPEND, seq_num, info);
	}

	return (RCM_SUCCESS);
}

/*
 * Process a device removal request, reply is needed
 */
int
process_resource_offline(char **rsrcnames, pid_t pid, uint_t flag, int seq_num,
    rcm_info_t **info)
{
	int i;
	int error = RCM_SUCCESS;
	int is_doorcall = ((seq_num & SEQ_NUM_MASK) == 0);

	/*
	 * Query the operation first.  The return value of the query indicates
	 * if the operation should proceed and be implemented.
	 */
	if (query(rsrcnames, CMD_OFFLINE, "offline", RCM_STATE_OFFLINE_QUERYING,
	    pid, flag, NULL, seq_num, info, &error) == 0) {
		return (error);
	}

	/*
	 * Implement the operation.
	 */
	for (i = 0; rsrcnames[i] != NULL; i++) {

		error = dr_req_update(rsrcnames[i], pid, flag,
		    RCM_STATE_OFFLINING, seq_num, info);
		if (error != RCM_SUCCESS) {
			rcm_log_message(RCM_DEBUG,
			    "offline %s denied with error %d\n", rsrcnames[i],
			    error);

			/*
			 * When called from a module, don't return EAGAIN.
			 * This is to avoid recursion if module always retries.
			 */
			if (!is_doorcall && error == EAGAIN) {
				return (RCM_CONFLICT);
			}

			return (error);
		}

		/* Actually offline the resource */
		error = common_resource_op(CMD_OFFLINE, rsrcnames[i], pid,
		    flag, seq_num, NULL, NULL, info);
		if (error != RCM_SUCCESS) {
			(void) dr_req_update(rsrcnames[i], pid, flag,
			    RCM_STATE_OFFLINE_FAIL, seq_num, info);
			rcm_log_message(RCM_DEBUG,
			    "offline tree failed for %s\n", rsrcnames[i]);
			return (error);
		}

		rcm_log_message(RCM_TRACE3, "offline tree succeeded for %s\n",
		    rsrcnames[i]);

		/* Update the lock for the successful offline */
		(void) dr_req_update(rsrcnames[i], pid, flag,
		    RCM_STATE_OFFLINE, seq_num, info);
	}

	return (RCM_SUCCESS);
}

/*
 * Add a resource client who wishes to interpose on DR, events, or capacity.
 * Reply needed.
 */
int
add_resource_client(char *modname, char *rsrcname, pid_t pid, uint_t flag,
    rcm_info_t **infop)
{
	int error = RCM_SUCCESS;
	client_t *user = NULL;
	rsrc_node_t *node = NULL;
	rcm_info_t *info = NULL;

	rcm_log_message(RCM_TRACE2,
	    "add_resource_client(%s, %s, %ld, 0x%x)\n",
	    modname, rsrcname, pid, flag);

	if (strcmp(rsrcname, "/") == 0) {
		/*
		 * No need to register for /  because it will never go away.
		 */
		rcm_log_message(RCM_INFO, gettext(
		    "registering for / by %s has been turned into a no-op\n"),
		    modname);
		return (RCM_SUCCESS);
	}

	/*
	 * Hold the rcm_req_lock so no dr request may come in while the
	 * registration is in progress.
	 */
	(void) mutex_lock(&rcm_req_lock);

	/*
	 * Test if the requested registration is a noop, and return EALREADY
	 * if it is.
	 */
	error = rsrc_node_find(rsrcname, RSRC_NODE_CREATE, &node);
	if ((error != RCM_SUCCESS) || (node == NULL)) {
		(void) mutex_unlock(&rcm_req_lock);
		return (RCM_FAILURE);
	}

	user = rsrc_client_find(modname, pid, &node->users);
	if ((user != NULL) &&
	    ((user->flag & (flag & RCM_REGISTER_MASK)) != 0)) {
		(void) mutex_unlock(&rcm_req_lock);
		if ((flag & RCM_REGISTER_DR) &&
		    (user->state == RCM_STATE_REMOVE)) {
			user->state = RCM_STATE_ONLINE;
			return (RCM_SUCCESS);
		}
		return (EALREADY);
	}

	/* If adding a new DR registration, reject if the resource is locked */
	if (flag & RCM_REGISTER_DR) {

		if (rsrc_check_lock_conflicts(rsrcname, flag, LOCK_FOR_USE,
		    &info) != RCM_SUCCESS) {
			/*
			 * The resource is being DR'ed, so return failure
			 */
			(void) mutex_unlock(&rcm_req_lock);

			/*
			 * If caller doesn't care about info, free it
			 */
			if (infop)
				*infop = info;
			else
				rcm_free_info(info);

			return (RCM_CONFLICT);
		}
	}

	/* The registration is new and allowable, so add it */
	error = rsrc_node_add_user(node, rsrcname, modname, pid, flag);
	(void) mutex_unlock(&rcm_req_lock);

	return (error);
}

/*
 * Remove a resource client, who no longer wishes to interpose on either
 * DR, events, or capacity.
 */
int
remove_resource_client(char *modname, char *rsrcname, pid_t pid, uint_t flag)
{
	int error;
	rsrc_node_t *node;

	rcm_log_message(RCM_TRACE2,
	    "remove_resource_client(%s, %s, %ld, 0x%x)\n",
	    modname, rsrcname, pid, flag);

	/*
	 * Allow resource client to leave anytime, assume client knows what
	 * it is trying to do.
	 */
	error = rsrc_node_find(rsrcname, 0, &node);
	if ((error != RCM_SUCCESS) || (node == NULL)) {
		rcm_log_message(RCM_WARNING,
		    gettext("resource %s not found\n"), rsrcname);
		return (ENOENT);
	}

	return (rsrc_node_remove_user(node, modname, pid, flag));
}

/*
 * Reply is needed
 */
int
get_resource_info(char **rsrcnames, uint_t flag, int seq_num, rcm_info_t **info)
{
	int rv = RCM_SUCCESS;

	if (flag & RCM_DR_OPERATION) {
		*info = rsrc_dr_info();
	} else if (flag & RCM_MOD_INFO) {
		*info = rsrc_mod_info();
	} else {
		rv = rsrc_usage_info(rsrcnames, flag, seq_num, info);
	}

	return (rv);
}

int
notify_resource_event(char *rsrcname, id_t pid, uint_t flag, int seq_num,
    nvlist_t *event_data, rcm_info_t **info)
{
	int error;

	assert(flag == 0);

	rcm_log_message(RCM_TRACE2, "notify_resource_event(%s, %ld, 0x%x)\n",
	    rsrcname, pid, flag);

	error = common_resource_op(CMD_EVENT, rsrcname, pid, flag, seq_num,
	    NULL, event_data, info);

	return (error);
}

int
request_capacity_change(char *rsrcname, id_t pid, uint_t flag, int seq_num,
    nvlist_t *nvl, rcm_info_t **info)
{
	int error;
	int is_doorcall = ((seq_num & SEQ_NUM_MASK) == 0);

	rcm_log_message(RCM_TRACE2,
	    "request_capacity_change(%s, %ld, 0x%x, %d)\n", rsrcname, pid,
	    flag, seq_num);

	if (is_doorcall || (flag & RCM_QUERY)) {

		error = common_resource_op(CMD_REQUEST_CHANGE, rsrcname, pid,
		    flag | RCM_QUERY, seq_num, NULL, nvl, info);

		if (error != RCM_SUCCESS) {
			rcm_log_message(RCM_DEBUG,
			    "request state change query denied\n");
			return (error);
		}
	}

	if (flag & RCM_QUERY)
		return (RCM_SUCCESS);

	error = common_resource_op(CMD_REQUEST_CHANGE, rsrcname, pid, flag,
	    seq_num, NULL, nvl, info);

	if (error != RCM_SUCCESS) {
		rcm_log_message(RCM_DEBUG, "request state change failed\n");
		return (RCM_FAILURE);
	}

	rcm_log_message(RCM_TRACE3, "request state change succeeded\n");

	return (error);
}

int
notify_capacity_change(char *rsrcname, id_t pid, uint_t flag, int seq_num,
    nvlist_t *nvl, rcm_info_t **info)
{
	int error;

	rcm_log_message(RCM_TRACE2,
	    "notify_capacity_change(%s, %ld, 0x%x, %d)\n", rsrcname, pid,
	    flag, seq_num);

	error = common_resource_op(CMD_NOTIFY_CHANGE, rsrcname, pid, flag,
	    seq_num, NULL, nvl, info);

	if (error != RCM_SUCCESS) {
		rcm_log_message(RCM_DEBUG, "notify state change failed\n");
		return (RCM_FAILURE);
	}

	rcm_log_message(RCM_TRACE3, "notify state change succeeded\n");

	return (error);
}

int
get_resource_state(char *rsrcname, pid_t pid, rcm_info_t **info)
{
	int error;
	int state;
	char *s;
	char *resolved;
	rcm_info_t *dr_info = NULL;
	rcm_info_tuple_t *dr_info_tuple = NULL;
	rsrc_node_t *node;
	client_t *client;
	char *state_info = gettext("State of resource");

	rcm_log_message(RCM_TRACE2, "get_resource_state(%s, %ld)\n",
	    rsrcname, pid);

	/*
	 * Check for locks, first.
	 */
	dr_info = rsrc_dr_info();
	if (dr_info) {
		state = RCM_STATE_UNKNOWN;
		if ((resolved = resolve_name(rsrcname)) == NULL)
			return (RCM_FAILURE);
		while (dr_info_tuple = rcm_info_next(dr_info, dr_info_tuple)) {
			s = (char *)rcm_info_rsrc(dr_info_tuple);
			if (s && (strcmp(resolved, s) == 0)) {
				state = rcm_info_state(dr_info_tuple);
				break;
			}
		}
		free(resolved);
		rcm_free_info(dr_info);
		if (state != RCM_STATE_UNKNOWN) {
			rcm_log_message(RCM_TRACE2,
			    "get_resource_state(%s)=%d\n", rsrcname, state);
			add_busy_rsrc_to_list(rsrcname, pid, state, 0, NULL,
			    (char *)state_info, NULL, NULL, info);
			return (RCM_SUCCESS);
		}
	}

	/*
	 * No locks, so look for client states in the resource tree.
	 *
	 * NOTE: It's possible the node doesn't exist, which means no RCM
	 * consumer registered for the resource. In this case we silently
	 * succeed.
	 */
	error = rsrc_node_find(rsrcname, 0, &node);
	state = RCM_STATE_ONLINE;

	if ((error == RCM_SUCCESS) && (node != NULL)) {
		for (client = node->users; client; client = client->next) {
			if (client->state == RCM_STATE_OFFLINE_FAIL ||
			    client->state == RCM_STATE_OFFLINE_QUERY_FAIL ||
			    client->state == RCM_STATE_SUSPEND_FAIL ||
			    client->state == RCM_STATE_SUSPEND_QUERY_FAIL) {
				state = client->state;
				break;
			}

			if (client->state != RCM_STATE_ONLINE &&
			    client->state != RCM_STATE_REMOVE)
				state = client->state;
		}
	}

	if (error == RCM_SUCCESS) {
		rcm_log_message(RCM_TRACE2, "get_resource_state(%s)=%d\n",
		    rsrcname, state);
		add_busy_rsrc_to_list(rsrcname, pid, state, 0, NULL,
		    (char *)state_info, NULL, NULL, info);
	}

	return (error);
}

/*
 * Perform a query of an offline or suspend.
 *
 * The return value of this function indicates whether the operation should
 * be implemented (0 == No, 1 == Yes).  Note that locks and client state
 * changes will only persist if the caller is going to implement the operation.
 */
static int
query(char **rsrcnames, int cmd, const char *opname, int querystate, pid_t pid,
    uint_t flag, timespec_t *interval, int seq_num, rcm_info_t **info,
    int *errorp)
{
	int	i;
	int	error;
	int	final_error;
	int	is_doorcall = ((seq_num & SEQ_NUM_MASK) == 0);

	/* Only query for door calls, or when the RCM_QUERY flag is set */
	if ((is_doorcall == 0) && ((flag & RCM_QUERY) == 0)) {
		return (1);
	}

	/* Lock all the resources.  Fail the query in the case of a conflict. */
	for (i = 0; rsrcnames[i] != NULL; i++) {

		rcm_log_message(RCM_TRACE2,
		    "process_resource_%s(%s, %ld, 0x%x, %d)\n",
		    opname, rsrcnames[i], pid, flag, seq_num);

		error = dr_req_add(rsrcnames[i], pid, flag, querystate, seq_num,
		    NULL, info);

		/* The query goes no further if a resource cannot be locked */
		if (error != RCM_SUCCESS) {

			rcm_log_message(RCM_DEBUG,
			    "%s query %s defined with error %d\n",
			    opname, rsrcnames[i], error);

			/*
			 * Replace EAGAIN with RCM_CONFLICT in the case of
			 * module callbacks; to avoid modules from trying
			 * again infinitely.
			 */
			if ((is_doorcall == 0) && (error == EAGAIN)) {
				error = RCM_CONFLICT;
			}

			goto finished;
		}
	}

	/*
	 * All the resources were locked above, so use common_resource_op()
	 * to pass the query on to the clients.  Accumulate the overall error
	 * value in 'final_error', before transferring it to 'error' at the end.
	 */
	for (final_error = RCM_SUCCESS, i = 0; rsrcnames[i] != NULL; i++) {

		/* Log the query (for tracing purposes). */
		rcm_log_message(RCM_TRACE2, "querying resource %s\n",
		    rsrcnames[i]);

		/* Query the resource's clients through common_resource_op(). */
		error = common_resource_op(cmd, rsrcnames[i], pid,
		    flag | RCM_QUERY, seq_num, interval, NULL, info);

		/*
		 * If a query fails, don't stop iterating through the loop.
		 * Just ensure that 'final_error' is set (if not already),
		 * log the error, and continue looping.
		 *
		 * In the case of a user who manually intervenes and retries
		 * the operation, this will maximize the extent of the query
		 * so that they experience fewer such iterations overall.
		 */
		if (error != RCM_SUCCESS) {

			/* Log each query that failed along the way */
			rcm_log_message(RCM_DEBUG, "%s %s query denied\n",
			    opname, rsrcnames[i]);

			if (final_error != RCM_FAILURE) {
				final_error = error;
			}
		}
	}
	error = final_error;

	/*
	 * Tell the calling function not to proceed any further with the
	 * implementation phase of the operation if the query failed, or
	 * if the user's intent was to only query the operation.
	 */
finished:
	if ((error != RCM_SUCCESS) || ((flag & RCM_QUERY) != 0)) {

		/*
		 * Since the operation won't be implemented, cancel the
		 * query (unlock resources and reverse client state changes).
		 *
		 * The cancellation routine cleans up everything for the entire
		 * operation, and thus it should only be called from the very
		 * root of the operation (e.g. when 'is_doorcall' is TRUE).
		 */
		if (is_doorcall != 0) {
			cancel_query(cmd, opname, pid, flag, seq_num);
		}

		*errorp = error;
		return (0);
	}

	/* Otherwise, tell the caller to proceed with the implementation. */
	*errorp = RCM_SUCCESS;
	return (1);
}

/*
 * Implementation of a query cancellation.
 *
 * The full scope of the query is already noted, so the scope of the operation
 * does not need to be expanded in the same recursive manner that was used for
 * the query itself.  (Clients don't have to be called to cross namespaces.)
 * Instead, the locks added to the DR request list during the query are scanned.
 */
static void
cancel_query(int cmd, const char *opname, pid_t pid, uint_t flag, int seq_num)
{
	char	rsrc[MAXPATHLEN];

	/*
	 * Find every lock in the DR request list that is a part of this
	 * sequence.  Call common_resource_op() with the QUERY_CANCEL flag to
	 * cancel each sub-operation, and then remove each lock from the list.
	 *
	 * The 'rsrc' buffer is required to retrieve the 'device' fields of
	 * matching DR request list entries in a way that's multi-thread safe.
	 */
	while (dr_req_lookup(seq_num, rsrc) == RCM_SUCCESS) {

		rcm_log_message(RCM_TRACE2, "%s query %s cancelled\n",
		    opname, rsrc);

		(void) common_resource_op(cmd, rsrc, pid,
		    flag | RCM_QUERY | RCM_QUERY_CANCEL, seq_num, NULL, NULL,
		    NULL);

		(void) dr_req_remove(rsrc, flag);
	}
}
