/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "rcm_impl.h"
#include "rcm_module.h"

/*
 * Global locks
 */
mutex_t rcm_req_lock;	/* protects global dr & info request list */

/*
 * Daemon state file
 */
static int state_fd;
#define	RCM_STATE_FILE	"/var/run/rcm_daemon_state"
#define	N_REQ_CHUNK	10	/* grow 10 entries at a time */

/*
 * Daemon timeout value
 */
#define	RCM_DAEMON_TIMEOUT	300	/* 5 minutes idle time */

/*
 * Struct for a list of outstanding rcm requests
 */
typedef struct {
	int	seq_num;		/* sequence number of request */
	int	state;			/* current state */
	pid_t	pid;			/* pid of initiator */
	uint_t	flag;			/* request flags */
	int	type;			/* resource(device) type */
	timespec_t interval;		/* suspend interval */
	char	device[MAXPATHLEN];	/* name of device or resource */
} req_t;

typedef struct {
	int	n_req;
	int	n_req_max;	/* number of req_t's to follow */
	int	n_seq_max;	/* last sequence number */
	int	idle_timeout;	/* persist idle timeout value */
	req_t	req[1];
	/* more req_t follows */
} req_list_t;

static req_list_t *dr_req_list;
static req_list_t *info_req_list;

static const char *locked_info = "DR operation in progress";
static const char *locked_err = "Resource is busy";

static int rcmd_get_state();
static void add_to_polling_list(pid_t);
static void remove_from_polling_list(pid_t);

void start_polling_thread();
static void stop_polling_thread();

/*
 * Initialize request lists required for locking
 */
void
rcmd_lock_init(void)
{
	int size;
	struct stat fbuf;

	/*
	 * Start info list with one slot, then grow on demand.
	 */
	info_req_list = s_calloc(1, sizeof (req_list_t));
	info_req_list->n_req_max = 1;

	/*
	 * Open daemon state file and map in contents
	 */
	state_fd = open(RCM_STATE_FILE, O_CREAT|O_RDWR, 0600);
	if (state_fd == -1) {
		rcm_log_message(RCM_ERROR, gettext("cannot open %s: %s\n"),
		    RCM_STATE_FILE, strerror(errno));
		rcmd_exit(errno);
	}

	if (fstat(state_fd, &fbuf) != 0) {
		rcm_log_message(RCM_ERROR, gettext("cannot stat %s: %s\n"),
		    RCM_STATE_FILE, strerror(errno));
		rcmd_exit(errno);
	}

	size = fbuf.st_size;
	if (size == 0) {
		size = sizeof (req_list_t);
		if (ftruncate(state_fd, size) != 0) {
			rcm_log_message(RCM_ERROR,
			    gettext("cannot truncate %s: %s\n"),
			    RCM_STATE_FILE, strerror(errno));
			rcmd_exit(errno);
		}
	}

	/*LINTED*/
	dr_req_list = (req_list_t *)mmap(NULL, size, PROT_READ|PROT_WRITE,
	    MAP_SHARED, state_fd, 0);
	if (dr_req_list == MAP_FAILED) {
		rcm_log_message(RCM_ERROR, gettext("cannot mmap %s: %s\n"),
		    RCM_STATE_FILE, strerror(errno));
		rcmd_exit(errno);
	}

	/*
	 * Initial size is one entry
	 */
	if (dr_req_list->n_req_max == 0) {
		dr_req_list->n_req_max = 1;
		(void) fsync(state_fd);
		return;
	}

	rcm_log_message(RCM_DEBUG, "n_req = %d, n_req_max = %d\n",
	    dr_req_list->n_req, dr_req_list->n_req_max);

	/*
	 * Recover the daemon state
	 */
	clean_dr_list();
}

/*
 * Get a unique sequence number--to be called with rcm_req_lock held.
 */
static int
get_seq_number()
{
	int number;

	if (dr_req_list == NULL)
		return (0);

	dr_req_list->n_seq_max++;
	number  = (dr_req_list->n_seq_max << SEQ_NUM_SHIFT);
	(void) fsync(state_fd);

	return (number);
}

/*
 * Find entry in list with the same resource name and sequence number.
 * If seq_num == -1, no seq_num matching is required.
 */
static req_t *
find_req_entry(char *device, uint_t flag, int seq_num, req_list_t *list)
{
	int i;

	/*
	 * Look for entry with the same resource and seq_num.
	 * Also match RCM_FILESYS field in flag.
	 */
	for (i = 0; i < list->n_req_max; i++) {
		if (list->req[i].state == RCM_STATE_REMOVE)
			/* stale entry */
			continue;
		/*
		 * We need to distiguish a file system root from the directory
		 * it is mounted on.
		 *
		 * Applications are not aware of any difference between the
		 * two, but the system keeps track of it internally by
		 * checking for mount points while traversing file path.
		 * In a similar spirit, RCM is keeping this difference as
		 * an implementation detail.
		 */
		if ((strcmp(device, list->req[i].device) != 0) ||
		    (list->req[i].flag & RCM_FILESYS) != (flag & RCM_FILESYS))
			/* different resource */
			continue;

		if ((seq_num != -1) && ((seq_num >> SEQ_NUM_SHIFT) !=
		    (list->req[i].seq_num >> SEQ_NUM_SHIFT)))
			/* different base seqnum */
			continue;

		return (&list->req[i]);
	}

	return (NULL);
}

/*
 * Get the next empty req_t entry. If no entry exists, grow the list.
 */
static req_t *
get_req_entry(req_list_t **listp)
{
	int i;
	int n_req = (*listp)->n_req;
	int n_req_max = (*listp)->n_req_max;

	/*
	 * If the list is full, grow the list and return the first
	 * entry in the new portion.
	 */
	if (n_req == n_req_max) {
		int newsize;

		n_req_max += N_REQ_CHUNK;
		newsize = sizeof (req_list_t) + (n_req_max - 1) *
		    sizeof (req_t);

		if (listp == &info_req_list) {
			*listp = s_realloc(*listp, newsize);
		} else if (ftruncate(state_fd, newsize) != 0) {
			rcm_log_message(RCM_ERROR,
			    gettext("cannot truncate %s: %s\n"),
			    RCM_STATE_FILE, strerror(errno));
			rcmd_exit(errno);
		/*LINTED*/
		} else if ((*listp = (req_list_t *)mmap(NULL, newsize,
		    PROT_READ|PROT_WRITE, MAP_SHARED, state_fd, 0)) ==
		    MAP_FAILED) {
			rcm_log_message(RCM_ERROR,
			    gettext("cannot mmap %s: %s\n"),
			    RCM_STATE_FILE, strerror(errno));
			rcmd_exit(errno);
		}

		/* Initialize the new entries */
		for (i = (*listp)->n_req_max; i < n_req_max; i++) {
			(*listp)->req[i].state = RCM_STATE_REMOVE;
			(void) strcpy((*listp)->req[i].device, "");
		}

		(*listp)->n_req_max = n_req_max;
		(*listp)->n_req++;
		return (&(*listp)->req[n_req]);
	}

	/*
	 * List contains empty slots, find it.
	 */
	for (i = 0; i < n_req_max; i++) {
		if (((*listp)->req[i].device[0] == '\0') ||
		    ((*listp)->req[i].state == RCM_STATE_REMOVE)) {
			break;
		}
	}

	assert(i < n_req_max);	/* empty slot must exist */

	(*listp)->n_req++;
	return (&(*listp)->req[i]);
}

/*
 * When one resource depends on multiple resources, it's possible that
 * rcm_get_info can be called multiple times on the resource, resulting
 * in duplicate information. By assigning a unique sequence number to
 * each rcm_get_info operation, this duplication can be eliminated.
 *
 * Insert a dr entry in info_req_list
 */
int
info_req_add(char *rsrcname, uint_t flag, int seq_num)
{
	int error = 0;
	char *device;
	req_t *req;

	rcm_log_message(RCM_TRACE2, "info_req_add(%s, %d)\n",
	    rsrcname, seq_num);

	device = resolve_name(rsrcname);
	(void) mutex_lock(&rcm_req_lock);

	/*
	 * Look for entry with the same resource and seq_num.
	 * If it exists, we return an error so that such
	 * information is not gathered more than once.
	 */
	if (find_req_entry(device, flag, seq_num, info_req_list) != NULL) {
		rcm_log_message(RCM_DEBUG, "getinfo cycle: %s %d \n",
		    device, seq_num);
		error = -1;
		goto out;
	}

	/*
	 * Get empty entry and fill in seq_num and device.
	 */
	req = get_req_entry(&info_req_list);
	req->seq_num = seq_num;
	req->state = RCM_STATE_ONLINE;  /* mark that the entry is in use */
	req->flag = flag;
	(void) strcpy(req->device, device);

out:
	(void) mutex_unlock(&rcm_req_lock);
	free(device);

	return (error);
}

/*
 * Remove all entries associated with seq_num from info_req_list
 */
void
info_req_remove(int seq_num)
{
	int i;

	rcm_log_message(RCM_TRACE3, "info_req_remove(%d)\n", seq_num);

	seq_num >>= SEQ_NUM_SHIFT;
	(void) mutex_lock(&rcm_req_lock);

	/* remove all entries with seq_num */
	for (i = 0; i < info_req_list->n_req_max; i++) {
		if (info_req_list->req[i].state == RCM_STATE_REMOVE)
			continue;

		if ((info_req_list->req[i].seq_num >> SEQ_NUM_SHIFT) != seq_num)
			continue;

		info_req_list->req[i].state = RCM_STATE_REMOVE;
		info_req_list->n_req--;
	}

	/*
	 * We don't shrink the info_req_list size for now.
	 */
	(void) mutex_unlock(&rcm_req_lock);
}

/*
 * Checking lock conflicts. There is a conflict if:
 * - attempt to DR a node when either its ancester or descendent
 *	is in the process of DR
 * - attempt to register for a node when its ancester is locked for DR
 */
static int
check_lock(char *device, uint_t flag, int cflag, rcm_info_t **info)
{
	int i, ret = RCM_SUCCESS;

	if (info)
		*info = NULL;

	/*
	 * During daemon initialization, don't check locks
	 */
	if (dr_req_list == NULL)
		return (ret);

	for (i = 0; i < dr_req_list->n_req; i++) {
		req_t *req = &dr_req_list->req[i];
		char *dr_dev = req->device;

		/*
		 * Skip empty entries
		 */
		if ((req->state == RCM_STATE_REMOVE) || (dr_dev[0] == '\0'))
			continue;

		/*
		 * Make sure that none of the ancestors of dr_dev is
		 * being operated upon.
		 */
		if (EQUAL(device, dr_dev) || DESCENDENT(device, dr_dev)) {
			/*
			 * An exception to this is the filesystem.
			 * We should allowed a filesystem rooted at a
			 * child directory to be unmounted.
			 */
			if ((flag & RCM_FILESYS) && (!EQUAL(device, dr_dev) ||
			    ((dr_req_list->req[i].flag & RCM_FILESYS) == 0)))
				continue;

			assert(info != 0);

			add_busy_rsrc_to_list(dr_dev, dr_req_list->req[i].pid,
			    dr_req_list->req[i].state,
			    dr_req_list->req[i].seq_num, NULL, locked_info,
			    locked_err, NULL, info);
			ret = RCM_CONFLICT;
			break;
		}

		if ((cflag == LOCK_FOR_DR) && DESCENDENT(dr_dev, device)) {
			/*
			 * Check descendents only for DR request.
			 *
			 * Could have multiple descendents doing DR,
			 * we want to find them all.
			 */
			assert(info != 0);

			add_busy_rsrc_to_list(dr_dev, dr_req_list->req[i].pid,
			    dr_req_list->req[i].state,
			    dr_req_list->req[i].seq_num, NULL, locked_info,
			    locked_err, NULL, info);
			ret = RCM_CONFLICT;
			/* don't break here, need to find all conflicts */
		}
	}

	return (ret);
}

/*
 * Check for lock conflicts for DR operation or client registration
 */
int
rsrc_check_lock_conflicts(char *rsrcname, uint_t flag, int cflag,
    rcm_info_t **info)
{
	int result;
	char *device;

	device = resolve_name(rsrcname);
	result = check_lock(device, flag, cflag, info);
	free(device);

	return (result);
}

static int
transition_state(int state)
{
	/*
	 * If the resource state is in transition, ask caller to
	 * try again.
	 */
	switch (state) {
	case RCM_STATE_OFFLINING:
	case RCM_STATE_SUSPENDING:
	case RCM_STATE_RESUMING:
	case RCM_STATE_ONLINING:
	case RCM_STATE_REMOVING:

		return (1);

	default:
		/*FALLTHROUGH*/
		break;
	}
	return (0);
}

/*
 * Update a dr entry in dr_req_list
 */
/*ARGSUSED*/
static int
dr_req_update_entry(char *device, pid_t pid, uint_t flag, int state,
    int seq_num, timespec_t *interval, rcm_info_t **infop)
{
	req_t *req;

	/*
	 * Find request entry. If not found, return RCM_FAILURE
	 */
	req = find_req_entry(device, flag, -1, dr_req_list);

	if (req == NULL) {
		switch (state) {
		case RCM_STATE_OFFLINE_QUERYING:
		case RCM_STATE_SUSPEND_QUERYING:
		case RCM_STATE_OFFLINING:
		case RCM_STATE_SUSPENDING:
			/* could be re-do operation, no error message */
			break;

		default:
			rcm_log_message(RCM_DEBUG,
			    "update non-existing resource %s\n", device);
		}
		return (RCM_FAILURE);
	}

	/*
	 * During initialization, update is unconditional (forced)
	 * in order to bring the daemon up in a sane state.
	 */
	if (rcmd_get_state() == RCMD_INIT)
		goto update;

	/*
	 * Don't allow update with mismatched initiator pid. This could happen
	 * as part of normal operation.
	 */
	if (pid != req->pid) {
		rcm_log_message(RCM_INFO,
		    gettext("mismatched dr initiator pid: %ld %ld\n"),
		    req->pid, pid);
		goto failure;
	}

	rcm_log_message(RCM_TRACE4,
	    "dr_req_update_entry: state=%d, device=%s\n",
	    req->state, req->device);

	/*
	 * Check that the state transition is valid
	 */
	switch (state) {
	case RCM_STATE_OFFLINE_QUERYING:
	case RCM_STATE_OFFLINING:
		/*
		 * This is the case of re-offlining, which applies only
		 * if a previous attempt failed.
		 */
		if ((req->state != RCM_STATE_OFFLINE_FAIL) &&
		    (req->state != RCM_STATE_OFFLINE_QUERYING) &&
		    (req->state != RCM_STATE_OFFLINE_QUERY) &&
		    (req->state != RCM_STATE_OFFLINE_QUERY_FAIL) &&
		    (req->state != RCM_STATE_OFFLINE)) {
			rcm_log_message(RCM_WARNING,
			    gettext("%s: invalid offlining from state %d\n"),
			    device, req->state);
			goto failure;
		}
		break;

	case RCM_STATE_SUSPEND_QUERYING:
	case RCM_STATE_SUSPENDING:
		/*
		 * This is the case of re-suspending, which applies only
		 * if a previous attempt failed.
		 */
		if ((req->state != RCM_STATE_SUSPEND_FAIL) &&
		    (req->state != RCM_STATE_SUSPEND_QUERYING) &&
		    (req->state != RCM_STATE_SUSPEND_QUERY) &&
		    (req->state != RCM_STATE_SUSPEND_QUERY_FAIL) &&
		    (req->state != RCM_STATE_SUSPEND)) {
			rcm_log_message(RCM_WARNING,
			    gettext("%s: invalid suspending from state %d\n"),
			    device, req->state);
			goto failure;
		}
		break;

	case RCM_STATE_RESUMING:
		if ((req->state != RCM_STATE_SUSPEND) &&
		    (req->state != RCM_STATE_SUSPEND_QUERYING) &&
		    (req->state != RCM_STATE_SUSPEND_QUERY) &&
		    (req->state != RCM_STATE_SUSPEND_QUERY_FAIL) &&
		    (req->state != RCM_STATE_SUSPEND_FAIL)) {
			rcm_log_message(RCM_DEBUG,
			    "%s: invalid resuming from state %d\n",
			    device, req->state);
			goto failure;
		}
		break;

	case RCM_STATE_ONLINING:
		if ((req->state != RCM_STATE_OFFLINE) &&
		    (req->state != RCM_STATE_OFFLINE_QUERYING) &&
		    (req->state != RCM_STATE_OFFLINE_QUERY) &&
		    (req->state != RCM_STATE_OFFLINE_QUERY_FAIL) &&
		    (req->state != RCM_STATE_OFFLINE_FAIL)) {
			rcm_log_message(RCM_INFO,
			    gettext("%s: invalid onlining from state %d\n"),
			    device, req->state);
			goto failure;
		}
		break;

	case RCM_STATE_REMOVING:
		if ((req->state != RCM_STATE_OFFLINE) &&
		    (req->state != RCM_STATE_OFFLINE_FAIL)) {
			rcm_log_message(RCM_INFO,
			    gettext("%s: invalid removing from state %d\n"),
			    device, req->state);
			goto failure;
		}
		break;

	case RCM_STATE_SUSPEND_FAIL:
		assert(req->state == RCM_STATE_SUSPENDING);
		break;

	case RCM_STATE_OFFLINE_FAIL:
		assert(req->state == RCM_STATE_OFFLINING);
		break;

	case RCM_STATE_SUSPEND:
		assert(req->state == RCM_STATE_SUSPENDING);
		break;

	case RCM_STATE_OFFLINE:
		assert(req->state == RCM_STATE_OFFLINING);
		break;

	case RCM_STATE_ONLINE:
		assert((req->state == RCM_STATE_RESUMING) ||
		    (req->state == RCM_STATE_ONLINING));
		break;

	default:	/* shouldn't be here */
		rcm_log_message(RCM_ERROR,
		    gettext("invalid update to dr state: %d\n"), state);
		return (RCM_FAILURE);
	}

update:
	/*
	 * update the state, interval, and sequence number; sync state file
	 */
	req->state = state;
	req->seq_num = seq_num;

	if (interval)
		req->interval = *interval;
	else
		bzero(&req->interval, sizeof (timespec_t));

	(void) fsync(state_fd);
	return (RCM_SUCCESS);

failure:
	if (infop != NULL) {
		add_busy_rsrc_to_list(req->device, req->pid, req->state,
		    req->seq_num, NULL, locked_info, locked_err, NULL, infop);
	}

	/*
	 * A request may be left in a transition state because the operator
	 * typed ctrl-C. In this case, the daemon thread continues to run
	 * and will eventually put the state in a non-transitional state.
	 *
	 * To be safe, we return EAGAIN to allow librcm to loop and retry.
	 * If we are called from a module, loop & retry could result in a
	 * deadlock. The called will check for this case and turn EAGAIN
	 * into RCM_CONFLICT.
	 */
	if (transition_state(req->state)) {
		return (EAGAIN);
	}

	return (RCM_CONFLICT);
}

/*
 * Insert a dr entry in dr_req_list
 */
int
dr_req_add(char *rsrcname, pid_t pid, uint_t flag, int state, int seq_num,
    timespec_t *interval, rcm_info_t **info)
{
	int error;
	char *device;
	req_t *req;

	rcm_log_message(RCM_TRACE3, "dr_req_add(%s, %ld, 0x%x, %d, %d, %p)\n",
	    rsrcname, pid, flag, state, seq_num, (void *)info);

	device = resolve_name(rsrcname);
	if (device == NULL)
		return (EINVAL);

	(void) mutex_lock(&rcm_req_lock);

	/*
	 * In the re-offline/suspend case, attempt to update dr request.
	 *
	 * If this succeeds, return success;
	 * If this fails because of a conflict, return error;
	 * If this this fails because no entry exists, add a new entry.
	 */
	error = dr_req_update_entry(device, pid, flag, state, seq_num, interval,
	    info);

	switch (error) {
	case RCM_FAILURE:
		/* proceed to add a new entry */
		break;

	case RCM_CONFLICT:
	case RCM_SUCCESS:
	case EAGAIN:
	default:
		goto out;
	}

	/*
	 * Check for lock conflicts
	 */
	error = check_lock(device, flag, LOCK_FOR_DR, info);
	if (error != RCM_SUCCESS) {
		error = RCM_CONFLICT;
		goto out;
	}

	/*
	 * Get empty request entry, fill in values and sync state file
	 */
	req = get_req_entry(&dr_req_list);

	req->seq_num = seq_num;
	req->pid = pid;
	req->flag = flag;
	req->state = state;
	req->type = rsrc_get_type(device);
	(void) strcpy(req->device, device);

	/* cache interval for failure recovery */
	if (interval)
		req->interval = *interval;
	else
		bzero(&req->interval, sizeof (timespec_t));

	(void) fsync(state_fd);

	/*
	 * Add initiator pid to polling list
	 */
	add_to_polling_list(req->pid);

out:
	(void) mutex_unlock(&rcm_req_lock);
	free(device);

	return (error);
}

/*
 * Update a dr entry in dr_req_list
 */
/*ARGSUSED*/
int
dr_req_update(char *rsrcname, pid_t pid, uint_t flag, int state, int seq_num,
    rcm_info_t **info)
{
	int error;
	char *device = resolve_name(rsrcname);

	rcm_log_message(RCM_TRACE3, "dr_req_update(%s, %ld, 0x%x, %d, %d)\n",
	    rsrcname, pid, flag, state, seq_num);

	(void) mutex_lock(&rcm_req_lock);
	error = dr_req_update_entry(device, pid, flag, state, seq_num, NULL,
	    info);
	(void) mutex_unlock(&rcm_req_lock);
	free(device);

	return (error);
}

/*
 * This function scans the DR request list for the next, non-removed
 * entry that is part of the specified sequence.  The 'device' name
 * of the entry is copied into the provided 'rsrc' buffer.
 *
 * The 'rsrc' buffer is required because the DR request list is only
 * locked during the duration of this lookup.  Giving a direct pointer
 * to something in the list would be unsafe.
 */
int
dr_req_lookup(int seq_num, char *rsrc)
{
	int	i;
	int	len;
	int	base = (seq_num >> SEQ_NUM_SHIFT);
	int	retval = RCM_FAILURE;

	if (rsrc == NULL) {
		return (RCM_FAILURE);
	}

	(void) mutex_lock(&rcm_req_lock);

	for (i = 0; i < dr_req_list->n_req_max; i++) {

		/* Skip removed or non-matching entries */
		if ((dr_req_list->req[i].state == RCM_STATE_REMOVE) ||
		    ((dr_req_list->req[i].seq_num >> SEQ_NUM_SHIFT) != base)) {
			continue;
		}

		/* Copy the next-matching 'device' name into 'rsrc' */
		len = strlcpy(rsrc, dr_req_list->req[i].device, MAXPATHLEN);
		if (len < MAXPATHLEN) {
			retval = RCM_SUCCESS;
		}
		break;
	}

	(void) mutex_unlock(&rcm_req_lock);

	return (retval);
}

/*
 * Remove a dr entry in dr_req_list
 */
void
dr_req_remove(char *rsrcname, uint_t flag)
{
	req_t *req;
	char *device = resolve_name(rsrcname);

	rcm_log_message(RCM_TRACE3, "dr_req_remove(%s)\n", rsrcname);

	(void) mutex_lock(&rcm_req_lock);

	/* find entry */
	req = find_req_entry(device, flag, -1, dr_req_list);
	free(device);

	if (req == NULL) {
		(void) mutex_unlock(&rcm_req_lock);
		rcm_log_message(RCM_WARNING,
		    gettext("dr_req entry %s not found\n"), rsrcname);
		return;
	}

	req->state = RCM_STATE_REMOVE;
	dr_req_list->n_req--;
	(void) fsync(state_fd);

	/*
	 * remove pid from polling list
	 */
	remove_from_polling_list(req->pid);

	/*
	 * We don't shrink the dr_req_list size for now.
	 * Shouldn't cause big memory leaks.
	 */
	(void) mutex_unlock(&rcm_req_lock);
}

/*
 * Return the list of ongoing dr operation requests
 */
rcm_info_t *
rsrc_dr_info()
{
	int i;
	rcm_info_t *info;
	rcm_info_t *result = NULL;
	char *rsrc;
	int len;

	rcm_log_message(RCM_TRACE2, "rsrc_dr_info()\n");

	(void) mutex_lock(&rcm_req_lock);
	for (i = 0; i < dr_req_list->n_req_max; i++) {
		if (dr_req_list->req[i].state == RCM_STATE_REMOVE)
			continue;

		if (dr_req_list->req[i].device[0] == '\0')
			continue;

		if (dr_req_list->req[i].flag & RCM_FILESYS) {
			len = strlen(dr_req_list->req[i].device) + 5;
			rsrc = s_malloc(len);
			(void) snprintf(rsrc, len, "%s(fs)",
			    dr_req_list->req[i].device);
		} else {
			rsrc = s_strdup(dr_req_list->req[i].device);
		}

		info = s_calloc(1, sizeof (*info));
		if (errno = nvlist_alloc(&(info->info), NV_UNIQUE_NAME, 0)) {
			rcm_log_message(RCM_ERROR,
			    gettext("failed (nvlist_alloc=%s).\n"),
			    strerror(errno));
			rcmd_exit(errno);
		}

		if (errno = nvlist_add_string(info->info, RCM_RSRCNAME, rsrc)) {
			rcm_log_message(RCM_ERROR,
			    gettext("failed (nvlist_add=%s).\n"),
			    strerror(errno));
			rcmd_exit(errno);
		}
		(void) free(rsrc);

		if (errno = nvlist_add_int64(info->info, RCM_CLIENT_ID,
		    dr_req_list->req[i].pid)) {
			rcm_log_message(RCM_ERROR,
			    gettext("failed (nvlist_add=%s).\n"),
			    strerror(errno));
			rcmd_exit(errno);
		}

		if (errno = nvlist_add_int32(info->info, RCM_SEQ_NUM,
		    dr_req_list->req[i].seq_num)) {
			rcm_log_message(RCM_ERROR,
			    gettext("failed (nvlist_add=%s).\n"),
			    strerror(errno));
			rcmd_exit(errno);
		}

		if (errno = nvlist_add_int32(info->info, RCM_RSRCSTATE,
		    dr_req_list->req[i].state)) {
			rcm_log_message(RCM_ERROR,
			    gettext("failed (nvlist_add=%s).\n"),
			    strerror(errno));
			rcmd_exit(errno);
		}

		if (errno = nvlist_add_string(info->info, RCM_CLIENT_INFO,
		    (char *)locked_info)) {
			rcm_log_message(RCM_ERROR,
			    gettext("failed (nvlist_add=%s).\n"),
			    strerror(errno));
			rcmd_exit(errno);
		}

		info->next = result;
		result = info;
	}
	(void) mutex_unlock(&rcm_req_lock);

	return (result);
}

/*
 * Eliminate entries whose dr initiator is no longer running
 * and recover daemon state during daemon restart.
 *
 * This routine is called from either during daemon initialization
 * after all modules have registered resources or from the cleanup
 * thread. In either case, it is the only thread running in the
 * daemon.
 */
void
clean_dr_list()
{
	int i;
	struct clean_list {
		struct clean_list *next;
		char *rsrcname;
		pid_t pid;
		int seq_num;
		int state;
		timespec_t interval;
	} *tmp, *list = NULL;
	char *rsrcnames[2];

	rcm_log_message(RCM_TRACE3,
	    "clean_dr_list(): look for stale dr initiators\n");

	rsrcnames[1] = NULL;

	/*
	 * Make a list of entries to recover. This is necessary because
	 * the recovery operation will modify dr_req_list.
	 */
	(void) mutex_lock(&rcm_req_lock);
	for (i = 0; i < dr_req_list->n_req_max; i++) {
		/* skip empty entries */
		if (dr_req_list->req[i].state == RCM_STATE_REMOVE)
			continue;

		if (dr_req_list->req[i].device[0] == '\0')
			continue;

		/* skip cascade operations */
		if (dr_req_list->req[i].seq_num & SEQ_NUM_MASK)
			continue;

		/*
		 * In the cleanup case, ignore entries with initiators alive
		 */
		if ((rcmd_get_state() == RCMD_CLEANUP) &&
		    proc_exist(dr_req_list->req[i].pid))
			continue;

		rcm_log_message(RCM_TRACE1,
		    "found stale entry: %s\n", dr_req_list->req[i].device);

		tmp = s_malloc(sizeof (*tmp));
		tmp->rsrcname = s_strdup(dr_req_list->req[i].device);
		tmp->state = dr_req_list->req[i].state;
		tmp->pid = dr_req_list->req[i].pid;
		tmp->seq_num = dr_req_list->req[i].seq_num;
		tmp->interval = dr_req_list->req[i].interval;
		tmp->next = list;
		list = tmp;
	}
	(void) mutex_unlock(&rcm_req_lock);

	if (list == NULL)
		return;

	/*
	 * If everything worked normally, we shouldn't be here.
	 * Since we are here, something went wrong, so say something.
	 */
	if (rcmd_get_state() == RCMD_INIT) {
		rcm_log_message(RCM_NOTICE, gettext("rcm_daemon died "
		    "unexpectedly, recovering previous daemon state\n"));
	} else {
		rcm_log_message(RCM_INFO, gettext("one or more dr initiator "
		    "died, attempting automatic recovery\n"));
	}

	while (list) {
		tmp = list;
		list = tmp->next;

		switch (tmp->state) {
		case RCM_STATE_OFFLINE_QUERY:
		case RCM_STATE_OFFLINE_QUERY_FAIL:
			rsrcnames[0] = tmp->rsrcname;
			if (proc_exist(tmp->pid)) {
				/* redo */
				(void) process_resource_offline(rsrcnames,
				    tmp->pid, RCM_QUERY, tmp->seq_num, NULL);
			} else {
				/* undo */
				(void) notify_resource_online(rsrcnames,
				    tmp->pid, 0, tmp->seq_num, NULL);
			}
			break;

		case RCM_STATE_OFFLINE:
		case RCM_STATE_OFFLINE_FAIL:
			rsrcnames[0] = tmp->rsrcname;
			if (proc_exist(tmp->pid)) {
				/* redo */
				(void) process_resource_offline(rsrcnames,
				    tmp->pid, 0, tmp->seq_num, NULL);
			} else {
				/* undo */
				(void) notify_resource_online(rsrcnames,
				    tmp->pid, 0, tmp->seq_num, NULL);
			}
			break;

		case RCM_STATE_SUSPEND_QUERY:
		case RCM_STATE_SUSPEND_QUERY_FAIL:
			rsrcnames[0] = tmp->rsrcname;
			if (proc_exist(tmp->pid)) {
				/* redo */
				(void) process_resource_suspend(rsrcnames,
				    tmp->pid, RCM_QUERY, tmp->seq_num,
				    &tmp->interval, NULL);
			} else {
				/* undo */
				(void) notify_resource_resume(rsrcnames,
				    tmp->pid, 0, tmp->seq_num, NULL);
			}
			break;

		case RCM_STATE_SUSPEND:
		case RCM_STATE_SUSPEND_FAIL:
			rsrcnames[0] = tmp->rsrcname;
			if (proc_exist(tmp->pid)) {
				/* redo */
				(void) process_resource_suspend(rsrcnames,
				    tmp->pid, 0, tmp->seq_num, &tmp->interval,
				    NULL);
			} else {
				/* undo */
				(void) notify_resource_resume(rsrcnames,
				    tmp->pid, 0, tmp->seq_num, NULL);
			}
			break;

		case RCM_STATE_OFFLINING:
		case RCM_STATE_ONLINING:
			rsrcnames[0] = tmp->rsrcname;
			(void) notify_resource_online(rsrcnames, tmp->pid, 0,
			    tmp->seq_num, NULL);
			break;

		case RCM_STATE_SUSPENDING:
		case RCM_STATE_RESUMING:
			rsrcnames[0] = tmp->rsrcname;
			(void) notify_resource_resume(rsrcnames, tmp->pid, 0,
			    tmp->seq_num, NULL);
			break;

		case RCM_STATE_REMOVING:
			rsrcnames[0] = tmp->rsrcname;
			(void) notify_resource_remove(rsrcnames, tmp->pid, 0,
			    tmp->seq_num, NULL);
			break;

		default:
			rcm_log_message(RCM_WARNING,
			    gettext("%s in unknown state %d\n"),
			    tmp->rsrcname, tmp->state);
			break;
		}
		free(tmp->rsrcname);
		free(tmp);
	}
}

/*
 * Selected thread blocking based on event type
 */
barrier_t barrier;

/*
 * Change barrier state:
 *	RCMD_INIT - daemon is intializing, only register allowed
 *	RCMD_NORMAL - normal daemon processing
 *	RCMD_CLEANUP - cleanup thread is waiting or running
 */
int
rcmd_get_state()
{
	return (barrier.state);
}

void
rcmd_set_state(int state)
{
	/*
	 * The state transition is as follows:
	 *	INIT --> NORMAL <---> CLEANUP
	 * The implementation favors the cleanup thread
	 */

	(void) mutex_lock(&barrier.lock);
	barrier.state = state;

	switch (state) {
	case RCMD_CLEANUP:
		/*
		 * Wait for existing threads to exit
		 */
		barrier.wanted++;
		while (barrier.thr_count != 0)
			(void) cond_wait(&barrier.cv, &barrier.lock);
		barrier.wanted--;
		barrier.thr_count = -1;
		break;

	case RCMD_INIT:
	case RCMD_NORMAL:
	default:
		if (barrier.thr_count == -1)
			barrier.thr_count = 0;
		if (barrier.wanted)
			(void) cond_broadcast(&barrier.cv);
		break;
	}

	(void) mutex_unlock(&barrier.lock);
}

/*
 * Increment daemon thread count
 */
int
rcmd_thr_incr(int cmd)
{
	int seq_num;

	(void) mutex_lock(&barrier.lock);
	/*
	 * Set wanted flag
	 */
	barrier.wanted++;

	/*
	 * Wait till it is safe for daemon to perform the operation
	 *
	 * NOTE: if a module registers by passing a request to the
	 *	client proccess, we may need to allow register
	 *	to come through during daemon initialization.
	 */
	while (barrier.state != RCMD_NORMAL)
		(void) cond_wait(&barrier.cv, &barrier.lock);

	if ((cmd == CMD_EVENT) ||
	    (cmd == CMD_REGISTER) ||
	    (cmd == CMD_UNREGISTER)) {
		/*
		 * Event passthru and register ops don't need sequence number
		 */
		seq_num = -1;
	} else {
		/*
		 * Non register operation gets a sequence number
		 */
		seq_num = get_seq_number();
	}
	barrier.wanted--;
	barrier.thr_count++;
	(void) mutex_unlock(&barrier.lock);

	if ((cmd == CMD_OFFLINE) ||
	    (cmd == CMD_SUSPEND) ||
	    (cmd == CMD_GETINFO)) {
		/*
		 * For these operations, need to ask modules to
		 * register any new resources that came online.
		 *
		 * This is because mount/umount are not instrumented
		 * to register with rcm before using system resources.
		 * Certain registration ops may fail during sync, which
		 * indicates race conditions. This cannot be avoided
		 * without changing mount/umount.
		 */
		rcmd_db_sync();
	}

	return (seq_num);
}

/*
 * Decrement thread count
 */
void
rcmd_thr_decr()
{
	/*
	 * Decrement thread count and wake up reload/cleanup thread.
	 */
	(void) mutex_lock(&barrier.lock);
	barrier.last_update = time(NULL);
	if (--barrier.thr_count == 0)
		(void) cond_broadcast(&barrier.cv);
	(void) mutex_unlock(&barrier.lock);
}

/*
 * Wakeup all waiting threads as a result of SIGHUP
 */
static int sighup_received = 0;

void
rcmd_thr_signal()
{
	(void) mutex_lock(&barrier.lock);
	sighup_received = 1;
	(void) cond_broadcast(&barrier.cv);
	(void) mutex_unlock(&barrier.lock);
}

void
rcmd_start_timer(int timeout)
{
	timestruc_t abstime;

	if (timeout == 0)
		timeout = RCM_DAEMON_TIMEOUT;	/* default to 5 minutes */
	else
		dr_req_list->idle_timeout = timeout;	/* persist timeout */

	if (timeout > 0) {
		abstime.tv_sec = time(NULL) + timeout;
	}

	(void) mutex_lock(&barrier.lock);
	for (;;) {
		int idletime;
		int is_active;

		if (timeout > 0)
			(void) cond_timedwait(&barrier.cv, &barrier.lock,
			    &abstime);
		else
			(void) cond_wait(&barrier.cv, &barrier.lock);

		/*
		 * If sighup received, change timeout to 0 so the daemon is
		 * shut down at the first possible moment
		 */
		if (sighup_received)
			timeout = 0;

		/*
		 * If timeout is negative, never shutdown the daemon
		 */
		if (timeout < 0)
			continue;

		/*
		 * Check for ongoing/pending activity
		 */
		is_active = (barrier.thr_count || barrier.wanted ||
		    (dr_req_list->n_req != 0));
		if (is_active) {
			abstime.tv_sec = time(NULL) + timeout;
			continue;
		}

		/*
		 * If idletime is less than timeout, continue to wait
		 */
		idletime = time(NULL) - barrier.last_update;
		if (idletime < timeout) {
			abstime.tv_sec = barrier.last_update + timeout;
			continue;
		}
		break;
	}

	(void) script_main_fini();

	rcm_log_message(RCM_INFO, gettext("rcm_daemon is shut down.\n"));
}

/*
 * Code related to polling client pid's
 * Not declared as static so that we can find this structure easily
 * in the core file.
 */
struct {
	int		n_pids;
	int		n_max_pids;
	thread_t	poll_tid;	/* poll thread id */
	int		signaled;
	pid_t		*pids;
	int		*refcnt;
	struct pollfd	*fds;
	cond_t		cv;	/* the associated lock is rcm_req_lock */
} polllist;

static int
find_pid_index(pid_t pid)
{
	int i;

	for (i = 0; i < polllist.n_pids; i++) {
		if (polllist.pids[i] == pid) {
			return (i);
		}
	}
	return (-1);
}

/*
 * Resize buffer for new pids
 */
static int
get_pid_index()
{
	const int n_chunk = 10;

	int n_max;
	int index = polllist.n_pids;

	if (polllist.n_pids < polllist.n_max_pids) {
		polllist.n_pids++;
		return (index);
	}

	if (polllist.n_max_pids == 0) {
		n_max = n_chunk;
		polllist.pids = s_calloc(n_max, sizeof (pid_t));
		polllist.refcnt = s_calloc(n_max, sizeof (int));
		polllist.fds = s_calloc(n_max, sizeof (struct pollfd));
	} else {
		n_max = polllist.n_max_pids + n_chunk;
		polllist.pids = s_realloc(polllist.pids,
		    n_max * sizeof (pid_t));
		polllist.refcnt = s_realloc(polllist.refcnt,
		    n_max * sizeof (int));
		polllist.fds = s_realloc(polllist.fds,
		    n_max * sizeof (struct pollfd));
	}
	polllist.n_max_pids = n_max;
	polllist.n_pids++;
	return (index);
}

/*
 * rcm_req_lock must be held
 */
static void
add_to_polling_list(pid_t pid)
{
	int fd, index;
	char procfile[MAXPATHLEN];

	if (pid == (pid_t)0)
		return;

	rcm_log_message(RCM_TRACE1, "add_to_polling_list(%ld)\n", pid);

	/*
	 * Need to stop the poll thread before manipulating the polllist
	 * since poll thread may possibly be using polllist.fds[] and
	 * polllist.n_pids. As an optimization, first check if the pid
	 * is already in the polllist. If it is, there is no need to
	 * stop the poll thread. Just increment the pid reference count
	 * and return;
	 */
	index = find_pid_index(pid);
	if (index != -1) {
		polllist.refcnt[index]++;
		return;
	}

	stop_polling_thread();

	/*
	 * In an attempt to stop the poll thread we may have released
	 * and reacquired rcm_req_lock. So find the index again.
	 */
	index = find_pid_index(pid);
	if (index != -1) {
		polllist.refcnt[index]++;
		goto done;
	}

	/*
	 * Open a /proc file
	 */
	(void) sprintf(procfile, "/proc/%ld/as", pid);
	if ((fd = open(procfile, O_RDONLY)) == -1) {
		rcm_log_message(RCM_NOTICE, gettext("open(%s): %s\n"),
		    procfile, strerror(errno));
		goto done;
	}

	/*
	 * add pid to polllist
	 */
	index = get_pid_index();
	polllist.pids[index] = pid;
	polllist.refcnt[index] = 1;
	polllist.fds[index].fd = fd;
	polllist.fds[index].events = 0;
	polllist.fds[index].revents = 0;

	rcm_log_message(RCM_DEBUG, "add pid %ld at index %ld\n", pid, index);

done:
	start_polling_thread();
}

/*
 * rcm_req_lock must be held
 */
static void
remove_from_polling_list(pid_t pid)
{
	int i, index;

	if (pid == (pid_t)0)
		return;

	rcm_log_message(RCM_TRACE1, "remove_from_polling_list(%ld)\n", pid);

	/*
	 * Need to stop the poll thread before manipulating the polllist
	 * since poll thread may possibly be using polllist.fds[] and
	 * polllist.n_pids. As an optimization, first check the pid
	 * reference count. If the pid reference count is greater than 1
	 * there is no need to stop the polling thread.
	 */

	index = find_pid_index(pid);
	if (index == -1) {
		rcm_log_message(RCM_NOTICE,
		    gettext("error removing pid %ld from polling list\n"), pid);
		return;
	}

	/*
	 * decrement the pid refcnt
	 */
	if (polllist.refcnt[index] > 1) {
		polllist.refcnt[index]--;
		return;
	}

	stop_polling_thread();

	/*
	 * In an attempt to stop the poll thread we may have released
	 * and reacquired rcm_req_lock. So find the index again.
	 */
	index = find_pid_index(pid);
	if (index == -1) {
		rcm_log_message(RCM_NOTICE,
		    gettext("error removing pid %ld from polling list\n"), pid);
		goto done;
	}

	if (--polllist.refcnt[index] > 0)
		goto done;

	/*
	 * refcnt down to zero, delete pid from polling list
	 */
	(void) close(polllist.fds[index].fd);
	polllist.n_pids--;

	for (i = index; i < polllist.n_pids; i++) {
		polllist.pids[i] = polllist.pids[i + 1];
		polllist.refcnt[i] = polllist.refcnt[i + 1];
		bcopy(&polllist.fds[i + 1], &polllist.fds[i],
		    sizeof (struct pollfd));
	}

	rcm_log_message(RCM_DEBUG, "remove pid %ld at index %d\n", pid, index);

done:
	start_polling_thread();
}

void
init_poll_thread()
{
	polllist.poll_tid = (thread_t)-1;
}

void
cleanup_poll_thread()
{
	(void) mutex_lock(&rcm_req_lock);
	if (polllist.poll_tid == thr_self()) {
		rcm_log_message(RCM_TRACE2,
		    "cleanup_poll_thread: n_pids = %d\n", polllist.n_pids);
		polllist.poll_tid = (thread_t)-1;
		(void) cond_broadcast(&polllist.cv);
	}
	(void) mutex_unlock(&rcm_req_lock);
}

/*ARGSUSED*/
static void *
pollfunc(void *arg)
{
	sigset_t mask;

	rcm_log_message(RCM_TRACE2, "poll thread started. n_pids = %d\n",
	    polllist.n_pids);

	/*
	 * Unblock SIGUSR1 to allow polling thread to be killed
	 */
	(void) sigemptyset(&mask);
	(void) sigaddset(&mask, SIGUSR1);
	(void) thr_sigsetmask(SIG_UNBLOCK, &mask, NULL);

	(void) poll(polllist.fds, polllist.n_pids, (time_t)-1);

	/*
	 * block SIGUSR1 to avoid being killed while holding a lock
	 */
	(void) sigemptyset(&mask);
	(void) sigaddset(&mask, SIGUSR1);
	(void) thr_sigsetmask(SIG_BLOCK, &mask, NULL);

	rcm_log_message(RCM_TRACE2, "returned from poll()\n");

	cleanup_poll_thread();

	(void) mutex_lock(&barrier.lock);
	need_cleanup = 1;
	(void) cond_broadcast(&barrier.cv);
	(void) mutex_unlock(&barrier.lock);

	return (NULL);
}

/*
 * rcm_req_lock must be held
 */
void
start_polling_thread()
{
	int err;

	if (rcmd_get_state() != RCMD_NORMAL)
		return;

	if (polllist.poll_tid != (thread_t)-1 || polllist.n_pids == 0)
		return;

	if ((err = thr_create(NULL, 0, pollfunc, NULL, THR_DETACHED,
	    &polllist.poll_tid)) == 0)
		polllist.signaled = 0;
	else
		rcm_log_message(RCM_ERROR,
		    gettext("failed to create polling thread: %s\n"),
		    strerror(err));
}

/*
 * rcm_req_lock must be held
 */
static void
stop_polling_thread()
{
	int err;

	while (polllist.poll_tid != (thread_t)-1) {
		if (polllist.signaled == 0) {
			if ((err = thr_kill(polllist.poll_tid, SIGUSR1)) == 0)
				polllist.signaled = 1;
			else
				/*
				 * thr_kill shouldn't have failed since the
				 * poll thread id and the signal are valid.
				 * So log an error. Since when thr_kill
				 * fails no signal is sent (as per man page),
				 * the cond_wait below will wait until the
				 * the poll thread exits by some other means.
				 * The poll thread, for example, exits on its
				 * own when any DR initiator process that it
				 * is currently polling exits.
				 */
				rcm_log_message(RCM_ERROR,
				    gettext(
				    "fail to kill polling thread %d: %s\n"),
				    polllist.poll_tid, strerror(err));
		}
		(void) cond_wait(&polllist.cv, &rcm_req_lock);
	}
}
