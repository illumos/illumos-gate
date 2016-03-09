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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>
#include <alloca.h>
#include <door.h>
#include <pthread.h>
#include <synch.h>
#include <pwd.h>
#include <auth_list.h>
#include <auth_attr.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <sys/sunddi.h>
#include <sys/ddi_hp.h>
#include <libnvpair.h>
#include <libhotplug.h>
#include <libhotplug_impl.h>
#include "hotplugd_impl.h"

/*
 * Buffer management for results.
 */
typedef struct i_buffer {
	uint64_t	seqnum;
	char		*buffer;
	struct i_buffer	*next;
} i_buffer_t;

static uint64_t		buffer_seqnum = 1;
static i_buffer_t	*buffer_list = NULL;
static pthread_mutex_t	buffer_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Door file descriptor.
 */
static int	door_fd = -1;

/*
 * Function prototypes.
 */
static void	door_server(void *, char *, size_t, door_desc_t *, uint_t);
static int	check_auth(ucred_t *, const char *);
static int	cmd_getinfo(nvlist_t *, nvlist_t **);
static int	cmd_changestate(nvlist_t *, nvlist_t **);
static int	cmd_private(hp_cmd_t, nvlist_t *, nvlist_t **);
static void	add_buffer(uint64_t, char *);
static void	free_buffer(uint64_t);
static uint64_t	get_seqnum(void);
static char	*state_str(int);
static int	audit_session(ucred_t *, adt_session_data_t **);
static void	audit_changestate(ucred_t *, char *, char *, char *, int, int,
		    int);
static void	audit_setprivate(ucred_t *, char *, char *, char *, char *,
		    int);

/*
 * door_server_init()
 *
 *	Create the door file, and initialize the door server.
 */
boolean_t
door_server_init(void)
{
	int	fd;

	/* Create the door file */
	if ((fd = open(HOTPLUGD_DOOR, O_CREAT|O_EXCL|O_RDONLY, 0644)) == -1) {
		if (errno == EEXIST) {
			log_err("Door service is already running.\n");
		} else {
			log_err("Cannot open door file '%s': %s\n",
			    HOTPLUGD_DOOR, strerror(errno));
		}
		return (B_FALSE);
	}
	(void) close(fd);

	/* Initialize the door service */
	if ((door_fd = door_create(door_server, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) == -1) {
		log_err("Cannot create door service: %s\n", strerror(errno));
		return (B_FALSE);
	}

	/* Cleanup stale door associations */
	(void) fdetach(HOTPLUGD_DOOR);

	/* Associate door service with door file */
	if (fattach(door_fd, HOTPLUGD_DOOR) != 0) {
		log_err("Cannot attach to door file '%s': %s\n", HOTPLUGD_DOOR,
		    strerror(errno));
		(void) door_revoke(door_fd);
		(void) fdetach(HOTPLUGD_DOOR);
		door_fd = -1;
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * door_server_fini()
 *
 *	Terminate and cleanup the door server.
 */
void
door_server_fini(void)
{
	if (door_fd != -1) {
		(void) door_revoke(door_fd);
		(void) fdetach(HOTPLUGD_DOOR);
	}

	(void) unlink(HOTPLUGD_DOOR);
}

/*
 * door_server()
 *
 *	This routine is the handler which responds to each door call.
 *	Each incoming door call is expected to send a packed nvlist
 *	of arguments which describe the requested action.  And each
 *	response is sent back as a packed nvlist of results.
 *
 *	Results are always allocated on the heap.  A global list of
 *	allocated result buffers is managed, and each one is tracked
 *	by a unique sequence number.  The final step in the protocol
 *	is for the caller to send a short response using the sequence
 *	number when the buffer can be released.
 */
/*ARGSUSED*/
static void
door_server(void *cookie, char *argp, size_t sz, door_desc_t *dp, uint_t ndesc)
{
	nvlist_t	*args = NULL;
	nvlist_t	*results = NULL;
	hp_cmd_t	cmd;
	int		rv;

	dprintf("Door call: cookie=%p, argp=%p, sz=%d\n", cookie, (void *)argp,
	    sz);

	/* Special case to free a results buffer */
	if (sz == sizeof (uint64_t)) {
		free_buffer(*(uint64_t *)(uintptr_t)argp);
		(void) door_return(NULL, 0, NULL, 0);
		return;
	}

	/* Unpack the arguments nvlist */
	if (nvlist_unpack(argp, sz, &args, 0) != 0) {
		log_err("Cannot unpack door arguments.\n");
		rv = EINVAL;
		goto fail;
	}

	/* Extract the requested command */
	if (nvlist_lookup_int32(args, HPD_CMD, (int32_t *)&cmd) != 0) {
		log_err("Cannot decode door command.\n");
		rv = EINVAL;
		goto fail;
	}

	/* Implement the command */
	switch (cmd) {
	case HP_CMD_GETINFO:
		rv = cmd_getinfo(args, &results);
		break;
	case HP_CMD_CHANGESTATE:
		rv = cmd_changestate(args, &results);
		break;
	case HP_CMD_SETPRIVATE:
	case HP_CMD_GETPRIVATE:
		rv = cmd_private(cmd, args, &results);
		break;
	default:
		rv = EINVAL;
		break;
	}

	/* The arguments nvlist is no longer needed */
	nvlist_free(args);
	args = NULL;

	/*
	 * If an nvlist was constructed for the results,
	 * then pack the results nvlist and return it.
	 */
	if (results != NULL) {
		uint64_t	seqnum;
		char		*buf = NULL;
		size_t		len = 0;

		/* Add a sequence number to the results */
		seqnum = get_seqnum();
		if (nvlist_add_uint64(results, HPD_SEQNUM, seqnum) != 0) {
			log_err("Cannot add sequence number.\n");
			rv = EFAULT;
			goto fail;
		}

		/* Pack the results nvlist */
		if (nvlist_pack(results, &buf, &len,
		    NV_ENCODE_NATIVE, 0) != 0) {
			log_err("Cannot pack door results.\n");
			rv = EFAULT;
			goto fail;
		}

		/* Link results buffer into list */
		add_buffer(seqnum, buf);

		/* The results nvlist is no longer needed */
		nvlist_free(results);

		/* Return the results */
		(void) door_return(buf, len, NULL, 0);
		return;
	}

	/* Return result code (when no nvlist) */
	(void) door_return((char *)&rv, sizeof (int), NULL, 0);
	return;

fail:
	log_err("Door call failed (%s)\n", strerror(rv));
	nvlist_free(args);
	nvlist_free(results);
	(void) door_return((char *)&rv, sizeof (int), NULL, 0);
}

/*
 * check_auth()
 *
 *	Perform an RBAC authorization check.
 */
static int
check_auth(ucred_t *ucred, const char *auth)
{
	struct passwd	pwd;
	uid_t		euid;
	char		buf[MAXPATHLEN];

	euid = ucred_geteuid(ucred);

	if ((getpwuid_r(euid, &pwd, buf, sizeof (buf)) == NULL) ||
	    (chkauthattr(auth, pwd.pw_name) == 0)) {
		log_info("Unauthorized door call.\n");
		return (-1);
	}

	return (0);
}

/*
 * cmd_getinfo()
 *
 *	Implements the door command to get a hotplug information snapshot.
 */
static int
cmd_getinfo(nvlist_t *args, nvlist_t **resultsp)
{
	hp_node_t	root;
	nvlist_t	*results;
	char		*path;
	char		*connection;
	char		*buf = NULL;
	size_t		len = 0;
	uint_t		flags;
	int		rv;

	dprintf("cmd_getinfo:\n");

	/* Get arguments */
	if (nvlist_lookup_string(args, HPD_PATH, &path) != 0) {
		dprintf("cmd_getinfo: invalid arguments.\n");
		return (EINVAL);
	}
	if (nvlist_lookup_string(args, HPD_CONNECTION, &connection) != 0)
		connection = NULL;
	if (nvlist_lookup_uint32(args, HPD_FLAGS, (uint32_t *)&flags) != 0)
		flags = 0;

	/* Get and pack the requested snapshot */
	if ((rv = getinfo(path, connection, flags, &root)) == 0) {
		rv = hp_pack(root, &buf, &len);
		hp_fini(root);
	}
	dprintf("cmd_getinfo: getinfo(): rv = %d, buf = %p.\n", rv,
	    (void *)buf);

	/*
	 * If the above failed or there is no snapshot,
	 * then only return a status code.
	 */
	if (rv != 0)
		return (rv);
	if (buf == NULL)
		return (EFAULT);

	/* Allocate nvlist for results */
	if (nvlist_alloc(&results, NV_UNIQUE_NAME_TYPE, 0) != 0) {
		dprintf("cmd_getinfo: nvlist_alloc() failed.\n");
		free(buf);
		return (ENOMEM);
	}

	/* Add snapshot and successful status to results */
	if ((nvlist_add_int32(results, HPD_STATUS, 0) != 0) ||
	    (nvlist_add_byte_array(results, HPD_INFO,
	    (uchar_t *)buf, len) != 0)) {
		dprintf("cmd_getinfo: nvlist add failure.\n");
		nvlist_free(results);
		free(buf);
		return (ENOMEM);
	}

	/* Packed snapshot no longer needed */
	free(buf);

	/* Success */
	*resultsp = results;
	return (0);
}

/*
 * cmd_changestate()
 *
 *	Implements the door command to initate a state change operation.
 *
 *	NOTE: requires 'modify' authorization.
 */
static int
cmd_changestate(nvlist_t *args, nvlist_t **resultsp)
{
	hp_node_t	root = NULL;
	nvlist_t	*results = NULL;
	char		*path, *connection;
	ucred_t		*uc = NULL;
	uint_t		flags;
	int		rv, state, old_state, status;

	dprintf("cmd_changestate:\n");

	/* Get arguments */
	if ((nvlist_lookup_string(args, HPD_PATH, &path) != 0) ||
	    (nvlist_lookup_string(args, HPD_CONNECTION, &connection) != 0) ||
	    (nvlist_lookup_int32(args, HPD_STATE, &state) != 0)) {
		dprintf("cmd_changestate: invalid arguments.\n");
		return (EINVAL);
	}
	if (nvlist_lookup_uint32(args, HPD_FLAGS, (uint32_t *)&flags) != 0)
		flags = 0;

	/* Get caller's credentials */
	if (door_ucred(&uc) != 0) {
		log_err("Cannot get door credentials (%s)\n", strerror(errno));
		return (EACCES);
	}

	/* Check authorization */
	if (check_auth(uc, HP_MODIFY_AUTH) != 0) {
		dprintf("cmd_changestate: access denied.\n");
		audit_changestate(uc, HP_MODIFY_AUTH, path, connection,
		    state, -1, ADT_FAIL_VALUE_AUTH);
		ucred_free(uc);
		return (EACCES);
	}

	/* Perform the state change operation */
	status = changestate(path, connection, state, flags, &old_state, &root);
	dprintf("cmd_changestate: changestate() == %d\n", status);

	/* Audit the operation */
	audit_changestate(uc, HP_MODIFY_AUTH, path, connection, state,
	    old_state, status);

	/* Caller's credentials no longer needed */
	ucred_free(uc);

	/*
	 * Pack the results into an nvlist if there is an error snapshot.
	 *
	 * If any error occurs while packing the results, the original
	 * error code from changestate() above is still returned.
	 */
	if (root != NULL) {
		char	*buf = NULL;
		size_t	len = 0;

		dprintf("cmd_changestate: results nvlist required.\n");

		/* Pack and discard the error snapshot */
		rv = hp_pack(root, &buf, &len);
		hp_fini(root);
		if (rv != 0) {
			dprintf("cmd_changestate: hp_pack() failed (%s).\n",
			    strerror(rv));
			return (status);
		}

		/* Allocate nvlist for results */
		if (nvlist_alloc(&results, NV_UNIQUE_NAME_TYPE, 0) != 0) {
			dprintf("cmd_changestate: nvlist_alloc() failed.\n");
			free(buf);
			return (status);
		}

		/* Add the results into the nvlist */
		if ((nvlist_add_int32(results, HPD_STATUS, status) != 0) ||
		    (nvlist_add_byte_array(results, HPD_INFO, (uchar_t *)buf,
		    len) != 0)) {
			dprintf("cmd_changestate: nvlist add failed.\n");
			nvlist_free(results);
			free(buf);
			return (status);
		}

		*resultsp = results;
	}

	return (status);
}

/*
 * cmd_private()
 *
 *	Implementation of the door command to set or get bus private options.
 *
 *	NOTE: requires 'modify' authorization for the 'set' command.
 */
static int
cmd_private(hp_cmd_t cmd, nvlist_t *args, nvlist_t **resultsp)
{
	nvlist_t	*results = NULL;
	ucred_t		*uc = NULL;
	char		*path, *connection, *options;
	char		*values = NULL;
	int		status;

	dprintf("cmd_private:\n");

	/* Get caller's credentials */
	if ((cmd == HP_CMD_SETPRIVATE) && (door_ucred(&uc) != 0)) {
		log_err("Cannot get door credentials (%s)\n", strerror(errno));
		return (EACCES);
	}

	/* Get arguments */
	if ((nvlist_lookup_string(args, HPD_PATH, &path) != 0) ||
	    (nvlist_lookup_string(args, HPD_CONNECTION, &connection) != 0) ||
	    (nvlist_lookup_string(args, HPD_OPTIONS, &options) != 0)) {
		dprintf("cmd_private: invalid arguments.\n");
		return (EINVAL);
	}

	/* Check authorization */
	if ((cmd == HP_CMD_SETPRIVATE) &&
	    (check_auth(uc, HP_MODIFY_AUTH) != 0)) {
		dprintf("cmd_private: access denied.\n");
		audit_setprivate(uc, HP_MODIFY_AUTH, path, connection, options,
		    ADT_FAIL_VALUE_AUTH);
		ucred_free(uc);
		return (EACCES);
	}

	/* Perform the operation */
	status = private_options(path, connection, cmd, options, &values);
	dprintf("cmd_private: private_options() == %d\n", status);

	/* Audit the operation */
	if (cmd == HP_CMD_SETPRIVATE) {
		audit_setprivate(uc, HP_MODIFY_AUTH, path, connection, options,
		    status);
		ucred_free(uc);
	}

	/* Construct an nvlist if values were returned */
	if (values != NULL) {

		/* Allocate nvlist for results */
		if (nvlist_alloc(&results, NV_UNIQUE_NAME_TYPE, 0) != 0) {
			dprintf("cmd_private: nvlist_alloc() failed.\n");
			free(values);
			return (ENOMEM);
		}

		/* Add values and status to the results */
		if ((nvlist_add_int32(results, HPD_STATUS, status) != 0) ||
		    (nvlist_add_string(results, HPD_OPTIONS, values) != 0)) {
			dprintf("cmd_private: nvlist add failed.\n");
			nvlist_free(results);
			free(values);
			return (ENOMEM);
		}

		/* The values string is no longer needed */
		free(values);

		*resultsp = results;
	}

	return (status);
}

/*
 * get_seqnum()
 *
 *	Allocate the next unique sequence number for a results buffer.
 */
static uint64_t
get_seqnum(void)
{
	uint64_t seqnum;

	(void) pthread_mutex_lock(&buffer_lock);

	seqnum = buffer_seqnum++;

	(void) pthread_mutex_unlock(&buffer_lock);

	return (seqnum);
}

/*
 * add_buffer()
 *
 *	Link a results buffer into the list containing all buffers.
 */
static void
add_buffer(uint64_t seqnum, char *buf)
{
	i_buffer_t	*node;

	if ((node = (i_buffer_t *)malloc(sizeof (i_buffer_t))) == NULL) {
		/* The consequence is a memory leak. */
		log_err("Cannot allocate results buffer: %s\n",
		    strerror(errno));
		return;
	}

	node->seqnum = seqnum;
	node->buffer = buf;

	(void) pthread_mutex_lock(&buffer_lock);

	node->next = buffer_list;
	buffer_list = node;

	(void) pthread_mutex_unlock(&buffer_lock);
}

/*
 * free_buffer()
 *
 *	Remove a results buffer from the list containing all buffers.
 */
static void
free_buffer(uint64_t seqnum)
{
	i_buffer_t	*node, *prev;

	(void) pthread_mutex_lock(&buffer_lock);

	prev = NULL;
	node = buffer_list;

	while (node) {
		if (node->seqnum == seqnum) {
			dprintf("Free buffer %lld\n", seqnum);
			if (prev) {
				prev->next = node->next;
			} else {
				buffer_list = node->next;
			}
			free(node->buffer);
			free(node);
			break;
		}
		prev = node;
		node = node->next;
	}

	(void) pthread_mutex_unlock(&buffer_lock);
}

/*
 * audit_session()
 *
 *	Initialize an audit session.
 */
static int
audit_session(ucred_t *ucred, adt_session_data_t **sessionp)
{
	adt_session_data_t	*session;

	if (adt_start_session(&session, NULL, 0) != 0) {
		log_err("Cannot start audit session.\n");
		return (-1);
	}

	if (adt_set_from_ucred(session, ucred, ADT_NEW) != 0) {
		log_err("Cannot set audit session from ucred.\n");
		(void) adt_end_session(session);
		return (-1);
	}

	*sessionp = session;
	return (0);
}

/*
 * audit_changestate()
 *
 *	Audit a 'changestate' door command.
 */
static void
audit_changestate(ucred_t *ucred, char *auth, char *path, char *connection,
    int new_state, int old_state, int result)
{
	adt_session_data_t	*session;
	adt_event_data_t	*event;
	int			pass_fail, fail_reason;

	if (audit_session(ucred, &session) != 0)
		return;

	if ((event = adt_alloc_event(session, ADT_hotplug_state)) == NULL) {
		(void) adt_end_session(session);
		return;
	}

	if (result == 0) {
		pass_fail = ADT_SUCCESS;
		fail_reason = ADT_SUCCESS;
	} else {
		pass_fail = ADT_FAILURE;
		fail_reason = result;
	}

	event->adt_hotplug_state.auth_used = auth;
	event->adt_hotplug_state.device_path = path;
	event->adt_hotplug_state.connection = connection;
	event->adt_hotplug_state.new_state = state_str(new_state);
	event->adt_hotplug_state.old_state = state_str(old_state);

	/* Put the event */
	if (adt_put_event(event, pass_fail, fail_reason) != 0)
		log_err("Cannot put audit event.\n");

	adt_free_event(event);
	(void) adt_end_session(session);
}

/*
 * audit_setprivate()
 *
 *	Audit a 'set private' door command.
 */
static void
audit_setprivate(ucred_t *ucred, char *auth, char *path, char *connection,
    char *options, int result)
{
	adt_session_data_t	*session;
	adt_event_data_t	*event;
	int			pass_fail, fail_reason;

	if (audit_session(ucred, &session) != 0)
		return;

	if ((event = adt_alloc_event(session, ADT_hotplug_set)) == NULL) {
		(void) adt_end_session(session);
		return;
	}

	if (result == 0) {
		pass_fail = ADT_SUCCESS;
		fail_reason = ADT_SUCCESS;
	} else {
		pass_fail = ADT_FAILURE;
		fail_reason = result;
	}

	event->adt_hotplug_set.auth_used = auth;
	event->adt_hotplug_set.device_path = path;
	event->adt_hotplug_set.connection = connection;
	event->adt_hotplug_set.options = options;

	/* Put the event */
	if (adt_put_event(event, pass_fail, fail_reason) != 0)
		log_err("Cannot put audit event.\n");

	adt_free_event(event);
	(void) adt_end_session(session);
}

/*
 * state_str()
 *
 *	Convert a state from integer to string.
 */
static char *
state_str(int state)
{
	switch (state) {
	case DDI_HP_CN_STATE_EMPTY:
		return ("EMPTY");
	case DDI_HP_CN_STATE_PRESENT:
		return ("PRESENT");
	case DDI_HP_CN_STATE_POWERED:
		return ("POWERED");
	case DDI_HP_CN_STATE_ENABLED:
		return ("ENABLED");
	case DDI_HP_CN_STATE_PORT_EMPTY:
		return ("PORT-EMPTY");
	case DDI_HP_CN_STATE_PORT_PRESENT:
		return ("PORT-PRESENT");
	case DDI_HP_CN_STATE_OFFLINE:
		return ("OFFLINE");
	case DDI_HP_CN_STATE_ATTACHED:
		return ("ATTACHED");
	case DDI_HP_CN_STATE_MAINTENANCE:
		return ("MAINTENANCE");
	case DDI_HP_CN_STATE_ONLINE:
		return ("ONLINE");
	default:
		return ("UNKNOWN");
	}
}
