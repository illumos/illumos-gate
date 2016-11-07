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

#include <libintl.h>
#include <librestart.h>
#include <librestart_priv.h>
#include <libscf.h>
#include <libscf_priv.h>

#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <exec_attr.h>
#include <grp.h>
#include <libsysevent.h>
#include <libuutil.h>
#include <limits.h>
#include <link.h>
#include <malloc.h>
#include <pool.h>
#include <priv.h>
#include <project.h>
#include <pthread.h>
#include <pwd.h>
#include <secdb.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/corectl.h>
#include <sys/machelf.h>
#include <sys/secflags.h>
#include <sys/task.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <ucontext.h>

#define	min(a, b)		((a) > (b) ? (b) : (a))

#define	MKW_TRUE	":true"
#define	MKW_KILL	":kill"
#define	MKW_KILL_PROC	":kill_process"

#define	ALLOCFAIL	((char *)"Allocation failure.")
#define	RCBROKEN	((char *)"Repository connection broken.")

#define	MAX_COMMIT_RETRIES		10
#define	MAX_COMMIT_RETRY_INT		(5 * 1000000)	/* 5 seconds */
#define	INITIAL_COMMIT_RETRY_INT	(10000)		/* 1/100th second */

/*
 * bad_fail() catches bugs in this and lower layers by reporting supposedly
 * impossible function failures.  The NDEBUG case keeps the strings out of the
 * library but still calls abort() so we can root-cause from the coredump.
 */
#ifndef NDEBUG
#define	bad_fail(func, err)	{					\
	(void) fprintf(stderr,						\
	    "At %s:%d, %s() failed with unexpected error %d.  Aborting.\n", \
	    __FILE__, __LINE__, (func), (err));				\
	abort();							\
}
#else
#define	bad_fail(func, err)	abort()
#endif

struct restarter_event_handle {
	char				*reh_restarter_name;
	char				*reh_delegate_channel_name;
	evchan_t			*reh_delegate_channel;
	char				*reh_delegate_subscriber_id;
	char				*reh_master_channel_name;
	evchan_t			*reh_master_channel;
	char				*reh_master_subscriber_id;
	int				(*reh_handler)(restarter_event_t *);
};

struct restarter_event {
	sysevent_t			*re_sysevent;
	restarter_event_type_t		re_type;
	char				*re_instance_name;
	restarter_event_handle_t	*re_event_handle;
	restarter_instance_state_t	re_state;
	restarter_instance_state_t	re_next_state;
};

/*
 * Long reasons must all parse/read correctly in the following contexts:
 *
 * "A service instance transitioned state: %s."
 * "A service failed: %s."
 * "Reason: %s."
 * "The service transitioned state (%s) and ..."
 *
 * With the exception of restart_str_none they must also fit the following
 * moulds:
 *
 * "An instance transitioned because %s, and ..."
 * "An instance transitioned to <new-state> because %s, and ..."
 *
 * Note that whoever is rendering the long message must provide the
 * terminal punctuation - don't include it here.  Similarly, do not
 * provide an initial capital letter in reason-long.
 *
 * The long reason strings are Volatile - within the grammatical constraints
 * above we may improve them as need be.  The intention is that a consumer
 * may blindly render the string along the lines of the above examples,
 * but has no other guarantees as to the exact wording.  Long reasons
 * are localized.
 *
 * We define revisions of the set of short reason strings in use.  Within
 * a given revision, all short reasons are Committed.  Consumers must check
 * the revision in use before relying on the semantics of the short reason
 * codes - if the version exceeds that which they are familiar with they should
 * fail gracefully.  Having checked for version compatability, a consumer
 * is assured that
 *
 *	"short_reason_A iff semantic_A", provided:
 *
 *		. the restarter uses this short reason code at all,
 *		. the short reason is not "none" (which a restarter could
 *		  specifiy for any transition semantics)
 *
 * To split/refine such a Committed semantic_A into further cases,
 * we are required to bump the revision number.  This should be an
 * infrequent occurence.  If you bump the revision number you may
 * need to make corresponding changes in any source that calls
 * restarter_str_version (e.g., FMA event generation).
 *
 * To add additional reasons to the set you must also bump the version
 * number.
 */

/*
 * The following describes revision 0 of the set of transition reasons.
 * Read the preceding block comment before making any changes.
 */
static const struct restarter_state_transition_reason restarter_str[] = {
	/*
	 * Any transition for which the restarter has not provided a reason.
	 */
	{
	    restarter_str_none,
	    "none",
	    "the restarter gave no reason"
	},

	/*
	 * A transition to maintenance state due to a
	 * 'svcadm mark maintenance <fmri>'.  *Not* used if the libscf
	 * interface smf_maintain_instance(3SCF) is used to request maintenance.
	 */
	{
	    restarter_str_administrative_request,
	    "administrative_request",
	    "maintenance was requested by an administrator"
	},

	/*
	 * A transition to maintenance state if a repository inconsistency
	 * exists when the service/instance state is first read by startd
	 * into the graph engine (this can also happen during startd restart).
	 */
	{
	    restarter_str_bad_repo_state,
	    "bad_repo_state",
	    "an SMF repository inconsistecy exists"
	},

	/*
	 * A transition 'maintenance -> uninitialized' resulting always
	 * from 'svcadm clear <fmri>'.  *Not* used if the libscf interface
	 * smf_restore_instance(3SCF) is used.
	 */
	{
	    restarter_str_clear_request,
	    "clear_request",
	    "maintenance clear was requested by an administrator"
	},

	/*
	 * A transition 'online -> offline' due to a process core dump.
	 */
	{
	    restarter_str_ct_ev_core,
	    "ct_ev_core",
	    "a process dumped core"
	},

	/*
	 * A transition 'online -> offline' due to an empty process contract,
	 * i.e., the last process in a contract type service has exited.
	 */
	{
	    restarter_str_ct_ev_exit,
	    "ct_ev_exit",
	    "all processes in the service have exited"
	},

	/*
	 * A transition 'online -> offline' due to a hardware error.
	 */
	{
	    restarter_str_ct_ev_hwerr,
	    "ct_ev_hwerr",
	    "a process was killed due to uncorrectable hardware error"
	},

	/*
	 * A transition 'online -> offline' due to a process in the service
	 * having received a fatal signal originating from outside the
	 * service process contract.
	 */
	{
	    restarter_str_ct_ev_signal,
	    "ct_ev_signal",
	    "a process received a fatal signal from outside the service"
	},

	/*
	 * A transition 'offline -> online' when all dependencies for the
	 * service have been met.
	 */
	{
	    restarter_str_dependencies_satisfied,
	    "dependencies_satisfied",
	    "all dependencies have been satisfied"
	},

	/*
	 * A transition 'online -> offline' because some dependency for the
	 * service is no-longer met.
	 */
	{
	    restarter_str_dependency_activity,
	    "dependency_activity",
	    "a dependency activity required a stop"
	},

	/*
	 * A transition to maintenance state due to a cycle in the
	 * service dependencies.
	 */
	{
	    restarter_str_dependency_cycle,
	    "dependency_cycle",
	    "a dependency cycle exists"
	},

	/*
	 * A transition 'online -> offline -> disabled' due to a
	 * 'svcadm disable [-t] <fmri>' or smf_disable_instance(3SCF) call.
	 */
	{
	    restarter_str_disable_request,
	    "disable_request",
	    "a disable was requested"
	},

	/*
	 * A transition 'disabled -> offline' due to a
	 * 'svcadm enable [-t] <fmri>' or smf_enable_instance(3SCF) call.
	 */
	{
	    restarter_str_enable_request,
	    "enable_request",
	    "an enable was requested"
	},

	/*
	 * A transition to maintenance state when a method fails
	 * repeatedly for a retryable reason.
	 */
	{
	    restarter_str_fault_threshold_reached,
	    "fault_threshold_reached",
	    "a method is failing in a retryable manner but too often"
	},

	/*
	 * A transition to uninitialized state when startd reads the service
	 * configuration and inserts it into the graph engine.
	 */
	{
	    restarter_str_insert_in_graph,
	    "insert_in_graph",
	    "the instance was inserted in the graph"
	},

	/*
	 * A transition to maintenance state due to an invalid dependency
	 * declared for the service.
	 */
	{
	    restarter_str_invalid_dependency,
	    "invalid_dependency",
	    "a service has an invalid dependency"
	},

	/*
	 * A transition to maintenance state because the service-declared
	 * restarter is invalid.
	 */
	{
	    restarter_str_invalid_restarter,
	    "invalid_restarter",
	    "the service restarter is invalid"
	},

	/*
	 * A transition to maintenance state because a restarter method
	 * exited with one of SMF_EXIT_ERR_CONFIG, SMF_EXIT_ERR_NOSMF,
	 * SMF_EXIT_ERR_PERM, or SMF_EXIT_ERR_FATAL.
	 */
	{
	    restarter_str_method_failed,
	    "method_failed",
	    "a start, stop or refresh method failed"
	},

	/*
	 * A transition 'uninitialized -> {disabled|offline}' after
	 * "insert_in_graph" to match the state configured in the
	 * repository.
	 */
	{
	    restarter_str_per_configuration,
	    "per_configuration",
	    "the SMF repository configuration specifies this state"
	},

	/*
	 * Refresh requested - no state change.
	 */
	{
	    restarter_str_refresh,
	    NULL,
	    "a refresh was requested (no change of state)"
	},

	/*
	 * A transition 'online -> offline -> online' due to a
	 * 'svcadm restart <fmri> or equivlaent libscf API call.
	 * Both the 'online -> offline' and 'offline -> online' transtions
	 * specify this reason.
	 */
	{
	    restarter_str_restart_request,
	    "restart_request",
	    "a restart was requested"
	},

	/*
	 * A transition to maintenance state because the start method is
	 * being executed successfully but too frequently.
	 */
	{
	    restarter_str_restarting_too_quickly,
	    "restarting_too_quickly",
	    "the instance is restarting too quickly"
	},

	/*
	 * A transition to maintenance state due a service requesting
	 * 'svcadm mark maintenance <fmri>' or equivalent libscf API call.
	 * A command line 'svcadm mark maintenance <fmri>' does not produce
	 * this reason - it produces administrative_request instead.
	 */
	{
	    restarter_str_service_request,
	    "service_request",
	    "maintenance was requested by another service"
	},

	/*
	 * An instanced inserted into the graph at its existing state
	 * during a startd restart - no state change.
	 */
	{
	    restarter_str_startd_restart,
	    NULL,
	    "the instance was inserted in the graph due to startd restart"
	}
};

uint32_t
restarter_str_version(void)
{
	return (RESTARTER_STRING_VERSION);
}

const char *
restarter_get_str_short(restarter_str_t key)
{
	int i;
	for (i = 0; i < sizeof (restarter_str) /
	    sizeof (struct restarter_state_transition_reason); i++)
		if (key == restarter_str[i].str_key)
			return (restarter_str[i].str_short);
	return (NULL);
}

const char *
restarter_get_str_long(restarter_str_t key)
{
	int i;
	for (i = 0; i < sizeof (restarter_str) /
	    sizeof (struct restarter_state_transition_reason); i++)
		if (key == restarter_str[i].str_key)
			return (dgettext(TEXT_DOMAIN,
			    restarter_str[i].str_long));
	return (NULL);
}

/*
 * A static no memory error message mc_error_t structure
 * to be used in cases when memory errors are to be returned
 * This avoids the need to attempt to allocate memory for the
 * message, therefore getting into a cycle of no memory failures.
 */
mc_error_t mc_nomem_err = {
	0, ENOMEM, sizeof ("Out of memory") - 1, "Out of memory"
};

static const char * const allocfail = "Allocation failure.\n";
static const char * const rcbroken = "Repository connection broken.\n";

static int method_context_safety = 0;	/* Can safely call pools/projects. */

int ndebug = 1;

/* PRINTFLIKE3 */
static mc_error_t *
mc_error_create(mc_error_t *e, int type, const char *format, ...)
{
	mc_error_t	*le;
	va_list		args;
	int		size;

	/*
	 * If the type is ENOMEM and format is NULL, then
	 * go ahead and return the default nomem error.
	 * Otherwise, attempt to allocate the memory and if
	 * that fails then there is no reason to continue.
	 */
	if (type == ENOMEM && format == NULL)
		return (&mc_nomem_err);

	if (e == NULL && (le = malloc(sizeof (mc_error_t))) == NULL)
		return (&mc_nomem_err);
	else
		le = e;

	le->type = type;
	le->destroy = 1;
	va_start(args, format);
	size = vsnprintf(NULL, 0, format, args) + 1;
	if (size >= RESTARTER_ERRMSGSZ) {
		if ((le = realloc(e, sizeof (mc_error_t) +
		    (size - RESTARTER_ERRMSGSZ))) == NULL) {
			size = RESTARTER_ERRMSGSZ - 1;
			le = e;
		}
	}

	le->size = size;
	(void) vsnprintf(le->msg, le->size, format, args);
	va_end(args);

	return (le);
}

void
restarter_mc_error_destroy(mc_error_t *mc_err)
{
	if (mc_err == NULL)
		return;

	/*
	 * If the error messages was allocated then free.
	 */
	if (mc_err->destroy) {
		free(mc_err);
	}
}

static void
free_restarter_event_handle(struct restarter_event_handle *h)
{
	if (h == NULL)
		return;

	/*
	 * Just free the memory -- don't unbind the sysevent handle,
	 * as otherwise events may be lost if this is just a restarter
	 * restart.
	 */

	if (h->reh_restarter_name != NULL)
		free(h->reh_restarter_name);
	if (h->reh_delegate_channel_name != NULL)
		free(h->reh_delegate_channel_name);
	if (h->reh_delegate_subscriber_id != NULL)
		free(h->reh_delegate_subscriber_id);
	if (h->reh_master_channel_name != NULL)
		free(h->reh_master_channel_name);
	if (h->reh_master_subscriber_id != NULL)
		free(h->reh_master_subscriber_id);

	free(h);
}

char *
_restarter_get_channel_name(const char *fmri, int type)
{
	char *name;
	char *chan_name = malloc(MAX_CHNAME_LEN);
	char prefix_name[3];
	int i;

	if (chan_name == NULL)
		return (NULL);

	if (type == RESTARTER_CHANNEL_DELEGATE)
		(void) strcpy(prefix_name, "d_");
	else if (type == RESTARTER_CHANNEL_MASTER)
		(void) strcpy(prefix_name, "m_");
	else {
		free(chan_name);
		return (NULL);
	}

	/*
	 * Create a unique name
	 *
	 * Use the entire name, using a replacement of the /
	 * characters to get a better name.
	 *
	 * Remove the svc:/ from the beginning as this really
	 * isn't going to provide any uniqueness...
	 *
	 * An fmri name greater than MAX_CHNAME_LEN is going
	 * to be rejected as too long for the chan_name below
	 * in the snprintf call.
	 */
	if ((name = strdup(strchr(fmri, '/') + 1)) == NULL) {
		free(chan_name);
		return (NULL);
	}
	i = 0;
	while (name[i]) {
		if (name[i] == '/') {
			name[i] = '_';
		}

		i++;
	}

	/*
	 * Should check for [a-z],[A-Z],[0-9],.,_,-,:
	 */

	if (snprintf(chan_name, MAX_CHNAME_LEN, "com.sun:scf:%s%s",
	    prefix_name, name) > MAX_CHNAME_LEN) {
		free(chan_name);
		chan_name = NULL;
	}

	free(name);
	return (chan_name);
}

int
cb(sysevent_t *syse, void *cookie)
{
	restarter_event_handle_t *h = (restarter_event_handle_t *)cookie;
	restarter_event_t *e;
	nvlist_t *attr_list = NULL;
	int ret = 0;

	e = uu_zalloc(sizeof (restarter_event_t));
	if (e == NULL)
		uu_die(allocfail);
	e->re_event_handle = h;
	e->re_sysevent = syse;

	if (sysevent_get_attr_list(syse, &attr_list) != 0)
		uu_die(allocfail);

	if ((nvlist_lookup_uint32(attr_list, RESTARTER_NAME_TYPE,
	    &(e->re_type)) != 0) ||
	    (nvlist_lookup_string(attr_list,
	    RESTARTER_NAME_INSTANCE, &(e->re_instance_name)) != 0)) {
		uu_warn("%s: Can't decode nvlist for event %p\n",
		    h->reh_restarter_name, (void *)syse);

		ret = 0;
	} else {
		ret = h->reh_handler(e);
	}

	uu_free(e);
	nvlist_free(attr_list);
	return (ret);
}

/*
 * restarter_bind_handle(uint32_t, char *, int (*)(restarter_event_t *), int,
 *     restarter_event_handle_t **)
 *
 * Bind to a delegated restarter event channel.
 * Each delegated restarter gets its own channel for resource management.
 *
 * Returns 0 on success or
 *   ENOTSUP	version mismatch
 *   EINVAL	restarter_name or event_handle is NULL
 *   ENOMEM	out of memory, too many channels, or too many subscriptions
 *   EBUSY	sysevent_evc_bind() could not establish binding
 *   EFAULT	internal sysevent_evc_bind()/sysevent_evc_subscribe() error
 *   EMFILE	out of file descriptors
 *   EPERM	insufficient privilege for sysevent_evc_bind()
 *   EEXIST	already subscribed
 */
int
restarter_bind_handle(uint32_t version, const char *restarter_name,
    int (*event_handler)(restarter_event_t *), int flags,
    restarter_event_handle_t **rehp)
{
	restarter_event_handle_t *h;
	size_t sz;
	int err;

	if (version != RESTARTER_EVENT_VERSION)
		return (ENOTSUP);

	if (restarter_name == NULL || event_handler == NULL)
		return (EINVAL);

	if (flags & RESTARTER_FLAG_DEBUG)
		ndebug++;

	if ((h = uu_zalloc(sizeof (restarter_event_handle_t))) == NULL)
		return (ENOMEM);

	h->reh_delegate_subscriber_id = malloc(MAX_SUBID_LEN);
	h->reh_master_subscriber_id = malloc(MAX_SUBID_LEN);
	h->reh_restarter_name = strdup(restarter_name);
	if (h->reh_delegate_subscriber_id == NULL ||
	    h->reh_master_subscriber_id == NULL ||
	    h->reh_restarter_name == NULL) {
		free_restarter_event_handle(h);
		return (ENOMEM);
	}

	sz = strlcpy(h->reh_delegate_subscriber_id, "del", MAX_SUBID_LEN);
	assert(sz < MAX_SUBID_LEN);
	sz = strlcpy(h->reh_master_subscriber_id, "master", MAX_SUBID_LEN);
	assert(sz < MAX_SUBID_LEN);

	h->reh_delegate_channel_name =
	    _restarter_get_channel_name(restarter_name,
	    RESTARTER_CHANNEL_DELEGATE);
	h->reh_master_channel_name =
	    _restarter_get_channel_name(restarter_name,
	    RESTARTER_CHANNEL_MASTER);

	if (h->reh_delegate_channel_name == NULL ||
	    h->reh_master_channel_name == NULL) {
		free_restarter_event_handle(h);
		return (ENOMEM);
	}

	if (sysevent_evc_bind(h->reh_delegate_channel_name,
	    &h->reh_delegate_channel, EVCH_CREAT|EVCH_HOLD_PEND) != 0) {
		err = errno;
		assert(err != EINVAL);
		assert(err != ENOENT);
		free_restarter_event_handle(h);
		return (err);
	}

	if (sysevent_evc_bind(h->reh_master_channel_name,
	    &h->reh_master_channel, EVCH_CREAT|EVCH_HOLD_PEND) != 0) {
		err = errno;
		assert(err != EINVAL);
		assert(err != ENOENT);
		free_restarter_event_handle(h);
		return (err);
	}

	h->reh_handler = event_handler;

	assert(strlen(restarter_name) <= MAX_CLASS_LEN - 1);
	assert(strlen(h->reh_delegate_subscriber_id) <= MAX_SUBID_LEN - 1);
	assert(strlen(h->reh_master_subscriber_id) <= MAX_SUBID_LEN - 1);

	if (sysevent_evc_subscribe(h->reh_delegate_channel,
	    h->reh_delegate_subscriber_id, EC_ALL, cb, h, EVCH_SUB_KEEP) != 0) {
		err = errno;
		assert(err != EINVAL);
		free_restarter_event_handle(h);
		return (err);
	}

	*rehp = h;
	return (0);
}

restarter_event_handle_t *
restarter_event_get_handle(restarter_event_t *e)
{
	assert(e != NULL && e->re_event_handle != NULL);
	return (e->re_event_handle);
}

restarter_event_type_t
restarter_event_get_type(restarter_event_t *e)
{
	assert(e != NULL);
	return (e->re_type);
}

ssize_t
restarter_event_get_instance(restarter_event_t *e, char *inst, size_t sz)
{
	assert(e != NULL && inst != NULL);
	return ((ssize_t)strlcpy(inst, e->re_instance_name, sz));
}

int
restarter_event_get_current_states(restarter_event_t *e,
    restarter_instance_state_t *state, restarter_instance_state_t *next_state)
{
	if (e == NULL)
		return (-1);
	*state = e->re_state;
	*next_state = e->re_next_state;
	return (0);
}

/*
 * restarter_event_publish_retry() is a wrapper around sysevent_evc_publish().
 * In case, the event cannot be sent at the first attempt (sysevent_evc_publish
 * returned EAGAIN - sysevent queue full), this function retries a few time
 * and return ENOSPC if it reaches the retry limit.
 *
 * The arguments to this function map the arguments of sysevent_evc_publish().
 *
 * On success, return 0. On error, return
 *
 *   EFAULT - internal sysevent_evc_publish() error
 *   ENOMEM - internal sysevent_evc_publish() error
 *   EBADF - scp is invalid (sysevent_evc_publish() returned EINVAL)
 *   ENOSPC - sysevent queue full (sysevent_evc_publish() returned EAGAIN)
 */
int
restarter_event_publish_retry(evchan_t *scp, const char *class,
    const char *subclass, const char *vendor, const char *pub_name,
    nvlist_t *attr_list, uint32_t flags)
{
	int retries, ret;
	useconds_t retry_int = INITIAL_COMMIT_RETRY_INT;

	for (retries = 0; retries < MAX_COMMIT_RETRIES; retries++) {
		ret = sysevent_evc_publish(scp, class, subclass, vendor,
		    pub_name, attr_list, flags);
		if (ret == 0)
			break;

		switch (ret) {
		case EAGAIN:
			/* Queue is full */
			(void) usleep(retry_int);

			retry_int = min(retry_int * 2, MAX_COMMIT_RETRY_INT);
			break;

		case EINVAL:
			ret = EBADF;
			/* FALLTHROUGH */

		case EFAULT:
		case ENOMEM:
			return (ret);

		case EOVERFLOW:
		default:
			/* internal error - abort */
			bad_fail("sysevent_evc_publish", ret);
		}
	}

	if (retries == MAX_COMMIT_RETRIES)
		ret = ENOSPC;

	return (ret);
}

/*
 * Commit the state, next state, and auxiliary state into the repository.
 * Let the graph engine know about the state change and error.  On success,
 * return 0. On error, return
 *   EPROTO - librestart compiled against different libscf
 *   ENOMEM - out of memory
 *	    - repository server out of resources
 *   ENOTACTIVE - repository server not running
 *   ECONNABORTED - repository connection established, but then broken
 *		  - unknown libscf error
 *   ENOENT - inst does not exist in the repository
 *   EPERM - insufficient permissions
 *   EACCESS - backend access denied
 *   EROFS - backend is readonly
 *   EFAULT - internal sysevent_evc_publish() error
 *   EBADF - h is invalid (sysevent_evc_publish() returned EINVAL)
 *   ENOSPC - sysevent queue full (sysevent_evc_publish() returned EAGAIN)
 */
int
restarter_set_states(restarter_event_handle_t *h, const char *inst,
    restarter_instance_state_t cur_state,
    restarter_instance_state_t new_cur_state,
    restarter_instance_state_t next_state,
    restarter_instance_state_t new_next_state, restarter_error_t e,
    restarter_str_t aux)
{
	nvlist_t *attr;
	scf_handle_t *scf_h;
	instance_data_t id;
	int ret = 0;
	const char *p = restarter_get_str_short(aux);

	assert(h->reh_master_channel != NULL);
	assert(h->reh_master_channel_name != NULL);
	assert(h->reh_master_subscriber_id != NULL);

	if ((scf_h = scf_handle_create(SCF_VERSION)) == NULL) {
		switch (scf_error()) {
		case SCF_ERROR_VERSION_MISMATCH:
			return (EPROTO);

		case SCF_ERROR_NO_MEMORY:
			return (ENOMEM);

		default:
			bad_fail("scf_handle_create", scf_error());
		}
	}

	if (scf_handle_bind(scf_h) == -1) {
		scf_handle_destroy(scf_h);
		switch (scf_error()) {
		case SCF_ERROR_NO_SERVER:
			return (ENOTACTIVE);

		case SCF_ERROR_NO_RESOURCES:
			return (ENOMEM);

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_IN_USE:
		default:
			bad_fail("scf_handle_bind", scf_error());
		}
	}

	if (nvlist_alloc(&attr, NV_UNIQUE_NAME, 0) != 0 ||
	    nvlist_add_int32(attr, RESTARTER_NAME_STATE, new_cur_state) != 0 ||
	    nvlist_add_int32(attr, RESTARTER_NAME_NEXT_STATE, new_next_state)
	    != 0 ||
	    nvlist_add_int32(attr, RESTARTER_NAME_ERROR, e) != 0 ||
	    nvlist_add_string(attr, RESTARTER_NAME_INSTANCE, inst) != 0 ||
	    nvlist_add_int32(attr, RESTARTER_NAME_REASON, aux) != 0) {
		ret = ENOMEM;
	} else {
		id.i_fmri = inst;
		id.i_state = cur_state;
		id.i_next_state = next_state;

		ret = _restarter_commit_states(scf_h, &id, new_cur_state,
		    new_next_state, p);

		if (ret == 0) {
			ret = restarter_event_publish_retry(
			    h->reh_master_channel, "master", "state_change",
			    "com.sun", "librestart", attr, EVCH_NOSLEEP);
		}
	}

	nvlist_free(attr);
	(void) scf_handle_unbind(scf_h);
	scf_handle_destroy(scf_h);

	return (ret);
}

restarter_instance_state_t
restarter_string_to_state(char *string)
{
	assert(string != NULL);

	if (strcmp(string, SCF_STATE_STRING_NONE) == 0)
		return (RESTARTER_STATE_NONE);
	else if (strcmp(string, SCF_STATE_STRING_UNINIT) == 0)
		return (RESTARTER_STATE_UNINIT);
	else if (strcmp(string, SCF_STATE_STRING_MAINT) == 0)
		return (RESTARTER_STATE_MAINT);
	else if (strcmp(string, SCF_STATE_STRING_OFFLINE) == 0)
		return (RESTARTER_STATE_OFFLINE);
	else if (strcmp(string, SCF_STATE_STRING_DISABLED) == 0)
		return (RESTARTER_STATE_DISABLED);
	else if (strcmp(string, SCF_STATE_STRING_ONLINE) == 0)
		return (RESTARTER_STATE_ONLINE);
	else if (strcmp(string, SCF_STATE_STRING_DEGRADED) == 0)
		return (RESTARTER_STATE_DEGRADED);
	else {
		return (RESTARTER_STATE_NONE);
	}
}

ssize_t
restarter_state_to_string(restarter_instance_state_t state, char *string,
    size_t len)
{
	assert(string != NULL);

	if (state == RESTARTER_STATE_NONE)
		return ((ssize_t)strlcpy(string, SCF_STATE_STRING_NONE, len));
	else if (state == RESTARTER_STATE_UNINIT)
		return ((ssize_t)strlcpy(string, SCF_STATE_STRING_UNINIT, len));
	else if (state == RESTARTER_STATE_MAINT)
		return ((ssize_t)strlcpy(string, SCF_STATE_STRING_MAINT, len));
	else if (state == RESTARTER_STATE_OFFLINE)
		return ((ssize_t)strlcpy(string, SCF_STATE_STRING_OFFLINE,
		    len));
	else if (state == RESTARTER_STATE_DISABLED)
		return ((ssize_t)strlcpy(string, SCF_STATE_STRING_DISABLED,
		    len));
	else if (state == RESTARTER_STATE_ONLINE)
		return ((ssize_t)strlcpy(string, SCF_STATE_STRING_ONLINE, len));
	else if (state == RESTARTER_STATE_DEGRADED)
		return ((ssize_t)strlcpy(string, SCF_STATE_STRING_DEGRADED,
		    len));
	else
		return ((ssize_t)strlcpy(string, "unknown", len));
}

/*
 * Sets pg to the name property group of s_inst.  If it doesn't exist, it is
 * added.
 *
 * Fails with
 *   ECONNABORTED - repository disconnection or unknown libscf error
 *   EBADF - inst is not set
 *   ECANCELED - inst is deleted
 *   EPERM - permission is denied
 *   EACCES - backend denied access
 *   EROFS - backend readonly
 */
static int
instance_get_or_add_pg(scf_instance_t *inst, const char *name,
    const char *type, uint32_t flags, scf_propertygroup_t *pg)
{
again:
	if (scf_instance_get_pg(inst, name, pg) == 0)
		return (0);

	switch (scf_error()) {
	case SCF_ERROR_CONNECTION_BROKEN:
	default:
		return (ECONNABORTED);

	case SCF_ERROR_NOT_SET:
		return (EBADF);

	case SCF_ERROR_DELETED:
		return (ECANCELED);

	case SCF_ERROR_NOT_FOUND:
		break;

	case SCF_ERROR_HANDLE_MISMATCH:
	case SCF_ERROR_INVALID_ARGUMENT:
		bad_fail("scf_instance_get_pg", scf_error());
	}

	if (scf_instance_add_pg(inst, name, type, flags, pg) == 0)
		return (0);

	switch (scf_error()) {
	case SCF_ERROR_CONNECTION_BROKEN:
	default:
		return (ECONNABORTED);

	case SCF_ERROR_DELETED:
		return (ECANCELED);

	case SCF_ERROR_EXISTS:
		goto again;

	case SCF_ERROR_PERMISSION_DENIED:
		return (EPERM);

	case SCF_ERROR_BACKEND_ACCESS:
		return (EACCES);

	case SCF_ERROR_BACKEND_READONLY:
		return (EROFS);

	case SCF_ERROR_HANDLE_MISMATCH:
	case SCF_ERROR_INVALID_ARGUMENT:
	case SCF_ERROR_NOT_SET:			/* should be caught above */
		bad_fail("scf_instance_add_pg", scf_error());
	}

	return (0);
}

/*
 * Fails with
 *   ECONNABORTED
 *   ECANCELED - pg was deleted
 */
static int
tx_set_value(scf_transaction_t *tx, scf_transaction_entry_t *ent,
    const char *pname, scf_type_t ty, scf_value_t *val)
{
	int r;

	for (;;) {
		if (scf_transaction_property_change_type(tx, ent, pname,
		    ty) == 0)
			break;

		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_IN_USE:
		case SCF_ERROR_NOT_SET:
			bad_fail("scf_transaction_property_change_type",
			    scf_error());
		}

		if (scf_transaction_property_new(tx, ent, pname, ty) == 0)
			break;

		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			return (ECONNABORTED);

		case SCF_ERROR_DELETED:
			return (ECANCELED);

		case SCF_ERROR_EXISTS:
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_IN_USE:
		case SCF_ERROR_NOT_SET:
			bad_fail("scf_transaction_property_new", scf_error());
		}
	}

	r = scf_entry_add_value(ent, val);
	assert(r == 0);

	return (0);
}

/*
 * Commit new_state, new_next_state, and aux to the repository for id.  If
 * successful, also set id's state and next-state as given, and return 0.
 * Fails with
 *   ENOMEM - out of memory
 *   ECONNABORTED - repository connection broken
 *		  - unknown libscf error
 *   EINVAL - id->i_fmri is invalid or not an instance FMRI
 *   ENOENT - id->i_fmri does not exist
 *   EPERM - insufficient permissions
 *   EACCES - backend access denied
 *   EROFS - backend is readonly
 */
int
_restarter_commit_states(scf_handle_t *h, instance_data_t *id,
    restarter_instance_state_t new_state,
    restarter_instance_state_t new_state_next, const char *aux)
{
	char str_state[MAX_SCF_STATE_STRING_SZ];
	char str_new_state[MAX_SCF_STATE_STRING_SZ];
	char str_state_next[MAX_SCF_STATE_STRING_SZ];
	char str_new_state_next[MAX_SCF_STATE_STRING_SZ];
	int ret = 0, r;
	struct timeval now;
	ssize_t sz;

	scf_transaction_t *t = NULL;
	scf_transaction_entry_t *t_state = NULL, *t_state_next = NULL;
	scf_transaction_entry_t *t_stime = NULL, *t_aux = NULL;
	scf_value_t *v_state = NULL, *v_state_next = NULL, *v_stime = NULL;
	scf_value_t *v_aux = NULL;
	scf_instance_t *s_inst = NULL;
	scf_propertygroup_t *pg = NULL;

	assert(new_state != RESTARTER_STATE_NONE);

	if ((s_inst = scf_instance_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (t = scf_transaction_create(h)) == NULL ||
	    (t_state = scf_entry_create(h)) == NULL ||
	    (t_state_next = scf_entry_create(h)) == NULL ||
	    (t_stime = scf_entry_create(h)) == NULL ||
	    (t_aux = scf_entry_create(h)) == NULL ||
	    (v_state = scf_value_create(h)) == NULL ||
	    (v_state_next = scf_value_create(h)) == NULL ||
	    (v_stime = scf_value_create(h)) == NULL ||
	    (v_aux = scf_value_create(h)) == NULL) {
		ret = ENOMEM;
		goto out;
	}

	sz = restarter_state_to_string(new_state, str_new_state,
	    sizeof (str_new_state));
	assert(sz < sizeof (str_new_state));
	sz = restarter_state_to_string(new_state_next, str_new_state_next,
	    sizeof (str_new_state_next));
	assert(sz < sizeof (str_new_state_next));
	sz = restarter_state_to_string(id->i_state, str_state,
	    sizeof (str_state));
	assert(sz < sizeof (str_state));
	sz = restarter_state_to_string(id->i_next_state, str_state_next,
	    sizeof (str_state_next));
	assert(sz < sizeof (str_state_next));

	ret = gettimeofday(&now, NULL);
	assert(ret != -1);

	if (scf_handle_decode_fmri(h, id->i_fmri, NULL, NULL, s_inst,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT) == -1) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
		default:
			ret = ECONNABORTED;
			break;

		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_CONSTRAINT_VIOLATED:
			ret = EINVAL;
			break;

		case SCF_ERROR_NOT_FOUND:
			ret = ENOENT;
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
			bad_fail("scf_handle_decode_fmri", scf_error());
		}
		goto out;
	}


	if (scf_value_set_astring(v_state, str_new_state) != 0 ||
	    scf_value_set_astring(v_state_next, str_new_state_next) != 0)
		bad_fail("scf_value_set_astring", scf_error());

	if (aux) {
		if (scf_value_set_astring(v_aux, aux) != 0)
			bad_fail("scf_value_set_astring", scf_error());
	}

	if (scf_value_set_time(v_stime, now.tv_sec, now.tv_usec * 1000) != 0)
		bad_fail("scf_value_set_time", scf_error());

add_pg:
	switch (r = instance_get_or_add_pg(s_inst, SCF_PG_RESTARTER,
	    SCF_PG_RESTARTER_TYPE, SCF_PG_RESTARTER_FLAGS, pg)) {
	case 0:
		break;

	case ECONNABORTED:
	case EPERM:
	case EACCES:
	case EROFS:
		ret = r;
		goto out;

	case ECANCELED:
		ret = ENOENT;
		goto out;

	case EBADF:
	default:
		bad_fail("instance_get_or_add_pg", r);
	}

	for (;;) {
		if (scf_transaction_start(t, pg) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_NOT_SET:
				goto add_pg;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_IN_USE:
				bad_fail("scf_transaction_start", scf_error());
			}
		}

		if ((r = tx_set_value(t, t_state, SCF_PROPERTY_STATE,
		    SCF_TYPE_ASTRING, v_state)) != 0 ||
		    (r = tx_set_value(t, t_state_next, SCF_PROPERTY_NEXT_STATE,
		    SCF_TYPE_ASTRING, v_state_next)) != 0 ||
		    (r = tx_set_value(t, t_stime, SCF_PROPERTY_STATE_TIMESTAMP,
		    SCF_TYPE_TIME, v_stime)) != 0) {
			switch (r) {
			case ECONNABORTED:
				ret = ECONNABORTED;
				goto out;

			case ECANCELED:
				scf_transaction_reset(t);
				goto add_pg;

			default:
				bad_fail("tx_set_value", r);
			}
		}

		if (aux) {
			if ((r = tx_set_value(t, t_aux, SCF_PROPERTY_AUX_STATE,
			    SCF_TYPE_ASTRING, v_aux)) != 0) {
				switch (r) {
				case ECONNABORTED:
					ret = ECONNABORTED;
					goto out;

				case ECANCELED:
					scf_transaction_reset(t);
					goto add_pg;

				default:
					bad_fail("tx_set_value", r);
				}
			}
		}

		ret = scf_transaction_commit(t);
		if (ret == 1)
			break;
		if (ret == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			case SCF_ERROR_NOT_SET:
				bad_fail("scf_transaction_commit", scf_error());
			}
		}

		scf_transaction_reset(t);
		if (scf_pg_update(pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_NOT_SET:
				goto add_pg;
			}
		}
	}

	id->i_state = new_state;
	id->i_next_state = new_state_next;
	ret = 0;

out:
	scf_transaction_destroy(t);
	scf_entry_destroy(t_state);
	scf_entry_destroy(t_state_next);
	scf_entry_destroy(t_stime);
	scf_entry_destroy(t_aux);
	scf_value_destroy(v_state);
	scf_value_destroy(v_state_next);
	scf_value_destroy(v_stime);
	scf_value_destroy(v_aux);
	scf_pg_destroy(pg);
	scf_instance_destroy(s_inst);

	return (ret);
}

/*
 * Fails with
 *   EINVAL - type is invalid
 *   ENOMEM
 *   ECONNABORTED - repository connection broken
 *   EBADF - s_inst is not set
 *   ECANCELED - s_inst is deleted
 *   EPERM - permission denied
 *   EACCES - backend access denied
 *   EROFS - backend readonly
 */
int
restarter_remove_contract(scf_instance_t *s_inst, ctid_t contract_id,
    restarter_contract_type_t type)
{
	scf_handle_t *h;
	scf_transaction_t *t = NULL;
	scf_transaction_entry_t *t_cid = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *val;
	scf_iter_t *iter = NULL;
	const char *pname;
	int ret = 0, primary;
	uint64_t c;

	switch (type) {
	case RESTARTER_CONTRACT_PRIMARY:
		primary = 1;
		break;
	case RESTARTER_CONTRACT_TRANSIENT:
		primary = 0;
		break;
	default:
		return (EINVAL);
	}

	h = scf_instance_handle(s_inst);

	pg = scf_pg_create(h);
	prop = scf_property_create(h);
	iter = scf_iter_create(h);
	t = scf_transaction_create(h);

	if (pg == NULL || prop == NULL || iter == NULL || t == NULL) {
		ret = ENOMEM;
		goto remove_contract_cleanup;
	}

add:
	scf_transaction_destroy_children(t);
	ret = instance_get_or_add_pg(s_inst, SCF_PG_RESTARTER,
	    SCF_PG_RESTARTER_TYPE, SCF_PG_RESTARTER_FLAGS, pg);
	if (ret != 0)
		goto remove_contract_cleanup;

	pname = primary? SCF_PROPERTY_CONTRACT :
	    SCF_PROPERTY_TRANSIENT_CONTRACT;

	for (;;) {
		if (scf_transaction_start(t, pg) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto remove_contract_cleanup;

			case SCF_ERROR_DELETED:
				goto add;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto remove_contract_cleanup;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto remove_contract_cleanup;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto remove_contract_cleanup;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_IN_USE:
			case SCF_ERROR_NOT_SET:
				bad_fail("scf_transaction_start", scf_error());
			}
		}

		t_cid = scf_entry_create(h);

		if (scf_pg_get_property(pg, pname, prop) == 0) {
replace:
			if (scf_transaction_property_change_type(t, t_cid,
			    pname, SCF_TYPE_COUNT) != 0) {
				switch (scf_error()) {
				case SCF_ERROR_CONNECTION_BROKEN:
				default:
					ret = ECONNABORTED;
					goto remove_contract_cleanup;

				case SCF_ERROR_DELETED:
					scf_entry_destroy(t_cid);
					goto add;

				case SCF_ERROR_NOT_FOUND:
					goto new;

				case SCF_ERROR_HANDLE_MISMATCH:
				case SCF_ERROR_INVALID_ARGUMENT:
				case SCF_ERROR_IN_USE:
				case SCF_ERROR_NOT_SET:
					bad_fail(
					"scf_transaction_property_changetype",
					    scf_error());
				}
			}

			if (scf_property_is_type(prop, SCF_TYPE_COUNT) == 0) {
				if (scf_iter_property_values(iter, prop) != 0) {
					switch (scf_error()) {
					case SCF_ERROR_CONNECTION_BROKEN:
					default:
						ret = ECONNABORTED;
						goto remove_contract_cleanup;

					case SCF_ERROR_NOT_SET:
					case SCF_ERROR_HANDLE_MISMATCH:
						bad_fail(
						    "scf_iter_property_values",
						    scf_error());
					}
				}

next_val:
				val = scf_value_create(h);
				if (val == NULL) {
					assert(scf_error() ==
					    SCF_ERROR_NO_MEMORY);
					ret = ENOMEM;
					goto remove_contract_cleanup;
				}

				ret = scf_iter_next_value(iter, val);
				if (ret == -1) {
					switch (scf_error()) {
					case SCF_ERROR_CONNECTION_BROKEN:
						ret = ECONNABORTED;
						goto remove_contract_cleanup;

					case SCF_ERROR_DELETED:
						scf_value_destroy(val);
						goto add;

					case SCF_ERROR_HANDLE_MISMATCH:
					case SCF_ERROR_INVALID_ARGUMENT:
					case SCF_ERROR_PERMISSION_DENIED:
					default:
						bad_fail("scf_iter_next_value",
						    scf_error());
					}
				}

				if (ret == 1) {
					ret = scf_value_get_count(val, &c);
					assert(ret == 0);

					if (c != contract_id) {
						ret = scf_entry_add_value(t_cid,
						    val);
						assert(ret == 0);
					} else {
						scf_value_destroy(val);
					}

					goto next_val;
				}

				scf_value_destroy(val);
			} else {
				switch (scf_error()) {
				case SCF_ERROR_CONNECTION_BROKEN:
				default:
					ret = ECONNABORTED;
					goto remove_contract_cleanup;

				case SCF_ERROR_TYPE_MISMATCH:
					break;

				case SCF_ERROR_INVALID_ARGUMENT:
				case SCF_ERROR_NOT_SET:
					bad_fail("scf_property_is_type",
					    scf_error());
				}
			}
		} else {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto remove_contract_cleanup;

			case SCF_ERROR_DELETED:
				scf_entry_destroy(t_cid);
				goto add;

			case SCF_ERROR_NOT_FOUND:
				break;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_SET:
				bad_fail("scf_pg_get_property", scf_error());
			}

new:
			if (scf_transaction_property_new(t, t_cid, pname,
			    SCF_TYPE_COUNT) != 0) {
				switch (scf_error()) {
				case SCF_ERROR_CONNECTION_BROKEN:
				default:
					ret = ECONNABORTED;
					goto remove_contract_cleanup;

				case SCF_ERROR_DELETED:
					scf_entry_destroy(t_cid);
					goto add;

				case SCF_ERROR_EXISTS:
					goto replace;

				case SCF_ERROR_HANDLE_MISMATCH:
				case SCF_ERROR_INVALID_ARGUMENT:
				case SCF_ERROR_NOT_SET:
					bad_fail("scf_transaction_property_new",
					    scf_error());
				}
			}
		}

		ret = scf_transaction_commit(t);
		if (ret == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto remove_contract_cleanup;

			case SCF_ERROR_DELETED:
				goto add;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto remove_contract_cleanup;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto remove_contract_cleanup;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto remove_contract_cleanup;

			case SCF_ERROR_NOT_SET:
				bad_fail("scf_transaction_commit", scf_error());
			}
		}
		if (ret == 1) {
			ret = 0;
			break;
		}

		scf_transaction_destroy_children(t);
		if (scf_pg_update(pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto remove_contract_cleanup;

			case SCF_ERROR_DELETED:
				goto add;

			case SCF_ERROR_NOT_SET:
				bad_fail("scf_pg_update", scf_error());
			}
		}
	}

remove_contract_cleanup:
	scf_transaction_destroy_children(t);
	scf_transaction_destroy(t);
	scf_iter_destroy(iter);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);

	return (ret);
}

/*
 * Fails with
 *   EINVAL - type is invalid
 *   ENOMEM
 *   ECONNABORTED - repository disconnection
 *   EBADF - s_inst is not set
 *   ECANCELED - s_inst is deleted
 *   EPERM
 *   EACCES
 *   EROFS
 */
int
restarter_store_contract(scf_instance_t *s_inst, ctid_t contract_id,
    restarter_contract_type_t type)
{
	scf_handle_t *h;
	scf_transaction_t *t = NULL;
	scf_transaction_entry_t *t_cid = NULL;
	scf_value_t *val;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_iter_t *iter = NULL;
	const char *pname;
	int ret = 0, primary;

	if (type == RESTARTER_CONTRACT_PRIMARY)
		primary = 1;
	else if (type == RESTARTER_CONTRACT_TRANSIENT)
		primary = 0;
	else
		return (EINVAL);

	h = scf_instance_handle(s_inst);

	pg = scf_pg_create(h);
	prop = scf_property_create(h);
	iter = scf_iter_create(h);
	t = scf_transaction_create(h);

	if (pg == NULL || prop == NULL || iter == NULL || t == NULL) {
		ret = ENOMEM;
		goto out;
	}

add:
	scf_transaction_destroy_children(t);
	ret = instance_get_or_add_pg(s_inst, SCF_PG_RESTARTER,
	    SCF_PG_RESTARTER_TYPE, SCF_PG_RESTARTER_FLAGS, pg);
	if (ret != 0)
		goto out;

	pname = primary ? SCF_PROPERTY_CONTRACT :
	    SCF_PROPERTY_TRANSIENT_CONTRACT;

	for (;;) {
		if (scf_transaction_start(t, pg) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				goto add;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_IN_USE:
			case SCF_ERROR_NOT_SET:
				bad_fail("scf_transaction_start", scf_error());
			}
		}

		t_cid = scf_entry_create(h);
		if (t_cid == NULL) {
			ret = ENOMEM;
			goto out;
		}

		if (scf_pg_get_property(pg, pname, prop) == 0) {
replace:
			if (scf_transaction_property_change_type(t, t_cid,
			    pname, SCF_TYPE_COUNT) != 0) {
				switch (scf_error()) {
				case SCF_ERROR_CONNECTION_BROKEN:
				default:
					ret = ECONNABORTED;
					goto out;

				case SCF_ERROR_DELETED:
					scf_entry_destroy(t_cid);
					goto add;

				case SCF_ERROR_NOT_FOUND:
					goto new;

				case SCF_ERROR_HANDLE_MISMATCH:
				case SCF_ERROR_INVALID_ARGUMENT:
				case SCF_ERROR_IN_USE:
				case SCF_ERROR_NOT_SET:
					bad_fail(
					"scf_transaction_propert_change_type",
					    scf_error());
				}
			}

			if (scf_property_is_type(prop, SCF_TYPE_COUNT) == 0) {
				if (scf_iter_property_values(iter, prop) != 0) {
					switch (scf_error()) {
					case SCF_ERROR_CONNECTION_BROKEN:
					default:
						ret = ECONNABORTED;
						goto out;

					case SCF_ERROR_NOT_SET:
					case SCF_ERROR_HANDLE_MISMATCH:
						bad_fail(
						    "scf_iter_property_values",
						    scf_error());
					}
				}

next_val:
				val = scf_value_create(h);
				if (val == NULL) {
					assert(scf_error() ==
					    SCF_ERROR_NO_MEMORY);
					ret = ENOMEM;
					goto out;
				}

				ret = scf_iter_next_value(iter, val);
				if (ret == -1) {
					switch (scf_error()) {
					case SCF_ERROR_CONNECTION_BROKEN:
					default:
						ret = ECONNABORTED;
						goto out;

					case SCF_ERROR_DELETED:
						scf_value_destroy(val);
						goto add;

					case SCF_ERROR_HANDLE_MISMATCH:
					case SCF_ERROR_INVALID_ARGUMENT:
					case SCF_ERROR_PERMISSION_DENIED:
						bad_fail(
						    "scf_iter_next_value",
						    scf_error());
					}
				}

				if (ret == 1) {
					ret = scf_entry_add_value(t_cid, val);
					assert(ret == 0);

					goto next_val;
				}

				scf_value_destroy(val);
			} else {
				switch (scf_error()) {
				case SCF_ERROR_CONNECTION_BROKEN:
				default:
					ret = ECONNABORTED;
					goto out;

				case SCF_ERROR_TYPE_MISMATCH:
					break;

				case SCF_ERROR_INVALID_ARGUMENT:
				case SCF_ERROR_NOT_SET:
					bad_fail("scf_property_is_type",
					    scf_error());
				}
			}
		} else {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				scf_entry_destroy(t_cid);
				goto add;

			case SCF_ERROR_NOT_FOUND:
				break;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_SET:
				bad_fail("scf_pg_get_property", scf_error());
			}

new:
			if (scf_transaction_property_new(t, t_cid, pname,
			    SCF_TYPE_COUNT) != 0) {
				switch (scf_error()) {
				case SCF_ERROR_CONNECTION_BROKEN:
				default:
					ret = ECONNABORTED;
					goto out;

				case SCF_ERROR_DELETED:
					scf_entry_destroy(t_cid);
					goto add;

				case SCF_ERROR_EXISTS:
					goto replace;

				case SCF_ERROR_HANDLE_MISMATCH:
				case SCF_ERROR_INVALID_ARGUMENT:
				case SCF_ERROR_NOT_SET:
					bad_fail("scf_transaction_property_new",
					    scf_error());
				}
			}
		}

		val = scf_value_create(h);
		if (val == NULL) {
			assert(scf_error() == SCF_ERROR_NO_MEMORY);
			ret = ENOMEM;
			goto out;
		}

		scf_value_set_count(val, contract_id);
		ret = scf_entry_add_value(t_cid, val);
		assert(ret == 0);

		ret = scf_transaction_commit(t);
		if (ret == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				goto add;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			case SCF_ERROR_NOT_SET:
				bad_fail("scf_transaction_commit", scf_error());
			}
		}
		if (ret == 1) {
			ret = 0;
			break;
		}

		scf_transaction_destroy_children(t);
		if (scf_pg_update(pg) == -1) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			default:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				goto add;

			case SCF_ERROR_NOT_SET:
				bad_fail("scf_pg_update", scf_error());
			}
		}
	}

out:
	scf_transaction_destroy_children(t);
	scf_transaction_destroy(t);
	scf_iter_destroy(iter);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);

	return (ret);
}

int
restarter_rm_libs_loadable()
{
	void *libhndl;

	if (method_context_safety)
		return (1);

	if ((libhndl = dlopen("libpool.so", RTLD_LAZY | RTLD_LOCAL)) == NULL)
		return (0);

	(void) dlclose(libhndl);

	if ((libhndl = dlopen("libproject.so", RTLD_LAZY | RTLD_LOCAL)) == NULL)
		return (0);

	(void) dlclose(libhndl);

	method_context_safety = 1;

	return (1);
}

static int
get_astring_val(scf_propertygroup_t *pg, const char *name, char *buf,
    size_t bufsz, scf_property_t *prop, scf_value_t *val)
{
	ssize_t szret;

	if (pg == NULL)
		return (-1);

	if (scf_pg_get_property(pg, name, prop) != SCF_SUCCESS) {
		if (scf_error() == SCF_ERROR_CONNECTION_BROKEN)
			uu_die(rcbroken);
		return (-1);
	}

	if (scf_property_get_value(prop, val) != SCF_SUCCESS) {
		if (scf_error() == SCF_ERROR_CONNECTION_BROKEN)
			uu_die(rcbroken);
		return (-1);
	}

	szret = scf_value_get_astring(val, buf, bufsz);

	return (szret >= 0 ? 0 : -1);
}

static int
get_boolean_val(scf_propertygroup_t *pg, const char *name, uint8_t *b,
    scf_property_t *prop, scf_value_t *val)
{
	if (scf_pg_get_property(pg, name, prop) != SCF_SUCCESS) {
		if (scf_error() == SCF_ERROR_CONNECTION_BROKEN)
			uu_die(rcbroken);
		return (-1);
	}

	if (scf_property_get_value(prop, val) != SCF_SUCCESS) {
		if (scf_error() == SCF_ERROR_CONNECTION_BROKEN)
			uu_die(rcbroken);
		return (-1);
	}

	if (scf_value_get_boolean(val, b))
		return (-1);

	return (0);
}

/*
 * Try to load mcp->pwd, if it isn't already.
 * Fails with
 *   ENOMEM - malloc() failed
 *   ENOENT - no entry found
 *   EIO - I/O error
 *   EMFILE - process out of file descriptors
 *   ENFILE - system out of file handles
 */
static int
lookup_pwd(struct method_context *mcp)
{
	struct passwd *pwdp;

	if (mcp->pwbuf != NULL && mcp->pwd.pw_uid == mcp->uid)
		return (0);

	if (mcp->pwbuf == NULL) {
		mcp->pwbufsz = sysconf(_SC_GETPW_R_SIZE_MAX);
		assert(mcp->pwbufsz >= 0);
		mcp->pwbuf = malloc(mcp->pwbufsz);
		if (mcp->pwbuf == NULL)
			return (ENOMEM);
	}

	do {
		errno = 0;
		pwdp = getpwuid_r(mcp->uid, &mcp->pwd, mcp->pwbuf,
		    mcp->pwbufsz);
	} while (pwdp == NULL && errno == EINTR);
	if (pwdp != NULL)
		return (0);

	free(mcp->pwbuf);
	mcp->pwbuf = NULL;

	switch (errno) {
	case 0:
	default:
		/*
		 * Until bug 5065780 is fixed, getpwuid_r() can fail with
		 * ENOENT, particularly on the miniroot.  Since the
		 * documentation is inaccurate, we'll return ENOENT for unknown
		 * errors.
		 */
		return (ENOENT);

	case EIO:
	case EMFILE:
	case ENFILE:
		return (errno);

	case ERANGE:
		bad_fail("getpwuid_r", errno);
		/* NOTREACHED */
	}
}

/*
 * Get the user id for str.  Returns 0 on success or
 *   ERANGE	the uid is too big
 *   EINVAL	the string starts with a digit, but is not a valid uid
 *   ENOMEM	out of memory
 *   ENOENT	no passwd entry for str
 *   EIO	an I/O error has occurred
 *   EMFILE/ENFILE  out of file descriptors
 */
int
get_uid(const char *str, struct method_context *ci, uid_t *uidp)
{
	if (isdigit(str[0])) {
		uid_t uid;
		char *cp;

		errno = 0;
		uid = strtol(str, &cp, 10);

		if (uid == 0 && errno != 0) {
			assert(errno != EINVAL);
			return (errno);
		}

		for (; *cp != '\0'; ++cp)
			if (*cp != ' ' || *cp != '\t')
				return (EINVAL);

		if (uid > UID_MAX)
			return (EINVAL);

		*uidp = uid;
		return (0);
	} else {
		struct passwd *pwdp;

		if (ci->pwbuf == NULL) {
			ci->pwbufsz = sysconf(_SC_GETPW_R_SIZE_MAX);
			ci->pwbuf = malloc(ci->pwbufsz);
			if (ci->pwbuf == NULL)
				return (ENOMEM);
		}

		do {
			errno = 0;
			pwdp =
			    getpwnam_r(str, &ci->pwd, ci->pwbuf, ci->pwbufsz);
		} while (pwdp == NULL && errno == EINTR);

		if (pwdp != NULL) {
			*uidp = ci->pwd.pw_uid;
			return (0);
		} else {
			free(ci->pwbuf);
			ci->pwbuf = NULL;
			switch (errno) {
			case 0:
				return (ENOENT);

			case ENOENT:
			case EIO:
			case EMFILE:
			case ENFILE:
				return (errno);

			case ERANGE:
			default:
				bad_fail("getpwnam_r", errno);
				/* NOTREACHED */
			}
		}
	}
}

gid_t
get_gid(const char *str)
{
	if (isdigit(str[0])) {
		gid_t gid;
		char *cp;

		errno = 0;
		gid = strtol(str, &cp, 10);

		if (gid == 0 && errno != 0)
			return ((gid_t)-1);

		for (; *cp != '\0'; ++cp)
			if (*cp != ' ' || *cp != '\t')
				return ((gid_t)-1);

		return (gid);
	} else {
		struct group grp, *ret;
		char *buffer;
		size_t buflen;

		buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
		buffer = malloc(buflen);
		if (buffer == NULL)
			uu_die(allocfail);

		errno = 0;
		ret = getgrnam_r(str, &grp, buffer, buflen);
		free(buffer);

		return (ret == NULL ? (gid_t)-1 : grp.gr_gid);
	}
}

/*
 * Fails with
 *   ENOMEM - out of memory
 *   ENOENT - no passwd entry
 *	      no project entry
 *   EIO - an I/O error occurred
 *   EMFILE - the process is out of file descriptors
 *   ENFILE - the system is out of file handles
 *   ERANGE - the project id is out of range
 *   EINVAL - str is invalid
 *   E2BIG - the project entry was too big
 *   -1 - the name service switch is misconfigured
 */
int
get_projid(const char *str, struct method_context *cip)
{
	int ret;
	void *buf;
	const size_t bufsz = PROJECT_BUFSZ;
	struct project proj, *pp;

	if (strcmp(str, ":default") == 0) {
		if (cip->uid == 0) {
			/* Don't change project for root services */
			cip->project = NULL;
			return (0);
		}

		switch (ret = lookup_pwd(cip)) {
		case 0:
			break;

		case ENOMEM:
		case ENOENT:
		case EIO:
		case EMFILE:
		case ENFILE:
			return (ret);

		default:
			bad_fail("lookup_pwd", ret);
		}

		buf = malloc(bufsz);
		if (buf == NULL)
			return (ENOMEM);

		do {
			errno = 0;
			pp = getdefaultproj(cip->pwd.pw_name, &proj, buf,
			    bufsz);
		} while (pp == NULL && errno == EINTR);

		/* to be continued ... */
	} else {
		projid_t projid;
		char *cp;

		if (!isdigit(str[0])) {
			cip->project = strdup(str);
			return (cip->project != NULL ? 0 : ENOMEM);
		}

		errno = 0;
		projid = strtol(str, &cp, 10);

		if (projid == 0 && errno != 0) {
			assert(errno == ERANGE);
			return (errno);
		}

		for (; *cp != '\0'; ++cp)
			if (*cp != ' ' || *cp != '\t')
				return (EINVAL);

		if (projid > MAXPROJID)
			return (ERANGE);

		buf = malloc(bufsz);
		if (buf == NULL)
			return (ENOMEM);

		do {
			errno = 0;
			pp = getprojbyid(projid, &proj, buf, bufsz);
		} while (pp == NULL && errno == EINTR);
	}

	if (pp) {
		cip->project = strdup(pp->pj_name);
		free(buf);
		return (cip->project != NULL ? 0 : ENOMEM);
	}

	free(buf);

	switch (errno) {
	case 0:
		return (ENOENT);

	case EIO:
	case EMFILE:
	case ENFILE:
		return (errno);

	case ERANGE:
		return (E2BIG);

	default:
		return (-1);
	}
}

/*
 * Parse the supp_groups property value and populate ci->groups.  Returns
 * EINVAL (get_gid() failed for one of the components), E2BIG (the property has
 * more than NGROUPS_MAX-1 groups), or 0 on success.
 */
int
get_groups(char *str, struct method_context *ci)
{
	char *cp, *end, *next;
	uint_t i;

	const char * const whitespace = " \t";
	const char * const illegal = ", \t";

	if (str[0] == '\0') {
		ci->ngroups = 0;
		return (0);
	}

	for (cp = str, i = 0; *cp != '\0'; ) {
		/* skip whitespace */
		cp += strspn(cp, whitespace);

		/* find the end */
		end = cp + strcspn(cp, illegal);

		/* skip whitespace after end */
		next = end + strspn(end, whitespace);

		/* if there's a comma, it separates the fields */
		if (*next == ',')
			++next;

		*end = '\0';

		if ((ci->groups[i] = get_gid(cp)) == (gid_t)-1) {
			ci->ngroups = 0;
			return (EINVAL);
		}

		++i;
		if (i > NGROUPS_MAX - 1) {
			ci->ngroups = 0;
			return (E2BIG);
		}

		cp = next;
	}

	ci->ngroups = i;
	return (0);
}


/*
 * Return an error message structure containing the error message
 * with context, and the error so the caller can make a decision
 * on what to do next.
 *
 * Because get_ids uses the mc_error_create() function which can
 * reallocate the merr, this function must return the merr pointer
 * in case it was reallocated.
 */
static mc_error_t *
get_profile(scf_propertygroup_t *methpg, scf_propertygroup_t *instpg,
    scf_property_t *prop, scf_value_t *val, const char *cmdline,
    struct method_context *ci, mc_error_t *merr)
{
	char *buf = ci->vbuf;
	ssize_t buf_sz = ci->vbuf_sz;
	char cmd[PATH_MAX];
	char *cp, *value;
	const char *cmdp;
	execattr_t *eap;
	mc_error_t *err = merr;
	int r;

	if (!(get_astring_val(methpg, SCF_PROPERTY_PROFILE, buf, buf_sz, prop,
	    val) == 0 || get_astring_val(instpg, SCF_PROPERTY_PROFILE, buf,
	    buf_sz, prop, val) == 0))
		return (mc_error_create(merr, scf_error(),
		    "Method context requires a profile, but the  \"%s\" "
		    "property could not be read. scf_error is %s",
		    SCF_PROPERTY_PROFILE, scf_strerror(scf_error())));

	/* Extract the command from the command line. */
	cp = strpbrk(cmdline, " \t");

	if (cp == NULL) {
		cmdp = cmdline;
	} else {
		(void) strncpy(cmd, cmdline, cp - cmdline);
		cmd[cp - cmdline] = '\0';
		cmdp = cmd;
	}

	/* Require that cmdp[0] == '/'? */

	eap = getexecprof(buf, KV_COMMAND, cmdp, GET_ONE);
	if (eap == NULL)
		return (mc_error_create(merr, ENOENT,
		    "Could not find the execution profile \"%s\", "
		    "command %s.", buf, cmdp));

	/* Based on pfexec.c */

	/* Get the euid first so we don't override ci->pwd for the uid. */
	if ((value = kva_match(eap->attr, EXECATTR_EUID_KW)) != NULL) {
		if ((r = get_uid(value, ci, &ci->euid)) != 0) {
			ci->euid = (uid_t)-1;
			err = mc_error_create(merr, r,
			    "Could not interpret profile euid value \"%s\", "
			    "from the execution profile \"%s\", error %d.",
			    value, buf, r);
			goto out;
		}
	}

	if ((value = kva_match(eap->attr, EXECATTR_UID_KW)) != NULL) {
		if ((r = get_uid(value, ci, &ci->uid)) != 0) {
			ci->euid = ci->uid = (uid_t)-1;
			err = mc_error_create(merr, r,
			    "Could not interpret profile uid value \"%s\", "
			    "from the execution profile \"%s\", error %d.",
			    value, buf, r);
			goto out;
		}
		ci->euid = ci->uid;
	}

	if ((value = kva_match(eap->attr, EXECATTR_GID_KW)) != NULL) {
		ci->egid = ci->gid = get_gid(value);
		if (ci->gid == (gid_t)-1) {
			err = mc_error_create(merr, EINVAL,
			    "Could not interpret profile gid value \"%s\", "
			    "from the execution profile \"%s\".", value, buf);
			goto out;
		}
	}

	if ((value = kva_match(eap->attr, EXECATTR_EGID_KW)) != NULL) {
		ci->egid = get_gid(value);
		if (ci->egid == (gid_t)-1) {
			err = mc_error_create(merr, EINVAL,
			    "Could not interpret profile egid value \"%s\", "
			    "from the execution profile \"%s\".", value, buf);
			goto out;
		}
	}

	if ((value = kva_match(eap->attr, EXECATTR_LPRIV_KW)) != NULL) {
		ci->lpriv_set = priv_str_to_set(value, ",", NULL);
		if (ci->lpriv_set == NULL) {
			if (errno != EINVAL)
				err = mc_error_create(merr, ENOMEM,
				    ALLOCFAIL);
			else
				err = mc_error_create(merr, EINVAL,
				    "Could not interpret profile "
				    "limitprivs value \"%s\", from "
				    "the execution profile \"%s\".",
				    value, buf);
			goto out;
		}
	}

	if ((value = kva_match(eap->attr, EXECATTR_IPRIV_KW)) != NULL) {
		ci->priv_set = priv_str_to_set(value, ",", NULL);
		if (ci->priv_set == NULL) {
			if (errno != EINVAL)
				err = mc_error_create(merr, ENOMEM,
				    ALLOCFAIL);
			else
				err = mc_error_create(merr, EINVAL,
				    "Could not interpret profile privs value "
				    "\"%s\", from the execution profile "
				    "\"%s\".", value, buf);
			goto out;
		}
	}

out:
	free_execattr(eap);

	return (err);
}

/*
 * Return an error message structure containing the error message
 * with context, and the error so the caller can make a decision
 * on what to do next.
 *
 * Because get_ids uses the mc_error_create() function which can
 * reallocate the merr, this function must return the merr pointer
 * in case it was reallocated.
 */
static mc_error_t *
get_ids(scf_propertygroup_t *methpg, scf_propertygroup_t *instpg,
    scf_property_t *prop, scf_value_t *val, struct method_context *ci,
    mc_error_t *merr)
{
	char *vbuf = ci->vbuf;
	ssize_t vbuf_sz = ci->vbuf_sz;
	int r;

	/*
	 * This should never happen because the caller should fall through
	 * another path of just setting the ids to defaults, instead of
	 * attempting to get the ids here.
	 */
	if (methpg == NULL && instpg == NULL)
		return (mc_error_create(merr, ENOENT,
		    "No property groups to get ids from."));

	if (!(get_astring_val(methpg, SCF_PROPERTY_USER,
	    vbuf, vbuf_sz, prop, val) == 0 || get_astring_val(instpg,
	    SCF_PROPERTY_USER, vbuf, vbuf_sz, prop,
	    val) == 0))
		return (mc_error_create(merr, ENOENT,
		    "Could not get \"%s\" property.", SCF_PROPERTY_USER));

	if ((r = get_uid(vbuf, ci, &ci->uid)) != 0) {
		ci->uid = (uid_t)-1;
		return (mc_error_create(merr, r,
		    "Could not interpret \"%s\" property value \"%s\", "
		    "error %d.", SCF_PROPERTY_USER, vbuf, r));
	}

	if (!(get_astring_val(methpg, SCF_PROPERTY_GROUP, vbuf, vbuf_sz, prop,
	    val) == 0 || get_astring_val(instpg, SCF_PROPERTY_GROUP, vbuf,
	    vbuf_sz, prop, val) == 0)) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			(void) strcpy(vbuf, ":default");
		} else {
			return (mc_error_create(merr, ENOENT,
			    "Could not get \"%s\" property.",
			    SCF_PROPERTY_GROUP));
		}
	}

	if (strcmp(vbuf, ":default") != 0) {
		ci->gid = get_gid(vbuf);
		if (ci->gid == (gid_t)-1) {
			return (mc_error_create(merr, ENOENT,
			    "Could not interpret \"%s\" property value \"%s\".",
			    SCF_PROPERTY_GROUP, vbuf));
		}
	} else {
		switch (r = lookup_pwd(ci)) {
		case 0:
			ci->gid = ci->pwd.pw_gid;
			break;

		case ENOENT:
			ci->gid = (gid_t)-1;
			return (mc_error_create(merr, ENOENT,
			    "No passwd entry for uid \"%d\".", ci->uid));

		case ENOMEM:
			return (mc_error_create(merr, ENOMEM,
			    "Out of memory."));

		case EIO:
		case EMFILE:
		case ENFILE:
			return (mc_error_create(merr, ENFILE,
			    "getpwuid_r() failed, error %d.", r));

		default:
			bad_fail("lookup_pwd", r);
		}
	}

	if (!(get_astring_val(methpg, SCF_PROPERTY_SUPP_GROUPS, vbuf, vbuf_sz,
	    prop, val) == 0 || get_astring_val(instpg,
	    SCF_PROPERTY_SUPP_GROUPS, vbuf, vbuf_sz, prop, val) == 0)) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			(void) strcpy(vbuf, ":default");
		} else {
			return (mc_error_create(merr, ENOENT,
			    "Could not get supplemental groups (\"%s\") "
			    "property.", SCF_PROPERTY_SUPP_GROUPS));
		}
	}

	if (strcmp(vbuf, ":default") != 0) {
		switch (r = get_groups(vbuf, ci)) {
		case 0:
			break;

		case EINVAL:
			return (mc_error_create(merr, EINVAL,
			    "Could not interpret supplemental groups (\"%s\") "
			    "property value \"%s\".", SCF_PROPERTY_SUPP_GROUPS,
			    vbuf));

		case E2BIG:
			return (mc_error_create(merr, E2BIG,
			    "Too many supplemental groups values in \"%s\".",
			    vbuf));

		default:
			bad_fail("get_groups", r);
		}
	} else {
		ci->ngroups = -1;
	}

	if (!(get_astring_val(methpg, SCF_PROPERTY_PRIVILEGES, vbuf, vbuf_sz,
	    prop, val) == 0 || get_astring_val(instpg, SCF_PROPERTY_PRIVILEGES,
	    vbuf, vbuf_sz, prop, val) == 0)) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			(void) strcpy(vbuf, ":default");
		} else {
			return (mc_error_create(merr, ENOENT,
			    "Could not get \"%s\" property.",
			    SCF_PROPERTY_PRIVILEGES));
		}
	}

	/*
	 * For default privs, we need to keep priv_set == NULL, as
	 * we use this test elsewhere.
	 */
	if (strcmp(vbuf, ":default") != 0) {
		ci->priv_set = priv_str_to_set(vbuf, ",", NULL);
		if (ci->priv_set == NULL) {
			if (errno != EINVAL) {
				return (mc_error_create(merr, ENOMEM,
				    ALLOCFAIL));
			} else {
				return (mc_error_create(merr, EINVAL,
				    "Could not interpret \"%s\" "
				    "property value \"%s\".",
				    SCF_PROPERTY_PRIVILEGES, vbuf));
			}
		}
	}

	if (!(get_astring_val(methpg, SCF_PROPERTY_LIMIT_PRIVILEGES, vbuf,
	    vbuf_sz, prop, val) == 0 || get_astring_val(instpg,
	    SCF_PROPERTY_LIMIT_PRIVILEGES, vbuf, vbuf_sz, prop, val) == 0)) {
		if (scf_error() == SCF_ERROR_NOT_FOUND) {
			(void) strcpy(vbuf, ":default");
		} else {
			return (mc_error_create(merr, ENOENT,
			    "Could not get \"%s\" property.",
			    SCF_PROPERTY_LIMIT_PRIVILEGES));
		}
	}

	if (strcmp(vbuf, ":default") == 0)
		/*
		 * L must default to all privileges so root NPA services see
		 * iE = all.  "zone" is all privileges available in the current
		 * zone, equivalent to "all" in the global zone.
		 */
		(void) strcpy(vbuf, "zone");

	ci->lpriv_set = priv_str_to_set(vbuf, ",", NULL);
	if (ci->lpriv_set == NULL) {
		if (errno != EINVAL) {
			return (mc_error_create(merr, ENOMEM, ALLOCFAIL));
		} else {
			return (mc_error_create(merr, EINVAL,
			    "Could not interpret \"%s\" property value \"%s\".",
			    SCF_PROPERTY_LIMIT_PRIVILEGES, vbuf));
		}
	}

	return (merr);
}

static int
get_environment(scf_handle_t *h, scf_propertygroup_t *pg,
    struct method_context *mcp, scf_property_t *prop, scf_value_t *val)
{
	scf_iter_t *iter;
	scf_type_t type;
	size_t i = 0;
	int ret;

	if (scf_pg_get_property(pg, SCF_PROPERTY_ENVIRONMENT, prop) != 0) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			return (ENOENT);
		return (scf_error());
	}
	if (scf_property_type(prop, &type) != 0)
		return (scf_error());
	if (type != SCF_TYPE_ASTRING)
		return (EINVAL);
	if ((iter = scf_iter_create(h)) == NULL)
		return (scf_error());

	if (scf_iter_property_values(iter, prop) != 0) {
		ret = scf_error();
		scf_iter_destroy(iter);
		return (ret);
	}

	mcp->env_sz = 10;

	if ((mcp->env = uu_zalloc(sizeof (*mcp->env) * mcp->env_sz)) == NULL) {
		ret = ENOMEM;
		goto out;
	}

	while ((ret = scf_iter_next_value(iter, val)) == 1) {
		ret = scf_value_get_as_string(val, mcp->vbuf, mcp->vbuf_sz);
		if (ret == -1) {
			ret = scf_error();
			goto out;
		}

		if ((mcp->env[i] = strdup(mcp->vbuf)) == NULL) {
			ret = ENOMEM;
			goto out;
		}

		if (++i == mcp->env_sz) {
			char **env;
			mcp->env_sz *= 2;
			env = uu_zalloc(sizeof (*mcp->env) * mcp->env_sz);
			if (env == NULL) {
				ret = ENOMEM;
				goto out;
			}
			(void) memcpy(env, mcp->env,
			    sizeof (*mcp->env) * (mcp->env_sz / 2));
			free(mcp->env);
			mcp->env = env;
		}
	}

	if (ret == -1)
		ret = scf_error();

out:
	scf_iter_destroy(iter);
	return (ret);
}

/*
 * Fetch method context information from the repository, allocate and fill
 * a method_context structure, return it in *mcpp, and return NULL.
 *
 * If no method_context is defined, original init context is provided, where
 * the working directory is '/', and uid/gid are 0/0.  But if a method_context
 * is defined at any level the smf_method(5) method_context defaults are used.
 *
 * Return an error message structure containing the error message
 * with context, and the error so the caller can make a decision
 * on what to do next.
 *
 * Error Types :
 * 	E2BIG		Too many values or entry is too big
 * 	EINVAL		Invalid value
 * 	EIO		an I/O error has occured
 * 	ENOENT		no entry for value
 * 	ENOMEM		out of memory
 * 	ENOTSUP		Version mismatch
 * 	ERANGE		value is out of range
 * 	EMFILE/ENFILE	out of file descriptors
 *
 * 	SCF_ERROR_BACKEND_ACCESS
 * 	SCF_ERROR_CONNECTION_BROKEN
 * 	SCF_ERROR_DELETED
 * 	SCF_ERROR_CONSTRAINT_VIOLATED
 * 	SCF_ERROR_HANDLE_DESTROYED
 * 	SCF_ERROR_INTERNAL
 * 	SCF_ERROR_INVALID_ARGUMENT
 * 	SCF_ERROR_NO_MEMORY
 * 	SCF_ERROR_NO_RESOURCES
 * 	SCF_ERROR_NOT_BOUND
 * 	SCF_ERROR_NOT_FOUND
 * 	SCF_ERROR_NOT_SET
 * 	SCF_ERROR_TYPE_MISMATCH
 *
 */
mc_error_t *
restarter_get_method_context(uint_t version, scf_instance_t *inst,
    scf_snapshot_t *snap, const char *mname, const char *cmdline,
    struct method_context **mcpp)
{
	scf_handle_t *h;
	scf_propertygroup_t *methpg = NULL;
	scf_propertygroup_t *instpg = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_property_t *prop = NULL;
	scf_value_t *val = NULL;
	scf_type_t ty;
	uint8_t use_profile;
	int ret = 0;
	int mc_used = 0;
	mc_error_t *err = NULL;
	struct method_context *cip;

	if ((err = malloc(sizeof (mc_error_t))) == NULL)
		return (mc_error_create(NULL, ENOMEM, NULL));

	/* Set the type to zero to track if an error occured. */
	err->type = 0;

	if (version != RESTARTER_METHOD_CONTEXT_VERSION)
		return (mc_error_create(err, ENOTSUP,
		    "Invalid client version %d. (Expected %d)",
		    version, RESTARTER_METHOD_CONTEXT_VERSION));

	/* Get the handle before we allocate anything. */
	h = scf_instance_handle(inst);
	if (h == NULL)
		return (mc_error_create(err, scf_error(),
		    scf_strerror(scf_error())));

	cip = malloc(sizeof (*cip));
	if (cip == NULL)
		return (mc_error_create(err, ENOMEM, ALLOCFAIL));

	(void) memset(cip, 0, sizeof (*cip));
	cip->uid = (uid_t)-1;
	cip->euid = (uid_t)-1;
	cip->gid = (gid_t)-1;
	cip->egid = (gid_t)-1;

	cip->vbuf_sz = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	assert(cip->vbuf_sz >= 0);
	cip->vbuf = malloc(cip->vbuf_sz);
	if (cip->vbuf == NULL) {
		free(cip);
		return (mc_error_create(err, ENOMEM, ALLOCFAIL));
	}

	if ((instpg = scf_pg_create(h)) == NULL ||
	    (methpg = scf_pg_create(h)) == NULL ||
	    (prop = scf_property_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL) {
		err = mc_error_create(err, scf_error(),
		    "Failed to create repository object: %s",
		    scf_strerror(scf_error()));
		goto out;
	}

	/*
	 * The method environment, and the credentials/profile data,
	 * may be found either in the pg for the method (methpg),
	 * or in the instance/service SCF_PG_METHOD_CONTEXT pg (named
	 * instpg below).
	 */

	if (scf_instance_get_pg_composed(inst, snap, mname, methpg) !=
	    SCF_SUCCESS) {
		err = mc_error_create(err, scf_error(), "Unable to get the "
		    "\"%s\" method, %s", mname, scf_strerror(scf_error()));
		goto out;
	}

	if (scf_instance_get_pg_composed(inst, snap, SCF_PG_METHOD_CONTEXT,
	    instpg) != SCF_SUCCESS) {
		if (scf_error() != SCF_ERROR_NOT_FOUND) {
			err = mc_error_create(err, scf_error(),
			    "Unable to retrieve the \"%s\" property group, %s",
			    SCF_PG_METHOD_CONTEXT, scf_strerror(scf_error()));
			goto out;
		}
		scf_pg_destroy(instpg);
		instpg = NULL;
	} else {
		mc_used++;
	}

	ret = get_environment(h, methpg, cip, prop, val);
	if (ret == ENOENT && instpg != NULL) {
		ret = get_environment(h, instpg, cip, prop, val);
	}

	switch (ret) {
	case 0:
		mc_used++;
		break;
	case ENOENT:
		break;
	case ENOMEM:
		err = mc_error_create(err, ret, "Out of memory.");
		goto out;
	case EINVAL:
		err = mc_error_create(err, ret, "Invalid method environment.");
		goto out;
	default:
		err = mc_error_create(err, ret,
		    "Get method environment failed: %s", scf_strerror(ret));
		goto out;
	}

	pg = methpg;

	ret = scf_pg_get_property(pg, SCF_PROPERTY_USE_PROFILE, prop);
	if (ret && scf_error() == SCF_ERROR_NOT_FOUND && instpg != NULL) {
		pg = NULL;
		ret = scf_pg_get_property(instpg, SCF_PROPERTY_USE_PROFILE,
		    prop);
	}

	if (ret) {
		switch (scf_error()) {
		case SCF_ERROR_NOT_FOUND:
			/* No profile context: use default credentials */
			cip->uid = 0;
			cip->gid = 0;
			break;

		case SCF_ERROR_CONNECTION_BROKEN:
			err = mc_error_create(err, SCF_ERROR_CONNECTION_BROKEN,
			    RCBROKEN);
			goto out;

		case SCF_ERROR_DELETED:
			err = mc_error_create(err, SCF_ERROR_NOT_FOUND,
			    "Could not find property group \"%s\"",
			    pg == NULL ? SCF_PG_METHOD_CONTEXT : mname);
			goto out;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			bad_fail("scf_pg_get_property", scf_error());
		}
	} else {
		if (scf_property_type(prop, &ty) != SCF_SUCCESS) {
			ret = scf_error();
			switch (ret) {
			case SCF_ERROR_CONNECTION_BROKEN:
				err = mc_error_create(err,
				    SCF_ERROR_CONNECTION_BROKEN, RCBROKEN);
				break;

			case SCF_ERROR_DELETED:
				err = mc_error_create(err,
				    SCF_ERROR_NOT_FOUND,
				    "Could not find property group \"%s\"",
				    pg == NULL ? SCF_PG_METHOD_CONTEXT : mname);
				break;

			case SCF_ERROR_NOT_SET:
			default:
				bad_fail("scf_property_type", ret);
			}

			goto out;
		}

		if (ty != SCF_TYPE_BOOLEAN) {
			err = mc_error_create(err,
			    SCF_ERROR_TYPE_MISMATCH,
			    "\"%s\" property is not boolean in property group "
			    "\"%s\".", SCF_PROPERTY_USE_PROFILE,
			    pg == NULL ? SCF_PG_METHOD_CONTEXT : mname);
			goto out;
		}

		if (scf_property_get_value(prop, val) != SCF_SUCCESS) {
			ret = scf_error();
			switch (ret) {
			case SCF_ERROR_CONNECTION_BROKEN:
				err = mc_error_create(err,
				    SCF_ERROR_CONNECTION_BROKEN, RCBROKEN);
				break;

			case SCF_ERROR_CONSTRAINT_VIOLATED:
				err = mc_error_create(err,
				    SCF_ERROR_CONSTRAINT_VIOLATED,
				    "\"%s\" property has multiple values.",
				    SCF_PROPERTY_USE_PROFILE);
				break;

			case SCF_ERROR_NOT_FOUND:
				err = mc_error_create(err,
				    SCF_ERROR_NOT_FOUND,
				    "\"%s\" property has no values.",
				    SCF_PROPERTY_USE_PROFILE);
				break;
			default:
				bad_fail("scf_property_get_value", ret);
			}

			goto out;
		}

		mc_used++;
		ret = scf_value_get_boolean(val, &use_profile);
		assert(ret == SCF_SUCCESS);

		/* get ids & privileges */
		if (use_profile)
			err = get_profile(pg, instpg, prop, val, cmdline,
			    cip, err);
		else
			err = get_ids(pg, instpg, prop, val, cip, err);

		if (err->type != 0)
			goto out;
	}

	/* get working directory */
	if ((methpg != NULL && scf_pg_get_property(methpg,
	    SCF_PROPERTY_WORKING_DIRECTORY, prop) == SCF_SUCCESS) ||
	    (instpg != NULL && scf_pg_get_property(instpg,
	    SCF_PROPERTY_WORKING_DIRECTORY, prop) == SCF_SUCCESS)) {
		if (scf_property_get_value(prop, val) != SCF_SUCCESS) {
			ret = scf_error();
			switch (ret) {
			case SCF_ERROR_CONNECTION_BROKEN:
				err = mc_error_create(err, ret, RCBROKEN);
				break;

			case SCF_ERROR_CONSTRAINT_VIOLATED:
				err = mc_error_create(err, ret,
				    "\"%s\" property has multiple values.",
				    SCF_PROPERTY_WORKING_DIRECTORY);
				break;

			case SCF_ERROR_NOT_FOUND:
				err = mc_error_create(err, ret,
				    "\"%s\" property has no values.",
				    SCF_PROPERTY_WORKING_DIRECTORY);
				break;

			default:
				bad_fail("scf_property_get_value", ret);
			}

			goto out;
		}

		mc_used++;
		ret = scf_value_get_astring(val, cip->vbuf, cip->vbuf_sz);
		assert(ret != -1);
	} else {
		ret = scf_error();
		switch (ret) {
		case SCF_ERROR_NOT_FOUND:
			/* okay if missing. */
			(void) strcpy(cip->vbuf, ":default");
			break;

		case SCF_ERROR_CONNECTION_BROKEN:
			err = mc_error_create(err, ret, RCBROKEN);
			goto out;

		case SCF_ERROR_DELETED:
			err = mc_error_create(err, ret,
			    "Property group could not be found");
			goto out;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			bad_fail("scf_pg_get_property", ret);
		}
	}

	if (strcmp(cip->vbuf, ":default") == 0 ||
	    strcmp(cip->vbuf, ":home") == 0) {
		switch (ret = lookup_pwd(cip)) {
		case 0:
			break;

		case ENOMEM:
			err = mc_error_create(err, ret, "Out of memory.");
			goto out;

		case ENOENT:
		case EIO:
		case EMFILE:
		case ENFILE:
			err = mc_error_create(err, ret,
			    "Could not get passwd entry.");
			goto out;

		default:
			bad_fail("lookup_pwd", ret);
		}

		cip->working_dir = strdup(cip->pwd.pw_dir);
		if (cip->working_dir == NULL) {
			err = mc_error_create(err, ENOMEM, ALLOCFAIL);
			goto out;
		}
	} else {
		cip->working_dir = strdup(cip->vbuf);
		if (cip->working_dir == NULL) {
			err = mc_error_create(err, ENOMEM, ALLOCFAIL);
			goto out;
		}
	}

	/* get security flags */
	if ((methpg != NULL && scf_pg_get_property(methpg,
	    SCF_PROPERTY_SECFLAGS, prop) == SCF_SUCCESS) ||
	    (instpg != NULL && scf_pg_get_property(instpg,
	    SCF_PROPERTY_SECFLAGS, prop) == SCF_SUCCESS)) {
		if (scf_property_get_value(prop, val) != SCF_SUCCESS) {
			ret = scf_error();
			switch (ret) {
			case SCF_ERROR_CONNECTION_BROKEN:
				err = mc_error_create(err, ret, RCBROKEN);
				break;

			case SCF_ERROR_CONSTRAINT_VIOLATED:
				err = mc_error_create(err, ret,
				    "\"%s\" property has multiple values.",
				    SCF_PROPERTY_SECFLAGS);
				break;

			case SCF_ERROR_NOT_FOUND:
				err = mc_error_create(err, ret,
				    "\"%s\" property has no values.",
				    SCF_PROPERTY_SECFLAGS);
				break;

			default:
				bad_fail("scf_property_get_value", ret);
			}

			(void) strlcpy(cip->vbuf, ":default", cip->vbuf_sz);
		} else {
			ret = scf_value_get_astring(val, cip->vbuf,
			    cip->vbuf_sz);
			assert(ret != -1);
		}
		mc_used++;
	} else {
		ret = scf_error();
		switch (ret) {
		case SCF_ERROR_NOT_FOUND:
			/* okay if missing. */
			(void) strlcpy(cip->vbuf, ":default", cip->vbuf_sz);
			break;

		case SCF_ERROR_CONNECTION_BROKEN:
			err = mc_error_create(err, ret, RCBROKEN);
			goto out;

		case SCF_ERROR_DELETED:
			err = mc_error_create(err, ret,
			    "Property group could not be found");
			goto out;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			bad_fail("scf_pg_get_property", ret);
		}
	}


	if (scf_default_secflags(h, &cip->def_secflags) != 0) {
		err = mc_error_create(err, EINVAL, "couldn't fetch "
		    "default security-flags");
		goto out;
	}

	if (strcmp(cip->vbuf, ":default") != 0) {
		if (secflags_parse(NULL, cip->vbuf,
		    &cip->secflag_delta) != 0) {
			err = mc_error_create(err, EINVAL, "couldn't parse "
			    "security flags: %s", cip->vbuf);
			goto out;
		}
	}

	/* get (optional) corefile pattern */
	if ((methpg != NULL && scf_pg_get_property(methpg,
	    SCF_PROPERTY_COREFILE_PATTERN, prop) == SCF_SUCCESS) ||
	    (instpg != NULL && scf_pg_get_property(instpg,
	    SCF_PROPERTY_COREFILE_PATTERN, prop) == SCF_SUCCESS)) {
		if (scf_property_get_value(prop, val) != SCF_SUCCESS) {
			ret = scf_error();
			switch (ret) {
			case SCF_ERROR_CONNECTION_BROKEN:
				err = mc_error_create(err, ret, RCBROKEN);
				break;

			case SCF_ERROR_CONSTRAINT_VIOLATED:
				err = mc_error_create(err, ret,
				    "\"%s\" property has multiple values.",
				    SCF_PROPERTY_COREFILE_PATTERN);
				break;

			case SCF_ERROR_NOT_FOUND:
				err = mc_error_create(err, ret,
				    "\"%s\" property has no values.",
				    SCF_PROPERTY_COREFILE_PATTERN);
				break;

			default:
				bad_fail("scf_property_get_value", ret);
			}

		} else {

			ret = scf_value_get_astring(val, cip->vbuf,
			    cip->vbuf_sz);
			assert(ret != -1);

			cip->corefile_pattern = strdup(cip->vbuf);
			if (cip->corefile_pattern == NULL) {
				err = mc_error_create(err, ENOMEM, ALLOCFAIL);
				goto out;
			}
		}

		mc_used++;
	} else {
		ret = scf_error();
		switch (ret) {
		case SCF_ERROR_NOT_FOUND:
			/* okay if missing. */
			break;

		case SCF_ERROR_CONNECTION_BROKEN:
			err = mc_error_create(err, ret, RCBROKEN);
			goto out;

		case SCF_ERROR_DELETED:
			err = mc_error_create(err, ret,
			    "Property group could not be found");
			goto out;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			bad_fail("scf_pg_get_property", ret);
		}
	}

	if (restarter_rm_libs_loadable()) {
		/* get project */
		if ((methpg != NULL && scf_pg_get_property(methpg,
		    SCF_PROPERTY_PROJECT, prop) == SCF_SUCCESS) ||
		    (instpg != NULL && scf_pg_get_property(instpg,
		    SCF_PROPERTY_PROJECT, prop) == SCF_SUCCESS)) {
			if (scf_property_get_value(prop, val) != SCF_SUCCESS) {
				ret = scf_error();
				switch (ret) {
				case SCF_ERROR_CONNECTION_BROKEN:
					err = mc_error_create(err, ret,
					    RCBROKEN);
					break;

				case SCF_ERROR_CONSTRAINT_VIOLATED:
					err = mc_error_create(err, ret,
					    "\"%s\" property has multiple "
					    "values.", SCF_PROPERTY_PROJECT);
					break;

				case SCF_ERROR_NOT_FOUND:
					err = mc_error_create(err, ret,
					    "\"%s\" property has no values.",
					    SCF_PROPERTY_PROJECT);
					break;

				default:
					bad_fail("scf_property_get_value", ret);
				}

				(void) strcpy(cip->vbuf, ":default");
			} else {
				ret = scf_value_get_astring(val, cip->vbuf,
				    cip->vbuf_sz);
				assert(ret != -1);
			}

			mc_used++;
		} else {
			(void) strcpy(cip->vbuf, ":default");
		}

		switch (ret = get_projid(cip->vbuf, cip)) {
		case 0:
			break;

		case ENOMEM:
			err = mc_error_create(err, ret, "Out of memory.");
			goto out;

		case ENOENT:
			err = mc_error_create(err, ret,
			    "Missing passwd or project entry for \"%s\".",
			    cip->vbuf);
			goto out;

		case EIO:
			err = mc_error_create(err, ret, "I/O error.");
			goto out;

		case EMFILE:
		case ENFILE:
			err = mc_error_create(err, ret,
			    "Out of file descriptors.");
			goto out;

		case -1:
			err = mc_error_create(err, ret,
			    "Name service switch is misconfigured.");
			goto out;

		case ERANGE:
		case E2BIG:
			err = mc_error_create(err, ret,
			    "Project ID \"%s\" too big.", cip->vbuf);
			goto out;

		case EINVAL:
			err = mc_error_create(err, ret,
			    "Project ID \"%s\" is invalid.", cip->vbuf);
			goto out;

		default:
			bad_fail("get_projid", ret);
		}

		/* get resource pool */
		if ((methpg != NULL && scf_pg_get_property(methpg,
		    SCF_PROPERTY_RESOURCE_POOL, prop) == SCF_SUCCESS) ||
		    (instpg != NULL && scf_pg_get_property(instpg,
		    SCF_PROPERTY_RESOURCE_POOL, prop) == SCF_SUCCESS)) {
			if (scf_property_get_value(prop, val) != SCF_SUCCESS) {
				ret = scf_error();
				switch (ret) {
				case SCF_ERROR_CONNECTION_BROKEN:
					err = mc_error_create(err, ret,
					    RCBROKEN);
					break;

				case SCF_ERROR_CONSTRAINT_VIOLATED:
					err = mc_error_create(err, ret,
					    "\"%s\" property has multiple "
					    "values.",
					    SCF_PROPERTY_RESOURCE_POOL);
					break;

				case SCF_ERROR_NOT_FOUND:
					err = mc_error_create(err, ret,
					    "\"%s\" property has no "
					    "values.",
					    SCF_PROPERTY_RESOURCE_POOL);
					break;

				default:
					bad_fail("scf_property_get_value", ret);
				}

				(void) strcpy(cip->vbuf, ":default");
			} else {
				ret = scf_value_get_astring(val, cip->vbuf,
				    cip->vbuf_sz);
				assert(ret != -1);
			}

			mc_used++;
		} else {
			ret = scf_error();
			switch (ret) {
			case SCF_ERROR_NOT_FOUND:
				/* okay if missing. */
				(void) strcpy(cip->vbuf, ":default");
				break;

			case SCF_ERROR_CONNECTION_BROKEN:
				err = mc_error_create(err, ret, RCBROKEN);
				goto out;

			case SCF_ERROR_DELETED:
				err = mc_error_create(err, ret,
				    "property group could not be found.");
				goto out;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_SET:
			default:
				bad_fail("scf_pg_get_property", ret);
			}
		}

		if (strcmp(cip->vbuf, ":default") != 0) {
			cip->resource_pool = strdup(cip->vbuf);
			if (cip->resource_pool == NULL) {
				err = mc_error_create(err, ENOMEM, ALLOCFAIL);
				goto out;
			}
		}
	}

	/*
	 * A method_context was not used for any configurable
	 * elements or attributes, so reset and use the simple
	 * defaults that provide historic init behavior.
	 */
	if (mc_used == 0) {
		free(cip->pwbuf);
		free(cip->vbuf);
		free(cip->working_dir);

		(void) memset(cip, 0, sizeof (*cip));
		cip->uid = 0;
		cip->gid = 0;
		cip->euid = (uid_t)-1;
		cip->egid = (gid_t)-1;

		if (scf_default_secflags(h, &cip->def_secflags) != 0) {
			err = mc_error_create(err, EINVAL, "couldn't fetch "
			    "default security-flags");
			goto out;
		}
	}

	*mcpp = cip;

out:
	(void) scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(instpg);
	scf_pg_destroy(methpg);

	if (cip->pwbuf != NULL) {
		free(cip->pwbuf);
		cip->pwbuf = NULL;
	}

	free(cip->vbuf);

	if (err->type != 0) {
		restarter_free_method_context(cip);
	} else {
		restarter_mc_error_destroy(err);
		err = NULL;
	}

	return (err);
}

/*
 * Modify the current process per the given method_context.  On success, returns
 * 0.  Note that the environment is not modified by this function to include the
 * environment variables in cip->env.
 *
 * On failure, sets *fp to NULL or the name of the function which failed,
 * and returns one of the following error codes.  The words in parentheses are
 * the values to which *fp may be set for the error case.
 *   ENOMEM - malloc() failed
 *   EIO - an I/O error occurred (getpwuid_r, chdir)
 *   EMFILE - process is out of file descriptors (getpwuid_r)
 *   ENFILE - system is out of file handles (getpwuid_r)
 *   EINVAL - gid or egid is out of range (setregid)
 *	      ngroups is too big (setgroups)
 *	      project's project id is bad (setproject)
 *	      uid or euid is out of range (setreuid)
 *	      poolname is invalid (pool_set_binding)
 *   EPERM - insufficient privilege (setregid, initgroups, setgroups, setppriv,
 *	         setproject, setreuid, settaskid)
 *   ENOENT - uid has a passwd entry but no shadow entry
 *	      working_dir does not exist (chdir)
 *	      uid has no passwd entry
 *	      the pool could not be found (pool_set_binding)
 *   EFAULT - lpriv_set or priv_set has a bad address (setppriv)
 *	      working_dir has a bad address (chdir)
 *   EACCES - could not access working_dir (chdir)
 *	      in a TASK_FINAL task (setproject, settaskid)
 *	      no resource pool accepting default binding exists (setproject)
 *   ELOOP - too many symbolic links in working_dir (chdir)
 *   ENAMETOOLONG - working_dir is too long (chdir)
 *   ENOLINK - working_dir is on an inaccessible remote machine (chdir)
 *   ENOTDIR - working_dir is not a directory (chdir)
 *   ESRCH - uid is not a user of project (setproject)
 *	     project is invalid (setproject)
 *	     the resource pool specified for project is unknown (setproject)
 *   EBADF - the configuration for the pool is invalid (pool_set_binding)
 *   -1 - core_set_process_path() failed (core_set_process_path)
 *	  a resource control assignment failed (setproject)
 *	  a system error occurred during pool_set_binding (pool_set_binding)
 */
int
restarter_set_method_context(struct method_context *cip, const char **fp)
{
	pid_t mypid = -1;
	int r, ret;

	cip->pwbuf = NULL;
	*fp = NULL;

	if (cip->gid != (gid_t)-1) {
		if (setregid(cip->gid,
		    cip->egid != (gid_t)-1 ? cip->egid : cip->gid) != 0) {
			*fp = "setregid";

			ret = errno;
			assert(ret == EINVAL || ret == EPERM);
			goto out;
		}
	} else {
		if (cip->pwbuf == NULL) {
			switch (ret = lookup_pwd(cip)) {
			case 0:
				break;

			case ENOMEM:
			case ENOENT:
				*fp = NULL;
				goto out;

			case EIO:
			case EMFILE:
			case ENFILE:
				*fp = "getpwuid_r";
				goto out;

			default:
				bad_fail("lookup_pwd", ret);
			}
		}

		if (setregid(cip->pwd.pw_gid,
		    cip->egid != (gid_t)-1 ?
		    cip->egid : cip->pwd.pw_gid) != 0) {
			*fp = "setregid";

			ret = errno;
			assert(ret == EINVAL || ret == EPERM);
			goto out;
		}
	}

	if (cip->ngroups == -1) {
		if (cip->pwbuf == NULL) {
			switch (ret = lookup_pwd(cip)) {
			case 0:
				break;

			case ENOMEM:
			case ENOENT:
				*fp = NULL;
				goto out;

			case EIO:
			case EMFILE:
			case ENFILE:
				*fp = "getpwuid_r";
				goto out;

			default:
				bad_fail("lookup_pwd", ret);
			}
		}

		/* Ok if cip->gid == -1 */
		if (initgroups(cip->pwd.pw_name, cip->gid) != 0) {
			*fp = "initgroups";
			ret = errno;
			assert(ret == EPERM);
			goto out;
		}
	} else if (cip->ngroups > 0 &&
	    setgroups(cip->ngroups, cip->groups) != 0) {
		*fp = "setgroups";

		ret = errno;
		assert(ret == EINVAL || ret == EPERM);
		goto out;
	}

	if (cip->corefile_pattern != NULL) {
		mypid = getpid();

		if (core_set_process_path(cip->corefile_pattern,
		    strlen(cip->corefile_pattern) + 1, mypid) != 0) {
			*fp = "core_set_process_path";
			ret = -1;
			goto out;
		}
	}


	if (psecflags(P_PID, P_MYID, PSF_INHERIT,
	    &cip->def_secflags.ss_default) != 0) {
		*fp = "psecflags (default inherit)";
		ret = errno;
		goto out;
	}

	if (psecflags(P_PID, P_MYID, PSF_LOWER,
	    &cip->def_secflags.ss_lower) != 0) {
		*fp = "psecflags (default lower)";
		ret = errno;
		goto out;
	}

	if (psecflags(P_PID, P_MYID, PSF_UPPER,
	    &cip->def_secflags.ss_upper) != 0) {
		*fp = "psecflags (default upper)";
		ret = errno;
		goto out;
	}

	if (psecflags(P_PID, P_MYID, PSF_INHERIT,
	    &cip->secflag_delta) != 0) {
		*fp = "psecflags (from manifest)";
		ret = errno;
		goto out;
	}

	if (restarter_rm_libs_loadable()) {
		if (cip->project == NULL) {
			if (settaskid(getprojid(), TASK_NORMAL) == -1) {
				switch (errno) {
				case EACCES:
				case EPERM:
					*fp = "settaskid";
					ret = errno;
					goto out;

				case EINVAL:
				default:
					bad_fail("settaskid", errno);
				}
			}
		} else {
			switch (ret = lookup_pwd(cip)) {
			case 0:
				break;

			case ENOMEM:
			case ENOENT:
				*fp = NULL;
				goto out;

			case EIO:
			case EMFILE:
			case ENFILE:
				*fp = "getpwuid_r";
				goto out;

			default:
				bad_fail("lookup_pwd", ret);
			}

			*fp = "setproject";

			switch (setproject(cip->project, cip->pwd.pw_name,
			    TASK_NORMAL)) {
			case 0:
				break;

			case SETPROJ_ERR_TASK:
			case SETPROJ_ERR_POOL:
				ret = errno;
				goto out;

			default:
				ret = -1;
				goto out;
			}
		}

		if (cip->resource_pool != NULL) {
			if (mypid == -1)
				mypid = getpid();

			*fp = "pool_set_binding";

			if (pool_set_binding(cip->resource_pool, P_PID,
			    mypid) != PO_SUCCESS) {
				switch (pool_error()) {
				case POE_INVALID_SEARCH:
					ret = ENOENT;
					break;

				case POE_BADPARAM:
					ret = EINVAL;
					break;

				case POE_INVALID_CONF:
					ret = EBADF;
					break;

				case POE_SYSTEM:
					ret = -1;
					break;

				default:
					bad_fail("pool_set_binding",
					    pool_error());
				}

				goto out;
			}
		}
	}

	/*
	 * Now, we have to assume our ID. If the UID is 0, we want it to be
	 * privilege-aware, otherwise the limit set gets used instead of E/P.
	 * We can do this by setting P as well, which keeps
	 * PA status (see priv_can_clear_PA()).
	 */

	*fp = "setppriv";

	if (cip->lpriv_set != NULL) {
		if (setppriv(PRIV_SET, PRIV_LIMIT, cip->lpriv_set) != 0) {
			ret = errno;
			assert(ret == EFAULT || ret == EPERM);
			goto out;
		}
	}
	if (cip->priv_set != NULL) {
		if (setppriv(PRIV_SET, PRIV_INHERITABLE, cip->priv_set) != 0) {
			ret = errno;
			assert(ret == EFAULT || ret == EPERM);
			goto out;
		}
	}

	/*
	 * If the limit privset is already set, then must be privilege
	 * aware.  Otherwise, don't assume anything, and force privilege
	 * aware status.
	 */

	if (cip->lpriv_set == NULL && cip->priv_set != NULL) {
		ret = setpflags(PRIV_AWARE, 1);
		assert(ret == 0);
	}

	*fp = "setreuid";
	if (setreuid(cip->uid,
	    cip->euid != (uid_t)-1 ? cip->euid : cip->uid) != 0) {
		ret = errno;
		assert(ret == EINVAL || ret == EPERM);
		goto out;
	}

	*fp = "setppriv";
	if (cip->priv_set != NULL) {
		if (setppriv(PRIV_SET, PRIV_PERMITTED, cip->priv_set) != 0) {
			ret = errno;
			assert(ret == EFAULT || ret == EPERM);
			goto out;
		}
	}

	/*
	 * The last thing to do is chdir to the specified working directory.
	 * This should come after the uid switching as only the user might
	 * have access to the specified directory.
	 */
	if (cip->working_dir != NULL) {
		do {
			r = chdir(cip->working_dir);
		} while (r != 0 && errno == EINTR);
		if (r != 0) {
			*fp = "chdir";
			ret = errno;
			goto out;
		}
	}

	ret = 0;
out:
	free(cip->pwbuf);
	cip->pwbuf = NULL;
	return (ret);
}

void
restarter_free_method_context(struct method_context *mcp)
{
	size_t i;

	if (mcp->lpriv_set != NULL)
		priv_freeset(mcp->lpriv_set);
	if (mcp->priv_set != NULL)
		priv_freeset(mcp->priv_set);

	if (mcp->env != NULL) {
		for (i = 0; i < mcp->env_sz; i++)
			free(mcp->env[i]);
		free(mcp->env);
	}

	free(mcp->working_dir);
	free(mcp->corefile_pattern);
	free(mcp->project);
	free(mcp->resource_pool);
	free(mcp);
}

/*
 * Method keyword functions
 */

int
restarter_is_null_method(const char *meth)
{
	return (strcmp(meth, MKW_TRUE) == 0);
}

static int
is_kill_method(const char *method, const char *kill_str,
    size_t kill_str_len)
{
	const char *cp;
	int sig;

	if (strncmp(method, kill_str, kill_str_len) != 0 ||
	    (method[kill_str_len] != '\0' &&
	    !isspace(method[kill_str_len])))
		return (-1);

	cp = method + kill_str_len;
	while (*cp != '\0' && isspace(*cp))
		++cp;

	if (*cp == '\0')
		return (SIGTERM);

	if (*cp != '-')
		return (-1);

	return (str2sig(cp + 1, &sig) == 0 ? sig : -1);
}

int
restarter_is_kill_proc_method(const char *method)
{
	return (is_kill_method(method, MKW_KILL_PROC,
	    sizeof (MKW_KILL_PROC) - 1));
}

int
restarter_is_kill_method(const char *method)
{
	return (is_kill_method(method, MKW_KILL, sizeof (MKW_KILL) - 1));
}

/*
 * Stubs for now.
 */

/* ARGSUSED */
int
restarter_event_get_enabled(restarter_event_t *e)
{
	return (-1);
}

/* ARGSUSED */
uint64_t
restarter_event_get_seq(restarter_event_t *e)
{
	return (-1);
}

/* ARGSUSED */
void
restarter_event_get_time(restarter_event_t *e, hrtime_t *time)
{
}

/*
 * Check for and validate fmri specified in restarter_actions/auxiliary_fmri
 * 0 - Success
 * 1 - Failure
 */
int
restarter_inst_validate_ractions_aux_fmri(scf_instance_t *inst)
{
	scf_handle_t *h;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *val;
	char *aux_fmri;
	size_t size = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	int ret = 1;

	if ((aux_fmri = malloc(size)) == NULL)
		return (1);

	h = scf_instance_handle(inst);

	pg = scf_pg_create(h);
	prop = scf_property_create(h);
	val = scf_value_create(h);
	if (pg == NULL || prop == NULL || val == NULL)
		goto out;

	if (instance_get_or_add_pg(inst, SCF_PG_RESTARTER_ACTIONS,
	    SCF_PG_RESTARTER_ACTIONS_TYPE, SCF_PG_RESTARTER_ACTIONS_FLAGS,
	    pg) != SCF_SUCCESS)
		goto out;

	if (get_astring_val(pg, SCF_PROPERTY_AUX_FMRI, aux_fmri, size,
	    prop, val) != SCF_SUCCESS)
		goto out;

	if (scf_parse_fmri(aux_fmri, NULL, NULL, NULL, NULL, NULL,
	    NULL) != SCF_SUCCESS)
		goto out;

	ret = 0;

out:
	free(aux_fmri);
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	return (ret);
}

/*
 * Get instance's boolean value in restarter_actions/auxiliary_tty
 * Return -1 on failure
 */
int
restarter_inst_ractions_from_tty(scf_instance_t *inst)
{
	scf_handle_t *h;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *val;
	uint8_t	has_tty;
	int ret = -1;

	h = scf_instance_handle(inst);
	pg = scf_pg_create(h);
	prop = scf_property_create(h);
	val = scf_value_create(h);
	if (pg == NULL || prop == NULL || val == NULL)
		goto out;

	if (instance_get_or_add_pg(inst, SCF_PG_RESTARTER_ACTIONS,
	    SCF_PG_RESTARTER_ACTIONS_TYPE, SCF_PG_RESTARTER_ACTIONS_FLAGS,
	    pg) != SCF_SUCCESS)
		goto out;

	if (get_boolean_val(pg, SCF_PROPERTY_AUX_TTY, &has_tty, prop,
	    val) != SCF_SUCCESS)
		goto out;

	ret = has_tty;

out:
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	return (ret);
}

/*
 * If the instance's dump-on-restart property exists, remove it and return true,
 * otherwise return false.
 */
int
restarter_inst_dump(scf_instance_t *inst)
{
	scf_handle_t *h;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *val;
	int ret = 0;

	h = scf_instance_handle(inst);
	pg = scf_pg_create(h);
	prop = scf_property_create(h);
	val = scf_value_create(h);
	if (pg == NULL || prop == NULL || val == NULL)
		goto out;

	if (scf_instance_get_pg(inst, SCF_PG_RESTARTER_ACTIONS, pg) !=
	    SCF_SUCCESS) {
		if (scf_error() == SCF_ERROR_CONNECTION_BROKEN)
			uu_die(rcbroken);
		goto out;
	}

	if (scf_pg_get_property(pg, SCF_PROPERTY_DODUMP, prop) != SCF_SUCCESS) {
		if (scf_error() == SCF_ERROR_CONNECTION_BROKEN)
			uu_die(rcbroken);
		goto out;
	}

	ret = 1;

	if (scf_instance_delete_prop(inst, SCF_PG_RESTARTER_ACTIONS,
	    SCF_PROPERTY_DODUMP) != SCF_SUCCESS) {
		if (scf_error() == SCF_ERROR_CONNECTION_BROKEN)
			uu_die(rcbroken);
		goto out;
	}

out:
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	return (ret);
}

static int
restarter_inst_set_astring_prop(scf_instance_t *inst, const char *pgname,
    const char *pgtype, uint32_t pgflags, const char *pname, const char *str)
{
	scf_handle_t *h;
	scf_propertygroup_t *pg;
	scf_transaction_t *t;
	scf_transaction_entry_t *e;
	scf_value_t *v;
	int ret = 1, r;

	h = scf_instance_handle(inst);

	pg = scf_pg_create(h);
	t = scf_transaction_create(h);
	e = scf_entry_create(h);
	v = scf_value_create(h);
	if (pg == NULL || t == NULL || e == NULL || v == NULL)
		goto out;

	if (instance_get_or_add_pg(inst, pgname, pgtype, pgflags, pg))
		goto out;

	if (scf_value_set_astring(v, str) != SCF_SUCCESS)
		goto out;

	for (;;) {
		if (scf_transaction_start(t, pg) != 0)
			goto out;

		if (tx_set_value(t, e, pname, SCF_TYPE_ASTRING, v) != 0)
			goto out;

		if ((r = scf_transaction_commit(t)) == 1)
			break;

		if (r == -1)
			goto out;

		scf_transaction_reset(t);
		if (scf_pg_update(pg) == -1)
			goto out;
	}
	ret = 0;

out:
	scf_transaction_destroy(t);
	scf_entry_destroy(e);
	scf_value_destroy(v);
	scf_pg_destroy(pg);

	return (ret);
}

int
restarter_inst_set_aux_fmri(scf_instance_t *inst)
{
	scf_handle_t *h;
	scf_propertygroup_t *pg;
	scf_property_t *prop;
	scf_value_t *val;
	char *aux_fmri;
	size_t size = scf_limit(SCF_LIMIT_MAX_VALUE_LENGTH);
	int ret = 1;

	if ((aux_fmri = malloc(size)) == NULL)
		return (1);

	h = scf_instance_handle(inst);

	pg = scf_pg_create(h);
	prop = scf_property_create(h);
	val = scf_value_create(h);
	if (pg == NULL || prop == NULL || val == NULL)
		goto out;

	/*
	 * Get auxiliary_fmri value from restarter_actions pg
	 */
	if (instance_get_or_add_pg(inst, SCF_PG_RESTARTER_ACTIONS,
	    SCF_PG_RESTARTER_ACTIONS_TYPE, SCF_PG_RESTARTER_ACTIONS_FLAGS,
	    pg) != SCF_SUCCESS)
		goto out;

	if (get_astring_val(pg, SCF_PROPERTY_AUX_FMRI, aux_fmri, size,
	    prop, val) != SCF_SUCCESS)
		goto out;

	/*
	 * Populate restarter/auxiliary_fmri with the obtained fmri.
	 */
	ret = restarter_inst_set_astring_prop(inst, SCF_PG_RESTARTER,
	    SCF_PG_RESTARTER_TYPE, SCF_PG_RESTARTER_FLAGS,
	    SCF_PROPERTY_AUX_FMRI, aux_fmri);

out:
	free(aux_fmri);
	scf_value_destroy(val);
	scf_property_destroy(prop);
	scf_pg_destroy(pg);
	return (ret);
}

int
restarter_inst_reset_aux_fmri(scf_instance_t *inst)
{
	return (scf_instance_delete_prop(inst,
	    SCF_PG_RESTARTER, SCF_PROPERTY_AUX_FMRI));
}

int
restarter_inst_reset_ractions_aux_fmri(scf_instance_t *inst)
{
	return (scf_instance_delete_prop(inst,
	    SCF_PG_RESTARTER_ACTIONS, SCF_PROPERTY_AUX_FMRI));
}
