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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <procfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <libintl.h>
#include <atomic.h>
#include <pthread.h>
#include <sys/mman.h>
#include <time.h>
#include "solaris-int.h"
#include "ns_connmgmt.h"
#include "ns_cache_door.h"
#include "ns_internal.h"

/*
 * Access (reference, shutdown, or reload) the current connection
 * management control structure conn_mgmt_t.
 */
#define	NS_CONN_MGMT_OP_REF		1
#define	NS_CONN_MGMT_OP_SHUTDOWN	2
#define	NS_CONN_MGMT_OP_RELOAD_CONFIG	3
#define	NS_CONN_MGMT_OP_NEW_CONFIG	4
#define	NS_CONN_MGMT_OP_LIB_INIT	5

static ns_conn_mgmt_t *access_conn_mgmt(int);
static ns_conn_mgmt_t *release_conn_mgmt(ns_conn_mgmt_t *, boolean_t);
static int close_conn_mt(ns_conn_mt_t *, int, ns_ldap_error_t **,
	ns_conn_user_t *);
static int close_conn_mt_when_nouser(ns_conn_mt_t *cm);
void shutdown_all_conn_mt(ns_conn_mgmt_t *cmg);
static int conn_signal(ns_conn_mt_t *);
static int conn_wait(ns_conn_mt_t *, ns_conn_user_t *);
static void close_conn_mt_by_procchg(ns_conn_mt_t *cm, int rc, char *errmsg);
static ns_conn_mgmt_t *proc_server_change(ns_server_status_change_t *chg,
	ns_conn_mgmt_t  *cmg);
static void get_preferred_servers(boolean_t, boolean_t, ns_conn_mgmt_t *);
static void start_thread();

static ns_conn_mgmt_t	*ns_connmgmt = NULL;
static ns_conn_mgmt_t	*ns_connmgmt_parent = NULL;
static mutex_t		ns_connmgmt_lock = DEFAULTMUTEX;
static boolean_t	ns_connmgmt_shutting_down = B_FALSE;

#define	NS_CONN_MSG_NO_CONN_MGMT gettext( \
	"libsldap: unable to allocate the connection management control")
#define	NS_CONN_MSG_NO_MTC_KEY gettext( \
	"libsldap: unable to allocate the TSD key for per-thread ldap error")
#define	NS_CONN_MSG_NO_CMG_KEY gettext( \
	"libsldap: unable to allocate the TSD key for connection management")
#define	NS_CONN_MSG_SHUTDOWN gettext("libsldap: library is being unloaded")
#define	NS_CONN_MSG_RELOADED gettext( \
	"libsldap: configuration has been reloaded")
#define	NS_CONN_MSG_SHUTDOWN_RELOADED gettext( \
	"libsldap: library unloaded or configuration has been reloaded")
#define	NS_CONN_MSG_BAD_CACHEMGR_DATA gettext( \
	"libsldap: received incorrect data from ldap_cachemgr")
#define	NS_CONN_MSG_MEMORY_ERROR gettext( \
	"libsldap: unable to allocate memory")
#define	NS_CONN_MSG_NO_PROCCHG_THREAD gettext( \
	"libsldap: unable to start the server monitor thread (%s)")
#define	NS_CONN_MSG_DOWN_FROM_CACHEMGR gettext( \
	"libsldap: server down reported by ldap_cachemgr")

static int ns_conn_free = 1;
#define	NS_CONN_UNLOCK_AND_FREE(free, cm, cmg)  \
{ \
	(void) mutex_unlock(&(cm)->lock);	\
	if (free == 1)	\
		cmg = free_conn_mt((cm), 1); \
	if (cmg != NULL) \
		(void) mutex_unlock(&(cmg)->lock); \
}

#define	NS_CONN_CHECK_ABORT_AND_LOCK(cmg, cu, errp) \
{ \
	char *msg = NULL; \
	(void) mutex_lock(&(cmg)->lock); \
	if ((cmg)->shutting_down == B_TRUE) \
		msg = NS_CONN_MSG_SHUTDOWN; \
	else if ((cmg)->cfg_reloaded == B_TRUE)  \
		msg = NS_CONN_MSG_RELOADED; \
	if (msg != NULL) { \
		(*errp) = __s_api_make_error(NS_LDAP_OP_FAILED, msg); \
		(void) mutex_unlock(&(cmg)->lock); \
		return (NS_LDAP_OP_FAILED); \
	} \
}

/*
 * TSD keys ns_mtckey and ns_cmgkey are for sharing ldap connections
 * and their associated connection management structure among
 * multiple threads. The pointers to the per-thread ldap error
 * information and the connection management structure are
 * saved in ns_mtckey and ns_cmgkey.
 */
thread_key_t ns_mtckey = THR_ONCE_KEY;
thread_key_t ns_cmgkey = THR_ONCE_KEY;

/* Per thread LDAP error resides in thread-specific data (ns_mtckey) */
struct ldap_error {
	int	le_errno;
	char	*le_matched;
	char	*le_errmsg;
};

/* NULL struct ldap_error */
static struct ldap_error ldap_error_NULL = { LDAP_SUCCESS, NULL, NULL};

/* destructor: free the ldap error data in the thread specific area */
static void
ns_mtckey_cleanup(void *key) {
	struct ldap_error *le = (struct ldap_error *)key;

	if (le == NULL)
		return;
	if (le->le_matched != NULL) {
		ldap_memfree(le->le_matched);
	}
	if (le->le_errmsg != NULL) {
		ldap_memfree(le->le_errmsg);
	}
	free(le);
}

/* Free/detach the thread specific data structures */
static void
conn_tsd_free() {
	void	*tsd = NULL;
	int	rc;

	/* free the per-thread ldap error info */
	rc = thr_getspecific(ns_mtckey, &tsd);
	if (rc == 0 && tsd != NULL)
		ns_mtckey_cleanup(tsd);
	(void) thr_setspecific(ns_mtckey, NULL);

	/* detach the connection management control */
	(void) thr_setspecific(ns_cmgkey, NULL);
}

/* per-thread callback function for allocating a mutex */
static void *
ns_mutex_alloc(void)
{
	mutex_t *mutexp = NULL;

	if ((mutexp = malloc(sizeof (mutex_t))) != NULL) {
		if (mutex_init(mutexp, USYNC_THREAD, NULL) != 0) {
			free(mutexp);
			mutexp = NULL;
		}
	}
	return (mutexp);
}

/* per-thread callback function for freeing a mutex */
static void
ns_mutex_free(void *mutexp)
{
	(void) mutex_destroy((mutex_t *)mutexp);
	free(mutexp);
}

/*
 * Function for setting up thread-specific data
 * where per thread LDAP error and the pointer
 * to the active connection management control
 * are stored.
 */
static int
conn_tsd_setup(ns_conn_mgmt_t *cmg)
{
	void	*tsd;
	int	rc;

	rc = thr_setspecific(ns_cmgkey, cmg);
	if (rc != 0) /* must be ENOMEM */
		return (-1);

	/* return success if the ns_mtckey TSD is already set */
	rc = thr_getspecific(ns_mtckey, &tsd);
	if (rc == 0 && tsd != NULL)
		return (0);

	/* allocate and set the ns_mtckey TSD */
	tsd = (void *) calloc(1, sizeof (struct ldap_error));
	if (tsd == NULL)
		return (-1);
	rc = thr_setspecific(ns_mtckey, tsd);
	if (rc != 0) { /* must be ENOMEM */
		free(tsd);
		return (-1);
	}
	return (0);
}

/* Callback function for setting the per thread LDAP error */
/*ARGSUSED*/
static void
set_ld_error(int err, char *matched, char *errmsg, void *dummy)
{
	struct ldap_error	*le;
	int			eno;

	if ((eno = thr_getspecific(ns_mtckey, (void **)&le)) != 0) {
		syslog(LOG_ERR, gettext(
		    "libsldap: set_ld_error: thr_getspecific failed (%s)."),
		    strerror(eno));
		return;
	}

	/* play safe, do nothing if TSD pointer is NULL */
	if (le == NULL) {
		syslog(LOG_INFO, gettext(
		    "libsldap: set_ld_error: TSD pointer is NULL."));
		return;
	}

	le->le_errno = err;

	if (le->le_matched != NULL) {
		ldap_memfree(le->le_matched);
		le->le_matched = NULL;
	}
	le->le_matched = matched;

	if (le->le_errmsg != NULL) {
		ldap_memfree(le->le_errmsg);
		le->le_errmsg = NULL;
	}
	le->le_errmsg = errmsg;
}

/* check and allocate the thread-specific data for using a MT connection */
static int
conn_tsd_check(ns_conn_mgmt_t *cmg)
{
	if (conn_tsd_setup(cmg) != 0)
		return (NS_LDAP_MEMORY);

	return (NS_LDAP_SUCCESS);
}

/* Callback function for getting the per thread LDAP error */
/*ARGSUSED*/
static int
get_ld_error(char **matched, char **errmsg, void *dummy)
{
	struct ldap_error	*le;
	int			eno;

	if ((eno = thr_getspecific(ns_mtckey, (void **)&le)) != 0) {
		syslog(LOG_ERR, gettext(
		    "libsldap: get_ld_error: thr_getspecific failed (%s)"),
		    strerror(eno));
		return (eno);
	}

	/* play safe, return NULL error data, if TSD pointer is NULL */
	if (le == NULL)
		le = &ldap_error_NULL;

	if (matched != NULL) {
		*matched = le->le_matched;
	}
	if (errmsg != NULL) {
		*errmsg = le->le_errmsg;
	}
	return (le->le_errno);
}

/* Callback function for setting per thread errno */
static void
set_errno(int err)
{
	errno = err;
}

/* Callback function for getting per thread errno */
static int
get_errno(void)
{
	return (errno);
}

/* set up an ldap session 'ld' for sharing among multiple threads */
static int
setup_mt_conn(LDAP *ld)
{

	struct ldap_thread_fns		tfns;
	struct ldap_extra_thread_fns	extrafns;
	int				rc;

	/*
	 * Set the function pointers for dealing with mutexes
	 * and error information
	 */
	(void) memset(&tfns, '\0', sizeof (struct ldap_thread_fns));
	tfns.ltf_mutex_alloc = (void *(*)(void)) ns_mutex_alloc;
	tfns.ltf_mutex_free = (void (*)(void *)) ns_mutex_free;
	tfns.ltf_mutex_lock = (int (*)(void *)) mutex_lock;
	tfns.ltf_mutex_unlock = (int (*)(void *)) mutex_unlock;
	tfns.ltf_get_errno = get_errno;
	tfns.ltf_set_errno = set_errno;
	tfns.ltf_get_lderrno = get_ld_error;
	tfns.ltf_set_lderrno = set_ld_error;
	tfns.ltf_lderrno_arg = NULL;

	/*
	 * Set up the ld to use those function pointers
	 */
	rc = ldap_set_option(ld, LDAP_OPT_THREAD_FN_PTRS,
	    (void *) &tfns);
	if (rc < 0) {
		syslog(LOG_INFO, gettext("libsldap: ldap_set_option "
		"(LDAP_OPT_THREAD_FN_PTRS)"));
		return (0);
	}

	/*
	 * Set the function pointers for working with semaphores
	 */
	(void) memset(&extrafns, '\0',
	    sizeof (struct ldap_extra_thread_fns));
	extrafns.ltf_threadid_fn = (void * (*)(void))thr_self;
	extrafns.ltf_mutex_trylock = NULL;
	extrafns.ltf_sema_alloc = NULL;
	extrafns.ltf_sema_free = NULL;
	extrafns.ltf_sema_wait = NULL;
	extrafns.ltf_sema_post = NULL;

	/* Set up the ld to use those function pointers */
	rc = ldap_set_option(ld, LDAP_OPT_EXTRA_THREAD_FN_PTRS,
	    (void *) &extrafns);
	if (rc < 0) {
		syslog(LOG_INFO, gettext("libsldap: ldap_set_option "
		"(LDAP_OPT_EXTRA_THREAD_FN_PTRS)"));
		return (0);
	}

	return (1);
}

/* set up an MT connection for sharing among multiple threads */
static int
setup_mt_ld(LDAP *ld, ns_conn_mgmt_t *cmg)
{
	thread_t	t = thr_self();

	/* set up the per-thread data for using the MT connection */
	if (conn_tsd_setup(cmg) == -1) {
		syslog(LOG_WARNING,
		    gettext("libsldap: tid= %d: unable to set up TSD\n"), t);
		return (-1);
	}

	if (setup_mt_conn(ld) == 0) {
		/* multiple threads per connection not supported */
		syslog(LOG_WARNING, gettext("libsldap: tid= %d: multiple "
		    "threads per connection not supported\n"), t);
		conn_tsd_free();
		return (-1);
	}
	return (0);
}

/*
 * Check name and UID of process, if it is nscd.
 *
 * Input:
 *   pid	: PID of checked process
 *   check_uid	: check if UID == 0
 * Output:
 *   B_TRUE	: nscd detected
 *   B_FALSE	: nscd not confirmed
 */
static boolean_t
check_nscd_proc(pid_t pid, boolean_t check_uid)
{
	psinfo_t	pinfo;
	char		fname[MAXPATHLEN];
	ssize_t		ret;
	int		fd;

	if (snprintf(fname, MAXPATHLEN, "/proc/%d/psinfo", pid) > 0) {
		if ((fd = open(fname,  O_RDONLY)) >= 0) {
			ret = read(fd, &pinfo, sizeof (psinfo_t));
			(void) close(fd);
			if ((ret == sizeof (psinfo_t)) &&
			    (strcmp(pinfo.pr_fname, "nscd") == 0)) {
				if (check_uid && (pinfo.pr_uid != 0))
					return (B_FALSE);
				return (B_TRUE);
			}
		}
	}
	return (B_FALSE);
}

/*
 * Check if this process is peruser nscd.
 */
boolean_t
__s_api_peruser_proc(void)
{
	pid_t		my_ppid;
	static mutex_t	nscdLock = DEFAULTMUTEX;
	static pid_t	checkedPpid = (pid_t)-1;
	static boolean_t isPeruserNscd = B_FALSE;

	my_ppid = getppid();

	/*
	 * Already checked before for this process? If yes, return cached
	 * response.
	 */
	if (my_ppid == checkedPpid) {
		return (isPeruserNscd);
	}

	(void) mutex_lock(&nscdLock);

	/* Check once more incase another thread has just complete this. */
	if (my_ppid == checkedPpid) {
		(void) mutex_unlock(&nscdLock);
		return (isPeruserNscd);
	}

	/* Reinitialize to be sure there is no residue after fork. */
	isPeruserNscd = B_FALSE;

	/* Am I the nscd process? */
	if (check_nscd_proc(getpid(), B_FALSE)) {
		/* Is my parent the nscd process with UID == 0. */
		isPeruserNscd = check_nscd_proc(my_ppid, B_TRUE);
	}

	/* Remember for whom isPeruserNscd is. */
	checkedPpid = my_ppid;

	(void) mutex_unlock(&nscdLock);
	return (isPeruserNscd);
}

/*
 * Check if this process is main nscd.
 */
boolean_t
__s_api_nscd_proc(void)
{
	pid_t		my_pid;
	static mutex_t	nscdLock = DEFAULTMUTEX;
	static pid_t	checkedPid = (pid_t)-1;
	static boolean_t isMainNscd = B_FALSE;

	/*
	 * Don't bother checking if this process isn't root, this cannot
	 * be main nscd.
	 */
	if (getuid() != 0)
		return (B_FALSE);

	my_pid = getpid();

	/*
	 * Already checked before for this process? If yes, return cached
	 * response.
	 */
	if (my_pid == checkedPid) {
		return (isMainNscd);
	}

	(void) mutex_lock(&nscdLock);

	/* Check once more incase another thread has just done this. */
	if (my_pid == checkedPid) {
		(void) mutex_unlock(&nscdLock);
		return (isMainNscd);
	}

	/*
	 * Am I the nscd process? UID is already checked, not needed from
	 * psinfo.
	 */
	isMainNscd = check_nscd_proc(my_pid, B_FALSE);

	/* Remember for whom isMainNscd is. */
	checkedPid = my_pid;

	(void) mutex_unlock(&nscdLock);
	return (isMainNscd);
}

/*
 * initialize a connection management control structure conn_mgmt_t
 */
ns_conn_mgmt_t *
init_conn_mgmt()
{
	ns_conn_mgmt_t	*cmg;

	cmg = (ns_conn_mgmt_t *)calloc(1, sizeof (*cmg));
	if (cmg == NULL) {
		syslog(LOG_ERR, NS_CONN_MSG_NO_CONN_MGMT);
		return (NULL);
	}

	/* is this process nscd or peruser nscd ? */
	cmg->is_nscd = __s_api_nscd_proc();
	cmg->is_peruser_nscd = __s_api_peruser_proc();

	/*
	 * assume the underlying libldap allows multiple threads sharing
	 * the same ldap connection (MT connection)
	 */
	cmg->ldap_mt = B_TRUE;
	/* state is inactive until MT connection is required/requested */
	cmg->state = NS_CONN_MGMT_INACTIVE;

	(void) mutex_init(&cmg->lock, USYNC_THREAD, NULL);
	(void) mutex_init(&cmg->cfg_lock, USYNC_THREAD, NULL);
	cmg->pid = getpid();

	/* for nscd or peruser nscd, MT connection is required */
	if (cmg->is_nscd == B_TRUE || cmg->is_peruser_nscd == B_TRUE)
		cmg->state = NS_CONN_MGMT_ACTIVE;

	/*
	 * reference (or initialize) the current Native LDAP configuration and
	 * if in nscd process, make it never refreshed
	 */
	cmg->config = __s_api_get_default_config_global();
	if (cmg->config == NULL)
		cmg->config = __s_api_loadrefresh_config_global();
	if (cmg->config != NULL) {
		/*
		 * main nscd get config change notice from ldap_cachemgr
		 * so won't times out and refresh the config
		 */
		if (cmg->is_nscd  == B_TRUE)
			(cmg->config)->paramList[NS_LDAP_EXP_P].ns_tm = 0;
		cmg->cfg_cookie = cmg->config->config_cookie;
	}

	return (cmg);
}

static void
mark_shutdown_or_reloaded(int op)
{
	ns_conn_mgmt_t	*cmg = ns_connmgmt;

	(void) mutex_lock(&cmg->lock);
	if (op == NS_CONN_MGMT_OP_SHUTDOWN)
		cmg->shutting_down = B_TRUE;
	else
		cmg->cfg_reloaded = B_TRUE;
	atomic_inc_uint(&cmg->ref_cnt);
	cmg->state = NS_CONN_MGMT_DETACHED;

	if (op == NS_CONN_MGMT_OP_RELOAD_CONFIG)
		__s_api_init_config_global(NULL);

	(void) mutex_unlock(&cmg->lock);
}

/*
 * Return a pointer to the current connection management. If
 * it has not been created, or is requested to recreate, then
 * create and return the pointer. It is possible, the current
 * one is created by the parent before fork, create a new
 * one too in such a case.
 */
static ns_conn_mgmt_t *
get_current_conn_mgmt(int op)
{
	ns_conn_mgmt_t	*cmg = ns_connmgmt;
	static pid_t	checked_pid = (pid_t)-1;
	pid_t		mypid;

	mypid = getpid();
	if (cmg == NULL || checked_pid != mypid) {
		checked_pid = mypid;

		/*
		 * if current conn_mgmt not created yet or is from parent
		 * or is requested to recreate, create it
		 */
		if (cmg == NULL || cmg->pid != mypid) {
			if (cmg != NULL) {
				/*
				 * We don't want to free the conn_mgmt
				 * allocated by the parent, since
				 * there may be ldap connections
				 * still being used. So leave it
				 * alone but keep it referenced,
				 * so that it will not be flagged
				 * as a piece of leaked memory.
				 */
				ns_connmgmt_parent = cmg;
				/*
				 * avoid lint warning; does not
				 * change the conn_mgmt in parent
				 */
				ns_connmgmt_parent->state =
				    NS_CONN_MGMT_DETACHED;
			}
			ns_connmgmt = init_conn_mgmt();
			cmg = ns_connmgmt;
			/*
			 * ensure it will not be destroyed until explicitly
			 * shut down or reloaded
			 */
			if (op == NS_CONN_MGMT_OP_REF)
				atomic_inc_uint(&cmg->ref_cnt);
		}
	}

	return (cmg);
}

static ns_conn_mgmt_t *
access_conn_mgmt(int op)
{
	ns_conn_mgmt_t	*cmg = NULL;
	ns_conn_mgmt_t	*cmg_prev;

	(void) mutex_lock(&ns_connmgmt_lock);

	/*
	 * connection management is not available when the libsldap is being
	 * unloaded or shut down
	 */
	if (ns_connmgmt_shutting_down == B_TRUE) {
		(void) mutex_unlock(&ns_connmgmt_lock);
		return (NULL);
	}

	if (op == NS_CONN_MGMT_OP_SHUTDOWN) {
		ns_connmgmt_shutting_down = B_TRUE;
		if (ns_connmgmt != NULL) {
			cmg = ns_connmgmt;
			mark_shutdown_or_reloaded(op);
			ns_connmgmt = NULL;
		}
		(void) mutex_unlock(&ns_connmgmt_lock);
		return (cmg);
	}

	if (op == NS_CONN_MGMT_OP_RELOAD_CONFIG ||
	    op == NS_CONN_MGMT_OP_NEW_CONFIG) {
		cmg_prev = ns_connmgmt;
		mark_shutdown_or_reloaded(op);
		/*
		 * the previous cmg (cmg_prev) will be freed later
		 * when its ref count reaches zero
		 */
		ns_connmgmt = NULL;
	}

	cmg = get_current_conn_mgmt(op);
	if (cmg == NULL) {
		(void) mutex_unlock(&ns_connmgmt_lock);
		return (NULL);
	}

	atomic_inc_uint(&cmg->ref_cnt);
	if (op == NS_CONN_MGMT_OP_RELOAD_CONFIG ||
	    op == NS_CONN_MGMT_OP_NEW_CONFIG)
		cmg = cmg_prev;
	else { /* op is  NS_CONN_MGMT_OP_REF  or NS_CONN_MGMT_OP_LIB_INIT */
		if (cmg->config == NULL)
			cmg->config = __s_api_get_default_config();
	}

	(void) mutex_unlock(&ns_connmgmt_lock);
	return (cmg);
}

/*
 * free a connection management control
 */
static void
free_conn_mgmt(ns_conn_mgmt_t *cmg)
{
	union {
		ldap_data_t	s_d;
		char		s_b[1024];
	} space;
	ldap_data_t	*sptr;
	int		ndata;
	int		adata;
	int		rc;
	ldap_get_chg_cookie_t cookie;

	if (cmg == NULL)
		return;
	cookie = cmg->cfg_cookie;

	__s_api_free2dArray(cmg->pservers);
	/* destroy the previous config or release the current one */
	if (cmg->config != NULL) {
		if (cmg->state == NS_CONN_MGMT_DETACHED)
			__s_api_destroy_config(cmg->config);
		else
			__s_api_release_config(cmg->config);
	}

	/* stop the server status/config-change monitor thread */
	if (cmg->procchg_started == B_TRUE) {
		if (cmg->procchg_tid != thr_self()) {
			if (cmg->procchg_door_call == B_TRUE) {
				adata = sizeof (ldap_call_t) + 1;
				ndata = sizeof (space);
				space.s_d.ldap_call.ldap_callnumber =
				    GETSTATUSCHANGE;
				space.s_d.ldap_call.ldap_u.get_change.op =
				    NS_STATUS_CHANGE_OP_STOP;
				space.s_d.ldap_call.ldap_u.get_change.cookie =
				    cookie;
				sptr = &space.s_d;
				rc = __ns_ldap_trydoorcall(&sptr, &ndata,
				    &adata);
				if (rc != NS_CACHE_SUCCESS)
					syslog(LOG_INFO,
					    gettext("libsldap: "
					    "free_conn_mgmt():"
					    " stopping door call "
					    " GETSTATUSCHANGE failed "
					    " (rc = %d)"), rc);
			}
			(void) pthread_cancel(cmg->procchg_tid);
			cmg->procchg_started = B_FALSE;
		}
	}

	free(cmg);
}

static ns_conn_mgmt_t *
release_conn_mgmt(ns_conn_mgmt_t *cmg, boolean_t unlock_cmg)
{
	if (cmg == NULL)
		return (NULL);
	if (atomic_dec_uint_nv(&cmg->ref_cnt) == 0) {
		if (cmg->state == NS_CONN_MGMT_DETACHED) {
			if (unlock_cmg == B_TRUE)
				(void) mutex_unlock(&cmg->lock);
			free_conn_mgmt(cmg);
			__s_api_free_sessionPool();
			return (NULL);
		} else {
			syslog(LOG_WARNING,
			    gettext("libsldap: connection management "
			    " has a refcount of zero but the state "
			    " is not DETACHED (%d)"), cmg->state);
			cmg = NULL;
		}
	}
	return (cmg);
}

/*
 * exposed function for initializing a connection management control structure
 */
ns_conn_mgmt_t *
__s_api_conn_mgmt_init()
{
	if (thr_keycreate_once(&ns_mtckey, ns_mtckey_cleanup) != 0) {
		syslog(LOG_WARNING, NS_CONN_MSG_NO_MTC_KEY);
		return (NULL);
	}

	if (thr_keycreate_once(&ns_cmgkey, NULL) != 0) {
		syslog(LOG_WARNING, NS_CONN_MSG_NO_CMG_KEY);
		return (NULL);
	}

	return (access_conn_mgmt(NS_CONN_MGMT_OP_LIB_INIT));
}

/* initialize a connection user */
ns_conn_user_t *
__s_api_conn_user_init(int type, void *userinfo, boolean_t referral)
{
	ns_conn_user_t	*cu;
	ns_conn_mgmt_t	*cmg;

	/* delete the reference to the previously used conn_mgmt */
	(void) thr_setspecific(ns_cmgkey, NULL);

	cmg = access_conn_mgmt(NS_CONN_MGMT_OP_REF);
	if (cmg == NULL)
		return (NULL);

	if (cmg->state != NS_CONN_MGMT_ACTIVE &&
	    cmg->state != NS_CONN_MGMT_INACTIVE) {
		atomic_dec_uint(&cmg->ref_cnt);
		return (NULL);
	}

	cu = (ns_conn_user_t *)calloc(1, sizeof (*cu));
	if (cu == NULL) {
		atomic_dec_uint(&cmg->ref_cnt);
		return (NULL);
	}

	cu->type = type;
	cu->state = NS_CONN_USER_ALLOCATED;
	cu->tid = thr_self();
	cu->userinfo = userinfo;
	cu->referral = referral;
	cu->ns_rc = NS_LDAP_SUCCESS;
	cu->conn_mgmt = cmg;

	(void) conn_tsd_setup(cmg);

	return (cu);
}

/*
 * Free the resources used by a connection user.
 * The caller should ensure this conn_user is
 * not associated with any conn_mt, i.e.,
 * not in any conn_mt's linked list of conn_users.
 * The caller needs to free the userinfo member
 * as well.
 */
void
__s_api_conn_user_free(ns_conn_user_t *cu)
{
	ns_conn_mgmt_t	*cmg;

	if (cu == NULL)
		return;

	cu->state = NS_CONN_USER_FREED;
	if (cu->ns_error != NULL)
		(void) __ns_ldap_freeError(&cu->ns_error);

	cmg = cu->conn_mgmt;
	conn_tsd_free();
	(void) release_conn_mgmt(cmg, B_FALSE);
	(void) free(cu);
}

/*
 * Initialize an MT connection control structure
 * that will be used to represent an ldap connection
 * to be shared among multiple threads and to hold
 * and manage all the conn_users using the ldap
 * connection.
 */
static ns_conn_mt_t *
init_conn_mt(ns_conn_mgmt_t *cmg, ns_ldap_error_t **ep)
{
	ns_conn_mt_t	*cm;
	ns_conn_mgmt_t	*cmg_a;

	cm = (ns_conn_mt_t *)calloc(1, sizeof (*cm));
	if (cm == NULL) {
		if (ep != NULL)
			*ep = __s_api_make_error(NS_LDAP_MEMORY, NULL);
		return (NULL);
	}

	cmg_a = access_conn_mgmt(NS_CONN_MGMT_OP_REF);
	if (cmg_a != cmg) {
		if (cmg_a != NULL) {
			(void) release_conn_mgmt(cmg_a, B_FALSE);
			if (ep != NULL)
				*ep = __s_api_make_error(NS_LDAP_OP_FAILED,
				    NS_CONN_MSG_SHUTDOWN_RELOADED);
		}
		return (NULL);
	}

	(void) mutex_init(&cm->lock, USYNC_THREAD, NULL);
	cm->state = NS_CONN_MT_CONNECTING;
	cm->tid = thr_self();
	cm->pid = getpid();
	cm->next = NULL;
	cm->cu_head = NULL;
	cm->cu_tail = NULL;
	cm->conn = NULL;
	cm->conn_mgmt = cmg;

	return (cm);
}

/*
 * Free an MT connection control structure, assume conn_mgmt is locked.
 * 'unlock_cmg' is passed to release_conn_mgmt() to indicate the
 * cmg needs to be unlocked or not.
 */
static ns_conn_mgmt_t *
free_conn_mt(ns_conn_mt_t *cm, int unlock_cmg)
{
	ns_conn_mgmt_t	*cmg;

	if (cm == NULL)
		return (NULL);
	if (cm->ns_error != NULL)
		(void) __ns_ldap_freeError(&cm->ns_error);
	if (cm->conn != NULL) {
		if (cm->conn->ld != NULL)
			(void) ldap_unbind(cm->conn->ld);
		__s_api_freeConnection(cm->conn);
	}
	cmg = cm->conn_mgmt;
	free(cm);
	return (release_conn_mgmt(cmg, unlock_cmg));
}

/* add a connection user to an MT connection */
static void
add_cu2cm(ns_conn_user_t *cu, ns_conn_mt_t *cm)
{

	if (cm->cu_head == NULL) {
		cm->cu_head = cu;
		cm->cu_tail = cu;
	} else {
		cm->cu_tail->next = cu;
		cm->cu_tail = cu;
	}
	cm->cu_cnt++;
}

/* add an MT connection to the connection management */
static void
add_cm2cmg(ns_conn_mt_t *cm, ns_conn_mgmt_t *cmg)
{
	/*
	 * add connection opened for WRITE to top of list
	 * for garbage collection purpose. This is to
	 * ensure the connection will be closed after a
	 * certain amount of time (60 seconds).
	 */
	if (cmg->cm_head == NULL) {
		cmg->cm_head = cm;
		cmg->cm_tail = cm;
	} else {
		if (cm->opened_for == NS_CONN_USER_WRITE) {
			cm->next = cmg->cm_head;
			cmg->cm_head = cm;
		} else {
			cmg->cm_tail->next = cm;
			cmg->cm_tail = cm;
		}
	}
	cmg->cm_cnt++;
}

/* delete a connection user from an MT connection */
static void
del_cu4cm(ns_conn_user_t *cu, ns_conn_mt_t *cm)
{
	ns_conn_user_t *pu, *u;

	if (cu == NULL || cm->cu_head == NULL || cm->cu_cnt == 0)
		return;

	/* only one conn_user on list */
	if (cm->cu_head == cm->cu_tail) {
		if (cu == cm->cu_head) {
			cm->cu_head = cm->cu_tail = NULL;
			cm->cu_cnt = 0;
			cu->next = NULL;
		}
		return;
	}

	/* more than one and cu is the first one */
	if (cu == cm->cu_head) {
		cm->cu_head = cu->next;
		cm->cu_cnt--;
		cu->next = NULL;
		return;
	}

	pu = cm->cu_head;
	for (u = cm->cu_head->next; u; u = u->next) {
		if (cu == u)
			break;
		pu = u;
	}
	if (pu != cm->cu_tail) {
		pu->next = cu->next;
		if (pu->next == NULL)
			cm->cu_tail = pu;
		cm->cu_cnt--;
		cu->next = NULL;
	} else {
		syslog(LOG_INFO, gettext(
		    "libsldap: del_cu4cm(): connection user not found"));
	}
}

/* delete an MT connection from the connection management control structure */
static void
del_cm4cmg(ns_conn_mt_t *cm, ns_conn_mgmt_t *cmg)
{
	ns_conn_mt_t *pm, *m;

	if (cm == NULL || cmg->cm_head == NULL || cmg->cm_cnt == 0)
		return;

	/* only one conn_mt on list */
	if (cmg->cm_head == cmg->cm_tail) {
		if (cm == cmg->cm_head) {
			cmg->cm_head = cmg->cm_tail = NULL;
			cmg->cm_cnt = 0;
			cm->next = NULL;
		}
		return;
	}

	/* more than one and cm is the first one */
	if (cm == cmg->cm_head) {
		cmg->cm_head = cm->next;
		cmg->cm_cnt--;
		cm->next = NULL;
		return;
	}

	pm = cmg->cm_head;
	for (m = cmg->cm_head->next; m; m = m->next) {
		if (cm == m)
			break;
		pm = m;
	}
	if (pm != cmg->cm_tail) {
		pm->next = cm->next;
		if (pm->next == NULL)
			cmg->cm_tail = pm;
		cmg->cm_cnt--;
		cm->next = NULL;
	} else {
		syslog(LOG_INFO, gettext(
		    "libsldap: del_cm4cmg(): MT connection not found"));
	}
}

/*
 * compare to see if the server and credential for authentication match
 * those used by an MT connection
 */
static boolean_t
is_server_cred_matched(const char *server, const ns_cred_t *cred,
	ns_conn_mt_t *cm)
{
	Connection	*cp = cm->conn;

	/* check server first */
	if (server != NULL && *server != 0) {
		if (strcasecmp(server, cp->serverAddr) != 0)
			return (B_FALSE);
	}

	if (cred == NULL)
		return (B_TRUE);

	/* then check cred */
	return (__s_api_is_auth_matched(cp->auth, cred));
}

/*
 * Wait until a pending MT connection becomes available.
 * Return 1 if so, 0 if error.
 *
 * Assume the current conn_mgmt and the input conn_mt
 * are locked.
 */
static int
wait_for_conn_mt(ns_conn_user_t *cu, ns_conn_mt_t *cm)
{

	cu->state = NS_CONN_USER_WAITING;
	add_cu2cm(cu, cm);
	cu->conn_mt = cm;

	(void) mutex_unlock(&cm->lock);
	/*
	 * It could take some time so we don't want to hold
	 * cm->conn_mgmt across the wait
	 */
	(void) mutex_unlock(&(cm->conn_mgmt)->lock);

	(void) mutex_lock(&cm->lock);
	/* check one more time see if need to wait */
	if (cm->state == NS_CONN_MT_CONNECTING) {
		(void) conn_wait(cm, cu);

		/* cm->lock is locked again at this point */

		cu->state = NS_CONN_USER_WOKEUP;
	}

	if (cm->state == NS_CONN_MT_CONNECTED)
		return (1);
	else {
		del_cu4cm(cu, cm);
		cu->conn_mt = NULL;
		cu->bad_mt_conn = B_FALSE;
		return (0);
	}
}

/*
 * Check and see if the input MT connection '*cm' should be closed.
 * In two cases, it should be closed. If a preferred server is
 * found to be up when ldap_cachemgr is queried and reported back.
 * Or when the server being used for the connection is found to
 * be down. Return B_FALSE if the connection is not closed (or not marked
 * to be closed), otherwise unlock mutex (*cm)->lock and return B_TRUE.
 * This function assumes conn_mgmt cmg and conn_mt *cm are locked.
 */
static boolean_t
check_and_close_conn(ns_conn_mgmt_t *cmg, ns_conn_mt_t **cm,
	ns_conn_user_t *cu) {

	int rc;
	int j;
	int svridx = -1;
	int upidx = -1;
	int free_cm;
	ns_server_info_t sinfo;
	ns_ldap_error_t *errorp = NULL;

	/*
	 * check only if preferred servers are defined
	 */
	if (cmg->pservers_loaded == B_FALSE)
		get_preferred_servers(B_FALSE, B_FALSE, cmg);
	if (cmg->pservers == NULL)
		return (B_FALSE);

	/*
	 * ask ldap_cachemgr for the first available server
	 */
	rc = __s_api_requestServer(NS_CACHE_NEW, NULL,
	    &sinfo, &errorp, NS_CACHE_ADDR_IP);
	if (rc != NS_LDAP_SUCCESS || sinfo.server == NULL) {
		(void) __ns_ldap_freeError(&errorp);
		return (B_FALSE);
	}

	/*
	 * Did ldap_cachemgr return a preferred server ?
	 */
	for (j = 0; cmg->pservers[j] != NULL; j++) {
		if (strcasecmp(sinfo.server, cmg->pservers[j]) != 0)
			continue;
		upidx = j;
		break;
	}

	/*
	 * Is the server being used a preferred one ?
	 */
	for (j = 0; cmg->pservers[j] != NULL; j++) {
		if (strcasecmp(cmg->pservers[j], (*cm)->conn->serverAddr) != 0)
			continue;
		svridx = j;
		break;
	}

	/*
	 * Need to fall back to a down-but-now-up preferred server ?
	 * A preferred server falls back to a more preferred one.
	 * A regular one falls back to any preferred ones. So if
	 * both are preferred ones and same index, or both
	 * are not preferred ones, then no need to close the
	 * connection.
	 */
	if ((upidx == -1 && svridx == -1) ||
	    (upidx != -1 && svridx != -1 && upidx == svridx)) {
		__s_api_free_server_info(&sinfo);
		return (B_FALSE);
	}

	/*
	 * otherwise, 4 cases, all may need to close the connection:
	 * For case 1 and 2, both servers are preferred ones:
	 * 1. ldap_cachemgr returned a better one to use (upidx < svridx)
	 * 2. the server being used is down (upidx > svridx)
	 * 3. ldap_cachemgr returned a preferred one, but the server
	 *    being used is not, so need to fall back to the preferred server
	 * 4. ldap_cachemgr returned a non-preferred one, but the server
	 *    being used is a preferred one, so it must be down (since
	 *    ldap_cachemgr always returns a preferred one when possible).
	 * For case 1 & 3, close the READ connection when no user uses it.
	 * For 2 and 4, close the connection with error rc, LDAP_SERVER_DOWN.
	 */
	if (upidx != -1 && (svridx == -1 || upidx < svridx)) { /* case 1 & 3 */
		/* fallback does not make sense for WRITE/referred connection */
		if ((*cm)->opened_for == NS_CONN_USER_WRITE ||
		    (*cm)->referral == B_TRUE) {
			__s_api_free_server_info(&sinfo);
			return (B_FALSE);
		}
		free_cm = close_conn_mt_when_nouser(*cm);
		if (cmg->shutting_down == B_FALSE)
			cu->retry = B_TRUE;
	} else {
		ns_ldap_error_t *ep;
		ep = __s_api_make_error(LDAP_SERVER_DOWN,
		    NS_CONN_MSG_DOWN_FROM_CACHEMGR);
		/* cu has not been attached to cm yet, use NULL as cu pointer */
		free_cm = close_conn_mt(*cm, LDAP_SERVER_DOWN, &ep, NULL);
		if (cmg->shutting_down == B_FALSE)
			cu->retry = B_TRUE;
		(void) __ns_ldap_freeError(&ep);
	}

	(void) mutex_unlock(&(*cm)->lock);
	if (free_cm == 1) {
		(void) free_conn_mt(*cm, 0);
		*cm = NULL;
	}

	__s_api_free_server_info(&sinfo);

	return (B_TRUE);
}

/*
 * Check to see if a conn_mt matches the connection criteria from
 * a conn_user. Return B_TRUE if yes, B_FALSE, otherwise. The input
 * conn_mt pointer (*cmt) may be freed and *cmt will be set to NULL
 * to indicate so.
 * conn_mt *cmt and conn_mgmt cm->conn_mgmt are assumed locked.
 * cm->lock is unlocked at exit if rc is B_FALSE.
 */
static boolean_t
match_conn_mt(ns_conn_user_t *cu, ns_conn_mt_t **cmt,
	ns_conn_mt_state_t st, const char *server,
	const ns_cred_t *cred)
{
	boolean_t	matched = B_FALSE;
	boolean_t	drop_conn;
	int		free_cm = 0;
	ns_conn_mt_t	*cm = *cmt;
	ns_conn_mgmt_t	*cmg = cm->conn_mgmt;

	if (cm->state != st || cm->close_when_nouser  == B_TRUE ||
	    cm->detached == B_TRUE || cm->pid != getpid() ||
	    cm->referral != cu->referral) {
		(void) mutex_unlock(&cm->lock);
		return (B_FALSE);
	}

	/*
	 * if a conn_mt opened for WRITE is idle
	 * long enough, then close it. To improve
	 * the performance of applications, such
	 * as ldapaddent, a WRITE connection is
	 * given a short time to live in the
	 * connection pool, expecting the write
	 * requests to come in a quick succession.
	 * To save resource, the connection will
	 * be closed if idle more than 60 seconds.
	 */
	if (cm->opened_for == NS_CONN_USER_WRITE &&
	    cu->type != NS_CONN_USER_WRITE && cm->cu_cnt == 0 &&
	    ((time(NULL) - cm->access_time) > 60)) {
		/*
		 * NS_LDAP_INTERNAL is irrelevant here. There no
		 * conn_user to consume the rc
		 */
		free_cm = close_conn_mt(cm, NS_LDAP_INTERNAL, NULL, NULL);
		(void) mutex_unlock(&cm->lock);
		if (free_cm == 1) {
			(void) free_conn_mt(cm, 0);
			*cmt = NULL;
		}
		return (B_FALSE);
	}

	switch (cu->type) {
	case NS_CONN_USER_SEARCH:
	case NS_CONN_USER_GETENT:
		if (cm->opened_for == NS_CONN_USER_SEARCH ||
		    cm->opened_for == NS_CONN_USER_GETENT)
			matched = B_TRUE;
		break;

	case NS_CONN_USER_WRITE:
		if (cm->opened_for == NS_CONN_USER_WRITE)
			matched = B_TRUE;
		break;

	default:
		matched = B_FALSE;
		break;
	}

	if (matched == B_TRUE && ((server != NULL || cred != NULL) &&
	    is_server_cred_matched(server, cred, cm) == B_FALSE))
		matched = B_FALSE;

	if (matched != B_FALSE) {
		/*
		 * Check and drop the 'connected' connection if
		 * necessary. Main nscd gets status changes from
		 * the ldap_cachemgr daemon directly via the
		 * GETSTATUSCHANGE door call, the standalone
		 * function works in a no ldap_cachemgr environment,
		 * so no need to check and drop connections.
		 */
		if (cm->state == NS_CONN_MT_CONNECTED &&
		    cmg->is_nscd == B_FALSE && !__s_api_isStandalone()) {
			drop_conn = check_and_close_conn(cmg, &cm, cu);
			if (drop_conn == B_TRUE) {
				if (cm == NULL)
					*cmt = NULL;
				return (B_FALSE);
			}
		}

		/* check if max. users using or waiting for the connection */
		if ((cm->state == NS_CONN_MT_CONNECTED &&
		    cm->cu_max != NS_CONN_MT_USER_NO_MAX &&
		    cm->cu_cnt >= cm->cu_max) ||
		    (cm->state == NS_CONN_MT_CONNECTING &&
		    cm->cu_max != NS_CONN_MT_USER_NO_MAX &&
		    cm->waiter_cnt >= cm->cu_max - 1))
			matched = B_FALSE;
	}

	if (matched == B_FALSE)
		(void) mutex_unlock(&cm->lock);

	return (matched);
}

/*
 * obtain an MT connection from the connection management for a conn_user
 *
 * Input:
 *   server	: server name or IP address
 *   flags	: libsldap API flags
 *   cred	: pointer to the user credential
 *   cu		: pointer to the conn_user structure
 * Output:
 *   session	: hold pointer to the Connection structure
 *   errorp	: hold pointer to error info (ns_ldap_error_t)
 */
int
__s_api_conn_mt_get(const char *server, const int flags, const ns_cred_t *cred,
	Connection **session, ns_ldap_error_t **errorp, ns_conn_user_t *cu)
{
	int		rc;
	int		i;
	ns_conn_mt_t	*cn;
	ns_conn_mt_state_t st;
	ns_conn_mgmt_t	*cmg;

	if (errorp == NULL || cu == NULL || session == NULL)
		return (NS_LDAP_INVALID_PARAM);

	*session = NULL;
	cmg = cu->conn_mgmt;

	/*
	 * for pam_ldap, always try opening a new connection
	 */
	if (cu->type == NS_CONN_USER_AUTH)
		return (NS_LDAP_NOTFOUND);

	/* if need a new conn, then don't reuse */
	if (flags & NS_LDAP_NEW_CONN)
		return (NS_LDAP_NOTFOUND);

	if (flags & NS_LDAP_KEEP_CONN)
		cu->keep_conn = B_TRUE;

	/*
	 * We want to use MT connection only if keep-connection flag is
	 * set or if MT was requested (or active)
	 */
	if (!((cmg->state == NS_CONN_MGMT_INACTIVE &&
	    cu->keep_conn == B_TRUE) || cmg->state == NS_CONN_MGMT_ACTIVE))
		return (NS_LDAP_NOTFOUND);

	/* MT connection will be used now (if possible/available) */
	cu->use_mt_conn = B_TRUE;

	NS_CONN_CHECK_ABORT_AND_LOCK(cmg, cu, errorp);

	/* first look for a connection already open */
	st = NS_CONN_MT_CONNECTED;
	cu->state = NS_CONN_USER_FINDING;
	for (i = 0; i < 2; i++) {
		for (cn = cmg->cm_head; cn; cn = cn->next) {
			(void) mutex_lock(&cn->lock);
			rc = match_conn_mt(cu, &cn, st, server, cred);
			if (rc == B_FALSE && cn != NULL) /* not found */
				continue;
			if (cn == NULL) { /* not found and cn freed */
				/*
				 * as the conn_mt list could
				 * be different due to cn's
				 * deletion, scan the entire
				 * conn_mt list again
				 */
				st = NS_CONN_MT_CONNECTED;
				i = -1;
				break;
			}

			/* return a connected one if found */
			if (cn->state == NS_CONN_MT_CONNECTED) {
				*session = cn->conn;
				add_cu2cm(cu, cn);
				cu->conn_mt = cn;
				cu->state = NS_CONN_USER_CONNECTED;
				(void) mutex_unlock(&cn->lock);
				(void) mutex_unlock(&cmg->lock);
				return (NS_LDAP_SUCCESS);
			}

			/*
			 * if cn is not connecting, or allow only
			 * one user, skip it
			 */
			if (cn->state != NS_CONN_MT_CONNECTING ||
			    cn->cu_max == 1) {
				(void) mutex_unlock(&cn->lock);
				continue;
			}

			/* wait for the connecting conn_mt */
			if (wait_for_conn_mt(cu, cn) != 1) {
				/*
				 * NS_LDAP_NOTFOUND signals that the function
				 * __s_api_check_libldap_MT_conn_support()
				 * detected that the lower libldap library
				 * does not support MT connection, so return
				 * NS_LDAP_NOTFOUND to let the caller to
				 * open a non-MT conneciton. Otherwise,
				 * connect error occurred, return
				 * NS_CONN_USER_CONNECT_ERROR
				 */
				if (cn->ns_rc != NS_LDAP_NOTFOUND)
					cu->state = NS_CONN_USER_CONNECT_ERROR;
				else {
					cu->state = NS_CONN_USER_FINDING;
					cu->use_mt_conn = B_FALSE;
				}
				(void) mutex_unlock(&cn->lock);

				/* cmg->lock unlocked by wait_for_conn_mt() */

				return (cn->ns_rc);
			}

			/* return the newly available conn_mt */
			*session = cn->conn;
			cu->state = NS_CONN_USER_CONNECTED;
			(void) mutex_unlock(&cn->lock);

			/* cmg->lock unlocked by wait_for_conn_mt() */

			return (NS_LDAP_SUCCESS);
		}

		/* next, look for a connecting conn_mt */
		if (i == 0)
			st = NS_CONN_MT_CONNECTING;
	}

	/* no connection found, start opening one */
	cn = init_conn_mt(cmg, errorp);
	if (cn == NULL) {
		(void) mutex_unlock(&cmg->lock);
		return ((*errorp)->status);
	}
	cu->conn_mt = cn;
	cn->opened_for = cu->type;
	cn->referral = cu->referral;
	if (cmg->ldap_mt == B_TRUE)
		cn->cu_max = NS_CONN_MT_USER_MAX;
	else
		cn->cu_max = 1;
	add_cm2cmg(cn, cmg);
	(void) mutex_unlock(&cmg->lock);

	return (NS_LDAP_NOTFOUND);
}


/*
 * add an MT connection to the connection management
 *
 * Input:
 *   con	: pointer to the Connection info
 *   cu		: pointer to the conn_user structure
 * Output:
 *   ep		: hold pointer to error info (ns_ldap_error_t)
 */
int
__s_api_conn_mt_add(Connection *con, ns_conn_user_t *cu, ns_ldap_error_t **ep)
{
	ns_conn_mgmt_t	*cmg = cu->conn_mgmt;
	ns_conn_mt_t	*cm = cu->conn_mt;

	/* if the conn_mgmt is being shut down, return error */
	NS_CONN_CHECK_ABORT_AND_LOCK(cmg, cu, ep);

	/*
	 * start the change monitor thread only if it
	 * hasn't been started and the process is the
	 * main nscd (not peruser nscd)
	 */
	if (cmg->procchg_started == B_FALSE && cmg->is_nscd == B_TRUE) {
		start_thread(cmg);
		cmg->procchg_started = B_TRUE;
	}
	(void) mutex_lock(&cm->lock);
	cm->conn = con;
	cm->state = NS_CONN_MT_CONNECTED;
	cm->pid = getpid();
	cm->create_time = time(NULL);
	cm->access_time = cm->create_time;
	cm->opened_for = cu->type;
	add_cu2cm(cu, cm);
	cu->conn_mt = cm;
	cu->state = NS_CONN_USER_CONNECTED;
	if (cmg->ldap_mt == B_TRUE)
		cm->cu_max = NS_CONN_MT_USER_MAX;
	else
		cm->cu_max = 1;

	/* wake up the waiters if any */
	(void) conn_signal(cm);

	(void) mutex_unlock(&cm->lock);
	(void) mutex_unlock(&cmg->lock);

	return (NS_LDAP_SUCCESS);
}

/*
 * return an MT connection to the pool when a conn user is done using it
 *
 * Input:
 *   cu		: pointer to the conn_user structure
 * Output:	NONE
 */
void
__s_api_conn_mt_return(ns_conn_user_t *cu)
{
	ns_conn_mt_t	*cm;
	ns_conn_mgmt_t	*cmg;

	if (cu == NULL || cu->use_mt_conn == B_FALSE)
		return;
	cm = cu->conn_mt;
	if (cm == NULL)
		return;
	cmg = cu->conn_mgmt;

	(void) mutex_lock(&cm->lock);
	del_cu4cm(cu, cm);
	cu->state = NS_CONN_USER_DISCONNECTED;
	cu->conn_mt = NULL;
	cu->bad_mt_conn = B_FALSE;

	/*
	 *  if this MT connection is no longer needed, or not usable, and
	 * no more conn_user uses it, then close it.
	 */

	if ((cm->close_when_nouser == B_TRUE ||
	    cm->state != NS_CONN_MT_CONNECTED) && cm->cu_cnt == 0) {
		(void) mutex_unlock(&cm->lock);
		(void) mutex_lock(&cmg->lock);
		(void) mutex_lock(&cm->lock);
		del_cm4cmg(cm, cmg);
		/* use ns_conn_free (instead of 1) to avoid lint warning */
		NS_CONN_UNLOCK_AND_FREE(ns_conn_free, cm, cmg);
	} else {
		if (cm->state == NS_CONN_MT_CONNECTED && cm->cu_cnt == 0 &&
		    cm->conn != NULL && cm->conn->ld != NULL) {
			struct timeval	zerotime;
			LDAPMessage	*res;

			zerotime.tv_sec = zerotime.tv_usec = 0L;
			/* clean up remaining results just in case */
			while (ldap_result(cm->conn->ld, LDAP_RES_ANY,
			    LDAP_MSG_ALL, &zerotime, &res) > 0) {
				if (res != NULL)
					(void) ldap_msgfree(res);
			}
		}
		(void) mutex_unlock(&cm->lock);
	}
}

/* save error info (rc and ns_ldap_error_t) in the conn_mt */
static void
err2cm(ns_conn_mt_t *cm, int rc, ns_ldap_error_t **errorp) {
	ns_ldap_error_t	*ep;

	cm->ns_rc = rc;
	cm->ns_error = NULL;
	if (errorp != NULL && *errorp != NULL) {
		ep = __s_api_copy_error(*errorp);
		if (ep == NULL)
			cm->ns_rc = NS_LDAP_MEMORY;
		else
			cm->ns_error = ep;
	}
}

/* copy error info (rc and ns_ldap_error_t) from conn_mt to conn_user */
static void
err_from_cm(ns_conn_user_t *cu, ns_conn_mt_t *cm) {
	ns_ldap_error_t	*ep;

	cu->ns_rc = cm->ns_rc;
	if (cu->ns_error != NULL)
		(void) __ns_ldap_freeError(&cu->ns_error);
	cu->ns_error = NULL;
	if (cm->ns_rc != NS_LDAP_SUCCESS && cm->ns_error != NULL) {
		ep = __s_api_copy_error(cm->ns_error);
		if (ep == NULL)
			cu->ns_rc = NS_LDAP_MEMORY;
		else
			cu->ns_error = ep;
	}
}

/* copy error info (rc and ns_ldap_error_t) from caller to conn_user */
static void
err_from_caller(ns_conn_user_t *cu, int rc, ns_ldap_error_t **errorp) {

	cu->ns_rc = rc;
	if (errorp != NULL) {
		if (cu->ns_error != NULL)
			(void) __ns_ldap_freeError(&cu->ns_error);
		cu->ns_error = *errorp;
		*errorp = NULL;
	} else
		cu->ns_error = NULL;
}

/*
 * remove an MT connection from the connection management when failed to open
 *
 * Input:
 *   cu		: pointer to the conn_user structure
 *   rc		: error code
 *   errorp	: pointer to pointer to error info (ns_ldap_error_t)
 * Output:
 *   errorp	: set to NULL, if none NULL cm, callers do not need to free it
 */
void
__s_api_conn_mt_remove(ns_conn_user_t *cu, int rc, ns_ldap_error_t **errorp)
{
	ns_conn_mgmt_t	*cmg;
	ns_conn_mt_t	*cm;
	int		free_cm = 0;

	if (cu == NULL || cu->use_mt_conn == B_FALSE)
		return;
	if ((cm = cu->conn_mt) == NULL)
		return;
	cmg = cu->conn_mgmt;

	(void) mutex_lock(&cmg->lock);
	(void) mutex_lock(&cm->lock);
	if (cm->state != NS_CONN_MT_CONNECT_ERROR) {
		cm->state = NS_CONN_MT_CONNECT_ERROR;
		cm->ns_rc = rc;
		if (errorp != NULL) {
			cm->ns_error = *errorp;
			*errorp = NULL;
		}
	}

	/* all the conn_users share the same error rc and ns_ldap_error_t */
	err_from_cm(cu, cm);
	/* wake up the waiters if any */
	(void) conn_signal(cm);

	del_cu4cm(cu, cm);
	cu->conn_mt = NULL;
	cu->bad_mt_conn = B_FALSE;
	if (cm->cu_cnt == 0) {
		del_cm4cmg(cm, cmg);
		free_cm = 1;
	}

	NS_CONN_UNLOCK_AND_FREE(free_cm, cm, cmg);
}

/*
 * check to see if the underlying libldap supports multi-threaded client
 * (MT connections)
 */
int
__s_api_check_libldap_MT_conn_support(ns_conn_user_t *cu, LDAP *ld,
	ns_ldap_error_t **ep)
{
	int		rc;
	ns_conn_mgmt_t	*cmg;

	/* if no need to check, just return success */
	if (cu->conn_mt == NULL || cu->use_mt_conn == B_FALSE)
		return (NS_LDAP_SUCCESS);

	cmg = cu->conn_mgmt;
	rc = setup_mt_ld(ld, cmg);

	if (cmg->do_mt_conn == B_FALSE) {
		/*
		 * If the conn_mgmt is being shut down, return error.
		 * if cmg is usable, cmg->lock will be locked. Otherwise,
		 * this function will return with rc NS_LDAP_OP_FAILED.
		 */
		NS_CONN_CHECK_ABORT_AND_LOCK(cmg, cu, ep);
		if (cmg->do_mt_conn == B_FALSE) {
			if (rc < 0)
				cmg->ldap_mt = B_FALSE;
			else {
				cmg->ldap_mt = B_TRUE;
				if (cmg->is_nscd  == B_TRUE ||
				    cmg->is_peruser_nscd == B_TRUE) {
					cmg->do_mt_conn = B_TRUE;
					cmg->state = NS_CONN_MGMT_ACTIVE;
				}
			}
		}
		(void) mutex_unlock(&cmg->lock);
	}

	if (rc < 0)
		__s_api_conn_mt_remove(cu, NS_LDAP_NOTFOUND, NULL);
	return (NS_LDAP_SUCCESS);
}

/*
 * Close an MT connection.
 * Assume cm not null and locked, assume conn_mgmt is also locked.
 * Return -1 if error, 1 if the cm should be freed, otherwise 0.
 */
static int
close_conn_mt(ns_conn_mt_t *cm, int rc, ns_ldap_error_t **errorp,
	ns_conn_user_t *cu)
{
	ns_conn_mgmt_t	*cmg = cm->conn_mgmt;
	ns_conn_mt_t	*m;
	ns_conn_user_t	*u;

	if ((cm->state != NS_CONN_MT_CONNECTED && cm->state !=
	    NS_CONN_MT_CLOSING) || cmg->cm_head == NULL || cmg->cm_cnt == 0)
		return (-1);

	/* if the conn_mt is not in the MT connection pool, nothing to do */
	for (m = cmg->cm_head; m; m = m->next) {
		if (cm == m)
			break;
	}
	if (m == NULL)
		return (-1);

	if (cm->state == NS_CONN_MT_CONNECTED) { /* first time in here */
		cm->state = NS_CONN_MT_CLOSING;
		/*
		 * If more cu exist to consume the error info, copy
		 * it to the cm. If the caller calls on behalf of
		 * a cu, cu won't be NULL. Check to see if there's
		 * more cu that needs the error info. If caller does
		 * not have a specific cu attached to it (e.g.,
		 * shutdown_all_conn_mt()), cu is NULL, check if at
		 * least one cu exists.
		 */
		if ((cu != NULL && cm->cu_cnt > 1) ||
		    (cu == NULL && cm->cu_cnt > 0)) {
			err2cm(cm, rc, errorp);
			/* wake up waiter (conn_user) if any */
			(void) conn_signal(cm);
		}

		/* for each conn_user using the conn_mt, set bad_mt_conn flag */
		if (cm->cu_head != NULL) {
			for (u = cm->cu_head; u; u = u->next) {
				u->bad_mt_conn = B_TRUE;
				if (cmg->shutting_down == B_FALSE)
					u->retry = B_TRUE;
			}
		}
	}

	/* detach the conn_mt if no more conn_user left */
	if ((cu != NULL && cm->cu_cnt == 1) ||
	    (cu == NULL && cm->cu_cnt ==  0)) {
		del_cm4cmg(cm, cmg);
		cm->detached = B_TRUE;
		return (1);
	}

	return (0);
}

/*
 * An MT connection becomes bad, close it and free resources.
 * This function is called with a ns_conn_user_t representing
 * a user of the MT connection.
 *
 * Input:
 *   cu		: pointer to the conn_user structure
 *   rc		: error code
 *   errorp	: pointer to pointer to error info (ns_ldap_error_t)
 * Output:
 *   errorp	: set to NULL (if no error), callers do not need to free it
 */
void
__s_api_conn_mt_close(ns_conn_user_t *cu, int rc, ns_ldap_error_t **errorp)
{
	ns_conn_mgmt_t	*cmg;
	ns_conn_mt_t	*cm;
	int		free_cm = 0;

	if (cu == NULL || cu->use_mt_conn == B_FALSE)
		return;

	if (cu->state != NS_CONN_USER_CONNECTED || (cm = cu->conn_mt) == NULL)
		return;
	cmg = cu->conn_mgmt;

	(void) mutex_lock(&cmg->lock);
	(void) mutex_lock(&cm->lock);

	/* close the MT connection if possible */
	free_cm = close_conn_mt(cm, rc, errorp, cu);
	if (free_cm == -1) { /* error case */
		(void) mutex_unlock(&cm->lock);
		(void) mutex_unlock(&cmg->lock);
		return;
	}

	if (rc != NS_LDAP_SUCCESS) { /* error info passed in, use it */
		err_from_caller(cu, rc, errorp);
	} else { /* error not passed in, use those saved in the conn_mt */
		err_from_cm(cu, cm);
	}

	/* detach the conn_user from the conn_mt */
	del_cu4cm(cu, cm);
	cu->conn_mt = NULL;
	cu->bad_mt_conn = B_FALSE;
	if (cmg->shutting_down == B_FALSE)
		cu->retry = B_TRUE;
	NS_CONN_UNLOCK_AND_FREE(free_cm, cm, cmg);
}

/*
 * Close an MT connection when the associated server is known to be
 * down. This function is called with a ns_conn_mt_t representing
 * the MT connection. That is, the caller is not a conn_user
 * thread but rather the procchg thread.
 */
static void
close_conn_mt_by_procchg(ns_conn_mt_t *cm, int rc, char *errmsg)
{
	ns_conn_mgmt_t	*cmg;
	int		free_cm = 0;
	ns_ldap_error_t	*ep;

	if (cm == NULL)
		return;
	cmg = cm->conn_mgmt;

	ep = (ns_ldap_error_t *)calloc(1, sizeof (*ep));
	if (ep != NULL) {
		ep->status = rc;
		if (errmsg != NULL)
			ep->message =  strdup(errmsg); /* OK if returns NULL */
	}

	(void) mutex_lock(&cmg->lock);
	(void) mutex_lock(&cm->lock);

	/* close the MT connection if possible */
	free_cm = close_conn_mt(cm, LDAP_SERVER_DOWN, &ep, NULL);
	if (free_cm == -1) { /* error case */
		(void) mutex_unlock(&cm->lock);
		(void) mutex_unlock(&cmg->lock);
		return;
	}
	(void) __ns_ldap_freeError(&ep);

	NS_CONN_UNLOCK_AND_FREE(free_cm, cm, cmg);
}

/*
 * Close an MT connection when there is a better server to connect to.
 * Mark the connection as to-be-closed-when-no-one-using so that
 * any outstanding ldap operations can run to completion.
 * Assume that both the conn_mt and conn_mgmt are locked.
 * Return 1 if the conn_mt should be freed.
 */
static int
close_conn_mt_when_nouser(ns_conn_mt_t *cm)
{
	int		free_cm = 0;

	if (cm->cu_cnt == 0) {
		del_cm4cmg(cm, cm->conn_mgmt);
		free_cm = 1;
	} else {
		cm->close_when_nouser = B_TRUE;
	}

	return (free_cm);
}

/*
 * Retrieve the configured preferred server list.
 * This function locked the conn_mgmt and does not
 * unlock at exit.
 */
static void
get_preferred_servers(boolean_t lock, boolean_t reload, ns_conn_mgmt_t *cmg)
{
	ns_ldap_error_t *errorp = NULL;
	void		**pservers = NULL;

	if (lock == B_TRUE)
		(void) mutex_lock(&cmg->lock);

	/* if already done, and no reload, then return */
	if (cmg->pservers_loaded == B_TRUE && reload == B_FALSE)
		return;

	if (cmg->pservers != NULL) {
		(void) __ns_ldap_freeParam((void ***)&cmg->pservers);
		cmg->pservers = NULL;
	}

	if (__ns_ldap_getParam(NS_LDAP_SERVER_PREF_P,
	    &pservers, &errorp) == NS_LDAP_SUCCESS) {
		cmg->pservers = (char **)pservers;
		cmg->pservers_loaded = B_TRUE;
	} else {
		(void) __ns_ldap_freeError(&errorp);
		(void) __ns_ldap_freeParam(&pservers);
	}
}

/*
 * This function handles the config or server status change notification
 * from the ldap_cachemgr.
 */
static ns_conn_mgmt_t *
proc_server_change(ns_server_status_change_t *chg, ns_conn_mgmt_t  *cmg)
{
	int		cnt, i, j, k, n;
	boolean_t	loop = B_TRUE;
	boolean_t	cmg_locked = B_FALSE;
	char 		*s;
	ns_conn_mt_t	*cm;
	ns_conn_mgmt_t	*ocmg;

	/* if config changed, reload the configuration */
	if (chg->config_changed == B_TRUE) {
		/* reload the conn_mgmt and Native LDAP config */
		ocmg = access_conn_mgmt(NS_CONN_MGMT_OP_RELOAD_CONFIG);
		shutdown_all_conn_mt(ocmg);
		/* release the one obtained from access_conn_mgmt(RELOAD) */
		(void) release_conn_mgmt(ocmg, B_FALSE);
		/* release the one obtained when ocmg was created */
		(void) release_conn_mgmt(ocmg, B_FALSE);
		return (ocmg);
	}

	if ((cnt = chg->num_server) == 0)
		return (cmg);

	/* handle down servers first */
	for (i = 0; i < cnt; i++) {

		if (chg->changes[i] != NS_SERVER_DOWN)
			continue;
		s = chg->servers[i];

		/*
		 * look for a CONNECTED MT connection using
		 * the same server s, and close it
		 */
		while (loop) {
			if (cmg_locked == B_FALSE) {
				(void) mutex_lock(&cmg->lock);
				cmg_locked = B_TRUE;
			}
			for (cm = cmg->cm_head; cm; cm = cm->next) {
				(void) mutex_lock(&cm->lock);

				if (cm->state == NS_CONN_MT_CONNECTED &&
				    cm->conn != NULL &&
				    strcasecmp(cm->conn->serverAddr, s) == 0) {
					(void) mutex_unlock(&cm->lock);
					break;
				}

				(void) mutex_unlock(&cm->lock);
			}
			if (cm != NULL) {
				(void) mutex_unlock(&cmg->lock);
				cmg_locked = B_FALSE;
				close_conn_mt_by_procchg(cm, LDAP_SERVER_DOWN,
				    NS_CONN_MSG_DOWN_FROM_CACHEMGR);
				/*
				 * Process the next cm using server s.
				 * Start from the head of the cm linked
				 * list again, as the cm list may change
				 * after close_conn_mt_by_procchg() is done.
				 */
				continue;
			}

			/*
			 * No (more) MT connection using the down server s.
			 * Process the next server on the list.
			 */
			break;
		} /* while loop */
	}

	/*
	 * Next handle servers whose status changed to up.
	 * Get the preferred server list first if not done yet.
	 * get_preferred_servers() leaves conn_mgmt locked.
	 */
	get_preferred_servers(cmg_locked == B_FALSE ? B_TRUE : B_FALSE,
	    B_FALSE, cmg);
	cmg_locked = B_TRUE;
	/*
	 * if no preferred server configured, we don't switch MT connection
	 * to a more preferred server (i.e., fallback), so just return
	 */
	if (cmg->pservers == NULL) {
		(void) mutex_unlock(&cmg->lock);
		return (cmg);
	}

	/* for each server that is up now */
	for (i = 0; i < cnt; i++) {
		if (chg->changes[i] != NS_SERVER_UP)
			continue;
		s = chg->servers[i];

		/*
		 * look for a CONNECTED MT connection which uses
		 * a server less preferred than s, and treat it
		 * as 'fallback needed' by calling
		 * close_conn_mt_when_nouser()
		 */
		k = -1;
		loop = B_TRUE;
		while (loop) {
			if (cmg_locked == B_FALSE) {
				(void) mutex_lock(&cmg->lock);
				cmg_locked = B_TRUE;
			}

			/* Is s a preferred server ? */
			if (k == -1) {
				for (j = 0; cmg->pservers[j] != NULL; j++) {
					if (strcasecmp(cmg->pservers[j],
					    s) == 0) {
						k = j;
						break;
					}
				}
			}
			/* skip s if not a preferred server */
			if (k == -1) {
				break;
			}

			/* check each MT connection */
			for (cm = cmg->cm_head; cm; cm = cm->next) {
				(void) mutex_lock(&cm->lock);
				/*
				 * Find an MT connection that is connected and
				 * not marked, but leave WRITE or REFERRAL
				 * connections alone, since fallback does not
				 * make sense for them.
				 */
				if (cm->state == NS_CONN_MT_CONNECTED &&
				    cm->close_when_nouser == B_FALSE &&
				    cm->conn != NULL && cm->opened_for !=
				    NS_CONN_USER_WRITE &&
				    cm->referral == B_FALSE) {
					n = -1;
					/*
					 * j < k ??? should we close
					 * an active MT that is using s ?
					 * ie could s went down and up
					 * again, but cm is bound prior to
					 * the down ? Play safe here,
					 * and check j <= k.
					 */
					for (j = 0; j <= k; j++) {
						if (strcasecmp(
						    cm->conn->serverAddr,
						    cmg->pservers[j]) == 0) {
							n = j;
							break;
						}
					}
					/*
					 * s is preferred, if its location
					 * in the preferred server list is
					 * ahead of that of the server
					 * used by the cm (i.e., no match
					 * found before s)
					 */
					if (n == -1) { /* s is preferred */
						int fr = 0;
						fr = close_conn_mt_when_nouser(
						    cm);
						NS_CONN_UNLOCK_AND_FREE(fr,
						    cm, cmg);
						cmg_locked = B_FALSE;
						/*
						 * break, not continue,
						 * because we need to
						 * check the entire cm
						 * list again. The call
						 * above may change the
						 * cm list.
						 */
						break;
					}
				}
				(void) mutex_unlock(&cm->lock);
			}
			/* if no (more) cm using s, check next server */
			if (cm == NULL)
				loop = B_FALSE;
		} /* while loop */
	}
	if (cmg_locked == B_TRUE)
		(void) mutex_unlock(&cmg->lock);
	return (cmg);
}

/* Shut down all MT connection managed by the connection management */
void
shutdown_all_conn_mt(ns_conn_mgmt_t  *cmg)
{
	ns_ldap_error_t	*ep;
	ns_conn_mt_t	*cm;
	int		free_cm = 0;
	boolean_t	done = B_FALSE;

	ep = (ns_ldap_error_t *)calloc(1, sizeof (*ep));
	if (ep != NULL) { /* if NULL, not a problem */
		/* OK if returns NULL */
		ep->message = strdup(NS_CONN_MSG_SHUTDOWN_RELOADED);
	}

	(void) mutex_lock(&cmg->lock);
	while (cmg->cm_head != NULL && done == B_FALSE) {
		for (cm = cmg->cm_head; cm; cm = cm->next) {
			(void) mutex_lock(&cm->lock);
			if (cm->next == NULL)
				done = B_TRUE;
			/* shut down each conn_mt, ignore errors */
			free_cm = close_conn_mt(cm, LDAP_OTHER, &ep, NULL);
			(void) mutex_unlock(&cm->lock);
			if (free_cm == 1) {
				(void) free_conn_mt(cm, 0);
				/*
				 * conn_mt may change, so start from
				 * top of list again
				 */
				break;
			}
		}
	}
	(void) mutex_unlock(&cmg->lock);
	(void) __ns_ldap_freeError(&ep);
}

/* free all the resources used by the connection management */
void
__s_api_shutdown_conn_mgmt()
{
	ns_conn_mgmt_t	*cmg;

	cmg = access_conn_mgmt(NS_CONN_MGMT_OP_SHUTDOWN);
	if (cmg == NULL) /* already being SHUT done */
		return;

	(void) shutdown_all_conn_mt(cmg);
	(void) release_conn_mgmt(cmg, B_FALSE);

	/* then destroy the conn_mgmt */
	(void) release_conn_mgmt(cmg, B_FALSE);
}


/*
 * Reinitialize the libsldap connection management after
 * a new native LDAP configuration is received.
 */
void
__s_api_reinit_conn_mgmt_new_config(ns_config_t *new_cfg)
{
	ns_conn_mgmt_t	*cmg;
	ns_conn_mgmt_t	*ocmg;

	cmg = access_conn_mgmt(NS_CONN_MGMT_OP_REF);
	if (cmg == NULL)
		return;
	if (cmg->config == new_cfg || cmg->state == NS_CONN_MGMT_DETACHED) {
		(void) release_conn_mgmt(cmg, B_FALSE);
		return;
	}

	/* reload the conn_mgmt and native LDAP config */
	ocmg = access_conn_mgmt(NS_CONN_MGMT_OP_NEW_CONFIG);
	if (ocmg == cmg)
		shutdown_all_conn_mt(ocmg);
	/* release the one obtained from access_conn_mgmt(RELOAD) */
	(void) release_conn_mgmt(ocmg, B_FALSE);
	/* release the one obtained when ocmg was created */
	(void) release_conn_mgmt(ocmg, B_FALSE);
	/* release the one obtained when this function is entered */
	(void) release_conn_mgmt(cmg, B_FALSE);
}

/*
 * Prepare to retry ldap search operation if needed.
 * Return 1 if retry is needed, otherwise 0.
 * If first time in, return 1. If not, return 1 if:
 * - not a NS_CONN_USER_GETENT conn_user AND
 * - have not retried 3 times yet AND
 * - previous search failed AND
 * - the retry flag is set in the ns_conn_user_t or config was reloaded
 */
int
__s_api_setup_retry_search(ns_conn_user_t **conn_user,
	ns_conn_user_type_t type, int *try_cnt, int *rc,
	ns_ldap_error_t **errorp)
{
	boolean_t	retry;
	ns_conn_user_t	*cu = *conn_user;
	ns_conn_mgmt_t	*cmg;

	if (*try_cnt > 0 && cu != NULL) {
		/*
		 * if called from firstEntry(), keep conn_mt for
		 * the subsequent getnext requests
		 */
		if (cu->type == NS_CONN_USER_GETENT && *rc == NS_LDAP_SUCCESS)
			return (0);
		cmg = cu->conn_mgmt;
		retry = cu->retry;
		if (cu->conn_mt != NULL)
			__s_api_conn_mt_return(cu);
		if (cmg != NULL && cmg->cfg_reloaded == B_TRUE)
			retry = B_TRUE;
		__s_api_conn_user_free(cu);
		*conn_user = NULL;

		if (*rc == NS_LDAP_SUCCESS || retry != B_TRUE)
			return (0);
	}

	*try_cnt = *try_cnt + 1;
	if (*try_cnt > NS_LIST_TRY_MAX)
		return (0);

	*conn_user = __s_api_conn_user_init(type, NULL, B_FALSE);
	if (*conn_user == NULL) {
		if (*try_cnt == 1) { /* first call before any retry */
			*rc = NS_LDAP_MEMORY;
			*errorp = NULL;
		}
		/* for 1+ try, use previous rc and errorp */
		return (0);
	}

	/* free ldap_error_t from previous search */
	if (*try_cnt > 1 && rc != NS_LDAP_SUCCESS && *errorp != NULL)
		(void) __ns_ldap_freeError(errorp);

	return (1);
}

/* prepare to get the next entry for an enumeration */
int
__s_api_setup_getnext(ns_conn_user_t *cu, int *ns_err,
	ns_ldap_error_t **errorp)
{
	int rc;
	ns_conn_mgmt_t	*cmg;

	/*
	 * if using an MT connection, ensure the thread-specific data are set,
	 * but if the MT connection is no longer good, return the error saved.
	 */
	if (cu->conn_mt != NULL && (cmg = cu->conn_mgmt) != NULL) {

		if (cu->bad_mt_conn ==  B_TRUE) {
			__s_api_conn_mt_close(cu, 0, NULL);
			*ns_err = cu->ns_rc;
			*errorp = cu->ns_error;
			cu->ns_error = NULL;
			return (*ns_err);
		}

		rc = conn_tsd_check(cmg);
		if (rc != NS_LDAP_SUCCESS) {
			*errorp = NULL;
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);
}

/* wait for an MT connection to become available */
static int
conn_wait(ns_conn_mt_t *conn_mt, ns_conn_user_t *conn_user)
{
	ns_conn_waiter_t	mywait;
	ns_conn_waiter_t	*head = &conn_mt->waiter;

	(void) cond_init(&(mywait.waitcv), USYNC_THREAD, 0);
	mywait.key = conn_user;
	mywait.signaled = 0;
	mywait.next = head->next;
	mywait.prev = head;
	if (mywait.next)
		mywait.next->prev = &mywait;
	head->next = &mywait;
	atomic_inc_uint(&conn_mt->waiter_cnt);

	while (!mywait.signaled)
		(void) cond_wait(&(mywait.waitcv), &conn_mt->lock);
	if (mywait.prev)
		mywait.prev->next = mywait.next;
	if (mywait.next)
		mywait.next->prev = mywait.prev;
	return (0);
}

/* signal that an MT connection is now available */
static int
conn_signal(ns_conn_mt_t *conn_mt)
{
	int			c = 0;
	ns_conn_waiter_t	*head = &conn_mt->waiter;
	ns_conn_waiter_t	*tmp = head->next;

	while (tmp) {
		(void) cond_signal(&(tmp->waitcv));
		tmp->signaled = 1;
		atomic_dec_uint(&conn_mt->waiter_cnt);
		c++;
		tmp = tmp->next;
	}

	return (c);
}

/*
 * wait and process the server status and/or config change notification
 * from ldap_cachemgr
 */
static void *
get_server_change(void *arg)
{
	union {
		ldap_data_t	s_d;
		char		s_b[DOORBUFFERSIZE];
	} space;
	ldap_data_t	*sptr = &space.s_d;
	int		ndata;
	int		adata;
	char		*ptr;
	int		ds_cnt;
	int		door_rc;
	int		which;
	int		retry = 0;
	boolean_t	loop = B_TRUE;
	char		*c, *oc;
	int		dslen = strlen(DOORLINESEP);
	char		dsep = DOORLINESEP_CHR;
	char		chg_data[DOORBUFFERSIZE];
	char		**servers = NULL;
	boolean_t	getchg_not_supported = B_FALSE;
	ns_conn_mgmt_t	*ocmg = (ns_conn_mgmt_t *)arg;
	ns_conn_mgmt_t	*cmg;
	ns_server_status_t *status = NULL;
	ns_server_status_change_t chg = { 0 };
	ldap_get_change_out_t *get_chg;
	ldap_get_chg_cookie_t cookie;
	ldap_get_chg_cookie_t new_cookie;

	cmg = access_conn_mgmt(NS_CONN_MGMT_OP_REF);
	if (cmg != ocmg)
		thr_exit(NULL);
	/* cmg is locked before called */
	cmg->procchg_tid = thr_self();

	/* make sure the thread specific data are set */
	(void) conn_tsd_setup(cmg);
	cookie = cmg->cfg_cookie;

	while (loop) {

		if (chg.servers != NULL)
			free(chg.servers);
		if (chg.changes != NULL)
			free(chg.changes);
		if (sptr != &space.s_d)
			(void) munmap((char *)sptr, sizeof (space));

		/*
		 * If the attached conn_mgmt has been deleted,
		 * then exit. The new conn_mgmt will starts it
		 * own monitor thread later. If libsldap is being
		 * unloaded or configuration reloaded, OR
		 * ldap_cachemgr rejected the GETSTATUSCHANGE door
		 * call, then exit as well.
		 */
		if (cmg == NULL || cmg->state == NS_CONN_MGMT_DETACHED ||
		    getchg_not_supported == B_TRUE) {

			if (cmg != NULL) {
				cmg->procchg_started = B_FALSE;
				(void) release_conn_mgmt(cmg, B_FALSE);
			}

			conn_tsd_free();
			thr_exit(NULL);
		}

		(void) memset(space.s_b, 0, DOORBUFFERSIZE);
		(void) memset(&chg, 0, sizeof (chg));
		adata = sizeof (ldap_call_t) + 1;
		ndata = sizeof (space);
		space.s_d.ldap_call.ldap_callnumber = GETSTATUSCHANGE;
		space.s_d.ldap_call.ldap_u.get_change.op =
		    NS_STATUS_CHANGE_OP_START;
		space.s_d.ldap_call.ldap_u.get_change.cookie = cookie;
		sptr = &space.s_d;
		door_rc = __ns_ldap_trydoorcall_getfd();
		cmg->procchg_door_call = B_TRUE;
		if (release_conn_mgmt(cmg, B_FALSE) == NULL) {
			conn_tsd_free();
			thr_exit(NULL);
		}

		if (door_rc == NS_CACHE_SUCCESS)
			door_rc = __ns_ldap_trydoorcall_send(&sptr, &ndata,
			    &adata);

		/*
		 * Check and see if the conn_mgmt is still current.
		 * If not, no need to continue.
		 */
		cmg = access_conn_mgmt(NS_CONN_MGMT_OP_REF);
		if (cmg != NULL)
			cmg->procchg_door_call = B_FALSE;
		if (cmg != ocmg) {
			if (cmg != NULL) {
				cmg->procchg_started = B_FALSE;
				(void) release_conn_mgmt(cmg, B_FALSE);
			}
			conn_tsd_free();
			thr_exit(NULL);
		}

		if (door_rc != NS_CACHE_SUCCESS) {
			if (door_rc == NS_CACHE_NOSERVER) {
				if (retry++ > 10)
					getchg_not_supported = B_TRUE;
				else {
					/*
					 * ldap_cachemgr may be down, give
					 * it time to restart
					 */
					(void) sleep(2);
				}
			} else if (door_rc == NS_CACHE_NOTFOUND)
				getchg_not_supported = B_TRUE;
			continue;
		} else
			retry = 0;

		/* copy info from door call return structure */
		get_chg =  &sptr->ldap_ret.ldap_u.changes;
		ptr = get_chg->data;
		/* configuration change ? */
		if (get_chg->type == NS_STATUS_CHANGE_TYPE_CONFIG) {
			chg.config_changed = B_TRUE;
			cmg = proc_server_change(&chg, cmg);
			continue;
		}

		/* server status changes ? */
		if (get_chg->type == NS_STATUS_CHANGE_TYPE_SERVER) {
			/*
			 * first check cookies, if don't match, config
			 * has changed
			 */
			new_cookie = get_chg->cookie;
			if (new_cookie.mgr_pid != cookie.mgr_pid ||
			    new_cookie.seq_num != cookie.seq_num) {
				chg.config_changed = B_TRUE;
				cmg = proc_server_change(&chg, cmg);
				continue;
			}

			(void) strlcpy(chg_data, ptr, sizeof (chg_data));
			chg.num_server = get_chg->server_count;

			servers = (char **)calloc(chg.num_server,
			    sizeof (char *));
			if (servers == NULL) {
				syslog(LOG_INFO, NS_CONN_MSG_MEMORY_ERROR);
				continue;
			}
			status = (ns_server_status_t *)calloc(chg.num_server,
			    sizeof (int));
			if (status == NULL) {
				syslog(LOG_INFO, NS_CONN_MSG_MEMORY_ERROR);
				free(servers);
				continue;
			}
			ds_cnt = 0;
			which = 0;
			oc = ptr;
			for (c = ptr; which != 2; c++) {
				/* look for DOORLINESEP or end of string */
				if (*c != dsep && *c != '\0')
					continue;
				if (*c == dsep) { /* DOORLINESEP */
					*c = '\0'; /* current value */
					c += dslen; /* skip to next value */
				}
				if (which == 0) { /* get server info */
					servers[ds_cnt] = oc;
					oc = c;
					which = 1; /* get status next */
					continue;
				}
				/* which == 1, get up/down status */
				if (strcmp(NS_SERVER_CHANGE_UP, oc) == 0) {
					status[ds_cnt] = NS_SERVER_UP;
				} else if (strcmp(NS_SERVER_CHANGE_DOWN,
				    oc) == 0)
					status[ds_cnt] = NS_SERVER_DOWN;
				else {
					syslog(LOG_INFO,
					    NS_CONN_MSG_BAD_CACHEMGR_DATA);
					continue;
				}
				oc = c;
				ds_cnt++;
				if (*c == '\0')
					which = 2; /* exit the loop */
				else
					which = 0; /* get server info next */
			}
			chg.servers = servers;
			chg.changes = status;
			cmg = proc_server_change(&chg, cmg);
			continue;
		}
	}

	return (NULL);
}

/* start the thread handling the change notification from ldap_cachemgr */
static void
start_thread(ns_conn_mgmt_t *cmg) {

	int		errnum;

	/*
	 * start a thread to get and process config and server status changes
	 */
	if (thr_create(NULL, 0, get_server_change,
	    (void *)cmg, THR_DETACHED, NULL) != 0) {
		errnum = errno;
		syslog(LOG_WARNING, NS_CONN_MSG_NO_PROCCHG_THREAD,
		    strerror(errnum));
	}
}
