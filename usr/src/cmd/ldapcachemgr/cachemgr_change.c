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
 * Copyright 2018 Joyent, Inc.
 */

#include <strings.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <libintl.h>
#include <door.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <procfs.h>
#include <pthread.h>
#include "cachemgr.h"

extern admin_t	current_admin;

#define	CLEANUP_WAIT_TIME 60

typedef enum cleanup_type {
	CLEANUP_ALL	= 1,
	CLEANUP_BY_PID	= 2
} cleanup_type_t;

typedef struct cleanup_op {
	pid_t		pid;
	cleanup_type_t	type;
} cleanup_op_t;

typedef struct main_nscd_struct {
	pid_t		pid;			/* main nscd pid */
	thread_t	tid;			/* main nscd tid */
	int		in_progress;		/* A main nscd thread is */
						/* waiting for change or */
						/* copying data */
	int		is_waiting_cleanup;	/* A main nscd thread is */
						/* waiting for another main */
						/* nscd thread to be cleaned */
						/* up */
} main_nscd_t;

static chg_info_t chg = { DEFAULTMUTEX, DEFAULTCV, 0, NULL, NULL, NULL, 0 };

static main_nscd_t chg_main_nscd = {0, 0, 0, 0};
static mutex_t chg_main_nscd_lock = DEFAULTMUTEX;
static cond_t chg_main_nscd_cv = DEFAULTCV;

/*
 * The cookie of the configuration and its mutex
 */
static ldap_get_chg_cookie_t config_cookie = {0, 0};
static mutex_t config_cookie_lock = DEFAULTMUTEX;

static void cleanup_thread_by_pid(pid_t pid);

ldap_get_chg_cookie_t
chg_config_cookie_get(void)
{
	ldap_get_chg_cookie_t cookie;
	(void) mutex_lock(&config_cookie_lock);
	cookie = config_cookie;
	(void) mutex_unlock(&config_cookie_lock);
	return (cookie);
}

static void
chg_config_cookie_increment_seq_num(void)
{
	(void) mutex_lock(&config_cookie_lock);
	config_cookie.seq_num++;
	(void) mutex_unlock(&config_cookie_lock);
}

void
chg_config_cookie_set(ldap_get_chg_cookie_t *cookie)
{
	(void) mutex_lock(&config_cookie_lock);
	config_cookie.mgr_pid = cookie->mgr_pid;
	config_cookie.seq_num = cookie->seq_num;
	(void) mutex_unlock(&config_cookie_lock);
}
static boolean_t
chg_cookie_equal(ldap_get_chg_cookie_t *c1, ldap_get_chg_cookie_t *c2)
{
	if (c1->mgr_pid == c2->mgr_pid && c1->seq_num == c2->seq_num)
		return (B_TRUE);
	else
		return (B_FALSE);
}
/*
 * Create a node in the list and output the node. The caller can NOT free it.
 */
static  int
waiting_list_add(chg_info_t *info, pid_t pid, thread_t tid,
    waiting_list_t **wlp)
{

	waiting_list_t	*wl;

	*wlp = NULL;

	if ((wl = (waiting_list_t *)calloc(1, sizeof (waiting_list_t)))
	    == NULL) {
		logit("waiting_list_add: No memory. pid %ld tid %d\n",
		    pid, tid);
		return (CHG_NO_MEMORY);
	}

	wl->pid = pid;
	wl->tid = tid;

	if (info->chg_w_first == NULL) {
		info->chg_w_first = wl;
		info->chg_w_last = wl;
	} else {
		info->chg_w_last->next = wl;
		wl->prev = info->chg_w_last;
		info->chg_w_last = wl;
	}
	*wlp = wl;
	return (CHG_SUCCESS);
}

/*
 * Find a node with matching tid in the list and remove it from the list.
 */
static int
waiting_list_delete(chg_info_t *info, thread_t tid)
{
	waiting_list_t	*wl;

	for (wl = info->chg_w_first; wl != NULL; wl = wl->next) {
		if (wl->tid == tid) {
			if (wl->next == NULL) {
				if (wl->prev == NULL) {
					info->chg_w_first = NULL;
					info->chg_w_last = NULL;
				} else {
					wl->prev->next = NULL;
					info->chg_w_last =  wl->prev;
				}
			} else {
				if (wl->prev == NULL) {
					wl->next->prev = NULL;
					info->chg_w_first = wl->next;
				} else {
					wl->prev->next = wl->next;
					wl->next->prev = wl->prev;
				}
			}
			free(wl);
			return (CHG_SUCCESS);
		}
	}
	return (CHG_NOT_FOUND_IN_WAITING_LIST);
}

/*
 * Delete the thread from the waiting list and remove data when the list
 * is empty.
 */
static void
waiting_list_cleanup(chg_info_t *chg, thread_t tid)
{
	int	rc;

	rc = waiting_list_delete(chg, tid);

	if (rc == CHG_SUCCESS && chg->chg_w_first == NULL) {
		free(chg->chg_data);
		chg->chg_data = NULL;
		chg->chg_wakeup = 0;
	}
}

/*
 * Set flag by pid so it can be cleaned up.
 */
static void
waiting_list_set_cleanup(chg_info_t *info, pid_t pid)
{
	waiting_list_t	*wl;

	for (wl = info->chg_w_first; wl != NULL; wl = wl->next) {
		if (wl->pid == pid) {
			wl->cleanup = 1;
			break;
		}
	}
}

/*
 * Return: 1 - door client is dead, 0 - door client is alive
 */
static int
door_client_dead(void)
{
	ucred_t *uc = NULL;
	int	rc;

	if (door_ucred(&uc) == -1 && errno == EINVAL) {
		rc = 1;
	} else {
		rc = 0;
	}
	if (uc)
		ucred_free(uc);

	return (rc);
}

/*
 * This function handles GETSTATUSCHANGE call from main nscd.
 * The call can be a START op or STOP op. A cookie is sent from main nscd too.
 * The static global variable main_nscd keeps record of pid, tid and some flags.
 * If the thread is door_return(), main_nscd.pid, main_nscd.tid are set to 0.
 * When the call is START op, it checks if main_nscd.pid is 0. If it is, it
 * proceeds to wait for the change notification. If it's not, which means
 * another main nscd handling thread is still around. It sends broadcast to
 * clean up that thread and wait until the cleanup is done then proceeds to
 * wait for the change notification. If same main nscd sends START op
 * repeatedly, it'll be rejected.
 * It also checks the cookie from main nscd. If it's not the same as
 * ldap_cachemgr's cookie, door returns config change.
 * If the door call is STOP op, it creates a thread to clean up main nscd START
 * thread so it won't be blocking.
 * In waiting for the change notification phase, the thread is waken up by
 * the notification threads or by the cleanup threads.
 * If it's a notification, it copies data to the stack then door return.
 * If it's a cleanup, door_client_dead() is called to verify it then
 * door return.
 */
int
chg_get_statusChange(LineBuf *info, ldap_call_t *in, pid_t nscd_pid)
{
	int	rc = CHG_SUCCESS, another_main_nscd_thread_alive = 0;
	int	len, return_now;
	thread_t this_tid = thr_self();
	waiting_list_t	*wl = NULL;
	ldap_get_change_out_t *cout;
	ldap_get_chg_cookie_t cookie;

	info->str = NULL;
	info->len = 0;

	if (in->ldap_u.get_change.op == NS_STATUS_CHANGE_OP_START) {

		(void) mutex_lock(&chg_main_nscd_lock);
		if (chg_main_nscd.pid != 0) {
			if (nscd_pid != chg_main_nscd.pid) {
				/*
				 * This is the case that nscd doesn't shut down
				 * properly(e.g. core) and STOP op is not sent,
				 * the thread handling it is still around and
				 * not cleaned up yet.
				 * Test if the thread is still alive.
				 * If it is, clean it up.
				 * For thr_kill, if sig is 0, a validity check
				 * is done for the existence of the target
				 * thread; no signal is sent.
				 */
				if (thr_kill(chg_main_nscd.tid, 0) == 0) {
					another_main_nscd_thread_alive = 1;
					cleanup_thread_by_pid(
					    chg_main_nscd.pid);
				}
			} else if (chg_main_nscd.in_progress ||
			    chg_main_nscd.is_waiting_cleanup) {
				/*
				 * Same nscd pid can only send door call
				 * one at a time and wait for ldap_cachemgr to
				 * return change data. If it's the same pid
				 * again, it's an nscd error.
				 */
				(void) mutex_unlock(&chg_main_nscd_lock);
				return (CHG_NSCD_REPEATED_CALL);
			}
		}
		/*
		 * Wait for another thread to be cleaned up if it's alive.
		 * After that this cond var is waken up.
		 */
		if (another_main_nscd_thread_alive) {
			while (chg_main_nscd.in_progress) {
				chg_main_nscd.is_waiting_cleanup = 1;
				(void) cond_wait(&chg_main_nscd_cv,
				    &chg_main_nscd_lock);
			}
		}

		/*
		 * Replace pid and tid and set the flag.
		 */
		chg_main_nscd.is_waiting_cleanup = 0;
		chg_main_nscd.pid = nscd_pid;
		chg_main_nscd.tid = this_tid;
		chg_main_nscd.in_progress = 1;
		(void) mutex_unlock(&chg_main_nscd_lock);

		cookie = chg_config_cookie_get();

		if (!chg_cookie_equal(&cookie, &in->ldap_u.get_change.cookie)) {
			/*
			 * different cookie, set new cookie and
			 * return door call right away
			 */
			len = sizeof (ldap_get_change_out_t);
			if ((cout = calloc(1, len)) == NULL) {
				rc = CHG_NO_MEMORY;
			} else {
				cout->type = NS_STATUS_CHANGE_TYPE_CONFIG;
				cout->cookie = cookie;
				info->str = (char *)cout;
				info->len = len;
			}

		} else {
			(void) mutex_lock(&chg.chg_lock);

			/* wait for the change notification */
			rc = waiting_list_add(&chg, nscd_pid, this_tid, &wl);
			if (rc == CHG_SUCCESS) {
				return_now = 0;
				while (!chg.chg_wakeup) {
					if (wl->cleanup ||
					    door_client_dead()) {
						return_now = 1;
						break;
					}
					(void) cond_wait(&chg.chg_cv,
					    &chg.chg_lock);
				}
				/* Check if door client is still alive again */
				if (!return_now && !wl->cleanup &&
				    !door_client_dead()) {
					/* copy data to buffer */
					if ((info->str = malloc(
					    chg.chg_data_size)) == NULL) {
						rc = CHG_NO_MEMORY;
					} else {
						(void) memcpy(info->str,
						    chg.chg_data,
						    chg.chg_data_size);
						info->len = chg.chg_data_size;
					}
				}
				waiting_list_cleanup(&chg, this_tid);
			}
			(void) mutex_unlock(&chg.chg_lock);
		}


		/*
		 * Reset pid, tid and flag, send wakeup signal.
		 */
		(void) mutex_lock(&chg_main_nscd_lock);
		chg_main_nscd.pid = 0;
		chg_main_nscd.tid = 0;
		chg_main_nscd.in_progress = 0;
		if (chg_main_nscd.is_waiting_cleanup)
			(void) cond_broadcast(&chg_main_nscd_cv);

		(void) mutex_unlock(&chg_main_nscd_lock);

	} else if (in->ldap_u.get_change.op == NS_STATUS_CHANGE_OP_STOP) {

		cleanup_thread_by_pid(nscd_pid);
		rc = CHG_SUCCESS;

	} else {
		rc = CHG_INVALID_PARAM;
	}
	if (rc == CHG_EXCEED_MAX_THREADS)
		cleanup_thread_by_pid(0);

	return (rc);
}

/*
 * This function copies the header and data stream to the buffer
 * then send broadcast to wake up the chg_get_statusChange() threads.
 */
int
chg_notify_statusChange(char *str)
{
	ldap_get_change_out_t *cout = (ldap_get_change_out_t *)str;

	cout->cookie = chg_config_cookie_get();

	(void) mutex_lock(&chg.chg_lock);
	if (chg.chg_w_first != NULL && chg.chg_wakeup == 0) {

		if (chg.chg_data) {
			free(chg.chg_data);
			chg.chg_data = NULL;
		}

		chg.chg_data = str;

		if (cout->type == NS_STATUS_CHANGE_TYPE_CONFIG)
			chg.chg_data_size = sizeof (ldap_get_change_out_t);
		else
			/* NS_STATUS_CHANGE_TYPE_SERVER */
			chg.chg_data_size = sizeof (ldap_get_change_out_t) -
			    sizeof (int) + cout->data_size;

		chg.chg_wakeup = 1;
		(void) cond_broadcast(&chg.chg_cv);
	}
	(void) mutex_unlock(&chg.chg_lock);

	return (CHG_SUCCESS);
}

/*
 * This is called when the configuration is refreshed.
 * The new configuration is different from the current one, a notification
 * is sent tochg_get_statusChange() threads.
 */
void
chg_test_config_change(ns_config_t *new, int *change_status)
{
	int	changed = 0;
	LineBuf	new_cfg, cur_cfg;
	ns_ldap_error_t *errp = NULL;
	ldap_config_out_t *new_out, *cur_out;
	ldap_get_change_out_t	*cout;

	(void) memset(&new_cfg, 0, sizeof (LineBuf));
	(void) memset(&cur_cfg, 0, sizeof (LineBuf));
	/*
	 * Flatten the config data of the newly downloaded config and
	 * current default config and compare both.
	 */
	if ((errp = __ns_ldap_LoadDoorInfo(&new_cfg, NULL, new, 0)) != NULL) {
		__ns_ldap_freeError(&errp);
		/* error, assume the config is changed */
		changed = 1;
	} else if ((errp = __ns_ldap_LoadDoorInfo(&cur_cfg, NULL, NULL, 0))
	    != NULL) {
		__ns_ldap_freeError(&errp);
		/* error, assume the config is changed */
		changed = 1;
	}
	if (changed == 0) {
		new_out = (ldap_config_out_t *)new_cfg.str;
		cur_out = (ldap_config_out_t *)cur_cfg.str;
		if (strcmp(new_out->config_str, cur_out->config_str) != 0) {
			changed = 1;
			if (current_admin.debug_level >= DBG_PROFILE_REFRESH) {
				logit("config changed.\n");
			}
		}
	}
	if (cur_cfg.str)
		free(cur_cfg.str);
	if (new_cfg.str)
		free(new_cfg.str);

	if (changed) {

		if ((cout = calloc(1, sizeof (ldap_get_change_out_t)))
		    == NULL) {
			logit("chg_test_config_change: No Memory\n");
		} else {
			/*
			 * Replace the currentdefault config with the new
			 * config
			 */
			__s_api_init_config(new);
			chg_config_cookie_increment_seq_num();
			cout->type = NS_STATUS_CHANGE_TYPE_CONFIG;
			/*
			 * cout->cookie is set by
			 * chg_notify_statusChange
			 */
			(void) chg_notify_statusChange((char *)cout);
		}
	} else {
		__s_api_destroy_config(new);
	}

	*change_status = changed;
}

/*
 * Wake up chg_get_statusChange() threads to clean up the threads
 * that main nscd doesn't exist on the other of door anymore or
 * the thread is marked as cleanup.
 */
static void
cleanup_threads(chg_info_t *chg, pid_t pid, cleanup_type_t type)
{
	(void) mutex_lock(&chg->chg_lock);
	if (type == CLEANUP_BY_PID)
		waiting_list_set_cleanup(chg, pid);
	/*
	 * wake up threads without setting chg.chg_wakeup.
	 * It's for cleanup purpose, not for notifying changes.
	 */
	(void) cond_broadcast(&chg->chg_cv);
	(void) mutex_unlock(&chg->chg_lock);
}
/*
 * If arg is NULL, it loops forever,
 * else it calls cleanup_threads once and exits.
 */
void *
chg_cleanup_waiting_threads(void *arg)
{
	cleanup_op_t *op = (cleanup_op_t *)arg;
	cleanup_type_t type = 0;
	pid_t	pid;
	int	always = 1, waiting;

	(void) pthread_setname_np(pthread_self(), "chg_cleanup_thr");

	if (op == NULL) {
		waiting = 1;
		type = CLEANUP_ALL;
		pid = 0;
	} else {
		waiting = 0;
		type = op->type;
		pid = op->pid;
	}

	while (always) {
		if (waiting)
			(void) sleep(CLEANUP_WAIT_TIME);
		cleanup_threads(&chg, pid, type);
		if (!waiting)
			break;
	}

	if (op)
		free(op);

	thr_exit(NULL);
	return (NULL);
}
/*
 * The door server thead which has the door client pid will be marked
 * as to be clean up. If pid is 0, no marking and just clean up all.
 */
static void
cleanup_thread_by_pid(pid_t pid)
{
	cleanup_op_t *op;

	if ((op = malloc(sizeof (cleanup_op_t))) == NULL)
		return;

	op->pid = pid;
	/* clean up all if pid is 0 */
	if (pid == 0)
		op->type = CLEANUP_ALL;
	else
		op->type = CLEANUP_BY_PID;

	if (thr_create(NULL, 0, chg_cleanup_waiting_threads,
	    (void *)op, THR_BOUND|THR_DETACHED, NULL) != 0) {
		free(op);
		logit("thr_create failed for cleanup_thread_by_pid(%ld)\n",
		    pid);
	}
}

/*
 * Output a psinfo of an nscd process with process id pid
 * Return: 0  - Can't find the process or it's not nscd
 *         1  - psinfo found
 * Note: If info is NULL, returns 0 or 1 only and no output from info.
 */
static int
get_nscd_psinfo(pid_t pid, psinfo_t *info)
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
				if (info)
					*info = pinfo;
				return (1);
			}
		}
	}
	return (0);
}
/*
 * If the parent process is nscd and euid is 0, it's a peruser nscd.
 */
static int
is_peruser_nscd(pid_t pid)
{
	pid_t	ppid;
	psinfo_t pinfo;

	if (get_nscd_psinfo(pid, &pinfo)) {
		ppid = pinfo.pr_ppid;
		if (get_nscd_psinfo(ppid, &pinfo) && pinfo.pr_euid == 0)
			/*
			 * get psinfo of parent forker nscd
			 */
			return (1);
		else
			return (0);
	} else {
		return (0);
	}
}
/*
 * Check if the door client making door call is a nscd or peruser nscd and
 * output door client's pid.
 */
int
chg_is_called_from_nscd_or_peruser_nscd(char *dc_str, pid_t *pidp)
{
	int	rc;
	uid_t	euid;
	pid_t	pid;
	ucred_t	*uc = NULL;

	if (door_ucred(&uc) != 0) {
		rc = errno;
		logit("door_ucred() call failed %s\n", strerror(rc));
		return (0);
	}
	euid = ucred_geteuid(uc);
	pid = *pidp = ucred_getpid(uc);

	if ((euid == 0 && is_called_from_nscd(pid)) ||
	    is_peruser_nscd(pid)) {
		if (current_admin.debug_level >= DBG_ALL)
			logit("ldap_cachemgr received %s call from pid %ld, "
			    "uid %u, euid %u\n", dc_str, pid,
			    ucred_getruid(uc), euid);
		rc = 1;
	} else {
		if (current_admin.debug_level >= DBG_CANT_FIND)
			logit("%s call failed(cred): caller pid %ld, uid %u, "
			    "euid %u\n", dc_str, pid,
			    ucred_getruid(uc), euid);

		rc = 0;
	}

	ucred_free(uc);

	return (rc);
}
