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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2018 Joyent Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <synch.h>
#include <thread.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <door.h>
#include <libscf.h>
#include <ucred.h>
#include <sys/varargs.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/proc.h>
#include <procfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libscf.h>
#include <pthread.h>
#include "nscd_door.h"
#include "nscd_config.h"
#include "nscd_log.h"
#include "nscd_frontend.h"
#include "nscd_selfcred.h"
#include "nscd_admin.h"
#include "nscd_common.h"
#include "ns_sldap.h"

extern int	_logfd;
static char	*execpath;
static char	**execargv;
static char	*selfcred_dbs = NULL;

static void *get_smf_prop(const char *var, char type, void *def_val);

/* current self-cred configuration data being used */
static nscd_cfg_global_selfcred_t	nscd_selfcred_cfg_g;

#define	_NSCD_PUN_BLOCK	1024
static uint8_t  pu_nscd_enabled;
static int	max_pu_nscd = _NSCD_PUN_BLOCK;
static int	pu_nscd_ttl;

static nscd_rc_t setup_ldap_backend();
static nscd_rc_t init_user_proc_monitor();

/*
 * clild state
 */
typedef enum {
	CHILD_STATE_NONE	= 0,
	CHILD_STATE_UIDKNOWN,
	CHILD_STATE_FORKSENT,
	CHILD_STATE_PIDKNOWN
} child_state_t;


typedef struct _child {
	int		child_slot;
	int		child_door;
	pid_t		child_pid;
	uid_t		child_uid;
	gid_t		child_gid;
	child_state_t	child_state;
	int		next_open;
	mutex_t		*mutex;
	cond_t		*cond;
} child_t;

static child_t	**child = NULL;
static mutex_t	child_lock = DEFAULTMUTEX;
static int	open_head;
static int	open_tail;
static int	used_slot;

/* nscd door id */
extern int _doorfd;
static pid_t main_uid = 0;

/* nscd id: main, forker, or child */
extern int _whoami;

/* forker nscd pid */
static pid_t forker_pid = 0;
static pid_t forker_uid = 0;

long		activity = 0;
mutex_t		activity_lock = DEFAULTMUTEX;

static int	forking_door = -1;
static mutex_t	forking_lock = DEFAULTMUTEX;

static void
free_slot(int	s)
{
	if (child[s] == NULL)
		return;
	free(child[s]->mutex);
	free(child[s]->cond);
	free(child[s]);
	child[s] = NULL;
}

void
_nscd_free_cslots()
{

	int i;

	(void) mutex_lock(&child_lock);

	for (i = 0; i < max_pu_nscd; i++)
		free_slot(i);

	open_head = -1;
	open_tail = -1;
	used_slot = -1;

	(void) mutex_unlock(&child_lock);

}

static int
init_slot(int	s)
{
	child_t	*ch;
	char	*me = "init_slot";

	if (child[s] == NULL) {
		child[s] = (child_t *)calloc(1, sizeof (child_t));
		if (child[s] == NULL)
			return (-1);
		ch = child[s];

		if ((ch->mutex = (mutex_t *)calloc(1,
		    sizeof (mutex_t))) == NULL) {
			free(ch);
			return (-1);
		}
		(void) mutex_init(ch->mutex, USYNC_THREAD, NULL);

		if ((ch->cond = (cond_t *)calloc(1,
		    sizeof (cond_t))) == NULL) {
			free(ch->mutex);
			free(ch);
			return (-1);
		}
		(void) cond_init(ch->cond, USYNC_THREAD, NULL);

		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "slot %d allocated\n", s);
	} else
		ch = child[s];

	ch->child_slot = s;
	ch->child_door = 0;
	ch->child_state = CHILD_STATE_NONE;
	ch->child_pid = 0;
	ch->child_uid = 0;
	ch->child_gid = 0;
	ch->next_open = -1;

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "slot %d initialized\n", s);

	return (0);
}

static int
_nscd_init_cslots()
{
	(void) mutex_lock(&child_lock);

	child = (child_t **)calloc(max_pu_nscd, sizeof (child_t *));
	if (child == NULL)
		return (-1);

	open_head = -1;
	open_tail = -1;
	used_slot = -1;

	(void) mutex_unlock(&child_lock);

	return (0);
}

static child_t *
get_cslot(
	uid_t		uid,
	int		no_alloc)
{
	int		i;
	child_t		*ch, *ret = NULL;
	char		*me = "get_cslot";

	(void) mutex_lock(&child_lock);

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "looking for uid %d (slot used = %d)\n", uid, used_slot);

	/* first find the slot with a matching uid */
	for (i = 0; i <= used_slot; i++) {
		ch = child[i];
		if (ch->child_state >= CHILD_STATE_UIDKNOWN &&
		    ch->child_uid == uid) {
			ret = ch;
			(void) mutex_unlock(&child_lock);

			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "slot %d found with uid %d\n",
			    ret->child_slot, ret->child_uid);

			return (ret);
		}
	}

	/* if no need to allocate a new slot, return NULL */
	if (no_alloc == 1) {
		(void) mutex_unlock(&child_lock);
		return (ret);
	}

	/* no open slot ? get a new one */
	if (open_head == -1) {
		/* if no slot available, allocate more */
		if (used_slot >= max_pu_nscd - 1) {
			child_t	**tmp;
			int	newmax = max_pu_nscd + _NSCD_PUN_BLOCK;

			tmp = (child_t **)calloc(newmax, sizeof (child_t *));
			if (tmp == NULL) {
				(void) mutex_unlock(&child_lock);
				return (ret);
			}
			(void) memcpy(tmp, child, sizeof (child_t) *
			    max_pu_nscd);
			free(child);
			child = tmp;
			max_pu_nscd = newmax;
		}
		used_slot++;
		if (init_slot(used_slot) == -1) {
			used_slot--;
			(void) mutex_unlock(&child_lock);
			return (ret);
		}
		ch = child[used_slot];
	} else {
		ch = child[open_head];
		open_head = ch->next_open;
		/* got last one ? reset tail */
		if (open_head == -1)
			open_tail = -1;
		ch->next_open = -1;
	}

	ch->child_uid = uid;
	ch->child_state = CHILD_STATE_UIDKNOWN;
	ret = ch;

	(void) mutex_unlock(&child_lock);

	return (ret);
}

static void
return_cslot_nolock(child_t *ch)
{

	int	slot = ch->child_slot;

	/* have open slot ? add to and reset tail */
	if (open_tail != -1) {
		child[open_tail]->next_open = slot;
		open_tail = slot;
	} else {
		/* no open slot ? make one */
		open_head = open_tail = slot;
	}

	(void) init_slot(ch->child_slot);
}

static void
return_cslot(child_t *ch)
{

	char *me = "return_cslot";

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "returning slot %d\n", ch->child_slot);

	/* return if the slot has been returned by another thread */
	if (ch->child_state == CHILD_STATE_NONE)
		return;

	(void) mutex_lock(&child_lock);

	/* check one more time */
	if (ch->child_state == CHILD_STATE_NONE) {
		(void) mutex_unlock(&child_lock);
		return;
	}

	return_cslot_nolock(ch);

	(void) mutex_unlock(&child_lock);
}

static int
selfcred_kill(
	int	fd)
{
	int	ret;
	char	*me = "selfcred_kill";

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "sending kill to door %d\n", fd);

	if (fd != -1)
		ret = _nscd_doorcall_fd(fd, NSCD_KILL, NULL, 0,
		    NULL, 0, NULL);
	else
		ret = _nscd_doorcall(NSCD_KILL);

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "kill request sent to door %d (rc = %d)\n", fd, ret);

	return (ret);
}


void
_nscd_kill_forker()
{
	(void) mutex_lock(&forking_lock);
	if (forking_door != -1)
		(void) selfcred_kill(forking_door);
	forking_door = -1;
	(void) mutex_unlock(&forking_lock);
}

void
_nscd_kill_all_children()
{
	int	i;
	int	ret;
	char	*me = "_nscd_kill_all_children";

	(void) mutex_lock(&child_lock);
	for (i = 0; i <= used_slot; i++) {
		if (child[i] == NULL)
			continue;

		if (child[i]->child_state >= CHILD_STATE_PIDKNOWN) {
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "killing child process %d (doorfd %d)\n",
			    child[i]->child_pid, child[i]->child_door);

			ret = selfcred_kill(child[i]->child_door);

			if (ret != -1)
				(void) kill(child[i]->child_pid, SIGTERM);
		}
		if (child[i]->child_state != CHILD_STATE_NONE)
			(void) return_cslot_nolock(child[i]);
	}
	(void) mutex_unlock(&child_lock);
}
static int
selfcred_pulse(
	int		fd)
{
	int		ret;
	char		*me = "selfcred_pulse";

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "start monitoring door %d\n", fd);

	ret = _nscd_doorcall_fd(fd, NSCD_PULSE |(_whoami & NSCD_WHOAMI),
	    NULL, 0, NULL, 0, NULL);

	/* Close door because the other side exited. */
	(void) close(fd);

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "door (%d) monitor exited (rc = %d)\n", fd, ret);

	return (ret);
}

/*ARGSUSED*/
static void *
forker_monitor(
	void		*arg)
{
	pid_t		fpid;
	char		*fmri;
	char		*me = "forker_monitor";

	(void) pthread_setname_np(pthread_self(), me);

	/* wait until forker exits */
	fpid = forker_pid;
	(void) selfcred_pulse(forking_door);

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "forker (pid = %d) exited or crashed, "
	    "killing all child processes\n", fpid);

	(void) mutex_lock(&forking_lock);
	forking_door = -1;
	forker_pid = -1;
	(void) mutex_unlock(&forking_lock);

	/* forker exited/crashed, kill all the child processes */
	_nscd_kill_all_children();

	/* restart forker */
	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "restarting the forker ...\n");

	switch (fpid = fork1()) {
	case (pid_t)-1:
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "unable to fork and start the forker ...\n");

		/* enter the maintenance mode */
		if ((fmri = getenv("SMF_FMRI")) != NULL) {
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "entering maintenance mode ...\n");
			(void) smf_maintain_instance(fmri, SMF_TEMPORARY);
		}
		return ((void *)1);
	case 0:
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "execv path = %s\n", execpath);

		(void) execv(execpath, execargv);
		exit(0);
	default:
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "new forker's pid is %d\n", fpid);
		forker_pid = fpid;
		break;
	}

	return (NULL);
}

static void *
child_monitor(
	void		*arg)
{
	child_t		*ch = (child_t *)arg;
	pid_t		cpid;
	char		*me = "child_monitor";

	/* wait until child exits */
	cpid = ch->child_pid;
	(void) selfcred_pulse(ch->child_door);

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "child (pid = %d) exited or crashed ...\n", cpid);

	/* return the slot used by the child */
	return_cslot(ch);

	return (NULL);
}


void
_nscd_proc_iamhere(
	void		*buf,
	door_desc_t	*dp,
	uint_t		n_desc,
	int		iam)
{
	int		cslot;
	child_t		*ch;
	int		errnum;
	ucred_t		*uc = NULL;
	uid_t		uid;
	nscd_imhere_t	*ih;
	nss_pheader_t	*phdr = (nss_pheader_t *)buf;
	char		*me = "_nscd_proc_iamhere";


	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "%d receives iamhere from %d\n", _whoami, iam);

	if (door_ucred(&uc) != 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "door_ucred failed: %s\n", strerror(errnum));

		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, errnum,
		    NSCD_DOOR_UCRED_ERROR);
		return;
	}
	uid = ucred_geteuid(uc);

	switch (iam) {

	case NSCD_MAIN:
		if (_whoami == NSCD_MAIN || uid != main_uid) {
			/*
			 * I'm main, or uid from door is not correct,
			 * this must be an imposter
			 */
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "MAIN IMPOSTER CAUGHT!\n");


			NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
			    NSCD_SELF_CRED_MAIN_IMPOSTER);
		}
		break;

	case NSCD_FORKER:
		if (_whoami == NSCD_FORKER || uid != forker_uid) {
			/*
			 * I'm forker, or uid from door is not correct,
			 * this must be an imposter
			 */
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "FORKER IMPOSTER CAUGHT!\n");


			NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
			    NSCD_SELF_CRED_FORKER_IMPOSTER);
			break;
		}

		/* only main needs to know the forker */
		if (_whoami != NSCD_MAIN) {

			NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
			    NSCD_SELF_CRED_WRONG_NSCD);
			break;
		}

		if (ucred_getpid(uc) != forker_pid) {
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "FORKER IMPOSTER CAUGHT: pid = %d should be %d\n",
			    ucred_getpid(uc), forker_pid);


			NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
			    NSCD_SELF_CRED_FORKER_IMPOSTER);
			break;
		}

		if (n_desc < 1) {
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "BAD FORKER, NO DOOR!\n");


			NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
			    NSCD_SELF_CRED_NO_DOOR);
			break;
		}

		if ((dp->d_attributes & DOOR_DESCRIPTOR) &&
		    dp->d_data.d_desc.d_descriptor > 0 &&
		    dp->d_data.d_desc.d_id != 0) {
			(void) mutex_lock(&forking_lock);
			if (forking_door != -1)
				(void) close(forking_door);
			forking_door = dp->d_data.d_desc.d_descriptor;
			(void) mutex_unlock(&forking_lock);

			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "forking door is %d\n", forking_door);

			NSCD_SET_STATUS_SUCCESS(phdr);
		} else {
			NSCD_SET_STATUS(phdr, NSS_ALTRETRY, 0);
			break;
		}

		/* monitor the forker nscd */
		(void) thr_create(NULL, 0, forker_monitor, NULL,
		    THR_DETACHED, NULL);

		break;

	case NSCD_CHILD:
		if (_whoami != NSCD_MAIN) {
			/* child nscd can only talk to the main nscd */
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "CHILD IMPOSTER CAUGHT!\n");

			NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
			    NSCD_SELF_CRED_CHILD_IMPOSTER);
			break;
		}

		/* get the main nscd assigned slot number */
		ih = NSCD_N2N_DOOR_DATA(nscd_imhere_t, buf);
		cslot = ih->slot;
		(void) mutex_lock(&child_lock);
		if (cslot < 0 || cslot >= max_pu_nscd)
			ch = NULL;
		else
			ch = child[cslot];
		(void) mutex_unlock(&child_lock);

		if (ch == NULL) {
			/* Bad slot number */
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "bad slot number %d\n", cslot);

			NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
			    NSCD_SELF_CRED_INVALID_SLOT_NUMBER);
			break;
		}

		if (uid != ch->child_uid) {
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "CHILD IMPOSTER CAUGHT: uid = %d should be %d\n",
		    uid, ch->child_uid);

			NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
			    NSCD_SELF_CRED_CHILD_IMPOSTER);
			break;
		}

		if (ch->child_state != CHILD_STATE_UIDKNOWN &&
		    ch->child_state != CHILD_STATE_FORKSENT) {
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "invalid slot/child state (%d) for uid %d\n",
			    ch->child_state, uid);

			NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
			    NSCD_SELF_CRED_INVALID_SLOT_STATE);
			break;
		}

		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "d_descriptor = %d, d_id = %lld\n",
		    dp->d_data.d_desc.d_descriptor, dp->d_data.d_desc.d_id);

		if ((dp->d_attributes & DOOR_DESCRIPTOR) &&
		    dp->d_data.d_desc.d_descriptor > 0 &&
		    dp->d_data.d_desc.d_id != 0) {
			(void) mutex_lock(ch->mutex);
			if (ch->child_door != -1)
				(void) close(ch->child_door);
			ch->child_door = dp->d_data.d_desc.d_descriptor;
			ch->child_pid  = ucred_getpid(uc);
			ch->child_state  = CHILD_STATE_PIDKNOWN;
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "child in slot %d has door %d\n",
			    cslot, ch->child_door);

			/*
			 * let waiters know that the child is ready to
			 * serve
			 */
			(void) cond_broadcast(ch->cond);
			(void) mutex_unlock(ch->mutex);

			/* monitor the child nscd */
			(void) thr_create(NULL, 0, child_monitor,
			    ch, THR_DETACHED, NULL);
			NSCD_SET_STATUS_SUCCESS(phdr);
			break;
		} else {
			NSCD_SET_STATUS(phdr, NSS_ALTRETRY, 0);
		}
		break;
	}

	ucred_free(uc);
	uc = NULL;
}

void
_nscd_proc_pulse(
	void		*buf,
	int		iam)
{
	long		last_active;
	int		done = 0;
	nss_pheader_t	*phdr = (nss_pheader_t *)buf;
	char		*me = "_nscd_proc_pulse";

	/* only main nscd sends pulse */
	if (iam != NSCD_MAIN) {
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "MAIN IMPOSTER CAUGHT! i am %d not NSCD_MAIN\n", iam);

		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
		    NSCD_SELF_CRED_MAIN_IMPOSTER);
		return;
	}

	/* forker doesn't return stats, it just pauses */
	if (_whoami == NSCD_FORKER) {
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "forker ready to pause ...\n");

		for (;;)
			(void) pause();
	}

	/* remember the current activity sequence number */
	(void) mutex_lock(&activity_lock);
	last_active = activity;
	(void) mutex_unlock(&activity_lock);

	while (!done) {

		/* allow per_user_nscd_ttl seconds of inactivity */
		(void) sleep(pu_nscd_ttl);

		(void) mutex_lock(&activity_lock);
		if (last_active == activity)
			done = 1;
		else {
			last_active = activity;
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "active, sleep again for %d seconds\n",
			    pu_nscd_ttl);
		}
		(void) mutex_unlock(&activity_lock);
	}

	/* no activity in the specified seconds, exit and disconnect */
	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "no activity in the last %d seconds, exit\n", pu_nscd_ttl);
	exit(0);
}

void
_nscd_proc_fork(
	void		*buf,
	int		iam)
{
	int		slot;
	int		ret;
	char		*fmri;
	pid_t		cid;
	uid_t		set2uid;
	gid_t		set2gid;
	nss_pheader_t	*phdr = (nss_pheader_t *)buf;
	char		*me = "_nscd_proc_fork";
	nscd_fork_t	*f;
	nscd_imhere_t	ih;

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "%d receives fork request from %d\n", _whoami, iam);

	/* only main nscd sends fork requests */
	if (iam != NSCD_MAIN) {
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "MAIN IMPOSTER CAUGHT! i am %d not NSCD_MAIN\n", iam);

		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
		    NSCD_SELF_CRED_MAIN_IMPOSTER);
		return;
	}

	/* only forker handles fork requests */
	if (_whoami != NSCD_FORKER) {
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "MAIN IMPOSTER CAUGHT! I AM NOT FORKER!\n");

		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
		    NSCD_SELF_CRED_WRONG_NSCD);
		return;
	}

	/* fork a child for the slot assigned by the main nscd */
	f = NSCD_N2N_DOOR_DATA(nscd_fork_t, buf);
	slot = f->slot;
	/* set the uid/gid as assigned by the main nscd */
	set2uid = f->uid;
	set2gid = f->gid;

	/* ignore bad slot number */
	if (slot < 0 || slot >= max_pu_nscd) {
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "bas slot number\n");

		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
		    NSCD_SELF_CRED_INVALID_SLOT_NUMBER);
		return;
	}

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "before fork1() ...\n");

	if ((cid = fork1()) == 0) {
		_whoami = NSCD_CHILD;

		/*
		 * remember when this child nscd starts
		 * (replace the forker start time)
		 */
		_nscd_set_start_time(1);

		/* close all except the log file */
		if (_logfd > 0) {
			int i;
			for (i = 0; i < _logfd; i++)
				(void) close(i);
			closefrom(_logfd + 1);
		} else
			closefrom(0);

		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "child %d\n", getpid());

		(void) setgid(set2gid);
		(void) setuid(set2uid);

		/* set up the door and server thread pool */
		if ((_doorfd = _nscd_setup_child_server(_doorfd)) == -1)
			exit(-1);

		/* tell libsldap to do self cred only */
		(void) setup_ldap_backend();

		/* notify main that child is active */
		ih.slot = slot;
		for (ret = NSS_ALTRETRY; ret == NSS_ALTRETRY; )
			ret = _nscd_doorcall_sendfd(_doorfd,
			    NSCD_IMHERE | (NSCD_CHILD & NSCD_WHOAMI),
			    &ih, sizeof (ih), NULL);

		NSCD_SET_STATUS_SUCCESS(phdr);
		return;
	} if (cid  == (pid_t)-1) {
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "forker unable to fork ...\n");

		/* enter the maintenance mode */
		if ((fmri = getenv("SMF_FMRI")) != NULL) {
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
			(me, "entering maintenance mode ...\n");
			(void) smf_maintain_instance(fmri, SMF_TEMPORARY);
		}
		exit(0);
	} else {
		/*
		 * start the monitor so as to exit as early as
		 * possible if no other processes are running
		 * with the same PUN uid (i.e., this PUN is
		 * not needed any more)
		 */
		(void) init_user_proc_monitor();

		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "child forked:  parent pid = %d, child pid = %d\n",
		    getpid(), cid);

		NSCD_SET_STATUS_SUCCESS(phdr);
	}

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "after fork\n");
}

static void
selfcred_fork(
	void		*buf,
	int		doorfd,
	int		cslot,
	uid_t		uid,
	gid_t		gid)
{
	int		ret;
	nscd_fork_t	f;
	nss_pheader_t	*phdr = (nss_pheader_t *)buf;
	char		*me = "selfcred_fork";

	/* if no door fd, do nothing */
	if (doorfd == -1) {
		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
		    NSCD_SELF_CRED_NO_DOOR);
	}

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "sending fork request to door %d for slot %d "
	    "(uid = %d, gid = %d)\n", doorfd, cslot, uid, gid);

	f.slot = cslot;
	f.uid = uid;
	f.gid = gid;

	ret = _nscd_doorcall_fd(doorfd, NSCD_FORK|(_whoami&NSCD_WHOAMI),
	    &f, sizeof (f), NULL, 0, phdr);

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "fork request sent to door %d for slot %d (rc = %d)\n",
	    doorfd, cslot, ret);

	if (NSCD_STATUS_IS_NOT_OK(phdr)) {

		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "fork request sent to door %d for slot %d failed: "
		    "status = %d, errno = %s, nscd status = %d\n", doorfd,
		    cslot, NSCD_GET_STATUS(phdr),
		    strerror(NSCD_GET_ERRNO(phdr)),
		    NSCD_GET_NSCD_STATUS(phdr));

	}
}

void
_nscd_proc_alt_get(
	void		*buf,
	int		*door)
{
	int		errnum;
	uid_t		set2uid;
	gid_t		set2gid;
	nss_pheader_t	*phdr = (nss_pheader_t *)buf;
	char		*me = "_nscd_proc_alt_get";
	ucred_t		*uc = NULL;
	child_t		*ch;

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "getting an alternate door ...\n");

	/* make sure there is a door to talk to the forker */
	if (forking_door == -1) {
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_ERROR)
		(me, "no door to talk to the forker\n");

		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
		    NSCD_SELF_CRED_NO_FORKER);
		return;
	}

	/* get door client's credential information */
	if (door_ucred(&uc) != 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "door_ucred failed: %s\n", strerror(errnum));

		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, errnum,
		    NSCD_DOOR_UCRED_ERROR);
		return;
	}

	/* get door client's effective uid and effective gid */
	set2uid = ucred_geteuid(uc);
	set2gid = ucred_getegid(uc);
	ucred_free(uc);
	uc = NULL;

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "child uid = %d, gid = %d\n", set2uid, set2gid);

	/* is a slot available ? if not, no one to serve */
	if (child == NULL || (ch = get_cslot(set2uid, 0)) == NULL) {

		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "no child slot available (child array = %p, slot = %d)\n",
		    child, ch->child_slot);

		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
		    NSCD_SELF_CRED_NO_CHILD_SLOT);
		return;
	}

	/* create the per user nscd if necessary */
	if (ch->child_state != CHILD_STATE_PIDKNOWN) {

		nss_pheader_t	phdr1;
		NSCD_CLEAR_STATUS(&phdr1);

		(void) mutex_lock(ch->mutex);
		if (ch->child_state == CHILD_STATE_UIDKNOWN) {

			/* ask forker to fork a new child */
			selfcred_fork(&phdr1, forking_door, ch->child_slot,
			    set2uid, set2gid);
			if (NSCD_STATUS_IS_NOT_OK(&phdr1)) {
				(void) mutex_unlock(ch->mutex);
				NSCD_COPY_STATUS(phdr, &phdr1);
				return;
			}
			ch->child_state = CHILD_STATE_FORKSENT;
		}

		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "waiting for door (slot = %d, uid = %d, gid = %d)\n",
		    ch->child_slot, set2uid, set2gid);

		/* wait for the per user nscd to become available */
		while (ch->child_state == CHILD_STATE_FORKSENT) {
			timestruc_t to;
			int err;
			int ttl = 5;

			to.tv_sec = ttl;
			to.tv_nsec = 0;
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
				(me, "cond_reltimedwait %d seconds\n", ttl);
			err = cond_reltimedwait(ch->cond, ch->mutex, &to);
			if (err == ETIME) {
				ch->child_state = CHILD_STATE_UIDKNOWN;
				_NSCD_LOG(NSCD_LOG_SELF_CRED,
				    NSCD_LOG_LEVEL_DEBUG)
				(me, "door wait timedout (slot = %d)\n",
				    ch->child_slot);
				break;
			}
		}
		(void) mutex_unlock(ch->mutex);
	}

	if (ch->child_state != CHILD_STATE_PIDKNOWN) {

		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
		    NSCD_SELF_CRED_INVALID_SLOT_STATE);
		return;
	}

	*door = ch->child_door;

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "returning door %d for slot %d, uid %d, gid = %d\n",
	    *door, ch->child_slot, set2uid, set2gid);

	NSCD_SET_STATUS(phdr, NSS_ALTRETRY, 0);
}

static char **
cpargv(
	int	argc,
	char	**inargv)
{
	char	**newargv;
	int	c = 4;
	int	i = 0, j, k = 0, n = 0;

	newargv = (char **)calloc(c + 1, sizeof (char *));
	if (newargv == NULL)
		return (NULL);

	newargv[n] = strdup(inargv[0]);
	if (newargv[n++] == NULL) {
		free(newargv);
		return (NULL);
	}

	newargv[n] = strdup("-F");
	if (newargv[n++] == NULL) {
		free(newargv[0]);
		free(newargv);
		return (NULL);
	}

	for (i = 1; i < argc; i++) {
		if (strcmp(inargv[i], "-f") == 0)
			k = 2;
		if (k  == 0)
			continue;

		newargv[n] = strdup(inargv[i]);
		if (newargv[n] == NULL) {
			for (j = 0; j < n; j++)
				free(newargv[j]);
			free(newargv);
			return (NULL);
		}

		k--;
		n++;
	}
	return (newargv);
}


void
_nscd_start_forker(
	char	*path,
	int	argc,
	char	**argv)
{
	pid_t	cid;

	/* if self cred is not configured, do nothing */
	if (!_nscd_is_self_cred_on(1, NULL))
		return;

	/* save pathname and generate the new argv for the forker */
	execpath = strdup(path);
	execargv = cpargv(argc, argv);
	if (execpath == NULL || execargv == NULL)
		exit(1);

	switch (cid = fork1()) {
		case (pid_t)-1:
			exit(1);
			break;
		case 0:
			/* start the forker nscd */
			(void) execv(path, execargv);
			exit(0);
			break;
		default:
			/* main nscd */
			/* remember process id of the forker */
			forker_pid = cid;

			/* enable child nscd management */
			(void) _nscd_init_cslots();
			break;
	}
}

static nscd_rc_t
get_ldap_funcs(
	char			*name,
	void			**func_p)
{
	char			*me = "get_ldap_funcs";
	static void		*handle = NULL;
	void			*sym;

	if (name == NULL && handle != NULL) {
		(void) dlclose(handle);
		return (NSCD_SUCCESS);
	}
	/* no handle to close, it's OK */
	if (name == NULL)
		return (NSCD_SUCCESS);

	if (handle == NULL) {
		handle = dlopen("libsldap.so.1", RTLD_LAZY);
		if (handle == NULL) {

			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to dlopen libsldap.so.1");
			return (NSCD_CFG_DLOPEN_ERROR);
		}
	}

	if ((sym = dlsym(handle, name)) == NULL) {

			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to find symbol %s", name);
			return (NSCD_CFG_DLSYM_ERROR);
	} else
		(void) memcpy(func_p, &sym, sizeof (void *));

	return (NSCD_SUCCESS);
}


int
_nscd_is_self_cred_on(int recheck, char **dblist)
{
	static int	checked = 0;
	static int	is_on = 0;
	static int	(*ldap_func)();
	char		*srcs = "ldap"; /* only ldap support self cred */
	int		ldap_on = 0;

	char		*ldap_sc_func = "__ns_ldap_self_gssapi_config";
	ns_ldap_self_gssapi_config_t ldap_config;

	if (checked && !recheck) {
		if (is_on && dblist != NULL)
			*dblist = selfcred_dbs;
		return (is_on);
	}

	if (selfcred_dbs != NULL)
		free(selfcred_dbs);
	selfcred_dbs = _nscd_srcs_in_db_nsw_policy(1, &srcs);

	if (selfcred_dbs == NULL) {
		is_on =  0;
		checked = 1;
		return (0);
	}

	/*
	 * also check the ldap backend to see if
	 * the configuration there is good for
	 * doing self credentialing
	 */
	if (ldap_func == NULL)
		(void) get_ldap_funcs(ldap_sc_func, (void **)&ldap_func);
	if (ldap_func != NULL) {
		if (ldap_func(&ldap_config) == NS_LDAP_SUCCESS &&
		    ldap_config != NS_LDAP_SELF_GSSAPI_CONFIG_NONE)
			ldap_on = 1;
	}

	is_on = (pu_nscd_enabled == nscd_true) && ldap_on;

	checked = 1;

	if (is_on && dblist != NULL)
		*dblist = selfcred_dbs;

	return (is_on);
}

static nscd_rc_t
setup_ldap_backend()
{
	nscd_rc_t	rc;
	static void	(*ldap_func)();
	char		*ldap_sc_func = "__ns_ldap_self_gssapi_only_set";
	if (ldap_func == NULL)
		rc = get_ldap_funcs(ldap_sc_func, (void **)&ldap_func);
	if (ldap_func != NULL) {
		ldap_func(1);
		return (NSCD_SUCCESS);
	}
	return (rc);
}

/*ARGSUSED*/
void
_nscd_peruser_getadmin(
	void		*buf,
	int		buf_size)
{
	void		*result_mn = NSCD_N2N_DOOR_DATA(void, buf);
	int		errnum = 0;
	int		ret;
	uid_t		uid;
	nss_pheader_t	*phdr = (nss_pheader_t *)buf;
	char		*me = "_nscd_peruser_getadmin";
	ucred_t		*uc = NULL;
	child_t		*ch;

	/* get door client's credential information */
	if (door_ucred(&uc) != 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "door_ucred failed: %s\n", strerror(errnum));

		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, errnum,
		    NSCD_DOOR_UCRED_ERROR);
		return;
	}

	/* get door client's effective uid */
	uid = ucred_geteuid(uc);
	ucred_free(uc);
	uc = NULL;

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "per user get admin ... (uid = %d)\n", uid);

	/* is the per-user nscd running ? if not, no one to serve */
	ch = get_cslot(uid, 1);
	if (ch == NULL) {
		NSCD_SET_N2N_STATUS(phdr, NSS_NSCD_PRIV, 0,
		    NSCD_SELF_CRED_NO_CHILD_SLOT);
		return;
	}

	ret = _nscd_doorcall_fd(ch->child_door, NSCD_GETADMIN,
	    NULL, sizeof (nscd_admin_t), result_mn,
	    sizeof (nscd_admin_t), phdr);

	if (ret == NSS_SUCCESS) {
		phdr->data_len = sizeof (nscd_admin_t);
		return;
	}
}

static void
set_selfcred_cfg(
	char	param,
	void	*data)
{
	int64_t	prop_int;
	uint8_t prop_boolean;
	char	*me = "set_selfcred_cfg";

	if (param == 'e') {
		prop_boolean = *(uint8_t *)data;
		pu_nscd_enabled = *(uint8_t *)get_smf_prop(
		    "enable_per_user_lookup", 'b', &prop_boolean);

		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "self cred config: enabled = %d\n", pu_nscd_enabled);
	}

	if (param == 't') {
		prop_int = *(int *)data;
		pu_nscd_ttl = *(int64_t *)get_smf_prop(
		    "per_user_nscd_time_to_live", 'i', &prop_int);

		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
		(me, "self cred config: PUN TTL = %d\n", pu_nscd_ttl);
	}
}

/* ARGSUSED */
nscd_rc_t
_nscd_cfg_selfcred_notify(
	void				*data,
	struct nscd_cfg_param_desc	*pdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			dflag,
	nscd_cfg_error_t		**errorp,
	void				*cookie)
{

	nscd_cfg_global_selfcred_t	*sc_cfg = &nscd_selfcred_cfg_g;
	int				off;

	/*
	 * At init time, the whole group of config params are received.
	 * At update time, group or individual parameter value could
	 * be received.
	 */

	if (_nscd_cfg_flag_is_set(dflag, NSCD_CFG_DFLAG_GROUP)) {

		*sc_cfg = *(nscd_cfg_global_selfcred_t *)data;

		off = offsetof(nscd_cfg_global_selfcred_t,
		    enable_selfcred);
		set_selfcred_cfg('e', (char *)data + off);

		off = offsetof(nscd_cfg_global_selfcred_t,
		    per_user_nscd_ttl);
		set_selfcred_cfg('t', (char *)data + off);

		return (NSCD_SUCCESS);
	}

	/*
	 * individual config parameter
	 */
	off = offsetof(nscd_cfg_global_selfcred_t, enable_selfcred);
	if (pdesc->p_offset == off) {
		sc_cfg->enable_selfcred = *(nscd_bool_t *)data;
		set_selfcred_cfg('e', data);
		return (NSCD_SUCCESS);
	}

	off = offsetof(nscd_cfg_global_selfcred_t, per_user_nscd_ttl);
	if (pdesc->p_offset == off) {
		sc_cfg->per_user_nscd_ttl = *(int *)data;
		set_selfcred_cfg('t', data);
		return (NSCD_SUCCESS);
	}

	return (NSCD_SUCCESS);
}

/* ARGSUSED */
nscd_rc_t
_nscd_cfg_selfcred_verify(
	void				*data,
	struct	nscd_cfg_param_desc	*pdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			dflag,
	nscd_cfg_error_t		**errorp,
	void				**cookie)
{

	return (NSCD_SUCCESS);
}

/* ARGSUSED */
nscd_rc_t
_nscd_cfg_selfcred_get_stat(
	void				**stat,
	struct nscd_cfg_stat_desc	*sdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			*dflag,
	void				(**free_stat)(void *stat),
	nscd_cfg_error_t		**errorp)
{
	return (NSCD_SUCCESS);
}

static int
check_uid(char *pid_name)
{
	char		pname[PATH_MAX];
	static pid_t	pid = 0;
	static uid_t	uid = 0;
	static uid_t	euid = 0;
	int		pfd; /* file descriptor for /proc/<pid>/psinfo */
	psinfo_t	info;  /* process information from /proc */

	if (uid == 0)  {
		pid = getpid();
		uid = getuid();
		euid = geteuid();
	}

	(void) snprintf(pname, sizeof (pname), "/proc/%s/psinfo", pid_name);
retry:
	if ((pfd = open(pname, O_RDONLY)) == -1) {
		/* Process may have exited */
			return (1);
	}

	/*
	 * Get the info structure for the process and close quickly.
	 */
	if (read(pfd, (char *)&info, sizeof (info)) < 0) {
		int	saverr = errno;

		(void) close(pfd);
		if (saverr == EAGAIN)
			goto retry;
		if (saverr != ENOENT)
			return (1);
	}
	(void) close(pfd);

	if (info.pr_pid != pid &&
	    info.pr_uid == uid && info.pr_euid == euid)
		return (0);
	else
		return (1);
}


/*
 * FUNCTION: check_user_process
 */
/*ARGSUSED*/
static void *
check_user_process(void *arg)
{

	DIR		*dp;
	struct dirent	*ep;
	int		found;
	char		*me = "check_user_process";

	(void) pthread_setname_np(pthread_self(), me);

	for (;;) {
		(void) sleep(60);

		found = 0;

		/*
		 * search the /proc directory and look at each process
		 */
		if ((dp = opendir("/proc")) == NULL) {
			_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_ERROR)
			(me, "unable to open the /proc directory\n");
			continue;
		}

		/* for each active process */
		while (ep = readdir(dp)) {
			if (ep->d_name[0] == '.')    /* skip . and .. */
				continue;
			if (check_uid(ep->d_name) == 0) {
				found = 1;
				break;
			}
		}

		/*
		 * if no process running as the PUN uid found, exit
		 * to kill this PUN
		 */
		if (found == 0) {
			(void) closedir(dp);
			exit(1);
		}
		(void) closedir(dp);
	}
	/*LINTED E_FUNC_HAS_NO_RETURN_STMT*/
}

static nscd_rc_t
init_user_proc_monitor() {

	int	errnum;
	char	*me = "init_user_proc_monitor";

	_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_DEBUG)
	(me, "initializing the user process monitor\n");

	/*
	 * start a thread to make sure there is at least a process
	 * running as the PUN user. If not, terminate this PUN.
	 */
	if (thr_create(NULL, NULL, check_user_process,
		NULL, THR_DETACHED, NULL) != 0) {
		errnum = errno;
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_ERROR)
		(me, "thr_create: %s\n", strerror(errnum));
		return (NSCD_THREAD_CREATE_ERROR);
	}

	return (NSCD_SUCCESS);
}

static void *
get_smf_prop(const char *var, char type, void *def_val)
{
	scf_simple_prop_t	*prop;
	void			*val;
	char			*me = "get_smf_prop";

	prop = scf_simple_prop_get(NULL, NULL, "config", var);
	if (prop) {
		switch (type) {
		case 'b':
			val = scf_simple_prop_next_boolean(prop);
			if (val != NULL)
				(void) memcpy(def_val, val, sizeof (uint8_t));
			break;

		case 'i':
			val = scf_simple_prop_next_integer(prop);
			if (val != NULL)
				(void) memcpy(def_val, val, sizeof (int64_t));
			break;
		}
		scf_simple_prop_free(prop);
	}

	if (prop == NULL || val == NULL) {
		char	vs[64];

		switch (type) {
		case 'b':
			if (*(uint8_t *)def_val)
				(void) strcpy(vs, "yes");
			else
				(void) strcpy(vs, "no");

			break;

		case 'i':
			(void) sprintf(vs, "%lld", *(int64_t *)def_val);
			break;

		}
		_NSCD_LOG(NSCD_LOG_SELF_CRED, NSCD_LOG_LEVEL_ALERT)
		(me, "no value for config/%s (%s). "
		    "Using default \"%s\"\n", var,
		    scf_strerror(scf_error()), vs);
	}

	return (def_val);
}
