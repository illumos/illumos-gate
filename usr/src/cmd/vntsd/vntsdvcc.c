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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Configuration and setup interface to vcc driver.
 * At intialization time, vntsd opens vcc ctrl port and read initial
 * configuratioa. It manages console groups, creates the listen thread,
 * dynamically adds and removes virtual console within a group.
 */


#include <syslog.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <wait.h>
#include <time.h>
#include <synch.h>
#include <netinet/in.h>
#include <thread.h>
#include <signal.h>
#include "vntsd.h"

/* signal all clients that console has been deleted */
boolean_t
vntsd_notify_client_cons_del(vntsd_client_t *clientp)
{
	(void) mutex_lock(&clientp->lock);
	clientp->status |= VNTSD_CLIENT_CONS_DELETED;
	(void) thr_kill(clientp->cons_tid, SIGUSR1);
	(void) mutex_unlock(&clientp->lock);
	return (B_FALSE);
}

/* free console  structure */
static void
free_cons(vntsd_cons_t *consp)
{
	assert(consp);
	(void) mutex_destroy(&consp->lock);
	(void) cond_destroy(&consp->cvp);
	if (consp->vcc_fd != -1)
		(void) close(consp->vcc_fd);
	free(consp);
}

/* free group structure */
static void
free_group(vntsd_group_t *groupp)
{
	assert(groupp);
	(void) mutex_destroy(&groupp->lock);
	(void) cond_destroy(&groupp->cvp);
	if (groupp->sockfd != -1)
		(void) close(groupp->sockfd);
	free(groupp);
}

/*
 *  all clients connected to a console must disconnect before
 *  removing a console.
 */
static void
cleanup_cons(vntsd_cons_t *consp)
{
	vntsd_group_t	*groupp;
	timestruc_t	to;

	assert(consp);
	D1(stderr, "t@%d vntsd_disconn_clients@%d\n", thr_self(),
	    consp->cons_no);

	groupp = consp->group;
	assert(groupp);


	(void) mutex_lock(&consp->lock);

	/* wait for all clients disconnect from the console */
	while (consp->clientpq != NULL) {
		consp->status |= VNTSD_CONS_SIG_WAIT;

		/* signal client to disconnect the console */
		(void) vntsd_que_walk(consp->clientpq,
		    (el_func_t)vntsd_notify_client_cons_del);

		(void) thr_kill(consp->wr_tid, SIGUSR1);
		to.tv_sec = VNTSD_CV_WAIT_DELTIME;
		to.tv_nsec = 0;

		/* wait for clients to disconnect  */
		(void) cond_reltimedwait(&consp->cvp, &consp->lock, &to);
	}

	/* reduce console count in the group */
	(void) mutex_lock(&groupp->lock);
	assert(groupp->num_cons > 0);
	groupp->num_cons--;
	(void) mutex_unlock(&groupp->lock);

	(void) mutex_unlock(&consp->lock);

	free_cons(consp);
}

/* search for a group whose console is being deleted */
static boolean_t
find_clean_cons_group(vntsd_group_t *groupp)
{
	if (groupp->status & VNTSD_GROUP_CLEAN_CONS) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

/* search for a console that is being deleted */
static boolean_t
find_clean_cons(vntsd_cons_t *consp)
{
	if (consp->status & VNTSD_CONS_DELETED) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

/* delete a console */
void
vntsd_delete_cons(vntsd_t *vntsdp)
{
	vntsd_group_t *groupp;
	vntsd_cons_t *consp;

	for (; ; ) {
		/* get the group contains deleted console */
		(void) mutex_lock(&vntsdp->lock);
		groupp = vntsd_que_walk(vntsdp->grouppq,
		    (el_func_t)find_clean_cons_group);
		if (groupp == NULL) {
			/* no more group has console deleted */
			(void) mutex_unlock(&vntsdp->lock);
			return;
		}
		(void) mutex_lock(&groupp->lock);
		groupp->status &= ~VNTSD_GROUP_CLEAN_CONS;
		(void) mutex_unlock(&groupp->lock);
		(void) mutex_unlock(&vntsdp->lock);

		for (; ; ) {
			/* get the console to be deleted */
			(void) mutex_lock(&groupp->lock);

			/* clean up any deleted console in the group */
			if (groupp->conspq != NULL) {
				consp = vntsd_que_walk(groupp->conspq,
				    (el_func_t)find_clean_cons);
				if (consp == NULL) {
					/* no more cons to delete */
					(void) mutex_unlock(&groupp->lock);
					break;
				}

				/* remove console from the group */
				(void) vntsd_que_rm(&groupp->conspq, consp);
				(void) mutex_unlock(&groupp->lock);

				/* clean up the console */
				cleanup_cons(consp);
			}

			/* delete group? */
			if (groupp->conspq == NULL) {
				/* no more console in the group delete group */
				assert(groupp->vntsd);

				(void) mutex_lock(&groupp->vntsd->lock);
				(void) vntsd_que_rm(&groupp->vntsd->grouppq,
				    groupp);
				(void) mutex_unlock(&groupp->vntsd->lock);

				/* clean up the group */
				vntsd_clean_group(groupp);
				break;
			}
		}
	}
}

/* clean up a group */
void
vntsd_clean_group(vntsd_group_t *groupp)
{

	timestruc_t	to;

	D1(stderr, "t@%d clean_group() group=%s tcp=%lld\n", thr_self(),
	    groupp->group_name, groupp->tcp_port);

	(void) mutex_lock(&groupp->lock);

	/* prevent from reentry */
	if (groupp->status & VNTSD_GROUP_IN_CLEANUP) {
		(void) mutex_unlock(&groupp->lock);
		return;
	}
	groupp->status |= VNTSD_GROUP_IN_CLEANUP;

	/* mark group waiting for listen thread to exits */
	groupp->status |= VNTSD_GROUP_SIG_WAIT;
	(void) mutex_unlock(&groupp->lock);

	vntsd_free_que(&groupp->conspq, (clean_func_t)cleanup_cons);

	(void) mutex_lock(&groupp->lock);
	/* walk through no cons client queue */
	while (groupp->no_cons_clientpq != NULL) {
		(void) vntsd_que_walk(groupp->no_cons_clientpq,
		    (el_func_t)vntsd_notify_client_cons_del);
		to.tv_sec = VNTSD_CV_WAIT_DELTIME;
		to.tv_nsec = 0;
		(void) cond_reltimedwait(&groupp->cvp, &groupp->lock, &to);
	}

	/* waiting for listen thread to exit */
	while (groupp->status & VNTSD_GROUP_SIG_WAIT) {
		/* signal listen thread to exit  */
		(void) thr_kill(groupp->listen_tid, SIGUSR1);
		to.tv_sec = VNTSD_CV_WAIT_DELTIME;
		to.tv_nsec = 0;
		/* wait listen thread to exit  */
		(void) cond_reltimedwait(&groupp->cvp, &groupp->lock, &to);
	}

	(void) mutex_unlock(&groupp->lock);
	(void) thr_join(groupp->listen_tid, NULL, NULL);
	/* free group */
	free_group(groupp);
}

/* allocate and initialize console structure */
static vntsd_cons_t *
alloc_cons(vntsd_group_t *groupp, vcc_console_t *consolep)
{
	vntsd_cons_t *consp;
	int	rv;

	/* allocate console */
	consp = (vntsd_cons_t *)malloc(sizeof (vntsd_cons_t));
	if (consp == NULL) {
		vntsd_log(VNTSD_ERR_NO_MEM, "alloc_cons");
		return (NULL);
	}

	/* intialize console */
	bzero(consp, sizeof (vntsd_cons_t));

	(void) mutex_init(&consp->lock, USYNC_THREAD|LOCK_ERRORCHECK, NULL);
	(void) cond_init(&consp->cvp, USYNC_THREAD, NULL);

	consp->cons_no = consolep->cons_no;
	(void) strlcpy(consp->domain_name, consolep->domain_name, MAXPATHLEN);
	(void) strlcpy(consp->dev_name, consolep->dev_name, MAXPATHLEN);
	consp->wr_tid = (thread_t)-1;
	consp->vcc_fd = -1;

	/* join the group */
	(void) mutex_lock(&groupp->lock);

	if ((rv = vntsd_que_append(&groupp->conspq, consp)) !=
	    VNTSD_SUCCESS) {
		(void) mutex_unlock(&groupp->lock);
		vntsd_log(rv, "alloc_cons");
		free_cons(consp);
		return (NULL);
	}
	groupp->num_cons++;
	consp->group = groupp;

	(void) mutex_unlock(&groupp->lock);

	D1(stderr, "t@%d alloc_cons@%d %s %s\n", thr_self(),
	    consp->cons_no, consp->domain_name, consp->dev_name);

	return (consp);
}

/* compare tcp with group->tcp */
static boolean_t
grp_by_tcp(vntsd_group_t *groupp, uint64_t *tcp_port)
{
	assert(groupp);
	assert(tcp_port);
	return (groupp->tcp_port == *tcp_port);
}

/* allocate and initialize group */
static vntsd_group_t *
alloc_group(vntsd_t *vntsdp, char *group_name, uint64_t tcp_port)
{
	vntsd_group_t *groupp;

	/* allocate group */
	groupp = (vntsd_group_t *)malloc(sizeof (vntsd_group_t));
	if (groupp == NULL) {
		vntsd_log(VNTSD_ERR_NO_MEM, "alloc_group");
		return (NULL);
	}

	/* initialize group */
	bzero(groupp, sizeof (vntsd_group_t));

	(void) mutex_init(&groupp->lock, USYNC_THREAD|LOCK_ERRORCHECK, NULL);
	(void) cond_init(&groupp->cvp, USYNC_THREAD, NULL);

	if (group_name != NULL) {
		(void) memcpy(groupp->group_name, group_name, MAXPATHLEN);
	}

	groupp->tcp_port = tcp_port;
	groupp->listen_tid = (thread_t)-1;
	groupp->sockfd = -1;
	groupp->vntsd = vntsdp;

	D1(stderr, "t@%d alloc_group@%lld:%s\n", thr_self(), groupp->tcp_port,
	    groupp->group_name);

	return (groupp);
}

/* mark a deleted console */
boolean_t
vntsd_mark_deleted_cons(vntsd_cons_t *consp)
{
	(void) mutex_lock(&consp->lock);
	consp->status |= VNTSD_CONS_DELETED;
	(void) mutex_unlock(&consp->lock);
	return (B_FALSE);
}

/*
 * Initialize a console, if console is associated with with a
 * new group, intialize the group.
 */
static int
alloc_cons_with_group(vntsd_t *vntsdp, vcc_console_t *consp,
    vntsd_group_t **new_groupp)
{
	vntsd_group_t	*groupp = NULL;
	int		rv;

	*new_groupp = NULL;

	/* match group by tcp port */


	(void) mutex_lock(&vntsdp->lock);
	groupp = vntsd_que_find(vntsdp->grouppq,
	    (compare_func_t)grp_by_tcp, (void *)&(consp->tcp_port));
	if (groupp != NULL)
		(void) mutex_lock(&groupp->lock);

	(void) mutex_unlock(&vntsdp->lock);

	if (groupp != NULL) {
		/*
		 *  group with same tcp port found.
		 *  if there is no console in the group, the
		 *  group should be removed and the tcp port can
		 *  be used for tne new group.
		 *  This is possible, when there is tight loop of
		 *  creating/deleting domains. When a vcc port is
		 *  removed, a read thread will have an I/O error because
		 *  vcc has closed the port. The read thread then marks
		 *  the console is removed and notify main thread to
		 *  remove the console.
		 *  Meanwhile, the same port and its group (with same
		 *  tcp port and group name) is created. Vcc notify
		 *  vntsd that new console is added.
		 *  Main thread now have two events. If main thread polls
		 *  out vcc notification first, it will find that there is
		 *  a group has no console.
		 */

		if (vntsd_chk_group_total_cons(groupp) == 0) {

			/* all consoles in the group have been removed */
			(void) vntsd_que_walk(groupp->conspq,
			    (el_func_t)vntsd_mark_deleted_cons);
			groupp->status |= VNTSD_GROUP_CLEAN_CONS;
			(void) mutex_unlock(&groupp->lock);
			groupp = NULL;

		} else if (strcmp(groupp->group_name, consp->group_name)) {
			/* conflict group name */
			vntsd_log(VNTSD_ERR_VCC_GRP_NAME,
			    "group name is different from existing group");
			(void) mutex_unlock(&groupp->lock);
			return (VNTSD_ERR_VCC_CTRL_DATA);

		} else {
			/* group already existed */
			(void) mutex_unlock(&groupp->lock);
		}

	}

	if (groupp == NULL) {
		/* new group */
		groupp = alloc_group(vntsdp, consp->group_name,
		    consp->tcp_port);
		if (groupp == NULL) {
			return (VNTSD_ERR_NO_MEM);
		}

		assert(groupp->conspq == NULL);
		/* queue group to vntsdp */
		(void) mutex_lock(&vntsdp->lock);
		rv = vntsd_que_append(&vntsdp->grouppq, groupp);
		(void) mutex_unlock(&vntsdp->lock);

		if (rv != VNTSD_SUCCESS) {
			return (rv);
		}

		*new_groupp = groupp;
	}

	/* intialize console */
	if (alloc_cons(groupp, consp) == NULL) {
		/* no memory */
		if (*new_groupp != NULL) {
			/* clean up new group */
			free_group(groupp);
		}

		return (VNTSD_ERR_NO_MEM);
	}

	return (VNTSD_SUCCESS);

}


/* create listen thread */
static boolean_t
create_listen_thread(vntsd_group_t *groupp)
{

	char err_msg[VNTSD_LINE_LEN];
	int rv;

	assert(groupp);

	(void) mutex_lock(&groupp->lock);
	assert(groupp->num_cons);

	D1(stderr, "t@%d create_listen:%lld\n", thr_self(), groupp->tcp_port);

	if ((rv = thr_create(NULL, 0, (thr_func_t)vntsd_listen_thread,
	    (void *)groupp, THR_DETACHED, &groupp->listen_tid)) != 0) {
		(void) (void) snprintf(err_msg, sizeof (err_msg),
		    "Can not create listen thread for"
		    "group %s tcp %llx\n", groupp->group_name,
		    groupp->tcp_port);
		vntsd_log(VNTSD_ERR_CREATE_LISTEN_THR, err_msg);

		/* clean up group queue */
		vntsd_free_que(&groupp->conspq, (clean_func_t)free_cons);
		groupp->listen_tid = (thread_t)-1;
	}

	(void) mutex_unlock(&groupp->lock);

	return (rv != 0);
}

/* find deleted console by console no */
static boolean_t
deleted_cons_by_consno(vntsd_cons_t *consp, int *cons_no)
{
	vntsd_client_t *clientp;

	assert(consp);

	if (consp->cons_no != *cons_no)
		return (B_FALSE);

	/* has console marked as deleted? */
	if ((consp->status & VNTSD_CONS_DELETED) == 0)
		return (B_TRUE);

	if (consp->clientpq == NULL)
		/* there is no client for this console */
		return (B_TRUE);

	/* need to notify clients of console ? */
	clientp = (vntsd_client_t *)consp->clientpq->handle;

	if (clientp->status & VNTSD_CLIENT_CONS_DELETED)
		/* clients of console have notified */
		return (B_FALSE);

	return (B_TRUE);
}

/* find group structure from console no */
static boolean_t
find_cons_group_by_cons_no(vntsd_group_t *groupp, uint_t *cons_no)
{
	vntsd_cons_t *consp;

	consp = vntsd_que_find(groupp->conspq,
	    (compare_func_t)deleted_cons_by_consno, cons_no);
	return (consp != NULL);

}

/* delete a console if the console exists in the vntsd */
static void
delete_cons_before_add(vntsd_t *vntsdp, uint_t cons_no)
{
	vntsd_group_t	    *groupp;
	vntsd_cons_t	    *consp;

	/* group exists? */
	(void) mutex_lock(&vntsdp->lock);
	groupp = vntsd_que_find(vntsdp->grouppq,
	    (compare_func_t)find_cons_group_by_cons_no,
	    &cons_no);
	(void) mutex_unlock(&vntsdp->lock);

	if (groupp == NULL) {
		/* no such group */
		return;
	}

	/* group exists, if console exists? */
	(void) mutex_lock(&groupp->lock);
	consp = vntsd_que_find(groupp->conspq,
	    (compare_func_t)deleted_cons_by_consno, &cons_no);

	if (consp == NULL) {
		/* no such console */
		(void) mutex_unlock(&groupp->lock);
		return;
	}

	/* console exists - mark console for main thread to delete it */
	(void) mutex_lock(&consp->lock);

	if (consp->status & VNTSD_CONS_DELETED) {
		/* already marked */
		(void) mutex_unlock(&consp->lock);
		(void) mutex_unlock(&groupp->lock);
		return;
	}

	consp->status |= VNTSD_CONS_DELETED;
	groupp->status |= VNTSD_GROUP_CLEAN_CONS;

	(void) mutex_unlock(&consp->lock);
	(void) mutex_unlock(&groupp->lock);

}

/* add a console */
static void
do_add_cons(vntsd_t *vntsdp, int cons_no)
{
	vcc_console_t	console;
	vntsd_group_t	*groupp;
	int		rv;
	char		err_msg[VNTSD_LINE_LEN];


	(void) snprintf(err_msg, sizeof (err_msg),
	    "do_add_cons():Can not add console=%d", cons_no);

	/* get console configuration from vcc */

	if ((rv = vntsd_vcc_ioctl(VCC_CONS_INFO, cons_no, (void *)&console))
	    != VNTSD_SUCCESS) {
		vntsd_log(rv, err_msg);
		return;
	}

	/* clean up the console if console was deleted and added again */
	delete_cons_before_add(vntsdp, console.cons_no);

	/* initialize console */

	if ((rv = alloc_cons_with_group(vntsdp, &console, &groupp)) !=
	    VNTSD_SUCCESS) {
		/* no memory to add this new console */
		vntsd_log(rv, err_msg);
		return;
	}

	if (groupp != NULL) {
		/* new group */
		/* create listen thread for this console */
		if (create_listen_thread(groupp)) {
			vntsd_log(VNTSD_ERR_CREATE_LISTEN_THR, err_msg);
			free_group(groupp);
		}

	}
}

/* daemon wake up */
void
vntsd_daemon_wakeup(vntsd_t *vntsdp)
{

	vcc_response_t	inq_data;

	/* reason to wake up  */
	if (vntsd_vcc_ioctl(VCC_INQUIRY, 0, (void *)&inq_data) !=
	    VNTSD_SUCCESS) {
		vntsd_log(VNTSD_ERR_VCC_IOCTL, "vntsd_daemon_wakeup()");
		return;
	}

	D1(stderr, "t@%d vntsd_daemon_wakup:msg %d port %x\n", thr_self(),
	    inq_data.reason, inq_data.cons_no);

	switch (inq_data.reason) {

	case VCC_CONS_ADDED:
		do_add_cons(vntsdp, inq_data.cons_no);
		break;

	case VCC_CONS_MISS_ADDED:
		/* an added port was deleted before vntsd can process it */
		return;

	default:
		DERR(stderr, "t@%d daemon_wakeup:ioctl_unknown %d\n",
		    thr_self(), inq_data.reason);
		vntsd_log(VNTSD_ERR_UNKNOWN_CMD, "from vcc\n");
		break;
	}
}

/* initial console configuration */
void
vntsd_get_config(vntsd_t *vntsdp)
{

	int		i;
	int		num_cons;
	vcc_console_t	*consp;
	vntsd_group_t	*groupp;

	/* num of consoles */
	num_cons = 0;

	if (vntsd_vcc_ioctl(VCC_NUM_CONSOLE, 0, (void *)&num_cons) !=
	    VNTSD_SUCCESS) {
		vntsd_log(VNTSD_ERR_VCC_IOCTL, "VCC_NUM_CONSOLE failed\n");
		return;
	}

	D3(stderr, "get_config:num_cons=%d", num_cons);

	if (num_cons == 0) {
		return;
	}

	/* allocate memory for all consoles */
	consp = malloc(num_cons*sizeof (vcc_console_t));

	if (consp == NULL) {
		vntsd_log(VNTSD_ERR_NO_MEM, "for console table.");
		return;
	}

	/* get console table */
	if (vntsd_vcc_ioctl(VCC_CONS_TBL, 0, (void *)consp) != VNTSD_SUCCESS) {
		vntsd_log(VNTSD_ERR_VCC_IOCTL, " VCC_CONS_TBL "
		    "for console table\n");
		return;
	}

	/* intialize groups and consoles  */
	for (i = 0; i < num_cons; i++) {
		if (alloc_cons_with_group(vntsdp, &consp[i], &groupp)
		    != VNTSD_SUCCESS) {
			vntsd_log(VNTSD_ERR_ADD_CONS_FAILED, "get_config");
		}
	}

	/* create listen thread for each group */
	(void) mutex_lock(&vntsdp->lock);

	for (; ; ) {
		groupp = vntsd_que_walk(vntsdp->grouppq,
		    (el_func_t)create_listen_thread);
		if (groupp == NULL) {
			break;
		}
		vntsd_log(VNTSD_ERR_CREATE_LISTEN_THR, "get config()");
	}

	(void) mutex_unlock(&vntsdp->lock);
}
