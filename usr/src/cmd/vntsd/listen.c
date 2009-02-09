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

/*
 * Each group has a listen thread. It is created at the time
 * of a group creation and destroyed when a group does not have
 * any console associated with it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <thread.h>
#include <assert.h>
#include <signal.h>
#include <ctype.h>
#include <syslog.h>
#include "vntsd.h"

#define	    MAX_BIND_RETRIES		6

/*
 * check the state of listen thread. exit if there is an fatal error
 * or the group is removed. Main thread will call free_group
 * to close group socket and free group structure.
 */
static void
listen_chk_status(vntsd_group_t *groupp, int status)
{
	char	    err_msg[VNTSD_LINE_LEN];


	D1(stderr, "t@%d listen_chk_status() status=%d group=%s "
	    "tcp=%lld group status = %x\n", thr_self(), status,
	    groupp->group_name, groupp->tcp_port, groupp->status);

	(void) snprintf(err_msg, sizeof (err_msg),
	    "Group:%s TCP port %lld status %x",
	    groupp->group_name, groupp->tcp_port, groupp->status);


	switch (status) {

	case VNTSD_SUCCESS:
		return;


	case VNTSD_STATUS_ACCEPT_ERR:
		return;

	case VNTSD_STATUS_INTR:
		assert(groupp->status & VNTSD_GROUP_SIG_WAIT);
		/*FALLTHRU*/
	case VNTSD_STATUS_NO_CONS:
	default:
		/* fatal error or no console in the group, remove the group. */

		(void) mutex_lock(&groupp->lock);

		if (groupp->status & VNTSD_GROUP_SIG_WAIT) {
			/*
			 * group is already being deleted, notify main
			 * thread and exit.
			 */
			groupp->status &= ~VNTSD_GROUP_SIG_WAIT;
			(void) cond_signal(&groupp->cvp);
			(void) mutex_unlock(&groupp->lock);
			thr_exit(0);
		}

		/*
		 * if there still is console(s) in the group,
		 * the console(s) could not be connected any more because of
		 * a fatal error. Therefore, mark the console and notify
		 * main thread to delete console and group.
		 */
		(void) vntsd_que_walk(groupp->conspq,
		    (el_func_t)vntsd_mark_deleted_cons);
		groupp->status |= VNTSD_GROUP_CLEAN_CONS;

		/* signal main thread to delete the group */
		(void) thr_kill(groupp->vntsd->tid, SIGUSR1);
		(void) mutex_unlock(&groupp->lock);

		/* log error */
		if (status != VNTSD_STATUS_NO_CONS)
			vntsd_log(status, err_msg);
		thr_exit(0);
	}
}

/* allocate and initialize listening socket. */
static int
open_socket(int port_no, int *sockfd)
{

	struct	    sockaddr_in addr;
	int	    on;
	int	    retries = 0;


	/* allocate a socket */
	*sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (*sockfd < 0) {
		if (errno == EINTR) {
			return (VNTSD_STATUS_INTR);
		}
		return (VNTSD_ERR_LISTEN_SOCKET);
	}

#ifdef DEBUG
	/* set reuse local socket address */
	on = 1;
	if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on))) {
		return (VNTSD_ERR_LISTEN_OPTS);
	}
#endif

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = (vntsd_ip_addr()).s_addr;
	addr.sin_port = htons(port_no);

	/* bind socket */

	for (; ; ) {

		/*
		 * After a socket is closed, the port
		 * is transitioned to TIME_WAIT state.
		 * It may take a few retries to bind
		 * a just released port.
		 */
		if (bind(*sockfd, (struct sockaddr *)&addr,
		    sizeof (addr)) < 0) {

			if (errno == EINTR) {
				return (VNTSD_STATUS_INTR);
			}

			if (errno == EADDRINUSE && retries < MAX_BIND_RETRIES) {
				/* port may be in TIME_WAIT state, retry */
				(void) sleep(5);

				/* woke up by signal? */
				if (errno == EINTR) {
					return (VNTSD_STATUS_INTR);
				}

				retries++;
				continue;
			}

			return (VNTSD_ERR_LISTEN_BIND);

		}

		break;

	}

	if (listen(*sockfd, VNTSD_MAX_SOCKETS) == -1) {
		if (errno == EINTR) {
			return (VNTSD_STATUS_INTR);
		}
		return (VNTSD_ERR_LISTEN_BIND);
	}

	D1(stderr, "t@%d open_socket() sockfd=%d\n", thr_self(), *sockfd);
	return (VNTSD_SUCCESS);
}

/* ceate console selection thread */
static int
create_console_thread(vntsd_group_t *groupp, int sockfd)
{
	vntsd_client_t	    *clientp;
	vntsd_thr_arg_t	    *thr_arg;
	int		    rv;


	assert(groupp);
	D1(stderr, "t@%d create_console_thread@%lld:client@%d\n", thr_self(),
	    groupp->tcp_port, sockfd);

	/* allocate a new client */
	clientp = (vntsd_client_t *)malloc(sizeof (vntsd_client_t));
	if (clientp  == NULL) {
		return (VNTSD_ERR_NO_MEM);
	}

	/* initialize the client */
	bzero(clientp, sizeof (vntsd_client_t));

	clientp->sockfd = sockfd;
	clientp->cons_tid = (thread_t)-1;

	(void) mutex_init(&clientp->lock, USYNC_THREAD|LOCK_ERRORCHECK, NULL);

	/* append client to group */
	(void) mutex_lock(&groupp->lock);

	/* check if the group is [being] removed */
	if (groupp->status & VNTSD_GROUP_IN_CLEANUP) {
		(void) mutex_unlock(&groupp->lock);
		vntsd_free_client(clientp);
		return (VNTSD_STATUS_NO_CONS);
	}


	if ((rv = vntsd_que_append(&groupp->no_cons_clientpq, clientp))
	    != VNTSD_SUCCESS) {
		(void) mutex_unlock(&groupp->lock);
		vntsd_free_client(clientp);
		return (rv);
	}

	(void) mutex_unlock(&groupp->lock);

	/*
	 * allocate thr_arg from heap for console thread so
	 * that thr_arg is still valid after this function exits.
	 * console thread will free thr_arg.
	 */

	thr_arg = (vntsd_thr_arg_t *)malloc(sizeof (vntsd_thr_arg_t));
	if (thr_arg  == NULL) {
		vntsd_free_client(clientp);
		return (VNTSD_ERR_NO_MEM);
	}
	thr_arg->handle = groupp;
	thr_arg->arg = clientp;

	(void) mutex_lock(&clientp->lock);


	/* create console selection thread */
	if (thr_create(NULL, 0, (thr_func_t)vntsd_console_thread,
	    thr_arg, THR_DETACHED, &clientp->cons_tid)) {

		free(thr_arg);
		(void) mutex_unlock(&clientp->lock);
		(void) mutex_lock(&groupp->lock);
		(void) vntsd_que_rm(&groupp->no_cons_clientpq, clientp);
		(void) mutex_unlock(&groupp->lock);
		vntsd_free_client(clientp);

		return (VNTSD_ERR_CREATE_CONS_THR);
	}

	(void) mutex_unlock(&clientp->lock);

	return (VNTSD_SUCCESS);
}

/* listen thread */
void *
vntsd_listen_thread(vntsd_group_t *groupp)
{

	int		newsockfd;
	size_t		clilen;
	struct		sockaddr_in cli_addr;
	int		rv;
	int		num_cons;
	vntsd_t		*vntsdp;

	assert(groupp);

	D1(stderr, "t@%d listen@%lld\n", thr_self(), groupp->tcp_port);


	vntsdp = groupp->vntsd;

	/* initialize listen socket */
	(void) mutex_lock(&groupp->lock);
	rv = open_socket(groupp->tcp_port, &groupp->sockfd);
	(void) mutex_unlock(&groupp->lock);
	listen_chk_status(groupp, rv);

	for (; ; ) {

		clilen = sizeof (cli_addr);

		/* listen to the socket */
		newsockfd = accept(groupp->sockfd, (struct sockaddr *)&cli_addr,
		    &clilen);

		D1(stderr, "t@%d listen_thread() connected sockfd=%d\n",
		    thr_self(), newsockfd);

		if (newsockfd <=  0) {

			if (errno == EINTR) {
				listen_chk_status(groupp, VNTSD_STATUS_INTR);
			} else {
				listen_chk_status(groupp,
				    VNTSD_STATUS_ACCEPT_ERR);
			}
			continue;
		}

		/* Check authorization if enabled */
		if ((vntsdp->options & VNTSD_OPT_AUTH_CHECK) != 0) {
			rv = auth_check_fd(newsockfd, groupp->group_name);
			if (rv != B_TRUE) {
				D3(stderr, "t@%d listen@%lld group@%s: "
				    "authorization failure\n", thr_self(),
				    groupp->tcp_port, groupp->group_name);
				(void) close(newsockfd);
				continue;
			}
		}

		num_cons = vntsd_chk_group_total_cons(groupp);
		if (num_cons == 0) {
			(void) close(newsockfd);
			listen_chk_status(groupp, VNTSD_STATUS_NO_CONS);
			continue;
		}

		/* a connection is established */
		rv = vntsd_set_telnet_options(newsockfd);
		if (rv != VNTSD_SUCCESS) {
			(void) close(newsockfd);
			listen_chk_status(groupp, rv);
		}
		rv = create_console_thread(groupp, newsockfd);
		if (rv != VNTSD_SUCCESS) {
			(void) close(newsockfd);
			listen_chk_status(groupp, rv);
		}
	}

	/*NOTREACHED*/
	return (NULL);
}
