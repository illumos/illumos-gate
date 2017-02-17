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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */
/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * svc.c, Server-side remote procedure call interface.
 *
 * There are two sets of procedures here.  The xprt routines are
 * for handling transport handles.  The svc routines handle the
 * list of service routines.
 *
 */

#include "mt.h"
#include "rpc_mt.h"
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <stropts.h>
#include <sys/conf.h>
#include <rpc/rpc.h>
#ifdef PORTMAP
#include <rpc/pmap_clnt.h>
#endif
#include <sys/poll.h>
#include <netconfig.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

extern bool_t __svc_get_door_cred();
extern bool_t __rpc_get_local_cred();

SVCXPRT **svc_xports;
static int nsvc_xports; 	/* total number of svc_xports allocated */

XDR **svc_xdrs;		/* common XDR receive area */
int nsvc_xdrs;		/* total number of svc_xdrs allocated */

int __rpc_use_pollfd_done;	/* to unlimit the number of connections */

#define	NULL_SVC ((struct svc_callout *)0)
#define	RQCRED_SIZE	400		/* this size is excessive */

/*
 * The services list
 * Each entry represents a set of procedures (an rpc program).
 * The dispatch routine takes request structs and runs the
 * appropriate procedure.
 */
static struct svc_callout {
	struct svc_callout *sc_next;
	rpcprog_t	    sc_prog;
	rpcvers_t	    sc_vers;
	char		   *sc_netid;
	void		    (*sc_dispatch)();
} *svc_head;
extern rwlock_t	svc_lock;

static struct svc_callout *svc_find();
int _svc_prog_dispatch();
void svc_getreq_common();
char *strdup();

extern mutex_t	svc_door_mutex;
extern cond_t	svc_door_waitcv;
extern int	svc_ndoorfds;
extern SVCXPRT_LIST *_svc_xprtlist;
extern mutex_t xprtlist_lock;
extern void __svc_rm_from_xlist();

#if !defined(_LP64)
extern fd_set _new_svc_fdset;
#endif

/*
 * If the allocated array of reactor is too small, this value is used as a
 * margin. This reduces the number of allocations.
 */
#define	USER_FD_INCREMENT 5

static void add_pollfd(int fd, short events);
static void remove_pollfd(int fd);
static void __svc_remove_input_of_fd(int fd);

/*
 * Data used to handle reactor:
 * 	- one file descriptor we listen to,
 *	- one callback we call if the fd pops,
 *	- and a cookie passed as a parameter to the callback.
 *
 * The structure is an array indexed on the file descriptor. Each entry is
 * pointing to the first element of a double-linked list of callback.
 * only one callback may be associated to a couple (fd, event).
 */

struct _svc_user_fd_head;

typedef struct {
	struct _svc_user_fd_node *next;
	struct _svc_user_fd_node *previous;
} _svc_user_link;

typedef struct _svc_user_fd_node {
	_svc_user_link lnk;
	svc_input_id_t id;
	int	    fd;
	unsigned int   events;
	svc_callback_t callback;
	void*	  cookie;
} _svc_user_fd_node;

typedef struct _svc_user_fd_head {
	struct _svc_user_fd_node *list;
	unsigned int mask;    /* logical OR of all sub-masks */
} _svc_user_fd_head;


/* Array of defined reactor - indexed on file descriptor */
static _svc_user_fd_head *svc_userfds = NULL;

/* current size of file descriptor */
static int svc_nuserfds = 0;

/* Mutex to ensure MT safe operations for user fds callbacks. */
static mutex_t svc_userfds_lock = DEFAULTMUTEX;


/*
 * This structure is used to have constant time alogrithms. There is an array
 * of this structure as large as svc_nuserfds. When the user is registering a
 * new callback, the address of the created structure is stored in a cell of
 * this array. The address of this cell is the returned unique identifier.
 *
 * On removing, the id is given by the user, then we know if this cell is
 * filled or not (with free). If it is free, we return an error. Otherwise,
 * we can free the structure pointed by fd_node.
 *
 * On insertion, we use the linked list created by (first_free,
 * next_free). In this way with a constant time computation, we can give a
 * correct index to the user.
 */

typedef struct _svc_management_user_fd {
	bool_t free;
	union {
		svc_input_id_t next_free;
		_svc_user_fd_node *fd_node;
	} data;
} _svc_management_user_fd;

/* index to the first free elem */
static svc_input_id_t first_free = (svc_input_id_t)-1;
/* the size of this array is the same as svc_nuserfds */
static _svc_management_user_fd* user_fd_mgt_array = NULL;

/* current size of user_fd_mgt_array */
static int svc_nmgtuserfds = 0;


/* Define some macros to access data associated to registration ids. */
#define	node_from_id(id) (user_fd_mgt_array[(int)id].data.fd_node)
#define	is_free_id(id) (user_fd_mgt_array[(int)id].free)

#ifndef POLLSTANDARD
#define	POLLSTANDARD \
	(POLLIN|POLLPRI|POLLOUT|POLLRDNORM|POLLRDBAND| \
	POLLWRBAND|POLLERR|POLLHUP|POLLNVAL)
#endif

/*
 * To free an Id, we set the cell as free and insert its address in the list
 * of free cell.
 */

static void
_svc_free_id(const svc_input_id_t id)
{
	assert(((int)id >= 0) && ((int)id < svc_nmgtuserfds));
	user_fd_mgt_array[(int)id].free = TRUE;
	user_fd_mgt_array[(int)id].data.next_free = first_free;
	first_free = id;
}

/*
 * To get a free cell, we just have to take it from the free linked list and
 * set the flag to "not free". This function also allocates new memory if
 * necessary
 */
static svc_input_id_t
_svc_attribute_new_id(_svc_user_fd_node *node)
{
	int selected_index = (int)first_free;
	assert(node != NULL);

	if (selected_index == -1) {
		/* Allocate new entries */
		int L_inOldSize = svc_nmgtuserfds;
		int i;
		_svc_management_user_fd *tmp;

		svc_nmgtuserfds += USER_FD_INCREMENT;

		tmp = realloc(user_fd_mgt_array,
		    svc_nmgtuserfds * sizeof (_svc_management_user_fd));

		if (tmp == NULL) {
			syslog(LOG_ERR, "_svc_attribute_new_id: out of memory");
			svc_nmgtuserfds = L_inOldSize;
			errno = ENOMEM;
			return ((svc_input_id_t)-1);
		}

		user_fd_mgt_array = tmp;

		for (i = svc_nmgtuserfds - 1; i >= L_inOldSize; i--)
			_svc_free_id((svc_input_id_t)i);
		selected_index = (int)first_free;
	}

	node->id = (svc_input_id_t)selected_index;
	first_free = user_fd_mgt_array[selected_index].data.next_free;

	user_fd_mgt_array[selected_index].data.fd_node = node;
	user_fd_mgt_array[selected_index].free = FALSE;

	return ((svc_input_id_t)selected_index);
}

/*
 * Access to a pollfd treatment. Scan all the associated callbacks that have
 * at least one bit in their mask that masks a received event.
 *
 * If event POLLNVAL is received, we check that one callback processes it, if
 * not, then remove the file descriptor from the poll. If there is one, let
 * the user do the work.
 */
void
__svc_getreq_user(struct pollfd *pfd)
{
	int fd = pfd->fd;
	short revents = pfd->revents;
	bool_t invalHandled = FALSE;
	_svc_user_fd_node *node;

	(void) mutex_lock(&svc_userfds_lock);

	if ((fd < 0) || (fd >= svc_nuserfds)) {
		(void) mutex_unlock(&svc_userfds_lock);
		return;
	}

	node = svc_userfds[fd].list;

	/* check if at least one mask fits */
	if (0 == (revents & svc_userfds[fd].mask)) {
		(void) mutex_unlock(&svc_userfds_lock);
		return;
	}

	while ((svc_userfds[fd].mask != 0) && (node != NULL)) {
		/*
		 * If one of the received events maps the ones the node listens
		 * to
		 */
		_svc_user_fd_node *next = node->lnk.next;

		if (node->callback != NULL) {
			if (node->events & revents) {
				if (revents & POLLNVAL) {
					invalHandled = TRUE;
				}

				/*
				 * The lock must be released before calling the
				 * user function, as this function can call
				 * svc_remove_input() for example.
				 */
				(void) mutex_unlock(&svc_userfds_lock);
				node->callback(node->id, node->fd,
				    node->events & revents, node->cookie);
				/*
				 * Do not use the node structure anymore, as it
				 * could have been deallocated by the previous
				 * callback.
				 */
				(void) mutex_lock(&svc_userfds_lock);
			}
		}
		node = next;
	}

	if ((revents & POLLNVAL) && !invalHandled)
		__svc_remove_input_of_fd(fd);
	(void) mutex_unlock(&svc_userfds_lock);
}


/*
 * Check if a file descriptor is associated with a user reactor.
 * To do this, just check that the array indexed on fd has a non-void linked
 * list (ie. first element is not NULL)
 */
bool_t
__is_a_userfd(int fd)
{
	/* Checks argument */
	if ((fd < 0) || (fd >= svc_nuserfds))
		return (FALSE);
	return ((svc_userfds[fd].mask == 0x0000)? FALSE:TRUE);
}

/* free everything concerning user fd */
/* used in svc_run.c => no static */

void
__destroy_userfd(void)
{
	int one_fd;
	/* Clean user fd */
	if (svc_userfds != NULL) {
		for (one_fd = 0; one_fd < svc_nuserfds; one_fd++) {
			_svc_user_fd_node *node;

			node = svc_userfds[one_fd].list;
			while (node != NULL) {
				_svc_user_fd_node *tmp = node;
				_svc_free_id(node->id);
				node = node->lnk.next;
				free(tmp);
			}
		}

		free(user_fd_mgt_array);
		user_fd_mgt_array = NULL;
		first_free = (svc_input_id_t)-1;

		free(svc_userfds);
		svc_userfds = NULL;
		svc_nuserfds = 0;
	}
}

/*
 * Remove all the callback associated with a fd => useful when the fd is
 * closed for instance
 */
static void
__svc_remove_input_of_fd(int fd)
{
	_svc_user_fd_node **pnode;
	_svc_user_fd_node *tmp;

	if ((fd < 0) || (fd >= svc_nuserfds))
		return;

	pnode = &svc_userfds[fd].list;
	while ((tmp = *pnode) != NULL) {
		*pnode = tmp->lnk.next;

		_svc_free_id(tmp->id);
		free(tmp);
	}

	svc_userfds[fd].mask = 0;
}

/*
 * Allow user to add an fd in the poll list. If it does not succeed, return
 * -1. Otherwise, return a svc_id
 */

svc_input_id_t
svc_add_input(int user_fd, unsigned int events,
    svc_callback_t user_callback, void *cookie)
{
	_svc_user_fd_node *new_node;

	if (user_fd < 0) {
		errno = EINVAL;
		return ((svc_input_id_t)-1);
	}

	if ((events == 0x0000) ||
	    (events & ~(POLLIN|POLLPRI|POLLOUT|POLLRDNORM|POLLRDBAND|\
	    POLLWRBAND|POLLERR|POLLHUP|POLLNVAL))) {
		errno = EINVAL;
		return ((svc_input_id_t)-1);
	}

	(void) mutex_lock(&svc_userfds_lock);

	if ((user_fd < svc_nuserfds) &&
	    (svc_userfds[user_fd].mask & events) != 0) {
		/* Already registrated call-back */
		errno = EEXIST;
		(void) mutex_unlock(&svc_userfds_lock);
		return ((svc_input_id_t)-1);
	}

	/* Handle memory allocation. */
	if (user_fd >= svc_nuserfds) {
		int oldSize = svc_nuserfds;
		int i;
		_svc_user_fd_head *tmp;

		svc_nuserfds = (user_fd + 1) + USER_FD_INCREMENT;

		tmp = realloc(svc_userfds,
		    svc_nuserfds * sizeof (_svc_user_fd_head));

		if (tmp == NULL) {
			syslog(LOG_ERR, "svc_add_input: out of memory");
			svc_nuserfds = oldSize;
			errno = ENOMEM;
			(void) mutex_unlock(&svc_userfds_lock);
			return ((svc_input_id_t)-1);
		}

		svc_userfds = tmp;

		for (i = oldSize; i < svc_nuserfds; i++) {
			svc_userfds[i].list = NULL;
			svc_userfds[i].mask = 0;
		}
	}

	new_node = malloc(sizeof (_svc_user_fd_node));
	if (new_node == NULL) {
		syslog(LOG_ERR, "svc_add_input: out of memory");
		errno = ENOMEM;
		(void) mutex_unlock(&svc_userfds_lock);
		return ((svc_input_id_t)-1);
	}

	/* create a new node */
	new_node->fd		= user_fd;
	new_node->events	= events;
	new_node->callback	= user_callback;
	new_node->cookie	= cookie;

	if (_svc_attribute_new_id(new_node) == -1) {
		(void) mutex_unlock(&svc_userfds_lock);
		free(new_node);
		return ((svc_input_id_t)-1);
	}

	/* Add the new element at the beginning of the list. */
	if (svc_userfds[user_fd].list != NULL)
		svc_userfds[user_fd].list->lnk.previous = new_node;
	new_node->lnk.next = svc_userfds[user_fd].list;
	new_node->lnk.previous = NULL;

	svc_userfds[user_fd].list = new_node;

	/* refresh global mask for this file desciptor */
	svc_userfds[user_fd].mask |= events;

	/* refresh mask for the poll */
	add_pollfd(user_fd, (svc_userfds[user_fd].mask));

	(void) mutex_unlock(&svc_userfds_lock);
	return (new_node->id);
}

int
svc_remove_input(svc_input_id_t id)
{
	_svc_user_fd_node* node;
	_svc_user_fd_node* next;
	_svc_user_fd_node* previous;
	int fd;		/* caching optim */

	(void) mutex_lock(&svc_userfds_lock);

	/* Immediately update data for id management */
	if (user_fd_mgt_array == NULL || id >= svc_nmgtuserfds ||
	    is_free_id(id)) {
		errno = EINVAL;
		(void) mutex_unlock(&svc_userfds_lock);
		return (-1);
	}

	node = node_from_id(id);
	assert(node != NULL);

	_svc_free_id(id);
	next		= node->lnk.next;
	previous	= node->lnk.previous;
	fd		= node->fd; /* caching optim */

	/* Remove this node from the list. */
	if (previous != NULL) {
		previous->lnk.next = next;
	} else {
		assert(svc_userfds[fd].list == node);
		svc_userfds[fd].list = next;
	}
	if (next != NULL)
		next->lnk.previous = previous;

	/* Remove the node flags from the global mask */
	svc_userfds[fd].mask ^= node->events;

	free(node);
	if (svc_userfds[fd].mask == 0) {
		assert(svc_userfds[fd].list == NULL);
		remove_pollfd(fd);
	} else {
		assert(svc_userfds[fd].list != NULL);
	}
	/* <=> CLEAN NEEDED TO SHRINK MEMORY USAGE */

	(void) mutex_unlock(&svc_userfds_lock);
	return (0);
}

/*
 * Provides default service-side functions for authentication flavors
 * that do not use all the fields in struct svc_auth_ops.
 */

/*ARGSUSED*/
static int
authany_wrap(AUTH *auth, XDR *xdrs, xdrproc_t xfunc, caddr_t xwhere)
{
	return (*xfunc)(xdrs, xwhere);
}

struct svc_auth_ops svc_auth_any_ops = {
	authany_wrap,
	authany_wrap,
};

/*
 * Return pointer to server authentication structure.
 */
SVCAUTH *
__svc_get_svcauth(SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	return (&SVC_XP_AUTH(xprt));
}

/*
 * A callback routine to cleanup after a procedure is executed.
 */
void (*__proc_cleanup_cb)() = NULL;

void *
__svc_set_proc_cleanup_cb(void *cb)
{
	void	*tmp = (void *)__proc_cleanup_cb;

	__proc_cleanup_cb = (void (*)())cb;
	return (tmp);
}

/* ***************  SVCXPRT related stuff **************** */


static int pollfd_shrinking = 1;


/*
 * Add fd to svc_pollfd
 */
static void
add_pollfd(int fd, short events)
{
	if (fd < FD_SETSIZE) {
		FD_SET(fd, &svc_fdset);
#if !defined(_LP64)
		FD_SET(fd, &_new_svc_fdset);
#endif
		svc_nfds++;
		svc_nfds_set++;
		if (fd >= svc_max_fd)
			svc_max_fd = fd + 1;
	}
	if (fd >= svc_max_pollfd)
		svc_max_pollfd = fd + 1;
	if (svc_max_pollfd > svc_pollfd_allocd) {
		int i = svc_pollfd_allocd;
		pollfd_t *tmp;
		do {
			svc_pollfd_allocd += POLLFD_EXTEND;
		} while (svc_max_pollfd > svc_pollfd_allocd);
		tmp = realloc(svc_pollfd,
		    sizeof (pollfd_t) * svc_pollfd_allocd);
		if (tmp != NULL) {
			svc_pollfd = tmp;
			for (; i < svc_pollfd_allocd; i++)
				POLLFD_CLR(i, tmp);
		} else {
			/*
			 * give an error message; undo fdset setting
			 * above;  reset the pollfd_shrinking flag.
			 * because of this poll will not be done
			 * on these fds.
			 */
			if (fd < FD_SETSIZE) {
				FD_CLR(fd, &svc_fdset);
#if !defined(_LP64)
				FD_CLR(fd, &_new_svc_fdset);
#endif
				svc_nfds--;
				svc_nfds_set--;
				if (fd == (svc_max_fd - 1))
					svc_max_fd--;
			}
			if (fd == (svc_max_pollfd - 1))
				svc_max_pollfd--;
			pollfd_shrinking = 0;
			syslog(LOG_ERR, "add_pollfd: out of memory");
			_exit(1);
		}
	}
	svc_pollfd[fd].fd	= fd;
	svc_pollfd[fd].events	= events;
	svc_npollfds++;
	svc_npollfds_set++;
}

/*
 * the fd is still active but only the bit in fdset is cleared.
 * do not subtract svc_nfds or svc_npollfds
 */
void
clear_pollfd(int fd)
{
	if (fd < FD_SETSIZE && FD_ISSET(fd, &svc_fdset)) {
		FD_CLR(fd, &svc_fdset);
#if !defined(_LP64)
		FD_CLR(fd, &_new_svc_fdset);
#endif
		svc_nfds_set--;
	}
	if (fd < svc_pollfd_allocd && POLLFD_ISSET(fd, svc_pollfd)) {
		POLLFD_CLR(fd, svc_pollfd);
		svc_npollfds_set--;
	}
}

/*
 * sets the bit in fdset for an active fd so that poll() is done for that
 */
void
set_pollfd(int fd, short events)
{
	if (fd < FD_SETSIZE) {
		FD_SET(fd, &svc_fdset);
#if !defined(_LP64)
		FD_SET(fd, &_new_svc_fdset);
#endif
		svc_nfds_set++;
	}
	if (fd < svc_pollfd_allocd) {
		svc_pollfd[fd].fd	= fd;
		svc_pollfd[fd].events	= events;
		svc_npollfds_set++;
	}
}

/*
 * remove a svc_pollfd entry; it does not shrink the memory
 */
static void
remove_pollfd(int fd)
{
	clear_pollfd(fd);
	if (fd == (svc_max_fd - 1))
		svc_max_fd--;
	svc_nfds--;
	if (fd == (svc_max_pollfd - 1))
		svc_max_pollfd--;
	svc_npollfds--;
}

/*
 * delete a svc_pollfd entry; it shrinks the memory
 * use remove_pollfd if you do not want to shrink
 */
static void
delete_pollfd(int fd)
{
	remove_pollfd(fd);
	if (pollfd_shrinking && svc_max_pollfd <
	    (svc_pollfd_allocd - POLLFD_SHRINK)) {
		do {
			svc_pollfd_allocd -= POLLFD_SHRINK;
		} while (svc_max_pollfd < (svc_pollfd_allocd - POLLFD_SHRINK));
		svc_pollfd = realloc(svc_pollfd,
		    sizeof (pollfd_t) * svc_pollfd_allocd);
		if (svc_pollfd == NULL) {
			syslog(LOG_ERR, "delete_pollfd: out of memory");
			_exit(1);
		}
	}
}


/*
 * Activate a transport handle.
 */
void
xprt_register(const SVCXPRT *xprt)
{
	int fd = xprt->xp_fd;
#ifdef CALLBACK
	extern void (*_svc_getreqset_proc)();
#endif
/* VARIABLES PROTECTED BY svc_fd_lock: svc_xports, svc_fdset */

	(void) rw_wrlock(&svc_fd_lock);
	if (svc_xports == NULL) {
		/* allocate some small amount first */
		svc_xports = calloc(FD_INCREMENT,  sizeof (SVCXPRT *));
		if (svc_xports == NULL) {
			syslog(LOG_ERR, "xprt_register: out of memory");
			_exit(1);
		}
		nsvc_xports = FD_INCREMENT;

#ifdef CALLBACK
		/*
		 * XXX: This code does not keep track of the server state.
		 *
		 * This provides for callback support.	When a client
		 * recv's a call from another client on the server fd's,
		 * it calls _svc_getreqset_proc() which would return
		 * after serving all the server requests.  Also look under
		 * clnt_dg.c and clnt_vc.c  (clnt_call part of it)
		 */
		_svc_getreqset_proc = svc_getreq_poll;
#endif
	}

	while (fd >= nsvc_xports) {
		SVCXPRT **tmp_xprts = svc_xports;

		/* time to expand svc_xprts */
		tmp_xprts = realloc(svc_xports,
		    sizeof (SVCXPRT *) * (nsvc_xports + FD_INCREMENT));
		if (tmp_xprts == NULL) {
			syslog(LOG_ERR, "xprt_register : out of memory.");
			_exit(1);
		}

		svc_xports = tmp_xprts;
		(void) memset(&svc_xports[nsvc_xports], 0,
		    sizeof (SVCXPRT *) * FD_INCREMENT);
		nsvc_xports += FD_INCREMENT;
	}

	svc_xports[fd] = (SVCXPRT *)xprt;

	add_pollfd(fd, MASKVAL);

	if (svc_polling) {
		char dummy;

		/*
		 * This happens only in one of the MT modes.
		 * Wake up poller.
		 */
		(void) write(svc_pipe[1], &dummy, sizeof (dummy));
	}
	/*
	 * If already dispatching door based services, start
	 * dispatching TLI based services now.
	 */
	(void) mutex_lock(&svc_door_mutex);
	if (svc_ndoorfds > 0)
		(void) cond_signal(&svc_door_waitcv);
	(void) mutex_unlock(&svc_door_mutex);

	if (svc_xdrs == NULL) {
		/* allocate initial chunk */
		svc_xdrs = calloc(FD_INCREMENT, sizeof (XDR *));
		if (svc_xdrs != NULL)
			nsvc_xdrs = FD_INCREMENT;
		else {
			syslog(LOG_ERR, "xprt_register : out of memory.");
			_exit(1);
		}
	}
	(void) rw_unlock(&svc_fd_lock);
}

/*
 * De-activate a transport handle.
 */
void
__xprt_unregister_private(const SVCXPRT *xprt, bool_t lock_not_held)
{
	int fd = xprt->xp_fd;

	if (lock_not_held)
		(void) rw_wrlock(&svc_fd_lock);
	if ((fd < nsvc_xports) && (svc_xports[fd] == xprt)) {
		svc_xports[fd] = NULL;
		delete_pollfd(fd);
	}
	if (lock_not_held)
		(void) rw_unlock(&svc_fd_lock);
	__svc_rm_from_xlist(&_svc_xprtlist, xprt, &xprtlist_lock);
}

void
xprt_unregister(const SVCXPRT *xprt)
{
	__xprt_unregister_private(xprt, TRUE);
}

/* ********************** CALLOUT list related stuff ************* */

/*
 * Add a service program to the callout list.
 * The dispatch routine will be called when a rpc request for this
 * program number comes in.
 */
bool_t
svc_reg(const SVCXPRT *xprt, const rpcprog_t prog, const rpcvers_t vers,
    void (*dispatch)(), const struct netconfig *nconf)
{
	struct svc_callout *prev;
	struct svc_callout *s, **s2;
	struct netconfig *tnconf;
	char *netid = NULL;
	int flag = 0;

/* VARIABLES PROTECTED BY svc_lock: s, prev, svc_head */

	if (xprt->xp_netid) {
		netid = strdup(xprt->xp_netid);
		flag = 1;
	} else if (nconf && nconf->nc_netid) {
		netid = strdup(nconf->nc_netid);
		flag = 1;
	} else if ((tnconf = __rpcfd_to_nconf(xprt->xp_fd, xprt->xp_type))
	    != NULL) {
		netid = strdup(tnconf->nc_netid);
		flag = 1;
		freenetconfigent(tnconf);
	} /* must have been created with svc_raw_create */
	if ((netid == NULL) && (flag == 1))
		return (FALSE);

	(void) rw_wrlock(&svc_lock);
	if ((s = svc_find(prog, vers, &prev, netid)) != NULL_SVC) {
		if (netid)
			free(netid);
		if (s->sc_dispatch == dispatch)
			goto rpcb_it; /* it is registering another xptr */
		(void) rw_unlock(&svc_lock);
		return (FALSE);
	}
	s = malloc(sizeof (struct svc_callout));
	if (s == NULL) {
		if (netid)
			free(netid);
		(void) rw_unlock(&svc_lock);
		return (FALSE);
	}

	s->sc_prog = prog;
	s->sc_vers = vers;
	s->sc_dispatch = dispatch;
	s->sc_netid = netid;
	s->sc_next = NULL;

	/*
	 * The ordering of transports is such that the most frequently used
	 * one appears first.  So add the new entry to the end of the list.
	 */
	for (s2 = &svc_head; *s2 != NULL; s2 = &(*s2)->sc_next)
		;
	*s2 = s;

	if ((xprt->xp_netid == NULL) && (flag == 1) && netid)
		if ((((SVCXPRT *)xprt)->xp_netid = strdup(netid)) == NULL) {
			syslog(LOG_ERR, "svc_reg : strdup failed.");
			free(netid);
			free(s);
			*s2 = NULL;
			(void) rw_unlock(&svc_lock);
			return (FALSE);
		}

rpcb_it:
	(void) rw_unlock(&svc_lock);

	/* now register the information with the local binder service */
	if (nconf)
		return (rpcb_set(prog, vers, nconf, &xprt->xp_ltaddr));
	return (TRUE);
	/*NOTREACHED*/
}

/*
 * Remove a service program from the callout list.
 */
void
svc_unreg(const rpcprog_t prog, const rpcvers_t vers)
{
	struct svc_callout *prev;
	struct svc_callout *s;

	/* unregister the information anyway */
	(void) rpcb_unset(prog, vers, NULL);

	(void) rw_wrlock(&svc_lock);
	while ((s = svc_find(prog, vers, &prev, NULL)) != NULL_SVC) {
		if (prev == NULL_SVC) {
			svc_head = s->sc_next;
		} else {
			prev->sc_next = s->sc_next;
		}
		s->sc_next = NULL_SVC;
		if (s->sc_netid)
			free(s->sc_netid);
		free(s);
	}
	(void) rw_unlock(&svc_lock);
}

#ifdef PORTMAP
/*
 * Add a service program to the callout list.
 * The dispatch routine will be called when a rpc request for this
 * program number comes in.
 * For version 2 portmappers.
 */
bool_t
svc_register(SVCXPRT *xprt, rpcprog_t prog, rpcvers_t vers,
    void (*dispatch)(), int protocol)
{
	struct svc_callout *prev;
	struct svc_callout *s;
	struct netconfig *nconf;
	char *netid = NULL;
	int flag = 0;

	if (xprt->xp_netid) {
		netid = strdup(xprt->xp_netid);
		flag = 1;
	} else if ((ioctl(xprt->xp_fd, I_FIND, "timod") > 0) && ((nconf =
	    __rpcfd_to_nconf(xprt->xp_fd, xprt->xp_type)) != NULL)) {
		/* fill in missing netid field in SVCXPRT */
		netid = strdup(nconf->nc_netid);
		flag = 1;
		freenetconfigent(nconf);
	} /* must be svc_raw_create */

	if ((netid == NULL) && (flag == 1))
		return (FALSE);

	(void) rw_wrlock(&svc_lock);
	if ((s = svc_find(prog, vers, &prev, netid)) != NULL_SVC) {
		if (netid)
			free(netid);
		if (s->sc_dispatch == dispatch)
			goto pmap_it;  /* it is registering another xptr */
		(void) rw_unlock(&svc_lock);
		return (FALSE);
	}
	s = malloc(sizeof (struct svc_callout));
	if (s == (struct svc_callout *)0) {
		if (netid)
			free(netid);
		(void) rw_unlock(&svc_lock);
		return (FALSE);
	}
	s->sc_prog = prog;
	s->sc_vers = vers;
	s->sc_dispatch = dispatch;
	s->sc_netid = netid;
	s->sc_next = svc_head;
	svc_head = s;

	if ((xprt->xp_netid == NULL) && (flag == 1) && netid)
		if ((xprt->xp_netid = strdup(netid)) == NULL) {
			syslog(LOG_ERR, "svc_register : strdup failed.");
			free(netid);
			svc_head = s->sc_next;
			free(s);
			(void) rw_unlock(&svc_lock);
			return (FALSE);
		}

pmap_it:
	(void) rw_unlock(&svc_lock);
	/* now register the information with the local binder service */
	if (protocol)
		return (pmap_set(prog, vers, protocol, xprt->xp_port));
	return (TRUE);
}

/*
 * Remove a service program from the callout list.
 * For version 2 portmappers.
 */
void
svc_unregister(rpcprog_t prog, rpcvers_t vers)
{
	struct svc_callout *prev;
	struct svc_callout *s;

	(void) rw_wrlock(&svc_lock);
	while ((s = svc_find(prog, vers, &prev, NULL)) != NULL_SVC) {
		if (prev == NULL_SVC) {
			svc_head = s->sc_next;
		} else {
			prev->sc_next = s->sc_next;
		}
		s->sc_next = NULL_SVC;
		if (s->sc_netid)
			free(s->sc_netid);
		free(s);
		/* unregister the information with the local binder service */
		(void) pmap_unset(prog, vers);
	}
	(void) rw_unlock(&svc_lock);
}
#endif /* PORTMAP */

/*
 * Search the callout list for a program number, return the callout
 * struct.
 * Also check for transport as well.  Many routines such as svc_unreg
 * dont give any corresponding transport, so dont check for transport if
 * netid == NULL
 */
static struct svc_callout *
svc_find(rpcprog_t prog, rpcvers_t vers, struct svc_callout **prev, char *netid)
{
	struct svc_callout *s, *p;

/* WRITE LOCK HELD ON ENTRY: svc_lock */

/*	assert(RW_WRITE_HELD(&svc_lock)); */
	p = NULL_SVC;
	for (s = svc_head; s != NULL_SVC; s = s->sc_next) {
		if (((s->sc_prog == prog) && (s->sc_vers == vers)) &&
		    ((netid == NULL) || (s->sc_netid == NULL) ||
		    (strcmp(netid, s->sc_netid) == 0)))
			break;
		p = s;
	}
	*prev = p;
	return (s);
}


/* ******************* REPLY GENERATION ROUTINES  ************ */

/*
 * Send a reply to an rpc request
 */
bool_t
svc_sendreply(const SVCXPRT *xprt, const xdrproc_t xdr_results,
    const caddr_t xdr_location)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = xprt->xp_verf;
	rply.acpted_rply.ar_stat = SUCCESS;
	rply.acpted_rply.ar_results.where = xdr_location;
	rply.acpted_rply.ar_results.proc = xdr_results;
	return (SVC_REPLY((SVCXPRT *)xprt, &rply));
}

/*
 * No procedure error reply
 */
void
svcerr_noproc(const SVCXPRT *xprt)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = xprt->xp_verf;
	rply.acpted_rply.ar_stat = PROC_UNAVAIL;
	SVC_REPLY((SVCXPRT *)xprt, &rply);
}

/*
 * Can't decode args error reply
 */
void
svcerr_decode(const SVCXPRT *xprt)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = xprt->xp_verf;
	rply.acpted_rply.ar_stat = GARBAGE_ARGS;
	SVC_REPLY((SVCXPRT *)xprt, &rply);
}

/*
 * Some system error
 */
void
svcerr_systemerr(const SVCXPRT *xprt)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = xprt->xp_verf;
	rply.acpted_rply.ar_stat = SYSTEM_ERR;
	SVC_REPLY((SVCXPRT *)xprt, &rply);
}

/*
 * Tell RPC package to not complain about version errors to the client.	 This
 * is useful when revving broadcast protocols that sit on a fixed address.
 * There is really one (or should be only one) example of this kind of
 * protocol: the portmapper (or rpc binder).
 */
void
__svc_versquiet_on(const SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	svc_flags(xprt) |= SVC_VERSQUIET;
}

void
__svc_versquiet_off(const SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	svc_flags(xprt) &= ~SVC_VERSQUIET;
}

void
svc_versquiet(const SVCXPRT *xprt)
{
	__svc_versquiet_on(xprt);
}

int
__svc_versquiet_get(const SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	return (svc_flags(xprt) & SVC_VERSQUIET);
}

/*
 * Authentication error reply
 */
void
svcerr_auth(const SVCXPRT *xprt, const enum auth_stat why)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_DENIED;
	rply.rjcted_rply.rj_stat = AUTH_ERROR;
	rply.rjcted_rply.rj_why = why;
	SVC_REPLY((SVCXPRT *)xprt, &rply);
}

/*
 * Auth too weak error reply
 */
void
svcerr_weakauth(const SVCXPRT *xprt)
{
	svcerr_auth(xprt, AUTH_TOOWEAK);
}

/*
 * Program unavailable error reply
 */
void
svcerr_noprog(const SVCXPRT *xprt)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = xprt->xp_verf;
	rply.acpted_rply.ar_stat = PROG_UNAVAIL;
	SVC_REPLY((SVCXPRT *)xprt, &rply);
}

/*
 * Program version mismatch error reply
 */
void
svcerr_progvers(const SVCXPRT *xprt, const rpcvers_t low_vers,
    const rpcvers_t high_vers)
{
	struct rpc_msg rply;

	rply.rm_direction = REPLY;
	rply.rm_reply.rp_stat = MSG_ACCEPTED;
	rply.acpted_rply.ar_verf = xprt->xp_verf;
	rply.acpted_rply.ar_stat = PROG_MISMATCH;
	rply.acpted_rply.ar_vers.low = low_vers;
	rply.acpted_rply.ar_vers.high = high_vers;
	SVC_REPLY((SVCXPRT *)xprt, &rply);
}

/* ******************* SERVER INPUT STUFF ******************* */

/*
 * Get server side input from some transport.
 *
 * Statement of authentication parameters management:
 * This function owns and manages all authentication parameters, specifically
 * the "raw" parameters (msg.rm_call.cb_cred and msg.rm_call.cb_verf) and
 * the "cooked" credentials (rqst->rq_clntcred).
 * However, this function does not know the structure of the cooked
 * credentials, so it make the following assumptions:
 *   a) the structure is contiguous (no pointers), and
 *   b) the cred structure size does not exceed RQCRED_SIZE bytes.
 * In all events, all three parameters are freed upon exit from this routine.
 * The storage is trivially management on the call stack in user land, but
 * is mallocated in kernel land.
 */

void
svc_getreq(int rdfds)
{
	fd_set readfds;

	FD_ZERO(&readfds);
	readfds.fds_bits[0] = rdfds;
	svc_getreqset(&readfds);
}

void
svc_getreqset(fd_set *readfds)
{
	int i;

	for (i = 0; i < svc_max_fd; i++) {
		/* fd has input waiting */
		if (FD_ISSET(i, readfds))
			svc_getreq_common(i);
	}
}

void
svc_getreq_poll(struct pollfd *pfdp, const int pollretval)
{
	int i;
	int fds_found;

	for (i = fds_found = 0; fds_found < pollretval; i++) {
		struct pollfd *p = &pfdp[i];

		if (p->revents) {
			/* fd has input waiting */
			fds_found++;
			/*
			 *	We assume that this function is only called
			 *	via someone select()ing from svc_fdset or
			 *	poll()ing from svc_pollset[].  Thus it's safe
			 *	to handle the POLLNVAL event by simply turning
			 *	the corresponding bit off in svc_fdset.  The
			 *	svc_pollset[] array is derived from svc_fdset
			 *	and so will also be updated eventually.
			 *
			 *	XXX Should we do an xprt_unregister() instead?
			 */
			/* Handle user callback */
			if (__is_a_userfd(p->fd) == TRUE) {
				(void) rw_rdlock(&svc_fd_lock);
				__svc_getreq_user(p);
				(void) rw_unlock(&svc_fd_lock);
			} else {
				if (p->revents & POLLNVAL) {
					(void) rw_wrlock(&svc_fd_lock);
					remove_pollfd(p->fd);	/* XXX */
					(void) rw_unlock(&svc_fd_lock);
				} else {
					svc_getreq_common(p->fd);
				}
			}
		}
	}
}

void
svc_getreq_common(const int fd)
{
	SVCXPRT *xprt;
	enum xprt_stat stat;
	struct rpc_msg *msg;
	struct svc_req *r;
	char *cred_area;

	(void) rw_rdlock(&svc_fd_lock);

	/* HANDLE USER CALLBACK */
	if (__is_a_userfd(fd) == TRUE) {
		struct pollfd virtual_fd;

		virtual_fd.events = virtual_fd.revents = (short)0xFFFF;
		virtual_fd.fd = fd;
		__svc_getreq_user(&virtual_fd);
		(void) rw_unlock(&svc_fd_lock);
		return;
	}

	/*
	 * The transport associated with this fd could have been
	 * removed from svc_timeout_nonblock_xprt_and_LRU, for instance.
	 * This can happen if two or more fds get read events and are
	 * passed to svc_getreq_poll/set, the first fd is seviced by
	 * the dispatch routine and cleans up any dead transports.  If
	 * one of the dead transports removed is the other fd that
	 * had a read event then svc_getreq_common() will be called with no
	 * xprt associated with the fd that had the original read event.
	 */
	if ((fd >= nsvc_xports) || (xprt = svc_xports[fd]) == NULL) {
		(void) rw_unlock(&svc_fd_lock);
		return;
	}
	(void) rw_unlock(&svc_fd_lock);
/* LINTED pointer alignment */
	msg = SVCEXT(xprt)->msg;
/* LINTED pointer alignment */
	r = SVCEXT(xprt)->req;
/* LINTED pointer alignment */
	cred_area = SVCEXT(xprt)->cred_area;
	msg->rm_call.cb_cred.oa_base = cred_area;
	msg->rm_call.cb_verf.oa_base = &(cred_area[MAX_AUTH_BYTES]);
	r->rq_clntcred = &(cred_area[2 * MAX_AUTH_BYTES]);

	/* receive msgs from xprtprt (support batch calls) */
	do {
		bool_t dispatch;

		if (dispatch = SVC_RECV(xprt, msg))
			(void) _svc_prog_dispatch(xprt, msg, r);
		/*
		 * Check if the xprt has been disconnected in a recursive call
		 * in the service dispatch routine. If so, then break
		 */
		(void) rw_rdlock(&svc_fd_lock);
		if (xprt != svc_xports[fd]) {
			(void) rw_unlock(&svc_fd_lock);
			break;
		}
		(void) rw_unlock(&svc_fd_lock);

		/*
		 * Call cleanup procedure if set.
		 */
		if (__proc_cleanup_cb != NULL && dispatch)
			(*__proc_cleanup_cb)(xprt);

		if ((stat = SVC_STAT(xprt)) == XPRT_DIED) {
			SVC_DESTROY(xprt);
			break;
		}
	} while (stat == XPRT_MOREREQS);
}

int
_svc_prog_dispatch(SVCXPRT *xprt, struct rpc_msg *msg, struct svc_req *r)
{
	struct svc_callout *s;
	enum auth_stat why;
	int prog_found;
	rpcvers_t low_vers;
	rpcvers_t high_vers;
	void (*disp_fn)();

	r->rq_xprt = xprt;
	r->rq_prog = msg->rm_call.cb_prog;
	r->rq_vers = msg->rm_call.cb_vers;
	r->rq_proc = msg->rm_call.cb_proc;
	r->rq_cred = msg->rm_call.cb_cred;
/* LINTED pointer alignment */
	SVC_XP_AUTH(r->rq_xprt).svc_ah_ops = svc_auth_any_ops;
/* LINTED pointer alignment */
	SVC_XP_AUTH(r->rq_xprt).svc_ah_private = NULL;

	/* first authenticate the message */
	/* Check for null flavor and bypass these calls if possible */

	if (msg->rm_call.cb_cred.oa_flavor == AUTH_NULL) {
		r->rq_xprt->xp_verf.oa_flavor = _null_auth.oa_flavor;
		r->rq_xprt->xp_verf.oa_length = 0;
	} else {
		bool_t no_dispatch;

		if ((why = __gss_authenticate(r, msg,
		    &no_dispatch)) != AUTH_OK) {
			svcerr_auth(xprt, why);
			return (0);
		}
		if (no_dispatch)
			return (0);
	}
	/* match message with a registered service */
	prog_found = FALSE;
	low_vers = (rpcvers_t)(0 - 1);
	high_vers = 0;
	(void) rw_rdlock(&svc_lock);
	for (s = svc_head; s != NULL_SVC; s = s->sc_next) {
		if (s->sc_prog == r->rq_prog) {
			prog_found = TRUE;
			if (s->sc_vers == r->rq_vers) {
				if ((xprt->xp_netid == NULL) ||
				    (s->sc_netid == NULL) ||
				    (strcmp(xprt->xp_netid,
				    s->sc_netid) == 0)) {
					disp_fn = (*s->sc_dispatch);
					(void) rw_unlock(&svc_lock);
					disp_fn(r, xprt);
					return (1);
				}
				prog_found = FALSE;
			}
			if (s->sc_vers < low_vers)
				low_vers = s->sc_vers;
			if (s->sc_vers > high_vers)
				high_vers = s->sc_vers;
		}		/* found correct program */
	}
	(void) rw_unlock(&svc_lock);

	/*
	 * if we got here, the program or version
	 * is not served ...
	 */
	if (prog_found) {
/* LINTED pointer alignment */
		if (!version_keepquiet(xprt))
			svcerr_progvers(xprt, low_vers, high_vers);
	} else {
		svcerr_noprog(xprt);
	}
	return (0);
}

/* ******************* SVCXPRT allocation and deallocation ***************** */

/*
 * svc_xprt_alloc() - allocate a service transport handle
 */
SVCXPRT *
svc_xprt_alloc(void)
{
	SVCXPRT		*xprt = NULL;
	SVCXPRT_EXT	*xt = NULL;
	SVCXPRT_LIST	*xlist = NULL;
	struct rpc_msg	*msg = NULL;
	struct svc_req	*req = NULL;
	char		*cred_area = NULL;

	if ((xprt = calloc(1, sizeof (SVCXPRT))) == NULL)
		goto err_exit;

	if ((xt = calloc(1, sizeof (SVCXPRT_EXT))) == NULL)
		goto err_exit;
	xprt->xp_p3 = (caddr_t)xt; /* SVCEXT(xprt) = xt */

	if ((xlist = calloc(1, sizeof (SVCXPRT_LIST))) == NULL)
		goto err_exit;
	xt->my_xlist = xlist;
	xlist->xprt = xprt;

	if ((msg = malloc(sizeof (struct rpc_msg))) == NULL)
		goto err_exit;
	xt->msg = msg;

	if ((req = malloc(sizeof (struct svc_req))) == NULL)
		goto err_exit;
	xt->req = req;

	if ((cred_area = malloc(2*MAX_AUTH_BYTES + RQCRED_SIZE)) == NULL)
		goto err_exit;
	xt->cred_area = cred_area;

/* LINTED pointer alignment */
	(void) mutex_init(&svc_send_mutex(xprt), USYNC_THREAD, (void *)0);
	return (xprt);

err_exit:
	svc_xprt_free(xprt);
	return (NULL);
}


/*
 * svc_xprt_free() - free a service handle
 */
void
svc_xprt_free(SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	SVCXPRT_EXT	*xt = xprt ? SVCEXT(xprt) : NULL;
	SVCXPRT_LIST	*my_xlist = xt ? xt->my_xlist: NULL;
	struct rpc_msg	*msg = xt ? xt->msg : NULL;
	struct svc_req	*req = xt ? xt->req : NULL;
	char		*cred_area = xt ? xt->cred_area : NULL;

	if (xprt)
		free(xprt);
	if (xt)
		free(xt);
	if (my_xlist)
		free(my_xlist);
	if (msg)
		free(msg);
	if (req)
		free(req);
	if (cred_area)
		free(cred_area);
}


/*
 * svc_xprt_destroy() - free parent and child xprt list
 */
void
svc_xprt_destroy(SVCXPRT *xprt)
{
	SVCXPRT_LIST	*xlist, *xnext = NULL;
	int		type;

/* LINTED pointer alignment */
	if (SVCEXT(xprt)->parent)
/* LINTED pointer alignment */
		xprt = SVCEXT(xprt)->parent;
/* LINTED pointer alignment */
	type = svc_type(xprt);
/* LINTED pointer alignment */
	for (xlist = SVCEXT(xprt)->my_xlist; xlist != NULL; xlist = xnext) {
		xnext = xlist->next;
		xprt = xlist->xprt;
		switch (type) {
		case SVC_DGRAM:
			svc_dg_xprtfree(xprt);
			break;
		case SVC_RENDEZVOUS:
			svc_vc_xprtfree(xprt);
			break;
		case SVC_CONNECTION:
			svc_fd_xprtfree(xprt);
			break;
		case SVC_DOOR:
			svc_door_xprtfree(xprt);
			break;
		}
	}
}


/*
 * svc_copy() - make a copy of parent
 */
SVCXPRT *
svc_copy(SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	switch (svc_type(xprt)) {
	case SVC_DGRAM:
		return (svc_dg_xprtcopy(xprt));
	case SVC_RENDEZVOUS:
		return (svc_vc_xprtcopy(xprt));
	case SVC_CONNECTION:
		return (svc_fd_xprtcopy(xprt));
	}
	return (NULL);
}


/*
 * _svc_destroy_private() - private SVC_DESTROY interface
 */
void
_svc_destroy_private(SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	switch (svc_type(xprt)) {
	case SVC_DGRAM:
		_svc_dg_destroy_private(xprt);
		break;
	case SVC_RENDEZVOUS:
	case SVC_CONNECTION:
		_svc_vc_destroy_private(xprt, TRUE);
		break;
	}
}

/*
 * svc_get_local_cred() - fetch local user credentials.  This always
 * works over doors based transports.  For local transports, this
 * does not yield correct results unless the __rpc_negotiate_uid()
 * call has been invoked to enable this feature.
 */
bool_t
svc_get_local_cred(SVCXPRT *xprt, svc_local_cred_t *lcred)
{
	/* LINTED pointer alignment */
	if (svc_type(xprt) == SVC_DOOR)
		return (__svc_get_door_cred(xprt, lcred));
	return (__rpc_get_local_cred(xprt, lcred));
}


/* ******************* DUPLICATE ENTRY HANDLING ROUTINES ************** */

/*
 * the dup cacheing routines below provide a cache of received
 * transactions. rpc service routines can use this to detect
 * retransmissions and re-send a non-failure response. Uses a
 * lru scheme to find entries to get rid of entries in the cache,
 * though only DUP_DONE entries are placed on the lru list.
 * the routines were written towards development of a generic
 * SVC_DUP() interface, which can be expanded to encompass the
 * svc_dg_enablecache() routines as well. the cache is currently
 * private to the automounter.
 */


/* dupcache header contains xprt specific information */
struct dupcache {
	rwlock_t	dc_lock;
	time_t		dc_time;
	int		dc_buckets;
	int		dc_maxsz;
	int		dc_basis;
	struct dupreq 	*dc_mru;
	struct dupreq	**dc_hashtbl;
};

/*
 * private duplicate cache request routines
 */
static int __svc_dupcache_check(struct svc_req *, caddr_t *, uint_t *,
		struct dupcache *, uint32_t, uint32_t);
static struct dupreq *__svc_dupcache_victim(struct dupcache *, time_t);
static int __svc_dupcache_enter(struct svc_req *, struct dupreq *,
		struct dupcache *, uint32_t, uint32_t, time_t);
static int __svc_dupcache_update(struct svc_req *, caddr_t, uint_t, int,
		struct dupcache *, uint32_t, uint32_t);
#ifdef DUP_DEBUG
static void __svc_dupcache_debug(struct dupcache *);
#endif /* DUP_DEBUG */

/* default parameters for the dupcache */
#define	DUPCACHE_BUCKETS	257
#define	DUPCACHE_TIME		900
#define	DUPCACHE_MAXSZ		INT_MAX

/*
 * __svc_dupcache_init(void *condition, int basis, char *xprt_cache)
 * initialize the duprequest cache and assign it to the xprt_cache
 * Use default values depending on the cache condition and basis.
 * return TRUE on success and FALSE on failure
 */
bool_t
__svc_dupcache_init(void *condition, int basis, char **xprt_cache)
{
	static mutex_t initdc_lock = DEFAULTMUTEX;
	int i;
	struct dupcache *dc;

	(void) mutex_lock(&initdc_lock);
	if (*xprt_cache != NULL) { /* do only once per xprt */
		(void) mutex_unlock(&initdc_lock);
		syslog(LOG_ERR,
		    "__svc_dupcache_init: multiply defined dup cache");
		return (FALSE);
	}

	switch (basis) {
	case DUPCACHE_FIXEDTIME:
		dc = malloc(sizeof (struct dupcache));
		if (dc == NULL) {
			(void) mutex_unlock(&initdc_lock);
			syslog(LOG_ERR,
			    "__svc_dupcache_init: memory alloc failed");
			return (FALSE);
		}
		(void) rwlock_init(&(dc->dc_lock), USYNC_THREAD, NULL);
		if (condition != NULL)
			dc->dc_time = *((time_t *)condition);
		else
			dc->dc_time = DUPCACHE_TIME;
		dc->dc_buckets = DUPCACHE_BUCKETS;
		dc->dc_maxsz = DUPCACHE_MAXSZ;
		dc->dc_basis = basis;
		dc->dc_mru = NULL;
		dc->dc_hashtbl = malloc(dc->dc_buckets *
		    sizeof (struct dupreq *));
		if (dc->dc_hashtbl == NULL) {
			free(dc);
			(void) mutex_unlock(&initdc_lock);
			syslog(LOG_ERR,
			    "__svc_dupcache_init: memory alloc failed");
			return (FALSE);
		}
		for (i = 0; i < DUPCACHE_BUCKETS; i++)
			dc->dc_hashtbl[i] = NULL;
		*xprt_cache = (char *)dc;
		break;
	default:
		(void) mutex_unlock(&initdc_lock);
		syslog(LOG_ERR,
		    "__svc_dupcache_init: undefined dup cache basis");
		return (FALSE);
	}

	(void) mutex_unlock(&initdc_lock);

	return (TRUE);
}

/*
 * __svc_dup(struct svc_req *req, caddr_t *resp_buf, uint_t *resp_bufsz,
 *	char *xprt_cache)
 * searches the request cache. Creates an entry and returns DUP_NEW if
 * the request is not found in the cache.  If it is found, then it
 * returns the state of the request (in progress, drop, or done) and
 * also allocates, and passes back results to the user (if any) in
 * resp_buf, and its length in resp_bufsz. DUP_ERROR is returned on error.
 */
int
__svc_dup(struct svc_req *req, caddr_t *resp_buf, uint_t *resp_bufsz,
    char *xprt_cache)
{
	uint32_t drxid, drhash;
	int rc;
	struct dupreq *dr = NULL;
	time_t timenow = time(NULL);

	/* LINTED pointer alignment */
	struct dupcache *dc = (struct dupcache *)xprt_cache;

	if (dc == NULL) {
		syslog(LOG_ERR, "__svc_dup: undefined cache");
		return (DUP_ERROR);
	}

	/* get the xid of the request */
	if (SVC_CONTROL(req->rq_xprt, SVCGET_XID, (void*)&drxid) == FALSE) {
		syslog(LOG_ERR, "__svc_dup: xid error");
		return (DUP_ERROR);
	}
	drhash = drxid % dc->dc_buckets;

	if ((rc = __svc_dupcache_check(req, resp_buf, resp_bufsz, dc, drxid,
	    drhash)) != DUP_NEW)
		return (rc);

	if ((dr = __svc_dupcache_victim(dc, timenow)) == NULL)
		return (DUP_ERROR);

	if ((rc = __svc_dupcache_enter(req, dr, dc, drxid, drhash, timenow))
	    == DUP_ERROR)
		return (rc);

	return (DUP_NEW);
}



/*
 * __svc_dupcache_check(struct svc_req *req, caddr_t *resp_buf,
 *		uint_t *resp_bufsz,truct dupcache *dc, uint32_t drxid,
 * 		uint32_t drhash)
 * Checks to see whether an entry already exists in the cache. If it does
 * copy back into the resp_buf, if appropriate. Return the status of
 * the request, or DUP_NEW if the entry is not in the cache
 */
static int
__svc_dupcache_check(struct svc_req *req, caddr_t *resp_buf, uint_t *resp_bufsz,
    struct dupcache *dc, uint32_t drxid, uint32_t drhash)
{
	struct dupreq *dr = NULL;

	(void) rw_rdlock(&(dc->dc_lock));
	dr = dc->dc_hashtbl[drhash];
	while (dr != NULL) {
		if (dr->dr_xid == drxid &&
		    dr->dr_proc == req->rq_proc &&
		    dr->dr_prog == req->rq_prog &&
		    dr->dr_vers == req->rq_vers &&
		    dr->dr_addr.len == req->rq_xprt->xp_rtaddr.len &&
		    memcmp(dr->dr_addr.buf, req->rq_xprt->xp_rtaddr.buf,
		    dr->dr_addr.len) == 0) { /* entry found */
			if (dr->dr_hash != drhash) {
				/* sanity check */
				(void) rw_unlock((&dc->dc_lock));
				syslog(LOG_ERR,
				    "\n__svc_dupdone: hashing error");
				return (DUP_ERROR);
			}

			/*
			 * return results for requests on lru list, if
			 * appropriate requests must be DUP_DROP or DUP_DONE
			 * to have a result. A NULL buffer in the cache
			 * implies no results were sent during dupdone.
			 * A NULL buffer in the call implies not interested
			 * in results.
			 */
			if (((dr->dr_status == DUP_DONE) ||
			    (dr->dr_status == DUP_DROP)) &&
			    resp_buf != NULL &&
			    dr->dr_resp.buf != NULL) {
				*resp_buf = malloc(dr->dr_resp.len);
				if (*resp_buf == NULL) {
					syslog(LOG_ERR,
					"__svc_dupcache_check: malloc failed");
					(void) rw_unlock(&(dc->dc_lock));
					return (DUP_ERROR);
				}
				(void) memset(*resp_buf, 0, dr->dr_resp.len);
				(void) memcpy(*resp_buf, dr->dr_resp.buf,
				    dr->dr_resp.len);
				*resp_bufsz = dr->dr_resp.len;
			} else {
				/* no result */
				if (resp_buf)
					*resp_buf = NULL;
				if (resp_bufsz)
					*resp_bufsz = 0;
			}
			(void) rw_unlock(&(dc->dc_lock));
			return (dr->dr_status);
		}
		dr = dr->dr_chain;
	}
	(void) rw_unlock(&(dc->dc_lock));
	return (DUP_NEW);
}

/*
 * __svc_dupcache_victim(struct dupcache *dc, time_t timenow)
 * Return a victim dupreq entry to the caller, depending on cache policy.
 */
static struct dupreq *
__svc_dupcache_victim(struct dupcache *dc, time_t timenow)
{
	struct dupreq *dr = NULL;

	switch (dc->dc_basis) {
	case DUPCACHE_FIXEDTIME:
		/*
		 * The hash policy is to free up a bit of the hash
		 * table before allocating a new entry as the victim.
		 * Freeing up the hash table each time should split
		 * the cost of keeping the hash table clean among threads.
		 * Note that only DONE or DROPPED entries are on the lru
		 * list but we do a sanity check anyway.
		 */
		(void) rw_wrlock(&(dc->dc_lock));
		while ((dc->dc_mru) && (dr = dc->dc_mru->dr_next) &&
		    ((timenow - dr->dr_time) > dc->dc_time)) {
			/* clean and then free the entry */
			if (dr->dr_status != DUP_DONE &&
			    dr->dr_status != DUP_DROP) {
				/*
				 * The LRU list can't contain an
				 * entry where the status is other than
				 * DUP_DONE or DUP_DROP.
				 */
				syslog(LOG_ERR,
				    "__svc_dupcache_victim: bad victim");
#ifdef DUP_DEBUG
				/*
				 * Need to hold the reader/writers lock to
				 * print the cache info, since we already
				 * hold the writers lock, we shall continue
				 * calling __svc_dupcache_debug()
				 */
				__svc_dupcache_debug(dc);
#endif /* DUP_DEBUG */
				(void) rw_unlock(&(dc->dc_lock));
				return (NULL);
			}
			/* free buffers */
			if (dr->dr_resp.buf) {
				free(dr->dr_resp.buf);
				dr->dr_resp.buf = NULL;
			}
			if (dr->dr_addr.buf) {
				free(dr->dr_addr.buf);
				dr->dr_addr.buf = NULL;
			}

			/* unhash the entry */
			if (dr->dr_chain)
				dr->dr_chain->dr_prevchain = dr->dr_prevchain;
			if (dr->dr_prevchain)
				dr->dr_prevchain->dr_chain = dr->dr_chain;
			if (dc->dc_hashtbl[dr->dr_hash] == dr)
				dc->dc_hashtbl[dr->dr_hash] = dr->dr_chain;

			/* modify the lru pointers */
			if (dc->dc_mru == dr) {
				dc->dc_mru = NULL;
			} else {
				dc->dc_mru->dr_next = dr->dr_next;
				dr->dr_next->dr_prev = dc->dc_mru;
			}
			free(dr);
			dr = NULL;
		}
		(void) rw_unlock(&(dc->dc_lock));

		/*
		 * Allocate and return new clean entry as victim
		 */
		if ((dr = malloc(sizeof (*dr))) == NULL) {
			syslog(LOG_ERR,
			    "__svc_dupcache_victim: malloc failed");
			return (NULL);
		}
		(void) memset(dr, 0, sizeof (*dr));
		return (dr);
	default:
		syslog(LOG_ERR,
		    "__svc_dupcache_victim: undefined dup cache_basis");
		return (NULL);
	}
}

/*
 * __svc_dupcache_enter(struct svc_req *req, struct dupreq *dr,
 *	struct dupcache *dc, uint32_t drxid, uint32_t drhash, time_t timenow)
 * build new duprequest entry and then insert into the cache
 */
static int
__svc_dupcache_enter(struct svc_req *req, struct dupreq *dr,
    struct dupcache *dc, uint32_t drxid, uint32_t drhash, time_t timenow)
{
	dr->dr_xid = drxid;
	dr->dr_prog = req->rq_prog;
	dr->dr_vers = req->rq_vers;
	dr->dr_proc = req->rq_proc;
	dr->dr_addr.maxlen = req->rq_xprt->xp_rtaddr.len;
	dr->dr_addr.len = dr->dr_addr.maxlen;
	if ((dr->dr_addr.buf = malloc(dr->dr_addr.maxlen)) == NULL) {
		syslog(LOG_ERR, "__svc_dupcache_enter: malloc failed");
		free(dr);
		return (DUP_ERROR);
	}
	(void) memset(dr->dr_addr.buf, 0, dr->dr_addr.len);
	(void) memcpy(dr->dr_addr.buf, req->rq_xprt->xp_rtaddr.buf,
	    dr->dr_addr.len);
	dr->dr_resp.buf = NULL;
	dr->dr_resp.maxlen = 0;
	dr->dr_resp.len = 0;
	dr->dr_status = DUP_INPROGRESS;
	dr->dr_time = timenow;
	dr->dr_hash = drhash;	/* needed for efficient victim cleanup */

	/* place entry at head of hash table */
	(void) rw_wrlock(&(dc->dc_lock));
	dr->dr_chain = dc->dc_hashtbl[drhash];
	dr->dr_prevchain = NULL;
	if (dc->dc_hashtbl[drhash] != NULL)
		dc->dc_hashtbl[drhash]->dr_prevchain = dr;
	dc->dc_hashtbl[drhash] = dr;
	(void) rw_unlock(&(dc->dc_lock));
	return (DUP_NEW);
}

/*
 * __svc_dupdone(struct svc_req *req, caddr_t resp_buf, uint_t resp_bufsz,
 *		int status, char *xprt_cache)
 * Marks the request done (DUP_DONE or DUP_DROP) and stores the response.
 * Only DONE and DROP requests can be marked as done. Sets the lru pointers
 * to make the entry the most recently used. Returns DUP_ERROR or status.
 */
int
__svc_dupdone(struct svc_req *req, caddr_t resp_buf, uint_t resp_bufsz,
    int status, char *xprt_cache)
{
	uint32_t drxid, drhash;
	int rc;

	/* LINTED pointer alignment */
	struct dupcache *dc = (struct dupcache *)xprt_cache;

	if (dc == NULL) {
		syslog(LOG_ERR, "__svc_dupdone: undefined cache");
		return (DUP_ERROR);
	}

	if (status != DUP_DONE && status != DUP_DROP) {
		syslog(LOG_ERR, "__svc_dupdone: invalid dupdone status");
		syslog(LOG_ERR, "	 must be DUP_DONE or DUP_DROP");
		return (DUP_ERROR);
	}

	/* find the xid of the entry in the cache */
	if (SVC_CONTROL(req->rq_xprt, SVCGET_XID, (void*)&drxid) == FALSE) {
		syslog(LOG_ERR, "__svc_dup: xid error");
		return (DUP_ERROR);
	}
	drhash = drxid % dc->dc_buckets;

	/* update the status of the entry and result buffers, if required */
	if ((rc = __svc_dupcache_update(req, resp_buf, resp_bufsz, status,
	    dc, drxid, drhash)) == DUP_ERROR) {
		syslog(LOG_ERR, "__svc_dupdone: cache entry error");
		return (DUP_ERROR);
	}

	return (rc);
}

/*
 * __svc_dupcache_update(struct svc_req *req, caddr_t resp_buf,
 * 	uint_t resp_bufsz, int status, struct dupcache *dc, uint32_t drxid,
 * 	uint32_t drhash)
 * Check if entry exists in the dupcacache. If it does, update its status
 * and time and also its buffer, if appropriate. Its possible, but unlikely
 * for DONE requests to not exist in the cache. Return DUP_ERROR or status.
 */
static int
__svc_dupcache_update(struct svc_req *req, caddr_t resp_buf, uint_t resp_bufsz,
    int status, struct dupcache *dc, uint32_t drxid, uint32_t drhash)
{
	struct dupreq *dr = NULL;
	time_t timenow = time(NULL);

	(void) rw_wrlock(&(dc->dc_lock));
	dr = dc->dc_hashtbl[drhash];
	while (dr != NULL) {
		if (dr->dr_xid == drxid &&
		    dr->dr_proc == req->rq_proc &&
		    dr->dr_prog == req->rq_prog &&
		    dr->dr_vers == req->rq_vers &&
		    dr->dr_addr.len == req->rq_xprt->xp_rtaddr.len &&
		    memcmp(dr->dr_addr.buf, req->rq_xprt->xp_rtaddr.buf,
		    dr->dr_addr.len) == 0) { /* entry found */
			if (dr->dr_hash != drhash) {
				/* sanity check */
				(void) rw_unlock(&(dc->dc_lock));
				syslog(LOG_ERR,
				"\n__svc_dupdone: hashing error");
				return (DUP_ERROR);
			}

			/* store the results if bufer is not NULL */
			if (resp_buf != NULL) {
				if ((dr->dr_resp.buf =
				    malloc(resp_bufsz)) == NULL) {
					(void) rw_unlock(&(dc->dc_lock));
					syslog(LOG_ERR,
					    "__svc_dupdone: malloc failed");
					return (DUP_ERROR);
				}
				(void) memset(dr->dr_resp.buf, 0, resp_bufsz);
				(void) memcpy(dr->dr_resp.buf, resp_buf,
				    (uint_t)resp_bufsz);
				dr->dr_resp.len = resp_bufsz;
			}

			/* update status and done time */
			dr->dr_status = status;
			dr->dr_time = timenow;

			/* move the entry to the mru position */
			if (dc->dc_mru == NULL) {
				dr->dr_next = dr;
				dr->dr_prev = dr;
			} else {
				dr->dr_next = dc->dc_mru->dr_next;
				dc->dc_mru->dr_next->dr_prev = dr;
				dr->dr_prev = dc->dc_mru;
				dc->dc_mru->dr_next = dr;
			}
			dc->dc_mru = dr;

			(void) rw_unlock(&(dc->dc_lock));
			return (status);
		}
		dr = dr->dr_chain;
	}
	(void) rw_unlock(&(dc->dc_lock));
	syslog(LOG_ERR, "__svc_dupdone: entry not in dup cache");
	return (DUP_ERROR);
}

#ifdef DUP_DEBUG
/*
 * __svc_dupcache_debug(struct dupcache *dc)
 * print out the hash table stuff
 *
 * This function requires the caller to hold the reader
 * or writer version of the duplicate request cache lock (dc_lock).
 */
static void
__svc_dupcache_debug(struct dupcache *dc)
{
	struct dupreq *dr = NULL;
	int i;
	bool_t bval;

	fprintf(stderr, "   HASHTABLE\n");
	for (i = 0; i < dc->dc_buckets; i++) {
		bval = FALSE;
		dr = dc->dc_hashtbl[i];
		while (dr != NULL) {
			if (!bval) {	/* ensures bucket printed only once */
				fprintf(stderr, "    bucket : %d\n", i);
				bval = TRUE;
			}
			fprintf(stderr, "\txid: %u status: %d time: %ld",
			    dr->dr_xid, dr->dr_status, dr->dr_time);
			fprintf(stderr, " dr: %x chain: %x prevchain: %x\n",
			    dr, dr->dr_chain, dr->dr_prevchain);
			dr = dr->dr_chain;
		}
	}

	fprintf(stderr, "   LRU\n");
	if (dc->dc_mru) {
		dr = dc->dc_mru->dr_next;	/* lru */
		while (dr != dc->dc_mru) {
			fprintf(stderr, "\txid: %u status : %d time : %ld",
			    dr->dr_xid, dr->dr_status, dr->dr_time);
			fprintf(stderr, " dr: %x next: %x prev: %x\n",
			    dr, dr->dr_next, dr->dr_prev);
			dr = dr->dr_next;
		}
		fprintf(stderr, "\txid: %u status: %d time: %ld",
		    dr->dr_xid, dr->dr_status, dr->dr_time);
		fprintf(stderr, " dr: %x next: %x prev: %x\n",
		    dr, dr->dr_next, dr->dr_prev);
	}
}
#endif /* DUP_DEBUG */
