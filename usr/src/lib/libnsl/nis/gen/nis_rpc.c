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
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module contains some grungy RPC binding functions that are
 * used by the client library.
 */
#include "mt.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <rpc/rpc.h>
#include <rpc/clnt.h>
#include <rpcsvc/nis.h>
#include <string.h>
#include "nis_clnt.h"
#include "nis_local.h"


CLIENT * nis_make_rpchandle_uaddr(nis_server *, int, rpcprog_t, rpcvers_t,
    uint_t, int, int, char *);


/*
 * This internal structure is used to track the bindings. NOTE
 * the client structure comes first because it is cast to a CLIENT *
 * by other functions. This keeps the private stuff out of our hair
 * in those other functions.
 */
struct server {
	CLIENT		*clnt;		/* RPC Client handle connection  */
	nis_name	mach_name;	/* server's name */
	char		*rpcb_uaddr;	/* address of rpcbind for server */
	char		*serv_uaddr;	/* address of actual server */
	char		*netid;		/* netconfig id */
	unsigned int	flags;		/* flags for this */
	int		bpc;		/* Binding policy control */
	int		key_type;	/* Type of authentication to use */
	pid_t		pid;		/* Process creating the handle */
	uid_t		uid;		/* uid of the process */
	unsigned int	ref_cnt;	/* reference count */
	struct server	*next;		/* linked list of these. */
	struct server	*prev;		/* linked list of these. */
	int		fd;		/* fd from clnt handle */
	dev_t		rdev;		/* device of clnt fd */
};
typedef struct server server;

extern int __nis_debuglevel;
extern FILE *__nis_debug_file;
extern int __nis_debug_bind;

/*
 * Prototypes for static functions.
 */
static void 		free_srv(server *);
static void 		remove_server(server *);
static void		set_rdev(server *);
static int		check_rdev(server *);

mutex_t	srv_cache_lock = DEFAULTMUTEX;  /* lock level 1 */
static server	*srv_listhead = NULL; 	/* protected by srv_cache_lock */
static server	*srv_listtail = NULL;   /* protected by srv_cache_lock */

static int	srv_count = 0;
/*
 *  A weak attempt was made to make the preferred server code be
 *  mt-safe.  But it doesn't quite work because the name of the
 *  preferred server is held in a global variable.  It must be
 *  made into a per-thread variable to allow separate threads
 *  to have different preferred servers.
 */
mutex_t	__nis_preferred_lock = DEFAULTMUTEX;  /* lock level ? */
static char __nis_test_server[NIS_MAXNAMELEN+1];
					/* protected by _nis_preferred_lock */

/*
 * our own version of rand() so we don't perturb the one in libc
 */
static mutex_t __nis_randx_lock = DEFAULTMUTEX; /* lock level ? */
static int32_t __nis_randx = 0;

int32_t
__nis_librand(void)
{
	int32_t		rx;
	struct timeval	tp;

	sig_mutex_lock(&__nis_randx_lock);
	if (__nis_randx == 0) {
		(void) gettimeofday(&tp, 0);
		__nis_randx = (int32_t)tp.tv_usec;
	}

	rx = __nis_randx = ((__nis_randx * 1103515245 + 12345) >> 16) & 0x7fff;
	sig_mutex_unlock(&__nis_randx_lock);
	return (rx);
}



void
__nis_set_preference(nis_name s)
{

	sig_mutex_lock(&__nis_preferred_lock);
	(void) strcpy(__nis_test_server, s);
	sig_mutex_unlock(&__nis_preferred_lock);
}

void
__nis_no_preference(void)
{

	sig_mutex_lock(&__nis_preferred_lock);
	(void) strcpy(__nis_test_server, "");
	sig_mutex_unlock(&__nis_preferred_lock);
}

static void
remove_server(server *srv)
{
	if (srv->prev)
		srv->prev->next = srv->next;
	if (srv->next)
		srv->next->prev = srv->prev;
	if (srv_listhead == srv)
		srv_listhead = srv->next;
	if (srv_listtail == srv)
		srv_listtail = srv->prev;
	srv->next = NULL;
	srv->prev = NULL;
}

/*
 * This STUPID function is provided TEMPORARILY to get around a csh BUG.
 */
extern int __nis_destroy_callback();

void
__nis_reset_state(void)
{
	server	*cur;

	/* WARNING: calling this function from a MT program	*/
	/* is dangerous, it should be avoid at all cost		*/
	sig_mutex_lock(&srv_cache_lock);
	cur = srv_listhead;
	while (cur) {
		/* XXX: Force reference to zero, otherwise	*/
		/* 	entry will not be freed.		*/
		cur->ref_cnt = 0;
		srv_listhead = cur->next;
		free_srv(cur);
		cur = srv_listhead;
	}
	sig_mutex_unlock(&srv_cache_lock);
}

/*
 * Cleans up local list of bad servers
 * Procedure called by nis_handle
 */
static
void
cleanup_srv(server *srv_toclean)
{
	server		*scan;
	server		*next_srv;

	/*
	 * Clean up RPC bindings. All entries inside this list
	 * will be deleted, regardless of their reference count.
	 * Free dynamic memory content.
	 */
	next_srv = 0;
	for (scan = srv_toclean; scan; scan = next_srv) {
		next_srv = scan->next;
		(void) check_rdev(scan);
		auth_destroy(scan->clnt->cl_auth);
		clnt_destroy(scan->clnt);
		free(scan->mach_name);
		free(scan->rpcb_uaddr);
		free(scan->serv_uaddr);
		free(scan->netid);
		(void) memset((char *)scan, 0, sizeof (server));
		free(scan);
	}
}


static
CLIENT *
nis_handle(nis_bound_directory *binding, int n, uint_t flags, int create)
{
	int fd;
	nis_bound_endpoint *bep;
	nis_server *srv;
	nis_server tsrv;
	endpoint	*ep;
	server		*cur;
	server		*next_srv;
	int		bpc;		/* binding policy control */
	pid_t		mypid;		/* current process pid */
	uid_t		myuid;		/* caller's uid */
	struct netconfig *nc;
	CLIENT		*clnt;
	server		*srv_toclean = NULL;
	server		*srv_new = NULL;
	int		srv_cached = 1;
	server		*dupcur;

	bep = &binding->bep_val[n];
	if ((flags & MASTER_ONLY) != 0 && bep->hostnum != 0)
		return (0);

	srv = &binding->dobj.do_servers.do_servers_val[bep->hostnum];
	ep = &srv->ep.ep_val[bep->epnum];
	nc = __nis_get_netconfig(ep);
	if (flags & USE_DGRAM) {
		if (nc->nc_semantics != NC_TPI_CLTS)
			return (0);
	} else {
		if (nc->nc_semantics != NC_TPI_COTS &&
		    nc->nc_semantics != NC_TPI_COTS_ORD)
			return (0);
	}

	/*
	 * Determine the binding policy :
	 *	0 - authenticated virtual circuit
	 * 	1 - authenticated datagram
	 *	2 - unauthenticated virtual circuit;
	 *	3 - unauthenticated datagram;
	 */
	bpc = ((flags & USE_DGRAM) != 0) ? 1 : 0;
	bpc += ((flags & NO_AUTHINFO) != 0) ? 2 : 0;

	if (__nis_debuglevel)
		syslog(LOG_INFO,
			"NIS+: nis_client_handle: wants (%s, %s())",
			(bpc == 2 || bpc == 0)? "VC" : "DG",
			(bpc == 0 || bpc == 1)? "auth" : "no auth");

	/*
	 * To perform the search and keep the LRU cache as small as possible:
	 * 1. Look in cache for a binding match. While doing so:
	 *	a. Check for invalid bindings
	 *		- if invalid - move to cleanup list
	 *	b. Look for matches
	 *		- if match, assign a pointer to it
	 * 2. If we don't have a cached match
	 *	a. Create a new entry into the cache
	 *	b. Rstabilish an RPC binding
	 * 3. Release all locks and clean up invalid entries
	 * 4. Return binding as result
	 */

	/* Look for the binding in our unlimited- entry LRU cache */
	mypid = getpid();
	myuid = geteuid();

	/*
	 * Starting cache access operation - grab lock
	 * Scan the list for matches
	 */

	sig_mutex_lock(&srv_cache_lock);

	for (cur = srv_listhead; cur; cur = next_srv) {
		/*
		 *  First save the next pointer in case
		 *  we delete this one.
		 */
		next_srv = cur->next;
		ASSERT(cur->flags != SRV_IS_FREE);

		/*
		 * Four things can cause us to throw out a cached
		 * handle :
		 * 	a) someone has called "bad_server()" on it.
		 *	b) Some other process created it (we're a
		 *	   forked child process, or a vforked process.)
		 *	c) application closed or changed file
		 *	   descriptor in clnt
		 *	d) the process has done a setuid on it and it
		 *	    wants to do a authenticated operation.
		 */

		if ((cur->flags == SRV_INVALID) ||
		    (cur->flags == SRV_AUTH_INVALID) ||
		    (cur->pid != mypid) ||
		    (!check_rdev(cur)) ||
		    ((bpc <= 1) && (cur->uid != myuid))) {
			if (cur->ref_cnt == 0) {
				remove_server(cur);
				cur->flags = SRV_TO_BE_FREED;
				cur->next = srv_toclean;
				cur->bpc = 0;
				srv_toclean = cur;
				srv_count--;
			}
			continue;
		}

		if (strcmp(ep->uaddr, cur->rpcb_uaddr) == 0) {
			/*
			 *  If the server's transport address has
			 *  changed, then throw out the client
			 *  handle. Of course, comparing the uaddrs
			 *  is only meaningful if the transport types
			 *  match.
			 */
			if ((bpc%2 == cur->bpc%2) &&
				strcmp(bep->uaddr, cur->serv_uaddr) != 0) {
				if (__nis_debug_bind) {
					(void) fprintf(__nis_debug_file,
						"server %s restarted\n",
						cur->mach_name);
				}
				if (cur->ref_cnt == 0) {
					remove_server(cur);
					cur->flags = SRV_TO_BE_FREED;
					cur->next = srv_toclean;
					cur->bpc = 0;
					srv_toclean = cur;
					srv_count--;
				}
				continue;
			}

			if ((cur->bpc == bpc) &&
			    (cur->key_type == srv->key_type))
				break;

			/* sometimes non-exact matches can be reused */

			/*
			 * DG+UNAUTH: do not worry about key_type.
			 * VC+UNAUTH and DG+UNAUTH can be reused.
			 */
			if ((bpc == 3) && ((cur->bpc == 3) ||
			    (cur->bpc == 2)))
				break;

			/*
			 * DG+AUTH: match key_types
			 * VC+AUTH can be reused.
			 */
			if ((cur->bpc == 0) &&
			    (bpc == 1) &&
			    (cur->key_type == srv->key_type))
				break;

#ifdef NIS_NON_EXACT
			/*
			 * These may be too ambitious.
			 * authenticated handles may not work
			 * sometimes when unauthenticated ones would.
			 * (e.g. if caller cannot be authenticated).
			 */


			/* DG+unauth can reuse any existing binding */
			if (bpc == 3)
				break;

			/*
			 * VC+auth can be used for
			 * VC+unauth
			 * DG+auth if key_types are the same
			 */
			if (cur->bpc == 0 &&
			    (bpc == 2 ||
			    (bpc == 1 &&
			    (cur->key_type == srv->key_type))))
				break;

#endif	/* NIS_NON_EXACT */
		}
	}

	/*
	 * If 'cur' has a non-NULL value, a match has been found.
	 * If no match was found, then try to create new node.
	 */

	if (!cur) {

		srv_cached = 0;

		/*
		 * Release lock to allow other threads to run while new binding
		 * is being created.
		 */
		sig_mutex_unlock(&srv_cache_lock);

		/* Check if allowed to create new node */
		if (!create) {
			cleanup_srv(srv_toclean);
			return (NULL);
		}


		/*
		 *  We need to create a new client handle.  Be careful to
		 *  not create handles to "bad" endpoints.
		 */

		if (strcmp(nc->nc_protofmly, NC_LOOPBACK) == 0 ||
		    strcmp(nc->nc_proto, NC_NOPROTO) == 0) {
			cleanup_srv(srv_toclean);
			return (0);
		}

		tsrv = *srv;
		tsrv.ep.ep_len = 1;
		tsrv.ep.ep_val = ep;
		srv = &tsrv;

new_address:
		switch (bpc) {
			case 0 : /* auth + circuit */
				if (__nis_debug_bind) {
					(void) fprintf(__nis_debug_file,
					    "create handle: VC+AUTH\n");
				}
				clnt = nis_make_rpchandle_uaddr(srv, 0,
				    NIS_PROG, NIS_VERSION,
				    ZMH_VC+ZMH_AUTH,
				    NIS_SEND_SIZE,
				    NIS_RECV_SIZE,
				    bep->uaddr);
				break;
			case 1 : /* auth + datagram */
				if (__nis_debug_bind) {
					(void) fprintf(__nis_debug_file,
					    "create handle: DG+AUTH\n");
				}
				clnt = nis_make_rpchandle_uaddr(srv, 0,
				    NIS_PROG, NIS_VERSION,
				    ZMH_DG+ZMH_AUTH, 0, 0,
				    bep->uaddr);
				break;
			case 2 : /* circuit */
				if (__nis_debug_bind) {
					(void) fprintf(__nis_debug_file,
					    "create handle: VC\n");
				}
				clnt = nis_make_rpchandle_uaddr(srv, 0,
				    NIS_PROG, NIS_VERSION,
				    ZMH_VC,
				    NIS_SEND_SIZE,
				    NIS_RECV_SIZE,
				    bep->uaddr);
				break;
			case 3 : /* datagram */
				if (__nis_debug_bind) {
					(void) fprintf(__nis_debug_file,
					    "create handle: DG\n");
				}
				clnt = nis_make_rpchandle_uaddr(srv, 0,
				    NIS_PROG, NIS_VERSION,
				    ZMH_DG, 0, 0,
				    bep->uaddr);
				break;
			default : /* error */
				clnt = NULL;
				break;
		}

		if (clnt == NULL) {
			/*
			 * We can't create a handle even though we have
			 * the address of the server.  The server address
			 * must be bad (server restarted or gone).
			 */
			if (__nis_CacheRefreshAddress(bep))
				goto new_address;
			if (__nis_debuglevel) {
				syslog(LOG_INFO,
				    "NIS+: __bind_rpc: could not "
				    "create handle to %s (%s, %s(%d))",
				    srv->name,
				    (bpc == 2 || bpc == 0) ?
				    "VC" : "DG",
				    (bpc == 0 || bpc == 1) ?
				    "auth" : "no auth",
				    srv->key_type);
			}
			cleanup_srv(srv_toclean);
			return (NULL);
		}

		if (__nis_debuglevel) {
			syslog(LOG_INFO,
			    "NIS+: __bind_rpc: "
			    "created handle to %s (%s, %s(%d))",
			    srv->name,
			    (bpc == 2 || bpc == 0) ? "VC" : "DG",
			    (bpc == 0 || bpc == 1)? "auth" : "no auth",
			    srv->key_type);
		}

		/*
		 * We have created a new RPC binding.
		 * Insert new entry into LRU cache.
		 */

		sig_mutex_lock(&srv_cache_lock);

		/*
		 * We must rescan the list, searching for duplicates.
		 * If a duplicate has been created by another thread,
		 * we simply return the duplicate.
		 * Strict checking - only exact matches allowed.
		 */
		for (dupcur = srv_listhead; dupcur; dupcur = dupcur->next) {
			if ((strcmp(ep->uaddr, dupcur->rpcb_uaddr) == 0) &&
			    (strcmp(bep->uaddr, dupcur->serv_uaddr) == 0) &&
			    (dupcur->bpc == bpc) &&
			    (dupcur->key_type == srv->key_type) &&
			    (dupcur->flags != SRV_INVALID) &&
			    (dupcur->flags != SRV_AUTH_INVALID))
				break;
		}

		if (dupcur != NULL) {
			/* Match found in the cache */
			if (srv_listhead != dupcur) {
				remove_server(dupcur);
				dupcur->next = srv_listhead;
				srv_listhead->prev = dupcur;
				srv_listhead = dupcur;
			}
			dupcur->ref_cnt++;
			ASSERT(dupcur->ref_cnt > 0);

			if ((__nis_debug_bind) && (srv_cached == 1)) {
				(void) fprintf(__nis_debug_file,
				    "using %s at %s (%s)\n", dupcur->mach_name,
				    dupcur->rpcb_uaddr, dupcur->netid);
			}
			if ((__nis_debuglevel) && (srv_cached == 1)) {
				syslog(LOG_INFO,
				    "NIS+: __bind_rpc: "
				    "reusing handle to %s (%s, %s(%d))",
				    dupcur->mach_name,
				    (dupcur->bpc == 2 || dupcur->bpc == 0) ?
						"VC" : "DG",
				    (dupcur->bpc == 0 || dupcur->bpc == 1) ?
						"auth" : "no auth",
				    dupcur->key_type);
			}

			/*
			 * Delete duplicate connection, so that
			 * fd's are not leaked. Release fd.
			 */
			sig_mutex_unlock(&srv_cache_lock);

			if (clnt->cl_auth) {
				auth_destroy(clnt->cl_auth);
			}
			clnt_destroy(clnt);

			cleanup_srv(srv_toclean);
			return (dupcur->clnt);
		}

		/*
		 * Allocate new server binding entry.
		 */

		if (srv_new = calloc(1, sizeof (struct server)))
			srv_count++;

		if (!srv_new) {
			/*  no free entry, so give up... */
			if (__nis_debuglevel) {
				(void) printf(
				    "can not create binding cache entry: "
				    "out of memory\n");
			}
			/* clean up */
			sig_mutex_unlock(&srv_cache_lock);

			cleanup_srv(srv_toclean);
			return (NULL);
		} else {
			cur = srv_new;
			cur->mach_name = strdup(srv->name);
			cur->rpcb_uaddr = strdup(ep->uaddr);
			cur->serv_uaddr = strdup(bep->uaddr);
			cur->netid = strdup(nc->nc_netid);
			cur->clnt	= clnt;
			cur->ref_cnt = 1;
			cur->flags	= SRV_IN_USE;
			cur->next	= srv_listhead;
			cur->prev	= NULL;
			cur->bpc	= bpc;
			cur->pid	= mypid;
			cur->uid	= myuid;
			cur->key_type = srv->key_type;
			set_rdev(cur);
			if (srv_listhead)
				srv_listhead->prev = cur;
			if (! srv_listtail)
				srv_listtail = cur;
			srv_listhead = cur;
		}
	}

	/*
	 * At this point, an entry has either been found in
	 * the cache or a new entry has been created.
	 */
	if (srv_cached == 0) {
		/* New entry */
		sig_mutex_unlock(&srv_cache_lock);
		if (clnt_control(clnt, CLGET_FD, (char *)&fd))
			(void) fcntl(fd, F_SETFD, 1);
		/* make it "close on exec" */
	} else {
		/* Match found in the cache */
		if (srv_listhead != cur) {
			remove_server(cur);
			cur->next = srv_listhead;
			srv_listhead->prev = cur;
			srv_listhead = cur;
		}
		cur->ref_cnt++;
		ASSERT(cur->ref_cnt > 0);
		sig_mutex_unlock(&srv_cache_lock);

		if ((__nis_debug_bind) && (srv_cached == 1)) {
			(void) fprintf(__nis_debug_file,
			    "using %s at %s (%s)\n", cur->mach_name,
			    cur->rpcb_uaddr, cur->netid);
		}
		if ((__nis_debuglevel) && (srv_cached == 1)) {
			syslog(LOG_INFO,
			    "NIS+: __bind_rpc: "
			    "reusing handle to %s (%s, %s(%d))",
			    cur->mach_name,
			    (cur->bpc == 2 || cur->bpc == 0) ?
					"VC" : "DG",
			    (cur->bpc == 0 || cur->bpc == 1) ?
					"auth" : "no auth",
			    cur->key_type);
		}
	}
	cleanup_srv(srv_toclean);
	return (cur->clnt);
}

CLIENT *
nis_client_handle(nis_bound_directory *binding, int n, uint_t flags)
{
	return (nis_handle(binding, n, flags, 1));
}

CLIENT *
nis_cached_handle(nis_bound_directory *binding, int n, uint_t flags)
{
	return (nis_handle(binding, n, flags, 0));
}


static void
free_srv(server *srv)
{
	ASSERT(MUTEX_HELD(&srv_cache_lock)); /* make sure we got the lock */
	ASSERT(srv->ref_cnt == 0);
	remove_server(srv);		/* remove from active list */
	srv_count--;
	sig_mutex_unlock(&srv_cache_lock);

	(void) check_rdev(srv);
	auth_destroy(srv->clnt->cl_auth);
	clnt_destroy(srv->clnt);
	free(srv->mach_name);
	free(srv->rpcb_uaddr);
	free(srv->serv_uaddr);
	free(srv->netid);
	free(srv);

	/* Finished critical ops - reacquire lock */
	sig_mutex_lock(&srv_cache_lock);
}

static
void
bind_message(nis_bound_directory *binding, int n, char *msg)
{
	nis_bound_endpoint *bep;
	nis_server *srv;
	endpoint *ep;
	struct netconfig *nc;

	bep  = &binding->bep_val[n];
	srv = &binding->dobj.do_servers.do_servers_val[bep->hostnum];
	ep = &srv->ep.ep_val[bep->epnum];
	nc = __nis_get_netconfig(ep);

	(void) fprintf(__nis_debug_file, "%s:  server %s at %s (%s)\n",
		msg, srv->name, bep->uaddr, nc->nc_netid);
}

char *
handle_to_server_name(CLIENT *c)
{
	struct server *cur;
	char *name = NULL;

	sig_mutex_lock(&srv_cache_lock);
	for (cur = srv_listhead; cur; cur = cur->next) {
		if (cur->clnt == c) {
			name = cur->mach_name;
			break;
		}
	}
	sig_mutex_unlock(&srv_cache_lock);
	return (name);
}

/*
 * Return the name of the server associated with a client handle.
 * We search for the client handle and then return a copy of
 * the server name.
 */
char *
__nis_server_name(nis_call_state *state)
{
	char *s = NULL;
	nis_bound_endpoint *bep;
	nis_server *srv;

	if (state == NULL || state->binding == NULL)
		return (NULL);

	bep = &state->binding->bep_val[state->bound_to];
	srv = &state->binding->dobj.do_servers.do_servers_val[bep->hostnum];
	s = strdup(srv->name);
	return (s);
}


/*
 * __nis_release_server()
 *
 * This function decreament the server reference count,
 * without destroying the client handle.
 *
 */
void
__nis_release_server(nis_call_state *state, CLIENT *c, enum clnt_stat status)
{
	server *cur;	/* some pointers to play with    */
	nis_bound_directory *binding;
	nis_bound_endpoint *beps;
	nis_bound_endpoint *bep;

	ASSERT(c != NULL); /* is someone freeing a bogus srv ??? */
	switch (status) {
	    case RPC_AUTHERROR:
		if (state->niserror == NIS_SUCCESS)
			state->niserror = NIS_SRVAUTH;
		__nis_bad_auth_server(c);
		return;

	    case RPC_CANTSEND:
	    case RPC_CANTRECV:
		/*
		 *  If we get either of these errors on a datagram
		 *  endpoint, then there was some sort of transport
		 *  error.  We set nis_error to NIS_RPCERROR (if
		 *  it isn't already set to something else).
		 */
		if (state->flags & USE_DGRAM) {
			if (state->niserror == NIS_SUCCESS)
				state->niserror = NIS_RPCERROR;
		}
		break;

	    case RPC_TIMEDOUT:
	    case RPC_SUCCESS:
		break;

	    default:
		if (state->niserror == NIS_SUCCESS)
			state->niserror = NIS_RPCERROR;
		break;
	}
	sig_mutex_lock(&srv_cache_lock);
	for (cur = srv_listhead; cur; cur = cur->next) {
		if (cur->clnt == c) {
			ASSERT(cur->ref_cnt > 0);
			cur->ref_cnt--;

			if (__nis_debug_bind) {
				(void) fprintf(__nis_debug_file,
					"release %s, status = %d\n",
					cur->mach_name, status);
			}
			if (status != RPC_SUCCESS) {
				cur->flags = SRV_INVALID;
				/*
				 *  If the server is restarted, datagram
				 *  clients will get RPC_TIMEDOUT and
				 *  virtual circuit clients will get
				 *  RPC_CANTSEND.  If we get either of
				 *  these errors, try to refresh the address.
				 *  If we can refresh it, then try the
				 *  endpoint again.
				 */
				if (state &&
					(status == RPC_TIMEDOUT ||
					status == RPC_CANTSEND)) {
					binding = state->binding;
					beps = state->binding->bep_val;
					bep = &beps[state->bound_to];
					if (__nis_debug_bind) {
						bind_message(binding,
							state->bound_to,
							"refreshing address");
					}
					if (__nis_CacheRefreshAddress(bep)) {
						if (__nis_debug_bind) {
							bind_message(binding,
							    state->bound_to,
							    "refreshed");
						}
					} else {
						if (__nis_debug_bind) {
							bind_message(binding,
							    state->bound_to,
							    "refresh failed");
						}
					}
				}
			} else {
				cur->flags = SRV_IN_USE;
			}
			break;
		}
	}
	sig_mutex_unlock(&srv_cache_lock);
	ASSERT(cur != NULL); /* is someone freeing a bogus srv ??? */
}

/*
 * Same as nis_bad_server except
 * 1.  it marks the flag as SRV_AUTH_INVALID to prevent deletion __bind_rpc
 * 2.  it marks all other authenticated handles for same server as bad too.
 */
void
__nis_bad_auth_server(CLIENT *c)
{
	server *cur;	/* some pointers to play with    */

	ASSERT(c != NULL); /* is someone freeing a bogus srv ??? */
	sig_mutex_lock(&srv_cache_lock);
	for (cur = srv_listhead; cur; cur = cur->next) {
		if (cur->clnt == c) {
			ASSERT(cur->ref_cnt > 0);
			cur->ref_cnt--;
			cur->flags = SRV_AUTH_INVALID;
			break;
		}
	}

	if (cur) {
		/* found it, now mark other auth handles as invalid too. */
		nis_name bad_server = cur->mach_name;

		/* Mark all other authenticated handles as invalid */
		for (cur = srv_listhead; cur; cur = cur->next) {
			if (nis_dir_cmp(cur->mach_name,
			    bad_server) == SAME_NAME && cur->bpc <= 1) {
				cur->flags = SRV_AUTH_INVALID;
			}
		}
	}
	sig_mutex_unlock(&srv_cache_lock);
	ASSERT(cur != NULL); /* is someone freeing a bogus srv ??? */
}


#define	S_INIT		0
#define	S_HAVEBINDING	1
#define	S_REFRESH	2
#define	S_BINDFAIL	3

void
__nis_init_call_state(nis_call_state *state)
{
	(void) memset((char *)state, 0, sizeof (nis_call_state));
	state->state = S_INIT;
	state->timeout.tv_sec = NIS_GEN_TIMEOUT;
	state->timeout.tv_usec = 0;
	state->aticks = 0;
}

void
__nis_reset_call_state(nis_call_state *state)
{
	if (state->binding)
		nis_free_binding(state->binding);
	__nis_init_call_state(state);
}

static
void
set_bep_range(nis_call_state *state, int init)
{
	int rank;
	nis_bound_endpoint *bep = state->binding->bep_val;
	int nbep = state->binding->bep_len;

	if (init) {
		state->base = 0;
	} else {
		state->base = state->end;
	}
	state->end = state->base;
	if (state->base < nbep) {
		rank = bep[state->base].rank;
		state->end = state->base + 1;
		while (state->end < nbep && bep[state->end].rank == rank) {
			state->end += 1;
		}
		state->count = state->end - state->base;
	} else  {
		state->count = 0;
	}
	state->cur = 0;
	state->start = state->count ? __nis_librand() % state->count : 0;
}

static
int
__nis_server_index(directory_obj *dobj, char *name)
{
	int i;
	nis_server *srv = dobj->do_servers.do_servers_val;
	int nsrv = dobj->do_servers.do_servers_len;

	for (i = 0; i < nsrv; i++) {
		if (strcasecmp(srv[i].name, name) == 0)
			return (i);
	}
	return (-1);
}

CLIENT *
__nis_get_server(nis_call_state *state)
{
	int i;
	int n;
	nis_error err;
	nis_bound_directory *old_binding;
	nis_server *srv;
	directory_obj *dobj;
	CLIENT *clnt;

	(void) __start_clock(CLOCK_CACHE);
	for (;;) {
		switch (state->state) {
		    case S_INIT:
			if (state->srv) {
				if (__nis_debug_bind) {
					(void) fprintf(__nis_debug_file,
						"binding to server %s\n",
						(char *)state->srv);
				}
				err = nis_bind_server(state->srv,
					state->nsrv,
					&state->binding);
			} else if (state->name) {
				if (__nis_debug_bind) {
					(void) fprintf(__nis_debug_file,
						"binding to directory %s%s%s\n",
						state->name,
						state->parent_first
							? " (parent first)"
							: " (name first)",
						(state->flags & MASTER_ONLY)
							? " (master only)"
							: "");
				}
				err = nis_bind_dir(state->name,
					state->parent_first,
					&state->binding,
					state->flags);
				if (err == NIS_SUCCESS && state->server_name) {
					n = __nis_server_index(
						&state->binding->dobj,
						state->server_name);
					if (n == -1) {
						syslog(LOG_ERR,
		"__nis_get_server:  can't find server %s in directory %s",
							state->server_name,
							state->name);
						state->niserror =
							NIS_SYSTEMERROR;
						return (NULL);
					} else if (n != 0) {
						old_binding = state->binding;
						dobj = &state->binding->dobj;
						srv = dobj->
						    do_servers.do_servers_val;
						err = nis_bind_server(
							&srv[n], 1,
							&state->binding);
						if (err == NIS_SUCCESS &&
						    old_binding != NULL)
							nis_free_binding(
								old_binding);
					}
				}
			} else if (state->binding) {
				err = NIS_SUCCESS;
				if (__nis_debug_bind) {
					(void) fprintf(__nis_debug_file,
						"binding passed in\n");
				}
			} else {
				err = NIS_SYSTEMERROR;
				if (__nis_debug_bind) {
					(void) fprintf(__nis_debug_file,
						"no binding information\n");
				}
			}
			if (err != NIS_SUCCESS) {
				if (__nis_debug_bind) {
					(void) fprintf(__nis_debug_file,
						"bind failed\n");
				}
				state->state = S_BINDFAIL;
				if (state->niserror == NIS_SUCCESS)
					state->niserror = err;
				state->aticks += __stop_clock(CLOCK_CACHE);
				if (state->binding != NULL)
					nis_free_binding(state->binding);
				state->binding = NULL;
				return (NULL);
			}
			if (__nis_debug_bind) {
				(void) fprintf(__nis_debug_file,
					"bind succeeded\n");
			}
			set_bep_range(state, 1);
			state->state = S_HAVEBINDING;
			break;

		    case S_HAVEBINDING:
			for (i = 0; i < state->count; i++) {
				clnt = nis_cached_handle(state->binding,
					state->base + i, state->flags);
				if (clnt) {
					state->bound_to = state->base + i;
					state->aticks +=
						__stop_clock(CLOCK_CACHE);
					return (clnt);
				}
			}
			if (state->cur < state->count) {
				n = state->base +
				    (state->start + state->cur) % state->count;
				clnt = nis_client_handle(state->binding,
						n, state->flags);
				state->cur += 1;
				if (clnt) {
					state->bound_to = n;
					state->aticks +=
						__stop_clock(CLOCK_CACHE);
					return (clnt);
				}
			} else if (state->end < state->binding->bep_len) {
				set_bep_range(state, 0);
			} else {
				state->state = S_REFRESH;
			}
			break;

		    case S_REFRESH:
			if (__nis_debug_bind) {
				(void) fprintf(__nis_debug_file,
					"refreshing binding\n");
			}
			if ((state->srv || state->name) &&
			    state->refresh_count == 0) {
				/*
				 *  We don't have to refresh a binding
				 *  obtained through __nis_CacheBindServer
				 *  because there is no directory
				 *  associated with it.
				 */
				if (state->srv == 0)
				    __nis_CacheRefreshBinding(state->binding);
				nis_free_binding(state->binding);
				state->binding = NULL;
				state->refresh_count = 1;
				state->state = S_INIT;
			} else {
				state->state = S_BINDFAIL;
				if (state->niserror == NIS_SUCCESS)
					state->niserror = NIS_NAMEUNREACHABLE;
				state->aticks += __stop_clock(CLOCK_CACHE);
				if (state->binding != NULL)
					nis_free_binding(state->binding);
				state->binding = NULL;
				return (NULL);
			}
			break;

		    case S_BINDFAIL:
			if (__nis_debug_bind) {
				(void) fprintf(__nis_debug_file,
				    "binding failure\n");
			}
			state->aticks += __stop_clock(CLOCK_CACHE);
			return (NULL);
		}
	}
	/*NOTREACHED*/
}

static
void
set_rdev(server *srv)
{
	int fd;
	struct stat stbuf;

	if (clnt_control(srv->clnt, CLGET_FD, (char *)&fd) != TRUE ||
	    fstat(fd, &stbuf) == -1) {
		syslog(LOG_DEBUG, "NIS+:  can't get rdev");
		srv->fd = -1;
		return;
	}
	srv->fd = fd;
	srv->rdev = stbuf.st_rdev;
}

static
int
check_rdev(server *srv)
{
	struct stat stbuf;

	if (srv->fd == -1)
		return (1);    /* can't check it, assume it is okay */

	if (fstat(srv->fd, &stbuf) == -1) {
		syslog(LOG_DEBUG, "NIS+:  can't stat %d", srv->fd);
		/* could be because file descriptor was closed */
		/* it's not our file descriptor, so don't try to close it */
		(void) clnt_control(srv->clnt, CLSET_FD_NCLOSE, NULL);
		return (0);
	}
	if (srv->rdev != stbuf.st_rdev) {
		syslog(LOG_DEBUG,
		    "NIS+:  fd %d changed, old=0x%lx, new=0x%lx",
		    srv->fd, srv->rdev, stbuf.st_rdev);
		/* it's not our file descriptor, so don't try to close it */
		(void) clnt_control(srv->clnt, CLSET_FD_NCLOSE, NULL);
		return (0);
	}
	return (1);    /* fd is okay */
}
