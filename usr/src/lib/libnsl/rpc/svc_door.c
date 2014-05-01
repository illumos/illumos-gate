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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * svc_door.c, Server side for doors IPC based RPC.
 */

#include "mt.h"
#include "rpc_mt.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <door.h>
#include <alloca.h>
#include <dlfcn.h>
#include <limits.h>
#include <rpc/svc_mt.h>

static void svc_door_destroy_pvt();
static int return_xprt_copy();

int __rpc_default_door_buf_size = 16000;
int __rpc_min_door_buf_size = 1000;

static struct xp_ops *svc_door_ops();

mutex_t	svc_door_mutex = DEFAULTMUTEX;
cond_t	svc_door_waitcv = DEFAULTCV;
int	svc_ndoorfds = 0;

/*
 * Dispatch information for door calls.
 */
typedef struct {
	rpcprog_t		prognum;
	rpcvers_t		versnum;
	void			(*dispatch)();
} call_info_t;

/*
 * kept in xprt->xp_p2
 */
struct svc_door_data {
	uint_t   	su_iosz;		/* size of send/recv buffer */
	uint32_t	su_xid;			/* transaction id */
	XDR		su_xdrs;		/* XDR handle */
	char		su_verfbody[MAX_AUTH_BYTES]; /* verifier body */
	call_info_t	call_info;		/* dispatch info */
	char		*argbuf;		/* argument buffer */
	size_t		arglen;			/* argument length */
	char		*buf;			/* result buffer */
	int		len;			/* result length */
};
#define	su_data(xprt)	((struct svc_door_data *)(xprt->xp_p2))

static SVCXPRT *get_xprt_copy();
static bool_t svc_door_recv();
static void svc_door_destroy();

static SVCXPRT_LIST *dxlist;	/* list of door based service handles */

/*
 * List management routines.
 */
bool_t
__svc_add_to_xlist(SVCXPRT_LIST **list, SVCXPRT *xprt, mutex_t *lockp)
{
	SVCXPRT_LIST	*l;

	if ((l = malloc(sizeof (*l))) == NULL)
		return (FALSE);
	l->xprt = xprt;
	if (lockp != NULL)
		(void) mutex_lock(lockp);
	l->next = *list;
	*list = l;
	if (lockp != NULL)
		(void) mutex_unlock(lockp);
	return (TRUE);
}

void
__svc_rm_from_xlist(SVCXPRT_LIST **list, SVCXPRT *xprt, mutex_t *lockp)
{
	SVCXPRT_LIST	**l, *tmp;

	if (lockp != NULL)
		(void) mutex_lock(lockp);
	for (l = list; *l != NULL; l = &(*l)->next) {
		if ((*l)->xprt == xprt) {
			tmp = (*l)->next;
			free(*l);
			*l = tmp;
			break;
		}
	}
	if (lockp != NULL)
		(void) mutex_unlock(lockp);
}

void
__svc_free_xlist(SVCXPRT_LIST **list, mutex_t *lockp)
{
	SVCXPRT_LIST	*tmp;

	if (lockp != NULL)
		(void) mutex_lock(lockp);
	while (*list != NULL) {
		tmp = (*list)->next;
		free(*list);
		*list = tmp;
	}
	if (lockp != NULL)
		(void) mutex_unlock(lockp);
}

/*
 * Destroy all door based service handles.
 */
void
__svc_cleanup_door_xprts(void)
{
	SVCXPRT_LIST	*l, *tmp = NULL;

	(void) mutex_lock(&svc_door_mutex);
	for (l = dxlist; l != NULL; l = tmp) {
		tmp = l->next;
		svc_door_destroy_pvt(l->xprt);
	}
	(void) mutex_unlock(&svc_door_mutex);
}

static bool_t
make_tmp_dir(void)
{
	struct stat statbuf;

	if (stat(RPC_DOOR_DIR, &statbuf) < 0) {
		(void) mkdir(RPC_DOOR_DIR, (mode_t)0755);
		(void) chmod(RPC_DOOR_DIR, (mode_t)01777);
		if (stat(RPC_DOOR_DIR, &statbuf) < 0)
			return (FALSE);
	}
	return ((statbuf.st_mode & S_IFMT) == S_IFDIR &&
	    (statbuf.st_mode & 01777) == 01777);
}

static void
svc_door_dispatch(SVCXPRT *xprt, struct rpc_msg *msg, struct svc_req *r)
{
	enum auth_stat		why;
/* LINTED pointer alignment */
	struct svc_door_data	*su = su_data(xprt);
	bool_t nd;

	r->rq_xprt = xprt;
	r->rq_prog = msg->rm_call.cb_prog;
	r->rq_vers = msg->rm_call.cb_vers;
	r->rq_proc = msg->rm_call.cb_proc;
	r->rq_cred = msg->rm_call.cb_cred;

	if (msg->rm_call.cb_cred.oa_flavor == AUTH_NULL) {
		r->rq_xprt->xp_verf.oa_flavor = _null_auth.oa_flavor;
		r->rq_xprt->xp_verf.oa_length = 0;

	} else if ((why = __gss_authenticate(r, msg, &nd)) != AUTH_OK) {
		svcerr_auth(xprt, why);
		return;
	}

	if (su->call_info.prognum == r->rq_prog && su->call_info.versnum ==
	    r->rq_vers) {
		(*su->call_info.dispatch)(r, xprt);
		return;
	}

	/*
	 * if we got here, the program or version
	 * is not served ...
	 */
	if (su->call_info.prognum == r->rq_prog)
		svcerr_progvers(xprt, su->call_info.versnum,
		    su->call_info.versnum);
	else
		svcerr_noprog(xprt);
}

/*
 * This is the door server procedure.
 */
/* ARGSUSED */
static void
door_server(void *cookie, char *argp, size_t arg_size,
    door_desc_t *dp, uint_t n_did)
{
	SVCXPRT			*parent = (SVCXPRT *)cookie;
	SVCXPRT			*xprt;
	struct rpc_msg		*msg;
	struct svc_req		*r;
	char			*cred_area;
	char			*result_buf;
	int			len;
	struct svc_door_data	*su;

	/*
	 * allocate result buffer
	 */
/* LINTED pointer alignment */
	result_buf = alloca(su_data(parent)->su_iosz);
	if (result_buf == NULL) {
		(void) syslog(LOG_ERR, "door_server: alloca failed");
		(void) door_return(NULL, 0, NULL, 0);
		/*NOTREACHED*/
	}

	(void) mutex_lock(&svc_door_mutex);
	if ((xprt = get_xprt_copy(parent, result_buf)) == NULL) {
		(void) syslog(LOG_ERR,
		    "door_server: memory allocation failure");
		(void) mutex_unlock(&svc_door_mutex);
		(void) door_return(NULL, 0, NULL, 0);
		/*NOTREACHED*/
	}
	(void) mutex_unlock(&svc_door_mutex);

/* LINTED pointer alignment */
	msg = SVCEXT(xprt)->msg;
/* LINTED pointer alignment */
	r = SVCEXT(xprt)->req;
/* LINTED pointer alignment */
	cred_area = SVCEXT(xprt)->cred_area;

	msg->rm_call.cb_cred.oa_base = cred_area;
	msg->rm_call.cb_verf.oa_base = &(cred_area[MAX_AUTH_BYTES]);
	r->rq_clntcred = &(cred_area[2 * MAX_AUTH_BYTES]);

/* LINTED pointer alignment */
	su = su_data(xprt);
	su->argbuf = argp;
	su->arglen = arg_size;

	if (svc_door_recv(xprt, msg))
		svc_door_dispatch(xprt, msg, r);

	if ((len = return_xprt_copy(xprt)) > 0) {
		(void) door_return(result_buf, (size_t)len, NULL, 0);
		/*NOTREACHED*/
	} else {
		(void) door_return(NULL, 0, NULL, 0);
		/*NOTREACHED*/
	}
}

/*
 * Usage:
 *	xprt = svc_door_create(dispatch, prognum, versnum, sendsize);
 * Once *xprt is initialized, it is registered.
 * see (svc.h, xprt_register). If recvsize or sendsize are 0 suitable
 * system defaults are chosen.
 * The routines returns NULL if a problem occurred.
 */

void
svc_door_xprtfree(SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	struct svc_door_data	*su = xprt ? su_data(xprt) : NULL;

	if (xprt == NULL)
		return;
	if (xprt->xp_netid)
		free(xprt->xp_netid);
	if (xprt->xp_tp)
		free(xprt->xp_tp);
	if (su != NULL)
		free(su);
	svc_xprt_free(xprt);
}

SVCXPRT *
svc_door_create(void (*dispatch)(), const rpcprog_t prognum,
				const rpcvers_t versnum, const uint_t sendsize)
{
	SVCXPRT			*xprt;
	struct svc_door_data	*su = NULL;
	char			rendezvous[128] = "";
	int			fd;
	int			did = -1;
	mode_t			mask;
	uint_t			ssize;

	(void) mutex_lock(&svc_door_mutex);

	if (!make_tmp_dir()) {
		(void) syslog(LOG_ERR, "svc_door_create: cannot open %s",
		    RPC_DOOR_DIR);
		(void) mutex_unlock(&svc_door_mutex);
		return (NULL);
	}

	if ((xprt = svc_xprt_alloc()) == NULL) {
		(void) syslog(LOG_ERR, "svc_door_create: out of memory");
		goto freedata;
	}
/* LINTED pointer alignment */
	svc_flags(xprt) |= SVC_DOOR;

	(void) sprintf(rendezvous, RPC_DOOR_RENDEZVOUS, (int)prognum,
	    (int)versnum);
	mask = umask(0);
	fd =  open(rendezvous, O_WRONLY|O_CREAT|O_EXCL|O_TRUNC, 0644);
	(void) umask(mask);
	if (fd < 0) {
		if (errno == EEXIST) {
			if (unlink(rendezvous) < 0) {
				(void) syslog(LOG_ERR,
				    "svc_door_create: %s %s:%m", rendezvous,
				    "exists and could not be removed");
				goto freedata;
			}
			mask = umask(0);
			fd =  open(rendezvous, O_WRONLY | O_CREAT | O_EXCL |
			    O_TRUNC, 0644);
			(void) umask(mask);
			if (fd < 0) {
				(void) syslog(LOG_ERR,
				    "svc_door_create: %s %s:%m",
				    "could not create", rendezvous);
				goto freedata;
			}
		} else {
			(void) syslog(LOG_ERR,
			    "svc_door_create: could not create %s:%m",
			    rendezvous);
			goto freedata;
		}
	}
	(void) close(fd);
	did = door_create(door_server, (void *)xprt, DOOR_REFUSE_DESC);
	if (did < 0) {
		(void) syslog(LOG_ERR,
		    "svc_door_create: door_create failed: %m");
		goto freedata;
	}

	if (fattach(did, rendezvous) < 0) {
		if (errno != EBUSY || fdetach(rendezvous) < 0 ||
		    fattach(did, rendezvous) < 0) {
			(void) syslog(LOG_ERR,
			    "svc_door_create: fattach failed: %m");
			goto freedata;
		}
	}

	/*
	 * Determine send size
	 */
	if (sendsize < __rpc_min_door_buf_size)
		ssize = __rpc_default_door_buf_size;
	else
		ssize = RNDUP(sendsize);

	su = malloc(sizeof (*su));
	if (su == NULL) {
		(void) syslog(LOG_ERR, "svc_door_create: out of memory");
		goto freedata;
	}
	su->su_iosz = ssize;
	su->call_info.prognum = prognum;
	su->call_info.versnum = versnum;
	su->call_info.dispatch = dispatch;

	xprt->xp_p2 = (caddr_t)su;
	xprt->xp_verf.oa_base = su->su_verfbody;
	xprt->xp_ops = svc_door_ops();
	xprt->xp_netid = strdup("door");
	if (xprt->xp_netid == NULL) {
		syslog(LOG_ERR, "svc_door_create: strdup failed");
		goto freedata;
	}
	xprt->xp_tp = strdup(rendezvous);
	if (xprt->xp_tp == NULL) {
		syslog(LOG_ERR, "svc_door_create: strdup failed");
		goto freedata;
	}
	xprt->xp_fd = did;

	svc_ndoorfds++;
	if (!__svc_add_to_xlist(&dxlist, xprt, NULL)) {

		(void) syslog(LOG_ERR, "svc_door_create: out of memory");
		goto freedata;
	}
	(void) mutex_unlock(&svc_door_mutex);
	return (xprt);
freedata:
	(void) fdetach(rendezvous);
	(void) unlink(rendezvous);
	if (did >= 0)
		(void) door_revoke(did);
	if (xprt)
		svc_door_xprtfree(xprt);
	(void) mutex_unlock(&svc_door_mutex);
	return (NULL);
}


static SVCXPRT *
svc_door_xprtcopy(SVCXPRT *parent)
{
	SVCXPRT			*xprt;
	struct svc_door_data	*su;

	if ((xprt = svc_xprt_alloc()) == NULL)
		return (NULL);

/* LINTED pointer alignment */
	SVCEXT(xprt)->parent = parent;
/* LINTED pointer alignment */
	SVCEXT(xprt)->flags = SVCEXT(parent)->flags;

	xprt->xp_fd = parent->xp_fd;
	xprt->xp_port = parent->xp_port;
	xprt->xp_ops = svc_door_ops();
	if (parent->xp_tp) {
		xprt->xp_tp = (char *)strdup(parent->xp_tp);
		if (xprt->xp_tp == NULL) {
			syslog(LOG_ERR, "svc_door_xprtcopy: strdup failed");
			svc_door_xprtfree(xprt);
			return (NULL);
		}
	}
	if (parent->xp_netid) {
		xprt->xp_netid = (char *)strdup(parent->xp_netid);
		if (xprt->xp_netid == NULL) {
			syslog(LOG_ERR, "svc_door_xprtcopy: strdup failed");
			if (parent->xp_tp)
				free(parent->xp_tp);
			svc_door_xprtfree(xprt);
			return (NULL);
		}
	}
	xprt->xp_type = parent->xp_type;

	if ((su = malloc(sizeof (struct svc_door_data))) == NULL) {
		svc_door_xprtfree(xprt);
		return (NULL);
	}
/* LINTED pointer alignment */
	su->su_iosz = su_data(parent)->su_iosz;
/* LINTED pointer alignment */
	su->call_info = su_data(parent)->call_info;

	xprt->xp_p2 = (caddr_t)su;	/* su_data(xprt) = su */
	xprt->xp_verf.oa_base = su->su_verfbody;

	return (xprt);
}


static SVCXPRT *
get_xprt_copy(SVCXPRT *parent, char *buf)
{
/* LINTED pointer alignment */
	SVCXPRT_LIST		*xlist = SVCEXT(parent)->my_xlist;
	SVCXPRT_LIST		*xret;
	SVCXPRT			*xprt;
	struct svc_door_data	*su;

	xret = xlist->next;
	if (xret) {
		xlist->next = xret->next;
		xret->next = NULL;
		xprt = xret->xprt;
/* LINTED pointer alignment */
		svc_flags(xprt) = svc_flags(parent);
	} else
		xprt = svc_door_xprtcopy(parent);

	if (xprt) {
/* LINTED pointer alignment */
		SVCEXT(parent)->refcnt++;
/* LINTED pointer alignment */
		su = su_data(xprt);
		su->buf = buf;
		su->len = 0;
	}
	return (xprt);
}

int
return_xprt_copy(SVCXPRT *xprt)
{
	SVCXPRT		*parent;
	SVCXPRT_LIST	*xhead, *xlist;
/* LINTED pointer alignment */
	int		len = su_data(xprt)->len;

	(void) mutex_lock(&svc_door_mutex);
/* LINTED pointer alignment */
	if ((parent = SVCEXT(xprt)->parent) == NULL) {
		(void) mutex_unlock(&svc_door_mutex);
		return (0);
	}
/* LINTED pointer alignment */
	xhead = SVCEXT(parent)->my_xlist;
/* LINTED pointer alignment */
	xlist = SVCEXT(xprt)->my_xlist;
	xlist->next = xhead->next;
	xhead->next = xlist;
/* LINTED pointer alignment */
	SVCEXT(parent)->refcnt--;

	/*
	 * Propagate any error flags.  This is done in both directions to
	 * ensure that if one child gets an error, everyone will see it
	 * (even if there are multiple outstanding children) and the
	 * door will get closed.
	 */
/* LINTED pointer alignment */
	svc_flags(xprt) |= svc_flags(parent);
/* LINTED pointer alignment */
	if (svc_defunct(xprt)) {
/* LINTED pointer alignment */
		svc_flags(parent) |= SVC_DEFUNCT;
		/* LINTED pointer cast */
		if (SVCEXT(parent)->refcnt == 0)
			svc_door_destroy_pvt(xprt);
	}
	(void) mutex_unlock(&svc_door_mutex);
	return (len);
}

/* ARGSUSED */
static enum xprt_stat
svc_door_stat(SVCXPRT *xprt)
{
	return (XPRT_IDLE);
}

static bool_t
svc_door_recv(SVCXPRT *xprt, struct rpc_msg *msg)
{
/* LINTED pointer alignment */
	struct svc_door_data	*su = su_data(xprt);
	XDR			*xdrs = &(su->su_xdrs);

	xdrmem_create(xdrs, su->argbuf, su->arglen, XDR_DECODE);
	if (!xdr_callmsg(xdrs, msg))
		return (FALSE);
	su->su_xid = msg->rm_xid;
	return (TRUE);
}

static bool_t
svc_door_reply(SVCXPRT *xprt, struct rpc_msg *msg)
{
/* LINTED pointer alignment */
	struct svc_door_data	*su = su_data(xprt);
	XDR			*xdrs = &(su->su_xdrs);

	xdrmem_create(xdrs, su->buf, su->su_iosz, XDR_ENCODE);
	msg->rm_xid = su->su_xid;
	if (xdr_replymsg(xdrs, msg)) {
		su->len = (int)XDR_GETPOS(xdrs);
		return (TRUE);
	}
	return (FALSE);
}

static bool_t
svc_door_getargs(SVCXPRT *xprt, xdrproc_t xdr_args, caddr_t args_ptr)
{
/* LINTED pointer alignment */
	return ((*xdr_args)(&(su_data(xprt)->su_xdrs), args_ptr));
}

static bool_t
svc_door_freeargs(SVCXPRT *xprt, xdrproc_t xdr_args, caddr_t args_ptr)
{
/* LINTED pointer alignment */
	XDR		*xdrs = &(su_data(xprt)->su_xdrs);

	xdrs->x_op = XDR_FREE;
	return ((*xdr_args)(xdrs, args_ptr));
}

static void
svc_door_destroy(SVCXPRT *xprt)
{
	(void) mutex_lock(&svc_door_mutex);
	svc_door_destroy_pvt(xprt);
	(void) mutex_unlock(&svc_door_mutex);
}

static void
svc_door_destroy_pvt(SVCXPRT *xprt)
{
/* LINTED pointer alignment */
	if (SVCEXT(xprt)->parent)
/* LINTED pointer alignment */
		xprt = SVCEXT(xprt)->parent;
/* LINTED pointer alignment */
	svc_flags(xprt) |= SVC_DEFUNCT;
/* LINTED pointer alignment */
	if (SVCEXT(xprt)->refcnt > 0)
		return;

	__svc_rm_from_xlist(&dxlist, xprt, NULL);

	if (xprt->xp_tp) {
		(void) fdetach(xprt->xp_tp);
		(void) unlink(xprt->xp_tp);
	}
	(void) door_revoke(xprt->xp_fd);

	svc_xprt_destroy(xprt);
	if (--svc_ndoorfds == 0)
		/* wake up door dispatching */
		(void) cond_signal(&svc_door_waitcv);
}

/* ARGSUSED */
static bool_t
svc_door_control(SVCXPRT *xprt, const uint_t rq, void *in)
{
	extern int __rpc_legal_connmaxrec(int);

	size_t door_param;
	int tmp;

	switch (rq) {
	case SVCSET_CONNMAXREC:
		tmp = __rpc_legal_connmaxrec(*(int *)in);
		if (tmp >= 0) {
			door_param = (tmp == 0)? SIZE_MAX :
			    (size_t)(ssize_t)tmp;
			if (door_setparam(xprt->xp_fd, DOOR_PARAM_DATA_MAX,
			    door_param) == 0)
				return (TRUE);
			return (FALSE);
		}
		return (FALSE);
	case SVCGET_CONNMAXREC:
		if (door_getparam(xprt->xp_fd, DOOR_PARAM_DATA_MAX,
		    &door_param) == 0) {
			if (door_param == SIZE_MAX)
				tmp = 0;
			else if (door_param > INT_MAX)
				tmp = INT_MAX;
			else if (door_param > 0)
				tmp = (int)door_param;
			else
				return (FALSE);

			*(int *)in = tmp;
			return (TRUE);
		}
		return (FALSE);
	}
	return (FALSE);
}

static struct xp_ops *
svc_door_ops(void)
{
	static struct xp_ops	ops;
	extern mutex_t		ops_lock;

	(void) mutex_lock(&ops_lock);
	if (ops.xp_recv == NULL) {
		ops.xp_recv = svc_door_recv;
		ops.xp_stat = svc_door_stat;
		ops.xp_getargs = svc_door_getargs;
		ops.xp_reply = svc_door_reply;
		ops.xp_freeargs = svc_door_freeargs;
		ops.xp_destroy = svc_door_destroy;
		ops.xp_control = svc_door_control;
	}
	(void) mutex_unlock(&ops_lock);
	return (&ops);
}

/*
 * Return door credentials.
 */
/* ARGSUSED */
bool_t
__svc_get_door_cred(SVCXPRT *xprt, svc_local_cred_t *lcred)
{
	door_cred_t		dc;

	if (door_cred(&dc) < 0)
		return (FALSE);
	lcred->euid = dc.dc_euid;
	lcred->egid = dc.dc_egid;
	lcred->ruid = dc.dc_ruid;
	lcred->rgid = dc.dc_rgid;
	lcred->pid = dc.dc_pid;
	return (TRUE);
}

/* ARGSUSED */
bool_t
__svc_get_door_ucred(const SVCXPRT *xprt, ucred_t *ucp)
{
	return (door_ucred(&ucp) == 0);
}
