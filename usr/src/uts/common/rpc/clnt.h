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
 */
/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

/*
 * clnt.h - Client side remote procedure call interface.
 */

#ifndef	_RPC_CLNT_H
#define	_RPC_CLNT_H

#include <sys/types.h>
#include <rpc/rpc_com.h>
#include <rpc/clnt_stat.h>
#include <rpc/auth.h>

/*
 * rpc calls return an enum clnt_stat.  This should be looked at more,
 * since each implementation is required to live with this (implementation
 * independent) list of errors.
 */
#include <sys/netconfig.h>
#ifdef _KERNEL
#include <sys/t_kuser.h>
#endif	/* _KERNEL */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Following defines the multicast group address used by IPV6 enabled
 * client to do the broadcast. IPv6 doesn't have any broadcast support
 * as IPv4 provides, thus it used this reserved address which is joined
 * by all rpc clients.
 */

#define	RPCB_MULTICAST_ADDR "FF02::202"

/*
 * the following errors are in general unrecoverable.  The caller
 * should give up rather than retry.
 */
#define	IS_UNRECOVERABLE_RPC(s)	(((s) == RPC_AUTHERROR) || \
	((s) == RPC_CANTENCODEARGS) || \
	((s) == RPC_CANTDECODERES) || \
	((s) == RPC_VERSMISMATCH) || \
	((s) == RPC_PROCUNAVAIL) || \
	((s) == RPC_PROGUNAVAIL) || \
	((s) == RPC_PROGVERSMISMATCH) || \
	((s) == RPC_SYSTEMERROR) || \
	((s) == RPC_CANTDECODEARGS))

/* Maximum rpc backoff time */
#define	RPC_MAX_BACKOFF	30

/*
 * Error info.
 */
struct rpc_err {
	enum clnt_stat re_status;
	union {
		struct {
			int RE_errno;	/* related system error */
			int RE_t_errno;	/* related tli error number */
		} RE_err;
		enum auth_stat RE_why;	/* why the auth error occurred */
		struct {
			rpcvers_t low;	/* lowest verion supported */
			rpcvers_t high;	/* highest verion supported */
		} RE_vers;
		struct {		/* maybe meaningful if RPC_FAILED */
			int32_t s1;
			int32_t s2;
		} RE_lb;		/* life boot & debugging only */
	} ru;
#define	re_errno	ru.RE_err.RE_errno
#define	re_terrno	ru.RE_err.RE_t_errno
#define	re_why		ru.RE_why
#define	re_vers		ru.RE_vers
#define	re_lb		ru.RE_lb
};


/*
 * Timers used for the pseudo-transport protocol when using datagrams
 */
struct rpc_timers {
	clock_t		rt_srtt;	/* smoothed round-trip time */
	clock_t		rt_deviate;	/* estimated deviation */
	clock_t		rt_rtxcur;	/* current (backed-off) rto */
};

/*
 * PSARC 2003/523 Contract Private Interface
 * CLIENT
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 *
 * Client rpc handle.
 * Created by individual implementations
 * Client is responsible for initializing auth, see e.g. auth_none.c.
 */

typedef struct __client {
	AUTH	*cl_auth;			/* authenticator */
	struct clnt_ops {
#ifdef __STDC__
		/* call remote procedure */
		enum clnt_stat	(*cl_call)(struct __client *, rpcproc_t,
				    xdrproc_t, caddr_t, xdrproc_t,
				    caddr_t, struct timeval);
		/* abort a call */
		void		(*cl_abort)(/* various */);
		/* get specific error code */
		void		(*cl_geterr)(struct __client *,
				    struct rpc_err *);
		/* frees results */
		bool_t		(*cl_freeres)(struct __client *, xdrproc_t,
				    caddr_t);
		/* destroy this structure */
		void		(*cl_destroy)(struct __client *);
		/* the ioctl() of rpc */
		bool_t		(*cl_control)(struct __client *, int, char *);
		/* set rpc level timers */
		int		(*cl_settimers)(struct __client *,
				    struct rpc_timers *, struct rpc_timers *,
				    int, void (*)(), caddr_t, uint32_t);
#ifndef _KERNEL
		/* send a one-way asynchronous call to remote procedure */
		enum clnt_stat	(*cl_send)(struct __client *, rpcproc_t,
				    xdrproc_t, caddr_t);
#endif /* !_KERNEL */
#else
		enum clnt_stat	(*cl_call)();	/* call remote procedure */
		void		(*cl_abort)();	/* abort a call */
		void		(*cl_geterr)();	/* get specific error code */
		bool_t		(*cl_freeres)(); /* frees results */
		void		(*cl_destroy)(); /* destroy this structure */
		bool_t		(*cl_control)(); /* the ioctl() of rpc */
		int		(*cl_settimers)(); /* set rpc level timers */
#ifndef _KERNEL
		enum clnt_stat  (*cl_send)();   /* send one-way request */
#endif /* !_KERNEL */
#endif
	} *cl_ops;
	caddr_t			cl_private;	/* private stuff */
#ifndef _KERNEL
	char			*cl_netid;	/* network token */
	char			*cl_tp;		/* device name */
#else
	bool_t			cl_nosignal;  /* to handle NOINTR */
#endif
} CLIENT;

/*
 * Feedback values used for possible congestion and rate control
 */
#define	FEEDBACK_REXMIT1	1	/* first retransmit */
#define	FEEDBACK_OK		2	/* no retransmits */

/*
 * The following defines the control routines
 * for rpcbind.
 */

#define	CLCR_GET_RPCB_TIMEOUT	1
#define	CLCR_SET_RPCB_TIMEOUT	2
#define	CLCR_SET_LOWVERS	3
#define	CLCR_GET_LOWVERS	4
#define	CLCR_SET_RPCB_RMTTIME	5
#define	CLCR_GET_RPCB_RMTTIME  	6
#define	CLCR_SET_CRED_CACHE_SZ 	7
#define	CLCR_GET_CRED_CACHE_SZ 	8

#define	RPCSMALLMSGSIZE	400	/* a more reasonable packet size */

#define	KNC_STRSIZE	128	/* maximum length of knetconfig strings */
/*
 * PSARC 2003/523 Contract Private Interface
 * knetconfig
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 *
 * Note that the knetconfig strings can either be dynamically allocated, or
 * they can be string literals.  The code that sets up the knetconfig is
 * responsible for keeping track of this and freeing the strings if
 * necessary when the knetconfig is destroyed.
 */
struct knetconfig {
	unsigned int	knc_semantics;	/* token name */
	caddr_t		knc_protofmly;	/* protocol family */
	caddr_t		knc_proto;	/* protocol */
	dev_t		knc_rdev;	/* device id */
	unsigned int	knc_unused[8];
};

#ifdef _SYSCALL32
struct knetconfig32 {
	uint32_t	knc_semantics;	/* token name */
	caddr32_t	knc_protofmly;	/* protocol family */
	caddr32_t	knc_proto;	/* protocol */
	dev32_t		knc_rdev;	/* device id */
	uint32_t	knc_unused[8];
};
#endif /* _SYSCALL32 */

#ifdef _KERNEL

/*
 * Bucket defined for the call table.  Padded out to 64 bytes so that
 * false sharing won't be induced.
 */
typedef	union call_table {
	struct {
		struct calllist_s	*uct_call_next;
		struct calllist_s	*uct_call_prev;
		uint_t			uct_len;
		kmutex_t		uct_lock;
	} ct_s;
	char				uct_pad[64];
} call_table_t;

/*
 * Define some macros for easy access into the call table structure
 */
#define	ct_call_next ct_s.uct_call_next
#define	ct_call_prev ct_s.uct_call_prev
#define	ct_len ct_s.uct_len
#define	ct_lock ct_s.uct_lock

/*
 * List of outstanding calls awaiting replies, for COTS, CLTS
 */
typedef struct calllist_s {
	struct calllist_s *call_next;	/* hash chain, MUST BE FIRST */
	struct calllist_s *call_prev;
	bool_t		call_notified;
	uint_t		call_xid;	/* the xid on the call */
	uint_t		call_hash;	/* hash value */
	call_table_t	*call_bucket;	/* back pointer to bucket */
	mblk_t		*call_reply;	/* the reply to the call */
	kcondvar_t	call_cv;	/* cv to notify when reply is done */
	kmutex_t	call_lock;	/* lock for cv */
	struct rpc_err	call_err;	/* status on reply */
#define	call_status call_err.re_status	/* error on reply (rep is invalid) */
#define	call_reason call_err.re_errno	/* reason code on T_DISCON_IND */
	queue_t		*call_wq;	/* the write queue the call is using */
	zoneid_t	call_zoneid;	/* zoneid the call was made from */
} calllist_t;

/*
 * Define macros for call table hashing
 */
/*
 * A simple hash function.  Due to the way XID's get allocated, this may be
 * sufficient.  This hash function provides round robin bucket selection so
 * that the next time a particular bucket gets picked is when there have
 * been N-1 calls.  N is the number of buckets.
 */
#define	call_hash(xid, hashsize) \
		(xid % hashsize);

#define	call_table_enter(e)				\
{							\
	call_table_t *ctp = e->call_bucket;		\
	mutex_enter(&ctp->ct_lock);			\
	ctp->ct_len++;					\
	e->call_next = (calllist_t *)ctp->ct_call_next;	\
	e->call_prev = (calllist_t *)ctp;		\
	((call_table_t *)ctp->ct_call_next)->ct_call_prev = e;		\
	ctp->ct_call_next = e;				\
	mutex_exit(&e->call_bucket->ct_lock);		\
}

#define	call_table_remove(e)				\
{							\
	call_table_t *ctp = e->call_bucket;		\
	mutex_enter(&ctp->ct_lock);			\
	ctp->ct_len--;					\
	((call_table_t *)e->call_prev)->ct_call_next = e->call_next;	\
	((call_table_t *)e->call_next)->ct_call_prev = e->call_prev;	\
	mutex_exit(&ctp->ct_lock);			\
}

#define	call_table_find(ctp, xid, ele)			\
{							\
	calllist_t *cp;					\
	ele = NULL;					\
	mutex_enter(&(ctp)->ct_lock);			\
	for (cp = (ctp)->ct_call_next;			\
		cp != (calllist_t *)ctp;		\
		cp = cp->call_next) {			\
		if (cp->call_xid == xid)		\
			ele = cp;			\
	}						\
}

#define	DEFAULT_MIN_HASH_SIZE	32
#define	DEFAULT_HASH_SIZE	1024

#define	RESERVED_PORTSPACE (IPPORT_RESERVED - (IPPORT_RESERVED/2))
#define	NONRESERVED_PORTSPACE (0xFFFF - IPPORT_RESERVED)

/*
 *	Alloc_xid presents an interface which kernel RPC clients
 *	should use to allocate their XIDs.  Its implementation
 *	may change over time (for example, to allow sharing of
 *	XIDs between the kernel and user-level applications, so
 *	all XID allocation should be done by calling alloc_xid().
 */
extern uint32_t alloc_xid(void);

extern struct zone *rpc_zone(void);
extern zoneid_t rpc_zoneid(void);

extern int clnt_tli_kcreate(struct knetconfig *config, struct netbuf *svcaddr,
	rpcprog_t, rpcvers_t, uint_t max_msgsize, int retrys,
	struct cred *cred, CLIENT **ncl);

extern int clnt_tli_kinit(CLIENT *h, struct knetconfig *config,
	struct netbuf *addr, uint_t max_msgsize, int retries,
	struct cred *cred);

extern int rpc_uaddr2port(int af, char *addr);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern int bindresvport(TIUSER *tiptr, struct netbuf *addr,
	struct netbuf *bound_addr, bool_t istcp);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern int clnt_clts_kcreate(struct knetconfig *config, struct netbuf *addr,
	rpcprog_t, rpcvers_t, int retries, struct cred *cred, CLIENT **cl);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern int clnt_cots_kcreate(dev_t dev, struct netbuf *addr, int family,
	rpcprog_t, rpcvers_t, uint_t max_msgsize, struct cred *cred,
	CLIENT **ncl);
/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern int clnt_rdma_kcreate(char *proto, void *handle, struct netbuf *raddr,
	int family, rpcprog_t pgm, rpcvers_t vers, struct cred *cred,
	CLIENT **cl);
/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern int rdma_reachable(int addr_type, struct netbuf *addr,
	struct knetconfig **knconf);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern void clnt_clts_kinit(CLIENT *h, struct netbuf *addr, int retries,
	struct cred *cred);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern void clnt_cots_kinit(CLIENT *h, dev_t dev, int family,
	struct netbuf *addr, int max_msgsize, struct cred *cred);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern void clnt_rdma_kinit(CLIENT *h, char *proto, void *handle,
	struct netbuf *addr, struct cred *cred);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern bool_t clnt_dispatch_notify(mblk_t *, zoneid_t);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern bool_t clnt_dispatch_notifyconn(queue_t *, mblk_t *);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern void clnt_dispatch_notifyall(queue_t *, int32_t, int32_t);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern enum clnt_stat clnt_clts_kcallit_addr(CLIENT *, rpcproc_t, xdrproc_t,
	caddr_t, xdrproc_t, caddr_t, struct timeval, struct netbuf *);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern call_table_t *call_table_init(int);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern void clnt_init(void);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern void clnt_fini(void);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern void clnt_clts_init(void);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern void clnt_clts_fini(void);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern void clnt_cots_init(void);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern void clnt_cots_fini(void);

/*
 * kRPC internal function. Not for general use. Subject to rapid change.
 */
extern void clnt_clts_dispatch_notify(mblk_t *, int, zoneid_t);

extern void rpc_poptimod(struct vnode *);
extern int kstr_push(struct vnode *, char *);
extern void t_kadvise(TIUSER *, uchar_t *, int);

extern boolean_t connmgr_cpr_reset(void *, int);

extern void put_inet_port(struct netbuf *, ushort_t);
extern void put_inet6_port(struct netbuf *, ushort_t);
extern void put_loopback_port(struct netbuf *, char *);
extern enum clnt_stat rpcbind_getaddr(struct knetconfig *, rpcprog_t,
    rpcvers_t, struct netbuf *);

/*
 * Kstat stuff
 */
#include <sys/zone.h>

extern zone_key_t rpcstat_zone_key;

struct rpc_clts_client;		/* unix:0:rpc_clts_client */
struct rpc_clts_server;		/* unix:0:rpc_clts_server */
struct rpc_cots_client;		/* unix:0:rpc_cots_client */
struct rpc_cots_server;		/* unix:0:rpc_cots_server */

struct rpcstat {
	struct rpc_clts_client *rpc_clts_client;
	struct rpc_clts_server *rpc_clts_server;
	struct rpc_cots_client *rpc_cots_client;
	struct rpc_cots_server *rpc_cots_server;
};

extern kstat_named_t *rpcstat_zone_init_common(zoneid_t, const char *,
    const char *, const kstat_named_t *, size_t);
extern void rpcstat_zone_fini_common(zoneid_t, const char *, const char *);

extern void clnt_clts_stats_init(zoneid_t, struct rpc_clts_client **);
extern void clnt_clts_stats_fini(zoneid_t, struct rpc_clts_client **);

extern void svc_clts_stats_init(zoneid_t, struct rpc_clts_server **);
extern void svc_clts_stats_fini(zoneid_t, struct rpc_clts_server **);

extern void clnt_cots_stats_init(zoneid_t, struct rpc_cots_client **);
extern void clnt_cots_stats_fini(zoneid_t, struct rpc_cots_client **);

extern void svc_cots_stats_init(zoneid_t, struct rpc_cots_server **);
extern void svc_cots_stats_fini(zoneid_t, struct rpc_cots_server **);

#endif /* _KERNEL */

/*
 * client side rpc interface ops
 */

/*
 * enum clnt_stat
 * CLNT_CALL(rh, proc, xargs, argsp, xres, resp, timeout)
 * 	CLIENT *rh;
 *	rpcproc_t proc;
 *	xdrproc_t xargs;
 *	caddr_t argsp;
 *	xdrproc_t xres;
 *	caddr_t resp;
 *	struct timeval timeout;
 *
 * PSARC 2003/523 Contract Private Interface
 * CLNT_CALL
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
#define	CLNT_CALL(rh, proc, xargs, argsp, xres, resp, secs)	\
	((*(rh)->cl_ops->cl_call)(rh, proc, xargs, argsp, xres, resp, secs))
#define	clnt_call(rh, proc, xargs, argsp, xres, resp, secs)	\
	((*(rh)->cl_ops->cl_call)(rh, proc, xargs, argsp, xres, resp, secs))

#ifndef _KERNEL
/*
 * enum clnt_stat
 * CLNT_SEND(rh, proc, xargs, argsp)
 * 	CLIENT *rh;
 *	rpcproc_t proc;
 *	xdrproc_t xargs;
 *	caddr_t argsp;
 *
 * PSARC 2000/428  Contract Private Interface
 */
#define	CLNT_SEND(rh, proc, xargs, argsp)	\
	((*(rh)->cl_ops->cl_send)(rh, proc, xargs, argsp))
#define	clnt_send(rh, proc, xargs, argsp)	\
	((*(rh)->cl_ops->cl_send)(rh, proc, xargs, argsp))
#endif /* !_KERNEL */

/*
 * void
 * CLNT_ABORT(rh);
 * 	CLIENT *rh;
 */
#define	CLNT_ABORT(rh)	((*(rh)->cl_ops->cl_abort)(rh))
#define	clnt_abort(rh)	((*(rh)->cl_ops->cl_abort)(rh))

/*
 * struct rpc_err
 * CLNT_GETERR(rh);
 * 	CLIENT *rh;
 */
#define	CLNT_GETERR(rh, errp)	((*(rh)->cl_ops->cl_geterr)(rh, errp))
#define	clnt_geterr(rh, errp)	((*(rh)->cl_ops->cl_geterr)(rh, errp))

/*
 * bool_t
 * CLNT_FREERES(rh, xres, resp);
 * 	CLIENT *rh;
 *	xdrproc_t xres;
 *	caddr_t resp;
 */
#define	CLNT_FREERES(rh, xres, resp) \
		((*(rh)->cl_ops->cl_freeres)(rh, xres, resp))
#define	clnt_freeres(rh, xres, resp) \
		((*(rh)->cl_ops->cl_freeres)(rh, xres, resp))

/*
 * bool_t
 * CLNT_CONTROL(cl, request, info)
 *	CLIENT *cl;
 *	uint_t request;
 *	char *info;
 *
 * PSARC 2003/523 Contract Private Interface
 * CLNT_CONTROL
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
#define	CLNT_CONTROL(cl, rq, in) ((*(cl)->cl_ops->cl_control)(cl, rq, in))
#define	clnt_control(cl, rq, in) ((*(cl)->cl_ops->cl_control)(cl, rq, in))


/*
 * control operations that apply to all transports
 */
#define	CLSET_TIMEOUT		1	/* set timeout (timeval) */
#define	CLGET_TIMEOUT		2	/* get timeout (timeval) */
#define	CLGET_SERVER_ADDR	3	/* get server's address (sockaddr) */
#define	CLGET_FD		6	/* get connections file descriptor */
#define	CLGET_SVC_ADDR		7	/* get server's address (netbuf) */
#define	CLSET_FD_CLOSE		8	/* close fd while clnt_destroy */
#define	CLSET_FD_NCLOSE		9	/* Do not close fd while clnt_destroy */
#define	CLGET_XID 		10	/* Get xid */
#define	CLSET_XID		11	/* Set xid */
#define	CLGET_VERS		12	/* Get version number */
#define	CLSET_VERS		13	/* Set version number */
#define	CLGET_PROG		14	/* Get program number */
#define	CLSET_PROG		15	/* Set program number */
#define	CLSET_SVC_ADDR		16	/* get server's address (netbuf) */
#define	CLSET_PUSH_TIMOD	17	/* push timod if not already present */
#define	CLSET_POP_TIMOD		18	/* pop timod */
#ifndef _KERNEL
/* 00-08-17 - NON STANDARD CONTROL PARAMETER */
#define	CLSET_IO_MODE		19	/* clnt_send behavior */
#define	CLGET_IO_MODE		20	/* clnt_send behavior */
#define	CLSET_FLUSH_MODE	21	/* flush behavior */
#define	CLGET_FLUSH_MODE	22	/* flush behavior */
#define	CLFLUSH			23	/* flush now (user wants it) */
#define	CLSET_CONNMAXREC_SIZE	24	/* set pending request buffer size */
#define	CLGET_CONNMAXREC_SIZE	25	/* set pending request buffer size */
#define	CLGET_CURRENT_REC_SIZE	26	/* get pending request buffer size */

typedef enum {
	RPC_CL_BESTEFFORT_FLUSH = 100,	/* flush as much as possible */
					/* without blocking */
	RPC_CL_BLOCKING_FLUSH,		/* flush the buffer completely */
					/* (possibly blocking) */
	RPC_CL_DEFAULT_FLUSH		/* flush according to the currently */
					/* defined policy. */
} rpcflushmode_t;


typedef enum {
	RPC_CL_BLOCKING = 10,	/* PASSED CLNT_CONTROL SET_IO_MODE */
	RPC_CL_NONBLOCKING
} rpciomode_t;
#endif /* !_KERNEL */
/*
 * Connectionless only control operations
 */
#define	CLSET_RETRY_TIMEOUT 4   /* set retry timeout (timeval) */
#define	CLGET_RETRY_TIMEOUT 5   /* get retry timeout (timeval) */

#ifdef	_KERNEL
/*
 * Connection oriented only control operation.
 */
#define	CLSET_PROGRESS		10000	/* Report RPC_INPROGRESS if a request */
					/* has been sent but no reply */
					/* received yet. */
#define	CLSET_BCAST		10001	/* Set RPC Broadcast hint */
#define	CLGET_BCAST		10002	/* Get RPC Broadcast hint */
#define	CLSET_NODELAYONERR	10003	/* Set enable/disable of delay on */
					/* connection setup error	  */
#define	CLGET_NODELAYONERR	10004	/* Get enable/disable of delay on */
					/* connection setup error	  */
#define	CLSET_BINDRESVPORT	10005	/* Set preference for reserve port */
#define	CLGET_BINDRESVPORT	10006	/* Get preference for reserve port */
#endif

/*
 * void
 * CLNT_SETTIMERS(rh);
 *	CLIENT *rh;
 *	struct rpc_timers *t;
 *	struct rpc_timers *all;
 *	unsigned int min;
 *	void    (*fdbck)();
 *	caddr_t arg;
 *	uint_t  xid;
 */
#define	CLNT_SETTIMERS(rh, t, all, min, fdbck, arg, xid) \
		((*(rh)->cl_ops->cl_settimers)(rh, t, all, min, \
		fdbck, arg, xid))
#define	clnt_settimers(rh, t, all, min, fdbck, arg, xid) \
		((*(rh)->cl_ops->cl_settimers)(rh, t, all, min, \
		fdbck, arg, xid))


/*
 * void
 * CLNT_DESTROY(rh);
 * 	CLIENT *rh;
 *
 * PSARC 2003/523 Contract Private Interface
 * CLNT_DESTROY
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
#define	CLNT_DESTROY(rh)	((*(rh)->cl_ops->cl_destroy)(rh))
#define	clnt_destroy(rh)	((*(rh)->cl_ops->cl_destroy)(rh))


/*
 * RPCTEST is a test program which is accessable on every rpc
 * transport/port.  It is used for testing, performance evaluation,
 * and network administration.
 */

#define	RPCTEST_PROGRAM		((rpcprog_t)1)
#define	RPCTEST_VERSION		((rpcvers_t)1)
#define	RPCTEST_NULL_PROC	((rpcproc_t)2)
#define	RPCTEST_NULL_BATCH_PROC	((rpcproc_t)3)

/*
 * By convention, procedure 0 takes null arguments and returns them
 */

#define	NULLPROC ((rpcproc_t)0)

/*
 * Below are the client handle creation routines for the various
 * implementations of client side rpc.  They can return NULL if a
 * creation failure occurs.
 */

#ifndef _KERNEL

/*
 * Generic client creation routine. Supported protocols are which belong
 * to the nettype name space
 */
#ifdef __STDC__
extern  CLIENT * clnt_create(const char *, const rpcprog_t, const rpcvers_t,
	const char *);
/*
 *
 * 	const char *hostname;			-- hostname
 *	const rpcprog_t prog;			-- program number
 *	const rpcvers_t vers;			-- version number
 *	const char *nettype;			-- network type
 */
#else
extern CLIENT * clnt_create();
#endif

/*
 * Generic client creation routine. Just like clnt_create(), except
 * it takes an additional timeout parameter.
 */
#ifdef __STDC__
extern  CLIENT * clnt_create_timed(const char *, const rpcprog_t,
	const rpcvers_t, const char *, const struct timeval *);
/*
 *
 * 	const char *hostname;			-- hostname
 *	const rpcprog_t prog;			-- program number
 *	const rpcvers_t vers;			-- version number
 *	const char *nettype;			-- network type
 *	const struct timeval *tp;		-- timeout
 */
#else
extern CLIENT * clnt_create_timed();
#endif

/*
 * Generic client creation routine. Supported protocols are which belong
 * to the nettype name space.
 */
#ifdef __STDC__
extern CLIENT * clnt_create_vers(const char *, const rpcprog_t, rpcvers_t *,
	const rpcvers_t, const rpcvers_t, const char *);
/*
 *	const char *host;		-- hostname
 *	const rpcprog_t prog;		-- program number
 *	rpcvers_t *vers_out;	-- servers highest available version number
 *	const rpcvers_t vers_low;	-- low version number
 *	const rpcvers_t vers_high;	-- high version number
 *	const char *nettype;		-- network type
 */
#else
extern CLIENT * clnt_create_vers();
#endif

/*
 * Generic client creation routine. Supported protocols are which belong
 * to the nettype name space.
 */
#ifdef __STDC__
extern CLIENT * clnt_create_vers_timed(const char *, const rpcprog_t,
	rpcvers_t *, const rpcvers_t, const rpcvers_t, const char *,
	const struct timeval *);
/*
 *	const char *host;		-- hostname
 *	const rpcprog_t prog;		-- program number
 *	rpcvers_t *vers_out;	-- servers highest available version number
 *	const rpcvers_t vers_low;	-- low version number
 *	const prcvers_t vers_high;	-- high version number
 *	const char *nettype;		-- network type
 *	const struct timeval *tp	-- timeout
 */
#else
extern CLIENT * clnt_create_vers_timed();
#endif


/*
 * Generic client creation routine. It takes a netconfig structure
 * instead of nettype
 */
#ifdef __STDC__
extern CLIENT * clnt_tp_create(const char *, const rpcprog_t, const rpcvers_t,
	const struct netconfig *);
/*
 *	const char *hostname;			-- hostname
 *	const rpcprog_t prog;			-- program number
 *	const rpcvers_t vers;			-- version number
 *	const struct netconfig *netconf; 	-- network config structure
 */
#else
extern CLIENT * clnt_tp_create();
#endif

/*
 * Generic client creation routine. Just like clnt_tp_create(), except
 * it takes an additional timeout parameter.
 */
#ifdef __STDC__
extern CLIENT * clnt_tp_create_timed(const char *, const rpcprog_t,
	const rpcvers_t, const struct netconfig *, const struct timeval *);
/*
 *	const char *hostname;			-- hostname
 *	const rpcprog_t prog;			-- program number
 *	const rpcvers_t vers;			-- version number
 *	const struct netconfig *netconf; 	-- network config structure
 *	const struct timeval *tp;		-- timeout
 */
#else
extern CLIENT * clnt_tp_create_timed();
#endif

/*
 * Generic TLI create routine
 */

#ifdef __STDC__
extern CLIENT * clnt_tli_create(const int, const struct netconfig *,
	struct netbuf *, const rpcprog_t, const rpcvers_t, const uint_t,
	const uint_t);
/*
 *	const int fd;		-- fd
 *	const struct netconfig *nconf;	-- netconfig structure
 *	struct netbuf *svcaddr;		-- servers address
 *	const rpcprog_t prog;		-- program number
 *	const rpcvers_t vers;		-- version number
 *	const uint_t sendsz;		-- send size
 *	const uint_t recvsz;		-- recv size
 */

#else
extern CLIENT * clnt_tli_create();
#endif

/*
 * Low level clnt create routine for connectionful transports, e.g. tcp.
 */
#ifdef __STDC__
extern  CLIENT * clnt_vc_create(const int, struct netbuf *,
	const rpcprog_t, const rpcvers_t, const uint_t, const uint_t);
/*
 *	const int fd;				-- open file descriptor
 *	const struct netbuf *svcaddr;		-- servers address
 *	const rpcprog_t prog;			-- program number
 *	const rpcvers_t vers;			-- version number
 *	const uint_t sendsz;			-- buffer recv size
 *	const uint_t recvsz;			-- buffer send size
 */
#else
extern CLIENT * clnt_vc_create();
#endif

/*
 * Low level clnt create routine for connectionless transports, e.g. udp.
 */
#ifdef __STDC__
extern  CLIENT * clnt_dg_create(const int, struct netbuf *,
	const rpcprog_t, const rpcvers_t, const uint_t, const uint_t);
/*
 *	const int fd;				-- open file descriptor
 *	const struct netbuf *svcaddr;		-- servers address
 *	const rpcprog_t program;		-- program number
 *	const rpcvers_t version;		-- version number
 *	const uint_t sendsz;			-- buffer recv size
 *	const uint_t recvsz;			-- buffer send size
 */
#else
extern CLIENT * clnt_dg_create();
#endif

/*
 * Memory based rpc (for speed check and testing)
 * CLIENT *
 * clnt_raw_create(prog, vers)
 *	const rpcprog_t prog;			-- program number
 *	const rpcvers_t vers;			-- version number
 */
#ifdef __STDC__
extern CLIENT *clnt_raw_create(const rpcprog_t, const rpcvers_t);
#else
extern CLIENT *clnt_raw_create();
#endif

/*
 * Client creation routine over doors transport.
 */
#ifdef __STDC__
extern  CLIENT * clnt_door_create(const rpcprog_t, const rpcvers_t,
	const uint_t);
/*
 *	const rpcprog_t prog;			-- program number
 *	const rpcvers_t vers;			-- version number
 *	const uint_t sendsz;			-- max send size
 */
#else
extern CLIENT * clnt_door_create();
#endif

/*
 * internal function. Not for general use. Subject to rapid change.
 */
#ifdef __STDC__
extern CLIENT *clnt_create_service_timed(const char *,
					const char *,
					const rpcprog_t,
					const rpcvers_t,
					const ushort_t,
					const char *,
					const struct timeval *);
#else
extern CLIENT *clnt_create_service_timed();
#endif

/*
 * Print why creation failed
 */
#ifdef __STDC__
void clnt_pcreateerror(const char *);	/* stderr */
char *clnt_spcreateerror(const char *);	/* string */
#else
void clnt_pcreateerror();
char *clnt_spcreateerror();
#endif

/*
 * Like clnt_perror(), but is more verbose in its output
 */
#ifdef __STDC__
void clnt_perrno(const enum clnt_stat);	/* stderr */
#else
void clnt_perrno();
#endif

/*
 * Print an error message, given the client error code
 */
#ifdef __STDC__
void clnt_perror(const CLIENT *, const char *);
#else
void clnt_perror();
#endif

/*
 * If a creation fails, the following allows the user to figure out why.
 */
struct rpc_createerr {
	enum clnt_stat cf_stat;
	struct rpc_err cf_error; /* useful when cf_stat == RPC_PMAPFAILURE */
};

#ifdef	_REENTRANT
extern struct rpc_createerr	*__rpc_createerr();
#define	rpc_createerr	(*(__rpc_createerr()))
#else
extern struct rpc_createerr rpc_createerr;
#endif	/* _REENTRANT */

/*
 * The simplified interface:
 * enum clnt_stat
 * rpc_call(host, prognum, versnum, procnum, inproc, in, outproc, out, nettype)
 *	const char *host;
 *	const rpcprog_t prognum;
 *	const rpcvers_t versnum;
 *	const rpcproc_t procnum;
 *	const xdrproc_t inproc, outproc;
 *	const char *in;
 *	char *out;
 *	const char *nettype;
 */
#ifdef __STDC__
extern enum clnt_stat rpc_call(const char *, const rpcprog_t, const rpcvers_t,
	const rpcproc_t, const xdrproc_t, const char *, const xdrproc_t,
	char *, const char *);
#else
extern enum clnt_stat rpc_call();
#endif

#ifdef	_REENTRANT
extern struct rpc_err	*__rpc_callerr();
#define	rpc_callerr	(*(__rpc_callerr()))
#else
extern struct rpc_err rpc_callerr;
#endif	/* _REENTRANT */

/*
 * RPC broadcast interface
 * The call is broadcasted to all locally connected nets.
 *
 * extern enum clnt_stat
 * rpc_broadcast(prog, vers, proc, xargs, argsp, xresults, resultsp,
 *			eachresult, nettype)
 *	const rpcprog_t		prog;		-- program number
 *	const rpcvers_t		vers;		-- version number
 *	const rpcproc_t		proc;		-- procedure number
 *	const xdrproc_t	xargs;		-- xdr routine for args
 *	caddr_t		argsp;		-- pointer to args
 *	const xdrproc_t	xresults;	-- xdr routine for results
 *	caddr_t		resultsp;	-- pointer to results
 *	const resultproc_t	eachresult;	-- call with each result
 *	const char		*nettype;	-- Transport type
 *
 * For each valid response received, the procedure eachresult is called.
 * Its form is:
 *		done = eachresult(resp, raddr, nconf)
 *			bool_t done;
 *			caddr_t resp;
 *			struct netbuf *raddr;
 *			struct netconfig *nconf;
 * where resp points to the results of the call and raddr is the
 * address if the responder to the broadcast.  nconf is the transport
 * on which the response was received.
 *
 * extern enum clnt_stat
 * rpc_broadcast_exp(prog, vers, proc, xargs, argsp, xresults, resultsp,
 *			eachresult, inittime, waittime, nettype)
 *	const rpcprog_t		prog;		-- program number
 *	const rpcvers_t		vers;		-- version number
 *	const rpcproc_t		proc;		-- procedure number
 *	const xdrproc_t	xargs;		-- xdr routine for args
 *	caddr_t		argsp;		-- pointer to args
 *	const xdrproc_t	xresults;	-- xdr routine for results
 *	caddr_t		resultsp;	-- pointer to results
 *	const resultproc_t	eachresult;	-- call with each result
 *	const int 		inittime;	-- how long to wait initially
 *	const int 		waittime;	-- maximum time to wait
 *	const char		*nettype;	-- Transport type
 */

typedef bool_t(*resultproc_t)(
#ifdef	__STDC__
	caddr_t,
	... /* for backward compatibility */
#endif				/* __STDC__ */
);
#ifdef __STDC__
extern enum clnt_stat rpc_broadcast(const rpcprog_t, const rpcvers_t,
	const rpcproc_t, const xdrproc_t, caddr_t, const xdrproc_t,
	caddr_t, const resultproc_t, const char *);
extern enum clnt_stat rpc_broadcast_exp(const rpcprog_t, const rpcvers_t,
	const rpcproc_t, const xdrproc_t, caddr_t, const xdrproc_t, caddr_t,
	const resultproc_t, const int, const int, const char *);
#else
extern enum clnt_stat rpc_broadcast();
extern enum clnt_stat rpc_broadcast_exp();
#endif
#endif /* !_KERNEL */

/*
 * Copy error message to buffer.
 */
#ifdef __STDC__
const char *clnt_sperrno(const enum clnt_stat);
#else
char *clnt_sperrno();	/* string */
#endif

/*
 * Print an error message, given the client error code
 */
#ifdef __STDC__
char *clnt_sperror(const CLIENT *, const char *);
#else
char *clnt_sperror();
#endif

/*
 * Client side rpc control routine for rpcbind.
 */
#ifdef __STDC__
bool_t __rpc_control(int, void *);
#else
bool_t __rpc_control();
#endif

#ifdef __cplusplus
}
#endif

#ifdef PORTMAP
/* For backward compatibility */
#include <rpc/clnt_soc.h>
#endif

#endif	/* !_RPC_CLNT_H */
