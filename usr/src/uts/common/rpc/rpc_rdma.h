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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RPC_RPC_RDMA_H
#define	_RPC_RPC_RDMA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/rpc.h>
#include <rpc/rpc_sztypes.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	RPCRDMA_VERS	0	/* Version of the RPC over RDMA protocol */
#define	RDMATF_VERS	1	/* Version of the API used by RPC for RDMA */
#define	RDMATF_VERS_1	1	/* Current version of RDMATF */

/*
 * The size of an RPC call or reply message
 */
#define	RPC_MSG_SZ  1024

/*
 * Storage for a chunk list
 */
#define	RPC_CL_SZ  1024

/*
 * Chunk size
 */
#define	MINCHUNK  1024

/*
 * Size of receive buffer
 */
#define	RPC_BUF_SIZE	2048

#define	NOWAIT	0	/* don't wait for operation of complete */
#define	WAIT	1	/* wait and ensure that operation is complete */

/*
 * RDMA xdr buffer control and other control flags. Add new flags here,
 * set them in private structure for xdr over RDMA in xdr_rdma.c
 */
#define	RDMA_NOCHUNK		0x1

/*
 * Return codes from RDMA operations
 */
typedef enum {

	RDMA_SUCCESS = 0,	/* successful operation */

	RDMA_INVAL = 1,		/* invalid parameter */
	RDMA_TIMEDOUT = 2,	/* operation timed out */
	RDMA_INTR = 3,		/* operation interrupted */
	RDMA_NORESOURCE = 4,	/* insufficient resource */
	/*
	 * connection errors
	 */
	RDMA_REJECT = 5,	/* connection req rejected */
	RDMA_NOLISTENER = 6,	/* no listener on server */
	RDMA_UNREACHABLE = 7,	/* host unreachable */
	RDMA_CONNLOST = 8,	/* connection lost */

	RDMA_XPRTFAILED = 9,	/* RDMA transport failed */
	RDMA_PROTECTERR = 10,	/* memory protection error */
	RDMA_OVERRUN = 11,	/* transport overrun */
	RDMA_RECVQEMPTY = 12,	/* incoming pkt dropped, recv q empty */
	RDMA_PROTFAILED = 13,	/* RDMA protocol failed */
	RDMA_NOTSUPP = 14,	/* requested feature not supported */
	RDMA_REMOTERR = 15,	/* error at remote end */
	/*
	 * RDMATF errors
	 */
	RDMA_BADVERS = 16,	/* mismatch RDMATF versions */
	RDMA_REG_EXIST = 17,	/* RDMATF registration already exists */

	/*
	 * fallback error
	 */
	RDMA_FAILED = 18	/* generic error */
} rdma_stat;

/*
 * Memory region context. This is an RDMA provider generated
 * handle for a registered arbitrary size contiguous virtual
 * memory. The RDMA Interface Adapter needs this for local or
 * remote memory access.
 *
 * The mrc_rmr field holds the remote memory region context
 * which is sent over-the-wire to provide the remote host
 * with RDMA access to the memory region.
 */
struct mrc {
	uint32_t	mrc_rmr;	/* Remote MR context, sent OTW */
	union {
		struct mr {
			uint32_t	lmr; 	/* Local MR context */
			uint64_t	linfo;	/* Local memory info */
		} mr;
	} lhdl;
};

#define	mrc_lmr		lhdl.mr.lmr
#define	mrc_linfo	lhdl.mr.linfo

/*
 * The XDR offset value is used by the XDR
 * routine to identify the position in the
 * RPC message where the opaque object would
 * normally occur. Neither the data content
 * of the chunk, nor its size field are included
 * in the RPC message.  The XDR offset is calculated
 * as if the chunks were present.
 *
 * The remaining fields identify the chunk of data
 * on the sender.  The c_memhandle identifies a
 * registered RDMA memory region and the c_addr
 * and c_len fields identify the chunk within it.
 */
struct clist {
	uint32		c_xdroff;	/* XDR offset */
	uint32		c_len;		/* Length */
	struct mrc	c_smemhandle;	/* src memory handle */
	uint64 		c_ssynchandle;	/* src sync handle */
	uint64		c_saddr;	/* src address */
	struct mrc	c_dmemhandle;	/* dst memory handle */
	uint64		c_dsynchandle;	/* dst sync handle */
	uint64		c_daddr;	/* dst address */
	struct clist	*c_next;	/* Next chunk */
};

typedef struct clist clist;

enum rdma_proc {
	RDMA_MSG	= 0,	/* chunk list and RPC msg follow */
	RDMA_NOMSG	= 1,	/* only chunk list follows */
	RDMA_MSGP	= 2,	/* chunk list and RPC msg with padding follow */
	RDMA_DONE	= 3	/* signal completion of chunk transfer */
};

/*
 * Listener information for a service
 */
struct rdma_svc_data {
	queue_t		q;	/* queue_t to place incoming pkts */
	int		active;	/* If active, after registeration startup */
	rdma_stat	err_code;	/* Error code from plugin layer */
	int32_t		svcid;		/* RDMA based service identifier */
};

/*
 * Per RDMA plugin module information.
 * Will be populated by each plugin
 * module during its initialization.
 */
typedef struct rdma_mod {
	char 		*rdma_api;		/* "kvipl", "ibtf", etc */
	uint_t 		rdma_version;		/* RDMATF API version */
	int		rdma_count;		/* # of devices */
	struct rdmaops 	*rdma_ops;		/* rdma op vector for api */
} rdma_mod_t;

/*
 * Registry of RDMA plugins
 */
typedef struct rdma_registry {
	rdma_mod_t	*r_mod;		/* plugin mod info */
	struct rdma_registry *r_next;	/* next registered RDMA plugin */
} rdma_registry_t;

/*
 * RDMA transport information
 */
typedef struct rdma_info {
	uint_t	addrlen;	/* address length */
	uint_t  mts;		/* max transfer size */
	uint_t  mtu;		/* native mtu size of unlerlying network */
} rdma_info_t;

/*
 * RDMA Connection information
 */
typedef struct conn {
	rdma_mod_t	*c_rdmamod;	/* RDMA transport info for conn */
	struct netbuf	c_raddr;	/* remote address */
	struct netbuf	c_laddr;	/* local address */
	int		c_ref;		/* no. of clients of connection */
	struct conn	*c_next;	/* next in list of connections */
	struct conn	*c_prev;	/* prev in list of connections */
	caddr_t		c_private;	/* transport specific stuff */

#define	C_IDLE		0x80000000
#define	C_CONN_PEND	0x40000000
#define	C_CONNECTED	0x20000000
#define	C_ERROR		0x10000000
#define	C_DISCONN_PEND	0x08000000
#define	C_REMOTE_DOWN	0x04000000

	uint_t		c_state;	/* state of connection */
	kmutex_t	c_lock;		/* protect c_state and c_ref fields */
	kcondvar_t	c_cv;		/* to signal when pending is done */
} CONN;


/*
 * Memory management for the RDMA buffers
 */
/*
 * RDMA buffer types
 */
typedef enum {
	SEND_BUFFER,	/* buf for send msg */
	SEND_DESCRIPTOR, /* buf used for send msg descriptor in plugins only */
	RECV_BUFFER,	/* buf for recv msg */
	RECV_DESCRIPTOR, /* buf used for recv msg descriptor in plugins only */
	CHUNK_BUFFER	/* chunk buf used in RDMATF only and not in plugins */
} rdma_btype;

/*
 * RDMA buffer information
 */
typedef struct rdma_buf {
	rdma_btype	type;	/* buffer type */
	int		len;	/* length of buffer */
	caddr_t		addr;	/* buffer address */
	struct mrc	handle;	/* buffer registration handle */
} rdma_buf_t;

/*
 * Data transferred from plugin interrupt to svc_queuereq()
 */
struct recv_data {
	CONN		*conn;
	int		status;
	rdma_buf_t	rpcmsg;
};

/*
 * Operations vector for RDMA transports.
 */
typedef struct rdmaops {
	/* Network */
	rdma_stat	(*rdma_reachable)(int addr_type, struct netbuf *,
						void **handle);
	/* Connection */
	rdma_stat	(*rdma_get_conn)(struct netbuf *, int addr_type,
						void *, CONN **);
	rdma_stat	(*rdma_rel_conn)(CONN *);
	/* Server side listner start and stop routines */
	void		(*rdma_svc_listen)(struct rdma_svc_data *);
	void		(*rdma_svc_stop)(struct rdma_svc_data *);
	/* Memory */
	rdma_stat	(*rdma_regmem)(CONN *, caddr_t, uint_t, struct mrc *);
	rdma_stat	(*rdma_deregmem)(CONN *, caddr_t, struct mrc);
	rdma_stat	(*rdma_regmemsync)(CONN *, caddr_t, uint_t,
				struct mrc *, void **);
	rdma_stat	(*rdma_deregmemsync)(CONN *, caddr_t, struct mrc,
				void *);
	rdma_stat	(*rdma_syncmem)(CONN *, void *, caddr_t, int, int);
	/* Buffer */
	rdma_stat	(*rdma_buf_alloc)(CONN *, rdma_buf_t *);
	void		(*rdma_buf_free)(CONN *, rdma_buf_t *);
	/* Transfer */
	rdma_stat	(*rdma_send)(CONN *, clist *, uint32_t);
	rdma_stat	(*rdma_send_resp)(CONN *, clist *, uint32_t);
	rdma_stat	(*rdma_clnt_recvbuf)(CONN *, clist *, uint32_t);
	rdma_stat	(*rdma_svc_recvbuf)(CONN *, clist *);
	rdma_stat	(*rdma_recv)(CONN *, clist **, uint32_t);
	/* RDMA */
	rdma_stat	(*rdma_read)(CONN *, clist *, int);
	rdma_stat	(*rdma_write)(CONN *, clist *, int);
	/* INFO */
	rdma_stat	(*rdma_getinfo)(rdma_info_t *info);

} rdmaops_t;

/*
 * RDMA operations.
 */
#define	RDMA_REACHABLE(rdma_ops, addr_type, addr, handle)	\
	(*(rdma_ops)->rdma_reachable)(addr_type, addr, handle)

#define	RDMA_GET_CONN(rdma_ops, addr, addr_type, handle, conn)	\
	(*(rdma_ops)->rdma_get_conn)(addr, addr_type, handle, conn)

#define	RDMA_REL_CONN(conn)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_rel_conn)(conn)

#define	RDMA_REGMEM(conn, buff, len, handle)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_regmem)(conn, buff, len, handle)

#define	RDMA_DEREGMEM(conn, buff, handle)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_deregmem)(conn, buff, handle)

#define	RDMA_REGMEMSYNC(conn, buff, len, handle, synchandle)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_regmemsync)(conn, buff, \
	    len, handle, synchandle)

#define	RDMA_DEREGMEMSYNC(conn, buff, handle, synchandle)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_deregmemsync)(conn, buff, \
	    handle, synchandle)

#define	RDMA_SYNCMEM(conn, handle, buff, len, direction)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_syncmem)(conn, handle, \
	    buff, len, direction)

#define	RDMA_BUF_ALLOC(conn, rbuf)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_buf_alloc)(conn, rbuf)

#define	RDMA_BUF_FREE(conn, rbuf)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_buf_free)(conn, rbuf)

#define	RDMA_SEND(conn, sendlist, xid)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_send)(conn, sendlist, xid)

#define	RDMA_SEND_RESP(conn, sendlist, xid)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_send_resp)(conn, sendlist, xid)

#define	RDMA_CLNT_RECVBUF(conn, cl, xid)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_clnt_recvbuf)(conn, cl, xid)

#define	RDMA_SVC_RECVBUF(conn, cl)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_svc_recvbuf)(conn, cl)

#define	RDMA_RECV(conn, recvlist, xid)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_recv)(conn, recvlist, xid)

#define	RDMA_READ(conn, cl, wait)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_read)(conn, cl, wait)

#define	RDMA_WRITE(conn, cl, wait)	\
	(*(conn)->c_rdmamod->rdma_ops->rdma_write)(conn, cl, wait)

#define	RDMA_GETINFO(rdma_mod, info)	\
	(*(rdma_mod)->rdma_ops->rdma_getinfo)(info)

#ifdef _KERNEL
extern rdma_registry_t	*rdma_mod_head;
extern krwlock_t rdma_lock;		/* protects rdma_mod_head list */
extern int rdma_modloaded;		/* flag for loading RDMA plugins */
extern int rdma_dev_available;		/* rdma device is loaded or not */
extern kmutex_t rdma_modload_lock;	/* protects rdma_modloaded flag */
extern uint_t rdma_minchunk;
extern ldi_ident_t rpcmod_li; 		/* needed by layed driver framework */

/*
 * General RDMA routines
 */
extern void clist_add(struct clist **clp, uint32_t xdroff, int len,
	struct mrc *shandle, caddr_t saddr,
	struct mrc *dhandle, caddr_t daddr);
extern void clist_free(struct clist *cl);
extern int clist_register(CONN *conn, struct clist *cl, bool_t src);
extern int clist_deregister(CONN *conn, struct clist *cl, bool_t src);
rdma_stat rdma_clnt_postrecv(CONN *conn, uint32_t xid);
rdma_stat rdma_svc_postrecv(CONN *conn);
extern rdma_stat clist_syncmem(CONN *conn, struct clist *cl, bool_t src);
extern rdma_stat rdma_register_mod(rdma_mod_t *mod);
extern rdma_stat rdma_unregister_mod(rdma_mod_t *mod);
extern void rdma_buf_free(CONN *conn, rdma_buf_t *rbuf);
extern int rdma_modload();

/*
 * RDMA XDR
 */
extern void xdrrdma_create(XDR *, caddr_t, uint_t, int, struct clist *,
	enum xdr_op, CONN *);
extern void xdrrdma_destroy(XDR *);
extern struct clist *xdrrdma_clist(XDR *);
extern uint_t xdrrdma_getpos(XDR *);
extern bool_t xdrrdma_setpos(XDR *, uint_t);
extern bool_t xdr_clist(XDR *, clist *);
extern bool_t xdr_do_clist(XDR *, clist **);
extern uint_t xdr_getbufsize(XDR *);
unsigned int xdrrdma_sizeof(xdrproc_t func, void *data, int min_chunk);
unsigned int xdrrdma_authsize(AUTH *auth, struct cred *cred, int min_chunk);
#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _RPC_RPC_RDMA_H */
