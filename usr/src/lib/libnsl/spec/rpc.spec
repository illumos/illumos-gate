#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libnsl/spec/rpc.spec

function	auth_destroy
include		<rpc/rpc.h>
declaration	void auth_destroy(AUTH *auth)
version		SUNW_0.7
end

function	authnone_create
include		<rpc/rpc.h>
declaration	AUTH *authnone_create(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	authsys_create
include		<rpc/rpc.h>
declaration	AUTH  *authsys_create(const char *host, const uid_t uid, \
			const gid_t gid, const int len, const gid_t *aup_gids)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	authsys_create_default
include		<rpc/rpc.h>
declaration	AUTH *authsys_create_default(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	clnt_call
include		<rpc/rpc.h>
declaration	enum clnt_stat clnt_call(CLIENT *clnt, const rpcproc_t procnum,\
			const xdrproc_t  inproc,  const caddr_t in, \
			const xdrproc_t	 outproc,  caddr_t  out, \
			const struct timeval	tout)
version		SUNW_0.7
exception	$return != RPC_SUCCESS
end

function	rpc_broadcast_exp
include		<rpc/rpc.h>
declaration	enum  clnt_stat  rpc_broadcast_exp(const rpcprog_t prognum, \
			const rpcvers_t  versnum, const  rpcproc_t procnum, \
			const xdrproc_t	xargs, caddr_t argsp, \
			const xdrproc_t xresults, caddr_t resultsp, \
			const resultproc_t eachresult, const int inittime,\
			const int waittime, const char *nettype)
version		i386=SUNW_0.7 sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return != RPC_SUCCESS
end

function	rpc_call
include		<rpc/rpc.h>
declaration	enum  clnt_stat rpc_call(const  char *host, \
			const rpcprog_t prognum, const rpcvers_t versnum,\
			const rpcproc_t procnum, const  xdrproc_t inproc, \
			const char *in, const xdrproc_t outproc, \
			char *out, const char *nettype)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return != RPC_SUCCESS
end

function	clnt_freeres
include		<rpc/rpc.h>
declaration	bool_t clnt_freeres(CLIENT *clnt, \
			const xdrproc_t outproc, caddr_t out)
version		SUNW_0.7
exception	$return == 0
end

function	clnt_geterr
include		<rpc/rpc.h>
declaration	void clnt_geterr(const CLIENT *clnt, struct rpc_err *errp)
version		SUNW_0.7
end

function	clnt_perrno
include		<rpc/rpc.h>
declaration	void clnt_perrno(const enum clnt_stat stat)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	clnt_perror
include		<rpc/rpc.h>
declaration	void clnt_perror(const CLIENT *clnt, const char *s)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	clnt_sperrno
include		<rpc/rpc.h>
declaration	const char *clnt_sperrno(const enum clnt_stat stat)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	clnt_sperror
include		<rpc/rpc.h>
declaration	char *clnt_sperror(const CLIENT *clnt, const char *s)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	rpc_broadcast
include		<rpc/rpc.h>
declaration	enum clnt_stat rpc_broadcast(const rpcprog_t prognum, \
			const rpcvers_t versnum, const  rpcproc_t  procnum, \
			const xdrproc_t inproc, const caddr_t in,\
			const xdrproc_t outproc, caddr_t out, \
			const resultproc_t eachresult, const char *nettype)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return != RPC_SUCCESS
end

function	clnt_control
include		<rpc/rpc.h>
declaration	bool_t clnt_control(CLIENT *clnt, const u_int req, char *info)
version		SUNW_0.7
exception	$return == FALSE
end

function	clnt_create
include		<rpc/rpc.h>
declaration	CLIENT *clnt_create(const char *host, \
			const rpcprog_t prognum, const rpcvers_t versnum, \
			const char *nettype)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end


function	clnt_create_service_timed
include		<rpc/rpc.h>
declaration	CLIENT *clnt_create_service_timed(const	char *host, \
			const char *service, const rpcprog_t prognum, \
			const rpcvers_t versnum, const ushort_t port, \
			const char *nettype, const struct timeval *timeout)
version		SUNWprivate_1.5
exception	$return == 0
end

function	clnt_create_timed
include		<rpc/rpc.h>
declaration	CLIENT *clnt_create_timed(const	char *host, \
			const rpcprog_t prognum, const rpcvers_t versnum, \
			const char *nettype, const struct timeval *timeout)
version		SUNW_0.9
exception	$return == 0
end

function	clnt_create_vers
include		<rpc/rpc.h>
declaration	CLIENT *clnt_create_vers(const char *host, \
			const rpcprog_t prognum, rpcvers_t *vers_outp, \
			const rpcvers_t vers_low, const rpcvers_t vers_high, \
			const char *nettype)
version		SUNW_0.7
exception	$return == 0
end

function	clnt_create_vers_timed
include		<rpc/rpc.h>
declaration	CLIENT *clnt_create_vers_timed(const char *host, \
			const rpcprog_t prognum, rpcvers_t *vers_outp, \
			const rpcvers_t vers_low, const rpcvers_t vers_high, \
			const char *nettype, const struct timeval *timeout)
version		SUNW_1.1
exception	$return == 0
end

function	clnt_destroy
include		<rpc/rpc.h>
declaration	void clnt_destroy(CLIENT *clnt)
version		SUNW_0.7
end

function	clnt_dg_create
include		<rpc/rpc.h>
declaration	CLIENT *clnt_dg_create(const int fildes, \
			struct netbuf *svcaddr, \
			const rpcprog_t prognum, const rpcvers_t versnum, \
			const uint_t sendsz, const uint_t recvsz)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	clnt_pcreateerror
include		<rpc/rpc.h>
declaration	void clnt_pcreateerror(const char *s)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	clnt_raw_create
include		<rpc/rpc.h>
declaration	CLIENT *clnt_raw_create(const rpcprog_t prognum, \
			const rpcvers_t versnum)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	clnt_spcreateerror
include		<rpc/rpc.h>
declaration	char *clnt_spcreateerror(const char *s)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	clnt_tli_create
include		<rpc/rpc.h>
declaration	CLIENT *clnt_tli_create(const int fildes, \
			const struct netconfig *netconf, \
			struct netbuf *svcaddr, \
			const rpcprog_t prognum, const rpcvers_t versnum, \
			const uint_t sendsz, const uint_t recvsz)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	clnt_tp_create
include		<rpc/rpc.h>
declaration	CLIENT *clnt_tp_create(const char *host, \
			const rpcprog_t prognum, const rpcvers_t versnum, \
			const struct netconfig *netconf)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	clnt_tp_create_timed
include		<rpc/rpc.h>
declaration	CLIENT *clnt_tp_create_timed(const char	*host, \
			const rpcprog_t prognum, const rpcvers_t versnum, \
			const struct netconfig *netconf, \
			const struct timeval *timeout)
version		SUNW_0.9
exception	$return == 0
end

function	clnt_vc_create
include		<rpc/rpc.h>
declaration	CLIENT *clnt_vc_create(const int fildes, \
			struct netbuf *svcaddr, \
			const rpcprog_t prognum, const rpcvers_t versnum, \
			const uint_t sendsz, const uint_t recvsz)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	rpc_control
include		<rpc/types.h>, <rpc/rpc_com.h>
declaration	bool_t rpc_control(int op,void *info)
version		SUNW_0.8
exception	$return == FALSE
end

function	authdes_create
include		<rpc/rpc.h>
declaration	AUTH * authdes_create(char *name, unsigned window, \
			struct sockaddr *syncaddr, des_block *ckey)
version		SUNW_0.7
exception	$return == 0
end

function	authdes_lock
version		SUNW_0.7
end

function	get_myaddress
include		<rpc/rpc.h>
declaration	void get_myaddress(struct sockaddr_in *addr)
version		SUNW_0.7
end

function	getrpcport
include		<rpc/rpc.h>
declaration	void  getrpcport(char *host, int prognum, int versnum, \
			int proto)
version		SUNW_0.9
end

function	pmap_getmaps
include		<rpc/rpc.h>, <rpc/pmap_prot.h>
declaration	struct pmaplist *pmap_getmaps(struct sockaddr_in *addr)
version		SUNW_0.7
exception	$return == 0
end

function	pmap_getport
include		<rpc/rpc.h>
declaration	u_short pmap_getport(struct sockaddr_in	*addr, \
			rpcprog_t prognum, rpcvers_t versnum, rpcprot_t protocol)
version		SUNW_0.7
exception	$return == 0
end

function	pmap_rmtcall
include		<rpc/rpc.h>
declaration	enum  clnt_stat	pmap_rmtcall(struct sockaddr_in	*addr, \
			rpcprog_t prognum, rpcvers_t  versnum, rpcproc_t procnum, \
			char *in, xdrproc_t inproc, char *out, \
			xdrproc_t outproc, struct timeval tout, rpcport_t *portp)
version		SUNW_0.7
exception	$return != RPC_SUCCESS
end

function	pmap_set
include		<rpc/rpc.h>
declaration	bool_t pmap_set(rpcprog_t prognum, rpcvers_t versnum, \
			rpcprot_t protocol, u_short port)
version		SUNW_0.7
exception	$return == FALSE
end

function	pmap_unset
include		<rpc/rpc.h>
declaration	bool_t pmap_unset(rpcprog_t prognum, rpcvers_t versnum)
version		SUNW_0.7
exception	$return == FALSE
end

function	svc_getreq
include		<rpc/rpc.h>
declaration	void svc_getreq(int rdfds)
version		SUNW_0.7
end

function	svcfd_create
include		<rpc/rpc.h>
declaration	SVCXPRT *svcfd_create(int fd, u_int sendsz, u_int recvsz)
version		SUNW_0.7
exception	$return == 0
end

function	svc_fdset
version		i386=SUNW_0.7	sparc=SISCD_2.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	_new_svc_fdset
arch		i386 sparc
version		SUNW_1.1
end

function	svcraw_create
include		<rpc/rpc.h>
declaration	SVCXPRT * svcraw_create(void)
version		SUNW_0.7
exception	$return == 0
end

function	svctcp_create
include		<rpc/rpc.h>
declaration	SVCXPRT *svctcp_create(int fd, u_int sendsz, u_int recvsz)
version		SUNW_0.7
exception	$return == 0
end

function	svcudp_bufcreate
include		<rpc/rpc.h>
declaration	SVCXPRT *svcudp_bufcreate(int fd, u_int	sendsz, u_int recvsz)
version		SUNW_0.7
exception	$return == 0
end

function	svcudp_create
include		<rpc/rpc.h>
declaration	SVCXPRT * svcudp_create(int fd)
version		SUNW_0.7
exception	$return == 0
end

function	registerrpc
include		<rpc/rpc.h>
declaration	int registerrpc(rpcprog_t prognum, rpcvers_t versnum, \
			rpcproc_t procnum, char *(*procname)(), xdrproc_t inproc, \
			xdrproc_t outproc)
version		SUNW_0.7
exception	$return == -1
end

function	svc_register
include		<rpc/rpc.h>
declaration	int svc_register(SVCXPRT *xprt, rpcprog_t prognum, \
			rpcvers_t versnum, void *dispatch)
version		SUNW_0.7
exception	$return == 0
end

function	svc_unregister
include		<rpc/rpc.h>
declaration	void svc_unregister(rpcprog_t prognum, rpcvers_t versnum)
version		SUNW_0.7
end

function	callrpc
include		<rpc/rpc.h>
declaration	int callrpc(char *host, rpcprog_t prognum, rpcvers_t versnum, \
			rpcproc_t procnum, xdrproc_t inproc, char *in, \
			xdrproc_t outproc, char *out)
version		SUNW_0.7
exception	$return == 0
end

function	clnt_broadcast
include		<rpc/rpc.h>
declaration	enum  clnt_stat clnt_broadcast(rpcprog_t prognum, \
			rpcvers_t versnum, rpcproc_t procnum, \
			xdrproc_t inproc, char *in, xdrproc_t outproc, \
			char *out, resultproc_t eachresult)
version		SUNW_0.7
exception	$return != RPC_SUCCESS
end

function	clnt_door_create
version		SUNW_1.1
end

function	clntraw_create
include		<rpc/rpc.h>
declaration	CLIENT *clntraw_create(rpcprog_t prognum, rpcvers_t versnum)
version		SUNW_0.7
exception	$return == 0
end

function	clnttcp_create
include		<rpc/rpc.h>
declaration	CLIENT *clnttcp_create(struct  sockaddr_in *addr, \
			rpcprog_t prognum, rpcvers_t versnum, int *fdp, \
			u_int sendsz, u_int recvsz)
version		SUNW_0.7
exception	$return == 0
end

function	clntudp_bufcreate
include		<rpc/rpc.h>
declaration	CLIENT *clntudp_bufcreate(struct sockaddr_in *addr, \
			rpcprog_t prognum, rpcvers_t versnum, \
			struct timeval wait, int *fdp, \
			u_int sendsz, u_int recvsz)
version		SUNW_0.7
exception	$return == 0
end

function	clntudp_create
include		<rpc/rpc.h>
declaration	CLIENT *clntudp_create(struct sockaddr_in *addr, \
			rpcprog_t prognum, rpcvers_t versnum, \
			struct timeval wait, int *fdp)
version		SUNW_0.7
exception	$return == 0
end

function	svc_dg_enablecache
include		<rpc/rpc.h>
declaration	int svc_dg_enablecache(SVCXPRT *xprt, \
			const uint_t cache_size)
version		SUNW_0.7
exception	$return == 0
end

function	svc_run
include		<rpc/rpc.h>
declaration	void svc_run(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	svc_sendreply
include		<rpc/rpc.h>
declaration	bool_t svc_sendreply(const SVCXPRT *xprt, \
			const xdrproc_t	outproc, const caddr_t out)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	svc_done
include		<rpc/rpc.h>
declaration	void svc_done(SVCXPRT *xprt)
version		SUNW_0.8
end

function	svc_exit
include		<rpc/rpc.h>
declaration	void svc_exit(void)
version		SUNW_0.7
end

function	svc_freeargs
include		<rpc/rpc.h>
declaration	bool_t svc_freeargs(const SVCXPRT *xprt, \
			const xdrproc_t inproc,	caddr_t in)
version		SUNW_0.7
exception	$return == FALSE
end

function	svc_getargs
include		<rpc/rpc.h>
declaration	bool_t svc_getargs(const SVCXPRT *xprt, \
			const xdrproc_t inproc, caddr_t in)
version		SUNW_0.7
exception	$return == FALSE
end

function	svc_getreq_common
include		<rpc/rpc.h>
declaration	void svc_getreq_common(const int fd)
version		SUNW_0.7
end

function	svc_getreq_poll
include		<rpc/rpc.h>
declaration	void svc_getreq_poll(struct pollfd *pfdp, \
			const int pollretval)
version		SUNW_0.7
end

function	svc_getreqset
include		<rpc/rpc.h>
declaration	void svc_getreqset(fd_set *rdfds)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	svc_getrpccaller
include		<rpc/rpc.h>
declaration	struct netbuf *svc_getrpccaller(const SVCXPRT *xprt)
version		SUNW_0.7
exception	$return == 0
end

function	svc_control
include		<rpc/rpc.h>
declaration	bool_t svc_control(SVCXPRT *svc, const u_int req, void *info)
version		SUNW_0.7
exception	$return == FALSE
end

function	svc_create
include		<rpc/rpc.h>
declaration	int  svc_create(void (*dispatch)(struct svc_req *, \
		SVCXPRT *), const rpcprog_t prognum, \
		const rpcvers_t versnum, const char *nettype);
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	svc_destroy
include		<rpc/rpc.h>
declaration	void svc_destroy(SVCXPRT *xprt)
version		SUNW_0.7
end

function	svc_dg_create
include		<rpc/rpc.h>
declaration	SVCXPRT *svc_dg_create(const int fildes, \
			const u_int sendsz, const u_int recvsz)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	svc_fd_create
include		<rpc/rpc.h>
declaration	SVCXPRT *svc_fd_create(const int fildes, \
			const u_int sendsz, const u_int recvsz)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	svc_raw_create
include		<rpc/rpc.h>
declaration	SVCXPRT *svc_raw_create(void)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	svc_tli_create
include		<rpc/rpc.h>
declaration	SVCXPRT *svc_tli_create(const int fildes, \
			const struct netconfig *netconf, \
			const struct t_bind *bindaddr, \
			const u_int sendsz, const u_int recvsz)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	svc_tp_create
include		<rpc/rpc.h>
declaration	SVCXPRT  *svc_tp_create(void (*dispatch)(struct svc_req *, \
		SVCXPRT *), const rpcprog_t prognum, \
		const rpcvers_t versnum, const struct netconfig *netconf);
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	svc_vc_create
include		<rpc/rpc.h>
declaration	SVCXPRT *svc_vc_create(const int fildes, \
			const u_int sendsz, const u_int recvsz)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	svcerr_auth
include		<rpc/rpc.h>
declaration	void svcerr_auth(const SVCXPRT *xprt, const enum auth_stat why)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	svcerr_decode
include		<rpc/rpc.h>
declaration	void svcerr_decode(const SVCXPRT *xprt)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	svcerr_noproc
include		<rpc/rpc.h>
declaration	void svcerr_noproc(const SVCXPRT *xprt)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	svcerr_noprog
include		<rpc/rpc.h>
declaration	void svcerr_noprog(const SVCXPRT *xprt)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	svcerr_progvers
include		<rpc/rpc.h>
declaration	void svcerr_progvers(const SVCXPRT *xprt, \
			rpcvers_t low_vers, rpcvers_t high_vers)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	svcerr_systemerr
include		<rpc/rpc.h>
declaration	void svcerr_systemerr(const SVCXPRT *xprt)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	svcerr_weakauth
include		<rpc/rpc.h>
declaration	void svcerr_weakauth(const	SVCXPRT	*xprt)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	rpc_reg
include		<rpc/rpc.h>
declaration	bool_t  rpc_reg(const rpcprog_t prognum,  \
			const rpcvers_t  versnum, const rpcproc_t procnum, \
			char * (*procname)(char *), const xdrproc_t inproc, \
			const xdrproc_t outproc, const char  *nettype)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	svc_reg
include		<rpc/rpc.h>
declaration	int  svc_reg(const SVCXPRT  *xprt, const rpcprog_t prognum, \
			const rpcvers_t versnum, void (*dispatch)(), \
			const struct netconfig *netconf)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	svc_unreg
include		<rpc/rpc.h>
declaration	void svc_unreg(const rpcprog_t prognum, const	rpcvers_t versnum)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	svc_auth_reg
include		<rpc/rpc.h>
declaration	int svc_auth_reg(int cred_flavor, enum auth_stat (*handler)())
version		SUNW_0.7
exception	$return != 0
end

function	svc_door_create
version		SUNW_1.1
end

function	svc_get_local_cred
version		SUNWprivate_1.1
end

function	svc_max_pollfd
version		SUNW_1.1
end

function	svc_pollfd
version		SUNW_1.1
end

function	xprt_register
include		<rpc/rpc.h>
declaration	void xprt_register(const SVCXPRT *xprt)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	xprt_unregister
include		<rpc/rpc.h>
declaration	void xprt_unregister(const	SVCXPRT	*xprt)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	xdr_accepted_reply
include		<rpc/rpc.h>
declaration	bool_t xdr_accepted_reply(XDR *xdrs, \
			struct accepted_reply *ar)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_authsys_parms
include		<rpc/rpc.h>
declaration	bool_t xdr_authsys_parms(XDR *xdrs, struct authsys_parms *aupp)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_callhdr
include		<rpc/rpc.h>
declaration	bool_t xdr_callhdr(XDR *xdrs, struct rpc_msg *chdr)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function	xdr_callmsg
include		<rpc/rpc.h>
declaration	bool_t xdr_callmsg(XDR *xdrs, struct rpc_msg *cmsg)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_opaque_auth
include		<rpc/rpc.h>
declaration	bool_t xdr_opaque_auth(XDR *xdrs, struct opaque_auth *ap)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_rejected_reply
include		<rpc/rpc.h>
declaration	bool_t xdr_rejected_reply(XDR *xdrs, \
			struct rejected_reply *rr)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	xdr_replymsg
include		<rpc/rpc.h>
declaration	bool_t xdr_replymsg(XDR *xdrs, struct rpc_msg *rmsg)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

data		rpc_createerr
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
end

function        __rpc_createerr
version         SUNW_0.7        
end

function	rpc_gss_get_error
version		SUNW_1.1
end

function	rpc_gss_get_mech_info
version		SUNW_1.1
end

function	rpc_gss_get_mechanisms
version		SUNW_1.1
end

function	rpc_gss_get_principal_name
version		SUNW_1.1
end

function	rpc_gss_get_versions
version		SUNW_1.1
end

function	rpc_gss_getcred
version		SUNW_1.1
end

function	rpc_gss_is_installed
version		SUNW_1.1
end

function	rpc_gss_max_data_length
version		SUNW_1.1
end

function	rpc_gss_mech_to_oid
version		SUNW_1.1
end

function	rpc_gss_qop_to_num
version		SUNW_1.1
end

function	rpc_gss_seccreate
version		SUNW_1.1
end

function	rpc_gss_set_callback
version		SUNW_1.1
end

function	rpc_gss_set_defaults
version		SUNW_1.1
end

function	rpc_gss_set_svc_name
version		SUNW_1.1
end

function	rpc_gss_svc_max_data_length
version		SUNW_1.1
end

function	rpcb_getmaps
include		<rpc/rpc.h>
declaration	rpcblist *rpcb_getmaps \
			(const struct netconfig *netconf, const char *host)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	rpcb_getaddr
include		<rpc/rpc.h>
declaration	bool_t rpcb_getaddr(const rpcprog_t prognum, \
			const rpcvers_t versnum, \
			const struct netconfig *netconf, \
			struct netbuf *svcaddr,	const char *host)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	rpcb_gettime
include		<rpc/rpc.h>
declaration	bool_t rpcb_gettime(const char *host, time_t *timep)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	rpcb_rmtcall
include		<rpc/rpc.h>
declaration	enum clnt_stat rpcb_rmtcall(const struct netconfig *netconf, \
			const char *host, const rpcprog_t prognum, \
			const rpcvers_t versnum, const rpcproc_t procnum, \
			const xdrproc_t inproc,	const caddr_t in, \
			const xdrproc_t	outproc, caddr_t out, \
			const struct timeval tout, struct netbuf *svcaddr)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return != RPC_SUCCESS
end

function	rpcb_set
include		<rpc/rpc.h>
declaration	bool_t rpcb_set(const rpcprog_t prognum, \
			const rpcvers_t versnum, \
			const struct netconfig *netconf, \
			const struct netbuf *svcaddr)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	rpcb_unset
include		<rpc/rpc.h>
declaration	bool_t rpcb_unset(const rpcprog_t prognum, \
			const rpcvers_t versnum, \
			const struct netconfig *netconf)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == FALSE
end

function	authdes_getucred
include		<rpc/rpc.h>, <sys/types.h>
declaration	int authdes_getucred(const struct authdes_cred *adc, \
			uid_t *uidp, gid_t *gidp, short *gidlenp, \
			gid_t *gidlist)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	netname2host
include		<rpc/rpc.h>, <sys/types.h>
declaration	int netname2host(const char *name, char	 *host, \
			const int hostlen)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	netname2user
include		<rpc/rpc.h>, <sys/types.h>
declaration	int netname2user(const  char  *name, uid_t *uidp, \
			gid_t *gidp, int *gidlenp, gid_t *gidlist)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	user2netname
include		<rpc/rpc.h>, <sys/types.h>
declaration	int user2netname(char *name, const uid_t uid, \
			const char *domain)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	authdes_seccreate
include		<rpc/rpc.h>, <sys/types.h>
declaration	AUTH *authdes_seccreate(const char *name, \
			const unsigned	int window, const char *timehost, \
			const des_block	*ckey)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	getnetname
include		<rpc/rpc.h>, <sys/types.h>
declaration	int getnetname(char *name)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	host2netname
include		<rpc/rpc.h>, <sys/types.h>
declaration	int host2netname(char *name, const char *host, \
			const char *domain)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == 0
end

function	key_decryptsession
include		<rpc/rpc.h>, <sys/types.h>
declaration	int  key_decryptsession(const char *remotename, \
			des_block *deskey)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	key_encryptsession
include		<rpc/rpc.h>, <sys/types.h>
declaration	int  key_encryptsession(const char *remotename, \
			des_block *deskey)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	key_gendes
include		<rpc/rpc.h>, <sys/types.h>
declaration	int key_gendes(des_block *deskey)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	key_setsecret
include		<rpc/rpc.h>, <sys/types.h>
declaration	int key_setsecret(const char *key)
version		sparc=SYSVABI_1.3 i386=SYSVABI_1.3 sparcv9=SUNW_0.7 amd64=SUNW_0.7
exception	$return == -1
end

function	key_secretkey_is_set
include		<rpc/rpc.h>, <sys/types.h>
declaration	int key_secretkey_is_set(void)
version		SUNW_0.7
exception	$return == 0
end

function	endrpcent
version		SUNW_0.7
end

function	maxbno
version		SUNW_0.7
end

function	clnt_send
include		<rpc/rpc.h>, <sys/types.h>
declaration	enum clnt_stat clnt_send(CLIENT *clnt, rpcproc_t procnum, \
			xdrproc_t proc, const caddr_t in)
version		SUNW_1.8
exception	$return != RPC_SUCCESS
end

function	svc_add_input
include		<rpc/rpc.h>
declaration	int svc_add_input(int user_fd, unsigned int user_events,  \
			void (*user_callback)(int id, int fd,		  \
                               unsigned int events, void* cookie), void* user_cookie)
version		SUNW_1.8
exception	$return != -1
end

function	svc_remove_input
include		<rpc/rpc.h>
declaration	int svc_remove_input(int id)
version		SUNW_1.8
exception	$return != -1
end

function	svc_fd_negotiate_ucred
include		<rpc/rpc.h>
declaration	void svc_fd_negotiate_ucred(int fd)
version		SUNW_1.9
end

function	svc_getcallerucred
include		<rpc/rpc.h>
declaration	int svc_getcallerucred(const SVCXPRT *xprt, \
		    struct ucred_s **ucred)
version		SUNW_1.9
end
