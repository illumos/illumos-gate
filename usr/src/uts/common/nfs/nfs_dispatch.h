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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 *	All rights reserved.
 *	Use is subject to license terms.
 */


#ifndef _NFS_DISPATCH_H
#define	_NFS_DISPATCH_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * RPC dispatch table
 * Indexed by version, proc
 */

typedef struct rpcdisp {
	void	  (*dis_proc)();	/* proc to call */
	xdrproc_t dis_xdrargs;		/* xdr routine to get args */
	xdrproc_t dis_fastxdrargs;	/* `fast' xdr routine to get args */
	int	  dis_argsz;		/* sizeof args */
	xdrproc_t dis_xdrres;		/* xdr routine to put results */
	xdrproc_t dis_fastxdrres;	/* `fast' xdr routine to put results */
	int	  dis_ressz;		/* size of results */
	void	  (*dis_resfree)();	/* frees space allocated by proc */
	int	  dis_flags;		/* flags, see below */
	void	  *(*dis_getfh)();	/* returns the fhandle for the req */
} rpcdisp_t;

#define	RPC_IDEMPOTENT	0x1	/* idempotent or not */
/*
 * Be very careful about which NFS procedures get the RPC_ALLOWANON bit.
 * Right now, if this bit is on, we ignore the results of per NFS request
 * access control.
 */
#define	RPC_ALLOWANON	0x2	/* allow anonymous access */
#define	RPC_MAPRESP	0x4	/* use mapped response buffer */
#define	RPC_AVOIDWORK	0x8	/* do work avoidance for dups */
#define	RPC_PUBLICFH_OK	0x10	/* allow use of public filehandle */

typedef struct rpc_disptable {
	int dis_nprocs;
	char **dis_procnames;
	kstat_named_t **dis_proccntp;
	kstat_t ***dis_prociop;
	struct rpcdisp *dis_table;
} rpc_disptable_t;

void	rpc_null(caddr_t *, caddr_t *, struct exportinfo *, struct svc_req *,
    cred_t *, bool_t);

#ifdef	__cplusplus
}
#endif

#endif /* _NFS_DISPATCH_H */
