/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 RackTop Systems.
 */

#include <sys/systm.h>
#include <sys/sdt.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/auth_unix.h>
#include <rpc/auth_des.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <nfs/nfs4.h>
#include <nfs/nfs_dispatch.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>

static void
rfs4_err_resp(COMPOUND4args *args, COMPOUND4res *resp, nfsstat4 err)
{
	size_t	sz;

	resp->array_len = 1;
	sz = resp->array_len * sizeof (nfs_resop4);
	resp->array = kmem_zalloc(sz, KM_SLEEP);

	resp->array[0].resop = args->array[0].argop;
	resp->status = resp->array[0].nfs_resop4_u.opillegal.status = err;
}

/*
 * The function checks if given compound operation is allowed
 * to be the very fist operation in compound array.
 */
static bool_t
valid_first_compound_op(nfs_opnum4 op)
{
	if (op == OP_BIND_CONN_TO_SESSION	||
	    op == OP_SEQUENCE			||
	    op == OP_EXCHANGE_ID		||
	    op == OP_CREATE_SESSION		||
	    op == OP_DESTROY_SESSION		||
	    op == OP_DESTROY_CLIENTID		||
	    op == OP_ILLEGAL)
		return (TRUE);

	return (FALSE);
}

/*
 * The function verifies arguments passed to mds_op_compound.
 * If agrguments are valid, NFS4_OK is returned, otherwise
 * function returns correspoinding NFS4 error code.
 */
static nfsstat4
verify_compound_args(COMPOUND4args *args)
{
	if (args->array_len == 0)
		return (NFS4_OK);

	if (!valid_first_compound_op(args->array[0].argop))
		return (NFS4ERR_OP_NOT_IN_SESSION);

	if (args->array_len > 1 && args->array[0].argop != OP_SEQUENCE) {
		/*
		 * Compound is outside the session. There must be
		 * only one operation in request.
		 */
		return (NFS4ERR_NOT_ONLY_OP);
	}

	return (NFS4_OK);
}

static void
rfs4x_dispatch_done(compound_state_t *cs)
{
	if (cs->slot)
		rfs4x_sequence_done(cs->cmpresp, cs);
	else {
		rfs4_compound_free(cs->cmpresp);
	}
	cs->cs_flags |= RFS4_DISPATCH_DONE;
}

static bool_t
xdr_compound_wrapper(XDR *xdrs, compound_state_t *cs)
{
	COMPOUND4res *resp = cs->cmpresp;
	bool_t res = FALSE;
	bool_t isreal = (xdrs->x_handy != 0);    /* real data encoding ? */

	if (!(cs->cs_flags & RFS4_DISPATCH_DONE)) {
		res = xdr_COMPOUND4res_srv(xdrs, resp);
		if (isreal)
			rfs4x_dispatch_done(cs);
	}

	return (res);
}

int
rfs4x_dispatch(struct svc_req *req, SVCXPRT *xprt, char *ap)
{
	struct compound_state cs;
	COMPOUND4res res_buf;
	COMPOUND4res *rbp;
	COMPOUND4args	*cap;
	int rpcerr = 0;
	nfsstat4 error;

	bzero(&res_buf, sizeof (COMPOUND4res));
	rbp = &res_buf;
	cap = (COMPOUND4args *)ap;
	rfs4_init_compound_state(&cs);

	cs.statusp = &error;
	cs.cmpresp = rbp;

	error = verify_compound_args(cap);
	if (error != NFS4_OK) {
		rfs4_err_resp(cap, rbp, error);
		goto out_send;
	}

	error = rfs4x_sequence_prep(cap, rbp, &cs, xprt);
	if (error != NFS4_OK) {
		if (error != nfserr_replay_cache)
			rfs4_err_resp(cap, rbp, error);
		goto out_send;
	}

	/* Regular processing */
	curthread->t_flag |= T_DONTPEND;
	rfs4_compound(cap, rbp, &cs, req, &rpcerr);
	curthread->t_flag &= ~T_DONTPEND;

	/*
	 * On RPC error, short sendreply
	 */
	if (rpcerr) {
		goto out_free;
	}

	if (curthread->t_flag & T_WOULDBLOCK) {
		curthread->t_flag &= ~T_WOULDBLOCK;
		error = 1;
		goto out_free;
	}

out_send:
	if (!svc_sendreply(xprt, xdr_compound_wrapper, (char *)&cs)) {
		DTRACE_PROBE2(sendfail, SVCXPRT *, xprt,
		    compound_state_t *, &cs);
		svcerr_systemerr(xprt);
		rpcerr = 1;
	}

out_free:
	if (!(cs.cs_flags & RFS4_DISPATCH_DONE)) {
		rfs4x_dispatch_done(&cs);
	}

	rfs4_fini_compound_state(&cs);
	return ((error != NFS4_OK || rpcerr) ? 1 : 0);
}
