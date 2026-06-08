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
 *
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 * Copyright 2017-2026 RackTop Systems.
 */

#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/rpcsec_gss.h>
#include <sys/sdt.h>
#include <sys/ddi.h>
#include <sys/disp.h>
#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/lm.h>
#include <sys/systeminfo.h>
#include <sys/flock.h>

/* Helpers */

/* Principal handling routines */
/* returns 0 if no match; or 1 for a match */
int
rfs4_cmp_cred_set(cred_set_t *p, struct compound_state *cs)
{
	int			 rc = 0;
	rpc_gss_principal_t	 recp;		/* cached clnt princ */
	rpc_gss_principal_t	 ibrp;		/* inbound req princ */


	if (p->cp_cr == NULL)
		return (rc);	/* nothing to compare with */

	if (p->cp_aflavor != cs->req->rq_cred.oa_flavor)
		return (rc);

	if (p->cp_secmod != cs->nfsflavor)
		return (rc);

	if (crcmp(p->cp_cr, cs->basecr))
		return (rc);

	switch (p->cp_aflavor) {
	case AUTH_DES:
		rc = (strcmp(p->cp_princ, cs->principal) == 0);
		break;

	case RPCSEC_GSS:
		recp = (rpc_gss_principal_t)p->cp_princ;
		ibrp = (rpc_gss_principal_t)cs->principal;

		if (recp->len != ibrp->len)
			break;
		rc = (bcmp(recp->name, ibrp->name, ibrp->len) == 0);
		break;

	case AUTH_SYS:
	case AUTH_NONE:
	default:
		rc = 1;
		break;
	}
	return (rc);
}

static rpc_gss_principal_t
rfs4_dup_princ(rpc_gss_principal_t ppl)
{
	rpc_gss_principal_t	pdup;
	size_t			len;

	if (ppl == NULL)
		return (NULL);

	len = sizeof (int) + ppl->len;
	pdup = (rpc_gss_principal_t)kmem_alloc(len, KM_SLEEP);
	bcopy(ppl, pdup, len);
	return (pdup);
}

void
rfs4_set_cred_set(cred_set_t *p, struct compound_state *cs)
{
	ASSERT(p->cp_cr == NULL);

	p->cp_cr = crdup(cs->basecr);
	p->cp_aflavor = cs->req->rq_cred.oa_flavor;
	p->cp_secmod = cs->nfsflavor;	/* secmod != flavor for RPCSEC_GSS */

	/*
	 * Set principal as per security flavor
	 */
	switch (p->cp_aflavor) {
	case AUTH_DES:
		p->cp_princ = strdup(cs->principal);
		break;

	case RPCSEC_GSS:
		p->cp_princ =
		    (caddr_t)rfs4_dup_princ((rpc_gss_principal_t)cs->principal);
		break;

	case AUTH_SYS:
	case AUTH_NONE:
	default:
		break;
	}
}

void
rfs4_free_cred_set(cred_set_t *p)
{
	rpc_gss_principal_t ppl;

	if (p->cp_cr == NULL)
		return;

	switch (p->cp_aflavor) {
	case AUTH_DES:
		kmem_free(p->cp_princ, strlen(p->cp_princ) + 1);
		break;

	case RPCSEC_GSS:
		ppl = (rpc_gss_principal_t)p->cp_princ;
		kmem_free(ppl, ppl->len + sizeof (int));
		break;
	}

	crfree(p->cp_cr);
	p->cp_cr = NULL;
}

/* principal end */

bool_t
nfs_clid4_cmp(nfs_client_id4 *s1, nfs_client_id4 *s2)
{
	if (s1->verifier != s2->verifier)
		return (FALSE);
	if (s1->id_len != s2->id_len)
		return (FALSE);
	if (bcmp(s1->id_val, s2->id_val, s2->id_len))
		return (FALSE);
	return (TRUE);
}

/*
 * Rudimentary server implementation (XXX - for now)
 */
void
rfs4x_get_server_impl_id(EXCHANGE_ID4resok *resp)
{
	char		*sol_impl = "illumos NFSv4.1 Server Implementation";
	char		*sol_idom = "nfsv41.ietf.org";
	void		*p;
	uint_t		 len = 0;
	nfs_impl_id4	*nip;

	resp->eir_server_impl_id.eir_server_impl_id_len = 1;
	nip = kmem_zalloc(sizeof (nfs_impl_id4), KM_SLEEP);
	resp->eir_server_impl_id.eir_server_impl_id_val = nip;

	/* Domain */
	nip->nii_domain.utf8string_len = len = strlen(sol_idom);
	p = kmem_zalloc(len * sizeof (char), KM_SLEEP);
	nip->nii_domain.utf8string_val = p;
	bcopy(sol_idom, p, len);

	/* Implementation */
	nip->nii_name.utf8string_len = len = strlen(sol_impl);
	p = kmem_zalloc(len * sizeof (char), KM_SLEEP);
	nip->nii_name.utf8string_val = p;
	bcopy(sol_impl, p, len);

	/* Time is zero for now */
}

static void
rfs4x_set_trunkinfo(EXCHANGE_ID4resok *rok)
{
	const char *nodename = uts_nodename();
	size_t nd_len = strlen(nodename);
	size_t hw_len = strlen(hw_serial);
	size_t id_len = nd_len + 1 + hw_len;
	char *s = kmem_alloc(id_len, KM_SLEEP);
	server_owner4 *so = &rok->eir_server_owner;
	struct eir_server_scope *ss = &rok->eir_server_scope;

	(void) memcpy(s, nodename, nd_len);
	s[nd_len] = ' ';
	(void) memcpy(s + nd_len + 1, hw_serial, hw_len);

	so->so_major_id.so_major_id_len = id_len;
	so->so_major_id.so_major_id_val = s;

	ss->eir_server_scope_len = id_len;
	ss->eir_server_scope_val = kmem_alloc(id_len, KM_SLEEP);
	(void) memcpy(ss->eir_server_scope_val, s, id_len);

	rok->eir_server_owner.so_minor_id = 0;
}

static bool_t
client_has_state_locked(rfs4_client_t *cp)
{
	if (list_head(&cp->rc_sessions) != NULL ||
	    list_head(&cp->rc_openownerlist) != NULL)
		return (TRUE);
	else
		return (FALSE);
}

/* OPERATIONS */

/*
 * EXCHANGE_ID
 * RFC5661 sec. 18.35
 */
void
rfs4x_op_exchange_id(nfs_argop4 *argop, nfs_resop4 *resop,
    struct svc_req *req, compound_state_t *cs)
{
	EXCHANGE_ID4args	*args = &argop->nfs_argop4_u.opexchange_id;
	EXCHANGE_ID4res		*resp = &resop->nfs_resop4_u.opexchange_id;
	EXCHANGE_ID4resok	*rok = &resp->EXCHANGE_ID4res_u.eir_resok4;
	rfs4_client_t		*cp, *conf;
	bool_t			 update, create;
	client_owner4		*cop;
	nfs_client_id4		 cid; /* cip */
	nfsstat4		status = NFS4_OK;
	nfs4_srv_t		*nsrv4;

	DTRACE_NFSV4_2(op__exchange__id__start,
	    struct compound_state *, cs,
	    EXCHANGE_ID4args *, args);

	/*
	 * EXCHANGE_ID's may be preceded by SEQUENCE
	 *
	 * Check that eia_flags only has "valid" spec bits
	 * and that no 'eir_flag' ONLY bits are specified.
	 */
	if (args->eia_flags & ~EXID4_FLAG_MASK) {
		status = NFS4ERR_INVAL;
		goto err;
	}

	update = (args->eia_flags & EXCHGID4_FLAG_UPD_CONFIRMED_REC_A);
	cop = &args->eia_clientowner;
	conf = NULL;

	cid.verifier = cop->co_verifier;
	cid.id_len = cop->co_ownerid.co_ownerid_len;
	cid.id_val = cop->co_ownerid.co_ownerid_val;
	cid.cl_addr = (struct sockaddr *)svc_getrpccaller(req->rq_xprt)->buf;

	/*
	 * Refer to Section 18.35.4
	 */
again:
	create = TRUE;
	cp = rfs4_findclient(&cid, &create, conf);

	if (cp == NULL) {
		status = NFS4ERR_RESOURCE;
		if (conf)
			rfs4_client_rele(conf);
		goto err;
	}

	if (conf) {
		rfs4_dbe_lock(cp->rc_dbe);
		if (cp->rc_cp_confirmed == NULL)
			cp->rc_cp_confirmed = conf;
		else
			rfs4_client_rele(conf);
		rfs4_dbe_unlock(cp->rc_dbe);
		conf = NULL;
	}

	if (create) {
		/* Record just created */
		if (!update) {
			/* case 1 - utok */
			rfs4_set_cred_set(&cp->rc_cr_set, cs);

			rok->eir_clientid = cp->rc_clientid;
			rok->eir_sequenceid = cp->rc_contrived.xi_sid;
			goto out;
		} else {
			/* no record and trying to update */
			status = NFS4ERR_NOENT;
			goto err_out;
		}
	}

	/* Record exists */

	/* expired clients should be ignored and released */
	if (rfs4_lease_expired(cp)) {
		rfs4_client_close(cp);
		update = FALSE;
		goto again;
	}

	if (cp->rc_need_confirm) {
		/* UNCONFIRMED */
		if (!update) {
			/* case 4 - utok */
			rfs4_client_close(cp);

			ASSERT(!update);
			goto again;
		} else {
			/* case 7 - utok */
			status = NFS4ERR_NOENT;
			goto err_out;
		}
	}

	/* record exists and confirmed */
	if (!update) {
		if (!rfs4_cmp_cred_set(&cp->rc_cr_set, cs)) {
			/* case 3 */
			/* lease is checked above */
			rfs4_dbe_lock(cp->rc_dbe);
			if (!client_has_state_locked(cp)) {
				rfs4_dbe_unlock(cp->rc_dbe);

				rfs4_client_close(cp);
				ASSERT(!update);
				goto again;
			}
			rfs4_dbe_unlock(cp->rc_dbe);

			/*
			 * clid_in_use. old_client_ret has unexpired
			 * lease with state.
			 */
			status = NFS4ERR_CLID_INUSE;
			goto err_out;
		} else if (cp->rc_nfs_client.verifier != cid.verifier) {
			/* case 5: Client Restart */
			/*
			 * Skip confirmed client record to allow confirmed
			 * and unconfirmed state at the same time. The number
			 * of states can collapse to one once the server
			 * receives an applicable CREATE_SESSION or EXCHANGE_ID.
			 */
			ASSERT(conf == NULL);
			conf = cp;
			ASSERT(!update);
			goto again;

		} else if (nfs_clid4_cmp(&cp->rc_nfs_client, &cid)) {
			/* case 2 - utok */
			rok->eir_clientid = cp->rc_clientid;
			rok->eir_sequenceid = cp->rc_contrived.xi_sid;
			/* trickle down to "out" */

		} else {
			/* something is really wacky in srv state */
			status = NFS4ERR_SERVERFAULT;
			goto err_out;
		}

	} else { /* UPDATE */
		if (cp->rc_nfs_client.verifier != cid.verifier) {
			/* 18.35.4 case 8 */
			status = NFS4ERR_NOT_SAME;
			goto err_out;
		}
		if (!rfs4_cmp_cred_set(&cp->rc_cr_set, cs)) {
			/* 18.35.4 case 9 */
			status = NFS4ERR_PERM;
			goto err_out;
		}

		/* case 6 - utok */
		rok->eir_clientid = cp->rc_clientid;
		rok->eir_sequenceid = cp->rc_contrived.xi_sid;
		/* trickle down to "out" */
	}
out:
	rok->eir_flags = 0;
	if (resp->eir_status == NFS4_OK && !cp->rc_need_confirm)
		rok->eir_flags |= EXCHGID4_FLAG_CONFIRMED_R;
	cp->rc_minorversion = cs->minorversion;

	/*
	 * State Protection (See sec. 2.10.8.3)
	 */
	cp->rc_state_prot.sp_type = args->eia_state_protect.spa_how;
	switch (cp->rc_state_prot.sp_type) {
	case SP4_NONE:
		break;

	case SP4_MACH_CRED:
		break;

	case SP4_SSV:
		/*
		 * SSV state protection is not implemented.
		 */
		status = NFS4ERR_ENCR_ALG_UNSUPP;
		goto err_out;
	default:
		status = NFS4ERR_INVAL;
		goto err_out;

	}

	/*
	 * Referrals supports
	 */
	if (args->eia_flags & EXCHGID4_FLAG_SUPP_MOVED_REFER) {
		rok->eir_flags |= EXCHGID4_FLAG_SUPP_MOVED_REFER;
	}

	/*
	 * Migration/Replication not (yet) supported
	 */
	if (args->eia_flags & EXCHGID4_FLAG_SUPP_MOVED_MIGR)
		rok->eir_flags &= ~EXCHGID4_FLAG_SUPP_MOVED_MIGR;

	/*
	 * RFC8881 Section 13.1 Client ID and Session Considerations
	 * Non-metadata server, do not support pNFS (yet).
	 */
	rok->eir_flags |= EXCHGID4_FLAG_USE_NON_PNFS;

	/* force no state protection for now */
	rok->eir_state_protect.spr_how = SP4_NONE;

	/* Implementation specific mojo */
	if (args->eia_client_impl_id.eia_client_impl_id_len != 0) {
		/* EMPTY */;
	}

	nsrv4 = nfs4_get_srv();

	/* Record clientid in stable storage */
	rfs4_ss_clid(nsrv4, cp);

	/* Server's implementation */
	rfs4x_get_server_impl_id(rok);

	/* compute trunking capabilities */
	bzero(&rok->eir_server_scope, sizeof (rok->eir_server_scope));
	bzero(&rok->eir_server_owner, sizeof (server_owner4));

	/* Add trunk handling */
	rfs4x_set_trunkinfo(rok);

	/*
	 * Check to see if client can perform reclaims
	 */
	rfs4_ss_chkclid(nsrv4, cp);

err_out:
	rfs4_client_rele(cp);
err:
	*cs->statusp = resp->eir_status = status;

	DTRACE_NFSV4_2(op__exchange__id__done,
	    struct compound_state *, cs,
	    EXCHANGE_ID4res *, resp);
}

void
rfs4x_exchange_id_free(nfs_resop4 *resop)
{
	EXCHANGE_ID4res		*resp = &resop->nfs_resop4_u.opexchange_id;
	EXCHANGE_ID4resok	*rok = &resp->EXCHANGE_ID4res_u.eir_resok4;
	struct server_owner4	*sop = &rok->eir_server_owner;
	nfs_impl_id4		*nip;
	int			 len = 0;

	/* Server Owner: major */
	if ((len = sop->so_major_id.so_major_id_len) != 0)
		kmem_free(sop->so_major_id.so_major_id_val, len);

	if ((nip = rok->eir_server_impl_id.eir_server_impl_id_val) != NULL) {
		/* Immplementation */
		len = nip->nii_name.utf8string_len;
		kmem_free(nip->nii_name.utf8string_val, len * sizeof (char));

		/* Domain */
		len = nip->nii_domain.utf8string_len;
		kmem_free(nip->nii_domain.utf8string_val, len * sizeof (char));

		/* Server Impl */
		kmem_free(nip, sizeof (nfs_impl_id4));
	}
}

void
rfs4x_op_create_session(nfs_argop4 *argop, nfs_resop4 *resop,
    struct svc_req *req, compound_state_t *cs)
{
	CREATE_SESSION4args	*args = &argop->nfs_argop4_u.opcreate_session;
	CREATE_SESSION4res	*resp = &resop->nfs_resop4_u.opcreate_session;
	CREATE_SESSION4resok	*rok = &resp->CREATE_SESSION4res_u.csr_resok4;
	CREATE_SESSION4resok	*crp;
	rfs4_client_t		*cp;
	rfs4_session_t		*sp;
	session41_create_t	 sca;
	sequenceid4		 stseq;
	sequenceid4		 agseq;
	nfsstat4		 status = NFS4_OK;

	DTRACE_NFSV4_2(op__create__session__start,
	    struct compound_state *, cs,
	    CREATE_SESSION4args*, args);

	/*
	 * A CREATE_SESSION request can be prefixed by OP_SEQUENCE.
	 * In this case, the newly created session has no relation
	 * to the sessid used for the OP_SEQUENCE.
	 */

	/*
	 * Find the clientid
	 */
	cp = rfs4_findclient_by_id(args->csa_clientid, TRUE);
	if (cp == NULL) {
		status = NFS4ERR_STALE_CLIENTID;
		goto out;
	}

	/*
	 * Make sure the lease is still valid.
	 */
	if (rfs4_lease_expired(cp)) {
		rfs4_client_close(cp);
		status = NFS4ERR_STALE_CLIENTID;
		goto out;
	}

	/*
	 * Sequenceid processing (handling replay's, etc)
	 */
	agseq = args->csa_sequence;
	stseq = cp->rc_contrived.xi_sid;
	if (stseq == agseq + 1) {
		/*
		 * If the previous sequenceid, then must be a replay of a
		 * previous CREATE_SESSION; return the cached result.
		 */
		crp = (CREATE_SESSION4resok *)&cp->rc_contrived.cs_res;
		status = cp->rc_contrived.cs_status;
		rok->csr_sequence = agseq;
		bcopy(crp->csr_sessionid, rok->csr_sessionid,
		    sizeof (sessionid4));
		rok->csr_flags = crp->csr_flags;
		rok->csr_fore_chan_attrs = crp->csr_fore_chan_attrs;
		rok->csr_back_chan_attrs = crp->csr_back_chan_attrs;

		rfs4_update_lease(cp);
		rfs4_client_rele(cp);
		goto out;
	}

	if (stseq != agseq) {
		/*
		 * No way to differentiate MISORD_NEWREQ vs. MISORD_REPLAY,
		 * so anything else, we simply treat as SEQ_MISORDERED.
		 */
		status = NFS4ERR_SEQ_MISORDERED;
		rfs4_client_rele(cp);
		goto out;
	}

	/*
	 * Clientid confirmation
	 */
	if (cp->rc_need_confirm) {
		if (rfs4_cmp_cred_set(&cp->rc_cr_set, cs)) {
			cp->rc_need_confirm = FALSE;
			if (cp->rc_cp_confirmed != NULL) {
				rfs4_client_close(cp->rc_cp_confirmed);
				cp->rc_cp_confirmed = NULL;
			}
		} else {
			status = NFS4ERR_CLID_INUSE;
			rfs4_client_rele(cp);
			goto out;
		}
	}

	/*
	 * Session creation
	 */
	sca.cs_error = 0;
	sca.cs_req = req;
	sca.cs_client = cp;
	sca.cs_aotw = *args;
	sp = rfs4x_createsession(&sca);

	if (sca.cs_error) {
		status = sca.cs_error;
		rfs4_client_rele(cp);
		if (sp != NULL)
			rfs4x_session_rele(sp);
		goto out;
	}

	if (sp == NULL) {
		status = NFS4ERR_SERVERFAULT;
		rfs4_client_rele(cp);
		goto out;
	}

	/*
	 * Need to store the result in the rfs4_client_t's contrived
	 * result slot and then respond from there. This way, when the
	 * csa_sequence == contrived.cc_sid, we can return the latest
	 * cached result. (see replay: above)
	 */
	crp = (CREATE_SESSION4resok *)&cp->rc_contrived.cs_res;
	cp->rc_contrived.cs_status = NFS4_OK;
	rok->csr_sequence = crp->csr_sequence = cp->rc_contrived.xi_sid;
	bcopy(sp->sn_sessid, rok->csr_sessionid, sizeof (sessionid4));
	bcopy(sp->sn_sessid, crp->csr_sessionid, sizeof (sessionid4));
	rok->csr_flags = crp->csr_flags = sp->sn_csflags;

	cp->rc_contrived.xi_sid++;

	rok->csr_fore_chan_attrs =
	    crp->csr_fore_chan_attrs = sp->cn_attrs;
	rok->csr_back_chan_attrs = crp->csr_back_chan_attrs =
	    sp->cn_back_attrs;

	rfs4_update_lease(cp);

	/*
	 * References from the session to the client are
	 * accounted for while session is being created.
	 */
	rfs4_client_rele(cp);
	rfs4x_session_rele(sp);
out:
	*cs->statusp = resp->csr_status = status;

	DTRACE_NFSV4_2(op__create__session__done,
	    struct compound_state *, cs,
	    CREATE_SESSION4res *, resp);
}

void
rfs4x_op_destroy_session(nfs_argop4 *argop, nfs_resop4 *resop,
    struct svc_req *req __unused, compound_state_t *cs)
{
	DESTROY_SESSION4args	*args = &argop->nfs_argop4_u.opdestroy_session;
	DESTROY_SESSION4res	*resp = &resop->nfs_resop4_u.opdestroy_session;
	rfs4_session_t		*sp;
	rfs4_client_t		*cp;
	nfsstat4 status = NFS4_OK;
	int addref = 0;		/* additional reference */

	DTRACE_NFSV4_2(op__destroy__session__start,
	    struct compound_state *, cs,
	    DESTROY_SESSION4args *, args);

	/* section 18.37.3 rfc5661 */
	if (rfs4_has_session(cs)) {
		/* compound with a sequence */
		if (bcmp(args->dsa_sessionid, cs->sp->sn_sessid,
		    sizeof (sessionid4)) == 0) {
			/*
			 * Same session.
			 * must be the final operation in the COMPOUND request
			 */
			if ((cs->op_pos + 1) != cs->op_len) {
				status = NFS4ERR_NOT_ONLY_OP;
				goto out;
			}
			addref++;
		} else {
			/* Not the same session */
			DTRACE_PROBE(nfss41__i__destroy_encap_session);

		}
	}

	sp = rfs4x_findsession_by_id(args->dsa_sessionid);
	if (sp == NULL) {
		status = NFS4ERR_BADSESSION;
		goto out;
	}

	/*
	 * State Protection (See sec. 2.10.8.3)
	 *
	 * verify cred that was used to create the session matches and is in
	 * concordance w/the state protection type used.
	 */
	cp = sp->sn_clnt;
	switch (cp->rc_state_prot.sp_type) {
	case SP4_MACH_CRED:
		if (!rfs4_cmp_cred_set(&cp->rc_cr_set, cs)) {
			status = NFS4ERR_PERM;
			goto err_out;
		}
		break;

	case SP4_SSV:
		/*
		 * Todo -- Missing SSV validation here, if/when
		 * SSV state protection is implemented.
		 * Should not get this after check in EXCHANGE_ID
		 */
		status = NFS4ERR_PERM;
		goto err_out;

	case SP4_NONE:
		break;

	default:
		break;
	}

	status = rfs4x_destroysession(sp, 2 + addref);
err_out:
	rfs4x_session_rele(sp);
out:
	*cs->statusp = resp->dsr_status = status;

	DTRACE_NFSV4_2(op__destroy__session__done,
	    struct compound_state *, cs,
	    DESTROY_SESSION4res *, resp);
}

/*
 * The thread will traverse the entire list pinging the connections
 * that need it and refreshing any stale/dead connections.
 */
static void
ping_cb_null_thr(rfs4_session_t *sp)
{
	CLIENT			*ch = NULL;
	struct timeval		tv;
	enum clnt_stat		cs;
	int			conn_num, attempts = 5;

	tv.tv_sec = 30;
	tv.tv_usec = 0;

	if ((ch = rfs4x_cb_getch(sp)) == NULL)
		goto out;

	/*
	 * Flag to let RPC know these are ping calls. RPC will only use
	 * untested connections.
	 */

	CLNT_CONTROL(ch, CLSET_CB_TEST, (void *)NULL);

	/*
	 * If another thread is working on the pings then
	 * just exit.
	 */

	rfs4_dbe_lock(sp->sn_dbe);
	if (sp->sn_bc.pnginprog != 0) {
		rfs4_dbe_unlock(sp->sn_dbe);
		goto out;
	}
	sp->sn_bc.pnginprog = 1;
	rfs4_dbe_unlock(sp->sn_dbe);

	/*
	 * Get the number of untested conections
	 */

	if (!CLNT_CONTROL(ch, CLGET_CB_UNTESTED, (void *)&conn_num))
		goto out;

	/*
	 * If number of untested connections is zero, either
	 * - another thread's already tested it
	 * - a previously tested connection is being reused
	 * So no further testing is required
	 */

	if (conn_num == 0) {
		rfs4_dbe_lock(sp->sn_dbe);
		sp->sn_bc.paths++;
		if (sp->sn_bc.pngcnt)
			sp->sn_bc.pngcnt--;
		rfs4_dbe_unlock(sp->sn_dbe);
		goto out;
	}

call_again:
	while (conn_num-- > 0) {

		/*
		 * With CB_TEST flag set, RPC iterates over untested
		 * connections for each of these CLNT_CALL()
		 */

		cs = CLNT_CALL(ch, CB_NULL, xdr_void, NULL, xdr_void, NULL, tv);
		if (cs == RPC_SUCCESS) {
			rfs4_dbe_lock(sp->sn_dbe);
			sp->sn_bc.paths++;
			sp->sn_bc.pngcnt--;
			rfs4_dbe_unlock(sp->sn_dbe);
		}
	}

	rfs4_dbe_lock(sp->sn_dbe);
	if (sp->sn_bc.paths == 0) {
		sp->sn_bc.failed = 1;
		cmn_err(CE_NOTE, "Unable to ping any back channel\n");
	}
	rfs4_dbe_unlock(sp->sn_dbe);

	if (!CLNT_CONTROL(ch, CLGET_CB_UNTESTED, (void *)&conn_num))
		goto out;

	if (conn_num != 0) {
		/*
		 * Pause inbetween attempts and
		 * only try 5 times.
		 */
		attempts--;
		if (attempts > 0) {
			delay(2 * drv_usectohz(1000000));
			goto call_again;
		}
		DTRACE_PROBE(nfss41__i__cb_null_failed_attempts);
	}
out:
	rfs4_dbe_lock(sp->sn_dbe);
	sp->sn_bc.pnginprog = 0;
	rfs4_dbe_unlock(sp->sn_dbe);

	if (ch != NULL) {
		(void) CLNT_CONTROL(ch, CLSET_CB_TEST_CLEAR, NULL);
		rfs4x_cb_freech(sp, ch);
	}

	rfs4x_session_rele(sp);
	thread_exit();
}

/*
 * Find session and validate sequence args.
 * If this function successfully completes the compound state
 * will contain a session pointer.
 */
static nfsstat4
rfs4x_find_session(SEQUENCE4args *sargs, struct compound_state *cs)
{
	rfs4_session_t	*sp;
	slotid4		 slot;

	ASSERT(sargs != NULL);

	if ((sp = rfs4x_findsession_by_id(sargs->sa_sessionid)) == NULL)
		return (NFS4ERR_BADSESSION);

	slot = sargs->sa_slotid;
	if (slot >= sp->cn_attrs.ca_maxrequests) {
		rfs4x_session_rele(sp);
		return (NFS4ERR_BADSLOT);
	}
	cs->sp = sp;
	cs->cachethis = sargs->sa_cachethis;

	return (NFS4_OK);
}

/* called under held lock */
static nfsstat4
check_slot_seqid(rfs4_slot_t *slot, sequenceid4 seqid)
{
	nfsstat4 status = NFS4ERR_SEQ_MISORDERED;

	if (slot->se_flags & RFS4_SLOT_INUSE) {
		/*
		 * There are three cases:
		 * 1. Duplicated requests for currently performing
		 *    duplicated request.
		 * 2. New request for currently performing duplicated
		 *    request.
		 * 3. Request with bad seqid for non finished performing
		 *    request (due to a little window between 'prep'
		 *    stage and actual renew se_seqid).
		 * In all cases tell a client to retry request later.
		 */
		if (slot->se_seqid == seqid || slot->se_seqid + 1 == seqid) {
			status = NFS4ERR_DELAY;
		}
	} else {
		if (seqid == slot->se_seqid + 1)
			status = NFS4_OK;
		else if (seqid == slot->se_seqid)
			status = nfserr_replay_cache;
	}
	return (status);
}

static boolean_t is_solo_sequence(const COMPOUND4res *resp)
{
	return (resp->array_len == 1 && resp->array[0].resop == OP_SEQUENCE);
}

/*
 * Prep stage for SEQUENCE operation.
 *
 * Main purpose to call this:
 *     - check on cached replay
 *     - Set cs.sp and cs.slot
 */
int
rfs4x_sequence_prep(COMPOUND4args *args, COMPOUND4res *resp,
    compound_state_t *cs, SVCXPRT *xprt)
{
	SEQUENCE4args	*sargs;
	nfsstat4	status;
	rfs4_slot_t	*slot;
	XDR		*xdrs;

	if (args->array_len == 0 || args->array[0].argop != OP_SEQUENCE)
		return (NFS4_OK);

	sargs = &args->array[0].nfs_argop4_u.opsequence;

	status = rfs4x_find_session(sargs, cs);
	if (status != NFS4_OK)
		return (status);

	ASSERT(cs->sp != NULL);

	if (args->array_len > cs->sp->cn_attrs.ca_maxoperations)
		return (NFS4ERR_TOO_MANY_OPS);

	xdrs = &xprt->xp_xdrin;
	if (xdr_getpos(xdrs) > cs->sp->cn_attrs.ca_maxrequestsize)
		return (NFS4ERR_REQ_TOO_BIG);

	/*  have reference to session */
	slot = &cs->sp->sn_slots[sargs->sa_slotid];

	mutex_enter(&slot->se_lock);
	status = check_slot_seqid(slot, sargs->sa_sequenceid);
	if (status == nfserr_replay_cache) {
		if (slot->se_flags & RFS4_SLOT_CACHED) {
			slot->se_flags |= RFS4_SLOT_INUSE;
			cs->slot = slot;
			*resp = slot->se_buf;
		} else if (args->array_len == 1) {
			/*
			 * If original request was solo 'sequence' operation,
			 * it would be always cached. So this request differs
			 * from the previous.
			 */
			status = NFS4ERR_SEQ_FALSE_RETRY;
		} else {
			status = NFS4ERR_RETRY_UNCACHED_REP;
		}
	} else if (status == NFS4_OK) {
		slot->se_flags |= RFS4_SLOT_INUSE;
		cs->slot = slot;

		/*
		 * slot previously used to return recallable state;
		 * since slot reused (NEW request) we are guaranteed
		 * the client saw the reply, so it's safe to nuke the
		 * race-detection accounting info.
		 */
		if (slot->se_p != NULL) {
			rfs4x_rs_erase(slot->se_p);
			slot->se_p = NULL;
		}
	}
	mutex_exit(&slot->se_lock);

	return (status);
}

/*
 * Do cleanup things
 *   1. cache reply
 *   2. release slot
 */
void
rfs4x_sequence_done(COMPOUND4res *resp, compound_state_t *cs)
{
	rfs4_slot_t *slot = cs->slot;
	rfs4_session_t *sp = cs->sp;
	int add = 0;

	ASSERT(slot != NULL);
	ASSERT(sp != NULL);

	mutex_enter(&slot->se_lock);
	slot->se_flags &= ~RFS4_SLOT_INUSE;

	if (*cs->statusp != nfserr_replay_cache) {
		if (slot->se_flags & RFS4_SLOT_CACHED) {
			rfs4_compound_free(&slot->se_buf);
			slot->se_flags &= ~RFS4_SLOT_CACHED;
			add = -1;
		}

		if (cs->cachethis || is_solo_sequence(resp)) {
			slot->se_flags |= RFS4_SLOT_CACHED;
			slot->se_buf = *resp;	/* cache a reply */
			add += 1;
		} else {
			rfs4_compound_free(resp);
		}
	}
	mutex_exit(&slot->se_lock);

	if (add != 0)
		atomic_add_32(&sp->sn_rcached, add);
}

/*
 * Process the SEQUENCE operation. The session pointer has already been
 * cached in the compound state, so we just dereference
 */
void
rfs4x_op_sequence(nfs_argop4 *argop, nfs_resop4 *resop,
    struct svc_req *req __unused, compound_state_t *cs)
{
	SEQUENCE4args	*args = &argop->nfs_argop4_u.opsequence;
	SEQUENCE4res	*resp = &resop->nfs_resop4_u.opsequence;
	SEQUENCE4resok	*rok  = &resp->SEQUENCE4res_u.sr_resok4;
	rfs4_session_t	*sp = cs->sp;
	rfs4_slot_t	*slot = cs->slot;
	nfsstat4	 status = NFS4_OK;
	uint32_t	 cbstat = 0;
	int buflen;

	DTRACE_NFSV4_2(op__sequence__start,
	    struct compound_state *, cs,
	    SEQUENCE4args *, args);

	ASSERT(sp != NULL && slot != NULL);

	if (cs->op_pos != 0) {
		status = NFS4ERR_SEQUENCE_POS;
		goto out;
	}

	if (rfs4_lease_expired(sp->sn_clnt)) {
		status = NFS4ERR_BADSESSION;
		goto out;
	}

	buflen = args->sa_cachethis ?
	    sp->cn_attrs.ca_maxresponsesize_cached :
	    sp->cn_attrs.ca_maxresponsesize;

	if (buflen < NFS4_MIN_HDR_SEQSZ) {
		status = args->sa_cachethis ?
		    NFS4ERR_REP_TOO_BIG_TO_CACHE : NFS4ERR_REP_TOO_BIG;
		goto out;
	}

	/*
	 * If the back channel has been established...
	 *	. if the channel has _not_ been marked as failed _AND_
	 *	  there are connections that have pings outstanding,
	 *	  we go ahead and fire the thread to traverse all of
	 *	  the session's conns, issuing CB_NULL's to those that
	 *	  need a ping.
	 *	. if the channel is _not_ OK (ie. failed), then notify
	 *	  client that there is currently a problem with the CB
	 *	  path.
	 */
	rfs4_dbe_lock(sp->sn_dbe);
	if (SN_CB_CHAN_EST(sp)) {
		if (SN_CB_CHAN_OK(sp)) {
			if (sp->sn_bc.pngcnt > 0 && !sp->sn_bc.pnginprog) {
				kthread_t *t;

				rfs4x_session_hold(sp);
				t = thread_create(NULL, 0, ping_cb_null_thr,
				    sp, 0, &p0, TS_RUN, minclsyspri);
				if (!t)
					rfs4x_session_rele(sp);
			}
		} else {
			cbstat |= SEQ4_STATUS_CB_PATH_DOWN;
		}
	}
	cs->client = sp->sn_clnt;

	DTRACE_PROBE1(compound_clid, clientid4, cs->client->rc_clientid);

	ASSERT(args->sa_sequenceid == slot->se_seqid + 1);

	/*
	 * New request.
	 */
	mutex_enter(&slot->se_lock);
	slot->se_seqid = args->sa_sequenceid;
	mutex_exit(&slot->se_lock);

	cs->slotno = args->sa_slotid;

	/* Update access time */
	sp->sn_laccess = nfs_sys_uptime();

	/* Prepare result */
	bcopy(sp->sn_sessid, rok->sr_sessionid, sizeof (sessionid4));
	rok->sr_sequenceid = slot->se_seqid;
	rok->sr_slotid = args->sa_slotid;
	rok->sr_highest_slotid =
	    sp->cn_attrs.ca_maxrequests - 1;
	rok->sr_target_highest_slotid =
	    sp->cn_attrs.ca_maxrequests - 1;
	if (cs->client->rc_deleg_revoked > 0)
		cbstat |= SEQ4_STATUS_RECALLABLE_STATE_REVOKED;
	rok->sr_status_flags |= cbstat;
	rfs4_dbe_unlock(sp->sn_dbe);

	/* Update lease (out of session lock) */
	rfs4_update_lease(cs->client);

out:
	*cs->statusp = resp->sr_status = status;
	DTRACE_NFSV4_2(op__sequence__done,
	    struct compound_state *, cs,
	    SEQUENCE4res *, resp);
}

void
rfs4x_op_reclaim_complete(nfs_argop4 *argop, nfs_resop4 *resop,
    struct svc_req *req __unused, compound_state_t *cs)
{
	RECLAIM_COMPLETE4args *args = &argop->nfs_argop4_u.opreclaim_complete;
	RECLAIM_COMPLETE4res *resp = &resop->nfs_resop4_u.opreclaim_complete;
	rfs4_client_t *cp;
	nfsstat4 status = NFS4_OK;

	DTRACE_NFSV4_2(op__reclaim__complete__start,
	    struct compound_state *, cs,
	    RECLAIM_COMPLETE4args *, args);

	cp = cs->client;
	rfs4_dbe_lock(cp->rc_dbe);
	if (args->rca_one_fs) {
		/* do what?  we don't track this */
		goto out;
	}

	if (cp->rc_reclaim_completed) {
		status = NFS4ERR_COMPLETE_ALREADY;
		goto out;
	}

	if (cp->rc_can_reclaim) {
		ASSERT(rfs4_servinst(cp)->nreclaim > 0);
		atomic_add_32(&(rfs4_servinst(cp))->nreclaim, -1);
	}

	cp->rc_reclaim_completed = 1;
out:
	rfs4_dbe_unlock(cp->rc_dbe);

	*cs->statusp = resp->rcr_status = status;
	DTRACE_NFSV4_2(op__reclaim__complete__done,
	    struct compound_state *, cs,
	    RECLAIM_COMPLETE4res *, resp);
}

void
rfs4x_op_destroy_clientid(nfs_argop4 *argop, nfs_resop4 *resop,
    struct svc_req *req __unused, compound_state_t *cs)
{
	DESTROY_CLIENTID4args *args = &argop->nfs_argop4_u.opdestroy_clientid;
	DESTROY_CLIENTID4res *resp = &resop->nfs_resop4_u.opdestroy_clientid;
	rfs4_client_t *cp;
	nfsstat4 status = NFS4_OK;

	DTRACE_NFSV4_2(op__destroy__clientid__start,
	    struct compound_state *, cs,
	    DESTROY_CLIENTID4args *, args);

	cp = rfs4_findclient_by_id(args->dca_clientid, TRUE);
	if (cp == NULL) {
		status = NFS4ERR_STALE_CLIENTID;
		goto end;
	}

	rfs4_dbe_lock(cp->rc_dbe);
	if (client_has_state_locked(cp))
		status = NFS4ERR_CLIENTID_BUSY;
	else
		cp->rc_destroying = TRUE;
	rfs4_dbe_unlock(cp->rc_dbe);

	if (status == NFS4_OK)
		rfs4_client_close(cp);
	else
		rfs4_client_rele(cp);
end:
	*cs->statusp = resp->dcr_status = status;

	DTRACE_NFSV4_2(op__destroy__clientid__done,
	    struct compound_state *, cs,
	    DESTROY_CLIENTID4res *, resp);
}

void
rfs4x_bc_setup(rfs4_session_t *sp)
{
	sess_channel_t	*bcp;
	sess_bcsd_t	*bsdp;

	ASSERT(sp != NULL);

	/* If sn_back != NULL, Nothing to do */
	rfs4_dbe_lock(sp->sn_dbe);
	if (SN_CB_CHAN_EST(sp)) {
		rfs4_dbe_unlock(sp->sn_dbe);
		return;
	}

	/* Create the back channel */
	bcp = rfs41_create_session_channel(CDFS4_BACK);
	rfs4_dbe_unlock(sp->sn_dbe);

	/*
	 * Setup and initialize the back channel.
	 */
	rw_enter(&bcp->cn_lock, RW_WRITER);
	bcp->cn_dir |= CDFS4_BACK;
	bsdp = CTOBSD(bcp);
	ASSERT(bsdp != NULL);
	slot_table_create(&bsdp->bsd_stok, sp->sn_bc.maxreqs);
	rw_exit(&bcp->cn_lock);

	/*
	 * If no back channel yet, make sure we set the session's
	 * back channel appropriately with the one we created now.
	 * Otherwise clean up the back channel we created above.
	 */
	rfs4_dbe_lock(sp->sn_dbe);
	if (atomic_cas_ptr(&sp->sn_back, NULL, bcp) != NULL) {
		rfs4_dbe_unlock(sp->sn_dbe);
		slot_table_destroy(bsdp->bsd_stok);
		rfs41_destroy_back_channel(bcp);
		return;
	}
	rfs4_dbe_unlock(sp->sn_dbe);

	/* now set the conn's state so we know a ping is needed */
	atomic_inc_32(&sp->sn_bc.pngcnt);
}

void
rfs4x_op_bind_conn_to_session(nfs_argop4 *argop, nfs_resop4 *resop,
    struct svc_req *req __unused, compound_state_t *cs)
{
	BIND_CONN_TO_SESSION4args  *args =
	    &argop->nfs_argop4_u.opbind_conn_to_session;
	BIND_CONN_TO_SESSION4res   *resp =
	    &resop->nfs_resop4_u.opbind_conn_to_session;
	BIND_CONN_TO_SESSION4resok *rok =
	    &resp->BIND_CONN_TO_SESSION4res_u.bctsr_resok4;
	rfs4_session_t	*sp;
	nfsstat4 status = NFS4_OK;
	SVCCB_ARGS			cbargs;
	rpcprog_t			prog;
	SVCMASTERXPRT			*mxprt;

	DTRACE_NFSV4_2(op__bind__conn__to__session__start,
	    struct compound_state *, cs,
	    BIND_CONN_TO_SESSION4args *, args);

	if (cs->op_pos != 0) {
		status = NFS4ERR_NOT_ONLY_OP;
		goto end;
	}

	sp = rfs4x_findsession_by_id(args->bctsa_sessid);
	if (sp == NULL) {
		status = NFS4ERR_BADSESSION;
		goto end;
	}

	if (rfs4_lease_expired(sp->sn_clnt)) {
		status = NFS4ERR_BADSESSION;
		goto end;
	}

	rfs4_update_lease(sp->sn_clnt); /* no need lock protection */

	rfs4_dbe_lock(sp->sn_dbe);
	sp->sn_laccess = nfs_sys_uptime();
	prog = sp->sn_bc.progno;
	rfs4_dbe_unlock(sp->sn_dbe);

	rok->bctsr_use_conn_in_rdma_mode = FALSE;
	mxprt = (SVCMASTERXPRT *)req->rq_xprt->xp_master;

	switch (args->bctsa_dir) {
	case CDFC4_FORE:
	case CDFC4_FORE_OR_BOTH:
		/* always map to Fore */
		rok->bctsr_dir = CDFS4_FORE;
		break;

	case CDFC4_BACK:
	case CDFC4_BACK_OR_BOTH:
		/* always map to Back */
		rok->bctsr_dir = CDFS4_BACK;
		rfs4x_bc_setup(sp);
		(void) SVC_CTL(req->rq_xprt,
		    SVCCTL_SET_TAG, (void *)sp->sn_sessid);

		cbargs.xprt = mxprt;
		cbargs.prog = prog;
		cbargs.vers = NFS_CB;
		cbargs.family = AF_INET;
		cbargs.tag = (void *)sp->sn_sessid;

		(void) SVC_CTL(req->rq_xprt,
		    SVCCTL_SET_CBCONN, (void *)&cbargs);
		break;
	default:
		break;
	}

	bcopy(sp->sn_sessid, rok->bctsr_sessid, sizeof (sessionid4));
	rfs4x_session_rele(sp);
end:
	*cs->statusp = resp->bctsr_status = status;

	DTRACE_NFSV4_2(op__bind__conn__to__session__done,
	    struct compound_state *, cs,
	    BIND_CONN_TO_SESSION4res *, resp);
}

void
rfs4x_op_secinfo_noname(nfs_argop4 *argop, nfs_resop4 *resop,
    struct svc_req *req __unused, compound_state_t *cs)
{
	SECINFO_NO_NAME4res *resp = &resop->nfs_resop4_u.opsecinfo_no_name;
	nfsstat4 status;
	bool_t dotdot;

	DTRACE_NFSV4_1(op__secinfo__no__name__start,
	    struct compound_state *, cs);

	if (cs->vp == NULL) {
		status = NFS4ERR_NOFILEHANDLE;
		goto out;
	}

	if (cs->vp->v_type != VDIR) {
		status = NFS4ERR_NOTDIR;
		goto out;
	}

	dotdot =
	    (argop->nfs_argop4_u.opsecinfo_no_name == SECINFO_STYLE4_PARENT);

	status = do_rfs4_op_secinfo(cs, dotdot ? ".." : ".", resp);

	/* Cleanup FH as described at 18.45.3 and 2.6.3.1.1.8 */
	if (status == NFS4_OK) {
		VN_RELE(cs->vp);
		cs->vp = NULL;
	}
out:
	*cs->statusp = resp->status = status;

	DTRACE_NFSV4_2(op__secinfo__no__name__done,
	    struct compound_state *, cs,
	    SECINFO_NO_NAME4res *, resp);
}

/*
 * TEST_STATEID (RFC 5661 §18.48): for each input stateid, return
 * a status code indicating its current validity.  The compound
 * always succeeds; individual errors are in the per-stateid array.
 */
void
rfs4x_op_test_stateid(nfs_argop4 *argop, nfs_resop4 *resop,
    struct svc_req *req __unused, compound_state_t *cs)
{
	TEST_STATEID4args	*args = &argop->nfs_argop4_u.optest_stateid;
	TEST_STATEID4res	*resp = &resop->nfs_resop4_u.optest_stateid;
	TEST_STATEID4resok	*rok  = &resp->TEST_STATEID4res_u.tsr_resok4;
	nfsstat4		*codes = NULL;
	uint_t			i, n;

	DTRACE_NFSV4_2(op__test__stateid__start,
	    struct compound_state *, cs,
	    TEST_STATEID4args *, args);

	n = args->ts_stateids.ts_stateids_len;
	if (n > 0)
		codes = kmem_alloc(n * sizeof (nfsstat4), KM_SLEEP);

	for (i = 0; i < n; i++) {
		stateid4 *sid = &args->ts_stateids.ts_stateids_val[i];
		rfs4_state_t *sp = NULL;
		rfs4_deleg_state_t *dsp = NULL;
		rfs4_lo_state_t *lsp = NULL;
		nfsstat4 st;

		get_stateid4(cs, sid);
		st = rfs4_get_all_state(sid, &sp, &dsp, &lsp);
		if (st == NFS4_OK) {
			if (sp != NULL)
				rfs4_state_rele(sp);
			if (dsp != NULL)
				rfs4_deleg_state_rele(dsp);
			if (lsp != NULL)
				rfs4_lo_state_rele(lsp, FALSE);
		}
		codes[i] = st;
	}

	rok->tsr_status_codes.tsr_status_codes_len = n;
	rok->tsr_status_codes.tsr_status_codes_val = codes;

	*cs->statusp = resp->tsr_status = NFS4_OK;

	DTRACE_NFSV4_2(op__test__stateid__done,
	    struct compound_state *, cs,
	    TEST_STATEID4res *, resp);
}

/*
 * Used to free a stateid that no longer has any associated locks.
 * If there are valid locks, error NFS4ERR_LOCKS_HELD is returned.
 * NB: Actual freeing of stateid will be taken care by reaper_thread().
 */
void
rfs4x_op_free_stateid(nfs_argop4 *argop, nfs_resop4 *resop,
    struct svc_req *req __unused, compound_state_t *cs)
{
	FREE_STATEID4args	*args = &argop->nfs_argop4_u.opfree_stateid;
	FREE_STATEID4res	*resp = &resop->nfs_resop4_u.opfree_stateid;
	nfsstat4		status = NFS4ERR_BAD_STATEID;
	stateid4		*sid;
	stateid_t		*id;

	DTRACE_NFSV4_2(op__free__stateid__start,
	    struct compound_state *, cs,
	    FREE_STATEID4args *, args);

	/* Fetch the ARG stateid */
	sid = &args->fsa_stateid;
	get_stateid4(cs, sid);

	id = (stateid_t *)sid;
	switch (id->bits.type) {
	case OPENID: {
		rfs4_state_t *sp;

		status = rfs4_get_state_nolock(sid, &sp, RFS4_DBS_VALID);
		if (status != NFS4_OK)
			goto final;

		rfs4_update_lease(sp->rs_owner->ro_client);
		rfs4_state_rele_nounlock(sp);
		status = NFS4ERR_LOCKS_HELD;
		break;
	}

	case LOCKID: {
		sysid_t sysid;
		rfs4_lo_state_t *lsp;
		rfs4_lockowner_t *lo;

		status = rfs4_get_lo_state(sid, &lsp, FALSE);
		if (status != NFS4_OK)
			goto final;

		lo = lsp->rls_locker;
		rfs4_update_lease(lo->rl_client);

		rfs4_dbe_lock(lo->rl_client->rc_dbe);
		sysid = lo->rl_client->rc_sysidt;
		rfs4_dbe_unlock(lo->rl_client->rc_dbe);

		/*
		 * Check for ACTIVE LOCKS by this lockowner.
		 */
		if (sysid != LM_NOSYSID) {
			locklist_t *llist;

			llist = flk_get_active_locks(sysid, lo->rl_pid);
			if (llist != NULL) {
				flk_free_locklist(llist);
				status = NFS4ERR_LOCKS_HELD;
			}
		}


		/*
		 * If the state does not have any active LOCKS,
		 * invalidate the LOCK stateid right away.
		 */
		if (status != NFS4ERR_LOCKS_HELD) {
			rfs4_dbe_lock(lsp->rls_dbe);
			rfs4_dbe_invalidate(lsp->rls_dbe);
			rfs4_dbe_unlock(lsp->rls_dbe);
		}

		rfs4_lo_state_rele(lsp, FALSE);
		break;
	}

	case DELEGID: {
		rfs4_deleg_state_t *dsp;

		/*
		 * Use rfs4_get_deleg_any() to retrieve the delegation even
		 * if it has been revoked — FREE_STATEID must acknowledge
		 * revoked delegations and return NFS4_OK (RFC 5661 §18.38).
		 *
		 * If this succeeds, must call rfs4_deleg_state_rele()
		 */
		status = rfs4_get_deleg_any(sid, &dsp);
		if (status != NFS4_OK)
			goto final;

		rfs4_update_lease(dsp->rds_client);

		/*
		 * Compare with rfs4_get_deleg_state()
		 * Except here in FREE_STATEID, if revoked:
		 * we now invalidate the revoked delegation.
		 */
		rfs4_dbe_lock(dsp->rds_dbe);
		if (dsp->rds_revoked) {
			dsp->rds_revoked = FALSE;
			rfs4_dbe_invalidate(dsp->rds_dbe);
			rfs4_dbe_unlock(dsp->rds_dbe);

			/*
			 * Adjust client's revoked count.
			 */
			rfs4_dbe_lock(dsp->rds_client->rc_dbe);
			if (dsp->rds_client->rc_deleg_revoked > 0)
				dsp->rds_client->rc_deleg_revoked--;
			rfs4_dbe_unlock(dsp->rds_client->rc_dbe);

			rfs4_deleg_state_rele(dsp);
			status = NFS4_OK;
			goto final;
		}
		rfs4_dbe_unlock(dsp->rds_dbe);

		/*
		 * Compare with rfs4_get_deleg_state()
		 * lease expired?
		 */
		if (rfs4_lease_expired(dsp->rds_client)) {
			rfs4_deleg_state_rele(dsp);
			status = NFS4ERR_EXPIRED;
			goto final;
		}

		/*
		 * Finally the original FREE_STATEID actions.
		 */
		rfs4_deleg_state_rele(dsp);
		status = NFS4ERR_LOCKS_HELD;
		break;
	}

	default:
		status = NFS4ERR_BAD_STATEID;
		break;
	}

final:
	*cs->statusp = resp->fsr_status = status;

	DTRACE_NFSV4_2(op__free__stateid__done,
	    struct compound_state *, cs,
	    FREE_STATEID4res *, resp);
}

void
rfs4x_op_backchannel_ctl(nfs_argop4 *argop, nfs_resop4 *resop,
    struct svc_req *req, compound_state_t *cs)
{
	rfs4_session_t		*sp = cs->sp;
	nfsstat4		status = NFS4_OK;
	BACKCHANNEL_CTL4args	*args = &argop->nfs_argop4_u.opbackchannel_ctl;
	BACKCHANNEL_CTL4res	*resp = &resop->nfs_resop4_u.opbackchannel_ctl;

	ASSERT(sp != NULL);

	DTRACE_NFSV4_2(op__backchannel__ctl__start,
	    struct compound_state *, cs,
	    BACKCHANNEL_CTL4args *, args);

	if ((args->bca_sec_parms.bca_sec_parms_len == 0) ||
	    (args->bca_sec_parms.bca_sec_parms_val == NULL)) {
		cmn_err(CE_WARN, "Invalid backchannel security.");
		status = NFS4ERR_INVAL;
		goto final;
	}

	if (!rfs4x_cbsec_valid(args->bca_sec_parms.bca_sec_parms_val)) {
		cmn_err(CE_WARN, "Unsupported backchannel security.");
		status = NFS4ERR_INVAL;
		goto final;
	}

	/*
	 * Currently AUTH_NONE and AUTH_UNIX (AUTH_SYS) are
	 * supported. TODO: RPCSEC_GSS support.
	 */
	rfs4_dbe_lock(sp->sn_dbe);
	sp->sn_bc.progno = args->bca_cb_program;
	rfs4x_cbsec_init(sp->sn_bc.secprms.csa_sec_parms_val,
	    args->bca_sec_parms.bca_sec_parms_val);
	rfs4_dbe_unlock(sp->sn_dbe);

	/*
	 * 1. Flush all the stale cached channels
	 * 2. Mark the backchannel that PING is needed
	 */
	rfs4x_cb_chflush(sp);
	atomic_inc_32(&sp->sn_bc.pngcnt);

final:
	*cs->statusp = resp->bcr_status = status;

	DTRACE_NFSV4_2(op__backchannel__ctl__done,
	    struct compound_state *, cs,
	    BACKCHANNEL_CTL4res *, resp);
}

/*
 * Validate the backchannel security part.
 * Supports only AUTH_NONE and AUTH_SYS
 * TODO: RPCSEC_GSS support
 */
bool_t
rfs4x_cbsec_valid(callback_sec_parms4 *secp)
{
	ASSERT(secp != NULL);

	switch (secp->cb_secflavor) {
	case AUTH_NONE:
	case AUTH_SYS:
		return (TRUE);
	default:
		return (FALSE);
	}
}

uid_t
rfs4x_cbsec_getuid(callback_sec_parms4 *secp)
{
	ASSERT(secp != NULL);

	if (secp->cb_secflavor == AUTH_SYS) {
		uid_t uid = secp->callback_sec_parms4_u.cbsp_sys_cred.aup_uid;
		return (uid);
	}

	return (0);
}

gid_t
rfs4x_cbsec_getgid(callback_sec_parms4 *secp)
{
	ASSERT(secp != NULL);

	if (secp->cb_secflavor == AUTH_SYS) {
		gid_t gid = secp->callback_sec_parms4_u.cbsp_sys_cred.aup_gid;
		return (gid);
	}

	return (0);
}

/*
 * Init the backchannel security part.
 * Supports only AUTH_NONE and AUTH_SYS
 * TODO: RPCSEC_GSS support
 */
void
rfs4x_cbsec_init(callback_sec_parms4 *tsp, callback_sec_parms4 *ssp)
{
	ASSERT(tsp != NULL);
	ASSERT(ssp != NULL);

	memset(tsp, 0, sizeof (callback_sec_parms4));

	tsp->cb_secflavor = ssp->cb_secflavor;
	if (ssp->cb_secflavor == AUTH_SYS) {
		authsys_parms *aup;
		aup = &tsp->callback_sec_parms4_u.cbsp_sys_cred;
		aup->aup_uid = rfs4x_cbsec_getuid(ssp);
		aup->aup_gid = rfs4x_cbsec_getgid(ssp);
	}
}

/*
 * Free up the backchannel security part.
 * Supports only AUTH_NONE and AUTH_SYS
 * TODO: RPCSEC_GSS support
 */
void
rfs4x_cbsec_fini(rfs4_session_t *sp)
{
	ASSERT(sp != NULL);

	if (sp->sn_bc.cr != NULL) {
		crfree(sp->sn_bc.cr);
		sp->sn_bc.cr = NULL;
	}

	if (sp->sn_bc.secprms.csa_sec_parms_len != 0) {
		ASSERT(sp->sn_bc.secprms.csa_sec_parms_val != NULL);
		kmem_free(sp->sn_bc.secprms.csa_sec_parms_val,
		    sizeof (callback_sec_parms4));
		sp->sn_bc.secprms.csa_sec_parms_val = NULL;
		sp->sn_bc.secprms.csa_sec_parms_len = 0;
	}
}

/*
 * We could implement nfs4x_share_to_delegreq() as just
 * (deleg_want & mask) >> 8, but let's not, for now.
 */
/* BEGIN CSTYLED */
CTASSERT((DELEG_WANT_NO_PREF << 8) == OPEN4_SHARE_WANT_NO_PREFERENCE);
CTASSERT((DELEG_WANT_READ    << 8) == OPEN4_SHARE_WANT_READ_DELEG);
CTASSERT((DELEG_WANT_WRITE   << 8) == OPEN4_SHARE_WANT_WRITE_DELEG);
CTASSERT((DELEG_WANT_ANY     << 8) == OPEN4_SHARE_WANT_ANY_DELEG);
CTASSERT((DELEG_WANT_NONE    << 8) == OPEN4_SHARE_WANT_NO_DELEG);
CTASSERT((DELEG_WANT_CANCEL  << 8) == OPEN4_SHARE_WANT_CANCEL);
/* END CSTYLED */

/*
 * The OPEN4_SHARE_WANT_*_DELEG flags were stashed in OPEN4args.deleg_want
 * by the (custom) XDR code in xdr_OPEN4args().  This converts those flags
 * to one of the delegreq_t values.
 */
delegreq_t
nfs4x_share_to_delegreq(uint32_t deleg_want)
{
	delegreq_t dreq;

	switch (deleg_want & OPEN4_SHARE_WANT_MASK) {

	default:
	case OPEN4_SHARE_WANT_NO_PREFERENCE:
		dreq = DELEG_WANT_NO_PREF;
		break;
	case OPEN4_SHARE_WANT_READ_DELEG:
		dreq = DELEG_WANT_READ;
		break;
	case OPEN4_SHARE_WANT_WRITE_DELEG:
		dreq = DELEG_WANT_WRITE;
		break;
	case OPEN4_SHARE_WANT_ANY_DELEG:
		dreq = DELEG_WANT_ANY;
		break;
	case OPEN4_SHARE_WANT_NO_DELEG:
		dreq = DELEG_WANT_NONE;
		break;
	case OPEN4_SHARE_WANT_CANCEL:
		dreq = DELEG_WANT_CANCEL;
		break;
	}
	return (dreq);
}

void
rfs4x_rs_record(struct compound_state *cs, rfs4_deleg_state_t *dsp)
{
	rfs4_slot_t		*slotent;

#ifdef DEBUG_VERBOSE
	ulong_t			offset;
	char			*who;

	who = modgetsymname((uintptr_t)caller(), &offset);

	/* sessid/slot/seqid + rsid */
	ASSERT(cs != NULL && cs->sp != NULL);

	ASSERT(dsp != NULL);

	cmn_err(CE_NOTE, "rfs41_rs_record: (%s, dsp = 0x%p)", who, dsp);
#endif /* DEBUG_VERBOSE */

	/* delegation state id stored in rfs4_deleg_state_t */
	bcopy(cs->sp->sn_sessid, dsp->rds_rs.sessid,
	    sizeof (sessionid4));
	rfs41_deleg_rs_hold(dsp);

	slotent = cs->slot;
	ASSERT(slotent != NULL);
	ASSERT(slotent->se_p == NULL);
	mutex_enter(&slotent->se_lock);
	dsp->rds_rs.seqid = cs->slot->se_seqid;
	dsp->rds_rs.slotno = cs->slotno;
	slotent->se_p = dsp;
	mutex_exit(&slotent->se_lock);

	rfs4_dbe_hold(dsp->rds_dbe);	/* added ref to deleg_state */
}

void
rfs4x_rs_erase(void *p)
{
	rfs4_deleg_state_t	*dsp = (rfs4_deleg_state_t *)p;
#ifdef DEBUG_VERBOSE
	/*
	 * XXX - Do not change this to a static D probe;
	 *	this is not intended for production !!!
	 */
	ulong_t			offset;
	char			*who;

	who = modgetsymname((uintptr_t)caller(), &offset);
	cmn_err(CE_NOTE, "rfs41_rs_erase: (%s, dsp = 0x%p)", who, dsp);
#endif /* DEBUG_VERBOSE */

	ASSERT(dsp != NULL);
	if (dsp->rds_rs.refcnt > 0) {
		rfs41_deleg_rs_rele(dsp);
		rfs4_deleg_state_rele(dsp);
	}
}
