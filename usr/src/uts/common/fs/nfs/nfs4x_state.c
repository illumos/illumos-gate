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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2017 RackTop Systems.
 */

#include <sys/sdt.h>
#include <sys/atomic.h>
#include <nfs/nfs4.h>

#ifdef DEBUG
#define	RFS4_TABSIZE 17
#else
#define	RFS4_TABSIZE 2047
#endif

#define	RFS4_MAXTABSZ 1024*1024

slotid4 rfs4_max_slots		= MAXSLOTS;		/* fore channel */
slotid4 rfs4_back_max_slots	= MAXSLOTS_BACK;	/* back channel */

typedef union {
	/* Both members have the same size */
	struct {
		uint32_t pad0;
		uint32_t pad1;
		uint32_t start_time;	/* NFS server start time */
		uint32_t s_id;		/* unique session index */
	} impl_id;
	sessionid4 id4;
} rfs4_sid;

/*
 * --------------------------------------------------------
 * MDS - NFSv4.1  Sessions
 * --------------------------------------------------------
 */
static uint32_t
sessid_hash(void *key)
{
	rfs4_sid *idp = key;

	return (idp->impl_id.s_id);
}

static bool_t
sessid_compare(rfs4_entry_t entry, void *key)
{
	rfs4_session_t	*sp = (rfs4_session_t *)entry;
	sessionid4	*idp = (sessionid4 *)key;

	return (bcmp(idp, &sp->sn_sessid, sizeof (sessionid4)) == 0);
}

static void *
sessid_mkkey(rfs4_entry_t entry)
{
	rfs4_session_t *sp = (rfs4_session_t *)entry;

	return (&sp->sn_sessid);
}

void
rfs4x_session_rele(rfs4_session_t *sp)
{
	rfs4_dbe_rele(sp->sn_dbe);
}

void
rfs4x_session_hold(rfs4_session_t *sp)
{
	rfs4_dbe_hold(sp->sn_dbe);
}

rfs4_session_t *
rfs4x_findsession_by_id(sessionid4 sessid)
{
	rfs4_session_t	*sp;
	bool_t		 create = FALSE;
	nfs4_srv_t *nsrv4 = nfs4_get_srv();

	sp = (rfs4_session_t *)rfs4_dbsearch(nsrv4->rfs4_session_idx,
	    sessid, &create, NULL, RFS4_DBS_VALID);

	return (sp);
}

/*
 * A clientid can have multiple sessions associated with it. Hence,
 * performing a raw 'mds_findsession' (even for a create) might
 * yield a list of sessions associated with the clientid in question.
 * Call rfs4_dbseach() function with key that cannot be found
 * and create an association between the session table and both
 * primary (sessionid) index and secondary (clientid) index for the
 * newly created session.
 */

rfs4_session_t	*
rfs4x_createsession(session41_create_t *ap)
{
	static uint32_t session_id_counter;

	rfs4_session_t	*sp = NULL;
	bool_t create = TRUE;
	rfs4_sid key = {0, 0, 0, 0};
	nfs4_srv_t *nsrv4 = nfs4_get_srv();

	/*
	 * Use unique counter for s_id and s_id to ensure that
	 * created entry will have the same index in dbi_buckets[]
	 */
	ap->cs_id = key.impl_id.s_id = atomic_inc_32_nv(&session_id_counter);

	if ((sp = (rfs4_session_t *)rfs4_dbsearch(nsrv4->rfs4_session_idx,
	    &key, &create, (void *)ap, RFS4_DBS_VALID)) == NULL) {
		DTRACE_PROBE1(mds__srv__createsession__fail,
		    session41_create_t *, ap);
	}
	return (sp);
}

/* return success of operation */
static bool_t
client_insert_session(rfs4_client_t *cp, rfs4_session_t *sp)
{
	bool_t res = TRUE;

	rfs4_dbe_lock(cp->rc_dbe);
	if (cp->rc_destroying)
		res = FALSE;
	else
		list_insert_tail(&cp->rc_sessions, sp);
	rfs4_dbe_unlock(cp->rc_dbe);

	return (res);
}

static void
client_remove_session(rfs4_client_t *cp, rfs4_session_t *sp)
{
	rfs4_dbe_lock(cp->rc_dbe);
	if (list_link_active(&sp->sn_node))
		list_remove(&cp->rc_sessions, sp);
	rfs4_dbe_unlock(cp->rc_dbe);
}

/*
 * Invalidate the session in the DB (so it can't be found anymore)
 */
nfsstat4
rfs4x_destroysession(rfs4_session_t *sp, unsigned useref)
{
	nfsstat4 status = NFS4_OK;

	/*
	 * RFC 7862 Section 14.1.3:
	 * In hindsight, the  NFSv4.1 specification should have
	 * mandated that DESTROY_SESSION either abort or complete
	 * all outstanding operations.
	 */
	rfs4_dbe_lock(sp->sn_dbe);
	if (rfs4_dbe_refcnt(sp->sn_dbe) > useref)
		status = NFS4ERR_DELAY;
	else
		rfs4_dbe_invalidate(sp->sn_dbe);
	rfs4_dbe_unlock(sp->sn_dbe);

	if (status == NFS4_OK)
		client_remove_session(sp->sn_clnt, sp);

	return (status);
}

/* Invalidate all client's sessions */
void
rfs4x_client_session_remove(rfs4_client_t *cp)
{
	rfs4_session_t *sp;

	/*
	 * Client is forcibly closing so invalidate all sessions
	 * without checking the refcount.
	 */
	rfs4_dbe_lock(cp->rc_dbe);
	while ((sp = list_head(&cp->rc_sessions)) != NULL) {
		list_remove(&cp->rc_sessions, sp);

		rfs4_dbe_invalidate(sp->sn_dbe);
	}
	rfs4_dbe_unlock(cp->rc_dbe);
}

nfsstat4
sess_chan_limits(sess_channel_t *scp)
{
	if (scp->cn_attrs.ca_maxrequests > rfs4_max_slots) {
		scp->cn_attrs.ca_maxrequests = rfs4_max_slots;
	}

	if (scp->cn_back_attrs.ca_maxrequests > rfs4_back_max_slots)
		scp->cn_back_attrs.ca_maxrequests = rfs4_back_max_slots;


	if (scp->cn_attrs.ca_maxoperations > NFS4_COMPOUND_LIMIT)
		scp->cn_attrs.ca_maxoperations = NFS4_COMPOUND_LIMIT;

	/*
	 * Lower limit should be set to smallest sane COMPOUND. Even
	 * though a singleton SEQUENCE op is the very smallest COMPOUND,
	 * it's also quite boring. For all practical purposes, the lower
	 * limit for creating a sess is limited to:
	 *
	 *		[SEQUENCE + PUTROOTFH + GETFH]
	 *
	 *	 Can't limit READ's to a specific threshold, otherwise
	 *	 we artificially limit the clients to perform reads of
	 *	 AT LEAST that granularity, which is WRONG !!! Same goes
	 *	 for READDIR's and GETATTR's.
	 */
	if (scp->cn_attrs.ca_maxresponsesize < (sizeof (SEQUENCE4res) +
	    sizeof (PUTROOTFH4res) + sizeof (GETFH4res)))
		return (NFS4ERR_TOOSMALL);
	return (NFS4_OK);
}

/*
 * NFSv4.1 Slot replay cache
 */
static void
rfs41_cleanup_slot(rfs4_slot_t *se)
{
	rfs4_compound_free((COMPOUND4res *)&se->se_buf);
}

static rfs4_slot_t *
slots_alloc(size_t n)
{
	rfs4_slot_t *p;
	int i;

	p = kmem_zalloc(sizeof (rfs4_slot_t) * n, KM_SLEEP);
	for (i = 0; i < n; i++) {
		mutex_init(&p[i].se_lock, NULL, MUTEX_DEFAULT, NULL);
	}

	return (p);
}

static void
slots_free(rfs4_slot_t *slots, size_t n)
{
	int i;

	for (i = 0; i < n; i++) {
		rfs4_slot_t *slot = &slots[i];

		mutex_destroy(&slot->se_lock);

		if (slot->se_flags & RFS4_SLOT_CACHED) {
			rfs41_cleanup_slot(slot);
		}
	}
	kmem_free(slots, sizeof (rfs4_slot_t) * n);
}

/* Additional functions */

/* check csa_flags for OP_CREATE_SESSION */
bool_t
nfs4x_csa_flags_valid(uint32_t flags)
{
	if (flags & ~CREATE_SESSION4_FLAG_MASK)
		return (FALSE);

	return (TRUE);
}

sess_channel_t *
rfs41_create_session_channel(channel_dir_from_server4 dir)
{
	sess_channel_t   *cp;
	sess_bcsd_t	 *bp;

	cp = (sess_channel_t *)kmem_zalloc(sizeof (sess_channel_t), KM_SLEEP);
	rw_init(&cp->cn_lock, NULL, RW_DEFAULT, NULL);

	switch (dir) {
	case CDFS4_FORE:
		break;

	case CDFS4_BOTH:
	case CDFS4_BACK:
		/* BackChan Specific Data */
		bp = (sess_bcsd_t *)kmem_zalloc(sizeof (sess_bcsd_t), KM_SLEEP);
		rw_init(&bp->bsd_rwlock, NULL, RW_DEFAULT, NULL);
		cp->cn_csd = (sess_bcsd_t *)bp;
		break;
	}
	return (cp);
}

void
rfs41_destroy_session_channel(rfs4_session_t *sp)
{
	sess_channel_t	*cp;
	sess_bcsd_t	*bp;

	if (sp->sn_back != NULL) {
		/* only one channel for both direction for now */
		ASSERT(sp->sn_fore == sp->sn_back);

		cp = sp->sn_back;
		bp = (sess_bcsd_t *)cp->cn_csd;
		rw_destroy(&bp->bsd_rwlock);
		kmem_free(bp, sizeof (sess_bcsd_t));
	} else {
		cp = sp->sn_fore;
	}

	rw_destroy(&cp->cn_lock);
	kmem_free(cp, sizeof (sess_channel_t));

	sp->sn_back = NULL;
	sp->sn_fore = NULL;
}

static bool_t
rfs4_session_create(rfs4_entry_t u_entry, void *arg)
{
	rfs4_session_t		*sp = (rfs4_session_t *)u_entry;
	session41_create_t	*ap = (session41_create_t *)arg;
	sess_channel_t		*ocp = NULL;
	rfs4_sid		*sidp;
	bool_t			 bdrpc = FALSE;
	channel_dir_from_server4 dir;
	nfsstat4		 sle;
	nfs4_srv_t *nsrv4 = nfs4_get_srv();

	ASSERT(sp != NULL);
	if (sp == NULL)
		return (FALSE);

	/*
	 * Back pointer/ref to parent data struct (rfs4_client_t)
	 */
	sp->sn_clnt = (rfs4_client_t *)ap->cs_client;
	rfs4_dbe_hold(sp->sn_clnt->rc_dbe);

	/*
	 * Handcrafting the session id
	 */
	sidp = (rfs4_sid *)&sp->sn_sessid;
	sidp->impl_id.pad0 = 0x00000000;
	sidp->impl_id.pad1 = 0xFFFFFFFF;
	sidp->impl_id.start_time = nsrv4->rfs4_start_time;
	sidp->impl_id.s_id = ap->cs_id;

	/*
	 * Process csa_flags; note that CREATE_SESSION4_FLAG_CONN_BACK_CHAN
	 * is processed below since it affects direction and setup of the
	 * backchannel accordingly.
	 */
	if (!nfs4x_csa_flags_valid(ap->cs_aotw.csa_flags)) {
		ap->cs_error = NFS4ERR_INVAL;
		goto err;
	}

	sp->sn_csflags = ap->cs_aotw.csa_flags;
	if (ap->cs_aotw.csa_flags & CREATE_SESSION4_FLAG_PERSIST)
		/* Do not support persistent reply cache (yet). */
		sp->sn_csflags &= ~CREATE_SESSION4_FLAG_PERSIST;

	if (ap->cs_aotw.csa_flags & CREATE_SESSION4_FLAG_CONN_RDMA)
		/* No RDMA for now */
		sp->sn_csflags &= ~CREATE_SESSION4_FLAG_CONN_RDMA;

	/*
	 * Initialize some overall sessions values
	 */
	sp->sn_bc.progno = ap->cs_aotw.csa_cb_program;
	sp->sn_laccess = nfs_sys_uptime();
	sp->sn_flags = 0;
	sp->sn_rcached = 0;

	/*
	 * Check if client has specified that the FORE channel should
	 * also be used for call back traffic (ie. bidir RPC). If so,
	 * let's try to accomodate the request.
	 */
	DTRACE_PROBE1(csa__flags, uint32_t, ap->cs_aotw.csa_flags);

	/*
	 * Session's channel flags depending on bdrpc
	 * TODO: Add backchannel handling, i.e. when bdrpc is TRUE
	 */
	dir = bdrpc ? (CDFS4_FORE | CDFS4_BACK) : CDFS4_FORE;
	ocp = rfs41_create_session_channel(dir);
	ocp->cn_dir = dir;
	sp->sn_fore = ocp;

	/*
	 * Check if channel attrs will be flexible enough for future
	 * purposes. Channel attribute enforcement is done as part of
	 * COMPOUND processing.
	 */
	ocp->cn_attrs = ap->cs_aotw.csa_fore_chan_attrs;
	ocp->cn_back_attrs = ap->cs_aotw.csa_back_chan_attrs;
	if (sle = sess_chan_limits(ocp)) {
		ap->cs_error = sle;
		goto err_free_chan;
	}

	/* will fail if client is going to destroy */
	if (!client_insert_session(sp->sn_clnt, sp)) {
		ap->cs_error = NFS4ERR_DELAY;
		goto err_free_chan;
	}

	/*
	 * No need for locks/synchronization at this time,
	 * since we're barely creating the session.
	 */
	if (bdrpc) {
		/* Need to be implemented */
		VERIFY(0);
	} else {
		sp->sn_csflags &= ~CREATE_SESSION4_FLAG_CONN_BACK_CHAN;
		sp->sn_back = NULL;
	}

	/*
	 * Now we allocate space for the slrc, initializing each slot's
	 * sequenceid and slotid to zero and a (pre)cached result of
	 * NFS4ERR_SEQ_MISORDERED. Note that we zero out the entries
	 * by virtue of the z-alloc.
	 */
	sp->sn_slots = slots_alloc(ocp->cn_attrs.ca_maxrequests);

	return (TRUE);

err_free_chan:
	rfs41_destroy_session_channel(sp);
err:
	rfs4_dbe_rele(sp->sn_clnt->rc_dbe);
	return (FALSE);
}

static void
rfs4_session_destroy(rfs4_entry_t u_entry)
{
	rfs4_session_t	*sp = (rfs4_session_t *)u_entry;
	sess_bcsd_t	*bsdp;

	if (SN_CB_CHAN_EST(sp) && (bsdp = sp->sn_back->cn_csd) != NULL) {
		slots_free(bsdp->bsd_slots,
		    sp->sn_back->cn_back_attrs.ca_maxrequests);
		bsdp->bsd_slots = NULL;
	}

	/*
	 * Nuke slot replay cache for this session
	 */
	if (sp->sn_slots) {
		slots_free(sp->sn_slots, sp->sn_fore->cn_attrs.ca_maxrequests);
		sp->sn_slots = NULL;
	}

	/*
	 * Remove the fore and back channels.
	 */
	rfs41_destroy_session_channel(sp);

	client_remove_session(sp->sn_clnt, sp);

	rfs4_client_rele(sp->sn_clnt);
}

static bool_t
rfs4_session_expiry(rfs4_entry_t u_entry)
{
	rfs4_session_t *sp = (rfs4_session_t *)u_entry;

	if (sp == NULL || rfs4_dbe_is_invalid(sp->sn_dbe))
		return (TRUE);

	if (rfs4_lease_expired(sp->sn_clnt))
		return (TRUE);

	return (FALSE);
}

void
rfs4x_state_init_locked(nfs4_srv_t *nsrv4)
{
	nsrv4->rfs4_session_tab = rfs4_table_create(nsrv4->nfs4_server_state,
	    "Session", 5 * rfs4_lease_time, 1, rfs4_session_create,
	    rfs4_session_destroy, rfs4_session_expiry, sizeof (rfs4_session_t),
	    RFS4_TABSIZE, RFS4_MAXTABSZ/8, -1);

	nsrv4->rfs4_session_idx = rfs4_index_create(nsrv4->rfs4_session_tab,
	    "session_idx", sessid_hash, sessid_compare, sessid_mkkey, TRUE);
}

void
rfs4x_state_fini(nfs4_srv_t *nsrv4)
{
	/* All tables will be destroyed by caller */
}
