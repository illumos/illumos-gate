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
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2012 Marcel Telka <marcel@telka.sk>
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id: svc_auth_gssapi.c,v 1.19 1994/10/27 12:38:51 jik Exp $
 */

/*
 * Server side handling of RPCSEC_GSS flavor.
 */

#include <sys/systm.h>
#include <sys/kstat.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/time.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <rpc/rpc.h>
#include <rpc/rpcsec_defs.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>

extern bool_t __rpc_gss_make_principal(rpc_gss_principal_t *, gss_buffer_t);

#ifdef	DEBUG
extern void prom_printf(const char *, ...);
#endif

#ifdef  _KERNEL
#define	memcmp(a, b, l) bcmp((a), (b), (l))
#endif


/*
 * Sequence window definitions.
 */
#define	SEQ_ARR_SIZE	4
#define	SEQ_WIN		(SEQ_ARR_SIZE*32)
#define	SEQ_HI_BIT	0x80000000
#define	SEQ_LO_BIT	1
#define	DIV_BY_32	5
#define	SEQ_MASK	0x1f
#define	SEQ_MAX		((unsigned int)0x80000000)


/* cache retransmit data */
typedef struct _retrans_entry {
	uint32_t	xid;
	rpc_gss_init_res result;
} retrans_entry;

/*
 * Server side RPCSEC_GSS context information.
 */
typedef struct _svc_rpc_gss_data {
	struct _svc_rpc_gss_data	*next, *prev;
	struct _svc_rpc_gss_data	*lru_next, *lru_prev;
	bool_t				established;
	gss_ctx_id_t			context;
	gss_buffer_desc			client_name;
	time_t				expiration;
	uint_t				seq_num;
	uint_t				seq_bits[SEQ_ARR_SIZE];
	uint_t				key;
	OM_uint32			qop;
	bool_t				done_docallback;
	bool_t				locked;
	rpc_gss_rawcred_t		raw_cred;
	rpc_gss_ucred_t			u_cred;
	time_t				u_cred_set;
	void				*cookie;
	gss_cred_id_t			deleg;
	kmutex_t			clm;
	int				ref_cnt;
	time_t				last_ref_time;
	bool_t				stale;
	retrans_entry			*retrans_data;
} svc_rpc_gss_data;

/*
 * Data structures used for LRU based context management.
 */


#define	HASH(key) ((key) % svc_rpc_gss_hashmod)
/* Size of hash table for svc_rpc_gss_data structures */
#define	GSS_DATA_HASH_SIZE	1024

/*
 * The following two defines specify a time delta that is used in
 * sweep_clients. When the last_ref_time of a context is older than
 * than the current time minus the delta, i.e, the context has not
 * been referenced in the last delta seconds, we will return the
 * context back to the cache if the ref_cnt is zero. The first delta
 * value will be used when sweep_clients is called from
 * svc_data_reclaim, the kmem_cache reclaim call back. We will reclaim
 * all entries except those that are currently "active". By active we
 * mean those that have been referenced in the last ACTIVE_DELTA
 * seconds. If sweep_client is not being called from reclaim, then we
 * will reclaim all entries that are "inactive". By inactive we mean
 * those entries that have not been accessed in INACTIVE_DELTA
 * seconds.  Note we always assume that ACTIVE_DELTA is less than
 * INACTIVE_DELTA, so that reaping entries from a reclaim operation
 * will necessarily imply reaping all "inactive" entries and then
 * some.
 */

/*
 * If low on memory reap cache entries that have not been active for
 * ACTIVE_DELTA seconds and have a ref_cnt equal to zero.
 */
#define	ACTIVE_DELTA		30*60		/* 30 minutes */

/*
 * If in sweeping contexts we find contexts with a ref_cnt equal to zero
 * and the context has not been referenced in INACTIVE_DELTA seconds, return
 * the entry to the cache.
 */
#define	INACTIVE_DELTA		8*60*60		/* 8 hours */

int				svc_rpc_gss_hashmod = GSS_DATA_HASH_SIZE;
static svc_rpc_gss_data		**clients;
static svc_rpc_gss_data		*lru_first, *lru_last;
static time_t			sweep_interval = 60*60;
static time_t			last_swept = 0;
static int			num_gss_contexts = 0;
static time_t			svc_rpcgss_gid_timeout = 60*60*12;
static kmem_cache_t		*svc_data_handle;
static time_t			svc_rpc_gss_active_delta = ACTIVE_DELTA;
static time_t			svc_rpc_gss_inactive_delta = INACTIVE_DELTA;

/*
 * lock used with context/lru variables
 */
static kmutex_t			ctx_mutex;

/*
 * Data structure to contain cache statistics
 */

static struct {
	int64_t total_entries_allocated;
	int64_t no_reclaims;
	int64_t no_returned_by_reclaim;
} svc_rpc_gss_cache_stats;


/*
 * lock used with server credential variables list
 *
 * server cred list locking guidelines:
 * - Writer's lock holder has exclusive access to the list
 */
static krwlock_t		cred_lock;

/*
 * server callback list
 */
typedef struct rpc_gss_cblist_s {
	struct rpc_gss_cblist_s		*next;
	rpc_gss_callback_t	cb;
} rpc_gss_cblist_t;

static rpc_gss_cblist_t			*rpc_gss_cblist = NULL;

/*
 * lock used with callback variables
 */
static kmutex_t			cb_mutex;

/*
 * forward declarations
 */
static bool_t			svc_rpc_gss_wrap();
static bool_t			svc_rpc_gss_unwrap();
static svc_rpc_gss_data		*create_client();
static svc_rpc_gss_data		*get_client();
static svc_rpc_gss_data		*find_client();
static void			destroy_client();
static void			sweep_clients(bool_t);
static void			insert_client();
static bool_t			check_verf(struct rpc_msg *, gss_ctx_id_t,
					int *, uid_t);
static bool_t			set_response_verf();
static void			retrans_add(svc_rpc_gss_data *, uint32_t,
					rpc_gss_init_res *);
static void			retrans_del(svc_rpc_gss_data *);
static bool_t			transfer_sec_context(svc_rpc_gss_data *);
static void			common_client_data_free(svc_rpc_gss_data *);

/*
 * server side wrap/unwrap routines
 */
struct svc_auth_ops svc_rpc_gss_ops = {
	svc_rpc_gss_wrap,
	svc_rpc_gss_unwrap,
};

/* taskq(9F) */
typedef struct svcrpcsec_gss_taskq_arg {
	SVCXPRT			*rq_xprt;
	rpc_gss_init_arg	*rpc_call_arg;
	struct rpc_msg		*msg;
	svc_rpc_gss_data	*client_data;
	uint_t			cr_version;
	rpc_gss_service_t	cr_service;
} svcrpcsec_gss_taskq_arg_t;

/* gssd is single threaded, so 1 thread for the taskq is probably good/ok */
int rpcsec_gss_init_taskq_nthreads = 1;
static ddi_taskq_t *svcrpcsec_gss_init_taskq = NULL;

extern struct rpc_msg *rpc_msg_dup(struct rpc_msg *);
extern void rpc_msg_free(struct rpc_msg **, int);

/*
 * from svc_clts.c:
 * Transport private data.
 * Kept in xprt->xp_p2buf.
 */
struct udp_data {
	mblk_t	*ud_resp;			/* buffer for response */
	mblk_t	*ud_inmp;			/* mblk chain of request */
};

/*ARGSUSED*/
static int
svc_gss_data_create(void *buf, void *pdata, int kmflag)
{
	svc_rpc_gss_data *client_data = (svc_rpc_gss_data *)buf;

	mutex_init(&client_data->clm, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
svc_gss_data_destroy(void *buf, void *pdata)
{
	svc_rpc_gss_data *client_data = (svc_rpc_gss_data *)buf;

	mutex_destroy(&client_data->clm);
}


/*ARGSUSED*/
static void
svc_gss_data_reclaim(void *pdata)
{
	mutex_enter(&ctx_mutex);

	svc_rpc_gss_cache_stats.no_reclaims++;
	sweep_clients(TRUE);

	mutex_exit(&ctx_mutex);
}

/*
 *  Init stuff on the server side.
 */
void
svc_gss_init()
{
	mutex_init(&cb_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ctx_mutex, NULL, MUTEX_DEFAULT, NULL);
	rw_init(&cred_lock, NULL, RW_DEFAULT, NULL);
	clients = (svc_rpc_gss_data **)
	    kmem_zalloc(svc_rpc_gss_hashmod * sizeof (svc_rpc_gss_data *),
	    KM_SLEEP);
	svc_data_handle = kmem_cache_create("rpc_gss_data_cache",
	    sizeof (svc_rpc_gss_data), 0,
	    svc_gss_data_create,
	    svc_gss_data_destroy,
	    svc_gss_data_reclaim,
	    NULL, NULL, 0);

	if (svcrpcsec_gss_init_taskq == NULL) {
		svcrpcsec_gss_init_taskq = ddi_taskq_create(NULL,
		    "rpcsec_gss_init_taskq", rpcsec_gss_init_taskq_nthreads,
		    TASKQ_DEFAULTPRI, 0);
		if (svcrpcsec_gss_init_taskq == NULL)
			cmn_err(CE_NOTE,
			    "svc_gss_init: ddi_taskq_create failed");
	}
}

/*
 * Destroy structures allocated in svc_gss_init().
 * This routine is called by _init() if mod_install() failed.
 */
void
svc_gss_fini()
{
	mutex_destroy(&cb_mutex);
	mutex_destroy(&ctx_mutex);
	rw_destroy(&cred_lock);
	kmem_free(clients, svc_rpc_gss_hashmod * sizeof (svc_rpc_gss_data *));
	kmem_cache_destroy(svc_data_handle);
}

/*
 * Cleanup routine for destroying context, called after service
 * procedure is executed. Actually we just decrement the reference count
 * associated with this context. If the reference count is zero and the
 * context is marked as stale, we would then destroy the context. Additionally,
 * we check if its been longer than sweep_interval since the last sweep_clients
 * was run, and if so run sweep_clients to free all stale contexts with zero
 * reference counts or contexts that are old. (Haven't been access in
 * svc_rpc_inactive_delta seconds).
 */
void
rpc_gss_cleanup(SVCXPRT *clone_xprt)
{
	svc_rpc_gss_data	*cl;
	SVCAUTH			*svcauth;

	/*
	 * First check if current context needs to be cleaned up.
	 * There might be other threads stale this client data
	 * in between.
	 */
	svcauth = &clone_xprt->xp_auth;
	mutex_enter(&ctx_mutex);
	if ((cl = (svc_rpc_gss_data *)svcauth->svc_ah_private) != NULL) {
		mutex_enter(&cl->clm);
		ASSERT(cl->ref_cnt > 0);
		if (--cl->ref_cnt == 0 && cl->stale) {
			mutex_exit(&cl->clm);
			destroy_client(cl);
			svcauth->svc_ah_private = NULL;
		} else
			mutex_exit(&cl->clm);
	}

	/*
	 * Check for other expired contexts.
	 */
	if ((gethrestime_sec() - last_swept) > sweep_interval)
		sweep_clients(FALSE);

	mutex_exit(&ctx_mutex);
}

/*
 * Shift the array arr of length arrlen right by nbits bits.
 */
static void
shift_bits(uint_t *arr, int arrlen, int nbits)
{
	int	i, j;
	uint_t	lo, hi;

	/*
	 * If the number of bits to be shifted exceeds SEQ_WIN, just
	 * zero out the array.
	 */
	if (nbits < SEQ_WIN) {
		for (i = 0; i < nbits; i++) {
			hi = 0;
			for (j = 0; j < arrlen; j++) {
				lo = arr[j] & SEQ_LO_BIT;
				arr[j] >>= 1;
				if (hi)
					arr[j] |= SEQ_HI_BIT;
				hi = lo;
			}
		}
	} else {
		for (j = 0; j < arrlen; j++)
			arr[j] = 0;
	}
}

/*
 * Check that the received sequence number seq_num is valid.
 */
static bool_t
check_seq(svc_rpc_gss_data *cl, uint_t seq_num, bool_t *kill_context)
{
	int			i, j;
	uint_t			bit;

	/*
	 * If it exceeds the maximum, kill context.
	 */
	if (seq_num >= SEQ_MAX) {
		*kill_context = TRUE;
		RPCGSS_LOG0(4, "check_seq: seq_num not valid\n");
		return (FALSE);
	}

	/*
	 * If greater than the last seen sequence number, just shift
	 * the sequence window so that it starts at the new sequence
	 * number and extends downwards by SEQ_WIN.
	 */
	if (seq_num > cl->seq_num) {
		(void) shift_bits(cl->seq_bits, SEQ_ARR_SIZE,
		    (int)(seq_num - cl->seq_num));
		cl->seq_bits[0] |= SEQ_HI_BIT;
		cl->seq_num = seq_num;
		return (TRUE);
	}

	/*
	 * If it is outside the sequence window, return failure.
	 */
	i = cl->seq_num - seq_num;
	if (i >= SEQ_WIN) {
		RPCGSS_LOG0(4, "check_seq: seq_num is outside the window\n");
		return (FALSE);
	}

	/*
	 * If within sequence window, set the bit corresponding to it
	 * if not already seen;  if already seen, return failure.
	 */
	j = SEQ_MASK - (i & SEQ_MASK);
	bit = j > 0 ? (1 << j) : 1;
	i >>= DIV_BY_32;
	if (cl->seq_bits[i] & bit) {
		RPCGSS_LOG0(4, "check_seq: sequence number already seen\n");
		return (FALSE);
	}
	cl->seq_bits[i] |= bit;
	return (TRUE);
}

/*
 * Set server callback.
 */
bool_t
rpc_gss_set_callback(rpc_gss_callback_t *cb)
{
	rpc_gss_cblist_t		*cbl, *tmp;

	if (cb->callback == NULL) {
		RPCGSS_LOG0(1, "rpc_gss_set_callback: no callback to set\n");
		return (FALSE);
	}

	/* check if there is already an entry in the rpc_gss_cblist. */
	mutex_enter(&cb_mutex);
	if (rpc_gss_cblist) {
		for (tmp = rpc_gss_cblist; tmp != NULL; tmp = tmp->next) {
			if ((tmp->cb.callback == cb->callback) &&
			    (tmp->cb.version == cb->version) &&
			    (tmp->cb.program == cb->program)) {
				mutex_exit(&cb_mutex);
				return (TRUE);
			}
		}
	}

	/* Not in rpc_gss_cblist.  Create a new entry. */
	if ((cbl = (rpc_gss_cblist_t *)kmem_alloc(sizeof (*cbl), KM_SLEEP))
	    == NULL) {
		mutex_exit(&cb_mutex);
		return (FALSE);
	}
	cbl->cb = *cb;
	cbl->next = rpc_gss_cblist;
	rpc_gss_cblist = cbl;
	mutex_exit(&cb_mutex);
	return (TRUE);
}

/*
 * Locate callback (if specified) and call server.  Release any
 * delegated credentials unless passed to server and the server
 * accepts the context.  If a callback is not specified, accept
 * the incoming context.
 */
static bool_t
do_callback(struct svc_req *req, svc_rpc_gss_data *client_data)
{
	rpc_gss_cblist_t		*cbl;
	bool_t			ret = TRUE, found = FALSE;
	rpc_gss_lock_t		lock;
	OM_uint32		minor;
	mutex_enter(&cb_mutex);
	for (cbl = rpc_gss_cblist; cbl != NULL; cbl = cbl->next) {
		if (req->rq_prog != cbl->cb.program ||
		    req->rq_vers != cbl->cb.version)
			continue;
		found = TRUE;
		lock.locked = FALSE;
		lock.raw_cred = &client_data->raw_cred;
		ret = (*cbl->cb.callback)(req, client_data->deleg,
		    client_data->context, &lock, &client_data->cookie);
		req->rq_xprt->xp_cookie = client_data->cookie;

		if (ret) {
			client_data->locked = lock.locked;
			client_data->deleg = GSS_C_NO_CREDENTIAL;
		}
		break;
	}
	if (!found) {
		if (client_data->deleg != GSS_C_NO_CREDENTIAL) {
			(void) kgss_release_cred(&minor, &client_data->deleg,
			    crgetuid(CRED()));
			client_data->deleg = GSS_C_NO_CREDENTIAL;
		}
	}
	mutex_exit(&cb_mutex);
	return (ret);
}

/*
 * Get caller credentials.
 */
bool_t
rpc_gss_getcred(struct svc_req *req, rpc_gss_rawcred_t **rcred,
    rpc_gss_ucred_t **ucred, void **cookie)
{
	SVCAUTH			*svcauth;
	svc_rpc_gss_data	*client_data;
	int			gssstat, gidlen;

	svcauth = &req->rq_xprt->xp_auth;
	client_data = (svc_rpc_gss_data *)svcauth->svc_ah_private;

	mutex_enter(&client_data->clm);

	if (rcred != NULL) {
		svcauth->raw_cred = client_data->raw_cred;
		*rcred = &svcauth->raw_cred;
	}
	if (ucred != NULL) {
		*ucred = &client_data->u_cred;

		if (client_data->u_cred_set == 0 ||
		    client_data->u_cred_set < gethrestime_sec()) {
			if (client_data->u_cred_set == 0) {
				if ((gssstat = kgsscred_expname_to_unix_cred(
				    &client_data->client_name,
				    &client_data->u_cred.uid,
				    &client_data->u_cred.gid,
				    &client_data->u_cred.gidlist,
				    &gidlen, crgetuid(CRED())))
				    != GSS_S_COMPLETE) {
					RPCGSS_LOG(1, "rpc_gss_getcred: "
					    "kgsscred_expname_to_unix_cred "
					    "failed %x\n", gssstat);
					*ucred = NULL;
				} else {
					client_data->u_cred.gidlen =
					    (short)gidlen;
					client_data->u_cred_set =
					    gethrestime_sec() +
					    svc_rpcgss_gid_timeout;
				}
			} else if (client_data->u_cred_set
			    < gethrestime_sec()) {
				if ((gssstat = kgss_get_group_info(
				    client_data->u_cred.uid,
				    &client_data->u_cred.gid,
				    &client_data->u_cred.gidlist,
				    &gidlen, crgetuid(CRED())))
				    != GSS_S_COMPLETE) {
					RPCGSS_LOG(1, "rpc_gss_getcred: "
					    "kgss_get_group_info failed %x\n",
					    gssstat);
					*ucred = NULL;
				} else {
					client_data->u_cred.gidlen =
					    (short)gidlen;
					client_data->u_cred_set =
					    gethrestime_sec() +
					    svc_rpcgss_gid_timeout;
				}
			}
		}
	}

	if (cookie != NULL)
		*cookie = client_data->cookie;
	req->rq_xprt->xp_cookie = client_data->cookie;

	mutex_exit(&client_data->clm);

	return (TRUE);
}

/*
 * Transfer the context data from the user land to the kernel.
 */
bool_t transfer_sec_context(svc_rpc_gss_data *client_data) {

	gss_buffer_desc process_token;
	OM_uint32 gssstat, minor;

	/*
	 * Call kgss_export_sec_context
	 * if an error is returned log a message
	 * go to error handling
	 * Otherwise call kgss_import_sec_context to
	 * convert the token into a context
	 */
	gssstat  = kgss_export_sec_context(&minor, client_data->context,
				&process_token);
	/*
	 * if export_sec_context returns an error we delete the
	 * context just to be safe.
	 */
	if (gssstat == GSS_S_NAME_NOT_MN) {
		RPCGSS_LOG0(4, "svc_rpcsec_gss: export sec context "
				"Kernel mod unavailable\n");

	} else if (gssstat != GSS_S_COMPLETE) {
		RPCGSS_LOG(1, "svc_rpcsec_gss: export sec context failed  "
				" gssstat = 0x%x\n", gssstat);
		(void) gss_release_buffer(&minor, &process_token);
		(void) kgss_delete_sec_context(&minor, &client_data->context,
				NULL);
		return (FALSE);

	} else if (process_token.length == 0) {
		RPCGSS_LOG0(1, "svc_rpcsec_gss:zero length token in response "
				"for export_sec_context, but "
				"gsstat == GSS_S_COMPLETE\n");
		(void) kgss_delete_sec_context(&minor, &client_data->context,
				NULL);
		return (FALSE);

	} else {
		gssstat = kgss_import_sec_context(&minor, &process_token,
					client_data->context);
		if (gssstat != GSS_S_COMPLETE) {
			RPCGSS_LOG(1, "svc_rpcsec_gss: import sec context "
				" failed gssstat = 0x%x\n", gssstat);
			(void) kgss_delete_sec_context(&minor,
				&client_data->context, NULL);
			(void) gss_release_buffer(&minor, &process_token);
			return (FALSE);
		}

		RPCGSS_LOG0(4, "gss_import_sec_context successful\n");
		(void) gss_release_buffer(&minor, &process_token);
	}

	return (TRUE);
}

/*
 * do_gss_accept is called from a taskq and does all the work for a
 * RPCSEC_GSS_INIT call (mostly calling kgss_accept_sec_context()).
 */
static enum auth_stat
do_gss_accept(
	SVCXPRT *xprt,
	rpc_gss_init_arg *call_arg,
	struct rpc_msg *msg,
	svc_rpc_gss_data *client_data,
	uint_t cr_version,
	rpc_gss_service_t cr_service)
{
	rpc_gss_init_res	call_res;
	gss_buffer_desc		output_token;
	OM_uint32		gssstat, minor, minor_stat, time_rec;
	int			ret_flags, ret;
	gss_OID			mech_type = GSS_C_NULL_OID;
	int			free_mech_type = 1;
	struct svc_req		r, *rqst;

	rqst = &r;
	rqst->rq_xprt = xprt;

	/*
	 * Initialize output_token.
	 */
	output_token.length = 0;
	output_token.value = NULL;

	bzero((char *)&call_res, sizeof (call_res));

	mutex_enter(&client_data->clm);
	if (client_data->stale) {
		ret = RPCSEC_GSS_NOCRED;
		RPCGSS_LOG0(1, "_svcrpcsec_gss: client data stale\n");
		goto error2;
	}

	/*
	 * Any response we send will use ctx_handle, so set it now;
	 * also set seq_window since this won't change.
	 */
	call_res.ctx_handle.length = sizeof (client_data->key);
	call_res.ctx_handle.value = (char *)&client_data->key;
	call_res.seq_window = SEQ_WIN;

	gssstat = GSS_S_FAILURE;
	minor = 0;
	minor_stat = 0;
	rw_enter(&cred_lock, RW_READER);

	if (client_data->client_name.length) {
		(void) gss_release_buffer(&minor,
		    &client_data->client_name);
	}
	gssstat = kgss_accept_sec_context(&minor_stat,
	    &client_data->context,
	    GSS_C_NO_CREDENTIAL,
	    call_arg,
	    GSS_C_NO_CHANNEL_BINDINGS,
	    &client_data->client_name,
	    &mech_type,
	    &output_token,
	    &ret_flags,
	    &time_rec,
	    NULL,		/* don't need a delegated cred back */
	    crgetuid(CRED()));

	RPCGSS_LOG(4, "gssstat 0x%x \n", gssstat);

	if (gssstat == GSS_S_COMPLETE) {
		/*
		 * Set the raw and unix credentials at this
		 * point.  This saves a lot of computation
		 * later when credentials are retrieved.
		 */
		client_data->raw_cred.version = cr_version;
		client_data->raw_cred.service = cr_service;

		if (client_data->raw_cred.mechanism) {
			kgss_free_oid(client_data->raw_cred.mechanism);
			client_data->raw_cred.mechanism = NULL;
		}
		client_data->raw_cred.mechanism = (rpc_gss_OID) mech_type;
		/*
		 * client_data is now responsible for freeing
		 * the data of 'mech_type'.
		 */
		free_mech_type = 0;

		if (client_data->raw_cred.client_principal) {
			kmem_free((caddr_t)client_data->\
			    raw_cred.client_principal,
			    client_data->raw_cred.\
			    client_principal->len + sizeof (int));
			client_data->raw_cred.client_principal = NULL;
		}

		/*
		 *  The client_name returned from
		 *  kgss_accept_sec_context() is in an
		 *  exported flat format.
		 */
		if (! __rpc_gss_make_principal(
		    &client_data->raw_cred.client_principal,
		    &client_data->client_name)) {
			RPCGSS_LOG0(1, "_svcrpcsec_gss: "
			    "make principal failed\n");
			gssstat = GSS_S_FAILURE;
			(void) gss_release_buffer(&minor_stat, &output_token);
		}
	}

	rw_exit(&cred_lock);

	call_res.gss_major = gssstat;
	call_res.gss_minor = minor_stat;

	if (gssstat != GSS_S_COMPLETE &&
	    gssstat != GSS_S_CONTINUE_NEEDED) {
		call_res.ctx_handle.length = 0;
		call_res.ctx_handle.value = NULL;
		call_res.seq_window = 0;
		rpc_gss_display_status(gssstat, minor_stat, mech_type,
		    crgetuid(CRED()),
		    "_svc_rpcsec_gss gss_accept_sec_context");
		(void) svc_sendreply(rqst->rq_xprt,
		    __xdr_rpc_gss_init_res, (caddr_t)&call_res);
		client_data->stale = TRUE;
		ret = AUTH_OK;
		goto error2;
	}

	/*
	 * If appropriate, set established to TRUE *after* sending
	 * response (otherwise, the client will receive the final
	 * token encrypted)
	 */
	if (gssstat == GSS_S_COMPLETE) {
		/*
		 * Context is established.  Set expiration time
		 * for the context.
		 */
		client_data->seq_num = 1;
		if ((time_rec == GSS_C_INDEFINITE) || (time_rec == 0)) {
			client_data->expiration = GSS_C_INDEFINITE;
		} else {
			client_data->expiration =
			    time_rec + gethrestime_sec();
		}

		if (!transfer_sec_context(client_data)) {
			ret = RPCSEC_GSS_FAILED;
			client_data->stale = TRUE;
			RPCGSS_LOG0(1,
			    "_svc_rpcsec_gss: transfer sec context failed\n");
			goto error2;
		}

		client_data->established = TRUE;
	}

	/*
	 * This step succeeded.  Send a response, along with
	 * a token if there's one.  Don't dispatch.
	 */

	if (output_token.length != 0)
		GSS_COPY_BUFFER(call_res.token, output_token);

	/*
	 * If GSS_S_COMPLETE: set response verifier to
	 * checksum of SEQ_WIN
	 */
	if (gssstat == GSS_S_COMPLETE) {
		if (!set_response_verf(rqst, msg, client_data,
		    (uint_t)SEQ_WIN)) {
			ret = RPCSEC_GSS_FAILED;
			client_data->stale = TRUE;
			RPCGSS_LOG0(1,
			    "_svc_rpcsec_gss:set response verifier failed\n");
			goto error2;
		}
	}

	if (!svc_sendreply(rqst->rq_xprt, __xdr_rpc_gss_init_res,
	    (caddr_t)&call_res)) {
		ret = RPCSEC_GSS_FAILED;
		client_data->stale = TRUE;
		RPCGSS_LOG0(1, "_svc_rpcsec_gss:send reply failed\n");
		goto error2;
	}

	/*
	 * Cache last response in case it is lost and the client
	 * retries on an established context.
	 */
	(void) retrans_add(client_data, msg->rm_xid, &call_res);
	ASSERT(client_data->ref_cnt > 0);
	client_data->ref_cnt--;
	mutex_exit(&client_data->clm);

	(void) gss_release_buffer(&minor_stat, &output_token);

	return (AUTH_OK);

error2:
	ASSERT(client_data->ref_cnt > 0);
	client_data->ref_cnt--;
	mutex_exit(&client_data->clm);
	(void) gss_release_buffer(&minor_stat, &output_token);
	if (free_mech_type && mech_type)
		kgss_free_oid(mech_type);

	return (ret);
}

static void
svcrpcsec_gss_taskq_func(void *svcrpcsecgss_taskq_arg)
{
	enum auth_stat retval;
	svcrpcsec_gss_taskq_arg_t *arg = svcrpcsecgss_taskq_arg;

	retval = do_gss_accept(arg->rq_xprt, arg->rpc_call_arg, arg->msg,
	    arg->client_data, arg->cr_version, arg->cr_service);
	if (retval != AUTH_OK) {
		cmn_err(CE_NOTE,
		    "svcrpcsec_gss_taskq_func:  do_gss_accept fail 0x%x",
		    retval);
	}
	rpc_msg_free(&arg->msg, MAX_AUTH_BYTES);
	SVC_RELE(arg->rq_xprt, NULL, FALSE);
	svc_clone_unlink(arg->rq_xprt);
	svc_clone_free(arg->rq_xprt);
	xdr_free(__xdr_rpc_gss_init_arg, (caddr_t)arg->rpc_call_arg);
	kmem_free(arg->rpc_call_arg, sizeof (*arg->rpc_call_arg));

	kmem_free(arg, sizeof (*arg));
}

static enum auth_stat
rpcsec_gss_init(
	struct svc_req		*rqst,
	struct rpc_msg		*msg,
	rpc_gss_creds		creds,
	bool_t			*no_dispatch,
	svc_rpc_gss_data	*c_d) /* client data, can be NULL */
{
	svc_rpc_gss_data	*client_data;
	int ret;
	svcrpcsec_gss_taskq_arg_t *arg;

	if (creds.ctx_handle.length != 0) {
		RPCGSS_LOG0(1, "_svcrpcsec_gss: ctx_handle not null\n");
		ret = AUTH_BADCRED;
		return (ret);
	}

	client_data = c_d ? c_d : create_client();
	if (client_data == NULL) {
		RPCGSS_LOG0(1,
		    "_svcrpcsec_gss: can't create a new cache entry\n");
		ret = AUTH_FAILED;
		return (ret);
	}

	mutex_enter(&client_data->clm);
	if (client_data->stale) {
		ret = RPCSEC_GSS_NOCRED;
		RPCGSS_LOG0(1, "_svcrpcsec_gss: client data stale\n");
		goto error2;
	}

	/*
	 * kgss_accept_sec_context()/gssd(8) can be overly time
	 * consuming so let's queue it and return asap.
	 *
	 * taskq func must free arg.
	 */
	arg = kmem_alloc(sizeof (*arg), KM_SLEEP);

	/* taskq func must free rpc_call_arg & deserialized arguments */
	arg->rpc_call_arg = kmem_zalloc(sizeof (*arg->rpc_call_arg), KM_SLEEP);

	/* deserialize arguments */
	if (!SVC_GETARGS(rqst->rq_xprt, __xdr_rpc_gss_init_arg,
	    (caddr_t)arg->rpc_call_arg)) {
		ret = RPCSEC_GSS_FAILED;
		client_data->stale = TRUE;
		goto error2;
	}

	/* get a xprt clone for taskq thread, taskq func must free it */
	arg->rq_xprt = svc_clone_init();
	svc_clone_link(rqst->rq_xprt->xp_master, arg->rq_xprt, rqst->rq_xprt);
	arg->rq_xprt->xp_xid = rqst->rq_xprt->xp_xid;

	/*
	 * Increment the reference count on the rpcmod slot so that is not
	 * freed before the task has finished.
	 */
	SVC_HOLD(arg->rq_xprt);

	/* set the appropriate wrap/unwrap routine for RPCSEC_GSS */
	arg->rq_xprt->xp_auth.svc_ah_ops = svc_rpc_gss_ops;
	arg->rq_xprt->xp_auth.svc_ah_private = (caddr_t)client_data;

	/* get a dup of rpc msg for taskq thread */
	arg->msg = rpc_msg_dup(msg);  /* taskq func must free msg dup */

	arg->client_data = client_data;
	arg->cr_version = creds.version;
	arg->cr_service = creds.service;

	/* should be ok to hold clm lock as taskq will have new thread(s) */
	ret = ddi_taskq_dispatch(svcrpcsec_gss_init_taskq,
	    svcrpcsec_gss_taskq_func, arg, DDI_SLEEP);
	if (ret == DDI_FAILURE) {
		cmn_err(CE_NOTE, "rpcsec_gss_init: taskq dispatch fail");
		ret = RPCSEC_GSS_FAILED;
		rpc_msg_free(&arg->msg, MAX_AUTH_BYTES);
		SVC_RELE(arg->rq_xprt, NULL, FALSE);
		svc_clone_unlink(arg->rq_xprt);
		svc_clone_free(arg->rq_xprt);
		kmem_free(arg, sizeof (*arg));
		goto error2;
	}

	mutex_exit(&client_data->clm);
	*no_dispatch = TRUE;
	return (AUTH_OK);

error2:
	ASSERT(client_data->ref_cnt > 0);
	client_data->ref_cnt--;
	mutex_exit(&client_data->clm);
	cmn_err(CE_NOTE, "rpcsec_gss_init: error 0x%x", ret);
	return (ret);
}

static enum auth_stat
rpcsec_gss_continue_init(
	struct svc_req		*rqst,
	struct rpc_msg		*msg,
	rpc_gss_creds		creds,
	bool_t			*no_dispatch)
{
	int ret;
	svc_rpc_gss_data	*client_data;
	svc_rpc_gss_parms_t	*gss_parms;
	rpc_gss_init_res	*retrans_result;

	if (creds.ctx_handle.length == 0) {
		RPCGSS_LOG0(1, "_svcrpcsec_gss: no ctx_handle\n");
		ret = AUTH_BADCRED;
		return (ret);
	}
	if ((client_data = get_client(&creds.ctx_handle)) == NULL) {
		ret = RPCSEC_GSS_NOCRED;
		RPCGSS_LOG0(1, "_svcrpcsec_gss: no security context\n");
		return (ret);
	}

	mutex_enter(&client_data->clm);
	if (client_data->stale) {
		ret = RPCSEC_GSS_NOCRED;
		RPCGSS_LOG0(1, "_svcrpcsec_gss: client data stale\n");
		goto error2;
	}

	/*
	 * If context not established, go thru INIT code but with
	 * this client handle.
	 */
	if (!client_data->established) {
		mutex_exit(&client_data->clm);
		return (rpcsec_gss_init(rqst, msg, creds, no_dispatch,
		    client_data));
	}

	/*
	 * Set the appropriate wrap/unwrap routine for RPCSEC_GSS.
	 */
	rqst->rq_xprt->xp_auth.svc_ah_ops = svc_rpc_gss_ops;
	rqst->rq_xprt->xp_auth.svc_ah_private = (caddr_t)client_data;

	/*
	 * Keep copy of parameters we'll need for response, for the
	 * sake of reentrancy (we don't want to look in the context
	 * data because when we are sending a response, another
	 * request may have come in).
	 */
	gss_parms = &rqst->rq_xprt->xp_auth.svc_gss_parms;
	gss_parms->established = client_data->established;
	gss_parms->service = creds.service;
	gss_parms->qop_rcvd = (uint_t)client_data->qop;
	gss_parms->context = (void *)client_data->context;
	gss_parms->seq_num = creds.seq_num;

	/*
	 * This is an established context. Continue to
	 * satisfy retried continue init requests out of
	 * the retransmit cache.  Throw away any that don't
	 * have a matching xid or the cach is empty.
	 * Delete the retransmit cache once the client sends
	 * a data request.
	 */
	if (client_data->retrans_data &&
	    (client_data->retrans_data->xid == msg->rm_xid)) {
		retrans_result = &client_data->retrans_data->result;
		if (set_response_verf(rqst, msg, client_data,
		    (uint_t)retrans_result->seq_window)) {
			gss_parms->established = FALSE;
			(void) svc_sendreply(rqst->rq_xprt,
			    __xdr_rpc_gss_init_res, (caddr_t)retrans_result);
			*no_dispatch = TRUE;
			ASSERT(client_data->ref_cnt > 0);
			client_data->ref_cnt--;
		}
	}
	mutex_exit(&client_data->clm);

	return (AUTH_OK);

error2:
	ASSERT(client_data->ref_cnt > 0);
	client_data->ref_cnt--;
	mutex_exit(&client_data->clm);
	return (ret);
}

static enum auth_stat
rpcsec_gss_data(
	struct svc_req		*rqst,
	struct rpc_msg		*msg,
	rpc_gss_creds		creds,
	bool_t			*no_dispatch)
{
	int ret;
	svc_rpc_gss_parms_t	*gss_parms;
	svc_rpc_gss_data	*client_data;

	switch (creds.service) {
	case rpc_gss_svc_none:
	case rpc_gss_svc_integrity:
	case rpc_gss_svc_privacy:
		break;
	default:
		cmn_err(CE_NOTE, "__svcrpcsec_gss: unknown service type=0x%x",
		    creds.service);
		RPCGSS_LOG(1, "_svcrpcsec_gss: unknown service type: 0x%x\n",
		    creds.service);
		ret = AUTH_BADCRED;
		return (ret);
	}

	if (creds.ctx_handle.length == 0) {
		RPCGSS_LOG0(1, "_svcrpcsec_gss: no ctx_handle\n");
		ret = AUTH_BADCRED;
		return (ret);
	}
	if ((client_data = get_client(&creds.ctx_handle)) == NULL) {
		ret = RPCSEC_GSS_NOCRED;
		RPCGSS_LOG0(1, "_svcrpcsec_gss: no security context\n");
		return (ret);
	}


	mutex_enter(&client_data->clm);
	if (!client_data->established) {
		ret = AUTH_FAILED;
		goto error2;
	}
	if (client_data->stale) {
		ret = RPCSEC_GSS_NOCRED;
		RPCGSS_LOG0(1, "_svcrpcsec_gss: client data stale\n");
		goto error2;
	}

	/*
	 * Once the context is established and there is no more
	 * retransmission of last continue init request, it is safe
	 * to delete the retransmit cache entry.
	 */
	if (client_data->retrans_data)
		retrans_del(client_data);

	/*
	 * Set the appropriate wrap/unwrap routine for RPCSEC_GSS.
	 */
	rqst->rq_xprt->xp_auth.svc_ah_ops = svc_rpc_gss_ops;
	rqst->rq_xprt->xp_auth.svc_ah_private = (caddr_t)client_data;

	/*
	 * Keep copy of parameters we'll need for response, for the
	 * sake of reentrancy (we don't want to look in the context
	 * data because when we are sending a response, another
	 * request may have come in).
	 */
	gss_parms = &rqst->rq_xprt->xp_auth.svc_gss_parms;
	gss_parms->established = client_data->established;
	gss_parms->service = creds.service;
	gss_parms->qop_rcvd = (uint_t)client_data->qop;
	gss_parms->context = (void *)client_data->context;
	gss_parms->seq_num = creds.seq_num;

	/*
	 * Context is already established.  Check verifier, and
	 * note parameters we will need for response in gss_parms.
	 */
	if (!check_verf(msg, client_data->context,
	    (int *)&gss_parms->qop_rcvd, client_data->u_cred.uid)) {
		ret = RPCSEC_GSS_NOCRED;
		RPCGSS_LOG0(1, "_svcrpcsec_gss: check verf failed\n");
		goto error2;
	}

	/*
	 *  Check and invoke callback if necessary.
	 */
	if (!client_data->done_docallback) {
		client_data->done_docallback = TRUE;
		client_data->qop = gss_parms->qop_rcvd;
		client_data->raw_cred.qop = gss_parms->qop_rcvd;
		client_data->raw_cred.service = creds.service;
		if (!do_callback(rqst, client_data)) {
			ret = AUTH_FAILED;
			RPCGSS_LOG0(1, "_svc_rpcsec_gss:callback failed\n");
			goto error2;
		}
	}

	/*
	 * If the context was locked, make sure that the client
	 * has not changed QOP.
	 */
	if (client_data->locked && gss_parms->qop_rcvd != client_data->qop) {
		ret = AUTH_BADVERF;
		RPCGSS_LOG0(1, "_svcrpcsec_gss: can not change qop\n");
		goto error2;
	}

	/*
	 * Validate sequence number.
	 */
	if (!check_seq(client_data, creds.seq_num, &client_data->stale)) {
		if (client_data->stale) {
			ret = RPCSEC_GSS_FAILED;
			RPCGSS_LOG0(1,
			    "_svc_rpcsec_gss:check seq failed\n");
		} else {
			RPCGSS_LOG0(4, "_svc_rpcsec_gss:check seq "
			    "failed on good context. Ignoring "
			    "request\n");
			/*
			 * Operational error, drop packet silently.
			 * The client will recover after timing out,
			 * assuming this is a client error and not
			 * a relpay attack.  Don't dispatch.
			 */
			ret = AUTH_OK;
			*no_dispatch = TRUE;
		}
		goto error2;
	}

	/*
	 * set response verifier
	 */
	if (!set_response_verf(rqst, msg, client_data, creds.seq_num)) {
		ret = RPCSEC_GSS_FAILED;
		client_data->stale = TRUE;
		RPCGSS_LOG0(1,
		    "_svc_rpcsec_gss:set response verifier failed\n");
		goto error2;
	}

	/*
	 * If context is locked, make sure that the client
	 * has not changed the security service.
	 */
	if (client_data->locked &&
	    client_data->raw_cred.service != creds.service) {
		RPCGSS_LOG0(1, "_svc_rpcsec_gss: "
		    "security service changed.\n");
		ret = AUTH_FAILED;
		goto error2;
	}

	/*
	 * Set client credentials to raw credential
	 * structure in context.  This is okay, since
	 * this will not change during the lifetime of
	 * the context (so it's MT safe).
	 */
	rqst->rq_clntcred = (char *)&client_data->raw_cred;

	mutex_exit(&client_data->clm);
	return (AUTH_OK);

error2:
	ASSERT(client_data->ref_cnt > 0);
	client_data->ref_cnt--;
	mutex_exit(&client_data->clm);
	return (ret);
}

/*
 * Note we don't have a client yet to use this routine and test it.
 */
static enum auth_stat
rpcsec_gss_destroy(
	struct svc_req		*rqst,
	rpc_gss_creds		creds,
	bool_t			*no_dispatch)
{
	svc_rpc_gss_data	*client_data;
	int ret;

	if (creds.ctx_handle.length == 0) {
		RPCGSS_LOG0(1, "_svcrpcsec_gss: no ctx_handle\n");
		ret = AUTH_BADCRED;
		return (ret);
	}
	if ((client_data = get_client(&creds.ctx_handle)) == NULL) {
		ret = RPCSEC_GSS_NOCRED;
		RPCGSS_LOG0(1, "_svcrpcsec_gss: no security context\n");
		return (ret);
	}

	mutex_enter(&client_data->clm);
	if (!client_data->established) {
		ret = AUTH_FAILED;
		goto error2;
	}
	if (client_data->stale) {
		ret = RPCSEC_GSS_NOCRED;
		RPCGSS_LOG0(1, "_svcrpcsec_gss: client data stale\n");
		goto error2;
	}

	(void) svc_sendreply(rqst->rq_xprt, xdr_void, NULL);
	*no_dispatch = TRUE;
	ASSERT(client_data->ref_cnt > 0);
	client_data->ref_cnt--;
	client_data->stale = TRUE;
	mutex_exit(&client_data->clm);
	return (AUTH_OK);

error2:
	ASSERT(client_data->ref_cnt > 0);
	client_data->ref_cnt--;
	client_data->stale = TRUE;
	mutex_exit(&client_data->clm);
	return (ret);
}

/*
 * Server side authentication for RPCSEC_GSS.
 */
enum auth_stat
__svcrpcsec_gss(
	struct svc_req		*rqst,
	struct rpc_msg		*msg,
	bool_t			*no_dispatch)
{
	XDR			xdrs;
	rpc_gss_creds		creds;
	struct opaque_auth	*cred;
	int			ret;

	*no_dispatch = FALSE;

	/*
	 * Initialize response verifier to NULL verifier.  If
	 * necessary, this will be changed later.
	 */
	rqst->rq_xprt->xp_verf.oa_flavor = AUTH_NONE;
	rqst->rq_xprt->xp_verf.oa_base = NULL;
	rqst->rq_xprt->xp_verf.oa_length = 0;

	/*
	 * Pull out and check credential and verifier.
	 */
	cred = &msg->rm_call.cb_cred;

	if (cred->oa_length == 0) {
		RPCGSS_LOG0(1, "_svcrpcsec_gss: zero length cred\n");
		return (AUTH_BADCRED);
	}

	xdrmem_create(&xdrs, cred->oa_base, cred->oa_length, XDR_DECODE);
	bzero((char *)&creds, sizeof (creds));
	if (!__xdr_rpc_gss_creds(&xdrs, &creds)) {
		XDR_DESTROY(&xdrs);
		RPCGSS_LOG0(1, "_svcrpcsec_gss: can't decode creds\n");
		ret = AUTH_BADCRED;
		return (AUTH_BADCRED);
	}
	XDR_DESTROY(&xdrs);

	switch (creds.gss_proc) {
	case RPCSEC_GSS_INIT:
		ret = rpcsec_gss_init(rqst, msg, creds, no_dispatch, NULL);
		break;
	case RPCSEC_GSS_CONTINUE_INIT:
		ret = rpcsec_gss_continue_init(rqst, msg, creds, no_dispatch);
		break;
	case RPCSEC_GSS_DATA:
		ret = rpcsec_gss_data(rqst, msg, creds, no_dispatch);
		break;
	case RPCSEC_GSS_DESTROY:
		ret = rpcsec_gss_destroy(rqst, creds, no_dispatch);
		break;
	default:
		cmn_err(CE_NOTE, "__svcrpcsec_gss: bad proc=%d",
		    creds.gss_proc);
		ret = AUTH_BADCRED;
	}

	if (creds.ctx_handle.length != 0)
		xdr_free(__xdr_rpc_gss_creds, (caddr_t)&creds);
	return (ret);
}

/*
 * Check verifier.  The verifier is the checksum of the RPC header
 * upto and including the credentials field.
 */

/* ARGSUSED */
static bool_t
check_verf(struct rpc_msg *msg, gss_ctx_id_t context, int *qop_state, uid_t uid)
{
	int			*buf, *tmp;
	char			hdr[128];
	struct opaque_auth	*oa;
	int			len;
	gss_buffer_desc		msg_buf;
	gss_buffer_desc		tok_buf;
	OM_uint32		gssstat, minor_stat;

	/*
	 * We have to reconstruct the RPC header from the previously
	 * parsed information, since we haven't kept the header intact.
	 */

	oa = &msg->rm_call.cb_cred;
	if (oa->oa_length > MAX_AUTH_BYTES)
		return (FALSE);

	/* 8 XDR units from the IXDR macro calls. */
	if (sizeof (hdr) < (8 * BYTES_PER_XDR_UNIT +
	    RNDUP(oa->oa_length)))
		return (FALSE);
	buf = (int *)hdr;
	IXDR_PUT_U_INT32(buf, msg->rm_xid);
	IXDR_PUT_ENUM(buf, msg->rm_direction);
	IXDR_PUT_U_INT32(buf, msg->rm_call.cb_rpcvers);
	IXDR_PUT_U_INT32(buf, msg->rm_call.cb_prog);
	IXDR_PUT_U_INT32(buf, msg->rm_call.cb_vers);
	IXDR_PUT_U_INT32(buf, msg->rm_call.cb_proc);
	IXDR_PUT_ENUM(buf, oa->oa_flavor);
	IXDR_PUT_U_INT32(buf, oa->oa_length);
	if (oa->oa_length) {
		len = RNDUP(oa->oa_length);
		tmp = buf;
		buf += len / sizeof (int);
		*(buf - 1) = 0;
		(void) bcopy(oa->oa_base, (caddr_t)tmp, oa->oa_length);
	}
	len = ((char *)buf) - hdr;
	msg_buf.length = len;
	msg_buf.value = hdr;
	oa = &msg->rm_call.cb_verf;
	tok_buf.length = oa->oa_length;
	tok_buf.value = oa->oa_base;

	gssstat = kgss_verify(&minor_stat, context, &msg_buf, &tok_buf,
	    qop_state);
	if (gssstat != GSS_S_COMPLETE) {
		RPCGSS_LOG(1, "check_verf: kgss_verify status 0x%x\n", gssstat);

		RPCGSS_LOG(4, "check_verf: msg_buf length %d\n", len);
		RPCGSS_LOG(4, "check_verf: msg_buf value 0x%x\n", *(int *)hdr);
		RPCGSS_LOG(4, "check_verf: tok_buf length %ld\n",
		    tok_buf.length);
		RPCGSS_LOG(4, "check_verf: tok_buf value 0x%p\n",
		    (void *)oa->oa_base);
		RPCGSS_LOG(4, "check_verf: context 0x%p\n", (void *)context);

		return (FALSE);
	}
	return (TRUE);
}


/*
 * Set response verifier.  This is the checksum of the given number.
 * (e.g. sequence number or sequence window)
 */
static bool_t
set_response_verf(struct svc_req *rqst, struct rpc_msg *msg,
    svc_rpc_gss_data *cl, uint_t num)
{
	OM_uint32		minor;
	gss_buffer_desc		in_buf, out_buf;
	uint_t			num_net;

	num_net = (uint_t)htonl(num);
	in_buf.length = sizeof (num);
	in_buf.value = (char *)&num_net;
/* XXX uid ? */

	if ((kgss_sign(&minor, cl->context, cl->qop, &in_buf, &out_buf))
	    != GSS_S_COMPLETE)
		return (FALSE);

	rqst->rq_xprt->xp_verf.oa_flavor = RPCSEC_GSS;
	rqst->rq_xprt->xp_verf.oa_base = msg->rm_call.cb_verf.oa_base;
	rqst->rq_xprt->xp_verf.oa_length = out_buf.length;
	bcopy(out_buf.value, rqst->rq_xprt->xp_verf.oa_base, out_buf.length);
	(void) gss_release_buffer(&minor, &out_buf);
	return (TRUE);
}

/*
 * Create client context.
 */
static svc_rpc_gss_data *
create_client()
{
	svc_rpc_gss_data	*client_data;
	static uint_t		key = 1;

	client_data = (svc_rpc_gss_data *) kmem_cache_alloc(svc_data_handle,
	    KM_SLEEP);
	if (client_data == NULL)
		return (NULL);

	/*
	 * set up client data structure
	 */
	client_data->next = NULL;
	client_data->prev = NULL;
	client_data->lru_next = NULL;
	client_data->lru_prev = NULL;
	client_data->client_name.length = 0;
	client_data->client_name.value = NULL;
	client_data->seq_num = 0;
	bzero(client_data->seq_bits, sizeof (client_data->seq_bits));
	client_data->key = 0;
	client_data->cookie = NULL;
	bzero(&client_data->u_cred, sizeof (client_data->u_cred));
	client_data->established = FALSE;
	client_data->locked = FALSE;
	client_data->u_cred_set = 0;
	client_data->context = GSS_C_NO_CONTEXT;
	client_data->expiration = GSS_C_INDEFINITE;
	client_data->deleg = GSS_C_NO_CREDENTIAL;
	client_data->ref_cnt = 1;
	client_data->last_ref_time = gethrestime_sec();
	client_data->qop = GSS_C_QOP_DEFAULT;
	client_data->done_docallback = FALSE;
	client_data->stale = FALSE;
	client_data->retrans_data = NULL;
	bzero(&client_data->raw_cred, sizeof (client_data->raw_cred));

	/*
	 * The client context handle is a 32-bit key (unsigned int).
	 * The key is incremented until there is no duplicate for it.
	 */

	svc_rpc_gss_cache_stats.total_entries_allocated++;
	mutex_enter(&ctx_mutex);
	for (;;) {
		client_data->key = key++;
		if (find_client(client_data->key) == NULL) {
			insert_client(client_data);
			mutex_exit(&ctx_mutex);
			return (client_data);
		}
	}
	/*NOTREACHED*/
}

/*
 * Insert client context into hash list and LRU list.
 */
static void
insert_client(svc_rpc_gss_data *client_data)
{
	svc_rpc_gss_data	*cl;
	int			index = HASH(client_data->key);

	ASSERT(mutex_owned(&ctx_mutex));

	client_data->prev = NULL;
	cl = clients[index];
	if ((client_data->next = cl) != NULL)
		cl->prev = client_data;
	clients[index] = client_data;

	client_data->lru_prev = NULL;
	if ((client_data->lru_next = lru_first) != NULL)
		lru_first->lru_prev = client_data;
	else
		lru_last = client_data;
	lru_first = client_data;

	num_gss_contexts++;
}

/*
 * Fetch a client, given the client context handle.  Move it to the
 * top of the LRU list since this is the most recently used context.
 */
static svc_rpc_gss_data *
get_client(gss_buffer_t ctx_handle)
{
	uint_t			key = *(uint_t *)ctx_handle->value;
	svc_rpc_gss_data	*cl;

	mutex_enter(&ctx_mutex);
	if ((cl = find_client(key)) != NULL) {
		mutex_enter(&cl->clm);
		if (cl->stale) {
			if (cl->ref_cnt == 0) {
				mutex_exit(&cl->clm);
				destroy_client(cl);
			} else {
				mutex_exit(&cl->clm);
			}
			mutex_exit(&ctx_mutex);
			return (NULL);
		}
		cl->ref_cnt++;
		cl->last_ref_time = gethrestime_sec();
		mutex_exit(&cl->clm);
		if (cl != lru_first) {
			cl->lru_prev->lru_next = cl->lru_next;
			if (cl->lru_next != NULL)
				cl->lru_next->lru_prev = cl->lru_prev;
			else
				lru_last = cl->lru_prev;
			cl->lru_prev = NULL;
			cl->lru_next = lru_first;
			lru_first->lru_prev = cl;
			lru_first = cl;
		}
	}
	mutex_exit(&ctx_mutex);
	return (cl);
}

/*
 * Given the client context handle, find the context corresponding to it.
 * Don't change its LRU state since it may not be used.
 */
static svc_rpc_gss_data *
find_client(uint_t key)
{
	int			index = HASH(key);
	svc_rpc_gss_data	*cl = NULL;

	ASSERT(mutex_owned(&ctx_mutex));

	for (cl = clients[index]; cl != NULL; cl = cl->next) {
		if (cl->key == key)
			break;
	}
	return (cl);
}

/*
 * Destroy a client context.
 */
static void
destroy_client(svc_rpc_gss_data *client_data)
{
	OM_uint32		minor;
	int			index = HASH(client_data->key);

	ASSERT(mutex_owned(&ctx_mutex));

	/*
	 * remove from hash list
	 */
	if (client_data->prev == NULL)
		clients[index] = client_data->next;
	else
		client_data->prev->next = client_data->next;
	if (client_data->next != NULL)
		client_data->next->prev = client_data->prev;

	/*
	 * remove from LRU list
	 */
	if (client_data->lru_prev == NULL)
		lru_first = client_data->lru_next;
	else
		client_data->lru_prev->lru_next = client_data->lru_next;
	if (client_data->lru_next != NULL)
		client_data->lru_next->lru_prev = client_data->lru_prev;
	else
		lru_last = client_data->lru_prev;

	/*
	 * If there is a GSS context, clean up GSS state.
	 */
	if (client_data->context != GSS_C_NO_CONTEXT) {
		(void) kgss_delete_sec_context(&minor, &client_data->context,
		    NULL);

		common_client_data_free(client_data);

		if (client_data->deleg != GSS_C_NO_CREDENTIAL) {
			(void) kgss_release_cred(&minor, &client_data->deleg,
			    crgetuid(CRED()));
		}
	}

	if (client_data->u_cred.gidlist != NULL) {
		kmem_free((char *)client_data->u_cred.gidlist,
		    client_data->u_cred.gidlen * sizeof (gid_t));
		client_data->u_cred.gidlist = NULL;
	}
	if (client_data->retrans_data != NULL)
		retrans_del(client_data);

	kmem_cache_free(svc_data_handle, client_data);
	num_gss_contexts--;
}

/*
 * Check for expired and stale client contexts.
 */
static void
sweep_clients(bool_t from_reclaim)
{
	svc_rpc_gss_data	*cl, *next;
	time_t			last_reference_needed;
	time_t			now = gethrestime_sec();

	ASSERT(mutex_owned(&ctx_mutex));

	last_reference_needed = now - (from_reclaim ?
	    svc_rpc_gss_active_delta : svc_rpc_gss_inactive_delta);

	cl = lru_last;
	while (cl) {
		/*
		 * We assume here that any manipulation of the LRU pointers
		 * and hash bucket pointers are only done when holding the
		 * ctx_mutex.
		 */
		next = cl->lru_prev;

		mutex_enter(&cl->clm);

		if ((cl->expiration != GSS_C_INDEFINITE &&
		    cl->expiration <= now) || cl->stale ||
		    cl->last_ref_time <= last_reference_needed) {

			if ((cl->expiration != GSS_C_INDEFINITE &&
			    cl->expiration <= now) || cl->stale ||
			    (cl->last_ref_time <= last_reference_needed &&
			    cl->ref_cnt == 0)) {

				cl->stale = TRUE;

				if (cl->ref_cnt == 0) {
					mutex_exit(&cl->clm);
					if (from_reclaim)
						svc_rpc_gss_cache_stats.
						    no_returned_by_reclaim++;
					destroy_client(cl);
				} else
					mutex_exit(&cl->clm);
			} else
				mutex_exit(&cl->clm);
		} else
			mutex_exit(&cl->clm);

		cl = next;
	}

	last_swept = gethrestime_sec();
}

/*
 * Encrypt the serialized arguments from xdr_func applied to xdr_ptr
 * and write the result to xdrs.
 */
static bool_t
svc_rpc_gss_wrap(SVCAUTH *auth, XDR *out_xdrs, bool_t (*xdr_func)(),
    caddr_t xdr_ptr)
{
	svc_rpc_gss_parms_t	*gss_parms = SVCAUTH_GSSPARMS(auth);
	bool_t ret;

	/*
	 * If context is not established, or if neither integrity nor
	 * privacy service is used, don't wrap - just XDR encode.
	 * Otherwise, wrap data using service and QOP parameters.
	 */
	if (!gss_parms->established || gss_parms->service == rpc_gss_svc_none)
		return ((*xdr_func)(out_xdrs, xdr_ptr));

	ret = __rpc_gss_wrap_data(gss_parms->service,
	    (OM_uint32)gss_parms->qop_rcvd,
	    (gss_ctx_id_t)gss_parms->context,
	    gss_parms->seq_num,
	    out_xdrs, xdr_func, xdr_ptr);
	return (ret);
}

/*
 * Decrypt the serialized arguments and XDR decode them.
 */
static bool_t
svc_rpc_gss_unwrap(SVCAUTH *auth, XDR *in_xdrs, bool_t (*xdr_func)(),
    caddr_t xdr_ptr)
{
	svc_rpc_gss_parms_t	*gss_parms = SVCAUTH_GSSPARMS(auth);

	/*
	 * If context is not established, or if neither integrity nor
	 * privacy service is used, don't unwrap - just XDR decode.
	 * Otherwise, unwrap data.
	 */
	if (!gss_parms->established || gss_parms->service == rpc_gss_svc_none)
		return ((*xdr_func)(in_xdrs, xdr_ptr));

	return (__rpc_gss_unwrap_data(gss_parms->service,
	    (gss_ctx_id_t)gss_parms->context,
	    gss_parms->seq_num,
	    gss_parms->qop_rcvd,
	    in_xdrs, xdr_func, xdr_ptr));
}


/* ARGSUSED */
int
rpc_gss_svc_max_data_length(struct svc_req *req, int max_tp_unit_len)
{
	return (0);
}

/*
 * Add retransmit entry to the context cache entry for a new xid.
 * If there is already an entry, delete it before adding the new one.
 */
static void retrans_add(client, xid, result)
	svc_rpc_gss_data *client;
	uint32_t	xid;
	rpc_gss_init_res *result;
{
	retrans_entry	*rdata;

	if (client->retrans_data && client->retrans_data->xid == xid)
		return;

	rdata = kmem_zalloc(sizeof (*rdata), KM_SLEEP);

	if (rdata == NULL)
		return;

	rdata->xid = xid;
	rdata->result = *result;

	if (result->token.length != 0) {
		GSS_DUP_BUFFER(rdata->result.token, result->token);
	}

	if (client->retrans_data)
		retrans_del(client);

	client->retrans_data = rdata;
}

/*
 * Delete the retransmit data from the context cache entry.
 */
static void retrans_del(client)
	svc_rpc_gss_data *client;
{
	retrans_entry *rdata;
	OM_uint32 minor_stat;

	if (client->retrans_data == NULL)
		return;

	rdata = client->retrans_data;
	if (rdata->result.token.length != 0) {
	    (void) gss_release_buffer(&minor_stat, &rdata->result.token);
	}

	kmem_free((caddr_t)rdata, sizeof (*rdata));
	client->retrans_data = NULL;
}

/*
 * This function frees the following fields of svc_rpc_gss_data:
 *	client_name, raw_cred.client_principal, raw_cred.mechanism.
 */
static void
common_client_data_free(svc_rpc_gss_data *client_data)
{
	if (client_data->client_name.length > 0) {
		(void) gss_release_buffer(NULL, &client_data->client_name);
	}

	if (client_data->raw_cred.client_principal) {
		kmem_free((caddr_t)client_data->raw_cred.client_principal,
		    client_data->raw_cred.client_principal->len +
		    sizeof (int));
		client_data->raw_cred.client_principal = NULL;
	}

	/*
	 * In the user GSS-API library, mechanism (mech_type returned
	 * by gss_accept_sec_context) is static storage, however
	 * since all the work is done for gss_accept_sec_context under
	 * gssd, what is returned in the kernel, is a copy from the oid
	 * obtained under from gssd, so need to free it when destroying
	 * the client data.
	 */

	if (client_data->raw_cred.mechanism) {
		kgss_free_oid(client_data->raw_cred.mechanism);
		client_data->raw_cred.mechanism = NULL;
	}
}
