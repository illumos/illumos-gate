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

/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Id: svc_auth_gssapi.c,v 1.19 1994/10/27 12:38:51 jik Exp $
 */

/*
 * Server side handling of RPCSEC_GSS flavor.
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <rpc/rpc.h>
#include <rpc/rpcsec_defs.h>
#include <sys/file.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <syslog.h>

/*
 * Sequence window definitions.
 */
#define	SEQ_ARR_SIZE	4
#define	SEQ_WIN		(SEQ_ARR_SIZE*32)
#define	SEQ_HI_BIT	0x80000000
#define	SEQ_LO_BIT	1
#define	DIV_BY_32	5
#define	SEQ_MASK	0x1f
#define	SEQ_MAX		0x80000000


/* cache retransmit data */
typedef struct _retrans_entry {
	uint32_t	xid;
	rpc_gss_init_res result;
	struct _retrans_entry *next, *prev;
} retrans_entry;

/*
 * Server side RPCSEC_GSS context information.
 */
typedef struct _svc_rpc_gss_data {
	struct _svc_rpc_gss_data	*next, *prev;
	struct _svc_rpc_gss_data	*lru_next, *lru_prev;
	bool_t				established;
	gss_ctx_id_t			context;
	gss_name_t			client_name;
	gss_cred_id_t			server_creds;
	uint_t				expiration;
	uint_t				seq_num;
	uint_t				seq_bits[SEQ_ARR_SIZE];
	uint_t				key;
	OM_uint32			qop;
	bool_t				done_docallback;
	bool_t				locked;
	rpc_gss_rawcred_t		raw_cred;
	rpc_gss_ucred_t			u_cred;
	bool_t				u_cred_set;
	void				*cookie;
	gss_cred_id_t			deleg;
	mutex_t				clm;
	int				ref_cnt;
	bool_t				stale;
	time_t				time_secs_set;
	retrans_entry			*retrans_data;
} svc_rpc_gss_data;

/*
 * Data structures used for LRU based context management.
 */
#define	HASHMOD			256
#define	HASHMASK		255

static svc_rpc_gss_data		*clients[HASHMOD];
static svc_rpc_gss_data		*lru_first, *lru_last;
static int			num_gss_contexts = 0;
static int			max_gss_contexts = 128;
static int			sweep_interval = 10;
static int			last_swept = 0;
static uint_t			max_lifetime = GSS_C_INDEFINITE;
static int			init_lifetime = 0;
static uint_t			gid_timeout = 43200; /* 43200 secs = 12 hours */

/*
 * lock used with context/lru variables
 */
static mutex_t			ctx_mutex = DEFAULTMUTEX;

/*
 * server credential management data and structures
 */
typedef struct svc_creds_list_s {
	struct svc_creds_list_s	*next;
	gss_cred_id_t		cred;
	gss_name_t		name;
	rpcprog_t		program;
	rpcvers_t		version;
	gss_OID_set		oid_set;
	OM_uint32		req_time;
	char			*server_name;
	mutex_t			refresh_mutex;
} svc_creds_list_t;


static svc_creds_list_t		*svc_creds_list;
static int			svc_creds_count = 0;

/*
 * lock used with server credential variables list
 *
 * server cred list locking guidelines:
 * - Writer's lock holder has exclusive access to the list
 * - Reader's lock holder(s) must also lock (refresh_mutex) each node
 *   before accessing that node's elements (ie. cred)
 */
static rwlock_t			cred_lock = DEFAULTRWLOCK;

/*
 * server callback list
 */
typedef struct cblist_s {
	struct cblist_s		*next;
	rpc_gss_callback_t	cb;
} cblist_t;

cblist_t			*cblist = NULL;

/*
 * lock used with callback variables
 */
static mutex_t			cb_mutex = DEFAULTMUTEX;

/*
 * forward declarations
 */
static bool_t			svc_rpc_gss_wrap();
static bool_t			svc_rpc_gss_unwrap();
static svc_rpc_gss_data		*create_client();
static svc_rpc_gss_data		*get_client();
static svc_rpc_gss_data		*find_client();
static void			destroy_client();
static void			sweep_clients();
static void			drop_lru_client();
static void			insert_client();
static bool_t			check_verf();
static bool_t			rpc_gss_refresh_svc_cred();
static bool_t			set_response_verf();
static void			retrans_add(svc_rpc_gss_data *, uint32_t,
					rpc_gss_init_res *);
static void			retrans_del(struct _svc_rpc_gss_data *);


/*
 * server side wrap/unwrap routines
 */
struct svc_auth_ops svc_rpc_gss_ops = {
	svc_rpc_gss_wrap,
	svc_rpc_gss_unwrap,
};

/*
 * Fetch server side authentication structure.
 */
extern SVCAUTH *__svc_get_svcauth();

/*
 * Cleanup routine for destroying context, called after service
 * procedure is executed, for MT safeness.
 */
extern void *__svc_set_proc_cleanup_cb();
static void (*old_cleanup_cb)() = NULL;
static bool_t cleanup_cb_set = FALSE;

static void
ctx_cleanup(SVCXPRT *xprt)
{
	svc_rpc_gss_data	*cl;
	SVCAUTH			*svcauth;

	if (old_cleanup_cb != NULL)
		(*old_cleanup_cb)(xprt);

	/*
	 * First check if current context needs to be cleaned up.
	 */
	svcauth = __svc_get_svcauth(xprt);
	/*LINTED*/
	if ((cl = (svc_rpc_gss_data *)svcauth->svc_ah_private) != NULL) {
		mutex_lock(&cl->clm);
		if (--cl->ref_cnt == 0 && cl->stale) {
			mutex_unlock(&cl->clm);
			mutex_lock(&ctx_mutex);
			destroy_client(cl);
			mutex_unlock(&ctx_mutex);
		} else
			mutex_unlock(&cl->clm);
	}

	/*
	 * Check for other expired contexts.
	 */
	if ((time(0) - last_swept) > sweep_interval) {
		mutex_lock(&ctx_mutex);
		/*
		 * Check again, in case some other thread got in.
		 */
		if ((time(0) - last_swept) > sweep_interval)
			sweep_clients();
		mutex_unlock(&ctx_mutex);
	}
}

/*
 * Set server parameters.
 */
void
__rpc_gss_set_server_parms(int init_cred_lifetime, int max_cred_lifetime,
    int cache_size)
{
	/*
	 * Ignore parameters unless greater than zero.
	 */
	mutex_lock(&ctx_mutex);
	if (cache_size > 0)
		max_gss_contexts = cache_size;
	if (max_cred_lifetime > 0)
		max_lifetime = (uint_t)max_cred_lifetime;
	if (init_cred_lifetime > 0)
		init_lifetime = init_cred_lifetime;
	mutex_unlock(&ctx_mutex);
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
		return (FALSE);
	}

	/*
	 * If greater than the last seen sequence number, just shift
	 * the sequence window so that it starts at the new sequence
	 * number and extends downwards by SEQ_WIN.
	 */
	if (seq_num > cl->seq_num) {
		shift_bits(cl->seq_bits, SEQ_ARR_SIZE, seq_num - cl->seq_num);
		cl->seq_bits[0] |= SEQ_HI_BIT;
		cl->seq_num = seq_num;
		return (TRUE);
	}

	/*
	 * If it is outside the sequence window, return failure.
	 */
	i = cl->seq_num - seq_num;
	if (i >= SEQ_WIN)
		return (FALSE);

	/*
	 * If within sequence window, set the bit corresponding to it
	 * if not already seen;  if already seen, return failure.
	 */
	j = SEQ_MASK - (i & SEQ_MASK);
	bit = j > 0 ? (1 << j) : 1;
	i >>= DIV_BY_32;
	if (cl->seq_bits[i] & bit)
		return (FALSE);
	cl->seq_bits[i] |= bit;
	return (TRUE);
}

/*
 * Convert a name in gss exported type to rpc_gss_principal_t type.
 */
static bool_t
__rpc_gss_make_principal(rpc_gss_principal_t *principal, gss_buffer_desc *name)
{
	int			plen;
	char			*s;

	plen = RNDUP(name->length) + sizeof (int);
	(*principal) = (rpc_gss_principal_t)malloc(plen);
	if ((*principal) == NULL)
		return (FALSE);
	bzero((caddr_t)(*principal), plen);
	(*principal)->len = RNDUP(name->length);
	s = (*principal)->name;
	memcpy(s, name->value, name->length);
	return (TRUE);
}

/*
 * Convert a name in internal form to the exported type.
 */
static bool_t
set_client_principal(gss_name_t g_name, rpc_gss_principal_t *r_name)
{
	gss_buffer_desc		name;
	OM_uint32		major, minor;
	bool_t			ret = FALSE;

	major = gss_export_name(&minor, g_name, &name);
	if (major != GSS_S_COMPLETE)
		return (FALSE);
	ret = __rpc_gss_make_principal(r_name, &name);
	(void) gss_release_buffer(&minor, &name);
	return (ret);
}

/*
 * Set server callback.
 */
bool_t
__rpc_gss_set_callback(rpc_gss_callback_t *cb)
{
	cblist_t		*cbl;

	if (cb->callback == NULL)
		return (FALSE);
	if ((cbl = (cblist_t *)malloc(sizeof (*cbl))) == NULL)
		return (FALSE);
	cbl->cb = *cb;
	mutex_lock(&cb_mutex);
	cbl->next = cblist;
	cblist = cbl;
	mutex_unlock(&cb_mutex);
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
	cblist_t		*cbl;
	bool_t			ret = TRUE, found = FALSE;
	rpc_gss_lock_t		lock;
	OM_uint32		minor;

	mutex_lock(&cb_mutex);
	for (cbl = cblist; cbl != NULL; cbl = cbl->next) {
		if (req->rq_prog != cbl->cb.program ||
		    req->rq_vers != cbl->cb.version)
			continue;
		found = TRUE;
		lock.locked = FALSE;
		lock.raw_cred = &client_data->raw_cred;
		ret = (*cbl->cb.callback)(req, client_data->deleg,
		    client_data->context, &lock, &client_data->cookie);
		if (ret) {
			client_data->locked = lock.locked;
			client_data->deleg = GSS_C_NO_CREDENTIAL;
		}
		break;
	}
	if (!found) {
		if (client_data->deleg != GSS_C_NO_CREDENTIAL) {
			(void) gss_release_cred(&minor, &client_data->deleg);
			client_data->deleg = GSS_C_NO_CREDENTIAL;
		}
	}
	mutex_unlock(&cb_mutex);
	return (ret);
}

/*
 * Return caller credentials.
 */
bool_t
__rpc_gss_getcred(struct svc_req *req, rpc_gss_rawcred_t **rcred,
    rpc_gss_ucred_t **ucred, void **cookie)
{
	SVCAUTH			*svcauth;
	svc_rpc_gss_data	*client_data;
	svc_rpc_gss_parms_t	*gss_parms;
	gss_OID			oid;
	OM_uint32		status;
	int			len = 0;
	struct timeval		now;

	svcauth = __svc_get_svcauth(req->rq_xprt);
	/*LINTED*/
	client_data = (svc_rpc_gss_data *)svcauth->svc_ah_private;
	gss_parms = &svcauth->svc_gss_parms;

	mutex_lock(&client_data->clm);

	if (rcred != NULL) {
		svcauth->raw_cred = client_data->raw_cred;
		svcauth->raw_cred.service = gss_parms->service;
		svcauth->raw_cred.qop = __rpc_gss_num_to_qop(
		    svcauth->raw_cred.mechanism, gss_parms->qop_rcvd);
		*rcred = &svcauth->raw_cred;
	}
	if (ucred != NULL) {
		if (!client_data->u_cred_set) {
			/*
			 * Double check making sure ucred is not set
			 * after acquiring the lock.
			 */
			if (!client_data->u_cred_set) {
				if (!__rpc_gss_mech_to_oid(
				    (*rcred)->mechanism, &oid)) {
					fprintf(stderr, dgettext(TEXT_DOMAIN,
					    "mech_to_oid failed in "
					    "getcred.\n"));
					*ucred = NULL;
				} else {
					status = gsscred_name_to_unix_cred(
					    client_data->client_name, oid,
					    &client_data->u_cred.uid,
					    &client_data->u_cred.gid,
					    &client_data->u_cred.gidlist,
					    &len);
					if (status == GSS_S_COMPLETE) {
						client_data->u_cred_set = TRUE;
						client_data->u_cred.gidlen =
						    (short)len;
						gettimeofday(&now, NULL);
						client_data->time_secs_set =
						    now.tv_sec;
						*ucred = &client_data->u_cred;
					} else
						*ucred = NULL;
				}
			}
		} else {
			/*
			 * gid's already set;
			 * check if they have expired.
			 */
			gettimeofday(&now, NULL);
			if ((now.tv_sec - client_data->time_secs_set)
			    > gid_timeout) {
				/* Refresh gid's */
				status = gss_get_group_info(
				    client_data->u_cred.uid,
				    &client_data->u_cred.gid,
				    &client_data->u_cred.gidlist,
				    &len);
				if (status == GSS_S_COMPLETE) {
					client_data->u_cred.gidlen =
					    (short)len;
					gettimeofday(&now, NULL);
					client_data->time_secs_set = now.tv_sec;
					*ucred = &client_data->u_cred;
				} else {
					client_data->u_cred_set = FALSE;
					*ucred = NULL;
				}
			}
			else
				*ucred = &client_data->u_cred;
		}
	}
	if (cookie != NULL)
		*cookie = client_data->cookie;

	mutex_unlock(&client_data->clm);

	return (TRUE);
}

/*
 * Server side authentication for RPCSEC_GSS.
 */

enum auth_stat
__svcrpcsec_gss(struct svc_req *rqst, struct rpc_msg *msg, bool_t *no_dispatch)
{
	XDR			xdrs;
	rpc_gss_creds		creds;
	rpc_gss_init_arg	call_arg;
	rpc_gss_init_res	call_res, *retrans_result;
	gss_buffer_desc		output_token;
	OM_uint32		gssstat, minor_stat, time_rec, ret_flags;
	struct opaque_auth	*cred;
	svc_rpc_gss_data	*client_data;
	int			ret;
	svc_creds_list_t	*sc;
	SVCAUTH			*svcauth;
	svc_rpc_gss_parms_t	*gss_parms;
	gss_OID			mech_type = GSS_C_NULL_OID;

	/*
	 * Initialize response verifier to NULL verifier.  If
	 * necessary, this will be changed later.
	 */
	rqst->rq_xprt->xp_verf.oa_flavor = AUTH_NONE;
	rqst->rq_xprt->xp_verf.oa_base = NULL;
	rqst->rq_xprt->xp_verf.oa_length = 0;
	/*
	 * Need to null out results to start with.
	 */
	memset((char *)&call_res, 0, sizeof (call_res));

	/*
	 * Pull out and check credential and verifier.
	 */
	cred = &msg->rm_call.cb_cred;
	if (cred->oa_length == 0) {
		return (AUTH_BADCRED);
	}

	xdrmem_create(&xdrs, cred->oa_base, cred->oa_length, XDR_DECODE);

	memset((char *)&creds, 0, sizeof (creds));
	if (!__xdr_rpc_gss_creds(&xdrs, &creds)) {
		XDR_DESTROY(&xdrs);
		ret = AUTH_BADCRED;
		goto error;
	}
	XDR_DESTROY(&xdrs);

	/*
	 * If this is a control message and proc is GSSAPI_INIT, then
	 * create a client handle for this client.  Otherwise, look up
	 * the existing handle.
	 */
	if (creds.gss_proc == RPCSEC_GSS_INIT) {
		if (creds.ctx_handle.length != 0) {
			ret = AUTH_BADCRED;
			goto error;
		}
		if ((client_data = create_client()) == NULL) {
			ret = AUTH_FAILED;
			goto error;
		}
	} else {
		/*
		 * Only verify values for service parameter when proc
		 * not RPCSEC_GSS_INIT or RPCSEC_GSS_CONTINUE_INIT.
		 * RFC2203 says contents for sequence and service args
		 * are undefined for creation procs.
		 *
		 * Note: only need to check for *CONTINUE_INIT here because
		 *	if() clause already checked for RPCSEC_GSS_INIT
		 */
		if (creds.gss_proc != RPCSEC_GSS_CONTINUE_INIT) {
			switch (creds.service) {
			case rpc_gss_svc_none:
			case rpc_gss_svc_integrity:
			case rpc_gss_svc_privacy:
				break;
			default:
				ret = AUTH_BADCRED;
				goto error;
			}
		}
		if (creds.ctx_handle.length == 0) {
			ret = AUTH_BADCRED;
			goto error;
		}
		if ((client_data = get_client(&creds.ctx_handle)) == NULL) {
			ret = RPCSEC_GSS_NOCRED;
			goto error;
		}
	}

	/*
	 * lock the client data until it's safe; if it's already stale,
	 * no more processing is possible
	 */
	mutex_lock(&client_data->clm);
	if (client_data->stale) {
		ret = RPCSEC_GSS_NOCRED;
		goto error2;
	}

	/*
	 * Any response we send will use ctx_handle, so set it now;
	 * also set seq_window since this won't change.
	 */
	call_res.ctx_handle.length = sizeof (client_data->key);
	call_res.ctx_handle.value = (char *)&client_data->key;
	call_res.seq_window = SEQ_WIN;

	/*
	 * Set the appropriate wrap/unwrap routine for RPCSEC_GSS.
	 */
	svcauth = __svc_get_svcauth(rqst->rq_xprt);
	svcauth->svc_ah_ops = svc_rpc_gss_ops;
	svcauth->svc_ah_private = (caddr_t)client_data;

	/*
	 * Keep copy of parameters we'll need for response, for the
	 * sake of reentrancy (we don't want to look in the context
	 * data because when we are sending a response, another
	 * request may have come in.
	 */
	gss_parms = &svcauth->svc_gss_parms;
	gss_parms->established = client_data->established;
	gss_parms->service = creds.service;
	gss_parms->qop_rcvd = (uint_t)client_data->qop;
	gss_parms->context = (void *)client_data->context;
	gss_parms->seq_num = creds.seq_num;

	if (!client_data->established) {
		if (creds.gss_proc == RPCSEC_GSS_DATA) {
			ret = RPCSEC_GSS_FAILED;
			client_data->stale = TRUE;
			goto error2;
		}

		/*
		 * If the context is not established, then only GSSAPI_INIT
		 * and _CONTINUE requests are valid.
		 */
		if (creds.gss_proc != RPCSEC_GSS_INIT && creds.gss_proc !=
		    RPCSEC_GSS_CONTINUE_INIT) {
			ret = RPCSEC_GSS_FAILED;
			client_data->stale = TRUE;
			goto error2;
		}

		/*
		 * call is for us, deserialize arguments
		 */
		memset(&call_arg, 0, sizeof (call_arg));
		if (!svc_getargs(rqst->rq_xprt, __xdr_rpc_gss_init_arg,
		    (caddr_t)&call_arg)) {
			ret = RPCSEC_GSS_FAILED;
			client_data->stale = TRUE;
			goto error2;
		}

		gssstat = GSS_S_FAILURE;
		minor_stat = 0;
		rw_rdlock(&cred_lock);
		/*
		 * set next sc to point to the server cred
		 * if the  client_data contains server_creds
		 */
		for (sc = svc_creds_list; sc != NULL; sc = sc->next) {
			if (rqst->rq_prog != sc->program ||
			    rqst->rq_vers != sc->version)
				continue;

			mutex_lock(&sc->refresh_mutex);
			gssstat = gss_accept_sec_context(&minor_stat,
			    &client_data->context,
			    sc->cred,
			    &call_arg,
			    GSS_C_NO_CHANNEL_BINDINGS,
			    &client_data->client_name,
			    &mech_type,
			    &output_token,
			    &ret_flags,
			    &time_rec,
			    NULL);

			if (gssstat == GSS_S_CREDENTIALS_EXPIRED) {
				if (rpc_gss_refresh_svc_cred(sc)) {
					gssstat = gss_accept_sec_context(
					    &minor_stat,
					    &client_data->context,
					    sc->cred,
					    &call_arg,
					    GSS_C_NO_CHANNEL_BINDINGS,
					    &client_data->client_name,
					    &mech_type,
					    &output_token,
					    &ret_flags,
					    &time_rec,
					    NULL);
					mutex_unlock(&sc->refresh_mutex);

				} else {
					mutex_unlock(&sc->refresh_mutex);
					gssstat = GSS_S_NO_CRED;
					break;
				}

			} else
				mutex_unlock(&sc->refresh_mutex);

			if (gssstat == GSS_S_COMPLETE) {
				/*
				 * Server_creds was right - set it.  Also
				 * set the raw and unix credentials at this
				 * point.  This saves a lot of computation
				 * later when credentials are retrieved.
				 */
				/*
				 * XXX server_creds will prob be stale
				 * after rpc_gss_refresh_svc_cred(), but
				 * it appears not to ever be referenced
				 * anyways.
				 */
				mutex_lock(&sc->refresh_mutex);
				client_data->server_creds = sc->cred;
				client_data->raw_cred.version = creds.version;
				client_data->raw_cred.service = creds.service;
				client_data->raw_cred.svc_principal =
				    sc->server_name;
				mutex_unlock(&sc->refresh_mutex);

				if ((client_data->raw_cred.mechanism
				    = __rpc_gss_oid_to_mech(mech_type))
				    == NULL) {
					gssstat = GSS_S_FAILURE;
					(void) gss_release_buffer(&minor_stat,
					    &output_token);
				} else if (!set_client_principal(client_data->
				    client_name, &client_data->
				    raw_cred.client_principal)) {
					gssstat = GSS_S_FAILURE;
					(void) gss_release_buffer(&minor_stat,
					    &output_token);
				}
				break;
			}

			if (gssstat == GSS_S_CONTINUE_NEEDED) {
				/*
				 * XXX server_creds will prob be stale
				 * after rpc_gss_refresh_svc_cred(), but
				 * it appears not to ever be referenced
				 * anyways.
				 */
				mutex_lock(&sc->refresh_mutex);
				client_data->server_creds = sc->cred;
				mutex_unlock(&sc->refresh_mutex);
				break;
			}

		}
		rw_unlock(&cred_lock);

		call_res.gss_major = gssstat;
		call_res.gss_minor = minor_stat;

		xdr_free(__xdr_rpc_gss_init_arg, (caddr_t)&call_arg);

		if (gssstat != GSS_S_COMPLETE &&
		    gssstat != GSS_S_CONTINUE_NEEDED) {
			/*
			 * We have a failure - send response and delete
			 * the context.  Don't dispatch. Set ctx_handle
			 * to NULL and seq_window to 0.
			 */
			call_res.ctx_handle.length = 0;
			call_res.ctx_handle.value = NULL;
			call_res.seq_window = 0;

			svc_sendreply(rqst->rq_xprt, __xdr_rpc_gss_init_res,
			    (caddr_t)&call_res);
			*no_dispatch = TRUE;
			ret = AUTH_OK;
			client_data->stale = TRUE;
			goto error2;
		}

		/*
		 * This step succeeded.  Send a response, along with
		 * a token if there's one.  Don't dispatch.
		 */
		if (output_token.length != 0) {
			GSS_COPY_BUFFER(call_res.token, output_token);
		}

		/*
		 * set response verifier: checksum of SEQ_WIN
		 */
		if (gssstat == GSS_S_COMPLETE) {
			if (!set_response_verf(rqst, msg, client_data,
			    (uint_t)SEQ_WIN)) {
				ret = RPCSEC_GSS_FAILED;
				client_data->stale = TRUE;
				(void) gss_release_buffer(&minor_stat,
				    &output_token);
				goto error2;
			}
		}

		svc_sendreply(rqst->rq_xprt, __xdr_rpc_gss_init_res,
		    (caddr_t)&call_res);
		/*
		 * Cache last response in case it is lost and the client
		 * retries on an established context.
		 */
		(void) retrans_add(client_data, msg->rm_xid, &call_res);
		*no_dispatch = TRUE;
		(void) gss_release_buffer(&minor_stat, &output_token);

		/*
		 * If appropriate, set established to TRUE *after* sending
		 * response (otherwise, the client will receive the final
		 * token encrypted)
		 */
		if (gssstat == GSS_S_COMPLETE) {
			/*
			 * Context is established.  Set expiry time for
			 * context (the minimum of time_rec and max_lifetime).
			 */
			client_data->seq_num = 1;
			if (time_rec == GSS_C_INDEFINITE) {
				if (max_lifetime != GSS_C_INDEFINITE) {
					client_data->expiration =
					    max_lifetime + time(0);
				} else {
					client_data->expiration =
					    GSS_C_INDEFINITE;
				}
			} else if (max_lifetime == GSS_C_INDEFINITE ||
			    max_lifetime > time_rec) {
				client_data->expiration = time_rec + time(0);
			} else {
				client_data->expiration = max_lifetime +
				    time(0);
			}
			client_data->established = TRUE;
		}

	} else {
		if ((creds.gss_proc != RPCSEC_GSS_DATA) &&
		    (creds.gss_proc != RPCSEC_GSS_DESTROY)) {

			switch (creds.gss_proc) {

			case RPCSEC_GSS_CONTINUE_INIT:
				/*
				 * This is an established context. Continue to
				 * satisfy retried continue init requests out of
				 * the retransmit cache.  Throw away any that
				 * don't have a matching xid or the cach is
				 * empty. Delete the retransmit cache once the
				 * client sends a data request.
				 */
				if (client_data->retrans_data &&
				    (client_data->retrans_data->xid ==
				    msg->rm_xid)) {

					retrans_result =
					    &client_data->retrans_data->result;
					if (set_response_verf(rqst, msg,
					    client_data, (uint_t)
					    retrans_result->seq_window)) {

						gss_parms->established = FALSE;
						svc_sendreply(rqst->rq_xprt,
						    __xdr_rpc_gss_init_res,
						    (caddr_t)retrans_result);
						*no_dispatch = TRUE;
						goto success;
					}
				}
				/* FALLTHROUGH */

			default:
				syslog(LOG_ERR, "_svcrpcsec_gss: non-data "
				    "request on an established context");
				ret = AUTH_FAILED;
				goto error2;
			}
		}

		/*
		 * Once the context is established and there is no more
		 * retransmission of last continue init request, it is safe
		 * to delete the retransmit cache entry.
		 */
		if (client_data->retrans_data)
			retrans_del(client_data);

		/*
		 * Context is already established.  Check verifier, and
		 * note parameters we will need for response in gss_parms.
		 */
		if (!check_verf(msg, client_data->context,
		    &gss_parms->qop_rcvd)) {
			ret = RPCSEC_GSS_NOCRED;
			goto error2;
		}
		/*
		 *  Check and invoke callback if necessary.
		 */
		if (!client_data->done_docallback) {
			client_data->done_docallback = TRUE;
			client_data->qop = gss_parms->qop_rcvd;
			client_data->raw_cred.qop = __rpc_gss_num_to_qop(
			    client_data->raw_cred.mechanism,
			    gss_parms->qop_rcvd);
			client_data->raw_cred.service = creds.service;
			if (!do_callback(rqst, client_data)) {
				ret = AUTH_FAILED;
				client_data->stale = TRUE;
				goto error2;
			}
		}

		/*
		 * If the context was locked, make sure that the client
		 * has not changed QOP.
		 */
		if (client_data->locked &&
		    gss_parms->qop_rcvd != client_data->qop) {
			ret = AUTH_BADVERF;
			goto error2;
		}

		/*
		 * Validate sequence number.
		 */
		if (!check_seq(client_data, creds.seq_num,
		    &client_data->stale)) {
			if (client_data->stale)
				ret = RPCSEC_GSS_FAILED;
			else {
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
			goto error2;
		}

		/*
		 * If this is a control message RPCSEC_GSS_DESTROY, process
		 * the call; otherwise, return AUTH_OK so it will be
		 * dispatched to the application server.
		 */
		if (creds.gss_proc == RPCSEC_GSS_DESTROY) {
			svc_sendreply(rqst->rq_xprt, xdr_void, NULL);
			*no_dispatch = TRUE;
			client_data->stale = TRUE;

		} else {
			/*
			 * This should be an RPCSEC_GSS_DATA request.
			 * If context is locked, make sure that the client
			 * has not changed the security service.
			 */
			if (client_data->locked &&
			    client_data->raw_cred.service != creds.service) {
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
		}
	}

success:
	/*
	 * Success.
	 */
	if (creds.ctx_handle.length != 0)
		xdr_free(__xdr_rpc_gss_creds, (caddr_t)&creds);
	mutex_unlock(&client_data->clm);
	return (AUTH_OK);
error2:
	mutex_unlock(&client_data->clm);
error:
	/*
	 * Failure.
	 */
	if (creds.ctx_handle.length != 0)
		xdr_free(__xdr_rpc_gss_creds, (caddr_t)&creds);
	return (ret);
}

/*
 * Check verifier.  The verifier is the checksum of the RPC header
 * upto and including the credentials field.
 */
static bool_t
check_verf(struct rpc_msg *msg, gss_ctx_id_t context, int *qop_state)
{
	int			*buf, *tmp;
	int			hdr[32];
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
	if (sizeof (hdr) < (8 * BYTES_PER_XDR_UNIT + RNDUP(oa->oa_length)))
		return (FALSE);
	buf = hdr;

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
		(void) memcpy((caddr_t)tmp, oa->oa_base, oa->oa_length);
	}
	len = ((char *)buf) - (char *)hdr;
	msg_buf.length = len;
	msg_buf.value = (char *)hdr;
	oa = &msg->rm_call.cb_verf;
	tok_buf.length = oa->oa_length;
	tok_buf.value = oa->oa_base;

	gssstat = gss_verify(&minor_stat, context, &msg_buf, &tok_buf,
	    qop_state);
	if (gssstat != GSS_S_COMPLETE)
		return (FALSE);
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
	if (gss_sign(&minor, cl->context, cl->qop, &in_buf,
	    &out_buf) != GSS_S_COMPLETE)
		return (FALSE);
	rqst->rq_xprt->xp_verf.oa_flavor = RPCSEC_GSS;
	rqst->rq_xprt->xp_verf.oa_base = msg->rm_call.cb_verf.oa_base;
	rqst->rq_xprt->xp_verf.oa_length = out_buf.length;
	memcpy(rqst->rq_xprt->xp_verf.oa_base, out_buf.value,
	    out_buf.length);
	(void) gss_release_buffer(&minor, &out_buf);
	return (TRUE);
}

/*
 * Create client context.
 */
static svc_rpc_gss_data *
create_client(void)
{
	svc_rpc_gss_data	*client_data;
	static uint_t		key = 1;

	client_data = (svc_rpc_gss_data *) malloc(sizeof (*client_data));
	if (client_data == NULL)
		return (NULL);
	memset((char *)client_data, 0, sizeof (*client_data));

	/*
	 * set up client data structure
	 */
	client_data->established = FALSE;
	client_data->locked = FALSE;
	client_data->u_cred_set = FALSE;
	client_data->context = GSS_C_NO_CONTEXT;
	client_data->expiration = init_lifetime + time(0);
	client_data->ref_cnt = 1;
	client_data->qop = GSS_C_QOP_DEFAULT;
	client_data->done_docallback = FALSE;
	client_data->stale = FALSE;
	client_data->time_secs_set = 0;
	client_data->retrans_data = NULL;
	mutex_init(&client_data->clm, USYNC_THREAD, NULL);
	/*
	 * Check totals.  If we've hit the limit, we destroy a context
	 * based on LRU method.
	 */
	mutex_lock(&ctx_mutex);
	if (num_gss_contexts >= max_gss_contexts) {
		/*
		 * now try on LRU basis
		 */
		drop_lru_client();
		if (num_gss_contexts >= max_gss_contexts) {
			mutex_unlock(&ctx_mutex);
			free((char *)client_data);
			return (NULL);
		}
	}

	/*
	 * The client context handle is a 32-bit key (unsigned int).
	 * The key is incremented until there is no duplicate for it.
	 */
	for (;;) {
		client_data->key = key++;
		if (find_client(client_data->key) == NULL) {
			insert_client(client_data);
			/*
			 * Set cleanup callback if we haven't.
			 */
			if (!cleanup_cb_set) {
				old_cleanup_cb =
				    (void (*)()) __svc_set_proc_cleanup_cb(
				    (void *)ctx_cleanup);
				cleanup_cb_set = TRUE;
			}
			mutex_unlock(&ctx_mutex);
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
	int			index = (client_data->key & HASHMASK);

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

	mutex_lock(&ctx_mutex);
	if ((cl = find_client(key)) != NULL) {
		mutex_lock(&cl->clm);
		if (cl->stale) {
			mutex_unlock(&cl->clm);
			mutex_unlock(&ctx_mutex);
			return (NULL);
		}
		cl->ref_cnt++;
		mutex_unlock(&cl->clm);
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
	mutex_unlock(&ctx_mutex);
	return (cl);
}

/*
 * Given the client context handle, find the context corresponding to it.
 * Don't change its LRU state since it may not be used.
 */
static svc_rpc_gss_data *
find_client(uint_t key)
{
	int			index = (key & HASHMASK);
	svc_rpc_gss_data	*cl;

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
	int			index = (client_data->key & HASHMASK);

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
		(void) gss_delete_sec_context(&minor, &client_data->context,
		    NULL);
		if (client_data->client_name) {
			(void) gss_release_name(&minor,
			    &client_data->client_name);
		}
		free(client_data->raw_cred.client_principal);
		free(client_data->u_cred.gidlist);
		if (client_data->deleg != GSS_C_NO_CREDENTIAL)
			(void) gss_release_cred(&minor, &client_data->deleg);
	}

	if (client_data->retrans_data != NULL)
		retrans_del(client_data);

	free(client_data);
	num_gss_contexts--;
}

/*
 * Check for expired client contexts.
 */
static void
sweep_clients(void)
{
	svc_rpc_gss_data	*cl, *next;
	int			index;

	for (index = 0; index < HASHMOD; index++) {
		cl = clients[index];
		while (cl) {
			next = cl->next;
			mutex_lock(&cl->clm);
			if ((cl->expiration != GSS_C_INDEFINITE &&
			    cl->expiration <= time(0)) || cl->stale) {
				cl->stale = TRUE;
				if (cl->ref_cnt == 0) {
					mutex_unlock(&cl->clm);
					destroy_client(cl);
				} else
					mutex_unlock(&cl->clm);
			} else
				mutex_unlock(&cl->clm);
			cl = next;
		}
	}
	last_swept = time(0);
}

/*
 * Drop the least recently used client context, if possible.
 */
static void
drop_lru_client(void)
{
	mutex_lock(&lru_last->clm);
	lru_last->stale = TRUE;
	mutex_unlock(&lru_last->clm);
	if (lru_last->ref_cnt == 0)
		destroy_client(lru_last);
	else
		sweep_clients();
}

/*
 * find service credentials
 * return cred if found,
 * other wise, NULL
 */
svc_creds_list_t *
find_svc_cred(char *service_name, uint_t program, uint_t version)
{

	svc_creds_list_t	*sc;

	if (!svc_creds_list)
		return (NULL);

	for (sc = svc_creds_list; sc != NULL; sc = sc->next) {
		if (program != sc->program || version != sc->version)
			continue;

		if (strcmp(service_name, sc->server_name) != 0)
			continue;
		return (sc);
	}
	return (NULL);
}

/*
 * Set the server principal name.
 */
bool_t
__rpc_gss_set_svc_name(char *server_name, char *mech, OM_uint32 req_time,
    uint_t program, uint_t version)
{
	gss_name_t		name;
	svc_creds_list_t	*svc_cred;
	gss_OID			mechanism;
	gss_OID_set_desc	oid_set_desc;
	gss_OID_set		oid_set;
	OM_uint32		ret_time;
	OM_uint32		major, minor;
	gss_buffer_desc		name_buf;

	if (!__rpc_gss_mech_to_oid(mech, &mechanism)) {
		return (FALSE);
	}

	name_buf.value = server_name;
	name_buf.length = strlen(server_name);
	major = gss_import_name(&minor, &name_buf,
	    (gss_OID) GSS_C_NT_HOSTBASED_SERVICE, &name);
	if (major != GSS_S_COMPLETE) {
		return (FALSE);
	}

	/* Check if there is already an entry in the svc_creds_list. */
	rw_wrlock(&cred_lock);
	if (svc_cred = find_svc_cred(server_name, program, version)) {

		major = gss_add_cred(&minor, svc_cred->cred, name,
		    mechanism, GSS_C_ACCEPT, 0, req_time, NULL,
		    &oid_set, NULL, &ret_time);
		(void) gss_release_name(&minor, &name);
		if (major == GSS_S_COMPLETE) {
			/*
			 * Successfully added the mech to the cred handle
			 * free the existing oid_set in svc_cred
			 */
			gss_release_oid_set(&minor, &svc_cred->oid_set);
			svc_cred->oid_set = oid_set;
			rw_unlock(&cred_lock);
			return (TRUE);
		} else if (major == GSS_S_DUPLICATE_ELEMENT) {
			rw_unlock(&cred_lock);
			return (TRUE);
		} else if (major == GSS_S_CREDENTIALS_EXPIRED) {
			if (rpc_gss_refresh_svc_cred(svc_cred)) {
				rw_unlock(&cred_lock);
				return (TRUE);
			} else {
				rw_unlock(&cred_lock);
				return (FALSE);
			}
		} else {
			rw_unlock(&cred_lock);
			return (FALSE);
		}
	} else {
		svc_cred = (svc_creds_list_t *)malloc(sizeof (*svc_cred));
		if (svc_cred == NULL) {
			(void) gss_release_name(&minor, &name);
			rw_unlock(&cred_lock);
			return (FALSE);
		}
		oid_set_desc.count = 1;
		oid_set_desc.elements = mechanism;
		major = gss_acquire_cred(&minor, name, req_time, &oid_set_desc,
		    GSS_C_ACCEPT, &svc_cred->cred, &oid_set, &ret_time);

		if (major != GSS_S_COMPLETE) {
			(void) gss_release_name(&minor, &name);
			free(svc_cred);
			rw_unlock(&cred_lock);
			return (FALSE);
		}

		svc_cred->name = name;
		svc_cred->program = program;
		svc_cred->version = version;
		svc_cred->req_time = req_time;
		svc_cred->oid_set = oid_set;
		svc_cred->server_name = strdup(server_name);
		if (svc_cred->server_name == NULL) {
			(void) gss_release_name(&minor, &name);
			free((char *)svc_cred);
			rw_unlock(&cred_lock);
			return (FALSE);
		}
		mutex_init(&svc_cred->refresh_mutex, USYNC_THREAD, NULL);

		svc_cred->next = svc_creds_list;
		svc_creds_list = svc_cred;
		svc_creds_count++;
		rw_unlock(&cred_lock);

		return (TRUE);
	}
}
/*
 * Refresh server credentials.
 */
static bool_t
rpc_gss_refresh_svc_cred(svc_creds_list_t *svc_cred)
{
	OM_uint32		major, minor;
	gss_OID_set		oid_set;
	OM_uint32		ret_time;

	(void) gss_release_cred(&minor, &svc_cred->cred);
	svc_cred->cred = GSS_C_NO_CREDENTIAL;
	major = gss_acquire_cred(&minor, svc_cred->name, svc_cred->req_time,
	    svc_cred->oid_set, GSS_C_ACCEPT, &svc_cred->cred, &oid_set,
	    &ret_time);
	if (major != GSS_S_COMPLETE) {
		return (FALSE);
	}
	gss_release_oid_set(&minor, &svc_cred->oid_set);
	svc_cred->oid_set = oid_set;
	return (TRUE);
}

/*
 * Encrypt the serialized arguments from xdr_func applied to xdr_ptr
 * and write the result to xdrs.
 */
static bool_t
svc_rpc_gss_wrap(SVCAUTH *auth, XDR *out_xdrs, bool_t (*xdr_func)(),
    caddr_t xdr_ptr)
{
	svc_rpc_gss_parms_t	*gss_parms = &auth->svc_gss_parms;

	/*
	 * If context is not established, or if neither integrity nor
	 * privacy service is used, don't wrap - just XDR encode.
	 * Otherwise, wrap data using service and QOP parameters.
	 */
	if (!gss_parms->established || gss_parms->service == rpc_gss_svc_none)
		return ((*xdr_func)(out_xdrs, xdr_ptr));

	return (__rpc_gss_wrap_data(gss_parms->service,
	    (OM_uint32)gss_parms->qop_rcvd,
	    (gss_ctx_id_t)gss_parms->context,
	    gss_parms->seq_num,
	    out_xdrs, xdr_func, xdr_ptr));
}

/*
 * Decrypt the serialized arguments and XDR decode them.
 */
static bool_t
svc_rpc_gss_unwrap(SVCAUTH *auth, XDR *in_xdrs, bool_t (*xdr_func)(),
    caddr_t xdr_ptr)
{
	svc_rpc_gss_parms_t	*gss_parms = &auth->svc_gss_parms;

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

int
__rpc_gss_svc_max_data_length(struct svc_req *req, int max_tp_unit_len)
{
	SVCAUTH			*svcauth;
	svc_rpc_gss_parms_t	*gss_parms;

	svcauth = __svc_get_svcauth(req->rq_xprt);
	gss_parms = &svcauth->svc_gss_parms;

	if (!gss_parms->established || max_tp_unit_len <= 0)
		return (0);

	return (__find_max_data_length(gss_parms->service,
	    (gss_ctx_id_t)gss_parms->context,
	    gss_parms->qop_rcvd, max_tp_unit_len));
}

/*
 * Add retransmit entry to the context cache entry for a new xid.
 * If there is already an entry, delete it before adding the new one.
 */
static void retrans_add(svc_rpc_gss_data *client, uint32_t xid,
    rpc_gss_init_res *result)
{
	retrans_entry	*rdata;

	if (client->retrans_data && client->retrans_data->xid == xid)
		return;

	rdata = (retrans_entry *) malloc(sizeof (*rdata));
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
static void retrans_del(svc_rpc_gss_data *client)
{
	retrans_entry *rdata;
	OM_uint32 minor_stat;

	if (client->retrans_data == NULL)
		return;

	rdata = client->retrans_data;
	if (rdata->result.token.length != 0) {
		(void) gss_release_buffer(&minor_stat, &rdata->result.token);
	}

	free((caddr_t)rdata);
	client->retrans_data = NULL;
}
