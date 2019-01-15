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
 * Copyright (c) 2018, Joyent, Inc.
 */

/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Header:
 * /afs/gza.com/product/secure/rel-eng/src/1.1/rpc/RCS/auth_gssapi.c,v
 * 1.14 1995/03/22 22:07:55 jik Exp $
 */

#include  <sys/systm.h>
#include  <sys/types.h>
#include  <gssapi/gssapi.h>
#include  <rpc/rpc.h>
#include  <rpc/rpcsec_defs.h>
#include  <sys/debug.h>
#include  <sys/cmn_err.h>
#include  <sys/ddi.h>

static	void	rpc_gss_nextverf();
static	bool_t	rpc_gss_marshall();
static	bool_t	rpc_gss_validate();
static	bool_t	rpc_gss_refresh();
static	void	rpc_gss_destroy();
#if 0
static	void	rpc_gss_destroy_pvt();
#endif
static	void	rpc_gss_free_pvt();
static	int	rpc_gss_seccreate_pvt();
static  bool_t	rpc_gss_wrap();
static  bool_t	rpc_gss_unwrap();
static	bool_t	validate_seqwin();


#ifdef	DEBUG
#include <sys/promif.h>
#endif

static struct auth_ops rpc_gss_ops = {
	rpc_gss_nextverf,
	rpc_gss_marshall,
	rpc_gss_validate,
	rpc_gss_refresh,
	rpc_gss_destroy,
	rpc_gss_wrap,
	rpc_gss_unwrap,
};

/*
 * Private data for RPCSEC_GSS.
 */
typedef struct _rpc_gss_data {
	bool_t		established;	/* TRUE when established */
	CLIENT		*clnt;		/* associated client handle */
	int		version;	/* RPCSEC version */
	gss_ctx_id_t	context;	/* GSS context id */
	gss_buffer_desc	ctx_handle;	/* RPCSEC GSS context handle */
	uint_t		seq_num;	/* last sequence number rcvd */
	gss_cred_id_t	my_cred;	/* caller's GSS credentials */
	OM_uint32	qop;		/* requested QOP */
	rpc_gss_service_t	service;	/* requested service */
	uint_t		gss_proc;	/* GSS control procedure */
	gss_name_t	target_name;	/* target server */
	int		req_flags;	/* GSS request bits */
	gss_OID		mech_type;	/* GSS mechanism */
	OM_uint32	time_req;	/* requested cred lifetime */
	bool_t		invalid;	/* can't use this any more */
	OM_uint32	seq_window;	/* server sequence window */
	struct opaque_auth *verifier;	/* rpc reply verifier saved for */
					/* validating the sequence window */
	gss_channel_bindings_t	icb;
} rpc_gss_data;
#define	AUTH_PRIVATE(auth)	((rpc_gss_data *)auth->ah_private)

#define	INTERRUPT_OK	1	/* allow interrupt */

/*
 *  RPCSEC_GSS auth cache definitions.
 */

/* The table size must be a power of two. */
#define	GSSAUTH_TABLESIZE 16
#define	HASH(keynum, uid_num) \
	((((intptr_t)(keynum)) ^ ((int)uid_num)) & (GSSAUTH_TABLESIZE - 1))

/*
 * gss auth cache entry.
 */
typedef struct ga_cache_entry {
	void	*cache_key;
	uid_t	uid;
	zoneid_t zoneid;
	bool_t	in_use;
	time_t	ref_time; /* the time referenced previously */
	time_t	ctx_expired_time; /* when the context will be expired */
	AUTH	*auth;
	struct ga_cache_entry *next;
} *ga_cache_list;

struct ga_cache_entry	*ga_cache_table[GSSAUTH_TABLESIZE];
static krwlock_t	ga_cache_table_lock;
static struct kmem_cache *ga_cache_handle;
static void gssauth_cache_reclaim(void *);

static void gssauth_zone_fini(zoneid_t, void *);
static zone_key_t	gssauth_zone_key;

int ga_cache_hit;
int ga_cache_miss;
int ga_cache_reclaim;

#define	NOT_DEAD(ptr)	ASSERT((((intptr_t)(ptr)) != 0xdeadbeef))

void
gssauth_init(void)
{
	/*
	 * Initialize gss auth cache table lock
	 */
	rw_init(&ga_cache_table_lock, NULL, RW_DEFAULT, NULL);

	/*
	 * Allocate gss auth cache handle
	 */
	ga_cache_handle = kmem_cache_create("ga_cache_handle",
	    sizeof (struct ga_cache_entry), 0, NULL, NULL,
	    gssauth_cache_reclaim, NULL, NULL, 0);
	zone_key_create(&gssauth_zone_key, NULL, NULL, gssauth_zone_fini);
}

/*
 * Destroy the structures previously initialized in gssauth_init()
 * This routine is called by _init() if mod_install() failed.
 */
void
gssauth_fini(void)
{
	(void) zone_key_delete(gssauth_zone_key);
	kmem_cache_destroy(ga_cache_handle);
	rw_destroy(&ga_cache_table_lock);
}

/*
 * This is a cleanup routine to release cached entries when a zone is being
 * destroyed.  The code is also used when kmem calls us to free up memory, at
 * which point ``zoneid'' will be ALL_ZONES.  We don't honor the cache timeout
 * when the zone is going away, since the zoneid (and all associated cached
 * entries) are invalid.
 */
time_t rpc_gss_cache_time = 60 * 60;

/* ARGSUSED */
static void
gssauth_zone_fini(zoneid_t zoneid, void *unused)
{
	struct ga_cache_entry *p, *prev, *next;
	int i;
	time_t now;

	rw_enter(&ga_cache_table_lock, RW_WRITER);

	for (i = 0; i < GSSAUTH_TABLESIZE; i++) {
		prev = NULL;
		for (p = ga_cache_table[i]; p; p = next) {
			NOT_DEAD(p->next);
			next = p->next;
			NOT_DEAD(next);
			if (zoneid == ALL_ZONES) {	/* kmem callback */
				/*
				 * Free entries that have not been
				 * used for rpc_gss_cache_time seconds.
				 */
				now = gethrestime_sec();
				if ((p->ref_time + rpc_gss_cache_time >
				    now) || p->in_use) {
					if ((p->ref_time + rpc_gss_cache_time <=
					    now) && p->in_use) {
						RPCGSS_LOG0(2, "gssauth_cache_"
						    "reclaim: in_use\n");
					}
					prev = p;
					continue;
				}
			} else {
				if (p->zoneid != zoneid) {
					prev = p;
					continue;
				}
				ASSERT(!p->in_use);
			}

			RPCGSS_LOG(2, "gssauth_cache_reclaim: destroy auth "
			    "%p\n", (void *)p->auth);
			rpc_gss_destroy(p->auth);
			kmem_cache_free(ga_cache_handle, (void *)p);
			if (prev == NULL) {
				ga_cache_table[i] = next;
			} else {
				NOT_DEAD(prev->next);
				prev->next = next;
			}
		}
	}

	rw_exit(&ga_cache_table_lock);

}

/*
 * Called by the kernel memory allocator when
 * memory is low. Free unused cache entries.
 * If that's not enough, the VM system will
 * call again for some more.
 */
/*ARGSUSED*/
static void
gssauth_cache_reclaim(void *cdrarg)
{
	gssauth_zone_fini(ALL_ZONES, NULL);
}

#define	NOT_NULL(ptr)	ASSERT(ptr)
#define	IS_ALIGNED(ptr)	ASSERT((((intptr_t)(ptr)) & 3) == 0)

/*
 *  Get the client gss security service handle.
 *  If it is in the cache table, get it, otherwise, create
 *  a new one by calling rpc_gss_seccreate().
 */
int
rpc_gss_secget(CLIENT *clnt,
	char	*principal,
	rpc_gss_OID	mechanism,
	rpc_gss_service_t service_type,
	uint_t	qop,
	rpc_gss_options_req_t *options_req,
	rpc_gss_options_ret_t *options_ret,
	void *cache_key,
	cred_t *cr,
	AUTH **retauth)
{
	struct ga_cache_entry **head, *current, *new, *prev;
	AUTH *auth = NULL;
	rpc_gss_data	*ap;
	rpc_gss_options_ret_t opt_ret;
	int status = 0;
	uid_t uid = crgetuid(cr);
	zoneid_t zoneid = getzoneid();

	if (retauth == NULL)
		return (EINVAL);
	*retauth = NULL;

	NOT_NULL(cr);
	IS_ALIGNED(cr);
#ifdef DEBUG
	if (HASH(cache_key, uid) < 0) {
		prom_printf("cache_key %p, cr %p\n", cache_key, (void *)cr);
	}
#endif

	/*
	 *  Get a valid gss auth handle from the cache table.
	 *  If auth in cache is invalid and not in use, destroy it.
	 */
	prev = NULL;
	rw_enter(&ga_cache_table_lock, RW_WRITER);

	ASSERT(HASH(cache_key, uid) >= 0);
	head = &ga_cache_table[HASH(cache_key, uid)];
	NOT_NULL(head);
	IS_ALIGNED(head);

	for (current = *head; current; current = current->next) {
		NOT_NULL(current);
		IS_ALIGNED(current);
		if ((cache_key == current->cache_key) &&
			(uid == current->uid) && (zoneid == current->zoneid) &&
			!current->in_use) {
			current->in_use = TRUE;
			current->ref_time = gethrestime_sec();
			ap = AUTH_PRIVATE(current->auth);
			ap->clnt = clnt;
			ga_cache_hit++;
			if (ap->invalid ||
			    ((current->ctx_expired_time != GSS_C_INDEFINITE) &&
			    (gethrestime_sec() >=
			    current->ctx_expired_time))) {
			    RPCGSS_LOG0(1, "NOTICE: rpc_gss_secget: time to "
					"refresh the auth\n");
			    if (prev == NULL) {
				*head = current->next;
			    } else {
				prev->next = current->next;
			    }
			    rpc_gss_destroy(current->auth);
			    kmem_cache_free(ga_cache_handle, (void *) current);
			    auth = NULL;
			} else {
			    auth = current->auth;
			}
			break;
		} else {
			prev = current;
		}
	}
	rw_exit(&ga_cache_table_lock);

	/*
	 *  If no valid gss auth handle can be found in the cache, create
	 *  a new one.
	 */
	if (!auth) {
		ga_cache_miss++;
		if (options_ret == NULL)
			options_ret = &opt_ret;

		status = rpc_gss_seccreate(clnt, principal, mechanism,
			service_type, qop, options_req, options_ret, cr, &auth);
		if (status == 0) {
			RPCGSS_LOG(2, "rpc_gss_secget: new auth %p\n",
					(void *)auth);
			new = kmem_cache_alloc(ga_cache_handle, KM_NOSLEEP);
			IS_ALIGNED(new);
			NOT_DEAD(new);
			if (new) {
				new->cache_key = cache_key;
				new->uid = uid;
				new->zoneid = zoneid;
				new->in_use = TRUE;
				new->ref_time = gethrestime_sec();
				if (options_ret->time_ret != GSS_C_INDEFINITE) {
				    new->ctx_expired_time = new->ref_time +
					options_ret->time_ret;
				} else {
				    new->ctx_expired_time = GSS_C_INDEFINITE;
				}
				new->auth = auth;
				rw_enter(&ga_cache_table_lock, RW_WRITER);
				NOT_DEAD(*head);
				NOT_DEAD(new->next);
				new->next = *head;
				*head = new;
				rw_exit(&ga_cache_table_lock);
			}
			/* done with opt_ret */
			if (options_ret == &opt_ret) {
			    kgss_free_oid((gss_OID) opt_ret.actual_mechanism);
			}
		}
	}

	*retauth = auth;
	return (status);
}



/*
 *  rpc_gss_secfree will destroy a rpcsec_gss context only if
 *  the auth handle is not in the cache table.
 */
void
rpc_gss_secfree(AUTH *auth)
{
	struct ga_cache_entry *next, *cur;
	int i;

	/*
	 *  Check the cache table to find the auth.
	 *  Marked it unused.
	 */
	rw_enter(&ga_cache_table_lock, RW_WRITER);
	for (i = 0; i < GSSAUTH_TABLESIZE; i++) {
		for (cur = ga_cache_table[i]; cur; cur = next) {
			NOT_DEAD(cur);
			next = cur->next;
			NOT_DEAD(next);
			if (cur->auth == auth) {
				ASSERT(cur->in_use == TRUE);
				cur->in_use = FALSE;
				rw_exit(&ga_cache_table_lock);
				return;
			}
		}
	}
	rw_exit(&ga_cache_table_lock);
	RPCGSS_LOG(2, "rpc_gss_secfree: destroy auth %p\n", (void *)auth);
	rpc_gss_destroy(auth);
}


/*
 *  Create a gss security service context.
 */
int
rpc_gss_seccreate(CLIENT *clnt,
	char			*principal,	/* target service@server */
	rpc_gss_OID		mechanism,	/* security mechanism */
	rpc_gss_service_t	service_type,	/* security service */
	uint_t			qop,		/* requested QOP */
	rpc_gss_options_req_t	*options_req,	/* requested options */
	rpc_gss_options_ret_t	*options_ret,	/* returned options */
	cred_t			*cr,		/* client's unix cred */
	AUTH			**retauth)	/* auth handle */
{
	OM_uint32		gssstat;
	OM_uint32		minor_stat;
	gss_name_t		target_name;
	int			ret_flags;
	OM_uint32		time_rec;
	gss_buffer_desc		input_name;
	AUTH			*auth = NULL;
	rpc_gss_data		*ap = NULL;
	int			error;

	/*
	 * convert name to GSS internal type
	 */
	input_name.value = principal;
	input_name.length = strlen(principal);

	gssstat = gss_import_name(&minor_stat, &input_name,
	    (gss_OID)GSS_C_NT_HOSTBASED_SERVICE, &target_name);

	if (gssstat != GSS_S_COMPLETE) {
		RPCGSS_LOG0(1,
		    "rpc_gss_seccreate: unable to import gss name\n");
		return (ENOMEM);
	}

	/*
	 * Create AUTH handle.  Save the necessary interface information
	 * so that the client can refresh the handle later if needed.
	 */
	if ((auth = (AUTH *) kmem_alloc(sizeof (*auth), KM_SLEEP)) != NULL)
		ap = (rpc_gss_data *) kmem_alloc(sizeof (*ap), KM_SLEEP);
	if (auth == NULL || ap == NULL) {
		RPCGSS_LOG0(1, "rpc_gss_seccreate: out of memory\n");
		if (auth != NULL)
			kmem_free((char *)auth, sizeof (*auth));
		(void) gss_release_name(&minor_stat, &target_name);
		return (ENOMEM);
	}

	bzero((char *)ap, sizeof (*ap));
	ap->clnt = clnt;
	ap->version = RPCSEC_GSS_VERSION;
	if (options_req != NULL) {
		ap->my_cred = options_req->my_cred;
		ap->req_flags = options_req->req_flags;
		ap->time_req = options_req->time_req;
		ap->icb = options_req->input_channel_bindings;
	} else {
		ap->my_cred = GSS_C_NO_CREDENTIAL;
		ap->req_flags = GSS_C_MUTUAL_FLAG;
		ap->time_req = 0;
		ap->icb = GSS_C_NO_CHANNEL_BINDINGS;
	}
	if ((ap->service = service_type) == rpc_gss_svc_default)
		ap->service = rpc_gss_svc_integrity;
	ap->qop = qop;
	ap->target_name = target_name;

	/*
	 * Now invoke the real interface that sets up the context from
	 * the information stashed away in the private data.
	 */
	if (error = rpc_gss_seccreate_pvt(&gssstat, &minor_stat, auth, ap,
	    mechanism, &ap->mech_type, &ret_flags, &time_rec, cr, 0)) {
		if (ap->target_name) {
			(void) gss_release_name(&minor_stat, &ap->target_name);
		}
		kmem_free((char *)ap, sizeof (*ap));
		kmem_free((char *)auth, sizeof (*auth));
		RPCGSS_LOG(1, "rpc_gss_seccreate: init context failed"
		    " errno=%d\n", error);
		return (error);
	}

	/*
	 * Make sure that the requested service is supported.  In all
	 * cases, integrity service must be available.
	 */
	if ((ap->service == rpc_gss_svc_privacy &&
	    !(ret_flags & GSS_C_CONF_FLAG)) ||
	    !(ret_flags & GSS_C_INTEG_FLAG)) {
		rpc_gss_destroy(auth);
		RPCGSS_LOG0(1, "rpc_gss_seccreate: service not supported\n");
		return (EPROTONOSUPPORT);
	}

	/*
	 * return option values if requested
	 */
	if (options_ret != NULL) {
		options_ret->major_status = gssstat;
		options_ret->minor_status = minor_stat;
		options_ret->rpcsec_version = ap->version;
		options_ret->ret_flags = ret_flags;
		options_ret->time_ret = time_rec;
		options_ret->gss_context = ap->context;
		/*
		 *  Caller's responsibility to free this.
		 */
		NOT_NULL(ap->mech_type);
		__rpc_gss_dup_oid(ap->mech_type,
		    (gss_OID *)&options_ret->actual_mechanism);
	}

	*retauth = auth;
	return (0);
}

/*
 * Private interface to create a context.  This is the interface
 * that's invoked when the context has to be refreshed.
 */
static int
rpc_gss_seccreate_pvt(gssstat, minor_stat, auth, ap, desired_mech_type,
			actual_mech_type, ret_flags, time_rec, cr, isrefresh)
	OM_uint32		*gssstat;
	OM_uint32		*minor_stat;
	AUTH			*auth;
	rpc_gss_data		*ap;
	gss_OID			desired_mech_type;
	gss_OID			*actual_mech_type;
	int			*ret_flags;
	OM_uint32		*time_rec;
	cred_t			*cr;
	int			isrefresh;
{
	CLIENT			*clnt = ap->clnt;
	AUTH			*save_auth;
	enum clnt_stat		callstat;
	rpc_gss_init_arg	call_arg;
	rpc_gss_init_res	call_res;
	gss_buffer_desc		*input_token_p, input_token, process_token;
	int 			free_results = 0;
	k_sigset_t		smask;
	int			error = 0;

	/*
	 * (re)initialize AUTH handle and private data.
	 */
	bzero((char *)auth, sizeof (*auth));
	auth->ah_ops = &rpc_gss_ops;
	auth->ah_private = (caddr_t)ap;
	auth->ah_cred.oa_flavor = RPCSEC_GSS;

	ap->established = FALSE;
	ap->ctx_handle.length = 0;
	ap->ctx_handle.value = NULL;
	ap->context = NULL;
	ap->seq_num = 0;
	ap->gss_proc = RPCSEC_GSS_INIT;

	/*
	 * should not change clnt->cl_auth at this time, so save
	 * old handle
	 */
	save_auth = clnt->cl_auth;
	clnt->cl_auth = auth;

	/*
	 * set state for starting context setup
	 */
	bzero((char *)&call_arg, sizeof (call_arg));
	input_token_p = GSS_C_NO_BUFFER;

next_token:
	*gssstat = kgss_init_sec_context(minor_stat,
					ap->my_cred,
					&ap->context,
					ap->target_name,
					desired_mech_type,
					ap->req_flags,
					ap->time_req,
					NULL,
					input_token_p,
					actual_mech_type,
					&call_arg,
					ret_flags,
					time_rec,
					crgetuid(cr));

	if (input_token_p != GSS_C_NO_BUFFER) {
		OM_uint32 minor_stat2;

		(void) gss_release_buffer(&minor_stat2, input_token_p);
		input_token_p = GSS_C_NO_BUFFER;
	}

	if (*gssstat != GSS_S_COMPLETE && *gssstat != GSS_S_CONTINUE_NEEDED) {
		rpc_gss_display_status(*gssstat, *minor_stat,
			desired_mech_type, crgetuid(cr),
			"rpcsec_gss_secreate_pvt:gss_init_sec_context");
		error = EACCES;
		goto cleanup;
	}

	/*
	 * if we got a token, pass it on
	 */
	if (call_arg.length != 0) {
		struct timeval timeout = {30, 0};
		int	 rpcsec_retry = isrefresh ?
			RPCSEC_GSS_REFRESH_ATTEMPTS : 1;
		uint32_t oldxid;
		uint32_t zeroxid = 0;

		bzero((char *)&call_res, sizeof (call_res));

		(void) CLNT_CONTROL(clnt, CLGET_XID, (char *)&oldxid);
		(void) CLNT_CONTROL(clnt, CLSET_XID, (char *)&zeroxid);


		while (rpcsec_retry > 0) {
			struct rpc_err rpcerr;

			sigintr(&smask, INTERRUPT_OK);

			callstat = clnt_call(clnt, NULLPROC,
				__xdr_rpc_gss_init_arg, (caddr_t)&call_arg,
				__xdr_rpc_gss_init_res, (caddr_t)&call_res,
				timeout);

			sigunintr(&smask);

			if (callstat == RPC_SUCCESS) {
				error = 0;
				if (isrefresh &&
				    call_res.gss_major == GSS_S_FAILURE) {

					clock_t one_sec = drv_usectohz(1000000);

					rpcsec_retry--;

					/*
					 * Pause a little and try again.
					 */

					if (clnt->cl_nosignal == TRUE) {
						delay(one_sec);
					} else {
						if (delay_sig(one_sec)) {
							error = EINTR;
							break;
						}
					}
					continue;
				}
				break;
			}

			if (callstat == RPC_TIMEDOUT) {
				error = ETIMEDOUT;
				break;
			}

			if (callstat == RPC_XPRTFAILED) {
				error = ECONNRESET;
				break;
			}

			if (callstat == RPC_INTR) {
				error = EINTR;
				break;
			}

			if (callstat == RPC_INPROGRESS) {
				continue;
			}

			clnt_geterr(clnt, &rpcerr);
			error = rpcerr.re_errno;
			break;
		}

		(void) CLNT_CONTROL(clnt, CLSET_XID, (char *)&oldxid);

		(void) gss_release_buffer(minor_stat, &call_arg);

		if (callstat != RPC_SUCCESS) {
			RPCGSS_LOG(1,
			    "rpc_gss_seccreate_pvt: clnt_call failed %d\n",
			    callstat);
			goto cleanup;
		}

		/*
		 * we have results - note that these need to be freed
		 */
		free_results = 1;

		if ((call_res.gss_major != GSS_S_COMPLETE) &&
		    (call_res.gss_major != GSS_S_CONTINUE_NEEDED)) {
			RPCGSS_LOG1(1, "rpc_gss_seccreate_pvt: "
				"call_res gss_major %x, gss_minor %x\n",
				call_res.gss_major, call_res.gss_minor);
			error = EACCES;
			goto cleanup;
		}

		ap->gss_proc = RPCSEC_GSS_CONTINUE_INIT;

		/*
		 * check for ctx_handle
		 */
		if (ap->ctx_handle.length == 0) {
			if (call_res.ctx_handle.length == 0) {
				RPCGSS_LOG0(1, "rpc_gss_seccreate_pvt: zero "
					"length handle in response\n");
				error = EACCES;
				goto cleanup;
			}
			GSS_DUP_BUFFER(ap->ctx_handle,
					call_res.ctx_handle);
		} else if (!GSS_BUFFERS_EQUAL(ap->ctx_handle,
						call_res.ctx_handle)) {
			RPCGSS_LOG0(1,
			"rpc_gss_seccreate_pvt: ctx_handle not the same\n");
			error = EACCES;
			goto cleanup;
		}

		/*
		 * check for token
		 */
		if (call_res.token.length != 0) {
			if (*gssstat == GSS_S_COMPLETE) {
				RPCGSS_LOG0(1, "rpc_gss_seccreate_pvt: non "
					"zero length token in response, but "
					"gsstat == GSS_S_COMPLETE\n");
				error = EACCES;
				goto cleanup;
			}
			GSS_DUP_BUFFER(input_token, call_res.token);
			input_token_p = &input_token;

		} else if (*gssstat != GSS_S_COMPLETE) {
			RPCGSS_LOG0(1, "rpc_gss_seccreate_pvt:zero length "
				"token in response, but "
				"gsstat != GSS_S_COMPLETE\n");
			error = EACCES;
			goto cleanup;
		}

		/* save the sequence window value; validate later */
		ap->seq_window = call_res.seq_window;
		xdr_free(__xdr_rpc_gss_init_res, (caddr_t)&call_res);
		free_results = 0;
	}

	/*
	 * results were okay.. continue if necessary
	 */
	if (*gssstat == GSS_S_CONTINUE_NEEDED) {
		goto next_token;
	}

	/*
	 * Context is established. Now use kgss_export_sec_context and
	 * kgss_import_sec_context to transfer the context from the user
	 * land to kernel if the mechanism specific kernel module is
	 * available.
	 */
	*gssstat  = kgss_export_sec_context(minor_stat, ap->context,
						&process_token);
	if (*gssstat == GSS_S_NAME_NOT_MN) {
		RPCGSS_LOG(2, "rpc_gss_seccreate_pvt: export_sec_context "
			"Kernel Module unavailable  gssstat = 0x%x\n",
			*gssstat);
		goto done;
	} else if (*gssstat != GSS_S_COMPLETE) {
		(void) rpc_gss_display_status(*gssstat, *minor_stat,
			isrefresh ? GSS_C_NULL_OID : *actual_mech_type,
					crgetuid(cr),
			"rpcsec_gss_secreate_pvt:gss_export_sec_context");
		(void) kgss_delete_sec_context(minor_stat,
					&ap->context, NULL);
		error = EACCES;
		goto cleanup;
	} else if (process_token.length == 0) {
		RPCGSS_LOG0(1, "rpc_gss_seccreate_pvt:zero length "
				"token in response for export_sec_context, but "
				"gsstat == GSS_S_COMPLETE\n");
		(void) kgss_delete_sec_context(minor_stat,
					&ap->context, NULL);
		error = EACCES;
		goto cleanup;
	} else
		*gssstat = kgss_import_sec_context(minor_stat, &process_token,
							ap->context);

	if (*gssstat == GSS_S_COMPLETE) {
		(void) gss_release_buffer(minor_stat, &process_token);
	} else {
		rpc_gss_display_status(*gssstat, *minor_stat,
			desired_mech_type, crgetuid(cr),
			"rpcsec_gss_secreate_pvt:gss_import_sec_context");
		(void) kgss_delete_sec_context(minor_stat,
					&ap->context, NULL);
		(void) gss_release_buffer(minor_stat, &process_token);
		error = EACCES;
		goto cleanup;
	}

done:
	/*
	 * Validate the sequence window - RFC 2203 section 5.2.3.1
	 */
	if (!validate_seqwin(ap)) {
		error = EACCES;
		goto cleanup;
	}

	/*
	 * Done!  Security context creation is successful.
	 * Ready for exchanging data.
	 */
	ap->established = TRUE;
	ap->seq_num = 1;
	ap->gss_proc = RPCSEC_GSS_DATA;
	ap->invalid = FALSE;

	clnt->cl_auth = save_auth;	/* restore cl_auth */

	return (0);

cleanup:
	if (free_results)
		xdr_free(__xdr_rpc_gss_init_res, (caddr_t)&call_res);
	clnt->cl_auth = save_auth;	/* restore cl_auth */

	/*
	 * If need to retry for AUTH_REFRESH, do not cleanup the
	 * auth private data.
	 */
	if (isrefresh && (error == ETIMEDOUT || error == ECONNRESET)) {
		return (error);
	}

	if (ap->context != NULL) {
		rpc_gss_free_pvt(auth);
	}

	return (error? error : EACCES);
}

/*
 * Marshall credentials.
 */
static bool_t
marshall_creds(ap, xdrs, cred_buf_len)
	rpc_gss_data		*ap;
	XDR			*xdrs;
	uint_t			cred_buf_len;
{
	rpc_gss_creds		ag_creds;
	char			*cred_buf;
	struct opaque_auth	creds;
	XDR			cred_xdrs;

	ag_creds.version = ap->version;
	ag_creds.gss_proc = ap->gss_proc;
	ag_creds.seq_num = ap->seq_num;
	ag_creds.service = ap->service;

	/*
	 * If context has not been set up yet, use NULL handle.
	 */
	if (ap->ctx_handle.length > 0)
		ag_creds.ctx_handle = ap->ctx_handle;
	else {
		ag_creds.ctx_handle.length = 0;
		ag_creds.ctx_handle.value = NULL;
	}

	cred_buf = kmem_alloc(cred_buf_len, KM_SLEEP);
	xdrmem_create(&cred_xdrs, (caddr_t)cred_buf, cred_buf_len,
								XDR_ENCODE);
	if (!__xdr_rpc_gss_creds(&cred_xdrs, &ag_creds)) {
		kmem_free(cred_buf, MAX_AUTH_BYTES);
		XDR_DESTROY(&cred_xdrs);
		return (FALSE);
	}

	creds.oa_flavor = RPCSEC_GSS;
	creds.oa_base = cred_buf;
	creds.oa_length = xdr_getpos(&cred_xdrs);
	XDR_DESTROY(&cred_xdrs);

	if (!xdr_opaque_auth(xdrs, &creds)) {
		kmem_free(cred_buf, cred_buf_len);
		return (FALSE);
	}

	kmem_free(cred_buf, cred_buf_len);
	return (TRUE);
}

/*
 * Marshall verifier.  The verifier is the checksum of the RPC header
 * up to and including the credential field.  The XDR handle that's
 * passed in has the header up to and including the credential field
 * encoded.  A pointer to the transmit buffer is also passed in.
 */
static bool_t
marshall_verf(ap, xdrs, buf)
	rpc_gss_data		*ap;
	XDR			*xdrs;	/* send XDR */
	char			*buf;	/* pointer of send buffer */
{
	struct opaque_auth	verf;
	OM_uint32		major, minor;
	gss_buffer_desc		in_buf, out_buf;
	bool_t			ret = FALSE;

	/*
	 * If context is not established yet, use NULL verifier.
	 */
	if (!ap->established) {
		verf.oa_flavor = AUTH_NONE;
		verf.oa_base = NULL;
		verf.oa_length = 0;
		return (xdr_opaque_auth(xdrs, &verf));
	}

	verf.oa_flavor = RPCSEC_GSS;
	in_buf.length = xdr_getpos(xdrs);
	in_buf.value = buf;
	if ((major = kgss_sign(&minor, ap->context, ap->qop, &in_buf,
				&out_buf)) != GSS_S_COMPLETE) {
		if (major == GSS_S_CONTEXT_EXPIRED) {
			ap->invalid = TRUE;
		}
		RPCGSS_LOG1(1,
		    "marshall_verf: kgss_sign failed GSS Major %x Minor %x\n",
		    major, minor);
		return (FALSE);
	}
	verf.oa_base = out_buf.value;
	verf.oa_length = out_buf.length;
	ret = xdr_opaque_auth(xdrs, &verf);
	(void) gss_release_buffer(&minor, &out_buf);

	return (ret);
}

/*
 * Validate sequence window upon a successful RPCSEC_GSS INIT session.
 * The sequence window sent back by the server should be verifiable by
 * the verifier which is a checksum of the sequence window.
 */
static bool_t
validate_seqwin(rpc_gss_data *ap)
{
	uint_t			seq_win_net;
	OM_uint32		major = 0, minor = 0;
	gss_buffer_desc		msg_buf, tok_buf;
	int			qop_state = 0;

	ASSERT(ap->verifier);
	ASSERT(ap->context);
	seq_win_net = (uint_t)htonl(ap->seq_window);
	msg_buf.length = sizeof (seq_win_net);
	msg_buf.value = (char *)&seq_win_net;
	tok_buf.length = ap->verifier->oa_length;
	tok_buf.value = ap->verifier->oa_base;
	major = kgss_verify(&minor, ap->context, &msg_buf, &tok_buf,
	    &qop_state);

	if (major != GSS_S_COMPLETE) {
		RPCGSS_LOG1(1,
		    "validate_seqwin: kgss_verify failed GSS Major "
		    "%x Minor %x\n", major, minor);
		RPCGSS_LOG1(1, "seq_window %d, verf len %d ", ap->seq_window,
		    ap->verifier->oa_length);
		return (FALSE);
	}
	return (TRUE);
}

/*
 * Validate RPC response verifier from server.  The response verifier
 * is the checksum of the request sequence number.
 */
static bool_t
rpc_gss_validate(auth, verf)
	AUTH			*auth;
	struct opaque_auth	*verf;
{
	rpc_gss_data		*ap = AUTH_PRIVATE(auth);
	uint_t			seq_num_net;
	OM_uint32		major, minor;
	gss_buffer_desc		msg_buf, tok_buf;
	int			qop_state;

	/*
	 * If context is not established yet, save the verifier for
	 * validating the sequence window later at the end of context
	 * creation session.
	 */
	if (!ap->established) {
	    if (ap->verifier == NULL) {
		ap->verifier = kmem_zalloc(sizeof (struct opaque_auth),
						KM_SLEEP);
		if (verf->oa_length > 0)
		    ap->verifier->oa_base = kmem_zalloc(verf->oa_length,
						KM_SLEEP);
	    } else {
		if (ap->verifier->oa_length > 0)
		    kmem_free(ap->verifier->oa_base, ap->verifier->oa_length);
		if (verf->oa_length > 0)
		    ap->verifier->oa_base = kmem_zalloc(verf->oa_length,
						KM_SLEEP);
	    }
	    ap->verifier->oa_length = verf->oa_length;
	    bcopy(verf->oa_base, ap->verifier->oa_base, verf->oa_length);
	    return (TRUE);
	}

	seq_num_net = (uint_t)htonl(ap->seq_num);
	msg_buf.length = sizeof (seq_num_net);
	msg_buf.value = (char *)&seq_num_net;
	tok_buf.length = verf->oa_length;
	tok_buf.value = verf->oa_base;
	major = kgss_verify(&minor, ap->context, &msg_buf, &tok_buf,
				&qop_state);
	if (major != GSS_S_COMPLETE) {
		RPCGSS_LOG1(1,
		"rpc_gss_validate: kgss_verify failed GSS Major %x Minor %x\n",
		major, minor);
		return (FALSE);
	}
	return (TRUE);
}

/*
 * Refresh client context.  This is necessary sometimes because the
 * server will ocassionally destroy contexts based on LRU method, or
 * because of expired credentials.
 */
static bool_t
rpc_gss_refresh(auth, msg, cr)
	AUTH		*auth;
	struct rpc_msg	*msg;
	cred_t		*cr;
{
	rpc_gss_data	*ap = AUTH_PRIVATE(auth);
	gss_ctx_id_t	ctx_sav = NULL;
	gss_buffer_desc	ctx_hdle_sav = {0, NULL};
	uint_t		sn_sav, proc_sav;
	bool_t		est_sav;
	OM_uint32	gssstat, minor_stat;
	int error;

	/*
	 * The context needs to be recreated only when the error status
	 * returned from the server is one of the following:
	 *	RPCSEC_GSS_NOCRED and RPCSEC_GSS_FAILED
	 * The existing context should not be destroyed unless the above
	 * error status codes are received or if the context has not
	 * been set up.
	 */

	if (msg->rjcted_rply.rj_why == RPCSEC_GSS_NOCRED ||
			msg->rjcted_rply.rj_why == RPCSEC_GSS_FAILED ||
							!ap->established) {
		/*
		 * Destroy the context if necessary.  Use the same memory
		 * for the new context since we've already passed a pointer
		 * to it to the user.
		 */
		if (ap->context != NULL) {
			ctx_sav = ap->context;
			ap->context = NULL;
		}
		if (ap->ctx_handle.length != 0) {
			ctx_hdle_sav.length = ap->ctx_handle.length;
			ctx_hdle_sav.value = ap->ctx_handle.value;
			ap->ctx_handle.length = 0;
			ap->ctx_handle.value = NULL;
		}

		/*
		 * If the context was not already established, don't try to
		 * recreate it.
		 */
		if (!ap->established) {
			ap->invalid = TRUE;
			RPCGSS_LOG0(1,
			"rpc_gss_refresh: context was not established\n");
			error = EINVAL;
			goto out;
		}

		est_sav = ap->established;
		sn_sav = ap->seq_num;
		proc_sav = ap->gss_proc;

		/*
		 * Recreate context.
		 */
		error = rpc_gss_seccreate_pvt(&gssstat, &minor_stat, auth,
				ap, ap->mech_type, (gss_OID *)NULL, (int *)NULL,
				(OM_uint32 *)NULL, cr, 1);

		switch (error) {
		case 0:
			RPCGSS_LOG(1,
			"rpc_gss_refresh: auth %p refreshed\n", (void *)auth);
			goto out;

		case ETIMEDOUT:
		case ECONNRESET:
			RPCGSS_LOG0(1, "rpc_gss_refresh: try again\n");

			if (ap->context != NULL) {
			    (void) kgss_delete_sec_context(&minor_stat,
					&ap->context, NULL);
			}
			if (ap->ctx_handle.length != 0) {
			    (void) gss_release_buffer(&minor_stat,
					&ap->ctx_handle);
			}

			/*
			 * Restore the original value for the caller to
			 * try again later.
			 */
			ap->context = ctx_sav;
			ap->ctx_handle.length = ctx_hdle_sav.length;
			ap->ctx_handle.value = ctx_hdle_sav.value;
			ap->established = est_sav;
			ap->seq_num = sn_sav;
			ap->gss_proc = proc_sav;

			return (FALSE);

		default:
			ap->invalid = TRUE;
			RPCGSS_LOG(1, "rpc_gss_refresh: can't refresh this "
				"auth, error=%d\n", error);
			goto out;
		}
	}
	RPCGSS_LOG0(1, "rpc_gss_refresh: don't refresh");
	return (FALSE);

out:
	if (ctx_sav != NULL) {
		(void) kgss_delete_sec_context(&minor_stat,
				&ctx_sav, NULL);
	}
	if (ctx_hdle_sav.length != 0) {
		(void) gss_release_buffer(&minor_stat, &ctx_hdle_sav);
	}

	return (error == 0);
}

/*
 * Destroy a context.
 */
static void
rpc_gss_destroy(auth)
	AUTH		*auth;
{
	rpc_gss_data	*ap = AUTH_PRIVATE(auth);

	/*
	 *  XXX Currently, we do not ping the server (rpc_gss_destroy_pvt)
	 *  to destroy the context in the server cache.
	 *  We assume there is a good LRU/aging mechanism for the
	 *  context cache on the server side.
	 */
	rpc_gss_free_pvt(auth);
	kmem_free((char *)ap, sizeof (*ap));
	kmem_free(auth, sizeof (*auth));
}

/*
 * Private interface to free memory allocated in the rpcsec_gss private
 * data structure (rpc_gss_data).
 */
static void
rpc_gss_free_pvt(auth)
	AUTH		*auth;
{
	OM_uint32	minor_stat;
	rpc_gss_data	*ap = AUTH_PRIVATE(auth);

	if (ap->ctx_handle.length != 0) {
		(void) gss_release_buffer(&minor_stat, &ap->ctx_handle);
		ap->ctx_handle.length = 0;
		ap->ctx_handle.value = NULL;
	}

	/*
	 * Destroy local GSS context.
	 */
	if (ap->context != NULL) {
		(void) kgss_delete_sec_context(&minor_stat, &ap->context, NULL);
		ap->context = NULL;
	}

	/*
	 * Looks like we need to release default credentials if we use it.
	 * Non-default creds need to be released by user.
	 */
	if (ap->my_cred == GSS_C_NO_CREDENTIAL)
		(void) kgss_release_cred(&minor_stat, &ap->my_cred,
					crgetuid(CRED()));

	/*
	 * Release any internal name structures.
	 */
	if (ap->target_name != NULL) {
		(void) gss_release_name(&minor_stat, &ap->target_name);
		ap->target_name = NULL;
	}

	/*
	 * Free mech_type oid structure.
	 */
	if (ap->mech_type != NULL) {
		kgss_free_oid(ap->mech_type);
		ap->mech_type = NULL;
	}

	/*
	 * Free the verifier saved for sequence window checking.
	 */
	if (ap->verifier != NULL) {
	    if (ap->verifier->oa_length > 0) {
		kmem_free(ap->verifier->oa_base, ap->verifier->oa_length);
	    }
	    kmem_free(ap->verifier, sizeof (struct opaque_auth));
	    ap->verifier = NULL;
	}
}

#if 0
/*
 * XXX this function is not used right now.
 * There is a client handle issue needs to be resolved.
 *
 * This is a private interface which will destroy a context
 * without freeing up the memory used by it.  We need to do this when
 * a refresh fails, for example, so the user will still have a handle.
 */
static void
rpc_gss_destroy_pvt(auth)
	AUTH		*auth;
{
	struct timeval	timeout;
	rpc_gss_data	*ap = AUTH_PRIVATE(auth);

	/*
	 * If we have a server context id, inform server that we are
	 * destroying the context.
	 */
	if (ap->ctx_handle.length != 0) {
		uint32_t oldxid;
		uint32_t zeroxid = 0;

		ap->gss_proc = RPCSEC_GSS_DESTROY;
		timeout.tv_sec = 10;
		timeout.tv_usec = 0;
		(void) CLNT_CONTROL(ap->clnt, CLGET_XID, (char *)&oldxid);
		(void) CLNT_CONTROL(ap->clnt, CLSET_XID, (char *)&zeroxid);
		(void) clnt_call(ap->clnt, NULLPROC, xdr_void, NULL,
						xdr_void, NULL, timeout);
		(void) CLNT_CONTROL(ap->clnt, CLSET_XID, (char *)&oldxid);
	}

	rpc_gss_free_pvt(auth);
}
#endif

/*
 * Wrap client side data.  The encoded header is passed in through
 * buf and buflen.  The header is up to but not including the
 * credential field.
 */
bool_t
rpc_gss_wrap(auth, buf, buflen, out_xdrs, xdr_func, xdr_ptr)
	AUTH			*auth;
	char			*buf;		/* encoded header */
/* has been changed to u_int in the user land */
	uint_t			buflen;		/* encoded header length */
	XDR			*out_xdrs;
	xdrproc_t		xdr_func;
	caddr_t			xdr_ptr;
{
	rpc_gss_data		*ap = AUTH_PRIVATE(auth);
	XDR			xdrs;
	char			*tmp_buf;
	uint_t			xdr_buf_len, cred_buf_len;

/*
 *  Here is how MAX_SIGNED_LEN is estimated.
 *  Signing a 48 bytes buffer using des_cbc_md5 would end up with
 *  a buffer length 33 (padded data + 16 bytes of seq_num/checksum).
 *  Current known max seq_num/checksum size is 24 bytes.
 *  88 is derived from RNDUP(33+(24-16)) * 2.
 */
#define	MAX_SIGNED_LEN	88

	/*
	 * Reject an invalid context.
	 */
	if (ap->invalid) {
		RPCGSS_LOG0(1, "rpc_gss_wrap: reject an invalid context\n");
		return (FALSE);
	}

	/*
	 * If context is established, bump up sequence number.
	 */
	if (ap->established)
		ap->seq_num++;

	/*
	 * Create the header in a temporary XDR context and buffer
	 * before putting it out.
	 */
	cred_buf_len = RNDUP(sizeof (ap->version) + sizeof (ap->gss_proc) +
			sizeof (ap->seq_num) + sizeof (ap->service) +
			sizeof (ap->ctx_handle) + ap->ctx_handle.length);

	xdr_buf_len = buflen + cred_buf_len + sizeof (struct opaque_auth) +
			MAX_SIGNED_LEN;
	tmp_buf = kmem_alloc(xdr_buf_len, KM_SLEEP);
	xdrmem_create(&xdrs, tmp_buf, xdr_buf_len, XDR_ENCODE);
	if (!XDR_PUTBYTES(&xdrs, buf, buflen)) {
		kmem_free(tmp_buf, xdr_buf_len);
		RPCGSS_LOG0(1, "rpc_gss_wrap: xdr putbytes failed\n");
		return (FALSE);
	}

	/*
	 * create cred field
	 */
	if (!marshall_creds(ap, &xdrs, cred_buf_len)) {
		kmem_free(tmp_buf, xdr_buf_len);
		RPCGSS_LOG0(1, "rpc_gss_wrap: marshall_creds failed\n");
		return (FALSE);
	}

	/*
	 * create verifier
	 */
	if (!marshall_verf(ap, &xdrs, tmp_buf)) {
		kmem_free(tmp_buf, xdr_buf_len);
		RPCGSS_LOG0(1, "rpc_gss_wrap: marshall_verf failed\n");
		return (FALSE);
	}

	/*
	 * write out header and destroy temp structures
	 */
	if (!XDR_PUTBYTES(out_xdrs, tmp_buf, XDR_GETPOS(&xdrs))) {
		kmem_free(tmp_buf, xdr_buf_len);
		RPCGSS_LOG0(1, "rpc_gss_wrap: write out header failed\n");
		return (FALSE);
	}
	XDR_DESTROY(&xdrs);
	kmem_free(tmp_buf, xdr_buf_len);

	/*
	 * If context is not established, or if neither integrity
	 * nor privacy is used, just XDR encode data.
	 */
	if (!ap->established || ap->service == rpc_gss_svc_none) {
		return ((*xdr_func)(out_xdrs, xdr_ptr));
	}

	return (__rpc_gss_wrap_data(ap->service, ap->qop, ap->context,
				ap->seq_num, out_xdrs, xdr_func, xdr_ptr));
}

/*
 * Unwrap received data.
 */
bool_t
rpc_gss_unwrap(auth, in_xdrs, xdr_func, xdr_ptr)
	AUTH			*auth;
	XDR			*in_xdrs;
	bool_t			(*xdr_func)();
	caddr_t			xdr_ptr;
{
	rpc_gss_data		*ap = AUTH_PRIVATE(auth);

	/*
	 * If context is not established, of if neither integrity
	 * nor privacy is used, just XDR encode data.
	 */
	if (!ap->established || ap->service == rpc_gss_svc_none)
		return ((*xdr_func)(in_xdrs, xdr_ptr));

	return (__rpc_gss_unwrap_data(ap->service,
				ap->context,
				ap->seq_num,
				ap->qop,
				in_xdrs, xdr_func, xdr_ptr));
}

/*
 *  Revoke an GSSAPI based security credentials
 *  from the cache table.
 */
int
rpc_gss_revauth(uid_t uid, rpc_gss_OID mech)
{
	struct ga_cache_entry *next, *prev, *cur;
	rpc_gss_data *ap;
	zoneid_t zoneid = getzoneid();
	int i;

	/*
	 *  Check the cache table against the uid and the
	 *  mechanism type.
	 */
	rw_enter(&ga_cache_table_lock, RW_WRITER);
	for (i = 0; i < GSSAUTH_TABLESIZE; i++) {
		prev = NULL;
		for (cur = ga_cache_table[i]; cur; cur = next) {
			NOT_DEAD(cur);
			next = cur->next;
			NOT_DEAD(next);
			ap = AUTH_PRIVATE(cur->auth);
			if (__rpc_gss_oids_equal(ap->mech_type,
			    (gss_OID) mech) && (cur->uid == uid) &&
			    (cur->zoneid == zoneid)) {
				if (cur->in_use) {
					RPCGSS_LOG(2, "rpc_gss_revauth:invalid "
					    "auth %p\n", (void *)cur->auth);
					ap->invalid = TRUE;
				} else {
					RPCGSS_LOG(2, "rpc_gss_revauth:destroy "
					    "auth %p\n", (void *)cur->auth);
					rpc_gss_destroy(cur->auth);
					kmem_cache_free(ga_cache_handle,
					    (void *)cur);
				}
				if (prev == NULL) {
					ga_cache_table[i] = next;
				} else {
					prev->next = next;
					NOT_DEAD(prev->next);
				}
			} else {
				prev = cur;
			}
		}
	}
	rw_exit(&ga_cache_table_lock);

	return (0);
}


/*
 *  Delete all the entries indexed by the cache_key.
 *
 *  For example, the cache_key used for NFS is the address of the
 *  security entry for each mount point.  When the file system is unmounted,
 *  all the cache entries indexed by this key should be deleted.
 */
void
rpc_gss_secpurge(void *cache_key)
{
	struct ga_cache_entry *next, *prev, *cur;
	int i;

	/*
	 *  Check the cache table against the cache_key.
	 */
	rw_enter(&ga_cache_table_lock, RW_WRITER);
	for (i = 0; i < GSSAUTH_TABLESIZE; i++) {
		prev = NULL;
		for (cur = ga_cache_table[i]; cur; cur = next) {
			NOT_DEAD(cur);
			next = cur->next;
			NOT_DEAD(next);
			if (cache_key == cur->cache_key) {
				RPCGSS_LOG(2, "rpc_gss_secpurge: destroy auth "
				    "%p\n", (void *)cur->auth);
				if (cur->in_use == FALSE)
					rpc_gss_destroy(cur->auth);
				kmem_cache_free(ga_cache_handle, (void *)cur);
				if (prev == NULL) {
					ga_cache_table[i] = next;
				} else {
					NOT_DEAD(prev->next);
					prev->next = next;
				}
			} else {
				prev = cur;
			}
		}
	}
	rw_exit(&ga_cache_table_lock);
}

/*
 * Function: rpc_gss_nextverf.  Not used.
 */
static void
rpc_gss_nextverf()
{
}

/*
 * Function: rpc_gss_marshall - no op routine.
 *		rpc_gss_wrap() is doing the marshalling.
 */
/*ARGSUSED*/
static bool_t
rpc_gss_marshall(auth, xdrs)
	AUTH		*auth;
	XDR		*xdrs;
{
	return (TRUE);
}

/*
 * Set service defaults.
 * Not supported yet.
 */
/* ARGSUSED */
bool_t
rpc_gss_set_defaults(auth, service, qop)
	AUTH			*auth;
	rpc_gss_service_t	service;
	uint_t			qop;
{
	return (FALSE);
}

/* ARGSUSED */
int
rpc_gss_max_data_length(AUTH *rpcgss_handle, int max_tp_unit_len)
{
	return (0);
}

rpc_gss_service_t
rpc_gss_get_service_type(AUTH *auth)
{
	rpc_gss_data		*ap = AUTH_PRIVATE(auth);

	return (ap->service);
}
