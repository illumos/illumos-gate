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
 *
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Header:
 * /afs/gza.com/product/secure/rel-eng/src/1.1/rpc/RCS/auth_gssapi.c,v
 * 1.14 1995/03/22 22:07:55 jik Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <pthread.h>
#include <thread.h>
#include <syslog.h>
#include <gssapi/gssapi.h>
#include <rpc/rpc.h>
#include <rpc/rpcsec_defs.h>

static void	rpc_gss_nextverf();
static bool_t	rpc_gss_marshall();
static bool_t	rpc_gss_validate();
static bool_t	rpc_gss_refresh();
static void	rpc_gss_destroy();
static void	rpc_gss_destroy_pvt();
static bool_t	rpc_gss_seccreate_pvt();
static bool_t	validate_seqwin();

/*
 * Globals that should have header files but don't.
 */
extern bool_t	xdr_opaque_auth(XDR *, struct opaque_auth *);


static struct auth_ops rpc_gss_ops = {
	rpc_gss_nextverf,
	rpc_gss_marshall,
	rpc_gss_validate,
	rpc_gss_refresh,
	rpc_gss_destroy
};

/*
 * Private data for RPCSEC_GSS.
 */
typedef struct _rpc_gss_data {
	bool_t			established;	/* TRUE when established */
	CLIENT			*clnt;		/* associated client handle */
	uint_t			version;	/* RPCSEC version */
	gss_ctx_id_t		context;	/* GSS context id */
	gss_buffer_desc		ctx_handle;	/* RPCSEC context handle */
	uint_t			seq_num;	/* last sequence number rcvd */
	gss_cred_id_t		my_cred;	/* GSS credentials */
	OM_uint32		qop;		/* requested QOP */
	rpc_gss_service_t	service;	/* requested service */
	uint_t			gss_proc;	/* GSS control procedure */
	gss_name_t		target_name;	/* target server */
	int			req_flags;	/* GSS request bits */
	gss_OID			mech_type;	/* GSS mechanism */
	OM_uint32		time_req;	/* requested cred lifetime */
	bool_t			invalid;	/* can't use this any more */
	OM_uint32		seq_window;	/* server sequence window */
	struct opaque_auth	*verifier;  /* rpc reply verifier saved for */
					    /* validating the sequence window */
	gss_channel_bindings_t	icb;
} rpc_gss_data;
#define	AUTH_PRIVATE(auth) ((rpc_gss_data *)auth->ah_private)

/*
 * Create a context.
 */
AUTH *
__rpc_gss_seccreate(clnt, server_name, mech, service, qop, options_req,
								options_ret)
	CLIENT			*clnt;		/* associated client handle */
	char			*server_name;	/* target server */
	char			*mech;		/* security mechanism */
	rpc_gss_service_t	service;	/* security service */
	char			*qop;		/* requested QOP */
	rpc_gss_options_req_t	*options_req;	/* requested options */
	rpc_gss_options_ret_t	*options_ret;	/* returned options */
{
	OM_uint32		gssstat;
	OM_uint32		minor_stat;
	gss_name_t		target_name;
	gss_OID			mech_type;
	OM_uint32		ret_flags;
	OM_uint32		time_rec;
	gss_buffer_desc		input_name;
	AUTH			*auth = NULL;
	rpc_gss_data		*ap = NULL;
	OM_uint32		qop_num;

	if (options_ret != NULL) {
		options_ret->major_status = 0;
		options_ret->minor_status = 0;
	}

	/*
	 * convert ascii strings to GSS values
	 */
	if (!__rpc_gss_qop_to_num(qop, mech, &qop_num)) {
		return (NULL);
	}

	if (!__rpc_gss_mech_to_oid(mech, &mech_type)) {
		return (NULL);
	}

	/*
	 * convert name to GSS internal type
	 */
	input_name.value = server_name;
	input_name.length = strlen(server_name);
	gssstat = gss_import_name(&minor_stat, &input_name,
				(gss_OID)GSS_C_NT_HOSTBASED_SERVICE,
				&target_name);
	if (gssstat != GSS_S_COMPLETE) {
		rpc_gss_err.rpc_gss_error = RPC_GSS_ER_SYSTEMERROR;
		rpc_gss_err.system_error = ENOMEM;
		if (options_ret != NULL) {
			options_ret->major_status = gssstat;
			options_ret->minor_status = minor_stat;
		}
		return (NULL);
	}

	/*
	 * Create AUTH handle.  Save the necessary interface information
	 * so that the client can refresh the handle later if needed.
	 */
	if ((auth = (AUTH *) malloc(sizeof (*auth))) != NULL)
		ap = (rpc_gss_data *) malloc(sizeof (*ap));
	if (auth == NULL || ap == NULL) {
		rpc_gss_err.rpc_gss_error = RPC_GSS_ER_SYSTEMERROR;
		rpc_gss_err.system_error = ENOMEM;
		if (auth != NULL)
			free((char *)auth);
		(void) gss_release_name(&minor_stat, &target_name);
		return (NULL);
	}

	memset((char *)ap, 0, sizeof (*ap));
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
		ap->icb = NULL;
	}
	if ((ap->service = service) == rpc_gss_svc_default)
		ap->service = rpc_gss_svc_integrity;
	ap->qop = qop_num;
	ap->target_name = target_name;
	ap->mech_type = mech_type;

	/*
	 * Now invoke the real interface that sets up the context from
	 * the information stashed away in the private data.
	 */
	if (!rpc_gss_seccreate_pvt(&gssstat, &minor_stat, auth, ap,
				&mech_type, &ret_flags, &time_rec)) {
		if (options_ret != NULL) {
			options_ret->major_status = gssstat;
			options_ret->minor_status = minor_stat;
		}
		if (ap->target_name)
			(void) gss_release_name(&minor_stat, &ap->target_name);
		free((char *)ap);
		free((char *)auth);
		return (NULL);
	}

	/*
	 * Make sure that the requested service is supported.  In all
	 * cases, integrity service must be available.
	 */
	if ((ap->service == rpc_gss_svc_privacy &&
					!(ret_flags & GSS_C_CONF_FLAG)) ||
			!(ret_flags & GSS_C_INTEG_FLAG)) {
		rpc_gss_destroy(auth);
		rpc_gss_err.rpc_gss_error = RPC_GSS_ER_SYSTEMERROR;
		rpc_gss_err.system_error = EPROTONOSUPPORT;
		return (NULL);
	}

	/*
	 * return option values if requested
	 */
	if (options_ret != NULL) {
		char	*s;

		options_ret->major_status = gssstat;
		options_ret->minor_status = minor_stat;
		options_ret->rpcsec_version = ap->version;
		options_ret->ret_flags = ret_flags;
		options_ret->time_ret = time_rec;
		options_ret->gss_context = ap->context;
		if ((s = __rpc_gss_oid_to_mech(mech_type)) != NULL)
			strcpy(options_ret->actual_mechanism, s);
		else
			options_ret->actual_mechanism[0] = '\0';
	}
	return (auth);
}

/*
 * Private interface to create a context.  This is the interface
 * that's invoked when the context has to be refreshed.
 */
static bool_t
rpc_gss_seccreate_pvt(gssstat, minor_stat, auth, ap, actual_mech_type,
						ret_flags, time_rec)
	OM_uint32		*gssstat;
	OM_uint32		*minor_stat;
	AUTH			*auth;
	rpc_gss_data		*ap;
	gss_OID			*actual_mech_type;
	OM_uint32		*ret_flags;
	OM_uint32		*time_rec;
{
	CLIENT			*clnt = ap->clnt;
	AUTH			*save_auth;
	enum clnt_stat		callstat;
	rpc_gss_init_arg	call_arg;
	rpc_gss_init_res	call_res;
	gss_buffer_desc		*input_token_p, input_token;
	bool_t			free_results = FALSE;

	/*
	 * initialize error
	 */
	memset(&rpc_createerr, 0, sizeof (rpc_createerr));

	/*
	 * (re)initialize AUTH handle and private data.
	 */
	memset((char *)auth, 0, sizeof (*auth));
	auth->ah_ops = &rpc_gss_ops;
	auth->ah_private = (caddr_t)ap;
	auth->ah_cred.oa_flavor = RPCSEC_GSS;

	ap->established = FALSE;
	ap->ctx_handle.length = 0;
	ap->ctx_handle.value = NULL;
	ap->context = GSS_C_NO_CONTEXT;
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
	input_token_p = GSS_C_NO_BUFFER;

next_token:
	*gssstat = gss_init_sec_context(minor_stat,
					ap->my_cred,
					&ap->context,
					ap->target_name,
					ap->mech_type,
					ap->req_flags,
					ap->time_req,
					NULL,
					input_token_p,
					actual_mech_type,
					&call_arg,
					ret_flags,
					time_rec);

	if (input_token_p != GSS_C_NO_BUFFER) {
		OM_uint32 minor_stat2;

		(void) gss_release_buffer(&minor_stat2, input_token_p);
		input_token_p = GSS_C_NO_BUFFER;
	}

	if (*gssstat != GSS_S_COMPLETE && *gssstat != GSS_S_CONTINUE_NEEDED) {

		goto cleanup;
	}

	/*
	 * if we got a token, pass it on
	 */
	if (call_arg.length != 0) {
		struct timeval timeout = {30, 0};

		memset((char *)&call_res, 0, sizeof (call_res));
		callstat = clnt_call(clnt, NULLPROC,
				__xdr_rpc_gss_init_arg, (caddr_t)&call_arg,
				__xdr_rpc_gss_init_res, (caddr_t)&call_res,
				timeout);
		(void) gss_release_buffer(minor_stat, &call_arg);

		if (callstat != RPC_SUCCESS) {
			goto cleanup;
		}
		/*
		 * we have results - note that these need to be freed
		 */
		free_results = TRUE;

		if (call_res.gss_major != GSS_S_COMPLETE &&
			call_res.gss_major != GSS_S_CONTINUE_NEEDED)
			goto cleanup;

		ap->gss_proc = RPCSEC_GSS_CONTINUE_INIT;

		/*
		 * check for ctx_handle
		 */
		if (ap->ctx_handle.length == 0) {
			if (call_res.ctx_handle.length == 0)
				goto cleanup;
			GSS_DUP_BUFFER(ap->ctx_handle,
				call_res.ctx_handle);
		} else if (!GSS_BUFFERS_EQUAL(ap->ctx_handle,
						call_res.ctx_handle))
			goto cleanup;

		/*
		 * check for token
		 */
		if (call_res.token.length != 0) {
			if (*gssstat == GSS_S_COMPLETE)
				goto cleanup;
			GSS_DUP_BUFFER(input_token, call_res.token);
			input_token_p = &input_token;

		} else if (*gssstat != GSS_S_COMPLETE)
			goto cleanup;

		/* save the sequence window value; validate later */
		ap->seq_window = call_res.seq_window;
		xdr_free(__xdr_rpc_gss_init_res, (caddr_t)&call_res);
		free_results = FALSE;
	}

	/*
	 * results were okay.. continue if necessary
	 */
	if (*gssstat == GSS_S_CONTINUE_NEEDED)
		goto next_token;

	/*
	 * Validate the sequence window - RFC 2203 section 5.2.3.1
	 */
	if (!validate_seqwin(ap)) {
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
	return (TRUE);

cleanup:
	if (ap->context != GSS_C_NO_CONTEXT)
		rpc_gss_destroy_pvt(auth);
	if (free_results)
		xdr_free(__xdr_rpc_gss_init_res, (caddr_t)&call_res);
	clnt->cl_auth = save_auth;	/* restore cl_auth */

/*
 *	if (rpc_createerr.cf_stat == 0)
 *		rpc_createerr.cf_stat = RPC_AUTHERROR;
 */
	if (rpc_createerr.cf_stat == 0) {
		rpc_gss_err.rpc_gss_error = RPC_GSS_ER_SYSTEMERROR;
		rpc_gss_err.system_error = RPC_AUTHERROR;
	}

	return (FALSE);
}

/*
 * Set service defaults.
 */
bool_t
__rpc_gss_set_defaults(auth, service, qop)
	AUTH			*auth;
	rpc_gss_service_t	service;
	char			*qop;
{
	/*LINTED*/
	rpc_gss_data		*ap = AUTH_PRIVATE(auth);
	char			*mech;
	OM_uint32		qop_num;

	switch (service) {
	case rpc_gss_svc_integrity:
	case rpc_gss_svc_privacy:
	case rpc_gss_svc_none:
		break;
	case rpc_gss_svc_default:
		service = rpc_gss_svc_integrity;
		break;
	default:
		return (FALSE);
	}

	if ((mech = __rpc_gss_oid_to_mech(ap->mech_type)) == NULL)
		return (FALSE);

	if (!__rpc_gss_qop_to_num(qop, mech, &qop_num))
		return (FALSE);

	ap->qop = qop_num;
	ap->service = service;
	return (TRUE);
}

/*
 * Marshall credentials.
 */
static bool_t
marshall_creds(ap, xdrs)
	rpc_gss_data		*ap;
	XDR			*xdrs;
{
	rpc_gss_creds		ag_creds;
	char			cred_buf[MAX_AUTH_BYTES];
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

	xdrmem_create(&cred_xdrs, (caddr_t)cred_buf, MAX_AUTH_BYTES,
								XDR_ENCODE);
	if (!__xdr_rpc_gss_creds(&cred_xdrs, &ag_creds)) {
		XDR_DESTROY(&cred_xdrs);
		return (FALSE);
	}

	creds.oa_flavor = RPCSEC_GSS;
	creds.oa_base = cred_buf;
	creds.oa_length = xdr_getpos(&cred_xdrs);
	XDR_DESTROY(&cred_xdrs);

	if (!xdr_opaque_auth(xdrs, &creds))
		return (FALSE);

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
	if ((major = gss_sign(&minor, ap->context, ap->qop, &in_buf,
					&out_buf)) != GSS_S_COMPLETE) {
		if (major == GSS_S_CONTEXT_EXPIRED) {
			ap->invalid = TRUE;
		}
		return (FALSE);
	}
	verf.oa_base = out_buf.value;
	verf.oa_length = out_buf.length;
	ret = xdr_opaque_auth(xdrs, &verf);
	(void) gss_release_buffer(&minor, &out_buf);

	return (ret);
}

/*
 * Function: rpc_gss_nextverf.  Not used.
 */
static void
rpc_gss_nextverf()
{
}

/*
 * Function: rpc_gss_marshall - not used.
 */
static bool_t
rpc_gss_marshall(auth, xdrs)
	AUTH		*auth;
	XDR		*xdrs;
{
	if (!xdr_opaque_auth(xdrs, &auth->ah_cred) ||
				!xdr_opaque_auth(xdrs, &auth->ah_verf))
		return (FALSE);
	return (TRUE);
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

	seq_win_net = (uint_t)htonl(ap->seq_window);
	msg_buf.length = sizeof (seq_win_net);
	msg_buf.value = (char *)&seq_win_net;
	tok_buf.length = ap->verifier->oa_length;
	tok_buf.value = ap->verifier->oa_base;
	major = gss_verify(&minor, ap->context, &msg_buf, &tok_buf, &qop_state);
	if (major != GSS_S_COMPLETE)
		return (FALSE);
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
	/*LINTED*/
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
		ap->verifier = malloc(sizeof (struct opaque_auth));
		memset(ap->verifier, 0, sizeof (struct opaque_auth));
		if (verf->oa_length > 0)
		    ap->verifier->oa_base = malloc(verf->oa_length);
	    } else {
		if (ap->verifier->oa_length > 0)
		    free(ap->verifier->oa_base);
		if (verf->oa_length > 0)
		    ap->verifier->oa_base = malloc(verf->oa_length);
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
	major = gss_verify(&minor, ap->context, &msg_buf, &tok_buf, &qop_state);
	if (major != GSS_S_COMPLETE)
		return (FALSE);
	return (TRUE);
}

/*
 * Refresh client context.  This is necessary sometimes because the
 * server will ocassionally destroy contexts based on LRU method, or
 * because of expired credentials.
 */
static bool_t
rpc_gss_refresh(auth, msg)
	AUTH		*auth;
	struct rpc_msg	*msg;
{
	/*LINTED*/
	rpc_gss_data	*ap = AUTH_PRIVATE(auth);
	OM_uint32	gssstat, minor_stat;

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
		if (ap->context != GSS_C_NO_CONTEXT) {
			(void) gss_delete_sec_context(&minor_stat, &ap->context,
								NULL);
			ap->context = GSS_C_NO_CONTEXT;
		}
		if (ap->ctx_handle.length != 0) {
			(void) gss_release_buffer(&minor_stat,
							&ap->ctx_handle);
			ap->ctx_handle.length = 0;
			ap->ctx_handle.value = NULL;
		}

		/*
		 * If the context was not already established, don't try to
		 * recreate it.
		 */
		if (!ap->established) {
			ap->invalid = TRUE;
			return (FALSE);
		}

		/*
		 * Recreate context.
		 */
		if (rpc_gss_seccreate_pvt(&gssstat, &minor_stat, auth, ap,
		    (gss_OID *)0, (OM_uint32 *)0, (OM_uint32 *)0))
			return (TRUE);
		else {
			ap->invalid = TRUE;
			return (FALSE);
		}
	}
	return (FALSE);
}

/*
 * Destroy a context.
 */
static void
rpc_gss_destroy(auth)
	AUTH		*auth;
{
	/*LINTED*/
	rpc_gss_data	*ap = AUTH_PRIVATE(auth);

	rpc_gss_destroy_pvt(auth);
	free((char *)ap);
	free(auth);
}

/*
 * Private interface to destroy a context without freeing up
 * the memory used by it.  We need to do this when a refresh
 * fails, for example, so the user will still have a handle.
 */
static void
rpc_gss_destroy_pvt(auth)
	AUTH		*auth;
{
	struct timeval	timeout;
	OM_uint32	minor_stat;
	/*LINTED*/
	rpc_gss_data	*ap = AUTH_PRIVATE(auth);

	/*
	 * If we have a server context id, inform server that we are
	 * destroying the context.
	 */
	if (ap->ctx_handle.length != 0) {
		ap->gss_proc = RPCSEC_GSS_DESTROY;
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		(void) clnt_call(ap->clnt, NULLPROC, xdr_void, NULL,
						xdr_void, NULL, timeout);

		(void) gss_release_buffer(&minor_stat, &ap->ctx_handle);
		ap->ctx_handle.length = 0;
		ap->ctx_handle.value = NULL;
	}

	/*
	 * Destroy local GSS context.
	 */
	if (ap->context != GSS_C_NO_CONTEXT) {
		(void) gss_delete_sec_context(&minor_stat, &ap->context, NULL);
		ap->context = GSS_C_NO_CONTEXT;
	}

	/*
	 * Looks like we need to release default credentials if we use it.
	 * Non-default creds need to be released by user.
	 */
	if (ap->my_cred == GSS_C_NO_CREDENTIAL)
		(void) gss_release_cred(&minor_stat, &ap->my_cred);

	/*
	 * Release any internal name structures.
	 */
	if (ap->target_name != NULL) {
		(void) gss_release_name(&minor_stat, &ap->target_name);
		ap->target_name = NULL;
	}

	/*
	 * Free the verifier saved for sequence window checking.
	 */
	if (ap->verifier != NULL) {
	    if (ap->verifier->oa_length > 0)
		free(ap->verifier->oa_base);
	    free(ap->verifier);
	    ap->verifier = NULL;
	}
}

/*
 * Wrap client side data.  The encoded header is passed in through
 * buf and buflen.  The header is up to but not including the
 * credential field.
 */
bool_t
__rpc_gss_wrap(auth, buf, buflen, out_xdrs, xdr_func, xdr_ptr)
	AUTH			*auth;
	char			*buf;		/* encoded header */
	uint_t			buflen;		/* encoded header length */
	XDR			*out_xdrs;
	bool_t			(*xdr_func)();
	caddr_t			xdr_ptr;
{
	/*LINTED*/
	rpc_gss_data		*ap = AUTH_PRIVATE(auth);
	XDR			xdrs;
	char			tmp_buf[512];


	/*
	 * Reject an invalid context.
	 */
	if (ap->invalid)
		return (FALSE);

	/*
	 * If context is established, bump up sequence number.
	 */
	if (ap->established)
		ap->seq_num++;

	/*
	 * Create the header in a temporary XDR context and buffer
	 * before putting it out.
	 */
	xdrmem_create(&xdrs, tmp_buf, sizeof (tmp_buf), XDR_ENCODE);
	if (!XDR_PUTBYTES(&xdrs, buf, buflen))
		return (FALSE);

	/*
	 * create cred field
	 */
	if (!marshall_creds(ap, &xdrs))
		return (FALSE);

	/*
	 * create verifier
	 */
	if (!marshall_verf(ap, &xdrs, tmp_buf))
		return (FALSE);

	/*
	 * write out header and destroy temp structures
	 */
	if (!XDR_PUTBYTES(out_xdrs, tmp_buf, XDR_GETPOS(&xdrs)))
		return (FALSE);
	XDR_DESTROY(&xdrs);

	/*
	 * If context is not established, or if neither integrity
	 * nor privacy is used, just XDR encode data.
	 */
	if (!ap->established || ap->service == rpc_gss_svc_none)
		return ((*xdr_func)(out_xdrs, xdr_ptr));

	return (__rpc_gss_wrap_data(ap->service, ap->qop, ap->context,
				ap->seq_num, out_xdrs, xdr_func, xdr_ptr));
}

/*
 * Unwrap received data.
 */
bool_t
__rpc_gss_unwrap(auth, in_xdrs, xdr_func, xdr_ptr)
	AUTH			*auth;
	XDR			*in_xdrs;
	bool_t			(*xdr_func)();
	caddr_t			xdr_ptr;
{
	/*LINTED*/
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

int
__rpc_gss_max_data_length(auth, max_tp_unit_len)
	AUTH		*auth;
	int		max_tp_unit_len;
{
	/*LINTED*/
	rpc_gss_data		*ap = AUTH_PRIVATE(auth);

	if (!ap->established || max_tp_unit_len <= 0)
		return (0);

	return (__find_max_data_length(ap->service,
			ap->context,
			ap->qop,
			max_tp_unit_len));
}

void
__rpc_gss_get_error(rpc_gss_error_t *error)
{
	*error = rpc_gss_err;
}

#undef  rpc_gss_err

rpc_gss_error_t	rpc_gss_err;

rpc_gss_error_t *
__rpc_gss_err()
{
	static thread_key_t rpc_gss_err_key = THR_ONCE_KEY;
	rpc_gss_error_t *tsd;

	if (thr_main())
		return (&rpc_gss_err);
	if (thr_keycreate_once(&rpc_gss_err_key, free) != 0)
		return (&rpc_gss_err);
	tsd = pthread_getspecific(rpc_gss_err_key);
	if (tsd == NULL) {
		tsd = (rpc_gss_error_t *)calloc(1, sizeof (rpc_gss_error_t));
		if (thr_setspecific(rpc_gss_err_key, tsd) != 0) {
			if (tsd)
				free(tsd);
			return (&rpc_gss_err);
		}
	}
	return (tsd);
}
