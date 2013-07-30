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
 * Copyright 1996,1997,1999,2002-2003 Sun Microsystems, Inc.
 * All rights reserved.  Use is subject to license terms.
 */

/*
 * Copyright 1993 OpenVision Technologies, Inc., All Rights Reserved.
 *
 * $Header:
 * /afs/gza.com/product/secure/rel-eng/src/1.1/rpc/RCS/auth_gssapi_misc.c,v 1.10
 * 1994/10/27 12:39:23 jik Exp $
 */

/*
 * Copyright (c) 2013 by Delphix. All rights reserved.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/cmn_err.h>
#include <gssapi/gssapi.h>
#include <rpc/rpc.h>
#include <rpc/rpcsec_defs.h>

/*
 * The initial allocation size for dynamic allocation.
 */
#define	CKU_INITSIZE    2048

/*
 * The size of additional allocations, if required.  It is larger to
 * reduce the number of actual allocations.
 */
#define	CKU_ALLOCSIZE   8192


/*
 * Miscellaneous XDR routines.
 */
bool_t
__xdr_gss_buf(xdrs, buf)
	XDR		*xdrs;
	gss_buffer_t	buf;
{
	uint_t cast_len, bound_len;

	/*
	 * We go through this contortion because size_t is a now a ulong,
	 * GSS-API uses ulongs.
	 */

	if (xdrs->x_op != XDR_DECODE) {
		bound_len = cast_len = (uint_t)buf->length;
	} else {
		bound_len = (uint_t)-1;
	}

	if (xdr_bytes(xdrs, (char **)&buf->value, &cast_len,
	    bound_len) == TRUE) {
		if (xdrs->x_op == XDR_DECODE)
			buf->length = cast_len;

		return (TRUE);
	}

	return (FALSE);
}

bool_t
__xdr_rpc_gss_creds(xdrs, creds)
	XDR			*xdrs;
	rpc_gss_creds		*creds;
{
	if (!xdr_u_int(xdrs, (uint_t *)&creds->version) ||
				!xdr_u_int(xdrs, (uint_t *)&creds->gss_proc) ||
				!xdr_u_int(xdrs, (uint_t *)&creds->seq_num) ||
				!xdr_u_int(xdrs, (uint_t *)&creds->service) ||
				!__xdr_gss_buf(xdrs, &creds->ctx_handle))
		return (FALSE);
	return (TRUE);
}

bool_t
__xdr_rpc_gss_init_arg(xdrs, init_arg)
	XDR			*xdrs;
	rpc_gss_init_arg	*init_arg;
{
	if (!__xdr_gss_buf(xdrs, init_arg))
		return (FALSE);
	return (TRUE);
}

bool_t
__xdr_rpc_gss_init_res(xdrs, init_res)
	XDR			*xdrs;
	rpc_gss_init_res	*init_res;
{
	if (!__xdr_gss_buf(xdrs, &init_res->ctx_handle) ||
			!xdr_u_int(xdrs, (uint_t *)&init_res->gss_major) ||
			!xdr_u_int(xdrs, (uint_t *)&init_res->gss_minor) ||
			!xdr_u_int(xdrs, (uint_t *)&init_res->seq_window) ||
			!__xdr_gss_buf(xdrs, &init_res->token))
		return (FALSE);
	return (TRUE);
}

/*
 * Generic routine to wrap data used by client and server sides.
 */
bool_t
__rpc_gss_wrap_data(service, qop, context, seq_num, out_xdrs,
			xdr_func, xdr_ptr)
	OM_uint32		qop;
	rpc_gss_service_t	service;
	gss_ctx_id_t		context;
	uint_t			seq_num;
	XDR			*out_xdrs;
	bool_t			(*xdr_func)();
	caddr_t			xdr_ptr;
{
	OM_uint32		major, minor;
	gss_buffer_desc		in_buf, out_buf;
	XDR			temp_xdrs;
	char			*temp_data;
	bool_t			conf_state;
	bool_t			ret = FALSE;
	int			size;

	/*
	 * Create a temporary XDR/buffer to hold the data to be wrapped.
	 * We need an extra bit for the sequence number serialized first.
	 */
	size = xdr_sizeof(xdr_func, xdr_ptr) + BYTES_PER_XDR_UNIT;
	temp_data = kmem_alloc(size, KM_SLEEP);
	out_buf.length = 0;

	xdrmem_create(&temp_xdrs, temp_data, size, XDR_ENCODE);

	/*
	 * serialize the sequence number into tmp memory
	 */
	if (!xdr_u_int(&temp_xdrs, &seq_num))
		goto fail;

	/*
	 * serialize the arguments into tmp memory
	 */
	if (!(*xdr_func)(&temp_xdrs, xdr_ptr))
		goto fail;

	/*
	 * Data to be wrapped goes in in_buf.  If privacy is used,
	 * out_buf will have wrapped data (in_buf will no longer be
	 * needed).  If integrity is used, out_buf will have checksum
	 * which will follow the data in in_buf.
	 */
	in_buf.length = xdr_getpos(&temp_xdrs);
	in_buf.value = (char *)temp_xdrs.x_base;

	switch (service) {
	case rpc_gss_svc_privacy:

		if ((major = kgss_seal(&minor, context, TRUE, qop, &in_buf,
				&conf_state, &out_buf)) != GSS_S_COMPLETE) {
			RPCGSS_LOG1(1, "rpc_gss_wrap: kgss_seal failed."
				"major = %x, minor = %x", major, minor);
			goto fail;
		}
		in_buf.length = 0;	/* in_buf not needed */
		if (!conf_state)
			goto fail;
		break;
	case rpc_gss_svc_integrity:
		if ((major = kgss_sign(&minor, context, qop, &in_buf,
				&out_buf)) != GSS_S_COMPLETE) {
			RPCGSS_LOG1(1, "rpc_gss_wrap: kgss_sign failed."
				"major = %x, minor = %x", major, minor);
			goto fail;
		}
		break;
	default:
		goto fail;
	}

	/*
	 * write out in_buf and out_buf as needed
	 */
	if (in_buf.length != 0) {
		if (!__xdr_gss_buf(out_xdrs, &in_buf))
			goto fail;
	}

	if (!__xdr_gss_buf(out_xdrs, &out_buf))
		goto fail;
	ret = TRUE;
fail:
	kmem_free(temp_data, size);
	if (out_buf.length != 0)
		(void) gss_release_buffer(&minor, &out_buf);
	return (ret);
}

/*
 * Generic routine to unwrap data used by client and server sides.
 */
bool_t
__rpc_gss_unwrap_data(service, context, seq_num, qop_check, in_xdrs,
			xdr_func, xdr_ptr)
	rpc_gss_service_t	service;
	gss_ctx_id_t		context;
	uint_t			seq_num;
	OM_uint32		qop_check;
	XDR			*in_xdrs;
	bool_t			(*xdr_func)();
	caddr_t			xdr_ptr;
{
	gss_buffer_desc		in_buf, out_buf;
	XDR			temp_xdrs;
	uint_t			seq_num2;
	bool_t			conf = FALSE;
	OM_uint32		major = GSS_S_COMPLETE, minor = 0;
	int			qop = 0;

	in_buf.value = NULL;
	out_buf.value = NULL;

	/*
	 * Pull out wrapped data.  For privacy service, this is the
	 * encrypted data.  For integrity service, this is the data
	 * followed by a checksum.
	 */
	if (!__xdr_gss_buf(in_xdrs, &in_buf)) {
		return (FALSE);
	}

	if (service == rpc_gss_svc_privacy) {
		major = GSS_S_FAILURE;
		major = kgss_unseal(&minor, context, &in_buf, &out_buf, &conf,
					&qop);
		kmem_free(in_buf.value, in_buf.length);
		if (major != GSS_S_COMPLETE) {
			RPCGSS_LOG1(1, "rpc_gss_unwrap: kgss_unseal failed."
				"major = %x, minor = %x", major, minor);
			return (FALSE);
		}
		/*
		 * Keep the returned token (unencrypted data) in in_buf.
		 */
		in_buf.length = out_buf.length;
		in_buf.value = out_buf.value;

		/*
		 * If privacy was not used, or if QOP is not what we are
		 * expecting, fail.
		 */
		if (!conf || qop != qop_check)
			goto fail;

	} else if (service == rpc_gss_svc_integrity) {
		if (!__xdr_gss_buf(in_xdrs, &out_buf)) {
			return (FALSE);
		}
		major = kgss_verify(&minor, context, &in_buf, &out_buf,
				&qop);
		kmem_free(out_buf.value, out_buf.length);
		if (major != GSS_S_COMPLETE) {
			kmem_free(in_buf.value, in_buf.length);
			RPCGSS_LOG1(1, "rpc_gss_unwrap: kgss_verify failed."
				"major = %x, minor = %x", major, minor);
			return (FALSE);
		}

		/*
		 * If QOP is not what we are expecting, fail.
		 */
		if (qop != qop_check)
			goto fail;
	}

	xdrmem_create(&temp_xdrs, in_buf.value, in_buf.length, XDR_DECODE);

	/*
	 * The data consists of the sequence number followed by the
	 * arguments.  Make sure sequence number is what we are
	 * expecting (i.e., the value in the header).
	 */
	if (!xdr_u_int(&temp_xdrs, &seq_num2))
		goto fail;
	if (seq_num2 != seq_num)
		goto fail;

	/*
	 * Deserialize the arguments into xdr_ptr, and release in_buf.
	 */
	if (!(*xdr_func)(&temp_xdrs, xdr_ptr)) {
		goto fail;
	}

	if (service == rpc_gss_svc_privacy)
		(void) gss_release_buffer(&minor, &in_buf);
	else
		kmem_free(in_buf.value, in_buf.length);
	XDR_DESTROY(&temp_xdrs);
	return (TRUE);
fail:
	XDR_DESTROY(&temp_xdrs);
	if (service == rpc_gss_svc_privacy)
		(void) gss_release_buffer(&minor, &in_buf);
	else
		kmem_free(in_buf.value, in_buf.length);
	return (FALSE);
}
