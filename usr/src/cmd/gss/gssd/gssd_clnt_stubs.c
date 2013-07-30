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
 */

/*
 *  GSSAPI library stub module for gssd.
 */

#include <stdio.h>
#include <stdlib.h>
#include <mechglueP.h>
#include "gssd.h"
#include <rpc/rpc.h>

#ifdef	_KERNEL
#define	MALLOC(n) kmem_alloc((n), KM_SLEEP)
#define	FREE(x, n) kmem_free((x), (n))
#define	memcpy(dst, src, n) bcopy((src), (dst), (n))
#define	clnt_pcreateerror(srv) printf("Cannot connect to server on %s\n", srv)

#ifdef	DEBUG
#ifndef	_SYS_CMN_ERR_H
#define	_SYS_CMN_ERR_H
#define	CE_NOTE 1
#endif
#include <sys/types.h>
#include <sys/devops.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/uio.h>
#endif /* DEBUG */

#else /* !_KERNEL */
#define	MALLOC(n) malloc(n)
#define	FREE(x, n) free(x)
#endif /* _KERNEL */
#define	DEFAULT_MINOR_STAT	((OM_uint32) ~0)

CLIENT  *clnt, *getgssd_handle();
char *server = "localhost";

OM_uint32
kgss_acquire_cred_wrapped(minor_status,
			desired_name,
			time_req,
			desired_mechs,
			cred_usage,
			output_cred_handle,
			actual_mechs,
			time_rec,
			uid,
			gssd_cred_verifier)
	OM_uint32 *minor_status;
	gss_name_t desired_name;
	OM_uint32 time_req;
	gss_OID_set desired_mechs;
	int cred_usage;
	gssd_cred_id_t *output_cred_handle;
	gss_OID_set *actual_mechs;
	OM_uint32 *time_rec;
	uid_t uid;
	OM_uint32 *gssd_cred_verifier;
{
	OM_uint32 minor_status_temp;
	gss_buffer_desc	external_name;
	gss_OID name_type;
	int i;

	gss_acquire_cred_arg arg;
	gss_acquire_cred_res res;

	/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* convert the desired name from internal to external format */

	if (gss_display_name(&minor_status_temp, desired_name, &external_name,
				&name_type) != GSS_S_COMPLETE) {

			*minor_status = (OM_uint32) minor_status_temp;
			gss_release_buffer(&minor_status_temp, &external_name);
		return ((OM_uint32) GSS_S_FAILURE);
	}


	/* copy the procedure arguments into the rpc arg parameter */

	arg.uid = (OM_uint32)uid;

	arg.desired_name.GSS_BUFFER_T_len = (uint_t)external_name.length;
	arg.desired_name.GSS_BUFFER_T_val = (char *)external_name.value;

	arg.name_type.GSS_OID_len =
		name_type == GSS_C_NULL_OID ?
			0 : (uint_t)name_type->length;

	arg.name_type.GSS_OID_val =
		name_type == GSS_C_NULL_OID ?
			(char *)NULL : (char *)name_type->elements;

	arg.time_req = time_req;

	if (desired_mechs != GSS_C_NULL_OID_SET) {
		arg.desired_mechs.GSS_OID_SET_len =
			(uint_t)desired_mechs->count;
		arg.desired_mechs.GSS_OID_SET_val = (GSS_OID *)
			MALLOC(sizeof (GSS_OID) * desired_mechs->count);

		for (i = 0; i < desired_mechs->count; i++) {
			arg.desired_mechs.GSS_OID_SET_val[i].GSS_OID_len =
				(uint_t)desired_mechs->elements[i].length;
			arg.desired_mechs.GSS_OID_SET_val[i].GSS_OID_val =
				(char *)
				MALLOC(desired_mechs->elements[i].length);
			memcpy(arg.desired_mechs.GSS_OID_SET_val[i].GSS_OID_val,
				desired_mechs->elements[i].elements,
				desired_mechs->elements[i].length);
		}
	} else
		arg.desired_mechs.GSS_OID_SET_len = 0;

	arg.cred_usage = cred_usage;

	/* call the remote procedure */

	memset(&res, 0, sizeof (res));
	if (gss_acquire_cred_1(&arg, &res, clnt) != RPC_SUCCESS) {

	/*
	 * if the RPC call times out, null out all return arguments,
	 * set minor_status to its maximum value, and return GSS_S_FAILURE
	 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		if (output_cred_handle != NULL)
			*output_cred_handle = NULL;
		if (actual_mechs != NULL)
			*actual_mechs = NULL;
		if (time_rec != NULL)
			*time_rec = 0;

		return (GSS_S_FAILURE);
	}

	/* free the allocated memory for the flattened name and desire_mechs */

	gss_release_buffer(&minor_status_temp, &external_name);
	for (i = 0; i < desired_mechs->count; i++)
		FREE(arg.desired_mechs.GSS_OID_SET_val[i].GSS_OID_val,
			arg.desired_mechs.GSS_OID_SET_val[i].GSS_OID_len);
	FREE(arg.desired_mechs.GSS_OID_SET_val,
		arg.desired_mechs.GSS_OID_SET_len * sizeof (GSS_OID));

	/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	if (output_cred_handle != NULL) {
		 *output_cred_handle =
		/*LINTED*/
		*((gssd_cred_id_t *)res.output_cred_handle.GSS_CRED_ID_T_val);
		 *gssd_cred_verifier = res.gssd_cred_verifier;
	}

	if (res.status == GSS_S_COMPLETE &&
		res.actual_mechs.GSS_OID_SET_len != 0 &&
		actual_mechs != NULL) {
		*actual_mechs = (gss_OID_set) MALLOC(sizeof (gss_OID_set_desc));
		(*actual_mechs)->count =
			(int)res.actual_mechs.GSS_OID_SET_len;
		(*actual_mechs)->elements = (gss_OID)
			MALLOC(sizeof (gss_OID_desc) * (*actual_mechs)->count);

		for (i = 0; i < (*actual_mechs)->count; i++) {
			(*actual_mechs)->elements[i].length = (OM_uint32)
			res.actual_mechs.GSS_OID_SET_val[i].GSS_OID_len;
			(*actual_mechs)->elements[i].elements =
			(void *) MALLOC((*actual_mechs)->elements[i].length);
			memcpy((*actual_mechs)->elements[i].elements,
			res.actual_mechs.GSS_OID_SET_val[i].GSS_OID_val,
			(*actual_mechs)->elements[i].length);
		}
	} else {
		if (res.status == GSS_S_COMPLETE && actual_mechs != NULL)
			(*actual_mechs)->count = 0;
	}

	if (time_rec != NULL)
		*time_rec = res.time_rec;

	/*
	 * free the memory allocated for the results and return with the status
	 * received in the rpc call
	 */

	clnt_freeres(clnt, xdr_gss_acquire_cred_res, (caddr_t)&res);
	return (res.status);
}

OM_uint32
kgss_acquire_cred(minor_status,
		desired_name,
		time_req,
		desired_mechs,
		cred_usage,
		output_cred_handle,
		actual_mechs,
		time_rec,
		uid)
	OM_uint32 *minor_status;
	gss_name_t desired_name;
	OM_uint32 time_req;
	gss_OID_set desired_mechs;
	int cred_usage;
	gss_cred_id_t *output_cred_handle;
	gss_OID_set *actual_mechs;
	OM_uint32 *time_rec;
	uid_t uid;
{

		OM_uint32	err;
		struct kgss_cred *kcred;

		kcred = KGSS_CRED_ALLOC();
		*output_cred_handle = (gss_cred_id_t)kcred;
		err = kgss_acquire_cred_wrapped(minor_status,
					desired_name, time_req,
					desired_mechs, cred_usage,
					&kcred->gssd_cred, actual_mechs,
					time_rec, uid,
					&kcred->gssd_cred_verifier);
		if (GSS_ERROR(err)) {
			KGSS_CRED_FREE(kcred);
			*output_cred_handle = GSS_C_NO_CREDENTIAL;
		}
		return (err);
}

OM_uint32
kgss_add_cred_wrapped(minor_status,
			input_cred_handle,
			gssd_cred_verifier,
			desired_name,
			desired_mech_type,
			cred_usage,
			initiator_time_req,
			acceptor_time_req,
			actual_mechs,
			initiator_time_rec,
			acceptor_time_rec,
			uid)
	OM_uint32 *minor_status;
	gssd_cred_id_t input_cred_handle;
	OM_uint32 gssd_cred_verifier;
	gss_name_t desired_name;
	gss_OID desired_mech_type;
	int cred_usage;
	int initiator_time_req;
	int acceptor_time_req;
	gss_OID_set *actual_mechs;
	OM_uint32 *initiator_time_rec;
	OM_uint32 *acceptor_time_rec;
	uid_t uid;
{
	CLIENT *clnt;

	OM_uint32 	minor_status_temp;
	gss_buffer_desc	external_name;
	gss_OID		name_type;
	int		i;

	gss_add_cred_arg arg;
	gss_add_cred_res res;

	/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}


	/* convert the desired name from internal to external format */

	if (gss_display_name(&minor_status_temp, desired_name, &external_name,
				&name_type) != GSS_S_COMPLETE) {

		*minor_status = (OM_uint32) minor_status_temp;
		(void) gss_release_buffer(&minor_status_temp, &external_name);
		clnt_pcreateerror(server);
		return ((OM_uint32) GSS_S_FAILURE);
	}


	/* copy the procedure arguments into the rpc arg parameter */

	arg.uid = (OM_uint32) uid;
	arg.input_cred_handle.GSS_CRED_ID_T_len =
			input_cred_handle == GSSD_NO_CREDENTIAL ?
			0 : (uint_t)sizeof (gssd_cred_id_t);
	arg.input_cred_handle.GSS_CRED_ID_T_val =
						(char *)&input_cred_handle;
	arg.gssd_cred_verifier = gssd_cred_verifier;
	arg.desired_name.GSS_BUFFER_T_len = (uint_t)external_name.length;
	arg.desired_name.GSS_BUFFER_T_val = (char *)external_name.value;
	arg.name_type.GSS_OID_len =
		name_type == GSS_C_NULL_OID ?
			0 : (uint_t)name_type->length;
	arg.name_type.GSS_OID_val =
		name_type == GSS_C_NULL_OID ?
			(char *)NULL : (char *)name_type->elements;

	arg.desired_mech_type.GSS_OID_len =
		(uint_t)(desired_mech_type != GSS_C_NULL_OID ?
		desired_mech_type->length : 0);
	arg.desired_mech_type.GSS_OID_val =
		(char *)(desired_mech_type != GSS_C_NULL_OID ?
		desired_mech_type->elements : 0);
	arg.cred_usage = cred_usage;
	arg.initiator_time_req = initiator_time_req;
	arg.acceptor_time_req = acceptor_time_req;

	/* call the remote procedure */

	bzero((caddr_t)&res, sizeof (res));
	if (gss_add_cred_1(&arg, &res, clnt) != RPC_SUCCESS) {

		/*
		 * if the RPC call times out, null out all return arguments,
		 * set minor_status to its maximum value, and return
		 * GSS_S_FAILURE
		 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		if (actual_mechs != NULL)
			*actual_mechs = NULL;
		if (initiator_time_rec != NULL)
			*initiator_time_rec = 0;
		if (acceptor_time_rec != NULL)
			*acceptor_time_rec = 0;
		return (GSS_S_FAILURE);
	}

	/* free the allocated memory for the flattened name */

	(void) gss_release_buffer(&minor_status_temp, &external_name);

	/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	if (res.status == GSS_S_COMPLETE &&
		res.actual_mechs.GSS_OID_SET_len != 0 &&
		actual_mechs != NULL) {
		*actual_mechs = (gss_OID_set) MALLOC(sizeof (gss_OID_set_desc));
		(*actual_mechs)->count =
					(int)res.actual_mechs.GSS_OID_SET_len;
		(*actual_mechs)->elements = (gss_OID)
			MALLOC(sizeof (gss_OID_desc) * (*actual_mechs)->count);

		for (i = 0; i < (*actual_mechs)->count; i++) {
		    (*actual_mechs)->elements[i].length = (OM_uint32)
			res.actual_mechs.GSS_OID_SET_val[i].GSS_OID_len;
		    (*actual_mechs)->elements[i].elements =
			(void *) MALLOC((*actual_mechs)->elements[i].length);
		    memcpy((*actual_mechs)->elements[i].elements,
			res.actual_mechs.GSS_OID_SET_val[i].GSS_OID_val,
			(*actual_mechs)->elements[i].length);
		}
	} else {
		if (res.status == GSS_S_COMPLETE &&
			actual_mechs != NULL)
			(*actual_mechs)->count = 0;
	}
	if (initiator_time_rec != NULL)
		*initiator_time_rec = res.initiator_time_rec;
	if (acceptor_time_rec != NULL)
		*acceptor_time_rec = res.acceptor_time_rec;

	/*
	 * free the memory allocated for the results and return with the status
	 * received in the rpc call
	 */

	clnt_freeres(clnt, xdr_gss_add_cred_res, (caddr_t)&res);
	return (res.status);

}

OM_uint32
kgss_add_cred(minor_status,
			input_cred_handle,
			desired_name,
			desired_mech_type,
			cred_usage,
			initiator_time_req,
			acceptor_time_req,
			actual_mechs,
			initiator_time_rec,
			acceptor_time_rec,
			uid)
	OM_uint32 *minor_status;
	gss_cred_id_t input_cred_handle;
	gss_name_t desired_name;
	gss_OID desired_mech_type;
	int cred_usage;
	int initiator_time_req;
	int acceptor_time_req;
	gss_OID_set *actual_mechs;
	OM_uint32 *initiator_time_rec;
	OM_uint32 *acceptor_time_rec;
	uid_t uid;
{

	OM_uint32	err;
	OM_uint32 gssd_cred_verifier;
	gssd_cred_id_t gssd_input_cred_handle;


	if (input_cred_handle != GSS_C_NO_CREDENTIAL) {
		gssd_cred_verifier = KCRED_TO_CREDV(input_cred_handle);
		gssd_input_cred_handle = KCRED_TO_CRED(input_cred_handle);
	} else
		gssd_input_cred_handle = GSSD_NO_CREDENTIAL;

	err = kgss_add_cred_wrapped(minor_status, gssd_input_cred_handle,
			gssd_cred_verifier, desired_name, desired_mech_type,
			cred_usage, initiator_time_req, acceptor_time_req,
			actual_mechs, initiator_time_rec,
			acceptor_time_rec, uid);
	return (err);
}

OM_uint32
kgss_release_cred_wrapped(minor_status,
		cred_handle,
		uid,
		gssd_cred_verifier)
OM_uint32 *minor_status;
gssd_cred_id_t *cred_handle;
uid_t uid;
OM_uint32 gssd_cred_verifier;
{

	gss_release_cred_arg arg;
	gss_release_cred_res res;


	/* get the client handle to GSSD */
	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* copy the procedure arguments into the rpc arg parameter */

	arg.uid = (OM_uint32) uid;
	arg.gssd_cred_verifier = gssd_cred_verifier;

	if (cred_handle != NULL) {
		arg.cred_handle.GSS_CRED_ID_T_len =
			(uint_t)sizeof (gssd_cred_id_t);
		arg.cred_handle.GSS_CRED_ID_T_val = (char *)cred_handle;
	} else
		arg.cred_handle.GSS_CRED_ID_T_len = 0;

	/* call the remote procedure */

	memset(&res, 0, sizeof (res));
	if (gss_release_cred_1(&arg, &res, clnt) != RPC_SUCCESS) {

		/*
		 * if the RPC call times out, null out all return arguments,
		 * set minor_status to its max value, and return GSS_S_FAILURE
		 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		if (cred_handle != NULL)
			*cred_handle = NULL;

		return (GSS_S_FAILURE);
	}

	/* if the release succeeded, null out the cred_handle */
	if (res.status == GSS_S_COMPLETE && cred_handle != NULL)
		*cred_handle = NULL;

	/* copy the rpc results into the return arguments */
	if (minor_status != NULL)
		*minor_status = res.minor_status;

	/* return with status returned in rpc call */
	return (res.status);
}

OM_uint32
kgss_release_cred(minor_status,
			cred_handle,
			uid)
	OM_uint32 *minor_status;
	gss_cred_id_t *cred_handle;
	uid_t uid;

{

		OM_uint32	err;
		struct kgss_cred *kcred;

		if (*cred_handle == GSS_C_NO_CREDENTIAL)
			return (GSS_S_COMPLETE);
		else
			kcred = KCRED_TO_KGSS_CRED(*cred_handle);

		err = kgss_release_cred_wrapped(minor_status, &kcred->gssd_cred,
			uid, kcred->gssd_cred_verifier);
		KGSS_CRED_FREE(kcred);
		*cred_handle = GSS_C_NO_CREDENTIAL;
		return (err);
}

OM_uint32
kgss_init_sec_context_wrapped(minor_status,
			claimant_cred_handle,
			gssd_cred_verifier,
			context_handle,
			gssd_context_verifier,
		target_name,
		mech_type,
		req_flags,
		time_req,
		input_chan_bindings,
		input_token,
		actual_mech_type,
		output_token,
		ret_flags,
		time_rec,
		uid)
	OM_uint32 *minor_status;
	gssd_cred_id_t claimant_cred_handle;
	OM_uint32 gssd_cred_verifier;
	OM_uint32 *context_handle;
	OM_uint32 *gssd_context_verifier;
	gss_name_t target_name;
	gss_OID mech_type;
	int req_flags;
	OM_uint32 time_req;
	gss_channel_bindings_t input_chan_bindings;
	gss_buffer_t input_token;
	gss_OID *actual_mech_type;
	gss_buffer_t output_token;
	int *ret_flags;
	OM_uint32 *time_rec;
	uid_t uid;
{
	OM_uint32 minor_status_temp;
	gss_buffer_desc external_name;
	gss_OID name_type;
	gss_init_sec_context_arg arg;
	gss_init_sec_context_res res;

	/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* convert the target name from internal to external format */

	if (gss_display_name(&minor_status_temp, target_name,
			&external_name, &name_type) != GSS_S_COMPLETE) {

		*minor_status = (OM_uint32) minor_status_temp;
		return ((OM_uint32) GSS_S_FAILURE);
	}


/* copy the procedure arguments into the rpc arg parameter */

	arg.uid = (OM_uint32) uid;

	arg.context_handle.GSS_CTX_ID_T_len =
		*context_handle == (OM_uint32) GSS_C_NO_CONTEXT ? 0 :
		(uint_t)sizeof (OM_uint32);
	arg.context_handle.GSS_CTX_ID_T_val =  (char *)context_handle;
	arg.gssd_context_verifier = *gssd_context_verifier;

	arg.claimant_cred_handle.GSS_CRED_ID_T_len =
		claimant_cred_handle == GSSD_NO_CREDENTIAL ?
		0 : (uint_t)sizeof (gssd_cred_id_t);
	arg.claimant_cred_handle.GSS_CRED_ID_T_val =
		(char *)&claimant_cred_handle;
	arg.gssd_cred_verifier =  gssd_cred_verifier;

	arg.target_name.GSS_BUFFER_T_len = (uint_t)external_name.length;
	arg.target_name.GSS_BUFFER_T_val = (char *)external_name.value;

	arg.name_type.GSS_OID_len =
		name_type == GSS_C_NULL_OID ?
		0 : (uint_t)name_type->length;

	arg.name_type.GSS_OID_val =
		name_type == GSS_C_NULL_OID ?
		(char *)NULL : (char *)name_type->elements;

	arg.mech_type.GSS_OID_len = (uint_t)(mech_type != GSS_C_NULL_OID ?
				mech_type->length : 0);
	arg.mech_type.GSS_OID_val = (char *)(mech_type != GSS_C_NULL_OID ?
				mech_type->elements : 0);

	arg.req_flags = req_flags;

	arg.time_req = time_req;

	if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) {
		arg.input_chan_bindings.present = YES;
		arg.input_chan_bindings.initiator_addrtype =
			input_chan_bindings->initiator_addrtype;
		arg.input_chan_bindings.initiator_address.GSS_BUFFER_T_len =
			(uint_t)input_chan_bindings->initiator_address.length;
		arg.input_chan_bindings.initiator_address.GSS_BUFFER_T_val =
			(void *) input_chan_bindings->initiator_address.value;
		arg.input_chan_bindings.acceptor_addrtype =
			input_chan_bindings->acceptor_addrtype;
		arg.input_chan_bindings.acceptor_address.GSS_BUFFER_T_len =
			(uint_t)input_chan_bindings->acceptor_address.length;
		arg.input_chan_bindings.acceptor_address.GSS_BUFFER_T_val =
			(void *) input_chan_bindings->acceptor_address.value;
		arg.input_chan_bindings.application_data.GSS_BUFFER_T_len =
			(uint_t)input_chan_bindings->application_data.length;
		arg.input_chan_bindings.application_data.GSS_BUFFER_T_val =
			(void *) input_chan_bindings->application_data.value;
	} else {
		arg.input_chan_bindings.present = NO;
		arg.input_chan_bindings.initiator_addrtype = 0;
		arg.input_chan_bindings.initiator_address.GSS_BUFFER_T_len = 0;
		arg.input_chan_bindings.initiator_address.GSS_BUFFER_T_val = 0;
		arg.input_chan_bindings.acceptor_addrtype = 0;
		arg.input_chan_bindings.acceptor_address.GSS_BUFFER_T_len = 0;
		arg.input_chan_bindings.acceptor_address.GSS_BUFFER_T_val = 0;
		arg.input_chan_bindings.application_data.GSS_BUFFER_T_len = 0;
		arg.input_chan_bindings.application_data.GSS_BUFFER_T_val = 0;
	}

	arg.input_token.GSS_BUFFER_T_len = (uint_t)
		(input_token != GSS_C_NO_BUFFER ? input_token->length : 0);
	arg.input_token.GSS_BUFFER_T_val = (char *)
		(input_token != GSS_C_NO_BUFFER ? input_token->value : 0);

	/* initialize the output parameters to empty values */
	if (minor_status != NULL)
		*minor_status = DEFAULT_MINOR_STAT;
	if (actual_mech_type != NULL)
		*actual_mech_type = NULL;
	if (output_token != NULL)
		output_token->length = 0;
	if (ret_flags != NULL)
		*ret_flags = 0;
	if (time_rec != NULL)
		*time_rec = 0;

	/* call the remote procedure */
	memset(&res, 0, sizeof (res));
	if (gss_init_sec_context_1(&arg, &res, clnt) != RPC_SUCCESS) {

		/* free the allocated memory for the flattened name */
		gss_release_buffer(&minor_status_temp, &external_name);

		return (GSS_S_FAILURE);
	}

	/*
	 * We could return from a GSS error here and need to return both the
	 * minor_status and output_token, back to the caller if applicable.
	 */
	if (minor_status != NULL)
		*minor_status = res.minor_status;

	if (output_token != NULL && res.output_token.GSS_BUFFER_T_val != NULL) {
		output_token->length =
			(size_t)res.output_token.GSS_BUFFER_T_len;
		output_token->value =
			(void *)res.output_token.GSS_BUFFER_T_val;
		res.output_token.GSS_BUFFER_T_val = NULL;
		res.output_token.GSS_BUFFER_T_len = 0;
	}

	/* free the allocated memory for the flattened name */
	gss_release_buffer(&minor_status_temp, &external_name);

	/* if the call was successful, copy out the results */
	if (res.status == (OM_uint32) GSS_S_COMPLETE ||
		res.status == (OM_uint32) GSS_S_CONTINUE_NEEDED) {
		/*
		 * copy the rpc results into the return argument
		 * on CONTINUE_NEEDED only ctx handle is ready.
		 */
		/*LINTED*/
		*context_handle = *((OM_uint32 *)
			res.context_handle.GSS_CTX_ID_T_val);

		*gssd_context_verifier = res.gssd_context_verifier;

		/* the rest of the parameters is only ready on COMPLETE */
		if (res.status == GSS_S_COMPLETE) {
			if (actual_mech_type != NULL) {
				*actual_mech_type = (gss_OID)
					MALLOC(sizeof (gss_OID_desc));
				(*actual_mech_type)->length = (OM_UINT32)
					res.actual_mech_type.GSS_OID_len;
				(*actual_mech_type)->elements = (void *)
					MALLOC((*actual_mech_type)->length);
				memcpy((*actual_mech_type)->elements, (void *)
					res.actual_mech_type.GSS_OID_val,
					(*actual_mech_type)->length);
			}


			if (ret_flags != NULL)
				*ret_flags = res.ret_flags;

			if (time_rec != NULL)
				*time_rec = res.time_rec;
		}
	}


	/*
	 * free the memory allocated for the results and return with the
	 * status received in the rpc call.
	 */

	clnt_freeres(clnt, xdr_gss_init_sec_context_res, (caddr_t)&res);
	return (res.status);
}
OM_uint32
kgss_init_sec_context(
		OM_uint32 *minor_status,
		gss_cred_id_t claimant_cred_handle,
		gss_ctx_id_t *context_handle,
		gss_name_t target_name,
		gss_OID mech_type,
		int req_flags,
		OM_uint32 time_req,
		gss_channel_bindings_t input_chan_bindings,
		gss_buffer_t input_token,
		gss_OID *actual_mech_type,
		gss_buffer_t output_token,
		int *ret_flags,
		OM_uint32 *time_rec,
		uid_t uid)
{
		OM_uint32	err;
		struct kgss_ctx	*kctx;
		OM_uint32 gssd_cred_verifier;
		gssd_cred_id_t gssd_cl_cred_handle;

		/*
		 * If this is an initial call, we'll need to create the
		 * wrapper struct that contains kernel state information, and
		 * a reference to the handle from gssd.
		 */
		if (*context_handle == GSS_C_NO_CONTEXT) {
			kctx = KGSS_ALLOC();
			*context_handle = (gss_ctx_id_t)kctx;
			kctx->gssd_ctx = (OM_uint32) GSS_C_NO_CONTEXT;
		} else
			kctx = (struct kgss_ctx *)*context_handle;

		if (claimant_cred_handle != GSS_C_NO_CREDENTIAL) {
			gssd_cred_verifier =
			    KCRED_TO_CREDV(claimant_cred_handle);
			gssd_cl_cred_handle =
			    KCRED_TO_CRED(claimant_cred_handle);
		} else {
			gssd_cl_cred_handle = GSSD_NO_CREDENTIAL;
		}

		err = kgss_init_sec_context_wrapped(minor_status,
		    gssd_cl_cred_handle,
		    gssd_cred_verifier, &kctx->gssd_ctx,
		    &kctx->gssd_ctx_verifier,
		    target_name, mech_type, req_flags, time_req,
		    input_chan_bindings, input_token, actual_mech_type,
		    output_token, ret_flags, time_rec, uid);

		if (GSS_ERROR(err)) {
			KGSS_FREE(kctx);
			*context_handle = GSS_C_NO_CONTEXT;
		}
		return (err);
}
OM_uint32
kgss_accept_sec_context_wrapped(minor_status,
				context_handle,
				gssd_context_verifier,
				verifier_cred_handle,
				gssd_cred_verifier,
		input_token,
		input_chan_bindings,
		src_name,
		mech_type,
		output_token,
		ret_flags,
		time_rec,
		delegated_cred_handle,
		uid)
	OM_uint32 *minor_status;
	gssd_ctx_id_t *context_handle;
	OM_uint32 *gssd_context_verifier;
	gssd_cred_id_t verifier_cred_handle;
	OM_uint32 gssd_cred_verifier;
	gss_buffer_t input_token;
	gss_channel_bindings_t input_chan_bindings;
	gss_buffer_t src_name;
	gss_OID *mech_type;
	gss_buffer_t output_token;
	int *ret_flags;
	OM_uint32 *time_rec;
	gss_cred_id_t *delegated_cred_handle;
	uid_t uid;
{
	gss_accept_sec_context_arg arg;
	gss_accept_sec_context_res res;
	struct kgss_cred *kcred;

	/* get the client handle to GSSD */
	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* copy the procedure arguments into the rpc arg parameter */
	arg.uid = (OM_uint32) uid;

	arg.context_handle.GSS_CTX_ID_T_len =
		*context_handle == GSSD_NO_CONTEXT ?
			0 : (uint_t)sizeof (gssd_ctx_id_t);
	arg.context_handle.GSS_CTX_ID_T_val =  (char *)context_handle;
	arg.gssd_context_verifier =
		*context_handle == (OM_uint32) GSS_C_NO_CONTEXT ?
			0 : *gssd_context_verifier;

	arg.verifier_cred_handle.GSS_CRED_ID_T_len =
			verifier_cred_handle == GSSD_NO_CREDENTIAL ?
			0 : (uint_t)sizeof (gssd_cred_id_t);
	arg.verifier_cred_handle.GSS_CRED_ID_T_val =
						(char *)&verifier_cred_handle;
	arg.gssd_cred_verifier = gssd_cred_verifier;

	arg.input_token_buffer.GSS_BUFFER_T_len =
			(uint_t)(input_token != GSS_C_NO_BUFFER ?
					input_token->length : 0);
	arg.input_token_buffer.GSS_BUFFER_T_val =
			(char *)(input_token != GSS_C_NO_BUFFER ?
					input_token->value : 0);

	if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) {
		arg.input_chan_bindings.present = YES;
		arg.input_chan_bindings.initiator_addrtype =
			input_chan_bindings->initiator_addrtype;
		arg.input_chan_bindings.initiator_address.GSS_BUFFER_T_len =
			(uint_t)input_chan_bindings->initiator_address.length;
		arg.input_chan_bindings.initiator_address.GSS_BUFFER_T_val =
			(void *) input_chan_bindings->initiator_address.value;
		arg.input_chan_bindings.acceptor_addrtype =
			input_chan_bindings->acceptor_addrtype;
		arg.input_chan_bindings.acceptor_address.GSS_BUFFER_T_len =
			(uint_t)input_chan_bindings->acceptor_address.length;
		arg.input_chan_bindings.acceptor_address.GSS_BUFFER_T_val =
			(void *) input_chan_bindings->acceptor_address.value;
		arg.input_chan_bindings.application_data.GSS_BUFFER_T_len =
			(uint_t)input_chan_bindings->application_data.length;
		arg.input_chan_bindings.application_data.GSS_BUFFER_T_val =
			(void *) input_chan_bindings->application_data.value;
	} else {
		arg.input_chan_bindings.present = NO;
		arg.input_chan_bindings.initiator_addrtype = 0;
		arg.input_chan_bindings.initiator_address.GSS_BUFFER_T_len = 0;
		arg.input_chan_bindings.initiator_address.GSS_BUFFER_T_val = 0;
		arg.input_chan_bindings.acceptor_addrtype = 0;
		arg.input_chan_bindings.acceptor_address.GSS_BUFFER_T_len = 0;
		arg.input_chan_bindings.acceptor_address.GSS_BUFFER_T_val = 0;
		arg.input_chan_bindings.application_data.GSS_BUFFER_T_len = 0;
		arg.input_chan_bindings.application_data.GSS_BUFFER_T_val = 0;
	}

	/* set the output parameters to empty values.... */
	if (minor_status != NULL)
		*minor_status = DEFAULT_MINOR_STAT;
	if (src_name != NULL) {
		src_name->length = 0;
		src_name->value = NULL;
	}
	if (mech_type != NULL)
		*mech_type = NULL;
	if (output_token != NULL)
		output_token->length = 0;
	if (ret_flags != NULL)
		*ret_flags = 0;
	if (time_rec != NULL)
		*time_rec = 0;
	if (delegated_cred_handle != NULL)
		*delegated_cred_handle = NULL;

	/* call the remote procedure */
	memset(&res, 0, sizeof (res));
	if (gss_accept_sec_context_1(&arg, &res, clnt) != RPC_SUCCESS) {
		return (GSS_S_FAILURE);
	}

	/*
	 * We could return from a GSS error here and need to return both the
	 * minor_status and output_token, back to the caller if applicable.
	 */
	if (minor_status != NULL)
		*minor_status = res.minor_status;

	if (output_token != NULL && res.output_token.GSS_BUFFER_T_val != NULL) {
		output_token->length =
			res.output_token.GSS_BUFFER_T_len;
		output_token->value =
			(void *) res.output_token.GSS_BUFFER_T_val;
		res.output_token.GSS_BUFFER_T_val = 0;
		res.output_token.GSS_BUFFER_T_len = 0;
	}

	if (res.status == (OM_uint32) GSS_S_COMPLETE ||
		res.status == (OM_uint32) GSS_S_CONTINUE_NEEDED) {
		/*
		 * when gss returns CONTINUE_NEEDED we can only
		 * use the context parameter.
		 */
		/*LINTED*/
		*context_handle = *((gssd_ctx_id_t *)
			res.context_handle.GSS_CTX_ID_T_val);
		*gssd_context_verifier = res.gssd_context_verifier;

		/* the other parameters are ready on for COMPLETE */
		if (res.status == GSS_S_COMPLETE)
		{

			/*
			 *  The src_name is in external format.
			 */
			if (src_name != NULL) {
			    src_name->length = res.src_name.GSS_BUFFER_T_len;
			    src_name->value = res.src_name.GSS_BUFFER_T_val;
			    res.src_name.GSS_BUFFER_T_val = NULL;
			    res.src_name.GSS_BUFFER_T_len = 0;
			}
			/*
			 * move mech type returned to mech_type
			 * for gss_import_name_for_mech()
			 */
			if (mech_type != NULL) {
				*mech_type =
					(gss_OID) MALLOC(sizeof (gss_OID_desc));
				(*mech_type)->length =
					(OM_UINT32) res.mech_type.GSS_OID_len;
				(*mech_type)->elements =
					(void *) MALLOC((*mech_type)->length);
				memcpy((*mech_type)->elements,
					res.mech_type.GSS_OID_val,
					(*mech_type)->length);
			}

			if (ret_flags != NULL)
				*ret_flags = res.ret_flags;

			if (time_rec != NULL)
				*time_rec = res.time_rec;

			if ((delegated_cred_handle != NULL) &&
				(res.delegated_cred_handle.GSS_CRED_ID_T_len
					!= 0)) {
				kcred = KGSS_CRED_ALLOC();
				/*LINTED*/
				kcred->gssd_cred = *((gssd_cred_id_t *)
				res.delegated_cred_handle.GSS_CRED_ID_T_val);
				kcred->gssd_cred_verifier =
					res.gssd_context_verifier;
				*delegated_cred_handle = (gss_cred_id_t)kcred;
			}
		} /* res.status == GSS_S_COMPLETE */
	} /* res.status == GSS_S_COMPLETE or GSS_CONTINUE_NEEDED */


	/*
	 * free the memory allocated for the results and return with the status
	 * received in the rpc call
	 */

	clnt_freeres(clnt, xdr_gss_accept_sec_context_res, (caddr_t)&res);
	return (res.status);
}

OM_uint32
kgss_accept_sec_context(
		OM_uint32 *minor_status,
		gss_ctx_id_t *context_handle,
		gss_cred_id_t verifier_cred_handle,
		gss_buffer_t input_token,
		gss_channel_bindings_t input_chan_bindings,
		gss_buffer_t src_name,
		gss_OID *mech_type,
		gss_buffer_t output_token,
		int *ret_flags,
		OM_uint32 *time_rec,
		gss_cred_id_t *delegated_cred_handle,
		uid_t uid)
{
		OM_uint32 err;
		struct kgss_ctx *kctx;
		OM_uint32 gssd_cred_verifier;
		gssd_cred_id_t gssd_ver_cred_handle;


		if (*context_handle == GSS_C_NO_CONTEXT) {
			kctx = KGSS_ALLOC();
			*context_handle = (gss_ctx_id_t)kctx;
		kctx->gssd_ctx = GSSD_NO_CONTEXT;
		} else
			kctx = (struct kgss_ctx *)*context_handle;

	if (verifier_cred_handle != GSS_C_NO_CREDENTIAL) {
			gssd_cred_verifier =
			    KCRED_TO_CREDV(verifier_cred_handle);
			gssd_ver_cred_handle =
			    KCRED_TO_CRED(verifier_cred_handle);
	} else
		gssd_ver_cred_handle = GSSD_NO_CREDENTIAL;

		err = kgss_accept_sec_context_wrapped(minor_status,
		    &kctx->gssd_ctx,
		    &kctx->gssd_ctx_verifier, gssd_ver_cred_handle,
		    gssd_cred_verifier, input_token, input_chan_bindings,
		    src_name, mech_type, output_token, ret_flags,
		    time_rec, delegated_cred_handle, uid);

	if (GSS_ERROR(err)) {
		KGSS_FREE(kctx);
		*context_handle = GSS_C_NO_CONTEXT;

	}

	return (err);
}

OM_uint32
kgss_process_context_token(minor_status,
			context_handle,
			token_buffer,
			uid)
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	gss_buffer_t token_buffer;
	uid_t uid;
{
	OM_uint32 gssd_context_verifier;

	gss_process_context_token_arg arg;
	gss_process_context_token_res res;

	gssd_context_verifier = KGSS_CTX_TO_GSSD_CTXV(context_handle);

	/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* copy the procedure arguments into the rpc arg parameter */
	arg.uid = (OM_uint32) uid;

	arg.context_handle.GSS_CTX_ID_T_len = (uint_t)sizeof (gss_ctx_id_t);
	arg.context_handle.GSS_CTX_ID_T_val = (char *)&context_handle;
	arg.gssd_context_verifier = gssd_context_verifier;
	arg.token_buffer.GSS_BUFFER_T_len = (uint_t)token_buffer;
	arg.token_buffer.GSS_BUFFER_T_val = (char *)token_buffer->value;

	/* call the remote procedure */

	memset(&res, 0, sizeof (res));
	if (gss_process_context_token_1(&arg, &res, clnt) != RPC_SUCCESS) {

	/*
	 * if the RPC call times out, null out all return arguments,
	 * set minor_status to its maximum value, and return GSS_S_FAILURE
	 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;

		return (GSS_S_FAILURE);
	}

	/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	/* return with status returned in rpc call */

	return (res.status);
}

OM_uint32
kgss_delete_sec_context_wrapped(minor_status,
			context_handle,
			gssd_context_verifier,
			output_token)
	OM_uint32 *minor_status;
	gssd_ctx_id_t *context_handle;
	OM_uint32 gssd_context_verifier;
	gss_buffer_t output_token;
{
	gss_delete_sec_context_arg arg;
	gss_delete_sec_context_res res;


	/* get the client handle to GSSD */
	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* copy the procedure arguments into the rpc arg parameter */

	arg.context_handle.GSS_CTX_ID_T_len =
		*context_handle == (OM_uint32) GSS_C_NO_CONTEXT ? 0 :
		(uint_t)sizeof (OM_uint32);
	arg.context_handle.GSS_CTX_ID_T_val =  (char *)context_handle;

	arg.gssd_context_verifier = gssd_context_verifier;

	/* call the remote procedure */

	memset(&res, 0, sizeof (res));
	if (gss_delete_sec_context_1(&arg, &res, clnt) != RPC_SUCCESS) {

		/*
		 * if the RPC call times out, null out all return arguments,
		 * set minor_status to its max value, and return GSS_S_FAILURE
		 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		if (context_handle != NULL)
			*context_handle = NULL;
		if (output_token != NULL)
			output_token->length = 0;

		return (GSS_S_FAILURE);
	}

	/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	if (res.context_handle.GSS_CTX_ID_T_len == 0)
		*context_handle = NULL;
	else
		/*LINTED*/
		*context_handle = *((gssd_ctx_id_t *)
			res.context_handle.GSS_CTX_ID_T_val);

	if (output_token != NULL && res.output_token.GSS_BUFFER_T_val != NULL) {
		output_token->length = res.output_token.GSS_BUFFER_T_len;
		output_token->value = res.output_token.GSS_BUFFER_T_val;
		res.output_token.GSS_BUFFER_T_len = 0;
		res.output_token.GSS_BUFFER_T_val = NULL;
	}

	/*
	 * free the memory allocated for the results and return with the status
	 * received in the rpc call
	 */

	clnt_freeres(clnt, xdr_gss_delete_sec_context_res, (caddr_t)&res);
	return (res.status);
}

/*ARGSUSED*/
OM_uint32
kgss_delete_sec_context(
		OM_uint32 *minor_status,
		gss_ctx_id_t *context_handle,
		gss_buffer_t output_token)
{
		OM_uint32 err;
		struct kgss_ctx *kctx;

		if (*context_handle == GSS_C_NO_CONTEXT) {
			return (GSS_S_NO_CONTEXT);
		} else
			kctx = KCTX_TO_KGSS_CTX(*context_handle);

		err = kgss_delete_sec_context_wrapped(minor_status,
		    &kctx->gssd_ctx, kctx->gssd_ctx_verifier,
		    output_token);

		if (kctx->gssd_ctx != GSSD_NO_CONTEXT)
			err = GSS_S_FAILURE;
		else
			err = GSS_S_COMPLETE;

		KGSS_FREE(kctx);
		*context_handle = GSS_C_NO_CONTEXT;
		return (err);
}

/*ARGSUSED*/
OM_uint32
kgss_context_time(minor_status,
		context_handle,
		time_rec,
		uid)
	OM_uint32 *minor_status;
	gss_ctx_id_t context_handle;
	OM_uint32 *time_rec;
	uid_t uid;
{
	return (GSS_S_FAILURE);
}

OM_uint32
kgss_sign_wrapped(minor_status,
		context_handle,
		qop_req,
		message_buffer,
		msg_token,
		gssd_context_verifier)
	OM_uint32 *minor_status;
	gssd_ctx_id_t context_handle;
	OM_uint32 gssd_context_verifier;
	int qop_req;
	gss_buffer_t message_buffer;
	gss_buffer_t msg_token;
{

	gss_sign_arg arg;
	gss_sign_res res;

	/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* copy the procedure arguments into the rpc arg parameter */


	arg.context_handle.GSS_CTX_ID_T_len = (uint_t)sizeof (gssd_ctx_id_t);
	arg.context_handle.GSS_CTX_ID_T_val = (char *)&context_handle;
	arg.gssd_context_verifier = gssd_context_verifier;

	arg.qop_req = qop_req;
	arg.message_buffer.GSS_BUFFER_T_len = (uint_t)message_buffer->length;
	arg.message_buffer.GSS_BUFFER_T_val = (char *)message_buffer->value;

	/* call the remote procedure */

	memset(&res, 0, sizeof (res));
	if (gss_sign_1(&arg, &res, clnt) != RPC_SUCCESS) {

	/*
	 * if the RPC call times out, null out all return arguments,
	 * set minor_status to its maximum value, and return GSS_S_FAILURE
	 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		if (msg_token != NULL)
			msg_token->length = 0;

		return (GSS_S_FAILURE);
	}

	/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	if (msg_token != NULL) {
		msg_token->length = res.msg_token.GSS_BUFFER_T_len;
		msg_token->value = (void *) MALLOC(msg_token->length);
		memcpy(msg_token->value, res.msg_token.GSS_BUFFER_T_val,
			msg_token->length);
	}

	/*
	 * free the memory allocated for the results and return with the status
	 * received in the rpc call
	 */

	clnt_freeres(clnt, xdr_gss_sign_res, (caddr_t)&res);
	return (res.status);
}

OM_uint32
kgss_sign(
		OM_uint32 *minor_status,
		gss_ctx_id_t context_handle,
		int qop_req,
		gss_buffer_t message_buffer,
		gss_buffer_t msg_token)
{
		if (context_handle == GSS_C_NO_CONTEXT)
			return (GSS_S_FAILURE);

		return (KGSS_SIGN(minor_status,
		    context_handle, qop_req, message_buffer,
		    msg_token));
}

OM_uint32
kgss_verify_wrapped(
		minor_status,
		context_handle,
		message_buffer,
		token_buffer,
		qop_state,
		gssd_context_verifier)
	OM_uint32 *minor_status;
	gssd_ctx_id_t context_handle;
	OM_uint32 gssd_context_verifier;
	gss_buffer_t message_buffer;
	gss_buffer_t token_buffer;
	int *qop_state;
{
	gss_verify_arg arg;
	gss_verify_res res;

/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* copy the procedure arguments into the rpc arg parameter */

	arg.context_handle.GSS_CTX_ID_T_len = (uint_t)sizeof (gssd_ctx_id_t);
	arg.context_handle.GSS_CTX_ID_T_val = (char *)&context_handle;

	arg.gssd_context_verifier = gssd_context_verifier;

	arg.message_buffer.GSS_BUFFER_T_len = (uint_t)message_buffer->length;
	arg.message_buffer.GSS_BUFFER_T_val = (char *)message_buffer->value;

	arg.token_buffer.GSS_BUFFER_T_len = (uint_t)token_buffer->length;
	arg.token_buffer.GSS_BUFFER_T_val = (char *)token_buffer->value;

	/* call the remote procedure */

	memset(&res, 0, sizeof (res));
	if (gss_verify_1(&arg, &res, clnt) != RPC_SUCCESS) {

	/*
	 * if the RPC call times out, null out all return arguments,
	 * set minor_status to its maximum value, and return GSS_S_FAILURE
	 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		if (qop_state != NULL)
			*qop_state = 0;

		return (GSS_S_FAILURE);
	}

	/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	if (qop_state != NULL)
		*qop_state = res.qop_state;

	/* return with status returned in rpc call */

	return (res.status);
}

OM_uint32
kgss_verify(OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	gss_buffer_t message_buffer,
	gss_buffer_t token_buffer,
	int *qop_state)
{
		if (context_handle == GSS_C_NO_CONTEXT)
			return (GSS_S_FAILURE);

		return (KGSS_VERIFY(minor_status, context_handle,
		    message_buffer, token_buffer, qop_state));
}


OM_uint32
kgss_seal_wrapped(
	minor_status,
	context_handle,
	conf_req_flag,
	qop_req,
	input_message_buffer,
	conf_state,
	output_message_buffer,
	gssd_context_verifier)

	OM_uint32 *minor_status;
	gssd_ctx_id_t context_handle;
	OM_uint32 gssd_context_verifier;
	int conf_req_flag;
	int qop_req;
	gss_buffer_t input_message_buffer;
	int *conf_state;
	gss_buffer_t output_message_buffer;
{
	gss_seal_arg arg;
	gss_seal_res res;

	/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* copy the procedure arguments into the rpc arg parameter */


	arg.context_handle.GSS_CTX_ID_T_len = (uint_t)sizeof (gssd_ctx_id_t);
	arg.context_handle.GSS_CTX_ID_T_val = (char *)&context_handle;
	arg.gssd_context_verifier = gssd_context_verifier;

	arg.conf_req_flag = conf_req_flag;

	arg.qop_req = qop_req;

	arg.input_message_buffer.GSS_BUFFER_T_len =
				(uint_t)input_message_buffer->length;

	arg.input_message_buffer.GSS_BUFFER_T_val =
				(char *)input_message_buffer->value;

	/* call the remote procedure */

	memset(&res, 0, sizeof (res));
	if (gss_seal_1(&arg, &res, clnt) != RPC_SUCCESS) {

	/*
	 * if the RPC call times out, null out all return arguments,
	 * set minor_status to its maximum value, and return GSS_S_FAILURE
	 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		if (conf_state != NULL)
			*conf_state = 0;
		if (output_message_buffer != NULL)
			output_message_buffer->length = 0;

		return (GSS_S_FAILURE);
	}

	/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	if (conf_state != NULL)
		*conf_state = res.conf_state;

	if (output_message_buffer != NULL) {
		output_message_buffer->length =
				res.output_message_buffer.GSS_BUFFER_T_len;

		output_message_buffer->value =
				(void *) MALLOC(output_message_buffer->length);
		memcpy(output_message_buffer->value,
			res.output_message_buffer.GSS_BUFFER_T_val,
			output_message_buffer->length);
	}

	/*
	 * free the memory allocated for the results and return with the status
	 * received in the rpc call
	 */

	clnt_freeres(clnt, xdr_gss_seal_res, (caddr_t)&res);
	return (res.status);
}

OM_uint32
kgss_seal(OM_uint32 *minor_status,
		gss_ctx_id_t context_handle,
		int conf_req_flag,
		int qop_req,
		gss_buffer_t input_message_buffer,
		int *conf_state,
		gss_buffer_t output_message_buffer)

{
		if (context_handle == GSS_C_NO_CONTEXT)
			return (GSS_S_FAILURE);

		return (KGSS_SEAL(minor_status, context_handle,
			conf_req_flag, qop_req,
			input_message_buffer,
			conf_state, output_message_buffer));
}

OM_uint32
kgss_unseal_wrapped(minor_status,
		context_handle,
		input_message_buffer,
		output_message_buffer,
		conf_state,
		qop_state,
		gssd_context_verifier)
	OM_uint32 *minor_status;
	gssd_ctx_id_t context_handle;
	OM_uint32 gssd_context_verifier;
	gss_buffer_t input_message_buffer;
	gss_buffer_t output_message_buffer;
	int *conf_state;
	int *qop_state;
{
	gss_unseal_arg arg;
	gss_unseal_res res;

	/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* copy the procedure arguments into the rpc arg parameter */


	arg.context_handle.GSS_CTX_ID_T_len = (uint_t)sizeof (gssd_ctx_id_t);
	arg.context_handle.GSS_CTX_ID_T_val = (char *)&context_handle;
	arg.gssd_context_verifier = gssd_context_verifier;

	arg.input_message_buffer.GSS_BUFFER_T_len =
				(uint_t)input_message_buffer->length;

	arg.input_message_buffer.GSS_BUFFER_T_val =
				(char *)input_message_buffer->value;

/* call the remote procedure */

	memset(&res, 0, sizeof (res));
	if (gss_unseal_1(&arg, &res, clnt) != RPC_SUCCESS) {

	/*
	 * if the RPC call times out, null out all return arguments,
	 * set minor_status to its maximum value, and return GSS_S_FAILURE
	 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		if (output_message_buffer != NULL)
			output_message_buffer->length = 0;
		if (conf_state != NULL)
			*conf_state = 0;
		if (qop_state != NULL)
			*qop_state = 0;

		return (GSS_S_FAILURE);
	}

	/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	if (output_message_buffer != NULL) {
		output_message_buffer->length =
				res.output_message_buffer.GSS_BUFFER_T_len;

		output_message_buffer->value =
			(void *) MALLOC(output_message_buffer->length);
		memcpy(output_message_buffer->value,
			res.output_message_buffer.GSS_BUFFER_T_val,
			output_message_buffer->length);
	}

	if (conf_state != NULL)
		*conf_state = res.conf_state;

	if (qop_state != NULL)
		*qop_state = res.qop_state;

	/*
	 * free the memory allocated for the results and return with the status
	 * received in the rpc call
	 */

	clnt_freeres(clnt, xdr_gss_unseal_res, (caddr_t)&res);
	return (res.status);
}

OM_uint32
kgss_unseal(OM_uint32 *minor_status,
	gss_ctx_id_t context_handle,
	gss_buffer_t input_message_buffer,
	gss_buffer_t output_message_buffer,
	int *conf_state,
	int *qop_state)
{
		if (context_handle == GSS_C_NO_CONTEXT)
			return (GSS_S_FAILURE);

		return (KGSS_UNSEAL(minor_status, context_handle,
		    input_message_buffer, output_message_buffer,
		    conf_state, qop_state));
}

OM_uint32
kgss_display_status(minor_status,
		status_value,
		status_type,
		mech_type,
		message_context,
		status_string,
		uid)
	OM_uint32 *minor_status;
	OM_uint32 status_value;
	int status_type;
	gss_OID mech_type;
	int *message_context;
	gss_buffer_t status_string;
	uid_t uid;
{
	gss_display_status_arg arg;
	gss_display_status_res res;

	/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* copy the procedure arguments into the rpc arg parameter */

	arg.uid = (OM_uint32) uid;

	arg.status_value = status_value;
	arg.status_type = status_type;

	arg.mech_type.GSS_OID_len = (uint_t)(mech_type != GSS_C_NULL_OID ?
					mech_type->length : 0);
	arg.mech_type.GSS_OID_val = (char *)(mech_type != GSS_C_NULL_OID ?
					mech_type->elements : 0);

	arg.message_context = *message_context;

	/* call the remote procedure */

	if (message_context != NULL)
		*message_context = 0;
	if (status_string != NULL) {
		status_string->length = 0;
		status_string->value = NULL;
	}

	memset(&res, 0, sizeof (res));
	if (gss_display_status_1(&arg, &res, clnt) != RPC_SUCCESS) {

	/*
	 * if the RPC call times out, null out all return arguments,
	 * set minor_status to its maximum value, and return GSS_S_FAILURE
	 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;

		return (GSS_S_FAILURE);
	}

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	/* now process the results and pass them back to the caller */

	if (res.status == GSS_S_COMPLETE) {
		if (message_context != NULL)
			*message_context = res.message_context;
		if (status_string != NULL) {
			status_string->length =
				(size_t)res.status_string.GSS_BUFFER_T_len;
			status_string->value =
				(void *)MALLOC(status_string->length);
			memcpy(status_string->value,
				res.status_string.GSS_BUFFER_T_val,
				status_string->length);
		}
	}

	clnt_freeres(clnt, xdr_gss_display_status_res, (caddr_t)&res);
	return (res.status);
}

/*ARGSUSED*/
OM_uint32
kgss_indicate_mechs(minor_status,
		mech_set,
		uid)
	OM_uint32 *minor_status;
	gss_OID_set *mech_set;
	uid_t uid;
{
	void *arg;
	gss_indicate_mechs_res res;
	int i;

	/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	memset(&res, 0, sizeof (res));
	if (gss_indicate_mechs_1(&arg, &res, clnt) != RPC_SUCCESS) {

	/*
	 * if the RPC call times out, null out all return arguments,
	 * set minor_status to its maximum value, and return GSS_S_FAILURE
	 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		if (mech_set != NULL)
			*mech_set = NULL;

		return (GSS_S_FAILURE);
	}

	/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	if (mech_set != NULL) {
		*mech_set = (gss_OID_set) MALLOC(sizeof (gss_OID_set_desc));
		(*mech_set)->count = res.mech_set.GSS_OID_SET_len;
		(*mech_set)->elements = (void *)
			MALLOC ((*mech_set)->count * sizeof (gss_OID_desc));
		for (i = 0; i < (*mech_set)->count; i++) {
			(*mech_set)->elements[i].length =
				res.mech_set.GSS_OID_SET_val[i].GSS_OID_len;
			(*mech_set)->elements[i].elements = (void *)
				MALLOC ((*mech_set)->elements[i].length);
			memcpy ((*mech_set)->elements[i].elements,
				res.mech_set.GSS_OID_SET_val[i].GSS_OID_val,
				(*mech_set)->elements[i].length);
		}
	}

	/*
	 * free the memory allocated for the results and return with the status
	 * received in the rpc call
	 */

	clnt_freeres(clnt, xdr_gss_indicate_mechs_res, (caddr_t)&res);
	return (res.status);
}


OM_uint32
kgss_inquire_cred_wrapped(minor_status,
			cred_handle,
			gssd_cred_verifier,
			name,
			lifetime,
			cred_usage,
			mechanisms,
			uid)
	OM_uint32 *minor_status;
	gssd_cred_id_t cred_handle;
	OM_uint32 gssd_cred_verifier;
	gss_name_t *name;
	OM_uint32 *lifetime;
	int *cred_usage;
	gss_OID_set *mechanisms;
	uid_t uid;
{
	OM_uint32 minor_status_temp;
	gss_buffer_desc external_name;
	gss_OID name_type;
	int i;

	gss_inquire_cred_arg arg;
	gss_inquire_cred_res res;

	/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}


	/* copy the procedure arguments into the rpc arg parameter */

	arg.uid = (OM_uint32) uid;

	arg.cred_handle.GSS_CRED_ID_T_len =
			cred_handle == GSSD_NO_CREDENTIAL ?
			0 : (uint_t)sizeof (gssd_cred_id_t);
	arg.cred_handle.GSS_CRED_ID_T_val = (char *)&cred_handle;
	arg.gssd_cred_verifier = gssd_cred_verifier;

	/* call the remote procedure */

	memset(&res, 0, sizeof (res));
	if (gss_inquire_cred_1(&arg, &res, clnt) != RPC_SUCCESS) {

	/*
	 * if the RPC call times out, null out all return arguments,
	 * set minor_status to its maximum value, and return GSS_S_FAILURE
	 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		if (name != NULL)
			*name = NULL;
		if (lifetime != NULL)
			*lifetime = 0;
		if (cred_usage != NULL)
			*cred_usage = 0;
		if (mechanisms != NULL)
			*mechanisms = NULL;

		return (GSS_S_FAILURE);
	}

	/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	/* convert name from external to internal format */

	if (name != NULL) {
		external_name.length = res.name.GSS_BUFFER_T_len;
		external_name.value = res.name.GSS_BUFFER_T_val;

		/*
		 * we have to allocate a name_type descriptor and
		 * elements storage, since gss_import_name() only
		 * stores a pointer to the name_type info in the
		 * union_name struct
		 */

		name_type = (gss_OID) MALLOC(sizeof (gss_OID_desc));

		name_type->length = res.name_type.GSS_OID_len;
		name_type->elements = (void *) MALLOC(name_type->length);
		memcpy(name_type->elements, res.name_type.GSS_OID_val,
			name_type->length);

		if (gss_import_name(&minor_status_temp, &external_name,
			name_type, name) != GSS_S_COMPLETE) {

			*minor_status = (OM_uint32) minor_status_temp;
			gss_release_buffer(&minor_status_temp, &external_name);

			clnt_freeres(clnt, xdr_gss_inquire_cred_res,
							(caddr_t)&res);
			return ((OM_uint32) GSS_S_FAILURE);
		}
	}

	if (lifetime != NULL)
		*lifetime = res.lifetime;

	if (cred_usage != NULL)
		*cred_usage = res.cred_usage;

	if (mechanisms != NULL) {
		*mechanisms =
			(gss_OID_set) MALLOC(sizeof (gss_OID_set_desc));
		if (res.mechanisms.GSS_OID_SET_len != 0) {
			(*mechanisms)->count =
					(int)res.mechanisms.GSS_OID_SET_len;
			(*mechanisms)->elements = (gss_OID)
				MALLOC(sizeof (gss_OID) * (*mechanisms)->count);

			for (i = 0; i < (*mechanisms)->count; i++) {
				(*mechanisms)->elements[i].length = (OM_uint32)
				res.mechanisms.GSS_OID_SET_val[i].GSS_OID_len;
				(*mechanisms)->elements[i].elements = (void *)
				MALLOC((*mechanisms)->elements[i].length);
				memcpy((*mechanisms)->elements[i].elements,
				res.mechanisms.GSS_OID_SET_val[i].GSS_OID_val,
				(*mechanisms)->elements[i].length);
			}
		} else
			(*mechanisms)->count = 0;
	}

	/*
	 * free the memory allocated for the results and return with the status
	 * received in the rpc call
	 */

	clnt_freeres(clnt, xdr_gss_inquire_cred_res, (caddr_t)&res);
	return (res.status);
}


OM_uint32
kgss_inquire_cred(minor_status,
			cred_handle,
			name,
			lifetime,
			cred_usage,
			mechanisms,
			uid)
	OM_uint32 *minor_status;
	gss_cred_id_t cred_handle;
	gss_name_t *name;
	OM_uint32 *lifetime;
	int *cred_usage;
	gss_OID_set * mechanisms;
	uid_t uid;
{

	OM_uint32 gssd_cred_verifier;
	gssd_cred_id_t gssd_cred_handle;

		gssd_cred_verifier = KCRED_TO_CREDV(cred_handle);
		gssd_cred_handle = KCRED_TO_CRED(cred_handle);

		return (kgss_inquire_cred_wrapped(minor_status,
				gssd_cred_handle, gssd_cred_verifier,
				name, lifetime, cred_usage, mechanisms, uid));
}


OM_uint32
kgss_inquire_cred_by_mech_wrapped(minor_status,
			cred_handle,
			gssd_cred_verifier,
			mech_type,
			uid)
	OM_uint32 *minor_status;
	gssd_cred_id_t cred_handle;
	OM_uint32 gssd_cred_verifier;
	gss_OID mech_type;
	uid_t uid;
{
	OM_uint32 minor_status_temp;

	gss_inquire_cred_by_mech_arg arg;
	gss_inquire_cred_by_mech_res res;

	/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}


	/* copy the procedure arguments into the rpc arg parameter */

	arg.uid = (OM_uint32) uid;

	arg.cred_handle.GSS_CRED_ID_T_len =
			cred_handle == GSSD_NO_CREDENTIAL ?
			0 : (uint_t)sizeof (gssd_cred_id_t);
	arg.cred_handle.GSS_CRED_ID_T_val = (char *)&cred_handle;
	arg.gssd_cred_verifier = gssd_cred_verifier;

	arg.mech_type.GSS_OID_len =
		(uint_t)(mech_type != GSS_C_NULL_OID ?
		mech_type->length : 0);
	arg.mech_type.GSS_OID_val =
		(char *)(mech_type != GSS_C_NULL_OID ?
		mech_type->elements : 0);
	/* call the remote procedure */

	memset(&res, 0, sizeof (res));
	if (gss_inquire_cred_by_mech_1(&arg, &res, clnt) != RPC_SUCCESS) {

	/*
	 * if the RPC call times out, null out all return arguments,
	 * set minor_status to its maximum value, and return GSS_S_FAILURE
	 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		return (GSS_S_FAILURE);
	}

	/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	/* convert name from external to internal format */

	/*
	 * free the memory allocated for the results and return with the status
	 * received in the rpc call
	 */

	clnt_freeres(clnt, xdr_gss_inquire_cred_by_mech_res, (caddr_t)&res);
	return (res.status);
}


OM_uint32
kgss_inquire_cred_by_mech(minor_status,
			cred_handle,
			mech_type,
			uid)
	OM_uint32 *minor_status;
	gss_cred_id_t cred_handle;
	gss_OID mech_type;
	uid_t uid;
{

	OM_uint32 gssd_cred_verifier;
	gssd_cred_id_t gssd_cred_handle;

	gssd_cred_verifier = KCRED_TO_CREDV(cred_handle);
	gssd_cred_handle = KCRED_TO_CRED(cred_handle);

	return (kgss_inquire_cred_by_mech_wrapped(minor_status,
			gssd_cred_handle, gssd_cred_verifier,
			mech_type, uid));
}

OM_uint32
kgsscred_expname_to_unix_cred(expName, uidOut, gidOut, gids, gidsLen, uid)
	const gss_buffer_t expName;
	uid_t *uidOut;
	gid_t *gidOut;
	gid_t *gids[];
	int *gidsLen;
	uid_t uid;
{
	gsscred_expname_to_unix_cred_arg args;
	gsscred_expname_to_unix_cred_res res;

	/* check input/output parameters */
	if (expName == NULL || expName->value == NULL)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (uidOut == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* NULL out output parameters */
	*uidOut = 0;
	if (gidsLen)
		*gidsLen = 0;

	if (gids)
		*gids = NULL;

	/* get the client handle to gssd */
	if ((clnt = getgssd_handle()) == NULL)
	{
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* copy the procedure arguments */
	args.uid = uid;
	args.expname.GSS_BUFFER_T_val = expName->value;
	args.expname.GSS_BUFFER_T_len = expName->length;

	/* null out the return buffer and call the remote proc */
	memset(&res, 0, sizeof (res));

	if (gsscred_expname_to_unix_cred_1(&args, &res, clnt) != RPC_SUCCESS)
	{
		return (GSS_S_FAILURE);
	}

	/* copy the results into the result parameters */
	if (res.major == GSS_S_COMPLETE)
	{
		*uidOut = res.uid;
		if (gidOut)
			*gidOut = res.gid;
		if (gids && gidsLen)
		{
			*gids = res.gids.GSSCRED_GIDS_val;
			*gidsLen = res.gids.GSSCRED_GIDS_len;
			res.gids.GSSCRED_GIDS_val = NULL;
			res.gids.GSSCRED_GIDS_len = 0;
		}
	}

	/* free RPC results */
	clnt_freeres(clnt, xdr_gsscred_expname_to_unix_cred_res, (caddr_t)&res);

	return (res.major);
} /* kgsscred_expname_to_unix_cred */

OM_uint32
kgsscred_name_to_unix_cred(intName, mechType, uidOut, gidOut, gids,
				gidsLen, uid)
	const gss_name_t intName;
	const gss_OID mechType;
	uid_t *uidOut;
	gid_t *gidOut;
	gid_t *gids[];
	int *gidsLen;
	uid_t uid;
{
	gsscred_name_to_unix_cred_arg args;
	gsscred_name_to_unix_cred_res res;
	OM_uint32 major, minor;
	gss_OID nameOid;
	gss_buffer_desc flatName = GSS_C_EMPTY_BUFFER;


	/* check the input/output parameters */
	if (intName == NULL || mechType == NULL)
		return (GSS_S_CALL_INACCESSIBLE_READ);

	if (uidOut == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* NULL out the output parameters */
	*uidOut = 0;
	if (gids)
		*gids = NULL;

	if (gidsLen)
		*gidsLen = 0;

	/* get the client handle to gssd */
	if ((clnt = getgssd_handle()) == NULL)
	{
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* convert the name to flat representation */
	if ((major = gss_display_name(&minor, intName, &flatName, &nameOid))
			!= GSS_S_COMPLETE)
	{
		return (major);
	}

	/* set the rpc parameters */
	args.uid = uid;
	args.pname.GSS_BUFFER_T_len = flatName.length;
	args.pname.GSS_BUFFER_T_val = flatName.value;
	args.name_type.GSS_OID_len = nameOid->length;
	args.name_type.GSS_OID_val = nameOid->elements;
	args.mech_type.GSS_OID_len = mechType->length;
	args.mech_type.GSS_OID_val = mechType->elements;

	/* call the remote procedure */
	memset(&res, 0, sizeof (res));
	if (gsscred_name_to_unix_cred_1(&args, &res, clnt) != RPC_SUCCESS)
	{
		gss_release_buffer(&minor, &flatName);
		return (GSS_S_FAILURE);
	}

	gss_release_buffer(&minor, &flatName);
	/* copy the output parameters on output */
	if (res.major == GSS_S_COMPLETE)
	{
		*uidOut = res.uid;
		if (gidOut)
			*gidOut = res.gid;
		if (gids && gidsLen)
		{
			*gids = res.gids.GSSCRED_GIDS_val;
			*gidsLen = res.gids.GSSCRED_GIDS_len;
			res.gids.GSSCRED_GIDS_val = NULL;
			res.gids.GSSCRED_GIDS_len = 0;
		}
	}

	/* delete RPC allocated memory */
	clnt_freeres(clnt, xdr_gsscred_name_to_unix_cred_res, (caddr_t)&res);

	return (res.major);
} /* kgsscred_name_to_unix_cred */

OM_uint32
kgss_get_group_info(puid, gidOut, gids, gidsLen, uid)
	const uid_t puid;
	gid_t *gidOut;
	gid_t *gids[];
	int *gidsLen;
	uid_t uid;
{
	gss_get_group_info_arg args;
	gss_get_group_info_res res;


	/* check the output parameters */
	if (gidOut == NULL || gids == NULL || gidsLen == NULL)
		return (GSS_S_CALL_INACCESSIBLE_WRITE);

	/* get the client GSSD handle */
	if ((clnt = getgssd_handle()) == NULL)
	{
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

	/* set the input parameters */
	args.uid = uid;
	args.puid = puid;


	/* call the remote procedure */
	memset(&res, 0, sizeof (res));
	if (gss_get_group_info_1(&args, &res, clnt) != RPC_SUCCESS)
	{
		return (GSS_S_FAILURE);
	}

	/* copy the results */
	if (res.major == GSS_S_COMPLETE)
	{
		*gidOut = res.gid;
		*gids = res.gids.GSSCRED_GIDS_val;
		*gidsLen = res.gids.GSSCRED_GIDS_len;
		res.gids.GSSCRED_GIDS_val = NULL;
		res.gids.GSSCRED_GIDS_len = 0;
	}

	/* nothing to free */

	return (res.major);
} /* kgss_get_group_info */

OM_uint32
kgss_export_sec_context_wrapped(minor_status,
				context_handle,
				output_token,
				gssd_context_verifier)
	OM_uint32 *minor_status;
	gssd_ctx_id_t *context_handle;
	gss_buffer_t output_token;
	OM_uint32 gssd_context_verifier;
{
	CLIENT *clnt;
	gss_export_sec_context_arg arg;
	gss_export_sec_context_res res;


/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

/* copy the procedure arguments into the rpc arg parameter */

	arg.context_handle.GSS_CTX_ID_T_len = (uint_t)sizeof (gssd_ctx_id_t);
	arg.context_handle.GSS_CTX_ID_T_val = (char *)context_handle;
	arg.gssd_context_verifier = gssd_context_verifier;

/* call the remote procedure */

	memset(&res, 0, sizeof (res));
	if (gss_export_sec_context_1(&arg, &res, clnt) != RPC_SUCCESS) {

/*
 * if the RPC call times out, null out all return arguments, set minor_status
 * to its maximum value, and return GSS_S_FAILURE
 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		if (context_handle != NULL)
			*context_handle = NULL;
		if (output_token != NULL)
			output_token->length = 0;

		return (GSS_S_FAILURE);
	}

/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	if (res.context_handle.GSS_CTX_ID_T_len == 0)
		*context_handle = NULL;
	else
		*context_handle =
		    *((gssd_ctx_id_t *)res.context_handle.GSS_CTX_ID_T_val);

	if (output_token != NULL && res.output_token.GSS_BUFFER_T_val != NULL) {
		output_token->length = res.output_token.GSS_BUFFER_T_len;
		output_token->value =
			(void *) MALLOC(output_token->length);
		memcpy(output_token->value,
			res.output_token.GSS_BUFFER_T_val,
			output_token->length);
	}

/*
 * free the memory allocated for the results and return with the status
 * received in the rpc call
 */

	clnt_freeres(clnt, xdr_gss_export_sec_context_res, (caddr_t)&res);
	return (res.status);

}

OM_uint32
kgss_export_sec_context(minor_status,
			context_handle,
			output_token)
	OM_uint32 *minor_status;
	gss_ctx_id_t *context_handle;
	gss_buffer_t output_token;
{
	OM_uint32 err;
	struct kgss_ctx *kctx;

	if (*context_handle == GSS_C_NO_CONTEXT) {
		return (GSS_S_NO_CONTEXT);
	} else
		kctx = KCTX_TO_KGSS_CTX(*context_handle);

	err = kgss_export_sec_context_wrapped(minor_status,
		&kctx->gssd_ctx, output_token,
		kctx->gssd_ctx_verifier);

	if (GSS_ERROR(err))
		return (err);
	else {
		KGSS_FREE(kctx);
		*context_handle = GSS_C_NO_CONTEXT;
		return (err);
	}

}

OM_uint32
kgss_import_sec_context_wrapped(minor_status,
			input_token,
			context_handle,
			gssd_context_verifier)
	OM_uint32 *minor_status;
	gss_buffer_t input_token;
	gss_ctx_id_t *context_handle;
	OM_uint32 gssd_context_verifier;
{
	CLIENT *clnt;
	gss_import_sec_context_arg arg;
	gss_import_sec_context_res res;


/* get the client handle to GSSD */

	if ((clnt = getgssd_handle()) == NULL) {
		clnt_pcreateerror(server);
		return (GSS_S_FAILURE);
	}

/* copy the procedure arguments into the rpc arg parameter */
	arg.input_token.GSS_BUFFER_T_len = (uint_t)
		(input_token != GSS_C_NO_BUFFER ? input_token->length : 0);
	arg.input_token.GSS_BUFFER_T_val = (char *)
		(input_token != GSS_C_NO_BUFFER ? input_token->value : 0);
	arg.gssd_context_verifier = gssd_context_verifier;


/* call the remote procedure */

	memset(&res, 0, sizeof (res));
	if (gss_import_sec_context_1(&arg, &res, clnt) != RPC_SUCCESS) {

/*
 * if the RPC call times out, null out all return arguments, set minor_status
 * to its maximum value, and return GSS_S_FAILURE
 */

		if (minor_status != NULL)
			*minor_status = DEFAULT_MINOR_STAT;
		if (context_handle != NULL)
			*context_handle = NULL;

		return (GSS_S_FAILURE);
	}

/* copy the rpc results into the return arguments */

	if (minor_status != NULL)
		*minor_status = res.minor_status;

	if (res.context_handle.GSS_CTX_ID_T_len == 0)
		*context_handle = NULL;
	else
		*context_handle =
		    *((gss_ctx_id_t *)res.context_handle.GSS_CTX_ID_T_val);


/*
 * free the memory allocated for the results and return with the status
 * received in the rpc call
 */

	clnt_freeres(clnt, xdr_gss_import_sec_context_res, (caddr_t)&res);
	return (res.status);
}

OM_uint32
kgss_import_sec_context(minor_status,
			input_token,
			context_handle)
	OM_uint32 *minor_status;
	gss_buffer_t input_token;
	gss_ctx_id_t *context_handle;
{
	struct kgss_ctx *kctx;

	if (*context_handle == GSS_C_NO_CONTEXT) {
		kctx = KGSS_ALLOC();
		*context_handle = (gss_ctx_id_t)kctx;
		kctx->gssd_ctx = (OM_uint32) GSS_C_NO_CONTEXT;
	} else
		kctx = (struct kgss_ctx *)*context_handle;
	return (kgss_import_sec_context_wrapped(minor_status,
		input_token, &kctx->gssd_ctx,
		KCTX_TO_CTXV(context_handle)));
}

#ifdef _KERNEL
#include <sys/modctl.h>

static void *gss_clnt = NULL;

#ifdef DEBUG
typedef struct {
	char		*name;		/* just put something here */
} gssd_devstate_t;


static void *gssd_state;

static int gssd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	/*	 cmn_err(CE_NOTE, "In gssd_attach"); */
	switch (cmd) {
	case DDI_ATTACH:
		if (ddi_create_minor_node(dip, "gssd", S_IFCHR, 0, "gssd", 0)
		    == DDI_FAILURE) {
			ddi_remove_minor_node(dip, NULL);
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int gssd_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd,
		void *arg, void **result)
{
	dev_t dev;
	int error;

/*	 cmn_err(CE_NOTE, "In gssd_getinfo"); */

	switch (infocmd) {
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		*result = (void *) getminor(dev);
		error = DDI_SUCCESS;
		break;

	case DDI_INFO_DEVT2DEVINFO:
	/*	cmn_err(CE_NOTE, "getinfo wants devinfo"); */
	default:
		error = DDI_FAILURE;
		break;
	}
	return (error);
}

static int gssd_identify(dev_info_t *dip)
{
	/*	 cmn_err(CE_NOTE, "in gssd_identify"); */
	if (strcmp(ddi_get_name(dip), "gssd") == 0)
		return (DDI_IDENTIFIED);
	else
		return (DDI_NOT_IDENTIFIED);
}

static int gssd_probe(dev_info_t *dip)
{
	/*	 cmn_err(CE_NOTE, "In gssd_probe"); */

	return (DDI_PROBE_SUCCESS);
}

static int gssd_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	/*	 cmn_err (CE_NOTE, "In gssd_open"); */
	if (otyp != OTYP_CHR)
		return (EINVAL);

	gss_clnt = getgssd_handle();
	return (0);
}

static int gssd_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	/*	 cmn_err(CE_NOTE, "In gssd_close"); */
	killgssd_handle(gss_clnt);
	return (0);
}

static int gssd_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	char buffer[1024];
	int len;

	/*	 cmn_err(CE_NOTE, "In gssd_write"); */
	bzero(buffer, 1024);

	uiomove(buffer, 1024, UIO_WRITE, uiop);
	len = strlen(buffer);

	if (buffer[len-1] == '\n')
		buffer[--len] = '\0';

	cmn_err(CE_NOTE, "Got command: (%d) \"%s\"", len, buffer);
	do_gssdtest(buffer);
	return (0);
}

static struct cb_ops gssd_cb_ops = {
	gssd_open,		/* cb_open */
	gssd_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nulldev,		/* cb_read */
	gssd_write,		/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	(int)(D_NEW|D_MP)	/* cb_flag */
};

static struct dev_ops gssd_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	gssd_getinfo,		/* devo_getinfo */
	gssd_identify,		/* devo_identify */
	nulldev,		/* devo_probe */
	gssd_attach,		/* devo_attach */
	nulldev,		/* devo_detach */
	nodev,			/* devo_reset */
	&gssd_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL	/* devo_bus_ops */
};

extern struct mod_ops mod_driverops;

static struct modldrv modlmisc = {
	&mod_driverops,
	"GSSD DRV Client Module",
	&gssd_ops

#else /* !DEBUG */

static struct modlmisc modlmisc = {
	&mod_miscops,
	"GSSD Client Module"
#endif /* DEBUG */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlmisc,
	NULL
};

char _depends_on[] = "strmod/rpcmod misc/tlimod";

_init(void)
{
	int status;

	if ((status = ddi_soft_state_init(&gssd_state,
	    sizeof (gssd_devstate_t), 1)) != 0)
		return (status);

	if ((status = mod_install((struct modlinkage *)&modlinkage)) != 0)
		ddi_soft_state_fini(&gssd_state);

	cmn_err(CE_NOTE, "gssd: I'm in the kernel: %d.", status);
	return (status);
}

_fini()
{
	int status;

	killgssd_handle(gss_clnt);
	cmn_err(CE_NOTE, "gssd: Handle destroyed.. leaving module.");

	if ((status = mod_remove(&modlinkage)) != 0)
		return (status);

	ddi_soft_state_fini(&gssd_state);
	return (status);
}

_info(modinfop)
struct modinfo *modinfop;
{
	return (mod_info(&modlinkage, modinfop));
}

#endif
