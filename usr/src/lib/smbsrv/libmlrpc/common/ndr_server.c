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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Server side RPC handler.
 */

#include <sys/byteorder.h>
#include <thread.h>
#include <synch.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <time.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/ndr.h>
#include <smbsrv/mlrpc.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/smb_winpipe.h>

/*
 * Fragment size (5680: NT style).
 */
#define	MLRPC_FRAG_SZ		5680
static unsigned long mlrpc_frag_size = MLRPC_FRAG_SZ;

/*
 * Context table.
 */
#define	CTXT_TABLE_ENTRIES	128
static struct mlsvc_rpc_context context_table[CTXT_TABLE_ENTRIES];
static mutex_t mlrpc_context_lock;

static int mlrpc_s_process(struct mlrpc_xaction *);
static int mlrpc_s_bind(struct mlrpc_xaction *);
static int mlrpc_s_request(struct mlrpc_xaction *);
static void mlrpc_reply_prepare_hdr(struct mlrpc_xaction *);
static int mlrpc_s_alter_context(struct mlrpc_xaction *);
static void mlrpc_reply_bind_ack(struct mlrpc_xaction *);
static void mlrpc_reply_fault(struct mlrpc_xaction *, unsigned long);
static int mlrpc_build_reply(struct mlrpc_xaction *);

/*
 * This is the RPC service server-side entry point.  All MSRPC encoded
 * messages should be passed through here.  We use the same context
 * structure as the client side but we don't need to set up the client
 * side info.
 */
struct mlsvc_rpc_context *
mlrpc_process(int fid, smb_dr_user_ctx_t *user_ctx)
{
	struct mlsvc_rpc_context	*context;
	struct mlrpc_xaction		*mxa;
	struct mlndr_stream		*recv_mlnds;
	struct mlndr_stream		*send_mlnds;
	unsigned char			*pdu_base_addr;
	char				*data;
	int				datalen;

	if ((context = mlrpc_lookup(fid)) == NULL)
		return (NULL);

	context->user_ctx = user_ctx;
	data = context->inpipe->sp_data;
	datalen = context->inpipe->sp_datalen;

	mxa = (struct mlrpc_xaction *)malloc(sizeof (struct mlrpc_xaction));
	if (mxa == NULL)
		return (NULL);

	bzero(mxa, sizeof (struct mlrpc_xaction));
	mxa->fid = fid;
	mxa->context = context;
	mxa->binding_list = context->binding;

	if ((mxa->heap = mlrpc_heap_create()) == NULL) {
		free(mxa);
		return (NULL);
	}

	recv_mlnds = &mxa->recv_mlnds;
	(void) mlnds_initialize(recv_mlnds, datalen, NDR_MODE_CALL_RECV,
	    mxa->heap);

	bcopy(data, recv_mlnds->pdu_base_addr, datalen);

	send_mlnds = &mxa->send_mlnds;
	(void) mlnds_initialize(send_mlnds, 0, NDR_MODE_RETURN_SEND, mxa->heap);

	(void) mlrpc_s_process(mxa);

	/*
	 * Different pointers for single frag vs multi frag responses.
	 */
	if (send_mlnds->pdu_base_addr_with_rpc_hdrs)
		pdu_base_addr = send_mlnds->pdu_base_addr_with_rpc_hdrs;
	else
		pdu_base_addr = send_mlnds->pdu_base_addr;

	datalen = send_mlnds->pdu_size_with_rpc_hdrs;
	context->outpipe->sp_datalen = datalen;
	bcopy(pdu_base_addr, context->outpipe->sp_data, datalen);

	mlnds_destruct(&mxa->recv_mlnds);
	mlnds_destruct(&mxa->send_mlnds);
	mlrpc_heap_destroy(mxa->heap);
	free(mxa);
	return (context);
}

/*
 * Lookup the context for pipeid. If one exists, return a pointer to it.
 * Otherwise attempt to allocate a new context and return it. If the
 * context table is full, return a null pointer.
 */
struct mlsvc_rpc_context *
mlrpc_lookup(int fid)
{
	struct mlsvc_rpc_context *context;
	struct mlsvc_rpc_context *available = NULL;
	int i;

	(void) mutex_lock(&mlrpc_context_lock);

	for (i = 0; i < CTXT_TABLE_ENTRIES; ++i) {
		context = &context_table[i];

		if (available == NULL && context->fid == 0) {
			available = context;
			continue;
		}

		if (context->fid == fid) {
			(void) mutex_unlock(&mlrpc_context_lock);
			return (context);
		}
	}

	if (available) {
		bzero(available, sizeof (struct mlsvc_rpc_context));
		available->inpipe = malloc(SMB_CTXT_PIPE_SZ);
		available->outpipe = malloc(SMB_CTXT_PIPE_SZ);

		if (available->inpipe == NULL || available->outpipe == NULL) {
			free(available->inpipe);
			free(available->outpipe);
			bzero(available, sizeof (struct mlsvc_rpc_context));
			(void) mutex_unlock(&mlrpc_context_lock);
			return (NULL);
		}

		bzero(available->inpipe, sizeof (smb_pipe_t));
		bzero(available->outpipe, sizeof (smb_pipe_t));
		available->fid = fid;
		available->inpipe->sp_pipeid = fid;
		available->outpipe->sp_pipeid = fid;

		mlrpc_binding_pool_initialize(&available->binding,
		    available->binding_pool, CTXT_N_BINDING_POOL);
	}

	(void) mutex_unlock(&mlrpc_context_lock);
	return (available);
}

/*
 * This function should be called to release the context associated
 * with a fid when the client performs a close file.
 */
void
mlrpc_release(int fid)
{
	struct mlsvc_rpc_context *context;
	int i;

	(void) mutex_lock(&mlrpc_context_lock);

	for (i = 0; i < CTXT_TABLE_ENTRIES; ++i) {
		context = &context_table[i];

		if (context->fid == fid) {
			ndr_hdclose(fid);
			free(context->inpipe);
			free(context->outpipe);
			bzero(context, sizeof (struct mlsvc_rpc_context));
			break;
		}
	}

	(void) mutex_unlock(&mlrpc_context_lock);
}

/*
 * This is the entry point for all server-side RPC processing.
 * It is assumed that the PDU has already been received.
 */
static int
mlrpc_s_process(struct mlrpc_xaction *mxa)
{
	int rc;

	rc = mlrpc_decode_pdu_hdr(mxa);
	if (!MLRPC_DRC_IS_OK(rc))
		return (-1);

	(void) mlrpc_reply_prepare_hdr(mxa);

	switch (mxa->ptype) {
	case MLRPC_PTYPE_BIND:
		rc = mlrpc_s_bind(mxa);
		break;

	case MLRPC_PTYPE_REQUEST:
		rc = mlrpc_s_request(mxa);
		break;

	case MLRPC_PTYPE_ALTER_CONTEXT:
		rc = mlrpc_s_alter_context(mxa);
		break;

	default:
		rc = MLRPC_DRC_FAULT_RPCHDR_PTYPE_INVALID;
		break;
	}

	if (MLRPC_DRC_IS_FAULT(rc))
		mlrpc_reply_fault(mxa, rc);

	(void) mlrpc_build_reply(mxa);
	return (rc);
}

/*
 * Multiple p_cont_elem[]s, multiple transfer_syntaxes[] and multiple
 * p_results[] not supported.
 */
static int
mlrpc_s_bind(struct mlrpc_xaction *mxa)
{
	mlrpc_p_cont_list_t	*cont_list;
	mlrpc_p_result_list_t	*result_list;
	mlrpc_p_result_t	*result;
	unsigned		p_cont_id;
	struct mlrpc_binding	*mbind;
	ndr_uuid_t		*as_uuid;
	ndr_uuid_t		*ts_uuid;
	char			as_buf[64];
	char			ts_buf[64];
	int			as_vers;
	int			ts_vers;
	struct mlndr_stream	*send_mlnds;
	struct mlrpc_service	*msvc;
	int			rc;
	mlrpc_port_any_t	*sec_addr;

	/* acquire targets */
	cont_list = &mxa->recv_hdr.bind_hdr.p_context_elem;
	result_list = &mxa->send_hdr.bind_ack_hdr.p_result_list;
	result = &result_list->p_results[0];

	/*
	 * Set up temporary secondary address port.
	 * We will correct this later (below).
	 */
	send_mlnds = &mxa->send_mlnds;
	sec_addr = &mxa->send_hdr.bind_ack_hdr.sec_addr;
	sec_addr->length = 13;
	(void) strcpy((char *)sec_addr->port_spec, "\\PIPE\\ntsvcs");

	result_list->n_results = 1;
	result_list->reserved = 0;
	result_list->reserved2 = 0;
	result->result = MLRPC_PCDR_ACCEPTANCE;
	result->reason = 0;
	bzero(&result->transfer_syntax, sizeof (result->transfer_syntax));

	/* sanity check */
	if (cont_list->n_context_elem != 1 ||
	    cont_list->p_cont_elem[0].n_transfer_syn != 1) {
		mlndo_trace("mlrpc_s_bind: warning: multiple p_cont_elem");
	}

	p_cont_id = cont_list->p_cont_elem[0].p_cont_id;

	if ((mbind = mlrpc_find_binding(mxa, p_cont_id)) != NULL) {
		/*
		 * Duplicate p_cont_id.
		 * Send a bind_ack with a better error.
		 */
		mlndo_trace("mlrpc_s_bind: duplicate binding");
		return (MLRPC_DRC_FAULT_BIND_PCONT_BUSY);
	}

	if ((mbind = mlrpc_new_binding(mxa)) == NULL) {
		/*
		 * No free binding slot
		 */
		result->result = MLRPC_PCDR_PROVIDER_REJECTION;
		result->reason = MLRPC_PPR_LOCAL_LIMIT_EXCEEDED;
		mlndo_trace("mlrpc_s_bind: no resources");
		return (MLRPC_DRC_OK);
	}

	as_uuid = &cont_list->p_cont_elem[0].abstract_syntax.if_uuid;
	as_vers = cont_list->p_cont_elem[0].abstract_syntax.if_version;

	ts_uuid = &cont_list->p_cont_elem[0].transfer_syntaxes[0].if_uuid;
	ts_vers = cont_list->p_cont_elem[0].transfer_syntaxes[0].if_version;

	msvc = mlrpc_find_service_by_uuids(as_uuid, as_vers, ts_uuid, ts_vers);
	if (!msvc) {
		mlrpc_uuid_to_str(as_uuid, as_buf);
		mlrpc_uuid_to_str(ts_uuid, ts_buf);

		mlndo_printf(send_mlnds, 0, "mlrpc_s_bind: unknown service");
		mlndo_printf(send_mlnds, 0, "abs=%s v%d, xfer=%s v%d",
		    as_buf, as_vers, ts_buf, ts_vers);

		result->result = MLRPC_PCDR_PROVIDER_REJECTION;
		result->reason = MLRPC_PPR_ABSTRACT_SYNTAX_NOT_SUPPORTED;
		return (MLRPC_DRC_OK);
	}

	/*
	 * We can now use the correct secondary address port.
	 */
	sec_addr = &mxa->send_hdr.bind_ack_hdr.sec_addr;
	sec_addr->length = strlen(msvc->sec_addr_port) + 1;
	(void) strlcpy((char *)sec_addr->port_spec, msvc->sec_addr_port,
	    MLRPC_PORT_ANY_MAX_PORT_SPEC);

	mbind->p_cont_id = p_cont_id;
	mbind->which_side = MLRPC_BIND_SIDE_SERVER;
	/* mbind->context set by app */
	mbind->service = msvc;
	mbind->instance_specific = 0;

	mxa->binding = mbind;

	if (msvc->bind_req) {
		/*
		 * Call the service-specific bind() handler.  If
		 * this fails, we shouild send a specific error
		 * on the bind ack.
		 */
		rc = (msvc->bind_req)(mxa);
		if (MLRPC_DRC_IS_FAULT(rc)) {
			mbind->service = 0;	/* free binding slot */
			mbind->which_side = 0;
			mbind->p_cont_id = 0;
			mbind->instance_specific = 0;
			return (rc);
		}
	}

	result->transfer_syntax =
	    cont_list->p_cont_elem[0].transfer_syntaxes[0];

	/*
	 * Special rejection of Windows 2000 DSSETUP interface.
	 * This interface was introduced in Windows 2000 but has
	 * been subsequently deprecated due to problems.
	 */
	if (strcmp(msvc->name, "DSSETUP") == 0) {
		result->result = MLRPC_PCDR_PROVIDER_REJECTION;
		result->reason = MLRPC_PPR_ABSTRACT_SYNTAX_NOT_SUPPORTED;
	}

	return (MLRPC_DRC_BINDING_MADE);
}

/*
 * mlrpc_s_alter_context
 *
 * The alter context request is used to request additional presentation
 * context for another interface and/or version. It's very similar to a
 * bind request.
 *
 * We don't fully support multiple contexts so, for now, we reject this
 * request.  Windows 2000 clients attempt to use an alternate LSA context
 * when ACLs are modified.
 */
static int
mlrpc_s_alter_context(struct mlrpc_xaction *mxa)
{
	mlrpc_p_result_list_t *result_list;
	mlrpc_p_result_t *result;
	mlrpc_p_cont_list_t *cont_list;
	struct mlrpc_binding *mbind;
	struct mlrpc_service *msvc;
	unsigned p_cont_id;
	ndr_uuid_t *as_uuid;
	ndr_uuid_t *ts_uuid;
	int as_vers;
	int ts_vers;
	mlrpc_port_any_t *sec_addr;

	result_list = &mxa->send_hdr.bind_ack_hdr.p_result_list;
	result_list->n_results = 1;
	result_list->reserved = 0;
	result_list->reserved2 = 0;

	result = &result_list->p_results[0];
	result->result = MLRPC_PCDR_ACCEPTANCE;
	result->reason = 0;
	bzero(&result->transfer_syntax, sizeof (result->transfer_syntax));

	if (mxa != NULL) {
		result->result = MLRPC_PCDR_PROVIDER_REJECTION;
		result->reason = MLRPC_PPR_ABSTRACT_SYNTAX_NOT_SUPPORTED;
		return (MLRPC_DRC_OK);
	}

	cont_list = &mxa->recv_hdr.bind_hdr.p_context_elem;
	p_cont_id = cont_list->p_cont_elem[0].p_cont_id;

	if ((mbind = mlrpc_find_binding(mxa, p_cont_id)) != NULL)
		return (MLRPC_DRC_FAULT_BIND_PCONT_BUSY);

	if ((mbind = mlrpc_new_binding(mxa)) == NULL) {
		result->result = MLRPC_PCDR_PROVIDER_REJECTION;
		result->reason = MLRPC_PPR_LOCAL_LIMIT_EXCEEDED;
		return (MLRPC_DRC_OK);
	}

	as_uuid = &cont_list->p_cont_elem[0].abstract_syntax.if_uuid;
	as_vers = cont_list->p_cont_elem[0].abstract_syntax.if_version;

	ts_uuid = &cont_list->p_cont_elem[0].transfer_syntaxes[0].if_uuid;
	ts_vers = cont_list->p_cont_elem[0].transfer_syntaxes[0].if_version;

	msvc = mlrpc_find_service_by_uuids(as_uuid, as_vers, ts_uuid, ts_vers);
	if (msvc == 0) {
		result->result = MLRPC_PCDR_PROVIDER_REJECTION;
		result->reason = MLRPC_PPR_ABSTRACT_SYNTAX_NOT_SUPPORTED;
		return (MLRPC_DRC_OK);
	}

	mbind->p_cont_id = p_cont_id;
	mbind->which_side = MLRPC_BIND_SIDE_SERVER;
	/* mbind->context set by app */
	mbind->service = msvc;
	mbind->instance_specific = 0;
	mxa->binding = mbind;

	sec_addr = &mxa->send_hdr.bind_ack_hdr.sec_addr;
	sec_addr->length = 0;
	bzero(sec_addr->port_spec, MLRPC_PORT_ANY_MAX_PORT_SPEC);

	result->transfer_syntax =
	    cont_list->p_cont_elem[0].transfer_syntaxes[0];

	return (MLRPC_DRC_BINDING_MADE);
}

static int
mlrpc_s_request(struct mlrpc_xaction *mxa)
{
	struct mlrpc_binding	*mbind;
	struct mlrpc_service	*msvc;
	unsigned		p_cont_id;
	int			rc;

	mxa->opnum = mxa->recv_hdr.request_hdr.opnum;
	p_cont_id = mxa->recv_hdr.request_hdr.p_cont_id;

	if ((mbind = mlrpc_find_binding(mxa, p_cont_id)) == NULL)
		return (MLRPC_DRC_FAULT_REQUEST_PCONT_INVALID);

	mxa->binding = mbind;
	msvc = mbind->service;

	/*
	 * Make room for the response hdr.
	 */
	mxa->send_mlnds.pdu_scan_offset = MLRPC_RSP_HDR_SIZE;

	if (msvc->call_stub)
		rc = (*msvc->call_stub)(mxa);
	else
		rc = mlrpc_generic_call_stub(mxa);

	if (MLRPC_DRC_IS_FAULT(rc)) {
		mlndo_printf(0, 0, "%s[0x%02x]: 0x%04x",
		    msvc->name, mxa->opnum, rc);
	}

	return (rc);
}

/*
 * The transaction and the two mlnds streams use the same heap, which
 * should already exist at this point.  The heap will also be available
 * to the stub.
 */
int
mlrpc_generic_call_stub(struct mlrpc_xaction *mxa)
{
	struct mlrpc_binding 	*mbind = mxa->binding;
	struct mlrpc_service 	*msvc = mbind->service;
	struct ndr_typeinfo 	*intf_ti = msvc->interface_ti;
	struct mlrpc_stub_table *ste;
	int			opnum = mxa->opnum;
	unsigned		p_len = intf_ti->c_size_fixed_part;
	char 			*param;
	int			rc;

	if (mxa->heap == NULL) {
		mlndo_printf(0, 0, "%s[0x%02x]: no heap", msvc->name, opnum);
		return (MLRPC_DRC_FAULT_OUT_OF_MEMORY);
	}

	if ((ste = mlrpc_find_stub_in_svc(msvc, opnum)) == NULL) {
		mlndo_printf(0, 0, "%s[0x%02x]: invalid opnum",
		    msvc->name, opnum);
		return (MLRPC_DRC_FAULT_REQUEST_OPNUM_INVALID);
	}

	if ((param = mlrpc_heap_malloc(mxa->heap, p_len)) == NULL)
		return (MLRPC_DRC_FAULT_OUT_OF_MEMORY);

	bzero(param, p_len);

	rc = mlrpc_decode_call(mxa, param);
	if (!MLRPC_DRC_IS_OK(rc))
		return (rc);

	rc = (*ste->func)(param, mxa);
	if (rc == MLRPC_DRC_OK)
		rc = mlrpc_encode_return(mxa, param);

	return (rc);
}

/*
 * We can perform some initial setup of the response header here.
 * We also need to cache some of the information from the bind
 * negotiation for use during subsequent RPC calls.
 */
static void
mlrpc_reply_prepare_hdr(struct mlrpc_xaction *mxa)
{
	mlrpcconn_common_header_t *rhdr = &mxa->recv_hdr.common_hdr;
	mlrpcconn_common_header_t *hdr = &mxa->send_hdr.common_hdr;

	hdr->rpc_vers = 5;
	hdr->rpc_vers_minor = 0;
	hdr->pfc_flags = MLRPC_PFC_FIRST_FRAG + MLRPC_PFC_LAST_FRAG;
	hdr->packed_drep = rhdr->packed_drep;
	hdr->frag_length = 0;
	hdr->auth_length = 0;
	hdr->call_id = rhdr->call_id;
#ifdef _BIG_ENDIAN
	hdr->packed_drep.intg_char_rep = MLRPC_REPLAB_CHAR_ASCII
	    | MLRPC_REPLAB_INTG_BIG_ENDIAN;
#else
	hdr->packed_drep.intg_char_rep = MLRPC_REPLAB_CHAR_ASCII
	    | MLRPC_REPLAB_INTG_LITTLE_ENDIAN;
#endif

	switch (mxa->ptype) {
	case MLRPC_PTYPE_BIND:
		hdr->ptype = MLRPC_PTYPE_BIND_ACK;
		mxa->send_hdr.bind_ack_hdr.max_xmit_frag =
		    mxa->recv_hdr.bind_hdr.max_xmit_frag;
		mxa->send_hdr.bind_ack_hdr.max_recv_frag =
		    mxa->recv_hdr.bind_hdr.max_recv_frag;
		mxa->send_hdr.bind_ack_hdr.assoc_group_id =
		    mxa->recv_hdr.bind_hdr.assoc_group_id;

		if (mxa->send_hdr.bind_ack_hdr.assoc_group_id == 0)
			mxa->send_hdr.bind_ack_hdr.assoc_group_id = time(0);

		/*
		 * Save the maximum fragment sizes
		 * for use with subsequent requests.
		 */
		mxa->context->max_xmit_frag =
		    mxa->recv_hdr.bind_hdr.max_xmit_frag;

		mxa->context->max_recv_frag =
		    mxa->recv_hdr.bind_hdr.max_recv_frag;

		break;

	case MLRPC_PTYPE_REQUEST:
		hdr->ptype = MLRPC_PTYPE_RESPONSE;
		/* mxa->send_hdr.response_hdr.alloc_hint */
		mxa->send_hdr.response_hdr.p_cont_id =
		    mxa->recv_hdr.request_hdr.p_cont_id;
		mxa->send_hdr.response_hdr.cancel_count = 0;
		mxa->send_hdr.response_hdr.reserved = 0;
		break;

	case MLRPC_PTYPE_ALTER_CONTEXT:
		hdr->ptype = MLRPC_PTYPE_ALTER_CONTEXT_RESP;
		/*
		 * The max_xmit_frag, max_recv_frag
		 * and assoc_group_id are ignored.
		 */
		break;

	default:
		hdr->ptype = 0xFF;
	}
}

/*
 * Finish and encode the bind acknowledge (MLRPC_PTYPE_BIND_ACK) header.
 * The frag_length is different from a regular RPC response.
 */
static void
mlrpc_reply_bind_ack(struct mlrpc_xaction *mxa)
{
	mlrpcconn_common_header_t	*hdr;
	mlrpcconn_bind_ack_hdr_t	*bahdr;

	hdr = &mxa->send_hdr.common_hdr;
	bahdr = &mxa->send_hdr.bind_ack_hdr;
	hdr->frag_length = mlrpc_bind_ack_hdr_size(bahdr);
}

/*
 * Signal an RPC fault. The stream is reset and we overwrite whatever
 * was in the response header with the fault information.
 */
static void
mlrpc_reply_fault(struct mlrpc_xaction *mxa, unsigned long drc)
{
	mlrpcconn_common_header_t *rhdr = &mxa->recv_hdr.common_hdr;
	mlrpcconn_common_header_t *hdr = &mxa->send_hdr.common_hdr;
	struct mlndr_stream *mlnds = &mxa->send_mlnds;
	unsigned long fault_status;

	MLNDS_RESET(mlnds);

	hdr->rpc_vers = 5;
	hdr->rpc_vers_minor = 0;
	hdr->pfc_flags = MLRPC_PFC_FIRST_FRAG + MLRPC_PFC_LAST_FRAG;
	hdr->packed_drep = rhdr->packed_drep;
	hdr->frag_length = sizeof (mxa->send_hdr.fault_hdr);
	hdr->auth_length = 0;
	hdr->call_id = rhdr->call_id;
#ifdef _BIG_ENDIAN
	hdr->packed_drep.intg_char_rep = MLRPC_REPLAB_CHAR_ASCII
	    | MLRPC_REPLAB_INTG_BIG_ENDIAN;
#else
	hdr->packed_drep.intg_char_rep = MLRPC_REPLAB_CHAR_ASCII
	    | MLRPC_REPLAB_INTG_LITTLE_ENDIAN;
#endif

	switch (drc & MLRPC_DRC_MASK_SPECIFIER) {
	case MLRPC_DRC_FAULT_OUT_OF_MEMORY:
	case MLRPC_DRC_FAULT_ENCODE_TOO_BIG:
		fault_status = MLRPC_FAULT_NCA_OUT_ARGS_TOO_BIG;
		break;

	case MLRPC_DRC_FAULT_REQUEST_PCONT_INVALID:
		fault_status = MLRPC_FAULT_NCA_INVALID_PRES_CONTEXT_ID;
		break;

	case MLRPC_DRC_FAULT_REQUEST_OPNUM_INVALID:
		fault_status = MLRPC_FAULT_NCA_OP_RNG_ERROR;
		break;

	case MLRPC_DRC_FAULT_DECODE_FAILED:
	case MLRPC_DRC_FAULT_ENCODE_FAILED:
		fault_status = MLRPC_FAULT_NCA_PROTO_ERROR;
		break;

	default:
		fault_status = MLRPC_FAULT_NCA_UNSPEC_REJECT;
		break;
	}

	mxa->send_hdr.fault_hdr.common_hdr.ptype = MLRPC_PTYPE_FAULT;
	mxa->send_hdr.fault_hdr.status = fault_status;
	mxa->send_hdr.response_hdr.alloc_hint = hdr->frag_length;
}

static int
mlrpc_build_reply(struct mlrpc_xaction *mxa)
{
	mlrpcconn_common_header_t *hdr = &mxa->send_hdr.common_hdr;
	struct mlndr_stream *mlnds = &mxa->send_mlnds;
	unsigned long pdu_size;
	unsigned long frag_size;
	unsigned long pdu_data_size;
	unsigned long frag_data_size;
	uint32_t rem_dlen;
	uint32_t save_rem_dlen;
	uint32_t bytesoff;
	uint32_t cnt;
	uint32_t obytes;
	uint32_t num_ext_frags;
	uint16_t last_frag = 0;
	uchar_t  *frag_startp;
	mlrpcconn_common_header_t *rpc_hdr;

	hdr = &mxa->send_hdr.common_hdr;

	frag_size = mlrpc_frag_size;
	pdu_size = mlnds->pdu_size;

	if (pdu_size <= frag_size) {
		/*
		 * Single fragment response. The PDU size may be zero
		 * here (i.e. bind or fault response). So don't make
		 * any assumptions about it until after the header is
		 * encoded.
		 */
		switch (hdr->ptype) {
		case MLRPC_PTYPE_BIND_ACK:
			mlrpc_reply_bind_ack(mxa);
			break;

		case MLRPC_PTYPE_FAULT:
			/* already setup */
			break;

		case MLRPC_PTYPE_RESPONSE:
			hdr->frag_length = pdu_size;
			mxa->send_hdr.response_hdr.alloc_hint =
			    hdr->frag_length;
			break;

		default:
			hdr->frag_length = pdu_size;
			break;
		}

		mlnds->pdu_scan_offset = 0;
		(void) mlrpc_encode_pdu_hdr(mxa);

		mlnds->pdu_size_with_rpc_hdrs = mlnds->pdu_size;
		mlnds->pdu_base_addr_with_rpc_hdrs = 0;
		return (0);
	}

	/*
	 * Multiple fragment response.
	 */
	hdr->pfc_flags = MLRPC_PFC_FIRST_FRAG;
	hdr->frag_length = frag_size;
	mxa->send_hdr.response_hdr.alloc_hint = pdu_size - MLRPC_RSP_HDR_SIZE;
	mlnds->pdu_scan_offset = 0;

	(void) mlrpc_encode_pdu_hdr(mxa);

	/*
	 * We need to update the 24-byte header in subsequent fragments.
	 *
	 *	pdu_data_size:	total data remaining to be handled
	 *	frag_size:		total fragment size including header
	 *	frag_data_size: data in fragment
	 *			(i.e. frag_size - MLRPC_RSP_HDR_SIZE)
	 */
	pdu_data_size = pdu_size - MLRPC_RSP_HDR_SIZE;
	frag_data_size = frag_size - MLRPC_RSP_HDR_SIZE;

	num_ext_frags = pdu_data_size / frag_data_size;

	/*
	 * We may need to stretch the pipe and insert an RPC header
	 * at each frag boundary.  The response will get chunked into
	 * xdrlen sizes for each trans request.
	 */
	mlnds->pdu_base_addr_with_rpc_hdrs
	    = malloc(pdu_size + (num_ext_frags * MLRPC_RSP_HDR_SIZE));
	mlnds->pdu_size_with_rpc_hdrs =
	    mlnds->pdu_size + (num_ext_frags * MLRPC_RSP_HDR_SIZE);

	/*
	 * Start stretching loop.
	 */
	bcopy(mlnds->pdu_base_addr,
	    mlnds->pdu_base_addr_with_rpc_hdrs, frag_size);
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	rpc_hdr = (mlrpcconn_common_header_t *)
	    mlnds->pdu_base_addr_with_rpc_hdrs;
	rpc_hdr->pfc_flags = MLRPC_PFC_FIRST_FRAG;
	rem_dlen = pdu_data_size - frag_size;
	bytesoff = frag_size;
	cnt = 1;
	while (num_ext_frags--) {
		/* first copy the RPC header to the front of the frag */
		bcopy(mlnds->pdu_base_addr, mlnds->pdu_base_addr_with_rpc_hdrs +
		    (cnt * frag_size), MLRPC_RSP_HDR_SIZE);

		/* then copy the data portion of the frag */
		save_rem_dlen = rem_dlen;
		if (rem_dlen >= (frag_size - MLRPC_RSP_HDR_SIZE)) {
			rem_dlen = rem_dlen - frag_size + MLRPC_RSP_HDR_SIZE;
			obytes = frag_size - MLRPC_RSP_HDR_SIZE;
		} else {
			last_frag = 1;   /* this is the last one */
			obytes = rem_dlen;
		}

		frag_startp = mlnds->pdu_base_addr_with_rpc_hdrs +
		    (cnt * frag_size);
		bcopy(mlnds->pdu_base_addr + bytesoff,
		    frag_startp + MLRPC_RSP_HDR_SIZE, obytes);

		/* set the FRAG FLAGS in the frag header spot */
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		rpc_hdr = (mlrpcconn_common_header_t *)frag_startp;
		if (last_frag) {
			rpc_hdr->frag_length = save_rem_dlen;
			rpc_hdr->pfc_flags = MLRPC_PFC_LAST_FRAG;
		} else {
			rpc_hdr->pfc_flags = 0;
		}

		bytesoff += (frag_size - MLRPC_RSP_HDR_SIZE);
		cnt++;
	}

	return (0);
}
