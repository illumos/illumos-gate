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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Server side RPC handler.
 */

#include <sys/byteorder.h>
#include <sys/uio.h>
#include <errno.h>
#include <synch.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <thread.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/ntaccess.h>

#define	NDR_PIPE_SEND(np, buf, len) \
	((np)->np_send)((np), (buf), (len))
#define	NDR_PIPE_RECV(np, buf, len) \
	((np)->np_recv)((np), (buf), (len))

static int ndr_svc_process(ndr_xa_t *);
static int ndr_svc_bind(ndr_xa_t *);
static int ndr_svc_request(ndr_xa_t *);
static void ndr_reply_prepare_hdr(ndr_xa_t *);
static int ndr_svc_alter_context(ndr_xa_t *);
static void ndr_reply_fault(ndr_xa_t *, unsigned long);

static int ndr_recv_request(ndr_xa_t *mxa);
static int ndr_recv_frag(ndr_xa_t *mxa);
static int ndr_send_reply(ndr_xa_t *);

static int ndr_pipe_process(ndr_pipe_t *, ndr_xa_t *);

/*
 * External entry point called by smbd.
 */
void
ndr_pipe_worker(ndr_pipe_t *np)
{
	ndr_xa_t	*mxa;
	int rc;

	ndr_svc_binding_pool_init(&np->np_binding, np->np_binding_pool,
	    NDR_N_BINDING_POOL);

	if ((mxa = malloc(sizeof (*mxa))) == NULL)
		return;

	do {
		bzero(mxa, sizeof (*mxa));
		rc = ndr_pipe_process(np, mxa);
	} while (rc == 0);

	free(mxa);

	/*
	 * Ensure that there are no RPC service policy handles
	 * (associated with this fid) left around.
	 */
	ndr_hdclose(np);
}

/*
 * Process one server-side RPC request.
 */
static int
ndr_pipe_process(ndr_pipe_t *np, ndr_xa_t *mxa)
{
	ndr_stream_t	*recv_nds;
	ndr_stream_t	*send_nds;
	int		rc = ENOMEM;

	mxa->pipe = np;
	mxa->binding_list = np->np_binding;

	if ((mxa->heap = ndr_heap_create()) == NULL)
		goto out1;

	recv_nds = &mxa->recv_nds;
	rc = nds_initialize(recv_nds, 0, NDR_MODE_CALL_RECV, mxa->heap);
	if (rc != 0)
		goto out2;

	send_nds = &mxa->send_nds;
	rc = nds_initialize(send_nds, 0, NDR_MODE_RETURN_SEND, mxa->heap);
	if (rc != 0)
		goto out3;

	rc = ndr_recv_request(mxa);
	if (rc != 0)
		goto out4;

	(void) ndr_svc_process(mxa);
	(void) ndr_send_reply(mxa);
	rc = 0;

out4:
	nds_destruct(&mxa->send_nds);
out3:
	nds_destruct(&mxa->recv_nds);
out2:
	ndr_heap_destroy(mxa->heap);
out1:
	return (rc);
}

/*
 * Check whether or not the specified user has administrator privileges,
 * i.e. is a member of Domain Admins or Administrators.
 * Returns true if the user is an administrator, otherwise returns false.
 */
boolean_t
ndr_is_admin(ndr_xa_t *xa)
{
	smb_netuserinfo_t *ctx = xa->pipe->np_user;

	return (ctx->ui_flags & SMB_ATF_ADMIN);
}

/*
 * Check whether or not the specified user has power-user privileges,
 * i.e. is a member of Domain Admins, Administrators or Power Users.
 * This is typically required for operations such as managing shares.
 * Returns true if the user is a power user, otherwise returns false.
 */
boolean_t
ndr_is_poweruser(ndr_xa_t *xa)
{
	smb_netuserinfo_t *ctx = xa->pipe->np_user;

	return ((ctx->ui_flags & SMB_ATF_ADMIN) ||
	    (ctx->ui_flags & SMB_ATF_POWERUSER));
}

int32_t
ndr_native_os(ndr_xa_t *xa)
{
	smb_netuserinfo_t *ctx = xa->pipe->np_user;

	return (ctx->ui_native_os);
}

/*
 * Receive an entire RPC request (all fragments)
 * Returns zero or an NDR fault code.
 */
static int
ndr_recv_request(ndr_xa_t *mxa)
{
	ndr_common_header_t	*hdr = &mxa->recv_hdr.common_hdr;
	ndr_stream_t		*nds = &mxa->recv_nds;
	unsigned long		saved_size;
	int			rc;

	rc = ndr_recv_frag(mxa);
	if (rc != 0)
		return (rc);
	if (!NDR_IS_FIRST_FRAG(hdr->pfc_flags))
		return (NDR_DRC_FAULT_DECODE_FAILED);

	while (!NDR_IS_LAST_FRAG(hdr->pfc_flags)) {
		rc = ndr_recv_frag(mxa);
		if (rc != 0)
			return (rc);
	}
	nds->pdu_scan_offset = 0;

	/*
	 * This whacks nds->pdu_size, so save/restore.
	 * It leaves scan_offset after the header.
	 */
	saved_size = nds->pdu_size;
	rc = ndr_decode_pdu_hdr(mxa);
	nds->pdu_size = saved_size;

	return (rc);
}

/*
 * Read one fragment, leaving the decoded frag header in
 * recv_hdr.common_hdr, and the data in the recv_nds.
 *
 * Returns zero or an NDR fault code.
 *
 * If a first frag, the header is included in the data
 * placed in recv_nds (because it's not fully decoded
 * until later - we only decode the common part here).
 * Additional frags are placed in the recv_nds without
 * the header, so that after the first frag header,
 * the remaining data will be contiguous.  We do this
 * by simply not advancing the offset in recv_nds after
 * reading and decoding these additional fragments, so
 * the payload of such frags will overwrite what was
 * (temporarily) the frag header.
 */
static int
ndr_recv_frag(ndr_xa_t *mxa)
{
	ndr_common_header_t	*hdr = &mxa->recv_hdr.common_hdr;
	ndr_stream_t		*nds = &mxa->recv_nds;
	unsigned char		*data;
	unsigned long		next_offset;
	unsigned long		pay_size;
	int			rc;

	/* Make room for the frag header. */
	next_offset = nds->pdu_scan_offset + NDR_RSP_HDR_SIZE;
	if (!NDS_GROW_PDU(nds, next_offset, 0))
		return (NDR_DRC_FAULT_OUT_OF_MEMORY);

	/* Read the frag header. */
	data = nds->pdu_base_addr + nds->pdu_scan_offset;
	rc = NDR_PIPE_RECV(mxa->pipe, data, NDR_RSP_HDR_SIZE);
	if (rc != 0)
		return (NDR_DRC_FAULT_RPCHDR_RECEIVED_RUNT);

	/*
	 * Decode the frag header, get the length.
	 * NB: It uses nds->pdu_scan_offset
	 */
	ndr_decode_frag_hdr(nds, hdr);
	ndr_show_hdr(hdr);
	if (hdr->frag_length < NDR_RSP_HDR_SIZE ||
	    hdr->frag_length > mxa->pipe->np_max_xmit_frag)
		return (NDR_DRC_FAULT_DECODE_FAILED);

	if (nds->pdu_scan_offset == 0) {
		/* First frag: header stays in the data. */
		nds->pdu_scan_offset = next_offset;
	} /* else overwrite with the payload */

	/* Make room for the payload. */
	pay_size = hdr->frag_length - NDR_RSP_HDR_SIZE;
	next_offset = nds->pdu_scan_offset + pay_size;
	if (!NDS_GROW_PDU(nds, next_offset, 0))
		return (NDR_DRC_FAULT_OUT_OF_MEMORY);

	/* Read the payload. */
	data = nds->pdu_base_addr + nds->pdu_scan_offset;
	rc = NDR_PIPE_RECV(mxa->pipe, data, pay_size);
	if (rc != 0)
		return (NDR_DRC_FAULT_RPCHDR_RECEIVED_RUNT);
	nds->pdu_scan_offset = next_offset;

	return (NDR_DRC_OK);
}

/*
 * This is the entry point for all server-side RPC processing.
 * It is assumed that the PDU has already been received.
 */
static int
ndr_svc_process(ndr_xa_t *mxa)
{
	int			rc;

	(void) ndr_reply_prepare_hdr(mxa);

	switch (mxa->ptype) {
	case NDR_PTYPE_BIND:
		rc = ndr_svc_bind(mxa);
		break;

	case NDR_PTYPE_REQUEST:
		rc = ndr_svc_request(mxa);
		break;

	case NDR_PTYPE_ALTER_CONTEXT:
		rc = ndr_svc_alter_context(mxa);
		break;

	default:
		rc = NDR_DRC_FAULT_RPCHDR_PTYPE_INVALID;
		break;
	}

	if (NDR_DRC_IS_FAULT(rc))
		ndr_reply_fault(mxa, rc);

	return (rc);
}

/*
 * Multiple p_cont_elem[]s, multiple transfer_syntaxes[] and multiple
 * p_results[] not supported.
 */
static int
ndr_svc_bind(ndr_xa_t *mxa)
{
	ndr_p_cont_list_t	*cont_list;
	ndr_p_result_list_t	*result_list;
	ndr_p_result_t		*result;
	unsigned		p_cont_id;
	ndr_binding_t		*mbind;
	ndr_uuid_t		*as_uuid;
	ndr_uuid_t		*ts_uuid;
	int			as_vers;
	int			ts_vers;
	ndr_service_t		*msvc;
	int			rc;
	ndr_port_any_t		*sec_addr;

	/* acquire targets */
	cont_list = &mxa->recv_hdr.bind_hdr.p_context_elem;
	result_list = &mxa->send_hdr.bind_ack_hdr.p_result_list;
	result = &result_list->p_results[0];

	/*
	 * Set up temporary secondary address port.
	 * We will correct this later (below).
	 */
	sec_addr = &mxa->send_hdr.bind_ack_hdr.sec_addr;
	sec_addr->length = 13;
	(void) strcpy((char *)sec_addr->port_spec, "\\PIPE\\ntsvcs");

	result_list->n_results = 1;
	result_list->reserved = 0;
	result_list->reserved2 = 0;
	result->result = NDR_PCDR_ACCEPTANCE;
	result->reason = 0;
	bzero(&result->transfer_syntax, sizeof (result->transfer_syntax));

	/* sanity check */
	if (cont_list->n_context_elem != 1 ||
	    cont_list->p_cont_elem[0].n_transfer_syn != 1) {
		ndo_trace("ndr_svc_bind: warning: multiple p_cont_elem");
	}

	p_cont_id = cont_list->p_cont_elem[0].p_cont_id;

	if ((mbind = ndr_svc_find_binding(mxa, p_cont_id)) != NULL) {
		/*
		 * Duplicate presentation context id.
		 */
		ndo_trace("ndr_svc_bind: duplicate binding");
		return (NDR_DRC_FAULT_BIND_PCONT_BUSY);
	}

	if ((mbind = ndr_svc_new_binding(mxa)) == NULL) {
		/*
		 * No free binding slot
		 */
		result->result = NDR_PCDR_PROVIDER_REJECTION;
		result->reason = NDR_PPR_LOCAL_LIMIT_EXCEEDED;
		ndo_trace("ndr_svc_bind: no resources");
		return (NDR_DRC_OK);
	}

	as_uuid = &cont_list->p_cont_elem[0].abstract_syntax.if_uuid;
	as_vers = cont_list->p_cont_elem[0].abstract_syntax.if_version;

	ts_uuid = &cont_list->p_cont_elem[0].transfer_syntaxes[0].if_uuid;
	ts_vers = cont_list->p_cont_elem[0].transfer_syntaxes[0].if_version;

	msvc = ndr_svc_lookup_uuid(as_uuid, as_vers, ts_uuid, ts_vers);
	if (msvc == NULL) {
		result->result = NDR_PCDR_PROVIDER_REJECTION;
		result->reason = NDR_PPR_ABSTRACT_SYNTAX_NOT_SUPPORTED;
		return (NDR_DRC_OK);
	}

	/*
	 * We can now use the correct secondary address port.
	 */
	sec_addr = &mxa->send_hdr.bind_ack_hdr.sec_addr;
	sec_addr->length = strlen(msvc->sec_addr_port) + 1;
	(void) strlcpy((char *)sec_addr->port_spec, msvc->sec_addr_port,
	    NDR_PORT_ANY_MAX_PORT_SPEC);

	mbind->p_cont_id = p_cont_id;
	mbind->which_side = NDR_BIND_SIDE_SERVER;
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
		if (NDR_DRC_IS_FAULT(rc)) {
			mbind->service = 0;	/* free binding slot */
			mbind->which_side = 0;
			mbind->p_cont_id = 0;
			mbind->instance_specific = 0;
			return (rc);
		}
	}

	result->transfer_syntax =
	    cont_list->p_cont_elem[0].transfer_syntaxes[0];

	return (NDR_DRC_BINDING_MADE);
}

/*
 * ndr_svc_alter_context
 *
 * The alter context request is used to request additional presentation
 * context for another interface and/or version.  It is very similar to
 * a bind request.
 */
static int
ndr_svc_alter_context(ndr_xa_t *mxa)
{
	ndr_p_result_list_t *result_list;
	ndr_p_result_t *result;
	ndr_p_cont_list_t *cont_list;
	ndr_binding_t *mbind;
	ndr_service_t *msvc;
	unsigned p_cont_id;
	ndr_uuid_t *as_uuid;
	ndr_uuid_t *ts_uuid;
	int as_vers;
	int ts_vers;
	ndr_port_any_t *sec_addr;

	result_list = &mxa->send_hdr.alter_context_rsp_hdr.p_result_list;
	result_list->n_results = 1;
	result_list->reserved = 0;
	result_list->reserved2 = 0;

	result = &result_list->p_results[0];
	result->result = NDR_PCDR_ACCEPTANCE;
	result->reason = 0;
	bzero(&result->transfer_syntax, sizeof (result->transfer_syntax));

	cont_list = &mxa->recv_hdr.alter_context_hdr.p_context_elem;
	p_cont_id = cont_list->p_cont_elem[0].p_cont_id;

	if (ndr_svc_find_binding(mxa, p_cont_id) != NULL)
		return (NDR_DRC_FAULT_BIND_PCONT_BUSY);

	if ((mbind = ndr_svc_new_binding(mxa)) == NULL) {
		result->result = NDR_PCDR_PROVIDER_REJECTION;
		result->reason = NDR_PPR_LOCAL_LIMIT_EXCEEDED;
		return (NDR_DRC_OK);
	}

	as_uuid = &cont_list->p_cont_elem[0].abstract_syntax.if_uuid;
	as_vers = cont_list->p_cont_elem[0].abstract_syntax.if_version;

	ts_uuid = &cont_list->p_cont_elem[0].transfer_syntaxes[0].if_uuid;
	ts_vers = cont_list->p_cont_elem[0].transfer_syntaxes[0].if_version;

	msvc = ndr_svc_lookup_uuid(as_uuid, as_vers, ts_uuid, ts_vers);
	if (msvc == NULL) {
		result->result = NDR_PCDR_PROVIDER_REJECTION;
		result->reason = NDR_PPR_ABSTRACT_SYNTAX_NOT_SUPPORTED;
		return (NDR_DRC_OK);
	}

	mbind->p_cont_id = p_cont_id;
	mbind->which_side = NDR_BIND_SIDE_SERVER;
	/* mbind->context set by app */
	mbind->service = msvc;
	mbind->instance_specific = 0;
	mxa->binding = mbind;

	sec_addr = &mxa->send_hdr.alter_context_rsp_hdr.sec_addr;
	sec_addr->length = 0;
	bzero(sec_addr->port_spec, NDR_PORT_ANY_MAX_PORT_SPEC);

	result->transfer_syntax =
	    cont_list->p_cont_elem[0].transfer_syntaxes[0];

	return (NDR_DRC_BINDING_MADE);
}

static int
ndr_svc_request(ndr_xa_t *mxa)
{
	ndr_binding_t	*mbind;
	ndr_service_t	*msvc;
	unsigned	p_cont_id;
	int		rc;

	mxa->opnum = mxa->recv_hdr.request_hdr.opnum;
	p_cont_id = mxa->recv_hdr.request_hdr.p_cont_id;

	if ((mbind = ndr_svc_find_binding(mxa, p_cont_id)) == NULL)
		return (NDR_DRC_FAULT_REQUEST_PCONT_INVALID);

	mxa->binding = mbind;
	msvc = mbind->service;

	/*
	 * Make room for the response hdr.
	 */
	mxa->send_nds.pdu_scan_offset = NDR_RSP_HDR_SIZE;

	if (msvc->call_stub)
		rc = (*msvc->call_stub)(mxa);
	else
		rc = ndr_generic_call_stub(mxa);

	if (NDR_DRC_IS_FAULT(rc)) {
		ndo_printf(0, 0, "%s[0x%02x]: 0x%04x",
		    msvc->name, mxa->opnum, rc);
	}

	return (rc);
}

/*
 * The transaction and the two nds streams use the same heap, which
 * should already exist at this point.  The heap will also be available
 * to the stub.
 */
int
ndr_generic_call_stub(ndr_xa_t *mxa)
{
	ndr_binding_t 		*mbind = mxa->binding;
	ndr_service_t		*msvc = mbind->service;
	ndr_typeinfo_t		*intf_ti = msvc->interface_ti;
	ndr_stub_table_t	*ste;
	int			opnum = mxa->opnum;
	unsigned		p_len = intf_ti->c_size_fixed_part;
	char 			*param;
	int			rc;

	if (mxa->heap == NULL) {
		ndo_printf(0, 0, "%s[0x%02x]: no heap", msvc->name, opnum);
		return (NDR_DRC_FAULT_OUT_OF_MEMORY);
	}

	if ((ste = ndr_svc_find_stub(msvc, opnum)) == NULL) {
		ndo_printf(0, 0, "%s[0x%02x]: invalid opnum",
		    msvc->name, opnum);
		return (NDR_DRC_FAULT_REQUEST_OPNUM_INVALID);
	}

	if ((param = ndr_heap_malloc(mxa->heap, p_len)) == NULL)
		return (NDR_DRC_FAULT_OUT_OF_MEMORY);

	bzero(param, p_len);

	rc = ndr_decode_call(mxa, param);
	if (!NDR_DRC_IS_OK(rc))
		return (rc);

	rc = (*ste->func)(param, mxa);
	if (rc == NDR_DRC_OK)
		rc = ndr_encode_return(mxa, param);

	return (rc);
}

/*
 * We can perform some initial setup of the response header here.
 * We also need to cache some of the information from the bind
 * negotiation for use during subsequent RPC calls.
 */
static void
ndr_reply_prepare_hdr(ndr_xa_t *mxa)
{
	ndr_common_header_t *rhdr = &mxa->recv_hdr.common_hdr;
	ndr_common_header_t *hdr = &mxa->send_hdr.common_hdr;

	hdr->rpc_vers = 5;
	hdr->rpc_vers_minor = 0;
	hdr->pfc_flags = NDR_PFC_FIRST_FRAG + NDR_PFC_LAST_FRAG;
	hdr->packed_drep = rhdr->packed_drep;
	hdr->frag_length = 0;
	hdr->auth_length = 0;
	hdr->call_id = rhdr->call_id;
#ifdef _BIG_ENDIAN
	hdr->packed_drep.intg_char_rep = NDR_REPLAB_CHAR_ASCII
	    | NDR_REPLAB_INTG_BIG_ENDIAN;
#else
	hdr->packed_drep.intg_char_rep = NDR_REPLAB_CHAR_ASCII
	    | NDR_REPLAB_INTG_LITTLE_ENDIAN;
#endif

	switch (mxa->ptype) {
	case NDR_PTYPE_BIND:
		/*
		 * Compute the maximum fragment sizes for xmit/recv
		 * and store in the pipe endpoint.  Note "xmit" is
		 * client-to-server; "recv" is server-to-client.
		 */
		if (mxa->pipe->np_max_xmit_frag >
		    mxa->recv_hdr.bind_hdr.max_xmit_frag)
			mxa->pipe->np_max_xmit_frag =
			    mxa->recv_hdr.bind_hdr.max_xmit_frag;
		if (mxa->pipe->np_max_recv_frag >
		    mxa->recv_hdr.bind_hdr.max_recv_frag)
			mxa->pipe->np_max_recv_frag =
			    mxa->recv_hdr.bind_hdr.max_recv_frag;

		hdr->ptype = NDR_PTYPE_BIND_ACK;
		mxa->send_hdr.bind_ack_hdr.max_xmit_frag =
		    mxa->pipe->np_max_xmit_frag;
		mxa->send_hdr.bind_ack_hdr.max_recv_frag =
		    mxa->pipe->np_max_recv_frag;

		/*
		 * We're supposed to assign a unique "assoc group"
		 * (identifies this connection for the client).
		 * Using the pipe address is adequate.
		 */
		mxa->send_hdr.bind_ack_hdr.assoc_group_id =
		    mxa->recv_hdr.bind_hdr.assoc_group_id;
		if (mxa->send_hdr.bind_ack_hdr.assoc_group_id == 0)
			mxa->send_hdr.bind_ack_hdr.assoc_group_id =
			    (DWORD)(uintptr_t)mxa->pipe;

		break;

	case NDR_PTYPE_REQUEST:
		hdr->ptype = NDR_PTYPE_RESPONSE;
		/* mxa->send_hdr.response_hdr.alloc_hint */
		mxa->send_hdr.response_hdr.p_cont_id =
		    mxa->recv_hdr.request_hdr.p_cont_id;
		mxa->send_hdr.response_hdr.cancel_count = 0;
		mxa->send_hdr.response_hdr.reserved = 0;
		break;

	case NDR_PTYPE_ALTER_CONTEXT:
		hdr->ptype = NDR_PTYPE_ALTER_CONTEXT_RESP;
		/*
		 * The max_xmit_frag, max_recv_frag and assoc_group_id are
		 * ignored by the client but it's useful to fill them in.
		 */
		mxa->send_hdr.alter_context_rsp_hdr.max_xmit_frag =
		    mxa->recv_hdr.alter_context_hdr.max_xmit_frag;
		mxa->send_hdr.alter_context_rsp_hdr.max_recv_frag =
		    mxa->recv_hdr.alter_context_hdr.max_recv_frag;
		mxa->send_hdr.alter_context_rsp_hdr.assoc_group_id =
		    mxa->recv_hdr.alter_context_hdr.assoc_group_id;
		break;

	default:
		hdr->ptype = 0xFF;
	}
}

/*
 * Signal an RPC fault. The stream is reset and we overwrite whatever
 * was in the response header with the fault information.
 */
static void
ndr_reply_fault(ndr_xa_t *mxa, unsigned long drc)
{
	ndr_common_header_t *rhdr = &mxa->recv_hdr.common_hdr;
	ndr_common_header_t *hdr = &mxa->send_hdr.common_hdr;
	ndr_stream_t *nds = &mxa->send_nds;
	unsigned long fault_status;

	NDS_RESET(nds);

	hdr->rpc_vers = 5;
	hdr->rpc_vers_minor = 0;
	hdr->pfc_flags = NDR_PFC_FIRST_FRAG + NDR_PFC_LAST_FRAG;
	hdr->packed_drep = rhdr->packed_drep;
	hdr->frag_length = sizeof (mxa->send_hdr.fault_hdr);
	hdr->auth_length = 0;
	hdr->call_id = rhdr->call_id;
#ifdef _BIG_ENDIAN
	hdr->packed_drep.intg_char_rep = NDR_REPLAB_CHAR_ASCII
	    | NDR_REPLAB_INTG_BIG_ENDIAN;
#else
	hdr->packed_drep.intg_char_rep = NDR_REPLAB_CHAR_ASCII
	    | NDR_REPLAB_INTG_LITTLE_ENDIAN;
#endif

	switch (drc & NDR_DRC_MASK_SPECIFIER) {
	case NDR_DRC_FAULT_OUT_OF_MEMORY:
	case NDR_DRC_FAULT_ENCODE_TOO_BIG:
		fault_status = NDR_FAULT_NCA_OUT_ARGS_TOO_BIG;
		break;

	case NDR_DRC_FAULT_REQUEST_PCONT_INVALID:
		fault_status = NDR_FAULT_NCA_INVALID_PRES_CONTEXT_ID;
		break;

	case NDR_DRC_FAULT_REQUEST_OPNUM_INVALID:
		fault_status = NDR_FAULT_NCA_OP_RNG_ERROR;
		break;

	case NDR_DRC_FAULT_DECODE_FAILED:
	case NDR_DRC_FAULT_ENCODE_FAILED:
		fault_status = NDR_FAULT_NCA_PROTO_ERROR;
		break;

	default:
		fault_status = NDR_FAULT_NCA_UNSPEC_REJECT;
		break;
	}

	mxa->send_hdr.fault_hdr.common_hdr.ptype = NDR_PTYPE_FAULT;
	mxa->send_hdr.fault_hdr.status = fault_status;
	mxa->send_hdr.response_hdr.alloc_hint = hdr->frag_length;
}

/*
 * Note that the frag_length for bind ack and alter context is
 * non-standard.
 */
static int
ndr_send_reply(ndr_xa_t *mxa)
{
	ndr_common_header_t *hdr = &mxa->send_hdr.common_hdr;
	ndr_stream_t *nds = &mxa->send_nds;
	uint8_t *pdu_buf;
	unsigned long pdu_size;
	unsigned long frag_size;
	unsigned long pdu_data_size;
	unsigned long frag_data_size;

	frag_size = mxa->pipe->np_max_recv_frag;
	pdu_size = nds->pdu_size;
	pdu_buf = nds->pdu_base_addr;

	if (pdu_size <= frag_size) {
		/*
		 * Single fragment response. The PDU size may be zero
		 * here (i.e. bind or fault response). So don't make
		 * any assumptions about it until after the header is
		 * encoded.
		 */
		switch (hdr->ptype) {
		case NDR_PTYPE_BIND_ACK:
			hdr->frag_length = ndr_bind_ack_hdr_size(mxa);
			break;

		case NDR_PTYPE_FAULT:
			/* already setup */
			break;

		case NDR_PTYPE_RESPONSE:
			hdr->frag_length = pdu_size;
			mxa->send_hdr.response_hdr.alloc_hint =
			    hdr->frag_length;
			break;

		case NDR_PTYPE_ALTER_CONTEXT_RESP:
			hdr->frag_length = ndr_alter_context_rsp_hdr_size();
			break;

		default:
			hdr->frag_length = pdu_size;
			break;
		}

		nds->pdu_scan_offset = 0;
		(void) ndr_encode_pdu_hdr(mxa);
		pdu_size = nds->pdu_size;
		(void) NDR_PIPE_SEND(mxa->pipe, pdu_buf, pdu_size);
		return (0);
	}

	/*
	 * Multiple fragment response.
	 *
	 * We need to update the RPC header for every fragment.
	 *
	 * pdu_data_size:	total data remaining to be handled
	 * frag_size:		total fragment size including header
	 * frag_data_size:	data in fragment
	 *			(i.e. frag_size - NDR_RSP_HDR_SIZE)
	 */
	pdu_data_size = pdu_size - NDR_RSP_HDR_SIZE;
	frag_data_size = frag_size - NDR_RSP_HDR_SIZE;

	/*
	 * Send the first frag.
	 */
	hdr->pfc_flags = NDR_PFC_FIRST_FRAG;
	hdr->frag_length = frag_size;
	mxa->send_hdr.response_hdr.alloc_hint = pdu_data_size;
	nds->pdu_scan_offset = 0;
	(void) ndr_encode_pdu_hdr(mxa);
	(void) NDR_PIPE_SEND(mxa->pipe, pdu_buf, frag_size);
	pdu_data_size -= frag_data_size;
	pdu_buf += frag_data_size;

	/*
	 * Send "middle" (full-sized) fragments...
	 */
	hdr->pfc_flags = 0;
	while (pdu_data_size > frag_data_size) {

		hdr->frag_length = frag_size;
		mxa->send_hdr.response_hdr.alloc_hint = pdu_data_size;
		nds->pdu_scan_offset = 0;
		(void) ndr_encode_pdu_hdr(mxa);
		bcopy(nds->pdu_base_addr, pdu_buf, NDR_RSP_HDR_SIZE);
		(void) NDR_PIPE_SEND(mxa->pipe, pdu_buf, frag_size);
		pdu_data_size -= frag_data_size;
		pdu_buf += frag_data_size;
	}

	/*
	 * Last frag (pdu_data_size <= frag_data_size)
	 */
	hdr->pfc_flags = NDR_PFC_LAST_FRAG;
	frag_size = pdu_data_size + NDR_RSP_HDR_SIZE;
	hdr->frag_length = frag_size;
	mxa->send_hdr.response_hdr.alloc_hint = pdu_data_size;
	nds->pdu_scan_offset = 0;
	(void) ndr_encode_pdu_hdr(mxa);
	bcopy(nds->pdu_base_addr, pdu_buf, NDR_RSP_HDR_SIZE);
	(void) NDR_PIPE_SEND(mxa->pipe, pdu_buf, frag_size);

	return (0);
}
