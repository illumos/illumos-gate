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
 * Server side RPC handler.
 */

#include <sys/byteorder.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <thread.h>
#include <synch.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <time.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/ntaccess.h>

/*
 * Fragment size (5680: NT style).
 */
#define	NDR_FRAG_SZ		5680

#define	NDR_PIPE_BUFSZ		65536
#define	NDR_PIPE_MAX		128
static ndr_pipe_t ndr_pipe_table[NDR_PIPE_MAX];
static mutex_t ndr_pipe_lock;

static int ndr_pipe_transact(ndr_pipe_t *);
static ndr_pipe_t *ndr_pipe_lookup(int);
static void ndr_pipe_release(ndr_pipe_t *);
static ndr_pipe_t *ndr_pipe_allocate(int);
static void ndr_pipe_deallocate(ndr_pipe_t *);
static void ndr_pipe_rewind(ndr_pipe_t *);
static void ndr_pipe_flush(ndr_pipe_t *);

static int ndr_svc_process(ndr_xa_t *);
static int ndr_svc_bind(ndr_xa_t *);
static int ndr_svc_request(ndr_xa_t *);
static void ndr_reply_prepare_hdr(ndr_xa_t *);
static int ndr_svc_alter_context(ndr_xa_t *);
static void ndr_reply_fault(ndr_xa_t *, unsigned long);
static int ndr_build_reply(ndr_xa_t *);
static void ndr_build_frag(ndr_stream_t *, uint8_t *, uint32_t);

/*
 * Allocate and associate a service context with a fid.
 */
int
ndr_pipe_open(int fid, uint8_t *data, uint32_t datalen)
{
	ndr_pipe_t *np;

	(void) mutex_lock(&ndr_pipe_lock);

	if ((np = ndr_pipe_lookup(fid)) != NULL) {
		ndr_pipe_release(np);
		(void) mutex_unlock(&ndr_pipe_lock);
		return (EEXIST);
	}

	if ((np = ndr_pipe_allocate(fid)) == NULL) {
		(void) mutex_unlock(&ndr_pipe_lock);
		return (ENOMEM);
	}

	if (smb_opipe_context_decode(&np->np_ctx, data, datalen) == -1) {
		ndr_pipe_release(np);
		(void) mutex_unlock(&ndr_pipe_lock);
		return (EINVAL);
	}

	ndr_svc_binding_pool_init(&np->np_binding, np->np_binding_pool,
	    NDR_N_BINDING_POOL);

	(void) mutex_unlock(&ndr_pipe_lock);
	return (0);
}

/*
 * Release the context associated with a fid when an opipe is closed.
 */
int
ndr_pipe_close(int fid)
{
	ndr_pipe_t *np;

	(void) mutex_lock(&ndr_pipe_lock);

	if ((np = ndr_pipe_lookup(fid)) == NULL) {
		(void) mutex_unlock(&ndr_pipe_lock);
		return (ENOENT);
	}

	/*
	 * Release twice: once for the lookup above
	 * and again to close the fid.
	 */
	ndr_pipe_release(np);
	ndr_pipe_release(np);
	(void) mutex_unlock(&ndr_pipe_lock);
	return (0);
}

/*
 * Write RPC request data to the input stream.  Input data is buffered
 * until the response is requested.
 */
int
ndr_pipe_write(int fid, uint8_t *buf, uint32_t len)
{
	ndr_pipe_t *np;
	ssize_t nbytes;

	if (len == 0)
		return (0);

	(void) mutex_lock(&ndr_pipe_lock);

	if ((np = ndr_pipe_lookup(fid)) == NULL) {
		(void) mutex_unlock(&ndr_pipe_lock);
		return (ENOENT);
	}

	nbytes = ndr_uiomove((caddr_t)buf, len, UIO_READ, &np->np_uio);

	ndr_pipe_release(np);
	(void) mutex_unlock(&ndr_pipe_lock);
	return ((nbytes == len) ? 0 : EIO);
}

/*
 * Read RPC response data.  If the input stream contains an RPC request,
 * we need to process the RPC transaction, which will place the RPC
 * response in the output (frags) stream.  Otherwise, read data from
 * the output stream.
 */
int
ndr_pipe_read(int fid, uint8_t *buf, uint32_t *len, uint32_t *resid)
{
	ndr_pipe_t *np;
	ssize_t nbytes = *len;
	int rc;

	if (nbytes == 0) {
		*resid = 0;
		return (0);
	}

	(void) mutex_lock(&ndr_pipe_lock);
	if ((np = ndr_pipe_lookup(fid)) == NULL) {
		(void) mutex_unlock(&ndr_pipe_lock);
		return (ENOENT);
	}
	(void) mutex_unlock(&ndr_pipe_lock);

	if (np->np_uio.uio_offset) {
		if ((rc = ndr_pipe_transact(np)) != 0) {
			ndr_pipe_flush(np);
			(void) mutex_lock(&ndr_pipe_lock);
			ndr_pipe_release(np);
			(void) mutex_unlock(&ndr_pipe_lock);
			return (rc);
		}

	}

	*len = ndr_uiomove((caddr_t)buf, nbytes, UIO_WRITE, &np->np_frags.uio);
	*resid = np->np_frags.uio.uio_resid;

	if (*resid == 0) {
		/*
		 * Nothing left, cleanup the output stream.
		 */
		ndr_pipe_flush(np);
	}

	(void) mutex_lock(&ndr_pipe_lock);
	ndr_pipe_release(np);
	(void) mutex_unlock(&ndr_pipe_lock);
	return (0);
}

/*
 * Process a server-side RPC request.
 */
static int
ndr_pipe_transact(ndr_pipe_t *np)
{
	ndr_xa_t	*mxa;
	ndr_stream_t	*recv_nds;
	ndr_stream_t	*send_nds;
	char		*data;
	int		datalen;

	data = np->np_buf;
	datalen = np->np_uio.uio_offset;

	if ((mxa = (ndr_xa_t *)malloc(sizeof (ndr_xa_t))) == NULL)
		return (ENOMEM);

	bzero(mxa, sizeof (ndr_xa_t));
	mxa->fid = np->np_fid;
	mxa->pipe = np;
	mxa->binding_list = np->np_binding;

	if ((mxa->heap = ndr_heap_create()) == NULL) {
		free(mxa);
		return (ENOMEM);
	}

	recv_nds = &mxa->recv_nds;
	nds_initialize(recv_nds, datalen, NDR_MODE_CALL_RECV, mxa->heap);

	/*
	 * Copy the input data and reset the input stream.
	 */
	bcopy(data, recv_nds->pdu_base_addr, datalen);
	ndr_pipe_rewind(np);

	send_nds = &mxa->send_nds;
	nds_initialize(send_nds, 0, NDR_MODE_RETURN_SEND, mxa->heap);

	(void) ndr_svc_process(mxa);

	nds_finalize(send_nds, &np->np_frags);
	nds_destruct(&mxa->recv_nds);
	nds_destruct(&mxa->send_nds);
	ndr_heap_destroy(mxa->heap);
	free(mxa);
	return (0);
}

/*
 * Return information about the specified pipe.
 */
int
ndr_pipe_getinfo(int ndx, ndr_pipe_info_t *npi)
{
	ndr_pipe_t *np;

	if ((ndx < 0) || (ndx >= NDR_PIPE_MAX) || (npi == NULL))
		return (-1);

	(void) mutex_lock(&ndr_pipe_lock);
	np = &ndr_pipe_table[ndx];

	if (np->np_fid == 0) {
		(void) mutex_unlock(&ndr_pipe_lock);
		return (-1);
	}

	npi->npi_fid = np->np_fid;
	npi->npi_permissions = FILE_READ_DATA | FILE_WRITE_DATA | FILE_EXECUTE;
	npi->npi_num_locks = 0;
	(void) snprintf(npi->npi_username, MAXNAMELEN, "%s\\%s",
	    np->np_ctx.oc_domain, np->np_ctx.oc_account);
	(void) snprintf(npi->npi_pathname, MAXPATHLEN, "%s",
	    np->np_binding->service->sec_addr_port);

	(void) mutex_unlock(&ndr_pipe_lock);
	return (0);
}

/*
 * Must be called with ndr_pipe_lock held.
 */
static ndr_pipe_t *
ndr_pipe_lookup(int fid)
{
	ndr_pipe_t *np;
	int i;

	for (i = 0; i < NDR_PIPE_MAX; ++i) {
		np = &ndr_pipe_table[i];

		if (np->np_fid == fid) {
			if (np->np_refcnt == 0)
				return (NULL);

			np->np_refcnt++;
			return (np);
		}
	}

	return (NULL);
}

/*
 * Must be called with ndr_pipe_lock held.
 */
static void
ndr_pipe_release(ndr_pipe_t *np)
{
	np->np_refcnt--;
	ndr_pipe_deallocate(np);
}

/*
 * Must be called with ndr_pipe_lock held.
 */
static ndr_pipe_t *
ndr_pipe_allocate(int fid)
{
	ndr_pipe_t *np = NULL;
	int i;

	for (i = 0; i < NDR_PIPE_MAX; ++i) {
		np = &ndr_pipe_table[i];

		if (np->np_fid == 0) {
			bzero(np, sizeof (ndr_pipe_t));

			if ((np->np_buf = malloc(NDR_PIPE_BUFSZ)) == NULL)
				return (NULL);

			ndr_pipe_rewind(np);
			np->np_fid = fid;
			np->np_refcnt = 1;
			return (np);
		}
	}

	return (NULL);
}

/*
 * Must be called with ndr_pipe_lock held.
 */
static void
ndr_pipe_deallocate(ndr_pipe_t *np)
{
	if (np->np_refcnt == 0) {
		/*
		 * Ensure that there are no RPC service policy handles
		 * (associated with this fid) left around.
		 */
		ndr_hdclose(np->np_fid);

		ndr_pipe_rewind(np);
		ndr_pipe_flush(np);
		free(np->np_buf);
		free(np->np_ctx.oc_domain);
		free(np->np_ctx.oc_account);
		free(np->np_ctx.oc_workstation);
		bzero(np, sizeof (ndr_pipe_t));
	}
}

/*
 * Rewind the input data stream, ready for the next write.
 */
static void
ndr_pipe_rewind(ndr_pipe_t *np)
{
	np->np_uio.uio_iov = &np->np_iov;
	np->np_uio.uio_iovcnt = 1;
	np->np_uio.uio_offset = 0;
	np->np_uio.uio_segflg = UIO_USERSPACE;
	np->np_uio.uio_resid = NDR_PIPE_BUFSZ;
	np->np_iov.iov_base = np->np_buf;
	np->np_iov.iov_len = NDR_PIPE_BUFSZ;
}

/*
 * Flush the output data stream.
 */
static void
ndr_pipe_flush(ndr_pipe_t *np)
{
	ndr_frag_t *frag;

	while ((frag = np->np_frags.head) != NULL) {
		np->np_frags.head = frag->next;
		free(frag);
	}

	free(np->np_frags.iov);
	bzero(&np->np_frags, sizeof (ndr_fraglist_t));
}

/*
 * Check whether or not the specified user has administrator privileges,
 * i.e. is a member of Domain Admins or Administrators.
 * Returns true if the user is an administrator, otherwise returns false.
 */
boolean_t
ndr_is_admin(ndr_xa_t *xa)
{
	smb_opipe_context_t *ctx = &xa->pipe->np_ctx;

	return (ctx->oc_flags & SMB_ATF_ADMIN);
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
	smb_opipe_context_t *ctx = &xa->pipe->np_ctx;

	return ((ctx->oc_flags & SMB_ATF_ADMIN) ||
	    (ctx->oc_flags & SMB_ATF_POWERUSER));
}

int32_t
ndr_native_os(ndr_xa_t *xa)
{
	smb_opipe_context_t *ctx = &xa->pipe->np_ctx;

	return (ctx->oc_native_os);
}

/*
 * This is the entry point for all server-side RPC processing.
 * It is assumed that the PDU has already been received.
 */
static int
ndr_svc_process(ndr_xa_t *mxa)
{
	int rc;

	rc = ndr_decode_pdu_hdr(mxa);
	if (!NDR_DRC_IS_OK(rc))
		return (-1);

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

	(void) ndr_build_reply(mxa);
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
		hdr->ptype = NDR_PTYPE_BIND_ACK;
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
		mxa->pipe->np_max_xmit_frag =
		    mxa->recv_hdr.bind_hdr.max_xmit_frag;
		mxa->pipe->np_max_recv_frag =
		    mxa->recv_hdr.bind_hdr.max_recv_frag;
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
ndr_build_reply(ndr_xa_t *mxa)
{
	ndr_common_header_t *hdr = &mxa->send_hdr.common_hdr;
	ndr_stream_t *nds = &mxa->send_nds;
	uint8_t *pdu_buf;
	unsigned long pdu_size;
	unsigned long frag_size;
	unsigned long pdu_data_size;
	unsigned long frag_data_size;

	frag_size = NDR_FRAG_SZ;
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
		ndr_build_frag(nds, pdu_buf,  pdu_size);
		return (0);
	}

	/*
	 * Multiple fragment response.
	 */
	hdr->pfc_flags = NDR_PFC_FIRST_FRAG;
	hdr->frag_length = frag_size;
	mxa->send_hdr.response_hdr.alloc_hint = pdu_size - NDR_RSP_HDR_SIZE;
	nds->pdu_scan_offset = 0;
	(void) ndr_encode_pdu_hdr(mxa);
	ndr_build_frag(nds, pdu_buf,  frag_size);

	/*
	 * We need to update the 24-byte header in subsequent fragments.
	 *
	 * pdu_data_size:	total data remaining to be handled
	 * frag_size:		total fragment size including header
	 * frag_data_size:	data in fragment
	 *			(i.e. frag_size - NDR_RSP_HDR_SIZE)
	 */
	pdu_data_size = pdu_size - NDR_RSP_HDR_SIZE;
	frag_data_size = frag_size - NDR_RSP_HDR_SIZE;

	while (pdu_data_size) {
		mxa->send_hdr.response_hdr.alloc_hint -= frag_data_size;
		pdu_data_size -= frag_data_size;
		pdu_buf += frag_data_size;

		if (pdu_data_size <= frag_data_size) {
			frag_data_size = pdu_data_size;
			frag_size = frag_data_size + NDR_RSP_HDR_SIZE;
			hdr->pfc_flags = NDR_PFC_LAST_FRAG;
		} else {
			hdr->pfc_flags = 0;
		}

		hdr->frag_length = frag_size;
		nds->pdu_scan_offset = 0;
		(void) ndr_encode_pdu_hdr(mxa);
		bcopy(nds->pdu_base_addr, pdu_buf, NDR_RSP_HDR_SIZE);

		ndr_build_frag(nds, pdu_buf, frag_size);

		if (hdr->pfc_flags & NDR_PFC_LAST_FRAG)
			break;
	}

	return (0);
}

/*
 * ndr_build_frag
 *
 * Build an RPC PDU fragment from the specified buffer.
 * If malloc fails, the client will see a header/pdu inconsistency
 * and report an error.
 */
static void
ndr_build_frag(ndr_stream_t *nds, uint8_t *buf, uint32_t len)
{
	ndr_frag_t *frag;
	int size = sizeof (ndr_frag_t) + len;

	if ((frag = (ndr_frag_t *)malloc(size)) == NULL)
		return;

	frag->next = NULL;
	frag->buf = (uint8_t *)frag + sizeof (ndr_frag_t);
	frag->len = len;
	bcopy(buf, frag->buf, len);

	if (nds->frags.head == NULL) {
		nds->frags.head = frag;
		nds->frags.tail = frag;
		nds->frags.nfrag = 1;
	} else {
		nds->frags.tail->next = frag;
		nds->frags.tail = frag;
		++nds->frags.nfrag;
	}
}
