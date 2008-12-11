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

#include <sys/errno.h>
#include <string.h>
#include <strings.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>

#define	NDR_IS_LAST_FRAG(F)	((F) & NDR_PFC_LAST_FRAG)
#define	NDR_DEFAULT_FRAGSZ	8192

static void ndr_clnt_init_hdr(ndr_client_t *, ndr_xa_t *);
static int ndr_clnt_get_frags(ndr_client_t *, ndr_xa_t *);
static void ndr_clnt_remove_hdr(ndr_stream_t *, int *);

int
ndr_clnt_bind(ndr_client_t *clnt, const char *service_name,
    ndr_binding_t **ret_binding_p)
{
	ndr_service_t		*msvc;
	ndr_binding_t		*mbind;
	ndr_xa_t		mxa;
	ndr_bind_hdr_t		*bhdr;
	ndr_p_cont_elem_t 	*pce;
	ndr_bind_ack_hdr_t	*bahdr;
	ndr_p_result_t		*pre;
	int			rc;

	bzero(&mxa, sizeof (mxa));

	msvc = ndr_svc_lookup_name(service_name);
	if (msvc == NULL)
		return (NDR_DRC_FAULT_API_SERVICE_INVALID);

	mxa.binding_list = clnt->binding_list;
	if ((mbind = ndr_svc_new_binding(&mxa)) == NULL)
		return (NDR_DRC_FAULT_API_BIND_NO_SLOTS);

	ndr_clnt_init_hdr(clnt, &mxa);

	bhdr = &mxa.send_hdr.bind_hdr;
	bhdr->common_hdr.ptype = NDR_PTYPE_BIND;
	bhdr->common_hdr.frag_length = sizeof (*bhdr);
	bhdr->max_xmit_frag = NDR_DEFAULT_FRAGSZ;
	bhdr->max_recv_frag = NDR_DEFAULT_FRAGSZ;
	bhdr->assoc_group_id = 0;
	bhdr->p_context_elem.n_context_elem = 1;

	/* Assign presentation context id */
	pce = &bhdr->p_context_elem.p_cont_elem[0];
	pce->p_cont_id = clnt->next_p_cont_id++;
	pce->n_transfer_syn = 1;

	/* Set up UUIDs and versions from the service */
	pce->abstract_syntax.if_version = msvc->abstract_syntax_version;
	rc = ndr_uuid_parse(msvc->abstract_syntax_uuid,
	    &pce->abstract_syntax.if_uuid);
	if (rc != 0)
		return (NDR_DRC_FAULT_API_SERVICE_INVALID);

	pce->transfer_syntaxes[0].if_version = msvc->transfer_syntax_version;
	rc = ndr_uuid_parse(msvc->transfer_syntax_uuid,
	    &pce->transfer_syntaxes[0].if_uuid);
	if (rc != 0)
		return (NDR_DRC_FAULT_API_SERVICE_INVALID);

	/* Format and exchange the PDU */

	if ((*clnt->xa_init)(clnt, &mxa) < 0)
		return (NDR_DRC_FAULT_OUT_OF_MEMORY);

	rc = ndr_encode_pdu_hdr(&mxa);
	if (NDR_DRC_IS_FAULT(rc))
		goto fault_exit;

	if ((*clnt->xa_exchange)(clnt, &mxa) < 0) {
		rc = NDR_DRC_FAULT_SEND_FAILED;
		goto fault_exit;
	}

	rc = ndr_decode_pdu_hdr(&mxa);
	if (NDR_DRC_IS_FAULT(rc))
		goto fault_exit;

	/* done with buffers */
	(*clnt->xa_destruct)(clnt, &mxa);

	bahdr = &mxa.recv_hdr.bind_ack_hdr;

	if (mxa.ptype != NDR_PTYPE_BIND_ACK)
		return (NDR_DRC_FAULT_RECEIVED_MALFORMED);

	if (bahdr->p_result_list.n_results != 1)
		return (NDR_DRC_FAULT_RECEIVED_MALFORMED);

	pre = &bahdr->p_result_list.p_results[0];

	if (pre->result != NDR_PCDR_ACCEPTANCE)
		return (NDR_DRC_FAULT_RECEIVED_MALFORMED);

	mbind->p_cont_id = pce->p_cont_id;
	mbind->which_side = NDR_BIND_SIDE_CLIENT;
	mbind->clnt = clnt;
	mbind->service = msvc;
	mbind->instance_specific = 0;

	*ret_binding_p = mbind;
	return (NDR_DRC_OK);

fault_exit:
	(*clnt->xa_destruct)(clnt, &mxa);
	return (rc);
}

int
ndr_clnt_call(ndr_binding_t *mbind, int opnum, void *params)
{
	ndr_client_t		*clnt = mbind->clnt;
	ndr_service_t		*msvc = mbind->service;
	ndr_xa_t		mxa;
	ndr_request_hdr_t	*reqhdr;
	ndr_common_header_t	*rsphdr;
	unsigned long		recv_pdu_scan_offset;
	int			rc;

	if (ndr_svc_find_stub(msvc, opnum) == NULL)
		return (NDR_DRC_FAULT_API_OPNUM_INVALID);

	bzero(&mxa, sizeof (mxa));
	mxa.ptype = NDR_PTYPE_REQUEST;
	mxa.opnum = opnum;
	mxa.binding = mbind;

	ndr_clnt_init_hdr(clnt, &mxa);

	reqhdr = &mxa.send_hdr.request_hdr;
	reqhdr->common_hdr.ptype = NDR_PTYPE_REQUEST;
	reqhdr->p_cont_id = mbind->p_cont_id;
	reqhdr->opnum = opnum;

	rc = (*clnt->xa_init)(clnt, &mxa);
	if (NDR_DRC_IS_FAULT(rc))
		return (rc);

	/* Reserve room for hdr */
	mxa.send_nds.pdu_scan_offset = sizeof (*reqhdr);

	rc = ndr_encode_call(&mxa, params);
	if (!NDR_DRC_IS_OK(rc))
		goto fault_exit;

	mxa.send_nds.pdu_scan_offset = 0;

	/*
	 * Now we have the PDU size, we need to set up the
	 * frag_length and calculate the alloc_hint.
	 */
	mxa.send_hdr.common_hdr.frag_length = mxa.send_nds.pdu_size;
	reqhdr->alloc_hint = mxa.send_nds.pdu_size -
	    sizeof (ndr_request_hdr_t);

	rc = ndr_encode_pdu_hdr(&mxa);
	if (NDR_DRC_IS_FAULT(rc))
		goto fault_exit;

	rc = (*clnt->xa_exchange)(clnt, &mxa);
	if (NDR_DRC_IS_FAULT(rc))
		goto fault_exit;

	rc = ndr_decode_pdu_hdr(&mxa);
	if (NDR_DRC_IS_FAULT(rc))
		goto fault_exit;

	if (mxa.ptype != NDR_PTYPE_RESPONSE) {
		rc = NDR_DRC_FAULT_RECEIVED_MALFORMED;
		goto fault_exit;
	}

	rsphdr = &mxa.recv_hdr.common_hdr;

	if (!NDR_IS_LAST_FRAG(rsphdr->pfc_flags)) {
		/*
		 * This is a multi-fragment response.
		 * Preserve the current scan offset while getting
		 * fragments so that we can continue afterward
		 * as if we had received the entire response as
		 * a single PDU.
		 */
		recv_pdu_scan_offset = mxa.recv_nds.pdu_scan_offset;

		if (ndr_clnt_get_frags(clnt, &mxa) < 0) {
			rc = NDR_DRC_FAULT_RECEIVED_MALFORMED;
			goto fault_exit;
		}

		mxa.recv_nds.pdu_scan_offset = recv_pdu_scan_offset;
	}

	rc = ndr_decode_return(&mxa, params);
	if (NDR_DRC_IS_FAULT(rc))
		goto fault_exit;

	(*clnt->xa_preserve)(clnt, &mxa);
	(*clnt->xa_destruct)(clnt, &mxa);
	return (NDR_DRC_OK);

fault_exit:
	(*clnt->xa_destruct)(clnt, &mxa);
	return (rc);
}

void
ndr_clnt_free_heap(ndr_client_t *clnt)
{
	(*clnt->xa_release)(clnt);
}

static void
ndr_clnt_init_hdr(ndr_client_t *clnt, ndr_xa_t *mxa)
{
	ndr_common_header_t *hdr = &mxa->send_hdr.common_hdr;

	hdr->rpc_vers = 5;
	hdr->rpc_vers_minor = 0;
	hdr->pfc_flags = NDR_PFC_FIRST_FRAG + NDR_PFC_LAST_FRAG;
	hdr->packed_drep.intg_char_rep = NDR_REPLAB_CHAR_ASCII;
#ifndef _BIG_ENDIAN
	hdr->packed_drep.intg_char_rep |= NDR_REPLAB_INTG_LITTLE_ENDIAN;
#endif
	/* hdr->frag_length */
	hdr->auth_length = 0;
	hdr->call_id = clnt->next_call_id++;
}

/*
 * ndr_clnt_remove_hdr
 *
 * Remove an RPC fragment header from the received data stream.
 *
 * Original RPC receive buffer:
 * |-      frag1                   -|    |-frag M(partial)-|
 * +==================+=============+----+=================+
 * | SmbTransact Rsp1 | SmbTransact |    | SmbReadX RspN   |
 * | (with RPC hdr)   | Rsp2        | .. | (with RPC hdr)  |
 * +-----+------------+-------------+    +-----+-----------+
 * | hdr | data       | data        | .. | hdr | data      |
 * +=====+============+=============+----+=====+===========+
 *                                       <------
 * ^                                     ^     ^
 * |                                     |     |
 * base_offset                          hdr   data
 *
 * |-------------------------------------|-----------------|
 *              offset                           len
 *
 * RPC receive buffer (after this call):
 * +==================+=============+----+===========+
 * | SmbTransact Rsp1 | SmbTransact |    | SmbReadX  |
 * | (with RPC hdr)   | Rsp2        | .. | RspN      |
 * +-----+------------+-------------+    +-----------+
 * | hdr | data       | data        | .. | data      |
 * +=====+============+=============+----+===========+
 */
static void
ndr_clnt_remove_hdr(ndr_stream_t *nds, int *nbytes)
{
	char *hdr;
	char *data;

	hdr = (char *)nds->pdu_base_offset + nds->pdu_scan_offset;
	data = hdr + NDR_RSP_HDR_SIZE;
	*nbytes -= NDR_RSP_HDR_SIZE;

	bcopy(data, hdr, *nbytes);
	nds->pdu_size -= NDR_RSP_HDR_SIZE;
}

/*
 * ndr_clnt_get_frags
 *
 * A DCE RPC message that is larger than a single fragment is transmitted
 * as a series of fragments: 5280 bytes for Windows NT and 4280 bytes for
 * both Windows 2000 and 2003.
 *
 * Collect RPC fragments and append them to the receive stream buffer.
 * Each received fragment has a header, which we need to remove as we
 * build the full RPC PDU.
 *
 * The xa_read() calls will translate to SmbReadX requests.  Note that
 * there is no correspondence between SmbReadX buffering and DCE RPC
 * fragment alignment.
 *
 * Return -1 on error. Otherwise, return the total data count of the
 * complete RPC response upon success.
 */
static int
ndr_clnt_get_frags(ndr_client_t *clnt, ndr_xa_t *mxa)
{
	ndr_stream_t *nds = &mxa->recv_nds;
	ndr_common_header_t hdr;
	int frag_rcvd;
	int frag_size;
	int last_frag;
	int nbytes;

	/*
	 * The scan offest will be used to locate the frag header.
	 */
	nds->pdu_scan_offset = nds->pdu_base_offset + nds->pdu_size;

	do {
		frag_rcvd = 0;

		do {
			if ((nbytes = (*clnt->xa_read)(clnt, mxa)) < 0)
				return (-1);

			if (frag_rcvd == 0) {
				ndr_decode_frag_hdr(nds, &hdr);

				last_frag = NDR_IS_LAST_FRAG(hdr.pfc_flags);
				frag_size = hdr.frag_length - NDR_RSP_HDR_SIZE;

				ndr_clnt_remove_hdr(nds, &nbytes);
				nds->pdu_scan_offset += frag_size;
			}

			frag_rcvd += nbytes;

		} while (frag_rcvd < frag_size);
	} while (!last_frag);

	return (0);
}
