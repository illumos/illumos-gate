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

#include <strings.h>
#include <sys/param.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>

#ifdef _BIG_ENDIAN
static const int ndr_native_byte_order = NDR_REPLAB_INTG_BIG_ENDIAN;
#else
static const int ndr_native_byte_order = NDR_REPLAB_INTG_LITTLE_ENDIAN;
#endif

int
ndr_encode_decode_common(ndr_xa_t *mxa, int mode, unsigned opnum,
    ndr_typeinfo_t *ti, void *datum)
{
	ndr_stream_t	*nds;
	int		m_op = NDR_MODE_TO_M_OP(mode);
	int		rc;

	if (m_op == NDR_M_OP_MARSHALL)
		nds = &mxa->send_nds;
	else
		nds = &mxa->recv_nds;

	/*
	 * Make sure that nds is in the correct mode
	 */
	if (!NDR_MODE_MATCH(nds, mode))
		return (NDR_DRC_FAULT_MODE_MISMATCH);

	/*
	 * Perform the (un)marshalling
	 */
	if (ndo_operation(nds, ti, opnum, datum))
		return (NDR_DRC_OK);

	switch (nds->error) {
	case NDR_ERR_MALLOC_FAILED:
		rc = NDR_DRC_FAULT_OUT_OF_MEMORY;
		break;

	case NDR_ERR_SWITCH_VALUE_INVALID:
		rc = NDR_DRC_FAULT_PARAM_0_INVALID;
		break;

	case NDR_ERR_UNDERFLOW:
		rc = NDR_DRC_FAULT_RECEIVED_RUNT;
		break;

	case NDR_ERR_GROW_FAILED:
		rc = NDR_DRC_FAULT_ENCODE_TOO_BIG;
		break;

	default:
		if (m_op == NDR_M_OP_MARSHALL)
			rc = NDR_DRC_FAULT_ENCODE_FAILED;
		else
			rc = NDR_DRC_FAULT_DECODE_FAILED;
		break;
	}

	return (rc);
}

int
ndr_decode_call(ndr_xa_t *mxa, void *params)
{
	int rc;

	rc = ndr_encode_decode_common(mxa, NDR_MODE_CALL_RECV,
	    mxa->opnum, mxa->binding->service->interface_ti, params);

	return (rc + NDR_PTYPE_REQUEST);
}

int
ndr_encode_return(ndr_xa_t *mxa, void *params)
{
	int rc;

	rc = ndr_encode_decode_common(mxa, NDR_MODE_RETURN_SEND,
	    mxa->opnum, mxa->binding->service->interface_ti, params);

	return (rc + NDR_PTYPE_RESPONSE);
}

int
ndr_encode_call(ndr_xa_t *mxa, void *params)
{
	int rc;

	rc = ndr_encode_decode_common(mxa, NDR_MODE_CALL_SEND,
	    mxa->opnum, mxa->binding->service->interface_ti, params);

	return (rc + NDR_PTYPE_REQUEST);
}

int
ndr_decode_return(ndr_xa_t *mxa, void *params)
{
	int rc;

	rc = ndr_encode_decode_common(mxa, NDR_MODE_RETURN_RECV,
	    mxa->opnum, mxa->binding->service->interface_ti, params);

	return (rc + NDR_PTYPE_RESPONSE);
}

int
ndr_decode_pdu_hdr(ndr_xa_t *mxa)
{
	ndr_common_header_t	*hdr = &mxa->recv_hdr.common_hdr;
	ndr_stream_t		*nds = &mxa->recv_nds;
	int			ptype;
	int			rc;
	int			charset;
	int			byte_order;

	if (nds->m_op != NDR_M_OP_UNMARSHALL)
		return (NDR_DRC_PTYPE_RPCHDR(NDR_DRC_FAULT_MODE_MISMATCH));

	/*
	 * All PDU headers are at least this big
	 */
	rc = NDS_GROW_PDU(nds, sizeof (ndr_common_header_t), 0);
	if (!rc)
		return (NDR_DRC_PTYPE_RPCHDR(NDR_DRC_FAULT_RECEIVED_RUNT));

	/*
	 * Peek at the first eight bytes to figure out what we're doing.
	 */
	rc = NDS_GET_PDU(nds, 0, 8, (char *)hdr, 0, 0);
	if (!rc)
		return (NDR_DRC_PTYPE_RPCHDR(NDR_DRC_FAULT_DECODE_FAILED));

	/*
	 * Verify the protocol version.
	 */
	if ((hdr->rpc_vers != 5) || (hdr->rpc_vers_minor != 0))
		return (NDR_DRC_PTYPE_RPCHDR(NDR_DRC_FAULT_DECODE_FAILED));

	/*
	 * Check for ASCII as the character set.  This is an ASCII
	 * versus EBCDIC option and has nothing to do with Unicode.
	 */
	charset = hdr->packed_drep.intg_char_rep & NDR_REPLAB_CHAR_MASK;
	if (charset != NDR_REPLAB_CHAR_ASCII)
		return (NDR_DRC_PTYPE_RPCHDR(NDR_DRC_FAULT_DECODE_FAILED));

	/*
	 * Set the byte swap flag if the PDU byte-order
	 * is different from the local byte-order.
	 */
	byte_order = hdr->packed_drep.intg_char_rep & NDR_REPLAB_INTG_MASK;
	nds->swap = (byte_order != ndr_native_byte_order) ? 1 : 0;

	ptype = hdr->ptype;
	if (ptype == NDR_PTYPE_REQUEST &&
	    (hdr->pfc_flags & NDR_PFC_OBJECT_UUID) != 0) {
		ptype = NDR_PTYPE_REQUEST_WITH;	/* fake for sizing */
	}

	mxa->ptype = hdr->ptype;

	rc = ndr_encode_decode_common(mxa,
	    NDR_M_OP_AND_DIR_TO_MODE(nds->m_op, nds->dir),
	    ptype, &TYPEINFO(ndr_hdr), hdr);

	return (NDR_DRC_PTYPE_RPCHDR(rc));
}

/*
 * Decode an RPC fragment header.  Use ndr_decode_pdu_hdr() to process
 * the first fragment header then this function to process additional
 * fragment headers.
 */
void
ndr_decode_frag_hdr(ndr_stream_t *nds, ndr_common_header_t *hdr)
{
	ndr_common_header_t *tmp;
	uint8_t *pdu;
	int byte_order;

	pdu = (uint8_t *)nds->pdu_base_offset + nds->pdu_scan_offset;
	bcopy(pdu, hdr, NDR_RSP_HDR_SIZE);

	/*
	 * Swap non-byte fields if the PDU byte-order
	 * is different from the local byte-order.
	 */
	byte_order = hdr->packed_drep.intg_char_rep & NDR_REPLAB_INTG_MASK;

	if (byte_order != ndr_native_byte_order) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		tmp = (ndr_common_header_t *)pdu;

		nds_bswap(&tmp->frag_length, &hdr->frag_length,
		    sizeof (WORD));
		nds_bswap(&tmp->auth_length, &hdr->auth_length,
		    sizeof (WORD));
		nds_bswap(&tmp->call_id, &hdr->call_id, sizeof (DWORD));
	}
}

int
ndr_encode_pdu_hdr(ndr_xa_t *mxa)
{
	ndr_common_header_t	*hdr = &mxa->send_hdr.common_hdr;
	ndr_stream_t		*nds = &mxa->send_nds;
	int			ptype;
	int			rc;

	if (nds->m_op != NDR_M_OP_MARSHALL)
		return (NDR_DRC_PTYPE_RPCHDR(NDR_DRC_FAULT_MODE_MISMATCH));

	ptype = hdr->ptype;
	if (ptype == NDR_PTYPE_REQUEST &&
	    (hdr->pfc_flags & NDR_PFC_OBJECT_UUID) != 0) {
		ptype = NDR_PTYPE_REQUEST_WITH;	/* fake for sizing */
	}

	rc = ndr_encode_decode_common(mxa,
	    NDR_M_OP_AND_DIR_TO_MODE(nds->m_op, nds->dir),
	    ptype, &TYPEINFO(ndr_hdr), hdr);

	return (NDR_DRC_PTYPE_RPCHDR(rc));
}

/*
 * This is a hand-coded derivative of the automatically generated
 * (un)marshalling routine for bind_ack headers. bind_ack headers
 * have an interior conformant array, which is inconsistent with
 * IDL/NDR rules.
 */
extern struct ndr_typeinfo ndt__uchar;
extern struct ndr_typeinfo ndt__ushort;
extern struct ndr_typeinfo ndt__ulong;

int ndr__ndr_bind_ack_hdr(ndr_ref_t *encl_ref);
ndr_typeinfo_t ndt__ndr_bind_ack_hdr = {
    1,		/* NDR version */
    3,		/* alignment */
    NDR_F_STRUCT,	/* flags */
    ndr__ndr_bind_ack_hdr,	/* ndr_func */
    68,		/* pdu_size_fixed_part */
    0,		/* pdu_size_variable_part */
    68,		/* c_size_fixed_part */
    0,		/* c_size_variable_part */
};

/*
 * [_no_reorder]
 */
int
ndr__ndr_bind_ack_hdr(ndr_ref_t *encl_ref)
{
	ndr_stream_t		*nds = encl_ref->stream;
	struct ndr_bind_ack_hdr	*val = /*LINTED E_BAD_PTR_CAST_ALIGN*/
	    (struct ndr_bind_ack_hdr *)encl_ref->datum;
	ndr_ref_t		myref;
	unsigned long		offset;

	bzero(&myref, sizeof (myref));
	myref.enclosing = encl_ref;
	myref.stream = encl_ref->stream;
	myref.packed_alignment = 0;

	/* do all members in order */
	NDR_MEMBER(_ndr_common_header, common_hdr, 0UL);
	NDR_MEMBER(_ushort, max_xmit_frag, 16UL);
	NDR_MEMBER(_ushort, max_recv_frag, 18UL);
	NDR_MEMBER(_ulong, assoc_group_id, 20UL);

	/* port any is the conformant culprit */
	offset = 24UL;

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		val->sec_addr.length =
		    strlen((char *)val->sec_addr.port_spec) + 1;
		break;

	case NDR_M_OP_UNMARSHALL:
		break;

	default:
		NDR_SET_ERROR(encl_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	NDR_MEMBER(_ushort, sec_addr.length, offset);
	NDR_MEMBER_ARR_WITH_DIMENSION(_uchar, sec_addr.port_spec,
	    offset+2UL, val->sec_addr.length);

	offset += 2;
	offset += val->sec_addr.length;
	offset += NDR_ALIGN4(offset);

	NDR_MEMBER(_ndr_p_result_list, p_result_list, offset);
	return (1);
}

/*
 * Assume a single presentation context element in the result list.
 */
unsigned
ndr_bind_ack_hdr_size(ndr_xa_t *mxa)
{
	ndr_bind_ack_hdr_t *bahdr = &mxa->send_hdr.bind_ack_hdr;
	unsigned	offset;
	unsigned	length;

	/* port any is the conformant culprit */
	offset = 24UL;

	length = strlen((char *)bahdr->sec_addr.port_spec) + 1;

	offset += 2;
	offset += length;
	offset += NDR_ALIGN4(offset);
	offset += sizeof (ndr_p_result_list_t);
	return (offset);
}

/*
 * This is a hand-coded derivative of the automatically generated
 * (un)marshalling routine for alter_context_rsp headers.
 * Alter context response headers have an interior conformant array,
 * which is inconsistent with IDL/NDR rules.
 */
int ndr__ndr_alter_context_rsp_hdr(ndr_ref_t *encl_ref);
ndr_typeinfo_t ndt__ndr_alter_context_rsp_hdr = {
    1,			/* NDR version */
    3,			/* alignment */
    NDR_F_STRUCT,	/* flags */
    ndr__ndr_alter_context_rsp_hdr,	/* ndr_func */
    56,			/* pdu_size_fixed_part */
    0,			/* pdu_size_variable_part */
    56,			/* c_size_fixed_part */
    0,			/* c_size_variable_part */
};

/*
 * [_no_reorder]
 */
int
ndr__ndr_alter_context_rsp_hdr(ndr_ref_t *encl_ref)
{
	ndr_stream_t		*nds = encl_ref->stream;
	ndr_alter_context_rsp_hdr_t *val = /*LINTED E_BAD_PTR_CAST_ALIGN*/
	    (ndr_alter_context_rsp_hdr_t *)encl_ref->datum;
	ndr_ref_t		myref;
	unsigned long		offset;

	bzero(&myref, sizeof (myref));
	myref.enclosing = encl_ref;
	myref.stream = encl_ref->stream;
	myref.packed_alignment = 0;

	/* do all members in order */
	NDR_MEMBER(_ndr_common_header, common_hdr, 0UL);
	NDR_MEMBER(_ushort, max_xmit_frag, 16UL);
	NDR_MEMBER(_ushort, max_recv_frag, 18UL);
	NDR_MEMBER(_ulong, assoc_group_id, 20UL);

	offset = 24UL;	/* offset of sec_addr */

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		val->sec_addr.length = 0;
		break;

	case NDR_M_OP_UNMARSHALL:
		break;

	default:
		NDR_SET_ERROR(encl_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	NDR_MEMBER(_ushort, sec_addr.length, offset);
	NDR_MEMBER_ARR_WITH_DIMENSION(_uchar, sec_addr.port_spec,
	    offset+2UL, val->sec_addr.length);

	offset += 2;	/* sizeof (sec_addr.length) */
	offset += NDR_ALIGN4(offset);

	NDR_MEMBER(_ndr_p_result_list, p_result_list, offset);
	return (1);
}

/*
 * Assume a single presentation context element in the result list.
 */
unsigned
ndr_alter_context_rsp_hdr_size(void)
{
	unsigned	offset;

	offset = 24UL;	/* offset of sec_addr */
	offset += 2;	/* sizeof (sec_addr.length) */
	offset += NDR_ALIGN4(offset);
	offset += sizeof (ndr_p_result_list_t);
	return (offset);
}
