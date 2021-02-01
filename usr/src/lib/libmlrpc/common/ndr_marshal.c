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
 * Copyright 2020 Tintri by DDN, Inc. All rights reserved.
 */

#include <assert.h>
#include <strings.h>
#include <sys/param.h>

#include <libmlrpc.h>

#ifdef _BIG_ENDIAN
static const int ndr_native_byte_order = NDR_REPLAB_INTG_BIG_ENDIAN;
#else
static const int ndr_native_byte_order = NDR_REPLAB_INTG_LITTLE_ENDIAN;
#endif

static int ndr_decode_hdr_common(ndr_stream_t *, ndr_common_header_t *);
static int ndr_decode_pac_hdr(ndr_stream_t *, ndr_pac_hdr_t *);

/*
 * This is the layout of an RPC PDU, as shown in
 * [MS-RPCE] 2.2.2.13 "Verification Trailer".
 *
 *	+-------------------------------+
 *	|       PDU Header              |
 *	+-------------------------------+ ====
 *	|       Stub Data               |
 *	+-------------------------------+ PDU
 *	|       Stub Padding Octets     |
 *	+-------------------------------+ Body
 *	|       Verification Trailer    |
 *	+-------------------------------+ Here
 *	|       Authentication Padding  |
 *	+-------------------------------+ ====
 *	|       sec_trailer             |
 *	+-------------------------------+
 *	|       Authentication Token    |
 *	+-------------------------------+
 *
 * We don't use the "Verification Trailer" for anything yet.
 * sec_trailer and Authentication Token are for Secure RPC,
 * and are collectively the 'auth_verifier_co' in DCERPC.
 *
 * Each fragment of a multi-fragment response has a unique
 * header and, if authentication was requested, a unique
 * sec_trailer.
 */

static int
ndr_convert_nds_error(ndr_stream_t *nds)
{
	int rc;

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
		if (nds->m_op == NDR_M_OP_MARSHALL)
			rc = NDR_DRC_FAULT_ENCODE_FAILED;
		else
			rc = NDR_DRC_FAULT_DECODE_FAILED;
		break;
	}

	return (rc);
}

static int
ndr_encode_decode_common(ndr_stream_t *nds, unsigned opnum,
    ndr_typeinfo_t *ti, void *datum)
{
	/*
	 * Perform the (un)marshalling
	 */
	if (ndo_operation(nds, ti, opnum, datum))
		return (NDR_DRC_OK);

	return (ndr_convert_nds_error(nds));
}

static int
ndr_encode_decode_type(ndr_stream_t *nds, ndr_typeinfo_t *ti, void *datum)
{
	/*
	 * Perform the (un)marshalling
	 */
	if (ndo_process(nds, ti, datum))
		return (NDR_DRC_OK);

	return (ndr_convert_nds_error(nds));
}

ndr_buf_t *
ndr_buf_init(ndr_typeinfo_t *ti)
{
	ndr_buf_t		*nbuf;

	if ((nbuf = calloc(1, sizeof (ndr_buf_t))) == NULL)
		return (NULL);

	if ((nbuf->nb_heap = ndr_heap_create()) == NULL) {
		free(nbuf);
		return (NULL);
	}

	nbuf->nb_ti = ti;
	nbuf->nb_magic = NDR_BUF_MAGIC;
	return (nbuf);
}

void
ndr_buf_fini(ndr_buf_t *nbuf)
{
	assert(nbuf->nb_magic == NDR_BUF_MAGIC);

	nds_destruct(&nbuf->nb_nds);
	ndr_heap_destroy(nbuf->nb_heap);
	nbuf->nb_magic = 0;
	free(nbuf);
}

/*
 * Decode an NDR encoded buffer.  The buffer is expected to contain
 * a single fragment packet with a valid PDU header followed by NDR
 * encoded data.  The structure to which result points should be
 * of the appropriate type to hold the decoded output.  For example:
 *
 *	pac_info_t info;
 *
 *	if ((nbuf = ndr_buf_init(&TYPEINFO(ndr_pac)) != NULL) {
 *		rc = ndr_decode_buf(nbuf, opnum, data, datalen, &info);
 *		...
 *		ndr_buf_fini(nbuf);
 *	}
 */
int
ndr_buf_decode(ndr_buf_t *nbuf, unsigned hdr_type, unsigned opnum,
    const char *data, size_t datalen, void *result)
{
	ndr_common_header_t	hdr;
	ndr_pac_hdr_t		pac_hdr;
	unsigned		pdu_size_hint;
	int			rc;

	assert(nbuf->nb_magic == NDR_BUF_MAGIC);
	assert(nbuf->nb_heap != NULL);
	assert(nbuf->nb_ti != NULL);

	if (datalen < NDR_PDU_SIZE_HINT_DEFAULT)
		pdu_size_hint = NDR_PDU_SIZE_HINT_DEFAULT;
	else
		pdu_size_hint = datalen;

	rc = nds_initialize(&nbuf->nb_nds, pdu_size_hint, NDR_MODE_BUF_DECODE,
	    nbuf->nb_heap);
	if (NDR_DRC_IS_FAULT(rc))
		return (rc);

	bcopy(data, nbuf->nb_nds.pdu_base_addr, datalen);
	nbuf->nb_nds.pdu_size = datalen;

	switch (hdr_type) {
	case NDR_PTYPE_COMMON:
		rc = ndr_decode_hdr_common(&nbuf->nb_nds, &hdr);
		if (NDR_DRC_IS_FAULT(rc))
			return (rc);

		if (!NDR_IS_SINGLE_FRAG(hdr.pfc_flags))
			return (NDR_DRC_FAULT_DECODE_FAILED);
		break;

	case NDR_PTYPE_PAC:
		rc = ndr_decode_pac_hdr(&nbuf->nb_nds, &pac_hdr);
		if (NDR_DRC_IS_FAULT(rc))
			return (rc);

		if (pac_hdr.common_hdr.hdrlen != sizeof (ndr_serialtype1_hdr_t))
			return (NDR_DRC_FAULT_DECODE_FAILED);
		break;

	default:
		return (NDR_ERR_UNIMPLEMENTED);
	}

	rc = ndr_encode_decode_common(&nbuf->nb_nds, opnum, nbuf->nb_ti,
	    result);
	return (rc);
}

/*
 * Use the receive stream to unmarshall data (NDR_MODE_CALL_RECV).
 */
int
ndr_decode_call(ndr_xa_t *mxa, void *params)
{
	ndr_stream_t	*nds = &mxa->recv_nds;
	int		rc;

	if (!NDR_MODE_MATCH(nds, NDR_MODE_CALL_RECV))
		return (NDR_DRC_FAULT_MODE_MISMATCH);

	rc = ndr_encode_decode_common(nds, mxa->opnum,
	    mxa->binding->service->interface_ti, params);

	return (rc + NDR_PTYPE_REQUEST);
}

/*
 * Use the send stream to marshall data (NDR_MODE_RETURN_SEND).
 */
int
ndr_encode_return(ndr_xa_t *mxa, void *params)
{
	ndr_stream_t	*nds = &mxa->send_nds;
	int		rc;

	if (!NDR_MODE_MATCH(nds, NDR_MODE_RETURN_SEND))
		return (NDR_DRC_FAULT_MODE_MISMATCH);

	rc = ndr_encode_decode_common(nds, mxa->opnum,
	    mxa->binding->service->interface_ti, params);

	return (rc + NDR_PTYPE_RESPONSE);
}

/*
 * Use the send stream to marshall data (NDR_MODE_CALL_SEND).
 */
int
ndr_encode_call(ndr_xa_t *mxa, void *params)
{
	ndr_stream_t	*nds = &mxa->send_nds;
	int		rc;

	if (!NDR_MODE_MATCH(nds, NDR_MODE_CALL_SEND))
		return (NDR_DRC_FAULT_MODE_MISMATCH);

	rc = ndr_encode_decode_common(nds, mxa->opnum,
	    mxa->binding->service->interface_ti, params);

	return (rc + NDR_PTYPE_REQUEST);
}

/*
 * Use the receive stream to unmarshall data (NDR_MODE_RETURN_RECV).
 */
int
ndr_decode_return(ndr_xa_t *mxa, void *params)
{
	ndr_stream_t	*nds = &mxa->recv_nds;
	int		rc;

	if (!NDR_MODE_MATCH(nds, NDR_MODE_RETURN_RECV))
		return (NDR_DRC_FAULT_MODE_MISMATCH);

	rc = ndr_encode_decode_common(nds, mxa->opnum,
	    mxa->binding->service->interface_ti, params);

	return (rc + NDR_PTYPE_RESPONSE);
}

int
ndr_decode_pdu_hdr(ndr_xa_t *mxa)
{
	ndr_common_header_t	*hdr = &mxa->recv_hdr.common_hdr;
	ndr_stream_t		*nds = &mxa->recv_nds;
	int			rc;
	ulong_t			saved_offset;

	saved_offset = nds->pdu_scan_offset;
	rc = ndr_decode_hdr_common(nds, hdr);
	if (NDR_DRC_IS_FAULT(rc))
		return (rc);

	/*
	 * Verify the protocol version.
	 */
	if ((hdr->rpc_vers != 5) || (hdr->rpc_vers_minor != 0))
		return (NDR_DRC_FAULT_RPCHDR_DECODE_FAILED);

	mxa->ptype = hdr->ptype;
	/* pdu_scan_offset now points to (this fragment's) stub data */
	nds->pdu_body_offset = nds->pdu_scan_offset;
	nds->pdu_hdr_size = nds->pdu_scan_offset - saved_offset;
	nds->pdu_body_size = hdr->frag_length - hdr->auth_length -
	    nds->pdu_hdr_size -
	    ((hdr->auth_length != 0) ? SEC_TRAILER_SIZE : 0);

	if (hdr->auth_length != 0 && hdr->auth_length >
	    (hdr->frag_length - nds->pdu_hdr_size - SEC_TRAILER_SIZE))
		return (NDR_DRC_FAULT_RECEIVED_MALFORMED);
	return (NDR_DRC_OK);
}

static int
ndr_decode_hdr_common(ndr_stream_t *nds, ndr_common_header_t *hdr)
{
	int			ptype;
	int			rc;
	int			charset;
	int			byte_order;
	ulong_t			saved_offset;

	if (nds->m_op != NDR_M_OP_UNMARSHALL)
		return (NDR_DRC_FAULT_RPCHDR_MODE_MISMATCH);

	/*
	 * All PDU headers are at least this big
	 */
	saved_offset = nds->pdu_scan_offset;
	if ((nds->pdu_size - saved_offset) < sizeof (ndr_common_header_t))
		return (NDR_DRC_FAULT_RPCHDR_RECEIVED_RUNT);

	/*
	 * Peek at the first eight bytes to figure out what we're doing.
	 */
	rc = NDS_GET_PDU(nds, 0, 8, (char *)hdr, 0, 0);
	if (!rc)
		return (NDR_DRC_FAULT_RPCHDR_DECODE_FAILED);

	/*
	 * Check for ASCII as the character set.  This is an ASCII
	 * versus EBCDIC option and has nothing to do with Unicode.
	 */
	charset = hdr->packed_drep.intg_char_rep & NDR_REPLAB_CHAR_MASK;
	if (charset != NDR_REPLAB_CHAR_ASCII)
		return (NDR_DRC_FAULT_RPCHDR_DECODE_FAILED);

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

	rc = ndr_encode_decode_common(nds, ptype, &TYPEINFO(ndr_hdr), hdr);

	if (hdr->frag_length > (nds->pdu_size - saved_offset))
		rc = NDR_DRC_FAULT_RECEIVED_MALFORMED;
	return (NDR_DRC_PTYPE_RPCHDR(rc));
}

static int
ndr_decode_pac_hdr(ndr_stream_t *nds, ndr_pac_hdr_t *hdr)
{
	int	rc;

	if (nds->m_op != NDR_M_OP_UNMARSHALL)
		return (NDR_DRC_FAULT_RPCHDR_MODE_MISMATCH);

	/*
	 * All PDU headers are at least this big
	 */
	if ((nds->pdu_size - nds->pdu_scan_offset) < sizeof (ndr_pac_hdr_t))
		return (NDR_DRC_FAULT_RPCHDR_RECEIVED_RUNT);

	/*
	 * Peek at the first eight bytes to figure out what we're doing.
	 */
	rc = NDS_GET_PDU(nds, 0, 8, (char *)hdr, 0, 0);
	if (!rc)
		return (NDR_DRC_FAULT_RPCHDR_DECODE_FAILED);

	/* Must be set to 1 to indicate type serialization version 1. */
	if (hdr->common_hdr.version != 1)
		return (NDR_DRC_FAULT_RPCHDR_DECODE_FAILED);

	/*
	 * Set the byte swap flag if the PDU byte-order
	 * is different from the local byte-order.
	 */
	nds->swap =
	    (hdr->common_hdr.endianness != ndr_native_byte_order) ? 1 : 0;

	rc = ndr_encode_decode_common(nds, NDR_PTYPE_PAC,
	    &TYPEINFO(ndr_hdr), hdr);

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

	/* pdu_scan_offset points to byte 0 of this fragment */
	nds->pdu_hdr_size = NDR_RSP_HDR_SIZE;
	nds->pdu_body_offset = nds->pdu_scan_offset + nds->pdu_hdr_size;
	nds->pdu_body_size = hdr->frag_length - hdr->auth_length -
	    nds->pdu_hdr_size -
	    ((hdr->auth_length != 0) ? SEC_TRAILER_SIZE : 0);
}

/*
 * Remove an RPC fragment header from the received data stream.
 *
 * NDR stream on entry:
 *
 *                |<--- frag --->|
 * +-----+--------+-----+--------+-----+---------+-----+
 * | hdr |  data  | hdr |  data  | hdr |  data   | ... |
 * +-----+--------+-----+--------+-----+---------+-----+
 *                 <----
 *
 * NDR stream on return:
 *
 * +-----+----------------+-----+---------+-----+
 * | hdr |       data     | hdr |  data   | ... |
 * +-----+----------------+-----+---------+-----+
 */
void
ndr_remove_frag_hdr(ndr_stream_t *nds)
{
	char	*hdr;
	char	*data;
	int	nbytes;

	hdr = (char *)nds->pdu_base_offset + nds->pdu_scan_offset;
	data = hdr + NDR_RSP_HDR_SIZE;
	nbytes = nds->pdu_size - nds->pdu_scan_offset - NDR_RSP_HDR_SIZE;

	/*
	 * Move all of the data after the header back to where the header began.
	 */
	memmove(hdr, data, nbytes);
	nds->pdu_size -= NDR_RSP_HDR_SIZE;
}

void
ndr_show_hdr(ndr_common_header_t *hdr)
{
	char	*fragtype;

	if (hdr == NULL) {
		ndo_printf(NULL, NULL, "ndr hdr: <null>");
		return;
	}

	if (NDR_IS_SINGLE_FRAG(hdr->pfc_flags))
		fragtype = "single";
	else if (NDR_IS_FIRST_FRAG(hdr->pfc_flags))
		fragtype = "first";
	else if (NDR_IS_LAST_FRAG(hdr->pfc_flags))
		fragtype = "last";
	else
		fragtype = "intermediate";

	ndo_printf(NULL, NULL,
	    "ndr hdr: %d.%d ptype=%d, %s frag (flags=0x%08x) len=%d "
	    "auth_len=%d",
	    hdr->rpc_vers, hdr->rpc_vers_minor, hdr->ptype,
	    fragtype, hdr->pfc_flags, hdr->frag_length, hdr->auth_length);
}

void
ndr_show_auth(ndr_sec_t *auth)
{
	if (auth == NULL) {
		ndo_printf(NULL, NULL, "ndr auth: <null>");
		return;
	}

	ndo_printf(NULL, NULL,
	    "ndr auth: type=0x%x, level=0x%x, pad_len=%d, ctx_id=%d",
	    auth->auth_type, auth->auth_level, auth->auth_pad_len,
	    auth->auth_context_id);
}

int
ndr_encode_pdu_hdr(ndr_xa_t *mxa)
{
	ndr_common_header_t	*hdr = &mxa->send_hdr.common_hdr;
	ndr_stream_t		*nds = &mxa->send_nds;
	int			ptype;
	int			rc;

	if (nds->m_op != NDR_M_OP_MARSHALL)
		return (NDR_DRC_FAULT_RPCHDR_MODE_MISMATCH);

	ptype = hdr->ptype;
	if (ptype == NDR_PTYPE_REQUEST &&
	    (hdr->pfc_flags & NDR_PFC_OBJECT_UUID) != 0) {
		ptype = NDR_PTYPE_REQUEST_WITH;	/* fake for sizing */
	}

	rc = ndr_encode_decode_common(nds, ptype, &TYPEINFO(ndr_hdr), hdr);

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

/*
 * This is a hand-coded (un)marshalling routine for auth_verifier_co
 * (aka ndr_sec_t).
 *
 * We need to pretend this structure isn't variably sized, until ndrgen
 * has been modified to support variable-sized arrays.
 * Here, we only account for the fixed-size members (8 bytes), plus
 * a pointer for the C structure.
 *
 * We then convert between a pointer to the auth token (auth_value,
 * allocated here during unmarshall) and a flat, 'fixed'-sized array.
 */

int ndr__auth_verifier_co(ndr_ref_t *encl_ref);
ndr_typeinfo_t ndt__auth_verifier_co = {
    1,		/* NDR version */
    3,		/* alignment */
    NDR_F_STRUCT,	/* flags */
    ndr__auth_verifier_co,	/* ndr_func */
    8,		/* pdu_size_fixed_part */
    0,		/* pdu_size_variable_part */
    8 + sizeof (void *),	/* c_size_fixed_part */
    0,		/* c_size_variable_part */
};

/*
 * [_no_reorder]
 */
int
ndr__auth_verifier_co(ndr_ref_t *encl_ref)
{
	ndr_stream_t		*nds = encl_ref->stream;
	ndr_xa_t		*mxa = /*LINTED E_BAD_PTR_CAST_ALIGN*/
	    (ndr_xa_t *)encl_ref->datum;
	ndr_common_header_t	*hdr;
	ndr_ref_t		myref;
	ndr_sec_t		*val;

	/*
	 * Assumes scan_offset points to the end of PDU body.
	 * (That's base + frag_len - auth_len - SEC_TRAILER_SIZE)
	 *
	 * At some point, NDRGEN could use struct initializers instead of
	 * bzero() + initialization.
	 */
	bzero(&myref, sizeof (myref));
	myref.enclosing = encl_ref;
	myref.stream = encl_ref->stream;

	switch (nds->m_op) {
	case NDR_M_OP_MARSHALL:
		val = &mxa->send_auth;
		hdr = &mxa->send_hdr.common_hdr;
		break;

	case NDR_M_OP_UNMARSHALL:
		val = &mxa->recv_auth;
		hdr = &mxa->recv_hdr.common_hdr;
		val->auth_value = (uchar_t *)NDS_MALLOC(nds, hdr->auth_length,
		    encl_ref);
		break;

	default:
		NDR_SET_ERROR(encl_ref, NDR_ERR_M_OP_INVALID);
		return (0);
	}

	/*
	 * ndr_topmost() can't account for auth_length (pdu_scan/end_offset).
	 * This would only matter if any of this struct's members
	 * are treated as 'outer' constructs, but they aren't.
	 */
	encl_ref->pdu_end_offset += hdr->auth_length;
	nds->pdu_scan_offset += hdr->auth_length;

	NDR_MEMBER(_uchar, auth_type, 0UL);
	NDR_MEMBER(_uchar, auth_level, 1UL);
	NDR_MEMBER(_uchar, auth_pad_len, 2UL);
	NDR_MEMBER(_uchar, auth_rsvd, 3UL);
	NDR_MEMBER(_ulong, auth_context_id, 4UL);

	NDR_MEMBER_PTR_WITH_DIMENSION(_uchar, auth_value, 8UL,
	    hdr->auth_length);

	return (1);
}

int
ndr_encode_pdu_auth(ndr_xa_t *mxa)
{
	ndr_common_header_t	*hdr = &mxa->send_hdr.common_hdr;
	ndr_stream_t		*nds = &mxa->send_nds;
	int			rc;
	ulong_t			want_size;

	if (nds->m_op != NDR_M_OP_MARSHALL)
		return (NDR_DRC_FAULT_MODE_MISMATCH);

	if (hdr->auth_length == 0)
		return (NDR_DRC_OK);

	want_size = nds->pdu_scan_offset + hdr->auth_length + SEC_TRAILER_SIZE;

	/*
	 * Make sure we have space for the sec trailer - the marshaller
	 * doesn't know how large the auth token is.
	 * Note: ndr_add_auth_token() has already added padding.
	 *
	 * NDS_GROW_PDU will adjust pdu_size for us.
	 */
	if (nds->pdu_max_size < want_size) {
		if (NDS_GROW_PDU(nds, want_size, NULL) == 0)
			return (NDR_DRC_FAULT_ENCODE_TOO_BIG);
	} else {
		nds->pdu_size = want_size;
	}
	rc = ndr_encode_decode_type(nds, &TYPEINFO(auth_verifier_co),
	    mxa);

	return (rc);
}

int
ndr_decode_pdu_auth(ndr_xa_t *mxa)
{
	ndr_common_header_t	*hdr = &mxa->recv_hdr.common_hdr;
	ndr_stream_t		*nds = &mxa->recv_nds;
	ndr_sec_t		*auth = &mxa->recv_auth;
	int			rc;
	ulong_t			saved_offset;
	size_t			auth_size;

	if (nds->m_op != NDR_M_OP_UNMARSHALL)
		return (NDR_DRC_FAULT_MODE_MISMATCH);

	mxa->recv_auth.auth_pad_len = 0;
	if (hdr->auth_length == 0)
		return (NDR_DRC_OK);

	/*
	 * Save the current offset, and skip to the sec_trailer.
	 * That's located after the (fragment of) stub data and the auth
	 * pad bytes (collectively the 'PDU Body').
	 */
	saved_offset = nds->pdu_scan_offset;
	nds->pdu_scan_offset = nds->pdu_body_offset + nds->pdu_body_size;

	/* auth_length is all of the data after the sec_trailer */
	if (hdr->auth_length >
	    (nds->pdu_size - nds->pdu_scan_offset - SEC_TRAILER_SIZE)) {
		nds->pdu_scan_offset = saved_offset;
		return (NDR_DRC_FAULT_RECEIVED_MALFORMED);
	}

	rc = ndr_encode_decode_type(nds, &TYPEINFO(auth_verifier_co),
	    mxa);

	/*
	 * Reset the scan_offset for call decode processing.
	 * If we were successful, remove the sec trailer and padding
	 * from size accounting.
	 */
	if (auth->auth_pad_len > nds->pdu_body_size)
		rc = NDR_DRC_FAULT_RECEIVED_MALFORMED;
	else if (rc == NDR_DRC_OK) {
		auth_size = hdr->auth_length + SEC_TRAILER_SIZE +
		    auth->auth_pad_len;

		/*
		 * After the authenticator has been decoded,
		 * pdu_scan_offset points to just after the auth token,
		 * which is the end of the fragment.
		 *
		 * If there's no data after the authenticator, then we
		 * just remove the authenticator from size accounting.
		 * Otherwise, need to memmove() all of that data back to after
		 * the stub data. The data we move starts at the beginning of
		 * the next fragment.
		 */
		if (nds->pdu_size > nds->pdu_scan_offset) {
			uchar_t *next_frag_ptr = nds->pdu_base_addr +
			    nds->pdu_scan_offset;

			memmove(next_frag_ptr - auth_size, next_frag_ptr,
			    nds->pdu_size - nds->pdu_scan_offset);
		}

		nds->pdu_size -= auth_size;
	}
	nds->pdu_scan_offset = saved_offset;
	return (rc);
}
