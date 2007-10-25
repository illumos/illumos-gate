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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <strings.h>
#include <sys/param.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/ndr.h>
#include <smbsrv/mlrpc.h>

#ifdef _BIG_ENDIAN
static const int mlrpc_native_byte_order = MLRPC_REPLAB_INTG_BIG_ENDIAN;
#else
static const int mlrpc_native_byte_order = MLRPC_REPLAB_INTG_LITTLE_ENDIAN;
#endif

int
mlrpc_encode_decode_common(struct mlrpc_xaction *mxa, int mode, unsigned opnum,
    struct ndr_typeinfo *ti, void *datum)
{
	struct mlndr_stream	*mlnds;
	int			m_op = NDR_MODE_TO_M_OP(mode);
	int			rc;

	if (m_op == NDR_M_OP_MARSHALL)
		mlnds = &mxa->send_mlnds;
	else
		mlnds = &mxa->recv_mlnds;

	/*
	 * Make sure that mlnds is in the correct mode
	 */
	if (!NDR_MODE_MATCH(mlnds, mode))
		return (MLRPC_DRC_FAULT_MODE_MISMATCH);

	/*
	 * Perform the (un)marshalling
	 */
	if (mlndo_operation(mlnds, ti, opnum, datum))
		return (MLRPC_DRC_OK);

	switch (mlnds->error) {
	case NDR_ERR_MALLOC_FAILED:
		rc = MLRPC_DRC_FAULT_OUT_OF_MEMORY;
		break;

	case NDR_ERR_SWITCH_VALUE_INVALID:
		rc = MLRPC_DRC_FAULT_PARAM_0_INVALID;
		break;

	case NDR_ERR_UNDERFLOW:
		rc = MLRPC_DRC_FAULT_RECEIVED_RUNT;
		break;

	case NDR_ERR_GROW_FAILED:
		rc = MLRPC_DRC_FAULT_ENCODE_TOO_BIG;
		break;

	default:
		if (m_op == NDR_M_OP_MARSHALL)
			rc = MLRPC_DRC_FAULT_ENCODE_FAILED;
		else
			rc = MLRPC_DRC_FAULT_DECODE_FAILED;
		break;
	}

	return (rc);
}

int
mlrpc_decode_call(struct mlrpc_xaction *mxa, void *params)
{
	int rc;

	rc = mlrpc_encode_decode_common(mxa, NDR_MODE_CALL_RECV,
	    mxa->opnum, mxa->binding->service->interface_ti, params);

	return (rc + MLRPC_PTYPE_REQUEST);
}

int
mlrpc_encode_return(struct mlrpc_xaction *mxa, void *params)
{
	int rc;

	rc = mlrpc_encode_decode_common(mxa, NDR_MODE_RETURN_SEND,
	    mxa->opnum, mxa->binding->service->interface_ti, params);

	return (rc + MLRPC_PTYPE_RESPONSE);
}

int
mlrpc_encode_call(struct mlrpc_xaction *mxa, void *params)
{
	int rc;

	rc = mlrpc_encode_decode_common(mxa, NDR_MODE_CALL_SEND,
	    mxa->opnum, mxa->binding->service->interface_ti, params);

	return (rc + MLRPC_PTYPE_REQUEST);
}

int
mlrpc_decode_return(struct mlrpc_xaction *mxa, void *params)
{
	int rc;

	rc = mlrpc_encode_decode_common(mxa, NDR_MODE_RETURN_RECV,
	    mxa->opnum, mxa->binding->service->interface_ti, params);

	return (rc + MLRPC_PTYPE_RESPONSE);
}

int
mlrpc_decode_pdu_hdr(struct mlrpc_xaction *mxa)
{
	mlrpcconn_common_header_t *hdr = &mxa->recv_hdr.common_hdr;
	struct mlndr_stream 	*mlnds = &mxa->recv_mlnds;
	int			ptype;
	int			rc;
	int			charset;
	int			byte_order;

	if (mlnds->m_op != NDR_M_OP_UNMARSHALL)
		return (MLRPC_DRC_FAULT_MODE_MISMATCH + 0xFF);

	/*
	 * All PDU headers are at least this big
	 */
	rc = MLNDS_GROW_PDU(mlnds, sizeof (mlrpcconn_common_header_t), 0);
	if (!rc)
		return (MLRPC_DRC_FAULT_RECEIVED_RUNT + 0xFF);

	/*
	 * Peek at the first eight bytes to figure out what we're doing.
	 */
	rc = MLNDS_GET_PDU(mlnds, 0, 8, (char *)hdr, 0, 0);
	if (!rc)
		return (MLRPC_DRC_FAULT_DECODE_FAILED + 0xFF);

	/*
	 * Verify the protocol version.
	 */
	if ((hdr->rpc_vers != 5) || (hdr->rpc_vers_minor != 0))
		return (MLRPC_DRC_FAULT_DECODE_FAILED + 0xFF);

	/*
	 * Check for ASCII as the character set.  This is an ASCII
	 * versus EBCDIC option and has nothing to do with Unicode.
	 */
	charset = hdr->packed_drep.intg_char_rep & MLRPC_REPLAB_CHAR_MASK;
	if (charset != MLRPC_REPLAB_CHAR_ASCII)
		return (MLRPC_DRC_FAULT_DECODE_FAILED + 0xFF);

	/*
	 * Set the byte swap flag if the PDU byte-order
	 * is different from the local byte-order.
	 */
	byte_order = hdr->packed_drep.intg_char_rep & MLRPC_REPLAB_INTG_MASK;
	mlnds->swap = (byte_order != mlrpc_native_byte_order) ? 1 : 0;

	ptype = hdr->ptype;
	if (ptype == MLRPC_PTYPE_REQUEST &&
	    (hdr->pfc_flags & MLRPC_PFC_OBJECT_UUID) != 0) {
		ptype = MLRPC_PTYPE_REQUEST_WITH;	/* fake for sizing */
	}

	mxa->ptype = hdr->ptype;

	rc = mlrpc_encode_decode_common(mxa,
	    NDR_M_OP_AND_DIR_TO_MODE(mlnds->m_op, mlnds->dir),
	    ptype, &TYPEINFO(mlrpcconn_hdr), hdr);

	return (rc + 0xFF);
}

/*
 * Decode an RPC fragment header.  Use mlrpc_decode_pdu_hdr() to process
 * the first fragment header then this function to process additional
 * fragment headers.
 */
void
mlrpc_decode_frag_hdr(struct mlndr_stream *mlnds,
    mlrpcconn_common_header_t *hdr)
{
	mlrpcconn_common_header_t *tmp;
	uint8_t *pdu;
	int byte_order;

	pdu = (uint8_t *)mlnds->pdu_base_offset + mlnds->pdu_scan_offset;
	bcopy(pdu, hdr, MLRPC_RSP_HDR_SIZE);

	/*
	 * Swap non-byte fields if the PDU byte-order
	 * is different from the local byte-order.
	 */
	byte_order = hdr->packed_drep.intg_char_rep & MLRPC_REPLAB_INTG_MASK;

	if (byte_order != mlrpc_native_byte_order) {
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		tmp = (mlrpcconn_common_header_t *)pdu;

		mlnds_bswap(&tmp->frag_length, &hdr->frag_length,
		    sizeof (WORD));
		mlnds_bswap(&tmp->auth_length, &hdr->auth_length,
		    sizeof (WORD));
		mlnds_bswap(&tmp->call_id, &hdr->call_id, sizeof (DWORD));
	}
}

int
mlrpc_encode_pdu_hdr(struct mlrpc_xaction *mxa)
{
	mlrpcconn_common_header_t *hdr = &mxa->send_hdr.common_hdr;
	struct mlndr_stream 	*mlnds = &mxa->send_mlnds;
	int			ptype;
	int			rc;

	if (mlnds->m_op != NDR_M_OP_MARSHALL)
		return (MLRPC_DRC_FAULT_MODE_MISMATCH + 0xFF);

	ptype = hdr->ptype;
	if (ptype == MLRPC_PTYPE_REQUEST &&
	    (hdr->pfc_flags & MLRPC_PFC_OBJECT_UUID) != 0) {
		ptype = MLRPC_PTYPE_REQUEST_WITH;	/* fake for sizing */
	}

	rc = mlrpc_encode_decode_common(mxa,
	    NDR_M_OP_AND_DIR_TO_MODE(mlnds->m_op, mlnds->dir),
	    ptype, &TYPEINFO(mlrpcconn_hdr), hdr);

	return (rc + 0xFF);
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

int mlndr__mlrpcconn_bind_ack_hdr(struct ndr_reference *encl_ref);
struct ndr_typeinfo ndt__mlrpcconn_bind_ack_hdr = {
    1,		/* NDR version */
    3,		/* alignment */
    NDR_F_STRUCT,	/* flags */
    mlndr__mlrpcconn_bind_ack_hdr,	/* ndr_func */
    68,		/* pdu_size_fixed_part */
    0,		/* pdu_size_variable_part */
    68,		/* c_size_fixed_part */
    0,		/* c_size_variable_part */
};

/*
 * [_no_reorder]
 */
int
mlndr__mlrpcconn_bind_ack_hdr(struct ndr_reference *encl_ref)
{
	struct mlndr_stream 		*mlnds = encl_ref->stream;
	struct mlrpcconn_bind_ack_hdr   *val = /*LINTED E_BAD_PTR_CAST_ALIGN*/
	    (struct mlrpcconn_bind_ack_hdr *)encl_ref->datum;
	struct ndr_reference	myref;
	unsigned long		offset;

	bzero(&myref, sizeof (myref));
	myref.enclosing = encl_ref;
	myref.stream = encl_ref->stream;
	myref.packed_alignment = 0;

	/* do all members in order */
	NDR_MEMBER(_mlrpcconn_common_header, common_hdr, 0UL);
	NDR_MEMBER(_ushort, max_xmit_frag, 16UL);
	NDR_MEMBER(_ushort, max_recv_frag, 18UL);
	NDR_MEMBER(_ulong, assoc_group_id, 20UL);

	/* port any is the conformant culprit */
	offset = 24UL;

	switch (mlnds->m_op) {
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
	offset += (4 - offset) & 3;

	NDR_MEMBER(_mlrpc_p_result_list, p_result_list, offset);
	return (1);
}

unsigned
mlrpc_bind_ack_hdr_size(struct mlrpcconn_bind_ack_hdr *bahdr)
{
	unsigned	offset;
	unsigned	length;

	/* port any is the conformant culprit */
	offset = 24UL;

	length = strlen((char *)bahdr->sec_addr.port_spec) + 1;

	offset += 2;
	offset += length;
	offset += (4 - offset) & 3;
	offset += sizeof (bahdr->p_result_list);
	return (offset);
}
