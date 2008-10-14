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

#ifndef	_ISNS_PDU_H
#define	_ISNS_PDU_H

#ifdef __cplusplus
extern "C" {
#endif

#define	ISNS_RCV_TIMEOUT	5
#define	ISNS_RCV_SHORT_TIMEOUT	1

#define	NEXT_TLV(OP, LEN)	{ \
	if ((LEN) >= (8 + (OP)->attr_len)) { \
		uint8_t *b1 = (uint8_t *)(OP); \
		(LEN) -= (8 + (OP)->attr_len); \
		b1 += (8 + (OP)->attr_len); \
		(OP) = (isns_tlv_t *)b1; \
	} else { \
		(LEN) = 0; \
		(OP) = NULL; \
	} \
}

size_t isns_rcv_pdu(int, isns_pdu_t **, size_t *, int);
int isns_send_pdu(int, isns_pdu_t *, size_t);
int pdu_reset_rsp(isns_pdu_t **, size_t *, size_t *);
int pdu_reset_scn(isns_pdu_t **, size_t *, size_t *);
int pdu_reset_esi(isns_pdu_t **, size_t *, size_t *);
int pdu_update_code(isns_pdu_t *, size_t *, int);
int pdu_add_tlv(isns_pdu_t **, size_t *, size_t *,
	uint32_t, uint32_t, void *, int);

isns_tlv_t *pdu_get_source(isns_pdu_t *);
isns_tlv_t *pdu_get_key(isns_pdu_t *, size_t *);
isns_tlv_t *pdu_get_operand(isns_pdu_t *, size_t *);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_PDU_H */
