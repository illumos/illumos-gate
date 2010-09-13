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

#ifndef	_ISNS_QRY_H
#define	_ISNS_QRY_H

#ifdef __cplusplus
extern "C" {
#endif

#define	TLV2TYPE(TLV)	\
	(TLV)->attr_id >= FIRST_TAG_DD ? OBJ_DD : \
	(TLV)->attr_id >= FIRST_TAG_DDS ? OBJ_DDS : \
	(TLV)->attr_id >= FIRST_TAG_PG ? OBJ_PG : \
	(TLV)->attr_id >= FIRST_TAG_ISCSI ? OBJ_ISCSI : \
	(TLV)->attr_id >= FIRST_TAG_PORTAL ? OBJ_PORTAL : \
	(TLV)->attr_id >= FIRST_TAG_ENTITY ? OBJ_ENTITY : 0;

#define	FOR_EACH_OBJS(IDS, NUM, UID, STMT)	\
{\
	uint32_t i1609 = 0;\
	while (i1609 < (NUM)) {\
		UID = (IDS)[i1609];\
		STMT\
		i1609 ++;\
	}\
}

#define	NEXT_OP(OP, OP_LEN, OP_TYPE)	\
do {\
	NEXT_TLV((OP), (OP_LEN));\
} while ((OP_LEN) >= 8 &&\
	(OP)->attr_id >= TAG_RANGE[OP_TYPE][0] &&\
	(OP)->attr_id <= TAG_RANGE[OP_TYPE][2]);

#define	FOR_EACH_OP(OP, OP_LEN, OP_TYPE, STMT)	\
{\
	while ((OP_LEN) >= 8) {\
		OP_TYPE = TLV2TYPE(OP);\
		STMT\
		NEXT_OP((OP), (OP_LEN), (OP_TYPE));\
	}\
}

int validate_qry_key(isns_type_t, isns_tlv_t *, uint16_t,
	isns_attr_t *);
int get_qry_keys(bmp_t *, uint32_t, isns_type_t *,
	isns_tlv_t *, uint16_t, uint32_t **, uint32_t *);
int get_qry_ops(uint32_t, isns_type_t,
	isns_type_t, uint32_t **, uint32_t *, uint32_t *);
int get_qry_ops2(uint32_t *, uint32_t, isns_type_t,
	uint32_t **, uint32_t *, uint32_t *);
int get_qry_attrs(uint32_t, isns_type_t, isns_tlv_t *,
	uint16_t, conn_arg_t *);
int get_qry_attrs1(uint32_t, isns_type_t, isns_tlv_t *,
	uint16_t, conn_arg_t *);
uint32_t get_next_obj(isns_tlv_t *, uint32_t, isns_type_t,
	uint32_t *, uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_QRY_H */
