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

#ifndef	_ISNS_PROTOCOL_H
#define	_ISNS_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#define	ISNSP_VERSION			(0x01)

#define	ISNS_DEFAULT_SERVER_PORT	(3205)

#define	ISNSP_HEADER_SIZE		(12)
#define	ISNSP_RSP_CODE_SIZE		(4)
#define	ISNSP_MAX_PAYLOAD_SIZE		(65532)
#define	ISNSP_MAX_PDU_SIZE		(ISNSP_HEADER_SIZE + \
					ISNSP_MAX_PAYLOAD_SIZE)

#define	ISNS_TLV_ATTR_ID_LEN		(4)
#define	ISNS_TLV_ATTR_LEN_LEN		(4)
#define	MAX_ISNS_MESG_ATTR_ENTRIES	(8)
#define	MAX_ISNS_OPER_ATTR_ENTRIES	(32)

/* iSNS Entity Protocol, iSNS Draft - section 6.2.2. */
#define	ISNS_ENTITY_PROTOCOL_NO		(1)
#define	ISNS_ENTITY_PROTOCOL_ISCSI	(2)
#define	ISNS_ENTITY_PROTOCOL_FCP	(3)

/* iSNS Function IDs, iSNS Draft - section 4.1.3. */
#define	ISNS_DEV_ATTR_REG		(0x0001)
#define	ISNS_DEV_ATTR_QRY		(0x0002)
#define	ISNS_DEV_GET_NEXT		(0x0003)
#define	ISNS_DEV_DEREG			(0x0004)
#define	ISNS_SCN_REG			(0x0005)
#define	ISNS_SCN_DEREG			(0x0006)
#define	ISNS_SCN_EVENT			(0x0007)
#define	ISNS_SCN			(0x0008)
#define	ISNS_DD_REG			(0x0009)
#define	ISNS_DD_DEREG			(0x000A)
#define	ISNS_DDS_REG			(0x000B)
#define	ISNS_DDS_DEREG			(0x000C)
#define	ISNS_ESI			(0x000D)
#define	ISNS_HEARTBEAT			(0x000E)
#define	ISNS_DEV_ATTR_REG_RSP		(0x8001)
#define	ISNS_DEV_ATTR_QRY_RSP		(0x8002)
#define	ISNS_DEV_GET_NEXT_RSP		(0x8003)
#define	ISNS_DEV_DEREG_RSP		(0x8004)
#define	ISNS_SCN_REG_RSP		(0x8005)
#define	ISNS_SCN_DEREG_RSP		(0x8006)
#define	ISNS_SCN_EVENT_RSP		(0x8007)
#define	ISNS_SCN_RSP			(0x8008)
#define	ISNS_DD_REG_RSP			(0x8009)
#define	ISNS_DD_DEREG_RSP		(0x800A)
#define	ISNS_DDS_REG_RSP		(0x800B)
#define	ISNS_DDS_DEREG_RSP		(0x800C)
#define	ISNS_ESI_RSP			(0x800D)

/* iSNS Flags, iSNS Draft - section 5.1.4. */
#define	ISNS_FLAG_FIRST_PDU		(0x0400)
#define	ISNS_FLAG_LAST_PDU		(0x0800)
#define	ISNS_FLAG_REPLACE_REG		(0x1000)
#define	ISNS_FLAG_AUTH_BLK_PRESENTED	(0x2000)
#define	ISNS_FLAG_SERVER		(0x4000)
#define	ISNS_FLAG_CLIENT		(0x8000)

/* iSNS Response Status, iSNS Draft - section 5.4 */
#define	ISNS_RSP_SUCCESSFUL		(0)
#define	ISNS_RSP_UNKNOWN_ERROR		(1)
#define	ISNS_RSP_MSG_FORMAT_ERROR	(2)
#define	ISNS_RSP_INVALID_REGIS		(3)
#define	ISNS_RSP_INVALID_QRY		(5)
#define	ISNS_RSP_SRC_UNKNOWN		(6)
#define	ISNS_RSP_SRC_ABSENT		(7)
#define	ISNS_RSP_SRC_UNAUTHORIZED	(8)
#define	ISNS_RSP_NO_SUCH_ENTRY		(9)
#define	ISNS_RSP_VER_NOT_SUPPORTED	(10)
#define	ISNS_RSP_INTERNAL_ERROR		(11)
#define	ISNS_RSP_BUSY			(12)
#define	ISNS_RSP_OPTION_NOT_UNDERSTOOD	(13)
#define	ISNS_RSP_INVALID_UPDATE		(14)
#define	ISNS_RSP_MSG_NOT_SUPPORTED	(15)
#define	ISNS_RSP_SCN_EVENT_REJECTED	(16)
#define	ISNS_RSP_SCN_REGIS_REJECTED	(17)
#define	ISNS_RSP_ATTR_NOT_IMPL		(18)
#define	ISNS_RSP_ESI_NOT_AVAILABLE	(21)
#define	ISNS_RSP_INVALID_DEREGIS	(22)
#define	ISNS_RSP_REGIS_NOT_SUPPORTED	(23)

/* iSNS Attribute IDs, iSNS Draft - section 6.1. */
#define	ISNS_DELIMITER_ATTR_ID		(0)
#define	ISNS_EID_ATTR_ID		(1)
#define	ISNS_ENTITY_PROTOCOL_ATTR_ID	(2)
#define	ISNS_MGMT_IP_ADDR_ATTR_ID	(3)
#define	ISNS_TIMESTAMP_ATTR_ID		(4)
#define	ISNS_VERSION_RANGE_ATTR_ID	(5)
#define	ISNS_ENTITY_REG_PERIOD_ATTR_ID	(6)
#define	ISNS_ENTITY_INDEX_ATTR_ID	(7)
#define	ISNS_ENTITY_NEXT_INDEX_ATTR_ID	(8)
#define	ISNS_ENTITY_ISAKMP_P1_ATTR_ID	(11)
#define	ISNS_ENTITY_CERT_ATTR_ID	(12)
#define	ISNS_PORTAL_IP_ADDR_ATTR_ID	(16)
#define	ISNS_PORTAL_PORT_ATTR_ID	(17)
#define	ISNS_PORTAL_NAME_ATTR_ID	(18)
#define	ISNS_ESI_INTERVAL_ATTR_ID	(19)
#define	ISNS_ESI_PORT_ATTR_ID		(20)
#define	ISNS_PORTAL_INDEX_ATTR_ID	(22)
#define	ISNS_SCN_PORT_ATTR_ID		(23)
#define	ISNS_PORTAL_NEXT_INDEX_ATTR_ID	(24)
#define	ISNS_PORTAL_SEC_BMP_ATTR_ID	(27)
#define	ISNS_PORTAL_ISAKMP_P1_ATTR_ID	(28)
#define	ISNS_PORTAL_ISAKMP_P2_ATTR_ID	(29)
#define	ISNS_PORTAL_CERT_ATTR_ID	(31)
#define	ISNS_ISCSI_NAME_ATTR_ID		(32)
#define	ISNS_ISCSI_NODE_TYPE_ATTR_ID	(33)
#define	ISNS_ISCSI_ALIAS_ATTR_ID	(34)
#define	ISNS_ISCSI_SCN_BITMAP_ATTR_ID	(35)
#define	ISNS_ISCSI_NODE_INDEX_ATTR_ID	(36)
#define	ISNS_WWNN_TOKEN_ATTR_ID		(37)
#define	ISNS_NODE_NEXT_INDEX_ATTR_ID	(38)
#define	ISNS_ISCSI_AUTH_METHOD_ATTR_ID	(42)
#define	ISNS_PG_ISCSI_NAME_ATTR_ID	(48)
#define	ISNS_PG_PORTAL_IP_ADDR_ATTR_ID	(49)
#define	ISNS_PG_PORTAL_PORT_ATTR_ID	(50)
#define	ISNS_PG_TAG_ATTR_ID		(51)
#define	ISNS_PG_INDEX_ATTR_ID		(52)
#define	ISNS_PG_NEXT_ID_ATTR_ID		(53)
#define	ISNS_DD_SET_ID_ATTR_ID		(2049)
#define	ISNS_DD_SET_NAME_ATTR_ID	(2050)
#define	ISNS_DD_SET_STATUS_ATTR_ID	(2051)
#define	ISNS_DD_ID_ATTR_ID		(2065)
#define	ISNS_DD_NAME_ATTR_ID		(2066)
#define	ISNS_DD_ISCSI_INDEX_ATTR_ID	(2067)
#define	ISNS_DD_ISCSI_NAME_ATTR_ID	(2068)
#define	ISNS_DD_FC_PORT_NAME_ATTR_ID	(2069)
#define	ISNS_DD_PORTAL_INDEX_ATTR_ID	(2070)
#define	ISNS_DD_PORTAL_IP_ADDR_ATTR_ID	(2071)
#define	ISNS_DD_PORTAL_PORT_ATTR_ID	(2072)
#define	ISNS_DD_FEATURES_ATTR_ID	(2078)

/* Entity Protocol, RFC 4171 - section 6.2.2. */
#define	ISNS_ENTITY_NO_PROTOCOL		(1)
#define	ISNS_ENTITY_ISCSI		(2)
#define	ISNS_ENTITY_IFCP		(3)

/* Protocol Version Range, RFC 4171 - section 6.2.5. */
#define	ISNS_VER_SHIFT			(16)
#define	ISNS_VERSION			(0x0000FFFF)

/* Portal Port, RFC 4171 - section 6.3.2. */
#define	ISNS_PORT_BITS			(0x0000FFFF)    /* Bits 16 - 31 */
#define	ISNS_PORT_TYPE			(0x00010000)    /* Bit 15 */

/* Portal Security Bitmap, RFC 4171 - section 6.3.9. */
#define	ISNS_TUNNEL_MODE_PREFERRED	(0x0040)	/* Bit 25 */
#define	ISNS_TRANS_MODE_PREFERRED	(0x0020)	/* Bit 26 */
#define	ISNS_PFS_ENABLED		(0x0010)	/* Bit 27 */
#define	ISNS_AGGR_MODE_ENABLED		(0x0008)	/* Bit 28 */
#define	ISNS_MAIN_MODE_ENABLED		(0x0004)	/* Bit 29 */
#define	ISNS_IKE_IPSEC_ENABLED		(0x0002)	/* Bit 30 */
#define	ISNS_BITMAP_VALID		(0x0001)	/* Bit 31 */

/* iSCSI Node Type, RFC 4171 - section 6.4.2. */
#define	ISNS_TARGET_NODE_TYPE		(0x0001)
#define	ISNS_INITIATOR_NODE_TYPE	(0x0002)
#define	ISNS_CONTROL_NODE_TYPE		(0x0004)

/* iSCSI Node SCN Bitmap, RFC 4171 - section 6.4.4. */
#define	ISNS_INIT_SELF_INFO_ONLY	(0x0080)	/* Bit 24 */
#define	ISNS_TARGET_SELF_INFO_ONLY	(0x0040)	/* Bit 25 */
#define	ISNS_MGMT_REG			(0x0020)	/* Bit 26 */
#define	ISNS_OBJECT_REMOVED		(0x0010)	/* Bit 27 */
#define	ISNS_OBJECT_ADDED		(0x0008)	/* Bit 28 */
#define	ISNS_OBJECT_UPDATED		(0x0004)	/* Bit 29 */
#define	ISNS_MEMBER_REMOVED		(0x0002)	/* Bit 30 */
#define	ISNS_MEMBER_ADDED		(0x0001)	/* Bit 31 */

/* Portal Group Tag, RFC 4171 - section 6.5.4. */
#define	ISNS_PG_TAG			(0x0000FFFF)	/* Bits 16 - 31 */

/* DDS Status, RFC 4171 - section 6.11.1.3. */
#define	ISNS_DDS_STATUS			(0x0001)	/* Bit 31 */

/* DD Feature, RFC 4171 - section 6.11.2.9. */
#define	ISNS_DD_BOOTLIST		(0x0001)	/* Bit 31 */

/* iSNS Defaults */
#define	ISNS_DEFAULT_PGT		(0x00000001)
#define	ISNS_DEFAULT_DD_SET_ID		(1)
#define	ISNS_DEFAULT_DD_ID		(1)

/* Min/Max length of names */
#define	ISNS_DDS_MAX_NAME_LEN		(256)
#define	ISNS_DD_MAX_NAME_LEN		(256)
#define	ISNS_ISCSI_MAX_NAME_LEN		(224)
#define	ISNS_ISCSI_MAX_ALIAS_LEN	(256)
#define	ISNS_ENTITY_MIN_EID_LEN		(3)
#define	ISNS_ENTITY_MAX_EID_LEN		(255)


typedef struct isns_tlv {
	uint32_t attr_id;
	uint32_t attr_len;
	uint8_t attr_value[1];
} isns_tlv_t;

typedef struct isns_packet_data {
	uint16_t version;
	uint16_t func_id;
	uint16_t payload_len;
	uint16_t flags;
	uint16_t xid;
	uint16_t seq;

	int num_of_tlvs;
	isns_tlv_t tlvs[MAX_ISNS_OPER_ATTR_ENTRIES];
} isns_packet_data_t;

typedef struct isns_reg_mesg {
	isns_tlv_t src_attr;
	int num_of_mesg_attrs;
	isns_tlv_t *mesg_attrs[MAX_ISNS_MESG_ATTR_ENTRIES];
	isns_tlv_t delimiter_attr;
	isns_tlv_t *operating_attrs[MAX_ISNS_OPER_ATTR_ENTRIES];
} isns_reg_mesg_t;

typedef struct isns_resp_mesg {
	uint8_t	status[4];
	isns_tlv_t messages_attrs[MAX_ISNS_MESG_ATTR_ENTRIES];
	isns_tlv_t delimiter_attr;
	isns_tlv_t operating_attrs[MAX_ISNS_OPER_ATTR_ENTRIES];
} isns_resp_mesg_t;

typedef struct isns_pdu {
	uint16_t version;
	uint16_t func_id;
	uint16_t payload_len;
	uint16_t flags;
	uint16_t xid;
	uint16_t seq;
	uint8_t payload[1];
} isns_pdu_t;

typedef struct isns_resp {
	uint32_t status;
	uint8_t data[1];
} isns_resp_t;

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_PROTOCOL_H */
