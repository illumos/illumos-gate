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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_IB_EOIB_FIP_H
#define	_SYS_IB_EOIB_FIP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ethernet.h>
#include <sys/ib/ib_types.h>

/*
 * Sizes of various objects in FIP headers
 */
#define	FIP_VENDOR_LEN			8
#define	FIP_GUID_LEN			8
#define	FIP_SYSNAME_LEN			32
#define	FIP_PORTNAME_LEN		8
#define	FIP_MGID_PREFIX_LEN		5
#define	FIP_VNIC_NAME_LEN		16
#define	FIP_VHUBID_LEN			3

/*
 * EoIB Pkeys and Qkeys
 */
#define	EIB_ADMIN_PKEY			0xFFFF
#define	EIB_FIP_QKEY			0x80020002
#define	EIB_DATA_QKEY			0x80020003

/*
 * EoIB Advertise and Solicit MCG GUIDs
 */
#define	EIB_GUID_ADVERTISE_PREFIX	0xFF12E01B00060000
#define	EIB_GUID_SOLICIT_PREFIX		0xFF12E01B00070000

/*
 * FIP_Protocol_Version
 */
#define	FIP_PROTO_VERSION		0
typedef struct fip_proto_s {
	uint8_t		pr_version;
	uint8_t		pr_reserved[3];
} fip_proto_t;

/*
 * Basic FIP Header: Opcodes and subcodes for EoIB
 */
#define	FIP_OPCODE_EOIB			0xFFF9

#define	FIP_SUBCODE_H_SOLICIT		0x1
#define	FIP_SUBCODE_G_ADVERTISE		0x2
#define	FIP_SUBCODE_H_VNIC_LOGIN	0x3
#define	FIP_SUBCODE_G_VNIC_LOGIN_ACK	0x4
#define	FIP_SUBCODE_H_VNIC_LOGOUT	0x5
#define	FIP_SUBCODE_G_VHUB_UPDATE	0x6
#define	FIP_SUBCODE_G_VHUB_TABLE	0x7
#define	FIP_SUBCODE_H_KEEP_ALIVE	0x8

/*
 * Basic FIP Header: Flags relevant to EoIB
 */
#define	FIP_BHFLAG_GWAVAIL		0x4
#define	FIP_BHFLAG_SLCTMSG		0x2

/*
 * FIP_Basic_Header
 */
#define	FIP_DESC_TYPE_VENDOR_ID		13
#define	FIP_DESC_LEN_VENDOR_ID		3
typedef struct fip_basic_hdr_s {
	uint16_t	hd_opcode;
	uint8_t		hd_reserved1;
	uint8_t		hd_subcode;
	uint16_t	hd_desc_list_len;
	uint16_t	hd_flags;
	uint8_t		hd_type;
	uint8_t		hd_len;
	uint8_t		hd_reserved2[2];
	uint8_t		hd_vendor_id[FIP_VENDOR_LEN];
} fip_basic_hdr_t;

#define	FIP_IBA_QPN_MASK		0x00FFFFFF
#define	FIP_IBA_PORTID_MASK		0x0FFF
#define	FIP_IBA_SL_MASK			0xF000
#define	FIP_IBA_SL_SHIFT		12

/*
 * FIP_Descriptor_Infiniband_Address
 */
#define	FIP_DESC_TYPE_IBA		240
#define	FIP_DESC_LEN_IBA		7
typedef struct fip_desc_iba_s {
	uint8_t		ia_type;
	uint8_t		ia_len;
	uint8_t		ia_reserved[2];
	uint8_t		ia_vendor_id[FIP_VENDOR_LEN];
	uint32_t	ia_qpn;
	uint16_t	ia_sl_portid;
	uint16_t	ia_lid;
	uint8_t		ia_guid[FIP_GUID_LEN];
} fip_desc_iba_t;

/*
 * FIP Solicitation Control Message:
 *
 * 	FIP_Protocol_Version
 * 	FIP_Basic_Header
 * 	FIP_Descriptor_Infiniband_Address
 */
typedef struct fip_solicit_s {
	fip_proto_t	sl_proto_version;
	fip_basic_hdr_t	sl_fip_hdr;
	fip_desc_iba_t	sl_iba;
} fip_solicit_t;

/*
 * FIP_Descriptor_EoIB_Gateway_Information
 */
#define	FIP_DESC_TYPE_EOIB_GW_INFO	241
#define	FIP_DESC_LEN_EOIB_GW_INFO	4
typedef struct fip_desc_gwinfo_s {
	uint8_t		gi_type;
	uint8_t		gi_len;
	uint8_t		gi_reserved1[2];
	uint8_t		gi_vendor_id[FIP_VENDOR_LEN];
	uint8_t		gi_flags;
	uint8_t		gi_reserved2;
	uint16_t	gi_rss_qpn_num_net_vnics;
} fip_desc_gwinfo_t;

#define	FIP_GWI_HOST_ADMIND_VNICS_MASK	0x80
#define	FIP_GWI_NUM_NET_VNICS_MASK	0x0FFF
#define	FIP_GWI_RSS_QPN_MASK		0xF000
#define	FIP_GWI_RSS_QPN_SHIFT		12

/*
 * FIP_Descriptor_Gateway_Identifier
 */
#define	FIP_DESC_TYPE_GW_ID		248
#define	FIP_DESC_LEN_GW_ID		15
typedef struct fip_desc_gwid_s {
	uint8_t		id_type;
	uint8_t		id_len;
	uint8_t		id_reserved[2];
	uint8_t		id_vendor_id[FIP_VENDOR_LEN];
	uint8_t		id_guid[FIP_GUID_LEN];
	uint8_t		id_sysname[FIP_SYSNAME_LEN];
	uint8_t		id_portname[FIP_PORTNAME_LEN];
} fip_desc_gwid_t;

/*
 * FIP_Descriptor_Keep_Alive_Parameters
 */
#define	FIP_DESC_TYPE_KEEP_ALIVE	249
#define	FIP_DESC_LEN_KEEP_ALIVE		6
typedef struct fip_desc_keepalive_s {
	uint8_t		ka_type;
	uint8_t		ka_len;
	uint8_t		ka_reserved[2];
	uint8_t		ka_vendor_id[FIP_VENDOR_LEN];
	uint32_t	ka_gw_adv_period;
	uint32_t	ka_gw_ka_period;
	uint32_t	ka_vnic_ka_period;
} fip_desc_keepalive_t;

/*
 * FIP Advertise Control Message:
 *
 * 	FIP_Protocol_Version
 * 	FIP_Basic_Header
 * 	FIP_Descriptor_Infiniband_Address
 * 	FIP_Descriptor_EoIB_Gateway_Information
 *	FIP_Descriptor_Gateway_Identifier
 *	FIP_Descriptor_Keep_Alive_Parameters
 */
typedef struct fip_advertise_s {
	fip_proto_t		ad_proto_version;
	fip_basic_hdr_t		ad_fip_header;
	fip_desc_iba_t		ad_iba;
	fip_desc_gwinfo_t	ad_gwinfo;
	fip_desc_gwid_t		ad_gwid;
	fip_desc_keepalive_t	ad_keep_alive;
} fip_advertise_t;

/*
 * FIP_Descriptor_vNIC_Login
 */
#define	FIP_DESC_TYPE_VNIC_LOGIN	242
#define	FIP_DESC_LEN_VNIC_LOGIN		13
typedef struct fip_desc_vnic_login_s {
	uint8_t			vl_type;
	uint8_t			vl_len;
	uint8_t			vl_reserved1[2];
	uint8_t			vl_vendor_id[FIP_VENDOR_LEN];
	uint16_t		vl_mtu;
	uint16_t		vl_vnic_id;
	uint16_t		vl_flags_vlan;
	uint8_t			vl_mac[ETHERADDRL];
	uint8_t			vl_gw_mgid_prefix[FIP_MGID_PREFIX_LEN];
	uint8_t			vl_reserved2;
	uint8_t			vl_flags_rss;
	uint8_t			vl_n_mac_mcgid;
	uint32_t		vl_syndrome_ctl_qpn;
	uint8_t			vl_vnic_name[FIP_VNIC_NAME_LEN];
} fip_desc_vnic_login_t;

/*
 * Flags, masks and error codes for FIP_Descriptor_vNIC_Login
 */
#define	FIP_VL_VNIC_ID_MSBIT		0x8000
#define	FIP_VL_FLAGS_V			0x8000
#define	FIP_VL_FLAGS_M			0x4000
#define	FIP_VL_FLAGS_VP			0x2000
#define	FIP_VL_FLAGS_H			0x1000
#define	FIP_VL_VLAN_MASK		0x0FFF
#define	FIP_VL_RSS_MASK			0x10
#define	FIP_VL_N_RSS_MCGID_MASK		0x0F
#define	FIP_VL_N_MAC_MCGID_MASK		0x3F
#define	FIP_VL_CTL_QPN_MASK		0x00FFFFFF

#define	FIP_VL_SYN_MASK			0xFF000000
#define	FIP_VL_SYN_SHIFT		24

#define	FIP_VL_SYN_SUCCESS		0
#define	FIP_VL_SYN_REJECTED		1
#define	FIP_VL_SYN_GW_NO_RESOURCE	2
#define	FIP_VL_SYN_NO_MORE_NWK_ADDRS	3
#define	FIP_VL_SYN_UNKNOWN_HOST		4
#define	FIP_VL_SYN_UNSUPP_PARAM		5

/*
 * FIP_Descriptor_Partition
 */
#define	FIP_DESC_TYPE_PARTITION		246
#define	FIP_DESC_LEN_PARTITION		4
typedef struct fip_desc_partition_s {
	uint8_t			pn_type;
	uint8_t			pn_len;
	uint8_t			pn_reserved1[2];
	uint8_t			pn_vendor_id[FIP_VENDOR_LEN];
	uint8_t			pn_reserved2[2];
	uint16_t		pn_pkey;
} fip_desc_partition_t;

/*
 * FIP Login Control Message:
 *
 * 	FIP_Protocol_Version
 * 	FIP_Basic_Header
 * 	FIP_Descriptor_Infiniband_Address
 * 	FIP_Descriptor_vNIC_Login
 */
typedef struct fip_login_s {
	fip_proto_t		lg_proto_version;
	fip_basic_hdr_t		lg_fip_header;
	fip_desc_iba_t		lg_iba;
	fip_desc_vnic_login_t	lg_vnic_login;
} fip_login_t;

/*
 * FIP Login ACK Control Message:
 *
 * 	FIP_Protocol_Version
 * 	FIP_Basic_Header
 * 	FIP_Descriptor_Infiniband_Address
 * 	FIP_Descriptor_vNIC_Login
 *	FIP_Descriptor_Partition
 */
typedef struct fip_login_ack_s {
	fip_proto_t		ak_proto_version;
	fip_basic_hdr_t		ak_fip_header;
	fip_desc_iba_t		ak_iba;
	fip_desc_vnic_login_t	ak_vnic_login;
	fip_desc_partition_t	ak_vhub_partition;
} fip_login_ack_t;

/*
 * FIP_Descriptor_vNIC_Identity
 */
#define	FIP_DESC_TYPE_VNIC_IDENTITY	245
#define	FIP_DESC_LEN_VNIC_IDENTITY	13
typedef struct fip_desc_vnic_identity_s {
	uint8_t			vi_type;
	uint8_t			vi_len;
	uint8_t			vi_reserved1[2];
	uint8_t			vi_vendor_id[FIP_VENDOR_LEN];
	uint32_t		vi_flags_vhub_id;
	uint32_t		vi_tusn;
	uint16_t		vi_vnic_id;
	uint8_t			vi_mac[ETHERADDRL];
	uint8_t			vi_port_guid[FIP_GUID_LEN];
	uint8_t			vi_vnic_name[FIP_VNIC_NAME_LEN];
} fip_desc_vnic_identity_t;

#define	FIP_VI_FLAG_U		0x80000000
#define	FIP_VI_FLAG_R		0x40000000
#define	FIP_VI_FLAG_VP		0x01000000

/*
 * FIP Keep Alive Control Message:
 *
 *	FIP_Protocol_Version
 *	FIP_Basic_Header
 *	FIP_Descriptor_vNIC_Identity
 */
typedef struct fip_keep_alive_s {
	fip_proto_t			ka_proto_version;
	fip_basic_hdr_t			ka_fip_header;
	fip_desc_vnic_identity_t	ka_vnic_identity;
} fip_keep_alive_t;

/*
 * FIP_vHUB_Table_Entry
 */
typedef struct fip_vhub_table_entry_s {
	uint8_t			te_v_rss_type;
	uint8_t			te_reserved1;
	uint8_t			te_mac[ETHERADDRL];
	uint32_t		te_qpn;
	uint8_t			te_reserved2;
	uint8_t			te_sl;
	uint16_t		te_lid;
} fip_vhub_table_entry_t;

#define	FIP_TE_VALID			0x80
#define	FIP_TE_RSS			0x40

#define	FIP_TE_TYPE_MASK		0x0F
#define	FIP_TE_TYPE_VNIC		0x00
#define	FIP_TE_TYPE_GATEWAY		0x01
#define	FIP_TE_TYPE_UNICAST_MISS	0x02
#define	FIP_TE_TYPE_MULTICAST_ENTRY	0x03
#define	FIP_TE_TYPE_VHUB_MULTICAST	0x04

#define	FIP_TE_SL_MASK			0x0F
#define	FIP_TE_QPN_MASK			0x00FFFFFF

#define	FIP_VHUB_TABLE_ENTRY_SZ		(sizeof (fip_vhub_table_entry_t))
#define	FIP_VHUB_TABLE_ENTRY_WORDS	(FIP_VHUB_TABLE_ENTRY_SZ >> 2)

/*
 * FIP_Descriptor_vHUB_Update
 */
#define	FIP_DESC_TYPE_VHUB_UPDATE	243
#define	FIP_DESC_LEN_VHUB_UPDATE	9
typedef struct fip_desc_vhub_update_s {
	uint8_t			up_type;
	uint8_t			up_len;
	uint8_t			up_reserved1[2];
	uint8_t			up_vendor_id[FIP_VENDOR_LEN];
	uint32_t		up_eport_vp_vhub_id;
	uint32_t		up_tusn;
	fip_vhub_table_entry_t	up_tbl_entry;
} fip_desc_vhub_update_t;

#define	FIP_UP_VP_SHIFT			24
#define	FIP_UP_VP_MASK			0x1
#define	FIP_UP_EPORT_STATE_SHIFT	28
#define	FIP_UP_EPORT_STATE_MASK		0x3
#define	FIP_UP_VHUB_ID_MASK		0x00FFFFFF

#define	FIP_EPORT_DOWN			0x0
#define	FIP_EPORT_UP			0x1

/*
 * FIP_Descriptor_vHUB_Table
 */
#define	FIP_DESC_TYPE_VHUB_TABLE	244
typedef struct fip_desc_vhub_table_s {
	uint8_t			tb_type;
	uint8_t			tb_len;
	uint8_t			tb_reserved1[2];
	uint8_t			tb_vendor_id[FIP_VENDOR_LEN];
	uint32_t		tb_flags_vhub_id;
	uint32_t		tb_tusn;
	uint8_t			tb_hdr;
	uint8_t			tb_reserved2;
	uint16_t		tb_table_size;
	/*
	 * FIP_vHUB_Table_Entry
	 * FIP_vHUB_Table_Entry
	 * .
	 * .
	 * .
	 * uint32_t Checksum
	 */
} fip_desc_vhub_table_t;

#define	FIP_TB_FLAGS_VP_SHIFT		24
#define	FIP_TB_FLAGS_VP_MASK		0x1

#define	FIP_TB_VHUB_ID_MASK		0x00FFFFFF

#define	FIP_TB_HDR_MIDDLE		0x00
#define	FIP_TB_HDR_FIRST		0x40
#define	FIP_TB_HDR_LAST			0x80
#define	FIP_TB_HDR_ONLY			0xC0

#define	FIP_DESC_VHUB_TABLE_SZ		(sizeof (fip_desc_vhub_table_t))
#define	FIP_DESC_VHUB_TABLE_WORDS	(FIP_DESC_VHUB_TABLE_SZ >> 2)

/*
 * FIP vHUB Table Message:
 *
 * 	FIP_Protocol_Version
 * 	FIP_Basic_Header
 * 	FIP_Descriptor_vHUB_Table
 */
typedef struct fip_vhub_table_s {
	fip_proto_t		vt_proto_version;
	fip_basic_hdr_t		vt_fip_header;
	fip_desc_vhub_table_t	vt_vhub_table;
} fip_vhub_table_t;

/*
 * FIP vHUB Update Message:
 *
 * 	FIP_Protocol_Version
 * 	FIP_Basic_Header
 * 	FIP_Descriptor_vHUB_Update
 */
typedef struct fip_vhub_update_s {
	fip_proto_t		vu_proto_version;
	fip_basic_hdr_t		vu_fip_header;
	fip_desc_vhub_update_t	vu_vhub_update;
} fip_vhub_update_t;

/*
 * Just a generic container to handle either type of VHUB
 * messages
 */
typedef struct fip_vhub_pkt_s {
	fip_proto_t		hb_proto_version;
	fip_basic_hdr_t		hb_fip_header;
} fip_vhub_pkt_t;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_EOIB_FIP_H */
