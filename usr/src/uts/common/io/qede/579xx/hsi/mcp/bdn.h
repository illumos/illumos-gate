/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

/****************************************************************************
 * Copyright(c) 2009-2015 Broadcom Corporation, all rights reserved
 * Proprietary and Confidential Information.
 *
 * This source file is the property of Broadcom Corporation, and
 * may not be copied or distributed in any isomorphic form without
 * the prior written consent of Broadcom Corporation.
 *
 * Name: bdn.h
 *
 * Description: BDN definitions
 *
 * Author: Yaniv Rosner
 *
 ****************************************************************************/

#ifndef BDN_H
#define BDN_H

#if 0
typedef u32 bdn_cfg;
#define BDN_CFG_SIZE_MASK		0x0000ffff
#define BDN_CFG_SIZE_OFFSET		0
#define BDN_CFG_STATE_MASK		0x00ff0000
#define BDN_CFG_STATE_OFFSET		16
	#define BDN_CFG_STATE_ACTIVE		0x00010000
	#define BDN_CFG_STATE_PENDING		0x00020000
	#define BDN_CFG_STATE_DEFAULT		0x00040000

#define SERVER_DESCRIPTION_MAX_LENGTH 64
struct server_descrip {
	u8 len;
	u8 str[SERVER_DESCRIPTION_MAX_LENGTH];
};

#define SERVER_UUID_LENGTH	 36
struct server_uuid {
	u8 len;
	u8 str[SERVER_UUID_LENGTH];
};

#define GENERALIZED_TIME_MAX_SIZE 16 /* YYYYMMDDhhmmss.s */
struct generalized_time {
	u8 len;
	u8 time_str[GENERALIZED_TIME_MAX_SIZE];
};
#define CONNECTION_ID_LENGTH	16

#define SLOT_TYPE_NUM_MAX_LENGTH 32
struct slot_type_num {
	u8 len;
	u8 str[SLOT_TYPE_NUM_MAX_LENGTH];
};

#define ILO_MGMT_MAX_NUM_OF_ADDR 3
#define ILO_MGMT_ADDR_MAX_LENGTH 16
struct iLO_mgmt_addr {
	u8 num_of_add;
	u8 len_of_add[ILO_MGMT_MAX_NUM_OF_ADDR];
	u8 str[ILO_MGMT_MAX_NUM_OF_ADDR][ILO_MGMT_ADDR_MAX_LENGTH];
};

#define ENCLOSURE_ID_LENGTH	 36
struct enclosure_id {
	u8 len;
	u8 str[ENCLOSURE_ID_LENGTH];
	u8 res[3];
};

struct base_dev_next_os {
	u8 reset_2_factory;
	u8 res[3];
};

struct base_dev_now {
	u8 one_view_config;
	u8 res[3];
};

struct base_dev {
	struct base_dev_now now;
	struct base_dev_next_os next_os;
};

struct server_info {
	u8 optional_bitmap;
#define SERVER_INFO_ILO_MGMT_VLAN_PRESENT	(1<<0)
#define SERVER_INFO_DATA_TIMESTAMP_PRESENT	(1<<1)
#define SERVER_INFO_ENCLOSURE_ID_PRESENT	(1<<2)
	struct server_descrip server_descrip;
	struct server_uuid server_uuid;
	struct slot_type_num slot_type_num;
	struct iLO_mgmt_addr iLO_mgmt_addr;
	u16 iLO_mgmt_vlan;
	struct generalized_time data_timestamp;
};

struct Codec_Info {
	u32 version;	/* Version of Codec */

	enum codec_location {
		e_None		= 0,
		e_Here		= 1,
		e_FRU_EEPROM	= 2
	} loc; /* DEFAULT e-None */
	u16 total_size;	/* total size of Codec in bytes.Max size 32K (64K?)*/
	u16 num_msg_segments;	/* number of segments = total size / max message payload size */
};

#define MAX_CODEC_SIZE		0x8000
#define CODEC_SEGMENT_SIZE	0x400
#define NUMBER_OF_SEGMENTS (MAX_CODEC_SIZE/CODEC_SEGMENT_SIZE)
struct codec_t {
	u8 data[NUMBER_OF_SEGMENTS][CODEC_SEGMENT_SIZE];
};

struct bdn_netport_now {
	bdn_cfg hdr;
	u8 enable_port;
	u8 enable_diag;
	u8 num_pfs_min_bw;
	u8 num_pfs_max_bw;
	u8 min_bw[MCP_GLOB_FUNC_MAX]; 
	u8 max_bw[MCP_GLOB_FUNC_MAX]; 
};

struct bdn_netport_on_port_reset {
	bdn_cfg hdr;
	u32 link_config;
/* Same definitions as in PORT_HW_CFG_SPEED_CAPABILITY_D3_MASK */
#define BDN_LINK_CONFIG_ADVERTISED_SPEED_MASK	0x0000ffff
#define BDN_LINK_CONFIG_ADVERTISED_SPEED_SHIFT	0
/* Same definitions as PORT_FEATURE_FLOW_CONTROL_MASK */
#define BDN_LINK_CONFIG_FLOW_CONTROL_MASK	0x00070000
#define BDN_LINK_CONFIG_FLOW_CONTROL_SHIFT	16

#define BDN_LINK_CONFIG_PFC_ENABLED_MASK	0x00080000
#define BDN_LINK_CONFIG_PFC_ENABLED_SHIFT	19

#define BDN_LINK_CONFIG_EEE_ENABLED_MASK	0x00100000
#define BDN_LINK_CONFIG_EEE_ENABLED_SHIFT	20
};

struct bdn_netport_next_os_boot {
	bdn_cfg hdr;
	u8   num_pfs;
	u8   num_vf_per_pf[MCP_GLOB_FUNC_MAX];
};

struct bdn_netport_diag_ctrl {
	bdn_cfg hdr;
	u8  port_reset;
	u8  local_loopback;
	u8  remote_loopback;
	u8  rsrv[1];
};

struct bdn_netport {
	struct bdn_netport_now now;
	struct bdn_netport_on_port_reset on_port_reset; /* On Port Reset */
	struct bdn_netport_next_os_boot next_os_boot; /* Next OS Boot */
	struct bdn_netport_diag_ctrl diag_ctrl;
};

#define CONNECTION_ID_LEN 16
struct bdn_flexfunc_now {
	bdn_cfg hdr;
	u8 connection_id[CONNECTION_ID_LEN];
	u8 fnic_enabled;
	u8 rsrv[3];
};

struct bdn_flexfunc_next_os_boot {
	bdn_cfg hdr;
	u32 optional_bitmap;
#define FLEXFUNC_CFG_NEXT_OS_C2S_PCP_MAP_PRESENT	(1<<0)
#define FLEXFUNC_CFG_NEXT_OS_PORT_ASSIGNMENT_PRESENT	(1<<1)
#define FLEXFUNC_CFG_NEXT_OS_EMB_LAG_PRESENT		(1<<2)
	u8 mac_addr[6];
	u8 func_type;
	u8 boot_mode;
	u8 c_2_s_pcp_map[9]; /*  Maps O/S C-VLAN PCP value to S-VLAN PCP value for TX
			      * -- items 1-8 correspond to the O/S C-VLAN PCP values 0-7
			      * -- item 9 is the default if no C-VLAN present
			      * -- Values in these 9 bytes are the expected S-PCP values.
			      * -- If NetDev-Device-Module: EVB-Support.c-2-s-pcp-map = FALSE, then
			      * --     all values must be identical
			      * -- else, it supports C-PCP -> S-PCP mapping
			      */
	u16 mtu_size;
	u8 rsrv[1];
};

struct bdn_flex_func_diag_ctrl {
	bdn_cfg hdr;
	u8  enable_wol;
	u8  rsrv[3];
};

struct bdn_flex_func {
	struct bdn_flexfunc_now now;
	struct bdn_flexfunc_next_os_boot next_os_boot; /* Next OS Boot */
	struct bdn_flex_func_diag_ctrl diag_ctrl;
};

#define FC_NPIV_WWPN_SIZE 8
#define FC_NPIV_WWNN_SIZE 8
struct bdn_npiv_settings {
	u8 npiv_wwpn[FC_NPIV_WWPN_SIZE];
	u8 npiv_wwnn[FC_NPIV_WWNN_SIZE];
};

struct bdn_fc_npiv_cfg {
	/* hdr used internally by the MFW */
	u32 hdr;
	u32 num_of_npiv;
};

#define MAX_NUMBER_NPIV 64
struct bdn_fc_npiv_tbl {
	struct bdn_fc_npiv_cfg fc_npiv_cfg;
	struct bdn_npiv_settings settings[MAX_NUMBER_NPIV];
};


struct bdn_fc_npiv {
	struct bdn_fc_npiv_tbl now; /* Next device level reset */
};

struct bdn_iscsi_initiator_cfg {
	u32 optional_bitmap;
#define ISCSI_INITIATOR_ROUTE_PRESENT	(1<<0)
#define ISCSI_INITIATOR_PRIMARY_DNS_PRESENT	(1<<1)
#define ISCSI_INITIATOR_SECONDARY_DNS_PRESENT	(1<<2)
	u8 name[232];
	u8 ip_add[16];
	u8 netmask[16];
	u8 route[16];
	u8 primary_dns[16];
	u8 secondary_dns[16];
};

struct bdn_iscsi_target_params {
	u32 optional_bitmap;
#define ISCSI_TARGET_LLMNR_ENABLE_PRESENT	(1<<0)
#define ISCSI_TARGET_ROUTE_ADV_ENABLE_PRESENT	(1<<1)
#define ISCSI_TARGET_IPV2_PRESENT	(1<<2)
	u8 name[232];
	u32 lun;
	u8 ip_addr[16];
	u32 tcp_port;
	u8 ip_addr_2[16];
	u32 tcp_port_2;
	u32 llmnr_en;
	u32 route_adv_en;
};

struct bdn_iscsi_authentication {
	u32 optional_bitmap;
#define ISCSI_AUTH_CHAP_USERNAME_PRESENT	(1<<0)
#define ISCSI_AUTH_CHAP_SECRET_PRESENT	(1<<1)
#define ISCSI_AUTH_MUTUAL_USERNAME_PRESENT	(1<<2)
#define ISCSI_AUTH_MUTUAL_SECRET_PRESENT	(1<<3)
	u32 auth_meth;
	u8 username[232];
	u8 secret[16];
	u32 secret_len;
	u8 mutual_username[232];
	u8 mutual_secret[16];
	u32 mutual_secret_len;
};

struct bdn_iscsi_boot_cfg {
	u32 optional_bitmap;
#define ISCSI_CFG_CVID_PRESENT	(1<<0)
#define ISCSI_CFG_DNS_VIA_DHCP_PRESENT	(1<<1)
#define ISCSI_CFG_TARGET_INFO_DHCP_PRESENT	(1<<2)
#define ISCSI_CFG_INITIATOR_PRESENT	(1<<3)
#define ISCSI_CFG_TARGET_PRESENT	(1<<4)
#define ISCSI_CFG_DHCP_VENDOR_ID_PRESENT	(1<<5)
#define ISCSI_CFG_AUTH_PRESENT	(1<<6)
#define ISCSI_AUTH_HEADER_DIGEST_FLAG_PRESENT	(1<<7)
#define ISCSI_AUTH_DATA_DIGEST_FLAG_PRESENT	(1<<8)
	bdn_cfg hdr;
	u32 cvid;
	u32 ip_add_type;
	u32 dns_via_dhcp;
	u32 target_via_dhcp;
	u8 dhcp_vendor_id[32];
	u32 head_digest_flag_en;
	u32 data_digest_flag_en;
};

struct bdn_iscsi_boot_next_dlr {
	struct bdn_iscsi_boot_cfg cfg; /* Next device level reset */
	struct bdn_iscsi_initiator_cfg initiator_cfg;
	struct bdn_iscsi_target_params target_params;
	struct bdn_iscsi_authentication authentication;
};

struct bdn_iscsi_boot {
	struct bdn_iscsi_boot_next_dlr next_dlr; /* Next device level reset */
};

#define FCOE_TARGETS_WWPN_SIZE 8
#define FCOE_TARGETS_LUN_SIZE 8

struct bdn_fcoe_targets {
	u8 wwpn[FCOE_TARGETS_WWPN_SIZE];
	u8 lun_id[FCOE_TARGETS_LUN_SIZE];
};

struct bdn_fcoe_boot_cfg {
		u32 optional_bitmap;
#define FCOE_CFG_CVID_PRESENT	(1<<0)
#define FCOE_BASE_WWNN_PRESENT	(1<<1)
#define FCOE_WWPN_PRESENT	(1<<2)
	bdn_cfg hdr;
	u32 cvid;
	u8 base_wwnn[FCOE_TARGETS_WWPN_SIZE]; /* Host World wide name*/
	u8 wwpn[FCOE_TARGETS_WWPN_SIZE]; /* base wwpn */
	u32 num_of_fcoe_targets;
};

struct bdn_fcoe_boot_next_dlr {
	struct bdn_fcoe_boot_cfg cfg; /* Next device level reset */
	struct bdn_fcoe_targets fcoe_targets[8];
};

struct bdn_fcoe_boot {
	struct bdn_fcoe_boot_next_dlr next_dlr; /* Next device level reset */
};
#ifndef PF_NUM_MAX
#define PF_NUM_MAX 8
#endif
struct bdn_ncsi_next_dlr {
	bdn_cfg hdr;
	u32 ncsi_scid;
};

struct bdn_ncsi {
	struct bdn_ncsi_next_dlr bdn_ncsi_next_dlr;
};

// Rapid-Response-Poll-Module definition
#define MAX_CCT_SIZE			64
#define VALID_RPP_SIGNATURE		0x69616853
struct rpp_sum_stc {
	u32 hash;
	u32 num;
};

struct digest_stc {
	u8 type;
	u8 inst;
	u16 digest;
};

struct bdn_rapid_respon_stc {
	u32 sig;
	struct rpp_sum_stc rpp_sum;
	u8 num_of_cct;
	u8 res[3];
	struct digest_stc cct[MAX_CCT_SIZE];
#ifdef CONFIG_SUPPORT_SCI
	struct digest_stc sci[MAX_CCT_SIZE];
#endif
};

struct bdn {
	u32 size;
	struct base_dev	base_dev;
	struct server_info server_info;
	struct bdn_netport netport[MCP_GLOB_PORT_MAX * MCP_GLOB_PATH_MAX];
	struct bdn_flex_func flexfunc[PF_NUM_MAX];
	struct bdn_fc_npiv fc_npiv[MCP_GLOB_PORT_MAX * MCP_GLOB_PATH_MAX];
	struct bdn_iscsi_boot iscsi_boot[MCP_GLOB_PORT_MAX * MCP_GLOB_PATH_MAX];
	struct bdn_fcoe_boot fcoe_boot[MCP_GLOB_PORT_MAX * MCP_GLOB_PATH_MAX];
	struct bdn_ncsi ncsi;
	struct bdn_rapid_respon_stc rpp_stc;
	struct enclosure_id serv_info_enc_id;
	u32 crc;
};

union bdn_image {
	struct bdn bdn;
	u8 rsrv[0x9000];
};

/* Expected BDN size is basically the offset of rsrv within the bdn structure */
#define BDN_SIZE (sizeof(struct bdn))
#define BDN_SERVER_INFO()		  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, server_info))
#define BDN_BASE_DEV_NEXT_OS()		   (ASN1_P->bdn_addr + OFFSETOF(struct bdn, base_dev.next_os))
#define BDN_BASE_DEV_NOW()			  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, base_dev.now))
/* #define BDN_CODEC_INFO()		  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, codec_info)) */
/* #define BDN_CODEC_DATA()		  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, codec)) */
#define BDN_NETPORT_NOW(papo)		  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, netport[(papo.path << 1) + papo.port].now))
#define BDN_NETPORT_ON_PORT_RESET(papo)   (ASN1_P->bdn_addr + OFFSETOF(struct bdn, netport[(papo.path << 1) + papo.port].on_port_reset))
#define BDN_NETPORT_NEXT_OS_BOOT(papo)	  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, netport[(papo.path << 1) + papo.port].next_os_boot))
#define BDN_NETPORT_DIAG_CTRL(papo)	  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, netport[(papo.path << 1) + papo.port].diag_ctrl))
#define BDN_FLEXFUNC_NOW(pf_num)	  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, flexfunc[pf_num].now))
#define BDN_FLEXFUNC_NEXT_OS_BOOT(pf_num) (ASN1_P->bdn_addr + OFFSETOF(struct bdn, flexfunc[pf_num].next_os_boot))
#define BDN_FLEXFUNC_DIAG_CTRL(pf_num)	  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, flexfunc[pf_num].diag_ctrl))
#define BDN_FC_NPIV_NOW(papo)		  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, fc_npiv[(papo.path << 1) + papo.port].now))
#define BDN_FC_NPIV_NOW_CFG(papo)		  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, fc_npiv[(papo.path << 1) + papo.port].now.fc_npiv_cfg))
#define BDN_FC_NPIV_NOW_SETTINGS(papo, idx)		  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, fc_npiv[(papo.path << 1) + papo.port].now.settings[idx]))
#define BDN_ISCSI_BOOT_NEXT_DLR_CFG(papo)	  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, iscsi_boot[(papo.path << 1) + papo.port].next_dlr.cfg))
#define BDN_ISCSI_BOOT_NEXT_DLR_INITIATOR(papo)	  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, iscsi_boot[(papo.path << 1) + papo.port].next_dlr.initiator_cfg))
#define BDN_ISCSI_BOOT_NEXT_DLR_TARGET(papo)	  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, iscsi_boot[(papo.path << 1) + papo.port].next_dlr.target_params))
#define BDN_ISCSI_BOOT_NEXT_DLR_AUTHENTICATION(papo)	  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, iscsi_boot[(papo.path << 1) + papo.port].next_dlr.authentication))
#define BDN_FCOE_BOOT_NEXT_DLR_CFG(papo)	  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, fcoe_boot[(papo.path << 1) + papo.port].next_dlr.cfg))
#define BDN_FCOE_BOOT_NEXT_DLR_TARGET(papo, idx)	 (ASN1_P->bdn_addr + OFFSETOF(struct bdn, fcoe_boot[(papo.path << 1) + papo.port].next_dlr.fcoe_targets[idx]))
#define BDN_NCSI_NEXT_DLR()	  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, ncsi.bdn_ncsi_next_dlr))
#define BDN_RAPID_RESPONSE		  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, rpp_stc))
#define BDN_SERV_INFO_ENC_ID()		  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, serv_info_enc_id))
#define BDN_CRC()			  (ASN1_P->bdn_addr + sizeof(union bdn_image))
#endif

#define BDN_SIZE_IMAGE_MAX		(0x9000)

#define BDN_SIZE_OF_MAC			(6)
#define BDN_SIZE_OF_WWN			(8)
#define BDN_SIZE_OF_IPV4		(4)
#define BDN_SIZE_OF_IPV6		(16)
#define BDN_DIR_MAX			(8)
#define BDN_SIZE_OF_PF_PER_PORT		(16)
#define BDN_SIZE_OF_CONNECTION_ID	(16)
#define BDN_SIZE_OF_C2SPCP_MAP		(9)
#define BDN_SIZE_OF_ISCSI_NAME		(236)
#define BDN_SIZE_OF_ISCSI_SEC		(16)
#define BDN_SIZE_OF_FCOE_TARGETS	(8)
#define BDN_SIZE_OF_FCOE_LUN_ID		(8)
#define BDN_SIZE_OF_DHCP_VENDOR_ID	(32)
#define BDN_SIZE_OF_SERV_DESC		(64)
#define BDN_SIZE_OF_SERV_UUID		(36)
#define BDN_SIZE_OF_SERV_SLOT		(32)
#define BDN_NUM_OF_ILO_ADDR		(3)
#define BDN_SIZE_OF_ILO_ADDR		(16)
#define BDN_SIZE_OF_SERV_TIME		(20)
#define BDN_SIZE_OF_ENCLOSURE_ID	(36)
#define BDN_CCT_MAX_SIZE		(64)
#define BDN_SCI_MAX_SIZE		(64)

struct bdn_dir {
	u16 offset;
	u16 length;
};

#define BDN_DIR_CFG_NOW			(0)
#define BDN_DIR_CFG_NEXT_FLR		(1)
#define BDN_DIR_CFG_PORT_RESET		(2)
#define BDN_DIR_CFG_NEXT_DLR		(3)
#define BDN_DIR_CFG_NEXT_OS_BOOT	(4)
#define BDN_DIR_CFG_NEXT_PWR_CYC	(5)
#define BDN_DIR_CFG_DIAG_CTRL		(6)

typedef u32 bdn_cfg_state;
#define BDN_CFG_STATE_MASK		0x000000ff
#define BDN_CFG_STATE_OFFSET		0
#define BDN_CFG_STATE_NA		0x00000000
#define BDN_CFG_STATE_ACTIVE		0x00000001
#define BDN_CFG_STATE_PENDING		0x00000002
#define BDN_CFG_STATE_DEFAULT		0x00000004

#define BDN_CFG_STATE_IS(x, y)		((((x)->state & BDN_CFG_STATE_MASK) >> BDN_CFG_STATE_OFFSET) == BDN_CFG_STATE_##y)
#define BDN_OPTIONAL_SET(x, y)		(x)->optional |= (1 << (y))
#define BDN_OPTIONAL_CHECK(x, y)	((x)->optional & (1 << (y)))

/*.************************* Base-Device-Module************************* */
struct bdn_base_now {
	bdn_cfg_state	state;
	u32		optional;

	u32	rsv:24,
		dci_mgmt:8;

	u32	rsrv;
};

struct bdn_base_osb {
	bdn_cfg_state	state;
	u32		optional;

	u32	rsv:31,
		reset_2_factory:1;

	u32	rsrv;
};

struct bdn_base {
	struct bdn_dir		dir[BDN_DIR_MAX];

	struct bdn_base_now	now;
	struct bdn_base_osb	osb;	/* Next os reboot */
};

/*.************************* Network-Device-Module********************** */
struct bdn_nport_now {
	bdn_cfg_state	state;
	u32		optional;
#define BDN_NETPORT_NOW_OPT_MIN_BW		(0)
#define BDN_NETPORT_NOW_OPT_MAX_BW		(1)

	u32	rsv:14,
		enable_port:1,
		enable_diag:1,
		num_pfs_min_bw:8,
		num_pfs_max_bw:8;

	u8	min_bw[BDN_SIZE_OF_PF_PER_PORT];
	u8	max_bw[BDN_SIZE_OF_PF_PER_PORT];

	u32	rsrv;
};

struct bdn_nport_plr {
	bdn_cfg_state	state;
	u32		optional;
#define BDN_NETPORT_RESET_OPT_ADV_SPEED		(0)
#define BDN_NETPORT_RESET_OPT_FLOW_CTRL		(1)
#define BDN_NETPORT_RESET_OPT_EEE_ENABLE	(2)

	u32	rsv:11,
		eee_enable:1,
		flow_ctrl:4,
		adv_speed:16;

	u32	rsrv;
};

struct bdn_nport_osb {
	bdn_cfg_state	state;
	u32		optional;
#define BDN_NETPORT_BOOT_OPT_NUM_VF		(0)
#define BDN_NETPORT_BOOT_OPT_NPIV_ENABLE	(1)

	u32	rsv:23,
		npiv_enable:1,
		num_pfs:8;
	u8	num_vfs[BDN_SIZE_OF_PF_PER_PORT];

	u32	rsrv;
};

struct bdn_nport_dgn {
	bdn_cfg_state	state;
	u32		optional;

	u32	rsv:29,
		port_reset:1,
		local_loopback:1,
		remote_loopback:1;

	u32	rsrv;
};

struct bdn_nport {
	struct bdn_dir		dir[BDN_DIR_MAX];

	struct bdn_nport_now	now;
	struct bdn_nport_plr	plr;	/* Next device level reset */
	struct bdn_nport_osb	osb;	/* Next os reboot */
	struct bdn_nport_dgn	dgn;
};

/* ************************* FlexFunc-Module************************* */
struct bdn_flex_now {
	bdn_cfg_state	state;
	u32		optional;

	u8	connection_id[BDN_SIZE_OF_CONNECTION_ID];
	u32	rsv:31,
		fnic_enabled:1;

	u32	rsrv;
};

struct bdn_flex_dlr {
	bdn_cfg_state	state;
	u32		optional;
#define BDN_FLEXFUNC_DLR_OPT_FC_WWNN		(0)
#define BDN_FLEXFUNC_DLR_OPT_FC_WWPN		(1)

	u8	fc_wwnn[BDN_SIZE_OF_WWN];
	u8	fc_wwpn[BDN_SIZE_OF_WWN];

	u32	rsrv[2];
};

struct bdn_flex_osb {
	bdn_cfg_state	state;
	u32		optional;
#define BDN_FLEXFUNC_BOOT_OPT_C2SPCP_MAP	(0)
#define BDN_FLEXFUNC_BOOT_OPT_PORT_ASSIGNMENT	(1)
#define BDN_FLEXFUNC_BOOT_OPT_EMB_LAG		(2)
#define BDN_FLEXFUNC_BOOT_OPT_MTU_SIZE		(3)
#define BDN_FLEXFUNC_BOOT_OPT_OVER_MTU		(4)

	u8	mac_addr[BDN_SIZE_OF_MAC];
	u8	c_2_s_pcp_map[BDN_SIZE_OF_C2SPCP_MAP];
	/*  Maps O/S C-VLAN PCP value to S-VLAN PCP value for TX
	 * -- items 1-8 correspond to the O/S C-VLAN PCP values 0-7
	 * -- item 9 is the default if no C-VLAN present
	 * -- Values in these 9 bytes are the expected S-PCP values.
	 * -- If NetDev-Device-Module: EVB-Support.c-2-s-pcp-map = FALSE, then
	 * --     all values must be identical
	 * -- else, it supports C-PCP -> S-PCP mapping
	 */
	u8	func_type;
	u32	rsv:2,
		valid_mac_addr:1,
		override_mtu:1,
		boot_mode:4,
		port_assign:4,
		emb_lag:4,
		mtu_size:16;

	u32	rsrv;
};

struct bdn_flex_dgn {
	bdn_cfg_state	state;
	u32		optional;

	u32	rsv:31,
		enable_wol:1;

	u32	rsrv;
};

struct bdn_flex {
	struct bdn_dir		dir[BDN_DIR_MAX];

	struct bdn_flex_now	now;
	struct bdn_flex_dlr	dlr;	/* Next device level reset */
	struct bdn_flex_osb	osb;	/* Next os reboot */
	struct bdn_flex_dgn	dgn;
};

/* ************************* FC-NPIV-Module************************* */
struct bdn_npiv_dlr {
	bdn_cfg_state	state;
	u32		optional;

	struct dci_fc_npiv_tbl	npiv_tbl;
};

struct bdn_npiv {
	struct bdn_dir		dir[BDN_DIR_MAX];

	struct bdn_npiv_dlr	dlr;	/* Next device level reset */
};

/* ************************* iSCSI-Boot-Module************************* */
struct bdn_iscsi_init {
	u32	rsv:21,
		opt_route:1,
		opt_pri_dns:1,
		opt_sec_dns:1,
		name_size:8;

	u8	ip_add[BDN_SIZE_OF_IPV6];
	u8	netmask[BDN_SIZE_OF_IPV6];
	u8	route[BDN_SIZE_OF_IPV6];
	u8	primary_dns[BDN_SIZE_OF_IPV6];
	u8	secondary_dns[BDN_SIZE_OF_IPV6];
	u8	name[BDN_SIZE_OF_ISCSI_NAME];
};

struct bdn_iscsi_trgt {
	u32 optional;
#define BDN_ISCSI_TARGET_OPT_LLMNR_ENABLE	(0)
#define BDN_ISCSI_TARGET_OPT_ROUTE_ADV_ENABLE	(1)

	u32	rsv:21,
		opt_ip2:1,
		llmnr_en:1,
		route_adv_en:1,
		name_size:8;

	u32	lun;
	u16	tcpport;
	u16	tcpport2;

	u8	ip[BDN_SIZE_OF_IPV6];
	u8	ip2[BDN_SIZE_OF_IPV6];
	u8	name[BDN_SIZE_OF_ISCSI_NAME];

	u32	rsrv;
};

struct bdn_iscsi_auth {
	u32	rsv:2,
		c_sec_size:6,
		auth_method:2,
		m_sec_size:6,
		c_name_size:8,
		m_name_size:8;

	u8	chap_username[BDN_SIZE_OF_ISCSI_NAME];
	u8	chap_secret[BDN_SIZE_OF_ISCSI_SEC];
	u8	mutual_username[BDN_SIZE_OF_ISCSI_NAME];
	u8	mutual_secret[BDN_SIZE_OF_ISCSI_SEC];

	u32	rsrv;
};

struct bdn_iboot_dlr {
	bdn_cfg_state	state;
	u32		optional;
#define BDN_ISCSI_BOOT_OPT_CVID			(0)
#define BDN_ISCSI_BOOT_OPT_INITIATOR		(1)
#define BDN_ISCSI_BOOT_OPT_TARGET		(2)
#define BDN_ISCSI_BOOT_OPT_AUTH			(3)
#define BDN_ISCSI_BOOT_OPT_HEAD_DIGEST_EN	(4)
#define BDN_ISCSI_BOOT_OPT_DATA_DIGEST_EN	(5)

	u32	rsv:4,
		initiator_dhcp:1,
		target_dhcp:1,
		head_digest_en:1,
		data_digest_en:1,
		dhcp_vendor_id_size:8,
		ip_type:4,
		cvid:12;

	u8	dhcp_vendor_id[BDN_SIZE_OF_DHCP_VENDOR_ID];

	u32	rsrv;

	struct bdn_iscsi_init	init;
	struct bdn_iscsi_trgt	trgt;
	struct bdn_iscsi_auth	auth;
};

struct bdn_iboot {
	struct bdn_dir		dir[BDN_DIR_MAX];

	struct bdn_iboot_dlr	dlr;	/* Next device level reset */
};

/* ************************* FCoE-Boot-Module************************* */
struct bdn_fcoe_trgt {
	u8 wwpn[BDN_SIZE_OF_WWN];
	u8 lunid[BDN_SIZE_OF_FCOE_LUN_ID];
};

struct bdn_fboot_dlr {
	bdn_cfg_state	state;
	u32		optional;

	u32	rsv:24,
		num_of_targets:4;

	struct bdn_fcoe_trgt trgt[BDN_SIZE_OF_FCOE_TARGETS];

	u32	rsrv;
};

struct bdn_fboot {
	struct bdn_dir		dir[BDN_DIR_MAX];

	struct bdn_fboot_dlr	dlr;	 /* Next device level reset */
};

/* *************************    NCSI-Module    ************************* */
struct bdn_ncsi_dlr {
	bdn_cfg_state	state;
	u32		optional;

	u32	ncsi_scid:12,
		rsv:20;
	u32	rsv2;
};

struct bdn_ncsi {
	struct bdn_dir		dir[BDN_DIR_MAX];

	struct bdn_ncsi_dlr	dlr;
};

/* ************************* Server-Info-Module************************* */
struct bdn_serv {
	bdn_cfg_state	state;
	u32		optional;
#define BDN_SERV_INFO_OPT_ILO_VLAN	(0)
#define BDN_SERV_INFO_OPT_TIMESTAMP	(1)
#define BDN_SERV_INFO_OPT_ENCLOSURE	(2)

	u16 ilo_vlan;
	u8 serv_desc_size;
	u8 serv_uuid_size;
	u8 slot_info_size;
	u8 timestamp_size;
	u8 enclosure_size;
	u8 ilo_addr_num;
	u8 ilo_addr_size[BDN_NUM_OF_ILO_ADDR];
	u8 crc8; /* the crc8 from last put command */

	u8 serv_desc[BDN_SIZE_OF_SERV_DESC];
	u8 serv_uuid[BDN_SIZE_OF_SERV_UUID];
	u8 slot_info[BDN_SIZE_OF_SERV_SLOT];
	u8 ilo_addr[BDN_NUM_OF_ILO_ADDR][BDN_SIZE_OF_ILO_ADDR];
	u8 timestamp[BDN_SIZE_OF_SERV_TIME];
	u8 enclosure[BDN_SIZE_OF_ENCLOSURE_ID];
};

/* ********************* Rapid-Response-Poll-Module ******************** */
struct bdn_rrp_digest {
	u8	object;
	u8	index;	/* the index from zero */
	u16	digest;
};

struct bdn_rrp {
	bdn_cfg_state	state;
	u32		optional;
#define BDN_RRP_OPT_CCT		(0)
#define BDN_RRP_OPT_SCI		(1)

	u32	hash;
	u32	num_cct:8,
		num_sci:8,
		rsv:16;

	struct bdn_rrp_digest cct[BDN_CCT_MAX_SIZE];
	struct bdn_rrp_digest sci[BDN_SCI_MAX_SIZE];
};

/* 0x20 bytes */
struct bdn_head {
	u32	signature;
#define BDN_HEAD_SIGN_SHIFT		(8)
#define BDN_HEAD_SIGN_MASK		(0xffffff << BDN_HEAD_SIGN_SHIFT)
#define BDN_HEAD_SIGN_VALID		(((u32)'B' << 16) | ((u32)'D' << 8) | 'N')
#define BDN_HEAD_SIGN_VER_SHIFT		(0)
#define BDN_HEAD_SIGN_VER_MASK		(0xff << BDN_HEAD_SIGN_VER_SHIFT)
#define BDN_HEAD_SIGN_VER_CURRENT	(1)
#define BDN_HEAD_SIGN_CURRENT		((BDN_HEAD_SIGN_VALID << BDN_HEAD_SIGN_SHIFT) | (BDN_HEAD_SIGN_VER_CURRENT << BDN_HEAD_SIGN_VER_SHIFT))

	u32	num_port:8,
		num_func:8,
		rsrv_bit:16;

	struct bdn_dir	glob;
	struct bdn_dir	port;
	struct bdn_dir	func;

	u32	rsrv[3];
};

struct bdn_glob {
#define BDN_DIR_GLOB_SERV_INFO		0
#define BDN_DIR_GLOB_BASE_DEV		1
#define BDN_DIR_GLOB_NCSI		2
#define BDN_DIR_GLOB_RRP		3
	struct bdn_dir	dir[BDN_DIR_MAX];

	struct bdn_serv	serv;
	struct bdn_base	base;
	struct bdn_ncsi	ncsi;
	struct bdn_rrp	rrp;

	u32	rsrv[8];
};

struct bdn_port {
#define BDN_DIR_PORT_NETPORT		0
#define BDN_DIR_PORT_FC_NPIV		1
#define BDN_DIR_PORT_ISCSI_BOOT		2
#define BDN_DIR_PORT_FCOE_BOOT		3
	struct bdn_dir		dir[BDN_DIR_MAX];

	struct bdn_nport	port;
	struct bdn_npiv		npiv;
	struct bdn_iboot	iboot;
	struct bdn_fboot	fboot;

};

struct bdn_func {
#define BDN_DIR_FUNC_FLEX_FUNC		0
	struct bdn_dir	dir[BDN_DIR_MAX];

	struct bdn_flex	flex;

	u32	rsrv[4];
};

struct bdn {
	struct bdn_head head;
	struct bdn_glob glob;
	struct bdn_port port[MCP_GLOB_PORT_MAX];
	struct bdn_func func[MCP_GLOB_FUNC_MAX];
};

#define BDN_OFFSET_GLOB(x)		(OFFSETOF(struct bdn, glob.x) & 0xffff)
#define BDN_OFFSET_BASE(x)		(OFFSETOF(struct bdn, glob.base.x) & 0xffff)
#define BDN_OFFSET_NCSI(x)		(OFFSETOF(struct bdn, glob.ncsi.x) & 0xffff)
#define BDN_OFFSET_PORT(x, y)		(OFFSETOF(struct bdn, port[(x)].y) & 0xffff)
#define BDN_OFFSET_NPORT(x, y)		(OFFSETOF(struct bdn, port[(x)].port.y) & 0xffff)
#define BDN_OFFSET_NPIV(x, y)		(OFFSETOF(struct bdn, port[(x)].npiv.y) & 0xffff)
#define BDN_OFFSET_IBOOT(x, y)		(OFFSETOF(struct bdn, port[(x)].iboot.y) & 0xffff)
#define BDN_OFFSET_FBOOT(x, y)		(OFFSETOF(struct bdn, port[(x)].fboot.y) & 0xffff)
#define BDN_OFFSET_FUNC(x, y)		(OFFSETOF(struct bdn, func[(x)].y) & 0xffff)
#define BDN_OFFSET_FLEX(x, y)		(OFFSETOF(struct bdn, func[(x)].flex.y) & 0xffff)
#define BDN_OFFSET_CRC			(BDN_SIZE_IMAGE_MAX - 4)

union bdn_image {
	struct bdn bdn;
	u8_t rsrv[BDN_SIZE_IMAGE_MAX];
};

#endif /* BDN_H */
