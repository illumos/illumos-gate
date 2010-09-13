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
 */

#ifndef _SYS_SCSI_GENERIC_SMP_FRAMES_H
#define	_SYS_SCSI_GENERIC_SMP_FRAMES_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sysmacros.h>

/*
 * The definitions of smp frame types and functions conforming to SAS-1.1 and
 * SAS-2.  Consumers are expected to determine protocol support by examining
 * the response to the REPORT GENERAL function.
 */

typedef enum smp_frame_type {
	SMP_FRAME_TYPE_REQUEST		= 0x40,
	SMP_FRAME_TYPE_RESPONSE		= 0x41
} smp_frame_type_t;

typedef enum smp_function {
	SMP_FUNC_REPORT_GENERAL			= 0x00,
	SMP_FUNC_REPORT_MANUFACTURER_INFO	= 0x01,
	SMP_FUNC_READ_GPIO_REGISTER		= 0x02,
	SMP_FUNC_REPORT_SELF_CONFIG_STATUS	= 0x03,
	SMP_FUNC_REPORT_ZONE_PERM_TABLE		= 0x04,
	SMP_FUNC_REPORT_ZONE_MANAGER_PASSWORD	= 0x05,
	SMP_FUNC_REPORT_BROADCAST		= 0x06,
	SMP_FUNC_DISCOVER			= 0x10,
	SMP_FUNC_REPORT_PHY_ERROR_LOG		= 0x11,
	SMP_FUNC_REPORT_PHY_SATA		= 0x12,
	SMP_FUNC_REPORT_ROUTE_INFO		= 0x13,
	SMP_FUNC_REPORT_PHY_EVENT		= 0x14,
	SMP_FUNC_DISCOVER_LIST			= 0x20,
	SMP_FUNC_REPORT_PHY_EVENT_LIST		= 0x21,
	SMP_FUNC_REPORT_EXP_ROUTE_TABLE_LIST	= 0x22,
	SMP_FUNC_CONFIG_GENERAL			= 0x80,
	SMP_FUNC_ENABLE_DISABLE_ZONING		= 0x81,
	SMP_FUNC_WRITE_GPIO_REGISTER		= 0x82,
	SMP_FUNC_ZONED_BROADCAST		= 0x85,
	SMP_FUNC_ZONE_LOCK			= 0x86,
	SMP_FUNC_ZONE_ACTIVATE			= 0x87,
	SMP_FUNC_ZONE_UNLOCK			= 0x88,
	SMP_FUNC_CONFIG_ZONE_MANAGER_PASSWORD	= 0x89,
	SMP_FUNC_CONFIG_ZONE_PHY_INFO		= 0x8A,
	SMP_FUNC_CONFIG_ZONE_PERM_TABLE		= 0x8B,
	SMP_FUNC_CONFIG_ROUTE_INFO		= 0x90,
	SMP_FUNC_PHY_CONTROL			= 0x91,
	SMP_FUNC_PHY_TEST_FUNCTION		= 0x92,
	SMP_FUNC_CONFIG_PHY_EVENT		= 0x93
} smp_function_t;

typedef enum smp_result {
	SMP_RES_FUNCTION_ACCEPTED		= 0x00,
	SMP_RES_UNKNOWN_FUNCTION		= 0x01,
	SMP_RES_FUNCTION_FAILED			= 0x02,
	SMP_RES_INVALID_REQUEST_FRAME_LENGTH	= 0x03,
	SMP_RES_INVALID_EXPANDER_CHANGE_COUNT	= 0x04,
	SMP_RES_BUSY				= 0x05,
	SMP_RES_INCOMPLETE_DESCRIPTOR_LIST	= 0x06,
	SMP_RES_PHY_DOES_NOT_EXIST		= 0x10,
	SMP_RES_INDEX_DOES_NOT_EXIST		= 0x11,
	SMP_RES_PHY_DOES_NOT_SUPPORT_SATA	= 0x12,
	SMP_RES_UNKNOWN_PHY_OPERATION		= 0x13,
	SMP_RES_UNKNOWN_PHY_TEST_FUNCTION	= 0x14,
	SMP_RES_PHY_TEST_IN_PROGRESS		= 0x15,
	SMP_RES_PHY_VACANT			= 0x16,
	SMP_RES_UNKNOWN_PHY_EVENT_SOURCE	= 0x17,
	SMP_RES_UNKNOWN_DESCRIPTOR_TYPE		= 0x18,
	SMP_RES_UNKNOWN_PHY_FILTER		= 0x19,
	SMP_RES_AFFILIATION_VIOLATION		= 0x1A,
	SMP_RES_ZONE_VIOLATION			= 0x20,
	SMP_RES_NO_MANAGEMENT_ACCESS_RIGHTS	= 0x21,
	SMP_RES_UNKNOWN_ENABLE_DISABLE_ZONING	= 0x22,
	SMP_RES_ZONE_LOCK_VIOLATION		= 0x23,
	SMP_RES_NOT_ACTIVATED			= 0x24,
	SMP_RES_ZONE_GROUP_OUT_OF_RANGE		= 0x25,
	SMP_RES_NO_PHYSICAL_PRESENCE		= 0x26,
	SMP_RES_SAVING_NOT_SUPPORTED		= 0x27,
	SMP_RES_SOURCE_ZONE_GROUP_DNE		= 0x28,
	SMP_RES_DISABLED_PW_NOT_SUPPORTED	= 0x29,
	SMP_RES_NONE				= -1
} smp_result_t;

#pragma	pack(1)

/*
 * SAS-2 10.4.3.2 request frame format
 */
typedef struct smp_request_frame {
	uint8_t srf_frame_type;
	uint8_t srf_function;
	uint8_t srf_allocated_response_len;	/* reserved in SAS-1 */
	uint8_t srf_request_len;
	uint8_t srf_data[1];
} smp_request_frame_t;

/*
 * SAS-2 10.4.3.3 response frame format
 */
typedef struct smp_response_frame {
	uint8_t srf_frame_type;
	uint8_t srf_function;
	uint8_t srf_result;
	uint8_t srf_response_len;	/* reserved in SAS-1 */
	uint8_t srf_data[1];
} smp_response_frame_t;

typedef uint8_t smp_crc_t[4];

#ifdef offsetof
#define	SMP_REQ_MINLEN	\
	(offsetof(smp_request_frame_t, srf_data[0]) + sizeof (smp_crc_t))
#define	SMP_RESP_MINLEN	\
	(offsetof(smp_response_frame_t, srf_data[0]) + sizeof (smp_crc_t))
#endif	/* offsetof */

/*
 * SAS-2 10.4.3.4 REPORT GENERAL (no additional request bytes)
 */
typedef struct smp_report_general_resp {
	uint16_t srgr_exp_change_count;
	uint16_t srgr_exp_route_indexes;
	DECL_BITFIELD2(
	    _reserved1		:7,
	    srgr_long_response	:1);
	uint8_t srgr_number_of_phys;
	DECL_BITFIELD7(
	    srgr_externally_configurable_route_table	:1,
	    srgr_configuring				:1,
	    srgr_configures_others			:1,
	    srgr_open_reject_retry_supported		:1,
	    srgr_stp_continue_awt			:1,
	    _reserved2					:2,
	    srgr_table_to_table_supported		:1);
	uint8_t _reserved3;
	uint64_t srgr_enclosure_logical_identifier;
	uint8_t _reserved4[8];
	uint8_t _reserved5[2];
	uint16_t srgr_stp_bus_inactivity_time_limit;
	uint16_t srgr_stp_maximum_connect_time_limit;
	uint16_t srgr_stp_smp_nexus_loss_time;
	DECL_BITFIELD7(
	    srgr_zoning_enabled				:1,
	    srgr_zoning_supported			:1,
	    srgr_physical_presence_asserted		:1,
	    srgr_physical_presence_supported		:1,
	    srgr_zone_locked				:1,
	    _reserved6					:1,
	    srgr_number_of_zone_grps			:2);
	DECL_BITFIELD6(
	    srgr_saving_zoning_enabled_supported	:1,
	    srgr_saving_zone_perm_table_supported	:1,
	    srgr_saving_zone_phy_info_supported		:1,
	    srgr_saving_zone_mgr_password_supported	:1,
	    srgr_saving					:1,
	    _reserved7					:3);
	uint16_t srgr_max_routed_sas_addrs;
	uint64_t srgr_active_zm_sas_addr;
	uint16_t srgr_zone_lock_inactivity_limit;
	uint8_t _reserved8[2];
	uint8_t _reserved9;
	uint8_t srgr_first_encl_conn_elem_idx;
	uint8_t srgr_number_encl_conn_elem_idxs;
	uint8_t _reserved10;
	DECL_BITFIELD2(
	    _reserved11					:7,
	    srgr_reduced_functionality			:1);
	uint8_t srgr_time_to_reduced_functionality;
	uint8_t srgr_initial_time_to_reduced_functionality;
	uint8_t srgr_max_reduced_functionality_time;
	uint16_t srgr_last_self_conf_status_descr_idx;
	uint16_t srgr_max_stored_self_config_status_descrs;
	uint16_t srgr_last_phy_event_list_descr_idx;
	uint16_t srgr_max_stored_phy_event_list_descrs;
	uint16_t srgr_stp_reject_to_open_limit;
	uint8_t _reserved12[2];
} smp_report_general_resp_t;

typedef enum smp_n_zone_grps {
	SMP_ZONE_GROUPS_128	= 0x0,
	SMP_ZONE_GROUPS_256	= 0x1
} smp_n_zone_grps_t;

/*
 * SAS-2 10.4.3.5 REPORT MANUFACTURER INFORMATION (no additional request bytes)
 */
typedef struct smp_report_manufacturer_info_resp {
	uint16_t srmir_exp_change_count;
	uint8_t _reserved1[2];
	DECL_BITFIELD2(
	    srmir_sas_1_1_format	:1,
	    _reserved2			:7);
	uint8_t _reserved3[3];
	char srmir_vendor_identification[8];
	char srmir_product_identification[16];
	char srmir_product_revision_level[4];
	char srmir_component_vendor_identification[8];
	uint16_t srmir_component_id;
	uint8_t srmir_component_revision_level;
	uint8_t _reserved4;
	uint8_t srmir_vs_52[8];
} smp_report_manufacturer_info_resp_t;

/*
 * SAS-2 10.4.3.6 REPORT SELF_CONFIGURATION STATUS
 */
typedef struct smp_report_self_config_status_req {
	uint8_t _reserved1[2];
	uint16_t srscsr_starting_self_config_status_descr_idx;
} smp_report_self_config_status_req_t;

typedef struct smp_report_self_config_status_resp {
	uint16_t srscsr_exp_change_count;
	uint16_t srscsr_starting_self_config_status_descr_idx;
	uint16_t srscsr_number_self_config_status_descrs;
	uint16_t srscsr_last_self_config_status_descr_idx;
	uint8_t srscsr_self_config_status_descr_len;
	uint8_t _reserved1[3];
	uint8_t srscsr_descrs[1];
} smp_report_self_config_status_resp_t;

typedef struct smp_self_config_status_descr {
	uint8_t sscsd_status_type;
	DECL_BITFIELD2(
	    sscsd_final		:1,
	    _reserved1		:7);
	uint8_t _reserved2;
	uint8_t sscsd_phy_identifier;
	uint8_t _reserved3[4];
	uint64_t sscsd_sas_addr;
} smp_self_config_status_descr_t;

typedef enum smp_self_config_status_type {
	SMP_SCST_NONSPECIFIC_ERROR	= 0x01,
	SMP_SCST_CONNECTION		= 0x02,
	SMP_SCST_ROUTE_TABLE_FULL	= 0x03,
	SMP_SCST_NOMEM			= 0x04,
	SMP_SCST_PHY_LAYER_ERROR	= 0x20,
	SMP_SCST_LOST_SYNC		= 0x21,
	SMP_SCST_LINK_LAYER_ERROR	= 0x40,
	SMP_SCST_OPEN_TIMEOUT		= 0x41,
	SMP_SCST_ABANDON_OPEN_REJECT	= 0x42,
	SMP_SCST_RETRY_OPEN_REJECTS	= 0x43,
	SMP_SCST_NEXUS_LOSS		= 0x44,
	SMP_SCST_BREAK			= 0x45,
	SMP_SCST_CRC_ERROR		= 0x46,
	SMP_SCST_PORT_LAYER_ERROR	= 0x60,
	SMP_SCST_RESPONSE_TIMEOUT	= 0x61,
	SMP_SCST_TRANSPORT_LAYER_ERROR	= 0x80,
	SMP_SCST_APP_LAYER_ERROR	= 0xA0,
	SMP_SCST_RESPONSE_TOO_SHORT	= 0xA1,
	SMP_SCST_UNSUPPORTED_VALUES	= 0xA2,
	SMP_SCST_INCONSISTENT		= 0xA3,
	SMP_SCST_CONFIGURING		= 0xA4
} smp_self_config_status_type_t;

/*
 * SAS-2 10.4.3.7 REPORT ZONE PERMISSION TABLE
 */
typedef struct smp_report_zone_perm_table_req {
	DECL_BITFIELD2(
	    srzptr_report_type		:2,
	    _reserved1			:6);
	uint8_t _reserved2;
	uint8_t srzptr_starting_src_zone_grp;
	uint8_t srzptr_max_zone_perm_descrs;
} smp_report_zone_perm_table_req_t;

typedef enum smp_zone_perm_table_report_type {
	SMP_ZPTRT_CURRENT		= 0x0,
	SMP_ZPTRT_SHADOW		= 0x1,
	SMP_ZPTRT_SAVED			= 0x2,
	SMP_ZPTRT_DEFAULT		= 0x3
} smp_zone_perm_table_report_type_t;

typedef struct smp_report_zone_perm_table_resp {
	uint16_t srzptr_exp_change_count;
	DECL_BITFIELD3(
	    srzptr_report_type		:2,
	    _reserved1			:5,
	    srzptr_zone_locked		:1);
	DECL_BITFIELD2(
	    _reserved2			:6,
	    srzptr_number_zone_grps	:2);
	uint8_t _reserved3[6];
	uint8_t srzptr_starting_src_zone_grp;
	uint8_t srzptr_number_zone_perm_descrs;
	uint8_t srzptr_descrs[1];
} smp_report_zone_perm_table_resp_t;

typedef uint8_t smp_zone_perm_descr128_t[16];
typedef uint8_t smp_zone_perm_descr256_t[32];

#define	SMP_ZONE_PERM_BIT128(__d, __z)	\
	((__d)[15 - ((__z) >> 3)] & (1 << ((__z) & 7)))

#define	SMP_ZONE_PERM_SET128(__d, __z)	\
	((__d)[15 - ((__z) >> 3)] |= (1 << ((__z) & 7)))

#define	SMP_ZONE_PERM_CLR128(__d, __z)	\
	((__d)[15 - ((__z) >> 3)] &= ~(1 << ((__z) & 7)))

#define	SMP_ZONE_PERM_BIT256(__d, __z)	\
	((__d)[31 - ((__z) >> 3)] & (1 << ((__z) & 7)))

#define	SMP_ZONE_PERM_SET256(__d, __z)	\
	((__d)[31 - ((__z) >> 3)] |= (1 << ((__z) & 7)))

#define	SMP_ZONE_PERM_CLR256(__d, __z)	\
	((__d)[31 - ((__z) >> 3)] &= ~(1 << ((__z) & 7)))

/*
 * SAS-2 10.4.3.8 REPORT ZONE MANAGER PASSWORD
 */
typedef enum smp_report_zmp_report_type {
	SMP_ZMP_TYPE_CURRENT		= 0x0,
	SMP_ZMP_TYPE_SAVED		= 0x2,
	SMP_ZMP_TYPE_DEFAULT		= 0x3
} smp_report_zmp_report_type_t;

typedef struct smp_report_zone_mgr_password_req {
	DECL_BITFIELD2(
	    srzmpr_rpt_type		:2,
	    _reserved1			:6);
	uint8_t _reserved2[2];
} smp_report_zone_mgr_password_req_t;

typedef struct smp_report_zone_mgr_password_resp {
	uint16_t srzmpr_exp_change_count;
	DECL_BITFIELD2(
	    srzmpr_rpt_type		:2,
	    _reserved1			:6);
	uint8_t _reserved2;
	uint8_t srzmpr_zone_mgr_password[32];
} smp_report_zone_mgr_password_resp_t;

/*
 * SAS-2 10.4.3.9 REPORT BROADCAST
 */
typedef struct smp_report_broadcast_req {
	DECL_BITFIELD2(
	    srbr_broadcast_type		:4,
	    _reserved1			:4);
	uint8_t _reserved2[3];
} smp_report_broadcast_req_t;

typedef enum smp_broadcast_type {
	SMP_BROADCAST_CHANGE		= 0x0,
	SMP_BROADCAST_RESERVED_CHANGE_0	= 0x1,
	SMP_BROADCAST_RESERVED_CHANGE_1	= 0x2,
	SMP_BROADCAST_SES		= 0x3,
	SMP_BROADCAST_EXPANDER		= 0x4,
	SMP_BROADCAST_ASYNC_EVENT	= 0x5,
	SMP_BROADCAST_RESERVED_3	= 0x6,
	SMP_BROADCAST_RESERVED_4	= 0x7,
	SMP_BROADCAST_ZONE_ACTIVATE	= 0x8
} smp_broadcast_type_t;

typedef struct smp_broadcast_descr {
	DECL_BITFIELD2(
	    sbd_broadcast_type		:4,
	    _reserved1			:4);
	uint8_t sbd_phy_identifier;
	DECL_BITFIELD2(
	    sbd_broadcast_reason	:4,
	    _reserved2			:4);
	uint16_t sbd_broadcast_count;
	uint8_t _reserved3[10];
} smp_broadcast_descr_t;

typedef struct smp_report_broadcast_resp {
	uint16_t srbr_exp_change_count;
	DECL_BITFIELD2(
	    srbr_broadcast_type		:4,
	    _reserved1			:4);
	uint8_t srbr_number_broadcast_descrs;
	smp_broadcast_descr_t srbr_descrs[1];
} smp_report_broadcast_resp_t;

/*
 * SAS-2 10.4.3.10 DISCOVER
 */
typedef struct smp_discover_req {
	uint8_t _reserved1[4];
	DECL_BITFIELD2(
	    sdr_ignore_zone_grp		:1,
	    _reserved2			:7);
	uint8_t sdr_phy_identifier;
	uint8_t _reserved3[2];
} smp_discover_req_t;

typedef struct smp_snw3_phy_cap {
	DECL_BITFIELD4(
	    sspc_requested_logical_link_rate	:4,	/* smp_link_rate_t */
	    _reserved1				:2,
	    sspc_tx_ssc_type			:1,
	    sspc_start				:1);
	DECL_BITFIELD7(
	    _reserved2				:2,
	    sspc_g3_ssc				:1,
	    sspc_g3_no_ssc			:1,
	    sspc_g2_ssc				:1,
	    sspc_g2_no_ssc			:1,
	    sspc_g1_ssc				:1,
	    sspc_g1_no_ssc			:1);
	uint8_t _reserved3;
	DECL_BITFIELD2(
	    sspc_parity		:1,
	    _reserved4		:7);
} smp_snw3_phy_cap_t;

typedef struct smp_discover_resp {
	uint16_t sdr_exp_change_count;
	uint8_t _reserved1[3];
	uint8_t sdr_phy_identifier;
	uint8_t _reserved2[2];
	DECL_BITFIELD3(
	    sdr_attached_reason		:4,
	    sdr_attached_device_type	:3,
	    _reserved3			:1);
	DECL_BITFIELD2(
	    sdr_negotiated_logical_link_rate	:4,	/* smp_link_rate_t */
	    _reserved4				:4);
	DECL_BITFIELD5(
	    sdr_attached_sata_host	:1,
	    sdr_attached_smp_initiator	:1,
	    sdr_attached_stp_initiator	:1,
	    sdr_attached_ssp_initiator	:1,
	    _reserved5			:4);
	DECL_BITFIELD6(
	    sdr_attached_sata_device		:1,
	    sdr_attached_smp_target		:1,
	    sdr_attached_stp_target		:1,
	    sdr_attached_ssp_target		:1,
	    _reserved6				:3,
	    sdr_attached_sata_port_selector	:1);
	uint64_t sdr_sas_addr;
	uint64_t sdr_attached_sas_addr;
	uint8_t sdr_attached_phy_identifier;
	DECL_BITFIELD4(
	    sdr_attached_break_reply_capable		:1,
	    sdr_attached_requested_inside_zpsds		:1,
	    sdr_attached_inside_zpsds_persistent	:1,
	    _reserved7					:5);
	uint8_t _reserved8[6];
	DECL_BITFIELD2(
	    sdr_hw_min_phys_link_rate	:4,	/* smp_link_rate_t */
	    sdr_prog_min_phys_link_rate	:4);	/* smp_link_rate_t */
	DECL_BITFIELD2(
	    sdr_hw_max_phys_link_rate	:4,	/* smp_link_rate_t */
	    sdr_prog_max_phys_link_rate	:4);	/* smp_link_rate_t */
	uint8_t sdr_phy_change_count;
	DECL_BITFIELD3(
	    sdr_partial_pwy_timeout	:4,
	    _reserved9			:3,
	    sdr_virtual_phy		:1);
	DECL_BITFIELD2(
	    sdr_routing_attr		:4,	/* smp_routing_attr_t */
	    _reserved10			:4);
	DECL_BITFIELD2(
	    sdr_connector_type		:7,
	    _reserved11			:1);
	uint8_t sdr_connector_element_index;
	uint8_t sdr_connector_physical_link;
	uint8_t _reserved12[2];
	uint8_t sdr_vendor[2];
	uint64_t sdr_attached_device_name;
	DECL_BITFIELD8(
	    sdr_zoning_enabled				:1,
	    sdr_inside_zpsds				:1,
	    sdr_zone_group_persistent			:1,
	    _reserved13					:1,
	    sdr_requested_inside_zpsds			:1,
	    sdr_inside_zpsds_persistent			:1,
	    sdr_requested_inside_zpsds_changed_by_exp	:1,
	    _reserved14					:1);
	uint8_t _reserved15[2];
	uint8_t sdr_zone_group;
	uint8_t sdr_self_config_status;
	uint8_t sdr_self_config_levels_completed;
	uint8_t _reserved16[2];
	uint64_t sdr_self_config_sas_addr;
	smp_snw3_phy_cap_t sdr_prog_phy_cap;
	smp_snw3_phy_cap_t sdr_current_phy_cap;
	smp_snw3_phy_cap_t sdr_attached_phy_cap;
	uint8_t _reserved17[6];
	DECL_BITFIELD2(
	    sdr_negotiated_phys_link_rate	:4,	/* smp_link_rate_t */
	    sdr_reason				:4);
	DECL_BITFIELD3(
	    sdr_hw_muxing_supported	:1,
	    sdr_negotiated_ssc		:1,
	    _reserved18			:6);
	DECL_BITFIELD7(
	    sdr_default_zoning_enabled		:1,
	    _reserved19				:1,
	    sdr_default_zone_group_persistent	:1,
	    _reserved20				:1,
	    sdr_default_requested_inside_zpsds	:1,
	    sdr_default_inside_zpsds_persistent	:1,
	    _reserved21				:2);
	uint8_t _reserved22[2];
	uint8_t sdr_default_zone_group;
	DECL_BITFIELD7(
	    sdr_saved_zoning_enabled		:1,
	    _reserved23				:1,
	    sdr_saved_zone_group_persistent	:1,
	    _reserved24				:1,
	    sdr_saved_requested_inside_zpsds	:1,
	    sdr_saved_inside_zpsds_persistent	:1,
	    _reserved25				:2);
	uint8_t _reserved26[2];
	uint8_t saved_zone_group;
	DECL_BITFIELD6(
	    _reserved27				:2,
	    sdr_shadow_zone_group_persistent	:1,
	    _reserved28				:1,
	    sdr_shadow_requested_inside_zpsds	:1,
	    sdr_shadow_inside_zpsds_persistent	:1,
	    _reserved29				:2);
	uint8_t _reserved30[2];
	uint8_t sdr_shadow_zone_group;
} smp_discover_resp_t;

typedef enum smp_link_rate {
	SMP_LINK_RATE_NO_CHANGE = 0x0,
	SMP_LINK_RATE_DISABLED = 0x1,
	SMP_LINK_RATE_RESET_PROBLEM = 0x2,
	SMP_LINK_RATE_SPINUP_HOLD = 0x3,
	SMP_LINK_RATE_PORT_SELECTOR = 0x4,
	SMP_LINK_RATE_RESET = 0x5,
	SMP_LINK_RATE_UNSUPPORTED = 0x6,
	SMP_LINK_RATE_1_5 = 0x8,
	SMP_LINK_RATE_3 = 0x9,
	SMP_LINK_RATE_6 = 0xA
} smp_link_rate_t;

typedef enum smp_device_type {
	SMP_DEV_NONE = 0x0,
	SMP_DEV_SAS_SATA = 0x1,
	SMP_DEV_EXPANDER = 0x2,
	SMP_DEV_EXPANDER_OLD = 0x3
} smp_device_type_t;

typedef enum smp_routing_attr {
	SMP_ROUTING_DIRECT = 0x0,
	SMP_ROUTING_SUBTRACTIVE = 0x1,
	SMP_ROUTING_TABLE = 0x2
} smp_routing_attr_t;

/*
 * SAS-2 10.4.3.11 REPORT PHY ERROR LOG
 */
typedef struct smp_report_phy_error_log_req {
	uint8_t _reserved1[5];
	uint8_t srpelr_phy_identifier;
	uint8_t _reserved2[2];
} smp_report_phy_error_log_req_t;

typedef struct smp_report_phy_error_log_resp {
	uint16_t srpelr_exp_change_count;
	uint8_t _reserved1[3];
	uint8_t srpelr_phy_identifier;
	uint8_t _reserved2[2];
	uint32_t srpelr_invalid_dword_count;
	uint32_t srpelr_running_disparity_error_count;
	uint32_t srpelr_loss_dword_sync_count;
	uint32_t srpelr_phy_reset_problem_count;
} smp_report_phy_error_log_resp_t;

/*
 * SAS-2 10.4.3.12 REPORT PHY SATA
 */
typedef struct smp_report_phy_sata_req {
	uint8_t _reserved1[5];
	uint8_t srpsr_phy_identifier;
	uint8_t srpsr_affiliation_context;
	uint8_t _reserved2;
} smp_report_phy_sata_req_t;

typedef struct smp_report_phy_sata_resp {
	uint16_t srpsr_exp_change_count;
	uint8_t _reserved1[3];
	uint8_t srpsr_phy_identifier;
	uint8_t _reserved2;
	DECL_BITFIELD4(
	    srpsr_affiliation_valid		:1,
	    srpsr_affiliations_supported	:1,
	    srpsr_stp_nexus_loss		:1,
	    _reserved3				:5);
	uint8_t _reserved4[4];
	uint64_t srpsr_stp_sas_addr;
	uint8_t srpsr_register_device_host_fis[20];
	uint8_t _reserved5[4];
	uint64_t srpsr_affiliated_stp_init_sas_addr;
	uint64_t srpsr_stp_nexus_loss_sas_addr;
	uint8_t _reserved6;
	uint8_t srpsr_affiliation_context;
	uint8_t srpsr_current_affiliation_contexts;
	uint8_t srpsr_max_affiliation_contexts;
} smp_report_phy_sata_resp_t;

/*
 * SAS-2 10.4.3.13 REPORT ROUTE INFORMATION
 */
typedef struct smp_report_route_info_req {
	uint8_t _reserved1[2];
	uint16_t srrir_exp_route_index;
	uint8_t _reserved2;
	uint8_t srrir_phy_identifier;
	uint8_t _reserved3[2];
} smp_report_route_info_req_t;

typedef struct smp_report_route_info_resp {
	uint16_t srrir_exp_change_count;
	uint16_t srrir_exp_route_index;
	uint8_t _reserved1;
	uint8_t srrir_phy_identifier;
	uint8_t _reserved2[2];
	DECL_BITFIELD2(
	    _reserved3				:7,
	    srrir_exp_route_entry_disabled	:1);
	uint8_t _reserved4[3];
	uint64_t srrir_routed_sas_addr;
	uint8_t _reserved5[16];
} smp_report_route_info_resp_t;

/*
 * SAS-2 10.4.3.14 SAS-2 REPORT PHY EVENT
 */
typedef enum smp_phy_event_source {
	SMP_PHY_EVENT_NO_EVENT				= 0x00,
	SMP_PHY_EVENT_INVALID_DWORD_COUNT		= 0x01,
	SMP_PHY_EVENT_RUNNING_DISPARITY_ERROR_COUNT	= 0x02,
	SMP_PHY_EVENT_LOSS_OF_DWORD_SYNC_COUNT		= 0x03,
	SMP_PHY_EVENT_PHY_RESET_PROBLEM_COUNT		= 0x04,
	SMP_PHY_EVENT_ELASTICITY_BUFFER_OVERFLOW_COUNT	= 0x05,
	SMP_PHY_EVENT_RX_ERROR_COUNT			= 0x06,
	SMP_PHY_EVENT_RX_ADDR_FRAME_ERROR_COUNT		= 0x20,
	SMP_PHY_EVENT_TX_ABANDON_CLASS_OPEN_REJ_COUNT	= 0x21,
	SMP_PHY_EVENT_RX_ABANDON_CLASS_OPEN_REJ_COUNT	= 0x22,
	SMP_PHY_EVENT_TX_RETRY_CLASS_OPEN_REJ_COUNT	= 0x23,
	SMP_PHY_EVENT_RX_RETRY_CLASS_OPEN_REJ_COUNT	= 0x24,
	SMP_PHY_EVENT_RX_AIP_W_O_PARTIAL_COUNT		= 0x25,
	SMP_PHY_EVENT_RX_AIP_W_O_CONN_COUNT		= 0x26,
	SMP_PHY_EVENT_TX_BREAK_COUNT			= 0x27,
	SMP_PHY_EVENT_RX_BREAK_COUNT			= 0x28,
	SMP_PHY_EVENT_BREAK_TIMEOUT_COUNT		= 0x29,
	SMP_PHY_EVENT_CONNECTION_COUNT			= 0x2A,
	SMP_PHY_EVENT_PEAK_TX_PATHWAY_BLOCKED_COUNT	= 0x2B,
	SMP_PHY_EVENT_PEAK_TX_ARB_WAIT_TIME		= 0x2C,
	SMP_PHY_EVENT_PEAK_ARB_TIME			= 0x2D,
	SMP_PHY_EVENT_PEAK_CONNECTION_TIME		= 0x2E,
	SMP_PHY_EVENT_TX_SSP_FRAME_COUNT		= 0x40,
	SMP_PHY_EVENT_RX_SSP_FRAME_COUNT		= 0x41,
	SMP_PHY_EVENT_TX_SSP_FRAME_ERROR_COUNT		= 0x42,
	SMP_PHY_EVENT_RX_SSP_FRAME_ERROR_COUNT		= 0x43,
	SMP_PHY_EVENT_TX_CREDIT_BLOCKED_COUNT		= 0x44,
	SMP_PHY_EVENT_RX_CREDIT_BLOCKED_COUNT		= 0x45,
	SMP_PHY_EVENT_TX_SATA_FRAME_COUNT		= 0x50,
	SMP_PHY_EVENT_RX_SATA_FRAME_COUNT		= 0x51,
	SMP_PHY_EVENT_SATA_FLOW_CTRL_BUF_OVERFLOW_COUNT	= 0x52,
	SMP_PHY_EVENT_TX_SMP_FRAME_COUNT		= 0x60,
	SMP_PHY_EVENT_RX_SMP_FRAME_COUNT		= 0x61,
	SMP_PHY_EVENT_RX_SMP_FRAME_ERROR_COUNT		= 0x63
} smp_phy_event_source_t;

typedef struct smp_report_phy_event_req {
	uint8_t _reserved1;
	uint8_t _reserved2[4];
	uint8_t srper_phy_identifier;
	uint8_t _reserved3[2];
} smp_report_phy_event_req_t;

typedef struct smp_phy_event_report_descr {
	uint8_t _reserved1[3];
	uint8_t sped_phy_event_source;
	uint32_t sped_phy_event;
	uint32_t sped_peak_detector_threshold;
} smp_phy_event_report_descr_t;

typedef struct smp_report_phy_event_resp {
	uint16_t srper_exp_change_count;
	uint8_t _reserved1[3];
	uint8_t srper_phy_identifier;
	uint8_t _reserved2[5];
	uint8_t srper_n_phy_event_descrs;
	smp_phy_event_report_descr_t srper_phy_event_descrs[1];
} smp_report_phy_event_resp_t;

/*
 * SAS-2 10.4.3.15 SAS-2 DISCOVER LIST
 */
typedef struct smp_discover_list_req {
	uint8_t _reserved1[4];
	uint8_t sdlr_starting_phy_identifier;
	uint8_t sdlr_max_descrs;
	DECL_BITFIELD3(
	    sdlr_phy_filter		:4,
	    _reserved2			:3,
	    sdlr_ignore_zone_group	:1);
	DECL_BITFIELD2(
	    sdlr_descr_type		:4,
	    _reserved3			:4);
	uint8_t _reserved4[4];
	uint8_t sdlr_vendor[12];
} smp_discover_list_req_t;

typedef struct smp_discover_short_descr {
	uint8_t sdsd_phy_identifier;
	uint8_t sdsd_function_result;
	DECL_BITFIELD3(
	    sdsd_attached_reason	:4,
	    sdsd_attached_device_type	:3,
	    _restricted1		:1);
	DECL_BITFIELD2(
	    sdsd_negotiated_logical_link_rate	:4,	/* smp_link_rate_t */
	    _restricted2			:4);
	DECL_BITFIELD5(
	    sdsd_attached_sata_host	:1,
	    sdsd_attached_smp_initiator	:1,
	    sdsd_attached_stp_initiator	:1,
	    sdsd_attached_ssp_initiator	:1,
	    _restricted3		:4);
	DECL_BITFIELD6(
	    sdsd_attached_sata_device		:1,
	    sdsd_attached_smp_target		:1,
	    sdsd_attached_stp_target		:1,
	    sdsd_attached_ssp_target		:1,
	    _restricted4			:3,
	    sdsd_attached_sata_port_selector	:1);
	DECL_BITFIELD3(
	    sdsd_routing_attribute	:4,		/* smp_routing_attr_t */
	    _reserved1			:3,
	    sdsd_virtual_phy		:1);
	DECL_BITFIELD2(
	    _reserved2			:4,
	    sdsd_reason			:4);
	uint8_t sdsd_zone_group;
	DECL_BITFIELD7(
	    _reserved3				:1,
	    sdsd_inside_zpsds			:1,
	    sdsd_zone_group_persistent		:1,
	    _reserved4				:1,
	    sdsd_requested_insize_zpsds		:1,
	    sdsd_inside_zpsds_persistent	:1,
	    _restricted5			:2);
	uint8_t sdsd_attached_phy_identifier;
	uint8_t sdsd_phy_change_count;
	uint64_t sdsd_attached_sas_addr;
	uint8_t _reserved5[4];
} smp_discover_short_descr_t;

typedef struct smp_discover_long_descr {
	uint8_t _reserved1[2];
	uint8_t sdld_function_result;
	uint8_t _reserved2[1];
	smp_discover_resp_t sdld_response;
} smp_discover_long_descr_t;

#define	SMP_DISCOVER_RESP(_ld)	\
	(((smp_discover_long_descr_t *)(_ld))->sdld_function_result ==	\
	SMP_FUNCTION_ACCEPTED ?	\
	&((smp_discover_long_descr_t *)(_ld))->sdld_response :	\
	NULL)

typedef struct smp_discover_list_resp {
	uint16_t sdlr_exp_change_count;
	uint8_t _reserved1[2];
	uint8_t sdlr_starting_phy_identifier;
	uint8_t sdlr_n_descrs;
	DECL_BITFIELD2(
	    sdlr_phy_filter		:4,
	    _reserved2			:4);
	DECL_BITFIELD2(
	    sdlr_descr_type		:4,
	    _reserved3			:4);
	uint8_t sdlr_descr_length;
	uint8_t _reserved4[3];
	DECL_BITFIELD5(
	    sdlr_externally_configurable_route_table	:1,
	    sdlr_configuring				:1,
	    _reserved5					:4,
	    sdlr_zoning_enabled				:1,
	    sdlr_zoning_supported			:1);
	uint8_t _reserved6;
	uint16_t sdlr_last_sc_status_descr_index;
	uint16_t sdlr_last_phy_event_list_descr_index;
	uint8_t _reserved7[10];
	uint8_t sdlr_vendor[16];
	uint8_t sdlr_descrs[1];	/* short or long format */
} smp_discover_list_resp_t;

/*
 * SAS-2 10.4.3.16 REPORT PHY EVENT LIST
 */
typedef struct smp_report_phy_event_list_req {
	uint8_t _reserved1[2];
	uint16_t srpelr_starting_descr_index;
} smp_report_phy_event_list_req_t;

typedef struct smp_phy_event_list_descr {
	uint8_t _reserved1[2];
	uint8_t speld_phy_identifier;
	uint8_t speld_phy_event_source;
	uint32_t speld_phy_event;
	uint32_t speld_peak_detector_threshold;
} smp_phy_event_list_descr_t;

typedef struct smp_report_phy_event_list_resp {
	uint16_t srpelr_exp_change_count;
	uint16_t srpelr_starting_descr_index;
	uint16_t srpelr_last_descr_index;
	uint8_t srpelr_phy_event_list_descr_length;
	uint8_t _reserved1[3];
	uint8_t srpelr_n_descrs;
	smp_phy_event_list_descr_t srpelr_descrs[1];
} smp_report_phy_event_list_resp_t;

/*
 * SAS-2 10.4.3.17 REPORT EXPANDER ROUTE TABLE LIST
 */
typedef struct smp_report_exp_route_table_list_req {
	uint8_t _reserved1[4];
	uint16_t srertlr_max_descrs;
	uint16_t srertlr_starting_routed_sas_addr_index;
	uint8_t _reserved2[7];
	uint8_t srertlr_starting_phy_identifier;
	uint8_t _reserved3[8];
} smp_report_exp_route_table_list_req_t;

typedef struct smp_route_table_descr {
	uint64_t srtd_routed_sas_addr;
	uint8_t srtd_phy_bitmap[6];
	DECL_BITFIELD2(
	    _reserved1			:7,
	    srtd_zone_group_valid	:1);
	uint8_t srtd_zone_group;
} smp_route_table_descr_t;

#define	SMP_ROUTE_PHY(_d, _s, _i)	\
	((_d)->srtd_phy_bitmap[(48 - (_i) + (_s)) >> 3] & \
	(1 << ((48 - (_i) + (_s)) & 7)))

typedef struct smp_report_exp_route_table_list_resp {
	uint16_t srertlr_exp_change_count;
	uint16_t srertlr_route_table_change_count;
	DECL_BITFIELD5(
	    srertlr_zoning_enabled	:1,
	    srertlr_configuring		:1,
	    srertlr_zone_configuring	:1,
	    srertlr_self_configuring	:1,
	    _reserved2			:4);
	uint8_t _reserved3;
	uint8_t srertlr_descr_length;
	uint8_t srertlr_n_descrs;
	uint16_t srertlr_first_routed_sas_addr_index;
	uint16_t srertlr_last_routed_sas_addr_index;
	uint8_t _reserved4[3];
	uint8_t srertlr_starting_phy_identifier;
	uint8_t _reserved5[12];
	smp_route_table_descr_t srertlr_descrs[1];
} smp_report_exp_route_table_list_resp_t;

/*
 * SAS-2 10.4.3.18 CONFIGURE GENERAL (no additional response)
 */
typedef struct smp_config_general_req {
	uint16_t scgr_expected_exp_change_count;
	uint8_t _reserved1[2];
	DECL_BITFIELD6(
	    scgr_update_stp_bus_inactivity			:1,
	    scgr_update_stp_max_conn				:1,
	    scgr_update_stp_smp_nexus_loss			:1,
	    scgr_update_initial_time_to_reduced_functionality	:1,
	    scgr_update_stp_reject_to_open			:1,
	    _reserved2						:3);
	uint8_t _reserved3;
	uint16_t scgr_stp_bus_inactivity;
	uint16_t scgr_stp_max_conn;
	uint16_t scgr_stp_smp_nexus_loss;
	uint8_t scgr_initial_time_to_reduced_functionality;
	uint8_t _reserved4;
	uint16_t scgr_stp_reject_to_open;
} smp_config_general_req_t;

/*
 * SAS-2 10.4.3.19 ENABLE DISABLE ZONING (no additional response)
 */
typedef struct smp_enable_disable_zoning_req {
	uint16_t sedzr_expected_exp_change_count;
	DECL_BITFIELD2(
	    sedzr_save	:2,		/* smp_zoning_save_t */
	    _reserved1	:6);
	uint8_t _reserved2;
	DECL_BITFIELD2(
	    sedzr_enable_disable_zoning	:2,
	    _reserved3			:6);
	uint8_t _reserved4[3];
} smp_enable_disable_zoning_req_t;

typedef enum smp_zoning_save {
	SMP_ZONING_SAVE_CURRENT = 0x0,
	SMP_ZONING_SAVE_SAVED = 0x1,
	SMP_ZONING_SAVE_BOTH_IF_SUPP = 0x2,
	SMP_ZONING_SAVE_BOTH = 0x3
} smp_zoning_save_t;

typedef enum smp_zoning_enable_op {
	SMP_ZONING_ENABLE_OP_NONE = 0x0,
	SMP_ZONING_ENABLE_OP_ENABLE = 0x1,
	SMP_ZONING_ENABLE_OP_DISABLE = 0x2
} smp_zoning_enable_op_t;

/*
 * SAS-2 10.4.3.20 ZONED BROADCAST (no additional response)
 */
typedef struct smp_zoned_broadcast_req {
	uint8_t _restricted1[2];
	DECL_BITFIELD2(
	    szbr_broadcast_type	:4,
	    _reserved		:4);
	uint8_t szbr_n_broadcast_source_zone_groups;
	uint8_t szbr_broadcast_source_zone_groups[1];
} smp_zoned_broadcast_req_t;

/*
 * SAS-2 10.4.3.21 ZONE LOCK
 */
typedef struct smp_zone_lock_req {
	uint16_t szlr_expected_exp_change_count;
	uint16_t szlr_zone_lock_inactivity_timeout;
	uint8_t szlr_zone_manager_password[32];
} smp_zone_lock_req_t;

typedef struct smp_zone_lock_resp {
	uint8_t _reserved1[4];
	uint64_t szlr_active_zone_manager_sas_addr;
} smp_zone_lock_resp_t;

/*
 * SAS-2 10.4.3.22 ZONE ACTIVATE (no additional response)
 */
typedef struct smp_zone_activate_req {
	uint16_t szar_expected_exp_change_count;
	uint8_t _reserved1[2];
} smp_zone_activate_req_t;

/*
 * SAS-2 10.4.3.23 ZONE UNLOCK (no additional response)
 */
typedef struct smp_zone_unlock_req {
	uint8_t _restricted1[2];
	DECL_BITFIELD2(
	    szur_activate_required	:1,
	    _reserved1			:7);
	uint8_t _reserved2;
} smp_zone_unlock_req_t;

/*
 * SAS-2 10.4.3.24 CONFIGURE ZONE MANAGER PASSWORD (no additional response)
 */
typedef struct smp_config_zone_manager_password_req {
	uint16_t sczmpr_expected_exp_change_count;
	DECL_BITFIELD2(
	    sczmpr_save		:2,		/* smp_zoning_save_t */
	    _reserved1		:6);
	uint8_t _reserved2;
	uint8_t sczmpr_zone_manager_password[32];
	uint8_t sczmpr_new_zone_manager_password[32];
} smp_config_zone_manager_password_req_t;

/*
 * SAS-2 10.4.3.25 CONFIGURE ZONE PHY INFORMATION (no additional response)
 */
typedef struct smp_zone_phy_config_descr {
	uint8_t szpcd_phy_identifier;
	DECL_BITFIELD6(
	    _reserved1				:2,
	    szpcd_zone_group_persistent		:1,
	    _reserved2				:1,
	    szpcd_requested_inside_zpsds	:1,
	    szpcd_inside_zpsds_persistent	:1,
	    _reserved3				:2);
	uint8_t _reserved4;
	uint8_t szpcd_zone_group;
} smp_zone_phy_config_descr_t;

typedef struct smp_config_zone_phy_info_req {
	uint16_t sczpir_expected_exp_change_count;
	DECL_BITFIELD2(
	    sczpir_save		:2,		/* smp_zoning_save_t */
	    _reserved1		:6);
	uint8_t sczpir_n_descrs;
	smp_zone_phy_config_descr_t sczpir_descrs[1];
} smp_config_zone_phy_info_req_t;

/*
 * SAS-2 10.4.3.26 CONFIGURE ZONE PERMISSION TABLE (no additional response)
 */
typedef struct smp_config_zone_perm_table_req {
	uint16_t sczptr_expected_exp_change_count;
	uint8_t sczptr_starting_source_zone_group;
	uint8_t sczptr_n_descrs;
	DECL_BITFIELD3(
	    sczptr_save			:2,	/* smp_zoning_save_t */
	    _reserved1			:4,
	    sczptr_n_zone_groups	:2);	/* smp_n_zone_grps_t */
	uint8_t _reserved2[7];
	uint8_t sczptr_descrs[1];	/* smp_zone_perm_descrXXX_t */
} smp_config_zone_perm_table_req_t;

/*
 * SAS-2 10.4.3.27 CONFIGURE ROUTE INFORMATION (no additional response)
 */
typedef struct smp_config_route_info_req {
	uint16_t scrir_expected_exp_change_count;
	uint16_t scrir_exp_route_index;
	uint8_t _reserved1;
	uint8_t scrir_phy_identifier;
	uint8_t _reserved2[2];
	DECL_BITFIELD2(
	    _reserved3				:7,
	    scrir_disable_exp_route_entry	:1);
	uint8_t _reserved4[3];
	uint64_t scrir_routed_sas_addr;
	uint8_t _reserved5[16];
} smp_config_route_info_req_t;

/*
 * SAS-2 10.4.3.28 PHY CONTROL (no additional response)
 */
typedef struct smp_phy_control_req {
	uint16_t spcr_expected_exp_change_count;
	uint8_t _reserved1[3];
	uint8_t spcr_phy_identifier;
	uint8_t spcr_phy_operation;
	DECL_BITFIELD2(
	    spcr_update_partial_pwy_timeout	:1,
	    _reserved2				:7);
	uint8_t _reserved3[12];
	uint64_t spcr_attached_device_name;
	DECL_BITFIELD2(
	    _reserved4				:4,
	    spcr_prog_min_phys_link_rate	:4);	/* smp_link_rate_t */
	DECL_BITFIELD2(
	    _reserved5				:4,
	    spcr_prog_max_phys_link_rate	:4);	/* smp_link_rate_t */
	uint8_t _reserved6[2];
	DECL_BITFIELD2(
	    spcr_partial_pwy_timeout	:4,
	    _reserved7			:4);
	uint8_t _reserved8[3];
} smp_phy_control_req_t;

typedef enum smp_phy_op {
	SMP_PHY_OP_NOP = 0x00,
	SMP_PHY_OP_LINK_RESET = 0x01,
	SMP_PHY_OP_HARD_RESET = 0x02,
	SMP_PHY_OP_DISABLE = 0x03,
	SMP_PHY_OP_CLEAR_ERROR_LOG = 0x05,
	SMP_PHY_OP_CLEAR_AFFILIATION = 0x06,
	SMP_PHY_OP_TRANSMIT_SATA_PORT_SELECTION_SIGNAL = 0x07,
	SMP_PHY_OP_CLEAR_STP_NEXUS_LOSS = 0x08,
	SMP_PHY_OP_SET_ATTACHED_DEVICE_NAME = 0x09
} smp_phy_op_t;

/*
 * SAS-2 10.4.3.29 PHY TEST FUNCTION (no additional response)
 */
typedef struct smp_phy_test_function_req {
	uint16_t sptfr_expected_exp_change_count;
	uint8_t _reserved1[3];
	uint8_t sptfr_phy_identifier;
	uint8_t sptfr_phy_test_function;
	uint8_t sptfr_phy_test_pattern;		/* smp_phy_test_function_t */
	uint8_t _reserved2[3];
	DECL_BITFIELD4(
	    sptfr_test_pattern_phys_link_rate	:4,	/* smp_link_rate_t */
	    sptfr_test_pattern_ssc		:2,
	    sptfr_test_pattern_sata		:1,
	    _reserved3				:1);
	uint8_t _reserved4[3];
	uint8_t sptfr_phy_test_pattern_dwords_ctl;
	uint8_t sptfr_phy_test_pattern_dwords[8];
	uint8_t _reserved5[12];
} smp_phy_test_function_req_t;

typedef enum smp_phy_test_function {
	SMP_PHY_TEST_FN_STOP = 0x00,
	SMP_PHY_TEST_FN_TRANSMIT_PATTERN = 0x01
} smp_phy_test_function_t;

/*
 * SAS-2 10.4.3.30 CONFIGURE PHY EVENT (no additional response)
 */
typedef struct smp_phy_event_config_descr {
	uint8_t _reserved1[3];
	uint8_t specd_phy_event_source;
	uint32_t specd_peak_value_detector_threshold;
} smp_phy_event_config_descr_t;

typedef struct smp_config_phy_event_req {
	uint16_t scper_expected_exp_change_count;
	DECL_BITFIELD2(
	    scper_clear_peaks	:1,
	    _reserved1		:7);
	uint8_t _reserved2[2];
	uint8_t scper_phy_identifier;
	uint8_t _reserved3;
	uint8_t scper_n_descrs;
	smp_phy_event_config_descr_t scper_descrs[1];
} smp_config_phy_event_req_t;

#pragma	pack()

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_GENERIC_SMP_FRAMES_H */
