/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _EMLXS_MENLO_H
#define	_EMLXS_MENLO_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef MENLO_SUPPORT

/*
 * COMMANDS
 */

typedef struct menlo_init_cmd
{
	uint32_t code;		/* Command code = MENLO_CMD_INITIALIZE */
	uint32_t bb_credit;	/* Menlo FC BB Credit */
	uint32_t frame_size;	/* Menlo FC receive frame size */

} menlo_init_cmd_t;


typedef struct menlo_fw_download_cmd
{
	uint32_t code;		/* Command code = MENLO_CMD_FW_DOWNLOAD */
	uint32_t length;	/* Firmware image length in bytes */
				/* (4 byte aligned) */
	uint32_t type;		/* Firmware image type */

#define	MENLO_IMAGE_TYPE_OP			1
#define	MENLO_IMAGE_TYPE_DIAG			2

/* Followed by length bytes of firmware image */
/* Firmware image will be in Little Endian format */

} menlo_fw_download_cmd_t;


typedef struct menlo_memory_cmd
{
	uint32_t code; 		/* Command code */
	uint32_t address;	/* Menlo memory address */
	uint32_t length;	/* Number of words */

} menlo_memory_cmd_t;


typedef struct menlo_fte_insert_cmd
{
	uint32_t code;		/* Command code = MENLO_CMD_FTE_INSERT */
	uint32_t mask;		/* mask = True or False */

#define	MENLO_SRC_MASK_FALSE	0
#define	MENLO_SRC_MASK_TRUE		1

	uint32_t fcid;		/* FCID of remote port */
	uint8_t wwpn[8];	/* WWPN of remote port */

} menlo_fte_insert_cmd_t;


typedef struct menlo_fte_delete_cmd
{
	uint32_t code;		/* Command code = MENLO_CMD_FTE_DELETE */
	uint32_t fcid;		/* FCID of remote port */
	uint8_t wwpn[8];	/* WWPN of remote port */

} menlo_fte_delete_cmd_t;


typedef struct menlo_get_cmd
{
	uint32_t code;		/* Command code */
	uint32_t context;	/* Context */

/* MENLO_CMD_GET_PORT_STATS */
#define	MENLO_PORT_ETH0		0
#define	MENLO_PORT_ETH1		1
#define	MENLO_PORT_NSL0		2
#define	MENLO_PORT_NSL1		3
#define	MENLO_PORT_FC0		4
#define	MENLO_PORT_FC1		5

/* MENLO_CMD_GET_LIF_STATS */
#define	MENLO_LIF_ETH0	0
#define	MENLO_LIF_ETH1	1
#define	MENLO_LIF_FC0	2
#define	MENLO_LIF_FC1	3

/* MENLO_CMD_GET_LB_MODE */
#define	MENLO_NSL_PORT_ID_0			0
#define	MENLO_NSL_PORT_ID_1			1

	uint32_t length;	/* Max response length */

} menlo_get_cmd_t;


typedef struct menlo_set_cmd
{
	uint32_t code; 		/* Command code = MENLO_CMD_SET_PAUSE */
	uint32_t value1;	/* value1 */
	uint32_t value2;	/* value2 */

/* MENLO_CMD_SET_PAUSE values */
#define	MENLO_PAUSE_TYPE_SP				1
#define	MENLO_PAUSE_TYPE_PPP			2

/* PPP Priority bits	:  [ ][ ][ ][ ][X][ ][ ][ ] */
/*		COS	:   7  6  5  4  3  2  1  0  */
#define	MENLO_PPP_COS0				0x01
#define	MENLO_PPP_COS1				0x02
#define	MENLO_PPP_COS2				0x04
#define	MENLO_PPP_COS3				0x08
#define	MENLO_PPP_COS4				0x10
#define	MENLO_PPP_COS5				0x20
#define	MENLO_PPP_COS6				0x40
#define	MENLO_PPP_COS7				0x80

/* MENLO_CMD_SET_FCOE_COS values */
#define	MENLO_FCOE_COS				3

/* MENLO_CMD_SET_UIF_PORT_TYPE values */
#define	MENLO_PORT_TYPE_ACCESS			1
#define	MENLO_PORT_TYPE_TRUNK			2

/* MENLO_CMD_SET_MODE values */
#define	MENLO_MAINTENANCE_MODE_DISABLE		0
#define	MENLO_MAINTENANCE_MODE_ENABLE		1

} menlo_set_cmd_t;


typedef struct menlo_loopback_cmd
{
	uint32_t code; 		/* Command code = MENLO_CMD_LOOPBACK */
	uint32_t context;	/* context = NSL port 0 or 1 */

#define	MENLO_NSL_PORT_ID_0			0
#define	MENLO_NSL_PORT_ID_1			1

	uint32_t type;		/* type  = loopback mode enable or disable */

#define	MENLO_LOOPBACK_DISABLE		0
#define	MENLO_LOOPBACK_ENABLE		1

} menlo_loopback_cmd_t;


typedef struct menlo_reset_cmd
{
	uint32_t code; 		/* Command code = MENLO_CMD_RESET */
	uint32_t firmware;

#define	MENLO_FW_OPERATIONAL		0
#define	MENLO_FW_GOLDEN				1

} menlo_reset_cmd_t;

typedef struct menlo_fru_data_cmd
{
	uint32_t code;		/* Response code */
	uint8_t mac0[8];	/* MAC address of port 0 */
	uint8_t mac1[8];	/* MAC address of port 1 */
	uint32_t flags;

/* Valid flags */
#define	MENLO_FLAG_SINGLE_CHANNEL	0x00000001
#define	MENLO_FLAG_DUAL_CHANNEL		0x00000002

} menlo_fru_data_cmd_t;


typedef struct menlo_diag_cmd
{
	uint32_t code;		/* Response code */
	uint32_t loop_count;	/* loop_count = 0 indicates loop forever */
				/* loop_count > 0 indicates number of test */
				/* iterations */
				/* NOTE : one test iteration takes */
				/* approximately 2-3 seconds */
	uint32_t test_bitmap;   /* Each bit represents a separate test to be */
				/* performed */
				/* test_bitmap = 0 will result in a */
				/* MENLO_ERR_INVALID_FLAG error */
} menlo_diag_cmd_t;


/* Hornet 2 */

#define	MAX_SUPPORTED_VLANS	4

typedef struct fip_params
{
	uint8_t sw_name[8]; /* Switch name */
	uint8_t fabric_name[8]; /* Fabric name */
	uint8_t sup_addr_mode;  /* Support addressing modes */

/* FCoE Addressing Mode */
#define	SPMA_ADDR_MODE	1
#define	FPMA_ADDR_MODE	2

	uint8_t	 pref_addr_mode; /* Preferred addressing modes */
	uint16_t fcf_disc_tov;   /* Discovery tmo period (multiple 500ms) */
	uint16_t vlan_id[MAX_SUPPORTED_VLANS]; /* VLAN list */

} fip_params_t;

typedef struct non_fip_params
{
	uint32_t fc_map;  /* Configured FC_MAP */

} non_fip_params_t;

typedef union menlo_fcoe_params
{
	fip_params_t fip;		/* FIP specific parameters */
	non_fip_params_t non_fip;	/* Non-FIP specific parameters */
} menlo_fcoe_params_t;

typedef struct menlo_set_fcoe_params_cmd
{
	uint32_t code; /* Command code=MENLO_CMD_SET_FCOE_PARAMS */
	uint32_t fcoe_mode; /* FIP or Non-FIP */

/* FCoE Operation Mode */
#define	FCOE_MODE_NON_FIP	0
#define	FCOE_MODE_FIP		1

	uint32_t lport_id; /* Logical port identification */
	menlo_fcoe_params_t params; /* Specific FCoE parameters */

} menlo_set_fcoe_params_cmd_t;


typedef	struct set_facl_cmd
{
	uint32_t code;  /* Command code = MENLO_CMD_SET_FACL */
	uint32_t lport_id; /* Logical port identification */
	uint32_t num_acls; /* Number of ACL entries */
	uint32_t facl_list; /* List of returned Fabric ACL, facl_t */
} set_facl_cmd_t;

typedef	struct facl
{
	uint8_t fabric_name[8]; /* Fabric name */
	uint8_t sw_name[8];  /* Switch name */
	uint32_t acc_ctrl;  /* PERMIT or DENY */
} facl_t;

typedef	struct fcf_id
{
	uint8_t sw_name[8];  /* Switch name */
	uint8_t fabric_name[8];	 /* Fabric name */

} fcf_id_t;

typedef	struct create_vl_cmd
{
	uint32_t code;  /* Command code = MENLO_CMD_CREATE_VL */
	uint32_t lport_id; /* Logical port identification */
	fcf_id_t fcf;  /* Specific FCF */

} create_vl_cmd_t;

typedef struct delete_vl_cmd
{
	uint32_t code;  /* Command code = MENLO_CMD_CREATE_VL */
	uint32_t vl_handle; /* Handle of created VL */

} delete_vl_cmd_t;

#define	MAX_GROUPS 8 /* Max supported by hardware */

typedef struct menlo_pg_info
{
	uint32_t num_pg;    /* Number of PGs specified */
	uint8_t pg_ids[MAX_GROUPS]; /* PG membership bitmaps */
	uint8_t pg_bw[MAX_GROUPS]; /* BW for each PG in 10% gran. */

} menlo_pg_info_t;

typedef struct menlo_set_pg_info_cmd
{
	uint32_t  code;  /* Command code = MENLO_CMD_SET_PG */
	menlo_pg_info_t pg_info; /* PG information */

} menlo_set_pg_info_cmd_t;


typedef struct menlo_set_host_eth_pfc_flag
{
	uint32_t code; /* Command code=MENLO_CMD_SET_HOST_ETH_PFC_FLAG */
	uint32_t host_pfc_enable; /* 1 = PFC on Host if enabled */

/* Host PFC Flag Definitions */
#define	MENLO_HOST_PFC_DISABLE	0x0
#define	MENLO_HOST_PFC_ENABLE	0x1

} menlo_set_host_eth_pfc_flag_t;



typedef union menlo_cmd
{
	uint32_t			word[5];
	uint32_t			code; 		/* Command code */

/* Command codes */
#define	MENLO_CMD_INITIALIZE		0x00000001
#define	MENLO_CMD_FW_DOWNLOAD		0x00000002
#define	MENLO_CMD_READ_MEMORY		0x00000003
#define	MENLO_CMD_WRITE_MEMORY		0x00000004
#define	MENLO_CMD_FTE_INSERT		0x00000005
#define	MENLO_CMD_FTE_DELETE		0x00000006

#define	MENLO_CMD_GET_INIT 		0x00000007
#define	MENLO_CMD_GET_CONFIG		0x00000008
#define	MENLO_CMD_GET_PORT_STATS	0x00000009
#define	MENLO_CMD_GET_LIF_STATS		0x0000000A
#define	MENLO_CMD_GET_ASIC_STATS	0x0000000B
#define	MENLO_CMD_GET_LOG_CONFIG	0x0000000C
#define	MENLO_CMD_GET_LOG_DATA		0x0000000D
#define	MENLO_CMD_GET_PANIC_LOG		0x0000000E
#define	MENLO_CMD_GET_LB_MODE		0x0000000F

#define	MENLO_CMD_SET_PAUSE		0x00000010
#define	MENLO_CMD_SET_FCOE_COS		0x00000011
#define	MENLO_CMD_SET_UIF_PORT_TYPE	0x00000012

#define	MENLO_CMD_DIAGNOSTICS		0x00000013
#define	MENLO_CMD_LOOPBACK		0x00000014
#define	MENLO_CMD_GET_FTABLE		0x00000015
#define	MENLO_CMD_GET_SFP_DATA		0x00000016
#define	MENLO_CMD_SET_FRU_DATA		0x00000017
#define	MENLO_CMD_GET_FRU_DATA		0x00000018
#define	MENLO_CMD_SET_FCOE_FORMAT	0x00000019
#define	MENLO_CMD_GET_DIAG_LOG		0x00000020
#define	MENLO_CMD_PANIC			0x00000021
#define	MENLO_CMD_SET_FCOE_PARAMS	0x00000022
#define	MENLO_CMD_GET_FCOE_PARAMS	0x00000023
#define	MENLO_CMD_GET_FCF_LIST		0x00000024
#define	MENLO_CMD_SET_FACL		0x00000025
#define	MENLO_CMD_GET_FACL		0x00000026
#define	MENLO_CMD_CREATE_VL		0x00000027
#define	MENLO_CMD_DELETE_VL		0x00000028
#define	MENLO_CMD_SET_PG		0x00000029
#define	MENLO_CMD_GET_PG		0x0000002A
#define	MENLO_CMD_SET_HOST_ETH_PFC_FLAG	0x0000002B
#define	MENLO_CMD_GET_HOST_ETH_PFC_FLAG	0x0000002C
#define	MENLO_CMD_GET_DCBX_MODE		0x0000002D


/* Zephyr specific Menlo commands */
#define	MENLO_CMD_RESET			0x80000001
#define	MENLO_CMD_SET_MODE		0x80000002

	menlo_init_cmd_t		init;
	menlo_fw_download_cmd_t		fw;
	menlo_memory_cmd_t		mem;
	menlo_fte_insert_cmd_t		fte_insert;
	menlo_fte_delete_cmd_t		fte_delete;
	menlo_get_cmd_t			get;
	menlo_set_cmd_t			set;
	menlo_loopback_cmd_t		lb;
	menlo_reset_cmd_t		reset;
	menlo_fru_data_cmd_t		fru;
	menlo_diag_cmd_t		diag;
	menlo_set_host_eth_pfc_flag_t	pfc;
} menlo_cmd_t;


/*
 * RESPONSES
 */

typedef struct menlo_init_rsp
{
	uint32_t code;
	uint32_t bb_credit;	/* Menlo FC BB Credit */
	uint32_t frame_size;	/* Menlo FC receive frame size */
	uint32_t fw_version;	/* Menlo firmware version   */
	uint32_t reset_status;	/* Reason for previous reset */

#define	MENLO_RESET_STATUS_NORMAL		0
#define	MENLO_RESET_STATUS_PANIC		1

	uint32_t maint_status;	/* Menlo Maintenance Mode status at link up */

#define	MENLO_MAINTENANCE_MODE_DISABLE	0
#define	MENLO_MAINTENANCE_MODE_ENABLE	1

	uint32_t fw_type;

#define	MENLO_FW_TYPE_OPERATIONAL	0xABCD0001
#define	MENLO_FW_TYPE_GOLDEN		0xABCD0002
#define	MENLO_FW_TYPE_DIAG		0xABCD0003

	uint32_t fru_data_valid;  /* 0=invalid, 1=valid */
} menlo_init_rsp_t;


#define	MENLO_MAX_FC_PORTS		2
#define	MENLO_MAX_UIF_PORTS		2

typedef struct menlo_get_config_rsp
{
	uint32_t code;

	uint32_t pause_type[MENLO_MAX_UIF_PORTS];
	uint32_t priority[MENLO_MAX_UIF_PORTS];
	uint32_t fcoe_cos[MENLO_MAX_FC_PORTS];
	uint32_t uif_port_type[MENLO_MAX_UIF_PORTS];

	uint32_t log_cfg_size;		/* Size of log config region. */
					/* Needed for */
					/* MENLO_CMD_GET_LOG_CONFIG */
	uint32_t panic_log_size;	/* Size of panic log region. */
					/* Needed for MENLO_CMD_GET_PANIC_LOG */

	uint32_t dcx_present[MENLO_MAX_UIF_PORTS];

	uint32_t current_pause_type[MENLO_MAX_UIF_PORTS];
	uint32_t current_priority[MENLO_MAX_UIF_PORTS];
	uint32_t current_fcoe_cos[MENLO_MAX_FC_PORTS];
	uint32_t current_uif_port_type[MENLO_MAX_UIF_PORTS];

	uint32_t fcoe_format;		/* Bit field - single bit will be set */
					/* (See below) */
	uint32_t current_fcoe_format;	/* Bit field - single bit will be set */
					/*  (See below) */
	uint32_t supported_fcoe_format;	/* Bit field - multiple bits may be */
					/* set (See below) */

#define	FCOE_FRAME_FORMAT_P0		0x00010000 /* Pre-T11 format */
#define	FCOE_FRAME_FORMAT_T0		0x00000001 /* T11 format Rev 0 */
#define	FCOE_FRAME_FORMAT_T1		0x00000002
#define	FCOE_FRAME_FORMAT_T2		0x00000004
#define	FCOE_FRAME_FORMAT_T3		0x00000008
#define	FCOE_FRAME_FORMAT_T4		0x00000010
#define	FCOE_FRAME_FORMAT_T5		0x00000020
#define	FCOE_FRAME_FORMAT_T6		0x00000040
#define	FCOE_FRAME_FORMAT_T7		0x00000080
#define	FCOE_FRAME_FORMAT_T8		0x00000100
#define	FCOE_FRAME_FORMAT_T9		0x00000200
#define	FCOE_FRAME_FORMAT_T10		0x00000400
#define	FCOE_FRAME_FORMAT_T11		0x00000800
#define	FCOE_FRAME_FORMAT_T12		0x00001000
#define	FCOE_FRAME_FORMAT_T13		0x00002000
#define	FCOE_FRAME_FORMAT_T14		0x00004000
#define	FCOE_FRAME_FORMAT_T15		0x00008000
} menlo_get_config_rsp_t;


typedef struct menlo_fc_stats_rsp
{
	uint32_t code;

	uint64_t rx_class_2_frames;
	uint64_t rx_class_3_frames;
	uint64_t rx_class_F_frames;
	uint64_t rx_class_other_frames;

	uint64_t tx_class_2_frames;
	uint64_t tx_class_3_frames;
	uint64_t tx_class_F_frames;
	uint64_t tx_class_other_frames;

	uint64_t rx_class_2_words;
	uint64_t rx_class_3_words;
	uint64_t rx_class_F_words;
	uint64_t rx_class_other_words;

	uint64_t tx_class_2_words;
	uint64_t tx_class_3_words;
	uint64_t tx_class_F_words;
	uint64_t tx_class_other_words;

	uint64_t rx_class_2_frames_bad;
	uint64_t rx_class_3_frames_bad;
	uint64_t rx_class_F_frames_bad;
	uint64_t rx_class_other_frames_bad;

	uint64_t tx_class_2_frames_bad;
	uint64_t tx_class_3_frames_bad;
	uint64_t tx_class_F_frames_bad;
	uint64_t tx_class_other_frames_bad;
} menlo_fc_stats_rsp_t;


typedef struct menlo_network_stats_rsp
{
	uint32_t code;

	uint64_t tx_pkt_lt64;
	uint64_t tx_pkt_64;
	uint64_t tx_pkt_65;
	uint64_t tx_pkt_128;
	uint64_t tx_pkt_256;
	uint64_t tx_pkt_512;
	uint64_t tx_pkt_1024;
	uint64_t tx_pkt_1519;
	uint64_t tx_pkt_2048;
	uint64_t tx_pkt_4096;
	uint64_t tx_pkt_8192;
	uint64_t tx_pkt_gt9216;
	uint64_t tx_pkt_total;
	uint64_t tx_octet_sok;
	uint64_t tx_pkt_ok;
	uint64_t tx_ucast;
	uint64_t tx_mcast;
	uint64_t tx_bcast;
	uint64_t tx_vlan;
	uint64_t tx_pause;
	uint64_t tx_priority_pause;
	uint64_t tx_frame_error;

	uint64_t rx_pkt_lt64;
	uint64_t rx_pkt_64;
	uint64_t rx_pkt_65;
	uint64_t rx_pkt_128;
	uint64_t rx_pkt_256;
	uint64_t rx_pkt_512;
	uint64_t rx_pkt_1024;
	uint64_t rx_pkt_1519;
	uint64_t rx_pkt_2048;
	uint64_t rx_pkt_4096;
	uint64_t rx_pkt_8192;
	uint64_t rx_pkt_gt9216;
	uint64_t rx_pkt_total;
	uint64_t rx_octet_sok;
	uint64_t rx_pkt_ok;
	uint64_t rx_ucast;
	uint64_t rx_mcast;
	uint64_t rx_bcast;
	uint64_t rx_vlan;
	uint64_t rx_oversize;
	uint64_t rx_toolong;
	uint64_t rx_discard;
	uint64_t rx_undersize;
	uint64_t rx_fragment;
	uint64_t rx_crc_err;
	uint64_t rx_inrange_err;
	uint64_t rx_jabber;
	uint64_t rx_pause;
	uint64_t rx_priority_pause;
} menlo_network_stats_rsp_t;


typedef struct menlo_lif_stats_rsp
{
	uint32_t code;

	uint64_t eg_pkt_count;
	uint64_t ig_pkt_count;

	uint64_t eg_byte_count;
	uint64_t ig_byte_count;

	uint64_t eg_error_count;
	uint64_t ig_error_count;

	uint64_t eg_drop_count;
	uint64_t ig_drop_count;
} menlo_lif_stats_rsp_t;


typedef struct menlo_asic_stats_rsp
{
	uint32_t code;

	uint64_t eq_cputx0_cecount;
	uint64_t eq_cputx0_dropacl;
	uint64_t eq_cputx0_dropovr;
	uint64_t eq_cputx0_droprunt;
	uint64_t eq_cputx0_poperr;
	uint64_t eq_cputx0_pusherr;
	uint64_t eq_cputx0_truncovr;
	uint64_t eq_cputx0_uecount;

	uint64_t eq_cputx1_cecount;
	uint64_t eq_cputx1_dropacl;
	uint64_t eq_cputx1_dropovr;
	uint64_t eq_cputx1_droprunt;
	uint64_t eq_cputx1_poperr;
	uint64_t eq_cputx1_pusherr;
	uint64_t eq_cputx1_truncovr;
	uint64_t eq_cputx1_uecount;

	uint64_t eq_eth0_dropovr;
	uint64_t eq_eth0_droprunt;
	uint64_t eq_eth0_truncovr;

	uint64_t eq_eth0a_cecount;
	uint64_t eq_eth0a_dropacl;
	uint64_t eq_eth0a_poperr;
	uint64_t eq_eth0a_pusherr;
	uint64_t eq_eth0a_uecount;

	uint64_t eq_eth0b_cecount;
	uint64_t eq_eth0b_dropacl;
	uint64_t eq_eth0b_poperr;
	uint64_t eq_eth0b_pusherr;
	uint64_t eq_eth0b_uecount;

	uint64_t eq_eth1_dropovr;
	uint64_t eq_eth1_droprunt;
	uint64_t eq_eth1_truncovr;

	uint64_t eq_eth1a_cecount;
	uint64_t eq_eth1a_dropacl;
	uint64_t eq_eth1a_poperr;
	uint64_t eq_eth1a_pusherr;
	uint64_t eq_eth1a_uecount;

	uint64_t eq_eth1b_cecount;
	uint64_t eq_eth1b_dropacl;
	uint64_t eq_eth1b_poperr;
	uint64_t eq_eth1b_pusherr;
	uint64_t eq_eth1b_uecount;

	uint64_t eq_fc0_cecount;
	uint64_t eq_fc0_dropacl;
	uint64_t eq_fc0_dropovr;
	uint64_t eq_fc0_droprunt;
	uint64_t eq_fc0_poperr;
	uint64_t eq_fc0_pusherr;
	uint64_t eq_fc0_truncovr;
	uint64_t eq_fc0_uecount;

	uint64_t eq_fc1_cecount;
	uint64_t eq_fc1_dropacl;
	uint64_t eq_fc1_dropovr;
	uint64_t eq_fc1_droprunt;
	uint64_t eq_fc1_poperr;
	uint64_t eq_fc1_pusherr;
	uint64_t eq_fc1_truncovr;
	uint64_t eq_fc1_uecount;

	uint64_t eq_fl_cecount;
	uint64_t eq_fl_uecount;

	uint64_t eq_pkt_buf_cecount;
	uint64_t eq_pkt_buf_uecount;

	uint64_t iq_cpurx0_cecount;
	uint64_t iq_cpurx0_n0_dropovr;
	uint64_t iq_cpurx0_n0_truncovr;
	uint64_t iq_cpurx0_n1_dropovr;
	uint64_t iq_cpurx0_n1_truncovr;
	uint64_t iq_cpurx0_poperr;
	uint64_t iq_cpurx0_pusherr;
	uint64_t iq_cpurx0_uecount;

	uint64_t iq_cpurx1_cecount;
	uint64_t iq_cpurx1_n0_dropovr;
	uint64_t iq_cpurx1_n0_truncovr;
	uint64_t iq_cpurx1_n1_dropovr;
	uint64_t iq_cpurx1_n1_truncovr;
	uint64_t iq_cpurx1_poperr;
	uint64_t iq_cpurx1_pusherr;
	uint64_t iq_cpurx1_uecount;

	uint64_t iq_cputx_cecount;
	uint64_t iq_cputx_dropovr;
	uint64_t iq_cputx_droprunt;
	uint64_t iq_cputx_poperr;
	uint64_t iq_cputx_pusherr;
	uint64_t iq_cputx_truncovr;
	uint64_t iq_cputx_uecount;

	uint64_t iq_eth0a_cecount;
	uint64_t iq_eth0a_n0_dropovr;
	uint64_t iq_eth0a_n0_truncovr;
	uint64_t iq_eth0a_n1_dropovr;
	uint64_t iq_eth0a_n1_truncovr;
	uint64_t iq_eth0a_poperr;
	uint64_t iq_eth0a_pusherr;
	uint64_t iq_eth0a_uecount;

	uint64_t iq_eth0b_cecount;
	uint64_t iq_eth0b_n0_dropovr;
	uint64_t iq_eth0b_n0_truncovr;
	uint64_t iq_eth0b_n1_dropovr;
	uint64_t iq_eth0b_n1_truncovr;
	uint64_t iq_eth0b_poperr;
	uint64_t iq_eth0b_pusherr;
	uint64_t iq_eth0b_uecount;

	uint64_t iq_eth1a_cecount;
	uint64_t iq_eth1a_n0_dropovr;
	uint64_t iq_eth1a_n0_truncovr;
	uint64_t iq_eth1a_n1_dropovr;
	uint64_t iq_eth1a_n1_truncovr;
	uint64_t iq_eth1a_poperr;
	uint64_t iq_eth1a_pusherr;
	uint64_t iq_eth1a_uecount;

	uint64_t iq_eth1b_cecount;
	uint64_t iq_eth1b_n0_dropovr;
	uint64_t iq_eth1b_n0_truncovr;
	uint64_t iq_eth1b_n1_dropovr;
	uint64_t iq_eth1b_n1_truncovr;
	uint64_t iq_eth1b_poperr;
	uint64_t iq_eth1b_pusherr;
	uint64_t iq_eth1b_uecount;

	uint64_t iq_fc0_cecount;
	uint64_t iq_fc0_n0_dropovr;
	uint64_t iq_fc0_n0_truncovr;
	uint64_t iq_fc0_n1_dropovr;
	uint64_t iq_fc0_n1_truncovr;
	uint64_t iq_fc0_poperr;
	uint64_t iq_fc0_pusherr;
	uint64_t iq_fc0_uecount;

	uint64_t iq_fc1_cecount;
	uint64_t iq_fc1_n0_dropovr;
	uint64_t iq_fc1_n0_truncovr;
	uint64_t iq_fc1_n1_dropovr;
	uint64_t iq_fc1_n1_truncovr;
	uint64_t iq_fc1_poperr;
	uint64_t iq_fc1_pusherr;
	uint64_t iq_fc1_uecount;

	uint64_t iq_fl_cecount;
	uint64_t iq_fl_uecount;

	uint64_t iq_n0_cecount;
	uint64_t iq_n0_dropacl;
	uint64_t iq_n0_dropovr;
	uint64_t iq_n0_droprunt;
	uint64_t iq_n0_poperr;
	uint64_t iq_n0_pusherr;
	uint64_t iq_n0_truncovr;
	uint64_t iq_n0_uecount;

	uint64_t iq_n1_cecount;
	uint64_t iq_n1_dropacl;
	uint64_t iq_n1_dropovr;
	uint64_t iq_n1_droprunt;
	uint64_t iq_n1_poperr;
	uint64_t iq_n1_pusherr;
	uint64_t iq_n1_truncovr;
	uint64_t iq_n1_uecount;

	uint64_t iq_pkt_buf_cecount;
	uint64_t iq_pkt_buf_uecount;

	uint64_t iq_rc_cecount;
	uint64_t iq_rc_uecount;

	uint64_t misc_mmem_cecount;
	uint64_t misc_mmem_uecount;

	uint64_t net_eg0_learn_req_drop;
	uint64_t net_eg0_pkt_drop_cmd;
	uint64_t net_eg0_pkt_drop_lifcfg_invalid;
	uint64_t net_eg0_pkt_drop_lifmap_no_hit;
	uint64_t net_eg0_pkt_drop_src_bind;

	uint64_t net_eg1_learn_req_drop;
	uint64_t net_eg1_pkt_drop_cmd;
	uint64_t net_eg1_pkt_drop_lifcfg_invalid;
	uint64_t net_eg1_pkt_drop_lifmap_no_hit;
	uint64_t net_eg1_pkt_drop_src_bind;

	uint64_t net_ig0_fwd_lookup_no_hit;
	uint64_t net_ig0_pkt_drop_fc_multicast;
	uint64_t net_ig0_pkt_drop_invalid_fc_lif;
	uint64_t net_ig0_pkt_null_pif;

	uint64_t net_ig1_fwd_lookup_no_hit;
	uint64_t net_ig1_pkt_drop_fc_multicast;
	uint64_t net_ig1_pkt_drop_invalid_fc_lif;
	uint64_t net_ig1_pkt_null_pif;

	uint64_t host10gbe_port0_rx_pause_cfc;
	uint64_t host10gbe_port0_rx_pause_pfc;
	uint64_t host10gbe_port0_tx_pause_cfc;
	uint64_t host10gbe_port0_tx_pause_pfc;

	uint64_t host10gbe_port1_rx_pause_cfc;
	uint64_t host10gbe_port1_rx_pause_pfc;
	uint64_t host10gbe_port1_tx_pause_cfc;
	uint64_t host10gbe_port1_tx_pause_pfc;

	uint64_t dce_port0_rx_pause_cfc;
	uint64_t dce_port0_rx_pause_pfc;
	uint64_t dce_port0_tx_pause_cfc;
	uint64_t dce_port0_tx_pause_pfc;

	uint64_t dce_port1_rx_pause_cfc;
	uint64_t dce_port1_rx_pause_pfc;
	uint64_t dce_port1_tx_pause_cfc;
	uint64_t dce_port1_tx_pause_pfc;
} menlo_asic_stats_rsp_t;


#define	MENLO_LOG_NAME_SIZE 		20

typedef struct menlo_log
{
#ifdef EMLXS_BIG_ENDIAN
	uint16_t num_entries;
	uint16_t id;

	uint16_t rsvd;
	uint16_t entry_size;
#endif /* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t id;
	uint16_t num_entries;

	uint16_t entry_size;
	uint16_t rsvd;
#endif /* EMLXS_LITTLE_ENDIAN */

	char name[MENLO_LOG_NAME_SIZE];
} menlo_log_t;


typedef struct menlo_log_config_rsp
{
	uint32_t code;

#ifdef EMLXS_BIG_ENDIAN
	uint16_t rsvd;
	uint16_t num_logs; 	/* Number of logs in log array  */
#endif /* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t num_logs; 	/* Number of logs in log array  */
	uint16_t rsvd;
#endif /* EMLXS_LITTLE_ENDIAN */

	uint32_t data;		/* First word of array: */
				/* menlo_log_t log[num_logs]  */
} menlo_log_config_rsp_t;


typedef struct menlo_log_data_rsp
{
	uint32_t code;

#ifdef EMLXS_BIG_ENDIAN
	uint16_t rsvd;
	uint16_t head;		/* Index of oldest log entry in circular */
				/* data array */
#endif /* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t head;		/* Index of oldest log entry in circular */
				/* data array */
	uint16_t rsvd;
#endif /* EMLXS_LITTLE_ENDIAN */

	uint32_t data;		/* char array[num_entries][entry_size]  */
} menlo_log_data_rsp_t;


#define	MENLO_NUM_GP_REGS				32

typedef struct menlo_panic_log_data_rsp
{
	uint32_t code;
	uint32_t rsvd_flag; 	/* N/A to mgmt utility */
	uint32_t type;		/* Panic type (See beleow) */

#define	MENLO_PANIC_TYPE_SOLICITED		0xdead0001
#define	MENLO_PANIC_TYPE_EXCEPTION		0xdead0002

	uint32_t regs_epc;
	uint32_t regs_cp0_cause;
	uint32_t regs_cp0_status;
	uint32_t regs_gp[MENLO_NUM_GP_REGS];

#ifdef EMLXS_BIG_ENDIAN
	uint16_t num_entries; 	/* Number of entries in data array  */
	uint16_t log_present; 	/* Number of entries in data array  */

	uint16_t head;		/* Index of oldest log entry in circular */
				/* data buffer */
	uint16_t entry_size;	/* Size of each entry */
#endif /* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN
	uint16_t log_present; 	/* Number of entries in data array  */
	uint16_t num_entries; 	/* Number of entries in data array  */

	uint16_t entry_size;	/* Size of each entry */
	uint16_t head;		/* Index of oldest log entry in circular */
				/* data buffer */
#endif /* EMLXS_LITTLE_ENDIAN */

	uint32_t data;		/* char array[num_entries][entry_size]  */
} menlo_panic_log_data_rsp_t;


typedef struct menlo_lb_mode_rsp
{
	uint32_t code;
	uint32_t mode;		/* Menlo loopback mode */
} menlo_lb_mode_rsp_t;


#define	MENLO_MAX_FTABLE_ENTRIES	256

typedef struct menlo_fte
{
#ifdef EMLXS_BIG_ENDIAN
    uint8_t type_mask;
    uint8_t type;
    uint16_t flags;

    uint16_t tag_mask;
    uint16_t tag;		/* Ehternet VLAN tag */
#endif /* EMLXS_BIG_ENDIAN */

#ifdef EMLXS_LITTLE_ENDIAN
    uint16_t flags;
    uint8_t type;
    uint8_t type_mask;

    uint16_t tag;		/* Ehternet VLAN tag */
    uint16_t tag_mask;
#endif /* EMLXS_LITTLE_ENDIAN */

#define	MENLO_FTABLE_ENTRY_VALID	0x8000	/* flags field */

    uint8_t mac_addr[8]; 	/* mac addr */
    uint8_t mac_addr_mask[8];	/* mac addr mask */
    uint8_t fc_wwpn[8]; 	/* wwpn */

    uint32_t lif_bitmap;	/* forwarding vector */
    uint32_t rsvd;
} menlo_fte_t;

typedef struct menlo_ftable_rsp
{
	uint32_t code;	/* Response code */

	menlo_fte_t  entry[MENLO_MAX_FTABLE_ENTRIES];
} menlo_ftable_rsp_t;


#define	MENLO_SFP_PAGE_SIZE			256

typedef struct menlo_sfp_rsp
{
	uint32_t code;	/* Response code */
	uint8_t page_a0[MENLO_SFP_PAGE_SIZE];
	uint8_t page_a2[MENLO_SFP_PAGE_SIZE];
} menlo_sfp_rsp_t;


typedef struct menlo_fru_data_rsp
{
	uint32_t code;		/* Response code */
	uint8_t  mac0[8];	/* MAC address of port 0 */
	uint8_t  mac1[8];    	/* MAC address of port 1 */
	uint32_t flags;
} menlo_fru_data_rsp_t;


typedef  struct menlo_diag_log_data_rsp
{
	uint32_t code;		/* Response code */
	uint32_t data_length;   /* Length of the diagnostic log */
				/* buffer (bytes) */
	uint32_t data;		/* menlo_diag_log_t log of size */
				/* data_length bytes */
} menlo_diag_log_data_rsp_t;


typedef struct menlo_diag_log
{
	uint32_t num_tests;		/* Number of entries in data array  */
	uint32_t status_length;		/* Size (words) of the */
					/* menlo_diag_log_entry_t.data array */
	uint32_t requested_loop_cnt;	/* Number of test iterations */
					/* requested */
	uint32_t completed_loop_cnt;	/* Number of test iterations actually */
					/* completed */
	uint32_t test_summary;		/* Overal test status */

#define	DIAG_TEST_STATUS_SUCCESS	0xD0000001
#define	DIAG_TEST_STATUS_FAIL		0xD0000002
#define	DIAG_TEST_STATUS_ABORT		0xD0000003

	uint32_t data;			/* menlo_diag_log_entry_t */
					/* entry[num_tests] */
} menlo_diag_log_t;

typedef struct menlo_diag_log_entry
{
	uint32_t status;		/* Test status See */
					/* DIAG_TEST_STATUS_XXXXX above */
	uint32_t data;			/* uint32_t array[status_length] */
} menlo_diag_log_entry_t;


/* Hornet 2 */

typedef struct menlo_get_fcoe_params_rsp
{
	uint32_t code;	 /* Response code */

	uint32_t fcoe_mode; /* FIP or Non-FIP */

/* FCoE Operation Mode */
#define	FCOE_MODE_NON_FIP	0
#define	FCOE_MODE_FIP		1

	menlo_fcoe_params_t params; /* Specific FCoE parameters */

} menlo_get_fcoe_params_rsp_t;

typedef struct fcf_info
{
	uint32_t handle; /* Handle of the subject FCF */
	uint8_t mac[6]; /* FCF MAC */
	uint16_t vlan_id; /* vlan_id */
	uint8_t sw_name[8]; /* Switch name */
	uint8_t fabric_name[8]; /* Fabric name */
	uint32_t fc_map; /* FC map (not applicable for SPMA) */
	uint32_t lka_period; /* Periodic LKA */

	uint16_t state; /* FCF state */

	uint16_t ctrl_flags; /* FIP header flags */
	uint16_t sup_addr_mode; /* FCoE addressing mode capability */

/* FCoE Addressing Mode */
#define	SPMA_ADDR_MODE		1
#define	FPMA_ADDR_MODE		2

	uint16_t priority; /* Priority of FCF */

} fcf_info_t;

typedef struct menlo_get_fcf_list_rsp
{
	uint32_t code;	 /* Response code */

	uint32_t returned_fcfs; /* Number of returned FCFs */
	uint32_t total_fcfs; /* Total number of discovered FCFs */
	uint32_t active_fcfs; /* Number of active FCFs */
	uint32_t fcf_list; /* List of returned FCFs' information, fcf_info_t */

} menlo_get_fcf_list_rsp_t;

typedef struct menlo_get_facl_rsp
{
	uint32_t code;	/* Response code */

	uint32_t returned_facls; /* Number of returned ACLs */
	uint32_t total_facls; /* Total number of configured ACLs */
	uint32_t facl_list; /* List of returned ACL entry, facl_t */

} menlo_get_facl_rsp_t;

typedef struct create_vl_rsp
{
	uint32_t code;	/* Response code */

	uint32_t vl_handle; /* Handle of created VL */
} create_vl_rsp_t;

typedef struct menlo_get_pg_info_rsp
{
	uint32_t code; /* Response code */

	uint32_t max_supported_pg; /* Max PG supported by hardware */
	uint32_t dcbx_feature_syncd; /* indicate DCBX feature syncd with peer */
	menlo_pg_info_t curr_pg_info; /* Current PG settings */
	menlo_pg_info_t def_pg_info; /* Default PG settings */
	uint32_t max_bg_bw[MAX_GROUPS]; /* Max bandwidth allowed per group */

} menlo_get_pg_info_rsp_t;

typedef struct menlo_get_host_eth_pfc_flag_rsp
{
	uint32_t code; /* Response code */

	uint32_t host_pfc_enable; /* 1 = PFC on Host i/f enabled */

/* Host PFC Flag Definitions */
#define	MENLO_HOST_PFC_DISABLE	0x0
#define	MENLO_HOST_PFC_ENABLE	0x1

} menlo_get_host_eth_pfc_flag_rsp_t;

typedef struct menlo_get_dcbx_mode_rsp
{
	uint32_t code; /* Response code */

	uint32_t mode; /* Mode value. See below */

#define	MENLO_DCBX_MODE_PRE_CEE		0x80000000
#define	MENLO_DCBX_MODE_CEE_VER_01	0x00000001
#define	MENLO_DCBX_MODE_CEE_VER_02	0x00000002
#define	MENLO_DCBX_MODE_CEE_VER_03	0x00000003
#define	MENLO_DCBX_MODE_CEE_VER_04	0x00000004

} menlo_get_dcbx_mode_rsp_t;



typedef union menlo_rsp
{
	uint32_t			word[32];
	uint32_t			code;

/* Response codes */
#define	MENLO_RSP_SUCCESS  		0x00000000
#define	MENLO_ERR_FAILED  		0x00000001
#define	MENLO_ERR_INVALID_CMD		0x00000002
#define	MENLO_ERR_INVALID_CREDIT	0x00000003
#define	MENLO_ERR_INVALID_SIZE   	0x00000004
#define	MENLO_ERR_INVALID_ADDRESS	0x00000005
#define	MENLO_ERR_INVALID_CONTEXT	0x00000006
#define	MENLO_ERR_INVALID_LENGTH	0x00000007
#define	MENLO_ERR_INVALID_TYPE		0x00000008
#define	MENLO_ERR_INVALID_DATA		0x00000009
#define	MENLO_ERR_INVALID_VALUE1	0x0000000A
#define	MENLO_ERR_INVALID_VALUE2	0x0000000B
#define	MENLO_ERR_INVALID_MASK		0x0000000C
#define	MENLO_ERR_CHECKSUM		0x0000000D
#define	MENLO_ERR_UNKNOWN_FCID		0x0000000E
#define	MENLO_ERR_UNKNOWN_WWN		0x0000000F
#define	MENLO_ERR_BUSY			0x00000010
#define	MENLO_ERR_INVALID_FLAG		0x00000011
#define	MENLO_ERR_SFP_ABSENT		0x00000012

	menlo_init_rsp_t		init;
	menlo_get_config_rsp_t		config;
	menlo_fc_stats_rsp_t		fc_stats;
	menlo_network_stats_rsp_t	net_stats;
	menlo_lif_stats_rsp_t		lif_stats;
	menlo_log_config_rsp_t		log_cfg;
	menlo_log_data_rsp_t		log;
	menlo_panic_log_data_rsp_t	panic_log;
	menlo_lb_mode_rsp_t		lb_mode;
	menlo_asic_stats_rsp_t		asic_stats;
	menlo_ftable_rsp_t		ftable;
	menlo_sfp_rsp_t			sfp;
	menlo_fru_data_rsp_t		fru;
	menlo_diag_log_data_rsp_t	diag_log;
} menlo_rsp_t;


/*
 * FIRMWARE IMAGE
 */

typedef struct menlo_image_hdr
{
	uint32_t rsvd1;
	uint32_t rsvd2;
	uint32_t version;
	uint32_t file_length;		/* Length of entire file */
	uint32_t image_length;		/* length of the image without */
					/* padding */
	uint32_t rsvd3;
	uint32_t rsvd4;
	uint32_t checksum_offset;	/* Byte offset to image checksum */
} menlo_image_hdr_t;


/* The version header structure needs to be a multiple of 4 bytes */
typedef struct menlo_version_hdr
{
	uint32_t padded;    /* 1 = Image padded, 0 = Image not padded */

	uint32_t type;

/* Type */
#define	MENLO_IMAGE_TYPE_FIRMWARE 	1
#define	MENLO_IMAGE_TYPE_DIAGNOSTICS 	2

	uint32_t version;   /* fw or diag version */
	uint32_t checksum;  /* 32bit XOR checksum -- needs to be at the end */
} menlo_version_hdr_t;


#endif	/* MENLO_SUPPORT */

#ifdef	__cplusplus
}
#endif

#endif	/* _EMLXS_MENLO_H */
