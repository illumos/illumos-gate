/****************************************************************************
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
 *
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
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

struct Codec_Info {
	u32_t version;	/* Version of Codec */

	enum codec_location {
		e_None		= 0,
		e_Here		= 1,
		e_FRU_EEPROM	= 2
	} loc; /* DEFAULT e-None */
	u16_t total_size;	/* total size of Codec in bytes.Max size 32K (64K?)*/
	u16_t num_msg_segments;	/* number of segments = total size / max message payload size */
};

#define MAX_CODEC_SIZE		0x8000
#define CODEC_SEGMENT_SIZE	0x400
#define NUMBER_OF_SEGMENTS (MAX_CODEC_SIZE/CODEC_SEGMENT_SIZE)
struct codec_t {
	u8_t data[NUMBER_OF_SEGMENTS][CODEC_SEGMENT_SIZE];
};

typedef u32 bdn_cfg;
#define BDN_CFG_SIZE_MASK 		0x0000ffff
#define BDN_CFG_SIZE_OFFSET		0
#define BDN_CFG_STATE_MASK 		0x00ff0000
#define BDN_CFG_STATE_OFFSET		16
	#define BDN_CFG_STATE_ACTIVE	0x00010000
	#define BDN_CFG_STATE_PENDING	0x00020000

struct bdn_fcoe_boot_target {
	u16 wwpn;
	u16 lUNID;
};

#if 0
#define MAX_FCOE_IBOOT_PORT_ID 8  /* @@@TBD - what's this ? */
#define MAX_IBOOT_TARGETS	8
struct bdn_fcoe_boot_next_dlr {
	bdn_cfg hdr;
	u16 fcoe_boot_enable;
	u16 fcoe_cvid;
	u16 fcoe_wwnn;
	u16 n_port_id[MAX_FCOE_IBOOT_PORT_ID];	//Still Not sure how big the array is
	struct fcoe_boot_target targets[MAX_IBOOT_TARGETS];	//Still Not sure how big the array is
};

struct bdn_fcoe_boot {	// Main fcoe_iboot struct
	fcoe_iboot_next_dlr next_dlr;	// Hold substruct per each activation type
};
#endif
struct bdn_netport_now {
	bdn_cfg hdr;
	u8 enable_port;
	u8 rsrv;
	u8 num_pfs_min_bw;
	u8 num_pfs_max_bw;
	u8 min_bw[E2_FUNC_MAX]; /* 4 PFs in 2 port mode / 2 PFs in 4 port mode */
	u8 max_bw[E2_FUNC_MAX]; /* 4 PFs in 2 port mode / 2 PFs in 4 port mode */
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
	u8   num_vf_per_pf[E2_FUNC_MAX];
};

struct bdn_netport {
	struct bdn_netport_now now;
	struct bdn_netport_on_port_reset on_port_reset; /* On Port Reset */
	struct bdn_netport_next_os_boot next_os_boot; /* Next OS Boot */
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
	u8 mac_addr[6];
	u8 func_type;
	u8 boot_mode;
};

struct bdn_flex_func {
	struct bdn_flexfunc_now now;
	struct bdn_flexfunc_next_os_boot next_os_boot; /* Next OS Boot */
};

#ifndef PF_NUM_MAX
#define PF_NUM_MAX 8
#endif

struct bdn {
	u32 size;
	u32 uuid;	// Unique identifer of the slot/chassis of the blade
	struct Codec_Info codec_info;
	struct codec_t codec;
	struct bdn_netport netport[PORT_MAX * NVM_PATH_MAX];
	struct bdn_flex_func flexfunc[PF_NUM_MAX];
	//struct bdn_pxe_boot pxe_boot;
	//struct bdn_iscsi_boot iscsi_boot;
	//struct bdn_fcoe_boot fcoe_boot;
	u32 crc;
};

union bdn_image {
	struct bdn bdn;
	u8_t rsrv[0x9000];
};

/* Expected BDN size is basically the offset of rsrv within the bdn structure */
#define BDN_SIZE (sizeof(struct bdn))

#define BDN_CODEC_INFO()		  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, codec_info))
#define BDN_CODEC_DATA()		  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, codec))
#define BDN_NETPORT_NOW(papo)		  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, netport[(papo.path << 1) + papo.port].now))
#define BDN_NETPORT_ON_PORT_RESET(papo)   (ASN1_P->bdn_addr + OFFSETOF(struct bdn, netport[(papo.path << 1) + papo.port].on_port_reset))
#define BDN_NETPORT_NEXT_OS_BOOT(papo)	  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, netport[(papo.path << 1) + papo.port].next_os_boot))
#define BDN_FLEXFUNC_NOW(pf_num)	  (ASN1_P->bdn_addr + OFFSETOF(struct bdn, flexfunc[pf_num].now))
#define BDN_FLEXFUNC_NEXT_OS_BOOT(pf_num) (ASN1_P->bdn_addr + OFFSETOF(struct bdn, flexfunc[pf_num].next_os_boot))
#define BDN_CRC()			  (ASN1_P->bdn_addr + sizeof(union bdn_image))

/*----------------------------------------------------------------------------
 * ------------------------------ Function Prototypes ------------------------
 * ---------------------------------------------------------------------------
 */

int bd_populate_os_reset_config(void);
int bd_populate_port_reset_config(int path, int port);
#endif /* BDN_H */
