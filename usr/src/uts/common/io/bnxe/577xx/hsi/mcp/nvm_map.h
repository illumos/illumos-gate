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
 * Name:        nvm_map.h
 *
 * Description: Everest NVRAM map
 *
 * Created:     05/03/2006 eilong
 *
 * $Date: 2014/07/16 $       $Revision: #111 $
 ****************************************************************************/

#ifndef NVM_MAP_H
#define NVM_MAP_H

#include "mcp_shmem.h"
#if !defined(MFW) && !defined(VMWARE)
#include "types.h"
#include "invm_cfg.h"
#define __FAR__ /*Need to define this as NULL, as it is defined in preboot make file*/
#include "fcb_nvm.h"
#endif

#define CRC_MAGIC_VALUE                     0xDEBB20E3
#define CRC32_POLYNOMIAL                    0xEDB88320


/****************************************************************************
 * Boot Strap Region                                                        *
 ****************************************************************************/
typedef struct _bootstrap_region_t
{
    u32_t magic_value;          /* a pattern not likely to occur randomly */
        #define NVM_MAGIC_VALUE                             0x669955aa
    u32_t sram_start_addr;      /* where to locate boot code (byte addr) */
        #define NVM_DEFAULT_SRAM_ADDR                       0x08000010
    u32_t code_len;             /* boot code length (in dwords) */
    u32_t code_start_addr;      /* location of code on media (media byte addr) */
    u32_t crc;                  /* 32-bit CRC */
} bootstrap_region_t;

#if !defined(MFW) && !defined(VMWARE)
typedef struct {
    NVM_ISCSI_CFG_BLOCK_V2 iscsi_cfg[4];
    NVM_FCB_CFG_BLOCK fcoe_cfg[4];
} shadow_image_t;
#else
typedef struct {
    u8_t iscsi_cfg[4][0x800];
    u8_t fcoe_cfg[4][0x400];
} shadow_image_t;
#endif

/****************************************************************************
 * Directories Region                                                       *
 ****************************************************************************/
typedef struct _code_entry_t
{
    u32_t sram_start_addr;      /* Relative to the execution CPU, see code image
                                   agent in code_attribute field */
    u32_t code_attribute;
        #define CODE_IMAGE_TYPE_MASK                        0xf0800003

        /* Images which are stored in extended dir have bit 0 set to 1 */
        #define CODE_IMAGE_IN_EXTENDED_DIR_MASK             0x00000001

        #define CODE_IMAGE_TYPE_BC2                         0x00000000
        #define CODE_IMAGE_TYPE_MBA                         0x10000000
        #define CODE_IMAGE_TYPE_NC_SI_CMN                   0x20000000
        #define CODE_IMAGE_TYPE_MODULES_PN                  0x30000000
        #define CODE_IMAGE_TYPE_IPMI                        0x40000000
        #define CODE_IMAGE_TYPE_ISCSI_BOOT_CFG2             0x50000000
        #define CODE_IMAGE_TYPE_NC_SI_EVEREST               0x60000000
        #define CODE_IMAGE_TYPE_L2T                         0x70000000
        #define CODE_IMAGE_TYPE_L2C                         0x80000000
        #define CODE_IMAGE_TYPE_L2X                         0x90000000
        #define CODE_IMAGE_TYPE_L2U                         0xa0000000
        #define CODE_IMAGE_TYPE_ISCSI_BOOT_CPRG             0xb0000000
        #define CODE_IMAGE_TYPE_ISCSI_BOOT_CFG              0xc0000000
        #define CODE_IMAGE_TYPE_ISCSI_BOOT                  0xd0000000
        #define CODE_IMAGE_TYPE_FCOE_BOOT_CFG               0x10000001
        #define CODE_IMAGE_TYPE_FCOE_BOOT                   0x20000001
        #define CODE_IMAGE_TYPE_FCOE_BOOT_CFG2              0x30000001
        #define CODE_IMAGE_TYPE_FCOE_BOOT_CPRG_EVRST        0x40000001
        #define CODE_IMAGE_TYPE_NIC_PARTITION_CFG           0x50000001
        #define CODE_IMAGE_TYPE_FCOE_BOOT_CFG3              0x60000001
        #define CODE_IMAGE_TYPE_FCOE_BOOT_CFG4              0x70000001
        #define CODE_IMAGE_TYPE_ISCSI_BOOT_CFG3             0x80000001
        #define CODE_IMAGE_TYPE_ISCSI_BOOT_CFG4             0x90000001
        #define CODE_IMAGE_TYPE_BOOT_CFG_SHADOW             0x10800001
        #define CODE_IMAGE_TYPE_VPD                         0xa0000001
        #define CODE_IMAGE_TYPE_E3_WC                       0xb0000001
        #define CODE_IMAGE_TYPE_E3_PCIE                     0xc0000001
        #define CODE_IMAGE_VNTAG_DATA                       0xd0000001
        #define CODE_IMAGE_TYPE_SWIM1                       0xe0000001
        #define CODE_IMAGE_TYPE_SWIM2                       0xf0000001
        #define CODE_IMAGE_TYPE_SWIM3                       0x10000003
        #define CODE_IMAGE_TYPE_MFW1                        0x20000003 /* Replace BC1 */
        #define CODE_IMAGE_TYPE_MFW2                        0x30000003 /* Replace BC2 + NCSI */
        #define CODE_IMAGE_TYPE_SWIM4                       0x40000003
        #define CODE_IMAGE_TYPE_SWIM5                       0x50000003
        #define CODE_IMAGE_TYPE_SWIM6                       0x60000003
        #define CODE_IMAGE_TYPE_SWIM7                       0x70000003
        #define CODE_IMAGE_TYPE_SWIM8                       0x80000003
        #define CODE_IMAGE_TYPE_MFW2_A                      0x90000003
        #define CODE_IMAGE_TYPE_OCNVM                       0xa0000003 /*ocnvm*/
        #define CODE_IMAGE_VNTAG_PROFILES_DATA              0xd0000003
        #define CODE_IMAGE_NVM_CFG_EXTENDED_SHARED          0xe0000003
        #define CODE_IMAGE_TYPE_E3_WCV2                     0xf0000003 /*wc_v2*/
        #define CODE_IMAGE_TYPE_E3_PCIEV2                   0x00800003 /*pcie_v2*/

        #define CODE_IMAGE_TYPE_CCM                         0x90800003

        /* for shaddow SWIMs feature */
        #define CODE_IMAGE_TYPE_SWIM1_B                     0x10800003
        #define CODE_IMAGE_TYPE_SWIM2_B                     0x20800003
        #define CODE_IMAGE_TYPE_SWIM3_B                     0x30800003
        #define CODE_IMAGE_TYPE_SWIM4_B                     0x40800003
        #define CODE_IMAGE_TYPE_SWIM5_B                     0x50800003
        #define CODE_IMAGE_TYPE_SWIM6_B                     0x60800003
        #define CODE_IMAGE_TYPE_SWIM7_B                     0x70800003
        #define CODE_IMAGE_TYPE_SWIM8_B                     0x80800003

        #define CODE_IMAGE_TYPE_CCM                         0x90800003
        #define CODE_IMAGE_TYPE_HW_SET                      0xa0800003
        #define CODE_IMAGE_TYPE_USR_BLK                     0xb0000003
        #define CODE_IMAGE_TYPE_ISCSI_PERS                  0xc0000003

        /* next few groups of image: 0x90800003 -- 0xf0800003
                                     0x00800001 -- 0xf0800001*/

        #define CODE_IMAGE_TYPE_EXTENDED_DIR                0xe0000000
        #define CODE_IMAGE_TYPE_MAX                         0xf0000000
        #define CODE_IMAGE_TYPE_BC1                         CODE_IMAGE_TYPE_MAX

        #define CODE_IMAGE_AGENT_TYPE_MASK                  0x0f000000
        #define CODE_IMAGE_AGENT_NONE                       0x00000000
        #define CODE_IMAGE_AGENT_HOST                       0x01000000
        #define CODE_IMAGE_AGENT_MCP                        0x02000000
        #define CODE_IMAGE_AGENT_TSTORM                     0x03000000
        #define CODE_IMAGE_AGENT_CSTORM                     0x04000000
        #define CODE_IMAGE_AGENT_XSTORM                     0x05000000
        #define CODE_IMAGE_AGENT_USTORM                     0x06000000
        #define CODE_IMAGE_AGENT_E3WC                       0x07000000
        #define CODE_IMAGE_AGENT_E3PCIE                     0x08000000
        #define CODE_IMAGE_AGENT_HOST_BCV                   0x09000000
        #define CODE_IMAGE_TYPE_BDN                         0xc0800003

        #define CODE_IMAGE_LENGTH_MASK                      0x007ffffc

    u32_t nvm_start_addr;
} code_entry_t;

#define CODE_ENTRY_MAX                      16
#define CODE_ENTRY_EXTENDED_DIR_IDX         15
#define MAX_IMAGES_IN_EXTENDED_DIR          64
#define MAX_SPARE_NUM_LENGTH                20

/* version since which shadow feature is supported */
#define MFW_SHADOW_FEATURE_SUPPORTED_MAJOR 7
#define MFW_SHADOW_FEATURE_SUPPORTED_MINOR 0
#define MFW_SHADOW_FEATURE_SUPPORTED_BUILD 24

typedef struct _dir_t
{
    code_entry_t code[CODE_ENTRY_MAX];
    u32_t unused[5];            /* Must be all zeroes */
    u8_t spare_part_num[MAX_SPARE_NUM_LENGTH];
                                /* Similar to the part number in VPD */
    u32_t crc;
} dir_t;

/****************************************************************************
 * Manufacturing Information Region                                         *
 ****************************************************************************/
typedef struct _manuf_info_t
{                                                     /* NVM Offset  (size) */
    u32_t length;                                     /* 0x100 */
        #define MANUF_INFO_FORMAT_REV_ID                    ('A'<<24)
        #define MANUF_INFO_FORMAT_REV_MASK                  0xff000000
        #define MANUF_INFO_LENGTH_MASK                      0x0000ffff
        #define MANUF_INFO_LENGTH                           0x00000000

    shared_hw_cfg_t shared_hw_config;                 /* 0x104      (0x128) */
    port_hw_cfg_t port_hw_config[PORT_MAX];           /* 0x12c(400*2=0x320) */
    u32_t crc;                                        /* 0x44c */

} manuf_info_t;


/****************************************************************************
 * Features Information Region                                              *
 ****************************************************************************/
typedef struct _feature_info_t
{
    shared_feat_cfg_t shared_feature_config;          /* 0x450 */
    port_feat_cfg_t port_feature_config[PORT_MAX];    /* 0x454 (116*2=0xe8) */
    u32_t crc;                                        /* 0x53c */

} feature_info_t;


/****************************************************************************
 * VPD Region                                                               *
 ****************************************************************************/

#define MAX_VPD_R_LENGTH                    128
#define MAX_VPD_W_LENGTH                    128

typedef struct media_vpd_read_t
{
    u8_t data[MAX_VPD_R_LENGTH];
} media_vpd_read_t;

typedef struct media_vpd_write_t
{
    u8_t data[MAX_VPD_W_LENGTH];
} media_vpd_write_t;

typedef struct media_vpd_t
{
    media_vpd_read_t vpd_r;                           /* 0x540 */
    media_vpd_write_t vpd_w;                          /* 0x5c0 */
} media_vpd_t;

/****************************************************************************
 * License Region                                                           *
 ****************************************************************************/

#define SHARED_SECRET_BYTE_CNT              20
#define OEM_OPAQUE_DATA_BYTE_CNT            32
#define MAC_ADDRESS_ALIGNED_BYTE_CNT        8

/* Upgrade License Region */
#define UPGRADE_KEY_COUNT                   1

typedef struct _upgrade_key_info_t
{
    u32_t key_available;
        #define KEY_AVAILABLE_UPGRADE_KEY_0                 0x1
    license_key_t upgrade_key[UPGRADE_KEY_COUNT];
    u8_t hwkey_mac[MAC_ADDRESS_ALIGNED_BYTE_CNT];                       /* Phony MAC address for HW key
                                                                           (SVID followed by MAC addr) */
    u8_t oem_opaque[OEM_OPAQUE_DATA_BYTE_CNT];                          /* Used via BMAPI */
    u32_t crc;
} upgrade_key_info_t;

/* Manufacturing License Region */
typedef struct _manuf_key_info_t
{
    u32_t revision;
        #define LICENSE_REV_A                               'A'
        #define LICENSE_REV_MASK                            0x0000ffff
        #define LICENSE_SIGNATURE_MASK                      0xffff0000
        #define LICENSE_SIGNATURE                           0x4c4b0000  /* LK */

    u8_t shared_secret[SHARED_SECRET_BYTE_CNT];                         /* Customer dependent */
        #define SSECRET_ENCODED_32BIT_VALUE                 0x5a5a5a5a
        #define SSECRET_ENCODED_8BIT_VALUE                  0x5a
    license_key_t manuf_key;
    u8_t oem_opaque[OEM_OPAQUE_DATA_BYTE_CNT];                          /* Used via BMAPI */
    u32_t crc;
} manuf_key_info_t;

/****************************************************************************
 * NVRAM FULL MAP                                                           *
 ****************************************************************************/
typedef struct _nvm_image_t
{                                                     /* NVM Offset  (size) */
    bootstrap_region_t bootstrap;                     /* 0x0         (0x14) */
    dir_t              dir;                           /* 0x14        (0xec) */
    manuf_info_t       manuf_info;                    /* 0x100      (0x350) */
    feature_info_t     feature_info;                  /* 0x450       (0xf0) */
    media_vpd_t        vpd;                           /* 0x540      (0x100) */
    upgrade_key_info_t upgrade_key_info[PORT_MAX];    /* 0x640 (100*2=0xc8) */
    manuf_key_info_t   manuf_key_info[PORT_MAX];      /* 0x708 (112*2=0xe0) */
} nvm_image_t;                                        /* 0x7e8 */

#define NVM_OFFSET(f)                  ((u32_t)((int_ptr_t)(&(((nvm_image_t*)0)->f))))


/* This struct defines the additional NVM configuration parameters needed for PATH 1 in E2 */

typedef struct _path1_nvm_image_t
{                                                     /* NVM Offset  (size) */
    manuf_info_t       manuf_info;                    /* 0x7e8      (0x350) */
    feature_info_t     feature_info;                  /* 0xb38       (0xf0) */
} path1_nvm_image_t;                                  /* 0xdd0 */

#define PATH1_NVM_OFFSET(f)            (sizeof(nvm_image_t) + __builtin_offsetof(path1_nvm_image_t, f))

#define NVM_OFFSET_PATH(field,path) \
        ((u32_t)((path == 0) ? (NVM_OFFSET(field)) : (PATH1_NVM_OFFSET(field))))


/****************************************/
/***      NVM RETAIN section          ***/
/****************************************/
// Max nvm retain bitmap size is currently set to the size of manuf_info
// To be to preserve manuf_info in a dword resolution, we need sizeof(manuf_info_t) >> 2
// To represent each dword in bit, divide by 32 ( >>5), and add 1 to round up.
#define NVM_RETAIN_BEGIN                0
#define NVM_RETAIN_END                  (PATH1_NVM_OFFSET(feature_info) + sizeof(feature_info_t))
#define NVM_RETAIN_ADDR_TO_ARR_IDX(addr) ((addr) >> 7)
#define NVM_RETAIN_ADDR_TO_DW_BIT(addr) (1<<(((addr) >> 2) & 0x1f))
#define NVM_RETAIN_BITMAP_SIZE          (NVM_RETAIN_ADDR_TO_ARR_IDX(NVM_RETAIN_END) + 1)


/*******************************************************/
/* These structs define the modules image block in NVM */
/*******************************************************/
#define SFF_VENDOR_NAME_LEN                 16
#define SFF_VENDOR_OUI_LEN                  3
#define SFF_VENDOR_PN_LEN                   16

typedef struct _module_info_t
{
    u32_t ctrl_flags;
	#define MODULE_INFO_FLAG_CHECK_VENDOR_NAME          (1 << 0)
	#define MODULE_INFO_FLAG_CHECK_VENDOR_OUI           (1 << 1)
	#define MODULE_INFO_FLAG_CHECK_VENDOR_PN            (1 << 2)
	#define MODULE_INFO_FLAG_CHECK_BRANDING             (1 << 3)

    char vendor_name[SFF_VENDOR_NAME_LEN];
    u8_t vendor_oui[SFF_VENDOR_OUI_LEN];
    u8_t reserved;
    char vendor_pn[SFF_VENDOR_PN_LEN];
} module_info_t;

typedef struct _module_image_t
{
    u32_t format_version;
	#define MODULE_IMAGE_VERSION_1        1
    /* With branding */
	#define MODULE_IMAGE_VERSION_2        2 /* With branding */
    u32_t no_modules;
    /* This array length depends on the no_modules */
    module_info_t modules[1];
} module_image_t;


typedef struct _vpd_image_t
{
    u32_t       format_revision;
        #define VPD_IMAGE_VERSION        1

    /* This array length depends on the number of VPD fields */
    u8_t        vpd_data[1];

} vpd_image_t;


typedef struct _extended_dir_image_t
{
    u32_t no_images;                        /* Number of images included in
                                                the extended dir image */

    u32_t total_byte_cnt;                   /* Total byte_cnt of all images
                                               included in the extended dir */

    code_entry_t extended_dir_images[MAX_IMAGES_IN_EXTENDED_DIR];
                                            /* Array of images information
                                               within extended dir image */
} extended_dir_image_t;


#define MAC_PARTITION_FORMAT_VERSION 1

struct macp_gbl_cfg {
        /* Reserved bits: 0-0 */
        #define MACP_GBL_CFG_FORMAT_VER_MASK                          0x000000FF
        #define MACP_GBL_CFG_FORMAT_VER_SHIFT                         0


        u32 gbl_cfg;
        #define MACP_GBL_CFG_GBL_CFG_MASK                             0x0000FF00
        #define MACP_GBL_CFG_GBL_CFG_SHIFT                            8
        #define MACP_GBL_CFG_GBL_CFG_DISABLED                         0x00000000
        #define MACP_GBL_CFG_GBL_CFG_ENABLED                          0x00000100

};

struct macp_port_cfg {

        u32 port_cfg;
        #define MACP_PORT_CFG_FLOW_CTRL_MASK                          0x000000FF
        #define MACP_PORT_CFG_FLOW_CTRL_SHIFT                         0
        #define MACP_PORT_CFG_FLOW_CTRL_AUTO                          0x00000000
        #define MACP_PORT_CFG_FLOW_CTRL_TX_ONLY                       0x00000001
        #define MACP_PORT_CFG_FLOW_CTRL_RX_ONLY                       0x00000002
        #define MACP_PORT_CFG_FLOW_CTRL_BOTH                          0x00000003
        #define MACP_PORT_CFG_FLOW_CTRL_NONE                          0x00000004

        #define MACP_PORT_CFG_PHY_LINK_SPD_MASK                       0x0000FF00
        #define MACP_PORT_CFG_PHY_LINK_SPD_SHIFT                      8
        #define MACP_PORT_CFG_PHY_LINK_SPD_1G                         0x00000000
        #define MACP_PORT_CFG_PHY_LINK_SPD_2_DOT_5G                   0x00000100
        #define MACP_PORT_CFG_PHY_LINK_SPD_10G                        0x00000200
        #define MACP_PORT_CFG_PHY_LINK_SPD_20G                        0x00000400

        #define MACP_PORT_CFG_NUM_PARTITIONS_MASK                     0x00FF0000
        #define MACP_PORT_CFG_NUM_PARTITIONS_SHIFT                    16


        u32 Reserved0[2];
};

struct macp_func_cfg {

        u32 func_cfg;
        #define MACP_FUNC_CFG_FLAGS_MASK                              0x0000007F
        #define MACP_FUNC_CFG_FLAGS_SHIFT                             0
        #define MACP_FUNC_CFG_FLAGS_ENABLED                           0x00000001
        #define MACP_FUNC_CFG_FLAGS_ETHERNET                          0x00000002
        #define MACP_FUNC_CFG_FLAGS_ISCSI_OFFLOAD                     0x00000004
        #define MACP_FUNC_CFG_FLAGS_FCOE_OFFLOAD                      0x00000008
        /*  pause on host ring */
        #define MACP_FUNC_CFG_PAUSE_ON_HOST_RING_MASK                 0x00000080
        #define MACP_FUNC_CFG_PAUSE_ON_HOST_RING_SHIFT                7
        #define MACP_FUNC_CFG_PAUSE_ON_HOST_RING_DISABLED             0x00000000
        #define MACP_FUNC_CFG_PAUSE_ON_HOST_RING_ENABLED              0x00000080

        #define MACP_FUNC_CFG_BW_WEIGHT_MASK                          0x0000FF00
        #define MACP_FUNC_CFG_BW_WEIGHT_SHIFT                         8

        #define MACP_FUNC_CFG_BW_MAX_MASK                             0xFFFF0000
        #define MACP_FUNC_CFG_BW_MAX_SHIFT                            16


        u32 net_mac_addr_upper;

        u32 net_mac_addr_lower;

        u32 iscsi_mac_addr_upper;

        u32 iscsi_mac_addr_lower;

        u32 fcoe_mac_addr_upper;

        u32 fcoe_mac_addr_lower;

        u32 fcoe_node_wwn_upper;

        u32 fcoe_node_wwn_lower;

        u32 fcoe_port_wwn_upper;

        u32 fcoe_port_wwn_lower;

        u32 pf_allocation;
        /* number of vfs in function, if 0 - sriov disabled */
        #define MACP_FUNC_CFG_NUMBER_OF_VFS_MASK                      0x000000FF
        #define MACP_FUNC_CFG_NUMBER_OF_VFS_SHIFT                     0
};


typedef struct _nvm_nic_part_cfg_t
{
  struct macp_gbl_cfg global_cfg;
  struct macp_port_cfg port_cfg[NVM_PATH_MAX][PORT_MAX];
  struct macp_func_cfg func_cfg[E1H_FUNC_MAX];
  u8_t reserved2[72];
  /* NOTE: CRC will be appended by nvm_program procedure */
}nvm_nic_part_cfg_t;

#define NIV_FORMAT_VERSION_ONE 1
#define NIV_MAX_PROFILE_LEN 80
#define NIV_NUM_PROFILES_SUPPORTED 64

struct niv_gbl_cfg {                              /* NVRAM OFFSET */

	u32 gbl_cfg;                                        /* 0x1000 */
	#define NIV_GBL_CFG_IMAGE_VER_MASK                            0x000000FF
	#define NIV_GBL_CFG_IMAGE_VER_SHIFT                           0


	u32 Reserved0[2];                                   /* 0x1004 */
};

struct niv_port_cfg {                             /* port 0: 0x100C port 1: 0x1018 */

	u32 port_cfg;                                       /* 0x100C */
	#define NIV_PORT_CFG_FLOW_CTRL_MASK                           0x000000FF
	#define NIV_PORT_CFG_FLOW_CTRL_SHIFT                          0
	#define NIV_PORT_CFG_FLOW_CTRL_AUTO                           0x00000000
	#define NIV_PORT_CFG_FLOW_CTRL_TX_ONLY                        0x00000001
	#define NIV_PORT_CFG_FLOW_CTRL_RX_ONLY                        0x00000002
	#define NIV_PORT_CFG_FLOW_CTRL_BOTH                           0x00000003
	#define NIV_PORT_CFG_FLOW_CTRL_NONE                           0x00000004

	#define NIV_PORT_CFG_PHY_LINK_SPD_MASK                        0x0000FF00
	#define NIV_PORT_CFG_PHY_LINK_SPD_SHIFT                       8
	#define NIV_PORT_CFG_PHY_LINK_SPD_1G                          0x00000000
	#define NIV_PORT_CFG_PHY_LINK_SPD_2_DOT_5G                    0x00000100
	#define NIV_PORT_CFG_PHY_LINK_SPD_10G                         0x00000200
	#define NIV_PORT_CFG_PHY_LINK_SPD_20G                         0x00000400
};

struct niv_func_cfg {                             /* port 0: 0x1024 port 1: 0x10AC */

	u32 bw_params;                                      /* 0x1024 */
	#define NIV_FUNC_CFG_bw_weight_MASK                           0x0000FFFF
	#define NIV_FUNC_CFG_bw_weight_SHIFT                          0

	#define NIV_FUNC_CFG_bw_max_MASK                              0xFFFF0000
	#define NIV_FUNC_CFG_bw_max_SHIFT                             16


	u32 func_cfg_1;                                     /* 0x1028 */
	#define NIV_FUNC_CFG_vif_type_MASK                            0x0000007F
	#define NIV_FUNC_CFG_vif_type_SHIFT                           0
	#define NIV_FUNC_CFG_vif_type_ENABLED                         0x00000001
	#define NIV_FUNC_CFG_vif_type_ETHERNET                        0x00000002
	#define NIV_FUNC_CFG_vif_type_ISCSI_OFFLOAD                   0x00000004
	#define NIV_FUNC_CFG_vif_type_FCOE_OFFLOAD                    0x00000008

	/*  pause on host ring */
	#define NIV_FUNC_CFG_PAUSE_ON_HOST_RING_MASK                  0x00000080
	#define NIV_FUNC_CFG_PAUSE_ON_HOST_RING_SHIFT                 7
	#define NIV_FUNC_CFG_PAUSE_ON_HOST_RING_DISABLED              0x00000000
	#define NIV_FUNC_CFG_PAUSE_ON_HOST_RING_ENABLED               0x00000080
	#define NIV_FUNC_CFG_remote_boot_enabled_MASK                 0x0000FF00
	#define NIV_FUNC_CFG_remote_boot_enabled_SHIFT                8
	#define NIV_FUNC_CFG_remote_boot_enabled_DISABLED             0x00000000
	#define NIV_FUNC_CFG_remote_boot_enabled_ENABLED              0x00000100

	#define NIV_FUNC_CFG_profile_enabled_MASK                     0x00FF0000
	#define NIV_FUNC_CFG_profile_enabled_SHIFT                    16
	#define NIV_FUNC_CFG_profile_enabled_DISABLED                 0x00000000
	#define NIV_FUNC_CFG_profile_enabled_ENABLED                  0x00010000


	u32 net_mac_addr_upper;                             /* 0x102B */

	u32 net_mac_addr_lower;                             /* 0x102F */

	u32 iscsi_mac_addr_upper;                           /* 0x1034 */

	u32 iscsi_mac_addr_lower;                           /* 0x1038 */

	u32 fcoe_mac_addr_upper;                            /* 0x103C */

	u32 fcoe_mac_addr_lower;                            /* 0x1040 */

	u32 fcoe_node_wwn_upper;                            /* 0x1044 */

	u32 fcoe_node_wwn_lower;                            /* 0x1048 */

	u32 fcoe_port_wwn_upper;                            /* 0x104C */

	u32 fcoe_port_wwn_lower;                            /* 0x1050 */

	u8 profile_name[80];                                /* 0x1054 */

	u32 Reserved0[2];                                   /* 0x10A4 */
};

typedef struct _nvm_niv_cfg_t
{
        struct niv_gbl_cfg      global_cfg;                // global config
        struct niv_port_cfg    port_cfg[NVM_PATH_MAX][PORT_MAX];       // per port config
        u32 reserved[2];
        struct niv_func_cfg     func_cfg[E1H_FUNC_MAX];   // per func config
} nvm_niv_cfg_t;

struct niv_port_profiles_cfg {                    /* port 0: 0x1600 port 1: 0x2A00 */

	u8 profiles_list[64][80];                           /* 0x1600 */
};

typedef struct _nvm_niv_port_profile_t
{
        struct niv_port_profiles_cfg    port_cfg[PORT_MAX];       // per port config
} nvm_niv_port_profile_t;


typedef struct _hw_set_info_t
{
    u32_t reg_type;
    #define GRC_REG_TYPE 1
    #define PHY_REG_TYPE 2
    #define PCI_REG_TYPE 4

    u32_t bank_num;
    u32_t pf_num;
    u32_t operation;
    #define READ_OP     1
    #define WRITE_OP    2
    #define RMW_SET_OP  3
    #define RMW_CLR_OP  4

    u32_t reg_addr;
    u32_t reg_data;

    u32_t reset_type;
    #define POR_RESET_TYPE  (1 << 0)
    #define HARD_RESET_TYPE (1 << 1)
    #define CORE_RESET_TYPE (1 << 2)
    #define MCP_RESET_TYPE  (1 << 3)
    #define PERSET_ASSERT   (1 << 4)
    #define PERSET_DEASSERT (1 << 5)

} hw_set_info_t;

typedef struct _hw_set_image_t
{
    u32_t format_version;
        #define HW_SET_IMAGE_VERSION        1
    u32_t no_hw_sets;
    /* This array length depends on the no_hw_sets */
    hw_set_info_t hw_sets[1];
} hw_set_image_t;


struct iscsi_flash_meta_data {
	u16_t signature;
	u8_t reserved_a;
	u8_t version;
	u32_t block_size;
	u16_t target_size;
	u8_t target_max;
	u8_t reserved[5];
};

#define ISID_SIZE 6

struct iscsi_flash_session {
	u32_t version;
	u32_t ctrl_flags;
	#define FLASH_SESS_CTRL_ENTRY_ENABLE		(0)
	#define FLASH_SESS_CTRL_AUTO_CONNECT		(1)
	#define FLASH_SESS_CTRL_AUTO_SEND_TGT_DISABLE	(2)
	#define FLASH_SESS_CTRL_DISCOVERY_SESS		(3)
	#define FLASH_SESS_CTRL_ENABLE_IMM_DATA		(4)
	#define FLASH_SESS_CTRL_ENABLE_INIT_R2T		(5)
	#define FLASH_SESS_CTRL_DATA_SEQ_IN_ORDER	(6)
	#define FLASH_SESS_CTRL_DATA_PDU_IN_ORDER	(7)
	#define FLASH_SESS_CTRL_CHAP_AUTH		(8)
	#define FLASH_SESS_CTRL_BIDI_CHAP		(9)
	#define FLASH_SESS_CTRL_DISCOVERY_LOGOUT	(10)
	#define FLASH_SESS_CTRL_DISCOVERY_AUTH_OPT	(11)
	u32_t stat_flags;
	#define FLASH_SESS_STAT_IS_BOOT_TARGET		(0)
	char portal_type[4];
	u32_t first_burst_len;
	u16_t def_time2wait;
	u16_t def_time2retain;
	u16_t max_outstanding_r2t;
	u16_t tsid;
	u8_t isid[ISID_SIZE];  /* ISID_SIZE = 6 */
	u8_t erl;
	u8_t def_taskmgmt_tmo;
	u32_t max_burst_len;
	char targetalias[32];
	u16_t tpgt;
	u16_t discovery_parent_idx;
	u16_t discovery_parent_type;
	u16_t chap_in_idx;
	u16_t chap_out_idx;
    u16_t reserved_a;
	char username[64];
	char username_in[64];
	char password[64];
	char password_in[64];
	char targetname[256];
	u8_t reserved[4];
};

struct iscsi_flash_connection {
	u32_t ctrl_flags;
	#define FLASH_CONN_CTRL_HEADER_DIGEST		(0)
	#define FLASH_CONN_CTRL_DATA_DIGEST		(1)
	#define FLASH_CONN_CTRL_SNACK_REQ		(2)
	#define FLASH_CONN_CTRL_TCP_TIMESTAMP_STAT	(3)
	#define FLASH_CONN_CTRL_TCP_NAGLE_DISABLE	(4)
	#define FLASH_CONN_CTRL_TCP_WSF_DISABLE		(5)
	#define FLASH_CONN_CTRL_TCP_TIMER_SCALE		(6)
	#define FLASH_CONN_CTRL_TCP_TIMESTAMP_ENABLE	(7)
	#define FLASH_CONN_CTRL_IP_FRAG_DISABLE		(8)
	u32_t stat_flags;
	#define FLASH_CONN_STAT_IS_FW_ASSIGNED_IPV6	(0)
	u32_t max_recv_dlength;
	u32_t max_xmit_dlength;
	u16_t keepalive_tmo;
	u16_t port;
	u32_t ipaddress[4];
	u32_t link_local_ipv6[4];
	u32_t redirect_ipaddr[4];
	u16_t max_segment_size;
	u16_t local_port;
	u8_t ipv4_tos;
	u8_t ipv6_traffic_class;
	u8_t ipv6_flow_label;
	u8_t reserved_a;
	u8_t tcp_xmit_wsf;
	u8_t tcp_recv_wsf;
	u8_t reserved_b[2];
	u32_t statsn;
	u32_t exp_statsn;
	u8_t reserved[12];
};

struct iscsi_flash_initiator {
	u32_t ctrl_flags;
	u32_t stat_flags;
	u8_t hwaddress[6];
	u8_t reserved_a[2];
	u32_t initiator_ip[4];
	u32_t subnet_mask[4];
	u32_t gateway[4];
	u16_t vlan_id;
	u8_t reserved_b[2];
	char initiatorname[256];
};

struct iscsi_flashnode {
	struct iscsi_flash_session session;
	struct iscsi_flash_connection connection;
	struct iscsi_flash_initiator initiator;
};

struct iscsi_persistent_image {
	struct iscsi_flash_meta_data meta_data;
	struct iscsi_flashnode flahsnode[16];
};


#define NVM_CFG_EXTENDED_SHARED_IMAGE_MAX_SIZE 256

#endif //NVM_MAP_H
