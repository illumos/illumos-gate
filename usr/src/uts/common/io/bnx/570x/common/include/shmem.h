/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _SHMEM_H
#define _SHMEM_H

#include "bcmtype.h"
#include "5706_reg.h"
#include "license.h"



/* This structure will be located at the beginning of the MCP scratchpad.
 * All firmwares need to be compiled to specify a starting address
 * (> 0x08000010).
 */
typedef struct _shm_hdr_t
{
    u32_t shm_hdr_signature;
        #define SHM_ADDR_SIGN_MASK                         0xffff0000
        #define SHM_ADDR_SIGNATURE                         0x53530000
        /* The dword count is meaningful only for version 0x2 or after */
        #define SHM_ADDR_DWORD_SIZE_MASK                   0xff00
        #define SHM_ADDR_HDR_VER_MASK                      0xff
        #define SHM_ADDR_HDR_CURR_VER                      0x1
        #define SHM_ADDR_HDR_FIXED_LEN_VER                 0x1   /* version 0 & 1 uses fixed length of SHM_ADDR_HDR_FIXED_LEN_SIZE (0x10) */
        #define SHM_ADDR_HDR_FIXED_LEN_SIZE                0x10
    u32_t shm_addr[2];
        /* The address value is the host view address. The first one is
         * for primary port, and the second one is for the secondary
         * port (applicable in Xinan). We don't know if the shared
         * memory will be part of the MCP scratchpad, thus, it is safer
         * to show the host view and let firmware to calculate the CPU
         * view.
         */
    u32_t reserved;
} shm_hdr_t;



/* This value (in milliseconds) determines the frequency of the driver
 * issuing the PULSE message code.  The firmware monitors this periodic
 * pulse to determine when to switch to an OS-absent mode. */
#define DRV_PULSE_PERIOD_MS                 250

/* This value (in milliseconds) determines how long the driver should
 * wait for an acknowledgement from the firmware before timing out.  Once
 * the firmware has timed out, the driver will assume there is no firmware
 * running and there won't be any firmware-driver synchronization during a
 * driver reset. */
#define FW_ACK_TIME_OUT_MS                  50

/* This value (in usec) is the period before which the BIOS can ask us
 * to disassociate the primary MAC address when checking on license. The
 * entire handshake must be complete within this time. */
#define HWKEY_SKIP_MAC_TIMEOUT_US           10000000  /* OEM specific */


typedef struct _drv_fw_mb_t
{
    u32_t drv_reset_signature;
        #define DRV_RESET_SIGNATURE                        0x47495352
        #define BIOS_SIGNATURE                             0x534f4942
        /* During BIOS POST, this field will also be used for handshake
         * of challenge-response with the BIOS to confirm its intent.
         * The details of the challenge-response is defined in the
         * implementation. */

    u32_t drv_mb;
        #define DRV_MSG_CODE                               0xff000000
        #define DRV_MSG_CODE_RESET                         0x01000000
        #define DRV_MSG_CODE_UNLOAD                        0x02000000
        #define DRV_MSG_CODE_SHUTDOWN                      0x03000000
        #define DRV_MSG_CODE_SUSPEND_WOL                   0x04000000
        #define DRV_MSG_CODE_FW_TIMEOUT                    0x05000000
        #define DRV_MSG_CODE_UNUSED                        0x06000000
        #define DRV_MSG_CODE_DIAG                          0x07000000
        #define DRV_MSG_CODE_VALIDATE_KEY                  0x08000000
        #define DRV_MSG_CODE_SUSPEND_NO_WOL                0x09000000
        #define DRV_MSG_CODE_GET_CURR_KEY                  0x0a000000
        #define DRV_MSG_CODE_UNLOAD_LNK_DN                 0x0b000000
        #define DRV_MSG_CODE_FIO_ACCESS                    0x0c000000
        #define DRV_MSG_CODE_KEEP_VLAN_UPDATE              0x0d000000
        #define DRV_MSG_CODE_CMD_SET_LINK                  0x10000000
        #define DRV_MSG_CODE_CMD_REMOTE_PHY_MDIO           0x40000000
        #define BIOS_MSG_CODE_HANDSHAKE                    0xff000000  /* OEM specific */

        #define DRV_MSG_DATA                               0x00ff0000
        #define DRV_MSG_DATA_WAIT0                         0x00010000
        #define DRV_MSG_DATA_WAIT1                         0x00020000
        #define DRV_MSG_DATA_WAIT2                         0x00030000
        #define DRV_MSG_DATA_WAIT3                         0x00040000
        #define DRV_MSG_DATA_WAIT_RESET                    0x00050000
        #define DRV_MSG_DATA_WAIT4                         0x00060000
        /* Used by DRV_MSG_CODE_VALIDATE_KEY command */
        #define DRV_MSG_DATA_MANUF_KEY                     0x00010000
        #define DRV_MSG_DATA_UPGRADE_KEY                   0x00020000
        /* Used by BIOS_MSG_CODE_HANDSHAKE command */
        #define BIOS_MSG_DATA_REQ                          0x00010000  /* OEM specific */
        #define BIOS_MSG_DATA_CONFIRM                      0x00020000  /* OEM specific */
        /* Used by BIOS_MSG_CODE_HANDSHAKE command and...
           The VIRT_*_MAC command requires two arguments in mb_args[].
           The top 16 bit of the first argument needs to be
           VIRT_MAC_SIGNATURE. The remaining six bytes (two from first
           argument, four from the second one) will be the MAC address.
           However, if all F's are used as MAC, boot code will treat
           this as reverting back to the original MAC in the NVRAM.
           */
        #define BIOS_MSG_DATA_USE_VIRT_PRIM_MAC            0x00030000  /* OEM specific */
        #define BIOS_MSG_DATA_USE_VIRT_ISCSI_MAC           0x00040000  /* OEM specific */
        /* Used by DRV_MSG_CODE_FIO_ACCESS command */
        #define DRV_MSG_DATA_FIO_READ                      0x00000000
        #define DRV_MSG_DATA_FIO_WRITE                     0x00010000

        #define DRV_MSG_SEQ                                0x0000ffff

    u32_t fw_mb;
        #define FW_SIGN_PRESERVE_MEMORY                    0x55aa5a5a
        #define FW_MSG_ACK                                 0x0000ffff
        #define FW_MSG_STATUS_MASK                         0x00ff0000
        #define FW_MSG_STATUS_OK                           0x00000000
        #define FW_MSG_STATUS_FAILURE                      0x00ff0000
        #define FW_MSG_STATUS_INVALID_ARGS                 0x00010000
        #define FW_MSG_STATUS_DRV_PRSNT                    0x00020000
        /* This "signature" is used to preserve memory content from
         * the hard reset issued by the boot code.
         */

    u32_t link_status;
    /* See netlink.h for bit definitions */
        #define FW_LINK_STATUS_BUSY                        0x0005A000
        #define FW_LINK_STATUS_CABLE_SENSE_MASK            0x40000000
        #define FW_LINK_STATUS_SW_TIMER_EVENT_MASK         0x80000000

    u32_t drv_pulse_mb;
        #define DRV_PULSE_SEQ_MASK                         0x00007fff
        #define DRV_PULSE_SYSTEM_TIME_MASK                 0xffff0000
        /* The system time is in the format of
         * (year-2001)*12*32 + month*32 + day. */
        #define DRV_PULSE_ALWAYS_ALIVE                     0x00008000
        /* Indicate to the firmware not to go into the
         * OS absent when it is not getting driver pulse.
         * This is used for debugging as well for PXE(MBA). */

    u32_t mb_args[2];
    /* This can be used to pass arguments to handshake with
     * firmware. */

    u32_t reserved[1];
} drv_fw_mb_t;



typedef struct _shared_hw_cfg_t
{
    u8_t  part_num[16];    /* Up to 16 bytes of NULL-terminated string */
    u32_t power_dissipated;
        #define SHARED_HW_CFG_POWER_STATE_D3_MASK          0xff000000
        #define SHARED_HW_CFG_POWER_STATE_D2_MASK          0xff0000
        #define SHARED_HW_CFG_POWER_STATE_D1_MASK          0xff00
        #define SHARED_HW_CFG_POWER_STATE_D0_MASK          0xff
    u32_t power_consumed;
    u32_t config;
        #define SHARED_HW_CFG_DESIGN_NIC                   0
        #define SHARED_HW_CFG_DESIGN_LOM                   0x1
        #define SHARED_HW_CFG_PORT_SWAP                    0x2   /* Xinan only */
        #define SHARED_HW_CFG_VAUX_OVERDRAW                0x4
        #define SHARED_HW_CFG_UMP_USE_MII                  0     /* TetonII */
        #define SHARED_HW_CFG_UMP_USE_RMII                 0x8   /* TetonII */
        #define SHARED_HW_CFG_WOL_ENABLE_BEACON            0x10  /* TetonII, on by hw default */
        #define SHARED_HW_CFG_PHY_FIBER_2_5G               0x20  /* TetonII/Xinan, off (1G only) by default */
        #define SHARED_HW_CFG_BACKPLANE_APP                0x40  /* TetonII/Xinan fiber */
        #define SHARED_HW_CFG_CRS_DV_SRC_SELECT_RXDV       0
        #define SHARED_HW_CFG_CRS_DV_SRC_SELECT_CRS        0x80  /* TetonII B0 and after */
        #define SHARED_HW_CFG_LED_MODE_SHIFT_BITS          8     /* Teton/TetonII only */
        #define SHARED_HW_CFG_LED_MODE_MASK                0x700 /* Teton/TetonII only */
        #define SHARED_HW_CFG_LED_MODE_MAC                 0     /* Teton/TetonII only */
        #define SHARED_HW_CFG_LED_MODE_GPHY1               0x100 /* Teton/TetonII only */
        #define SHARED_HW_CFG_LED_MODE_GPHY2               0x200 /* Teton/TetonII only */
        #define SHARED_HW_CFG_LED_MODE_GPHY3               0x300 /* Teton/TetonII only */
        #define SHARED_HW_CFG_LED_MODE_GPHY4               0x400 /* Teton/TetonII only */
        #define SHARED_HW_CFG_LED_MODE_GPHY5               0x500 /* Teton/TetonII only */
        #define SHARED_HW_CFG_LED_MODE_GPHY6               0x600 /* Teton/TetonII only */
        #define SHARED_HW_CFG_LED_MODE_GPHY7               0x700 /* Teton/TetonII only */
        #define SHARED_HW_CFG_UMP_PHY_TIMING_ENABLE        0x800 /* TetonII B0 and after */
        #define SHARED_HW_CFG_UMP_PHY_TIMING_DISABLE       0     /* TetonII B0 and after */
        /* Select a GPIO to determine what mgmt fw to run, GPIO1 for ignore */
        #define SHARED_HW_CFG_MFW_CHOICE_SHIFT_BITS        12
        #define SHARED_HW_CFG_MFW_CHOICE_GPIO_MASK         0x7000   /* Teton/TetonII only */
        #define SHARED_HW_CFG_MFW_CHOICE_IGNORE            0x0000   /* Teton/TetonII only */
        #define SHARED_HW_CFG_MFW_CHOICE_UNUSED1           0x1000   /* Teton/TetonII only */
        #define SHARED_HW_CFG_MFW_CHOICE_UNUSED2           0x2000   /* Teton/TetonII only */
        #define SHARED_HW_CFG_MFW_CHOICE_GPIO3             0x3000   /* Teton/TetonII only */
        #define SHARED_HW_CFG_MFW_CHOICE_GPIO4             0x4000   /* Teton/TetonII only */
        #define SHARED_HW_CFG_MFW_CHOICE_GPIO5             0x5000   /* Teton/TetonII only */
        #define SHARED_HW_CFG_MFW_CHOICE_GPIO6             0x6000   /* Teton/TetonII only */
        #define SHARED_HW_CFG_MFW_CHOICE_GPIO7             0x7000   /* Teton/TetonII only */
        #define SHARED_HW_CFG_MFW_CHOICE_MASK              0x7000   /* Xinan only */
        #define SHARED_HW_CFG_MFW_CHOICE_ANY               0x0000   /* Xinan only */
        #define SHARED_HW_CFG_MFW_CHOICE_NCSI              0x1000   /* Xinan only */
        #define SHARED_HW_CFG_MFW_CHOICE_UMP               0x2000   /* Xinan only */
        #define SHARED_HW_CFG_MFW_CHOICE_IPMI              0x3000   /* Xinan only */
        #define SHARED_HW_CFG_MFW_CHOICE_SPIO4_NCSI0_IPMI1 0x4000   /* Xinan only */
        #define SHARED_HW_CFG_MFW_CHOICE_SPIO4_UMP0_IPMI1  0x5000   /* Xinan only */
        #define SHARED_HW_CFG_MFW_CHOICE_SPIO4_NCSI0_UMP1  0x6000   /* Xinan only */
        #define SHARED_HW_CFG_MFW_CHOICE_RESERVED          0x7000   /* Xinan only */
        #define SHARED_HW_CFG_GIG_LINK_ON_VAUX             0x8000
        #define SHARED_HW_CFG_LED_APP_MASK                 0x30000  /* TetonII fiber (A0 and B0) only */
        #define SHARED_HW_CFG_LED_APP_INDEPENDENT          0x00000  /* TetonII fiber (A0 and B0) only */
        #define SHARED_HW_CFG_LED_APP_MULTI_COLOR          0x10000  /* TetonII fiber (A0 and B0) only */
        #define SHARED_HW_CFG_LED_APP_ALL_TIED             0x20000  /* TetonII fiber (A0 and B0) only */
        #define SHARED_HW_CFG_DUAL_MAC_MASK                0x30000  /* Xinan only */
        #define SHARED_HW_CFG_DUAL_MAC_BOTH                0x00000  /* Xinan only */
        #define SHARED_HW_CFG_DUAL_MAC_RESERVED            0x10000  /* Xinan only */
        #define SHARED_HW_CFG_DUAL_MAC_HIDE_FN1            0x20000  /* Xinan only */
        #define SHARED_HW_CFG_DUAL_MAC_INVALID             0x30000  /* Xinan only */
        #define SHARED_HW_CFG_PCIE_GEN2_ENABLE             0x40000  /* Xinan only */
        #define SHARED_HW_CFG_SMBUS_TIMING_100KHZ          0x0      /* Xinan only */
        #define SHARED_HW_CFG_SMBUS_TIMING_400KHZ          0x80000  /* Xinan only */
        #define SHARED_HW_CFG_PREVENT_PCIE_L1_ENTRY        0x100000 /* Xinan only */
        #define SHARED_HW_CFG_DUAL_MEDIA_CFG_MASK          0xe00000   /* Xinan only: reserved for future support */
        #define SHARED_HW_CFG_NO_LINK_FLAP                 0x1000000  /* Xinan copper AN only */
        #define SHARED_HW_CFG_DUAL_MEDIA_OVERRIDE          0x2000000  /* Xinan only: reserved for future support */
        #define SHARED_HW_CFG_GEN2_TX_PREEMP_MASK          0xf0000000  /* Xinan only */
        #define SHARED_HW_CFG_GEN2_TX_PREEMP_HW            0x00000000  /* Xinan only: HW and 0_0DB are swapped in hw register */
        #define SHARED_HW_CFG_GEN2_TX_PREEMP_0_0DB         0xc0000000  /* Xinan only: HW and 0_0DB are swapped in hw register */
        #define SHARED_HW_CFG_GEN2_TX_PREEMP_3_5DB         0xa0000000  /* Xinan only */
        #define SHARED_HW_CFG_GEN2_TX_PREEMP_6_0DB         0xe0000000  /* Xinan only */
    u32_t config2;
        #define SHARED_HW_CFG2_NVM_SIZE_MASK               0xfff000
    u32_t shared_eco_ctl;
        /* The bit definitions below are for TetonII only */
        #define SHARED_ECO_CTL_ECO203_EPB_0x78_BIT02       0x4
        #define SHARED_ECO_CTL_ECO204_EPB_0x78_BIT31       0x80000000
        #define SHARED_ECO_CTL_ECO206_EPB_0x78_BIT03       0x8
        #define SHARED_ECO_CTL_ECO207_EPB_0x48_BIT24       0x100    /* Need to shift 16 bits to left */
        #define SHARED_ECO_CTL_EPB_0x48_SHIFT_BITS         16       /* Need to shift 16 bits to left */
        #define SHARED_ECO_CTL_ECO208_EPB_0x7C_BIT30       0x40000000
        #define SHARED_ECO_CTL_ECO209_EPB_0x7C_BIT24       0x1000000
        #define SHARED_ECO_CTL_ECO210_EPB_0x78_BIT26       0x4000000
        #define SHARED_ECO_CTL_EPB_0x78_MASK               (SHARED_ECO_CTL_ECO203_EPB_0x78_BIT02 | \
                                                            SHARED_ECO_CTL_ECO206_EPB_0x78_BIT03 | \
                                                            SHARED_ECO_CTL_ECO210_EPB_0x78_BIT26 | \
                                                            SHARED_ECO_CTL_ECO204_EPB_0x78_BIT31)
        #define SHARED_ECO_CTL_EPB_0x7C_MASK               (SHARED_ECO_CTL_ECO209_EPB_0x7C_BIT24 | \
                                                            SHARED_ECO_CTL_ECO208_EPB_0x7C_BIT30)
        #define SHARED_ECO_CTL_EPB_0x48_MASK               (SHARED_ECO_CTL_ECO207_EPB_0x48_BIT24)
    u32_t reserved[1];     /* Any common info to all ports */
} shared_hw_cfg_t;




#define PORT_HW_CFG_RESERVED_WORD_CNT 6
typedef struct _port_hw_cfg_t
{
    /* Fields below are port specific (in anticipation of dual port devices */
    u32_t mac_upper;
        #define PORT_HW_CFG_UPPERMAC_MASK                  0xffff
    u32_t mac_lower;
    u32_t config;
        #define PORT_HW_CFG_SERDES_TXCTL3_MASK             0xffff
        #define PORT_HW_CFG_DEFAULT_LINK_MASK              0x1f0000
        #define PORT_HW_CFG_DEFAULT_LINK_AN                0x0
        #define PORT_HW_CFG_DEFAULT_LINK_SPEED_MASK        0x070000
        #define PORT_HW_CFG_DEFAULT_LINK_1G                0x030000
        #define PORT_HW_CFG_DEFAULT_LINK_2_5G              0x040000
        #define PORT_HW_CFG_DEFAULT_LINK_AN_FALLBACK_MASK  0x100000
        #define PORT_HW_CFG_DEFAULT_LINK_AN_1G_FALLBACK    0x130000
        #define PORT_HW_CFG_DEFAULT_LINK_AN_2_5G_FALLBACK  0x140000
        #define PORT_HW_CFG_DISABLE_PCIE_RELAX_ORDER       0x200000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_MASK               0x0f000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_MAC                0x00000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_PHY1               0x01000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_PHY2               0x02000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_PHY3               0x03000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_MAC2               0x04000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_PHY4               0x05000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_PHY5               0x06000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_PHY6               0x07000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_MAC3               0x08000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_PHY7               0x09000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_PHY8               0x0a000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_PHY9               0x0b000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_MAC4               0x0c000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_PHY10              0x0d000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_PHY11              0x0e000000 /* Xinan only */
        #define PORT_HW_CFG_XI_LED_MODE_UNUSED             0x0f000000 /* Xinan only */
    u32_t l2_reserved[5];
    u32_t pci_id;              /* Xinan only */
        #define PORT_HW_CFG_PCI_VENDOR_ID_MASK             0xffff0000
        #define PORT_HW_CFG_PCI_DEVICE_ID_MASK             0x0ffff
    u32_t pci_sub_id;          /* Xinan only */
        #define PORT_HW_CFG_PCI_SUBSYS_DEVICE_ID_MASK      0xffff0000
        #define PORT_HW_CFG_PCI_SUBSYS_VENDOR_ID_MASK      0x0ffff
    u32_t iscsi_mac_upper; /* Upper 16 bits are always zeroes */
    u32_t iscsi_mac_lower;
    u32_t backup_l2_mac_upper; /* Upper 16 bits are reserved, could be...  */
    u32_t backup_l2_mac_lower; /* non-zeroes, used by OEM software (BIOS?) */
    u32_t port_eco_ctl;

    /* The reserved fields must have values of 0 */
    /* Reserving fields for L4, L5, and iSCSI config for a specific port. */
    u32_t reserved[PORT_HW_CFG_RESERVED_WORD_CNT];

} port_hw_cfg_t;


typedef struct _shared_feat_cfg_t
{
    u32_t config;  /* Any features common to all ports */
        #define SHARED_FEATURE_ENABLE_ISCSI_OFLD           0x1        /* For Linux of one OEM */
        #define SHARED_FEATURE_RESERVED_MASK               0xfffffffe
    u32_t reserved[3];
} shared_feat_cfg_t;


typedef struct _res_alloc_t
{
    u32_t version;
        #define RES_VER_STRING                             'A'
        #define RES_VER_STRING_MASK                        0xff000000
        #define RES_VER_STRING_SHIFT_BITS                  24
        /* These bits are maintained by BACS, no other SW/FW entity
         * should manipulate them. They are consumed by TOE/iSCSI FW. */
        #define RES_RES_CFG_TOE_IPV6                       (0x1 << 0)
        #define RES_RES_CFG_ISCSI_IPV6                     (0x1 << 1)

    u32_t res_cfg;
        /* Used for the users to decide what they want */
        #define RES_RES_CFG_VALID                          0x01
        /* Overloading with VPD FDO, should be okay. */
        #define RES_RES_CFG_DIAG                           0x02
        #define RES_RES_CFG_L2                             0x04
        #define RES_RES_CFG_ISCSI                          0x08
        #define RES_RES_CFG_RDMA                           0x10
        #define RES_RES_CFG_FCFS_DISABLED                  0x80000000UL
    u32_t enum_val;
        /* Used for the base driver to figure out what to enumerate */
        #define RES_ENUM_VALID                   RES_RES_CFG_VALID
        #define RES_ENUM_VAL_DIAG                RES_RES_CFG_DIAG
        #define RES_ENUM_VAL_L2                  RES_RES_CFG_L2
        #define RES_ENUM_VAL_ISCSI               RES_RES_CFG_ISCSI
        #define RES_ENUM_VAL_RDMA                RES_RES_CFG_RDMA
        #define RES_ENUM_VAL_UNUSED              RES_RES_CFG_FCFS_DISABLED

    u32_t conn_resource1;
        #define RES_CONN_RDMA_MASK                         0xffff0000
        #define RES_CONN_TOE_MASK                          0xffff
    u32_t conn_resource2;
        #define RES_CONN_ISCSI_MASK                        0xffff0000
        #define RES_CONN_ISER_MASK                         0xffff
    u32_t conn_resource3;
        #define RES_CONN_UNUSED                            0xffff0000
        /* iSCSI pending tasks: range from 32 to 2048, relevent when
         * RES_RES_CFG_ISCSI flag is set. */
        #define RES_CONN_ISCSI_PTASK_MASK                  0xffff
    u32_t conn_resource4;

} res_alloc_t;


#define PORT_FEAT_CFG_RESERVED_WORD_CNT                    14
typedef struct _port_feat_cfg_t
{
    u32_t config;
        #define PORT_FEATURE_FORCE_EXPROM_ENABLED          0x00800000
        #define PORT_FEATURE_WOL_ENABLED                   0x01000000
        #define PORT_FEATURE_MBA_ENABLED                   0x02000000
        #define PORT_FEATURE_MFW_ENABLED                   0x04000000
        #define PORT_FEATURE_RPHY_ENABLED                  0x08000000
        #define PORT_FEATURE_PCIE_CAPABILITY_MASK          0xf0  /* Xinan only */
        #define PORT_FEATURE_PCIE_CAPABILITY_ALL           0xf0  /* Xinan only */
        #define PORT_FEATURE_PCIE_CAPABILITY_ALL_DEF       0x0   /* Xinan only */
        #define PORT_FEATURE_BAR1_SIZE_MASK                0xf
        #define PORT_FEATURE_BAR1_SIZE_DISABLED            0x0
        #define PORT_FEATURE_BAR1_SIZE_64K                 0x1
        #define PORT_FEATURE_BAR1_SIZE_128K                0x2
        #define PORT_FEATURE_BAR1_SIZE_256K                0x3
        #define PORT_FEATURE_BAR1_SIZE_512K                0x4
        #define PORT_FEATURE_BAR1_SIZE_1M                  0x5
        #define PORT_FEATURE_BAR1_SIZE_2M                  0x6
        #define PORT_FEATURE_BAR1_SIZE_4M                  0x7
        #define PORT_FEATURE_BAR1_SIZE_8M                  0x8
        #define PORT_FEATURE_BAR1_SIZE_16M                 0x9
        #define PORT_FEATURE_BAR1_SIZE_32M                 0xa
        #define PORT_FEATURE_BAR1_SIZE_64M                 0xb
        #define PORT_FEATURE_BAR1_SIZE_128M                0xc
        #define PORT_FEATURE_BAR1_SIZE_256M                0xd
        #define PORT_FEATURE_BAR1_SIZE_512M                0xe
        #define PORT_FEATURE_BAR1_SIZE_1G                  0xf
    u32_t wol_config;
        /* Default is used when driver sets to "auto" mode */
        #define FEATURE_WOL_DEFAULT_SHIFT_BITS             4
        #define FEATURE_WOL_DEFAULT_MASK                   0x30
        #define FEATURE_WOL_DEFAULT_DISABLE                0
        #define FEATURE_WOL_DEFAULT_MAGIC                  0x10
        #define FEATURE_WOL_DEFAULT_ACPI                   0x20
        #define FEATURE_WOL_DEFAULT_MAGIC_AND_ACPI         0x30
        #define FEATURE_WOL_LINK_SPEED_MASK                0xf
        #define FEATURE_WOL_LINK_SPEED_AUTONEG             0
        #define FEATURE_WOL_LINK_SPEED_10HALF              1
        #define FEATURE_WOL_LINK_SPEED_10FULL              2
        #define FEATURE_WOL_LINK_SPEED_100HALF             3
        #define FEATURE_WOL_LINK_SPEED_100FULL             4
        #define FEATURE_WOL_LINK_SPEED_1000HALF            5
        #define FEATURE_WOL_LINK_SPEED_1000FULL            6
        #define FEATURE_WOL_LINK_SPEED_2500HALF            7
        #define FEATURE_WOL_LINK_SPEED_2500FULL            8
        #define FEATURE_WOL_AUTONEG_LIMIT_MASK             0xc0
        #define FEATURE_WOL_AUTONEG_LIMIT_10               0x80
        #define FEATURE_WOL_AUTONEG_LIMIT_100              0x00
        #define FEATURE_WOL_AUTONEG_LIMIT_1000             0x40
        #define FEATURE_WOL_AUTONEG_ADVERTISE_1000         0x40
        #define FEATURE_WOL_RESERVED_PAUSE_CAP             0x400
        #define FEATURE_WOL_RESERVED_ASYM_PAUSE_CAP        0x800
    u32_t mba_config;
        #define FEATURE_MBA_BOOT_AGENT_TYPE_SHIFT_BITS     0
        #define FEATURE_MBA_BOOT_AGENT_TYPE_SHIFT_BITS2    20
        #define FEATURE_MBA_BOOT_AGENT_TYPE_MASK           0x400003
        #define FEATURE_MBA_BOOT_AGENT_TYPE_PXE            0
        #define FEATURE_MBA_BOOT_AGENT_TYPE_RPL            1
        #define FEATURE_MBA_BOOT_AGENT_TYPE_BOOTP          2
        #define FEATURE_MBA_BOOT_AGENT_TYPE_ISCSIB         3
        #define FEATURE_MBA_BOOT_AGENT_TYPE_FCOE           0x400000
        #define FEATURE_MBA_BOOT_AGENT_TYPE_RESERVED_1     0x400001
        #define FEATURE_MBA_BOOT_AGENT_TYPE_RESERVED_2     0x400002
        #define FEATURE_MBA_BOOT_AGENT_TYPE_NONE           0x400003
        #define FEATURE_MBA_LINK_SPEED_SHIFT_BITS          2
        #define FEATURE_MBA_LINK_SPEED_MASK                0x3c
        #define FEATURE_MBA_LINK_SPEED_AUTONEG             0
        #define FEATURE_MBA_LINK_SPEED_10HALF              0x4
        #define FEATURE_MBA_LINK_SPEED_10FULL              0x8
        #define FEATURE_MBA_LINK_SPEED_100HALF             0xc
        #define FEATURE_MBA_LINK_SPEED_100FULL             0x10
        #define FEATURE_MBA_LINK_SPEED_1000HALF            0x14
        #define FEATURE_MBA_LINK_SPEED_1000FULL            0x18
        #define FEATURE_MBA_LINK_SPEED_2500HALF            0x1c
        #define FEATURE_MBA_LINK_SPEED_2500FULL            0x20
        #define FEATURE_MBA_SETUP_PROMPT_ENABLE            0x40
        #define FEATURE_MBA_HOTKEY_CTRL_S                  0
        #define FEATURE_MBA_HOTKEY_CTRL_B                  0x80
        #define FEATURE_MBA_EXP_ROM_SIZE_SHIFT_BITS        8
        #define FEATURE_MBA_EXP_ROM_SIZE_MASK              0xff00
        #define FEATURE_MBA_EXP_ROM_SIZE_DISABLED          0
        #define FEATURE_MBA_EXP_ROM_SIZE_1K                0x100
        #define FEATURE_MBA_EXP_ROM_SIZE_2K                0x200
        #define FEATURE_MBA_EXP_ROM_SIZE_4K                0x300
        #define FEATURE_MBA_EXP_ROM_SIZE_8K                0x400
        #define FEATURE_MBA_EXP_ROM_SIZE_16K               0x500
        #define FEATURE_MBA_EXP_ROM_SIZE_32K               0x600
        #define FEATURE_MBA_EXP_ROM_SIZE_64K               0x700
        #define FEATURE_MBA_EXP_ROM_SIZE_128K              0x800
        #define FEATURE_MBA_EXP_ROM_SIZE_256K              0x900
        #define FEATURE_MBA_EXP_ROM_SIZE_512K              0xa00
        #define FEATURE_MBA_EXP_ROM_SIZE_1M                0xb00
        #define FEATURE_MBA_EXP_ROM_SIZE_2M                0xc00
        #define FEATURE_MBA_EXP_ROM_SIZE_4M                0xd00
        #define FEATURE_MBA_EXP_ROM_SIZE_8M                0xe00
        #define FEATURE_MBA_EXP_ROM_SIZE_16M               0xf00
        #define FEATURE_MBA_MSG_TIMEOUT_SHIFT_BITS         16
        #define FEATURE_MBA_MSG_TIMEOUT_MASK               0xf0000
        #define FEATURE_MBA_BIOS_BOOTSTRAP_SHIFT_BITS      20
        #define FEATURE_MBA_BIOS_BOOTSTRAP_MASK            0x300000
        #define FEATURE_MBA_BIOS_BOOTSTRAP_AUTO            0
        #define FEATURE_MBA_BIOS_BOOTSTRAP_BBS             0x100000
        #define FEATURE_MBA_BIOS_BOOTSTRAP_INT18H          0x200000
        #define FEATURE_MBA_BIOS_BOOTSTRAP_INT19H          0x300000
        #define FEATURE_MBA_BOOT_RETRY_MASK                0x3800000 /* bit 25 24 23*/
        #define FEATURE_MBA_BOOT_RETRY_SHIFT_BITS          23
    u32_t bmc_common;
        #define FEATURE_BMC_CMN_UNUSED_0                   0x1 /* Used to be link override */
        #define FEATURE_BMC_CMN_ECHO_MODE_ENABLE           0x2
        #define FEATURE_BMC_CMN_UNUSED_2                   0x4
        #define FEATURE_BMC_CMN_UMP_ID_ENABLE              0x8  /* Xinan only */
        #define FEATURE_BMC_CMN_UMP_ID_MASK                0x30 /* Xinan only */
    u32_t mba_vlan_cfg;
        #define FEATURE_MBA_VLAN_TAG_MASK                  0xffffL
        #define FEATURE_MBA_VLAN_ENABLE                    0x10000L

    res_alloc_t resource;

    u32_t smbus_config;
        #define FEATURE_SMBUS_ENABLE                       1 /* Obsolete */
        #define FEATURE_SMBUS_ADDR_MASK                    0xfe

    u32_t iscsib_basic_config;
        #define FEATURE_ISCSIB_SKIP_TARGET_BOOT            1

    union u_t
    {
        u32_t t2_epb_cfg;
            #define T2_EPB_CFG_ENABLED                     0x80000000
            #define T2_EPB_CFG_OPT_L23                     0x40000000
            #define T2_EPB_CFG_OPT_NIC_D3                  0x20000000
            #define T2_EPB_CFG_OPT_INACTIVITY_CHK          0x10000000
            #define T2_EPB_CFG_OPT_ACTIVITY_CHK            0x8000000
            #define T2_EPB_CFG_OPT_PREP_L23                0x4000000
            #define T2_EPB_CFG_IDLE_TMR_MS_MASK            0xffff
            #define T2_EPB_FORCED_L1_VALUE                 0xd8000bb8
#ifdef SOLARIS
    } u1;
#else
    } u;
#endif

    u32_t reserved[PORT_FEAT_CFG_RESERVED_WORD_CNT];

} port_feat_cfg_t;



#ifdef SOLARIS
typedef struct _bnx2shm_dev_info_t
#else
typedef struct _dev_info_t
#endif
{
    u32_t signature;
        #define DEV_INFO_SIGNATURE_MASK                    0xffffff00
        #define DEV_INFO_SIGNATURE                         0x44564900
        #define DEV_INFO_FEATURE_CFG_VALID                 0x01
        #define DEV_INFO_KEY_IN_EFFECT_MASK                0x06
        #define DEV_INFO_MANUF_KEY_IN_EFFECT               0x02
        #define DEV_INFO_UPGRADE_KEY_IN_EFFECT             0x04
        #define DEV_INFO_NO_KEY_IN_EFFECT                  0x06
        #define DEV_INFO_DRV_ALWAYS_ALIVE                  0x40
        //#define DEV_INFO_SECONDARY_PORT                    0x80

    shared_hw_cfg_t shared_hw_config;

    u32_t bc_rev;              /* 8 bits each: Major, minor, build, 0x05 */

    port_hw_cfg_t port_hw_config;

    u32_t virt_prim_mac_upper;  /* Upper 16 bits are a signature */
        #define VIRT_MAC_SIGN_MASK                         0xffff0000
        #define VIRT_MAC_SIGNATURE                         0x564d0000
    u32_t virt_prim_mac_lower;
    u32_t virt_iscsi_mac_upper; /* Upper 16 bits are a signature */
    u32_t virt_iscsi_mac_lower;
    u32_t unused_a[4];

    /* Format revision: applies to shared and port features */
    u32_t format_rev;
        #define FEATURE_FORMAT_REV_MASK                    0xff000000
        #define FEATURE_FORMAT_REV_ID                      ('A' << 24)
    shared_feat_cfg_t shared_feature_config;
    port_feat_cfg_t port_feature_config;

    u32_t mfw_ver_ptr;
        /* Valid only when mgmt FW is loaded (see CONDITION_MFW_RUN_MASK field). */
        #define MFW_VER_PTR_MASK                          0x00ffffff
    u32_t inv_table_ptr;
        /* This is a scratchpad address for mgmt FW to use. */
    u32_t unused_b[(sizeof(port_feat_cfg_t))/4 - 2];

#ifdef SOLARIS
} bnx2shm_dev_info_t;
#else
} dev_info_t;
#endif



typedef struct _bc_state_t
{
    u32_t reset_type;
        #define RESET_TYPE_SIGNATURE_MASK        0x0000ffff
        #define RESET_TYPE_SIGNATURE             0x00005254
        #define RESET_TYPE_NONE                  (RESET_TYPE_SIGNATURE |\
                                                  0x00010000)
        #define RESET_TYPE_PCI                   (RESET_TYPE_SIGNATURE |\
                                                  0x00020000)
        #define RESET_TYPE_VAUX                  (RESET_TYPE_SIGNATURE |\
                                                  0x00030000)
        #define RESET_TYPE_DRV_MASK              DRV_MSG_CODE
        #define RESET_TYPE_DRV_RESET             (RESET_TYPE_SIGNATURE |\
                                                  DRV_MSG_CODE_RESET)
        #define RESET_TYPE_DRV_UNLOAD            (RESET_TYPE_SIGNATURE |\
                                                  DRV_MSG_CODE_UNLOAD)
        #define RESET_TYPE_DRV_SHUTDOWN          (RESET_TYPE_SIGNATURE |\
                                                  DRV_MSG_CODE_SHUTDOWN)
        #define RESET_TYPE_DRV_SUSPEND_NO_WOL    (RESET_TYPE_SIGNATURE |\
                                                  DRV_MSG_CODE_SUSPEND_NO_WOL)
        #define RESET_TYPE_DRV_SUSPEND_WOL       (RESET_TYPE_SIGNATURE |\
                                                  DRV_MSG_CODE_SUSPEND_WOL)
        #define RESET_TYPE_DRV_FW_TIMEOUT        (RESET_TYPE_SIGNATURE |\
                                                  DRV_MSG_CODE_FW_TIMEOUT)
        #define RESET_TYPE_DRV_DIAG              (RESET_TYPE_SIGNATURE |\
                                                  DRV_MSG_CODE_DIAG)
        #define RESET_TYPE_DRV_UNLOAD_LNK_DN     (RESET_TYPE_SIGNATURE |\
                                                  DRV_MSG_CODE_UNLOAD_LNK_DN)
        #define RESET_TYPE_VALUE(msg_code)       (RESET_TYPE_SIGNATURE |\
                                                  (msg_code))
    u32_t state;
        #define BC_STATE_ERR_MASK                0x0000ff00
        #define BC_STATE_SIGN_MASK               0xffff0000
        #define BC_STATE_SIGN                    0x42530000
        #define BC_STATE_BC1_START               (BC_STATE_SIGN | 0x1)  /* not used */
        #define BC_STATE_GET_NVM_CFG1            (BC_STATE_SIGN | 0x2)  /* not used */
        #define BC_STATE_PROG_BAR                (BC_STATE_SIGN | 0x3)  /* not used */
        #define BC_STATE_INIT_VID                (BC_STATE_SIGN | 0x4)  /* not used */
        #define BC_STATE_GET_NVM_CFG2            (BC_STATE_SIGN | 0x5)  /* not used */
        #define BC_STATE_APPLY_WKARND            (BC_STATE_SIGN | 0x6)  /* not used */
        #define BC_STATE_LOAD_BC2                (BC_STATE_SIGN | 0x7)  /* not used */
        #define BC_STATE_GOING_BC2               (BC_STATE_SIGN | 0x8)  /* not used */
        #define BC_STATE_GOING_DIAG              (BC_STATE_SIGN | 0x9)  /* not used */
        #define BC_STATE_RT_FINAL_INIT           (BC_STATE_SIGN | 0x81) /* not used */
        #define BC_STATE_RT_WKARND               (BC_STATE_SIGN | 0x82) /* not used */
        #define BC_STATE_RT_DRV_PULSE            (BC_STATE_SIGN | 0x83) /* not used */
        #define BC_STATE_RT_FIOEVTS              (BC_STATE_SIGN | 0x84) /* not used */
        #define BC_STATE_RT_DRV_CMD              (BC_STATE_SIGN | 0x85) /* not used */
        #define BC_STATE_RT_LOW_POWER            (BC_STATE_SIGN | 0x86) /* not used */
        #define BC_STATE_RT_SET_WOL              (BC_STATE_SIGN | 0x87) /* not used */
        #define BC_STATE_RT_OTHER_FW             (BC_STATE_SIGN | 0x88) /* not used */
        #define BC_STATE_RT_GOING_D3             (BC_STATE_SIGN | 0x89) /* not used */
        #define BC_STATE_ERROR_SET               0x8000
        #define BC_STATE_ERR_BAD_VERSION         (BC_STATE_SIGN | 0x8001)
        #define BC_STATE_ERR_BAD_BC2_CRC         (BC_STATE_SIGN | 0x8002)
        #define BC_STATE_ERR_BC1_LOOP            (BC_STATE_SIGN | 0x8003)
        #define BC_STATE_ERR_UNKNOWN_CMD         (BC_STATE_SIGN | 0x8004)
        #define BC_STATE_ERR_DRV_DEAD            (BC_STATE_SIGN | 0x8005)
        #define BC_STATE_ERR_NO_RXP              (BC_STATE_SIGN | 0x8006)
        #define BC_STATE_ERR_TOO_MANY_RBUF       (BC_STATE_SIGN | 0x8007)
        #define BC_STATE_ERR_BAD_PCI_ID          (BC_STATE_SIGN | 0x8008)
        #define BC_STATE_ERR_FW_TIMEOUT          (BC_STATE_SIGN | 0x8009)
        #define BC_STATE_ERR_BAD_VPD_REQ         (BC_STATE_SIGN | 0x800a)
        #define BC_STATE_ERR_NO_LIC_KEY          (BC_STATE_SIGN | 0x800b)
        #define BC_STATE_ERR_NO_MGMT_FW          (BC_STATE_SIGN | 0x800c)
        #define BC_STATE_ERR_STACK_OVERFLOW      (BC_STATE_SIGN | 0x800d)
        #define BC_STATE_ERR_PCIE_LANE_DOWN      (BC_STATE_SIGN | 0x800e)
        #define BC_STATE_ERR_MEM_PARITY          (BC_STATE_SIGN | 0x800f)
        #define BC_STATE_ERR_WKARND_TOO_LONG     (BC_STATE_SIGN | 0x8010)
    u32_t condition;
        #define CONDITION_INIT_POR               0x00000001
        #define CONDITION_INIT_VAUX_AVAIL        0x00000002
        #define CONDITION_INIT_PCI_AVAIL         0x00000004
        /* The INIT_PCI_RESET is really a reset type, but defining as
         * RESET_TYPE may break backward compatibility. */
        #define CONDITION_INIT_PCI_RESET         0x00000008
        #define CONDITION_INIT_HD_RESET          0x00000010 /* Xinan only */
        #define CONDITION_DRV_PRESENT            0x00000100
        #define CONDITION_LOW_POWER_LINK         0x00000200
        #define CONDITION_CORE_RST_OCCURRED      0x00000400 /* Xinan only */
        #define CONDITION_UNUSED                 0x00000800 /* Obsolete */
        #define CONDITION_BUSY_EXPROM            0x00001000 /* Teton/TetonII only */
        #define CONDITION_MFW_RUN_MASK           0x0000e000
        #define CONDITION_MFW_RUN_UNKNOWN        0x00000000
        #define CONDITION_MFW_RUN_IPMI           0x00002000
        #define CONDITION_MFW_RUN_UMP            0x00004000
        #define CONDITION_MFW_RUN_NCSI           0x00006000
        #define CONDITION_MFW_RUN_NONE           0x0000e000
        /* The followings are for Xinan in managing chip power on both ports */
        #define CONDITION_PM_STATE_MASK          0x00030000 /* Xinan only */
        #define CONDITION_PM_STATE_FULL          0x00030000 /* Xinan only */
        #define CONDITION_PM_STATE_PREP          0x00020000 /* Xinan only */
        #define CONDITION_PM_STATE_UNPREP        0x00010000 /* Xinan only */
        #define CONDITION_PM_RESERVED            0x00000000 /* Xinan only */

        #define CONDITION_WANT_FULL_POWER        0x00030000 /* Obsolete */
        #define CONDITION_WANT_PM_POWER          0x00010000 /* Can still have gigabit in LOMs */ /* Obsolete */
        #define CONDITION_WANT_ZERO_POWER        0x00000000 /* Obsolete */

        #define CONDITION_RXMODE_KEEP_VLAN       0x00040000 /* Mirroring RX_MODE_KEEP_VLAN bit in EMAC */
        #define CONDITION_DRV_WOL_ENABLED        0x00080000 /* Xinan only */
        #define CONDITION_PORT_DISABLED          0x00100000 /* Xinan only: meant to tell driver about port disabled */
        #define CONDITION_DRV_MAYBE_OUT          0x00200000 /* Xinan only for now */
        #define CONDITION_DPFW_DEAD              0x00400000 /* Xinan only for now */
    u32_t override;
        #define OVERRIDE_SIGNATURE_MASK          0xffff0000
        #define OVERRIDE_SIGNATURE               0x424f0000
        #define OVERRIDE_MFW_CHOICE_MASK (CONDITION_MFW_RUN_MASK >> 13)  // 0x7
        #define OVERRIDE_MFW_DONTCARE    (CONDITION_MFW_RUN_UNKNOWN >> 13)  // 0x0
        #define OVERRIDE_MFW_LOAD_IPMI   (CONDITION_MFW_RUN_IPMI >> 13)  // 0x1
        #define OVERRIDE_MFW_LOAD_UMP    (CONDITION_MFW_RUN_UMP >> 13)   // 0x2
        #define OVERRIDE_MFW_LOAD_NCSI   (CONDITION_MFW_RUN_NCSI >> 13)  // 0x3
        #define OVERRIDE_MFW_LOAD_NONE   (CONDITION_MFW_RUN_NONE >> 13)  // 0x7
    u32_t misc;
        #define BC_MISC_PHY_ADDR_MASK               0x1f
    u32_t wol_signature;
        /* This is a simple signature value to indicate WOL being enabled
         * on the next boot code invocation (reset). This allows driver to
         * override the NVRAM setting for S5 WOL. */
        #define WOL_ENABLE_SIGNATURE             0x574f4c00
    u32_t reserved[1];
    u32_t debug_cmd;                                       /* Not used */
        #define BC_DBG_CMD_SIGNATURE_MASK                  0xffff0000
        #define BC_DBG_CMD_SIGNATURE                       0x42440000
        #define BC_DBG_CMD_LOOP_CNT_MASK                   0xffff
        #define BC_DBG_CMD_LOOP_INFINITE                   0xffff
} bc_state_t;

/* This macro is used by to determine whether another
 * software entity exists before making changes to the hardware.
 * FW_TIMEOUT is included to handle the communication loss with the driver.
 * It's better to assume that driver is still running to avoid messing up
 * the driver in this case. */
#define DRV_PRESENT(s)  ( \
        ((shmem_region_t volatile *)s)->bc_state.condition & CONDITION_DRV_PRESENT)

#define PORT_DISABLED(s)  ( \
        ((shmem_region_t volatile *)s)->bc_state.condition & CONDITION_PORT_DISABLED)

#ifdef DEBUG
#define SET_BC_STATE(p,s) \
        { \
            u32_t *ptr; \
            ptr = (u32_t *)&(((shmem_region_t volatile *)p)->bc_state.state); \
            if ((*ptr & BC_STATE_ERR_MASK) == 0) *ptr = s; \
        }
#else
#define SET_BC_STATE(p,s)
#endif

#define MGMTFW_STATE_WORD_SIZE 80
typedef struct _mgmtfw_state_t
{
    /* Allocate 320 bytes for management firmware: still not known exactly
     * how much IMD needs. */
    u32_t opaque[MGMTFW_STATE_WORD_SIZE];
} mgmtfw_state_t;

typedef struct _fw_evt_mb_t
{
    u32_t fw_evt_code_mb;
        #define FW_EVT_CODE_LINK_STATUS_CHANGE_EVENT       0x00000001
        #define FW_EVT_CODE_SW_TIMER_EXPIRATION_EVENT      0x00000000

    u32_t fw_evt_data_mb[3];

} fw_evt_mb_t;


typedef struct drv_fw_cap_mb
{
    u32_t drv_ack_cap_mb;
        #define CAPABILITY_SIGNATURE_MASK                  0xFFFF0000
        #define DRV_ACK_CAP_SIGNATURE                      0x35450000
        #define FW_ACK_DRV_SIGNATURE                       0x52500000
    u32_t fw_cap_mb;
        #define FW_CAP_SIGNATURE                           0xAA550000

        #define FW_CAP_REMOTE_PHY_CAPABLE                  0x00000001
        #define FW_CAP_REMOTE_PHY_PRESENT                  0x00000002   //bit 1 indicates absence or presence of remote phy HW
        #define FW_CAP_UNUSED_BIT3                         0x00000004
        #define FW_CAP_MFW_CAN_KEEP_VLAN                   0x00000008
        #define FW_CAP_BC_CAN_UPDATE_VLAN                  0x00000010

} drv_fw_cap_mb_t;

typedef struct remotephy
{
    u32_t   load_signature;
        #define	REMOTE_PHY_LOAD_SIGNATURE	               0x5a5a5a5a
        #define	REMOTE_PHY_LEGACY_MODE_SIGNATURE           0xFFDEADFF

    u32_t   flags;

    u32_t   serdes_link_pref;

    u32_t   copper_phy_link_pref;

    u32_t   serdes_autoneg_pref;     /* Xinan only, not supported in TetonII */
    u32_t   copper_autoneg_pref;     /* Xinan only, not supported in TetonII */
        /* The bit definitions follow those in netlink.h */

    u32_t   link_backup;             /* Teton II only; Xinan does not restart on driver load */

} remotephy_t;

typedef struct _rt_param_t
{
    /* These parameters are loaded with defaults by bootcode just before
     * ack'ing WAIT1. Since there are two instances of shmem, if the
     * parameter is shared for both ports, only the parameter of the
     * first instance counts. */
    u32_t drv_timeout_val;           /* Xinan only, in (val * 1.5) sec */
    u32_t dpfw_timeout_val;          /* Xinan only, in timer_25mhz_free_run format */
    u32_t reserved[3];
} rt_param_t;

/* Total size should be exactly 1k bytes */
#define KEY_RSVD_DW_CNT                ((52-sizeof(license_key_t))/4)
typedef struct _shmem_region_t
{
    drv_fw_mb_t      drv_fw_mb;        /* 0x000 - 0x01f */
#ifdef SOLARIS
    bnx2shm_dev_info_t dev_info;         /* 0x020 - 0x1bf */
#else
    dev_info_t       dev_info;         /* 0x020 - 0x1bf */
#endif
    bc_state_t       bc_state;         /* 0x1c0 - 0x1df */
    license_key_t    fw_lic_key;       /* 0x1e0 - 0x213 */
    mgmtfw_state_t   mgmtfw_state;     /* 0x214 - 0x353 */
    fw_evt_mb_t      fw_evt_mb;        /* 0x354 - 0x363 */
    drv_fw_cap_mb_t  drv_fw_cap_mb;    /* 0x364 - 0x36b */
    remotephy_t      remotephy;        /* 0x36c - 0x387 */
    u32_t            dpfw_mb;          /* 0x388 - 0x38b */
    rt_param_t       rt_param;         /* 0x38c - 0x39f */
        #define DPFW_MB_FW_ALIVE                           0x00000001
        /* Xinan only: Datapath firmware keeps writing 1 to it and
         * BC keeps clearing it. */
#ifdef SOLARIS
    u32_t            reserved[256 \
                              - sizeof(drv_fw_mb_t)/4 \
                              - sizeof(bnx2shm_dev_info_t)/4  \
                              - sizeof(bc_state_t)/4  \
                              - sizeof(license_key_t)/4  \
                              - KEY_RSVD_DW_CNT \
                              - sizeof(mgmtfw_state_t)/4 \
                              - sizeof(fw_evt_mb_t)/4 \
                              - sizeof(drv_fw_cap_mb_t)/4 \
                              - sizeof(remotephy_t)/4 \
                              - sizeof(u32_t)/4 \
                              - sizeof(rt_param_t)/4 \
                              - sizeof(license_key_t)/4  \
                              - KEY_RSVD_DW_CNT \
                              - 2 \
                              ];
#else
    u32_t            reserved[256 \
                              - sizeof(drv_fw_mb_t)/4 \
                              - sizeof(dev_info_t)/4  \
                              - sizeof(bc_state_t)/4  \
                              - sizeof(license_key_t)/4  \
                              - KEY_RSVD_DW_CNT \
                              - sizeof(mgmtfw_state_t)/4 \
                              - sizeof(fw_evt_mb_t)/4 \
                              - sizeof(drv_fw_cap_mb_t)/4 \
                              - sizeof(remotephy_t)/4 \
                              - sizeof(u32_t)/4 \
                              - sizeof(rt_param_t)/4 \
                              - sizeof(license_key_t)/4  \
                              - KEY_RSVD_DW_CNT \
                              - 2 \
                              ];
#endif
    u32_t            l1_wkarnd_dbg0;   /* 0x3c4: used by TetonII BC only */
    u32_t            l1_wkarnd_dbg1;   /* 0x3c8: used by TetonII BC only */
    license_key_t    drv_lic_key;      /* 0x3cc - 0x3ff */
} shmem_region_t;


#ifdef DOS16BIT_DRIVER
/* These will be generated in 5706_reg.h for 16-bit DOS driver */
#define MCP_SCRATCH         0x160000
#define MCP_UNUSED_E        0x168000
/****************************************/
#define MCP_SCRATCHPAD_START  MCP_SCRATCH
#define MCP_SCRATCHPAD_END    MCP_UNUSED_E
#else
#define MCP_SCRATCHPAD_START ROFFSET(mcp.mcp_scratch)
#define MCP_SCRATCHPAD_END   ROFFSET(mcp.mcp_unused_e)
#endif

#define MCP_TETON_SCRATCH_SIZE 0x8000

/* Add the following to the original shared memory offset if the chip
 * is 5708B0 or after, since it has 8kB more of scratchpad.
 */
#define MCP_SHMEM_5708B0_DELTA 0x2000
#define HOST_VIEW_SHMEM_BASE   (MCP_SCRATCHPAD_START + \
                                MCP_TETON_SCRATCH_SIZE - \
                                sizeof(shmem_region_t)) /* 0x167c00 */
#define SHMEM_BASE           (HOST_VIEW_SHMEM_BASE - MCP_SCRATCHPAD_START)   /* 0x7C00 */


#endif /* _SHMEM_H */

