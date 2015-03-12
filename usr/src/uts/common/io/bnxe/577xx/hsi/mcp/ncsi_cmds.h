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
 * FILE NAME:       ncsi_cmds.h
 *
 * DESCRIPTION:     Note that the response definitions include the notion of
 *                  a rsp Payload consisting of the actual data returned for a 
 *                  given rsp, and the rsp frame Payload consisting of the rsp 
 *                  Payload plus all padding and checksum bytes.  The size of  
 *                  each of these must be understood independently for proper
 *                  programming of the rsp pkt header, and the actual UMP TX
 *                  operation.
 *
 * CONVENTIONS:
 *
 * AUTHOR:          Tim Sharp
 *
 * CREATION DATE:   2007
 *
 * 
 ****************************************************************************/


#ifndef NCSI_CMDS_H
#define NCSI_CMDS_H



/*----------------------------------------------------------------------------
------------------------------ include files ---------------------------------
----------------------------------------------------------------------------*/

#include "bcmtype.h"
#include "ncsi_basic_types.h"

/*----------------------------------------------------------------------------
------------------------------ local definitions -----------------------------

structs, unions, typedefs, #defines, etc belong here...

----------------------------------------------------------------------------*/


typedef enum NcsiGetParameterSelector
{

	NCSI_PARAM_BOOTCODE_REV             = 0,
	NCSI_PARAM_HOST_L2_MAC,
	NCSI_PARAM_ALT_HOST_L2_MAC,
	NCSI_PARAM_HOST_ISCSI_MAC,
	NCSI_PARAM_ALT_HOST_ISCSI_MAC,
	NCSI_PARAM_PXE_BOOT_REV,
	NCSI_PARAM_ISCSI_BOOT_REV,
	NCSI_PARAM_PCI_DEVICE_ID,
	NCSI_PARAM_PCI_VENDOR_ID,
	NCSI_PARAM_PCI_SUBSYSTEM_ID,
	NCSI_PARAM_PCI_SUBSYSTEM_VENDOR_ID

}NcsiGetParameterSelector_t;



/*****************************************************************************

NcsiRmiiControlPktHeader_t

    this structure definition is for the common UMP command/response frame 
    header used in both cmd and rsp pkts.
    
    UMP frame header idntifies wheteher a received packet is to be processed 
    locally or forwarded for transmission.
     
*****************************************************************************/
#define NCSI_CMD_CHANNEL_ID_MAX_VALUE       1

#define NCSI_CMD_HEADER_SIZE                16



typedef struct NcsiControlPktHeader
#if defined (BIG_ENDIAN)
{
	u16_t   PlusTwoPadding;                  /* for plus 2 alignment */
	u8_t    DestAddr[SIZEOF_MAC_ADDRESS];    /* 6                    */
	u8_t    SrcAddr[SIZEOF_MAC_ADDRESS];     /* 12                    */


	u16_t   EtherType;                       /* 14 ids pkt as cmd       */
#define NCSI_ETHER_TYPE_ID             (0x88F8)
	u8_t    McId;


	u8_t    HeaderRevNum;                 /* 16 ids        */
	u8_t    Reserved0;
	u8_t    InstanceId;                     /* 18 ids order of pkts    */


	u8_t    TypeCode;                        /* 19 ids specific command */
#define NCSI_CMD_TYPE_AEN                                   (0xFF)
#define NCSI_CMD_TYPE_MASK                                     (0x7F)
#define NCSI_CMD_TYPE_CLEAR_INITIAL_STATE                       (0x00)
#define NCSI_CMD_TYPE_PACKAGE_SELECT                            (0x01)
#define NCSI_CMD_TYPE_PACKAGE_DESELECT                          (0x02)
#define NCSI_CMD_TYPE_ENABLE_CHANNEL                            (0x03)
#define NCSI_CMD_TYPE_DISABLE_CHANNEL                           (0x04)
#define NCSI_CMD_TYPE_RESET_CHANNEL                             (0x05)
#define NCSI_CMD_TYPE_ENABLE_CHANNEL_EGRESS_TX                  (0x06)
#define NCSI_CMD_TYPE_DISABLE_CHANNEL_EGRESS_TX                 (0x07)
#define NCSI_CMD_TYPE_ENABLE_AEN                                (0x08)
#define NCSI_CMD_TYPE_SET_LINK                                  (0x09)
#define NCSI_CMD_TYPE_GET_LINK_STATUS                           (0x0A)
#define NCSI_CMD_TYPE_SET_VLAN_FILTERS                          (0x0B)
#define NCSI_CMD_TYPE_ENABLE_VLAN                               (0x0C)
#define NCSI_CMD_TYPE_DISABLE_VLAN                              (0x0D)
#define NCSI_CMD_TYPE_SET_MAC_ADDRESS                           (0x0E)
#define NCSI_CMD_TYPE_ENABLE_BROADCAST_PKT_FILTER               (0x10)
#define NCSI_CMD_TYPE_DISABLE_BROADCAST_PKT_FILTER              (0x11)
#define NCSI_CMD_TYPE_ENABLE_MULTICAST_PKT_FILTER               (0x12)
#define NCSI_CMD_TYPE_DISABLE_MULTICAST_PKT_FILTER              (0x13)
#define NCSI_CMD_TYPE_SET_NCSI_FLOW_CONTROL                     (0x14)
#define NCSI_CMD_TYPE_GET_VERSION_ID                            (0x15)
#define NCSI_CMD_TYPE_GET_CAPABILITIES                          (0x16)
#define NCSI_CMD_TYPE_GET_PARAMETERS                            (0x17)
#define NCSI_CMD_TYPE_GET_IF_STATISTICS                         (0x18)
#define NCSI_CMD_TYPE_GET_NCSI_STATISTICS                       (0x19)
#define NCSI_CMD_TYPE_GET_NCSI_PASS_THROUGH_STATISTICS          (0x1A)
#define NCSI_CMD_TYPE_LAST_NON_OEM_CMD                          NCSI_CMD_TYPE_GET_NCSI_PASS_THROUGH_STATISTICS
#define NCSI_CMD_TYPE_OEM                                       (0x50)
#define NCSI_CMD_RESPONSE_BIT                                     (0x80)


	u8_t    ChannelId;                       /* 20 ids specific bcm5706 */
#define NCSI_CMD_CHANNEL_ID_MASK            0x1F
#define NCSI_CMD_PACKAGE_ID_MASK            0xE0
	u16_t   PayloadSize;                     /* 22 ids how much Payload */
	u32_t   Reserved1[2];

} NcsiRmiiControlPktHeader_t;
#elif defined (LITTLE_ENDIAN)
{
	   u8_t    DestAddr[SIZEOF_MAC_ADDRESS+2];    /* 6 + 2 padding     */
	   u8_t    SrcAddr[SIZEOF_MAC_ADDRESS-2];
	   u16_t   EtherType;                       /* 14 ids pkt as cmd       */
#define NCSI_ETHER_TYPE_ID             (0x88F8)
	   u8_t    SrcAddr_lsw[2];

	   u8_t    InstanceId;
	   u8_t    Reserved0;
	   u8_t    HeaderRevNum;
	   u8_t    McId;

	   u16_t   PayloadSize;                     /* 22 ids how much Payload */

	   u8_t    ChannelId;
#define NCSI_CMD_PACKAGE_ID_MASK            0xE0
#define NCSI_CMD_CHANNEL_ID_MASK            0x1F
	   u8_t    TypeCode;
#define NCSI_CMD_RESPONSE_BIT                                     (0x80)
#define NCSI_CMD_TYPE_OEM                                       (0x50)
#define NCSI_CMD_TYPE_LAST_NON_OEM_CMD                          NCSI_CMD_TYPE_GET_NCSI_PASS_THROUGH_STATISTICS
#define NCSI_CMD_TYPE_GET_NCSI_PASS_THROUGH_STATISTICS          (0x1A)
#define NCSI_CMD_TYPE_GET_NCSI_STATISTICS                       (0x19)
#define NCSI_CMD_TYPE_GET_IF_STATISTICS                         (0x18)
#define NCSI_CMD_TYPE_GET_PARAMETERS                            (0x17)
#define NCSI_CMD_TYPE_GET_CAPABILITIES                          (0x16)
#define NCSI_CMD_TYPE_GET_VERSION_ID                            (0x15)
#define NCSI_CMD_TYPE_SET_NCSI_FLOW_CONTROL                     (0x14)
#define NCSI_CMD_TYPE_DISABLE_MULTICAST_PKT_FILTER              (0x13)
#define NCSI_CMD_TYPE_ENABLE_MULTICAST_PKT_FILTER               (0x12)
#define NCSI_CMD_TYPE_DISABLE_BROADCAST_PKT_FILTER              (0x11)
#define NCSI_CMD_TYPE_ENABLE_BROADCAST_PKT_FILTER               (0x10)
#define NCSI_CMD_TYPE_SET_MAC_ADDRESS                           (0x0E)
#define NCSI_CMD_TYPE_DISABLE_VLAN                              (0x0D)
#define NCSI_CMD_TYPE_ENABLE_VLAN                               (0x0C)
#define NCSI_CMD_TYPE_SET_VLAN_FILTERS                          (0x0B)
#define NCSI_CMD_TYPE_GET_LINK_STATUS                           (0x0A)
#define NCSI_CMD_TYPE_SET_LINK                                  (0x09)
#define NCSI_CMD_TYPE_ENABLE_AEN                                (0x08)
#define NCSI_CMD_TYPE_DISABLE_CHANNEL_EGRESS_TX                 (0x07)
#define NCSI_CMD_TYPE_ENABLE_CHANNEL_EGRESS_TX                  (0x06)
#define NCSI_CMD_TYPE_RESET_CHANNEL                             (0x05)
#define NCSI_CMD_TYPE_DISABLE_CHANNEL                           (0x04)
#define NCSI_CMD_TYPE_ENABLE_CHANNEL                            (0x03)
#define NCSI_CMD_TYPE_PACKAGE_DESELECT                          (0x02)
#define NCSI_CMD_TYPE_PACKAGE_SELECT                            (0x01)
#define NCSI_CMD_TYPE_CLEAR_INITIAL_STATE                       (0x00)
#define NCSI_CMD_TYPE_MASK                                     (0x7F)
#define NCSI_CMD_TYPE_AEN                                   (0xFF)

	   u32_t   Reserved1[2];

}
   NcsiRmiiControlPktHeader_t;
#endif // ENDIAN

typedef NcsiRmiiControlPktHeader_t *pNcsiRmiiControlPktHeader_t;

#define NCSI_DEFS_SIZE_OF_NCSI_FRAME_HEADER  (sizeof (NcsiRmiiControlPktHeader_t))



/*****************************************************************************

FwTestCmdPayload_t    

    Structure definition for most basic UMP cmd Payload
    
    Write command is not bounded.
    
    Read command is bounded to 128 bytes, or 32 dwords.  That fits in with
    existing statistics command response payload size, and handles existing
    testing needs.
	 
*****************************************************************************/

typedef struct FwTestCmdPayload
{
	u32_t     OperationType;
#define NCSI_TEST_READ                              0x0   // read N register dwords starting at address provided (word count, address )
#define NCSI_TEST_WRITE                             0x1   // write N words starting at address provided with Value provided (word count, address, value)
#define NCSI_TEST_READ_FW_STATE                     0x2   // read and return internal fw state word
#define NCSI_TEST_SAVE_SET_OS_PRES_FLAG             0x3   // canned functional meaning
#define NCSI_TEST_RESTORE_OS_PRES_FLAG              0x4   // canned functional meaning
#define NCSI_TEST_SAVE_SET_EXCEED_LOW_POWER_FLAG    0x5   // canned functional meaning
#define NCSI_TEST_RESTORE_EXCEED_LOW_POWER_FLAG     0x6   // canned functional meaning
	union {
		struct {
			u32_t    Address;
			u32_t    WordCount;
		} Read;

		struct {
			u32_t    Address;
			u32_t    WordCount;
			u32_t    Value;

		} Write;

	} OperationParameters;

} FwTestCmdPayload_t;

// type definitions for Dual Media Support
typedef enum PhyPrioritySel
{
	PHY_PRI_HW_PIN,          // HW pin strapping value
	PHY_PRI_COPPER_FIRST,          // Copper priority selection
	PHY_PRI_XAUI_FIRST,          // XAUI  priority selection
	PHY_PRI_COPPER_ONLY,          // use copper, ignore XAUI priority
	PHY_PRI_XAUI_ONLY              // use XAUI, ignore copper priority
}PhyPrioritySel_t;


/*****************************************************************************

SetDualMediaParametersPayload_t    

    Structure definitions for Dual Media support
	 
*****************************************************************************/
#define NCSI_CMD_SET_PHY_PRIORITY_RSP_PAYLOAD_VERSION     0

typedef struct SetDualMediaParametersPayload
#if defined (BIG_ENDIAN)
{
	u8_t     Reserved[3];
	u8_t     PhyPrioritySelection;
} SetDualMediaParametersPayload_t;
#elif defined (LITTLE_ENDIAN)
{
	   u8_t     PhyPrioritySelection;
	   u8_t     Reserved[3];
}
   SetDualMediaParametersPayload_t;
#endif // ENDIAN

typedef struct NcsiOemGetDualMediaParametersPayload
#if defined (BIG_ENDIAN)
{
	u16_t    Reserved;
	u8_t     PhySelection;
	u8_t     PhyPrioritySelection;
} NcsiOemGetDualMediaParametersPayload_t;
#elif defined (LITTLE_ENDIAN)
{
	   u8_t     PhyPrioritySelection;
	   u8_t     PhySelection;
	   u16_t    Reserved;
}
   NcsiOemGetDualMediaParametersPayload_t;
#endif // ENDIAN


#define NCSI_CMD_SET_MAC_OEM_CMD_PAYLOAD_VERSION    0
typedef struct BrcmOemCmdRspHeader
{
#if defined (BIG_ENDIAN)
	u8_t     PayloadVersion;
	u8_t     CommandType;
#define BRCM_OEM_SET_ALT_HOST_MAC_ADDRESS_CMD                     0x00
#define BRCM_OEM_GET_NCSI_PARAMETERS_CMD                          0x01
#define BRCM_OEM_NCSI_TEST_CMD                                    0x02
#define BRCM_OEM_SET_PHY_PRIORITY_CMD                             0x03
#define BRCM_OEM_GET_PHY_PRIORITY_CMD                             0x04
	u16_t    PayloadLength;
	u32_t    Reserved;

#elif defined (LITTLE_ENDIAN)
	u16_t    PayloadLength;
	u8_t     CommandType;
#define BRCM_OEM_SET_ALT_HOST_MAC_ADDRESS_CMD                     0x00
#define BRCM_OEM_GET_NCSI_PARAMETERS_CMD                          0x01
#define BRCM_OEM_NCSI_TEST_CMD                                    0x02
#define BRCM_OEM_SET_PHY_PRIORITY_CMD                             0x03
#define BRCM_OEM_GET_PHY_PRIORITY_CMD                             0x04
	u8_t     PayloadVersion;
	u32_t    Reserved;

#endif // ENDIAN
} BrcmOemCmdRspHeader_t;


typedef struct ModifyHostMacAddrCmdPayload
#if defined (BIG_ENDIAN)
{
	u8_t     Res;
	u8_t     Flags;
#define NCSI_OEM_CMD_SET_ALT_HOST_MAC_ADDR_FLAG_FIELD_ENABLE_MAC_ADDR       0x01
#define NCSI_OEM_CMD_SET_ALT_HOST_MAC_ADDR_FLAG_FIELD_ISCSI_MAC_ADDR_SELECT 0x02

	u16_t    MacHigh;
	u16_t    MacMiddle;
	u16_t    MacLow;


} ModifyHostMacAddrCmdPayload_t;
#elif defined (LITTLE_ENDIAN)
{

	   u16_t    MacHigh;
	   u8_t     Flags;
#define NCSI_OEM_CMD_SET_ALT_HOST_MAC_ADDR_FLAG_FIELD_ENABLE_MAC_ADDR       0x01
#define NCSI_OEM_CMD_SET_ALT_HOST_MAC_ADDR_FLAG_FIELD_ISCSI_MAC_ADDR_SELECT 0x02
	   u8_t     Res;
	   u16_t    MacLow;
	   u16_t    MacMiddle;


}
   ModifyHostMacAddrCmdPayload_t;
#endif // ENDIAN



typedef union BrcmOemCmdPayload
{
	ModifyHostMacAddrCmdPayload_t   ModifyHostMacAddrCmd;          // BRCM_OEM_SET_ALT_HOST_MAC_ADDRESS_CMD
	FwTestCmdPayload_t              NsciTestCmd;                   // BRCM_OEM_NCSI_TEST_CMD

	SetDualMediaParametersPayload_t         SetDualMediaParametersCmd;            // BRCM_OEM_SET_PHY_PRIORITY_CMD

} BrcmOemCmdPayload_t;

/* OEM command ID */
#define DELL_OEM_GET_INVENTORY_CMD                                               0x00
#define DELL_OEM_GET_EXTENDED_CAPABILITIES_CMD                                   0x01
#define DELL_OEM_GET_PARTITION_INFORMATION_CMD                                   0x02
#define DELL_OEM_GET_FCOE_CAPABILITIES_CMD                                       0x03
#define DELL_OEM_GET_VIRTUAL_LINK_CMD                                            0x04
#define DELL_OEM_GET_LAN_STATISTICS_CMD                                          0x05
#define DELL_OEM_GET_FCOE_STATISTICS_CMD                                         0x06
#define DELL_OEM_SET_ADDR_CMD                                                    0x07
#define DELL_OEM_GET_ADDR_CMD                                                    0x08
#define DELL_OEM_SET_LICENSE_CMD                                                 0x09
#define DELL_OEM_GET_LICENSE_CMD                                                 0x0A
#define DELL_OEM_SET_PASSTHRU_CONTROL_CMD                                        0x0B
#define DELL_OEM_GET_PASSTHRU_CONTROL_CMD                                        0x0C
#define DELL_OEM_SET_PARTITION_TX_BANDWIDTH_CMD                                  0x0D
#define DELL_OEM_GET_PARTITION_TX_BANDWIDTH_CMD                                  0x0E
#define DELL_OEM_SET_MC_IP_ADDRESS_CMD                                           0x0F
#define DELL_OEM_GET_TEAMING_INFORMATION_CMD                                     0x10
#define DELL_OEM_ENABLE_PORTS_CMD                                                0x11
#define DELL_OEM_DISABLE_PORTS_CMD                                               0x12
#define DELL_OEM_GET_TEMPERATURE_CMD                                             0x13
#define DELL_OEM_SET_LINK_TUNING_CMD                                             0x14
#define DELL_OEM_ENABLE_OUTOFBOX_WOL_CMD                                         0x15
#define DELL_OEM_DISABLE_OUTOFBOX_WOL_CMD                                        0x16
#define DELL_OEM_GET_SUPP_PAYLOAD_VERSION_CMD                                    0x1A
#define DELL_OEM_GET_OS_DRIVER_VERSION_CMD                                       0x1C
#define DELL_OEM_GET_ISCSI_BOOT_INITIATOR_CONFIG_CMD                             0x1D
#define DELL_OEM_SET_ISCSI_BOOT_INITIATOR_CONFIG_CMD                             0x1E
#define DELL_OEM_GET_ISCSI_BOOT_TARGET_CONFIG_CMD                                0x1F
#define DELL_OEM_SET_ISCSI_BOOT_TARGET_CONFIG_CMD                                0x20
#define DELL_OEM_GET_FCOE_BOOT_TARGET_CONFIG_CMD                                 0x21
#define DELL_OEM_SET_FCOE_BOOT_TARGET_CONFIG_CMD                                 0x22
#define DELL_OEM_NVRAM_COMMIT_CMD        		                         0x23
#define DELL_OEM_NVRAM_COMMIT_STATUS_CMD                                         0x24

/* ManufacturerId IANA */
#define NCSI_QLOGIC_IANA                                  (0x113D)
#define NCSI_DELL_IANA                                      (0x2A2)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x00    Get Inventory   Used to get the inventory information for the Ethernet Controller   0x00    (Mandatory)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define DELL_OEM_PAYLOAD_V1	(1<<1)
#define DELL_OEM_PAYLOAD_V2	(1<<2)

typedef struct DellDfltCmd
{
#if defined (BIG_ENDIAN)
	u32_t    ManufacturerId;         /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType; /* OEM command ID */
	u16_t    Pad;

#elif defined (LITTLE_ENDIAN)
	u32_t    ManufacturerId;         /* ManufacturerId IANA */
	u16_t    Pad;
	u8_t     CommandType; /* OEM command ID */
	u8_t     PayloadVersion;
#endif // ENDIAN
}DellDfltCmd_t;

typedef struct DellDfltCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;           /* OEM command ID */
	u16_t    Pad;
#elif defined (LITTLE_ENDIAN)
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u16_t    Pad;
	u8_t     CommandType;           /* OEM command ID */
	u8_t     PayloadVersion;
#endif // endian
} DellDfltCmdRspData_t;


typedef DellDfltCmd_t DellGetInventoryCmd_t;

typedef struct DellGetInventoryCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;       /* OEM command ID */
	u16_t     MediaType;
#define MEDIA_BASE_T        0x0001  // 0    Base-T      0b =    Base-T is not supported.  1b =  Base-T is supported.
#define MEDIA_BASE_KR       0x0002  // 1    Base-KR     0b =    Base-KR is not supported. 1b =  Base-KR is supported.
#define MEDIA_BASE_KX       0x0004  // 2    Base-KX     0b =    Base-KX is not supported. 1b =  Base-KX is supported.
#define MEDIA_BASE_KX4      0x0008  // 3    Base-KX4    0b =    Base-KX4 is not supported.1b =  Base-KX4 is supported.
#define MEDIA_SR            0x0010  // 4    SR          0b =    SR is not supported.      1b =  SR is supported.
#define MEDIA_SFP           0x0020  // 5    SFP         0b =    SFP is not supported.     1b =  SFP is supported.
#define MEDIA_SFP_PLUS      0x0040  // 6    SFP+        0b =    SFP+ is not supported.    1b =  SFP+ is supported.
#define MEDIA_DCA           0x0080  // 7    DCA         0b =    DCA is not supported.     1b =  DCA is supported.
#define MEDIA_RESERVED      0xFF00  // 8-15 Reserved
	u32_t     FamilyFWVer;
#define FW_VER_MAJOR_MASK          0xFF000000
#define FW_VER_MINOR_MASK          0x00FF0000
#define FW_VER_BUILD_MASK          0x0000FF00
#define FW_VER_SUB_BUILD_MASK      0x000000FF
	u32_t     FamilyDrvVer;
#define DRV_FW_VER_MAJOR_MASK          0xFF000000
#define DRV_FW_VER_MINOR_MASK          0x00FF0000
#define DRV_FW_VER_BUILD_MASK          0x0000FF00
#define DRV_FW_VER_SUB_BUILD_MASK      0x000000FF
	u8_t   FirstInventoryLength;
	u8_t   FirstInventoryType;
#define INVENTORY_TYPE_DEVICE     0x0 // = Device Name
#define INVENTORY_TYPE_VENDOR     0x1 // = Vendor Name
	//    0x2-0xFF = Reserved
	u8_t   InventoryNameBuf[];
#elif defined (LITTLE_ENDIAN)
	u16_t     ReasonCode;            /* ids reasons for rsp  */
	u16_t     ResponseCode;          /* ids outcome of cmd   */
	u32_t     ManufacturerId;        /* ManufacturerId IANA */
	u16_t     MediaType;
#define MEDIA_BASE_T        0x0001  // 0    Base-T      0b =    Base-T is not supported.  1b =  Base-T is supported.
#define MEDIA_BASE_KR       0x0002  // 1    Base-KR     0b =    Base-KR is not supported. 1b =  Base-KR is supported.
#define MEDIA_BASE_KX       0x0004  // 2    Base-KX     0b =    Base-KX is not supported. 1b =  Base-KX is supported.
#define MEDIA_BASE_KX4      0x0008  // 3    Base-KX4    0b =    Base-KX4 is not supported.1b =  Base-KX4 is supported.
#define MEDIA_SR            0x0010  // 4    SR          0b =    SR is not supported.      1b =  SR is supported.
#define MEDIA_SFP           0x0020  // 5    SFP         0b =    SFP is not supported.     1b =  SFP is supported.
#define MEDIA_SFP_PLUS      0x0040  // 6    SFP+        0b =    SFP+ is not supported.    1b =  SFP+ is supported.
#define MEDIA_DCA           0x0080  // 7    DCA         0b =    DCA is not supported.     1b =  DCA is supported.
#define MEDIA_RESERVED      0xFF00  // 8-15 Reserved
	u8_t     CommandType;   /* OEM command ID */
	u8_t     PayloadVersion;
	u32_t     FamilyFWVer;
#define FW_VER_MAJOR_MASK          0xFF000000
#define FW_VER_MINOR_MASK          0x00FF0000
#define FW_VER_BUILD_MASK          0x0000FF00
#define FW_VER_SUB_BUILD_MASK      0x000000FF
	u32_t     FamilyDrvVer;
#define DRV_FW_VER_MAJOR_MASK          0xFF000000
#define DRV_FW_VER_MINOR_MASK          0x00FF0000
#define DRV_FW_VER_BUILD_MASK          0x0000FF00
#define DRV_FW_VER_SUB_BUILD_MASK      0x000000FF
	u8_t   FirstInventoryNameBuf[2];
	u8_t   FirstInventoryLength;
	u8_t   FirstInventoryType;
#define INVENTORY_TYPE_DEVICE     0x0 // = Device Name
#define INVENTORY_TYPE_VENDOR     0x1 // = Vendor Name
	//    0x2-0xFF = Reserved
	u8_t   InventoryNameBuf[];
#endif // endian
} DellGetInventoryCmdRspData_t;


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x01    Get Extended Capabilities   Used to get the feature capabilities of a channel.  0x01    (Mandatory)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef DellDfltCmd_t DellGetExtendedCapabilitiesCmd_t;

typedef struct DellGetExtendedCapabilitiesCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;       /* OEM command ID */
	u16_t     CapabilitiesHiWord;
	// 16-17    Reserved
#define CAP_PXE_SUPPORT_SUPPORT                  (1<< (18-16))  // 18   PXE 0b = PXE is not supported.                                     1b = PXE is supported.
#define CAP_ISCSI_BOOT_SUPPORT                   (1<< (19-16))  // 19   iSCSI Boot (iBFT or HBA)    0b = iSCSI Boot is not supported.      1b = iSCSI Boot is supported.
#define CAP_FCOE_BOOT_SUPPORT                    (1<< (20-16))  // 20   FCoE Boot   0b = FCoE Boot is not supported.                       1b = FCoE Boot is supported.
#define CAP_STORAGE_BOOT_M_PROVISIONING          (1<< (21-16)) // 20   Storage Boot Parameter Provisioning   0b =  not supported.         1b = is supported.
	// 22-23    Reserved
#define CAP_NIC_PARTITIONING_SUPPORT             (1<< (24-16))  // 24   NIC Partitioning    0b = NIC Partitioning is not supported.        1b = NIC Partitioning is supported.
#define CAP_SRIOV_SUPPORT                        (1<< (25-16))  // 25   SR-IOV  0b = SR-IOV is not supported.                              1b = SR-IOV is supported.
#define CAP_DELL_LICENSE_MGR_SUPPORT             (1<< (26-16))  // 26   Dell License Manager    0b = Dell License Manager is not supported 1b = Dell License Manager is supported
#define CAP_IPSEC_OFFLOAD_SUPPORT                (1<< (27-16))  // 27   IPSec Offload   0b = IPSec Offload is not supported                1b = IPSec Offload is supported
#define CAP_MACSEC_SUPPORT                       (1<< (28-16))  // 28   MACSec  0b = MACSec is not supported                               1b = MACSec is supported
#define CAP_RDMA_SUPPORT                         (1<< (29-16))  // 29   RDMA    0b = RDMA is not supported                                 1b = RDMA is supported
	// 30-31    Reserved
	u16_t     CapabilitiesLoWord;
#define CAP_VIRTUAL_ADDRESSING_SUPPORT              0x0001  // 0    Virtual Addressing  0b =    Virtual Addressing is not supported.   1b = Virtual Addressing is supported.
#define CAP_LINK_TUNING_SUPPORT                     0x0002  // 1    Link Tuning 0b =    Link Tuning is not supported.                  1b = Link Tuning is supported.
#define CAP_REMOTEPHY_SUPPORT                       0x0004  // 2    RemotePHY   0b = RemotePHY is not supported                        1b = RemotePHY is supported
#define CAP_OPTION_ROM_PRESENT_SUPPORT              0x0008  // 3    Option ROM Present  0b = OPROM is not present                      1b = OPROM is present
#define CAP_UEFI_SUPPORT                            0x0010  // 4    uEFI    0b = uEFI is not supported                                 1b = uEFI is supported
#define CAP_WOL_SUPPORT                             0x0020  // 5    WakeOnLAN   0b = WakeOnLAN is not supported.                       1b = WakeOnLAN is supported.
#define CAP_NETWORK_MGMT_PASS_THRU_SUPPORT          0x0040  // 6    Network Management pass through 0b = Network Management pass through is not supported. 1b = Network Management pass through is supported.
#define CAP_OS_BMC_PASS_THRU_SUPPORT                0x0080  // 7    OS-BMC pass through 0b = OS-BMC pass through is not supported.     1b = OS-BMC pass through is supported.
#define CAP_EEE_SUPPORT                             0x0100  // 8    Energy Efficient Ethernet   0b = EEE is not supported.             1b = EEE is supported.
#define CAP_ON_CHIP_THERMAL_SENSOR_SUPPORT          0x0200  // 9    On chip thermal sensor  0b = On chip thermal sensor is supported.  1b = On chip thermal sensor is not supported.
	// 10-11    Reserved
#define CAP_TCP_OFFLOAD_SUPPORT                     0x1000  // 12   TCP Offload 0b = TCP Offload is not supported.                     1b = TCP Offload is supported.
#define CAP_ISCSI_OFFLOAD_SUPPORT                   0x2000  // 13   iSCSI Offload   0b = iSCSI Offload is not supported.               1b = iSCSI Offload is supported.
#define CAP_FCOE_SUPPORT                            0x4000  // 14   Fibre Channel over Ethernet 0b = Fibre Channel over Ethernet is not supported. 1b = Fibre Channel over Ethernet is supported.
	// 15       Reserved
	u8_t      Reserved;
	u8_t     DCB_Capabilities;
#define DCB_CAP_ETS_SUPPORT                         0x0001  // 0    Enhanced Transmission Selection (ETS)   0b =    ETS is not supported.  1b = ETS is supported.
#define DCB_CAP_PFC_SUPPORT                         0x0002  // 1    Priority Flow Control (PFC) 0b =    PFC is not supported.              1b = PFC is supported.
#define DCB_CAP_CN_SUPPORT                          0x0004  // 2    Congestion Notification (CN)    0b =    CN is not supported.           1b = CN is supported.
#define DCB_CAP_DCBX_SUPPORT                        0x0008  // 3    DCB Exchange Protocol (DCBXP)   0b =    DCBXP is not supported.        1b = DCBXP is supported.
	// 4-7  Reserved
	u8_t     NP_Capabilities;
#define NP_CAP_WOL                                  0x01    // 0    WakeOnLan   0b =    WakeOnLan is not supported.                1b = WakeOnLan is supported.
#define NP_CAP_VIRTUAL_LINK_CTRL                    0x02    // 1    Virtual Link Control    0b =    Virtual Link Control is not supported. 1b = Virtual Link Control is supported.
#define NP_CAP_RX_FLOW_CTRL                         0x04    // 2    Receive Flow Control    0b =    Receive Flow Control is not supported. 1b = Receive Flow Control is supported
#define NP_CAP_TX_FLOW_CTRL                         0x08    // 3    Transmit Flow Control   0b =    Transmit Flow Control is not supported.1b = Transmit Flow Control is supported
#define NP_CAP_TX_BW_CTRL_MAX                       0x10    // 4    Transmit Bandwidth Control Maximum  0b =    TX Bandwidth Control Maximum is not supported. 1b = TX Bandwidth Control Maximum is supported.
#define NP_CAP_TX_BW_CTRL_MIN                       0x20    // 5    Transmit Bandwidth Control Minimum  0b =    TX Bandwidth Control Minimum is not supported. 1b = TX Bandwidth Control Minimum is supported.
	// 6-7  Reserved
	u8_t    E_Switch_Capabilities;
#define E_SWITCH_CAP_VEB                            0x0001  // 0   VEB         0b =  VEB is not supported.  1b = VEB is supported.
#define E_SWITCH_CAP_BIT1                           0x0002  // 1   Reserved
#define E_SWITCH_CAP_BIT2                           0x0004  // 2   Reserved
#define E_SWITCH_CAP_BPE                            0x0008  // 3   BPE         0b =  BPE is not supported. 1b =  BPE is supported.
#define E_SWITCH_CAP_OPEN_FLOW                      0x0010  // 4   Open Flow   0b =  Open Flow is not supported. 1b = Open Flow is supported.
	// 5-7 Reserved
	u8_t    PF_num;                                         // Number of PCI Physical functions
	u8_t    VF_num;                                         // Number of PCI Virtual functions
#elif defined (LITTLE_ENDIAN)
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u16_t     CapabilitiesHiWord;
	// 16-17    Reserved
#define CAP_PXE_SUPPORT_SUPPORT                      (1<< (18-16)) // 18   PXE 0b = PXE is not supported.                                     1b = PXE is supported.
#define CAP_ISCSI_BOOT_SUPPORT                       (1<< (19-16)) // 19   iSCSI Boot (iBFT or HBA)    0b = iSCSI Boot is not supported.      1b = iSCSI Boot is supported.
#define CAP_FCOE_BOOT_SUPPORT                        (1<< (20-16)) // 20   FCoE Boot   0b = FCoE Boot is not supported.                       1b = FCoE Boot is supported.
#define CAP_STORAGE_BOOT_M_PROVISIONING              (1<< (21-16)) // 20   Storage Boot Parameter Provisioning   0b =  not supported.         1b = is supported.

	// 22-23    Reserved
#define CAP_NIC_PARTITIONING_SUPPORT                 (1<< (24-16)) // 24   NIC Partitioning    0b = NIC Partitioning is not supported.        1b = NIC Partitioning is supported.
#define CAP_SRIOV_SUPPORT                            (1<< (25-16)) // 25   SR-IOV  0b = SR-IOV is not supported.                              1b = SR-IOV is supported.
#define CAP_DELL_LICENSE_MGR_SUPPORT                 (1<< (26-16)) // 26   Dell License Manager    0b = Dell License Manager is not supported 1b = Dell License Manager is supported
#define CAP_IPSEC_OFFLOAD_SUPPORT                    (1<< (27-16)) // 27   IPSec Offload   0b = IPSec Offload is not supported                1b = IPSec Offload is supported
#define CAP_MACSEC_SUPPORT                           (1<< (28-16)) // 28   MACSec  0b = MACSec is not supported                               1b = MACSec is supported
#define CAP_RDMA_SUPPORT                             (1<< (29-16)) // 29   RDMA    0b = RDMA is not supported                                 1b = RDMA is supported
	u8_t     CommandType;           /* OEM command ID */
	u8_t     PayloadVersion;
	// 30-31    Reserved
	u8_t     DCB_Capabilities;
#define DCB_CAP_ETS_SUPPORT                         0x0001  // 0    Enhanced Transmission Selection (ETS)   0b =    ETS is not supported.  1b = ETS is supported.
#define DCB_CAP_PFC_SUPPORT                         0x0002  // 1    Priority Flow Control (PFC) 0b =    PFC is not supported.              1b = PFC is supported.
#define DCB_CAP_CN_SUPPORT                          0x0004  // 2    Congestion Notification (CN)    0b =    CN is not supported.           1b = CN is supported.
#define DCB_CAP_DCBX_SUPPORT                        0x0008  // 3    DCB Exchange Protocol (DCBXP)   0b =    DCBXP is not supported.        1b = DCBXP is supported.
	// 4-7  Reserved
	u8_t      Reserved;
	u16_t     CapabilitiesLoWord;
#define CAP_VIRTUAL_ADDRESSING_SUPPORT              0x0001  // 0    Virtual Addressing  0b =    Virtual Addressing is not supported.   1b = Virtual Addressing is supported.
#define CAP_LINK_TUNING_SUPPORT                     0x0002  // 1    Link Tuning 0b =    Link Tuning is not supported.                  1b = Link Tuning is supported.
#define CAP_REMOTEPHY_SUPPORT                       0x0004  // 2    RemotePHY   0b = RemotePHY is not supported                        1b = RemotePHY is supported
#define CAP_OPTION_ROM_PRESENT_SUPPORT              0x0008  // 3    Option ROM Present  0b = OPROM is not present                      1b = OPROM is present
#define CAP_UEFI_SUPPORT                            0x0010  // 4    uEFI    0b = uEFI is not supported                                 1b = uEFI is supported
#define CAP_WOL_SUPPORT                             0x0020  // 5    WakeOnLAN   0b = WakeOnLAN is not supported.                       1b = WakeOnLAN is supported.
#define CAP_NETWORK_MGMT_PASS_THRU_SUPPORT          0x0040  // 6    Network Management pass through 0b = Network Management pass through is not supported. 1b = Network Management pass through is supported.
#define CAP_OS_BMC_PASS_THRU_SUPPORT                0x0080  // 7    OS-BMC pass through 0b = OS-BMC pass through is not supported.     1b = OS-BMC pass through is supported.
#define CAP_EEE_SUPPORT                             0x0100  // 8    Energy Efficient Ethernet   0b = EEE is not supported.             1b = EEE is supported.
#define CAP_ON_CHIP_THERMAL_SENSOR_SUPPORT          0x0200  // 9    On chip thermal sensor  0b = On chip thermal sensor is supported.  1b = On chip thermal sensor is not supported.
	// 10-11    Reserved
#define CAP_TCP_OFFLOAD_SUPPORT                     0x1000  // 12   TCP Offload 0b = TCP Offload is not supported.                     1b = TCP Offload is supported.
#define CAP_ISCSI_OFFLOAD_SUPPORT                   0x2000  // 13   iSCSI Offload   0b = iSCSI Offload is not supported.               1b = iSCSI Offload is supported.
#define CAP_FCOE_SUPPORT                            0x4000  // 14   Fibre Channel over Ethernet 0b = Fibre Channel over Ethernet is not supported. 1b = Fibre Channel over Ethernet is supported.
	// 15       Reserved
	u8_t    VF_num;                                         // Number of PCI Virtual functions
	u8_t    PF_num;                                         // Number of PCI Physical functions
	u8_t    E_Switch_Capabilities;
#define E_SWITCH_CAP_VEB                            0x0001  // 0   VEB         0b =  VEB is not supported.  1b = VEB is supported.
	// 1   Reserved
	// 2   Reserved
#define E_SWITCH_CAP_BPE                            0x0008  // 3   BPE         0b =  BPE is not supported. 1b =  BPE is supported.
#define E_SWITCH_CAP_OPEN_FLOW                      0x0010  // 4   Open Flow   0b =  Open Flow is not supported. 1b = Open Flow is supported.
	// 5-7 Reserved
	u8_t     NP_Capabilities;
#define NP_CAP_WOL                                  0x01    // 0    WakeOnLan   0b =    WakeOnLan is not supported.                1b = WakeOnLan is supported.
#define NP_CAP_VIRTUAL_LINK_CTRL                    0x02    // 1    Virtual Link Control    0b =    Virtual Link Control is not supported. 1b = Virtual Link Control is supported.
#define NP_CAP_RX_FLOW_CTRL                         0x04    // 2    Receive Flow Control    0b =    Receive Flow Control is not supported. 1b = Receive Flow Control is supported
#define NP_CAP_TX_FLOW_CTRL                         0x08    // 3    Transmit Flow Control   0b =    Transmit Flow Control is not supported.1b = Transmit Flow Control is supported
#define NP_CAP_TX_BW_CTRL_MAX                       0x10    // 4    Transmit Bandwidth Control Maximum  0b =    TX Bandwidth Control Maximum is not supported. 1b = TX Bandwidth Control Maximum is supported.
#define NP_CAP_TX_BW_CTRL_MIN                       0x20    // 5    Transmit Bandwidth Control Minimum  0b =    TX Bandwidth Control Minimum is not supported. 1b = TX Bandwidth Control Minimum is supported.
	// 6-7  Reserved
#endif // endian
} DellGetExtendedCapabilitiesCmdRspData_t;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x02    Get Partition Information   Used to get NIC Partition information of a channel. 0x02    (Mandatory)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef DellDfltCmd_t DellGetPartitionInfoCmd_t;

typedef struct DellGetPartitionInfoCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;           /* OEM command ID */
	u8_t     Enabled_PF_num;    // Number of PCI Physical Functions Enabled
	u8_t     PartitionId;       // Partition ID #1
	u16_t    PartitionStatus;  // Partition Status
#define PARTITION_STATUS_PERSONALITIES_NUM_MASK       0x07   // 0..2    Number of personalities configured  Number of personalities configured on the partition.
#define PARTITION_STATUS_LAN                          0x08   // 3   LAN             0b = LAN is not configured 1b = LAN is configured
#define PARTITION_STATUS_ISOE                         0x10   // 4   iSOE (Stateful) 0b = iSOE is not configured 1b = iSOE is configured  iSOE = iSCSI Offload Engine
#define PARTITION_STATUS_FCOE                         0x20   // 5   FCoE (Stateful) 0b = FCoE is not configured 1b = FCoE is configured  FCoE = Fibre Channel Over Ethernet
	// 6-15    Reserved
	u8_t    FirstPartitionInterfaceLength;
	u8_t    FirstPartitionInterfaceType;
#define PARTITION_INTERFACE_LAN     0x0   // 0x0 = LAN
#define PARTITION_INTERFACE_ISCSI   0x1   // 0x1 = iSCSI
#define PARTITION_INTERFACE_FCOE    0x2   // 0x2 = FCoE
	// 0x3-0xFF = Reserved
	u8_t    InterfaceBuf[4*2*44]; // worst case scenario == 4 pf * 2 personalities * 44 bytes/personality
#elif defined (LITTLE_ENDIAN)
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PartitionId;       // Partition ID #1
	u8_t     Enabled_PF_num;    // Number of PCI Physical Functions Enabled
	u8_t     CommandType;           /* OEM command ID */
	u8_t     PayloadVersion;
	// 30-31    Reserved
	u16_t    PartitionStatus;  // Partition Status
#define PARTITION_STATUS_PERSONALITIES_NUM_MASK       0x07   // 0..2    Number of personalities configured  Number of personalities configured on the partition.
#define PARTITION_STATUS_LAN                          0x08   // 3   LAN             0b = LAN is not configured 1b = LAN is configured
#define PARTITION_STATUS_ISOE                         0x10   // 4   iSOE (Stateful) 0b = iSOE is not configured 1b = iSOE is configured  iSOE = iSCSI Offload Engine
#define PARTITION_STATUS_FCOE                         0x20   // 5   FCoE (Stateful) 0b = FCoE is not configured 1b = FCoE is configured  FCoE = Fibre Channel Over Ethernet
	// 6-15    Reserved
	u8_t     FirstPartitionInterfaceType;
#define PARTITION_INTERFACE_LAN     0x0   // 0x0 = LAN
#define PARTITION_INTERFACE_ISCSI   0x1   // 0x1 = iSCSI
#define PARTITION_INTERFACE_FCOE    0x2   // 0x2 = FCoE
	// 0x3-0xFF = Reserved
	u8_t     FirstPartitionInterfaceLength;
	u8_t     InterfaceBuf[4*2*44]; // worst case scenario == 4 pf * 2 personalities * 44 bytes/personality
#endif // endian
} DellGetPartitionInfoCmdRspData_t;



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x03    Get FCoE Capabilities   Used to get FCoE Capabilities of a channel. 0x03    (Conditional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef DellDfltCmd_t DellGetFcoeCapabilitiesCmd_t;

typedef struct DellGetFcoeCapabilitiesCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;           /* OEM command ID */
	u8_t     Reserved;                     // Reserved
	u8_t     FcoeFeatureSettings;          // FCoE Feature Settings
#define FCOE_FEATURE_FCOE_SUPPORT              0x0001  // 0    FCoE Support 0b = Stateless Offload   1b = Stateful Offload
	// 7..1  Reserved
	u16_t    MaxIoPerConnection;           // Maximum number of I/Os per connection
	u16_t    MaxLoginsPerPort;             // Maximum number of Logins per port
	u16_t    MaxExchanges;                 // Maximum number of exchanges
	u16_t    MaxNPIV_WWN_PerPort;          // Maximum NPIV WWN per port
	u16_t    MaxSupportedTargets;          // Maximum number of targets supported
	u16_t    MaxOutstandingCmds;           // Maximum number of outstanding commands across all connections
#elif defined (LITTLE_ENDIAN)
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     FcoeFeatureSettings;          // FCoE Feature Settings
#define FCOE_FEATURE_FCOE_SUPPORT              0x0001  // 0    FCoE Support 0b = Stateless Offload   1b = Stateful Offload
	// 7..1  Reserved

	u8_t     Reserved;                     // Reserved

	u8_t     CommandType;           /* OEM command ID */
	u8_t     PayloadVersion;

	u16_t    MaxLoginsPerPort;             // Maximum number of Logins per port
	u16_t    MaxIoPerConnection;           // Maximum number of I/Os per connection
	u16_t    MaxNPIV_WWN_PerPort;          // Maximum NPIV WWN per port
	u16_t    MaxExchanges;                 // Maximum number of exchanges
	u16_t    MaxOutstandingCmds;           // Maximum number of outstanding commands across all connections
	u16_t    MaxSupportedTargets;          // Maximum number of targets supported
#endif // endian
} DellGetFcoeCapabilitiesCmdRspData_t;


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x04    Get Virtual Link    Used to get virtual link status of a partition enabled in a specific channel.   0x04    (Conditional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct DellGetVirtualLinkCmd
{
#if defined (BIG_ENDIAN)
	u32_t    ManufacturerId;         /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;            /* OEM command ID */
	u8_t    PartitionId;
	u8_t    Pad;

#elif defined (LITTLE_ENDIAN)
	u32_t   ManufacturerId;         /* ManufacturerId IANA */
	u8_t    Pad;
	u8_t    PartitionId;
	u8_t    CommandType; /* OEM command ID */
	u8_t    PayloadVersion;
#endif // ENDIAN
}DellCmdPartition_t;

typedef DellCmdPartition_t DellGetVirtualLinkCmd_t;
typedef struct DellGetVirtualLinkCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;       /* OEM command ID */
	u8_t    PartitionId;
	u8_t     Status;
#define VIRTUAL_LINK_STATUS           (0x1 << 0)                                // 0   Virtual Link    0b = Virtual Link is up  1b = Virtual Link is down
#define LAN_HOST_DRV_STATE_MASK       (0X3 << 1)                                // 2..1   LAN Host driver state
#define LAN_HOST_DRV_NOT_IMPLEMENTED  (0x0 << 1)                            //     0x0 = LAN Host driver state feature is not implemented.
#define LAN_HOST_DRV_NOT_OPERATIONAL  (0x1 << 1)                            //     0x1 = LAN Host driver state is not operational
#define LAN_HOST_DRV_OPERATIONAL      (0x2 << 1)                            //     0x2 = LAN Host driver state is operational
	//     0x3 = Reserved
#define ISOE_HOST_DRV_STATE_MASK      (0x3 << 3)                                // 4..3    iSOE Host driver state
#define ISOE_HOST_DRV_NOT_IMPLEMENTED (0x0 << 3)                            //     0x0 = iSOE Host driver state feature is not implemented.
#define ISOE_HOST_DRV_NOT_OPERATIONAL (0x1 << 3)                            //     0x1 = iSOE Host driver state is not operational
#define ISOE_HOST_DRV_OPERATIONAL     (0x2 << 3)                            //     0x2 = iSOE Host driver state is operational
	//     0x3 = Reserved
#define FCOE_HOST_DRV_STATE_MASK      (0x3 << 5)                                // 6..5    FCoE Host driver state
#define FCOE_HOST_DRV_NOT_IMPLEMENTED (0x0 << 5)                            //     0x0 = FCoE Host driver state feature is not implemented.
#define FCOE_HOST_DRV_NOT_OPERATIONAL (0x1 << 5)                            //     0x1 = FCoE Host driver state is not operational
#define FCOE_HOST_DRV_OPERATIONAL     (0x2 << 5)                            //     0x2 = FCoE Host driver state is operational
	//     0x3 = Reserved
	// 7   Reserved
#elif defined (LITTLE_ENDIAN)
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     Status;
#define VIRTUAL_LINK_STATUS           (0x1 << 0)                                // 0   Virtual Link    0b = Virtual Link is up  1b = Virtual Link is down
#define LAN_HOST_DRV_STATE_MASK       (0X3 << 1)                                // 2..1   LAN Host driver state
#define LAN_HOST_DRV_NOT_IMPLEMENTED  (0x0 << 1)                            //     0x0 = LAN Host driver state feature is not implemented.
#define LAN_HOST_DRV_NOT_OPERATIONAL  (0x1 << 1)                            //     0x1 = LAN Host driver state is not operational
#define LAN_HOST_DRV_OPERATIONAL      (0x2 << 1)                            //     0x2 = LAN Host driver state is operational
	//     0x3 = Reserved
#define ISOE_HOST_DRV_STATE_MASK      (0x3 << 3)                                // 4..3    iSOE Host driver state
#define ISOE_HOST_DRV_NOT_IMPLEMENTED (0x0 << 3)                            //     0x0 = iSOE Host driver state feature is not implemented.
#define ISOE_HOST_DRV_NOT_OPERATIONAL (0x1 << 3)                            //     0x1 = iSOE Host driver state is not operational
#define ISOE_HOST_DRV_OPERATIONAL     (0x2 << 3)                            //     0x2 = iSOE Host driver state is operational
	//     0x3 = Reserved
#define FCOE_HOST_DRV_STATE_MASK      (0x3 << 5)                                // 6..5    FCoE Host driver state
#define FCOE_HOST_DRV_NOT_IMPLEMENTED (0x0 << 5)                            //     0x0 = FCoE Host driver state feature is not implemented.
#define FCOE_HOST_DRV_NOT_OPERATIONAL (0x1 << 5)                            //     0x1 = FCoE Host driver state is not operational
#define FCOE_HOST_DRV_OPERATIONAL     (0x2 << 5)                            //     0x2 = FCoE Host driver state is operational
	//     0x3 = Reserved
	// 7   Reserved
	u8_t    PartitionId;

	u8_t    CommandType;           /* OEM command ID */
	u8_t    PayloadVersion;
#endif // endian
} DellGetVirtualLinkCmdRspData_t;


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x05    Get LAN Statistics  Used to get LAN statistics of a partition enabled in a specific channel.    0x05    (Conditional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef DellCmdPartition_t DellGetLanStatisticsCmd_t;


typedef struct DellGetLanStatisticsCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;           /* OEM command ID */

	u8_t     PartitionId;                                            // Partition ID
	u8_t     CountersClearedFromLastRead;                            // Counters Cleared from Last Read
#define    TOTAL_UNICAST_PKT_RCVD_CLEARED             0x01 //     0   Total Unicast Packets Received  0b =    Not Cleared  1b =   Cleared
#define    TOTAL_UNICAST_PKT_XMIT_CLEARED             0x02 //     1   Total Unicast Packets Transmitted   0b =    Not Cleared 1b =    Cleared
#define    FCS_ERRORS_CLEARED                         0x04 //     2   FCS Receive Errors  0b =    Not Cleared 1b = Cleared
	//     7:3 Reserved
	u32_t    TotalUnicastPktsRcvdHi;                                 // 64-bit Total Unicast Packets Received
	u32_t    TotalUnicastPktsRcvdLo;                                 // 64-bit Total Unicast Packets Received
	u32_t    TotalUnicastPktsXmitHi;                                 // 64-bit Total Unicast Packets Transmitted
	u32_t    TotalUnicastPktsXmitLo;                                 // 64-bit Total Unicast Packets Transmitted
	u32_t FCS_Errors;                                             // FCS Receive Errors
#elif defined (LITTLE_ENDIAN)
	u16_t     ReasonCode;            /* ids reasons for rsp  */
	u16_t     ResponseCode;          /* ids outcome of cmd   */
	u32_t     ManufacturerId;        /* ManufacturerId IANA */
	u8_t      CountersClearedFromLastRead;                            // Counters Cleared from Last Read
#define    TOTAL_UNICAST_PKT_RCVD_CLEARED             0x01 //     0   Total Unicast Packets Received  0b =    Not Cleared  1b =   Cleared
#define    TOTAL_UNICAST_PKT_XMIT_CLEARED             0x02 //     1   Total Unicast Packets Transmitted   0b =    Not Cleared 1b =    Cleared
#define    FCS_ERRORS_CLEARED                         0x04 //     2   FCS Receive Errors  0b =    Not Cleared 1b = Cleared
	//     7:3 Reserved

	u8_t     PartitionId;                                            // Partition ID
	u8_t     CommandType;            /* OEM command ID */
	u8_t     PayloadVersion;
	u32_t    TotalUnicastPktsRcvdHi;                                 // 64-bit Total Unicast Packets Received
	u32_t    TotalUnicastPktsRcvdLo;                                 // 64-bit Total Unicast Packets Received
	u32_t    TotalUnicastPktsXmitHi;                                 // 64-bit Total Unicast Packets Transmitted
	u32_t    TotalUnicastPktsXmitLo;                                 // 64-bit Total Unicast Packets Transmitted
	u32_t    FCS_Errors;                                             // FCS Receive Errors
#endif // endian
} DellGetLanStatisticsCmdRspData_t;


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x06    Get FCoE Statistics Used to get FCoE statistics of a partition enabled in a specific channel.   0x06    (Conditional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef DellCmdPartition_t DellGetFcoeStatisticsCmd_t;

typedef struct DellFcoeStat
{
	u32_t TotalFcoePktsRcvdHi;                                      // 64-bit Total FCoE Packets Received
	u32_t TotalFcoePktsRcvdLo;                                      // 64-bit Total FCoE Packets Received
	u32_t TotalFcoePktsXmitHi;                                      // 64-bit Total FCoE Packets Transmitted
	u32_t TotalFcoePktsXmitLo;                                      // 64-bit Total FCoE Packets Transmitted
	u32_t FCS_Errors;                                             // FCS Receive Errors
	u32_t FC_ErrCnt;                                              // FC CRC Error Count
	u32_t FIP_LoginFailureCnt;                                    // FIP Login Failure Count
}DellFcoeStat_t;

typedef struct DellGetFcoeStatisticsCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;            /* OEM command ID */

	u8_t  PartitionId;                                            // Partition ID
	u8_t  CountersClearedFromLastRead;                            // Counters Cleared from Last Read
#define    TOTAL_UNICAST_PKT_RCVD_CLEARED            0x01 // 0  Total FCoE Packets Received 0b =    Not Cleared 1b =    Cleared
#define    TOTAL_UNICAST_PKT_XMIT_CLEARED            0x02 // 1  Total FCoE Packets Transmitted  0b =    Not Cleared 1b =    Cleared
#define    FCS_ERRORS_CLEARED                        0x04 // 2  FCS Receive Errors  0b =    Not Cleared 1b = Cleared
#define    FC_CRC_ERR_CNT_CLEARED                    0x08 // 3  FC CRC Error Count  0b =    Not Cleared 1b = Cleared
#define    FIP_LOGIN_FAILURE_CNT_CLEARED             0x10 // 4  FIP Login Failure Count 0b =    Not Cleared 1b = Cleared
	// 7:5    Reserved
	DellFcoeStat_t  stat;
#elif defined (LITTLE_ENDIAN)
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     CountersClearedFromLastRead;                            // Counters Cleared from Last Read
#define    TOTAL_UNICAST_PKT_RCVD_CLEARED            0x01 // 0  Total FCoE Packets Received 0b =    Not Cleared 1b =    Cleared
#define    TOTAL_UNICAST_PKT_XMIT_CLEARED            0x02 // 1  Total FCoE Packets Transmitted  0b =    Not Cleared 1b =    Cleared
#define    FCS_ERRORS_CLEARED                        0x04 // 2  FCS Receive Errors  0b =    Not Cleared 1b = Cleared
#define    FC_CRC_ERR_CNT_CLEARED                    0x08 // 3  FC CRC Error Count  0b =    Not Cleared 1b = Cleared
#define    FIP_LOGIN_FAILURE_CNT_CLEARED             0x10 // 4  FIP Login Failure Count 0b =    Not Cleared 1b = Cleared
	// 7:5    Reserved
	u8_t     PartitionId;                                            // Partition ID
	u8_t     CommandType;          /* OEM command ID */
	u8_t     PayloadVersion;
	DellFcoeStat_t  stat;
#endif // endian
} DellGetFcoeStatisticsCmdRspData_t;


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x07    Set Address Used to program virtual addresses of a partition enabled in a specific channel. 0x07    (Mandatory)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct DellSetAddrCmd
{
#if defined (BIG_ENDIAN)
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID
	u8_t     PartitionId;
	// The Partition ID field indicates the PCI identity of the partition
#define NP_DEVICE_ID_MASK              0x18
#define NP_DEVICE_ID_MASK_SHIFT          3
#define NP_FUNC_ID_MASK                0x7
#define NP_FUNC_ID_MASK_SHIFT            0
	u8_t   AddrLength;
#define          MAC_ADDR_LENGTH_MAX                      8
	u8_t     AddrType;
	// Field to define type of address that follows
	// 0x0 = Reserved
	// 0x1 = LAN
	// 0x2 = iSCSI
	// 0x3 = WWN
	// 0x4 = FCoE-FIP
	// 0x5 = IB GUID
	// 0x6 = LAN/iSCSI
	// 0x7 = LAN/FCoE-FIP
	// 0x8 = iSCSI/FCoE-FIP
	// 0x9-0xFF = Reserved
#define          MAC_ADDR_TYPE_RESERVED                   0x0
#define          MAC_ADDR_TYPE_LAN                        0x1
#define          MAC_ADDR_TYPE_ISCSI                      0x2
#define          MAC_ADDR_TYPE_WWN                        0x3
#define          MAC_ADDR_TYPE_FCOE_FIP                   0x4
#define          MAC_ADDR_TYPE_IB GUID                    0x5
#define          MAC_ADDR_TYPE_MAX                        0x6

	u8_t   AddrBuf[MAC_ADDR_LENGTH_MAX];
#elif defined (LITTLE_ENDIAN)
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     AddrLength;
#define          MAC_ADDR_LENGTH_MAX                      8
	u8_t     PartitionId;
	// The Partition ID field indicates the PCI identity of the partition
#define NP_DEVICE_ID_MASK              0x18
#define NP_DEVICE_ID_MASK_SHIFT          3
#define NP_FUNC_ID_MASK                0x7
#define NP_FUNC_ID_MASK_SHIFT            0
	u8_t     CommandType;          /* OEM command ID */
	u8_t     PayloadVersion;

	u8_t     AddrBufTemp[3];  // the rest of TLV data up to 16 bytes

	u8_t     AddrType;
	// The MAC Addr Type
	// Field to define type of address that follows
	// 0x0 = Reserved
	// 0x1 = LAN
	// 0x2 = iSCSI
	// 0x3 = WWN
	// 0x4 = FCoE-FIP
	// 0x5 = IB GUID
	// 0x6 = LAN/iSCSI
	// 0x7 = LAN/FCoE-FIP
	// 0x8 = iSCSI/FCoE-FIP
	// 0x9-0xFF = Reserved
#define          MAC_ADDR_TYPE_RESERVED                   0x0
#define          MAC_ADDR_TYPE_LAN                        0x1
#define          MAC_ADDR_TYPE_ISCSI                      0x2
#define          MAC_ADDR_TYPE_WWN                        0x3
#define          MAC_ADDR_TYPE_FCOE_FIP                   0x4
#define          MAC_ADDR_TYPE_IB GUID                    0x5
#define          MAC_ADDR_TYPE_MAX                        0x6
	u8_t     AddrBuf[MAC_ADDR_LENGTH_MAX-3];
#endif // ENDIAN
}DellSetAddrCmd_t;


typedef struct DellRspsPartition
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID
	u8_t     PartitionId;
	// The Partition ID field indicates the PCI identity of the partition
#define NP_DEVICE_ID_MASK              0x18
#define NP_DEVICE_ID_MASK_SHIFT          3
#define NP_FUNC_ID_MASK                0x7
#define NP_FUNC_ID_MASK_SHIFT            0
	u8_t     Reserved;

#elif defined (LITTLE_ENDIAN)
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     Reserved;
	u8_t     PartitionId;
	// The Partition ID field indicates the PCI identity of the partition
#define NP_DEVICE_ID_MASK              0x18
#define NP_DEVICE_ID_MASK_SHIFT          3
#define NP_FUNC_ID_MASK                0x7
#define NP_FUNC_ID_MASK_SHIFT            0
	u8_t     CommandType;          /* OEM command ID */
	u8_t     PayloadVersion;
#endif // endian
} DellRspsPartition_t;
typedef DellRspsPartition_t DellSetAddrCmdRspData_t;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x08    Get Address Used to read virtual and permanent addresses of a partition enabled in a specific channel.  0x08    (Mandatory)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct DellGetAddrCmd
{
#if defined (BIG_ENDIAN)
	u32_t    anufacturerId;  /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType; /* OEM command ID */
	u8_t     PartitionId;
	// The Partition ID field indicates the PCI identity of the partition
#define NP_DEVICE_ID_MASK              0x18
#define NP_DEVICE_ID_MASK_SHIFT          3
#define NP_FUNC_ID_MASK                0x7
#define NP_FUNC_ID_MASK_SHIFT            0
	u8_t     AddrVer;
	// The MAC Addr Type
	// bit 0 MAC Source 0b = Permanent MAC Address
	//                  1b = Active MAC Address
#define MAC_ADDR_VER_MAC_SOURCE_MASK         0x1
#define          MAC_ADDR_VER_MAC_SOURCE_PERMANENT    0x0
#define          MAC_ADDR_VER_MAC_SOURCE_VIRTUAL      0x1

#elif defined (LITTLE_ENDIAN)
	u32_t    ManufacturerId;    /* ManufacturerId IANA */
	u8_t     AddrVer;
	// The MAC Addr Type
	// bit 0 MAC Source 0b = Permanent MAC Address
	//                  1b = Active MAC Address
#define MAC_ADDR_VER_MAC_SOURCE_MASK         0x1
#define          MAC_ADDR_VER_MAC_SOURCE_PERMANENT    0x0
#define          MAC_ADDR_VER_MAC_SOURCE_VIRTUAL      0x1
	u8_t     PartitionId;
	// The Partition ID field indicates the PCI identity of the partition
#define NP_DEVICE_ID_MASK              0x18
#define NP_DEVICE_ID_MASK_SHIFT          3
#define NP_FUNC_ID_MASK                0x7
#define NP_FUNC_ID_MASK_SHIFT            0
	u8_t     CommandType; /* OEM command ID */
	u8_t     PayloadVersion;
#endif // ENDIAN
}DellGetAddrCmd_t;

typedef struct DellGetAddrCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID
	u8_t     PartitionId;
	// The Partition ID field indicates the PCI identity of the partition
#define NP_DEVICE_ID_MASK              0x18
#define NP_DEVICE_ID_MASK_SHIFT          3
#define NP_FUNC_ID_MASK                0x7
#define NP_FUNC_ID_MASK_SHIFT            0
	u8_t   FirstAddrLength;
#define          MAC_ADDR_LENGTH_MAX                      8
	u8_t     FirstAddrType;
	// Field to define type of address that follows
	// 0x0 = Reserved
	// 0x1 = LAN
	// 0x2 = iSCSI
	// 0x3 = WWN
	// 0x4 = FCoE-FIP
	// 0x5 = IB GUID
	// 0x6 = LAN/iSCSI
	// 0x7 = LAN/FCoE-FIP
	// 0x8 = iSCSI/FCoE-FIP
	// 0x9-0xFF = Reserved
#define          MAC_ADDR_TYPE_RESERVED                   0x0
#define          MAC_ADDR_TYPE_LAN                        0x1
#define          MAC_ADDR_TYPE_ISCSI                      0x2
#define          MAC_ADDR_TYPE_WWN                        0x3
#define          MAC_ADDR_TYPE_FCOE_FIP                   0x4
#define          MAC_ADDR_TYPE_IB GUID                    0x5
#define          MAC_ADDR_TYPE_MAX                        0x6
	u8_t   AddrBuf[5*(MAC_ADDR_LENGTH_MAX + 2)];
	// In the future, we might have up to 5 addresses for each PF

#elif defined (LITTLE_ENDIAN)
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
	u32_t                            ManufacturerId;        /* ManufacturerId IANA */
	u8_t   FirstAddrLength;
#define          MAC_ADDR_LENGTH_MAX                      8
	u8_t     PartitionId;
	// The Partition ID field indicates the PCI identity of the partition
#define NP_DEVICE_ID_MASK              0x18
#define NP_DEVICE_ID_MASK_SHIFT          3
#define NP_FUNC_ID_MASK                0x7
#define NP_FUNC_ID_MASK_SHIFT            0
	u8_t     CommandType;
	// OEM command ID
	u8_t     PayloadVersion;


	u8_t   AddrBufTemp[3];
	u8_t     FirstAddrType;
	// Field to define type of address that follows
	// 0x0 = Reserved
	// 0x1 = LAN
	// 0x2 = iSCSI
	// 0x3 = WWN
	// 0x4 = FCoE-FIP
	// 0x5 = IB GUID
	// 0x6 = LAN/iSCSI
	// 0x7 = LAN/FCoE-FIP
	// 0x8 = iSCSI/FCoE-FIP
	// 0x9-0xFF = Reserved
#define          MAC_ADDR_TYPE_RESERVED                   0x0
#define          MAC_ADDR_TYPE_LAN                        0x1
#define          MAC_ADDR_TYPE_ISCSI                      0x2
#define          MAC_ADDR_TYPE_WWN                        0x3
#define          MAC_ADDR_TYPE_FCOE_FIP                   0x4
#define          MAC_ADDR_TYPE_IB GUID                    0x5
#define          MAC_ADDR_TYPE_MAX                        0x6
	u8_t   AddrBuf[5*(MAC_ADDR_LENGTH_MAX + 2)-3];

#endif // endian
} DellGetAddrCmdRspData_t;



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x09    Set License Used to program license for licensable features of Ethernet Controller. 0x09    (Conditional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct DellSetLicenseCmd
{
#if defined (BIG_ENDIAN)
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID
	u16_t           Reserved;
	u32_t           FEB;            // Feature Enablement Bitmap (FEB)
#define FEB_ISOE       1    // 0   iSOE    0b = Disable the License for iSOE 1b = Enable the License for iSOE
#define FEB_FCOE       2    // 1   FCoE    0b = Disable the License for FCoE 1b = Enable the License for FCoE
	// 2-31    Reserved
	u8_t            EPO[24];        // EntitlementID Plus Object (EPO)
					// EntitlementID Plus object field is a 24 byte ASCII string
					// defined by the Dell license manager. Ethernet Controllers
					// shall store the information when provided by the Management Controller.
#elif defined (LITTLE_ENDIAN)
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u16_t           Reserved;
	u8_t     CommandType;
	// OEM command ID
	u8_t     PayloadVersion;
	u32_t           FEB;            // Feature Enablement Bitmap (FEB)
#define FEB_ISOE       1    // 0   iSOE    0b = Disable the License for iSOE 1b = Enable the License for iSOE
#define FEB_FCOE       2    // 1   FCoE    0b = Disable the License for FCoE 1b = Enable the License for FCoE
	// 2-31    Reserved
	u8_t            EPO[24];        // EntitlementID Plus Object (EPO)
					// EntitlementID Plus object field is a 24 byte ASCII string
					// defined by the Dell license manager. Ethernet Controllers
					// shall store the information when provided by the Management Controller.
#endif // ENDIAN
}DellSetLicenseCmd_t;

typedef struct DellSetLicenseCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID

	u16_t           Reserved;
	u32_t           EFB;            // Enabled Features Bitmap Field
#define EFB_ISOE       1    // 0    iSOE    0b = Disable the License for iSOE  1b = Enable the License for iSOE
#define EFB_FCOE       2    // 1    FCoE    0b = Disable the License for FCoE  1b = Enable the License for FCoE
	// 2-31 Reserved    2-31    Reserved
#elif defined (LITTLE_ENDIAN)
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u16_t           Reserved;
	u8_t     CommandType;
	// OEM command ID
	u8_t     PayloadVersion;
	u32_t           EFB;            // Enabled Features Bitmap Field
#define EFB_ISOE       1    // 0    iSOE    0b = Disable the License for iSOE  1b = Enable the License for iSOE
#define EFB_FCOE       2    // 1    FCoE    0b = Disable the License for FCoE  1b = Enable the License for FCoE
#endif // endian
} DellSetLicenseCmdRspData_t;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x0A    Get License Used to read licensable features information of the Ethernet Controller.    0x0A    (Conditional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef DellDfltCmd_t DellGetLicenseCmd_t;

typedef struct DellGetLicenseCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID

	u8_t        StorageType;                  // Storage Type
#define LICENSE_PERSISTENT         1  // 0   Storage Type    0b = License is persistent 1b = License is not persistent
	// 1-7 Reserved
	u8_t        Reserved;                     // Reserved
	u32_t       EFB;                          // Enabled Features  Bitmap (EFB)
#define EFB_iSOE    (1)               // 0   iSOE    0b = iSOE license is disabled 1b = iSOE license is enabled
#define EFB_FCoE    (2)               // 1   FCoE    0b = FCoE license is disabled 1b = FCoE license is enabled
	// 2-31    Reserved
	//
	u32_t       FCB;                          // Feature Capability Bitmap  (FCB)
#define FCB_iSOE    (1)               // 0   iSOE    0b = Not capable of licensing iSOE  1b = Capable of licensing iSOE
#define FCB_FCoE    (2)               // 1   FCoE    0b = Not capable of licensing FCoE  1b = Capable of licensing FCoE
	// 2-31    Reserved
	u8_t            UID[16];                  // Unique Identifier (UID)
						  // The Unique Identifier field is a 16 byte ASCII string defined to uniquely identify the Ethernet Controller. It is generated using the permanent MAC address of PCI physical function 0 of the Ethernet Controller. The least 12 bytes is the permanent LAN MAC address of the PCI Physical function 0 and most significant 4 bytes is padded with zeroes.  UID shall be all zeros if the Ethernet Controller cannot provide it.
						  // Example:  "00000019D2485C12" for MAC address 00:19:D2:48:5C:12
	u8_t            EPO[24];                  // EntitlementID Plus Object (EPO)
						  // EntitlementID Plus object field is a 24 byte string defined by the Dell license manager. Ethernet Controllers shall store the information when provided by the Management Controller. EPO shall be all zeroes if not provided by the Management Controller.
#elif defined (LITTLE_ENDIAN)
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
	u32_t                            ManufacturerId;        /* ManufacturerId IANA */
	u8_t        Reserved;                     // Reserved
	u8_t        StorageType;                  // Storage Type
#define LICENSE_PERSISTENT         1  // 0   Storage Type    0b = License is persistent 1b = License is not persistent
	// 1-7 Reserved
	u8_t     CommandType;
	// OEM command ID

	u8_t     PayloadVersion;
	u32_t       EFB;                          // Enabled Features  Bitmap (EFB)
#define EFB_iSOE    (1)               // 0   iSOE    0b = iSOE license is disabled 1b = iSOE license is enabled
#define EFB_FCoE    (2)               // 1   FCoE    0b = FCoE license is disabled 1b = FCoE license is enabled
	// 2-31    Reserved
	//
	u32_t       FCB;                          // Feature Capability Bitmap  (FCB)
#define FCB_iSOE    (1)               // 0   iSOE    0b = Not capable of licensing iSOE  1b = Capable of licensing iSOE
#define FCB_FCoE    (2)               // 1   FCoE    0b = Not capable of licensing FCoE  1b = Capable of licensing FCoE
	// 2-31    Reserved
	u8_t            UID[16];                  // Unique Identifier (UID)
						  // The Unique Identifier field is a 16 byte ASCII string defined to uniquely identify the Ethernet Controller. It is generated using the permanent MAC address of PCI physical function 0 of the Ethernet Controller. The least 12 bytes is the permanent LAN MAC address of the PCI Physical function 0 and most significant 4 bytes is padded with zeroes.  UID shall be all zeros if the Ethernet Controller cannot provide it.
						  // Example:  "00000019D2485C12" for MAC address 00:19:D2:48:5C:12
	u8_t            EPO[24];                  // EntitlementID Plus Object (EPO)
						  // EntitlementID Plus object field is a 24 byte string defined by the Dell license manager. Ethernet Controllers shall store the information when provided by the Management Controller. EPO shall be all zeroes if not provided by the Management Controller.
#endif // endian
} DellGetLicenseCmdRspData_t;



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x0B    Set Passthru Control    Used to enable/disable different passthru data paths in the Controller. 0x0B    (Conditional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef struct DellSetPassthruCtrlCmd
{
#if defined (BIG_ENDIAN)
	u32_t    ManufacturerId;      /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID
	u8_t    PassthruType;    // Passthru Type
#define PASSTHRU_ENABLE                  1               // 0   Status  0b = Disable 1b = Enable
#define PASSTHRU_MASK               (1<<1)               // 7..1    Type
#define OS_BMC_PASSTHRU             (0<<1)           //     0x00 = OS-BMC Passthru
#define NETW_BMC_PASSTHRU           (1<<1)           //     0x01 = Network-BMC Passthru
	//     0x02-0x7F = Reserved
	u8_t    Pad;                                // Pad (0x00)
#elif defined (LITTLE_ENDIAN)
	u32_t   ManufacturerId;    /* ManufacturerId IANA */
	u8_t    Pad;                                // Pad (0x00)
	u8_t    PassthruType;    // Passthru Type
#define PASSTHRU_ENABLE                  1               // 0   Status  0b = Disable 1b = Enable
#define PASSTHRU_MASK               (1<<1)               // 7..1    Type
#define OS_BMC_PASSTHRU             (0<<1)           //     0x00 = OS-BMC Passthru
#define NETW_BMC_PASSTHRU           (1<<1)           //     0x01 = Network-BMC Passthru
	//     0x02-0x7F = Reserved
	u8_t     CommandType;
	// OEM command ID
	u8_t     PayloadVersion;
#endif // ENDIAN
}DellSetPassthruCtrlCmd_t;

typedef struct DellRspsDefault
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID

	u16_t    Pad;                                // Pad (0x00)
#elif defined (LITTLE_ENDIAN)
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
	u32_t                            ManufacturerId;        /* ManufacturerId IANA */
	u16_t    Pad;                                // Pad (0x00)
	u8_t     CommandType;
	// OEM command ID

	u8_t     PayloadVersion;
#endif // endian
} DellRspsDefault_t;

typedef DellRspsDefault_t DellSetPassthruCtrlCmdRspData_t;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x0C    Get Passthru Control    Used to read current status of different passthru data paths in the Controller  0x0C    (Mandatory)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct DellGetPassthruCtrlCmd
{
#if defined (BIG_ENDIAN)
	u32_t    ManufacturerId;         /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID
	u8_t    PassthruType;    // Passthru Type
				 // 0   Reserved
#define PASSTHRU_MASK               (1<<1)               // 7..1    Type
#define OS_BMC_PASSTHRU             (0<<1)           //     0x00 = OS-BMC Passthru
#define NETW_BMC_PASSTHRU           (1<<1)           //     0x01 = Network-BMC Passthru
	//     0x02-0x7F = Reserved
	u8_t    Pad;                                // Pad (0x00)
#elif defined (LITTLE_ENDIAN)
	u32_t   ManufacturerId;         /* ManufacturerId IANA */
	u8_t    Pad;                                // Pad (0x00)
	u8_t    PassthruType;    // Passthru Type
				 // 0   Reserved
#define PASSTHRU_MASK               (1<<1)               // 7..1    Type
#define OS_BMC_PASSTHRU             (0<<1)           //     0x00 = OS-BMC Passthru
#define NETW_BMC_PASSTHRU           (1<<1)           //     0x01 = Network-BMC Passthru
	//     0x02-0x7F = Reserved
	u8_t     CommandType;
	// OEM command ID
	u8_t     PayloadVersion;
#endif // ENDIAN
}DellGetPassthruCtrlCmd_t;

typedef struct DellGetPassthruCtrlCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID

	u8_t    PassthruType;               // Passthru Type
#define PASSTHRU_ENABLE                  1               // 0   Status  0b = Disable 1b = Enable
#define PASSTHRU_MASK               (1<<1)               // 7..1    Type
#define OS_BMC_PASSTHRU             (0<<1)           //     0x00 = OS-BMC Passthru
#define NETW_BMC_PASSTHRU           (1<<1)           //     0x01 = Network-BMC Passthru
	//     0x02-0x7F = Reserved
	u8_t    Pad;                                // Pad (0x00)
#elif defined (LITTLE_ENDIAN)
	u16_t   ReasonCode;            /* ids reasons for rsp  */
	u16_t   ResponseCode;          /* ids outcome of cmd   */
	u32_t   ManufacturerId;        /* ManufacturerId IANA */
	u8_t    Pad;                                // Pad (0x00)
	u8_t    PassthruType;           // Passthru Type
#define PASSTHRU_ENABLE                  1               // 0   Status  0b = Disable 1b = Enable
#define PASSTHRU_MASK               (1<<1)               // 7..1    Type
#define OS_BMC_PASSTHRU             (0<<1)           //     0x00 = OS-BMC Passthru
#define NETW_BMC_PASSTHRU           (1<<1)           //     0x01 = Network-BMC Passthru
	//     0x02-0x7F = Reserved
	u8_t     CommandType;
	// OEM command ID

	u8_t     PayloadVersion;
#endif // endian
} DellGetPassthruCtrlCmdRspData_t;



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x0D    Set Partition TX Bandwidth  Used to configure bandwidth of a partition enabled on a specific channel.   0x0D    (Conditional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct DellSetPartitionTxBandwidthCmd
{
#if defined (BIG_ENDIAN)
	u32_t    ManufacturerId;   /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID
	u8_t    PartitionId;    //  Partition ID
	u8_t    MinBandwidth;   //  Minimum Bandwidth   value ranges from 0 to 100
	u8_t    MaxBandwidth;   //  Maximum Bandwidth   value ranges from 0 to 100
	u8_t    Pad[3];                               // Pad
#elif defined (LITTLE_ENDIAN)
	u32_t   ManufacturerId;         /* ManufacturerId IANA */
	u8_t    MinBandwidth;   //  Minimum Bandwidth   value ranges from 0 to 100
	u8_t    PartitionId;    //  Partition ID
	u8_t     CommandType;
	// OEM command ID
	u8_t     PayloadVersion;
	u8_t    Pad[3];                               // Pad
	u8_t    MaxBandwidth;   //  Maximum Bandwidth   value ranges from 0 to 100
#endif // ENDIAN
}DellSetPartitionTxBandwidthCmd_t;

typedef DellRspsPartition_t DellSetPartitionTxBandwidthCmdRspData_t;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x0E    Get Partition TX Bandwidth  Used to read bandwidth of a partition enabled on a specific channel.    0x0E    (Conditional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef DellCmdPartition_t DellGetPartitionTxBandwidthCmd_t;

typedef struct DellGetPartitionTxBandwidthCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID

	u8_t    PartitionId;    //  Partition ID
	u8_t    MinBandwidth;   //  Minimum Bandwidth   value ranges from 0 to 100
	u8_t    MaxBandwidth;   //  Maximum Bandwidth   value ranges from 0 to 100
	u8_t    Pad[3];                               // Pad
#elif defined (LITTLE_ENDIAN)
	u16_t   ReasonCode;            /* ids reasons for rsp  */
	u16_t   ResponseCode;          /* ids outcome of cmd   */
	u32_t   ManufacturerId;     /*     ManufacturerId IANA */
	u8_t    MinBandwidth;   //  Minimum Bandwidth   value ranges from 0 to 100
	u8_t    PartitionId;    //  Partition ID
	u8_t     CommandType;
	// OEM command ID
	u8_t     PayloadVersion;
	u8_t    Pad[3];                               // Pad
	u8_t    MaxBandwidth;   //  Maximum Bandwidth   value ranges from 0 to 100
#endif // endian
} DellGetPartitionTxBandwidthCmdRspData_t;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x0F    Set MC IP Address   Used to program the IP address of the Management Controller.    0x0F    (Optional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  The Set MC IP Address command allows the Management controller to provide
//  its own IP address to the Ethernet Controller for OS-BMC operations. This
//  IP address must be programmed before the OS-BMC feature is enabled.
//  Type-Length and IP addresses fields are repeated if the Management
//  Controller is to be configured to work in both IPv4 and IPV6 network
//  environments.
//
//  The Set MC IP Address Command is addressed to the package, rather than
//  to a particular channel (that is, the command is sent with a Channel ID
//  where the Package ID subfield matches the ID of the intended package and
//  the Internal Channel ID subfield is set to 0x1F).
typedef struct DellSetMcIpAddrCmd
{
#if defined (BIG_ENDIAN)
	u32_t    ManufacturerId;         //* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID
	u8_t   AddrType;                                        // 7:0  IP Address Type     Field to define type of address that follows
#define ADDR_TYPE_IPv4                0         //     0x0 = IPv4
#define ADDR_TYPE_IPv6                1         //     0x1 = IPv6
	//     0x2-0xFF = Reserved
	u8_t   Length;                                          // 15:8 IP Address Length   The length indicates the number of bytes used to represent the IP Address.
	u8_t   Addr[16];                                        //  IP Address shall be provided in hexadecimal and
								//  the least significant byte of the IP Address
								//  field should carry the first octet of the address.
#elif defined (LITTLE_ENDIAN)
	u32_t   ManufacturerId;         /* ManufacturerId IANA */
	u8_t   Length;                                          // 15:8 IP Address Length   The length indicates the number of bytes used to represent the IP Address.
	u8_t   AddrType;                                        // 7:0  IP Address Type     Field to define type of address that follows
#define ADDR_TYPE_IPv4                0         //     0x0 = IPv4
#define ADDR_TYPE_IPv6                1         //     0x1 = IPv6
	//     0x2-0xFF = Reserved
	u8_t     CommandType;
	// OEM command ID
	u8_t     PayloadVersion;
	u8_t   Addr[16];                                        //  IP Address shall be provided in hexadecimal and
								//  the least significant byte of the IP Address
								//  field should carry the first octet of the address.

#endif // ENDIAN
}DellSetMcIpAddrCmd_t;


typedef DellRspsDefault_t DellSetMcIpAddrCmdRspData_t;



//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x10    Get Teaming Information Used to read Network teaming information of a partition in a specific channel.  0x10    (Optional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef DellCmdPartition_t DellGetTeamingInfoCmd_t;

typedef struct DellGetTeamingInfoCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID

	u8_t    PartitionId;
	u8_t    TeamingInfo;                            // Team Information
#define     TEAMING_ENABLED    1            //  0   Network Teaming Status  0b = Network Teaming is not enabled 1b = Network Teaming is enabled
#define     TEAMING_ID_MASK    (0x7F << 1)  //  7:1 Team ID Team ID represents the ID of the team of which the network interface on a partition is one of the members. The value ranges from 0x00 - 0x7F.
	u8_t    TeamLength;                             //  15..8   Team Length:    Value indicates the length of the string to represent the name of the Team type. Ex: IEEE 802.3ad
	u8_t    TeamType;                               //  7..0    Team Type
#define TEAM_TYPE_UNKNOWNR          0x0 //      0x0 = Unknown
#define TEAM_TYPE_FAILOVER          0x1 //      0x1 =  Failover
#define TEAM_TYPE_LOAD_BALANCE      0x2 //      0x2 =  Load Balance
#define TEAM_TYPE_LINK_AGGREGATION  0x3 //      0x3 =  Link Aggregation
	//      0x4-0xFF = Reserved
	u8_t    TeamName[16];
#elif defined (LITTLE_ENDIAN)
	u16_t   ReasonCode;            /* ids reasons for rsp  */
	u16_t   ResponseCode;          /* ids outcome of cmd   */
	u32_t   ManufacturerId;        /* ManufacturerId IANA */
	u8_t    TeamingInfo;                            // Team Information
	u8_t    PartitionId;

	u8_t     CommandType;
	// OEM command ID
	u8_t     PayloadVersion;
#define     TEAMING_ENABLED    1            //  0   Network Teaming Status  0b = Network Teaming is not enabled 1b = Network Teaming is enabled
#define     TEAMING_ID_MASK    (0x7F << 1)  //  7:1 Team ID Team ID represents the ID of the team of which the network interface on a partition is one of the members. The value ranges from 0x00 - 0x7F.
	u8_t    TeamNameExtra[2];
	u8_t    TeamType;                               //  7..0    Team Type
#define TEAM_TYPE_UNKNOWNR          0x0 //      0x0 = Unknown
#define TEAM_TYPE_FAILOVER          0x1 //      0x1 =  Failover
#define TEAM_TYPE_LOAD_BALANCE      0x2 //      0x2 =  Load Balance
#define TEAM_TYPE_LINK_AGGREGATION  0x3 //      0x3 =  Link Aggregation
	//      0x4-0xFF = Reserved
	u8_t    TeamLength;                             //  15..8   Team Length:    Value indicates the length of the string to represent the name of the Team type. Ex: IEEE 802.3ad
	u8_t    TeamName[16-2];
#endif // endian
} DellGetTeamingInfoCmdRspData_t;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x11    Enable Ports    Used to enable physical ports of the Ethernet Controller.   0x11    (Mandatory)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef DellDfltCmd_t DellEnablePortsCmd_t;
typedef DellRspsDefault_t DellEnablePortsCmdRspData_t;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x12    Disable Ports   Used to disable physical ports of the Ethernet Controller.  0x12    (Mandatory)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef DellDfltCmd_t DellDisablePortsCmd_t;
typedef DellRspsDefault_t DellDisablePortsCmdRspData_t;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x13    Get Temperature Used to read on-chip temperature values of the Ethernet Controller. 0x13    (Conditional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef DellDfltCmd_t DellGetTempCmd_t;
typedef struct DellGetTempCmdRspData
{
#if defined (BIG_ENDIAN)
	u16_t    ResponseCode;          /* ids outcome of cmd   */
	u16_t    ReasonCode;            /* ids reasons for rsp  */
	u32_t    ManufacturerId;        /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID

	u8_t MaxTemp;    // Maximum temperature in degrees Celsius
	u8_t CurTemp;    // Current temperature in degrees Celsius
#elif defined (LITTLE_ENDIAN)
	u16_t   ReasonCode;            /* ids reasons for rsp  */
	u16_t   ResponseCode;          /* ids outcome of cmd   */
	u32_t   ManufacturerId;        /* ManufacturerId IANA */
	u8_t CurTemp;    // Current temperature in degrees Celsius
	u8_t MaxTemp;    // Maximum temperature in degrees Celsius

	u8_t     CommandType;
	// OEM command ID
	u8_t     PayloadVersion;
#endif // endian
} DellGetTempCmdRspData_t;


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x14    Set Link Tuning Used to configure Link Tuning parameters of a specific channel. 0x14    (Conditional)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct DellSetLinkTuningCmd
{
#if defined (BIG_ENDIAN)
	u32_t    ManufacturerId;         /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	// OEM command ID
	u8_t    LinkTuning[8];         // Link Tuning Data is an 8 byte value defined in accordance with the Link Tuning and FlexAddress Interface Specification
	u16_t    Pad;                               // Pad
#elif defined (LITTLE_ENDIAN)
	u32_t    ManufacturerId;         /* ManufacturerId IANA */
	u8_t    LinkTuning_first[2];         // Link Tuning Data is an 8 byte value defined in accordance with the Link Tuning and FlexAddress Interface Specification
	u8_t     CommandType;
	// OEM command ID
	u8_t     PayloadVersion;
	u8_t    LinkTuning[4];         // Link Tuning Data is an 8 byte value defined in accordance with the Link Tuning and FlexAddress Interface Specification
	u16_t    Pad;                               // Pad
	u8_t    LinkTuning_last[2];    // Link Tuning Data is an 8 byte value defined in accordance with the Link Tuning and FlexAddress Interface Specification
#endif // ENDIAN
}DellSetLinkTuningCmd_t;


typedef DellRspsDefault_t DellSetLinkTuningCmdRspData_t;

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  0x15    Enable OutOfBox WOL Used to enable OutOfBox WOL on a specific channel.  0x15    (Mandatory)
//  0x16    Disable OutOfBox WOL    Used to disable OutOfBox WOL on a specific channel. 0x16    (Mandatory)
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef DellDfltCmd_t DellEnableDisableOutOfBoxWolCmd_t;
typedef DellRspsDefault_t DellEnableDisableOutOfBoxWolCmdRspData_t;

/*MAX_TLV_COMMAND_SIZE :(i.e.  GetiSCSIBootTargetConfig)
		connectTgt                         2+8 =10 (“Disabled”)
		TgtIpAddress                     2+39=41 (IPv6 max size is 39)
		TgtTcpPort                          2+5=7  (2^16 so 5 digits)
		TgtBootLun                         2+3=5 (max support is 256)
		TgtIscsiName                     2+128=130
		TgtChapId                           2+128=130
		TgtChapPwd                      2+16=18
		TgtIpVer                              2+4= 6 (“IPv6”)

		Total 347 *2 = 694 bytes (for 1st and 2nd target) just for TLVs
*/
#define MAX_TLV_COMMAND_SIZE  (694)
/*
//  0x1A  Get Supported Payload Version - Used to indicate Payload Versions supported by controller (Mandatory)
//  0x1C  Get iSCSI Offload Statistics - Used to get vendor version ID of the OS driver currently running on the
//  partition(or Port) (Mandatory)
//  0x1D  Get iSCSI Boot Initiator Config Command - query the channel (partition) for the iSCSI Boot Initiator settings
//  configured on the channel (Mandatory)
//  0x1E  Set iSCSI Boot Initiator Config Command - send to the channel (partition) the iSCSI Boot Initiator settings
//  to be used by the channel (Mandatory)
//  0x1F  Get iSCSI Boot Target Config Command - query the channel for the iSCSI Boot Target configuration settings of
//  the port or partition (Mandatory)
//  0x20  Set iSCSI Boot Target Config Command - send to the channel (partition) the iSCSI Boot Target settings to be
//  used by the channel (Mandatory)
//  0x21  Get FC/FCoE Boot Target Config Command - query the channel for the FC/FCoE Boot Target configuration settings
//  of the port or partition (Mandatory)
//  0x22  Set FC/FCoE Boot Target Config Command - send to the channel (partition) the FC/FCoE Boot Target settings to
//  be used by the channel (Mandatory)
//  0x23  NVRAM Commit Command - instructs the Ethernet or FC Controller to write attribute settings held in temporary
//  storage to the controller’s NVRAM  (Mandatory)
//  0x24  NVRAM Commit Status Command - send to the channel (partition) the iSCSI Boot Target settings to be used by
//  the channel (Mandatory)
*/

typedef struct
{
	u32_t    ManufacturerId; /* ManufacturerId IANA */
	u8_t     PayloadVersion;
	u8_t     CommandType;
	u8_t     PartitionId;
	u8_t     NumOfTLVs;
	/*This is a place holder for the Maximum size in bytesof this command with all TLV's present*/
	u8_t     buf[MAX_TLV_COMMAND_SIZE];
} DellOemCmdPartitionTLV_t;

typedef DellDfltCmd_t DellGetSupportedVerCmd_t;
typedef DellCmdPartition_t DellGetOsDriverVerCmd_t;
typedef DellCmdPartition_t DellGetiScsiInitiatorConfCmd_t;
typedef DellOemCmdPartitionTLV_t DellSetiScsiInitiatorConfCmd_t;
typedef DellCmdPartition_t DellGetiScsiTargetConfCmd_t;
typedef DellOemCmdPartitionTLV_t DellSetiScsiTargetConfCmd_t;
typedef DellCmdPartition_t DellGetFcoeTargetConfCmd_t;
typedef DellOemCmdPartitionTLV_t DellSetFcoeTargetConfCmd_t;
typedef DellDfltCmd_t DellCommitNvramCmd_t;
typedef DellDfltCmd_t DellGetCommitNvramStatusCmd_t;

typedef union DellOemCmdPayload
{
	// Dell OEM NCSI commands
	DellGetInventoryCmd_t               GetInventoryCmd;              // DELL_OEM_GET_INVENTORY_CMD
	DellGetExtendedCapabilitiesCmd_t    GetExtendedCapabilitiesCmd;   // DELL_OEM_GET_EXTENDED_CAPABILITIES_CMD
	DellGetPartitionInfoCmd_t           GetPartitionInfoCmd;          // DELL_OEM_GET_PARTITION_INFORMATION_CMD
	DellGetFcoeCapabilitiesCmd_t        GetFcoeCapabilitiesCmd;       // DELL_OEM_GET_FCOE_CAPABILITIES_CMD
	DellGetVirtualLinkCmd_t             GetVirtualLinkCmd;            // DELL_OEM_GET_VIRTUAL_LINK_CMD
	DellGetLanStatisticsCmd_t           GetLanStatisticsCmd;          // DELL_OEM_GET_LAN_STATISTICS_CMD
	DellGetFcoeStatisticsCmd_t          GetFcoeStatisticsCmd;         // DELL_OEM_GET_FCOE_STATISTICS_CMD
	DellSetAddrCmd_t                    SetAddrCmd;                   // DELL_OEM_SET_ADDR_CMD
	DellGetAddrCmd_t                    GetAddrCmd;                   // DELL_OEM_GET_ADDR_CMD
	DellSetLicenseCmd_t                 SetLicenseCmd;                // DELL_OEM_SET_LICENSE_CMD
	DellGetLicenseCmd_t                 GetLicenseCmd;                // DELL_OEM_GET_LICENSE_CMD
	DellSetPassthruCtrlCmd_t            SetPassthruCtrlCmd;           // DELL_OEM_SET_PASSTHRU_CONTROL_CMD
	DellGetPassthruCtrlCmd_t            GetPassthruCtrlCmd;           // DELL_OEM_GET_PASSTHRU_CONTROL_CMD
	DellSetPartitionTxBandwidthCmd_t    SetPartitionTxBandwidthCmd;   // DELL_OEM_SET_PARTITIONCmd_tX_BANDWIDTH_CMD
	DellGetPartitionTxBandwidthCmd_t    GetPartitionTxBandwidthCmd;   // DELL_OEM_GET_PARTITIONCmd_tX_BANDWIDTH_CMD
	DellSetMcIpAddrCmd_t                SetMcIpAddrCmd;               // DELL_OEM_SET_MC_IP_ADDRESS_CMD
	DellGetTeamingInfoCmd_t             GetTeamingInfoCmd;            // DELL_OEM_GETCmd_tEAMING_INFORMATION_CMD
	DellEnablePortsCmd_t                EnablePortsCmd;               // DELL_OEM_ENABLE_PORTS_CMD
	DellDisablePortsCmd_t               DisablePortsCmd;              // DELL_OEM_DISABLE_PORTS_CMD
	DellGetTempCmd_t                    GetTempCmd;                   // DELL_OEM_GET_TEMPERATURE_CMD
	DellSetLinkTuningCmd_t              SetLinkTuningCmd;             // DELL_OEM_SET_LINKTUNING_CMD
	DellEnableDisableOutOfBoxWolCmd_t   EnableDisableOutOfBoxWolCmd;  // DELL_OEM_ENABLE_OUTOFBOX_WOL_CMD and DELL_OEM_DISABLE_OUTOFBOX_WOL_CMD
	DellGetSupportedVerCmd_t           GetSupportedVerCmd;        // DELL_OEM_GET_SUPP_PAYLOAD_VERSION_CMD
	DellGetOsDriverVerCmd_t            GetOsDriverVerCmd;         // DELL_OEM_GET_OS_DRIVER_VERSION_CMD
	DellGetiScsiInitiatorConfCmd_t     GetiScsiInitiatorConfCmd;      // DELL_OEM_GET_ISCSI_BOOT_INITIATOR_CONFIG_CMD
	DellSetiScsiInitiatorConfCmd_t     SetiScsiInitiatorConfCmd;      // DELL_OEM_SET_ISCSI_BOOT_INITIATOR_CONFIG_CMD
	DellGetiScsiTargetConfCmd_t        GetiScsiTargetConfCmd;         // DELL_OEM_GET_ISCSI_BOOT_TARGET_CONFIG_CMD
	DellSetiScsiTargetConfCmd_t        SetiScsiTargetConfCmd;         // DELL_OEM_SET_ISCSI_BOOT_TARGET_CONFIG_CMD
	DellGetFcoeTargetConfCmd_t         GetFcoeTargetConfCmd;          // DELL_OEM_GET_FCOE_BOOT_TARGET_CONFIG_CMD
	DellSetFcoeTargetConfCmd_t         SetFcoeTargetConfCmd;          // DELL_OEM_SET_FCOE_BOOT_TARGET_CONFIG_CMD
	DellCommitNvramCmd_t               CommitNvramCmd;                    // DELL_OEM_NVRAM_COMMIT_CMD
	DellGetCommitNvramStatusCmd_t      GetCommitNvramStatusCmd;           // DELL_OEM_NVRAM_COMMIT_STATUS_CMD
} DellOemCmdPayload_t;


typedef struct BrcmOemVendorData
{
	BrcmOemCmdRspHeader_t   BrcmOemCmdRspHeader;
	BrcmOemCmdPayload_t     OemPayload;

} BrcmOemVendorData_t;

typedef struct NcsiCmdOemCmdPayload
{
	u32_t            ManufacturerId;         /* ManufacturerId IANA */
	BrcmOemVendorData_t     VendorData;

} NcsiCmdOemCmdPayload_t;

/*****************************************************************************

NcsiCmdSelectPackageCmdPayload_t    

    this structure definition is for the select package cmd Payload.
	 
*****************************************************************************/
typedef struct NcsiCmdSelectPackageCmdPayload
{
	u32_t    DisableHwArbitration;
#define    HW_ARBITRATION_MASK             0x1
#define    HW_ARBITRATION_ENABLE               0x0
#define    HW_ARBITRATION_DISABLE              0x1
} NcsiCmdSelectPackageCmdPayload_t;

/*****************************************************************************

NcsiCmdEnableMulticastPacketFilteringCmdPayload_t    

    this structure definition is for the  cmd Payload.
	 
*****************************************************************************/
typedef struct NcsiCmdEnableMulticastPacketFilteringCmdPayload
{
	u32_t    Setting;
#define NCSI_CMD_MULTICAST_PACKET_PASSTHRU_SETTING_MASK                 7
#define NCSI_CMD_MULTICAST_PACKET_PASSTHRU_SETTING_IPV6_NEIGHBOR_ADV    1
#define NCSI_CMD_MULTICAST_PACKET_PASSTHRU_SETTING_IPV6_ROUTER_ADV      2
#define NCSI_CMD_MULTICAST_PACKET_PASSTHRU_SETTING_DHCPV6               4

} NcsiCmdEnableMulticastPacketFilteringCmdPayload_t;

/*****************************************************************************

NcsiCmdSetNcsiFlowControlCmdPayload_t    

    this structure definition is for the set ncsi flowcontrol cmd Payload.
	 
*****************************************************************************/
typedef struct NcsiCmdSetNcsiFlowControlCmdPayload
{
	u32_t    Setting;
#define NCSI_CMD_NCSI_FLOW_CONTROL_SETTING_ENABLE   3
#define NCSI_CMD_NCSI_FLOW_CONTROL_SETTING_DISABLE  0

} NcsiCmdSetNcsiFlowControlCmdPayload_t;

/*****************************************************************************

NcsiCmdEnableVlanCmdPayload_t    

    this structure definition is for the set ncsi flowcontrol cmd Payload.
	 
*****************************************************************************/
typedef struct NcsiCmdEnableVlanCmdPayload
{
	u32_t    Setting;
#define NCSI_CMD_ENABLE_VLAN_SETTING_VLAN_TAG_MODE      1
#define NCSI_CMD_ENABLE_VLAN_SETTING_MIXED_MODE         2
#define NCSI_CMD_ENABLE_VLAN_SETTING_PROM_VLAN_MODE     3

} NcsiCmdEnableVlanCmdPayload_t;


/*****************************************************************************

NcsiCmdSetVlanCmdPayload_t    

    this structure definition is for the enable VLAN cmd Payload.
	 
*****************************************************************************/
typedef struct NcsiCmdSetVlanCmdPayload
#if defined (BIG_ENDIAN)
{
	u16_t   Reserved0;
	u16_t   VlanTag;
	u16_t   Reserved1;
	u8_t    FilterSelector;
	u8_t    Enable;

} NcsiCmdSetVlanCmdPayload_t;
#elif defined (LITTLE_ENDIAN)
{
	   u16_t   VlanTag;
	   u16_t   Reserved0;
	   u8_t    Enable;
	   u8_t    FilterSelector;
	   u16_t   Reserved1;

}
   NcsiCmdSetVlanCmdPayload_t;
#endif // ENDIAN

/*****************************************************************************

NcsiCmdEnableAenCmdPayload_t    

    this structure definition is for the enable aen cmd Payload.
	 
*****************************************************************************/
typedef struct NcsiCmdEnableAenCmdPayload
#if defined (BIG_ENDIAN)
{
	u8_t     Reserved[3];
	u8_t     AenMcId;
	u32_t    AenControl;
#define NCSI_CMD_ENABLE_AEN_CMD_PAYLOAD_ENABLE_LINK_CHANGED_AEN     0x1
#define NCSI_CMD_ENABLE_AEN_CMD_PAYLOAD_ENABLE_RESET_OCCURRED_AEN   0x2
#define NCSI_CMD_ENABLE_AEN_CMD_PAYLOAD_ENABLE_OS_CHANGED_AEN       0x4

} NcsiCmdEnableAenCmdPayload_t;
#elif defined (LITTLE_ENDIAN)
{
	   u8_t     AenMcId;
	   u8_t     Reserved[3];
	   u32_t    AenControl;
#define NCSI_CMD_ENABLE_AEN_CMD_PAYLOAD_ENABLE_LINK_CHANGED_AEN     0x1
#define NCSI_CMD_ENABLE_AEN_CMD_PAYLOAD_ENABLE_RESET_OCCURRED_AEN   0x2
#define NCSI_CMD_ENABLE_AEN_CMD_PAYLOAD_ENABLE_OS_CHANGED_AEN       0x4

}
   NcsiCmdEnableAenCmdPayload_t;
#endif // ENDIAN

/*****************************************************************************

NcsiCmdSetMacAddrCmdPayload_t    

    this structure definition is for the set MAC addr command Payload
	 
*****************************************************************************/
typedef struct NcsiCmdSetMacAddrCmdPayload
#if defined (BIG_ENDIAN)
{

	u16_t       MacAddrHigh;
	u16_t       MacAddrLowHigh;
	u16_t       MacAddrLowLow;
	u8_t        MacAddrNum;
	u8_t        AddrTypeEnable; //  bits 7..5=address type, bits 4..1=reserved, bit 0=address enable
#define NCSI_CMD_SET_MAC_ADDR_CMD_ADDR_ENABLE           0x01
#define NCSI_CMD_SET_MAC_ADDR_CMD_ADDR_TYPE_MASK        0xE0
#define NCSI_CMD_SET_MAC_ADDR_CMD_ADDR_TYPE_UNICAST     0x00
#define NCSI_CMD_SET_MAC_ADDR_CMD_ADDR_TYPE_MULTICAST   0x20
} NcsiCmdSetMacAddrCmdPayload_t;
#elif defined (LITTLE_ENDIAN)
{

	   u16_t       MacAddrLowHigh;
	   u16_t       MacAddrHigh;
	   u8_t        AddrTypeEnable; //  bits 7..5=address type, bits 4..1=reserved, bit 0=address enable
	   u8_t        MacAddrNum;
	   u16_t       MacAddrLowLow;
#define NCSI_CMD_SET_MAC_ADDR_CMD_ADDR_ENABLE           0x01
#define NCSI_CMD_SET_MAC_ADDR_CMD_ADDR_TYPE_MASK        0xE0
#define NCSI_CMD_SET_MAC_ADDR_CMD_ADDR_TYPE_UNICAST     0x00
#define NCSI_CMD_SET_MAC_ADDR_CMD_ADDR_TYPE_MULTICAST   0x20
}
   NcsiCmdSetMacAddrCmdPayload_t;
#endif // ENDIAN

/*****************************************************************************

NcsiCmdSetLinkCmdPayload_t    

    this structure definition is for the set link command Payload
	 
*****************************************************************************/
typedef struct NcsiCmdSetLinkCmdPayload
{

	u32_t   LinkSettings;
	u32_t   OemLinkSettings;

} NcsiCmdSetLinkCmdPayload_t;


/*****************************************************************************

NcsiCmdDisableResetChannelCmdPayload_t    

    this structure definition is for the reset channel command Payload
	 
*****************************************************************************/
typedef struct NcsiCmdDisableResetChannelCmdPayload
{

	u32_t   Reserved;

} NcsiCmdDisableResetChannelCmdPayload_t;



/*****************************************************************************

NcsiCmdEnableBroadcastPacketFilteringCmdPayload_t    

    this structure definition is for the set link command Payload
	 
*****************************************************************************/
typedef struct NcsiCmdEnableBroadcastPacketFilteringCmdPayload
{

	u32_t   FilterSettings;
#define     NCSI_CMD_ENABLE_BROADCAST_PKT_PASSTHROUGH_ARP              1
#define     NCSI_CMD_ENABLE_BROADCAST_PKT_PASSTHROUGH_DHCP_CLIENT      2
#define     NCSI_CMD_ENABLE_BROADCAST_PKT_PASSTHROUGH_DHCP_SERVER      4
#define     NCSI_CMD_ENABLE_BROADCAST_PKT_PASSTHROUGH_NETBIOS          8

} NcsiCmdEnableBroadcastPacketFilteringCmdPayload_t;

typedef NcsiCmdEnableBroadcastPacketFilteringCmdPayload_t *pNcsiCmdEnableBroadcastPacketFilteringCmdPayload_t;


/*****************************************************************************

NcsiCmdPayload_t

    this union definition combines the various response Payload definitions
    into a single reference.
	 
*****************************************************************************/
typedef union NcsiCmdPayload
{
	NcsiCmdDisableResetChannelCmdPayload_t              ResetChannelCmdPayload;
	NcsiCmdDisableResetChannelCmdPayload_t              DisableChannelCmdPayload;
	NcsiCmdSetMacAddrCmdPayload_t                       SetMacAddrPayload;
	NcsiCmdSetVlanCmdPayload_t                          SetVlanPayload;
	NcsiCmdSetLinkCmdPayload_t                          SetLinkPayload;
	NcsiCmdEnableAenCmdPayload_t                        EnableAenPayload;
	NcsiCmdEnableBroadcastPacketFilteringCmdPayload_t   EnableBroadcastFilterPayload;
	NcsiCmdSelectPackageCmdPayload_t                    SelectPackagePayload;
	NcsiCmdSetNcsiFlowControlCmdPayload_t               SetFlowControlPayload;
	NcsiCmdEnableVlanCmdPayload_t                       EnableVlanPayload;
	NcsiCmdEnableMulticastPacketFilteringCmdPayload_t   EnableMulticastFilterPayload;
	NcsiCmdOemCmdPayload_t                              OemCmdPayload;
	DellOemCmdPayload_t                                 DellOemCmdPayload;
} NcsiCmdPayload_t;


#define NCSI_CMD_DISABLE_RESET_CHANNEL_CMD_PAYLOAD_SIZE     (sizeof (NcsiCmdDisableResetChannelCmdPayload_t))
#define UMPCMDPUB_SET_VLAN_CMD_PAYLOAD_SIZE                 (sizeof (NcsiCmdSetVlanCmdPayload_t))
#define UMPCMDPUB_SET_MAC_CMD_PAYLOAD_SIZE                  (sizeof (NcsiCmdSetMacAddrCmdPayload_t))
#define UMPCMDPUB_CLR_MAC_CMD_PAYLOAD_SIZE                  (sizeof (NcsiCmdClearMacAddrCmdPayload_t))
#define UMPCMDPUB_SET_LINK_CMD_PAYLOAD_SIZE                 (sizeof (NcsiCmdSetLinkCmdPayload_t))
#define UMPCMDPUB_CMD_PAYLOAD_SIZE                          (sizeof (NcsiCmdPayload_t))

#define UC_32_BIT_ALIGN(X)              ((4 - (X & 3)) & 3)

/*****************************************************************************

NcsiRmiiCmdPkt_t

    this structure definition is for the the UMP command frame.
	
    IMD command frames are received from iLO over the UMP interface, and are
    either processed locally for configuration and control, or are forwarded 
    for transmission at the primary ethernet port.    
     
*****************************************************************************/
typedef struct NcsiCmdPkt
{
	NcsiRmiiControlPktHeader_t   Header;
	NcsiCmdPayload_t         Payload;

} NcsiRmiiCmdPkt_t;

typedef NcsiRmiiCmdPkt_t *pNcsiRmiiCmdPkt_t;

#define UC_MAX_CMD_FRAME_SIZE sizeof(NcsiRmiiCmdPkt_t)


/*****************************************************************************

OemDefaultReturnData_t    

    Structure definition for data portion of most basic response Payload
	 
*****************************************************************************/
typedef struct NcsiCmdRspStatus
#if defined (BIG_ENDIAN)
{
	u16_t   ResponseCode;          /* ids outcome of cmd   */
#define NCSI_CMD_RSP_CODE_CMD_COMPLETED_OK                        0
#define NCSI_CMD_RSP_CODE_CMD_FAILED                              1
#define NCSI_CMD_RSP_CODE_CMD_UNAVAILABLE                         2
#define NCSI_CMD_RSP_CODE_CMD_UNSUPPORTED                         3
	u16_t   ReasonCode;            /* ids reasons for rsp  */
#define NCSI_CMD_RSN_CODE_NO_ERROR                                0
#define NCSI_CMD_RSN_CODE_INTERFACE_INIT_REQUIRED                 1
#define NCSI_CMD_RSN_CODE_PARAMETER_INVALID_OUT_OF_RANGE          2
#define NCSI_CMD_RSN_CODE_CHANNEL_NOT_READY                       3
#define NCSI_CMD_RSN_CODE_PACKAGE_NOT_READY                       4
#define NCSI_CMD_RSN_CODE_INVALID_PAYLOAD_LENGTH                  5
#define NCSI_CMD_RSN_CODE_VLAN_TAG_OF_0_IS_INVALID                ((NCSI_CMD_TYPE_SET_VLAN_FILTERS << 8) + 7)
#define NCSI_CMD_RSN_CODE_MAC_ADDR_OF_0_IS_INVALID                ((NCSI_CMD_TYPE_SET_MAC_ADDRESS  << 8) + 8)
#define NCSI_CMD_RSN_CODE_ASYNCH_FC_NOT_SUPPORTED                 ((NCSI_CMD_TYPE_SET_NCSI_FLOW_CONTROL << 8) + 9)
#define NCSI_CMD_OEM_GENERIC_RSN_CODE_OS_CONFLICT                   0x80
#define NCSI_CMD_OEM_GENERIC_RSN_CODE_OEM_PAYLOAD_VER_ERR           0x81
	// 0x1 Set Link Host OS/ Driver Conflict Returned when the Set Link command is received
	// when the Host NC driver is operational
	// 0x2 Set Link Media Conflict Returned when Set Link command parameters conflict
	// with the media type (for example, Fiber Media)
	// 0x3 Set Link Parameter Conflict Returned when Set Link parameters conflict with each
	// other (for example, 1000 Mbps HD with copper media)
	// 0x4 Set Link Power Mode Conflict Returned when Set Link parameters conflict with
	// current low-power levels by exceeding capability
	// 0x5 Set Link Speed Conflict Returned when Set Link parameters attempt to force
	// more than one speed at the same time
	// 0x6 Link Command Failed-Hardware Access Error
	// Returned when PHY R/W access fails to complete
	// normally while executing the Set Link or Get Link Status command
#define NCSI_CMD_RSN_CODE_SET_LINK_HOST_CONFLICT                           1
#define NCSI_CMD_RSN_CODE_SET_LINK_MEDIA_CONFLICT                          2
#define NCSI_CMD_RSN_CODE_SET_LINK_PARAMETER_CONFLICT                      3
#define NCSI_CMD_RSN_CODE_SET_LINK_POWER_MODE_CONFLICT                     4
#define NCSI_CMD_RSN_CODE_SET_LINK_SPEED_CONFLICT                          5
#define NCSI_CMD_RSN_CODE_SET_LINK_HW_ACCESS_ERR                           6

	// Dell OEM Set Mac Command-specific Reason Code
	// 0x8000  NIC Partitioning not enabled    Returned when the NIC Partitioning feature is not enabled.
	// 0x8001  Partition ID not enabled    Returned when the individual partition is not enabled.
	// 0x8002  Partition ID not associated Returned when the Partition ID is not one of the partitions enumerated on the channel.
	// 0x8003  System reboot required  Returned when the command can be executed only at system power up or when no operating system is present or driver is loaded.
	// 0x8004  Invalid Length  The length of a Type-Length field in the Command is incorrect.
	// 0x8005  Information not available   Returned when the controller is not able to provide the requested information.
	// 0x8006  Unsupported Address type    Returned when the SetAddress command failed because the specified Address Type in the command is not supported.
	// 0x8007  Unsupported Passthru type   Returned when the Set Passthru Control or Get Passthru Control command failed because the specified Passthru Type in the command is not supported.
	// 0x8008  Reached maximum number of allowed ports Returned when OutOfBox WOL is already configured on the maximum number of ports per channel or Device (may be implementation dependent)
	// 0x8009  System reboot required for the changes to be effective  Returned when the command was executed successfully (Response code = 0) but a driver unload or system reboot is required in order for the changes to become effective.
#define NCSI_CMD_OEM_DELL_RSN_CODE_NP_NOT_ENABLED                   0x8000
#define NCSI_CMD_OEM_DELL_RSN_CODE_PARTITION_ID_NOT_ENABLED         0x8001
#define NCSI_CMD_OEM_DELL_RSN_CODE_PARTITION_ID_NOT_ASSOCIATED      0x8002
#define NCSI_CMD_OEM_DELL_RSN_CODE_REBOOT_REQUIRED                  0x8003
#define NCSI_CMD_OEM_DELL_RSN_CODE_INVALID_LENGTH                   0x8004
#define NCSI_CMD_OEM_DELL_RSN_CODE_INFO_NOT_AVAILABLE               0x8005
#define NCSI_CMD_OEM_DELL_RSN_CODE_UNSUPPORTED_ADDR_TYPE            0x8006
#define NCSI_CMD_OEM_DELL_RSN_CODE_UNSUPPORTED_PASSTHRU_TYPE        0x8007
#define NCSI_CMD_OEM_DELL_RSN_CODE_MAX_ALLOW_PORTS_REACHED          0x8008
#define NCSI_CMD_OEM_DELL_RSN_CODE_SYS_REBOOT_REQUIRED              0x8009
#define NCSI_CMD_OEM_DELL_UNSUPPORTED_PAYLOAD_VERSION               0x800a
#define NCSI_CMD_OEM_DELL_HOST_DRIVER_NOT_LOADED                    0x800b
#define NCSI_CMD_OEM_DELL_LINK_CMD_FAILED_HW_ACCESS_ERR             0x800c
#define NCSI_CMD_OEM_DELL_INTERNAL_STORAGE_EXCEEDED                 0x800d
#define NCSI_CMD_OEM_DELL_NVRAM_WRITE_FAILURE                       0x800e
#define NCSI_CMD_OEM_DELL_NVRAM_WRITE_PENDING                       0x800f
#define NCSI_CMD_RSN_CODE_UNK_CMD_TYPE                              0x7FFF

#define NCSI_CMD_OEM_SPECIFIC_RSN_CODE_TYPE_MASK                          0xFF00
#define NCSI_CMD_OEM_SPECIFIC_RSN_CODE_ERR_MASK                           0x00FF
#define NCSI_CMD_OEM_SPECIFIC_RSN_CODE_MAC_ADDR_INIT_ERR           ((NCSI_CMD_TYPE_ENABLE_CHANNEL_EGRESS_TX << 8) + 0x80)
#define NCSI_CMD_OEM_SPECIFIC_RSN_CODE_VLAN_TAG_INIT_ERR           ((NCSI_CMD_TYPE_ENABLE_VLAN << 8) + 0x81)
} NcsiCmdRspStatus_t;
#elif defined (LITTLE_ENDIAN)
{
	   u16_t   ReasonCode;            /* ids reasons for rsp  */
	   u16_t   ResponseCode;          /* ids outcome of cmd   */
#define NCSI_CMD_RSP_CODE_CMD_UNSUPPORTED                         3
#define NCSI_CMD_RSP_CODE_CMD_UNAVAILABLE                         2
#define NCSI_CMD_RSP_CODE_CMD_FAILED                              1
#define NCSI_CMD_RSP_CODE_CMD_COMPLETED_OK                        0
#define NCSI_CMD_RSN_CODE_NO_ERROR                                0
#define NCSI_CMD_RSN_CODE_INTERFACE_INIT_REQUIRED                 1
#define NCSI_CMD_RSN_CODE_PARAMETER_INVALID_OUT_OF_RANGE          2
#define NCSI_CMD_RSN_CODE_CHANNEL_NOT_READY                       3
#define NCSI_CMD_RSN_CODE_PACKAGE_NOT_READY                       4
#define NCSI_CMD_RSN_CODE_INVALID_PAYLOAD_LENGTH                  5
#define NCSI_CMD_RSN_CODE_VLAN_TAG_OF_0_IS_INVALID                ((NCSI_CMD_TYPE_SET_VLAN_FILTERS << 8) + 7)
#define NCSI_CMD_RSN_CODE_MAC_ADDR_OF_0_IS_INVALID                ((NCSI_CMD_TYPE_SET_MAC_ADDRESS  << 8) + 8)
#define NCSI_CMD_RSN_CODE_ASYNCH_FC_NOT_SUPPORTED                 ((NCSI_CMD_TYPE_SET_NCSI_FLOW_CONTROL << 8) + 9)
#define NCSI_CMD_OEM_GENERIC_RSN_CODE_OS_CONFLICT                   0x80
#define NCSI_CMD_OEM_GENERIC_RSN_CODE_OEM_PAYLOAD_VER_ERR           0x81

	/* Dell OEM Set Mac Command-specific Reason Code
	0x8000  NIC Partitioning not enabled    Returned when the NIC Partitioning feature is not enabled.
	0x8001  Partition ID not enabled    Returned when the individual partition is not enabled.
	0x8002  Partition ID not associated Returned when the Partition ID is not one of the partitions enumerated on the channel.
	0x8003  System reboot required  Returned when the command can be executed only at system power up or when no operating system is present or driver is loaded.
	0x8004  Invalid Length  The length of a Type-Length field in the Command is incorrect.
	0x8005  Information not available   Returned when the controller is not able to provide the requested information.
	0x8006  Unsupported Address type    Returned when the SetAddress command failed because the specified Address Type in the command is not supported.
	0x8007  Unsupported Passthru type   Returned when the Set Passthru Control or Get Passthru Control command failed because the specified Passthru Type in the command is not supported.
	0x8008  Reached maximum number of allowed ports Returned when OutOfBox WOL is already configured on the maximum number of ports per channel or Device (may be implementation dependent)
	0x8009  System reboot required for the changes to be effective  Returned when the command was executed successfully (Response code = 0) but a driver unload or system reboot is required in order for the changes to become effective. 
	0x800A  Returned when the Ethernet or FC controller does not support the Payload Version specified in the incoming OEM command. Note: This Reason code does not apply to the Get Supported Payload Version command 
	0x800B  Returned when the command is unable to be successfully executed because there is no OS driver loaded 
	0x800D  Returned when there is insufficient storage to store parameters to be written to NVRAM 
	0x800E  Returned when there is a failure in the NVRAM write operation 
	0x800F  Returned when the NVRAM write operation is not complete 
	*/
#define NCSI_CMD_OEM_DELL_RSN_CODE_NP_NOT_ENABLED                   0x8000
#define NCSI_CMD_OEM_DELL_RSN_CODE_PARTITION_ID_NOT_ENABLED         0x8001
#define NCSI_CMD_OEM_DELL_RSN_CODE_PARTITION_ID_NOT_ASSOCIATED      0x8002
#define NCSI_CMD_OEM_DELL_RSN_CODE_REBOOT_REQUIRED                  0x8003
#define NCSI_CMD_OEM_DELL_RSN_CODE_INVALID_LENGTH                   0x8004
#define NCSI_CMD_OEM_DELL_RSN_CODE_INFO_NOT_AVAILABLE               0x8005
#define NCSI_CMD_OEM_DELL_RSN_CODE_UNSUPPORTED_ADDR_TYPE            0x8006
#define NCSI_CMD_OEM_DELL_RSN_CODE_UNSUPPORTED_PASSTHRU_TYPE        0x8007
#define NCSI_CMD_OEM_DELL_RSN_CODE_MAX_ALLOW_PORTS_REACHED          0x8008
#define NCSI_CMD_OEM_DELL_RSN_CODE_SYS_REBOOT_REQUIRED              0x8009
#define NCSI_CMD_OEM_DELL_UNSUPPORTED_PAYLOAD_VERSION               0x800A
#define NCSI_CMD_OEM_DELL_HOST_DRIVER_NOT_LOADED                    0x800B
#define NCSI_CMD_OEM_DELL_INTERNAL_STORAGE_EXCEEDED                 0x800D
#define NCSI_CMD_OEM_DELL_NVRAM_WRITE_FAILURE                       0x800E
#define NCSI_CMD_OEM_DELL_NVRAM_WRITE_PENDING                       0x800F
#define NCSI_CMD_RSN_CODE_UNK_CMD_TYPE                            0x7FFF

#define NCSI_CMD_OEM_SPECIFIC_RSN_CODE_TYPE_MASK                          0xFF00
#define NCSI_CMD_OEM_SPECIFIC_RSN_CODE_ERR_MASK                           0x00FF
#define NCSI_CMD_OEM_SPECIFIC_RSN_CODE_MAC_ADDR_INIT_ERR           ((NCSI_CMD_TYPE_ENABLE_CHANNEL_EGRESS_TX << 8) + 0x80)
#define NCSI_CMD_OEM_SPECIFIC_RSN_CODE_VLAN_TAG_INIT_ERR           ((NCSI_CMD_TYPE_ENABLE_VLAN << 8) + 0x81)
}
   NcsiCmdRspStatus_t;
#endif // ENDIAN


typedef struct OemDefaultReturnData
{
	BrcmOemCmdRspHeader_t     BrcmOemCmdRspHeader;

} OemDefaultReturnData_t;

/*****************************************************************************

NcsiDefaultOemCmdRspData_t

    this structure definition is for the data fields of the rsp frm Payload 
    returned in response to the OEM cmd.

*****************************************************************************/
typedef struct NcsiDefaultOemCmdRspData
#if defined (BIG_ENDIAN)
{

	u16_t                ResponseCode;          /* ids outcome of cmd   */
	u16_t                ReasonCode;            /* ids reasons for rsp  */

	u32_t                ManufacturerId;        /* ManufacturerId IANA */
	OemDefaultReturnData_t  ReturnData;

} NcsiDefaultOemCmdRspData_t;
#elif defined (LITTLE_ENDIAN)
{

	   u16_t                ReasonCode;            /* ids reasons for rsp  */
	   u16_t                ResponseCode;          /* ids outcome of cmd   */

	   u32_t                ManufacturerId;        /* ManufacturerId IANA */
	   OemDefaultReturnData_t  ReturnData;

}
   NcsiDefaultOemCmdRspData_t;
#endif // ENDIAN


typedef struct OemTestReturnData
{
	BrcmOemCmdRspHeader_t      BrcmOemCmdRspHeader;

	u32_t        OemPayload[33];

} OemTestReturnData_t;

/*****************************************************************************

NcsiCmdNcsiTestReadCmdRspData_t

    this structure definition is for the data fields of the rsp frm Payload 
    returned in response to the NCSI Test OEM cmd.

*****************************************************************************/
typedef struct NcsiCmdNcsiTestReadCmdRspData
#if defined (BIG_ENDIAN)
{

	u16_t                ResponseCode;          /* ids outcome of cmd   */
	u16_t                ReasonCode;            /* ids reasons for rsp  */
	u32_t                ManufacturerId;        /* ManufacturerId IANA */
	OemTestReturnData_t     ReturnData;

} NcsiCmdNcsiTestReadCmdRspData_t;
#elif defined (LITTLE_ENDIAN)
{

	   u16_t                ReasonCode;            /* ids reasons for rsp  */
	   u16_t                ResponseCode;          /* ids outcome of cmd   */
	   u32_t                ManufacturerId;         /* ManufacturerId IANA */
	   OemTestReturnData_t     ReturnData;

}
   NcsiCmdNcsiTestReadCmdRspData_t;
#endif // ENDIAN

typedef struct NcsiOemGetNcsiParametersPayload
#if defined (BIG_ENDIAN)
{
	u32_t        NcsiFwVersionNumber;
	u32_t        BootcodeVersionNumber;
	u32_t        PxeBootVersionNumber;
	u32_t        IScsiBootVersionNumber;
	u32_t        OemLinkSettings;

	u16_t        HostMacAddrHigh;
	u16_t        HostMacAddrMiddle;
	u16_t        HostMacAddrLow;

	u16_t        HostVirtualL2MacAddrHigh;
	u16_t        HostVirtualL2MacAddrMiddle;
	u16_t        HostVirtualL2MacAddrLow;

	u16_t        HostIscsiMacAddrHigh;
	u16_t        HostIscsiMacAddrMiddle;
	u16_t        HostIscsiMacAddrLow;

	u16_t        HostVirtualIscsiMacAddrHigh;
	u16_t        HostVirtualIscsiMacAddrMiddle;
	u16_t        HostVirtualIscsiMacAddrLow;

	// UmpMacAddr_t    HostMacAddr;
	// UmpMacAddr_t    HostVirtualL2MacAddr;
	// UmpMacAddr_t    HostIscsiMacAddr;
	// UmpMacAddr_t    HostVirtualIscsiMacAddr;
}NcsiOemGetNcsiParametersPayload_t;
#elif defined (LITTLE_ENDIAN)
{
	   u32_t        NcsiFwVersionNumber;
	   u32_t        BootcodeVersionNumber;
	   u32_t        PxeBootVersionNumber;
	   u32_t        IScsiBootVersionNumber;
	   u32_t        OemLinkSettings;

	   u16_t        HostMacAddrMiddle;
	   u16_t        HostMacAddrHigh;

	   u16_t        HostVirtualL2MacAddrHigh;
	   u16_t        HostMacAddrLow;
	   u16_t        HostVirtualL2MacAddrLow;
	   u16_t        HostVirtualL2MacAddrMiddle;

	   u16_t        HostIscsiMacAddrMiddle;
	   u16_t        HostIscsiMacAddrHigh;

	   u16_t        HostVirtualIscsiMacAddrHigh;
	   u16_t        HostIscsiMacAddrLow;
	   u16_t        HostVirtualIscsiMacAddrLow;
	   u16_t        HostVirtualIscsiMacAddrMiddle;

	// UmpMacAddr_t    HostMacAddr;
	// UmpMacAddr_t    HostVirtualL2MacAddr;
	// UmpMacAddr_t    HostIscsiMacAddr;
	// UmpMacAddr_t    HostVirtualIscsiMacAddr;
}
   NcsiOemGetNcsiParametersPayload_t;
#endif // ENDIAN


#define NCSI_CMD_GET_NCSI_PARAM_RSP_PAYLOAD_VERSION     0
typedef struct NcsiOemGetNcsiParametersReturnData
{
	BrcmOemCmdRspHeader_t      BrcmOemCmdRspHeader;
	NcsiOemGetNcsiParametersPayload_t  OemPayload;

} NcsiOemGetNcsiParametersReturnData_t;

#define NCSI_CMD_GET_PHY_PRIORITY_RSP_PAYLOAD_VERSION     0
typedef struct NcsiOemGetDualMediaParametersReturnData
{
	BrcmOemCmdRspHeader_t      BrcmOemCmdRspHeader;
	NcsiOemGetDualMediaParametersPayload_t  OemPayload;

} NcsiOemGetDualMediaParametersReturnData_t;



/*****************************************************************************

NcsiOemGetNcsiParametersRspData_t

    this structure definition is for the data fields of the rsp frm Payload 
    returned in response to the  OEM cmds.

*****************************************************************************/
typedef struct NcsiOemGetNcsiParametersRspData
{
#if defined (BIG_ENDIAN)
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
#elif defined (LITTLE_ENDIAN)
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
#endif // endian
	u32_t                            ManufacturerId;         /* ManufacturerId IANA */
	NcsiOemGetNcsiParametersReturnData_t    ReturnData;

} NcsiOemGetNcsiParametersRspData_t;

/*****************************************************************************

NcsiOemGetDualMediaParametersRspData_t

    this structure definition is for the data fields of the rsp frm Payload 
    returned in response to the  OEM cmds.

*****************************************************************************/
typedef struct NcsiOemGetDualMediaParametersRspData
{
#if defined (BIG_ENDIAN)
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
#elif defined (LITTLE_ENDIAN)
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
#endif // endian
	u32_t                            ManufacturerId;        /* ManufacturerId IANA */
	NcsiOemGetDualMediaParametersReturnData_t    ReturnData;

} NcsiOemGetDualMediaParametersRspData_t;






/*****************************************************************************

NcsiCmdGetParametersRspData_t

    this structure definition is for the data fields of the rsp frm Payload 
    returned in response to the get parameters ump cmd.

*****************************************************************************/
typedef struct NcsiCmdGetParametersRspData
#if defined (BIG_ENDIAN)
{

	u16_t        ResponseCode;          /* ids outcome of cmd   */
	u16_t        ReasonCode;            /* ids reasons for rsp  */
	u8_t         MacAddrCount;
	u8_t         Reserved0[2];
	u8_t         MacAddrFlags;

	u8_t         VlanTagCount;
	u8_t         Reserved1;
	u16_t        VlanTagFlags;

	u32_t        LinkSettings;

	u32_t        BroadcastFilterSettings;
	u32_t        ConfigurationFlags;

	u8_t         VlanMode;
	u8_t         FcEnable;
	u16_t        Reserved2;
	u32_t        AenControl;

	NcsiMacAddr_t   Mac[NCSI_MAC_ADDRESS_MAX];


	u16_t        VlanTag[NCSI_VLAN_TAG_COUNT];


}NcsiCmdGetParametersRspData_t;
#elif defined (LITTLE_ENDIAN)
{

	   u16_t        ReasonCode;            /* ids reasons for rsp  */
	   u16_t        ResponseCode;          /* ids outcome of cmd   */
	   u8_t         MacAddrFlags;
	   u8_t         Reserved0[2];
	   u8_t         MacAddrCount;

	   u16_t        VlanTagFlags;
	   u8_t         Reserved1;
	   u8_t         VlanTagCount;

	   u32_t        LinkSettings;

	   u32_t        BroadcastFilterSettings;
	   u32_t        ConfigurationFlags;

	   u16_t        Reserved2;
	   u8_t         FcEnable;
	   u8_t         VlanMode;
	   u32_t        AenControl;

	   NcsiMacAddr_t   Mac[NCSI_MAC_ADDRESS_MAX];




	   u16_t        VlanTag[NCSI_VLAN_TAG_COUNT];
}
   NcsiCmdGetParametersRspData_t;
#endif // endian


/*****************************************************************************


*****************************************************************************/

typedef struct NcsiCmdGetCapabilitiesRspData
#if defined (BIG_ENDIAN)
{

	u16_t   ResponseCode;          /* ids outcome of cmd   */
	u16_t   ReasonCode;         /* ids reasons for rsp  */

	u32_t    Flags;
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_CAPABILITY_FLAG_HW_ARBITRATION    0x01
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_CAPABILITY_FLAG_OS_AWARENESS      0x02
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_CAPABILITY_FLAG_TX_FLOWCONTROL    0x04
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_CAPABILITY_FLAG_RX_FLOWCONTROL    0x08
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_CAPABILITY_FLAG_MULTICAST_SUPPORT 0x10

	u32_t    BroadcastFiltering;
	u32_t    MulticastFiltering;
	u32_t    IngressBuffering;
	u32_t    AenControl;
	u8_t     VlanFilterCount;
	u8_t     MixedMacFilterCount;
	u8_t     MulticastFilterCount;
	u8_t     UnicastFilterCount;
	u16_t    Reserved0;
	u8_t     VlanModes;
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_VLAN_MODE_VLAN_ONLY         0x01
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_VLAN_MODE_VLAN_NON_VLAN     0x02
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_VLAN_MODE_PROMISCUOUS_VLAN  0x04


	u8_t     ChannelCount;

} NcsiCmdGetCapabilitiesRspData_t;
#elif defined (LITTLE_ENDIAN)
{

	   u16_t   ReasonCode;         /* ids reasons for rsp  */
	   u16_t   ResponseCode;          /* ids outcome of cmd   */

	   u32_t    Flags;
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_CAPABILITY_FLAG_HW_ARBITRATION    0x01
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_CAPABILITY_FLAG_OS_AWARENESS      0x02
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_CAPABILITY_FLAG_TX_FLOWCONTROL    0x04
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_CAPABILITY_FLAG_RX_FLOWCONTROL    0x08
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_CAPABILITY_FLAG_MULTICAST_SUPPORT 0x10

	   u32_t    BroadcastFiltering;
	   u32_t    MulticastFiltering;
	   u32_t    IngressBuffering;
	   u32_t    AenControl;
	   u8_t     UnicastFilterCount;
	   u8_t     MulticastFilterCount;
	   u8_t     MixedMacFilterCount;
	   u8_t     VlanFilterCount;


	   u8_t     ChannelCount;
	   u8_t     VlanModes;
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_VLAN_MODE_PROMISCUOUS_VLAN  0x04
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_VLAN_MODE_VLAN_NON_VLAN     0x02
#define NCSI_CMD_GET_CAPABILITY_RSP_PAYLOAD_VLAN_MODE_VLAN_ONLY         0x01
	   u16_t    Reserved0;

}
   NcsiCmdGetCapabilitiesRspData_t;
#endif // endian

/*****************************************************************************

NcsiCmdGetLinkStatusRspData_t    

    this structure definition is for the data field portion of the response 
    Payload returned when processing the get link status ump cmd.
	 
*****************************************************************************/
typedef struct NcsiCmdGetLinkStatusRspData
{
#if defined (BIG_ENDIAN)
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
#elif defined (LITTLE_ENDIAN)
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
#endif // endian
	u32_t   LinkState;
#define LINK_STATUS_LINK_MASK                                                    (1<<0)
#define LINK_STATUS_LINK_ENABLED                                                 (1<<0)
#define LINK_STATUS_LINK_SPEED_DUPLEX_NO_HCD                                     (0<<0)
#define LINK_STATUS_LINK_SPEED_AND_DUPLEX_MASK                                   (0xF<<1)
#define LINK_STATUS_LINK_SPEED_DUPLEX_10BASE_T_HD                                (1<<1)
#define LINK_STATUS_LINK_SPEED_DUPLEX_10BASE_T_FD                                (2<<1)
#define LINK_STATUS_LINK_SPEED_DUPLEX_100BASE_TX_HD                              (3<<1)
#define LINK_STATUS_LINK_SPEED_DUPLEX_100BASE_TX_FD                              (5<<1)
#define LINK_STATUS_LINK_SPEED_DUPLEX_1000BASE_T_FD                              (7<<1)
#define LINK_STATUS_LINK_SPEED_DUPLEX_UMP_2_5GB_HD                               (8<<1)
#define LINK_STATUS_LINK_SPEED_DUPLEX_UMP_2_5GB_FD                               (9<<1)
#define LINK_STATUS_LINK_SPEED_DUPLEX_UMP_10GBASE_T                              (10<<1)
#define LINK_STATUS_LINK_SPEED_DUPLEX_NCSI_10GBASE_T                             (8<<1)
#define LINK_STATUS_AUTO_NEG_ENABLED                                             (1<<5)
#define LINK_STATUS_AUTO_NEG_COMPLETE                                            (1<<6)
#define LINK_STATUS_PARALLEL_DETECTION                                           (1<<7)
#define LINK_STATUS_LINK_PARTNER_ADVERTIZED_PAUSE_FC_CAPABLE                     (1<<8)
#define LINK_STATUS_LINK_PARTNER_ADVERTIZED_SPEED_DUPLEX_1000BASE_T_FD           (1<<9)
#define LINK_STATUS_LINK_PARTNER_ADVERTIZED_SPEED_DUPLEX_1000BASE_T_HD           (1<<10)
#define LINK_STATUS_LINK_PARTNER_ADVERTIZED_SPEED_DUPLEX_100BASE_TX_FD           (1<<12)
#define LINK_STATUS_LINK_PARTNER_ADVERTIZED_SPEED_DUPLEX_100BASE_TX_HD           (1<<13)
#define LINK_STATUS_LINK_PARTNER_ADVERTIZED_SPEED_DUPLEX_10BASE_T_FD             (1<<14)
#define LINK_STATUS_LINK_PARTNER_ADVERTIZED_SPEED_DUPLEX_10BASE_T_HD             (1<<15)
#define LINK_STATUS_TX_FC_ENABLED                                                (1<<16)
#define LINK_STATUS_RX_FC_ENABLED                                                (1<<17)
#define LINK_STATUS_LINK_PARTNER_ADVERTIZED_FC_1000X_MASK                    (3<<18)
#define LINK_STATUS_LINK_PARTNER_ADVERTIZED_FC_1000X_NO_PAUSE                    (0<<18)
#define LINK_STATUS_LINK_PARTNER_ADVERTIZED_FC_1000X_SYM_PAUSE                   (1<<18)
#define LINK_STATUS_LINK_PARTNER_ADVERTIZED_FC_1000X_ASYM_PAUSE_TO_PARTNER       (2<<18)
#define LINK_STATUS_LINK_PARTNER_ADVERTIZED_FC_1000X_SYM_ASYM_PAUSE_TO_PARTNER   (3<<18)

#define LINK_STATUS_SERDES_FLAG                                                  (1<<20)
#define LINK_STATUS_OEM_LINK_SPEED_VALID_FLAG                                    (1<<21)


	u32_t   OtherIndications;
	u32_t   OemLinkSpeed;
#define LINK_STATUS_LINK_SPEED_DUPLEX_NCSI_2_5GB_HD                              (1<<0)
#define LINK_STATUS_LINK_SPEED_DUPLEX_NCSI_2_5GB_FD                              (1<<1)

} NcsiCmdGetLinkStatusRspData_t;

/*****************************************************************************

NcsiCmdGetNcsiStatisticsRspData_t

    this structure defines the data field portion of the response Payload 
    returned when processing the get ncsi statistics cmd.
	 
*****************************************************************************/
typedef struct NcsiCmdGetNcsiStatisticsRspData
{
#if defined (BIG_ENDIAN)
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
#elif defined (LITTLE_ENDIAN)
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
#endif // endian

	u32_t   CommandPktsRx;               // ncsi cmds rx and processed
	u32_t   TotalCommandPktsDropped;     // total ncsi cmds dropped
	u32_t   CommandPktsDroppedTypeError; // ncsi cmds dropped for type error
	u32_t   CommandPktsDroppedCsError;   // ncsi cmds dropped for checksum error
	u32_t   TotalControlPktsRx;          // total ncsi cmds rx, processed + dropped
	u32_t   TotalControlPktsTx;          // total ncsi pkts sent, AEN + rsp
	u32_t   TotalAensSent;               //

} NcsiCmdGetNcsiStatisticsRspData_t;

typedef NcsiCmdGetNcsiStatisticsRspData_t *pNcsiCmdGetNcsiStatisticsRspData_t;


/*****************************************************************************

NcsiCmdGetNcsiPassThruStatisticsRspData_t

    this structure defines the data field portion of the response Payload 
    returned when processing the get ncsi pass through statistics  cmd.
	 
*****************************************************************************/
typedef struct NcsiCmdGetNcsiPassThruStatisticsRspData
{
#if defined (BIG_ENDIAN)
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
#elif defined (LITTLE_ENDIAN)
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
#endif // endian

	u32_t   TotalEgressPktsHigh;
	u32_t   TotalEgressPktsLow;
	u32_t   TotalEgressPktsDropped;
	u32_t   EgressPktsDroppedChannelStateError;
	u32_t   EgressPktsDroppedUndersizedError;
	u32_t   EgressPktsDroppedOversizedError;
	u32_t   TotalIngressPkts;
	u32_t   TotalIngressPktsDropped;
	u32_t   IngressPktsDroppedChannelStateError;
	u32_t   IngressPktsDroppedUndersizedError;
	u32_t   IngressPktsDroppedOversizedError;

} NcsiCmdGetNcsiPassThruStatisticsRspData_t;

typedef NcsiCmdGetNcsiPassThruStatisticsRspData_t *pNcsiCmdGetNcsiPassThruStatisticsRspData_t;


typedef struct NcsiNicEmacStats
{

	u32_t   TotalBytesRx_High;
	u32_t   TotalBytesRx_Low;
	u32_t   TotalBytesTx_High;
	u32_t   TotalBytesTx_Low;
	u32_t   TotalUnicastPktsRx_High;
	u32_t   TotalUnicastPktsRx_Low;
	u32_t   TotalMulticastPktsRx_High;
	u32_t   TotalMulticastPktsRx_Low;
	u32_t   TotalBroadcastPktsRx_High;
	u32_t   TotalBroadcastPktsRx_Low;
	u32_t   TotalUnicastPktsTx_High;
	u32_t   TotalUnicastPktsTx_Low;
	u32_t   TotalMulticastPktsTx_High;
	u32_t   TotalMulticastPktsTx_Low;
	u32_t   TotalBroadcastPktsTx_High;
	u32_t   TotalBroadcastPktsTx_Low;
	u32_t   CrcRxErrors;
	u32_t   AlignmentErrors;
	u32_t   FalseCarrierDetects;
	u32_t   RuntPktsRx;
	u32_t   JabberPktsRx;
	u32_t   PauseXonFramesRx;
	u32_t   PauseXoffFramesRx;
	u32_t   PauseXonFramesTx;
	u32_t   PauseXoffFramesTx;
	u32_t   SingleCollisionTxFrames;
	u32_t   MultipleCollisionTxFrames;
	u32_t   LateCollisionFrames;
	u32_t   ExcessiveCollisionFrames;
	u32_t   ControlFramesRx;
	u32_t   FramesRx64Byte;
	u32_t   FramesRx65_127Bytes;
	u32_t   FramesRx128_255Bytes;
	u32_t   FramesRx256_511Bytes;
	u32_t   FramesRx512_1023Bytes;
	u32_t   FramesRx1024_1522Bytes;
	u32_t   FramesRx1523_9022Bytes;
	u32_t   FramesTx64Byte;
	u32_t   FramesTx65_127Bytes;
	u32_t   FramesTx128_255Bytes;
	u32_t   FramesTx256_511Bytes;
	u32_t   FramesTx512_1023Bytes;
	u32_t   FramesTx1024_1522Bytes;
	u32_t   FramesTx1523_9022Bytes;
	u32_t   ValidBytesRx_High;
	u32_t   ValidBytesRx_Low;
	u32_t   ErrorRuntPktsRx;
	u32_t   ErrorJabberPktsRx;

} NcsiNicEmacStats_t;

typedef NcsiNicEmacStats_t *pNcsiNicEmacStats_t;


/*****************************************************************************

NcsiCmdGetPortStatisticsRspData_t

    this structure defines the data field portion of the response Payload 
    returned when processing the get ump i/f statistics ump cmd.
	 
*****************************************************************************/
typedef struct NcsiCmdGetPortStatisticsRspData
{
#if defined (BIG_ENDIAN)
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
#elif defined (LITTLE_ENDIAN)
	u16_t                            ReasonCode;            /* ids reasons for rsp  */
	u16_t                            ResponseCode;          /* ids outcome of cmd   */
#endif // endian

	u32_t   CountersClearedHigh;
	u32_t   CountersClearedLow;

	NcsiNicEmacStats_t  Stats;

} NcsiCmdGetPortStatisticsRspData_t;

typedef NcsiCmdGetPortStatisticsRspData_t *pNcsiCmdGetPortStatisticsRspData_t;


/*****************************************************************************

NcsiCmdGetControllerVerIdRspData_t

    this structure definition is for the data fields of the response Payload 
    returned used processing the get bcm version ID ump cmd.
	 
*****************************************************************************/
#define GET_NIC_VER_ID_SIZE_OF_FW_NAME 12
typedef struct NcsiCmdGetControllerVerIdRspData
#if defined (BIG_ENDIAN)
{

	u16_t   ResponseCode;         /* ids outcome of cmd   */
	u16_t   ReasonCode;         /* ids reasons for rsp  */

	NcsiVersion_t   NcsiVersion;
	u8_t    FirmwareName[GET_NIC_VER_ID_SIZE_OF_FW_NAME];
	u32_t   FirmwareRev;

	u16_t   PciDeviceId;
	u16_t   PciVendorId;
	u16_t   PciSubsystemId;
	u16_t   PciSubsystemVendorId;

	u32_t   ManufacturerId;      /* ManufacturerId IANA */

} NcsiCmdGetControllerVerIdRspData_t;
#elif defined (LITTLE_ENDIAN)
{

	   u16_t   ReasonCode;         /* ids reasons for rsp  */
	   u16_t   ResponseCode;         /* ids outcome of cmd   */

	   NcsiVersion_t   NcsiVersion;
/*    u8_t    Major;
    u8_t    Reserved0;
    u8_t    Alpha1;
    u8_t    Update;
    u8_t    Minor;
*/
	   u8_t    FirmwareName[12];
	   u8_t    Alpha2;
	   u8_t    Reserved2;
	   u8_t    Reserved1;
	   u32_t   FirmwareRev;

	   u16_t   PciVendorId;
	   u16_t   PciDeviceId;
	   u16_t   PciSubsystemVendorId;
	   u16_t   PciSubsystemId;

	   u32_t   ManufacturerId;    /* ManufacturerId IANA */

}
   NcsiCmdGetControllerVerIdRspData_t;
#endif // endian

#define NCSI_CMD_SIZEOF_DEFAULT_RSP_DATA                            (sizeof (NcsiCmdRspStatus_t))
#define NCSI_CMD_SIZEOF_GET_PARAMS_RSP_DATA                         (sizeof (NcsiCmdGetParametersRspData_t))
#define NCSI_CMD_SIZEOF_GET_LINK_STATUS_RSP_DATA                    (sizeof (NcsiCmdGetLinkStatusRspData_t))
#define NCSI_CMD_SIZEOF_GET_STATS_RSP_DATA                          (sizeof (NcsiCmdGetPortStatisticsRspData_t))
#define NCSI_CMD_SIZEOF_GET_CNTLR_VER_ID_RSP_DATA                     (sizeof (NcsiCmdGetControllerVerIdRspData_t))
#define NCSI_CMD_SIZEOF_GET_NCSI_STATS_RSP_DATA                     (sizeof (NcsiCmdGetNcsiStatisticsRspData_t))
#define NCSI_CMD_SIZEOF_GET_CAPABILITY_RSP_DATA                     (sizeof (NcsiCmdGetCapabilitiesRspData_t))
#define NCSI_CMD_SIZEOF_GET_NCSI_PASSTHRU_STATS_RSP_DATA            (sizeof (NcsiCmdGetNcsiPassThruStatisticsRspData_t))
#define NCSI_CMD_SIZEOF_DEFAULT_OEM_CMD_RSP_DATA                    (sizeof (NcsiDefaultOemCmdRspData_t))
#define NCSI_CMD_SIZEOF_DEFAULT_DELL_OEM_CMD_RSP_DATA               (sizeof(DellDfltCmdRspData_t))   // response/reason code, Manufacture ID, payload ver, Cmd ID, .. )
#define NCSI_CMD_SIZEOF_GET_NCSI_PARAMETERS_RSP_DATA                (sizeof (NcsiOemGetNcsiParametersRspData_t))
#define NCSI_CMD_SIZEOF_NCSI_TEST_READ_CMD_RSP_DATA                 (sizeof (NcsiCmdNcsiTestReadCmdRspData_t))
#define NCSI_CMD_SIZEOF_GET_PHY_PRIORITY_CMD_RSP_DATA               (sizeof (NcsiOemGetDualMediaParametersRspData_t))



/*****************************************************************************

NcsiCmdDefaultRspPayload_t    

    Structure definition for most basic UMP response Payload
	 
*****************************************************************************/
typedef struct NcsiCmdDefaultRspPayload
{
	NcsiCmdRspStatus_t     Data;
	u32_t               ChecksumCompensation;

} NcsiCmdDefaultRspPayload_t;
typedef NcsiCmdDefaultRspPayload_t *pNcsiCmdDefaultRspPayload_t;





/*****************************************************************************

NcsiDefaultOemCmdRspPayload_t    

    this structure defines the response Payload returned after processing
    the Oem cmd.
	 
*****************************************************************************/
typedef struct NcsiDefaultOemCmdRspPayload
{
	NcsiDefaultOemCmdRspData_t   Data;
	u32_t                        ChecksumCompensation;

} NcsiDefaultOemCmdRspPayload_t;
typedef NcsiDefaultOemCmdRspPayload_t *pNcsiDefaultOemCmdRspPayload_t;


/*****************************************************************************

NcsiOemGetNcsiParametersRspPayload_t    

    this structure defines the response Payload returned after processing
    the Oem cmd.
	 
*****************************************************************************/
typedef struct NcsiOemGetNcsiParametersRspPayload
{
	NcsiOemGetNcsiParametersRspData_t  Data;
	u32_t                            ChecksumCompensation;

} NcsiOemGetNcsiParametersRspPayload_t;
typedef NcsiOemGetNcsiParametersRspPayload_t *pNcsiOemGetNcsiParametersRspPayload_t;



/*****************************************************************************

NcsiOemGetDualMediaParametersRspPayload_t    

    this structure defines the response Payload returned after processing
    the Oem cmd.
	 
*****************************************************************************/
typedef struct NcsiOemGetDualMediaParametersRspPayload
{
	NcsiOemGetDualMediaParametersRspData_t  Data;
	u32_t                           ChecksumCompensation;

} NcsiOemGetDualMediaParametersRspPayload_t;
typedef NcsiOemGetDualMediaParametersRspPayload_t *pNcsiOemGetDualMediaParametersRspPayload_t;


typedef struct {
	u16_t     ResponseCode;
	u16_t     ReasonCode;
	u32_t     ManufacturerId;         /* ManufacturerId IANA */
	u8_t      PayloadVersion;
	u8_t      CommandType;            /* OEM command ID */
	u16_t     SupportedVersons;
	u32_t     Reserved;
} DellRspsGetSupportedVer_t;

typedef struct {

	u16_t   	ResponseCode;
	u16_t   	ReasonCode;
	u32_t	ManufacturerId;         /* ManufacturerId IANA */
	u8_t        PayloadVersion;
	u8_t        CommandType;
	u8_t        PartitionId;
	u8_t        NumOfTLVs;
	u8_t        buf[MAX_TLV_COMMAND_SIZE]; /*This is a place holder for the Maximum size in bytesof this command with all TLV's present*/
} DellRspsPartitionTLV_t;
#define DELLOEMRSP_PARTITION_TLV_BASE_SIZE	12	//exclude pad & chksum

// TLV type definition for Get OS Driver Version Command
#define OSVER_TYPE_LAN		0
#define OSVER_TYPE_ISCSI	1
#define OSVER_TYPE_FCOE		2
#define OSVER_TYPE_RDMA		3
#define OSVER_TYPE_FC		4

// TLV type definition for Set/Get iSCSI Boot Initiator Config Command
//v4 v6	size
#define ISCSI_INITIATOR_TYPE_ADDR		0
#define ISCSI_INITIATOR_TYPE_ADDR_V4		1
#define ISCSI_INITIATOR_TYPE_ADDR_V6		2
#define ISCSI_INITIATOR_TYPE_SUBNET		3
#define ISCSI_INITIATOR_TYPE_SUBNET_PREFIX	4
#define ISCSI_INITIATOR_TYPE_GATEWAY		5
#define ISCSI_INITIATOR_TYPE_GATEWAY_V4		6
#define ISCSI_INITIATOR_TYPE_GATEWAY_V6		7
#define ISCSI_INITIATOR_TYPE_PRIMARY_DNS	8
#define ISCSI_INITIATOR_TYPE_PRIMARY_DNS_V4	9
#define ISCSI_INITIATOR_TYPE_PRIMARY_DNS_V6	0xa
#define ISCSI_INITIATOR_TYPE_SECOND_DNS		0xb
#define ISCSI_INITIATOR_TYPE_SECOND_DNS_V4	0xc
#define ISCSI_INITIATOR_TYPE_SECOND_DNS_V6	0xd
#define ISCSI_INITIATOR_TYPE_NAME		0xe
#define ISCSI_INITIATOR_TYPE_CHAP_ID		0xf
#define ISCSI_INITIATOR_TYPE_CHAP_PSWD		0x10
#define ISCSI_INITIATOR_TYPE_IP_VER		0x11
#define ISCSI_INITIATOR_TYPE_MAX		ISCSI_INITIATOR_TYPE_IP_VER

#define ISCSI_INITIATOR_TYPE_SUPPORTED_V4_MASK	((1<<ISCSI_INITIATOR_TYPE_ADDR)|(1<<ISCSI_INITIATOR_TYPE_ADDR_V4)| \
						(1<<ISCSI_INITIATOR_TYPE_SUBNET)|(1<<ISCSI_INITIATOR_TYPE_GATEWAY)| \
						(1<<ISCSI_INITIATOR_TYPE_GATEWAY_V4)| \
						(1<<ISCSI_INITIATOR_TYPE_PRIMARY_DNS)| \
						(1<<ISCSI_INITIATOR_TYPE_PRIMARY_DNS_V4)| \
						(1<<ISCSI_INITIATOR_TYPE_SECOND_DNS)| \
						(1<<ISCSI_INITIATOR_TYPE_SECOND_DNS_V4)| \
						(1<<ISCSI_INITIATOR_TYPE_NAME)|(1<<ISCSI_INITIATOR_TYPE_CHAP_ID)| \
						(1<<ISCSI_INITIATOR_TYPE_CHAP_PSWD)|(1<<ISCSI_INITIATOR_TYPE_IP_VER))
#define ISCSI_INITIATOR_TYPE_SUPPORTED_V6_MASK	((1<<ISCSI_INITIATOR_TYPE_ADDR)|(1<<ISCSI_INITIATOR_TYPE_ADDR_V6)| \
						(1<<ISCSI_INITIATOR_TYPE_SUBNET_PREFIX)| \
						(1<<ISCSI_INITIATOR_TYPE_GATEWAY)| \
						(1<<ISCSI_INITIATOR_TYPE_GATEWAY_V6)| \
						(1<<ISCSI_INITIATOR_TYPE_PRIMARY_DNS)| \
						(1<<ISCSI_INITIATOR_TYPE_PRIMARY_DNS_V6)| \
						(1<<ISCSI_INITIATOR_TYPE_SECOND_DNS)| \
						(1<<ISCSI_INITIATOR_TYPE_SECOND_DNS_V6)| \
						(1<<ISCSI_INITIATOR_TYPE_NAME)|(1<<ISCSI_INITIATOR_TYPE_CHAP_ID)| \
						(1<<ISCSI_INITIATOR_TYPE_CHAP_PSWD)|(1<<ISCSI_INITIATOR_TYPE_IP_VER))

// TLV type definition for Set/Get iSCSI Boot Target Config Command
#define ISCSI_TARGET_TYPE_CONNECT		0x0
#define ISCSI_TARGET_TYPE_IP_ADDR		0x1
#define ISCSI_TARGET_TYPE_TCP_PORT		0x2
#define ISCSI_TARGET_TYPE_BOOT_LUN		0x3
#define ISCSI_TARGET_TYPE_NAME			0x4
#define ISCSI_TARGET_TYPE_CHAP_ID		0x5
#define ISCSI_TARGET_TYPE_CHAP_PSWD		0x6
#define ISCSI_TARGET_TYPE_IP_VER		0x7
#define ISCSI_TARGET2_TYPE_CONNECT		0x8
#define ISCSI_TARGET2_TYPE_IP_ADDR		0x9
#define ISCSI_TARGET2_TYPE_TCP_PORT		0xa
#define ISCSI_TARGET2_TYPE_BOOT_LUN		0xb
#define ISCSI_TARGET2_TYPE_NAME			0xc
#define ISCSI_TARGET2_TYPE_CHAP_ID		0xd
#define ISCSI_TARGET2_TYPE_CHAP_PSWD		0xe
#define ISCSI_TARGET2_TYPE_IP_VER		0xf
#define ISCSI_TARGET2_BASE			ISCSI_TARGET2_TYPE_CONNECT
#define ISCSI_TARGET_TYPE_MAX			ISCSI_TARGET2_TYPE_IP_VER

#define FCOE_BOOT_SCAN_SELECTION                           0x0
#define FCOE_FIRST_WWPN_TARGET                             0x1
#define FCOE_FIRST_BOOT_TARGET_LUN                         0x2
#define FCOE_FIRST_FCF_VLAN_ID                             0x3
#define FCOE_TGT_BOOT                                      0x4
#define FCOE_TARGET_TYPE_MAX			           FCOE_TGT_BOOT

typedef DellRspsPartitionTLV_t DellRspsGetOsDriverVer_t;
typedef DellRspsPartitionTLV_t DellRspsGetiScsiInitiatorConf_t;
typedef DellRspsPartition_t    DellRspsSetiScsiInitiatorConf_t;
typedef DellRspsPartitionTLV_t DellRspsGetiScsiTargetConf_t;
typedef DellRspsPartition_t    DellRspsSetiScsiTargetConf_t;
typedef DellRspsPartitionTLV_t DellRspsGetFcoeTargetConf_t;
typedef DellRspsPartition_t    DellRspsSetFcoeTargetConf_t;
typedef DellRspsDefault_t      DellRspsCommitNvram_t;
typedef DellRspsDefault_t      DellRspsGetCommitNvramStatus_t;

/*****************************************************************************

NcsiDellOemCmdRspPayload_t    

    this structure defines the response Payload returned after processing
    the Oem cmd.
	 
*****************************************************************************/
typedef struct NcsiDellOemCmdRspPayload
{
	union
	{
		// Dell OEM commands Response Payload
		DellGetInventoryCmdRspData_t                GetInventory;             // 0x00 DELL_OEM_GET_INVENTORY_CMD
		DellGetExtendedCapabilitiesCmdRspData_t     GetExtendedCapabilities;  // 0x01 DELL_OEM_GET_EXTENDED_CAPABILITIES_CMD
		DellGetPartitionInfoCmdRspData_t            GetPartitionInfo;         // 0x02 DELL_OEM_GET_PARTITION_INFORMATION_CMD
		DellGetFcoeCapabilitiesCmdRspData_t         GetFcoeCapabilities;      // 0x03 DELL_OEM_GET_FCOE_CAPABILITIES_CMD
		DellGetVirtualLinkCmdRspData_t              GetVirtualLink;           // 0x04 DELL_OEM_GET_VIRTUAL_LINK_CMD
		DellGetLanStatisticsCmdRspData_t            GetLanStatistics;         // 0x05 DELL_OEM_GET_LAN_STATISTICS_CMD
		DellGetFcoeStatisticsCmdRspData_t           GetFcoeStatistics;        // 0x06 DELL_OEM_GET_FCOE_STATISTICS_CMD
		DellSetAddrCmdRspData_t                     SetAddr;                  // 0x07 DELL_OEM_SET_ADDR_CMD
		DellGetAddrCmdRspData_t                     GetAddr;                  // 0x08 DELL_OEM_GET_ADDR_CMD
		DellSetLicenseCmdRspData_t                  SetLicense;               // 0x09 DELL_OEM_SET_LICENSE_CMD
		DellGetLicenseCmdRspData_t                  GetLicense;               // 0x0A DELL_OEM_GET_LICENSE_CMD
		DellSetPassthruCtrlCmdRspData_t             SetPassthruCtrl;          // 0x0B DELL_OEM_SET_PASSTHRU_CONTROL_CMD
		DellGetPassthruCtrlCmdRspData_t             GetPassthruCtrl;          // 0x0C DELL_OEM_GET_PASSTHRU_CONTROL_CMD
		DellSetPartitionTxBandwidthCmdRspData_t     SetPartitionTxBandwidth;  // 0x0D DELL_OEM_SET_PARTITIONCmd_tX_BANDWIDTH_CMD
		DellGetPartitionTxBandwidthCmdRspData_t     GetPartitionTxBandwidth;  // 0x0E DELL_OEM_GET_PARTITIONCmd_tX_BANDWIDTH_CMD
		DellSetMcIpAddrCmdRspData_t                 SetMcIpAddr;              // 0x0F DELL_OEM_SET_MC_IP_ADDRESS_CMD
		DellGetTeamingInfoCmdRspData_t              GetTeamingInfo;           // 0x10 DELL_OEM_GETCmd_tEAMING_INFORMATION_CMD
		DellEnablePortsCmdRspData_t                 EnablePorts;              // 0x11 DELL_OEM_ENABLE_PORTS_CMD
		DellDisablePortsCmdRspData_t                DisablePorts;             // 0x12 DELL_OEM_DISABLE_PORTS_CMD
		DellGetTempCmdRspData_t                     GetTemp;                  // 0x13 DELL_OEM_GET_TEMPERATURE_CMD
		DellSetLinkTuningCmdRspData_t               SetLinkTuning;            // 0x14 DELL_OEM_SET_LINKTUNING_CMD
		DellEnableDisableOutOfBoxWolCmdRspData_t    EnableDisableOutOfBoxWol; // 0x15 DELL_OEM_ENABLE_OUTOFBOX_WOL_CMD and 0x16 DELL_OEM_DISABLE_OUTOFBOX_WOL_CMD
		DellRspsGetSupportedVer_t                   GetSupportedVer;          // 0x1A DELL_OEM_GET_SUPP_PAYLOAD_VERSION_CMD
		DellRspsGetOsDriverVer_t                    GetOsDriverVer;           // 0x1C DELL_OEM_GET_OS_DRIVER_VERSION_CMD
		DellRspsGetiScsiInitiatorConf_t             GetiScsiInitiatorConf;    // 0x1D DELL_OEM_GET_ISCSI_BOOT_INITIATOR_CONFIG_CMD
		DellRspsSetiScsiInitiatorConf_t             SetiScsiInitiatorConf;    // 0x1E DELL_OEM_SET_ISCSI_BOOT_INITIATOR_CONFIG_CMD
		DellRspsGetiScsiTargetConf_t                GetiScsiTargetConf;       // 0x1F DELL_OEM_GET_ISCSI_BOOT_TARGET_CONFIG_CMD
		DellRspsSetiScsiTargetConf_t                SetiScsiTargetConf;       // 0x20 DELL_OEM_SET_ISCSI_BOOT_TARGET_CONFIG_CMD
		DellRspsGetFcoeTargetConf_t                 GetFcoeTargetConf;        // 0x21 DELL_OEM_GET_FCOE_BOOT_TARGET_CONFIG_CMD
		DellRspsSetFcoeTargetConf_t                 SetFcoeTargetConf;        // 0x22 DELL_OEM_SET_FCOE_BOOT_TARGET_CONFIG_CMD
		DellRspsCommitNvram_t                       CommitNvram;              // 0x23 DELL_OEM_NVRAM_COMMIT_CMD
		DellRspsGetCommitNvramStatus_t              GetCommitNvramStatus;     // 0x24 DELL_OEM_NVRAM_COMMIT_STATUS_CMD
	};
	u32_t                        ChecksumCompensation;
} NcsiDellOemCmdRspPayload_t;

typedef NcsiDellOemCmdRspPayload_t *pNcsiDellOemCmdRspPayload_t;


/*****************************************************************************

NcsiCmdGetParametersRspPayload_t

    this structure defines the response frame Payload returned in response to
    the get parameters ump cmd.

*****************************************************************************/
typedef struct NcsiCmdGetParametersRspPayload
{
	NcsiCmdGetParametersRspData_t    Data;
	u32_t                         ChecksumCompensation;
}NcsiCmdGetParametersRspPayload_t;





/*****************************************************************************

NcsiCmdNcsiTestReadRspPayload_t

    this structure defines the response frame Payload returned in response to
    the NCSI Test read cmd.

*****************************************************************************/
typedef struct NcsiCmdNcsiTestReadRspPayload
{
	NcsiCmdNcsiTestReadCmdRspData_t    Data;
	u32_t                         ChecksumCompensation;

} NcsiCmdNcsiTestReadRspPayload_t;


/*****************************************************************************

NcsiCmdGetLinkStatusRspPayload_t    

    this structure defines the response Payload returned after processing
    the get link status ump cmd.
	 
*****************************************************************************/
typedef struct NcsiCmdGetLinkStatusRspPayload
{
	NcsiCmdGetLinkStatusRspData_t   Data;
	u32_t                        ChecksumCompensation;

} NcsiCmdGetLinkStatusRspPayload_t;

typedef NcsiCmdGetLinkStatusRspPayload_t *pNcsiCmdGetLinkStatusRspPayload_t;


/*****************************************************************************

NcsiCmdGetCapabilitiesRspPayload_t    

    this structure defines the response Payload returned after processing
    the get link status ump cmd.
	 
*****************************************************************************/
typedef struct NcsiCmdGetCapabilitiesRspPayload
{
	NcsiCmdGetCapabilitiesRspData_t     Data;
	u32_t                            ChecksumCompensation;

} NcsiCmdGetCapabilitiesRspPayload_t;

typedef NcsiCmdGetCapabilitiesRspPayload_t *pNcsiCmdGetCapabilitiesRspPayload_t;




/*****************************************************************************

NcsiCmdGetPortStatisticsRspPayload_t

    this structure definition is for the response Payload used when processing
    the get i/f statistics ump cmd.
	 
*****************************************************************************/
typedef struct NcsiCmdGetPortStatisticsRspPayload
{
	NcsiCmdGetPortStatisticsRspData_t    Data;
	u32_t                               ChecksumCompensation;

} NcsiCmdGetPortStatisticsRspPayload_t;
typedef NcsiCmdGetPortStatisticsRspPayload_t *pNcsiCmdGetPortStatisticsRspPayload_t;

/*****************************************************************************

NcsiCmdGetNcsiStatisticsRspPayload_t

    this structure definition is for the response Payload used when processing
    the get ump i/f statistics ump cmd.
	 
*****************************************************************************/
typedef struct NcsiCmdGetNcsiStatisticsRspPayload
{
	NcsiCmdGetNcsiStatisticsRspData_t    Data;
	u32_t                             ChecksumCompensation;

} NcsiCmdGetNcsiStatisticsRspPayload_t;
typedef NcsiCmdGetNcsiStatisticsRspPayload_t *pNcsiCmdGetNcsiStatisticsRspPayload_t;



/*****************************************************************************
		   
NcsiCmdGetNcsiPassThruStatisticsRspPayload_t

    this structure definition is for the response Payload used when processing
    the get .
	 
*****************************************************************************/
typedef struct NcsiCmdGetNcsiPassThruStatisticsRspPayload
{
	NcsiCmdGetNcsiPassThruStatisticsRspData_t    Data;
	u32_t                                     ChecksumCompensation;

} NcsiCmdGetNcsiPassThruStatisticsRspPayload_t;
typedef NcsiCmdGetNcsiPassThruStatisticsRspPayload_t *pNcsiCmdGetNcsiPassThruStatisticsRspPayload_t;


/*****************************************************************************

NcsiCmdGetControllerVerIdRspPayload_t

    this structure definition is for the response Payload used when processing
    the get bcm version ID ump cmd.
	 
*****************************************************************************/
typedef struct  NcsiCmdGetControllerVerIdRspPayload
{
	NcsiCmdGetControllerVerIdRspData_t  Data;
	u32_t                            ChecksumCompensation;

} NcsiCmdGetControllerVerIdRspPayload_t;

/*****************************************************************************

NcsiCmdRspPayload_t

    this union definition combines the various response Payload definitions
    into a single reference.
	 
*****************************************************************************/
typedef union NcsiCmdRspPayload
{

	NcsiCmdDefaultRspPayload_t                      DefaultPayload;
	NcsiDefaultOemCmdRspPayload_t                   DefaultOemCmdPayload;
	NcsiOemGetNcsiParametersRspPayload_t            GetNcsiParametersPayload;
	NcsiOemGetDualMediaParametersRspPayload_t       GetDualMediaParametersPayload;
	NcsiCmdGetParametersRspPayload_t                GetParametersPayload;
	NcsiCmdGetLinkStatusRspPayload_t                GetLinkStatusPayload;
	NcsiCmdGetPortStatisticsRspPayload_t            GetStatisticsPayload;
	NcsiCmdGetControllerVerIdRspPayload_t           GetCntlrVerIdPayload;
	NcsiCmdGetNcsiStatisticsRspPayload_t            GetNcsiStatsPayload;
	NcsiCmdGetNcsiPassThruStatisticsRspPayload_t    GetNcsiPassThruStatsPayload;
	NcsiCmdGetCapabilitiesRspPayload_t              GetCapabilitiesPayload;
	NcsiCmdNcsiTestReadRspPayload_t                 NcsiTestReadPayload;
	// Dell OEM commands Response Payload
	NcsiDellOemCmdRspPayload_t                      DellOemCmdRspPayload;

} NcsiCmdRspPayload_t;

#define NCSI_CMD_CHKSUM_SIZE        SIZEOF(NcsiCmdDefaultRspPayload_t, ChecksumCompensation)


/*****************************************************************************

NcsiRmiiCmdRspPkt_t

    this structure definition is for the command response frame that is sent
    back to the IMD for each processed UMP command.
    
    IMD command frames are acknowledged by copying the command frame header 
    into received from iLO over the UMP interface, and are
    either processed locally for configuration and control, or are forwarded 
    for transmission at the primary ethernet port.    
     
*****************************************************************************/
typedef struct NcsiRmiiCmdRspPkt
{
	NcsiRmiiControlPktHeader_t   Header;
	NcsiCmdRspPayload_t    Payload;

} NcsiRmiiCmdRspPkt_t;

typedef NcsiRmiiCmdRspPkt_t *pNcsiRmiiCmdRspPkt_t;


/*****************************************************************************

NcsiCmdDefaultAenData_t    

    Structure definition for most basic Aen data
	 
*****************************************************************************/
typedef struct NcsiCmdDefaultAenData
{
	u32_t    AenType;
#define NCSI_CMD_AEN_TYPE_LINK_CHANGED                                (0)
#define NCSI_CMD_AEN_TYPE_SOFT_RESET                                  (1)
#define NCSI_CMD_AEN_TYPE_OS_CHANGED                                  (2)

} NcsiCmdDefaultAenData_t;

/*****************************************************************************

NcsiCmdLinkChangedAenData_t    

    Structure definition for link changed Aen data
	 
*****************************************************************************/
typedef struct NcsiCmdLinkChangedAenData
{
	u32_t   AenType;
	u32_t   LinkState;
	u32_t   OemLinkSpeed;

} NcsiCmdLinkChangedAenData_t;

/*****************************************************************************

NcsiCmdOsChangedAenData_t    

    Structure definition for os changed Aen data
	 
*****************************************************************************/
typedef struct NcsiCmdOsChangedAenData
{
	u32_t    AenType;
	u32_t    OsState;
#define UMPCMDPUB_OS_STATE_CHANGED_AEN_OS_PRESENT   1
#define UMPCMDPUB_OS_STATE_CHANGED_AEN_OS_ABSENT    0

} NcsiCmdOsChangedAenData_t;



#define NCSI_CMD_SIZEOF_DEFAULT_AEN_DATA        (sizeof (NcsiCmdDefaultAenData_t))
#define NCSI_CMD_SIZEOF_LINK_CHANGED_AEN_DATA   (sizeof (NcsiCmdLinkChangedAenData_t))
#define NCSI_CMD_SIZEOF_OS_CHANGED_AEN_DATA     (sizeof (NcsiCmdOsChangedAenData_t))


/*****************************************************************************

NcsiCmdDefaultAenPayload_t    

    Structure definition for most basic Aen Payload
	 
*****************************************************************************/
typedef struct NcsiCmdDefaultAenPayload
{
	NcsiCmdDefaultAenData_t Data;
	u32_t                ChecksumCompensation;

} NcsiCmdDefaultAenPayload_t;

/*****************************************************************************

NcsiCmdLinkChangedAenPayload_t    

    Structure definition for Link changed Aen Payload
	 
*****************************************************************************/
typedef struct NcsiCmdLinkChangedAenPayload
{
	NcsiCmdLinkChangedAenData_t     Data;
	u32_t                        ChecksumCompensation;

} NcsiCmdLinkChangedAenPayload_t;

/*****************************************************************************

NcsiCmdOsChangedAenPayload_t    

    Structure definition for os chagned Aen Payload
	 
*****************************************************************************/
typedef struct NcsiCmdOsChangedAenPayload
{
	NcsiCmdOsChangedAenData_t   Data;
	u32_t                    ChecksumCompensation;

} NcsiCmdOsChangedAenPayload_t;


/*****************************************************************************

NcsiCmdAenPayload_t

    this union definition combines the various Aen Payload definitions
    into a single reference.
	 
*****************************************************************************/
typedef union NcsiCmdAenPayload
{

	NcsiCmdDefaultAenPayload_t       DefaultPayload;
	NcsiCmdLinkChangedAenPayload_t   LinkChangedPayload;
	NcsiCmdOsChangedAenPayload_t     OsChangedPayload;

} NcsiCmdAenPayload_t;


#define NCSI_CMD_SIZEOF_DEFAULT_AEN_PAYLOAD          (sizeof (NcsiCmdDefaultAenPayload_t))
#define NCSI_CMD_SIZEOF_LINK_CHANGED_AEN_PAYLOAD     (sizeof (NcsiCmdLinkChangedAenPayload_t))
#define NCSI_CMD_SIZEOF_OS_CHANGED_AEN_PAYLOAD       (sizeof (NcsiCmdOsChangedAenPayload_t))


/*****************************************************************************

NcsiCmdAenPacket_t

    this structure definition is for the UMP AEN frame that is sent to the BMC 
    for to report asynchronous events.
	 
*****************************************************************************/
typedef struct NcsiCmdAenPacket
{
	NcsiRmiiControlPktHeader_t  Header;
	NcsiCmdAenPayload_t     Payload;
} NcsiCmdAenPacket_t;

typedef NcsiCmdAenPacket_t *pNcsiCmdAenPacket_t;


#endif







