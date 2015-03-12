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
* FILE NAME:       ncsi_types.h
*
* DESCRIPTION: 
*
* CONVENTIONS:
*
* AUTHOR:          Tim Sharp
*
* CREATION DATE:     
*
* REVISION HISTORY
*
*   When        Who     What
*   -------------------------------------------------------------------------
****************************************************************************/


#ifndef NCSI_BASIC_TYPES_H
#define NCSI_BASIC_TYPES_H

#include "bcmtype.h"
#include "license.h"    // needed by shmem.h
#include "mcp_shmem.h"

#define NCSI_TYPES_INTERFACE_REV   0x0010
/*----------------------------------------------------------------------------
------------------------------ include files ---------------------------------
----------------------------------------------------------------------------*/
// Currently only E2 support 2 PATH. To make data structure same for all chips, 
// we make sure data structure fit all 2 paths regardless of the chips
#define PATH_SUPPORTED          2    

#define NCSI_MAC_ADDRESS_MAX    4
#define NCSI_VLAN_TAG_COUNT     2


#define NCSI_HEADER_REV (0x01)

/*----------------------------------------------------------------------------
------------------------------ local definitions -----------------------------

structs, unions, typedefs, #defines, etc belong here...

----------------------------------------------------------------------------*/
#define INTEGRATED_WITH_BOOTCODE

typedef u8_t*           pu8_t;
typedef u16_t*          pu16_t;
typedef u32_t*          pu32_t;
typedef void*           pVoid_t;


#define NCSI_TYPES_MILLISEC_TO_MICROSEC_MULTIPLIER          1000


#define NCSI_TYPES_CHANNEL_ID_MASK                          0x000000C0
#define NCSI_TYPES_MAGIC_NUMBER                             0xA5A5A5A5

#define NCSI_LANDMARK_SIGNATURE                             0x01234567
#define NCSI_TYPES_MAX_MCP_FTQ_DEPTH_OS_PRESENT             (5 << 12)    // set depth to 5 entries
#define NCSI_TYPES_MAX_MCP_FTQ_DEPTH_OS_ABSENT              (32 << 12)   // set depth to 32 entries

#define NCSI_TYPES_MAX_L2_PKT_SIZE                          1514            /* max Ethernet frame size for IMD */
#define NCSI_TYPES_MAX_L2_PKT_SIZE_PLUS_VLAN                1518            /* max Ethernet frame size for IMD */
#define NCSI_TYPES_MIN_L2_PKT_SIZE                          60              /* min Ethernet frame size */

#define UMP_BCNT_FRAGMENT_AND_ALIGNMENT_ADJUSTMENT          5 /* 3 bytes for fragment 
                                                            rounding and 2 more for 
                                                            the +2 alignment.  The 
                                                            CRC is not included here */
#define SIZEOF_CRC                                          4
#define SIZEOF_MAC_ADDRESS                                  6



#define SUCCESS                                             0
#define FAILURE                                             1

#define STATUS_OK                                                  0
#define STATUS_ERROR                                               1  


#define NCSI_TYPES_MIN_UMP_CMD_RSP_FRAME_SIZE  60


#define MDIO_PHY_ADDR(X)             ( ( (X) & 0x1F ) << 21 )
#define MDIO_PHY_REG(X)              ( ( (X) & 0x1F ) << 16 )


/*****************************************************************************

    The NCSI version type is based on the format used in the get version
    command, and is intended to allow the struct value to be copied directly 
    into the packet structure byte for byte without processing.
    
*****************************************************************************/

typedef struct NcsiVersion
#if defined (BIG_ENDIAN)
{
    u8_t    Major;
    u8_t    Minor;
    u8_t    Update;
    u8_t    Alpha1;
    u8_t    Reserved0;
    u8_t    Reserved1;
    u8_t    Reserved2;
    u8_t    Alpha2;
}NcsiVersion_t;
#elif defined (LITTLE_ENDIAN)
{
    u8_t    Alpha1;
    u8_t    Update;
    u8_t    Minor;
    u8_t    Major;
    u8_t    Alpha2;
    u8_t    Reserved2;
    u8_t    Reserved1;
    u8_t    Reserved0;
}NcsiVersion_t;
#endif // ENDIAN

/*****************************************************************************

*****************************************************************************/


typedef struct NcsiMacAddr
#if defined (BIG_ENDIAN)
{
    u16_t   High;       
    u16_t   LowHigh;    
    u16_t   LowLow;     
                           
} NcsiMacAddr_t;  
#elif defined (LITTLE_ENDIAN)
{
    u16_t   LowHigh;    
    u16_t   High;       
                           
    u16_t   LowLow;     
	u8_t	NcsiMacAddr_padding_16;	// padding fields added 
	u8_t	NcsiMacAddr_padding_24;	// padding fields added 
} NcsiMacAddr_t;  
#endif // ENDIAN



typedef struct UmpMacAddr
{
    u32_t   High;       
    u32_t   Low;     
} UmpMacAddr_t;                                                 // 8 bytes total


typedef UmpMacAddr_t* pUmpMacAddr_t;

typedef struct MacAddrConfig
{
    u32_t        IsEnabled;  
    UmpMacAddr_t    Addr;       
    
} MacAddrConfig_t;                                              //12 bytes total



/*****************************************************************************

UmpVlan_t    

    Structure definition for vlan tag
         
*****************************************************************************/
typedef struct UmpVlan
#if defined (BIG_ENDIAN)
{
    u16_t   IsEnabled;           // 
    u16_t   TagControlInfo ;     // tag control info 
        #define VLAN_TAG_VID_FIELD_MASK     (0x0FFF << 0)
        #define VLAN_TAG_PRI_FIELD_MASK     (0xE000 << 0)
        #define VLAN_TAG_CFI_FIELD_MASK     (0x1000 << 0)

} UmpVlan_t;                                                    // 4 bytes total   
#elif defined (LITTLE_ENDIAN)
{
    u16_t   TagControlInfo ;     // tag control info 
    u16_t   IsEnabled;           // 
        #define VLAN_TAG_VID_FIELD_MASK     (0x0FFF << 0)
        #define VLAN_TAG_PRI_FIELD_MASK     (0xE000 << 0)
        #define VLAN_TAG_CFI_FIELD_MASK     (0x1000 << 0)

} UmpVlan_t;                                                    // 4 bytes total   
#endif // ENDIAN

typedef UmpVlan_t* pVlanTag_t;


/*****************************************************************************

*****************************************************************************/


typedef struct PktErrorStat_t
{
    u32_t    EgressPktsDroppedNoSaMatch;
    u32_t    IngressPktsDroppedVlanMis;
    u32_t    CmdsDroppedSizeErr;
    u32_t    CmdsDroppedChanPkgIdErr;
    u32_t    CmdsDroppedNcsiHdrRevErr;
    
} PktErrorStat_t;


typedef struct UmpDebugData
#if defined (BIG_ENDIAN)
{
    u32_t    LandMark;          
    u32_t    GlobalResetCount;
    u32_t    NcsiCmdDataAddr;   
    u32_t    UmpRxDataAddr;     
    u32_t    UmpTxDataAddr;     
    u16_t    TxDescErrCount;
    u16_t    LoopBackPktCount;

} UmpDebugData_t;               
#elif defined (LITTLE_ENDIAN)
{
    u32_t    LandMark;          
    u32_t    GlobalResetCount;
    u32_t    NcsiCmdDataAddr;   
    u32_t    UmpRxDataAddr;     
    u32_t    UmpTxDataAddr;     
    u16_t    LoopBackPktCount;
    u16_t    TxDescErrCount;
        
} UmpDebugData_t;               
#endif // ENDIAN

typedef UmpDebugData_t * UmpDebugDataPtr_t;

/*****************************************************************************

*****************************************************************************/
typedef struct CmdPktCnt
{
    u32_t   Rx;           //  Num of valid cmds rx by cmd proc
    u32_t   Dropped;      //  Num of cmds dropped by cmd proc
    u32_t   CmdTypeErrs;  //  Num of cmds that have had cmd type err
    u32_t   ChkSumErrs;   //  Num of cmds that have failed checksum calc
    u64_t   TotalRxPkts;  //  total of all cmd pkts rx
    u64_t   TotalTxPkts;  //  total of all control pkts sent
    u64_t   TotalRxBytes; //  total of all cmd pkts rx
    u64_t   TotalTxBytes; //  total of all control pkts sent
    u32_t   AensSent;     //  count of all aens sent

} CmdPktCnt_t;

typedef struct EgressPktCnt
{
    u32_t   TotalPktHigh;       // 0-3      count of all ump mgmt pkts rx
    u32_t   TotalPktLow;       // 0-3      count of all ump mgmt pkts rx
    u32_t   TotalDropped;    // 12-15    count of all ump pkts dropped regardless of type
    u32_t   ChannelStateErr; // 16-19    count of all ump mgmt pkts rx while channel is disabled
    u32_t   UnderSized;      // 20-23    count of all ump rx pkts whose bcnt was less than 60 bytes
    u32_t   OverSized;       // 24-27    count of all ump rx pkts whose bcnt was greater than 1514 bytes

} EgressPktCnt_t;                   

typedef struct IngressPktCnt
{
    u32_t   TotalPkt;        // 0-3    count of all packets received on the mcp ftq
    u32_t   TotalDropped;    // 4-7    count of all packets dropped for any reason
    u32_t   OverSizedErr;    // 8-11   count of all packets dropped due to being undersized 
    u32_t   UnderSizedErr;   // 12-15  count of all packets dropped due to being oversized 
    u32_t   ChannelStateErr; // 16-19  count of all packets dropped because rx when chan disabled
                                  
} IngressPktCnt_t;                

typedef struct SmbusErrCnt
#if defined (BIG_ENDIAN)
{
    u8_t      slave_rd_event;            //  SLAVE_RD_EVENT             
    u8_t      slave_start_busy;          //  SLAVE_START_BUSY           
    u8_t      slave_arp_event;           //  SLAVE_ARP_EVENT            
    u8_t      master_rx_event;           //  MASTER_RX_EVENT            

    u8_t      slave_tx_underrun;         //  SLAVE_TX_UNDERRUN          
    u8_t      slave_rx_threshold_hit;    //  SLAVE_RX_THRESHOLD_HIT     
    u8_t      slave_rx_fifo_full;        //  SLAVE_RX_FIFO_FULL         
    u8_t      master_tx_underrun;        //  MASTER_TX_UNDERRUN         

    u8_t      master_rx_threshold_hit;   //  MASTER_RX_THRESHOLD_HIT    
    u8_t      master_rx_fifo_full;       //  MASTER_RX_FIFO_FULL        
    u8_t      fifo_overflow;             //  FIFO overflow              
    u8_t      transaction_error;         //  General SMBUS transaction err

    u8_t      pec_error;                 //  PEC error 
    u8_t      illegal_pkt_len;           //  rx pkt len > max len
    u8_t      lost_arbitration;          //  Lost Arbitration
    u8_t      slave_off_line;            //  slave device is off-line, NACK detected after (slave address) first byte

    u8_t      slave_busy;                //  slave device maybe busy, NACK detected after byte other than first
    u8_t      slave_bus_timeout;         //  slave device held bus for more then 25ms
    u8_t      master_busy_timeout;       //  Master Start Busy for > 200 msec
    u8_t      unused;                                     
} SmbusErrCnt_t;                
#elif defined (LITTLE_ENDIAN)
{
    u8_t      master_rx_event;           //  MASTER_RX_EVENT            
    u8_t      slave_arp_event;           //  SLAVE_ARP_EVENT            
    u8_t      slave_start_busy;          //  SLAVE_START_BUSY           
    u8_t      slave_rd_event;            //  SLAVE_RD_EVENT             

    u8_t      master_tx_underrun;        //  MASTER_TX_UNDERRUN         
    u8_t      slave_rx_threshold_hit;    //  SLAVE_RX_THRESHOLD_HIT     
    u8_t      slave_rx_fifo_full;        //  SLAVE_RX_FIFO_FULL         
    u8_t      slave_tx_underrun;         //  SLAVE_TX_UNDERRUN          

    u8_t      transaction_error;         //  General SMBUS transaction err
    u8_t      fifo_overflow;             //  FIFO overflow              
    u8_t      master_rx_fifo_full;       //  MASTER_RX_FIFO_FULL        
    u8_t      master_rx_threshold_hit;   //  MASTER_RX_THRESHOLD_HIT    

    u8_t      slave_off_line;            //  slave device is off-line, NACK detected after (slave address) first byte
    u8_t      lost_arbitration;          //  Lost Arbitration
    u8_t      illegal_pkt_len;           //  rx pkt len > max len
    u8_t      pec_error;                 //  PEC error 

    u8_t      unused;                                     
    u8_t      master_busy_timeout;       //  Master Start Busy for > 200 msec
    u8_t      slave_bus_timeout;         //  slave device held bus for more then 25ms
    u8_t      slave_busy;                //  slave device maybe busy, NACK detected after byte other than first
} SmbusErrCnt_t;                
#endif // ENDIAN


typedef struct UmpStatistics
{
    CmdPktCnt_t NcsiCmdPktCnts;                
    union
    {
        EgressPktCnt_t BMC2MCP;          
        SmbusErrCnt_t  smbus_err_cnts;
    };
    IngressPktCnt_t MCP2BMC;      
} UmpStatistics_t;                 


typedef struct ChannelState
{
    u32_t    Ready         :1; // 1b= ready, 0b = not ready
    u32_t    InitialState  :1; // 1b= in intial state, 0b = not in initial state
    u32_t    TxPtEnabled   :1; // 1b = tx pass through enabled, 0b = not enabled
    u32_t    RxPtEnabled   :1; // 1b = rx pass through enabled, 0b = not enabled
    
} ChannelState_t;



/*****************************************************************************

UmpPortConfig_t

    this structure definition is for the container of IMD configured data that  
    is saved and used in recovery from soft reset, and is returned in response 
    to the get parameters ump cmd.  This struct also stores the pointer to the 
    saved rsp frm also used in error recovery.
    
    Note that this definition is using the cmd pkt desc ptr for the prev rsp
    frm.  This is valid.

*****************************************************************************/
typedef struct UmpPortConfigFlag 
#if defined (BIG_ENDIAN)
{
    u32_t                             :11;
    u32_t    NetwBmcPassthruDisabled  :1;     // enabled by default, can be forced disabled by OEM command
    u32_t    VntagEnabled             :1;
    u32_t    InvalidHiGigLen          :1;     // This is set ONLY if HI_GIG header is 12

    u32_t    PerformReset             :1;    //#define UMPTX_FLAG_CHANNEL_RESET_PENDING   (1<<4)  // IMD channel reset has been rx
    u32_t    LinkStateChange          :1;    // indicates change in link state was detected on invocation

    u32_t    DriverStateChange        :1;    // indicates change in driver state was detected while processing port reset
    u32_t    DriverPresent            :1;        
    u32_t    ChannelSpecificReset     :1;
    u32_t    Exceed375MaFlag          :1;

    u32_t    OsPresentFlag            :1;            // used to store "actual" state of flag during testing        
    u32_t    HostBmcPassthruEnabled   :1;
    u32_t    ResetPending             :1; //10        TRUE=channel reset pending
    u32_t    VlanEnabled              :1; //9         TRUE=VlAN enabled

    u32_t    LinkForcedByBmc          :1; //8         TRUE=link config forced by IMD
    u32_t    HiGigMode                :1; //7         This is set ONLY if HI_GIG header is non-zero
    u32_t    BroadcastFilterEnabled   :1; //6         FALSE=dis, TRUE=en
    u32_t    MulticastFilterEnabled   :1; //5         FALSE=dis, TRUE=en

    u32_t    InitialState             :1; //4         1b= in intial state, 0b = not in initial state
    u32_t    Ready                    :1; //3         1b= ready, 0b = not ready
    u32_t    EgressPassThruEnabled    :1; //2         1b = tx pass through enabled, 0b = not enabled
    u32_t    ChannelEnabled           :1; //1        FALSE=dis, 1=en
} UmpPortConfigFlag_t;    
#elif defined (LITTLE_ENDIAN)
{
    u32_t    ChannelEnabled           :1; //1        FALSE=dis, 1=en
    u32_t    EgressPassThruEnabled    :1; //2         1b = tx pass through enabled, 0b = not enabled
    u32_t    Ready                    :1; //3         1b= ready, 0b = not ready
    u32_t    InitialState             :1; //4         1b= in intial state, 0b = not in initial state
    u32_t    MulticastFilterEnabled   :1; //5         FALSE=dis, TRUE=en
    u32_t    BroadcastFilterEnabled   :1; //6         FALSE=dis, TRUE=en
    u32_t    HiGigMode                :1; //7         This is set ONLY if HI_GIG header is non-zero
    u32_t    LinkForcedByBmc          :1; //8         TRUE=link config forced by IMD
    u32_t    VlanEnabled              :1; //9         TRUE=VlAN enabled
    u32_t    ResetPending             :1; //10        TRUE=channel reset pending
    u32_t    HostBmcPassthruEnabled   :1;
    u32_t    OsPresentFlag            :1;            // used to store "actual" state of flag during testing        
    u32_t    Exceed375MaFlag          :1;
    u32_t    ChannelSpecificReset     :1;
    u32_t    DriverPresent            :1;        
    u32_t    DriverStateChange        :1;    // indicates change in driver state was detected while processing port reset
    u32_t    LinkStateChange          :1;    // indicates change in link state was detected on invocation
    u32_t    PerformReset             :1;    //#define UMPTX_FLAG_CHANNEL_RESET_PENDING   (1<<4)  // IMD channel reset has been rx
    u32_t    InvalidHiGigLen          :1;     // This is set ONLY if HI_GIG header is 12
    u32_t    VntagEnabled             :1;
    u32_t    NetwBmcPassthruDisabled  :1;     // enabled by default, can be forced disabled by OEM command
    u32_t                             :11;
} UmpPortConfigFlag_t;    
#endif // ENDIAN
    
typedef struct UmpPortConfig
#if defined (BIG_ENDIAN)
{

    UmpPortConfigFlag_t Flags;    
    u32_t            ResetCount           : 12;
    u32_t            McId                : 4;       // id provided by mc in aen enable
    u32_t            AenConfig           : 4;       //
    u32_t            BroadcastFilter     : 4;       //
    u32_t            MulticastFilter     : 4;       //
    u32_t            VlanConfiguration   : 4;       //

    u32_t            LinkSettingsFromBmc;
    u32_t            OemLinkSettingsFromBmc;
    
    MacAddrConfig_t  MacAddr[NCSI_MAC_ADDRESS_MAX];    //60 Bytes (4 * 12 bytes each)
    UmpVlan_t        VlanTag[NCSI_VLAN_TAG_COUNT];     //68 Bytes (2 * 4 bytes each)
    u32_t            LinkStatus;                       //72 BYtes

} UmpPortConfig_t;                                        //72 bytes total
#elif defined (LITTLE_ENDIAN)
{

    UmpPortConfigFlag_t Flags;    
    u32_t            VlanConfiguration   : 4;       //
    u32_t            MulticastFilter     : 4;       //
    u32_t            BroadcastFilter     : 4;       //
    u32_t            AenConfig           : 4;       //
    u32_t            McId                : 4;       // id provided by mc in aen enable
    u32_t            ResetCount           : 12;

    u32_t            LinkSettingsFromBmc;
    u32_t            OemLinkSettingsFromBmc;
    
    MacAddrConfig_t  MacAddr[NCSI_MAC_ADDRESS_MAX];  //60 Bytes (4 * 12 bytes each)
    UmpVlan_t        VlanTag[NCSI_VLAN_TAG_COUNT];     //68 Bytes (2 * 4 bytes each)
    u32_t            LinkStatus;                       //72 BYtes

} UmpPortConfig_t;                                        //72 bytes total
#endif // ENDIAN

typedef struct
#if defined (BIG_ENDIAN)
{
    u8_t  vif_id;
    u8_t  allowed_priorities;
    u16_t default_vlan_tag;
}vntag_cfg_t;
#elif defined (LITTLE_ENDIAN)
{
    u16_t default_vlan_tag;
    u8_t  allowed_priorities;
    u8_t  vif_id;
}vntag_cfg_t;
#endif

/*****************************************************************************

    This data structure is intended to encapsulate runtime debug data that 
    could be accessed from a host based diagnostics program, as well as an
    embedded debug ump command.
    
*****************************************************************************/
typedef struct NcsiChannelData
{
    UmpStatistics_t     Statistics;              // 72 bytes
    UmpPortConfig_t        Config;               //current config state data-80 bytes
    vntag_cfg_t         VntagCfg;
} NcsiChannelData_t;                               // 152 bytes total

typedef struct SrcMacAddr
{
    u32_t   chnl    : 8;
    u32_t   addr_hi : 24;
    u32_t   addr_lo;
} SrcMacAddr_t;

#define HOST_SRC_ADDR_HIST_SIZE       8

typedef struct HostSrcMacBuff 
{
    u32_t current_index;
    SrcMacAddr_t  host_addr[HOST_SRC_ADDR_HIST_SIZE];
} HostSrcMacBuff_t;

#if defined (BIG_ENDIAN)
typedef NcsiChannelData_t* pNcsiChannelData_t;
#else
// define pointer as 32-bit value to ease diag encoding
typedef u32_t    pNcsiChannelData_t;
#endif

typedef struct PackageState
#if defined (BIG_ENDIAN)
{
    u32_t                        :12;
    u32_t    DellOemCmdSupport   :1;
    
    u32_t                        :1; 
    u32_t    PrevResetType       :8;
            #define NCSI_RESET_TYPE_CHANNEL0_RESET      0           // driver events D0
            #define NCSI_RESET_TYPE_CHANNEL1_RESET      1           // driver events D0
            #define NCSI_RESET_TYPE_COLD_START          0xAA        // POR from D3 hot
            #define NCSI_RESET_TYPE_WARM_START          0xBB        // OOB, and possibly POR from D3 cold
    
    u32_t    ControlPacketSeen   :1;
    u32_t    LoopBackPktActive   :1;

    u32_t    LoopBackEnabled     :1;
    u32_t    SmbusMode           :1; // 1b indicates SMBUS instead of RMII is being used 
    u32_t    SmbusFix            :1; // 1b indicates SMBUS tx fifo is fixed in HW
    u32_t    Ready               :1; // 1b= ready, 0b = not ready

    u32_t    Selected            :1; // 1b= selected, 0b = not selected
    u32_t    DeselectPending     :1; // 1b= waiting for ingress fifo to become empty
    u32_t    HwArbEnabled        :1; // 1b = HW arb in use, 0b = manual selection in use
    u32_t    FcDisabled          :1; //FALSE=dis, TRUE=en
    
} PackageState_t;
#elif defined (LITTLE_ENDIAN)
{
    
    u32_t    FcDisabled          :1; //FALSE=dis, TRUE=en
    u32_t    HwArbEnabled        :1; // 1b = HW arb in use, 0b = manual selection in use
    u32_t    DeselectPending     :1; // 1b= waiting for ingress fifo to become empty
    u32_t    Selected            :1; // 1b= selected, 0b = not selected
    u32_t    Ready               :1; // 1b= ready, 0b = not ready
    u32_t    SmbusFix            :1; // 1b indicates SMBUS tx fifo is fixed in HW
    u32_t    SmbusMode           :1; // 1b indicates SMBUS instead of RMII is being used 
    u32_t    LoopBackEnabled     :1;
    u32_t    LoopBackPktActive   :1;
    u32_t    ControlPacketSeen   :1;
    u32_t    PrevResetType        :8;
            #define NCSI_RESET_TYPE_CHANNEL0_RESET      0           // driver events D0
            #define NCSI_RESET_TYPE_CHANNEL1_RESET      1           // driver events D0
            #define NCSI_RESET_TYPE_COLD_START          0xAA        // POR from D3 hot
            #define NCSI_RESET_TYPE_WARM_START          0xBB        // OOB, and possibly POR from D3 cold
    u32_t                        :1; 
    u32_t    DellOemCmdSupport   :1;
    u32_t                        :12;
} PackageState_t;
#endif // ENDIAN

/*****************************************************************************


*****************************************************************************/
#define UMP_SELECTION_STATE_DESELECTED    FALSE
#define UMP_SELECTION_STATE_SELECTED      TRUE

typedef struct NcsiPersistentData
{

    UmpDebugData_t          Debug;                      // 76 bytes
    u32_t                PackageId;                  // 92

    pNcsiChannelData_t      pChannelSpecific[PATH_SUPPORTED * PORT_MAX]; //8 bytes  
    
    PackageState_t          PackageState;               // 132 bytes
    NcsiChannelData_t       ChannelData[PORT_MAX];                // 420 bytes total  288 bytes (2 data blocks)
    HostSrcMacBuff_t    *   pHostSrcBuff;                                                   
} NcsiPersistentData_t;                                 // 284 bytes total


#if defined (BIG_ENDIAN)
typedef NcsiPersistentData_t* pNcsiPersistentData_t;
#else
// define pointer as 32-bit value to ease diag encoding
typedef u32_t            pNcsiPersistentData_t;
#endif

#define   pNcsiPersistentData ((NcsiPersistentData_t *)&SHMEM(PATH_0)->mgmtfw_state)

typedef enum NcsiLibraryEntryType
{
    
    NCSI_MAIN_LIB_MCP_SHARED_MEM_POINTER    = 0         ,
    NCSI_MAIN_LIB_MCP_REG_POINTER                       ,
    NCSI_MAIN_LIB_MEM_FILL                              ,
    NCSI_MAIN_LIB_MEM_CMP                               ,
    NCSI_MAIN_LIB_MEM_COPY_BYTES                        ,
    NCSI_MAIN_LIB_DELAY_US                              ,
    NCSI_MAIN_LIB_FW_HACK                               ,
    NCSI_MAIN_LIB_GET_LINK_STATUS_WORD                  ,
    NCSI_MAIN_LIB_GET_OS_STATUS_WORD                    ,
    NCSI_MAIN_LIB_GET_PORT_RESET_STATUS                 ,
    NCSI_MAIN_LIB_HANDLE_PORT_RESET                     ,
    
    NCSI_MAIN_LIB_GET_LOW_POWER_LINK_FLAG               ,
    NCSI_MAIN_LIB_SET_LOW_POWER_LINK_FLAG               ,
    NCSI_MAIN_LIB_SET_OS_STATUS_FLAG                    ,

    
    NCSI_RX_LIB_COMPLETE_EGRESS_PACKET_TRANSFER         ,
    NCSI_RX_LIB_ALLOCATE_EGRESS_BUFFER                  ,
    NCSI_RX_LIB_INITIALIZE_CHANNEL_RESOURCES            ,
    NCSI_RX_LIB_INITIALIZE                              ,

    NCSI_TX_LIB_INITIALIZE                              ,
    NCSI_TX_LIB_GET_INGRESS_BUFFER_ADDRESS              ,
    NCSI_TX_LIB_FREE_INGRESS_PACKET_BUFFER              ,
    NCSI_TX_LIB_VALIDATE_INGRESS_PACKET             ,
    
    NCSI_CMD_LIB_INITIALIZE                             ,
    NCSI_CMD_LIB_DISABLE_VLAN_FILTER                    ,             
    NCSI_CMD_LIB_ENABLE_VLAN_FILTER                     ,                                 
    NCSI_CMD_LIB_SET_VLAN_MODE                          ,                                 
    NCSI_CMD_LIB_DISABLE_VLAN                           ,                                 
    NCSI_CMD_LIB_GET_UPDATED_STATISTICS        ,                                        
    NCSI_CMD_LIB_ENABLE_CHANNEL                         ,
    NCSI_CMD_LIB_ENABLE_BROADCAST_PACKET_FILTERING      ,
    NCSI_CMD_LIB_DISABLE_BROADCAST_PACKET_FILTERING     ,
    NCSI_CMD_LIB_DISABLE_MULTICAST_PACKET_FILTERING     ,
    NCSI_CMD_LIB_ENABLE_MULTICAST_PACKET_FILTERING      ,
    NCSI_CMD_LIB_SET_MAC_ADDRESS                        ,
    NCSI_CMD_LIB_DISABLE_CHANNEL                        ,
    NCSI_CMD_LIB_CLEAR_MAC_ADDRESS                      ,

#if 0
    NCSI_CMD_LIB_GET_PCI_DEVICE_ID                      ,
    NCSI_CMD_LIB_GET_PCI_VENDOR_ID                      ,
    NCSI_CMD_LIB_GET_PCI_SUBSYSTEM_ID                   ,
    NCSI_CMD_LIB_GET_PCI_SUBSYSTEMVENDOR_ID             ,
    NCSI_CMD_LIB_GET_HOST_MAC_ADDRESS                   ,
    NCSI_CMD_LIB_GET_GET_BC_REV                         ,

#else
    NCSI_CMD_LIB_GET_NCSI_PARAMETER                     ,
#endif

    NCSI_CMD_LIB_SET_LINK                               ,
    NCSI_CMD_LIB_GET_LINK_STATUS                        ,
    NCSI_CMD_LIB_SET_VIRTUAL_MAC_ADDRESS                ,
    NCSI_LIB_SIZE

}NcsiLibraryEntry_t;




extern u32_t NcsiMain_Mem_Cmp                    (pu8_t, pu8_t, u32_t);
extern void     NcsiMain_Delay_Usec                 (u32_t);
extern void     NcsiMain_Mem_Fill                   (u8_t, pu8_t, u32_t);
extern void     NcsiMain_Mem_Copy_Bytes             (pu8_t, pu8_t, u32_t);

#endif




