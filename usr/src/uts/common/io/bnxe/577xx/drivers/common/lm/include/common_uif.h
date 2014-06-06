#ifndef _COMMON_UIF_H
#define _COMMON_UIF_H

/*  
I M P O R T A N T 
BEFORE YOU MODIFY THESE STRUCTS:
please make sure that DIAG was updated accordingly.
windiag\ediag should be checked to compile and run correctly
modification is in file: tcl_driver.c,  function: driver_init_stats_object,  macros: REGISTER_STAT_FIELD
*/


/*******************************************************************************
 * Hardware statistics structure for B10_IOC_GET_L2_CHIP_STATISTICS
 ******************************************************************************/    
typedef struct _b10_l2_chip_statistics_t
{
    u64_t ver_num;
    #define L2_CHIP_STATISTICS_VER_NUM_1 1
    #define L2_CHIP_STATISTICS_VER_NUM_2 2
    #define L2_CHIP_STATISTICS_VER_NUM_3 3
    u64_t  IfHCInOctets;
    u64_t  IfHCInBadOctets;
    u64_t  IfHCOutOctets;
    u64_t  IfHCOutBadOctets;
    u64_t  IfHCOutPkts ;
    u64_t  IfHCInPkts ;
    u64_t  IfHCInUcastPkts;
    u64_t  IfHCInMulticastPkts;
    u64_t  IfHCInBroadcastPkts;
    u64_t  IfHCOutUcastPkts;
    u64_t  IfHCOutMulticastPkts;
    u64_t  IfHCOutBroadcastPkts;
    u64_t  IfHCInUcastOctets ;
    u64_t  IfHCInMulticastOctets ;
    u64_t  IfHCInBroadcastOctets ;
    u64_t  IfHCOutUcastOctets ;
    u64_t  IfHCOutMulticastOctets ;
    u64_t  IfHCOutBroadcastOctets ;
    u64_t  IfHCOutDiscards ;
    u64_t  IfHCInFalseCarrierErrors ;
    u64_t  Dot3StatsInternalMacTransmitErrors;
    u64_t  Dot3StatsCarrierSenseErrors;
    u64_t  Dot3StatsFCSErrors;
    u64_t  Dot3StatsAlignmentErrors;
    u64_t  Dot3StatsSingleCollisionFrames;
    u64_t  Dot3StatsMultipleCollisionFrames;
    u64_t  Dot3StatsDeferredTransmissions;
    u64_t  Dot3StatsExcessiveCollisions;
    u64_t  Dot3StatsLateCollisions;
    u64_t  EtherStatsCollisions;
    u64_t  EtherStatsFragments;
    u64_t  EtherStatsJabbers;
    u64_t  EtherStatsUndersizePkts;
    u64_t  EtherStatsOverrsizePkts;
    u64_t  EtherStatsPktsTx64Octets;
    u64_t  EtherStatsPktsTx65Octetsto127Octets;
    u64_t  EtherStatsPktsTx128Octetsto255Octets;
    u64_t  EtherStatsPktsTx256Octetsto511Octets;
    u64_t  EtherStatsPktsTx512Octetsto1023Octets;
    u64_t  EtherStatsPktsTx1024Octetsto1522Octets;
    u64_t  EtherStatsPktsTxOver1522Octets;
    u64_t  XonPauseFramesReceived;
    u64_t  XoffPauseFramesReceived;
    u64_t  OutXonSent;                                 
    u64_t  OutXoffSent;                             
    u64_t  FlowControlDone;
    u64_t  MacControlFramesReceived;
    u64_t  XoffStateEntered;
    u64_t  IfInFramesL2FilterDiscards;
    u64_t  IfInTTL0Discards ;
    u64_t  IfInxxOverflowDiscards ;
    u64_t  IfInMBUFDiscards;
    u64_t  IfInErrors;
    u64_t  IfInErrorsOctets;
    u64_t  IfInNoBrbBuffer;
    //u64_t  Reserved0 ;
    //u64_t  Reserved1 ;
    //u64_t  Reserved2 ;
    //u64_t  Reserved3 ;

    // Nig statistics
    u64_t  Nig_brb_packet             ;
    u64_t  Nig_brb_truncate           ;
    u64_t  Nig_flow_ctrl_discard      ;
    u64_t  Nig_flow_ctrl_octets       ;
    u64_t  Nig_flow_ctrl_packet       ;
    u64_t  Nig_mng_discard            ;
    u64_t  Nig_mng_octet_inp          ;
    u64_t  Nig_mng_octet_out          ;
    u64_t  Nig_mng_packet_inp         ;
    u64_t  Nig_mng_packet_out         ;
    u64_t  Nig_pbf_octets             ;
    u64_t  Nig_pbf_packet             ;
    u64_t  Nig_safc_inp               ;

} b10_l2_chip_statistics_t;

typedef struct _b10_l2_chip_statistics_v2_t
{
    struct _b10_l2_chip_statistics_t v1;

    struct _v2
    {
        u64_t Tx_lpi_count;			// This counter counts the number of timers the debounced version of EEE link idle is asserted”
    } v2;

} b10_l2_chip_statistics_v2_t;

typedef struct _b10_l2_chip_statistics_v3_t
{
    struct  _b10_l2_chip_statistics_v2_t v2;
    struct _v3
    {
        u64_t   coalesced_pkts        /* the number of packets coalesced in all aggregations */;
        u64_t   coalesced_bytes       /* the number of bytes coalesced in all aggregations */;
        u64_t   coalesced_events      /* the number of aggregations */;
        u64_t   coalesced_aborts      /* the number of exception which avoid aggregation */;
    } v3;
    
} b10_l2_chip_statistics_v3_t;


/*******************************************************************************
 * Hardware statistics structure for B10_IOC_GET_L4_CHIP_STATISTICS
 ******************************************************************************/    
typedef struct _b10_l4_chip_statistics_t
{    
    u64_t ver_num;
    #define L4_CHIP_STATISTISTCS_VER_NUM 1
    u64_t NoTxCqes ;
    u64_t InTCP4Segments ;
    u64_t OutTCP4Segments ;
    u64_t RetransmittedTCP4Segments ;
    u64_t InTCP4Errors ;
    u64_t InIP4Receives ; 
    u64_t InIP4HeaderErrors ;
    u64_t InIP4Discards ;
    u64_t InIP4Delivers ;
    u64_t InIP4Octets ;
    u64_t OutIP4Octets ;
    u64_t InIP4TruncatedPackets ;
    u64_t InTCP6Segments ;
    u64_t OutTCP6Segments ;
    u64_t RetransmittedTCP6Segments ;
    u64_t InTCP6Errors ;
    u64_t InIP6Receives ; 
    u64_t InIP6HeaderErrors ;
    u64_t InIP6Discards ;
    u64_t InIP6Delivers ;
    u64_t InIP6Octets ;
    u64_t OutIP6Octets ;
    u64_t InIP6TruncatedPackets ;
    //u64_t Reserved0 ;
    //u64_t Reserved1 ;
    //u64_t Reserved2 ;
    //u64_t Reserved3 ;

} b10_l4_chip_statistics_t;

/*******************************************************************************
 * Driver statistics structure for B10_IOC_GET_L2_DRIVER_STATISTICS
 ******************************************************************************/    
typedef struct _b10_l2_driver_statistics_t
{
    u64_t ver_num;
    #define L2_DRIVER_STATISTISTCS_VER_NUM 1
    u64_t RxIPv4FragCount;
    u64_t RxIpCsErrorCount;
    u64_t RxTcpCsErrorCount;
    u64_t RxLlcSnapCount;
    u64_t RxPhyErrorCount;
    u64_t RxIpv6ExtCount;
    u64_t TxNoL2Bd;
    u64_t TxNoSqWqe;
    u64_t TxL2AssemblyBufUse;
    //u64_t Reserved0 ;
    //u64_t Reserved1 ;
    //u64_t Reserved2 ;
    //u64_t Reserved3 ;
} b10_l2_driver_statistics_t;

/*******************************************************************************
 * Driver statistics structure for B10_IOC_GET_L4_DRIVER_STATISTICS
 ******************************************************************************/    

typedef struct _b10_l4_driver_statistics_t
{
    u64_t ver_num;
    #define L4_DRIVER_STATISTISTCS_VER_NUM 1
    u64_t CurrentlyIpv4Established ;
    u64_t OutIpv4Resets ;
    u64_t OutIpv4Fin ;
    u64_t InIpv4Reset ;
    u64_t InIpv4Fin ;
    u64_t CurrentlyIpv6Established ;
    u64_t OutIpv6Resets ;
    u64_t OutIpv6Fin ;
    u64_t InIpv6Reset ;
    u64_t InIpv6Fin ;
    u64_t RxIndicateReturnPendingCnt;
    u64_t RxIndicateReturnDoneCnt;
    u64_t RxActiveGenBufCnt;
    u64_t TxNoL4Bd;
    u64_t TxL4AssemblyBufUse ;
    //u64_t Reserved0 ;
    //u64_t Reserved1 ;
    //u64_t Reserved2 ;
    //u64_t Reserved3 ;

} b10_l4_driver_statistics_t;

/*******************************************************************************
 * Driver statistics structure for B10_IOC_GET_DRIVER_STATISTICS.
 ******************************************************************************/
typedef struct _b10_driver_statistics_t
{
    u64_t ver_num;
    #define DRIVER_STATISTISTCS_VER_NUM 1
    u64_t tx_lso_frames;        // supported
    u64_t tx_aborted;           // supported
    u64_t tx_no_bd;
    u64_t tx_no_desc;
    u64_t tx_no_coalesce_buf;   // supported
    u64_t tx_no_map_reg;
    u64_t rx_aborted;           // supported
    u64_t rx_err;
    u64_t rx_crc;
    u64_t rx_phy_err;
    u64_t rx_alignment;
    u64_t rx_short_packet;
    u64_t rx_giant_packet;
    //u64_t Reserved0 ;
    //u64_t Reserved1 ;
    //u64_t Reserved2 ;
    //u64_t Reserved3 ;
} b10_driver_statistics_t;


#define DCBX_CONFIG_INV_VALUE            (0xFFFFFFFF)
enum
{
    OVERWRITE_SETTINGS_DISABLE  = 0,
    OVERWRITE_SETTINGS_ENABLE   = 1,
    OVERWRITE_SETTINGS_INVALID  = DCBX_CONFIG_INV_VALUE
};
/*******************************************************************************
 * LLDP protocol registry configuration parameters.
 ******************************************************************************/
typedef struct _config_lldp_params_t 
{
    u32_t   overwrite_settings;
    u32_t   msg_tx_hold;
    u32_t   msg_fast_tx;
    u32_t   tx_credit_max; 
    u32_t   msg_tx_interval;
    u32_t   tx_fast;
}config_lldp_params_t;

/*******************************************************************************
 * LLDP structure for B10_IOC_GET_LLDP_PARAMS.
 ******************************************************************************/
typedef struct _b10_lldp_params_get_t
{
    u32_t ver_num;
    #define LLDP_PARAMS_VER_NUM 2
    config_lldp_params_t config_lldp_params;
    // The reserved field should follow in case the struct above will increase
    u32_t _reserved[50];
    u32_t 	admin_status;
        #define LLDP_TX_ONLY  0x01
        #define LLDP_RX_ONLY  0x02
        #define LLDP_TX_RX    0x03
        #define LLDP_DISABLED 0x04
    u32_t   remote_chassis_id[65];
    u32_t   remote_port_id[65];
    u32_t   local_chassis_id[2];
    u32_t   local_port_id[2];
}b10_lldp_params_get_t;


/*******************************************************************************
 * DCBX protocol registry configuration parameters.
 ******************************************************************************/

typedef struct _admin_priority_app_table_t 
{
    u32_t valid;
    u32_t priority;
#define INVALID_TRAFFIC_TYPE_PRIORITY                  (0xFFFFFFFF)
    u32_t traffic_type;
    #define TRAFFIC_TYPE_ETH    0
    #define TRAFFIC_TYPE_PORT   1
    u32_t app_id;
}admin_priority_app_table_t;

typedef struct _config_dcbx_params_t 
{
    u32_t dcb_enable;
    u32_t admin_dcbx_enable;
    // "admin_dcbx_enable" and "dcb_enable" are stand alone registry keys(if present
    // will always be valid and not ignored), for all other DCBX registry set only 
    // if the entire DCBX registry set is present and differ from 0xFFFFFFFF (invalid
    // value) the DCBX registry parameters are taken, otherwise the registry key set
    // is ignored.)(Expect "admin_dcbx_enable" and "dcb_enable")
    u32_t overwrite_settings;
    u32_t admin_dcbx_version;
    #define ADMIN_DCBX_VERSION_CEE 0
    #define ADMIN_DCBX_VERSION_IEEE 1
    u32_t admin_ets_enable;
    u32_t admin_pfc_enable;
    u32_t admin_tc_supported_tx_enable;
    u32_t admin_ets_configuration_tx_enable;
    u32_t admin_ets_recommendation_tx_enable;
    u32_t admin_pfc_tx_enable;
    u32_t admin_application_priority_tx_enable;
    u32_t admin_ets_willing;
    u32_t admin_ets_reco_valid;
    u32_t admin_pfc_willing;
    u32_t admin_app_priority_willing;
    u32_t admin_configuration_bw_percentage[8];
    u32_t admin_configuration_ets_pg[8];
    u32_t admin_recommendation_bw_percentage[8];
    u32_t admin_recommendation_ets_pg[8];
    u32_t admin_pfc_bitmap;

    admin_priority_app_table_t admin_priority_app_table[4];
    u32_t admin_default_priority;
}config_dcbx_params_t;


/*******************************************************************************
 * DCBX structure for B10_IOC_GET_DCBX_PARAMS.
 ******************************************************************************/
typedef struct _b10_dcbx_params_get_t
{
    u32_t ver_num;
    #define DCBX_PARAMS_VER_NUM 4
    config_dcbx_params_t config_dcbx_params;
    // The reserved field should follow in case the struct above will increase
    u32_t _reserved[49];

    u32_t dcb_current_oper_state_bitmap;
    #define DCBX_CURRENT_STATE_IS_SYNC                  (1 << 0)
    #define PFC_IS_CURRENTLY_OPERATIONAL                (1 << 1)
    #define ETS_IS_CURRENTLY_OPERATIONAL                (1 << 2)
    #define PRIORITY_TAGGING_IS_CURRENTLY_OPERATIONAL   (1 << 3)
    #define DRIVER_CONFIGURED_BY_OS_QOS                 (1 << 4)
    #define DRIVER_CONFIGURED_BY_OS_QOS_TO_WILLING      (1 << 5)


    u32_t local_tc_supported;
    u32_t local_pfc_caps;
    u32_t remote_tc_supported;
    u32_t remote_pfc_cap;
    u32_t remote_ets_willing;
    u32_t remote_ets_reco_valid;
    u32_t remote_pfc_willing;
    u32_t remote_app_priority_willing;
    u32_t remote_configuration_bw_percentage[8];
    u32_t remote_configuration_ets_pg[8];
    u32_t remote_recommendation_bw_percentage[8];
    u32_t remote_recommendation_ets_pg[8];
    u32_t remote_pfc_bitmap;
    admin_priority_app_table_t remote_priority_app_table[16];
    u32_t local_ets_enable;
    u32_t local_pfc_enable;
    u32_t local_configuration_bw_percentage[8];
    u32_t local_configuration_ets_pg[8];
    u32_t local_pfc_bitmap;
    admin_priority_app_table_t local_priority_app_table[16];
    u32_t pfc_mismatch;
    u32_t priority_app_mismatch;
    u32_t dcbx_frames_sent;
    u32_t dcbx_frames_received;
    u64_t pfc_frames_sent;
    u64_t pfc_frames_received;
}b10_dcbx_params_get_t;

/*******************************************************************************
 * Transceiver Data B10_IOC_GET_TRANSCEIVER_DATA
 ******************************************************************************/

typedef struct _b10_transceiver_data_t
{
    u8_t ver_num;
    #define TRANSCEIVER_DATA_VER_NUM   1

    u8_t _pad[3];

    // NOTE: All these strings are ASCII buffers without trailing NULL '\0'

    u8_t vendor_name[16];  // ELINK_SFP_EEPROM_VENDOR_NAME_ADDR
    u8_t model_num[16];    // ELINK_SFP_EEPROM_PART_NO_ADDR
    u8_t serial_num[16];   // ELINK_SFP_EEPROM_SERIAL_ADDR
    u8_t revision_num[4];  // ELINK_SFP_EEPROM_REVISION_ADDR
    u8_t mfg_date[6];      // ELINK_SFP_EEPROM_DATE_ADDR

    u8_t _pad_[2];

    u32_t reserved[40];

} b10_transceiver_data_t;

#endif // _COMMON_UIF_H
