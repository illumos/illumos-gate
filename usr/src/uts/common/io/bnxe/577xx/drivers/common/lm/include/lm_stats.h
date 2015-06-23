/*******************************************************************************
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
 * Module Description:
 *
 *
 * History:
 *    02/05/07 Alon Elhanani    Inception.
 ******************************************************************************/

#ifndef _LM_STATS_H
#define _LM_STATS_H

#include "common_uif.h"
#include "mac_stx.h"

/*******************************************************************************
 * Forward definition.
 ******************************************************************************/
/* structure for DCBX statistic */
struct _lm_dcbx_stat;

// defines
#define DMAE_SGL_STATS_NUM_OF_EMAC_COMMANDS   4 // includes NIG (3+1(nig)=4)
#define DMAE_SGL_STATS_NUM_OF_BIGMAC_COMMANDS 3 // includes NIG (2+1(nig)=3)
#define DMAE_SGL_STATS_NUM_OF_MSTAT_COMMANDS  3 // MSTAT requires 2 DMAE transactions (Rx/Tx) + 1 for the NIG stats

#define LM_STATS_FW_DONE_FLAG                   0xffffffff
#define MAX_STATS_TIMER_WAKEUP_NO_COMPLETION    50  // Might be a real problem with SW/FW HSI
#define MAX_STATS_TIMER_WAKEUP_COMP_NOT_HANDLED 600 // probably due to DPC starvation by the OS, this timeout can be large (currently 5 minutes)

#define HAS_MSTAT(_pdev) CHIP_IS_E3(_pdev)

typedef enum
{
    STATS_MACS_IDX_CURRENT = 0,
    STATS_MACS_IDX_TOTAL   = 1,
    STATS_MACS_IDX_MAX     = 2
} stats_macs_idx_t;

#define STATS_IP_4_IDX                        0
#define STATS_IP_6_IDX                        1
#define STATS_IP_IDX_MAX                      2


// converts reg_pair_t to u64_t
#define REGPAIR_TO_U64( val_64, val_regpair ) val_64 = ((u64_t)(mm_le32_to_cpu(val_regpair.hi))<<32) + mm_le32_to_cpu(val_regpair.lo) ;


#define LM_STATS_HW_GET_MACS_U64(_pdev, field_name) ( _pdev->vars.stats.stats_mirror.stats_hw.macs[STATS_MACS_IDX_TOTAL].field_name )


// LM_STATS_FLAGS_XXX defines
#define LM_STATS_FLAG_XSTORM 0x0001
#define LM_STATS_FLAG_TSTORM 0x0002
#define LM_STATS_FLAG_USTORM 0x0020
#define LM_STATS_FLAG_CSTORM 0x0100

#define LM_STATS_FLAGS_ALL (LM_STATS_FLAG_XSTORM | LM_STATS_FLAG_TSTORM | LM_STATS_FLAG_USTORM | LM_STATS_FLAG_CSTORM )

// Check that done flags are set
#define LM_STATS_REGPAIR_CHECK_DONE(done_regpair) (( LM_STATS_FW_DONE_FLAG == done_regpair.lo ) && \
                                                   ( LM_STATS_FW_DONE_FLAG == done_regpair.hi ))

#define LM_STATS_VERIFY_COUNTER(_pdev, _counter ) ( _pdev->vars.stats.stats_collect.stats_fw.drv_counter == mm_le16_to_cpu(pdev->vars.stats.stats_collect.stats_fw._counter) )



// Check that done flags are set
#define LM_STATS_REGPAIR_CLEAR_DONE(done_regpair) done_regpair.lo = done_regpair.hi = 0 ;


// Do we need to assign (done is true assigned is false)
#define LM_STATS_DO_ASSIGN(flag_done, flag_assigned, flag_type)  ( 0 == GET_FLAGS(flag_assigned,flag_type) && \
                                                                   0 != GET_FLAGS(flag_done,flag_type) )
// do we need to assign any of the flags
#define LM_STATS_DO_ASSIGN_ANY(flag_done, flag_assigned) ( LM_STATS_DO_ASSIGN(flag_done,flag_assigned,LM_STATS_FLAG_XSTORM) || \
                                                           LM_STATS_DO_ASSIGN(flag_done,flag_assigned,LM_STATS_FLAG_TSTORM) || \
                                                           LM_STATS_DO_ASSIGN(flag_done,flag_assigned,LM_STATS_FLAG_USTORM) || \
                                                           LM_STATS_DO_ASSIGN(flag_done,flag_assigned,LM_STATS_FLAG_CSTORM) )
// mapping of client id to statistics entry
// the imporance of this macro is that it'll return a unique number per function.
#define LM_STATS_CNT_ID(_pdev) (IS_VFDEV(_pdev) ? (_pdev)->params.base_fw_stats_id : FUNC_ID(_pdev))

// Functions prototypes
void        lm_stats_on_timer  ( struct _lm_device_t* pdev) ;
lm_status_t lm_stats_dmae      ( struct _lm_device_t* pdev) ;
lm_status_t lm_stats_hw_setup  ( struct _lm_device_t* pdev) ;
void        lm_stats_fw_setup  ( struct _lm_device_t* pdev) ;
void        lm_stats_fw_reset  ( struct _lm_device_t* pdev) ;
lm_status_t lm_stats_alloc_fw_resc (struct _lm_device_t *pdev);
lm_status_t lm_stats_alloc_resc( struct _lm_device_t* pdev) ;
lm_status_t lm_stats_on_link_update( struct _lm_device_t *pdev, const u8_t b_is_link_up );

void        lm_stats_fw_assign ( struct _lm_device_t* pdev, IN u32_t stats_flags_done, OUT u32_t* ptr_stats_flags_assigned ) ;

#ifdef VF_INVOLVED
void        lm_pf_stats_vf_fw_assign(struct _lm_device_t *pdev, u32_t stats_flags_done, u32_t* ptr_stats_flags_assigned);
#endif

void        lm_stats_hw_assign ( struct _lm_device_t* pdev ) ;
void        lm_stats_fw_check_update_done( struct _lm_device_t *pdev, OUT u32_t* ptr_stats_flags_done ) ;
lm_status_t lm_stats_fw_complete( struct _lm_device_t *pdev  ) ;
void        lm_stats_mgmt_assign( IN struct _lm_device_t* pdev ) ;
lm_status_t lm_stats_drv_info_to_mfw_assign( struct _lm_device_t *pdev, const enum drv_info_opcode drv_info_op );


void        lm_stats_get_dcb_stats      ( IN struct _lm_device_t* pdev, OUT struct _lm_dcbx_stat *stats ) ;
void        lm_stats_get_driver_stats   ( IN struct _lm_device_t* pdev, OUT b10_driver_statistics_t *stats ) ;
void        lm_stats_get_l2_driver_stats( IN struct _lm_device_t* pdev, OUT b10_l2_driver_statistics_t *stats ) ;
void        lm_stats_get_l4_driver_stats( IN struct _lm_device_t* pdev, OUT b10_l4_driver_statistics_t *stats ) ;
void        lm_stats_get_l2_chip_stats  ( IN struct _lm_device_t* pdev, OUT void *stats, u8_t version ) ;
void        lm_stats_get_l4_chip_stats  ( IN struct _lm_device_t* pdev, OUT b10_l4_chip_statistics_t *stats ) ;
void        lm_stats_hw_config_stats    ( struct _lm_device_t* pdev, u8_t b_enabled ) ;
void        lm_stats_fw_config_stats    ( struct _lm_device_t* pdev, u8_t b_enabled ) ;
void        lm_stats_init_port_part     ( IN struct _lm_device_t* pdev );
void        lm_stats_init_func_part     ( IN struct _lm_device_t* pdev );

lm_status_t lm_stats_on_pmf_update( struct _lm_device_t* pdev, IN u8_t b_on ) ;
lm_status_t lm_stats_on_pmf_init( struct _lm_device_t* pdev ) ;

lm_status_t lm_stats_drv_info_to_mfw_event( struct _lm_device_t* pdev ) ;

#ifdef VF_INVOLVED
void        lm_stats_prep_vf_fw_stats_req( struct _lm_device_t* pdev );
#endif

// hw statistics structures (as read from GRC)

// bmac
struct _stats_bmac1_query_t
{
    struct
    {
    u64_t tx_gtpkt   ;
    u64_t tx_gtxpf   ;
    u64_t tx_gtfcs   ;
    u64_t tx_gtmca   ;
    u64_t tx_gtgca   ;
    u64_t tx_gtfrg   ;
    u64_t tx_gtovr   ;
    u64_t tx_gt64    ;
    u64_t tx_gt127   ;
    u64_t tx_gt255   ;
    u64_t tx_gt511   ;
    u64_t tx_gt1023  ;
    u64_t tx_gt1518  ;
    u64_t tx_gt2047  ;
    u64_t tx_gt4095  ;
    u64_t tx_gt9216  ;
    u64_t tx_gt16383 ;
    u64_t tx_gtmax   ;
    u64_t tx_gtufl   ;
    u64_t tx_gterr   ;
    u64_t tx_gtbyt   ; // 42 bit
    } stats_tx ;
    struct
    {
    u64_t rx_gr64    ;
    u64_t rx_gr127   ;
    u64_t rx_gr255   ;
    u64_t rx_gr511   ;
    u64_t rx_gr1023  ;
    u64_t rx_gr1518  ;
    u64_t rx_gr2047  ;
    u64_t rx_gr4095  ;
    u64_t rx_gr9216  ;
    u64_t rx_gr16383 ;
    u64_t rx_grmax   ;
    u64_t rx_grpkt   ;
    u64_t rx_grfcs   ;
    u64_t rx_grmca   ;
    u64_t rx_grbca   ;
    u64_t rx_grxcf   ;
    u64_t rx_grxpf   ;
    u64_t rx_grxuo   ;
    u64_t rx_grjbr   ;
    u64_t rx_grovr   ;
    u64_t rx_grflr   ;
    u64_t rx_grmeg   ;
    u64_t rx_grmeb   ;
    u64_t rx_grbyt   ; // 42 bit
    u64_t rx_grund   ;
    u64_t rx_grfrg   ;
    u64_t rx_grerb   ;
    u64_t rx_grfre   ; // 42 bit
    u64_t rx_gripj   ; // 42 bit
    } stats_rx ;
}; //stats_bmac_query_t

// bmac2
struct _stats_bmac2_query_t
{
    struct
    {
    u64_t tx_gtpkt   ; // tx_itpok
    u64_t tx_gtxpf   ;
    u64_t tx_gtxpp   ; // NEW BMAC2
    u64_t tx_gtfcs   ;
    u64_t tx_gtuca   ; // NEW BMAC2
    u64_t tx_gtmca   ;
    u64_t tx_gtgca   ;
    u64_t tx_gtovr   ; // SWAPPED with below in BMAC1
    u64_t tx_gtfrg   ;
    u64_t tx_itpkt   ; // NEW BMAC2
    u64_t tx_gt64    ;
    u64_t tx_gt127   ;
    u64_t tx_gt255   ;
    u64_t tx_gt511   ;
    u64_t tx_gt1023  ;
    u64_t tx_gt1518  ;
    u64_t tx_gt2047  ;
    u64_t tx_gt4095  ;
    u64_t tx_gt9216  ;
    u64_t tx_gt16383 ;
    u64_t tx_gtmax   ;
    u64_t tx_gtufl   ;
    u64_t tx_gterr   ;
    u64_t tx_gtbyt   ; // 42 bit
    } stats_tx ;
    struct
    {
    u64_t rx_gr64    ;
    u64_t rx_gr127   ;
    u64_t rx_gr255   ;
    u64_t rx_gr511   ;
    u64_t rx_gr1023  ;
    u64_t rx_gr1518  ;
    u64_t rx_gr2047  ;
    u64_t rx_gr4095  ;
    u64_t rx_gr9216  ;
    u64_t rx_gr16383 ;
    u64_t rx_grmax   ;
    u64_t rx_grpkt   ;
    u64_t rx_grfcs   ;
    u64_t rx_gruca   ; // NEW BMAC2
    u64_t rx_grmca   ;
    u64_t rx_grbca   ;
    //u64_t rx_grxcf   ; // MOVED BMAC2
    u64_t rx_grxpf   ;
    u64_t rx_grxpp   ; // NEW BMAC2
    u64_t rx_grxuo   ;
    u64_t rx_grjbr   ;
    u64_t rx_grovr   ;
    u64_t rx_grxcf   ; // MOVED BMAC2
    u64_t rx_grflr   ;
    u64_t rx_grpok   ; // NEW BMAC2
    u64_t rx_grmeg   ;
    u64_t rx_grmeb   ;
    u64_t rx_grbyt   ; // 42 bit
    u64_t rx_grund   ;
    u64_t rx_grfrg   ;
    u64_t rx_grerb   ;
    u64_t rx_grfre   ; // 42 bit - BMAC2: IRERPKT
    u64_t rx_gripj   ; // 42 bit - BMAC2: IRJUNK
    } stats_rx ;
}; //stats_bmac_query_t

// emac
struct _stats_emac_query_t
{
    struct
{
    u32_t rx_stat_ifhcinoctets                        ;
    u32_t rx_stat_ifhcinbadoctets                     ;
    u32_t rx_stat_etherstatsfragments                 ;
    u32_t rx_stat_ifhcinucastpkts                     ;
    u32_t rx_stat_ifhcinmulticastpkts                 ;
    u32_t rx_stat_ifhcinbroadcastpkts                 ;
    u32_t rx_stat_dot3statsfcserrors                  ;
    u32_t rx_stat_dot3statsalignmenterrors            ;
    u32_t rx_stat_dot3statscarriersenseerrors         ;
    u32_t rx_stat_xonpauseframesreceived              ;
    u32_t rx_stat_xoffpauseframesreceived             ;
    u32_t rx_stat_maccontrolframesreceived            ;
    u32_t rx_stat_xoffstateentered                    ;
    u32_t rx_stat_dot3statsframestoolong              ;
    u32_t rx_stat_etherstatsjabbers                   ;
    u32_t rx_stat_etherstatsundersizepkts             ;
    u32_t rx_stat_etherstatspkts64octets              ;
    u32_t rx_stat_etherstatspkts65octetsto127octets   ;
    u32_t rx_stat_etherstatspkts128octetsto255octets  ;
    u32_t rx_stat_etherstatspkts256octetsto511octets  ;
    u32_t rx_stat_etherstatspkts512octetsto1023octets ;
    u32_t rx_stat_etherstatspkts1024octetsto1522octets;
    u32_t rx_stat_etherstatspktsover1522octets        ;
    } stats_rx ;
    struct
    {
    u32_t rx_stat_falsecarriererrors                  ;
    } stats_rx_err ;
    struct
    {
    u32_t tx_stat_ifhcoutoctets                       ;
    u32_t tx_stat_ifhcoutbadoctets                    ;
    u32_t tx_stat_etherstatscollisions                ;
    u32_t tx_stat_outxonsent                          ;
    u32_t tx_stat_outxoffsent                         ;
    u32_t tx_stat_flowcontroldone                     ;
    u32_t tx_stat_dot3statssinglecollisionframes      ;
    u32_t tx_stat_dot3statsmultiplecollisionframes    ;
    u32_t tx_stat_dot3statsdeferredtransmissions      ;
    u32_t tx_stat_dot3statsexcessivecollisions        ;
    u32_t tx_stat_dot3statslatecollisions             ;
    u32_t tx_stat_ifhcoutucastpkts                    ;
    u32_t tx_stat_ifhcoutmulticastpkts                ;
    u32_t tx_stat_ifhcoutbroadcastpkts                ;
    u32_t tx_stat_etherstatspkts64octets              ;
    u32_t tx_stat_etherstatspkts65octetsto127octets   ;
    u32_t tx_stat_etherstatspkts128octetsto255octets  ;
    u32_t tx_stat_etherstatspkts256octetsto511octets  ;
    u32_t tx_stat_etherstatspkts512octetsto1023octets ;
    u32_t tx_stat_etherstatspkts1024octetsto1522octet ;
    u32_t tx_stat_etherstatspktsover1522octets        ;
    u32_t tx_stat_dot3statsinternalmactransmiterrors  ;
    } stats_tx ;

}; // stats_emac_query_t

struct _stats_mstat_query_t
{
    struct {
        u64_t tx_gtxpok  ; ///NOTE MSTAT on E3 has a bug where this register's contents are actually tx_gtxpok + tx_gtxpf + (possibly)tx_gtxpp
        u64_t tx_gtxpf   ;
        u64_t tx_gtxpp   ;
        u64_t tx_gtfcs   ;
        u64_t tx_gtuca   ;
        u64_t tx_gtmca   ;
        u64_t tx_gtgca   ;
        u64_t tx_gtpkt   ;
        u64_t tx_gt64    ;
        u64_t tx_gt127   ;
        u64_t tx_gt255   ;
        u64_t tx_gt511   ;
        u64_t tx_gt1023  ;
        u64_t tx_gt1518  ;
        u64_t tx_gt2047  ;
        u64_t tx_gt4095  ;
        u64_t tx_gt9216  ;
        u64_t tx_gt16383 ;
        u64_t tx_gtufl   ;
        u64_t tx_gterr   ;
        u64_t tx_gtbyt   ;

        u64_t tx_collisions;
        u64_t tx_singlecollision;
        u64_t tx_multiplecollisions;
        u64_t tx_deferred;
        u64_t tx_excessivecollisions;
        u64_t tx_latecollisions;
    }stats_tx;

    struct{
        u64_t rx_gr64    ;
        u64_t rx_gr127   ;
        u64_t rx_gr255   ;
        u64_t rx_gr511   ;
        u64_t rx_gr1023  ;
        u64_t rx_gr1518  ;
        u64_t rx_gr2047  ;
        u64_t rx_gr4095  ;
        u64_t rx_gr9216  ;
        u64_t rx_gr16383 ;
        u64_t rx_grpkt   ;
        u64_t rx_grfcs   ;
        u64_t rx_gruca   ;
        u64_t rx_grmca   ;
        u64_t rx_grbca   ;
        u64_t rx_grxpf   ;
        u64_t rx_grxpp   ;
        u64_t rx_grxuo   ;
        u64_t rx_grovr   ;
        u64_t rx_grxcf   ;
        u64_t rx_grflr   ;
        u64_t rx_grpok   ;
        u64_t rx_grbyt   ;
        u64_t rx_grund   ;
        u64_t rx_grfrg   ;
        u64_t rx_grerb   ;
        u64_t rx_grfre   ;

        u64_t rx_alignmenterrors;
        u64_t rx_falsecarrier;
        u64_t rx_llfcmsgcnt;
    }stats_rx;
};

// Nig
struct _stats_nig_query_t
{
    u32_t brb_discard       ;
    u32_t brb_packet        ;
    u32_t brb_truncate      ;
    u32_t flow_ctrl_discard ;
    u32_t flow_ctrl_octets  ;
    u32_t flow_ctrl_packet  ;
    u32_t mng_discard       ;
    u32_t mng_octet_inp     ;
    u32_t mng_octet_out     ;
    u32_t mng_packet_inp    ;
    u32_t mng_packet_out    ;
    u32_t pbf_octets        ;
    u32_t pbf_packet        ;
    u32_t safc_inp          ;
};

typedef struct _stats_nig_ex_t
{
    u64_t egress_mac_pkt0                             ; // Spec. 23
    u64_t egress_mac_pkt1                             ; // Spec. 24
} stats_nig_ex_t ;

typedef struct _misc_stats_t
{
    u64_t tx_lpi_count;
} misc_stats_t;

union _stats_bmac_query_t
{
    struct _stats_bmac1_query_t bmac1_stats;
    struct _stats_bmac2_query_t bmac2_stats;
};
typedef struct _lm_stats_hw_collect_t
{
    union{
        struct{
            volatile struct _stats_emac_query_t*   addr_emac_stats_query ;
            volatile struct _stats_bmac1_query_t*  addr_bmac1_stats_query ;
            volatile struct _stats_bmac2_query_t*  addr_bmac2_stats_query ;
        } s;
        volatile struct _stats_mstat_query_t*  addr_mstat_stats_query ;
    } u;
    volatile struct _stats_nig_query_t*    addr_nig_stats_query ;

    void*                                   non_emac_dmae_operation;
    void*                                   emac_dmae_operation;

    struct _stats_nig_ex_t                 nig_ex_stats_query ;
    u8_t                                   b_is_link_up ;
    u8_t                                   b_collect_enabled ; // enable collection?
    lm_address_t                           mac_stats_phys_addr; // physical address of the beginning of the MAC stats structure (either EMAC or MSTAT)
    lm_address_t                           bmac_stats_phys_addr; //physical address of the beginning of the MAC stats structure (BMAC1/BMAC2)
    lm_address_t                           nig_stats_phys_addr; // physical address of the beginning of the NIG stats structure

    struct _misc_stats_t                   misc_stats_query;

}lm_stats_hw_collect_t;

typedef struct _lm_stats_drv_info_to_mfw_t
{
    union
    {
        volatile  eth_stats_info_t*   eth_stats;
        volatile  fcoe_stats_info_t*  fcoe_stats ;
        volatile  iscsi_stats_info_t* iscsi_stats ;
    } addr;

    lm_address_t drv_info_to_mfw_phys_addr; // physical address of the beginning of the drv_info_to_mfw stats

} lm_stats_drv_info_to_mfw_t;


/************************FW Statistic Structures **************************/
typedef enum {
    LM_STATS_PORT_QUERY_IDX,
    LM_STATS_PF_QUERY_IDX,
    LM_STATS_FIRST_QUEUE_QUERY_IDX,
    LM_STATS_TOE_IDX,
    LM_STATS_FCOE_IDX,
    LM_STATS_FIRST_VF_QUEUE_QUERY_IDX
} lm_stats_query_idx ;

typedef struct _lm_stats_fw_stats_req_t {
    struct stats_query_header hdr;
    struct stats_query_entry query[STATS_QUERY_CMD_COUNT];
} lm_stats_fw_stats_req_t;

typedef struct _lm_stats_fw_stats_data_t {
    struct stats_counter          storm_counters;
    struct per_port_stats         port;
    struct per_pf_stats           pf;
    struct toe_stats_query        toe;
    struct fcoe_statistics_params fcoe;
    struct per_queue_stats        queue_stats;
    /* TODO: more queue stats? VF? */
} lm_stats_fw_stats_data_t;

typedef struct _lm_stats_fw_collect_t
{
    /* Total number of FW statistics requests */
    u8_t                fw_stats_num;
    /* Total number of FW statistics static (PF) requests */
    u8_t                fw_static_stats_num;
    u8_t                pad[2];


    /* This is a memory buffer that will contain both statistics
     * ramrod request and data.
     */
    void            * fw_stats;
    lm_address_t      fw_stats_mapping;

    /* FW statistics request shortcut (points at the
     * beginning of fw_stats buffer).
     */
    lm_stats_fw_stats_req_t * fw_stats_req;
    lm_address_t              fw_stats_req_mapping;
    u32_t                     fw_stats_req_sz;

    /* FW statistics data shortcut (points at the begining of
     * fw_stats buffer + fw_stats_req_sz).
     */
    lm_stats_fw_stats_data_t * fw_stats_data;
    lm_address_t               fw_stats_data_mapping;
    u32_t                      fw_stats_data_sz;

    struct          sq_pending_command      stats_sp_list_command;               // A pre allocated SPO pending command
    u16_t                                   drv_counter;
    volatile u8_t                           b_completion_done ;                  // 0 if stats ramrod completion haven't been done yet
    volatile u8_t                           b_ramrod_completed ;                 // 0 if stats ramrod completion haven't been done yet
    volatile u8_t                           b_collect_enabled ;                  // enable collection?
    u32_t                                   timer_wakeup_no_completion_current ; // times that current timer wakeup without stats ramrod completion
    u32_t                                   timer_wakeup_no_completion_total ;   // times that timers wakeup without stats ramrod completion (total count - for debugging)
    u32_t                                   timer_wakeup_no_completion_max ;     // max consecutive times timers wakeup without stats ramrod completion
    u32_t                                   stats_ramrod_cnt ;                   // number of times ramrod was called
}lm_stats_fw_collect_t ;

typedef struct _lm_fcoe_stats_t
{
    //XSTORM
    u64_t fcoe_tx_pkt_cnt              /* Number of transmitted FCoE packets */;
    u64_t fcoe_tx_byte_cnt             /* Number of transmitted FCoE bytes */;
    u64_t fcp_tx_pkt_cnt               /* Number of transmitted FCP packets */;
    //TSTORM section 0
    u64_t fcoe_rx_pkt_cnt              /* Number of FCoE packets that were legally received */;
    u64_t fcoe_rx_byte_cnt             /* Number of FCoE bytes that were legally received */;
    //TSTORM section 1
    u64_t fcoe_ver_cnt                 /* Number of packets with wrong FCoE version */;
    u64_t fcoe_rx_drop_pkt_cnt_tstorm  /* Number of FCoE packets that were dropped */;
    //USTORM
    u64_t fc_crc_cnt                   /* Number of packets with FC CRC error */;
    u64_t eofa_del_cnt                 /* Number of packets with EOFa delimiter */;
    u64_t miss_frame_cnt               /* Number of missing packets */;
    u64_t seq_timeout_cnt              /* Number of sequence timeout expirations (E_D_TOV) */;
    u64_t drop_seq_cnt                 /* Number of Sequences that were sropped */;
    u64_t fcoe_rx_drop_pkt_cnt_ustorm  /* Number of FCoE packets that were dropped */;
    u64_t fcp_rx_pkt_cnt               /* Number of FCP packets that were legally received */;
}lm_fcoe_stats_t;

// duplicate of fw HSI structures (using u64 instead u32)
typedef struct _lm_stats_fw_t
{
    struct //eth_xstorm_common
    {
        struct
        {
            u64_t total_sent_bytes ;
            u64_t total_sent_pkts ;
            u64_t unicast_pkts_sent ;
            u64_t unicast_bytes_sent ;
            u64_t multicast_bytes_sent ;
            u64_t multicast_pkts_sent ;
            u64_t broadcast_pkts_sent ;
            u64_t broadcast_bytes_sent ;
            u64_t error_drop_pkts ;
        } client_statistics[LM_CLI_IDX_MAX] ;
    } eth_xstorm_common ;

    struct //eth_tstorm_common
    {
        struct
        {
            u64_t rcv_unicast_bytes /* number of bytes in unicast packets received without errors and pass the filter */;
            u64_t rcv_broadcast_bytes /* number of bytes in broadcast packets received without errors and pass the filter */;
            u64_t rcv_multicast_bytes /* number of bytes in multicast packets received without errors and pass the filter */;
            u64_t rcv_error_bytes /* number of bytes in dropped packets */;
            u64_t checksum_discard /* number of bytes in dropped packets */;
            u64_t packets_too_big_discard /* number of bytes in dropped packets */;
            u64_t rcv_unicast_pkts /* number of packets in unicast packets received without errors and pass the filter */;
            u64_t rcv_broadcast_pkts /* number of packets in broadcast packets received without errors and pass the filter */;
            u64_t rcv_multicast_pkts /* number of packets in multicast packets received without errors and pass the filter */;
            u64_t no_buff_discard /* the number of frames received from network dropped because of no buffer at host */;
            u64_t ttl0_discard /* the number of good frames dropped because of TTL=0 */;
        } client_statistics[LM_CLI_IDX_MAX] ;

        struct
        {
            u64_t mac_filter_discard /* the number of good frames dropped because of no perfect match to MAC/VLAN address */;
            u64_t xxoverflow_discard /* the number of good frames dropped because of xxOverflow in Tstorm */;
            u64_t brb_truncate_discard /* the number of packtes that were dropped because they were truncated in BRB */;
            u64_t mac_discard /* the number of received frames dropped because of errors in packet */;
        } port_statistics;
    } eth_tstorm_common ;

    struct //eth_ustorm_common
    {
        struct
        {
            u64_t ucast_no_buff_bytes   /* the number of unicast bytes received from network dropped because of no buffer at host */;
            u64_t mcast_no_buff_bytes   /* the number of multicast bytes received from network dropped because of no buffer at host */;
            u64_t bcast_no_buff_bytes   /* the number of broadcast bytes received from network dropped because of no buffer at host */;
            u64_t ucast_no_buff_pkts    /* the number of unicast frames received from network dropped because of no buffer at host */;
            u64_t mcast_no_buff_pkts    /* the number of unicast frames received from network dropped because of no buffer at host */;
            u64_t bcast_no_buff_pkts    /* the number of unicast frames received from network dropped because of no buffer at host */;
            u64_t coalesced_pkts        /* the number of packets coalesced in all aggregations */;
            u64_t coalesced_bytes       /* the number of bytes coalesced in all aggregations */;
            u64_t coalesced_events      /* the number of aggregations */;
            u64_t coalesced_aborts      /* the number of exception which avoid aggregation */;
        } client_statistics[LM_CLI_IDX_MAX] ;
    } eth_ustorm_common ;

    struct // toe_xstorm_common
    {
        struct
        {   u64_t tcp_out_segments;
            u64_t tcp_retransmitted_segments;
            u64_t ip_out_octets;
            u64_t ip_out_requests;
        } statistics[STATS_IP_IDX_MAX] ;
    } toe_xstorm_toe ;

    struct // toe_tstorm_common
    {
        struct
        {
            u64_t ip_in_receives;
            u64_t ip_in_delivers;
            u64_t ip_in_octets;
            u64_t tcp_in_errors /* all discards except discards already counted by Ipv4 stats */;
            u64_t ip_in_header_errors /* IP checksum */;
            u64_t ip_in_discards /* no resources */;
            u64_t ip_in_truncated_packets;
        } statistics[STATS_IP_IDX_MAX] ;
    } toe_tstorm_toe ;

    struct
    {
        u64_t no_tx_cqes /* count the number of time storm find that there are no more CQEs */;
    } toe_cstorm_toe ;

    lm_fcoe_stats_t fcoe;

}lm_stats_fw_t;

// duplicate of hw structures (using u64 instead u32 when needed)
typedef struct _stats_macs_t
{
    struct
    {
    u64_t rx_stat_ifhcinoctets                            ;
    u64_t rx_stat_ifhcinbadoctets                         ;                   // HW_MAND_28 E1H_Spec.32
    u64_t rx_stat_etherstatsfragments                     ; // Spec. 38       // HW_MAND_21 E1H_Spec.25
    u64_t rx_stat_ifhcinucastpkts                         ;
    u64_t rx_stat_ifhcinmulticastpkts                     ;
    u64_t rx_stat_ifhcinbroadcastpkts                     ;
    u64_t rx_stat_dot3statsfcserrors                      ; // Spec. 9       // HW_MAND_00 E1H_Spec.4
    u64_t rx_stat_dot3statsalignmenterrors                ; // Spec. 10      // HW_MAND_01 E1H_Spec.5
    u64_t rx_stat_dot3statscarriersenseerrors             ;                  // HW_MAND_31 E1H_Spec.35
    u64_t rx_stat_xonpauseframesreceived                  ;                  // HW_MAND_05 E1H_Spec.9
    u64_t rx_stat_xoffpauseframesreceived                 ; // Spec. 15      // HW_MAND_06 E1H_Spec.10
    u64_t rx_stat_maccontrolframesreceived                ; // Spec. 22      // HW_MAND_13 E1H_Spec.17
    u64_t rx_stat_maccontrolframesreceived_bmac_xpf       ; // Spec. 22 xpf  // HW_MAND_13 E1H_Spec.17 *
    u64_t rx_stat_maccontrolframesreceived_bmac_xcf       ; // Spec. 22 xcf  // HW_MAND_13 E1H_Spec.17 *
    u64_t rx_stat_xoffstateentered                        ; // Spec. 44      // HW_MAND_27 E1H_Spec.31
    u64_t rx_stat_dot3statsframestoolong                  ; // Spec. 13      // HW_MAND_04 E1H_Spec.8
    u64_t rx_stat_etherstatsjabbers                       ; // Spec. 39      // HW_MAND_22 E1H_Spec.26
    u64_t rx_stat_etherstatsundersizepkts                 ; // Spec. 12      // HW_MAND_03 E1H_Spec.7
    u64_t rx_stat_etherstatspkts64octets                  ;
    u64_t rx_stat_etherstatspkts65octetsto127octets       ;
    u64_t rx_stat_etherstatspkts128octetsto255octets      ;
    u64_t rx_stat_etherstatspkts256octetsto511octets      ;
    u64_t rx_stat_etherstatspkts512octetsto1023octets     ;
    u64_t rx_stat_etherstatspkts1024octetsto1522octets    ;
    u64_t rx_stat_etherstatspktsover1522octets            ; // Spec. (29)
    u64_t rx_stat_pfcPacketCounter                        ; // Rx PFC Packet Counter
    } stats_rx ;

    struct
    {
    u64_t rx_stat_falsecarriererrors                  ;                      // HW_MAND_02 E1H_Spec.6
    } stats_rx_err ;

    struct
    {
    u64_t tx_stat_ifhcoutoctets                           ;
    u64_t tx_stat_ifhcoutbadoctets                        ; // Spec. 46      // HW_MAND_29 E1H_Spec.33
    u64_t tx_stat_etherstatscollisions                    ;                  // HW_MAND_25 E1H_Spec.29
    u64_t tx_stat_outxonsent                              ;                  // HW_MAND_07 E1H_Spec.11
    u64_t tx_stat_outxoffsent                             ; // Spec. 17      // HW_MAND_08 E1H_Spec.12
    u64_t tx_stat_flowcontroldone                         ; // Spec. 43      // HW_MAND_26 E1H_Spec.30
    u64_t tx_stat_dot3statssinglecollisionframes          ; // Spec. 18      // HW_MAND_09 E1H_Spec.13
    u64_t tx_stat_dot3statsmultiplecollisionframes        ;                  // HW_MAND_10 E1H_Spec.14
    u64_t tx_stat_dot3statsdeferredtransmissions          ; // Spec. 40      // HW_MAND_23 E1H_Spec.27
    u64_t tx_stat_dot3statsexcessivecollisions            ; // Spec. 21      // HW_MAND_12 E1H_Spec.16
    u64_t tx_stat_dot3statslatecollisions                 ;                  // HW_MAND_11 E1H_Spec.15
    u64_t tx_stat_ifhcoutucastpkts                        ; // Spec. 6
    u64_t tx_stat_ifhcoutucastpkts_bmac_pkt               ; // Spec. 6 pkt
    u64_t tx_stat_ifhcoutucastpkts_bmac_mca               ; // Spec. 6 mca
    u64_t tx_stat_ifhcoutucastpkts_bmac_bca               ; // Spec. 6 bca
    u64_t tx_stat_ifhcoutmulticastpkts                    ; // Spec. 7
    u64_t tx_stat_ifhcoutbroadcastpkts                    ; // Spec. 8
    u64_t tx_stat_etherstatspkts64octets                  ; // Spec. 30      // HW_MAND_14 E1H_Spec.18
    u64_t tx_stat_etherstatspkts65octetsto127octets       ; // Spec. 31      // HW_MAND_15 E1H_Spec.19
    u64_t tx_stat_etherstatspkts128octetsto255octets      ; // Spec. 32      // HW_MAND_16 E1H_Spec.20
    u64_t tx_stat_etherstatspkts256octetsto511octets      ; // Spec. 33      // HW_MAND_17 E1H_Spec.21
    u64_t tx_stat_etherstatspkts512octetsto1023octets     ; // Spec. 34      // HW_MAND_18 E1H_Spec.22
    u64_t tx_stat_etherstatspkts1024octetsto1522octet     ; // Spec. 35      // HW_MAND_19 E1H_Spec.23
    u64_t tx_stat_etherstatspktsover1522octets            ; // Spec. 36      // HW_MAND_20 E1H_Spec.24
    u64_t tx_stat_etherstatspktsover1522octets_bmac_2047  ; // Spec. 36 2047 // HW_MAND_20 E1H_Spec.24
    u64_t tx_stat_etherstatspktsover1522octets_bmac_4095  ; // Spec. 36 4095 // HW_MAND_20 E1H_Spec.24
    u64_t tx_stat_etherstatspktsover1522octets_bmac_9216  ; // Spec. 36 9216 // HW_MAND_20 E1H_Spec.24
    u64_t tx_stat_etherstatspktsover1522octets_bmac_16383 ; // Spec. 36 16383// HW_MAND_20 E1H_Spec.24
    u64_t tx_stat_dot3statsinternalmactransmiterrors      ; // Spec. 41      // HW_MAND_24 E1H_Spec.28
    u64_t tx_stat_ifhcoutdiscards                         ; // Spec. 47      // HW_MAND_30 E1H_Spec.34
    u64_t tx_stat_pfcPacketCounter                        ; // Tx PFC Packet Counter
    } stats_tx ;

} stats_macs_t ;

typedef struct _stats_nig_t
{
    u64_t brb_discard                                 ; // Spec. 49              // HW_MAND_32 E1H_Spec.36
    u64_t brb_packet                                  ; // All the rest we'll need for mcp
    u64_t brb_truncate                                ;
    u64_t flow_ctrl_discard                           ;
    u64_t flow_ctrl_octets                            ;
    u64_t flow_ctrl_packet                            ;
    u64_t mng_discard                                 ;
    u64_t mng_octet_inp                               ;
    u64_t mng_octet_out                               ;
    u64_t mng_packet_inp                              ;
    u64_t mng_packet_out                              ;
    u64_t pbf_octets                                  ;
    u64_t pbf_packet                                  ;
    u64_t safc_inp                                    ;
} stats_nig_t ;

typedef struct _lm_stats_hw_t
{
    stats_macs_t    macs[STATS_MACS_IDX_MAX] ; // 2 copies, one for pre-reset values, one for updating
    stats_nig_t     nig ; // nig is always available - no need for 2 copies
    stats_nig_ex_t  nig_ex ;
    misc_stats_t    misc;
} lm_stats_hw_t ;

typedef struct _lm_stats_drv_t
{
    // L2 statistics collected by driver
    struct
    {
        u32_t rx_ipv4_frag_count;      // Spec 6.2.1: IPv4 Fragment received packets - (indication from RCQ WQE)
        u32_t rx_ip_cs_error_count;    // Spec 6.2.2: IPv4 CS error received packets - (indication from RCQ WQE)
        u32_t rx_tcp_cs_error_count;   // Spec 6.2.3: TCP CS error received packets  - (indication from RCQ WQE)
        u32_t rx_llc_snap_count;       // Spec 6.2.4: LLC/SNAP  received packets - (indication from RCQ WQE)
        u32_t rx_phy_error_count;      // Spec 6.2.5: PHY error received packets - (indication from RCQ WQE)
        u32_t rx_ipv6_ext_count ;      // Spec 6.2.6: IPv6 Ext header received packets (indication from RCQ WQE)
        u32_t rx_aborted ;
        u32_t tx_no_l2_bd ;            // Spec 6.2.7: Event counter: No free BD in the BD chain
        u32_t tx_no_sq_wqe ;           // Spec 6.2.8: Event counter: No free WQE for sending slow path command
        u32_t tx_l2_assembly_buf_use ; // Spec 6.2.9: The number of packets on which the driver used the assembly buffer
        u32_t tx_lso_frames ;
        u32_t tx_aborted ;
        u32_t tx_no_coalesce_buf ;

    } drv_eth ;

    // L4 statistics collected by driver
    struct
    {
        struct
        {
            // for NDIS (per ipv)
            u32_t currently_established;       // Spec 6.3: Number of TCP which the current state is either ESTABLISHED or CLOSE-WAIT
            u32_t out_resets;                  // Spec 6.3: Number of times that offloaded TCP connections have made a direct transition to the CLOSED state from either the ESTABLISHED state or the CLOSE-WAIT state
            u32_t out_discards;                // Spec 6.3: The number of output IP datagrams that the offload target supplied to its IP layer for which no problem was encountered to prevent their transmission but that were discarded for run-time reasons, such as a lack of memory or other resources
                                               //           Note: driver will always return '0' since it doesn't drop packets due to resourcse (stats email)
            u32_t out_no_routes;               // Spec 6.3: The number of output IP datagrams that the offload target supplied to its IP layer that were discarded because no route (such as an offloaded path state object) could be found to transmit them to their destination
                                               //           Note: driver will always return '0' (similar to above. see stats email)

            // additional (per ipv)
            u32_t out_fin ;                    // Spec 6.4.1-2: Number of Fin requests
            u32_t in_fin ;                     // Spec 6.4.3-4: Number of Fin received
            u32_t in_reset ;                   // Spec 6.4.5-6: Number of Reset received

        } ipv[STATS_IP_IDX_MAX] ;

        u32_t tx_no_l4_bd ;                    // Spec 6.4.: Event counter: No free BD in the BD chain
        u32_t tx_l4_assembly_buf_use ;         // Spec 6.4: The number of times that assembly buffer was used
        u32_t rx_indicate_return_pending_cnt ; // Spec 6.4: The number of return pending indications
        u32_t rx_indicate_return_done_cnt ;    // Spec 6.4: The number of return done indications
        u32_t rx_active_gen_buf_cnt;           // Spec 6.4: The occupancy of generic buffer

    } drv_toe ;

    struct
    {
        eth_stats_info_t    eth_stats;
        fcoe_stats_info_t   fcoe_stats;
        iscsi_stats_info_t  iscsi_stats;

    } drv_info_to_mfw;

    struct
    {
        fcoe_capabilities_t fcoe_capabilities;
    } drv_info_to_shmem;

} lm_stats_drv_t ;

// main statistics structure inside lm_device
typedef struct _lm_stats_all_t
{
    // device updated copy of statistics colected from fw/hw/driver?
    struct
    {
        lm_stats_fw_t     stats_fw ; // stats collected from fw using ramrod
        lm_stats_hw_t     stats_hw ; // stats collected from hw using DMAE
        lm_stats_drv_t    stats_drv; // stats collected from VBD driver

        host_port_stats_t stats_mcp_port ;      // stats need to be preserved on PMF migration
        host_func_stats_t stats_mcp_func ;      // stats need to be saved to mgmt periodically
        host_func_stats_t stats_mcp_func_base ; // stats mgmt base for a funciton

    } stats_mirror ;

    // struct used to collect stats from fw & hw
    struct
    {
        // fw shared memory copy of stats data
        lm_stats_fw_collect_t stats_fw ;

        // hw shared memory copy of stats data
        lm_stats_hw_collect_t stats_hw ;

        lm_stats_drv_info_to_mfw_t drv_info_to_mfw;

        u32_t timer_wakeup ; // how many times timer was wake

        u32_t shmem_disabled; // how many times stats were not collected due to shmem disable command

        u32_t sp_record_disabled; // how many times stats were not collected due to FW SP trace

        u64_t next_timer_ms ; // represents next stats timer wakeup (system time in milliseconds)

        u8_t  b_last_called ; // last call of timer ended

    } stats_collect ;

} lm_stats_all_t;

#endif // _LM_STATS_H
