
#ifndef __MICROCODE_CONSTANTS_H_
#define __MICROCODE_CONSTANTS_H_

/* This file defines HSI constants common to all microcode flows */

/* offset in bits of protocol in the state context parameter */
#define PROTOCOL_STATE_BIT_OFFSET               6

//state value to bitwise or for protocol
#define ETH_STATE       (ETH_CONNECTION_TYPE << PROTOCOL_STATE_BIT_OFFSET)
#define TOE_STATE       (TOE_CONNECTION_TYPE << PROTOCOL_STATE_BIT_OFFSET)
#define RDMA_STATE      (RDMA_CONNECTION_TYPE << PROTOCOL_STATE_BIT_OFFSET)

/* microcode fixed page page size 4K (chains and ring segments) */
#define MC_PAGE_SIZE                            4096

/* Number of indices per slow-path SB */
#define HC_SP_SB_MAX_INDICES        16 /*  The Maximum of all */

/* Number of indices per SB */
#define HC_SB_MAX_INDICES_E1X           8  /* Multiple of 4 */
#define HC_SB_MAX_INDICES_E2            8  /* Multiple of 4 */

/* Number of SB */
#define HC_SB_MAX_SB_E1X                        32
#define HC_SB_MAX_SB_E2                         136 /* include PF */

/* ID of slow path status block */
#define HC_SP_SB_ID                             0xde

/* Num of State machines */
#define HC_SB_MAX_SM                            2 /* Fixed */

/* Num of dynamic indices */
#define HC_SB_MAX_DYNAMIC_INDICES   4 /* 0..3 fixed */

/* max number of slow path commands per port */
#define MAX_RAMRODS_PER_PORT                    8


/**** DEFINES FOR TIMERS/CLOCKS RESOLUTIONS ****/

/* chip timers frequency constants */
#define TIMERS_TICK_SIZE_CHIP                   (1e-3)

/* used in toe: TsRecentAge, MaxRt, and temporarily RTT */
#define TSEMI_CLK1_RESUL_CHIP                   (1e-3)

/* temporarily used for RTT */
#define XSEMI_CLK1_RESUL_CHIP                   (1e-3)

/* used for Host Coallescing */
#define SDM_TIMER_TICK_RESUL_CHIP           (4 * (1e-6))
#define TSDM_TIMER_TICK_RESUL_CHIP			(1 * (1e-6))

/**** END DEFINES FOR TIMERS/CLOCKS RESOLUTIONS ****/

#define XSTORM_IP_ID_ROLL_HALF 0x8000
#define XSTORM_IP_ID_ROLL_ALL 0

/* assert list: number of entries */
#define FW_LOG_LIST_SIZE                        50

#define NUM_OF_SAFC_BITS                16
#define MAX_COS_NUMBER                  4
#define MAX_TRAFFIC_TYPES				8
#define MAX_PFC_PRIORITIES              8

/* used by array traffic_type_to_priority[] to mark traffic type that is not mapped to priority*/
#define LLFC_TRAFFIC_TYPE_TO_PRIORITY_UNMAPPED 0xFF

/* Event Ring definitions */
#define C_ERES_PER_PAGE                 ( PAGE_SIZE / BITS_TO_BYTES(STRUCT_SIZE(event_ring_elem)) )
#define C_ERE_PER_PAGE_MASK             ( C_ERES_PER_PAGE - 1 )

/* number of statistic command  */
#define STATS_QUERY_CMD_COUNT 16

/* niv list table size */
#define AFEX_LIST_TABLE_SIZE 4096

/* invalid VNIC Id. used in VNIC classification */
#define INVALID_VNIC_ID		0xFF

/* used for indicating an undefined RAM offset in the IRO arrays */
#define UNDEF_IRO 0x80000000

/* used for defining the amount of FCoE tasks supported for PF */
#define MAX_FCOE_FUNCS_PER_ENGINE		2
#define MAX_NUM_FCOE_TASKS_PER_ENGINE	4096 /*Each port can have at max 1 function*/

#endif /*__MICROCODE_CONSTANTS_H_*/
