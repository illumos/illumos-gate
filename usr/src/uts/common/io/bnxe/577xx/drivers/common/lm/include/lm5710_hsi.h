#ifndef _LM5710_HSI_H
#define _LM5710_HSI_H
/*******************************************************************************
 * Constants (formerly HSI)
 ******************************************************************************/



#define HC_USTORM_SB_NUM_INDICES          4
#define HC_CSTORM_SB_NUM_INDICES          4
#define HC_DHC_SB_NUM_INDICES             4

 /* index values - which counter to update */

#define SM_RX_ID                            0
#define SM_TX_ID                            1

#define HC_PARAMS_TOE_INDEX                0
#define HC_PARAMS_ETH_INDEX                1


#define HC_INDEX_TOE_RX_CQ_CONS             0
#define HC_INDEX_ETH_RX_CQ_CONS             1
#define HC_INDEX_TOE_TX_CQ_CONS				2
#define HC_INDEX_FCOE_EQ_CONS               3

#define HC_INDEX_VF_ETH_RX_CQ_CONS          HC_INDEX_ETH_RX_CQ_CONS

#define HC_INDEX_ISCSI_EQ_CONS		        4 
#define HC_INDEX_ETH_TX_CQ_CONS_COS0	    5
#define HC_INDEX_ETH_TX_CQ_CONS_COS1	    6
#define HC_INDEX_ETH_TX_CQ_CONS_COS2	    7

#define HC_INDEX_VF_ETH_TX_CQ_CONS	        HC_INDEX_ETH_TX_CQ_CONS_COS0
 
#define HC_SP_INDEX_ETH_FW_TX_CQ_CONS           0       // ETH :    FW connection TX CQ index (Formerly HC_INDEX_DEF_C_ETH_FW_TX_CQ_CONS)
#define HC_SP_INDEX_EQ_CONS                     1       // COMMMON: Event queue index
#define HC_SP_INDEX_ETH_ISCSI_CQ_CONS           2       // iSCSI:   L2 connection completions (Formerly HC_INDEX_DEF_C_ETH_ISCSI_CQ_CONS)
#define HC_SP_INDEX_ETH_FCOE_CQ_CONS            3       // FCoE:    L2 connection completions (Formrrly HC_INDEX_DEF_C_ETH_FCOE_CQ_CONS)
#define HC_SP_INDEX_ETH_ISCSI_RX_CQ_CONS        4       // iSCSI:   L2 connection Rx completions (Formerly HC_INDEX_DEF_U_ETH_ISCSI_RX_CQ_CONS)
#define HC_SP_INDEX_ETH_ISCSI_RX_BD_CONS        6       // iSCSI:   L2 connection BDS (Formerly HC_INDEX_DEF_U_ETH_ISCSI_RX_BD_CONS)
#define HC_SP_INDEX_ETH_FCOE_RX_CQ_CONS         7       // FCoE:    L2 connection Rx completions (Formerly HC_INDEX_DEF_U_ETH_FCOE_RX_CQ_CONS)
#define HC_SP_INDEX_ETH_FCOE_RX_BD_CONS         8       // FCoE:    L2 connection BDS (Formrly HC_INDEX_DEF_U_ETH_FCOE_RX_BD_CONS)
#define HC_SP_INDEX_ISCSI_OOO_RX_CONS           9       // ISCSI_OOO: ISCSI OOO RX completions
#define HC_SP_INDEX_NOT_USED                    15       // For debugging
#endif
/* */
