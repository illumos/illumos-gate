/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#ifndef __ECORE_HSI_TOE__
#define __ECORE_HSI_TOE__ 
/************************************************************************/
/* Add include to common TCP target */
/************************************************************************/
#include "tcp_common.h"

/********************/
/* TOE FW CONSTANTS */
/********************/

#define TOE_MAX_RAMROD_PER_PF				8
#define TOE_TX_PAGE_SIZE_BYTES				4096
#define TOE_GRQ_PAGE_SIZE_BYTES				4096
#define TOE_RX_CQ_PAGE_SIZE_BYTES			4096

#define TOE_RX_MAX_RSS_CHAINS				64
#define TOE_TX_MAX_TSS_CHAINS				64
#define TOE_RSS_INDIRECTION_TABLE_SIZE		128


/*
 * The toe storm context of Mstorm
 */
struct mstorm_toe_conn_st_ctx
{
	__le32 reserved[24];
};


/*
 * The toe storm context of Pstorm
 */
struct pstorm_toe_conn_st_ctx
{
	__le32 reserved[36];
};


/*
 * The toe storm context of Ystorm
 */
struct ystorm_toe_conn_st_ctx
{
	__le32 reserved[8];
};

/*
 * The toe storm context of Xstorm
 */
struct xstorm_toe_conn_st_ctx
{
	__le32 reserved[44];
};

struct e4_ystorm_toe_conn_ag_ctx
{
	u8 byte0 /* cdu_validation */;
	u8 byte1 /* state */;
	u8 flags0;
#define E4_YSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_MASK          0x1 /* exist_in_qm0 */
#define E4_YSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT         0
#define E4_YSTORM_TOE_CONN_AG_CTX_BIT1_MASK                  0x1 /* exist_in_qm1 */
#define E4_YSTORM_TOE_CONN_AG_CTX_BIT1_SHIFT                 1
#define E4_YSTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_MASK          0x3 /* cf0 */
#define E4_YSTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_SHIFT         2
#define E4_YSTORM_TOE_CONN_AG_CTX_RESET_RECEIVED_CF_MASK     0x3 /* cf1 */
#define E4_YSTORM_TOE_CONN_AG_CTX_RESET_RECEIVED_CF_SHIFT    4
#define E4_YSTORM_TOE_CONN_AG_CTX_CF2_MASK                   0x3 /* cf2 */
#define E4_YSTORM_TOE_CONN_AG_CTX_CF2_SHIFT                  6
	u8 flags1;
#define E4_YSTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_EN_MASK       0x1 /* cf0en */
#define E4_YSTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_EN_SHIFT      0
#define E4_YSTORM_TOE_CONN_AG_CTX_RESET_RECEIVED_CF_EN_MASK  0x1 /* cf1en */
#define E4_YSTORM_TOE_CONN_AG_CTX_RESET_RECEIVED_CF_EN_SHIFT 1
#define E4_YSTORM_TOE_CONN_AG_CTX_CF2EN_MASK                 0x1 /* cf2en */
#define E4_YSTORM_TOE_CONN_AG_CTX_CF2EN_SHIFT                2
#define E4_YSTORM_TOE_CONN_AG_CTX_REL_SEQ_EN_MASK            0x1 /* rule0en */
#define E4_YSTORM_TOE_CONN_AG_CTX_REL_SEQ_EN_SHIFT           3
#define E4_YSTORM_TOE_CONN_AG_CTX_RULE1EN_MASK               0x1 /* rule1en */
#define E4_YSTORM_TOE_CONN_AG_CTX_RULE1EN_SHIFT              4
#define E4_YSTORM_TOE_CONN_AG_CTX_RULE2EN_MASK               0x1 /* rule2en */
#define E4_YSTORM_TOE_CONN_AG_CTX_RULE2EN_SHIFT              5
#define E4_YSTORM_TOE_CONN_AG_CTX_RULE3EN_MASK               0x1 /* rule3en */
#define E4_YSTORM_TOE_CONN_AG_CTX_RULE3EN_SHIFT              6
#define E4_YSTORM_TOE_CONN_AG_CTX_CONS_PROD_EN_MASK          0x1 /* rule4en */
#define E4_YSTORM_TOE_CONN_AG_CTX_CONS_PROD_EN_SHIFT         7
	u8 completion_opcode /* byte2 */;
	u8 byte3 /* byte3 */;
	__le16 word0 /* word0 */;
	__le32 rel_seq /* reg0 */;
	__le32 rel_seq_threshold /* reg1 */;
	__le16 app_prod /* word1 */;
	__le16 app_cons /* word2 */;
	__le16 word3 /* word3 */;
	__le16 word4 /* word4 */;
	__le32 reg2 /* reg2 */;
	__le32 reg3 /* reg3 */;
};

struct e4_xstorm_toe_conn_ag_ctx
{
	u8 reserved0 /* cdu_validation */;
	u8 state /* state */;
	u8 flags0;
#define E4_XSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_MASK          0x1 /* exist_in_qm0 */
#define E4_XSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT         0
#define E4_XSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM1_MASK          0x1 /* exist_in_qm1 */
#define E4_XSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM1_SHIFT         1
#define E4_XSTORM_TOE_CONN_AG_CTX_RESERVED1_MASK             0x1 /* exist_in_qm2 */
#define E4_XSTORM_TOE_CONN_AG_CTX_RESERVED1_SHIFT            2
#define E4_XSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM3_MASK          0x1 /* exist_in_qm3 */
#define E4_XSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM3_SHIFT         3
#define E4_XSTORM_TOE_CONN_AG_CTX_TX_DEC_RULE_RES_MASK       0x1 /* bit4 */
#define E4_XSTORM_TOE_CONN_AG_CTX_TX_DEC_RULE_RES_SHIFT      4
#define E4_XSTORM_TOE_CONN_AG_CTX_RESERVED2_MASK             0x1 /* cf_array_active */
#define E4_XSTORM_TOE_CONN_AG_CTX_RESERVED2_SHIFT            5
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT6_MASK                  0x1 /* bit6 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT6_SHIFT                 6
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT7_MASK                  0x1 /* bit7 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT7_SHIFT                 7
	u8 flags1;
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT8_MASK                  0x1 /* bit8 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT8_SHIFT                 0
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT9_MASK                  0x1 /* bit9 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT9_SHIFT                 1
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT10_MASK                 0x1 /* bit10 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT10_SHIFT                2
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT11_MASK                 0x1 /* bit11 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT11_SHIFT                3
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT12_MASK                 0x1 /* bit12 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT12_SHIFT                4
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT13_MASK                 0x1 /* bit13 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT13_SHIFT                5
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT14_MASK                 0x1 /* bit14 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT14_SHIFT                6
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT15_MASK                 0x1 /* bit15 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT15_SHIFT                7
	u8 flags2;
#define E4_XSTORM_TOE_CONN_AG_CTX_CF0_MASK                   0x3 /* timer0cf */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF0_SHIFT                  0
#define E4_XSTORM_TOE_CONN_AG_CTX_CF1_MASK                   0x3 /* timer1cf */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF1_SHIFT                  2
#define E4_XSTORM_TOE_CONN_AG_CTX_CF2_MASK                   0x3 /* timer2cf */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF2_SHIFT                  4
#define E4_XSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_MASK        0x3 /* timer_stop_all */
#define E4_XSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_SHIFT       6
	u8 flags3;
#define E4_XSTORM_TOE_CONN_AG_CTX_CF4_MASK                   0x3 /* cf4 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF4_SHIFT                  0
#define E4_XSTORM_TOE_CONN_AG_CTX_CF5_MASK                   0x3 /* cf5 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF5_SHIFT                  2
#define E4_XSTORM_TOE_CONN_AG_CTX_CF6_MASK                   0x3 /* cf6 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF6_SHIFT                  4
#define E4_XSTORM_TOE_CONN_AG_CTX_CF7_MASK                   0x3 /* cf7 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF7_SHIFT                  6
	u8 flags4;
#define E4_XSTORM_TOE_CONN_AG_CTX_CF8_MASK                   0x3 /* cf8 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF8_SHIFT                  0
#define E4_XSTORM_TOE_CONN_AG_CTX_CF9_MASK                   0x3 /* cf9 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF9_SHIFT                  2
#define E4_XSTORM_TOE_CONN_AG_CTX_CF10_MASK                  0x3 /* cf10 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF10_SHIFT                 4
#define E4_XSTORM_TOE_CONN_AG_CTX_CF11_MASK                  0x3 /* cf11 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF11_SHIFT                 6
	u8 flags5;
#define E4_XSTORM_TOE_CONN_AG_CTX_CF12_MASK                  0x3 /* cf12 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF12_SHIFT                 0
#define E4_XSTORM_TOE_CONN_AG_CTX_CF13_MASK                  0x3 /* cf13 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF13_SHIFT                 2
#define E4_XSTORM_TOE_CONN_AG_CTX_CF14_MASK                  0x3 /* cf14 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF14_SHIFT                 4
#define E4_XSTORM_TOE_CONN_AG_CTX_CF15_MASK                  0x3 /* cf15 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF15_SHIFT                 6
	u8 flags6;
#define E4_XSTORM_TOE_CONN_AG_CTX_CF16_MASK                  0x3 /* cf16 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF16_SHIFT                 0
#define E4_XSTORM_TOE_CONN_AG_CTX_CF17_MASK                  0x3 /* cf_array_cf */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF17_SHIFT                 2
#define E4_XSTORM_TOE_CONN_AG_CTX_CF18_MASK                  0x3 /* cf18 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF18_SHIFT                 4
#define E4_XSTORM_TOE_CONN_AG_CTX_DQ_FLUSH_MASK              0x3 /* cf19 */
#define E4_XSTORM_TOE_CONN_AG_CTX_DQ_FLUSH_SHIFT             6
	u8 flags7;
#define E4_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_MASK              0x3 /* cf20 */
#define E4_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_SHIFT             0
#define E4_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q1_MASK              0x3 /* cf21 */
#define E4_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q1_SHIFT             2
#define E4_XSTORM_TOE_CONN_AG_CTX_SLOW_PATH_MASK             0x3 /* cf22 */
#define E4_XSTORM_TOE_CONN_AG_CTX_SLOW_PATH_SHIFT            4
#define E4_XSTORM_TOE_CONN_AG_CTX_CF0EN_MASK                 0x1 /* cf0en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF0EN_SHIFT                6
#define E4_XSTORM_TOE_CONN_AG_CTX_CF1EN_MASK                 0x1 /* cf1en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF1EN_SHIFT                7
	u8 flags8;
#define E4_XSTORM_TOE_CONN_AG_CTX_CF2EN_MASK                 0x1 /* cf2en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF2EN_SHIFT                0
#define E4_XSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_EN_MASK     0x1 /* cf3en */
#define E4_XSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_EN_SHIFT    1
#define E4_XSTORM_TOE_CONN_AG_CTX_CF4EN_MASK                 0x1 /* cf4en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF4EN_SHIFT                2
#define E4_XSTORM_TOE_CONN_AG_CTX_CF5EN_MASK                 0x1 /* cf5en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF5EN_SHIFT                3
#define E4_XSTORM_TOE_CONN_AG_CTX_CF6EN_MASK                 0x1 /* cf6en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF6EN_SHIFT                4
#define E4_XSTORM_TOE_CONN_AG_CTX_CF7EN_MASK                 0x1 /* cf7en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF7EN_SHIFT                5
#define E4_XSTORM_TOE_CONN_AG_CTX_CF8EN_MASK                 0x1 /* cf8en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF8EN_SHIFT                6
#define E4_XSTORM_TOE_CONN_AG_CTX_CF9EN_MASK                 0x1 /* cf9en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF9EN_SHIFT                7
	u8 flags9;
#define E4_XSTORM_TOE_CONN_AG_CTX_CF10EN_MASK                0x1 /* cf10en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF10EN_SHIFT               0
#define E4_XSTORM_TOE_CONN_AG_CTX_CF11EN_MASK                0x1 /* cf11en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF11EN_SHIFT               1
#define E4_XSTORM_TOE_CONN_AG_CTX_CF12EN_MASK                0x1 /* cf12en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF12EN_SHIFT               2
#define E4_XSTORM_TOE_CONN_AG_CTX_CF13EN_MASK                0x1 /* cf13en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF13EN_SHIFT               3
#define E4_XSTORM_TOE_CONN_AG_CTX_CF14EN_MASK                0x1 /* cf14en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF14EN_SHIFT               4
#define E4_XSTORM_TOE_CONN_AG_CTX_CF15EN_MASK                0x1 /* cf15en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF15EN_SHIFT               5
#define E4_XSTORM_TOE_CONN_AG_CTX_CF16EN_MASK                0x1 /* cf16en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF16EN_SHIFT               6
#define E4_XSTORM_TOE_CONN_AG_CTX_CF17EN_MASK                0x1 /* cf_array_cf_en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF17EN_SHIFT               7
	u8 flags10;
#define E4_XSTORM_TOE_CONN_AG_CTX_CF18EN_MASK                0x1 /* cf18en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF18EN_SHIFT               0
#define E4_XSTORM_TOE_CONN_AG_CTX_DQ_FLUSH_EN_MASK           0x1 /* cf19en */
#define E4_XSTORM_TOE_CONN_AG_CTX_DQ_FLUSH_EN_SHIFT          1
#define E4_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_EN_MASK           0x1 /* cf20en */
#define E4_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_EN_SHIFT          2
#define E4_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q1_EN_MASK           0x1 /* cf21en */
#define E4_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q1_EN_SHIFT          3
#define E4_XSTORM_TOE_CONN_AG_CTX_SLOW_PATH_EN_MASK          0x1 /* cf22en */
#define E4_XSTORM_TOE_CONN_AG_CTX_SLOW_PATH_EN_SHIFT         4
#define E4_XSTORM_TOE_CONN_AG_CTX_CF23EN_MASK                0x1 /* cf23en */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF23EN_SHIFT               5
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE0EN_MASK               0x1 /* rule0en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE0EN_SHIFT              6
#define E4_XSTORM_TOE_CONN_AG_CTX_MORE_TO_SEND_RULE_EN_MASK  0x1 /* rule1en */
#define E4_XSTORM_TOE_CONN_AG_CTX_MORE_TO_SEND_RULE_EN_SHIFT 7
	u8 flags11;
#define E4_XSTORM_TOE_CONN_AG_CTX_TX_BLOCKED_EN_MASK         0x1 /* rule2en */
#define E4_XSTORM_TOE_CONN_AG_CTX_TX_BLOCKED_EN_SHIFT        0
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE3EN_MASK               0x1 /* rule3en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE3EN_SHIFT              1
#define E4_XSTORM_TOE_CONN_AG_CTX_RESERVED3_MASK             0x1 /* rule4en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RESERVED3_SHIFT            2
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE5EN_MASK               0x1 /* rule5en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE5EN_SHIFT              3
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE6EN_MASK               0x1 /* rule6en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE6EN_SHIFT              4
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE7EN_MASK               0x1 /* rule7en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE7EN_SHIFT              5
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED1_MASK          0x1 /* rule8en */
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED1_SHIFT         6
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE9EN_MASK               0x1 /* rule9en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE9EN_SHIFT              7
	u8 flags12;
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE10EN_MASK              0x1 /* rule10en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE10EN_SHIFT             0
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE11EN_MASK              0x1 /* rule11en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE11EN_SHIFT             1
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED2_MASK          0x1 /* rule12en */
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED2_SHIFT         2
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED3_MASK          0x1 /* rule13en */
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED3_SHIFT         3
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE14EN_MASK              0x1 /* rule14en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE14EN_SHIFT             4
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE15EN_MASK              0x1 /* rule15en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE15EN_SHIFT             5
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE16EN_MASK              0x1 /* rule16en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE16EN_SHIFT             6
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE17EN_MASK              0x1 /* rule17en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE17EN_SHIFT             7
	u8 flags13;
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE18EN_MASK              0x1 /* rule18en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE18EN_SHIFT             0
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE19EN_MASK              0x1 /* rule19en */
#define E4_XSTORM_TOE_CONN_AG_CTX_RULE19EN_SHIFT             1
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED4_MASK          0x1 /* rule20en */
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED4_SHIFT         2
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED5_MASK          0x1 /* rule21en */
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED5_SHIFT         3
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED6_MASK          0x1 /* rule22en */
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED6_SHIFT         4
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED7_MASK          0x1 /* rule23en */
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED7_SHIFT         5
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED8_MASK          0x1 /* rule24en */
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED8_SHIFT         6
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED9_MASK          0x1 /* rule25en */
#define E4_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED9_SHIFT         7
	u8 flags14;
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT16_MASK                 0x1 /* bit16 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT16_SHIFT                0
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT17_MASK                 0x1 /* bit17 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT17_SHIFT                1
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT18_MASK                 0x1 /* bit18 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT18_SHIFT                2
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT19_MASK                 0x1 /* bit19 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT19_SHIFT                3
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT20_MASK                 0x1 /* bit20 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT20_SHIFT                4
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT21_MASK                 0x1 /* bit21 */
#define E4_XSTORM_TOE_CONN_AG_CTX_BIT21_SHIFT                5
#define E4_XSTORM_TOE_CONN_AG_CTX_CF23_MASK                  0x3 /* cf23 */
#define E4_XSTORM_TOE_CONN_AG_CTX_CF23_SHIFT                 6
	u8 byte2 /* byte2 */;
	__le16 physical_q0 /* physical_q0 */;
	__le16 physical_q1 /* physical_q1 */;
	__le16 word2 /* physical_q2 */;
	__le16 word3 /* word3 */;
	__le16 bd_prod /* word4 */;
	__le16 word5 /* word5 */;
	__le16 word6 /* conn_dpi */;
	u8 byte3 /* byte3 */;
	u8 byte4 /* byte4 */;
	u8 byte5 /* byte5 */;
	u8 byte6 /* byte6 */;
	__le32 reg0 /* reg0 */;
	__le32 reg1 /* reg1 */;
	__le32 reg2 /* reg2 */;
	__le32 more_to_send_seq /* reg3 */;
	__le32 local_adv_wnd_seq /* reg4 */;
	__le32 reg5 /* cf_array0 */;
	__le32 reg6 /* cf_array1 */;
	__le16 word7 /* word7 */;
	__le16 word8 /* word8 */;
	__le16 word9 /* word9 */;
	__le16 word10 /* word10 */;
	__le32 reg7 /* reg7 */;
	__le32 reg8 /* reg8 */;
	__le32 reg9 /* reg9 */;
	u8 byte7 /* byte7 */;
	u8 byte8 /* byte8 */;
	u8 byte9 /* byte9 */;
	u8 byte10 /* byte10 */;
	u8 byte11 /* byte11 */;
	u8 byte12 /* byte12 */;
	u8 byte13 /* byte13 */;
	u8 byte14 /* byte14 */;
	u8 byte15 /* byte15 */;
	u8 e5_reserved /* e5_reserved */;
	__le16 word11 /* word11 */;
	__le32 reg10 /* reg10 */;
	__le32 reg11 /* reg11 */;
	__le32 reg12 /* reg12 */;
	__le32 reg13 /* reg13 */;
	__le32 reg14 /* reg14 */;
	__le32 reg15 /* reg15 */;
	__le32 reg16 /* reg16 */;
	__le32 reg17 /* reg17 */;
};

struct e4_tstorm_toe_conn_ag_ctx
{
	u8 reserved0 /* cdu_validation */;
	u8 byte1 /* state */;
	u8 flags0;
#define E4_TSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_MASK       0x1 /* exist_in_qm0 */
#define E4_TSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT      0
#define E4_TSTORM_TOE_CONN_AG_CTX_BIT1_MASK               0x1 /* exist_in_qm1 */
#define E4_TSTORM_TOE_CONN_AG_CTX_BIT1_SHIFT              1
#define E4_TSTORM_TOE_CONN_AG_CTX_BIT2_MASK               0x1 /* bit2 */
#define E4_TSTORM_TOE_CONN_AG_CTX_BIT2_SHIFT              2
#define E4_TSTORM_TOE_CONN_AG_CTX_BIT3_MASK               0x1 /* bit3 */
#define E4_TSTORM_TOE_CONN_AG_CTX_BIT3_SHIFT              3
#define E4_TSTORM_TOE_CONN_AG_CTX_BIT4_MASK               0x1 /* bit4 */
#define E4_TSTORM_TOE_CONN_AG_CTX_BIT4_SHIFT              4
#define E4_TSTORM_TOE_CONN_AG_CTX_BIT5_MASK               0x1 /* bit5 */
#define E4_TSTORM_TOE_CONN_AG_CTX_BIT5_SHIFT              5
#define E4_TSTORM_TOE_CONN_AG_CTX_TIMEOUT_CF_MASK         0x3 /* timer0cf */
#define E4_TSTORM_TOE_CONN_AG_CTX_TIMEOUT_CF_SHIFT        6
	u8 flags1;
#define E4_TSTORM_TOE_CONN_AG_CTX_CF1_MASK                0x3 /* timer1cf */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF1_SHIFT               0
#define E4_TSTORM_TOE_CONN_AG_CTX_CF2_MASK                0x3 /* timer2cf */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF2_SHIFT               2
#define E4_TSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_MASK     0x3 /* timer_stop_all */
#define E4_TSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_SHIFT    4
#define E4_TSTORM_TOE_CONN_AG_CTX_CF4_MASK                0x3 /* cf4 */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF4_SHIFT               6
	u8 flags2;
#define E4_TSTORM_TOE_CONN_AG_CTX_CF5_MASK                0x3 /* cf5 */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF5_SHIFT               0
#define E4_TSTORM_TOE_CONN_AG_CTX_CF6_MASK                0x3 /* cf6 */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF6_SHIFT               2
#define E4_TSTORM_TOE_CONN_AG_CTX_CF7_MASK                0x3 /* cf7 */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF7_SHIFT               4
#define E4_TSTORM_TOE_CONN_AG_CTX_CF8_MASK                0x3 /* cf8 */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF8_SHIFT               6
	u8 flags3;
#define E4_TSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_MASK           0x3 /* cf9 */
#define E4_TSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_SHIFT          0
#define E4_TSTORM_TOE_CONN_AG_CTX_CF10_MASK               0x3 /* cf10 */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF10_SHIFT              2
#define E4_TSTORM_TOE_CONN_AG_CTX_TIMEOUT_CF_EN_MASK      0x1 /* cf0en */
#define E4_TSTORM_TOE_CONN_AG_CTX_TIMEOUT_CF_EN_SHIFT     4
#define E4_TSTORM_TOE_CONN_AG_CTX_CF1EN_MASK              0x1 /* cf1en */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF1EN_SHIFT             5
#define E4_TSTORM_TOE_CONN_AG_CTX_CF2EN_MASK              0x1 /* cf2en */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF2EN_SHIFT             6
#define E4_TSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_EN_MASK  0x1 /* cf3en */
#define E4_TSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_EN_SHIFT 7
	u8 flags4;
#define E4_TSTORM_TOE_CONN_AG_CTX_CF4EN_MASK              0x1 /* cf4en */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF4EN_SHIFT             0
#define E4_TSTORM_TOE_CONN_AG_CTX_CF5EN_MASK              0x1 /* cf5en */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF5EN_SHIFT             1
#define E4_TSTORM_TOE_CONN_AG_CTX_CF6EN_MASK              0x1 /* cf6en */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF6EN_SHIFT             2
#define E4_TSTORM_TOE_CONN_AG_CTX_CF7EN_MASK              0x1 /* cf7en */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF7EN_SHIFT             3
#define E4_TSTORM_TOE_CONN_AG_CTX_CF8EN_MASK              0x1 /* cf8en */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF8EN_SHIFT             4
#define E4_TSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_EN_MASK        0x1 /* cf9en */
#define E4_TSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_EN_SHIFT       5
#define E4_TSTORM_TOE_CONN_AG_CTX_CF10EN_MASK             0x1 /* cf10en */
#define E4_TSTORM_TOE_CONN_AG_CTX_CF10EN_SHIFT            6
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE0EN_MASK            0x1 /* rule0en */
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE0EN_SHIFT           7
	u8 flags5;
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE1EN_MASK            0x1 /* rule1en */
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE1EN_SHIFT           0
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE2EN_MASK            0x1 /* rule2en */
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE2EN_SHIFT           1
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE3EN_MASK            0x1 /* rule3en */
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE3EN_SHIFT           2
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE4EN_MASK            0x1 /* rule4en */
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE4EN_SHIFT           3
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE5EN_MASK            0x1 /* rule5en */
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE5EN_SHIFT           4
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE6EN_MASK            0x1 /* rule6en */
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE6EN_SHIFT           5
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE7EN_MASK            0x1 /* rule7en */
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE7EN_SHIFT           6
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE8EN_MASK            0x1 /* rule8en */
#define E4_TSTORM_TOE_CONN_AG_CTX_RULE8EN_SHIFT           7
	__le32 reg0 /* reg0 */;
	__le32 reg1 /* reg1 */;
	__le32 reg2 /* reg2 */;
	__le32 reg3 /* reg3 */;
	__le32 reg4 /* reg4 */;
	__le32 reg5 /* reg5 */;
	__le32 reg6 /* reg6 */;
	__le32 reg7 /* reg7 */;
	__le32 reg8 /* reg8 */;
	u8 byte2 /* byte2 */;
	u8 byte3 /* byte3 */;
	__le16 word0 /* word0 */;
};

struct e4_ustorm_toe_conn_ag_ctx
{
	u8 reserved /* cdu_validation */;
	u8 byte1 /* state */;
	u8 flags0;
#define E4_USTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_MASK       0x1 /* exist_in_qm0 */
#define E4_USTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT      0
#define E4_USTORM_TOE_CONN_AG_CTX_BIT1_MASK               0x1 /* exist_in_qm1 */
#define E4_USTORM_TOE_CONN_AG_CTX_BIT1_SHIFT              1
#define E4_USTORM_TOE_CONN_AG_CTX_CF0_MASK                0x3 /* timer0cf */
#define E4_USTORM_TOE_CONN_AG_CTX_CF0_SHIFT               2
#define E4_USTORM_TOE_CONN_AG_CTX_CF1_MASK                0x3 /* timer1cf */
#define E4_USTORM_TOE_CONN_AG_CTX_CF1_SHIFT               4
#define E4_USTORM_TOE_CONN_AG_CTX_PUSH_TIMER_CF_MASK      0x3 /* timer2cf */
#define E4_USTORM_TOE_CONN_AG_CTX_PUSH_TIMER_CF_SHIFT     6
	u8 flags1;
#define E4_USTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_MASK     0x3 /* timer_stop_all */
#define E4_USTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_SHIFT    0
#define E4_USTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_MASK       0x3 /* cf4 */
#define E4_USTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_SHIFT      2
#define E4_USTORM_TOE_CONN_AG_CTX_DQ_CF_MASK              0x3 /* cf5 */
#define E4_USTORM_TOE_CONN_AG_CTX_DQ_CF_SHIFT             4
#define E4_USTORM_TOE_CONN_AG_CTX_CF6_MASK                0x3 /* cf6 */
#define E4_USTORM_TOE_CONN_AG_CTX_CF6_SHIFT               6
	u8 flags2;
#define E4_USTORM_TOE_CONN_AG_CTX_CF0EN_MASK              0x1 /* cf0en */
#define E4_USTORM_TOE_CONN_AG_CTX_CF0EN_SHIFT             0
#define E4_USTORM_TOE_CONN_AG_CTX_CF1EN_MASK              0x1 /* cf1en */
#define E4_USTORM_TOE_CONN_AG_CTX_CF1EN_SHIFT             1
#define E4_USTORM_TOE_CONN_AG_CTX_PUSH_TIMER_CF_EN_MASK   0x1 /* cf2en */
#define E4_USTORM_TOE_CONN_AG_CTX_PUSH_TIMER_CF_EN_SHIFT  2
#define E4_USTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_EN_MASK  0x1 /* cf3en */
#define E4_USTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_EN_SHIFT 3
#define E4_USTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_EN_MASK    0x1 /* cf4en */
#define E4_USTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_EN_SHIFT   4
#define E4_USTORM_TOE_CONN_AG_CTX_DQ_CF_EN_MASK           0x1 /* cf5en */
#define E4_USTORM_TOE_CONN_AG_CTX_DQ_CF_EN_SHIFT          5
#define E4_USTORM_TOE_CONN_AG_CTX_CF6EN_MASK              0x1 /* cf6en */
#define E4_USTORM_TOE_CONN_AG_CTX_CF6EN_SHIFT             6
#define E4_USTORM_TOE_CONN_AG_CTX_RULE0EN_MASK            0x1 /* rule0en */
#define E4_USTORM_TOE_CONN_AG_CTX_RULE0EN_SHIFT           7
	u8 flags3;
#define E4_USTORM_TOE_CONN_AG_CTX_RULE1EN_MASK            0x1 /* rule1en */
#define E4_USTORM_TOE_CONN_AG_CTX_RULE1EN_SHIFT           0
#define E4_USTORM_TOE_CONN_AG_CTX_RULE2EN_MASK            0x1 /* rule2en */
#define E4_USTORM_TOE_CONN_AG_CTX_RULE2EN_SHIFT           1
#define E4_USTORM_TOE_CONN_AG_CTX_RULE3EN_MASK            0x1 /* rule3en */
#define E4_USTORM_TOE_CONN_AG_CTX_RULE3EN_SHIFT           2
#define E4_USTORM_TOE_CONN_AG_CTX_RULE4EN_MASK            0x1 /* rule4en */
#define E4_USTORM_TOE_CONN_AG_CTX_RULE4EN_SHIFT           3
#define E4_USTORM_TOE_CONN_AG_CTX_RULE5EN_MASK            0x1 /* rule5en */
#define E4_USTORM_TOE_CONN_AG_CTX_RULE5EN_SHIFT           4
#define E4_USTORM_TOE_CONN_AG_CTX_RULE6EN_MASK            0x1 /* rule6en */
#define E4_USTORM_TOE_CONN_AG_CTX_RULE6EN_SHIFT           5
#define E4_USTORM_TOE_CONN_AG_CTX_RULE7EN_MASK            0x1 /* rule7en */
#define E4_USTORM_TOE_CONN_AG_CTX_RULE7EN_SHIFT           6
#define E4_USTORM_TOE_CONN_AG_CTX_RULE8EN_MASK            0x1 /* rule8en */
#define E4_USTORM_TOE_CONN_AG_CTX_RULE8EN_SHIFT           7
	u8 byte2 /* byte2 */;
	u8 byte3 /* byte3 */;
	__le16 word0 /* conn_dpi */;
	__le16 word1 /* word1 */;
	__le32 reg0 /* reg0 */;
	__le32 reg1 /* reg1 */;
	__le32 reg2 /* reg2 */;
	__le32 reg3 /* reg3 */;
	__le16 word2 /* word2 */;
	__le16 word3 /* word3 */;
};

/*
 * The toe storm context of Tstorm
 */
struct tstorm_toe_conn_st_ctx
{
	__le32 reserved[16];
};

/*
 * The toe storm context of Ustorm
 */
struct ustorm_toe_conn_st_ctx
{
	__le32 reserved[52];
};

/*
 * toe connection context
 */
struct toe_conn_context
{
	struct ystorm_toe_conn_st_ctx ystorm_st_context /* ystorm storm context */;
	struct pstorm_toe_conn_st_ctx pstorm_st_context /* pstorm storm context */;
	struct regpair pstorm_st_padding[2] /* padding */;
	struct xstorm_toe_conn_st_ctx xstorm_st_context /* xstorm storm context */;
	struct regpair xstorm_st_padding[2] /* padding */;
	struct e4_ystorm_toe_conn_ag_ctx ystorm_ag_context /* ystorm aggregative context */;
	struct e4_xstorm_toe_conn_ag_ctx xstorm_ag_context /* xstorm aggregative context */;
	struct e4_tstorm_toe_conn_ag_ctx tstorm_ag_context /* tstorm aggregative context */;
	struct regpair tstorm_ag_padding[2] /* padding */;
	struct timers_context timer_context /* timer context */;
	struct e4_ustorm_toe_conn_ag_ctx ustorm_ag_context /* ustorm aggregative context */;
	struct tstorm_toe_conn_st_ctx tstorm_st_context /* tstorm storm context */;
	struct mstorm_toe_conn_st_ctx mstorm_st_context /* mstorm storm context */;
	struct ustorm_toe_conn_st_ctx ustorm_st_context /* ustorm storm context */;
};


/*
 * toe init ramrod header
 */
struct toe_init_ramrod_header
{
	u8 first_rss /* First rss in PF */;
	u8 num_rss /* Num of rss ids in PF */;
	u8 reserved[6];
};

/*
 * toe pf init parameters
 */
struct toe_pf_init_params
{
	__le32 push_timeout /* push timer timeout in miliseconds */;
	__le16 grq_buffer_size /* GRQ buffer size in bytes */;
	__le16 grq_sb_id /* GRQ status block id */;
	u8 grq_sb_index /* GRQ status block index */;
	u8 max_seg_retransmit /* Maximum number of retransmits for one segment */;
	u8 doubt_reachability /* Doubt reachability threshold */;
	u8 ll2_rx_queue_id /* Queue ID of the Light-L2 Rx Queue */;
	__le16 grq_fetch_threshold /* when passing this threshold, firmware will sync the driver with grq consumer */;
	u8 reserved1[2];
	struct regpair grq_page_addr /* Address of the first page in the grq ring */;
};

/*
 * toe tss parameters
 */
struct toe_tss_params
{
	struct regpair curr_page_addr /* Address of the current page in the tx cq ring */;
	struct regpair next_page_addr /* Address of the next page in the tx cq ring */;
	u8 reserved0 /* Status block id */;
	u8 status_block_index /* Status block index */;
	__le16 status_block_id /* Status block id */;
	__le16 reserved1[2];
};

/*
 * toe rss parameters
 */
struct toe_rss_params
{
	struct regpair curr_page_addr /* Address of the current page in the rx cq ring */;
	struct regpair next_page_addr /* Address of the next page in the rx cq ring */;
	u8 reserved0 /* Status block id */;
	u8 status_block_index /* Status block index */;
	__le16 status_block_id /* Status block id */;
	__le16 reserved1[2];
};

/*
 * toe init ramrod data
 */
struct toe_init_ramrod_data
{
	struct toe_init_ramrod_header hdr;
	struct tcp_init_params tcp_params;
	struct toe_pf_init_params pf_params;
	struct toe_tss_params tss_params[TOE_TX_MAX_TSS_CHAINS];
	struct toe_rss_params rss_params[TOE_RX_MAX_RSS_CHAINS];
};



/*
 * toe offload parameters
 */
struct toe_offload_params
{
	struct regpair tx_bd_page_addr /* Tx Bd page address */;
	struct regpair tx_app_page_addr /* Tx App page address */;
	struct regpair rx_bd_page_addr /* Rx Bd page address */;
	__le32 more_to_send_seq /* Last byte in bd prod (not including fin) */;
	__le16 tx_app_prod /* Producer of application buffer ring */;
	__le16 rcv_indication_size /* Recieve indication threshold */;
	__le16 reserved;
	u8 rss_tss_id /* RSS/TSS absolute id */;
	u8 ignore_grq_push;
	struct regpair rx_db_data_ptr;
	__le32 reserved1;
};


/*
 * TOE offload ramrod data - DMAed by firmware
 */
struct toe_offload_ramrod_data
{
	struct tcp_offload_params tcp_ofld_params;
	struct toe_offload_params toe_ofld_params;
};



/*
 * TOE ramrod command IDs
 */
enum toe_ramrod_cmd_id
{
	TOE_RAMROD_UNUSED,
	TOE_RAMROD_FUNC_INIT,
	TOE_RAMROD_INITATE_OFFLOAD,
	TOE_RAMROD_FUNC_CLOSE,
	TOE_RAMROD_SEARCHER_DELETE,
	TOE_RAMROD_TERMINATE,
	TOE_RAMROD_QUERY,
	TOE_RAMROD_UPDATE,
	TOE_RAMROD_EMPTY,
	TOE_RAMROD_RESET_SEND,
	TOE_RAMROD_INVALIDATE,
	MAX_TOE_RAMROD_CMD_ID
};



/*
 * Toe RQ buffer descriptor
 */
struct toe_rx_bd
{
	struct regpair addr /* Address of buffer */;
	__le16 size /* Size of buffer */;
	__le16 flags;
#define TOE_RX_BD_START_MASK      0x1 /* this bd is the beginning of an application buffer */
#define TOE_RX_BD_START_SHIFT     0
#define TOE_RX_BD_END_MASK        0x1 /* this bd is the end of an application buffer */
#define TOE_RX_BD_END_SHIFT       1
#define TOE_RX_BD_NO_PUSH_MASK    0x1 /* this application buffer must not be partially completed */
#define TOE_RX_BD_NO_PUSH_SHIFT   2
#define TOE_RX_BD_SPLIT_MASK      0x1
#define TOE_RX_BD_SPLIT_SHIFT     3
#define TOE_RX_BD_RESERVED0_MASK  0xFFF
#define TOE_RX_BD_RESERVED0_SHIFT 4
	__le32 reserved1;
};


/*
 * TOE RX completion queue opcodes (opcode 0 is illegal)
 */
enum toe_rx_cmp_opcode
{
	TOE_RX_CMP_OPCODE_GA=1,
	TOE_RX_CMP_OPCODE_GR=2,
	TOE_RX_CMP_OPCODE_GNI=3,
	TOE_RX_CMP_OPCODE_GAIR=4,
	TOE_RX_CMP_OPCODE_GAIL=5,
	TOE_RX_CMP_OPCODE_GRI=6,
	TOE_RX_CMP_OPCODE_GJ=7,
	TOE_RX_CMP_OPCODE_DGI=8,
	TOE_RX_CMP_OPCODE_CMP=9,
	TOE_RX_CMP_OPCODE_REL=10,
	TOE_RX_CMP_OPCODE_SKP=11,
	TOE_RX_CMP_OPCODE_URG=12,
	TOE_RX_CMP_OPCODE_RT_TO=13,
	TOE_RX_CMP_OPCODE_KA_TO=14,
	TOE_RX_CMP_OPCODE_MAX_RT=15,
	TOE_RX_CMP_OPCODE_DBT_RE=16,
	TOE_RX_CMP_OPCODE_SYN=17,
	TOE_RX_CMP_OPCODE_OPT_ERR=18,
	TOE_RX_CMP_OPCODE_FW2_TO=19,
	TOE_RX_CMP_OPCODE_2WY_CLS=20,
	TOE_RX_CMP_OPCODE_RST_RCV=21,
	TOE_RX_CMP_OPCODE_FIN_RCV=22,
	TOE_RX_CMP_OPCODE_FIN_UPL=23,
	TOE_RX_CMP_OPCODE_INIT=32,
	TOE_RX_CMP_OPCODE_RSS_UPDATE=33,
	TOE_RX_CMP_OPCODE_CLOSE=34,
	TOE_RX_CMP_OPCODE_INITIATE_OFFLOAD=80,
	TOE_RX_CMP_OPCODE_SEARCHER_DELETE=81,
	TOE_RX_CMP_OPCODE_TERMINATE=82,
	TOE_RX_CMP_OPCODE_QUERY=83,
	TOE_RX_CMP_OPCODE_RESET_SEND=84,
	TOE_RX_CMP_OPCODE_INVALIDATE=85,
	TOE_RX_CMP_OPCODE_EMPTY=86,
	TOE_RX_CMP_OPCODE_UPDATE=87,
	MAX_TOE_RX_CMP_OPCODE
};


/*
 * TOE rx ooo completion data
 */
struct toe_rx_cqe_ooo_params
{
	__le32 nbytes;
	__le16 grq_buff_id /* grq buffer identifier */;
	u8 isle_num;
	u8 reserved0;
};

/*
 * TOE rx in order completion data
 */
struct toe_rx_cqe_in_order_params
{
	__le32 nbytes;
	__le16 grq_buff_id /* grq buffer identifier - applicable only for GA,GR opcodes */;
	__le16 reserved1;
};

/*
 * Union for TOE rx completion data
 */
union toe_rx_cqe_data_union
{
	struct toe_rx_cqe_ooo_params ooo_params;
	struct toe_rx_cqe_in_order_params in_order_params;
	struct regpair raw_data;
};

/*
 * TOE rx completion element
 */
struct toe_rx_cqe
{
	__le16 icid;
	u8 completion_opcode;
	u8 reserved0;
	__le32 reserved1;
	union toe_rx_cqe_data_union data;
};





/*
 * toe RX doorbel data
 */
struct toe_rx_db_data
{
	__le32 local_adv_wnd_seq /* Sequence of the right edge of the local advertised window (receive window) */;
	__le32 reserved[3];
};


/*
 * Toe GRQ buffer descriptor
 */
struct toe_rx_grq_bd
{
	struct regpair addr /* Address of buffer */;
	__le16 buff_id /* buffer indentifier */;
	__le16 reserved0;
	__le32 reserved1;
};



/*
 * Toe transmission application buffer descriptor
 */
struct toe_tx_app_buff_desc
{
	__le32 next_buffer_start_seq /* Tcp sequence of the first byte in the next application buffer */;
	__le32 reserved;
};


/*
 * Toe transmission application buffer descriptor page pointer
 */
struct toe_tx_app_buff_page_pointer
{
	struct regpair next_page_addr /* Address of next page */;
};


/*
 * Toe transmission buffer descriptor
 */
struct toe_tx_bd
{
	struct regpair addr /* Address of buffer */;
	__le16 size /* Size of buffer */;
	__le16 flags;
#define TOE_TX_BD_PUSH_MASK      0x1 /* Push flag */
#define TOE_TX_BD_PUSH_SHIFT     0
#define TOE_TX_BD_NOTIFY_MASK    0x1 /* Notify flag */
#define TOE_TX_BD_NOTIFY_SHIFT   1
#define TOE_TX_BD_LARGE_IO_MASK  0x1 /* Large IO flag */
#define TOE_TX_BD_LARGE_IO_SHIFT 2
#define TOE_TX_BD_BD_CONS_MASK   0x1FFF /* 13 LSbits of the consumer of this bd for debugging */
#define TOE_TX_BD_BD_CONS_SHIFT  3
	__le32 next_bd_start_seq /* Tcp sequence of the first byte in the next buffer */;
};


/*
 * TOE completion opcodes
 */
enum toe_tx_cmp_opcode
{
	TOE_TX_CMP_OPCODE_DATA,
	TOE_TX_CMP_OPCODE_TERMINATE,
	TOE_TX_CMP_OPCODE_EMPTY,
	TOE_TX_CMP_OPCODE_RESET_SEND,
	TOE_TX_CMP_OPCODE_INVALIDATE,
	TOE_TX_CMP_OPCODE_RST_RCV,
	MAX_TOE_TX_CMP_OPCODE
};


/*
 * Toe transmission completion element
 */
struct toe_tx_cqe
{
	__le16 icid /* Connection ID */;
	u8 opcode /* Completion opcode */;
	u8 reserved;
	__le32 size /* Size of completed data */;
};


/*
 * Toe transmission page pointer bd
 */
struct toe_tx_page_pointer_bd
{
	struct regpair next_page_addr /* Address of next page */;
	struct regpair prev_page_addr /* Address of previous page */;
};


/*
 * Toe transmission completion element page pointer
 */
struct toe_tx_page_pointer_cqe
{
	struct regpair next_page_addr /* Address of next page */;
};


/*
 * toe update parameters
 */
struct toe_update_params
{
	__le16 flags;
#define TOE_UPDATE_PARAMS_RCV_INDICATION_SIZE_CHANGED_MASK  0x1
#define TOE_UPDATE_PARAMS_RCV_INDICATION_SIZE_CHANGED_SHIFT 0
#define TOE_UPDATE_PARAMS_RESERVED_MASK                     0x7FFF
#define TOE_UPDATE_PARAMS_RESERVED_SHIFT                    1
	__le16 rcv_indication_size;
	__le16 reserved1[2];
};


/*
 * TOE update ramrod data - DMAed by firmware
 */
struct toe_update_ramrod_data
{
	struct tcp_update_params tcp_upd_params;
	struct toe_update_params toe_upd_params;
};






struct e4_mstorm_toe_conn_ag_ctx
{
	u8 byte0 /* cdu_validation */;
	u8 byte1 /* state */;
	u8 flags0;
#define E4_MSTORM_TOE_CONN_AG_CTX_BIT0_MASK     0x1 /* exist_in_qm0 */
#define E4_MSTORM_TOE_CONN_AG_CTX_BIT0_SHIFT    0
#define E4_MSTORM_TOE_CONN_AG_CTX_BIT1_MASK     0x1 /* exist_in_qm1 */
#define E4_MSTORM_TOE_CONN_AG_CTX_BIT1_SHIFT    1
#define E4_MSTORM_TOE_CONN_AG_CTX_CF0_MASK      0x3 /* cf0 */
#define E4_MSTORM_TOE_CONN_AG_CTX_CF0_SHIFT     2
#define E4_MSTORM_TOE_CONN_AG_CTX_CF1_MASK      0x3 /* cf1 */
#define E4_MSTORM_TOE_CONN_AG_CTX_CF1_SHIFT     4
#define E4_MSTORM_TOE_CONN_AG_CTX_CF2_MASK      0x3 /* cf2 */
#define E4_MSTORM_TOE_CONN_AG_CTX_CF2_SHIFT     6
	u8 flags1;
#define E4_MSTORM_TOE_CONN_AG_CTX_CF0EN_MASK    0x1 /* cf0en */
#define E4_MSTORM_TOE_CONN_AG_CTX_CF0EN_SHIFT   0
#define E4_MSTORM_TOE_CONN_AG_CTX_CF1EN_MASK    0x1 /* cf1en */
#define E4_MSTORM_TOE_CONN_AG_CTX_CF1EN_SHIFT   1
#define E4_MSTORM_TOE_CONN_AG_CTX_CF2EN_MASK    0x1 /* cf2en */
#define E4_MSTORM_TOE_CONN_AG_CTX_CF2EN_SHIFT   2
#define E4_MSTORM_TOE_CONN_AG_CTX_RULE0EN_MASK  0x1 /* rule0en */
#define E4_MSTORM_TOE_CONN_AG_CTX_RULE0EN_SHIFT 3
#define E4_MSTORM_TOE_CONN_AG_CTX_RULE1EN_MASK  0x1 /* rule1en */
#define E4_MSTORM_TOE_CONN_AG_CTX_RULE1EN_SHIFT 4
#define E4_MSTORM_TOE_CONN_AG_CTX_RULE2EN_MASK  0x1 /* rule2en */
#define E4_MSTORM_TOE_CONN_AG_CTX_RULE2EN_SHIFT 5
#define E4_MSTORM_TOE_CONN_AG_CTX_RULE3EN_MASK  0x1 /* rule3en */
#define E4_MSTORM_TOE_CONN_AG_CTX_RULE3EN_SHIFT 6
#define E4_MSTORM_TOE_CONN_AG_CTX_RULE4EN_MASK  0x1 /* rule4en */
#define E4_MSTORM_TOE_CONN_AG_CTX_RULE4EN_SHIFT 7
	__le16 word0 /* word0 */;
	__le16 word1 /* word1 */;
	__le32 reg0 /* reg0 */;
	__le32 reg1 /* reg1 */;
};






struct e5_mstorm_toe_conn_ag_ctx
{
	u8 byte0 /* cdu_validation */;
	u8 byte1 /* state_and_core_id */;
	u8 flags0;
#define E5_MSTORM_TOE_CONN_AG_CTX_BIT0_MASK     0x1 /* exist_in_qm0 */
#define E5_MSTORM_TOE_CONN_AG_CTX_BIT0_SHIFT    0
#define E5_MSTORM_TOE_CONN_AG_CTX_BIT1_MASK     0x1 /* exist_in_qm1 */
#define E5_MSTORM_TOE_CONN_AG_CTX_BIT1_SHIFT    1
#define E5_MSTORM_TOE_CONN_AG_CTX_CF0_MASK      0x3 /* cf0 */
#define E5_MSTORM_TOE_CONN_AG_CTX_CF0_SHIFT     2
#define E5_MSTORM_TOE_CONN_AG_CTX_CF1_MASK      0x3 /* cf1 */
#define E5_MSTORM_TOE_CONN_AG_CTX_CF1_SHIFT     4
#define E5_MSTORM_TOE_CONN_AG_CTX_CF2_MASK      0x3 /* cf2 */
#define E5_MSTORM_TOE_CONN_AG_CTX_CF2_SHIFT     6
	u8 flags1;
#define E5_MSTORM_TOE_CONN_AG_CTX_CF0EN_MASK    0x1 /* cf0en */
#define E5_MSTORM_TOE_CONN_AG_CTX_CF0EN_SHIFT   0
#define E5_MSTORM_TOE_CONN_AG_CTX_CF1EN_MASK    0x1 /* cf1en */
#define E5_MSTORM_TOE_CONN_AG_CTX_CF1EN_SHIFT   1
#define E5_MSTORM_TOE_CONN_AG_CTX_CF2EN_MASK    0x1 /* cf2en */
#define E5_MSTORM_TOE_CONN_AG_CTX_CF2EN_SHIFT   2
#define E5_MSTORM_TOE_CONN_AG_CTX_RULE0EN_MASK  0x1 /* rule0en */
#define E5_MSTORM_TOE_CONN_AG_CTX_RULE0EN_SHIFT 3
#define E5_MSTORM_TOE_CONN_AG_CTX_RULE1EN_MASK  0x1 /* rule1en */
#define E5_MSTORM_TOE_CONN_AG_CTX_RULE1EN_SHIFT 4
#define E5_MSTORM_TOE_CONN_AG_CTX_RULE2EN_MASK  0x1 /* rule2en */
#define E5_MSTORM_TOE_CONN_AG_CTX_RULE2EN_SHIFT 5
#define E5_MSTORM_TOE_CONN_AG_CTX_RULE3EN_MASK  0x1 /* rule3en */
#define E5_MSTORM_TOE_CONN_AG_CTX_RULE3EN_SHIFT 6
#define E5_MSTORM_TOE_CONN_AG_CTX_RULE4EN_MASK  0x1 /* rule4en */
#define E5_MSTORM_TOE_CONN_AG_CTX_RULE4EN_SHIFT 7
	__le16 word0 /* word0 */;
	__le16 word1 /* word1 */;
	__le32 reg0 /* reg0 */;
	__le32 reg1 /* reg1 */;
};


struct e5_tstorm_toe_conn_ag_ctx
{
	u8 reserved0 /* cdu_validation */;
	u8 byte1 /* state_and_core_id */;
	u8 flags0;
#define E5_TSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_MASK       0x1 /* exist_in_qm0 */
#define E5_TSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT      0
#define E5_TSTORM_TOE_CONN_AG_CTX_BIT1_MASK               0x1 /* exist_in_qm1 */
#define E5_TSTORM_TOE_CONN_AG_CTX_BIT1_SHIFT              1
#define E5_TSTORM_TOE_CONN_AG_CTX_BIT2_MASK               0x1 /* bit2 */
#define E5_TSTORM_TOE_CONN_AG_CTX_BIT2_SHIFT              2
#define E5_TSTORM_TOE_CONN_AG_CTX_BIT3_MASK               0x1 /* bit3 */
#define E5_TSTORM_TOE_CONN_AG_CTX_BIT3_SHIFT              3
#define E5_TSTORM_TOE_CONN_AG_CTX_BIT4_MASK               0x1 /* bit4 */
#define E5_TSTORM_TOE_CONN_AG_CTX_BIT4_SHIFT              4
#define E5_TSTORM_TOE_CONN_AG_CTX_BIT5_MASK               0x1 /* bit5 */
#define E5_TSTORM_TOE_CONN_AG_CTX_BIT5_SHIFT              5
#define E5_TSTORM_TOE_CONN_AG_CTX_TIMEOUT_CF_MASK         0x3 /* timer0cf */
#define E5_TSTORM_TOE_CONN_AG_CTX_TIMEOUT_CF_SHIFT        6
	u8 flags1;
#define E5_TSTORM_TOE_CONN_AG_CTX_CF1_MASK                0x3 /* timer1cf */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF1_SHIFT               0
#define E5_TSTORM_TOE_CONN_AG_CTX_CF2_MASK                0x3 /* timer2cf */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF2_SHIFT               2
#define E5_TSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_MASK     0x3 /* timer_stop_all */
#define E5_TSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_SHIFT    4
#define E5_TSTORM_TOE_CONN_AG_CTX_CF4_MASK                0x3 /* cf4 */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF4_SHIFT               6
	u8 flags2;
#define E5_TSTORM_TOE_CONN_AG_CTX_CF5_MASK                0x3 /* cf5 */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF5_SHIFT               0
#define E5_TSTORM_TOE_CONN_AG_CTX_CF6_MASK                0x3 /* cf6 */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF6_SHIFT               2
#define E5_TSTORM_TOE_CONN_AG_CTX_CF7_MASK                0x3 /* cf7 */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF7_SHIFT               4
#define E5_TSTORM_TOE_CONN_AG_CTX_CF8_MASK                0x3 /* cf8 */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF8_SHIFT               6
	u8 flags3;
#define E5_TSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_MASK           0x3 /* cf9 */
#define E5_TSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_SHIFT          0
#define E5_TSTORM_TOE_CONN_AG_CTX_CF10_MASK               0x3 /* cf10 */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF10_SHIFT              2
#define E5_TSTORM_TOE_CONN_AG_CTX_TIMEOUT_CF_EN_MASK      0x1 /* cf0en */
#define E5_TSTORM_TOE_CONN_AG_CTX_TIMEOUT_CF_EN_SHIFT     4
#define E5_TSTORM_TOE_CONN_AG_CTX_CF1EN_MASK              0x1 /* cf1en */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF1EN_SHIFT             5
#define E5_TSTORM_TOE_CONN_AG_CTX_CF2EN_MASK              0x1 /* cf2en */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF2EN_SHIFT             6
#define E5_TSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_EN_MASK  0x1 /* cf3en */
#define E5_TSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_EN_SHIFT 7
	u8 flags4;
#define E5_TSTORM_TOE_CONN_AG_CTX_CF4EN_MASK              0x1 /* cf4en */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF4EN_SHIFT             0
#define E5_TSTORM_TOE_CONN_AG_CTX_CF5EN_MASK              0x1 /* cf5en */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF5EN_SHIFT             1
#define E5_TSTORM_TOE_CONN_AG_CTX_CF6EN_MASK              0x1 /* cf6en */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF6EN_SHIFT             2
#define E5_TSTORM_TOE_CONN_AG_CTX_CF7EN_MASK              0x1 /* cf7en */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF7EN_SHIFT             3
#define E5_TSTORM_TOE_CONN_AG_CTX_CF8EN_MASK              0x1 /* cf8en */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF8EN_SHIFT             4
#define E5_TSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_EN_MASK        0x1 /* cf9en */
#define E5_TSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_EN_SHIFT       5
#define E5_TSTORM_TOE_CONN_AG_CTX_CF10EN_MASK             0x1 /* cf10en */
#define E5_TSTORM_TOE_CONN_AG_CTX_CF10EN_SHIFT            6
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE0EN_MASK            0x1 /* rule0en */
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE0EN_SHIFT           7
	u8 flags5;
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE1EN_MASK            0x1 /* rule1en */
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE1EN_SHIFT           0
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE2EN_MASK            0x1 /* rule2en */
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE2EN_SHIFT           1
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE3EN_MASK            0x1 /* rule3en */
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE3EN_SHIFT           2
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE4EN_MASK            0x1 /* rule4en */
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE4EN_SHIFT           3
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE5EN_MASK            0x1 /* rule5en */
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE5EN_SHIFT           4
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE6EN_MASK            0x1 /* rule6en */
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE6EN_SHIFT           5
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE7EN_MASK            0x1 /* rule7en */
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE7EN_SHIFT           6
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE8EN_MASK            0x1 /* rule8en */
#define E5_TSTORM_TOE_CONN_AG_CTX_RULE8EN_SHIFT           7
	u8 flags6;
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED1_MASK       0x1 /* bit6 */
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED1_SHIFT      0
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED2_MASK       0x1 /* bit7 */
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED2_SHIFT      1
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED3_MASK       0x1 /* bit8 */
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED3_SHIFT      2
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED4_MASK       0x3 /* cf11 */
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED4_SHIFT      3
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED5_MASK       0x1 /* cf11en */
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED5_SHIFT      5
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED6_MASK       0x1 /* rule9en */
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED6_SHIFT      6
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED7_MASK       0x1 /* rule10en */
#define E5_TSTORM_TOE_CONN_AG_CTX_E4_RESERVED7_SHIFT      7
	u8 byte2 /* byte2 */;
	__le16 word0 /* word0 */;
	__le32 reg0 /* reg0 */;
	__le32 reg1 /* reg1 */;
	__le32 reg2 /* reg2 */;
	__le32 reg3 /* reg3 */;
	__le32 reg4 /* reg4 */;
	__le32 reg5 /* reg5 */;
	__le32 reg6 /* reg6 */;
	__le32 reg7 /* reg7 */;
	__le32 reg8 /* reg8 */;
};


struct e5_ustorm_toe_conn_ag_ctx
{
	u8 reserved /* cdu_validation */;
	u8 byte1 /* state_and_core_id */;
	u8 flags0;
#define E5_USTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_MASK       0x1 /* exist_in_qm0 */
#define E5_USTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT      0
#define E5_USTORM_TOE_CONN_AG_CTX_BIT1_MASK               0x1 /* exist_in_qm1 */
#define E5_USTORM_TOE_CONN_AG_CTX_BIT1_SHIFT              1
#define E5_USTORM_TOE_CONN_AG_CTX_CF0_MASK                0x3 /* timer0cf */
#define E5_USTORM_TOE_CONN_AG_CTX_CF0_SHIFT               2
#define E5_USTORM_TOE_CONN_AG_CTX_CF1_MASK                0x3 /* timer1cf */
#define E5_USTORM_TOE_CONN_AG_CTX_CF1_SHIFT               4
#define E5_USTORM_TOE_CONN_AG_CTX_PUSH_TIMER_CF_MASK      0x3 /* timer2cf */
#define E5_USTORM_TOE_CONN_AG_CTX_PUSH_TIMER_CF_SHIFT     6
	u8 flags1;
#define E5_USTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_MASK     0x3 /* timer_stop_all */
#define E5_USTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_SHIFT    0
#define E5_USTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_MASK       0x3 /* cf4 */
#define E5_USTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_SHIFT      2
#define E5_USTORM_TOE_CONN_AG_CTX_DQ_CF_MASK              0x3 /* cf5 */
#define E5_USTORM_TOE_CONN_AG_CTX_DQ_CF_SHIFT             4
#define E5_USTORM_TOE_CONN_AG_CTX_CF6_MASK                0x3 /* cf6 */
#define E5_USTORM_TOE_CONN_AG_CTX_CF6_SHIFT               6
	u8 flags2;
#define E5_USTORM_TOE_CONN_AG_CTX_CF0EN_MASK              0x1 /* cf0en */
#define E5_USTORM_TOE_CONN_AG_CTX_CF0EN_SHIFT             0
#define E5_USTORM_TOE_CONN_AG_CTX_CF1EN_MASK              0x1 /* cf1en */
#define E5_USTORM_TOE_CONN_AG_CTX_CF1EN_SHIFT             1
#define E5_USTORM_TOE_CONN_AG_CTX_PUSH_TIMER_CF_EN_MASK   0x1 /* cf2en */
#define E5_USTORM_TOE_CONN_AG_CTX_PUSH_TIMER_CF_EN_SHIFT  2
#define E5_USTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_EN_MASK  0x1 /* cf3en */
#define E5_USTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_EN_SHIFT 3
#define E5_USTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_EN_MASK    0x1 /* cf4en */
#define E5_USTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_EN_SHIFT   4
#define E5_USTORM_TOE_CONN_AG_CTX_DQ_CF_EN_MASK           0x1 /* cf5en */
#define E5_USTORM_TOE_CONN_AG_CTX_DQ_CF_EN_SHIFT          5
#define E5_USTORM_TOE_CONN_AG_CTX_CF6EN_MASK              0x1 /* cf6en */
#define E5_USTORM_TOE_CONN_AG_CTX_CF6EN_SHIFT             6
#define E5_USTORM_TOE_CONN_AG_CTX_RULE0EN_MASK            0x1 /* rule0en */
#define E5_USTORM_TOE_CONN_AG_CTX_RULE0EN_SHIFT           7
	u8 flags3;
#define E5_USTORM_TOE_CONN_AG_CTX_RULE1EN_MASK            0x1 /* rule1en */
#define E5_USTORM_TOE_CONN_AG_CTX_RULE1EN_SHIFT           0
#define E5_USTORM_TOE_CONN_AG_CTX_RULE2EN_MASK            0x1 /* rule2en */
#define E5_USTORM_TOE_CONN_AG_CTX_RULE2EN_SHIFT           1
#define E5_USTORM_TOE_CONN_AG_CTX_RULE3EN_MASK            0x1 /* rule3en */
#define E5_USTORM_TOE_CONN_AG_CTX_RULE3EN_SHIFT           2
#define E5_USTORM_TOE_CONN_AG_CTX_RULE4EN_MASK            0x1 /* rule4en */
#define E5_USTORM_TOE_CONN_AG_CTX_RULE4EN_SHIFT           3
#define E5_USTORM_TOE_CONN_AG_CTX_RULE5EN_MASK            0x1 /* rule5en */
#define E5_USTORM_TOE_CONN_AG_CTX_RULE5EN_SHIFT           4
#define E5_USTORM_TOE_CONN_AG_CTX_RULE6EN_MASK            0x1 /* rule6en */
#define E5_USTORM_TOE_CONN_AG_CTX_RULE6EN_SHIFT           5
#define E5_USTORM_TOE_CONN_AG_CTX_RULE7EN_MASK            0x1 /* rule7en */
#define E5_USTORM_TOE_CONN_AG_CTX_RULE7EN_SHIFT           6
#define E5_USTORM_TOE_CONN_AG_CTX_RULE8EN_MASK            0x1 /* rule8en */
#define E5_USTORM_TOE_CONN_AG_CTX_RULE8EN_SHIFT           7
	u8 flags4;
#define E5_USTORM_TOE_CONN_AG_CTX_E4_RESERVED1_MASK       0x1 /* bit2 */
#define E5_USTORM_TOE_CONN_AG_CTX_E4_RESERVED1_SHIFT      0
#define E5_USTORM_TOE_CONN_AG_CTX_E4_RESERVED2_MASK       0x1 /* bit3 */
#define E5_USTORM_TOE_CONN_AG_CTX_E4_RESERVED2_SHIFT      1
#define E5_USTORM_TOE_CONN_AG_CTX_E4_RESERVED3_MASK       0x3 /* cf7 */
#define E5_USTORM_TOE_CONN_AG_CTX_E4_RESERVED3_SHIFT      2
#define E5_USTORM_TOE_CONN_AG_CTX_E4_RESERVED4_MASK       0x3 /* cf8 */
#define E5_USTORM_TOE_CONN_AG_CTX_E4_RESERVED4_SHIFT      4
#define E5_USTORM_TOE_CONN_AG_CTX_E4_RESERVED5_MASK       0x1 /* cf7en */
#define E5_USTORM_TOE_CONN_AG_CTX_E4_RESERVED5_SHIFT      6
#define E5_USTORM_TOE_CONN_AG_CTX_E4_RESERVED6_MASK       0x1 /* cf8en */
#define E5_USTORM_TOE_CONN_AG_CTX_E4_RESERVED6_SHIFT      7
	u8 byte2 /* byte2 */;
	__le16 word0 /* conn_dpi */;
	__le16 word1 /* word1 */;
	__le32 reg0 /* reg0 */;
	__le32 reg1 /* reg1 */;
	__le32 reg2 /* reg2 */;
	__le32 reg3 /* reg3 */;
	__le16 word2 /* word2 */;
	__le16 word3 /* word3 */;
};


struct e5_xstorm_toe_conn_ag_ctx
{
	u8 reserved0 /* cdu_validation */;
	u8 state_and_core_id /* state_and_core_id */;
	u8 flags0;
#define E5_XSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_MASK          0x1 /* exist_in_qm0 */
#define E5_XSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT         0
#define E5_XSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM1_MASK          0x1 /* exist_in_qm1 */
#define E5_XSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM1_SHIFT         1
#define E5_XSTORM_TOE_CONN_AG_CTX_RESERVED1_MASK             0x1 /* exist_in_qm2 */
#define E5_XSTORM_TOE_CONN_AG_CTX_RESERVED1_SHIFT            2
#define E5_XSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM3_MASK          0x1 /* exist_in_qm3 */
#define E5_XSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM3_SHIFT         3
#define E5_XSTORM_TOE_CONN_AG_CTX_TX_DEC_RULE_RES_MASK       0x1 /* bit4 */
#define E5_XSTORM_TOE_CONN_AG_CTX_TX_DEC_RULE_RES_SHIFT      4
#define E5_XSTORM_TOE_CONN_AG_CTX_RESERVED2_MASK             0x1 /* cf_array_active */
#define E5_XSTORM_TOE_CONN_AG_CTX_RESERVED2_SHIFT            5
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT6_MASK                  0x1 /* bit6 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT6_SHIFT                 6
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT7_MASK                  0x1 /* bit7 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT7_SHIFT                 7
	u8 flags1;
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT8_MASK                  0x1 /* bit8 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT8_SHIFT                 0
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT9_MASK                  0x1 /* bit9 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT9_SHIFT                 1
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT10_MASK                 0x1 /* bit10 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT10_SHIFT                2
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT11_MASK                 0x1 /* bit11 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT11_SHIFT                3
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT12_MASK                 0x1 /* bit12 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT12_SHIFT                4
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT13_MASK                 0x1 /* bit13 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT13_SHIFT                5
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT14_MASK                 0x1 /* bit14 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT14_SHIFT                6
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT15_MASK                 0x1 /* bit15 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT15_SHIFT                7
	u8 flags2;
#define E5_XSTORM_TOE_CONN_AG_CTX_CF0_MASK                   0x3 /* timer0cf */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF0_SHIFT                  0
#define E5_XSTORM_TOE_CONN_AG_CTX_CF1_MASK                   0x3 /* timer1cf */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF1_SHIFT                  2
#define E5_XSTORM_TOE_CONN_AG_CTX_CF2_MASK                   0x3 /* timer2cf */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF2_SHIFT                  4
#define E5_XSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_MASK        0x3 /* timer_stop_all */
#define E5_XSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_SHIFT       6
	u8 flags3;
#define E5_XSTORM_TOE_CONN_AG_CTX_CF4_MASK                   0x3 /* cf4 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF4_SHIFT                  0
#define E5_XSTORM_TOE_CONN_AG_CTX_CF5_MASK                   0x3 /* cf5 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF5_SHIFT                  2
#define E5_XSTORM_TOE_CONN_AG_CTX_CF6_MASK                   0x3 /* cf6 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF6_SHIFT                  4
#define E5_XSTORM_TOE_CONN_AG_CTX_CF7_MASK                   0x3 /* cf7 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF7_SHIFT                  6
	u8 flags4;
#define E5_XSTORM_TOE_CONN_AG_CTX_CF8_MASK                   0x3 /* cf8 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF8_SHIFT                  0
#define E5_XSTORM_TOE_CONN_AG_CTX_CF9_MASK                   0x3 /* cf9 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF9_SHIFT                  2
#define E5_XSTORM_TOE_CONN_AG_CTX_CF10_MASK                  0x3 /* cf10 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF10_SHIFT                 4
#define E5_XSTORM_TOE_CONN_AG_CTX_CF11_MASK                  0x3 /* cf11 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF11_SHIFT                 6
	u8 flags5;
#define E5_XSTORM_TOE_CONN_AG_CTX_CF12_MASK                  0x3 /* cf12 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF12_SHIFT                 0
#define E5_XSTORM_TOE_CONN_AG_CTX_CF13_MASK                  0x3 /* cf13 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF13_SHIFT                 2
#define E5_XSTORM_TOE_CONN_AG_CTX_CF14_MASK                  0x3 /* cf14 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF14_SHIFT                 4
#define E5_XSTORM_TOE_CONN_AG_CTX_CF15_MASK                  0x3 /* cf15 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF15_SHIFT                 6
	u8 flags6;
#define E5_XSTORM_TOE_CONN_AG_CTX_CF16_MASK                  0x3 /* cf16 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF16_SHIFT                 0
#define E5_XSTORM_TOE_CONN_AG_CTX_CF17_MASK                  0x3 /* cf_array_cf */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF17_SHIFT                 2
#define E5_XSTORM_TOE_CONN_AG_CTX_CF18_MASK                  0x3 /* cf18 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF18_SHIFT                 4
#define E5_XSTORM_TOE_CONN_AG_CTX_DQ_FLUSH_MASK              0x3 /* cf19 */
#define E5_XSTORM_TOE_CONN_AG_CTX_DQ_FLUSH_SHIFT             6
	u8 flags7;
#define E5_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_MASK              0x3 /* cf20 */
#define E5_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_SHIFT             0
#define E5_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q1_MASK              0x3 /* cf21 */
#define E5_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q1_SHIFT             2
#define E5_XSTORM_TOE_CONN_AG_CTX_SLOW_PATH_MASK             0x3 /* cf22 */
#define E5_XSTORM_TOE_CONN_AG_CTX_SLOW_PATH_SHIFT            4
#define E5_XSTORM_TOE_CONN_AG_CTX_CF0EN_MASK                 0x1 /* cf0en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF0EN_SHIFT                6
#define E5_XSTORM_TOE_CONN_AG_CTX_CF1EN_MASK                 0x1 /* cf1en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF1EN_SHIFT                7
	u8 flags8;
#define E5_XSTORM_TOE_CONN_AG_CTX_CF2EN_MASK                 0x1 /* cf2en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF2EN_SHIFT                0
#define E5_XSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_EN_MASK     0x1 /* cf3en */
#define E5_XSTORM_TOE_CONN_AG_CTX_TIMER_STOP_ALL_EN_SHIFT    1
#define E5_XSTORM_TOE_CONN_AG_CTX_CF4EN_MASK                 0x1 /* cf4en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF4EN_SHIFT                2
#define E5_XSTORM_TOE_CONN_AG_CTX_CF5EN_MASK                 0x1 /* cf5en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF5EN_SHIFT                3
#define E5_XSTORM_TOE_CONN_AG_CTX_CF6EN_MASK                 0x1 /* cf6en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF6EN_SHIFT                4
#define E5_XSTORM_TOE_CONN_AG_CTX_CF7EN_MASK                 0x1 /* cf7en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF7EN_SHIFT                5
#define E5_XSTORM_TOE_CONN_AG_CTX_CF8EN_MASK                 0x1 /* cf8en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF8EN_SHIFT                6
#define E5_XSTORM_TOE_CONN_AG_CTX_CF9EN_MASK                 0x1 /* cf9en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF9EN_SHIFT                7
	u8 flags9;
#define E5_XSTORM_TOE_CONN_AG_CTX_CF10EN_MASK                0x1 /* cf10en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF10EN_SHIFT               0
#define E5_XSTORM_TOE_CONN_AG_CTX_CF11EN_MASK                0x1 /* cf11en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF11EN_SHIFT               1
#define E5_XSTORM_TOE_CONN_AG_CTX_CF12EN_MASK                0x1 /* cf12en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF12EN_SHIFT               2
#define E5_XSTORM_TOE_CONN_AG_CTX_CF13EN_MASK                0x1 /* cf13en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF13EN_SHIFT               3
#define E5_XSTORM_TOE_CONN_AG_CTX_CF14EN_MASK                0x1 /* cf14en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF14EN_SHIFT               4
#define E5_XSTORM_TOE_CONN_AG_CTX_CF15EN_MASK                0x1 /* cf15en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF15EN_SHIFT               5
#define E5_XSTORM_TOE_CONN_AG_CTX_CF16EN_MASK                0x1 /* cf16en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF16EN_SHIFT               6
#define E5_XSTORM_TOE_CONN_AG_CTX_CF17EN_MASK                0x1 /* cf_array_cf_en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF17EN_SHIFT               7
	u8 flags10;
#define E5_XSTORM_TOE_CONN_AG_CTX_CF18EN_MASK                0x1 /* cf18en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF18EN_SHIFT               0
#define E5_XSTORM_TOE_CONN_AG_CTX_DQ_FLUSH_EN_MASK           0x1 /* cf19en */
#define E5_XSTORM_TOE_CONN_AG_CTX_DQ_FLUSH_EN_SHIFT          1
#define E5_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_EN_MASK           0x1 /* cf20en */
#define E5_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q0_EN_SHIFT          2
#define E5_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q1_EN_MASK           0x1 /* cf21en */
#define E5_XSTORM_TOE_CONN_AG_CTX_FLUSH_Q1_EN_SHIFT          3
#define E5_XSTORM_TOE_CONN_AG_CTX_SLOW_PATH_EN_MASK          0x1 /* cf22en */
#define E5_XSTORM_TOE_CONN_AG_CTX_SLOW_PATH_EN_SHIFT         4
#define E5_XSTORM_TOE_CONN_AG_CTX_CF23EN_MASK                0x1 /* cf23en */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF23EN_SHIFT               5
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE0EN_MASK               0x1 /* rule0en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE0EN_SHIFT              6
#define E5_XSTORM_TOE_CONN_AG_CTX_MORE_TO_SEND_RULE_EN_MASK  0x1 /* rule1en */
#define E5_XSTORM_TOE_CONN_AG_CTX_MORE_TO_SEND_RULE_EN_SHIFT 7
	u8 flags11;
#define E5_XSTORM_TOE_CONN_AG_CTX_TX_BLOCKED_EN_MASK         0x1 /* rule2en */
#define E5_XSTORM_TOE_CONN_AG_CTX_TX_BLOCKED_EN_SHIFT        0
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE3EN_MASK               0x1 /* rule3en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE3EN_SHIFT              1
#define E5_XSTORM_TOE_CONN_AG_CTX_RESERVED3_MASK             0x1 /* rule4en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RESERVED3_SHIFT            2
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE5EN_MASK               0x1 /* rule5en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE5EN_SHIFT              3
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE6EN_MASK               0x1 /* rule6en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE6EN_SHIFT              4
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE7EN_MASK               0x1 /* rule7en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE7EN_SHIFT              5
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED1_MASK          0x1 /* rule8en */
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED1_SHIFT         6
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE9EN_MASK               0x1 /* rule9en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE9EN_SHIFT              7
	u8 flags12;
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE10EN_MASK              0x1 /* rule10en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE10EN_SHIFT             0
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE11EN_MASK              0x1 /* rule11en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE11EN_SHIFT             1
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED2_MASK          0x1 /* rule12en */
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED2_SHIFT         2
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED3_MASK          0x1 /* rule13en */
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED3_SHIFT         3
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE14EN_MASK              0x1 /* rule14en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE14EN_SHIFT             4
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE15EN_MASK              0x1 /* rule15en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE15EN_SHIFT             5
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE16EN_MASK              0x1 /* rule16en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE16EN_SHIFT             6
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE17EN_MASK              0x1 /* rule17en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE17EN_SHIFT             7
	u8 flags13;
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE18EN_MASK              0x1 /* rule18en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE18EN_SHIFT             0
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE19EN_MASK              0x1 /* rule19en */
#define E5_XSTORM_TOE_CONN_AG_CTX_RULE19EN_SHIFT             1
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED4_MASK          0x1 /* rule20en */
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED4_SHIFT         2
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED5_MASK          0x1 /* rule21en */
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED5_SHIFT         3
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED6_MASK          0x1 /* rule22en */
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED6_SHIFT         4
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED7_MASK          0x1 /* rule23en */
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED7_SHIFT         5
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED8_MASK          0x1 /* rule24en */
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED8_SHIFT         6
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED9_MASK          0x1 /* rule25en */
#define E5_XSTORM_TOE_CONN_AG_CTX_A0_RESERVED9_SHIFT         7
	u8 flags14;
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT16_MASK                 0x1 /* bit16 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT16_SHIFT                0
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT17_MASK                 0x1 /* bit17 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT17_SHIFT                1
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT18_MASK                 0x1 /* bit18 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT18_SHIFT                2
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT19_MASK                 0x1 /* bit19 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT19_SHIFT                3
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT20_MASK                 0x1 /* bit20 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT20_SHIFT                4
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT21_MASK                 0x1 /* bit21 */
#define E5_XSTORM_TOE_CONN_AG_CTX_BIT21_SHIFT                5
#define E5_XSTORM_TOE_CONN_AG_CTX_CF23_MASK                  0x3 /* cf23 */
#define E5_XSTORM_TOE_CONN_AG_CTX_CF23_SHIFT                 6
	u8 byte2 /* byte2 */;
	__le16 physical_q0 /* physical_q0 */;
	__le16 physical_q1 /* physical_q1 */;
	__le16 word2 /* physical_q2 */;
	__le16 word3 /* word3 */;
	__le16 bd_prod /* word4 */;
	__le16 word5 /* word5 */;
	__le16 word6 /* conn_dpi */;
	u8 byte3 /* byte3 */;
	u8 byte4 /* byte4 */;
	u8 byte5 /* byte5 */;
	u8 byte6 /* byte6 */;
	__le32 reg0 /* reg0 */;
	__le32 reg1 /* reg1 */;
	__le32 reg2 /* reg2 */;
	__le32 more_to_send_seq /* reg3 */;
	__le32 local_adv_wnd_seq /* reg4 */;
	__le32 reg5 /* cf_array0 */;
	__le32 reg6 /* cf_array1 */;
	u8 flags15;
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED1_MASK          0x1 /* bit22 */
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED1_SHIFT         0
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED2_MASK          0x1 /* bit23 */
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED2_SHIFT         1
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED3_MASK          0x1 /* bit24 */
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED3_SHIFT         2
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED4_MASK          0x3 /* cf24 */
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED4_SHIFT         3
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED5_MASK          0x1 /* cf24en */
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED5_SHIFT         5
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED6_MASK          0x1 /* rule26en */
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED6_SHIFT         6
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED7_MASK          0x1 /* rule27en */
#define E5_XSTORM_TOE_CONN_AG_CTX_E4_RESERVED7_SHIFT         7
	u8 byte7 /* byte7 */;
	__le16 word7 /* word7 */;
	__le16 word8 /* word8 */;
	__le16 word9 /* word9 */;
	__le16 word10 /* word10 */;
	__le16 word11 /* word11 */;
	__le32 reg7 /* reg7 */;
	__le32 reg8 /* reg8 */;
	__le32 reg9 /* reg9 */;
	u8 byte8 /* byte8 */;
	u8 byte9 /* byte9 */;
	u8 byte10 /* byte10 */;
	u8 byte11 /* byte11 */;
	u8 byte12 /* byte12 */;
	u8 byte13 /* byte13 */;
	u8 byte14 /* byte14 */;
	u8 byte15 /* byte15 */;
	__le32 reg10 /* reg10 */;
	__le32 reg11 /* reg11 */;
	__le32 reg12 /* reg12 */;
	__le32 reg13 /* reg13 */;
	__le32 reg14 /* reg14 */;
	__le32 reg15 /* reg15 */;
	__le32 reg16 /* reg16 */;
	__le32 reg17 /* reg17 */;
};


struct e5_ystorm_toe_conn_ag_ctx
{
	u8 byte0 /* cdu_validation */;
	u8 byte1 /* state_and_core_id */;
	u8 flags0;
#define E5_YSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_MASK          0x1 /* exist_in_qm0 */
#define E5_YSTORM_TOE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT         0
#define E5_YSTORM_TOE_CONN_AG_CTX_BIT1_MASK                  0x1 /* exist_in_qm1 */
#define E5_YSTORM_TOE_CONN_AG_CTX_BIT1_SHIFT                 1
#define E5_YSTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_MASK          0x3 /* cf0 */
#define E5_YSTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_SHIFT         2
#define E5_YSTORM_TOE_CONN_AG_CTX_RESET_RECEIVED_CF_MASK     0x3 /* cf1 */
#define E5_YSTORM_TOE_CONN_AG_CTX_RESET_RECEIVED_CF_SHIFT    4
#define E5_YSTORM_TOE_CONN_AG_CTX_CF2_MASK                   0x3 /* cf2 */
#define E5_YSTORM_TOE_CONN_AG_CTX_CF2_SHIFT                  6
	u8 flags1;
#define E5_YSTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_EN_MASK       0x1 /* cf0en */
#define E5_YSTORM_TOE_CONN_AG_CTX_SLOW_PATH_CF_EN_SHIFT      0
#define E5_YSTORM_TOE_CONN_AG_CTX_RESET_RECEIVED_CF_EN_MASK  0x1 /* cf1en */
#define E5_YSTORM_TOE_CONN_AG_CTX_RESET_RECEIVED_CF_EN_SHIFT 1
#define E5_YSTORM_TOE_CONN_AG_CTX_CF2EN_MASK                 0x1 /* cf2en */
#define E5_YSTORM_TOE_CONN_AG_CTX_CF2EN_SHIFT                2
#define E5_YSTORM_TOE_CONN_AG_CTX_REL_SEQ_EN_MASK            0x1 /* rule0en */
#define E5_YSTORM_TOE_CONN_AG_CTX_REL_SEQ_EN_SHIFT           3
#define E5_YSTORM_TOE_CONN_AG_CTX_RULE1EN_MASK               0x1 /* rule1en */
#define E5_YSTORM_TOE_CONN_AG_CTX_RULE1EN_SHIFT              4
#define E5_YSTORM_TOE_CONN_AG_CTX_RULE2EN_MASK               0x1 /* rule2en */
#define E5_YSTORM_TOE_CONN_AG_CTX_RULE2EN_SHIFT              5
#define E5_YSTORM_TOE_CONN_AG_CTX_RULE3EN_MASK               0x1 /* rule3en */
#define E5_YSTORM_TOE_CONN_AG_CTX_RULE3EN_SHIFT              6
#define E5_YSTORM_TOE_CONN_AG_CTX_CONS_PROD_EN_MASK          0x1 /* rule4en */
#define E5_YSTORM_TOE_CONN_AG_CTX_CONS_PROD_EN_SHIFT         7
	u8 completion_opcode /* byte2 */;
	u8 byte3 /* byte3 */;
	__le16 word0 /* word0 */;
	__le32 rel_seq /* reg0 */;
	__le32 rel_seq_threshold /* reg1 */;
	__le16 app_prod /* word1 */;
	__le16 app_cons /* word2 */;
	__le16 word3 /* word3 */;
	__le16 word4 /* word4 */;
	__le32 reg2 /* reg2 */;
	__le32 reg3 /* reg3 */;
};


/*
 * TOE doorbell data
 */
struct toe_db_data
{
	u8 params;
#define TOE_DB_DATA_DEST_MASK         0x3 /* destination of doorbell (use enum db_dest) */
#define TOE_DB_DATA_DEST_SHIFT        0
#define TOE_DB_DATA_AGG_CMD_MASK      0x3 /* aggregative command to CM (use enum db_agg_cmd_sel) */
#define TOE_DB_DATA_AGG_CMD_SHIFT     2
#define TOE_DB_DATA_BYPASS_EN_MASK    0x1 /* enable QM bypass */
#define TOE_DB_DATA_BYPASS_EN_SHIFT   4
#define TOE_DB_DATA_RESERVED_MASK     0x1
#define TOE_DB_DATA_RESERVED_SHIFT    5
#define TOE_DB_DATA_AGG_VAL_SEL_MASK  0x3 /* aggregative value selection */
#define TOE_DB_DATA_AGG_VAL_SEL_SHIFT 6
	u8 agg_flags /* bit for every DQ counter flags in CM context that DQ can increment */;
	__le16 bd_prod;
};

#endif /* __ECORE_HSI_TOE__ */
