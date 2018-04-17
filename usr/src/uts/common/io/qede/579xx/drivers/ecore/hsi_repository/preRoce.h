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

#ifndef __PREROCE__
#define __PREROCE__ 
/********************************/
/* Add include to common target */
/********************************/
#include "common_hsi.h"

/************************/
/* PREROCE FW CONSTANTS */
/************************/

#define		PREROCE_MAX_SGE_PER_SQ_WQE		4		//max number of SGEs in a single request
#define		PREROCE_MAX_MR_SIZE			9000	//max size for MR (temporary firmware limitation)

#define PREROCE_PAGE_SIZE					(0x1000)	//4KB pages

/*
 * The roce storm context of Mstorm
 */
struct mstorm_pre_roce_conn_st_ctx
{
	struct regpair temp[2];
};


/*
 * The roce task context of Mstorm
 */
struct mstorm_pre_roce_task_st_ctx
{
	struct regpair temp[6];
};


/*
 * The roce storm context of Ystorm
 */
struct ystorm_pre_roce_conn_st_ctx
{
	struct regpair temp[4];
};

/*
 * The roce storm context of Mstorm
 */
struct pstorm_pre_roce_conn_st_ctx
{
	struct regpair temp[20];
};

/*
 * The roce storm context of Xstorm
 */
struct xstorm_pre_roce_conn_st_ctx
{
	struct regpair temp[20];
};

struct e4_xstorm_pre_roce_conn_ag_ctx
{
	UCHAR reserved0 /* cdu_validation */;
	UCHAR state /* state */;
	UCHAR flags0;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_MASK         0x1 /* exist_in_qm0 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT        0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED1_MASK            0x1 /* exist_in_qm1 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED1_SHIFT           1
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED2_MASK            0x1 /* exist_in_qm2 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED2_SHIFT           2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM3_MASK         0x1 /* exist_in_qm3 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM3_SHIFT        3
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED3_MASK            0x1 /* bit4 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED3_SHIFT           4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED4_MASK            0x1 /* cf_array_active */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED4_SHIFT           5
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED5_MASK            0x1 /* bit6 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED5_SHIFT           6
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED6_MASK            0x1 /* bit7 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED6_SHIFT           7
	UCHAR flags1;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED7_MASK            0x1 /* bit8 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED7_SHIFT           0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED8_MASK            0x1 /* bit9 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED8_SHIFT           1
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DA_ENABLE_MASK            0x1 /* bit10 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DA_ENABLE_SHIFT           2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT11_MASK                0x1 /* bit11 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT11_SHIFT               3
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT12_MASK                0x1 /* bit12 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT12_SHIFT               4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT13_MASK                0x1 /* bit13 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT13_SHIFT               5
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT14_MASK                0x1 /* bit14 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT14_SHIFT               6
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT15_MASK                0x1 /* bit15 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT15_SHIFT               7
	UCHAR flags2;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF0_MASK                  0x3 /* timer0cf */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF0_SHIFT                 0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF1_MASK                  0x3 /* timer1cf */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF1_SHIFT                 2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF2_MASK                  0x3 /* timer2cf */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF2_SHIFT                 4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_MASK       0x3 /* timer_stop_all */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_SHIFT      6
	UCHAR flags3;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SET_DA_TIMER_CF_MASK      0x3 /* cf4 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SET_DA_TIMER_CF_SHIFT     0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_FORCE_ACK_CF_MASK         0x3 /* cf5 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_FORCE_ACK_CF_SHIFT        2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_IRQ_RXMIT_CF_MASK         0x3 /* cf6 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_IRQ_RXMIT_CF_SHIFT        4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_TMR_RWND_CF_MASK          0x3 /* cf7 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_TMR_RWND_CF_SHIFT         6
	UCHAR flags4;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RXMIT_CF_MASK         0x3 /* cf8 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RXMIT_CF_SHIFT        0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RNR_CF_MASK           0x3 /* cf9 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RNR_CF_SHIFT          2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF10_MASK                 0x3 /* cf10 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF10_SHIFT                4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF11_MASK                 0x3 /* cf11 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF11_SHIFT                6
	UCHAR flags5;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF12_MASK                 0x3 /* cf12 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF12_SHIFT                0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF13_MASK                 0x3 /* cf13 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF13_SHIFT                2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF14_MASK                 0x3 /* cf14 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF14_SHIFT                4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF15_MASK                 0x3 /* cf15 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF15_SHIFT                6
	UCHAR flags6;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_CF_MASK          0x3 /* cf16 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_CF_SHIFT         0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF17_MASK                 0x3 /* cf_array_cf */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF17_SHIFT                2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF18_MASK                 0x3 /* cf18 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF18_SHIFT                4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_MASK             0x3 /* cf19 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_SHIFT            6
	UCHAR flags7;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_MASK             0x3 /* cf20 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_SHIFT            0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED10_MASK           0x3 /* cf21 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED10_SHIFT          2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SLOW_PATH_MASK            0x3 /* cf22 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SLOW_PATH_SHIFT           4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF0EN_MASK                0x1 /* cf0en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF0EN_SHIFT               6
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_MASK                0x1 /* cf1en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_SHIFT               7
	UCHAR flags8;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_MASK                0x1 /* cf2en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_SHIFT               0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_EN_MASK    0x1 /* cf3en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_EN_SHIFT   1
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DA_EXPIRED_MASK           0x1 /* cf4en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DA_EXPIRED_SHIFT          2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_FORCE_ACK_CF_EN_MASK      0x1 /* cf5en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_FORCE_ACK_CF_EN_SHIFT     3
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_IRQ_RXMIT_CF_EN_MASK      0x1 /* cf6en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_IRQ_RXMIT_CF_EN_SHIFT     4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_TMR_RWND_CF_EN_MASK       0x1 /* cf7en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_TMR_RWND_CF_EN_SHIFT      5
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RXMIT_CF_EN_MASK      0x1 /* cf8en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RXMIT_CF_EN_SHIFT     6
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RNR_CF_EN_MASK        0x1 /* cf9en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RNR_CF_EN_SHIFT       7
	UCHAR flags9;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF10EN_MASK               0x1 /* cf10en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF10EN_SHIFT              0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF11EN_MASK               0x1 /* cf11en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF11EN_SHIFT              1
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF12EN_MASK               0x1 /* cf12en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF12EN_SHIFT              2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF13EN_MASK               0x1 /* cf13en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF13EN_SHIFT              3
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF14EN_MASK               0x1 /* cf14en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF14EN_SHIFT              4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF15EN_MASK               0x1 /* cf15en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF15EN_SHIFT              5
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_CF_EN_MASK       0x1 /* cf16en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_CF_EN_SHIFT      6
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF17EN_MASK               0x1 /* cf_array_cf_en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF17EN_SHIFT              7
	UCHAR flags10;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF18EN_MASK               0x1 /* cf18en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_CF18EN_SHIFT              0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_EN_MASK          0x1 /* cf19en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_EN_SHIFT         1
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_EN_MASK          0x1 /* cf20en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_EN_SHIFT         2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED11_MASK           0x1 /* cf21en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED11_SHIFT          3
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SLOW_PATH_EN_MASK         0x1 /* cf22en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SLOW_PATH_EN_SHIFT        4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DPM_DONE_CF_EN_MASK       0x1 /* cf23en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DPM_DONE_CF_EN_SHIFT      5
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED12_MASK           0x1 /* rule0en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED12_SHIFT          6
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED13_MASK           0x1 /* rule1en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED13_SHIFT          7
	UCHAR flags11;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED14_MASK           0x1 /* rule2en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED14_SHIFT          0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED15_MASK           0x1 /* rule3en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED15_SHIFT          1
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED16_MASK           0x1 /* rule4en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED16_SHIFT          2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DA_CNT_EN_MASK            0x1 /* rule5en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DA_CNT_EN_SHIFT           3
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE6EN_MASK              0x1 /* rule6en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE6EN_SHIFT             4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_UNA_EN_MASK           0x1 /* rule7en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_UNA_EN_SHIFT          5
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED1_MASK         0x1 /* rule8en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED1_SHIFT        6
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE9EN_MASK              0x1 /* rule9en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE9EN_SHIFT             7
	UCHAR flags12;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SQ_PROD_EN_MASK           0x1 /* rule10en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SQ_PROD_EN_SHIFT          0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE11EN_MASK             0x1 /* rule11en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE11EN_SHIFT            1
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED2_MASK         0x1 /* rule12en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED2_SHIFT        2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED3_MASK         0x1 /* rule13en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED3_SHIFT        3
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SQ_CMP_CONS_EN_MASK       0x1 /* rule14en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SQ_CMP_CONS_EN_SHIFT      4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SNDLSN_NE_SNDSSN_EN_MASK  0x1 /* rule15en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_SNDLSN_NE_SNDSSN_EN_SHIFT 5
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE16EN_MASK             0x1 /* rule16en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE16EN_SHIFT            6
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE17EN_MASK             0x1 /* rule17en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE17EN_SHIFT            7
	UCHAR flags13;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RCQ_PROD_EN_MASK          0x1 /* rule18en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_RCQ_PROD_EN_SHIFT         0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_HQ_EN_MASK                0x1 /* rule19en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_HQ_EN_SHIFT               1
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED4_MASK         0x1 /* rule20en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED4_SHIFT        2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED5_MASK         0x1 /* rule21en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED5_SHIFT        3
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED6_MASK         0x1 /* rule22en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED6_SHIFT        4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED7_MASK         0x1 /* rule23en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED7_SHIFT        5
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED8_MASK         0x1 /* rule24en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED8_SHIFT        6
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED9_MASK         0x1 /* rule25en */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED9_SHIFT        7
	UCHAR flags14;
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_MIGRATION_MASK            0x1 /* bit16 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_MIGRATION_SHIFT           0
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT17_MASK                0x1 /* bit17 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT17_SHIFT               1
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DPM_PORT_NUM_MASK         0x3 /* bit18 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DPM_PORT_NUM_SHIFT        2
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_L2_EDPM_ENABLE_MASK       0x1 /* bit20 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_L2_EDPM_ENABLE_SHIFT      4
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_ROCE_EDPM_ENABLE_MASK     0x1 /* bit21 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_ROCE_EDPM_ENABLE_SHIFT    5
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DPM_DONE_CF_MASK          0x3 /* cf23 */
		#define E4_XSTORM_PRE_ROCE_CONN_AG_CTX_DPM_DONE_CF_SHIFT         6
	UCHAR da_mode /* byte2 */;
	USHORT physical_q0 /* physical_q0 */;
	USHORT word1 /* physical_q1 */;
	USHORT sq_cmp_cons /* physical_q2 */;
	USHORT sq_cons /* word3 */;
	USHORT sq_prod /* word4 */;
	USHORT word5 /* word5 */;
	USHORT conn_dpi /* conn_dpi */;
	UCHAR da_cnt /* byte3 */;
	UCHAR snd_syn /* byte4 */;
	UCHAR da_threshold /* byte5 */;
	UCHAR da_timeout_value /* byte6 */;
	ULONG snd_una_psn /* reg0 */;
	ULONG snd_una_psn_th /* reg1 */;
	ULONG snd_lsn /* reg2 */;
	ULONG snd_nxt_psn /* reg3 */;
	ULONG reg4 /* reg4 */;
	ULONG snd_ssn /* cf_array0 */;
	ULONG irq_rxmit_psn /* cf_array1 */;
	USHORT rcq_prod /* word7 */;
	USHORT rcq_prod_th /* word8 */;
	USHORT hq_cons_th /* word9 */;
	USHORT hq_cons /* word10 */;
	ULONG ack_msn_syn_to_fe /* reg7 */;
	ULONG ack_psn_to_fe /* reg8 */;
	ULONG inv_stag /* reg9 */;
	UCHAR rxmit_cmd_seq /* byte7 */;
	UCHAR rxmit_seq /* byte8 */;
	UCHAR byte9 /* byte9 */;
	UCHAR byte10 /* byte10 */;
	UCHAR byte11 /* byte11 */;
	UCHAR byte12 /* byte12 */;
	UCHAR byte13 /* byte13 */;
	UCHAR byte14 /* byte14 */;
	UCHAR byte15 /* byte15 */;
	UCHAR e5_reserved /* e5_reserved */;
	USHORT word11 /* word11 */;
};

struct e4_tstorm_pre_roce_conn_ag_ctx
{
	UCHAR reserved0 /* cdu_validation */;
	UCHAR state /* state */;
	UCHAR flags0;
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_MASK       0x1 /* exist_in_qm0 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT      0
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT1_MASK               0x1 /* exist_in_qm1 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT1_SHIFT              1
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT2_MASK               0x1 /* bit2 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT2_SHIFT              2
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT3_MASK               0x1 /* bit3 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT3_SHIFT              3
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT4_MASK               0x1 /* bit4 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT4_SHIFT              4
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT5_MASK               0x1 /* bit5 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT5_SHIFT              5
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMEOUT_MASK            0x3 /* timer0cf */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMEOUT_SHIFT           6
	UCHAR flags1;
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_MASK           0x3 /* timer1cf */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_SHIFT          0
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_SND_DONE_MASK           0x3 /* timer2cf */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_SND_DONE_SHIFT          2
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_MASK     0x3 /* timer_stop_all */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_SHIFT    4
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED_CF_MASK        0x3 /* cf4 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED_CF_SHIFT       6
	UCHAR flags2;
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_MASK           0x3 /* cf5 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_SHIFT          0
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF6_MASK                0x3 /* cf6 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF6_SHIFT               2
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF7_MASK                0x3 /* cf7 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF7_SHIFT               4
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF8_MASK                0x3 /* cf8 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF8_SHIFT               6
	UCHAR flags3;
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF9_MASK                0x3 /* cf9 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF9_SHIFT               0
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF10_MASK               0x3 /* cf10 */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF10_SHIFT              2
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMEOUT_EN_MASK         0x1 /* cf0en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMEOUT_EN_SHIFT        4
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_EN_MASK        0x1 /* cf1en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_EN_SHIFT       5
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_SND_DONE_EN_MASK        0x1 /* cf2en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_SND_DONE_EN_SHIFT       6
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_EN_MASK  0x1 /* cf3en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_EN_SHIFT 7
	UCHAR flags4;
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED_CF_EN_MASK     0x1 /* cf4en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED_CF_EN_SHIFT    0
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_EN_MASK        0x1 /* cf5en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_EN_SHIFT       1
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF6EN_MASK              0x1 /* cf6en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF6EN_SHIFT             2
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF7EN_MASK              0x1 /* cf7en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF7EN_SHIFT             3
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF8EN_MASK              0x1 /* cf8en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF8EN_SHIFT             4
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF9EN_MASK              0x1 /* cf9en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF9EN_SHIFT             5
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF10EN_MASK             0x1 /* cf10en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_CF10EN_SHIFT            6
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RXMIT_SEQ_EN_MASK       0x1 /* rule0en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RXMIT_SEQ_EN_SHIFT      7
	UCHAR flags5;
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RXMIT_SEQ_LAG_EN_MASK   0x1 /* rule1en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RXMIT_SEQ_LAG_EN_SHIFT  0
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_MASK            0x1 /* rule2en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_SHIFT           1
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE3EN_MASK            0x1 /* rule3en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE3EN_SHIFT           2
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_MASK            0x1 /* rule4en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_SHIFT           3
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE5EN_MASK            0x1 /* rule5en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE5EN_SHIFT           4
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE6EN_MASK            0x1 /* rule6en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE6EN_SHIFT           5
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE7EN_MASK            0x1 /* rule7en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE7EN_SHIFT           6
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE8EN_MASK            0x1 /* rule8en */
		#define E4_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE8EN_SHIFT           7
	ULONG reg0 /* reg0 */;
	ULONG reg1 /* reg1 */;
	ULONG snd_max_psn /* reg2 */;
	ULONG orq_prod /* reg3 */;
	ULONG irq_cons /* reg4 */;
	ULONG snd_nxt_psn /* reg5 */;
	ULONG reg6 /* reg6 */;
	ULONG irq_rxmit_psn_echo /* reg7 */;
	ULONG trcq_cons /* reg8 */;
	UCHAR rxmit_seq /* byte2 */;
	UCHAR rxmit_seq_echo /* byte3 */;
	USHORT rq_prod /* word0 */;
	UCHAR byte4 /* byte4 */;
	UCHAR byte5 /* byte5 */;
	USHORT word1 /* word1 */;
	USHORT conn_dpi /* conn_dpi */;
	USHORT word3 /* word3 */;
	ULONG reg9 /* reg9 */;
	ULONG reg10 /* reg10 */;
};

struct e4_ustorm_pre_roce_conn_ag_ctx
{
	UCHAR reserved /* cdu_validation */;
	UCHAR byte1 /* state */;
	UCHAR flags0;
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_MASK     0x1 /* exist_in_qm0 */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT    0
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_BIT1_MASK             0x1 /* exist_in_qm1 */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_BIT1_SHIFT            1
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF0_MASK              0x3 /* timer0cf */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF0_SHIFT             2
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF1_MASK              0x3 /* timer1cf */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF1_SHIFT             4
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF2_MASK              0x3 /* timer2cf */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF2_SHIFT             6
	UCHAR flags1;
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF3_MASK              0x3 /* timer_stop_all */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF3_SHIFT             0
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_SE_CF_MASK     0x3 /* cf4 */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_SE_CF_SHIFT    2
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_CF_MASK        0x3 /* cf5 */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_CF_SHIFT       4
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF6_MASK              0x3 /* cf6 */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF6_SHIFT             6
	UCHAR flags2;
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF0EN_MASK            0x1 /* cf0en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF0EN_SHIFT           0
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_MASK            0x1 /* cf1en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_SHIFT           1
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_MASK            0x1 /* cf2en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_SHIFT           2
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF3EN_MASK            0x1 /* cf3en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF3EN_SHIFT           3
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_SE_CF_EN_MASK  0x1 /* cf4en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_SE_CF_EN_SHIFT 4
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_CF_EN_MASK     0x1 /* cf5en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_CF_EN_SHIFT    5
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF6EN_MASK            0x1 /* cf6en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CF6EN_SHIFT           6
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_SE_EN_MASK         0x1 /* rule0en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_SE_EN_SHIFT        7
	UCHAR flags3;
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_EN_MASK            0x1 /* rule1en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_EN_SHIFT           0
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_MASK          0x1 /* rule2en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_SHIFT         1
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE3EN_MASK          0x1 /* rule3en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE3EN_SHIFT         2
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_MASK          0x1 /* rule4en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_SHIFT         3
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE5EN_MASK          0x1 /* rule5en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE5EN_SHIFT         4
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE6EN_MASK          0x1 /* rule6en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE6EN_SHIFT         5
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE7EN_MASK          0x1 /* rule7en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE7EN_SHIFT         6
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE8EN_MASK          0x1 /* rule8en */
		#define E4_USTORM_PRE_ROCE_CONN_AG_CTX_RULE8EN_SHIFT         7
	UCHAR byte2 /* byte2 */;
	UCHAR byte3 /* byte3 */;
	USHORT conn_dpi /* conn_dpi */;
	USHORT word1 /* word1 */;
	ULONG cq_cons /* reg0 */;
	ULONG cq_se_prod /* reg1 */;
	ULONG cq_prod /* reg2 */;
	ULONG reg3 /* reg3 */;
	USHORT word2 /* word2 */;
	USHORT word3 /* word3 */;
};

/*
 * The roce storm context of Tstorm
 */
struct tstorm_pre_roce_conn_st_ctx
{
	struct regpair temp[14];
};

/*
 * The roce storm context of Ystorm
 */
struct ustorm_pre_roce_conn_st_ctx
{
	struct regpair temp[2];
};

/*
 * pre_roce connection context
 */
struct pre_roce_conn_context
{
	struct ystorm_pre_roce_conn_st_ctx ystorm_st_context /* ystorm storm context */;
	struct pstorm_pre_roce_conn_st_ctx pstorm_st_context /* pstorm storm context */;
	struct xstorm_pre_roce_conn_st_ctx xstorm_st_context /* xstorm storm context */;
	struct e4_xstorm_pre_roce_conn_ag_ctx xstorm_ag_context /* xstorm aggregative context */;
	struct regpair xstorm_ag_padding[4] /* padding */;
	struct e4_tstorm_pre_roce_conn_ag_ctx tstorm_ag_context /* tstorm aggregative context */;
	struct timers_context timer_context /* timer context */;
	struct e4_ustorm_pre_roce_conn_ag_ctx ustorm_ag_context /* ustorm aggregative context */;
	struct tstorm_pre_roce_conn_st_ctx tstorm_st_context /* tstorm storm context */;
	struct regpair tstorm_st_padding[2] /* padding */;
	struct mstorm_pre_roce_conn_st_ctx mstorm_st_context /* mstorm storm context */;
	struct regpair mstorm_st_padding[2] /* padding */;
	struct ustorm_pre_roce_conn_st_ctx ustorm_st_context /* ustorm storm context */;
	struct regpair ustorm_st_padding[2] /* padding */;
};


/*
 * roce protocol connection states
 */
enum pre_roce_conn_state
{
	PREROCE_STATE_REQ_CONNECTION=0,
	PREROCE_STATE_RESP_CONNECTION=4,
	MAX_PRE_ROCE_CONN_STATE
};


/*
 * roce connection type: requestor/responder
 */
enum pre_roce_conn_type
{
	PREROCE_CONN_TYPE_REQ=0,
	PREROCE_CONN_TYPE_RESP=1,
	MAX_PRE_ROCE_CONN_TYPE
};


/*
 * CQE of a regular requester completion
 */
struct pre_roce_cqe_requester
{
	UCHAR type /* CQE type (0 in roce_cqe_requester) */;
	UCHAR reserved0;
	USHORT sq_cons /* Send-queue consumer */;
	ULONG reserved1;
	struct regpair qp_handle /* pointer to QP handle in driver memory */;
	ULONG reserved2[4];
};

/*
 * CQE of a regular responder completion
 */
struct pre_roce_cqe_responder
{
	UCHAR type /* CQE type (1 in roce_cqe_responder) */;
	UCHAR flags;
		#define PRE_ROCE_CQE_RESPONDER_INVALIDATE_MASK  0x1 /* Set in case of SEND_WITH_INVALIDATE completion */
		#define PRE_ROCE_CQE_RESPONDER_INVALIDATE_SHIFT 0
		#define PRE_ROCE_CQE_RESPONDER_SRQ_MASK         0x1 /* Set in case SRQ was used */
		#define PRE_ROCE_CQE_RESPONDER_SRQ_SHIFT        1
		#define PRE_ROCE_CQE_RESPONDER_IMMEDIATE_MASK   0x1 /* Set in case immediate data */
		#define PRE_ROCE_CQE_RESPONDER_IMMEDIATE_SHIFT  2
		#define PRE_ROCE_CQE_RESPONDER_RESERVED0_MASK   0x1F
		#define PRE_ROCE_CQE_RESPONDER_RESERVED0_SHIFT  3
	USHORT reserved1;
	ULONG length /* Length of the data placed */;
	struct regpair qp_handle /* pointer to QP handle in driver memory */;
	struct regpair srq_handle /* pointer to SQR handle in driver memory (in case SRQ was used) */;
	ULONG r_key /* The invalidated r_key in case of SEND_WITH_INVALIDATE */;
	ULONG immData /* The immediate data in case on SEND_WITH_IMMEDIATE or RDMA_WRITE_WITH_IMMEDIATE */;
};

/*
 * CQE of an error notification
 */
struct pre_roce_cqe_error
{
	UCHAR type /* CQE type (2/3 in roce_cqe_error) */;
	UCHAR err_code;
	USHORT reserved0;
	ULONG err_data;
	struct regpair qp_handle /* pointer to QP handle in driver memory */;
	ULONG reserved1[4];
};

union pre_roce_cqe
{
	struct pre_roce_cqe_requester req /* CQE of a regular requester completion */;
	struct pre_roce_cqe_responder resp /* CQE of a regular responder completion */;
	struct pre_roce_cqe_error err /* CQE of an error notification */;
};





/*
 * CQE type enumeration
 */
enum pre_roce_cqe_type
{
	PREROCE_REQUESTER_COMP,
	PREROCE_RESPONDER_COMP,
	PREROCE_REQUSTER_ERR,
	PREROCE_RESPONDER_ERR,
	MAX_PRE_ROCE_CQE_TYPE
};


struct pre_roce_eqe_data
{
	ULONG cq_id;
	USHORT cq_prod /* CQ producer index of the FW */;
	USHORT reserved;
};


/*
 * opcodes for the event ring
 */
enum pre_roce_event_opcode
{
	PREROCE_EVENT_UNUSED,
	PREROCE_EVENT_COMP,
	MAX_PRE_ROCE_EVENT_OPCODE
};


/*
 * MR state enum
 */
enum pre_roce_mr_state
{
	PREROCE_FREE,
	PREROCE_INVALID,
	PREROCE_VALID,
	MAX_PRE_ROCE_MR_STATE
};


/*
 * Scather/Gather element used for packets data placement/transmission 
 */
struct pre_roce_sge
{
	struct regpair va /* virtual address of SGE beginning */;
	ULONG l_key /* local key of MR */;
	ULONG length /* length of the sge */;
};


/*
 * Second WQEs for RMDA write
 */
struct pre_roce_sq_rdma_write_second_wqe
{
	ULONG remote_key /* Remote key */;
	struct regpair va /* Remote virtual address */;
	ULONG reserved;
};


/*
 * SQ WQE req type enumeration
 */
enum pre_roce_sq_req_type
{
	PREROCE_REQ_TYPE_SEND,
	PREROCE_REQ_TYPE_SEND_WITH_INVALIDATE,
	PREROCE_REQ_TYPE_SEND_WITH_IMMEDIATE,
	PREROCE_REQ_TYPE_LOCAL_INVALIDATE,
	PREROCE_REQ_TYPE_RDMA_WRITE,
	PREROCE_REQ_TYPE_RDMA_WRITE_WITH_IMMEDIATE,
	PREROCE_REQ_TYPE_INVALID,
	MAX_PRE_ROCE_SQ_REQ_TYPE
};


struct pre_roce_sq_wqe_struct
{
	UCHAR req_type /* Type of WQE */;
	UCHAR flags;
		#define PRE_ROCE_SQ_WQE_STRUCT_COMP_FLAG_MASK       0x1 /* If set, completion will be generated when the WQE is completed */
		#define PRE_ROCE_SQ_WQE_STRUCT_COMP_FLAG_SHIFT      0
		#define PRE_ROCE_SQ_WQE_STRUCT_RD_FENCE_FLAG_MASK   0x1 /* If set, all pending READ operations will be completed before start processing this WQE */
		#define PRE_ROCE_SQ_WQE_STRUCT_RD_FENCE_FLAG_SHIFT  1
		#define PRE_ROCE_SQ_WQE_STRUCT_INV_FENCE_FLAG_MASK  0x1 /* If set, all pending LOCAL_INVALIDATE operations will be completed before start processing this WQE */
		#define PRE_ROCE_SQ_WQE_STRUCT_INV_FENCE_FLAG_SHIFT 2
		#define PRE_ROCE_SQ_WQE_STRUCT_SE_FLAG_MASK         0x1 /* If set, signal the responder to generate a solicited event on this WQE */
		#define PRE_ROCE_SQ_WQE_STRUCT_SE_FLAG_SHIFT        3
		#define PRE_ROCE_SQ_WQE_STRUCT_NUM_SGES_MASK        0x7 /* Number of SGEs following this WQE (up to 4) */
		#define PRE_ROCE_SQ_WQE_STRUCT_NUM_SGES_SHIFT       4
		#define PRE_ROCE_SQ_WQE_STRUCT_RESERVED0_MASK       0x1
		#define PRE_ROCE_SQ_WQE_STRUCT_RESERVED0_SHIFT      7
	USHORT reserved1;
	ULONG data_2_trans /* Total data to transfer in bytes */;
	ULONG invalidate_key /* In case of SEND_WITH_INVALIDATE, this is the r_key to invalidate. In case of LOCAL_INVALIDATE, this is the l_key to invalidate */;
	ULONG imm_data /* In case of send with immediate or RDMA write with immediate, this is the immediate data */;
};


/*
 * The roce task context of Mstorm
 */
struct ystorm_pre_roce_task_st_ctx
{
	struct regpair temp[6];
};

struct e4_ystorm_pre_roce_task_ag_ctx
{
	UCHAR reserved /* cdu_validation */;
	UCHAR byte1 /* state */;
	USHORT icid /* icid */;
	UCHAR flags0;
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_CONNECTION_TYPE_MASK   0xF /* connection_type */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_CONNECTION_TYPE_SHIFT  0
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_EXIST_IN_QM0_MASK      0x1 /* exist_in_qm0 */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_EXIST_IN_QM0_SHIFT     4
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_BIT1_MASK              0x1 /* exist_in_qm1 */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_BIT1_SHIFT             5
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_VALID_MASK             0x1 /* bit2 */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_VALID_SHIFT            6
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_BIT3_MASK              0x1 /* bit3 */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_BIT3_SHIFT             7
	UCHAR flags1;
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_CF0_MASK               0x3 /* cf0 */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_CF0_SHIFT              0
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_CF1_MASK               0x3 /* cf1 */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_CF1_SHIFT              2
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_CF2SPECIAL_MASK        0x3 /* cf2special */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_CF2SPECIAL_SHIFT       4
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_MASK             0x1 /* cf0en */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_SHIFT            6
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_MASK             0x1 /* cf1en */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_SHIFT            7
	UCHAR flags2;
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_BIT4_MASK              0x1 /* bit4 */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_BIT4_SHIFT             0
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_EQ_EN_MASK  0x1 /* rule0en */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_EQ_EN_SHIFT 1
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_NE_EN_MASK  0x1 /* rule1en */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_NE_EN_SHIFT 2
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_EQ_EN_MASK  0x1 /* rule2en */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_EQ_EN_SHIFT 3
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_NE_EN_MASK  0x1 /* rule3en */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_NE_EN_SHIFT 4
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_MASK           0x1 /* rule4en */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_SHIFT          5
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_MASK           0x1 /* rule5en */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_SHIFT          6
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_RULE6EN_MASK           0x1 /* rule6en */
		#define E4_YSTORM_PRE_ROCE_TASK_AG_CTX_RULE6EN_SHIFT          7
	UCHAR rx_ref_count /* byte2 */;
	ULONG mw_cnt /* reg0 */;
	UCHAR rx_ref_count_th /* byte3 */;
	UCHAR byte4 /* byte4 */;
	USHORT word1 /* word1 */;
	USHORT tx_ref_count /* word2 */;
	USHORT tx_ref_count_th /* word3 */;
	USHORT word4 /* word4 */;
	USHORT word5 /* word5 */;
	ULONG reg1 /* reg1 */;
	ULONG reg2 /* reg2 */;
};

struct e4_mstorm_pre_roce_task_ag_ctx
{
	UCHAR reserved /* cdu_validation */;
	UCHAR byte1 /* state */;
	USHORT icid /* icid */;
	UCHAR flags0;
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CONNECTION_TYPE_MASK   0xF /* connection_type */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CONNECTION_TYPE_SHIFT  0
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_EXIST_IN_QM0_MASK      0x1 /* exist_in_qm0 */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_EXIST_IN_QM0_SHIFT     4
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_BIT1_MASK              0x1 /* exist_in_qm1 */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_BIT1_SHIFT             5
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_VALID_MASK             0x1 /* bit2 */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_VALID_SHIFT            6
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_BIT3_MASK              0x1 /* bit3 */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_BIT3_SHIFT             7
	UCHAR flags1;
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CF0_MASK               0x3 /* cf0 */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CF0_SHIFT              0
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CF1_MASK               0x3 /* cf1 */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CF1_SHIFT              2
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CF2_MASK               0x3 /* cf2 */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CF2_SHIFT              4
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_MASK             0x1 /* cf0en */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_SHIFT            6
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_MASK             0x1 /* cf1en */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_SHIFT            7
	UCHAR flags2;
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CF2EN_MASK             0x1 /* cf2en */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_CF2EN_SHIFT            0
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_EQ_EN_MASK  0x1 /* rule0en */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_EQ_EN_SHIFT 1
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_NE_EN_MASK  0x1 /* rule1en */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_NE_EN_SHIFT 2
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_EQ_EN_MASK  0x1 /* rule2en */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_EQ_EN_SHIFT 3
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_NE_EN_MASK  0x1 /* rule3en */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_NE_EN_SHIFT 4
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_MASK           0x1 /* rule4en */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_SHIFT          5
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_MASK           0x1 /* rule5en */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_SHIFT          6
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_RULE6EN_MASK           0x1 /* rule6en */
		#define E4_MSTORM_PRE_ROCE_TASK_AG_CTX_RULE6EN_SHIFT          7
	UCHAR rx_ref_count /* byte2 */;
	ULONG mw_cnt /* reg0 */;
	UCHAR rx_ref_count_th /* byte3 */;
	UCHAR byte4 /* byte4 */;
	USHORT word1 /* word1 */;
	USHORT tx_ref_count /* word2 */;
	USHORT tx_ref_count_th /* word3 */;
	USHORT word4 /* word4 */;
	USHORT word5 /* word5 */;
	ULONG reg1 /* reg1 */;
	ULONG reg2 /* reg2 */;
};

/*
 * pre_roce task context
 */
struct pre_roce_task_context
{
	struct ystorm_pre_roce_task_st_ctx ystorm_st_context /* ystorm storm context */;
	struct regpair ystorm_st_padding[2] /* padding */;
	struct e4_ystorm_pre_roce_task_ag_ctx ystorm_ag_context /* ystorm aggregative context */;
	struct e4_mstorm_pre_roce_task_ag_ctx mstorm_ag_context /* mstorm aggregative context */;
	struct mstorm_pre_roce_task_st_ctx mstorm_st_context /* mstorm storm context */;
	struct regpair mstorm_st_padding[2] /* padding */;
};








struct e4_mstorm_pre_roce_conn_ag_ctx
{
	UCHAR reserved /* cdu_validation */;
	UCHAR byte1 /* state */;
	UCHAR flags0;
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_MASK         0x1 /* exist_in_qm0 */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT        0
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_BIT1_MASK                 0x1 /* exist_in_qm1 */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_BIT1_SHIFT                1
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_DONE_CF_MASK     0x3 /* cf0 */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_DONE_CF_SHIFT    2
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_CF1_MASK                  0x3 /* cf1 */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_CF1_SHIFT                 4
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_CF2_MASK                  0x3 /* cf2 */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_CF2_SHIFT                 6
	UCHAR flags1;
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_DONE_CF_EN_MASK  0x1 /* cf0en */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_DONE_CF_EN_SHIFT 0
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_MASK                0x1 /* cf1en */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_SHIFT               1
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_MASK                0x1 /* cf2en */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_SHIFT               2
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE0EN_MASK              0x1 /* rule0en */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE0EN_SHIFT             3
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE1EN_MASK              0x1 /* rule1en */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE1EN_SHIFT             4
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_MASK              0x1 /* rule2en */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_SHIFT             5
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_RCQ_CONS_EN_MASK          0x1 /* rule3en */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_RCQ_CONS_EN_SHIFT         6
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_MASK              0x1 /* rule4en */
		#define E4_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_SHIFT             7
	USHORT rcq_cons /* word0 */;
	USHORT rcq_cons_th /* word1 */;
	ULONG reg0 /* reg0 */;
	ULONG reg1 /* reg1 */;
};




struct e4_tstorm_pre_roce_task_ag_ctx
{
	UCHAR byte0 /* cdu_validation */;
	UCHAR byte1 /* state */;
	USHORT word0 /* icid */;
	UCHAR flags0;
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_NIBBLE0_MASK  0xF /* connection_type */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_NIBBLE0_SHIFT 0
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT0_MASK     0x1 /* exist_in_qm0 */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT0_SHIFT    4
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT1_MASK     0x1 /* exist_in_qm1 */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT1_SHIFT    5
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT2_MASK     0x1 /* bit2 */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT2_SHIFT    6
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT3_MASK     0x1 /* bit3 */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT3_SHIFT    7
	UCHAR flags1;
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT4_MASK     0x1 /* bit4 */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT4_SHIFT    0
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT5_MASK     0x1 /* bit5 */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT5_SHIFT    1
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF0_MASK      0x3 /* timer0cf */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF0_SHIFT     2
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF1_MASK      0x3 /* timer1cf */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF1_SHIFT     4
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF2_MASK      0x3 /* timer2cf */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF2_SHIFT     6
	UCHAR flags2;
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF3_MASK      0x3 /* timer_stop_all */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF3_SHIFT     0
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF4_MASK      0x3 /* cf4 */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF4_SHIFT     2
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF5_MASK      0x3 /* cf5 */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF5_SHIFT     4
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF6_MASK      0x3 /* cf6 */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF6_SHIFT     6
	UCHAR flags3;
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF7_MASK      0x3 /* cf7 */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF7_SHIFT     0
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_MASK    0x1 /* cf0en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_SHIFT   2
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_MASK    0x1 /* cf1en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_SHIFT   3
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF2EN_MASK    0x1 /* cf2en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF2EN_SHIFT   4
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF3EN_MASK    0x1 /* cf3en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF3EN_SHIFT   5
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF4EN_MASK    0x1 /* cf4en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF4EN_SHIFT   6
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF5EN_MASK    0x1 /* cf5en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF5EN_SHIFT   7
	UCHAR flags4;
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF6EN_MASK    0x1 /* cf6en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF6EN_SHIFT   0
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF7EN_MASK    0x1 /* cf7en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_CF7EN_SHIFT   1
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE0EN_MASK  0x1 /* rule0en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE0EN_SHIFT 2
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE1EN_MASK  0x1 /* rule1en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE1EN_SHIFT 3
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE2EN_MASK  0x1 /* rule2en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE2EN_SHIFT 4
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE3EN_MASK  0x1 /* rule3en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE3EN_SHIFT 5
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_MASK  0x1 /* rule4en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_SHIFT 6
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_MASK  0x1 /* rule5en */
		#define E4_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_SHIFT 7
	UCHAR byte2 /* byte2 */;
	USHORT word1 /* word1 */;
	ULONG reg0 /* reg0 */;
	UCHAR byte3 /* byte3 */;
	UCHAR byte4 /* byte4 */;
	USHORT word2 /* word2 */;
	USHORT word3 /* word3 */;
	USHORT word4 /* word4 */;
	ULONG reg1 /* reg1 */;
	ULONG reg2 /* reg2 */;
};



struct e4_ustorm_pre_roce_task_ag_ctx
{
	UCHAR byte0 /* cdu_validation */;
	UCHAR byte1 /* state */;
	USHORT word0 /* icid */;
	UCHAR flags0;
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_NIBBLE0_MASK  0xF /* connection_type */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_NIBBLE0_SHIFT 0
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_BIT0_MASK     0x1 /* exist_in_qm0 */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_BIT0_SHIFT    4
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_BIT1_MASK     0x1 /* exist_in_qm1 */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_BIT1_SHIFT    5
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF0_MASK      0x3 /* timer0cf */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF0_SHIFT     6
	UCHAR flags1;
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF1_MASK      0x3 /* timer1cf */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF1_SHIFT     0
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF2_MASK      0x3 /* timer2cf */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF2_SHIFT     2
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF3_MASK      0x3 /* timer_stop_all */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF3_SHIFT     4
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF4_MASK      0x3 /* cf4 */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF4_SHIFT     6
	UCHAR flags2;
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_MASK    0x1 /* cf0en */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_SHIFT   0
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_MASK    0x1 /* cf1en */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_SHIFT   1
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF2EN_MASK    0x1 /* cf2en */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF2EN_SHIFT   2
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF3EN_MASK    0x1 /* cf3en */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF3EN_SHIFT   3
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF4EN_MASK    0x1 /* cf4en */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_CF4EN_SHIFT   4
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE0EN_MASK  0x1 /* rule0en */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE0EN_SHIFT 5
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE1EN_MASK  0x1 /* rule1en */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE1EN_SHIFT 6
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE2EN_MASK  0x1 /* rule2en */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE2EN_SHIFT 7
	UCHAR flags3;
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE3EN_MASK  0x1 /* rule3en */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE3EN_SHIFT 0
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_MASK  0x1 /* rule4en */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_SHIFT 1
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_MASK  0x1 /* rule5en */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_SHIFT 2
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE6EN_MASK  0x1 /* rule6en */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_RULE6EN_SHIFT 3
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_NIBBLE1_MASK  0xF /* nibble1 */
		#define E4_USTORM_PRE_ROCE_TASK_AG_CTX_NIBBLE1_SHIFT 4
	ULONG reg0 /* reg0 */;
	ULONG reg1 /* reg1 */;
	ULONG reg2 /* reg2 */;
	ULONG reg3 /* reg3 */;
	ULONG reg4 /* reg4 */;
	ULONG reg5 /* reg5 */;
	UCHAR byte2 /* byte2 */;
	UCHAR byte3 /* byte3 */;
	USHORT word1 /* word1 */;
	USHORT word2 /* word2 */;
	USHORT word3 /* word3 */;
	ULONG reg6 /* reg6 */;
	ULONG reg7 /* reg7 */;
};



struct e4_ystorm_pre_roce_conn_ag_ctx
{
	UCHAR byte0 /* cdu_validation */;
	UCHAR byte1 /* state */;
	UCHAR flags0;
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_BIT0_MASK     0x1 /* exist_in_qm0 */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_BIT0_SHIFT    0
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_BIT1_MASK     0x1 /* exist_in_qm1 */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_BIT1_SHIFT    1
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_CF0_MASK      0x3 /* cf0 */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_CF0_SHIFT     2
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_CF1_MASK      0x3 /* cf1 */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_CF1_SHIFT     4
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_CF2_MASK      0x3 /* cf2 */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_CF2_SHIFT     6
	UCHAR flags1;
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_CF0EN_MASK    0x1 /* cf0en */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_CF0EN_SHIFT   0
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_MASK    0x1 /* cf1en */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_SHIFT   1
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_MASK    0x1 /* cf2en */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_SHIFT   2
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE0EN_MASK  0x1 /* rule0en */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE0EN_SHIFT 3
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE1EN_MASK  0x1 /* rule1en */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE1EN_SHIFT 4
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_MASK  0x1 /* rule2en */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_SHIFT 5
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE3EN_MASK  0x1 /* rule3en */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE3EN_SHIFT 6
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_MASK  0x1 /* rule4en */
		#define E4_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_SHIFT 7
	UCHAR byte2 /* byte2 */;
	UCHAR byte3 /* byte3 */;
	USHORT word0 /* word0 */;
	ULONG reg0 /* reg0 */;
	ULONG reg1 /* reg1 */;
	USHORT word1 /* word1 */;
	USHORT word2 /* word2 */;
	USHORT word3 /* word3 */;
	USHORT word4 /* word4 */;
	ULONG reg2 /* reg2 */;
	ULONG reg3 /* reg3 */;
};



struct e5_mstorm_pre_roce_conn_ag_ctx
{
	UCHAR reserved /* cdu_validation */;
	UCHAR byte1 /* state_and_core_id */;
	UCHAR flags0;
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_MASK         0x1 /* exist_in_qm0 */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT        0
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_BIT1_MASK                 0x1 /* exist_in_qm1 */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_BIT1_SHIFT                1
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_DONE_CF_MASK     0x3 /* cf0 */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_DONE_CF_SHIFT    2
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_CF1_MASK                  0x3 /* cf1 */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_CF1_SHIFT                 4
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_CF2_MASK                  0x3 /* cf2 */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_CF2_SHIFT                 6
	UCHAR flags1;
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_DONE_CF_EN_MASK  0x1 /* cf0en */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_DONE_CF_EN_SHIFT 0
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_MASK                0x1 /* cf1en */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_SHIFT               1
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_MASK                0x1 /* cf2en */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_SHIFT               2
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE0EN_MASK              0x1 /* rule0en */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE0EN_SHIFT             3
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE1EN_MASK              0x1 /* rule1en */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE1EN_SHIFT             4
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_MASK              0x1 /* rule2en */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_SHIFT             5
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_RCQ_CONS_EN_MASK          0x1 /* rule3en */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_RCQ_CONS_EN_SHIFT         6
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_MASK              0x1 /* rule4en */
		#define E5_MSTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_SHIFT             7
	USHORT rcq_cons /* word0 */;
	USHORT rcq_cons_th /* word1 */;
	ULONG reg0 /* reg0 */;
	ULONG reg1 /* reg1 */;
};


struct e5_mstorm_pre_roce_task_ag_ctx
{
	UCHAR reserved /* cdu_validation */;
	UCHAR byte1 /* state_and_core_id */;
	USHORT icid /* icid */;
	UCHAR flags0;
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CONNECTION_TYPE_MASK   0xF /* connection_type */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CONNECTION_TYPE_SHIFT  0
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_EXIST_IN_QM0_MASK      0x1 /* exist_in_qm0 */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_EXIST_IN_QM0_SHIFT     4
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_BIT1_MASK              0x1 /* exist_in_qm1 */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_BIT1_SHIFT             5
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_VALID_MASK             0x1 /* bit2 */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_VALID_SHIFT            6
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_BIT3_MASK              0x1 /* bit3 */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_BIT3_SHIFT             7
	UCHAR flags1;
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CF0_MASK               0x3 /* cf0 */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CF0_SHIFT              0
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CF1_MASK               0x3 /* cf1 */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CF1_SHIFT              2
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CF2_MASK               0x3 /* cf2 */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CF2_SHIFT              4
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_MASK             0x1 /* cf0en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_SHIFT            6
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_MASK             0x1 /* cf1en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_SHIFT            7
	UCHAR flags2;
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CF2EN_MASK             0x1 /* cf2en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_CF2EN_SHIFT            0
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_EQ_EN_MASK  0x1 /* rule0en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_EQ_EN_SHIFT 1
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_NE_EN_MASK  0x1 /* rule1en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_NE_EN_SHIFT 2
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_EQ_EN_MASK  0x1 /* rule2en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_EQ_EN_SHIFT 3
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_NE_EN_MASK  0x1 /* rule3en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_NE_EN_SHIFT 4
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_MASK           0x1 /* rule4en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_SHIFT          5
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_MASK           0x1 /* rule5en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_SHIFT          6
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_RULE6EN_MASK           0x1 /* rule6en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_RULE6EN_SHIFT          7
	UCHAR flags3;
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED1_MASK      0x1 /* bit4 */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED1_SHIFT     0
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED2_MASK      0x3 /* cf3 */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED2_SHIFT     1
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED3_MASK      0x3 /* cf4 */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED3_SHIFT     3
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED4_MASK      0x1 /* cf3en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED4_SHIFT     5
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED5_MASK      0x1 /* cf4en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED5_SHIFT     6
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED6_MASK      0x1 /* rule7en */
		#define E5_MSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED6_SHIFT     7
	ULONG mw_cnt /* reg0 */;
	UCHAR rx_ref_count /* byte2 */;
	UCHAR rx_ref_count_th /* byte3 */;
	UCHAR byte4 /* byte4 */;
	UCHAR e4_reserved7 /* byte5 */;
	USHORT word1 /* regpair0 */;
	USHORT tx_ref_count /* word2 */;
	USHORT tx_ref_count_th /* word3 */;
	USHORT word4 /* word4 */;
	USHORT word5 /* regpair1 */;
	USHORT e4_reserved8 /* word6 */;
	ULONG reg1 /* reg1 */;
};


struct e5_tstorm_pre_roce_conn_ag_ctx
{
	UCHAR reserved0 /* cdu_validation */;
	UCHAR state_and_core_id /* state_and_core_id */;
	UCHAR flags0;
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_MASK       0x1 /* exist_in_qm0 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT      0
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT1_MASK               0x1 /* exist_in_qm1 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT1_SHIFT              1
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT2_MASK               0x1 /* bit2 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT2_SHIFT              2
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT3_MASK               0x1 /* bit3 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT3_SHIFT              3
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT4_MASK               0x1 /* bit4 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT4_SHIFT              4
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT5_MASK               0x1 /* bit5 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_BIT5_SHIFT              5
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMEOUT_MASK            0x3 /* timer0cf */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMEOUT_SHIFT           6
	UCHAR flags1;
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_MASK           0x3 /* timer1cf */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_SHIFT          0
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_SND_DONE_MASK           0x3 /* timer2cf */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_SND_DONE_SHIFT          2
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_MASK     0x3 /* timer_stop_all */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_SHIFT    4
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED_CF_MASK        0x3 /* cf4 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED_CF_SHIFT       6
	UCHAR flags2;
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_MASK           0x3 /* cf5 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_SHIFT          0
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF6_MASK                0x3 /* cf6 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF6_SHIFT               2
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF7_MASK                0x3 /* cf7 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF7_SHIFT               4
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF8_MASK                0x3 /* cf8 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF8_SHIFT               6
	UCHAR flags3;
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF9_MASK                0x3 /* cf9 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF9_SHIFT               0
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF10_MASK               0x3 /* cf10 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF10_SHIFT              2
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMEOUT_EN_MASK         0x1 /* cf0en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMEOUT_EN_SHIFT        4
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_EN_MASK        0x1 /* cf1en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_EN_SHIFT       5
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_SND_DONE_EN_MASK        0x1 /* cf2en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_SND_DONE_EN_SHIFT       6
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_EN_MASK  0x1 /* cf3en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_EN_SHIFT 7
	UCHAR flags4;
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED_CF_EN_MASK     0x1 /* cf4en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED_CF_EN_SHIFT    0
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_EN_MASK        0x1 /* cf5en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_EN_SHIFT       1
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF6EN_MASK              0x1 /* cf6en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF6EN_SHIFT             2
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF7EN_MASK              0x1 /* cf7en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF7EN_SHIFT             3
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF8EN_MASK              0x1 /* cf8en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF8EN_SHIFT             4
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF9EN_MASK              0x1 /* cf9en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF9EN_SHIFT             5
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF10EN_MASK             0x1 /* cf10en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_CF10EN_SHIFT            6
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RXMIT_SEQ_EN_MASK       0x1 /* rule0en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RXMIT_SEQ_EN_SHIFT      7
	UCHAR flags5;
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RXMIT_SEQ_LAG_EN_MASK   0x1 /* rule1en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RXMIT_SEQ_LAG_EN_SHIFT  0
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_MASK            0x1 /* rule2en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_SHIFT           1
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE3EN_MASK            0x1 /* rule3en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE3EN_SHIFT           2
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_MASK            0x1 /* rule4en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_SHIFT           3
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE5EN_MASK            0x1 /* rule5en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE5EN_SHIFT           4
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE6EN_MASK            0x1 /* rule6en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE6EN_SHIFT           5
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE7EN_MASK            0x1 /* rule7en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE7EN_SHIFT           6
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE8EN_MASK            0x1 /* rule8en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_RULE8EN_SHIFT           7
	UCHAR flags6;
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED1_MASK       0x1 /* bit6 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED1_SHIFT      0
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED2_MASK       0x1 /* bit7 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED2_SHIFT      1
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED3_MASK       0x1 /* bit8 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED3_SHIFT      2
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED4_MASK       0x3 /* cf11 */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED4_SHIFT      3
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED5_MASK       0x1 /* cf11en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED5_SHIFT      5
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED6_MASK       0x1 /* rule9en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED6_SHIFT      6
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED7_MASK       0x1 /* rule10en */
		#define E5_TSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED7_SHIFT      7
	UCHAR rxmit_seq /* byte2 */;
	USHORT rq_prod /* word0 */;
	ULONG reg0 /* reg0 */;
	ULONG reg1 /* reg1 */;
	ULONG snd_max_psn /* reg2 */;
	ULONG orq_prod /* reg3 */;
	ULONG irq_cons /* reg4 */;
	ULONG snd_nxt_psn /* reg5 */;
	ULONG reg6 /* reg6 */;
	ULONG irq_rxmit_psn_echo /* reg7 */;
	ULONG trcq_cons /* reg8 */;
	UCHAR rxmit_seq_echo /* byte3 */;
	UCHAR byte4 /* byte4 */;
	UCHAR byte5 /* byte5 */;
	UCHAR e4_reserved8 /* byte6 */;
	USHORT word1 /* word1 */;
	USHORT conn_dpi /* conn_dpi */;
	ULONG reg9 /* reg9 */;
	USHORT word3 /* word3 */;
	USHORT e4_reserved9 /* word4 */;
};


struct e5_tstorm_pre_roce_task_ag_ctx
{
	UCHAR byte0 /* cdu_validation */;
	UCHAR byte1 /* state_and_core_id */;
	USHORT word0 /* icid */;
	UCHAR flags0;
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_NIBBLE0_MASK  0xF /* connection_type */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_NIBBLE0_SHIFT 0
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT0_MASK     0x1 /* exist_in_qm0 */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT0_SHIFT    4
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT1_MASK     0x1 /* exist_in_qm1 */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT1_SHIFT    5
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT2_MASK     0x1 /* bit2 */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT2_SHIFT    6
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT3_MASK     0x1 /* bit3 */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT3_SHIFT    7
	UCHAR flags1;
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT4_MASK     0x1 /* bit4 */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT4_SHIFT    0
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT5_MASK     0x1 /* bit5 */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_BIT5_SHIFT    1
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF0_MASK      0x3 /* timer0cf */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF0_SHIFT     2
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF1_MASK      0x3 /* timer1cf */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF1_SHIFT     4
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF2_MASK      0x3 /* timer2cf */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF2_SHIFT     6
	UCHAR flags2;
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF3_MASK      0x3 /* timer_stop_all */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF3_SHIFT     0
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF4_MASK      0x3 /* cf4 */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF4_SHIFT     2
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF5_MASK      0x3 /* cf5 */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF5_SHIFT     4
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF6_MASK      0x3 /* cf6 */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF6_SHIFT     6
	UCHAR flags3;
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF7_MASK      0x3 /* cf7 */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF7_SHIFT     0
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_MASK    0x1 /* cf0en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_SHIFT   2
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_MASK    0x1 /* cf1en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_SHIFT   3
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF2EN_MASK    0x1 /* cf2en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF2EN_SHIFT   4
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF3EN_MASK    0x1 /* cf3en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF3EN_SHIFT   5
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF4EN_MASK    0x1 /* cf4en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF4EN_SHIFT   6
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF5EN_MASK    0x1 /* cf5en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF5EN_SHIFT   7
	UCHAR flags4;
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF6EN_MASK    0x1 /* cf6en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF6EN_SHIFT   0
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF7EN_MASK    0x1 /* cf7en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_CF7EN_SHIFT   1
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE0EN_MASK  0x1 /* rule0en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE0EN_SHIFT 2
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE1EN_MASK  0x1 /* rule1en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE1EN_SHIFT 3
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE2EN_MASK  0x1 /* rule2en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE2EN_SHIFT 4
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE3EN_MASK  0x1 /* rule3en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE3EN_SHIFT 5
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_MASK  0x1 /* rule4en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_SHIFT 6
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_MASK  0x1 /* rule5en */
		#define E5_TSTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_SHIFT 7
	UCHAR byte2 /* byte2 */;
	USHORT word1 /* word1 */;
	ULONG reg0 /* reg0 */;
	UCHAR byte3 /* regpair0 */;
	UCHAR byte4 /* byte4 */;
	USHORT word2 /* word2 */;
	USHORT word3 /* word3 */;
	USHORT word4 /* word4 */;
	ULONG reg1 /* regpair1 */;
	ULONG reg2 /* reg2 */;
};


struct e5_ustorm_pre_roce_conn_ag_ctx
{
	UCHAR reserved /* cdu_validation */;
	UCHAR byte1 /* state_and_core_id */;
	UCHAR flags0;
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_MASK     0x1 /* exist_in_qm0 */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT    0
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_BIT1_MASK             0x1 /* exist_in_qm1 */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_BIT1_SHIFT            1
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF0_MASK              0x3 /* timer0cf */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF0_SHIFT             2
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF1_MASK              0x3 /* timer1cf */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF1_SHIFT             4
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF2_MASK              0x3 /* timer2cf */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF2_SHIFT             6
	UCHAR flags1;
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF3_MASK              0x3 /* timer_stop_all */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF3_SHIFT             0
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_SE_CF_MASK     0x3 /* cf4 */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_SE_CF_SHIFT    2
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_CF_MASK        0x3 /* cf5 */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_CF_SHIFT       4
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF6_MASK              0x3 /* cf6 */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF6_SHIFT             6
	UCHAR flags2;
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF0EN_MASK            0x1 /* cf0en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF0EN_SHIFT           0
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_MASK            0x1 /* cf1en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_SHIFT           1
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_MASK            0x1 /* cf2en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_SHIFT           2
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF3EN_MASK            0x1 /* cf3en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF3EN_SHIFT           3
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_SE_CF_EN_MASK  0x1 /* cf4en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_SE_CF_EN_SHIFT 4
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_CF_EN_MASK     0x1 /* cf5en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_ARM_CF_EN_SHIFT    5
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF6EN_MASK            0x1 /* cf6en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CF6EN_SHIFT           6
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_SE_EN_MASK         0x1 /* rule0en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_SE_EN_SHIFT        7
	UCHAR flags3;
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_EN_MASK            0x1 /* rule1en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_CQ_EN_SHIFT           0
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_MASK          0x1 /* rule2en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_SHIFT         1
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE3EN_MASK          0x1 /* rule3en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE3EN_SHIFT         2
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_MASK          0x1 /* rule4en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_SHIFT         3
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE5EN_MASK          0x1 /* rule5en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE5EN_SHIFT         4
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE6EN_MASK          0x1 /* rule6en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE6EN_SHIFT         5
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE7EN_MASK          0x1 /* rule7en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE7EN_SHIFT         6
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE8EN_MASK          0x1 /* rule8en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_RULE8EN_SHIFT         7
	UCHAR flags4;
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED1_MASK     0x1 /* bit2 */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED1_SHIFT    0
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED2_MASK     0x1 /* bit3 */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED2_SHIFT    1
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED3_MASK     0x3 /* cf7 */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED3_SHIFT    2
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED4_MASK     0x3 /* cf8 */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED4_SHIFT    4
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED5_MASK     0x1 /* cf7en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED5_SHIFT    6
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED6_MASK     0x1 /* cf8en */
		#define E5_USTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED6_SHIFT    7
	UCHAR byte2 /* byte2 */;
	USHORT conn_dpi /* conn_dpi */;
	USHORT word1 /* word1 */;
	ULONG cq_cons /* reg0 */;
	ULONG cq_se_prod /* reg1 */;
	ULONG cq_prod /* reg2 */;
	ULONG reg3 /* reg3 */;
	USHORT word2 /* word2 */;
	USHORT word3 /* word3 */;
};


struct e5_ustorm_pre_roce_task_ag_ctx
{
	UCHAR byte0 /* cdu_validation */;
	UCHAR byte1 /* state_and_core_id */;
	USHORT word0 /* icid */;
	UCHAR flags0;
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_NIBBLE0_MASK       0xF /* connection_type */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_NIBBLE0_SHIFT      0
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_BIT0_MASK          0x1 /* exist_in_qm0 */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_BIT0_SHIFT         4
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_BIT1_MASK          0x1 /* exist_in_qm1 */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_BIT1_SHIFT         5
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF0_MASK           0x3 /* timer0cf */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF0_SHIFT          6
	UCHAR flags1;
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF1_MASK           0x3 /* timer1cf */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF1_SHIFT          0
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF2_MASK           0x3 /* timer2cf */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF2_SHIFT          2
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF3_MASK           0x3 /* timer_stop_all */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF3_SHIFT          4
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF4_MASK           0x3 /* dif_error_cf */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF4_SHIFT          6
	UCHAR flags2;
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_MASK         0x1 /* cf0en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_SHIFT        0
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_MASK         0x1 /* cf1en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_SHIFT        1
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF2EN_MASK         0x1 /* cf2en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF2EN_SHIFT        2
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF3EN_MASK         0x1 /* cf3en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF3EN_SHIFT        3
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF4EN_MASK         0x1 /* cf4en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_CF4EN_SHIFT        4
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE0EN_MASK       0x1 /* rule0en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE0EN_SHIFT      5
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE1EN_MASK       0x1 /* rule1en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE1EN_SHIFT      6
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE2EN_MASK       0x1 /* rule2en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE2EN_SHIFT      7
	UCHAR flags3;
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE3EN_MASK       0x1 /* rule3en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE3EN_SHIFT      0
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_MASK       0x1 /* rule4en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_SHIFT      1
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_MASK       0x1 /* rule5en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_SHIFT      2
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE6EN_MASK       0x1 /* rule6en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_RULE6EN_SHIFT      3
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED1_MASK  0x1 /* bit2 */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED1_SHIFT 4
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED2_MASK  0x1 /* bit3 */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED2_SHIFT 5
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED3_MASK  0x1 /* bit4 */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED3_SHIFT 6
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED4_MASK  0x1 /* rule7en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED4_SHIFT 7
	UCHAR flags4;
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED5_MASK  0x3 /* cf5 */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED5_SHIFT 0
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED6_MASK  0x1 /* cf5en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED6_SHIFT 2
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED7_MASK  0x1 /* rule8en */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED7_SHIFT 3
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_NIBBLE1_MASK       0xF /* dif_error_type */
		#define E5_USTORM_PRE_ROCE_TASK_AG_CTX_NIBBLE1_SHIFT      4
	UCHAR byte2 /* byte2 */;
	UCHAR byte3 /* byte3 */;
	UCHAR e4_reserved8 /* byte4 */;
	ULONG reg0 /* dif_err_intervals */;
	ULONG reg1 /* dif_error_1st_interval */;
	ULONG reg2 /* reg2 */;
	ULONG reg3 /* reg3 */;
	ULONG reg4 /* reg4 */;
	ULONG reg5 /* reg5 */;
	USHORT word1 /* word1 */;
	USHORT word2 /* word2 */;
	ULONG reg6 /* reg6 */;
	ULONG reg7 /* reg7 */;
};


struct e5_xstorm_pre_roce_conn_ag_ctx
{
	UCHAR reserved0 /* cdu_validation */;
	UCHAR state_and_core_id /* state_and_core_id */;
	UCHAR flags0;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_MASK         0x1 /* exist_in_qm0 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM0_SHIFT        0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED1_MASK            0x1 /* exist_in_qm1 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED1_SHIFT           1
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED2_MASK            0x1 /* exist_in_qm2 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED2_SHIFT           2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM3_MASK         0x1 /* exist_in_qm3 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_EXIST_IN_QM3_SHIFT        3
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED3_MASK            0x1 /* bit4 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED3_SHIFT           4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED4_MASK            0x1 /* cf_array_active */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED4_SHIFT           5
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED5_MASK            0x1 /* bit6 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED5_SHIFT           6
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED6_MASK            0x1 /* bit7 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED6_SHIFT           7
	UCHAR flags1;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED7_MASK            0x1 /* bit8 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED7_SHIFT           0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED8_MASK            0x1 /* bit9 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED8_SHIFT           1
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DA_ENABLE_MASK            0x1 /* bit10 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DA_ENABLE_SHIFT           2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT11_MASK                0x1 /* bit11 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT11_SHIFT               3
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT12_MASK                0x1 /* bit12 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT12_SHIFT               4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT13_MASK                0x1 /* bit13 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT13_SHIFT               5
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT14_MASK                0x1 /* bit14 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT14_SHIFT               6
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT15_MASK                0x1 /* bit15 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT15_SHIFT               7
	UCHAR flags2;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF0_MASK                  0x3 /* timer0cf */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF0_SHIFT                 0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF1_MASK                  0x3 /* timer1cf */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF1_SHIFT                 2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF2_MASK                  0x3 /* timer2cf */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF2_SHIFT                 4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_MASK       0x3 /* timer_stop_all */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_SHIFT      6
	UCHAR flags3;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SET_DA_TIMER_CF_MASK      0x3 /* cf4 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SET_DA_TIMER_CF_SHIFT     0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_FORCE_ACK_CF_MASK         0x3 /* cf5 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_FORCE_ACK_CF_SHIFT        2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_IRQ_RXMIT_CF_MASK         0x3 /* cf6 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_IRQ_RXMIT_CF_SHIFT        4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_TMR_RWND_CF_MASK          0x3 /* cf7 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_TMR_RWND_CF_SHIFT         6
	UCHAR flags4;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RXMIT_CF_MASK         0x3 /* cf8 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RXMIT_CF_SHIFT        0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RNR_CF_MASK           0x3 /* cf9 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RNR_CF_SHIFT          2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF10_MASK                 0x3 /* cf10 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF10_SHIFT                4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF11_MASK                 0x3 /* cf11 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF11_SHIFT                6
	UCHAR flags5;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF12_MASK                 0x3 /* cf12 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF12_SHIFT                0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF13_MASK                 0x3 /* cf13 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF13_SHIFT                2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF14_MASK                 0x3 /* cf14 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF14_SHIFT                4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF15_MASK                 0x3 /* cf15 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF15_SHIFT                6
	UCHAR flags6;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_CF_MASK          0x3 /* cf16 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_CF_SHIFT         0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF17_MASK                 0x3 /* cf_array_cf */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF17_SHIFT                2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF18_MASK                 0x3 /* cf18 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF18_SHIFT                4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_MASK             0x3 /* cf19 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_SHIFT            6
	UCHAR flags7;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_MASK             0x3 /* cf20 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_SHIFT            0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED10_MASK           0x3 /* cf21 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED10_SHIFT          2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SLOW_PATH_MASK            0x3 /* cf22 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SLOW_PATH_SHIFT           4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF0EN_MASK                0x1 /* cf0en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF0EN_SHIFT               6
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_MASK                0x1 /* cf1en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_SHIFT               7
	UCHAR flags8;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_MASK                0x1 /* cf2en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_SHIFT               0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_EN_MASK    0x1 /* cf3en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_TIMER_STOP_ALL_EN_SHIFT   1
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DA_EXPIRED_MASK           0x1 /* cf4en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DA_EXPIRED_SHIFT          2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_FORCE_ACK_CF_EN_MASK      0x1 /* cf5en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_FORCE_ACK_CF_EN_SHIFT     3
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_IRQ_RXMIT_CF_EN_MASK      0x1 /* cf6en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_IRQ_RXMIT_CF_EN_SHIFT     4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_TMR_RWND_CF_EN_MASK       0x1 /* cf7en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_TMR_RWND_CF_EN_SHIFT      5
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RXMIT_CF_EN_MASK      0x1 /* cf8en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RXMIT_CF_EN_SHIFT     6
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RNR_CF_EN_MASK        0x1 /* cf9en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_RNR_CF_EN_SHIFT       7
	UCHAR flags9;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF10EN_MASK               0x1 /* cf10en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF10EN_SHIFT              0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF11EN_MASK               0x1 /* cf11en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF11EN_SHIFT              1
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF12EN_MASK               0x1 /* cf12en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF12EN_SHIFT              2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF13EN_MASK               0x1 /* cf13en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF13EN_SHIFT              3
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF14EN_MASK               0x1 /* cf14en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF14EN_SHIFT              4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF15EN_MASK               0x1 /* cf15en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF15EN_SHIFT              5
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_CF_EN_MASK       0x1 /* cf16en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_INV_STAG_CF_EN_SHIFT      6
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF17EN_MASK               0x1 /* cf_array_cf_en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF17EN_SHIFT              7
	UCHAR flags10;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF18EN_MASK               0x1 /* cf18en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_CF18EN_SHIFT              0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_EN_MASK          0x1 /* cf19en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DQ_FLUSH_EN_SHIFT         1
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_EN_MASK          0x1 /* cf20en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_FLUSH_Q0_EN_SHIFT         2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED11_MASK           0x1 /* cf21en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED11_SHIFT          3
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SLOW_PATH_EN_MASK         0x1 /* cf22en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SLOW_PATH_EN_SHIFT        4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DPM_DONE_CF_EN_MASK       0x1 /* cf23en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DPM_DONE_CF_EN_SHIFT      5
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED12_MASK           0x1 /* rule0en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED12_SHIFT          6
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED13_MASK           0x1 /* rule1en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED13_SHIFT          7
	UCHAR flags11;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED14_MASK           0x1 /* rule2en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED14_SHIFT          0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED15_MASK           0x1 /* rule3en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED15_SHIFT          1
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED16_MASK           0x1 /* rule4en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RESERVED16_SHIFT          2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DA_CNT_EN_MASK            0x1 /* rule5en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DA_CNT_EN_SHIFT           3
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE6EN_MASK              0x1 /* rule6en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE6EN_SHIFT             4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_UNA_EN_MASK           0x1 /* rule7en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SND_UNA_EN_SHIFT          5
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED1_MASK         0x1 /* rule8en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED1_SHIFT        6
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE9EN_MASK              0x1 /* rule9en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE9EN_SHIFT             7
	UCHAR flags12;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SQ_PROD_EN_MASK           0x1 /* rule10en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SQ_PROD_EN_SHIFT          0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE11EN_MASK             0x1 /* rule11en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE11EN_SHIFT            1
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED2_MASK         0x1 /* rule12en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED2_SHIFT        2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED3_MASK         0x1 /* rule13en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED3_SHIFT        3
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SQ_CMP_CONS_EN_MASK       0x1 /* rule14en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SQ_CMP_CONS_EN_SHIFT      4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SNDLSN_NE_SNDSSN_EN_MASK  0x1 /* rule15en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_SNDLSN_NE_SNDSSN_EN_SHIFT 5
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE16EN_MASK             0x1 /* rule16en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE16EN_SHIFT            6
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE17EN_MASK             0x1 /* rule17en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RULE17EN_SHIFT            7
	UCHAR flags13;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RCQ_PROD_EN_MASK          0x1 /* rule18en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_RCQ_PROD_EN_SHIFT         0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_HQ_EN_MASK                0x1 /* rule19en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_HQ_EN_SHIFT               1
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED4_MASK         0x1 /* rule20en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED4_SHIFT        2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED5_MASK         0x1 /* rule21en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED5_SHIFT        3
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED6_MASK         0x1 /* rule22en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED6_SHIFT        4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED7_MASK         0x1 /* rule23en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED7_SHIFT        5
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED8_MASK         0x1 /* rule24en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED8_SHIFT        6
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED9_MASK         0x1 /* rule25en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_A0_RESERVED9_SHIFT        7
	UCHAR flags14;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_MIGRATION_MASK            0x1 /* bit16 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_MIGRATION_SHIFT           0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT17_MASK                0x1 /* bit17 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_BIT17_SHIFT               1
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DPM_PORT_NUM_MASK         0x3 /* bit18 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DPM_PORT_NUM_SHIFT        2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_L2_EDPM_ENABLE_MASK       0x1 /* bit20 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_L2_EDPM_ENABLE_SHIFT      4
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_ROCE_EDPM_ENABLE_MASK     0x1 /* bit21 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_ROCE_EDPM_ENABLE_SHIFT    5
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DPM_DONE_CF_MASK          0x3 /* cf23 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_DPM_DONE_CF_SHIFT         6
	UCHAR da_mode /* byte2 */;
	USHORT physical_q0 /* physical_q0 */;
	USHORT word1 /* physical_q1 */;
	USHORT sq_cmp_cons /* physical_q2 */;
	USHORT sq_cons /* word3 */;
	USHORT sq_prod /* word4 */;
	USHORT word5 /* word5 */;
	USHORT conn_dpi /* conn_dpi */;
	UCHAR da_cnt /* byte3 */;
	UCHAR snd_syn /* byte4 */;
	UCHAR da_threshold /* byte5 */;
	UCHAR da_timeout_value /* byte6 */;
	ULONG snd_una_psn /* reg0 */;
	ULONG snd_una_psn_th /* reg1 */;
	ULONG snd_lsn /* reg2 */;
	ULONG snd_nxt_psn /* reg3 */;
	ULONG reg4 /* reg4 */;
	ULONG snd_ssn /* cf_array0 */;
	ULONG irq_rxmit_psn /* cf_array1 */;
	UCHAR flags15;
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED1_MASK         0x1 /* bit22 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED1_SHIFT        0
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED2_MASK         0x1 /* bit23 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED2_SHIFT        1
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED3_MASK         0x1 /* bit24 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED3_SHIFT        2
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED4_MASK         0x3 /* cf24 */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED4_SHIFT        3
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED5_MASK         0x1 /* cf24en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED5_SHIFT        5
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED6_MASK         0x1 /* rule26en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED6_SHIFT        6
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED7_MASK         0x1 /* rule27en */
		#define E5_XSTORM_PRE_ROCE_CONN_AG_CTX_E4_RESERVED7_SHIFT        7
	UCHAR rxmit_cmd_seq /* byte7 */;
	USHORT rcq_prod /* word7 */;
	USHORT rcq_prod_th /* word8 */;
	USHORT hq_cons_th /* word9 */;
	USHORT hq_cons /* word10 */;
	USHORT word11 /* word11 */;
	ULONG ack_msn_syn_to_fe /* reg7 */;
	ULONG ack_psn_to_fe /* reg8 */;
	ULONG inv_stag /* reg9 */;
	UCHAR rxmit_seq /* byte8 */;
	UCHAR byte9 /* byte9 */;
	UCHAR byte10 /* byte10 */;
	UCHAR byte11 /* byte11 */;
	UCHAR byte12 /* byte12 */;
	UCHAR byte13 /* byte13 */;
	UCHAR byte14 /* byte14 */;
	UCHAR byte15 /* byte15 */;
};


struct e5_ystorm_pre_roce_conn_ag_ctx
{
	UCHAR byte0 /* cdu_validation */;
	UCHAR byte1 /* state_and_core_id */;
	UCHAR flags0;
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_BIT0_MASK     0x1 /* exist_in_qm0 */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_BIT0_SHIFT    0
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_BIT1_MASK     0x1 /* exist_in_qm1 */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_BIT1_SHIFT    1
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_CF0_MASK      0x3 /* cf0 */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_CF0_SHIFT     2
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_CF1_MASK      0x3 /* cf1 */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_CF1_SHIFT     4
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_CF2_MASK      0x3 /* cf2 */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_CF2_SHIFT     6
	UCHAR flags1;
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_CF0EN_MASK    0x1 /* cf0en */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_CF0EN_SHIFT   0
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_MASK    0x1 /* cf1en */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_CF1EN_SHIFT   1
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_MASK    0x1 /* cf2en */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_CF2EN_SHIFT   2
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE0EN_MASK  0x1 /* rule0en */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE0EN_SHIFT 3
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE1EN_MASK  0x1 /* rule1en */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE1EN_SHIFT 4
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_MASK  0x1 /* rule2en */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE2EN_SHIFT 5
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE3EN_MASK  0x1 /* rule3en */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE3EN_SHIFT 6
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_MASK  0x1 /* rule4en */
		#define E5_YSTORM_PRE_ROCE_CONN_AG_CTX_RULE4EN_SHIFT 7
	UCHAR byte2 /* byte2 */;
	UCHAR byte3 /* byte3 */;
	USHORT word0 /* word0 */;
	ULONG reg0 /* reg0 */;
	ULONG reg1 /* reg1 */;
	USHORT word1 /* word1 */;
	USHORT word2 /* word2 */;
	USHORT word3 /* word3 */;
	USHORT word4 /* word4 */;
	ULONG reg2 /* reg2 */;
	ULONG reg3 /* reg3 */;
};


struct e5_ystorm_pre_roce_task_ag_ctx
{
	UCHAR reserved /* cdu_validation */;
	UCHAR byte1 /* state_and_core_id */;
	USHORT icid /* icid */;
	UCHAR flags0;
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_CONNECTION_TYPE_MASK   0xF /* connection_type */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_CONNECTION_TYPE_SHIFT  0
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_EXIST_IN_QM0_MASK      0x1 /* exist_in_qm0 */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_EXIST_IN_QM0_SHIFT     4
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_BIT1_MASK              0x1 /* exist_in_qm1 */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_BIT1_SHIFT             5
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_VALID_MASK             0x1 /* bit2 */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_VALID_SHIFT            6
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_BIT3_MASK              0x1 /* bit3 */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_BIT3_SHIFT             7
	UCHAR flags1;
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_CF0_MASK               0x3 /* cf0 */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_CF0_SHIFT              0
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_CF1_MASK               0x3 /* cf1 */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_CF1_SHIFT              2
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_CF2SPECIAL_MASK        0x3 /* cf2special */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_CF2SPECIAL_SHIFT       4
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_MASK             0x1 /* cf0en */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_CF0EN_SHIFT            6
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_MASK             0x1 /* cf1en */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_CF1EN_SHIFT            7
	UCHAR flags2;
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_BIT4_MASK              0x1 /* bit4 */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_BIT4_SHIFT             0
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_EQ_EN_MASK  0x1 /* rule0en */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_EQ_EN_SHIFT 1
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_NE_EN_MASK  0x1 /* rule1en */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_RX_REF_CNT_NE_EN_SHIFT 2
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_EQ_EN_MASK  0x1 /* rule2en */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_EQ_EN_SHIFT 3
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_NE_EN_MASK  0x1 /* rule3en */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_TX_REF_CNT_NE_EN_SHIFT 4
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_MASK           0x1 /* rule4en */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_RULE4EN_SHIFT          5
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_MASK           0x1 /* rule5en */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_RULE5EN_SHIFT          6
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_RULE6EN_MASK           0x1 /* rule6en */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_RULE6EN_SHIFT          7
	UCHAR flags3;
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED1_MASK      0x1 /* bit5 */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED1_SHIFT     0
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED2_MASK      0x3 /* cf3 */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED2_SHIFT     1
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED3_MASK      0x3 /* cf4 */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED3_SHIFT     3
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED4_MASK      0x1 /* cf3en */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED4_SHIFT     5
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED5_MASK      0x1 /* cf4en */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED5_SHIFT     6
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED6_MASK      0x1 /* rule7en */
		#define E5_YSTORM_PRE_ROCE_TASK_AG_CTX_E4_RESERVED6_SHIFT     7
	ULONG mw_cnt /* reg0 */;
	UCHAR rx_ref_count /* byte2 */;
	UCHAR rx_ref_count_th /* byte3 */;
	UCHAR byte4 /* byte4 */;
	UCHAR e4_reserved7 /* byte5 */;
	USHORT word1 /* word1 */;
	USHORT tx_ref_count /* word2 */;
	USHORT tx_ref_count_th /* word3 */;
	USHORT word4 /* word4 */;
	USHORT word5 /* word5 */;
	USHORT e4_reserved8 /* word6 */;
	ULONG reg1 /* reg1 */;
};


/*
 * Pre-Roce doorbell data
 */
struct pre_roce_db_data
{
	UCHAR params;
		#define PRE_ROCE_DB_DATA_DEST_MASK         0x3 /* destination of doorbell (use enum db_dest) */
		#define PRE_ROCE_DB_DATA_DEST_SHIFT        0
		#define PRE_ROCE_DB_DATA_AGG_CMD_MASK      0x3 /* aggregative command to CM (use enum db_agg_cmd_sel) */
		#define PRE_ROCE_DB_DATA_AGG_CMD_SHIFT     2
		#define PRE_ROCE_DB_DATA_BYPASS_EN_MASK    0x1 /* enable QM bypass */
		#define PRE_ROCE_DB_DATA_BYPASS_EN_SHIFT   4
		#define PRE_ROCE_DB_DATA_RESERVED_MASK     0x1
		#define PRE_ROCE_DB_DATA_RESERVED_SHIFT    5
		#define PRE_ROCE_DB_DATA_AGG_VAL_SEL_MASK  0x3 /* aggregative value selection */
		#define PRE_ROCE_DB_DATA_AGG_VAL_SEL_SHIFT 6
	UCHAR agg_flags /* bit for every DQ counter flags in CM context that DQ can increment */;
	USHORT prod_val;
};


/*
 * Pre-RoCE doorbell data for SQ and RQ
 */
struct pre_roce_pwm_val16_data
{
	USHORT icid /* internal CID */;
	USHORT prod_val /* aggregated value to update */;
};


/*
 * Pre-RoCE doorbell data for CQ
 */
struct pre_roce_pwm_val32_data
{
	USHORT icid /* internal CID */;
	UCHAR agg_flags /* bit for every DQ counter flags in CM context that DQ can increment */;
	UCHAR params;
		#define PRE_ROCE_PWM_VAL32_DATA_AGG_CMD_MASK             0x3 /* aggregative command to CM (use enum db_agg_cmd_sel) */
		#define PRE_ROCE_PWM_VAL32_DATA_AGG_CMD_SHIFT            0
		#define PRE_ROCE_PWM_VAL32_DATA_BYPASS_EN_MASK           0x1 /* enable QM bypass */
		#define PRE_ROCE_PWM_VAL32_DATA_BYPASS_EN_SHIFT          2
		#define PRE_ROCE_PWM_VAL32_DATA_CONN_TYPE_IS_IWARP_MASK  0x1 /* Connection type is iWARP */
		#define PRE_ROCE_PWM_VAL32_DATA_CONN_TYPE_IS_IWARP_SHIFT 3
		#define PRE_ROCE_PWM_VAL32_DATA_RESERVED_MASK            0xF
		#define PRE_ROCE_PWM_VAL32_DATA_RESERVED_SHIFT           4
	ULONG cq_cons_val /* aggregated value to update */;
};

#endif /* __PREROCE__ */
