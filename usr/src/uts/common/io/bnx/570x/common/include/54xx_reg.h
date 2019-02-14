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

#ifndef _54xx_reg_h
#define _54xx_reg_h

#include "bits.h"



/* Control register. */
#define PHY_CTRL_REG                                0x00
#define PHY_CTRL_SPEED_MASK                         (BIT_6 | BIT_13)
#define PHY_CTRL_SPEED_SELECT_10MBPS                BIT_NONE
#define PHY_CTRL_SPEED_SELECT_100MBPS               BIT_13
#define PHY_CTRL_SPEED_SELECT_1000MBPS              BIT_6
#define PHY_CTRL_COLLISION_TEST_ENABLE              BIT_7
#define PHY_CTRL_FULL_DUPLEX_MODE                   BIT_8
#define PHY_CTRL_RESTART_AUTO_NEG                   BIT_9
#define PHY_CTRL_ISOLATE_PHY                        BIT_10
#define PHY_CTRL_LOWER_POWER_MODE                   BIT_11
#define PHY_CTRL_AUTO_NEG_ENABLE                    BIT_12
#define PHY_CTRL_LOOPBACK_MODE                      BIT_14
#define PHY_CTRL_PHY_RESET                          BIT_15


/* Status register. */
#define PHY_STATUS_REG                              0x01
#define PHY_STATUS_LINK_PASS                        BIT_2
#define PHY_STATUS_AUTO_NEG_COMPLETE                BIT_5


/* Phy Id registers. */
#define PHY_ID1_REG                                 0x02
#define PHY_ID2_REG                                 0x03

/* PHY_ID1: bits 31-16; PHY_ID2: bits 15-0.  */
#define PHY_BCM5400_PHY_ID                          0x00206040
#define PHY_BCM5401_PHY_ID                          0x00206050
#define PHY_BCM5411_PHY_ID                          0x00206070
#define PHY_BCM5701_PHY_ID                          0x00206110
#define PHY_BCM5703_PHY_ID                          0x00206160
#define PHY_BCM5706_PHY_ID                          0x00206160

#define PHY_ID(id)                                  ((id) & 0xfffffff0)
#define PHY_REV_ID(id)                              ((id) & 0xf)
#define PHY_BCM5401_B0_REV                          0x1
#define PHY_BCM5401_B2_REV                          0x3
#define PHY_BCM5401_C0_REV                          0x6


/* Auto-negotiation advertisement register. */
#define PHY_AN_AD_REG                               0x04
#define PHY_AN_AD_10BASET_HALF                      BIT_5
#define PHY_AN_AD_10BASET_FULL                      BIT_6
#define PHY_AN_AD_100BASETX_HALF                    BIT_7
#define PHY_AN_AD_100BASETX_FULL                    BIT_8
#define PHY_AN_AD_PAUSE_CAPABLE                     BIT_10
#define PHY_AN_AD_ASYM_PAUSE                        BIT_11
#define PHY_AN_AD_PROTOCOL_802_3_CSMA_CD            0x01


/* Apply to 1000-X fiber mode only */
#define PHY_AN_AD_1000X_FULL_DUPLEX                 BIT_5
#define PHY_AN_AD_1000X_HALF_DUPLEX                 BIT_6
#define PHY_AN_AD_1000X_PAUSE_CAPABLE               BIT_7
#define PHY_AN_AD_1000X_ASYM_PAUSE                  BIT_8
#define PHY_AN_AD_1000X_REMOTE_FAULT_LINK_FAILURE   BIT_12
#define PHY_AN_AD_1000X_REMOTE_FAULT_OFFLINE        BIT_13
#define PHY_AN_AD_1000X_REMOTE_FAULT_AUTONEG_ERR    (BIT_12 | BIT_13)

/* Auto-negotiation Link Partner Ability register. */
#define PHY_LINK_PARTNER_ABILITY_REG                0x05
#define PHY_LINK_PARTNER_10BASET_HALF               BIT_5
#define PHY_LINK_PARTNER_10BASET_FULL               BIT_6
#define PHY_LINK_PARTNER_100BASETX_HALF             BIT_7
#define PHY_LINK_PARTNER_100BASETX_FULL             BIT_8
#define PHY_LINK_PARTNER_PAUSE_CAPABLE              BIT_10
#define PHY_LINK_PARTNER_ASYM_PAUSE                 BIT_11


/* Auto-negotiation expansion register. */
#define PHY_AN_EXPANSION_REG                        0x06
#define PHY_LINK_PARTNER_AUTONEG_ABILITY            BIT_0


/* 1000Base-T control/advertisement register. */
#define PHY_1000BASET_CTRL_REG                      0x09
#define PHY_AN_AD_1000BASET_HALF                    BIT_8
#define PHY_AN_AD_1000BASET_FULL                    BIT_9
#define PHY_CONFIG_AS_MASTER                        BIT_11
#define PHY_ENABLE_CONFIG_AS_MASTER                 BIT_12


/* 1000Base-T status/link partner advertisement. */
#define PHY_1000BASET_STATUS_REG                    0x0a
#define PHY_LINK_PARTNER_1000BASET_HALF             BIT_10
#define PHY_LINK_PARTNER_1000BASET_FULL             BIT_11


/* Extended control register. */
#define BCM540X_EXT_CTRL_REG                        0x10

#define BCM540X_EXT_CTRL_LINK3_LED_MODE             BIT_1
#define BCM540X_EXT_CTRL_TBI                        BIT_15


/* DSP Coefficient Read/Write Port. */
#define BCM540X_DSP_RW_PORT                         0x15


/* DSP Coeficient Address Register. */
#define BCM540X_DSP_ADDRESS_REG                     0x17

#define BCM540X_DSP_TAP_NUMBER_MASK                 0x00
#define BCM540X_DSP_AGC_A                           0x00
#define BCM540X_DSP_AGC_B                           0x01
#define BCM540X_DSP_MSE_PAIR_STATUS                 0x02
#define BCM540X_DSP_SOFT_DECISION                   0x03
#define BCM540X_DSP_PHASE_REG                       0x04
#define BCM540X_DSP_SKEW                            0x05
#define BCM540X_DSP_POWER_SAVER_UPPER_BOUND         0x06
#define BCM540X_DSP_POWER_SAVER_LOWER_BOUND         0x07
#define BCM540X_DSP_LAST_ECHO                       0x08
#define BCM540X_DSP_FREQUENCY                       0x09
#define BCM540X_DSP_PLL_BANDWIDTH                   0x0a
#define BCM540X_DSP_PLL_PHASE_OFFSET                0x0b

#define BCM540X_DSP_FILTER_DCOFFSET                 (BIT_10 | BIT_11)
#define BCM540X_DSP_FILTER_FEXT3                    (BIT_8 | BIT_9 | BIT_11)
#define BCM540X_DSP_FILTER_FEXT2                    (BIT_9 | BIT_11)
#define BCM540X_DSP_FILTER_FEXT1                    (BIT_8 | BIT_11)
#define BCM540X_DSP_FILTER_FEXT0                    BIT_11
#define BCM540X_DSP_FILTER_NEXT3                    (BIT_8 | BIT_9 | BIT_10)
#define BCM540X_DSP_FILTER_NEXT2                    (BIT_9 | BIT_10)
#define BCM540X_DSP_FILTER_NEXT1                    (BIT_8 | BIT_10)
#define BCM540X_DSP_FILTER_NEXT0                    BIT_10
#define BCM540X_DSP_FILTER_ECHO                     (BIT_8 | BIT_9)
#define BCM540X_DSP_FILTER_DFE                      BIT_9
#define BCM540X_DSP_FILTER_FFE                      BIT_8

#define BCM540X_DSP_CONTROL_ALL_FILTERS             BIT_12

#define BCM540X_DSP_SEL_CH_0                        BIT_NONE
#define BCM540X_DSP_SEL_CH_1                        BIT_13
#define BCM540X_DSP_SEL_CH_2                        BIT_14
#define BCM540X_DSP_SEL_CH_3                        (BIT_13 | BIT_14)

#define BCM540X_CONTROL_ALL_CHANNELS                BIT_15


/* Auxilliary Control Register (Shadow Register) */
#define BCM5401_AUX_CTRL                            0x18

#define BCM5401_SHADOW_SEL_MASK                     0x7
#define BCM5401_SHADOW_SEL_NORMAL                   0x00
#define BCM5401_SHADOW_SEL_10BASET                  0x01
#define BCM5401_SHADOW_SEL_POWER_CONTROL            0x02
#define BCM5401_SHADOW_SEL_IP_PHONE                 0x03
#define BCM5401_SHADOW_SEL_MISC_TEST1               0x04
#define BCM5401_SHADOW_SEL_MISC_TEST2               0x05
#define BCM5401_SHADOW_SEL_IP_PHONE_SEED            0x06


/* Shadow register selector == '000' */
#define BCM5401_SHDW_NORMAL_DIAG_MODE               BIT_3
#define BCM5401_SHDW_NORMAL_DISABLE_MBP             BIT_4
#define BCM5401_SHDW_NORMAL_DISABLE_LOW_PWR         BIT_5
#define BCM5401_SHDW_NORMAL_DISABLE_INV_PRF         BIT_6
#define BCM5401_SHDW_NORMAL_DISABLE_PRF             BIT_7
#define BCM5401_SHDW_NORMAL_RX_SLICING_NORMAL       BIT_NONE
#define BCM5401_SHDW_NORMAL_RX_SLICING_4D           BIT_8
#define BCM5401_SHDW_NORMAL_RX_SLICING_3LVL_1D      BIT_9
#define BCM5401_SHDW_NORMAL_RX_SLICING_5LVL_1D      (BIT_8 | BIT_9)
#define BCM5401_SHDW_NORMAL_TX_6DB_CODING           BIT_10
#define BCM5401_SHDW_NORMAL_ENABLE_SM_DSP_CLOCK     BIT_11
#define BCM5401_SHDW_NORMAL_EDGERATE_CTRL_4NS       BIT_NONE
#define BCM5401_SHDW_NORMAL_EDGERATE_CTRL_5NS       BIT_12
#define BCM5401_SHDW_NORMAL_EDGERATE_CTRL_3NS       BIT_13
#define BCM5401_SHDW_NORMAL_EDGERATE_CTRL_0NS       (BIT_12 | BIT_13)
#define BCM5401_SHDW_NORMAL_EXT_PACKET_LENGTH       BIT_14
#define BCM5401_SHDW_NORMAL_EXTERNAL_LOOPBACK       BIT_15


/* Auxilliary status summary. */
#define BCM540X_AUX_STATUS_REG                      0x19

#define BCM540X_AUX_LINK_PASS                       BIT_2
#define BCM540X_AUX_SPEED_MASK                      (BIT_8 | BIT_9 | BIT_10)
#define BCM540X_AUX_10BASET_HD                      BIT_8
#define BCM540X_AUX_10BASET_FD                      BIT_9
#define BCM540X_AUX_100BASETX_HD                    (BIT_8 | BIT_9)
#define BCM540X_AUX_100BASET4                       BIT_10
#define BCM540X_AUX_100BASETX_FD                    (BIT_8 | BIT_10)
#define BCM540X_AUX_1000BASET_HD                    (BIT_9 | BIT_10)
#define BCM540X_AUX_1000BASET_FD                    (BIT_8 | BIT_9 | BIT_10)


/* Interrupt status. */
#define BCM540X_INT_STATUS_REG                      0x1a

#define BCM540X_INT_LINK_CHNG                       BIT_1
#define BCM540X_INT_SPEED_CHNG                      BIT_2
#define BCM540X_INT_DUPLEX_CHNG                     BIT_3
#define BCM540X_INT_AUTO_NEG_PAGE_RX                BIT_10


/* Interrupt mask register. */
#define BCM540X_INT_MASK_REG                        0x1b



#endif // _54xx_reg_h
