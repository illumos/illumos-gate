
/*
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
 * Generated On Date:  07/24/2009 20:59
 *
 */

#ifndef EMAC_REG_H
#define EMAC_REG_H

/*
 *  emac_reg definition
 *  offset: 0x1400
 */
#define EMAC_REG_EMAC_MODE                                        0x0	//ACCESS:??  DataWidth:0x20
        #define EMAC_MODE_RESET                            (1L<<0)
        #define EMAC_MODE_RESET_BITSHIFT                   0
        #define EMAC_MODE_HALF_DUPLEX                      (1L<<1)
        #define EMAC_MODE_HALF_DUPLEX_BITSHIFT             1
        #define EMAC_MODE_PORT                             (0x3L<<2)
        #define EMAC_MODE_PORT_BITSHIFT                    2
            #define EMAC_MODE_PORT_NONE                    (0L<<2)
            #define EMAC_MODE_PORT_NONE_BITSHIFT           2
            #define EMAC_MODE_PORT_MII                     (1L<<2)
            #define EMAC_MODE_PORT_MII_BITSHIFT            2
            #define EMAC_MODE_PORT_GMII                    (2L<<2)
            #define EMAC_MODE_PORT_GMII_BITSHIFT           2
            #define EMAC_MODE_PORT_MII_10M                 (3L<<2)
            #define EMAC_MODE_PORT_MII_10M_BITSHIFT        2
        #define EMAC_MODE_MAC_LOOP                         (1L<<4)
        #define EMAC_MODE_MAC_LOOP_BITSHIFT                4
        #define EMAC_MODE_25G_MODE                         (1L<<5)
        #define EMAC_MODE_25G_MODE_BITSHIFT                5
        #define EMAC_MODE_TAGGED_MAC_CTL                   (1L<<7)
        #define EMAC_MODE_TAGGED_MAC_CTL_BITSHIFT          7
        #define EMAC_MODE_TX_BURST                         (1L<<8)
        #define EMAC_MODE_TX_BURST_BITSHIFT                8
        #define EMAC_MODE_MAX_DEFER_DROP_ENA               (1L<<9)
        #define EMAC_MODE_MAX_DEFER_DROP_ENA_BITSHIFT      9
        #define EMAC_MODE_EXT_LINK_POL                     (1L<<10)
        #define EMAC_MODE_EXT_LINK_POL_BITSHIFT            10
        #define EMAC_MODE_FORCE_LINK                       (1L<<11)
        #define EMAC_MODE_FORCE_LINK_BITSHIFT              11
        #define EMAC_MODE_MPKT                             (1L<<18)
        #define EMAC_MODE_MPKT_BITSHIFT                    18
        #define EMAC_MODE_MPKT_RCVD                        (1L<<19)
        #define EMAC_MODE_MPKT_RCVD_BITSHIFT               19
        #define EMAC_MODE_ACPI_RCVD                        (1L<<20)
        #define EMAC_MODE_ACPI_RCVD_BITSHIFT               20
#define EMAC_REG_EMAC_STATUS                                      0x4	//ACCESS:??  DataWidth:0x20
        #define EMAC_STATUS_LINK                           (1L<<11)
        #define EMAC_STATUS_LINK_BITSHIFT                  11
        #define EMAC_STATUS_LINK_CHANGE                    (1L<<12)
        #define EMAC_STATUS_LINK_CHANGE_BITSHIFT           12
        #define EMAC_STATUS_SERDES_AUTONEG_COMPLETE        (1L<<13)
        #define EMAC_STATUS_SERDES_AUTONEG_COMPLETE_BITSHIFT 13
        #define EMAC_STATUS_SERDES_AUTONEG_CHANGE          (1L<<14)
        #define EMAC_STATUS_SERDES_AUTONEG_CHANGE_BITSHIFT 14
        #define EMAC_STATUS_SERDES_NXT_PG_CHANGE           (1L<<16)
        #define EMAC_STATUS_SERDES_NXT_PG_CHANGE_BITSHIFT  16
        #define EMAC_STATUS_SERDES_RX_CONFIG_IS_0          (1L<<17)
        #define EMAC_STATUS_SERDES_RX_CONFIG_IS_0_BITSHIFT 17
        #define EMAC_STATUS_SERDES_RX_CONFIG_IS_0_CHANGE   (1L<<18)
        #define EMAC_STATUS_SERDES_RX_CONFIG_IS_0_CHANGE_BITSHIFT 18
        #define EMAC_STATUS_MI_COMPLETE                    (1L<<22)
        #define EMAC_STATUS_MI_COMPLETE_BITSHIFT           22
        #define EMAC_STATUS_MI_INT                         (1L<<23)
        #define EMAC_STATUS_MI_INT_BITSHIFT                23
        #define EMAC_STATUS_AP_ERROR                       (1L<<24)
        #define EMAC_STATUS_AP_ERROR_BITSHIFT              24
        #define EMAC_STATUS_PARITY_ERROR_STATE             (1L<<31)
        #define EMAC_STATUS_PARITY_ERROR_STATE_BITSHIFT    31
#define EMAC_REG_EMAC_ATTENTION_ENA                               0x8	//ACCESS:??  DataWidth:0x20
        #define EMAC_ATTENTION_ENA_LINK                    (1L<<11)
        #define EMAC_ATTENTION_ENA_LINK_BITSHIFT           11
        #define EMAC_ATTENTION_ENA_AUTONEG_CHANGE          (1L<<14)
        #define EMAC_ATTENTION_ENA_AUTONEG_CHANGE_BITSHIFT 14
        #define EMAC_ATTENTION_ENA_NXT_PG_CHANGE           (1L<<16)
        #define EMAC_ATTENTION_ENA_NXT_PG_CHANGE_BITSHIFT  16
        #define EMAC_ATTENTION_ENA_SERDES_RX_CONFIG_IS_0_CHANGE  (1L<<18)
        #define EMAC_ATTENTION_ENA_SERDES_RX_CONFIG_IS_0_CHANGE_BITSHIFT 18
        #define EMAC_ATTENTION_ENA_MI_COMPLETE             (1L<<22)
        #define EMAC_ATTENTION_ENA_MI_COMPLETE_BITSHIFT    22
        #define EMAC_ATTENTION_ENA_MI_INT                  (1L<<23)
        #define EMAC_ATTENTION_ENA_MI_INT_BITSHIFT         23
        #define EMAC_ATTENTION_ENA_AP_ERROR                (1L<<24)
        #define EMAC_ATTENTION_ENA_AP_ERROR_BITSHIFT       24
#define EMAC_REG_EMAC_LED                                         0xc	//ACCESS:??  DataWidth:0x20
        #define EMAC_LED_OVERRIDE                          (1L<<0)
        #define EMAC_LED_OVERRIDE_BITSHIFT                 0
        #define EMAC_LED_1000MB_OVERRIDE                   (1L<<1)
        #define EMAC_LED_1000MB_OVERRIDE_BITSHIFT          1
        #define EMAC_LED_100MB_OVERRIDE                    (1L<<2)
        #define EMAC_LED_100MB_OVERRIDE_BITSHIFT           2
        #define EMAC_LED_10MB_OVERRIDE                     (1L<<3)
        #define EMAC_LED_10MB_OVERRIDE_BITSHIFT            3
        #define EMAC_LED_TRAFFIC_OVERRIDE                  (1L<<4)
        #define EMAC_LED_TRAFFIC_OVERRIDE_BITSHIFT         4
        #define EMAC_LED_BLNK_TRAFFIC                      (1L<<5)
        #define EMAC_LED_BLNK_TRAFFIC_BITSHIFT             5
        #define EMAC_LED_TRAFFIC                           (1L<<6)
        #define EMAC_LED_TRAFFIC_BITSHIFT                  6
        #define EMAC_LED_1000MB                            (1L<<7)
        #define EMAC_LED_1000MB_BITSHIFT                   7
        #define EMAC_LED_100MB                             (1L<<8)
        #define EMAC_LED_100MB_BITSHIFT                    8
        #define EMAC_LED_10MB                              (1L<<9)
        #define EMAC_LED_10MB_BITSHIFT                     9
        #define EMAC_LED_TRAFFIC_STAT                      (1L<<10)
        #define EMAC_LED_TRAFFIC_STAT_BITSHIFT             10
        #define EMAC_LED_2500MB                            (1L<<11)
        #define EMAC_LED_2500MB_BITSHIFT                   11
        #define EMAC_LED_2500MB_OVERRIDE                   (1L<<12)
        #define EMAC_LED_2500MB_OVERRIDE_BITSHIFT          12
        #define EMAC_LED_ACTIVITY_SEL                      (0x3L<<17)
        #define EMAC_LED_ACTIVITY_SEL_BITSHIFT             17
            #define EMAC_LED_ACTIVITY_SEL_0                (0L<<17)
            #define EMAC_LED_ACTIVITY_SEL_0_BITSHIFT       17
            #define EMAC_LED_ACTIVITY_SEL_1                (1L<<17)
            #define EMAC_LED_ACTIVITY_SEL_1_BITSHIFT       17
            #define EMAC_LED_ACTIVITY_SEL_2                (2L<<17)
            #define EMAC_LED_ACTIVITY_SEL_2_BITSHIFT       17
            #define EMAC_LED_ACTIVITY_SEL_3                (3L<<17)
            #define EMAC_LED_ACTIVITY_SEL_3_BITSHIFT       17
        #define EMAC_LED_BLNK_RATE                         (0xfffL<<19)
        #define EMAC_LED_BLNK_RATE_BITSHIFT                19
        #define EMAC_LED_BLNK_RATE_ENA                     (1L<<31)
        #define EMAC_LED_BLNK_RATE_ENA_BITSHIFT            31
#define EMAC_REG_EMAC_MAC_MATCH                                   0x10	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_MAC_MATCH_COUNT                             32
#define EMAC_REG_EMAC_LED2                                        0x90	//ACCESS:??  DataWidth:0x20
        #define EMAC_LED2_PHY_10MB_SOFT                    (1L<<0)
        #define EMAC_LED2_PHY_10MB_SOFT_BITSHIFT           0
        #define EMAC_LED2_PHY_10MB_MSK                     (0x7L<<1)
        #define EMAC_LED2_PHY_10MB_MSK_BITSHIFT            1
        #define EMAC_LED2_PHY_10MB_CMP                     (0x7L<<4)
        #define EMAC_LED2_PHY_10MB_CMP_BITSHIFT            4
        #define EMAC_LED2_PHY_100MB_SOFT                   (1L<<8)
        #define EMAC_LED2_PHY_100MB_SOFT_BITSHIFT          8
        #define EMAC_LED2_PHY_100MB_MSK                    (0x7L<<9)
        #define EMAC_LED2_PHY_100MB_MSK_BITSHIFT           9
        #define EMAC_LED2_PHY_100MB_CMP                    (0x7L<<12)
        #define EMAC_LED2_PHY_100MB_CMP_BITSHIFT           12
        #define EMAC_LED2_PHY_1GB_SOFT                     (1L<<16)
        #define EMAC_LED2_PHY_1GB_SOFT_BITSHIFT            16
        #define EMAC_LED2_PHY_1GB_MSK                      (0x7L<<17)
        #define EMAC_LED2_PHY_1GB_MSK_BITSHIFT             17
        #define EMAC_LED2_PHY_1GB_CMP                      (0x7L<<20)
        #define EMAC_LED2_PHY_1GB_CMP_BITSHIFT             20
        #define EMAC_LED2_PHY_10GB_SOFT                    (1L<<24)
        #define EMAC_LED2_PHY_10GB_SOFT_BITSHIFT           24
        #define EMAC_LED2_PHY_10GB_MSK                     (0x7L<<25)
        #define EMAC_LED2_PHY_10GB_MSK_BITSHIFT            25
        #define EMAC_LED2_PHY_10GB_CMP                     (0x7L<<28)
        #define EMAC_LED2_PHY_10GB_CMP_BITSHIFT            28
#define EMAC_REG_EMAC_LED3                                        0x94	//ACCESS:??  DataWidth:0x20
        #define EMAC_LED3_PHY_ACT_MSK                      (0x3L<<0)
        #define EMAC_LED3_PHY_ACT_MSK_BITSHIFT             0
        #define EMAC_LED3_PHY_ACT_CMP                      (0x3L<<2)
        #define EMAC_LED3_PHY_ACT_CMP_BITSHIFT             2
        #define EMAC_LED3_PHY_QUAL_MSK                     (0x3L<<4)
        #define EMAC_LED3_PHY_QUAL_MSK_BITSHIFT            4
        #define EMAC_LED3_PHY_QUAL_CMP                     (0x3L<<6)
        #define EMAC_LED3_PHY_QUAL_CMP_BITSHIFT            6
        #define EMAC_LED3_PHY_QUAL_SOFT                    (1L<<8)
        #define EMAC_LED3_PHY_QUAL_SOFT_BITSHIFT           8
#define EMAC_REG_EMAC_BACKOFF_SEED                                0x98	//ACCESS:??  DataWidth:0x20
        #define EMAC_BACKOFF_SEED_EMAC_BACKOFF_SEED        (0x3ffL<<0)
        #define EMAC_BACKOFF_SEED_EMAC_BACKOFF_SEED_BITSHIFT 0
#define EMAC_REG_EMAC_RX_MTU_SIZE                                 0x9c	//ACCESS:??  DataWidth:0x20
        #define EMAC_RX_MTU_SIZE_MTU_SIZE                  (0xffffL<<0)
        #define EMAC_RX_MTU_SIZE_MTU_SIZE_BITSHIFT         0
        #define EMAC_RX_MTU_SIZE_JUMBO_ENA                 (1L<<31)
        #define EMAC_RX_MTU_SIZE_JUMBO_ENA_BITSHIFT        31
#define EMAC_REG_EMAC_UNUSED2                                     0xa0	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_UNUSED2_COUNT                               2
#define EMAC_REG_EMAC_MDIO_AUTO_POLL                              0xa8	//ACCESS:??  DataWidth:0x20
        #define EMAC_MDIO_AUTO_POLL_DATA_MASK              (0xffffL<<0)
        #define EMAC_MDIO_AUTO_POLL_DATA_MASK_BITSHIFT     0
        #define EMAC_MDIO_AUTO_POLL_REG_ADDR               (0xffffL<<16)
        #define EMAC_MDIO_AUTO_POLL_REG_ADDR_BITSHIFT      16
#define EMAC_REG_EMAC_MDIO_COMM                                   0xac	//ACCESS:??  DataWidth:0x20
        #define EMAC_MDIO_COMM_DATA                        (0xffffL<<0)
        #define EMAC_MDIO_COMM_DATA_BITSHIFT               0
        #define EMAC_MDIO_COMM_REG_ADDR                    (0x1fL<<16)
        #define EMAC_MDIO_COMM_REG_ADDR_BITSHIFT           16
        #define EMAC_MDIO_COMM_PHY_ADDR                    (0x1fL<<21)
        #define EMAC_MDIO_COMM_PHY_ADDR_BITSHIFT           21
        #define EMAC_MDIO_COMM_COMMAND                     (0x3L<<26)
        #define EMAC_MDIO_COMM_COMMAND_BITSHIFT            26
            #define EMAC_MDIO_COMM_COMMAND_UNDEFINED_0     (0L<<26)
            #define EMAC_MDIO_COMM_COMMAND_UNDEFINED_0_BITSHIFT 26
            #define EMAC_MDIO_COMM_COMMAND_ADDRESS         (0L<<26)
            #define EMAC_MDIO_COMM_COMMAND_ADDRESS_BITSHIFT 26
            #define EMAC_MDIO_COMM_COMMAND_WRITE_22        (1L<<26)
            #define EMAC_MDIO_COMM_COMMAND_WRITE_22_BITSHIFT 26
            #define EMAC_MDIO_COMM_COMMAND_WRITE_45        (1L<<26)
            #define EMAC_MDIO_COMM_COMMAND_WRITE_45_BITSHIFT 26
            #define EMAC_MDIO_COMM_COMMAND_READ_22         (2L<<26)
            #define EMAC_MDIO_COMM_COMMAND_READ_22_BITSHIFT 26
            #define EMAC_MDIO_COMM_COMMAND_READ_INC_45     (2L<<26)
            #define EMAC_MDIO_COMM_COMMAND_READ_INC_45_BITSHIFT 26
            #define EMAC_MDIO_COMM_COMMAND_UNDEFINED_3     (3L<<26)
            #define EMAC_MDIO_COMM_COMMAND_UNDEFINED_3_BITSHIFT 26
            #define EMAC_MDIO_COMM_COMMAND_READ_45         (3L<<26)
            #define EMAC_MDIO_COMM_COMMAND_READ_45_BITSHIFT 26
        #define EMAC_MDIO_COMM_FAIL                        (1L<<28)
        #define EMAC_MDIO_COMM_FAIL_BITSHIFT               28
        #define EMAC_MDIO_COMM_START_BUSY                  (1L<<29)
        #define EMAC_MDIO_COMM_START_BUSY_BITSHIFT         29
#define EMAC_REG_EMAC_MDIO_STATUS                                 0xb0	//ACCESS:??  DataWidth:0x20
        #define EMAC_MDIO_STATUS_LINK                      (1L<<0)
        #define EMAC_MDIO_STATUS_LINK_BITSHIFT             0
        #define EMAC_MDIO_STATUS_10MB                      (1L<<1)
        #define EMAC_MDIO_STATUS_10MB_BITSHIFT             1
#define EMAC_REG_EMAC_MDIO_MODE                                   0xb4	//ACCESS:??  DataWidth:0x20
        #define EMAC_MDIO_MODE_SHORT_PREAMBLE              (1L<<1)
        #define EMAC_MDIO_MODE_SHORT_PREAMBLE_BITSHIFT     1
        #define EMAC_MDIO_MODE_AUTO_POLL                   (1L<<4)
        #define EMAC_MDIO_MODE_AUTO_POLL_BITSHIFT          4
        #define EMAC_MDIO_MODE_BIT_BANG                    (1L<<8)
        #define EMAC_MDIO_MODE_BIT_BANG_BITSHIFT           8
        #define EMAC_MDIO_MODE_MDIO                        (1L<<9)
        #define EMAC_MDIO_MODE_MDIO_BITSHIFT               9
        #define EMAC_MDIO_MODE_MDIO_OE                     (1L<<10)
        #define EMAC_MDIO_MODE_MDIO_OE_BITSHIFT            10
        #define EMAC_MDIO_MODE_MDC                         (1L<<11)
        #define EMAC_MDIO_MODE_MDC_BITSHIFT                11
        #define EMAC_MDIO_MODE_MDINT                       (1L<<12)
        #define EMAC_MDIO_MODE_MDINT_BITSHIFT              12
        #define EMAC_MDIO_MODE_EXT_MDINT                   (1L<<13)
        #define EMAC_MDIO_MODE_EXT_MDINT_BITSHIFT          13
        #define EMAC_MDIO_MODE_CLOCK_CNT                   (0x3ffL<<16)
        #define EMAC_MDIO_MODE_CLOCK_CNT_BITSHIFT          16
        #define EMAC_MDIO_MODE_CLAUSE_45                   (1L<<31)
        #define EMAC_MDIO_MODE_CLAUSE_45_BITSHIFT          31
#define EMAC_REG_EMAC_MDIO_AUTO_STATUS                            0xb8	//ACCESS:??  DataWidth:0x20
        #define EMAC_MDIO_AUTO_STATUS_AUTO_ERR             (1L<<0)
        #define EMAC_MDIO_AUTO_STATUS_AUTO_ERR_BITSHIFT    0
#define EMAC_REG_EMAC_TX_MODE                                     0xbc	//ACCESS:??  DataWidth:0x20
        #define EMAC_TX_MODE_RESET                         (1L<<0)
        #define EMAC_TX_MODE_RESET_BITSHIFT                0
        #define EMAC_TX_MODE_CS16_TEST                     (1L<<2)
        #define EMAC_TX_MODE_CS16_TEST_BITSHIFT            2
        #define EMAC_TX_MODE_EXT_PAUSE_EN                  (1L<<3)
        #define EMAC_TX_MODE_EXT_PAUSE_EN_BITSHIFT         3
        #define EMAC_TX_MODE_FLOW_EN                       (1L<<4)
        #define EMAC_TX_MODE_FLOW_EN_BITSHIFT              4
        #define EMAC_TX_MODE_BIG_BACKOFF                   (1L<<5)
        #define EMAC_TX_MODE_BIG_BACKOFF_BITSHIFT          5
        #define EMAC_TX_MODE_LONG_PAUSE                    (1L<<6)
        #define EMAC_TX_MODE_LONG_PAUSE_BITSHIFT           6
        #define EMAC_TX_MODE_LINK_AWARE                    (1L<<7)
        #define EMAC_TX_MODE_LINK_AWARE_BITSHIFT           7
#define EMAC_REG_EMAC_TX_STATUS                                   0xc0	//ACCESS:??  DataWidth:0x20
        #define EMAC_TX_STATUS_XOFFED                      (1L<<0)
        #define EMAC_TX_STATUS_XOFFED_BITSHIFT             0
        #define EMAC_TX_STATUS_XOFF_SENT                   (1L<<1)
        #define EMAC_TX_STATUS_XOFF_SENT_BITSHIFT          1
        #define EMAC_TX_STATUS_XON_SENT                    (1L<<2)
        #define EMAC_TX_STATUS_XON_SENT_BITSHIFT           2
        #define EMAC_TX_STATUS_LINK_UP                     (1L<<3)
        #define EMAC_TX_STATUS_LINK_UP_BITSHIFT            3
        #define EMAC_TX_STATUS_UNDERRUN                    (1L<<4)
        #define EMAC_TX_STATUS_UNDERRUN_BITSHIFT           4
        #define EMAC_TX_STATUS_CS16_ERROR                  (1L<<5)
        #define EMAC_TX_STATUS_CS16_ERROR_BITSHIFT         5
#define EMAC_REG_EMAC_TX_LENGTHS                                  0xc4	//ACCESS:??  DataWidth:0x20
        #define EMAC_TX_LENGTHS_SLOT                       (0xffL<<0)
        #define EMAC_TX_LENGTHS_SLOT_BITSHIFT              0
        #define EMAC_TX_LENGTHS_IPG                        (0xfL<<8)
        #define EMAC_TX_LENGTHS_IPG_BITSHIFT               8
        #define EMAC_TX_LENGTHS_IPG_CRS                    (0x3L<<12)
        #define EMAC_TX_LENGTHS_IPG_CRS_BITSHIFT           12
#define EMAC_REG_EMAC_RX_MODE                                     0xc8	//ACCESS:??  DataWidth:0x20
        #define EMAC_RX_MODE_RESET                         (1L<<0)
        #define EMAC_RX_MODE_RESET_BITSHIFT                0
        #define EMAC_RX_MODE_FLOW_EN                       (1L<<2)
        #define EMAC_RX_MODE_FLOW_EN_BITSHIFT              2
        #define EMAC_RX_MODE_KEEP_MAC_CONTROL              (1L<<3)
        #define EMAC_RX_MODE_KEEP_MAC_CONTROL_BITSHIFT     3
        #define EMAC_RX_MODE_KEEP_PAUSE                    (1L<<4)
        #define EMAC_RX_MODE_KEEP_PAUSE_BITSHIFT           4
        #define EMAC_RX_MODE_ACCEPT_OVERSIZE               (1L<<5)
        #define EMAC_RX_MODE_ACCEPT_OVERSIZE_BITSHIFT      5
        #define EMAC_RX_MODE_ACCEPT_RUNTS                  (1L<<6)
        #define EMAC_RX_MODE_ACCEPT_RUNTS_BITSHIFT         6
        #define EMAC_RX_MODE_LLC_CHK                       (1L<<7)
        #define EMAC_RX_MODE_LLC_CHK_BITSHIFT              7
        #define EMAC_RX_MODE_PROMISCUOUS                   (1L<<8)
        #define EMAC_RX_MODE_PROMISCUOUS_BITSHIFT          8
        #define EMAC_RX_MODE_NO_CRC_CHK                    (1L<<9)
        #define EMAC_RX_MODE_NO_CRC_CHK_BITSHIFT           9
        #define EMAC_RX_MODE_KEEP_VLAN_TAG                 (1L<<10)
        #define EMAC_RX_MODE_KEEP_VLAN_TAG_BITSHIFT        10
        #define EMAC_RX_MODE_FILT_BROADCAST                (1L<<11)
        #define EMAC_RX_MODE_FILT_BROADCAST_BITSHIFT       11
        #define EMAC_RX_MODE_SORT_MODE                     (1L<<12)
        #define EMAC_RX_MODE_SORT_MODE_BITSHIFT            12
#define EMAC_REG_EMAC_RX_STATUS                                   0xcc	//ACCESS:??  DataWidth:0x20
        #define EMAC_RX_STATUS_FFED                        (1L<<0)
        #define EMAC_RX_STATUS_FFED_BITSHIFT               0
        #define EMAC_RX_STATUS_FF_RECEIVED                 (1L<<1)
        #define EMAC_RX_STATUS_FF_RECEIVED_BITSHIFT        1
        #define EMAC_RX_STATUS_N_RECEIVED                  (1L<<2)
        #define EMAC_RX_STATUS_N_RECEIVED_BITSHIFT         2
#define EMAC_REG_EMAC_MULTICAST_HASH                              0xd0	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_MULTICAST_HASH_COUNT                        8
#define EMAC_REG_EMAC_CKSUM_ERROR_STATUS                          0xf0	//ACCESS:??  DataWidth:0x20
        #define EMAC_CKSUM_ERROR_STATUS_CALCULATED         (0xffffL<<0)
        #define EMAC_CKSUM_ERROR_STATUS_CALCULATED_BITSHIFT 0
        #define EMAC_CKSUM_ERROR_STATUS_EXPECTED           (0xffffL<<16)
        #define EMAC_CKSUM_ERROR_STATUS_EXPECTED_BITSHIFT  16
#define EMAC_REG_EMAC_EEE_MODE                                    0xf4	//ACCESS:??  DataWidth:0x20
        #define EMAC_EEE_MODE_RX_LPI_ENA                   (1L<<0)
        #define EMAC_EEE_MODE_RX_LPI_ENA_BITSHIFT          0
        #define EMAC_EEE_MODE_TX_LPI_ENA                   (1L<<1)
        #define EMAC_EEE_MODE_TX_LPI_ENA_BITSHIFT          1
        #define EMAC_EEE_MODE_AUTO_WAKE_ENA                (1L<<2)
        #define EMAC_EEE_MODE_AUTO_WAKE_ENA_BITSHIFT       2
        #define EMAC_EEE_MODE_BLOCK_TIME                   (0xffL<<24)
        #define EMAC_EEE_MODE_BLOCK_TIME_BITSHIFT          24
#define EMAC_REG_EMAC_EEE_TIMER                                   0xf8	//ACCESS:??  DataWidth:0x20
        #define EMAC_EEE_TIMER_EXIT_TIME                   (0xffffL<<0)
        #define EMAC_EEE_TIMER_EXIT_TIME_BITSHIFT          0
        #define EMAC_EEE_TIMER_MIN_ASSERT                  (0xffffL<<16)
        #define EMAC_EEE_TIMER_MIN_ASSERT_BITSHIFT         16
#define EMAC_REG_EMAC_EEE_DEBUG                                   0xfc	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_IFHCINOCTETS                        0x100	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_IFHCINBADOCTETS                     0x104	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_ETHERSTATSFRAGMENTS                 0x108	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_IFHCINUCASTPKTS                     0x10c	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_IFHCINMULTICASTPKTS                 0x110	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_IFHCINBROADCASTPKTS                 0x114	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_DOT3STATSFCSERRORS                  0x118	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_DOT3STATSALIGNMENTERRORS            0x11c	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_DOT3STATSCARRIERSENSEERRORS         0x120	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_XONPAUSEFRAMESRECEIVED              0x124	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_XOFFPAUSEFRAMESRECEIVED             0x128	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_MACCONTROLFRAMESRECEIVED            0x12c	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_XOFFSTATEENTERED                    0x130	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_DOT3STATSFRAMESTOOLONG              0x134	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_ETHERSTATSJABBERS                   0x138	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_ETHERSTATSUNDERSIZEPKTS             0x13c	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_ETHERSTATSPKTS64OCTETS              0x140	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_ETHERSTATSPKTS65OCTETSTO127OCTETS   0x144	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_ETHERSTATSPKTS128OCTETSTO255OCTETS  0x148	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_ETHERSTATSPKTS256OCTETSTO511OCTETS  0x14c	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_ETHERSTATSPKTS512OCTETSTO1023OCTETS 0x150	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_ETHERSTATSPKTS1024OCTETSTO1522OCTETS0x154	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_ETHERSTATSPKTSOVER1522OCTETS        0x158	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RXMAC_DEBUG0                                0x15c	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RXMAC_DEBUG1                                0x160	//ACCESS:??  DataWidth:0x20
        #define EMAC_RXMAC_DEBUG1_LENGTH_NE_BYTE_COUNT     (1L<<0)
        #define EMAC_RXMAC_DEBUG1_LENGTH_NE_BYTE_COUNT_BITSHIFT 0
        #define EMAC_RXMAC_DEBUG1_LENGTH_OUT_RANGE         (1L<<1)
        #define EMAC_RXMAC_DEBUG1_LENGTH_OUT_RANGE_BITSHIFT 1
        #define EMAC_RXMAC_DEBUG1_BAD_CRC                  (1L<<2)
        #define EMAC_RXMAC_DEBUG1_BAD_CRC_BITSHIFT         2
        #define EMAC_RXMAC_DEBUG1_RX_ERROR                 (1L<<3)
        #define EMAC_RXMAC_DEBUG1_RX_ERROR_BITSHIFT        3
        #define EMAC_RXMAC_DEBUG1_ALIGN_ERROR              (1L<<4)
        #define EMAC_RXMAC_DEBUG1_ALIGN_ERROR_BITSHIFT     4
        #define EMAC_RXMAC_DEBUG1_LAST_DATA                (1L<<5)
        #define EMAC_RXMAC_DEBUG1_LAST_DATA_BITSHIFT       5
        #define EMAC_RXMAC_DEBUG1_ODD_BYTE_START           (1L<<6)
        #define EMAC_RXMAC_DEBUG1_ODD_BYTE_START_BITSHIFT  6
        #define EMAC_RXMAC_DEBUG1_BYTE_COUNT               (0xffffL<<7)
        #define EMAC_RXMAC_DEBUG1_BYTE_COUNT_BITSHIFT      7
        #define EMAC_RXMAC_DEBUG1_SLOT_TIME                (0xffL<<23)
        #define EMAC_RXMAC_DEBUG1_SLOT_TIME_BITSHIFT       23
#define EMAC_REG_EMAC_RXMAC_DEBUG2                                0x164	//ACCESS:??  DataWidth:0x20
        #define EMAC_RXMAC_DEBUG2_SM_STATE                 (0x7L<<0)
        #define EMAC_RXMAC_DEBUG2_SM_STATE_BITSHIFT        0
            #define EMAC_RXMAC_DEBUG2_SM_STATE_IDLE        (0L<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_IDLE_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG2_SM_STATE_SFD         (1L<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_SFD_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG2_SM_STATE_DATA        (2L<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_DATA_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG2_SM_STATE_SKEEP       (3L<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_SKEEP_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG2_SM_STATE_EXT         (4L<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_EXT_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG2_SM_STATE_DROP        (5L<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_DROP_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG2_SM_STATE_SDROP       (6L<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_SDROP_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG2_SM_STATE_FC          (7L<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_FC_BITSHIFT 0
        #define EMAC_RXMAC_DEBUG2_IDI_STATE                (0xfL<<3)
        #define EMAC_RXMAC_DEBUG2_IDI_STATE_BITSHIFT       3
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_IDLE       (0L<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_IDLE_BITSHIFT 3
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_DATA0      (1L<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_DATA0_BITSHIFT 3
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_DATA1      (2L<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_DATA1_BITSHIFT 3
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_DATA2      (3L<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_DATA2_BITSHIFT 3
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_DATA3      (4L<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_DATA3_BITSHIFT 3
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_ABORT      (5L<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_ABORT_BITSHIFT 3
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_WAIT       (6L<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_WAIT_BITSHIFT 3
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_STATUS     (7L<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_STATUS_BITSHIFT 3
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_LAST       (8L<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_LAST_BITSHIFT 3
        #define EMAC_RXMAC_DEBUG2_BYTE_IN                  (0xffL<<7)
        #define EMAC_RXMAC_DEBUG2_BYTE_IN_BITSHIFT         7
        #define EMAC_RXMAC_DEBUG2_FALSEC                   (1L<<15)
        #define EMAC_RXMAC_DEBUG2_FALSEC_BITSHIFT          15
        #define EMAC_RXMAC_DEBUG2_TAGGED                   (1L<<16)
        #define EMAC_RXMAC_DEBUG2_TAGGED_BITSHIFT          16
        #define EMAC_RXMAC_DEBUG2_PAUSE_STATE              (1L<<18)
        #define EMAC_RXMAC_DEBUG2_PAUSE_STATE_BITSHIFT     18
            #define EMAC_RXMAC_DEBUG2_PAUSE_STATE_IDLE     (0L<<18)
            #define EMAC_RXMAC_DEBUG2_PAUSE_STATE_IDLE_BITSHIFT 18
            #define EMAC_RXMAC_DEBUG2_PAUSE_STATE_PAUSED   (1L<<18)
            #define EMAC_RXMAC_DEBUG2_PAUSE_STATE_PAUSED_BITSHIFT 18
        #define EMAC_RXMAC_DEBUG2_SE_COUNTER               (0xfL<<19)
        #define EMAC_RXMAC_DEBUG2_SE_COUNTER_BITSHIFT      19
        #define EMAC_RXMAC_DEBUG2_QUANTA                   (0x1fL<<23)
        #define EMAC_RXMAC_DEBUG2_QUANTA_BITSHIFT          23
#define EMAC_REG_EMAC_RXMAC_DEBUG3                                0x168	//ACCESS:??  DataWidth:0x20
        #define EMAC_RXMAC_DEBUG3_PAUSE_CTR                (0xffffL<<0)
        #define EMAC_RXMAC_DEBUG3_PAUSE_CTR_BITSHIFT       0
        #define EMAC_RXMAC_DEBUG3_TMP_PAUSE_CTR            (0xffffL<<16)
        #define EMAC_RXMAC_DEBUG3_TMP_PAUSE_CTR_BITSHIFT   16
#define EMAC_REG_EMAC_RXMAC_DEBUG4                                0x16c	//ACCESS:??  DataWidth:0x20
        #define EMAC_RXMAC_DEBUG4_TYPE_FIELD               (0xffffL<<0)
        #define EMAC_RXMAC_DEBUG4_TYPE_FIELD_BITSHIFT      0
        #define EMAC_RXMAC_DEBUG4_FILT_STATE               (0x3fL<<16)
        #define EMAC_RXMAC_DEBUG4_FILT_STATE_BITSHIFT      16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_IDLE      (0L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_IDLE_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UMAC2     (1L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UMAC2_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UMAC3     (2L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UMAC3_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UNI       (3L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UNI_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MMAC3     (5L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MMAC3_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PSA1      (6L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PSA1_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MMAC2     (7L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MMAC2_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PSA2      (7L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PSA2_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PSA3      (8L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PSA3_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MC2       (9L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MC2_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MC3       (10L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MC3_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MWAIT1    (14L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MWAIT1_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MWAIT2    (15L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MWAIT2_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MCHECK    (16L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MCHECK_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MC        (17L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MC_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BC2       (18L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BC2_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BC3       (19L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BC3_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BSA1      (20L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BSA1_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BSA2      (21L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BSA2_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BSA3      (22L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BSA3_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BTYPE     (23L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BTYPE_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BC        (24L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BC_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PTYPE     (25L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PTYPE_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_CMD       (26L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_CMD_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MAC       (27L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MAC_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_LATCH     (28L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_LATCH_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_XOFF      (29L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_XOFF_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_XON       (30L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_XON_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PAUSED    (31L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PAUSED_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_NPAUSED   (32L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_NPAUSED_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_TTYPE     (33L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_TTYPE_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_TVAL      (34L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_TVAL_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_USA1      (35L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_USA1_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_USA2      (36L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_USA2_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_USA3      (37L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_USA3_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UTYPE     (38L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UTYPE_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UTTYPE    (39L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UTTYPE_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UTVAL     (40L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UTVAL_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MTYPE     (41L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MTYPE_BITSHIFT 16
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_DROP      (42L<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_DROP_BITSHIFT 16
        #define EMAC_RXMAC_DEBUG4_DROP_PKT                 (1L<<22)
        #define EMAC_RXMAC_DEBUG4_DROP_PKT_BITSHIFT        22
        #define EMAC_RXMAC_DEBUG4_SLOT_FILLED              (1L<<23)
        #define EMAC_RXMAC_DEBUG4_SLOT_FILLED_BITSHIFT     23
        #define EMAC_RXMAC_DEBUG4_FALSE_CARRIER            (1L<<24)
        #define EMAC_RXMAC_DEBUG4_FALSE_CARRIER_BITSHIFT   24
        #define EMAC_RXMAC_DEBUG4_LAST_DATA                (1L<<25)
        #define EMAC_RXMAC_DEBUG4_LAST_DATA_BITSHIFT       25
        #define EMAC_RXMAC_DEBUG4_SFD_FOUND                (1L<<26)
        #define EMAC_RXMAC_DEBUG4_SFD_FOUND_BITSHIFT       26
        #define EMAC_RXMAC_DEBUG4_ADVANCE                  (1L<<27)
        #define EMAC_RXMAC_DEBUG4_ADVANCE_BITSHIFT         27
        #define EMAC_RXMAC_DEBUG4_START                    (1L<<28)
        #define EMAC_RXMAC_DEBUG4_START_BITSHIFT           28
#define EMAC_REG_EMAC_RXMAC_DEBUG5                                0x170	//ACCESS:??  DataWidth:0x20
        #define EMAC_RXMAC_DEBUG5_PS_IDISM                 (0x7L<<0)
        #define EMAC_RXMAC_DEBUG5_PS_IDISM_BITSHIFT        0
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_IDLE        (0L<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_IDLE_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_WAIT_EOF    (1L<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_WAIT_EOF_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_WAIT_STAT   (2L<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_WAIT_STAT_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_SET_EOF4FCRC  (3L<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_SET_EOF4FCRC_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_SET_EOF4RDE  (4L<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_SET_EOF4RDE_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_SET_EOF4ALL  (5L<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_SET_EOF4ALL_BITSHIFT 0
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_1WD_WAIT_STAT  (6L<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_1WD_WAIT_STAT_BITSHIFT 0
        #define EMAC_RXMAC_DEBUG5_CCODE_BUF1               (0x7L<<4)
        #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_BITSHIFT      4
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_VDW       (0L<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_VDW_BITSHIFT 4
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_STAT      (1L<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_STAT_BITSHIFT 4
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_AEOF      (2L<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_AEOF_BITSHIFT 4
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_NEOF      (3L<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_NEOF_BITSHIFT 4
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_SOF       (4L<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_SOF_BITSHIFT 4
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_SAEOF     (6L<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_SAEOF_BITSHIFT 4
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_SNEOF     (7L<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_SNEOF_BITSHIFT 4
        #define EMAC_RXMAC_DEBUG5_EOF_DETECTED             (1L<<7)
        #define EMAC_RXMAC_DEBUG5_EOF_DETECTED_BITSHIFT    7
        #define EMAC_RXMAC_DEBUG5_CCODE_BUF0               (0x7L<<8)
        #define EMAC_RXMAC_DEBUG5_CCODE_BUF0_BITSHIFT      8
        #define EMAC_RXMAC_DEBUG5_RPM_IDI_FIFO_FULL        (1L<<11)
        #define EMAC_RXMAC_DEBUG5_RPM_IDI_FIFO_FULL_BITSHIFT 11
        #define EMAC_RXMAC_DEBUG5_LOAD_CCODE               (1L<<12)
        #define EMAC_RXMAC_DEBUG5_LOAD_CCODE_BITSHIFT      12
        #define EMAC_RXMAC_DEBUG5_LOAD_DATA                (1L<<13)
        #define EMAC_RXMAC_DEBUG5_LOAD_DATA_BITSHIFT       13
        #define EMAC_RXMAC_DEBUG5_LOAD_STAT                (1L<<14)
        #define EMAC_RXMAC_DEBUG5_LOAD_STAT_BITSHIFT       14
        #define EMAC_RXMAC_DEBUG5_CLR_STAT                 (1L<<15)
        #define EMAC_RXMAC_DEBUG5_CLR_STAT_BITSHIFT        15
        #define EMAC_RXMAC_DEBUG5_IDI_RPM_CCODE            (0x3L<<16)
        #define EMAC_RXMAC_DEBUG5_IDI_RPM_CCODE_BITSHIFT   16
        #define EMAC_RXMAC_DEBUG5_IDI_RPM_ACCEPT           (1L<<19)
        #define EMAC_RXMAC_DEBUG5_IDI_RPM_ACCEPT_BITSHIFT  19
        #define EMAC_RXMAC_DEBUG5_FMLEN                    (0xfffL<<20)
        #define EMAC_RXMAC_DEBUG5_FMLEN_BITSHIFT           20
#define EMAC_REG_EMAC_RX_STAT_FALSECARRIERERRORS                  0x174	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_UNUSED4                                     0x178	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_UNUSED4_COUNT                               2
#define EMAC_REG_EMAC_RX_STAT_AC                                  0x180	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RX_STAT_AC_COUNT                            23
#define EMAC_REG_EMAC_RXMAC_SUC_DBG_OVERRUNVEC                    0x1dc	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_RXMAC_MPKT_MODE                             0x1e0	//ACCESS:??  DataWidth:0x20
        #define EMAC_RXMAC_MPKT_MODE_MAC_ADDR_EN            (0xfL<<0)
        #define EMAC_RXMAC_MPKT_MODE_MAC_ADDR_EN_BITSHIFT   0
        #define EMAC_RXMAC_MPKT_MODE_MPKT_RCVD              (1L<<19)
        #define EMAC_RXMAC_MPKT_MODE_MPKT_RCVD_BITSHIFT     19
        #define EMAC_RXMAC_MPKT_MODE_ACPI_RCVD              (1L<<20)
        #define EMAC_RXMAC_MPKT_MODE_ACPI_RCVD_BITSHIFT     20
#define EMAC_REG_EMAC_UNUSED5                                     0x1e4	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_UNUSED5_COUNT                               4
#define EMAC_REG_EMAC_RX_STAT_AC_28                               0x1f4	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_UNUSED9                                     0x1f8	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_UNUSED9_COUNT                               2
#define EMAC_REG_EMAC_TX_STAT_IFHCOUTOCTETS                       0x200	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_IFHCOUTBADOCTETS                    0x204	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_ETHERSTATSCOLLISIONS                0x208	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_OUTXONSENT                          0x20c	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_OUTXOFFSENT                         0x210	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_FLOWCONTROLDONE                     0x214	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_DOT3STATSSINGLECOLLISIONFRAMES      0x218	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_DOT3STATSMULTIPLECOLLISIONFRAMES    0x21c	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_DOT3STATSDEFERREDTRANSMISSIONS      0x220	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_DOT3STATSEXCESSIVECOLLISIONS        0x224	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_DOT3STATSLATECOLLISIONS             0x228	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_IFHCOUTUCASTPKTS                    0x22c	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_IFHCOUTMULTICASTPKTS                0x230	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_IFHCOUTBROADCASTPKTS                0x234	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_ETHERSTATSPKTS64OCTETS              0x238	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_ETHERSTATSPKTS65OCTETSTO127OCTETS   0x23c	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_ETHERSTATSPKTS128OCTETSTO255OCTETS  0x240	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_ETHERSTATSPKTS256OCTETSTO511OCTETS  0x244	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_ETHERSTATSPKTS512OCTETSTO1023OCTETS 0x248	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_ETHERSTATSPKTS1024OCTETSTO1522OCTETS0x24c	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_ETHERSTATSPKTSOVER1522OCTETS        0x250	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_DOT3STATSINTERNALMACTRANSMITERRORS  0x254	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TXMAC_DEBUG0                                0x258	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TXMAC_DEBUG1                                0x25c	//ACCESS:??  DataWidth:0x20
        #define EMAC_TXMAC_DEBUG1_ODI_STATE                (0xfL<<0)
        #define EMAC_TXMAC_DEBUG1_ODI_STATE_BITSHIFT       0
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_IDLE       (0L<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_IDLE_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_START0     (1L<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_START0_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_DATA0      (4L<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_DATA0_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_DATA1      (5L<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_DATA1_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_DATA2      (6L<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_DATA2_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_DATA3      (7L<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_DATA3_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_WAIT0      (8L<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_WAIT0_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_WAIT1      (9L<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_WAIT1_BITSHIFT 0
        #define EMAC_TXMAC_DEBUG1_CRS_ENABLE               (1L<<4)
        #define EMAC_TXMAC_DEBUG1_CRS_ENABLE_BITSHIFT      4
        #define EMAC_TXMAC_DEBUG1_BAD_CRC                  (1L<<5)
        #define EMAC_TXMAC_DEBUG1_BAD_CRC_BITSHIFT         5
        #define EMAC_TXMAC_DEBUG1_SE_COUNTER               (0xfL<<6)
        #define EMAC_TXMAC_DEBUG1_SE_COUNTER_BITSHIFT      6
        #define EMAC_TXMAC_DEBUG1_SEND_PAUSE               (1L<<10)
        #define EMAC_TXMAC_DEBUG1_SEND_PAUSE_BITSHIFT      10
        #define EMAC_TXMAC_DEBUG1_LATE_COLLISION           (1L<<11)
        #define EMAC_TXMAC_DEBUG1_LATE_COLLISION_BITSHIFT  11
        #define EMAC_TXMAC_DEBUG1_MAX_DEFER                (1L<<12)
        #define EMAC_TXMAC_DEBUG1_MAX_DEFER_BITSHIFT       12
        #define EMAC_TXMAC_DEBUG1_DEFERRED                 (1L<<13)
        #define EMAC_TXMAC_DEBUG1_DEFERRED_BITSHIFT        13
        #define EMAC_TXMAC_DEBUG1_ONE_BYTE                 (1L<<14)
        #define EMAC_TXMAC_DEBUG1_ONE_BYTE_BITSHIFT        14
        #define EMAC_TXMAC_DEBUG1_IPG_TIME                 (0xfL<<15)
        #define EMAC_TXMAC_DEBUG1_IPG_TIME_BITSHIFT        15
        #define EMAC_TXMAC_DEBUG1_SLOT_TIME                (0xffL<<19)
        #define EMAC_TXMAC_DEBUG1_SLOT_TIME_BITSHIFT       19
#define EMAC_REG_EMAC_TXMAC_DEBUG2                                0x260	//ACCESS:??  DataWidth:0x20
        #define EMAC_TXMAC_DEBUG2_BACK_OFF                 (0x3ffL<<0)
        #define EMAC_TXMAC_DEBUG2_BACK_OFF_BITSHIFT        0
        #define EMAC_TXMAC_DEBUG2_BYTE_COUNT               (0xffffL<<10)
        #define EMAC_TXMAC_DEBUG2_BYTE_COUNT_BITSHIFT      10
        #define EMAC_TXMAC_DEBUG2_COL_COUNT                (0x1fL<<26)
        #define EMAC_TXMAC_DEBUG2_COL_COUNT_BITSHIFT       26
        #define EMAC_TXMAC_DEBUG2_COL_BIT                  (1L<<31)
        #define EMAC_TXMAC_DEBUG2_COL_BIT_BITSHIFT         31
#define EMAC_REG_EMAC_TXMAC_DEBUG3                                0x264	//ACCESS:??  DataWidth:0x20
        #define EMAC_TXMAC_DEBUG3_SM_STATE                 (0xfL<<0)
        #define EMAC_TXMAC_DEBUG3_SM_STATE_BITSHIFT        0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_IDLE        (0L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_IDLE_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_PRE1        (1L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_PRE1_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_PRE2        (2L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_PRE2_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_SFD         (3L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_SFD_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_DATA        (4L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_DATA_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_CRC1        (5L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_CRC1_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_CRC2        (6L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_CRC2_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_EXT         (7L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_EXT_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_STATB       (8L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_STATB_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_STATG       (9L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_STATG_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_JAM         (10L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_JAM_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_EJAM        (11L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_EJAM_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_BJAM        (12L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_BJAM_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_SWAIT       (13L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_SWAIT_BITSHIFT 0
            #define EMAC_TXMAC_DEBUG3_SM_STATE_BACKOFF     (14L<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_BACKOFF_BITSHIFT 0
        #define EMAC_TXMAC_DEBUG3_FILT_STATE               (0x7L<<4)
        #define EMAC_TXMAC_DEBUG3_FILT_STATE_BITSHIFT      4
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_IDLE      (0L<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_IDLE_BITSHIFT 4
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_WAIT      (1L<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_WAIT_BITSHIFT 4
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_UNI       (2L<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_UNI_BITSHIFT 4
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_MC        (3L<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_MC_BITSHIFT 4
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_BC2       (4L<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_BC2_BITSHIFT 4
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_BC3       (5L<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_BC3_BITSHIFT 4
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_BC        (6L<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_BC_BITSHIFT 4
        #define EMAC_TXMAC_DEBUG3_CRS_DONE                 (1L<<7)
        #define EMAC_TXMAC_DEBUG3_CRS_DONE_BITSHIFT        7
        #define EMAC_TXMAC_DEBUG3_XOFF                     (1L<<8)
        #define EMAC_TXMAC_DEBUG3_XOFF_BITSHIFT            8
        #define EMAC_TXMAC_DEBUG3_SE_COUNTER               (0xfL<<9)
        #define EMAC_TXMAC_DEBUG3_SE_COUNTER_BITSHIFT      9
        #define EMAC_TXMAC_DEBUG3_QUANTA_COUNTER           (0x1fL<<13)
        #define EMAC_TXMAC_DEBUG3_QUANTA_COUNTER_BITSHIFT  13
#define EMAC_REG_EMAC_TXMAC_DEBUG4                                0x268	//ACCESS:??  DataWidth:0x20
        #define EMAC_TXMAC_DEBUG4_PAUSE_COUNTER            (0xffffL<<0)
        #define EMAC_TXMAC_DEBUG4_PAUSE_COUNTER_BITSHIFT   0
        #define EMAC_TXMAC_DEBUG4_PAUSE_STATE              (0xfL<<16)
        #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_BITSHIFT     16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_IDLE     (0L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_IDLE_BITSHIFT 16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_MCA1     (2L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_MCA1_BITSHIFT 16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_MCA2     (3L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_MCA2_BITSHIFT 16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_SRC3     (4L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_SRC3_BITSHIFT 16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_SRC2     (5L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_SRC2_BITSHIFT 16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_MCA3     (6L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_MCA3_BITSHIFT 16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_SRC1     (7L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_SRC1_BITSHIFT 16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_CRC1     (8L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_CRC1_BITSHIFT 16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_CRC2     (9L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_CRC2_BITSHIFT 16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_TIME     (10L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_TIME_BITSHIFT 16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_TYPE     (12L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_TYPE_BITSHIFT 16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_WAIT     (13L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_WAIT_BITSHIFT 16
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_CMD      (14L<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_CMD_BITSHIFT 16
        #define EMAC_TXMAC_DEBUG4_STATS0_VALID             (1L<<20)
        #define EMAC_TXMAC_DEBUG4_STATS0_VALID_BITSHIFT    20
        #define EMAC_TXMAC_DEBUG4_APPEND_CRC               (1L<<21)
        #define EMAC_TXMAC_DEBUG4_APPEND_CRC_BITSHIFT      21
        #define EMAC_TXMAC_DEBUG4_SLOT_FILLED              (1L<<22)
        #define EMAC_TXMAC_DEBUG4_SLOT_FILLED_BITSHIFT     22
        #define EMAC_TXMAC_DEBUG4_MAX_DEFER                (1L<<23)
        #define EMAC_TXMAC_DEBUG4_MAX_DEFER_BITSHIFT       23
        #define EMAC_TXMAC_DEBUG4_SEND_EXTEND              (1L<<24)
        #define EMAC_TXMAC_DEBUG4_SEND_EXTEND_BITSHIFT     24
        #define EMAC_TXMAC_DEBUG4_SEND_PADDING             (1L<<25)
        #define EMAC_TXMAC_DEBUG4_SEND_PADDING_BITSHIFT    25
        #define EMAC_TXMAC_DEBUG4_EOF_LOC                  (1L<<26)
        #define EMAC_TXMAC_DEBUG4_EOF_LOC_BITSHIFT         26
        #define EMAC_TXMAC_DEBUG4_COLLIDING                (1L<<27)
        #define EMAC_TXMAC_DEBUG4_COLLIDING_BITSHIFT       27
        #define EMAC_TXMAC_DEBUG4_COL_IN                   (1L<<28)
        #define EMAC_TXMAC_DEBUG4_COL_IN_BITSHIFT          28
        #define EMAC_TXMAC_DEBUG4_BURSTING                 (1L<<29)
        #define EMAC_TXMAC_DEBUG4_BURSTING_BITSHIFT        29
        #define EMAC_TXMAC_DEBUG4_ADVANCE                  (1L<<30)
        #define EMAC_TXMAC_DEBUG4_ADVANCE_BITSHIFT         30
        #define EMAC_TXMAC_DEBUG4_GO                       (1L<<31)
        #define EMAC_TXMAC_DEBUG4_GO_BITSHIFT              31
#define EMAC_REG_EMAC_UNUSED6                                     0x26c	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_UNUSED6_COUNT                               5
#define EMAC_REG_EMAC_TX_STAT_AC                                  0x280	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_TX_STAT_AC_COUNT                            22
#define EMAC_REG_EMAC_TXMAC_SUC_DBG_OVERRUNVEC                    0x2d8	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_UNUSED7                                     0x2dc	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_UNUSED7_COUNT                               8
#define EMAC_REG_EMAC_TX_RATE_LIMIT_CTRL                          0x2fc	//ACCESS:??  DataWidth:0x20
        #define EMAC_TX_RATE_LIMIT_CTRL_TX_THROTTLE_INC    (0x7fL<<0)
        #define EMAC_TX_RATE_LIMIT_CTRL_TX_THROTTLE_INC_BITSHIFT 0
        #define EMAC_TX_RATE_LIMIT_CTRL_TX_THROTTLE_NUM    (0x7fL<<16)
        #define EMAC_TX_RATE_LIMIT_CTRL_TX_THROTTLE_NUM_BITSHIFT 16
        #define EMAC_TX_RATE_LIMIT_CTRL_RATE_LIMITER_EN    (1L<<31)
        #define EMAC_TX_RATE_LIMIT_CTRL_RATE_LIMITER_EN_BITSHIFT 31
#define EMAC_REG_EMAC_UNUSED8                                     0x300	//ACCESS:??  DataWidth:0x20
#define EMAC_REG_EMAC_UNUSED8_COUNT                               64
#define EMAC_REG_RX_PFC_MODE					  0x320
	#define EMAC_REG_RX_PFC_MODE_TX_EN			  (1L<<0)
	#define EMAC_REG_RX_PFC_MODE_TX_EN_BITSHIFT		  0
	#define EMAC_REG_RX_PFC_MODE_RX_EN			  (1L<<1)
	#define EMAC_REG_RX_PFC_MODE_RX_EN_BITSHIFT		  1
	#define EMAC_REG_RX_PFC_MODE_PRIORITIES			  (1L<<2)
	#define EMAC_REG_RX_PFC_MODE_PRIORITIES_BITSHIFT	  2
	#define EMAC_REG_RX_PFC_MODE_KEEP_PFC			  (1L<<3)
	#define EMAC_REG_RX_PFC_MODE_KEEP_PFC_BITSHIFT	          3

#define EMAC_REG_RX_PFC_PARAM					  0x324
	#define EMAC_REG_RX_PFC_PARAM_OPCODE			  (0xffff<<0)
	#define EMAC_REG_RX_PFC_PARAM_OPCODE_BITSHIFT		  0
	#define EMAC_REG_RX_PFC_PARAM_PRIORITY_EN		  (0xffff<<16)
	#define EMAC_REG_RX_PFC_PARAM_PRIORITY_EN_BITSHIFT	  16

#define EMAC_REG_RX_PFC_STATS_XOFF_RCVD                     0x328
    #define EMAC_REG_RX_PFC_STATS_XOFF_RCVD_COUNT           (0xffff<<0)
    #define EMAC_REG_RX_PFC_STATS_XOFF_RCVD_COUNT_BITSHIFT  0
    #define EMAC_REG_RX_PFC_STATS_XOFF_RCVD_UNUSED          (0xffff<<16)
    #define EMAC_REG_RX_PFC_STATS_XOFF_RCVD_UNUSED_BITSHIFT 16

#define EMAC_REG_RX_PFC_STATS_XON_RCVD                      0x32c
    #define EMAC_REG_RX_PFC_STATS_XON_RCVD_COUNT            (0xffff<<0)
    #define EMAC_REG_RX_PFC_STATS_XON_RCVD_COUNT_BITSHIFT   0
    #define EMAC_REG_RX_PFC_STATS_XON_RCVD_UNUSED           (0xffff<<16)
    #define EMAC_REG_RX_PFC_STATS_XON_RCVD_UNUSED_BITSHIFT  16

#define EMAC_REG_RX_PFC_STATS_XOFF_SENT                     0x330
    #define EMAC_REG_RX_PFC_STATS_XOFF_SENT_COUNT           (0xffff<<0)
    #define EMAC_REG_RX_PFC_STATS_XOFF_SENT_COUNT_BITSHIFT  0
    #define EMAC_REG_RX_PFC_STATS_XOFF_SENT_UNUSED          (0xffff<<16)
    #define EMAC_REG_RX_PFC_STATS_XOFF_SENT_UNUSED_BITSHIFT 16

#define EMAC_REG_RX_PFC_STATS_XON_SENT                      0x334
    #define EMAC_REG_RX_PFC_STATS_XON_SENT_COUNT            (0xffff<<0)
    #define EMAC_REG_RX_PFC_STATS_XON_SENT_COUNT_BITSHIFT   0
    #define EMAC_REG_RX_PFC_STATS_XON_SENT_UNUSED           (0xffff<<16)
    #define EMAC_REG_RX_PFC_STATS_XON_SENT_UNUSED_BITSHIFT  16

#endif /* EMAC_REG_H */

