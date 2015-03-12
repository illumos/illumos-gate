#ifndef PHY_REG_H
#define PHY_REG_H

#define MDIO_REG_BANK_CL73_IEEEB0                       0x0
    #define MDIO_CL73_IEEEB0_CL73_AN_CONTROL                0x0
        #define MDIO_CL73_IEEEB0_CL73_AN_CONTROL_RESTART_AN     0x0200
        #define MDIO_CL73_IEEEB0_CL73_AN_CONTROL_AN_EN          0x1000
        #define MDIO_CL73_IEEEB0_CL73_AN_CONTROL_MAIN_RST       0x8000

#define MDIO_REG_BANK_CL73_IEEEB1                       0x10
    #define MDIO_CL73_IEEEB1_AN_ADV2                        0x01
        #define MDIO_CL73_IEEEB1_AN_ADV2_ADVR_1000M             0x0000
        #define MDIO_CL73_IEEEB1_AN_ADV2_ADVR_1000M_KX          0x0020
        #define MDIO_CL73_IEEEB1_AN_ADV2_ADVR_10G_KX4           0x0040
        #define MDIO_CL73_IEEEB1_AN_ADV2_ADVR_10G_KR            0x0080

#define MDIO_REG_BANK_RX0                               0x80b0
    #define MDIO_RX0_RX_EQ_BOOST                            0x1c
        #define MDIO_RX0_RX_EQ_BOOST_EQUALIZER_CTRL_MASK        0x7
        #define MDIO_RX0_RX_EQ_BOOST_OFFSET_CTRL                0x10

#define MDIO_REG_BANK_RX1                               0x80c0
    #define MDIO_RX1_RX_EQ_BOOST                            0x1c
        #define MDIO_RX1_RX_EQ_BOOST_EQUALIZER_CTRL_MASK        0x7
        #define MDIO_RX1_RX_EQ_BOOST_OFFSET_CTRL                0x10

#define MDIO_REG_BANK_RX2                               0x80d0
    #define MDIO_RX2_RX_EQ_BOOST                            0x1c
        #define MDIO_RX2_RX_EQ_BOOST_EQUALIZER_CTRL_MASK        0x7
        #define MDIO_RX2_RX_EQ_BOOST_OFFSET_CTRL                0x10

#define MDIO_REG_BANK_RX3                               0x80e0
    #define MDIO_RX3_RX_EQ_BOOST                            0x1c
        #define MDIO_RX3_RX_EQ_BOOST_EQUALIZER_CTRL_MASK        0x7
        #define MDIO_RX3_RX_EQ_BOOST_OFFSET_CTRL                0x10

#define MDIO_REG_BANK_RX_ALL                            0x80f0
    #define MDIO_RX_ALL_RX_EQ_BOOST                         0x1c
        #define MDIO_RX_ALL_RX_EQ_BOOST_EQUALIZER_CTRL_MASK     0x7
        #define MDIO_RX_ALL_RX_EQ_BOOST_OFFSET_CTRL             0x10

#define MDIO_REG_BANK_TX0                               0x8060
    #define MDIO_TX0_TX_DRIVER                              0x17
        #define MDIO_TX0_TX_DRIVER_PREEMPHASIS_MASK             0xf000
        #define MDIO_TX0_TX_DRIVER_PREEMPHASIS_SHIFT            12
        #define MDIO_TX0_TX_DRIVER_IDRIVER_MASK                 0x0f00
        #define MDIO_TX0_TX_DRIVER_IDRIVER_SHIFT                8
        #define MDIO_TX0_TX_DRIVER_IPREDRIVER_MASK              0x00f0
        #define MDIO_TX0_TX_DRIVER_IPREDRIVER_SHIFT             4
        #define MDIO_TX0_TX_DRIVER_IFULLSPD_MASK                0x000e
        #define MDIO_TX0_TX_DRIVER_IFULLSPD_SHIFT               1
        #define MDIO_TX0_TX_DRIVER_ICBUF1T                      1

#define MDIO_REG_BANK_TX1                               0x8070
    #define MDIO_TX1_TX_DRIVER                              0x17
        #define MDIO_TX0_TX_DRIVER_PREEMPHASIS_MASK             0xf000
        #define MDIO_TX0_TX_DRIVER_PREEMPHASIS_SHIFT            12
        #define MDIO_TX0_TX_DRIVER_IDRIVER_MASK                 0x0f00
        #define MDIO_TX0_TX_DRIVER_IDRIVER_SHIFT                8
        #define MDIO_TX0_TX_DRIVER_IPREDRIVER_MASK              0x00f0
        #define MDIO_TX0_TX_DRIVER_IPREDRIVER_SHIFT             4
        #define MDIO_TX0_TX_DRIVER_IFULLSPD_MASK                0x000e
        #define MDIO_TX0_TX_DRIVER_IFULLSPD_SHIFT               1
        #define MDIO_TX0_TX_DRIVER_ICBUF1T                      1

#define MDIO_REG_BANK_TX2                               0x8080
    #define MDIO_TX2_TX_DRIVER                              0x17
        #define MDIO_TX0_TX_DRIVER_PREEMPHASIS_MASK             0xf000
        #define MDIO_TX0_TX_DRIVER_PREEMPHASIS_SHIFT            12
        #define MDIO_TX0_TX_DRIVER_IDRIVER_MASK                 0x0f00
        #define MDIO_TX0_TX_DRIVER_IDRIVER_SHIFT                8
        #define MDIO_TX0_TX_DRIVER_IPREDRIVER_MASK              0x00f0
        #define MDIO_TX0_TX_DRIVER_IPREDRIVER_SHIFT             4
        #define MDIO_TX0_TX_DRIVER_IFULLSPD_MASK                0x000e
        #define MDIO_TX0_TX_DRIVER_IFULLSPD_SHIFT               1
        #define MDIO_TX0_TX_DRIVER_ICBUF1T                      1

#define MDIO_REG_BANK_TX3                               0x8090
    #define MDIO_TX3_TX_DRIVER                              0x17
        #define MDIO_TX0_TX_DRIVER_PREEMPHASIS_MASK             0xf000
        #define MDIO_TX0_TX_DRIVER_PREEMPHASIS_SHIFT            12
        #define MDIO_TX0_TX_DRIVER_IDRIVER_MASK                 0x0f00
        #define MDIO_TX0_TX_DRIVER_IDRIVER_SHIFT                8
        #define MDIO_TX0_TX_DRIVER_IPREDRIVER_MASK              0x00f0
        #define MDIO_TX0_TX_DRIVER_IPREDRIVER_SHIFT             4
        #define MDIO_TX0_TX_DRIVER_IFULLSPD_MASK                0x000e
        #define MDIO_TX0_TX_DRIVER_IFULLSPD_SHIFT               1
        #define MDIO_TX0_TX_DRIVER_ICBUF1T                      1

#define MDIO_REG_BANK_XGXS_BLOCK0                       0x8000
    #define MDIO_BLOCK0_XGXS_CONTROL                        0x10

#define MDIO_REG_BANK_XGXS_BLOCK1                       0x8010
    #define MDIO_BLOCK1_LANE_CTRL0                          0x15
    #define MDIO_BLOCK1_LANE_CTRL1                          0x16
    #define MDIO_BLOCK1_LANE_CTRL2                          0x17
    #define MDIO_BLOCK1_LANE_PRBS                           0x19

#define MDIO_REG_BANK_XGXS_BLOCK2                       0x8100
    #define MDIO_XGXS_BLOCK2_RX_LN_SWAP                     0x10
        #define MDIO_XGXS_BLOCK2_RX_LN_SWAP_ENABLE              0x8000
        #define MDIO_XGXS_BLOCK2_RX_LN_SWAP_FORCE_ENABLE        0x4000
    #define MDIO_XGXS_BLOCK2_TX_LN_SWAP                     0x11
        #define MDIO_XGXS_BLOCK2_TX_LN_SWAP_ENABLE              0x8000
    #define MDIO_XGXS_BLOCK2_UNICORE_MODE_10G               0x14
        #define MDIO_XGXS_BLOCK2_UNICORE_MODE_10G_CX4_XGXS      0x0001
        #define MDIO_XGXS_BLOCK2_UNICORE_MODE_10G_HIGIG_XGXS    0x0010
    #define MDIO_XGXS_BLOCK2_TEST_MODE_LANE                 0x15

#define MDIO_REG_BANK_GP_STATUS                         0x8120
    #define MDIO_GP_STATUS_TOP_AN_STATUS1                       0x1B
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_CL73_AUTONEG_COMPLETE 0x0001
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_CL37_AUTONEG_COMPLETE 0x0002
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_LINK_STATUS           0x0004 //1= link up;0= link down
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_DUPLEX_STATUS         0x0008 //1= full-duplex; 0= half-duplex
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_CL73_MR_LP_NP_AN_ABLE 0x0010 //1 = Indicates that the LP and the LD supports
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_CL73_LP_NP_BAM_ABLE   0x0020 // the BAM function for Clause 37 AN. This bit is
                                                                           // asserted when both the LD and the LP have
                                                                           // successfully exchanged BAM73 NPs and, therefore,
                                                                           // determined that a switch over to CL37 AN will follow

        #define MDIO_GP_STATUS_TOP_AN_STATUS1_PAUSE_RSOLUTION_TXSIDE 0x0040
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_PAUSE_RSOLUTION_RXSIDE 0x0080
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_MASK	    0x3f00
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10M      0x0000 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_100M     0x0100 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_1G       0x0200 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_2_5G     0x0300 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_5G       0x0400 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_6G       0x0500 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_HIG  0x0600 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_CX4  0x0700 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_12G_HIG  0x0800 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_12_5G    0x0900 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_13G      0x0A00 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_15G      0x0B00 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_16G      0x0C00 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_1G_KX    0x0D00 //bits [13:8]
        #define MDIO_GP_STATUS_TOP_AN_STATUS1_ACTUAL_SPEED_10G_KX4  0x0E00 //bits [13:8]


#define MDIO_REG_BANK_10G_PARALLEL_DETECT               0x8130
    #define MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_CONTROL        0x11
        #define MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_CONTROL_PARDET10G_EN 0x1
    #define MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_LINK           0x13
        #define MDIO_10G_PARALLEL_DETECT_PAR_DET_10G_LINK_CNT       (0xb71<<1)

#define MDIO_REG_BANK_SERDES_DIGITAL                    0x8300
    #define MDIO_SERDES_DIGITAL_A_1000X_CONTROL1            0x10
        #define MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_FIBER_MODE 0x0001 //1= Fiber mode (1000X); 0= SGMII mode
        #define MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_TBI_IF     0x0002 //1= Ten Bit Interface; 0= GMII interface
        #define MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_SIGNAL_DETECT_EN     0x0004
        #define MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_INVERT_SIGNAL_DETECT 0x0008
        #define MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_AUTODET    0x0010
        #define MDIO_SERDES_DIGITAL_A_1000X_CONTROL1_MSTR_MODE  0x0020
    #define MDIO_SERDES_DIGITAL_A_1000X_CONTROL2            0x11
        #define MDIO_SERDES_DIGITAL_A_1000X_CONTROL2_PRL_DT_EN  0x0001
        #define MDIO_SERDES_DIGITAL_A_1000X_CONTROL2_AN_FST_TMR 0x0040
    #define MDIO_SERDES_DIGITAL_A_1000X_STATUS1             0x14
        #define MDIO_SERDES_DIGITAL_A_1000X_STATUS1_DUPLEX      0x0004 //1= full-duplex; 0= half-duplex
        #define MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SPEED_MASK  0x0018
        #define MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SPEED_SHIFT 3
        #define MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SPEED_2_5G  0x0018
        #define MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SPEED_1G    0x0010
        #define MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SPEED_100M  0x0008
        #define MDIO_SERDES_DIGITAL_A_1000X_STATUS1_SPEED_10M   0x0000
    #define MDIO_SERDES_DIGITAL_MISC1                       0x18
        #define MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_MASK       0xE000
        #define MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_25M        0x0000
        #define MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_100M       0x2000
        #define MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_125M       0x4000
        #define MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_156_25M    0x6000
        #define MDIO_SERDES_DIGITAL_MISC1_REFCLK_SEL_187_5M     0x8000
        #define MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_SEL       0x0010
        #define MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_MASK      0x000f
        #define MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_2_5G      0x0000
        #define MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_5G        0x0001
        #define MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_6G        0x0002
        #define MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_10G_HIG   0x0003
        #define MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_10G_CX4   0x0004
        #define MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_12G       0x0005
        #define MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_12_5G     0x0006
        #define MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_13G       0x0007
        #define MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_15G       0x0008
        #define MDIO_SERDES_DIGITAL_MISC1_FORCE_SPEED_16G       0x0009

#define MDIO_REG_BANK_OVER_1G                           0x8320
    #define MDIO_OVER_1G_DIGCTL_3_4                         0x14
        #define MDIO_OVER_1G_DIGCTL_3_4_MP_ID_MASK              0xffe0 //message page ID for over 1G next pages
        #define MDIO_OVER_1G_DIGCTL_3_4_MP_ID_SHIFT             5
    #define MDIO_OVER_1G_UP1                                0x19
        #define MDIO_OVER_1G_UP1_2_5G                           0x0001
        #define MDIO_OVER_1G_UP1_5G                             0x0002
        #define MDIO_OVER_1G_UP1_6G                             0x0004
        #define MDIO_OVER_1G_UP1_10G                            0x0010
        #define MDIO_OVER_1G_UP1_10GH                           0x0008
//        #define MDIO_OVER_1G_UP1_10G                            0x0008 - yaronw
//        #define MDIO_OVER_1G_UP1_10GH                           0x0010 - yaronw
        #define MDIO_OVER_1G_UP1_12G                            0x0020
        #define MDIO_OVER_1G_UP1_12_5G                          0x0040
        #define MDIO_OVER_1G_UP1_13G                            0x0080
        #define MDIO_OVER_1G_UP1_15G                            0x0100
        #define MDIO_OVER_1G_UP1_16G                            0x0200
    #define MDIO_OVER_1G_UP2                                0x1A
        #define MDIO_OVER_1G_UP2_IPREDRIVER_MASK                0x0007
        #define MDIO_OVER_1G_UP2_IDRIVER_MASK                   0x0038
        #define MDIO_OVER_1G_UP2_PREEMPHASIS_MASK               0x03C0
    #define MDIO_OVER_1G_UP3                                0x1B
        #define MDIO_OVER_1G_UP3_HIGIG2                         0x0001
    #define MDIO_OVER_1G_LP_UP1                             0x1C
    #define MDIO_OVER_1G_LP_UP2                             0x1D
        #define MDIO_OVER_1G_LP_UP2_MR_ADV_OVER_1G_MASK         0x03ff
        #define MDIO_OVER_1G_LP_UP2_PREEMPHASIS_MASK            0x0780
        #define MDIO_OVER_1G_LP_UP2_PREEMPHASIS_SHIFT           7
    #define MDIO_OVER_1G_LP_UP3                             0x1E

#define MDIO_REG_BANK_BAM_NEXT_PAGE                     0x8350
    #define MDIO_BAM_NEXT_PAGE_MP5_NEXT_PAGE_CTRL           0x10
        #define MDIO_BAM_NEXT_PAGE_MP5_NEXT_PAGE_CTRL_BAM_MODE  0x0001  //force teton_mode override
        #define MDIO_BAM_NEXT_PAGE_MP5_NEXT_PAGE_CTRL_TETON_AN  0x0002  //force teton_mode override value

#define MDIO_REG_BANK_CL73_USERB0                       0x8370
    #define MDIO_CL73_USERB0_CL73_BAM_CTRL1                 0x12
        #define MDIO_CL73_USERB0_CL73_BAM_CTRL1_BAM_EN                  0x8000 //Clause73 BAM73 AN enable
        #define MDIO_CL73_USERB0_CL73_BAM_CTRL1_BAM_STATION_MNGR_EN     0x4000 //BAM73 Station Manager enable
        #define MDIO_CL73_USERB0_CL73_BAM_CTRL1_BAM_NP_AFTER_BP_EN      0x2000 //Enables STA to send BAM73 Next Pagess immediately after Base Page; otherwise send BAM73 NPs following software NPs
    #define MDIO_CL73_USERB0_CL73_BAM_CTRL3                 0x14
        #define MDIO_CL73_USERB0_CL73_BAM_CTRL3_USE_CL73_HCD_MR 0x0001

#define MDIO_REG_BANK_AER_BLOCK                         0xFFD0 // Address Expansion Register
    #define MDIO_AER_BLOCK_AER_REG                          0x1E

#define MDIO_REG_BANK_COMBO_IEEE0                       0xFFE0
    #define MDIO_COMBO_IEEE0_MII_CONTROL                    0x10
        #define MDIO_COMBO_IEEO_MII_CONTROL_MAN_SGMII_SP_MASK   0x2040 //The 2 bits are split
        #define MDIO_COMBO_IEEO_MII_CONTROL_MAN_SGMII_SP_10     0x0000
        #define MDIO_COMBO_IEEO_MII_CONTROL_MAN_SGMII_SP_100    0x2000
        #define MDIO_COMBO_IEEO_MII_CONTROL_MAN_SGMII_SP_1000   0x0040
        #define MDIO_COMBO_IEEO_MII_CONTROL_FULL_DUPLEX         0x0100 //0=half duplex
        #define MDIO_COMBO_IEEO_MII_CONTROL_RESTART_AN          0x0200
        #define MDIO_COMBO_IEEO_MII_CONTROL_AN_EN               0x1000
        #define MDIO_COMBO_IEEO_MII_CONTROL_LOOPBACK            0x4000
        #define MDIO_COMBO_IEEO_MII_CONTROL_RESET               0x8000
    #define MDIO_COMBO_IEEE0_MII_STATUS                     0x11
        #define MDIO_COMBO_IEEE0_MII_STATUS_LINK_PASS           0x0004 //status: 0=link fail; 1=link pass
        #define MDIO_COMBO_IEEE0_MII_STATUS_AUTONEG_COMPLETE    0x0020
    #define MDIO_COMBO_IEEE0_AUTO_NEG_ADV                   0x14
        #define MDIO_COMBO_IEEE0_AUTO_NEG_ADV_FULL_DUPLEX       0x0020
        #define MDIO_COMBO_IEEE0_AUTO_NEG_ADV_HALF_DUPLEX       0x0040
        #define MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_MASK        0x0180
        #define MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_NONE        0x0000
        #define MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_SYMMETRIC   0x0080
        #define MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_ASYMMETRIC  0x0100
        #define MDIO_COMBO_IEEE0_AUTO_NEG_ADV_PAUSE_BOTH        0x0180
        #define MDIO_COMBO_IEEE0_AUTO_NEG_ADV_NEXT_PAGE         0x8000 //supports additional pages using NP function
    #define MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1 0x15
        #define MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_NEXT_PAGE    0x8000 //1=LP is NP able; 0= not able
        #define MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_ACK          0x4000 //1=LP has received link code word
        #define MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_PAUSE_MASK   0x0180
        #define MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_PAUSE_NONE        0x0000
        //#define MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_PAUSE_SYMMETRIC   0x0080
        //#define MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_PAUSE_ASYMMETRIC  0x0100
        #define MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_PAUSE_BOTH        0x0180
        #define MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_HALF_DUP_CAP 0x0040
        #define MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_FULL_DUP_CAP 0x0020
        // When the link partner is in SGMII mode (bit 0 = 1), then
        // bit 15 = link, bit 12 = duplex, bits 11:10 = speed, bit 14 = acknowledge.
        // The other bits are reserved and should be zero
        #define MDIO_COMBO_IEEE0_AUTO_NEG_LINK_PARTNER_ABILITY1_SGMII_MODE   0x0001 //1=SGMII mode; 0=fiber mode


// Optical Ext PHY (8705/6) registers
        #define EXT_PHY_AUTO_NEG_DEVAD                          0x7
        #define EXT_PHY_OPT_PMA_PMD_DEVAD                       0x1
        #define EXT_PHY_OPT_WIS_DEVAD                           0x2
        #define EXT_PHY_OPT_PCS_DEVAD                           0x3
        #define EXT_PHY_OPT_PHY_XS_DEVAD                        0x4
        #define EXT_PHY_OPT_CNTL                                0x0
        #define EXT_PHY_OPT_CNTL2                               0x7
        #define EXT_PHY_OPT_PMD_RX_SD                           0xa
        #define EXT_PHY_OPT_PMD_MISC_CNTL                       0xca0a
        #define EXT_PHY_OPT_PHY_IDENTIFIER                      0xc800
        #define EXT_PHY_OPT_PMD_DIGITAL_CNT                     0xc808
        #define EXT_PHY_OPT_PMD_DIGITAL_SATUS                   0xc809
        #define EXT_PHY_OPT_CMU_PLL_BYPASS                      0xca09
        #define EXT_PHY_OPT_LASI_CNTL                           0x9002
        #define EXT_PHY_OPT_RX_ALARM                            0x9003
        #define EXT_PHY_OPT_LASI_STATUS                         0x9005
        #define EXT_PHY_OPT_PCS_STATUS                          0x0020
        #define EXT_PHY_OPT_XGXS_LANE_STATUS                    0x0018
        #define EXT_PHY_OPT_AN_LINK_STATUS                      0x8304
        #define EXT_PHY_OPT_AN_CL37_CL73                        0x8370
        #define EXT_PHY_OPT_AN_CL37_FD                          0xffe4
        #define EXT_PHY_OPT_AN_CL37_AN                          0xffe0
        #define EXT_PHY_OPT_AN_ADV                              0x11

// KR (8072) Registers
        #define EXT_PHY_KR_PMA_PMD_DEVAD                        0x1
        #define EXT_PHY_KR_PCS_DEVAD                            0x3
        #define EXT_PHY_KR_AUTO_NEG_DEVAD                       0x7
        #define EXT_PHY_KR_CTRL                                 0x0000
        #define EXT_PHY_KR_STATUS                               0x0001
        #define EXT_PHY_KR_AUTO_NEG_COMPLETE                    0x0020 //bit5
        #define EXT_PHY_KR_AUTO_NEG_ADVERT                      0x0010
        #define EXT_PHY_KR_AUTO_NEG_ADVERT_PAUSE                0x0400 //bit10
        #define EXT_PHY_KR_AUTO_NEG_ADVERT_PAUSE_ASYMMETRIC     0x0800 //bit11
        #define EXT_PHY_KR_AUTO_NEG_ADVERT_PAUSE_BOTH           0x0C00 //bit10+bit11
        #define EXT_PHY_KR_AUTO_NEG_ADVERT_PAUSE_MASK           0x0C00 //bit10+bit11
        #define EXT_PHY_KR_LP_AUTO_NEG                          0x0013
        #define EXT_PHY_KR_CTRL2                                0x0007
        #define EXT_PHY_KR_PCS_STATUS                           0x0020
        #define EXT_PHY_KR_PMD_CTRL                             0x0096
        #define EXT_PHY_KR_LASI_CNTL                            0x9002
        #define EXT_PHY_KR_LASI_STATUS                          0x9005
        #define EXT_PHY_KR_MISC_CTRL1                           0xca85
        #define EXT_PHY_KR_GEN_CTRL                             0xca10
        #define EXT_PHY_KR_ROM_CODE                             0xca19
        #define EXT_PHY_KR_ROM_RESET_INTERNAL_MP                0x0188
        #define EXT_PHY_KR_ROM_MICRO_RESET                      0x018a

// SFX7101 Registers
        #define EXT_PHY_SFX7101_XGXS_TEST1                      0xc00a


#endif //PHY_REG_H
