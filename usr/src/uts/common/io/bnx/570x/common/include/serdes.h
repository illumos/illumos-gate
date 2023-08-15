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

#ifndef _serdes_h_
#define _serdes_h_

#include "bcmtype.h"


/*
 * This structure defines the MDIO registers for the 2.5G Serdes block
 *   Only those registers relevant to normal operation and configuration
 *   are described.  Extra verbage is provided based on TetonII teams
 *   experience with the core.  Bible for all registers is still
 *   the spreadsheet provided by the serdes group.
 */
typedef struct serdes_reg
{
    u16_t mii_ctrl;            /* RW offset 0x00 */
        #define MII_CTRL_RESET (1<<15)  /* SC */ /* Reset:0 */
                /* Write of '1' initiate reset and will self clear when reset
                   is complete.  Read of '1' indicates if PHY is currently
                   executing reset. */
        #define MII_CTRL_LOOPBACK (1<<14)  /* RW */
                /* Value of '1' sets global loopback mode. */
        #define MII_CTRL_MANUAL_SPD0 (1<<13)  /* RW */
                /* Combine with <b>MANUAL_SPD1</b> and is valid in SGMII mode
                   only.<br>
                   00 = 10Mb/s<br>
                   01 = 100Mb/s<br>
                   10 = 1000Mb/s<br>
                   11 = reserved */
        #define MII_CTRL_ANEG_ENA (1<<12)  /* Reset:1 */
        #define MII_CTRL_POWER_DOWN (1<<11)
                /* Value of '1 enables low power mode. */
        #define MII_CTRL_RESTART_ANEG (1<<9) /* SC */
                /* Write of '1' initiate auto-negotiation and will self clear
                   when auto-negotiation
                   is complete. */
        #define MII_CTRL_DUPLEX_MODE (1<<8)
                /* Value of '1' indicates full duplex mode is set. */
        #define MII_CTRL_COLLISION_TEST (1<<7)
                /* Value of '1' enables collision test mode. */
        #define MII_CTRL_MANUAL_SPD1 (1<<6)  /* RW */
                /* Combine with <b>MANUAL_SPD0</b> and is valid in SGMII mode
                   only. */
        #define MII_CTRL_MANUAL_FORCE_2500 (1<<5)  /* RW */ /* Reset:0 */
                /* Force 2.5G mode when autoneg is disabled and <b>USE_IEEE</b>
                   is set.  Otherwise write as 0, ignore on read. */
                /* Reset value is from <b>serdes_control_reg[13]</b> value in
                   the misc block. */
    u16_t mii_status;           /* RO offset 0x01 */
        #define MII_STAT_100BASE_T4_CAP (1<<15) /* RO */ /* Reset:0 */
        #define MII_STAT_100BASE_X_FULL_DUP_CAP (1<<14) /* RO */ /* Reset:0 */
        #define MII_STAT_100BASE_X_HALF_DUP_CAP (1<<13) /* RO */ /* Reset:0 */
        #define MII_STAT_10BASE_T_FULL_DUP_CAP (1<<12) /* RO */ /* Reset:0 */
        #define MII_STAT_10BASE_T_HALF_DUP_CAP (1<<11) /* RO */ /* Reset:0 */
        #define MII_STAT_100BASE_T2_FULL_DUP_CAP (1<<10) /* RO */ /* Reset:0 */
        #define MII_STAT_100BASE_T2_HALF_DUP_CAP (1<<9) /* RO */ /* Reset:0 */
        #define MII_STAT_EXT_STATUS (1<<8) /* RO */ /* Reset:1 */
            /* Indicates that extended status information is in register f'h.
               */
        #define MII_STAT_MF_PREAMBLE_SUPP (1<<6) /* RO */ /* Reset:1 */
            /* Indicates that preamble is not require on all MII accesses. */
        #define MII_STAT_ANEG_CMPL (1<<5) /* RO */ /* Reset:0 */
            /* Value of '1' indicates auto-negotiation complete. */
            /* Value of '0' indicates auto-negotiation is in progress. */
        #define MII_STAT_REMOTE_FAULT (1<<4) /* AC */ /* Reset:0 */
            /* Value of '1' indicates remote fault detected. */
            /* This bit latches high until read. */
        #define MII_STAT_ANEG_ABILITY (1<<3) /* RO */ /* Reset:1 */
            /* Value of '1' indicates auto-negotiation capable. */
        #define MII_STAT_LINK_STATUS (1<<2) /* RO */ /* Reset:0 */
            /* Value of '1' indicates line pass. */
            /* Value of '0' indicates line fail. */
            /* This bit latches low until read. */
        #define MII_STAT_JABBER_DETECT (1<<1) /* RO */ /* Reset:0 */
            /* Value of '1' indicates jabber condition detected. */
        #define MII_STAT_EXTENDED_CAP (1<<0) /* RO */ /* Reset:1 */
            /* Value of '1' indicates that extended register capabilities are
               supported. */
    u16_t mii_phy_id_msb;       /* Reset:0x143 offset 0x02 */
            /* Bits [3:18] of organizationally unique identifier. */
    u16_t mii_phy_id_lsb;       /* offset 0x03 */
       #define MII_PHY_ID_OUI (0x3f<<10) /* RO */ /* Reset:0x2f */
            /* Bits [19:24] of organizationally unique identifier. */
       #define MII_PHY_ID_MODEL (0x3f<<4) /* RO */ /* Reset:0x15 */
            /* Device Mode number. */
       #define MII_PHY_ID_REV (0xf<<0) /* RO */ /* Reset:0 */
            /* Device revision number. */

    u16_t mii_aneg_advert;           /* RW offset 0x04 */
       #define MII_ADVERT_NXT_PG (1<<15) /* RO */
            /* Value of '0' indicates that next page ability capability can
               not be advertised. */
       #define MII_ADVERT_REM_FAULT (0x3<<12) /* RW */
        #define MII_ADVERT_REM_FAULT_NO_FAULT (0<<12)
                /* No remote fault */
        #define MII_ADVERT_REM_FAULT_LINK_FAILURE (1<<12)
                /* Link failure */
        #define MII_ADVERT_REM_FAULT_OFFLINE (2<<12)
                /* offline */
        #define MII_ADVERT_REM_FAULT_AUTONEG_ERR (3<<12)
                /* auto-negotiation error */
       #define MII_ADVERT_PAUSE (3<<7) /* RW */ /* Reset:0x3 */
        #define MII_ADVERT_NO_PAUSE (0x0<<7)
                /* Advertise no Pause */
        #define MII_ADVERT_SYM_PAUSE (0x1<<7)
                /* Advertise symmetric Pause */
        #define MII_ADVERT_ASYM_PAUSE (0x2<<7)
                /* Advertise asymmetric Pause toward link partner */
//        #define MII_ADVERT_PAUSE (0x3<<7)
                /* Advertise both symmetric pause and asymmetric pause
                   toward local device. */
       #define MII_ADVERT_HALF (1<<6) /* RW */  /* Reset:1 */
                /* Advertise half duplex capability. */
       #define MII_ADVERT_FULL (1<<5) /* RW */  /* Reset:1 */
    u16_t mii_aneg_ability;           /* RW offset 0x05 */
       #define MII_ABILITY_NXT_PG (1<<15) /* RO */
            /* Value of '1' indicates that link partner has next page ability.
               */
       #define MII_ABILITY_ACKNOWLEDGE (1<<14) /* RO */
            /* Value of '1' indicates that link partner has receive link code
               word. */
       #define MII_ABILITY_REM_FAULT (3<<12) /* RO */
         #define MII_ABILITY_REM_FAULT_AUTONEG_ERR (0<<12) /* RO */
            /* auto-negotiation error. */
         #define MII_ABILITY_REM_FAULT_OFFLINE (1<<12) /* RO */
            /* Offline. */
         #define MII_ABILITY_REM_FAULT_LINK_FAILURE (2<<12) /* RO */
            /* Link Failure. */
         #define MII_ABILITY_REM_FAULT_NO_FAULT (3<<12) /* RO */
            /* No remote fault detected. */
       #define MII_ABILITY_PAUSE (3<<7) /* RO */ /* Reset:0x3 */
        #define MII_ADVERT_NO_PAUSE (0x0<<7)
                /* Line partner indicates No Pause capable */
        #define MII_ADVERT_SYM_PAUSE (0x1<<7)
                /* Line partner wants Symmetric Pause capable */
        #define MII_ADVERT_ASYM_PAUSE (0x2<<7)
                /* Line partner wants Asymetric Pause toward link partner
                   capable */
//        #define MII_ADVERT_PAUSE (0x3<<7)
                /* Line partner wants Both symmetric pause and asymmetric pause
                   toward local device capable. */
       #define MII_ABILITY_HALF (1<<6) /* RO */ /* Reset:1 */
                /* Value of '1' indicates Link partner is half duplex capable.
                   */
       #define MII_ABILITY_FULL (1<<5) /* RO */ /* Reset:1 */
                /* Value of '1' indicates Link partner is full duplex capable.
                   */
       #define MII_ABILITY_SGMII (1<<0) /* RO */
                /* Value of '1' indicates link partner is in SGMII mode. */
       /* When SGMII mode is enabled, reading values reflect values sent by
           link partner where:<br>
           [15] = copper link<br>
           [14] = acknowledge<br>
           [12] = copper duplex<br>
           [11:10] = copper speed<br>
           [0] = SGMII selector */
    u16_t mii_aneg_exp;           /* RW offset 0x06 */
       #define MII_ANEG_EXP_NP_ABLE (1<<2) /* RO */
            /* Value of '1' indicates local device is next page capable.
               */
       #define MII_ANEG_EXP_PG_RCV (1<<1) /* AC */
            /* Value of '1' indicates a new link code word has been received.
               */
    u16_t mii_aneg_nxt_pg;           /* RW offset 0x07 */
       #define MII_ANEG_NXT_PG_NX_PG (1<<15) /* RW */
            /* During SW controlled auto-negotiation, this value controls the
               next_page value in the next page generated. */
       #define MII_ANEG_NXT_PG_ACK (1<<14) /* RW */
            /* During SW controlled auto-negotiation, this value is controlled
               by autoneg state machine to confirm page reception. */
       #define MII_ANEG_NXT_PG_MP (1<<13) /* RW */
            /* During SW controlled auto-negotiation, this value controls the
               message page bit value in the next page generated. */
       #define MII_ANEG_NXT_PG_ACK2 (1<<12) /* RW */
            /* During SW controlled auto-negotiation, this value is controlled
               by autoneg state machine to confirm page reception. */
       #define MII_ANEG_NXT_PG_TOG (1<<11) /* RW */
            /* During SW controlled auto-negotiation, this value is controlled
               by autoneg state machine to confirm page reception. */
       #define MII_ANEG_NXT_PG_VALUE (0x7ff<<0) /* RW */
            /* During SW controlled auto-negotiation, this value controls the
               11-bit message page or unformatted code field in the next page
               generated. */
    u16_t mii_aneg_nxt_ability;           /* RW offset 0x08 */
       #define MII_ANEG_NXT_ABIL_NX_PG (1<<15) /* RW */
            /* During SW controlled auto-negotiation, this value reflects the
               next_page value in the last page received. */
       #define MII_ANEG_NXT_ABIL_ACK (1<<14) /* RW */
            /* During SW controlled auto-negotiation, this value is used
               by autoneg state machine to confirm page reception. */
       #define MII_ANEG_NXT_ABIL_MP (1<<13) /* RW */
            /* During SW controlled auto-negotiation, this value reflects the
               message page bit value in the last page received. */
       #define MII_ANEG_NXT_ABIL_ACK2 (1<<12) /* RW */
            /* During SW controlled auto-negotiation, this value is used
               by autoneg state machine to confirm page reception. */
       #define MII_ANEG_NXT_ABIL_TOG (1<<11) /* RW */
            /* During SW controlled auto-negotiation, this value is used
               by autoneg state machine to confirm page reception. */
       #define MII_ANEG_NXT_ABIL_VALUE (0x7ff<<0) /* RW */
            /* During SW controlled auto-negotiation, this value reflects the
               11-bit message page or unformatted code field in the last page
               received. */
    u16_t mii_reserved_9[2];               /* offset 0x09-0x0a */
    u16_t mii_aneg_nxt_pg_xmit1;           /* RW offset 0x0b */
            /* If <b>USE_IEEE</b> is set, this page is transmitted after
               the message page of value 1024 is sent.   */
       #define MII_ANEG_NXT_PG_XMIT1_VALUE (0x3ff<<1) /* RW */
            /* Advertise reserved BRCM proprietary values. */
       #define MII_ANEG_NXT_PG_XMIT1_2G5 (1<<0) /* RW */
            /* Reset value is defined by the
               value of <b>serdes_control_reg[11]</b> value in the misc block.
               Value advertizes 2.5G capability by BRCM
               proprietary convention.
               */
    u16_t mii_aneg_nxt_pg_xmit2;           /* RW offset 0x0c */
            /* If <b>USE_IEEE</b> is set, this page is transmitted after
               the <b>auto_nxt_pg_xmit1</b> page is sent.   */
       #define MII_ANEG_NXT_PG_XMIT2_VALUE (0x7ff<<0) /* RW */ /* Reset:0 */
            /* By BRCM proprietary convention, these bits advertize the
               pre-compensation value to be used for backplane media and should
               be non-zero if local end knows the nature of the backplane
               media. */
    u16_t mii_aneg_nxt_pg_rcv1;           /* RW offset 0x0d */
            /* This register shows the value received after the
               message page of value 1024 is received when
               <b>USE_IEEE</b> is set. */
       #define MII_ANEG_NXT_PG_RCV1_VALUE (0x3ff<<1) /* RW */
            /* The advertized capability of link partner for reserved
               BRCM proprietary values.
               */
       #define MII_ANEG_NXT_PG_RCV1_2G5 (1<<0) /* RW */
            /* The link partner advertized 2.5G capability by
               BRCM proprietary convention.
               */
    u16_t mii_aneg_nxt_pg_rcv2;           /* RW offset 0x0e */
            /* This register shows the value received after the
               <b>auto_nxt_pg_rcv1</b> page is received when
               <b>USE_IEEE</b> is set. */
       #define MII_ANEG_NXT_PG_RCV2_VALUE (0x7ff<<0) /* RW */ /* Reset:0 */
            /* By BRCM proprietary convention, bits [3:0] of this value are the
               advertized value of pre-emphasis value to be used for backplane
               media and should be non-zero if remote end knows the nature of
               the backplane media.
               Firmware must manually move this value to the <b>PREEMPHASIS</b>
               value in 5*0x17 and re-start auto-negotiation with the new
               pre-emphasis value in use.
             */
    u16_t mii_extend_stat;           /* RO offset 0x0f */
       #define MII_EXT_STAT_X_FULL_CAP (1<<15) /* RO */
                /* This bit indicates that the negotiated link is 1000Base-X
                   full duplex capable. */
       #define MII_EXT_STAT_X_HALF_CAP (1<<14) /* RO */
                /* This bit indicates that the negotiated link is 1000Base-X
                   half duplex capable. */
       #define MII_EXT_STAT_T_FULL_CAP (1<<13) /* RO */
                /* This bit indicates that the negotiated link is 1000Base-T
                   full duplex capable. */
       #define MII_EXT_STAT_T_HALF_CAP (1<<12) /* RO */
                /* This bit indicates that the negotiated link is 1000Base-T
                   half duplex capable. */
    u16_t mii_block[15];           /* RW offset 0x10-0x1e */
    u16_t mii_block_addr;          /* RW offset 0x1f */
       #define MII_BLK_ADDR_VALUE (0x1f<<0) /* RW */ /* VALUE: */
                /* Writes to this value set the block address value. */
            #define MII_BLK_ADDR_DIGITAL (0x0<<0)
                    /* This block value selects the digital register block. */
                    /* This block is partially documented in this spec. */
                    /* See SERDES documentation for full details on this
                       register block. */
            #define MII_BLK_ADDR_TEST (0x1<<0)
                    /* This block value selects the test register block. */
                    /* See SERDES documentation for details on this register
                       block. */
            #define MII_BLK_ADDR_DIGITAL3 (0x2<<0)
                    /* This block value selects the test register block. */
                    /* This block is partially documented in this spec. */
                    /* See SERDES documentation for full details on this
                       register block. */
            #define MII_BLK_ADDR_PLL (0x3<<0)
                    /* This block value selects the PLL register block. */
                    /* See SERDES documentation for details on this register
                       block. */
            #define MII_BLK_ADDR_RX (0x4<<0)
                    /* This block value selects the RX register block. */
                    /* See SERDES documentation for details on this register
                       block. */
            #define MII_BLK_ADDR_TXMISC (0x5<<0)
                    /* This block value selects the TX/Misc register block. */
                    /* This block is partially documented in this spec. */
                    /* See SERDES documentation for full details on this
                       register block. */

} serdes_reg_t;


/*
 * DIGITAL Block selected in <b>block</b> section of serdes
 * registers when <b>block_addr</b> value is 0.
 */
typedef struct serdes_digital_reg
{
    u16_t mii_1000x_ctl1;            /* RW */
       #define MII_1000X_CTL1_MSTR_MDIO_PHY_SEL (1<<13) /* RW */
                    /* When set to '1', all MDIO write accesses to PHY address
                       "00000" will write this PHY in addition to its own PHY
                       address. */
       #define MII_1000X_CTL1_TX_AMPL_ORIDE (1<<12) /* RW */
                    /* When set to '1', the transmit amplitude of the serdes
                       will com from register 1*10h, bit 14.
                       When set to '0', the amplitude is selected by fiber or
                       SGMII mode. */
       #define MII_1000X_CTL1_SEL_RX_PKTS_CNT (1<<11) /* RW */
                    /* When set to '1', received packets will be selected for
                       the 0*17h counter register. */
       #define MII_1000X_CTL1_REM_LOOP (1<<10) /* RW */
                    /* When set to '1', remote loopback is enabled.  This mode
                       only operates at gigabit speed. */
       #define MII_1000X_CTL1_ZERO_COMMA_PHASE (1<<9) /* RW */
                    /* When set to '1', the comma phase detector is forced to
                       zero. */
       #define MII_1000X_CTL1_COMMA_DET_EN (1<<8) /* RW */ /* Reset:1 */
                    /* When set to '1', the comma detector is enabled. */
       #define MII_1000X_CTL1_CRC_CHK_DIS (1<<7) /* RW */ /* Reset:1 */
                    /* When set to '1', the CRC checker is disabled by gating
                       the clock to that logic to save power. */
       #define MII_1000X_CTL1_PLL_PWR_DWN_DIS (1<<6) /* RW */ /* Reset:0 */
                    /* When set to '1', the PLL will never be powered down.
                       This is used when the MAC/Switch uses the tx_wclk_o
                       output of the SERDES core. */
       #define MII_1000X_CTL1_SGMII_MSTR (1<<5) /* RW */ /* Reset:0 */
                    /* When set to '1', the SGMII mode operates in "PHY mode",
                       sending out link, speed, and duplex settings from
                       register 0 of the copper PHY to the SERDES link partner.
                       */
       #define MII_1000X_CTL1_AUTODET_EN (1<<4) /* RW */ /* Reset:0 */
                    /* when set to '1', the PHY will switch between SGMII mode
                       and fiber mode when an auto-negotiation page is
                       received with the wrong selector field in bit 0.
                       When set to '0', selection of fiber/SGMII mode is
                       controlled by <b>FIBER_MODE</b> bit. */
       #define MII_1000X_CTL1_INV_SIG_DET (1<<3) /* RW */ /* Reset:0 */
                    /* When set to '1', the signal detect sense of the signal
                       detect input is active low, instead of active high. */
       #define MII_1000X_CTL1_SIG_DET_EN (1<<2) /* RW */ /* Reset:1 */
                    /* When set to '1', the signal detect input of the chip
                       must be active to link.  In SGMII mode, the signal
                       detect input is always ignored, regardless of the
                       setting of this bit. */
       #define MII_1000X_CTL1_TBI_INTF (1<<1) /* RW */ /* Reset:0 */
                    /* This bit must always be set to '0' for proper operation
                       of TetonII. */
       #define MII_1000X_CTL1_FIBER_MODE (1<<0) /* RW */
                    /* Reset value of this register is controlled by the
                       value of <b>serdes_control_reg[12]</b> value in the misc
                       block.
                       When this bit is '0', SGMII mode is selected.
                       When this bit is '1', Fiber mode (Clause 37 mode) is
                       selected.
                       Automatic mode selection, overiding this bit's value is
                       enabled by the <b>AUTONEG_EN</b> bit. */
    u16_t mii_1000x_ctl2;            /* RW */
       #define MII_1000X_CTL2_TEST_CNTR (1<<11) /* RW */ /* Reset:0 */
                    /* When this bit is '1', the counter at location 0*17h
                       counts on each clock for testing. */
       #define MII_1000X_CTL2_BYP_PCS_TX (1<<10) /* RW */ /* Reset:0 */
                    /* When this bit is '1', the PCS transmit section
                       is bypassed. */
       #define MII_1000X_CTL2_BYP_PCS_RX (1<<9) /* RW */ /* Reset:0 */
                    /* When this bit is '1', the PCS receive section
                       is bypassed. */
       #define MII_1000X_CTL2_TRRR_GEN_DIS (1<<8) /* RW */ /* Reset:0 */
                    /* When this bit is '1', the TRRR generation in the PCS
                       transmit is disabled. */
       #define MII_1000X_CTL2_CARRIER_EXT_DIS (1<<7) /* RW */ /* Reset:0 */
                    /* When this bit is '1', carrier extension in the PCS
                       receive is disabled. */
       #define MII_1000X_CTL2_FAST_TIMERS (1<<6) /* RW */ /* Reset:0 */
                    /* When this bit is '1', timers during auto-negotiation are
                       sped-up for testing. */
       #define MII_1000X_CTL2_FRCE_XMIT_DATA (1<<5) /* RW */ /* Reset:0 */
                    /* When this bit is '1', packets are allowed to transmit
                       regardless of the condition of link or synchronization.
                       */
       #define MII_1000X_CTL2_REM_FAULT_SENSE_DIS (1<<4) /* RW */ /* Reset:0 */
                    /* When this bit is '1', sensing of remote faults such as
                       auto-negotiation errors is disabled.
                       When this bit is '0', SERDES automatically detects
                       remote faults and sends remote fault status to link
                       partner via auto-negotiation when fiber mode is
                       selected.  SGMII mode does not support remote faults. */
       #define MII_1000X_CTL2_ANEG_ERR_TMR_EN (1<<3) /* RW */ /* Reset:0 */
                    /* When this bit is '1', it enables the auto-negotiation
                       error timer.  Error occurs when timer expires in
                       ability-detect, ack-detect, or idle-detect.  When the
                       error occurs, config words of all zeros are sent until
                       an ability match occurs, then the autoneg-enable state
                       is entered. */
       #define MII_1000X_CTL2_FILTER_FORCE_LINK (1<<2) /* RW */ /* Reset:0 */
                    /* When this bit is '1', sync-status must be set for a
                       solid 10ms before a valid link will be established when
                       auto-negotiation is disabled.  This is useful for fiber
                       application where the user does not have the signal
                       detect pin connnection to the fiber module and
                       auto-negotiation is turned off. */
       #define MII_1000X_CTL2_FLASE_LINK_DIS (1<<1) /* RW */ /* Reset:0 */
                    /* When this bit is '1', do not allow link to be
                       established when auto-negotiation is disabled and
                       receiving auto-negotiation code words.  The link will
                       only be established in this case after idles are
                       received.  This bit does not need to be set if
                       <b>PAR_DET_EN</b> is set. */
       #define MII_1000X_CTL2_PAR_DET_EN (1<<0) /* RW */ /* Reset:0 */
                    /* Reset value of this register is controlled by the
                       value of <b>serdes_control_reg[15]</b> value in the misc
                       block.
                       When this bit is '1', parallel detection will be
                       enabled.  This will turn auto-negotiation on and off as
                       needed to properly link up with the link partner.  The
                       idles and auto-negotiation code words received from the
                       link partner are used to make decision.   */
    u16_t mii_1000x_ctl3;            /* RW */
       #define MII_1000X_CTL3_DIS_TX_CRS (1<<13) /* RW */ /* Reset:0 */
                    /* When this bit is '1', generating CRS from transmitting
                       in half duplex mode is disabled.  Only receiving will
                       generate CRS. */
       #define MII_1000X_CTL3_INV_EXT_CRS (1<<12) /* RW */ /* Reset:0 */
                    /* When this bit is '1', the "receive rcs from PHY" pin
                       value will be inverted. */
       #define MII_1000X_CTL3_EXT_PHY_CRS (1<<11) /* RW */ /* Reset:0 */
                    /* When this bit is '1', use external pin for PHY's
                       "receive only" CRS output.  This is useful in 10/100
                       half-duplex applications to reduce the collision domain
                       latency.  This requires a PHY which generates a "receive
                       only" CRS output to a pin. */
       #define MII_1000X_CTL3_JAM_FALSE (1<<10) /* RW */ /* Reset:0 */
                    /* When this bit is '1', change false carriers received
                       into packets with preamble only.  Not necessary if MAC
                       uses CRS to determine collision. */
       #define MII_1000X_CTL3_BLOCK_TXEN (1<<9) /* RW */ /* Reset:0 */
                    /* When this bit is '1', block TXEN when necessary to
                       guarantee an IPG of at least 6.5 bytes in 10/100 mode
                       and 7 byte in 1G mode. */
       #define MII_1000X_CTL3_FORCE_TXFIFO_ON (1<<8) /* RW */ /* Reset:0 */
                    /* When this bit is '1', force transmit FIFO to free-run in
                       1G mode.  This requires clk_IN and tx_wclk_o to be
                       frequency locked. */
       #define MII_1000X_CTL3_BYP_TXFIFO1000 (1<<7) /* RW */ /* Reset:0 */
                    /* When this bit is '1', bypass transmit FIFO in 1G mode.
                       This is useful for fiber or gigabit only applications
                       where the MAC is using tx_wclk_o as the clk_in port.
                       MAC must meet timing to the tx_wclk_o domain. */
       #define MII_1000X_CTL3_FREQ_LOCK_ELAST_TX (1<<6) /* RW */ /* Reset:0 */
                    /* When this bit is '1', minimum FIFO latency to properly
                       handle a clock which is frequency locked, but out of
                       phase.  This over-rides bits [2:1] of this register.
                       Note:  tx_wclk_o and clk_in must be using the same
                       crystal. */
       #define MII_1000X_CTL3_FREQ_LOCK_ELAST_RX (1<<5) /* RW */ /* Reset:0 */
                    /* When this bit is '1', minimum FIFO latency to properly
                       handle a clock which is frequency locked, but out of
                       phase.  Not necessary if MAC users CRS to determine
                       collision.  This over-rides bits [2:1] of this register.
                       Note:  MAC and PHY must be using the same crystal for
                       this mode to be enabled. */
       #define MII_1000X_CTL3_ERLY_PREAMBLE_RX (1<<4) /* RW */ /* Reset:0 */
                    /* When this bit is '1', send extra bytes of preamble to
                       avoid FIFO latency.  Not needed if MAC uses CRS to
                       determine collision. */
       #define MII_1000X_CTL3_ERLY_PREAMBLE_TX (1<<3) /* RW */ /* Reset:0 */
                    /* When this bit is '1', send extra bytes of preamble to
                       avoid FIFO latency.  Uses in half-duplex applications to
                       reduce collision domain latency.  MAC must send 5 bytes
                       of preamble or less to avoid non-compliant behavior. */
       #define MII_1000X_CTL3_FIFO_ELAST (3<<1) /* RW */ /* Reset:0 */
        #define MII_1000X_CTL3_FIFO_ELAST_5K (0<<1)
            /* Supports packets up to 5k bytes. */
        #define MII_1000X_CTL3_FIFO_ELAST_10K (1<<1)
            /* Supports packets up to 10k bytes. */
        #define MII_1000X_CTL3_FIFO_ELAST_13K5 (2<<1)
            /* Supports packets up to 13.5k bytes. */
    #define MII_1000X_CTL3_TX_FIFO_RXT (1<<0)
                    /* When this bit is set to '1', the transmit FIFO is reset.
                       FIFO will remain in reset until this bit is cleared. */
    u16_t mii_reserved1;            /* RW */
    u16_t mii_1000x_stat1;            /* RO */
       #define MII_1000X_STAT1_TXFIFO_ERR_DET (1<<15) /* AC */ /* Reset:0 */
                    /* When this bit is '1', transmit FIFO error has been
                       detected since last read. */
       #define MII_1000X_STAT1_RXFIFO_ERR_DET (1<<14) /* AC */ /* Reset:0 */
                    /* When this bit is '1', receive FIFO error has been
                       detected since last read. */
       #define MII_1000X_STAT1_FALSE_CARRIER_DET (1<<13) /* AC */ /* Reset:0 */
                    /* When this bit is '1', flase carrier has been
                       detected since last read. */
       #define MII_1000X_STAT1_CRC_ERR_DET (1<<12) /* AC */ /* Reset:0 */
                    /* When this bit is '1', CRC error has been detected since
                       last read. */
       #define MII_1000X_STAT1_TX_ERR_DET (1<<11) /* AC */ /* Reset:0 */
                    /* When this bit is '1', a transmit error has been
                       detected.  This indicates tx_data_error_state in PCS
                       receive FSM has been reached since the last read. */
       #define MII_1000X_STAT1_RX_ERR_DET (1<<10) /* AC */ /* Reset:0 */
                    /* When this bit is '1', a receive error has been
                       detected.  This indicates early_end_state in PCS
                       receive FSM has been reached since the last read. */
       #define MII_1000X_STAT1_CARRIER_EXT_ERR_DET (1<<9) /* AC */ /* Reset:0 */
                    /* When this bit is '1', a carrier extend error code has
                       been detected.  This indicates extend_err_state in PCS
                       receive FSM has been reached since the last read. */
       #define MII_1000X_STAT1_EARLY_END_EXT_ERR_DET (1<<8) /* AC */ /* Reset:0 */
                    /* When this bit is '1', a early end extension error code
                       has been detected.  This indicates early_end_ext_state
                       in PCS receive FSM has been reached since the last
                       read. */
       #define MII_1000X_STAT1_LINK_STATUS (1<<7) /* RO */ /* Reset:0 */
                    /* When this bit is '1', it indicates that link has been up
                       the entire time since the last read.
                       This bit latches low until next read and return to '1'
                       upon read when link is up. */
       #define MII_1000X_STAT1_PAUSE_RX_RESOLVE (1<<6) /* RO */ /* Reset:0 */
                    /* This bit will read as '1' when auto-negotiation has
                       resolved to allow reception of pause frames locally. */
       #define MII_1000X_STAT1_PAUSE_TX_RESOLVE (1<<5) /* RO */ /* Reset:0 */
                    /* This bit will read as '1' when auto-negotiation has
                       resolved to allow transmission of pause frames
                       locally. */
       #define MII_1000X_STAT1_SPEED (3<<3) /* RO */ /* Reset:0 */
                    /* These bits indicate the current speed status. */
            #define MII_1000X_STAT1_SPEED_10 (0<<3) /* 10 MBPS */
            #define MII_1000X_STAT1_SPEED_100 (1<<3) /* 100 MBPS */
            #define MII_1000X_STAT1_SPEED_1G (2<<3) /* 1 GBPS */
            #define MII_1000X_STAT1_SPEED_2G5 (3<<3) /* 2.5 GBPS */
       #define MII_1000X_STAT1_DUPLEX (1<<2) /* RO */ /* Reset:0 */
                    /* When this bit is '0', half duplex is enabled.
                       When this bit is '1', full duplex is enabled. */
       #define MII_1000X_STAT1_LINK (1<<1) /* RO */ /* Reset:0 */
                    /* When this bit is '1', the link is up.
                       When this bit is '0', the link is down. */
       #define MII_1000X_STAT1_SGMII_MODE (1<<0) /* RO */ /* Reset:0 */
                    /* When this bit is '1', SGMII mode has been selected.
                       When this bit is '0', Fiber mode has been selected. */
    u16_t mii_1000x_stat2;            /* RW */
       #define MII_1000X_STAT2_SGMII_CHG (1<<15) /* AC */ /* Reset:0 */
                    /* When this bit is '1', SGMII mode has changed since the
                       last read.  SGMII mode has been enabled or disabled.
                       This bit is useful when the auto-detection is enabled
                       in 0*10h, bit 4. */
       #define MII_1000X_STAT2_CONS_MISMATCH (1<<14) /* AC */ /* Reset:0 */
                    /* When this bit is '1', a consistency mismatch has been
                       detected since the last read. */
       #define MII_1000X_STAT2_ANEG_RES_ERR (1<<13) /* AC */ /* Reset:0 */
                    /* When this bit is '1', a auto-negotiation HCD error has
                       been detected since  the last read. */
       #define MII_1000X_STAT2_SGMII_SEL_MISMATCH (1<<12) /* AC */ /* Reset:0 */
                    /* When this bit is '1', a SGMII selector mismatch has
                       been detected since  the last read.  An auto-negotiation
                       page has been received from link partner with bit 0 = 0
                       while in SGMII mode.  */
       #define MII_1000X_STAT2_SYN_STAT_FAIL (1<<11) /* AC */ /* Reset:0 */
                    /* When this bit is '1', sync_status has failed since the
                       last read.  Synchronization has been lost. */
       #define MII_1000X_STAT2_SYN_STAT_OK (1<<10) /* AC */ /* Reset:0 */
                    /* When this bit is '1', sync_status ok has been detected
                       since the last read.  Synchronization has been achieved.
                     */
       #define MII_1000X_STAT2_RUDI_C (1<<9) /* AC */ /* Reset:0 */
                    /* When this bit is '1', rudi_c has been detected
                       since the last read.  */
       #define MII_1000X_STAT2_RUDI_I (1<<8) /* AC */ /* Reset:0 */
                    /* When this bit is '1', rudi_i has been detected
                       since the last read.  */
       #define MII_1000X_STAT2_RUDI_INVALID (1<<7) /* AC */ /* Reset:0 */
                    /* When this bit is '1', rudi_invalid has been detected
                       since the last read.  */
       #define MII_1000X_STAT2_AN_SYNC_STAT (1<<6) /* RO */ /* Reset:0 */
                    /* When this bit is '1', an_sync_status in auto-negotiation
                       block has not failed since last read.
                       When this bit is '0', an_sync_status in auto-negotiation
                       block has failed since last read.  Value sticks at '0'
                       until read. */
       #define MII_1000X_STAT2_IDLE_DET (1<<5) /* AC */ /* Reset:0 */
                    /* When this bit is '1', the idle detect state in
                       auto-negotiation fsm has been entered since last read.
                     */
       #define MII_1000X_STAT2_CMPL_ACK (1<<4) /* AC */ /* Reset:0 */
                    /* When this bit is '1', the complete acknowledge state in
                       auto-negotiation fsm has been entered since last read. */
       #define MII_1000X_STAT2_ACK_DET (1<<3) /* AC */ /* Reset:0 */
                    /* When this bit is '1', the acknowledge detect state in
                       auto-negotiation fsm has been entered since last read. */
       #define MII_1000X_STAT2_ABIL_DET (1<<2) /* AC */ /* Reset:0 */
                    /* When this bit is '1', the ability detect state in
                       auto-negotiation fsm has been entered since last read. */
       #define MII_1000X_STAT2_AN_ERR_DET (1<<1) /* AC */ /* Reset:0 */
                    /* When <b>ANEG_ERR_TMR_EN</b> is '1' and this bit is '1',
                       the an_error state in auto-negotiation fsm has been
                       entered since last read. */
                    /* When <b>ANEG_ERR_TMR_EN</b> is '0' and this bit is '1',
                       the an_disable_link_ok state in auto-negotiation fsm has
                       been entered since last read. */
       #define MII_1000X_STAT2_AN_EN_DET (1<<0) /* AC */ /* Reset:0 */
                    /* When this bit is '1', the an_enable state in
                       auto-negotiation fsm has been entered since last read. */
    u16_t mii_reserved2[9];            /* RW */

} serdes_digital_reg_t;

/*
 * DIGITAL3 Block selected in <b>block</b> section of serdes
 * registers when <b>block_addr</b> value is 2.
 */
typedef struct serdes_digital3_reg
{
    u16_t mii_digctl_3_0;            /* RW */
       #define MII_DIG3_USE_IEEE (1<<0) /* RW */ /* USE_IEEE: */
                    /* When this bit is '0', extended auto-negotiation
                       capabilities
                       and results are in digital_3 block registers.
                       When this bit is '1', extended auto-negotiation
                       capabilities and results are stored in digital block
                       registers. */
    u16_t mii_reserved1[14];            /* RW */

} serdes_digital3_reg_t;

/*
 * TX/Misc Block selected in <b>block</b> section of serdes
 * registers when <b>block_addr</b> value is 5.
 */
typedef struct serdes_tx_misc_reg
{
    u16_t mii_2500status1;            /* RW */
       #define MII_2500STAT1_HCDOVER1G (1<<12) /* RW */
                    /* When this bit is '1', the HCD is over 1G. */
       #define MII_2500STAT1_HCDOVER1G_STKY (1<<11) /* AC */
                    /* When this bit is '1', the HCD has been over 1G since the
                       last read. */
       #define MII_2500STAT1_BC_REG_RST (1<<10) /* AC */
                    /* When this bit is '1', then advertisement of over 1G has
                       been disabled due to repeated failures to link over 1G
                       since the last read. */
       #define MII_2500STAT1_COMPLETE (1<<9) /* AC */
                    /* 2.5G state machine has reached complete state since last
                       read. */
       #define MII_2500STAT1_WAIT4LINK (1<<8) /* AC */
                    /* 2.5G state machine has reached wait4link state since last
                       read. */
       #define MII_2500STAT1_PLLSWIT (1<<7) /* AC */
                    /* 2.5G state machine has reached pllswit state since last
                       read. */
       #define MII_2500STAT1_FORCE2500 (1<<6) /* AC */
                    /* 2.5G state machine has reached force2500 state since
                       last read. */
       #define MII_2500STAT1_DEAD (1<<5) /* AC */
                    /* 2.5G state machine has reached dead state since
                       last read. */
       #define MII_2500STAT1_WAIT2RES (1<<4) /* AC */
                    /* 2.5G state machine has reached wait2res state since
                       last read. */
    u16_t mii_reserved1[4];            /* RW */

    u16_t mii_txactl1;            /* RW */
        /* Use read-modify-write procedure for changing this register with
           firmware because default values may change from chip version to chip
           version, based on foundry, process, etc. */
       #define MII_TXACTL1_DRIVER_VCM (0x3<<4) /* RW */
                                               /* Reset:1 */
       #define MII_TXACTL1_PREEMPHASIS_PRE (0x7<<6) /* RW */
       #define MII_TXACTL1_DRIVEMODE (0x1<<9) /* RW */
       #define MII_TXACTL1_TX_TDATAEN (0x1<<10) /* RW */
       #define MII_TXACTL1_REFH_TX (0x1<<11) /* RW */
       #define MII_TXACTL1_REFL_TX (0x1<<12) /* RW */
       #define MII_TXACTL1_ID2C_2 (0x1<<13) /* RW */
            /* Bits [2] of ID2C. */

    u16_t mii_reserved2;            /* RW */

    u16_t mii_txactl3;            /* RW */
        /* Use read-modify-write procedure for changing this register with
           firmware because default values may change from chip version to chip
           version, based on foundry, process, etc. */
       #define MII_TXACTL3_PREEMPHASIS (0xf<<12) /* RW */
                    /* This value controls transmitter pre-emphasis.
                       Value is A where pre-emphasis=A/(40-A).  For example, if
                       register is set to 0x1, then pre-empasis co-efficient
                       is 1/(40-1)=0.025 or 1/39th of main tap current. */
                    /* This value is bit flipped such that the value is [0:3]
                       within the field. */
       #define MII_TXACTL3_IDRIVER (0xf<<8) /* RW */    /* Reset:0xe */
                    /* This value is bit flipped such that the value is [0:3]
                       within the field. */
       #define MII_TXACTL3_IPREDRIVER (0xf<<4) /* RW */    /* Reset:0x9 */
                    /* This value is bit flipped such that the value is [0:3]
                       within the field. */
       #define MII_TXACTL3_IFULLSPD (0x7<<1) /* RW */    /* Reset:0 */
                    /* This value is bit flipped such that the value is [0:2]
                       within the field. */
       #define MII_TXACTL3_ICBUF1T (0x1<<0) /* RW */    /* Reset:0 */

    u16_t mii_reserved3[7];            /* RW */

} serdes_tx_misc_reg_t;

#endif  /* _serdes_h_ */

/****************************************************************************
 * End of file
 ****************************************************************************/

