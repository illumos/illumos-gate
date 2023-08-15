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

#include "54xx_reg.h"
#include "serdes.h"
#include "lm5706.h"
#include "netlink.h"



/*******************************************************************************
 * Macros.
 ******************************************************************************/

#define MII_REG(_type, _field)          (OFFSETOF(_type, _field)/2)



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_mwrite(
    lm_device_t *pdev,
    u32_t phy_addr,
    u32_t reg,
    u32_t val)
{
    lm_status_t lm_status;
    u32_t tmp;
    u32_t cnt;

    DbgBreakIf(pdev->params.enable_remote_phy);

    if(pdev->params.phy_int_mode == PHY_INT_MODE_AUTO_POLLING)
    {
        REG_RD(pdev, emac.emac_mdio_mode, &tmp);
        tmp &= ~EMAC_MDIO_MODE_AUTO_POLL;

        REG_WR(pdev, emac.emac_mdio_mode, tmp);

        mm_wait(pdev, 40);
    }

    tmp = (phy_addr << 21) |
        (reg << 16) |
        val |
        EMAC_MDIO_COMM_COMMAND_WRITE_TE |
        EMAC_MDIO_COMM_START_BUSY |
        EMAC_MDIO_COMM_DISEXT;

    REG_WR(pdev, emac.emac_mdio_comm, tmp);

    for(cnt = 0; cnt < 1000; cnt++)
    {
        mm_wait(pdev, 10);

        REG_RD(pdev, emac.emac_mdio_comm, &tmp);
        if(!(tmp & EMAC_MDIO_COMM_START_BUSY))
        {
            mm_wait(pdev, 5);
            break;
        }
    }

    if(tmp & EMAC_MDIO_COMM_START_BUSY)
    {
        DbgBreakMsg("Write phy register failed\n");

        lm_status = LM_STATUS_FAILURE;
    }
    else
    {
        lm_status = LM_STATUS_SUCCESS;
    }

    if(pdev->params.phy_int_mode == PHY_INT_MODE_AUTO_POLLING)
    {
        REG_RD(pdev, emac.emac_mdio_mode, &tmp);
        tmp |= EMAC_MDIO_MODE_AUTO_POLL;

        REG_WR(pdev, emac.emac_mdio_mode, tmp);
    }

    return lm_status;
} /* lm_mwrite */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_mread(
    lm_device_t *pdev,
    u32_t phy_addr,
    u32_t reg,
    u32_t *ret_val)
{
    lm_status_t lm_status;
    u32_t val;
    u32_t cnt;

    DbgBreakIf(pdev->params.enable_remote_phy);

    if(pdev->params.phy_int_mode == PHY_INT_MODE_AUTO_POLLING)
    {
        REG_RD(pdev, emac.emac_mdio_mode, &val);
        val &= ~EMAC_MDIO_MODE_AUTO_POLL;

        REG_WR(pdev, emac.emac_mdio_mode, val);

        mm_wait(pdev, 40);
    }

    val = (phy_addr << 21) |
        (reg << 16) |
        EMAC_MDIO_COMM_COMMAND_READ_TE |
        EMAC_MDIO_COMM_DISEXT |
        EMAC_MDIO_COMM_START_BUSY;

    REG_WR(pdev, emac.emac_mdio_comm, val);

    for(cnt = 0; cnt < 1000; cnt++)
    {
        mm_wait(pdev, 10);

        REG_RD(pdev, emac.emac_mdio_comm, &val);
        if(!(val & EMAC_MDIO_COMM_START_BUSY))
        {
            /* There is a bug here.  The MI_COM_BUSY bit may be cleared
             * before the data is loaded into the register. */
            REG_RD(pdev, emac.emac_mdio_comm, &val);

            REG_RD(pdev, emac.emac_mdio_comm, &val);
            val &= EMAC_MDIO_COMM_DATA;

            break;
        }
    }

    if(val & EMAC_MDIO_COMM_START_BUSY)
    {
        DbgBreakMsg("Read phy register failed\n");

        val = 0;

        lm_status = LM_STATUS_FAILURE;
    }
    else
    {
        lm_status = LM_STATUS_SUCCESS;
    }

    *ret_val = val;

    if(pdev->params.phy_int_mode == PHY_INT_MODE_AUTO_POLLING)
    {
        REG_RD(pdev, emac.emac_mdio_mode, &val);
        val |= EMAC_MDIO_MODE_AUTO_POLL;

        REG_WR(pdev, emac.emac_mdio_mode, val);
    }

    return lm_status;
} /* lm_mread */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
phy_ad_settings(
    lm_device_t *pdev,
    lm_medium_t req_medium,
    lm_flow_control_t flow_ctrl)
{
    u32_t val;

    val = 0;

    /* Please refer to Table 28B-3 of the 802.3ab-1999 spec. */
    if((flow_ctrl == LM_FLOW_CONTROL_AUTO_PAUSE) ||
        ((flow_ctrl & LM_FLOW_CONTROL_RECEIVE_PAUSE) &&
        (flow_ctrl & LM_FLOW_CONTROL_TRANSMIT_PAUSE)))
    {
        if(GET_MEDIUM_TYPE(req_medium) == LM_MEDIUM_TYPE_FIBER)
        {
            if(CHIP_NUM(pdev) == CHIP_NUM_5706)
            {
                val |= PHY_AN_AD_1000X_PAUSE_CAPABLE |
                    PHY_AN_AD_1000X_ASYM_PAUSE;
            }
            else
            {
                val |= MII_ADVERT_PAUSE;
            }
        }
        else
        {
            val |= PHY_AN_AD_PAUSE_CAPABLE | PHY_AN_AD_ASYM_PAUSE;
        }
    }
    else if(flow_ctrl & LM_FLOW_CONTROL_TRANSMIT_PAUSE)
    {
        if(GET_MEDIUM_TYPE(req_medium) == LM_MEDIUM_TYPE_FIBER)
        {
            if(CHIP_NUM(pdev) == CHIP_NUM_5706)
            {
                val |= PHY_AN_AD_1000X_ASYM_PAUSE;
            }
            else
            {
                val |= MII_ADVERT_ASYM_PAUSE;
            }
        }
        else
        {
            val |= PHY_AN_AD_ASYM_PAUSE;
        }
    }
    else if(flow_ctrl & LM_FLOW_CONTROL_RECEIVE_PAUSE)
    {
        if(GET_MEDIUM_TYPE(req_medium) == LM_MEDIUM_TYPE_FIBER)
        {
            if(CHIP_NUM(pdev) == CHIP_NUM_5706)
            {
                val |= PHY_AN_AD_1000X_PAUSE_CAPABLE |
                    PHY_AN_AD_1000X_ASYM_PAUSE;
            }
            else
            {
                val |= MII_ADVERT_PAUSE;
            }
        }
        else
        {
            val |= PHY_AN_AD_PAUSE_CAPABLE | PHY_AN_AD_ASYM_PAUSE;
        }
    }

    return val;
} /* phy_ad_settings */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
init_utp(
    lm_device_t *pdev,
    lm_medium_t req_medium,
    lm_flow_control_t flow_ctrl,
    u32_t selective_autoneg,
    u32_t wire_speed,
    u32_t wait_link_timeout_us)
{
    u32_t restart_autoneg;
    lm_status_t lm_status;
    lm_medium_t duplex;
    lm_medium_t speed;
    u32_t val;
    u32_t cnt;

    if(GET_MEDIUM_TYPE(req_medium) != LM_MEDIUM_TYPE_UTP)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    speed = GET_MEDIUM_SPEED(req_medium);
    duplex = GET_MEDIUM_DUPLEX(req_medium);

    lm_status = LM_STATUS_SUCCESS;

    (void) lm_mwrite(pdev, pdev->params.phy_addr, PHY_CTRL_REG, PHY_CTRL_PHY_RESET);
    for(cnt = 0; cnt < 1000; cnt++)
    {
        mm_wait(pdev, 5);

        (void) lm_mread(pdev, pdev->params.phy_addr, PHY_CTRL_REG, &val);

        if(!(val & PHY_CTRL_PHY_RESET))
        {
            mm_wait(pdev, 5);

            break;
        }
    }

    DbgBreakIf(val & PHY_CTRL_PHY_RESET);

    /* Get the PHY id. */
    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_ID1_REG, &val);
    pdev->hw_info.phy_id = val << 16;
    DbgMessage1(pdev, INFORM, "Phy Id1 0x%x\n", val);

    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_ID2_REG, &val);
    pdev->hw_info.phy_id |= val & 0xffff;
    DbgMessage1(pdev, INFORM, "Phy Id2 0x%x\n", val);

    DbgBreakIf(
        (pdev->hw_info.phy_id & 0x0fffffff) == 0x0fffffff ||
        pdev->hw_info.phy_id == 0);

    if(CHIP_REV(pdev) == CHIP_REV_FPGA)
    {
        /* Configure how the MAC obtain link from the external PHY.
         * On the FPGA board, LED2 is used as a link signal into the
         * MAC.  Configure LED2 to a link event on the AC101L PHY. */
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 28, 0x3044);
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 29, 0x0100);
    }
    else
    {
        if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
        {
            /* Gen6 PHY core has a slight increase in CRC error.
             * This will workaround the problem which will be
             * fixed in Gen7 PHY core. */
            (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x18, 0x0c00);
            (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x17, 0x000a);
            (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x15, 0x310b);
            (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x17, 0x201f);
            (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x15, 0x9506);
            (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x17, 0x401f);
            (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x15, 0x14e2);
            (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x18, 0x0400);
        }

        /* Enable/Disable Ethernet@WireSpeed. */
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x18, 0x7007);
        (void) lm_mread(pdev, pdev->params.phy_addr, 0x18, &val);

        val &= 0x0ff8;

        if(wire_speed)
        {
            val |= 0x10;
        }
        else
        {
            val &= ~0x10;
        }
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x18, val | 0x8000 | 0x7);

        /*
         * Cont00039501	Issue Description: Auto MDIX mode doesn't work in forced speed
         * while two 5716 connected back-to-back
         */
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x18, 0x7007);
        (void) lm_mread(pdev, pdev->params.phy_addr, 0x18, &val);
        val |= BIT_9; /*auto mdix*/
        (void) lm_mwrite(pdev, pdev->params.phy_addr, BCM5401_AUX_CTRL, val | 0x8000 | 0x7);

    }

    /* Expansion register 0x8 is the 10BT control register.  BIT 8 of this
     * register controls the Early DAC Wakeup Enable.  this bit allows the
     * transmitter to be shutdown in 10BT mode except for sending out link
     * pulses. This allows for a low power operation in 10BT mode which is
     * useful in WOL application.  The default value of this register bit
     * gets loaded from a strap value on the GPHY provided by the chip that
     * instantiates the PHY.  in Xinan this strap value is 1, meaning that
     * the early DAC Wakeup Enable bit is set by default. FW/Driver needs to
     * clear this bit when bringing the PHY out of reset. */
    if(CHIP_ID(pdev) == CHIP_ID_5709_A0 ||
        CHIP_ID(pdev) == CHIP_ID_5709_A1 ||
        CHIP_ID(pdev) == CHIP_ID_5709_B0 ||
        CHIP_ID(pdev) == CHIP_ID_5709_B1)
    {
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x17, 0xf08);
        (void) lm_mread(pdev, pdev->params.phy_addr, 0x15, &val);
        val &= ~0x100;
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x15, val);
    }

    /* Configure the PHY for jumbo frame. */
    if(pdev->params.mtu > MAX_ETHERNET_PACKET_SIZE)
    {
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x10, 0x0001);
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x18, 0x4400);
    }
    else
    {
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x10, 0x0000);
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x18, 0x0400);
    }

    /* Configure line speed. */
    restart_autoneg = FALSE;

    switch(speed)
    {
        case LM_MEDIUM_SPEED_10MBPS:
            /* Don't advertise 1000mb.  This register is undefined on a
             * 10/100 Mb PHY. */
            (void) lm_mwrite(pdev, pdev->params.phy_addr, PHY_1000BASET_CTRL_REG, 0);

            /* Setup AN_AD to advertise 10mb. */
            val = PHY_AN_AD_PROTOCOL_802_3_CSMA_CD;
            val |= phy_ad_settings(pdev, req_medium, flow_ctrl);

            if(duplex == LM_MEDIUM_FULL_DUPLEX)
            {
                val |= PHY_AN_AD_10BASET_FULL;

                if(selective_autoneg == SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS)
                {
                    val |= PHY_AN_AD_10BASET_HALF;
                }
            }
            else
            {
                val |= PHY_AN_AD_10BASET_HALF;
            }

            (void) lm_mwrite(pdev, pdev->params.phy_addr, PHY_AN_AD_REG, val);

            /* Forcing or advertising 10mb. */
            if(selective_autoneg)
            {
                restart_autoneg = TRUE;

                DbgMessage(pdev, INFORM, "autoneg 10mb hd\n");
                if(duplex == LM_MEDIUM_FULL_DUPLEX)
                {
                    DbgMessage(pdev, INFORM, "and 10mb fd\n");
                }
            }
            else
            {
                if(duplex == LM_MEDIUM_HALF_DUPLEX)
                {
                    DbgMessage(pdev, INFORM, "force 10mb hd\n");
                    (void) lm_mwrite(
                        pdev,
                        pdev->params.phy_addr,
                        PHY_CTRL_REG,
                        PHY_CTRL_SPEED_SELECT_10MBPS);
                }
                else
                {
                    DbgMessage(pdev, INFORM, "force 10mb fd\n");
                    (void) lm_mwrite(
                        pdev,
                        pdev->params.phy_addr,
                        PHY_CTRL_REG,
                        PHY_CTRL_SPEED_SELECT_10MBPS |
                            PHY_CTRL_FULL_DUPLEX_MODE);
                }
            }

            break;

        case LM_MEDIUM_SPEED_100MBPS:
            /* Don't advertise 1000mb.  This register is undefined on a
             * 10/100 PHY. */
            (void) lm_mwrite(pdev, pdev->params.phy_addr, PHY_1000BASET_CTRL_REG, 0);

            /* Setup AN_AD to advertise 10/100mb. */
            val = PHY_AN_AD_PROTOCOL_802_3_CSMA_CD;
            val |= phy_ad_settings(pdev, req_medium, flow_ctrl);

            if(selective_autoneg == SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS)
            {
                val |= PHY_AN_AD_10BASET_HALF | PHY_AN_AD_10BASET_FULL;
            }

            if(duplex == LM_MEDIUM_FULL_DUPLEX)
            {
                val |= PHY_AN_AD_100BASETX_FULL;

                if(selective_autoneg == SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS)
                {
                    val |= PHY_AN_AD_100BASETX_HALF;
                }
            }
            else
            {
                val |= PHY_AN_AD_100BASETX_HALF;
            }

            (void) lm_mwrite(pdev, pdev->params.phy_addr, PHY_AN_AD_REG, val);

            /* Forcing or advertising 100mb. */
            if(selective_autoneg)
            {
                restart_autoneg = TRUE;

                DbgMessage(pdev, INFORM, "autoneg 10mb and 100mb hd\n");
                if(duplex == LM_MEDIUM_FULL_DUPLEX)
                {
                    DbgMessage(pdev, INFORM, "and 100mb fd\n");
                }
            }
            else
            {
                if(duplex == LM_MEDIUM_HALF_DUPLEX)
                {
                    DbgMessage(pdev, INFORM, "force 100mb hd\n");
                    (void) lm_mwrite(
                        pdev,
                        pdev->params.phy_addr,
                        PHY_CTRL_REG,
                        PHY_CTRL_SPEED_SELECT_100MBPS);
                }
                else
                {
                    DbgMessage(pdev, INFORM, "force 100mb fd\n");
                    (void) lm_mwrite(
                        pdev,
                        pdev->params.phy_addr,
                        PHY_CTRL_REG,
                        PHY_CTRL_SPEED_SELECT_100MBPS |
                            PHY_CTRL_FULL_DUPLEX_MODE);
                }
            }

            break;

        case LM_MEDIUM_SPEED_1000MBPS:
            /* Don't advertise 10/100mb. */
            val = PHY_AN_AD_PROTOCOL_802_3_CSMA_CD;
            val |= phy_ad_settings(pdev, req_medium, flow_ctrl);

            if(selective_autoneg == SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS)
            {
                val |= PHY_AN_AD_10BASET_HALF | PHY_AN_AD_10BASET_FULL;
                val |= PHY_AN_AD_100BASETX_HALF | PHY_AN_AD_100BASETX_FULL;
            }

            (void) lm_mwrite(pdev, pdev->params.phy_addr, PHY_AN_AD_REG, val);

            /* Setup AN_AD to advertise 1000mb.  This register is defined on
             * a 10/100 Mb PHY. */
            if(duplex == LM_MEDIUM_FULL_DUPLEX)
            {
                val |= PHY_AN_AD_1000BASET_FULL;

                if(selective_autoneg == SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS)
                {
                    val |= PHY_AN_AD_1000BASET_HALF;
                }
            }
            else
            {
                val |= PHY_AN_AD_1000BASET_HALF;
            }

            /* Forcing or advertising 1000mb. */
            if(selective_autoneg)
            {
                DbgMessage(pdev, INFORM, "autoneg 10/100mb and 1000mb hd\n");
                if(duplex == LM_MEDIUM_FULL_DUPLEX)
                {
                    DbgMessage(pdev, INFORM, "and 1000mb fd\n");
                }

                restart_autoneg = TRUE;
            }
            else
            {
                /* external loopback at 1gb link. */
                (void) lm_mwrite(
                        pdev,
                        pdev->params.phy_addr,
                        PHY_CTRL_REG,
                        PHY_CTRL_SPEED_SELECT_1000MBPS);

                (void) lm_mwrite(pdev, pdev->params.phy_addr, BCM5401_AUX_CTRL, 0x7);
                (void) lm_mread(pdev, pdev->params.phy_addr, BCM5401_AUX_CTRL, &val);
                val |= BCM5401_SHDW_NORMAL_EXTERNAL_LOOPBACK;
                (void) lm_mwrite(pdev, pdev->params.phy_addr, BCM5401_AUX_CTRL, val);

                val = PHY_CONFIG_AS_MASTER | PHY_ENABLE_CONFIG_AS_MASTER;
            }

            (void) lm_mwrite(pdev, pdev->params.phy_addr, PHY_1000BASET_CTRL_REG, val);
            break;

        default:
            val = PHY_AN_AD_PROTOCOL_802_3_CSMA_CD |
                PHY_AN_AD_10BASET_HALF |
                PHY_AN_AD_10BASET_FULL |
                PHY_AN_AD_100BASETX_FULL |
                PHY_AN_AD_100BASETX_HALF;
            val |= phy_ad_settings(pdev, req_medium, flow_ctrl);

            /* Set up the 10/100 advertisement register. */
            (void) lm_mwrite(pdev, pdev->params.phy_addr, PHY_AN_AD_REG, val);

            /* Advertise 1000Mbps.  This register is undefined on a
             * 10/100 Mb PHY. */
            (void) lm_mwrite(
                pdev,
                pdev->params.phy_addr,
                PHY_1000BASET_CTRL_REG,
                PHY_AN_AD_1000BASET_HALF |
                    PHY_AN_AD_1000BASET_FULL);

            restart_autoneg = TRUE;
            speed = LM_MEDIUM_SPEED_AUTONEG;
            break;
    }

    /* exit mac loopback.  we could be in mac loopback mode if previously
     * the upper module calls lm_init_phy with LM_MEDIUM_TYPE_MAC_LOOPBACK
     * medium type for diagnostic. */
    REG_RD(pdev, emac.emac_mode, &val);
    val &= ~(EMAC_MODE_MAC_LOOP | EMAC_MODE_FORCE_LINK);
    REG_WR(pdev, emac.emac_mode, val);

    /* Restart auto-negotation. */
    if(restart_autoneg)
    {
        DbgMessage(pdev, INFORM, "phy init - restart autoneg\n");

        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            PHY_CTRL_REG,
            PHY_CTRL_AUTO_NEG_ENABLE | PHY_CTRL_RESTART_AUTO_NEG);
    }

    /* Save current medium settings. */
    SET_MEDIUM_TYPE(pdev->vars.medium, LM_MEDIUM_TYPE_UTP);
    SET_MEDIUM_SPEED(pdev->vars.medium, speed);
    SET_MEDIUM_DUPLEX(pdev->vars.medium, duplex);

    pdev->vars.cable_is_attached = FALSE;

    /* Wait for link. */
    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_STATUS_REG, &val);

    if(CHIP_REV(pdev) != CHIP_REV_FPGA)
    {
        /* Wait for link only if the cable is connected. */
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1c, 0x7c00);
        (void) lm_mread(pdev, pdev->params.phy_addr, 0x1c, &val);
        if(val & 0x20)
        {
            for(; ;)
            {
                (void) lm_mread(pdev, pdev->params.phy_addr, PHY_STATUS_REG, &val);
                if(val & PHY_STATUS_LINK_PASS)
                {
                    break;
                }

                mm_wait(pdev, 10);

                if(wait_link_timeout_us <= 10)
                {
                    break;
                }

                wait_link_timeout_us -= 10;
            }

            pdev->vars.cable_is_attached = TRUE;
        }
    }

    /* Need to read a second time to get the current link status. */
    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_STATUS_REG, &val);
    if(val & PHY_STATUS_LINK_PASS)
    {
        pdev->vars.link_status = LM_STATUS_LINK_ACTIVE;
        DbgMessage(pdev, INFORM, "phy init link up\n");

        pdev->vars.cable_is_attached = TRUE;
    }
    else
    {
        pdev->vars.link_status = LM_STATUS_LINK_DOWN;
        DbgMessage(pdev, INFORM, "phy init link down\n");
    }

    return lm_status;
} /* init_utp */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
mii_get_serdes_link_status(
    lm_device_t *pdev)
{
    u32_t val;

    /* The link status in the MII status register is not reliable for
     * the SERDES part.  We need to get the link info from the MAC. */
    if(CHIP_NUM(pdev) == CHIP_NUM_5706 &&
        lm_get_medium(pdev) == LM_MEDIUM_TYPE_FIBER)
    {
        REG_RD(pdev, emac.emac_status, &val);
        if(val & EMAC_STATUS_LINK)
        {
            val = PHY_STATUS_LINK_PASS;
        }
        else
        {
            val = 0;
        }
    }
    else
    {
        /* The second read returns the current status. */
        (void) lm_mread(pdev, pdev->params.phy_addr, PHY_STATUS_REG, &val);
        (void) lm_mread(pdev, pdev->params.phy_addr, PHY_STATUS_REG, &val);
    }

    return val;
} /* mii_get_serdes_link_status */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u8_t
set_5708_serdes_pre_emphasis(
    lm_device_t *pdev,
    u32_t pre_emphasis)
{
    u8_t restart_autoneg;
    u32_t val;

    restart_autoneg = FALSE;

    if(pre_emphasis == 0)
    {
        (void) lm_mread(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_aneg_nxt_pg_rcv2),
            &pre_emphasis);
        pre_emphasis &= 0xf;

        if(pre_emphasis != pdev->vars.serdes_pre_emphasis)
        {
            pdev->vars.serdes_pre_emphasis = pre_emphasis;

            restart_autoneg = TRUE;

            /* Switch to Bank 5. */
            (void) lm_mwrite(
                pdev,
                pdev->params.phy_addr,
                MII_REG(serdes_reg_t, mii_block_addr),
                MII_BLK_ADDR_TXMISC);

            /* Write the new pre-emphasis. */
            (void) lm_mread(
                pdev,
                pdev->params.phy_addr,
                0x10+MII_REG(serdes_tx_misc_reg_t, mii_txactl3),
                &val);

            pre_emphasis =
                ((pre_emphasis & 0x1) << 15) |
                ((pre_emphasis & 0x2) << 13) |
                ((pre_emphasis & 0x4) << 11) |
                ((pre_emphasis & 0x8) << 9);
            val = (val & 0x0fff) | pre_emphasis;

            (void) lm_mwrite(
                pdev,
                pdev->params.phy_addr,
                0x10+MII_REG(serdes_tx_misc_reg_t, mii_txactl3),
                val);

            /* Select Bank 0. */
            (void) lm_mwrite(
                pdev,
                pdev->params.phy_addr,
                MII_REG(serdes_reg_t, mii_block_addr),
                MII_BLK_ADDR_DIGITAL);

            /* Restart autoneg. */
            (void) lm_mwrite(
                pdev,
                pdev->params.phy_addr,
                MII_REG(serdes_reg_t, mii_ctrl),
                MII_CTRL_RESTART_ANEG | MII_CTRL_ANEG_ENA);
        }
    }
    else
    {
        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_block_addr),
            MII_BLK_ADDR_TXMISC);

        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            0x10+MII_REG(serdes_tx_misc_reg_t, mii_txactl3),
            pre_emphasis);

        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_block_addr),
            MII_BLK_ADDR_DIGITAL);
    }

    return restart_autoneg;
} /* set_5708_serdes_pre_emphasis */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
init_5708_serdes(
    lm_device_t *pdev,
    lm_medium_t req_medium,
    lm_flow_control_t flow_ctrl,
    u32_t selective_autoneg,
    u32_t wait_link_timeout_us)
{
    lm_medium_t duplex;
    lm_medium_t speed;
    u32_t cnt;
    u32_t val;

    if(GET_MEDIUM_SPEED(req_medium) == LM_MEDIUM_SPEED_UNKNOWN)
    {
        selective_autoneg = FALSE;
    }

    speed = GET_MEDIUM_SPEED(req_medium);
    duplex = GET_MEDIUM_DUPLEX(req_medium);

    if(speed == LM_MEDIUM_SPEED_HARDWARE_DEFAULT)
    {
        REG_RD_IND(
            pdev,
            pdev->hw_info.shmem_base +
                OFFSETOF(shmem_region_t, dev_info.port_hw_config.config),
            &val);

        switch(val & PORT_HW_CFG_DEFAULT_LINK_MASK)
        {
            case PORT_HW_CFG_DEFAULT_LINK_1G:
                speed = LM_MEDIUM_SPEED_1000MBPS;
                break;

            case PORT_HW_CFG_DEFAULT_LINK_2_5G:
                speed = LM_MEDIUM_SPEED_2500MBPS;
                break;

            default:
                speed = LM_MEDIUM_SPEED_UNKNOWN;
                break;
        }
    }

    /* Reset the SERDES. */
    (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_ctrl),
            MII_CTRL_RESET);

    for(cnt = 0; cnt < 1000; cnt++)
    {
        mm_wait(pdev, 5);

        (void) lm_mread(
                pdev,
                pdev->params.phy_addr,
                MII_REG(serdes_reg_t, mii_ctrl),
                &val);

        if(!(val & MII_CTRL_RESET))
        {
            mm_wait(pdev, 5);

            break;
        }
    }

    DbgBreakIf(val & MII_CTRL_RESET);

    /* Workaround for 5708A0 and B0.
     *
     * Errata 1.75: Tx peak-to-peak amplitude was measured as low
     * as 765mV under full PVT testing, whereas 800mV is considered
     * a passing result. */
    if(CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        /* Switch to Bank 5. */
        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_block_addr),
            MII_BLK_ADDR_TXMISC);

        (void) lm_mread(
            pdev,
            pdev->params.phy_addr,
            0x10+MII_REG(serdes_tx_misc_reg_t, mii_txactl1),
            &val);

        val &= ~ MII_TXACTL1_DRIVER_VCM;

        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            0x10+MII_REG(serdes_tx_misc_reg_t, mii_txactl1),
            val);
    }

    /* Set up pre-emphasis for a backplane application. */
    if(pdev->hw_info.nvm_hw_config & SHARED_HW_CFG_BACKPLANE_APP)
    {
        (void) set_5708_serdes_pre_emphasis(pdev, pdev->params.serdes_pre_emphasis);
    }

    /* Reset the pre_emphasis. */
    pdev->vars.serdes_pre_emphasis = 0;

    /* Get the PHY id. */
    (void) lm_mread(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_phy_id_msb),
            &val);
    pdev->hw_info.phy_id = val << 16;
    DbgMessage1(pdev, INFORM, "Phy Id1 0x%x\n", val);

    (void) lm_mread(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_phy_id_lsb),
            &val);
    pdev->hw_info.phy_id |= val & 0xffff;
    DbgMessage1(pdev, INFORM, "Phy Id2 0x%x\n", val);

    DbgBreakIf((pdev->hw_info.phy_id & 0x0fffffff) == 0x0fffffff ||
        pdev->hw_info.phy_id == 0);

    /* Enable 2.5G register set to be accessible in the IEEE registers. */
    (void) lm_mwrite(
        pdev,
        pdev->params.phy_addr,
        MII_REG(serdes_reg_t, mii_block_addr),
        MII_BLK_ADDR_DIGITAL3);
    (void) lm_mwrite(
        pdev,
        pdev->params.phy_addr,
        0x10+MII_REG(serdes_digital3_reg_t, mii_digctl_3_0),
        MII_DIG3_USE_IEEE);

    /* Switch back to the IEEE Bank. */
    (void) lm_mwrite(
        pdev,
        pdev->params.phy_addr,
        MII_REG(serdes_reg_t, mii_block_addr),
        MII_BLK_ADDR_DIGITAL);

    /* Enable SGMII/Fiber mode autodetection. */
    (void) lm_mread(
        pdev,
        pdev->params.phy_addr,
        0x10+MII_REG(serdes_digital_reg_t, mii_1000x_ctl1),
        &val);

    val |= MII_1000X_CTL1_FIBER_MODE | MII_1000X_CTL1_AUTODET_EN;

    /* Sigdet is enabled by default.  For backplane application, we need
     * to disable Sigdet by clearing 0*0x10.2 of the Digital Bank. */
    if(pdev->hw_info.nvm_hw_config & SHARED_HW_CFG_BACKPLANE_APP)
    {
        val &= ~MII_1000X_CTL1_SIG_DET_EN;
    }
    else
    {
        val |= MII_1000X_CTL1_SIG_DET_EN;
    }

    (void) lm_mwrite(
        pdev,
        pdev->params.phy_addr,
        0x10+MII_REG(serdes_digital_reg_t, mii_1000x_ctl1),
        val);

    /* We should always enable parallel detection. */
    (void) lm_mread(
        pdev,
        pdev->params.phy_addr,
        0x10+MII_REG(serdes_digital_reg_t, mii_1000x_ctl2),
        &val);

    val |= MII_1000X_CTL2_PAR_DET_EN;

    (void) lm_mwrite(
        pdev,
        pdev->params.phy_addr,
        0x10+MII_REG(serdes_digital_reg_t, mii_1000x_ctl2),
        val);

    /* Enable/disable 2.5G capability. */
    (void) lm_mread(
        pdev,
        pdev->params.phy_addr,
        MII_REG(serdes_reg_t, mii_aneg_nxt_pg_xmit1),
        &val);

    val &= ~MII_ANEG_NXT_PG_XMIT1_2G5;

    if(selective_autoneg)
    {
        if(speed == LM_MEDIUM_SPEED_2500MBPS)
        {
            val |= MII_ANEG_NXT_PG_XMIT1_2G5;
        }
    }
    else if(speed == LM_MEDIUM_SPEED_AUTONEG)
    {
        if(pdev->hw_info.nvm_hw_config & SHARED_HW_CFG_PHY_FIBER_2_5G)
        {
            val |= MII_ANEG_NXT_PG_XMIT1_2G5;
        }
    }
    else if(speed == LM_MEDIUM_SPEED_2500MBPS)
    {
        val |= MII_ANEG_NXT_PG_XMIT1_2G5;
    }

    (void) lm_mwrite(
        pdev,
        pdev->params.phy_addr,
        MII_REG(serdes_reg_t, mii_aneg_nxt_pg_xmit1),
        val);

    val = 0;

    if(selective_autoneg || speed == LM_MEDIUM_SPEED_UNKNOWN)
    {
        val |= phy_ad_settings(pdev, req_medium, flow_ctrl);

        if((selective_autoneg && speed == LM_MEDIUM_SPEED_1000MBPS) ||
            speed == LM_MEDIUM_SPEED_UNKNOWN)
        {
            val |= MII_ABILITY_HALF | MII_ABILITY_FULL;
        }

        (void) lm_mwrite(
                pdev,
                pdev->params.phy_addr,
                MII_REG(serdes_reg_t, mii_aneg_advert),
                val);

        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_ctrl),
            MII_CTRL_RESTART_ANEG | MII_CTRL_ANEG_ENA);

        speed = LM_MEDIUM_SPEED_AUTONEG;
    }
    else
    {
        switch(speed)
        {
            case LM_MEDIUM_SPEED_10MBPS:
                if(duplex == LM_MEDIUM_FULL_DUPLEX)
                {
                    val |= MII_CTRL_DUPLEX_MODE;
                }

                (void) lm_mwrite(
                        pdev,
                        pdev->params.phy_addr,
                        MII_REG(serdes_reg_t, mii_ctrl),
                        val);
                /* Switch to SGMII mode and disable auto-detect */
                (void) lm_mread(
                        pdev,
                        pdev->params.phy_addr,
                        0x10+MII_REG(serdes_digital_reg_t, mii_1000x_ctl1),
                        &val);
                (void) lm_mwrite(
                        pdev,
                        pdev->params.phy_addr,
                        0x10+MII_REG(serdes_digital_reg_t, mii_1000x_ctl1),
                        val & ~(MII_1000X_CTL1_FIBER_MODE | MII_1000X_CTL1_AUTODET_EN));
                break;

            case LM_MEDIUM_SPEED_100MBPS:
                if(duplex == LM_MEDIUM_FULL_DUPLEX)
                {
                    val |= MII_CTRL_DUPLEX_MODE;
                }

                val |= MII_CTRL_MANUAL_SPD0;

                (void) lm_mwrite(
                        pdev,
                        pdev->params.phy_addr,
                        MII_REG(serdes_reg_t, mii_ctrl),
                        val);
                /* Switch to SGMII mode and disable auto-detect */
                (void) lm_mread(
                        pdev,
                        pdev->params.phy_addr,
                        0x10+MII_REG(serdes_digital_reg_t, mii_1000x_ctl1),
                        &val);
                (void) lm_mwrite(
                        pdev,
                        pdev->params.phy_addr,
                        0x10+MII_REG(serdes_digital_reg_t, mii_1000x_ctl1),
                        val & ~(MII_1000X_CTL1_FIBER_MODE | MII_1000X_CTL1_AUTODET_EN));
                break;

            case LM_MEDIUM_SPEED_1000MBPS:
                if(duplex == LM_MEDIUM_FULL_DUPLEX)
                {
                    val |= MII_CTRL_DUPLEX_MODE;
                }

                val |= MII_CTRL_MANUAL_SPD1;

                (void) lm_mwrite(
                        pdev,
                        pdev->params.phy_addr,
                        MII_REG(serdes_reg_t, mii_ctrl),
                        val);
                break;

            case LM_MEDIUM_SPEED_2500MBPS:
                if(duplex == LM_MEDIUM_FULL_DUPLEX)
                {
                    val |= MII_CTRL_DUPLEX_MODE;
                }

                val |= MII_CTRL_MANUAL_FORCE_2500;

                (void) lm_mwrite(
                        pdev,
                        pdev->params.phy_addr,
                        MII_REG(serdes_reg_t, mii_ctrl),
                        val);
                break;
        }
    }

    /* exit mac loopback.  we could be in mac loopback mode if previously
     * the upper module calls lm_init_phy with LM_MEDIUM_TYPE_MAC_LOOPBACK
     * medium type for diagnostic. */
    REG_RD(pdev, emac.emac_mode, &val);
    val &= ~(EMAC_MODE_MAC_LOOP | EMAC_MODE_FORCE_LINK);
    REG_WR(pdev, emac.emac_mode, val);

    /* Configure the PHY for jumbo frame. */
    if(pdev->params.mtu > MAX_ETHERNET_PACKET_SIZE)
    {
        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            0x10+MII_REG(serdes_digital_reg_t, mii_1000x_ctl3),
            MII_1000X_CTL3_FIFO_ELAST_10K);
    }
    else
    {
        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            0x10+MII_REG(serdes_digital_reg_t, mii_1000x_ctl3),
            0);
    }

    /* Save current medium settings. */
    SET_MEDIUM_TYPE(pdev->vars.medium, LM_MEDIUM_TYPE_FIBER);
    SET_MEDIUM_SPEED(pdev->vars.medium, speed);
    SET_MEDIUM_DUPLEX(pdev->vars.medium, duplex);

    pdev->vars.cable_is_attached = FALSE;

    /* Wait for link. */
    (void) lm_mread(
        pdev,
        pdev->params.phy_addr,
        MII_REG(serdes_reg_t, mii_status),
        &val);

    for(; ;)
    {
        (void) lm_mread(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_status),
            &val);
        if(val & MII_STAT_LINK_STATUS)
        {
            break;
        }

        mm_wait(pdev, 10);

        if(wait_link_timeout_us <= 10)
        {
            break;
        }

        wait_link_timeout_us -= 10;
    }

    /* Need to read a second time to get the current link status. */
    (void) lm_mread(
        pdev,
        pdev->params.phy_addr,
        MII_REG(serdes_reg_t, mii_status),
        &val);
    if(val & MII_STAT_LINK_STATUS)
    {
        pdev->vars.link_status = LM_STATUS_LINK_ACTIVE;
        DbgMessage(pdev, INFORM, "phy init link up\n");

        pdev->vars.cable_is_attached = TRUE;
    }
    else
    {
        pdev->vars.link_status = LM_STATUS_LINK_DOWN;
        DbgMessage(pdev, INFORM, "phy init link down\n");
    }

    return LM_STATUS_SUCCESS;
} /* init_5708_serdes */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
force_5709_serdes_link(
    lm_device_t *pdev,
    lm_medium_t speed,
    lm_medium_t duplex)
{
    u32_t val;

    /* select serdes digital block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0x8300);

    /* disable sgmii/fiber mode autodetection. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x10, &val);
    val &= ~0x10;

    /* sgmii or 1000x_fiber mode. */
    val &= ~1;
    if(speed == LM_MEDIUM_SPEED_2500MBPS)
    {
        val |= 1;
    }

    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x10, val);

    /* select combo ieee0 block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0xffe0);

    /* phy control register. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x10, &val);

    val &= ~0x1000; /* autoneg. */
    val &= ~0x100;  /* duplex. */
    val &= ~0x2060; /* speed. */

    if(duplex == LM_MEDIUM_FULL_DUPLEX)
    {
        val |= 0x100;
    }

    if(speed == LM_MEDIUM_SPEED_10MBPS)
    {
        /* bit 13 and 6 are already cleared. */
        ;
    }
    else if(speed == LM_MEDIUM_SPEED_100MBPS)
    {
        val |= 0x2000;
    }
    else if(speed == LM_MEDIUM_SPEED_1000MBPS)
    {
        val |= 0x2040;
    }
    else if(speed == LM_MEDIUM_SPEED_2500MBPS)
    {
        val |= 0x20;
    }
    else
    {
        DbgBreakMsg("unknown forced speed.\n");
    }

    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x10, val);

    /* set speed. */
    if(speed == LM_MEDIUM_SPEED_2500MBPS)
    {
        /* select serdes digital block. */
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0x8300);

        /* set 2.5g speed. */
        (void) lm_mread(pdev, pdev->params.phy_addr, 0x18, &val);
        val &= 0xfff0;
        val |= 0x10;
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x18, val);
    }
} /* force_5709_serdes_link */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_5709_serdes_for_autoneg(
    lm_device_t *pdev,
    lm_medium_t req_medium,
    lm_flow_control_t flow_ctrl,
    u32_t selective_autoneg)
{
    u32_t val;

    if(GET_MEDIUM_SPEED(req_medium) == LM_MEDIUM_SPEED_UNKNOWN)
    {
        selective_autoneg = FALSE;
    }

    if(!(pdev->hw_info.nvm_hw_config & SHARED_HW_CFG_PHY_FIBER_2_5G) ||
        (selective_autoneg &&
            GET_MEDIUM_SPEED(req_medium) != LM_MEDIUM_SPEED_2500MBPS))
    {
        /* disable 2.5g adv */
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0x8320);
        (void) lm_mread(pdev, pdev->params.phy_addr, 0x19, &val);
	val &= ~1;
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x19, val);
    }

    /* select serdes digital block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0x8300);

    /* enable sgmii/fiber mode autodetection. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x10, &val);
    val |= 0x10;
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x10, val);

    /* disable parallel detection. */
    if(selective_autoneg)
    {
        (void) lm_mread(pdev, pdev->params.phy_addr, 0x11, &val);
        val &= ~0x1;
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x11, val);
    }

    /* select bam next page block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0x8350);

    /* mp5_next_page_control. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x10, &val);
    val &= ~3;
    val |= 1;   /* set bam mode. */
    val |= 2;   /* enable t2 mode. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x10, val);

    /* select cl73_userb0 block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0x8370);

    /* enable bam_en, bam_station_mngr_en, bam_np_after_bp_en. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x12, 0xe000);

    /* select ieee1 block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0x10);

    /* advertise 1000kx. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x1, &val);
    val |= 0x20;
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1, val);

    /* select ieee0 block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0);

    /* enable cl73 aneg. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x0, &val);
    val |= 0x1200;
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x0, val);

    /* select combo ieee0 block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0xffe0);

    /* advertise pause capability and duplex mode. */
    val = phy_ad_settings(pdev, req_medium, flow_ctrl);
    if(selective_autoneg &&
        GET_MEDIUM_SPEED(req_medium) == LM_MEDIUM_SPEED_2500MBPS)
    {
        val &= ~0x60;
    }
    else
    {
        val |= 0x60;    /* half/full duplex. */
    }
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x14, val);

    /* autoneg_enable and restart. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x10, &val);
    val |= 0x1200;
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x10, val);
} /* init_5709_serdes_for_autoneg */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
init_5709_serdes(
    lm_device_t *pdev,
    lm_medium_t req_medium,
    lm_flow_control_t flow_ctrl,
    u32_t selective_autoneg,
    u32_t wait_link_timeout_us)
{
    lm_medium_t duplex;
    lm_medium_t speed;
    u32_t idx;
    u32_t val;

    speed = GET_MEDIUM_SPEED(req_medium);
    duplex = GET_MEDIUM_DUPLEX(req_medium);

    /* use nvram link speed configuration. */
    if(speed == LM_MEDIUM_SPEED_HARDWARE_DEFAULT)
    {
        REG_RD_IND(
            pdev,
            pdev->hw_info.shmem_base +
                OFFSETOF(shmem_region_t, dev_info.port_hw_config.config),
            &val);

        switch(val & PORT_HW_CFG_DEFAULT_LINK_MASK)
        {
            case PORT_HW_CFG_DEFAULT_LINK_1G:
                speed = LM_MEDIUM_SPEED_1000MBPS;
                break;

            case PORT_HW_CFG_DEFAULT_LINK_2_5G:
                speed = LM_MEDIUM_SPEED_2500MBPS;
                break;

            default:
                speed = LM_MEDIUM_SPEED_UNKNOWN;
                break;
        }

        selective_autoneg = FALSE;
    }

    /* set an_mmd.  an_mmd is the only register set we need for
     * programming xinan serdes.  all other registers are can
     * be access through an_mmd. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0xffd0);
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1e, 0x3800);

    /* select combo_ieee0 block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0xffe0);

    /* reset. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x10, MII_CTRL_RESET);
    for(idx = 0; idx < 1000; idx++)
    {
        mm_wait(pdev, 5);

        (void) lm_mread(pdev, pdev->params.phy_addr, 0x10, &val);
        if(!(val & MII_CTRL_RESET))
        {
            mm_wait(pdev, 5);
            break;
        }
    }
    DbgBreakIf(val & MII_CTRL_RESET);

    /* get phy id. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x12, &val);
    pdev->hw_info.phy_id = val << 16;
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x13, &val);
    pdev->hw_info.phy_id |= val & 0xffff;

    if(speed == LM_MEDIUM_SPEED_AUTONEG_1G_FALLBACK)
    {
        speed = LM_MEDIUM_SPEED_AUTONEG;
    }

    /* config link speed or autoneg setting. */
    if(speed == LM_MEDIUM_SPEED_AUTONEG || selective_autoneg)
    {
        init_5709_serdes_for_autoneg(
            pdev,
            req_medium,
            flow_ctrl,
            selective_autoneg);
    }
    else
    {
        force_5709_serdes_link(pdev, speed, duplex);
    }

    /* exit mac loopback.  we could be in mac loopback mode if previously
     * the upper module calls lm_init_phy with LM_MEDIUM_TYPE_MAC_LOOPBACK
     * medium type for diagnostic. */
    REG_RD(pdev, emac.emac_mode, &val);
    val &= ~(EMAC_MODE_MAC_LOOP | EMAC_MODE_FORCE_LINK);
    REG_WR(pdev, emac.emac_mode, val);

    SET_MEDIUM_TYPE(pdev->vars.medium, LM_MEDIUM_TYPE_FIBER);
    SET_MEDIUM_SPEED(pdev->vars.medium, speed);
    SET_MEDIUM_DUPLEX(pdev->vars.medium, duplex);

    pdev->vars.cable_is_attached = FALSE;

    /* select combo_ieee0 block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0xffe0);

    /* wait for link. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x11, &val);

    for(; ;)
    {
        (void) lm_mread(pdev, pdev->params.phy_addr, 0x11, &val);
        if(val & 0x4)
        {
            break;
        }

        mm_wait(pdev, 10);

        if(wait_link_timeout_us <= 10)
        {
            break;
        }

        wait_link_timeout_us -= 10;
    }

    /* need to read a second time to get the current link status. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x11, &val);

    if(val & MII_STAT_LINK_STATUS)
    {
        pdev->vars.link_status = LM_STATUS_LINK_ACTIVE;
        pdev->vars.cable_is_attached = TRUE;
    }
    else
    {
        pdev->vars.link_status = LM_STATUS_LINK_DOWN;
    }

    return LM_STATUS_SUCCESS;
} /* init_5709_serdes */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
init_5706_serdes(
    lm_device_t *pdev,
    lm_medium_t req_medium,
    lm_flow_control_t flow_ctrl,
    u32_t wait_link_timeout_us)
{
    lm_medium_t duplex;
    lm_medium_t speed;
    u32_t val;
    u32_t cnt;

    speed = GET_MEDIUM_SPEED(req_medium);
    duplex = GET_MEDIUM_DUPLEX(req_medium);

    if(speed == LM_MEDIUM_SPEED_HARDWARE_DEFAULT)
    {
        REG_RD_IND(
            pdev,
            pdev->hw_info.shmem_base +
                OFFSETOF(shmem_region_t, dev_info.port_hw_config.config),
            &val);
        switch(val & PORT_HW_CFG_DEFAULT_LINK_MASK)
        {
            case PORT_HW_CFG_DEFAULT_LINK_1G:
                speed = LM_MEDIUM_SPEED_1000MBPS;
                break;

            case PORT_HW_CFG_DEFAULT_LINK_2_5G:
                speed = LM_MEDIUM_SPEED_2500MBPS;
                break;

            case PORT_HW_CFG_DEFAULT_LINK_AN_1G_FALLBACK:
                speed = LM_MEDIUM_SPEED_AUTONEG_1G_FALLBACK;
                break;

            case PORT_HW_CFG_DEFAULT_LINK_AN_2_5G_FALLBACK:
                speed = LM_MEDIUM_SPEED_AUTONEG_2_5G_FALLBACK;
                break;

            default:
                speed = LM_MEDIUM_SPEED_UNKNOWN;
        }
    }

    (void) lm_mwrite(pdev, pdev->params.phy_addr, PHY_CTRL_REG, PHY_CTRL_PHY_RESET);
    for(cnt = 0; cnt < 1000; cnt++)
    {
        mm_wait(pdev, 5);

        (void) lm_mread(pdev, pdev->params.phy_addr, PHY_CTRL_REG, &val);

        if(!(val & PHY_CTRL_PHY_RESET))
        {
            mm_wait(pdev, 5);

            break;
        }
    }

    DbgBreakIf(val & PHY_CTRL_PHY_RESET);

    /* Get the PHY id. */
    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_ID1_REG, &val);
    pdev->hw_info.phy_id = val << 16;
    DbgMessage1(pdev, INFORM, "Phy Id1 0x%x\n", val);

    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_ID2_REG, &val);
    pdev->hw_info.phy_id |= val & 0xffff;
    DbgMessage1(pdev, INFORM, "Phy Id2 0x%x\n", val);

    DbgBreakIf((pdev->hw_info.phy_id & 0x0fffffff) == 0x0fffffff ||
        pdev->hw_info.phy_id == 0);

    /* The 5706S has problem determining link so getting link from
     * the MII status register is not reliable.  This will force
     * the MAC to qualify the link ready signal with signal detect.
     * We will need to get the link status from the MAC instead of
     * the SERDES (MII status register). */
    if(CHIP_NUM(pdev) == CHIP_NUM_5706 &&
        lm_get_medium(pdev) == LM_MEDIUM_TYPE_FIBER)
    {
        REG_WR(pdev, misc.misc_gp_hw_ctl0,
                MISC_GP_HW_CTL0_ENA_SEL_VAUX_B_IN_L2_TE |
                MISC_GP_HW_CTL0_GRC_BNK_FREE_FIX_TE);
    }

    /* Setup flow control capabilities advertisement. */
    val = PHY_AN_AD_1000X_HALF_DUPLEX;
    if(duplex == LM_MEDIUM_FULL_DUPLEX)
    {
        val |= PHY_AN_AD_1000X_FULL_DUPLEX;
    }
    val |= phy_ad_settings(pdev, req_medium, flow_ctrl);

    (void) lm_mwrite(pdev, pdev->params.phy_addr, PHY_AN_AD_REG, val);

    /* Determine the fallback selection. */
    switch(speed)
    {
        case LM_MEDIUM_SPEED_AUTONEG_1G_FALLBACK:
            DbgMessage(pdev, INFORM, "enable serdes_fallback_1g\n");
            pdev->vars.serdes_fallback_select = SERDES_FALLBACK_1G;
            break;

        case LM_MEDIUM_SPEED_AUTONEG_2_5G_FALLBACK:
            DbgMessage(pdev, INFORM, "enable serdes_fallback_2.5g\n");
            pdev->vars.serdes_fallback_select = SERDES_FALLBACK_2_5G;
            break;

        default:
            DbgMessage(pdev, INFORM, "disable serdes_fallback.\n");
            pdev->vars.serdes_fallback_select = SERDES_FALLBACK_NONE;
            pdev->vars.serdes_fallback_status = SERDES_FALLBACK_NONE;
            break;
    }

    /* This routine could be called anytime.  So if has not gone down
     * yet, we want to perserve the fallback setting. */
    if(pdev->vars.serdes_fallback_select != SERDES_FALLBACK_NONE)
    {
        speed = LM_MEDIUM_SPEED_AUTONEG;

        if(pdev->vars.link_status == LM_STATUS_LINK_ACTIVE)
        {
            if(pdev->vars.serdes_fallback_status == SERDES_FALLBACK_1G)
            {
                speed = LM_MEDIUM_SPEED_1000MBPS;
            }
            else if(pdev->vars.serdes_fallback_status == SERDES_FALLBACK_2_5G)
            {
                speed = LM_MEDIUM_SPEED_2500MBPS;
            }
        }
    }

    if(speed == LM_MEDIUM_SPEED_1000MBPS)
    {
        val = PHY_CTRL_SPEED_SELECT_1000MBPS;
        if(duplex == LM_MEDIUM_FULL_DUPLEX)
        {
            val |= PHY_CTRL_FULL_DUPLEX_MODE;
        }

        (void) lm_mwrite(pdev, pdev->params.phy_addr, PHY_CTRL_REG, val);
    }
    else
    {
        val = PHY_CTRL_AUTO_NEG_ENABLE | PHY_CTRL_RESTART_AUTO_NEG;

        (void) lm_mwrite(pdev, pdev->params.phy_addr, PHY_CTRL_REG, val);

        speed = LM_MEDIUM_SPEED_AUTONEG;
    }

    /* exit mac loopback.  we could be in mac loopback mode if previously
     * the upper module calls lm_init_phy with LM_MEDIUM_TYPE_MAC_LOOPBACK
     * medium type for diagnostic. */
    REG_RD(pdev, emac.emac_mode, &val);
    val &= ~(EMAC_MODE_MAC_LOOP | EMAC_MODE_FORCE_LINK);
    REG_WR(pdev, emac.emac_mode, val);

    /* Configure the PHY for jumbo frame. */
    if(pdev->params.mtu > MAX_ETHERNET_PACKET_SIZE)
    {
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x18, 0x4400);
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1c, 0xec87);
    }
    else
    {
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x18, 0x0400);
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1c, 0xec85);
    }

    SET_MEDIUM_TYPE(pdev->vars.medium, LM_MEDIUM_TYPE_FIBER);
    SET_MEDIUM_SPEED(pdev->vars.medium, speed);
    SET_MEDIUM_DUPLEX(pdev->vars.medium, duplex);

    pdev->vars.cable_is_attached = FALSE;

    /* Clear the latch bits.  The second read below will get the
     * current status. */
    val = mii_get_serdes_link_status(pdev);

    /* Wait for link only if the cable is connected. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1c, 0x7c00);
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x1c, &val);
    if(val & 0x10)
    {
        for(; ;)
        {
            val = mii_get_serdes_link_status(pdev);

            if(val & PHY_STATUS_LINK_PASS)
            {
                break;
            }

            mm_wait(pdev, 10);

            if(wait_link_timeout_us <= 10)
            {
                break;
            }

            wait_link_timeout_us -= 10;
        }

        pdev->vars.cable_is_attached = TRUE;
    }

    /* Need to read a second time to get the current link status. */
    val = mii_get_serdes_link_status(pdev);

    if(val & PHY_STATUS_LINK_PASS)
    {
        pdev->vars.link_status = LM_STATUS_LINK_ACTIVE;
        DbgMessage(pdev, INFORM, "phy init link up\n");
    }
    else
    {
        pdev->vars.link_status = LM_STATUS_LINK_DOWN;
        DbgMessage(pdev, INFORM, "phy init link down\n");
    }

    return LM_STATUS_SUCCESS;
} /* init_5706_serdes */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_serdes_or_phy_loopback(
    lm_device_t *pdev)
{
    u32_t cnt;
    u32_t val;

    (void) lm_mwrite(
        pdev,
        pdev->params.phy_addr,
        PHY_CTRL_REG,
        PHY_CTRL_PHY_RESET);
    for(cnt = 0; cnt < 1000; cnt++)
    {
        mm_wait(pdev, 5);

        (void) lm_mread(pdev, pdev->params.phy_addr, PHY_CTRL_REG, &val);

        if(!(val & PHY_CTRL_PHY_RESET))
        {
            mm_wait(pdev, 5);
            break;
        }
    }

    DbgBreakIf(val & PHY_CTRL_PHY_RESET);

    /* Get the PHY id. */
    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_ID1_REG, &val);
    pdev->hw_info.phy_id = val << 16;
    DbgMessage1(pdev, INFORM, "Phy Id1 0x%x\n", val);

    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_ID2_REG, &val);
    pdev->hw_info.phy_id |= val & 0xffff;
    DbgMessage1(pdev, INFORM, "Phy Id2 0x%x\n", val);

    DbgBreakIf((pdev->hw_info.phy_id & 0x0fffffff) == 0x0fffffff ||
        pdev->hw_info.phy_id == 0);

    REG_WR(pdev, emac.emac_tx_lengths, 0x26ff);

    /* Set the phy into loopback mode. */
    (void) lm_mwrite(
        pdev,
        pdev->params.phy_addr,
        PHY_CTRL_REG,
        PHY_CTRL_LOOPBACK_MODE |
            PHY_CTRL_FULL_DUPLEX_MODE |
            PHY_CTRL_SPEED_SELECT_1000MBPS);
} /* init_serdes_or_phy_loopback */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_5709_serdes_loopback(
    lm_device_t *pdev)
{
    u32_t val;

    /*
     * reset causes the speed not be back to 2.5g intermittently
     * after phy lookback test when connecting to a switch.
     */
#if 0
    /* select combo_ieee0 block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0xffe0);

    /* reset. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x10, MII_CTRL_RESET);
    for(idx = 0; idx < 1000; idx++)
    {
        mm_wait(pdev, 5);

        (void) lm_mread(pdev, pdev->params.phy_addr, 0x10, &val);
        if(!(val & MII_CTRL_RESET))
        {
            mm_wait(pdev, 5);
            break;
        }
    }
    DbgBreakIf(val & MII_CTRL_RESET);
#endif

    /* set an_mmd.  an_mmd is the only register set we need for
     * programming xinan serdes.  all other registers are can
     * be access through an_mmd. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0xffd0);
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1e, 0x3800);

    /* get phy id. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x12, &val);
    pdev->hw_info.phy_id = val << 16;
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x13, &val);
    pdev->hw_info.phy_id |= val & 0xffff;

    /* select combo_ieee0 block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0xffe0);

    /*CQ31687:set autoneg_enable bit too.*/
    /* Set the phy into loopback mode. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x10, 0x5140);

} /* init_5709_serdes_loopback */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
init_loopback_mac_link(
    lm_device_t *pdev,
    lm_medium_t req_medium,
    lm_flow_control_t flow_ctrl)
{
    lm_status_t lm_status;
    u32_t val;

    lm_status = LM_STATUS_SUCCESS;

    if(GET_MEDIUM_TYPE(req_medium) == LM_MEDIUM_TYPE_PHY_LOOPBACK)
    {
        if(CHIP_NUM(pdev) == CHIP_NUM_5709 &&
            lm_get_medium(pdev) == LM_MEDIUM_TYPE_FIBER)
        {
            init_5709_serdes_loopback(pdev);
        }
        else
        {
            init_serdes_or_phy_loopback(pdev);
        }

        REG_WR(pdev, emac.emac_tx_lengths, 0x26ff);

        REG_RD(pdev, emac.emac_mode, &val);
        val &= ~(EMAC_MODE_MAC_LOOP | EMAC_MODE_PORT);
        val |= EMAC_MODE_FORCE_LINK | EMAC_MODE_PORT_GMII;
        REG_WR(pdev, emac.emac_mode, val);

        SET_MEDIUM_TYPE(pdev->vars.medium, LM_MEDIUM_TYPE_PHY_LOOPBACK);
        SET_MEDIUM_SPEED(pdev->vars.medium, LM_MEDIUM_SPEED_UNKNOWN);
        SET_MEDIUM_DUPLEX(pdev->vars.medium, LM_MEDIUM_FULL_DUPLEX);

        /* Save current link status. */
        pdev->vars.link_status = LM_STATUS_LINK_ACTIVE;

        pdev->vars.cable_is_attached = TRUE;
    }
    else if(GET_MEDIUM_TYPE(req_medium) == LM_MEDIUM_TYPE_MAC_LOOPBACK)
    {
        DbgMessage(pdev, INFORM, "Set up MAC loopback mode.\n");

        /* Set the MAC into loopback mode.  Mac loopback will intermittenly
         * fail if half_duplex bit is set.  CQ#24594. */
        REG_RD(pdev, emac.emac_mode, &val);
        val &= ~(EMAC_MODE_PORT | EMAC_MODE_HALF_DUPLEX);
        val |= EMAC_MODE_MAC_LOOP | EMAC_MODE_FORCE_LINK;

        /* The port mode must be set to none on the real chip. */
        if(CHIP_REV(pdev) == CHIP_REV_FPGA)
        {
            val |= EMAC_MODE_PORT_GMII;
        }

        REG_WR(pdev, emac.emac_mode, val);

        SET_MEDIUM_TYPE(pdev->vars.medium, LM_MEDIUM_TYPE_MAC_LOOPBACK);
        SET_MEDIUM_SPEED(pdev->vars.medium, LM_MEDIUM_SPEED_UNKNOWN);
        SET_MEDIUM_DUPLEX(pdev->vars.medium, LM_MEDIUM_FULL_DUPLEX);

        /* Save current link status. */
        pdev->vars.link_status = LM_STATUS_LINK_ACTIVE;

        pdev->vars.cable_is_attached = TRUE;
    }
    else
    {
        DbgBreakMsg("Not loopback medium type.\n");

        lm_status = LM_STATUS_FAILURE;

        /* Save current link status. */
        pdev->vars.link_status = LM_STATUS_LINK_DOWN;

        pdev->vars.cable_is_attached = FALSE;
    }

    /* Enable status block link attention. */
    REG_RD(pdev, hc.hc_attn_bits_enable, &val);
    val |= STATUS_ATTN_BITS_LINK_STATE;
    REG_WR(pdev, hc.hc_attn_bits_enable, val);

    return lm_status;
} /* init_loopback_mac_link */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
init_null_phy(
    lm_device_t *pdev,
    lm_medium_t req_medium,
    lm_flow_control_t flow_ctrl,
    u32_t wait_link_timeout_us)
{
    DbgMessage(pdev, INFORM, "### init_null_phy\n");

    if(GET_MEDIUM_TYPE(req_medium) != LM_MEDIUM_TYPE_NULL)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    /* Save current medium settings. */
    SET_MEDIUM_TYPE(pdev->vars.medium, LM_MEDIUM_TYPE_NULL);
    SET_MEDIUM_SPEED(pdev->vars.medium, LM_MEDIUM_SPEED_1000MBPS);
    SET_MEDIUM_DUPLEX(pdev->vars.medium, LM_MEDIUM_FULL_DUPLEX);

    pdev->vars.cable_is_attached = TRUE;

    return LM_STATUS_SUCCESS;
} /* init_null_phy */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
netlink_pause_ad(
    lm_flow_control_t flow_ctrl)
{
    u32_t pause_ad;

    pause_ad = 0;

    if((flow_ctrl == LM_FLOW_CONTROL_AUTO_PAUSE) ||
        ((flow_ctrl & LM_FLOW_CONTROL_RECEIVE_PAUSE) &&
        (flow_ctrl & LM_FLOW_CONTROL_TRANSMIT_PAUSE)))
    {
        pause_ad |= NETLINK_DRV_SET_LINK_FC_SYM_PAUSE |
                    NETLINK_DRV_SET_LINK_FC_ASYM_PAUSE;
    }
    else if(flow_ctrl & LM_FLOW_CONTROL_TRANSMIT_PAUSE)
    {
        pause_ad |= NETLINK_DRV_SET_LINK_FC_ASYM_PAUSE;
    }
    else if(flow_ctrl & LM_FLOW_CONTROL_RECEIVE_PAUSE)
    {
        pause_ad |= NETLINK_DRV_SET_LINK_FC_SYM_PAUSE |
                    NETLINK_DRV_SET_LINK_FC_ASYM_PAUSE;
    }

    return pause_ad;
} /* netlink_pause_ad */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
link_setting_to_netlink(
    lm_link_settings_t *link_settings,
    u32_t serdes)
{
    lm_medium_t duplex;
    lm_medium_t speed;
    u32_t netlink;

    speed = GET_MEDIUM_SPEED(link_settings->req_medium);
    duplex = GET_MEDIUM_DUPLEX(link_settings->req_medium);
    netlink = 0;

    switch(speed)
    {
        case LM_MEDIUM_SPEED_10MBPS:
            if(duplex == LM_MEDIUM_FULL_DUPLEX)
            {
                netlink |= NETLINK_DRV_SET_LINK_SPEED_10FULL;

                if((link_settings->flag & LINK_FLAG_SELECTIVE_AUTONEG_MASK) ==
                    LINK_FLAG_SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS)
                {
                    netlink |= NETLINK_DRV_SET_LINK_SPEED_10HALF;
                }
            }
            else
            {
                netlink |= NETLINK_DRV_SET_LINK_SPEED_10HALF;
            }
            break;

        case LM_MEDIUM_SPEED_100MBPS:
            if((link_settings->flag & LINK_FLAG_SELECTIVE_AUTONEG_MASK) ==
                LINK_FLAG_SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS)
            {
                netlink |= NETLINK_DRV_SET_LINK_SPEED_10FULL;
                netlink |= NETLINK_DRV_SET_LINK_SPEED_10HALF;
            }

            if(duplex == LM_MEDIUM_FULL_DUPLEX)
            {
                netlink |= NETLINK_DRV_SET_LINK_SPEED_100FULL;

                if((link_settings->flag & LINK_FLAG_SELECTIVE_AUTONEG_MASK) ==
                    LINK_FLAG_SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS)
                {
                    netlink |= NETLINK_DRV_SET_LINK_SPEED_100HALF;
                }
            }
            else
            {
                netlink |= NETLINK_DRV_SET_LINK_SPEED_100HALF;
            }
            break;

        case LM_MEDIUM_SPEED_1000MBPS:
            if((link_settings->flag & LINK_FLAG_SELECTIVE_AUTONEG_MASK) ==
                LINK_FLAG_SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS)
            {
                netlink |= NETLINK_DRV_SET_LINK_SPEED_10FULL;
                netlink |= NETLINK_DRV_SET_LINK_SPEED_10HALF;
                netlink |= NETLINK_DRV_SET_LINK_SPEED_100FULL;
                netlink |= NETLINK_DRV_SET_LINK_SPEED_100HALF;
            }

            if(duplex == LM_MEDIUM_FULL_DUPLEX)
            {
                netlink |= NETLINK_DRV_SET_LINK_SPEED_1GFULL;

                if((link_settings->flag & LINK_FLAG_SELECTIVE_AUTONEG_MASK) ==
                    LINK_FLAG_SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS)
                {
                    netlink |= NETLINK_DRV_SET_LINK_SPEED_1GHALF;
                }
            }
            else
            {
                netlink |= NETLINK_DRV_SET_LINK_SPEED_1GHALF;
            }
            break;

        default:
            if (serdes)
            {
                netlink |= NETLINK_DRV_SET_LINK_ENABLE_AUTONEG |
                    NETLINK_DRV_SET_LINK_SPEED_1GHALF |
                    NETLINK_DRV_SET_LINK_SPEED_1GFULL;
            }
            else
            {
                netlink |= NETLINK_DRV_SET_LINK_ENABLE_AUTONEG |
                    NETLINK_DRV_SET_LINK_SPEED_10HALF |
                    NETLINK_DRV_SET_LINK_SPEED_10FULL |
                    NETLINK_DRV_SET_LINK_SPEED_100HALF |
                    NETLINK_DRV_SET_LINK_SPEED_100FULL |
                    NETLINK_DRV_SET_LINK_SPEED_1GHALF |
                    NETLINK_DRV_SET_LINK_SPEED_1GFULL;
            }
            break;
    }

    netlink |= NETLINK_DRV_SET_LINK_PHY_RESET;

    if(link_settings->flag & LINK_FLAG_SELECTIVE_AUTONEG_MASK)
    {
        netlink |= NETLINK_DRV_SET_LINK_ENABLE_AUTONEG;
    }

    if(link_settings->flag & LINK_FLAG_WIRE_SPEED)
    {
        netlink |= NETLINK_DRV_SET_LINK_ETH_AT_WIRESPEED_ENABLE;
    }

    netlink |= netlink_pause_ad(link_settings->flow_ctrl);

    return netlink;
} /* link_settings_to_netlink */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_init_remote_phy(
    lm_device_t *pdev,
    lm_link_settings_t *serdes_link,
    lm_link_settings_t *rphy_link)
{
    u32_t serdes_netlink;
    u32_t rphy_netlink;
    u32_t set_link_arg;
    u32_t val;

    DbgBreakIf(pdev->params.enable_remote_phy == FALSE);

    serdes_netlink = link_setting_to_netlink(serdes_link, TRUE);
    rphy_netlink = link_setting_to_netlink(rphy_link, FALSE);

    REG_WR_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, remotephy.serdes_link_pref),
        serdes_netlink);

    REG_WR_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, remotephy.copper_phy_link_pref),
        rphy_netlink | NETLINK_DRV_SET_LINK_PHY_APP_REMOTE);

    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, drv_fw_mb.link_status),
        &val);
    if(val & NETLINK_GET_LINK_STATUS_SERDES_LINK)
    {
        set_link_arg = serdes_netlink;
    }
    else
    {
        set_link_arg = rphy_netlink | NETLINK_DRV_SET_LINK_PHY_APP_REMOTE;
    }

    REG_WR_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, drv_fw_mb.mb_args[0]),
        set_link_arg);

    (void) lm_submit_fw_cmd(pdev, DRV_MSG_CODE_CMD_SET_LINK);

    return LM_STATUS_SUCCESS;
} /* lm_init_remote_phy */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_init_phy(
    lm_device_t *pdev,
    lm_medium_t req_medium,
    lm_flow_control_t flow_ctrl,
    u32_t selective_autoneg,
    u32_t wire_speed,
    u32_t wait_link_timeout_us)
{
    lm_status_t lm_status;

    DbgBreakIf(pdev->params.enable_remote_phy);

    if(GET_MEDIUM_AUTONEG_MODE(req_medium) == LM_MEDIUM_SELECTIVE_AUTONEG)
    {
        selective_autoneg = TRUE;
    }

    if(GET_MEDIUM_TYPE(req_medium) == LM_MEDIUM_AUTO_DETECT)
    {
        if(CHIP_REV(pdev) == CHIP_REV_IKOS)
        {
            req_medium = LM_MEDIUM_TYPE_NULL;
        }
        else if(CHIP_REV(pdev) == CHIP_REV_FPGA)
        {
            selective_autoneg = TRUE;
            req_medium = LM_MEDIUM_TYPE_UTP |
                LM_MEDIUM_SPEED_10MBPS |
                LM_MEDIUM_FULL_DUPLEX;
        }
        else if(lm_get_medium(pdev) == LM_MEDIUM_TYPE_FIBER)
        {
            if(req_medium == LM_MEDIUM_AUTO_DETECT)
            {
                req_medium = LM_MEDIUM_TYPE_FIBER;
            }
            else
            {
                SET_MEDIUM_TYPE(req_medium, LM_MEDIUM_TYPE_FIBER);
            }
        }
        else
        {
            if(req_medium == LM_MEDIUM_AUTO_DETECT)
            {
                req_medium = LM_MEDIUM_TYPE_UTP;
            }
            else
            {
                SET_MEDIUM_TYPE(req_medium, LM_MEDIUM_TYPE_UTP);
            }
        }
    }

    switch(GET_MEDIUM_TYPE(req_medium))
    {
        case LM_MEDIUM_TYPE_UTP:
            lm_status = init_utp(
                pdev,
                req_medium,
                flow_ctrl,
                selective_autoneg,
                wire_speed,
                wait_link_timeout_us);
            break;

        case LM_MEDIUM_TYPE_FIBER:
            DbgBreakIf(CHIP_NUM(pdev) != CHIP_NUM_5706 &&
                       CHIP_NUM(pdev) != CHIP_NUM_5708 &&
                       CHIP_NUM(pdev) != CHIP_NUM_5709);

            if(CHIP_NUM(pdev) == CHIP_NUM_5706)
            {
                lm_status = init_5706_serdes(
                    pdev,
                    req_medium,
                    flow_ctrl,
                    wait_link_timeout_us);
            }
            else if(CHIP_NUM(pdev) == CHIP_NUM_5708)
            {
                lm_status = init_5708_serdes(
                    pdev,
                    req_medium,
                    flow_ctrl,
                    selective_autoneg,
                    wait_link_timeout_us);
            }
            else
            {
                lm_status = init_5709_serdes(
                    pdev,
                    req_medium,
                    flow_ctrl,
                    selective_autoneg,
                    wait_link_timeout_us);
            }

            break;

        case LM_MEDIUM_TYPE_NULL:
            lm_status = init_null_phy(
                pdev,
                req_medium,
                flow_ctrl,
                wait_link_timeout_us);
            break;

        case LM_MEDIUM_TYPE_PHY_LOOPBACK:
        case LM_MEDIUM_TYPE_MAC_LOOPBACK:
            lm_status = init_loopback_mac_link(
                pdev,
                req_medium,
                flow_ctrl);
            break;

        default:
            lm_status = LM_STATUS_UNKNOWN_MEDIUM;
            break;
    }

    return lm_status;
} /* lm_init_phy */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
get_serdes_phy_ad(
    lm_device_t *pdev,
    u32_t *local_phy_ad,
    u32_t *remote_phy_ad)
{
    u32_t val;

    *local_phy_ad = 0;
    *remote_phy_ad = 0;

    if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        (void) lm_mread(pdev, pdev->params.phy_addr, PHY_AN_AD_REG, &val);

        if(val & PHY_AN_AD_1000X_PAUSE_CAPABLE)
        {
            *local_phy_ad |= PHY_AN_AD_PAUSE_CAPABLE;
        }

        if(val & PHY_AN_AD_1000X_ASYM_PAUSE)
        {
            *local_phy_ad |= PHY_AN_AD_ASYM_PAUSE;
        }

        (void) lm_mread(pdev,pdev->params.phy_addr,PHY_LINK_PARTNER_ABILITY_REG,&val);

        if(val & PHY_AN_AD_1000X_PAUSE_CAPABLE)
        {
            *remote_phy_ad |= PHY_AN_AD_PAUSE_CAPABLE;
        }

        if(val & PHY_AN_AD_1000X_ASYM_PAUSE)
        {
            *remote_phy_ad |= PHY_AN_AD_ASYM_PAUSE;
        }
    }
    else
    {
        /* select combo ieee0 block. */
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0xffe0);

        /* local advertisement. */
        (void) lm_mread(pdev, pdev->params.phy_addr, 0x14, &val);

        if(val & 0x80)
        {
            *local_phy_ad |= PHY_AN_AD_PAUSE_CAPABLE;
        }

        if(val & 0x100)
        {
            *local_phy_ad |= PHY_AN_AD_ASYM_PAUSE;
        }

        /* remote advertisement. */
        (void) lm_mread(pdev, pdev->params.phy_addr, 0x15, &val);

        if(val & 0x80)
        {
            *remote_phy_ad |= PHY_AN_AD_PAUSE_CAPABLE;
        }

        if(val & 0x100)
        {
            *remote_phy_ad |= PHY_AN_AD_ASYM_PAUSE;
        }
    }
} /* get_serdes_phy_ad */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_flow_control_t
set_mac_flow_control(
    lm_device_t *pdev,
    lm_medium_t medium,
    lm_flow_control_t flow_control_cap)
{
    lm_flow_control_t flow_ctrl;
    u32_t remote_phy_link;
    u32_t remote_phy_ad;
    u32_t local_phy_ad;
    u32_t val;
    lm_rx_chain_t *rxq;
    u32_t idx;

    if(pdev->params.enable_remote_phy)
    {
        local_phy_ad = 0;

        if((flow_control_cap == LM_FLOW_CONTROL_AUTO_PAUSE) ||
            ((flow_control_cap & LM_FLOW_CONTROL_RECEIVE_PAUSE) &&
            (flow_control_cap & LM_FLOW_CONTROL_TRANSMIT_PAUSE)) ||
            (flow_control_cap & LM_FLOW_CONTROL_RECEIVE_PAUSE))
        {
            local_phy_ad |= (PHY_AN_AD_PAUSE_CAPABLE | PHY_AN_AD_ASYM_PAUSE);
        }
        else if(flow_control_cap & LM_FLOW_CONTROL_TRANSMIT_PAUSE)
        {
            local_phy_ad |= PHY_AN_AD_ASYM_PAUSE;
        }

        remote_phy_ad = 0;

        REG_RD_IND(
            pdev,
            pdev->hw_info.shmem_base +
                OFFSETOF(shmem_region_t, drv_fw_mb.link_status),
            &remote_phy_link);

        if(remote_phy_link & NETLINK_GET_LINK_STATUS_PARTNER_SYM_PAUSE_CAP)
        {
            remote_phy_ad |= PHY_LINK_PARTNER_PAUSE_CAPABLE;
        }

        if(remote_phy_link & NETLINK_GET_LINK_STATUS_PARTNER_ASYM_PAUSE_CAP)
        {
            remote_phy_ad |= PHY_LINK_PARTNER_ASYM_PAUSE;
        }
    }
    else
    {
        if(GET_MEDIUM_TYPE(medium) == LM_MEDIUM_TYPE_FIBER)
        {
            get_serdes_phy_ad(pdev, &local_phy_ad, &remote_phy_ad);
        }
        else
        {
            (void) lm_mread(
                pdev,
                pdev->params.phy_addr,
                PHY_AN_AD_REG,
                &local_phy_ad);

            (void) lm_mread(
                pdev,
                pdev->params.phy_addr,
                PHY_LINK_PARTNER_ABILITY_REG,
                &remote_phy_ad);
        }
    }

    DbgMessage(pdev, INFORM, "Local flow control settings.\n");

    if(local_phy_ad & PHY_AN_AD_PAUSE_CAPABLE)
    {
        DbgMessage(pdev, INFORM, "   PAUSE capable.\n");
    }

    if(local_phy_ad & PHY_AN_AD_ASYM_PAUSE)
    {
        DbgMessage(pdev, INFORM, "   ASYM_PAUSE capable.\n");
    }

    DbgMessage(pdev, INFORM, "Remote flow control settings.\n");

    if(remote_phy_ad & PHY_LINK_PARTNER_PAUSE_CAPABLE)
    {
        DbgMessage(pdev, INFORM, "   PAUSE capable.\n");
    }

    if(remote_phy_ad & PHY_LINK_PARTNER_ASYM_PAUSE)
    {
        DbgMessage(pdev, INFORM, "   ASYM_PAUSE capable.\n");
    }

    /* Resultant flow control setting. */
    flow_ctrl = LM_FLOW_CONTROL_NONE;

    if((flow_control_cap & LM_FLOW_CONTROL_AUTO_PAUSE) ||
        pdev->params.flow_control_reporting_mode)
    {
        /* See Table 28B-3 of 802.3ab-1999 spec. */
        if(local_phy_ad & PHY_AN_AD_PAUSE_CAPABLE)
        {
            if(local_phy_ad & PHY_AN_AD_ASYM_PAUSE)
            {
                if(remote_phy_ad & PHY_LINK_PARTNER_PAUSE_CAPABLE)
                {
                    DbgMessage(pdev, INFORM, "FlowCap: tx/rx\n");

                    flow_ctrl =
                        LM_FLOW_CONTROL_TRANSMIT_PAUSE |
                        LM_FLOW_CONTROL_RECEIVE_PAUSE;
                }
                else if(remote_phy_ad & PHY_LINK_PARTNER_ASYM_PAUSE)
                {
                    DbgMessage(pdev, INFORM, "FlowCap: rx PAUSE\n");

                    flow_ctrl = LM_FLOW_CONTROL_RECEIVE_PAUSE;
                }
            }
            else
            {
                if(remote_phy_ad & PHY_LINK_PARTNER_PAUSE_CAPABLE)
                {
                    DbgMessage(pdev, INFORM, "FlowCap: tx/rx\n");

                    flow_ctrl =
                        LM_FLOW_CONTROL_TRANSMIT_PAUSE |
                        LM_FLOW_CONTROL_RECEIVE_PAUSE;
                }
            }
        }
        else if(local_phy_ad & PHY_AN_AD_ASYM_PAUSE)
        {
            if((remote_phy_ad & PHY_LINK_PARTNER_PAUSE_CAPABLE) &&
                (remote_phy_ad & PHY_LINK_PARTNER_ASYM_PAUSE))
            {
                DbgMessage(pdev, INFORM, "FlowCap: tx PAUSE\n");

                flow_ctrl = LM_FLOW_CONTROL_TRANSMIT_PAUSE;
            }
        }
    }
    else
    {
        flow_ctrl = flow_control_cap;
    }

    DbgMessage(pdev, INFORM, "Flow control capabilities.\n");

    if(flow_ctrl & LM_FLOW_CONTROL_TRANSMIT_PAUSE)
    {
        DbgMessage(pdev, INFORM, "   tx PAUSE\n");
    }

    if(flow_ctrl & LM_FLOW_CONTROL_RECEIVE_PAUSE)
    {
        DbgMessage(pdev, INFORM, "   rx PAUSE\n");
    }

    if(flow_ctrl == LM_FLOW_CONTROL_NONE)
    {
        DbgMessage(pdev, INFORM, "   none.\n");
    }

    /* Enable/disable rx PAUSE. */
    REG_RD(pdev, emac.emac_rx_mode, &val);
    val &= ~EMAC_RX_MODE_FLOW_EN;

    if(flow_ctrl & LM_FLOW_CONTROL_RECEIVE_PAUSE)
    {
        val |= EMAC_RX_MODE_FLOW_EN;
        DbgMessage(pdev, INFORM, "Enable rx PAUSE.\n");
    }
    REG_WR(pdev, emac.emac_rx_mode, val);

    /* Enable/disable tx PAUSE. */
    REG_RD(pdev, emac.emac_tx_mode, &val);
    val &= ~EMAC_TX_MODE_FLOW_EN;

    if(flow_ctrl & LM_FLOW_CONTROL_TRANSMIT_PAUSE)
    {
        val |= EMAC_TX_MODE_FLOW_EN;
        DbgMessage(pdev, INFORM, "Enable tx PAUSE.\n");
    }
    REG_WR(pdev, emac.emac_tx_mode, val);

    for(idx = 0; idx < pdev->rx_info.num_rxq; idx++)
    {
        rxq = &pdev->rx_info.chain[idx];
        val = CTX_RD(
            pdev,
            rxq->cid_addr,
            WORD_ALIGNED_OFFSETOF(l2_bd_chain_context_t, l2ctx_ctx_type));

        /* Enable/disable RV2P wait (i.e. watermark field) for buffer post based on flow control setting. */
        if(flow_ctrl & LM_FLOW_CONTROL_TRANSMIT_PAUSE)
        {
            val |= 0xFF;
        }
        else
        {
            // RV2P is checking for non-zero in this byte field
            val &= ~0xFF;
        }
        CTX_WR(
            pdev,
            rxq->cid_addr,
            WORD_ALIGNED_OFFSETOF(l2_bd_chain_context_t, l2ctx_ctx_type),
            val);
    }

    return flow_ctrl;
} /* set_mac_flow_control */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
get_copper_phy_link(
    lm_device_t *pdev,
    lm_medium_t *medium)
{
    lm_medium_t duplex;
    lm_medium_t speed;
    lm_status_t link;
    u32_t phy_status;
    u32_t remote_adv;
    u32_t local_adv;
    u32_t phy_ctrl;
    u32_t val;

    DbgMessage(pdev, INFORM, "### get_copper_phy_link\n");

    *medium = LM_MEDIUM_TYPE_UTP |
        LM_MEDIUM_SPEED_UNKNOWN |
        LM_MEDIUM_FULL_DUPLEX;

    pdev->vars.cable_is_attached = FALSE;

    /* Check for link.  The first read returns the latched value, the
     * second read returns the current value. */
    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_STATUS_REG, &phy_status);
    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_STATUS_REG, &phy_status);
    if((phy_status & PHY_STATUS_LINK_PASS) == 0)
    {
        DbgMessage(pdev, INFORM, "link down.\n");

        if(CHIP_REV(pdev) != CHIP_REV_FPGA)
        {
            (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1c, 0x7c00);
            (void) lm_mread(pdev, pdev->params.phy_addr, 0x1c, &val);
            if(val & 0x20)
            {
                pdev->vars.cable_is_attached = TRUE;
            }
        }

        return LM_STATUS_LINK_DOWN;
    }

    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_CTRL_REG, &phy_ctrl);

    /* Make sure the PHY control register is valid. */
    DbgBreakIf(phy_ctrl & (
        PHY_CTRL_COLLISION_TEST_ENABLE |
        PHY_CTRL_RESTART_AUTO_NEG |
        PHY_CTRL_ISOLATE_PHY |
        PHY_CTRL_LOOPBACK_MODE |
        PHY_CTRL_PHY_RESET));

    link = LM_STATUS_LINK_ACTIVE;
    pdev->vars.cable_is_attached = TRUE;

    /* Determine duplex mode.  Link is present also means autoneg is done. */
    if(phy_ctrl & PHY_CTRL_AUTO_NEG_ENABLE)
    {
        /* Autonegotiation is enabled.  And since we have link, we know
         * autonegotiation has completed.
         *
         * Infer the link speed by figuring out the highest common speed
         * between us and our link partner. */

        /* Get local and remote 1000BASET advertisement. */
        (void) lm_mread(
                pdev,
                pdev->params.phy_addr,
                PHY_1000BASET_CTRL_REG,
                &local_adv);
        (void) lm_mread(
                pdev,
                pdev->params.phy_addr,
                PHY_1000BASET_STATUS_REG,
                &remote_adv);

        val = local_adv & (remote_adv >> 2);
        if(val & PHY_AN_AD_1000BASET_FULL)
        {
            DbgMessage(pdev, INFORM, "detected 1gb full autoneg.\n");

            speed = LM_MEDIUM_SPEED_1000MBPS;
            duplex = LM_MEDIUM_FULL_DUPLEX;
        }
        else if(val & PHY_AN_AD_1000BASET_HALF)
        {
            DbgMessage(pdev, INFORM, "detected 1gb half autoneg.\n");

            speed = LM_MEDIUM_SPEED_1000MBPS;
            duplex = LM_MEDIUM_HALF_DUPLEX;
        }
        else
        {
            /* Get local and remote 10/100 mb advertisement. */
            (void) lm_mread(
                    pdev,
                    pdev->params.phy_addr,
                    PHY_AN_AD_REG,
                    &local_adv);

            (void) lm_mread(
                    pdev,
                    pdev->params.phy_addr,
                    PHY_LINK_PARTNER_ABILITY_REG,
                    &remote_adv);

            val = local_adv & remote_adv;
            if(val & PHY_AN_AD_100BASETX_FULL)
            {
                DbgMessage(pdev, INFORM, "detected 100mb full autoneg.\n");

                speed = LM_MEDIUM_SPEED_100MBPS;
                duplex = LM_MEDIUM_FULL_DUPLEX;
            }
            else if(val & PHY_AN_AD_100BASETX_HALF)
            {
                DbgMessage(pdev, INFORM, "detected 100mb half autoneg.\n");

                speed = LM_MEDIUM_SPEED_100MBPS;
                duplex = LM_MEDIUM_HALF_DUPLEX;
            }
            else if(val & PHY_AN_AD_10BASET_FULL)
            {
                DbgMessage(pdev, INFORM, "detected 10mb full autoneg.\n");

                speed = LM_MEDIUM_SPEED_10MBPS;
                duplex = LM_MEDIUM_FULL_DUPLEX;
            }
            else if(val & PHY_AN_AD_10BASET_HALF)
            {
                DbgMessage(pdev, INFORM, "detected 10mb half autoneg.\n");

                speed = LM_MEDIUM_SPEED_10MBPS;
                duplex = LM_MEDIUM_HALF_DUPLEX;
            }
            else
            {
                DbgBreakMsg("unable to determine autoneg speed.\n");

                speed = LM_MEDIUM_SPEED_UNKNOWN;
                duplex = LM_MEDIUM_FULL_DUPLEX;
                link = LM_STATUS_LINK_DOWN;
            }
        }
    }
    else
    {
        /* The link speed speed and duplex mode are forced.  Get the forced
         * line settings from the PHY control register. */
        if(phy_ctrl & PHY_CTRL_SPEED_SELECT_100MBPS)
        {
            DbgMessage(pdev, INFORM, "PHY forced to 100mb.\n");
            speed = LM_MEDIUM_SPEED_100MBPS;
        }
        else if(phy_ctrl & PHY_CTRL_SPEED_SELECT_1000MBPS)
        {
            DbgMessage(pdev, INFORM, "PHY forced to 1gb.\n");

            speed = LM_MEDIUM_SPEED_1000MBPS;
        }
        else
        {
            DbgMessage(pdev, INFORM, "PHY forced to 10mb.\n");

            speed = LM_MEDIUM_SPEED_10MBPS;
        }

        if(phy_ctrl & PHY_CTRL_FULL_DUPLEX_MODE)
        {
            DbgMessage(pdev, INFORM, "PHY forced to full duplex.\n");

            duplex = LM_MEDIUM_FULL_DUPLEX;
        }
        else
        {
            DbgMessage(pdev, INFORM, "PHY forced to half duplex.\n");

            duplex = LM_MEDIUM_HALF_DUPLEX;
        }
    }

    *medium = LM_MEDIUM_TYPE_UTP | speed | duplex;

    return link;
} /* get_copper_phy_link */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
init_mac_link(
    lm_device_t *pdev,
    lm_status_t link,
    lm_medium_t medium,
    lm_flow_control_t flow_ctrl)
{
    u32_t val;

    /* Configure slot time, IPG, and 802.3 flow control. */
    REG_WR(pdev, emac.emac_tx_lengths, 0x2620);
    if(link == LM_STATUS_LINK_ACTIVE)
    {
        if(GET_MEDIUM_SPEED(medium) == LM_MEDIUM_SPEED_1000MBPS &&
            GET_MEDIUM_DUPLEX(medium) == LM_MEDIUM_HALF_DUPLEX)
        {
            REG_WR(pdev, emac.emac_tx_lengths, 0x26ff);
        }

        pdev->vars.flow_control = set_mac_flow_control(pdev, medium, flow_ctrl);
    }

    /* Configure the EMAC mode register. */
    REG_RD(pdev, emac.emac_mode, &val);

    val &= ~(EMAC_MODE_PORT | EMAC_MODE_FORCE_LINK);

    if(link == LM_STATUS_LINK_ACTIVE)
    {
        if(GET_MEDIUM_SPEED(medium) == LM_MEDIUM_SPEED_10MBPS)
        {
            if(CHIP_NUM(pdev) == CHIP_NUM_5706)
            {
                val |= EMAC_MODE_PORT_MII;
            }
            else
            {
                /* 5708 setting. */
                val |= EMAC_MODE_PORT_MII_10M;
            }
        }
        else if(GET_MEDIUM_SPEED(medium) == LM_MEDIUM_SPEED_100MBPS)
        {
            val |= EMAC_MODE_PORT_MII;
        }
        else
        {
            val |= EMAC_MODE_PORT_GMII;
        }

        if(GET_MEDIUM_SPEED(medium) == LM_MEDIUM_SPEED_2500MBPS)
        {
            val |= EMAC_MODE_25G_MODE;
        }

        /* We need to set the port mode to GMII when we are running in
         * the FPGA mode, regardless of the actual line speed. */
        if(CHIP_REV(pdev) == CHIP_REV_FPGA)
        {
            val &= ~EMAC_MODE_PORT;
            val |= EMAC_MODE_PORT_GMII;
        }
    }
    else
    {
        val |= EMAC_MODE_PORT_GMII;
    }

    if(GET_MEDIUM_TYPE(medium) == LM_MEDIUM_TYPE_NULL)
    {
        val |= EMAC_MODE_FORCE_LINK;
    }

    /* Set the MAC to operate in the appropriate duplex mode. */
    val &= ~EMAC_MODE_HALF_DUPLEX;
    if(GET_MEDIUM_DUPLEX(medium) == LM_MEDIUM_HALF_DUPLEX)
    {
        val |= EMAC_MODE_HALF_DUPLEX;
    }
    REG_WR(pdev, emac.emac_mode, val);

    /* Acknowledge the interrupt. */
    REG_WR(pdev, emac.emac_status, EMAC_STATUS_LINK_CHANGE);

    /* Enable phy link change attention. */
    if(pdev->params.phy_int_mode == PHY_INT_MODE_MI_INTERRUPT)
    {
        REG_WR(pdev, emac.emac_attention_ena, EMAC_ATTENTION_ENA_MI_INT);
    }
    else
    {
        REG_WR(pdev, emac.emac_attention_ena, EMAC_ATTENTION_ENA_LINK);
    }

    /* Enable status block link attention. */
    REG_RD(pdev, hc.hc_attn_bits_enable, &val);
    val &= ~STATUS_ATTN_BITS_LINK_STATE;
    if(pdev->params.link_chng_mode == LINK_CHNG_MODE_USE_STATUS_BLOCK)
    {
        val |= STATUS_ATTN_BITS_LINK_STATE;
    }
    REG_WR(pdev, hc.hc_attn_bits_enable, val);

    pdev->vars.medium = medium;
    pdev->vars.link_status = link;
} /* init_mac_link */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
serdes_fallback(
    lm_device_t *pdev,
    u8_t fallback_select)
{
    u32_t intr_exp_status;
    u8_t fallback_to;
    u32_t phy_status;
    u32_t phy_ctrl;
    u32_t val;
    u32_t cnt;

    pdev->vars.serdes_fallback_status = SERDES_FALLBACK_NONE;

    if(fallback_select == SERDES_FALLBACK_NONE)
    {
        return LM_STATUS_LINK_DOWN;
    }

    /* See if the cable is connected. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1c, 0x7c00);
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x1c, &val);

    /* We think the cable is not attached, set up the serdes to
     * autoneg as the default. */
    if(!(val & 0x10))       /* SIG_DETECT */
    {
        DbgMessage(pdev, INFORM, "no cable, default to autoneg.\n");

        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            PHY_CTRL_REG,
            PHY_CTRL_AUTO_NEG_ENABLE);

        return LM_STATUS_LINK_DOWN;
    }

    /* Read the interrupt expansion register to see if rudi_c is set.
     * rudi_c is set when we are receiving config words which means
     * the link partner is attempting to autonegotiate.
     *
     * When the link partner is attempting to autonegotiate and we
     * are not able to get linke, it could mean our transmit cable
     * is not plugged in.  In this case we don't want to fallback
     * to the force mode.  We want to remain in autonegotiation mode. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x17, 0x0f01);
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x15, &intr_exp_status);
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x15, &intr_exp_status);

    /* See if autoneg is enabled and the remote is not sending us
     * configs.  If this is the case and link is currently down, we
     * will switch to the force mode and disable autonegotiation.
     *
     * If we are current in the forced mode or the link partner is
     * sending use configs, we'll enable autoneg and restart it. */
    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_CTRL_REG, &phy_ctrl);
    if((phy_ctrl & PHY_CTRL_AUTO_NEG_ENABLE) && !(intr_exp_status & 0x20))
    {
        DbgMessage(pdev, INFORM, "switch to force mode - 1G full\n");

        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            PHY_CTRL_REG,
            PHY_CTRL_SPEED_SELECT_1000MBPS | PHY_CTRL_FULL_DUPLEX_MODE);

        fallback_to = SERDES_FALLBACK_1G;
    }
    else
    {
        DbgMessage(pdev, INFORM, "switch to autoneg mode - 1G full\n");

        /* Switch to autoneg mode. */
        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            PHY_CTRL_REG,
            PHY_CTRL_AUTO_NEG_ENABLE | PHY_CTRL_RESTART_AUTO_NEG);

        fallback_to = SERDES_FALLBACK_NONE;
    }

    for(cnt = 0; cnt < 100; cnt++)
    {
        mm_wait(pdev, 10);
    }

    phy_status = mii_get_serdes_link_status(pdev);

    if(phy_status & PHY_STATUS_LINK_PASS)
    {
        pdev->vars.serdes_fallback_status = fallback_to;

        return LM_STATUS_LINK_ACTIVE;
    }

    return LM_STATUS_LINK_DOWN;
} /* serdes_fallback */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
get_5708_serdes_link(
    lm_device_t *pdev,
    lm_medium_t *medium)
{
    u8_t restarted_autoneg;
    lm_medium_t duplex;
    lm_medium_t speed;
    lm_status_t link;
    u32_t val;
    u32_t idx;

    *medium = LM_MEDIUM_TYPE_FIBER |
        LM_MEDIUM_SPEED_UNKNOWN |
        LM_MEDIUM_FULL_DUPLEX;

    pdev->vars.cable_is_attached = FALSE;

    /* Check for link.  The first read returns the latched value, the
     * second read returns the current value. */
    (void) lm_mread(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_status),
            &val);
    (void) lm_mread(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_status),
            &val);

    /* CQ#23742 - Link status in the status block and the link status
     * in the mii_status are not consistent.  mii_status appears to
     * return invalid value.  Added a workaround here. */
    for(idx = 0; idx < 10 && val == 0; idx++)
    {
        mm_wait(pdev, 10);

        (void) lm_mread(
                pdev,
                pdev->params.phy_addr,
                MII_REG(serdes_reg_t, mii_status),
                &val);
    }

    if((val & MII_STAT_LINK_STATUS) == 0)
    {
        DbgMessage(pdev, INFORM, "serdes link down.\n");

        pdev->vars.cable_is_attached = FALSE;

        return LM_STATUS_LINK_DOWN;
    }

    link = LM_STATUS_LINK_ACTIVE;
    pdev->vars.cable_is_attached = TRUE;

    /* Determine duplex mode.  Link is present also means autoneg is done. */
    (void) lm_mread(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_ctrl),
            &val);
    if(val & MII_CTRL_ANEG_ENA)
    {
        /* Select Bank 0. */
        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            MII_REG(serdes_reg_t, mii_block_addr),
            MII_BLK_ADDR_DIGITAL);

        /* Get the negotiated speed and duplex mode. */
        (void) lm_mread(
            pdev,
            pdev->params.phy_addr,
            0x10+MII_REG(serdes_digital_reg_t, mii_1000x_stat1),
            &val);
        switch(val & MII_1000X_STAT1_SPEED)
        {
            case MII_1000X_STAT1_SPEED_2G5:
                DbgMessage(pdev, INFORM, "serdes autoneg to 2.5gb.\n");
                speed = LM_MEDIUM_SPEED_2500MBPS;
                break;

            case MII_1000X_STAT1_SPEED_1G:
                DbgMessage(pdev, INFORM, "serdes autoneg to 1gb.\n");
                speed = LM_MEDIUM_SPEED_1000MBPS;
                break;

            case MII_1000X_STAT1_SPEED_100:
                DbgMessage(pdev, INFORM, "serdes autoneg to 100mb.\n");
                speed = LM_MEDIUM_SPEED_100MBPS;
                break;

            case MII_1000X_STAT1_SPEED_10:
            default:
                DbgMessage(pdev, INFORM, "serdes autoneg to 10mb.\n");
                speed = LM_MEDIUM_SPEED_10MBPS;
                break;
        }

        /* Get the duplex mode. */
        duplex = LM_MEDIUM_FULL_DUPLEX;
        if(val & MII_1000X_STAT1_DUPLEX)
        {
            DbgMessage(pdev, INFORM, "serdes autoneg to full duplex.\n");
        }
        else
        {
            (void) lm_mread(
                    pdev,
                    pdev->params.phy_addr,
                    MII_REG(serdes_reg_t, mii_status),
                    &val);
            if(val & MII_STAT_ANEG_CMPL)
            {
                duplex = LM_MEDIUM_HALF_DUPLEX;
                DbgMessage(pdev, INFORM, "serdes autoneg to half duplex.\n");
            }
            else
            {
                DbgMessage(pdev, INFORM, "serdes autoneg to full duplex.\n");
            }
        }

        /* Set up pre-emphasis for a backplane application. */
        if(pdev->hw_info.nvm_hw_config & SHARED_HW_CFG_BACKPLANE_APP)
        {
            restarted_autoneg = set_5708_serdes_pre_emphasis(
                pdev,
                pdev->params.serdes_pre_emphasis);

            if(restarted_autoneg)
            {
                speed = LM_MEDIUM_SPEED_UNKNOWN;
                duplex = LM_MEDIUM_FULL_DUPLEX;
                link = LM_STATUS_LINK_DOWN;
            }
        }
    }
    else
    {
        /* Determine the forced link settings. */
        if(val & MII_CTRL_MANUAL_FORCE_2500)
        {
            DbgMessage(pdev, INFORM, "serdes forced to 2.5gb.\n");
            speed = LM_MEDIUM_SPEED_2500MBPS;
        }
        else if(val & MII_CTRL_MANUAL_SPD1)
        {
            DbgMessage(pdev, INFORM, "serdes forced to 1gb.\n");
            speed = LM_MEDIUM_SPEED_1000MBPS;
        }
        else if(val & MII_CTRL_MANUAL_SPD0)
        {
            DbgMessage(pdev, INFORM, "serdes forced to 100mb.\n");
            speed = LM_MEDIUM_SPEED_100MBPS;
        }
        else
        {
            DbgMessage(pdev, INFORM, "serdes forced to 10mb.\n");
            speed = LM_MEDIUM_SPEED_10MBPS;
        }

        if(val & MII_CTRL_DUPLEX_MODE)
        {
            DbgMessage(pdev, INFORM, "serdes forced to full duplex.\n");
            duplex = LM_MEDIUM_FULL_DUPLEX;
        }
        else
        {
            DbgMessage(pdev, INFORM, "serdes forced to half duplex.\n");
            duplex = LM_MEDIUM_HALF_DUPLEX;
        }
    }

    *medium = LM_MEDIUM_TYPE_FIBER | speed | duplex;

    return link;
} /* get_5708_serdes_link */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
get_5709_serdes_link(
    lm_device_t *pdev,
    lm_medium_t *medium)
{
    lm_medium_t duplex = LM_MEDIUM_FULL_DUPLEX;
    lm_medium_t speed = LM_MEDIUM_SPEED_UNKNOWN;
    lm_status_t link = LM_STATUS_LINK_UNKNOWN;
    u32_t mac_status;
    u32_t val;

    *medium = LM_MEDIUM_TYPE_FIBER |
        LM_MEDIUM_SPEED_UNKNOWN |
        LM_MEDIUM_FULL_DUPLEX;

    pdev->vars.cable_is_attached = FALSE;

    /* select gp_status block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0x8120);

    /* get status. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x1b, &val);
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x1b, &val);  /* is this needed? */

    /* sometimes when we get a link event, mii register 0x1b does not
     * reflect the current link status but mac_status does reflect the
     * correct link status. */
    REG_RD(pdev, emac.emac_status, &mac_status);

    /* link down. */
    if((val & 0x4) == 0 && (mac_status & EMAC_STATUS_LINK) == 0)
    {
        return LM_STATUS_LINK_DOWN;
    }

    link = LM_STATUS_LINK_ACTIVE;
    pdev->vars.cable_is_attached = TRUE;

    /* select combo ieee0 block. */
    (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0xffe0);

    /* phy_ctrl register. */
    (void) lm_mread(pdev, pdev->params.phy_addr, 0x10, &val);

    if(val & 0x1000)
    {
        /* select gp_status block. */
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1f, 0x8120);

        /* get status. */
        (void) lm_mread(pdev, pdev->params.phy_addr, 0x1b, &val);

        /* duplex mode. */
        if(val & 0x8)
        {
            duplex = LM_MEDIUM_FULL_DUPLEX;
        }
        else
        {
            duplex = LM_MEDIUM_HALF_DUPLEX;
        }

        /* Determine autoneg speed. */
        val = (val >> 8) & 0x3f;
        if(val == 0)
        {
            speed = LM_MEDIUM_SPEED_10MBPS;
        }
        else if(val == 1)
        {
            speed = LM_MEDIUM_SPEED_100MBPS;
        }
        else if(val == 2 || val == 13)
        {
            speed = LM_MEDIUM_SPEED_1000MBPS;
        }
        else if(val == 3)
        {
            speed = LM_MEDIUM_SPEED_2500MBPS;
        }
        else
        {
            DbgBreakMsg("unknown link speed status.\n");
        }
    }
    else
    {
        /* get forced duplex mode. */
        if(val & 0x100)
        {
            duplex = LM_MEDIUM_FULL_DUPLEX;
        }
        else
        {
            duplex = LM_MEDIUM_HALF_DUPLEX;
        }

        /* get forced speed. */
        if(val & 0x20)
        {
            speed = LM_MEDIUM_SPEED_2500MBPS;
        }
        else if((val & 0x2040) == 0)
        {
            speed = LM_MEDIUM_SPEED_10MBPS;
        }
        else if((val & 0x2040) == 0x2000)
        {
            speed = LM_MEDIUM_SPEED_100MBPS;
        }
        else if((val & 0x2040) == 0x40)
        {
            speed = LM_MEDIUM_SPEED_1000MBPS;
        }
        else
        {
            DbgBreakMsg("unknown speed.\n");
        }
    }

    *medium = LM_MEDIUM_TYPE_FIBER | speed | duplex;

    return link;
} /* get_5709_serdes_link */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
get_5706_serdes_link(
    lm_device_t *pdev,
    lm_medium_t *medium)
{
    lm_status_t link;
    u32_t phy_status;
    u32_t remote_adv;
    u32_t local_adv;
    u32_t phy_ctrl;
    u32_t val;

    *medium = LM_MEDIUM_TYPE_FIBER;

    phy_status = mii_get_serdes_link_status(pdev);

    if(phy_status & PHY_STATUS_LINK_PASS)
    {
        DbgMessage(pdev, INFORM, "serdes link up.\n");

        link = LM_STATUS_LINK_ACTIVE;
        *medium |= LM_MEDIUM_SPEED_1000MBPS;

        /* Determine duplex mode.  Link is present also means
         * autoneg is done. */
        (void) lm_mread(pdev, pdev->params.phy_addr, PHY_CTRL_REG, &phy_ctrl);
        if(phy_ctrl & PHY_CTRL_AUTO_NEG_ENABLE)
        {
            (void) lm_mread(
                    pdev,
                    pdev->params.phy_addr,
                    PHY_AN_AD_REG,
                    &local_adv);
            (void) lm_mread(
                    pdev,
                    pdev->params.phy_addr,
                    PHY_LINK_PARTNER_ABILITY_REG,
                    &remote_adv);

            val = local_adv & remote_adv;
            if(val & PHY_AN_AD_1000X_FULL_DUPLEX)
            {
                DbgMessage(pdev, INFORM, "serdes autoneg to full duplex.\n");

                *medium |= LM_MEDIUM_FULL_DUPLEX;
            }
            else
            {
                DbgMessage(pdev, INFORM, "serdes autoneg to half duplex.\n");

                *medium |= LM_MEDIUM_HALF_DUPLEX;
            }

            pdev->vars.serdes_fallback_status = SERDES_FALLBACK_NONE;
        }
        else
        {
            if(phy_ctrl & PHY_CTRL_FULL_DUPLEX_MODE)
            {
                DbgMessage(pdev, INFORM, "serdes forced to full duplex.\n");

                *medium |= LM_MEDIUM_FULL_DUPLEX;
            }
            else
            {
                DbgMessage(pdev, INFORM, "serdes forced to half duplex.\n");

                *medium |= LM_MEDIUM_HALF_DUPLEX;
            }

            if(pdev->vars.serdes_fallback_select)
            {
                pdev->vars.serdes_fallback_status = SERDES_FALLBACK_1G;
            }
        }
    }
    else
    {
        DbgMessage(pdev, INFORM, "serdes link down.\n");

        /* This routine is called only when the link is down. */
        link = serdes_fallback(pdev, pdev->vars.serdes_fallback_select);
    }

    /* cq#30504 - restore the tx driver current so we can get link. */
    if(pdev->vars.bcm5706s_tx_drv_cur)
    {
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x17, 0x0f03);

        (void) lm_mwrite(
            pdev,
            pdev->params.phy_addr,
            0x15,
            pdev->vars.bcm5706s_tx_drv_cur);

        pdev->vars.bcm5706s_tx_drv_cur = 0;
    }

    pdev->vars.cable_is_attached = TRUE;

    if(link == LM_STATUS_LINK_DOWN)
    {
        (void) lm_mwrite(pdev, pdev->params.phy_addr, 0x1c, 0x7c00);
        (void) lm_mread(pdev, pdev->params.phy_addr, 0x1c, &val);
        if(!(val & 0x10))
        {
            pdev->vars.cable_is_attached = FALSE;
        }
    }

    return link;
} /* get_5706_serdes_link */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC lm_status_t
get_remote_phy_link(
    lm_device_t *pdev,
    lm_medium_t *medium)
{
    u32_t remote_phy_link;
    lm_medium_t duplex;
    lm_medium_t speed;
    lm_status_t link;

    DbgBreakIf(pdev->params.enable_remote_phy == FALSE);

    *medium = LM_MEDIUM_TYPE_FIBER |
        LM_MEDIUM_SPEED_UNKNOWN |
        LM_MEDIUM_FULL_DUPLEX;

    pdev->vars.cable_is_attached = FALSE;

    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, drv_fw_mb.link_status),
        &remote_phy_link);

    pdev->vars.rphy_status = 0;

    if((remote_phy_link & NETLINK_GET_LINK_STATUS_SERDES_LINK) == 0)
    {
        pdev->vars.rphy_status |= RPHY_STATUS_ACTIVE;
    }

    if((remote_phy_link & NETLINK_GET_LINK_STATUS_NO_MEDIA_DETECTED) == 0)
    {
        pdev->vars.rphy_status |= RPHY_STATUS_MODULE_PRESENT;
    }

    if((remote_phy_link & NETLINK_GET_LINK_STATUS_LINK_UP) == 0)
    {
        return LM_STATUS_LINK_DOWN;
    }

    link = LM_STATUS_LINK_ACTIVE;
    pdev->vars.cable_is_attached = TRUE;

    switch(remote_phy_link & NETLINK_GET_LINK_STATUS_SPEED_MASK)
    {
        case NETLINK_GET_LINK_STATUS_10HALF:
            speed = LM_MEDIUM_SPEED_10MBPS;
            duplex = LM_MEDIUM_HALF_DUPLEX;
            break;

        case NETLINK_GET_LINK_STATUS_10FULL:
            speed = LM_MEDIUM_SPEED_10MBPS;
            duplex = LM_MEDIUM_FULL_DUPLEX;
            break;

        case NETLINK_GET_LINK_STATUS_100HALF:
            speed = LM_MEDIUM_SPEED_100MBPS;
            duplex = LM_MEDIUM_HALF_DUPLEX;
            break;

        case NETLINK_GET_LINK_STATUS_100FULL:
            speed = LM_MEDIUM_SPEED_100MBPS;
            duplex = LM_MEDIUM_FULL_DUPLEX;
            break;

        case NETLINK_GET_LINK_STATUS_1000HALF:
            speed = LM_MEDIUM_SPEED_1000MBPS;
            duplex = LM_MEDIUM_HALF_DUPLEX;
            break;

        case NETLINK_GET_LINK_STATUS_1000FULL:
            speed = LM_MEDIUM_SPEED_1000MBPS;
            duplex = LM_MEDIUM_FULL_DUPLEX;
            break;

        case NETLINK_GET_LINK_STATUS_2500HALF:
            speed = LM_MEDIUM_SPEED_2500MBPS;
            duplex = LM_MEDIUM_HALF_DUPLEX;
            break;

        case NETLINK_GET_LINK_STATUS_2500FULL:
            speed = LM_MEDIUM_SPEED_2500MBPS;
            duplex = LM_MEDIUM_FULL_DUPLEX;
            break;

        default:
            speed = LM_MEDIUM_SPEED_UNKNOWN;
            duplex = LM_MEDIUM_FULL_DUPLEX;
            break;
    }

    *medium = LM_MEDIUM_TYPE_FIBER | speed | duplex;

    return link;
} /* get_remote_phy_link */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_init_mac_link(
    lm_device_t *pdev)
{
    lm_status_t lm_status;
    lm_medium_t medium;
    lm_status_t link;
    u32_t val, phy_ctrl, phy_status;

    if(pdev->params.enable_remote_phy)
    {
        link = get_remote_phy_link(pdev, &medium);
        init_mac_link(pdev, link, medium, pdev->params.flow_ctrl_cap);

        return LM_STATUS_SUCCESS;
    }

    switch(GET_MEDIUM_TYPE(pdev->vars.medium))
    {
        case LM_MEDIUM_TYPE_UTP:
            link = get_copper_phy_link(pdev, &medium);
            init_mac_link(pdev, link, medium, pdev->params.flow_ctrl_cap);

            lm_status = LM_STATUS_SUCCESS;
            break;

        case LM_MEDIUM_TYPE_FIBER:
            DbgBreakIf(CHIP_NUM(pdev) != CHIP_NUM_5706 &&
                       CHIP_NUM(pdev) != CHIP_NUM_5708 &&
                       CHIP_NUM(pdev) != CHIP_NUM_5709);

            if(CHIP_NUM(pdev) == CHIP_NUM_5706)
            {
                link = get_5706_serdes_link(pdev, &medium);
            }
            else if(CHIP_NUM(pdev) == CHIP_NUM_5708)
            {
                link = get_5708_serdes_link(pdev, &medium);
            }
            else
            {
                link = get_5709_serdes_link(pdev, &medium);
            }

            init_mac_link(pdev, link, medium, pdev->params.flow_ctrl_cap);

            lm_status = LM_STATUS_SUCCESS;
            break;

        case LM_MEDIUM_TYPE_PHY_LOOPBACK:
        case LM_MEDIUM_TYPE_MAC_LOOPBACK:
            lm_status = init_loopback_mac_link(
                pdev,
                pdev->params.req_medium,
                pdev->params.flow_ctrl_cap);
            break;

        case LM_MEDIUM_TYPE_NULL:
            init_mac_link(
                pdev,
                LM_STATUS_LINK_ACTIVE,
                LM_MEDIUM_TYPE_NULL |
                    LM_MEDIUM_SPEED_1000MBPS |
                    LM_MEDIUM_FULL_DUPLEX,
                pdev->params.flow_ctrl_cap);

            lm_status = LM_STATUS_SUCCESS;
            break;

        default:
            lm_status = LM_STATUS_UNKNOWN_MEDIUM;
            break;
    }

    /* Report the currnet link status to the management firmware. */
    val = 0;

    if(pdev->vars.link_status == LM_STATUS_LINK_ACTIVE)
    {
        val |= NETLINK_GET_LINK_STATUS_LINK_UP;

        if(lm_get_medium(pdev) == LM_MEDIUM_TYPE_FIBER)
        {
            val |= NETLINK_GET_LINK_STATUS_SERDES_LINK;
        }
    }

    switch(GET_MEDIUM_SPEED(pdev->vars.medium))
    {
        case LM_MEDIUM_SPEED_10MBPS:
            if(GET_MEDIUM_DUPLEX(pdev->vars.medium) == LM_MEDIUM_FULL_DUPLEX)
            {
                val |= NETLINK_GET_LINK_STATUS_10FULL;
            }
            else
            {
                val |= NETLINK_GET_LINK_STATUS_10HALF;
            }
            break;

        case LM_MEDIUM_SPEED_100MBPS:
            if(GET_MEDIUM_DUPLEX(pdev->vars.medium) == LM_MEDIUM_FULL_DUPLEX)
            {
                val |= NETLINK_GET_LINK_STATUS_100FULL;
            }
            else
            {
                val |= NETLINK_GET_LINK_STATUS_100HALF;
            }
            break;

        case LM_MEDIUM_SPEED_1000MBPS:
            if(GET_MEDIUM_DUPLEX(pdev->vars.medium) == LM_MEDIUM_FULL_DUPLEX)
            {
                val |= NETLINK_GET_LINK_STATUS_1000FULL;
            }
            else
            {
                val |= NETLINK_GET_LINK_STATUS_1000HALF;
            }
            break;

        case LM_MEDIUM_SPEED_2500MBPS:
            if(GET_MEDIUM_DUPLEX(pdev->vars.medium) == LM_MEDIUM_FULL_DUPLEX)
            {
                val |= NETLINK_GET_LINK_STATUS_2500FULL;
            }
            else
            {
                val |= NETLINK_GET_LINK_STATUS_2500HALF;
            }
            break;
    }

    // read PHY_CTRL_REG to see if auto-negotiation is enabled/completed
    (void) lm_mread(pdev, pdev->params.phy_addr, PHY_CTRL_REG, &phy_ctrl);

    if(phy_ctrl & PHY_CTRL_AUTO_NEG_ENABLE)
    {
        val |= NETLINK_GET_LINK_STATUS_AN_ENABLED;
        (void) lm_mread(pdev, pdev->params.phy_addr, PHY_STATUS_REG, &phy_status);
        if(phy_status & PHY_STATUS_AUTO_NEG_COMPLETE)
        {
            val |= NETLINK_GET_LINK_STATUS_AN_COMPLETE;
            // Following bits are valid for copper (i.e. SerDes flag == 0)
            if ((val & NETLINK_GET_LINK_STATUS_SERDES_LINK) == 0)
            {
                u32_t remote_phy_ad;
                (void) lm_mread(
                        pdev,
                        pdev->params.phy_addr,
                        PHY_1000BASET_STATUS_REG,
                        &remote_phy_ad);

                if(remote_phy_ad & PHY_LINK_PARTNER_1000BASET_FULL)
                    val |= NETLINK_GET_LINK_STATUS_PARTNER_AD_1000FULL;
                if(remote_phy_ad & PHY_LINK_PARTNER_1000BASET_HALF)
                    val |= NETLINK_GET_LINK_STATUS_PARTNER_AD_1000HALF;

                (void) lm_mread(
                    pdev,
                    pdev->params.phy_addr,
                    PHY_LINK_PARTNER_ABILITY_REG,
                    &remote_phy_ad);
                if (remote_phy_ad & PHY_LINK_PARTNER_10BASET_HALF)
                    val |= NETLINK_GET_LINK_STATUS_PARTNER_AD_10HALF;
                if (remote_phy_ad & PHY_LINK_PARTNER_10BASET_FULL)
                    val |= NETLINK_GET_LINK_STATUS_PARTNER_AD_10FULL;
                if (remote_phy_ad & PHY_LINK_PARTNER_100BASETX_HALF)
                    val |= NETLINK_GET_LINK_STATUS_PARTNER_AD_100HALF;
                if (remote_phy_ad & PHY_LINK_PARTNER_100BASETX_FULL)
                    val |= NETLINK_GET_LINK_STATUS_PARTNER_AD_100FULL;
                if (remote_phy_ad & PHY_LINK_PARTNER_PAUSE_CAPABLE)
                    val |= NETLINK_GET_LINK_STATUS_PARTNER_SYM_PAUSE_CAP;
                if (remote_phy_ad & PHY_LINK_PARTNER_ASYM_PAUSE)
                    val |= NETLINK_GET_LINK_STATUS_PARTNER_ASYM_PAUSE_CAP;
                // Read PHY_AN_EXPANSION_REG to see if Link partner support auto
                // negotiation
                (void) lm_mread(
                    pdev,
                    pdev->params.phy_addr,
                    PHY_AN_EXPANSION_REG,
                    &remote_phy_ad);
                // If Link partner does not support auto negotiation,  we assume
                // parallel detection was used to get link.
                if ((remote_phy_ad & PHY_LINK_PARTNER_AUTONEG_ABILITY) == 0)
                    val |= NETLINK_GET_LINK_STATUS_PARALLEL_DET;
            }
        }
    }
    if(pdev->vars.flow_control & LM_FLOW_CONTROL_TRANSMIT_PAUSE)
    {
        val |= NETLINK_GET_LINK_STATUS_TX_FC_ENABLED;
    }
    if(pdev->vars.flow_control & LM_FLOW_CONTROL_RECEIVE_PAUSE)
    {
        val |= NETLINK_GET_LINK_STATUS_RX_FC_ENABLED;
    }
    // Following bits are not supported yet
    // NETLINK_GET_LINK_STATUS_NO_MEDIA_DETECTED;
    // NETLINK_GET_LINK_STATUS_CABLESENSE;
    // NETLINK_GET_LINK_STATUS_SW_TIMER_EVENT;
    REG_WR_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, drv_fw_mb.link_status),
        val);

    return lm_status;
} /* lm_init_mac_link */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_service_phy_int(
    lm_device_t *pdev,
    u32_t force_service_int)
{
    u32_t deasserted_attns;
    u32_t asserted_attns;
    u32_t link_chng;
    u32_t val;

    link_chng = FALSE;

    if(pdev->params.link_chng_mode == LINK_CHNG_MODE_USE_STATUS_REG)
    {
        REG_RD(pdev, emac.emac_status, &val);
        if(pdev->params.phy_int_mode == PHY_INT_MODE_MI_INTERRUPT)
        {
            if(val & EMAC_STATUS_MI_INT)
            {
                link_chng = TRUE;
            }
        }
        else if(val & EMAC_STATUS_LINK_CHANGE)
        {
            link_chng = TRUE;
        }
    }
    else
    {
        link_chng = FALSE;

        GET_ATTN_CHNG_BITS(pdev, &asserted_attns, &deasserted_attns);

        asserted_attns &= STATUS_ATTN_BITS_LINK_STATE;
        deasserted_attns &= STATUS_ATTN_BITS_LINK_STATE;

        if(asserted_attns)
        {
            link_chng = TRUE;

            REG_WR(
                pdev,
                pci_config.pcicfg_status_bit_set_cmd,
                asserted_attns);
        }
        else if(deasserted_attns)
        {
            link_chng = TRUE;

            REG_WR(
                pdev,
                pci_config.pcicfg_status_bit_clear_cmd,
                deasserted_attns);
        }
    }

    if(link_chng || force_service_int || pdev->params.enable_remote_phy)
    {
        (void) lm_init_mac_link(pdev);

        mm_indicate_link(pdev, pdev->vars.link_status, pdev->vars.medium);
    }
} /* lm_service_phy_int */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_medium_t
lm_get_medium(
    lm_device_t *pdev)
{
    u32_t decode;
    u32_t val;

    if(CHIP_REV(pdev) == CHIP_REV_IKOS)
    {
        return LM_MEDIUM_TYPE_NULL;
    }

    if(CHIP_REV(pdev) == CHIP_REV_FPGA)
    {
        return LM_MEDIUM_TYPE_UTP;
    }

    if(CHIP_NUM(pdev) == CHIP_NUM_5706 || CHIP_NUM(pdev) == CHIP_NUM_5708)
    {
        if(CHIP_BOND_ID(pdev) & CHIP_BOND_ID_SERDES_BIT)
        {
            return LM_MEDIUM_TYPE_FIBER;
        }

        return LM_MEDIUM_TYPE_UTP;
    }

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        REG_RD(pdev, misc.misc_dual_media_ctrl, &val);

        if((val & MISC_DUAL_MEDIA_CTRL_BOND_ID) ==
            MISC_DUAL_MEDIA_CTRL_BOND_ID_C)
        {
            return LM_MEDIUM_TYPE_UTP;
        }

        if((val & MISC_DUAL_MEDIA_CTRL_BOND_ID) ==
            MISC_DUAL_MEDIA_CTRL_BOND_ID_S)
        {
            return LM_MEDIUM_TYPE_FIBER;
        }

        /* mac to phy/serdes decode.
         *    swap strap mac0 mac1
         *    ==== ===== ==== ====
         *    0    000   phy0 phy1
         *    0    001   phy0 ser0
         *    0    010   phy0 ser1
         *    0    110   ser0 phy0
         *    0    101   ser0 phy1
         *    0    100   ser0 ser1
         *
         *    1    000   phy1 phy0
         *    1    001   phy1 ser1
         *    1    010   phy1 ser0
         *    1    110   ser1 phy1
         *    1    101   ser1 phy0
         *    1    100   ser1 ser0 */
        if(val & MISC_DUAL_MEDIA_CTRL_STRAP_OVERRIDE)
        {
            decode = (val & MISC_DUAL_MEDIA_CTRL_PHY_CTRL) >> 21;

            if(val & MISC_DUAL_MEDIA_CTRL_PORT_SWAP)
            {
                decode |= 0x8;
            }
        }
        else
        {
            decode = (val & MISC_DUAL_MEDIA_CTRL_PHY_CTRL_STRAP) >> 8;

            if(val & MISC_DUAL_MEDIA_CTRL_PORT_SWAP_PIN)
            {
                decode |= 0x8;
            }
        }

        decode |= pdev->hw_info.mac_id << 4;

        /* mac:4, swap:3, strap:2-0. */
        switch(decode)
        {
            case 0x00: /* 00000 - mac0, phy0 */
            case 0x01: /* 00001 - mac0, phy0 */
            case 0x02: /* 00010 - mac0, phy0 */
            case 0x08: /* 01000 - mac0, phy1 */
            case 0x09: /* 01001 - mac0, phy1 */
            case 0x0a: /* 01010 - mac0, phy1 */
            case 0x10: /* 10000 - mac1, phy1 */
            case 0x15: /* 10101 - mac1, phy1 */
            case 0x16: /* 10110 - mac1, phy0 */
            case 0x18: /* 11000 - mac1, phy0 */
            case 0x1d: /* 11101 - mac1, phy0 */
            case 0x1e: /* 11110 - mac1, phy1 */
                return LM_MEDIUM_TYPE_UTP;

            case 0x04: /* 00100 - mac0, ser0 */
            case 0x05: /* 00101 - mac0, ser0 */
            case 0x06: /* 00110 - mac0, ser0 */
            case 0x0c: /* 01100 - mac0, ser1 */
            case 0x0d: /* 01101 - mac0, ser1 */
            case 0x0e: /* 01110 - mac0, ser1 */
            case 0x11: /* 10001 - mac1, ser0 */
            case 0x12: /* 10010 - mac1, ser1 */
            case 0x14: /* 10100 - mac1, ser1 */
            case 0x19: /* 11001 - mac1, ser1 */
            case 0x1a: /* 11010 - mac1, ser0 */
            case 0x1c: /* 11100 - mac1, ser0 */
                return LM_MEDIUM_TYPE_FIBER;
        }
    }

    return LM_MEDIUM_TYPE_NULL;
} /* lm_get_medium */
