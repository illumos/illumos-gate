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
 *    11/15/01 Hav Khauv        Inception.
 ******************************************************************************/

#include "lm5710.h"
#include "phy_reg.h"
#include "license.h"
#include "mcp_shmem.h"
#include "lm_stats.h"
#include "577xx_int_offsets.h"

/***********************************************************/
/*              CLC - Common Link Component API            */
/***********************************************************/

/* Driver needs to redefine the cps_cb_st_ptr ( CPS CallBack Struct Pointer ) with its own */

#if defined(ELINK_DEBUG) && !defined(__SunOS)

void elink_cb_dbg(struct elink_dev *bp, _In_ char* fmt )
{
    DbgMessage(bp, WARNelink, fmt);
}
void elink_cb_dbg1(struct elink_dev *bp, _In_ char* fmt, u32 arg1 )
{
    DbgMessage(bp, WARNelink, fmt, arg1);
}
void elink_cb_dbg2(struct elink_dev *bp, _In_ char* fmt, u32 arg1, u32 arg2 )
{
    DbgMessage(bp, WARNelink, fmt, arg1, arg2);
}

void elink_cb_dbg3(struct elink_dev *bp, _In_ char* fmt, u32 arg1, u32 arg2, u32 arg3 )
{
    DbgMessage(bp, WARNelink, fmt, arg1, arg2, arg3);
}

#endif /* ELINK_DEBUG */

u32 elink_cb_reg_read(struct elink_dev *cb, u32 reg_addr )
{
    return REG_RD(cb, reg_addr);
}

void elink_cb_reg_write(struct elink_dev *cb, u32 reg_addr, u32 val )
{
    REG_WR(cb, reg_addr, val);
}

/* wb_write - pointer to 2 32 bits vars to be passed to the DMAE*/
void elink_cb_reg_wb_write(struct elink_dev *cb, u32 offset, u32 *wb_write, u16 len )
{
   REG_WR_DMAE_LEN(cb, offset, wb_write, len);
}

void elink_cb_reg_wb_read(struct elink_dev *cb, u32 offset, u32 *wb_write, u16 len )
{
   REG_RD_DMAE_LEN(cb, offset, wb_write, len);
}

/* mode - 0( LOW ) /1(HIGH)*/
u8 elink_cb_gpio_write(struct elink_dev *cb, u16 gpio_num, u8 mode, u8 port)
{
    return lm_gpio_write(cb, gpio_num, mode, port);
}

u8 elink_cb_gpio_mult_write(struct elink_dev *cb, u8 pins, u8 mode)
{
    return lm_gpio_mult_write(cb, pins, mode);
}

u32 elink_cb_gpio_read(struct elink_dev *cb, u16 gpio_num, u8 port)
{
    u32 val=0;
    lm_gpio_read(cb, gpio_num, &val, port);
    return val;
}

u8 elink_cb_gpio_int_write(struct elink_dev *cb, u16 gpio_num, u8 mode, u8 port)
{
    return lm_gpio_int_write(cb, gpio_num, mode, port);
}
void elink_cb_udelay(struct elink_dev *cb, u32 microsecond)
{
#define MAX_WAIT_INTERVAL 50

    u32_t wait_itr  = (microsecond/MAX_WAIT_INTERVAL) ;
    u32_t cnt       = 0;
    u32_t wait_time = MAX_WAIT_INTERVAL ;

    if( 0 == wait_itr )
    {
        wait_time = microsecond ;
        wait_itr = 1;
    }

    for(cnt = 0; cnt < wait_itr; cnt++)
    {
        mm_wait(cb , wait_time );
    }
}
u32 elink_cb_fw_command(struct elink_dev *cb, u32 command, u32 param)
{
    u32 fw_resp = 0;
    lm_mcp_cmd_send_recieve(cb, lm_mcp_mb_header, command, param, MCP_CMD_DEFAULT_TIMEOUT,
                &fw_resp );
    return fw_resp;
}

void elink_cb_download_progress(struct elink_dev *cb, u32 cur, u32 total)
{
    UNREFERENCED_PARAMETER_(cb);
    UNREFERENCED_PARAMETER_(cur);
    UNREFERENCED_PARAMETER_(total);

#ifdef DOS
    printf("Downloaded %u bytes out of %u bytes\n", cur, total );
#endif // DOS
}

void elink_cb_event_log(struct elink_dev *cb, const elink_log_id_t elink_log_id, ...)
{
    va_list     ap;
    lm_log_id_t lm_log_id = LM_LOG_ID_MAX;

    switch( elink_log_id )
    {
    case ELINK_LOG_ID_OVER_CURRENT:
        lm_log_id = LM_LOG_ID_OVER_CURRENT;
        break;

    case ELINK_LOG_ID_PHY_UNINITIALIZED:
        lm_log_id = LM_LOG_ID_PHY_UNINITIALIZED;
        break;

    case ELINK_LOG_ID_UNQUAL_IO_MODULE:
        lm_log_id = LM_LOG_ID_UNQUAL_IO_MODULE;
        break;

    case ELINK_LOG_ID_MDIO_ACCESS_TIMEOUT:
        lm_log_id = LM_LOG_ID_MDIO_ACCESS_TIMEOUT;
        break;

    case ELINK_LOG_ID_NON_10G_MODULE:
        lm_log_id = LM_LOG_ID_NON_10G_MODULE;
        break;

    default:
        DbgBreakIf(TRUE);
        break;
    } // elink_log_id switch

    va_start(ap, elink_log_id);

    mm_event_log_generic_arg_fwd( cb, lm_log_id, ap );

    va_end(ap);
}

u8 elink_cb_path_id(struct elink_dev *cb)
{
   return PATH_ID(cb);
}

void elink_cb_notify_link_changed(struct elink_dev *cb)
{
   REG_WR(cb, MISC_REG_AEU_GENERAL_ATTN_12 + FUNC_ID((lm_device_t *)cb)*sizeof(u32), 1);
}
/*******************************************************************************
* Macros.
******************************************************************************/

#define MII_REG(_type, _field)          (OFFSETOF(_type, _field)/2)

#define MDIO_INDIRECT_REG_ADDR      0x1f
#define MDIO_SET_REG_BANK(pdev,reg_bank)\
    lm_mwrite(pdev,MDIO_INDIRECT_REG_ADDR, reg_bank)

#define MDIO_ACCESS_TIMEOUT          1000

#define ELINK_STATUS_TO_LM_STATUS(_rc, _lm_status) switch(_rc)\
{\
case ELINK_STATUS_OK:\
    _lm_status = LM_STATUS_SUCCESS;\
    break;\
case ELINK_STATUS_TIMEOUT:\
    _lm_status = LM_STATUS_TIMEOUT;\
    break;\
case ELINK_STATUS_NO_LINK:\
    _lm_status = LM_STATUS_LINK_DOWN;\
    break;\
case ELINK_STATUS_ERROR:\
default:\
    _lm_status = LM_STATUS_FAILURE;\
    break;\
}

/*******************************************************************************
* Description:
*
* Return:
******************************************************************************/
lm_status_t
lm_mwrite( lm_device_t *pdev,
          u32_t reg,
          u32_t val)
{
    lm_status_t lm_status;
    u32_t tmp;
    u32_t cnt;
    u8_t port = PORT_ID(pdev);
    u32_t emac_base = (port?GRCBASE_EMAC1:GRCBASE_EMAC0);

    REG_WR(pdev,NIG_REG_XGXS0_CTRL_MD_ST + port*0x18, 1);

    DbgMessage(pdev, INFORM, "lm_mwrite\n");

    if(pdev->params.phy_int_mode == PHY_INT_MODE_AUTO_POLLING)
    {
        tmp=REG_RD(pdev,emac_base+EMAC_REG_EMAC_MDIO_MODE);
        tmp &= ~EMAC_MDIO_MODE_AUTO_POLL;

        REG_WR(pdev,emac_base+EMAC_REG_EMAC_MDIO_MODE,tmp);

        mm_wait(pdev, 40);
    }

    tmp = (pdev->vars.phy_addr << 21) | (reg << 16) | (val & EMAC_MDIO_COMM_DATA) |
        EMAC_MDIO_COMM_COMMAND_WRITE_22 |
        EMAC_MDIO_COMM_START_BUSY;

    REG_WR(pdev,emac_base+EMAC_REG_EMAC_MDIO_COMM,tmp);


    for(cnt = 0; cnt < 1000; cnt++)
    {
        mm_wait(pdev, 10);

        tmp=REG_RD(pdev,emac_base+EMAC_REG_EMAC_MDIO_COMM);
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
        tmp=REG_RD(pdev,emac_base+EMAC_REG_EMAC_MDIO_MODE);
        tmp |= EMAC_MDIO_MODE_AUTO_POLL;

        REG_WR(pdev,emac_base+EMAC_REG_EMAC_MDIO_MODE,tmp);
    }
    REG_WR(pdev,NIG_REG_XGXS0_CTRL_MD_ST +
           port*0x18, 0);
    return lm_status;
} /* lm_mwrite */



/*******************************************************************************
* Description:
*
* Return:
******************************************************************************/
lm_status_t
lm_mread( lm_device_t *pdev,
         u32_t reg,
         u32_t *ret_val)
{
    lm_status_t lm_status;
    u32_t val;
    u32_t cnt;
    u8_t port = PORT_ID(pdev);
    u32_t emac_base = (port?GRCBASE_EMAC1:GRCBASE_EMAC0);

    REG_WR(pdev,NIG_REG_XGXS0_CTRL_MD_ST + port*0x18, 1);

    DbgMessage(pdev, INFORM, "lm_mread\n");

    if(pdev->params.phy_int_mode == PHY_INT_MODE_AUTO_POLLING)
    {
        val=REG_RD(pdev,emac_base+EMAC_REG_EMAC_MDIO_MODE);
        val &= ~EMAC_MDIO_MODE_AUTO_POLL;

        REG_WR(pdev,emac_base+EMAC_REG_EMAC_MDIO_MODE,val);

        mm_wait(pdev, 40);
    }

    val = (pdev->vars.phy_addr << 21) | (reg << 16) |
        EMAC_MDIO_COMM_COMMAND_READ_22 |
        EMAC_MDIO_COMM_START_BUSY;

    REG_WR(pdev,emac_base+EMAC_REG_EMAC_MDIO_COMM,val);

    for(cnt = 0; cnt < 1000; cnt++)
    {
        mm_wait(pdev, 10);

        val=REG_RD(pdev,emac_base+EMAC_REG_EMAC_MDIO_COMM);
        if(!(val & EMAC_MDIO_COMM_START_BUSY))
        {
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
        val=REG_RD(pdev,emac_base+EMAC_REG_EMAC_MDIO_MODE);
        val |= EMAC_MDIO_MODE_AUTO_POLL;

        REG_WR(pdev,emac_base+EMAC_REG_EMAC_MDIO_MODE,val);
    }
    REG_WR(pdev,NIG_REG_XGXS0_CTRL_MD_ST +
           port*0x18, 0);
    return lm_status;
} /* lm_mread */

/*******************************************************************************
* Description:
*
* Return:
******************************************************************************/
lm_status_t
lm_phy45_read(
    lm_device_t *pdev,
    u8_t  phy_addr,
    u8_t dev_addr,
    u16_t reg, // offset
    u16_t *ret_val)
{

    u16_t       rc           = ELINK_STATUS_OK;
    lm_status_t lm_status    = LM_STATUS_SUCCESS;

    PHY_HW_LOCK(pdev);

    rc = elink_phy_read(&pdev->params.link, phy_addr, dev_addr, reg, ret_val);

    PHY_HW_UNLOCK(pdev);

    ELINK_STATUS_TO_LM_STATUS( rc, lm_status );

    return lm_status;
}

/*******************************************************************************
* Description:
*
* Return:
******************************************************************************/
lm_status_t
lm_phy45_write(
    lm_device_t *pdev,
    u8_t  phy_addr,
    u8_t  dev_addr,
    u16_t reg, // offset
    u16_t val)
{

    u16_t       rc           = ELINK_STATUS_OK;
    lm_status_t lm_status    = LM_STATUS_SUCCESS;

    PHY_HW_LOCK(pdev);

    rc = elink_phy_write(&pdev->params.link, phy_addr, dev_addr, reg, val);

    PHY_HW_UNLOCK(pdev);

    ELINK_STATUS_TO_LM_STATUS( rc, lm_status );

    return lm_status;
}

lm_status_t
lm_set_phy_addr(lm_device_t *pdev,
                u8_t addr)
{
    if (addr > 0x1f)
    {
        DbgBreakMsg("lm_set_phy_addr: error addr not valid\n");
        return LM_STATUS_FAILURE;
    }
    pdev->vars.phy_addr = addr;
    return LM_STATUS_SUCCESS;
}

/*
 *Function Name: lm_get_speed_real_from_elink_line_speed
 *
 *Parameters: IN line speed (from elink)
 *
 *Description:
 *
 *Returns: "real speed" in mbps units
 *
 */
u32_t lm_get_speed_real_from_elink_line_speed( IN const struct elink_vars* link_vars )
{
    const u16_t line_speed = link_vars->line_speed;
    u32_t       real_speed = 0;

    if( !link_vars->link_up )
    {
        // probably we get here from ioc_get_driver_info in case of no link
        // we return 0 in that case
        return 0;
    }

    switch(line_speed)
    {
    case ELINK_SPEED_10:
        real_speed = 10;
        break;

    case ELINK_SPEED_100:
        real_speed = 100;
        break;

    case ELINK_SPEED_1000:
        real_speed = 1000;
        break;

    case ELINK_SPEED_2500:
        real_speed = 2500;
        break;

    case ELINK_SPEED_10000:
        real_speed = 10000;
        break;

    case ELINK_SPEED_20000:
        real_speed = 20000;
        break;

    default:
        DbgBreakIf(1);
        break;
    }
    return real_speed;
}

/*
 *Function Name: lm_get_speed_medium_from_elink_line_speed
 *
 *Parameters: IN line speed (from elink)
 *
 *Description:
 *
 *Returns: "medium"  translation to LM units
 *
 */
u32_t lm_get_speed_medium_from_elink_line_speed( IN const struct elink_vars* link_vars )
{
    const u16_t line_speed = link_vars->line_speed;
    u32_t       medium     = 0;

    switch(line_speed)
    {
    case ELINK_SPEED_10:
        medium = LM_MEDIUM_SPEED_10MBPS;
        break;

    case ELINK_SPEED_100:
        medium = LM_MEDIUM_SPEED_100MBPS;
        break;

    case ELINK_SPEED_1000:
        medium = LM_MEDIUM_SPEED_1000MBPS;
        break;

    case ELINK_SPEED_2500:
        medium = LM_MEDIUM_SPEED_2500MBPS;
        break;

    case ELINK_SPEED_10000:
        medium = LM_MEDIUM_SPEED_10GBPS;
        break;

    case ELINK_SPEED_20000:
        medium = LM_MEDIUM_SPEED_20GBPS;
        break;

    default:
        DbgBreakIf(1);
        break;
    }
    return medium;
}

u32_t lm_get_port_max_speed(IN struct _lm_device_t *pdev)
{
    static const u32_t PORT_SPEED_10G = 10000;
    static const u32_t PORT_SPEED_1G  = 1000;

    u32_t port_default_cfg = 0;

    if(!CHIP_IS_E3(pdev))
    {
        return PORT_SPEED_10G;
    }

    if(LM_CHIP_PORT_MODE_4 != CHIP_PORT_MODE(pdev))
    {
        return PORT_SPEED_10G;
    }

    LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.port_hw_config[PORT_ID(pdev)].default_cfg),&port_default_cfg);

    if (GET_FLAGS(port_default_cfg, PORT_HW_CFG_NET_SERDES_IF_MASK) == PORT_HW_CFG_NET_SERDES_IF_SGMII)
    {
        return PORT_SPEED_1G;
    }
    else
    {
        return PORT_SPEED_10G;
    }
}

/*
 *Function Name: lm_loopback_req_meduim_convert
 *
 *Parameters: IN req_medium as received from upper layer
 *
 *Description: convert the req_meduim (recieved from diag driver / BMAPI) to relevant type according to the chip
 *             this is a little bit conusing since we override the value recieved by a new value
 *             but we need to do it for backward compatbiality.
 *Returns: "medium"  translation to LM units
 *
 */
lm_medium_t lm_loopback_req_medium_convert( IN struct _lm_device_t *pdev, IN const lm_medium_t req_medium )
{
    u32_t       default_cfg = 0;
    lm_medium_t ret_medium  = req_medium;

    // Assumption bxdiag always send the following for each test type:
    // LOOPBACK_TYPE_MAC --> LM_MEDIUM_TYPE_BMAC_LOOPBACK/LM_MEDIUM_TYPE_UMAC_LOOPBACK/LM_MEDIUM_TYPE_XMAC_LOOPBACK (bxdiag 7.0.1 only, never gold...)
    // LOOPBACK_TYPE_PHY --> LM_MEDIUM_TYPE_XGXS_10_LOOPBACK

    // Here, we'll "translate" the LM_MEDIUM_TYPE_XXX so it will work correctly in BCM578xx
    if( CHIP_IS_E3(pdev) )
    {
        LM_SHMEM_READ(pdev,OFFSETOF(shmem_region_t,dev_info.port_hw_config[PORT_ID(pdev)].default_cfg),&default_cfg);
        default_cfg &= PORT_HW_CFG_NET_SERDES_IF_MASK;
    }

    switch(req_medium)
    {
        // MAC loopback test
    case LM_MEDIUM_TYPE_BMAC_LOOPBACK:
    case LM_MEDIUM_TYPE_UMAC_LOOPBACK:
    case LM_MEDIUM_TYPE_XMAC_LOOPBACK:
    case LM_MEDIUM_TYPE_MAC_LOOPBACK:
        if( CHIP_IS_E3(pdev) )
        {
            if( PORT_HW_CFG_NET_SERDES_IF_SGMII == default_cfg )
            {
                ret_medium = LM_MEDIUM_TYPE_UMAC_LOOPBACK; //1GB
            }
            else
            {
                ret_medium = LM_MEDIUM_TYPE_XMAC_LOOPBACK; //10GB/20GB
            }
        }
        else
        {
            ret_medium = LM_MEDIUM_TYPE_BMAC_LOOPBACK;
        }
        break;

        // PHY loopback test
    case LM_MEDIUM_TYPE_XGXS_10_LOOPBACK:
        if( CHIP_IS_E3(pdev) )
        {
            switch(default_cfg)
            {
            case PORT_HW_CFG_NET_SERDES_IF_SGMII:
                ret_medium = LM_MEDIUM_TYPE_XGXS_LOOPBACK; //1GB
                break;

            case PORT_HW_CFG_NET_SERDES_IF_XFI:
            case PORT_HW_CFG_NET_SERDES_IF_SFI:
            case PORT_HW_CFG_NET_SERDES_IF_KR:
                ret_medium = LM_MEDIUM_TYPE_XGXS_10_LOOPBACK; //10GB
                break;

            case PORT_HW_CFG_NET_SERDES_IF_DXGXS:
            case PORT_HW_CFG_NET_SERDES_IF_KR2:
            default:
                ret_medium = req_medium; //20GB - TBD!! for T7.2
                break;
            }
        }
        else
        {
            ret_medium = LM_MEDIUM_TYPE_XGXS_10_LOOPBACK; //10GB
        }
        break;

    default:
        break;
    }

    return ret_medium;
}

static void get_link_params(lm_device_t *pdev)
{
    u32_t real_speed                = 0; // speed in 100M steps
    u32_t medium                    = 0; // LM_MEDIUM_XXX
    u16_t max_bw_in_Mbps            = 0; // In Mbps steps
    u16_t max_bw_in_100Mbps         = 0; // In 100Mbps steps

    if (IS_VFDEV(pdev))
    {
        pdev->vars.cable_is_attached = TRUE;
        pdev->vars.link_status = LM_STATUS_LINK_ACTIVE;
        SET_MEDIUM_SPEED(pdev->vars.medium,LM_MEDIUM_SPEED_10GBPS);
        return;
    }
    // link status

    if (!pdev->vars.link.link_up)
    {
        pdev->vars.link_status = LM_STATUS_LINK_DOWN;
        pdev->vars.cable_is_attached = FALSE;

    }
    else
    {
        // if we are in multifunction mode and function is disabled indicate OS link down (unless loopback medium is set)
        // Note that the CLC link is up so pmf handling is still going on
        if (IS_MULTI_VNIC(pdev) && (GET_FLAGS(pdev->hw_info.mf_info.func_mf_cfg, FUNC_MF_CFG_FUNC_DISABLED)) &&
            (!LM_MEDIUM_IS_LOOPBACK(pdev->params.req_medium)))
        {
            pdev->vars.link_status = LM_STATUS_LINK_DOWN;
            pdev->vars.cable_is_attached = FALSE;
        }
        else
        {
            //in NIV mode, link_status is modified only from lm_niv_vif_set or from the FUNCTION_UPDATE completion(for loopback)
            if(!IS_MF_AFEX_MODE(pdev))
            {
                pdev->vars.link_status = LM_STATUS_LINK_ACTIVE;
            }
            pdev->vars.cable_is_attached = TRUE;
        }
        // get speed

        real_speed = lm_get_speed_real_from_elink_line_speed(&pdev->vars.link);
        real_speed = real_speed/100;

        medium     = lm_get_speed_medium_from_elink_line_speed(&pdev->vars.link);

        SET_MEDIUM_SPEED(pdev->vars.medium, medium );

        // get duplex
        SET_MEDIUM_DUPLEX(pdev->vars.medium,LM_MEDIUM_FULL_DUPLEX);
        if (pdev->vars.link.duplex == DUPLEX_HALF )
        {
            SET_MEDIUM_DUPLEX(pdev->vars.medium,LM_MEDIUM_HALF_DUPLEX);
        }
        // get flow_control
        pdev->vars.flow_control = LM_FLOW_CONTROL_NONE;
        if (pdev->vars.link.flow_ctrl & ELINK_FLOW_CTRL_RX)
        {
            pdev->vars.flow_control |= LM_FLOW_CONTROL_RECEIVE_PAUSE;
        }
        if (pdev->vars.link.flow_ctrl & ELINK_FLOW_CTRL_TX)
        {
            pdev->vars.flow_control |= LM_FLOW_CONTROL_TRANSMIT_PAUSE;
        }

        // get EEE state

        if (GET_FLAGS(pdev->vars.link.eee_status,SHMEM_EEE_REQUESTED_BIT))
        {
            pdev->vars.autogreeen = LM_AUTOGREEEN_ENABLED;
            pdev->vars.eee_policy = pdev->vars.link.eee_status & SHMEM_EEE_TIMER_MASK;
        }
        else
        {
            pdev->vars.autogreeen = LM_AUTOGREEEN_DISABLED;
        }

        if (IS_MULTI_VNIC(pdev))
        {

            max_bw_in_Mbps = lm_get_max_bw(pdev,
                                           (real_speed *100),
                                           VNIC_ID(pdev));

            max_bw_in_100Mbps = max_bw_in_Mbps /100; // In 100Mbps steps

            if (real_speed > max_bw_in_100Mbps)
            {
                if (max_bw_in_100Mbps)
                {
                    SET_MEDIUM_SPEED(pdev->vars.medium,(LM_MEDIUM_SPEED_SEQ_START + ((max_bw_in_100Mbps-1)<<8)));
                }
                else
                {
                    // in case the pdev->params.max_bw[VNIC_ID(pdev)] = 0
                    SET_MEDIUM_SPEED(pdev->vars.medium,LM_MEDIUM_SPEED_SEQ_START);
                }
            }
        }
    }
}

void sync_link_status(lm_device_t *pdev)
{
    u32_t      i       = 0;
    const u8_t func_id = FUNC_ID(pdev);
    const u8_t port_id = PORT_ID(pdev);

    DbgMessage(pdev, WARN, "sync_link_status: Func %d \n", func_id );

    // inform all other port vnics not ourself
    for( i=0; i<4 ;i++ )
     {
        if (func_id != (i*2 + port_id))
        {
            REG_WR(pdev,MISC_REG_AEU_GENERAL_ATTN_12 + 4*(i*2 + port_id),0x1);
            DbgMessage(pdev, WARN, "sync_link_status: send attention to Func %d\n", (i*2 + port_id));
        }
    }
}

void
lm_reset_link(lm_device_t *pdev)
{
    if (IS_VFDEV(pdev))
    {
        DbgMessage(pdev, FATAL, "lm_reset_link not implemented for VF\n");
        return;

    }
    // notify stats
    lm_stats_on_link_update(pdev, FALSE );
    pdev->vars.link_status       = LM_STATUS_LINK_DOWN;
    pdev->vars.cable_is_attached = FALSE;
    pdev->vars.mac_type          = MAC_TYPE_NONE;

    PHY_HW_LOCK(pdev);
    elink_lfa_reset(&pdev->params.link,&pdev->vars.link);
    PHY_HW_UNLOCK(pdev);
}
/**
 * @description
 * Configure cmng the firmware to the right CMNG values if this
 * device is the PMF ,after link speed/ETS changes.
 *
 * @note This function must be called under PHY_LOCK
 * @param pdev
 */
void lm_cmng_update(lm_device_t *pdev)
{
    u32_t port_speed = 0;

    /* fairness is only supported for vnics in the meantime... */
    if ((!IS_MULTI_VNIC(pdev)) ||        
        (!pdev->vars.link.link_up))
    {
        return;
    }

    if (!IS_PMF(pdev) && !IS_MF_AFEX_MODE(pdev))
    {
        // in case we are not PMF we still want to run this code in AFEX mode.        
        return;
    }

    port_speed = lm_get_speed_real_from_elink_line_speed(&pdev->vars.link);

    lm_cmng_init(pdev,port_speed);
}

void lm_reload_link_and_cmng(lm_device_t *pdev)
{
    if( IS_MULTI_VNIC(pdev) && pdev->hw_info.mcp_detected )
    {
        lm_cmng_get_shmem_info(pdev);
        lm_cmng_calc_params(pdev);
    }

    get_link_params(pdev);

    lm_cmng_update(pdev);

}

void lm_link_fill_reported_data( IN lm_device_t *pdev, OUT lm_reported_link_params_t *lm_reported_link_params )
{
    lm_reported_link_params->cable_is_attached = pdev->vars.cable_is_attached;
    lm_reported_link_params->link              = pdev->vars.link_status;
    lm_reported_link_params->medium            = pdev->vars.medium;
    lm_reported_link_params->flow_ctrl         = pdev->vars.flow_control;
    lm_reported_link_params->eee_policy        = (u8_t)pdev->vars.eee_policy; // one of PORT_FEAT_CFG_EEE_POWER_MODE_*
}

// This function is called due to link change attention for none pmf it gets the link status from the shmem
void lm_link_report(lm_device_t *pdev)
{
    u8_t                      pause_ena           = 0;
    lm_reported_link_params_t current_link_params = {0};
    u8_t                      b_indicate          = TRUE;

    lm_reload_link_and_cmng(pdev);

    // get current link params into current_link_params
    lm_link_fill_reported_data(pdev, &current_link_params );

    /* Don't report link down again (if it is already down) */
    if( (LM_STATUS_LINK_DOWN == pdev->vars.last_reported_link_params.link) &&
        (LM_STATUS_LINK_DOWN == current_link_params.link) )
    {
        b_indicate = FALSE;
    }
    else
    {
        // Don't report exact same link status twice
        ASSERT_STATIC( sizeof(current_link_params) == sizeof(pdev->vars.last_reported_link_params) );
        b_indicate = ( FALSE == mm_memcmp( &current_link_params, &pdev->vars.last_reported_link_params, sizeof(current_link_params)) );
    }

    if (pdev->vars.link.link_up)
    {
        // link up
        // dropless flow control
        if (IS_PMF(pdev) && pdev->params.l2_fw_flow_ctrl)
        {
            if (pdev->vars.link.flow_ctrl & ELINK_FLOW_CTRL_TX)
            {
                pause_ena = 1;
            }
            LM_INTMEM_WRITE16(pdev,USTORM_ETH_PAUSE_ENABLED_OFFSET(PORT_ID(pdev)), pause_ena, BAR_USTRORM_INTMEM);
        }
        pdev->vars.mac_type = pdev->vars.link.mac_type;
        DbgBreakIf(pdev->vars.mac_type >= MAC_TYPE_MAX);

        // indicate link up - except if we're in NIV mode where we wait for the VIF-SET/enable command from the MCP.
        if( IS_MF_AFEX_MODE(pdev) )
        {
            b_indicate = FALSE;
        }

        // indicate link up
        if( b_indicate )
        {
            mm_indicate_link(pdev, pdev->vars.link_status, pdev->vars.medium);
            DbgMessage(pdev, WARN, "lm_link_update: indicate link %d 0x%x \n",pdev->vars.link_status,pdev->vars.medium);
        }

        // notify stats
        lm_stats_on_link_update(pdev, TRUE );
    }
    else
    {   // link down
        // indicate link down
        pdev->vars.mac_type = MAC_TYPE_NONE;
        pdev->vars.stats.stats_collect.stats_hw.b_is_link_up = FALSE;

        // indicate link down
        if( b_indicate )
        {
            mm_indicate_link(pdev, pdev->vars.link_status, pdev->vars.medium);
            DbgMessage(pdev, WARN, "lm_link_update: indicate link %d 0x%x \n",pdev->vars.link_status,pdev->vars.medium);
        }
    }

    // notify othres funcs
    if (IS_MULTI_VNIC(pdev) && IS_PMF(pdev))
    {
        sync_link_status(pdev);
    }
}

// This function is called due to link change interrupt for the relevant function
// NOTE: this function must be called under phy lock
lm_status_t lm_link_update(lm_device_t *pdev)
{
    if CHK_NULL( pdev )
    {
        DbgBreakIf(!pdev);
        return LM_STATUS_FAILURE;
    }
    // notify stats
    lm_stats_on_link_update(pdev, FALSE );

    if( pdev->params.i2c_interval_sec )
    {
        pdev->params.i2c_elink_status[I2C_SECTION_A0] = ELINK_STATUS_INVALID_IMAGE;
        pdev->params.i2c_elink_status[I2C_SECTION_A2] = ELINK_STATUS_INVALID_IMAGE;
    }

    PHY_HW_LOCK(pdev);
    elink_link_update(&pdev->params.link,&pdev->vars.link);
    PHY_HW_UNLOCK(pdev);
    lm_link_report(pdev);
    // increment link_chng_cnt counter to indicate there was some link change.
    pdev->vars.link_chng_cnt++;
    return LM_STATUS_SUCCESS;
}

static void lm_set_phy_selection( lm_device_t *pdev, u8_t i)
{
    u32 phy_sel ;
    if (pdev->params.link.multi_phy_config & PORT_HW_CFG_PHY_SWAPPED_ENABLED)
    {
        phy_sel = PORT_HW_CFG_PHY_SELECTION_SECOND_PHY - (i - ELINK_EXT_PHY1);
    }
    else
    {
        phy_sel = PORT_HW_CFG_PHY_SELECTION_FIRST_PHY + (i - ELINK_EXT_PHY1);
    }
    RESET_FLAGS( pdev->params.link.multi_phy_config, PORT_HW_CFG_PHY_SELECTION_MASK );
    SET_FLAGS( pdev->params.link.multi_phy_config, phy_sel);
}

static void lm_set_phy_priority_selection( lm_device_t *pdev, u8_t i)
{
    u32 phy_sel;

    if (pdev->params.link.multi_phy_config & PORT_HW_CFG_PHY_SWAPPED_ENABLED)
    {
        phy_sel = PORT_HW_CFG_PHY_SELECTION_SECOND_PHY_PRIORITY - (i - ELINK_EXT_PHY1);
    }
    else
    {
        phy_sel = PORT_HW_CFG_PHY_SELECTION_FIRST_PHY_PRIORITY + (i - ELINK_EXT_PHY1);
    }
    RESET_FLAGS( pdev->params.link.multi_phy_config, PORT_HW_CFG_PHY_SELECTION_MASK );
    SET_FLAGS( pdev->params.link.multi_phy_config, phy_sel);
}

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC
lm_status_t lm_set_phy_priority_mode(lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t        i         = 0;

    if (CHK_NULL(pdev))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    switch (pdev->params.phy_priority_mode)
    {
    case PHY_PRIORITY_MODE_HW_DEF:
        RESET_FLAGS( pdev->params.link.multi_phy_config, PORT_HW_CFG_PHY_SELECTION_MASK );
        SET_FLAGS( pdev->params.link.multi_phy_config, pdev->hw_info.multi_phy_config);
        break;

    case PHY_PRIORITY_MODE_10GBASET:
        i = ELINK_EXT_PHY1;
        while (i < ELINK_MAX_PHYS)
        {
            if (pdev->params.link.phy[i].media_type == ELINK_ETH_PHY_BASE_T)
            {
                lm_set_phy_priority_selection(pdev, i);
                break;
                }
            i++;
            }
            break;

    case PHY_PRIORITY_MODE_SERDES:
        i = ELINK_EXT_PHY1;
        while (i < ELINK_MAX_PHYS)
        {
            if ((pdev->params.link.phy[i].media_type == ELINK_ETH_PHY_SFPP_10G_FIBER) ||
                (pdev->params.link.phy[i].media_type == ELINK_ETH_PHY_SFP_1G_FIBER)   ||
                (pdev->params.link.phy[i].media_type == ELINK_ETH_PHY_XFP_FIBER)      ||
                (pdev->params.link.phy[i].media_type == ELINK_ETH_PHY_DA_TWINAX)      ||
                (pdev->params.link.phy[i].media_type == ELINK_ETH_PHY_NOT_PRESENT))
            {
                lm_set_phy_priority_selection(pdev, i);
                break;
            }
            i++;
        }
        break;

    case PHY_PRIORITY_MODE_HW_PIN:
        RESET_FLAGS( pdev->params.link.multi_phy_config, PORT_HW_CFG_PHY_SELECTION_MASK );
        SET_FLAGS( pdev->params.link.multi_phy_config, PORT_HW_CFG_PHY_SELECTION_HARDWARE_DEFAULT);
        break;

    default:
        DbgBreak();
        lm_status = LM_STATUS_FAILURE;
        break;
    }

    return lm_status;
}

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC
lm_status_t lm_set_phy_link_params(lm_device_t     *pdev,
                                 lm_medium_t        req_medium,
                                 lm_flow_control_t  flow_control,
                                 u8_t               sw_config,
                                 u8_t               phy_num)
{
    lm_medium_t speed  = GET_MEDIUM_SPEED(req_medium);
    lm_medium_t duplex = GET_MEDIUM_DUPLEX(req_medium);

    DbgMessage(pdev, WARN, "lm_set_phy_link_params: speed 0x%x\n",speed);
    // Get speed from shared memory not registry - if mcp is detected...
    if(pdev->hw_info.mcp_detected && ((speed == LM_MEDIUM_SPEED_HARDWARE_DEFAULT) || (IS_MULTI_VNIC(pdev))))
    {
        DbgMessage(pdev, WARN, "lm_init_phy: pdev->hw_info.link_config[phy_num] = 0x%x\n",pdev->hw_info.link_config[phy_num]);
        switch(pdev->hw_info.link_config[phy_num] & PORT_FEATURE_LINK_SPEED_MASK)
        {

        case PORT_FEATURE_LINK_SPEED_10M_FULL:
            SET_MEDIUM_SPEED(speed,LM_MEDIUM_SPEED_10MBPS);
            SET_MEDIUM_DUPLEX(duplex,LM_MEDIUM_FULL_DUPLEX);
            break;
        case PORT_FEATURE_LINK_SPEED_10M_HALF:
            SET_MEDIUM_SPEED(speed,LM_MEDIUM_SPEED_10MBPS);
            SET_MEDIUM_DUPLEX(duplex,LM_MEDIUM_HALF_DUPLEX);
            break;
        case PORT_FEATURE_LINK_SPEED_100M_FULL:
            SET_MEDIUM_SPEED(speed,LM_MEDIUM_SPEED_100MBPS);
            SET_MEDIUM_DUPLEX(duplex,LM_MEDIUM_FULL_DUPLEX);
            break;
        case PORT_FEATURE_LINK_SPEED_100M_HALF:
            SET_MEDIUM_SPEED(speed,LM_MEDIUM_SPEED_100MBPS);
            SET_MEDIUM_DUPLEX(duplex,LM_MEDIUM_HALF_DUPLEX);
            break;
        case PORT_FEATURE_LINK_SPEED_1G:
            SET_MEDIUM_SPEED(speed,LM_MEDIUM_SPEED_1000MBPS);
            SET_MEDIUM_DUPLEX(duplex,LM_MEDIUM_FULL_DUPLEX);
            break;
        case PORT_FEATURE_LINK_SPEED_2_5G:
            SET_MEDIUM_SPEED(speed,LM_MEDIUM_SPEED_2500MBPS);
            SET_MEDIUM_DUPLEX(duplex,LM_MEDIUM_FULL_DUPLEX);
            break;
        case PORT_FEATURE_LINK_SPEED_10G_CX4:
            SET_MEDIUM_SPEED(speed,LM_MEDIUM_SPEED_10GBPS);
            SET_MEDIUM_DUPLEX(duplex,LM_MEDIUM_FULL_DUPLEX);
            break;
    case PORT_FEATURE_LINK_SPEED_20G:
        SET_MEDIUM_SPEED(speed,LM_MEDIUM_SPEED_20GBPS);
            SET_MEDIUM_DUPLEX(duplex,LM_MEDIUM_FULL_DUPLEX);
            break;
        case PORT_FEATURE_LINK_SPEED_AUTO:
            SET_MEDIUM_SPEED(speed,LM_MEDIUM_SPEED_AUTONEG);
            SET_MEDIUM_DUPLEX(duplex,LM_MEDIUM_FULL_DUPLEX);
            break;
        default:
            //Follow Teton solution:We need to do this because Microsoft's definition
            // is not complete, like speed 2.5gb or some other speeds.
            SET_MEDIUM_SPEED(speed,LM_MEDIUM_SPEED_AUTONEG);
            SET_MEDIUM_DUPLEX(duplex,LM_MEDIUM_FULL_DUPLEX);
            break;
        }

        DbgMessage(pdev, WARN, "lm_set_phy_link_params: speed 0x%x duplex 0x%x\n",speed,duplex);
    }
    pdev->params.link.req_duplex[phy_num] = DUPLEX_FULL;
    if ( duplex == LM_MEDIUM_HALF_DUPLEX)
    {
        pdev->params.link.req_duplex[phy_num] = DUPLEX_HALF;
    }

    switch (speed)
    {
    case  LM_MEDIUM_SPEED_AUTONEG:
        pdev->params.link.req_line_speed[phy_num] = ELINK_SPEED_AUTO_NEG;
        break;
    case  LM_MEDIUM_SPEED_10MBPS:
        pdev->params.link.req_line_speed[phy_num] = ELINK_SPEED_10;
        break;
    case  LM_MEDIUM_SPEED_100MBPS:
        pdev->params.link.req_line_speed[phy_num] = ELINK_SPEED_100;
        break;
    case  LM_MEDIUM_SPEED_1000MBPS:
        pdev->params.link.req_line_speed[phy_num] = ELINK_SPEED_1000;
        break;
    case  LM_MEDIUM_SPEED_2500MBPS:
        pdev->params.link.req_line_speed[phy_num] = ELINK_SPEED_2500;
        break;
    case  LM_MEDIUM_SPEED_10GBPS:
        pdev->params.link.req_line_speed[phy_num] = ELINK_SPEED_10000;
        break;
    case  LM_MEDIUM_SPEED_20GBPS:
        pdev->params.link.req_line_speed[phy_num] = ELINK_SPEED_20000;
        break;
    default:
        DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
        return LM_STATUS_INVALID_PARAMETER;
    }

    pdev->params.link.req_flow_ctrl[phy_num] = 0;
    if (flow_control == LM_FLOW_CONTROL_NONE)
    {
        pdev->params.link.req_flow_ctrl[phy_num] = ELINK_FLOW_CTRL_NONE;
    }
    else if (flow_control & LM_FLOW_CONTROL_AUTO_PAUSE)
    {
        pdev->params.link.req_flow_ctrl[phy_num] = ELINK_FLOW_CTRL_AUTO;
    }
    else
    {
        /* Under flow control reporting mode we */
        if ((speed == LM_MEDIUM_SPEED_AUTONEG) &&
            (pdev->params.flow_control_reporting_mode == LM_FLOW_CONTROL_REPORTING_MODE_ENABLED))
        {
            pdev->params.link.req_flow_ctrl[phy_num] = ELINK_FLOW_CTRL_AUTO;
        }
        else
        {
            if (flow_control & LM_FLOW_CONTROL_RECEIVE_PAUSE)
            {
                pdev->params.link.req_flow_ctrl[phy_num] |= ELINK_FLOW_CTRL_RX;
            }
            if (flow_control & LM_FLOW_CONTROL_TRANSMIT_PAUSE)
            {
                pdev->params.link.req_flow_ctrl[phy_num] |= ELINK_FLOW_CTRL_TX;
            }
        }
    }

    return LM_STATUS_SUCCESS;
}

/**
 * @Description
 *      this function sets the flow control auto negotiation
 *      advertise parameter.
 *
 * @param pdev
 * @param flow_control
 */
void lm_set_fc_auto_adv_params(lm_device_t * pdev, lm_flow_control_t flow_control)
{
    u16_t req_fc_auto_adv     = ELINK_FLOW_CTRL_BOTH;
    u8_t  mtu_above_thr       = FALSE;
    u8_t  report_mode_tx_only = FALSE;

    /* There are two cases where we will set flow control auto adv to TX only.
     * 1. Has to do with a bug in E1/E1x in which we can't support rx flow control if mtu is larger than
     *    a certain threshold. (mtu_above_th)
     * 2. cq CQ57772, required only under special registry key, in which we want the flow control displayed
     *    in gui (i.e. received by ioctl) to show the resolved flow control (after auto negotiation) and not
     *    the requested flow control (in case forced force control is used). For this purpose, if we're in auto-neg
     *    and a forced flow control was requested, we set the request flow control to auto (later on in set_link_parameters)
     *    if forced TX is requested, we se the adv to tx only..(report_mode_tx_only)
     */
    mtu_above_thr       = CHIP_IS_E1x(pdev) && !IS_MULTI_VNIC(pdev) && (pdev->params.mtu_max > LM_MTU_FLOW_CTRL_TX_THR);
    report_mode_tx_only = (pdev->params.flow_control_reporting_mode == LM_FLOW_CONTROL_REPORTING_MODE_ENABLED) &&
                          (flow_control == LM_FLOW_CONTROL_TRANSMIT_PAUSE);

    if (mtu_above_thr || report_mode_tx_only)
    {
        req_fc_auto_adv = ELINK_FLOW_CTRL_TX;
    }

    pdev->params.link.req_fc_auto_adv = req_fc_auto_adv;
}
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_init_phy( lm_device_t       *pdev,
             lm_medium_t       req_medium,
             lm_flow_control_t flow_control,
             u32_t             selective_autoneg,
             u32_t             wire_speed,
             u32_t             wait_link_timeout_us)
{
    u8_t                   i                    = 0;
    u8_t                   sw_config            = 0;
    u8_t                   elink_status         = ELINK_STATUS_OK;
    lm_medium_t            speed                = 0;
    lm_medium_t            type                 = GET_MEDIUM_TYPE(req_medium);
    struct elink_params    *link                = &pdev->params.link;
    lm_status_t            lm_status            = LM_STATUS_SUCCESS;
    iscsi_info_block_hdr_t iscsi_info_block_hdr = {0} ;

    UNREFERENCED_PARAMETER_(wait_link_timeout_us);
    UNREFERENCED_PARAMETER_(wire_speed);
    UNREFERENCED_PARAMETER_(selective_autoneg);

    if (IS_VFDEV(pdev))
    {
        return LM_STATUS_SUCCESS;
    }

    //fill clc params
    if CHK_NULL( pdev )
    {
        DbgBreakIf(!pdev) ;
        return LM_STATUS_FAILURE;
    }

    // override preemphasis for specific svid/ssid
    if( 0x1120 == pdev->hw_info.svid )
    {
        switch (pdev->hw_info.ssid)
        {
        case 0x4f70:
        case 0x4375:
            {
                if( pdev->params.preemphasis_enable )
                {
                    // The relevant ssids are from SINGLE_MEDIA board type, so only EXT_PHY1 needs to be set.
                    SET_FLAGS(pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_OVERRIDE_PREEMPHASIS_ENABLED);
                    pdev->params.link.phy[ELINK_EXT_PHY1].rx_preemphasis[0] = (u16_t)pdev->params.preemphasis_rx_0;
                    pdev->params.link.phy[ELINK_EXT_PHY1].rx_preemphasis[1] = (u16_t)pdev->params.preemphasis_rx_1;
                    pdev->params.link.phy[ELINK_EXT_PHY1].rx_preemphasis[2] = (u16_t)pdev->params.preemphasis_rx_2;
                    pdev->params.link.phy[ELINK_EXT_PHY1].rx_preemphasis[3] = (u16_t)pdev->params.preemphasis_rx_3;
                    pdev->params.link.phy[ELINK_EXT_PHY1].tx_preemphasis[0] = (u16_t)pdev->params.preemphasis_tx_0;
                    pdev->params.link.phy[ELINK_EXT_PHY1].tx_preemphasis[1] = (u16_t)pdev->params.preemphasis_tx_1;
                    pdev->params.link.phy[ELINK_EXT_PHY1].tx_preemphasis[2] = (u16_t)pdev->params.preemphasis_tx_2;
                    pdev->params.link.phy[ELINK_EXT_PHY1].tx_preemphasis[3] = (u16_t)pdev->params.preemphasis_tx_3;
                }
            }
            break;

        default:
            break;
        }
    }

    /* Set req_fc_auto_adv */
    lm_set_fc_auto_adv_params(pdev, flow_control);

    for (i = 0 ; i < 6 ; i++)
    {
        pdev->params.link.mac_addr[i] = pdev->params.mac_addr[i];
    }

    sw_config = (u8_t)pdev->params.sw_config;
    DbgMessage(pdev, WARN, "lm_init_phy: sw_config 0x%x\n",sw_config);

    if (LM_SWCFG_HW_DEF == sw_config )
    {
        if (CHIP_IS_E1x(pdev) || CHIP_IS_E2(pdev))
        {
            sw_config = (u8_t)(pdev->params.link.switch_cfg>>PORT_FEATURE_CONNECTED_SWITCH_SHIFT);
        }
        else
        {
            sw_config = LM_SWCFG_10G;
        }
        DbgMessage(pdev, WARN, "lm_init_phy: sw_config 0x%x\n",sw_config);
    }

#ifndef EDIAG

    switch( pdev->params.autogreeen )
    {
        case LM_AUTOGREEEN_NVRAM:

            // Use whatever is configured in the NVRAM
            break;

        case LM_AUTOGREEEN_DISABLED:

            RESET_FLAGS(pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_AUTOGREEEN_ENABLED );

            RESET_FLAGS(pdev->params.link.eee_mode, // no EEE
                        ELINK_EEE_MODE_ENABLE_LPI |
                        ELINK_EEE_MODE_ADV_LPI);

            break;

        case LM_AUTOGREEEN_ENABLED:

            SET_FLAGS(pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_AUTOGREEEN_ENABLED );

            RESET_FLAGS(pdev->params.link.eee_mode, ELINK_EEE_MODE_OVERRIDE_NVRAM);
            RESET_FLAGS(pdev->params.link.eee_mode, ELINK_EEE_MODE_NVRAM_MASK);

            switch (pdev->params.eee_policy)
            {
                case LM_EEE_CONTROL_HIGH: // enable EEE mode, advertise "AGGRESSIVE" (Registry: MaxPowerSave)

                    SET_FLAGS(pdev->params.link.eee_mode,
                              ELINK_EEE_MODE_OVERRIDE_NVRAM |
                              ELINK_EEE_MODE_ADV_LPI |
                              ELINK_EEE_MODE_ENABLE_LPI |
                              PORT_FEAT_CFG_EEE_POWER_MODE_AGGRESSIVE );
                    break;

                case LM_EEE_CONTROL_MED: // enable EEE mode, advertise "BALANCED" (Registry: Balance)

                    SET_FLAGS(pdev->params.link.eee_mode,
                              ELINK_EEE_MODE_OVERRIDE_NVRAM |
                              ELINK_EEE_MODE_ADV_LPI |
                              ELINK_EEE_MODE_ENABLE_LPI |
                              PORT_FEAT_CFG_EEE_POWER_MODE_BALANCED);
                    break;

                case LM_EEE_CONTROL_LOW: // enable EEE mode, advertise "LOW_LATENCY" (Registry: MaxPerformace)

                    SET_FLAGS(pdev->params.link.eee_mode,
                              ELINK_EEE_MODE_OVERRIDE_NVRAM |
                              ELINK_EEE_MODE_ADV_LPI |
                              ELINK_EEE_MODE_ENABLE_LPI |
                              PORT_FEAT_CFG_EEE_POWER_MODE_LOW_LATENCY);
                    break;

                case LM_EEE_CONTROL_NVRAM: // use NVRAM value

                    SET_FLAGS(pdev->params.link.eee_mode,
                              ELINK_EEE_MODE_ENABLE_LPI |
                              ELINK_EEE_MODE_ADV_LPI);
                    break;

                default:

                    // break here if illegal value was read from registry (CHK version only).
                    DbgBreakIf(1);

                    break;
            }

            break;

        default:

            DbgBreakIf(1); // unknown value
    }

    DbgMessage(pdev, WARN, "lm_init_phy: autogreeen 0x%x\n", pdev->params.autogreeen);
#endif

    switch (sw_config)
    {
        // TODO change to shmem defines
        case LM_SWCFG_1G:
            SET_MEDIUM_TYPE(pdev->vars.medium, LM_MEDIUM_TYPE_SERDES);
            break;
        case LM_SWCFG_10G:
            SET_MEDIUM_TYPE(pdev->vars.medium, LM_MEDIUM_TYPE_XGXS);
            break;
        default:
            DbgBreakIf(1);
            break;
    }
    // Override setting if dual media and phy type specified from miniport
    if ((ELINK_DUAL_MEDIA(link)) &&
        ((type == LM_MEDIUM_TYPE_SERDES) ||
         (type == LM_MEDIUM_TYPE_XGXS)))
    {
        SET_MEDIUM_TYPE(pdev->vars.medium, type);
    }

    lm_status = lm_set_phy_link_params(pdev, req_medium, flow_control, sw_config, ELINK_INT_PHY);
    if (LM_STATUS_SUCCESS == lm_status) {
    if (ELINK_DUAL_MEDIA(link))
    {
        lm_set_phy_link_params(pdev, req_medium, flow_control, sw_config, ELINK_EXT_PHY1);
    }
    } else {
        return lm_status;
    }

    /* If 10G is requested and it is blocked on this KR, issue event log */
    if( pdev->hw_info.no_10g_kr )
    {
        speed = GET_MEDIUM_SPEED(req_medium);
        if( LM_MEDIUM_SPEED_10GBPS == speed )
        {
            DbgMessage(pdev, WARN, "lm_init_phy: 10gb speed parameter is blocked 0x%x\n",speed);

            // block this request (elink does not support it) & log
            mm_event_log_generic(pdev, LM_LOG_ID_NO_10G_SUPPORT, PORT_ID(pdev) );
            return LM_STATUS_SUCCESS;
        }
    }

    switch (type)
    {
    case LM_MEDIUM_TYPE_XGXS_LOOPBACK:
        pdev->params.link.loopback_mode = ELINK_LOOPBACK_XGXS;
        pdev->params.link.req_line_speed[0] = ELINK_SPEED_1000;
        break;
    case LM_MEDIUM_TYPE_XGXS_10_LOOPBACK:
        pdev->params.link.loopback_mode = ELINK_LOOPBACK_XGXS;
        // for bacs PHY loopback test set speed to 10G.
        // Otherwise do not overwrite the speed        
        if (!pdev->params.link.req_line_speed[0]) 
        {
             if (pdev->params.link.speed_cap_mask[0] & PORT_HW_CFG_SPEED_CAPABILITY2_D0_20G)
             {
                 pdev->params.link.req_line_speed[0] = ELINK_SPEED_20000;
             }
             else
             {
                 pdev->params.link.req_line_speed[0] = ELINK_SPEED_10000;
             }
        }
        break;
    case LM_MEDIUM_TYPE_EMAC_LOOPBACK:
        pdev->params.link.loopback_mode = ELINK_LOOPBACK_EMAC;
        break;
    case LM_MEDIUM_TYPE_BMAC_LOOPBACK:
        pdev->params.link.loopback_mode = ELINK_LOOPBACK_BMAC;
        break;
    case LM_MEDIUM_TYPE_EXT_PHY_LOOPBACK:
        pdev->params.link.loopback_mode = ELINK_LOOPBACK_EXT_PHY;
        if (pdev->params.link.speed_cap_mask[0] & PORT_HW_CFG_SPEED_CAPABILITY2_D0_20G)
        {
            pdev->params.link.req_line_speed[0] = ELINK_SPEED_20000;
        }
        else if (pdev->params.link.speed_cap_mask[0] & PORT_HW_CFG_SPEED_CAPABILITY2_D0_10G)
        {
            pdev->params.link.req_line_speed[0] = ELINK_SPEED_10000;
        }
        else
        {
            pdev->params.link.req_line_speed[0] = ELINK_SPEED_1000;
        }
        // TBD: Dual Media ext PHY loopback test for second ext PHY ?
        break;
    case LM_MEDIUM_TYPE_EXT_LOOPBACK:
        pdev->params.link.loopback_mode = ELINK_LOOPBACK_EXT;
        break;
    case LM_MEDIUM_TYPE_XMAC_LOOPBACK:
        pdev->params.link.loopback_mode = ELINK_LOOPBACK_XMAC;
        break;
    case LM_MEDIUM_TYPE_UMAC_LOOPBACK:
        pdev->params.link.loopback_mode = ELINK_LOOPBACK_UMAC;
        break;
    default:
        pdev->params.link.loopback_mode = ELINK_LOOPBACK_NONE;
        break;
    }

    // Handle dual media boards, if phy type specified from miniport
    if (ELINK_DUAL_MEDIA(link))
    {
        switch (type)
        {
        case LM_MEDIUM_TYPE_SERDES:
            i = ELINK_EXT_PHY1;
            while (i < ELINK_MAX_PHYS)
            {
                if ((pdev->params.link.phy[i].media_type == ELINK_ETH_PHY_SFPP_10G_FIBER) ||
                    (pdev->params.link.phy[i].media_type == ELINK_ETH_PHY_SFP_1G_FIBER) ||
                    (pdev->params.link.phy[i].media_type == ELINK_ETH_PHY_XFP_FIBER) ||
                    (pdev->params.link.phy[i].media_type == ELINK_ETH_PHY_DA_TWINAX))
                {
                    lm_set_phy_selection(pdev, i);
                    break;
                }
                i++;
            }
            break;

        case LM_MEDIUM_TYPE_XGXS:
            i = ELINK_EXT_PHY1;
            while (i < ELINK_MAX_PHYS)
            {
                if ((pdev->params.link.phy[i].media_type == ELINK_ETH_PHY_BASE_T))
                {
                    lm_set_phy_selection(pdev, i);
                    break;
                }
                i++;
            }
            break;

        case LM_MEDIUM_AUTO_DETECT:
            lm_set_phy_priority_mode(pdev);
            break;

        case LM_MEDIUM_TYPE_XGXS_LOOPBACK:
        case LM_MEDIUM_TYPE_XGXS_10_LOOPBACK:
        case LM_MEDIUM_TYPE_EMAC_LOOPBACK:
        case LM_MEDIUM_TYPE_BMAC_LOOPBACK:
        case LM_MEDIUM_TYPE_EXT_PHY_LOOPBACK:
        case LM_MEDIUM_TYPE_EXT_LOOPBACK:
        case LM_MEDIUM_TYPE_XMAC_LOOPBACK:
        case LM_MEDIUM_TYPE_UMAC_LOOPBACK:
            // Do nothing.
            break;
        default:
            DbgBreak();
            break;
        }
    }

    DbgMessage(pdev, WARN, "lm_init_phy: loopback_mode 0x%x\n",pdev->params.link.loopback_mode);
    if (IS_PMF(pdev))
    {
        if( pdev->params.i2c_interval_sec )
        {
            pdev->params.i2c_elink_status[I2C_SECTION_A0] = ELINK_STATUS_INVALID_IMAGE;
            pdev->params.i2c_elink_status[I2C_SECTION_A2] = ELINK_STATUS_INVALID_IMAGE;
        }
        if (lm_get_iscsi_boot_info_block(pdev,&iscsi_info_block_hdr) == LM_STATUS_SUCCESS)
        {
           if (iscsi_info_block_hdr.boot_flags & BOOT_INFO_FLAGS_UEFI_BOOT)
           {
              SET_FLAGS(pdev->params.link.feature_config_flags,ELINK_FEATURE_CONFIG_BOOT_FROM_SAN);
           }
        }

        PHY_HW_LOCK(pdev);
        elink_status = elink_phy_init(&pdev->params.link,&pdev->vars.link);
        PHY_HW_UNLOCK(pdev);
    }
    else
    {
        elink_link_status_update(&pdev->params.link,&pdev->vars.link);
    }
    // Emulation FPGA or LOOPBACK non pmf in multi vnic mode link might be up now
    lm_link_report(pdev);
    return LM_STATUS_SUCCESS;
} /* lm_init_phy */


#ifndef EDIAG
/*
 * \brief query i2c information if exists and write it to 3rd party known place
 *
 * \param pdev
 *
 * \return lm_status_t
 *
 */
lm_status_t lm_link_i2c_update(struct _lm_device_t *pdev)
{
    elink_status_t elink_status      = ELINK_STATUS_ERROR;
    u8_t           ext_phy_type   = 0;
    lm_status_t    lm_status      = LM_STATUS_SUCCESS;   
    const u64_t    current_ts     = mm_query_system_time(); // get current system time ms
    const u64_t    current_ms     = current_ts/10000; // get current system time ms
    const u64_t    interval_ms    = pdev->params.i2c_interval_sec*1000;
    const u64_t    delta_ms       = current_ms - (pdev->i2c_binary_info.last_query_ts/10000);
    const u8_t     b_need_refresh = ( interval_ms > 0 ) && ( delta_ms > interval_ms );
    u8_t           sff8472_comp   = 0;
    u8_t           diag_type      = 0;

    DbgBreakIf(!IS_PMF(pdev));

    if( !b_need_refresh )
    {
        // that means we need nothing here...
        return lm_status;
    }

    // Check which PHY controls the SFP+ module
    for( ext_phy_type = ELINK_EXT_PHY1; ext_phy_type < pdev->params.link.num_phys; ext_phy_type++ )
    {
        if(( ELINK_ETH_PHY_SFPP_10G_FIBER == pdev->params.link.phy[ext_phy_type].media_type )||
           ( ELINK_ETH_PHY_SFP_1G_FIBER   == pdev->params.link.phy[ext_phy_type].media_type )||
           ( ELINK_ETH_PHY_DA_TWINAX      == pdev->params.link.phy[ext_phy_type].media_type ))
            {
                pdev->i2c_binary_info.last_query_ts = current_ts;

                // Capture A0 section + static part of A2 section only once if A2 is supportd
                if (( pdev->params.i2c_elink_status[I2C_SECTION_A0] != ELINK_STATUS_OK) ||
                    ((pdev->params.i2c_elink_status[I2C_SECTION_A2] != ELINK_STATUS_OK) &&
                     (pdev->params.i2c_elink_status[I2C_SECTION_A2] != ELINK_OP_NOT_SUPPORTED)))
                {
                    PHY_HW_LOCK(pdev);
                    elink_status = elink_read_sfp_module_eeprom( &pdev->params.link.phy[ext_phy_type], // ELINK_INT_PHY, ELINK_EXT_PHY1, ELINK_EXT_PHY2
                                                              &pdev->params.link,
                                                              ELINK_I2C_DEV_ADDR_A0,
                                                              0,
                                                              I2C_BINARY_SIZE,
                                                              pdev->i2c_binary_info.ax_data[I2C_SECTION_A0] ) ;

                    pdev->params.i2c_elink_status[I2C_SECTION_A0] = elink_status;

                    if (pdev->params.i2c_elink_status[I2C_SECTION_A0] != ELINK_STATUS_OK)
                    {
                        PHY_HW_UNLOCK(pdev);

                        // Set same status to A2 section and quit as A0 is mandatory
                        pdev->params.i2c_elink_status[I2C_SECTION_A2] = elink_status;
                        break; // Quit the loop
                    }

                    // Check if the module is compliant with SFF8472, meaning it supports A2 section.
                    sff8472_comp = pdev->i2c_binary_info.ax_data[I2C_SECTION_A0][ELINK_SFP_EEPROM_SFF_8472_COMP_ADDR];
                    diag_type    = pdev->i2c_binary_info.ax_data[I2C_SECTION_A0][ELINK_SFP_EEPROM_DIAG_TYPE_ADDR];

                    if ( (!sff8472_comp) ||
                         ( diag_type & ELINK_SFP_EEPROM_DIAG_ADDR_CHANGE_REQ) )
                    {
                        // Release the HW LOCK
                        PHY_HW_UNLOCK(pdev);

                        // Set A2 section query status to NOT SUPPORTED and quit
                        pdev->params.i2c_elink_status[I2C_SECTION_A2] = ELINK_OP_NOT_SUPPORTED;

                        // Exit loop
                        break;
                    }

                    elink_status = elink_read_sfp_module_eeprom( &pdev->params.link.phy[ext_phy_type], // ELINK_INT_PHY, ELINK_EXT_PHY1, ELINK_EXT_PHY2
                                                                 &pdev->params.link,
                                                                 ELINK_I2C_DEV_ADDR_A2,
                                                                 I2C_A2_STATIC_OFFSET,
                                                                 I2C_A2_STATIC_SIZE,
                                                                 &pdev->i2c_binary_info.ax_data[I2C_SECTION_A2][I2C_A2_STATIC_OFFSET] ) ;
                    PHY_HW_UNLOCK(pdev);

                    pdev->params.i2c_elink_status[I2C_SECTION_A2] = elink_status;

                    if (pdev->params.i2c_elink_status[I2C_SECTION_A2] != ELINK_STATUS_OK)
                    {                        
                        break; // no use continue if we didn't get A2 data
                    }
                } // !ELINK_STATUS_OK

                /* Avoid reading A2 section if the module doesn't support SFF8472. */
                if (pdev->params.i2c_elink_status[I2C_SECTION_A2] == ELINK_OP_NOT_SUPPORTED)
                {
                    break;
                }

                // Capture the dynamic part of A2
                PHY_HW_LOCK(pdev);

                elink_status = elink_read_sfp_module_eeprom( &pdev->params.link.phy[ext_phy_type], // ELINK_INT_PHY, ELINK_EXT_PHY1, ELINK_EXT_PHY2
                                                          &pdev->params.link,
                                                          ELINK_I2C_DEV_ADDR_A2,
                                                          I2C_A2_DYNAMIC_OFFSET,
                                                          I2C_A2_DYNAMIC_SIZE,
                                                          &pdev->i2c_binary_info.ax_data[I2C_SECTION_A2][I2C_A2_DYNAMIC_OFFSET] );

                PHY_HW_UNLOCK(pdev);

                // Calculate and validate I2C section checksum
                if( ELINK_STATUS_OK == elink_status )
                {
                    elink_status = elink_validate_cc_dmi(pdev->i2c_binary_info.ax_data[I2C_SECTION_A2]);
                    if( ELINK_STATUS_OK != elink_status )
                    {
                        pdev->params.i2c_elink_status[I2C_SECTION_A2] = ELINK_STATUS_INVALID_IMAGE;
                    }
                }
                // only one sfp+ module is expected on board so we exit the ext_phy_type loop
                break;
        } // if( ELINK_ETH_PHY_SFPP_10G_FIBER == ...
    } // for "ext_phy_type"

    // it means that there is a need to write otherwise we even didn't enter the loop
    // so the registry write is redundent.
    if ( current_ts == pdev->i2c_binary_info.last_query_ts )
    {
        lm_status = mm_i2c_update(pdev);
    }
    return lm_status;
} /* lm_link_i2c_update */
#endif

/**
 * @Description
 *     This function is called periodically, every time the link
 *     timer expires, it's main purpose is to call elink under
 *     appropriate locks to perform any periodic tasks
 * @assumptions:
 *     called under UM_PHY_LOCK!
 *
 * @param pdev
 *
 * @return lm_status_t
 */
lm_status_t lm_link_on_timer(struct _lm_device_t *pdev)
{
    if (CHIP_REV_IS_SLOW(pdev))
    {
        return LM_STATUS_SUCCESS;
    }

    if (IS_PMF(pdev))
    {
        PHY_HW_LOCK(pdev);

        elink_period_func(&pdev->params.link, &pdev->vars.link);

        PHY_HW_UNLOCK(pdev);

#ifndef EDIAG
        lm_link_i2c_update(pdev);
#endif
    }

    return LM_STATUS_SUCCESS;
}
/*
 *Function Name:lm_get_external_phy_fw_version
 *
 *Parameters:
 *
 *Description:
 *  Funciton should be called under PHY_LOCK
 *Returns:
 *
 */
lm_status_t
lm_get_external_phy_fw_version( lm_device_t *pdev,
                                u8_t *      sz_version,
                                u8_t        len )
{
    u8_t        elink_status = ELINK_STATUS_OK;

    if ( CHK_NULL( sz_version ) || CHK_NULL( pdev ) )
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    // reset the returned value to zero
    *sz_version = '\0';

    elink_status = elink_get_ext_phy_fw_version(&pdev->params.link, (u8_t *)sz_version, len );

    if (elink_status == ELINK_STATUS_OK)
    {
        // Update internal hw_info structure for debugging purpose
        if( len <= sizeof(pdev->hw_info.sz_ext_phy_fw_ver) )
        {
            mm_memcpy( pdev->hw_info.sz_ext_phy_fw_ver,
                       sz_version,
                       min( (u32_t)sizeof(pdev->hw_info.sz_ext_phy_fw_ver), (u32_t)len) ) ;
        }
        return LM_STATUS_SUCCESS ;
    }
    else
    {
        return LM_STATUS_FAILURE;
    }
}

/*
 *Function Name:lm_update_external_phy_fw_prepare
 *
 *Parameters:
 *
 *Description:
 *
 *Returns:
 *
 */
lm_status_t
lm_update_external_phy_fw_prepare( lm_device_t *pdev )
{
    u8_t        elink_status = ELINK_STATUS_OK;
    lm_status_t lm_status  = LM_STATUS_SUCCESS;

    MM_ACQUIRE_PHY_LOCK(pdev);

    PHY_HW_LOCK(pdev);

    do
    {
        u32_t shmem_base[MAX_PATH_NUM], shmem_base2[MAX_PATH_NUM];
        shmem_base[0] = pdev->hw_info.shmem_base;
        shmem_base2[0] = pdev->hw_info.shmem_base2;

        if (!CHIP_IS_E1x(pdev))
        {
            LM_SHMEM2_READ(pdev, OFFSETOF(shmem2_region_t,other_shmem_base_addr), &shmem_base[1]);
            LM_SHMEM2_READ(pdev, OFFSETOF(shmem2_region_t,other_shmem2_base_addr), &shmem_base2[1]);
        }

        elink_common_init_phy(pdev, shmem_base, shmem_base2, CHIP_ID(pdev), 0);
        elink_pre_init_phy(pdev, shmem_base[0], shmem_base2[0], CHIP_ID(pdev), 0);

        if( ELINK_STATUS_OK != elink_status )
        {
            break;
        }

        elink_status = elink_phy_init(&pdev->params.link,&pdev->vars.link);
        if( ELINK_STATUS_OK != elink_status )
        {
            break;
        }

        elink_status = elink_link_reset(&pdev->params.link,&pdev->vars.link,0);

    } while(0);

    PHY_HW_UNLOCK(pdev);

    lm_link_report(pdev);

    MM_RELEASE_PHY_LOCK(pdev);

    if( ELINK_STATUS_OK != elink_status )
    {
        goto _exit;
    }

    switch( pdev->params.link.phy[ELINK_EXT_PHY1].type )
    {
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_SFX7101:
        {
            lm_gpio_write(pdev, MISC_REGISTERS_GPIO_0, MISC_REGISTERS_GPIO_HIGH, PORT_ID(pdev) );
        }
        break;
    default:
        break;
    }

_exit:

    ELINK_STATUS_TO_LM_STATUS( elink_status, lm_status );

    return lm_status;
}

/*
 *Function Name:lm_update_external_phy_fw_reinit
 *
 *Parameters:
 *
 *Description:
 *
 *Returns:
 *
 */
lm_status_t
lm_update_external_phy_fw_reinit( lm_device_t *pdev )
{
    lm_status_t lm_status  = LM_STATUS_SUCCESS;
    u8_t        elink_status = ELINK_STATUS_OK;

    MM_ACQUIRE_PHY_LOCK(pdev);

    lm_reset_link(pdev);

    PHY_HW_LOCK(pdev);
    elink_status = elink_phy_init(&pdev->params.link,&pdev->vars.link);
    PHY_HW_UNLOCK(pdev);

    DbgBreakIf(ELINK_STATUS_OK != elink_status);

    // Emulation FPGA or LOOPBACK non pmf in multi vnic mode link might be up now
    lm_link_report(pdev);

    ELINK_STATUS_TO_LM_STATUS( elink_status, lm_status );

    if( LM_STATUS_SUCCESS == lm_status )
    {
        // in case success -reset version
        pdev->hw_info.sz_ext_phy_fw_ver[0] = '\0';
    }

    MM_RELEASE_PHY_LOCK(pdev);

    return lm_status;
}

/*
 *Function Name:lm_update_external_phy_fw_done
 *
 *Parameters:
 *
 *Description:
 *
 *Returns:
 *
 */
lm_status_t
lm_update_external_phy_fw_done( lm_device_t *pdev )
{
    lm_status_t lm_status    = LM_STATUS_SUCCESS;
    u8_t        ext_phy_addr = 0;
    u8_t        b_exit       = FALSE;

    MM_ACQUIRE_PHY_LOCK(pdev);
    switch( pdev->params.link.phy[ELINK_EXT_PHY1].type )
    {
    case PORT_HW_CFG_XGXS_EXT_PHY_TYPE_SFX7101:
        break;
    default:
        b_exit = TRUE;
        break;
    }
    if( b_exit )
    {
        MM_RELEASE_PHY_LOCK(pdev);
        return lm_status ;
    }

    ext_phy_addr = pdev->params.link.phy[ELINK_EXT_PHY1].addr;

    /* DSP Remove Download Mode */
    lm_gpio_write(pdev, MISC_REGISTERS_GPIO_0, MISC_REGISTERS_GPIO_LOW, PORT_ID(pdev) );

    PHY_HW_LOCK(pdev);
    elink_sfx7101_sp_sw_reset(pdev, &pdev->params.link.phy[ELINK_EXT_PHY1] );
    /* wait 0.5 sec to allow it to run */
    mm_wait( pdev, 500000);
    elink_ext_phy_hw_reset( pdev, PORT_ID(pdev) );
    mm_wait(pdev, 500000);
    PHY_HW_UNLOCK(pdev);

    MM_RELEASE_PHY_LOCK(pdev);

    return lm_status;
}

lm_status_t lm_check_phy_link_params(lm_device_t *pdev, lm_medium_t req_medium)
{
    lm_medium_t speed = GET_MEDIUM_SPEED(req_medium);
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    if (IS_VFDEV(pdev))
    {
        return LM_STATUS_SUCCESS;
    }

    DbgMessage(pdev, WARN, "lm_check_phy_link_params: speed 0x%x\n",speed);
    // Get speed from registry not shared memory  - if mcp is not detected...
    if(!pdev->hw_info.mcp_detected || ((speed != LM_MEDIUM_SPEED_HARDWARE_DEFAULT) && (!IS_MULTI_VNIC(pdev))))
    {
        switch (speed)
        {
        case  LM_MEDIUM_SPEED_AUTONEG:
        case  LM_MEDIUM_SPEED_10MBPS:
        case  LM_MEDIUM_SPEED_100MBPS:
        case  LM_MEDIUM_SPEED_1000MBPS:
        case  LM_MEDIUM_SPEED_2500MBPS:
        case  LM_MEDIUM_SPEED_10GBPS:
        case  LM_MEDIUM_SPEED_20GBPS:
            break;
        default:
            DbgMessage(pdev, FATAL, "lm_check_phy_link_params: abnormal speed parameter 0x%x.\n",speed);
            lm_status = LM_STATUS_INVALID_PARAMETER;
        }
    }
    return lm_status;
}

