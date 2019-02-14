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

#include "lm5706.h"



/*******************************************************************************
 * Description:
 * 
 * Return:
 ******************************************************************************/
lm_status_t
lm_set_mac_addr(
    lm_device_t *pdev,
    u32_t addr_idx,
    u8_t *mac_addr) 
{
    u32_t val;

    if(addr_idx >= 16)
    {
        DbgBreakMsg("Invalid mac address index.\n");

        return LM_STATUS_FAILURE;
    }

    val = (mac_addr[0]<<8) | mac_addr[1];
    REG_WR(pdev, emac.emac_mac_match[addr_idx*2], val);

    val = (mac_addr[2]<<24) | (mac_addr[3]<<16) | 
        (mac_addr[4]<<8) | mac_addr[5];
    REG_WR(pdev, emac.emac_mac_match[addr_idx*2+1], val);

    return LM_STATUS_SUCCESS;
} /* lm_set_mac_addr */



/*******************************************************************************
 * Description:
 *
 * Return:
 *    None.
 *
 * Note:
 *    The caller is responsible for synchronizing calls to lm_reg_rd_ind and 
 *    lm_reg_wr_ind.
 ******************************************************************************/
void
lm_reg_rd_ind(
    lm_device_t *pdev,
    u32_t offset,
    u32_t *ret)
{
    /* DbgBreakIf(offset & 0x3); // this can occur for some shmem accesses */

    mm_acquire_ind_reg_lock(pdev);

    REG_WR(pdev, pci_config.pcicfg_reg_window_address, offset);
    REG_RD(pdev, pci_config.pcicfg_reg_window, ret);

    mm_release_ind_reg_lock(pdev);
} /* lm_reg_rd_ind */



/*******************************************************************************
 * Description:
 *
 * Return:
 *    None.
 *
 * Note:
 *    The caller is responsible for synchronizing calls to lm_reg_rd_ind and 
 *    lm_reg_wr_ind.
 ******************************************************************************/
void
lm_reg_wr_ind(
    lm_device_t *pdev,
    u32_t offset,
    u32_t val)
{
    DbgBreakIf(offset & 0x3);

    mm_acquire_ind_reg_lock(pdev);

    REG_WR(pdev, pci_config.pcicfg_reg_window_address, offset);
    REG_WR(pdev, pci_config.pcicfg_reg_window, val);

    mm_release_ind_reg_lock(pdev);
} /* lm_reg_wr_ind */



/*******************************************************************************
 * Description:
 * 
 * Return:
 ******************************************************************************/
void
lm_ctx_wr(
    lm_device_t *pdev,
    u32_t cid_addr,
    u32_t offset,
    u32_t val)
{
    u32_t retry_cnt;
    u32_t idx;

    DbgBreakIf(cid_addr > MAX_CID_ADDR || offset & 0x3 || cid_addr & CTX_MASK);

    offset += cid_addr;

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        if (CHIP_REV(pdev) == CHIP_REV_IKOS)
        {
            retry_cnt = 2000;
        }
        else
        {
            retry_cnt = 250;
        }

        REG_WR(pdev, context.ctx_ctx_data, val);
        REG_WR(pdev, context.ctx_ctx_ctrl, offset | CTX_CTX_CTRL_WRITE_REQ);

        for(idx=0; idx < retry_cnt; idx++)
        {
            REG_RD(pdev, context.ctx_ctx_ctrl, &val);

            if((val & CTX_CTX_CTRL_WRITE_REQ) == 0)
            {
                break;
            }

            mm_wait(pdev, 10);
        }

        DbgBreakIf(idx == retry_cnt);
    }
    else
    {
        REG_WR(pdev, context.ctx_data_adr, offset);
        REG_WR(pdev, context.ctx_data, val);
    }
} /* lm_ctx_wr */



/*******************************************************************************
 * Description:
 * 
 * Return:
 ******************************************************************************/
u32_t
lm_ctx_rd(
    lm_device_t *pdev,
    u32_t cid_addr,
    u32_t offset)
{
    u32_t retry_cnt;
    u32_t val;
    u32_t idx;

    DbgBreakIf(cid_addr > MAX_CID_ADDR || offset & 0x3 || cid_addr & CTX_MASK);

    offset += cid_addr;

    if(CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        if(CHIP_REV(pdev) == CHIP_REV_IKOS)
        {
            retry_cnt = 1000;
        }
        else
        {
            retry_cnt = 25;
        }

        REG_WR(pdev, context.ctx_ctx_ctrl, offset | CTX_CTX_CTRL_READ_REQ);

        for(idx = 0; idx < retry_cnt; idx++)
        {
            REG_RD(pdev, context.ctx_ctx_ctrl, &val);

            if((val & CTX_CTX_CTRL_READ_REQ) == 0)
            {
                break;
            }

            mm_wait(pdev, 5);
        }

        DbgBreakIf(idx == retry_cnt);

        REG_RD(pdev, context.ctx_ctx_data, &val);
    }
    else
    {
        REG_WR(pdev, context.ctx_data_adr, offset);
        REG_RD(pdev, context.ctx_data, &val);
    }

    return val;
} /* lm_ctx_rd */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_disable_int(
    lm_device_t *pdev)
{
    u32_t sb_idx;
    u32_t val;

    switch(CHIP_NUM(pdev))
    {
        case CHIP_NUM_5706:
        case CHIP_NUM_5708:
            REG_RD(pdev, pci_config.pcicfg_int_ack_cmd, &val);
            val |= PCICFG_INT_ACK_CMD_MASK_INT;
            REG_WR(pdev, pci_config.pcicfg_int_ack_cmd, val);
            break;

        case CHIP_NUM_5709:
            for(sb_idx = 0; sb_idx < 9; sb_idx++)
            {
                val = PCICFG_INT_ACK_CMD_MASK_INT | (sb_idx << 24);
                REG_WR(pdev, pci_config.pcicfg_int_ack_cmd, val);
            }
            break;

        default:
            DbgBreakMsg("Unsupported chip.\n");
            break;
    }
} /* lm_disable_int */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_enable_int(
    lm_device_t *pdev)
{
    u32_t val;

    switch(CHIP_NUM(pdev))
    {
        case CHIP_NUM_5706:
        case CHIP_NUM_5708:
            REG_RD(pdev, pci_config.pcicfg_int_ack_cmd, &val);
            val &= ~PCICFG_INT_ACK_CMD_MASK_INT;
            REG_WR(pdev, pci_config.pcicfg_int_ack_cmd, val);
            break;

        case CHIP_NUM_5709:
            REG_RD(pdev, hc.hc_config, &val);
            val |= HC_CONFIG_UNMASK_ALL;
            REG_WR(pdev, hc.hc_config, val);
            break;

        default:
            DbgBreakMsg("Unsupported chip.\n");
            break;
    }
} /* lm_enable_int */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_reg_rd_blk(
    lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *buf_ptr,
    u32_t u32t_cnt)
{
    u32_t grc_win_offset;
    u32_t grc_win_base;

    DbgBreakIf(reg_offset & 0x3);

    grc_win_offset = reg_offset & (GRC_WINDOW_SIZE - 1);
    grc_win_base = reg_offset & ~(GRC_WINDOW_SIZE - 1);

    REG_WR(pdev, pci.pci_grc_window_addr, grc_win_base);

    while(u32t_cnt)
    {
        if(grc_win_offset >= GRC_WINDOW_SIZE)
        {
            grc_win_offset = 0;
            grc_win_base += GRC_WINDOW_SIZE;

            REG_WR(pdev, pci.pci_grc_window_addr, grc_win_base);
        }

        REG_RD_OFFSET(pdev, GRC_WINDOW_BASE + grc_win_offset, buf_ptr);

        buf_ptr++;
        u32t_cnt--;
        grc_win_offset += 4;
    }

    REG_WR(pdev, pci.pci_grc_window_addr, pdev->hw_info.shmem_base & ~0x7fff);
} /* lm_reg_rd_blk */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_reg_rd_blk_ind(
    lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *buf_ptr,
    u32_t u32t_cnt)
{
    DbgBreakIf(reg_offset & 0x3);

    mm_acquire_ind_reg_lock(pdev);

    while(u32t_cnt)
    {
        REG_WR(pdev, pci_config.pcicfg_reg_window_address, reg_offset);
        REG_RD(pdev, pci_config.pcicfg_reg_window, buf_ptr);

        buf_ptr++;
        u32t_cnt--;
        reg_offset += 4;
    }

    mm_release_ind_reg_lock(pdev);
} /* lm_reg_rd_blk_ind */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_reg_wr_blk(
    lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *data_ptr,
    u32_t u32t_cnt)
{
    u32_t grc_win_offset;
    u32_t grc_win_base;
    u32_t grc_win_size;

    DbgBreakIf(reg_offset & 0x3);

    if (CHIP_NUM(pdev) == CHIP_NUM_5709)
    {
        grc_win_size = GRC_WINDOW_SIZE / 4;
    }
    else
    {
        grc_win_size = GRC_WINDOW_SIZE;
    }

    grc_win_offset = reg_offset & (grc_win_size - 1);
    grc_win_base = reg_offset & ~(grc_win_size - 1);

    REG_WR(pdev, pci.pci_grc_window_addr, grc_win_base);

    while(u32t_cnt)
    {
        if(grc_win_offset >= grc_win_size)
        {
            grc_win_offset = 0;
            grc_win_base += grc_win_size;

            REG_WR(pdev, pci.pci_grc_window_addr, grc_win_base);
        }

        REG_WR_OFFSET(pdev, GRC_WINDOW_BASE + grc_win_offset, *data_ptr);

        data_ptr++;
        u32t_cnt--;
        grc_win_offset += 4;
    }

    REG_WR(pdev, pci.pci_grc_window_addr, pdev->hw_info.shmem_base & ~0x7fff);
} /* lm_reg_wr_blk */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_reg_wr_blk_ind(
    lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *data_ptr,
    u32_t u32t_cnt)
{
    DbgBreakIf(reg_offset & 0x3);

    mm_acquire_ind_reg_lock(pdev);

    while(u32t_cnt)
    {
        REG_WR(pdev, pci_config.pcicfg_reg_window_address, reg_offset);
        REG_WR(pdev, pci_config.pcicfg_reg_window, *data_ptr);

        data_ptr++;
        u32t_cnt--;
        reg_offset += 4;
    }

    mm_release_ind_reg_lock(pdev);
} /* lm_reg_wr_blk_ind */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_submit_fw_cmd(
    lm_device_t *pdev,
    u32_t drv_msg)
{
    u32_t val;

    if(pdev->vars.fw_timed_out)
    {
        DbgMessage(pdev, WARN, "fw timed out.\n");

        return LM_STATUS_FAILURE;
    }

    DbgBreakIf(drv_msg & 0xffff);

    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base + OFFSETOF(shmem_region_t, drv_fw_mb.fw_mb),
        &val);
    if((val & FW_MSG_ACK) != (pdev->vars.fw_wr_seq & DRV_MSG_SEQ))
    {
        DbgMessage(pdev, WARN, "command pending.\n");
        
        return LM_STATUS_FAILURE;
    }

    pdev->vars.fw_wr_seq++;

    drv_msg |= (pdev->vars.fw_wr_seq & DRV_MSG_SEQ);

    REG_WR_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, drv_fw_mb.drv_mb),
        drv_msg);

    return LM_STATUS_SUCCESS;
} /* lm_submit_fw_cmd */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_last_fw_cmd_status(
    lm_device_t *pdev)
{
    u32_t val;

    if(pdev->vars.fw_timed_out)
    {
        DbgMessage(pdev, WARN, "fw timed out.\n");

        return LM_STATUS_TIMEOUT;
    }

    REG_RD_IND(
        pdev,
        pdev->hw_info.shmem_base +
            OFFSETOF(shmem_region_t, drv_fw_mb.fw_mb),
        &val);
    if((val & FW_MSG_ACK) != (pdev->vars.fw_wr_seq & DRV_MSG_SEQ))
    {
        return LM_STATUS_BUSY;
    }

    if((val & FW_MSG_STATUS_MASK) != FW_MSG_STATUS_OK)
    {
        return LM_STATUS_FAILURE;
    }

    return LM_STATUS_SUCCESS;
} /* lm_last_fw_cmd_status */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u32_t
lm_mb_get_cid_addr(
    lm_device_t *pdev,
    u32_t cid)
{
    u32_t mq_offset;

    DbgBreakIf(pdev->params.bin_mq_mode && CHIP_NUM(pdev) != CHIP_NUM_5709);

    if(cid < 256 || pdev->params.bin_mq_mode == FALSE)
    {
        mq_offset = 0x10000 + (cid << MB_KERNEL_CTX_SHIFT);
    }
    else
    {
        DbgBreakIf(cid < pdev->hw_info.first_l4_l5_bin);

        mq_offset = 0x10000 + 
                    ((((cid - pdev->hw_info.first_l4_l5_bin) /
                    pdev->hw_info.bin_size) + 256) << MB_KERNEL_CTX_SHIFT);
    }

    DbgBreakIf(mq_offset > pdev->hw_info.bar_size);

    return mq_offset;
} /* lm_mb_get_cid_addr */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u32_t
lm_mb_get_bypass_addr(
    lm_device_t *pdev,
    u32_t cid)
{
    u32_t mq_offset;

    DbgBreakIf(pdev->params.bin_mq_mode && CHIP_NUM(pdev) != CHIP_NUM_5709);

    if(cid < 256 || pdev->params.bin_mq_mode == FALSE)
    {
        mq_offset = 0x10000 + 
                    MB_KERNEL_CTX_SIZE * MAX_CID_CNT +
                    cid * LM_PAGE_SIZE;
    }
    else
    {
        DbgBreakIf(cid < pdev->hw_info.first_l4_l5_bin);

        mq_offset = 0x10000 + 
                    MB_KERNEL_CTX_SIZE * MAX_CID_CNT +
                    (((cid - pdev->hw_info.first_l4_l5_bin) /
                    pdev->hw_info.bin_size) + 256) * LM_PAGE_SIZE;
    }

    DbgBreakIf(mq_offset > pdev->hw_info.bar_size);

    return mq_offset;
} /* lm_mb_get_bypass_addr */

