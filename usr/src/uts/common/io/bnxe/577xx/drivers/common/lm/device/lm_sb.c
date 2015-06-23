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
 *      This file contains functions that handle IGU access and SB management
 *
 ******************************************************************************/

#include "lm5710.h"
#include "577xx_int_offsets.h"
#include "bcmtype.h"

/* Reads IGU interrupt status register MSB / LSB */
static u32_t lm_read_isr32 (
    lm_device_t *pdev,
    u32_t addr)
{
    u32 offset = IS_PFDEV(pdev) ? BAR_IGU_INTMEM : VF_BAR0_IGU_OFFSET;
    u32_t res = 0;
    u32_t value;
    do {
        /* Read the 32 bit value from BAR */
        LM_BAR_RD32_OFFSET(pdev,BAR_0,offset + addr, &value);
        DbgMessage(pdev, VERBOSEi, "  ### lm_read_isr32 read address 0x%x value=0x%x\n",addr,value);
        DbgBreakIf(value == 0xffffffff);
        res |= value;
        /* Do one more iteration if we got the value for a legitimate "all ones" */
    } while (value == 0xefffffff);
    return res;
}

/* Reads IGU interrupt status register MSB / LSB */
static u64_t lm_read_isr64(
    lm_device_t *pdev,
    u32_t addr)
{
    u32 offset = IS_PFDEV(pdev) ? BAR_IGU_INTMEM : VF_BAR0_IGU_OFFSET;
    u64_t res = 0;
    u64_t value;
    do {
        /* Read the 32 bit value from BAR */
        LM_BAR_RD64_OFFSET(pdev,BAR_0, offset + addr,&value);
        DbgMessage(pdev, FATAL, "  ### lm_read_isr64 read address 0x%x value=0x%x 0x%x\n",addr,(u32_t)(value>>32),(u32_t)value);
        DbgBreakIf(value == 0xffffffffffffffffULL);
        res |= value;
        /* Do one more iteration if we got the value for a legitimate "all ones" */
    } while (value == 0xefffffffffffffffULL);
    DbgMessage(pdev, FATAL, "  ### lm_read_isr64 res=0x%x 0x%x\n",(u32_t)(res>>32),(u32_t)res);
    return res;
}

u64_t lm_igutest_get_isr32(struct _lm_device_t *pdev)
{
    u64_t intr_status = 0;
    intr_status = ((u64_t)lm_read_isr32(pdev,8 * IGU_REG_SISR_MDPC_WMASK_MSB_UPPER) << 32) |
        lm_read_isr32(pdev,8 * IGU_REG_SISR_MDPC_WMASK_LSB_UPPER);
    return intr_status;
}

u64_t
lm_igutest_get_isr64(struct _lm_device_t *pdev)
{
    return lm_read_isr64(pdev,8 * IGU_REG_SISR_MDPC_WMASK_UPPER);
}

lm_interrupt_status_t
lm_get_interrupt_status_wo_mask(
    lm_device_t *pdev)
{
    lm_interrupt_status_t intr_status = 0;
    if (INTR_BLK_REQUIRE_CMD_CTRL(pdev)) {
        /* This is IGU GRC Access... need to write ctrl and then read data */
        REG_WR(pdev, IGU_REG_COMMAND_REG_CTRL, INTR_BLK_CMD_CTRL_RD_WOMASK(pdev));
    }
    intr_status = REG_RD(pdev, INTR_BLK_SIMD_ADDR_WOMASK(pdev));
    /* if above, need to read 64 bits from IGU...and take care of all-ones */
    ASSERT_STATIC(MAX_RSS_CHAINS <= 32);
    return intr_status;
}

lm_interrupt_status_t
lm_get_interrupt_status(
    lm_device_t *pdev)
{
    lm_interrupt_status_t intr_status = 0;

    if (INTR_BLK_REQUIRE_CMD_CTRL(pdev)) {
        /* This is IGU GRC Access... need to write ctrl and then read data */
        REG_WR(pdev, IGU_REG_COMMAND_REG_CTRL, INTR_BLK_CMD_CTRL_RD_WMASK(pdev));
    }
    intr_status = REG_RD(pdev, INTR_BLK_SIMD_ADDR_WMASK(pdev));
    /* if above, need to read 64 bits from IGU...and take care of all-ones */
    ASSERT_STATIC(MAX_RSS_CHAINS <= 32);
    return intr_status;
} /* lm_get_interrupt_status */

lm_status_t lm_set_interrupt_moderation(struct _lm_device_t *pdev, u8_t is_enable)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t            sb_id      = 0 ;

    pdev->params.int_coalesing_mode_disabled_by_ndis = !is_enable;
    if (pdev->params.int_coalesing_mode == LM_INT_COAL_NONE) {
        DbgMessage(pdev, WARN, "HC is not supported (disabled) in driver\n");
        return LM_STATUS_SUCCESS;
    }
    if (IS_PFDEV(pdev)) 
    {
        LM_FOREACH_SB_ID(pdev, sb_id)
        {
            if ((lm_status = lm_set_hc_flag(pdev, sb_id, HC_INDEX_TOE_RX_CQ_CONS, is_enable)) != LM_STATUS_SUCCESS)
                break;
            if ((lm_status = lm_set_hc_flag(pdev, sb_id, HC_INDEX_TOE_TX_CQ_CONS, is_enable)) != LM_STATUS_SUCCESS)
                break;
            if ((lm_status = lm_set_hc_flag(pdev, sb_id, HC_INDEX_ETH_RX_CQ_CONS, is_enable)) != LM_STATUS_SUCCESS)
                break;
            if ((lm_status = lm_set_hc_flag(pdev, sb_id, HC_INDEX_ETH_TX_CQ_CONS_COS0, is_enable)) != LM_STATUS_SUCCESS)
                break;
            if ((lm_status = lm_set_hc_flag(pdev, sb_id, HC_INDEX_ETH_TX_CQ_CONS_COS1, is_enable)) != LM_STATUS_SUCCESS)
                break;
            if ((lm_status = lm_set_hc_flag(pdev, sb_id, HC_INDEX_ETH_TX_CQ_CONS_COS2, is_enable)) != LM_STATUS_SUCCESS)
                break;
    
        }
    }

    return lm_status;
}

void lm_set_igu_tmode(struct _lm_device_t *pdev, u8_t tmode)
{
    pdev->vars.is_igu_test_mode = tmode;
}

u8_t lm_get_igu_tmode(struct _lm_device_t *pdev)
{
    return pdev->vars.is_igu_test_mode;
}

void lm_set_interrupt_mode(struct _lm_device_t *pdev, u32_t mode)
{
    DbgBreakIf(mode > LM_INT_MODE_MIMD);
    pdev->params.interrupt_mode = mode;
}

u32_t lm_get_interrupt_mode(struct _lm_device_t *pdev)
{
    return pdev->params.interrupt_mode;
}

u8_t lm_get_num_fp_msix_messages(struct _lm_device_t *pdev)
{
    if (INTR_BLK_TYPE(pdev) == INTR_BLK_IGU) {
        if (pdev->vars.is_igu_test_mode) {
            DbgMessage(pdev, FATAL, "IGU test mode: returned %d fp-messages\n", pdev->hw_info.intr_blk_info.igu_info.igu_test_sb_cnt + pdev->hw_info.intr_blk_info.igu_info.igu_sb_cnt);
            return (pdev->hw_info.intr_blk_info.igu_info.igu_test_sb_cnt + pdev->hw_info.intr_blk_info.igu_info.igu_sb_cnt);
        }
        return pdev->hw_info.intr_blk_info.igu_info.igu_sb_cnt;
    } else {
        return pdev->params.sb_cnt;
    }
}

u8_t lm_get_base_msix_msg(struct _lm_device_t *pdev)
{
    if (IS_PFDEV(pdev)) {
        return 1;
    } else {
        return 0;
    }
}

u8_t lm_has_sp_msix_vector(struct _lm_device_t *pdev)
{
    if (IS_PFDEV(pdev)) {
        return TRUE;
    } else {
        return FALSE;
    }
}

lm_status_t lm_set_hc_flag(struct _lm_device_t *pdev, u8_t sb_id, u8_t idx, u8_t is_enable)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    struct hc_index_data * hc_index_entry;
    u8_t fw_sb_id;
    u8_t notify_fw = FALSE;

    if (CHIP_IS_E1x(pdev)) {
        hc_index_entry = pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data.index_data + idx;
    } else {
        hc_index_entry = pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.index_data + idx;
    }
    if (pdev->params.int_coalesing_mode == LM_INT_COAL_PERIODIC_SYNC) {
        if (is_enable) {
            if (!(hc_index_entry->flags & HC_INDEX_DATA_HC_ENABLED) && hc_index_entry->timeout) {
                hc_index_entry->flags |= HC_INDEX_DATA_HC_ENABLED;
                notify_fw = TRUE;
            }
        } else {
            if (hc_index_entry->flags & HC_INDEX_DATA_HC_ENABLED) {
                hc_index_entry->flags &= ~HC_INDEX_DATA_HC_ENABLED;
                notify_fw = TRUE;
            }
        }
    }
    if (notify_fw) {
        fw_sb_id = LM_FW_SB_ID(pdev, sb_id);
        if (CHIP_IS_E1x(pdev)) {
            LM_INTMEM_WRITE8(PFDEV(pdev), (CSTORM_STATUS_BLOCK_DATA_OFFSET(fw_sb_id)
                                           + OFFSETOF(struct hc_status_block_data_e1x, index_data)
                                           + sizeof(struct hc_index_data)*idx
                                           + OFFSETOF(struct hc_index_data,flags)),
                                           hc_index_entry->flags, BAR_CSTRORM_INTMEM);
        } else {
            LM_INTMEM_WRITE8(PFDEV(pdev), (CSTORM_STATUS_BLOCK_DATA_OFFSET(fw_sb_id)
                                           + OFFSETOF(struct hc_status_block_data_e2, index_data)
                                           + sizeof(struct hc_index_data)*idx
                                           + OFFSETOF(struct hc_index_data,flags)),
                                           hc_index_entry->flags, BAR_CSTRORM_INTMEM);

        }
        DbgMessage(pdev, INFORMi, "HC set to %d for SB%d(index%d)\n",is_enable,sb_id,idx);
    } else {
        DbgMessage(pdev, INFORMi, "HC already set to %d for SB%d(index%d)\n",is_enable,sb_id,idx);
    }

    return lm_status;
}

void lm_update_def_hc_indices(lm_device_t *pdev, u8_t dummy_sb_id, u32_t *activity_flg)
{
    volatile struct hc_sp_status_block * sp_sb          = NULL;
    volatile struct atten_sp_status_block * attn_sb = NULL;
    u16_t                             atomic_index   = 0;

    *activity_flg = 0;

    DbgBreakIf(!pdev);


    //It's a default status block

        DbgMessage(pdev, INFORMi, "BEFORE update: hc_def_ack:%d, attn_def_ack:%d\n",
            pdev->vars.hc_def_ack,
            pdev->vars.attn_def_ack);

    sp_sb = lm_get_default_status_block(pdev);

    atomic_index = mm_le16_to_cpu(sp_sb->running_index);
    if (atomic_index != pdev->vars.hc_def_ack)
    {
        pdev->vars.hc_def_ack = atomic_index;
        (*activity_flg) |= LM_SP_ACTIVE;
    }


    attn_sb = lm_get_attention_status_block(pdev);

    atomic_index = mm_le16_to_cpu(attn_sb->attn_bits_index);
    if (atomic_index != pdev->vars.attn_def_ack)
    {
        pdev->vars.attn_def_ack = atomic_index;
        (*activity_flg) |= LM_DEF_ATTN_ACTIVE;
    }

    DbgMessage(pdev, INFORMi, "AFTER update: hc_def_ack:%d, attn_def_ack:%d\n",
        pdev->vars.hc_def_ack,
        pdev->vars.attn_def_ack);
}

void lm_update_fp_hc_indices(lm_device_t *pdev, u8_t igu_sb_id, u32_t *activity_flg, u8_t *drv_rss_id)
{
    u16_t                                   atomic_index   = 0;
    u8_t flags;
    u8_t drv_sb_id;

    *activity_flg = 0;
    drv_sb_id = igu_sb_id;

    DbgBreakIf(!(pdev && (drv_sb_id <= ARRSIZE(pdev->vars.status_blocks_arr))));
    DbgMessage(pdev, INFORMi, "lm_update_hc_indices: inside with sb_idx:%d\n", drv_sb_id);

    DbgBreakIf(!LM_SB_ID_VALID(pdev, drv_sb_id));


    flags = lm_query_storm_intr(pdev, igu_sb_id, &drv_sb_id);

    DbgMessage(pdev, INFORMi, "BEFORE update: c_hc_ack:%d\n", pdev->vars.c_hc_ack[drv_sb_id]);
    DbgMessage(pdev, INFORMi, "BEFORE update: u_hc_ack:%d\n", pdev->vars.u_hc_ack[drv_sb_id]);

    if (GET_FLAGS(flags, CSTORM_INTR_FLAG)) {
        atomic_index = lm_get_sb_running_index(pdev, drv_sb_id, SM_TX_ID);

        if (atomic_index != pdev->vars.c_hc_ack[drv_sb_id])
        {
            pdev->vars.c_hc_ack[drv_sb_id] = atomic_index;
            (*activity_flg) |= LM_NON_DEF_CSTORM_ACTIVE;
        }
    }

    if (GET_FLAGS(flags, USTORM_INTR_FLAG)) {
        atomic_index = lm_get_sb_running_index(pdev, drv_sb_id, SM_RX_ID);

        if (atomic_index != pdev->vars.u_hc_ack[drv_sb_id])
        {
            pdev->vars.u_hc_ack[drv_sb_id] = atomic_index;
            (*activity_flg) |= LM_NON_DEF_USTORM_ACTIVE;
            if ((pdev->params.ndsb_type == LM_SINGLE_SM) || (pdev->params.ndsb_type == LM_DOUBLE_SM_SINGLE_IGU)) {
                (*activity_flg) |= LM_NON_DEF_CSTORM_ACTIVE;
            }
        }
    }


    DbgMessage(pdev, INFORMi, "AFTER update: c_hc_ack:%d\n", pdev->vars.c_hc_ack[drv_sb_id]);
    DbgMessage(pdev, INFORMi, "AFTER update: u_hc_ack:%d\n", pdev->vars.u_hc_ack[drv_sb_id]);

    /* Fixme - doesn't have to be... */
    *drv_rss_id = drv_sb_id;
}

u8_t lm_is_def_sb_updated(lm_device_t *pdev)
{
    volatile struct hc_sp_status_block * sp_sb                = NULL;
    volatile struct atten_sp_status_block * attn_sb           = NULL;
    u8_t result                                            = FALSE;
    u16_t hw_sb_idx                                        = 0;

    DbgBreakIfFastPath(!pdev);
    if (!pdev || IS_VFDEV(pdev))
    {
        return FALSE;
    }

    DbgMessage(pdev, INFORMi, "lm_is_def_sb_updated() inside!\n");

    sp_sb = lm_get_default_status_block(pdev);
    //it is legit that only a subgroup of the storms may change between our local copy.
    //at least one storm index change implies that we have work to do on this sb
    hw_sb_idx = mm_le16_to_cpu(sp_sb->running_index);
    if (hw_sb_idx != pdev->vars.hc_def_ack)
    {
        DbgMessage(pdev, INFORMi, "lm_is_sb_updated: sp running_index:%d, hc_def_ack:%d\n",
                    hw_sb_idx, pdev->vars.hc_def_ack);

        result     = TRUE;
    }

    attn_sb = lm_get_attention_status_block(pdev);
    hw_sb_idx = mm_le16_to_cpu(attn_sb->attn_bits_index);
    if (hw_sb_idx != pdev->vars.attn_def_ack)
    {
        DbgMessage(pdev, INFORMi, "lm_is_sb_updated: def.attn_bits_index:%d attn_def_ack:%d\n",
                    hw_sb_idx, pdev->vars.attn_def_ack);

        result = TRUE;
    }

    DbgMessage(pdev, INFORMi, "lm_is_def_sb_updated:  result:%s\n", result? "TRUE" : "FALSE");

    return result;
}




u8_t lm_handle_igu_sb_id(lm_device_t *pdev, u8_t igu_sb_id, u8_t *rx_rss_id, u8_t *tx_rss_id)
{
    u16_t atomic_index = 0;
    u8_t  drv_sb_id = 0;
    u8_t  flags = 0;
    u8_t  drv_rss_id = 0;

    drv_sb_id = igu_sb_id;

    if ((INTR_BLK_TYPE(pdev) == INTR_BLK_HC) || (IGU_U_NDSB_OFFSET(pdev) == 0)) {
        /* One Segment Per u/c */
        SET_FLAGS(flags, USTORM_INTR_FLAG);
        SET_FLAGS(flags, CSTORM_INTR_FLAG);
    } else {
        if (drv_sb_id >= IGU_U_NDSB_OFFSET(pdev)) {
            drv_sb_id -= IGU_U_NDSB_OFFSET(pdev);
            SET_FLAGS(flags, USTORM_INTR_FLAG);
            //DbgMessage(pdev, FATAL, "Ustorm drv_sb_id=%d\n", drv_sb_id);
        } else {
            SET_FLAGS(flags, CSTORM_INTR_FLAG);
            //DbgMessage(pdev, FATAL, "Cstorm drv_sb_id=%d\n", drv_sb_id);
        }
    }

    if (GET_FLAGS(flags, USTORM_INTR_FLAG)) {
        atomic_index = lm_get_sb_running_index(pdev, drv_sb_id, SM_RX_ID);

        if (atomic_index != pdev->vars.u_hc_ack[drv_sb_id]) {
            pdev->vars.u_hc_ack[drv_sb_id] = atomic_index;
        }

        drv_rss_id = drv_sb_id; /* FIXME: doesn't have to be... */
        //Check for Rx completions
        if (lm_is_rx_completion(pdev, drv_rss_id))
        {
            //DbgMessage(pdev, FATAL, "RX_completion=%d\n", drv_rss_id);
            SET_FLAGS(flags, SERV_RX_INTR_FLAG);
        }

#ifdef INCLUDE_L4_SUPPORT
        //Check for L4 Rx completions
        if (lm_toe_is_rx_completion(pdev, drv_rss_id))
        {
            lm_toe_service_rx_intr(pdev, drv_rss_id);
        }
#endif
    }
    if (GET_FLAGS(flags, CSTORM_INTR_FLAG)) {
        if (IGU_U_NDSB_OFFSET(pdev)) {
            atomic_index = lm_get_sb_running_index(pdev, drv_sb_id, SM_TX_ID);

            if (atomic_index != pdev->vars.c_hc_ack[drv_sb_id]) {
                pdev->vars.c_hc_ack[drv_sb_id] = atomic_index;
            }
        }
        drv_rss_id = drv_sb_id; /* FIXME: doesn't have to be... */
        //Check for Tx completions
        if (lm_is_tx_completion(pdev, drv_rss_id))
        {
            //DbgMessage(pdev, FATAL, "TX_completion=%d\n", drv_rss_id);
            SET_FLAGS(flags, SERV_TX_INTR_FLAG);
        }


#ifdef INCLUDE_L4_SUPPORT
        //Check for L4 Tx completions
        if (lm_toe_is_tx_completion(pdev, drv_rss_id))
        {
            lm_toe_service_tx_intr(pdev, drv_rss_id);
        }
#endif
    }
    *rx_rss_id = drv_rss_id;
    *tx_rss_id = drv_rss_id;

    return flags;
}


volatile struct host_hc_status_block_e2 * lm_get_e2_status_block(lm_device_t *pdev, u8_t rss_id)
{
    return pdev->vars.status_blocks_arr[rss_id].host_hc_status_block.e2_sb;
}

volatile struct host_hc_status_block_e1x * lm_get_e1x_status_block(lm_device_t *pdev, u8_t rss_id)
{
    return pdev->vars.status_blocks_arr[rss_id].host_hc_status_block.e1x_sb;
}

volatile struct hc_sp_status_block * lm_get_default_status_block(lm_device_t *pdev)
{
    return &pdev->vars.gen_sp_status_block.hc_sp_status_blk->sp_sb;
}

volatile struct atten_sp_status_block * lm_get_attention_status_block(lm_device_t *pdev)
{
    return &pdev->vars.gen_sp_status_block.hc_sp_status_blk->atten_status_block;
}


void print_sb_info(lm_device_t *pdev)
{
#if 0
    u8_t index                                    = 0;
    volatile struct host_status_block *rss_sb     = NULL;

    DbgBreakIf(!pdev);
    DbgMessage(pdev, INFORMi, "print_sb_info() inside!\n");
    //print info of all non-default status blocks
    for(index=0; index < MAX_RSS_CHAINS; index++)
    {
        rss_sb = lm_get_status_block(pdev, index);

        DbgBreakIf(!rss_sb);
        DbgBreakIf(*(LM_RCQ(pdev, index).
             hw_con_idx_ptr) != rss_sb->u_status_block.index_values[HC_INDEX_U_ETH_RX_CQ_CONS]);
        DbgBreakIf(*(LM_TXQ(pdev, index).hw_con_idx_ptr) != rss_sb->c_status_block.index_values[HC_INDEX_C_ETH_TX_CQ_CONS]);

        DbgMessage(pdev, INFORMi, "rss sb #%d: u_new_cons:%d, c_new_cons:%d, c_status idx:%d, c_sbID:%d, u_status idx:%d, u_sbID:%d\n",
            index,
            rss_sb->u_status_block.index_values[HC_INDEX_U_ETH_RX_CQ_CONS],
            rss_sb->c_status_block.index_values[HC_INDEX_C_ETH_TX_CQ_CONS],
            rss_sb->c_status_block.status_block_index,
            rss_sb->c_status_block.status_block_id,
            rss_sb->u_status_block.status_block_index,
            rss_sb->u_status_block.status_block_id);

        DbgMessage(pdev, INFORMi, "____________________________________________________________\n");
    }
    //print info of the default status block
    DbgBreakIf(pdev->vars.gen_sp_status_block.hc_sp_status_blk == NULL);

    DbgMessage(pdev, INFORMi, "sp sb: c_status idx:%d, c_sbID:%d\n",
        pdev->vars.gen_sp_status_block.hc_sp_status_blk->sp_sb.running_index, pdev->vars.gen_sp_status_block.sb_data.igu_sb_id);

    DbgMessage(pdev, INFORMi, "____________________________________________________________\n");
#endif
}

/**
 * This function sets all the status-block ack values back to
 * zero. Must be called BEFORE initializing the igu + before
 * initializing status-blocks.
 *
 * @param pdev
 */
void lm_reset_sb_ack_values(struct _lm_device_t *pdev)
{
    //re-initialize all the local copy indices of sbs for load/unload scenarios
    pdev->vars.hc_def_ack = 0;

    //init attn state
    pdev->vars.attn_state = 0;

    pdev->vars.attn_def_ack = 0;

    mm_memset(pdev->vars.c_hc_ack, 0, sizeof(pdev->vars.c_hc_ack));
    mm_memset(pdev->vars.u_hc_ack, 0, sizeof(pdev->vars.u_hc_ack));
}

static void init_hc_attn_status_block(struct _lm_device_t *pdev,
                              u8_t  sb_id,
                              lm_address_t *host_sb_addr)
{
    volatile struct atten_sp_status_block * attention_sb = NULL;
    //give the IGU the status block number(ID) of attention bits section.
    DbgBreakIf(!pdev);

    DbgMessage(pdev, INFORMi, "init_status_block: host_sb_addr_low:0x%x; host_sb_addr_low:0x%x\n",
                    host_sb_addr->as_u32.low, host_sb_addr->as_u32.high);
    attention_sb = lm_get_attention_status_block(pdev);
    attention_sb->status_block_id = sb_id;
    //write to IGU the physical address where the attention bits lie
    REG_WR(pdev,  HC_REG_ATTN_MSG0_ADDR_L + 8*PORT_ID(pdev), host_sb_addr->as_u32.low);
    REG_WR(pdev,  HC_REG_ATTN_MSG0_ADDR_H + 8*PORT_ID(pdev), host_sb_addr->as_u32.high);
}

static void init_igu_attn_status_block(
    struct _lm_device_t *pdev,
    lm_address_t *host_sb_addr)
{

    //write to IGU the physical address where the attention bits lie
    REG_WR(pdev,  IGU_REG_ATTN_MSG_ADDR_L, host_sb_addr->as_u32.low);
    REG_WR(pdev,  IGU_REG_ATTN_MSG_ADDR_H, host_sb_addr->as_u32.high);

    DbgMessage(pdev, INFORMi, "init_attn_igu_status_block: host_sb_addr_low:0x%x; host_sb_addr_low:0x%x\n",
                host_sb_addr->as_u32.low, host_sb_addr->as_u32.high);


}


static void init_attn_status_block(struct _lm_device_t *pdev,
                              u8_t  sb_id,
                              lm_address_t *host_sb_addr)
{
    if (INTR_BLK_TYPE(pdev) == INTR_BLK_HC) {
        init_hc_attn_status_block(pdev,sb_id,host_sb_addr);
    } else {
        init_igu_attn_status_block(pdev, host_sb_addr);
    }
}

static void lm_init_sp_status_block(struct _lm_device_t *pdev)
{
    lm_address_t    sb_phy_addr;
    u8_t igu_sp_sb_index; /* igu Status Block constant identifier (0-135) */
    u8_t igu_seg_id;
    u8_t func;
    u8_t i;

    DbgBreakIf(!pdev);
    DbgBreakIf(IS_VFDEV(pdev));

    DbgBreakIf((CSTORM_SP_STATUS_BLOCK_SIZE % 4) != 0);
    DbgBreakIf((CSTORM_SP_STATUS_BLOCK_DATA_SIZE % 4) != 0);
    DbgBreakIf((CSTORM_SP_SYNC_BLOCK_SIZE % 4) != 0);
    func = FUNC_ID(pdev);

    if ((INTR_BLK_TYPE(pdev) == INTR_BLK_IGU) && (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_NORM) ) {
        igu_sp_sb_index = IGU_DSB_ID(pdev);
        igu_seg_id = IGU_SEG_ACCESS_DEF;
    } else {
        igu_sp_sb_index = DEF_STATUS_BLOCK_IGU_INDEX;
        igu_seg_id = HC_SEG_ACCESS_DEF;
    }

    sb_phy_addr = pdev->vars.gen_sp_status_block.blk_phy_address;

    init_attn_status_block(pdev, igu_sp_sb_index, &sb_phy_addr);

    LM_INC64(&sb_phy_addr, OFFSETOF(struct host_sp_status_block, sp_sb));

    /* CQ#46240: Disable the function in the status-block data before nullifying sync-line + status-block */
    LM_INTMEM_WRITE8(pdev, CSTORM_SP_STATUS_BLOCK_DATA_STATE_OFFSET(func),
                     SB_DISABLED, BAR_CSTRORM_INTMEM);

    REG_WR_DMAE_LEN_ZERO(pdev, CSEM_REG_FAST_MEMORY + CSTORM_SP_SYNC_BLOCK_OFFSET(func), CSTORM_SP_SYNC_BLOCK_SIZE/4);
    REG_WR_DMAE_LEN_ZERO(pdev, CSEM_REG_FAST_MEMORY + CSTORM_SP_STATUS_BLOCK_OFFSET(func), CSTORM_SP_STATUS_BLOCK_SIZE/4);


    pdev->vars.gen_sp_status_block.sb_data.host_sb_addr.lo = sb_phy_addr.as_u32.low;
    pdev->vars.gen_sp_status_block.sb_data.host_sb_addr.hi = sb_phy_addr.as_u32.high;
    pdev->vars.gen_sp_status_block.sb_data.igu_sb_id = igu_sp_sb_index;
    pdev->vars.gen_sp_status_block.sb_data.igu_seg_id = igu_seg_id;
    pdev->vars.gen_sp_status_block.sb_data.p_func.pf_id = func;
    pdev->vars.gen_sp_status_block.sb_data.p_func.vnic_id = VNIC_ID(pdev);
    pdev->vars.gen_sp_status_block.sb_data.p_func.vf_id = 0xff;
    pdev->vars.gen_sp_status_block.sb_data.p_func.vf_valid = FALSE;
    pdev->vars.gen_sp_status_block.sb_data.state = SB_ENABLED;

    for (i = 0; i < sizeof(struct hc_sp_status_block_data)/sizeof(u32_t); i++) {
        LM_INTMEM_WRITE32(PFDEV(pdev), CSTORM_SP_STATUS_BLOCK_DATA_OFFSET(func) + i*sizeof(u32_t), *((u32_t*)&pdev->vars.gen_sp_status_block.sb_data + i), BAR_CSTRORM_INTMEM);
    }


}

/* Initalize the whole status blocks per port - overall: 1 defalt sb, 16 non-default sbs
 *
 * Parameters:
 * pdev - the LM device which holds the sbs
 * port - the port number
 */
void init_status_blocks(struct _lm_device_t *pdev)
{
    u8_t                                    sb_id        = 0;
    u8_t                                    port         = PORT_ID(pdev);
    u8_t                                    group_idx;
    DbgMessage(pdev, INFORMi, "init_status_blocks() inside! func:%d\n",FUNC_ID(pdev));
    DbgBreakIf(!pdev);

    pdev->vars.num_attn_sig_regs =
        (CHIP_IS_E1x(pdev))? NUM_ATTN_REGS_E1X : NUM_ATTN_REGS_E2;

    //Read routing configuration for attn signal output of groups. Currently, only group 0,1,2 are wired.
    for (group_idx = 0; group_idx < MAX_DYNAMIC_ATTN_GRPS; group_idx++)
    {

        //group index
        pdev->vars.attn_groups_output[group_idx].attn_sig_dword[0] =
            REG_RD(pdev, (PORT_ID(pdev) ? MISC_REG_AEU_ENABLE1_FUNC_1_OUT_0 : MISC_REG_AEU_ENABLE1_FUNC_0_OUT_0) + group_idx*16);
        pdev->vars.attn_groups_output[group_idx].attn_sig_dword[1] =
            REG_RD(pdev, (PORT_ID(pdev) ? MISC_REG_AEU_ENABLE2_FUNC_1_OUT_0 : MISC_REG_AEU_ENABLE2_FUNC_0_OUT_0) + group_idx*16);
        pdev->vars.attn_groups_output[group_idx].attn_sig_dword[2] =
            REG_RD(pdev, (PORT_ID(pdev) ? MISC_REG_AEU_ENABLE3_FUNC_1_OUT_0 : MISC_REG_AEU_ENABLE3_FUNC_0_OUT_0) + group_idx*16);
        pdev->vars.attn_groups_output[group_idx].attn_sig_dword[3] =
            REG_RD(pdev, (PORT_ID(pdev) ? MISC_REG_AEU_ENABLE4_FUNC_1_OUT_0 : MISC_REG_AEU_ENABLE4_FUNC_0_OUT_0) + group_idx*16);
        if (pdev->vars.num_attn_sig_regs == 5) {
            /* enable5 is separate from the rest of the registers, and therefore the address skip is 4 and not 16 between the different groups */
            pdev->vars.attn_groups_output[group_idx].attn_sig_dword[4] =
                REG_RD(pdev, (PORT_ID(pdev) ? MISC_REG_AEU_ENABLE5_FUNC_1_OUT_0 : MISC_REG_AEU_ENABLE5_FUNC_0_OUT_0) + group_idx*4);
        } else {
            pdev->vars.attn_groups_output[group_idx].attn_sig_dword[4] = 0;
        }

        DbgMessage(pdev, INFORMi, "lm_handle_deassertion_processing: group %d mask1:0x%x, mask2:0x%x, mask3:0x%x, mask4:0x%x, mask5:0x%x\n",
                       group_idx,
                       pdev->vars.attn_groups_output[group_idx].attn_sig_dword[0],
                       pdev->vars.attn_groups_output[group_idx].attn_sig_dword[1],
                       pdev->vars.attn_groups_output[group_idx].attn_sig_dword[2],
                       pdev->vars.attn_groups_output[group_idx].attn_sig_dword[3],
                       pdev->vars.attn_groups_output[group_idx].attn_sig_dword[4]);

    }
    pdev->vars.attn_sig_af_inv_reg_addr[0] =
        PORT_ID(pdev) ? MISC_REG_AEU_AFTER_INVERT_1_FUNC_1 : MISC_REG_AEU_AFTER_INVERT_1_FUNC_0;
    pdev->vars.attn_sig_af_inv_reg_addr[1] =
        PORT_ID(pdev) ? MISC_REG_AEU_AFTER_INVERT_2_FUNC_1 : MISC_REG_AEU_AFTER_INVERT_2_FUNC_0;
    pdev->vars.attn_sig_af_inv_reg_addr[2] =
        PORT_ID(pdev) ? MISC_REG_AEU_AFTER_INVERT_3_FUNC_1 : MISC_REG_AEU_AFTER_INVERT_3_FUNC_0;
    pdev->vars.attn_sig_af_inv_reg_addr[3] =
        PORT_ID(pdev) ? MISC_REG_AEU_AFTER_INVERT_4_FUNC_1 : MISC_REG_AEU_AFTER_INVERT_4_FUNC_0;
    pdev->vars.attn_sig_af_inv_reg_addr[4] =
        PORT_ID(pdev) ? MISC_REG_AEU_AFTER_INVERT_5_FUNC_1 : MISC_REG_AEU_AFTER_INVERT_5_FUNC_0;

    // init the non-default status blocks
    LM_FOREACH_SB_ID(pdev, sb_id)
    {
        lm_init_non_def_status_block(pdev, sb_id, port);
    }

    if (pdev->params.int_coalesing_mode_disabled_by_ndis) {
        lm_set_interrupt_moderation(pdev, FALSE);
    }
    // init the default status block  - composed of 5 parts per storm: Attention bits, Ustorm, Cstorm, Xstorm, Tstorm

    //Init the attention bits part of the default status block
    lm_init_sp_status_block(pdev);
}

/* set interrupt coalesing parameters.
   - these settings are derived from user configured interrupt coalesing mode and tx/rx interrupts rate (lm params).
   - these settings are used for status blocks initialization */
void lm_set_int_coal_info(struct _lm_device_t *pdev)
{
    lm_int_coalesing_info* ic           = &pdev->vars.int_coal;
    u32_t                  rx_coal_usec[HC_USTORM_SB_NUM_INDICES];
    u32_t                  tx_coal_usec[HC_CSTORM_SB_NUM_INDICES];
    u32_t                  i            = 0;

    mm_mem_zero( ic, sizeof(lm_int_coalesing_info) );

    for (i = 0; i < HC_USTORM_SB_NUM_INDICES; i++) {
        rx_coal_usec[i] = 0;
    }

    for (i = 0; i < HC_CSTORM_SB_NUM_INDICES; i++) {
        tx_coal_usec[i] = 0;
    }

    switch (pdev->params.int_coalesing_mode)
    {
    case LM_INT_COAL_PERIODIC_SYNC: /* static periodic sync */
        for (i = 0; i < HC_USTORM_SB_NUM_INDICES; i++) {
            if (pdev->params.int_per_sec_rx_override)
                pdev->params.int_per_sec_rx[i] = pdev->params.int_per_sec_rx_override;

            DbgMessage(pdev, WARN, "##lm_set_int_coal_info: int_per_sec_rx[%d] = %d\n",i,pdev->params.int_per_sec_rx[i]);
            if (pdev->params.int_per_sec_rx[i])
            {
                rx_coal_usec[i] = 1000000 / pdev->params.int_per_sec_rx[i];
            }
            if(rx_coal_usec[i] > 0x3ff)
            {
                rx_coal_usec[i] = 0x3ff; /* min 1k us, i.e. 1k int per sec */
            }
        }

        for (i = 0; i < HC_CSTORM_SB_NUM_INDICES; i++) {
            if (pdev->params.int_per_sec_tx_override)
                pdev->params.int_per_sec_tx[i] = pdev->params.int_per_sec_tx_override;

            DbgMessage(pdev, WARN, "##lm_set_int_coal_info: int_per_sec_tx[%d] = %d\n",i,pdev->params.int_per_sec_tx[i]);

            if (pdev->params.int_per_sec_tx[i])
            {
                tx_coal_usec[i] = 1000000 / pdev->params.int_per_sec_tx[i];
            }
            if(tx_coal_usec[i] > 0x3ff)
            {
                tx_coal_usec[i] = 0x3ff; /* min 1k us, i.e. 1k int per sec */
            }
        }
        break;

    case LM_INT_COAL_NONE: /* this is the default */
    default:
        break;
    }

    /* set hc period for c sb for all indices */
    for (i = 0; i < HC_CSTORM_SB_NUM_INDICES; i++) {
        ic->hc_usec_c_sb[i] = tx_coal_usec[i];
    }
    /* set hc period for u sb for all indices */
    for (i = 0; i < HC_USTORM_SB_NUM_INDICES; i++) {
        ic->hc_usec_u_sb[i] = rx_coal_usec[i];
    }

#if 0
    if (pdev->params.l4_fw_dca_enabled) {
        /* set TOE HC to minimum possible for ustorm */
        ic->hc_usec_u_sb[HC_INDEX_U_TOE_RX_CQ_CONS] = pdev->params.l4_hc_ustorm_thresh;  /* 12usec */
    }
#endif

    /* by default set hc period for x/t/c/u defualt sb to NONE.
      (that was already implicitly done by memset 0 above) */


    /* set dynamic hc params */
    for (i = 0; i < HC_USTORM_SB_NUM_INDICES; i++) {
        ic->eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout0[i] = (u8_t)pdev->params.hc_timeout0[SM_RX_ID][i];
        ic->eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout1[i] = (u8_t)pdev->params.hc_timeout1[SM_RX_ID][i];
        ic->eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout2[i] = (u8_t)pdev->params.hc_timeout2[SM_RX_ID][i];
        ic->eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout3[i] = (u8_t)pdev->params.hc_timeout3[SM_RX_ID][i];
    }
    ic->eth_dynamic_hc_cfg.sm_config[SM_RX_ID].threshold[0] = pdev->params.hc_threshold0[SM_RX_ID];
    ic->eth_dynamic_hc_cfg.sm_config[SM_RX_ID].threshold[1] = pdev->params.hc_threshold1[SM_RX_ID];
    ic->eth_dynamic_hc_cfg.sm_config[SM_RX_ID].threshold[2] = pdev->params.hc_threshold2[SM_RX_ID];

    for (i = 0; i < HC_CSTORM_SB_NUM_INDICES; i++) {
        ic->eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout0[i] = (u8_t)pdev->params.hc_timeout0[SM_TX_ID][i];
        ic->eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout1[i] = (u8_t)pdev->params.hc_timeout1[SM_TX_ID][i];
        ic->eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout2[i] = (u8_t)pdev->params.hc_timeout2[SM_TX_ID][i];
        ic->eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout3[i] = (u8_t)pdev->params.hc_timeout3[SM_TX_ID][i];
    }
    ic->eth_dynamic_hc_cfg.sm_config[SM_TX_ID].threshold[0] = pdev->params.hc_threshold0[SM_TX_ID];
    ic->eth_dynamic_hc_cfg.sm_config[SM_TX_ID].threshold[1] = pdev->params.hc_threshold1[SM_TX_ID];
    ic->eth_dynamic_hc_cfg.sm_config[SM_TX_ID].threshold[2] = pdev->params.hc_threshold2[SM_TX_ID];
}



void lm_setup_ndsb_index(struct _lm_device_t *pdev, u8_t sb_id, u8_t idx, u8_t sm_idx, u8_t timeout, u8_t dhc_enable)
{
    struct hc_index_data * hc_index_entry;
    if (CHIP_IS_E1x(pdev)) {
        hc_index_entry = pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data.index_data + idx;
    } else {
        hc_index_entry = pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.index_data + idx;
    }
    hc_index_entry->timeout = timeout;
    hc_index_entry->flags = (sm_idx << HC_INDEX_DATA_SM_ID_SHIFT) & HC_INDEX_DATA_SM_ID;
    if (timeout) {
        hc_index_entry->flags |= HC_INDEX_DATA_HC_ENABLED;
    }
    if (dhc_enable) {
        hc_index_entry->flags |= HC_INDEX_DATA_DYNAMIC_HC_ENABLED;
    }
}

void lm_setup_ndsb_state_machine(struct _lm_device_t *pdev, u8_t sb_id, u8_t sm_id, u8_t igu_sb_id, u8_t igu_seg_id)
{
    struct hc_status_block_sm  * hc_state_machine;
    if (CHIP_IS_E1x(pdev)) {
        hc_state_machine = pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data.common.state_machine + sm_id;
    } else {
        hc_state_machine = pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.state_machine + sm_id;
    }

    hc_state_machine->igu_sb_id = igu_sb_id;
    hc_state_machine->igu_seg_id = igu_seg_id;
    hc_state_machine->timer_value = 0xFF;
    hc_state_machine->time_to_expire = 0xFFFFFFFF;
}



void lm_int_hc_ack_sb(lm_device_t *pdev, u8_t rss_id, u8_t storm_id, u16_t sb_index, u8_t int_op, u8_t is_update_idx)
{
    struct igu_ack_register hc_data;

    //this is the result which should be communicated to the driver!
    u32_t result = 0;



    //don't forget this
    hc_data.sb_id_and_flags    = 0;
    hc_data.status_block_index = 0;

    DbgMessage(pdev, INFORMi, "lm_int_ack_sb() inside! rss_id:%d, sb_index:%d, func_num:%d is_update:%d\n", rss_id, sb_index, FUNC_ID(pdev), is_update_idx);

    hc_data.sb_id_and_flags   |= (0xffffffff & (int_op << IGU_ACK_REGISTER_INTERRUPT_MODE_SHIFT));
    hc_data.sb_id_and_flags   |= (0xffffffff & (rss_id << IGU_ACK_REGISTER_STATUS_BLOCK_ID_SHIFT));
    hc_data.sb_id_and_flags   |= (0xffffffff & (storm_id << IGU_ACK_REGISTER_STORM_ID_SHIFT));
    hc_data.sb_id_and_flags   |= (0xffffffff & (is_update_idx << IGU_ACK_REGISTER_UPDATE_INDEX_SHIFT));
    hc_data.status_block_index = sb_index;

    DbgMessage(pdev, INFORMi, "lm_int_ack_sb() inside! data:0x%x; status_block_index:%d\n", hc_data.sb_id_and_flags, hc_data.status_block_index);

    result = ((u32_t)hc_data.sb_id_and_flags) << 16 | hc_data.status_block_index;

    DbgMessage(pdev, INFORMi, "lm_int_ack_sb() result:0x%x\n", result);

    // interrupt ack
    REG_WR(pdev,  HC_REG_COMMAND_REG + PORT_ID(pdev)*32 + COMMAND_REG_INT_ACK, result);

}



void lm_int_igu_ack_sb(lm_device_t *pdev, u8_t igu_sb_id, u8_t segment_access, u16_t sb_index, u8_t int_op, u8_t is_update_idx)
{
    struct igu_regular cmd_data;
    struct igu_ctrl_reg cmd_ctrl;
    u32_t cmd_addr;

    //DbgMessage(pdev, FATAL, "int-igu-ack segment_access=%d\n", segment_access);
    DbgBreakIf(sb_index & ~IGU_REGULAR_SB_INDEX);

    /*
     * We may get here with IGU disabled. In that case, no IGU access is permitted.
     */
    if (!pdev->vars.enable_intr) 
    {
        return;
    }

    cmd_data.sb_id_and_flags =
        ((sb_index << IGU_REGULAR_SB_INDEX_SHIFT) |
         (segment_access << IGU_REGULAR_SEGMENT_ACCESS_SHIFT) |
         (is_update_idx << IGU_REGULAR_BUPDATE_SHIFT) |
         (int_op << IGU_REGULAR_ENABLE_INT_SHIFT));

    cmd_addr = IGU_CMD_INT_ACK_BASE + igu_sb_id;

    if (INTR_BLK_ACCESS(pdev) == INTR_BLK_ACCESS_IGUMEM) {
        if (IS_PFDEV(pdev)) {
            REG_WR(pdev, BAR_IGU_INTMEM + cmd_addr*8, cmd_data.sb_id_and_flags);
        } else {
            VF_REG_WR(pdev, VF_BAR0_IGU_OFFSET + cmd_addr*8, cmd_data.sb_id_and_flags);
        }
    } else {
        u8_t igu_func_id = 0;

        /* GRC ACCESS: */
        DbgBreakIf(IS_VFDEV(pdev));
        /* Write the Data, then the control */
        /* [18:12] - FID (if VF - [18] = 0; [17:12] = VF number; if PF - [18] = 1; [17:14] = 0; [13:12] = PF number) */
        igu_func_id = IGU_FUNC_ID(pdev);
        cmd_ctrl.ctrl_data =
            ((cmd_addr << IGU_CTRL_REG_ADDRESS_SHIFT) |
             (igu_func_id << IGU_CTRL_REG_FID_SHIFT) |
             (IGU_CTRL_CMD_TYPE_WR << IGU_CTRL_REG_TYPE_SHIFT));

        REG_WR(pdev, IGU_REG_COMMAND_REG_32LSB_DATA, cmd_data.sb_id_and_flags);
        REG_WR(pdev, IGU_REG_COMMAND_REG_CTRL, cmd_ctrl.ctrl_data);
    }
}

void lm_int_igu_sb_cleanup(lm_device_t *pdev, u8 igu_sb_id)
{
    struct igu_regular  cmd_data = {0};
    struct igu_ctrl_reg cmd_ctrl = {0};
    u32_t igu_addr_ack           = IGU_REG_CSTORM_TYPE_0_SB_CLEANUP + (igu_sb_id/32)*4;
    u32_t sb_bit                 =  1 << (igu_sb_id%32);
    u32_t cnt                    = 100;

#ifdef _VBD_CMD_
    return;
#endif

    /* Not supported in backward compatible mode! */
    if (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_BC)
    {
        return;
    }

    /* Cleanup can be done only via GRC access using the producer update command */
    cmd_data.sb_id_and_flags =
        ((IGU_USE_REGISTER_cstorm_type_0_sb_cleanup << IGU_REGULAR_CLEANUP_TYPE_SHIFT) |
          IGU_REGULAR_CLEANUP_SET |
          IGU_REGULAR_BCLEANUP);

    cmd_ctrl.ctrl_data =
        (((IGU_CMD_E2_PROD_UPD_BASE + igu_sb_id) << IGU_CTRL_REG_ADDRESS_SHIFT) |
         (IGU_FUNC_ID(pdev) << IGU_CTRL_REG_FID_SHIFT) |
         (IGU_CTRL_CMD_TYPE_WR << IGU_CTRL_REG_TYPE_SHIFT));

    REG_WR(pdev, IGU_REG_COMMAND_REG_32LSB_DATA, cmd_data.sb_id_and_flags);
    REG_WR(pdev, IGU_REG_COMMAND_REG_CTRL, cmd_ctrl.ctrl_data);

    /* wait for clean up to finish */
    while (!(REG_RD(pdev, igu_addr_ack) & sb_bit) && --cnt)
    {
        mm_wait(pdev, 10);
    }

    if (!(REG_RD(pdev, igu_addr_ack) & sb_bit))
    {
        DbgMessage(pdev, FATAL, "Unable to finish IGU cleanup - set: igu_sb_id %d offset %d bit %d (cnt %d)\n",
                    igu_sb_id, igu_sb_id/32, igu_sb_id%32, cnt);
    }

    /* Now we clear the cleanup-bit... same command without cleanup_set... */
    cmd_data.sb_id_and_flags =
        ((IGU_USE_REGISTER_cstorm_type_0_sb_cleanup << IGU_REGULAR_CLEANUP_TYPE_SHIFT) |
          IGU_REGULAR_BCLEANUP);


    REG_WR(pdev, IGU_REG_COMMAND_REG_32LSB_DATA, cmd_data.sb_id_and_flags);
    REG_WR(pdev, IGU_REG_COMMAND_REG_CTRL, cmd_ctrl.ctrl_data);

    /* wait for clean up to finish */
    while ((REG_RD(pdev, igu_addr_ack) & sb_bit) && --cnt)
    {
        mm_wait(pdev, 10);
    }

    if ((REG_RD(pdev, igu_addr_ack) & sb_bit))
    {
        DbgMessage(pdev, FATAL, "Unable to finish IGU cleanup - clear: igu_sb_id %d offset %d bit %d (cnt %d)\n",
                    igu_sb_id, igu_sb_id/32, igu_sb_id%32, cnt);
    }
}


void lm_int_ack_def_sb_disable(lm_device_t *pdev)
{
    pdev->debug_info.ack_def_dis++;
    if (INTR_BLK_TYPE(pdev) == INTR_BLK_HC) {
        lm_int_hc_ack_sb(pdev, DEF_STATUS_BLOCK_IGU_INDEX, HC_SEG_ACCESS_DEF, DEF_SB_INDEX(pdev), IGU_INT_DISABLE, 0); //DEF_STATUS_BLOCK_INDEX
    } else {
        if (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_BC) {
            lm_int_igu_ack_sb(pdev, IGU_DSB_ID(pdev), HC_SEG_ACCESS_DEF, DEF_SB_INDEX(pdev), IGU_INT_DISABLE, 0);
        } else {
            lm_int_igu_ack_sb(pdev, IGU_DSB_ID(pdev), IGU_SEG_ACCESS_DEF, DEF_SB_INDEX(pdev), IGU_INT_DISABLE, 1);
        }
    }
}

/* Assumptions: Called when acking a status-block and enabling interrupts */
void lm_int_ack_def_sb_enable(lm_device_t *pdev)
{
    pdev->debug_info.ack_def_en++;
    if (INTR_BLK_TYPE(pdev) == INTR_BLK_HC) {
        lm_int_hc_ack_sb(pdev, DEF_STATUS_BLOCK_IGU_INDEX, HC_SEG_ACCESS_ATTN, DEF_SB_INDEX_OF_ATTN(pdev), IGU_INT_NOP, 1); //DEF_STATUS_BLOCK_INDEX
        lm_int_hc_ack_sb(pdev, DEF_STATUS_BLOCK_IGU_INDEX, HC_SEG_ACCESS_DEF, DEF_SB_INDEX(pdev), IGU_INT_ENABLE, 1); //DEF_STATUS_BLOCK_INDEX
    } else {
        if (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_BC) {
            lm_int_igu_ack_sb(pdev, IGU_DSB_ID(pdev), HC_SEG_ACCESS_ATTN, DEF_SB_INDEX_OF_ATTN(pdev), IGU_INT_NOP, 1);
            lm_int_igu_ack_sb(pdev, IGU_DSB_ID(pdev), HC_SEG_ACCESS_DEF, DEF_SB_INDEX(pdev), IGU_INT_ENABLE, 1);
        } else {
            lm_int_igu_ack_sb(pdev, IGU_DSB_ID(pdev), IGU_SEG_ACCESS_ATTN, DEF_SB_INDEX_OF_ATTN(pdev), IGU_INT_NOP, 1);
            lm_int_igu_ack_sb(pdev, IGU_DSB_ID(pdev), IGU_SEG_ACCESS_DEF, DEF_SB_INDEX(pdev), IGU_INT_ENABLE, 1);
        }
    }
}

void lm_int_ack_sb_disable(lm_device_t *pdev, u8_t rss_id)
{
    if (INTR_BLK_TYPE(pdev) == INTR_BLK_HC) {
        lm_int_hc_ack_sb(pdev, rss_id , HC_SEG_ACCESS_NORM, 0, IGU_INT_DISABLE, 0);
        pdev->debug_info.ack_dis[rss_id]++;
    } else {
        if (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_BC) {
            lm_int_igu_ack_sb(pdev, rss_id  + IGU_BASE_NDSB(pdev) , HC_SEG_ACCESS_NORM, 0, IGU_INT_DISABLE, 0);
            pdev->debug_info.ack_dis[rss_id]++;
        } else {
            if (pdev->debug_info.ack_dis[rss_id] == pdev->debug_info.ack_en[rss_id]) {
                //DbgMessage(pdev, WARN, "********lm_int_ack_sb_disable() during DPC\n");
//                REG_WR(PFDEV(pdev), IGU_REG_ECO_RESERVED, 8);
//                DbgBreak();
            }
            if (IS_PFDEV(pdev)) 
            {
                lm_int_igu_ack_sb(pdev, rss_id  + IGU_BASE_NDSB(pdev), IGU_SEG_ACCESS_NORM, 0, IGU_INT_DISABLE, 0);
            }
            else
            {
                lm_int_igu_ack_sb(pdev, IGU_VF_NDSB(pdev,rss_id), IGU_SEG_ACCESS_NORM, 0, IGU_INT_DISABLE, 0);
            }
            pdev->debug_info.ack_dis[rss_id]++;
        }
    }
}

void lm_int_ack_sb_enable(lm_device_t *pdev, u8_t rss_id)
{
    if (INTR_BLK_TYPE(pdev) == INTR_BLK_HC) {
        lm_int_hc_ack_sb(pdev, rss_id , HC_SEG_ACCESS_NORM, SB_RX_INDEX(pdev,rss_id), IGU_INT_ENABLE, 1);
        pdev->debug_info.ack_en[rss_id]++;
    } else {
        if (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_BC) {
            lm_int_igu_ack_sb(pdev, rss_id  + IGU_BASE_NDSB(pdev) , HC_SEG_ACCESS_NORM, SB_RX_INDEX(pdev,rss_id), IGU_INT_ENABLE, 1);
            pdev->debug_info.ack_en[rss_id]++;
        } else {
            if (rss_id >= IGU_U_NDSB_OFFSET(pdev)) {
                if (IS_PFDEV(pdev)) 
                {
                    lm_int_igu_ack_sb(pdev, rss_id  + IGU_BASE_NDSB(pdev), IGU_SEG_ACCESS_NORM, SB_RX_INDEX(pdev,rss_id), IGU_INT_ENABLE, 1);
                }
                else
                {
                    lm_int_igu_ack_sb(pdev, IGU_VF_NDSB(pdev,rss_id), IGU_SEG_ACCESS_NORM, SB_RX_INDEX(pdev,rss_id), IGU_INT_ENABLE, 1);
                }
                pdev->debug_info.ack_en[rss_id]++;
            } else {
                lm_int_igu_ack_sb(pdev, rss_id  + IGU_BASE_NDSB(pdev), IGU_SEG_ACCESS_NORM, SB_TX_INDEX(pdev,rss_id), IGU_INT_ENABLE, 1);
            }
         }
    }
}

void lm_enable_hc_int(struct _lm_device_t *pdev)
{
    u32_t val;
    u32_t reg_name;

    DbgBreakIf(!pdev);

    reg_name = PORT_ID(pdev) ? HC_REG_CONFIG_1 : HC_REG_CONFIG_0;

    DbgMessage(pdev, INFORMnv, "### lm_enable_int\n");

    val = 0x1000;

    SET_FLAGS(val, (PORT_ID(pdev)?  HC_CONFIG_1_REG_ATTN_BIT_EN_1 : HC_CONFIG_0_REG_ATTN_BIT_EN_0));

    switch (pdev->params.interrupt_mode) {
    case LM_INT_MODE_INTA:
        SET_FLAGS(val, (HC_CONFIG_0_REG_INT_LINE_EN_0 |
                        HC_CONFIG_0_REG_SINGLE_ISR_EN_0));

        /* we trust that if we're in inta... the os will take care of the configuration space...and therefore
         * that will determine whether we are in inta or msix and not this configuration, we can't take down msix
         * due to a hw bug */
        if (CHIP_IS_E1(pdev))
        {
            SET_FLAGS(val, HC_CONFIG_0_REG_MSI_MSIX_INT_EN_0);
        }
        break;
    case LM_INT_MODE_SIMD:
        SET_FLAGS(val, (HC_CONFIG_0_REG_SINGLE_ISR_EN_0 | HC_CONFIG_0_REG_MSI_MSIX_INT_EN_0) );
        RESET_FLAGS(val, HC_CONFIG_0_REG_INT_LINE_EN_0);
        break;
    case LM_INT_MODE_MIMD:
        SET_FLAGS(val, HC_CONFIG_0_REG_MSI_MSIX_INT_EN_0);
        RESET_FLAGS(val, (HC_CONFIG_0_REG_INT_LINE_EN_0 |
                          HC_CONFIG_0_REG_SINGLE_ISR_EN_0));
        break;
    default:
        DbgBreakMsg("Wrong Interrupt Mode\n");
        return;
    }

    if (CHIP_IS_E1(pdev))
    {
        REG_WR(pdev, HC_REG_INT_MASK + PORT_ID(pdev)*4, 0x1FFFF);
    }

    REG_WR(pdev,  reg_name, val);

    if(!CHIP_IS_E1(pdev))
    {
        /* init leading/trailing edge */
        if(IS_MULTI_VNIC(pdev))
        {
            /* in mf mode:
             *  - Set only VNIC bit out of the "per vnic group attentions" (bits[4-7]) */
            val = (0xee0f | (1 << (VNIC_ID(pdev) + 4)));
            /* Connect to PMF to NIG attention bit 8 */
            if (IS_PMF(pdev)) {
                val |= 0x1100;
            }
        } else
        {
            val = 0xffff;
        }
        REG_WR(pdev,  (PORT_ID(pdev) ? HC_REG_TRAILING_EDGE_1 : HC_REG_TRAILING_EDGE_0), val);
        REG_WR(pdev,  (PORT_ID(pdev) ? HC_REG_LEADING_EDGE_1 : HC_REG_LEADING_EDGE_0), val);
    }

    pdev->vars.enable_intr = 1;
}

lm_status_t lm_enable_igu_int(struct _lm_device_t *pdev)
{
    u32_t val = 0;

    if(ERR_IF(!pdev)) {
        return LM_STATUS_INVALID_PARAMETER;
    }

#ifdef VF_INVOLVED
    if (IS_VFDEV(pdev)) {
        lm_status_t lm_status;
        lm_status =  lm_vf_enable_igu_int(pdev);
        if (lm_status != LM_STATUS_SUCCESS) {
            DbgMessage(pdev, FATAL, "VF can't enable igu interrupt\n");
            return lm_status;
        }
        pdev->vars.enable_intr = 1;
        return lm_status;

    }
#endif

    DbgMessage(pdev, INFORMnv, "### lm_enable_int\n");

    val=REG_RD(pdev, IGU_REG_PF_CONFIGURATION);

    SET_FLAGS(val, IGU_PF_CONF_FUNC_EN);
    SET_FLAGS(val, IGU_PF_CONF_ATTN_BIT_EN);

    switch (pdev->params.interrupt_mode) {
    case LM_INT_MODE_INTA:
        SET_FLAGS(val, (IGU_PF_CONF_INT_LINE_EN | IGU_PF_CONF_SINGLE_ISR_EN));
        RESET_FLAGS(val, IGU_PF_CONF_MSI_MSIX_EN);
        break;
    case LM_INT_MODE_SIMD:
        SET_FLAGS(val, (IGU_PF_CONF_SINGLE_ISR_EN | IGU_PF_CONF_MSI_MSIX_EN) );
        RESET_FLAGS(val, IGU_PF_CONF_INT_LINE_EN);
        break;
    case LM_INT_MODE_MIMD:
        SET_FLAGS(val, IGU_PF_CONF_MSI_MSIX_EN);
        RESET_FLAGS(val, (IGU_PF_CONF_INT_LINE_EN | IGU_PF_CONF_SINGLE_ISR_EN));
        break;
    default:
        DbgBreakMsg("Wrong Interrupt Mode\n");
        return LM_STATUS_FAILURE;
    }

    REG_WR(pdev,  IGU_REG_PF_CONFIGURATION, val);

    if(!CHIP_IS_E1(pdev))
    {
        /* init leading/trailing edge */
        if(IS_MULTI_VNIC(pdev))
        {
            /* in mf mode:
             *  - Do not set the link attention (bit 11) (will be set by MCP for the PMF)
             *  - Set only VNIC bit out of the "per vnic group attentions" (bits[4-7]) */
            val = (0xee0f | (1 << (VNIC_ID(pdev) + 4)));
            /* Connect to PMF to NIG attention bit 8 */
            if (IS_PMF(pdev)) {
                val |= 0x1100;
            }
        } else
        {
            val = 0xffff;
        }
        if (CHIP_IS_E3(pdev)) {
            val &= ~ATTN_SW_TIMER_4_FUNC; // To prevent Timer4 expiration attention 
        }
        REG_WR(pdev,  IGU_REG_TRAILING_EDGE_LATCH, val);
        REG_WR(pdev,  IGU_REG_LEADING_EDGE_LATCH, val);
    }

    pdev->vars.enable_intr = 1;

    return LM_STATUS_SUCCESS;
}

void lm_enable_int(struct _lm_device_t *pdev)
{
    if (INTR_BLK_TYPE(pdev) == INTR_BLK_HC) {
        lm_enable_hc_int(pdev);
    } else {
        lm_enable_igu_int(pdev);
    }
}


void lm_disable_hc_int(struct _lm_device_t *pdev)
{
    u32_t val;
    u32_t reg_name;

    DbgBreakIf(!pdev);

    reg_name = PORT_ID(pdev) ? HC_REG_CONFIG_1 : HC_REG_CONFIG_0;

    DbgMessage(pdev, INFORMnv, "### lm_disable_int\n");

    val=REG_RD(pdev, reg_name);

    /* disable both bits, for INTA, MSI and MSI-X. */
    RESET_FLAGS(val, (HC_CONFIG_0_REG_MSI_MSIX_INT_EN_0 |
                      HC_CONFIG_0_REG_INT_LINE_EN_0 |
                      HC_CONFIG_0_REG_ATTN_BIT_EN_0 |
                      HC_CONFIG_0_REG_SINGLE_ISR_EN_0));

    if (CHIP_IS_E1(pdev))
    {
        REG_WR(pdev, HC_REG_INT_MASK + PORT_ID(pdev)*4, 0);

        /* E1 Errate: can't ever take msix bit down */
        SET_FLAGS(val,HC_CONFIG_0_REG_MSI_MSIX_INT_EN_0);
    }

    REG_WR(pdev,  reg_name, val);

    pdev->vars.enable_intr = 0;
}

void lm_disable_igu_int(struct _lm_device_t *pdev)
{
    u32_t val;

    DbgBreakIf(!pdev);

    DbgMessage(pdev, INFORMnv, "### lm_disable_int\n");

#ifdef VF_INVOLVED
    if (IS_VFDEV(pdev)) {
        lm_vf_disable_igu_int(pdev);
        pdev->vars.enable_intr = 0;
        return;
    }
#endif

    val = REG_RD(pdev, IGU_REG_PF_CONFIGURATION);

    /* disable both bits, for INTA, MSI and MSI-X. */
    RESET_FLAGS(val, (IGU_PF_CONF_MSI_MSIX_EN |
                      IGU_PF_CONF_INT_LINE_EN |
                      IGU_PF_CONF_ATTN_BIT_EN |
                      IGU_PF_CONF_SINGLE_ISR_EN |
                      IGU_PF_CONF_FUNC_EN));

    REG_WR(pdev,  IGU_REG_PF_CONFIGURATION, val);

    pdev->vars.enable_intr = 0;
}

void lm_disable_int(struct _lm_device_t *pdev)
{
    if (INTR_BLK_TYPE(pdev) == INTR_BLK_HC) {
        lm_disable_hc_int(pdev);
    } else {
        lm_disable_igu_int(pdev);
    }
}

void lm_init_non_def_status_block(struct _lm_device_t *pdev,
                              u8_t  sb_id,
                              u8_t  port)
{
    lm_int_coalesing_info *ic  = &pdev->vars.int_coal;
    u8_t index                 = 0;
    const u8_t fw_sb_id        = LM_FW_SB_ID(pdev, sb_id);
    const u8_t dhc_qzone_id    = LM_FW_DHC_QZONE_ID(pdev, sb_id);
    const u8_t byte_counter_id = CHIP_IS_E1x(pdev)? fw_sb_id : dhc_qzone_id;
    u8_t igu_sb_id = 0;
    u8_t igu_seg_id = 0;
    u8_t timeout = 0;
    u8_t dhc_enable = FALSE;
    u8_t sm_idx;
    u8_t hc_sb_max_indices;

    DbgBreakIf(!pdev);

    /* CQ#46240: Disable the function in the status-block data before nullifying sync-line + status-block */
    LM_INTMEM_WRITE8(pdev, CSTORM_STATUS_BLOCK_DATA_STATE_OFFSET(fw_sb_id),
                      SB_DISABLED, BAR_CSTRORM_INTMEM);

    /* nullify the status block */
    DbgBreakIf((CSTORM_STATUS_BLOCK_SIZE % 4) != 0);
    DbgBreakIf((CSTORM_STATUS_BLOCK_DATA_SIZE % 4) != 0);
    DbgBreakIf((CSTORM_SYNC_BLOCK_SIZE % 4) != 0);
    
    for (index = 0; index < CSTORM_SYNC_BLOCK_SIZE / sizeof(u32_t); index++) {
        LM_INTMEM_WRITE32(PFDEV(pdev), CSTORM_SYNC_BLOCK_OFFSET(fw_sb_id) + 4*index, 0, BAR_CSTRORM_INTMEM);
    }
    for (index = 0; index < CSTORM_STATUS_BLOCK_SIZE / sizeof(u32_t); index++) {
        LM_INTMEM_WRITE32(PFDEV(pdev), CSTORM_STATUS_BLOCK_OFFSET(fw_sb_id) + 4*index, 0, BAR_CSTRORM_INTMEM);
    }


    /* Initialize cstorm_status_block_data structure */
    if (CHIP_IS_E1x(pdev)) {

        pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data.common.p_func.pf_id = FUNC_ID(pdev);
        pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data.common.p_func.vf_id = 0xff;
        pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data.common.p_func.vf_valid = FALSE;
        pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data.common.p_func.vnic_id = VNIC_ID(pdev);

        if (pdev->params.ndsb_type == LM_DOUBLE_SM_SINGLE_IGU) {
            pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data.common.same_igu_sb_1b = TRUE;
        } else {
            pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data.common.same_igu_sb_1b = FALSE;
        }

        pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data.common.state = SB_ENABLED;
    } else {

        pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.p_func.pf_id = FUNC_ID(pdev);
        if (IS_PFDEV(pdev)) {
            pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.p_func.vf_id = 0xff;
            pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.p_func.vf_valid = FALSE;
        } else {
            pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.p_func.vf_id = ABS_VFID(pdev);
            pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.p_func.vf_valid = TRUE;
        }
        pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.p_func.vnic_id = VNIC_ID(pdev);
        if (pdev->params.ndsb_type == LM_DOUBLE_SM_SINGLE_IGU) {
            pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.same_igu_sb_1b = TRUE;
        } else {
            pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.same_igu_sb_1b = FALSE;
        }
        pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.dhc_qzone_id = dhc_qzone_id;

        pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.state = SB_ENABLED;

    }

    if ((INTR_BLK_TYPE(pdev) == INTR_BLK_IGU) && (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_NORM) ) {
        igu_sb_id = IGU_BASE_NDSB(pdev) + /*IGU_U_NDSB_OFFSET(pdev)*/ + sb_id;
        igu_seg_id = IGU_SEG_ACCESS_NORM;
    } else {
        igu_sb_id = sb_id;
        igu_seg_id = HC_SEG_ACCESS_NORM;
    }

    lm_setup_ndsb_state_machine(pdev, sb_id, SM_RX_ID, igu_sb_id + IGU_U_NDSB_OFFSET(pdev), igu_seg_id);
    if (pdev->params.ndsb_type != LM_SINGLE_SM) {
        lm_setup_ndsb_state_machine(pdev, sb_id, SM_TX_ID, igu_sb_id,igu_seg_id);
    }

    //init host coalescing params - supported dymanicHC indices
    if (CHIP_IS_E1x(pdev)) {
        hc_sb_max_indices = HC_SB_MAX_INDICES_E1X;
    } else {
        hc_sb_max_indices = HC_SB_MAX_INDICES_E2;
    }
    for (index = 0; index < hc_sb_max_indices; index++) {
        if (index < HC_DHC_SB_NUM_INDICES) {
            dhc_enable = (pdev->params.enable_dynamic_hc[index] != 0);
            REG_WR(PFDEV(pdev), CSEM_REG_FAST_MEMORY + CSTORM_BYTE_COUNTER_OFFSET(byte_counter_id, index), 0);
        } else {
            dhc_enable = FALSE;
        }
        switch (index) {
        case HC_INDEX_TOE_RX_CQ_CONS:
        case HC_INDEX_ETH_RX_CQ_CONS:
        case HC_INDEX_FCOE_EQ_CONS:
            sm_idx = SM_RX_ID;
            if (dhc_enable && ic->hc_usec_u_sb[index]) {
                timeout = (u8_t)pdev->params.hc_timeout0[SM_RX_ID][index];
            } else {
                timeout = (u8_t)(ic->hc_usec_u_sb[index] / HC_TIMEOUT_RESOLUTION_IN_US);
            }
            break;
        case HC_INDEX_TOE_TX_CQ_CONS:
            if (pdev->params.ndsb_type != LM_SINGLE_SM) {
                sm_idx = SM_TX_ID;
            } else {
                sm_idx = SM_RX_ID;
            }
            if (dhc_enable && ic->hc_usec_c_sb[0]) {
                if (pdev->params.ndsb_type != LM_SINGLE_SM) {
                    timeout = (u8_t)pdev->params.hc_timeout0[SM_TX_ID][index];
                } else {
                    timeout = (u8_t)pdev->params.hc_timeout0[SM_RX_ID][index];
                }
            } else {
                timeout = (u8_t)(ic->hc_usec_c_sb[0] / HC_TIMEOUT_RESOLUTION_IN_US);
            }
            break;

        case HC_INDEX_ETH_TX_CQ_CONS_COS0:
        case HC_INDEX_ETH_TX_CQ_CONS_COS1: 
        case HC_INDEX_ETH_TX_CQ_CONS_COS2: 
            if (pdev->params.ndsb_type != LM_SINGLE_SM) {
                sm_idx = SM_TX_ID;
            } else {
            sm_idx = SM_RX_ID;
            }
            // TODO Shayh: HC_PARAMS_ETH_INDEX (DYNAMIC_HC_ETH_INDEX) Should be handeled better from registry 
            // (not as part of this submit) .
            timeout = (u8_t)(ic->hc_usec_c_sb[1] / HC_TIMEOUT_RESOLUTION_IN_US);
            break;

        case HC_INDEX_ISCSI_EQ_CONS:
            if (pdev->params.ndsb_type != LM_SINGLE_SM) {
                sm_idx = SM_TX_ID;
            } else {
                sm_idx = SM_RX_ID;
            }
            // DYNAMIC_HC_ISCSI_INDEX
            timeout = (u8_t)(ic->hc_usec_c_sb[2] / HC_TIMEOUT_RESOLUTION_IN_US);
            break;

        default:
            if (pdev->params.ndsb_type != LM_SINGLE_SM) {
                sm_idx = SM_TX_ID;
            } else {
                sm_idx = SM_RX_ID;
            }
            timeout = (u8_t)(ic->hc_usec_c_sb[3] / HC_TIMEOUT_RESOLUTION_IN_US);
            dhc_enable = FALSE;
            break;
        }
        lm_setup_ndsb_index(pdev, sb_id, index, sm_idx, timeout, dhc_enable);
    }
    if (CHIP_IS_E1x(pdev)) {
        for (index = 0; index < sizeof(struct hc_status_block_data_e1x)/sizeof(u32_t); index++) {
            LM_INTMEM_WRITE32(PFDEV(pdev), CSTORM_STATUS_BLOCK_DATA_OFFSET(fw_sb_id) + sizeof(u32_t)*index,
                              *((u32_t*)(&pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data) + index), BAR_CSTRORM_INTMEM);
        }
    } else {
        for (index = 0; index < sizeof(struct hc_status_block_data_e2)/sizeof(u32_t); index++) {
            LM_INTMEM_WRITE32(PFDEV(pdev), CSTORM_STATUS_BLOCK_DATA_OFFSET(fw_sb_id) + sizeof(u32_t)*index,
                              *((u32_t*)(&pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data) + index), BAR_CSTRORM_INTMEM);
        }
    }
}

/**
 * @description
 * Get the HC_INDEX_ETH_TX_CQ_CONS_COSX index from chain. 
 * @param pdev 
 * @param chain 
 * 
 * @return STATIC u8_t 
 */
u8_t
lm_eth_tx_hc_cq_cons_cosx_from_chain(IN         lm_device_t *pdev,
                                     IN const   u32_t        chain)
{
    u8_t sb_index_number    = HC_INDEX_ETH_TX_CQ_CONS_COS0;
    const u8_t cos          = lm_mp_cos_from_chain(pdev,chain);

    DbgBreakIf(lm_chain_type_not_cos == lm_mp_get_chain_type(pdev, chain));

    switch(cos)
    {
    case 0:
        sb_index_number = HC_INDEX_ETH_TX_CQ_CONS_COS0;
        break;
    case 1:
        sb_index_number = HC_INDEX_ETH_TX_CQ_CONS_COS1;
        break;
    case 2:
        sb_index_number = HC_INDEX_ETH_TX_CQ_CONS_COS2;
        break;
    default:
        DbgBreakMsg("Invalid cos");
        break;
    }

    return sb_index_number;
}

#ifdef VF_INVOLVED

lm_status_t lm_pf_init_vf_non_def_sb(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, u8_t sb_idx, u64 sb_addr)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    lm_int_coalesing_info *ic  = &pdev->vars.int_coal;
    u8_t index                 = 0;
    const u8_t fw_sb_id        = LM_FW_VF_SB_ID(vf_info, sb_idx);
    const u8_t dhc_qzone_id    = LM_FW_VF_DHC_QZONE_ID(vf_info, sb_idx);
    const u8_t byte_counter_id = dhc_qzone_id;
    u8_t igu_sb_id = 0;
    u8_t igu_seg_id = 0;
    lm_address_t    sb_phy_address;
    u8_t hc_sb_max_indices;
    u8_t dhc_enable = FALSE;
    u8_t sm_idx;
    u8_t timeout = 0;

    DbgBreakIf(!pdev);

    /* CQ#46240: Disable the function in the status-block data before nullifying sync-line + status-block */
    LM_INTMEM_WRITE8(pdev, CSTORM_STATUS_BLOCK_DATA_STATE_OFFSET(fw_sb_id),
                      SB_DISABLED, BAR_CSTRORM_INTMEM);

    /* nullify the status block */
    DbgBreakIf((CSTORM_STATUS_BLOCK_SIZE % 4) != 0);
    DbgBreakIf((CSTORM_STATUS_BLOCK_DATA_SIZE % 4) != 0);
    DbgBreakIf((CSTORM_SYNC_BLOCK_SIZE % 4) != 0);
    if (IS_PFDEV(pdev)) {
        for (index = 0; index < CSTORM_SYNC_BLOCK_SIZE / sizeof(u32_t); index++) {
            LM_INTMEM_WRITE32(PFDEV(pdev), CSTORM_SYNC_BLOCK_OFFSET(fw_sb_id) + 4*index, 0, BAR_CSTRORM_INTMEM);
        }
        for (index = 0; index < CSTORM_STATUS_BLOCK_SIZE / sizeof(u32_t); index++) {
            LM_INTMEM_WRITE32(PFDEV(pdev), CSTORM_STATUS_BLOCK_OFFSET(fw_sb_id) + 4*index, 0, BAR_CSTRORM_INTMEM);
        }
    } else {
        DbgBreak();
    }

    sb_phy_address.as_u64 = sb_addr;
    pdev->vars.status_blocks_arr[LM_SW_VF_SB_ID(vf_info,sb_idx)].hc_status_block_data.e2_sb_data.common.host_sb_addr.lo = sb_phy_address.as_u32.low;
    pdev->vars.status_blocks_arr[LM_SW_VF_SB_ID(vf_info,sb_idx)].hc_status_block_data.e2_sb_data.common.host_sb_addr.hi = sb_phy_address.as_u32.high;

    /* Initialize cstorm_status_block_data structure */
    pdev->vars.status_blocks_arr[LM_SW_VF_SB_ID(vf_info,sb_idx)].hc_status_block_data.e2_sb_data.common.p_func.pf_id = FUNC_ID(pdev);
    pdev->vars.status_blocks_arr[LM_SW_VF_SB_ID(vf_info,sb_idx)].hc_status_block_data.e2_sb_data.common.p_func.vf_id = vf_info->abs_vf_id;
    pdev->vars.status_blocks_arr[LM_SW_VF_SB_ID(vf_info,sb_idx)].hc_status_block_data.e2_sb_data.common.p_func.vf_valid = TRUE;
    pdev->vars.status_blocks_arr[LM_SW_VF_SB_ID(vf_info,sb_idx)].hc_status_block_data.e2_sb_data.common.p_func.vnic_id = VNIC_ID(pdev);
    if (pdev->params.ndsb_type == LM_DOUBLE_SM_SINGLE_IGU) {
        pdev->vars.status_blocks_arr[LM_SW_VF_SB_ID(vf_info,sb_idx)].hc_status_block_data.e2_sb_data.common.same_igu_sb_1b = TRUE;
    } else {
        pdev->vars.status_blocks_arr[LM_SW_VF_SB_ID(vf_info,sb_idx)].hc_status_block_data.e2_sb_data.common.same_igu_sb_1b = FALSE;
    }
    pdev->vars.status_blocks_arr[LM_SW_VF_SB_ID(vf_info,sb_idx)].hc_status_block_data.e2_sb_data.common.dhc_qzone_id = dhc_qzone_id;
    pdev->vars.status_blocks_arr[LM_SW_VF_SB_ID(vf_info,sb_idx)].hc_status_block_data.e2_sb_data.common.state = SB_ENABLED;

    if ((INTR_BLK_TYPE(pdev) == INTR_BLK_IGU) && (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_NORM) ) {
        igu_sb_id = LM_VF_IGU_SB_ID(vf_info,sb_idx);
        igu_seg_id = IGU_SEG_ACCESS_NORM;
    } else {
        DbgBreak();
    }

    lm_setup_ndsb_state_machine(pdev, LM_SW_VF_SB_ID(vf_info,sb_idx), SM_RX_ID, igu_sb_id + IGU_U_NDSB_OFFSET(pdev), igu_seg_id);
    if (pdev->params.ndsb_type != LM_SINGLE_SM) {
        lm_setup_ndsb_state_machine(pdev, LM_SW_VF_SB_ID(vf_info,sb_idx), SM_TX_ID, igu_sb_id,igu_seg_id);
    }

    //init host coalescing params - supported dymanicHC indices
    if (CHIP_IS_E1x(pdev)) {
        DbgBreak();
    } else {
        hc_sb_max_indices = HC_SB_MAX_INDICES_E2;
    }
    for (index = 0; index < hc_sb_max_indices; index++) {
        if (index < HC_DHC_SB_NUM_INDICES) {
            dhc_enable = (pdev->params.enable_dynamic_hc[index] != 0);
        REG_WR(PFDEV(pdev), CSEM_REG_FAST_MEMORY + CSTORM_BYTE_COUNTER_OFFSET(byte_counter_id, index), 0);
        } else {
            dhc_enable = FALSE;
    }
        switch (index) {
        case HC_INDEX_TOE_RX_CQ_CONS:
        case HC_INDEX_ETH_RX_CQ_CONS:
        case HC_INDEX_FCOE_EQ_CONS:
            sm_idx = SM_RX_ID;
            if (dhc_enable && ic->hc_usec_u_sb[index]) {
                timeout = (u8_t)pdev->params.hc_timeout0[SM_RX_ID][index];
            } else {
                timeout = (u8_t)(ic->hc_usec_u_sb[index] / HC_TIMEOUT_RESOLUTION_IN_US);
            }
            break;
        case HC_INDEX_TOE_TX_CQ_CONS:
            if (pdev->params.ndsb_type != LM_SINGLE_SM) {
                sm_idx = SM_TX_ID;
            } else {
                sm_idx = SM_RX_ID;
    }
            if (dhc_enable && ic->hc_usec_c_sb[0]) {
                if (pdev->params.ndsb_type != LM_SINGLE_SM) {
                    timeout = (u8_t)pdev->params.hc_timeout0[SM_TX_ID][index];
                } else {
                    timeout = (u8_t)pdev->params.hc_timeout0[SM_RX_ID][index];
                }
            } else {
                timeout = (u8_t)(ic->hc_usec_c_sb[0] / HC_TIMEOUT_RESOLUTION_IN_US);
            }
            break;

        case HC_INDEX_ETH_TX_CQ_CONS_COS0:
        case HC_INDEX_ETH_TX_CQ_CONS_COS1:
        case HC_INDEX_ETH_TX_CQ_CONS_COS2:
        if (pdev->params.ndsb_type != LM_SINGLE_SM) {
                sm_idx = SM_TX_ID;
        } else {
                sm_idx = SM_RX_ID;
        }
            // TODO Shayh: HC_PARAMS_ETH_INDEX (DYNAMIC_HC_ETH_INDEX) Should be handeled better from registry 
            // (not as part of this submit) .
            timeout = (u8_t)(ic->hc_usec_c_sb[1] / HC_TIMEOUT_RESOLUTION_IN_US);
            break;

        case HC_INDEX_ISCSI_EQ_CONS:
            if (pdev->params.ndsb_type != LM_SINGLE_SM) {
                sm_idx = SM_TX_ID;
            } else {
                sm_idx = SM_RX_ID;
            }
            // DYNAMIC_HC_ISCSI_INDEX
            timeout = (u8_t)(ic->hc_usec_c_sb[2] / HC_TIMEOUT_RESOLUTION_IN_US);
            break;

        default:
        if (pdev->params.ndsb_type != LM_SINGLE_SM) {
                sm_idx = SM_TX_ID;
        } else {
                sm_idx = SM_RX_ID;
    }
            timeout = (u8_t)(ic->hc_usec_c_sb[3] / HC_TIMEOUT_RESOLUTION_IN_US);
            dhc_enable = FALSE;
            break;
        }
        lm_setup_ndsb_index(pdev, LM_SW_VF_SB_ID(vf_info,sb_idx), index, sm_idx, timeout, dhc_enable);
    }

    if (!CHIP_IS_E1x(pdev)) {
        for (index = 0; index < sizeof(struct hc_status_block_data_e2)/sizeof(u32_t); index++) {
            LM_INTMEM_WRITE32(pdev, CSTORM_STATUS_BLOCK_DATA_OFFSET(fw_sb_id) + sizeof(u32_t)*index,
                              *((u32_t*)(&pdev->vars.status_blocks_arr[LM_SW_VF_SB_ID(vf_info,sb_idx)].hc_status_block_data.e2_sb_data) + index), BAR_CSTRORM_INTMEM);
        }
    } else {
        DbgBreak();
    }


    return lm_status;
}

#endif //VF_INVOLVED

void lm_clear_non_def_status_block(struct _lm_device_t *pdev, u8_t  fw_sb_id)
{
    u32_t   index    = 0;
    u8_t    func     = 0;

    DbgBreakIf(!pdev);
    DbgMessage(pdev, INFORMi, "clear_status_block: fw_sb_id:%d\n",fw_sb_id);

    func = FUNC_ID(pdev);

    /* nullify the status block */
    DbgBreakIf((CSTORM_STATUS_BLOCK_SIZE % 4) != 0);
    DbgBreakIf((CSTORM_STATUS_BLOCK_DATA_SIZE % 4) != 0);
    DbgBreakIf((CSTORM_SYNC_BLOCK_SIZE % 4) != 0);

    LM_INTMEM_WRITE8(pdev, CSTORM_STATUS_BLOCK_DATA_STATE_OFFSET(fw_sb_id),
                      SB_DISABLED, BAR_CSTRORM_INTMEM);

    
    for (index = 0; index < CSTORM_SYNC_BLOCK_SIZE / sizeof(u32_t); index++) {
        LM_INTMEM_WRITE32(PFDEV(pdev), CSTORM_SYNC_BLOCK_OFFSET(fw_sb_id) + 4*index, 0, BAR_CSTRORM_INTMEM);
    }
    for (index = 0; index < CSTORM_STATUS_BLOCK_SIZE / sizeof(u32_t); index++) {
        LM_INTMEM_WRITE32(PFDEV(pdev), CSTORM_STATUS_BLOCK_OFFSET(fw_sb_id) + 4*index, 0, BAR_CSTRORM_INTMEM);
    }

}


