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
 *      This file encapsulates all the functions required to support error 
 *      recovery in E2. It is an isolated module that can be compiled in/out
 *      according to error recovery support in upper layer
 *
 *
 ******************************************************************************/

#include "lm5710.h"
#include "aeu_inputs.h"
#include "lm_defs.h"
#include "general_atten_bits.h"
/** 
 * @Description
 *      This function should be called to acquire the leader lock. the leader
 *      lock should not be released until recovery process id done.
 *      The leader lock is not waited for, its a non-blockinf function 
 *
 * @param pdev
 * 
 * @return lm_status_t SUCCESS or FAILURE
 */
lm_status_t lm_er_acquire_leader_lock(lm_device_t * pdev)
{
    return lm_hw_lock(pdev, HW_LOCK_RESOURCE_RECOVERY_LEADER_0, FALSE);
}

/** 
 * @Description
 *      release the lock acquired in the previous function 
 * @param pdev
 * 
 * @return lm_status_t SUCCESS, INVALID_PARAM: if invalid input 
 *         is provided, LM_STATUS_OBJECT_NOT_FOUND if the lock
 *         isn't taken.
 */
lm_status_t lm_er_release_leader_lock(lm_device_t * pdev)
{
    return lm_hw_unlock(pdev, HW_LOCK_RESOURCE_RECOVERY_LEADER_0);
}


/** 
 * @Description
 *      This function disables close the gate functionality
 *      should be called from the last driver that unloads
 *      (unless recovery is in progress)
 * 
 * @param pdev
 */
void lm_er_disable_close_the_gate(lm_device_t *pdev)
{
    u32_t val;

    DbgMessage(pdev, INFORMer, "Disabling \"close the gates\"\n");

    if (CHIP_IS_E2(pdev) || CHIP_IS_E3(pdev))
    {
        val = REG_RD(pdev, MISC_REG_AEU_GENERAL_MASK);
        val &= ~(MISC_AEU_GENERAL_MASK_REG_AEU_PXP_CLOSE_MASK |
             MISC_AEU_GENERAL_MASK_REG_AEU_NIG_CLOSE_MASK);
        REG_WR(pdev, MISC_REG_AEU_GENERAL_MASK, val);
    }
}

/* Close gates #2, #3 and #4: */
static void lm_er_set_234_gates(lm_device_t *pdev, u8_t close_g8)
{
    u32_t val, enable_bit;

    enable_bit = close_g8? 1 : 0;
   
    /* close gate #4 */
    REG_WR(pdev, PXP_REG_HST_DISCARD_DOORBELLS, enable_bit);
           
    /* close gate #2 */
    REG_WR(pdev, PXP_REG_HST_DISCARD_INTERNAL_WRITES, enable_bit);

    /* close gate #3 (this will disable new interrupts */
    val = REG_RD(pdev, IGU_REG_BLOCK_CONFIGURATION);
    close_g8? RESET_FLAGS(val, IGU_BLOCK_CONFIGURATION_REG_BLOCK_ENABLE) : 
        SET_FLAGS(val, IGU_BLOCK_CONFIGURATION_REG_BLOCK_ENABLE);
    
    REG_WR(pdev, IGU_REG_BLOCK_CONFIGURATION, val);
    

    DbgMessage(pdev, FATAL, "%s gates #2, #3 and #4\n",
        close_g8 ? "closing" : "opening");
    
}


static void lm_er_pxp_prep(lm_device_t *pdev)
{
    if (!CHIP_IS_E1(pdev)) 
    {
        REG_WR(pdev, PXP2_REG_RD_START_INIT, 0);
        REG_WR(pdev, PXP2_REG_RQ_RBC_DONE, 0);
    }
}

/*
 * Reset the whole chip except for:
 *      - PCIE core
 *      - PCI Glue, PSWHST, PXP/PXP2 RF (all controlled by
 *              one reset bit)
 *      - IGU
 *      - MISC (including AEU)
 *      - GRC
 *      - RBCN, RBCP
 * Reset MCP ONLY if reset_mcp is TRUE
 */
static void lm_er_process_kill_chip_reset(lm_device_t *pdev, u8_t reset_mcp)
{
    u32_t not_reset_mask1, reset_mask1, not_reset_mask2, reset_mask2;

    not_reset_mask1 =
        MISC_REGISTERS_RESET_REG_1_RST_HC |
        MISC_REGISTERS_RESET_REG_1_RST_PXPV |
        MISC_REGISTERS_RESET_REG_1_RST_PXP;

    not_reset_mask2 =
        MISC_REGISTERS_RESET_REG_2_RST_PCI_MDIO |
        MISC_REGISTERS_RESET_REG_2_RST_EMAC0_HARD_CORE |
        MISC_REGISTERS_RESET_REG_2_RST_EMAC1_HARD_CORE |
        MISC_REGISTERS_RESET_REG_2_RST_MISC_CORE |
        MISC_REGISTERS_RESET_REG_2_RST_RBCN |
        MISC_REGISTERS_RESET_REG_2_RST_GRC  |
        MISC_REGISTERS_RESET_REG_2_RST_MCP_N_RESET_REG_HARD_CORE |
        MISC_REGISTERS_RESET_REG_2_RST_MCP_N_HARD_CORE_RST_B;

    
    reset_mask1 = 0xffffffff;
    reset_mask2 = 0x1ffff;

    if (!reset_mcp)
    {
        RESET_FLAGS(reset_mask2, MISC_REGISTERS_RESET_REG_2_RST_MCP_N_RESET_CMN_CPU);
        RESET_FLAGS(reset_mask2, MISC_REGISTERS_RESET_REG_2_RST_MCP_N_RESET_CMN_CORE);
    }

    if (CHIP_IS_E3(pdev)) /* Maybe some day... */
    {
        reset_mask2 |= MISC_REGISTERS_RESET_REG_2_MSTAT0;
        reset_mask2 |= MISC_REGISTERS_RESET_REG_2_MSTAT1;
    }

    /* CQ54250, CQ54294, CQ54298, CQ54396	
     * Error Recovery: break at evbda!lm_dmae_command+960 during error recovery, 
     * REG_1 must be called after reg_2 so that QM is reset AFTER PXP, this is because
     * resetting QM cancels close the gates, initiates request to PXP 
     * <Ofer Zipin>: theory when QM is reset before PXP: 'close the gates' is de-activated shortly before resetting PXP.
     * PSWRQ sends a write request to PGLUE. Then PXP is reset (PGLUE is not reset). 
     * PGLUE tries to read the payload data from PSWWR, but PSWWR does not respond. The write queue in PGLUE will be stuck.
     */
   
    REG_WR(pdev, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_CLEAR,
           reset_mask2 & (~not_reset_mask2));

    REG_WR(pdev, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_1_CLEAR,
           reset_mask1 & (~not_reset_mask1));
    /* Take blocks out of reset */
    REG_WR(pdev, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_2_SET, reset_mask2);
        
    REG_WR(pdev, GRCBASE_MISC + MISC_REGISTERS_RESET_REG_1_SET, reset_mask1);


    
}

/** 
 * @Description 
 *      13.2 Poll for Tetris buffer to empty. PSWWR FIFOs are
 *      not guaraneteed to empty. wait for all Glue tags to
 *      become unused (all read completions have returned).
 * 
 * @param pdev
 * 
 * @return lm_status_t
 */
static lm_status_t lm_er_empty_tetris_buffer(lm_device_t * pdev)
{
    u32_t cnt            = 1000;
    u32_t sr_cnt         = 0;
    u32_t blk_cnt        = 0;
    u32_t port_is_idle_0 = 0;
    u32_t port_is_idle_1 = 0;
    u32_t pgl_exp_rom2   = 0;
    u32_t pgl_b_reg_tags = 0;
    
    do {
        sr_cnt  = REG_RD(pdev, PXP2_REG_RD_SR_CNT);
        blk_cnt = REG_RD(pdev, PXP2_REG_RD_BLK_CNT);
        port_is_idle_0 = REG_RD(pdev, PXP2_REG_RD_PORT_IS_IDLE_0);
        port_is_idle_1 = REG_RD(pdev, PXP2_REG_RD_PORT_IS_IDLE_1);
        pgl_exp_rom2 = REG_RD(pdev, PXP2_REG_PGL_EXP_ROM2);
        pgl_b_reg_tags = REG_RD(pdev, PGLUE_B_REG_TAGS_63_32);

        if (TRUE 
            && (sr_cnt >= 0x7e) 
            && (blk_cnt == 0xa0) 
            && ((port_is_idle_0 & 0x1) == 0x1) 
            && ((port_is_idle_1 & 0x1) == 0x1) 
            && (pgl_exp_rom2 == 0xffffffff)
            && (!CHIP_IS_E3(pdev) || (pgl_b_reg_tags == 0xffffffff)))
        {
            break;
        }
        mm_wait(pdev, 1000);
    } while (cnt-- > 0);

    if (cnt == 0) {
        DbgMessage(pdev, FATAL, "Tetris buffer didn't get empty or there are still outstanding read requests after 1s!\n");
        DbgMessage(pdev, FATAL, "sr_cnt=0x%08x, blk_cnt=0x%08x, port_is_idle_0=0x%08x, port_is_idle_1=0x%08x, pgl_exp_rom2=0x%08x\n",
              sr_cnt, blk_cnt, port_is_idle_0, port_is_idle_1, pgl_exp_rom2);
        return LM_STATUS_BUSY;
    }

    return LM_STATUS_SUCCESS;
}


/** 
 * @Description 
 *      13.5.   Poll for IGU VQ to become empty
 * 
 * @param pdev
 * 
 * @return lm_status_t
 */
static lm_status_t lm_er_poll_igu_vq(lm_device_t * pdev)
{
    u32_t cnt       = 1000;
    u32_t pend_bits = 0;
    
    do {
        pend_bits  = REG_RD(pdev, IGU_REG_PENDING_BITS_STATUS);

        if (pend_bits == 0)
        {
            break;
        }
        mm_wait(pdev, 1000);
    } while (cnt-- > 0);

    if (cnt == 0) {
        DbgMessage(pdev, FATAL, "Still pending IGU requests pend_bits=%x!\n", pend_bits);
        
        return LM_STATUS_BUSY;
    }

    return LM_STATUS_SUCCESS;
}

/** 
 * @Description 
 *      This section is based on E2 Recovery Flows Design
 *      document by Yuval Eliyahu. Section 12.2 (process kill)
 *      item #13. Number below refer to items inside item #13.
 *      Some modifications were made to accomidate to E2.
 * 
 * @param pdev
 * 
 * @return lm_status_t
 */
static lm_status_t lm_er_process_kill(lm_device_t *pdev, u8_t reset_mcp)
{
    lm_status_t lm_status = LM_STATUS_FAILURE;
    u32_t magic_val = 0;
    
    /* 13.2 Empty the Tetris buffer, wait for 1s TODO_ER: is this needed for E2? */
    lm_status = lm_er_empty_tetris_buffer(pdev);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    /* 13.3, 13.4 Close gates #2, #3 and #4 */
    lm_er_set_234_gates(pdev, TRUE);

    /* 13.5 Poll for IGU VQ to become empty */
    lm_status = lm_er_poll_igu_vq(pdev);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }
    
    /* 13.6 Indicate that "process kill" is in progress to MCP TODO_ER: how/why?  */

    /* 13.7 Clear "unprepared" bit */
    REG_WR(pdev, MISC_REG_UNPREPARED, 0);

    /* 13.8 Wait for 1ms to empty GLUE and PCI-E core queues,
     * PSWHST, GRC and PSWRD Tetris buffer.
     */
    mm_wait(pdev, 1000);

    /* Prepare to chip reset: */
    /* MCP */
    if (reset_mcp)
    {
        lm_reset_mcp_prep(pdev, &magic_val);
    }

    /* 13.11.1 PXP preparations TODO_ER: should this really be called before or only after
     * spec says after, bnx2x implementation does this before as well.  */
    lm_er_pxp_prep(pdev);

    /* 13.9 reset the chip */
    /* 13.10 check that PSWRD, PSWRQ, PSWWR are reset : handled in function  */
    lm_er_process_kill_chip_reset(pdev, reset_mcp);

   
    /* 13.11 Recover after reset: */
    /* MCP */
    if (reset_mcp)
    {
        lm_status = lm_reset_mcp_comp(pdev, magic_val);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }

    /* Reset the loader for no-mcp mode, mcp has been reset!! */
    lm_loader_reset(pdev);
        
    /* 13.11.1.2 PXP */

    // PXP2 initialization skipped here to address CQ61863: 
    //  - PXP2 must not be re-initialized.
    //  - Starting MCP 7.0.45, PXP2 is initialized by MCP.

    //lm_er_pxp_prep(pdev);

    /* 13.11.2 Open the gates #2, #3 and #4 */
    lm_er_set_234_gates(pdev, FALSE);

    /* 13.11.3 TODO_ER:  IGU/AEU preparation bring back the AEU/IGU to a
     * reset state, re-enable attentions. This is done in "init" */

    /* Clear the general attention used to notify second engine */
    REG_WR(pdev, MISC_REG_AEU_GENERAL_ATTN_20 , 0);
    /* Some Notes: 
     * 1. parity bits will be cleard for blocks that are being reset, so no need to take care of it... 
     * 2. MCP notification isn't handled yet, when it is leader will need to nofity mcp reset is done.
     */
    return 0;
}


/** 
 * @Description 
 *     Perform the error recovery leader process kill flow. 
 * 
 * @param pdev
 * 
 * @return lm_status_t SUCCESS or FAILURE
 */
lm_status_t lm_er_leader_reset(lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u32_t       cnt       = 1;
    u8_t        reset_mcp = FALSE;
    u8_t        function_of_opposite_path = 0;

    /* Try to recover after the failure */
    /* need to recover on both paths using pretend */
    function_of_opposite_path = !PATH_ID(pdev);
    do
    {
        lm_status = lm_er_process_kill(pdev, reset_mcp);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            break;
        }

        /* Pretend to the other path... */
        if (!reset_mcp)
        {
            lm_pretend_func(pdev, function_of_opposite_path); 
            /* Only second go should reset MCP, so that the second engine doesn't get out of close-dg8 before the process is done */
            reset_mcp = TRUE; 
        }
    } while (cnt--);

    /* in anycase pretend back... */
    lm_pretend_func(pdev, ABS_FUNC_ID(pdev));    

    return lm_status;
}

/** 
 * @Description 
 *      This function notifies the second engine that a
 *      attention occured and error recovery will initiate on
 *      second engine as well. Only the leader does this meaning
 *      that the second engine either hasn't seen that there was
 *      an error, or seen it and is waiting (won't initiate
 *      leader reset) which means it won't see it anyway... 
 * @param pdev
 * 
 * @return lm_status_t
 */
lm_status_t lm_er_notify_other_path(lm_device_t *pdev)
{
    u8_t function_of_opposite_path = 0;
    
    DbgMessage(pdev, FATAL, "lm_er_notify_other_path\n");
    /* Pretend to the other path... */
    function_of_opposite_path = lm_er_get_first_func_of_opp_path(pdev);
    if (function_of_opposite_path != 0xFF)
    {
        lm_pretend_func(pdev, function_of_opposite_path); 
    
        REG_WR(pdev, MISC_REG_AEU_GENERAL_ATTN_20 , 1);
        
        /* in anycase pretend back... */
        lm_pretend_func(pdev, ABS_FUNC_ID(pdev));    
    } 
    else 
    {
        DbgMessage(pdev, FATAL, "No ebnabled functions on path%d, the pah is not notfied about ER\n",!PATH_ID(pdev));
    }
    
    return LM_STATUS_SUCCESS;
}

/** 
 * @Description     
 *      This function attaches attentions to NIG / PXP
 *      close-the-g8, any attention that is added here should
 *      also be added to the lm_recoverable_error function. 
 * @param pdev
 */
void lm_er_config_close_the_g8(lm_device_t *pdev)
{
    u32_t val;

    if (!pdev->params.enable_error_recovery || CHIP_IS_E1x(pdev))
    {
        return;
    }
    
    /* HW Attentions (Except Parity which is configured by init-tool / reset-values ) */
    
    /* QM Block */
    val = REG_RD(pdev, MISC_REG_AEU_ENABLE2_NIG_0);
    SET_FLAGS(val, AEU_INPUTS_ATTN_BITS_QM_HW_INTERRUPT); /* QM HW Interrupt */
    REG_WR(pdev, MISC_REG_AEU_ENABLE2_NIG_0, val);
    
    val = REG_RD(pdev, MISC_REG_AEU_ENABLE2_PXP_0);
    SET_FLAGS(val, AEU_INPUTS_ATTN_BITS_QM_HW_INTERRUPT); /* QM HW Interrupt */
    REG_WR(pdev, MISC_REG_AEU_ENABLE2_PXP_0, val);

    /* General Attention 20 (error recovery attention) */
    val = REG_RD(pdev, MISC_REG_AEU_ENABLE4_NIG_0);
    SET_FLAGS(val, AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN20); /* general attention 20 */
    REG_WR(pdev, MISC_REG_AEU_ENABLE4_NIG_0, val);
    
    val = REG_RD(pdev, MISC_REG_AEU_ENABLE4_PXP_0);
    SET_FLAGS(val, AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN20); /* general attention 20 */
    REG_WR(pdev, MISC_REG_AEU_ENABLE4_PXP_0, val);
   
}

u32_t lm_er_get_func_bit(struct _lm_device_t *pdev)
{
    u32_t func_bit = 1 << ABS_FUNC_ID(pdev);
    return func_bit;
}

u32_t lm_er_get_number_of_functions(u32_t er_register)
{
    u8_t i = 0;
    u32_t func_num = 0;
    for (i = 0; i < MAX_FUNC_NUM; i++)
    {
        if (er_register & (1 << i))
        {
            func_num++;
        }
    }
    return func_num;
}

u8_t lm_er_get_first_func_of_opp_path(struct _lm_device_t *pdev)
{
    lm_status_t lm_status           = LM_STATUS_SUCCESS;
    u32_t       por_aux_register    = 0;
    u8_t        opposite_path       = 0;
    u8_t        i                   = 0;
    u8_t        func_of_opp_path    = 0xFF;

    if (IS_ASSIGNED_TO_VM_PFDEV(pdev)) 
    {
        lm_status = lm_hw_lock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG, TRUE);
        if (LM_STATUS_SUCCESS == lm_status)
        {
            por_aux_register = REG_RD(pdev, LM_ERROR_RECOVERY_COUNTER_HW_REGISTER); 
            lm_status = lm_hw_unlock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG);
            if (LM_STATUS_SUCCESS != lm_status)
            {
                DbgBreakMsg("Failed to release HW Recovery Counter lock.\n");
            }
            opposite_path = !PATH_ID(pdev);
            for (i = 0; i < MAX_FUNC_NUM/2; i++)
            {
                if (por_aux_register & (1 << (i*2 + opposite_path)))
                {
                    func_of_opp_path = i*2 + opposite_path;
                    break;
                }
            }
        }
        else
        {
            DbgBreakMsg("Failed to acquire HW Recovery Counter lock.\n");
        }
    }
    else
    {
        func_of_opp_path = !PATH_ID(pdev);
    }
    return func_of_opp_path;
}

u32_t lm_er_inc_load_cnt(lm_device_t *pdev, u8_t sync_it)
{
    lm_status_t             lm_status = LM_STATUS_SUCCESS;
    u32_t                   counter = 0;
    u32_t                   por_aux_register = 0;
    u32_t                   func_er_bit = 0;

    if (sync_it) 
    {
        lm_status = lm_hw_lock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG, TRUE);
    }
    
    if (LM_STATUS_SUCCESS == lm_status)
    {
        por_aux_register = REG_RD(pdev, LM_ERROR_RECOVERY_COUNTER_HW_REGISTER); 
        func_er_bit = lm_er_get_func_bit(pdev);
        if ((por_aux_register & func_er_bit))
        {
            if (sync_it) 
            {
                lm_status = lm_hw_unlock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG);
            }
            DbgMessage(pdev, FATAL, "HW Recovery bit was not cleared in previous session.\n");
            pdev->debug_info.er_bit_is_set_already = TRUE;
            pdev->debug_info.er_bit_from_previous_sessions++;
        }
        else
        {
            por_aux_register |= func_er_bit;
            REG_WR(pdev, LM_ERROR_RECOVERY_COUNTER_HW_REGISTER, por_aux_register);
            pdev->debug_info.er_bit_is_set_already = FALSE;
            if (sync_it) 
            {
                lm_status = lm_hw_unlock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG);
            }
        }
        if (LM_STATUS_SUCCESS != lm_status)
        {
            DbgBreakMsg("Failed to release HW Recovery Counter lock.\n");
        }
        counter = lm_er_get_number_of_functions(por_aux_register);
    }
    else
    {
        DbgBreakMsg("Failed to acquire HW Recovery Counter lock.\n");
    }
    return counter;
}

u32_t lm_er_dec_load_cnt(lm_device_t *pdev, u8_t sync_it)
{
    lm_status_t             lm_status = LM_STATUS_SUCCESS;
    u32_t                   counter = 0;
    u32_t                   por_aux_register = 0;
    u32_t                   func_er_bit = 0;

    if (sync_it) 
    {
        lm_status = lm_hw_lock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG, TRUE);
    }
    
    if (LM_STATUS_SUCCESS == lm_status)
    {
        por_aux_register = REG_RD(pdev, LM_ERROR_RECOVERY_COUNTER_HW_REGISTER); 
        func_er_bit = lm_er_get_func_bit(pdev);
        if (!(por_aux_register & func_er_bit))
        {
            if (sync_it) 
            {
                lm_status = lm_hw_unlock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG);
            }
            DbgMessage(pdev, FATAL, "HW Recovery bit is clear already.\n");
        }
        else
        {
            por_aux_register &= ~func_er_bit;
            REG_WR(pdev, LM_ERROR_RECOVERY_COUNTER_HW_REGISTER, por_aux_register);
            if (sync_it) 
            {
                lm_status = lm_hw_unlock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG);
            }
        }
        if (LM_STATUS_SUCCESS != lm_status)
        {
            DbgBreakMsg("Failed to release HW Recovery Counter lock.\n");
        }
        counter = lm_er_get_number_of_functions(por_aux_register);
    }
    else
    {
        DbgBreakMsg("Failed to acquire HW Recovery Counter lock.\n");
    }
    return counter;
}

u32_t lm_er_get_load_cnt(lm_device_t *pdev, u8_t sync_it)
{
    lm_status_t             lm_status = LM_STATUS_SUCCESS;
    u32_t                   counter = 0;
    u32_t                   por_aux_register = 0;

    if (sync_it) 
    {
        lm_status = lm_hw_lock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG, TRUE);
    }
    
    if (LM_STATUS_SUCCESS == lm_status)
    {
        por_aux_register = REG_RD(pdev, LM_ERROR_RECOVERY_COUNTER_HW_REGISTER); 
        if (sync_it) 
        {
            lm_status = lm_hw_unlock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG);
            if (LM_STATUS_SUCCESS != lm_status)
            {
                DbgBreakMsg("Failed to release HW Recovery Counter lock.\n");
            }
        }
        counter = lm_er_get_number_of_functions(por_aux_register);
    }
    else
    {
        DbgBreakMsg("Failed to acquire HW Recovery Counter lock.\n");
    }
    return counter;
}

void lm_er_clear_load_cnt(lm_device_t *pdev, u8_t sync_it)
{
    lm_status_t             lm_status = LM_STATUS_SUCCESS;

    if (sync_it) 
    {
        lm_status = lm_hw_lock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG, TRUE);
    }
    if (LM_STATUS_SUCCESS == lm_status)
    {
        REG_WR(pdev, LM_ERROR_RECOVERY_COUNTER_HW_REGISTER, 0); 
        if (sync_it) 
        {
            lm_status = lm_hw_unlock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG);
            if (LM_STATUS_SUCCESS != lm_status)
            {
                DbgBreakMsg("Failed to release HW Recovery Counter lock.\n");
            }
        }
    }
    else
    {
        DbgBreakMsg("Failed to acquire HW Recovery Counter lock.\n");
    }
}

void lm_er_set_recover_done(lm_device_t *pdev, u8_t sync_it)
{
    lm_status_t             lm_status = LM_STATUS_SUCCESS;
    u32_t                   por_aux_register = 0;
   
    
    DbgMessage(pdev, FATAL, "Setting recovery in progress = 0\n");
    if (sync_it) 
    {
        lm_status = lm_hw_lock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG, TRUE);
    }
    if (LM_STATUS_SUCCESS == lm_status)
    {
        por_aux_register = REG_RD(pdev, LM_ERROR_RECOVERY_COUNTER_HW_REGISTER); 
        por_aux_register &= ~LM_ERROR_RECOVERY_IN_PROGRESS_FLAG;
        REG_WR(pdev, LM_ERROR_RECOVERY_COUNTER_HW_REGISTER, por_aux_register);
        if (sync_it) 
        {
            lm_status = lm_hw_unlock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG);
            if (LM_STATUS_SUCCESS != lm_status)
            {
                DbgBreakMsg("Failed to release HW Recovery Counter lock.\n");
            }
        }
    }
    else
    {
        DbgBreakMsg("Failed to acquire HW Recovery Counter lock.\n");
    }
}

void lm_er_set_recover_in_progress(lm_device_t *pdev, u8_t sync_it)
{
    lm_status_t             lm_status = LM_STATUS_SUCCESS;
    u32_t                   por_aux_register = 0;
    
    DbgMessage(pdev, FATAL, "Setting recovery in progress = 1\n");
    if (sync_it) 
    {
        lm_status = lm_hw_lock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG, TRUE);
    }
    if (LM_STATUS_SUCCESS == lm_status)
    {
        por_aux_register = REG_RD(pdev, LM_ERROR_RECOVERY_COUNTER_HW_REGISTER); 
        por_aux_register |= LM_ERROR_RECOVERY_IN_PROGRESS_FLAG;
        REG_WR(pdev, LM_ERROR_RECOVERY_COUNTER_HW_REGISTER, por_aux_register);
        if (sync_it) 
        {
            lm_status = lm_hw_unlock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG);
            if (LM_STATUS_SUCCESS != lm_status)
            {
                DbgBreakMsg("Failed to release HW Recovery Counter lock.\n");
            }
        }
    }
    else
    {
        DbgBreakMsg("Failed to acquire HW Recovery Counter lock.\n");
    }
}


u8_t lm_er_recovery_in_progress(lm_device_t *pdev, u8_t sync_it)
{
    lm_status_t             lm_status = LM_STATUS_SUCCESS;
    u32_t                   por_aux_register = 0;
    u8_t                    is_progress = FALSE; 

    if (sync_it) 
    {
        lm_status = lm_hw_lock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG, TRUE);
    }
    if (LM_STATUS_SUCCESS == lm_status)
    {
        por_aux_register = REG_RD(pdev, LM_ERROR_RECOVERY_COUNTER_HW_REGISTER); 
        if (sync_it) 
        {
            lm_status = lm_hw_unlock(pdev, HW_LOCK_RESOURCE_RECOVERY_REG);
            if (LM_STATUS_SUCCESS != lm_status)
            {
                DbgBreakMsg("Failed to release HW Recovery Counter lock.\n");
            }
        }
        if (por_aux_register & LM_ERROR_RECOVERY_IN_PROGRESS_FLAG)
        {
            is_progress = TRUE;
        }
    }
    else
    {
        DbgBreakMsg("Failed to acquire HW Recovery Counter lock.\n");
    }
    return is_progress;
}

