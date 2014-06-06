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
 *      This file contains functions that handle HW and FW attention
 *
 ******************************************************************************/

#include "lm5710.h"
#include "general_atten_bits.h"
#include "aeu_inputs.h"
#include "command.h"

static INLINE void lm_inc_er_debug_idx(lm_device_t * pdev)
{
    pdev->debug_info.curr_er_debug_idx++;
    if (pdev->debug_info.curr_er_debug_idx == MAX_ER_DEBUG_ENTRIES)
    {
        pdev->debug_info.curr_er_debug_idx=0;
    }
}

/**
 * @description
 *      called from attention handling routines, checks if the
 *      attention received is an error which is recoverable via
 *      process kill. If error recovery is disabled this
 *      function always returns FALSE;
 *
 * @param pdev
 * @param attn_sig : values of the after_invert registers read
 *                 in the misc that indicate which attention
 *                 occured
 *
 *
 * @return u8_t TRUE: attention requires process_kill. FALSE o/w
 */
u8_t lm_recoverable_error(lm_device_t *pdev, u32_t * attn_sig, u32_t arr_size)
{
    lm_er_debug_info_t * debug_info = NULL;
    u32_t                i;

    if (!pdev->params.enable_error_recovery || CHIP_IS_E1x(pdev))
    {
        return FALSE;
    }

    ASSERT_STATIC(ARRSIZE(debug_info->attn_sig) >= MAX_ATTN_REGS);
    DbgBreakIf(arr_size < MAX_ATTN_REGS);

    if ((attn_sig[0] & HW_PRTY_ASSERT_SET_0) || (attn_sig[1] & HW_PRTY_ASSERT_SET_1) ||
        (attn_sig[2] & HW_PRTY_ASSERT_SET_2) || (attn_sig[3] & HW_PRTY_ASSERT_SET_3))
    {
        /* Parity Error... Assuming we only enable parities we can deal with
         * this is a recoverable error...
         */
        debug_info = &((pdev)->debug_info.er_debug_info[pdev->debug_info.curr_er_debug_idx]);
        for (i = 0; i < arr_size; i++)
        {
            debug_info->attn_sig[i] = attn_sig[i];
        }
        lm_inc_er_debug_idx(pdev);

        /* TODO: maybe get GRCDump here in the future... */
        DbgMessage(pdev, FATAL, "lm_recoverable_error: funcid:%d, 0:0x%x, 0:0x%x, 0:0x%x, 0:0x%x\n",
                   ABS_FUNC_ID(pdev), attn_sig[0], attn_sig[1], attn_sig[2], attn_sig[3]);

        return TRUE;
    }

    /* HW Attentions (other than parity ) */
    if (attn_sig[1] & HW_INTERRUT_ASSERT_SET_1)
    {
        /* QM Interrupt is recoverable */
        if (attn_sig[1] & AEU_INPUTS_ATTN_BITS_QM_HW_INTERRUPT)
        {
            debug_info = &((pdev)->debug_info.er_debug_info[pdev->debug_info.curr_er_debug_idx]);
            for (i = 0; i < arr_size; i++)
            {
                debug_info->attn_sig[i] = attn_sig[i];
            }
            lm_inc_er_debug_idx(pdev);

            DbgMessage(pdev, FATAL, "lm_recoverable_error: funcid:%d, 0:0x%x, 0:0x%x, 0:0x%x, 0:0x%x\n",
                   ABS_FUNC_ID(pdev), attn_sig[0], attn_sig[1], attn_sig[2], attn_sig[3]);
            return TRUE;
        }

    }

    if (attn_sig[3] & EVEREST_GEN_ATTN_IN_USE_MASK)
    {
        if ( GENERAL_ATTEN_OFFSET(ERROR_RECOVERY_ATTENTION_BIT) & attn_sig[3])
        {
            debug_info = &((pdev)->debug_info.er_debug_info[pdev->debug_info.curr_er_debug_idx]);
            for (i = 0; i < arr_size; i++)
            {
                debug_info->attn_sig[i] = attn_sig[i];
            }
            lm_inc_er_debug_idx(pdev);

            DbgMessage(pdev, FATAL, "lm_recoverable_error: funcid:%d, 0:0x%x, 0:0x%x, 0:0x%x, 0:0x%x\n",
                   ABS_FUNC_ID(pdev), attn_sig[0], attn_sig[1], attn_sig[2], attn_sig[3]);
            return TRUE;
        }
    }

    return FALSE;
}

void enable_blocks_attention(struct _lm_device_t *pdev)
{
    u32_t val = 0;

    REG_WR(pdev,PXP_REG_PXP_INT_MASK_0,0);
    if (!CHIP_IS_E1x(pdev))
    {
        REG_WR(pdev,PXP_REG_PXP_INT_MASK_1, (PXP_PXP_INT_MASK_1_REG_HST_INCORRECT_ACCESS
                                             | PXP_PXP_INT_MASK_1_REG_HST_VF_DISABLED_ACCESS /*Temporary solution*/
                                             | PXP_PXP_INT_MASK_1_REG_HST_PERMISSION_VIOLATION) /*Win8 MMIO (security test)???*/);
    }
    REG_WR(pdev,DORQ_REG_DORQ_INT_MASK,0);
    /* CFC_REG_CFC_INT_MASK see in init_cfc_common */


    //mask read length error interrupts in brb for parser (parsing unit and 'checksum and crc' unit)
    //these errors are legal (PU reads fixe length and CAC can cause read length error on truncated packets)
    REG_WR(pdev,BRB1_REG_BRB1_INT_MASK ,0xFC00);

    REG_WR(pdev,QM_REG_QM_INT_MASK ,0);
    REG_WR(pdev,TM_REG_TM_INT_MASK ,0);
    REG_WR(pdev,XSDM_REG_XSDM_INT_MASK_0 ,0);
    REG_WR(pdev,XSDM_REG_XSDM_INT_MASK_1 ,0);
    REG_WR(pdev,XCM_REG_XCM_INT_MASK ,0);
    //REG_WR(pdev,XSEM_REG_XSEM_INT_MASK_0 ,0);
    //REG_WR(pdev,XSEM_REG_XSEM_INT_MASK_1 ,0);
    REG_WR(pdev,USDM_REG_USDM_INT_MASK_0 ,0);
    REG_WR(pdev,USDM_REG_USDM_INT_MASK_1 ,0);
    REG_WR(pdev,UCM_REG_UCM_INT_MASK ,0);
    //REG_WR(pdev,USEM_REG_USEM_INT_MASK_0 ,0);
    //REG_WR(pdev,USEM_REG_USEM_INT_MASK_1 ,0);
    REG_WR(pdev,GRCBASE_UPB+PB_REG_PB_INT_MASK ,0);
    REG_WR(pdev,CSDM_REG_CSDM_INT_MASK_0 ,0);
    REG_WR(pdev,CSDM_REG_CSDM_INT_MASK_1 ,0);
    REG_WR(pdev,CCM_REG_CCM_INT_MASK ,0);
    //REG_WR(pdev,CSEM_REG_CSEM_INT_MASK_0 ,0);
    //REG_WR(pdev,CSEM_REG_CSEM_INT_MASK_1 ,0);
    val = PXP2_PXP2_INT_MASK_0_REG_PGL_CPL_AFT  |
          PXP2_PXP2_INT_MASK_0_REG_PGL_CPL_OF |
          PXP2_PXP2_INT_MASK_0_REG_PGL_PCIE_ATTN;
    if (!CHIP_IS_E1x(pdev))
    {
        val |= PXP2_PXP2_INT_MASK_0_REG_PGL_READ_BLOCKED |
               PXP2_PXP2_INT_MASK_0_REG_PGL_WRITE_BLOCKED;
    }
    REG_WR(pdev, PXP2_REG_PXP2_INT_MASK_0, val);

    REG_WR(pdev,TSDM_REG_TSDM_INT_MASK_0 ,0);
    REG_WR(pdev,TSDM_REG_TSDM_INT_MASK_1 ,0);
    REG_WR(pdev,TCM_REG_TCM_INT_MASK ,0);
    //REG_WR(pdev,TSEM_REG_TSEM_INT_MASK_0 ,0);
    //REG_WR(pdev,TSEM_REG_TSEM_INT_MASK_1 ,0);
    REG_WR(pdev,CDU_REG_CDU_INT_MASK ,0);
    REG_WR(pdev,DMAE_REG_DMAE_INT_MASK ,0);
    //REG_WR(pdev,GRCBASE_MISC+MISC_REGISTERS_MISC_INT_MASK ,0);
    //MASK BIT 3,4
    REG_WR(pdev,PBF_REG_PBF_INT_MASK ,0X18);

}

void disable_blocks_attention(struct _lm_device_t *pdev)
{
#define MASK_VALUE_GENERATE(_val) ((u32_t)((((u64_t)0x1)<<_val)-1))
    typedef struct _block_mask_info_t
    {
        u32_t reg_offset;    /* the register offset */
        u32_t mask_value[3]; /* the mask value per hw (e1 =0 /e1.5 = 1/e2 = 2)*/
    } block_mask_info_t;

    u8_t  chip_idx   = 0;
    u32_t mask_idx   = 0;
    u32_t val        = 0;
    u32_t offset     = 0;
    u32_t mask_value = 0;

    static const block_mask_info_t init_mask_values_arr[] =
    {
        { ATC_REG_ATC_INT_MASK,           { 0,
                                            0,
                                            6 } },

        { BRB1_REG_BRB1_INT_MASK,         { 19,
                                            19,
                                            19} },

        { CCM_REG_CCM_INT_MASK,           { 11,
                                            11,
                                            11 } },

        { CDU_REG_CDU_INT_MASK,           { 7,
                                            7,
                                            7 } },

        { CFC_REG_CFC_INT_MASK,           { 2,
                                            2,
                                            2  } },

        { CSDM_REG_CSDM_INT_MASK_0,       { 32,
                                            32,
                                            32 } },

        { CSDM_REG_CSDM_INT_MASK_1,       { 10,
                                            10,
                                            11 } },

#if 0
        { CSEM_REG_CSEM_INT_MASK_0,       { 32,
                                            32,
                                            32 } },

        { CSEM_REG_CSEM_INT_MASK_1,       { 10,
                                            11,
                                            11} },

        { DBG_REG_DBG_INT_MASK,           { 2,
                                            2,
                                            2 } },
#endif //0

        { DMAE_REG_DMAE_INT_MASK,         { 2,
                                            2,
                                            2 } },

        { DORQ_REG_DORQ_INT_MASK,         { 5,
                                            5,
                                            6 } },
#if 0
        { HC_REG_HC_INT_MASK,             { 7,
                                            7,
                                            7 } },
#endif //0

        { IGU_REG_IGU_INT_MASK,           { 0,
                                            0,
                                            11 } },
#if 0
        { MISC_REGISTERS_MISC_INT_MASK,   { 4,
                                            4,
                                            8 } },

        { NIG_REGISTERS_NIG_INT_MASK_0,   { 32,
                                            32,
                                            32 } },

        { NIG_REGISTERS_NIG_INT_MASK_1,   { 2,
                                            4,
                                            14 } },

        { PB_REGISTERS_PB_INT_MASK,       { 2,
                                            2,
                                            2} },
#endif // 0

        { PBF_REG_PBF_INT_MASK,           { 5,
                                            5,
                                            7 } },

        { PGLUE_B_REG_PGLUE_B_INT_MASK,   { 0,
                                            0,
                                            9 } },
#if 0
        { PRS_REG_PRS_INT_MASK,           { 1,
                                            1,
                                            1 } },
#endif // 0

        { PXP2_REG_PXP2_INT_MASK_0,       { 25,
                                            32,
                                            32 } },

#if 0
        { PXP2_REG_PXP2_INT_MASK_1,       { 0,
                                            6,
                                            16} },
#endif //0

        { PXP_REG_PXP_INT_MASK_0,         { 32,
                                            32,
                                            32 } },

        { PXP_REG_PXP_INT_MASK_1,         { 5,
                                            5,
                                            8 } },

        { QM_REG_QM_INT_MASK,             { 2,
                                            2,
                                            14 } },
#if 0
        { SEM_FAST_REG_SEM_FAST_INT_MASK, { 1, // This offset is actually 4 different registers (per SEM)
                                            1,
                                            1} },

        { SRC_REG_SRC_INT_MASK,           { 1,
                                            3,
                                            3 } },
#endif //0

        { TCM_REG_TCM_INT_MASK,           { 11,
                                            11,
                                            11 } },

        { TM_REG_TM_INT_MASK,             { 1,
                                            1,
                                            1} },

        { TSDM_REG_TSDM_INT_MASK_0,       { 32,
                                            32,
                                            32 } },

        { TSDM_REG_TSDM_INT_MASK_1,       { 10,
                                            10,
                                            11 } },
#if 0
        { TSEM_REG_TSEM_INT_MASK_0,       { 32,
                                            32,
                                            32 } },

        { TSEM_REG_TSEM_INT_MASK_1,       { 10,
                                            11,
                                            13 } },
#endif // 0

        { UCM_REG_UCM_INT_MASK,           { 11,
                                            11,
                                            11} },

        { USDM_REG_USDM_INT_MASK_0,       { 32,
                                            32,
                                            32 } },

        { USDM_REG_USDM_INT_MASK_1,       { 10,
                                            10,
                                            11 } },
#if 0
        { USEM_REG_USEM_INT_MASK_0,       { 32,
                                            32,
                                            32 } },

        { USEM_REG_USEM_INT_MASK_1,       { 10,
                                            11,
                                            11 } },
#endif //0

        { VFC_REG_VFC_INT_MASK,           { 0,
                                            0,
                                            1 } },

        { XCM_REG_XCM_INT_MASK,           { 14,
                                            14,
                                            14 } },

        { XSDM_REG_XSDM_INT_MASK_0,       { 32,
                                            32,
                                            32 } },

        { XSDM_REG_XSDM_INT_MASK_1,       { 10,
                                            10,
                                            11} },
#if 0
        { XSEM_REG_XSEM_INT_MASK_0,      { 32,
                                           32,
                                           32 } },

        { XSEM_REG_XSEM_INT_MASK_1,      { 10,
                                           11,
                                           13 } } ,
#endif // 0
    }; // init_mask_values_arr

    if (IS_VFDEV(pdev)) 
    {
        return;
    }
    if CHIP_IS_E1( pdev )
    {
        chip_idx = 0; // E1.0
    }
    else if CHIP_IS_E1H(pdev)
    {
        chip_idx = 1; // E1.5
    }
    else if CHIP_IS_E2E3(pdev)
    {
        chip_idx = 2; // E2
    }
    else
    {
        // New chip!!!
        DbgBreakIf(1); // E??
    }

    DbgBreakIf( chip_idx >= ARRSIZE( init_mask_values_arr[0].mask_value ) );

    for( mask_idx = 0; mask_idx < ARRSIZE(init_mask_values_arr);  mask_idx++ )
    {
        mask_value = init_mask_values_arr[mask_idx].mask_value[chip_idx] ;

        if( mask_value )
        {
            val        = MASK_VALUE_GENERATE(mask_value);
            offset     = init_mask_values_arr[mask_idx].reg_offset;
            REG_WR(pdev, offset, val );
        }
    }
    /*

    REG_WR(pdev,PXP_REG_PXP_INT_MASK_0,0xffffffff);
    if (IS_E2(pdev)) {
        REG_WR(pdev,PXP_REG_PXP_INT_MASK_1,0xff);
    } else {
    REG_WR(pdev,PXP_REG_PXP_INT_MASK_1,0x1f);
    }
    REG_WR(pdev,DORQ_REG_DORQ_INT_MASK,0x1f);
    REG_WR(pdev,CFC_REG_CFC_INT_MASK ,0x3);
    REG_WR(pdev,QM_REG_QM_INT_MASK ,0x3);
    REG_WR(pdev,TM_REG_TM_INT_MASK ,0x1);
    REG_WR(pdev,XSDM_REG_XSDM_INT_MASK_0 ,0xffffffff);
    REG_WR(pdev,XSDM_REG_XSDM_INT_MASK_1 ,0x3ff);
    REG_WR(pdev,XCM_REG_XCM_INT_MASK,0x3fff);
    //REG_WR(pdev,XSEM_REG_XSEM_INT_MASK_0 ,0);
    //REG_WR(pdev,XSEM_REG_XSEM_INT_MASK_1 ,0);
    REG_WR(pdev,USDM_REG_USDM_INT_MASK_0 ,0xffffffff);
    REG_WR(pdev,USDM_REG_USDM_INT_MASK_1 ,0x3ff);
    REG_WR(pdev,UCM_REG_UCM_INT_MASK ,0x7ff);
    //REG_WR(pdev,USEM_REG_USEM_INT_MASK_0 ,0);
    //REG_WR(pdev,USEM_REG_USEM_INT_MASK_1 ,0);
    REG_WR(pdev,GRCBASE_UPB+PB_REG_PB_INT_MASK ,0x3);
    REG_WR(pdev,CSDM_REG_CSDM_INT_MASK_0 ,0xffffffff);
    REG_WR(pdev,CSDM_REG_CSDM_INT_MASK_1 ,0x3ff);
    REG_WR(pdev,CCM_REG_CCM_INT_MASK ,0x7ff);
    //REG_WR(pdev,CSEM_REG_CSEM_INT_MASK_0 ,0);
    //REG_WR(pdev,CSEM_REG_CSEM_INT_MASK_1 ,0);

    REG_WR(pdev,PXP2_REG_PXP2_INT_MASK_0,0xffffffff);

    REG_WR(pdev,TSDM_REG_TSDM_INT_MASK_0 ,0xffffffff);
    REG_WR(pdev,TSDM_REG_TSDM_INT_MASK_1 ,0x3ff);
    REG_WR(pdev,TCM_REG_TCM_INT_MASK ,0x7ff);
    //REG_WR(pdev,TSEM_REG_TSEM_INT_MASK_0 ,0);
    //REG_WR(pdev,TSEM_REG_TSEM_INT_MASK_1 ,0);
    REG_WR(pdev,CDU_REG_CDU_INT_MASK ,0x7f);
    REG_WR(pdev,DMAE_REG_DMAE_INT_MASK ,0x3);
    //REG_WR(pdev,GRCBASE_MISC+MISC_REGISTERS_MISC_INT_MASK ,0);
    //MASK BIT 3,4
    REG_WR(pdev,PBF_REG_PBF_INT_MASK ,0x1f);
    */

    // disable MCP's attentions
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_0_OUT_0,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_0_OUT_1,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_0_OUT_2,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_0_OUT_3,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_1_OUT_0,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_1_OUT_1,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_1_OUT_2,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_1_OUT_3,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_0_OUT_4,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_0_OUT_5,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_0_OUT_6,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_0_OUT_7,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_1_OUT_4,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_1_OUT_5,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_1_OUT_6,0);
    REG_WR(pdev,MISC_REG_AEU_ENABLE4_FUNC_1_OUT_7,0);
}

void lm_reset_mask_attn(struct _lm_device_t *pdev)
{
    // mask the pxp attentions
    REG_WR(pdev,PXP_REG_PXP_INT_MASK_0,0xffffffff); // 32 bits
    if (CHIP_IS_E1x(pdev))
    {
        REG_WR(pdev,PXP_REG_PXP_INT_MASK_1,0x1f); // 5 bits
    }
    else
    {
        REG_WR(pdev,PXP_REG_PXP_INT_MASK_1,0xff); // 8 bits
    }
    REG_WR(pdev,PXP2_REG_PXP2_INT_MASK_0,0xffffffff); // 32 bits

    /* We never unmask this register so no need to re-mask it*/
    //REG_WR(pdev,PXP2_REG_PXP2_INT_MASK_1,0x3f); // 32 bits
}

static void lm_latch_attn_everest_processing(lm_device_t *pdev, u32_t sig_word_aft_inv)
{
    u32_t latch_bit_to_clr = 0;
    u32_t val              = 0;
    u32_t offset           = 0;

    //pass over all latched attentions
    offset = GENERAL_ATTEN_OFFSET(LATCHED_ATTN_RBCR);
    if ( offset & sig_word_aft_inv)
    {
        latch_bit_to_clr = 0x1;
        REG_WR(pdev, MISC_REG_AEU_CLR_LATCH_SIGNAL, latch_bit_to_clr);
        DbgMessage(pdev, FATAL, "lm_latch_attn_everest_processing: LATCHED_ATTN_RBCR received!!!\n");
        DbgBreakIfAll(1);
    }
    offset = GENERAL_ATTEN_OFFSET(LATCHED_ATTN_RBCT);
    if ( offset & sig_word_aft_inv)
    {
        latch_bit_to_clr = 0x2;
        REG_WR(pdev, MISC_REG_AEU_CLR_LATCH_SIGNAL, latch_bit_to_clr);
        DbgMessage(pdev, FATAL, "lm_latch_attn_everest_processing: LATCHED_ATTN_RBCT received!!!\n");
        DbgBreakIfAll(1);
    }
    offset = GENERAL_ATTEN_OFFSET(LATCHED_ATTN_RBCN);
    if ( offset & sig_word_aft_inv)
    {
        latch_bit_to_clr = 0x4;
        REG_WR(pdev, MISC_REG_AEU_CLR_LATCH_SIGNAL, latch_bit_to_clr);
        DbgMessage(pdev, FATAL, "lm_latch_attn_everest_processing: LATCHED_ATTN_RBCN received!!!\n");
        DbgBreakIfAll(1);
    }
    offset = GENERAL_ATTEN_OFFSET(LATCHED_ATTN_RBCU);
    if ( offset & sig_word_aft_inv)
    {
        latch_bit_to_clr = 0x8;
        REG_WR(pdev, MISC_REG_AEU_CLR_LATCH_SIGNAL, latch_bit_to_clr);
        DbgMessage(pdev, FATAL, "lm_latch_attn_everest_processing: LATCHED_ATTN_RBCU received!!!\n");
        DbgBreakIfAll(1);
    }
    offset = GENERAL_ATTEN_OFFSET(LATCHED_ATTN_RBCP);
    if ( offset & sig_word_aft_inv)
    {
        latch_bit_to_clr = 0x10;
        REG_WR(pdev, MISC_REG_AEU_CLR_LATCH_SIGNAL, latch_bit_to_clr);
        DbgMessage(pdev, FATAL, "lm_latch_attn_everest_processing: LATCHED_ATTN_RBCP received!!! \n");
        DbgBreakIfAll(1);
    }
    offset = GENERAL_ATTEN_OFFSET(LATCHED_ATTN_TIMEOUT_GRC);
    if ( offset & sig_word_aft_inv)
    {
#define GRC_TIMEOUT_MASK_ADDRESS(_val)  ( (_val)     & ((1<<19)-1)) // 0x000fffff
#define GRC_TIMEOUT_MASK_FUNCTION(_val) ( (_val>>20) & ((1<<3)-1))  // 0x00700000
#define GRC_TIMEOUT_MASK_MASTER(_val)   ( (_val>>24) & ((1<<4)-1))  // 0x0f000000

        u32_t       addr                            = 0;
        u32_t       func                            = 0;
        u32_t       master                          = 0;
        u32_t       grc_timeout_cnt                 = 0;
        u8_t        b_assert                        = TRUE;
        u8_t        b_nig_reset_called              = lm_is_nig_reset_called(pdev);
        const u32_t grc_timeout_max_ignore          = pdev->params.grc_timeout_max_ignore;

        latch_bit_to_clr = 0x20;

        // we check if nig reset was done
        if( b_nig_reset_called )
        {
            b_assert = FALSE;
        }

        if (!CHIP_IS_E1(pdev))
        {
            val    = REG_RD(pdev, MISC_REG_GRC_TIMEOUT_ATTN);
            addr   = GRC_TIMEOUT_MASK_ADDRESS(val);
            func   = GRC_TIMEOUT_MASK_FUNCTION(val);
            master = GRC_TIMEOUT_MASK_MASTER(val);

            // in non E1 we can verify it is mcp cause (due to nig probably)
            if( 2 != master ) // 2 is mcp cause
            {
                b_assert = TRUE;
            }
        }

        REG_WR(pdev, MISC_REG_AEU_CLR_LATCH_SIGNAL, latch_bit_to_clr);
        DbgMessage(pdev, FATAL, "lm_latch_attn_everest_processing: LATCHED_ATTN_TIMEOUT_GRC received!!! val=0x%08x master=0x%x func=0x%x addr=0x%xx4=0x%X)\n"
                               ,val, master, func, addr, addr*4 );

        // NOTE: we ignore b_nig_reset_called and ASSERT only according to grc_timeout_max_ignore value (default is 0x10)

        grc_timeout_cnt = lm_inc_cnt_grc_timeout_ignore(pdev, val);
        // if we are here it means we ignore the ASSERT inc counter
        if( grc_timeout_cnt >= grc_timeout_max_ignore )
        {
            b_assert = TRUE;
        }
        else
        {
            b_assert = FALSE;
        }

        if( b_assert )
        {
            DbgBreakIf(1);
        }

        if( b_nig_reset_called )
        {
            // we reset the flag (we "allow" one timeout after nig reset)
            lm_clear_nig_reset_called(pdev);
        }
    }
    offset = GENERAL_ATTEN_OFFSET(LATCHED_ATTN_RSVD_GRC);
    if ( offset & sig_word_aft_inv)
    {
        latch_bit_to_clr = 0x40;
        REG_WR(pdev, MISC_REG_AEU_CLR_LATCH_SIGNAL, latch_bit_to_clr);
        DbgMessage(pdev, FATAL, "lm_latch_attn_everest_processing: LATCHED_ATTN_RSVD_GRC received!!!\n");
        DbgBreakIfAll(1);
    }
    offset = GENERAL_ATTEN_OFFSET(LATCHED_ATTN_ROM_PARITY_MCP);
    if ( offset & sig_word_aft_inv)
    {
        latch_bit_to_clr = 0x80;
        REG_WR(pdev, MISC_REG_AEU_CLR_LATCH_SIGNAL, latch_bit_to_clr);
        val = lm_mcp_check(pdev);
        DbgMessage(pdev, FATAL, "lm_latch_attn_everest_processing: LATCHED_ATTN_ROM_PARITY_MCP received!!!\n");
        /* For E2, at the time this code was written (e2-bringup ) the parity is (somehow) expected */
        if (CHIP_IS_E1x(pdev))
        {
            DbgBreakIfAll(1);
        }
        else
        {
            DbgBreakIf(1);
        }
    }
    offset = GENERAL_ATTEN_OFFSET(LATCHED_ATTN_UM_RX_PARITY_MCP);
    if ( offset & sig_word_aft_inv)
    {
        latch_bit_to_clr = 0x100;
        REG_WR(pdev, MISC_REG_AEU_CLR_LATCH_SIGNAL, latch_bit_to_clr);
        val = lm_mcp_check(pdev);
        DbgMessage(pdev, FATAL, "lm_latch_attn_everest_processing: LATCHED_ATTN_UM_RX_PARITY_MCP received!!!\n");
        DbgBreakIfAll(1);
    }
    offset = GENERAL_ATTEN_OFFSET(LATCHED_ATTN_UM_TX_PARITY_MCP);
    if ( offset & sig_word_aft_inv)
    {
        latch_bit_to_clr = 0x200;
        REG_WR(pdev, MISC_REG_AEU_CLR_LATCH_SIGNAL, latch_bit_to_clr);
        val = lm_mcp_check(pdev);
        DbgMessage(pdev, FATAL, "lm_latch_attn_everest_processing: LATCHED_ATTN_UM_TX_PARITY_MCP received!!!\n");
        DbgBreakIfAll(1);
    }
    offset = GENERAL_ATTEN_OFFSET(LATCHED_ATTN_SCPAD_PARITY_MCP);
    if ( offset & sig_word_aft_inv)
    {
        latch_bit_to_clr = 0x400;
        REG_WR(pdev, MISC_REG_AEU_CLR_LATCH_SIGNAL, latch_bit_to_clr);
        val = lm_mcp_check(pdev);
        DbgMessage(pdev, FATAL, "lm_latch_attn_everest_processing: LATCHED_ATTN_SCPAD_PARITY_MCP received!!!\n");
        DbgBreakIfAll(1);
    }
}

static void lm_hard_wired_processing(lm_device_t *pdev, u16_t assertion_proc_flgs)
{
    /* processing of highest 8-15 bits of 8 "hard-wired" attention signals toward IGU.
       Excluding NIG & PXP "close the gates"

       ! No need to lock here since this is an uncommon group whether there is a recovery procedure or not.

       Signal name         Bit position    SOURCE       Type        Required Destination
       -----------------------------------------------------------------------------
       NIG attention for port0  D8         NIG          Event       MCP/Driver0(PHY)
       SW timer#4 port0         D9         MISC         Event       MCP -> Ignore!
       GPIO#2 port0             D10        MISC         Event       MCP
       GPIO#3 port0             D11        MISC         Event       MCP
       GPIO#4 port0             D12        MISC         Event       MCP
       General attn1            D13        GRC mapped   Attention   MCP/Driver0/Driver1 -> ASSERT!
       General attn2            D14        GRC mapped   Attention   MCP/Driver0/Driver1 -> ASSERT!
       General attn3            D15        GRC mapped   Attention   MCP/Driver0/Driver1 -> ASSERT!
    */
    //TODO: for the required attn signals, need to "clean the hw block" (INT_STS_CLR..)
    if (PORT_ID(pdev) == 0)
    {
#if 0   // Timer 4 is being used by OCBB now
        if (assertion_proc_flgs & ATTN_SW_TIMER_4_FUNC)
        {
            //DbgMessage(pdev, FATAL, "lm_hard_wired_processing: ATTN_SW_TIMER_4_FUNC!\n");
            //to deal with this signal, add dispatch func call here
        }
#endif
        if (assertion_proc_flgs & GPIO_2_FUNC)
        {
            DbgMessage(pdev, WARN, "lm_hard_wired_processing: GPIO_1_FUNC!\n");
            //to deal with this signal, add dispatch func call here
        }
        if (assertion_proc_flgs & GPIO_3_FUNC)
        {
            DbgMessage(pdev, WARN, "lm_hard_wired_processing: GPIO_2_FUNC!\n");
            //to deal with this signal, add dispatch func call here
        }
        if (assertion_proc_flgs & GPIO_4_FUNC)
        {
        DbgMessage(pdev, WARN, "lm_hard_wired_processing: GPIO_3_FUNC0!\n");
        // Will be handled in deassertion
        }
        if (assertion_proc_flgs & ATTN_GENERAL_ATTN_1)
        {
            DbgMessage(pdev, FATAL, "lm_hard_wired_processing: ATTN_GENERAL_ATTN_1! and clean it!!!\n");
            REG_WR(pdev,MISC_REG_AEU_GENERAL_ATTN_1,0x0);
        }
        if (assertion_proc_flgs & ATTN_GENERAL_ATTN_2)
        {
            DbgMessage(pdev, FATAL, "lm_hard_wired_processing: ATTN_GENERAL_ATTN_2! and clean it!!!\n");
            REG_WR(pdev,MISC_REG_AEU_GENERAL_ATTN_2,0x0);
        }
        if (assertion_proc_flgs & ATTN_GENERAL_ATTN_3)
        {
            DbgMessage(pdev, FATAL, "lm_hard_wired_processing: ATTN_GENERAL_ATTN_3! and clean it!!!\n");
            REG_WR(pdev,MISC_REG_AEU_GENERAL_ATTN_3,0x0);
        }
    }
    else
    {
        DbgBreakIf(PORT_ID(pdev) != 1);

        if (assertion_proc_flgs & ATTN_SW_TIMER_4_FUNC1)
        {
            //DbgMessage(pdev, FATAL, "lm_hard_wired_processing: ATTN_SW_TIMER_4_FUNC1!\n");
            //to deal with this signal, add dispatch func call here
        }
        if (assertion_proc_flgs & GPIO_2_FUNC1)
        {
            DbgMessage(pdev, WARN, "lm_hard_wired_processing: GPIO_1_FUNC1!\n");
            //to deal with this signal, add dispatch func call here
        }
        if (assertion_proc_flgs & GPIO_3_FUNC1)
        {
            DbgMessage(pdev, WARN, "lm_hard_wired_processing: GPIO_2_FUNC1!\n");
            //to deal with this signal, add dispatch func call here
        }
        if (assertion_proc_flgs & GPIO_4_FUNC1)
        {
            DbgMessage(pdev, WARN, "lm_hard_wired_processing: GPIO_3_FUNC1!\n");
            // Will be handled in deassertion
        }
        if (assertion_proc_flgs & ATTN_GENERAL_ATTN_4)
        {
            DbgMessage(pdev, FATAL, "lm_hard_wired_processing: ATTN_GENERAL_ATTN_4! and clean it!!!\n");
            REG_WR(pdev,MISC_REG_AEU_GENERAL_ATTN_4,0x0);
        }
        if (assertion_proc_flgs & ATTN_GENERAL_ATTN_5)
        {
            DbgMessage(pdev, FATAL, "lm_hard_wired_processing: ATTN_GENERAL_ATTN_5! and clean it!!!\n");
            REG_WR(pdev,MISC_REG_AEU_GENERAL_ATTN_5,0x0);
        }
        if (assertion_proc_flgs & ATTN_GENERAL_ATTN_6)
        {
            DbgMessage(pdev, FATAL, "lm_hard_wired_processing: ATTN_GENERAL_ATTN_6! and clean it!!!\n");
            REG_WR(pdev,MISC_REG_AEU_GENERAL_ATTN_6,0x0);
        }
    }
}

static void lm_nig_processing(lm_device_t *pdev)
{
    u32_t nig_status_port          = 0;
    u32_t unicore_val              = 0;
    u32_t is_unicore_intr_asserted = 0;
    // save nig interrupt mask and set it back later
    lm_link_update(pdev);
    if (PORT_ID(pdev) == 0)
    {
        //read the status interrupt of the NIG for the appropriate port (will do read-modify-write)
        nig_status_port = REG_RD(pdev,  NIG_REG_STATUS_INTERRUPT_PORT0);

        //pass over each of the 24 NIG REG to find out why the NIG attention was asserted.
        //every unicore interrupt read, in case it differs from the corresponding bit in the
        //NIG_REG_STATUS_INTERRUPT_PORT0, then we need to assign the value read into the apporpriate bit
        // in NIG_REG_STATUS_INTERRUPT_PORT0 register.

        //HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_EMAC0_STATUS_MISC_MI_INT, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_MI_INT, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_MI_INT_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_EMAC0_STATUS_MISC_MI_COMPLETE, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_MI_COMPLETE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_MI_COMPLETE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_EMAC0_STATUS_MISC_CFG_CHANGE, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_CFG_CHANGE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_CFG_CHANGE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_EMAC0_STATUS_MISC_LINK_STATUS, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_LINK_STATUS, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_LINK_STATUS_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_EMAC0_STATUS_MISC_LINK_CHANGE, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_LINK_CHANGE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_LINK_CHANGE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_EMAC0_STATUS_MISC_ATTN, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_ATTN, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_EMAC0_MISC_ATTN_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES0_STATUS_MAC_CRS, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_MAC_CRS, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_MAC_CRS_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES0_STATUS_AUTONEG_COMPLETE, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_AUTONEG_COMPLETE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_AUTONEG_COMPLETE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES0_STATUS_FIBER_RXACT, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_FIBER_RXACT, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_FIBER_RXACT_SIZE);
        //HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES0_STATUS_LINK_STATUS, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_LINK_STATUS, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_LINK_STATUS_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES0_STATUS_MR_PAGE_RX, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_MR_PAGE_RX, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_MR_PAGE_RX_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES0_STATUS_CL73_AN_COMPLETE, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_CL73_AN_COMPLETE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_CL73_AN_COMPLETE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES0_STATUS_CL73_MR_PAGE_RX, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_CL73_MR_PAGE_RX, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_CL73_MR_PAGE_RX_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES0_STATUS_RX_SIGDET, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_RX_SIGDET, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_SERDES0_RX_SIGDET_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS0_STATUS_REMOTEMDIOREQ, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_REMOTEMDIOREQ, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_REMOTEMDIOREQ_SIZE);
        //HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS0_STATUS_LINK10G, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_LINK10G, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_LINK10G_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS0_STATUS_AUTONEG_COMPLETE, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_AUTONEG_COMPLETE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_AUTONEG_COMPLETE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS0_STATUS_FIBER_RXACT, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_FIBER_RXACT, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_FIBER_RXACT_SIZE);
        //HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS0_STATUS_LINK_STATUS, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_LINK_STATUS, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_LINK_STATUS_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS0_STATUS_MR_PAGE_RX, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_MR_PAGE_RX, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_MR_PAGE_RX_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS0_STATUS_CL73_AN_COMPLETE, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_CL73_AN_COMPLETE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_CL73_AN_COMPLETE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS0_STATUS_CL73_MR_PAGE_RX, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_CL73_MR_PAGE_RX, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_CL73_MR_PAGE_RX_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS0_STATUS_RX_SIGDET, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_RX_SIGDET, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_RX_SIGDET_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS0_STATUS_MAC_CRS, &unicore_val, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_MAC_CRS, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT0_REG_STATUS_XGXS0_MAC_CRS_SIZE);

        //write back the updated status interrupt of the NIG for the appropriate port.
        REG_WR(pdev,  NIG_REG_STATUS_INTERRUPT_PORT0, nig_status_port);
    }
    else
    {
        DbgBreakIf(PORT_ID(pdev) != 1);
        nig_status_port = REG_RD(pdev,  NIG_REG_STATUS_INTERRUPT_PORT1);

        //HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_EMAC1_STATUS_MISC_MI_INT, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_EMAC1_MISC_MI_INT, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_EMAC1_MISC_MI_INT_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_EMAC1_STATUS_MISC_MI_COMPLETE, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_EMAC1_MISC_MI_COMPLETE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_EMAC1_MISC_MI_COMPLETE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_EMAC1_STATUS_MISC_CFG_CHANGE, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_EMAC1_MISC_CFG_CHANGE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_EMAC1_MISC_CFG_CHANGE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_EMAC1_STATUS_MISC_LINK_STATUS, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_EMAC1_MISC_LINK_STATUS, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_EMAC1_MISC_LINK_STATUS_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_EMAC1_STATUS_MISC_LINK_CHANGE, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_EMAC1_MISC_LINK_CHANGE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_EMAC1_MISC_LINK_CHANGE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_EMAC1_STATUS_MISC_ATTN, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_EMAC1_MISC_ATTN, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_EMAC1_MISC_ATTN_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES1_STATUS_MAC_CRS, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_MAC_CRS, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_MAC_CRS_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES1_STATUS_AUTONEG_COMPLETE, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_AUTONEG_COMPLETE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_AUTONEG_COMPLETE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES1_STATUS_FIBER_RXACT, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_FIBER_RXACT, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_FIBER_RXACT_SIZE);
        //HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES1_STATUS_LINK_STATUS, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_LINK_STATUS, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_LINK_STATUS_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES1_STATUS_MR_PAGE_RX, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_MR_PAGE_RX, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_MR_PAGE_RX_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES1_STATUS_CL73_AN_COMPLETE, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_CL73_AN_COMPLETE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_CL73_AN_COMPLETE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES1_STATUS_CL73_MR_PAGE_RX, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_CL73_MR_PAGE_RX, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_CL73_MR_PAGE_RX_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_SERDES1_STATUS_RX_SIGDET, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_RX_SIGDET, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_SERDES1_RX_SIGDET_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS1_STATUS_REMOTEMDIOREQ, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_REMOTEMDIOREQ, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_REMOTEMDIOREQ_SIZE);
        //HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS1_STATUS_LINK10G, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_LINK10G, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_LINK10G_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS1_STATUS_AUTONEG_COMPLETE, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_AUTONEG_COMPLETE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_AUTONEG_COMPLETE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS1_STATUS_FIBER_RXACT, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_FIBER_RXACT, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_FIBER_RXACT_SIZE);
        //HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS1_STATUS_LINK_STATUS, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_LINK_STATUS, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_LINK_STATUS_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS1_STATUS_MR_PAGE_RX, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_MR_PAGE_RX, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_MR_PAGE_RX_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS1_STATUS_CL73_AN_COMPLETE, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_CL73_AN_COMPLETE, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_CL73_AN_COMPLETE_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS1_STATUS_CL73_MR_PAGE_RX, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_CL73_MR_PAGE_RX, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_CL73_MR_PAGE_RX_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS1_STATUS_RX_SIGDET, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_RX_SIGDET, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_RX_SIGDET_SIZE);
        HANDLE_UNICORE_INT_ASSERTED(pdev, NIG_REG_XGXS1_STATUS_MAC_CRS, &unicore_val, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_MAC_CRS, &nig_status_port, &is_unicore_intr_asserted, NIG_STATUS_INTERRUPT_PORT1_REG_STATUS_XGXS1_MAC_CRS_SIZE);

        REG_WR(pdev,  NIG_REG_STATUS_INTERRUPT_PORT1, nig_status_port);

    }
}

void lm_handle_assertion_processing(lm_device_t *pdev, u16_t assertion_proc_flgs)
{
    u32_t       val           = 0;
    u32_t       port_reg_name = 0;
    u32_t       mask_val      = 0;
    u32_t       nig_mask      = 0;

    DbgMessage(pdev, INFORM, "lm_handle_assertion_processing: assertion_proc_flgs:%d\n", assertion_proc_flgs);

    //mask only appropriate attention output signals from configured routing and unifier logic toward IGU.
    //This is for driver/chip sync to eventually return to '00' monitored state
    //in both leading & trailing latch.
    //mask non-hard-wired dynamic groups only

    DbgBreakIf(pdev->vars.attn_state & assertion_proc_flgs);

    //mask relevant AEU attn lines
    //             mask  assert_flgs  new mask
    //legal:        0       0       ->    0
    //              1       0       ->    1
    //              1       1       ->    0
    //ASSERT:       0       1 -> this won't change us thanks to & ~

    ASSERT_STATIC( HW_LOCK_RESOURCE_PORT0_ATT_MASK +1 == HW_LOCK_RESOURCE_PORT1_ATT_MASK );
    ASSERT_STATIC( NIG_REG_MASK_INTERRUPT_PORT0 + 4   == NIG_REG_MASK_INTERRUPT_PORT1 );

    lm_hw_lock(pdev, HW_LOCK_RESOURCE_PORT0_ATT_MASK + PORT_ID(pdev), TRUE);
    port_reg_name = PORT_ID(pdev) ? MISC_REG_AEU_MASK_ATTN_FUNC_1 : MISC_REG_AEU_MASK_ATTN_FUNC_0;
    // read the hw current mask value
    mask_val=REG_RD(pdev, port_reg_name);
    //changed rrom XOR to & ~
    pdev->vars.aeu_mask_attn_func = mask_val & 0xff;
    DbgMessage(pdev, INFORM, "lm_handle_assertion_processing: BEFORE: aeu_mask_attn_func:0x%x\n", pdev->vars.aeu_mask_attn_func);
    //changed rrom XOR to & ~
    pdev->vars.aeu_mask_attn_func &= ~(assertion_proc_flgs & 0xff);
    REG_WR(pdev, port_reg_name, pdev->vars.aeu_mask_attn_func);
    DbgMessage(pdev, INFORM, "lm_handle_assertion_processing: AFTER : aeu_mask_attn_func:0x%x\n", pdev->vars.aeu_mask_attn_func);
    lm_hw_unlock(pdev, HW_LOCK_RESOURCE_PORT0_ATT_MASK + PORT_ID(pdev));
    //update the bits states

    //        state  assert_flgs  new state
    //legal:    0       0         -> 0
    //          0       1         -> 1
    //          1       0         -> 1
    //error:    1       1 -> this won't change us thanks to |
    DbgMessage(pdev, INFORM, "lm_handle_assertion_processing: BEFORE: attn_state:0x%x\n", pdev->vars.attn_state);
    //changed from XOR to OR for safety
    pdev->vars.attn_state |= assertion_proc_flgs;

    DbgMessage(pdev, INFORM, "lm_handle_assertion_processing: AFTER : attn_state:0x%x\n", pdev->vars.attn_state);
    //process only hard-wired lines in case any got up
    if (assertion_proc_flgs & ATTN_HARD_WIRED_MASK)
    {
        lm_hard_wired_processing(pdev, assertion_proc_flgs);
    }

    // now handle nig
    if (assertion_proc_flgs & ATTN_NIG_FOR_FUNC)
    {
        MM_ACQUIRE_PHY_LOCK(pdev);
         // save nig interrupt mask and set it back later
        nig_mask = REG_RD(pdev,  NIG_REG_MASK_INTERRUPT_PORT0 + 4*PORT_ID(pdev));
        REG_WR(pdev,  NIG_REG_MASK_INTERRUPT_PORT0 + 4*PORT_ID(pdev), 0);

        // we'll handle the attention only if mask is not 0
        // if mask is 0, it means that "old" and irrelevant is sent
        // and we should not hnalde it (e.g. CQ48990 - got link down event after loopback mode was set).
        if( nig_mask )
        {
            lm_nig_processing(pdev);
        }
        else
        {
            DbgMessage(pdev, WARN, "lm_handle_deassertion_processing: got attention when nig_mask is 0\n" );
        }
    }

    //parallel write to IGU to set the attn_ack for _all asserted_ lines.
    val = assertion_proc_flgs;

    // attntion bits set
    if (INTR_BLK_TYPE(pdev) == INTR_BLK_HC)
    {
        REG_WR(pdev,  HC_REG_COMMAND_REG + PORT_ID(pdev)*32 + COMMAND_REG_ATTN_BITS_SET,val);
    }
    else
    {
        u32_t cmd_addr = IGU_CMD_ATTN_BIT_SET_UPPER;
        if (INTR_BLK_ACCESS(pdev) == INTR_BLK_ACCESS_IGUMEM)
        {
            REG_WR(pdev, BAR_IGU_INTMEM + cmd_addr*8, val);
        }
        else
        {
            struct igu_ctrl_reg cmd_ctrl;
            u8_t                igu_func_id = 0;
            /* GRC ACCESS: */
            /* Write the Data, then the control */
             /* [18:12] - FID (if VF - [18] = 0; [17:12] = VF number; if PF - [18] = 1; [17:14] = 0; [13:12] = PF number) */
            igu_func_id = IGU_FUNC_ID(pdev);
            cmd_ctrl.ctrl_data =
                ((cmd_addr << IGU_CTRL_REG_ADDRESS_SHIFT) |
                 (igu_func_id << IGU_CTRL_REG_FID_SHIFT) |
                 (IGU_CTRL_CMD_TYPE_WR << IGU_CTRL_REG_TYPE_SHIFT));

            REG_WR(pdev, IGU_REG_COMMAND_REG_32LSB_DATA, val);
            REG_WR(pdev, IGU_REG_COMMAND_REG_CTRL, cmd_ctrl.ctrl_data);
        }
    }

    // now set back the mask
    if (assertion_proc_flgs & ATTN_NIG_FOR_FUNC)
    {
        u8_t blk_type   = INTR_BLK_TYPE(pdev);
        u8_t blk_access = INTR_BLK_ACCESS(pdev);

        if ( ( blk_type != INTR_BLK_HC ) && ( blk_access == INTR_BLK_ACCESS_IGUMEM ))
        {
            u32 cnt = 0;
            // Verify that IGU ack through BAR was written before restoring NIG mask.
            // This loop should exit after 2-3 iterations max.
            do
            {
                val = REG_RD(pdev, IGU_REG_ATTENTION_ACK_BITS);
            }
            while (((val & ATTN_NIG_FOR_FUNC) == 0) && (++cnt < MAX_IGU_ATTN_ACK_TO));

            if (!val)
            {
                DbgMessage(pdev, FATAL, "Failed to verify IGU ack on time\n");
            }
        }
        REG_WR(pdev,  NIG_REG_MASK_INTERRUPT_PORT0 + 4*PORT_ID(pdev), nig_mask);
        MM_RELEASE_PHY_LOCK(pdev);
    }
}

static u32_t lm_cfc_attn_everest_processing(lm_device_t *pdev)
{
    u32_t val, valc;
    val = REG_RD(pdev,CFC_REG_CFC_INT_STS);

    // TODO add defines here
    DbgMessage(pdev, FATAL, "CFC hw attention 0x%x\n",val);
    if (val) {
        pdev->vars.cfc_int_status_cnt++;
    // CFC error attention
    if (val & 0x2)
    {
                //DbgBreakIfAll(1);
    }
}
    valc = REG_RD(pdev,CFC_REG_CFC_INT_STS_CLR);
    return val;
}
static void lm_pxp_attn_everest_processing(lm_device_t *pdev)
{
    u32_t val = REG_RD(pdev,PXP_REG_PXP_INT_STS_0);

    // TODO add defines here
    DbgMessage(pdev, FATAL, "PXP hw attention 0x%x\n",val);
    // RQ_USDMDP_FIFO_OVERFLOW attention
    if (val & 0x18000)
    {
        DbgBreakIfAll(1);
    }

}
/*
 *Function Name:lm_spio5_attn_everest_processing
 *
 *Parameters:
 *
 *Description:
 *  Indicates fan failure on specific external_phy_config (PORT_HW_CFG_XGXS_EXT_PHY_TYPE_SFX7101)
 *Returns:
 *
 */
static void lm_spio5_attn_everest_processing(lm_device_t *pdev)
{
    u32_t      val            = 0;
    u32_t      offset         = 0;
    u32_t      ext_phy_config = 0;
    const u8_t port_id        = PORT_ID(pdev);

   // Special fan failure handling for boards with external PHY SFX7101 (which include fan)
    PHY_HW_LOCK(pdev);
    elink_hw_reset_phy(&pdev->params.link);
    PHY_HW_UNLOCK(pdev);

    offset = ( 0 == port_id ) ? MISC_REG_AEU_ENABLE1_FUNC_0_OUT_0 : MISC_REG_AEU_ENABLE1_FUNC_1_OUT_0 ;

    val = REG_RD(pdev, offset );

    DbgMessage(pdev, FATAL, "lm_spio5_attn_everest_processing: SPIO5 hw attention 0x%x\n",val);

    // mask flags so we won't get this attention anymore
    RESET_FLAGS(val, AEU_INPUTS_ATTN_BITS_SPIO5 ) ;
    REG_WR(pdev, offset, val ) ;

    // change phy_type to type failure (under phy lock)
    MM_ACQUIRE_PHY_LOCK(pdev);

    offset = OFFSETOF(shmem_region_t,dev_info.port_hw_config[port_id].external_phy_config);

    LM_SHMEM_READ(pdev, offset, &ext_phy_config);

    RESET_FLAGS(ext_phy_config, PORT_HW_CFG_XGXS_EXT_PHY_TYPE_MASK ) ;
    SET_FLAGS(ext_phy_config, PORT_HW_CFG_XGXS_EXT_PHY_TYPE_FAILURE ) ;

    // Set external phy type to failure for MCP to know about the failure
    LM_SHMEM_WRITE(pdev, offset, ext_phy_config);

    DbgMessage(pdev, WARN, "lm_spio5_attn_everest_processing: external_phy_type 0x%x\n",ext_phy_config);

    // Indicate "link-down". elink_hw_reset_phy takes care of the physical part, but part of the function
    // masks attentions, which means we won't get a link event from anywhere else. Therefore we need to
    // indicate link down at this point to OS... to supress traffic and upload toe connections...
    // we do this under lock since we change the link status...
    pdev->vars.link_status = LM_STATUS_LINK_DOWN;

    mm_indicate_link(pdev, pdev->vars.link_status, pdev->vars.medium);

    MM_RELEASE_PHY_LOCK(pdev);

    // write to the event log!
    mm_event_log_generic( pdev, LM_LOG_ID_FAN_FAILURE );

    mm_indicate_hw_failure(pdev);
}

// Check current fan failure state - report in case signaled.
void lm_check_fan_failure(struct _lm_device_t *pdev)
{
    u32_t val = 0;

    if (IS_VFDEV(pdev))
    {
        return;
    }

    val = REG_RD(pdev, MISC_REG_AEU_AFTER_INVERT_1_FUNC_0 + PORT_ID(pdev)*4);

    if( GET_FLAGS(val, AEU_INPUTS_ATTN_BITS_SPIO5))
    {
        lm_spio5_attn_everest_processing(pdev);
    }
}

// Change PMF or link change
// PMF sent link updates to all func (but himself) OR I become a PMF from MCP notification
// on some cases PMF sends link event to himself as well if errors occured in the mac.
static void lm_pmf_or_link_event(lm_device_t *pdev, u32_t drv_status)
{
    u32_t val = 0;


    DbgMessage(pdev, WARN, "lm_pmf_or_link_event: sync general attention received!!! for func%d\n",FUNC_ID(pdev));

    // sync with link
    MM_ACQUIRE_PHY_LOCK(pdev);
    elink_link_status_update(&pdev->params.link,&pdev->vars.link);
    lm_link_report(pdev);
    MM_RELEASE_PHY_LOCK(pdev);

    if (!IS_PMF(pdev) && GET_FLAGS(drv_status,DRV_STATUS_PMF))
    {
        //pmf migration
        pdev->vars.is_pmf = PMF_MIGRATION;
        // load stat from MCP
        MM_ACQUIRE_PHY_LOCK(pdev);
        lm_stats_on_pmf_update(pdev,TRUE);
        MM_RELEASE_PHY_LOCK(pdev);

        // Connect to NIG attentions
        val = (0xff0f | (1 << (VNIC_ID(pdev) + 4)));
        if (INTR_BLK_TYPE(pdev) == INTR_BLK_HC)
        {
            REG_WR(pdev,  (PORT_ID(pdev) ? HC_REG_TRAILING_EDGE_1 : HC_REG_TRAILING_EDGE_0), val);
            REG_WR(pdev,  (PORT_ID(pdev) ? HC_REG_LEADING_EDGE_1  : HC_REG_LEADING_EDGE_0) , val);
        }
        else
        {
            if (CHIP_IS_E3(pdev))
            {
                val &= ~ATTN_SW_TIMER_4_FUNC; // To prevent Timer4 expiration attention
            }
            REG_WR(pdev,  IGU_REG_TRAILING_EDGE_LATCH, val);
            REG_WR(pdev,  IGU_REG_LEADING_EDGE_LATCH, val);
        }

        if(TRUE == IS_DCB_ENABLED(pdev))
        {
            lm_dcbx_pmf_migration(pdev);
        }
    }
}

static void lm_dcc_event(lm_device_t *pdev, u32_t dcc_event)
{
    u32_t       val               = 0;
    u32_t       event_val_current = 0;
    u32_t       fw_resp           = 0 ;
    lm_status_t lm_status         = LM_STATUS_FAILURE ;

    DbgMessage(pdev, WARN, "lm_dcc_event: dcc_event=0x%x\n",dcc_event);

    if( !IS_MULTI_VNIC(pdev) )
    {
        DbgBreakIf(1);
        return;
    }

    // read shemem

    // Read new mf config from shemem
    LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].config), &val);

    pdev->hw_info.mf_info.func_mf_cfg = val ;

    // is it enable/disable
    event_val_current = DRV_STATUS_DCC_DISABLE_ENABLE_PF ;

    if GET_FLAGS( dcc_event, event_val_current )
    {
        if( GET_FLAGS( pdev->hw_info.mf_info.func_mf_cfg, FUNC_MF_CFG_FUNC_DISABLED ) )
        {
            DbgMessage(pdev, WARN, "lm_dcc_event: mf_cfg function disabled val=0x%x\n",val);

            // TODO - receive packets fronm another machine when link is down - expected - miniport drop packets
            // TBD - disable RX & TX
        }
        else
        {
            DbgMessage(pdev, WARN, "lm_dcc_event: mf_cfg function enabled val=0x%x\n",val);
            // TBD - enable RX & TX
        }
        lm_status = LM_STATUS_SUCCESS ;
        RESET_FLAGS( dcc_event, event_val_current );
    }

    event_val_current = DRV_STATUS_DCC_BANDWIDTH_ALLOCATION ;

    if GET_FLAGS(dcc_event, event_val_current)
    {
        if( !IS_PMF(pdev) )
        {
            DbgBreakIf(1);
            return;
        }
        lm_status = LM_STATUS_SUCCESS ;
        RESET_FLAGS( dcc_event, event_val_current );
    }

    /* Report results to MCP */
    if (dcc_event)
    {
        // unknown event
        lm_status = lm_mcp_cmd_send_recieve( pdev, lm_mcp_mb_header, DRV_MSG_CODE_DCC_FAILURE, 0, MCP_CMD_DEFAULT_TIMEOUT, &fw_resp ) ;
    }
    else
    {
        // we are done
        if( LM_STATUS_SUCCESS == lm_status )
        {
            // sync with link --> update min max/link for all function
            MM_ACQUIRE_PHY_LOCK(pdev);
            elink_link_status_update(&pdev->params.link,&pdev->vars.link);
            lm_link_report(pdev);
            MM_RELEASE_PHY_LOCK(pdev);
        }
        lm_status = lm_mcp_cmd_send_recieve( pdev, lm_mcp_mb_header, DRV_MSG_CODE_DCC_OK, 0, MCP_CMD_DEFAULT_TIMEOUT, &fw_resp ) ;
        //bnx2x_fw_command(bp, DRV_MSG_CODE_DCC_OK);
    }
    DbgBreakIf( lm_status != LM_STATUS_SUCCESS );
}

static lm_status_t lm_set_bandwidth_event(lm_device_t *pdev)
{
    u32_t       mcp_resp    = 0;
    lm_status_t lm_status   = LM_STATUS_SUCCESS;

    DbgBreakIf(!IS_SD_UFP_MODE(pdev) && (!IS_MULTI_VNIC(pdev) || !pdev->vars.is_pmf));

    MM_ACQUIRE_PHY_LOCK(pdev);

    //update CMNG data from SHMEM
    lm_reload_link_and_cmng(pdev);

    //acknoledge the MCP event
    lm_mcp_cmd_send_recieve(pdev,lm_mcp_mb_header, DRV_MSG_CODE_SET_MF_BW_ACK, 0, MCP_CMD_DEFAULT_TIMEOUT, &mcp_resp);

    if ( mcp_resp != FW_MSG_CODE_SET_MF_BW_DONE)
    {
        DbgBreakIf(mcp_resp != FW_MSG_CODE_SET_MF_BW_DONE);
        lm_status = LM_STATUS_FAILURE;
        goto _exit;
    }

    //indicate link change to OS, since sync_link_status does not generate a link event for the PMF.
    mm_indicate_link(pdev, pdev->vars.link_status, pdev->vars.medium);

    //notify all functions
    sync_link_status(pdev);

_exit:
    MM_RELEASE_PHY_LOCK(pdev);
    return lm_status;
}

typedef enum drv_info_opcode drv_info_opcode_t;

lm_status_t lm_stats_drv_info_to_mfw_event( struct _lm_device_t* pdev )
{
    u32_t              val             = 0;
    u32_t              drv_msg         = 0;
    u32_t              ver             = 0;
    u32_t              fw_resp         = 0 ;
    lm_status_t        lm_status       = LM_STATUS_SUCCESS ;
    drv_info_opcode_t  drv_info_op     = -1;

    if( !LM_SHMEM2_HAS(pdev, drv_info_control) )
    {
        // We should never get here...
        DbgBreakIfAll(!LM_SHMEM2_HAS(pdev, drv_info_control));
        return LM_STATUS_FAILURE;
    }

    LM_SHMEM2_READ(pdev, OFFSETOF(shmem2_region_t, drv_info_control), &val );

    ver = ( GET_FLAGS( val, DRV_INFO_CONTROL_VER_MASK ) ) >> DRV_INFO_CONTROL_VER_SHIFT ;

    do
    {
        if( DRV_INFO_CUR_VER != ver )
        {
            // We don't support this interface verison
            drv_msg = DRV_MSG_CODE_DRV_INFO_NACK;
            break;
        }

        drv_info_op = ( GET_FLAGS( val, DRV_INFO_CONTROL_OP_CODE_MASK ) ) >> DRV_INFO_CONTROL_OP_CODE_SHIFT;

        lm_status = lm_stats_drv_info_to_mfw_assign(pdev, drv_info_op );

        if( LM_STATUS_SUCCESS != lm_status )
        {
            // We don't support this interface verison/opcode
            drv_msg = DRV_MSG_CODE_DRV_INFO_NACK;
            break;
        }

        LM_SHMEM2_WRITE(pdev, OFFSETOF(shmem2_region_t, drv_info_host_addr_lo), pdev->vars.stats.stats_collect.drv_info_to_mfw.drv_info_to_mfw_phys_addr.as_u32.low );
        LM_SHMEM2_WRITE(pdev, OFFSETOF(shmem2_region_t, drv_info_host_addr_hi), pdev->vars.stats.stats_collect.drv_info_to_mfw.drv_info_to_mfw_phys_addr.as_u32.high );

        drv_msg = DRV_MSG_CODE_DRV_INFO_ACK;

    } while(0);

    lm_status = lm_mcp_cmd_send_recieve( pdev, lm_mcp_mb_header, drv_msg, 0, MCP_CMD_DEFAULT_TIMEOUT, &fw_resp );

    return lm_status;
}

static lm_status_t lm_ufp_pf_disable(lm_device_t *pdev)
{
    lm_status_t status        = LM_STATUS_SUCCESS;
    u32_t       mcp_resp      = 0;

    /*TODO: Have to do some processing based on fi the pF is enabled or disabled*/
    ///indicate "link-down"
    MM_ACQUIRE_PHY_LOCK(pdev);

    pdev->vars.link_status = LM_STATUS_LINK_DOWN;
    mm_indicate_link(pdev, pdev->vars.link_status, pdev->vars.medium);

    MM_RELEASE_PHY_LOCK(pdev);

    /* Report results to MCP */
    ///ACK the MCP message
    if(status == LM_STATUS_SUCCESS)
        lm_mcp_cmd_send_recieve(pdev, lm_mcp_mb_header, DRV_MSG_CODE_OEM_OK, 0, MCP_CMD_DEFAULT_TIMEOUT, &mcp_resp);
    else
        lm_mcp_cmd_send_recieve(pdev, lm_mcp_mb_header, DRV_MSG_CODE_OEM_FAILURE, 0, MCP_CMD_DEFAULT_TIMEOUT, &mcp_resp);

    DbgBreakIf(mcp_resp != FW_MSG_CODE_OEM_ACK);
    return status;
}

static void lm_ufp_pf_enable(lm_device_t *pdev)
{
    lm_status_t                  status    = LM_STATUS_SUCCESS;
    u32_t                        mcp_resp  = 0;
    struct function_update_data  *data     = LM_SLOWPATH(pdev, ufp_function_update_data);
    const lm_address_t           data_phys = LM_SLOWPATH_PHYS(pdev, ufp_function_update_data);
    lm_hardware_mf_info_t        *mf_info  = &pdev->hw_info.mf_info;
    u32_t                        tag       = 0;

    //Reconfigure rate-limit
    MM_ACQUIRE_PHY_LOCK(pdev);
    lm_reload_link_and_cmng(pdev);
    MM_RELEASE_PHY_LOCK(pdev);

    /* Other than vlan tag what are other UFP specific data? 
     * Should we read the priority etc
     */

    /* get ovlan if we're in switch-dependent mode... */
    LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].e1hov_tag),&tag);
    mf_info->ext_id    = (u16_t)tag;
    pdev->params.ovlan = (u16_t)tag;

    /* modify the NIG LLH registers */
    init_nig_func(pdev);

    DbgBreakIf(pdev->slowpath_info.ufp_func_ramrod_state != UFP_RAMROD_NOT_POSTED);

    /* send function update ramrod to change the tag in the FW */
    data->sd_vlan_tag_change_flg = TRUE;
    data->sd_vlan_tag            = mm_cpu_to_le16((u16_t)tag);
    data->echo                   = FUNC_UPDATE_RAMROD_SOURCE_UFP;

    status = lm_eq_ramrod_post_sync(pdev,
                                    RAMROD_CMD_ID_COMMON_FUNCTION_UPDATE,
                                    data_phys.as_u64,CMD_PRIORITY_NORMAL,
                                    &pdev->slowpath_info.ufp_func_ramrod_state,
                                    UFP_RAMROD_PF_LINK_UPDATE_POSTED,
                                    UFP_RAMROD_COMPLETED);

    /* Report results to MCP */
    ///ACK the MCP message
    if(status == LM_STATUS_SUCCESS)
        lm_mcp_cmd_send_recieve(pdev, lm_mcp_mb_header, DRV_MSG_CODE_OEM_OK, 0, MCP_CMD_DEFAULT_TIMEOUT, &mcp_resp);
    else
        lm_mcp_cmd_send_recieve(pdev, lm_mcp_mb_header, DRV_MSG_CODE_OEM_FAILURE, 0, MCP_CMD_DEFAULT_TIMEOUT, &mcp_resp);

    DbgBreakIf(mcp_resp != FW_MSG_CODE_OEM_ACK);

    pdev->slowpath_info.ufp_func_ramrod_state = UFP_RAMROD_NOT_POSTED;
}

static lm_status_t lm_oem_event(lm_device_t *pdev, u32_t event)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    const u32_t offset    = OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].config);
    u32_t       config    = 0;

    DbgMessage(pdev, INFORM, "oem_event 0x%x\n", event);

    ///read FUNC-DISABLED and FUNC-DELETED from func_mf_cfg
    LM_MFCFG_READ(pdev, offset, &config);
    pdev->hw_info.mf_info.func_mf_cfg = config ;

    if (event & DRV_STATUS_OEM_DISABLE_ENABLE_PF)
    {
        if((config & FUNC_MF_CFG_FUNC_DISABLED) || (config & FUNC_MF_CFG_FUNC_DELETED))
        {
            lm_status = lm_ufp_pf_disable(pdev);
            if (lm_status != LM_STATUS_SUCCESS)
            {
                DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
                return lm_status;
            }
        }
        else
        {
#ifdef EDIAG
            lm_ufp_pf_enable(pdev);
#else
            lm_status = MM_REGISTER_LPME(pdev, lm_ufp_pf_enable, TRUE, TRUE);
#endif
            if (lm_status != LM_STATUS_SUCCESS)
            {
                DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
                return lm_status;
            }
        }
    }
    else if (event & DRV_STATUS_OEM_BANDWIDTH_ALLOCATION)
    {
        //lm_hardware_mf_info_t *mf_info = &pdev->hw_info.mf_info;

        ///* get min/max bw */
        //mf_info->min_bw[vnic] = (GET_FLAGS(config, FUNC_MF_CFG_MIN_BW_MASK) >> FUNC_MF_CFG_MIN_BW_SHIFT);
        //mf_info->max_bw[vnic] = (GET_FLAGS(config, FUNC_MF_CFG_MAX_BW_MASK) >> FUNC_MF_CFG_MAX_BW_SHIFT);

        /* this function reads the bw configuration and does the necessary processing..
         * only drawback is it reads the configuration for all the functions?
         *. todo check if we should be using this or not...
         */
        lm_status = lm_set_bandwidth_event(pdev);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
            return lm_status;
        }
    }

    return lm_status;
}

static void lm_update_svid(lm_device_t *pdev)
{
    lm_hardware_mf_info_t          *mf_info        = &pdev->hw_info.mf_info;
    u32_t                          tag             = 0;
    u32_t                          mcp_resp        = 0;
    lm_status_t                    lm_status       = LM_STATUS_SUCCESS;
    struct function_update_data    *data           = LM_SLOWPATH(pdev, ufp_function_update_data);
    const lm_address_t             data_phys       = LM_SLOWPATH_PHYS(pdev, ufp_function_update_data);

    /* get ovlan if we're in switch-dependent mode... */
    LM_MFCFG_READ(pdev, OFFSETOF(mf_cfg_t, func_mf_config[ABS_FUNC_ID(pdev)].e1hov_tag),&tag);
    mf_info->ext_id      = (u16_t)tag;
    pdev->params.ovlan   = (u16_t)tag;

    /* modify the NIG LLH registers */
    init_nig_func(pdev);

    DbgBreakIf(pdev->slowpath_info.ufp_func_ramrod_state != UFP_RAMROD_NOT_POSTED);

    /* send function update ramrod to change the tag in the FW */
    data->sd_vlan_tag_change_flg = TRUE;
    data->sd_vlan_tag            = mm_cpu_to_le16((u16_t)tag);
    data->echo	                 = FUNC_UPDATE_RAMROD_SOURCE_UFP;

    lm_status = lm_eq_ramrod_post_sync(pdev,
                                       RAMROD_CMD_ID_COMMON_FUNCTION_UPDATE,
                                       data_phys.as_u64,CMD_PRIORITY_NORMAL,
                                       &pdev->slowpath_info.ufp_func_ramrod_state,
                                       UFP_RAMROD_PF_UPDATE_POSTED,
                                       UFP_RAMROD_COMPLETED);

    /* Report results to MCP */
    if(lm_status == LM_STATUS_SUCCESS)
        lm_mcp_cmd_send_recieve(pdev, lm_mcp_mb_header, DRV_MSG_CODE_OEM_UPDATE_SVID_OK, 0, MCP_CMD_DEFAULT_TIMEOUT, &mcp_resp);
    else
        lm_mcp_cmd_send_recieve(pdev, lm_mcp_mb_header, DRV_MSG_CODE_OEM_UPDATE_SVID_FAILURE, 0, MCP_CMD_DEFAULT_TIMEOUT, &mcp_resp);

    DbgBreakIf(mcp_resp != DRV_MSG_CODE_OEM_UPDATE_SVID_ACK);
    pdev->slowpath_info.ufp_func_ramrod_state = UFP_RAMROD_NOT_POSTED;
}

#ifndef EDIAG
static void lm_ufp_update_priority(lm_device_t *pdev)
{
    lm_hardware_mf_info_t          *mf_info        = &pdev->hw_info.mf_info;
    u32_t                          new_priority    = 0;
    u32_t                          mcp_resp        = 0;
    lm_status_t                    lm_status       = LM_STATUS_SUCCESS;
    struct function_update_data    *data           = LM_SLOWPATH(pdev, ufp_function_update_data);
    const lm_address_t             data_phys       = LM_SLOWPATH_PHYS(pdev, ufp_function_update_data);

    DbgBreakIf(pdev->slowpath_info.ufp_func_ramrod_state != UFP_RAMROD_NOT_POSTED);

    /* Todo get the priority from somewhere */

    /* send function update ramrod to change the tag in the FW */
    data->sd_vlan_force_pri_change_flg = TRUE;
    data->sd_vlan_force_pri_flg        = TRUE;
    //data->sd_vlan_force_pri_val        = mm_cpu_to_le16((u16_t)new_priority);

    data->echo	                       = FUNC_UPDATE_RAMROD_SOURCE_UFP;

    lm_status = lm_eq_ramrod_post_sync(pdev,
                                       RAMROD_CMD_ID_COMMON_FUNCTION_UPDATE,
                                       data_phys.as_u64,CMD_PRIORITY_NORMAL,
                                       &pdev->slowpath_info.ufp_func_ramrod_state,
                                       UFP_RAMROD_PF_UPDATE_POSTED,
                                       UFP_RAMROD_COMPLETED);
    /*Todo Report results to mcp?*/
    pdev->slowpath_info.ufp_func_ramrod_state = UFP_RAMROD_NOT_POSTED;
}
#endif

static lm_status_t lm_svid_event(lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
#ifdef EDIAG
    lm_update_svid(pdev);
#else
    lm_status = MM_REGISTER_LPME(pdev, lm_update_svid, TRUE, TRUE);
#endif
    if (lm_status != LM_STATUS_SUCCESS)
    {
            DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
            return lm_status;
    }

    return lm_status;
}

static void lm_generic_event(lm_device_t *pdev)
{
    u32_t      val              = 0;
    u32_t      offset           = 0; // for debugging convenient
    u8_t       call_pmf_or_link = FALSE;
    const u8_t func_id          = FUNC_ID(pdev);


    offset = MISC_REG_AEU_GENERAL_ATTN_12 + 4*func_id;

    // reset attention
    REG_WR(pdev, offset ,0x0);

    offset = OFFSETOF(shmem_region_t, func_mb[FUNC_MAILBOX_ID(pdev)].drv_status) ;

    // drv_status
    LM_SHMEM_READ(pdev,
                  offset,
                  &val);

    // E1H NIG status sync attention mapped to group 4-7

    if (GET_FLAGS( val, DRV_STATUS_VF_DISABLED))
    {
        u32_t mcp_vf_disabled[E2_VF_MAX / 32] = {0};
        u32_t i, fw_resp = 0;

        // Read VFs
        for (i = 0; i < ARRSIZE(mcp_vf_disabled); i++)
        {
            LM_SHMEM2_READ(pdev, OFFSETOF(shmem2_region_t,mcp_vf_disabled[i]), &mcp_vf_disabled[i]);
        }
        DbgMessage(pdev, FATAL, "lm_generic_event: DRV_STATUS_VF_DISABLED received for vfs bitmap %x %x!!!\n", mcp_vf_disabled[0], mcp_vf_disabled[1]);

        // SHMULIK, PLACE YOUR CODE HERE ( Handle only VFs of this PF )

        // Acknoledge the VFs you handled ( This array is per PF driver on path )
        for (i = 0; i < ARRSIZE(mcp_vf_disabled) ; i++)
        {
            LM_SHMEM2_WRITE(pdev, OFFSETOF(shmem2_region_t,drv_ack_vf_disabled[FUNC_MAILBOX_ID(pdev)][i]), mcp_vf_disabled[i]);
        }
        lm_mcp_cmd_send_recieve( pdev,
                                 lm_mcp_mb_header,
                                 DRV_MSG_CODE_VF_DISABLED_DONE,
                                 0,
                                 MCP_CMD_DEFAULT_TIMEOUT,
                                 &fw_resp);
        return; // YANIV - DEBUG @@@!!!
    }
    if(IS_MULTI_VNIC(pdev))
    {
        if( GET_FLAGS( val, DRV_STATUS_DCC_EVENT_MASK ) )
        {
            lm_dcc_event(pdev, (DRV_STATUS_DCC_EVENT_MASK & val) );
        }

        if (GET_FLAGS(val, DRV_STATUS_SET_MF_BW ))
        {
            lm_set_bandwidth_event(pdev);
        }

        //if val has any NIV event flags, call lm_niv_event
        if ( GET_FLAGS(val, DRV_STATUS_AFEX_EVENT_MASK) )
        {
            lm_niv_event(pdev, GET_FLAGS(val, DRV_STATUS_AFEX_EVENT_MASK) );
        }
    }

    if GET_FLAGS(val, DRV_STATUS_DRV_INFO_REQ)
    {
        lm_stats_drv_info_to_mfw_event(pdev);
    }

    // NOTE:
    // once we have events such as DCC and NIV, this condition doesn't stand anymore
    // we might get here TRUE although we are in MULTI_VNIC AND we are not PMF
    // and this is not for link change or pmf migration
    // the potential problem (redundant link report to OS CQ60223)
    // is resolved in "lm_link_report" function that check current link
    // with previous reported link

    /* Check if pmf or link event function should be called: */
    call_pmf_or_link = IS_MULTI_VNIC(pdev) && !pdev->vars.is_pmf;


    /* PMF or link event */
    if (GET_FLAGS(pdev->vars.link.periodic_flags, ELINK_PERIODIC_FLAGS_LINK_EVENT))
    {
        DbgMessage(pdev, WARN, "lm_generic_event: ELINK_PERIODIC_FLAGS_LINK_EVENT func_id=%d!!!\n", func_id );

        /*  sync with link */
        MM_ACQUIRE_PHY_LOCK_DPC(pdev);
        RESET_FLAGS(pdev->vars.link.periodic_flags, ELINK_PERIODIC_FLAGS_LINK_EVENT);
        MM_RELEASE_PHY_LOCK_DPC(pdev);

        call_pmf_or_link = TRUE;
    }

    if(call_pmf_or_link)
    {
        lm_pmf_or_link_event(pdev, val);
    }

    if GET_FLAGS(val, DRV_STATUS_OEM_EVENT_MASK)
    {
        lm_oem_event(pdev, val);
    }

    if GET_FLAGS(val, DRV_STATUS_OEM_UPDATE_SVID)
    {
        lm_svid_event(pdev);
    }

    lm_dcbx_event(pdev,val);
}

static void lm_gen_attn_everest_processing(lm_device_t *pdev, u32_t sig_word_aft_inv)
{
    u32_t offset = 0; // for debugging convenient
    u32_t val    = 0;

    //pass over all attention generals which are wired to a dynamic group of the lower 8 bits
    offset = GENERAL_ATTEN_OFFSET(TSTORM_FATAL_ASSERT_ATTENTION_BIT) ;
    if ( offset & sig_word_aft_inv)
    {
        REG_WR(pdev,MISC_REG_AEU_GENERAL_ATTN_7,0x0);
        DbgMessage(pdev, FATAL, "lm_gen_attn_everest_processing: TSTORM_FATAL_ASSERT_ATTENTION_BIT received!!!\n");
        DbgBreakIfAll(1);
    }
    offset = GENERAL_ATTEN_OFFSET(USTORM_FATAL_ASSERT_ATTENTION_BIT);
    if ( offset & sig_word_aft_inv)
    {
        REG_WR(pdev,MISC_REG_AEU_GENERAL_ATTN_8,0x0);
        DbgMessage(pdev, FATAL, "lm_gen_attn_everest_processing: USTORM_FATAL_ASSERT_ATTENTION_BIT received!!!\n");
        DbgBreakIfAll(1);
    }
    offset = GENERAL_ATTEN_OFFSET(CSTORM_FATAL_ASSERT_ATTENTION_BIT);
    if ( offset & sig_word_aft_inv)
    {
        REG_WR(pdev,MISC_REG_AEU_GENERAL_ATTN_9,0x0);
        DbgMessage(pdev, FATAL, "lm_gen_attn_everest_processing: CSTORM_FATAL_ASSERT_ATTENTION_BIT received!!!\n");
        DbgBreakIfAll(1);
    }
    offset = GENERAL_ATTEN_OFFSET(XSTORM_FATAL_ASSERT_ATTENTION_BIT);
    if ( offset & sig_word_aft_inv)
    {
        REG_WR(pdev,MISC_REG_AEU_GENERAL_ATTN_10,0x0);
        DbgMessage(pdev, FATAL, "lm_gen_attn_everest_processing: XSTORM_FATAL_ASSERT_ATTENTION_BIT received!!!\n");
        DbgBreakIfAll(1);
    }
    offset = GENERAL_ATTEN_OFFSET(MCP_FATAL_ASSERT_ATTENTION_BIT);
    if ( offset & sig_word_aft_inv)
    {
        REG_WR(pdev,MISC_REG_AEU_GENERAL_ATTN_11,0x0);
        val = lm_mcp_check(pdev);
        DbgMessage(pdev, FATAL, "lm_gen_attn_everest_processing: MCP_FATAL_ASSERT_ATTENTION_BIT received mcp_check=0x%x!!!\n" , val);
        DbgBreakIfAll(1);
    }
     // E1H NIG status sync attention mapped to group 4-7
    if (!CHIP_IS_E1(pdev))
    {
        // PMF change or link update
        offset = GENERAL_ATTEN_OFFSET(LINK_SYNC_ATTENTION_BIT_FUNC_0 + FUNC_ID(pdev));

        if ( offset & sig_word_aft_inv)
        {
           lm_generic_event(pdev);
        }
    }
}

void lm_read_attn_regs(lm_device_t *pdev, u32_t * attn_sig_af_inv_arr, u32_t arr_size)
{
    u8_t i;
    DbgBreakIf( pdev->vars.num_attn_sig_regs > arr_size );
    DbgBreakIf( pdev->vars.num_attn_sig_regs > ARRSIZE(pdev->vars.attn_sig_af_inv_reg_addr) );

    //Read the 128 attn signals bits after inverter
    for (i = 0; i < pdev->vars.num_attn_sig_regs; i++)
    {
        attn_sig_af_inv_arr[i] = REG_RD(pdev, pdev->vars.attn_sig_af_inv_reg_addr[i]);
    }

    DbgMessage(pdev, INFORM, "lm_handle_deassertion_processing: attn_sig_aft_invert_1:0x%x; attn_sig_aft_invert_2:0x%x; attn_sig_aft_invert_3:0x%x; attn_sig_aft_invert_4:0x%x,attn_sig_aft_invert_5:0x%x\n",
                attn_sig_af_inv_arr[0],
                attn_sig_af_inv_arr[1],
                attn_sig_af_inv_arr[2],
                attn_sig_af_inv_arr[3],
                attn_sig_af_inv_arr[4]);
}



void lm_get_attn_info(lm_device_t *pdev, u16_t *attn_bits, u16_t *attn_ack)
{
    volatile struct atten_sp_status_block *       attention_sb = NULL;
    u16_t                                   lcl_attn_sb_index = 0;

    DbgBreakIf(!(pdev && attn_bits && attn_ack));

    attention_sb = lm_get_attention_status_block(pdev);

    //guard against dynamic change of attn lines - 15 interations max
    //the main idea here is to assure that we work on synchronized snapshots of the attn_bits and
    //attn_ack and avoid a faulty scenario where attn_ack we read in sanpshot #2 corresponds to attn_bits
    //of snapshot #1 which occured on different time frames.
    do
    {
        lcl_attn_sb_index = mm_le16_to_cpu(attention_sb->attn_bits_index);
        *attn_bits = (u16_t)mm_le32_to_cpu(attention_sb->attn_bits);
        *attn_ack  = (u16_t)mm_le32_to_cpu(attention_sb->attn_bits_ack);

    } while (lcl_attn_sb_index != mm_le16_to_cpu(attention_sb->attn_bits_index));
    //the lcl_attn_sb_index differs from the real local attn_index in the pdev since in this while loop it could
    //have been changed, we don't save it locally, and thus we will definitely receive an interrupt in case the
    //while condition is met.

    DbgMessage(pdev,
               INFORMi,
               "lm_get_attn_info: def_sb->attn_bits:0x%x, def_sb->attn_ack:0x%x, attn_bits:0x%x, attn_ack:0x%x\n",
               mm_le32_to_cpu(attention_sb->attn_bits),
               mm_le32_to_cpu(attention_sb->attn_bits_ack),
               *attn_bits,
               *attn_ack);
}


static u32_t lm_dq_attn_everest_processing(lm_device_t *pdev)
{
    u32_t val,valc;
    val=REG_RD(pdev,DORQ_REG_DORQ_INT_STS);
    // TODO add defines here
    DbgMessage(pdev, FATAL, "DB hw attention 0x%x\n",val);
    if (val) {
        pdev->vars.dq_int_status_cnt++;
        if (val & DORQ_DORQ_INT_STS_REG_DB_DISCARD)
        {
    // DORQ discard attention
            pdev->vars.dq_int_status_discard_cnt++;//DbgBreakIfAll(1);
        }
        if (val & DORQ_DORQ_INT_STS_REG_TYPE_VAL_ERR)
    {
            // DORQ discard attention
            pdev->vars.dq_int_status_vf_val_err_cnt++;//DbgBreakIfAll(1);
            pdev->vars.dq_vf_type_val_err_fid = REG_RD(pdev,DORQ_REG_VF_TYPE_VAL_ERR_FID); 
            pdev->vars.dq_vf_type_val_err_mcid = REG_RD(pdev,DORQ_REG_VF_TYPE_VAL_ERR_MCID); 
    }
    }
    valc = REG_RD(pdev,DORQ_REG_DORQ_INT_STS_CLR);
    return val;
}

void lm_handle_deassertion_processing(lm_device_t *pdev, u16_t deassertion_proc_flgs)
{
    lm_status_t lm_status                     = LM_STATUS_SUCCESS;
    u32_t  val                                = 0;
    u32_t  port_reg_name                      = 0;
    u8_t   index                              = 0;
    u8_t   i                                  = 0;
    u32_t  mask_val                           = 0;
    u32_t  attn_sig_af_inv_arr[MAX_ATTN_REGS] = {0};
    u32_t  group_mask_arr[MAX_ATTN_REGS]      = {0};
    u32_t  mask_arr_val[MAX_ATTN_REGS]        = {0};
    u32_t  dq_int_sts, cfc_int_sts;

    DbgBreakIf(!pdev);
    DbgMessage(pdev, INFORM, "lm_handle_deassertion_processing: deassertion_proc_flgs:%d\n", deassertion_proc_flgs);


    //acquire split lock for attention signals handling
    acquire_split_alr(pdev);

    lm_read_attn_regs(pdev, attn_sig_af_inv_arr, ARRSIZE(attn_sig_af_inv_arr));

    if (lm_recoverable_error(pdev, attn_sig_af_inv_arr,ARRSIZE(attn_sig_af_inv_arr)))
    {
        DbgMessage(pdev, WARNer, "Starting lm recover flow ");
        lm_status = mm_er_initiate_recovery(pdev);
        if (lm_status == LM_STATUS_SUCCESS)
        {
            /* Continue only on success... */
            /* Disable HW interrupts */
            lm_disable_int(pdev);

            release_split_alr(pdev);
            /* In case of recoverable error don't handle attention so that
            * other functions get this parity as well.
            */
            return;
        }
        DbgMessage(pdev, WARNer, "mm_er_initiate_recovery returned status %d ", lm_status);

        /* Recovery failed... we'll keep going, and eventually hit
         * the attnetion and assert...
         */
    }

    //For all deasserted groups, pass over entire attn_bits after inverter and if they
    // are members of that particular gruop, treat each one of them accordingly.
    for (index = 0; index < ARRSIZE(pdev->vars.attn_groups_output); index++)
    {
        if (deassertion_proc_flgs & (1 << index))
        {
            for (i = 0; i < ARRSIZE(group_mask_arr); i++)
            {
                group_mask_arr[i] = pdev->vars.attn_groups_output[index].attn_sig_dword[i];
            }

            DbgMessage(pdev, WARN, "lm_handle_deassertion_processing: group #%d got attention on it!\n", index);
            DbgMessage(pdev, WARN, "lm_handle_deassertion_processing: mask1:0x%x, mask2:0x%x, mask3:0x%x, mask4:0x%x,mask5:0x%x\n",
                       group_mask_arr[0],
                       group_mask_arr[1],
                       group_mask_arr[2],
                       group_mask_arr[3],
                       group_mask_arr[4]);
            DbgMessage(pdev, WARN, "lm_handle_deassertion_processing: attn1:0x%x, attn2:0x%x, attn3:0x%x, attn4:0x%x,attn5:0x%x\n",
                       attn_sig_af_inv_arr[0],
                       attn_sig_af_inv_arr[1],
                       attn_sig_af_inv_arr[2],
                       attn_sig_af_inv_arr[3],
                       attn_sig_af_inv_arr[4]);

            if (attn_sig_af_inv_arr[3] & EVEREST_GEN_ATTN_IN_USE_MASK & group_mask_arr[3])
            {
                lm_gen_attn_everest_processing(pdev, attn_sig_af_inv_arr[3]);
            }

            // DQ attn
            if (attn_sig_af_inv_arr[1] & AEU_INPUTS_ATTN_BITS_DOORBELLQ_HW_INTERRUPT & group_mask_arr[1])
            {
                dq_int_sts = lm_dq_attn_everest_processing(pdev);
            }
            // CFC attn
            if (attn_sig_af_inv_arr[2] & AEU_INPUTS_ATTN_BITS_CFC_HW_INTERRUPT & group_mask_arr[2])
            {
                cfc_int_sts = lm_cfc_attn_everest_processing(pdev);
            }
            // PXP attn
            if (attn_sig_af_inv_arr[2] & AEU_INPUTS_ATTN_BITS_PXP_HW_INTERRUPT & group_mask_arr[2])
            {
                lm_pxp_attn_everest_processing(pdev);
            }
            // SPIO 5 bit in register 0
            if (attn_sig_af_inv_arr[0] & AEU_INPUTS_ATTN_BITS_SPIO5 & group_mask_arr[0])
            {
                lm_spio5_attn_everest_processing(pdev);
            }

            // GPIO3 bits in register 0
            if (attn_sig_af_inv_arr[0] & pdev->vars.link.aeu_int_mask & group_mask_arr[0])
            {
                // Handle it only for PMF
                if (IS_PMF(pdev))
                {
                    MM_ACQUIRE_PHY_LOCK(pdev);
                    PHY_HW_LOCK(pdev);
                    elink_handle_module_detect_int(&pdev->params.link);
                    PHY_HW_UNLOCK(pdev);
                    MM_RELEASE_PHY_LOCK(pdev);
                }
            }

            //TODO: attribute each attention signal arrived and which is a member of a group and give it its own
            // specific treatment. later, for each attn, do "clean the hw block" via the INT_STS_CLR.

            //Check for lattched attn signals
            if (attn_sig_af_inv_arr[3] & EVEREST_LATCHED_ATTN_IN_USE_MASK & group_mask_arr[3])
            {
                lm_latch_attn_everest_processing(pdev, attn_sig_af_inv_arr[3]);
            }

            // general hw block attention
            i = 0;
            mask_arr_val[i] = attn_sig_af_inv_arr[i] & HW_INTERRUT_ASSERT_SET_0 & group_mask_arr[i];
            i = 1;
            mask_arr_val[i] = attn_sig_af_inv_arr[i] & HW_INTERRUT_ASSERT_SET_1 & group_mask_arr[i];
            i = 2;
            mask_arr_val[i] = attn_sig_af_inv_arr[i] & HW_INTERRUT_ASSERT_SET_2 & group_mask_arr[i];
            i = 4;
            mask_arr_val[i] = attn_sig_af_inv_arr[i] & HW_INTERRUT_ASSERT_SET_4 & group_mask_arr[i];

            if (mask_arr_val[2] & AEU_INPUTS_ATTN_BITS_PXP_HW_INTERRUPT) {
                pdev->vars.pxp_hw_interrupts_cnt++;
            }

            if ( (mask_arr_val[0]) ||
                 (mask_arr_val[1] & ~AEU_INPUTS_ATTN_BITS_DOORBELLQ_HW_INTERRUPT) ||
                 (mask_arr_val[2] & ~(AEU_INPUTS_ATTN_BITS_PXP_HW_INTERRUPT | AEU_INPUTS_ATTN_BITS_CFC_HW_INTERRUPT)) ||
                 (mask_arr_val[4]) )
            {
                DbgMessage(pdev, FATAL, "hw block attention:\n");
                DbgMessage(pdev, FATAL, "0: 0x%08x\n", mask_arr_val[0]);
                DbgMessage(pdev, FATAL, "1: 0x%08x\n", mask_arr_val[1]);
                DbgMessage(pdev, FATAL, "2: 0x%08x\n", mask_arr_val[2]);
                DbgMessage(pdev, FATAL, "4: 0x%08x\n", mask_arr_val[4]);
                DbgBreakIfAll(1);
            }
            // general hw block mem prty
            i = 0;
            mask_arr_val[i] = attn_sig_af_inv_arr[i] & HW_PRTY_ASSERT_SET_0 & group_mask_arr[i];
            i = 1;
            mask_arr_val[i] = attn_sig_af_inv_arr[i] & HW_PRTY_ASSERT_SET_1 & group_mask_arr[i];
            i = 2;
            mask_arr_val[i] = attn_sig_af_inv_arr[i] & HW_PRTY_ASSERT_SET_2 & group_mask_arr[i];
            i = 4;
            mask_arr_val[i] = attn_sig_af_inv_arr[i] & HW_PRTY_ASSERT_SET_4 & group_mask_arr[i];

            if ( (mask_arr_val[0]) ||
                 (mask_arr_val[1]) ||
                 (mask_arr_val[2]) ||
                 (mask_arr_val[4]) )
            {
                DbgMessage(pdev, FATAL, "hw block parity attention\n");
                DbgMessage(pdev, FATAL, "0: 0x%08x\n", mask_arr_val[0]);
                DbgMessage(pdev, FATAL, "1: 0x%08x\n", mask_arr_val[1]);
                DbgMessage(pdev, FATAL, "2: 0x%08x\n", mask_arr_val[2]);
                DbgMessage(pdev, FATAL, "4: 0x%08x\n", mask_arr_val[4]);
                DbgBreakIfAll(1);
            }
        }
    }

    //release split lock
    release_split_alr(pdev);

    //TODO: the attn_ack bits to clear must be passed with '0'
    //val = deassertion_proc_flgs;
    val = ~deassertion_proc_flgs;
    // attntion bits clear
    if (INTR_BLK_TYPE(pdev) == INTR_BLK_HC)
    {
        REG_WR(pdev,  HC_REG_COMMAND_REG + PORT_ID(pdev)*32 + COMMAND_REG_ATTN_BITS_CLR,val);
    }
    else
    {
        u32_t cmd_addr = IGU_CMD_ATTN_BIT_CLR_UPPER;

        if (INTR_BLK_ACCESS(pdev) == INTR_BLK_ACCESS_IGUMEM)
        {
            REG_WR(pdev, BAR_IGU_INTMEM + cmd_addr*8, val);
        }
        else
        {
            struct igu_ctrl_reg cmd_ctrl;
            u8_t                igu_func_id = 0;

            /* GRC ACCESS: */
            /* Write the Data, then the control */
             /* [18:12] - FID (if VF - [18] = 0; [17:12] = VF number; if PF - [18] = 1; [17:14] = 0; [13:12] = PF number) */
            igu_func_id = IGU_FUNC_ID(pdev);
            cmd_ctrl.ctrl_data =
                ((cmd_addr << IGU_CTRL_REG_ADDRESS_SHIFT) |
                 (igu_func_id << IGU_CTRL_REG_FID_SHIFT) |
                 (IGU_CTRL_CMD_TYPE_WR << IGU_CTRL_REG_TYPE_SHIFT));

            REG_WR(pdev, IGU_REG_COMMAND_REG_32LSB_DATA, val);
            REG_WR(pdev, IGU_REG_COMMAND_REG_CTRL, cmd_ctrl.ctrl_data);
        }
    }

    //unmask only appropriate attention output signals from configured routing and unifier logic toward IGU.
    //This is for driver/chip sync to eventually return to '00' monitored state
    //in both leading & trailing latch.
    //unmask non-hard-wired dynamic groups only

    DbgBreakIf(~pdev->vars.attn_state & deassertion_proc_flgs);

    //unmask relevant AEU attn lines
    //             mask  deassert_flgs  new mask
    //legal:        0       0       ->    0
    //              0       1       ->    1
    //              1       0       ->    1
    //ASSERT:       1       1 -> this won't change us thanks to the |

    port_reg_name = PORT_ID(pdev) ? MISC_REG_AEU_MASK_ATTN_FUNC_1 : MISC_REG_AEU_MASK_ATTN_FUNC_0;

    lm_hw_lock(pdev, HW_LOCK_RESOURCE_PORT0_ATT_MASK + PORT_ID(pdev), TRUE);

    mask_val = REG_RD(pdev, port_reg_name);

    pdev->vars.aeu_mask_attn_func = mask_val & 0xff;

    DbgMessage(pdev, INFORM, "lm_handle_deassertion_processing: BEFORE: aeu_mask_attn_func:0x%x\n", pdev->vars.aeu_mask_attn_func);
    //changed from XOR to OR for safely
    pdev->vars.aeu_mask_attn_func |= (deassertion_proc_flgs & 0xff);

    DbgMessage(pdev, INFORM, "lm_handle_deassertion_processing: AFTER : aeu_mask_attn_func:0x%x\n", pdev->vars.aeu_mask_attn_func);

    REG_WR(pdev, port_reg_name, pdev->vars.aeu_mask_attn_func);
    lm_hw_unlock(pdev, HW_LOCK_RESOURCE_PORT0_ATT_MASK + PORT_ID(pdev));
    //update the attn bits states
    //            state  deassert_flgs  new state
    //legal:        0       0       ->    0
    //              1       0       ->    1
    //              1       1       ->    0
    //ASSERT:       0       1 -> this won't change our state thanks to & ~ !
    DbgMessage(pdev, INFORM, "lm_handle_deassertion_processing: BEFORE: attn_state:0x%x\n", pdev->vars.attn_state);

    //changed from XOR to : AND ~ for safety
    pdev->vars.attn_state &= ~deassertion_proc_flgs;

    DbgMessage(pdev, INFORM, "lm_handle_deassertion_processing: AFTER : attn_state:0x%x\n", pdev->vars.attn_state);
}
