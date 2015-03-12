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
 *      This file contains functions that handle chip init and reset
 *
 ******************************************************************************/
#include "lm5710.h"
#include "command.h"
#include "bd_chain.h"
#include "ecore_init.h"
#include "ecore_init_ops.h"

// the phys address is shifted right 12 bits and has an added 1=valid bit added to the 53rd bit
// then since this is a wide register(TM) we split it into two 32 bit writes
#define ONCHIP_ADDR1(x)   ((u32_t)( x>>12 & 0xFFFFFFFF ))
#define ONCHIP_ADDR2(x)   ((u32_t)( 1<<20 | x>>44 ))

#define ONCHIP_ADDR0_VALID() ((u32_t)( 1<<20 )) /* Address valued 0 with valid bit on. */

#define PXP2_SET_FIRST_LAST_ILT(pdev, blk, first, last) \
                do { \
                    if (CHIP_IS_E1(pdev)) { \
                        REG_WR(pdev,(PORT_ID(pdev) ? PXP2_REG_PSWRQ_##blk##1_L2P: PXP2_REG_PSWRQ_##blk##0_L2P),((last)<<10 | (first))); \
                    } else { \
                        REG_WR(pdev,PXP2_REG_RQ_##blk##_FIRST_ILT,(first)); \
                        REG_WR(pdev,PXP2_REG_RQ_##blk##_LAST_ILT,(last)); \
                    } \
                } while(0)

                                     /*  offset                  valid
                                                                 e1,e1h,e2,e3 save / restore */
#define NIG_REG_PORT_0_OFFSETS_VALUES { { NIG_REG_LLH0_FUNC_EN,        {0,1,1,1}, (LM_NIG_RESTORE) },      \
                                        { NIG_REG_LLH0_FUNC_VLAN_ID,   {0,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_ENABLE,    {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_0_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_1_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_2_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_3_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_4_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_5_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_6_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_7_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_0_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_1_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_2_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_3_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_4_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_5_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_6_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH0_ACPI_PAT_7_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }}

#define NIG_REG_PORT_1_OFFSETS_VALUES { { NIG_REG_LLH1_FUNC_EN,        {0,1,1,1}, (LM_NIG_RESTORE) },        \
                                        { NIG_REG_LLH1_FUNC_VLAN_ID,   {0,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_ENABLE,    {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_0_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_1_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_2_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_3_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_4_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_5_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_6_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_7_LEN, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_0_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_1_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_2_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_3_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_4_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_5_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_6_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }, \
                                        { NIG_REG_LLH1_ACPI_PAT_7_CRC, {1,1,1,1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }}

#define ECORE_INIT_COMN(_pdev, _block) \
    ecore_init_block(_pdev, BLOCK_##_block, PHASE_COMMON)

#define ECORE_INIT_PORT(_pdev, _block) \
    ecore_init_block(_pdev, BLOCK_##_block, PHASE_PORT0 + PORT_ID(_pdev))

#define ECORE_INIT_FUNC(_pdev, _block) \
    ecore_init_block(_pdev, BLOCK_##_block, PHASE_PF0 + FUNC_ID(_pdev))

typedef enum {
    LM_RESET_NIG_OP_SAVE      = 0,
    LM_RESET_NIG_OP_PROCESS   = 1,
    LM_RESET_NIG_OP_RESTORE   = 2,
    LM_RESET_NIG_OP_MAX       = 3
} lm_reset_nig_op_t;

typedef struct _lm_nig_save_restore_data_t
{
    u32_t offset;
    struct {
        u8_t e1;  /* 57710 */
        u8_t e1h; /* 57711 */
        u8_t e2;  /* 57712 */
        u8_t e3;  /* 578xx */
    } reg_valid;  /* 1 if valid for chip 0 o/`w */

    u8_t  flags;
    #define LM_NIG_SAVE    ((u8_t)0x1) /* Should this register be saved    */
    #define LM_NIG_RESTORE ((u8_t)0x2) /* Should this register be restored */
} lm_nig_save_restore_data_t ;

lm_chip_global_t g_lm_chip_global[MAX_PCI_BUS_NUM] = {{0}};

void lm_reset_set_inprogress(struct _lm_device_t *pdev)
{
    const u8_t bus_num = INST_ID_TO_BUS_NUM(PFDEV(pdev)->vars.inst_id) ;
    const u8_t flags   = LM_CHIP_GLOBAL_FLAG_RESET_IN_PROGRESS;

    SET_FLAGS( g_lm_chip_global[bus_num].flags, flags) ;
}

void lm_reset_clear_inprogress(struct _lm_device_t *pdev)
{
    const u8_t bus_num = INST_ID_TO_BUS_NUM(PFDEV(pdev)->vars.inst_id) ;
    const u8_t flags   = LM_CHIP_GLOBAL_FLAG_RESET_IN_PROGRESS;

    RESET_FLAGS( g_lm_chip_global[bus_num].flags, flags) ;
}

u8_t lm_pm_reset_is_inprogress(struct _lm_device_t *pdev)
{
    const u8_t bus_num = INST_ID_TO_BUS_NUM(PFDEV(pdev)->vars.inst_id) ;
    const u8_t flags   = LM_CHIP_GLOBAL_FLAG_RESET_IN_PROGRESS;

    return ( 0 != GET_FLAGS(g_lm_chip_global[bus_num].flags, flags ) );
}

void lm_read_attn_regs(lm_device_t *pdev, u32_t * attn_sig_af_inv_arr, u32_t arr_size);
u8_t lm_recoverable_error(lm_device_t *pdev, u32_t * attn_sig, u32_t arr_size);

/**
 * @Description
 *      This function checks if there is optionally a attention
 *      pending that is recoverable. If it is, then we won't
 *      assert in the locations that call reset_is_inprogress,
 *      because there's a high probability we'll overcome the
 *      error with recovery
 * @param pdev
 *
 * @return u8_t
 */
u8_t lm_er_handling_pending(struct _lm_device_t *pdev)
{
    u32_t  attn_sig_af_inv_arr[MAX_ATTN_REGS] = {0};

    if (!pdev->params.enable_error_recovery || CHIP_IS_E1x(pdev))
    {
        return FALSE;
    }

    lm_read_attn_regs(pdev, attn_sig_af_inv_arr, ARRSIZE(attn_sig_af_inv_arr));

    return lm_recoverable_error(pdev, attn_sig_af_inv_arr, ARRSIZE(attn_sig_af_inv_arr));
}

u8_t lm_reset_is_inprogress(struct _lm_device_t *pdev)
{
    u8_t reset_in_progress =
        lm_pm_reset_is_inprogress(pdev)        ||
        lm_er_handling_pending(pdev)           ||
        lm_fl_reset_is_inprogress(PFDEV(pdev)) ||
        pdev->panic                            ||
        (IS_VFDEV(pdev) ? lm_fl_reset_is_inprogress(pdev) : FALSE);

    return reset_in_progress;
}

/*
 *------------------------------------------------------------------------
 * FLR in progress handling -
 *-------------------------------------------------------------------------
 */
void lm_fl_reset_set_inprogress(struct _lm_device_t *pdev)
{
    pdev->params.is_flr = TRUE;
    if (IS_PFDEV(pdev))
    {
        DbgMessage(pdev, FATAL, "PF[%d] is under FLR\n",FUNC_ID(pdev));
    }
    else
    {
        DbgMessage(pdev, FATAL, "VF[%d] is under FLR\n",ABS_VFID(pdev));
    }
    return;
}

void lm_fl_reset_clear_inprogress(struct _lm_device_t *pdev)
{
    pdev->params.is_flr = FALSE;
    return;
}

u8_t lm_fl_reset_is_inprogress(struct _lm_device_t *pdev)
{
    return  pdev->params.is_flr;
}

u8_t lm_is_function_after_flr(struct _lm_device_t * pdev)
{
    u8_t is_after_flr = FALSE;
    is_after_flr = pdev->params.is_flr;
    if (is_after_flr)
    {
        if (IS_PFDEV(pdev))
        {
            DbgMessage(pdev, FATAL, "PF[%d] was FLRed\n",FUNC_ID(pdev));
        }
        else
        {
            DbgMessage(pdev, FATAL, "VF[%d] was FLRed\n",ABS_VFID(pdev));
        }
    }
    return is_after_flr;
}

u32_t lm_dmae_idx_to_go_cmd( u8_t idx );

lm_status_t lm_cleanup_after_flr(struct _lm_device_t * pdev)
{
    lm_status_t lm_status  = LM_STATUS_SUCCESS;
    u32_t wait_ms          = 60000000;
    u16_t pretend_value    = 0;
    u32_t factor           = 0;
    u32_t cleanup_complete = 0;
#if defined(__LINUX) || defined(_VBD_)
    u32_t pcie_caps_offset = 0;
#endif

    u8_t  function_for_clean_up = 0;
    u8_t  idx                   = 0;

    struct sdm_op_gen final_cleanup;

    // TODO - use here pdev->vars.clk_factor
    if (CHIP_REV_IS_EMUL(pdev))
    {
            factor = LM_EMUL_FACTOR;
    }
    else if (CHIP_REV_IS_FPGA(pdev))
    {
            factor = LM_FPGA_FACTOR;
    }
    else
    {
            factor = 1;
    }

    wait_ms *= factor;
    pdev->flr_stats.default_wait_interval_ms = DEFAULT_WAIT_INTERVAL_MICSEC;
    if (IS_PFDEV(pdev))
    {
        DbgMessage(pdev, FATAL, "lm_cleanup_after_flr PF[%d] >>>\n",FUNC_ID(pdev));
        pdev->flr_stats.is_pf = TRUE;
        /* Re-enable target PF read access */
        REG_WR(pdev, PGLUE_B_REG_INTERNAL_PFID_ENABLE_TARGET_READ, 1);

        /*Poll on CFC per-pf usage-counter until its 0*/

        pdev->flr_stats.cfc_usage_counter = REG_WAIT_VERIFY_VAL(pdev, CFC_REG_NUM_LCIDS_INSIDE_PF, 0, wait_ms);
        DbgMessage(pdev, FATAL, "%d*%dms waiting for zeroed CFC per pf usage counter\n",pdev->flr_stats.cfc_usage_counter,DEFAULT_WAIT_INTERVAL_MICSEC);
        //return LM_STATUS_FAILURE;

        /* Poll on DQ per-pf usage-counter (until full dq-cleanup is implemented) until its 0*/
        pdev->flr_stats.dq_usage_counter = REG_WAIT_VERIFY_VAL(pdev, DORQ_REG_PF_USAGE_CNT, 0, wait_ms);
        DbgMessage(pdev, FATAL, "%d*%dms waiting for zeroed DQ per pf usage counter\n", pdev->flr_stats.dq_usage_counter, DEFAULT_WAIT_INTERVAL_MICSEC);

        /* Poll on QM per-pf usage-counter until its 0*/
        pdev->flr_stats.qm_usage_counter = REG_WAIT_VERIFY_VAL(pdev, QM_REG_PF_USG_CNT_0 + 4*FUNC_ID(pdev),0, wait_ms);
        DbgMessage(pdev, FATAL, "%d*%dms waiting for zeroed QM per pf usage counter\n", pdev->flr_stats.qm_usage_counter, DEFAULT_WAIT_INTERVAL_MICSEC);

        /* Poll on TM per-pf-usage-counter until its 0 */

        pdev->flr_stats.tm_vnic_usage_counter = REG_WAIT_VERIFY_VAL(pdev, TM_REG_LIN0_VNIC_UC + 4*PORT_ID(pdev),0, wait_ms);
        DbgMessage(pdev, FATAL, "%d*%dms waiting for zeroed TM%d(VNIC) per pf usage counter\n",
                    pdev->flr_stats.tm_vnic_usage_counter, DEFAULT_WAIT_INTERVAL_MICSEC, PORT_ID(pdev));

        pdev->flr_stats.tm_num_scans_usage_counter = REG_WAIT_VERIFY_VAL(pdev, TM_REG_LIN0_NUM_SCANS + 4*PORT_ID(pdev),0, wait_ms);
        DbgMessage(pdev, FATAL, "%d*%dms waiting for zeroed TM%d(NUM_SCANS) per pf usage counter\n",
                    pdev->flr_stats.tm_num_scans_usage_counter, DEFAULT_WAIT_INTERVAL_MICSEC, PORT_ID(pdev));

        pdev->flr_stats.dmae_cx = REG_WAIT_VERIFY_VAL(pdev, lm_dmae_idx_to_go_cmd(DMAE_WB_ACCESS_FUNCTION_CMD(FUNC_ID(pdev))), 0, wait_ms);
        DbgMessage(pdev, FATAL, "%d*%dms waiting for zeroed DMAE_REG_GO_C%d \n",
                    pdev->flr_stats.tm_num_scans_usage_counter, DEFAULT_WAIT_INTERVAL_MICSEC, DMAE_WB_ACCESS_FUNCTION_CMD(FUNC_ID(pdev)));
    }
    else
    {
        DbgMessage(pdev, FATAL, "lm_cleanup_after_flr VF[%d] >>>\n",ABS_VFID(pdev));

        /*
            VF FLR only part
        a.  Wait until there are no pending ramrods for this VFid in the PF DB. - No pending VF's pending ramrod. It's based on "FLR not during driver load/unload".
            What about set MAC?

        b.  Send the new "L2 connection terminate" ramrod for each L2 CID that was used by the VF,
            including sending the doorbell with the "terminate" flag. - Will be implemented in FW later

        c.  Send CFC delete ramrod on all L2 connections of that VF (set the CDU-validation field to "invalid"). - part of FW cleanup. VF_TO_PF_CID must initialized in
            PF CID array*/

        /*  3.  Poll on the DQ per-function usage-counter until it's 0. */
        pretend_value = ABS_FUNC_ID(pdev) | (1<<3) | (ABS_VFID(pdev) << 4);
        lm_status = lm_pretend_func(PFDEV(pdev), pretend_value);
        if (lm_status == LM_STATUS_SUCCESS)
        {
            pdev->flr_stats.dq_usage_counter = REG_WAIT_VERIFY_VAL(PFDEV(pdev), DORQ_REG_VF_USAGE_CNT, 0, wait_ms);
            lm_pretend_func(PFDEV(pdev), ABS_FUNC_ID(pdev));
            DbgMessage(pdev, FATAL, "%d*%dms waiting for DQ per vf usage counter\n", pdev->flr_stats.dq_usage_counter, DEFAULT_WAIT_INTERVAL_MICSEC);
        }
        else
        {
            DbgMessage(pdev, FATAL, "lm_pretend_func(%x) returns %d\n",pretend_value,lm_status);
            DbgMessage(pdev, FATAL, "VF[%d]: could not read DORQ_REG_VF_USAGE_CNT\n", ABS_VFID(pdev));
            return lm_status;
        }
    }

/*  4.  Activate the FW cleanup process by activating AggInt in the FW with GRC. Set the bit of the relevant function in the AggInt bitmask,
        to indicate to the FW which function is being cleaned. Wait for the per-function completion indication in the Cstorm RAM
*/
    function_for_clean_up = IS_VFDEV(pdev) ? FW_VFID(pdev) : FUNC_ID(pdev);
    cleanup_complete = 0xFFFFFFFF;
    LM_INTMEM_READ32(PFDEV(pdev),CSTORM_FINAL_CLEANUP_COMPLETE_OFFSET(function_for_clean_up),&cleanup_complete, BAR_CSTRORM_INTMEM);
    DbgMessage(pdev, FATAL, "CSTORM_FINAL_CLEANUP_COMPLETE_OFFSET is %x",cleanup_complete);
    if (cleanup_complete)
    {
        DbgBreak();
    }

    final_cleanup.command = (XSTORM_AGG_INT_FINAL_CLEANUP_INDEX << SDM_OP_GEN_COMP_PARAM_SHIFT) & SDM_OP_GEN_COMP_PARAM;
    final_cleanup.command |= (XSTORM_AGG_INT_FINAL_CLEANUP_COMP_TYPE << SDM_OP_GEN_COMP_TYPE_SHIFT) & SDM_OP_GEN_COMP_TYPE;
    final_cleanup.command |= 1 << SDM_OP_GEN_AGG_VECT_IDX_VALID_SHIFT;
    final_cleanup.command |= (function_for_clean_up << SDM_OP_GEN_AGG_VECT_IDX_SHIFT) & SDM_OP_GEN_AGG_VECT_IDX;

    DbgMessage(pdev, FATAL, "Final cleanup\n");

    REG_WR(PFDEV(pdev),XSDM_REG_OPERATION_GEN, final_cleanup.command);
    pdev->flr_stats.final_cleanup_complete = REG_WAIT_VERIFY_VAL(PFDEV(pdev), BAR_CSTRORM_INTMEM + CSTORM_FINAL_CLEANUP_COMPLETE_OFFSET(function_for_clean_up), 1, wait_ms);
    DbgMessage(pdev, FATAL, "%d*%dms waiting for final cleanup compete\n", pdev->flr_stats.final_cleanup_complete, DEFAULT_WAIT_INTERVAL_MICSEC);
    /* Lets cleanup for next FLR final-cleanup... */
    LM_INTMEM_WRITE32(PFDEV(pdev),CSTORM_FINAL_CLEANUP_COMPLETE_OFFSET(function_for_clean_up),0, BAR_CSTRORM_INTMEM);


/*  5.  ATC cleanup. This process will include the following steps (note that ATC will not be available for phase2 of the
        integration and the following should be added only in phase3):
    a.  Optionally, wait 2 ms. This is not a must. The driver can start polling (next steps) immediately,
        but take into account that it may take time till the done indications will be set.
    b.  Wait until INVALIDATION_DONE[function] = 1
    c.  Write-clear INVALIDATION_DONE[function] */


/*  6.  Verify PBF cleanup. Do the following for all PBF queues (queues 0,1,4, that will be indicated below with N):
    a.  Make sure PBF command-queue is flushed: Read pN_tq_occupancy. Let's say that the value is X.
        This number indicates the number of occupied transmission-queue lines.
        Poll on pN_tq_occupancy and pN_tq_lines_freed_cnt until one of the following:
            i.  pN_tq_occupancy is 0 (queue is empty). OR
            ii. pN_tq_lines_freed_cnt equals has advanced (cyclically) by X (all lines that were in the queue were processed). */

    for (idx = 0; idx < 3; idx++)
    {
        u32_t tq_to_free;
        u32_t tq_freed_cnt_start;
        u32_t tq_occ;
        u32_t tq_freed_cnt_last;
        u32_t pbf_reg_pN_tq_occupancy = 0;
        u32_t pbf_reg_pN_tq_lines_freed_cnt = 0;

        switch (idx)
        {
        case 0:
            pbf_reg_pN_tq_occupancy = (CHIP_IS_E3B0(pdev))? PBF_REG_TQ_OCCUPANCY_Q0 : PBF_REG_P0_TQ_OCCUPANCY;
            pbf_reg_pN_tq_lines_freed_cnt = (CHIP_IS_E3B0(pdev)) ? PBF_REG_TQ_LINES_FREED_CNT_Q0 : PBF_REG_P0_TQ_LINES_FREED_CNT;
            break;
        case 1:
            pbf_reg_pN_tq_occupancy = (CHIP_IS_E3B0(pdev)) ? PBF_REG_TQ_OCCUPANCY_Q1 : PBF_REG_P1_TQ_OCCUPANCY;
            pbf_reg_pN_tq_lines_freed_cnt = (CHIP_IS_E3B0(pdev)) ? PBF_REG_TQ_LINES_FREED_CNT_Q1 : PBF_REG_P1_TQ_LINES_FREED_CNT;
            break;
        case 2:
            pbf_reg_pN_tq_occupancy = (CHIP_IS_E3B0(pdev)) ? PBF_REG_TQ_OCCUPANCY_LB_Q : PBF_REG_P4_TQ_OCCUPANCY;
            pbf_reg_pN_tq_lines_freed_cnt = (CHIP_IS_E3B0(pdev)) ? PBF_REG_TQ_LINES_FREED_CNT_LB_Q : PBF_REG_P4_TQ_LINES_FREED_CNT;
            break;
        }
        pdev->flr_stats.pbf_queue[idx] = 0;
        tq_freed_cnt_last = tq_freed_cnt_start = REG_RD(PFDEV(pdev), pbf_reg_pN_tq_lines_freed_cnt);
        tq_occ = tq_to_free = REG_RD(PFDEV(pdev), pbf_reg_pN_tq_occupancy);
        DbgMessage(pdev, FATAL, "TQ_OCCUPANCY[%d]      : s:%x\n", (idx == 2) ? 4 : idx, tq_to_free);
        DbgMessage(pdev, FATAL, "TQ_LINES_FREED_CNT[%d]: s:%x\n", (idx == 2) ? 4 : idx, tq_freed_cnt_start);
        while(tq_occ && ((u32_t)S32_SUB(tq_freed_cnt_last, tq_freed_cnt_start) < tq_to_free))
        {
            if (pdev->flr_stats.pbf_queue[idx]++ < wait_ms/DEFAULT_WAIT_INTERVAL_MICSEC)
            {
                mm_wait(PFDEV(pdev), DEFAULT_WAIT_INTERVAL_MICSEC);
                tq_occ = REG_RD(PFDEV(pdev), pbf_reg_pN_tq_occupancy);
                tq_freed_cnt_last = REG_RD(PFDEV(pdev), pbf_reg_pN_tq_lines_freed_cnt);
            }
            else
            {
                DbgMessage(pdev, FATAL, "TQ_OCCUPANCY[%d]      : c:%x\n", (idx == 2) ? 4 : idx, tq_occ);
                DbgMessage(pdev, FATAL, "TQ_LINES_FREED_CNT[%d]: c:%x\n", (idx == 2) ? 4 : idx, tq_freed_cnt_last);
                DbgBreak();
                break;
            }
        }
        DbgMessage(pdev, FATAL, "%d*%dms waiting for PBF command queue[%d] is flushed\n",
                    pdev->flr_stats.pbf_queue[idx], DEFAULT_WAIT_INTERVAL_MICSEC, (idx == 2) ? 4 : idx);
    }

/*  b.  Make sure PBF transmission buffer is flushed: read pN_init_crd once and keep it in variable Y.
        Read pN_credit and keep it in X. Poll on pN_credit and pN_internal_crd_freed until one of the following:
            i.  (Y - pN_credit) is 0 (transmission buffer is empty). OR
            ii. pN_internal_crd_freed_cnt has advanced (cyclically) by Y-X (all transmission buffer lines that were occupied were freed).*/

    for (idx = 0; idx < 3; idx++)
    {
        u32_t init_crd;
        u32_t credit_last,credit_start;
        u32_t inernal_freed_crd_start;
        u32_t inernal_freed_crd_last = 0;
        u32_t pbf_reg_pN_init_crd = 0;
        u32_t pbf_reg_pN_credit = 0;
        u32_t pbf_reg_pN_internal_crd_freed = 0;
        switch (idx)
        {
        case 0:
            pbf_reg_pN_init_crd = (CHIP_IS_E3B0(pdev)) ? PBF_REG_INIT_CRD_Q0 : PBF_REG_P0_INIT_CRD;
            pbf_reg_pN_credit = (CHIP_IS_E3B0(pdev)) ? PBF_REG_CREDIT_Q0 : PBF_REG_P0_CREDIT;
            pbf_reg_pN_internal_crd_freed = (CHIP_IS_E3B0(pdev)) ? PBF_REG_INTERNAL_CRD_FREED_CNT_Q0 : PBF_REG_P0_INTERNAL_CRD_FREED_CNT;
            break;
        case 1:
            pbf_reg_pN_init_crd = (CHIP_IS_E3B0(pdev)) ? PBF_REG_INIT_CRD_Q1 : PBF_REG_P1_INIT_CRD;
            pbf_reg_pN_credit = (CHIP_IS_E3B0(pdev)) ? PBF_REG_CREDIT_Q1 : PBF_REG_P1_CREDIT;
            pbf_reg_pN_internal_crd_freed = (CHIP_IS_E3B0(pdev)) ? PBF_REG_INTERNAL_CRD_FREED_CNT_Q1 : PBF_REG_P1_INTERNAL_CRD_FREED_CNT;
            break;
        case 2:
            pbf_reg_pN_init_crd = (CHIP_IS_E3B0(pdev)) ? PBF_REG_INIT_CRD_LB_Q : PBF_REG_P4_INIT_CRD;
            pbf_reg_pN_credit = (CHIP_IS_E3B0(pdev)) ? PBF_REG_CREDIT_LB_Q : PBF_REG_P4_CREDIT;
            pbf_reg_pN_internal_crd_freed = (CHIP_IS_E3B0(pdev)) ? PBF_REG_INTERNAL_CRD_FREED_CNT_LB_Q : PBF_REG_P4_INTERNAL_CRD_FREED_CNT;
            break;
        }
        pdev->flr_stats.pbf_transmit_buffer[idx] = 0;
        inernal_freed_crd_last = inernal_freed_crd_start = REG_RD(PFDEV(pdev), pbf_reg_pN_internal_crd_freed);
        credit_last = credit_start = REG_RD(PFDEV(pdev), pbf_reg_pN_credit);
        init_crd = REG_RD(PFDEV(pdev), pbf_reg_pN_init_crd);
        DbgMessage(pdev, FATAL, "INIT CREDIT[%d]       : %x\n", (idx == 2) ? 4 : idx, init_crd);
        DbgMessage(pdev, FATAL, "CREDIT[%d]            : s:%x\n", (idx == 2) ? 4 : idx, credit_start);
        DbgMessage(pdev, FATAL, "INTERNAL_CRD_FREED[%d]: s:%x\n", (idx == 2) ? 4 : idx, inernal_freed_crd_start);
        while ((credit_last != init_crd)
               && (u32_t)S32_SUB(inernal_freed_crd_last, inernal_freed_crd_start) < (init_crd - credit_start))
        {
            if (pdev->flr_stats.pbf_transmit_buffer[idx]++ < wait_ms/DEFAULT_WAIT_INTERVAL_MICSEC)
            {
                mm_wait(PFDEV(pdev), DEFAULT_WAIT_INTERVAL_MICSEC);
                credit_last = REG_RD(PFDEV(pdev), pbf_reg_pN_credit);
                inernal_freed_crd_last = REG_RD(PFDEV(pdev), pbf_reg_pN_internal_crd_freed);
            }
            else
            {
                DbgMessage(pdev, FATAL, "CREDIT[%d]            : c:%x\n", (idx == 2) ? 4 : idx, credit_last);
                DbgMessage(pdev, FATAL, "INTERNAL_CRD_FREED[%d]: c:%x\n", (idx == 2) ? 4 : idx, inernal_freed_crd_last);
                DbgBreak();
                break;
            }
        }
        DbgMessage(pdev, FATAL, "%d*%dms waiting for PBF transmission buffer[%d] is flushed\n",
                    pdev->flr_stats.pbf_transmit_buffer[idx], DEFAULT_WAIT_INTERVAL_MICSEC, (idx == 2) ? 4 : idx);
    }

/*  7.  Wait for 100ms in order to make sure that the chip is clean, including all PCI related paths
        (in Emulation the driver can wait for 10ms*EmulationFactor, i.e.: 20s). This is especially required if FW doesn't implement
        the flows in Optional Operations (future enhancements).) */
    mm_wait(pdev, 10000*factor);

/*  8.  Verify that the transaction-pending bit of each of the function in the Device Status Register in the PCIe is cleared. */

#if defined(__LINUX) || defined(_VBD_)
    pcie_caps_offset = mm_get_cap_offset(pdev, PCI_CAP_PCIE);
    if (pcie_caps_offset != 0 && pcie_caps_offset != 0xFFFFFFFF)
    {
        u32_t dev_control_and_status = 0xFFFFFFFF;
        mm_read_pci(pdev, pcie_caps_offset + PCIE_DEV_CTRL, &dev_control_and_status);
        DbgMessage(pdev, FATAL, "Device Control&Status of PCIe caps is %x\n",dev_control_and_status);
        if (dev_control_and_status & (PCIE_DEV_STATUS_PENDING_TRANSACTION << 16))
        {
            DbgBreak();
        }
    }
#else
    DbgMessage(pdev, FATAL, "Function mm_get_cap_offset is not implemented yet\n");
    DbgBreak();
#endif
/*  9.  Initialize the function as usual this should include also re-enabling the function in all the HW blocks and Storms that
    were disabled by the MCP and cleaning relevant per-function information in the chip (internal RAM related information, IGU memory etc.).
        a.  In case of VF, PF resources that were allocated for previous VF can be re-used by the new VF. If there are resources
            that are not needed by the new VF then they should be cleared.
        b.  Note that as long as slow-path prod/cons update to Xstorm is not atomic, they must be cleared by the driver before setting
            the function to "enable" in the Xstorm.
        c.  Don't forget to enable the VF in the PXP or the DMA operation for PF in the PXP. */

    if (IS_PFDEV(pdev))
    {
        u32_t m_en;
        u32_t tmp = 0;

        tmp = REG_RD(pdev,CFC_REG_WEAK_ENABLE_PF);
        DbgMessage(pdev, FATAL, "CFC_REG_WEAK_ENABLE_PF is 0x%x\n",tmp);

        tmp = REG_RD(pdev,PBF_REG_DISABLE_PF);
        DbgMessage(pdev, FATAL, "PBF_REG_DISABLE_PF is 0x%x\n",tmp);

        tmp = REG_RD(pdev,IGU_REG_PCI_PF_MSI_EN);
        DbgMessage(pdev, FATAL, "IGU_REG_PCI_PF_MSI_EN is 0x%x\n",tmp);

        tmp = REG_RD(pdev,IGU_REG_PCI_PF_MSIX_EN);
        DbgMessage(pdev, FATAL, "IGU_REG_PCI_PF_MSIX_EN is 0x%x\n",tmp);

        tmp = REG_RD(pdev,IGU_REG_PCI_PF_MSIX_FUNC_MASK);
        DbgMessage(pdev, FATAL, "IGU_REG_PCI_PF_MSIX_FUNC_MASK is 0x%x\n",tmp);

        tmp = REG_RD(pdev,PGLUE_B_REG_SHADOW_BME_PF_7_0_CLR);
        DbgMessage(pdev, FATAL, "PGLUE_B_REG_SHADOW_BME_PF_7_0_CLR is 0x%x\n",tmp);

        tmp = REG_RD(pdev,PGLUE_B_REG_FLR_REQUEST_PF_7_0_CLR);
        DbgMessage(pdev, FATAL, "PGLUE_B_REG_FLR_REQUEST_PF_7_0_CLR is 0x%x\n",tmp);

        REG_WR(pdev, PGLUE_B_REG_INTERNAL_PFID_ENABLE_MASTER, 1);
        mm_wait(pdev,999999);

        m_en = REG_RD(pdev, PGLUE_B_REG_INTERNAL_PFID_ENABLE_MASTER);
        DbgMessage(pdev, FATAL, "M:0x%x\n",m_en);
    }

    if (IS_VFDEV(pdev))
    {
#ifdef VF_INVOLVED
        //lm_vf_enable_vf(pdev);
        lm_status = lm_vf_recycle_resc_in_pf(pdev);
        lm_set_con_state(pdev, LM_SW_LEADING_RSS_CID(pdev), LM_CON_STATE_CLOSE);
#endif
    }

    lm_fl_reset_clear_inprogress(pdev);

    return lm_status;
}

#define LM_GRC_TIMEOUT_MAX_IGNORE ARRSIZE(g_lm_chip_global[0].grc_timeout_val)



u32_t lm_inc_cnt_grc_timeout_ignore(struct _lm_device_t *pdev, u32_t val)
{
    const        u8_t bus_num  = INST_ID_TO_BUS_NUM(PFDEV(pdev)->vars.inst_id) ;
    static const u8_t arr_size = ARRSIZE(g_lm_chip_global[0].grc_timeout_val);
    const        u8_t idx      = g_lm_chip_global[bus_num].cnt_grc_timeout_ignored % arr_size ;

    g_lm_chip_global[bus_num].grc_timeout_val[idx] = val;

    return ++g_lm_chip_global[bus_num].cnt_grc_timeout_ignored;
}

static int ecore_gunzip(struct _lm_device_t *pdev, const u8 *zbuf, int len)
{
    /* TODO : Implement... */
    UNREFERENCED_PARAMETER_(pdev);
    UNREFERENCED_PARAMETER_(zbuf);
    UNREFERENCED_PARAMETER_(len);
    DbgBreakMsg("ECORE_GUNZIP NOT IMPLEMENTED\n");
    return FALSE;
}

static void ecore_reg_wr_ind(struct _lm_device_t *pdev, u32 addr, u32 val)
{
    lm_reg_wr_ind(pdev, addr, val);
}

static void ecore_write_dmae_phys_len(struct _lm_device_t *pdev,
                      lm_address_t phys_addr, u32 addr,
                      u32 len)
{
    lm_dmae_reg_wr_phys(pdev, lm_dmae_get(pdev, LM_DMAE_DEFAULT)->context,
                phys_addr, addr, (u16_t)len);
}

//The bug is that the RBC doesn't get out of reset after we reset the RBC.
static void rbc_reset_workaround(lm_device_t *pdev)
{
    u32_t val = 0;
#if defined(_VBD_CMD_) //This function is not needed in vbd_cmd env.
    return;
#endif

    if (CHIP_IS_E1x(pdev))
    {
        //a.Wait 60 microseconds only for verifying the ~64 cycles have passed.
        mm_wait(pdev, (DEFAULT_WAIT_INTERVAL_MICSEC *2));

        val = REG_RD(pdev,MISC_REG_RESET_REG_1) ;
        if(0 == (val & MISC_REGISTERS_RESET_REG_1_RST_RBCP))
        {
            //If bit 28 is '0' - This means RBCP block is in reset.(one out of reset)
            // Take RBC out of reset.
            REG_WR(pdev,(GRCBASE_MISC + MISC_REGISTERS_RESET_REG_1_SET),MISC_REGISTERS_RESET_REG_1_RST_RBCP);

            mm_wait(pdev, (DEFAULT_WAIT_INTERVAL_MICSEC *2));

            val = REG_RD(pdev,MISC_REG_RESET_REG_1) ;

            DbgMessage(pdev, WARN, "rbc_reset_workaround: MISC_REG_RESET_REG_1 after set= 0x%x\n",val);
            DbgBreakIf(0 == (val & MISC_REGISTERS_RESET_REG_1_RST_RBCP));
        }
    }
}


void lm_set_nig_reset_called(struct _lm_device_t *pdev)
{
    const u8_t bus_num = INST_ID_TO_BUS_NUM(PFDEV(pdev)->vars.inst_id) ;
    const u8_t flags   = LM_CHIP_GLOBAL_FLAG_NIG_RESET_CALLED;

    SET_FLAGS( g_lm_chip_global[bus_num].flags, flags) ;
}

void lm_clear_nig_reset_called(struct _lm_device_t *pdev)
{
    const u8_t bus_num = INST_ID_TO_BUS_NUM(PFDEV(pdev)->vars.inst_id) ;
    const u8_t flags   = LM_CHIP_GLOBAL_FLAG_NIG_RESET_CALLED;

    RESET_FLAGS( g_lm_chip_global[bus_num].flags, flags) ;
}

u8_t lm_is_nig_reset_called(struct _lm_device_t *pdev)
{
    const u8_t bus_num = INST_ID_TO_BUS_NUM(PFDEV(pdev)->vars.inst_id) ;
    const u8_t flags   = LM_CHIP_GLOBAL_FLAG_NIG_RESET_CALLED;

    return ( 0 != GET_FLAGS( g_lm_chip_global[bus_num].flags, flags ) );
}

/* This function reset a path (e2) or a chip (e1/e1.5)
 * includeing or excluding the nig (b_with_nig)
 */
void lm_reset_path( IN struct _lm_device_t *pdev,
                    IN const  u8_t          b_with_nig )
{
    const u32_t reg_1_clear     = b_with_nig ? 0xd3ffffff : 0xd3ffff7f ;
    u32_t       reg_2_clear     = 0x1400;
    u32_t       idx             = 0;
    u32_t       val             = 0;
    u32_t       offset          = 0;
    u32_t       wait_cnt        = 5;

    // set of registers to be saved/restored before/after nig reset
    static const u32_t reg_arr_e3[]    = { NIG_REG_P0_MAC_IN_EN,
                                           NIG_REG_P1_MAC_IN_EN };

    static const u32_t reg_arr_e1_e2[] = { NIG_REG_EMAC0_IN_EN,
                                           NIG_REG_EMAC1_IN_EN,
                                           NIG_REG_BMAC0_IN_EN,
                                           NIG_REG_BMAC1_IN_EN };

    static const u32_t reg_arr_ftq[]   = { NIG_REG_EGRESS_MNG0_FIFO_EMPTY,
                                           NIG_REG_EGRESS_MNG1_FIFO_EMPTY,
                                           NIG_REG_INGRESS_RMP0_DSCR_EMPTY,
                                           NIG_REG_INGRESS_RMP1_DSCR_EMPTY};

    static const u32_t ftq_mask        = ( 1 << ARRSIZE(reg_arr_ftq) ) - 1 ; // we need all regs to be 1...

    // save values of registers
    u32_t        restore_arr[max(ARRSIZE(reg_arr_e1_e2),ARRSIZE(reg_arr_e3))]  = {0};

    const u8_t   idx_max     = CHIP_IS_E3(pdev) ? ARRSIZE(reg_arr_e3) : ARRSIZE(reg_arr_e1_e2) ;
    const u32_t* reg_arr_ptr = CHIP_IS_E3(pdev) ? reg_arr_e3 : reg_arr_e1_e2 ;

    DbgMessage(pdev, WARN, "lm_reset_path:%sreset [begin]\n", b_with_nig ? " (with NIG) " : " ");

    if( b_with_nig )
    {
        // Ugly patch - we need to prevent nig reset - to be fixed SOON (TODO T7.2?)
        // We don't care port0/port1 the registers will always exist

        // save values + write zeros
        for( idx = 0; idx < idx_max; idx++ )
        {
            restore_arr[idx] = REG_RD( pdev, reg_arr_ptr[idx] );
            REG_WR( pdev, reg_arr_ptr[idx], 0 );
        }

        // wait 200 msec before we reset the nig so all packets will pass thorugh
        // 200000 and not 50*4000 since we want this wait to be "only" 200000ms
        // when we used 50*4000 method, the actual sleep time was much higher (more than 16 seconds...!)
        // this caused hw lock timeout (16sec) in lm_reset_device_if_undi_active() funciton.
        do
        {
            val = 0;

            // first 200000ms we always wait...
            mm_wait( pdev, 200000 );

            // check values of FTQ and verify they are all one
            // if not wait 200000ms up to 5 times...(1 second)
            for( idx = 0; idx < ARRSIZE(reg_arr_ftq); idx++ )
            {
                offset = reg_arr_ftq[idx];
                val |= ( REG_RD( pdev, offset ) ) << idx ;
            }
        } while( wait_cnt-- && ( ftq_mask != val ) );

        // Debug break only if MCP is detected (NVM is not empty)
        if (lm_is_mcp_detected(pdev))
        {
            DbgBreakIf( ftq_mask != val );
        }
    }

    /* reset device */
    REG_WR(pdev, GRCBASE_MISC+ MISC_REGISTERS_RESET_REG_1_CLEAR, reg_1_clear );

    if (CHIP_IS_E3(pdev))
    {
        // New blocks that need to be taken out of reset
        // Mstat0 - bit 24 of RESET_REG_2
        // Mstat1 - bit 25 of RESET_REG_2
        reg_2_clear |= (MISC_REGISTERS_RESET_REG_2_MSTAT1 | MISC_REGISTERS_RESET_REG_2_MSTAT0);
    }

    REG_WR(pdev, GRCBASE_MISC+ MISC_REGISTERS_RESET_REG_2_CLEAR, reg_2_clear);

    if( b_with_nig  )
    {
        lm_set_nig_reset_called(pdev);
        /* take the NIG out of reset */
        REG_WR(pdev, GRCBASE_MISC+ MISC_REGISTERS_RESET_REG_1_SET, MISC_REGISTERS_RESET_REG_1_RST_NIG);

        // restore....
        for( idx = 0; idx < idx_max; idx++ )
        {
            REG_WR( pdev, reg_arr_ptr[idx], restore_arr[idx] );
        }
    }

    pdev->vars.b_is_dmae_ready = FALSE;

    DbgMessage(pdev, WARN, "lm_reset_path:%sreset [end]\n", b_with_nig ? " (with NIG) ": " ");

    // rbc_reset_workaround() should be called AFTER nig is out of reset
    // otherwise the probability that nig will be accessed by bootcode while
    // it is in reset is very high (this will cause GRC_TIMEOUT)

    // TODO - we still need to deal with CQ45947 (calling rbc_reset_workaround before nig is out of reset will
    //        cause the grc_timeout to happen
    DbgMessage(pdev, WARN, "lm_reset_path:%sreset rbcp wait [begin]\n", b_with_nig ? " (with NIG) ": " ");
    rbc_reset_workaround(pdev);
    DbgMessage(pdev, WARN, "lm_reset_path:%sreset rbcp wait [end]\n", b_with_nig ? " (with NIG) ": " ");
}

/*
 * quote from bnx2x:
 *
 * "previous driver DMAE transaction may have occurred when pre-boot stage ended
 * and boot began, or when kdump kernel was loaded. Either case would invalidate
 * the addresses of the transaction, resulting in was-error bit set in the pci
 * causing all hw-to-host pcie transactions to timeout. If this happened we want
 * to clear the interrupt which detected this from the pglueb and the was done
 * bit"
 */

static void lm_reset_prev_interrupted_dmae(struct _lm_device_t *pdev)
{
    u32_t val = 0;

    if ( CHIP_IS_E1x(pdev) )
    {
        // the register below doesn't exists in E1/E1.5 and will cause RBCN attention in
        // case accessed, so we do nothing in case chip is earlier than E2 (CQ63388, CQ63302).
        return;
    }

    val = REG_RD(pdev, PGLUE_B_REG_PGLUE_B_INT_STS);

    if (val & PGLUE_B_PGLUE_B_INT_STS_REG_WAS_ERROR_ATTN)
    {
        DbgMessage(pdev, WARNi, "lm_reset_prev_interrupted_dmae: was error bit was found to be set in pglueb upon startup. Clearing");
        REG_WR(pdev, PGLUE_B_REG_WAS_ERROR_PF_7_0_CLR, 1 << FUNC_ID(pdev));
    }
}

// return TRUE if function is hidden
static u8_t lm_reset_device_if_undi_func_hide_helper( struct _lm_device_t       *pdev,
                                                      const  u32_t               chip_id,
                                                      const  u8_t                path_id,
                                                      const  u8_t                port,
                                                      const  u8_t                vnic,
                                                      const  u8_t                port_factor,
                                                      const  lm_chip_port_mode_t port_mode )
{
    u8_t  b_hidden       = FALSE;
    u8_t  func_config_id = 0;
    u32_t offset         = 0;
    u32_t mf_config      = 0;    

    // Macros taken from MFW .h files to have a better and correct use of the function/port matrix.
    #define E2_2P_PF_NUM(path, port, pf)            (((pf) << 1) | (path))                  /* pf: 0..3     ==> pf_num: 0..7 */
    #define E2_4P_PF_NUM(path, port, pf)            (((pf) << 2) | ((port) << 1) | (path))  /* pf: 0..1     ==> pf_num: 0..7 */
    #define E2_PF_NUM(path, port, pf)               ((port_mode == LM_CHIP_PORT_MODE_4) ? E2_4P_PF_NUM(path, port, pf) : E2_2P_PF_NUM(path, port, pf))

     if( CHIP_IS_E1_PARAM(chip_id) )
     {
         DbgBreakMsg("We should not reach this line\n");
         return b_hidden;
     }

     if( CHIP_IS_E1x_PARAM(chip_id) )
     {
         func_config_id = ( port_factor * vnic ) + port;
     }
     else
     {
         func_config_id = E2_PF_NUM( path_id , port, vnic );
     }

     offset = OFFSETOF(mf_cfg_t, func_mf_config[func_config_id].config);
     LM_MFCFG_READ(pdev, offset, &mf_config);     
     
     if( mf_config & FUNC_MF_CFG_FUNC_HIDE )
     {
         b_hidden = TRUE;
     }

     return b_hidden;
}

void lm_reset_device_if_undi_active(struct _lm_device_t *pdev)
{
    u32_t                         val                                 = 0;
    u8_t                          vnic                                = 0;
    u8_t                          port                                = 0;
    u8_t                          opcode_idx                          = 0; // 0 = load, 1 = unload
    lm_loader_response            resp                                = 0;
    u32_t                         swap_val                            = 0;
    u32_t                         swap_en                             = 0;
    u32_t                         rst_dorq_val                        = 0;
    u8_t                          port_max                            = 0;
    u8_t                          b_hidden                            = FALSE;
    u8_t                          b_first_non_hidden_iter             = TRUE;
    u8_t                          last_valid_vnic                     = 0;
    static const u32_t            param_loader                        = DRV_MSG_CODE_UNLOAD_SKIP_LINK_RESET;
    static const u32_t            UNDI_ACTIVE_INDICATION_VAL          = 7;
    static const lm_loader_opcode opcode_arr[]                        = {LM_LOADER_OPCODE_LOAD, LM_LOADER_OPCODE_UNLOAD_WOL_DIS} ;
    const lm_chip_port_mode_t     port_mode                           = CHIP_PORT_MODE(pdev);
    u8_t                          port_factor                         = 0;
    u8_t                          vnics_per_port                      = 0;
    const u8_t                    func_mb_id                          = FUNC_MAILBOX_ID(pdev); // Store original pdev func mb id
    const u8_t                    path_id                             = PATH_ID(pdev);
    static const u32_t            misc_registers_reset_reg_1_rst_dorq = MISC_REGISTERS_RESET_REG_1_RST_DORQ;

    /*
     * Clear possible previously interrupted DMAE which may have left PCI inaccessible.
     */

    lm_reset_prev_interrupted_dmae(pdev);

    /*
    * Check if device is active and was previously initialized by
    * UNDI driver.  UNDI driver initializes CID offset for normal bell
    * to 0x7.
    */

    if( LM_STATUS_SUCCESS == lm_hw_lock(pdev, HW_LOCK_RESOURCE_RESET, TRUE) )
    {
        rst_dorq_val = REG_RD(pdev,MISC_REG_RESET_REG_1);

        // dorq is out of reset
        if( rst_dorq_val & misc_registers_reset_reg_1_rst_dorq )
        {
            val = REG_RD(pdev,DORQ_REG_NORM_CID_OFST);
        }

        DbgMessage(pdev, WARN, "lm_reset_device_if_undi_active: DORQ_REG_NORM_CID_OFST val = 0x%x\n",val);

        if( UNDI_ACTIVE_INDICATION_VAL == val )
        {
            REG_WR( pdev, DORQ_REG_NORM_CID_OFST ,0 );
        }
        else
        {
            // We call here with FALSE since there might be a race (only here)
            // that lm_hw_clear_all_locks() will clear the lock altough it is acquired
            // and than we get ASSERT in checked builds.
            // so this FALSE here is only to prevent ASSERT on checked builds when ER enabled (CQ60944).
            lm_hw_unlock_ex(pdev, HW_LOCK_RESOURCE_RESET, FALSE );

            // undi is not active, nothing to do.
            return;
        }
    }
    else
    {
        // lock is already taken by other func we have nothing to do though this is NOT acceptable we get here...
        return;
    }

    DbgMessage(pdev, WARN, "lm_reset_device_if_undi_active: UNDI is active! need to reset device\n");

    if (GET_FLAGS( pdev->params.test_mode, TEST_MODE_NO_MCP))
    {
        /* TBD: E1H - when MCP is not present, determine if possible to get here */
        DbgBreakMsg("lm_reset_device_if_undi_active: reading from shmem when MCP is not present\n");
    }

    switch( port_mode )
    {
    case LM_CHIP_PORT_MODE_NONE: // E1.0/E1.5: we enter this if() one time  - for one of the functions, and and mailbox func numbers are 0 and 1
    case LM_CHIP_PORT_MODE_4:    // E2
        port_max       = PORT_MAX;
        port_factor    = (LM_CHIP_PORT_MODE_4 == port_mode) ? 4 : 2;
        vnics_per_port = (LM_CHIP_PORT_MODE_4 == port_mode )? 2 : pdev->params.vnics_per_port; // for 4-port it is always 2. for others its upon param
        break;

    case LM_CHIP_PORT_MODE_2:
        port_max       = 1; // E2: we enter this if() maximum twice - once for each path, and mailbox func number is 0 for both times
        port_factor    = 2;
        vnics_per_port = pdev->params.vnics_per_port;; // Always symetric in case not 4 port mode.
        break;

    default:
        DbgBreakMsg("we should not reach this line!");
        break;
    }

    ASSERT_STATIC( 2 == ARRSIZE(opcode_arr) );
    DbgBreakIf( LM_LOADER_OPCODE_LOAD != opcode_arr[0] );
    DbgBreakIf( LM_LOADER_OPCODE_LOAD == opcode_arr[1] );

    // We do here two opcode iterations, each one of them for all ports...
    // 1. first iteration(s) will "tell" the mcp that all ports are loaded (MCP accepts LOAD requests for ports that are already loaded.)
    //    This way we cann assure that driver is the "owner" of the hardware (includes NIG)
    //    So we can reset the nig.
    //
    // 2. second iteration(s) will "tell" the mcp that all ports are unloaded so we can "come clean" for regular driver load flow
    for( opcode_idx = 0; opcode_idx < ARRSIZE(opcode_arr); opcode_idx++ )
    {
        for( port = 0; port < port_max; port++ )
        {
            b_first_non_hidden_iter = TRUE;

            // Check what is the last valid vnic (non hidden one)
            for( vnic = 0; vnic < vnics_per_port; vnic++ )
            {                
                if( CHIP_IS_E1(pdev) )
                {
                    // we don't have func_mf_config in E1. To prevent invalid access to shmem - break.
                    last_valid_vnic = 0;
                    break;
                }

                b_hidden = lm_reset_device_if_undi_func_hide_helper( pdev,
                                                                     CHIP_NUM(pdev),
                                                                     path_id,
                                                                     port,
                                                                     vnic,
                                                                     port_factor,
                                                                     port_mode );

                if( !b_hidden )
                {
                    last_valid_vnic = vnic; // we save "last_valid_vnic" for later use in reset loop
                                            // this is the reason we make this loop twice (here and below)
                }
            }

            for( vnic = 0; vnic <= last_valid_vnic; vnic++ )
            {
                // NOTE: it seems that these two line are redundant after we have the new FUNC_MAILBOX_ID macro
                //       keep it for now
                pdev->params.pfunc_mb_id = FUNC_MAILBOX_ID_PARAM( port, vnic, CHIP_NUM(pdev), port_mode );

                if( !CHIP_IS_E1(pdev) )
                {
                    b_hidden = lm_reset_device_if_undi_func_hide_helper( pdev,
                                                                         CHIP_NUM(pdev),
                                                                         path_id,
                                                                         port,
                                                                         vnic,
                                                                         port_factor,
                                                                         port_mode );

                    if( b_hidden )
                    {
                        continue;
                    }
                }

                // get fw_wr_seq for the func
                lm_mcp_cmd_init(pdev);

                resp = lm_loader_lock(pdev, opcode_arr[opcode_idx] );

                if( LM_LOADER_RESPONSE_UNLOAD_COMMON == resp )
                {
                    DbgBreakIf( LM_LOADER_OPCODE_LOAD == opcode_arr[opcode_idx] );
                }

                if ( LM_LOADER_OPCODE_LOAD == opcode_arr[opcode_idx] )
                {
                    // clean HC config (only if exists  E1.0/E1.5)
                    // INTR_BLK_TYPE is not valid since we don't have this information at this phase yet.
                    if ( CHIP_IS_E1x(pdev) )
                    {
                        if( b_first_non_hidden_iter ) // This might be redundent but since before BCV change this code was running once per port we keep it as it is
                        {
                            REG_WR(pdev,HC_REG_CONFIG_0+(4*port),0x1000);
                        }
                    }

                    if( b_first_non_hidden_iter ) // per port no need to run more than once
                    {
                        // mask AEU signal
                        REG_WR(pdev,MISC_REG_AEU_MASK_ATTN_FUNC_0+(4*port),0);
                        b_first_non_hidden_iter = FALSE;
                    }

                    if( last_valid_vnic == vnic )
                    {
                         // TODO: Reset take into account mstat - dealed better in main branch where reset chip issue is tidier,
                         // leaving this for integrate...

                        // save nig swap register before NIG reset
                        swap_val = REG_RD(pdev,NIG_REG_PORT_SWAP);
                        swap_en  = REG_RD(pdev,NIG_REG_STRAP_OVERRIDE);

                        // reset the chip with nig
                        lm_reset_path( pdev, TRUE );

                        // restore nig swap register
                        REG_WR(pdev,NIG_REG_PORT_SWAP,swap_val);
                        REG_WR(pdev,NIG_REG_STRAP_OVERRIDE,swap_en);
                    }// nig reset
                }
                lm_loader_unlock(pdev, opcode_arr[opcode_idx], &param_loader ) ;
            } // vnic loop
        } // port loop
    } // opcode loop

    // We expect that last reposne will be LM_LOADER_RESPONSE_UNLOAD_COMMON
    if( LM_LOADER_RESPONSE_UNLOAD_COMMON != resp )
    {
        DbgBreakIf( LM_LOADER_RESPONSE_UNLOAD_COMMON != resp );
    }

    // restore original function number
    pdev->params.pfunc_mb_id = func_mb_id;

    lm_hw_unlock(pdev, HW_LOCK_RESOURCE_RESET);

    // after the unlock the chip/path is in reset for sure, then second port won't see 7 in the DORQ_REG_NORM_CID_OFST

} // lm_reset_device_if_undi_active

/**lm_disable_function_in_nig
 * Configure the NIG LLH so that packets targeting the given PF
 * are marked as "classification failed".
 * This function must be called before sending the FUNCTION_STOP
 * ramrod.
 *
 * @param pdev the PF to disable.
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         failure value on failure.
 */
lm_status_t lm_disable_function_in_nig(struct _lm_device_t *pdev)
{
    lm_status_t lm_status   = LM_STATUS_SUCCESS;
    u32_t nig_entry_idx     = 0;
    const u32_t MAX_OFFSET_IN_NIG_MEM1      = 8;
    const u32_t MAX_OFFSET_IN_NIG_MEM2      = MAX_MAC_OFFSET_IN_NIG - MAX_OFFSET_IN_NIG_MEM1;
    const u32_t nig_mem_enable_base_offset  = (PORT_ID(pdev) ? NIG_REG_LLH1_FUNC_MEM_ENABLE : NIG_REG_LLH0_FUNC_MEM_ENABLE);
    const u32_t nig_mem2_enable_base_offset = (PORT_ID(pdev) ? NIG_REG_P1_LLH_FUNC_MEM2_ENABLE : NIG_REG_P0_LLH_FUNC_MEM2_ENABLE);

    if (!IS_MULTI_VNIC(pdev))
    {
        DbgBreakIf(!IS_MULTI_VNIC(pdev));
        return LM_STATUS_SUCCESS;
    }

    if (IS_MF_SD_MODE(pdev))
    {
        /* for SD mode, clear NIG_REG_LLH1_FUNC_EN */
        REG_WR(pdev, (PORT_ID(pdev) ? NIG_REG_LLH1_FUNC_EN : NIG_REG_LLH0_FUNC_EN), 0);
        lm_set_func_en(pdev, FALSE); /* if function should be enabled it will be set when wol is configured */
    }
    else if (IS_MF_SI_MODE(pdev) || IS_MF_AFEX_MODE(pdev))
    {
    /*for NPAR/NPAR-SD mode, clear every NIG LLH entry by clearing NIG_REG_LLH1_FUNC_MEM_ENABLE for every entry in both
     NIG mem1 and mem2.*/
        for (nig_entry_idx = 0; nig_entry_idx < MAX_OFFSET_IN_NIG_MEM1; ++nig_entry_idx)
        {
            REG_WR(pdev, nig_mem_enable_base_offset + nig_entry_idx*sizeof(u32_t), 0);
        }
        for (nig_entry_idx = 0; nig_entry_idx < MAX_OFFSET_IN_NIG_MEM2; ++nig_entry_idx)
        {
            REG_WR(pdev, nig_mem2_enable_base_offset + nig_entry_idx*sizeof(u32_t), 0);
        }
    }
    else
    {
        DbgBreakMsg("Invalid MF mode.");
    }

    return lm_status;
}

/**
 * This function sends the function-stop ramrod and waits
 * synchroniously for its completion
 *
 * @param pdev
 *
 * @return lm_status_t SUCCESS / TIMEOUT on waiting for
 *         completion
 */
lm_status_t lm_function_stop(struct _lm_device_t *pdev)
{

    lm_status_t lm_status = LM_STATUS_SUCCESS;


    DbgMessage(pdev, INFORMeq|INFORMl2sp, "#lm_function_stop\n");


    pdev->eq_info.function_state = FUNCTION_STOP_POSTED;

    lm_status = lm_sq_post(pdev,
                           0,
                           RAMROD_CMD_ID_COMMON_FUNCTION_STOP,
                           CMD_PRIORITY_NORMAL,
                           NONE_CONNECTION_TYPE,
                           0 );

    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = lm_wait_state_change(pdev, &pdev->eq_info.function_state, FUNCTION_STOP_COMPLETED);

    return lm_status;
} /* lm_function_stop */

lm_status_t lm_chip_stop(struct _lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    const u32_t fwd_cid   = FWD_CID(pdev);

#ifdef VF_INVOLVED
    if (IS_VFDEV(pdev))
    {
        return lm_status;
    }
#endif
    if (lm_fl_reset_is_inprogress(pdev))
    {
        lm_set_con_state(pdev, fwd_cid, LM_CON_STATE_CLOSE);
        DbgMessage(pdev, WARN, "lm_chip_stop: Under FLR: \"close\" leading and FWD conns.\n");
        return LM_STATUS_SUCCESS;
    }
    if ((lm_status = lm_close_forward_con(pdev)) != LM_STATUS_SUCCESS)
    {
        DbgMessage(pdev, FATAL, "lm_chip_stop: ERROR closing FWD connection!!!\n");
    }

    if (pdev->params.multi_vnics_mode)
    {
        lm_disable_function_in_nig(pdev);
    }

    lm_status = lm_function_stop(pdev);

    if ((lm_status != LM_STATUS_SUCCESS) && (lm_status != LM_STATUS_ABORTED))
    {
        DbgMessage(pdev, FATAL, "lm_chip_stop: ERROR closing function!!!\n");
        DbgBreak();
    }

    /* Function stop has been sent, we should now block slowpath commands  */
    lm_sq_change_state(pdev, SQ_STATE_BLOCKED);

    return lm_status;
}

/* This function clears the pf enable bit in the pglue-b and cfc, to make sure that if any requests
 * are made on this function they will be dropped before they can cause any fatal errors. */
static void clear_pf_enable(lm_device_t *pdev)
{
    REG_WR(pdev, PGLUE_B_REG_INTERNAL_PFID_ENABLE_MASTER, 0);
    REG_WR(pdev, CFC_REG_WEAK_ENABLE_PF,0);
    //REG_WR(pdev, CFC_REG_STRONG_ENABLE_PF,0);
}

static void uninit_pxp2_blk(lm_device_t *pdev)
{
    u32_t rq_onchip_at_reg, on_chip_addr2_val;
    u32_t k, temp;

    if(ERR_IF(!pdev))
    {
        return;
    }


    /* clean ILT table
     * before doing that we must promise that all the ILT clients (CDU/TM/QM/SRC) of the
     * disabled function are not going to access the table anymore:
     * - TM: already disabled in "reset function part"
     * - CDU/QM: all L2/L4/L5 connections are already closed
     * - SRC: In order to make sure SRC request is not initiated:
     *    - in MF mode, we clean the ILT table in the per func phase, after LLH was already disabled
     *    - in SF mode, we clean the ILT table in the per port phase, after port link was already reset */

    temp              = FUNC_ID(pdev) * ILT_NUM_PAGE_ENTRIES_PER_FUNC;
    rq_onchip_at_reg  = CHIP_IS_E1(pdev) ? PXP2_REG_RQ_ONCHIP_AT : PXP2_REG_RQ_ONCHIP_AT_B0;
    on_chip_addr2_val = CHIP_IS_E1x(pdev)? 0 : ONCHIP_ADDR0_VALID();

    for (k=0;k<ILT_NUM_PAGE_ENTRIES_PER_FUNC;temp++,k++)
    {
        REG_WR_IND(pdev,rq_onchip_at_reg+temp*8,0);
        REG_WR_IND(pdev,rq_onchip_at_reg+temp*8+4,on_chip_addr2_val);
    }

    PXP2_SET_FIRST_LAST_ILT(pdev, CDU, 0, 0);
    PXP2_SET_FIRST_LAST_ILT(pdev, QM,  0, 0);
    PXP2_SET_FIRST_LAST_ILT(pdev, SRC, 0, 0);

    /* Timers workaround bug for E2 phase3: if this is vnic-3, we need to set the entire ilt range for this timers. */
    if (!CHIP_IS_E1x(pdev) && VNIC_ID(pdev) == 3)
    {
        PXP2_SET_FIRST_LAST_ILT(pdev, TM,  0, ILT_NUM_PAGE_ENTRIES - 1);
    }
    else
    {
        PXP2_SET_FIRST_LAST_ILT(pdev, TM,  0, 0);
    }
}

/**
 * Function takes care of resetting everything related to the
 * function stage
 *
 * @param pdev
 * @param cleanup - this indicates whether we are in the last
 *                "Reset" function to be called, if so we need
 *                to do some cleanups here, otherwise they'll be
 *                done in later stages
 *
 * @return lm_status_t
 */
lm_status_t lm_reset_function_part(struct _lm_device_t *pdev, u8_t cleanup)
{
    /*It assumed that all protocols are down all unload ramrod already completed*/
    u32_t cnt         = 0;
    u32_t val         = 0;
    const u8_t  port  = PORT_ID(pdev);
    const u8_t  func  = FUNC_ID(pdev);
    u8_t  sb_id       = 0;


    if (IS_MULTI_VNIC(pdev) && IS_PMF(pdev))
    {
        DbgMessage(pdev, WARN,
                        "lm_reset_function_part: Func %d is no longer PMF \n", FUNC_ID(pdev));
        // disconnect from NIG attention
        if (INTR_BLK_TYPE(pdev) == INTR_BLK_HC)
        {
            REG_WR(pdev,  (PORT_ID(pdev) ? HC_REG_LEADING_EDGE_1 : HC_REG_LEADING_EDGE_0), 0);
            REG_WR(pdev,  (PORT_ID(pdev) ? HC_REG_TRAILING_EDGE_1 : HC_REG_TRAILING_EDGE_0), 0);
        }
        else
        {
            REG_WR(pdev,  IGU_REG_TRAILING_EDGE_LATCH, 0);
            REG_WR(pdev,  IGU_REG_LEADING_EDGE_LATCH, 0);
        }
        MM_ACQUIRE_PHY_LOCK(pdev);
        lm_stats_on_pmf_update(pdev,FALSE);
        MM_RELEASE_PHY_LOCK(pdev);
    }

    /*  Configure IGU */
    if (INTR_BLK_TYPE(pdev) == INTR_BLK_HC)
    {
        REG_WR(pdev,HC_REG_CONFIG_0+(4*port),0x1000);
    }

    /*  Timer stop scan.*/
    REG_WR(pdev,TM_REG_EN_LINEAR0_TIMER + (4*port),0);
    for(cnt = 0; cnt < LM_TIMERS_SCAN_POLL; cnt++)
    {
        mm_wait(pdev, LM_TIMERS_SCAN_TIME); /* 1m */

        val=REG_RD(pdev,TM_REG_LIN0_SCAN_ON+(4*port));
        if (!val)
        {
            break;
        }

        // in case reset in progress
        // we won't get completion so no need to wait
        if(CHIP_IS_E1x(pdev) && lm_reset_is_inprogress(pdev) )
        {
            break;
        }
    }
    /*timeout*/
    DbgMessage(pdev, INFORMi, "timer status on %d \n",val);

    /* shutdown bug - in case of shutdown it's quite possible that the timer blocks hangs the scan never ends */
    if (!lm_reset_is_inprogress(pdev))
    {
        DbgBreakIf(cnt == LM_TIMERS_SCAN_POLL);
    }

    // reset the fw statistics (so next time client is up data will be correct)
    // if we don't call it here - we'll see in statistics 4GB+real
    lm_stats_fw_reset(pdev) ;

    /* Timers workaround bug: before cleaning the ilt we need to disable the pf-enable bit in the pglc + cfc */
    if (cleanup)
    { /* pdev->params.multi_vnics_mode, function that gets response "port/common" does this in the lm_reset_port_part  */
        if (!CHIP_IS_E1x(pdev))
        {
            clear_pf_enable(pdev);
            pdev->vars.b_is_dmae_ready = FALSE; /* Can't access dmae since bus-master is disabled */
        }
        uninit_pxp2_blk(pdev);
    }

    /* Disable the function and status  blocks in the STORMs unless under FLR (don't want to intefere
     * with FW flow) */
    if (!lm_reset_is_inprogress(pdev))
    {
        LM_INTMEM_WRITE8(pdev, XSTORM_FUNC_EN_OFFSET(FUNC_ID(pdev)), 0, BAR_XSTRORM_INTMEM);
        LM_INTMEM_WRITE8(pdev, CSTORM_FUNC_EN_OFFSET(FUNC_ID(pdev)), 0, BAR_CSTRORM_INTMEM);
        LM_INTMEM_WRITE8(pdev, TSTORM_FUNC_EN_OFFSET(FUNC_ID(pdev)), 0, BAR_TSTRORM_INTMEM);
        LM_INTMEM_WRITE8(pdev, USTORM_FUNC_EN_OFFSET(FUNC_ID(pdev)), 0, BAR_USTRORM_INTMEM);

        LM_FOREACH_SB_ID(pdev, sb_id)
        {
            LM_INTMEM_WRITE8(pdev, CSTORM_STATUS_BLOCK_DATA_STATE_OFFSET(LM_FW_SB_ID(pdev, sb_id)),
                      SB_DISABLED, BAR_CSTRORM_INTMEM);
        }

        LM_INTMEM_WRITE8(pdev, CSTORM_SP_STATUS_BLOCK_DATA_STATE_OFFSET(func),
                         SB_DISABLED, BAR_CSTRORM_INTMEM);
    }

    return LM_STATUS_SUCCESS;
}



lm_status_t lm_reset_port_part(struct _lm_device_t *pdev)
{
    /*It assumed that all protocols are down all unload ramrod already completed*/
    u32_t      val  = 0;
    const u8_t port = PORT_ID(pdev);

    /*  TODO Configure ACPI pattern if required. */
    /*  TODO Close the NIG port (also include congestion management toward XCM).*/
    // disable attention from nig
    REG_WR(pdev, NIG_REG_MASK_INTERRUPT_PORT0 + 4*port,0x0);

    // Do not rcv packets to BRB
    REG_WR(pdev, NIG_REG_LLH0_BRB1_DRV_MASK + 4*port,0x0);

    // Do not direct rcv packets that are not for MCP to the brb
    REG_WR(pdev, NIG_REG_LLH0_BRB1_NOT_MCP  + 4*32*port,0x0);

    // If DCBX is enabled we always want to go back to ETS disabled.
    // NIG is not reset
    if(IS_DCB_ENABLED(pdev))
    {
        elink_ets_disabled(&pdev->params.link,
                           &pdev->vars.link);
    }

    // reset external phy to cause link partner to see link down
    MM_ACQUIRE_PHY_LOCK(pdev);
    lm_reset_link(pdev);
    MM_RELEASE_PHY_LOCK(pdev);
    /*  Configure AEU.*/
    REG_WR(pdev,MISC_REG_AEU_MASK_ATTN_FUNC_0+(4*port),0);

    /* shutdown bug - in case of shutdown don't bother with clearing the BRB or the ILT */
    if (!lm_reset_is_inprogress(pdev))
    {
        /*  Wait a timeout (100msec).*/
        mm_wait(pdev,LM_UNLOAD_TIME);
        /*  Check for BRB port occupancy. If BRB is not empty driver starts the ChipErrorRecovery routine.*/
        val=REG_RD(pdev,BRB1_REG_PORT_NUM_OCC_BLOCKS_0+(4*port));
        /* brb1 not empty */
        if (val)
        {
            DbgMessage(pdev, INFORMi, "lm_reset_function_part BRB1 is not empty %d blooks are occupied\n",val);
            return LM_STATUS_TIMEOUT;
        }


        if (!CHIP_IS_E1x(pdev))
        {
            clear_pf_enable(pdev);
            pdev->vars.b_is_dmae_ready = FALSE; /* Can't access dmae since bus-master is disabled */
        }
        /* link is closed and BRB is empty, can safely delete SRC ILT table: */
        uninit_pxp2_blk(pdev);

    }

    return LM_STATUS_SUCCESS;
}

/**
 * @Description
 *     This function checks whether a certain data entry
 *     (register in NIG) is valid for current phase and chip.
 * @param pdev
 * @param data: A register in the nig with data on when it is
 *            valid
 * @param op: which phase we're in (save/restore/process
 *
 * @return INLINE u8_t TRUE: if entry is valid FALSE o/w
 */
static INLINE u8_t lm_reset_nig_valid_offset(lm_device_t                      * pdev,
                                             const lm_nig_save_restore_data_t * data,
                                             lm_reset_nig_op_t                  op)
{
    if ((op == LM_RESET_NIG_OP_SAVE) && !GET_FLAGS(data->flags, LM_NIG_SAVE))
    {
        return FALSE;
    }

    if ((op == LM_RESET_NIG_OP_RESTORE) && !GET_FLAGS(data->flags, LM_NIG_RESTORE))
    {
        return FALSE;
    }

    if (CHIP_IS_E1(pdev))
    {
        return data->reg_valid.e1;
    }
    else if (CHIP_IS_E1H(pdev))
    {
        return data->reg_valid.e1h;
    }
    else if (CHIP_IS_E2(pdev))
    {
        return data->reg_valid.e2;
    }
    else
    {
        return data->reg_valid.e3;
    }
}

// This function should be called only if we are on MCP lock
// This function should be called only on E1.5 or on E2 (width of PXP2_REG_PGL_PRETEND_FUNC_xx reg is 16bit)
lm_status_t lm_pretend_func( struct _lm_device_t *pdev, u16_t pretend_func_num )
{
    u32_t offset = 0;

    if (CHIP_IS_E1(pdev))
    {
        return LM_STATUS_FAILURE;
    }

    if(CHIP_IS_E1H(pdev) && (pretend_func_num >= E1H_FUNC_MAX))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    switch (ABS_FUNC_ID(pdev))
    {
    case 0:
        offset = PXP2_REG_PGL_PRETEND_FUNC_F0;
        break;

    case 1:
        offset = PXP2_REG_PGL_PRETEND_FUNC_F1;
        break;

    case 2:
        offset = PXP2_REG_PGL_PRETEND_FUNC_F2;
        break;

    case 3:
        offset = PXP2_REG_PGL_PRETEND_FUNC_F3;
        break;

    case 4:
        offset = PXP2_REG_PGL_PRETEND_FUNC_F4;
        break;

    case 5:
        offset = PXP2_REG_PGL_PRETEND_FUNC_F5;
        break;

    case 6:
        offset = PXP2_REG_PGL_PRETEND_FUNC_F6;
        break;

    case 7:
        offset = PXP2_REG_PGL_PRETEND_FUNC_F7;
        break;

    default:
        break;
    }

    if( 0 == offset )
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    if(offset)
    {
        REG_WR(pdev, offset, pretend_func_num );
        REG_WAIT_VERIFY_VAL(pdev, offset, pretend_func_num, 200);
    }

    return LM_STATUS_SUCCESS;
}

/**
 * @Description
 *      This function is called between saving the nig registers
 *      and restoring them. It's purpose is to do any special
 *      handling that requires knowing what the registers that
 *      were read are and before restoring them. It can change
 *      the values of other registers based on knowledge
 *      obtained by values of different registers.
 *
 *      Current processing rules:
 *              NIG_REG_LLHX_FUNC_EN should be set to '1' if
 *              lm_get_func_en is valid. otherwise it
 *              will remain '0'. Only under sd mode.
 *
 * @param pdev
 * @param reg_offsets_port
 * @param reg_port_arr
 * @param reg_port_arr_size
 */
static void lm_reset_nig_process(IN struct _lm_device_t              *pdev,
                                 IN  lm_nig_save_restore_data_t const reg_offsets_port[],
                                 OUT u32_t                            reg_port_arr[],
                                 IN  u32_t                      const reg_port_arr_size,
                                 IN  u8_t                       const func_id)

{
    const lm_nig_save_restore_data_t  * data = NULL;
    u32_t                               idx  = 0;

    /* Current processing only has to do with SD multi function mode. this if should be removed
     * if  the case changes... */
    if (!IS_MF_SD_MODE(pdev))
    {
        return;
    }

    /* We loop on all the registers to make sure we access the correct offset: incase someone moves it. */
    for( idx = 0; idx < reg_port_arr_size ; idx++ )
    {
        data = &reg_offsets_port[idx];
        if (lm_reset_nig_valid_offset(pdev, data, LM_RESET_NIG_OP_RESTORE))
        {
            if ((data->offset == NIG_REG_LLH0_FUNC_EN) || (data->offset == NIG_REG_LLH1_FUNC_EN))
            {
                reg_port_arr[idx] = lm_get_func_en(pdev, func_id);
            }

        }
    }

}

static void lm_reset_nig_values_for_func_save_restore( IN struct _lm_device_t              *pdev,
                                                       IN  lm_reset_nig_op_t          const save_or_restore,
                                                       IN  u8_t                       const pretend_func_id,
                                                       IN  lm_nig_save_restore_data_t const reg_offsets_port[],
                                                       OUT u32_t                            reg_port_arr[],
                                                       IN  u32_t                      const reg_port_arr_size,
                                                       IN  u32_t                      const reg_port_wb_offset_base,
                                                       OUT u64_t                            reg_port_wb_arr[],
                                                       IN  u32_t                      const reg_port_wb_arr_size )
{
    const lm_nig_save_restore_data_t * data        = NULL;
    u32_t                              offset      = 0;
    u32_t                              val_32[2]   = {0} ;
    u32_t                              idx         = 0;
    u8_t                               abs_func_id = ABS_FUNC_ID(pdev);
    u8_t                               b_save      = FALSE;

    switch(save_or_restore)
    {
    case LM_RESET_NIG_OP_SAVE:
        b_save = TRUE;
        break;

    case LM_RESET_NIG_OP_RESTORE:
        b_save = FALSE;
        break;

    case LM_RESET_NIG_OP_PROCESS:
        lm_reset_nig_process(pdev,reg_offsets_port,reg_port_arr,reg_port_arr_size, pretend_func_id);
        return; /* Return on purpose: processing is done in a separate function */

    default:
        DbgBreakIf(TRUE);
        break;
    }

    if( pretend_func_id != abs_func_id  )
    {
        lm_pretend_func( pdev, pretend_func_id );
    }

    for( idx = 0; idx < reg_port_arr_size ; idx++ )
    {
        data = &reg_offsets_port[idx];
        if (lm_reset_nig_valid_offset(pdev, data, save_or_restore))
        {
            if( b_save )
            {
                reg_port_arr[idx] = REG_RD(pdev, data->offset );
            }
            else
            {
                REG_WR(pdev, data->offset, reg_port_arr[idx] );
            }
        }
    }

    for( idx = 0; idx < reg_port_wb_arr_size; idx++)
    {
        offset = reg_port_wb_offset_base + 8*idx;

        if( b_save)
        {
            REG_RD_IND( pdev,  offset,   &val_32[0] );
            REG_RD_IND( pdev,  offset+4, &val_32[1] );
            reg_port_wb_arr[idx] = HILO_U64( val_32[1], val_32[0] );
        }
        else
        {
            val_32[0] = U64_LO(reg_port_wb_arr[idx]);
            val_32[1] = U64_HI(reg_port_wb_arr[idx]);

            REG_WR_IND( pdev,  offset,   val_32[0] );
            REG_WR_IND( pdev,  offset+4, val_32[1] );
        }
    }

    if( pretend_func_id != abs_func_id  )
    {
        lm_pretend_func( pdev, abs_func_id );
    }
}

/*
   1. save known essential NIG values (port swap, WOL nwuf for all funcs)
   2. Pretend to relevant func - for split register as well
   3. Resets the device and the NIG.
   4. Restore known essential NIG values (port swap and WOL nwuf).
*/

void
lm_reset_device_with_nig(struct _lm_device_t *pdev)
{
    u8_t                          idx                                        = 0;
    u8_t                          idx_port                                   = 0;
    u8_t                          abs_func_vector                            = 0;
    u8_t                          abs_func_id                                = ABS_FUNC_ID(pdev); // for debugging only
    const u8_t                    idx_max                                    = MAX_FUNC_NUM;
    const u8_t                    path_id                                    = PATH_ID(pdev);
    const u32_t                   chip_num                                   = CHIP_NUM(pdev);
    const lm_chip_port_mode_t     chip_port_mode                             = CHIP_PORT_MODE(pdev);
    static const u32_t            offset_base_wb[PORT_MAX]                   = { NIG_REG_LLH0_ACPI_BE_MEM_DATA, NIG_REG_LLH1_ACPI_BE_MEM_DATA };
    lm_reset_nig_op_t             lm_reset_nig_op                            = LM_RESET_NIG_OP_SAVE;

    // List of registers that are split-4 (different addresses per port, but same per function)
    static const lm_nig_save_restore_data_t reg_offsets_port0[]              = NIG_REG_PORT_0_OFFSETS_VALUES;
    static const lm_nig_save_restore_data_t reg_offsets_port1[]              = NIG_REG_PORT_1_OFFSETS_VALUES;

    /* List of registers that are "global" for all funcitons in path               offset                         valid
                                                                                                                  e1,e1h,e2,e3 save / restore */
    const lm_nig_save_restore_data_t non_split_offsets[]                     = { { NIG_REG_PORT_SWAP,             {1, 1, 0, 1}, (LM_NIG_SAVE | LM_NIG_RESTORE) },
                                                                                 { NIG_REG_STRAP_OVERRIDE,        {1, 1 ,0, 1}, (LM_NIG_SAVE | LM_NIG_RESTORE) },
                                                                                 { NIG_REG_P0_ACPI_MF_GLOBAL_EN,  {0 ,0, 1, 1}, (LM_NIG_SAVE | LM_NIG_RESTORE) },
                                                                                 { NIG_REG_P1_ACPI_MF_GLOBAL_EN,  {0 ,0, 1, 1}, (LM_NIG_SAVE | LM_NIG_RESTORE) },
                                                                                 { NIG_REG_LLH_E1HOV_MODE,        {0, 1, 0, 0}, (LM_NIG_SAVE | LM_NIG_RESTORE) },
                                                                                 { NIG_REG_LLH_MF_MODE,           {0, 1, 1, 1}, (LM_NIG_SAVE | LM_NIG_RESTORE) },
                                                                                 { NIG_REG_LLH1_MF_MODE,          {0, 0, 0, 1}, (LM_NIG_SAVE | LM_NIG_RESTORE) },
                                                                                 { NIG_REG_MASK_INTERRUPT_PORT0,  {1, 1, 1, 1}, (LM_NIG_SAVE | LM_NIG_RESTORE) },
                                                                                 { NIG_REG_MASK_INTERRUPT_PORT1,  {1, 1, 1, 1}, (LM_NIG_SAVE | LM_NIG_RESTORE) }};

    u32_t                         non_split_vals[ARRSIZE(non_split_offsets)] = {0};
    static u64_t                  reg_nig_port_restore_wb[MAX_FUNC_NUM][NIG_REG_LLH0_ACPI_BE_MEM_DATA_SIZE/2] = {{0}} ; // the nwuf data
    static u32_t                  reg_nig_port_restore[MAX_FUNC_NUM][ARRSIZE(reg_offsets_port0)]              = {{0}};

    UNREFERENCED_PARAMETER_( abs_func_id );

    // Note:
    // Due to kernel stack limitation we use reg_nig_port_restore(_wb) as static variables.
    // At first glance, it doesn't look good BUT avoiding multiple access to the values is assured:
    //    mcp locking mechanism LOAD_COMMON etc

    // Currently we work with max 8 PF, in case of a change - need to verify code is still valid
    ASSERT_STATIC( 8 == MAX_FUNC_NUM );
    ASSERT_STATIC( 2 == PORT_MAX );

    // verify enum values
    ASSERT_STATIC( LM_RESET_NIG_OP_SAVE    < LM_RESET_NIG_OP_PROCESS );
    ASSERT_STATIC( LM_RESET_NIG_OP_PROCESS < LM_RESET_NIG_OP_RESTORE );
    ASSERT_STATIC( 3 == LM_RESET_NIG_OP_MAX );

    // verify that save/restores are same size as offsets range
    ASSERT_STATIC( ARRSIZE(reg_nig_port_restore[0]) == ARRSIZE(reg_offsets_port0) );
    ASSERT_STATIC( ARRSIZE(reg_nig_port_restore[1]) == ARRSIZE(reg_offsets_port1) );
    ASSERT_STATIC( NIG_REG_LLH0_ACPI_BE_MEM_DATA_SIZE == NIG_REG_LLH1_ACPI_BE_MEM_DATA_SIZE );

    abs_func_vector = lm_get_abs_func_vector( chip_num, chip_port_mode, IS_MULTI_VNIC(pdev), path_id );

    // start the "save/restore" operation
    for( lm_reset_nig_op = LM_RESET_NIG_OP_SAVE; lm_reset_nig_op < LM_RESET_NIG_OP_MAX; lm_reset_nig_op++ )
    {
        for( idx = 0; idx < idx_max; idx++ )
        {
            // we skip non-marked functions
            if( 0 == GET_BIT( abs_func_vector, idx ) )
            {
                continue;
            }

            // choose the correct idx_port
            idx_port = PORT_ID_PARAM_FUNC_ABS( chip_num, chip_port_mode, idx );

            DbgBreakIf( idx_port >= PORT_MAX );

            // save for 1st iteariton
            // restore for 2nd iteration
            lm_reset_nig_values_for_func_save_restore( pdev,
                                                       lm_reset_nig_op,
                                                       idx,
                                                       idx_port ? reg_offsets_port1 : reg_offsets_port0,
                                                       reg_nig_port_restore[idx],
                                                       ARRSIZE(reg_nig_port_restore[idx]),
                                                       offset_base_wb[idx_port],
                                                       reg_nig_port_restore_wb[idx],
                                                       ARRSIZE(reg_nig_port_restore_wb[idx]) );
        } // for func iterations

        // This code section should be done once and anyway!
        if ( LM_RESET_NIG_OP_SAVE == lm_reset_nig_op)
        {
            for( idx = 0; idx < ARRSIZE(non_split_vals); idx++ )
            {
                if (lm_reset_nig_valid_offset(pdev, &non_split_offsets[idx], LM_RESET_NIG_OP_SAVE))
                {
                    non_split_vals[idx] = REG_RD( pdev, non_split_offsets[idx].offset );
                }

            }

            //reset chip with NIG!!
            lm_reset_path( pdev, TRUE );

            // save nig swap register and global acpi enable before NIG reset
            for( idx = 0; idx < ARRSIZE(non_split_vals); idx++ )
            {
                if (lm_reset_nig_valid_offset(pdev, &non_split_offsets[idx], LM_RESET_NIG_OP_RESTORE))
                {
                    REG_WR(pdev, non_split_offsets[idx].offset, non_split_vals[idx]);
                }
            }

        } // save iteartion only code

    } // for save/restore loop

} // lm_reset_device_with_nig

void
lm_reset_common_part(struct _lm_device_t *pdev)
{
    /* Reset the HW blocks that are listed in section 4.13.18.*/
    if (lm_pm_reset_is_inprogress(pdev))
    {
        /* In case of shutdown we reset the NIG as well */
        lm_reset_device_with_nig(pdev);
    }
    else
    {
        lm_reset_path( pdev, FALSE );
    }

    /* According to E1/E1H/E2 Recovery flow spec, as long as MCP does not support process kill, "close the gates"
     * should be disabled while no drivers are loaded. The last driver that unloads should disable "close the gates"
     */
    lm_er_disable_close_the_gate(pdev);
}

void lm_chip_reset(struct _lm_device_t *pdev, lm_reason_t reason)
{
    lm_loader_opcode       opcode = 0 ;
    lm_loader_response     resp   = 0 ;
    u32_t                  val    = 0;
    u32_t                  enabled_wols = mm_get_wol_flags(pdev);

    DbgMessage(pdev, INFORMi , "### lm_chip_reset\n");

#ifdef VF_INVOLVED
    if (IS_VFDEV(pdev))
    {
        lm_status_t lm_status = lm_vf_chip_reset(pdev,reason);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(pdev, FATAL, "lm_chip_reset: ERROR (%d) resetting VF!!!\n",lm_status);
            DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
        }
        return;
    }
#endif

    // depends on reason, send relevant message to MCP
    switch( reason )
    {
    case LM_REASON_WOL_SUSPEND:
        opcode = LM_LOADER_OPCODE_UNLOAD_WOL_EN | LM_LOADER_OPCODE_UNLOAD_SUSPEND;
        break ;

    case LM_REASON_NO_WOL_SUSPEND:
        opcode = LM_LOADER_OPCODE_UNLOAD_WOL_DIS | LM_LOADER_OPCODE_UNLOAD_SUSPEND;
        break ;

    case LM_REASON_DRIVER_UNLOAD:
    case LM_REASON_DRIVER_UNLOAD_POWER_DOWN:
    case LM_REASON_DRIVER_SHUTDOWN:
        enabled_wols = LM_WAKE_UP_MODE_NONE; // in S5 default is by nvm cfg 19
        // in case we do support wol_cap, we ignore OS configuration and
        // we decide upon nvm settings (CQ49516 - S5 WOL functionality to always look at NVRAM WOL Setting)
        if( GET_FLAGS( pdev->hw_info.port_feature_config, PORT_FEATURE_WOL_ENABLED ) )
        {
            opcode = LM_LOADER_OPCODE_UNLOAD_WOL_EN ;
            // enabled_wols so the mac address will be written by lm_set_d3_mpkt()
            SET_FLAGS( enabled_wols, LM_WAKE_UP_MODE_MAGIC_PACKET );
        }
        else
        {
            opcode = LM_LOADER_OPCODE_UNLOAD_WOL_DIS ;
        }
        break;

    default:
        break;
    }

    if ( !CHIP_IS_E1(pdev) )
    {
        if (CHIP_IS_E2(pdev) || CHIP_IS_E1H(pdev))
        {
            val = REG_RD( pdev, MISC_REG_E1HMF_MODE);
        }
        else
        {
            ASSERT_STATIC(MISC_REG_E1HMF_MODE_P1 == (MISC_REG_E1HMF_MODE_P0 + 4));
            val = REG_RD( pdev, MISC_REG_E1HMF_MODE_P0 + PORT_ID(pdev)*4);
        }

        // We do expect that register value will be consistent with multi_vnics_mode.
        if (!lm_fl_reset_is_inprogress(pdev))
        {
            DbgBreakIf( pdev->params.multi_vnics_mode ^ val );
        }
    }

    if (lm_fl_reset_is_inprogress(pdev))
    {
        if (TEST_MODE_NO_MCP == GET_FLAGS(pdev->params.test_mode, TEST_MODE_NO_MCP))
        {
            DbgMessage(pdev, FATAL, "lm_chip_reset under FLR: NO MCP\n");
            lm_loader_lock(pdev, opcode);
            lm_loader_unlock(pdev, opcode, NULL);
        }

        DbgMessage(pdev, FATAL, "lm_chip_reset under FLR: return\n");
        return;
    }

    // magic packet should be programmed before unload request send to MCP
    lm_set_d3_mpkt(pdev, enabled_wols) ;

    resp = lm_loader_lock(pdev, opcode ) ;

    if (!IS_ASSIGNED_TO_VM_PFDEV(pdev))
    {
        lm_pcie_state_save_for_d3(pdev);
    }

    // nwuf is programmed before chip reset since if we reset the NIG we resotre all function anyway
    lm_set_d3_nwuf(pdev, enabled_wols) ;

    switch (resp)
    {
    case LM_LOADER_RESPONSE_UNLOAD_FUNCTION:
        lm_reset_function_part(pdev, TRUE /* cleanup*/);
        break;
    case LM_LOADER_RESPONSE_UNLOAD_PORT:
        lm_reset_function_part(pdev, FALSE /* cleanup */ );
        lm_reset_port_part(pdev);
        break;
    case LM_LOADER_RESPONSE_UNLOAD_COMMON:
        lm_reset_function_part(pdev, FALSE /* cleanup */);
        lm_reset_port_part(pdev);
        //Check if there is dbus work
        mm_dbus_stop_if_started(pdev);
        lm_reset_common_part(pdev);
        break;
    default:
        DbgMessage(pdev, WARN, "wrong loader response=0x%x\n", resp);
        DbgBreakIfAll(1);
    }

    pdev->vars.b_is_dmae_ready = FALSE ;

    // unset pmf flag needed for D3 state
    pdev->vars.is_pmf = NOT_PMF;

    resp = lm_loader_unlock(pdev, opcode, NULL ) ;

    if (resp != LM_LOADER_RESPONSE_UNLOAD_DONE )
    {
        DbgMessage(pdev, WARN, "wrong loader response=0x%x\n", resp);
        DbgBreakIfAll(1);
    }
}

/**
 * This function sends the "function-start" ramrod and waits
 * synchroniously for it's completion. Called from the
 * chip-start flow.
 *
 * @param pdev
 *
 * @return lm_status_t SUCCESS / TIMEOUT on waiting for
 *         completion
 */
lm_status_t lm_function_start(struct _lm_device_t *pdev)
{
    struct function_start_data * func_start_data = NULL;
    lm_status_t                  lm_status       = LM_STATUS_SUCCESS;

    DbgMessage(pdev, INFORMeq|INFORMl2sp, "#lm_function_start\n");

    pdev->eq_info.function_state = FUNCTION_START_POSTED;

    if (CHK_NULL(pdev) || CHK_NULL(pdev->slowpath_info.slowpath_data.func_start_data))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    func_start_data = pdev->slowpath_info.slowpath_data.func_start_data;

    if (pdev->params.multi_vnics_mode)
    {
        DbgBreakIf(pdev->params.mf_mode >= MAX_MF_MODE);
        func_start_data->function_mode = pdev->params.mf_mode;
    }
    else
    {
        func_start_data->function_mode = SINGLE_FUNCTION;
    }

    func_start_data->sd_vlan_tag = mm_cpu_to_le16(pdev->params.ovlan);
    /* NIV_TODO: func_start_data->vif_id = mm_cpu_to_le16(??) */

    /* TODO: For Modifying Ether type of Outer VLAN to SVLAN:
        To use, first set these registers to to SVLAN Ethertype (0x88a8)
        PRS_REG_VLAN_TYPE_0 
        PBF_REG_VLAN_TYPE_0
        NIG_REG_LLH_OUTER_VLAN_TYPE_1
        Then modify/create the function with  sd_vlan_eth_type set to SVLAN Ethertype (0x88a8)
    */
    if (IS_MF_SD_MODE(pdev) && IS_SD_BD_MODE(pdev))
    {
        const u8_t  port   = PORT_ID(pdev);
        u32_t offset = ( port ? NIG_REG_LLH1_OUTER_VLAN_ID : NIG_REG_LLH0_OUTER_VLAN_ID );

        func_start_data->sd_vlan_eth_type = mm_cpu_to_le16(0x88a8);
        REG_WR(pdev, PRS_REG_VLAN_TYPE_0, 0x88a8);
        REG_WR(pdev, PBF_REG_VLAN_TYPE_0, 0x88a8);
        REG_WR(pdev, offset , 0x88a8);
    }
    else
        func_start_data->sd_vlan_eth_type = mm_cpu_to_le16(pdev->params.sd_vlan_eth_type);

    func_start_data->path_id = PATH_ID(pdev);

    // Function start is sent when the first miniport clients binds. (Can be also FCOE or iSCSI)
    // The requirement for NW multiple priority is only known to eVBD when the NDIS miniport binds.
    if(MM_DCB_MP_L2_IS_ENABLE(pdev))
    {
        // Multiple priority enabled (only from D3 flow)
        func_start_data->network_cos_mode = STATIC_COS;
    }
    else
    {
        func_start_data->network_cos_mode = OVERRIDE_COS;
    }

    // encapsulated packets offload is disabled by default
    // in case of an error, restore last fw state.
    if (ENCAP_OFFLOAD_DISABLED == pdev->encap_info.current_encap_offload_state)
    {
        func_start_data->tunn_clss_en  = 0;
        func_start_data->tunnel_mode = TUNN_MODE_NONE;
    }
    else
    { 
        func_start_data->tunn_clss_en  = 1;
        func_start_data->tunnel_mode = TUNN_MODE_GRE;
        func_start_data->gre_tunnel_type = NVGRE_TUNNEL;
    }

    if ((IS_SD_UFP_MODE(pdev) || IS_SD_BD_MODE(pdev)) &&
        GET_FLAGS(pdev->params.mf_proto_support_flags, LM_PROTO_SUPPORT_FCOE))
    {
        func_start_data->sd_accept_mf_clss_fail_match_ethtype = 1;
        func_start_data->sd_accept_mf_clss_fail               = 1;
        func_start_data->sd_accept_mf_clss_fail_ethtype       = mm_cpu_to_le16(0x8914);
        func_start_data->no_added_tags                        = 1;
    }

    if (IS_SD_UFP_MODE(pdev) || IS_SD_BD_MODE(pdev))
    {
        /* modify sd_vlan_force_pri_val through registry */
        func_start_data->sd_vlan_force_pri_flg = 1;
        func_start_data->sd_vlan_force_pri_val = func_start_data->sd_vlan_force_pri_val;
    }

    lm_status = lm_sq_post(pdev,
                           0,
                           RAMROD_CMD_ID_COMMON_FUNCTION_START,
                           CMD_PRIORITY_NORMAL,
                           NONE_CONNECTION_TYPE,
                           LM_SLOWPATH_PHYS(pdev, func_start_data).as_u64);

    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = lm_wait_state_change(pdev, &pdev->eq_info.function_state, FUNCTION_START_COMPLETED);

    return lm_status;
} /* lm_function_start */

lm_status_t lm_chip_start(struct _lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS ;
    u8_t        min_bw    = (u8_t)pdev->params.bandwidth_min;
    u8_t        max_bw    = (u8_t)pdev->params.bandwidth_max;

    DbgMessage(pdev, INFORMi, "lm_chip_start\n");

    if (IS_VFDEV(pdev))
    {
        return LM_STATUS_SUCCESS; //lm_vf_chip_start(pdev);
    }

    if ( max_bw != 0 )
    {
        //we assume that if one of the BW registry parameters is not 0, then so is the other one.
        DbgBreakIf(min_bw == 0);
        lm_status = lm_mcp_set_mf_bw(pdev, min_bw, max_bw);
        if (LM_STATUS_SUCCESS != lm_status)
        {
            return lm_status;
        }
    }

    /* Chip is initialized. We are now about to send first ramrod we can open slow-path-queue */
    lm_sq_change_state(pdev, SQ_STATE_NORMAL);

    lm_status = lm_function_start(pdev);
    if ( LM_STATUS_SUCCESS != lm_status )
    {
        return lm_status;
    }

    // start timer scan after leading connection ramrod.
    REG_WR(pdev, TM_REG_EN_LINEAR0_TIMER + 4*PORT_ID(pdev),1);

    lm_status = lm_establish_forward_con(pdev);
    if ( LM_STATUS_SUCCESS != lm_status )
    {
        goto on_err ;
    }

on_err:
    if( LM_STATUS_SUCCESS != lm_status )
    {
        DbgMessage(pdev, FATAL, "lm_chip_start on_err:\n");
        lm_function_stop(pdev);
        REG_WR(pdev, TM_REG_EN_LINEAR0_TIMER + 4*PORT_ID(pdev),0);
    }

    return lm_status;
}

/*
 *Function Name:lm_read_fw_stats_ptr
 *
 *Parameters:
 *
 *Description: read stats_ptr ( port and func) from shmem
 *
 *Assumption: stats scratch pad address from MCP can not change on run time (bc upgrade is not valid)
 *            in case bc upgraded - need to stop statistics and read addresses again
 *Returns:
 *
 */
void lm_setup_read_mgmt_stats_ptr( struct _lm_device_t *pdev, IN const u32_t mailbox_num, OUT u32_t* OPTIONAL fw_port_stats_ptr, OUT u32_t* OPTIONAL fw_func_stats_ptr )
{
    if (GET_FLAGS( pdev->params.test_mode, TEST_MODE_NO_MCP))
    {
        // E2 TODO: move this to lm_main and get info at get_shmem_info...
        #define NO_MCP_WA_FW_FUNC_STATS_PTR       (0xAF900)
        #define NO_MCP_WA_FW_PORT_STATS_PTR       (0xAFA00)
        if ( 0 != fw_func_stats_ptr)
        {
            *fw_func_stats_ptr = NO_MCP_WA_FW_FUNC_STATS_PTR;
        }

        if ( 0 != fw_port_stats_ptr)
        {
            *fw_port_stats_ptr = NO_MCP_WA_FW_PORT_STATS_PTR;
        }
        return;
    }

    if ( NULL != fw_func_stats_ptr )
    {
        // read func_stats address
        LM_SHMEM_READ(pdev,
                      OFFSETOF(shmem_region_t,
                      func_mb[mailbox_num].fw_mb_param),
                      fw_func_stats_ptr);

        // Backward compatibility adjustments for Bootcode v4.0.8 and below
        if( 0xf80a0000 == *fw_func_stats_ptr )
        {
            DbgMessage(pdev, FATAL , "lm_read_fw_stats_ptr: boot code earlier than v4.0.8 fw_mb=%p-->NULL\n", *fw_func_stats_ptr );
            *fw_func_stats_ptr = 0;//NULL
        }
        DbgMessage(pdev, WARN , "lm_read_fw_stats_ptr: pdev->vars.fw_func_stats_ptr=%p\n", *fw_func_stats_ptr );
    }

    if ( NULL != fw_port_stats_ptr )
    {
        // read port_stats address
        LM_SHMEM_READ(pdev,
                      OFFSETOF(shmem_region_t,
                      port_mb[PORT_ID(pdev)].port_stx),
                      fw_port_stats_ptr);

        DbgMessage(pdev, WARN, "lm_read_fw_stats_ptr: pdev->vars.fw_port_stats_ptr=%p\n", *fw_port_stats_ptr );
    }
}

/**lm_init_get_modes_bitmap
 * Get the representation of the device's configuration as
 * inittool init-modes flags.
 *
 * @param pdev the device to use
 *
 * @return u32_t a bitmap with the appropriate INIT_MODE_XXX
 *         flags set.
 */
static u32_t
lm_init_get_modes_bitmap(struct _lm_device_t *pdev)
{
    u32_t   flags    = 0;
    u32_t   chip_rev = 0;

    if (CHIP_REV_IS_ASIC(pdev))
    {
        SET_FLAGS(flags, MODE_ASIC);
    }
    else if (CHIP_REV_IS_FPGA(pdev))
    {
        SET_FLAGS(flags, MODE_FPGA);
    }
    else if (CHIP_REV_IS_EMUL(pdev))
    {
        SET_FLAGS(flags, MODE_EMUL);
    }
    else
    {
        DbgBreakIf(TRUE);
    }

    if (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4)
    {
        SET_FLAGS(flags, MODE_PORT4);
    }
    else if ((CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_2)||(CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_NONE))
    {
        SET_FLAGS(flags, MODE_PORT2);
    }
    else
    {
        DbgBreakIf(TRUE);
    }

    DbgMessage(pdev, INFORMi, "chipid is 0x%x, rev is 0x%x\n", CHIP_NUM(pdev), CHIP_REV(pdev));
    if (CHIP_IS_E2(pdev))
    {
        DbgMessage(pdev, INFORMi, "chip is E2\n");
        SET_FLAGS(flags, MODE_E2);
    }
    else if (CHIP_IS_E3(pdev))
    {
        DbgMessage(pdev, INFORMi, "chip is E3\n");
        SET_FLAGS(flags, MODE_E3);
        if (CHIP_REV_IS_ASIC(pdev))
        {
            DbgMessage(pdev, INFORMi, "chip is ASIC\n");
            chip_rev = CHIP_REV(pdev);
        }
        else
        {
            chip_rev = CHIP_REV_SIM(pdev);
            DbgMessage(pdev, INFORMi, "chip is EMUL/FPGA. modified chip_rev is 0x%x\n", chip_rev);
        }

        if ((chip_rev == CHIP_REV_Ax))
        {
            DbgMessage(pdev, INFORMi, "chip is E3 Ax\n");
            SET_FLAGS(flags, MODE_E3_A0);
        }
        else if (chip_rev == CHIP_REV_Bx)
        {
            DbgMessage(pdev, INFORMi, "chip is E3 Bx\n");
            SET_FLAGS(flags, MODE_E3_B0);

            /* Multiple cos mode is relevant to E3 B0 only... */
            switch (pdev->params.e3_cos_modes)
            {
            case LM_COS_MODE_COS3:
                SET_FLAGS(flags, MODE_COS3);
                break;
            case LM_COS_MODE_COS6:
                SET_FLAGS(flags, MODE_COS6);
                break;
            default:
                DbgBreakMsg("Unknown Cos Mode");
            }
        }
        else
        {
            DbgBreakIf(TRUE);
        }
    }
    else
    {
        DbgMessage(pdev, INFORMi, "chip is not E2/E3\n");
    }


    if (pdev->params.multi_vnics_mode)
    {
        SET_FLAGS(flags, MODE_MF);
        switch(pdev->params.mf_mode)
        {
        case MULTI_FUNCTION_SD:
            SET_FLAGS(flags, MODE_MF_SD);
            break;
        case MULTI_FUNCTION_SI:
            SET_FLAGS(flags, MODE_MF_SI);
            break;
        case MULTI_FUNCTION_AFEX:
            SET_FLAGS(flags, MODE_MF_AFEX);
            break;
        default:
            DbgBreakIf(TRUE);
        }
    }
    else
    {
        SET_FLAGS(flags, MODE_SF);
    }


#if defined(LITTLE_ENDIAN)
    SET_FLAGS(flags, MODE_LITTLE_ENDIAN);
#else
    SET_FLAGS(flags, MODE_BIG_ENDIAN);
#endif

//validation
#define SINGLE_BIT_SET(_bitmap) POWER_OF_2(_bitmap)
#define AT_MOST_SINGLE_SET(_bitmap) (((_bitmap)==0)||(SINGLE_BIT_SET(_bitmap)))

    DbgBreakIf(!SINGLE_BIT_SET(GET_FLAGS(flags, MODE_EMUL|MODE_FPGA|MODE_ASIC)) );
    DbgBreakIf(!SINGLE_BIT_SET(GET_FLAGS(flags, MODE_PORT2|MODE_PORT4)) );
    DbgBreakIf(!SINGLE_BIT_SET(GET_FLAGS(flags, MODE_SF|MODE_MF)) );
    DbgBreakIf(!SINGLE_BIT_SET(GET_FLAGS(flags, MODE_LITTLE_ENDIAN|MODE_BIG_ENDIAN)) );
    DbgBreakIf(!AT_MOST_SINGLE_SET(GET_FLAGS(flags,MODE_E3_A0|MODE_E3_B0)));
    DbgBreakIf(!AT_MOST_SINGLE_SET(GET_FLAGS(flags,MODE_MF_SD|MODE_MF_SI|MODE_MF_AFEX)));
    DbgBreakIf(GET_FLAGS(flags, MODE_E3)&& !(GET_FLAGS(flags,MODE_E3_A0|MODE_E3_B0) ));
    DbgBreakIf(GET_FLAGS(flags, MODE_MF)&& !(GET_FLAGS(flags,MODE_MF_SD|MODE_MF_SI|MODE_MF_AFEX) ));

    return flags;
}

/**lm_ncsi_get_shmem_address
 * @brief get ncsi shmem address
 * @param lm_device
 *
 * @return ncsi_oem_shmem address or 0 if doesn't exists
 */
static u32_t
lm_ncsi_get_shmem_address( struct _lm_device_t *pdev)
{
    u32_t shmem2_size        = 0;
    u32_t ncsi_oem_data_addr = 0;
    u32_t offset             = 0;

    offset = OFFSETOF(shmem2_region_t, size);
    LM_SHMEM2_READ( pdev, offset, &shmem2_size );

    offset = OFFSETOF(shmem2_region_t, ncsi_oem_data_addr);

    if ( shmem2_size > offset )
    {
        LM_SHMEM2_READ(pdev, offset, &ncsi_oem_data_addr);
    }

    return ncsi_oem_data_addr;
}

/**
 *  @brief: Writes product version to shmem (for NCSI)
 *
 *  No endian conversion is needed if data type is u32.  Although, MCP is big endian, basic storage unit is u32.
 *  Unless you access individual byte,  writing a 32-bit word in shmem from host DOES NOT need any endian conversion.
 *  In other word, if host driver write 0x12345678 to a 4-byte location in shmem,  MCP will read it correctly.  eVBD doesn’t need to do mm_cpu_to_be32.
 *
 * @param[in] lm_device
 *
 * @return LM_STATUS_SUCCESS if written, other if not.
 */
static lm_status_t
lm_ncsi_drv_ver_to_scratchpad( struct _lm_device_t *pdev, u32_t ver_32 )
{
    const u32_t           ncsi_oem_data_addr = lm_ncsi_get_shmem_address(pdev);
    static const u32_t    offset             = OFFSETOF(struct glob_ncsi_oem_data ,driver_version);

    if ( 0 == ncsi_oem_data_addr )
    {
        return LM_STATUS_FAILURE;
    }

    REG_WR(pdev, ncsi_oem_data_addr + offset, ver_32);

    return LM_STATUS_SUCCESS;
}

u8_t
lm_ncsi_prev_drv_ver_is_win8_inbox( struct _lm_device_t *pdev)
{
    const u32_t           ncsi_oem_data_addr = lm_ncsi_get_shmem_address(pdev);
    static const u32_t    offset             = OFFSETOF(struct glob_ncsi_oem_data ,driver_version);
    static const u32_t    offset_unused      = OFFSETOF(struct glob_ncsi_oem_data ,unused);
    u8_t                  ver_str[16]        = {0};
    u32_t                 ver_num[4]         = {0};
    u32_t                 ver_num_prev       = 0;
    u32_t                 i                  = 0;
    u32_t                 str_idx            = 0;
    u8_t                  num_dwords         = 0;
    u32_t                 val                = 0;
    u32_t                 mult               = 0;
    u8_t                * p                  = NULL;
    u8_t                * ver_str_end        = NULL;


    /* inbox will only load with bootcode 7.4 and above, in which this field exists
     * for sure. So if it's zero, we're not an inbox driver.
     */
    if ( 0 == ncsi_oem_data_addr )
    {
        return FALSE;
    }

    /* First figure out if we're reading a string or a number, T7.0 and inbox used
     * strings, whereas T7.2 and above use just the product ver as a u32_t. We do
     * this by reading the unused fields
     */
    val = REG_RD(pdev, ncsi_oem_data_addr + offset_unused);
    if (0 == val)
    {
        /* Previous version is not inbox... we're ok... */
        return FALSE;
    }

    /* Now read the version string -> as if we are inbox. This will read the values
     * from the unused fields as well. */
    num_dwords = ARRSIZE(ver_str)/sizeof(u32_t);
    for (i = 0; i < num_dwords; i++)
    {
        str_idx = i*sizeof(u32_t);
        val = REG_RD(pdev, ncsi_oem_data_addr + offset + str_idx);
        val = mm_be32_to_cpu(val);
        *((u32 *)&ver_str[str_idx]) = val;
    }

    /* Now we just need to figure out if the engineering number is != 0,
     * and version is more than 7.0.35.94 (inbox version) that'll mean we're inbox...
     * the string looks like this:  vXX.XX.XX.XX, X are digits.
     */
    p = ver_str;
    if (*p != 'v')
    {
        /* Not inbox... */
        return FALSE;
    }
    p++; // we took away the v, now it looks like this: XX.XX.XX.XX

    ver_str_end = ver_str + ARRSIZE(ver_str) - 1;

    for (i = 0; i < 4; i++)
    {
        mult = 1;
        while ((*p != '.') &&                           /* Between separator     */
               (IS_DIGIT(*p)) &&          /* Is a digit            */
               (p < ver_str_end))                       /* Doesn't overrun array */
        {
            ver_num[i] = ver_num[i]*mult + (*p-'0');
            mult = mult*10;
            p++;
        }
        p++;
    }

    /* Save for debugging */
    ver_num_prev =
        (ver_num[0] << 24) |
        (ver_num[1] << 16) |
        (ver_num[2] << 8)  |
         ver_num[3] ;

    /* Check inbox: 7.0.35.xx make sure xx != 0*/
    if (((ver_num_prev & 0xffffff00) == 0x07002300) && (ver_num[3] != 0) )
    {
        return TRUE;
    }

    return FALSE;
}

/**
 * @brief Writes FCoE capabilites to shmem (for NCSI)
 *  No endian conversion is needed if data type is u32.  Although, MCP is big endian, basic storage unit is u32.
 *  Unless you access individual byte,  writing a 32-bit word in shmem from host DOES NOT need any endian conversion.
 *  In other word, if host driver write 0x12345678 to a 4-byte location in shmem,  MCP will read it correctly.  eVBD doesn’t need to do mm_cpu_to_be32.
 *
 * @param lm_device
 *
 * @return LM_STATUS_SUCCESS if written, FAILED if not
 */
lm_status_t
lm_ncsi_fcoe_cap_to_scratchpad( struct _lm_device_t *pdev)
{
    const u32_t                   ncsi_oem_data_addr = lm_ncsi_get_shmem_address(pdev);
    const u8_t                    path_id            = PATH_ID(pdev);
    const u8_t                    port_id            = PORT_ID(pdev);
    u8_t                          i                  = 0;
    u32_t                         offset             = 0;
    const u32_t                   bc_rev             = LM_GET_BC_REV_MAJOR(pdev);
    const u32_t                   bc_rev_min         = REQ_BC_VER_4_FCOE_FEATURES;
    u32_t*                        buf32              = (u32_t*)(&pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_shmem.fcoe_capabilities);
    static const u8_t             idx_max            = sizeof(pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_shmem.fcoe_capabilities)/sizeof(u32_t);

    ASSERT_STATIC( FIELD_SIZE( struct glob_ncsi_oem_data, fcoe_features[0][0] ) ==
                   sizeof(pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_shmem.fcoe_capabilities) );

    if ( 0 == ncsi_oem_data_addr )
    {
        return LM_STATUS_FAILURE;
    }

    if ( bc_rev < bc_rev_min )
    {
        // not supported before this bootcode.
        return LM_STATUS_INVALID_PARAMETER;
    }

    // populate fcoe_features
    offset = OFFSETOF(struct glob_ncsi_oem_data ,fcoe_features[path_id][port_id]);

    // no endian conversion is needed if data type is u32.  Although, MCP is big endian, basic storage unit is u32.
    // Unless you access individual byte,  writing a 32-bit word in shmem from host DOES NOT need any endian conversion.
    // In other word, if host driver write 0x12345678 to a 4-byte location in shmem,  MCP will read it correctly.  eVBD doesn’t need to do mm_cpu_to_be32.
    for (i = 0; i < idx_max; i++)
    {
        REG_WR(pdev,
               ncsi_oem_data_addr + offset + i*sizeof(u32_t),
               buf32[i]);
    }

    return LM_STATUS_SUCCESS;
}

static void init_misc_common(lm_device_t *pdev)
{
    u32_t reset_reg_1_val = 0xffffffff;
    u32_t reset_reg_2_val = 0xfffc;

    /* Take Chip Blocks out of Reset */
    if (CHIP_IS_E3(pdev))
    {
        // New blocks that need to be taken out of reset
        // Mstat0 - bit 24 of RESET_REG_2
        // Mstat1 - bit 25 of RESET_REG_2
        reset_reg_2_val |= (MISC_REGISTERS_RESET_REG_2_MSTAT1 | MISC_REGISTERS_RESET_REG_2_MSTAT0) ;
    }

    REG_WR(pdev,GRCBASE_MISC+MISC_REGISTERS_RESET_REG_1_SET,reset_reg_1_val);
    // BMAC is not out of reset
    REG_WR(pdev,GRCBASE_MISC+MISC_REGISTERS_RESET_REG_2_SET,reset_reg_2_val);

    ECORE_INIT_COMN(pdev, MISC);

    if (!CHIP_IS_E1(pdev)) /* multi-function not supported in E1 */
    {
        // init multifunction_mode reg. For E3 - this is done in the port-phase, and can differ between ports...
        if (CHIP_IS_E2(pdev) || CHIP_IS_E1H(pdev))
        {
            REG_WR(pdev,MISC_REG_E1HMF_MODE , (pdev->params.multi_vnics_mode ? 1 : 0));
        }
        // TBD: E1H, consider disabling grc timeout enable
    }

    /* Chip is out of reset */

    /* Timers bug workaround. The chip has just been taken out of reset. We need to make sure that all the functions (except this one)
     * are marked as disabled in the PGLC + CFC to avoid timer bug to occur */
    if (!CHIP_IS_E1x(pdev))
    {
        u8_t abs_func_id;

        /* 4-port mode or 2-port mode we need to turn of master-enable for everyone, after that, turn it back on for self.
         * so, we disregard multi-function or not, and always disable for all functions on the given path, this means 0,2,4,6 for
         * path 0 and 1,3,5,7 for path 1 */
        for (abs_func_id = PATH_ID(pdev); abs_func_id  < E2_FUNC_MAX*2; abs_func_id+=2)
        {
            if (abs_func_id == ABS_FUNC_ID(pdev))
            {
                REG_WR(pdev, PGLUE_B_REG_INTERNAL_PFID_ENABLE_MASTER, 1);
                continue;
            }
            lm_pretend_func(pdev, abs_func_id);

            clear_pf_enable(pdev);

            lm_pretend_func(pdev, ABS_FUNC_ID(pdev));
        }

        /* Error recovery: we may have caused a BSOD during last error recovery attempt leaving some locks taken and attentions on,
         * code below sort of "recovers" from a failed recovery.
         */
        if (pdev->params.enable_error_recovery && !CHIP_IS_E1x(pdev))
        {
            lm_hw_clear_all_locks(pdev);
            /* Clear the general attention used to notify second engine: just incase it was left turned on...  */
            REG_WR(pdev, MISC_REG_AEU_GENERAL_ATTN_20 , 0);
        }
    }

}

static void init_aeu_port(lm_device_t *pdev)
{
    u32_t offset = 0;
    u32_t val    = 0;

    if(ERR_IF(!pdev))
    {
        return;
    }

    ECORE_INIT_PORT(pdev, MISC_AEU);

    // init aeu_mask_attn_func_0/1:
    // - SF mode: bits 3-7 are masked. only bits 0-2 are in use
    // - MF mode: bit 3 is masked. bits 0-2 are in use as in SF.
    //            bits 4-7 are used for "per vnic group attention"
    val = (pdev->params.multi_vnics_mode ? 0xF7 : 0x7);
    if(!CHIP_IS_E1(pdev))
    {
        // For DCBX we need to enable group 4 even in SF.
        val |= 0x10;
    }
    REG_WR(pdev, (PORT_ID(pdev) ? MISC_REG_AEU_MASK_ATTN_FUNC_1 : MISC_REG_AEU_MASK_ATTN_FUNC_0), val);

    // If SPIO5 is set to generate interrupts, enable it for this port
    val = REG_RD(pdev, MISC_REG_SPIO_EVENT_EN);
    if (val & MISC_SPIO_SPIO5)
    {
        // fan failure handling
        offset = (PORT_ID(pdev) ? MISC_REG_AEU_ENABLE1_FUNC_1_OUT_0 : MISC_REG_AEU_ENABLE1_FUNC_0_OUT_0) ;
        val=REG_RD(pdev, offset );
        // add SPIO5 to group
        SET_FLAGS(val, AEU_INPUTS_ATTN_BITS_SPIO5 ) ;
        REG_WR(pdev, offset, val ) ;
    }

    if (pdev->params.enable_error_recovery && !CHIP_IS_E1x(pdev))
    {
        /* Under error recovery we use general attention 20 (bit 18) therefore
         * we need to enable it*/
        offset = (PORT_ID(pdev) ? MISC_REG_AEU_ENABLE4_FUNC_1_OUT_0 : MISC_REG_AEU_ENABLE4_FUNC_0_OUT_0) ;
        val = REG_RD(pdev, offset);
        val |= AEU_INPUTS_ATTN_BITS_GRC_MAPPED_GENERAL_ATTN20;
        REG_WR(pdev, offset, val);
    }
}

static void init_pxp_common(lm_device_t *pdev)
{
    if(ERR_IF(!pdev))
    {
        return;
    }

    ECORE_INIT_COMN(pdev, PXP);
    if( CHIP_NUM(pdev) <= CHIP_NUM_5710 )
    {
        // enable hw interrupt from PXP on usdm overflow bit 16 on INT_MASK_0
        REG_WR(pdev,PXP_REG_PXP_INT_MASK_0,0);
    }
}


static void init_pxp2_common(lm_device_t *pdev)
{
    u32_t wait_ms = (CHIP_REV_IS_ASIC(pdev)) ? 200 : 200000;
    u32_t       i = 0;

    if(ERR_IF(!pdev))
    {
        return;
    }

    // static init
    ECORE_INIT_COMN(pdev, PXP2);

    // runtime init
#ifdef __BIG_ENDIAN
    REG_WR(pdev,  PXP2_REG_RQ_QM_ENDIAN_M, 1);
    REG_WR(pdev,  PXP2_REG_RQ_TM_ENDIAN_M, 1);
    REG_WR(pdev,  PXP2_REG_RQ_SRC_ENDIAN_M, 1);
    REG_WR(pdev,  PXP2_REG_RQ_CDU_ENDIAN_M, 1);
    REG_WR(pdev,  PXP2_REG_RQ_DBG_ENDIAN_M, 1);

    REG_WR(pdev,  PXP2_REG_RD_QM_SWAP_MODE, 1);
    REG_WR(pdev,  PXP2_REG_RD_TM_SWAP_MODE, 1);
    REG_WR(pdev,  PXP2_REG_RD_SRC_SWAP_MODE, 1);
    REG_WR(pdev,  PXP2_REG_RD_CDURD_SWAP_MODE, 1);
#endif
    ecore_init_pxp_arb(pdev, pdev->hw_info.max_read_req_size, pdev->hw_info.max_payload_size);

    REG_WR(pdev,PXP2_REG_RQ_CDU_P_SIZE,LOG2(pdev->params.ilt_client_page_size/LM_PAGE_SIZE));
    REG_WR(pdev,PXP2_REG_RQ_TM_P_SIZE,LOG2(pdev->params.ilt_client_page_size/LM_PAGE_SIZE));
    REG_WR(pdev,PXP2_REG_RQ_QM_P_SIZE,LOG2(pdev->params.ilt_client_page_size/LM_PAGE_SIZE));
    REG_WR(pdev,PXP2_REG_RQ_SRC_P_SIZE,LOG2(pdev->params.ilt_client_page_size/LM_PAGE_SIZE));

    // on E 1.5 fpga set number of max pcie tag number to 5
    if (CHIP_REV_IS_FPGA(pdev) && CHIP_IS_E1H(pdev))
    {
        REG_WR(pdev,PXP2_REG_PGL_TAGS_LIMIT,0x1);
    }

    // verify PXP init finished (we want to use the DMAE)
    REG_WAIT_VERIFY_VAL(pdev,PXP2_REG_RQ_CFG_DONE, 1, wait_ms);
    REG_WAIT_VERIFY_VAL(pdev,PXP2_REG_RD_INIT_DONE,1, wait_ms);

    REG_WR(pdev,PXP2_REG_RQ_DISABLE_INPUTS,0);
    REG_WR(pdev,PXP2_REG_RD_DISABLE_INPUTS,0);

    /* Timers bug workaround E2 only. We need to set the entire ILT to have entries with value "0" and valid bit on.
     * This needs to be done by the first PF that is loaded in a path (i.e. common phase)
     */
    if (!CHIP_IS_E1x(pdev))
    {
        /* Step 1: set zeroes to all ilt page entries with valid bit on */
        for (i=0; i < ILT_NUM_PAGE_ENTRIES; i++)
        {
            REG_WR(pdev,PXP2_REG_RQ_ONCHIP_AT_B0+i*8,  0);
            REG_WR(pdev,PXP2_REG_RQ_ONCHIP_AT_B0+i*8+4,ONCHIP_ADDR0_VALID());
        }
        /* Step 2: set the timers first/last ilt entry to point to the entire range to prevent ILT range error */
        if (pdev->params.multi_vnics_mode)
        {
            lm_pretend_func(pdev, (PATH_ID(pdev) + 6));
            PXP2_SET_FIRST_LAST_ILT(pdev, TM,  0, ILT_NUM_PAGE_ENTRIES - 1);
            lm_pretend_func(pdev, ABS_FUNC_ID(pdev));
        }

        /* set E2 HW for 64B cache line alignment */
        /* TODO: align according to runtime cache line size */
        REG_WR(pdev,PXP2_REG_RQ_DRAM_ALIGN,1); /* for 128B cache line value should be 2 */
        REG_WR(pdev,PXP2_REG_RQ_DRAM_ALIGN_RD,1); /* for 128B cache line value should be 2 */
        REG_WR(pdev,PXP2_REG_RQ_DRAM_ALIGN_SEL,1);
    }
}

static void init_pglue_b_common(lm_device_t *pdev)
{
    ECORE_INIT_COMN(pdev, PGLUE_B);
}

static void init_atc_common(lm_device_t *pdev)
{
    u32_t wait_ms = (CHIP_REV_IS_ASIC(pdev)) ? 200 : 200000;
    if (!CHIP_IS_E1x(pdev))
    {
        ECORE_INIT_COMN(pdev, ATC);

        REG_WAIT_VERIFY_VAL(pdev, ATC_REG_ATC_INIT_DONE ,1,wait_ms );
    }
}

static void init_pxp2_func(lm_device_t *pdev)
{
    #define PXP2_NUM_TABLES 4
    lm_address_t * addr_table[PXP2_NUM_TABLES];
    u32_t           num_pages[PXP2_NUM_TABLES];
    u32_t           first_ilt[PXP2_NUM_TABLES];
    u32_t           last_ilt[PXP2_NUM_TABLES];
    u32_t rq_onchip_at_reg;
    u32_t i,j,k,temp;

    ECORE_INIT_FUNC(pdev, PXP2);

    addr_table[0] = pdev->vars.context_cdu_phys_addr_table;
    addr_table[1] = pdev->vars.timers_linear_phys_addr_table;
    addr_table[2] = pdev->vars.qm_queues_phys_addr_table;
    addr_table[3] = pdev->vars.searcher_t1_phys_addr_table;
    num_pages[0] = pdev->vars.context_cdu_num_pages;
    num_pages[1] = pdev->vars.timers_linear_num_pages;
    num_pages[2] = pdev->vars.qm_queues_num_pages;
    num_pages[3] = pdev->vars.searcher_t1_num_pages;

    temp = FUNC_ID(pdev) * ILT_NUM_PAGE_ENTRIES_PER_FUNC;
    rq_onchip_at_reg = CHIP_IS_E1(pdev) ? PXP2_REG_RQ_ONCHIP_AT : PXP2_REG_RQ_ONCHIP_AT_B0;

    for (k=0;k<PXP2_NUM_TABLES;k++)
    {
        // j is the first table entry line for this block temp is the number of the last written entry (each entry is 8 octets long)
        j=temp;
        for (i=0; i<num_pages[k]; temp++, i++)
        {
            REG_WR_IND(pdev,rq_onchip_at_reg+temp*8,ONCHIP_ADDR1(addr_table[k][i].as_u64));
            REG_WR_IND(pdev,rq_onchip_at_reg+temp*8+4,ONCHIP_ADDR2(addr_table[k][i].as_u64));
        }
        first_ilt[k] = j;
        last_ilt[k] = (temp - 1);
    }
    DbgBreakIf(!(temp<((u32_t)ILT_NUM_PAGE_ENTRIES_PER_FUNC*(FUNC_ID(pdev)+1))));

    PXP2_SET_FIRST_LAST_ILT(pdev, CDU, first_ilt[0], last_ilt[0]);
    PXP2_SET_FIRST_LAST_ILT(pdev, TM,  first_ilt[1], last_ilt[1]);
    PXP2_SET_FIRST_LAST_ILT(pdev, QM,  first_ilt[2], last_ilt[2]);
    PXP2_SET_FIRST_LAST_ILT(pdev, SRC, first_ilt[3], last_ilt[3]);

    if (!CHIP_IS_E1x(pdev))
    {
        /* Timers workaround bug: function init part. Need to wait 20msec after initializing ILT,
         * needed to make sure there are no requests in one of the PXP internal queues with "old" ILT addresses */
        mm_wait(pdev, 20000);
    }

}


static void init_dmae_common(lm_device_t *pdev)
{
    if(ERR_IF(!pdev))
    {
        return;
    }

    ECORE_INIT_COMN( pdev, DMAE);

    // write arbitrary buffer to DMAE, hw memory setup phase


    REG_WR_DMAE_LEN_ZERO(pdev,  TSEM_REG_PRAM, 8);
    pdev->vars.b_is_dmae_ready = TRUE ;
}

static void init_qm_common(lm_device_t *pdev)
{
    u8_t i    = 0;
    u8_t func = 0;

    if(ERR_IF(!pdev))
    {
        return;
    }

    ECORE_INIT_COMN( pdev, QM);

    /* nullify PTRTBL */
    for (i=0; i<64; i++)
    {
        REG_WR_IND(pdev,QM_REG_PTRTBL +8*i ,0);
        REG_WR_IND(pdev,QM_REG_PTRTBL +8*i +4 ,0);
    }

    /* nullify extended PTRTBL (E1H only) */
    if (CHIP_IS_E1H(pdev))
    {
        for (i=0; i<64; i++)
        {
            REG_WR_IND(pdev,QM_REG_PTRTBL_EXT_A +8*i ,0);
            REG_WR_IND(pdev,QM_REG_PTRTBL_EXT_A +8*i +4 ,0);
        }
    }

    /* softrest pulse */
    REG_WR(pdev,QM_REG_SOFT_RESET,1);
    REG_WR(pdev,QM_REG_SOFT_RESET,0);

    /* We initialize the QM with max_common_conns, this way, the value is identical for all queues and it saves
     * the driver the need for knowing the mapping of the physical queses to functions.
     * Since we assume  writing the same value to all queue entries, we can do this in the common phase and just initialize
     * all queues the same */
    /* physical queues mapping :
     *  E1 queues:
     *  - q[0-63].
     *  - initialized via QM_REG_BASEADDR and QM_REG_PTRTBL REG
     *  - port0 uses q[0-15], port1 uses q[32-47], q[16-31,48-63] are not used
     *
     *  E1.5 queues:
     *  - _ON TOP OF_ E1 queues !
     *  - q[64-127]
     **/

    /* Initialize QM Queues */
    #define QM_QUEUES_PER_FUNC 16

    /* To eliminate the need of the driver knowing the exact function --> queue mapping, we simply initialize all queues, even for E1
     * we initialize all 64 queues (as if we had 4 functions). For E1H we initialize the extension as well. */
    for (func = 0; func < 4; func++)
    {
        for (i = 0; i < QM_QUEUES_PER_FUNC; i++)
        {
            REG_WR(pdev,QM_REG_BASEADDR +4*(func*QM_QUEUES_PER_FUNC+i) , pdev->hw_info.max_common_conns * 4*i);
        }
    }

    if (CHIP_IS_E1H(pdev))
    {
        for (func = 0; func < 4; func++)
        {
            for (i=0; i<QM_QUEUES_PER_FUNC; i++)
            {
                REG_WR(pdev,QM_REG_BASEADDR_EXT_A +4*(func*QM_QUEUES_PER_FUNC+i) , pdev->hw_info.max_common_conns * 4*i);
            }
        }
    }
}

static void init_qm_func(lm_device_t *pdev)
{
    ECORE_INIT_FUNC( pdev, QM);

    if (!CHIP_IS_E1x(pdev))
    {
        /* Array of PF Enable bits, each pf needs to set its own,
         * is set to 'zero' by MCP on PF FLR */
        REG_WR(pdev, QM_REG_PF_EN, 1);
    }
}

static void init_qm_port(lm_device_t *pdev)
{
    if(ERR_IF(!pdev))
    {
        return;
    }

    ECORE_INIT_PORT(pdev, QM);

    /* The same for all functions on port, therefore we use the max_port_connections */
    REG_WR(pdev, (PORT_ID(pdev) ? QM_REG_CONNNUM_1 : QM_REG_CONNNUM_0), pdev->hw_info.max_common_conns/16 -1);
}

static void init_tm_port(lm_device_t *pdev)
{
    if(ERR_IF(!pdev))
    {
        return;
    }

    ECORE_INIT_PORT(pdev, TM);

    /* when more then 64K connections per _port_ are supported, we need to change the init value for LIN0/1_SCAN_TIME */
    REG_WR(pdev,(PORT_ID(pdev) ? TM_REG_LIN1_SCAN_TIME : TM_REG_LIN0_SCAN_TIME), 20);
    /* The same for all functions on port, therefore we need to use the max_port_connections */
    REG_WR(pdev,(PORT_ID(pdev) ? TM_REG_LIN1_MAX_ACTIVE_CID : TM_REG_LIN0_MAX_ACTIVE_CID), (pdev->hw_info.max_port_conns/32)-1);

}

static void init_dq_common(lm_device_t *pdev)
{
    if(ERR_IF(!pdev))
    {
        return;
    }

    ECORE_INIT_COMN(pdev, DORQ);


    // TBD: consider setting to the OS page size
    REG_WR(pdev,DORQ_REG_DPM_CID_OFST,LM_DQ_CID_BITS);
    if (CHIP_REV_IS_ASIC(pdev))
    {
        // enable hw interrupt from doorbell Q
        REG_WR(pdev,DORQ_REG_DORQ_INT_MASK,0);
    }
}

void init_dq_func(lm_device_t *pdev)
{
    ECORE_INIT_FUNC(pdev, DORQ);
#ifdef VF_INVOLVED
    if (!CHIP_IS_E1x(pdev) && (IS_BASIC_VIRT_MODE_MASTER_PFDEV(pdev) || IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev)))
    {
        REG_WR(pdev, DORQ_REG_MAX_RVFID_SIZE, 6);       // As long as we want to use absolute VF-id number
        REG_WR(pdev, DORQ_REG_VF_NORM_VF_BASE, 0);      //(a VF-id that is unique within the port), like the id
                                                        //that is used by all HW blocks and FW

        REG_WR(pdev, DORQ_REG_VF_NORM_CID_BASE, LM_VF_CID_BASE(pdev));  /*64 for single connection.
                                                                    PF connections in the beginning (L2 connections),
                                                                    then VF connections, and then the rest of PF connections */

        REG_WR(pdev, DORQ_REG_VF_NORM_CID_WND_SIZE, LM_VF_CID_WND_SIZE(pdev)); /* should reflect the maximal number of connections in a VF.
                                                                           0 for single connection  */
#if 0
        ASSERT_STATIC(LM_DQ_CID_BITS >=  3);
        REG_WR(pdev, DORQ_REG_VF_NORM_CID_OFST, LM_DQ_CID_BITS - 3);    /*means the number of bits in a VF doorbell.
                                                                         For 8B doorbells it should be 0, 128B should be 4 */
#endif
        REG_WR(pdev, DORQ_REG_VF_NORM_CID_OFST, LM_VF_DQ_CID_BITS);
        /*In addition, in order to configure the way that the DQ builds the CID,
          the driver should also configure the DQ security checks for the VFs,
          thresholds for VF-doorbells, VF CID range. In the first step it's possible
          to configure all these checks in a way that disables validation checks:
            DQ security checks for VFs - configure single rule (out of 16) with mask = 0x1 and value = 0x0.
            CID range - 0 to 0x1ffff
            VF doorbell thresholds - according to the DQ size. */

        REG_WR(pdev, DORQ_REG_VF_TYPE_MASK_0, 0x71);
        REG_WR(pdev, DORQ_REG_VF_TYPE_VALUE_0, 0);
        REG_WR(pdev, DORQ_REG_VF_TYPE_MIN_MCID_0, 0);
        REG_WR(pdev, DORQ_REG_VF_TYPE_MAX_MCID_0, 0x1ffff);


        REG_WR(pdev, DORQ_REG_VF_NORM_MAX_CID_COUNT, 0x20000);
        REG_WR(pdev, DORQ_REG_VF_USAGE_CT_LIMIT, 64);
    }
#endif
}

static void init_brb1_common(lm_device_t *pdev)
{
    ECORE_INIT_COMN(pdev, BRB1);
}

static void init_pbf_common(lm_device_t *pdev)
{
    ECORE_INIT_COMN(pdev, PBF);

    if (!CHIP_IS_E1x(pdev))
    {
        if (IS_MF_AFEX_MODE(pdev))
        {
            REG_WR(pdev, PBF_REG_HDRS_AFTER_BASIC, 0xE);
            REG_WR(pdev, PBF_REG_MUST_HAVE_HDRS, 0xA);
            REG_WR(pdev, PBF_REG_HDRS_AFTER_TAG_0, 0x6);
            REG_WR(pdev, PBF_REG_TAG_ETHERTYPE_0, 0x8926);
            REG_WR(pdev, PBF_REG_TAG_LEN_0, 0x4);
        }
        else
        {
            /* Ovlan exists only if we are in path multi-function + switch-dependent mode, in switch-independent there is no ovlan headers */
            REG_WR(pdev, PBF_REG_HDRS_AFTER_BASIC, (pdev->params.path_has_ovlan ? 7 : 6)); //Bit-map indicating which L2 hdrs may appear after the basic Ethernet header.
        }
    }
}

static void init_pbf_func(lm_device_t *pdev)
{
    ECORE_INIT_FUNC(pdev, PBF);
    if (!CHIP_IS_E1x(pdev))
    {
        REG_WR(pdev,PBF_REG_DISABLE_PF,0);
    }
}

static void init_brb_port(lm_device_t *pdev)
{
    u32_t low  = 0;
    u32_t high = 0;
    u8_t  port = 0;

    port=PORT_ID(pdev);

    ECORE_INIT_PORT( pdev, BRB1);

    if (CHIP_IS_E1x(pdev))
    {
        // on E1H we do support enable pause
        if (CHIP_REV_IS_EMUL(pdev) || (CHIP_REV_IS_FPGA(pdev) && CHIP_IS_E1(pdev)))
        {
            // special emulation and FPGA values for pause no pause
            high = 513;
            low = 0;
        }
        else
        {
            if (IS_MULTI_VNIC(pdev))
            {
                // A - 24KB + MTU(in K) *4
                // A - 24*4 + 150; (9600*4)/256 - (mtu = jumbo = 9600)
                low = 246;
            }
            else
            {
                if (pdev->params.mtu_max <= 4096)
                {
                    // A - 40KB low = 40*4
                    low = 160;
                }
                else
                {
                    // A - 24KB + MTU(in K) *4
                    low = 96 + (pdev->params.mtu_max*4)/256;
                }
            }
            // B - 14KB High = low+14*4
            high = low + 56;
        }

        REG_WR(pdev,BRB1_REG_PAUSE_LOW_THRESHOLD_0+port*4,low);
        REG_WR(pdev,BRB1_REG_PAUSE_HIGH_THRESHOLD_0+port*4,high);
    }

    if (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4)
    {
        REG_WR(pdev, (PORT_ID(pdev)?  BRB1_REG_MAC_GUARANTIED_1 : BRB1_REG_MAC_GUARANTIED_0), 40);
    }

}


static void init_prs_common(lm_device_t *pdev)
{
    if(ERR_IF(!pdev))
    {
        return;
    }

    ECORE_INIT_COMN( pdev, PRS);

    if (!CHIP_IS_E1(pdev))
    {
        REG_WR(pdev,PRS_REG_E1HOV_MODE, (pdev->params.path_has_ovlan ? 1 : 0));
    }

    if (!CHIP_IS_E1x(pdev))
    {
        if (IS_MF_AFEX_MODE(pdev))
        {
            if (!CHIP_IS_E3B0(pdev)) //on E3 B0 this initialization happens in port phase.
            {
                REG_WR(pdev, PRS_REG_HDRS_AFTER_BASIC, 0xE);
                REG_WR(pdev, PRS_REG_HDRS_AFTER_TAG_0, 0x6);
                REG_WR(pdev, PRS_REG_MUST_HAVE_HDRS, 0xA);
            }

            REG_WR(pdev, PRS_REG_TAG_ETHERTYPE_0, 0x8926);
            REG_WR(pdev, PRS_REG_TAG_LEN_0, 0x4);
        }
        else
        {
            if (!CHIP_IS_E3B0(pdev)) //on E3 B0 this initialization happens in port phase.
            {
                /* Ovlan exists only if we are in multi-function + switch-dependent mode, in switch-independent there is no ovlan headers */
                REG_WR(pdev, PRS_REG_HDRS_AFTER_BASIC, (pdev->params.path_has_ovlan ? 7 : 6)); //Bit-map indicating which L2 hdrs may appear after the basic Ethernet header.
            }
        }
    }

}

static void init_prs_port(lm_device_t *pdev)
{
    ECORE_INIT_PORT(pdev, PRS);

    if (IS_MF_AFEX_MODE(pdev))
    {
        if (CHIP_IS_E3B0(pdev)) //on E3 B0 this initialization happens in port phase.
        {
            REG_WR(pdev, (0 == PORT_ID(pdev))? PRS_REG_HDRS_AFTER_BASIC_PORT_0 :PRS_REG_HDRS_AFTER_BASIC_PORT_1 , 0xE);
            REG_WR(pdev, (0 == PORT_ID(pdev))? PRS_REG_HDRS_AFTER_TAG_0_PORT_0 :PRS_REG_HDRS_AFTER_TAG_0_PORT_1 , 0x6);
            REG_WR(pdev, (0 == PORT_ID(pdev))? PRS_REG_MUST_HAVE_HDRS_PORT_0   :PRS_REG_MUST_HAVE_HDRS_PORT_1   , 0xA);
        }
    }
    else
    {
        if (CHIP_IS_E3B0(pdev)) //on E3 B0 this initialization happens in port phase.
        {
            /* Ovlan exists only if we are in multi-function + switch-dependent mode, in switch-independent there is no ovlan headers */
            REG_WR(pdev, (0 == PORT_ID(pdev))? PRS_REG_HDRS_AFTER_BASIC_PORT_0:PRS_REG_HDRS_AFTER_BASIC_PORT_1, (IS_MF_SD_MODE(pdev) ? 7 : 6)); //Bit-map indicating which L2 hdrs may appear after the basic Ethernet header.
        }
    }
}

static void init_prs_func(lm_device_t *pdev)
{
    if(ERR_IF(!pdev))
    {
        return;
    }

    ECORE_INIT_FUNC( pdev, PRS);
}


static void init_semi_common(lm_device_t *pdev)
{

    if (!CHIP_IS_E1x(pdev))
    {
        /* reset VFC memories - relevant only for E2, has to be done before initialing semi blocks which also
         * initialize VFC blocks.  */
        REG_WR(pdev, TSEM_REG_FAST_MEMORY + VFC_REG_MEMORIES_RST,
               VFC_MEMORIES_RST_REG_CAM_RST |
               VFC_MEMORIES_RST_REG_RAM_RST);
        REG_WR(pdev, XSEM_REG_FAST_MEMORY + VFC_REG_MEMORIES_RST,
               VFC_MEMORIES_RST_REG_CAM_RST |
               VFC_MEMORIES_RST_REG_RAM_RST);
    }


    ECORE_INIT_COMN(pdev, TSEM);
    ECORE_INIT_COMN(pdev, CSEM);
    ECORE_INIT_COMN(pdev, USEM);
    ECORE_INIT_COMN(pdev, XSEM);
    }

static void init_semi_port(lm_device_t *pdev)
{
    ECORE_INIT_PORT(pdev, TSEM);
    ECORE_INIT_PORT(pdev, USEM);
    ECORE_INIT_PORT(pdev, CSEM);
    ECORE_INIT_PORT(pdev, XSEM);

    /*
      Passive buffer REG setup - Dual port memory in semi passive buffer in E1 must be read once before used
      NOTE: This code is needed only for E1 though we will leave it as it is since it makes no harm and doesn't effect performance
    */
    {
        u32_t kuku = 0;
        kuku= REG_RD(pdev,  XSEM_REG_PASSIVE_BUFFER);
        kuku = REG_RD(pdev,  XSEM_REG_PASSIVE_BUFFER + 4);
        kuku = REG_RD(pdev,  XSEM_REG_PASSIVE_BUFFER + 8);

        kuku = REG_RD(pdev,  CSEM_REG_PASSIVE_BUFFER );
        kuku = REG_RD(pdev,  CSEM_REG_PASSIVE_BUFFER + 4);
        kuku = REG_RD(pdev,  CSEM_REG_PASSIVE_BUFFER + 8);

        kuku = REG_RD(pdev,  TSEM_REG_PASSIVE_BUFFER );
        kuku = REG_RD(pdev,  TSEM_REG_PASSIVE_BUFFER + 4);
        kuku = REG_RD(pdev,  TSEM_REG_PASSIVE_BUFFER + 8);

        kuku = REG_RD(pdev,  USEM_REG_PASSIVE_BUFFER );
        kuku = REG_RD(pdev,  USEM_REG_PASSIVE_BUFFER + 4);
        kuku = REG_RD(pdev,  USEM_REG_PASSIVE_BUFFER + 8);
    }
}

static void init_semi_func(lm_device_t *pdev)
{
    ECORE_INIT_FUNC(pdev, TSEM);
    ECORE_INIT_FUNC(pdev, USEM);
    ECORE_INIT_FUNC(pdev, CSEM);
    ECORE_INIT_FUNC(pdev, XSEM);

    if (!CHIP_IS_E1x(pdev))
    {
        REG_WR(pdev,TSEM_REG_VFPF_ERR_NUM, (FUNC_ID(pdev) + E2_MAX_NUM_OF_VFS));
        REG_WR(pdev,USEM_REG_VFPF_ERR_NUM, (FUNC_ID(pdev) + E2_MAX_NUM_OF_VFS));
        REG_WR(pdev,CSEM_REG_VFPF_ERR_NUM, (FUNC_ID(pdev) + E2_MAX_NUM_OF_VFS));
        REG_WR(pdev,XSEM_REG_VFPF_ERR_NUM, (FUNC_ID(pdev) + E2_MAX_NUM_OF_VFS));
    }

}


static void init_pbf_port(lm_device_t *pdev)
{
    if(ERR_IF(!pdev))
    {
        return;
    }

    ECORE_INIT_PORT(pdev, PBF);

    // configure PBF to work without PAUSE mtu 9600 - bug in E1/E1H
    if (CHIP_IS_E1x(pdev))
    {
        REG_WR(pdev,(PORT_ID(pdev) ? PBF_REG_P1_PAUSE_ENABLE : PBF_REG_P0_PAUSE_ENABLE),0);
        //  update threshold
        REG_WR(pdev,(PORT_ID(pdev) ? PBF_REG_P1_ARB_THRSH : PBF_REG_P0_ARB_THRSH),(MAXIMUM_PACKET_SIZE/16));
        //  update init credit
        REG_WR(pdev,(PORT_ID(pdev) ? PBF_REG_P1_INIT_CRD : PBF_REG_P0_INIT_CRD),(MAXIMUM_PACKET_SIZE/16) + 553 -22);
        // probe changes
        REG_WR(pdev,(PORT_ID(pdev) ? PBF_REG_INIT_P1 : PBF_REG_INIT_P0),1);
        mm_wait(pdev,5);
        REG_WR(pdev,(PORT_ID(pdev) ? PBF_REG_INIT_P1 : PBF_REG_INIT_P0),0);
    }

}

static void init_src_common(lm_device_t *pdev)
{
    if(ERR_IF(!pdev))
    {
        return;
    }

    REG_WR(pdev,SRC_REG_SOFT_RST,1);

    ECORE_INIT_COMN(pdev, SRC);

    REG_WR(pdev,SRC_REG_KEYSEARCH_0,*(u32_t *)(&pdev->context_info->searcher_hash.searcher_key[0]));
    REG_WR(pdev,SRC_REG_KEYSEARCH_1,*(u32_t *)(&pdev->context_info->searcher_hash.searcher_key[4]));
    REG_WR(pdev,SRC_REG_KEYSEARCH_2,*(u32_t *)(&pdev->context_info->searcher_hash.searcher_key[8]));
    REG_WR(pdev,SRC_REG_KEYSEARCH_3,*(u32_t *)(&pdev->context_info->searcher_hash.searcher_key[12]));
    REG_WR(pdev,SRC_REG_KEYSEARCH_4,*(u32_t *)(&pdev->context_info->searcher_hash.searcher_key[16]));
    REG_WR(pdev,SRC_REG_KEYSEARCH_5,*(u32_t *)(&pdev->context_info->searcher_hash.searcher_key[20]));
    REG_WR(pdev,SRC_REG_KEYSEARCH_6,*(u32_t *)(&pdev->context_info->searcher_hash.searcher_key[24]));
    REG_WR(pdev,SRC_REG_KEYSEARCH_7,*(u32_t *)(&pdev->context_info->searcher_hash.searcher_key[28]));
    REG_WR(pdev,SRC_REG_KEYSEARCH_8,*(u32_t *)(&pdev->context_info->searcher_hash.searcher_key[32]));
    REG_WR(pdev,SRC_REG_KEYSEARCH_9,*(u32_t *)(&pdev->context_info->searcher_hash.searcher_key[36]));

    REG_WR(pdev,SRC_REG_SOFT_RST,0);
}

static void init_src_func(lm_device_t *pdev)
{
    lm_address_t src_addr;

    ECORE_INIT_FUNC(pdev, SRC);
    // tell the searcher where the T2 table is
    REG_WR(pdev,  (PORT_ID(pdev) ? SRC_REG_COUNTFREE1 : SRC_REG_COUNTFREE0) ,pdev->vars.searcher_t2_num_pages * pdev->params.ilt_client_page_size/64);
    REG_WR_IND(pdev,  (PORT_ID(pdev) ? SRC_REG_FIRSTFREE1 : SRC_REG_FIRSTFREE0),pdev->vars.searcher_t2_phys_addr_table[0].as_u32.low);
    REG_WR_IND(pdev,  (PORT_ID(pdev) ? SRC_REG_FIRSTFREE1 : SRC_REG_FIRSTFREE0)+4,pdev->vars.searcher_t2_phys_addr_table[0].as_u32.high);
    src_addr.as_u64 = pdev->vars.searcher_t2_phys_addr_table[pdev->vars.searcher_t2_num_pages-1].as_u64
        + pdev->params.ilt_client_page_size - 64 ;
    REG_WR_IND(pdev,  (PORT_ID(pdev) ? SRC_REG_LASTFREE1 : SRC_REG_LASTFREE0),src_addr.as_u32.low);
    REG_WR_IND(pdev,  (PORT_ID(pdev) ? SRC_REG_LASTFREE1 : SRC_REG_LASTFREE0)+4,src_addr.as_u32.high);
    REG_WR(pdev,  (PORT_ID(pdev) ? SRC_REG_NUMBER_HASH_BITS1 : SRC_REG_NUMBER_HASH_BITS0),pdev->context_info->searcher_hash.num_hash_bits);
}

static void init_cdu_common(lm_device_t *pdev)
{
    u32_t val = 0;

    if(ERR_IF(!pdev))
    {
        return;
    }
    // static initialization only for Common part
    ECORE_INIT_COMN(pdev, CDU);

    val = (pdev->params.num_context_in_page<<24) +
        (pdev->params.context_waste_size<<12)  +
        pdev->params.context_line_size;
    REG_WR(pdev,CDU_REG_CDU_GLOBAL_PARAMS,val);
    /* configure cdu to work with cdu-validation. TODO: Move init to hw init tool */
    REG_WR(pdev,CDU_REG_CDU_CONTROL0,0X1UL);
    REG_WR(pdev,CDU_REG_CDU_CHK_MASK0,0X0003d000UL); /* enable region 2 */
    REG_WR(pdev,CDU_REG_CDU_CHK_MASK1,0X0000003dUL); /* enable region 4 */

}


static void init_cfc_common(lm_device_t *pdev)
{
    u32_t cfc_init_reg = 0;
    if(ERR_IF(!pdev))
    {
        return;
    }

    ECORE_INIT_COMN(pdev, CFC);
    /* init cfc with user configurable number of connections in cfc */

    cfc_init_reg |= (1 << CFC_INIT_REG_REG_AC_INIT_SIZE);
    cfc_init_reg |= (pdev->params.cfc_last_lcid << CFC_INIT_REG_REG_LL_INIT_LAST_LCID_SIZE);
    cfc_init_reg |= (1 << CFC_INIT_REG_REG_LL_INIT_SIZE);
    cfc_init_reg |= (1 << CFC_INIT_REG_REG_CAM_INIT_SIZE);
    REG_WR(pdev,  CFC_REG_INIT_REG, cfc_init_reg);

    // enable context validation interrupt from CFC
    #ifdef VF_INVOLVED
    if (!CHIP_IS_E1x(pdev) && (IS_BASIC_VIRT_MODE_MASTER_PFDEV(pdev) || IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev)))
    {
        /* with vfs - due to flr.. we don't want cfc to give attention on error from pxp,
         * in regular environemt - we want this error bit5:
         * The CDU responded with an error bit #0 (PCIe error) DORQ client has separate control
         * for this exec error
         */
        REG_WR(pdev, CFC_REG_DISABLE_ON_ERROR, 0xffdf);
        REG_WR(pdev, CFC_REG_CFC_INT_MASK, 0x2);
        REG_WR(pdev, CFC_REG_DORQ_MASK_PCIERR, 0x1);
        REG_WR(pdev, CFC_REG_DORQ_MASK_VALERR, 0x1);
    }
    else
    {
        REG_WR(pdev,CFC_REG_CFC_INT_MASK ,0);
        REG_WR(pdev, CFC_REG_DORQ_MASK_PCIERR, 0);
        REG_WR(pdev, CFC_REG_DORQ_MASK_VALERR, 0);
    }
    #else
    REG_WR(pdev,CFC_REG_CFC_INT_MASK ,0);
    #endif



    // configure CFC/CDU. TODO: Move CFC init to hw init tool */
    REG_WR(pdev,CFC_REG_DEBUG0 ,0x20020000);
    REG_WR(pdev,CFC_REG_INTERFACES ,0x280000);
    REG_WR(pdev,CFC_REG_INTERFACES ,0);

}



static void init_hc_port(lm_device_t *pdev)
{
    if(ERR_IF(!pdev))
    {
        return;
    }

    if(CHIP_IS_E1(pdev))
    {
        REG_WR(pdev,  (PORT_ID(pdev) ? HC_REG_LEADING_EDGE_1 : HC_REG_LEADING_EDGE_0), 0);
        REG_WR(pdev,  (PORT_ID(pdev) ? HC_REG_TRAILING_EDGE_1 : HC_REG_TRAILING_EDGE_0), 0);
    }

    ECORE_INIT_PORT(pdev, HC);
}

static void init_hc_func(lm_device_t *pdev)
{
    const u8_t func = FUNC_ID(pdev);

    if(ERR_IF(!pdev))
    {
        return;
    }

    if(CHIP_IS_E1H(pdev))
    {
        REG_WR(pdev, MISC_REG_AEU_GENERAL_ATTN_12 + 4*func,0x0);
        REG_WR(pdev,  (PORT_ID(pdev) ? HC_REG_LEADING_EDGE_1 : HC_REG_LEADING_EDGE_0), 0);
        REG_WR(pdev,  (PORT_ID(pdev) ? HC_REG_TRAILING_EDGE_1 : HC_REG_TRAILING_EDGE_0), 0);
    }

    ECORE_INIT_FUNC(pdev, HC);
}

static void init_igu_common( lm_device_t *pdev )
{

    ECORE_INIT_COMN(pdev, IGU);

    /* Enable IGU debugging feature */
#if 0 /* uncomment if you want to enable igu debug command for function 0, more changes required for different functions - will also need to define u32_t val=0*/
    REG_WR(pdev, IGU_REG_COMMAND_DEBUG, 1); // 1 - FIFO collects eight last incoming command
    /* Configure fid = PF (bit 6) and function 0 (PF#0)*/
    val = ((0x40 & IGU_ERROR_HANDLING_FILTER_REG_ERROR_HANDLING_FILTER_FID) |
        IGU_ERROR_HANDLING_FILTER_REG_ERROR_HANDLING_FILTER_EN);

    REG_WR(pdev, IGU_REG_ERROR_HANDLING_FILTER, val);

#endif
}

static void init_igu_func(lm_device_t *pdev)
{
    u32_t prod_idx,i,val;
    u8_t num_segs;
    u8_t base_prod;
    u8_t sb_id;
    u8_t dsb_idx;
    u8_t igu_func_id;

    if(ERR_IF(!pdev))
    {
        return;
    }

    if (INTR_BLK_TYPE(pdev) == INTR_BLK_IGU)
    {
        /* E2 TODO: make sure that misc is updated accordingly and that three lines below are not required */
        REG_WR(pdev, MISC_REG_AEU_GENERAL_ATTN_12 + 4*FUNC_ID(pdev),0x0);
        REG_WR(pdev,  IGU_REG_LEADING_EDGE_LATCH, 0);
        REG_WR(pdev,  IGU_REG_TRAILING_EDGE_LATCH, 0);

        ECORE_INIT_FUNC(pdev, IGU);

        /* Let's enable the function in the IGU - this is to enable consumer updates */
        val=REG_RD(pdev, IGU_REG_PF_CONFIGURATION);
        SET_FLAGS(val, IGU_PF_CONF_FUNC_EN);
        REG_WR(pdev,  IGU_REG_PF_CONFIGURATION, val);

        /* Producer memory:
         * E2 mode: address 0-135 match to the mapping memory;
         * 136 - PF0 default prod; 137 PF1 default prod; 138 - PF2 default prod;  139 PF3 default prod;
         * 140 - PF0 - ATTN prod; 141 - PF1 - ATTN prod; 142 - PF2 - ATTN prod; 143 - PF3 - ATTN prod;
         * 144-147 reserved.
         * E1.5 mode - In backward compatible mode; for non default SB; each even line in the memory
         * holds the U producer and each odd line hold the C producer. The first 128 producer are for
         * NDSB (PF0 - 0-31; PF1 - 32-63 and so on).
         * The last 20 producers are for the DSB for each PF. each PF has five segments
         * (the order inside each segment is PF0; PF1; PF2; PF3) - 128-131 U prods; 132-135 C prods; 136-139 X prods; 140-143 T prods; 144-147 ATTN prods;
         */
        /* non-default-status-blocks*/
        num_segs = IGU_NORM_NDSB_NUM_SEGS;
        for (sb_id = 0; sb_id < LM_IGU_SB_CNT(pdev); sb_id++)
        {
            prod_idx = (IGU_BASE_NDSB(pdev) + sb_id)*num_segs; /* bc-assumption consecutive pfs, norm-no assumption */
            for (i = 0; i < num_segs;i++)
            {
                REG_WR(pdev, IGU_REG_PROD_CONS_MEMORY + (prod_idx + i)*4, 0);
            }
            /* Give Consumer updates with value '0' */
            lm_int_ack_sb_enable(pdev, sb_id);

            /* Send cleanup command */
            lm_int_igu_sb_cleanup(pdev, IGU_BASE_NDSB(pdev) + sb_id);
        }

        /* default-status-blocks */
        if (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4)
        {
            dsb_idx = FUNC_ID(pdev);
        }
        else
        {
            dsb_idx = VNIC_ID(pdev);
        }
        num_segs = (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_BC)? IGU_BC_DSB_NUM_SEGS : IGU_NORM_DSB_NUM_SEGS;
        base_prod = (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_BC) ? (IGU_BC_BASE_DSB_PROD + dsb_idx) : (IGU_NORM_BASE_DSB_PROD + dsb_idx);
        for (i = 0; i < num_segs; i++)
        {
            REG_WR(pdev, IGU_REG_PROD_CONS_MEMORY + (base_prod + i*MAX_VNIC_NUM)*4, 0);
        }

        lm_int_ack_def_sb_enable(pdev);

        /* Send cleanup command */
        lm_int_igu_sb_cleanup(pdev, IGU_DSB_ID(pdev));

        /* Reset statistics msix / attn */
        igu_func_id = (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4)? FUNC_ID(pdev) : VNIC_ID(pdev);
        igu_func_id |= (1 << IGU_FID_ENCODE_IS_PF_SHIFT);

        REG_WR(pdev, IGU_REG_STATISTIC_NUM_MESSAGE_SENT + igu_func_id*4, 0);
        REG_WR(pdev, IGU_REG_STATISTIC_NUM_MESSAGE_SENT + (igu_func_id + MAX_VNIC_NUM)*4, 0);

        /* E2 TODO: these should become driver const once rf-tool supports split-68 const. */
        REG_WR(pdev, IGU_REG_SB_INT_BEFORE_MASK_LSB, 0);
        REG_WR(pdev, IGU_REG_SB_INT_BEFORE_MASK_MSB, 0);
        REG_WR(pdev, IGU_REG_SB_MASK_LSB, 0);
        REG_WR(pdev, IGU_REG_SB_MASK_MSB, 0);
        REG_WR(pdev, IGU_REG_PBA_STATUS_LSB, 0);
        REG_WR(pdev, IGU_REG_PBA_STATUS_MSB, 0);

    }
}


static void init_nig_common(lm_device_t *pdev)
{
    ECORE_INIT_COMN( pdev, NIG);

    if (CHIP_IS_E2(pdev) || CHIP_IS_E1H(pdev)) /* E3 supports this per port - and is therefore done in the port phase */
    {
        REG_WR(pdev,NIG_REG_LLH_MF_MODE,    IS_MULTI_VNIC(pdev) ? 1 : 0);
    }

    /* E1HOV mode was removed in E2 and is replaced with hdrs-after-basic... */
    if (CHIP_IS_E1H(pdev))
    {
        REG_WR(pdev,NIG_REG_LLH_E1HOV_MODE, IS_MF_SD_MODE(pdev) ? 1 : 0);
    }

}

static void init_nig_port(lm_device_t *pdev)
{
    ECORE_INIT_PORT( pdev, NIG);

    if (!CHIP_IS_E3(pdev))
    {
        REG_WR(pdev,(PORT_ID(pdev) ? NIG_REG_XGXS_SERDES1_MODE_SEL : NIG_REG_XGXS_SERDES0_MODE_SEL),1);
    }

    if (!CHIP_IS_E1x(pdev))
    {
        /* MF-mode can be set separately per port in E3, and therefore is done here... for E2 and before it is done in the common phase */
        if (CHIP_IS_E3(pdev))
        {
            REG_WR(pdev,(PORT_ID(pdev)?  NIG_REG_LLH1_MF_MODE: NIG_REG_LLH_MF_MODE), IS_MULTI_VNIC(pdev) ? 1 : 0);
        }
    }

    if (!CHIP_IS_E1(pdev))
    {
        /*   LLH0/1_BRB1_DRV_MASK_MF        MF      SF
              mask_no_outer_vlan            0       1
              mask_outer_vlan               1       0*/
        u32_t mask_mf_reg = PORT_ID(pdev) ? NIG_REG_LLH1_BRB1_DRV_MASK_MF : NIG_REG_LLH0_BRB1_DRV_MASK_MF;
        u32_t val = IS_MF_SD_MODE(pdev) ? NIG_LLH0_BRB1_DRV_MASK_MF_REG_LLH0_BRB1_DRV_MASK_OUTER_VLAN : NIG_LLH0_BRB1_DRV_MASK_MF_REG_LLH0_BRB1_DRV_MASK_NO_OUTER_VLAN;

        ASSERT_STATIC(NIG_LLH0_BRB1_DRV_MASK_MF_REG_LLH0_BRB1_DRV_MASK_OUTER_VLAN    == NIG_LLH1_BRB1_DRV_MASK_MF_REG_LLH1_BRB1_DRV_MASK_OUTER_VLAN);
        ASSERT_STATIC(NIG_LLH0_BRB1_DRV_MASK_MF_REG_LLH0_BRB1_DRV_MASK_NO_OUTER_VLAN == NIG_LLH1_BRB1_DRV_MASK_MF_REG_LLH1_BRB1_DRV_MASK_NO_OUTER_VLAN);
        REG_WR(pdev, mask_mf_reg, val);

        if (!CHIP_IS_E1x(pdev))
        {
            if (IS_MF_SD_MODE(pdev))
            {
                REG_WR(pdev, (PORT_ID(pdev) ? NIG_REG_LLH1_CLS_TYPE : NIG_REG_LLH0_CLS_TYPE), 1);
            }
            else
            {
                REG_WR(pdev, (PORT_ID(pdev) ? NIG_REG_LLH1_CLS_TYPE : NIG_REG_LLH0_CLS_TYPE), 2);
            }
        }
    }
}

void init_nig_func(lm_device_t *pdev)
{
    const u8_t  mf     = pdev->params.multi_vnics_mode;
    const u8_t  port   = PORT_ID(pdev);
    u32_t       offset = 0;

    ECORE_INIT_FUNC(pdev, NIG);

    if (mf)
    {
        offset = ( port ? NIG_REG_LLH1_FUNC_EN : NIG_REG_LLH0_FUNC_EN );

        if (IS_SD_UFP_MODE(pdev) && GET_FLAGS(pdev->params.mf_proto_support_flags, LM_PROTO_SUPPORT_FCOE))
        {
            REG_WR(pdev, offset , 0);
        }
        else
        {
            REG_WR(pdev, offset , 1);
        }

        offset = ( port ? NIG_REG_LLH1_FUNC_VLAN_ID : NIG_REG_LLH0_FUNC_VLAN_ID );
        REG_WR(pdev, offset , pdev->params.ovlan);
    }
}

static void init_pxpcs_common(lm_device_t *pdev)
{
    if(ERR_IF(!pdev))
    {
        return;
    }

    /* Reset pciex errors */
    REG_WR(pdev,0x2814,0xffffffff);
    REG_WR(pdev,0x3820,0xffffffff);

    if (!CHIP_IS_E1x(pdev))
    {
        REG_WR(pdev,PCICFG_OFFSET + PXPCS_TL_CONTROL_5,  (PXPCS_TL_CONTROL_5_ERR_UNSPPORT1 | PXPCS_TL_CONTROL_5_ERR_UNSPPORT));
        REG_WR(pdev,PCICFG_OFFSET + PXPCS_TL_FUNC345_STAT,
               (PXPCS_TL_FUNC345_STAT_ERR_UNSPPORT4 | PXPCS_TL_FUNC345_STAT_ERR_UNSPPORT3 | PXPCS_TL_FUNC345_STAT_ERR_UNSPPORT2));
        REG_WR(pdev,PCICFG_OFFSET + PXPCS_TL_FUNC678_STAT,
               (PXPCS_TL_FUNC678_STAT_ERR_UNSPPORT7 | PXPCS_TL_FUNC678_STAT_ERR_UNSPPORT6 | PXPCS_TL_FUNC678_STAT_ERR_UNSPPORT5));
    }
}

static void init_pxpcs_func(lm_device_t *pdev)
{
    if(ERR_IF(!pdev))
    {
        return;
    }
    /* Reset pciex errors */
    REG_WR(pdev,0x2114,0xffffffff);
    REG_WR(pdev,0x2120,0xffffffff);
}

static void init_pglue_b_port(lm_device_t *pdev)
{
    ECORE_INIT_PORT(pdev, PGLUE_B);
    /* Timers bug workaround: disables the pf_master bit in pglue at common phase, we need to enable it here before
     * any dmae access are attempted. Therefore we manually added the enable-master to the port phase (it also happens
     * in the function phase) */
    if (!CHIP_IS_E1x(pdev))
    {
        REG_WR(pdev, PGLUE_B_REG_INTERNAL_PFID_ENABLE_MASTER, 1);
    }
}

static void init_pglue_b_func(lm_device_t *pdev)
{
    ECORE_INIT_FUNC(pdev, PGLUE_B);

    if (!CHIP_IS_E1x(pdev))
    {
        /* 1. Timers bug workaround. There may be an error here. do this only if func_id=6, otherwise
         * an error isn't expected
         * 2. May be an error due to FLR.
         */
        REG_WR(pdev,PGLUE_B_REG_WAS_ERROR_PF_7_0_CLR, FUNC_ID(pdev));
    }

}

static void init_cfc_func(lm_device_t *pdev)
{
    ECORE_INIT_FUNC(pdev, CFC);
    if (!CHIP_IS_E1x(pdev))
    {
        REG_WR(pdev, CFC_REG_WEAK_ENABLE_PF,1);
        //REG_WR(pdev, CFC_REG_STRONG_ENABLE_PF,1);
    }
}

static void init_aeu_common(lm_device_t * pdev)
{
    ECORE_INIT_COMN(pdev, MISC_AEU);

    /* Error Recovery : attach some attentions to close-the-g8 NIG + PXP2 */
    lm_er_config_close_the_g8(pdev);
}

#define init_tcm_common( pdev)     ECORE_INIT_COMN(pdev, TCM);
#define init_ccm_common( pdev)     ECORE_INIT_COMN(pdev, CCM);
#define init_ucm_common( pdev)     ECORE_INIT_COMN(pdev, UCM);
#define init_xcm_common( pdev)     ECORE_INIT_COMN(pdev, XCM)
#define init_tsdm_common(pdev)     ECORE_INIT_COMN(pdev, TSDM)
#define init_csdm_common(pdev)     ECORE_INIT_COMN(pdev, CSDM)
#define init_usdm_common(pdev)     ECORE_INIT_COMN(pdev, USDM)
#define init_xsdm_common(pdev)     ECORE_INIT_COMN(pdev, XSDM)
#define init_tm_common(  pdev)     ECORE_INIT_COMN(pdev, TM)
#define init_upb_common( pdev)     ECORE_INIT_COMN(pdev, UPB)
#define init_xpb_common( pdev)     ECORE_INIT_COMN(pdev, XPB)
#define init_hc_common(  pdev)     ECORE_INIT_COMN(pdev, HC)
#define init_dbg_common(pdev)      ECORE_INIT_COMN(pdev, DBG)

#define init_pxp_port(pdev)        ECORE_INIT_PORT(pdev, PXP)
#define init_pxp2_port(pdev)       ECORE_INIT_PORT(pdev, PXP2)
#define init_atc_port(pdev)        ECORE_INIT_PORT(pdev, ATC)
#define init_tcm_port( pdev)       ECORE_INIT_PORT(pdev, TCM)
#define init_ucm_port( pdev)       ECORE_INIT_PORT(pdev, UCM)
#define init_ccm_port( pdev)       ECORE_INIT_PORT(pdev, CCM)
#define init_misc_port( pdev)      ECORE_INIT_PORT(pdev, MISC)
#define init_xcm_port( pdev)       ECORE_INIT_PORT(pdev, XCM)
#define init_dq_port(pdev)         ECORE_INIT_PORT(pdev, DORQ)
#define init_tsdm_port( pdev)      ECORE_INIT_PORT(pdev, TSDM)
#define init_csdm_port( pdev)      ECORE_INIT_PORT(pdev, CSDM)
#define init_usdm_port( pdev)      ECORE_INIT_PORT(pdev, USDM)
#define init_xsdm_port( pdev)      ECORE_INIT_PORT(pdev, XSDM)
#define init_upb_port(pdev)        ECORE_INIT_PORT(pdev, UPB)
#define init_xpb_port(pdev)        ECORE_INIT_PORT(pdev, XPB)
#define init_src_port(pdev)        ECORE_INIT_PORT(pdev, SRC)
#define init_cdu_port(pdev)        ECORE_INIT_PORT(pdev, CDU)
#define init_cfc_port(pdev)        ECORE_INIT_PORT(pdev, CFC)

#define init_igu_port( pdev)       ECORE_INIT_PORT(pdev, IGU)
#define init_dbg_port(pdev)        ECORE_INIT_PORT(pdev, DBG)
#define init_dmae_port(pdev)       ECORE_INIT_PORT(pdev, DMAE)

#define init_misc_func(pdev)       ECORE_INIT_FUNC(pdev, MISC)
#define init_pxp_func(pdev)        ECORE_INIT_FUNC(pdev, PXP)
#define init_atc_func(pdev)        ECORE_INIT_FUNC(pdev, ATC)
#define init_tcm_func(pdev)        ECORE_INIT_FUNC(pdev, TCM)
#define init_ucm_func(pdev)        ECORE_INIT_FUNC(pdev, UCM)
#define init_ccm_func(pdev)        ECORE_INIT_FUNC(pdev, CCM)
#define init_xcm_func(pdev)        ECORE_INIT_FUNC(pdev, XCM)
#define init_tm_func(pdev)         ECORE_INIT_FUNC(pdev, TM)
#define init_brb_func(pdev)        ECORE_INIT_FUNC(pdev, BRB1)
#define init_tsdm_func(pdev)       ECORE_INIT_FUNC(pdev, TSDM)
#define init_csdm_func(pdev)       ECORE_INIT_FUNC(pdev, CSDM)
#define init_usdm_func(pdev)       ECORE_INIT_FUNC(pdev, USDM)
#define init_xsdm_func(pdev)       ECORE_INIT_FUNC(pdev, XSDM)
#define init_upb_func(pdev)        ECORE_INIT_FUNC(pdev, UPB)
#define init_xpb_func(pdev)        ECORE_INIT_FUNC(pdev, XPB)
#define init_cdu_func(pdev)        ECORE_INIT_FUNC(pdev, CDU)
#define init_aeu_func(pdev)        ECORE_INIT_FUNC(pdev, MISC_AEU)
#define init_dbg_func(pdev)        ECORE_INIT_FUNC(pdev, DBG)
#define init_dmae_func(pdev)       ECORE_INIT_FUNC(pdev, DMAE)

// for PRS BRB mem setup
static void init_nig_pkt(struct _lm_device_t *pdev)
{
    u32 wb_write[3] = {0} ;

    wb_write[0] = 0x55555555 ;
    wb_write[1] = 0x55555555 ;
    wb_write[2] = 0x20 ;

    // TBD: consider use DMAE to these writes

    // Ethernet source and destination addresses
    REG_WR_IND(pdev,NIG_REG_DEBUG_PACKET_LB,  wb_write[0]);
    REG_WR_IND(pdev,NIG_REG_DEBUG_PACKET_LB+4,wb_write[1]);
    // #SOP
    REG_WR_IND(pdev,NIG_REG_DEBUG_PACKET_LB+8,wb_write[2]);

    wb_write[0] = 0x09000000 ;
    wb_write[1] = 0x55555555 ;
    wb_write[2] = 0x10 ;

    // NON-IP protocol
    REG_WR_IND(pdev,NIG_REG_DEBUG_PACKET_LB,  wb_write[0]);
    REG_WR_IND(pdev,NIG_REG_DEBUG_PACKET_LB+4,wb_write[1]);
    // EOP, eop_bvalid = 0
    REG_WR_IND(pdev,NIG_REG_DEBUG_PACKET_LB+8,wb_write[2]);
}

static void prs_brb_mem_setup (struct _lm_device_t *pdev)
{
    u32_t val    = 0;
    u32_t trash  = 0;
    u32_t cnt    = 0;
    u8_t  i      = 0;

#ifdef _VBD_CMD_
    return;
#endif
    DbgBreakIf(!pdev->vars.clk_factor);

    DbgMessage(pdev, WARN, "mem_wrk start part1\n");
    //First part
    // Disable inputs of parser neighbor blocks
    REG_WR(pdev,TSDM_REG_ENABLE_IN1,0x0);
    REG_WR(pdev,TCM_REG_PRS_IFEN,0x0);
    REG_WR(pdev,CFC_REG_DEBUG0,0x1);
    REG_WR(pdev,NIG_REG_PRS_REQ_IN_EN,0x0);

    // Write 0 to parser credits for CFC search request
    REG_WR(pdev,PRS_REG_CFC_SEARCH_INITIAL_CREDIT,0x0);

    // send Ethernet packet
    init_nig_pkt(pdev);

    // TODO: Reset NIG statistic
    // Wait until NIG register shows 1 packet of size 0x10
    cnt = 1000;
    while (cnt)
    {
        val=REG_RD(pdev,NIG_REG_STAT2_BRB_OCTET);
        trash=REG_RD(pdev,NIG_REG_STAT2_BRB_OCTET+4);

        if (val == 0x10)
        {
            break;
        }
        mm_wait(pdev,10 * pdev->vars.clk_factor);
        cnt--;
    }
    if (val != 0x10)
    {
        DbgMessage(pdev, FATAL, "mem_wrk: part1 NIG timeout val = 0x%x\n",val);
        DbgBreakIfAll(1);
    }

    // Wait until PRS register shows 1 packet
    cnt = 1000;
    while (cnt)
    {
        val=REG_RD(pdev,PRS_REG_NUM_OF_PACKETS);

        if (val == 0x1)
        {
            break;
        }
        mm_wait(pdev,10 * pdev->vars.clk_factor);
        cnt--;
    }
    if (val != 0x1)
    {
        DbgMessage(pdev, FATAL, "mem_wrk: part1 PRS timeout val = 0x%x\n",val);
        DbgBreakIfAll(1);
    }
    // End of part 1

    // #Reset and init BRB,PRS
    REG_WR(pdev,GRCBASE_MISC+MISC_REGISTERS_RESET_REG_1_CLEAR,0x3);
    mm_wait(pdev,50);
    REG_WR(pdev,GRCBASE_MISC+MISC_REGISTERS_RESET_REG_1_SET,0x3);
    mm_wait(pdev,50);
    init_brb1_common( pdev );
    init_prs_common(pdev);

    DbgMessage(pdev, WARN, "mem_wrk start part2\n");
    // "Start of part 2"

    // Disable inputs of parser neighbor blocks
    REG_WR(pdev,TSDM_REG_ENABLE_IN1,0x0);
    REG_WR(pdev,TCM_REG_PRS_IFEN,0x0);
    REG_WR(pdev,CFC_REG_DEBUG0,0x1);
    REG_WR(pdev,NIG_REG_PRS_REQ_IN_EN,0x0);

    // Write 0 to parser credits for CFC search request
    REG_WR(pdev,PRS_REG_CFC_SEARCH_INITIAL_CREDIT,0x0);

    // send 10 Ethernet packets
    for (i=0;i<10;i++)
    {
        init_nig_pkt(pdev);
    }

    // Wait until NIG register shows 10+1 packets of size 11*0x10 = 0xb0
    cnt = 1000;
    while (cnt)
    {
        val=REG_RD(pdev,NIG_REG_STAT2_BRB_OCTET);
        trash=REG_RD(pdev,NIG_REG_STAT2_BRB_OCTET+4);

        if (val == 0xb0)
        {
            break;
        }
        mm_wait(pdev,10 * pdev->vars.clk_factor );
        cnt--;
    }
    if (val != 0xb0)
    {
        DbgMessage(pdev, FATAL, "mem_wrk: part2 NIG timeout val = 0x%x\n",val);
        DbgBreakIfAll(1);
    }

    // Wait until PRS register shows 2 packet
    val=REG_RD(pdev,PRS_REG_NUM_OF_PACKETS);

    if (val != 0x2)
    {
        DbgMessage(pdev, FATAL, "mem_wrk: part2 PRS wait for 2 timeout val = 0x%x\n",val);
        DbgBreakIfAll(1);
    }

    // Write 1 to parser credits for CFC search request
    REG_WR(pdev,PRS_REG_CFC_SEARCH_INITIAL_CREDIT,0x1);

    // Wait until PRS register shows 3 packet
    mm_wait(pdev,100 * pdev->vars.clk_factor);
    // Wait until NIG register shows 1 packet of size 0x10
    val=REG_RD(pdev,PRS_REG_NUM_OF_PACKETS);

    if (val != 0x3)
    {
        DbgMessage(pdev, FATAL, "mem_wrk: part2 PRS wait for 3 timeout val = 0x%x\n",val);
        DbgBreakIfAll(1);
    }

     // clear NIG EOP FIFO
    for (i=0;i<11;i++)
    {
        trash=REG_RD(pdev,NIG_REG_INGRESS_EOP_LB_FIFO);
    }
    val=REG_RD(pdev,NIG_REG_INGRESS_EOP_LB_EMPTY);
    DbgBreakIfAll(val != 1);

    // #Reset and init BRB,PRS
    REG_WR(pdev,GRCBASE_MISC+MISC_REGISTERS_RESET_REG_1_CLEAR,0x03);
    mm_wait(pdev,50);
    REG_WR(pdev,GRCBASE_MISC+MISC_REGISTERS_RESET_REG_1_SET,0x03);
    mm_wait(pdev,50);
    init_brb1_common( pdev );
    init_prs_common(pdev);
    // everest_init_part( pdev, BLCNUM_NIG  ,COMMON, hw);

    // Enable inputs of parser neighbor blocks
    REG_WR(pdev,TSDM_REG_ENABLE_IN1,0x7fffffff);
    REG_WR(pdev,TCM_REG_PRS_IFEN,0x1);
    REG_WR(pdev,CFC_REG_DEBUG0,0x0);
    REG_WR(pdev,NIG_REG_PRS_REQ_IN_EN,0x1);

    DbgMessage(pdev, WARN, "mem_wrk: Finish start part2\n");

}

static void lm_init_intmem_common(struct _lm_device_t *pdev)
{
    /* ip_id_mask (determines how the ip id (ipv4) rolls over, (init value currently constant: 'half')) */
    /* TODO need to add constant in common constant */
    LM_INTMEM_WRITE16(pdev, XSTORM_COMMON_IP_ID_MASK_OFFSET, 0x8000, BAR_XSTRORM_INTMEM);

    LM_INTMEM_WRITE16(pdev, USTORM_ETH_DYNAMIC_HC_PARAM_OFFSET, (u16_t)pdev->params.l2_dynamic_hc_min_bytes_per_packet, BAR_USTRORM_INTMEM);
    DbgBreakIf(USTORM_ETH_DYNAMIC_HC_PARAM_SIZE != sizeof(u16_t));

    if (!CHIP_IS_E1x(pdev))
    {
        DbgBreakIf(CSTORM_IGU_MODE_SIZE != 1);
        if (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_NORM)
        {
            LM_INTMEM_WRITE8(pdev, CSTORM_IGU_MODE_OFFSET, HC_IGU_NBC_MODE, BAR_CSTRORM_INTMEM);
        }
        else
        {
            LM_INTMEM_WRITE8(pdev, CSTORM_IGU_MODE_OFFSET, HC_IGU_BC_MODE, BAR_CSTRORM_INTMEM);
        }
    }
}


static void lm_init_intmem_port(struct _lm_device_t *pdev)
{
    u8_t func = 0;

    /* Licensing with no MCP workaround. */
    if (GET_FLAGS( pdev->params.test_mode, TEST_MODE_NO_MCP))
    {
        /* If there is no MCP then there is no shmem_base, therefore we write to an absolute address. port 1 is 28 bytes away.  */
        #define SHMEM_ABSOLUTE_LICENSE_ADDRESS 0xaff3c
        DbgMessage(pdev, WARN, "writing reg: %p\n", SHMEM_ABSOLUTE_LICENSE_ADDRESS + (PORT_ID(pdev) * 0x1c));
        LM_SHMEM_WRITE(pdev, SHMEM_ABSOLUTE_LICENSE_ADDRESS + (PORT_ID(pdev) * 0x1c), 0xffff);
    }

    DbgBreakIf(!pdev->vars.clk_factor);
    if(CHIP_IS_E1H(pdev))
    {
        /* in a non-mf-aware chip, we don't need to take care of all the other functions */
        LM_FOREACH_FUNC_IN_PORT(pdev, func)
        {
            /* Set all mac filter drop flags to '0' to make sure we don't accept packets for vnics that aren't up yet... do this for each vnic! */
            LM_INTMEM_WRITE32(pdev,TSTORM_MAC_FILTER_CONFIG_OFFSET(func) + OFFSETOF(struct tstorm_eth_mac_filter_config, ucast_drop_all), 0, BAR_TSTRORM_INTMEM);
            LM_INTMEM_WRITE32(pdev,TSTORM_MAC_FILTER_CONFIG_OFFSET(func) + OFFSETOF(struct tstorm_eth_mac_filter_config, ucast_accept_all), 0, BAR_TSTRORM_INTMEM);
            LM_INTMEM_WRITE32(pdev,TSTORM_MAC_FILTER_CONFIG_OFFSET(func) + OFFSETOF(struct tstorm_eth_mac_filter_config, mcast_drop_all), 0, BAR_TSTRORM_INTMEM);
            LM_INTMEM_WRITE32(pdev,TSTORM_MAC_FILTER_CONFIG_OFFSET(func) + OFFSETOF(struct tstorm_eth_mac_filter_config, mcast_accept_all), 0, BAR_TSTRORM_INTMEM);
            LM_INTMEM_WRITE32(pdev,TSTORM_MAC_FILTER_CONFIG_OFFSET(func) + OFFSETOF(struct tstorm_eth_mac_filter_config, bcast_accept_all), 0, BAR_TSTRORM_INTMEM);
        }
    }
    // for now only in multi vnic mode for min max cmng
    if (IS_MULTI_VNIC(pdev))
    {
        // first time always use 10000 for 10G
        lm_cmng_init(pdev,10000);
    }

    /* Tx switching is only enabled if in MF SI mode and npar_vm_switching is enabled...*/
    if (IS_MF_SI_MODE(pdev) && pdev->params.npar_vm_switching_enable)
    {
        //In switch independent mode, driver must enable TCP TX switching using XSTORM_TCP_TX_SWITCHING_EN_OFFSET.
        LM_INTMEM_WRITE32(pdev,XSTORM_TCP_TX_SWITCHING_EN_OFFSET(PORT_ID(pdev)), 1, BAR_XSTRORM_INTMEM);
    }
    else
    {
        if (!CHIP_IS_E1x(pdev)) //no Tx switching in E1, and the internal RAM offset for it is invalid.
        {
            LM_INTMEM_WRITE32(pdev,XSTORM_TCP_TX_SWITCHING_EN_OFFSET(PORT_ID(pdev)), 0, BAR_XSTRORM_INTMEM);
        }
    }
}

static void lm_init_intmem_eq(struct _lm_device_t * pdev)
{
    struct event_ring_data eq_data = {{0}};
    u32_t  addr                    = CSTORM_EVENT_RING_DATA_OFFSET(FUNC_ID(pdev));
    u32_t  index                   = 0;

    eq_data.base_addr.hi = lm_bd_chain_phys_addr(&pdev->eq_info.eq_chain.bd_chain, 0).as_u32.high;
    eq_data.base_addr.lo = lm_bd_chain_phys_addr(&pdev->eq_info.eq_chain.bd_chain, 0).as_u32.low;
    eq_data.producer     = lm_bd_chain_prod_idx(&pdev->eq_info.eq_chain.bd_chain);
    eq_data.index_id     = HC_SP_INDEX_EQ_CONS;
    eq_data.sb_id        = DEF_STATUS_BLOCK_INDEX;

    for (index = 0; index < sizeof(struct event_ring_data) / sizeof(u32_t); index++)
    {
        LM_INTMEM_WRITE32(pdev, addr + (sizeof(u32_t) * index), *((u32 *)&eq_data + index), BAR_CSTRORM_INTMEM);
    }
}

static void lm_init_intmem_function(struct _lm_device_t *pdev)
{
    u8_t const      func                                    = FUNC_ID(pdev);

    /* status blocks are done in init_status_blocks() */    /* need to be write using GRC don't generate interrupt spq prod init WB */
    REG_WR(pdev,XSEM_REG_FAST_MEMORY + (XSTORM_SPQ_PAGE_BASE_OFFSET(func)),pdev->sq_info.sq_chain.bd_chain_phy.as_u32.low);
    REG_WR(pdev,XSEM_REG_FAST_MEMORY + (XSTORM_SPQ_PAGE_BASE_OFFSET(func)) + 4,pdev->sq_info.sq_chain.bd_chain_phy.as_u32.high);
    REG_WR(pdev,XSEM_REG_FAST_MEMORY + (XSTORM_SPQ_PROD_OFFSET(func)),pdev->sq_info.sq_chain.prod_idx);

    /* Initialize the event-queue */
    lm_init_intmem_eq(pdev);

    /* Todo: Init indirection table */

    if(CHIP_IS_E1(pdev))
    {
        // Should run only for E1 (begining fw 6.4.10). In earlier versions (e.g. 6.2) the workaorund is relevant for E1.5 as well.
        /* add for PXP dual port memory setup */
        DbgBreakIf(lm_bd_chain_phys_addr(&pdev->eq_info.eq_chain.bd_chain, 0).as_u64 == 0);
        LM_INTMEM_WRITE32(pdev,USTORM_MEM_WORKAROUND_ADDRESS_OFFSET(func),lm_bd_chain_phys_addr(&pdev->eq_info.eq_chain.bd_chain, 0).as_u32.low, BAR_USTRORM_INTMEM); /* need to check */
        LM_INTMEM_WRITE32(pdev,USTORM_MEM_WORKAROUND_ADDRESS_OFFSET(func)+4,lm_bd_chain_phys_addr(&pdev->eq_info.eq_chain.bd_chain, 0).as_u32.high, BAR_USTRORM_INTMEM); /* need to check */
    }


    ASSERT_STATIC( 3 == ARRSIZE(pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[0].threshold) ) ;

    //init dynamic hc
    LM_INTMEM_WRITE32(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func), pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].threshold[0], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE32(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+4, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].threshold[1], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE32(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+8, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].threshold[2], BAR_CSTRORM_INTMEM);

    /*Set DHC scaling factor for L4*/
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+12, (16 - (u8_t)pdev->params.l4_hc_scaling_factor), BAR_CSTRORM_INTMEM);

    /*Reset DHC scaling factors for rest of protocols*/
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+13, 0, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+14, 0, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+15, 0, BAR_CSTRORM_INTMEM);

    ASSERT_STATIC( 4 == ARRSIZE(pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout0) ) ;
    ASSERT_STATIC( 4 == ARRSIZE(pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout1) ) ;
    ASSERT_STATIC( 4 == ARRSIZE(pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout2) ) ;
    ASSERT_STATIC( 4 == ARRSIZE(pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout3) ) ;

    /*Set DHC timeout 0 for all protocols*/
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+16, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout0[0], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+17, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout0[1], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+18, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout0[2], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+19, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout0[3], BAR_CSTRORM_INTMEM);

    /*Set DHC timeout 1 for all protocols*/
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+20, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout1[0], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+21, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout1[1], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+22, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout1[2], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+23, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout1[3], BAR_CSTRORM_INTMEM);

    /*Set DHC timeout 2 for all protocols*/
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+24, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout2[0], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+25, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout2[1], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+26, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout2[2], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+27, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout2[3], BAR_CSTRORM_INTMEM);

    /*Set DHC timeout 3 for all protocols*/
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+28, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout3[0], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+29, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout3[1], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+30, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout3[2], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+31, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_RX_ID].hc_timeout3[3], BAR_CSTRORM_INTMEM);

#define TX_DHC_OFFSET   32
    LM_INTMEM_WRITE32(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].threshold[0], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE32(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+4, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].threshold[1], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE32(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+8, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].threshold[2], BAR_CSTRORM_INTMEM);


    /*Reset DHC scaling factors for all protocols*/
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+12, 0, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+13, 0, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+14, 0, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+15, 0, BAR_CSTRORM_INTMEM);

    /*Set DHC timeout 0 for all protocols*/
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+16, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout0[0], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+17, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout0[1], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+18, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout0[2], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+19, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout0[3], BAR_CSTRORM_INTMEM);

    /*Set DHC timeout 1 for all protocols*/
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+20, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout1[0], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+21, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout1[1], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+22, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout1[2], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+23, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout1[3], BAR_CSTRORM_INTMEM);

    /*Set DHC timeout 2 for all protocols*/
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+24, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout2[0], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+25, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout2[1], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+26, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout2[2], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+27, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout2[3], BAR_CSTRORM_INTMEM);

    /*Set DHC timeout 3 for all protocols*/
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+28, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout3[0], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+29, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout3[1], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+30, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout3[2], BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev,CSTORM_DYNAMIC_HC_CONFIG_OFFSET(func)+TX_DHC_OFFSET+31, pdev->vars.int_coal.eth_dynamic_hc_cfg.sm_config[SM_TX_ID].hc_timeout3[3], BAR_CSTRORM_INTMEM);

    /* E1H specific init */
    if (pdev->params.disable_patent_using)
    {
        DbgMessage(pdev, WARN, "Patent is disabled\n");
        LM_INTMEM_WRITE8(pdev, TSTORM_TCP_GLOBAL_PARAMS_OFFSET, 0, BAR_TSTRORM_INTMEM);
    }

    /* Below statements forces FW to trace SP operation. This debugger feature may be involved via initialization correspnding params value
       in bootleg or/and via undocumented registry value (per function). Disableing statistics is highly recommmended using this debug option*/
    if (pdev->params.record_sp & XSTORM_RECORD_SLOW_PATH)
    {
        LM_INTMEM_WRITE8(pdev, XSTORM_RECORD_SLOW_PATH_OFFSET(FUNC_ID(pdev)), 1, BAR_XSTRORM_INTMEM);
    }

    if (pdev->params.record_sp & CSTORM_RECORD_SLOW_PATH)
    {
        LM_INTMEM_WRITE8(pdev, CSTORM_RECORD_SLOW_PATH_OFFSET(FUNC_ID(pdev)), 1, BAR_CSTRORM_INTMEM);
    }

    if (pdev->params.record_sp & TSTORM_RECORD_SLOW_PATH)
    {
        LM_INTMEM_WRITE8(pdev, TSTORM_RECORD_SLOW_PATH_OFFSET(FUNC_ID(pdev)), 1, BAR_TSTRORM_INTMEM);
    }

    if (pdev->params.record_sp & USTORM_RECORD_SLOW_PATH)
    {
        LM_INTMEM_WRITE8(pdev, USTORM_RECORD_SLOW_PATH_OFFSET(FUNC_ID(pdev)), 1, BAR_USTRORM_INTMEM);
    }

    /* Enable the function in STORMs */
    LM_INTMEM_WRITE8(pdev, XSTORM_VF_TO_PF_OFFSET(FUNC_ID(pdev)), FUNC_ID(pdev), BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev, CSTORM_VF_TO_PF_OFFSET(FUNC_ID(pdev)), FUNC_ID(pdev), BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev, TSTORM_VF_TO_PF_OFFSET(FUNC_ID(pdev)), FUNC_ID(pdev), BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev, USTORM_VF_TO_PF_OFFSET(FUNC_ID(pdev)), FUNC_ID(pdev), BAR_USTRORM_INTMEM);

    LM_INTMEM_WRITE8(pdev, XSTORM_FUNC_EN_OFFSET(FUNC_ID(pdev)), 1, BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev, CSTORM_FUNC_EN_OFFSET(FUNC_ID(pdev)), 1, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev, TSTORM_FUNC_EN_OFFSET(FUNC_ID(pdev)), 1, BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE8(pdev, USTORM_FUNC_EN_OFFSET(FUNC_ID(pdev)), 1, BAR_USTRORM_INTMEM);
}

static  void init_common_part(struct _lm_device_t *pdev)
{
    u32_t       temp                      = 0;
    u32_t       val                       = 0;
    u32_t       trash                     = 0;
    u8_t        rc                        = 0;
    const u32_t wait_ms                   = 200*pdev->vars.clk_factor ;
    u32_t       shmem_base[MAX_PATH_NUM]  = {0};
    u32_t       shmem_base2[MAX_PATH_NUM] = {0};
    const u8_t  port                      = PORT_ID(pdev);

    DbgMessage(pdev, INFORMi, "init_common_part\n");

    /* shutdown bug - clear the shutdown inprogress flag*/
    /* Must be done before DMAE */
    lm_reset_clear_inprogress(pdev);

    DbgBreakIf( !pdev->vars.clk_factor );

    init_misc_common( pdev );
    init_pxp_common ( pdev );
    init_pxp2_common( pdev );
    init_pglue_b_common(pdev);
    init_atc_common ( pdev );
    init_dmae_common( pdev );
    init_tcm_common ( pdev );
    init_ucm_common ( pdev );
    init_ccm_common ( pdev );
    init_xcm_common ( pdev );
    init_qm_common  ( pdev );
    init_tm_common  ( pdev );
    init_dq_common  ( pdev );
    init_brb1_common( pdev );
    init_prs_common( pdev);
    init_tsdm_common( pdev );
    init_csdm_common( pdev );
    init_usdm_common( pdev );
    init_xsdm_common( pdev );

    init_semi_common(pdev);

    // syncronize rtc of the semi's
    REG_WR(pdev,GRCBASE_MISC+MISC_REGISTERS_RESET_REG_1_CLEAR,0x80000000);
    REG_WR(pdev,GRCBASE_MISC+MISC_REGISTERS_RESET_REG_1_SET,0x80000000);

    init_upb_common( pdev );
    init_xpb_common( pdev );
    init_pbf_common( pdev );

    init_src_common(pdev);
    init_cdu_common(pdev);
    init_cfc_common(pdev);
    init_hc_common(pdev);

    if (!CHIP_IS_E1x(pdev) && GET_FLAGS( pdev->params.test_mode, TEST_MODE_NO_MCP))
    {
        /* don't zeroize msix memory - this overrides windows OS initialization */
        REG_WR(pdev,IGU_REG_RESET_MEMORIES,0x36);
    }
    init_igu_common(pdev);
    init_aeu_common(pdev);
    init_pxpcs_common(pdev);
    init_dbg_common(pdev);
    init_nig_common(pdev);

    // TBD: E1H - determine whether to move from here, or have "wait for blks done" function
    //finish CFC init
    REG_WAIT_VERIFY_VAL(pdev, CFC_REG_LL_INIT_DONE,1,wait_ms );

    REG_WAIT_VERIFY_VAL(pdev, CFC_REG_AC_INIT_DONE,1,wait_ms);
    // moved here because of timing problem
    REG_WAIT_VERIFY_VAL(pdev, CFC_REG_CAM_INIT_DONE,1,wait_ms);
    // we need to enable inputs here.
    REG_WR(pdev,CFC_REG_DEBUG0,0);

    if (CHIP_IS_E1(pdev))
    {
        // read NIG statistic
        val   = REG_RD(pdev,NIG_REG_STAT2_BRB_OCTET);
        trash = REG_RD(pdev,NIG_REG_STAT2_BRB_OCTET+4);

        // PRS BRB memory setup only after full power cycle
        if(val == 0)
        {
            prs_brb_mem_setup(pdev);
        }
    }

    lm_setup_fan_failure_detection(pdev);

    /* One time initialization of the phy:
    in 2-port-mode - only for the first device on a chip!
    in 4-port-mode - always */

    if ((pdev->vars.load_code == LM_LOADER_RESPONSE_LOAD_COMMON_CHIP) ||
        CHIP_IS_E1x(pdev))
    {
        shmem_base[0]  = pdev->hw_info.shmem_base;
        shmem_base2[0] = pdev->hw_info.shmem_base2;

        if (!CHIP_IS_E1x(pdev))
        {
            LM_SHMEM2_READ(pdev, OFFSETOF(shmem2_region_t,other_shmem_base_addr), &shmem_base[1]);
            LM_SHMEM2_READ(pdev, OFFSETOF(shmem2_region_t,other_shmem2_base_addr), &shmem_base2[1]);
        }

        // Apply common init only in case LFA is not supported by MFW.
        if ( !LM_SHMEM2_HAS(pdev, lfa_host_addr[port]) )
        {
            rc = elink_common_init_phy(pdev, shmem_base, shmem_base2, CHIP_ID(pdev), 0);
            DbgBreakIf( ELINK_STATUS_OK != rc );

            rc = elink_pre_init_phy(pdev, shmem_base[0], shmem_base2[0], CHIP_ID(pdev), port);
            DbgBreakIf( ELINK_STATUS_OK != rc );
        }
    }

    //clear PXP2 attentions
    temp = REG_RD(pdev,PXP2_REG_PXP2_INT_STS_CLR_0);

    // set dcc_support in case active
    if(pdev->hw_info.shmem_base2)
    {
        val = (SHMEM_DCC_SUPPORT_DISABLE_ENABLE_PF_TLV | SHMEM_DCC_SUPPORT_BANDWIDTH_ALLOCATION_TLV) ;
        temp = OFFSETOF( shmem2_region_t, dcc_support);
        LM_SHMEM2_WRITE(pdev, temp, val );
    }

    ///Write driver NIV support
    if (IS_MF_AFEX_MODE(pdev))
    {
        DbgBreakIf(!pdev->hw_info.shmem_base2);
        LM_SHMEM2_WRITE(pdev,   OFFSETOF( shmem2_region_t, afex_driver_support),
                                SHMEM_AFEX_SUPPORTED_VERSION_ONE );
    }

    if (LM_SHMEM2_HAS(pdev, drv_capabilities_flag))
    {
        DbgBreakIf(!pdev->hw_info.shmem_base2);
        //we clear all the other capabilites flags and set just DRV_FLAGS_CAPABALITIES_LOADED_SUPPORTED
        LM_SHMEM2_WRITE(pdev, OFFSETOF(shmem2_region_t, drv_capabilities_flag[FUNC_MAILBOX_ID(pdev)]), DRV_FLAGS_CAPABILITIES_LOADED_SUPPORTED);
    }


    enable_blocks_attention(pdev);

    /* Enable parity error only for E2 and above */
    if (!CHIP_IS_E1x(pdev))
    {
        DbgMessage(pdev, WARN, "Enabling parity errors\n");
        ecore_enable_blocks_parity(pdev);
    }
}


void init_port_part(struct _lm_device_t *pdev)
{
    u32_t val = 0;
    const u8_t  port = PORT_ID(pdev);

    /* Probe phys on board - must happen before lm_reset_link*/
    elink_phy_probe(&pdev->params.link);

    REG_WR(pdev,(port ? NIG_REG_MASK_INTERRUPT_PORT1 : NIG_REG_MASK_INTERRUPT_PORT0), 0);

    init_misc_port(pdev);
    init_pxp_port(pdev);
    init_pxp2_port(pdev);
    init_pglue_b_port(pdev);
    init_atc_port(pdev);
    init_tcm_port( pdev);
    init_ucm_port( pdev);
    init_ccm_port( pdev);
    init_xcm_port( pdev);
    init_qm_port ( pdev);
    init_tm_port ( pdev);
    init_dq_port ( pdev);
    init_brb_port( pdev);
    init_prs_port( pdev);
    init_tsdm_port( pdev);
    init_csdm_port( pdev);
    init_usdm_port( pdev);
    init_xsdm_port( pdev);

    init_semi_port(pdev);
    init_upb_port(pdev);
    init_xpb_port(pdev);
    init_pbf_port( pdev );
    init_src_port(pdev);
    init_cdu_port(pdev);
    init_cfc_port(pdev);
    init_hc_port( pdev);
    init_igu_port( pdev);
    init_aeu_port( pdev);
    init_dbg_port(pdev);

    init_nig_port( pdev);
    init_dmae_port(pdev);


    MM_ACQUIRE_PHY_LOCK(pdev);
    lm_stats_init_port_part(pdev);
    elink_init_mod_abs_int(pdev, &pdev->vars.link, CHIP_ID(pdev), pdev->hw_info.shmem_base, pdev->hw_info.shmem_base2, port);
    MM_RELEASE_PHY_LOCK(pdev);

    // iSCSI FW expect bit 28 to be set
    if (!GET_FLAGS( pdev->params.test_mode, TEST_MODE_NO_MCP))
    {
        LM_SHMEM_READ(pdev,  OFFSETOF(shmem_region_t,dev_info.port_feature_config[port].config), &val );
        SET_FLAGS(val, (1 << 28)) ;
        LM_SHMEM_WRITE(pdev, OFFSETOF(shmem_region_t,dev_info.port_feature_config[port].config), val );
    }
    // Clear the shared port bit of the DCBX completion
    lm_dcbx_config_drv_flags(pdev, lm_dcbx_drv_flags_reset_flags,0);
}

void init_function_part(struct _lm_device_t *pdev)
{
    const u8_t func       = FUNC_ID(pdev);
    const u8_t func_mb_id = FUNC_MAILBOX_ID(pdev);

    DbgMessage(pdev, INFORMi, "init_function_part, func=%d\n", func);

    if (!CHIP_IS_E1x(pdev) && LM_SHMEM2_HAS(pdev, drv_capabilities_flag))
    {
        //we clear all the other capabilites flags and set just DRV_FLAGS_CAPAIALITIES_LOADED_SUPPORTED
        LM_SHMEM2_WRITE(pdev, OFFSETOF(shmem2_region_t, drv_capabilities_flag[func_mb_id]), DRV_FLAGS_CAPABILITIES_LOADED_SUPPORTED | (pdev->params.mtu_max << DRV_FLAGS_MTU_SHIFT));
    }

    init_pxp_func(pdev);
    init_pxp2_func( pdev );
    init_pglue_b_func(pdev);
    init_atc_func(pdev);
    init_misc_func(pdev);
    init_tcm_func(pdev);
    init_ucm_func(pdev);
    init_ccm_func(pdev);
    init_xcm_func(pdev);
    init_semi_func(pdev);
    init_qm_func(pdev);
    init_tm_func(pdev);
    init_dq_func(pdev);
    init_brb_func(pdev);
    init_prs_func(pdev);
    init_tsdm_func(pdev);
    init_csdm_func(pdev);
    init_usdm_func(pdev);
    init_xsdm_func(pdev);
    init_upb_func(pdev);
    init_xpb_func(pdev);

    init_pbf_func(pdev);
    init_src_func(pdev);
    init_cdu_func(pdev);
    init_cfc_func(pdev);
    init_hc_func(pdev);
    init_igu_func(pdev);
    init_aeu_func(pdev);
    init_pxpcs_func(pdev);
    init_dbg_func(pdev);
    init_nig_func( pdev);
    init_dmae_func(pdev);


    /* Probe phys on board */
    elink_phy_probe(&pdev->params.link);
    if (IS_PMF(pdev) && IS_MULTI_VNIC(pdev))
    {
        DbgMessage(pdev, WARN, "init_function_part: Func %d is the PMF\n", func );
    }

    MM_ACQUIRE_PHY_LOCK(pdev);
    lm_stats_init_func_part(pdev);
    MM_RELEASE_PHY_LOCK(pdev);
}

/**
 * @Description
 *      The purpose of this function is to check that the chip
 *      is ready for initialization. Most checks are done in
 *      get_dev_info, however, due to Diag requirements its
 *      possible that certain things are not configured properly
 *      but get_dev_info passed. At time of writing this
 *      function it was IGU configuration in E3, but in the
 *      future there may be more things like this...
 *
 * @param pdev
 *
 * @return TRUE / FALSE
 */
u8_t
lm_chip_ready_for_init( struct _lm_device_t *pdev)
{
    lm_igu_info_t * igu_info = &pdev->hw_info.intr_blk_info.igu_info;
    const u8_t      blk_type = INTR_BLK_TYPE(pdev);
    const u8_t      blk_mode = INTR_BLK_MODE(pdev);

    if (( blk_type == INTR_BLK_IGU) &&
        ( blk_mode == INTR_BLK_MODE_NORM))
    {
        if ((igu_info->igu_sb_cnt < 1) ||(igu_info->igu_base_sb == 0xff))
        {
            return FALSE;
        }
    }

    return TRUE;
}

lm_status_t lm_init_common_chip_part(struct _lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u32_t       val       = 0;

    #ifdef _VBD_
    lm_fl_reset_clear_inprogress(pdev);
    #endif

    val = convert_to_bcd( pdev->product_version );
    lm_ncsi_drv_ver_to_scratchpad(pdev, val );

    return lm_status;
}

/* Description:
 *    The main function of this routine is to initialize the
 *    hardware. it configues all hw blocks in several phases acording to mcp response:
 *    1. common blocks
 *    2. per function blocks
 */
lm_status_t
lm_chip_init( struct _lm_device_t *pdev)
{

    const lm_loader_opcode opcode    = LM_LOADER_OPCODE_LOAD;
    lm_loader_response     resp      = 0;
    lm_status_t            lm_status = LM_STATUS_SUCCESS;


    DbgMessage(pdev, INFORMi , "### lm_chip_init %x\n",CHIP_NUM(pdev));

#ifdef VF_INVOLVED
    if (IS_VFDEV(pdev))
    {
        return lm_vf_chip_init(pdev);
    }
#endif

    if (!lm_chip_ready_for_init(pdev))
    {
        return LM_STATUS_FAILURE;
    }

    /* Check if we need to reset the device:
     * This can happen for two reasons:
     * 1. Undi was active
     * 2. BFS/CrashDump Hibernation (fcoe crashdump driver) */
    if (IS_PFDEV(pdev))
    {
        lm_reset_device_if_undi_active(pdev);
    }

    // init mcp sequences
    lm_status = lm_mcp_cmd_init(pdev);

    if( LM_STATUS_SUCCESS != lm_status )
    {
        DbgMessage(pdev, FATAL, "lm_chip_init: mcp_cmd_init failed. lm_status=0x%x\n", lm_status);
        DbgBreakMsg("lm_mcp_cmd_init failed!\n");
        return lm_status ;
    }

    INIT_MODE_FLAGS(pdev) = lm_init_get_modes_bitmap(pdev);

    resp = lm_loader_lock(pdev, opcode );


    /* Save the load response */
    pdev->vars.load_code = resp;
    // This should be first call after load request since we must complete
    // these settings in 5 seconds (MCP keepalive timeout or start pulse)
    lm_driver_pulse_always_alive(pdev);

    if( LM_LOADER_RESPONSE_INVALID != resp )
    {
        if (IS_ASSIGNED_TO_VM_PFDEV(pdev))
        {
            //Validate FW if Port or Function
            switch (resp)
            {
            case LM_LOADER_RESPONSE_LOAD_PORT:
            case LM_LOADER_RESPONSE_LOAD_FUNCTION:
                if (!lm_is_fw_version_valid(pdev))
                {
                    lm_loader_lock(pdev, LM_LOADER_OPCODE_UNLOAD_WOL_MCP);
                    lm_loader_unlock(pdev, LM_LOADER_OPCODE_UNLOAD_WOL_MCP, NULL );
                    return LM_STATUS_BAD_SIGNATURE;
                }
                break;
            default:
                break;
            }
        }
        // We need to call it here since init_funciton_part use these pointers
        lm_setup_read_mgmt_stats_ptr(pdev, FUNC_MAILBOX_ID(pdev), &pdev->vars.fw_port_stats_ptr, &pdev->vars.fw_func_stats_ptr );
    }

    if (!IS_DRIVER_PULSE_ALWAYS_ALIVE(pdev))
    {
        if(LM_STATUS_SUCCESS != lm_send_driver_pulse(pdev))
        {
            lm_driver_pulse_always_alive(pdev);
            DbgBreak();
        }
    }

    // update mps and mrrs from pcicfg
    lm_status = lm_get_pcicfg_mps_mrrs(pdev);

    if (!IS_ASSIGNED_TO_VM_PFDEV(pdev))
    {
        lm_pcie_state_restore_for_d0( pdev);
    }

    switch (resp)
    {
    case LM_LOADER_RESPONSE_LOAD_COMMON_CHIP:
        lm_status = lm_init_common_chip_part(pdev);
        if (LM_STATUS_SUCCESS != lm_status)
        {
            return lm_status;
        }
    case LM_LOADER_RESPONSE_LOAD_COMMON:
#ifdef _VBD_
        lm_fl_reset_clear_inprogress(pdev);
#endif
        lm_reset_path( pdev, FALSE ); /* Give a chip-reset (path) before initializing driver*/
        init_common_part(pdev);
        if (IS_MULTI_VNIC(pdev) && CHIP_IS_E2E3(pdev) && CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_2)
        {
            int i = 0;
            u32_t start_reg = IGU_REG_FUNC_WITH_MORE_16_SB_0;
            u32_t function_number = (1 << 8) | (1 << 6) | 0;

            for (i = 0; i < VNICS_PER_PATH(pdev); i++)
            {
                 REG_WR(pdev, start_reg + 4 * i, function_number + 2 * i);
            }
        }

        lm_init_intmem_common(pdev);
        // going to the port part no break

        // Clear pervious dbus info which may have been left
        // during error recovery (if any)
        mm_dbus_stop_if_started(pdev);

        //Check if there is dbus work
        mm_dbus_start_if_enable(pdev);

    case LM_LOADER_RESPONSE_LOAD_PORT:
#ifdef _VBD_
        if (lm_is_function_after_flr(pdev))
        {
            if (IS_PFDEV(pdev))
            {
                lm_status = lm_cleanup_after_flr(pdev);

                if(lm_status != LM_STATUS_SUCCESS)
                {
                    return lm_status;
                }
            }
            else
            {
                lm_fl_reset_clear_inprogress(pdev);
            }
        }
#endif
        // If we are here, DMAE is ready (from common part init) - set it for TRUE for non-first devices
        pdev->vars.b_is_dmae_ready = TRUE;

        // set device as pmf
        pdev->vars.is_pmf = PMF_ORIGINAL;

        init_port_part(pdev);
        lm_init_intmem_port(pdev);

        // going to the function part - fall through
    case LM_LOADER_RESPONSE_LOAD_FUNCTION:
#ifdef _VBD_
    if (lm_is_function_after_flr(pdev))
    {
        if (IS_PFDEV(pdev))
        {
            lm_status = lm_cleanup_after_flr(pdev);

            if(lm_status != LM_STATUS_SUCCESS)
            {
                return lm_status;
            }
        }
        else
        {
            lm_fl_reset_clear_inprogress(pdev);
        }
    }
#endif
        // If we are here, DMAE is ready (from port part init) - set it for TRUE for non-first devices
        pdev->vars.b_is_dmae_ready = TRUE;
        init_function_part(pdev);
        init_status_blocks(pdev);
        lm_init_intmem_function(pdev);
#ifndef __BIG_ENDIAN
        lm_tcp_init_chip_common(pdev);
#endif
        break;

    default:
        DbgMessage(pdev, WARN, "wrong loader response\n");
        DbgBreakIfAll(1);
    }

    resp = lm_loader_unlock( pdev, opcode, NULL ) ;

    if (resp != LM_LOADER_RESPONSE_LOAD_DONE)
    {
        DbgMessage(pdev, WARN, "wrong loader response\n");
        DbgBreakIfAll(1);
    }

    /* Read MF config parameters: there is a time window between MF
     * configuration initialization and DCC attention, allowing DCC
     * link state change to go unnoticed. This may cause wrong link
     * state to be seen by clients, hence re-sync here.
     */

    if (IS_MF_MODE_CAPABLE(pdev))
    {
           lm_get_shmem_info(pdev);
    }

    // TBD link training

    return LM_STATUS_SUCCESS;
}
