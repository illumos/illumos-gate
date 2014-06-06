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
 *    11/26/07 Alon Elhanani    Inception.
 ******************************************************************************/

#include "lm5710.h"
#include "license.h"
#include "mcp_shmem.h"
#include "debug.h"

#define MCP_EMUL_TIMEOUT 200000    /* 200 ms (in us) */
#define MCP_TIMEOUT      5000000   /* 5 seconds (in us) */
#define MCP_ONE_TIMEOUT  100000    /* 100 ms (in us) */

/**
 * Waits for MCP_ONE_TIMEOUT or MCP_ONE_TIMEOUT*10,
 * depending on the HW type.
 *
 * @param pdev
 */
static __inline void lm_mcp_wait_one (
    IN  struct _lm_device_t * pdev
    )
{
    /* special handling for emulation and FPGA,
       wait 10 times longer */
    if (CHIP_REV_IS_SLOW(pdev)) {
        mm_wait(pdev, MCP_ONE_TIMEOUT*10);
    } else {
        mm_wait(pdev, MCP_ONE_TIMEOUT);
    }
}


#if !defined(b710)

/**
 * Prepare CLP to MCP reset.
 *
 * @param pdev Device handle
 * @param magic_val Old value of `magic' bit.
 */
void lm_clp_reset_prep(
    IN  struct _lm_device_t * pdev,
    OUT u32_t               * magic_val
    )
{
    u32_t val = 0;
    u32_t offset;

#define SHARED_MF_CLP_MAGIC  0x80000000 /* `magic' bit */

    ASSERT_STATIC(sizeof(struct mf_cfg) % sizeof(u32_t) == 0);

    /* Do some magic... */
    offset = OFFSETOF(mf_cfg_t, shared_mf_config.clp_mb);
    LM_MFCFG_READ(pdev, offset, &val);
    *magic_val = val & SHARED_MF_CLP_MAGIC;
    LM_MFCFG_WRITE(pdev, offset, val | SHARED_MF_CLP_MAGIC);
}

/**
 * Restore the value of the `magic' bit.
 *
 * @param pdev Device handle.
 * @param magic_val Old value of the `magic' bit.
 */
void lm_clp_reset_done(
    IN  struct _lm_device_t * pdev,
    IN  u32_t                 magic_val
    )
{
    u32_t val = 0;
    u32_t offset;

    /* Restore the `magic' bit value... */
    offset = OFFSETOF(mf_cfg_t, shared_mf_config.clp_mb);
    LM_MFCFG_READ(pdev, offset, &val);
    LM_MFCFG_WRITE(pdev, offset, (val & (~SHARED_MF_CLP_MAGIC)) | magic_val);
}

#endif // !b710

u8_t lm_is_mcp_detected(
    IN struct _lm_device_t *pdev
    )
{
    return pdev->hw_info.mcp_detected;
}

/**
 * @Description
 *      Prepares for MCP reset: takes care of CLP configurations
 *      (saves it aside to resotre later) .
 *
 * @param pdev
 * @param magic_val Old value of 'magic' bit.
 */
lm_status_t lm_reset_mcp_prep(lm_device_t *pdev, u32_t * magic_val)
{
    u32_t shmem;
    u32_t validity_offset;

    /* Set `magic' bit in order to save MF config */
    if (!CHIP_IS_E1(pdev))
    {
        lm_clp_reset_prep(pdev, magic_val);
    }

    /* Get shmem offset */
    shmem = REG_RD(pdev, MISC_REG_SHARED_MEM_ADDR);
    validity_offset = OFFSETOF(shmem_region_t, validity_map[0]);

    /* Clear validity map flags */
    if( shmem > 0 )
    {
        REG_WR(pdev, shmem + validity_offset, 0);
    }

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_reset_mcp_comp(lm_device_t *pdev, u32_t magic_val)
{
    lm_status_t lm_status         = LM_STATUS_SUCCESS;
    u32_t       shmem_sig_timeout = 0;
    u32_t       validity_offset   = 0;
    u32_t       shmem             = 0;
    u32_t       val               = 0;
    u32_t       cnt               = 0;

#ifdef _VBD_CMD_
    return LM_STATUS_SUCCESS;
#endif

    /* Get shmem offset */
    shmem = REG_RD(pdev, MISC_REG_SHARED_MEM_ADDR);
    if( shmem == 0 ) {
        DbgMessage(pdev, FATAL, "Shmem 0 return failure\n");
        lm_status = LM_STATUS_FAILURE;
        goto exit_lbl;
    }

    ASSERT_STATIC(0 != MCP_ONE_TIMEOUT);

    if (CHIP_REV_IS_EMUL(pdev))
        shmem_sig_timeout = MCP_EMUL_TIMEOUT / MCP_ONE_TIMEOUT; // 200ms
    else
        shmem_sig_timeout = MCP_TIMEOUT / MCP_ONE_TIMEOUT; // 5sec

    validity_offset = OFFSETOF(shmem_region_t, validity_map[0]);

    /* Wait for MCP to come up */
    for(cnt = 0; cnt < shmem_sig_timeout; cnt++)
    {
        /* TBD: its best to check validity map of last port. currently checks on port 0. */
        val = REG_RD(pdev, shmem + validity_offset);
        DbgMessage(pdev, INFORM, "shmem 0x%x validity map(0x%x)=0x%x\n", shmem, shmem + validity_offset, val);

        /* check that shared memory is valid. */
        if((val & (SHR_MEM_VALIDITY_DEV_INFO | SHR_MEM_VALIDITY_MB)) ==
           (SHR_MEM_VALIDITY_DEV_INFO|SHR_MEM_VALIDITY_MB)) {
            break;
        }

        lm_mcp_wait_one(pdev);
    }

    DbgMessage(pdev, INFORM , "Cnt=%d Shmem validity map 0x%x\n",cnt, val);

    /* Check that shared memory is valid. This indicates that MCP is up. */
    if((val & (SHR_MEM_VALIDITY_DEV_INFO | SHR_MEM_VALIDITY_MB)) !=
       (SHR_MEM_VALIDITY_DEV_INFO | SHR_MEM_VALIDITY_MB))
    {
        DbgMessage(pdev, FATAL, "Shmem signature not present. MCP is not up !!\n");
        lm_status = LM_STATUS_FAILURE;
        goto exit_lbl;
    }

exit_lbl:

    if (!CHIP_IS_E1(pdev))
    {
        /* Restore `magic' bit value */
        lm_clp_reset_done(pdev, magic_val);
    }

    return lm_status;
}

lm_status_t lm_reset_mcp(
    IN struct _lm_device_t *pdev
    )
{

    u32_t magic_val = 0;
    u32_t val, retries=0;
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    DbgMessage(pdev, VERBOSE, "Entered lm_reset_mcp\n");

    lm_reset_mcp_prep(pdev, &magic_val);

    /* wait up to 3 seconds to get all locks. Whatsoever, reset mcp afterwards */
    do {
         REG_WR(pdev, MISC_REG_DRIVER_CONTROL_15 + 4, 0xffffffff);
         val = REG_RD(pdev, MISC_REG_DRIVER_CONTROL_15);
         mm_wait(pdev, 1);
    } while ((val != 0xffffffff) && (++retries < 3000000));

    /* Reset the MCP */
    REG_WR(pdev, GRCBASE_MISC+ MISC_REGISTERS_RESET_REG_2_CLEAR,
         MISC_REGISTERS_RESET_REG_2_RST_MCP_N_RESET_REG_HARD_CORE  |
         MISC_REGISTERS_RESET_REG_2_RST_MCP_N_HARD_CORE_RST_B      |
         MISC_REGISTERS_RESET_REG_2_RST_MCP_N_RESET_CMN_CPU        |
         MISC_REGISTERS_RESET_REG_2_RST_MCP_N_RESET_CMN_CORE);

    /* release the locks taken */
    REG_WR(pdev, MISC_REG_DRIVER_CONTROL_15, 0xffffffff);

    mm_wait(pdev, 100000);

    // No need to wait here a minimum time, since the mcp_comp will
    // returns only when mcp is ready.
    lm_status = lm_reset_mcp_comp(pdev, magic_val);

    return lm_status;
}

//acquire split MCP access lock register
lm_status_t
acquire_split_alr(
    lm_device_t *pdev)
{
    lm_status_t lm_status;
    u32_t j, cnt;
    u32_t val_wr, val_rd;

    DbgMessage(pdev, INFORM, "acquire_split_alr() - %d START!\n", FUNC_ID(pdev) );

    //Adjust timeout for our emulation needs
    cnt = 30000 * 100;
    val_wr = 1UL << 31;
    val_rd = 0;

    //acquire lock using mcpr_access_lock SPLIT register

    for(j = 0; j < cnt*10; j++)
    {
        REG_WR(pdev,  GRCBASE_MCP + 0x9c, val_wr);
        val_rd = REG_RD(pdev,  GRCBASE_MCP + 0x9c);
        if (val_rd & (1UL << 31))
        {
            break;
        }

        mm_wait(pdev, 5);
    }

    if(val_rd & (1UL << 31))
    {
        lm_status = LM_STATUS_SUCCESS;
    }
    else
    {
        DbgBreakMsg("Cannot get access to nvram interface.\n");

        lm_status = LM_STATUS_BUSY;
    }

    DbgMessage(pdev, INFORM, "acquire_split_alr() - %d END!\n", FUNC_ID(pdev) );

    return lm_status;
}

//Release split MCP access lock register
void
release_split_alr(
    lm_device_t *pdev)
{
    u32_t val = 0;

    DbgMessage(pdev, INFORM, "release_split_alr() - %d START!\n", FUNC_ID(pdev) );

    //This is only a sanity check, can remove later in free build.
    val= REG_RD(pdev, GRCBASE_MCP + 0x9c);
    DbgBreakIf(!(val & (1L << 31)));

    val = 0;

    //release mcpr_access_lock SPLIT register
    REG_WR(pdev,  GRCBASE_MCP + 0x9c, val);
    DbgMessage(pdev, INFORM, "release_split_alr() - %d END!\n", FUNC_ID(pdev) );
} /* release_nvram_lock */

/*******************************************************************************
 * Description:
 *         sends the mcp a keepalive to known registers
 * Return:
 ******************************************************************************/
lm_status_t lm_send_driver_pulse( lm_device_t* pdev )
{
    u32_t        msg_code   = 0;
    u32_t        drv_pulse  = 0;
    u32_t        mcp_pulse  = 0;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }

    if GET_FLAGS(pdev->params.test_mode, TEST_MODE_NO_MCP)
    {
        return LM_STATUS_SUCCESS ;
    }

    ++pdev->vars.drv_pulse_wr_seq;
    msg_code = pdev->vars.drv_pulse_wr_seq & DRV_PULSE_SEQ_MASK;
    if (GET_FLAGS(pdev->params.test_mode, TEST_MODE_DRIVER_PULSE_ALWAYS_ALIVE)
        || IS_DRIVER_PULSE_ALWAYS_ALIVE(pdev))
    {
        SET_FLAGS( msg_code, DRV_PULSE_ALWAYS_ALIVE ) ;
    }

    drv_pulse = msg_code;

    LM_SHMEM_WRITE(pdev,
                   OFFSETOF(shmem_region_t,
                   func_mb[FUNC_MAILBOX_ID(pdev)].drv_pulse_mb),msg_code);
    LM_SHMEM_READ(pdev,
                  OFFSETOF(shmem_region_t,
                  func_mb[FUNC_MAILBOX_ID(pdev)].mcp_pulse_mb),
                  &mcp_pulse);

    mcp_pulse&= MCP_PULSE_SEQ_MASK ;
    /* The delta between driver pulse and mcp response
     * should be 1 (before mcp response) or 0 (after mcp response)
    */
    if ((drv_pulse != mcp_pulse) &&
        (drv_pulse != ((mcp_pulse + 1) & MCP_PULSE_SEQ_MASK)))
    {
        DbgMessage(pdev, FATAL, "drv_pulse (0x%x) != mcp_pulse (0x%x)\n", drv_pulse, mcp_pulse );
        return LM_STATUS_FAILURE ;
    }
    DbgMessage(pdev, INFORMi , "Sent driver pulse cmd to MCP\n");
    return LM_STATUS_SUCCESS ;
}
/*******************************************************************************
 * Description:
 *         Set driver pulse to MCP to always alive
 * Return:
 ******************************************************************************/
void lm_driver_pulse_always_alive(struct _lm_device_t* pdev)
{
    if CHK_NULL(pdev)
    {
        return;
    }
    if GET_FLAGS(pdev->params.test_mode, TEST_MODE_NO_MCP)
    {
        return ;
    }
    // Reset the MCP pulse to always alive
    LM_SHMEM_WRITE( pdev,
                    OFFSETOF(shmem_region_t,
                    func_mb[FUNC_MAILBOX_ID(pdev)].drv_pulse_mb),
                    DRV_PULSE_ALWAYS_ALIVE );
}
// entry that represents a function in the loader objcet
typedef struct _lm_loader_func_entry_t
{
    u8_t b_loaded ;   // does this function was loaded
} lm_loader_func_entry_t ;
// global object represents MCP - should be one per CHIP (boards)
typedef struct _lm_loader_path_obj_t
{
    u32_t*                   lock_ctx ;               // reserved - lock object context (currently not in use)
    lm_loader_func_entry_t   func_arr[E1H_FUNC_MAX] ; // array of function entries
} lm_loader_path_obj_t ;

typedef struct _lm_loader_obj_t
{
    u8_t                     lock_owner ;             // is a function acquire the lock? (1 based)
    lm_loader_path_obj_t path_arr[MAX_PATH_NUM] ;
} lm_loader_obj_t ;

lm_loader_obj_t g_lm_loader  = {0};

// TRUE if the function is first on the port
#define LM_LOADER_IS_FIRST_ON_PORT(_pdev,_path_idx,_port_idx) \
 ( (FALSE == g_lm_loader.path_arr[_path_idx].func_arr[_port_idx+0].b_loaded) && \
   (FALSE == g_lm_loader.path_arr[_path_idx].func_arr[_port_idx+2].b_loaded) && \
   (FALSE == g_lm_loader.path_arr[_path_idx].func_arr[_port_idx+4].b_loaded) && \
   (FALSE == g_lm_loader.path_arr[_path_idx].func_arr[_port_idx+6].b_loaded) )

// TRUE if the function is last on the port
#define LM_LOADER_IS_LAST_ON_PORT(_pdev,_path_idx,_port_idx) \
  ( ( ( FUNC_ID(_pdev) == (_port_idx+0) ) ? TRUE : (FALSE == g_lm_loader.path_arr[_path_idx].func_arr[(_port_idx+0)].b_loaded) ) && \
    ( ( FUNC_ID(_pdev) == (_port_idx+2) ) ? TRUE : (FALSE == g_lm_loader.path_arr[_path_idx].func_arr[(_port_idx+2)].b_loaded) ) && \
    ( ( FUNC_ID(_pdev) == (_port_idx+4) ) ? TRUE : (FALSE == g_lm_loader.path_arr[_path_idx].func_arr[(_port_idx+4)].b_loaded) ) && \
    ( ( FUNC_ID(_pdev) == (_port_idx+6) ) ? TRUE : (_port_idx == 0)?(FALSE == g_lm_loader.path_arr[_path_idx].func_arr[6].b_loaded):(FALSE == g_lm_loader.path_arr[_path_idx].func_arr[7].b_loaded) ) )


#define LM_LOADER_IS_FIRST_ON_COMMON(_pdev,_path_idx) (LM_LOADER_IS_FIRST_ON_PORT(_pdev,_path_idx,0) && LM_LOADER_IS_FIRST_ON_PORT(_pdev,_path_idx,1))
#define LM_LOADER_IS_LAST_ON_COMMON(_pdev,_path_idx)  (LM_LOADER_IS_LAST_ON_PORT(_pdev,_path_idx,0)  && LM_LOADER_IS_LAST_ON_PORT(_pdev,_path_idx,1))

#define LM_LOADER_IS_FIRST_ON_CHIP(_pdev) (LM_LOADER_IS_FIRST_ON_COMMON(_pdev,0) && LM_LOADER_IS_FIRST_ON_COMMON(_pdev,1))
#define LM_LOADER_IS_LAST_ON_CHIP(_pdev)  (LM_LOADER_IS_LAST_ON_COMMON(_pdev,0)  && LM_LOADER_IS_LAST_ON_COMMON(_pdev,1))

// Accessed only with lock!
// TRUE if any device is currently locked
#define LM_LOADER_IS_LOCKED(_chip_idx) ( (FALSE != g_lm_loader.lock_owner) )

/*
 *Function Name:lm_loader_opcode_to_mcp_msg
 *
 *Parameters:
 *      b_lock - true if it is lock false if unlock
 *Description:
 *      LM_LOADER_OPCODE_XXX-->DRV_MSG_CODE_XXX
 *Returns:
 *
 */
static u32_t lm_loader_opcode_to_mcp_msg( lm_loader_opcode opcode, u8_t b_lock )
{
    u32_t mcp_msg = 0xffffffff ;

    switch(opcode)
    {
    case LM_LOADER_OPCODE_LOAD:
        mcp_msg = b_lock ? DRV_MSG_CODE_LOAD_REQ : DRV_MSG_CODE_LOAD_DONE ;
        break;
    case LM_LOADER_OPCODE_UNLOAD_WOL_EN:
        mcp_msg = b_lock ? DRV_MSG_CODE_UNLOAD_REQ_WOL_EN : DRV_MSG_CODE_UNLOAD_DONE ;
        break;
    case LM_LOADER_OPCODE_UNLOAD_WOL_DIS:
        mcp_msg = b_lock ? DRV_MSG_CODE_UNLOAD_REQ_WOL_DIS : DRV_MSG_CODE_UNLOAD_DONE ;
        break;
    case LM_LOADER_OPCODE_UNLOAD_WOL_MCP:
        mcp_msg = b_lock ? DRV_MSG_CODE_UNLOAD_REQ_WOL_MCP : DRV_MSG_CODE_UNLOAD_DONE ;
        break;
    default:
        DbgBreakIf(1) ;
        break;
    }
    return mcp_msg ;
}
/*
 *Function Name:mcp_resp_to_lm_loader_resp
 *
 *Parameters:
 *
 *Description:
 *      Translates mcp response to loader response FW_MSG_CODE_DRV_XXX->LM_LOADER_RESPONSE_XX
 *Returns:
 *
 */
lm_loader_response mcp_resp_to_lm_loader_resp( u32_t mcp_resp )
{
    lm_loader_response resp = LM_LOADER_RESPONSE_INVALID ;
    switch(mcp_resp)
    {
    case FW_MSG_CODE_DRV_LOAD_COMMON:
        resp = LM_LOADER_RESPONSE_LOAD_COMMON ;
        break;
    case FW_MSG_CODE_DRV_LOAD_COMMON_CHIP:
        resp = LM_LOADER_RESPONSE_LOAD_COMMON_CHIP ;
        break;
    case FW_MSG_CODE_DRV_LOAD_PORT:
        resp = LM_LOADER_RESPONSE_LOAD_PORT ;
        break;
    case FW_MSG_CODE_DRV_LOAD_FUNCTION:
        resp = LM_LOADER_RESPONSE_LOAD_FUNCTION ;
        break;
    case FW_MSG_CODE_DRV_UNLOAD_COMMON:
        resp = LM_LOADER_RESPONSE_UNLOAD_COMMON ;
        break;
    case FW_MSG_CODE_DRV_UNLOAD_PORT:
        resp = LM_LOADER_RESPONSE_UNLOAD_PORT ;
        break;
    case FW_MSG_CODE_DRV_UNLOAD_FUNCTION:
        resp = LM_LOADER_RESPONSE_UNLOAD_FUNCTION ;
        break;
    case FW_MSG_CODE_DRV_LOAD_DONE:
        resp = LM_LOADER_RESPONSE_LOAD_DONE ;
        break;
    case FW_MSG_CODE_DRV_UNLOAD_DONE:
        resp = LM_LOADER_RESPONSE_UNLOAD_DONE ;
        break;
    default:
        DbgMessage(NULL, FATAL, "mcp_resp=0x%x\n", mcp_resp );
        DbgBreakIf(1) ;
        break;
    }
    return resp ;
}
// TBD - should it be the only indication??
#define IS_MCP_ON(_pdev) ( TEST_MODE_NO_MCP != GET_FLAGS(_pdev->params.test_mode, TEST_MODE_NO_MCP ) )

/*
 *Function Name:lm_loader_lock
 *
 *Parameters:
 *
 *Description:
 *     sync loading/unloading of port/funciton
 *Returns:
 *
 */
lm_loader_response lm_loader_lock( lm_device_t* pdev, lm_loader_opcode opcode )
{
    u32_t              mcp_msg        = 0;
    u32_t              param          = 0;
    u32_t              fw_resp        = 0;
    lm_loader_response resp           = LM_LOADER_RESPONSE_INVALID ;
    lm_status_t        lm_status      = LM_STATUS_SUCCESS ;
    u32_t              wait_cnt       = 0;
    u32_t              wait_cnt_limit = 5000;
    const u32_t        feature_flags  = mm_get_feature_flags( pdev );
    const u8_t         is_suspend     = opcode & LM_LOADER_OPCODE_UNLOAD_SUSPEND;

    opcode &= LM_LOADER_OPCODE_MASK;
    if( IS_MCP_ON(pdev) )
    {
        mcp_msg = lm_loader_opcode_to_mcp_msg( opcode, TRUE ) ;

        // in case it is load (and not unload)
        // send mfw LFA param
        if ( DRV_MSG_CODE_LOAD_REQ == mcp_msg )
        {
            SET_FLAGS(param, DRV_MSG_CODE_LOAD_REQ_WITH_LFA );

            // in case BFS, set FORCE_LFA flag on
            if( GET_FLAGS( feature_flags, FEATURE_ETH_BOOTMODE_PXE )   ||
                GET_FLAGS( feature_flags, FEATURE_ETH_BOOTMODE_ISCSI ) ||
                GET_FLAGS( feature_flags, FEATURE_ETH_BOOTMODE_FCOE ) )
            {
                SET_FLAGS( param, DRV_MSG_CODE_LOAD_REQ_FORCE_LFA );
            }

        }
        else if (is_suspend)
        {
            SET_FLAGS( param, DRV_MSG_CODE_UNLOAD_NON_D3_POWER ); //temporary
        }

        //we do this with no locks because acquiring the loader lock may take a long time (e.g in case another function takes a
        //long time to initialize we will only get a response from the MCP when it's done). We don't need a lock because interrupts
        //are disabled at this point and we won't get any IOCTLs.
        lm_status = lm_mcp_cmd_send_recieve_non_atomic( pdev, lm_mcp_mb_header, mcp_msg, param, MCP_CMD_DEFAULT_TIMEOUT, &fw_resp ) ;
        if ( LM_STATUS_SUCCESS == lm_status )
        {
            resp = mcp_resp_to_lm_loader_resp(  fw_resp ) ;
            pdev->vars.b_in_init_reset_flow = TRUE;
        }
    }
    else // MCP_SIM
    {
        if( ERR_IF(PORT_ID(pdev) > 1) || ERR_IF(( FUNC_ID(pdev)) >= ARRSIZE(g_lm_loader.path_arr[PATH_ID(pdev)].func_arr)) )
        {
            DbgBreakMsg("Invalid PORT_ID/FUNC_ID\n");
            return resp ;
        }
        do
        {
            MM_ACQUIRE_LOADER_LOCK();
            if( LM_LOADER_IS_LOCKED(PATH_ID(pdev)) )
            {
                MM_RELEASE_LOADER_LOCK();
                mm_wait(pdev,20) ;
                DbgBreakIfAll( ++wait_cnt > wait_cnt_limit ) ;
            }
            else
            {
                // we'll release the lock when we are finish the work
                break;
            }
        }while(1) ;
        // Verify no one hold the lock, if so - it's a bug!
        DbgBreakIf( 0 != g_lm_loader.lock_owner ) ;

        // mark our current function id as owner
        g_lm_loader.lock_owner = FUNC_ID(pdev)+1 ;

        switch( opcode )
        {
        case LM_LOADER_OPCODE_LOAD:
            if( LM_LOADER_IS_FIRST_ON_CHIP(pdev) )
            {
                resp = LM_LOADER_RESPONSE_LOAD_COMMON_CHIP;
            }
            else if( LM_LOADER_IS_FIRST_ON_COMMON(pdev,PATH_ID(pdev)) )
            {
                resp = LM_LOADER_RESPONSE_LOAD_COMMON ;
            }
            else if( LM_LOADER_IS_FIRST_ON_PORT( pdev, PATH_ID(pdev), PORT_ID(pdev) ) )
            {
                resp = LM_LOADER_RESPONSE_LOAD_PORT ;
            }
            else
            {
                resp = LM_LOADER_RESPONSE_LOAD_FUNCTION ;
            }
            break;
        case LM_LOADER_OPCODE_UNLOAD_WOL_EN:
        case LM_LOADER_OPCODE_UNLOAD_WOL_DIS:
        case LM_LOADER_OPCODE_UNLOAD_WOL_MCP:
            if( LM_LOADER_IS_LAST_ON_COMMON(pdev,PATH_ID(pdev)) )
            {
                resp = LM_LOADER_RESPONSE_UNLOAD_COMMON ;
            }
            else if( LM_LOADER_IS_LAST_ON_PORT( pdev, PATH_ID(pdev), PORT_ID(pdev) ) )
            {
                resp = LM_LOADER_RESPONSE_UNLOAD_PORT ;
            }
            else
            {
                resp = LM_LOADER_RESPONSE_UNLOAD_FUNCTION ;
            }
            break;
        default:
            DbgBreakIf(1) ;
            break;
        }  // switch
        pdev->vars.b_in_init_reset_flow = TRUE;
        MM_RELEASE_LOADER_LOCK();
    } // MCP_SIM
    return resp ;
}
/*
 *Function Name:lm_loader_unlock
 *
 *Parameters:
 *
 *Description:
 *      sync loading/unloading of port/funciton
 *Returns:
 *
 */
lm_loader_response lm_loader_unlock( struct _lm_device_t *pdev, lm_loader_opcode opcode, OPTIONAL const u32_t* IN p_param )
{
    u32_t              mcp_msg     = 0 ;
    u32_t              param       = p_param ? (*p_param) : 0 ;
    lm_loader_response resp        = LM_LOADER_RESPONSE_INVALID ;
    u32_t              fw_resp     = 0 ;
    lm_status_t        lm_status   = LM_STATUS_SUCCESS ;
    u8_t               b_new_state = 0xff ;
    if CHK_NULL(pdev)
    {
        return resp ;
    }
    opcode &= LM_LOADER_OPCODE_MASK;
    if( IS_MCP_ON(pdev) )
    {
        mcp_msg   = lm_loader_opcode_to_mcp_msg( opcode, FALSE );
        //we do this with no locks because acquiring the loader lock may take a long time (e.g in case another function takes a
        //long time to initialize we will only get a response from the MCP when it's done). We don't need a lock because interrupts
        //are disabled at this point and we won't get any IOCTLs.
        lm_status = lm_mcp_cmd_send_recieve_non_atomic(pdev, lm_mcp_mb_header, mcp_msg, param, MCP_CMD_DEFAULT_TIMEOUT, &fw_resp ) ;
        if ( LM_STATUS_SUCCESS == lm_status )
        {
            resp = mcp_resp_to_lm_loader_resp( fw_resp ) ;
            pdev->vars.b_in_init_reset_flow = FALSE;
        }
    }
    else // MCP_SIM
    {
        MM_ACQUIRE_LOADER_LOCK();

        // Verify current function id is the owner
        DbgBreakIf( g_lm_loader.lock_owner != FUNC_ID(pdev)+1 ) ;

        switch( opcode )
        {
        case LM_LOADER_OPCODE_LOAD:
            b_new_state = TRUE ;
            resp        = LM_LOADER_RESPONSE_LOAD_DONE ;
            break;
        case LM_LOADER_OPCODE_UNLOAD_WOL_EN:
        case LM_LOADER_OPCODE_UNLOAD_WOL_DIS:
        case LM_LOADER_OPCODE_UNLOAD_WOL_MCP:
            b_new_state = FALSE  ;
            resp        = LM_LOADER_RESPONSE_UNLOAD_DONE ;
            break;
        default:
            DbgBreakIf(1) ;
            break;
        }  // switch
        // verify new state differs than current
        DbgBreakIf(g_lm_loader.path_arr[PATH_ID(pdev)].func_arr[FUNC_ID(pdev)].b_loaded == b_new_state);

        // assign new state
        g_lm_loader.path_arr[PATH_ID(pdev)].func_arr[FUNC_ID(pdev)].b_loaded = b_new_state ;

        // mark we don't own the lock anymore
        g_lm_loader.lock_owner = FALSE ;

        pdev->vars.b_in_init_reset_flow = FALSE;
        MM_RELEASE_LOADER_LOCK();
    } // MCP_SIM
    return resp ;
}

/* Used for simulating a mcp reset where the mcp no longer knows the state of the uploaded drivers... */
void lm_loader_reset ( struct _lm_device_t *pdev )
{
    mm_memset(&g_lm_loader, 0, sizeof(g_lm_loader));
}

/*
 *Function Name:lm_mcp_cmd_init
 *
 *Parameters:
 *
 *Description:
 *      initiate sequence of mb + verify boot code version
 *Returns:
 *
 */
lm_status_t lm_mcp_cmd_init( struct _lm_device_t *pdev)
{
    u32_t val        = 0 ;
    u32_t bc_rev     = 0 ;
    u32_t offset     = 0 ;
    u8_t  func_mb_id = 0;

    DbgMessage(pdev, INFORMi , "### mcp_cmd_init\n");

    if CHK_NULL(pdev)
    {
        return LM_STATUS_FAILURE ;
    }

    // we are on NO_MCP mode - nothing to do
    if( 0 != GET_FLAGS(pdev->params.test_mode, TEST_MODE_NO_MCP ) )
    {
        return LM_STATUS_SUCCESS ;
    }

    //validtae bc version
    bc_rev = LM_GET_BC_REV_MAJOR(pdev);

    if (bc_rev < BC_REV_SUPPORTED)
    {
        DbgMessage(pdev, FATAL,"bc version is less than 0x%x equal to 0x%x.\n", BC_REV_SUPPORTED, bc_rev );
        DbgBreakMsg("Please upgrade the bootcode version.\n");
        // TODO add event log
        return LM_STATUS_INVALID_PARAMETER;
    }

    // enable optic module verification according to BC version
    if (bc_rev >= REQ_BC_VER_4_VRFY_FIRST_PHY_OPT_MDL)
    {
        SET_FLAGS(pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_BC_SUPPORTS_OPT_MDL_VRFY);
    }

    if (bc_rev >= REQ_BC_VER_4_VRFY_SPECIFIC_PHY_OPT_MDL)
    {
        SET_FLAGS(pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_BC_SUPPORTS_DUAL_PHY_OPT_MDL_VRFY);
    }

    if (bc_rev >= REQ_BC_VER_4_VRFY_AFEX_SUPPORTED)
    {
        SET_FLAGS(pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_BC_SUPPORTS_AFEX);
    }

    if (bc_rev >= REQ_BC_VER_4_SFP_TX_DISABLE_SUPPORTED)
    {
        SET_FLAGS(pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_BC_SUPPORTS_SFP_TX_DISABLED);
    }

    if (bc_rev >= REQ_BC_VER_4_MT_SUPPORTED)
    {
        SET_FLAGS(pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_MT_SUPPORT);
    }

    // regular MCP mode
    func_mb_id = pdev->params.pfunc_mb_id;

    // read first seq number from shared memory
    offset = OFFSETOF(shmem_region_t, func_mb[func_mb_id].drv_mb_header);
    LM_SHMEM_READ(pdev, offset, &val);
    pdev->vars.fw_wr_seq = (u16_t)(val & DRV_MSG_SEQ_NUMBER_MASK);

    // read current mcp_pulse value
    offset = OFFSETOF(shmem_region_t,func_mb[func_mb_id].mcp_pulse_mb) ;
    LM_SHMEM_READ(pdev, offset ,&val);
    pdev->vars.drv_pulse_wr_seq = (u16_t)(val & MCP_PULSE_SEQ_MASK);

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_mcp_set_mf_bw(struct _lm_device_t *pdev, IN u8_t min_bw, IN u8_t max_bw)
{
    u32_t       minmax_param    = 0;
    u32_t       resp            = 0;
    lm_status_t lm_status       = LM_STATUS_SUCCESS;
    const u32_t bc_rev          = LM_GET_BC_REV_MAJOR(pdev);

    //if in no MCP mode, don't do anything
    if(!lm_is_mcp_detected(pdev))
    {
        DbgMessage(pdev, WARNmi, "No MCP detected.\n");
        return LM_STATUS_SUCCESS;
    }
    //if bootcode is less then REQ_BC_VER_4_SET_MF_BW, fail
    if( bc_rev < REQ_BC_VER_4_SET_MF_BW )
    {
        DbgMessage(pdev, WARNmi, "Invalid bootcode version.\n");
        return LM_STATUS_INVALID_PARAMETER;
    }
    //if not E2 or not MF mode, fail
    if(CHIP_IS_E1x(pdev) || !IS_MULTI_VNIC(pdev))
    {
        DbgMessage(pdev, WARNmi, "Device is E1/E1.5 or in SF mode.\n");
        return LM_STATUS_INVALID_PARAMETER;
    }
    //if the parameters are not valid, fail
    if (max_bw > 100)
    {
        DbgMessage(pdev, WARNmi, "Invalid parameters.\n");
        return LM_STATUS_INVALID_PARAMETER;
    }
    //build MCP command parameter from min_bw/max_bw
    //we use FUNC_MF_CFG_MIN_BW_SHIFT because the param structure is supposed to
    //be equivalent for this opcode and for the DCC opcode, but there is no define
    //for this opcode.
    ASSERT_STATIC(FUNC_MF_CFG_MIN_BW_MASK == DRV_MSG_CODE_SET_MF_BW_MIN_MASK);
    ASSERT_STATIC(FUNC_MF_CFG_MAX_BW_MASK == DRV_MSG_CODE_SET_MF_BW_MAX_MASK);
    minmax_param =  (min_bw << FUNC_MF_CFG_MIN_BW_SHIFT)|
                    (max_bw << FUNC_MF_CFG_MAX_BW_SHIFT);

    //call lm_mcp_cmd_send_recieve with DRV_MSG_CODE_SET_MF_BW opcode and the parameter
    lm_mcp_cmd_send_recieve(pdev, lm_mcp_mb_header, DRV_MSG_CODE_SET_MF_BW, minmax_param, MCP_CMD_DEFAULT_TIMEOUT, &resp);

    //make sure that the response is FW_MSG_CODE_SET_MF_BW_SENT
    if(resp != FW_MSG_CODE_SET_MF_BW_SENT)
    {
        DbgBreakIf(resp != FW_MSG_CODE_SET_MF_BW_SENT);
        return LM_STATUS_FAILURE;
    }

    //return what lm_mcp_cmd_send_recieve returned
    return lm_status;
}

/*
 *Function Name:lm_mcp_cmd_send
 *
 *Parameters:
 *
 *Description:
 *      send
 *Returns:
 *
 */
lm_status_t lm_mcp_cmd_send( struct _lm_device_t *pdev, lm_mcp_mb_type mb_type, u32_t drv_msg, u32_t param )
{
    u16_t*     p_seq      = NULL ;
    u32_t      offset     = 0 ;
    u32_t      drv_mask   = 0 ;
    const u8_t func_mb_id = pdev->params.pfunc_mb_id;

    DbgMessage(pdev, INFORMi , "### mcp_cmd_send mb_type=0x%x drv_msg=0x%x param=0x%x\n", mb_type, drv_msg, param );

    // we are on NO_MCP mode - nothing to do
    if( 0 != GET_FLAGS(pdev->params.test_mode, TEST_MODE_NO_MCP ) )
    {
        return LM_STATUS_SUCCESS ;
    }

    switch( mb_type )
    {
    case lm_mcp_mb_header:
        p_seq      = &pdev->vars.fw_wr_seq ;
        drv_mask   = DRV_MSG_SEQ_NUMBER_MASK ;
        offset     = OFFSETOF(shmem_region_t, func_mb[func_mb_id].drv_mb_header) ;
        /* Write the parameter to the mcp */
        if (p_seq)
        {
            LM_SHMEM_WRITE(pdev,OFFSETOF(shmem_region_t, func_mb[func_mb_id].drv_mb_param),param);
        }
        break;

    case lm_mcp_mb_pulse:
        p_seq      = &pdev->vars.drv_pulse_wr_seq ;
        drv_mask   = DRV_PULSE_SEQ_MASK ;
        offset     = OFFSETOF(shmem_region_t, func_mb[func_mb_id].mcp_pulse_mb) ;
        break;
    case lm_mcp_mb_param:
    default:
        break;
    }

    if CHK_NULL( p_seq )
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }

    // incremant sequence
    ++(*p_seq);

    // prepare message
    drv_msg |= ( (*p_seq) & drv_mask );

    LM_SHMEM_WRITE(pdev,offset,drv_msg);

    DbgMessage(pdev, INFORMi , "mcp_cmd_send: Sent driver load cmd to MCP at 0x%x\n", drv_msg);

    return LM_STATUS_SUCCESS ;
}

/*
 *Function Name:lm_mcp_cmd_response
 *
 *Parameters:
 *              TBD - add timeout value
 *Description:
 *              assumption - only one request can be sent simultaneously
 *Returns:
 *
 */
lm_status_t lm_mcp_cmd_response( struct _lm_device_t *pdev,
                                 lm_mcp_mb_type       mcp_mb_type,
                                 u32_t                drv_msg,
                                 u32_t                timeout,
                                 OUT u32_t*           p_fw_resp )
{
    u16_t*      p_seq      = NULL ;
    u32_t       offset     = 0 ;
    u32_t       drv_mask   = 0 ;
    u32_t       fw_mask    = 0 ;
    u32_t       cnt        = 0 ;
    u32_t       wait_itr   = 0 ;
    u32_t       resp_mask  = 0xffffffff ;
    lm_status_t lm_status  = LM_STATUS_SUCCESS ;
    const u8_t  func_mb_id = pdev->params.pfunc_mb_id;

    UNREFERENCED_PARAMETER_(timeout);

    DbgMessage(pdev, INFORMi, "### mcp_cmd_response mb_type=0x%x drv_msg=0x%x\n", mcp_mb_type, drv_msg );

    if ( CHK_NULL(p_fw_resp) )
    {
        return LM_STATUS_FAILURE ;
    }

    switch( mcp_mb_type )
    {
    case lm_mcp_mb_header:
        p_seq      = &pdev->vars.fw_wr_seq ;
        drv_mask   = DRV_MSG_SEQ_NUMBER_MASK ;
        fw_mask    = FW_MSG_SEQ_NUMBER_MASK ;
        resp_mask  = FW_MSG_CODE_MASK ;
        offset     = OFFSETOF(shmem_region_t, func_mb[func_mb_id].fw_mb_header) ;
        break;

        // TBD - is it needed ??
    case lm_mcp_mb_pulse:
        p_seq      = &pdev->vars.drv_pulse_wr_seq ;
        drv_mask   = DRV_PULSE_SEQ_MASK ;
        fw_mask    = MCP_PULSE_SEQ_MASK ;
        offset     = OFFSETOF(shmem_region_t, func_mb[func_mb_id].mcp_pulse_mb) ;
        break;

    case lm_mcp_mb_param:
    default:
        break;
    }

    if CHK_NULL( p_seq )
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }

    lm_status = LM_STATUS_TIMEOUT ;

    // Wait for reply 5 sec per unloading function
    //TODO exponential back off
    wait_itr = 240 * FW_ACK_NUM_OF_POLL * PORT_MAX * (u32_t)(IS_MULTI_VNIC(pdev) ? MAX_VNIC_NUM : 1);
    for(cnt = 0; cnt < wait_itr; cnt++)
    {
        mm_wait(pdev, FW_ACK_POLL_TIME_MS * 50);

        LM_SHMEM_READ(pdev, offset, p_fw_resp);

        if(( (*p_fw_resp) & fw_mask) == ( (*p_seq) & drv_mask))
        {
            lm_status = LM_STATUS_SUCCESS ;
            break;
        }
    }

    *p_fw_resp = (*p_fw_resp & resp_mask);

    return lm_status ;
}

lm_status_t lm_mcp_cmd_send_recieve_non_atomic( struct _lm_device_t *pdev,
                                             lm_mcp_mb_type       mcp_mb_type,
                                             u32_t                drv_msg,
                                             u32_t                param,
                                             u32_t                timeout,
                                             OUT u32_t*           p_fw_resp )
{
    lm_status_t lm_status = LM_STATUS_FAILURE;
    u32_t       val       = 0;

    lm_status = lm_mcp_cmd_send( pdev, mcp_mb_type, drv_msg, param) ;

    if( LM_STATUS_SUCCESS != lm_status )
    {
        val = lm_mcp_check(pdev);
        DbgMessage(pdev, FATAL, "mcp_cmd_send_and_recieve: mcp_cmd_send drv_msg=0x%x failed. lm_status=0x%x mcp_check=0x%x\n", drv_msg, lm_status, val);
        DbgBreakMsg("mcp_cmd_send_and_recieve: mcp_cmd_send failed!\n");
        return lm_status;
    }

    DbgMessage(pdev, INFORMi , "mcp_cmd_send_and_recieve: Sent driver cmd=0x%x to MCP\n",  drv_msg );

    lm_status = lm_mcp_cmd_response( pdev, mcp_mb_type, drv_msg, timeout, p_fw_resp ) ;

    if( LM_STATUS_SUCCESS != lm_status )
    {
        val = lm_mcp_check(pdev);
        DbgMessage(pdev, FATAL, "mcp_cmd_send_and_recieve: mcp_cmd_response drv_msg=0x%x failed. lm_status=0x%x mcp_check=0x%x\n", drv_msg, lm_status, val);
        DbgBreakMsg("mcp_cmd_send_and_recieve: mcp_cmd_response failed!\n");
        return lm_status;
    }

    DbgMessage(pdev, INFORMi , "mcp_cmd_send_and_recieve: Got response 0x%x from MCP\n", *p_fw_resp );

    return LM_STATUS_SUCCESS;
}

/*
 *Function Name:lm_mcp_cmd_send_recieve
 *
 *Parameters:
 *
 *Description:
 *
 *Returns: lm_status_t
 *
 */
lm_status_t lm_mcp_cmd_send_recieve( struct _lm_device_t *pdev,
                                     lm_mcp_mb_type       mcp_mb_type,
                                     u32_t                drv_msg,
                                     u32_t                param,
                                     u32_t                timeout,
                                     OUT u32_t*           p_fw_resp )
{
    lm_status_t lm_status = LM_STATUS_SUCCESS ;

    MM_ACQUIRE_MCP_LOCK(pdev);

    lm_status = lm_mcp_cmd_send_recieve_non_atomic(pdev, mcp_mb_type, drv_msg, param, timeout, p_fw_resp);

    MM_RELEASE_MCP_LOCK(pdev);

    return lm_status ;
}


// check if mcp program counter is advancing, In case it doesn't return the value in case it does, return 0
u32_t lm_mcp_check( struct _lm_device_t *pdev)
{
    static u32_t const offset = MCP_REG_MCPR_CPU_PROGRAM_COUNTER ;
    u32_t              reg    = 0 ;
    u32_t              i      = 0 ;

    reg = REG_RD(pdev, offset);

    for( i = 0; i<4; i++ )
    {
        if( REG_RD(pdev, offset) != reg )
        {
            return 0; // OK
        }
    }
    return reg; // mcp is hang on this value as program counter!
}

/**lm_mcp_cli_idx_to_drv_cap_flag
 * Get the flag to set in drv_capabilities_flag for a given LM
 * client.
 *
 * @param cli_id the LM client index.
 *
 * @return u32_t the appropriate flag for cli_id, or 0 if there
 *         is no matching flag.
 */
static u32_t lm_mcp_cli_idx_to_drv_cap_flag(IN const lm_cli_idx_t cli_id)
{
    switch(cli_id)
    {
    case LM_CLI_IDX_NDIS:
        return DRV_FLAGS_CAPABILITIES_LOADED_L2;
    case LM_CLI_IDX_ISCSI:
        return DRV_FLAGS_CAPABILITIES_LOADED_ISCSI;
    case LM_CLI_IDX_FCOE:
        return DRV_FLAGS_CAPABILITIES_LOADED_FCOE;
    case LM_CLI_IDX_MAX://may happen for UM clients that have no matching LM client, such as diag.
        return 0;
    case LM_CLI_IDX_FWD://fallthrough - this client has no bind/unbind flow and no matching UM client
    case LM_CLI_IDX_OOO://fallthrough - this client has no bind/unbind flow and no matching UM client
    default:
        DbgBreakMsg("Invalid client type");
        return 0;
    }
}

void lm_mcp_indicate_client_imp(struct _lm_device_t *pdev, IN const lm_cli_idx_t cli_id, IN const u8_t b_bind )
{
    const u32_t drv_cap_client = lm_mcp_cli_idx_to_drv_cap_flag(cli_id);
    const u32_t func_mb_id = FUNC_MAILBOX_ID(pdev);
    const u32_t shmem_offset = OFFSETOF(shmem2_region_t, drv_capabilities_flag[func_mb_id]);
    u32_t       drv_cap_shmem  = 0;

    if (CHIP_IS_E1x(pdev) ||
        !LM_SHMEM2_HAS(pdev, drv_capabilities_flag))
    {
        return;
    }

    if (0 == drv_cap_client)
    {
        //this is a client that does not require updating the SHMEM
        return;
    }

    LM_SHMEM2_READ(pdev, shmem_offset, &drv_cap_shmem);

    if( b_bind )
    {
        SET_FLAGS( drv_cap_shmem, drv_cap_client );
    }
    else
    {
        RESET_FLAGS( drv_cap_shmem, drv_cap_client );
    }

    LM_SHMEM2_WRITE(pdev, shmem_offset, drv_cap_shmem);
}

void lm_mcp_indicate_client_bind(struct _lm_device_t *pdev, IN const lm_cli_idx_t cli_id)
{
    lm_mcp_indicate_client_imp(pdev, cli_id, TRUE);
}

void lm_mcp_indicate_client_unbind(struct _lm_device_t *pdev, IN const lm_cli_idx_t cli_id)
{
    lm_mcp_indicate_client_imp(pdev, cli_id, FALSE);
}
