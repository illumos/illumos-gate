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
 *    02/05/07 Alon Elhanani    Inception.
 ******************************************************************************/

#include "lm5710.h"


// converts index to DMAE command register name define
u32_t lm_dmae_idx_to_go_cmd( u8_t idx )
{
    u32_t ret = 0 ;
    switch( idx )
    {
    case 0:  ret = DMAE_REG_GO_C0;  break;
    case 1:  ret = DMAE_REG_GO_C1;  break;
    case 2:  ret = DMAE_REG_GO_C2;  break;
    case 3:  ret = DMAE_REG_GO_C3;  break;
    case 4:  ret = DMAE_REG_GO_C4;  break;
    case 5:  ret = DMAE_REG_GO_C5;  break;
    case 6:  ret = DMAE_REG_GO_C6;  break;
    case 7:  ret = DMAE_REG_GO_C7;  break;
    case 8:  ret = DMAE_REG_GO_C8;  break;
    case 9:  ret = DMAE_REG_GO_C9;  break;
    case 10: ret = DMAE_REG_GO_C10; break;
    case 11: ret = DMAE_REG_GO_C11; break;
    case 12: ret = DMAE_REG_GO_C12; break;
    case 13: ret = DMAE_REG_GO_C13; break;
    case 14: ret = DMAE_REG_GO_C14; break;
    case 15: ret = DMAE_REG_GO_C15; break;
    default:
        break;
    }
    return ret ;
}

/**
 * @defgroup LockingPolicy Locking Policy
 * @{ 
 */

/**lm_locking_policy_hwlock_id_for_resource 
 * Return the hwlock for some protected resource.
 * 
 * 
 * @param resource the resource
 * 
 * @return u8_t the hwlock for the given resource.
 */
static u8_t lm_dmae_locking_policy_hwlock_id_for_resource(struct _lm_device_t* pdev, IN const u32_t resource)
{
    switch (resource)
    {
    case LM_PROTECTED_RESOURCE_DMAE_TOE:
        {
            return HW_LOCK_RESOURCE_PORT0_DMAE_COPY_CMD + PORT_ID(pdev);
        }
        break;
    default:
        {
            DbgBreakMsg("HW lock for resource does not exist.\n");
            return LM_DMAE_NO_HWLOCK;
        }
        break;
    }
}


lm_status_t lm_dmae_locking_policy_create(  struct _lm_device_t* pdev,
                                            IN const u32_t resource, 
                                            IN const lm_dmae_locking_policy_type_t type, 
                                            OUT lm_dmae_locking_policy_t* policy)
{
    mm_mem_zero(policy, sizeof(lm_dmae_locking_policy_t));

    if (type > LM_DMAE_LOCKING_POLICY_TYPE_NONE)
    {
        mm_init_lock(pdev, &policy->spinlock);
    }

    if (type == LM_DMAE_LOCKING_POLICY_TYPE_INTER_PF)
    {
        policy->hwlock = lm_dmae_locking_policy_hwlock_id_for_resource(pdev, resource);
    }

    return LM_STATUS_SUCCESS;
}

#ifdef _VBD_
/*28158 is 'No IRQL was saved into '_Param_(2)->spinlock.irql'. The IRQL is saved by the call to mm_acquire_lock.*/
#pragma warning(push)
#pragma warning(disable:28158)

__drv_maxIRQL(DISPATCH_LEVEL)
__drv_at(context->locking_policy->spinlock.irql, __drv_savesIRQL)
__drv_setsIRQL(DISPATCH_LEVEL)
#endif
lm_status_t lm_dmae_locking_policy_lock(struct _lm_device_t* pdev, lm_dmae_locking_policy_t* locking_policy)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    lm_status = mm_acquire_lock(&locking_policy->spinlock);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg("Failed to acquire spinlock.\n");
        return lm_status;
    }

    if (LM_DMAE_NO_HWLOCK != locking_policy->hwlock)
    {
        lm_status = lm_hw_lock(pdev, locking_policy->hwlock, TRUE);
        if (LM_STATUS_SUCCESS != lm_status)
        {
            DbgBreakMsg("Failed to acquire HW lock.\n");

            lm_status = mm_release_lock(&locking_policy->spinlock);
            if (LM_STATUS_SUCCESS != lm_status)
            {
                DbgBreakMsg("Failed to roll-back after locking failure.\n");
                return lm_status;
            }

            return lm_status;
        }
    }

    return lm_status;
}
#ifdef _VBD_
#pragma warning(pop)

/*28157 is 'The IRQL in '_Param_(2)->spinlock.irql' was never restored'. The IRQL is restored by the call to mm_release_lock.*/
#pragma warning(push)
#pragma warning(disable:28157)
#if defined(NTDDI_WIN8)
_IRQL_requires_(DISPATCH_LEVEL)
__drv_at(context->locking_policy->spinlock.irql, __drv_restoresIRQL )
#endif
#endif
lm_status_t lm_dmae_locking_policy_unlock(struct _lm_device_t* pdev, lm_dmae_locking_policy_t* locking_policy)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    if (LM_DMAE_NO_HWLOCK != locking_policy->hwlock)
    {
        lm_status = lm_hw_unlock(pdev, locking_policy->hwlock);
        if (LM_STATUS_SUCCESS != lm_status)
        {
            DbgBreakMsg("Failed to release HW lock.\n");
            return lm_status;
        }
    }

    lm_status = mm_release_lock(&locking_policy->spinlock);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg("Failed to release spinlock.\n");

        if (LM_DMAE_NO_HWLOCK != locking_policy->hwlock)
        {
            //try to re-acquire the HW lock, so at least we'll be in a consistent state.
            lm_status = lm_hw_lock(pdev, locking_policy->hwlock, TRUE);
            if (LM_STATUS_SUCCESS != lm_status)
            {
                DbgBreakMsg("Failed to roll-back after release failure.\n"); //This is a double-fault. Don't try to recover.
                return lm_status;
            }
        }

        return lm_status;
    }


    return lm_status;
}


#ifdef _VBD_
#pragma warning(pop)
#endif
/**
 * @}
 */

/**
 * @defgroup DMAE_Operation DMAE operation 
 * @{ 
 */

/**lm_dmae_opcode
 * Construct a DMAE command opcode according to HSI and given 
 * parameters. 
 * 
 * 
 * @param pdev the device to use 
 * @param source the source of the operation
 * @param dest the destination of the operation
 * @param b_complete_to_host TRUE if the completion value of the 
 *                           operation whould be written to host
 *                           memory, FALSE if to GRC.
 * @param b_resume_prev TRUE if this operation should resume a 
 *                      previous operation, FALSE if the source
 *                      address should be used.
 * @param b_change_endianity TRUE if the operation should 
 *                           byte-swap its data
 * 
 * @return u32_t an opcode according to HSI rules.
 */
static u32_t 
lm_dmae_opcode( struct _lm_device_t* pdev,
                IN const lm_dmae_address_t source, 
                IN const lm_dmae_address_t dest, 
                IN const u8_t b_complete_to_host, 
                IN const u8_t b_resume_prev,
                IN const u8_t b_change_endianity)
{
    u32_t opcode = 0;

    opcode |= ((source.type == LM_DMAE_ADDRESS_GRC)?1:0) <<DMAE_CMD_SRC_SHIFT;
    opcode |= ((dest.type == LM_DMAE_ADDRESS_GRC)?2:1) <<DMAE_CMD_DST_SHIFT;
    opcode |= (!b_complete_to_host)<< DMAE_CMD_C_DST_SHIFT;
    opcode |= 1 << DMAE_CMD_C_TYPE_ENABLE_SHIFT;
    opcode |= 0 << DMAE_CMD_C_TYPE_CRC_ENABLE_SHIFT;
    opcode |= (b_change_endianity ? 3:2)<<DMAE_CMD_ENDIANITY_SHIFT;
    opcode |=  PORT_ID(pdev) << DMAE_CMD_PORT_SHIFT;
    opcode |= 0 << DMAE_CMD_CRC_RESET_SHIFT ;
    opcode |= (!b_resume_prev) << DMAE_CMD_SRC_RESET_SHIFT;
    opcode |= 1 << DMAE_CMD_DST_RESET_SHIFT;
    opcode |= VNIC_ID(pdev) << DMAE_CMD_E1HVN_SHIFT;

    return opcode;
}

/**lm_dmae_command_set_block
 * Set the source, destination and length of a DMAE command HSI 
 * structure. 
 * 
 * 
 * @param pdev the device to use
 * @param command the command to initialize
 * @param source the source of the operation
 * @param dest the destination of the operation
 * @param length the length, in DWORDS, of the operation
 */
static void 
lm_dmae_command_set_block(  struct _lm_device_t* pdev,
                            struct dmae_cmd* command,
                            IN const lm_dmae_address_t source,
                            IN const lm_dmae_address_t dest,
                            IN const u16_t length/*in DWORDS*/)
{
    u64_t source_offset = lm_dmae_address_native_offset(&source);
    u64_t dest_offset = lm_dmae_address_native_offset(&dest);

    command->src_addr_hi = U64_HI(source_offset);
    command->src_addr_lo = U64_LO(source_offset);

    command->dst_addr_hi = U64_HI(dest_offset);
    command->dst_addr_lo = U64_LO(dest_offset);

    command->len = length;
}


/**lm_dmae_initialize_command_by_block
 * Initialize an HSI DMAE command struct according to a driver 
 * DMAE block data structure. 
 *  
 * @param pdev the device to use
 * @param context the context of the operation
 * @param command the command to initialize
 * @param block the DMAE block according to which the command 
 *              will be initialized
 * @param completion_value the completion value that should be 
 *                         written to the context's completion
 *                         word when this command completes.
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other 
 *         failure value on failure.
 */
static lm_status_t 
lm_dmae_initialize_command_by_block(struct _lm_device_t* pdev,
                                    lm_dmae_context_t* context,
                                    struct dmae_cmd* command, 
                                    IN lm_dmae_block_t* block,
                                    IN const u32_t completion_value)
{
    command->opcode = lm_dmae_opcode(pdev, block->source, block->dest, TRUE, FALSE, context->change_endianity);

    lm_dmae_command_set_block(pdev, command, block->source, block->dest, block->length);
    
    command->comp_addr_hi = context->completion_word_paddr.as_u32.high;
    command->comp_addr_lo = context->completion_word_paddr.as_u32.low;

    command->comp_val = completion_value;

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_dmae_operation_create(   struct _lm_device_t* pdev,
                                        IN const lm_dmae_address_t source,
                                        IN const lm_dmae_address_t dest,
                                        IN const u16_t length,
                                        IN const u8_t replicate_source,
                                        IN const u8_t le32_swap,
                                        IN lm_dmae_context_t* context,
                                        OUT lm_dmae_operation_t* operation)
{
    lm_status_t lm_status = LM_STATUS_FAILURE;

    DbgBreakIf(LM_DMAE_MODE_SINGLE_BLOCK != context->mode);
    DbgBreakIf(0 == context->completion_word_paddr.as_u64);

    if( (LM_DMAE_ADDRESS_HOST_VIRT == source.type) && (LM_DMAE_ADDRESS_HOST_VIRT == dest.type) )
    {
        DbgBreakMsg("the intermediate buffer can be used for source or destination but not both.\n");
        return LM_STATUS_INVALID_PARAMETER;
    }

    mm_mem_zero(operation, sizeof(lm_dmae_operation_t));

    operation->mode = LM_DMAE_MODE_SINGLE_BLOCK;
    operation->b_replicate_source = replicate_source;
    operation->le32_swap = le32_swap;
    operation->context = context;
    operation->b_sync = TRUE;

    operation->blocks[0].source = source;
    operation->blocks[0].dest = dest;
    operation->blocks[0].length = length;

    lm_status = lm_dmae_initialize_command_by_block(pdev, 
                                                    operation->context, 
                                                    &operation->main_cmd, 
                                                    &operation->blocks[0], 
                                                    DMAE_COMPLETION_VAL);
    if (LM_STATUS_SUCCESS != lm_status) 
    {
        return lm_status;
    }

    return lm_status;
}

/**lm_dmae_initialize_sgl_loader_command
 * Initialize the DMAE command HSI struct for an SGL loader 
 * command. 
 * 
 * @param pdev the device to use
 * @param operation the operation which the command is a part of
 * @param command the command to initialize
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other 
 *         failure value on failure.
 */
static lm_status_t 
lm_dmae_initialize_sgl_loader_command(  struct _lm_device_t* pdev,
                                        lm_dmae_operation_t* operation,
                                        struct dmae_cmd* command)
{
    lm_dmae_address_t source = lm_dmae_address( operation->executer_paddr.as_u64 ,LM_DMAE_ADDRESS_HOST_PHYS);
    lm_dmae_address_t dest = lm_dmae_address(   DMAE_REG_CMD_MEM + operation->context->executer_channel*DMAE_CMD_SIZE*sizeof(u32_t), 
                                                LM_DMAE_ADDRESS_GRC);


    command->opcode = lm_dmae_opcode(pdev, source, dest, FALSE, TRUE, operation->context->change_endianity);

    lm_dmae_command_set_block(pdev, command, source, dest, sizeof(struct dmae_cmd) / sizeof(u32_t));

    // Special handling for E1 HW DMAE operation: we give here the size we are writing MINUS 1,
    // since when 'no reset' is on (src address is 0 ), the DMAE advance pointer by
    // length + 1, so in order to comply, we send length-1
    // when relevant data struct we send is not bigger than lnegth-1,
    // in this specific case, we send struct size 14 when relevant data is 9
    // so even when we send 13 as length, it's ok, since we copy 13, 9 is intersting
    // and next time DMAE will read from +14 which is good for us
    if( CHIP_IS_E1(pdev) )
    {
        --command->len;
    }


    command->comp_addr_lo =  lm_dmae_idx_to_go_cmd(operation->context->executer_channel)  / 4;
    command->comp_addr_hi = 0;

    command->comp_val = DMAE_GO_VALUE;

    return LM_STATUS_SUCCESS;
}

lm_dmae_operation_t* lm_dmae_operation_create_sgl(  struct _lm_device_t* pdev,
                                                    IN const u8_t b_sync,
                                                    IN lm_dmae_context_t* context)
{
    lm_dmae_operation_t* operation = NULL;
    lm_address_t operation_phys_addr = {{0}};
    lm_address_t executer_phys_addr = {{0}};

    DbgBreakIf(LM_DMAE_MODE_SGL != context->mode);
    DbgBreakIf(0 == context->completion_word_paddr.as_u64);

    operation = mm_alloc_phys_mem(pdev, sizeof(lm_dmae_operation_t), &operation_phys_addr, PHYS_MEM_TYPE_NONCACHED, LM_RESOURCE_COMMON);

    if (CHK_NULL(operation))
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return NULL;
    }

    mm_mem_zero(operation, sizeof(lm_dmae_operation_t));

    operation->mode = LM_DMAE_MODE_SGL;
    operation->context = context;
    operation->b_sync = b_sync;

    executer_phys_addr = operation_phys_addr;
    LM_INC64(&executer_phys_addr, OFFSETOF(lm_dmae_operation_t, executer_cmd[0]));
    operation->executer_paddr = executer_phys_addr;

    lm_dmae_initialize_sgl_loader_command(pdev, operation, &operation->main_cmd);
    return operation;
}

lm_status_t lm_dmae_operation_add_sge(  struct _lm_device_t* pdev,
                                        lm_dmae_operation_t* operation,
                                        IN const lm_dmae_address_t source,
                                        IN const lm_dmae_address_t dest,
                                        IN const u16_t length)
{
    u8_t last_sge_idx = 0;
    u8_t new_sge_idx = 0;
    struct dmae_cmd* last_sge = NULL;
    lm_status_t lm_status = LM_STATUS_FAILURE;

    if( (LM_DMAE_ADDRESS_HOST_VIRT == source.type) && (LM_DMAE_ADDRESS_HOST_VIRT == dest.type) )
    {
        DbgBreakMsg("the intermediate buffer can be used for source or destination but not both.\n");
        return LM_STATUS_INVALID_PARAMETER;
    }

    new_sge_idx = operation->next_free_block;

    if (new_sge_idx >= ARRSIZE(operation->blocks))
    {
        DbgBreakMsg("Too many SGEs in DMAE operation");
        return LM_STATUS_INVALID_PARAMETER;
    }

    if (0 != operation->next_free_block) 
    {
        last_sge_idx = operation->next_free_block-1;
        last_sge = &operation->executer_cmd[last_sge_idx];

        SET_FLAGS(last_sge->opcode, 1<<DMAE_CMD_C_DST_SHIFT);

        last_sge->comp_addr_lo = lm_dmae_idx_to_go_cmd(operation->context->main_channel) / 4;
        last_sge->comp_addr_hi = 0;

        last_sge->comp_val = DMAE_GO_VALUE;
    }

    operation->blocks[new_sge_idx].source = source;
    operation->blocks[new_sge_idx].dest = dest;
    operation->blocks[new_sge_idx].length = length;

    lm_status = lm_dmae_initialize_command_by_block(pdev, 
                                                    operation->context, 
                                                    &operation->executer_cmd[new_sge_idx], 
                                                    &operation->blocks[new_sge_idx], 
                                                    DMAE_SGL_COMPLETION_VAL);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    operation->next_free_block++;

    return lm_status;
}

void lm_dmae_operation_clear_all_sges(lm_dmae_operation_t* operation)
{
    DbgBreakIf(LM_DMAE_MODE_SGL != operation->mode);

    operation->next_free_block = 0;
}

u8_t lm_dmae_operation_is_complete(IN lm_dmae_operation_t* operation)
{
    return operation->context->completion_word != operation->command_id;
}

/**lm_dmae_operation_wait
 * Wait for an operation to finish. Note that this function 
 * busy-waits and does not yield the CPU, so it can be used in 
 * high IRQLs. 
 * 
 * @param pdev the device to use
 * @param operation the operation to wait for
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, 
 *         LM_STATUS_TIMEOUT if the operation did not finish in
 *         reasonable time, LM_STATUS_ABORTED if reset is in
 *         progress.
 */
static lm_status_t 
lm_dmae_operation_wait(struct _lm_device_t* pdev, lm_dmae_operation_t* operation)
{
    u32_t wait_cnt = 0;
    u32_t wait_cnt_limit = 10000 * pdev->vars.clk_factor;
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    while (!lm_dmae_operation_is_complete(operation))
    {
        mm_wait(pdev, 20);
        if (++wait_cnt > wait_cnt_limit)
        {
            DbgMessage(pdev,
                       FATAL,
                      "Timed-out waiting for operation %d to complete. Completion word is 0x%x expected 0x%x.\n",(u64_t)operation->command_id,
                       (u64_t)operation->context->completion_word,
                       (u64_t)operation->context->completion_value);
            lm_status = LM_STATUS_TIMEOUT;
            break;
        }

        if (lm_reset_is_inprogress(pdev))
        {
            lm_status = LM_STATUS_ABORTED;
            break;
        }
    }

    if (LM_STATUS_SUCCESS != lm_status)
    {
        if (LM_STATUS_SUCCESS != lm_dmae_context_reset(operation->context))
        {
            DbgBreakMsg("Unable to clean up after a DMAE error. DMAE context is unusable.\n");
        }
    }

    return lm_status;
}

/**
 * @}
 */

/**
 * @defgroup DMAE_Context DMAE Context
 * @{ 
 */

lm_dmae_context_t* lm_dmae_context_create(  struct _lm_device_t* pdev,
                                            IN const u8_t channel_idx, 
                                            IN lm_dmae_locking_policy_t* locking_policy, 
                                            IN const u8_t change_endianity)
{
    lm_dmae_context_t* context = NULL;
    lm_address_t context_paddr = {{0}};
    lm_address_t completion_word_paddr = {{0}};
    lm_address_t intermediate_buffer_paddr = {{0}};

    context = mm_alloc_phys_mem(pdev, sizeof(lm_dmae_context_t), &context_paddr, PHYS_MEM_TYPE_NONCACHED, LM_RESOURCE_COMMON);

    if (CHK_NULL(context))
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return NULL;
    }

    context->mode = LM_DMAE_MODE_SINGLE_BLOCK;
    context->main_channel = channel_idx;
    context->executer_channel = (u8_t)-1;
    context->locking_policy = locking_policy;
    context->change_endianity = change_endianity;
    context->next_command_id = 1;

#ifndef __BIG_ENDIAN
    // if we changed the endianity, the completion word should be swapped
    context->completion_value = context->change_endianity ? DMAE_COMPLETION_VAL_SWAPPED : DMAE_COMPLETION_VAL ;
#else
    context->completion_value = DMAE_COMPLETION_VAL;
#endif // !__BIG_ENDIAN

    context->completion_word = context->completion_value;

    completion_word_paddr = context_paddr;
    LM_INC64(&completion_word_paddr, OFFSETOF(lm_dmae_context_t, completion_word));
    context->completion_word_paddr = completion_word_paddr;

    intermediate_buffer_paddr = context_paddr;
    LM_INC64(&intermediate_buffer_paddr, OFFSETOF(lm_dmae_context_t, intermediate_buffer));
    context->intermediate_buffer_paddr = intermediate_buffer_paddr;

    return context;
}


lm_dmae_context_t* lm_dmae_context_create_sgl(  struct _lm_device_t* pdev,
                                                IN const u8_t loader_channel_idx,
                                                IN const u8_t executer_channel_idx,
                                                IN lm_dmae_locking_policy_t* locking_policy,
                                                IN const u8_t change_endianity)
{
    lm_dmae_context_t* context = NULL;
    lm_address_t context_paddr = {{0}};
    lm_address_t completion_word_paddr = {{0}};
    lm_address_t intermediate_buffer_paddr = {{0}};

    context = mm_alloc_phys_mem(pdev, sizeof(lm_dmae_context_t), &context_paddr, PHYS_MEM_TYPE_NONCACHED, LM_RESOURCE_COMMON);

    if (CHK_NULL(context))
    {
        DbgMessage(NULL, FATAL, "Failed to allocate SGL DMAE context.\n");
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return NULL;
    }

    context->mode = LM_DMAE_MODE_SGL;
    context->main_channel = loader_channel_idx;
    context->executer_channel = executer_channel_idx;
    context->locking_policy = locking_policy;
    context->change_endianity = change_endianity;
    context->next_command_id = 1;

    context->completion_value = DMAE_SGL_COMPLETION_VAL;

    context->completion_word = context->completion_value;

    completion_word_paddr = context_paddr;
    LM_INC64(&completion_word_paddr, OFFSETOF(lm_dmae_context_t, completion_word));
    context->completion_word_paddr = completion_word_paddr;

    intermediate_buffer_paddr = context_paddr;
    LM_INC64(&intermediate_buffer_paddr, OFFSETOF(lm_dmae_context_t, intermediate_buffer));
    context->intermediate_buffer_paddr = intermediate_buffer_paddr;

    return context;
}

/**lm_dmae_context_reset
 * Bring a DMAE context to a known-good state. This function 
 * must be used on an acquired context. It should be used if for 
 * some reason the context is left in an invalid state (e.g an 
 * error occured during a DMAE transaction using this context). 
 * 
 * @param context the context to reset.
 * 
 * @return lm_status LM_STATUS_SUCCESS on success, some other 
 *         failure code on failure.
 */
lm_status_t lm_dmae_context_reset(lm_dmae_context_t *context)
{
    context->completion_word = context->completion_value;

    return LM_STATUS_SUCCESS;
}

#ifdef _VBD_
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_at(context->locking_policy->spinlock.irql, __drv_savesIRQL)
__drv_setsIRQL(DISPATCH_LEVEL)
#endif
lm_status_t lm_dmae_context_acquire(struct _lm_device_t* pdev, lm_dmae_context_t *context)
{
    return lm_dmae_locking_policy_lock(pdev, context->locking_policy);
}

#ifdef _VBD_
#if defined(NTDDI_WIN8)
_IRQL_requires_(DISPATCH_LEVEL)
__drv_at(context->locking_policy->spinlock.irql, __drv_restoresIRQL )
#endif
#endif
lm_status_t lm_dmae_context_release(struct _lm_device_t* pdev, lm_dmae_context_t *context)
{
    return lm_dmae_locking_policy_unlock(pdev, context->locking_policy);
}

lm_status_t lm_dmae_context_execute(struct _lm_device_t* pdev, lm_dmae_context_t *context, lm_dmae_operation_t *operation)
{
    lm_status_t lm_status = LM_STATUS_FAILURE;

    lm_status = lm_dmae_context_acquire(pdev,context);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg("Failed to acquire context.\n");
        return lm_status;
    }

    lm_status = lm_dmae_context_execute_unsafe(pdev, context,operation);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        DbgMessage(pdev, FATAL, "lm_dmae_context_execute_unsafe returned %d\n", lm_status);
        if (LM_STATUS_ABORTED != lm_status)
        {
            //we'll let the caller decide if DbgBreak should be called when lm_reset_is_inprogress interrupts a DMAE operation.
            DbgBreakMsg("DMAE execution failed.\n");
        }

        //don't return - release the context first.
    }

    //no need to check the return code, since we can't really recover from 
    //not being able to release the context anyway.
    lm_dmae_context_release(pdev,context);

    return lm_status;
}

/**lm_dmae_context_advance_command_id
 * DMAE context has a 'private' variable of the next command ID 
 * to use. This function returns the next valid value for this 
 * context's command ID in a thread-safe manner. 
 *  
 * @param context the context to change
 * 
 * @return u32_t the new command ID for the context.
 */
static u32_t 
lm_dmae_context_advance_command_id(lm_dmae_context_t* context)
{
    u32_t cmd_id = mm_atomic_inc(&context->next_command_id);

    if ((0 == cmd_id)||
        (context->completion_value == cmd_id))
    {
        cmd_id = mm_atomic_inc(&context->next_command_id);
    }

    return cmd_id;
}

// Copy the loader command to DMAE - need to do it before every call - for source/dest address no reset...
// Due to parity checks error, we write zero for last 5 registers of command (9-13, zero based)
static void 
lm_dmae_post_command(   IN struct _lm_device_t*   pdev,
                        IN const u8_t             idx_cmd,
                        IN const struct dmae_cmd* command  )
{
    u8_t i = 0 ;

    DbgBreakIf(IS_VFDEV(pdev));

    if ( CHK_NULL(pdev) || CHK_NULL(command))
    {
        return;
    }

    // verify address is not NULL
    if ERR_IF( ( ( 0 == command->dst_addr_lo ) && ( command->dst_addr_hi == command->dst_addr_lo ) ) ||
               ( ( 0 == command->src_addr_lo ) && ( command->src_addr_hi == command->src_addr_lo ) ) )

    {
            DbgMessage(pdev,
                       FATAL,
                       "lm_dmae_command: idx_cmd=%d opcode = 0x%x opcode_iov=0x%x len=0x%x src=0x%x:%x dst=0x%x:%x\n",
                       idx_cmd,
                       (int)command->opcode,
                       (int)command->opcode_iov,
                       (int)command->len,
                       (int)command->src_addr_hi,
                       (int)command->src_addr_lo,
                       (int)command->dst_addr_hi,
                       (int)command->dst_addr_lo );
            DbgBreakMsg("lm_dmae_command: Trying to write/read to NULL address\n");
    }

    // Copy the command to DMAE - need to do it before every call - for source/dest address no reset...
    // Due to parity checks error, we write zero for last 5 registers of command (9-13, zero based)
    for( i = 0 ; i < 14 ; i++ )
    {
        REG_WR( pdev,
                DMAE_REG_CMD_MEM+(idx_cmd*DMAE_CMD_SIZE*sizeof(u32_t))+i*sizeof(u32_t),
                i < 9 ? *(((u32_t*)command)+i) : 0 ) ;
    }

    REG_WR(pdev, lm_dmae_idx_to_go_cmd(idx_cmd), DMAE_GO_VALUE) ;
}


/**lm_dmae_context_execute_single_block
 * Execute an SGL operation without acquiring the 
 * context. 
 * 
 * 
 * @param pdev the device to use
 * @param context the context that executes the operation
 * @param operation the operation to execute
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, 
 *         LM_STATUS_TIMEOUT if the operation did not finish in
 *         reasonable time, some other failure value on failure.
 */
lm_status_t lm_dmae_context_execute_sgl(struct _lm_device_t* pdev, lm_dmae_context_t *context, lm_dmae_operation_t *operation)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    context->completion_word = operation->command_id;

    lm_dmae_post_command(pdev, context->main_channel, &operation->main_cmd);

    if (operation->b_sync)
    {
        lm_status = lm_dmae_operation_wait(pdev, operation);
        if (LM_STATUS_SUCCESS != lm_status)
        {
            DbgMessage(pdev, FATAL, "lm_dmae_operation_wait returned %d\n", lm_status);
        }
    }

    return lm_status;
}

/**lm_dmae_context_execute_sub_operation
 * lm_dmae_context_execute_single_block splits every command to 
 * sub-operations, each with a length that is less the the HW 
 * limit for DMAE lengths. This function executes one of these 
 * sub-operations. 
 * Note: This function modifies operation->main_cmd. 
 * 
 * 
 * @param pdev the device to use
 * @param context the context that executes the operation
 * @param operation the operation to execute
 * @param src_offset the source offset of the current 
 *                   sub-operation. This value overrides
 *                   whatever is stored in operation
 * @param dst_offset the destination offset of the current 
 *                   sub-operation. This value overrides
 *                   whatever is stored in operation
 * @param length the length of the current sub-operation. This 
 *               value overrides whatever is stored in operation
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, 
 *         LM_STATUS_TIMEOUT if the operation did not finish in
 *         reasonable time, some other failure value on failure.
 */
static lm_status_t
lm_dmae_context_execute_sub_operation(  struct _lm_device_t* pdev, 
                                        lm_dmae_context_t *context,
                                        lm_dmae_operation_t *operation,   
                                        IN const u64_t src_offset, 
                                        IN const u64_t dst_offset, 
                                        IN const u16_t length)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    lm_address_t src_addr = {{0}};
    lm_address_t dst_addr = {{0}};

    u16_t i = 0;

    src_addr.as_u64 = src_offset;
    dst_addr.as_u64 = dst_offset;

    switch (operation->blocks[0].source.type)
    {
        case LM_DMAE_ADDRESS_GRC://fallthrough
        case LM_DMAE_ADDRESS_HOST_PHYS:
            {
                operation->main_cmd.src_addr_hi = src_addr.as_u32.high;
                operation->main_cmd.src_addr_lo = src_addr.as_u32.low;
            }
            break;
        case LM_DMAE_ADDRESS_HOST_VIRT: //for virtual source addresses we use the intermediate buffer.
            {
                operation->main_cmd.src_addr_hi = context->intermediate_buffer_paddr.as_u32.high;
                operation->main_cmd.src_addr_lo = context->intermediate_buffer_paddr.as_u32.low;
    
                mm_memcpy( &context->intermediate_buffer[0], src_addr.as_ptr, length*sizeof(u32_t));
                if (operation->le32_swap)
                {
                    for (i=0; i < length; ++i)
                    {    
                        context->intermediate_buffer[i] = mm_cpu_to_le32(context->intermediate_buffer[i]);
                    }
                }
            }
            break;
        default:
            {
                DbgBreakMsg("Unknown source address type for DMAE operation.\n");
                return LM_STATUS_INVALID_PARAMETER;
            }
            break;
    }

    switch (operation->blocks[0].dest.type)
    {
        case LM_DMAE_ADDRESS_GRC://fallthrough
        case LM_DMAE_ADDRESS_HOST_PHYS:
            {
                operation->main_cmd.dst_addr_hi = dst_addr.as_u32.high;
                operation->main_cmd.dst_addr_lo = dst_addr.as_u32.low;
            }
            break;
        case LM_DMAE_ADDRESS_HOST_VIRT: //for virtual source addresses we use the intermediate buffer.
            {
                operation->main_cmd.dst_addr_hi = context->intermediate_buffer_paddr.as_u32.high;
                operation->main_cmd.dst_addr_lo = context->intermediate_buffer_paddr.as_u32.low;
            }
            break;
        default:
            {
                DbgBreakMsg("Unknown destination address type for DMAE operation.\n");
                return LM_STATUS_INVALID_PARAMETER;
            }
            break;
    }

    DbgBreakIf(context->completion_word != context->completion_value);

    context->completion_word = operation->command_id;

    operation->main_cmd.len = length;

    lm_dmae_post_command(pdev, context->main_channel, &operation->main_cmd);

    lm_status = lm_dmae_operation_wait(pdev, operation);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    DbgBreakIf(context->completion_word != context->completion_value);

    if (operation->blocks[0].dest.type == LM_DMAE_ADDRESS_HOST_VIRT)
    {
        mm_memcpy( dst_addr.as_ptr, &context->intermediate_buffer[0], length*sizeof(u32_t));
    }

    return lm_status;
}

/**lm_dmae_context_execute_single_block
 * Execute a single-block operation without acquiring the 
 * context. 
 * 
 * 
 * @param pdev the device to use
 * @param context the context that executes the operation
 * @param operation the operation to execute
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, 
 *         LM_STATUS_TIMEOUT if the operation did not finish in
 *         reasonable time, some other failure value on failure.
 */
static lm_status_t 
lm_dmae_context_execute_single_block(struct _lm_device_t* pdev, lm_dmae_context_t *context, lm_dmae_operation_t *operation)
{
    lm_status_t        lm_status       = LM_STATUS_SUCCESS ;
    u16_t              length_current  = 0 ;
    u16_t              i               = 0 ;
    u32_t              offset          = 0 ;
    lm_address_t       src_addr        = {{0}};
    lm_address_t       dst_addr        = {{0}};
    u64_t              src_addr_split  = 0;
    u64_t              dst_addr_split  = 0;


    const u16_t        length_limit    = (operation->blocks[0].dest.type != LM_DMAE_ADDRESS_GRC) ? min( DMAE_MAX_READ_SIZE, DMAE_MAX_RW_SIZE(pdev) ) : DMAE_MAX_RW_SIZE(pdev) ;
    u16_t        cnt_split       = 0; // number of chunks of splits
    u16_t        length_mod      = 0;

    DbgBreakIf(0 == length_limit); //to avoid divide-by-0. can't do static assert because it depends on CHIP_ID

    cnt_split = operation->blocks[0].length / length_limit;
    length_mod = operation->blocks[0].length % length_limit;

    src_addr.as_u64 = lm_dmae_address_native_offset(&operation->blocks[0].source);
    src_addr_split = src_addr.as_u64;

    dst_addr.as_u64 = lm_dmae_address_native_offset(&operation->blocks[0].dest);
    dst_addr_split  = dst_addr.as_u64;


    DbgBreakIf(IS_VFDEV(pdev));

    if ( CHK_NULL(pdev) || ERR_IF( 0 == operation->blocks[0].length ) )
    {
       return LM_STATUS_INVALID_PARAMETER ;
    }

    for( i = 0; i <= cnt_split; i++ )
    {
        offset = length_limit*i ;

        if( !operation->b_replicate_source )
        {
            if (operation->blocks[0].source.type == LM_DMAE_ADDRESS_GRC)
            {
                src_addr_split = src_addr.as_u64 + offset;
            }
            else
            {
                src_addr_split = src_addr.as_u64 + (offset*4);
            }
        }

        if (operation->blocks[0].dest.type == LM_DMAE_ADDRESS_GRC)
        {
            dst_addr_split = dst_addr.as_u64 + offset;
        }
        else
        {
            dst_addr_split = dst_addr.as_u64 + (offset*4);
        }

        length_current = (cnt_split==i)? length_mod : length_limit ;

        // might be zero on last iteration
        if( 0 != length_current )
        {
            lm_status = lm_dmae_context_execute_sub_operation(pdev, context, operation, src_addr_split, dst_addr_split, length_current);
            if( LM_STATUS_SUCCESS != lm_status )
            {
                return lm_status ;
            }
        }
    }
    
    return lm_status ;
}

lm_status_t lm_dmae_context_execute_unsafe(struct _lm_device_t* pdev, lm_dmae_context_t *context, lm_dmae_operation_t *operation)
{
    lm_status_t lm_status = LM_STATUS_FAILURE;

    if (context->completion_word != context->completion_value)
    {
        return LM_STATUS_BUSY;
    }
    
    DbgBreakIf(context->mode != operation->mode);

    operation->command_id = lm_dmae_context_advance_command_id(context);

    switch (context->mode)
    {
    case LM_DMAE_MODE_SINGLE_BLOCK:
        {
            lm_status = lm_dmae_context_execute_single_block(pdev, context, operation);
        }
        break;
    case LM_DMAE_MODE_SGL:
        {
            lm_status = lm_dmae_context_execute_sgl(pdev, context, operation);
        }
        break;
    default:
        {
            DbgBreakMsg("Unknown context mode.\n");
            lm_status = LM_STATUS_INVALID_PARAMETER;
        }
        break;
    }

    return lm_status;
}

/**
 * @}
 */


/**
 * @defgroup DMAE_Address DMAE address
 * @{ 
 */

u64_t lm_dmae_address_native_offset(IN const lm_dmae_address_t* address)
{
    switch (address->type)
    {
    case LM_DMAE_ADDRESS_GRC:
        {
            return address->u.grc_offset / sizeof(u32_t);
        }
        break;
    case LM_DMAE_ADDRESS_HOST_PHYS:
        {
            return address->u.host_phys_address.as_u64;
        }
        break;
    case LM_DMAE_ADDRESS_HOST_VIRT:
        {
            lm_address_t temp;
            temp.as_ptr = address->u.host_virt_address;
            return temp.as_u64;
        }
        break;
    default:
        {
            DbgBreakMsg("Unknown address type.\n");
            return 0;
        }
        break;

    }
}

lm_dmae_address_t lm_dmae_address(IN const u64_t offset, IN const lm_dmae_address_type_t type)
{
    lm_dmae_address_t address = {{0}};

    address.type = type;

    switch (type)
    {
    case LM_DMAE_ADDRESS_GRC:
        {
            ASSERT_STATIC(sizeof(address.u.grc_offset) == sizeof(u32_t));
            DbgBreakIf (offset > MAX_VARIABLE_VALUE(address.u.grc_offset));

            address.u.grc_offset = (u32_t)offset;
        }
        break;
    case LM_DMAE_ADDRESS_HOST_PHYS:
        {
            address.u.host_phys_address.as_u64 = offset;
        }
        break;
    case LM_DMAE_ADDRESS_HOST_VIRT:
        {
            lm_address_t temp;
            temp.as_u64 = offset;

            address.u.host_virt_address = temp.as_ptr;
        }
        break;
    default:
        {
            DbgBreakMsg("Unknown address type.\n");
        }
        break;
    }

    return address;
}

/**
 * @}
 */


/**
 * @defgroup DMAE_User DMAE users API
 * @{ 
 */

lm_dmae_context_info_t* lm_dmae_get(struct _lm_device_t* pdev, IN const lm_dmae_type_t type)
{
    ASSERT_STATIC(LM_DMAE_MAX_TYPE == ARRSIZE(pdev->dmae_info.ctx_arr));

    if (type >= LM_DMAE_MAX_TYPE) 
    {
        DbgBreakMsg("Invalid DMAE user index.\n");
        return NULL;
    }

    return &pdev->dmae_info.ctx_arr[type];
}

static const u32_t MAX_GRC_OFFSET = 0x00400000; //GRC space is 4MB for 57710-578xx

lm_status_t lm_dmae_reg_wr(struct _lm_device_t* pdev, lm_dmae_context_t* context, void* source_vaddr, u32_t dest_offset, u16_t length, u8_t replicate_source, u8_t le32_swap)
{
    lm_address_t source_offset = {{0}};
    lm_dmae_address_t source = {{0}};
    lm_dmae_address_t dest = lm_dmae_address(dest_offset, LM_DMAE_ADDRESS_GRC);
    lm_dmae_operation_t operation = {0};
    lm_status_t lm_status = LM_STATUS_FAILURE;

    DbgBreakIf(dest_offset > MAX_GRC_OFFSET); //make sure dest_offset is a valid GRC offset

    source_offset.as_ptr = source_vaddr;
    source = lm_dmae_address(source_offset.as_u64, LM_DMAE_ADDRESS_HOST_VIRT);

    lm_status = lm_dmae_operation_create(pdev, source, dest, length, replicate_source, le32_swap, context, &operation);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    lm_status = lm_dmae_context_execute(pdev, context, &operation);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    return lm_status;
}

lm_status_t lm_dmae_reg_wr_phys(struct _lm_device_t* pdev, lm_dmae_context_t* context, lm_address_t source_paddr, u32_t dest_offset, u16_t length)
{
    lm_dmae_address_t source =lm_dmae_address(source_paddr.as_u64, LM_DMAE_ADDRESS_HOST_PHYS);
    lm_dmae_address_t dest = lm_dmae_address(dest_offset, LM_DMAE_ADDRESS_GRC);
    lm_dmae_operation_t operation = {0};
    lm_status_t lm_status = LM_STATUS_FAILURE;

    DbgBreakIf(dest_offset > MAX_GRC_OFFSET); //make sure dest_offset is a valid GRC offset

    lm_status = lm_dmae_operation_create(pdev, source, dest, length, FALSE, FALSE, context, &operation);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    lm_status = lm_dmae_context_execute(pdev, context, &operation);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    return lm_status;
}

lm_status_t lm_dmae_reg_rd(struct _lm_device_t* pdev, lm_dmae_context_t* context, u32_t source_offset, void* dest_vaddr, u16_t length, u8_t le32_swap)
{
    lm_address_t dest_offset = {{0}};
    lm_dmae_address_t source = lm_dmae_address(source_offset, LM_DMAE_ADDRESS_GRC);
    lm_dmae_address_t dest = {{0}};
    lm_dmae_operation_t operation = {0};
    lm_status_t lm_status = LM_STATUS_FAILURE;

    DbgBreakIf(source_offset > MAX_GRC_OFFSET); //make sure source_offset is a valid GRC offset

    dest_offset.as_ptr = dest_vaddr;
    dest = lm_dmae_address(dest_offset.as_u64, LM_DMAE_ADDRESS_HOST_VIRT);

    lm_status = lm_dmae_operation_create(pdev, source, dest, length, FALSE, le32_swap, context, &operation);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    lm_status = lm_dmae_context_execute(pdev, context, &operation);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    return lm_status;
}

lm_status_t lm_dmae_copy_phys_buffer_unsafe(struct _lm_device_t* pdev, lm_dmae_context_t* context, lm_address_t source_paddr, lm_address_t dest_paddr, u16_t length)
{
    lm_dmae_address_t source = lm_dmae_address(source_paddr.as_u64, LM_DMAE_ADDRESS_HOST_PHYS);
    lm_dmae_address_t dest = lm_dmae_address(dest_paddr.as_u64, LM_DMAE_ADDRESS_HOST_PHYS);
    lm_dmae_operation_t operation = {0};
    lm_status_t lm_status = LM_STATUS_FAILURE;

    lm_status = lm_dmae_operation_create(pdev, source, dest, length, FALSE, FALSE, context, &operation);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    lm_status = lm_dmae_context_execute_unsafe(pdev, context, &operation);
    if (LM_STATUS_ABORTED == lm_status)
    {
        //if the operation failed due to lm_reset_is_inprogress, treat it as success. 
        lm_status = LM_STATUS_SUCCESS;
    }

    if (LM_STATUS_SUCCESS != lm_status) 
    {
        return lm_status;
    }

    return lm_status;
}


/**
 * @}
 */

