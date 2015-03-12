/*******************************************************************************
 *
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
 * Module Description:
 *
 *
 * History:
 *    02/05/07 Alon Elhanani    Inception.
 ******************************************************************************/

/**@file hw_dmae.h
 *
 * A module encapsulating the DMAE HW block. 
 * 
 * Use cases for this module include:
 * 
 * - 'Single-block' DMA operations
 *   Single-block DMA operations are composed of a single HW
 *   command that contains a GRC/PCI source, a GRC/PCI
 *   destination and length. Single-block DMA operations are
 *   locked from before writing the command to the HW registers,
 *   until after the DMAE writes the completion word to the
 *   appropriate location in host memory. Single-block DMA
 *   operations use a single DMAE channel.
 * 
 * - SGL DMA operations
 *   SGL DMA operations use two DMAE channels - one called a
 *   'loader' and one called an 'executer'. The operation is
 *   composed of a single HW command called a 'loader' that
 *   uses the loader channel, and multiple HW commands called
 *   'executers' that use the executer channel. The loader
 *   command is configured so that whenever it is executed,
 *   it loads and executes the next pending executer command.
 *   Executer commands are configured so that whenever they
 *   complete they execute the loader command, except the last
 *   executer command that simply writes the completion word
 *   to the appropriate location in host memory.
 *   SGL DMA operations lock both channels from the time the
 *   loader first executes, until the last executer completes.
 * 
 * - SGL DMA operations in asynchronous mode (a.k.a post/poll)
 *   SGL DMA operations in asynchronous mode only lock the
 *   context for the time required to load the loader command
 *   to the HW registers (called the 'post' stage). Afterwords
 *   they return immediately and unlock both channels. Then a
 *   DMAE user may query the context's state to check if the
 *   last executer command has already finished (the 'poll' stage).
 *   The context is locked only for the duration of a single
 *   query at a time. Note that a DMAE user may not use the
 *   context until the query returns with a code that indicates
 *   the context is available.
 */

#ifndef _LM_DMAE_H
#define _LM_DMAE_H

#include "mm.h"

// defines
#define DMAE_SGL_MAX_COMMANDS       5         // max number of commands in a DMAE SGL (just as a limit - can be defined other number)
#define DMAE_GO_VALUE               0x1         // DMAE spec
#define DMAE_SGL_COMPLETION_VAL     0xD0AE      // local completion word value (for SGL)
#define DMAE_COMPLETION_VAL         0xD1AE      // local completion word value with edianity mode 2 (for regular command)
#define DMAE_COMPLETION_VAL_SWAPPED 0xAED10000  // local completion word value with edianity mode 3

#define DMAE_CMD_SIZE               14          // size of DMAE command structure

#define DMAE_MAX_RW_SIZE_E1        0x0400 // maximun size (in DW) of read/write commands (HW limit) - for  (chip id<=5710)

// up to 0xffff actually limit is 64KB-1 so 0x2000 dwords is 32KB
#define DMAE_MAX_RW_SIZE_NEW       0x2000 // maximun size of read/write commands (HW limit) - for E1.5 and above (chip id>5710)
#define DMAE_MAX_READ_SIZE         0x80   // due to a HW issue in E1, E1.5 A0, pci to pci and grc to pci operations are limited to 128 DWORDS

// max value for static allocations
#define DMAE_MAX_RW_SIZE_STATIC    max(DMAE_MAX_RW_SIZE_E1,DMAE_MAX_RW_SIZE_NEW)

#define DMAE_MAX_RW_SIZE(pdev)    (CHIP_IS_E1(pdev) ?  DMAE_MAX_RW_SIZE_E1 : DMAE_MAX_RW_SIZE_NEW)


#define DMAE_STATS_GET_PORT_CMD_IDX(port_num,cmd_idx) DMAE_STATS_PORT_##port_num##_CMD_IDX_##cmd_idx

#define DMAE_STATS_PORT_0_CMD_IDX_0       DMAE_CMD_DRV_0
#define DMAE_STATS_PORT_0_CMD_IDX_1       DMAE_CMD_DRV_1
#define DMAE_STATS_PORT_1_CMD_IDX_0       DMAE_CMD_DRV_2
#define DMAE_STATS_PORT_1_CMD_IDX_1       DMAE_CMD_DRV_3
#define DMAE_WB_ACCESS_FUNCTION_CMD(_idx) DMAE_CMD_DRV_4+(_idx)
#define DMAE_COPY_PCI_PCI_PORT_0_CMD      DMAE_CMD_DRV_12
#define DMAE_COPY_PCI_PCI_PORT_1_CMD      DMAE_CMD_DRV_13

#define LM_DMAE_INTERMEDIATE_BUFFER_SIZE DMAE_MAX_RW_SIZE_NEW

#define LM_DMAE_NO_HWLOCK 0

typedef enum _lm_dmae_protected_resource_t
{
    LM_PROTECTED_RESOURCE_DMAE_STATS = 0,
    LM_PROTECTED_RESOURCE_DMAE_TOE,
    LM_PROTECTED_RESOURCE_DMAE_DEFAULT,
    LM_MAX_PROTECTED_RESOURCE
}lm_dmae_protected_resource_t;

typedef enum _lm_dmae_type_t
{
    LM_DMAE_STATS,
    LM_DMAE_TOE,
    LM_DMAE_DEFAULT,
    LM_DMAE_MAX_TYPE
}lm_dmae_type_t;

typedef enum _lm_dmae_address_type_t
{
    LM_DMAE_ADDRESS_HOST_VIRT,
    LM_DMAE_ADDRESS_HOST_PHYS,
    LM_DMAE_ADDRESS_GRC
}lm_dmae_address_type_t;

typedef enum _lm_dmae_mode_t
{
    LM_DMAE_MODE_SGL,
    LM_DMAE_MODE_SINGLE_BLOCK
}lm_dmae_mode_t;

typedef enum _lm_dmae_locking_policy_type_t
{
    LM_DMAE_LOCKING_POLICY_TYPE_NONE,
    LM_DMAE_LOCKING_POLICY_TYPE_PER_PF,
    LM_DMAE_LOCKING_POLICY_TYPE_INTER_PF
}lm_dmae_locking_policy_type_t;

/**
 * An encapsulation of the synchronization method for resource. 
 * The type of locking policy depends on the synchronization 
 * requirements for the protected resource (in this design's 
 * case - the DMAE context) 
 *  
 *  - No synchronization  
 *  Use this type of policy when there is no contention on the
 *  protected resource. No locking will take place.
 *  - per-PF synchronization
 *  synchronizes access to the protected resource among users in
 *  the same PF, but not between multiple PFs. Use this type of
 *  policy when the protected resource is per-PF.
 *  - inter-PF synchronization
 *  synchronizes access to the protected resource among multiple
 *  users that may be running in the contexts of multiple PFs.
 *  Use this type of policy when the protected resource is
 *  shared among multiple PFs.
 *  
 *  @ingroup LockingPolicy
 */
typedef struct _lm_dmae_locking_policy_t
{
    mm_spin_lock_t spinlock; /**< an opaque context for the spinlock that's used by this locking policy*/
    u32_t hwlock; /**< the HW lock used by this locking policy*/
}lm_dmae_locking_policy_t;

/**
 * A source/target address for a DMA operation. 
 *  
 * @ingroup DMAE_Address 
 */
typedef struct _lm_dmae_address_t
{
    /**The offset of this address (either a virtual address, a 
    physical address or a GRC offset) */
    union { 
        u32_t grc_offset;
        void* host_virt_address;
        lm_address_t host_phys_address;
    } u;

    /**The type of this address*/
    lm_dmae_address_type_t type;
}lm_dmae_address_t;


/**
 * @ingroup DMAE_Operation
 */
typedef struct _lm_dmae_block_t
{
    lm_dmae_address_t source;
    lm_dmae_address_t dest;
    u16_t length;
}lm_dmae_block_t;

/**
 * An aggregation of one or more DMAE channels that are used by 
 * the driver for the same function with the same configuration. 
 * A context may be a non-SGL context (in which case it is 
 * associated with a single DMAE channel) or an SGL context (in 
 * which case it is associated with two DMAE channels). Every 
 * context may have one current operation. 
 *  
 * @ingroup DMAE_Context 
 */
typedef struct _lm_dmae_context_t
{
    /**The type of the context (SGL or single-block)   */
    lm_dmae_mode_t mode;

    /** - single-block context: the index of the DMAE channel for
     *  this context
     *  - SGL context: the index of the loader DMAE channel for this
     *    context*/
    u8_t main_channel;

    /**SGL context: the index of the executer DMAE channel for this 
     * context. 
     * This field has no meaning for single-block contexts */ 
    u8_t executer_channel;

    u8_t change_endianity;

    u32_t next_command_id;

    lm_dmae_locking_policy_t* locking_policy;

    /**This physical address of the field completion_word   */
    lm_address_t completion_word_paddr;

    /**The memory location where the DMAE writes the completion 
     * value when an operation is finished on this context.*/ 
    volatile u32_t completion_word;

    /**The value that the DMAE writes to completion_word when an 
     * operation is finished on this context. Endianess note: The 
     * completion value that's written as part of the command is 
     * always the same, but the value that's later written to 
     * memory depends on the endianness mode of the command, so 
     * this value represents the value that's written by the DMAE 
     * and not the value that's used by the VBD. */ 
    u32_t completion_value;

    /**This physical address of the beginnning of 
     * intermediate_buffer*/ 
    lm_address_t intermediate_buffer_paddr;

    /**An intermediate buffer for DMAE operations that use virtual 
     * addresses - data is DMA'd to/from this buffer and then 
     * memcpy'd to/from the virtual address*/ 
    u32_t intermediate_buffer[LM_DMAE_INTERMEDIATE_BUFFER_SIZE];
}lm_dmae_context_t;


/**
 * A single logical DMAE transfer, which may be either a 
 * single-block transfer (in which case it has a single source 
 * and a single target) or an SGL transfer (in which case it is 
 * composed of multiple SGEs, each having a single source and a 
 * single target). An SGL operation may be synchronous or 
 * asynchronous - executing a synchronous DMAE operation results
 * in a wait until the operation completes, while an 
 * asynchronous operation may be posted to the hardware without 
 * waiting for its completion. 
 *  
 * @ingroup DMAE_Operation 
 */
typedef struct _lm_dmae_operation_t
{
    /**The type of this operation (SGL or single-block)*/ 
    lm_dmae_mode_t mode;

    /**The context of this operation.*/ 
    lm_dmae_context_t* context;

/**TRUE if the source is a block of length DMAE_MAX_RW_SIZE_E1 /
 * DMAE_MAX_RW_SIZE_NEW and the destination is larger. In this 
 * case the source block will be duplicated as many times as 
 * required to fill the destination block.*/ 
    u8_t b_replicate_source; 

    u8_t le32_swap;

    /**SGL: TRUE if this operation is synchronous. This field has 
     * no meaning for single-block operations. */ 
    u8_t b_sync;
    
    u32_t command_id;
        
    /**SGL: The loader command for this operation
     *SINGLE_BLOCK: The command for this operation*/
    struct dmae_cmd main_cmd;

    /**The next available entry in blocks[] and executer_cmdp[] */
    u8_t next_free_block;

    /**The block/blocks of this operation*/ 
    lm_dmae_block_t blocks[DMAE_SGL_MAX_COMMANDS];

    /**SGL: The physical address of the beginning of executer_cmd. 
     * This field has no meaning for single-block operations.   */
    lm_address_t executer_paddr;

    /**SGL: The executer HSI commands for this operation. This 
     * field has no meaning for single-block operations. */ 
    struct dmae_cmd executer_cmd[DMAE_SGL_MAX_COMMANDS]; //these must be consecutive, so they can't be a part of the blocks[] array. 
}lm_dmae_operation_t;

typedef struct _lm_dmae_context_info_t 
{
    lm_dmae_context_t* context;
    lm_dmae_locking_policy_t locking_policy;
}lm_dmae_context_info_t ;

typedef struct _lm_dmae_info_t
{
    lm_dmae_context_info_t ctx_arr[LM_DMAE_MAX_TYPE];
}lm_dmae_info_t;

//------------------ Locking Policy ------------------//

/**lm_dmae_locking_policy_create
 * Create a locking policy
 *  
 * @param resource The ID of the protected resource. This ID is 
 *                 used to determine which synchronization
 *                 objects will be used by the policy.
 * @param type the type of this locking policy 
 * @param policy the policy to initialize. 
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other 
 *         failure value on failure.
 */
lm_status_t lm_dmae_locking_policy_create(  struct _lm_device_t* pdev,
                                            IN const u32_t resource, 
                                            IN const lm_dmae_locking_policy_type_t type, 
                                            OUT lm_dmae_locking_policy_t* policy);

/**lm_dmae_locking_policy_lock
 * Use a locking policy to lock a resource, acquiring whatever 
 * spinlock or hardware lock required. 
 * 
 * @param locking_policy the policy to use
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other 
 *         failure code on failure.
 */
#ifdef _VBD_
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_at(locking_policy->spinlock.irql, __drv_savesIRQL)
__drv_setsIRQL(DISPATCH_LEVEL)
#endif
lm_status_t lm_dmae_locking_policy_lock(struct _lm_device_t* pdev, lm_dmae_locking_policy_t* locking_policy);

/**lm_dmae_locking_policy_unlock
 * Use a locking policy to unlock a resource, releasing 
 * whatever spinlock or hardware lock required. 
 *  
 * @param locking_policy the policy to use
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other 
 *         failure code on failure
 */
#ifdef _VBD_
#if defined(NTDDI_WIN8)
_IRQL_requires_(DISPATCH_LEVEL)
__drv_at(locking_policy->spinlock.irql, __drv_restoresIRQL )
#endif
#endif
lm_status_t lm_dmae_locking_policy_unlock(struct _lm_device_t* pdev, lm_dmae_locking_policy_t* locking_policy);



//------------------ DMAE Context ------------------//

/**lm_dmae_context_create
 * Create a non-SGL DMA context, using the given policy for 
 * synchronization. 
 *  
 * @param channel_idx the DMAE channel index that is used by 
 *                    this context
 * @param locking_policy the synchronization policy used by this 
 *                       context
 * @param change_endianity 
 * 
 * @return lm_dmae_context_t* a single-block DMAE context 
 *                configured according to the supplied
 *                parameters.
 */
lm_dmae_context_t* lm_dmae_context_create(  struct _lm_device_t* pdev,
                                            IN const u8_t channel_idx, 
                                            lm_dmae_locking_policy_t* locking_policy, 
                                            IN const u8_t change_endianity);

/**lm_dmae_context_create_sgl
 * Create an SGL DMA context, using the given policy for 
 * synchronization. 
 *  
 * @param loader_channel_idx the 'loader' DMAE channel index 
 *                           that is used by this context
 * @param executer_channel_idx the 'executer' DMAE channel index 
 *                             that is used by this context
 * @param locking_policy the synchronization policy used by this 
 *                       context
 * @param change_endianity 
 * 
 * @return lm_status_t an SGL DMAE context configured according 
 *                to the supplied parameters.
 */
lm_dmae_context_t* lm_dmae_context_create_sgl( struct _lm_device_t* pdev,
                                               IN const u8_t loader_channel_idx,
                                               IN const u8_t executer_channel_idx,
                                               lm_dmae_locking_policy_t* locking_policy,
                                               IN const u8_t change_endianity);

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
lm_status_t lm_dmae_context_reset(lm_dmae_context_t *context);

/**lm_dmae_context_acquire
 * Acquire the context, so that multiple DMAE operations may be 
 * executed on it without locking the context once for every 
 * operation. Only after calling this function can 
 * lm_dmae_context_execute_unsafe be used. 
 *  
 * @param context the context to acquire
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other 
 *         failure value on failure
 */
#ifdef _VBD_
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_at(context->locking_policy->spinlock.irql, __drv_savesIRQL)
__drv_setsIRQL(DISPATCH_LEVEL)
#endif
lm_status_t lm_dmae_context_acquire(struct _lm_device_t* pdev, lm_dmae_context_t *context);

/**lm_dmae_context_release
 * Release a context that was acquired with 
 * lm_dmae_context_release. After calling this function, 
 * lm_dmae_context_execute_unsafe may not be used on the 
 * context. 
 *  
 * @param context the context to release
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other 
 *         failure value on failure
 */
#ifdef _VBD_
#if defined(NTDDI_WIN8)
_IRQL_requires_(DISPATCH_LEVEL)
__drv_at(context->locking_policy->spinlock.irql, __drv_restoresIRQL )
#endif
#endif
lm_status_t lm_dmae_context_release(struct _lm_device_t* pdev, lm_dmae_context_t *context);


/**lm_dmae_context_execute
 * Execute a command in a context, using the context's locking 
 * policy 
 * 
 * @param context the context to use
 * @param operation the operation to execute
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, 
 *         LM_STATUS_PENDING if executing an asynchronous
 *         operation, LM_STATUS_BUSY if another asyncronous
 *         operation is in progress or some other failure code
 *         on failure.
 */
lm_status_t lm_dmae_context_execute(struct _lm_device_t* pdev, lm_dmae_context_t *context, lm_dmae_operation_t *operation);

/**lm_dmae_context_execute_unsafe
 * Execute a command in a context, without locking. This 
 * function must be called between calls to 
 * lm_dmae_context_acquire and lm_dmae_context_release. 
 * 
 * @param context the context to use
 * @param operation the operation to execute
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, 
 *         LM_STATUS_PENDING if executing an asynchronous
 *         operation, LM_STATUS_BUSY if another asyncronous
 *         operation is in progress or some other failure code
 *         on failure.
 */
lm_status_t lm_dmae_context_execute_unsafe(struct _lm_device_t* pdev, lm_dmae_context_t *context, lm_dmae_operation_t *operation);




//------------------ DMAE Operation ------------------//

/**lm_dmae_operation_create
 * Create a single-block DMAE operation and the DMAE command 
 * that it uses. 
 *  
 * @param source the source for this DMAE operation
 * @param dest the destination for this DMAE operation
 * @param length the length of the block to transfer
 * @param replicate_source TRUE if the source is a block of 
 *                           length DMAE_MAX_RW_SIZE_E1/DMAE_MAX_RW_SIZE_NEW
 *                           and the destination is larger. In
 *                           this case the source block will be
 *                           duplicated as many times as
 *                           required to fill the destination
 *                           block.
 * @param le32_swap should byte-swapping occur before executing 
 *                  the operation.
 * @param context the DMAE context for this operation 
 * @param operation the operation to initialize. If this function 
 *                  returns LM_STATUS_SUCCESS, the operation
 *                  pointed to by this parameter is initialized
 *                  to a single-block DMAE operation configured
 *                  according to the supplied parameters.
 *  
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other 
 *         failure value on failure.
 */
lm_status_t lm_dmae_operation_create(   struct _lm_device_t* pdev,
                                        IN const lm_dmae_address_t source,
                                        IN const lm_dmae_address_t dest,
                                        IN const u16_t length,
                                        IN const u8_t replicate_source,
                                        IN const u8_t le32_swap,
                                        IN lm_dmae_context_t* context,
                                        OUT lm_dmae_operation_t* operation);

/**lm_dmae_operation_create_sgl
 * Create an SGL DMAE operation and the DMAE commands that it 
 * uses. 
 * 
 * @param b_sync TRUE if this operation is synchronous, FALSE 
 *               otherwise.
 * @param context the DMAE context for this operation
 * 
 * @return lm_dmae_operation_t* An empty SGL DMAE operation 
 *         based on the supplied parameters. Use
 *         lm_dmae_operation_add_sge to add SGEs to this
 *         operation. On failure the function returns NULL.
 */
lm_dmae_operation_t* lm_dmae_operation_create_sgl(  struct _lm_device_t* pdev,
                                                    IN const u8_t b_sync,
                                                    IN lm_dmae_context_t* context);

/**lm_dmae_operation_add_sge
 * Add an SGE to an SGL operation.
 * 
 * @param operation the operation to add an SGE to. 
 * @param source the source for this SGE
 * @param dest the destination for this SGE
 * @param length the length of the block to transfer
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, 
 *         LM_STATUS_INVALID_PARAMETER if the supplied operation
 *         is not an SGL operation, some other failure code on
 *         failure.
 */
lm_status_t lm_dmae_operation_add_sge(  struct _lm_device_t* pdev,
                                        lm_dmae_operation_t* operation,
                                        IN const lm_dmae_address_t source,
                                        IN const lm_dmae_address_t dest,
                                        IN const u16_t length);

/**lm_dmae_operation_clear_all_sges
 * Remove all SGEs from an SGL DMAE command. 
 *  
 * @param operation the operation to clear
 * 
 */
void lm_dmae_operation_clear_all_sges(lm_dmae_operation_t* operation);

/**lm_dmae_operation_is_complete
 * check if an operation has finished
 *  
 * @param operation the operation to check
 * 
 * @return u8_t TRUE if the given operation is complete
 */
u8_t lm_dmae_operation_is_complete(IN lm_dmae_operation_t* operation);




//------------------ DMAE Address ------------------//

/**lm_dmae_address_native_offset
 * Get a u64_t representation of the address's value which can 
 * be used as a source/destination address by DMAE hardware (i.e 
 * byte offset for host memory address,  DWORD offset for GRC 
 * offsets) 
 *  
 * @param address the address to use
 * 
 * @return u64_t see description
 */
u64_t lm_dmae_address_native_offset(IN const lm_dmae_address_t* address);

/**lm_dmae_address
 * create a DMAE address 
 * 
 * @param offset the offset of the address (either 
 *               physical/virtual address or GRC offset)
 * @param type the type of the address
 * 
 * @return lm_dmae_address_t a DMAE address initialized 
 *         according to the supplied parameters
 */
lm_dmae_address_t lm_dmae_address(IN const u64_t offset, IN const lm_dmae_address_type_t type);

//------------------ DMAE users ------------------//

/**lm_dmae_get
 * Return the context info for a given DMAE user. 
 * 
 * @param pdev the device to use
 * @param type the dmae user
 * 
 * @return lm_dmae_context_info_t* the context info for the given user, or NULL on error.
 */
lm_dmae_context_info_t* lm_dmae_get(struct _lm_device_t* pdev, IN const lm_dmae_type_t type);

/**lm_dmae_reg_wr
 * Write a block of data from host memory (given as a virtual 
 * address) to GRC. 
 * 
 * @param pdev the device to use
 * @param context the DMAE context to use
 * @param source_vaddr the beginning of the source memory block
 * @param dest_offset the GRC offset of the destination block
 * @param length the length (in DWORDS) of the block
 * @param b_replicate_source TRUE if the source is a block of 
 *                           length
 *                           DMAE_MAX_RW_SIZE_E1/DMAE_MAX_RW_SIZE_NEW
 *                           and the destination is larger. In
 *                           this case the source block will be
 *                           duplicated as many times as
 *                           required to fill the destination
 *                           block.
 * @param le32_swap if TRUE, change all DWORDS in the source 
 *                  block to little-endian representation before
 *                  executing the operation.
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, 
 *         LM_STATUS_TIMEOUT if the operation did not finish in
 *         reasonable time, some other failure value on failure.
 */
lm_status_t lm_dmae_reg_wr(struct _lm_device_t* pdev, lm_dmae_context_t* context, void* source_vaddr, u32_t dest_offset, u16_t length, u8_t b_replicate_source, u8_t le32_swap);

/**lm_dmae_reg_wr_phys 
 * Write a block of data from host memory (given as a physical 
 * address) to GRC. 
 * 
 * @param pdev the device to use
 * @param context the DMAE context to use
 * @param source_paddr the beginning of the source memory block
 * @param dest_offset the GRC offset of the destination block
 * @param length the length (in DWORDS) of the block
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, 
 *         LM_STATUS_TIMEOUT if the operation did not finish in
 *         reasonable time, some other failure value on failure.
 */
lm_status_t lm_dmae_reg_wr_phys(struct _lm_device_t* pdev, lm_dmae_context_t* context, lm_address_t source_paddr, u32_t dest_offset, u16_t length);

/**lm_dmae_reg_rd
 * Read a block from GRC to host memory(given as a virtual 
 * address). 
 * 
 * 
 * @param pdev the device to use
 * @param context the DMAE context to use
 * @param source_offset the GRC offset of the source block
 * @param dest_vaddr the beginning of the destination memory 
 *                   block
 * @param length the length (in DWORDS) of the block
 * @param le32_swap if TRUE, change all DWORDS in data to 
 *                  little-endian after it's read from GRC.
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, 
 *         LM_STATUS_TIMEOUT if the operation did not finish in
 *         reasonable time, some other failure value on failure.
 */
lm_status_t lm_dmae_reg_rd(struct _lm_device_t* pdev, lm_dmae_context_t* context, u32_t source_offset, void* dest_vaddr, u16_t length, u8_t le32_swap);


/**lm_dmae_copy_phys_buffer_unsafe
 * Copy a block from host memory to host memory, both addresses 
 * given as physical addresses. 
 * 
 * 
 * @param pdev the device to use
 * @param context the DMAE context to use
 * @param source_paddr the beginning of the source memory block
 * @param dest_paddr the beginning of the destination memory 
 *                   block
 * @param length the length (in DWORDS) of the block
 * 
 * @return lm_status_t LM_STATUS_SUCCESS on success, 
 *         LM_STATUS_TIMEOUT if the operation did not finish in
 *         reasonable time, some other failure value on failure.
 */
lm_status_t lm_dmae_copy_phys_buffer_unsafe(struct _lm_device_t* pdev, lm_dmae_context_t* context, lm_address_t source_paddr, lm_address_t dest_paddr, u16_t length);

#endif// _LM_DMAE_H
