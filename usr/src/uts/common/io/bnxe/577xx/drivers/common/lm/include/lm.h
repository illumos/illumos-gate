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
 *    10/09/01 Hav Khauv        Inception.
 ******************************************************************************/

#ifndef _LM_H
#define _LM_H

#include "lm_defs.h"
#include "listq.h"
#include "iscsi_info.h"

/*******************************************************************************
 * Constants.
 ******************************************************************************/

#define BAD_DEFAULT_VALUE                   0xffffffff

#define ETHERNET_ADDRESS_SIZE               6
#define ETHERNET_PACKET_HEADER_SIZE         14
#define ETHERNET_VLAN_TAG_SIZE              4
#define ETHERNET_LLC_SNAP_SIZE              8
#define ETHERNET_CRC32_SIZE                 4
#define ETHERNET_GRE_SIZE                   8

#define MIN_ETHERNET_PACKET_SIZE            60

// VLAN TAG
#define ETHERNET_VLAN_ID_MASK                    (0xFFF<<0)
#define ETHERNET_VLAN_ID_OFFSET                  (0)
#define ETHERNET_CFI_MASK                        (0x1<<12)
#define ETHERNET_CFI_OFFSET                      (12)
#define ETHERNET_PRIORITY_MASK                   (0x7<<13)
#define ETHERNET_PRIORITY_OFFSET                 (13)

#define VLAN_TAGGED_FRAME_ETH_TYPE          0x8100

#define ATOMIC_MOVE_MAC                     1
/*******************************************************************************
 * Forward definition.
 ******************************************************************************/

/* Main device structure. */
/* typedef struct _lm_device_t lm_device_t; */
struct _lm_device_t;

/* Packet descriptor for sending/receiving packets. */
/* typedef struct _lm_packet_t lm_packet_t; */
struct _lm_packet_t;


/* Current link information */
struct _lm_reported_link_params_t;

/* typedef struct _lm_dcbx_ie_local_classif_vars_t lm_dcbx_ie_local_classif_vars_t; */
struct _lm_dcbx_ie_local_classif_vars_t;
/* structure for represnting an array of slow-path cqes */
struct _sp_cqes_info;

/* LLDP structure for GET_LLDP_PARAMS */
struct _b10_lldp_params_get_t;

/* DCBX structure for GET_DCBX_PARAMS */
struct _b10_dcbx_params_get_t;

/* structure for B10_IOC_GET_TRANSCEIVER_DATA */
struct _b10_transceiver_data_t;

/*******************************************************************************
 * Network wake-up frame.
 ******************************************************************************/

#ifndef LM_NWUF_PATTERN_SIZE
#define LM_NWUF_PATTERN_SIZE                    128
#endif
#define LM_NWUF_PATTERN_MASK_SIZE               (LM_NWUF_PATTERN_SIZE/8) // (8 = sizeof(byte)) ==> 16
#define MAX_IGU_ATTN_ACK_TO                     100
/* Wake-up frame pattern. */
typedef struct _lm_nwuf_pattern_t
{
    u32_t size;         /* Mask size */
    u32_t pattern_size; /* Pattern size */
    u8_t  mask    [LM_NWUF_PATTERN_MASK_SIZE]; // 16 bytes  --> (128 bits - each bit represents pattern byte)
    u8_t  pattern [LM_NWUF_PATTERN_SIZE];      // 128 bytes --> (1024 bits)
    u32_t crc32 ;                              // crc32 on (pattern & mask)
} lm_nwuf_t;


#ifndef LM_MAX_NWUF_CNT
#define LM_MAX_NWUF_CNT                         8
#endif

typedef struct _lm_nwuf_list_t
{
    lm_nwuf_t nwuf_arr[LM_MAX_NWUF_CNT];
    u32_t cnt;
} lm_nwuf_list_t;




typedef u32_t lm_interrupt_status_t;



/*******************************************************************************
 * Function prototypes.
 ******************************************************************************/

/* Description:
 *    1.  Retrieves the adapter information, such as IRQ, BAR, chip
 *        IDs, MAC address, etc.
 *    2.  Maps the BAR to system address space so hardware registers are
 *        accessible.
 *    3.  Initializes the default parameters in 'pdev'.
 *    4.  Reads user configurations.
 *    5.  Resets the transceiver.
 * This routine calls the following mm routines:
 *    mm_map_io_base, mm_get_user_config. */
lm_status_t
lm_get_dev_info(
    struct _lm_device_t *pdev);

/**
 * @Description
 *     This function is responsible for reading all the data
 *     that the driver needs before loading from the shmem.
 *
 * @param pdev
 *
 * @return lm_status_t
 */
lm_status_t
lm_get_shmem_info(
        struct _lm_device_t *pdev);

/* Description:
*    This routine is called during driver initialization.  It is responsible
*    for allocating memory resources needed by the driver for common init.
*    This routine calls the following mm routines:
*    mm_alloc_mem, mm_alloc_phys_mem, and mm_init_packet_desc. */
lm_status_t
lm_alloc_resc(
    struct _lm_device_t *pdev);

/* Description:
*    This routine is called during driver initialization.  It is responsible
*    for initilazing  memory resources needed by the driver for common init.
*    This routine calls the following mm routines:
*    mm_alloc_mem, mm_alloc_phys_mem, and mm_init_packet_desc. */
lm_status_t
lm_setup_resc(
    struct _lm_device_t *pdev);


lm_status_t lm_service_eq_intr(struct _lm_device_t * pdev);

typedef enum _lm_abort_op_t
{
    ABORT_OP_RX_CHAIN          = 1,
    ABORT_OP_TPA_CHAIN          = 2,
    ABORT_OP_INDICATE_TX_CHAIN  = 3,
    ABORT_OP_INDICATE_RX_CHAIN  = 4,
    ABORT_OP_INDICATE_TPA_CHAIN = 5,
    ABORT_OP_MAX                = 6,
} lm_abort_op_t ;

/* Each log type has its own parameters    |-------------------------------------------------------------------------------------------------------| */
typedef enum lm_log_id {                /* | MSGLOG name (msglog.mc)          | (req params)   | elink cb name                    | elink cb params| */
                                        /* | ---------------------------------|----------------|----------------------------------|----------------| */
    LM_LOG_ID_UNQUAL_IO_MODULE    = 0,  /* | MSGLOG_SFP_PLUS_UNQUAL_IO_MODULE | port, name, pn | ELINK_LOG_ID_UNQUAL_IO_MODULE    | port, name, pn | */
    LM_LOG_ID_OVER_CURRENT        = 1,  /* | MSGLOG_SFP_PLUS_OVER_CURRENT     | port           | ELINK_LOG_ID_OVER_CURRENT        | port           | */
    LM_LOG_ID_PHY_UNINITIALIZED   = 2,  /* | MSGLOG_PHY_UNINITIALIZED         | port           | ELINK_LOG_ID_PHY_UNINITIALIZED   | port           | */
    LM_LOG_ID_NO_10G_SUPPORT      = 3,  /* | MSGLOG_NO_10G_SUPPORT            | port           | N/A                              | N/A            | */
    LM_LOG_ID_FAN_FAILURE         = 4,  /* | MSGLOG_DELL_FAN_FAILURE          | none           | N/A                              | N/A            | */
    LM_LOG_ID_MDIO_ACCESS_TIMEOUT = 5,  /* | MSGLOG_MDIO_ACCESS_TIMEOUT       | port           | ELINK_LOG_ID_MDIO_ACCESS_TIMEOUT | (none)         | */
    LM_LOG_ID_NON_10G_MODULE      = 6,  /* | MSGLOG_SFP_NON_10G_MODULE        | port           | ELINK_LOG_ID_NON_10G_MODULE      | port           | */
                                        /* |-------------------------------------------------------------------------------------------------------| */
    LM_LOG_ID_MAX                 = 7   /* | Invalid */
} lm_log_id_t;

/* Description:
 *    This routine is responsible for stopping the hardware from running,
 *    cleaning up various request queues, aborting transmit requests, and
 *    reclaiming all the receive buffers.
 * This routine calls the following mm routines:
 *    mm_indicate_tx, mm_free_rx_buf. */
void lm_abort( IN OUT   struct _lm_device_t*  pdev,
               IN const         lm_abort_op_t abort_op,
               IN const         u32_t         idx);


/* Description:
 *    The main function of this routine is to reset and initialize the
 *    hardware.  Upon exit, interrupt generation is not enable; however,
 *    the hardware is ready to accept transmit requests and receive receive
 *    packets.  'lm_abort' must be called prior to calling 'lm_reset'.
 *    This routine is a wrapper for lm_reset_setup and lm_reset_run. */
lm_status_t
lm_reset(
    struct _lm_device_t *pdev);

/* Description:
 *    The main function of this routine is to initialize the
 *    hardware. it configues all hw blocks in several phases acording to mcp response:
 *    1. common blocks
 *    2. per function blocks
 */
lm_status_t
lm_chip_init(
    struct _lm_device_t *pdev);

lm_resource_idx_t cid_to_resource(
        struct _lm_device_t *pdev, u32_t cid);

void init_nig_func(struct _lm_device_t *pdev);

void init_nig_common_llh(struct _lm_device_t *pdev);

/* Description:
 *    Verify that the MCP validity bit already up
 */
lm_status_t lm_verify_validity_map(
    struct _lm_device_t *pdev);

/* Description:
 *    Calls lm_function_start. add here other stuff to follow if any.
 */
lm_status_t
lm_chip_start(struct _lm_device_t *pdev);

/* Description:
*    This routine close port or assert reset for all needed blocks
*/
void lm_chip_reset(struct _lm_device_t *pdev, lm_reason_t reason) ;

/** Description:
 *    Resets all "needed" blacks plus NIG.
 *    It's a pure reset: no locks are taken.
 */
void lm_chip_reset_with_nig(struct _lm_device_t *pdev);

/* This function reset a path (e2) or a chip (e1/e1.5)
 * includeing or excluding the nig (b_with_nig)
 */
void lm_reset_path(struct _lm_device_t *pdev, const  u8_t b_with_nig );

/** Description:
 *    Resets MCP. Waits until MCP wakes up.
 *
 *    This function sleeps!!!
 *
 *  Returns:
 *    LM_STATUS_SUCCESS if MCP reset and woke up successfully,
 *    LM_STATUS_FAILURE otherwise.
 */
lm_status_t lm_reset_mcp(struct _lm_device_t *pdev);

/**
 *
 * @param pdev Device instance
 *
 * @return TRUE if MCP was detected.
 */
u8_t lm_is_mcp_detected(
    IN struct _lm_device_t *pdev
    );


/* Description:
*    Configures nwuf packets.
*    Must be called before chip reset since it uses DMAE block
*    (for wide bus)
*/
void lm_set_d3_nwuf( struct _lm_device_t*        pdev,
                     const  lm_wake_up_mode_t    wake_up_mode );

/* Description:
*    Configures magic packets.
*/
void lm_set_d3_mpkt( struct _lm_device_t*     pdev,
                     const  lm_wake_up_mode_t wake_up_mode );

/* Description:
*    Sets the FLR flag
*/
void lm_fl_reset_set_inprogress(struct _lm_device_t *pdev);

/* Description:
*    Clears the FLR flag
*/
void lm_fl_reset_clear_inprogress(struct _lm_device_t *pdev);

/* Description:
*    Returns true when the FLR flag is set
*/
u8_t lm_fl_reset_is_inprogress(struct _lm_device_t *pdev);

/* Description:
*    Sets the global shutdown-in-progress flag
*/
void lm_reset_set_inprogress(struct _lm_device_t *pdev);

/* Description:
*    Clears the global shutdown-in-progress flag
*/
void lm_reset_clear_inprogress(struct _lm_device_t *pdev);

/* Description:
*    Returns true when the global shutdown-in-progress flag is set
*/
u8_t lm_pm_reset_is_inprogress(struct _lm_device_t *pdev);

/* Description:
*    Returns true when the global shutdown-in-progress flag is set
*    OR FLR_PF (both PF and VF) flag is set
*    OR FLR_VF (VF only) flag is set
*/
u8_t lm_reset_is_inprogress(struct _lm_device_t *pdev);

/* Description
 *    marks the function to be enabled after reseting nig: used for WOL
 */
void lm_set_func_en(struct _lm_device_t *pdev, const u8_t b_enable);

/* Description
 *    returns the value of function enabled.
 */
u8_t lm_get_func_en(struct _lm_device_t *pdev, const u8_t pfunc_abs);

/* Description:
*    Masks the HW attention as part of the shutdown flow
*/
void lm_reset_mask_attn(struct _lm_device_t *pdev);


void lm_setup_read_mgmt_stats_ptr( struct    _lm_device_t* pdev,
                                   IN  const u32_t         func_mailbox_num,
                                   OUT       u32_t*        fw_port_stats_ptr,
                                   OUT       u32_t*        fw_func_stats_ptr );


/* Description:
 *         Acquiring the HW lock for a specific resource.
 *         The assumption is that only 1 bit is set in the resource parameter
 *         There is a HW attention in case the same function attempts to
 *         acquire the same lock more than once
 *
 * Params:
 *         resource: the HW LOCK Register name
 *         b_block: Try to get lock until succesful, or backout immediately on failure.
 * Return:
 *          Success - got the lock
 *          Fail - Invalid parameter or could not obtain the lock for over 1 sec in block mode
 *          or couldn't obtain lock one-shot in non block mode
 */
lm_status_t lm_hw_lock(struct _lm_device_t*      pdev,
                       const  u32_t              resource,
                       const  u8_t               b_block);
/* Description:
 *         Releasing the HW lock for a specific resource.
 *         There is a HW attention in case the a function attempts to release
 *         a lock that it did not acquire
 * Return:
 *          Success - if the parameter is valid, the assumption is that it
 *                    will succeed
 *          Fail - Invalid parameter
 */
lm_status_t lm_hw_unlock(struct _lm_device_t*      pdev,
                         const u32_t               resource);

lm_status_t lm_hw_unlock_ex(struct _lm_device_t*      pdev,
                            const  u32_t              resource,
                            const  u8_t               b_verify_locked );


lm_status_t
lm_ncsi_fcoe_cap_to_scratchpad( struct _lm_device_t *pdev);

/**
 * @Desription
 *      This function is used to recover from a state where the
 *      locks stayed in "taken" state during a reboot. We want
 *      to clear all the locks before proceeding.
 *
 * @param pdev
 */
void lm_hw_clear_all_locks(struct _lm_device_t *pdev);

/* Description:
 *    This routine post the indicate buffer or receive buffers in the
 *    free buffer pool.  If 'packet' is null, all buffers in the free poll
 *    will be posted; otherwise, only the 'packet' will be posted. */
u32_t
lm_post_buffers(
    struct _lm_device_t *pdev,
    u32_t chain_idx,
    struct _lm_packet_t *packet,/* optional. */
    u8_t const  is_tpa);

/* Description:
 *    This routine sends the given packet.  Resources required to send this
 *    must have already been reserved.  The upper moduel is resposible for
 *    any necessary queueing. */
lm_status_t
lm_send_packet(
    struct _lm_device_t *pdev,
    u32_t chain_idx,
    struct _lm_packet_t *packet,
    lm_frag_list_t *frags);

/**
 * @description
 * Check if VLAN exist and if the VLAN exists get priority.
 * @param pdev
 * @param packet
 *
 * @return u32_t
 */
u8_t
lm_get_pri_from_send_packet_param(
    struct _lm_device_t *pdev,
    struct _lm_packet_t *packet);
/* Description:
 *    This routine sends the given cmd.  Resources required to send this
 *    must have already been reserved.  The upper moduel is resposible for
 *    any necessary queueing. */
lm_status_t
lm_send_sq_cmd(
    struct _lm_device_t *pdev,
    u32_t cid,
    u8_t cmd_id);

/* Description:
* This routine completes the cmd. it should safely increment the number
* of pending comands and send the next commnad if any
*/
lm_status_t
lm_complete_sq_cmd(
    struct _lm_device_t *pdev,
    u32_t cid,
    u8_t cmd_id);


/* Description:
* This routine sends ring pending commands. it should be safely increment the number
* of pending comands and send the next commnad if any
*/
lm_status_t
lm_enlist_sq_cmd(
    struct _lm_device_t *pdev
);

/* Description:
 *    This routine is called to get all pending interrupts. */
lm_interrupt_status_t
lm_get_interrupt_status(
    struct _lm_device_t *pdev);

/* Description:
 *    Replacement function for lm_get_interrupt_status for dedicated IGU tests */
u64_t
lm_igutest_get_isr64(struct _lm_device_t *pdev);
u64_t
lm_igutest_get_isr32(struct _lm_device_t *pdev);

/* Description:
 *    This routine is called to get all pending interrupts. */
lm_interrupt_status_t
lm_get_interrupt_status_wo_mask(
    struct _lm_device_t *pdev);

/* Description:
 *    This routine is called to get all pending interrupts for ediag dummy interrupt. */
lm_interrupt_status_t
lm_get_interrupt_status_and_mask(
    struct _lm_device_t *pdev);


u32_t
lm_get_packets_rcvd(
    struct _lm_device_t  *pdev,
    u32_t const          chain_idx,
    s_list_t             *rcvd_list,
    struct _sp_cqes_info *sp_cqes);

lm_status_t
lm_complete_ramrods(
    struct _lm_device_t *pdev,
    struct _sp_cqes_info *sp_cqes);

u32_t
lm_get_packets_sent(
    struct _lm_device_t *pdev,
    u32_t chain_idx,
    s_list_t *sent_list);


/* Description:
 *    This routine is called to mask out interrupt from the hardware. */
void lm_disable_int(struct _lm_device_t *pdev);

/* Description:
 *    This routine is called to enable interrupt generation. */
void lm_enable_int(struct _lm_device_t *pdev);

/**
 * @Description: This routine is called to set the receive
 * filter. drop unicast/multicast/broadcast for a fast-path
 * chain-idx
 *
 * @param pdev
 * @param chain_idx - which chain to set the filtering on
 * @param rx_mask - the rx mask information
 * @param cookie - will be returned when indicating to "mm" that
 *               the operation completed.
 *
 * @return lm_status_t - SUCCESS (if completed synchrounously)
 *                       PENDING (if completion will arrive
 *                       asynchrounously)
 *                       FAILURE o/w
 */
lm_status_t lm_set_rx_mask(struct _lm_device_t *pdev, u8_t chain_idx, lm_rx_mask_t rx_mask, void * cookie);

/**
 * @Description: This function waits for the rx mask to complete
 *
 * @param pdev
 * @param chain_idx- which chain to wait on
 *
 * @return lm_status_t
 */
lm_status_t lm_wait_set_rx_mask_done(struct _lm_device_t *pdev, u8_t chain_idx);


/*************************  MULTICAST  *****************************************/


/**
 * @Description
 *      Function configures a list of multicast addresses. Or
 *      resets the list previously configured
 *
 * @param pdev
 * @param mc_addrs    - array of multicast addresses. NULL if unset is required
 * @param buf_len     - length of the buffer - 0 if unset is required
 * @param cookie      - will be returned on completion
 * @param lm_cli_idx  - which lm client to send request on
 *
 * @return lm_status_t - SUCCESS on syncrounous completion
 *                       PENDING on asyncounous completion
 *                       FAILURE o/w
 */
lm_status_t lm_set_mc(struct _lm_device_t *pdev, u8_t* mc_addrs, u32_t buf_len, void * cookie, lm_cli_idx_t lm_cli_idx);

lm_status_t lm_set_mc_list(struct _lm_device_t *pdev,
                           d_list_t * mc_addrs, /* may be NULL (for unset) */
                           void * cookie,
                           lm_cli_idx_t lm_cli_idx);

/**
 * Description
 *      This routine is called to wait for the multicast set
 *      completion. It must be called in passive level since it
 *      may sleep
 * @param pdev
 * @param lm_cli_idx the cli-idx that the multicast was sent on.
 *
 * @return lm_status SUCCESS on done, TIMEOUT o/w
 */
lm_status_t lm_wait_set_mc_done(struct _lm_device_t *pdev, lm_cli_idx_t lm_cli_idx);


lm_status_t lm_eth_wait_state_change(struct _lm_device_t *pdev, u32_t new_state, u32_t cid);


/**
 * Set/Unset a mac-address or mac-vlan pair on a given chain.
 *
 * @param pdev
 * @param mac_addr  - array of size ETHERNET_ADDRESS_SIZE
 *                    containing a valid mac addresses
 * @param vlan_tag  - vlan tag to be set with mac address
 * @param chain_idx - which chain to set the mac on. Chain_idx
 *                    will be transformed to a l2 client-id
 * @param cookie    - will be returned to MM layer on completion
 * @param set       - set or remove mac address
 * @param is_encap_inner_mac_filter - set if we filter according
 *                                  to inner mac (VMQ offload of
 *                                  encapsulated packets)
 *
 * @return lm_status_t SUCCESS on syncrounous success, PENDING
 *         if completion will be called later, FAILURE o/w
 */
lm_status_t lm_set_mac_addr(struct _lm_device_t *pdev, u8_t *mac_addr, u16_t vlan_tag, u8_t chain_idx,  void * cookie, const u8_t b_set, u8_t is_encap_inner_mac_filter);

/**
 * Set/Unset a vlan on a given chain.
 *      Setting/unsetting a vlan is a bit more complex than
 *      setting a mac address and is therefore implemented in a
 *      separate function. It require deleting a previous vlan
 *      tag if one was set, and changing rx-filtering rules. The
 *      change in rx-filtering rules has to do with "any-vlan".
 *      If no vlan is set we want "any-vlan" otherwise we want
 *      to remove the any-vlan, this requires another ramrod.
 *      The way this is implemented is as follows:
 *          1. prepare vlan add/remove commands without
 *          executing them (sp-verbs feature don't send EXEC)
 *          2. If need to set rx-mask, turn on a flag that will
 *          be checked on completion of rx-mask, in
 *          lm_eq_handle_rx_filter.., we look at this flag and
 *          if it's on execute the vlan pending command
 *          (sp-verbs CONT feature).
 *
 * @param pdev
 * @param vlan_tag  - vlan tag to be set
 * @param chain_idx - which chain to set the vlan on. Chain_idx
 *                    will be transformed to a l2 client-id
 * @param cookie    - will be returned to MM layer on completion
 * @param set       - set or remove vlan
 *
 * @return lm_status_t SUCCESS on syncrounous success, PENDING
 *         if completion will be called later, FAILURE o/w
 */
lm_status_t lm_set_vlan_only(struct _lm_device_t *pdev, u16_t vlan_tag, u8_t chain_idx,  void * cookie, const u8_t b_set);

/**
 *  Move a filter from one chain idx to another atomically
 *
 * @param pdev
 *
 * @param mac_addr       - array of size ETHERNET_ADDRESS_SIZE
 *                         containing a valid mac addresses
 * @param vlan_tag       - vlan tag to be set with mac address
 * @param src_chain_idx  - which chain to remove the mac from
 * @param dest_chain_idx - which chain to set the mac on
 * @param cookie         - will be returned to MM layer on completion
 *
 * @return lm_status_t
 */
lm_status_t lm_move_mac_addr(struct _lm_device_t *pdev, u8_t *mac_addr, u16_t vlan_tag, 
			     u8_t src_chain_idx,  u8_t dest_chain_idx, void * cookie, u8_t is_encap_inner_mac_filter);

/**
 * @Description
 *      Waits for the last set-mac called to complete
 * @param pdev
 * @param chain_idx - the same chain-idx that the set-mac was
 *                  called on
 *
 * @return lm_status_t SUCCESS or TIMEOUT
 */
lm_status_t lm_wait_set_mac_done(struct _lm_device_t *pdev, u8_t chain_idx);


/**
 * @Description
 *      Waits for the last set-vlan called to complete
 * @param pdev
 * @param chain_idx - the same chain-idx that the set-vlan was
 *                  called on
 *
 * @return lm_status_t SUCCESS or TIMEOUT
 */
lm_status_t lm_wait_set_vlan_done(struct _lm_device_t *pdev, u8_t chain_idx);

/* Description:
 *    Clears all the mac address that are set on a certain cid...
 */
lm_status_t lm_clear_all_mac_addr(struct _lm_device_t *pdev, const u8_t chain_idx);

/**
 * Description
 *      Restores all the mac address that are set on a certain
 *      cid (after sleep / hibernate...)
 * @param pdev
 * @param chain_idx - which chain_idx to clear macs on...
 *
 * @assumptions: Called in PASSIVE_LEVEL!! function sleeps...
 * @return lm_status_t
 */
lm_status_t lm_restore_all_mac_addr(struct _lm_device_t *pdev, u8_t chain_idx);

/**insert_nig_entry
 * Reference an entry for a given MAC address. If this is the
 * first reference, add it to the NIG, otherwise increase its
 * refcount.
 *
 * @param pdev
 * @param addr the MAC address
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success,
 *         LM_STATUS_RESOURCE if no more NIG entries are
 *         available, other failure codes on other errors.
 */
lm_status_t lm_insert_nig_entry(    struct _lm_device_t *pdev,
                                    u8_t        *addr);


/**remove_nig_entry
 * Dereference the entry for a given MAC address. If this was
 * the last reference the MAC address is removed from the NIG.
 *
 * @param pdev
 * @param addr the MAC address
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success,
 *         LM_STATUS_FAILURE if the given MAC is not in the NIG,
 *         other failure codes on other errors.
 */
lm_status_t lm_remove_nig_entry(    struct _lm_device_t *pdev,
                                    u8_t        *addr);

lm_status_t lm_set_mac_in_nig(struct _lm_device_t * pdev, u8_t * mac_addr, lm_cli_idx_t lm_cli_idx, u8_t offset);


/*************************  RSS  *****************************************/
/**
 * @Description
 *      Enable RSS for Eth with given indirection table also updates the rss key

 * @param pdev
 * @param chain_indirection_table - array of size @table_size containing chain numbers
 * @param table_size - size of @indirection_table
 * @param hash_key - new hash_key to be configured. 0 means no key
 * @param key_size
 * @param hash_type
 * @param sync_with_toe - This field indicates that the completion to the mm layer
 *                        should take into account the fact that toe rss update will
 *                        be sent as well. A counter will be increased in lm for this purpose
 * @param cookie        - will be returned on completion
 *
 * @return lm_status_t - SUCCESS on syncrounous completion
 *                       PENDING on asyncounous completion
 *                       FAILURE o/w
 */
lm_status_t lm_enable_rss(struct _lm_device_t *pdev, u8_t *chain_indirection_table,
                          u32_t table_size, u8_t *hash_key, u32_t key_size, lm_rss_hash_t hash_type,
                          u8 sync_with_toe, void * cookie);

/**
 * @Description
 *      This routine disables rss functionality by sending a
 *      ramrod to FW.
 *
 * @param pdev
 * @param cookie - will be returned on completion
 * @param sync_with_toe - true means this call is synced with
 *                      toe, and completion will be called only
 *                      when both toe + eth complete. Eth needs
 *                      to know this (reason in code)
 *
 * @return lm_status_t - SUCCESS on syncrounous completion
 *                       PENDING on asyncounous completion
 *                       FAILURE o/w
 */
lm_status_t lm_disable_rss(struct _lm_device_t *pdev, u8_t sync_with_toe, void * cookie);

/**
 * @Description
 *      Wait for the rss disable/enable configuration to
 *      complete
 *
 * @param pdev
 *
 * @return lm_status_t lm_status_t SUCCESS or TIMEOUT
 */
lm_status_t lm_wait_config_rss_done(struct _lm_device_t *pdev);

/**
 * @description
 * Configure cmng the firmware to the right CMNG values if this
 * device is the PMF ,after link speed/ETS changes.
 *
 * @note This function must be called under PHY_LOCK
 * @param pdev
 */
void lm_cmng_update(struct _lm_device_t *pdev);
/*************************  NIV  *****************************************/

/**lm_niv_set_loopback_mode
 * Configure the FW to loopback mode - Tx packets will have the VN tag
 * of Rx packets so that they will not be dropped by the Rx path.
 * Note that once this function enables VN-Tag loopback mode the traffic that
 * leaves the NIG is not valid VN-Tag traffic - don't use it unless MAC/PHY/external
 * loopback is configured.
 *
 * @param pdev
 * @param b_enable TRUE if loopback mode should be enabled, false otherwise.
 */
lm_status_t lm_niv_set_loopback_mode(struct _lm_device_t *pdev, IN const u8_t b_enable);


/**lm_niv_event
 * handle a NIV-related MCP general attention by scheduling the
 * appropriate work item.
 *
 * @param pdev the device to use
 * @param niv_event the DRIVER_STATUS flags that the MCP sent.
 *                  It's assumed that only NIV-related flags are
 *                  set.
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         failure code on failure.
 */
lm_status_t lm_niv_event(struct _lm_device_t *pdev, const u32_t niv_event);

/**lm_niv_post_command
 * Post a NIV ramrod and wait for its completion.
 *
 *
 * @param pdev the device
 * @param command the ramrod cmd_id (NONE_CONNECTION_TYPE is
 *                assumed)
 * @param data the ramrod data
 * @param initial_state the type of the NIV command (one of the
 *                      NIV_RAMROD_???_POSTED values)
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         failure code on failure.
 */
lm_status_t lm_niv_post_command(struct _lm_device_t *pdev,
                                IN const u8_t       command,
                                IN const u64_t      data,
                                IN const u32_t      initial_state);

/**lm_niv_vif_update
 * Send a VIF function update ramrod and wait for its completion.
 *
 *
 * @param pdev the device
 * @param vif_id the new VIF ID for this function
 * @param default_vlan the new default VLAN for this function
 * @param allowed_priorities the new allowed priorities for this function
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other failure code on failure.
 */
lm_status_t lm_niv_vif_update(struct _lm_device_t *pdev,
                              IN const u16_t vif_id,
                              IN const u16_t default_vlan,
                              IN const u8_t allowed_priorities);

/**lm_niv_vif_list_update
 * Send a VIF lists ramrod and wait for its completion.
 *
 *
 * @param pdev the device
 * @param command the operation to perform. @see
 *                vif_list_rule_kind
 * @param list_index the list to set/get (used in LIST_GET and
 *                   LIST_SET commands)
 * @param func_bit_map the new bitmap for the list (used in
 *                     LIST_SET)
 * @param func_to_clear the function to remove from all lists
 *                      (used in CLEAR_FUNC)
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         failure code on failure.
 */
lm_status_t lm_niv_vif_list_update(struct _lm_device_t* pdev,
                                   IN const enum vif_list_rule_kind opcode,
                                   IN const u16_t list_index,
                                   IN const u8_t func_bit_map,
                                   IN const u8_t func_to_clear);


/**lm_get_shmem_mf_cfg_info_niv
 * Refresh NIV-related MF HW info from SHMEM.
 *
 * @param pdev the device to use
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         failure code on failure.
 */
lm_status_t lm_get_shmem_mf_cfg_info_niv(struct _lm_device_t *pdev);

/**
 * @brief Update mf configuration from SHMEM
 *
 * @param pdev the device to use
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         failure code on failure.
 */

lm_status_t lm_get_shmem_mf_cfg_info(struct _lm_device_t *pdev);


#define LM_SET_CAM_NO_VLAN_FILTER  0xFFFF

#define PHY_HW_LOCK(pdev)   lm_hw_lock(pdev, HW_LOCK_RESOURCE_MDIO, TRUE);

#define PHY_HW_UNLOCK(pdev) lm_hw_unlock(pdev, HW_LOCK_RESOURCE_MDIO);

/* Description:
 *    This routine is called to retrieve statistics.  */

struct _lm_vf_info_t;
lm_status_t
lm_get_stats(
    struct _lm_device_t *pdev,
    lm_stats_t stats_type,
    u64_t *stats_cnt
#ifdef VF_INVOLVED
    ,struct _lm_vf_info_t * vf_info
#endif
    );


void lm_stats_reset( struct _lm_device_t* pdev) ;

/* Description:
 *    This routine is called to add a wake-up pattern to the main list that
 *    contains all the wake-up frame. */
lm_status_t
lm_add_nwuf(
    struct _lm_device_t *pdev,
    u32_t byte_mask_size,
    u8_t *byte_mask,
    u8_t *byte_pattern);

/* Description:
 *    This routine is called to remove the wake-up pattern from the main list
 *    that contains all the wake-up frame. */
lm_status_t
lm_del_nwuf(
    struct _lm_device_t *pdev,
    u32_t byte_mask_size,
    u8_t *byte_mask,
    u8_t *byte_pattern);

/* Description:
 *    Delete all the NWUF entries. */
void
lm_clear_nwuf(
    struct _lm_device_t *pdev);


/**lm_save_hw_state_for_d3
 * Save whatever HW state is needed before the device goes to
 * D3, so that it can be restored when returning to D0 by
 * lm_pcie_state_restore_for_d0
 *
 *
 * @param pdev the device to use.
 */
void lm_pcie_state_save_for_d3(struct _lm_device_t *pdev);

/**lm_save_hw_state_for_d3
 * Restore whatever HW state was saved by
 * lm_pcie_state_save_for_d3 before the device's power state was
 * changed to D3.
 *
 * @param pdev the device to use.
 */
void lm_pcie_state_restore_for_d0(struct _lm_device_t *pdev);

/* Description:
 *    This routine is called to set up the device power state. */
void
lm_set_power_state(
    struct _lm_device_t *pdev,
    lm_power_state_t power_state,
    lm_wake_up_mode_t wake_up_mode,     /* Valid when power_state is D3. */
    u8_t set_pci_pm);

lm_status_t lm_check_phy_link_params(struct _lm_device_t *pdev, lm_medium_t req_medium);

/* Description:
 *    This routine is called to initialize the PHY based one 'media_type'
 *    setting.  'wait_for_link_timeout' specifies how long to poll for
 *    link before returning. */
lm_status_t
lm_init_phy(
    struct _lm_device_t *pdev,
    lm_medium_t req_medium,
    lm_flow_control_t flow_control,
    u32_t selective_autoneg,
    u32_t wire_speed,
    u32_t wait_for_link_timeout);

lm_status_t
lm_link_update(struct _lm_device_t *pdev);

u32_t lm_get_speed_real_from_elink_line_speed( IN const struct elink_vars* link_vars );
u32_t lm_get_speed_medium_from_elink_line_speed( IN const struct elink_vars* link_vars );

lm_medium_t lm_loopback_req_medium_convert( IN struct _lm_device_t *pdev, IN const lm_medium_t req_medium );

/**lm_get_port_max_speed
 *
 * @param pdev the device to check
 *
 * @return u32_t the maximum speed (in Mbps) the physical port
 *         that pdev is on is capable of. This may be different
 *         than the current medium's speed.
 */
u32_t lm_get_port_max_speed(IN struct _lm_device_t *pdev);

/**
 * @Description
 *     This function is called periodically, every time the link
 *     timer expires, it's main purpose is to call elink under
 *     appropriate locks to perform any periodic tasks
 * @param pdev
 *
 * @return lm_status_t
 */
lm_status_t
lm_link_on_timer(struct _lm_device_t *pdev);

/* Description:
 *    This routine is called to report link to the OS and sync
 *    Statistic gathering.
 */
void
lm_link_report(struct _lm_device_t *pdev);

/* Description:
 *    Fills struct from type _lm_reported_link_params_t with
 *    current link information
 */
void lm_link_fill_reported_data( IN struct _lm_device_t *pdev,
                                OUT struct _lm_reported_link_params_t *lm_reported_link_params );

/* Description:
 *    This routine is called to get the external phy fw version
 *    will return zero in case no external phy or failure type
 */
lm_status_t
lm_get_external_phy_fw_version(
          struct _lm_device_t *pdev,
          u8_t *               version,
          u8_t                 len );

/* Description:
 *    This routine is called to update ext phy fw
 */
lm_status_t
lm_update_external_phy_fw(
    struct _lm_device_t *pdev,
    u32_t offset,
    u8_t * data,
    u32_t size);

/* Description:
 *    This routine is called before update ext phy fw file
 */
lm_status_t
lm_update_external_phy_fw_prepare( struct _lm_device_t *pdev );

/* Description:
 *    This routine is called after update ext phy fw file
 */
lm_status_t
lm_update_external_phy_fw_reinit( struct _lm_device_t *pdev );

/* Description:
 *    This routine is called after update ext phy fw file
 */
lm_status_t
lm_update_external_phy_fw_done( struct _lm_device_t *pdev );

/* Description:
 *    This routine check if there is a fan failure in board
 *    in case there is - event log will be sent
 */
void lm_check_fan_failure(struct _lm_device_t *pdev);

/* Description:
 *    Checks if all the HW is in idle state
 * Returned Value
 *    Number of errors (not idle items) */
/* Description:
 *    Sends keepalive to mcp
 */
lm_status_t lm_send_driver_pulse( struct _lm_device_t *pdev );

/* Description:
 *    Set driver pulse to MCP to always alive
 */
void lm_driver_pulse_always_alive(struct _lm_device_t *pdev);

/* Description:
 *    stop any dma transactions to/from chip and verify no pending requests
 */
void lm_disable_pci_dma(struct _lm_device_t *pdev, u8_t b_wait_for_done);

/* Description:
 *    enable  dma transactions to/from chip
 */
void lm_enable_pci_dma(struct _lm_device_t *pdev);

/* Description:
 *    Disables all the attention
 */
void disable_blocks_attention(struct _lm_device_t *pdev);


// This code section is for WinDbg Extension (b10kd)
#if !defined(_B10KD_EXT)
u32_t       lm_idle_chk( struct _lm_device_t *pdev);
lm_status_t lm_get_storms_assert( struct _lm_device_t *pdev );
#endif // (_B10KD_EXT)

void lm_collect_idle_storms_dorrbell_asserts( struct _lm_device_t *pdev,
                                              const  u8_t          b_idle_chk,
                                              const  u8_t          b_storms_asserts,
                                              const  u8_t          b_dorrbell_info );

/* Description:
 *    cmng interface
 */
void lm_cmng_calc_params( struct _lm_device_t *pdev );
void lm_cmng_get_shmem_info( struct _lm_device_t *pdev );

lm_status_t
lm_get_doorbell_info(
    struct _lm_device_t *pdev);

lm_status_t
lm_gpio_read(struct _lm_device_t *pdev, u32_t pin_num, u32_t* value_ptr, u8_t port);

lm_status_t
lm_gpio_write(struct _lm_device_t *pdev, u32_t pin_num, u32_t value, u8_t port);

lm_status_t
lm_gpio_mult_write(struct _lm_device_t *pdev, u8_t pins, u32_t value);

lm_status_t
lm_gpio_int_write(struct _lm_device_t *pdev, u32_t pin_num, u32_t value, u8_t port);

lm_status_t
lm_spio_read(struct _lm_device_t *pdev, u32_t pin_num, u32_t* value_ptr);

lm_status_t
lm_spio_write(struct _lm_device_t *pdev, u32_t pin_num, u32_t value);

lm_status_t
lm_set_led_mode(struct _lm_device_t *pdev, u32_t port_idx, u32_t mode_idx);

lm_status_t
lm_get_led_mode(struct _lm_device_t *pdev, u32_t port_idx, u32_t* mode_idx_ptr);

lm_status_t
lm_override_led_value(struct _lm_device_t *pdev, u32_t port_idx, u32_t led_idx, u32_t value);

lm_status_t
lm_blink_traffic_led(struct _lm_device_t *pdev, u32_t port_idx, u32_t rate);

lm_status_t
lm_get_led_status(struct _lm_device_t *pdev, u32_t port_idx, u32_t led_idx, u32_t* value_ptr);

void
lm_set_led(struct _lm_device_t *pdev, lm_medium_t speed);

void
lm_reset_led(struct _lm_device_t *pdev);

void
lm_return_packet_bytes( struct _lm_device_t *pdev,
                        u32_t const         qidx,
                        u32_t const         returned_bytes);

void
lm_reg_rd_blk(
    struct _lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *buf_ptr,
    u32_t u32t_cnt);

void
lm_reg_rd_blk_ind(
    struct _lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *buf_ptr,
    u32_t u32t_cnt,
    u8_t acquire_lock_flag);

void
lm_reg_wr_blk(
    struct _lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *data_ptr,
    u32_t u32t_cnt);

void
lm_reg_wr_blk_ind(
    struct _lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *data_ptr,
    u32_t u32t_cnt);

lm_status_t 
lm_get_ibft_physical_addr_for_efi( 
    struct _lm_device_t *pdev, 
    u32_t *phy_hi, 
    u32_t *phy_lo);

lm_status_t lm_get_iscsi_boot_info_block( struct _lm_device_t *pdev, struct _iscsi_info_block_hdr_t* iscsi_info_block_hdr_ptr );

typedef enum {
    lm_mcp_mb_header,
    lm_mcp_mb_param,
    lm_mcp_mb_pulse
} lm_mcp_mb_type;

#define MCP_CMD_DEFAULT_TIMEOUT 0x0

// lm_mcp_cmd functions
lm_status_t lm_mcp_cmd_init( struct _lm_device_t *pdev) ;
lm_status_t lm_mcp_cmd_send( struct _lm_device_t *pdev, lm_mcp_mb_type mcp_mb_type, u32_t drv_msg, u32_t param) ;
lm_status_t lm_mcp_cmd_response( struct _lm_device_t *pdev,
                                 lm_mcp_mb_type       mcp_mb_type,
                                 u32_t                drv_msg,
                                 u32_t                timeout,
                                 OUT u32_t*           p_fw_resp );

/**Perform a send/receive transaction with the MCP. This
 * function is guarenteed to be atomic against all other calls
 * to lm_mcp_cmd_send_recieve.
 *
 * @param pdev the LM device
 * @param mcp_mb_type
 * @param drv_msg the opcode to send to the MCP
 * @param param the parameter to send
 * @param timeout
 * @param p_fw_resp the response from the MCP
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         value on failure.
 */
lm_status_t lm_mcp_cmd_send_recieve( struct _lm_device_t* pdev,
                                     lm_mcp_mb_type       mcp_mb_type,
                                     u32_t                drv_msg,
                                     u32_t                param,
                                     u32_t                timeout,
                                     OUT u32_t*           p_fw_resp);

/**Perform a send/receive transaction with the MCP, with no
 * atomicity guarentee. Only call this function when you know no
 * other context may initiate an MCP transaction (e.g from the
 * load/unload flow).
 *
 * @param pdev the LM device
 * @param mcp_mb_type
 * @param drv_msg the opcode to send to the MCP
 * @param param the parameter to send
 * @param timeout
 * @param p_fw_resp the response from the MCP
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         value on failure.
 */
lm_status_t lm_mcp_cmd_send_recieve_non_atomic( struct _lm_device_t *pdev,
                                             lm_mcp_mb_type       mcp_mb_type,
                                             u32_t                drv_msg,
                                             u32_t                param,
                                             u32_t                timeout,
                                             OUT u32_t*           p_fw_resp );

u32_t lm_mcp_check( struct _lm_device_t *pdev);

/**lm_mcp_set_mf_bw
 * Set the bandwidth parameters of this function through the MCP
 * opcode DRV_MSG_CODE_SET_MF_BW.
 *
 *
 * @param pdev the LM device
 * @param min_bw the minimum bandwidth for this function
 * @param max_bw the maximum bandwidth for this function
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success,
 *         LM_STATUS_INVALID_PARAMETER if the bootcode version
 *         is not new enough or the device is not in
 *         multifunction mode.
 */
lm_status_t lm_mcp_set_mf_bw(struct _lm_device_t *pdev, IN u8_t min_bw, IN u8_t max_bw);

/**lm_mcp_indicate_client_bind
 * Update the SHMEM as needed when a client binds.
 *
 * @param pdev the LM device
 * @param cli_id the client that was bound.
 */
void lm_mcp_indicate_client_bind(struct _lm_device_t *pdev, lm_cli_idx_t cli_id);

/**lm_mcp_indicate_client_unbind
 * Update the SHMEM as needed when a client unbinds.
 *
 *
 * @param pdev the LM device
 * @param cli_id the client that was unbound.
 */
void lm_mcp_indicate_client_unbind(struct _lm_device_t *pdev, lm_cli_idx_t cli_id);

// lm_lodaer interface

typedef enum {
    LM_LOADER_OPCODE_LOAD           = 0x10,
    LM_LOADER_OPCODE_UNLOAD_WOL_EN  = 0x11,
    LM_LOADER_OPCODE_UNLOAD_WOL_DIS = 0x12,
    LM_LOADER_OPCODE_UNLOAD_WOL_MCP = 0x13
} lm_loader_opcode;

#define LM_LOADER_OPCODE_UNLOAD_SUSPEND	0x80
#define LM_LOADER_OPCODE_MASK		0x7F

typedef enum {
    LM_LOADER_RESPONSE_LOAD_COMMON      = 0x100,
    LM_LOADER_RESPONSE_LOAD_PORT        = 0x101,
    LM_LOADER_RESPONSE_LOAD_FUNCTION    = 0x102,
    LM_LOADER_RESPONSE_LOAD_DONE        = 0x103,
    LM_LOADER_RESPONSE_UNLOAD_COMMON    = 0x104,
    LM_LOADER_RESPONSE_UNLOAD_PORT      = 0x105,
    LM_LOADER_RESPONSE_UNLOAD_FUNCTION  = 0x106,
    LM_LOADER_RESPONSE_UNLOAD_DONE      = 0x107,
    LM_LOADER_RESPONSE_LOAD_COMMON_CHIP = 0x108,
    LM_LOADER_RESPONSE_INVALID         = -1
} lm_loader_response;

// lm_loader functions
lm_loader_response lm_loader_lock( struct _lm_device_t *pdev, lm_loader_opcode opcode ) ;
lm_loader_response lm_loader_unlock( struct _lm_device_t *pdev, lm_loader_opcode opcode, OPTIONAL const u32_t* IN p_param );
void lm_loader_reset ( struct _lm_device_t *pdev );

/* Get limit function[s]*/
u32_t lm_get_max_supported_toe_cons(struct _lm_device_t *pdev);
u8_t lm_get_toe_rss_possibility(struct _lm_device_t *pdev);

/**
 * Returns TRUE is device is not ASIC. May be called even when
 * device is not in D0 power state.
 *
 * @param pdev Device handle
 *
 * @return 0 if device is ASIC.
 */
int lm_chip_is_slow(struct _lm_device_t *pdev);

/*
 * returns the first MSI-X message for the given function
 */
u8_t lm_get_base_msix_msg(struct _lm_device_t *pdev);

/*
 * returns the first MSI-X message for the given function
 */
u8_t lm_get_base_msix_msg(struct _lm_device_t *pdev);


/*
 * returns the number of msix messages for the given function
 */
u8_t lm_get_num_fp_msix_messages(struct _lm_device_t *pdev);

/**
 * Set/Get IGU test mode
 */
void lm_set_igu_tmode(struct _lm_device_t *pdev, u8_t tmode);
u8_t lm_get_igu_tmode(struct _lm_device_t *pdev);

/**
 * Set/Get interrupt mode.
 */
void lm_set_interrupt_mode(struct _lm_device_t *pdev, u32_t mode);
u32_t lm_get_interrupt_mode(struct _lm_device_t *pdev);


/*
 * Check if, pdev has sp-vector i.e. pf / vf...
 */
u8_t lm_has_sp_msix_vector(struct _lm_device_t *pdev);


u8_t lm_is_function_after_flr(struct _lm_device_t * pdev);
lm_status_t lm_cleanup_after_flr(struct _lm_device_t * pdev);

lm_status_t
lm_set_cam_params(struct _lm_device_t * pdev,
                  u32_t mac_requestors_mask,
                  u32_t base_offset_in_cam_table,
                  u32_t cam_size,
                  u32_t mma_size,
                  u32_t mc_size);

void
lm_dcbx_pmf_migration(
    IN struct _lm_device_t *pdev);
/*******************************************************************************
 * Description:
 *
 *
 * Return:
******************************************************************************/
lm_status_t
lm_dcbx_free_resc(
    IN struct _lm_device_t *pdev
    );

/**
 * @description
 *  Called to clean dcbx info after D3
 * @param pdev
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_init_info(
    IN struct _lm_device_t *pdev
    );
/*******************************************************************************
 * Description:
 *
 * Return:
******************************************************************************/
void
lm_dcbx_init(IN struct _lm_device_t *pdev,
             IN const u8_t          b_only_setup);

void
lm_dcbx_init_default_params(struct _lm_device_t *pdev);
/*******************************************************************************
 * Description:
 *
 * Return:
******************************************************************************/
lm_status_t
lm_dcbx_lldp_read_params(struct _lm_device_t            * pdev,
                         struct _b10_lldp_params_get_t  * lldp_params);

/*******************************************************************************
 * Description:
 *
 * Return:
******************************************************************************/
lm_status_t
lm_dcbx_read_params(struct _lm_device_t            * pdev,
                    struct _b10_dcbx_params_get_t  * dcbx_params);

u8_t lm_dcbx_cos_max_num(
    INOUT   const struct _lm_device_t * pdev);

lm_status_t
lm_dcbx_ie_check_if_param_change(
    INOUT   struct _lm_device_t     *pdev,
    IN      lldp_local_mib_t        *p_local_mib,
    IN      lldp_local_mib_ext_t    *p_local_mib_ext,
    IN      u8_t                    is_local_ets_change);

/**
 * @description
 * Enable indicate event to upper layer
 * @param pdev
 */
void lm_dcbx_ie_update_state(
    INOUT       struct _lm_device_t *pdev,
    IN const    u8_t                is_en);


lm_status_t
lm_dcbx_ie_params_updated_validate(
    INOUT       struct _lm_device_t                     *pdev,
    OUT         dcb_indicate_event_params_t             *dcb_params,
    OUT         dcb_indicate_event_params_t             *dcb_params_copy,
    IN const    u8_t                                    lm_cli_idx);

lm_status_t
lm_dcbx_ie_runtime_params_updated(
    INOUT       struct _lm_device_t                     *pdev,
    INOUT       dcb_indicate_event_params_t             *dcb_params,
    IN const    u8_t                                    lm_cli_idx);

lm_status_t
lm_dcbx_ie_initialize(
    INOUT       struct _lm_device_t         *pdev,
    IN const    u8_t                        lm_cli_idx);

void
lm_dcbx_ie_deinitialize(
    INOUT       struct _lm_device_t         *pdev,
    IN const    u8_t                        lm_cli_idx);

/**
 * @description
 * Return chain type.
 * @param pdev
 * @param chain
 *
 * @return lm_chain_type_t
 */
lm_chain_type_t
lm_mp_get_chain_type(IN struct _lm_device_t   *pdev,
                     IN const u32_t           chain);
/**
 * @description
 * Get regular chain from chain.
 * If chain isn't a COS chain(e.g. ISCSI L2) than return
 * original value.
 * @param pdev
 * @param chain
 *
 * @return u32_t
 */
u32_t
lm_mp_get_reg_chain_from_chain(IN struct _lm_device_t   *pdev,
                               IN u32_t                 chain);


/**
 * @description
 * Get COS chain from regular chain.
 * @param pdev
 * @param chain
 * @param cos
 *
 * @return u32_t
 */
u8_t
lm_mp_get_cos_chain_from_reg_chain(
    IN struct _lm_device_t  *pdev,
    INOUT u8_t              chain,
    INOUT const u8_t        cos);

lm_status_t
lm_get_transceiver_data(struct _lm_device_t*     pdev,
                        struct _b10_transceiver_data_t*  b10_transceiver_data );

lm_status_t
lm_set_led_wrapper(struct _lm_device_t*     pdev,
                   const   u8_t             led_mode );

/*******************************************************************************
 * Description:
 *              Runtime changes can take more than 1 second and can't be handled
 *              from DPC.
 *              When the PMF detects a DCBX update it will schedule a WI that
 *              will handle the job.
 *              Also the function lm_dcbx_stop_HW_TX/lm_dcbx_resume_HW_TX must be
 *              called in mutual exclusion.
 *              lm_mcp_cmd_send_recieve must be called from default DPC, so when the
 *              WI will finish the processing an interrupt that will be called from
 *              The WI will cause us to enter this function again and send the Ack.
 *
 * Return:
******************************************************************************/
void
lm_dcbx_event(struct _lm_device_t            * pdev,
              u32_t         drv_status);

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
lm_status_t lm_reset_function_part(struct _lm_device_t *pdev, u8_t cleanup);

lm_status_t lm_reset_port_part(struct _lm_device_t *pdev);

lm_status_t lm_set_hc_flag(struct _lm_device_t *pdev, u8_t sb_id, u8_t idx, u8_t is_enable);

lm_status_t lm_set_interrupt_moderation(struct _lm_device_t *pdev, u8_t is_enable);
unsigned long power2_lower_align(unsigned long n);

lm_status_t lm_tpa_send_ramrods(IN struct  _lm_device_t    *pdev,
                                IN const u8_t              chain_idx_base);

u8_t lm_tpa_ramrod_update_ipvx(IN struct  _lm_device_t   *pdev,
                          IN const u8_t          chain_idx,
                          IN const u8_t          vbd_tpa_ipvx_bit);

/**
 * @description
 * Send all the ramrods and wait for there return.
 * @param pdev
 * @param chain_idx_base
 *
 * @return lm_status_t
 * status success is returned if all the ramrods where received.
 * Status failure is returned if not all the ramrods were
 * received.
 */
lm_status_t
lm_tpa_send_ramrods_wait( IN struct _lm_device_t *pdev,
                         IN const u8_t   chain_idx_base);

lm_status_t lm_setup_tpa_chain( IN struct _lm_device_t *pdev,
                                IN u32_t const          cid);

/**
 * @description
 * Clear TPA parameters. TPA can be disabled between NDIS bind
 * unbind but the RX cahin will stay used.
 * @param pdev
 * @param cid
 */
lm_status_t
lm_tpa_chain_reset(IN struct _lm_device_t *pdev,
                   IN u32_t const          cid);


/**
 * @description
 * Fill and send function_update_data ramrod.
 * @param pdev
 */
lm_status_t
lm_encap_send_ramrod(IN struct _lm_device_t *pdev, u8_t new_encap_offload_state, void* cookie);

/**
 * @Description
 *      Function is the callback function for completing eq
 *      completions when no chip access exists. Part of
 *      "complete-pending-sq" flow
 * @param pdev
 * @param pending
 */
void lm_eq_comp_cb(struct _lm_device_t *pdev, struct sq_pending_command * pending);

/**
 * @Description
 *      Function is the callback function for completing eth
 *      completions when no chip access exists. Part of
 *      "complete-pending-sq" flow
 * @param pdev
 * @param pending
 */
void lm_eth_comp_cb(struct _lm_device_t *pdev, struct sq_pending_command * pending);

/********************************* ERROR Recovery Related *****************************/
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
lm_status_t lm_er_acquire_leader_lock(struct _lm_device_t * pdev);

/**
 * @Description
 *      release the lock acquired in the previous function
 * @param pdev
 *
 * @return lm_status_t SUCCESS, INVALID_PARAM: if invalid input
 *         is provided, LM_STATUS_OBJECT_NOT_FOUND if the lock
 *         isn't taken.
 */
lm_status_t lm_er_release_leader_lock(struct _lm_device_t * pdev);

/**
 * @Description
 *     Perform the error recovery leader process kill flow.
 *
 * @param pdev
 *
 * @return lm_status_t SUCCESS or FAILURE
 */
lm_status_t lm_er_leader_reset(struct _lm_device_t *pdev);

/**
 * @Description
 *      This function disables close the gate functionality
 *      should be called from the last driver that unloads
 *      (unless recovery is in progress)
 *
 * @param pdev
 */
void lm_er_disable_close_the_gate(struct _lm_device_t *pdev);

/**
 * @Description
 *      This function notifies the second engine that a
 *      attention occured and error recovery will initiate on
 *      second engine as well
 * @param pdev
 *
 * @return lm_status_t
 */
lm_status_t lm_er_notify_other_path(struct _lm_device_t *pdev);

/**
 * @Description
 *      This function attaches attentions to NIG / PXP
 *      close-the-g8, any attention that is added here should
 *      also be added to the lm_recoverable_error function.
 * @param pdev
 */
void lm_er_config_close_the_g8(struct _lm_device_t *pdev);

u32_t   lm_er_get_func_bit(struct _lm_device_t *pdev);
u32_t   lm_er_get_number_of_functions(u32_t er_register);
u8_t    lm_er_get_first_func_of_opp_path(struct _lm_device_t *pdev);
u32_t   lm_er_inc_load_cnt(struct _lm_device_t *pdev, u8_t sync_it);
u32_t   lm_er_dec_load_cnt(struct _lm_device_t *pdev, u8_t sync_it);
u32_t   lm_er_get_load_cnt(struct _lm_device_t *pdev, u8_t sync_it);
void    lm_er_clear_load_cnt(struct _lm_device_t *pdev, u8_t sync_it);
void    lm_er_set_recover_done(struct _lm_device_t *pdev, u8_t sync_it);
void    lm_er_set_recover_in_progress(struct _lm_device_t *pdev, u8_t sync_it);
u8_t    lm_er_recovery_in_progress(struct _lm_device_t *pdev, u8_t sync_it);

#define LM_ERROR_RECOVERY_COUNTER_HW_REGISTER   MISC_REG_GENERIC_POR_1
#define LM_ERROR_RECOVERY_IN_PROGRESS_FLAG      0x80000000

/**
 * Calculate CRC32_BE.
 *
 * @param crc32_packet
 * @param crc32_length
 * @param crc32_seed
 * @param complement
 *
 * @return u32_t
 */
u32_t calc_crc32(u8_t *crc32_packet, u32_t crc32_length, u32_t crc32_seed, u8_t complement);
u32_t convert_to_bcd( const u8_t IN ver_arr[4] );
/**
 * General function that waits for a certain state to change,
 * not protocol specific. It takes into account vbd-commander
 * and reset-is-in-progress
 *
 * @param pdev
 * @param curr_state -> what to poll on
 * @param new_state -> what we're waiting for
 *
 * @return lm_status_t TIMEOUT if state didn't change, SUCCESS
 *         otherwise
 */
lm_status_t lm_wait_state_change(struct _lm_device_t *pdev, volatile u32_t * curr_state, u32_t new_state);

/**lm_func_update_post_command Post a func_update ramrod and
 * wait for its completion.
 *
 * @param pdev the device
 * @param command the ramrod cmd_id (NONE_CONNECTION_TYPE is
 *                assumed)
 * @param data the ramrod data
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         failure code on failure.
 */
lm_status_t
lm_l2mp_func_update_command( IN struct _lm_device_t                 *pdev,
                             IN const struct function_update_data   *func_data);
lm_status_t
lm_dcbx_set_params_and_read_mib(
    IN struct _lm_device_t  *pdev,
    IN  const   u8_t        is_local_ets_change,
    IN  const   u8_t        b_can_update_ie);

lm_status_t
lm_dcbx_disable_dcb_at_fw_and_hw(
    IN struct _lm_device_t  *pdev,
    IN  const   u8_t        b_can_update_ie);

u8_t
lm_dcbx_is_dcb_config(IN struct _lm_device_t  *pdev);

u8_t
lm_ncsi_prev_drv_ver_is_win8_inbox( struct _lm_device_t *pdev);

u8_t lm_check_mac_addr_exist(struct _lm_device_t *pdev, u8_t chain_idx, u8_t *mac_addr, u16_t vlan_tag, u8_t is_encap_inner_mac_filter);

lm_status_t lm_update_default_vlan(IN struct _lm_device_t    *pdev, IN u8_t client_idx,
                              IN const u16_t            silent_vlan_value,
                              IN const u16_t            silent_vlan_mask,
                              IN const u8_t             silent_vlan_removal_flg,
                              IN const u8_t             silent_vlan_change_flg,
                              IN const u16_t            default_vlan,
                              IN const u8_t             default_vlan_enable_flg,
                              IN const u8_t             default_vlan_change_flg);

u8_t lm_is_mac_locally_administrated(IN struct _lm_device_t    *pdev, IN u8_t * mac);
#endif /* _LM_H */
