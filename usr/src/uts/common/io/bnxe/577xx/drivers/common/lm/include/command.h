#ifndef __COMMAND_H__
#define __COMMAND_H__

/* This file containes the slow-path send queue and the L2 Command code */
#include "57712_reg.h"
#include "577xx_int_offsets.h"
#include "context.h"
#include "lm5710.h"
//#include "5710_hsi.h"
//#define MAX_PROTO 2

/* How many slow-path-queue elements can be sent in parallel divided into normal and high priority */
#define MAX_NORMAL_PRIORITY_SPE 7
#define MAX_HIGH_PRIORITY_SPE   1
#define MAX_NUM_SPE 8

#define CMD_PRIORITY_NORMAL 0x10
#define CMD_PRIORITY_MEDIUM 0x20
#define CMD_PRIORITY_HIGH   0x30




/* structure representing a list of slow-path-completions */
typedef struct _sp_cqes_info {
    union eth_rx_cqe sp_cqe[MAX_NUM_SPE];
    u8_t idx;
} sp_cqes_info;


static __inline void _lm_sq_post(struct _lm_device_t *pdev,struct sq_pending_command * pending)
{
    u32_t func = FUNC_ID(pdev);

    /* TODO replace this with the proper struct */
    /* CID needs port number to be encoded int it */
    mm_memcpy(pdev->sq_info.sq_chain.prod_bd, &pending->command, sizeof(pending->command));
    
    pdev->sq_info.sq_chain.prod_idx ++;
    pdev->sq_info.sq_chain.bd_left --;

    if (pdev->sq_info.sq_chain.prod_bd == pdev->sq_info.sq_chain.last_bd) {
        pdev->sq_info.sq_chain.prod_bd = pdev->sq_info.sq_chain.sq_chain_virt;
    }else{
        pdev->sq_info.sq_chain.prod_bd ++ ;
    }

    
    DbgMessage(pdev,VERBOSEl2sp | VERBOSEl4sp, "Writing SP prod %d, conn_and_cmd_data=%x, type=%d \n",pdev->sq_info.sq_chain.prod_idx, pending->command.hdr.conn_and_cmd_data, pending->command.hdr.type);

    if (IS_PFDEV(pdev) && pdev->sq_info.sq_state == SQ_STATE_NORMAL) {
        LM_INTMEM_WRITE16(pdev, XSTORM_SPQ_PROD_OFFSET(func), pdev->sq_info.sq_chain.prod_idx, BAR_XSTRORM_INTMEM);
    } 
#ifdef VF_INVOLVED
    else {
        LM_INTMEM_WRITE16(PFDEV(pdev),XSTORM_VF_SPQ_PROD_OFFSET(ABS_VFID(pdev)), pdev->sq_info.sq_chain.prod_idx, BAR_XSTRORM_INTMEM);
    }
#endif
}

/** 
 *  @Description: This function fills a command that is received
 *              as a parameter given the input... 
 * 
 * @param pdev
 * @param pending - OUT: this entry is filled given the input 
 *                below
 * @param cid
 * @param command - FW Command ID
 * @param type   - The type of connection, can optionally 
 *               include the function id as well if it differs
 *               from the function of pdev (for example for VFs)
 *  
 * @param data - Data for FW ramrod 
 * @param release_mem_flag - Determines whether the sp pending 
 *                         command will be returned to the pool
 *                         at the end of usage. 
 */
static __inline void lm_sq_post_fill_entry(struct _lm_device_t* pdev,
                                           struct sq_pending_command * pending,
                                           u32_t                cid,
                                           u8_t                 command,
                                           u16_t                type,
                                           u64_t                data,
                                           u8_t                 release_mem_flag)
{
    /* In some cases type may already contain the func-id (VF specifically) so we add it only if it's not there... */
    if (!(type & SPE_HDR_T_FUNCTION_ID))
    {
        type |= (FUNC_ID(pdev) << SPE_HDR_T_FUNCTION_ID_SHIFT);
    }

    // CID MSB is function number
    pending->command.hdr.conn_and_cmd_data = mm_cpu_to_le32((command << SPE_HDR_T_CMD_ID_SHIFT ) | HW_CID(pdev,cid));
    pending->command.hdr.type = mm_cpu_to_le16(type);
    pending->command.protocol_data.hi = mm_cpu_to_le32(U64_HI(data));
    pending->command.protocol_data.lo = mm_cpu_to_le32(U64_LO(data));
    pending->flags = 0;
    
    if (release_mem_flag)
    {
        SET_FLAGS(pending->flags, SQ_PEND_RELEASE_MEM);
    }

    pending->cid  = cid;
    pending->type = type; /* don't kill function ID, RSC VF update really uses the value (& SPE_HDR_T_CONN_TYPE);*/
    pending->cmd  = command;

}

/** 
 * Description
 *	Add the entry to the pending SP list.   
 *	Try to add entry's from the list to the sq_chain if possible.(there is are less then 8 ramrod commands pending) 
 * 
 * @param pdev
 * @param pending  - The pending list entry.
 * @param priority - (high or low) to witch list to insert the pending list entry.
 * 
 * @return lm_status_t: LM_STATUS_SUCCESS on success or 
 *         LM_STATUS_REQUEST_NOT_ACCEPTED if slowpath queue is
 *         in blocked state.
 */
lm_status_t lm_sq_post_entry(struct _lm_device_t       * pdev,
                             struct sq_pending_command * pending,
                             u8_t                        priority);

/*  
    post a ramrod to the sq 
    takes the sq pending list spinlock and adds the request
    will not block
    but the actuall posting to the sq might be deffered until there is room
    MUST only have one request pending per CID (this is up to the caller to enforce)
*/
lm_status_t lm_sq_post(struct _lm_device_t *pdev,
                       u32_t                cid,
                       u8_t                 command,
                       u8_t                 priority,
                       u16_t                type,
                       u64_t                data);

/** 
 * @Description 
 *      inform the sq mechanism of completed ramrods because the
 *      completions arrive on the fast-path rings the fast-path
 *      needs to inform the sq that the ramrod has been serviced
 *      will not block, it also needs to notify which ramrod has
 *      been completed since completions can arrive in a different
 *      sequence than sent.
 * @param pdev
 * @param priority: priority of ramrod being completed 
 *                (different credits) 
 * @param command:  which command is completed
 * @param type:     connection type
 * @param cid:      connection id that ramrod was sent with 
 */
void lm_sq_complete(struct _lm_device_t *pdev, u8_t priority, 
                    u8_t command, u16_t type, u32_t cid );

/** 
 * @description 
 *    do any deffered posting pending on the sq, will take the list spinlock
 *    will not block. Check sq state, if its pending (it means no hw...) call flush
 *    at the end, which will take care of completing these completions internally.
 * @param pdev
 * 
 * @return lm_status_t SUCCESS: is no pending requests were sent. PENDING if a
 *                              if pending request was sent. 
 */
lm_status_t lm_sq_post_pending(struct _lm_device_t *pdev);

/* 
    post a slow-path command 
    takes a spinlock, does not sleep
    actuall command posting may be delayed
*/
static __inline lm_status_t lm_command_post( struct _lm_device_t* pdev,
                                   u32_t                cid,
                                   u8_t                 command,
                                   u8_t                 priority,
                                   u16_t                type,
                                   u64_t                data )
{
    return lm_sq_post(pdev, cid, command, priority, type, data );
}


/* TODO: move functions above to lm_sp.c */
/** 
 * @Description
 *      change state of slowpath queue. 
 *
 * @param pdev
 * @param state NORMAL, PENDING, BLOCKED
 */
void lm_sq_change_state(struct _lm_device_t *pdev, lm_sq_state_t state);

/** 
 * @Description 
 *      This function completes any pending slowpath requests.
 *      It does this as if they were completed via cookie...
 *      It needs to know all the possible cookies and which
 *      completions to give. Any new ramrod should be added to
 *      this function. Also if it should be ignored.
 *  
 * @param pdev
 */
void lm_sq_complete_pending_requests(struct _lm_device_t *pdev);

/** 
 * @Description 
 *      This function takes care of registering a DPC for
 *      completing slowpaths internally in the driver (if such
 *      exist) 
 * @param pdev
 * 
 * @return lm_status_t SUCCESS: if all flushed (i.e. dpc not 
 *                              scheduled)
 *                      PENDING: if dpc is scheduled 
 */
lm_status_t lm_sq_flush(struct _lm_device_t *pdev);

/** 
 * @Description 
 *      Checks if the sq is empty  
 * 
 * @param pdev
 * 
 * @return u8_t TRUE if empty FALSE o/w
 */
u8_t lm_sq_is_empty(struct _lm_device_t *pdev);


lm_status_t lm_sq_comp_cb_register(struct _lm_device_t *pdev, u8_t type, lm_sq_comp_cb_t cb);

lm_status_t lm_sq_comp_cb_deregister(struct _lm_device_t *pdev, u8_t type);



#endif //__COMMAND_H__
