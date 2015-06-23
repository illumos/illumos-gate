/*******************************************************************************
* mm_l4if.h - L4 mm interface 
******************************************************************************/
#ifndef _MM_L4IF_H
#define _MM_L4IF_H


/* per OS methods */
#if defined(DOS)
#include "sync.h"
#define MM_INIT_TCP_LOCK_HANDLE()

#define mm_acquire_tcp_lock(_pdev, con)  LOCK()
#define mm_release_tcp_lock(_pdev, con)  UNLOCK()

#define MM_ACQUIRE_TOE_LOCK(_pdev)      LOCK()     
#define MM_RELEASE_TOE_LOCK(_pdev)      UNLOCK()

#define MM_ACQUIRE_TOE_GRQ_LOCK(_pdev, idx)  LOCK()
#define MM_RELEASE_TOE_GRQ_LOCK(_pdev, idx)  UNLOCK()

#define MM_ACQUIRE_TOE_GRQ_LOCK_DPC(_pdev, idx) LOCK()
#define MM_RELEASE_TOE_GRQ_LOCK_DPC(_pdev, idx) UNLOCK()

#elif defined(__LINUX) || defined(__SunOS)
void
mm_acquire_tcp_lock(
    struct _lm_device_t *pdev,
    lm_tcp_con_t *tcp_con);

void
mm_release_tcp_lock(
    struct _lm_device_t *pdev,
    lm_tcp_con_t *tcp_con);

#define MM_INIT_TCP_LOCK_HANDLE()

void MM_ACQUIRE_TOE_LOCK(struct _lm_device_t *_pdev);
void MM_RELEASE_TOE_LOCK(struct _lm_device_t *_pdev);
void MM_ACQUIRE_TOE_GRQ_LOCK(struct _lm_device_t *_pdev, u8_t idx);
void MM_RELEASE_TOE_GRQ_LOCK(struct _lm_device_t *_pdev, u8_t idx);
void MM_ACQUIRE_TOE_GRQ_LOCK_DPC(struct _lm_device_t *_pdev, u8_t idx);
void MM_RELEASE_TOE_GRQ_LOCK_DPC(struct _lm_device_t *_pdev, u8_t idx);

#elif defined(_VBD_) || defined(_VBD_CMD_) 

#if USE_QUEUED_SLOCK

void
mm_acquire_tcp_q_lock(
    lm_device_t *pdev,
    lm_tcp_con_t *tcp_con,
    void *ql_hdl);
void
mm_release_tcp_q_lock(
    lm_device_t *pdev,
    lm_tcp_con_t *tcp_con,
    void *ql_hdl);

/* MM_INIT_TCP_LOCK_HANDLE:
 * a macro for decleration of KLOCK_QUEUE_HANDLE in stack, to be declared 
 * in stack by every lm/um caller to mm_acquire_tcp_q_lock.
 * since KLOCK_QUEUE_HANDLE is a WDM structure that can't be compiled
 * in lm, we define a size SIZEOF_QL_HDL that should be larger/equal to
 * sizeof(KLOCK_QUEUE_HANDLE) */
#define SIZEOF_QL_HDL 24 // 24 is the size KLOCK_QUEUE_HANDLE structure in Win 64 bit, so it supossed to be good enough for both 32 & 64
#define MM_INIT_TCP_LOCK_HANDLE()   u8_t __ql_hdl[SIZEOF_QL_HDL] = {0}
#define mm_acquire_tcp_lock(pdev,tcp_con)   mm_acquire_tcp_q_lock((pdev),(tcp_con),__ql_hdl)
#define mm_release_tcp_lock(pdev,tcp_con)   mm_release_tcp_q_lock((pdev),(tcp_con),__ql_hdl)

#else /* USE_QUEUED_SLOCK */

#define MM_INIT_TCP_LOCK_HANDLE()

void
mm_acquire_tcp_lock(
    lm_device_t *pdev,
    lm_tcp_con_t *tcp_con);

void
mm_release_tcp_lock(
    lm_device_t *pdev,
    lm_tcp_con_t *tcp_con);

#endif /* USE_QUEUED_SLOCK */

void MM_ACQUIRE_TOE_LOCK(lm_device_t *_pdev);
void MM_RELEASE_TOE_LOCK(lm_device_t *_pdev);
void MM_ACQUIRE_TOE_GRQ_LOCK(lm_device_t *_pdev, u8_t idx);
void MM_RELEASE_TOE_GRQ_LOCK(lm_device_t *_pdev, u8_t idx);
void MM_ACQUIRE_TOE_GRQ_LOCK_DPC(lm_device_t *_pdev, u8_t idx);
void MM_RELEASE_TOE_GRQ_LOCK_DPC(lm_device_t *_pdev, u8_t idx);

#elif defined(__USER_MODE_DEBUG)

#define MM_INIT_TCP_LOCK_HANDLE()

__inline static void mm_acquire_tcp_lock(
    struct _lm_device_t *pdev,
    lm_tcp_con_t *tcp_con)
{
    DbgMessage(pdev, INFORMl4, "Acquiring tcp lock for con %p\n", tcp_con);
}

__inline static void mm_release_tcp_lock(
    struct _lm_device_t *pdev,
    lm_tcp_con_t *tcp_con) 
{
    DbgMessage(pdev, INFORMl4, "Releasing tcp lock for con %p\n", tcp_con);
}

#define MM_ACQUIRE_TOE_LOCK(_pdev)          DbgMessage(pdev, INFORMl4, "Acquiring global toe lock\n");
#define MM_RELEASE_TOE_LOCK(_pdev)          DbgMessage(pdev, INFORMl4, "Releasing global toe lock\n");
#define MM_ACQUIRE_TOE_GRQ_LOCK(_pdev, idx) DbgMessage(pdev, INFORMl4, "Acquiring global toe grq lock\n");
#define MM_RELEASE_TOE_GRQ_LOCK(_pdev, idx) DbgMessage(pdev, INFORMl4, "Releasing global toe grq lock\n");
#define MM_ACQUIRE_TOE_GRQ_LOCK_DPC(_pdev, idx) DbgMessage(pdev, INFORMl4, "Acquiring global toe grq lock\n");
#define MM_RELEASE_TOE_GRQ_LOCK_DPC(_pdev, idx) DbgMessage(pdev, INFORMl4, "Releasing global toe grq lock\n");

#elif defined (NDISMONO)
/*
 * stubs for NDIS
 */
#define MM_INIT_TCP_LOCK_HANDLE()

void
mm_acquire_tcp_lock(
    lm_device_t *pdev,
    lm_tcp_con_t *tcp_con);

void
mm_release_tcp_lock(
    lm_device_t *pdev,
    lm_tcp_con_t *tcp_con);

void MM_ACQUIRE_TOE_LOCK(lm_device_t *_pdev);
void MM_RELEASE_TOE_LOCK(lm_device_t *_pdev);
void MM_ACQUIRE_TOE_GRQ_LOCK(lm_device_t *_pdev, u8_t idx);
void MM_RELEASE_TOE_GRQ_LOCK(lm_device_t *_pdev, u8_t idx);
void MM_ACQUIRE_TOE_GRQ_LOCK_DPC(lm_device_t *_pdev, u8_t idx);
void MM_RELEASE_TOE_GRQ_LOCK_DPC(lm_device_t *_pdev, u8_t idx);

#endif /* NDISMONO */

u32_t mm_tcp_rx_peninsula_to_rq_copy_dmae(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    lm_address_t          gen_buf_phys,    /* Memory buffer to copy from */
    u32_t                 gen_buf_offset,
    lm_tcp_buffer_t     * tcp_buf,         /* TCP buffer to copy to      */
    u32_t                 tcp_buf_offset,
    u32_t                 nbytes           
    );

void mm_tcp_comp_slow_path_request(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    lm_tcp_slow_path_request_t *sp_request);

/** Description:
 *  - complete Tx and Rx application buffers towards the client 
 *    (with any kind of completion status)
 *  - handle various pending ‘down stream’ tasks: post more application buffers,
 *    post graceful disconnect request (Tx only)
 * Assumptions:
 *  - in each given lm buffer with flag BUFFER_END the field ‘app_buf_xferred’ 
 *    was correctly set by the caller */
void mm_tcp_complete_bufs(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    lm_tcp_con_t        *tcp_con,   /* Rx OR Tx connection */
    s_list_t            *buf_list,  /* list of lm_tcp_buffer_t */
    lm_status_t         lm_status   /* completion status for all given TBs */
    );



/**
 * Description: 
 *        Returns TRUE if generic data OR preposted buffer is being indicated to the client 
 * for the given connection and FALSE otherwise.
 * 
 */ 
u8_t mm_tcp_indicating_bufs(
    lm_tcp_con_t * con
    );

/** Description:
 *  - Completes graceful disconnect request towards client with the given status.
 * Assumptions:
 *  - Assumptions described in client.disconnect_tcp_done() (see design doc)
 *  - The connection's lock is already taken by the caller
 */
void mm_tcp_abort_bufs (
    IN    struct _lm_device_t     * pdev,  /* device handle */
    IN    lm_tcp_state_t          * tcp,   /* L4 state handle */
    IN    lm_tcp_con_t            * con,   /* connection handle */
    IN    lm_status_t               status /* status to abort buffers with */       
    );

/**
 * Description:
 *    Indicates toward the client reception of the remote FIN.
 * 
 */ 
void mm_tcp_indicate_fin_received(
    IN   struct _lm_device_t     * pdev,   /* device handle */    
    IN   lm_tcp_state_t          * tcp
    );

/**
 * Description:
 *    Indicates toward the client reception of the remote RST.
 * 
 */ 
void mm_tcp_indicate_rst_received(
    IN   struct _lm_device_t     * pdev,          /* device handle */                        
    IN   lm_tcp_state_t          * tcp
    );


/**
 * Description:
 *      Indicates toward the client the completion of the FIN request.
 */ 
void mm_tcp_graceful_disconnect_done(
    IN   struct _lm_device_t     * pdev,    /* device handle */    
    IN   lm_tcp_state_t          * tcp,     /* L4 state handle */  
    IN   lm_status_t               status   /* May be SUCCESS, ABORTED or UPLOAD IN PROGRESS */
    );



/** Description
 *  This function is called by lm when there are generic buffers that need indication
 *  - indicate received data using generic buffers to the client (client.indicate_tcp_rx_buf)
 *  - receive the buffered data by calling lm_get_buffered_data, and notify the lm of the 
 *    status by calling lm_buffer_data_indicated after returning from client.indicate_tcp_rx_buf
 */
void mm_tcp_rx_indicate_gen (
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp
    );

/** Description
 *  Removes Generic Buffers from the generic buffer pool and passes them to the LM. 
 * 
 *  Returns:
 *  - The actual number of buffers returned (may be less than required_bufs in case there are not 
 *    enough buffers in the pool)
 */ 
u32_t mm_tcp_get_gen_bufs(
    struct _lm_device_t * pdev,
    d_list_t            * gb_list,
    u32_t                 nbufs, 
    u8_t                  sb_idx
    );

/** Description
 *  Returns a list of generic buffers to the generic buffer pool
 * Assumption:
 *  gen_buf is a list of generic buffers that ALL need to be returned to the pool
 */ 
#define MM_TCP_RGB_COMPENSATE_GRQS      0x01
#define MM_TCP_RGB_COLLECT_GEN_BUFS     0x02

#define MM_TCP_RGB_USE_ALL_GEN_BUFS     0x80

#define NON_EXISTENT_SB_IDX             0xFF

void mm_tcp_return_gen_bufs(
    struct _lm_device_t * pdev, 
    lm_tcp_gen_buf_t    * gen_buf,
    u32_t                 flags,
    u8_t                  grq_idx
    );


void mm_tcp_return_list_of_gen_bufs(
    struct _lm_device_t * pdev, 
    d_list_t            * gen_buf_list,
    u32_t                 flags,
    u8_t                  grq_idx
    );

/** Description
 *  Copys data from a memory buffer to the tcp buffer using client_if.copy_l4buffer
 * Assumptions:
 * - size of mem_buf is larger than nbytes
 * Returns:
 * - The actual number of bytes copied
 */
u32_t mm_tcp_copy_to_tcp_buf(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp_state,
    lm_tcp_buffer_t     * tcp_buf,         /* TCP buffer to copy to      */
    u8_t                * mem_buf,         /* Memory buffer to copy from */
    u32_t                 tcp_buf_offset,
    u32_t                 nbytes           
    );

void
mm_tcp_indicate_retrieve_indication(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp_state,
    l4_upload_reason_t upload_reason);

/** Description
 *  This function is used for updating the required number of generic buffer pools
 *  given an old and new mss and initial receive window. It is called as a result of an 
 *  update to one of these parameters
 */ 
void mm_tcp_update_required_gen_bufs(
    struct _lm_device_t * pdev, 
    u32_t  new_mss, 
    u32_t  old_mss, 
    u32_t  new_initial_rcv_wnd,
    u32_t  old_initial_rcv_wnd);

/** Description
 *  completes a path upload request. It completes the request to the client
 *  only if coplete_to_client is true...
 */
void mm_tcp_complete_path_upload_request(
    struct _lm_device_t * pdev,
    lm_path_state_t     * path);


/** Description
 * called when the upload neigh request is completed. This occurs when the last path dependent
 * of a path state that is in the upload_pending state has been upload completed
 * Assumptions
 *  - caller holds the TOE LOCK
 */
void mm_tcp_complete_neigh_upload_request(
    struct _lm_device_t * pdev,
    lm_neigh_state_t    * neigh
    );

/* Post an empty ramrod initiated by TOE. */
lm_status_t mm_tcp_post_empty_slow_path_request(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u32_t                 request_type);

/* Delete the tcp state (initiated from lm)  */
void mm_tcp_del_tcp_state(
    struct _lm_device_t * pdev, 
    lm_tcp_state_t * tcp);

#endif /* _MM_L4IF_H */
