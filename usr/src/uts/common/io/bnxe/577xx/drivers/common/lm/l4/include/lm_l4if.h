/*******************************************************************************
* lm_l4if.h - L4 lm interface 
******************************************************************************/
#ifndef _LM_L4IF_H
#define _LM_L4IF_H

lm_status_t lm_tcp_init_chip_common(
    struct _lm_device_t *pdev);

lm_status_t lm_tcp_init(
    struct _lm_device_t *pdev);

lm_status_t lm_tcp_init_resc(struct _lm_device_t *pdev, u8_t b_is_init );
lm_status_t lm_tcp_init_chip(struct _lm_device_t *pdev);
lm_status_t lm_tcp_start_chip(struct _lm_device_t *pdev);

lm_status_t
lm_tcp_set_ofld_params(
    struct _lm_device_t *pdev,    
    lm_state_block_t *state_blk,
    l4_ofld_params_t *params);

lm_status_t lm_tcp_init_neigh_state(
    struct _lm_device_t *pdev,
    lm_state_block_t *state_blk,
    lm_neigh_state_t *neigh,
    l4_neigh_const_state_t *neigh_const,
    l4_neigh_cached_state_t *neigh_cached,
    l4_neigh_delegated_state_t *neigh_delegated);

lm_status_t lm_tcp_init_path_state(
    struct _lm_device_t *pdev,
    lm_state_block_t *state_blk,
    lm_path_state_t *path,
    lm_neigh_state_t *neigh,
    l4_path_const_state_t *path_const,
    l4_path_cached_state_t *path_cached,
    l4_path_delegated_state_t *path_delegated);

lm_status_t lm_tcp_init_tcp_state(
    struct _lm_device_t *pdev,
    lm_state_block_t *state_blk,
    lm_tcp_state_t *tcp,
    lm_path_state_t *path,
    l4_tcp_const_state_t *tcp_const,
    l4_tcp_cached_state_t *tcp_cached,
    l4_tcp_delegated_state_t *tcp_delegated,
    u32_t tcp_cid_addr);

/** Description: 
 *   Initialize the tx/rx connection fields and resources
 * Parameters
 *   - mblk: memory block for the virtual memory
 *   - phy_mblk: memory block for the physical memory
 */ 
lm_status_t lm_tcp_init_tcp_resc(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    lm_tcp_mem_block_t * mblk,
    lm_tcp_phy_mem_block_t * phy_mblk);

/** Description
 * Post buffered data
 */ 
lm_status_t lm_tcp_post_buffered_data(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    d_list_t *buffered_data);

/** Description
 * Init sp_data phys and virt memory for a given tcp state to
 * the sp_req_mgr sp_data memory
 */ 
void lm_tcp_init_tcp_sp_data_mem(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp
    );

/** Description: 
 *   Initialize the common fields, or fields specific for rx/tx that use the
 *   same space in the memory block (such as doorbell-data)
 * Parameters
 *   - mblk: memory block for the virtual memory
 *   - phy_mblk: memory block for the physical memory
 */ 
lm_status_t lm_tcp_init_tcp_common(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp);

/* Get the required size for a connections virtual memory 
 * Parameters:
 * - tcp_state: A specific tcp state that the size is requested for. If NULL, then 
 *   the default size is returned
 */
u32_t lm_tcp_get_virt_size(
    struct _lm_device_t * pdev, 
    lm_tcp_state_t * tcp_state);

/* Get the required size for a connections physical memory 
 * Assumptions: Physical memory size is the same for all connections
 */
u32_t lm_tcp_get_phys_size(
    struct _lm_device_t * pdev); 

lm_status_t lm_tcp_post_upload_path_request (
    struct _lm_device_t * pdev, 
    lm_path_state_t * path_state, 
    l4_path_delegated_state_t * ret_delegated);

lm_status_t lm_tcp_post_upload_neigh_request(
    struct _lm_device_t * pdev, 
    lm_neigh_state_t * neigh_state);

/* Desciption:
 *  delete tcp state from lm _except_ from actual freeing of memory.
 *  the task of freeing of memory is done in lm_tcp_free_tcp_state()
 * Assumptions:
 *  global toe lock is taken by the caller 
 */
void lm_tcp_del_tcp_state(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp);

/* Desciption:
 *  delete path state from lm
 * Assumptions:
 *  global toe lock is taken by the caller 
 */
void lm_tcp_del_path_state(
    struct _lm_device_t *pdev,
    lm_path_state_t *path);

/* Desciption:
 *  delete neigh state from lm
 * Assumptions:
 *  global toe lock is taken by the caller 
 */
void lm_tcp_del_neigh_state(
    struct _lm_device_t *pdev,
    lm_neigh_state_t *neigh);

void lm_tcp_free_tcp_resc(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp);

lm_status_t lm_tcp_post_slow_path_request(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    lm_tcp_slow_path_request_t *request);

/* initiate offload request completion */
void lm_tcp_comp_initiate_offload_request(
    struct _lm_device_t *pdev,
    lm_tcp_state_t *tcp,
    u32_t comp_status);

lm_status_t lm_tcp_tx_post_buf(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    lm_tcp_buffer_t     *tcp_buf,
    lm_frag_list_t      *frag_list);



lm_status_t lm_tcp_rx_post_buf(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    lm_tcp_buffer_t     *tcp_buf,
    lm_frag_list_t      *frag_list
    );

/** Description
 *  Returns data that is buffered in the generic buffers to the mm. 
 *  after this function completes, and the data is indicated to the client
 *  the next function (lm_tcp_rx_buffered_data_indicated) should be called.
 * Assumptions:
 *  - function is called as a result of a call to mm_tcp_rx_indicate_gen
 *  - return_buf_ctx will be sent to lm_tcp_rx_buffered_data_indicated and to l4_buffer_return
 * Returns:
 * - LM_STATUS_SUCCESS - buffered data succesfully passed to mm
 * - LM_STATUS_FAILURE - no more buffered data
 */ 
lm_status_t lm_tcp_rx_get_buffered_data(
    IN  struct _lm_device_t * pdev,
    IN  lm_tcp_state_t      * tcp,
    OUT lm_frag_list_t     ** frag_list, 
    OUT lm_tcp_gen_buf_t   ** gen_buf /* head of indications generic buffer */
    );

/** Description
 *  Called from the flow of terminate. Returns data that is buffered in the generic buffers
 *  with no conditions
 * Assumptions:
 *  - function is called as a result of a terminate
 *  - return_buf_ctx will be sent to l4_buffer_return
 */ 
lm_status_t lm_tcp_rx_get_buffered_data_from_terminate (
    IN  struct _lm_device_t * pdev,
    IN  lm_tcp_state_t      * tcp,
    OUT lm_frag_list_t     ** frag_list, 
    OUT lm_tcp_gen_buf_t   ** gen_buf /* head of indications generic buffer */
    );

/** Description
 *  Called by the mm to notify the result of the indication
 *  accepted_bytes contains the number of bytes that were accepted by the client. This value can
 *  be less than the indicated number of bytes. In which case the indication was a partially succesful
 *  indication
 * Assumption:
 *  - This function is called as a result of a call to mm_tcp_rx_indicate_gen call
 *    and only after lm_tcp_rx_get_buffered_data was called.
 *  - return_buf_ctx is the buffer returned to lm_tcp_rx_get_buffered_data
 *  - accepted_bytes <= indicated number of bytes
 */
void lm_tcp_rx_buffered_data_indicated(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u32_t                 accepted_bytes,
    lm_tcp_gen_buf_t    * gen_buf /* head of indications generic buffer */
    );

/** Description
 *  If connection is still open updates the sws, updates the pending return indications 
 */ 
void lm_tcp_rx_indication_returned(
    struct _lm_device_t * pdev, 
    lm_tcp_state_t      * tcp, 
    lm_tcp_gen_buf_t    * gen_buf/* head of indications generic buffer */
    ); 

/** Description
 *  Called: 
 *   1. when a buffer is returned from a client and the connection is already closed
 *   2. when upload_completion returns from the client
 *  Checks if the connection is dead and can be deleted (depending on state, 
 *  and pending return indications)
 *  If the call is due to (2), changes the state to UPLOAD_DONE
 *  3. when offload completion is proceesed and we service deferred cqes,
 *  its possible that the connection was uploaded while waiting to the offload completion
 * Assumptions:
 *  SP and Rx locks are taken by the caller
 * Return:
 *  TRUE  - if connection can be deleted  i.e. state = UPLOAD_DONE,
 *          and all pending indications returned
 *  FALSE - o/w
 */
u8_t lm_tcp_is_tcp_dead(
    struct _lm_device_t * pdev,
    lm_tcp_state_t      * tcp,
    u8_t                  op
    );
#define TCP_IS_DEAD_OP_RTRN_BUFS         (0)
#define TCP_IS_DEAD_OP_UPLD_COMP         (1)
#define TCP_IS_DEAD_OP_OFLD_COMP_DFRD    (2)

/** Description
 *  checks the state of the connection (POST_BLOCKED or NOT)
 * Returns
 *  SUCCESS           - if connection is open
 *  CONNECTION_CLOSED - if connection is blocked
 */ 
lm_status_t lm_tcp_con_status(
    struct _lm_device_t * pdev,
    lm_tcp_con_t        * rx_con);

/** Description
 *  calculates the size of a generic buffer based on min_gen_buf_size and mtu
 *  this function should be called at init, it does not initialize the lm
 *  toe_info parameter 
 * Assumptions:
 *  mtu and min_gen_buf_size are initialized
 * Returns:
 *  size of generic buffer
 */ 
u32_t lm_tcp_calc_gen_buf_size(struct _lm_device_t * pdev);

/** Description
 * extracts the size of a generic buffer from the lmdev
 */ 
#define LM_TCP_GEN_BUF_SIZE(lmdev) ((lmdev)->toe_info.gen_buf_size)

u8_t lm_toe_is_tx_completion(struct _lm_device_t *pdev, u8_t drv_toe_rss_id);
u8_t lm_toe_is_rx_completion(struct _lm_device_t *pdev, u8_t drv_toe_rss_id);
u8_t lm_toe_is_rcq_suspended(struct _lm_device_t *pdev, u8_t drv_toe_rss_id);
void lm_toe_service_tx_intr(struct _lm_device_t *pdev, u8_t drv_toe_rss_id);
void lm_toe_service_rx_intr(struct _lm_device_t *pdev, u8_t drv_toe_rss_id);
void lm_tcp_clear_grqs(struct _lm_device_t * lmdev);

/*********************** TOE RSS ******************************/
/** 
 * @Description: Update TOE RSS. The origin of this call is when getting
 *               an OS RSS update. It's actually by L2 interface and not
 *               L4. However, the ramrods are separate for L4 + L2 due to the
 *               assumptions by the different protocols of what the data is 
 *               in the indirection table.
 *  
 * @Assumptions: Called BEFORE calling L2
 *                 enable-rss!!
 *  
 * @param pdev
 * @param chain_indirection_table - table of TOE RCQ chain values
 * @param table_size    - size of table above
 * @param enable    - is this enable/disable rss if it's disable, the 
 *                    table will all point to the same entry
 * 
 * @return lm_status_t - PENDING is completion will arrive asyncrounoulsy
 *                     - SUCCESS if no ramrod is sent (for example table didn't change)
 *                     - FAILURE o/w
 */
lm_status_t lm_tcp_update_rss(struct _lm_device_t * pdev, u8_t * chain_indirection_table,
                              u32_t table_size, u8_t  enable);


/* This functions sets the update window mode. We work in two modes: 
 * SHORT_LOOP and LONG_LOOP. 
 * SHORT_LOOP: if generic indication succeeded, the window is update immediately by the accepted bytes
 * LONG_LOOP: if generic indication succeeded, the window is updated only when the buffer is returned via l4_return_buffer 
 */
#define LM_TCP_SET_UPDATE_WINDOW_MODE(lmdev, mode) (lmdev)->toe_info.update_window_mode = mode

#define LM_TCP_GET_UPDATE_WINDOW_MODE(lmdev) ((lmdev)->toe_info.update_window_mode)



/**
 * Description:
 *  - Post a fin request BD in the bd chain
 * Returns:
 *  - SUCCESS - fin request was posted on the BD chain
 *  - CONNECTION CLOSED- as described in lm_tcp_tx_post_buf()
 */ 
lm_status_t lm_tcp_graceful_disconnect(
    IN struct _lm_device_t          * pdev,     /* device handle */
    IN lm_tcp_state_t               * tcp_state /* L4 state */ 
);

/** Description
 *  check if there is a pending remote disconnect on the rx connection. 
 *  This function is called from the um, after buffers have been posted. If there is a
 *  remote disconnect pending, it will be processed.
 */ 
__inline static u8_t lm_tcp_rx_is_remote_disconnect_pending(lm_tcp_state_t * tcp_state)
{
    lm_tcp_con_t             * rx_con   = tcp_state->rx_con;
    lm_tcp_con_rx_gen_info_t * gen_info = &rx_con->u.rx.gen_info;

    return (u8_t)(!(rx_con->flags & TCP_RX_POST_BLOCKED) && 
            (gen_info->peninsula_nbytes == 0)      && 
            (rx_con->u.rx.flags & (TCP_CON_FIN_IND_PENDING | TCP_CON_RST_IND_PENDING)));

}

/** Description
 *  checks whether it is OK to update the tcp state. We only update if the connection
 *  is not being offload/uploaded/invalidated i.e. normal or aborted.
 */ 
__inline static u8_t lm_tcp_ok_to_update(lm_tcp_state_t * tcp)
{
    /* a state status is changed to invalidate only after the invalidate is completed, therefore 
     * to make sure a state isn't in the process of being invalidated we check it's flags to see
     * whether an invalidate request has already been posted. */
    return (u8_t)(((tcp->hdr.status == STATE_STATUS_NORMAL) ||
            (tcp->hdr.status == STATE_STATUS_ABORTED)) &&
            !(tcp->rx_con->flags & TCP_INV_REQ_POSTED)); 
}

/**
 * Description:
 *     initializes the lm data in a slow path request given the request parameters
 */ 
void lm_init_sp_req_type (
    struct _lm_device_t        * pdev, 
    lm_tcp_state_t             * tcp, 
    lm_tcp_slow_path_request_t * lm_req, 
    void                       * req_input_data);

/**
 * Description (for following two functions)
 *     finds the next tcp states dependent of the path/neigh
 *     given the previous tcp state. If tcp_state is NULL, it
 *     returns the first such tcp_state
 * Returns
 *     tcp_state: if such exists
 *     NULL: if there are no more tcp states dependent of the
 *     given path/neigh
 */ 
lm_tcp_state_t * lm_tcp_get_next_path_dependent(
    struct _lm_device_t *pdev, 
    void   *path_state, 
    lm_tcp_state_t * tcp_state);

lm_tcp_state_t * lm_tcp_get_next_neigh_dependent(
    struct _lm_device_t *pdev, 
    void   * neigh_state, 
    lm_tcp_state_t * tcp_state);


/**
 * Description
 *     finds the next neigh state following by given the
 *     previous neigh_state. If neigh_state is NULL, it returns
 *     the first neigh_state in list of neigh states
 * Returns
 *     neigh_state: if exists
 *     NULL: if neigh list is empty or no more neigh states in
 *     the list
 */ 
lm_neigh_state_t * lm_tcp_get_next_neigh(
    struct _lm_device_t *pdev, 
    lm_neigh_state_t * neigh_state);

/**
 * Description
 *     finds the next path states matched non NULL neigh
 *     If neigh_state is NULL, it returns the next path state in
 *     list of path states
 * Returns
 *     path_state: if such exists
 *     NULL: if there are no more path states dependent of the
 *     given neigh (in not NULL)
 */ 
lm_path_state_t * lm_tcp_get_next_path(
    struct _lm_device_t *pdev, 
    lm_neigh_state_t * neigh_state,
    lm_path_state_t * path_state);

/**
 * Description
 *     finds the next tcp states in list of tcp
 *     
 * Returns
 *     tcp_state: if such exists
 *     NULL: if there are no more tcp states in the list
 */ 

lm_tcp_state_t * lm_tcp_get_next_tcp(
    struct _lm_device_t *pdev, 
    lm_tcp_state_t * tcp_state);

/* GilR 8/22/2006 - TBD - temp implementation, for debugging. to be removed?/wrapped with "#if DBG"? */
void lm_tcp_internal_query(
    IN    struct _lm_device_t * pdev);

/**
 * Returns the number of entries needed in frag list 
 * taking into an account the CWnd and MSS 
 */ 
u32_t lm_tcp_calc_frag_cnt(
    struct _lm_device_t * pdev,
    lm_tcp_state_t * tcp
    );

/** Description
 *  function is called whenever the UM allocates more generic buffers
 */ 
void lm_tcp_rx_gen_bufs_alloc_cb(
    struct _lm_device_t * pdev);

/** Description
 *  Callback function for cids being recylced
 */ 
void lm_tcp_recycle_cid_cb(
    struct _lm_device_t *pdev,
    void *cookie,
    s32_t cid);

void lm_tcp_init_num_of_blocks_per_connection(
    struct _lm_device_t *pdev,
    u8_t    num);

u8_t lm_tcp_get_num_of_blocks_per_connection(
    struct _lm_device_t *pdev);

lm_status_t lm_tcp_erase_connection(
    IN    struct _lm_device_t   * pdev,
    IN    lm_tcp_state_t        * tcp);

u8_t lm_tcp_get_src_ip_cam_byte(    
    IN    struct _lm_device_t   * pdev,
    IN    lm_path_state_t        * path);

lm_tcp_state_t* lm_tcp_find_offloaded_tcp_tuple(struct _lm_device_t   * pdev, u8_t src_ip_byte, u8_t src_tcp_b, u8_t dst_tcp_b, lm_tcp_state_t * prev_tcp);


void lm_tcp_rx_clear_isles(struct _lm_device_t * pdev, lm_tcp_state_t * tcp_state, d_list_t * isles_list);

u8_t * lm_tcp_get_pattern(struct _lm_device_t *, 
                          lm_tcp_state_t * tcp, 
                          u8_t  pattern_idx, 
                          u32_t offset, 
                          u32_t * pattern_size);

void lm_tcp_set_pattern_offset(struct _lm_device_t * pdev, 
                          lm_tcp_state_t * tcp, 
                          u8_t  pattern_idx, 
                          u32_t offset);

u32_t lm_tcp_find_pattern_offset(struct _lm_device_t * pdev, u8_t * sub_buf, u32_t sub_buf_size);

#endif /* _LM_L4IF_H */
