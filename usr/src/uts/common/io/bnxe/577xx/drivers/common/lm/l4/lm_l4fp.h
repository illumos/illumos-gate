
/*******************************************************************************
* lm_l4fp.h - l4 common fast path interface 
*******************************************************************************/
#ifndef _LM_L4FP_H
#define _LM_L4FP_H

/* Maximum size of the SGE BD may point at */
#define TCP_MAX_SGE_SIZE                   0xffff   /* 64KB */ 
/* Maximum size of the SGL */
#define TCP_MAX_SGL_SIZE                   0xffff   /* 64KB - bd_used field is u16_t */ 

/* Assumptions: Called only from DPC flow OR deferred cqes. Holds the fp-lock */
void lm_tcp_complete_bufs(
    struct _lm_device_t *pdev,
    lm_tcp_state_t      *tcp,
    lm_tcp_con_t        *con);

/* Assumptions: Called only from DPC flow OR deferred cqes. Does not hold the fp-lock */
u32_t lm_tcp_complete_nbytes(
    struct _lm_device_t *pdev,
	lm_tcp_state_t      *tcp,
	lm_tcp_con_t        *con,            /* Rx OR Tx connection */
	u32_t               completed_bytes, /* num bytes completed (might be 0) */
	u8_t                push             /* if == 0, don't complete partialy 
										 completed buffers towards mm */);

/**
 * Description:
 *      Aborts the pending buffers on the given connection : 
 * immediately completes them with the  given status.
 */ 
void lm_tcp_abort_bufs(
    struct _lm_device_t * pdev,   /* device handle */
    lm_tcp_state_t      * tcp,    /* L4 state */
    lm_tcp_con_t    * con,        /* L4 connection to abort buffers on */
    lm_status_t       stat        /* status to abort with */
    );


/******** qe_buffer interface: cyclic NO-OVERRIDE buffer  ****************/
/** Description
 *  returns the next cqe in the cqe_buffer and updates the buffer params
 *  (head)
 */ 
char * lm_tcp_qe_buffer_next_free_cqe(lm_tcp_qe_buffer_t * cqe_buffer);

/** Description
 *  returns the next occupied cqe in the cqe_buffer and updates the buffer params
 * (tail)
 */ 
char * lm_tcp_qe_buffer_next_occupied_cqe(lm_tcp_qe_buffer_t * cqe_buffer);

/** Description
 *  returns whether the buffer is empty or not (head == tail)
 */ 
u8_t lm_tcp_qe_buffer_is_empty(lm_tcp_qe_buffer_t * cqe_buffer);


/******** qe_buffer interface: cyclic OVERRIDE buffer  ****************/
/** Description
 * returns the next head location in a cyclic manner. This is an override
 * function, meaning that the returned head could be overriding a previous
 * written cqe
 */
char * lm_tcp_qe_buffer_next_cqe_override(lm_tcp_qe_buffer_t * cqe_buffer);

/** Description
 * processes a single rx cqe
 * called as a result of deferred cqes
 */
void lm_tcp_rx_process_cqe(
    lm_device_t       * pdev, 
    struct toe_rx_cqe * cqe, 
    lm_tcp_state_t    * tcp, 
    u8_t                sb_idx
    );
/** Description
 * processes a single tx cqe
 * called as a result of deferred cqes
 */
void lm_tcp_tx_process_cqe(
    lm_device_t        * pdev, 
    struct toe_tx_cqe  * cqe, 
    lm_tcp_state_t     * tcp
    );

void lm_tcp_rx_complete_tcp_fp(
    lm_device_t * pdev, 
    lm_tcp_state_t * tcp, 
    lm_tcp_con_t * con
    );

void lm_tcp_tx_complete_tcp_fp(
    lm_device_t * pdev, 
    lm_tcp_state_t * tcp, 
    lm_tcp_con_t * con
    );

/** Description
 *  adds another nbytes to the sws counter, and posts a doorbell if we're
 *  above a certain threshold
 *  assumptions : caller took the rx-lock
 */ 
void lm_tcp_rx_post_sws (
    lm_device_t    * pdev,
    lm_tcp_state_t * tcp,
    lm_tcp_con_t   * rx_con,
    u32_t            nbytes,
    u8_t             op /* Increase / Decrease */
    );
#define TCP_RX_POST_SWS_INC 0
#define TCP_RX_POST_SWS_DEC 1
#define TCP_RX_POST_SWS_SET 2

/** Description
 *  while we are in a DPC, we don't pop buffers from the active_tb_list, this function
 *  helps in determining the next buffer in the active tb list that is valid (i.e. the 
 *  head of active_tb_list had we popped buffers)
 */ 
static __inline lm_tcp_buffer_t * lm_tcp_next_entry_dpc_active_list(lm_tcp_con_t * con)
{
    if (con->dpc_info.dpc_completed_tail) {
        return (lm_tcp_buffer_t *)s_list_next_entry(con->dpc_info.dpc_completed_tail);
    } else {
        return (lm_tcp_buffer_t *)s_list_peek_head(&con->active_tb_list);
    }
}
#endif /* _LM_L4FP_H */
