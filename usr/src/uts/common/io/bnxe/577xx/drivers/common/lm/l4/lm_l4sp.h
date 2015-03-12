

/*******************************************************************************
* lm_l4sp.h - l4 common slow path interface for usage from lm_l4rx.c/lm_l4tx.c
*******************************************************************************/
#ifndef _LM_L4SP_H
#define _LM_L4SP_H

void lm_tcp_init_ramrod_comp(
	IN    struct _lm_device_t * pdev);

void lm_tcp_rss_update_ramrod_comp(
	IN    struct _lm_device_t * pdev,
	IN    lm_tcp_rcq_t        * rcq,
	IN    u32_t cid,
	IN    u32_t update_stats_type,
    IN    u8_t update_suspend_rcq);

void lm_tcp_rss_update_suspend_rcq(
	IN    struct _lm_device_t * pdev,
	IN    lm_tcp_rcq_t        * rcq);

void lm_tcp_tx_complete_tcp_sp(
    IN    struct _lm_device_t * pdev, 
    IN    lm_tcp_state_t      * tcp, 
    IN    lm_tcp_con_t        * con);

void lm_tcp_rx_complete_tcp_sp(
    IN    struct _lm_device_t * pdev, 
    IN    lm_tcp_state_t      * tcp, 
    IN    lm_tcp_con_t        * con);

void lm_tcp_searcher_ramrod_complete(
    IN    struct _lm_device_t * pdev, 
    IN    lm_tcp_state_t      * tcp
    );

void lm_tcp_terminate_ramrod_complete(
    IN    struct _lm_device_t * pdev, 
    IN    lm_tcp_state_t      * tcp
    );

void lm_tcp_query_ramrod_complete(
    IN    struct _lm_device_t * pdev, 
    IN    lm_tcp_state_t      * tcp
    );


/** Description
 *  function fills a certain grq with generic buffers from the generic buffer pool
 * Assumptions:
 *  - called after the generic buffer pool is ready to deliver generic buffers
 * Returns:
 *  - TRUE if grq was filled with any new buffers
 *  - FALSE if grq qas not filled at all
 */

#define FILL_GRQ_MIN_CASHED_BDS     0x00
#define FILL_GRQ_LOW_THRESHOLD      0x01
#define FILL_GRQ_FULL               0x02

u8_t lm_tcp_rx_fill_grq(struct _lm_device_t * pdev, u8_t sb_idx, d_list_t * bypass_gen_pool_list, u8_t filling_mode);
void lm_tcp_update_isles_cnts(struct _lm_device_t * pdev, s16_t number_of_isles, s32_t number_of_gen_bufs);

void lm_tcp_flush_db(struct _lm_device_t * pdev, lm_tcp_state_t *tcp);


#endif /* _LM_L4SP_H */
